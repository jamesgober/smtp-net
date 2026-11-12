//! Pacing before submission (PLAN 7.13): a host such as cPanel accepts mail
//! over its hourly cap and then queues or drops it, so the client has to
//! stay under the cap itself.

use core::time::Duration;

use crate::message::prepared::Envelope;

/// Asked before connecting and before each transaction.
///
/// A gate that already exists elsewhere (throttle-net inside a job runner,
/// a database counter shared by several processes) implements this in a
/// few lines; a gate that counts recipients reads
/// `envelope.recipients().len()`. Two gates together are a gate:
/// `(HourlyLimit, DomainLimit)` admits only what both admit.
///
/// # Examples
///
/// ```
/// use smtp_net::{Admission, Envelope, SendGate};
/// use std::sync::atomic::{AtomicU32, Ordering};
///
/// /// A fixed number of recipients for the life of the process.
/// struct Budget { left: AtomicU32 }
///
/// impl SendGate for Budget {
///     fn admit(&self, envelope: &Envelope, _now_unix_ms: u64) -> Admission {
///         let n = envelope.recipients().len() as u32;
///         match self.left.fetch_update(Ordering::AcqRel, Ordering::Acquire, |l| l.checked_sub(n)) {
///             Ok(_) => Admission::Admit,
///             Err(_) => Admission::RetryAfter(std::time::Duration::from_secs(3600)),
///         }
///     }
///
///     fn refund(&self, envelope: &Envelope, _admitted_unix_ms: u64) {
///         self.left.fetch_add(envelope.recipients().len() as u32, Ordering::AcqRel);
///     }
/// }
///
/// let server = smtp_net::Server::builder("127.0.0.1", smtp_net::Security::PlaintextLoopback)
///     .gate(Budget { left: AtomicU32::new(500) })
///     .build()?;
/// # let _ = server;
/// # Ok::<(), smtp_net::Error>(())
/// ```
pub trait SendGate: Send + Sync {
    /// Whether a message with `envelope` may be sent at `now_unix_ms`
    /// (wall clock, milliseconds). An admitted message counts against the
    /// gate until [`refund`](SendGate::refund) gives it back.
    fn admit(&self, envelope: &Envelope, now_unix_ms: u64) -> Admission;

    /// An admitted message was then not sent (the connection failed before
    /// the server accepted MAIL): give its allowance back.
    /// `admitted_unix_ms` is the time that was passed to the `admit` being
    /// refunded, not the time of the failure, so the allowance goes back to
    /// the window it was taken from even when the failure came minutes
    /// later. The default keeps the allowance.
    fn refund(&self, envelope: &Envelope, admitted_unix_ms: u64) {
        let _ = (envelope, admitted_unix_ms);
    }
}

#[cfg_attr(not(target_has_atomic = "64"), allow(dead_code))]
fn recipient_count(envelope: &Envelope) -> u32 {
    u32::try_from(envelope.recipients().len()).unwrap_or(u32::MAX)
}

/// Both gates: admitted only when both admit; when the second refuses, the
/// first is given its allowance back.
impl<A: SendGate, B: SendGate> SendGate for (A, B) {
    fn admit(&self, envelope: &Envelope, now_unix_ms: u64) -> Admission {
        match self.0.admit(envelope, now_unix_ms) {
            Admission::Admit => match self.1.admit(envelope, now_unix_ms) {
                Admission::Admit => Admission::Admit,
                other => {
                    self.0.refund(envelope, now_unix_ms);
                    other
                }
            },
            other => other,
        }
    }

    fn refund(&self, envelope: &Envelope, admitted_unix_ms: u64) {
        self.0.refund(envelope, admitted_unix_ms);
        self.1.refund(envelope, admitted_unix_ms);
    }
}

/// A gate's answer.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    /// Send now.
    Admit,
    /// Do not send before this much time has passed; the send fails with
    /// `ErrorKind::Throttled` (temporary) and `Error::retry_after`.
    RetryAfter(Duration),
}

/// What an [`HourlyLimit`] counts.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CountUnit {
    /// One per message.
    Messages,
    /// One per recipient (the default assumption for cPanel, D-027).
    Recipients,
}

#[cfg(target_has_atomic = "64")]
pub use hourly::HourlyLimit;

#[cfg(feature = "std")]
pub use domain::DomainLimit;

#[cfg(target_has_atomic = "64")]
mod hourly {
    use core::time::Duration;

    #[cfg(not(smtp_net_loom))]
    use core::sync::atomic::{AtomicU64, Ordering};

    #[cfg(smtp_net_loom)]
    use loom::sync::atomic::{AtomicU64, Ordering};

    use super::{Admission, CountUnit, SendGate, recipient_count};
    use crate::message::prepared::Envelope;

    const MINUTE_MS: u64 = 60_000;
    const BUCKETS: usize = 60;

    /// A rolling 60-minute limit in one-minute buckets. Lock-free: admission
    /// is a compare-and-swap on the window total after expired buckets are
    /// retired, so it never admits more than the limit in any 60-minute
    /// window, under any number of threads. Per process: several processes
    /// share nothing (divide the cap between them, O-21).
    ///
    /// # Examples
    ///
    /// ```
    /// use smtp_net::{Address, Admission, Envelope, HourlyLimit, SendGate};
    /// let gate = HourlyLimit::recipients(2);
    /// let one = Envelope::new(Address::parse("no-reply@example.com")?, &[Address::parse("a@example.org")?])?;
    /// let t = 1_700_000_000_000;
    /// assert_eq!(gate.admit(&one, t), Admission::Admit);
    /// assert_eq!(gate.admit(&one, t + 1_000), Admission::Admit);
    /// assert!(matches!(gate.admit(&one, t + 2_000), Admission::RetryAfter(_)));
    /// assert_eq!(gate.admit(&one, t + 3_600_000), Admission::Admit);
    /// assert_eq!(gate.remaining(t + 3_600_000), 1);
    /// # Ok::<(), smtp_net::Error>(())
    /// ```
    ///
    /// On a [`Server`](crate::Server):
    ///
    /// ```
    /// # #[cfg(feature = "client")] {
    /// let server = smtp_net::Server::builder("127.0.0.1", smtp_net::Security::PlaintextLoopback)
    ///     .gate(smtp_net::HourlyLimit::recipients(450))
    ///     .build()?;
    /// # let _ = server;
    /// # }
    /// # Ok::<(), smtp_net::Error>(())
    /// ```
    #[derive(Debug)]
    pub struct HourlyLimit {
        limit: u64,
        unit: CountUnit,
        /// Admitted and not yet retired.
        total: AtomicU64,
        /// Each bucket: minute number (high 32 bits) and count (low 32 bits).
        buckets: [AtomicU64; BUCKETS],
    }

    fn pack(minute: u64, count: u64) -> u64 {
        ((minute & 0xffff_ffff) << 32) | (count & 0xffff_ffff)
    }

    fn unpack(v: u64) -> (u64, u64) {
        (v >> 32, v & 0xffff_ffff)
    }

    impl HourlyLimit {
        fn new(per_hour: u32, unit: CountUnit) -> HourlyLimit {
            HourlyLimit {
                limit: u64::from(per_hour),
                unit,
                total: AtomicU64::new(0),
                buckets: core::array::from_fn(|_| AtomicU64::new(0)),
            }
        }

        /// At most `per_hour` messages in any 60 minutes.
        #[must_use]
        pub fn messages(per_hour: u32) -> HourlyLimit {
            HourlyLimit::new(per_hour, CountUnit::Messages)
        }

        /// At most `per_hour` recipients in any 60 minutes.
        #[must_use]
        pub fn recipients(per_hour: u32) -> HourlyLimit {
            HourlyLimit::new(per_hour, CountUnit::Recipients)
        }

        /// What is counted.
        #[must_use]
        pub fn unit(&self) -> CountUnit {
            self.unit
        }

        /// How much is left in the window at `now_unix_ms`.
        #[must_use]
        pub fn remaining(&self, now_unix_ms: u64) -> u32 {
            self.retire(now_unix_ms / MINUTE_MS);
            let used = self.total.load(Ordering::Acquire);
            u32::try_from(self.limit.saturating_sub(used)).unwrap_or(u32::MAX)
        }

        /// Retires every bucket whose minute left the window ending at `minute`.
        /// Each bucket's count is subtracted once: only the thread whose swap
        /// takes it subtracts it.
        fn retire(&self, minute: u64) {
            let window_start = minute.saturating_sub(BUCKETS as u64 - 1) & 0xffff_ffff;
            for b in &self.buckets {
                let mut cur = b.load(Ordering::Acquire);
                loop {
                    let (m, c) = unpack(cur);
                    if c == 0 || m >= window_start {
                        break;
                    }
                    match b.compare_exchange(cur, pack(m, 0), Ordering::AcqRel, Ordering::Acquire) {
                        Ok(_) => {
                            self.total.fetch_sub(c, Ordering::AcqRel);
                            break;
                        }
                        Err(now) => cur = now,
                    }
                }
            }
        }

        /// Adds `n` to the bucket of `minute`, taking over a retired bucket.
        fn record(&self, minute: u64, n: u64) {
            let b = self.buckets.get((minute % BUCKETS as u64) as usize);
            let Some(b) = b else { return };
            let mut cur = b.load(Ordering::Acquire);
            loop {
                let (m, c) = unpack(cur);
                let next = if m == (minute & 0xffff_ffff) || c == 0 {
                    pack(minute, c.saturating_add(n).min(0xffff_ffff))
                } else {
                    // An old minute still counted (a clock step): keep counting
                    // it in place so nothing is lost; it is retired with the slot.
                    pack(m, c.saturating_add(n).min(0xffff_ffff))
                };
                match b.compare_exchange(cur, next, Ordering::AcqRel, Ordering::Acquire) {
                    Ok(_) => return,
                    Err(now) => cur = now,
                }
            }
        }

        /// Time until enough of the oldest buckets leave the window for `n` more.
        fn wait_for(&self, minute: u64, n: u64, now_unix_ms: u64) -> Duration {
            let used = self.total.load(Ordering::Acquire);
            let mut need = (used + n).saturating_sub(self.limit);
            let window_start = minute.saturating_sub(BUCKETS as u64 - 1);
            for age in 0..BUCKETS as u64 {
                let m = window_start + age;
                let Some(b) = self.buckets.get((m % BUCKETS as u64) as usize) else {
                    continue;
                };
                let (bm, c) = unpack(b.load(Ordering::Acquire));
                if bm != (m & 0xffff_ffff) || c == 0 {
                    continue;
                }
                if c >= need {
                    let frees_at = (m + BUCKETS as u64) * MINUTE_MS;
                    return Duration::from_millis(frees_at.saturating_sub(now_unix_ms).max(1));
                }
                need -= c;
            }
            // More than the limit was asked for: one full window.
            Duration::from_millis(BUCKETS as u64 * MINUTE_MS)
        }
    }

    impl SendGate for HourlyLimit {
        fn admit(&self, envelope: &Envelope, now_unix_ms: u64) -> Admission {
            self.admit_count(recipient_count(envelope), now_unix_ms)
        }

        fn refund(&self, envelope: &Envelope, admitted_unix_ms: u64) {
            self.refund_count(recipient_count(envelope), admitted_unix_ms);
        }
    }

    impl HourlyLimit {
        fn admit_count(&self, recipients: u32, now_unix_ms: u64) -> Admission {
            let n = match self.unit {
                CountUnit::Messages => 1,
                CountUnit::Recipients => u64::from(recipients.max(1)),
            };
            let minute = now_unix_ms / MINUTE_MS;
            self.retire(minute);
            let mut cur = self.total.load(Ordering::Acquire);
            loop {
                if cur + n > self.limit {
                    return Admission::RetryAfter(self.wait_for(minute, n, now_unix_ms));
                }
                match self
                    .total
                    .compare_exchange(cur, cur + n, Ordering::AcqRel, Ordering::Acquire)
                {
                    Ok(_) => break,
                    Err(now) => cur = now,
                }
            }
            self.record(minute, n);
            Admission::Admit
        }

        fn refund_count(&self, recipients: u32, admitted_unix_ms: u64) {
            let n = match self.unit {
                CountUnit::Messages => 1,
                CountUnit::Recipients => u64::from(recipients.max(1)),
            };
            let minute = admitted_unix_ms / MINUTE_MS;
            if let Some(b) = self.buckets.get((minute % BUCKETS as u64) as usize) {
                let mut cur = b.load(Ordering::Acquire);
                loop {
                    let (m, c) = unpack(cur);
                    if m != (minute & 0xffff_ffff) || c == 0 {
                        // Already retired or another minute: nothing to give back safely.
                        return;
                    }
                    let take = c.min(n);
                    match b.compare_exchange(
                        cur,
                        pack(m, c - take),
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => {
                            self.total.fetch_sub(take, Ordering::AcqRel);
                            return;
                        }
                        Err(now) => cur = now,
                    }
                }
            }
        }
    }

    #[cfg(all(test, not(smtp_net_loom)))]
    mod tests {
        use super::*;

        const T: u64 = 1_700_000_000_000 / MINUTE_MS * MINUTE_MS;

        #[test]
        fn test_limit_minus_one_limit_plus_one() {
            let g = HourlyLimit::messages(3);
            assert_eq!(g.admit_count(10, T), Admission::Admit);
            assert_eq!(g.admit_count(10, T), Admission::Admit);
            assert_eq!(g.remaining(T), 1);
            assert_eq!(g.admit_count(10, T), Admission::Admit);
            assert!(matches!(g.admit_count(10, T), Admission::RetryAfter(_)));
        }

        #[test]
        fn test_retry_after_is_when_the_oldest_bucket_expires() {
            let g = HourlyLimit::recipients(5);
            assert_eq!(g.admit_count(3, T), Admission::Admit);
            assert_eq!(g.admit_count(2, T + 10 * MINUTE_MS), Admission::Admit);
            let Admission::RetryAfter(d) = g.admit_count(1, T + 20 * MINUTE_MS) else {
                panic!()
            };
            assert_eq!(d, Duration::from_millis(40 * MINUTE_MS));
            // One millisecond before the first bucket leaves: still refused.
            assert!(matches!(
                g.admit_count(1, T + 60 * MINUTE_MS - 1),
                Admission::RetryAfter(_)
            ));
            assert_eq!(g.admit_count(3, T + 60 * MINUTE_MS), Admission::Admit);
        }

        #[test]
        fn test_bucket_roll_over_at_minute_boundary() {
            let g = HourlyLimit::messages(1);
            assert_eq!(g.admit_count(1, T + MINUTE_MS - 1), Admission::Admit);
            assert!(matches!(
                g.admit_count(1, T + MINUTE_MS),
                Admission::RetryAfter(_)
            ));
            assert_eq!(g.admit_count(1, T + 61 * MINUTE_MS), Admission::Admit);
        }

        #[test]
        fn test_clock_going_backwards_is_no_time_passing() {
            let g = HourlyLimit::messages(2);
            assert_eq!(g.admit_count(1, T + 30 * MINUTE_MS), Admission::Admit);
            assert_eq!(g.admit_count(1, T), Admission::Admit);
            assert!(matches!(
                g.admit_count(1, T + 29 * MINUTE_MS),
                Admission::RetryAfter(_)
            ));
        }

        #[test]
        fn test_clock_jumping_forward_retires_the_window() {
            // The gate reads the wall clock (D-106): a forward step of an hour
            // retires the hour's counts, as it does for a provider counting
            // on the same clock.
            let g = HourlyLimit::messages(2);
            assert_eq!(g.admit_count(1, T), Admission::Admit);
            assert_eq!(g.admit_count(1, T), Admission::Admit);
            assert!(matches!(g.admit_count(1, T), Admission::RetryAfter(_)));
            assert_eq!(g.admit_count(1, T + 60 * MINUTE_MS), Admission::Admit);
        }

        #[test]
        fn test_refund_gives_back_and_request_over_limit_waits_a_window() {
            let g = HourlyLimit::recipients(4);
            assert_eq!(g.admit_count(4, T), Admission::Admit);
            g.refund_count(4, T);
            assert_eq!(g.remaining(T), 4);
            assert_eq!(
                g.admit_count(9, T),
                Admission::RetryAfter(Duration::from_millis(BUCKETS as u64 * MINUTE_MS))
            );
            let zero = HourlyLimit::messages(0);
            assert!(matches!(zero.admit_count(1, T), Admission::RetryAfter(_)));
        }

        #[test]
        fn test_never_over_admits_under_64_threads() {
            let g = std::sync::Arc::new(HourlyLimit::messages(1000));
            let admitted = std::sync::Arc::new(core::sync::atomic::AtomicU64::new(0));
            let threads: std::vec::Vec<_> = (0..64)
                .map(|i| {
                    let (g, a) = (g.clone(), admitted.clone());
                    std::thread::spawn(move || {
                        for k in 0..100u64 {
                            if g.admit_count(1, T + (i * 100 + k) % (59 * MINUTE_MS))
                                == Admission::Admit
                            {
                                a.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
                            }
                        }
                    })
                })
                .collect();
            for t in threads {
                t.join().unwrap();
            }
            assert_eq!(admitted.load(core::sync::atomic::Ordering::SeqCst), 1000);
        }

        #[test]
        fn test_hourly_limit_is_send_and_sync() {
            fn both<T: Send + Sync>() {}
            both::<HourlyLimit>();
        }
    }

    #[cfg(all(test, smtp_net_loom))]
    mod loom_tests {
        use super::*;

        fn model(f: impl Fn() + Sync + Send + 'static) {
            let mut b = loom::model::Builder::new();
            b.preemption_bound = Some(3);
            b.check(f);
        }

        #[test]
        fn loom_two_threads_at_the_limit_admit_exactly_the_limit() {
            model(|| {
                let g = loom::sync::Arc::new(HourlyLimit::messages(1));
                let g2 = g.clone();
                let t = loom::thread::spawn(move || g2.admit_count(1, 0) == Admission::Admit);
                let a = g.admit_count(1, 0) == Admission::Admit;
                let b = t.join().unwrap();
                assert!(a ^ b, "exactly one of two concurrent admissions wins");
            });
        }

        #[test]
        fn loom_retire_races_admission_without_double_subtract() {
            model(|| {
                let g = loom::sync::Arc::new(HourlyLimit::messages(1));
                assert_eq!(g.admit_count(1, 0), Admission::Admit);
                let g2 = g.clone();
                let later = 61 * MINUTE_MS;
                let t = loom::thread::spawn(move || g2.admit_count(1, later) == Admission::Admit);
                let a = g.admit_count(1, later) == Admission::Admit;
                let b = t.join().unwrap();
                assert!(a ^ b);
                assert_eq!(g.remaining(later), 0);
            });
        }
    }
}

#[cfg(feature = "std")]
mod domain {
    use alloc::{boxed::Box, vec::Vec};
    use core::time::Duration;
    use std::{collections::HashMap, sync::Mutex};

    use super::{Admission, SendGate};
    use crate::message::prepared::Envelope;

    /// Five-minute buckets.
    const BUCKET_MS: u64 = 5 * 60_000;
    /// A bucket is kept until its whole span has left the 60-minute window,
    /// so a count is never dropped early (it may be kept up to 5 minutes
    /// late: the limit errs towards refusing).
    const BUCKETS: usize = 13;

    #[derive(Debug, Default)]
    struct Domain {
        /// (bucket number, recipients) per slot.
        buckets: [(u64, u32); BUCKETS],
        last_used: u64,
    }

    impl Domain {
        fn used(&mut self, bucket: u64) -> u64 {
            let oldest = bucket.saturating_sub(BUCKETS as u64 - 1);
            let mut used = 0u64;
            for (b, n) in &mut self.buckets {
                if *b < oldest {
                    *n = 0;
                }
                used += u64::from(*n);
            }
            used
        }

        /// When enough recipients leave the window for `need` more.
        fn wait(&self, bucket: u64, mut need: u64, now_unix_ms: u64) -> Duration {
            let mut live: Vec<(u64, u32)> = self
                .buckets
                .iter()
                .copied()
                .filter(|&(_, n)| n > 0)
                .collect();
            live.sort_unstable();
            for (b, n) in live {
                if u64::from(n) >= need {
                    let frees_at = (b + BUCKETS as u64) * BUCKET_MS;
                    return Duration::from_millis(frees_at.saturating_sub(now_unix_ms).max(1));
                }
                need -= u64::from(n);
            }
            Duration::from_millis(
                ((bucket + BUCKETS as u64) * BUCKET_MS).saturating_sub(now_unix_ms),
            )
        }

        fn slot(&mut self, bucket: u64) -> Option<&mut (u64, u32)> {
            self.buckets.get_mut((bucket % BUCKETS as u64) as usize)
        }

        fn add(&mut self, bucket: u64, n: u32) {
            if let Some(slot) = self.slot(bucket) {
                // An older bucket is retired and its slot taken. A newer one
                // (the clock stepped back by a whole window or more) keeps
                // counting in place, so nothing is lost; it retires with its
                // slot (D-058, D-106).
                if slot.0 < bucket {
                    *slot = (bucket, 0);
                }
                slot.1 = slot.1.saturating_add(n);
            }
        }

        fn take(&mut self, bucket: u64, n: u32) {
            if let Some(slot) = self.slot(bucket) {
                if slot.0 == bucket {
                    slot.1 = slot.1.saturating_sub(n);
                }
            }
        }
    }

    /// At most `per_hour` recipients at any one recipient domain in any 60
    /// minutes (PLAN 10.3): a compromised account or an abused form mailing
    /// one victim domain is stopped at the limit and shows up as `Throttled`
    /// errors, while mail to other domains goes on. Combine it with an
    /// [`HourlyLimit`](crate::HourlyLimit) for the total:
    /// `.gate((HourlyLimit::recipients(500), DomainLimit::recipients(100)))`.
    ///
    /// Domains are compared without regard to ASCII case. The table holds at
    /// most [`max_domains`](DomainLimit::max_domains) domains (default
    /// 1,024; about 250 octets each); when it is full, the domain used least
    /// recently is forgotten, so a domain under steady mail keeps its count.
    /// A message is admitted for all its domains or none.
    ///
    /// # Examples
    ///
    /// ```
    /// use smtp_net::{Address, Admission, DomainLimit, Envelope, SendGate};
    /// let to = |s: &str| {
    ///     Envelope::new(Address::parse("a@example.com").unwrap(), &[Address::parse(s).unwrap()])
    ///         .unwrap()
    /// };
    /// let gate = DomainLimit::recipients(2);
    /// let t = 1_700_000_000_000;
    /// assert_eq!(gate.admit(&to("x@victim.example"), t), Admission::Admit);
    /// assert_eq!(gate.admit(&to("y@victim.example"), t), Admission::Admit);
    /// assert!(matches!(
    ///     gate.admit(&to("z@VICTIM.example"), t),
    ///     Admission::RetryAfter(_)
    /// ));
    /// assert_eq!(gate.admit(&to("z@other.example"), t), Admission::Admit);
    /// ```
    #[derive(Debug)]
    pub struct DomainLimit {
        per_hour: u32,
        max_domains: usize,
        table: Mutex<HashMap<Box<str>, Domain>>,
    }

    impl DomainLimit {
        /// At most `per_hour` recipients per recipient domain in any 60 minutes.
        #[must_use]
        pub fn recipients(per_hour: u32) -> DomainLimit {
            DomainLimit {
                per_hour,
                max_domains: 1024,
                table: Mutex::new(HashMap::new()),
            }
        }

        /// Most domains remembered at once (at least 1, default 1,024). A
        /// domain is forgotten only once it has no count left in the window,
        /// so a sender cannot reset a domain's count by mailing many others:
        /// while every remembered domain still has counts, a message to a new
        /// domain waits (`RetryAfter`) instead.
        #[must_use]
        pub fn max_domains(mut self, n: usize) -> DomainLimit {
            self.max_domains = n.max(1);
            self
        }

        /// How many more recipients `domain` may have at `now_unix_ms`.
        #[must_use]
        pub fn remaining(&self, domain: &str, now_unix_ms: u64) -> u32 {
            let key = domain.to_ascii_lowercase();
            let used = match self.table.lock() {
                Ok(mut t) => t
                    .get_mut(key.as_str())
                    .map_or(0, |d| d.used(now_unix_ms / BUCKET_MS)),
                Err(_) => u64::from(self.per_hour),
            };
            u32::try_from(u64::from(self.per_hour).saturating_sub(used)).unwrap_or(0)
        }

        /// The envelope's recipients counted per domain, lowercase.
        fn per_domain_counts(envelope: &Envelope) -> Vec<(Box<str>, u32)> {
            let mut out: Vec<(Box<str>, u32)> = Vec::new();
            for a in envelope.recipients() {
                let d = a.domain().as_str().to_ascii_lowercase();
                match out.iter_mut().find(|(k, _)| **k == *d) {
                    Some((_, n)) => *n = n.saturating_add(1),
                    None => out.push((d.into_boxed_str(), 1)),
                }
            }
            out
        }
    }

    impl SendGate for DomainLimit {
        fn admit(&self, envelope: &Envelope, now_unix_ms: u64) -> Admission {
            let bucket = now_unix_ms / BUCKET_MS;
            let counts = DomainLimit::per_domain_counts(envelope);
            let Ok(mut table) = self.table.lock() else {
                // A panic while the lock was held: refuse rather than guess.
                return Admission::RetryAfter(Duration::from_millis(BUCKET_MS));
            };
            let limit = u64::from(self.per_hour);
            let mut wait = Duration::ZERO;
            for (d, n) in &counts {
                let n = u64::from(*n);
                match table.get_mut(d) {
                    Some(entry) => {
                        let used = entry.used(bucket);
                        if used + n > limit {
                            wait = wait.max(entry.wait(bucket, used + n - limit, now_unix_ms));
                        }
                    }
                    None if n > limit => {
                        wait = wait.max(Duration::from_millis(BUCKETS as u64 * BUCKET_MS));
                    }
                    None => {}
                }
            }
            if !wait.is_zero() {
                return Admission::RetryAfter(wait);
            }
            let new = counts
                .iter()
                .filter(|(d, _)| !table.contains_key(d))
                .count();
            if table.len() + new > self.max_domains {
                // Room comes only from domains with nothing left in the
                // window: evicting a busy one would reset its count.
                let idle = table
                    .values_mut()
                    .map(|e| e.used(bucket))
                    .filter(|&u| u == 0)
                    .count();
                if table.len() + new - idle > self.max_domains {
                    return Admission::RetryAfter(Duration::from_millis(BUCKET_MS));
                }
            }
            for (d, n) in counts {
                if !table.contains_key(&d) && table.len() >= self.max_domains {
                    let idle = table
                        .iter_mut()
                        .filter_map(|(k, v)| {
                            (v.used(bucket) == 0).then(|| (v.last_used, k.clone()))
                        })
                        .min();
                    if let Some((_, k)) = idle {
                        table.remove(&k);
                    }
                }
                let entry = table.entry(d).or_default();
                entry.add(bucket, n);
                entry.last_used = now_unix_ms;
            }
            Admission::Admit
        }

        fn refund(&self, envelope: &Envelope, admitted_unix_ms: u64) {
            let bucket = admitted_unix_ms / BUCKET_MS;
            if let Ok(mut table) = self.table.lock() {
                for (d, n) in DomainLimit::per_domain_counts(envelope) {
                    if let Some(entry) = table.get_mut(&d) {
                        entry.take(bucket, n);
                    }
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::Address;

        const T: u64 = 1_700_000_000_000 / BUCKET_MS * BUCKET_MS;
        const MIN: u64 = 60_000;

        fn env(to: &[&str]) -> Envelope {
            let to: Vec<Address> = to.iter().map(|s| Address::parse(s).unwrap()).collect();
            Envelope::new(Address::parse("a@example.com").unwrap(), &to).unwrap()
        }

        fn refused(a: Admission) -> bool {
            matches!(a, Admission::RetryAfter(_))
        }

        #[test]
        fn test_per_domain_limit_and_other_domains() {
            let g = DomainLimit::recipients(3);
            assert_eq!(
                g.admit(&env(&["a@v.example", "b@v.example"]), T),
                Admission::Admit
            );
            assert_eq!(g.remaining("V.example", T), 1);
            // Two more at v would pass the limit: the whole message waits,
            // its w recipient included.
            assert!(refused(
                g.admit(&env(&["c@v.example", "d@v.example", "x@w.example"]), T)
            ));
            assert_eq!(g.remaining("w.example", T), 3);
            assert_eq!(
                g.admit(&env(&["c@v.example", "x@w.example"]), T),
                Admission::Admit
            );
            assert!(refused(g.admit(&env(&["e@v.example"]), T)));
        }

        #[test]
        fn test_clock_going_backwards_keeps_every_count() {
            // 13 buckets back lands on the slot that holds the newer bucket: its
            // count must stay counted, not be reset (D-058, D-106).
            let g = DomainLimit::recipients(3);
            assert_eq!(
                g.admit(&env(&["a@v.example", "b@v.example"]), T),
                Admission::Admit
            );
            let back = T - 13 * BUCKET_MS;
            assert_eq!(g.remaining("v.example", back), 1);
            assert_eq!(g.admit(&env(&["c@v.example"]), back), Admission::Admit);
            assert!(refused(g.admit(&env(&["d@v.example"]), back)));
            assert!(refused(g.admit(&env(&["d@v.example"]), T)));
        }

        #[test]
        fn test_window_and_retry_after() {
            let g = DomainLimit::recipients(2);
            assert_eq!(g.admit(&env(&["a@v.example"]), T), Admission::Admit);
            assert_eq!(
                g.admit(&env(&["b@v.example"]), T + 20 * MIN),
                Admission::Admit
            );
            let Admission::RetryAfter(d) = g.admit(&env(&["c@v.example"]), T + 30 * MIN) else {
                panic!("admitted over the limit")
            };
            // The first recipient's bucket leaves 65 minutes after it opened.
            assert_eq!(d, Duration::from_millis(35 * MIN));
            assert!(refused(g.admit(&env(&["c@v.example"]), T + 65 * MIN - 1)));
            assert_eq!(
                g.admit(&env(&["c@v.example"]), T + 65 * MIN),
                Admission::Admit
            );
        }

        #[test]
        fn test_refund_and_oversized_message() {
            let g = DomainLimit::recipients(2);
            let e = env(&["a@v.example", "b@v.example"]);
            assert_eq!(g.admit(&e, T), Admission::Admit);
            g.refund(&e, T);
            assert_eq!(g.remaining("v.example", T), 2);
            let three = env(&["a@v.example", "b@v.example", "c@v.example"]);
            assert!(refused(g.admit(&three, T)));
        }

        #[test]
        fn test_table_is_bounded_and_never_forgets_a_counted_domain() {
            // Mailing many other domains cannot push a counted domain
            // out of the table (which would reset its count); a new domain
            // waits until a remembered one has nothing left in the window.
            let g = DomainLimit::recipients(1).max_domains(4);
            assert_eq!(g.admit(&env(&["a@busy.example"]), T), Admission::Admit);
            for i in 0..3u64 {
                let other = format!("x@d{i}.example");
                assert_eq!(
                    g.admit(&env(&[other.as_str()]), T + i + 1),
                    Admission::Admit
                );
            }
            for i in 3..100u64 {
                let other = format!("x@d{i}.example");
                assert!(refused(g.admit(&env(&[other.as_str()]), T + i + 1)));
                assert!(refused(g.admit(&env(&["b@busy.example"]), T + i + 1)));
                assert_eq!(g.table.lock().unwrap().len(), 4);
            }
            // Once the window (13 buckets of 5 minutes) has passed, every
            // count has left it: room again.
            let later = T + 70 * MIN;
            assert_eq!(g.admit(&env(&["x@new.example"]), later), Admission::Admit);
            assert_eq!(g.admit(&env(&["b@busy.example"]), later), Admission::Admit);
            assert!(g.table.lock().unwrap().len() <= 4);
        }

        #[test]
        fn test_pair_refunds_the_first_when_the_second_refuses() {
            let g = (
                crate::HourlyLimit::recipients(10),
                DomainLimit::recipients(1),
            );
            assert_eq!(g.admit(&env(&["a@v.example"]), T), Admission::Admit);
            assert!(refused(g.admit(&env(&["b@v.example"]), T)));
            assert_eq!(g.0.remaining(T), 9);
        }

        #[test]
        fn test_domain_limit_behind_a_trait_object_still_counts_per_domain() {
            // Before 0.8 the count-based `admit` of a DomainLimit admitted
            // everything; any caller that used it bypassed the limit.
            let g: alloc::sync::Arc<dyn SendGate> =
                alloc::sync::Arc::new(DomainLimit::recipients(1));
            assert_eq!(g.admit(&env(&["a@v.example"]), T), Admission::Admit);
            assert!(refused(g.admit(&env(&["b@v.example"]), T)));
            g.refund(&env(&["a@v.example"]), T);
            assert_eq!(g.admit(&env(&["b@v.example"]), T), Admission::Admit);
        }
    }
}

//! Pacing before submission (PLAN 7.13): a host such as cPanel accepts mail
//! over its hourly cap and then queues or drops it, so the client has to
//! stay under the cap itself.

use core::time::Duration;

/// Asked before connecting and before each transaction.
///
/// A gate that already exists elsewhere (throttle-net inside a job runner,
/// a database counter shared by several processes) implements this in a
/// few lines.
pub trait SendGate: Send + Sync {
    /// Whether a message to `recipients` recipients may be sent at
    /// `now_unix_ms` (wall clock, milliseconds).
    fn admit(&self, recipients: u32, now_unix_ms: u64) -> Admission;

    /// An admitted message was then not sent (the connection failed before
    /// the server accepted MAIL): give the allowance back.
    fn refund(&self, recipients: u32, now_unix_ms: u64) {
        let _ = (recipients, now_unix_ms);
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

#[cfg(target_has_atomic = "64")]
mod hourly {
    use core::time::Duration;

    #[cfg(not(smtp_net_loom))]
    use core::sync::atomic::{AtomicU64, Ordering};

    #[cfg(smtp_net_loom)]
    use loom::sync::atomic::{AtomicU64, Ordering};

    use super::{Admission, CountUnit, SendGate};

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
    /// use smtp_net::{Admission, HourlyLimit, SendGate};
    /// let gate = HourlyLimit::recipients(2);
    /// let t = 1_700_000_000_000;
    /// assert_eq!(gate.admit(1, t), Admission::Admit);
    /// assert_eq!(gate.admit(1, t + 1_000), Admission::Admit);
    /// assert!(matches!(gate.admit(1, t + 2_000), Admission::RetryAfter(_)));
    /// assert_eq!(gate.admit(1, t + 3_600_000), Admission::Admit);
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
        fn admit(&self, recipients: u32, now_unix_ms: u64) -> Admission {
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

        fn refund(&self, recipients: u32, now_unix_ms: u64) {
            let n = match self.unit {
                CountUnit::Messages => 1,
                CountUnit::Recipients => u64::from(recipients.max(1)),
            };
            let minute = now_unix_ms / MINUTE_MS;
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
            assert_eq!(g.admit(10, T), Admission::Admit);
            assert_eq!(g.admit(10, T), Admission::Admit);
            assert_eq!(g.remaining(T), 1);
            assert_eq!(g.admit(10, T), Admission::Admit);
            assert!(matches!(g.admit(10, T), Admission::RetryAfter(_)));
        }

        #[test]
        fn test_retry_after_is_when_the_oldest_bucket_expires() {
            let g = HourlyLimit::recipients(5);
            assert_eq!(g.admit(3, T), Admission::Admit);
            assert_eq!(g.admit(2, T + 10 * MINUTE_MS), Admission::Admit);
            let Admission::RetryAfter(d) = g.admit(1, T + 20 * MINUTE_MS) else {
                panic!()
            };
            assert_eq!(d, Duration::from_millis(40 * MINUTE_MS));
            // One millisecond before the first bucket leaves: still refused.
            assert!(matches!(
                g.admit(1, T + 60 * MINUTE_MS - 1),
                Admission::RetryAfter(_)
            ));
            assert_eq!(g.admit(3, T + 60 * MINUTE_MS), Admission::Admit);
        }

        #[test]
        fn test_bucket_roll_over_at_minute_boundary() {
            let g = HourlyLimit::messages(1);
            assert_eq!(g.admit(1, T + MINUTE_MS - 1), Admission::Admit);
            assert!(matches!(
                g.admit(1, T + MINUTE_MS),
                Admission::RetryAfter(_)
            ));
            assert_eq!(g.admit(1, T + 61 * MINUTE_MS), Admission::Admit);
        }

        #[test]
        fn test_clock_going_backwards_is_no_time_passing() {
            let g = HourlyLimit::messages(2);
            assert_eq!(g.admit(1, T + 30 * MINUTE_MS), Admission::Admit);
            assert_eq!(g.admit(1, T), Admission::Admit);
            assert!(matches!(
                g.admit(1, T + 29 * MINUTE_MS),
                Admission::RetryAfter(_)
            ));
        }

        #[test]
        fn test_refund_gives_back_and_request_over_limit_waits_a_window() {
            let g = HourlyLimit::recipients(4);
            assert_eq!(g.admit(4, T), Admission::Admit);
            g.refund(4, T);
            assert_eq!(g.remaining(T), 4);
            assert_eq!(
                g.admit(9, T),
                Admission::RetryAfter(Duration::from_millis(BUCKETS as u64 * MINUTE_MS))
            );
            let zero = HourlyLimit::messages(0);
            assert!(matches!(zero.admit(1, T), Admission::RetryAfter(_)));
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
                            if g.admit(1, T + (i * 100 + k) % (59 * MINUTE_MS)) == Admission::Admit
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
                let t = loom::thread::spawn(move || g2.admit(1, 0) == Admission::Admit);
                let a = g.admit(1, 0) == Admission::Admit;
                let b = t.join().unwrap();
                assert!(a ^ b, "exactly one of two concurrent admissions wins");
            });
        }

        #[test]
        fn loom_retire_races_admission_without_double_subtract() {
            model(|| {
                let g = loom::sync::Arc::new(HourlyLimit::messages(1));
                assert_eq!(g.admit(1, 0), Admission::Admit);
                let g2 = g.clone();
                let later = 61 * MINUTE_MS;
                let t = loom::thread::spawn(move || g2.admit(1, later) == Admission::Admit);
                let a = g.admit(1, later) == Admission::Admit;
                let b = t.join().unwrap();
                assert!(a ^ b);
                assert_eq!(g.remaining(later), 0);
            });
        }
    }
}

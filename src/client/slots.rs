//! The pool's slot bitmaps: which slots are checked out, and which hold an
//! open connection. Lock-free; modelled with loom.

#[cfg(not(smtp_net_loom))]
use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(smtp_net_loom)]
use loom::sync::atomic::{AtomicU64, Ordering};

/// Most slots (one bit each).
pub(crate) const MAX_SLOTS: usize = 64;

pub(crate) struct Slots {
    len: u32,
    /// Bit set: the slot is checked out; only its owner touches the slot.
    busy: AtomicU64,
    /// Bit set: the slot holds an open connection. Written only by the
    /// slot's owner.
    open: AtomicU64,
}

impl Slots {
    pub(crate) fn new(len: usize) -> Slots {
        Slots {
            len: u32::try_from(len.clamp(1, MAX_SLOTS)).unwrap_or(1),
            busy: AtomicU64::new(0),
            open: AtomicU64::new(0),
        }
    }

    fn all(&self) -> u64 {
        if self.len >= 64 {
            u64::MAX
        } else {
            (1u64 << self.len) - 1
        }
    }

    /// Checks out a free slot, preferring one with an open connection.
    pub(crate) fn acquire(&self) -> Option<usize> {
        let mut busy = self.busy.load(Ordering::Acquire);
        loop {
            let free = self.all() & !busy;
            if free == 0 {
                return None;
            }
            let warm = free & self.open.load(Ordering::Acquire);
            let pick = if warm != 0 { warm } else { free };
            let bit = pick & pick.wrapping_neg();
            match self.busy.compare_exchange_weak(
                busy,
                busy | bit,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(bit.trailing_zeros() as usize),
                Err(now) => busy = now,
            }
        }
    }

    /// Returns slot `i`, recording whether it keeps an open connection.
    pub(crate) fn release(&self, i: usize, open: bool) {
        let bit = 1u64 << (i % MAX_SLOTS);
        if open {
            self.open.fetch_or(bit, Ordering::Release);
        } else {
            self.open.fetch_and(!bit, Ordering::Release);
        }
        self.busy.fetch_and(!bit, Ordering::Release);
    }

    /// Open connections not checked out.
    pub(crate) fn idle(&self) -> usize {
        let busy = self.busy.load(Ordering::Acquire);
        (self.open.load(Ordering::Acquire) & !busy & self.all()).count_ones() as usize
    }
}

#[cfg(all(test, not(smtp_net_loom)))]
mod tests {
    use super::*;

    #[test]
    fn test_acquire_prefers_warm_slots_and_runs_out() {
        let s = Slots::new(3);
        let a = s.acquire().unwrap();
        let b = s.acquire().unwrap();
        let c = s.acquire().unwrap();
        assert_eq!(s.acquire(), None);
        s.release(b, true);
        s.release(a, false);
        assert_eq!(s.idle(), 1);
        assert_eq!(s.acquire(), Some(b), "the slot with a connection first");
        assert_eq!(s.idle(), 0);
        s.release(c, false);
        assert!(s.acquire().is_some());
        let all = Slots::new(64);
        for _ in 0..64 {
            assert!(all.acquire().is_some());
        }
        assert_eq!(all.acquire(), None);
    }

    #[test]
    fn test_many_threads_never_share_a_slot() {
        let s = std::sync::Arc::new(Slots::new(4));
        let owners: std::sync::Arc<[std::sync::atomic::AtomicU32; 4]> =
            std::sync::Arc::new(Default::default());
        let threads: Vec<_> = (0..16)
            .map(|_| {
                let s = s.clone();
                let owners = owners.clone();
                std::thread::spawn(move || {
                    for _ in 0..2_000 {
                        if let Some(i) = s.acquire() {
                            let o = &owners[i];
                            assert_eq!(o.fetch_add(1, core::sync::atomic::Ordering::SeqCst), 0);
                            o.fetch_sub(1, core::sync::atomic::Ordering::SeqCst);
                            s.release(i, i % 2 == 0);
                        }
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(s.acquire().map(|_| ()), Some(()));
    }
}

#[cfg(all(test, smtp_net_loom))]
mod loom_tests {
    use super::*;

    #[test]
    fn loom_two_threads_one_slot_never_both_own_it() {
        let mut b = loom::model::Builder::new();
        b.preemption_bound = Some(3);
        b.check(|| {
            let s = loom::sync::Arc::new(Slots::new(1));
            let owned = loom::sync::Arc::new(loom::sync::atomic::AtomicU64::new(0));
            let (s2, o2) = (s.clone(), owned.clone());
            let t = loom::thread::spawn(move || {
                if let Some(i) = s2.acquire() {
                    assert_eq!(o2.fetch_add(1, Ordering::SeqCst), 0);
                    o2.fetch_sub(1, Ordering::SeqCst);
                    s2.release(i, true);
                }
            });
            if let Some(i) = s.acquire() {
                assert_eq!(owned.fetch_add(1, Ordering::SeqCst), 0);
                owned.fetch_sub(1, Ordering::SeqCst);
                s.release(i, false);
            }
            t.join().unwrap();
            // Both returned: the slot is free again.
            assert!(s.acquire().is_some());
        });
    }

    #[test]
    fn loom_release_publishes_open_state() {
        let mut b = loom::model::Builder::new();
        b.preemption_bound = Some(3);
        b.check(|| {
            let s = loom::sync::Arc::new(Slots::new(2));
            let a = s.acquire().unwrap();
            let b = s.acquire().unwrap();
            let s2 = s.clone();
            let t = loom::thread::spawn(move || s2.release(a, true));
            s.release(b, false);
            t.join().unwrap();
            assert_eq!(s.idle(), 1);
            assert_eq!(s.acquire(), Some(a), "the open slot first");
        });
    }
}

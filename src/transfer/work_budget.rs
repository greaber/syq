//! Per-worker service-time budgets. These size future work, not completed
//! progress or tuning evidence; requests already issued cannot be recalled.
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct WorkSize {
    pub bytes: u64,
    pub files: usize,
}
impl WorkSize {
    pub const UNLIMITED: Self = Self {
        bytes: u64::MAX,
        files: usize::MAX,
    };
}

pub(super) struct WorkBudget {
    limit: WorkSize,
    target: Duration,
    recheck_latency: bool,
    next_latency_check: Instant,
    earliest_latency_check: Instant,
    limit_at_check: WorkSize,
}
impl Default for WorkBudget {
    fn default() -> Self {
        Self {
            limit: WorkSize {
                bytes: 64 << 10,
                files: 64,
            },
            target: Duration::from_millis(250),
            recheck_latency: false,
            next_latency_check: Instant::now() + Duration::from_secs(30),
            earliest_latency_check: Instant::now() + Duration::from_secs(2),
            limit_at_check: WorkSize {
                bytes: 64 << 10,
                files: 64,
            },
        }
    }
}
impl WorkBudget {
    /// Configuration RPCs supply a latency allowance on SSH too. Include both
    /// endpoints, but not connection startup, authentication or helper setup.
    pub fn set_latency(&mut self, round_trip: Duration) {
        // Replies can include service for the preceding groups in the
        // pipeline. Allow a full window of round trips before draining or
        // shrinking; a single-RPC allowance stalls fast delayed connections.
        self.target = Duration::from_millis(250)
            .max(round_trip.saturating_mul(crate::transfer_tuning::DEFAULT_PIPELINE_DEPTH as u32));
    }

    pub fn latency_target(&self) -> Duration {
        self.target
    }

    pub fn latency_check_due(&self, now: Instant) -> bool {
        let shrunk = self.limit.bytes.saturating_mul(2) < self.limit_at_check.bytes
            || self.limit.files.saturating_mul(2) < self.limit_at_check.files;
        (now >= self.next_latency_check
            && (self.recheck_latency || self.target > Duration::from_millis(250)))
            || (now >= self.earliest_latency_check && self.recheck_latency && shrunk)
    }

    pub fn refreshed_latency(&mut self, round_trip: Duration, now: Instant) {
        let previous = self.target;
        let periodic = now >= self.next_latency_check;
        self.set_latency(round_trip);
        if !periodic {
            // An urgent check responds to a slowdown. A transiently empty
            // queue during its drain is not evidence for a lower allowance;
            // periodic checks can lower it again when conditions improve.
            self.target = self.target.max(previous);
        }
        self.recheck_latency = false;
        self.limit_at_check = self.limit;
        self.earliest_latency_check = now
            + Duration::from_secs(2)
                .max(round_trip.saturating_mul(8))
                .min(Duration::from_secs(300));
        // Draining for a check costs a round trip. Keep checks infrequent even
        // when a slow data path remains above the target after a cheap RPC.
        let interval = Duration::from_secs(30)
            .max(round_trip.saturating_mul(32))
            .min(Duration::from_secs(300));
        self.next_latency_check = now + interval;
    }

    pub fn limit(&self) -> WorkSize {
        self.limit
    }

    // A completion target is not a stall deadline. Leave room for ordinary
    // queuing variation instead of draining a healthy pipe at its operating point.
    pub fn overdue(&self, now: Instant, oldest: Option<Instant>) -> bool {
        oldest.is_some_and(|start| {
            now.saturating_duration_since(start) > self.target.saturating_mul(2)
        })
    }

    /// End-to-end completion includes reads, writes and time behind earlier
    /// requests. Reduce immediately when service slows; grow at most fourfold
    /// per observation so a briefly cached operation cannot reserve a huge tail.
    pub fn observe(&mut self, work: WorkSize, elapsed: Duration) {
        self.recheck_latency |= elapsed > self.target;
        let elapsed = elapsed.max(Duration::from_micros(1)).as_nanos();
        let target = self.target.as_nanos();
        fn resized(current: u64, amount: u64, elapsed: u128, target: u128) -> u64 {
            if amount == 0 {
                return current;
            }
            // A short tail can be late because larger groups preceded it.
            // Reduce the current budget in proportion to that delay instead
            // of treating the tail's size as the connection's full capacity.
            let measured = if elapsed > target {
                amount.max(current)
            } else {
                amount
            };
            let estimate = (u128::from(measured).saturating_mul(target) / elapsed)
                .clamp(1, u128::from(current.saturating_mul(4))) as u64;
            // Groups can be smaller than the budget at a boundary or because
            // they were issued before it grew. An on-time remainder does not
            // show that the current budget is too large. Likewise, a late
            // reply from an older, larger group cannot justify growing it.
            if elapsed <= target {
                estimate.max(current)
            } else {
                estimate.min(current)
            }
        }
        self.limit.bytes = resized(self.limit.bytes, work.bytes, elapsed, target).min(1 << 20);
        self.limit.files =
            resized(self.limit.files as u64, work.files as u64, elapsed, target).min(2048) as usize;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budgets_follow_each_workers_service_and_recover_after_a_slowdown() {
        let mut fast = WorkBudget::default();
        let mut slow = WorkBudget::default();
        let work = WorkSize {
            bytes: 64 << 10,
            files: 64,
        };
        fast.observe(work, Duration::from_millis(10));
        slow.observe(work, Duration::from_secs(4));
        assert_eq!(
            fast.limit(),
            WorkSize {
                bytes: 256 << 10,
                files: 256
            }
        );
        assert_eq!(
            slow.limit(),
            WorkSize {
                bytes: 4096,
                files: 4
            }
        );
        slow.observe(slow.limit(), Duration::from_millis(10));
        assert_eq!(
            slow.limit(),
            WorkSize {
                bytes: 16 << 10,
                files: 16
            }
        );
        fast.observe(fast.limit(), Duration::from_secs(16));
        assert_eq!(
            fast.limit(),
            WorkSize {
                bytes: 4096,
                files: 4
            }
        );
    }

    #[test]
    fn on_time_remainders_keep_capacity_and_late_old_groups_cannot_grow_it() {
        let mut budget = WorkBudget::default();
        for _ in 0..4 {
            budget.observe(budget.limit(), Duration::from_millis(50));
        }
        let large = budget.limit();
        assert_eq!(large.bytes, 1 << 20);
        assert_eq!(large.files, 2048);
        for work in [
            WorkSize {
                bytes: 16 << 10,
                files: 1,
            },
            WorkSize { bytes: 0, files: 1 },
        ] {
            budget.observe(work, Duration::from_millis(200));
            assert_eq!(
                budget.limit(),
                large,
                "fast tail is not a slower connection"
            );
        }
        budget.observe(large, Duration::from_secs(1));
        let reduced = budget.limit();
        assert!(reduced.bytes < large.bytes && reduced.files < large.files);
        budget.observe(large, Duration::from_millis(300));
        assert_eq!(
            budget.limit(),
            reduced,
            "late sample cannot undo a reduction"
        );
        budget.observe(reduced, Duration::from_millis(50));
        assert!(
            budget.limit().bytes > reduced.bytes,
            "growth resumes with fast service"
        );
    }

    #[test]
    fn slightly_late_remainders_reduce_current_capacity_proportionally() {
        for remainder in [
            WorkSize {
                bytes: 16 << 10,
                files: 1,
            },
            WorkSize { bytes: 0, files: 1 },
        ] {
            let mut budget = WorkBudget::default();
            for _ in 0..4 {
                budget.observe(budget.limit(), Duration::from_millis(50));
            }
            let before = budget.limit();
            // This tail waited behind earlier groups. Being five percent late
            // is not evidence that only one file fits in the target interval.
            budget.observe(remainder, Duration::from_micros(262_500));
            let reduced = budget.limit();
            assert_eq!(reduced.files, before.files * 20 / 21);
            assert_eq!(
                reduced.bytes,
                if remainder.bytes == 0 {
                    before.bytes
                } else {
                    before.bytes * 20 / 21
                }
            );
            budget.observe(reduced, Duration::from_millis(50));
            assert_eq!(
                budget.limit(),
                before,
                "timely full groups restore capacity"
            );
            budget.observe(before, Duration::from_secs(4));
            assert_eq!(budget.limit().files, before.files / 16);
            assert_eq!(budget.limit().bytes, before.bytes / 16);
        }
    }

    #[test]
    fn empty_files_and_very_fast_or_slow_samples_stay_bounded() {
        let mut budget = WorkBudget::default();
        budget.observe(
            WorkSize {
                bytes: 0,
                files: 64,
            },
            Duration::from_secs(16),
        );
        assert_eq!(
            budget.limit(),
            WorkSize {
                bytes: 64 << 10,
                files: 1
            }
        );
        for _ in 0..32 {
            budget.observe(
                WorkSize {
                    bytes: u64::MAX,
                    files: usize::MAX,
                },
                Duration::ZERO,
            );
        }
        assert_eq!(
            budget.limit(),
            WorkSize {
                bytes: 1 << 20,
                files: 2048
            }
        );
        budget.observe(WorkSize { bytes: 1, files: 1 }, Duration::MAX);
        assert_eq!(budget.limit(), WorkSize { bytes: 1, files: 1 });
    }

    #[test]
    fn latency_preserves_pipeline_room_and_age_stops_refills_without_a_completion() {
        let mut budget = WorkBudget::default();
        budget.set_latency(Duration::from_millis(400));
        let start = Instant::now();
        assert!(!budget.overdue(start + Duration::from_millis(700), Some(start)));
        assert!(!budget.overdue(start + Duration::from_secs(1), Some(start)));
        assert!(!budget.overdue(start + Duration::from_secs(2), Some(start)));
        assert!(budget.overdue(start + Duration::from_secs(4), Some(start)));
        assert!(!budget.overdue(start + Duration::from_secs(20), None));
        budget.observe(budget.limit(), Duration::from_millis(400));
        assert_eq!(
            budget.limit(),
            WorkSize {
                bytes: 256 << 10,
                files: 256
            }
        );
    }

    #[test]
    fn initial_periodic_check_waits_but_budget_collapse_can_check_early() {
        let mut budget = WorkBudget::default();
        let now = Instant::now();
        budget.set_latency(Duration::from_millis(150));
        budget.observe(budget.limit(), Duration::from_millis(100));
        assert!(!budget.latency_check_due(now + Duration::from_secs(3)));
        assert!(!budget.latency_check_due(now + Duration::from_secs(29)));
        assert!(budget.latency_check_due(now + Duration::from_secs(31)));

        let mut collapsed = WorkBudget::default();
        collapsed.observe(collapsed.limit(), Duration::from_secs(2));
        assert!(!collapsed.latency_check_due(now + Duration::from_secs(1)));
        assert!(collapsed.latency_check_due(now + Duration::from_secs(3)));
    }

    #[test]
    fn latency_checks_are_bounded_and_allow_recovery_when_queueing_disappears() {
        let mut budget = WorkBudget::default();
        let now = Instant::now() + Duration::from_secs(31);
        assert!(!budget.latency_check_due(now));
        budget.observe(budget.limit(), Duration::from_millis(400));
        assert!(budget.latency_check_due(now));
        budget.refreshed_latency(Duration::from_millis(300), now);
        assert_eq!(budget.latency_target(), Duration::from_millis(1200));
        budget.observe(budget.limit(), Duration::from_millis(1300));
        assert!(!budget.latency_check_due(now + Duration::from_secs(29)));
        assert!(budget.latency_check_due(now + Duration::from_secs(30)));
        budget.refreshed_latency(Duration::from_millis(10), now + Duration::from_secs(30));
        assert_eq!(budget.latency_target(), Duration::from_millis(250));
        assert!(!budget.latency_check_due(now + Duration::from_secs(61)));
        budget.observe(budget.limit(), Duration::from_secs(4));
        assert!(!budget.latency_check_due(now + Duration::from_secs(31)));
        assert!(
            budget.latency_check_due(now + Duration::from_secs(33)),
            "a new severe drop need not wait thirty seconds"
        );
        budget.refreshed_latency(Duration::from_secs(4), now + Duration::from_secs(33));
        assert_eq!(budget.latency_target(), Duration::from_secs(16));
        budget.observe(budget.limit(), Duration::from_secs(64));
        assert!(budget.latency_check_due(now + Duration::from_secs(66)));
        budget.refreshed_latency(Duration::from_millis(10), now + Duration::from_secs(66));
        assert_eq!(
            budget.latency_target(),
            Duration::from_secs(16),
            "an urgent check must not mistake a transiently empty queue for recovery"
        );
        assert!(!budget.latency_check_due(now + Duration::from_secs(95)));
        assert!(budget.latency_check_due(now + Duration::from_secs(96)));
        budget.refreshed_latency(Duration::from_millis(10), now + Duration::from_secs(96));
        assert_eq!(budget.latency_target(), Duration::from_millis(250));
        budget.refreshed_latency(Duration::MAX, now + Duration::from_secs(97));
        assert!(!budget.latency_check_due(now + Duration::from_secs(396)));
        assert!(budget.latency_check_due(now + Duration::from_secs(397)));
    }
}

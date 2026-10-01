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
}
impl Default for WorkBudget {
    fn default() -> Self {
        Self {
            limit: WorkSize {
                bytes: 64 << 10,
                files: 64,
            },
            target: Duration::from_millis(250),
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

    pub fn limit(&self) -> WorkSize {
        self.limit
    }

    pub fn overdue(&self, now: Instant, oldest: Option<Instant>) -> bool {
        oldest.is_some_and(|start| now.saturating_duration_since(start) > self.target)
    }

    /// End-to-end completion includes reads, writes and time behind earlier
    /// requests. Reduce immediately when service slows; grow at most fourfold
    /// per observation so a briefly cached operation cannot reserve a huge tail.
    pub fn observe(&mut self, work: WorkSize, elapsed: Duration) {
        let elapsed = elapsed.max(Duration::from_micros(1)).as_nanos();
        let target = self.target.as_nanos();
        fn resized(current: u64, amount: u64, elapsed: u128, target: u128) -> u64 {
            if amount == 0 {
                return current;
            }
            (u128::from(amount).saturating_mul(target) / elapsed)
                .clamp(1, u128::from(current.saturating_mul(4))) as u64
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
        assert!(budget.overdue(start + Duration::from_secs(2), Some(start)));
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
}

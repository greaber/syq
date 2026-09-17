//! Bounded recovery of a body that progresses far more slowly than its peers.
//! Samples count time awaiting network data, excluding pacing and local writes.
use std::{
    collections::VecDeque,
    sync::Mutex,
    time::{Duration, Instant},
};

#[derive(Default)]
pub(super) struct Recovery {
    state: Mutex<State>,
}
#[derive(Default)]
struct State {
    samples: VecDeque<Sample>,
    credits: usize,
    active: bool,
}
struct Sample {
    length: u64,
    waited: Duration,
    finished: Instant,
}
pub(super) struct Retry<'a>(&'a Recovery);
impl Drop for Retry<'_> {
    fn drop(&mut self) {
        self.0.state.lock().unwrap().active = false;
    }
}
fn class(length: u64) -> u32 {
    u64::BITS - length.saturating_sub(1).leading_zeros()
}
impl Recovery {
    pub fn completed(&self, length: u64, waited: Duration, finished: Instant) {
        if length == 0 {
            return;
        }
        let mut state = self.state.lock().unwrap();
        if state.samples.len() == 64 {
            state.samples.pop_front();
        }
        state.samples.push_back(Sample {
            length,
            waited,
            finished,
        });
        // Fund at most one speculative restart per eight successful ranges.
        // Cap saved credit so a long healthy phase cannot fund a retry storm.
        state.credits = (state.credits + 1).min(64);
    }
    pub fn retry(&self, length: u64, started: Instant, waited: Duration) -> Option<Retry<'_>> {
        if length == 0 || waited < Duration::from_secs(1) {
            return None;
        }
        let mut state = self.state.lock().unwrap();
        if state.active || state.credits < 8 {
            return None;
        }
        // An earlier phase is not evidence that the current path is healthy.
        // Require comparable reads to finish during
        // this attempt, and use their upper decile rather than their fastest rate.
        let mut peers: Vec<_> = state
            .samples
            .iter()
            .filter(|s| s.finished >= started && class(s.length) == class(length))
            .map(|s| s.waited.as_secs_f64() * length as f64 / s.length as f64)
            .collect();
        if peers.len() < 8 {
            return None;
        }
        peers.sort_unstable_by(f64::total_cmp);
        // Leave room for ordinary variation before paying for another range.
        // The floor avoids reacting to nearly prebuffered or cached responses.
        let threshold = (2.0 * peers[(peers.len() * 9).div_ceil(10) - 1]).max(1.0);
        if waited.as_secs_f64() <= threshold {
            return None;
        }
        state.credits -= 8;
        state.active = true;
        Some(Retry(self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const MIB: u64 = 1024 * 1024;
    fn seed(recovery: &Recovery, count: usize, length: u64, wait: f64, finished: Instant) {
        for _ in 0..count {
            recovery.completed(length, Duration::from_secs_f64(wait), finished);
        }
    }
    #[test]
    fn only_contemporary_comparable_peers_can_trigger_recovery() {
        let recovery = Recovery::default();
        let now = Instant::now();
        seed(&recovery, 64, MIB, 0.1, now - Duration::from_secs(1));
        seed(&recovery, 64, MIB * 4, 0.1, now);
        assert!(recovery.retry(MIB, now, Duration::from_secs(20)).is_none());
        seed(&recovery, 7, MIB, 0.1, now);
        assert!(recovery.retry(MIB, now, Duration::from_secs(20)).is_none());
        seed(&recovery, 1, MIB, 0.1, now);
        assert!(recovery.retry(MIB, now, Duration::from_secs(2)).is_some());
    }
    #[test]
    fn uniformly_slow_reads_are_not_mistaken_for_stragglers() {
        let recovery = Recovery::default();
        let now = Instant::now();
        seed(&recovery, 32, MIB, 20.0, now);
        assert!(recovery.retry(MIB, now, Duration::from_secs(30)).is_none());
        assert!(recovery.retry(MIB, now, Duration::from_secs(81)).is_some());
    }
    #[test]
    fn recovery_is_serial_and_success_funded() {
        let recovery = Recovery::default();
        let now = Instant::now();
        seed(&recovery, 16, MIB, 0.1, now);
        let first = recovery.retry(MIB, now, Duration::from_secs(2)).unwrap();
        assert!(recovery.retry(MIB, now, Duration::from_secs(2)).is_none());
        drop(first);
        drop(recovery.retry(MIB, now, Duration::from_secs(2)).unwrap());
        assert!(recovery.retry(MIB, now, Duration::from_secs(2)).is_none());
        seed(&recovery, 8, MIB, 0.1, now);
        assert!(recovery.retry(MIB, now, Duration::from_secs(2)).is_some());
    }
    #[test]
    fn a_few_fast_completions_do_not_override_the_slow_majority() {
        let recovery = Recovery::default();
        let now = Instant::now();
        seed(&recovery, 16, MIB, 10.0, now);
        seed(&recovery, 8, MIB, 0.01, now);
        assert!(recovery.retry(MIB, now, Duration::from_secs(5)).is_none());
    }
}

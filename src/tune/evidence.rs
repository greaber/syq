//! Sequential evidence, independent of whether more work remains to experiment.
use std::time::Duration;
#[derive(Debug, serde::Serialize)]
pub(super) struct Score {
    pub rate: f64,
    pub seconds: f64,
    pub intervals: usize,
}

/// Consecutive usable intervals at a single active count. Live decisions
/// consume a whole window. History can also read overlapping windows.
#[derive(Default)]
pub(super) struct Evidence {
    intervals: std::collections::VecDeque<(f64, f64)>,
}

impl Evidence {
    pub fn clear(&mut self) {
        self.intervals.clear();
    }

    pub fn remaining(&self, window: Duration, partial: Duration) -> Duration {
        let collected: f64 = self.intervals.iter().map(|p| p.1).sum();
        window
            .saturating_sub(Duration::from_secs_f64(collected))
            .saturating_sub(partial)
    }

    pub fn push(&mut self, rate: f64, seconds: f64, base: f64) -> Option<Score> {
        self.observe(rate, seconds, base, super::SAMPLE)
    }

    pub fn observe(
        &mut self,
        rate: f64,
        seconds: f64,
        base: f64,
        window: Duration,
    ) -> Option<Score> {
        if !rate.is_finite() || rate < 0.0 || !seconds.is_finite() || seconds <= 0.0 {
            self.clear();
            return None;
        }
        self.intervals.push_back((rate, seconds));
        let window = window.as_secs_f64();
        let mut duration: f64 = self.intervals.iter().map(|p| p.1).sum();
        while self.intervals.len() > 2 && duration - self.intervals[0].1 >= window {
            duration -= self.intervals.pop_front().unwrap().1;
        }
        // Two or more consecutive nonzero readings below half the probe
        // baseline warrant early rollback. A zero can be batched reporting:
        // include it in the ordinary time-weighted window.
        let mut loss = true;
        let (mut elapsed, mut activity) = (0.0, 0.0);
        for (i, &(rate, seconds)) in self.intervals.iter().rev().enumerate() {
            elapsed += seconds;
            activity += rate * seconds;
            loss &= rate > 0.0 && rate < 0.5 * base;
            if i >= 1 && (elapsed >= window || (loss && elapsed >= window * 0.4)) {
                return Some(Score {
                    rate: activity / elapsed,
                    seconds: elapsed,
                    intervals: i + 1,
                });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rising_gain_does_not_need_a_plateau() {
        let mut evidence = Evidence::default();
        assert!(evidence.push(125.0, 2.5, 100.0).is_none());
        assert!(evidence.push(156.25, 2.5, 100.0).unwrap().rate > 125.0);
    }

    #[test]
    fn window_weights_elapsed_time_and_discards_interrupted_evidence() {
        let mut evidence = Evidence::default();
        assert!(evidence.push(20.0, 0.5, 100.0).is_none());
        assert!(evidence.push(f64::NAN, 0.5, 100.0).is_none());
        assert!(evidence.push(20.0, 0.5, 100.0).is_none());
        let score = evidence.push(120.0, 2.0, 100.0).unwrap();
        assert_eq!(
            (score.rate, score.seconds, score.intervals),
            (100.0, 2.5, 2)
        );
    }

    #[test]
    fn dramatic_loss_ends_before_ambiguous_change() {
        let mut severe = Evidence::default();
        let mut ambiguous = Evidence::default();
        assert!(severe.push(20.0, 0.5, 100.0).is_none());
        assert!(ambiguous.push(98.0, 0.5, 100.0).is_none());
        assert_eq!(severe.push(20.0, 0.5, 100.0).unwrap().rate, 20.0);
        assert!(ambiguous.push(102.0, 0.5, 100.0).is_none());
    }
}

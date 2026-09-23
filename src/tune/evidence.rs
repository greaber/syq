//! Sequential evidence, independent of whether more work remains to experiment.
#[derive(Debug, serde::Serialize)]
pub(super) struct Score {
    pub rate: f64,
    pub seconds: f64,
    pub intervals: usize,
}

#[derive(Default)]
pub(super) struct Evidence {
    intervals: std::collections::VecDeque<(f64, f64)>,
}

impl Evidence {
    pub fn clear(&mut self) {
        self.intervals.clear();
    }

    /// Consistent losses warrant shorter exposure as their cost increases.
    /// Use recent intervals so early warm-up cannot veto later clear evidence.
    pub fn push(&mut self, rate: f64, seconds: f64, base: f64) -> Option<Score> {
        if !rate.is_finite() || rate < 0.0 || !seconds.is_finite() || seconds <= 0.0 {
            self.clear();
            return None;
        }
        self.intervals.push_back((rate, seconds));
        let mut duration: f64 = self.intervals.iter().map(|p| p.1).sum();
        while self.intervals.len() > 2 && duration - self.intervals[0].1 >= 5.0 {
            duration -= self.intervals.pop_front().unwrap().1;
        }
        if base <= 0.0 || !base.is_finite() {
            return None;
        }
        let (mut elapsed, mut activity, mut low, mut high) = (0.0, 0.0, f64::INFINITY, 0.0_f64);
        for (i, (rate, seconds)) in self.intervals.iter().rev().enumerate() {
            elapsed += seconds;
            activity += rate * seconds;
            low = low.min(*rate);
            high = high.max(*rate);
            // Zero counters can be batched completion reports. Require the
            // longer exposure before interpreting complete silence as loss.
            if i >= 1
                && ((elapsed >= 1.0 && low > 0.0 && high < base * 0.5)
                    || (elapsed >= 2.5 && ((low > 0.0 && high < base * 0.8) || low > base * 1.2))
                    || (elapsed >= 5.0 && (high < base * 0.95 || low * 0.95 > base)))
            {
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
    fn dramatic_loss_ends_before_ambiguous_change() {
        let mut severe = Evidence::default();
        let mut ambiguous = Evidence::default();
        assert!(severe.push(20.0, 0.5, 100.0).is_none());
        assert!(ambiguous.push(98.0, 0.5, 100.0).is_none());
        assert_eq!(severe.push(20.0, 0.5, 100.0).unwrap().rate, 20.0);
        assert!(ambiguous.push(102.0, 0.5, 100.0).is_none());
    }
}

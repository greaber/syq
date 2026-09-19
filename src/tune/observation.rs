//! Sequential observations over short, nonoverlapping samples. Variation is
//! an empirical decision margin, not an IID/sequential confidence guarantee.
use std::collections::VecDeque;
use std::time::Duration;

#[derive(Clone, Copy, Debug)]
pub(super) struct Estimate {
    pub rate: f64,
    pub variation: f64,
    pub seconds: f64,
}

struct Sample {
    activity: f64,
    seconds: f64,
    outstanding_before: u64,
    outstanding_after: u64,
}

pub(super) struct Observation {
    samples: VecDeque<Sample>,
    minimum: f64,
    maximum: f64,
    outstanding: u64,
}

impl Observation {
    pub fn new(cadence: Duration, outstanding: u64) -> Self {
        Self {
            samples: VecDeque::new(),
            minimum: cadence.as_secs_f64() * 8.0,
            maximum: cadence.as_secs_f64() * 30.0,
            outstanding,
        }
    }

    pub fn minimum(&self) -> Duration {
        Duration::from_secs_f64(self.minimum)
    }
    pub fn maximum(&self) -> Duration {
        Duration::from_secs_f64(self.maximum)
    }

    pub fn reset(&mut self, outstanding: u64) {
        self.samples.clear();
        self.outstanding = outstanding;
    }

    pub fn push(
        &mut self,
        rate: f64,
        seconds: f64,
        outstanding: u64,
        contributing: bool,
        threshold: Option<(f64, f64)>,
    ) -> Option<Estimate> {
        if !contributing
            || !rate.is_finite()
            || !seconds.is_finite()
            || seconds <= 0.0
            || rate < 0.0
        {
            self.reset(outstanding);
            return None;
        }
        self.samples.push_back(Sample {
            activity: rate * seconds,
            seconds,
            outstanding_before: self.outstanding,
            outstanding_after: outstanding,
        });
        self.outstanding = outstanding;
        let mut elapsed: f64 = self.samples.iter().map(|s| s.seconds).sum();
        while self.samples.len() > 8 && elapsed - self.samples.front()?.seconds >= self.maximum {
            elapsed -= self.samples.pop_front()?.seconds;
        }
        if self.samples.len() < 8 || elapsed < self.minimum {
            return None;
        }
        let rate = self.samples.iter().map(|s| s.activity).sum::<f64>() / elapsed;
        if rate <= 0.0 {
            return None;
        }
        let half = self.samples.len() / 2;
        let mean = |start: usize, end: usize| {
            let samples = self.samples.iter().skip(start).take(end - start);
            let (activity, seconds) =
                samples.fold((0.0, 0.0), |(a, t), s| (a + s.activity, t + s.seconds));
            activity / seconds
        };
        let trend = (mean(0, half) - mean(half, self.samples.len())).abs();
        // Pair short bins before estimating variability, rather than treating
        // every byte/frame or polling event as independent evidence.
        let blocks: Vec<_> = (0..self.samples.len() - 1)
            .step_by(2)
            .map(|i| mean(i, i + 2))
            .collect();
        let average = blocks.iter().sum::<f64>() / blocks.len() as f64;
        let variance =
            blocks.iter().map(|v| (v - average).powi(2)).sum::<f64>() / (blocks.len() - 1) as f64;
        let variation = trend.max(2.0 * (variance / blocks.len() as f64).sqrt());
        let outstanding_growth = (self.samples.back()?.outstanding_after as f64
            - self.samples.front()?.outstanding_before as f64)
            .abs()
            / elapsed;
        if trend > 0.05 * rate || outstanding_growth > 0.05 * rate {
            return None;
        }
        let resolved = match threshold {
            Some((boundary, baseline_variation)) => {
                rate - variation > boundary + baseline_variation
                    || rate + variation < boundary - baseline_variation
            }
            // A baseline need not be precise to start exploring. Carry its
            // uncertainty into the comparison instead of waiting indefinitely
            // for a naturally bursty (for example paced) stream to look quiet.
            None => true,
        };
        resolved.then_some(Estimate {
            rate,
            variation,
            seconds: elapsed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn observer() -> Observation {
        Observation::new(Duration::from_millis(250), 0)
    }
    #[test]
    fn flat_old_workers_are_not_evidence_before_new_workers_contribute() {
        let mut o = observer();
        for _ in 0..24 {
            assert!(o.push(100.0, 0.25, 0, false, Some((105.0, 0.0))).is_none());
        }
        for i in 0..8 {
            let result = o.push(150.0, 0.25, 0, true, Some((105.0, 0.0)));
            assert_eq!(result.is_some(), i == 7);
        }
    }
    #[test]
    fn submission_growth_and_draining_are_not_stable_delivery() {
        for growing in [false, true] {
            let mut o = Observation::new(Duration::from_millis(250), if growing { 0 } else { 800 });
            for i in 1..=8 {
                let pending = if growing { i * 100 } else { 800 - i * 100 };
                assert!(o
                    .push(200.0, 0.25, pending, true, Some((100.0, 0.0)))
                    .is_none());
            }
        }
    }
    #[test]
    fn uncertain_or_trending_samples_do_not_force_a_score_at_a_deadline() {
        let mut o = observer();
        for i in 0..120 {
            assert!(o
                .push(
                    if i % 2 == 0 { 70.0 } else { 130.0 },
                    0.25,
                    0,
                    true,
                    Some((100.0, 0.0))
                )
                .is_none());
        }
        let mut o = observer();
        for i in 0..20 {
            assert!(o
                .push(100.0 + i as f64 * 10.0, 0.25, 0, true, None)
                .is_none());
        }
    }
    #[test]
    fn a_bursty_baseline_carries_uncertainty_into_the_comparison() {
        let mut o = observer();
        let mut baseline = None;
        for rate in [70.0, 70.0, 130.0, 130.0, 70.0, 70.0, 130.0, 130.0] {
            baseline = o.push(rate, 0.25, 0, true, None);
        }
        let baseline = baseline.unwrap();
        assert_eq!(baseline.rate, 100.0);
        assert!(baseline.variation > 30.0);
        o.reset(0);
        for _ in 0..30 {
            assert!(o
                .push(110.0, 0.25, 0, true, Some((105.0, baseline.variation)))
                .is_none());
        }
    }
    #[test]
    fn a_clear_gain_or_loss_can_finish_without_a_fixed_experiment_length() {
        for rate in [80.0, 150.0] {
            let mut o = observer();
            let mut result = None;
            for _ in 0..8 {
                result = o.push(rate, 0.25, 0, true, Some((105.0, 2.0)));
            }
            let e = result.unwrap();
            assert_eq!(e.rate, rate);
            assert_eq!(e.seconds, 2.0);
        }
    }
}

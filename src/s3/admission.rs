//! Adjust whole-object admission without interrupting requests already in flight.
use crate::tune::FILE_CREDIT;
use anyhow::Result;
use std::{sync::Arc, time::Duration};

const SAMPLE: Duration = Duration::from_millis(250);

// Object completions can arrive in batches even on a stationary path. Waiting
// for adjacent rates to agree discards partial batches, biases the score, and
// stretches the controller's sampling and backoff periods. Average every pair
// of eligible observations instead. The driver still requires 16 completions
// per observation and measures its actual elapsed time.
#[derive(Default)]
struct RateWindow {
    previous: Option<f64>,
    discard: bool,
}

impl RateWindow {
    fn reset(&mut self) {
        self.previous = None;
        self.discard = true;
    }

    fn push(&mut self, rate: f64) -> Option<f64> {
        if self.discard {
            self.discard = false;
            return None;
        }
        if let Some(previous) = self.previous.take() {
            Some((previous + rate) * 0.5)
        } else {
            self.previous = Some(rate);
            None
        }
    }
}

pub(super) struct Concurrency {
    pub initial: usize,
    pub maximum: Option<usize>,
    pub initial_probe_up: bool,
    pub requests: Option<Arc<super::tuning::Budget>>,
}

struct Probe {
    from: usize,
    baseline: f64,
    upward: bool,
    revisit: bool,
    confirming: bool,
}

struct Controller {
    limit: usize,
    maximum: usize,
    sampler: RateWindow,
    probe: Option<Probe>,
    upward: bool,
    hold: usize,
    lower: usize,
    upper: usize,
    scores: usize,
    failures: [u32; 2],
    revisit_at: [usize; 2],
    nearby: [bool; 2],
    reference: Option<f64>,
    changed_scores: usize,
    rate_variation: f64,
}

impl Controller {
    fn new(start: usize, maximum: usize, initial_probe_up: bool) -> Self {
        let mut sampler = RateWindow::default();
        sampler.reset();
        Self {
            limit: start.clamp(1, maximum),
            maximum,
            sampler,
            probe: None,
            upward: initial_probe_up,
            hold: 0,
            lower: 0,
            upper: maximum + 1,
            scores: 0,
            failures: [0; 2],
            revisit_at: [0; 2],
            nearby: [false; 2],
            reference: None,
            changed_scores: 0,
            rate_variation: 0.0,
        }
    }

    fn observe(
        &mut self,
        rate: f64,
        active: usize,
        queued: usize,
        measurement_work: usize,
    ) -> usize {
        // A decrease drains existing work before its measurement starts. Also
        // avoid learning from a drained queue. New probes need enough queued
        // work to measure them; an existing probe may still finish in the tail.
        if active != self.limit {
            self.sampler.reset();
            return self.limit;
        }
        if let Some(score) = self.sampler.push(rate) {
            let before = self.limit;
            self.scores += 1;
            if let Some(mut probe) = self.probe.take() {
                // Pay for more concurrency only when it improves throughput.
                // Prefer fewer objects only when measured speed holds: a
                // tolerated loss per step can accumulate into a large loss.
                let floor = if probe.upward { 1.02 } else { 1.0 };
                let direction = usize::from(probe.upward);
                if score > 0.0 && score >= probe.baseline * floor {
                    // A small apparent improvement can be ordinary variation.
                    // Require another successful score before accepting it;
                    // clearly better settings need no extra confirmation.
                    if probe.revisit
                        && !probe.confirming
                        && score < probe.baseline * (1.0 + 2.0 * self.rate_variation)
                    {
                        probe.confirming = true;
                        self.probe = Some(probe);
                        return self.limit;
                    }
                    if probe.revisit {
                        // A nearby probe found a change outside the old bounds.
                        // Resume the coarse search only in that direction.
                        if probe.upward {
                            self.upper = self.maximum + 1;
                        } else {
                            self.lower = 0;
                        }
                    }
                    self.failures[direction] = 0;
                    self.reference = Some(score);
                    self.changed_scores = 0;
                    if probe.upward {
                        self.lower = probe.from;
                    } else {
                        self.upper = probe.from;
                    }
                    self.upward = probe.upward;
                    self.hold = 0;
                } else {
                    if probe.upward {
                        self.upper = self.upper.min(self.limit);
                    } else {
                        self.lower = self.lower.max(self.limit);
                    }
                    self.failures[direction] = (self.failures[direction] + 1).min(3);
                    self.revisit_at[direction] = self.scores + (8 << self.failures[direction]);
                    self.reference = Some(probe.baseline);
                    self.changed_scores = 0;
                    self.limit = probe.from;
                    self.upward = !probe.upward;
                    self.hold = 1;
                }
            } else if self.hold > 0 {
                self.hold -= 1;
            } else if score > 0.0 && queued >= measurement_work.max(active.saturating_mul(2)) {
                self.observe_change(score);
                if self.limit == self.maximum {
                    self.upward = false;
                }
                if self.limit == 1 {
                    self.upward = true;
                }
                let mut candidate = self.candidate();
                if candidate == self.limit {
                    self.upward = !self.upward;
                    candidate = self.candidate();
                }
                let mut revisit = false;
                if candidate == self.limit {
                    // Once the bounds converge, only occasionally test outside
                    // them. Small steps limit the recurring exploration cost.
                    for upward in [self.upward, !self.upward] {
                        if self.scores >= self.revisit_at[usize::from(upward)] {
                            let step = self.limit.div_ceil(if upward { 2 } else { 4 });
                            let direction = usize::from(upward);
                            let nearby = self.nearby[direction];
                            // Alternate nearby and broader revisits. A broad
                            // step can jump over a newly improved optimum;
                            // tiny steps can be lost in normal rate variation.
                            let step = if nearby {
                                let boundary = if upward {
                                    self.upper.saturating_sub(self.limit)
                                } else {
                                    self.limit.saturating_sub(self.lower)
                                };
                                let variation_step =
                                    (self.limit as f64 * 2.0 * self.rate_variation).ceil() as usize;
                                step.min(boundary.max(variation_step))
                            } else {
                                step
                            };
                            let next = if upward {
                                (self.limit + step).min(self.maximum)
                            } else {
                                self.limit.saturating_sub(step).max(1)
                            };
                            if next != self.limit {
                                self.nearby[direction] = !nearby;
                                self.upward = upward;
                                candidate = next;
                                revisit = true;
                                break;
                            }
                        }
                    }
                }
                if candidate != self.limit {
                    self.probe = Some(Probe {
                        from: self.limit,
                        baseline: if revisit {
                            self.reference.unwrap_or(score)
                        } else {
                            score
                        },
                        upward: self.upward,
                        revisit,
                        confirming: false,
                    });
                    self.limit = candidate;
                }
            }
            if self.limit != before {
                self.sampler.reset();
                super::diagnostics::object_concurrency(before, self.limit, score);
            }
        }
        self.limit
    }
    fn observe_change(&mut self, score: f64) {
        if let Some(reference) = self.reference {
            if (score - reference).abs() > reference * 0.25 {
                self.changed_scores += 1;
                if self.changed_scores < 3 {
                    return;
                }
                // A sustained rate change invalidates both search bounds.
                // A capacity increase need not change the current rate, so
                // periodic probes remain necessary even without this signal.
                self.lower = 0;
                self.upper = self.maximum + 1;
                self.failures = [0; 2];
                self.revisit_at = [0; 2];
            } else {
                if reference > 0.0 {
                    self.rate_variation =
                        self.rate_variation * 0.9 + ((score - reference) / reference).abs() * 0.1;
                }
                self.reference = Some(reference * 0.9 + score * 0.1);
                self.changed_scores = 0;
                return;
            }
        }
        self.reference = Some(score);
        self.changed_scores = 0;
    }

    fn candidate(&self) -> usize {
        if self.upward {
            (self.limit * 2)
                .min((self.limit + self.upper) / 2)
                .min(self.maximum)
        } else {
            (self.limit / 2)
                .max((self.limit + self.lower).div_ceil(2))
                .max(1)
        }
    }
}

// Each object gets a runtime task so hashing and filesystem work can use more
// than one executor thread. JoinSet bounds live tasks and aborts them together
// when the copy is cancelled; detached uploads must never outlive the command.
pub(super) async fn parallel<T, F, Fut>(
    jobs: Vec<T>,
    concurrency: Concurrency,
    mut work: F,
) -> Result<()>
where
    F: FnMut(T) -> Fut,
    Fut: std::future::Future<Output = Result<Option<u64>>> + Send + 'static,
{
    let begin = || {
        let maximum = concurrency.maximum?;
        let initial = match &concurrency.requests {
            Some(requests) => requests.begin_objects(concurrency.initial)?,
            None => concurrency.initial,
        };
        Some(Controller::new(
            initial,
            maximum,
            // The request ramp already tested a higher setting. Try downward
            // first after it backed off instead of immediately repeating that
            // losing probe. This is a starting direction, not a lasting bound.
            concurrency.initial_probe_up
                && !concurrency
                    .requests
                    .as_ref()
                    .is_some_and(|requests| requests.rejected_increase()),
        ))
    };
    let mut controller = begin();
    let mut handoff_pending = controller.is_some() && concurrency.requests.is_some();
    let mut limit = controller.as_ref().map_or(concurrency.initial, |c| c.limit);
    let mut tasks = tokio::task::JoinSet::new();
    let mut jobs = jobs.into_iter();
    let mut interval = tokio::time::interval(SAMPLE);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut since = tokio::time::Instant::now();
    let mut activity = 0u64;
    let mut completed = 0usize;
    let mut error = None;
    loop {
        if handoff_pending && tasks.len() <= limit {
            // The old request cap stays in force until queued requests belong
            // to no more than the new number of live object tasks.
            concurrency
                .requests
                .as_ref()
                .unwrap()
                .finish_objects(concurrency.maximum.unwrap());
            handoff_pending = false;
        }
        while error.is_none() && tasks.len() < limit {
            let Some(job) = jobs.next() else { break };
            tasks.spawn(work(job));
        }
        if tasks.is_empty() {
            break;
        }
        tokio::select! {
            result = tasks.join_next() => {
                match result.unwrap().map_err(anyhow::Error::from).and_then(|r| r) {
                    Ok(Some(bytes)) => {
                        activity = activity.saturating_add(bytes.saturating_add(FILE_CREDIT));
                        completed += 1;
                    }
                    Ok(None) => {}, // Skips and failed copies are not transferred work.
                    Err(e) => { if error.is_none() { error = Some(e); } },
                }
            }
            _ = interval.tick(), if concurrency.maximum.is_some() && error.is_none() => {
                if controller.is_none() {
                    // Preserve the existing request ramp before taking over.
                    // Only one controller changes concurrency at a time.
                    controller = begin();
                    if let Some(controller) = &controller {
                        limit = controller.limit;
                        handoff_pending = concurrency.requests.is_some();
                    }
                    activity = 0;
                    completed = 0;
                    since = tokio::time::Instant::now();
                    continue;
                }
                let elapsed = since.elapsed();
                // Sparse completions need a longer window; one straggler must
                // not be treated as a reliable measurement of a setting.
                // The interval controls cadence. Processing jitter can make
                // consecutive ticks slightly less than SAMPLE apart; rejecting
                // those ticks needlessly doubles some measurement windows.
                if !elapsed.is_zero() && completed >= 16 {
                    limit = controller.as_mut().unwrap().observe(
                        activity as f64 / elapsed.as_secs_f64(), tasks.len(), jobs.len(),
                        (completed as f64 * 4.0 * SAMPLE.as_secs_f64() / elapsed.as_secs_f64()).ceil() as usize,
                    );
                    activity = 0;
                    completed = 0;
                    since = tokio::time::Instant::now();
                }
            }
        }
    }
    error.map_or(Ok(()), Err)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exercise(controller: &mut Controller, optimum: usize) {
        for _ in 0..500 {
            let active = controller.limit;
            let rate = if active <= optimum {
                active as f64
            } else {
                (optimum * optimum) as f64 / active as f64
            };
            controller.observe(rate, active, 10000, 16);
        }
        let settled = controller
            .probe
            .as_ref()
            .map_or(controller.limit, |probe| probe.from);
        assert!(
            settled.abs_diff(optimum) <= (optimum / 10).max(1),
            "optimum {optimum}, settled {settled}, active {}",
            controller.limit
        );
    }

    #[test]
    fn resetting_measurements_excludes_the_previous_setting() {
        let mut window = Controller::new(7, 256, false).sampler;
        assert!(window.push(100.0).is_none());
        assert!(window.push(10000.0).is_none());
        window.reset();
        assert!(window.push(20000.0).is_none());
        assert!(window.push(10.0).is_none());
        assert_eq!(window.push(20.0), Some(15.0));
    }

    #[test]
    fn scores_include_partial_completion_batches() {
        let mut sampler = Controller::new(7, 256, false).sampler;
        assert!(sampler.push(0.0).is_none()); // Discard the warmup observation.
        let counts = [28.0, 35.0, 35.0, 28.0, 35.0, 35.0];
        let scores: Vec<_> = counts
            .into_iter()
            .filter_map(|rate| sampler.push(rate))
            .collect();
        assert_eq!(scores.len(), 3);
        let measured = scores.iter().sum::<f64>() / scores.len() as f64;
        let delivered = counts.iter().sum::<f64>() / counts.len() as f64;
        assert!((measured - delivered).abs() < 1e-9);
    }

    #[test]
    fn learns_different_optima_and_revisits_changed_conditions() {
        for optimum in [3, 4, 9, 16, 24, 42, 64, 96, 128] {
            for initial_probe_up in [false, true] {
                exercise(&mut Controller::new(32, 256, initial_probe_up), optimum);
            }
        }
        let mut controller = Controller::new(32, 256, false);
        for optimum in [16, 64, 4] {
            exercise(&mut controller, optimum);
        }
    }

    // A fluid request model: requests finish at the aggregate rate, and a
    // reduction must drain the excess before the next setting can be measured.
    // Noise changes delivery, not just the controller's reported score.
    struct PathModel {
        active: usize,
        completions: f64,
        random: u64,
    }

    impl PathModel {
        fn sample(&mut self, controller: &mut Controller, optimum: usize, noise: f64) -> f64 {
            self.random ^= self.random << 13;
            self.random ^= self.random >> 7;
            self.random ^= self.random << 17;
            let jitter = 1.0 + noise * (2.0 * self.random as f64 / u64::MAX as f64 - 1.0);
            let rate = if self.active <= optimum {
                self.active as f64
            } else {
                (optimum * optimum) as f64 / self.active as f64
            } * 16.0
                * jitter;
            controller.observe(rate, self.active, 1_000_000, 16);
            if controller.limit >= self.active {
                self.active = controller.limit;
            } else {
                self.completions += rate * SAMPLE.as_secs_f64();
                let completed = self.completions.floor() as usize;
                self.completions -= completed as f64;
                self.active = self.active.saturating_sub(completed).max(controller.limit);
            }
            rate / (optimum as f64 * 16.0 * jitter)
        }
    }

    #[test]
    fn stationary_paths_spend_little_work_on_repeated_probes() {
        for optimum in [1, 2, 3, 4, 8, 32, 128, 256] {
            let mut controller = Controller::new(32, 256, false);
            let mut model = PathModel {
                active: 32,
                completions: 0.0,
                random: 17,
            };
            // Separate initial learning from the recurring cost under review.
            for _ in 0..1000 {
                model.sample(&mut controller, optimum, 0.0);
            }
            let fraction: f64 = (0..4000)
                .map(|_| model.sample(&mut controller, optimum, 0.0))
                .sum::<f64>()
                / 4000.0;
            assert!(
                fraction > 0.97,
                "optimum {optimum}: useful fraction {fraction}"
            );
        }
    }

    #[test]
    fn probes_discover_capacity_increases_without_a_rate_drop() {
        let mut controller = Controller::new(4, 256, false);
        let mut model = PathModel {
            active: 4,
            completions: 0.0,
            random: 251,
        };
        for _ in 0..2000 {
            model.sample(&mut controller, 4, 0.0);
        }
        // Increasing capacity does not change the rate at the old optimum.
        let recovered = (0..400).any(|_| model.sample(&mut controller, 128, 0.0) >= 0.9);
        assert!(recovered, "periodic probes must discover unused capacity");
        let fraction = (0..1000)
            .map(|_| model.sample(&mut controller, 128, 0.0))
            .sum::<f64>()
            / 1000.0;
        assert!(fraction > 0.95, "must sustain the improvement: {fraction}");
    }

    #[test]
    fn an_ambiguous_revisit_can_fail_its_confirmation() {
        let mut controller = Controller::new(32, 256, false);
        controller.limit = 36;
        controller.rate_variation = 0.1;
        controller.probe = Some(Probe {
            from: 32,
            baseline: 1000.0,
            upward: true,
            revisit: true,
            confirming: false,
        });
        // The first stable score looks 3% better, within the observed variation.
        for _ in 0..3 {
            assert_eq!(controller.observe(1030.0, 36, 10000, 16), 36);
        }
        assert!(controller.probe.as_ref().unwrap().confirming);
        // A subsequent score reverses that finding. Restore the accepted limit.
        controller.observe(990.0, 36, 10000, 16);
        assert_eq!(controller.observe(990.0, 36, 10000, 16), 32);
        assert!(controller.probe.is_none());
    }

    #[test]
    fn probes_discover_modest_capacity_changes() {
        for (before, after) in [(7, 8), (8, 9), (9, 8), (32, 36)] {
            let mut controller = Controller::new(32, 256, false);
            let mut model = PathModel {
                active: 32,
                completions: 0.0,
                random: 17,
            };
            for _ in 0..1000 {
                model.sample(&mut controller, before, 0.0);
            }
            // A modest change can put the optimum between the settled limit
            // and a broad probe. Repeatedly jumping over it must not strand us.
            for _ in 0..1000 {
                model.sample(&mut controller, after, 0.0);
            }
            let fraction = (0..1000)
                .map(|_| model.sample(&mut controller, after, 0.0))
                .sum::<f64>()
                / 1000.0;
            assert!(
                fraction > 0.97,
                "capacity {before}->{after}: useful fraction {fraction}"
            );
        }
    }

    #[test]
    fn adapts_to_noisy_changes_and_drains_decreases() {
        for seed in [17, 251, 902, 1009, 65537] {
            let mut controller = Controller::new(32, 256, false);
            let mut model = PathModel {
                active: 32,
                completions: 0.0,
                random: seed,
            };
            let mut delivered = 0.0;
            let mut possible = 0.0;
            for optimum in [96, 9, 42, 3] {
                for _ in 0..1000 {
                    delivered += model.sample(&mut controller, optimum, 0.2) * optimum as f64;
                    possible += optimum as f64;
                }
            }
            assert!(
                delivered / possible > 0.8,
                "seed {seed}: useful fraction {}",
                delivered / possible
            );
        }
    }

    #[test]
    fn draining_and_tail_samples_do_not_advance_the_policy() {
        let mut controller = Controller::new(32, 256, false);
        for _ in 0..50 {
            assert_eq!(controller.observe(1000.0, 33, 10000, 16), 32);
            assert_eq!(controller.observe(1000.0, 32, 2, 16), 32);
        }
        assert!(controller.probe.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn scheduler_learns_when_timer_processing_jitter_shortens_intervals() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let copy = parallel(
            (0..1024).collect(),
            Concurrency {
                initial: 4,
                maximum: Some(16),
                initial_probe_up: true,
                requests: None,
            },
            |_| {
                let active = active.clone();
                let peak = peak.clone();
                async move {
                    peak.fetch_max(active.fetch_add(1, SeqCst) + 1, SeqCst);
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    active.fetch_sub(1, SeqCst);
                    Ok(Some(1024))
                }
            },
        );
        tokio::pin!(copy);
        assert!(futures_util::poll!(&mut copy).is_pending());
        // Poll slightly after each timer deadline. The lateness diminishes
        // across successive deadlines, so their measured spacing is just
        // below 250ms despite the ticker maintaining its intended cadence.
        for _ in 0..900 {
            tokio::time::advance(Duration::from_micros(999)).await;
            assert!(futures_util::poll!(&mut copy).is_pending());
        }
        assert!(
            peak.load(SeqCst) >= 8,
            "three scheduled samples should suffice for the first probe"
        );
        copy.await.unwrap();
        assert_eq!(active.load(SeqCst), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn adaptive_scheduler_grows_without_losing_or_duplicating_jobs() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering::SeqCst},
            Arc,
        };
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let seen = Arc::new((0..16384).map(|_| AtomicUsize::new(0)).collect::<Vec<_>>());
        parallel(
            (0..16384).collect(),
            Concurrency {
                initial: 4,
                maximum: Some(16),
                initial_probe_up: false,
                requests: None,
            },
            |n| {
                let active = active.clone();
                let peak = peak.clone();
                let seen = seen.clone();
                async move {
                    peak.fetch_max(active.fetch_add(1, SeqCst) + 1, SeqCst);
                    tokio::time::sleep(Duration::from_millis(2)).await;
                    seen[n].fetch_add(1, SeqCst);
                    active.fetch_sub(1, SeqCst);
                    Ok(Some(1024))
                }
            },
        )
        .await
        .unwrap();
        assert!(peak.load(SeqCst) > 4 && peak.load(SeqCst) <= 16);
        assert_eq!(active.load(SeqCst), 0);
        assert!(seen.iter().all(|count| count.load(SeqCst) == 1));
    }

    #[tokio::test]
    async fn fixed_limit_and_failure_drain_started_jobs() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering::SeqCst},
            Arc,
        };
        let started = Arc::new(AtomicUsize::new(0));
        let finished = Arc::new(AtomicUsize::new(0));
        let error = parallel(
            (0..20).collect(),
            Concurrency {
                initial: 2,
                maximum: None,
                initial_probe_up: false,
                requests: None,
            },
            |n| {
                let started = started.clone();
                let finished = finished.clone();
                async move {
                    started.fetch_add(1, SeqCst);
                    if n == 0 {
                        anyhow::bail!("fixture failure");
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    finished.fetch_add(1, SeqCst);
                    Ok(Some(1))
                }
            },
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("fixture failure"));
        assert_eq!(started.load(SeqCst), 2);
        assert_eq!(finished.load(SeqCst), 1);
    }
}

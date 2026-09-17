//! Adjust whole-object admission without interrupting requests already in flight.
use crate::tune::FILE_CREDIT;
use anyhow::Result;
use std::{sync::Arc, time::Duration};

const SAMPLE: Duration = Duration::from_millis(250);

// Object completions can arrive in batches even on a stationary path. Waiting
// for adjacent rates to agree discards partial batches, biases the score, and
// stretches sampling and backoff periods. Combine each pair by elapsed time:
// sparse completions can extend a window, so equal weighting would overstate
// the contribution of a short burst. The driver requires 16 completions per
// observation and supplies its actual duration.
#[derive(Default)]
struct RateWindow {
    previous: Option<f64>,
    previous_fresh: Option<f64>,
    previous_elapsed: Duration,
    discard: bool,
}

impl RateWindow {
    fn reset(&mut self) {
        self.previous = None;
        self.previous_fresh = None;
        self.previous_elapsed = Duration::ZERO;
        self.discard = true;
    }

    fn seed(&mut self, rate: f64, elapsed: Duration) {
        self.previous = Some(rate);
        self.previous_fresh = None;
        self.previous_elapsed = elapsed;
    }

    fn remember(&mut self, rate: f64, fresh: f64, elapsed: Duration) {
        self.seed(rate, elapsed);
        self.previous_fresh = Some(fresh);
    }

    fn push(&mut self, rate: f64, fresh: f64, elapsed: Duration) -> Option<(f64, f64)> {
        if self.discard {
            self.discard = false;
            return None;
        }
        if let Some(previous) = self.previous.take() {
            let previous_fresh = self.previous_fresh.take().unwrap_or(previous);
            let seconds = elapsed.as_secs_f64();
            let previous_seconds = self.previous_elapsed.as_secs_f64();
            let total = previous_seconds + seconds;
            Some((
                (previous * previous_seconds + rate * seconds) / total,
                (previous_fresh * previous_seconds + fresh * seconds) / total,
            ))
        } else {
            self.remember(rate, fresh, elapsed);
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
    growth_baseline: Option<(usize, f64)>,
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
            growth_baseline: None,
        }
    }

    #[cfg(test)]
    fn observe(
        &mut self,
        rate: f64,
        active: usize,
        queued: usize,
        measurement_work: usize,
        old_rate: f64,
    ) -> usize {
        self.observe_window(rate, active, queued, measurement_work, old_rate, SAMPLE)
    }

    fn observe_window(
        &mut self,
        rate: f64,
        active: usize,
        queued: usize,
        measurement_work: usize,
        old_rate: f64,
        elapsed: Duration,
    ) -> usize {
        if rate > 0.0 && old_rate >= rate && !self.sampler.discard {
            // No completion in this window describes the new setting yet.
            self.sampler.previous = None;
            self.sampler.previous_fresh = None;
            return self.limit;
        }
        // A decrease drains existing work before its measurement starts. Also
        // avoid learning from a drained queue. New probes need enough queued
        // work to measure them; an existing probe may still finish in the tail.
        if active != self.limit {
            self.sampler.reset();
            return self.limit;
        }
        let fresh = (rate - old_rate).max(0.0);
        if let Some((score, fresh_score)) = self.sampler.push(rate, fresh, elapsed) {
            let before = self.limit;
            self.scores += 1;
            if let Some(mut probe) = self.probe.take() {
                // Pay for more concurrency only when it improves throughput.
                // Prefer fewer objects only when measured speed holds: a
                // tolerated loss per step can accumulate into a large loss.
                let floor = if probe.upward { 1.02 } else { 1.0 };
                let direction = usize::from(probe.upward);
                if fresh_score < probe.baseline * floor && score >= probe.baseline * floor {
                    // Old completions could explain the apparent gain. Neither
                    // accept it nor infer a loss from excluding that traffic.
                    // Keep the latest observation so the next one can resolve it.
                    self.sampler.remember(rate, fresh, elapsed);
                    self.probe = Some(probe);
                    return self.limit;
                }
                if fresh_score > 0.0 && fresh_score >= probe.baseline * floor {
                    let score = fresh_score;
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
                    // Preserve momentum after a strong gain. Only reconsider
                    // an increase whose gain was already sublinear, so one
                    // later noisy score cannot reverse useful rapid growth.
                    let growth = self.limit as f64 / probe.from as f64 - 1.0;
                    self.growth_baseline = (probe.upward
                        && score < probe.baseline * (1.0 + growth * 0.5))
                        .then_some((probe.from, probe.baseline));
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
            } else if fresh_score * 1.02 < score {
                // Establish a baseline whose old-work contribution is smaller
                // than the minimum gain we search for. Sparse late completions
                // can still be included without restarting the whole warmup.
                self.sampler.remember(rate, fresh, elapsed);
                return self.limit;
            } else if self.hold > 0 {
                self.hold -= 1;
            } else if score > 0.0 && queued >= measurement_work.max(active.saturating_mul(2)) {
                self.observe_change(score);
                if let Some((from, baseline)) = self.growth_baseline.take() {
                    // Use the latest score, not the transient burst that may
                    // have accepted the increase. A large concurrency increase
                    // with little gain can have crossed an intermediate peak.
                    // Keep the gain, but search that interval before growing.
                    let concurrency_gain = self.limit as f64 / from as f64 - 1.0;
                    self.upward = score >= baseline * (1.0 + concurrency_gain * 0.25);
                }
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
                self.growth_baseline = None;
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
    let begin = |remaining: usize| {
        let maximum = concurrency.maximum?;
        let initial = match &concurrency.requests {
            Some(requests) => requests.begin_objects(concurrency.initial)?,
            None => concurrency.initial,
        };
        let rejected = concurrency
            .requests
            .as_ref()
            .and_then(|r| r.rejected_limit());
        // A doubling with a small gain can hide an intermediate optimum.
        // Search that interval first; an actual loss still starts downward.
        let mut controller = Controller::new(
            initial,
            maximum,
            (concurrency.initial_probe_up && rejected.is_none())
                || concurrency
                    .requests
                    .as_ref()
                    .is_some_and(|r| r.probe_preserved_rate()),
        );
        if let Some(requests) = &concurrency.requests {
            // Reuse a full-count score only at the same limit. If an immediate
            // probe is not justified, it supplies the first baseline observation.
            if let Some((rate, elapsed)) = requests.object_rate(initial) {
                controller.sampler.seed(rate, elapsed);
            }
            // The ramp may also have demonstrated that fewer requests lose
            // throughput. Revisit that bound normally if conditions change.
            controller.lower = requests.slower_limit().min(initial.saturating_sub(1));
        }
        if let Some(rejected) = rejected {
            // Reuse the request ramp's result instead of immediately retrying
            // the same losing setting. Normal revisits can reopen this bound.
            controller.upper = controller.upper.min(rejected.max(initial + 1));
        }
        // A full-count request score at this same limit can start the first
        // upward probe without another baseline. Keep normal warmup and fresh-
        // work checks for the probe itself, and enough queued work to measure it.
        if controller.upward {
            if let Some(rate) = controller.sampler.previous {
                let candidate = controller.candidate();
                if candidate > initial && remaining >= candidate.saturating_mul(2) {
                    controller.probe = Some(Probe {
                        from: initial,
                        baseline: rate,
                        upward: true,
                        revisit: false,
                        confirming: false,
                    });
                    controller.limit = candidate;
                    controller.sampler.reset();
                    super::diagnostics::object_concurrency(initial, candidate, rate);
                }
            }
        }
        Some(controller)
    };
    let mut controller = begin(jobs.len());
    let mut handoff_pending = controller.is_some() && concurrency.requests.is_some();
    let mut limit = controller.as_ref().map_or(concurrency.initial, |c| c.limit);
    let mut tasks = tokio::task::JoinSet::new();
    let mut jobs = jobs.into_iter();
    let mut interval = tokio::time::interval(SAMPLE);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut since = tokio::time::Instant::now();
    let mut activity = 0u64;
    let mut completed = 0usize;
    let mut generation = 0u64;
    let mut old_activity = 0u64;
    let mut error = None;
    let mut observations = concurrency
        .maximum
        .and_then(|_| super::diagnostics::ObjectWindows::new());
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
        // While the request ramp is in charge, prepare only one job beyond
        // its current capacity. That waiter signals demand without starting
        // a queue that must drain if the ramp backs off.
        let preparation_limit = if controller.is_none() && concurrency.maximum.is_some() {
            concurrency
                .requests
                .as_ref()
                .map_or(limit, |requests| limit.min(requests.preparation_limit()))
        } else {
            limit
        };
        while error.is_none() && tasks.len() < preparation_limit {
            let Some(job) = jobs.next() else { break };
            let prepared = generation;
            let future = work(job);
            tasks.spawn(async move { (prepared, future.await) });
        }
        if tasks.is_empty() {
            break;
        }
        tokio::select! {
            result = tasks.join_next() => {
                let result = result.unwrap();
                if let (Some(observations), Ok((prepared, result))) = (&mut observations, &result) {
                    observations.completed(*prepared,
                        result.as_ref().ok().and_then(|bytes| *bytes)
                            .map(|bytes| bytes.saturating_add(FILE_CREDIT)));
                }
                match result.map_err(anyhow::Error::from)
                    .and_then(|(prepared, result)| result.map(|bytes| (prepared, bytes))) {
                    Ok((prepared, Some(bytes))) => {
                        let work = bytes.saturating_add(FILE_CREDIT);
                        if prepared != generation {
                            old_activity = old_activity.saturating_add(work);
                        }
                        activity = activity.saturating_add(work);
                        completed += 1;
                    }
                    Ok((_, None)) => {}, // Skips and failed copies are not transferred work.
                    Err(e) => { if error.is_none() { error = Some(e); } },
                }
            }
            _ = interval.tick(), if concurrency.maximum.is_some() && error.is_none() => {
                if controller.is_none() {
                    // Preserve the existing request ramp before taking over.
                    // Only one controller changes concurrency at a time.
                    controller = begin(jobs.len());
                    if let Some(controller) = &controller {
                        generation += 1;
                        if let Some(observations) = &mut observations {
                            observations.changed();
                        }
                        limit = controller.limit;
                        handoff_pending = concurrency.requests.is_some();
                    }
                    activity = 0;
                    completed = 0;
                    old_activity = 0;
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
                    if let Some(observations) = &mut observations {
                        let controller = controller.as_ref().unwrap();
                        observations.sample(super::diagnostics::ObjectWindow {
                            limit, active: tasks.len(), queued: jobs.len(),
                            completed, activity, elapsed,
                            warmup: controller.sampler.discard || old_activity == activity,
                            previous_rate: controller.sampler.previous,
                            probe_from: controller.probe.as_ref().map(|probe| probe.from),
                            probe_baseline: controller.probe.as_ref().map(|probe| probe.baseline),
                        });
                    }
                    let before = limit;
                    limit = controller.as_mut().unwrap().observe_window(
                        activity as f64 / elapsed.as_secs_f64(), tasks.len(), jobs.len(),
                        (completed as f64 * 4.0 * SAMPLE.as_secs_f64() / elapsed.as_secs_f64()).ceil() as usize,
                        old_activity as f64 / elapsed.as_secs_f64(),
                        elapsed,
                    );
                    if limit != before {
                        generation += 1;
                        if let Some(observations) = &mut observations {
                            observations.changed();
                        }
                    }
                    activity = 0;
                    completed = 0;
                    old_activity = 0;
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
            controller.observe(rate, active, 10000, 16, 0.0);
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
        assert!(window.push(100.0, 100.0, SAMPLE).is_none());
        assert!(window.push(10000.0, 10000.0, SAMPLE).is_none());
        window.reset();
        assert!(window.push(20000.0, 20000.0, SAMPLE).is_none());
        assert!(window.push(10.0, 10.0, SAMPLE).is_none());
        assert_eq!(window.push(20.0, 20.0, SAMPLE), Some((15.0, 15.0)));
    }

    #[test]
    fn old_response_bursts_cannot_accept_a_losing_increase() {
        let mut controller = Controller::new(256, 512, true);
        controller.upper = 512;
        for _ in 0..3 {
            controller.observe(302.6, 256, 10000, 16, 0.0);
        }
        assert_eq!(controller.limit, 384);
        // These rates reproduce a delayed old response wave followed by slower
        // fresh completions. Including 452.5 would falsely accept the increase.
        assert_eq!(controller.observe(150.7, 384, 10000, 16, 150.7), 384);
        assert_eq!(controller.observe(452.5, 384, 10000, 16, 452.5), 384);
        assert_eq!(controller.observe(184.2, 384, 10000, 16, 0.0), 384);
        assert_eq!(controller.observe(193.9, 384, 10000, 16, 0.0), 256);
    }

    #[test]
    fn a_quiet_fresh_window_can_be_part_of_a_useful_probe() {
        let mut controller = Controller::new(256, 1024, true);
        for _ in 0..3 {
            controller.observe(280.0, 256, 10000, 16, 0.0);
        }
        assert_eq!(controller.limit, 512);
        // A healthy HTTP fixture returned 32 fresh responses in one window,
        // then 224 in the next. Rejecting its first window below half the
        // baseline cut useful concurrency and increased the copy time.
        controller.observe(300.0, 512, 10000, 16, 300.0);
        assert_eq!(controller.observe(75.5, 512, 10000, 16, 0.0), 512);
        assert!(controller.probe.is_some());
        assert_eq!(controller.observe(527.0, 512, 10000, 16, 0.0), 512);
        assert!(controller.probe.is_none());
        assert_eq!(controller.lower, 256);
    }

    #[test]
    fn old_only_windows_cannot_reject_an_unmeasured_probe() {
        let mut controller = Controller::new(256, 512, true);
        controller.upper = 512;
        for _ in 0..3 {
            controller.observe(300.0, 256, 10000, 16, 0.0);
        }
        for _ in 0..4 {
            assert_eq!(controller.observe(100.0, 384, 10000, 16, 100.0), 384);
            assert!(controller.probe.is_some());
        }
        controller.observe(360.0, 384, 10000, 16, 0.0);
        assert_eq!(controller.observe(360.0, 384, 10000, 16, 0.0), 384);
        assert!(controller.probe.is_none());
    }

    #[test]
    fn sparse_old_completions_do_not_delay_clear_decisions() {
        let mut controller = Controller::new(256, 512, true);
        controller.upper = 512;
        controller.sampler.seed(300.0, SAMPLE);
        assert_eq!(controller.observe(300.0, 256, 10000, 16, 300.0), 256);
        assert_eq!(controller.observe(300.0, 256, 10000, 16, 2.0), 384);
        assert_eq!(controller.observe(300.0, 384, 10000, 16, 300.0), 384);
        assert_eq!(controller.observe(120.0, 384, 10000, 16, 0.0), 384);
        assert_eq!(controller.observe(115.0, 384, 10000, 16, 5.0), 256);
    }

    #[test]
    fn uncertain_old_work_does_not_reject_a_useful_increase() {
        let mut controller = Controller::new(256, 512, true);
        controller.upper = 512;
        for _ in 0..3 {
            controller.observe(300.0, 256, 10000, 16, 0.0);
        }
        assert_eq!(controller.limit, 384);
        controller.observe(300.0, 384, 10000, 16, 300.0);
        controller.observe(360.0, 384, 10000, 16, 120.0);
        controller.observe(360.0, 384, 10000, 16, 0.0);
        assert!(controller.probe.is_some());
        assert_eq!(controller.observe(360.0, 384, 10000, 16, 0.0), 384);
        assert!(controller.probe.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn tuning_continues_while_an_old_job_is_still_pending() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let copy_peak = peak.clone();
        let copy_gate = gate.clone();
        let copy = tokio::spawn(async move {
            parallel(
                (0..2048).collect(),
                Concurrency {
                    initial: 4,
                    maximum: Some(16),
                    initial_probe_up: true,
                    requests: None,
                },
                move |job| {
                    let active = active.clone();
                    let peak = copy_peak.clone();
                    let gate = copy_gate.clone();
                    async move {
                        peak.fetch_max(active.fetch_add(1, SeqCst) + 1, SeqCst);
                        if job == 0 {
                            let _permit = gate.acquire().await.unwrap();
                        }
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        active.fetch_sub(1, SeqCst);
                        Ok(Some(1024))
                    }
                },
            )
            .await
        });
        tokio::time::sleep(Duration::from_secs(2)).await;
        let peak_before_old_job_finished = peak.load(SeqCst);
        gate.add_permits(1);
        copy.await.unwrap().unwrap();
        assert!(peak_before_old_job_finished > 4);
    }

    #[test]
    fn inherited_request_score_still_excludes_the_handoff_warmup() {
        let mut controller = Controller::new(32, 256, true);
        controller.sampler.seed(1000.0, SAMPLE);
        assert_eq!(controller.observe(100000.0, 32, 10000, 16, 0.0), 32);
        assert_eq!(controller.observe(1000.0, 32, 10000, 16, 0.0), 64);
        assert_eq!(controller.probe.as_ref().unwrap().baseline, 1000.0);
    }

    #[test]
    fn a_short_burst_cannot_outweigh_a_long_slow_window() {
        for reverse in [false, true] {
            let mut samples = [(960.0, SAMPLE), (16.0 / 1.5, Duration::from_millis(1500))];
            if reverse {
                samples.reverse();
            }
            let mut sampler = RateWindow::default();
            assert!(sampler
                .push(samples[0].0, samples[0].0 * 0.5, samples[0].1)
                .is_none());
            let (total, fresh) = sampler
                .push(samples[1].0, samples[1].0 * 0.5, samples[1].1)
                .unwrap();
            assert!((total - 256.0 / 1.75).abs() < 1e-9);
            assert!((fresh - 128.0 / 1.75).abs() < 1e-9);
        }
        let mut controller = Controller::new(256, 1024, true);
        for _ in 0..3 {
            controller.observe(475.0, 256, 10000, 16, 0.0);
        }
        assert_eq!(controller.limit, 512);
        controller.observe(475.0, 512, 10000, 16, 475.0); // Warmup.
        controller.observe_window(960.0, 512, 10000, 16, 0.0, SAMPLE);
        assert_eq!(
            controller.observe_window(16.0 / 1.5, 512, 10000, 16, 0.0, Duration::from_millis(1500)),
            256
        );
    }

    #[test]
    fn scores_include_partial_completion_batches() {
        let mut sampler = Controller::new(7, 256, false).sampler;
        assert!(sampler.push(0.0, 0.0, SAMPLE).is_none()); // Discard the warmup observation.
        let counts = [28.0, 35.0, 35.0, 28.0, 35.0, 35.0];
        let scores: Vec<_> = counts
            .into_iter()
            .filter_map(|rate| sampler.push(rate, rate, SAMPLE))
            .collect();
        assert_eq!(scores.len(), 3);
        let measured = scores.iter().map(|(score, _)| score).sum::<f64>() / scores.len() as f64;
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
            controller.observe(rate, self.active, 1_000_000, 16, 0.0);
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
    fn small_upward_gains_refine_the_interval_before_growing_again() {
        for (probe_rate, later_rate, next) in [
            (1040.0, 1040.0, 96),
            (1300.0, 1040.0, 96),
            (1400.0, 1400.0, 192),
            (1600.0, 1040.0, 192),
        ] {
            let mut controller = Controller::new(64, 256, true);
            for _ in 0..3 {
                controller.observe(1000.0, 64, 10000, 16, 0.0);
            }
            assert_eq!(controller.limit, 128);
            for _ in 0..3 {
                controller.observe(probe_rate, 128, 10000, 16, 0.0);
            }
            // Both gains are kept. Only the next search direction differs.
            assert_eq!(controller.limit, 128);
            assert!(controller.probe.is_none());
            assert_eq!(controller.lower, 64);
            controller.observe(later_rate, 128, 10000, 16, 0.0);
            assert_eq!(controller.observe(later_rate, 128, 10000, 16, 0.0), next);
        }
    }

    #[test]
    fn intermediate_optimum_is_found_before_repeated_upward_probes() {
        let mut controller = Controller::new(64, 256, false);
        controller.lower = 32;
        controller.upper = 128;
        let mut model = PathModel {
            active: 64,
            completions: 0.0,
            random: 251,
        };
        // The request ramp rejected 128, but the optimum lies above 64.
        // Finding a small gain at 96 should lead to testing 80, rather than
        // spending a short copy probing 112 and returning to 96.
        let found = (0..20).any(|_| model.sample(&mut controller, 80, 0.0) >= 0.99);
        assert!(found, "intermediate optimum was not found promptly");
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
    fn an_inherited_request_bound_can_reopen() {
        let mut controller = Controller::new(64, 256, false);
        controller.upper = 128;
        let mut model = PathModel {
            active: 64,
            completions: 0.0,
            random: 251,
        };
        // A request probe previously rejected 128. If the path now has more
        // capacity, that hint must not become a permanent request cap.
        let recovered = (0..400).any(|_| model.sample(&mut controller, 256, 0.0) >= 0.9);
        assert!(recovered);
        assert!(controller.limit > 128);
    }

    #[test]
    fn an_inherited_slower_setting_does_not_prevent_decreasing_concurrency() {
        let mut controller = Controller::new(256, 256, false);
        controller.lower = 128;
        let mut model = PathModel {
            active: 256,
            completions: 0.0,
            random: 251,
        };
        // The request ramp established that 128 was slower than 256. The
        // first object probe should refine that interval rather than halve
        // concurrency again. A later capacity loss must still escape it.
        for _ in 0..3 {
            model.sample(&mut controller, 256, 0.0);
        }
        assert!(controller.limit > 128);
        let recovered = (0..400).any(|_| model.sample(&mut controller, 32, 0.0) >= 0.9);
        assert!(
            recovered,
            "an inherited lower bound must remain revisitable"
        );
        let fraction = (0..1000)
            .map(|_| model.sample(&mut controller, 32, 0.0))
            .sum::<f64>()
            / 1000.0;
        assert!(fraction > 0.95, "must sustain the recovery: {fraction}");
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
            assert_eq!(controller.observe(1030.0, 36, 10000, 16, 0.0), 36);
        }
        assert!(controller.probe.as_ref().unwrap().confirming);
        // A subsequent score reverses that finding. Restore the accepted limit.
        controller.observe(990.0, 36, 10000, 16, 0.0);
        assert_eq!(controller.observe(990.0, 36, 10000, 16, 0.0), 32);
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
            assert_eq!(controller.observe(1000.0, 33, 10000, 16, 0.0), 32);
            assert_eq!(controller.observe(1000.0, 32, 2, 16, 0.0), 32);
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

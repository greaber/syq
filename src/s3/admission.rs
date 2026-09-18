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
    probe_completed: usize,
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
            probe_completed: 0,
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
        // Count-independent policy tests supply enough fresh completions.
        // Count-sensitive tests call observe_window with explicit completions.
        if self.probe.is_some() && old_rate < rate {
            self.probe_completed = self.probe_completed.saturating_add(active);
        }
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
                    if probe.upward && self.probe_completed < self.limit {
                        // The fastest replies of a new generation can arrive
                        // first. Wait for a full count before accepting a gain,
                        // while still rejecting measured losses promptly.
                        self.sampler.remember(rate, fresh, elapsed);
                        self.probe = Some(probe);
                        return self.limit;
                    }
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
                self.probe_completed = 0;
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
    let mut fresh_completed = 0usize;
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
                        } else {
                            fresh_completed += 1;
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
                    fresh_completed = 0;
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
                    let controller = controller.as_mut().unwrap();
                    controller.probe_completed = controller.probe_completed.saturating_add(fresh_completed);
                    limit = controller.observe_window(
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
                    fresh_completed = 0;
                    since = tokio::time::Instant::now();
                }
            }
        }
    }
    error.map_or(Ok(()), Err)
}

#[cfg(test)]
mod tests;

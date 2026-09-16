//! Adjust whole-object admission without interrupting requests already in flight.
use crate::tune::{Sampler, FILE_CREDIT};
use anyhow::Result;
use std::time::Duration;

const SAMPLE: Duration = Duration::from_millis(250);

pub(super) struct Concurrency {
    pub initial: usize,
    pub maximum: Option<usize>,
}

struct Probe {
    from: usize,
    baseline: f64,
    upward: bool,
}

struct Controller {
    limit: usize,
    maximum: usize,
    sampler: Sampler,
    probe: Option<Probe>,
    upward: bool,
    hold: usize,
    lower: usize,
    upper: usize,
    age: usize,
}

impl Controller {
    fn new(start: usize, maximum: usize) -> Self {
        let mut sampler = Sampler::default();
        sampler.reset();
        Self {
            limit: start.clamp(1, maximum),
            maximum,
            sampler,
            probe: None,
            upward: false,
            hold: 0,
            lower: 0,
            upper: maximum + 1,
            age: 0,
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
            self.age += 1;
            if self.age >= 24 {
                // Bounds from old conditions guide probes only temporarily.
                self.lower = 0;
                self.upper = self.maximum + 1;
                self.age = 0;
            }
            if let Some(probe) = self.probe.take() {
                // Pay for more concurrency only when it improves throughput.
                // Prefer fewer objects only when measured speed holds: a
                // tolerated loss per step can accumulate into a large loss.
                let floor = if probe.upward { 1.02 } else { 1.0 };
                if score > 0.0 && score >= probe.baseline * floor {
                    if probe.upward {
                        self.lower = probe.from;
                    } else {
                        self.upper = probe.from;
                    }
                    self.upward = probe.upward;
                    self.hold = 0;
                } else {
                    if probe.upward {
                        self.upper = self.limit;
                    } else {
                        self.lower = self.limit;
                    }
                    self.limit = probe.from;
                    self.upward = !probe.upward;
                    self.hold = 1;
                }
            } else if self.hold > 0 {
                self.hold -= 1;
            } else if score > 0.0 && queued >= measurement_work.max(active.saturating_mul(2)) {
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
                if candidate != self.limit {
                    self.probe = Some(Probe {
                        from: self.limit,
                        baseline: score,
                        upward: self.upward,
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
    let mut controller = concurrency
        .maximum
        .map(|maximum| Controller::new(concurrency.initial, maximum));
    let mut limit = concurrency.initial;
    let mut tasks = tokio::task::JoinSet::new();
    let mut jobs = jobs.into_iter();
    let mut interval = tokio::time::interval(SAMPLE);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut since = tokio::time::Instant::now();
    let mut activity = 0u64;
    let mut completed = 0usize;
    let mut error = None;
    loop {
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
            _ = interval.tick(), if controller.is_some() && error.is_none() => {
                let elapsed = since.elapsed();
                // Sparse completions need a longer window; one straggler must
                // not be treated as a reliable measurement of a setting.
                if elapsed >= SAMPLE && completed >= 16 {
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
    fn learns_different_optima_and_revisits_changed_conditions() {
        for optimum in [3, 4, 9, 16, 24, 42, 64, 96, 128] {
            exercise(&mut Controller::new(32, 256), optimum);
        }
        let mut controller = Controller::new(32, 256);
        for optimum in [16, 64, 4] {
            exercise(&mut controller, optimum);
        }
    }

    #[test]
    fn draining_and_tail_samples_do_not_advance_the_policy() {
        let mut controller = Controller::new(32, 256);
        for _ in 0..50 {
            assert_eq!(controller.observe(1000.0, 33, 10000, 16), 32);
            assert_eq!(controller.observe(1000.0, 32, 2, 16), 32);
        }
        assert!(controller.probe.is_none());
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

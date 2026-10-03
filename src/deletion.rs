//! Deletion admission is measured separately from payload transfers.
use crate::tune::{Policy, Sampler};
use std::time::{Duration, Instant};

pub(crate) const SAMPLE: Duration = Duration::from_millis(250);
pub(crate) const FILESYSTEM_START: usize = 32;

#[derive(Clone, Copy)]
pub(crate) struct Concurrency {
    pub initial: usize,
    pub maximum: usize,
    pub automatic: bool,
    pub startup_doubling: bool,
}

impl Concurrency {
    pub fn filesystem(workers: usize) -> Self {
        if workers != 0 {
            return Self {
                initial: workers,
                maximum: workers,
                automatic: false,
                startup_doubling: false,
            };
        }
        // Recursive removal pins directory handles in its bounded queue. Leave
        // room for those handles, running workers and the rest of the process.
        let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
        let maximum = if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) } == 0 {
            (unsafe { limit.assume_init() }.rlim_cur.saturating_sub(64) / 4).clamp(1, 256) as usize
        } else {
            32
        };
        Self {
            initial: FILESYSTEM_START.min(maximum),
            maximum,
            automatic: true,
            // The existing filesystem pool already starts with useful parallelism.
            // Refine it gradually; doubling briefly hurts contended directories.
            startup_doubling: false,
        }
    }

    pub fn s3(args: &crate::cli::Args) -> Self {
        let fixed = args.tuning_options.and_then(|t| t.s3_requests);
        let maximum = fixed.unwrap_or(256).min(
            args.resource_limits
                .as_ref()
                .and_then(|l| l.s3_requests)
                .unwrap_or(usize::MAX),
        );
        Self {
            initial: fixed.unwrap_or(10).min(maximum),
            maximum,
            automatic: fixed.is_none(),
            startup_doubling: true,
        }
    }
}

pub(crate) struct Control {
    policy: Policy,
    automatic: bool,
    sampler: Sampler,
    completed: u64,
    elapsed: Duration,
}

impl Control {
    pub fn new(concurrency: Concurrency) -> Self {
        let mut sampler = Sampler::default();
        sampler.reset();
        Self {
            policy: if concurrency.startup_doubling {
                Policy::new(concurrency.initial, 1, concurrency.maximum)
            } else {
                Policy::refine(concurrency.initial, 1, concurrency.maximum)
            },
            automatic: concurrency.automatic,
            sampler,
            completed: 0,
            elapsed: Duration::ZERO,
        }
    }

    pub fn limit(&self) -> usize {
        self.policy.n
    }

    /// Samples contain successful entries, never their byte sizes or failed
    /// attempts. Callers exclude idle time and tell us when their queue drains.
    pub fn observe(&mut self, completed: u64, elapsed: Duration, backlogged: bool) -> usize {
        if !self.automatic {
            return self.limit();
        }
        if !backlogged {
            self.completed = 0;
            self.elapsed = Duration::ZERO;
            self.sampler.reset();
            return self.limit();
        }
        self.completed += completed;
        self.elapsed += elapsed;
        if self.elapsed < SAMPLE || self.completed < 16 {
            return self.limit();
        }
        let rate = self.completed as f64 / self.elapsed.as_secs_f64();
        self.completed = 0;
        self.elapsed = Duration::ZERO;
        if let Some(score) = self.sampler.push(rate) {
            let before = self.limit();
            self.policy.observe(score);
            self.policy.activated();
            if self.limit() != before {
                self.sampler.reset();
                #[cfg(debug_assertions)]
                if std::env::var_os("SYQ_TEST_DELETE_TUNING").is_some() {
                    eprintln!(
                        "syq: deletion workers {before} -> {} ({score:.0} entries/s)",
                        self.limit()
                    );
                }
            }
        }
        self.limit()
    }
}

/// Reuse endpoint-local threads across prune batches. Pool construction and
/// control-connection round trips do not enter filesystem throughput samples.
pub(crate) struct Batch {
    control: Control,
    pool: Option<rayon::ThreadPool>,
}

impl Default for Batch {
    fn default() -> Self {
        Self::new(FILESYSTEM_START)
    }
}

impl Batch {
    pub fn new(initial: usize) -> Self {
        let mut concurrency = Concurrency::filesystem(0);
        concurrency.initial = initial.clamp(1, concurrency.maximum);
        Self {
            control: Control::new(concurrency),
            pool: None,
        }
    }

    /// Keep the first samples bounded when starting with little parallelism.
    pub fn chunk_size(&self) -> usize {
        (self.control.limit() * 32).min(1000)
    }

    pub fn run<T: Sync, R: Send>(
        &mut self,
        items: &[T],
        work: impl Fn(&T) -> R + Sync,
        succeeded: impl Fn(&R) -> bool,
    ) -> anyhow::Result<Vec<R>> {
        // Avoid creating a pool for a few entries and exclude the short tail
        // from the next batch's measurement.
        if items.len() < 32 {
            self.control.observe(0, Duration::ZERO, false);
            return Ok(items.iter().map(work).collect());
        }
        let workers = self.control.limit().min(items.len());
        if workers == 1 {
            let start = Instant::now();
            let results: Vec<_> = items.iter().map(work).collect();
            self.control.observe(
                results.iter().filter(|r| succeeded(r)).count() as u64,
                start.elapsed(),
                true,
            );
            return Ok(results);
        }
        if self
            .pool
            .as_ref()
            .is_none_or(|p| p.current_num_threads() != workers)
        {
            self.pool = Some(
                rayon::ThreadPoolBuilder::new()
                    .num_threads(workers)
                    .thread_name(|n| format!("syq-delete-{n}"))
                    .build()?,
            );
        }
        let start = Instant::now();
        use rayon::prelude::*;
        let results: Vec<_> = self
            .pool
            .as_ref()
            .unwrap()
            // Keep coarse shares as in the existing metadata pool. Splitting
            // a cheap unlink into many Rayon jobs costs throughput on XFS.
            .install(|| {
                items
                    .par_chunks(items.len().div_ceil(workers))
                    .flat_map_iter(|chunk| chunk.iter().map(&work))
                    .collect()
            });
        self.control.observe(
            results.iter().filter(|r| succeeded(r)).count() as u64,
            start.elapsed(),
            items.len() >= workers * 2,
        );
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deletion_control_finds_parallelism_and_rejects_contention() {
        for (initial, startup_doubling) in [(1, false), (4, false), (4, true)] {
            let mut control = Control::new(Concurrency {
                initial,
                maximum: 64,
                automatic: true,
                startup_doubling,
            });
            let mut highest = 0;
            for _ in 0..120 {
                let n = control.limit();
                highest = highest.max(n);
                let rate = if n <= 16 { n * 100 } else { 1600 * 16 / n };
                control.observe(rate as u64, Duration::from_secs(1), true);
            }
            assert!(highest > 16, "must test higher concurrency");
            // Multiplicative probes need not land on exactly 16, and a probe
            // may still be active. Judge the settled rate near the optimum.
            let n = control.policy.settled();
            let rate = if n <= 16 { n * 100 } else { 1600 * 16 / n };
            assert!(rate >= 1280, "settled count {n}, rate {rate}");
        }
    }

    #[test]
    fn fixed_deletion_counts_and_idle_queues_do_not_tune() {
        for automatic in [false, true] {
            let mut control = Control::new(Concurrency {
                initial: 8,
                maximum: 64,
                automatic,
                startup_doubling: true,
            });
            for _ in 0..100 {
                assert_eq!(control.observe(1000, Duration::from_secs(1), !automatic), 8);
            }
        }
    }

    #[test]
    fn deletion_batch_preserves_outcome_order_and_reports_failures() {
        for initial in [1, FILESYSTEM_START] {
            let mut batch = Batch::new(initial);
            let results = batch
                .run(
                    &(0..1000).collect::<Vec<_>>(),
                    |n| {
                        if n % 7 == 0 {
                            Err(*n)
                        } else {
                            Ok(*n)
                        }
                    },
                    Result::is_ok,
                )
                .unwrap();
            for (n, result) in results.into_iter().enumerate() {
                assert_eq!(result, if n % 7 == 0 { Err(n) } else { Ok(n) });
            }
        }
    }
}

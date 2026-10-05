//! Deletion admission is measured separately from payload transfers.
use crate::rooted::{RelativePath, RemovalEntry, Root};
use crate::tune::{Policy, Sampler};
use anyhow::{bail, Context};
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::path::Path;
use std::sync::Arc;
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
            policy: (if concurrency.startup_doubling {
                Policy::new(concurrency.initial, 1, concurrency.maximum)
            } else {
                Policy::refine(concurrency.initial, 1, concurrency.maximum)
            })
            .require_gain(),
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

/// A worker retains one parent descriptor across adjacent planned removals.
/// The batch ends with its work share, never survives a receiver request, and
/// grants no permission to discover or delete additional entries.
#[derive(Default)]
pub(crate) struct DirectoryBatch {
    parent: Option<RemovalParent>,
    #[cfg(target_os = "linux")]
    held: Option<DeletionDirectory>,
}

struct RemovalParent {
    root: Arc<Root>,
    parents: Vec<Vec<u8>>,
    directory: File,
}

#[cfg(target_os = "linux")]
struct DeletionDirectory {
    root: Arc<Root>,
    parents: Vec<Vec<u8>>,
    _permit: crate::rooted::directory_gate::Permit,
    entries: usize,
    bytes: u64,
}

impl DirectoryBatch {
    pub(crate) fn remove(
        &mut self,
        root: &Arc<Root>,
        path: &RelativePath,
        label: &Path,
        directory: bool,
    ) -> anyhow::Result<()> {
        let (parents, leaf) = path.leaf()?;
        let reuse = self
            .parent
            .as_ref()
            .is_some_and(|parent| Arc::ptr_eq(&parent.root, root) && parent.parents == parents);
        if !reuse {
            // Release the previous directory before resolving or waiting on
            // another one. Root object identity also separates mount views and
            // roots revalidated by guarded requests.
            #[cfg(target_os = "linux")]
            {
                self.held = None;
            }
            self.parent = None;
            let directory = root.resolve_parent(path)?.into_directory()?;
            self.parent = Some(RemovalParent {
                root: root.clone(),
                parents: parents.to_vec(),
                directory,
            });
        }
        let name = CString::new(leaf).expect("RelativePath excludes NUL");
        let metadata =
            match RemovalEntry::new(&self.parent.as_ref().unwrap().directory, &name).metadata() {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(error) => {
                    return Err(error).with_context(|| format!("inspect {}", label.display()))
                }
            };
        if !directory {
            if metadata.is_dir() {
                bail!("{}: is now a directory; not deleting it", label.display());
            }
            self.before_unlink(root, path, metadata.len)?;
        }
        RemovalEntry::new(&self.parent.as_ref().unwrap().directory, &name)
            .unlink(directory)
            .with_context(|| format!("remove {}", label.display()))
    }

    pub(crate) fn before_unlink(
        &mut self,
        _root: &Arc<Root>,
        _path: &RelativePath,
        _len: u64,
    ) -> anyhow::Result<()> {
        #[cfg(target_os = "linux")]
        {
            const BYTES: u64 = 128 * 1024;
            if _len >= BYTES {
                // Block reclamation for large files benefits from parallelism.
                self.held = None;
                return Ok(());
            }
            let (parents, _) = _path.leaf()?;
            let reuse = self.held.as_ref().is_some_and(|held| {
                held.root.identity() == _root.identity()
                    && held.parents == parents
                    && held.entries < 64
                    && held.bytes + _len <= BYTES
            });
            if !reuse {
                // Never wait for a directory while holding another one's turn.
                self.held = None;
                let permit = crate::rooted::directory_gate::deletion(_root.identity(), parents);
                self.held = Some(DeletionDirectory {
                    root: _root.clone(),
                    parents: parents.to_vec(),
                    _permit: permit,
                    entries: 0,
                    bytes: 0,
                });
            }
            let held = self.held.as_mut().unwrap();
            held.entries += 1;
            held.bytes += _len;
        }
        Ok(())
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

    #[cfg(test)]
    pub fn run<T: Sync, R: Send>(
        &mut self,
        items: &[T],
        work: impl Fn(&T) -> R + Sync,
        succeeded: impl Fn(&R) -> bool,
    ) -> anyhow::Result<Vec<R>> {
        self.run_init(items, || (), |_, item| work(item), succeeded)
    }

    pub fn run_init<T: Sync, R: Send, S>(
        &mut self,
        items: &[T],
        init: impl Fn() -> S + Sync,
        work: impl Fn(&mut S, &T) -> R + Sync,
        succeeded: impl Fn(&R) -> bool,
    ) -> anyhow::Result<Vec<R>> {
        let run_chunk = |chunk: &[T]| {
            let mut state = init();
            chunk
                .iter()
                .map(|item| work(&mut state, item))
                .collect::<Vec<_>>()
        };
        // Avoid creating a pool for a few entries and exclude the short tail
        // from the next batch's measurement.
        if items.len() < 32 {
            self.control.observe(0, Duration::ZERO, false);
            return Ok(run_chunk(items));
        }
        let workers = self.control.limit().min(items.len());
        if workers == 1 {
            let start = Instant::now();
            let results = run_chunk(items);
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
            .is_none_or(|p| p.current_num_threads() < workers)
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
                    .flat_map_iter(run_chunk)
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

    use std::fs;
    use std::os::unix::fs::symlink;

    fn remove(
        batch: &mut DirectoryBatch,
        root: &Arc<Root>,
        path: &[u8],
        directory: bool,
    ) -> anyhow::Result<()> {
        batch.remove(
            root,
            &RelativePath::new(path)?,
            Path::new("test entry"),
            directory,
        )
    }

    #[test]
    fn planned_removals_keep_the_open_parent_without_following_a_replacement_link() {
        let temporary = crate::test_support::tempdir().unwrap();
        let base = temporary.path();
        fs::create_dir_all(base.join("root/sub")).unwrap();
        fs::create_dir(base.join("outside")).unwrap();
        for name in ["first", "second", "third"] {
            fs::write(base.join("root/sub").join(name), b"selected").unwrap();
            fs::write(base.join("outside").join(name), b"outside").unwrap();
        }
        let root = Arc::new(Root::open(&base.join("root")).unwrap());
        let mut batch = DirectoryBatch::default();
        remove(&mut batch, &root, b"sub/first", false).unwrap();
        fs::rename(base.join("root/sub"), base.join("root/held")).unwrap();
        symlink(base.join("outside"), base.join("root/sub")).unwrap();
        remove(&mut batch, &root, b"sub/second", false).unwrap();
        assert!(!base.join("root/held/second").exists());
        assert_eq!(fs::read(base.join("outside/second")).unwrap(), b"outside");
        drop(batch);
        // A later request must resolve again and reject the replacement link.
        assert!(remove(&mut DirectoryBatch::default(), &root, b"sub/third", false).is_err());
        assert!(base.join("root/held/third").exists());
        assert_eq!(fs::read(base.join("outside/third")).unwrap(), b"outside");
    }

    #[test]
    fn planned_removals_recheck_types_and_never_expand_the_plan() {
        let temporary = crate::test_support::tempdir().unwrap();
        let base = temporary.path();
        fs::create_dir(base.join("sub")).unwrap();
        fs::write(base.join("sub/first"), b"first").unwrap();
        fs::write(base.join("outside"), b"outside").unwrap();
        let root = Arc::new(Root::open(base).unwrap());
        let mut batch = DirectoryBatch::default();
        remove(&mut batch, &root, b"sub/first", false).unwrap();
        fs::create_dir_all(base.join("sub/later")).unwrap();
        fs::write(base.join("sub/later/keep"), b"keep").unwrap();
        let error = remove(&mut batch, &root, b"sub/later", false).unwrap_err();
        assert!(error.to_string().contains("is now a directory"));
        assert!(remove(&mut batch, &root, b"sub/later", true).is_err());
        assert_eq!(fs::read(base.join("sub/later/keep")).unwrap(), b"keep");
        symlink(base.join("outside"), base.join("sub/link")).unwrap();
        remove(&mut batch, &root, b"sub/link", false).unwrap();
        assert!(fs::symlink_metadata(base.join("sub/link")).is_err());
        assert_eq!(fs::read(base.join("outside")).unwrap(), b"outside");
        remove(&mut batch, &root, b"sub/missing", false).unwrap();
        fs::create_dir(base.join("empty")).unwrap();
        remove(&mut batch, &root, b"empty", true).unwrap();
        assert!(!base.join("empty").exists());
    }

    #[test]
    fn a_new_root_object_does_not_reuse_an_old_child_directory() {
        let temporary = crate::test_support::tempdir().unwrap();
        let base = temporary.path();
        fs::create_dir(base.join("sub")).unwrap();
        fs::write(base.join("sub/first"), b"first").unwrap();
        fs::write(base.join("sub/second"), b"old").unwrap();
        let root = Arc::new(Root::open(base).unwrap());
        let mut batch = DirectoryBatch::default();
        remove(&mut batch, &root, b"sub/first", false).unwrap();
        fs::rename(base.join("sub"), base.join("held")).unwrap();
        fs::create_dir(base.join("sub")).unwrap();
        fs::write(base.join("sub/second"), b"new").unwrap();
        let reopened = Arc::new(Root::open(base).unwrap());
        assert_eq!(root.identity(), reopened.identity());
        remove(&mut batch, &reopened, b"sub/second", false).unwrap();
        assert!(!base.join("sub/second").exists());
        assert_eq!(fs::read(base.join("held/second")).unwrap(), b"old");
    }

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
    #[test]
    fn prune_pool_survives_short_batches_and_worker_reductions() {
        let mut batch = Batch::new(64);
        batch.control = Control::new(Concurrency::filesystem(64));
        let items: Vec<_> = (0..1000).collect();
        assert_eq!(batch.run(&items, |n| *n, |_| true).unwrap(), items);
        assert_eq!(batch.pool.as_ref().unwrap().current_num_threads(), 64);
        assert_eq!(
            batch.run(&items[..32], |n| *n, |_| true).unwrap(),
            items[..32]
        );
        assert_eq!(batch.pool.as_ref().unwrap().current_num_threads(), 64);
        batch.control = Control::new(Concurrency::filesystem(8));
        assert_eq!(batch.run(&items, |n| *n, |_| true).unwrap(), items);
        assert_eq!(batch.pool.as_ref().unwrap().current_num_threads(), 64);
    }

    #[test]
    fn noisy_deletion_measurements_preserve_throughput_and_find_clear_gains() {
        fn uniform(state: &mut u64) -> f64 {
            *state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (((*state >> 11) as f64) + 0.5) / ((1u64 << 53) as f64)
        }
        for sigma in [0.03, 0.06] {
            for curve in 0..3 {
                let rate = |n: usize| match curve {
                    0 => n as f64 / (n as f64 + 2.0),
                    1 => {
                        if n <= 8 {
                            n as f64 / 8.0
                        } else {
                            8.0 / n as f64
                        }
                    }
                    _ => n.min(128) as f64 / 128.0,
                };
                let reference = if curve == 0 { rate(32) } else { 1.0 };
                let mut scores = Vec::new();
                for seed in 1..=40 {
                    let mut rng = seed;
                    let mut control = Control::new(Concurrency {
                        initial: 32,
                        maximum: 256,
                        automatic: true,
                        startup_doubling: false,
                    });
                    let mut tail = 0.0;
                    for tick in 0..960 {
                        let n = control.limit();
                        let noise = (-2.0 * uniform(&mut rng).ln()).sqrt()
                            * (std::f64::consts::TAU * uniform(&mut rng)).cos();
                        let completed =
                            (rate(n) * 25000.0 * (1.0 + sigma * noise)).max(0.0).round() as u64;
                        if tick >= 720 {
                            tail += rate(n) / 240.0;
                        }
                        control.observe(completed, SAMPLE, true);
                    }
                    scores.push(tail / reference);
                }
                scores.sort_by(f64::total_cmp);
                // Judge useful throughput, not whether the search reaches an
                // exact count. This catches noisy cumulative downward drift.
                assert!(
                    scores[20] >= 0.97,
                    "curve {curve}, noise {sigma}: {scores:?}"
                );
                assert!(
                    scores[4] >= 0.93,
                    "curve {curve}, noise {sigma}: {scores:?}"
                );
            }
        }
    }
}

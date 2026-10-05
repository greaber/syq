//! Deletion admission is measured separately from payload transfers.
pub(crate) mod workers;

use crate::rooted::{RelativePath, Root};
use crate::tune::{Policy, Sampler};
use anyhow::{bail, Context};
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

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
    directory: Option<File>,
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
        size: Option<u64>,
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
            let directory = root.resolve_parent(path)?.into_owned_directory();
            self.parent = Some(RemovalParent {
                root: root.clone(),
                parents: parents.to_vec(),
                directory,
            });
        }
        let name = CString::new(leaf).expect("RelativePath excludes NUL");
        let len = if let Some(size) = size {
            size
        } else {
            let metadata = match root
                .removal_entry(self.parent.as_ref().unwrap().directory.as_ref(), &name)
                .metadata()
            {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(error) => {
                    return Err(error).with_context(|| format!("inspect {}", label.display()))
                }
            };
            if !directory && metadata.is_dir() {
                bail!("{}: is now a directory; not deleting it", label.display());
            }
            metadata.len
        };
        if !directory {
            self.before_unlink(root, path, len)?;
        }
        root.removal_entry(self.parent.as_ref().unwrap().directory.as_ref(), &name)
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

/// A planner-selected, nonrecursive operation. `size: None` preserves Apply's
/// pre-unlink type check; a known size preserves S3 pruning's stat-free unlink.
pub(crate) struct Selected {
    pub root: Arc<Root>,
    pub path: RelativePath,
    pub label: std::path::PathBuf,
    pub directory: bool,
    pub size: Option<u64>,
}

struct SelectedTask(
    Vec<(usize, Selected)>,
    Option<Arc<std::sync::atomic::AtomicBool>>,
);
impl workers::Work for SelectedTask {
    type Outcome = Vec<(usize, anyhow::Result<()>)>;
    fn run(self, pool: &Arc<workers::Pool<Self>>) {
        let mut parent = DirectoryBatch::default();
        let mut results = Vec::with_capacity(self.0.len());
        for (index, entry) in self.0 {
            if pool.is_cancelled()
                || self
                    .1
                    .as_ref()
                    .is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed))
            {
                break;
            }
            let result = parent.remove(
                &entry.root,
                &entry.path,
                &entry.label,
                entry.directory,
                entry.size,
            );
            results.push((index, result));
        }
        drop(parent);
        pool.outcome(results);
    }
    fn completed(outcome: &Self::Outcome) -> u64 {
        outcome.iter().filter(|(_, result)| result.is_ok()).count() as u64
    }
}

/// Interleave short sibling groups before bounding a transport request. Sorting
/// all names by parent and only then cutting requests hides other directories
/// from the receiver, even when its executor has idle workers.
pub(crate) fn spread<T>(items: Vec<T>, path: impl Fn(&T) -> &[u8]) -> Vec<T> {
    use std::collections::{BTreeMap, VecDeque};
    let count = items.len();
    let mut parents: BTreeMap<Vec<u8>, VecDeque<T>> = BTreeMap::new();
    for item in items {
        let name = path(&item);
        let parent = name
            .iter()
            .rposition(|&b| b == b'/')
            .map_or(&[][..], |end| &name[..end]);
        parents.entry(parent.to_vec()).or_default().push_back(item);
    }
    let mut groups: VecDeque<_> = parents.into_values().collect();
    let mut spread = Vec::with_capacity(count);
    while let Some(mut group) = groups.pop_front() {
        spread.extend(group.drain(..group.len().min(64)));
        if !group.is_empty() {
            groups.push_back(group);
        }
    }
    spread
}

#[derive(Default)]
pub(crate) struct Batch {
    executor: Option<workers::Executor<SelectedTask>>,
    cancelled: Option<Arc<std::sync::atomic::AtomicBool>>,
}

impl Batch {
    pub fn with_cancellation(cancelled: Arc<std::sync::atomic::AtomicBool>) -> Self {
        Self {
            executor: None,
            cancelled: Some(cancelled),
        }
    }

    fn check_cancelled(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self
                .cancelled
                .as_ref()
                .is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed)),
            "pruning cancelled"
        );
        Ok(())
    }
    pub fn run(
        &mut self,
        items: Vec<anyhow::Result<Selected>>,
    ) -> anyhow::Result<Vec<anyhow::Result<()>>> {
        let mut results = Vec::with_capacity(items.len());
        let mut tasks = Vec::new();
        let mut group: Vec<(usize, Selected)> = Vec::new();
        for (index, item) in items.into_iter().enumerate() {
            match item {
                Err(error) => results.push(Err(error)),
                Ok(entry) => {
                    let siblings = group.last().is_none_or(|(_, previous)| {
                        Arc::ptr_eq(&previous.root, &entry.root)
                            && previous.path.leaf().ok().map(|(p, _)| p)
                                == entry.path.leaf().ok().map(|(p, _)| p)
                    });
                    if !siblings || group.len() == 64 {
                        tasks.push(SelectedTask(
                            std::mem::take(&mut group),
                            self.cancelled.clone(),
                        ));
                    }
                    results.push(Ok(()));
                    group.push((index, entry));
                }
            }
        }
        if !group.is_empty() {
            tasks.push(SelectedTask(group, self.cancelled.clone()));
        }
        if results.len() < 32 {
            for SelectedTask(entries, _) in tasks {
                let mut parent = DirectoryBatch::default();
                for (index, entry) in entries {
                    self.check_cancelled()?;
                    results[index] = parent.remove(
                        &entry.root,
                        &entry.path,
                        &entry.label,
                        entry.directory,
                        entry.size,
                    );
                }
            }
            return Ok(results);
        }
        let executor = self
            .executor
            .get_or_insert_with(|| workers::Executor::new(Concurrency::filesystem(0), false));
        let backlogged = results.len()
            >= executor
                .pool
                .limit
                .load(std::sync::atomic::Ordering::Relaxed)
                * 2;
        executor.run(tasks, backlogged, &mut |batches| {
            for (index, result) in batches.into_iter().flatten() {
                results[index] = result;
            }
            Ok(())
        })?;
        self.check_cancelled()?;
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
            None,
        )
    }

    #[test]
    fn removing_direct_children_needs_no_additional_descriptors() {
        use crate::process::CommandExt as _;
        const CHILD_ENV: &str = "SYQ_TEST_DELETION_LOW_FD_CHILD";
        const TEST: &str =
            "deletion::tests::removing_direct_children_needs_no_additional_descriptors";
        if std::env::var_os(CHILD_ENV).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture"])
                .env(CHILD_ENV, "1")
                .status_guarded()
                .unwrap();
            assert!(status.success());
            return;
        }
        let temporary = crate::test_support::tempdir().unwrap();
        let base = temporary.path();
        fs::write(base.join("file"), b"selected").unwrap();
        fs::create_dir(base.join("empty")).unwrap();
        let root = Arc::new(Root::open(base).unwrap());
        let mut limit = crate::fsops::nofile_limits().unwrap();
        limit.rlim_cur = limit.rlim_cur.min(64);
        crate::fsops::set_nofile_limits(&limit).unwrap();
        let mut descriptors = Vec::new();
        loop {
            match File::open("/dev/null") {
                Ok(file) => descriptors.push(file),
                Err(error) => {
                    assert_eq!(error.raw_os_error(), Some(libc::EMFILE));
                    break;
                }
            }
        }
        let mut batch = DirectoryBatch::default();
        remove(&mut batch, &root, b"file", false).unwrap();
        remove(&mut batch, &root, b"empty", true).unwrap();
        drop(descriptors);
        assert!(!base.join("file").exists());
        assert!(!base.join("empty").exists());
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
    #[test]
    fn selected_batches_preserve_order_failures_and_directory_boundaries() {
        let temp = crate::test_support::tempdir().unwrap();
        let root = Arc::new(Root::open(temp.path()).unwrap());
        let mut batch = Batch::default();
        for round in 0..3 {
            let mut entries = Vec::new();
            for index in 0..1000 {
                let name = format!("{round}-{index}");
                if index % 7 == 0 {
                    fs::create_dir(temp.path().join(&name)).unwrap();
                    fs::write(temp.path().join(&name).join("unselected"), b"keep").unwrap();
                } else {
                    fs::write(temp.path().join(&name), b"remove").unwrap();
                }
                entries.push(Ok(Selected {
                    root: root.clone(),
                    path: RelativePath::new(name.as_bytes()).unwrap(),
                    label: temp.path().join(name),
                    directory: false,
                    size: None,
                }));
            }
            let results = batch.run(entries).unwrap();
            assert_eq!(results.len(), 1000);
            for (index, result) in results.into_iter().enumerate() {
                assert_eq!(result.is_err(), index % 7 == 0);
                let path = temp.path().join(format!("{round}-{index}"));
                assert_eq!(path.exists(), index % 7 == 0);
                if path.exists() {
                    assert_eq!(fs::read(path.join("unselected")).unwrap(), b"keep");
                }
            }
        }
    }

    #[test]
    fn bounded_requests_expose_independent_directories() {
        let items: Vec<_> = (0..32)
            .flat_map(|dir| (0..4096).map(move |file| format!("{dir:02}/{file:04}")))
            .collect();
        let spread = spread(items, |path| path.as_bytes());
        for request in spread.chunks(1000) {
            let parents: std::collections::HashSet<_> = request
                .iter()
                .map(|path| path.split('/').next().unwrap())
                .collect();
            assert!(parents.len() >= request.len().div_ceil(64));
        }
        assert_eq!(
            spread
                .into_iter()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            32 * 4096
        );
    }

    #[test]
    fn cancellation_prevents_selected_removals() {
        let temp = crate::test_support::tempdir().unwrap();
        fs::write(temp.path().join("keep"), b"keep").unwrap();
        let mut batch =
            Batch::with_cancellation(Arc::new(std::sync::atomic::AtomicBool::new(true)));
        let results = batch.run(vec![Ok(Selected {
            root: Arc::new(Root::open(temp.path()).unwrap()),
            path: RelativePath::new(b"keep").unwrap(),
            label: temp.path().join("keep"),
            directory: false,
            size: Some(4),
        })]);
        assert!(results.is_err());
        assert_eq!(fs::read(temp.path().join("keep")).unwrap(), b"keep");
    }
}

//! The sidecars this process has created and not yet published or removed.
//!
//! A receiver that is interrupted, or whose copy's control connection
//! closes, removes them before it exits. No later run uses a small file's
//! stage or a grouped or streamed patch's stage: each run stages under names
//! of its own. A partial of a file copied on its own is kept when it is at
//! least `RESUMABLE_PARTIAL_MIN` long, since a rerun compares its blocks with
//! the source and reuses those that match; a shorter one is removed.
//!
//! Each sidecar is known by the inode it was created as. A sweep removes a
//! name only while it still holds that inode as a singly linked regular
//! file, so it never touches a published file, a file that has replaced the
//! sidecar at its name, or another run's partial. Nothing scans directories.
//!
//! Only a process that serves one copy, and so can sweep, registers its
//! sidecars. There, each thread registers in a shard of its own, where its
//! publications usually find them, so that a receiver's many workers
//! neither wait for one another nor move one another's cache lines.
//! Registering then costs an uncontended lock, a map entry reused from
//! earlier sidecars, and one small allocation per sidecar, against the
//! create, write, rename and close that the sidecar itself costs.

use super::*;
use std::hash::{BuildHasherDefault, Hasher};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
use std::sync::PoisonError;
use std::time::{Duration, Instant};

/// A per-file partial at least this long is kept for resumption.
pub(crate) const RESUMABLE_PARTIAL_MIN: u64 = 1 << 20;

/// Up to this many threads remove sidecars at once. On a network
/// filesystem each removal waits a round trip.
const SWEEP_THREADS: usize = 8;

/// Registered sidecars, and creations under way, are kept in this many
/// shards by thread.
const SHARDS: usize = 64;

/// The roots a process registers sidecars under are held here once, rather
/// than counted again for every sidecar. A process serves one copy, which
/// has one destination root; any beyond these are held by their sidecars.
const ROOT_SLOTS: usize = 8;

/// What a sidecar holds, which decides whether an interruption keeps it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Sidecar {
    /// A small file's stage, or a grouped or streamed patch's: always
    /// removed.
    Stage,
    /// The partial of a file copied on its own: kept when long enough to be
    /// worth resuming.
    Partial,
}

enum EntryRoot {
    Slot(usize),
    Held(Arc<Root>),
}

struct Entry {
    root: EntryRoot,
    /// The sidecar's path below its root, as `RelativePath::to_bytes` gives
    /// it.
    path: Vec<u8>,
    kind: Sidecar,
}

/// What a sweep did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Swept {
    pub(crate) removed: usize,
    /// Partials kept for resumption.
    pub(crate) kept: usize,
    /// Sidecars no longer at their names, or replaced there by other files.
    pub(crate) gone: usize,
    /// Sidecars the sweep could not remove, or did not reach before its
    /// deadline.
    pub(crate) left: usize,
}

/// Mixes the device and inode numbers that key the registry.
#[derive(Default)]
struct IdentityHasher(u64);

impl Hasher for IdentityHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.write_u64(u64::from(*byte));
        }
    }

    fn write_u64(&mut self, value: u64) {
        self.0 = (self.0.rotate_left(5) ^ value).wrapping_mul(0x517c_c1b7_2722_0a95);
    }
}

type Entries = HashMap<(u64, u64), Entry, BuildHasherDefault<IdentityHasher>>;

/// One shard, on a cache line of its own.
#[repr(align(128))]
struct Padded<T>(T);

pub(super) struct Registry {
    /// Set by a process that will sweep; until then nothing is registered.
    enabled: AtomicBool,
    /// Creations begun and not yet registered, counted by thread.
    creating: [Padded<AtomicUsize>; SHARDS],
    /// Set by the first sweep: no sidecar is created after it.
    closed: AtomicBool,
    roots: [OnceLock<Arc<Root>>; ROOT_SLOTS],
    entries: [Padded<Mutex<Entries>>; SHARDS],
    /// Sweeps run one at a time; a later one finds what an earlier left.
    sweeping: Mutex<()>,
}

/// This thread's shard.
fn thread_shard() -> usize {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    thread_local! {
        static SHARD: usize = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % SHARDS;
    }
    SHARD.with(|shard| *shard)
}

static SIDECARS: Registry = Registry::new();

/// Held from just before a sidecar is created until it is registered, so
/// that a sweep cannot miss a sidecar whose creation was under way.
#[must_use]
pub(super) struct Creation<'a> {
    registry: &'a Registry,
    /// None when this process does not register its sidecars.
    shard: Option<usize>,
}

impl Drop for Creation<'_> {
    fn drop(&mut self) {
        if let Some(shard) = self.shard {
            self.registry.creating[shard].0.fetch_sub(1, SeqCst);
        }
    }
}

impl Creation<'_> {
    /// Record the sidecar just created at `relative` below `root`.
    pub(super) fn register(
        self,
        root: &Arc<Root>,
        relative: &RelativePath,
        identity: (u64, u64),
        kind: Sidecar,
    ) {
        if self.shard.is_none() {
            return;
        }
        let entry = Entry {
            root: self.registry.root(root),
            path: relative.to_bytes(),
            kind,
        };
        let replaced = self.registry.lock(thread_shard()).insert(identity, entry);
        drop(replaced);
    }
}

impl Registry {
    pub(super) const fn new() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            creating: [const { Padded(AtomicUsize::new(0)) }; SHARDS],
            closed: AtomicBool::new(false),
            roots: [const { OnceLock::new() }; ROOT_SLOTS],
            entries: [const { Padded(Mutex::new(HashMap::with_hasher(BuildHasherDefault::new()))) };
                SHARDS],
            sweeping: Mutex::new(()),
        }
    }

    pub(super) fn enable(&self) {
        self.enabled.store(true, SeqCst);
    }

    fn lock(&self, shard: usize) -> std::sync::MutexGuard<'_, Entries> {
        self.entries[shard]
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn root(&self, root: &Arc<Root>) -> EntryRoot {
        let identity = root.identity();
        for (slot, held) in self.roots.iter().enumerate() {
            if held.get_or_init(|| Arc::clone(root)).identity() == identity {
                return EntryRoot::Slot(slot);
            }
        }
        EntryRoot::Held(Arc::clone(root))
    }

    fn creating(&self) -> usize {
        self.creating.iter().map(|shard| shard.0.load(SeqCst)).sum()
    }

    /// Begin creating a sidecar, unless a sweep has begun: a stopping
    /// receiver creates none.
    pub(super) fn begin(&self) -> Result<Creation<'_>> {
        if !self.enabled.load(std::sync::atomic::Ordering::Relaxed) {
            return Ok(Creation {
                registry: self,
                shard: None,
            });
        }
        // Paired with the sweep, which closes and then waits for creations
        // to end: either this sees the registry closed, or the sweep sees
        // this creation and waits for it to register.
        let shard = thread_shard();
        self.creating[shard].0.fetch_add(1, SeqCst);
        let creation = Creation {
            registry: self,
            shard: Some(shard),
        };
        if self.closed.load(SeqCst) {
            bail!("the receiver is stopping");
        }
        Ok(creation)
    }

    /// A sidecar is usually published by the thread that created it. One
    /// that is not, such as a partial another range worker finishes, is
    /// looked for in the other shards.
    pub(super) fn forget(&self, identity: (u64, u64)) {
        if !self.enabled.load(std::sync::atomic::Ordering::Relaxed) {
            return;
        }
        let own = thread_shard();
        if let Some(removed) = self.lock(own).remove(&identity) {
            drop(removed);
            return;
        }
        for shard in (0..SHARDS).filter(|shard| *shard != own) {
            let removed = self.lock(shard).remove(&identity);
            if removed.is_some() {
                return;
            }
        }
    }

    /// Stop creating sidecars and remove those registered: stages, and
    /// partials too short to resume when `partials` is set. Other partials
    /// stay registered for a later sweep that includes them. Removal stops
    /// at `deadline`.
    pub(super) fn sweep(&self, partials: bool, deadline: Instant) -> Swept {
        let _one = self.sweeping.lock().unwrap_or_else(PoisonError::into_inner);
        self.closed.store(true, SeqCst);
        #[cfg(debug_assertions)]
        let _ = test_race_barrier(
            "SYQ_TEST_SIDECAR_SWEEP_READY_FILE",
            "SYQ_TEST_SIDECAR_SWEEP_CONTINUE_FILE",
            "sidecar sweep",
        );
        while self.creating() != 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_micros(200));
        }
        let mut entries = Vec::new();
        for shard in &self.entries {
            let mut registered = shard.0.lock().unwrap_or_else(PoisonError::into_inner);
            entries
                .extend(registered.extract_if(|_, entry| partials || entry.kind == Sidecar::Stage));
        }
        let roots = |entry: &Entry| -> Option<Arc<Root>> {
            match &entry.root {
                EntryRoot::Slot(slot) => self.roots[*slot].get().cloned(),
                EntryRoot::Held(root) => Some(Arc::clone(root)),
            }
        };
        remove_all(&entries, &roots, deadline)
    }

    #[cfg(test)]
    pub(super) fn registered(&self) -> usize {
        self.entries
            .iter()
            .map(|shard| shard.0.lock().unwrap().len())
            .sum()
    }
}

/// Remove `entries`, on several threads when there are many.
fn remove_all(
    entries: &[((u64, u64), Entry)],
    root: &(dyn Fn(&Entry) -> Option<Arc<Root>> + Sync),
    deadline: Instant,
) -> Swept {
    let remove_part = |part: &[((u64, u64), Entry)]| {
        let mut swept = Swept::default();
        for (identity, entry) in part {
            if Instant::now() >= deadline {
                swept.left += 1;
                continue;
            }
            let removal = root(entry)
                .context("sidecar root is gone")
                .and_then(|root| remove(&root, entry, *identity));
            match removal {
                Ok(Removal::Removed) => swept.removed += 1,
                Ok(Removal::Kept) => swept.kept += 1,
                Ok(Removal::Gone) => swept.gone += 1,
                Err(_) => swept.left += 1,
            }
        }
        swept
    };
    let per_thread = entries.len().div_ceil(SWEEP_THREADS).max(32);
    let parts: Vec<_> = entries.chunks(per_thread).collect();
    let Some((first, rest)) = parts.split_first() else {
        return Swept::default();
    };
    std::thread::scope(|scope| {
        let threads: Vec<_> = rest
            .iter()
            .map(|part| {
                std::thread::Builder::new()
                    .spawn_scoped(scope, move || remove_part(part))
                    .map_err(|_| part)
            })
            .collect();
        let mut swept = remove_part(first);
        for thread in threads {
            let part = match thread {
                Ok(thread) => thread.join().unwrap_or(Swept {
                    left: 1,
                    ..Swept::default()
                }),
                // A thread the system refused: this one removes its part.
                Err(part) => remove_part(part),
            };
            swept.removed += part.removed;
            swept.kept += part.kept;
            swept.gone += part.gone;
            swept.left += part.left;
        }
        swept
    })
}

enum Removal {
    Removed,
    Kept,
    Gone,
}

fn remove(root: &Root, entry: &Entry, (dev, ino): (u64, u64)) -> Result<Removal> {
    let relative = RelativePath::new(&entry.path)?;
    let parent = root.resolve_parent(&relative)?;
    let current = match parent.metadata() {
        Ok(current) => current,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Removal::Gone),
        Err(error) => return Err(error.into()),
    };
    if !is_safe_rooted_partial(current) || current.dev != dev || current.ino != ino {
        return Ok(Removal::Gone);
    }
    if entry.kind == Sidecar::Partial && current.len >= RESUMABLE_PARTIAL_MIN {
        return Ok(Removal::Kept);
    }
    match parent.unlink() {
        Ok(()) => Ok(Removal::Removed),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Removal::Gone),
        Err(error) => Err(error.into()),
    }
}

/// Begin creating a sidecar; see `Registry::begin`.
pub(super) fn begin() -> Result<Creation<'static>> {
    SIDECARS.begin()
}

/// The sidecar with this identity was published or removed.
pub(super) fn forget(identity: (u64, u64)) {
    SIDECARS.forget(identity)
}

/// Register this process's sidecars from now on: it serves one copy and
/// removes them when interrupted or when the copy's connection ends.
pub(crate) fn track() {
    SIDECARS.enable()
}

/// Remove the sidecars this process created and has not published; see
/// `Registry::sweep`. After the first sweep the process creates no more.
pub(crate) fn sweep(partials: bool, deadline: Instant) -> Swept {
    SIDECARS.sweep(partials, deadline)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> (tempfile::TempDir, Arc<Root>) {
        let directory = crate::test_support::tempdir().unwrap();
        let root = Arc::new(Root::open(directory.path()).unwrap());
        (directory, root)
    }

    fn create(registry: &Registry, root: &Arc<Root>, name: &str, len: u64, kind: Sidecar) {
        let creation = registry.begin().unwrap();
        let relative = RelativePath::new(name.as_bytes()).unwrap();
        let file = root.create_file(&relative, 0o600).unwrap();
        file.set_len(len).unwrap();
        let metadata = file.metadata().unwrap();
        creation.register(root, &relative, (metadata.dev(), metadata.ino()), kind);
    }

    fn tracking() -> Registry {
        let registry = Registry::new();
        registry.enable();
        registry
    }

    fn far() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

    #[test]
    fn a_sweep_removes_stages_and_short_partials_and_keeps_resumable_ones() {
        let (directory, root) = root();
        let registry = tracking();
        create(&registry, &root, ".a.syq-tmp.stage", 10, Sidecar::Stage);
        create(&registry, &root, ".b.syq-tmp.empty", 0, Sidecar::Partial);
        create(&registry, &root, ".c.syq-tmp.short", 4096, Sidecar::Partial);
        create(
            &registry,
            &root,
            ".d.syq-tmp.long",
            RESUMABLE_PARTIAL_MIN,
            Sidecar::Partial,
        );
        let swept = registry.sweep(true, far());
        assert_eq!(
            swept,
            Swept {
                removed: 3,
                kept: 1,
                gone: 0,
                left: 0
            }
        );
        let mut names: Vec<_> = fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        names.sort();
        assert_eq!(names, [OsString::from(".d.syq-tmp.long")]);
    }

    #[test]
    fn a_sweep_without_partials_keeps_them_registered_for_a_later_sweep() {
        let (directory, root) = root();
        let registry = tracking();
        create(&registry, &root, ".a.syq-tmp.stage", 10, Sidecar::Stage);
        create(&registry, &root, ".b.syq-tmp.short", 10, Sidecar::Partial);
        assert_eq!(registry.sweep(false, far()).removed, 1);
        assert!(directory.path().join(".b.syq-tmp.short").exists());
        assert_eq!(registry.registered(), 1);
        assert_eq!(registry.sweep(true, far()).removed, 1);
        assert!(!directory.path().join(".b.syq-tmp.short").exists());
    }

    #[test]
    fn a_sweep_leaves_published_replaced_and_linked_files_alone() {
        let (directory, root) = root();
        let registry = tracking();
        let path = |name: &str| directory.path().join(name);
        // Published: renamed to its final name before the sweep.
        create(&registry, &root, ".published.syq-tmp.x", 1, Sidecar::Stage);
        fs::rename(path(".published.syq-tmp.x"), path("published")).unwrap();
        // Replaced at its name by another file, such as another writer's.
        create(&registry, &root, ".replaced.syq-tmp.x", 1, Sidecar::Stage);
        let held = File::open(path(".replaced.syq-tmp.x")).unwrap();
        fs::write(path("other"), b"another file").unwrap();
        fs::rename(path("other"), path(".replaced.syq-tmp.x")).unwrap();
        // Given a second name: no longer a private sidecar.
        create(&registry, &root, ".linked.syq-tmp.x", 1, Sidecar::Stage);
        fs::hard_link(path(".linked.syq-tmp.x"), path("linked")).unwrap();
        let swept = registry.sweep(true, far());
        assert_eq!(swept.removed, 0);
        assert_eq!(swept.gone, 3);
        drop(held);
        for name in [
            "published",
            ".replaced.syq-tmp.x",
            ".linked.syq-tmp.x",
            "linked",
        ] {
            assert!(path(name).exists(), "{name}");
        }
        assert_eq!(
            fs::read(path(".replaced.syq-tmp.x")).unwrap(),
            b"another file"
        );
    }

    #[test]
    fn a_forgotten_sidecar_is_not_swept() {
        let (directory, root) = root();
        let registry = tracking();
        create(&registry, &root, ".kept.syq-tmp.x", 1, Sidecar::Stage);
        let metadata = fs::metadata(directory.path().join(".kept.syq-tmp.x")).unwrap();
        registry.forget((metadata.dev(), metadata.ino()));
        assert_eq!(registry.sweep(true, far()), Swept::default());
        assert!(directory.path().join(".kept.syq-tmp.x").exists());
    }

    #[test]
    fn a_sidecar_published_by_another_thread_is_forgotten() {
        let (directory, root) = root();
        let registry = tracking();
        create(&registry, &root, ".kept.syq-tmp.x", 1, Sidecar::Partial);
        let metadata = fs::metadata(directory.path().join(".kept.syq-tmp.x")).unwrap();
        std::thread::scope(|scope| {
            scope.spawn(|| registry.forget((metadata.dev(), metadata.ino())));
        });
        assert_eq!(registry.registered(), 0);
    }

    #[test]
    fn a_process_that_does_not_track_registers_nothing() {
        let (directory, root) = root();
        let registry = Registry::new();
        create(&registry, &root, ".a.syq-tmp.x", 1, Sidecar::Stage);
        assert_eq!(registry.registered(), 0);
        assert_eq!(registry.sweep(true, far()), Swept::default());
        assert!(directory.path().join(".a.syq-tmp.x").exists());
    }

    #[test]
    fn sidecars_under_more_roots_than_slots_are_still_removed() {
        let registry = tracking();
        let roots: Vec<_> = (0..ROOT_SLOTS + 2).map(|_| root()).collect();
        for (_, root) in &roots {
            create(&registry, root, ".a.syq-tmp.x", 1, Sidecar::Stage);
        }
        assert_eq!(registry.sweep(true, far()).removed, roots.len());
        for (directory, _) in &roots {
            assert!(!directory.path().join(".a.syq-tmp.x").exists());
        }
    }

    #[test]
    fn no_sidecar_is_created_once_a_sweep_has_begun() {
        let registry = tracking();
        registry.sweep(true, far());
        let error = registry.begin().err().expect("creation refused");
        assert!(error.to_string().contains("stopping"), "{error:#}");
        assert_eq!(registry.creating(), 0);
    }

    #[test]
    fn a_sweep_waits_for_a_creation_under_way() {
        let (directory, root) = root();
        let registry = tracking();
        let creation = registry.begin().unwrap();
        std::thread::scope(|scope| {
            let sweep = scope.spawn(|| registry.sweep(true, far()));
            std::thread::sleep(Duration::from_millis(50));
            assert!(!sweep.is_finished(), "sweep did not wait for the creation");
            let relative = RelativePath::new(b".late.syq-tmp.x").unwrap();
            let file = root.create_file(&relative, 0o600).unwrap();
            let metadata = file.metadata().unwrap();
            creation.register(
                &root,
                &relative,
                (metadata.dev(), metadata.ino()),
                Sidecar::Stage,
            );
            assert_eq!(sweep.join().unwrap().removed, 1);
        });
        assert!(!directory.path().join(".late.syq-tmp.x").exists());
    }

    #[test]
    fn a_sweep_stops_removing_at_its_deadline() {
        let (directory, root) = root();
        let registry = tracking();
        create(&registry, &root, ".a.syq-tmp.x", 1, Sidecar::Stage);
        let swept = registry.sweep(true, Instant::now());
        assert_eq!(swept.left, 1);
        assert!(directory.path().join(".a.syq-tmp.x").exists());
    }

    #[test]
    fn many_sidecars_are_removed_on_several_threads() {
        let (directory, root) = root();
        let registry = tracking();
        fs::create_dir(directory.path().join("nested")).unwrap();
        for index in 0..300 {
            create(
                &registry,
                &root,
                &format!("nested/.f{index}.syq-tmp.x"),
                1,
                Sidecar::Stage,
            );
        }
        assert_eq!(registry.sweep(true, far()).removed, 300);
        assert_eq!(
            fs::read_dir(directory.path().join("nested"))
                .unwrap()
                .count(),
            0
        );
    }
}

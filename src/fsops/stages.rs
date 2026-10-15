//! The files this receiver is writing a copy's data into: each copy's
//! sidecars ("stages"), and the new files `--in-place=new` writes. Every connection of
//! a copy runs in this process, so the descriptor that created or opened such
//! a file is kept here, and every later write, from any connection, and
//! Finalize go through it. A file someone renames into its place in the
//! meantime is never written, and never gets the copy's metadata.
//!
//! A file is held from the request that created or opened it until Finalize
//! takes it, a later attempt replaces it, or the copy's control connection
//! ends. A write to a file not held here is refused, and the file fails as
//! for any other write error.
//!
//! At most `MAX_HELD` files are held. Beyond that the one used least
//! recently is let go, unless a connection is using it. A copy has about two
//! files in flight per worker, so what is let go is a file that failed and
//! was not retried.

use super::*;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Condvar, MutexGuard};

/// Files held at once, about two for each connection a receiver serves.
/// Tests reach the bound with fewer.
pub(super) const MAX_HELD: usize = if cfg!(test) { 16 } else { 1024 };

/// A new scope for one copy's held files, in a process that serves several
/// copies. Scope 0 is the copy of a process that serves only one.
pub(crate) fn new_scope() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Relaxed)
}

/// A held file is found by the file it is for, the copy's target: a stage's
/// own name can be shortened to fit the filesystem when it is created.
#[derive(Clone, PartialEq, Eq, Hash)]
struct Key {
    scope: u64,
    root: (u64, u64),
    target: Vec<u8>,
    copy_id: CopyId,
    inplace: bool,
}

/// What a stage or in-place file is for: `target` below `root`, written for
/// `copy_id` of the copy `scope`, in place or through a stage.
#[derive(Clone, Copy)]
pub(super) struct For<'a> {
    pub(super) scope: u64,
    pub(super) root: &'a Root,
    pub(super) target: &'a RelativePath,
    pub(super) copy_id: &'a CopyId,
    pub(super) inplace: bool,
}

/// What the copy `scope` writes to `target` for `copy_id` is for.
pub(super) fn of<'a>(
    scope: u64,
    target: &'a RootedTarget,
    copy_id: &'a CopyId,
    inplace: bool,
) -> For<'a> {
    For {
        scope,
        root: &target.root,
        target: &target.relative,
        copy_id,
        inplace,
    }
}

/// The name a held stage is shown by: its own, beside its target's.
pub(super) fn label(target: &RootedTarget, relative: &RelativePath) -> PathBuf {
    match relative.to_path_buf().file_name() {
        Some(name) => target.label.with_file_name(name),
        None => target.label.clone(),
    }
}

impl For<'_> {
    fn key(&self) -> Key {
        let identity = self.root.identity();
        Key {
            scope: self.scope,
            root: (identity.dev, identity.ino),
            target: self.target.to_bytes(),
            copy_id: *self.copy_id,
            inplace: self.inplace,
        }
    }
}

/// A held file: the descriptor that created or opened it, the metadata read
/// then, before anything was written, its name (the stage's, or the target's
/// for an in-place file), and whether this copy created it.
pub(super) struct Held {
    pub(super) file: File,
    pub(super) opened: Option<fs::Metadata>,
    pub(super) relative: RelativePath,
    pub(super) created: bool,
    /// Shared with each connection that caches a descriptor of the file,
    /// which is then not let go to make room.
    in_use: Arc<()>,
    used: u64,
}

impl Held {
    fn in_use(&self) -> bool {
        Arc::strong_count(&self.in_use) > 1
    }
}

/// A duplicate of a held file's descriptor, sharing its open file
/// description, with its name.
pub(super) struct Got {
    pub(super) file: File,
    pub(super) relative: RelativePath,
    pub(super) in_use: Arc<()>,
    /// This copy created the file, as `Held::created`.
    pub(super) created: bool,
}

#[derive(Default)]
struct Registry {
    held: HashMap<Key, Held>,
    /// Files whose Finalize is running; a second Finalize waits for it.
    finalizing: HashSet<Key>,
    clock: u64,
}

struct Shared {
    registry: Mutex<Registry>,
    finalized: Condvar,
}

fn shared() -> &'static Shared {
    static SHARED: OnceLock<Shared> = OnceLock::new();
    SHARED.get_or_init(|| Shared {
        registry: Mutex::new(Registry::default()),
        finalized: Condvar::new(),
    })
}

fn registry() -> MutexGuard<'static, Registry> {
    shared()
        .registry
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Hold `file`, which this receiver just created (`created`) or opened at
/// `relative`, as the file for `target`, replacing what was held for it, and
/// return the share of its use count for a connection that caches `file`.
/// Descriptors let go are closed after the registry is unlocked: a close
/// can wait for a network filesystem.
pub(super) fn hold(
    target: For<'_>,
    relative: &RelativePath,
    file: &File,
    opened: Option<fs::Metadata>,
    created: bool,
) -> io::Result<Arc<()>> {
    let file = file.try_clone()?;
    let in_use = Arc::new(());
    let key = target.key();
    let mut released = Vec::new();
    {
        let mut registry = registry();
        registry.clock += 1;
        let held = Held {
            file,
            opened,
            relative: relative.clone(),
            created,
            in_use: in_use.clone(),
            used: registry.clock,
        };
        released.extend(registry.held.insert(key.clone(), held));
        while registry.held.len() > MAX_HELD {
            let Some(oldest) = registry
                .held
                .iter()
                .filter(|(other, held)| **other != key && !held.in_use())
                .min_by_key(|(_, held)| held.used)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            released.extend(registry.held.remove(&oldest));
        }
    }
    drop(released);
    Ok(in_use)
}

/// The file held for `target`.
pub(super) fn get(target: For<'_>) -> io::Result<Option<Got>> {
    let mut registry = registry();
    registry.clock += 1;
    let clock = registry.clock;
    let Some(held) = registry.held.get_mut(&target.key()) else {
        return Ok(None);
    };
    held.used = clock;
    Ok(Some(Got {
        file: held.file.try_clone()?,
        relative: held.relative.clone(),
        in_use: held.in_use.clone(),
        created: held.created,
    }))
}

/// Whether a file is held for `target` at `relative`.
pub(super) fn holds(target: For<'_>, relative: &RelativePath) -> bool {
    registry()
        .held
        .get(&target.key())
        .is_some_and(|held| &held.relative == relative)
}

/// Stop holding the file for `target` and return it.
pub(super) fn take(target: For<'_>) -> Option<Held> {
    registry().held.remove(&target.key())
}

/// A running Finalize of a held file. A Finalize for the same file waits
/// until this is dropped, so a retry sent after its connection dropped sees
/// what the first one did: the file published, or held again.
pub(super) struct Finalizing(Key);

impl Drop for Finalizing {
    fn drop(&mut self) {
        registry().finalizing.remove(&self.0);
        shared().finalized.notify_all();
    }
}

/// Take the file held for `target` to finalize it, after any Finalize of it
/// already running ends.
pub(super) fn finalize(target: For<'_>) -> Option<(Held, Finalizing)> {
    let key = target.key();
    let mut registry = registry();
    while registry.finalizing.contains(&key) {
        registry = shared()
            .finalized
            .wait(registry)
            .unwrap_or_else(|poisoned| poisoned.into_inner());
    }
    let held = registry.held.remove(&key)?;
    registry.finalizing.insert(key.clone());
    Some((held, Finalizing(key)))
}

/// Let go of every file held for the copy `scope`, when its control
/// connection ends.
pub(crate) fn release(scope: u64) {
    let released: Vec<Held> = {
        let mut registry = registry();
        let keys: Vec<Key> = registry
            .held
            .keys()
            .filter(|key| key.scope == scope)
            .cloned()
            .collect();
        keys.iter()
            .filter_map(|key| registry.held.remove(key))
            .collect()
    };
    drop(released);
}

/// How many files are held for the copy `scope`.
#[cfg(test)]
pub(crate) fn count(scope: u64) -> usize {
    registry()
        .held
        .keys()
        .filter(|key| key.scope == scope)
        .count()
}

/// The refusal for a write to a file this receiver does not hold.
pub(super) fn not_held(label: &Path) -> anyhow::Error {
    anyhow::anyhow!("{} is not open in this receiver", label.display())
}

/// The refusal for a new in-place file whose name no longer leads to it.
pub(super) fn moved(label: &Path) -> anyhow::Error {
    anyhow::anyhow!(
        "{} was replaced while this copy wrote it in place",
        label.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(count: usize) -> Vec<RelativePath> {
        (0..count)
            .map(|index| RelativePath::new(format!("f{index}").as_bytes()).unwrap())
            .collect()
    }

    #[test]
    fn beyond_the_bound_the_least_recently_used_file_not_in_use_is_let_go() {
        let directory = crate::test_support::tempdir().unwrap();
        let root = Root::open(directory.path()).unwrap();
        let file = File::create(directory.path().join("file")).unwrap();
        let (scope, copy_id) = (new_scope(), [1; 16]);
        let names = names(MAX_HELD + 2);
        let held = |name| For {
            scope,
            root: &root,
            target: name,
            copy_id: &copy_id,
            inplace: false,
        };
        for name in &names[..MAX_HELD] {
            hold(held(name), name, &file, None, true).unwrap();
        }
        // The oldest was used since; the next is cached by a connection.
        get(held(&names[0])).unwrap().unwrap();
        let cached = get(held(&names[1])).unwrap().unwrap().in_use;
        hold(held(&names[MAX_HELD]), &names[MAX_HELD], &file, None, true).unwrap();
        assert_eq!(count(scope), MAX_HELD);
        assert!(get(held(&names[2])).unwrap().is_none());
        for name in [&names[0], &names[1], &names[3], &names[MAX_HELD]] {
            assert!(get(held(name)).unwrap().is_some());
        }
        // Files in use are never let go, even beyond the bound.
        let in_use: Vec<_> = names[3..MAX_HELD + 1]
            .iter()
            .chain(&names[..1])
            .map(|name| get(held(name)).unwrap().unwrap().in_use)
            .collect();
        hold(
            held(&names[MAX_HELD + 1]),
            &names[MAX_HELD + 1],
            &file,
            None,
            true,
        )
        .unwrap();
        assert_eq!(count(scope), MAX_HELD + 1);
        drop((cached, in_use));
        release(scope);
    }

    #[test]
    fn a_copys_files_are_let_go_together_and_only_its_own() {
        let directory = crate::test_support::tempdir().unwrap();
        let root = Root::open(directory.path()).unwrap();
        let file = File::create(directory.path().join("file")).unwrap();
        let name = RelativePath::new(b"file").unwrap();
        let (ended, running) = (new_scope(), new_scope());
        for scope in [ended, running] {
            for copy_id in [[1; 16], [2; 16]] {
                let held = For {
                    scope,
                    root: &root,
                    target: &name,
                    copy_id: &copy_id,
                    inplace: false,
                };
                hold(held, &name, &file, None, true).unwrap();
            }
        }
        release(ended);
        assert_eq!((count(ended), count(running)), (0, 2));
        release(running);
    }

    #[test]
    fn a_second_finalize_waits_for_the_first() {
        let directory = crate::test_support::tempdir().unwrap();
        let root = Root::open(directory.path()).unwrap();
        let file = File::create(directory.path().join("file")).unwrap();
        let name = RelativePath::new(b"file").unwrap();
        let (scope, copy_id) = (new_scope(), [3; 16]);
        let held = For {
            scope,
            root: &root,
            target: &name,
            copy_id: &copy_id,
            inplace: false,
        };
        hold(held, &name, &file, None, true).unwrap();
        let (first, finalizing) = finalize(held).unwrap();
        std::thread::scope(|threads| {
            let (sender, receiver) = std::sync::mpsc::channel();
            threads.spawn(move || {
                sender
                    .send(finalize(held).map(|(held, _)| held.relative))
                    .unwrap();
            });
            // The first fails and holds the file again; only then does the
            // second take it.
            assert!(receiver
                .recv_timeout(std::time::Duration::from_millis(200))
                .is_err());
            hold(held, &first.relative, &first.file, None, true).unwrap();
            drop(finalizing);
            let second = receiver
                .recv_timeout(std::time::Duration::from_secs(10))
                .unwrap();
            assert!(second == Some(name.clone()));
        });
        // After one that published, a second finds nothing held.
        hold(held, &name, &file, None, true).unwrap();
        drop(finalize(held).unwrap());
        assert!(finalize(held).is_none());
        release(scope);
    }
}

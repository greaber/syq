//! The files this receiver is writing a copy's data into: each copy's
//! sidecars ("stages"), and the new files `--in-place=new` writes. Every connection of
//! a copy runs in this process, so the descriptor that created or opened such
//! a file is kept here, and every later write, from any connection, and
//! Finalize go through it. A file someone renames into its place in the
//! meantime is never written, and never gets the copy's metadata.
//!
//! A file is held from the request that created or opened it until Finalize
//! takes it, a later attempt replaces it, or the copy's control connection
//! ends, after which nothing is held for the copy. A write to a file not
//! held here is refused, and the file fails as for any other write error.
//!
//! At most `MAX_HELD` files are held. Beyond that the one used least
//! recently is let go, unless a connection is using it. A worker has at most
//! three files in flight: the one it writes and up to two whose publication
//! is in flight (`transfer::publication`). So what is let go is a file that
//! failed and was not retried.
//!
//! Each connection also remembers the last few files its Finalize published
//! (`REMEMBERED`), until one of them is held again or the copy's control
//! connection ends. When a connection drops before its Finalize reply is
//! read, the copy sends that Finalize again on another connection, which
//! then gets the same answer: the file was published, with the identity the
//! first one reported.
//!
//! Each held file keeps the size the request that created or opened it
//! declared, and no write goes past it: what a copy writes is bounded by
//! what it said it would write, on every receiver.

use super::*;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Condvar, MutexGuard};

/// Files held at once: four for each worker connection a receiver serves
/// (`server::MAX_WORKER_CONNECTIONS`), more than a worker has in flight.
/// Tests reach the bound with fewer.
pub(super) const MAX_HELD: usize = if cfg!(test) { 16 } else { 1024 };

/// A new scope for one copy's held files, in a process that serves several
/// copies, which runs until `release`. Scope 0 is the copy of a process
/// that serves only one.
pub(crate) fn new_scope() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let scope = NEXT.fetch_add(1, Relaxed);
    registry().running.insert(scope);
    scope
}

/// The published files each connection remembers: its last few. A worker
/// has at most two Finalize replies unread, and they are for the last
/// Finalizes its connection ran (`transfer::publication`).
const REMEMBERED: usize = 4;

/// A new number for a connection, which the files its Finalize published
/// are remembered by (`Finalizing::published`).
pub(super) fn new_connection() -> u64 {
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
    /// The size declared for the file, which no write may go past.
    pub(super) declared: u64,
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
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(super) created: bool,
    /// As `Held::declared`.
    pub(super) declared: u64,
}

#[derive(Default)]
struct Registry {
    held: HashMap<Key, Held>,
    /// Files whose Finalize is running, and whether their copy has ended
    /// since; a second Finalize waits for it.
    finalizing: HashMap<Key, bool>,
    /// Files a Finalize published and that are not held again, with the
    /// connection that published them and the identity it reported.
    published: HashMap<Key, (u64, Option<(u64, u64)>)>,
    /// The files in `published`, oldest first, by copy scope and connection.
    published_by: HashMap<(u64, u64), VecDeque<Key>>,
    /// The scopes from `new_scope` whose copy has not ended (`release`).
    running: HashSet<u64>,
    clock: u64,
}

impl Registry {
    /// No longer remember that `key`'s file was published: another file is
    /// held for it now.
    fn forget_published(&mut self, key: &Key) {
        if let Some((connection, _)) = self.published.remove(key) {
            if let Some(keys) = self.published_by.get_mut(&(key.scope, connection)) {
                keys.retain(|other| other != key);
            }
        }
    }

    /// Whether the copy `scope` goes on: a file is held for it only then,
    /// as nothing would let the file go after its copy ended.
    fn running(&self, scope: u64) -> bool {
        scope == 0 || self.running.contains(&scope)
    }
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
/// `relative`, as the file for `target`, `declared` bytes long, replacing
/// what was held for it, and return the share of its use count for a
/// connection that caches `file`. A request that its copy's end overtook
/// holds nothing, and fails: its file stays, as an interrupted copy leaves
/// one.
/// Descriptors let go are closed after the registry is unlocked: a close
/// can wait for a network filesystem.
pub(super) fn hold(
    target: For<'_>,
    relative: &RelativePath,
    file: &File,
    opened: Option<fs::Metadata>,
    created: bool,
    declared: u64,
) -> io::Result<Arc<()>> {
    let scope = target.scope;
    let held = hold_if(
        target.key(),
        relative,
        file,
        opened,
        created,
        declared,
        |registry| registry.running(scope),
    )?;
    held.ok_or_else(|| io::Error::other("the copy has ended"))
}

/// `hold`, if `allowed` says so with the registry locked.
fn hold_if(
    key: Key,
    relative: &RelativePath,
    file: &File,
    opened: Option<fs::Metadata>,
    created: bool,
    declared: u64,
    allowed: impl FnOnce(&Registry) -> bool,
) -> io::Result<Option<Arc<()>>> {
    let file = file.try_clone()?;
    let in_use = Arc::new(());
    let mut released = Vec::new();
    {
        let mut registry = registry();
        if !allowed(&registry) {
            return Ok(None);
        }
        registry.clock += 1;
        let held = Held {
            file,
            opened,
            relative: relative.clone(),
            created,
            declared,
            in_use: in_use.clone(),
            used: registry.clock,
        };
        registry.forget_published(&key);
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
    Ok(Some(in_use))
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
        declared: held.declared,
    }))
}

/// Declare the file held for `target` `declared` bytes long, as a request
/// that prepares it again does.
pub(super) fn declare(target: For<'_>, declared: u64) {
    if let Some(held) = registry().held.get_mut(&target.key()) {
        held.declared = declared;
    }
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

impl Finalizing {
    /// The Finalize published the file, as `identity`: remember that as one
    /// of the last files `connection` published, before a Finalize waiting
    /// for this one looks. Nothing is remembered for a copy that ended
    /// meanwhile: nothing would forget it. Nor while a newer file is held
    /// for the same name, which a Finalize publishes instead: if it were let
    /// go unpublished, this one's identity would answer for it.
    pub(super) fn published(&self, connection: u64, identity: Option<(u64, u64)>) {
        let key = &self.0;
        let mut guard = registry();
        let registry = &mut *guard;
        if registry.finalizing.get(key) != Some(&false) || registry.held.contains_key(key) {
            return;
        }
        registry.forget_published(key);
        let keys = registry
            .published_by
            .entry((key.scope, connection))
            .or_default();
        keys.push_back(key.clone());
        if keys.len() > REMEMBERED {
            if let Some(oldest) = keys.pop_front() {
                registry.published.remove(&oldest);
            }
        }
        registry
            .published
            .insert(key.clone(), (connection, identity));
    }

    /// The Finalize failed: hold the file again, as `hold` does, so that the
    /// copy can finalize it again, unless the copy ended meanwhile. Nothing
    /// would let the file go then, and a Finalize waiting for this one finds
    /// nothing held.
    pub(super) fn hold_again(
        &self,
        relative: &RelativePath,
        file: &File,
        opened: Option<fs::Metadata>,
        created: bool,
        declared: u64,
    ) -> io::Result<()> {
        let key = &self.0;
        hold_if(
            key.clone(),
            relative,
            file,
            opened,
            created,
            declared,
            |registry| registry.finalizing.get(key) == Some(&false),
        )
        .map(drop)
    }
}

impl Drop for Finalizing {
    fn drop(&mut self) {
        registry().finalizing.remove(&self.0);
        shared().finalized.notify_all();
    }
}

/// What a Finalize finds for its file.
pub(super) enum Found {
    /// The file, held: finalize it.
    Held(Box<Held>, Finalizing),
    /// A Finalize published the file, as this identity, and nothing has been
    /// held for it since.
    Published(Option<(u64, u64)>),
}

/// Take the file held for `target` to finalize it, after any Finalize of it
/// already running ends, or find that one published it.
pub(super) fn finalize(target: For<'_>) -> Option<Found> {
    let key = target.key();
    let mut registry = registry();
    while registry.finalizing.contains_key(&key) {
        registry = shared()
            .finalized
            .wait(registry)
            .unwrap_or_else(|poisoned| poisoned.into_inner());
    }
    let Some(held) = registry.held.remove(&key) else {
        return registry
            .published
            .get(&key)
            .map(|&(_, identity)| Found::Published(identity));
    };
    registry.finalizing.insert(key.clone(), false);
    Some(Found::Held(Box::new(held), Finalizing(key)))
}

/// The identity a Finalize reported when it published the file for
/// `target`, if one did and nothing is held for it now, after any Finalize
/// of it already running ends. Unlike `finalize`, this takes nothing to
/// publish. A file held for `target` is one that Finalize would publish,
/// even when a Finalize running as it was held recorded its own.
pub(super) fn repeated(target: For<'_>) -> Option<Option<(u64, u64)>> {
    let key = target.key();
    let mut registry = registry();
    while registry.finalizing.contains_key(&key) {
        registry = shared()
            .finalized
            .wait(registry)
            .unwrap_or_else(|poisoned| poisoned.into_inner());
    }
    if registry.held.contains_key(&key) {
        return None;
    }
    registry.published.get(&key).map(|&(_, identity)| identity)
}

/// Let go of every file held for the copy `scope`, and forget those it
/// published, when its control connection ends. Nothing is held for it
/// after that.
pub(crate) fn release(scope: u64) {
    let released: Vec<Held> = {
        let mut registry = registry();
        registry.running.remove(&scope);
        for (key, ended) in &mut registry.finalizing {
            *ended |= key.scope == scope;
        }
        registry.published.retain(|key, _| key.scope != scope);
        registry
            .published_by
            .retain(|&(published, _), _| published != scope);
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

/// How many published files are remembered for the copy `scope`, and by
/// how many connections.
#[cfg(test)]
fn remembered(scope: u64) -> (usize, usize) {
    let registry = registry();
    (
        registry
            .published
            .keys()
            .filter(|key| key.scope == scope)
            .count(),
        registry
            .published_by
            .keys()
            .filter(|(published, _)| *published == scope)
            .count(),
    )
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
            hold(held(name), name, &file, None, true, 0).unwrap();
        }
        // The oldest was used since; the next is cached by a connection.
        get(held(&names[0])).unwrap().unwrap();
        let cached = get(held(&names[1])).unwrap().unwrap().in_use;
        hold(
            held(&names[MAX_HELD]),
            &names[MAX_HELD],
            &file,
            None,
            true,
            0,
        )
        .unwrap();
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
            0,
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
                hold(held, &name, &file, None, true, u64::MAX).unwrap();
            }
        }
        release(ended);
        assert_eq!((count(ended), count(running)), (0, 2));
        release(running);
    }

    #[test]
    fn a_repeat_finds_nothing_while_a_newer_file_is_held() {
        let directory = crate::test_support::tempdir().unwrap();
        let root = Root::open(directory.path()).unwrap();
        let file = File::create(directory.path().join("file")).unwrap();
        let name = RelativePath::new(b"file").unwrap();
        let (scope, copy_id) = (new_scope(), [9; 16]);
        let held = For {
            scope,
            root: &root,
            target: &name,
            copy_id: &copy_id,
            inplace: false,
        };
        hold(held, &name, &file, None, true, 1).unwrap();
        let (_, finalizing) = taken(finalize(held));
        // A newer file is held while the first Finalize runs, which then
        // records its publication.
        hold(held, &name, &file, None, true, 1).unwrap();
        finalizing.published(new_connection(), Some((1, 2)));
        drop(finalizing);
        assert!(repeated(held).is_none());
        // Let go unpublished, the newer file leaves no publication for a
        // Finalize to be answered with.
        drop(take(held));
        assert!(finalize(held).is_none());
        assert!(repeated(held).is_none());
        hold(held, &name, &file, None, true, 1).unwrap();
        let (newer, finalizing) = taken(finalize(held));
        assert!(newer.relative == name);
        finalizing.published(new_connection(), Some((3, 4)));
        drop(finalizing);
        assert_eq!(repeated(held), Some(Some((3, 4))));
        release(scope);
    }

    #[test]
    fn a_scope_is_let_go_when_dropped() {
        let scope = StageScope::new();
        let number = scope.get();
        assert!(registry().running(number));
        drop(scope);
        assert!(!registry().running(number));
    }

    #[test]
    fn nothing_is_held_for_a_copy_that_ended() {
        let directory = crate::test_support::tempdir().unwrap();
        let root = Root::open(directory.path()).unwrap();
        let file = File::create(directory.path().join("file")).unwrap();
        let name = RelativePath::new(b"file").unwrap();
        let (ended, running, copy_id) = (new_scope(), new_scope(), [8; 16]);
        let held = |scope| For {
            scope,
            root: &root,
            target: &name,
            copy_id: &copy_id,
            inplace: false,
        };
        release(ended);
        // A request its copy's end overtook holds nothing, so nothing is
        // left held for a copy that will not let it go.
        let error = hold(held(ended), &name, &file, None, true, 1).unwrap_err();
        assert_eq!(error.to_string(), "the copy has ended");
        assert!(get(held(ended)).unwrap().is_none());
        assert_eq!(count(ended), 0);
        hold(held(running), &name, &file, None, true, 1).unwrap();
        assert_eq!(count(running), 1);
        release(running);
        assert_eq!(count(running), 0);
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
        hold(held, &name, &file, None, true, u64::MAX).unwrap();
        let (first, finalizing) = taken(finalize(held));
        std::thread::scope(|threads| {
            let (sender, receiver) = std::sync::mpsc::channel();
            threads.spawn(move || {
                sender
                    .send(finalize(held).map(|found| taken(Some(found)).0.relative))
                    .unwrap();
            });
            // The first fails and holds the file again; only then does the
            // second take it.
            assert!(receiver
                .recv_timeout(std::time::Duration::from_millis(200))
                .is_err());
            finalizing
                .hold_again(&first.relative, &first.file, None, true, u64::MAX)
                .unwrap();
            drop(finalizing);
            let second = receiver
                .recv_timeout(std::time::Duration::from_secs(10))
                .unwrap();
            assert!(second == Some(name.clone()));
        });
        // After one that failed and let the file go, a second finds
        // nothing held.
        hold(held, &name, &file, None, true, u64::MAX).unwrap();
        drop(taken(finalize(held)));
        assert!(finalize(held).is_none());
        release(scope);
    }

    #[test]
    fn a_finalize_that_fails_after_its_copy_ended_lets_the_file_go() {
        let directory = crate::test_support::tempdir().unwrap();
        let root = Root::open(directory.path()).unwrap();
        let file = File::create(directory.path().join("file")).unwrap();
        let name = RelativePath::new(b"file").unwrap();
        let (scope, copy_id) = (new_scope(), [6; 16]);
        let held = For {
            scope,
            root: &root,
            target: &name,
            copy_id: &copy_id,
            inplace: true,
        };
        hold(held, &name, &file, None, true, u64::MAX).unwrap();
        let (first, finalizing) = taken(finalize(held));
        std::thread::scope(|threads| {
            let (sender, receiver) = std::sync::mpsc::channel();
            threads.spawn(move || {
                let found = finalize(held);
                sender.send(matches!(found, Some(Found::Held(..)))).unwrap();
            });
            // A second Finalize waits for the first. The copy ends, then
            // the first fails: the file is not held again, so the second
            // finds nothing to publish or remember.
            assert!(receiver
                .recv_timeout(std::time::Duration::from_millis(200))
                .is_err());
            release(scope);
            finalizing
                .hold_again(&first.relative, &first.file, None, true, u64::MAX)
                .unwrap();
            drop(finalizing);
            let found = receiver
                .recv_timeout(std::time::Duration::from_secs(10))
                .unwrap();
            assert!(!found);
        });
        assert_eq!(count(scope), 0);
        assert_eq!(remembered(scope), (0, 0));
    }

    fn taken(found: Option<Found>) -> (Held, Finalizing) {
        match found {
            Some(Found::Held(held, finalizing)) => (*held, finalizing),
            Some(Found::Published(_)) => panic!("published, not held"),
            None => panic!("not held"),
        }
    }

    fn published(found: Option<Found>) -> Option<(u64, u64)> {
        match found {
            Some(Found::Published(identity)) => identity,
            Some(Found::Held(..)) => panic!("held, not published"),
            None => panic!("not held"),
        }
    }

    #[test]
    fn a_finalize_sent_again_answers_as_the_one_that_published() {
        let directory = crate::test_support::tempdir().unwrap();
        let root = Root::open(directory.path()).unwrap();
        let file = File::create(directory.path().join("file")).unwrap();
        let (scope, copy_id) = (new_scope(), [4; 16]);
        let names = names(REMEMBERED + 2);
        let held = |name| For {
            scope,
            root: &root,
            target: name,
            copy_id: &copy_id,
            inplace: true,
        };
        let publish = |name, connection, identity| {
            hold(held(name), name, &file, None, true, 1).unwrap();
            let (_, finalizing) = taken(finalize(held(name)));
            finalizing.published(connection, identity);
        };
        let (dropped, other) = (new_connection(), new_connection());
        publish(&names[0], dropped, Some((1, 2)));
        publish(&names[1], dropped, None);
        // Another connection's publications displace none of them.
        for name in &names[2..] {
            publish(name, other, Some((3, 4)));
        }
        assert_eq!(published(finalize(held(&names[0]))), Some((1, 2)));
        assert_eq!(published(finalize(held(&names[1]))), None);
        // The same answer again, and only for this copy and file.
        assert_eq!(published(finalize(held(&names[0]))), Some((1, 2)));
        let another_copy = [5; 16];
        assert!(finalize(For {
            copy_id: &another_copy,
            ..held(&names[0])
        })
        .is_none());
        assert!(finalize(For {
            inplace: false,
            ..held(&names[0])
        })
        .is_none());
        // A connection remembers its last few.
        for name in &names[2..] {
            publish(name, dropped, Some((5, 6)));
        }
        assert!(finalize(held(&names[0])).is_none());
        assert!(finalize(held(&names[1])).is_none());
        assert_eq!(published(finalize(held(&names[2]))), Some((5, 6)));
        // A file held again is finalized as that one; the copy's end
        // forgets the rest.
        hold(held(&names[2]), &names[2], &file, None, true, 1).unwrap();
        drop(taken(finalize(held(&names[2]))));
        assert!(finalize(held(&names[2])).is_none());
        // A Finalize that ends after its copy did leaves nothing behind.
        hold(held(&names[0]), &names[0], &file, None, true, 1).unwrap();
        let (_, finalizing) = taken(finalize(held(&names[0])));
        release(scope);
        finalizing.published(dropped, Some((7, 8)));
        drop(finalizing);
        assert!(finalize(held(&names[0])).is_none());
        assert!(finalize(held(&names[3])).is_none());
        assert_eq!(remembered(scope), (0, 0));
    }
}

//! The files this receiver is writing a copy's data into: each copy's
//! sidecars ("stages"), and the files `--inplace` writes. Every connection of
//! a copy runs in this process, so the descriptor that created or opened such
//! a file is kept here, and every later write, from any connection, and
//! Finalize go through it. Nothing reopens the file by name to write it: a
//! file someone renames into its place in the meantime is never written, and
//! never gets the copy's metadata.
//!
//! A file is held from the request that created or opened it until Finalize
//! takes it, or until a later attempt replaces it. A write to a file not held
//! here is refused; the coordinator then retries the file, and the retry
//! starts a new stage, reading whatever it finds at the name only as a donor
//! of blocks the source's hashes confirm.
//!
//! At most `MAX_HELD` files are held; beyond that the oldest is let go, and a
//! write to it is refused as above. A copy has at most about two files in
//! flight per worker, so this bound is reached only by files that failed and
//! were not retried.

use super::*;

/// Files held at once, about two for each connection a receiver serves.
pub(super) const MAX_HELD: usize = 1024;

/// A held file is found by the file it is for, the copy's target: a stage's
/// own name can be shortened to fit the filesystem when it is created.
#[derive(Clone, PartialEq, Eq, Hash)]
struct Key {
    root: (u64, u64),
    target: Vec<u8>,
    copy_id: CopyId,
    inplace: bool,
}

/// What a stage or in-place file is for: `target` below `root`, written for
/// `copy_id`, in place or through a stage.
#[derive(Clone, Copy)]
pub(super) struct For<'a> {
    pub(super) root: &'a Root,
    pub(super) target: &'a RelativePath,
    pub(super) copy_id: &'a CopyId,
    pub(super) inplace: bool,
}

/// What the copy writes to `target` for `copy_id` is for.
pub(super) fn of<'a>(target: &'a RootedTarget, copy_id: &'a CopyId, inplace: bool) -> For<'a> {
    For {
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
            root: (identity.dev, identity.ino),
            target: self.target.to_bytes(),
            copy_id: *self.copy_id,
            inplace: self.inplace,
        }
    }
}

/// A held file: the descriptor that created or opened it, the metadata read
/// then, before anything was written, and its name: the stage's, or the
/// target's for an in-place file.
pub(super) struct Held {
    pub(super) file: File,
    pub(super) opened: Option<fs::Metadata>,
    pub(super) relative: RelativePath,
}

#[derive(Default)]
struct Registry {
    held: HashMap<Key, Held>,
    order: std::collections::VecDeque<Key>,
}

fn registry() -> std::sync::MutexGuard<'static, Registry> {
    static HELD: OnceLock<Mutex<Registry>> = OnceLock::new();
    HELD.get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

/// Hold `file`, which this receiver just created or opened at `relative`,
/// as the file for `target`, replacing what was held for it.
pub(super) fn hold(
    target: For<'_>,
    relative: &RelativePath,
    file: &File,
    opened: Option<fs::Metadata>,
) -> io::Result<()> {
    let held = Held {
        file: file.try_clone()?,
        opened,
        relative: relative.clone(),
    };
    let key = target.key();
    let mut registry = registry();
    if registry.held.insert(key.clone(), held).is_some() {
        registry.order.retain(|held| held != &key);
    }
    registry.order.push_back(key);
    while registry.order.len() > MAX_HELD {
        if let Some(oldest) = registry.order.pop_front() {
            registry.held.remove(&oldest);
        }
    }
    Ok(())
}

/// A descriptor of the file held for `target`, sharing the held one's open
/// file description, with the metadata read when it was opened and its name.
pub(super) fn get(
    target: For<'_>,
) -> io::Result<Option<(File, Option<fs::Metadata>, RelativePath)>> {
    registry()
        .held
        .get(&target.key())
        .map(|held| {
            Ok((
                held.file.try_clone()?,
                held.opened.clone(),
                held.relative.clone(),
            ))
        })
        .transpose()
}

/// Whether a file is held for `target` at `relative`.
pub(super) fn holds(target: For<'_>, relative: &RelativePath) -> bool {
    registry()
        .held
        .get(&target.key())
        .is_some_and(|held| &held.relative == relative)
}

/// Stop holding the file for `target` and return it, as Finalize does.
pub(super) fn take(target: For<'_>) -> Option<Held> {
    let key = target.key();
    let mut registry = registry();
    let held = registry.held.remove(&key)?;
    registry.order.retain(|held| held != &key);
    Some(held)
}

/// The refusal for a write to a file this receiver does not hold.
pub(super) fn not_held(label: &Path) -> anyhow::Error {
    anyhow::anyhow!(
        "{} is not open in this receiver; it will be written again",
        label.display()
    )
}

/// A descriptor for reading the held file `writer`: a duplicate when it is
/// open for reading, or else the file at `relative` opened for reading, which
/// must be the held file.
pub(super) fn reader(
    root: &Root,
    relative: &RelativePath,
    label: &Path,
    writer: &File,
) -> Result<File> {
    // SAFETY: F_GETFL only reads the descriptor's status flags.
    let flags = unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETFL) };
    if flags >= 0 && flags & libc::O_ACCMODE != libc::O_WRONLY {
        return Ok(writer.try_clone()?);
    }
    let reader = root.open_regular_read(relative)?;
    let (held, opened) = (writer.metadata()?, reader.metadata()?);
    if (held.dev(), held.ino()) != (opened.dev(), opened.ino()) {
        bail!(
            "{} was replaced while this receiver held it",
            label.display()
        );
    }
    Ok(reader)
}

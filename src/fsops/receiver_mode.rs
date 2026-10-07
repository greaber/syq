//! Modes the receiver chooses. Without permission preservation a sender
//! proposes its source mode with `flags::RECEIVER_MODE`, and the receiver
//! applies the no-`-p` rule itself, as every receiver does: a file published
//! over a regular file takes that file's mode, a new object gets the
//! proposal's permission bits limited by the receiver's umask (or, for
//! `syq rsync`, by its directory's default ACL), and an existing object keeps
//! its mode.
//! A proposal is never applied as it stands: the metadata steps apply only
//! `flags::MODE`, so a `RECEIVER_MODE` left unresolved keeps the mode.
//! What the sender's scan found at a file's path (`ScannedDestination`)
//! spares the receiver a lookup; a command-restricted receiver's authority
//! discards it, and the receiver looks.

use super::*;
use crate::proto::ScannedDestination;
use crate::rooted::HeldParent;
use std::borrow::Cow;

/// Directories this connection created with more access than their mode
/// (private, or with the owner access to fill them), with the modes they
/// were created with, which a later receiver-chosen mode gives the mode
/// creating them would have given them, and directories it widened, with
/// the modes to restore. Directory creation, widening and their final
/// metadata all travel on the connection that plans them.
#[derive(Default)]
pub(super) struct ReceiverDirectories {
    created: Mutex<HashMap<(u64, u64), u32>>,
    widened: Mutex<HashMap<(u64, u64), u32>>,
}

/// Directories created private that a connection remembers. A planner asks
/// for a mode only for the destination root, which it creates before
/// anything in it, so the first few cover it; one not remembered keeps its
/// mode, and a tree of private directories costs no memory per directory.
/// Directories to narrow are all remembered, until they are narrowed.
const REMEMBERED_PRIVATE_DIRECTORIES: usize = 1024;

impl ReceiverDirectories {
    /// Remember a directory this connection created: one to narrow once it
    /// is filled, or one created private.
    pub(super) fn created(&self, identity: (u64, u64), mode: u32, narrowing: bool) {
        let mut created = self.created.lock().unwrap();
        if narrowing || created.len() < REMEMBERED_PRIVATE_DIRECTORIES {
            created.insert(identity, mode);
        }
    }

    pub(super) fn widened(&self, identity: (u64, u64), mode: u32) {
        self.widened.lock().unwrap().insert(identity, mode);
    }

    /// `op` with its receiver-chosen mode resolved. Only a directory this
    /// connection widened, or created private, takes a mode; anything else
    /// keeps its own.
    pub(super) fn resolve_op<'a>(
        &self,
        op: &'a Op,
        guard: Option<&ContainerGuard>,
        destination_root: Option<Arc<Root>>,
        destination_prefix: Option<&[u8]>,
    ) -> Cow<'a, Op> {
        match op {
            Op::SetFileMetaIfSame { flags, .. } if flags & flags::RECEIVER_MODE != 0 => {
                let mut op = op.clone();
                if let Op::SetFileMetaIfSame { flags, .. } = &mut op {
                    *flags &= !flags::RECEIVER_MODE;
                }
                Cow::Owned(op)
            }
            Op::SetMeta {
                path,
                meta,
                flags,
                condition,
            } if flags & flags::RECEIVER_MODE != 0 => {
                let mut meta = meta.clone();
                let mut flags = flags & !flags::RECEIVER_MODE;
                let mut condition = *condition;
                // A failed decision keeps the mode; the operation itself
                // reports what is wrong with its path.
                let target =
                    apply::operation_target(path, guard, destination_root, destination_prefix);
                if let Ok(Some((mode, identity))) =
                    target.and_then(|target| self.directory_mode(&target, meta.mode))
                {
                    let matched = match condition {
                        TargetCondition::Any => true,
                        TargetCondition::Matches { dev, ino }
                        | TargetCondition::MatchesFingerprint { dev, ino, .. } => {
                            (dev, ino) == identity
                        }
                        TargetCondition::Absent => false,
                    };
                    if matched {
                        meta.mode = mode;
                        flags |= flags::MODE;
                        if condition == TargetCondition::Any {
                            condition = TargetCondition::Matches {
                                dev: identity.0,
                                ino: identity.1,
                            };
                        }
                    }
                }
                Cow::Owned(Op::SetMeta {
                    path: path.clone(),
                    meta,
                    flags,
                    condition,
                })
            }
            _ => Cow::Borrowed(op),
        }
    }

    /// The mode for the directory at `target` this connection widened (the
    /// mode it had) or created (the mode creating it with `proposed` would
    /// have given it), with its identity. A directory it created keeps a
    /// setgid bit while it has one, and gets back the one it inherited at
    /// creation when `proposed` has that bit, as its final metadata asks
    /// after a group change that cleared it. A proposal without owner access
    /// is a directory's last: it is forgotten then.
    fn directory_mode(
        &self,
        target: &RootedTarget,
        proposed: u32,
    ) -> Result<Option<(u32, (u64, u64))>> {
        let Some(metadata) = target.root.metadata_optional(&target.relative)? else {
            return Ok(None);
        };
        if !metadata.is_dir() {
            return Ok(None);
        }
        let identity = (metadata.dev, metadata.ino);
        if let Some(mode) = self.widened.lock().unwrap().remove(&identity) {
            return Ok(Some((mode, identity)));
        }
        let created = {
            let mut created = self.created.lock().unwrap();
            if proposed & 0o700 != 0o700 {
                created.remove(&identity)
            } else {
                created.get(&identity).copied()
            }
        };
        let Some(created) = created else {
            return Ok(None);
        };
        let directory = target.root.open_metadata(&target.relative)?;
        let opened = directory.metadata()?;
        if !opened.is_dir() || (opened.dev(), opened.ino()) != identity {
            return Ok(None);
        }
        let mode = apply::created_directory_mode(&directory, proposed, opened.mode())?;
        Ok(Some((mode | (proposed & created & 0o2000), identity)))
    }
}

/// How a file to be written in place was opened: created by this copy, or
/// found with this mode before anything was written to it.
#[derive(Clone, Copy, Debug)]
enum InplaceOpen {
    Created,
    Found(u32),
}

/// Files this process opened to write a copy's data in place, which
/// finalize gives the mode creating them would have given them or, since
/// writes clear set-ID bits, the mode they were found with. Finalize may
/// come on another connection than the open, so the record is shared by the
/// process; the copy ID keeps one copy's files from another's.
fn inplace_opened() -> &'static Mutex<InplaceOpens> {
    static OPENED: OnceLock<Mutex<InplaceOpens>> = OnceLock::new();
    OPENED.get_or_init(Default::default)
}

/// In-place opens by copy and file identity.
type InplaceOpens = HashMap<(CopyId, u64, u64), InplaceOpen>;

/// Record a file this process just opened to write `copy_id`'s data in
/// place: one it `created`, or one it found as `opened` says. A retry's
/// open, after writes that may have cleared set-ID bits, keeps the first
/// record.
pub(super) fn note_inplace_open(copy_id: &CopyId, opened: &fs::Metadata, created: bool) {
    let open = if created {
        InplaceOpen::Created
    } else {
        InplaceOpen::Found(opened.mode() & 0o7777)
    };
    inplace_opened()
        .lock()
        .unwrap()
        .entry((*copy_id, opened.dev(), opened.ino()))
        .or_insert(open);
}

/// Whether this process created the file `opened` describes to write
/// `copy_id`'s data in place.
pub(super) fn created_inplace(copy_id: &CopyId, opened: &fs::Metadata) -> bool {
    matches!(
        inplace_opened()
            .lock()
            .unwrap()
            .get(&(*copy_id, opened.dev(), opened.ino())),
        Some(InplaceOpen::Created)
    )
}

impl FsOps {
    /// The mode creating a file at `target` from `proposed` gives it: the
    /// proposal's permission bits limited by its directory's default ACL if
    /// it has one, or else by the umask. Each directory's ACL is read once
    /// per connection.
    pub(super) fn new_file_mode(&self, target: &RootedTarget, proposed: u32) -> Result<u32> {
        let (parents, _) = target.relative.leaf()?;
        let identity = target.root.identity();
        let key = (identity.dev, identity.ino, parents.to_vec());
        let cached = self.creation_permissions.lock().unwrap().get(&key).copied();
        let permitted = match cached {
            Some(permitted) => permitted,
            None => {
                let permitted = target.root.creation_permissions(&target.relative)?;
                let mut cache = self.creation_permissions.lock().unwrap();
                if cache.len() >= CREATION_PERMISSION_DIRECTORIES {
                    cache.clear();
                }
                cache.insert(key, permitted);
                permitted
            }
        };
        Ok(proposed & permitted & 0o777)
    }

    /// Decide `flags` and `meta` for publishing a file at `target`, where
    /// the sender's scan found `scanned`: a new file gets the mode creating
    /// it gives, a replacement keeps the mode of the file it replaces, and
    /// with nothing known the receiver looks (`held` keeps the last
    /// directory it looked in open for the next name).
    pub(super) fn resolve_publication(
        &self,
        target: &RootedTarget,
        meta: &mut Meta,
        flags: &mut u8,
        held: &mut Option<HeldParent>,
        scanned: ScannedDestination,
    ) -> Result<()> {
        if *flags & flags::RECEIVER_MODE == 0 {
            return Ok(());
        }
        meta.mode = match scanned {
            ScannedDestination::Unknown => {
                target
                    .root
                    .receiver_file_mode(&target.relative, meta.mode, held)?
            }
            ScannedDestination::Absent => self.new_file_mode(target, meta.mode)?,
            ScannedDestination::File(mode) => mode & 0o7777,
        };
        *flags = (*flags & !flags::RECEIVER_MODE) | flags::MODE;
        Ok(())
    }

    /// The metadata and flags for finalizing a file written in place, when
    /// the receiver chooses its mode: a file the copy created gets the mode
    /// creating it would have given it, without the owner access its other
    /// writers needed, and an existing file the mode it had before the
    /// writes, which clear its set-ID bits. This process records the files
    /// it opened; a copy whose writers run in other processes says what its
    /// scan found. `None` leaves the metadata as it is.
    pub(super) fn inplace_final_mode(
        &self,
        target: &RootedTarget,
        copy_id: &CopyId,
        current: &fs::Metadata,
        meta: &Meta,
        flags: u8,
        scanned: ScannedDestination,
    ) -> Result<Option<(Meta, u8)>> {
        let opened =
            inplace_opened()
                .lock()
                .unwrap()
                .remove(&(*copy_id, current.dev(), current.ino()));
        if flags & flags::RECEIVER_MODE == 0 {
            return Ok(None);
        }
        let flags = flags & !flags::RECEIVER_MODE;
        // A file this receiver created, or one the scan found absent before
        // the copy, is new: one this process merely found may be an earlier
        // attempt's, made by another process with the owner access its
        // writers needed, as the small-file in-place path decides too. Then
        // what this receiver found, then what the scan found.
        let mode = match (opened, scanned) {
            (Some(InplaceOpen::Created), _) | (_, ScannedDestination::Absent) => {
                self.new_file_mode(target, meta.mode)?
            }
            (Some(InplaceOpen::Found(mode)), _) | (None, ScannedDestination::File(mode)) => mode,
            (None, ScannedDestination::Unknown) => return Ok(Some((meta.clone(), flags))),
        };
        Ok(Some((
            Meta {
                mode: mode & 0o7777,
                ..meta.clone()
            },
            flags | flags::MODE,
        )))
    }

    /// The mode `Prepare` creates its file in: an `--inplace` file in the
    /// publication's mode, as creating it limits a receiver-chosen one; a
    /// sidecar in its staged mode, from the mode publication will give it,
    /// with `scanned` what the sender's scan found at `path`.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn creation_mode(
        &mut self,
        path: &[u8],
        guard: Option<&ContainerGuard>,
        inplace: bool,
        mode: u32,
        mut flags: u8,
        acl: bool,
        scanned: ScannedDestination,
    ) -> Result<u32> {
        if inplace {
            // A proposal's special bits are never created.
            let mode = if flags & flags::RECEIVER_MODE != 0 {
                mode & 0o777
            } else {
                mode
            };
            return Ok(mode);
        }
        if flags & flags::RECEIVER_MODE == 0 {
            return Ok(staged_mode(mode, flags, acl));
        }
        // What the scan found spares the lookup; a new file's mode depends
        // on its directory's default ACL, read once per directory.
        let final_mode = match scanned {
            ScannedDestination::File(found) => found & 0o7777,
            _ => {
                let target = self.destination_mutation_target(path, guard)?;
                let mut meta = Meta {
                    mode,
                    uid: 0,
                    gid: 0,
                    mtime: 0,
                    mtime_nsec: 0,
                    inode_metadata: None,
                };
                self.resolve_publication(&target, &mut meta, &mut flags, &mut None, scanned)?;
                meta.mode
            }
        };
        flags = (flags & !flags::RECEIVER_MODE) | flags::MODE;
        Ok(staged_mode(final_mode, flags, acl))
    }
}

/// Directories whose default ACL a connection remembers before it starts
/// over.
const CREATION_PERMISSION_DIRECTORIES: usize = 4096;

/// The permission bits each directory's default ACL lets new files have, by
/// root identity and directory.
pub(super) type CreationPermissions = HashMap<(u64, u64, Vec<Vec<u8>>), u32>;

//! Modes the receiver chooses. Without permission preservation a sender
//! proposes its source mode with `flags::RECEIVER_MODE`, and the receiver
//! applies the no-`-p` rule itself, as every receiver does: a file published
//! over a regular file takes that file's mode, a new object gets the
//! proposal's permission bits limited by the receiver's umask (or, for
//! `syq rsync`, by its directory's default ACL), and an existing object keeps
//! its mode.
//! A proposal is never applied as it stands: the metadata steps apply only
//! `flags::MODE`, so a `RECEIVER_MODE` left unresolved keeps the mode.

use super::*;
use crate::rooted::HeldParent;

/// Directories this connection created private, with the modes they were
/// created with, which a later receiver-chosen mode gives the mode creating
/// them would have given them, and directories it widened, with the modes
/// to restore. Directory creation, widening and their final metadata all
/// travel on the connection that plans them.
#[derive(Default)]
pub(super) struct ReceiverDirectories {
    created_private: Mutex<HashMap<(u64, u64), u32>>,
    widened: Mutex<HashMap<(u64, u64), u32>>,
}

impl ReceiverDirectories {
    pub(super) fn created_private(&self, identity: (u64, u64), mode: u32) {
        self.created_private.lock().unwrap().insert(identity, mode);
    }

    pub(super) fn widened(&self, identity: (u64, u64), mode: u32) {
        self.widened.lock().unwrap().insert(identity, mode);
    }
}

/// Files this process created to write in place, which finalize gives the
/// mode their creation would have given them. Finalize may come on another
/// connection than the creation, so the set is shared by the process; the
/// copy ID keeps one copy's files from another's.
fn inplace_created() -> &'static Mutex<HashSet<(CopyId, u64, u64)>> {
    static CREATED: OnceLock<Mutex<HashSet<(CopyId, u64, u64)>>> = OnceLock::new();
    CREATED.get_or_init(Default::default)
}

/// Record a file this process just created to write `copy_id`'s data in
/// place.
pub(super) fn note_inplace_creation(copy_id: &CopyId, created: &fs::Metadata) {
    inplace_created()
        .lock()
        .unwrap()
        .insert((*copy_id, created.dev(), created.ino()));
}

/// Decide `flags` and `meta` for publishing a file at `target`, a new
/// file's permissions limited by its directory's default ACL with
/// `default_acl`, and otherwise by the umask.
pub(super) fn resolve_file_publication(
    target: &RootedTarget,
    meta: &mut Meta,
    flags: &mut u8,
    default_acl: bool,
    held: &mut Option<HeldParent>,
) -> Result<()> {
    if *flags & flags::RECEIVER_MODE == 0 {
        return Ok(());
    }
    meta.mode = target
        .root
        .receiver_file_mode(&target.relative, meta.mode, default_acl, held)?;
    *flags = (*flags & !flags::RECEIVER_MODE) | flags::MODE;
    Ok(())
}

impl FsOps {
    /// The metadata and flags for finalizing a file written in place, when
    /// the receiver chooses its mode: an existing file keeps its mode, and a
    /// file the copy created gets the mode creating it would have given it,
    /// without the owner access its other writers needed. This process knows
    /// the files it created; a copy whose writers run in other processes says
    /// which it created. `None` leaves the metadata as it is.
    pub(super) fn inplace_final_mode(
        &self,
        target: &RootedTarget,
        copy_id: &CopyId,
        current: &fs::Metadata,
        meta: &Meta,
        flags: u8,
        created: bool,
    ) -> Result<Option<(Meta, u8)>> {
        let noted =
            inplace_created()
                .lock()
                .unwrap()
                .remove(&(*copy_id, current.dev(), current.ino()));
        if flags & flags::RECEIVER_MODE == 0 {
            return Ok(None);
        }
        let flags = flags & !flags::RECEIVER_MODE;
        if !noted && !created {
            return Ok(Some((meta.clone(), flags)));
        }
        let mode = target.root.receiver_creation_mode(
            &target.relative,
            meta.mode,
            self.default_acl_creation,
            &mut None,
        )?;
        Ok(Some((
            Meta {
                mode,
                ..meta.clone()
            },
            flags | flags::MODE,
        )))
    }

    /// The mode `Prepare` creates its file in: an `--inplace` file in the
    /// publication's mode, which for a receiver-chosen mode is the proposal
    /// creation limits; a sidecar in its staged mode, from the mode
    /// publication will give it.
    pub(super) fn creation_mode(
        &mut self,
        path: &[u8],
        guard: Option<&ContainerGuard>,
        inplace: bool,
        mut mode: u32,
        mut flags: u8,
        acl: bool,
    ) -> Result<u32> {
        if inplace {
            return Ok(mode);
        }
        if flags & flags::RECEIVER_MODE != 0 {
            let target = self.destination_mutation_target(path, guard)?;
            let mut meta = Meta {
                mode,
                uid: 0,
                gid: 0,
                mtime: 0,
                mtime_nsec: 0,
                inode_metadata: None,
            };
            resolve_file_publication(
                &target,
                &mut meta,
                &mut flags,
                self.default_acl_creation,
                &mut None,
            )?;
            mode = meta.mode;
        }
        Ok(staged_mode(mode, flags, acl))
    }

    /// Resolve the receiver-chosen modes of an `Apply` request's metadata
    /// operations. Only a directory this connection widened, or created
    /// private, takes a mode; anything else keeps its own. Returns the
    /// operations to run when any changed.
    pub(super) fn resolve_metadata_ops(
        &self,
        ops: &[Op],
        guard: Option<&ContainerGuard>,
    ) -> Option<Vec<Op>> {
        if !ops.iter().any(|op| {
            matches!(op, Op::SetMeta { flags, .. } | Op::SetFileMetaIfSame { flags, .. }
                if flags & flags::RECEIVER_MODE != 0)
        }) {
            return None;
        }
        let mut ops = ops.to_vec();
        for op in &mut ops {
            match op {
                Op::SetFileMetaIfSame { flags, .. } => *flags &= !flags::RECEIVER_MODE,
                Op::SetMeta {
                    path,
                    meta,
                    flags,
                    condition,
                } if *flags & flags::RECEIVER_MODE != 0 => {
                    *flags &= !flags::RECEIVER_MODE;
                    // A failed decision keeps the mode; the operation itself
                    // reports what is wrong with its path.
                    if let Ok(Some((mode, identity))) = self.directory_mode(path, meta.mode, guard)
                    {
                        let matched = match *condition {
                            TargetCondition::Any => true,
                            TargetCondition::Matches { dev, ino }
                            | TargetCondition::MatchesFingerprint { dev, ino, .. } => {
                                (dev, ino) == identity
                            }
                            TargetCondition::Absent => false,
                        };
                        if matched {
                            meta.mode = mode;
                            *flags |= flags::MODE;
                            if *condition == TargetCondition::Any {
                                *condition = TargetCondition::Matches {
                                    dev: identity.0,
                                    ino: identity.1,
                                };
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        Some(ops)
    }

    /// The mode for a directory at `path` this connection widened (the mode
    /// it had) or created private (the mode creating it with `proposed`
    /// would have given it), with its identity. A directory created private
    /// keeps a setgid bit while it has one, and gets back the one it
    /// inherited at creation when `proposed` has that bit, as its final
    /// metadata asks after a group change that cleared it.
    fn directory_mode(
        &self,
        path: &[u8],
        proposed: u32,
        guard: Option<&ContainerGuard>,
    ) -> Result<Option<(u32, (u64, u64))>> {
        let target = apply::operation_target(
            path,
            guard,
            self.destination_root.clone(),
            self.destination_prefix.as_deref(),
        )?;
        let Some(metadata) = target.root.metadata_optional(&target.relative)? else {
            return Ok(None);
        };
        if !metadata.is_dir() {
            return Ok(None);
        }
        let identity = (metadata.dev, metadata.ino);
        if let Some(mode) = self
            .receiver_directories
            .widened
            .lock()
            .unwrap()
            .remove(&identity)
        {
            return Ok(Some((mode, identity)));
        }
        let Some(created) = self
            .receiver_directories
            .created_private
            .lock()
            .unwrap()
            .get(&identity)
            .copied()
        else {
            return Ok(None);
        };
        let directory = target.root.open_metadata(&target.relative)?;
        let opened = directory.metadata()?;
        if !opened.is_dir() || (opened.dev(), opened.ino()) != identity {
            return Ok(None);
        }
        let mode = apply::created_directory_mode(&directory, proposed | 0o700, opened.mode())?;
        Ok(Some((mode | (proposed & created & 0o2000), identity)))
    }
}

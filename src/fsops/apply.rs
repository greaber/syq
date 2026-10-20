use super::*;
use std::ffi::CStr;

pub(super) fn op_path(op: &Op) -> &[u8] {
    match op {
        Op::Mkdir { path, .. }
        | Op::Symlink { path, .. }
        | Op::Mknod { path, .. }
        | Op::Hardlink { path, .. }
        | Op::SetMeta { path, .. }
        | Op::SetFileMetaIfSame { path, .. }
        | Op::Remove { path }
        | Op::Rmdir { path }
        | Op::Unlink { path } => path,
    }
}

/// Carry out `op`. What it creates is limited as creating it limits it: by
/// its directory's default ACL, or else by the umask. A restricted
/// receiver's session never creates missing parents on the way
/// (`create_missing_parents`): each directory it creates passes its
/// authority.
/// Told the directory a new directory was made in, once a creation made
/// one (`mkdir_rooted`).
pub(super) type MadeDirectory<'a> = Option<&'a (dyn Fn(&File) + Sync)>;

pub(super) fn apply_one(
    op: &Op,
    destination_root: Option<Arc<Root>>,
    destination_prefix: Option<&[u8]>,
    create_missing_parents: bool,
    (owned, made): (Option<&owned::OwnedObjects>, MadeDirectory<'_>),
) -> Result<()> {
    let Some(root) = destination_root else {
        bail!("{UNROOTED_MUTATION}");
    };
    let path = op_path(op);
    let relative = RelativePath::new(path)?;
    let label = PathBuf::from(OsStr::from_bytes(
        &destination_prefix.map_or_else(|| path.to_vec(), |prefix| join(prefix, path)),
    ));
    hold_before_destination_mutation_for_test(&label)?;
    let target = RootedTarget {
        root,
        relative,
        label,
        create_missing_parents,
    };
    #[cfg(debug_assertions)]
    fail_apply_capacity_for_test(&target.label)?;
    #[cfg(debug_assertions)]
    if matches!(op, Op::SetMeta { .. } | Op::SetFileMetaIfSame { .. }) {
        fail_set_meta_for_test(&target.label)?;
        meet_concurrent_set_meta_for_test(&target.label)?;
    }
    if matches!(op, Op::SetFileMetaIfSame { .. }) {
        hold_before_quick_metadata_for_test()?;
    }
    apply_one_rooted(op, &target, owned, made).map_err(|error| {
        // A no-replace creation whose name something already holds made
        // nothing: its condition was not met.
        let absent = matches!(
            op,
            Op::Mkdir {
                condition: TargetCondition::Absent,
                ..
            } | Op::Symlink {
                condition: TargetCondition::Absent,
                ..
            } | Op::Mknod {
                condition: TargetCondition::Absent,
                ..
            } | Op::Hardlink {
                condition: TargetCondition::Absent,
                ..
            }
        );
        let taken = error.chain().any(|cause| {
            cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::AlreadyExists)
        });
        if absent && taken && !is_condition_not_met(&error) {
            error.context(ConditionNotMet(
                "the name was taken before a no-replace creation".into(),
            ))
        } else {
            error
        }
    })
}

/// Resolve one authorized request's root, then keep the caller's explicit
/// names. No Selected operation permits traversal or recursive discovery.
pub(super) fn selected_removals(
    ops: &[Op],
    destination_root: Option<Arc<Root>>,
    destination_prefix: Option<&[u8]>,
) -> Vec<Result<crate::deletion::Selected>> {
    let root = destination_root.context(UNROOTED_MUTATION);
    ops.iter()
        .map(|op| {
            let root = root
                .as_ref()
                .map_err(|error| anyhow::Error::new(wire_error(error)))?
                .clone();
            let path = op_path(op);
            let label = PathBuf::from(OsStr::from_bytes(
                &destination_prefix.map_or_else(|| path.to_vec(), |prefix| join(prefix, path)),
            ));
            #[cfg(debug_assertions)]
            fail_apply_capacity_for_test(&label)?;
            Ok(crate::deletion::Selected {
                root,
                path: RelativePath::new(path)?,
                label,
                directory: matches!(op, Op::Rmdir { .. }),
                size: None,
            })
        })
        .collect()
}

pub(super) fn error_is_kind(error: &anyhow::Error, kind: io::ErrorKind) -> bool {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<io::Error>())
        .is_some_and(|error| error.kind() == kind)
}

pub(super) struct RootedTarget {
    pub(super) root: Arc<Root>,
    pub(super) relative: RelativePath,
    pub(super) label: PathBuf,
    pub(super) create_missing_parents: bool,
}

// One filename-limit observation for adjacent siblings in a read-only batch
// chunk. This avoids repeating parent resolution (including missing-parent
// probes). The cache opens no descriptors and ends with the chunk. Later
// requests query again; file operations keep their own confined resolution.
#[derive(Default)]
pub(super) struct PartialNameLimits {
    pub(super) last: Option<(Arc<Root>, PathBuf, usize)>,
}

impl PartialNameLimits {
    pub(super) fn get_or_query(
        &mut self,
        root: &Arc<Root>,
        parent: &Path,
        query: impl FnOnce() -> Result<usize>,
    ) -> Result<usize> {
        if let Some((previous_root, previous_parent, limit)) = &self.last {
            if Arc::ptr_eq(previous_root, root) && previous_parent == parent {
                return Ok(*limit);
            }
        }
        self.last = None;
        let limit = query()?;
        // Keep the actual root alive: device/inode can coincide across
        // distinct mount views, and a raw pointer could otherwise be reused.
        self.last = Some((root.clone(), parent.to_path_buf(), limit));
        Ok(limit)
    }
}

impl RootedTarget {
    pub(super) fn partial_name_max(&self) -> Result<usize> {
        self.root.partial_name_max(&self.relative)
    }

    pub(super) fn location(&self) -> FileLocation {
        FileLocation::Rooted {
            root: self.root.identity(),
            relative: self.relative.clone(),
        }
    }
}

pub(super) fn rooted_partial_target(
    target: &RootedTarget,
    copy_id: &CopyId,
) -> Result<(RelativePath, PathBuf)> {
    rooted_partial_target_with_limit(target, copy_id, target.partial_name_max()?)
}

fn rooted_partial_target_with_limit(
    target: &RootedTarget,
    copy_id: &CopyId,
    component_limit: usize,
) -> Result<(RelativePath, PathBuf)> {
    let relative_path = target.relative.to_path_buf();
    // Derive the visible component from the logical command-line spelling so
    // PartialPaths and every state-machine request keep one stable sidecar
    // name, including the PATH_MAX compact form. Only the resulting component
    // is placed beneath the retained root.
    let label = partial_path_with_name_max(&target.label, copy_id, component_limit)?;
    let name = label
        .file_name()
        .context("partial path has no final component")?;
    let relative_partial = relative_path
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .join(name);
    Ok((
        RelativePath::new(relative_partial.as_os_str().as_bytes())?,
        label,
    ))
}

/// Retry only the initial access to a partial. Later writes and publication
/// must use the returned name; never replay a completed mutation or a batch.
pub(super) fn with_rooted_partial<T>(
    target: &RootedTarget,
    copy_id: &CopyId,
    mut access: impl FnMut(&RelativePath, &Path) -> Result<T>,
) -> Result<(RelativePath, PathBuf, T)> {
    let (relative, label) = rooted_partial_target(target, copy_id)?;
    match access(&relative, &label) {
        Ok(value) => Ok((relative, label, value)),
        Err(error) => {
            let too_long = error
                .downcast_ref::<io::Error>()
                .is_some_and(|error| error.raw_os_error() == Some(libc::ENAMETOOLONG));
            if !too_long {
                return Err(error);
            }
            let limit = target.root.rejected_partial_name_max(&target.relative)?;
            let (short, label) = rooted_partial_target_with_limit(target, copy_id, limit)?;
            if short == relative {
                return Err(error);
            }
            let value = access(&short, &label)?;
            Ok((short, label, value))
        }
    }
}

/// Observe the object at a destination path and hold it to the planner's
/// condition. `Absent` requires nothing there (the following `*at` creation
/// then fails atomically if something appears); the matching conditions
/// require the observed identity. `Any` accepts whatever is found.
pub(super) fn observe_rooted_condition(
    target: &RootedTarget,
    condition: TargetCondition,
) -> Result<Option<crate::rooted::RootMetadata>> {
    let observed = target.root.metadata_optional(&target.relative)?;
    let label = &target.label;
    match (condition, observed) {
        (TargetCondition::Any, observed) => Ok(observed),
        (TargetCondition::Absent, None) => Ok(None),
        (TargetCondition::Absent, Some(_)) => Err(condition_not_met(format!(
            "destination {} appeared before no-replace creation",
            label.display()
        ))),
        (TargetCondition::Matches { dev, ino }, Some(metadata))
            if metadata.dev == dev && metadata.ino == ino =>
        {
            Ok(Some(metadata))
        }
        (
            TargetCondition::MatchesFingerprint {
                dev,
                ino,
                ctime,
                ctime_nsec,
            },
            Some(metadata),
        ) if metadata.dev == dev
            && metadata.ino == ino
            && metadata.ctime == ctime
            && metadata.ctime_nsec == ctime_nsec =>
        {
            Ok(Some(metadata))
        }
        (TargetCondition::Matches { .. } | TargetCondition::MatchesFingerprint { .. }, _) => {
            Err(condition_not_met(format!(
                "destination {} changed before it could be replaced",
                label.display()
            )))
        }
    }
}

/// Carry out `op` at `target`. With `owned`, a hard link gives a new name
/// only to a file recorded there.
fn apply_one_rooted(
    op: &Op,
    target: &RootedTarget,
    owned: Option<&owned::OwnedObjects>,
    made: MadeDirectory<'_>,
) -> Result<()> {
    let root = &target.root;
    let path = &target.relative;
    match op {
        Op::Mkdir {
            mode, condition, ..
        } => mkdir_rooted(target, *mode, *condition, false, made).map(drop),
        Op::Symlink {
            target: link,
            condition,
            meta,
            flags,
            ..
        } => {
            let replacement = leaf_replacement(target, *condition, MODE_SYMLINK)?;
            let existing = existing_leaf(target, replacement, MODE_SYMLINK, meta, *flags, |_| {
                Ok(target.root.read_link(&target.relative)? == *link)
            })?;
            let Some((meta, flags)) = existing.settle(meta, *flags)? else {
                return Ok(());
            };
            root.publish_symlink(path, link, replacement, |directory, name| {
                set_new_leaf_metadata(root, directory, name, MODE_SYMLINK, &meta, flags)
            })
        }
        Op::Mknod {
            mode,
            rdev,
            condition,
            meta,
            flags,
            ..
        } => {
            let file_type = file_type_bits(*mode);
            let replacement = leaf_replacement(target, *condition, file_type)?;
            let existing =
                existing_leaf(target, replacement, file_type, meta, *flags, |current| {
                    Ok(current.rdev() == *rdev)
                })?;
            let Some((meta, flags)) = existing.settle(meta, *flags)? else {
                return Ok(());
            };
            // A node created again starts with the permissions it ends with.
            let mode = if flags & flags::MODE != 0 {
                file_type | (meta.mode & 0o7777)
            } else {
                *mode
            };
            root.publish_node(path, mode, *rdev, replacement, |directory, name| {
                set_new_leaf_metadata(root, directory, name, file_type, &meta, flags)
            })
        }
        Op::Hardlink {
            source,
            dev,
            ino,
            condition,
            ..
        } => {
            // The publication links only the file with this identity, so
            // checking the identity checks the file linked (`OwnedObjects`).
            // Where inode numbers cannot show that, a restricted receiver
            // refuses the link, and an ordinary one links as without the
            // check.
            let owned = match owned {
                Some(owned) if !owned.applies(false) => {
                    let trusted = root.link_counts_trusted_on(*dev, &root.parent_directory(path)?);
                    trusted.then_some(owned)
                }
                owned => owned,
            };
            if let Some(owned) = owned {
                owned.require_link((*dev, *ino), &target.label)?;
            }
            root.publish_hardlink_to(
                &RelativePath::new(source)?,
                path,
                (*dev, *ino),
                *condition,
                owned.is_some(),
            )
        }
        Op::SetMeta {
            meta,
            flags,
            condition,
            directory,
            ..
        } => set_meta_rooted(target, meta, *flags, *condition, *directory),
        Op::SetFileMetaIfSame {
            condition,
            meta,
            flags,
            ..
        } => {
            let file = root.open_metadata(path)?;
            let opened = file.metadata()?;
            if !opened.file_type().is_file() {
                bail!(
                    "destination {} changed before metadata repair",
                    target.label.display()
                );
            }
            require_open_target_known(&opened, &target.label, *condition)?;
            // Only a file the receiver can vouch for is changed in place;
            // the copy replaces any other (`vouch`).
            vouch::require(target, &file, &opened, meta, *flags)?;
            set_meta_handle_known_portable(&file, meta, *flags, &opened)?;
            require_rooted_named_identity_known(
                &target.root,
                &target.relative,
                &target.label,
                &opened,
                *condition,
            )
        }
        Op::Rmdir { .. } | Op::Unlink { .. } => crate::deletion::DirectoryBatch::default().remove(
            root,
            path,
            &target.label,
            matches!(op, Op::Rmdir { .. }),
            None,
        ),
        Op::Remove { .. } => bail!("recursive remove cannot use a confined destination root"),
    }
}

/// The type bits of a symlink.
#[allow(clippy::unnecessary_cast)] // `mode_t` is narrower on macOS.
const MODE_SYMLINK: u32 = libc::S_IFLNK as u32;

/// What a new symlink or node of type `file_type` at `target` may replace
/// under `condition`.
fn leaf_replacement(
    target: &RootedTarget,
    condition: TargetCondition,
    file_type: u32,
) -> Result<crate::rooted::LeafReplacement> {
    use crate::rooted::LeafReplacement;
    Ok(match condition {
        TargetCondition::Absent => LeafReplacement::Nothing,
        TargetCondition::Any => LeafReplacement::Any,
        TargetCondition::Matches { .. } | TargetCondition::MatchesFingerprint { .. } => {
            let Some(metadata) = observe_rooted_condition(target, condition)? else {
                return Err(condition_not_met(format!(
                    "destination {} changed before it could be replaced",
                    target.label.display()
                )));
            };
            if file_type_bits(metadata.mode) != file_type {
                return Err(condition_not_met(format!(
                    "destination {} cannot change type under a matched condition",
                    target.label.display()
                )));
            }
            LeafReplacement::Same {
                dev: metadata.dev,
                ino: metadata.ino,
            }
        }
    })
}

/// Whether the symlink a matched replacement would replace already holds
/// everything the new one would: its target and the metadata `flags`
/// selects, as when only its access time was to be restored and it had
/// not changed. It is then left as it is. ACLs, extended attributes and
/// birth times are not compared here.
/// What the existing symlink or node of type `file_type` that `replacement`
/// names needs to hold `meta` under `flags` (`existing_leaf`).
enum ExistingLeaf {
    /// Nothing: it already holds them.
    Holds,
    /// Only its access time, restored in place through this handle of it,
    /// as on any file (`fsops::vouch`).
    AccessTime(File, crate::inode_metadata::Timestamp),
    /// To be created again, keeping the permissions, owner and group the
    /// copy does not select: these.
    Recreate { mode: u32, uid: u32, gid: u32 },
    /// Created with what the request gives: there is no existing entry to
    /// keep anything of.
    New,
}

impl ExistingLeaf {
    /// Restore an access time in place, and return the metadata and flags
    /// to create the entry with, if it is to be created.
    fn settle(self, meta: &Meta, flags: u8) -> Result<Option<(Meta, u8)>> {
        match self {
            Self::Holds => Ok(None),
            Self::AccessTime(handle, atime) => {
                let metadata = crate::inode_metadata::InodeMetadata {
                    atime: Some(atime),
                    ..Default::default()
                };
                crate::inode_metadata::apply_after_acls(&handle, Some(&metadata), meta.mode)?;
                Ok(None)
            }
            Self::New => Ok(Some((meta.clone(), flags))),
            Self::Recreate { mode, uid, gid } => {
                let mut meta = meta.clone();
                let mut flags = flags;
                if flags & flags::MODE == 0 {
                    meta.mode = (meta.mode & !0o7777) | mode;
                    flags = (flags & !flags::RECEIVER_MODE) | flags::MODE;
                }
                // Only root can keep another account's owner; a group is kept
                // where the receiving account may give it.
                if flags & flags::OWNER == 0 && is_superuser() {
                    meta.uid = uid;
                    flags |= flags::OWNER;
                }
                if flags & flags::GROUP == 0 {
                    meta.gid = gid;
                    flags |= flags::GROUP;
                }
                Ok(Some((meta, flags)))
            }
        }
    }
}

/// What the existing entry `replacement` names, a symlink or node of type
/// `file_type` whose contents `same_contents` compares (its target, or its
/// device number), needs to hold `meta` under `flags`. Every value is read
/// through a handle of the entry, after its identity is checked.
fn existing_leaf(
    target: &RootedTarget,
    replacement: crate::rooted::LeafReplacement,
    file_type: u32,
    meta: &Meta,
    flags: u8,
    same_contents: impl FnOnce(&fs::Metadata) -> Result<bool>,
) -> Result<ExistingLeaf> {
    let crate::rooted::LeafReplacement::Same { dev, ino } = replacement else {
        return Ok(ExistingLeaf::New);
    };
    let Ok(handle) = target.root.open_metadata(&target.relative) else {
        return Ok(ExistingLeaf::New);
    };
    let current = handle.metadata()?;
    if file_type_bits(current.mode()) != file_type || (current.dev(), current.ino()) != (dev, ino) {
        // Publication refuses to replace it (`LeafReplacement::Same`).
        return Ok(ExistingLeaf::New);
    }
    let kept = ExistingLeaf::Recreate {
        mode: current.mode() & 0o7777,
        uid: current.uid(),
        gid: current.gid(),
    };
    if !same_contents(&current)? {
        return Ok(kept);
    }
    let symlink = file_type == MODE_SYMLINK;
    // A symlink's times are not set where the filesystem would set its
    // target's instead (`Profile::symlink_times`).
    let link_times = !symlink
        || target
            .root
            .known_profile(current.dev())
            .is_none_or(|profile| profile.symlink_times);
    let owner = flags & flags::OWNER != 0
        && (is_superuser() || flags & flags::REQUIRE_OWNER != 0)
        && current.uid() != meta.uid;
    let group = flags & flags::GROUP != 0 && current.gid() != meta.gid;
    let mode = flags & flags::MODE != 0
        && !(symlink && cfg!(target_os = "linux"))
        && current.mode() & 0o7777 != meta.mode & 0o7777;
    let times = flags & flags::TIMES != 0
        && link_times
        && (current.mtime(), current.mtime_nsec() as u32) != (meta.mtime, meta.mtime_nsec);
    if owner
        || group
        || mode
        || times
        || crate::inode_metadata::would_change_besides_atime(
            &handle,
            meta.inode_metadata.as_deref(),
            meta.mode,
        )?
    {
        return Ok(kept);
    }
    match meta
        .inode_metadata
        .as_deref()
        .and_then(|inode| inode.atime)
        .filter(|_| link_times)
    {
        Some(atime)
            if (current.atime(), current.atime_nsec() as u32)
                != (atime.seconds, atime.nanoseconds) =>
        {
            Ok(ExistingLeaf::AccessTime(handle, atime))
        }
        _ => Ok(ExistingLeaf::Holds),
    }
}

/// The step that gives a new symlink, before `Root::publish_symlink`
/// publishes it, `meta` under `flags` (`set_new_leaf_metadata`).
pub(crate) fn new_symlink_metadata<'a>(
    root: &'a Root,
    meta: &'a Meta,
    flags: u8,
) -> impl FnOnce(&File, &CStr) -> Result<()> + 'a {
    move |directory, name| set_new_leaf_metadata(root, directory, name, MODE_SYMLINK, meta, flags)
}

/// Give a new symlink or node of type `file_type`, just created at `name`
/// in `directory` and not yet published, `meta` under `flags`, through a
/// descriptor of it: the entry is what this receiver created, and nothing
/// is applied by its final name. A symlink's times are set only where the
/// filesystem sets the link's own (`Profile::symlink_times`), and on macOS
/// a device node, which may not be opened without opening the device, is
/// changed by its temporary name, checked first.
fn set_new_leaf_metadata(
    root: &Root,
    directory: &File,
    name: &CStr,
    file_type: u32,
    meta: &Meta,
    flags: u8,
) -> Result<()> {
    let flags = flags & !flags::RECEIVER_MODE;
    if flags & (flags::MODE | flags::OWNER | flags::GROUP | flags::TIMES) == 0
        && meta.inode_metadata.is_none()
    {
        return Ok(());
    }
    let symlink = file_type == MODE_SYMLINK;
    #[cfg(target_os = "linux")]
    let open = libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    // A device node is opened for events only, without its terminal
    // becoming the controlling one, as for any entry's metadata.
    #[cfg(target_os = "macos")]
    let open = libc::O_EVTONLY
        | libc::O_NONBLOCK
        | libc::O_NOCTTY
        | libc::O_CLOEXEC
        | if symlink {
            libc::O_SYMLINK
        } else {
            libc::O_NOFOLLOW
        };
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let open = libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let handle = crate::sys::open_at(directory.as_raw_fd(), name, open, 0)
        .context("open a new entry to set its metadata")?;
    let current = handle.metadata()?;
    // Owned as the files this process creates there show, which is not
    // the receiving account on every filesystem (`rooted::created_owner`).
    anyhow::ensure!(
        file_type_bits(current.mode()) == file_type
            && current.nlink() == 1
            && Some(current.uid()) == crate::rooted::created_owner(directory, current.dev()),
        "the new entry changed before its metadata was set"
    );
    let flags = if symlink && !root.sets_symlink_times(directory, current.dev()) {
        flags & !flags::TIMES
    } else {
        flags
    };
    // A symlink has no mode of its own to set on Linux.
    let flags = if symlink && cfg!(target_os = "linux") {
        flags & !flags::MODE
    } else {
        flags
    };
    set_handle_metadata(&handle, meta, flags, &current, Some((directory, name)))
}

/// Apply `meta` under `flags` to the object `handle` refers to, whose
/// metadata `current` was read through it, never by a name. The times go
/// first: macOS may lower a birth time when an older modification time is
/// set, and the birth time follows. `created` is the temporary name of an
/// entry this receiver just created there, for a symlink's times where the
/// kernel cannot set them through its handle (`set_handle_times`).
fn set_handle_metadata(
    handle: &File,
    meta: &Meta,
    flags: u8,
    current: &fs::Metadata,
    created: Option<(&File, &CStr)>,
) -> Result<()> {
    if flags & flags::TIMES != 0
        && (current.mtime(), current.mtime_nsec() as u32) != (meta.mtime, meta.mtime_nsec)
    {
        let times = [
            timespec(0, libc::UTIME_OMIT as u32),
            timespec(meta.mtime, meta.mtime_nsec),
        ];
        match (set_handle_times(handle, &times), created) {
            (Ok(()), _) => {}
            (Err(error), Some((directory, name))) if error.kind() == io::ErrorKind::Unsupported => {
                set_created_symlink_times(directory, name, current, &times)?
            }
            (Err(error), _) => return Err(error.into()),
        }
    }
    set_meta_handle_known_portable(handle, meta, flags & !flags::TIMES, current)
}

/// Set the times of the symlink `current` describes, which this receiver
/// just created at `name` in `directory`, by that name and without
/// following it, once the name shows itself to lead to it still.
fn set_created_symlink_times(
    directory: &File,
    name: &CStr,
    current: &fs::Metadata,
    times: &[libc::timespec; 2],
) -> Result<()> {
    let named = crate::rooted::metadata_at(directory.as_raw_fd(), name)?;
    anyhow::ensure!(
        (named.dev, named.ino) == (current.dev(), current.ino()) && named.is_symlink(),
        "the new entry changed before its metadata was set"
    );
    crate::sys::retry_zero(|| unsafe {
        libc::utimensat(
            directory.as_raw_fd(),
            name.as_ptr(),
            times.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    })?;
    Ok(())
}

/// Set the times of the object `handle` refers to, which may be a symlink
/// or a directory, through `handle`. Linux before 5.8 cannot set times
/// through a handle with an empty path: then anything but a symlink is
/// reached through the handle's `/proc/self/fd` link, which leads to the
/// object itself and to no name, and a symlink, whose link would lead on to
/// its target, is refused as `Unsupported` for the caller to set by a name
/// it has checked (`set_created_symlink_times`).
pub(crate) fn set_handle_times(handle: &File, times: &[libc::timespec; 2]) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        #[cfg(debug_assertions)]
        let refused = std::env::var_os("SYQ_TEST_REFUSE_EMPTY_PATH_TIMES").is_some();
        #[cfg(not(debug_assertions))]
        let refused = false;
        let result = if refused {
            Err(io::Error::from_raw_os_error(libc::EINVAL))
        } else {
            crate::sys::retry_zero(|| unsafe {
                libc::utimensat(
                    handle.as_raw_fd(),
                    c"".as_ptr(),
                    times.as_ptr(),
                    libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
                )
            })
        };
        match result {
            Err(error) if error.raw_os_error() == Some(libc::EINVAL) => {
                if handle.metadata()?.file_type().is_symlink() {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "this kernel cannot set a symlink's times through a handle",
                    ));
                }
                let path = std::ffi::CString::new(crate::sys::proc_fd_path(handle))?;
                crate::sys::retry_zero(|| unsafe {
                    libc::utimensat(libc::AT_FDCWD, path.as_ptr(), times.as_ptr(), 0)
                })
            }
            result => result,
        }
    }
    #[cfg(not(target_os = "linux"))]
    crate::sys::retry_zero(|| unsafe { libc::futimens(handle.as_raw_fd(), times.as_ptr()) })
}

/// Apply `meta` to the directory at `target`. It goes only to a directory:
/// anything else found at its name, such as a file someone put there in its
/// place, is refused before any change, so that it never takes the
/// directory's owner, group or mode. Every change, times included, goes
/// through a handle of the directory, never its name. Its identity is
/// checked only where its own filesystem keeps inode numbers
/// (`Profile::link_counts_trusted`): elsewhere a directory's number can
/// change while it stays, and the type check stands alone. Any other
/// entry's metadata changes by creating it again (`Op::Symlink`,
/// `Op::Mknod`) or, for a file, as the copy finishes it.
pub(super) fn set_meta_rooted(
    target: &RootedTarget,
    meta: &Meta,
    flags: u8,
    condition: TargetCondition,
    directory: bool,
) -> Result<()> {
    let require_directory = |is_dir: bool| {
        if !is_dir {
            if directory {
                bail!(
                    "destination {} is no longer a directory",
                    target.label.display()
                );
            }
            bail!(
                "{} is not changed in place: only a directory's metadata is",
                target.label.display()
            );
        }
        Ok(())
    };
    let metadata = target.root.metadata(&target.relative)?;
    require_directory(metadata.is_dir())?;
    let handle = target
        .root
        .open_metadata(&target.relative)
        .with_context(|| format!("open confined metadata handle {}", target.label.display()))?;
    require_rooted_metadata(&handle, metadata, &target.label)?;
    let opened = handle.metadata()?;
    require_directory(opened.is_dir())?;
    let condition = match condition {
        TargetCondition::Matches { .. } | TargetCondition::MatchesFingerprint { .. }
            if !target.root.link_counts_trusted_on(opened.dev(), &handle) =>
        {
            TargetCondition::Any
        }
        condition => condition,
    };
    require_rooted_condition(metadata, condition, &target.label)?;
    require_open_target_known(&opened, &target.label, condition)?;
    let owner_differs = (flags & flags::OWNER != 0
        && (is_superuser() || flags & flags::REQUIRE_OWNER != 0)
        && opened.uid() != meta.uid)
        || (flags & flags::GROUP != 0 && opened.gid() != meta.gid);
    let mode_differs = flags & flags::MODE != 0 && opened.mode() & 0o7777 != meta.mode & 0o7777;
    let time_differs = flags & flags::TIMES != 0
        && (opened.mtime(), opened.mtime_nsec() as u32) != (meta.mtime, meta.mtime_nsec);
    if !owner_differs && !mode_differs && !time_differs && meta.inode_metadata.is_none() {
        return Ok(());
    }
    set_handle_metadata(&handle, meta, flags, &opened, None)?;
    // The final lookup resolves from Root again.
    require_rooted_named_identity_known(
        &target.root,
        &target.relative,
        &target.label,
        &opened,
        condition,
    )
}

/// The target an operation on `path` resolves to, as `apply_one` resolves it.
pub(super) fn operation_target(
    path: &[u8],
    destination_root: Option<Arc<Root>>,
    destination_prefix: Option<&[u8]>,
    create_missing_parents: bool,
) -> Result<RootedTarget> {
    let Some(root) = destination_root else {
        bail!("{UNROOTED_MUTATION}");
    };
    Ok(RootedTarget {
        root,
        relative: RelativePath::new(path)?,
        label: PathBuf::from(OsStr::from_bytes(
            &destination_prefix.map_or_else(|| path.to_vec(), |prefix| join(prefix, path)),
        )),
        create_missing_parents,
    })
}

/// The group and mode of the directories new ones are created in, observed
/// once per request.
pub(super) type CreationParents = std::sync::Mutex<HashMap<Vec<u8>, Option<(u32, u32)>>>;

/// Whether a directory created at `path` might start with a group other
/// than `group`. On Linux it takes its parent's group when the parent is
/// setgid, and otherwise this process's group, or its parent's group on a
/// filesystem mounted with BSD group semantics. Elsewhere it always takes
/// its parent's group. When unsure, the answer is yes.
pub(super) fn starting_group_may_differ(
    path: &[u8],
    group: u32,
    parents: &CreationParents,
    destination_root: Option<Arc<Root>>,
    destination_prefix: Option<&[u8]>,
) -> bool {
    let parent_path = path[..path.iter().rposition(|byte| *byte == b'/').unwrap_or(0)].to_vec();
    let cached = parents.lock().unwrap().get(&parent_path).copied();
    let parent = cached.unwrap_or_else(|| {
        let observed = (|| -> Result<(u32, u32)> {
            let target = operation_target(path, destination_root, destination_prefix, false)?;
            let (parents, _) = target.relative.leaf()?;
            let parent = target
                .root
                .metadata(&RelativePath::new(&parents.join(&b'/'))?)?;
            Ok((parent.gid, parent.mode))
        })()
        .ok();
        parents.lock().unwrap().insert(parent_path, observed);
        observed
    });
    group_may_differ(parent, group)
}

/// The group and mode of the directories in-place files are created in,
/// by root identity and path, observed once per small-file batch.
pub(super) type InplaceParents = HashMap<(u64, u64, Vec<u8>), Option<(u32, u32)>>;

/// Whether a file created at `target` might start with a group other than
/// `group`, decided as for a directory (`starting_group_may_differ`) from
/// its parent, which this looks up unless `parents` already holds it.
pub(super) fn new_file_group_may_differ(
    target: &RootedTarget,
    group: u32,
    parents: Option<&mut InplaceParents>,
) -> bool {
    let Ok((directories, _)) = target.relative.leaf() else {
        return true;
    };
    let directory = directories.join(&b'/');
    let observe = || -> Option<(u32, u32)> {
        let parent = target
            .root
            .metadata(&RelativePath::new(&directory).ok()?)
            .ok()?;
        Some((parent.gid, parent.mode))
    };
    let parent = match parents {
        Some(parents) => {
            let identity = target.root.identity();
            let key = (identity.dev, identity.ino, directory.clone());
            *parents.entry(key).or_insert_with(observe)
        }
        None => observe(),
    };
    group_may_differ(parent, group)
}

/// Whether an object created in a directory with `parent`'s group and mode
/// might start with a group other than `group`.
pub(super) fn group_may_differ(parent: Option<(u32, u32)>, group: u32) -> bool {
    let Some((parent_group, parent_mode)) = parent else {
        return true;
    };
    if cfg!(target_os = "linux") && parent_mode & 0o2000 == 0 {
        parent_group != group || unsafe { libc::getegid() } != group
    } else {
        parent_group != group
    }
}

/// The identity and mode of a directory a call created.
pub(super) type CreatedDirectory = (u64, u64, u32);

/// Run a Mkdir as `apply_one` runs it, with mode 0700 when `private`, and
/// return the identity and mode of the directory if this call created it
/// rather than finding one already there.
pub(super) fn create_identified_directory(
    op: &Op,
    destination_root: Option<Arc<Root>>,
    destination_prefix: Option<&[u8]>,
    create_missing_parents: bool,
    private: bool,
    made: MadeDirectory<'_>,
) -> Result<Option<CreatedDirectory>> {
    let Op::Mkdir {
        path,
        mode,
        condition,
    } = op
    else {
        bail!("identified creation requires a Mkdir");
    };
    let target = operation_target(
        path,
        destination_root,
        destination_prefix,
        create_missing_parents,
    )?;
    hold_before_destination_mutation_for_test(&target.label)?;
    #[cfg(debug_assertions)]
    fail_apply_capacity_for_test(&target.label)?;
    let mode = if private { 0o700 } else { *mode };
    mkdir_rooted(&target, mode, *condition, true, made)
}

/// Give a directory this receiver created private, once it has taken its
/// group, the mode its creation with `proposed` would have given it. Like
/// such a creation followed by that group change, it keeps a setgid bit
/// only if the change left it in place. Only the directory with the
/// `created` identity is changed: another one now at its name is left as
/// it is, even though the group change already reached it.
pub(super) fn open_created_directory(
    path: &[u8],
    proposed: u32,
    created: (u64, u64),
    destination_root: Option<Arc<Root>>,
    destination_prefix: Option<&[u8]>,
) -> Result<()> {
    let target = operation_target(path, destination_root, destination_prefix, false)?;
    let directory = target.root.open_metadata(&target.relative)?;
    let current = directory.metadata()?;
    if (current.dev(), current.ino()) != created || !current.is_dir() {
        return Ok(());
    }
    set_mode_handle(
        &directory,
        created_directory_mode(&directory, (proposed & 0o7777) | 0o700, current.mode())?,
    )
}

/// The mode creating `directory` with `proposed` would have given it, for a
/// directory created private instead: permission bits limited by the default
/// ACL it inherited, or else by the umask, and the setgid bit of `current`,
/// which it inherited from its parent. Creation never sets other bits.
pub(crate) fn created_directory_mode(directory: &File, proposed: u32, current: u32) -> Result<u32> {
    Ok(crate::inode_metadata::creation_mode(directory, proposed)? | (current & 0o2000))
}

/// Create the directory `target` names, or accept an existing one as the
/// condition allows, without changing an existing directory. With `identify`,
/// return the identity of a directory this call created; `None` means it
/// found one already there. `made` is told the directory a directory this
/// call created is in.
fn mkdir_rooted(
    target: &RootedTarget,
    mode: u32,
    condition: TargetCondition,
    identify: bool,
    made: MadeDirectory<'_>,
) -> Result<Option<CreatedDirectory>> {
    let root = &target.root;
    let path = &target.relative;
    if path.is_empty() {
        if condition == TargetCondition::Absent {
            bail!("destination root {} already exists", target.label.display());
        }
        let metadata = root.metadata(path)?;
        require_rooted_condition(metadata, condition, &target.label)?;
        return Ok(None);
    }
    let parent = if target.create_missing_parents {
        root.resolve_parent_creating(path, 0o777)?
    } else {
        root.resolve_parent(path)?
    };
    if matches!(condition, TargetCondition::Any | TargetCondition::Absent) {
        match parent
            .create_directory((mode & 0o7777) | 0o700)
            .with_context(|| format!("create confined directory {}", target.label.display()))
        {
            Ok(()) => {
                if let Some(made) = made {
                    made(parent.directory());
                }
                let created = identify
                    .then(|| {
                        parent
                            .metadata()
                            .map(|metadata| (metadata.dev, metadata.ino, metadata.mode))
                    })
                    .transpose()?;
                hold_after_directory_creation_for_test(&target.label)?;
                return Ok(created);
            }
            Err(error) if error_is_kind(&error, io::ErrorKind::AlreadyExists) => {
                if condition == TargetCondition::Absent {
                    // Something holds the name: nothing was created.
                    return Err(condition_not_met(format!(
                        "destination {} appeared before no-replace creation",
                        target.label.display()
                    )));
                }
            }
            Err(error) => return Err(error),
        }
    }
    drop(parent);
    match observe_rooted_condition(target, condition)? {
        Some(metadata) if metadata.is_dir() => Ok(None),
        Some(_) => bail!(
            "cannot replace non-directory {} with a directory",
            target.label.display()
        ),
        None => create_rooted_directory_or_existing(target, mode, identify),
    }
}

/// `TargetCondition::Any` mkdir operations can race each other because apply
/// batches are parallel and deeper paths create implicit parents. Accept the
/// winner only when the conflicting name is a real directory beneath the
/// retained root; a symlink or any other type remains an error.
pub(super) fn create_rooted_directory_or_existing(
    target: &RootedTarget,
    mode: u32,
    identify: bool,
) -> Result<Option<CreatedDirectory>> {
    match target
        .root
        .create_directory(&target.relative, (mode & 0o7777) | 0o700)
    {
        Ok(()) => {
            let created = identify
                .then(|| {
                    target
                        .root
                        .metadata(&target.relative)
                        .map(|metadata| (metadata.dev, metadata.ino, metadata.mode))
                })
                .transpose()?;
            hold_after_directory_creation_for_test(&target.label)?;
            Ok(created)
        }
        Err(error)
            if error.chain().any(|cause| {
                cause
                    .downcast_ref::<io::Error>()
                    .is_some_and(|error| error.kind() == io::ErrorKind::AlreadyExists)
            }) =>
        {
            let metadata = target.root.metadata(&target.relative)?;
            if !metadata.is_dir() {
                return Err(error);
            }
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

/// The marker of a destination that did not meet an operation's
/// condition, found before anything was changed
/// (`WireError::condition_not_met`).
#[derive(Debug)]
pub(crate) struct ConditionNotMet(pub(crate) String);

impl std::fmt::Display for ConditionNotMet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConditionNotMet {}

/// The error for a destination that does not meet an operation's
/// condition, found before anything was changed. The copy's existing-file
/// policy may keep it: under `--if-exists=keep` and `--only-existing` such
/// a file is skipped, not failed.
pub(crate) fn condition_not_met(message: String) -> anyhow::Error {
    anyhow::Error::new(ConditionNotMet(message))
}

/// `condition_not_met`, keeping the operating system's error that showed
/// it, so its kind still reaches the copy's results.
pub(crate) fn condition_not_met_by(error: std::io::Error, message: String) -> anyhow::Error {
    anyhow::Error::new(error).context(ConditionNotMet(message))
}

/// Whether `error` says the destination did not meet the operation's
/// condition and nothing was changed (`condition_not_met`), here or at the
/// receiver.
pub(crate) fn is_condition_not_met(error: &anyhow::Error) -> bool {
    // A context layer downcasts through the error itself, not its chain.
    error.downcast_ref::<ConditionNotMet>().is_some()
        || error.chain().any(|cause| cause.is::<ConditionNotMet>())
        || crate::conn::wire_error_of(error).is_some_and(is_condition_not_met_wire)
}

/// The same for an error the receiver sent.
pub(crate) fn is_condition_not_met_wire(error: &WireError) -> bool {
    error.condition_not_met
}

/// The marker of an operation that changed nothing: found impossible
/// before it started (`WireError::unchanged`).
#[derive(Debug)]
pub(crate) struct Unchanged(pub(crate) String);

impl std::fmt::Display for Unchanged {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Unchanged {}

/// The error for an operation found impossible before it changed anything.
pub(crate) fn unchanged(message: String) -> anyhow::Error {
    anyhow::Error::new(Unchanged(message))
}

/// Whether `error` says nothing was changed: an unmet condition
/// (`condition_not_met`) or another reason found before starting
/// (`unchanged`), here or at the receiver.
pub(crate) fn is_unchanged(error: &anyhow::Error) -> bool {
    is_condition_not_met(error)
        || error.downcast_ref::<Unchanged>().is_some()
        || error.chain().any(|cause| cause.is::<Unchanged>())
        || crate::conn::wire_error_of(error).is_some_and(is_unchanged_wire)
}

/// The same for an error the receiver sent.
pub(crate) fn is_unchanged_wire(error: &WireError) -> bool {
    error.unchanged || error.condition_not_met
}

impl FsOps {
    /// On a filesystem whose inode numbers cannot show which file a name
    /// leads to (`Profile::link_counts_trusted`), a condition that names
    /// the object the copy found (`TargetCondition::Matches`,
    /// `InPlaceUpdate::only`) is held to whatever is at the name now: the
    /// receiver checks only that something is there, which is all it can
    /// check. The destination root's filesystem decides; one mounted below
    /// it is judged as the root's.
    pub(super) fn existence_only_where_numbers_mislead(&self, request: &mut Request) {
        let Some(root) = &self.destination_root else {
            return;
        };
        if root.link_counts_trusted() {
            return;
        }
        let now = |path: &[u8]| {
            RelativePath::new(path)
                .ok()
                .and_then(|relative| root.metadata_optional(&relative).ok().flatten())
        };
        let observe = |path: &[u8], condition: &mut TargetCondition| {
            if let TargetCondition::Matches { .. } = condition {
                if let Some(now) = now(path) {
                    *condition = TargetCondition::Matches {
                        dev: now.dev,
                        ino: now.ino,
                    };
                }
            }
        };
        let observe_update =
            |path: &[u8], update: &mut Option<Box<crate::proto::InPlaceUpdate>>| {
                if let Some(update) = update {
                    if update.only.is_some() {
                        if let Some(now) = now(path) {
                            update.only = Some((now.dev, now.ino));
                        }
                    }
                }
            };
        match request {
            Request::Finalize {
                path, condition, ..
            }
            | Request::HashAndHold {
                path, condition, ..
            }
            | Request::FinishBasis {
                path, condition, ..
            } => observe(path, condition),
            // A put renames over whatever its name holds
            // (`publish_partial_rooted`): its condition is not looked at.
            Request::PatchSmallBatch(patches) => {
                for patch in patches {
                    observe(&patch.path, &mut patch.condition);
                }
            }
            Request::PatchBegin { patch, .. } => observe(&patch.path, &mut patch.condition),
            Request::HashExistingBatch { files, .. } => {
                for file in files {
                    observe(&file.path, &mut file.condition);
                }
            }
            Request::Apply { ops } => {
                for op in ops {
                    match op {
                        Op::Mkdir {
                            path, condition, ..
                        }
                        | Op::Symlink {
                            path, condition, ..
                        }
                        | Op::Mknod {
                            path, condition, ..
                        }
                        | Op::Hardlink {
                            path, condition, ..
                        }
                        | Op::SetMeta {
                            path, condition, ..
                        }
                        | Op::SetFileMetaIfSame {
                            path, condition, ..
                        } => observe(path, condition),
                        Op::Remove { .. } | Op::Rmdir { .. } | Op::Unlink { .. } => {}
                    }
                }
            }
            Request::Prepare { path, update, .. } => observe_update(path, update),
            Request::CopyLocal { dst, update, .. } => observe_update(dst, update),
            _ => {}
        }
    }
}

pub(super) fn require_rooted_condition(
    metadata: RootMetadata,
    condition: TargetCondition,
    label: &Path,
) -> Result<()> {
    match condition {
        TargetCondition::Any => Ok(()),
        TargetCondition::Absent => Err(condition_not_met(format!(
            "destination {} appeared before metadata update",
            label.display()
        ))),
        TargetCondition::Matches { dev, ino } if (metadata.dev, metadata.ino) == (dev, ino) => {
            Ok(())
        }
        TargetCondition::MatchesFingerprint {
            dev,
            ino,
            ctime,
            ctime_nsec,
        } if (
            metadata.dev,
            metadata.ino,
            metadata.ctime,
            metadata.ctime_nsec,
        ) == (dev, ino, ctime, ctime_nsec) =>
        {
            Ok(())
        }
        TargetCondition::Matches { .. } | TargetCondition::MatchesFingerprint { .. } => {
            Err(condition_not_met(format!(
                "destination {} changed before metadata update",
                label.display()
            )))
        }
    }
}

pub(super) fn require_rooted_metadata(
    file: &File,
    expected: RootMetadata,
    label: &Path,
) -> Result<()> {
    let opened = file.metadata()?;
    if opened.dev() != expected.dev || opened.ino() != expected.ino {
        bail!(
            "confined destination {} changed while opening it",
            label.display()
        );
    }
    Ok(())
}

pub(super) fn require_rooted_named_identity(
    root: &Root,
    relative: &RelativePath,
    label: &Path,
    file: &File,
    condition: TargetCondition,
) -> Result<()> {
    let opened = file.metadata()?;
    require_rooted_named_identity_known(root, relative, label, &opened, condition)
}

pub(super) fn require_rooted_named_identity_known(
    root: &Root,
    relative: &RelativePath,
    label: &Path,
    opened: &fs::Metadata,
    condition: TargetCondition,
) -> Result<()> {
    let (dev, ino) = match condition {
        TargetCondition::Any => (opened.dev(), opened.ino()),
        TargetCondition::Absent => bail!("new destination unexpectedly received metadata repair"),
        TargetCondition::Matches { dev, ino }
        | TargetCondition::MatchesFingerprint { dev, ino, .. } => (dev, ino),
    };
    let named = root.metadata(relative)?;
    if opened.dev() != dev || opened.ino() != ino || named.dev != dev || named.ino != ino {
        bail!("destination {} changed during update", label.display());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn file_type_bits(mode: u32) -> u32 {
    mode & libc::S_IFMT
}

#[cfg(not(target_os = "linux"))]
pub(super) fn file_type_bits(mode: u32) -> u32 {
    mode & libc::S_IFMT as u32
}

/// Pause before an Apply operation on a destination path ending with
/// `SYQ_TEST_DESTINATION_MUTATION_SUFFIX` resolves it beneath the root.
#[cfg(any(test, debug_assertions))]
pub(super) fn hold_before_destination_mutation_for_test(label: &Path) -> Result<()> {
    let Some(suffix) = std::env::var_os("SYQ_TEST_DESTINATION_MUTATION_SUFFIX") else {
        return Ok(());
    };
    if !label.as_os_str().as_bytes().ends_with(suffix.as_bytes()) {
        return Ok(());
    }
    test_race_barrier(
        "SYQ_TEST_DESTINATION_MUTATION_READY_FILE",
        "SYQ_TEST_DESTINATION_MUTATION_CONTINUE_FILE",
        "destination-mutation-ready",
    )
}

#[cfg(not(any(test, debug_assertions)))]
pub(super) fn hold_before_destination_mutation_for_test(_label: &Path) -> Result<()> {
    Ok(())
}

/// Pause right after creating a directory whose path ends with
/// `SYQ_TEST_CREATED_DIRECTORY_SUFFIX`, before anything is created inside it.
#[cfg(debug_assertions)]
pub(super) fn hold_after_directory_creation_for_test(path: &Path) -> Result<()> {
    let Some(suffix) = std::env::var_os("SYQ_TEST_CREATED_DIRECTORY_SUFFIX") else {
        return Ok(());
    };
    if !path.as_os_str().as_bytes().ends_with(suffix.as_bytes()) {
        return Ok(());
    }
    test_race_barrier(
        "SYQ_TEST_CREATED_DIRECTORY_READY_FILE",
        "SYQ_TEST_CREATED_DIRECTORY_CONTINUE_FILE",
        "directory created",
    )
}

#[cfg(not(debug_assertions))]
pub(super) fn hold_after_directory_creation_for_test(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(debug_assertions)]
pub(super) fn hold_before_quick_metadata_for_test() -> Result<()> {
    test_race_barrier(
        "SYQ_TEST_QUICK_META_READY_FILE",
        "SYQ_TEST_QUICK_META_CONTINUE_FILE",
        "quick metadata repair",
    )
}

#[cfg(not(debug_assertions))]
pub(super) fn hold_before_quick_metadata_for_test() -> Result<()> {
    Ok(())
}

pub(super) fn require_open_target(
    file: &File,
    path: &Path,
    condition: TargetCondition,
) -> Result<()> {
    match condition {
        TargetCondition::Any => Ok(()),
        TargetCondition::Absent => Err(condition_not_met(format!(
            "destination {} appeared after the new-path precondition was checked",
            path.display()
        ))),
        TargetCondition::Matches { .. } | TargetCondition::MatchesFingerprint { .. } => {
            require_open_target_known(&file.metadata()?, path, condition)
        }
    }
}

pub(super) fn require_open_target_known(
    metadata: &fs::Metadata,
    path: &Path,
    condition: TargetCondition,
) -> Result<()> {
    match condition {
        TargetCondition::Any => Ok(()),
        TargetCondition::Absent => Err(condition_not_met(format!(
            "destination {} appeared after the new-path precondition was checked",
            path.display()
        ))),
        TargetCondition::Matches { dev, ino } => {
            if metadata.dev() != dev || metadata.ino() != ino {
                return Err(condition_not_met(format!(
                    "destination {} changed after the existing-path precondition was checked",
                    path.display()
                )));
            }
            Ok(())
        }
        TargetCondition::MatchesFingerprint {
            dev,
            ino,
            ctime,
            ctime_nsec,
        } => {
            if metadata.dev() != dev
                || metadata.ino() != ino
                || metadata.ctime() != ctime
                || metadata.ctime_nsec() as u32 != ctime_nsec
            {
                return Err(condition_not_met(format!(
                    "destination {} changed after the existing-path precondition was checked",
                    path.display()
                )));
            }
            Ok(())
        }
    }
}

#[cfg(target_os = "linux")]
pub(super) fn set_meta_handle_known(
    file: &File,
    meta: &Meta,
    flags: u8,
    current: &fs::Metadata,
) -> Result<()> {
    let fd = file.as_raw_fd();
    let empty = c"";
    // Owner first: chown clears setuid/setgid, so mode must follow it.
    let owner_changed =
        apply_owner_if_changed(flags, meta, current.uid(), current.gid(), |uid, gid| {
            let r = unsafe {
                libc::fchownat(
                    fd,
                    empty.as_ptr(),
                    uid.unwrap_or(u32::MAX),
                    gid.unwrap_or(u32::MAX),
                    libc::AT_EMPTY_PATH,
                )
            };
            if r == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        })?;
    if owner_changed {
        super::access_changed(file);
    }
    // A Linux ACL before the mode (see `apply_acls`).
    let narrowed = crate::inode_metadata::apply_acls(
        file,
        meta.inode_metadata.as_deref(),
        meta.mode,
        flags & flags::MODE != 0,
    )?;
    if flags & flags::MODE != 0 {
        let current = narrowed.unwrap_or(current.mode() & 0o7777);
        let wanted = meta.mode & 0o7777;
        if current != wanted || (owner_changed && wanted & 0o6000 != 0) {
            set_mode_handle(file, wanted)?;
            super::access_changed(file);
        }
    }
    if flags & flags::TIMES != 0 {
        bail!("metadata-only O_PATH repair does not support timestamp changes");
    }
    crate::inode_metadata::apply_after_acls(file, meta.inode_metadata.as_deref(), meta.mode)
}

#[cfg(target_os = "linux")]
pub(super) fn set_meta_handle_known_portable(
    file: &File,
    meta: &Meta,
    flags: u8,
    current: &fs::Metadata,
) -> Result<()> {
    set_meta_handle_known(file, meta, flags, current)
}

#[cfg(not(target_os = "linux"))]
pub(super) fn set_meta_handle_known_portable(
    file: &File,
    meta: &Meta,
    flags: u8,
    current: &fs::Metadata,
) -> Result<()> {
    set_meta_file_known(file, meta, flags, current)
}

/// Give the file `file` refers to the owner `uid` and group `gid`, where
/// given. `file` may be an `O_PATH` handle, which `fchown` refuses.
pub(crate) fn chown_handle(file: &File, uid: Option<u32>, gid: Option<u32>) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let r = unsafe {
            libc::fchownat(
                file.as_raw_fd(),
                c"".as_ptr(),
                uid.unwrap_or(u32::MAX),
                gid.unwrap_or(u32::MAX),
                libc::AT_EMPTY_PATH,
            )
        };
        if r != 0 {
            return Err(io::Error::last_os_error().into());
        }
    }
    #[cfg(not(target_os = "linux"))]
    std::os::unix::fs::fchown(file, uid, gid)?;
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn set_mode_handle(file: &File, mode: u32) -> Result<()> {
    let fd = file.as_raw_fd();
    let r = unsafe { libc::fchmodat(fd, c"".as_ptr(), mode as libc::mode_t, libc::AT_EMPTY_PATH) };
    if r == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if !matches!(
        error.raw_os_error(),
        Some(libc::EINVAL | libc::ENOSYS | libc::EOPNOTSUPP)
    ) {
        return Err(error.into());
    }
    // Older libc/kernel combinations do not expose fchmodat2's AT_EMPTY_PATH
    // support. procfs still resolves this stable O_PATH descriptor, never the
    // possibly replaced pathname.
    fs::set_permissions(
        crate::sys::proc_fd_path(file),
        fs::Permissions::from_mode(mode),
    )?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn set_mode_handle(file: &File, mode: u32) -> Result<()> {
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(debug_assertions)]
pub(super) fn fail_set_meta_for_test(p: &Path) -> Result<()> {
    if let Some(pat) = std::env::var_os("SYQ_TEST_FAIL_SETMETA") {
        if !pat.is_empty() && p.as_os_str().as_bytes().ends_with(pat.as_bytes()) {
            return Err(anyhow!("set metadata {}: injected failure", p.display()));
        }
    }
    Ok(())
}

/// Hold the metadata change of each path whose name starts with
/// `SYQ_TEST_CONCURRENT_SET_META_PREFIX` until
/// `SYQ_TEST_CONCURRENT_SET_META_COUNT` of them have started, and fail it if
/// they do not all start within a few seconds, as when they run one at a time.
#[cfg(debug_assertions)]
fn meet_concurrent_set_meta_for_test(p: &Path) -> Result<()> {
    use std::sync::{Condvar, Mutex};
    static STARTED: Mutex<usize> = Mutex::new(0);
    static CHANGED: Condvar = Condvar::new();
    let Some(prefix) = std::env::var_os("SYQ_TEST_CONCURRENT_SET_META_PREFIX") else {
        return Ok(());
    };
    if !p
        .file_name()
        .is_some_and(|name| name.as_bytes().starts_with(prefix.as_bytes()))
    {
        return Ok(());
    }
    let count: usize = std::env::var("SYQ_TEST_CONCURRENT_SET_META_COUNT")?.parse()?;
    let mut started = STARTED.lock().unwrap();
    *started += 1;
    CHANGED.notify_all();
    let (started, waited) = CHANGED
        .wait_timeout_while(started, std::time::Duration::from_secs(5), |started| {
            *started < count
        })
        .unwrap();
    if waited.timed_out() {
        bail!(
            "set metadata {}: only {} of {count} changes started together",
            p.display(),
            *started
        );
    }
    Ok(())
}

#[cfg(debug_assertions)]
pub(super) fn fail_apply_capacity_for_test(p: &Path) -> Result<()> {
    if let Some(pat) = std::env::var_os("SYQ_TEST_FAIL_APPLY_ENOSPC") {
        if !pat.is_empty() && p.as_os_str().as_bytes().ends_with(pat.as_bytes()) {
            return Err(io::Error::from_raw_os_error(libc::ENOSPC))
                .with_context(|| format!("apply {}: injected capacity failure", p.display()));
        }
    }
    Ok(())
}

#[cfg(any(test, debug_assertions))]
pub(super) fn fail_put_small_before_rename_for_test(p: &Path) -> Result<()> {
    if let Some(pat) = std::env::var_os("SYQ_TEST_FAIL_PUT_SMALL_BEFORE_RENAME") {
        // Model interruption after the sidecar is complete but before it
        // becomes the final name.
        if !pat.is_empty() && p.as_os_str().as_bytes().ends_with(pat.as_bytes()) {
            bail!("put small {}: injected failure before rename", p.display());
        }
    }
    Ok(())
}

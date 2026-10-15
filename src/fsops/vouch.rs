//! Whether the receiver may change an existing file's metadata in place.
//!
//! syq writes contents only into files it created in this run. It changes
//! the owner, group, mode, times, extended attributes or ACLs of a file it
//! did not create only when it can vouch for that file:
//!
//! - it is a regular file with one name, on a filesystem whose link counts
//!   can be trusted (the file's own filesystem: another can be mounted
//!   below the destination), so the change reaches no name outside the
//!   copy;
//! - it is owned by the receiving user, or, when the receiver runs as root,
//!   already by the owner and group it ends with, so root never adopts a
//!   file someone else made;
//! - the change gives it no set-user-ID or set-group-ID bit and no file
//!   capability it lacks.
//!
//! Access times are the exception: they are restored in place on any file,
//! through the descriptor the receiver holds, so a rerun with `-U` does not
//! replace a file (or relink a hard-link group) that was only read. Setting
//! one reveals and changes nothing else about the file.
//!
//! Every check reads the descriptor the change then goes through, never a
//! name. A file that fails is replaced as a changed file is, and the
//! receiver says so (`WireIoKind::ReplaceRequired`): a new file built from
//! the source, with the old one at most a donor of blocks the source's
//! hashes confirm.
//!
//! A hard-link representative (`flags::REPORT_IDENTITY`) that already
//! exists must pass the owner check even when nothing about it changes,
//! because the copy is about to give it new names.

use super::*;

/// Where a file the receiver would change is: its name below a root, and
/// the name it is shown by.
#[derive(Clone, Copy)]
pub(crate) struct Place<'a> {
    pub(crate) root: &'a Root,
    pub(crate) relative: &'a RelativePath,
    pub(crate) label: &'a Path,
}

impl<'a> From<&'a RootedTarget> for Place<'a> {
    fn from(target: &'a RootedTarget) -> Self {
        Place {
            root: &target.root,
            relative: &target.relative,
            label: &target.label,
        }
    }
}

impl Place<'_> {
    /// Whether a file created at this name might start with a group other
    /// than `group` (`apply::group_may_differ`), from its directory.
    fn new_file_group_may_differ(&self, group: u32) -> bool {
        let parent = self.relative.leaf().ok().and_then(|(directories, _)| {
            let directory = RelativePath::new(&directories.join(&b'/')).ok()?;
            let metadata = self.root.metadata(&directory).ok()?;
            Some((metadata.gid, metadata.mode))
        });
        apply::group_may_differ(parent, group)
    }
}

/// The error that tells the copy to replace `label` instead.
pub(crate) fn replace_required(label: &Path, reason: &str) -> anyhow::Error {
    anyhow::Error::new(WireError {
        message: format!(
            "{} must be replaced to change its metadata: {reason}",
            label.display()
        ),
        io_kind: Some(WireIoKind::ReplaceRequired),
        raw_os_error: None,
    })
}

/// Whether `error` says the file must be replaced (`replace_required`).
pub(crate) fn is_replace_required(error: &anyhow::Error) -> bool {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<WireError>())
        .is_some_and(is_replace_required_wire)
}

/// The same for an error the receiver sent.
pub(crate) fn is_replace_required_wire(error: &WireError) -> bool {
    error.io_kind == Some(WireIoKind::ReplaceRequired)
}

/// Whether applying `meta` under `flags` through `file`, whose metadata
/// `current` was read through it, would change anything that needs the
/// receiver to vouch for the file: anything, as the metadata step judges it
/// (`set_meta_file_inner`), but the access time.
pub(super) fn changes(file: &File, current: &fs::Metadata, meta: &Meta, flags: u8) -> Result<bool> {
    let owner = flags & flags::OWNER != 0
        && (is_superuser() || flags & flags::REQUIRE_OWNER != 0)
        && current.uid() != meta.uid;
    let group = flags & flags::GROUP != 0 && current.gid() != meta.gid;
    let mode = flags & flags::MODE != 0 && current.mode() & 0o7777 != meta.mode & 0o7777;
    let times = flags & flags::TIMES != 0
        && (current.mtime(), current.mtime_nsec() as u32) != (meta.mtime, meta.mtime_nsec);
    if owner || group || mode || times {
        return Ok(true);
    }
    crate::inode_metadata::would_change_besides_atime(
        file,
        meta.inode_metadata.as_deref(),
        meta.mode,
    )
}

/// Whether `current` is owned as a file syq may change in place must be:
/// by the receiving user, or, as root, already by the owner and group it
/// ends with. Without an owner or group to set, that is the one a new file
/// at `target` would get.
pub(super) fn owner_vouches(
    place: Place<'_>,
    current: &fs::Metadata,
    meta: &Meta,
    flags: u8,
) -> bool {
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        return current.uid() == euid;
    }
    let uid = if flags & flags::OWNER != 0 {
        meta.uid
    } else {
        0
    };
    if current.uid() != uid {
        return false;
    }
    if flags & flags::GROUP != 0 {
        current.gid() == meta.gid
    } else {
        !place.new_file_group_may_differ(current.gid())
    }
}

/// Whether the receiver may change `file`'s metadata in place (see the
/// module documentation), and if not, why.
pub(super) fn refusal(
    place: Place<'_>,
    file: &File,
    current: &fs::Metadata,
    meta: &Meta,
    flags: u8,
) -> Result<Option<&'static str>> {
    if !current.is_file() {
        return Ok(Some("it is not a regular file"));
    }
    if current.nlink() != 1 {
        return Ok(Some("it has other names"));
    }
    if !place.root.link_counts_trusted_on(current.dev(), file) {
        return Ok(Some("its filesystem's link counts cannot be trusted"));
    }
    if !owner_vouches(place, current, meta, flags) {
        return Ok(Some(
            "syq did not create it and does not own it as it would",
        ));
    }
    if flags & flags::MODE != 0 && meta.mode & 0o6000 & !current.mode() != 0 {
        return Ok(Some("the change adds a set-ID bit"));
    }
    if crate::inode_metadata::adds_capability(file, meta.inode_metadata.as_deref())? {
        return Ok(Some("the change adds a file capability"));
    }
    Ok(None)
}

/// Refuse, with `replace_required`, to change `file`'s metadata in place
/// unless the receiver can vouch for it or the change would change nothing
/// but the access time.
/// A hard-link representative must pass the owner check either way.
/// `current` was read through `file`.
pub(crate) fn require<'a>(
    place: impl Into<Place<'a>>,
    file: &File,
    current: &fs::Metadata,
    meta: &Meta,
    flags: u8,
) -> Result<()> {
    let place = place.into();
    if flags & flags::REPORT_IDENTITY != 0 && !owner_vouches(place, current, meta, flags) {
        return Err(replace_required(
            place.label,
            "it is to get new names, and syq did not create it and does not own it as it would",
        ));
    }
    if !changes(file, current, meta, flags)? {
        return Ok(());
    }
    match refusal(place, file, current, meta, flags)? {
        None => Ok(()),
        Some(reason) => Err(replace_required(place.label, reason)),
    }
}

/// Whether `require` would let the change through, for a caller that has
/// another way to finish the file (a stage it can publish instead).
pub(crate) fn allows<'a>(
    place: impl Into<Place<'a>>,
    file: &File,
    current: &fs::Metadata,
    meta: &Meta,
    flags: u8,
) -> Result<bool> {
    match require(place, file, current, meta, flags) {
        Ok(()) => Ok(true),
        Err(error) if is_replace_required(&error) => Ok(false),
        Err(error) => Err(error),
    }
}

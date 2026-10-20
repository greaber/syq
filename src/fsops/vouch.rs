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
//! - for a receiver other than root, it is owned as the files the receiver
//!   creates on that filesystem show (`rooted::created_owner`): mostly the
//!   receiving account, another on SSHFS without uid mapping, NFS that
//!   squashes root or CIFS mounted with `uid=`;
//! - for root, the change is one the file's owner could make themselves:
//!   its permission bits, times, ordinary extended attributes and ACLs, but
//!   not another owner or group, so root never hands someone's file to
//!   another account;
//! - the change gives it no set-user-ID or set-group-ID bit, and sets or
//!   removes no `security.*` or `trusted.*` attribute, such as a file
//!   capability or an SELinux label.
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
//!
//! `--in-place=update` writes new contents into an existing file only when
//! the receiver can vouch for it in the same way, whatever its metadata
//! change, with root's owner test that of a file to get new names: the
//! owner can read what is written, so root writes only into a file that
//! already has the owner and group it ends with. No one who can open the
//! file now may be unable to once the copy gives it its final metadata
//! (`update_refusal`). Anyone who opened it
//! earlier, or opens it while it is written, can still read what the copy
//! writes: the option's documented tradeoff.

use super::*;

/// Where a file the receiver would change is: its name below a root, and
/// the name it is shown by.
#[derive(Clone, Copy)]
pub(crate) struct Place<'a> {
    pub(crate) root: &'a Root,
    pub(crate) relative: &'a RelativePath,
    pub(crate) label: &'a Path,
    /// The check only predicts, for a preview: it creates nothing to learn
    /// whom the receiver's files show, and where it does not know, it takes
    /// the receiving account, as the planner's prediction does.
    pub(crate) preview: bool,
}

impl<'a> From<&'a RootedTarget> for Place<'a> {
    fn from(target: &'a RootedTarget) -> Self {
        Place {
            root: &target.root,
            relative: &target.relative,
            label: &target.label,
            preview: false,
        }
    }
}

impl Place<'_> {
    /// The owner files the receiver creates on `dev` show, learned in this
    /// file's directory or the root (`Root::created_owner_in`).
    fn created_owner(&self, dev: u64) -> Option<u32> {
        let directory = self
            .relative
            .leaf()
            .ok()
            .and_then(|(directories, _)| RelativePath::new(&directories.join(&b'/')).ok())?;
        if self.preview {
            return Some(
                self.root
                    .created_owner_known_in(&directory, dev)
                    .unwrap_or_else(crate::rooted::own_uid),
            );
        }
        self.root.created_owner_in(&directory, dev)
    }

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

/// Why the receiver will not change a file in place, with the detail its
/// error gives.
pub(crate) type Refusal = (ReplaceReason, &'static str);

/// The error that tells the copy to replace `label` instead, to do what
/// `doing` says.
pub(crate) fn replace_required(
    label: &Path,
    doing: &str,
    (reason, detail): Refusal,
) -> anyhow::Error {
    anyhow::Error::new(WireError {
        message: format!("{} must be replaced to {doing}: {detail}", label.display()),
        io_kind: Some(WireIoKind::ReplaceRequired(reason)),
        raw_os_error: None,
        condition_not_met: false,
        unchanged: true,
    })
}

/// Why `error` says the file must be replaced (`replace_required`), if it
/// does.
pub(crate) fn replace_reason(error: &anyhow::Error) -> Option<ReplaceReason> {
    crate::conn::wire_error_of(error).and_then(replace_reason_wire)
}

/// Whether `error` says the file must be replaced (`replace_required`).
pub(crate) fn is_replace_required(error: &anyhow::Error) -> bool {
    replace_reason(error).is_some()
}

/// The same for an error the receiver sent.
pub(crate) fn replace_reason_wire(error: &WireError) -> Option<ReplaceReason> {
    match error.io_kind {
        Some(WireIoKind::ReplaceRequired(reason)) => Some(reason),
        _ => None,
    }
}

/// The same for an error the receiver sent.
pub(crate) fn is_replace_required_wire(error: &WireError) -> bool {
    replace_reason_wire(error).is_some()
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

/// Whether `current` is owned as a file a receiver other than root may
/// change in place, or any receiver may give new names to, must be: as the
/// files the receiver creates on its filesystem show, or, as root, already
/// by the owner and group it ends with. Without an owner or group to set,
/// that is the one a new file at `place` would get. Where the receiver
/// cannot learn the owner its files show, nothing is owned.
pub(super) fn owner_vouches(
    place: Place<'_>,
    current: &fs::Metadata,
    meta: &Meta,
    flags: u8,
) -> bool {
    let Some(created) = place.created_owner(current.dev()) else {
        return false;
    };
    if !is_superuser() {
        return current.uid() == created;
    }
    let uid = if flags & flags::OWNER != 0 {
        meta.uid
    } else {
        created
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
) -> Result<Option<Refusal>> {
    use ReplaceReason::*;
    if !current.is_file() {
        return Ok(Some((NotRegular, "it is not a regular file")));
    }
    if current.nlink() != 1 {
        return Ok(Some((OtherNames, "it has other names")));
    }
    if !place.root.link_counts_trusted_on(current.dev(), file) {
        return Ok(Some((
            UntrustedFilesystem,
            "its filesystem's link counts cannot be trusted",
        )));
    }
    if is_superuser() {
        // Root decides by the change: what the file's owner could change
        // themselves goes in place; another owner or group replaces it.
        if flags & flags::OWNER != 0 && current.uid() != meta.uid {
            return Ok(Some((Owner, "the change gives it another owner")));
        }
        if flags & flags::GROUP != 0 && current.gid() != meta.gid {
            return Ok(Some((Owner, "the change gives it another group")));
        }
    } else if !owner_vouches(place, current, meta, flags) {
        return Ok(Some((
            Owner,
            "syq did not create it and does not own it as its files show",
        )));
    }
    if flags & flags::MODE != 0 && meta.mode & 0o6000 & !current.mode() != 0 {
        return Ok(Some((Privileges, "the change adds a set-ID bit")));
    }
    if crate::inode_metadata::changes_privileged_attributes(file, meta.inode_metadata.as_deref())? {
        return Ok(Some((
            Privileges,
            "the change sets or removes a security or trusted attribute",
        )));
    }
    Ok(None)
}

/// Whether the receiver may write new contents into `file`, the existing
/// file at `place`, in place (`--in-place=update`), to finalize it with
/// `meta` under `flags`, and if not, why. It must pass the checks for any
/// metadata change (`refusal`) and, for root or as a hard-link
/// representative, the owner check (`owner_vouches`): root writes only into
/// a file that already has the owner and group it ends with. It must have
/// no set-ID bit or file capability,
/// which writing it would take away, and let no one read or write it whom
/// its final permissions do not: its permission bits must be among the
/// final ones, its group the final one or unable to read or write it, and
/// its ACL the one it ends with: the one the copy gives it, or without ACL
/// copying the one a new file there would inherit from its directory, as
/// `inherited` gives it (`inode_metadata::acl_differs_from_final`). Without `-p` or `-g`, the
/// file keeps its mode or group. `current` was read through `file`.
pub(crate) fn update_refusal(
    place: Place<'_>,
    file: &File,
    current: &fs::Metadata,
    meta: &Meta,
    flags: u8,
    inherited: impl FnOnce() -> Result<crate::inode_metadata::Inherited>,
) -> Result<Option<Refusal>> {
    use ReplaceReason::*;
    if let Some(refused) = refusal(place, file, current, meta, flags)? {
        return Ok(Some(refused));
    }
    // Root decides metadata changes by the change, which writes no data.
    // New contents would be readable by the file's owner, so root writes
    // them only into a file that already has the owner and group it ends
    // with, as `require` asks of a hard-link representative.
    if (is_superuser() || flags & flags::REPORT_IDENTITY != 0)
        && !owner_vouches(place, current, meta, flags)
    {
        return Ok(Some((
            Owner,
            "syq did not create it and it does not have the owner and group the copy gives it",
        )));
    }
    if current.mode() & 0o6000 != 0 || crate::inode_metadata::has_file_capability(file)? {
        return Ok(Some((
            Privileges,
            "it has a set-ID bit or a file capability, which writing it would take away",
        )));
    }
    let mode = if flags & flags::MODE != 0 {
        meta.mode
    } else {
        current.mode()
    } & 0o777;
    if current.mode() & 0o777 & !mode != 0 {
        return Ok(Some((
            WiderPermissions,
            "its mode lets others read or write it whom the copy's mode does not",
        )));
    }
    if flags & flags::GROUP != 0 && current.gid() != meta.gid && current.mode() & 0o060 != 0 {
        return Ok(Some((
            WiderPermissions,
            "its group, which the copy changes, can read or write it",
        )));
    }
    if crate::inode_metadata::acl_differs_from_final(
        file,
        meta.inode_metadata.as_deref(),
        inherited,
        mode,
    )? {
        return Ok(Some((
            WiderPermissions,
            "its ACL is not the one it ends with, which may keep out someone it lets in",
        )));
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
            "change its metadata",
            (
                ReplaceReason::Owner,
                "it is to get new names, and syq did not create it and does not own it as it would",
            ),
        ));
    }
    if !changes(file, current, meta, flags)? {
        return Ok(());
    }
    match refusal(place, file, current, meta, flags)? {
        None => Ok(()),
        Some(refused) => Err(replace_required(
            place.label,
            "change its metadata",
            refused,
        )),
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
    declines(place, file, current, meta, flags).map(|declined| declined.is_none())
}

/// Why `require` would refuse the change, if it would, for a caller that
/// replaces the file instead and says why.
pub(crate) fn declines<'a>(
    place: impl Into<Place<'a>>,
    file: &File,
    current: &fs::Metadata,
    meta: &Meta,
    flags: u8,
) -> Result<Option<ReplaceReason>> {
    match require(place, file, current, meta, flags) {
        Ok(()) => Ok(None),
        Err(error) => match replace_reason(&error) {
            Some(reason) => Ok(Some(reason)),
            None => Err(error),
        },
    }
}

//! Publishing a name where a filesystem lacks an atomic rename flag or hard
//! links.
//!
//! Exchange (`RENAME_EXCHANGE`, macOS `RENAME_SWAP`) is missing on HFS+,
//! exFAT, NFS, SMB and FUSE filesystems such as SSHFS. A no-replace rename
//! (`RENAME_NOREPLACE`, macOS `RENAME_EXCL`) is not atomic on most of those,
//! and hard links are missing on FAT, exFAT and rclone mounts. The
//! filesystem's profile (`fsops::Profile`) says which to try. A filesystem
//! that refuses one anyway, as OpenZFS before 2.2 refuses exchange, is
//! remembered (`fsops::record_refusal`), and later publications there go
//! straight to the fallback.

use super::{metadata_at, rename_noreplace, retry_zero, RootMetadata};
use crate::fsops::{Profile, Refusal};
use std::ffi::CStr;
use std::io;
use std::os::fd::RawFd;

#[cfg(test)]
thread_local! {
    /// Tests stand in for a filesystem whose profile allows exchange and
    /// no-replace renames but whose kernel refuses them.
    pub(super) static REFUSE_RENAME_FLAGS: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
    /// Rename-flag calls made while refusing them.
    pub(super) static REFUSED_RENAME_FLAG_CALLS: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
    /// Names other than fresh recovery names published by the
    /// check-then-rename step.
    pub(super) static CHECKED_RENAMES: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
    /// Tests stand in for a filesystem that fails each link step of a
    /// publication with this error.
    pub(super) static LINK_ERROR: std::cell::Cell<Option<i32>> =
        const { std::cell::Cell::new(None) };
}

/// A refusal tests stand in for, or None to make the call.
pub(super) fn simulated_refusal() -> Option<io::Error> {
    #[cfg(test)]
    if REFUSE_RENAME_FLAGS.get() {
        REFUSED_RENAME_FLAG_CALLS.set(REFUSED_RENAME_FLAG_CALLS.get() + 1);
        return Some(io::Error::from_raw_os_error(libc::EINVAL));
    }
    None
}

/// The kernel's internal "not supported" code, which AFS returns for a
/// rename flag its server lacks.
#[cfg(target_os = "linux")]
const KERNEL_ENOTSUPP: i32 = 524;

/// Whether a rename-flag call failed because the filesystem does not
/// implement the flag. Linux filesystems reject an unknown flag with
/// `EINVAL`; for two names in one directory and the leaves syq publishes,
/// `EINVAL` has no other cause. macOS volumes answer `ENOTSUP`.
pub(super) fn rename_flag_unsupported(error: &io::Error) -> bool {
    error.raw_os_error().is_some_and(|code| {
        #[cfg(target_os = "linux")]
        if code == KERNEL_ENOTSUPP {
            return true;
        }
        matches!(code, libc::EINVAL | libc::ENOSYS | libc::EOPNOTSUPP) || code == libc::ENOTSUP
    })
}

/// Whether `linkat` failed with an error that says the filesystem has no
/// hard links: `ENOTSUP` from macOS FAT, exFAT and SMB, `ENOSYS` from a
/// server without them.
pub(super) fn links_unsupported(error: &io::Error) -> bool {
    error.raw_os_error().is_some_and(|code| {
        matches!(code, libc::ENOSYS | libc::EOPNOTSUPP) || code == libc::ENOTSUP
    })
}

/// Whether a failed link falls back to the final check-then-rename: where
/// the filesystem has no hard links; on `EPERM`, which Linux gives for a
/// filesystem without links (and FUSE for a server without them), SSHFS
/// for an existing target, and Linux for a file that may not be linked,
/// such as another user's under `fs.protected_hardlinks`; and on `EIO`
/// only where the filesystem was not audited, as an rclone mount answers
/// a link with it. On an audited filesystem `EIO` is an I/O error.
fn link_falls_back(error: &io::Error, profile: &Profile) -> bool {
    links_unsupported(error)
        || error.raw_os_error() == Some(libc::EPERM)
        || (error.raw_os_error() == Some(libc::EIO) && !profile.audited)
}

/// Whether `from` may be linked to `to` and its own name then removed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Link {
    /// No: `from` moves by rename. It is an entry another writer may
    /// replace meanwhile, which must move so that exactly what is at the
    /// name moves, or an entry being put back that is not a regular file,
    /// such as a directory, which cannot be linked.
    Never,
    /// Yes, for a name only this publication uses that is not a staged
    /// file: a regular file moved aside, a new name of an existing file, or
    /// a new symlink or node where the filesystem was audited. Its link may
    /// be refused for reasons of its own, as Linux refuses another user's
    /// file under `fs.protected_hardlinks`, so a refusal is not remembered.
    Entry,
    /// Yes, for a staged file this receiver created, and a refusal that
    /// says the filesystem has no hard links is remembered: nothing about
    /// the file can be the reason.
    Staged,
}

impl Link {
    /// How a new symlink, device node or FIFO may be published: by linking
    /// only where the filesystem was audited, where a link names the entry
    /// itself. Elsewhere the link may be made by a server whose `link()`
    /// follows symlinks, as macOS's does behind SSHFS, which would publish
    /// a hard link to the file a sender's symlink names.
    pub(super) fn new_entry(profile: Profile) -> Self {
        if profile.audited {
            Self::Entry
        } else {
            Self::Never
        }
    }

    /// How an entry being put back may move: by linking a regular file,
    /// and renaming anything else.
    pub(super) fn putting_back(entry: RootMetadata) -> Self {
        if entry.is_file() {
            Self::Entry
        } else {
            Self::Never
        }
    }
}

/// How a name was published without replacing another.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Moved {
    /// The source name is gone.
    Renamed,
    /// The source name remains, for the caller to check and remove.
    Linked,
}

/// Where to publish and which steps the filesystem may use.
pub(super) struct Placement<'a> {
    pub(super) from_directory: RawFd,
    pub(super) from: &'a CStr,
    pub(super) to_directory: RawFd,
    pub(super) to: &'a CStr,
    pub(super) link: Link,
    /// A link is made from this open file (`/proc/self/fd/N` on Linux)
    /// rather than from `from`'s name, so it links exactly that file.
    pub(super) descriptor: Option<&'a CStr>,
}

/// Give `from` the name `to` without replacing anything already there,
/// failing with `EEXIST` when `to` exists. Tries, in turn:
///
/// 1. an atomic no-replace rename, where the profile says the filesystem
///    implements it atomically: audited Linux filesystems, and macOS APFS
///    and HFS+ volumes. A network filesystem may check the target itself
///    and then tell its server to replace (SMB), or ignore the flag (one of
///    rclone's mount modes), so others skip to linking;
/// 2. a hard link, which the kernel or server refuses atomically when the
///    name exists, when `link` allows and the filesystem may have links;
/// 3. a check that `to` is absent, then a plain rename.
///
/// Steps 1 and 2 never replace anything. Step 3 runs where neither is
/// available, as on rclone mounts and on FAT and exFAT volumes on macOS,
/// and where an ordinary receiver's copy accepts it in place of a link
/// (`Root::publish_new_staged`); there a name another writer creates
/// between the check and the rename is replaced. A name that existed
/// before is always refused, so a policy that keeps existing files keeps
/// them, and a restricted receiver always uses this same order: a sender
/// cannot move an existing file onto the name, because no operation it may
/// request renames an existing destination entry to another name.
///
/// A refusal of a step the profile allowed is passed to `record_refusal`
/// and taken out of `profile`, so the rest of a publication skips it too:
/// a rename flag the filesystem rejects, whatever the entry (Linux and the
/// filesystems check flags before the names), and hard links only when a
/// staged file's link fails with an error that says they are missing.
/// `EXDEV`, `EPERM`, `EACCES` and `EIO` are never taken for refusals.
pub(super) fn move_without_replacing(
    profile: &mut Profile,
    placement: &Placement<'_>,
    record_refusal: &dyn Fn(Refusal),
) -> io::Result<Moved> {
    let Placement {
        from_directory,
        from,
        to_directory,
        to,
        link,
        descriptor,
    } = *placement;
    let refuse = |profile: &mut Profile, refusal| {
        *profile = profile.without(refusal);
        record_refusal(refusal);
    };
    if profile.atomic_no_replace_rename {
        let renamed = match simulated_refusal() {
            Some(error) => Err(error),
            None => rename_noreplace(from_directory, from, to_directory, to),
        };
        match renamed {
            Ok(()) => return Ok(Moved::Renamed),
            Err(error) if rename_flag_unsupported(&error) => {
                refuse(profile, Refusal::NoReplaceRename)
            }
            Err(error) => return Err(error),
        }
    }
    if link != Link::Never && profile.hard_links {
        #[cfg(test)]
        let simulated = LINK_ERROR.get().map(io::Error::from_raw_os_error);
        #[cfg(not(test))]
        let simulated = None;
        let linked = match (simulated, descriptor) {
            (Some(error), _) => Err(error),
            (None, Some(descriptor)) => retry_zero(|| unsafe {
                libc::linkat(
                    libc::AT_FDCWD,
                    descriptor.as_ptr(),
                    to_directory,
                    to.as_ptr(),
                    libc::AT_SYMLINK_FOLLOW,
                )
            }),
            (None, None) => retry_zero(|| unsafe {
                libc::linkat(from_directory, from.as_ptr(), to_directory, to.as_ptr(), 0)
            }),
        };
        match linked {
            Ok(()) => return Ok(Moved::Linked),
            Err(error) if link_falls_back(&error, profile) => {
                // SSHFS reports a refused existing target as EPERM.
                if metadata_at(to_directory, to).is_ok() {
                    return Err(io::Error::from_raw_os_error(libc::EEXIST));
                }
                if link == Link::Staged && links_unsupported(&error) {
                    refuse(profile, Refusal::HardLinks);
                }
            }
            Err(error) => return Err(error),
        }
    }
    #[cfg(test)]
    if !crate::fsops::is_recovery_name(std::os::unix::ffi::OsStrExt::from_bytes(to.to_bytes())) {
        CHECKED_RENAMES.set(CHECKED_RENAMES.get() + 1);
    }
    match metadata_at(to_directory, to) {
        Ok(_) => return Err(io::Error::from_raw_os_error(libc::EEXIST)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    retry_zero(|| unsafe {
        libc::renameat(from_directory, from.as_ptr(), to_directory, to.as_ptr())
    })?;
    Ok(Moved::Renamed)
}

/// Whether an entry is the object a matched replacement expects.
pub(super) fn is_expected(metadata: RootMetadata, dev: u64, ino: u64, file_type: u32) -> bool {
    metadata.dev == dev && metadata.ino == ino && metadata.file_type() == file_type
}

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

/// Whether a rename-flag call failed because the filesystem does not
/// implement the flag. Linux filesystems reject an unknown flag with
/// `EINVAL`; for two names in one directory and the leaves syq publishes,
/// `EINVAL` has no other cause. macOS volumes answer `ENOTSUP`.
pub(super) fn rename_flag_unsupported(error: &io::Error) -> bool {
    error.raw_os_error().is_some_and(|code| {
        matches!(code, libc::EINVAL | libc::ENOSYS | libc::EOPNOTSUPP) || code == libc::ENOTSUP
    })
}

/// Whether `linkat` failed because the filesystem has no hard links:
/// `EPERM` from Linux FAT and FUSE servers without links, `ENOTSUP` from
/// macOS FAT, exFAT and SMB, `EIO` from rclone mounts.
fn links_unavailable(error: &io::Error) -> bool {
    error.raw_os_error().is_some_and(|code| {
        matches!(
            code,
            libc::EPERM | libc::ENOSYS | libc::EOPNOTSUPP | libc::EIO
        ) || code == libc::ENOTSUP
    })
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
    /// Whether linking and then removing the source name is acceptable:
    /// it is for a private staged file, not for a name others may change.
    pub(super) allow_link: bool,
}

/// Give `from` the name `to` without replacing anything already there,
/// failing with `EEXIST` when `to` exists. Tries, in turn:
///
/// 1. an atomic no-replace rename, where the profile says the filesystem
///    implements it atomically: verified local filesystems, and macOS
///    volumes that advertise it. A network filesystem may check the target
///    itself and then tell its server to replace (SMB), or ignore the flag
///    (one of rclone's mount modes), so others skip to linking;
/// 2. a hard link, which servers create atomically, when allowed and the
///    filesystem may have links;
/// 3. a check that `to` is absent, then a plain rename.
///
/// The last step can replace only a name that appeared after its check.
/// A name that existed before is always refused, so a policy that keeps
/// existing files keeps them, and every receiver uses this same order: a
/// sender cannot move an existing file onto the name, because no operation
/// it may request renames an existing destination entry to another name.
pub(super) fn move_without_replacing(
    profile: Profile,
    placement: &Placement<'_>,
    record_refusal: &dyn Fn(Refusal),
) -> io::Result<Moved> {
    let Placement {
        from_directory,
        from,
        to_directory,
        to,
        allow_link,
    } = *placement;
    if profile.atomic_no_replace_rename {
        let renamed = match simulated_refusal() {
            Some(error) => Err(error),
            None => rename_noreplace(from_directory, from, to_directory, to),
        };
        match renamed {
            Ok(()) => return Ok(Moved::Renamed),
            Err(error) if rename_flag_unsupported(&error) => {
                record_refusal(Refusal::NoReplaceRename);
            }
            Err(error) => return Err(error),
        }
    }
    if allow_link && profile.hard_links {
        match retry_zero(|| unsafe {
            libc::linkat(from_directory, from.as_ptr(), to_directory, to.as_ptr(), 0)
        }) {
            Ok(()) => return Ok(Moved::Linked),
            Err(error) if links_unavailable(&error) => {
                // SSHFS reports a refused existing target as EPERM.
                if metadata_at(to_directory, to).is_ok() {
                    return Err(io::Error::from_raw_os_error(libc::EEXIST));
                }
                // EIO may be transient; only a definite refusal is kept.
                if error.raw_os_error() != Some(libc::EIO) {
                    record_refusal(Refusal::HardLinks);
                }
            }
            Err(error) => return Err(error),
        }
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

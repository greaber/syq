//! Publishing a name where a filesystem lacks an atomic rename flag or hard
//! links, learned per root as syq uses them.
//!
//! Exchange (`RENAME_EXCHANGE`, macOS `RENAME_SWAP`) is missing on HFS+,
//! exFAT, NFS, SMB and FUSE filesystems such as SSHFS. A no-replace rename
//! (`RENAME_NOREPLACE`, macOS `RENAME_EXCL`) is missing on most of those
//! too, and hard links are missing on FAT, exFAT and rclone mounts. Each
//! operation is tried first; a filesystem that refuses one as unsupported
//! is remembered, so later publications skip straight to the fallback.

use super::{metadata_at, rename_noreplace, retry_zero, RootMetadata};
use std::ffi::CStr;
use std::io;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicU8, Ordering};

// Zero, the default, means not yet known.
const SUPPORTED: u8 = 1;
const UNSUPPORTED: u8 = 2;

/// One operation's support, learned from its first conclusive result.
#[derive(Default)]
pub(super) struct Learned(AtomicU8);

impl Learned {
    pub(super) fn unsupported(&self) -> bool {
        self.0.load(Ordering::Relaxed) == UNSUPPORTED
    }

    pub(super) fn record(&self, supported: bool) {
        self.0.store(
            if supported { SUPPORTED } else { UNSUPPORTED },
            Ordering::Relaxed,
        );
    }
}

/// What the root's filesystem has shown it supports.
#[derive(Default)]
pub(super) struct Capabilities {
    pub(super) exchange: Learned,
    pub(super) no_replace_rename: Learned,
    pub(super) links: Learned,
}

impl Capabilities {
    /// Tests stand in for filesystems that lack these operations.
    pub(super) fn new() -> Self {
        let capabilities = Self::default();
        #[cfg(debug_assertions)]
        {
            if std::env::var_os("SYQ_TEST_NO_RENAME_EXCHANGE").is_some() {
                capabilities.exchange.record(false);
            }
            if std::env::var_os("SYQ_TEST_NO_RENAME_NOREPLACE").is_some() {
                capabilities.no_replace_rename.record(false);
            }
            if std::env::var_os("SYQ_TEST_NO_HARD_LINKS").is_some() {
                capabilities.links.record(false);
            }
        }
        capabilities
    }
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
/// 1. an atomic no-replace rename, where the filesystem implements it
///    atomically: local filesystems on Linux, and macOS volumes that
///    advertise it. A network filesystem may check the target itself and
///    then tell its server to replace (SMB), or ignore the flag (one of
///    rclone's mount modes), so those skip to linking;
/// 2. a hard link, which servers create atomically, when allowed;
/// 3. a check that `to` is absent, then a plain rename.
///
/// The last step can replace only a name that appeared after its check.
/// A name that existed before is always refused, so a policy that keeps
/// existing files keeps them, and every receiver uses this same order: a
/// sender cannot move an existing file onto the name, because no operation
/// it may request renames an existing destination entry to another name.
pub(super) fn move_without_replacing(
    capabilities: &Capabilities,
    atomic_rename: bool,
    placement: &Placement<'_>,
) -> io::Result<Moved> {
    let Placement {
        from_directory,
        from,
        to_directory,
        to,
        allow_link,
    } = *placement;
    if atomic_rename && !capabilities.no_replace_rename.unsupported() {
        match rename_noreplace(from_directory, from, to_directory, to) {
            Ok(()) => {
                capabilities.no_replace_rename.record(true);
                return Ok(Moved::Renamed);
            }
            Err(error) if rename_flag_unsupported(&error) => {
                capabilities.no_replace_rename.record(false);
            }
            Err(error) => return Err(error),
        }
    }
    if allow_link && !capabilities.links.unsupported() {
        match retry_zero(|| unsafe {
            libc::linkat(from_directory, from.as_ptr(), to_directory, to.as_ptr(), 0)
        }) {
            Ok(()) => {
                capabilities.links.record(true);
                return Ok(Moved::Linked);
            }
            Err(error) if links_unavailable(&error) => {
                // SSHFS reports a refused existing target as EPERM.
                if metadata_at(to_directory, to).is_ok() {
                    return Err(io::Error::from_raw_os_error(libc::EEXIST));
                }
                // EIO may be transient; only a definite refusal is kept.
                if error.raw_os_error() != Some(libc::EIO) {
                    capabilities.links.record(false);
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

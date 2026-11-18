//! Small private state files: atomic publication, private directories and
//! bounded, validated reads.
//!
//! Each caller states its own policy (mode rule, replace or no-clobber,
//! durability and size bound); the files' names, locations and contents are
//! shared between syq versions on one host, so this module never chooses them.
use anyhow::{bail, Context, Result};
use std::ffi::{CString, OsStr};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::Path;

/// Temporary files are named `<TEMP_PREFIX><pid>-<random hex>`, so that a
/// directory scan can recognize one left behind by a killed writer.
const TEMP_PREFIX: &str = ".syq-tmp-";

/// Whether `name` is a temporary file of an atomic write: this module's
/// own, or the `.tmpXXXXXX` names that earlier builds' writers left.
pub(crate) fn is_own_temp_name(name: &OsStr) -> bool {
    let name = name.as_bytes();
    if let Some(rest) = name.strip_prefix(TEMP_PREFIX.as_bytes()) {
        return !rest.is_empty()
            && rest
                .iter()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f' | b'-'));
    }
    // `tempfile::NamedTempFile::new_in`: ".tmp" and six alphanumerics.
    name.strip_prefix(b".tmp")
        .is_some_and(|rest| rest.len() == 6 && rest.iter().all(u8::is_ascii_alphanumeric))
}

/// What to do when the destination name already exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Publish {
    /// Replace it atomically.
    Replace,
    /// Leave it; the write reports `false`.
    NoClobber,
}

/// How durable a completed write is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Durability {
    /// Readers see the old or the new contents, but a power loss may lose
    /// the change. For caches and state that a restart recreates.
    RenameOnly,
    /// The file's contents are synced before the rename, but not the
    /// directory entry: after a power loss the old or the new file survives,
    /// never a partly written one.
    FileSynced,
    /// The file and the directory entry are synced before returning.
    Synced,
}

/// Atomically publish `contents` as `path`, with permission bits `mode`.
/// Returns `false` only for [`Publish::NoClobber`] when `path` existed.
pub(crate) fn write_atomic(
    path: &Path,
    contents: &[u8],
    mode: u32,
    publish: Publish,
    durability: Durability,
) -> io::Result<bool> {
    let parent = match path.parent() {
        Some(parent) if parent.as_os_str().is_empty() => Path::new("."),
        Some(parent) => parent,
        None => return Err(io::Error::new(io::ErrorKind::InvalidInput, "no parent")),
    };
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no file name"))?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(parent)?;
    write_atomic_at(&directory, name, contents, mode, publish, durability)
}

/// [`write_atomic`] relative to an open directory: the temporary file is
/// created with `O_EXCL | O_NOFOLLOW` and renamed within `directory`.
pub(crate) fn write_atomic_at(
    directory: &File,
    name: &OsStr,
    contents: &[u8],
    mode: u32,
    publish: Publish,
    durability: Durability,
) -> io::Result<bool> {
    let destination = leaf(name)?;
    let (temporary_name, mut file) = create_temporary(directory, mode)?;
    // Whether the temporary name still exists once this is done.
    let mut temporary_remains = true;
    let result = (|| -> io::Result<bool> {
        // The creation mode passed through the umask; the file gets
        // exactly `mode`, whatever the umask.
        if file.metadata()?.mode() & 0o7777 != mode {
            file.set_permissions(std::fs::Permissions::from_mode(mode))?;
        }
        file.write_all(contents)?;
        if durability != Durability::RenameOnly {
            file.sync_all()?;
        }
        // Close before publishing: Linux refuses to run an executable that
        // still has a writer open.
        drop(file);
        match publish {
            Publish::Replace => {
                crate::sys::retry_zero(|| unsafe {
                    libc::renameat(
                        directory.as_raw_fd(),
                        temporary_name.as_ptr(),
                        directory.as_raw_fd(),
                        destination.as_ptr(),
                    )
                })?;
                temporary_remains = false;
            }
            Publish::NoClobber => {
                match rename_no_replace(directory, &temporary_name, &destination) {
                    Ok(linked) => temporary_remains = linked,
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => return Ok(false),
                    Err(error) => return Err(error),
                }
            }
        }
        if durability == Durability::Synced {
            directory.sync_all()?;
        }
        Ok(true)
    })();
    if temporary_remains {
        let removed = unlink(directory, &temporary_name);
        if result.as_ref().is_ok_and(|published| *published) {
            // A hard link published the file: removing the temporary name
            // is part of the write.
            removed?;
            if durability == Durability::Synced {
                directory.sync_all()?;
            }
        }
    }
    result
}

fn create_temporary(directory: &File, mode: u32) -> io::Result<(CString, File)> {
    for _ in 0..16 {
        let mut random = [0u8; 8];
        getrandom::fill(&mut random).map_err(io::Error::other)?;
        let name = CString::new(format!(
            "{TEMP_PREFIX}{}-{:016x}",
            std::process::id(),
            u64::from_le_bytes(random)
        ))
        .expect("temporary name has no NUL");
        match crate::sys::open_at(
            directory.as_raw_fd(),
            &name,
            libc::O_WRONLY
                | libc::O_CREAT
                | libc::O_EXCL
                | libc::O_NOFOLLOW
                | libc::O_NOCTTY
                | libc::O_CLOEXEC,
            mode & 0o700,
        ) {
            Ok(file) => return Ok((name, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not choose a unique temporary file name",
    ))
}

/// Publish `from` as `to` unless `to` exists. As `tempfile` does, use the
/// kernel's no-replace rename and fall back to a hard link where the
/// filesystem lacks it. Returns whether it linked, leaving `from` in place.
fn rename_no_replace(directory: &File, from: &CString, to: &CString) -> io::Result<bool> {
    let fd = directory.as_raw_fd();
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let renamed = crate::sys::retry_zero(|| unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            fd,
            from.as_ptr(),
            fd,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        ) as libc::c_int
    });
    #[cfg(target_vendor = "apple")]
    let renamed = crate::sys::retry_zero(|| unsafe {
        libc::renameatx_np(fd, from.as_ptr(), fd, to.as_ptr(), libc::RENAME_EXCL)
    });
    #[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
    let renamed: io::Result<()> = Err(io::Error::from_raw_os_error(libc::ENOSYS));
    match renamed {
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(libc::EINVAL | libc::ENOSYS | libc::ENOTSUP)
            ) => {}
        result => return result.map(|()| false),
    }
    crate::sys::retry_zero(|| unsafe { libc::linkat(fd, from.as_ptr(), fd, to.as_ptr(), 0) })?;
    Ok(true)
}

fn unlink(directory: &File, name: &CString) -> io::Result<()> {
    crate::sys::retry_zero(|| unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) })
}

fn leaf(name: &OsStr) -> io::Result<CString> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.contains(&b'/') || bytes == b"." || bytes == b".." {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid state file name",
        ));
    }
    CString::new(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in state file name"))
}

/// Which permission bits a private state file may have. Every rule except
/// [`FileRule::Regular`] also requires the file to belong to this user.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FileRule {
    /// Exactly 0600 (no set-id or sticky bits).
    Exact0600,
    /// No group or other permission bits.
    NoGroupOther,
    /// No group or other write bits.
    NoGroupOtherWrite,
    /// Owned by this user, any mode.
    Owned,
    /// Any regular file; for files other accounts may manage.
    Regular,
}

const READ_FLAGS: libc::c_int =
    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC;

/// Open a state file for [`read_open`] without following a final symlink.
/// The caller decides what an absent file means.
pub(crate) fn open_private(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(READ_FLAGS & !libc::O_RDONLY)
        .open(path)
}

/// Validate an opened state file against `rule` and read at most `maximum`
/// bytes, in one buffer rather than one system call per byte.
pub(crate) fn read_open(
    mut file: File,
    label: &dyn std::fmt::Display,
    maximum: usize,
    rule: FileRule,
) -> Result<Vec<u8>> {
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect {label}"))?;
    let mode = metadata.mode() & 0o7777;
    let owned = metadata.uid() == unsafe { libc::geteuid() };
    let problem = if !metadata.is_file() {
        Some("be a regular file")
    } else {
        match rule {
            FileRule::Regular => None,
            _ if !owned => Some("belong to this user"),
            FileRule::Exact0600 if mode != 0o600 => Some("have mode 0600"),
            FileRule::NoGroupOther if mode & 0o077 != 0 => {
                Some("not be accessible by group or other users")
            }
            FileRule::NoGroupOtherWrite if mode & 0o022 != 0 => {
                Some("not be writable by group or other users")
            }
            _ => None,
        }
    };
    if let Some(problem) = problem {
        bail!("{label} must {problem}");
    }
    let capacity = usize::try_from(metadata.len()).map_or(maximum, |len| len.min(maximum)) + 1;
    let mut contents = Vec::with_capacity(capacity);
    Read::by_ref(&mut file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut contents)
        .with_context(|| format!("read {label}"))?;
    if contents.len() > maximum {
        bail!("{label} exceeds {maximum} bytes");
    }
    Ok(contents)
}

/// Read a state file, or `None` if it does not exist.
pub(crate) fn read_private(
    path: &Path,
    label: &str,
    maximum: usize,
    rule: FileRule,
) -> Result<Option<Vec<u8>>> {
    let file = match open_private(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("open {label} {}", path.display()))
        }
    };
    read_open(
        file,
        &format_args!("{label} {}", path.display()),
        maximum,
        rule,
    )
    .map(Some)
}

/// [`read_private`] for a name in an open directory.
pub(crate) fn read_private_at(
    directory: &File,
    name: &OsStr,
    label: &str,
    maximum: usize,
    rule: FileRule,
) -> Result<Option<Vec<u8>>> {
    let file = match crate::sys::open_at(directory.as_raw_fd(), &leaf(name)?, READ_FLAGS, 0) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("open {label}")),
    };
    read_open(file, &label, maximum, rule).map(Some)
}

/// Which permission bits a private directory may have. Every rule requires
/// a directory of this user's, reached without following a final symlink.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DirRule {
    /// Exactly 0700.
    Exact0700,
    /// No group or other permission bits.
    NoGroupOther,
    /// Remove any group or other permission bits it has.
    Tighten,
}

/// Open a private directory, creating it (only its last component, mode
/// 0700) when `create` is set. Without `create`, `None` means it is absent.
pub(crate) fn open_private_dir(
    path: &Path,
    label: &str,
    create: bool,
    rule: DirRule,
) -> Result<Option<File>> {
    if create {
        use std::os::unix::fs::DirBuilderExt;
        match std::fs::DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error).with_context(|| format!("create {label} {}", path.display()))
            }
        }
    }
    let directory = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NOCTTY | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(directory) => directory,
        Err(error) if !create && error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("open {label} {} (symlinks are refused)", path.display()))
        }
    };
    check_private_dir(&directory, path, label, rule)?;
    Ok(Some(directory))
}

/// Check an open directory against `rule`, as [`open_private_dir`] does.
pub(crate) fn check_private_dir(
    directory: &File,
    path: &Path,
    label: &str,
    rule: DirRule,
) -> Result<()> {
    let metadata = directory
        .metadata()
        .with_context(|| format!("inspect {label} {}", path.display()))?;
    if !metadata.is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
        bail!(
            "{label} {} must belong to this account and not be a symlink",
            path.display()
        );
    }
    let mode = metadata.mode() & 0o777;
    match rule {
        DirRule::Exact0700 if mode != 0o700 => bail!(
            "{label} {} must have mode 0700 (found {mode:04o})",
            path.display()
        ),
        DirRule::NoGroupOther if mode & 0o077 != 0 => bail!(
            "{label} {} must not be accessible by group or other users",
            path.display()
        ),
        DirRule::Tighten if mode & 0o077 != 0 => {
            crate::sys::retry_zero(|| unsafe { libc::fchmod(directory.as_raw_fd(), 0o700) })
                .with_context(|| format!("restrict {label} {}", path.display()))?;
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests;

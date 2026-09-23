//! Public xattrs only. Compression storage and the ACL-owned security attribute
//! are never replayed as user metadata. Wire names follow rsync's user. mapping.
use super::{ExtendedAttributes, MAX_INODE_METADATA};
use anyhow::{ensure, Context, Result};
use std::{
    ffi::CString,
    fs::File,
    io,
    os::{fd::AsRawFd, macos::fs::MetadataExt},
};

const RESOURCE_FORK: &[u8] = b"com.apple.ResourceFork";
const NAME_LIST_LIMIT: usize = 64 * 1024;
fn compressed(file: &File) -> Result<bool> {
    Ok(file.metadata()?.st_flags() & libc::UF_COMPRESSED != 0)
}
fn selected(name: &[u8], compressed: bool) -> bool {
    name != b"com.apple.system.Security"
        && name != b"com.apple.decmpfs"
        && !(compressed && name == RESOURCE_FORK)
}
fn names(file: &File) -> Result<Vec<Vec<u8>>> {
    let size = unsafe { libc::flistxattr(file.as_raw_fd(), std::ptr::null_mut(), 0, 0) };
    if size < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOTSUP) {
            return Ok(Vec::new());
        }
        return Err(error).context("list macOS extended attributes");
    }
    ensure!(
        size as usize <= NAME_LIST_LIMIT,
        "extended attribute names exceed 64 KiB"
    );
    if size == 0 {
        return Ok(Vec::new());
    }
    let mut bytes = vec![0; size as usize];
    let count =
        unsafe { libc::flistxattr(file.as_raw_fd(), bytes.as_mut_ptr().cast(), bytes.len(), 0) };
    if count < 0 {
        return Err(io::Error::last_os_error()).context("read macOS attribute names");
    }
    let mut names = bytes[..count as usize]
        .split(|b| *b == 0)
        .filter(|n| !n.is_empty())
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
    names.sort_unstable();
    Ok(names)
}
fn get(file: &File, name: &[u8]) -> Result<Option<Vec<u8>>> {
    let name = CString::new(name)?;
    let count = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            name.as_ptr(),
            std::ptr::null_mut(),
            0,
            0,
            0,
        )
    };
    if count < 0 {
        let error = io::Error::last_os_error();
        if matches!(error.raw_os_error(), Some(libc::ENOATTR | libc::ENOTSUP)) {
            return Ok(None);
        }
        return Err(error).with_context(|| format!("size attribute {name:?}"));
    }
    ensure!(
        count as usize <= MAX_INODE_METADATA,
        "inode metadata exceeds the 4 MiB transfer limit"
    );
    let mut value = vec![0; count as usize];
    if count != 0 {
        let read = unsafe {
            libc::fgetxattr(
                file.as_raw_fd(),
                name.as_ptr(),
                value.as_mut_ptr().cast(),
                value.len(),
                0,
                0,
            )
        };
        if read < 0 {
            return Err(io::Error::last_os_error())
                .with_context(|| format!("read attribute {name:?}"));
        }
        ensure!(read == count, "attribute changed while reading it");
    }
    Ok(Some(value))
}
fn set(file: &File, name: &[u8], value: Option<&[u8]>) -> Result<()> {
    if get(file, name)?.as_deref() == value {
        return Ok(());
    }
    // A resource fork can be compressed file data. Never replace that storage
    // with a user resource fork during an unchanged-content metadata update.
    ensure!(name != RESOURCE_FORK || !compressed(file)?,
        "cannot change a resource fork on a compressed destination; copy to an uncompressed destination");
    let name = CString::new(name)?;
    let result = match value {
        Some(value) => unsafe {
            libc::fsetxattr(
                file.as_raw_fd(),
                name.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
                0,
            )
        },
        None => unsafe { libc::fremovexattr(file.as_raw_fd(), name.as_ptr(), 0) },
    };
    if result != 0 {
        let error = io::Error::last_os_error();
        if value.is_none() && error.raw_os_error() == Some(libc::ENOATTR) {
            return Ok(());
        }
        return Err(error).with_context(|| format!("reconcile attribute {name:?}"));
    }
    Ok(())
}
pub(super) fn capture(file: &File) -> Result<ExtendedAttributes> {
    let is_compressed = compressed(file)?;
    let mut values = Vec::new();
    let mut size = 64;
    for name in names(file)? {
        if !selected(&name, is_compressed) {
            continue;
        }
        let value =
            get(file, &name)?.context("source attribute disappeared while reading metadata")?;
        let mut wire_name = b"user.".to_vec();
        wire_name.extend(name);
        size += wire_name.len() + value.len() + 32;
        ensure!(
            size <= MAX_INODE_METADATA,
            "inode metadata exceeds the 4 MiB transfer limit"
        );
        values.push((wire_name, value));
    }
    Ok(ExtendedAttributes {
        privileged: false,
        values,
    })
}
pub(super) fn apply(file: &File, attributes: &ExtendedAttributes) -> Result<()> {
    let is_compressed = compressed(file)?;
    let mut previous: Option<&[u8]> = None;
    let mut values = Vec::with_capacity(attributes.values.len());
    for (wire_name, value) in &attributes.values {
        let name = wire_name
            .strip_prefix(b"user.")
            .context("macOS can receive only Linux user.* extended attributes")?;
        ensure!(
            !name.is_empty() && !name.contains(&0) && name.len() <= 127 && selected(name, false),
            "invalid or storage-internal macOS extended attribute"
        );
        ensure!(
            previous.is_none_or(|p| p < wire_name.as_slice()),
            "extended attributes must be unique and ordered"
        );
        previous = Some(wire_name);
        values.push((name, value.as_slice()));
    }
    let mut changes = Vec::new();
    for name in names(file)? {
        if selected(&name, is_compressed)
            && values
                .binary_search_by(|(n, _)| n.cmp(&name.as_slice()))
                .is_err()
        {
            changes.push((name, None));
        }
    }
    for (name, value) in values {
        if get(file, name)?.as_deref() != Some(value) {
            changes.push((name.to_vec(), Some(value)));
        }
    }
    if changes.is_empty() {
        return Ok(());
    }
    let current = file.metadata()?;
    use std::os::unix::fs::MetadataExt;
    let temporary_write = current.mode() & 0o200 == 0
        && current.uid() == unsafe { libc::geteuid() }
        && !current.file_type().is_symlink();
    if temporary_write {
        crate::fsops::set_mode_handle(file, current.mode() & 0o7777 | 0o200)?;
    }
    let result = changes
        .into_iter()
        .try_for_each(|(name, value)| set(file, &name, value));
    if temporary_write {
        crate::fsops::set_mode_handle(file, current.mode() & 0o7777)
            .context("restore permissions after extended attributes")?;
    }
    // Resource-fork writes can change the file's data modification time. The
    // caller has already restored the requested mtime; keep it intact, then
    // let the shared metadata layer restore access/birth times and the ACL.
    let after = file.metadata()?;
    if (after.mtime(), after.mtime_nsec()) != (current.mtime(), current.mtime_nsec()) {
        let times = [
            libc::timespec {
                tv_sec: 0,
                tv_nsec: libc::UTIME_OMIT as _,
            },
            libc::timespec {
                tv_sec: current.mtime(),
                tv_nsec: current.mtime_nsec(),
            },
        ];
        if unsafe { libc::futimens(file.as_raw_fd(), times.as_ptr()) } != 0 {
            return Err(io::Error::last_os_error())
                .context("restore mtime after extended attributes");
        }
    }
    result
}

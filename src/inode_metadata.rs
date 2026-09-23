//! Opt-in inode metadata. Absence means unrequested; an empty selected set
//! means reconciliation, including removal of destination-only values.
#[cfg(target_os = "linux")]
use anyhow::Context;
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::fs::File;

pub(crate) const MAX_INODE_METADATA: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct Selection {
    pub acls: bool,
    pub xattrs: bool,
}

impl Selection {
    pub(crate) fn any(self) -> bool {
        self.acls || self.xattrs
    }
    pub(crate) fn validate(self) -> Result<()> {
        if self.any() && !cfg!(target_os = "linux") {
            bail!("ACL and extended-attribute preservation currently requires Linux endpoints");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct InodeMetadata {
    pub acls: Option<PosixAcls>,
    pub xattrs: Option<ExtendedAttributes>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct PosixAcls {
    pub access: Option<Vec<u8>>,
    pub default: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ExtendedAttributes {
    /// The source's privilege determines the selected namespace set. A root
    /// receiver must not widen a nonroot sender's user.* selection.
    pub privileged: bool,
    pub values: Vec<(Vec<u8>, Vec<u8>)>,
}

impl InodeMetadata {
    /// Resolve chmod-like mapping overrides before comparison and publication.
    /// Invalid wire ACLs are left intact for the application validator to reject.
    pub(crate) fn resolve_mode(&mut self, mode: u32) {
        #[cfg(target_os = "linux")]
        if let Some(access) = self.acls.as_mut().and_then(|a| a.access.as_mut()) {
            if let Ok(resolved) = platform::access_for_mode(access, mode) {
                *access = resolved;
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = mode;
    }
    pub(crate) fn size_hint(&self) -> usize {
        64 + self.acls.as_ref().map_or(0, |a| {
            a.access.as_ref().map_or(0, Vec::len) + a.default.as_ref().map_or(0, Vec::len)
        }) + self.xattrs.as_ref().map_or(0, |x| {
            x.values.iter().map(|(n, v)| n.len() + v.len() + 32).sum()
        })
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use std::{
        ffi::CString,
        io,
        os::{fd::AsRawFd, unix::fs::MetadataExt},
    };
    const ACCESS: &[u8] = b"system.posix_acl_access";
    const DEFAULT: &[u8] = b"system.posix_acl_default";
    const ATTRIBUTE_LIMIT: usize = 65536;

    // Resolving the procfs descriptor link selects the held inode, including
    // O_PATH|O_NOFOLLOW symlink inodes; it never follows their stored target.
    fn handle(file: &File) -> CString {
        CString::new(format!("/proc/self/fd/{}", file.as_raw_fd())).unwrap()
    }
    fn selected(name: &[u8], privileged: bool) -> bool {
        if privileged {
            !name.starts_with(b"system.")
        } else {
            name.starts_with(b"user.")
        }
    }
    fn missing(e: &io::Error) -> bool {
        matches!(e.raw_os_error(), Some(libc::ENODATA | libc::ENOTSUP))
    }
    fn names(file: &File) -> Result<Vec<Vec<u8>>> {
        let path = handle(file);
        let mut bytes = vec![0; ATTRIBUTE_LIMIT];
        let count =
            unsafe { libc::listxattr(path.as_ptr(), bytes.as_mut_ptr().cast(), bytes.len()) };
        if count < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ENOTSUP) {
                return Ok(Vec::new());
            }
            return Err(error).context("list extended attributes");
        }
        bytes.truncate(count as usize);
        let mut names = bytes
            .split(|b| *b == 0)
            .filter(|n| !n.is_empty())
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>();
        names.sort_unstable();
        Ok(names)
    }
    fn get(file: &File, name: &[u8]) -> Result<Option<Vec<u8>>> {
        let path = handle(file);
        let name = CString::new(name)?;
        let mut value = vec![0; ATTRIBUTE_LIMIT];
        let count = unsafe {
            libc::getxattr(
                path.as_ptr(),
                name.as_ptr(),
                value.as_mut_ptr().cast(),
                value.len(),
            )
        };
        if count < 0 {
            let error = io::Error::last_os_error();
            if missing(&error) {
                return Ok(None);
            }
            return Err(error).with_context(|| format!("read attribute {:?}", name));
        }
        value.truncate(count as usize);
        // These values live in the scan plan. Do not retain a 64 KiB read
        // buffer for every tiny ACL or attribute on a large source tree.
        value.shrink_to_fit();
        Ok(Some(value))
    }
    fn set(file: &File, name: &[u8], value: Option<&[u8]>) -> Result<()> {
        // Avoid changing ctime or invoking security hooks for identical values.
        if get(file, name)?.as_deref() == value {
            return Ok(());
        }
        let path = handle(file);
        let name = CString::new(name)?;
        let result = if let Some(value) = value {
            unsafe {
                libc::setxattr(
                    path.as_ptr(),
                    name.as_ptr(),
                    value.as_ptr().cast(),
                    value.len(),
                    0,
                )
            }
        } else {
            unsafe { libc::removexattr(path.as_ptr(), name.as_ptr()) }
        };
        if result != 0 {
            let error = io::Error::last_os_error();
            if value.is_none() && error.raw_os_error() == Some(libc::ENODATA) {
                return Ok(());
            }
            return Err(error).with_context(|| format!("reconcile attribute {:?}", name));
        }
        Ok(())
    }
    pub(super) fn capture(file: &File, selection: Selection) -> Result<InodeMetadata> {
        let before = file.metadata()?;
        let attribute_names = names(file)?;
        if selection.acls
            && attribute_names
                .iter()
                .any(|n| n == b"system.nfs4_acl" || n == b"system.richacl")
        {
            bail!("POSIX ACL preservation cannot represent this filesystem's NFSv4 ACLs");
        }
        let acls = if selection.acls && !before.file_type().is_symlink() {
            Some(PosixAcls {
                access: get(file, ACCESS)?,
                default: if before.is_dir() {
                    get(file, DEFAULT)?
                } else {
                    None
                },
            })
        } else {
            None
        };
        let mut metadata = InodeMetadata { acls, xattrs: None };
        if selection.xattrs {
            let privileged = unsafe { libc::geteuid() == 0 };
            let mut values = Vec::new();
            let mut size = metadata.size_hint();
            for name in attribute_names {
                if !selected(&name, privileged) {
                    continue;
                }
                let value = get(file, &name)?
                    .context("source attribute disappeared while reading metadata")?;
                size += name.len() + value.len() + 32;
                anyhow::ensure!(
                    size <= MAX_INODE_METADATA,
                    "inode metadata exceeds the 4 MiB transfer limit"
                );
                values.push((name, value));
            }
            metadata.xattrs = Some(ExtendedAttributes { privileged, values });
        }
        let after = file.metadata()?;
        anyhow::ensure!(
            (before.ctime(), before.ctime_nsec()) == (after.ctime(), after.ctime_nsec()),
            "inode metadata changed while reading it"
        );
        Ok(metadata)
    }
    pub(super) fn access_for_mode(raw: &[u8], mode: u32) -> Result<Vec<u8>> {
        anyhow::ensure!(
            raw.len() >= 4 && (raw.len() - 4).is_multiple_of(8) && raw[..4] == 2u32.to_le_bytes(),
            "invalid Linux POSIX ACL encoding"
        );
        let mask = raw[4..]
            .chunks_exact(8)
            .any(|e| u16::from_le_bytes([e[0], e[1]]) == 0x10);
        let mut acl = raw.to_vec();
        for entry in acl[4..].chunks_exact_mut(8) {
            let permissions = match u16::from_le_bytes([entry[0], entry[1]]) {
                0x01 => Some((mode >> 6) & 7),
                0x04 if !mask => Some((mode >> 3) & 7),
                0x10 => Some((mode >> 3) & 7),
                0x20 => Some(mode & 7),
                _ => None,
            };
            if let Some(permissions) = permissions {
                entry[2..4].copy_from_slice(&(permissions as u16).to_le_bytes());
            }
        }
        Ok(acl)
    }
    pub(super) fn apply(file: &File, metadata: &InodeMetadata, mode: u32) -> Result<()> {
        anyhow::ensure!(
            metadata.size_hint() <= MAX_INODE_METADATA,
            "inode metadata exceeds the 4 MiB transfer limit"
        );
        let current = file.metadata()?;
        if let Some(acls) = &metadata.acls {
            anyhow::ensure!(
                !current.file_type().is_symlink(),
                "POSIX ACLs cannot be applied to a symlink"
            );
            let access = acls
                .access
                .as_deref()
                .map(|a| access_for_mode(a, mode))
                .transpose()?;
            set(file, ACCESS, access.as_deref())?;
            if current.is_dir() {
                set(file, DEFAULT, acls.default.as_deref())?;
            } else {
                anyhow::ensure!(acls.default.is_none(), "default ACL requires a directory");
            }
        }
        if let Some(attributes) = &metadata.xattrs {
            let mut previous: Option<&[u8]> = None;
            for (name, value) in &attributes.values {
                anyhow::ensure!(
                    selected(name, attributes.privileged)
                        && !name.contains(&0)
                        && name.len() <= 255
                        && value.len() <= ATTRIBUTE_LIMIT,
                    "invalid or excluded extended attribute"
                );
                anyhow::ensure!(
                    previous.is_none_or(|p| p < name.as_slice()),
                    "extended attributes must be unique and ordered"
                );
                previous = Some(name);
            }
            let mut changes: Vec<(Vec<u8>, Option<&[u8]>)> = Vec::new();
            for name in names(file)? {
                if selected(&name, attributes.privileged)
                    && attributes
                        .values
                        .binary_search_by(|(n, _)| n.cmp(&name))
                        .is_err()
                {
                    changes.push((name, None));
                }
            }
            for (name, value) in &attributes.values {
                if get(file, name)?.as_deref() != Some(value) {
                    changes.push((name.clone(), Some(value)));
                }
            }
            if !changes.is_empty() {
                // Linux user.* writes require write permission, even for the
                // owner. Temporarily add only the owner's write bit and always
                // restore it, including after an attribute error. This leaves
                // unselected named ACL entries and the ACL mask intact.
                let current = file.metadata()?;
                let temporary_write =
                    unsafe { libc::geteuid() != 0 && libc::geteuid() == current.uid() }
                        && !current.file_type().is_symlink()
                        && current.mode() & 0o200 == 0;
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
                result?;
            }
            // Privileged writers never need that temporary chmod, so
            // security.capability follows the final mode and ACL restoration.
        }
        Ok(())
    }
}

pub(crate) fn capture(file: &File, selection: Selection) -> Result<Option<Box<InodeMetadata>>> {
    if !selection.any() {
        return Ok(None);
    }
    selection.validate()?;
    #[cfg(target_os = "linux")]
    {
        platform::capture(file, selection).map(|m| Some(Box::new(m)))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = file;
        unreachable!()
    }
}
pub(crate) fn apply(file: &File, metadata: Option<&InodeMetadata>, mode: u32) -> Result<()> {
    let Some(metadata) = metadata else {
        return Ok(());
    };
    anyhow::ensure!(
        metadata.size_hint() <= MAX_INODE_METADATA,
        "inode metadata exceeds the 4 MiB transfer limit"
    );
    #[cfg(target_os = "linux")]
    {
        platform::apply(file, metadata, mode)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (file, metadata, mode);
        bail!("Linux inode metadata cannot be applied on this platform")
    }
}

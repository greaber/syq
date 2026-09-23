//! Opt-in inode metadata. Absence means unrequested; an empty selected set
//! means reconciliation, including removal of destination-only values.
use anyhow::Context;
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::fs::File;

pub(crate) const MAX_INODE_METADATA: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct Selection {
    pub acls: bool,
    pub xattrs: bool,
    pub atimes: bool,
    pub crtimes: bool,
    pub open_noatime: bool,
}

impl Selection {
    pub(crate) fn any(self) -> bool {
        self.acls || self.xattrs || self.atimes || self.crtimes
    }
    pub(crate) fn validate_destination(self) -> Result<()> {
        self.validate()?;
        anyhow::ensure!(!self.crtimes || cfg!(target_os = "macos"), "birth-time preservation requires a macOS destination; this platform cannot set arbitrary birth times");
        Ok(())
    }
    pub(crate) fn validate(self) -> Result<()> {
        if (self.acls || self.xattrs) && !cfg!(target_os = "linux") {
            bail!("ACL and extended-attribute preservation currently requires Linux endpoints");
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct Timestamp {
    pub seconds: i64,
    pub nanoseconds: u32,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct InodeMetadata {
    pub acls: Option<PosixAcls>,
    pub xattrs: Option<ExtendedAttributes>,
    pub atime: Option<Timestamp>,
    pub crtime: Option<Timestamp>,
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
    // Most listings and ACL values are tiny. Avoid allocating and zeroing the
    // Linux maximum for every lookup; retry large values at the fixed limit.
    fn read_bytes(mut read: impl FnMut(*mut libc::c_void, usize) -> isize) -> io::Result<Vec<u8>> {
        let mut small = [0u8; 256];
        let count = read(small.as_mut_ptr().cast(), small.len());
        if count >= 0 {
            return Ok(small[..count as usize].to_vec());
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ERANGE) {
            return Err(error);
        }
        let mut bytes = Vec::<u8>::with_capacity(ATTRIBUTE_LIMIT);
        let count = read(bytes.as_mut_ptr().cast(), ATTRIBUTE_LIMIT);
        if count < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: listxattr/getxattr initialize exactly the returned byte count
        // on success, bounded by the supplied buffer length.
        unsafe { bytes.set_len(count as usize) };
        // Captured values live in the scan plan; retain only their actual size.
        bytes.shrink_to_fit();
        Ok(bytes)
    }
    fn names(file: &File) -> Result<Vec<Vec<u8>>> {
        let path = handle(file);
        let bytes = match read_bytes(|buffer, len| unsafe {
            libc::listxattr(path.as_ptr(), buffer.cast(), len)
        }) {
            Ok(bytes) => bytes,
            Err(error) if error.raw_os_error() == Some(libc::ENOTSUP) => return Ok(Vec::new()),
            Err(error) => return Err(error).context("list extended attributes"),
        };
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
        match read_bytes(|buffer, len| unsafe {
            libc::getxattr(path.as_ptr(), name.as_ptr(), buffer, len)
        }) {
            Ok(value) => Ok(Some(value)),
            Err(error) if missing(&error) => Ok(None),
            Err(error) => Err(error).with_context(|| format!("read attribute {:?}", name)),
        }
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
                access: if attribute_names.iter().any(|name| name == ACCESS) {
                    get(file, ACCESS)?
                } else {
                    None
                },
                default: if before.is_dir() && attribute_names.iter().any(|name| name == DEFAULT) {
                    get(file, DEFAULT)?
                } else {
                    None
                },
            })
        } else {
            None
        };
        let mut metadata = InodeMetadata {
            acls,
            ..Default::default()
        };
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

pub(crate) fn capture(
    file: &File,
    selection: Selection,
    atime: Timestamp,
) -> Result<Option<Box<InodeMetadata>>> {
    if !selection.any() {
        return Ok(None);
    }
    selection.validate()?;
    let mut metadata = InodeMetadata::default();
    if selection.acls || selection.xattrs {
        #[cfg(target_os = "linux")]
        {
            metadata = platform::capture(file, selection)?;
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = file;
            unreachable!();
        }
    }
    metadata.atime = selection.atimes.then_some(atime);
    if selection.crtimes {
        metadata.crtime = Some(Timestamp::from_system_time(
            file.metadata()?
                .created()
                .context("source filesystem does not report birth time")?,
        )?);
    }
    Ok(Some(Box::new(metadata)))
}
pub(crate) fn apply(file: &File, metadata: Option<&InodeMetadata>, mode: u32) -> Result<()> {
    let Some(metadata) = metadata else {
        return Ok(());
    };
    anyhow::ensure!(
        metadata.size_hint() <= MAX_INODE_METADATA,
        "inode metadata exceeds the 4 MiB transfer limit"
    );
    anyhow::ensure!(
        metadata.crtime.is_none() || cfg!(target_os = "macos"),
        "birth-time preservation requires a macOS destination"
    );
    #[cfg(target_os = "linux")]
    {
        if metadata.acls.is_some() || metadata.xattrs.is_some() {
            platform::apply(file, metadata, mode)?;
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = mode;
        anyhow::ensure!(
            metadata.acls.is_none() && metadata.xattrs.is_none(),
            "Linux inode metadata cannot be applied on this platform"
        );
    }
    if let Some(atime) = metadata.atime {
        use std::os::{fd::AsRawFd, unix::fs::MetadataExt};
        anyhow::ensure!(
            atime.nanoseconds < 1_000_000_000,
            "invalid access-time nanoseconds"
        );
        let current = file.metadata()?;
        if (current.atime(), current.atime_nsec() as u32) != (atime.seconds, atime.nanoseconds) {
            let times = [
                libc::timespec {
                    tv_sec: atime.seconds as _,
                    tv_nsec: atime.nanoseconds as _,
                },
                libc::timespec {
                    tv_sec: 0,
                    tv_nsec: libc::UTIME_OMIT as _,
                },
            ];
            #[cfg(target_os = "linux")]
            let result = unsafe {
                libc::utimensat(
                    file.as_raw_fd(),
                    c"".as_ptr(),
                    times.as_ptr(),
                    libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            #[cfg(not(target_os = "linux"))]
            let result = unsafe { libc::futimens(file.as_raw_fd(), times.as_ptr()) };
            if result != 0 {
                return Err(std::io::Error::last_os_error())
                    .context("restore access time on held inode");
            }
        }
    }
    if let Some(crtime) = metadata.crtime {
        anyhow::ensure!(
            crtime.nanoseconds < 1_000_000_000,
            "invalid birth-time nanoseconds"
        );
        #[cfg(target_os = "macos")]
        {
            use std::os::fd::AsRawFd;
            let current = Timestamp::from_system_time(file.metadata()?.created()?)?;
            if current != crtime {
                let mut attributes = libc::attrlist {
                    bitmapcount: libc::ATTR_BIT_MAP_COUNT as _,
                    reserved: 0,
                    commonattr: libc::ATTR_CMN_CRTIME,
                    volattr: 0,
                    dirattr: 0,
                    fileattr: 0,
                    forkattr: 0,
                };
                let mut time = libc::timespec {
                    tv_sec: crtime.seconds as _,
                    tv_nsec: crtime.nanoseconds as _,
                };
                if unsafe {
                    libc::fsetattrlist(
                        file.as_raw_fd(),
                        (&mut attributes as *mut libc::attrlist).cast(),
                        (&mut time as *mut libc::timespec).cast(),
                        std::mem::size_of_val(&time),
                        0,
                    )
                } != 0
                {
                    return Err(std::io::Error::last_os_error())
                        .context("restore birth time on held inode");
                }
            }
        }
    }
    Ok(())
}

impl Timestamp {
    fn from_system_time(time: std::time::SystemTime) -> Result<Self> {
        match time.duration_since(std::time::UNIX_EPOCH) {
            Ok(duration) => Ok(Self {
                seconds: i64::try_from(duration.as_secs())?,
                nanoseconds: duration.subsec_nanos(),
            }),
            Err(error) => {
                let duration = error.duration();
                let seconds = i64::try_from(duration.as_secs())?
                    .checked_neg()
                    .context("birth time out of range")?;
                if duration.subsec_nanos() == 0 {
                    Ok(Self {
                        seconds,
                        nanoseconds: 0,
                    })
                } else {
                    Ok(Self {
                        seconds: seconds.checked_sub(1).context("birth time out of range")?,
                        nanoseconds: 1_000_000_000 - duration.subsec_nanos(),
                    })
                }
            }
        }
    }
}

/// Best-effort read policy, applied before the first data access. Changing the
/// status flags keeps the already-confined descriptor and never reopens a path.
pub(crate) fn prepare_read(file: &File, requested: bool) {
    if !requested {
        return;
    }
    #[cfg(target_os = "linux")]
    let error = {
        use std::os::fd::AsRawFd;
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        if flags >= 0
            && unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NOATIME) } == 0
        {
            return;
        }
        std::io::Error::last_os_error().to_string()
    };
    #[cfg(not(target_os = "linux"))]
    let error = {
        let _ = file;
        "not supported on this platform".to_string()
    };
    static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        crate::output::diagnostic!("syq: warning: --open-noatime unavailable ({error}); reads may update source access times");
    }
}

#[cfg(test)]
mod timestamp_tests {
    use super::*;

    #[test]
    fn birth_time_capture_uses_the_filesystems_creation_time() {
        let temporary = crate::test_support::tempdir().unwrap();
        let file = File::create(temporary.path().join("file")).unwrap();
        let observed = file.metadata().unwrap().created();
        let result = capture(
            &file,
            Selection {
                crtimes: true,
                ..Default::default()
            },
            Timestamp::default(),
        );
        match observed {
            Ok(created) => assert_eq!(
                result.unwrap().unwrap().crtime,
                Some(Timestamp::from_system_time(created).unwrap())
            ),
            Err(_) => {
                assert!(format!("{:#}", result.unwrap_err()).contains("does not report birth time"))
            }
        }
    }

    #[test]
    fn pre_epoch_birth_times_keep_the_fraction_positive() {
        let time = std::time::UNIX_EPOCH - std::time::Duration::new(2, 123_456_789);
        assert_eq!(
            Timestamp::from_system_time(time).unwrap(),
            Timestamp {
                seconds: -3,
                nanoseconds: 876_543_211
            }
        );
        assert_eq!(
            Timestamp::from_system_time(std::time::UNIX_EPOCH).unwrap(),
            Timestamp::default()
        );
    }
}

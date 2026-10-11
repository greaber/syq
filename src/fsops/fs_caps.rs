//! What a destination filesystem's own reports can be trusted for: link
//! counts and inode numbers, the atomic renames a macOS volume supports,
//! whether setting a symlink's times might reach its target instead, and
//! FAT's two-second modification times.
//!
//! Each answer comes from facts syq already reads cheaply (the filesystem
//! type, mount options, macOS volume capabilities) and is cached per mount
//! or volume. Where these facts are unknown, the answers keep syq's checks:
//! counts count as trustworthy and no rename flag counts as supported.

use std::fs::File;
#[cfg(target_os = "macos")]
use std::os::fd::RawFd;

#[cfg(target_os = "linux")]
use super::FileSystemKey;

/// exFAT's filesystem type, which libc does not name.
#[cfg(target_os = "linux")]
const EXFAT_SUPER_MAGIC: u32 = 0x2011_bab0;

/// Whether this filesystem reports link counts and inode numbers that syq
/// can rely on: two names of one file show the same inode number and a
/// count that includes both, and a number stays with its file.
///
/// SSHFS and rclone report one link for every name, and give each name of
/// a file its own number (SFTP carries neither); other FUSE filesystems may
/// do the same. FAT and exFAT have no hard links, and their inode numbers
/// are not kept for a file. An SMB mount that has stopped using the
/// server's file IDs (`noserverino`) makes numbers up per name.
///
/// Checks that compare counts or numbers right after linking are skipped
/// where this is false. Rules that rely on a count to find a file's other
/// names, such as a restricted receiver's limit on files that may have
/// names outside its approved directories, must instead assume any file
/// may have them. The answer covers the filesystem `file` is on.
pub(crate) fn link_counts_trusted(file: &File) -> bool {
    #[cfg(debug_assertions)]
    if std::env::var_os("SYQ_TEST_UNTRUSTED_LINK_COUNTS").is_some() {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        super::opened_file_system(file).map_or(true, |(_, traits)| !traits.untrusted_link_counts)
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsRawFd;
        volume_capabilities(file.as_raw_fd())
            .is_none_or(|volume| volume.hard_links && volume.persistent_ids)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = file;
        true
    }
}

/// Linux: whether a filesystem of this type gives each name its own inode
/// number or a link count that misses other names.
#[cfg(target_os = "linux")]
pub(super) fn linux_link_counts_untrusted(
    file_system_type: u32,
    file: &File,
    key: FileSystemKey,
) -> bool {
    match file_system_type {
        t if t == libc::FUSE_SUPER_MAGIC as u32
            || t == libc::MSDOS_SUPER_MAGIC as u32
            || t == EXFAT_SUPER_MAGIC =>
        {
            true
        }
        0xfe53_4d42 | 0xff53_4d42 => smb_without_server_inode_numbers(file, key),
        t if t == libc::SMB_SUPER_MAGIC as u32 => smb_without_server_inode_numbers(file, key),
        _ => false,
    }
}

/// The name syq reports for a filesystem type it treats specially but has
/// no tuning label for. FAT keeps modification times in two-second steps;
/// exFAT keeps 10 ms, which the ordinary comparison of significant digits
/// already covers.
#[cfg(target_os = "linux")]
pub(super) fn linux_kind(file_system_type: u32) -> Option<&'static str> {
    if file_system_type == libc::MSDOS_SUPER_MAGIC as u32 {
        Some(FAT_KIND)
    } else if file_system_type == EXFAT_SUPER_MAGIC {
        Some("exfat")
    } else {
        None
    }
}

/// The filesystem kind a Linux receiver reports for FAT (vfat or msdos).
pub(crate) const FAT_KIND: &str = "fat";

/// Whether a destination of this reported kind keeps modification times
/// in two-second steps: Linux FAT, or a macOS `msdos` volume.
pub(crate) fn kind_has_two_second_mtimes(kind: &str) -> bool {
    kind == FAT_KIND || kind == "msdos"
}

#[cfg(target_os = "linux")]
fn smb_without_server_inode_numbers(file: &File, key: FileSystemKey) -> bool {
    let mount = match key {
        FileSystemKey::Mount(id) => Some(id),
        FileSystemKey::Device(_) => super::btrfs::fdinfo_mount_id(file),
    };
    let Some(mount) = mount else {
        return false;
    };
    std::fs::read("/proc/self/mountinfo")
        .ok()
        .and_then(|mounts| super_options(&mounts, mount).map(|options| options.to_vec()))
        .is_some_and(|options| {
            options
                .split(|byte| *byte == b',')
                .any(|option| option == b"noserverino")
        })
}

/// The superblock options of one mount in `/proc/self/mountinfo`.
#[cfg(target_os = "linux")]
fn super_options(mounts: &[u8], mount: u64) -> Option<&[u8]> {
    for line in mounts.split(|byte| *byte == b'\n') {
        let mut fields = line.split(|byte| byte.is_ascii_whitespace());
        let id = fields
            .next()
            .and_then(|id| std::str::from_utf8(id).ok())
            .and_then(|id| id.parse::<u64>().ok());
        if id != Some(mount) || !fields.any(|field| field == b"-") {
            continue;
        }
        fields.next(); // filesystem type
        fields.next(); // mount source
        return fields.next();
    }
    None
}

/// Whether setting a symlink's times on this filesystem might reach the
/// link's target: true for network filesystems, whose servers may follow
/// the link (an SFTP server does). Local filesystems set the link itself.
pub(crate) fn symlink_times_may_follow(file: &File, dev: u64) -> bool {
    #[cfg(debug_assertions)]
    if std::env::var_os("SYQ_TEST_SYMLINK_TIMES_FOLLOW").is_some() {
        return true;
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsRawFd;
        let _ = dev;
        let mut stats = std::mem::MaybeUninit::<libc::statfs>::zeroed();
        // SAFETY: fstatfs writes only into the local structure.
        if unsafe { libc::fstatfs(file.as_raw_fd(), stats.as_mut_ptr()) } != 0 {
            return true;
        }
        let stats = unsafe { stats.assume_init() };
        stats.f_flags & libc::MNT_LOCAL as u32 == 0
    }
    #[cfg(not(target_os = "macos"))]
    {
        super::on_network_file_system(file, dev)
    }
}

/// The atomic renames and identity reports a macOS volume advertises.
#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct VolumeCapabilities {
    /// `renameatx_np(RENAME_SWAP)` exchanges the two names. A FAT32 volume
    /// that does not advertise it completes such a call as a plain rename
    /// over the target, so it must not be called there.
    pub(crate) rename_swap: bool,
    /// `renameatx_np(RENAME_EXCL)` refuses an existing target atomically.
    pub(crate) rename_exclusive: bool,
    pub(crate) hard_links: bool,
    pub(crate) persistent_ids: bool,
}

/// The capabilities of the volume holding `fd`, cached per mount point.
/// None when they cannot be read.
#[cfg(target_os = "macos")]
pub(crate) fn volume_capabilities(fd: RawFd) -> Option<VolumeCapabilities> {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    static VOLUMES: OnceLock<Mutex<HashMap<Vec<u8>, Option<VolumeCapabilities>>>> = OnceLock::new();
    let mut stats = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    // SAFETY: fstatfs writes only into the local structure.
    if unsafe { libc::fstatfs(fd, stats.as_mut_ptr()) } != 0 {
        return None;
    }
    let stats = unsafe { stats.assume_init() };
    // SAFETY: fstatfs NUL-terminates the mount point.
    let mount = unsafe { std::ffi::CStr::from_ptr(stats.f_mntonname.as_ptr()) };
    let volumes = VOLUMES.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(known) = volumes.lock().unwrap().get(mount.to_bytes()) {
        return *known;
    }
    let capabilities = read_volume_capabilities(mount);
    volumes
        .lock()
        .unwrap()
        .insert(mount.to_bytes().to_vec(), capabilities);
    capabilities
}

/// Volume attributes are only answered for a volume's mount point.
#[cfg(target_os = "macos")]
fn read_volume_capabilities(mount: &std::ffi::CStr) -> Option<VolumeCapabilities> {
    #[repr(C)]
    struct Reply {
        length: u32,
        capabilities: libc::vol_capabilities_attr_t,
    }
    let mut request = libc::attrlist {
        bitmapcount: libc::ATTR_BIT_MAP_COUNT,
        reserved: 0,
        commonattr: 0,
        volattr: libc::ATTR_VOL_INFO | libc::ATTR_VOL_CAPABILITIES,
        dirattr: 0,
        fileattr: 0,
        forkattr: 0,
    };
    let mut reply = std::mem::MaybeUninit::<Reply>::zeroed();
    // SAFETY: the request and reply buffers are live and correctly sized.
    let result = unsafe {
        libc::getattrlist(
            mount.as_ptr(),
            (&mut request as *mut libc::attrlist).cast(),
            reply.as_mut_ptr().cast(),
            std::mem::size_of::<Reply>(),
            0,
        )
    };
    if result != 0 {
        return None;
    }
    let reply = unsafe { reply.assume_init() };
    let has = |set: usize, bit: u32| {
        reply.capabilities.valid[set] & bit != 0 && reply.capabilities.capabilities[set] & bit != 0
    };
    Some(VolumeCapabilities {
        rename_swap: has(
            libc::VOL_CAPABILITIES_INTERFACES,
            libc::VOL_CAP_INT_RENAME_SWAP,
        ),
        rename_exclusive: has(
            libc::VOL_CAPABILITIES_INTERFACES,
            libc::VOL_CAP_INT_RENAME_EXCL,
        ),
        hard_links: has(libc::VOL_CAPABILITIES_FORMAT, libc::VOL_CAP_FMT_HARDLINKS),
        persistent_ids: has(
            libc::VOL_CAPABILITIES_FORMAT,
            libc::VOL_CAP_FMT_PERSISTENTOBJECTIDS,
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_second_mtimes_belong_to_fat_kinds_only() {
        assert!(kind_has_two_second_mtimes(FAT_KIND));
        assert!(kind_has_two_second_mtimes("msdos"));
        for kind in ["exfat", "ext", "apfs", "hfs", "other", "nfs"] {
            assert!(!kind_has_two_second_mtimes(kind), "{kind}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mount_super_options_are_found_by_mount_id() {
        let mounts = b"11 1 8:1 / / rw - ext4 /dev/a rw\n\
22 1 0:42 / /mnt/share rw shared:1 - cifs //server/share rw,vers=3.1.1,noserverino\n\
23 1 0:43 / /mnt/other\\040share rw - smb3 //server/other rw,vers=3.1.1,serverino\n";
        assert_eq!(
            super_options(mounts, 22),
            Some(&b"rw,vers=3.1.1,noserverino"[..])
        );
        assert_eq!(
            super_options(mounts, 23),
            Some(&b"rw,vers=3.1.1,serverino"[..])
        );
        assert_eq!(super_options(mounts, 99), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn local_test_filesystems_report_trusted_link_counts() {
        let directory = crate::test_support::tempdir().unwrap();
        let file = File::open(directory.path()).unwrap();
        // The test directory may be on any local filesystem; none of the
        // ones syq is tested on gives names their own inode numbers.
        if std::env::var_os("SYQ_TEST_UNTRUSTED_LINK_COUNTS").is_none() {
            assert!(link_counts_trusted(&file));
        }
        assert_eq!(linux_kind(libc::MSDOS_SUPER_MAGIC as u32), Some(FAT_KIND));
        assert_eq!(linux_kind(EXFAT_SUPER_MAGIC), Some("exfat"));
        assert_eq!(linux_kind(libc::EXT4_SUPER_MAGIC as u32), None);
    }
}

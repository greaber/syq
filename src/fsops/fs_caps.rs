//! What syq relies on a destination filesystem for, as one profile per
//! filesystem.
//!
//! There is no end to unusual filesystems, so syq does not assume good
//! semantics. A filesystem type whose behavior was verified gets the
//! capabilities it was found to have; every other type, including any syq
//! cannot identify, gets the conservative profile. Each conservative choice
//! is correct on every filesystem, only slower or less complete where the
//! capability exists: matched replacement moves the old entry aside instead
//! of exchanging, publication without replacing uses its fallback chain,
//! checks that rely on link counts or inode numbers are not trusted, and
//! symlink times are left alone.
//!
//! The profile comes from facts syq already reads cheaply: the filesystem
//! type, mount options, and on macOS the capabilities a volume advertises.
//! It is cached per mount or volume. Nothing is probed.

use std::fs::File;
#[cfg(target_os = "macos")]
use std::os::fd::RawFd;

#[cfg(target_os = "linux")]
use super::FileSystemKey;

/// exFAT's filesystem type, which libc does not name.
#[cfg(target_os = "linux")]
const EXFAT_SUPER_MAGIC: u32 = 0x2011_bab0;
/// ZFS's filesystem type, which libc does not name.
#[cfg(target_os = "linux")]
const ZFS_SUPER_MAGIC: u32 = 0x2fc1_2fc1;

/// What syq may rely on a filesystem for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Profile {
    /// Matched replacement first tries an atomic exchange
    /// (`RENAME_EXCHANGE`, macOS `RENAME_SWAP`). Otherwise it moves the old
    /// entry aside, checks it, then publishes without replacing.
    pub(crate) exchange: bool,
    /// A no-replace rename (`RENAME_NOREPLACE`, macOS `RENAME_EXCL`) is
    /// atomic here, so publication without replacing starts with it. A
    /// network filesystem may check the target in the client and then tell
    /// its server to replace (SMB), or ignore the flag (an rclone mount
    /// mode).
    pub(crate) atomic_no_replace_rename: bool,
    /// Hard links may exist, so publication without replacing tries one
    /// before its final check-then-rename.
    pub(crate) hard_links: bool,
    /// Two names of one file show the same inode number and a link count
    /// that includes both, and a number stays with its file. SSHFS and
    /// rclone report one link for every name and give each name its own
    /// number; FAT and exFAT keep no numbers for files; an SMB mount without
    /// the server's file IDs (`noserverino`) makes them up per name.
    ///
    /// Where this is false, checks that compare counts or numbers are not
    /// made, nothing is skipped because two names seem to be one file, and
    /// leftover staging files are not reused. A rule that relies on a count
    /// to find a file's other names (a restricted receiver's limit on files
    /// that may have names outside its approved directories) must assume
    /// any file may have them.
    pub(crate) link_counts_trusted: bool,
    /// Setting a symlink's times with `AT_SYMLINK_NOFOLLOW` sets the link's
    /// own. An SFTP server behind SSHFS follows the link and sets the
    /// target's instead, so symlink times are only set where this is known.
    pub(crate) symlink_times: bool,
    /// Modification times are kept in two-second steps (FAT).
    pub(crate) two_second_mtimes: bool,
}

impl Default for Profile {
    fn default() -> Self {
        Self::CONSERVATIVE
    }
}

impl Profile {
    /// For filesystems whose behavior is not known.
    pub(crate) const CONSERVATIVE: Self = Self {
        exchange: false,
        atomic_no_replace_rename: false,
        hard_links: true,
        link_counts_trusted: false,
        symlink_times: false,
        two_second_mtimes: false,
    };

    /// Local POSIX filesystems verified to support all of it: ext2/3/4,
    /// XFS, btrfs, tmpfs, ZFS (exchange since 2.2; an older one refuses it,
    /// and the refusal is remembered), overlayfs, APFS.
    const LOCAL: Self = Self {
        exchange: true,
        atomic_no_replace_rename: true,
        hard_links: true,
        link_counts_trusted: true,
        symlink_times: true,
        two_second_mtimes: false,
    };

    /// Tests stand in for filesystems that lack these capabilities.
    fn with_test_overrides(self) -> Self {
        #[cfg(debug_assertions)]
        {
            let set = |name| std::env::var_os(name).is_some();
            if set("SYQ_TEST_CONSERVATIVE_FILESYSTEM") {
                return Self::CONSERVATIVE;
            }
            let mut profile = self;
            if set("SYQ_TEST_NO_RENAME_EXCHANGE") {
                profile.exchange = false;
            }
            if set("SYQ_TEST_NO_RENAME_NOREPLACE") {
                profile.atomic_no_replace_rename = false;
            }
            if set("SYQ_TEST_NO_HARD_LINKS") {
                profile.hard_links = false;
            }
            if set("SYQ_TEST_UNTRUSTED_LINK_COUNTS") {
                profile.link_counts_trusted = false;
            }
            if set("SYQ_TEST_SYMLINK_TIMES_FOLLOW") {
                profile.symlink_times = false;
            }
            profile
        }
        #[cfg(not(debug_assertions))]
        self
    }
}

/// The profile of the filesystem `file` is on.
pub(crate) fn profile(file: &File) -> Profile {
    #[cfg(target_os = "linux")]
    let profile =
        super::opened_file_system(file).map_or(Profile::CONSERVATIVE, |(_, traits)| traits.profile);
    #[cfg(target_os = "macos")]
    let profile = {
        use std::os::fd::AsRawFd;
        macos_profile(file.as_raw_fd())
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let profile = {
        let _ = file;
        Profile::CONSERVATIVE
    };
    profile.with_test_overrides()
}

/// Linux: the profile for a filesystem type, from the type syq already
/// reads and, for SMB, the mount's options.
#[cfg(target_os = "linux")]
pub(super) fn linux_profile(file_system_type: u32, file: &File, key: FileSystemKey) -> Profile {
    match file_system_type {
        t if t == libc::EXT4_SUPER_MAGIC as u32
            || t == libc::XFS_SUPER_MAGIC as u32
            || t == libc::BTRFS_SUPER_MAGIC as u32
            || t == libc::TMPFS_MAGIC as u32
            || t == libc::OVERLAYFS_SUPER_MAGIC as u32
            || t == ZFS_SUPER_MAGIC =>
        {
            Profile::LOCAL
        }
        // The server keeps link counts and file IDs, and sets attributes on
        // the object a handle names, never following a symlink.
        t if t == libc::NFS_SUPER_MAGIC as u32 => Profile {
            exchange: false,
            atomic_no_replace_rename: false,
            hard_links: true,
            link_counts_trusted: true,
            symlink_times: true,
            two_second_mtimes: false,
        },
        0xfe53_4d42 | 0xff53_4d42 => Profile {
            exchange: false,
            atomic_no_replace_rename: false,
            hard_links: true,
            link_counts_trusted: !smb_without_server_inode_numbers(file, key),
            symlink_times: false,
            two_second_mtimes: false,
        },
        // The kernel checks the target of a no-replace rename itself, under
        // the directory lock, so on these local filesystems it is atomic.
        t if t == libc::MSDOS_SUPER_MAGIC as u32 => Profile {
            exchange: false,
            atomic_no_replace_rename: true,
            hard_links: false,
            link_counts_trusted: false,
            symlink_times: false,
            two_second_mtimes: true,
        },
        EXFAT_SUPER_MAGIC => Profile {
            exchange: false,
            atomic_no_replace_rename: true,
            hard_links: false,
            link_counts_trusted: false,
            symlink_times: false,
            two_second_mtimes: false,
        },
        // FUSE (SSHFS, rclone and any other server), SMB1, Ceph, 9p, NTFS
        // and every type not verified.
        _ => Profile::CONSERVATIVE,
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
/// in two-second steps: Linux FAT, or a macOS `msdos` volume. The
/// coordinator compares times by the kind its receiver reports.
pub(crate) fn kind_has_two_second_mtimes(kind: &str) -> bool {
    kind == FAT_KIND || kind == "msdos"
}

#[cfg(target_os = "linux")]
fn smb_without_server_inode_numbers(file: &File, key: FileSystemKey) -> bool {
    let mount = match key {
        FileSystemKey::Mount(id) => Some(id),
        FileSystemKey::Device(_) => super::btrfs::fdinfo_mount_id(file),
    };
    // Unknown options count as made-up numbers.
    let Some(mount) = mount else {
        return true;
    };
    std::fs::read("/proc/self/mountinfo")
        .ok()
        .and_then(|mounts| super_options(&mounts, mount).map(|options| options.to_vec()))
        .is_none_or(|options| {
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

/// macOS: the profile of the volume holding `fd`, from the capabilities it
/// advertises, cached per mount point. A capability a volume was seen to
/// violate does not count: FAT32 (`msdos`) completes `RENAME_SWAP` as a
/// plain rename over the target and reports success. It does not
/// advertise the capability, but it is excluded by name as well.
#[cfg(target_os = "macos")]
pub(crate) fn macos_profile(fd: RawFd) -> Profile {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    static VOLUMES: OnceLock<Mutex<HashMap<Vec<u8>, Profile>>> = OnceLock::new();
    let mut stats = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    // SAFETY: fstatfs writes only into the local structure.
    if unsafe { libc::fstatfs(fd, stats.as_mut_ptr()) } != 0 {
        return Profile::CONSERVATIVE;
    }
    let stats = unsafe { stats.assume_init() };
    // SAFETY: fstatfs NUL-terminates both names.
    let mount = unsafe { std::ffi::CStr::from_ptr(stats.f_mntonname.as_ptr()) };
    let kind = unsafe { std::ffi::CStr::from_ptr(stats.f_fstypename.as_ptr()) }.to_bytes();
    let volumes = VOLUMES.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(known) = volumes.lock().unwrap().get(mount.to_bytes()) {
        return *known;
    }
    let profile = match read_volume_capabilities(mount) {
        None => Profile::CONSERVATIVE,
        Some(volume) => Profile {
            exchange: volume.rename_swap && kind != b"msdos",
            atomic_no_replace_rename: volume.rename_exclusive,
            hard_links: volume.hard_links,
            link_counts_trusted: volume.hard_links && volume.persistent_ids,
            // Verified on these volumes; FAT and exFAT keep symlinks as
            // small files, whose own times are set.
            symlink_times: matches!(kind, b"apfs" | b"hfs" | b"msdos" | b"exfat"),
            two_second_mtimes: kind == b"msdos",
        },
    };
    volumes
        .lock()
        .unwrap()
        .insert(mount.to_bytes().to_vec(), profile);
    profile
}

/// The atomic renames and identity reports a macOS volume advertises.
#[cfg(target_os = "macos")]
struct VolumeCapabilities {
    rename_swap: bool,
    rename_exclusive: bool,
    hard_links: bool,
    persistent_ids: bool,
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

    /// The conservative choices are the safe side of every capability.
    #[test]
    fn the_conservative_profile_assumes_nothing() {
        let profile = Profile::CONSERVATIVE;
        assert!(!profile.exchange);
        assert!(!profile.atomic_no_replace_rename);
        assert!(!profile.link_counts_trusted);
        assert!(!profile.symlink_times);
        assert!(!profile.two_second_mtimes);
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
    fn verified_types_get_their_profiles_and_others_the_conservative_one() {
        let directory = crate::test_support::tempdir().unwrap();
        let file = File::open(directory.path()).unwrap();
        let key = FileSystemKey::Device(0);
        for local in [
            libc::EXT4_SUPER_MAGIC as u32,
            libc::XFS_SUPER_MAGIC as u32,
            libc::BTRFS_SUPER_MAGIC as u32,
            libc::TMPFS_MAGIC as u32,
            ZFS_SUPER_MAGIC,
        ] {
            assert_eq!(linux_profile(local, &file, key), Profile::LOCAL);
        }
        let nfs = linux_profile(libc::NFS_SUPER_MAGIC as u32, &file, key);
        assert!(!nfs.exchange && nfs.link_counts_trusted && nfs.symlink_times);
        let fat = linux_profile(libc::MSDOS_SUPER_MAGIC as u32, &file, key);
        assert!(fat.two_second_mtimes && !fat.hard_links && fat.atomic_no_replace_rename);
        for unknown in [libc::FUSE_SUPER_MAGIC as u32, 0x5346_544e, 0x0102_1997] {
            assert_eq!(
                linux_profile(unknown, &file, key),
                Profile::CONSERVATIVE,
                "{unknown:x}"
            );
        }
        assert_eq!(linux_kind(libc::MSDOS_SUPER_MAGIC as u32), Some(FAT_KIND));
        assert_eq!(linux_kind(EXFAT_SUPER_MAGIC), Some("exfat"));
        assert_eq!(linux_kind(libc::EXT4_SUPER_MAGIC as u32), None);
    }
}

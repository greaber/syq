//! What syq relies on a destination filesystem for, as one profile per
//! filesystem.
//!
//! There is no end to unusual filesystems, so syq trusts a capability only
//! where a test, source code or authoritative documentation shows it, and
//! is conservative elsewhere. Each conservative choice is correct on every
//! filesystem, only slower or less complete where the capability exists.
//!
//! - Atomic rename flags are tried where a filesystem that lacks them is
//!   known to refuse them: the Linux in-tree filesystems below, whose
//!   rename handlers reject flags they do not implement, and macOS volumes
//!   that advertise them. A refusal falls back and is remembered. FUSE
//!   passes the flags to a userspace server, which could ignore them, so
//!   they are not tried there, nor on types not audited.
//! - Link counts, inode numbers and symlink times cannot be checked by
//!   their errors, so they are trusted only on filesystems with evidence.
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
/// ntfs3's filesystem type ("ntfs").
#[cfg(target_os = "linux")]
const NTFS3_SUPER_MAGIC: u32 = 0x7366_746e;
#[cfg(target_os = "linux")]
const F2FS_SUPER_MAGIC: u32 = 0xf2f5_2010;
#[cfg(target_os = "linux")]
const CEPH_SUPER_MAGIC: u32 = 0x00c3_6400;
#[cfg(target_os = "linux")]
const SMB2_SUPER_MAGIC: u32 = 0xfe53_4d42;
#[cfg(target_os = "linux")]
const CIFS_SUPER_MAGIC: u32 = 0xff53_4d42;
#[cfg(target_os = "linux")]
const GFS2_SUPER_MAGIC: u32 = 0x0116_1970;

/// Linux filesystems whose rename handler rejects every flag it does not
/// implement with `EINVAL` (kernel 7.2 source; OpenZFS 2.4 for ZFS, whose
/// releases before 2.2 reject all flags), so a flag can be tried and a
/// refusal falls back. The kernel itself rejects unknown flags
/// (`do_renameat2` in fs/namei.c) and passes the rest to the handler.
#[cfg(target_os = "linux")]
const RENAME_FLAGS_REFUSED_WHEN_UNSUPPORTED: [u32; 29] = [
    0xef53,      // ext2, ext3, ext4: ext4_rename2
    0x5846_5342, // XFS: xfs_vn_rename
    0x9123_683e, // btrfs: btrfs_rename2
    0x0102_1994, // tmpfs: shmem_rename2
    0x794c_7630, // overlayfs: ovl_rename_start
    ZFS_SUPER_MAGIC,
    F2FS_SUPER_MAGIC,
    NTFS3_SUPER_MAGIC,
    EXFAT_SUPER_MAGIC,
    0x4d44,      // FAT: vfat_rename2, msdos_rename
    0x4244,      // HFS
    0x482b,      // HFS+
    0x3153_464a, // JFS
    0x3434,      // NILFS
    0x1501_3346, // UDF
    0x0001_1954, // UFS
    0x7461_636f, // OCFS2: refuses every flag
    GFS2_SUPER_MAGIC,
    CEPH_SUPER_MAGIC, // refuses every flag
    0x6969,           // NFS: refuses every flag
    CIFS_SUPER_MAGIC,
    SMB2_SUPER_MAGIC,
    0x0102_1997, // 9p: refuses every flag
    0x6b41_4653, // AFS: flags only to YFS servers, else ENOTSUPP
    0x5346_414f, // AFS
    0x2405_1905, // UBIFS
    0x72b6,      // JFFS2
    0x7375_7245, // Coda: refuses every flag
    0x786f_4256, // vboxsf: refuses every flag
];

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
    /// made, and nothing is skipped because two names seem to be one file.
    /// Leftover partial files are still used: they are only read into a new
    /// partial, block by block against the source. A rule that relies on a
    /// count to find a file's other names (a restricted receiver's limit on
    /// files that may have names outside its approved directories) must
    /// assume any file may have them.
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

    /// Every capability, as on the tested local filesystems.
    #[cfg(test)]
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

/// An operation a filesystem refused although its profile allowed it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Refusal {
    Exchange,
    NoReplaceRename,
    HardLinks,
}

impl Profile {
    /// The profile as bits, for an atomic cache.
    pub(crate) const fn to_bits(self) -> u8 {
        self.exchange as u8
            | (self.atomic_no_replace_rename as u8) << 1
            | (self.hard_links as u8) << 2
            | (self.link_counts_trusted as u8) << 3
            | (self.symlink_times as u8) << 4
            | (self.two_second_mtimes as u8) << 5
    }

    pub(crate) const fn from_bits(bits: u8) -> Self {
        Self {
            exchange: bits & 1 != 0,
            atomic_no_replace_rename: bits & 1 << 1 != 0,
            hard_links: bits & 1 << 2 != 0,
            link_counts_trusted: bits & 1 << 3 != 0,
            symlink_times: bits & 1 << 4 != 0,
            two_second_mtimes: bits & 1 << 5 != 0,
        }
    }

    /// This profile without the capability a filesystem refused.
    pub(crate) fn without(mut self, refusal: Refusal) -> Self {
        match refusal {
            Refusal::Exchange => self.exchange = false,
            Refusal::NoReplaceRename => self.atomic_no_replace_rename = false,
            Refusal::HardLinks => self.hard_links = false,
        }
        self
    }
}

/// Remember for the rest of the process that the filesystem `file` is on
/// refused an operation its profile allowed, so that later publications
/// there take the conservative path at once. A profile can be wrong by
/// version as well as by type: OpenZFS gained exchange and no-replace
/// renames only in 2.2, and older kernels and overlay layers vary. Calls
/// that fail this way change nothing, so learning from them needs no probe
/// and costs nothing where the call works.
pub(crate) fn record_refusal(file: &File, refusal: Refusal) {
    #[cfg(target_os = "linux")]
    super::update_profile(file, |profile| *profile = profile.without(refusal));
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsRawFd;
        update_macos_profile(file.as_raw_fd(), |profile| {
            *profile = profile.without(refusal)
        });
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let _ = (file, refusal);
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
/// reads and, for SMB and CephFS, the mount's options.
#[cfg(target_os = "linux")]
pub(super) fn linux_profile(file_system_type: u32, file: &File, key: FileSystemKey) -> Profile {
    let t = file_system_type;
    let tries_flags = RENAME_FLAGS_REFUSED_WHEN_UNSUPPORTED.contains(&t);
    // SMB checks a no-replace target in the client and then asks the server
    // to replace (smb2inode.c), and GFS2 drops the flag after the local
    // check, so neither keeps another client or node from the name.
    let no_replace_is_atomic =
        tries_flags && !matches!(t, CIFS_SUPER_MAGIC | SMB2_SUPER_MAGIC | GFS2_SUPER_MAGIC);
    let fat = t == libc::MSDOS_SUPER_MAGIC as u32;
    // Link counts and symlink times, where there is evidence:
    // - tested: ext4, XFS, btrfs, tmpfs, overlayfs, ZFS;
    // - source: f2fs and ntfs3 count links (f2fs_i_links_write, ntfs_link)
    //   and keep stable inode numbers, and the kernel sets a symlink's own
    //   times on local filesystems (fs/utimes.c follows no link);
    // - NFS: the server keeps counts and file IDs, and SETATTR acts on the
    //   object a file handle names, the link itself;
    // - CephFS: the MDS keeps counts (ceph_fill_inode) and sets attributes
    //   on the inode named; `ino32` folds inode numbers so they can collide;
    // - SMB with the server's file IDs: counts from NumberOfLinks; whether a
    //   server follows a symlink when setting its times is not known;
    // - FAT and exFAT have no hard links, so every count is one.
    let (link_counts_trusted, symlink_times) = match t {
        0xef53 | 0x5846_5342 | 0x9123_683e | 0x0102_1994 | 0x794c_7630 | ZFS_SUPER_MAGIC
        | F2FS_SUPER_MAGIC | NTFS3_SUPER_MAGIC | 0x6969 => (true, true),
        CEPH_SUPER_MAGIC => (!mount_has_option(file, key, b"ino32"), true),
        CIFS_SUPER_MAGIC | SMB2_SUPER_MAGIC => {
            (!mount_has_option(file, key, b"noserverino"), false)
        }
        _ if fat || t == EXFAT_SUPER_MAGIC => (true, false),
        _ => (false, false),
    };
    Profile {
        exchange: tries_flags,
        atomic_no_replace_rename: no_replace_is_atomic,
        hard_links: !(fat || t == EXFAT_SUPER_MAGIC),
        link_counts_trusted,
        symlink_times,
        two_second_mtimes: fat,
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
    } else if file_system_type == ZFS_SUPER_MAGIC {
        Some("zfs")
    } else if file_system_type == F2FS_SUPER_MAGIC {
        Some("f2fs")
    } else if file_system_type == NTFS3_SUPER_MAGIC {
        Some("ntfs3")
    } else if file_system_type == CEPH_SUPER_MAGIC {
        Some("ceph")
    } else {
        None
    }
}

/// Whether a destination of this reported kind sets a symlink's own times
/// (see `Profile::symlink_times`): the coordinator compares symlink times
/// only there, so that where they are left alone a rerun finds nothing to
/// change. The kinds are those of the profiles that set them, on Linux and
/// macOS.
pub(crate) fn kind_sets_symlink_times(kind: &str) -> bool {
    matches!(
        kind,
        "ext"
            | "xfs"
            | "tmpfs"
            | "btrfs"
            | "overlay"
            | "zfs"
            | "f2fs"
            | "ntfs3"
            | "ceph"
            | "nfs"
            | "apfs"
            | "hfs"
    )
}

/// The filesystem kind a Linux receiver reports for FAT (vfat or msdos).
pub(crate) const FAT_KIND: &str = "fat";

/// Whether a destination of this reported kind keeps modification times
/// in two-second steps: Linux FAT, or a macOS `msdos` volume. The
/// coordinator compares times by the kind its receiver reports.
pub(crate) fn kind_has_two_second_mtimes(kind: &str) -> bool {
    kind == FAT_KIND || kind == "msdos"
}

/// Whether a mount's options include `option`. Unknown options count as
/// including it, the conservative answer for the options asked about.
#[cfg(target_os = "linux")]
fn mount_has_option(file: &File, key: FileSystemKey, option: &[u8]) -> bool {
    let mount = match key {
        FileSystemKey::Mount(id) => Some(id),
        FileSystemKey::Device(_) => super::btrfs::fdinfo_mount_id(file),
    };
    let Some(mount) = mount else {
        return true;
    };
    std::fs::read("/proc/self/mountinfo")
        .ok()
        .and_then(|mounts| super_options(&mounts, mount).map(|options| options.to_vec()))
        .is_none_or(|options| {
            options
                .split(|byte| *byte == b',')
                .any(|item| item == option)
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
fn volumes() -> &'static std::sync::Mutex<std::collections::HashMap<Vec<u8>, Profile>> {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    static VOLUMES: OnceLock<Mutex<HashMap<Vec<u8>, Profile>>> = OnceLock::new();
    VOLUMES.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The mount point and filesystem type name of the volume holding `fd`.
#[cfg(target_os = "macos")]
fn volume_of(fd: RawFd) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut stats = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    // SAFETY: fstatfs writes only into the local structure.
    if unsafe { libc::fstatfs(fd, stats.as_mut_ptr()) } != 0 {
        return None;
    }
    let stats = unsafe { stats.assume_init() };
    // SAFETY: fstatfs NUL-terminates both names.
    let mount = unsafe { std::ffi::CStr::from_ptr(stats.f_mntonname.as_ptr()) };
    let kind = unsafe { std::ffi::CStr::from_ptr(stats.f_fstypename.as_ptr()) };
    Some((mount.to_bytes().to_vec(), kind.to_bytes().to_vec()))
}

#[cfg(target_os = "macos")]
fn update_macos_profile(fd: RawFd, update: impl FnOnce(&mut Profile)) {
    let profile = macos_profile(fd);
    if let Some((mount, _)) = volume_of(fd) {
        update(volumes().lock().unwrap().entry(mount).or_insert(profile));
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn macos_profile(fd: RawFd) -> Profile {
    let Some((mount, kind)) = volume_of(fd) else {
        return Profile::CONSERVATIVE;
    };
    let kind = kind.as_slice();
    if let Some(known) = volumes().lock().unwrap().get(&mount) {
        return *known;
    }
    let Ok(mount_name) = std::ffi::CString::new(mount.clone()) else {
        return Profile::CONSERVATIVE;
    };
    let profile = match read_volume_capabilities(&mount_name) {
        None => Profile::CONSERVATIVE,
        Some(volume) => Profile {
            exchange: volume.rename_swap && kind != b"msdos",
            atomic_no_replace_rename: volume.rename_exclusive,
            hard_links: volume.hard_links,
            // Tested on APFS and HFS+ only; other volumes may report
            // capabilities they were not tested for.
            link_counts_trusted: matches!(kind, b"apfs" | b"hfs")
                && volume.hard_links
                && volume.persistent_ids,
            // Tested on APFS and HFS+; on NFS, SETATTR acts on the object a
            // file handle names, the link itself.
            symlink_times: matches!(kind, b"apfs" | b"hfs" | b"nfs"),
            two_second_mtimes: kind == b"msdos",
        },
    };
    *volumes().lock().unwrap().entry(mount).or_insert(profile)
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

    #[test]
    fn a_refusal_removes_only_its_capability() {
        let local = Profile::LOCAL;
        assert_eq!(
            local.without(Refusal::Exchange),
            Profile {
                exchange: false,
                ..local
            }
        );
        assert_eq!(
            local.without(Refusal::NoReplaceRename),
            Profile {
                atomic_no_replace_rename: false,
                ..local
            }
        );
        assert_eq!(
            local.without(Refusal::HardLinks),
            Profile {
                hard_links: false,
                ..local
            }
        );
    }

    #[test]
    fn profiles_survive_their_bits() {
        for bits in 0..64 {
            assert_eq!(Profile::from_bits(bits).to_bits(), bits);
        }
        assert_eq!(Profile::from_bits(Profile::LOCAL.to_bits()), Profile::LOCAL);
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

    /// The profile behind each Linux kind that reports symlink times set.
    #[cfg(target_os = "linux")]
    fn linux_kind_profile_sets_symlink_times(kind: &str) -> bool {
        let directory = crate::test_support::tempdir().unwrap();
        let file = File::open(directory.path()).unwrap();
        let file_system_type = match kind {
            "ext" => libc::EXT4_SUPER_MAGIC as u32,
            "xfs" => libc::XFS_SUPER_MAGIC as u32,
            "tmpfs" => libc::TMPFS_MAGIC as u32,
            "btrfs" => libc::BTRFS_SUPER_MAGIC as u32,
            "overlay" => libc::OVERLAYFS_SUPER_MAGIC as u32,
            "zfs" => ZFS_SUPER_MAGIC,
            "nfs" => libc::NFS_SUPER_MAGIC as u32,
            _ => return false,
        };
        linux_profile(file_system_type, &file, FileSystemKey::Device(0)).symlink_times
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
        for evidenced in [
            F2FS_SUPER_MAGIC,
            NTFS3_SUPER_MAGIC,
            libc::NFS_SUPER_MAGIC as u32,
        ] {
            let profile = linux_profile(evidenced, &file, key);
            assert!(profile.exchange && profile.link_counts_trusted && profile.symlink_times);
        }
        // Rename flags are tried where a refusal is certain, but counts and
        // symlink times need evidence.
        let p9 = linux_profile(0x0102_1997, &file, key);
        assert!(p9.exchange && p9.atomic_no_replace_rename);
        assert!(!p9.link_counts_trusted && !p9.symlink_times);
        for racy in [CIFS_SUPER_MAGIC, SMB2_SUPER_MAGIC, GFS2_SUPER_MAGIC] {
            let profile = linux_profile(racy, &file, key);
            assert!(
                profile.exchange && !profile.atomic_no_replace_rename,
                "{racy:x}"
            );
        }
        let fat = linux_profile(libc::MSDOS_SUPER_MAGIC as u32, &file, key);
        assert!(fat.two_second_mtimes && !fat.hard_links && fat.atomic_no_replace_rename);
        // FUSE (also virtiofs), the old NTFS driver's type, bcachefs (now
        // outside the kernel tree) and anything unknown.
        for unknown in [
            libc::FUSE_SUPER_MAGIC as u32,
            0x5346_544e,
            0xca45_1a4e,
            0x1234_5678,
        ] {
            assert_eq!(
                linux_profile(unknown, &file, key),
                Profile::CONSERVATIVE,
                "{unknown:x}"
            );
        }
        assert_eq!(linux_kind(libc::MSDOS_SUPER_MAGIC as u32), Some(FAT_KIND));
        assert_eq!(linux_kind(EXFAT_SUPER_MAGIC), Some("exfat"));
        assert_eq!(linux_kind(ZFS_SUPER_MAGIC), Some("zfs"));
        for kind in ["ext", "xfs", "tmpfs", "btrfs", "overlay", "zfs", "nfs"] {
            assert!(kind_sets_symlink_times(kind), "{kind}");
            assert!(linux_kind_profile_sets_symlink_times(kind), "{kind}");
        }
        assert!(!kind_sets_symlink_times("other"));
        assert!(!kind_sets_symlink_times(FAT_KIND));
        assert_eq!(linux_kind(libc::EXT4_SUPER_MAGIC as u32), None);
    }
}

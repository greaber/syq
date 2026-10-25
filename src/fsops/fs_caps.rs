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
//!   rename handlers reject flags they do not implement, and macOS APFS
//!   and HFS+ volumes that advertise them, where tests show them working.
//!   A refusal falls back and is remembered. They are not tried where the
//!   handler implements none, as on NFS, so that what a copy plans there
//!   knows from the start that it will publish without them. FUSE passes
//!   the flags to a userspace server, which could ignore them, so they are
//!   not tried there, nor on types not audited.
//! - Link counts, inode numbers and symlink times cannot be checked by
//!   their errors, so they are trusted only on filesystems with evidence.
//!
//! The profile comes from facts syq already reads cheaply: the filesystem
//! type, mount options, and on macOS the capabilities a volume advertises.
//! It is read when a publication first needs it and cached per mount or
//! volume. Nothing is probed.

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

/// Of those, the filesystems whose rename handler implements no flag at
/// all, so every flag is refused: none is tried there.
#[cfg(target_os = "linux")]
const RENAME_FLAGS_NEVER_IMPLEMENTED: [u32; 6] = [
    0x7461_636f, // OCFS2
    CEPH_SUPER_MAGIC,
    0x6969,      // NFS
    0x0102_1997, // 9p
    0x7375_7245, // Coda
    0x786f_4256, // vboxsf
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
    /// that includes both, and a number stays with its file while it is in
    /// use. SSHFS and rclone report one link for every name and give each
    /// name its own number; the Linux SMB client reports one link for files
    /// it has only listed or opened; macOS FAT and exFAT volumes report that
    /// their object IDs are not persistent. Linux FAT and exFAT have no hard
    /// links, so every count of one is true, and a file keeps the number it
    /// was given while it is in use.
    ///
    /// Where this is false, checks that compare counts or numbers are not
    /// made, and nothing is skipped because two names seem to be one file.
    /// Leftover partial files are still used: they are only read into a new
    /// partial, block by block against the source. A check that relies on a
    /// count to know a file has no other names must assume it may have
    /// some, and one that relies on a number to know which file a name
    /// leads to cannot be made.
    pub(crate) link_counts_trusted: bool,
    /// Setting a symlink's times with `AT_SYMLINK_NOFOLLOW` sets the link's
    /// own. An SFTP server behind SSHFS follows the link and sets the
    /// target's instead, so symlink times are only set where this is known.
    pub(crate) symlink_times: bool,
    /// Modification times are kept in two-second steps (FAT).
    pub(crate) two_second_mtimes: bool,
    /// The filesystem's type was audited, so its errors mean what its
    /// source or tests show: `EIO` is an I/O error. A FUSE server or a type
    /// not audited may answer an operation it lacks with `EIO`, as an
    /// rclone mount answers a hard link, so only there does a link that
    /// fails with `EIO` fall back to check-then-rename.
    pub(crate) audited: bool,
    /// Concurrent range writes to one file are taken one at a time
    /// (`write_gate`): on most filesystems they contend inside it, and
    /// serializing them saves CPU at the same speed. ZFS locks only the
    /// ranges written, so there they run concurrently, which is faster.
    pub(crate) serialized_writes: bool,
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
        audited: false,
        serialized_writes: true,
    };

    /// Every capability, as on the tested local filesystems.
    #[cfg(test)]
    pub(crate) const LOCAL: Self = Self {
        exchange: true,
        atomic_no_replace_rename: true,
        hard_links: true,
        link_counts_trusted: true,
        symlink_times: true,
        two_second_mtimes: false,
        audited: true,
        serialized_writes: true,
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
            | (self.audited as u8) << 6
            | (self.serialized_writes as u8) << 7
    }

    pub(crate) const fn from_bits(bits: u8) -> Self {
        Self {
            exchange: bits & 1 != 0,
            atomic_no_replace_rename: bits & 1 << 1 != 0,
            hard_links: bits & 1 << 2 != 0,
            link_counts_trusted: bits & 1 << 3 != 0,
            symlink_times: bits & 1 << 4 != 0,
            two_second_mtimes: bits & 1 << 5 != 0,
            audited: bits & 1 << 6 != 0,
            serialized_writes: bits & 1 << 7 != 0,
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

/// Given the device a profile is looked up for and its profile, the
/// profile a test stands in for.
#[cfg(test)]
type TestProfiles = Box<dyn Fn(u64, Profile) -> Profile>;

#[cfg(test)]
thread_local! {
    /// Tests stand in for filesystems with other profiles.
    static TEST_PROFILES: std::cell::RefCell<Option<TestProfiles>> =
        const { std::cell::RefCell::new(None) };
}

/// Until the returned guard drops, profiles looked up on this thread are
/// what `profiles` makes of the device and real profile.
#[cfg(test)]
pub(crate) fn override_profiles_for_test(
    profiles: impl Fn(u64, Profile) -> Profile + 'static,
) -> impl Drop {
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            TEST_PROFILES.with_borrow_mut(|profiles| *profiles = None);
        }
    }
    TEST_PROFILES.with_borrow_mut(|current| *current = Some(Box::new(profiles)));
    Restore
}

#[cfg(test)]
thread_local! {
    /// Tests stand in for filesystems that show other owners.
    static UNFAITHFUL_OWNERS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Until the returned guard drops, no filesystem looked up on this thread
/// counts as reporting owners faithfully (`reports_owners_faithfully`).
#[cfg(test)]
pub(crate) fn distrust_owners_for_test() -> impl Drop {
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            UNFAITHFUL_OWNERS.set(false);
        }
    }
    UNFAITHFUL_OWNERS.set(true);
    Restore
}

/// Whether the filesystem `file` is on is a local one that shows a file this
/// process creates as owned by the account it runs as, and a new file's
/// group as the platform's rule gives it: ext4, XFS, btrfs, ZFS, tmpfs,
/// overlayfs and f2fs on Linux, APFS and HFS+ on macOS. On network, FUSE and
/// other filesystems, such as NFS that squashes root, SSHFS without uid
/// mapping or CIFS mounted with `uid=`, the owner is learned from what this
/// process creates there (`rooted::created_owner`). Debug builds given
/// another account to compare owners with (`SYQ_TEST_OWN_UID`) stand in for
/// such a filesystem everywhere.
pub(crate) fn reports_owners_faithfully(file: &File) -> bool {
    #[cfg(debug_assertions)]
    if std::env::var_os("SYQ_TEST_OWN_UID").is_some() {
        return false;
    }
    #[cfg(test)]
    if UNFAITHFUL_OWNERS.get() {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let mut stats = std::mem::MaybeUninit::<libc::statfs>::zeroed();
        // SAFETY: fstatfs writes only into the local structure.
        if unsafe { libc::fstatfs(file.as_raw_fd(), stats.as_mut_ptr()) } != 0 {
            return false;
        }
        let stats = unsafe { stats.assume_init() };
        matches!(
            stats.f_type as u32,
            0xef53 // ext2, ext3, ext4
                | 0x5846_5342 // XFS
                | 0x9123_683e // btrfs
                | 0x0102_1994 // tmpfs
                | 0x794c_7630 // overlayfs
                | ZFS_SUPER_MAGIC
                | F2FS_SUPER_MAGIC
        )
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsRawFd;
        volume_of(file.as_raw_fd())
            .is_some_and(|volume| matches!(volume.kind.as_slice(), b"apfs" | b"hfs"))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = file;
        false
    }
}

/// Whether the filesystem at `path` shows every file with an owner and mode
/// set when it was mounted, rather than kept per file, so neither says who
/// can change a file. On Linux: FAT, exFAT, NTFS through the kernel's ntfs3,
/// SMB, VirtualBox shared folders, NTFS and exFAT through FUSE drivers such as
/// ntfs-3g and exfat-fuse (`fuseblk`), and WSL's Windows drives (drvfs). On
/// macOS: FAT, exFAT, NTFS and SMB volumes, and volumes mounted to ignore
/// ownership. NFS, other FUSE filesystems such as SSHFS, and other 9p shares
/// keep the owners their servers report, so they are not included.
///
/// This is one `statfs`, plus the mount's entry in `/proc/self/mountinfo`
/// for FUSE and 9p, whose one type covers filesystems of both kinds. A path
/// that cannot be inspected counts as keeping owners. Debug builds given
/// `SYQ_TEST_FIXED_OWNERS` count every filesystem.
pub(crate) fn fixed_owners_and_modes(path: &std::path::Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    #[cfg(debug_assertions)]
    if std::env::var_os("SYQ_TEST_FIXED_OWNERS").is_some() {
        return true;
    }
    let Ok(path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    let mut stats = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    // SAFETY: statfs writes only into the local structure.
    if unsafe { libc::statfs(path.as_ptr(), stats.as_mut_ptr()) } != 0 {
        return false;
    }
    let stats = unsafe { stats.assume_init() };
    #[cfg(target_os = "linux")]
    {
        let kind = stats.f_type as u32;
        linux_fixed_owners_and_modes(kind)
            || ((kind == libc::FUSE_SUPER_MAGIC as u32 || kind == V9FS_MAGIC)
                && mount_fields_at(&path).is_some_and(|(kind, options)| {
                    linux_mount_fixes_owners_and_modes(&kind, &options)
                }))
    }
    #[cfg(target_os = "macos")]
    {
        // SAFETY: statfs NUL-terminates the type name.
        let kind = unsafe { std::ffi::CStr::from_ptr(stats.f_fstypename.as_ptr()) };
        macos_fixed_owners_and_modes(kind.to_bytes(), stats.f_flags)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = stats;
        false
    }
}

/// Whether a read lease on `file` shows every write to it (`leases`): the
/// filesystem grants leases, and its files change only through opens in
/// this kernel, which break them. Tested on ext4, XFS, Btrfs, tmpfs and
/// OpenZFS 2.4 (whose `zpl_file.c` uses `generic_setlease`): an open for
/// writing or a truncate breaks a lease, and a file open for writing, or
/// mapped writable and shared, is refused one. Network filesystems, FUSE and
/// overlayfs are not trusted: another client, a FUSE server or a write to an
/// overlay's layers changes a file without opening it here, and FUSE grants
/// leases that such writes leave intact. Debug builds given
/// `SYQ_TEST_LEASES=unsupported` trust no filesystem.
#[cfg(target_os = "linux")]
pub(crate) fn leases_show_writers(file: &File) -> bool {
    use std::os::fd::AsRawFd;
    #[cfg(debug_assertions)]
    if std::env::var_os("SYQ_TEST_LEASES").is_some_and(|value| value == "unsupported") {
        return false;
    }
    let mut stats = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    // SAFETY: fstatfs writes only into the local structure.
    if unsafe { libc::fstatfs(file.as_raw_fd(), stats.as_mut_ptr()) } != 0 {
        return false;
    }
    let stats = unsafe { stats.assume_init() };
    linux_leases_show_writers(stats.f_type as u32)
}

#[cfg(target_os = "linux")]
fn linux_leases_show_writers(file_system_type: u32) -> bool {
    matches!(
        file_system_type,
        0xef53 // ext2, ext3, ext4
            | 0x5846_5342 // XFS
            | 0x9123_683e // btrfs
            | 0x0102_1994 // tmpfs
            | ZFS_SUPER_MAGIC
    )
}

#[cfg(target_os = "linux")]
fn linux_fixed_owners_and_modes(file_system_type: u32) -> bool {
    matches!(
        file_system_type,
        0x4d44 // FAT
            | EXFAT_SUPER_MAGIC
            | NTFS3_SUPER_MAGIC
            | CIFS_SUPER_MAGIC
            | SMB2_SUPER_MAGIC
            | 0x517b // SMB
            | 0x786f_4256 // vboxsf
    )
}

/// 9p's filesystem type, which libc does not name.
#[cfg(target_os = "linux")]
const V9FS_MAGIC: u32 = 0x0102_1997;

/// Of the FUSE and 9p mounts, the ones with fixed owners and modes: block
/// devices served by FUSE (`fuseblk`: ntfs-3g, exfat-fuse) and WSL's drvfs,
/// which WSL 2 mounts as 9p with `aname=drvfs`.
#[cfg(target_os = "linux")]
fn linux_mount_fixes_owners_and_modes(kind: &[u8], options: &[u8]) -> bool {
    kind == b"fuseblk"
        || kind == b"drvfs"
        || (kind == b"9p"
            && options
                .split(|byte| *byte == b',')
                .any(|option| option.starts_with(b"aname=drvfs")))
}

/// The type and superblock options of the mount holding `path`.
#[cfg(target_os = "linux")]
fn mount_fields_at(path: &std::ffi::CStr) -> Option<(Vec<u8>, Vec<u8>)> {
    use std::os::unix::ffi::OsStrExt;
    let file = File::open(std::ffi::OsStr::from_bytes(path.to_bytes())).ok()?;
    let mount = super::mount_id(&file).or_else(|| super::btrfs::fdinfo_mount_id(&file))?;
    let mounts = std::fs::read("/proc/self/mountinfo").ok()?;
    let (kind, _, options) = mount_fields(&mounts, mount)?;
    Some((kind.to_vec(), options.to_vec()))
}

#[cfg(target_os = "macos")]
fn macos_fixed_owners_and_modes(kind: &[u8], flags: u32) -> bool {
    matches!(kind, b"msdos" | b"exfat" | b"ntfs" | b"smbfs")
        || flags & libc::MNT_IGNORE_OWNERSHIP as u32 != 0
}

/// The profile of the filesystem `file` is on.
pub(crate) fn profile(file: &File) -> Profile {
    #[cfg(target_os = "linux")]
    let profile = super::file_system_profile(file).unwrap_or(Profile::CONSERVATIVE);
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
    #[cfg(test)]
    let profile = TEST_PROFILES.with_borrow(|profiles| match profiles {
        Some(profiles) => {
            use std::os::unix::fs::MetadataExt;
            file.metadata()
                .map_or(profile, |metadata| profiles(metadata.dev(), profile))
        }
        None => profile,
    });
    profile.with_test_overrides()
}

/// Linux: the profile for a filesystem type, from the type syq already
/// reads and, for NFS and CephFS, the mount's options.
#[cfg(target_os = "linux")]
pub(super) fn linux_profile(file_system_type: u32, file: &File, key: FileSystemKey) -> Profile {
    let t = file_system_type;
    let audited = RENAME_FLAGS_REFUSED_WHEN_UNSUPPORTED.contains(&t);
    let tries_flags = audited && !RENAME_FLAGS_NEVER_IMPLEMENTED.contains(&t);
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
    //   object a file handle names, the link itself. An open revalidates a
    //   file's attributes; with `nocto` it does not, and a count can be as
    //   stale as the attribute cache allows;
    // - CephFS: the MDS keeps counts (ceph_fill_inode) and sets attributes
    //   on the inode named; `ino32` folds inode numbers so they can collide;
    // - FAT and exFAT have no hard links, so every count is one, and a file
    //   keeps the number iunique gave it while its inode is in use
    //   (fs/fat/inode.c:609, fs/exfat/inode.c:432).
    // SMB counts are not trusted: a listing marks counts unknown
    // (readdir.c:207), which gives a new inode a count of one (inode.c:165),
    // and so does the CREATE response of an open (smb2pdu.c:3383); the real
    // count arrives only when the attribute cache next expires. The client
    // can also stop using the server's file IDs mid-mount
    // (cifs_autodisable_serverino), and whether a server follows a symlink
    // when setting its times is not known.
    let (link_counts_trusted, symlink_times) = match t {
        0xef53 | 0x5846_5342 | 0x9123_683e | 0x0102_1994 | 0x794c_7630 | ZFS_SUPER_MAGIC
        | F2FS_SUPER_MAGIC | NTFS3_SUPER_MAGIC => (true, true),
        0x6969 => (!mount_has_option(file, key, b"nocto"), true),
        CEPH_SUPER_MAGIC => (!mount_has_option(file, key, b"ino32"), true),
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
        audited,
        serialized_writes: t != ZFS_SUPER_MAGIC,
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
            | "msdos"
            | "exfat"
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
    mount_fields(mounts, mount).map(|(_, _, options)| options)
}

/// The filesystem type, source and superblock options of one mount in
/// `/proc/self/mountinfo`.
#[cfg(target_os = "linux")]
fn mount_fields(mounts: &[u8], mount: u64) -> Option<(&[u8], &[u8], &[u8])> {
    for line in mounts.split(|byte| *byte == b'\n') {
        let mut fields = line.split(|byte| byte.is_ascii_whitespace());
        let id = fields
            .next()
            .and_then(|id| std::str::from_utf8(id).ok())
            .and_then(|id| id.parse::<u64>().ok());
        if id != Some(mount) || !fields.any(|field| field == b"-") {
            continue;
        }
        return Some((fields.next()?, fields.next()?, fields.next()?));
    }
    None
}

/// macOS: the volumes whose profiles are known, by volume identity: the
/// filesystem ID, mount point and type together, so that a volume mounted
/// where another was is read again.
#[cfg(target_os = "macos")]
fn volumes() -> &'static std::sync::Mutex<std::collections::HashMap<Vec<u8>, Profile>> {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    static VOLUMES: OnceLock<Mutex<HashMap<Vec<u8>, Profile>>> = OnceLock::new();
    VOLUMES.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The volume holding `fd`: its identity (filesystem ID, mount point and
/// type name), mount point, and type name.
#[cfg(target_os = "macos")]
struct Volume {
    identity: Vec<u8>,
    mount: std::ffi::CString,
    kind: Vec<u8>,
}

#[cfg(target_os = "macos")]
fn volume_of(fd: RawFd) -> Option<Volume> {
    let mut stats = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    // SAFETY: fstatfs writes only into the local structure.
    if unsafe { libc::fstatfs(fd, stats.as_mut_ptr()) } != 0 {
        return None;
    }
    let stats = unsafe { stats.assume_init() };
    // SAFETY: fstatfs NUL-terminates both names.
    let mount = unsafe { std::ffi::CStr::from_ptr(stats.f_mntonname.as_ptr()) };
    let kind = unsafe { std::ffi::CStr::from_ptr(stats.f_fstypename.as_ptr()) };
    // SAFETY: fsid_t is plain data; its fields are not public in libc.
    let fsid = unsafe {
        std::slice::from_raw_parts(
            (&stats.f_fsid as *const libc::fsid_t).cast::<u8>(),
            std::mem::size_of::<libc::fsid_t>(),
        )
    };
    let mut identity = fsid.to_vec();
    identity.extend_from_slice(mount.to_bytes_with_nul());
    identity.extend_from_slice(kind.to_bytes());
    Some(Volume {
        identity,
        mount: mount.to_owned(),
        kind: kind.to_bytes().to_vec(),
    })
}

/// What a volume of this type may be trusted with, whatever it advertises
/// or a cached profile says. A volume can advertise a rename flag it does
/// not keep: FAT32 (`msdos`) completes `RENAME_SWAP` as a plain rename over
/// the target and reports success. So the flags are tried only where tests
/// show them working: `RENAME_SWAP` on APFS, and `RENAME_EXCL` on APFS and
/// HFS+ (which refuses a swap). Inode numbers were tested on APFS and HFS+
/// only; symlink times on APFS, HFS+, FAT and exFAT (where links are small
/// files), and on NFS, SETATTR acts on the object a file handle names, the
/// link itself.
#[cfg(any(target_os = "macos", test))]
fn within_kind(mut profile: Profile, kind: &[u8]) -> Profile {
    profile.exchange &= kind == b"apfs";
    profile.atomic_no_replace_rename &= matches!(kind, b"apfs" | b"hfs");
    profile.link_counts_trusted &= matches!(kind, b"apfs" | b"hfs");
    let tested = matches!(kind, b"apfs" | b"hfs" | b"msdos" | b"exfat" | b"nfs");
    profile.symlink_times &= tested;
    profile.audited &= tested;
    profile.two_second_mtimes = kind == b"msdos";
    profile
}

#[cfg(target_os = "macos")]
fn update_macos_profile(fd: RawFd, update: impl FnOnce(&mut Profile)) {
    let profile = macos_profile(fd);
    if let Some(volume) = volume_of(fd) {
        update(
            volumes()
                .lock()
                .unwrap()
                .entry(volume.identity)
                .or_insert(profile),
        );
    }
}

/// macOS: the profile of the volume holding `fd`, from the capabilities it
/// advertises and its type, cached per volume.
#[cfg(target_os = "macos")]
pub(crate) fn macos_profile(fd: RawFd) -> Profile {
    let Some(volume) = volume_of(fd) else {
        return Profile::CONSERVATIVE;
    };
    if let Some(known) = volumes().lock().unwrap().get(&volume.identity) {
        return within_kind(*known, &volume.kind);
    }
    let profile = match read_volume_capabilities(&volume.mount) {
        None => Profile::CONSERVATIVE,
        Some(capabilities) => within_kind(
            Profile {
                exchange: capabilities.rename_swap,
                atomic_no_replace_rename: capabilities.rename_exclusive,
                hard_links: capabilities.hard_links,
                link_counts_trusted: capabilities.hard_links && capabilities.persistent_ids,
                symlink_times: true,
                two_second_mtimes: false,
                audited: true,
                serialized_writes: true,
            },
            &volume.kind,
        ),
    };
    *volumes()
        .lock()
        .unwrap()
        .entry(volume.identity)
        .or_insert(profile)
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

    #[cfg(target_os = "linux")]
    #[test]
    fn fat_exfat_ntfs_and_smb_have_fixed_owners_on_linux() {
        for kind in [
            0x4d44,
            EXFAT_SUPER_MAGIC,
            NTFS3_SUPER_MAGIC,
            CIFS_SUPER_MAGIC,
            SMB2_SUPER_MAGIC,
        ] {
            assert!(linux_fixed_owners_and_modes(kind), "{kind:#x}");
        }
        for kind in [
            0xef53,
            0x5846_5342,
            0x9123_683e,
            0x0102_1994,
            ZFS_SUPER_MAGIC,
            libc::NFS_SUPER_MAGIC as u32,
            libc::FUSE_SUPER_MAGIC as u32,
        ] {
            assert!(!linux_fixed_owners_and_modes(kind), "{kind:#x}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn leases_are_trusted_only_on_local_filesystems_that_break_them() {
        for kind in [
            0xef53,
            0x5846_5342,
            0x9123_683e,
            0x0102_1994,
            ZFS_SUPER_MAGIC,
        ] {
            assert!(linux_leases_show_writers(kind), "{kind:#x}");
        }
        for kind in [
            libc::NFS_SUPER_MAGIC as u32,
            libc::FUSE_SUPER_MAGIC as u32,
            0x794c_7630, // overlayfs
            CIFS_SUPER_MAGIC,
            SMB2_SUPER_MAGIC,
            CEPH_SUPER_MAGIC,
            GFS2_SUPER_MAGIC,
            V9FS_MAGIC,
            F2FS_SUPER_MAGIC,
            0x4d44,
        ] {
            assert!(!linux_leases_show_writers(kind), "{kind:#x}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fuse_block_drivers_and_wsl_drives_have_fixed_owners_but_sshfs_does_not() {
        for (kind, options) in [
            (&b"fuseblk"[..], &b"rw,user_id=0,group_id=0,allow_other"[..]),
            (
                b"9p",
                b"rw,aname=drvfs;path=C:\\;uid=1000;gid=1000,trans=fd",
            ),
            (b"drvfs", b"rw,case=off"),
        ] {
            assert!(linux_mount_fixes_owners_and_modes(kind, options));
        }
        for (kind, options) in [
            (&b"fuse.sshfs"[..], &b"rw,user_id=1000,group_id=1000"[..]),
            (b"9p", b"rw,trans=virtio,version=9p2000.L"),
        ] {
            assert!(!linux_mount_fixes_owners_and_modes(kind, options));
        }
        let mounts = b"36 35 98:0 / /mnt rw,noatime master:1 - fuseblk /dev/sdb1 rw,user_id=0\n\
37 35 0:41 / /mnt/c rw - 9p C:\\134 rw,aname=drvfs;path=C:\\;uid=1000,trans=fd\n";
        assert_eq!(
            mount_fields(mounts, 36),
            Some((&b"fuseblk"[..], &b"/dev/sdb1"[..], &b"rw,user_id=0"[..]))
        );
        assert_eq!(
            mount_fields(mounts, 37).map(|fields| fields.0),
            Some(&b"9p"[..])
        );
        assert_eq!(mount_fields(mounts, 38), None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn fat_exfat_ntfs_smb_and_ignored_ownership_have_fixed_owners_on_macos() {
        for kind in [&b"msdos"[..], b"exfat", b"ntfs", b"smbfs"] {
            assert!(macos_fixed_owners_and_modes(kind, 0));
        }
        for kind in [&b"apfs"[..], b"hfs", b"nfs"] {
            assert!(!macos_fixed_owners_and_modes(kind, 0));
        }
        assert!(macos_fixed_owners_and_modes(
            b"apfs",
            libc::MNT_IGNORE_OWNERSHIP as u32
        ));
    }

    #[test]
    fn a_local_test_directory_keeps_owners() {
        let directory = crate::test_support::tempdir().unwrap();
        assert!(!fixed_owners_and_modes(directory.path()));
    }

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
        for bits in 0..=u8::MAX {
            assert_eq!(Profile::from_bits(bits).to_bits(), bits);
        }
        assert_eq!(Profile::from_bits(Profile::LOCAL.to_bits()), Profile::LOCAL);
    }

    /// A macOS volume's rename flags are tried only on volume types where
    /// tests show them working, whatever the volume advertises: a swap on
    /// APFS, an exclusive rename on APFS and HFS+.
    #[test]
    fn macos_rename_flags_are_trusted_only_on_tested_volume_types() {
        let advertised = Profile::LOCAL;
        let apfs = within_kind(advertised, b"apfs");
        assert!(apfs.exchange && apfs.atomic_no_replace_rename && apfs.audited);
        let hfs = within_kind(advertised, b"hfs");
        assert!(!hfs.exchange && hfs.atomic_no_replace_rename && hfs.audited);
        for kind in ["msdos", "exfat", "nfs", "smbfs", "macfuse", "other"] {
            let profile = within_kind(advertised, kind.as_bytes());
            assert!(
                !profile.exchange && !profile.atomic_no_replace_rename,
                "{kind}: {profile:?}"
            );
        }
        for kind in ["smbfs", "macfuse", "other"] {
            assert!(!within_kind(advertised, kind.as_bytes()).audited, "{kind}");
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
        ] {
            assert_eq!(linux_profile(local, &file, key), Profile::LOCAL);
        }
        // ZFS locks only the ranges written, so its writes run concurrently.
        assert_eq!(
            linux_profile(ZFS_SUPER_MAGIC, &file, key),
            Profile {
                serialized_writes: false,
                ..Profile::LOCAL
            }
        );
        for evidenced in [F2FS_SUPER_MAGIC, NTFS3_SUPER_MAGIC] {
            let profile = linux_profile(evidenced, &file, key);
            assert!(profile.exchange && profile.link_counts_trusted && profile.symlink_times);
        }
        // NFS has counts and symlink times, but no rename flag to try.
        let nfs = linux_profile(libc::NFS_SUPER_MAGIC as u32, &file, key);
        assert!(!nfs.exchange && !nfs.atomic_no_replace_rename && nfs.audited);
        assert!(nfs.link_counts_trusted && nfs.symlink_times);
        // Rename flags are tried where a refusal is certain and the handler
        // implements some, but counts and symlink times need evidence.
        let afs = linux_profile(0x6b41_4653, &file, key);
        assert!(afs.exchange && afs.atomic_no_replace_rename && afs.audited);
        assert!(!afs.link_counts_trusted && !afs.symlink_times);
        let p9 = linux_profile(0x0102_1997, &file, key);
        assert!(!p9.exchange && !p9.atomic_no_replace_rename && p9.audited);
        for racy in [CIFS_SUPER_MAGIC, SMB2_SUPER_MAGIC, GFS2_SUPER_MAGIC] {
            let profile = linux_profile(racy, &file, key);
            assert!(
                profile.exchange && !profile.atomic_no_replace_rename,
                "{racy:x}"
            );
            assert!(!profile.link_counts_trusted && !profile.symlink_times);
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

/// macOS: a profile belongs to a volume, not to the path it is mounted at.
#[cfg(all(test, target_os = "macos"))]
mod volume_tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::process::Command;

    fn hdiutil(arguments: &[&std::ffi::OsStr]) {
        let output = Command::new("hdiutil").args(arguments).output().unwrap();
        assert!(
            output.status.success(),
            "hdiutil {arguments:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    struct Attached(std::path::PathBuf);

    impl Drop for Attached {
        fn drop(&mut self) {
            let _ = Command::new("hdiutil")
                .args(["detach", "-force"])
                .arg(&self.0)
                .output();
        }
    }

    fn attach(image: &std::path::Path, point: &std::path::Path) -> Attached {
        hdiutil(&[
            "attach".as_ref(),
            "-nobrowse".as_ref(),
            "-mountpoint".as_ref(),
            point.as_os_str(),
            image.as_os_str(),
        ]);
        Attached(point.to_path_buf())
    }

    /// Volumes mounted in turn at one mount point each get their own
    /// profile: APFS swaps and renames exclusively; HFS+ renames
    /// exclusively but refuses a swap; FAT32 neither, as it would complete
    /// a swap as a plain rename over the target, and its inode numbers are
    /// not trusted.
    #[test]
    fn a_reused_mount_point_gets_its_own_volumes_profile() {
        let tree = crate::test_support::tempdir().unwrap();
        let point = tree.path().join("mounted");
        std::fs::create_dir(&point).unwrap();
        for (name, filesystem) in [("apfs", "APFS"), ("hfs", "HFS+"), ("fat", "MS-DOS FAT32")] {
            let image = tree.path().join(format!("{name}.dmg"));
            hdiutil(&[
                "create".as_ref(),
                "-quiet".as_ref(),
                "-size".as_ref(),
                "64m".as_ref(),
                "-fs".as_ref(),
                filesystem.as_ref(),
                "-volname".as_ref(),
                format!("syqprofile{name}").as_ref(),
                image.as_os_str(),
            ]);
        }
        let profile_of = |name: &str| {
            let _attached = attach(&tree.path().join(format!("{name}.dmg")), &point);
            let volume = File::open(&point).unwrap();
            macos_profile(volume.as_raw_fd())
        };
        let apfs = profile_of("apfs");
        assert!(apfs.exchange && apfs.atomic_no_replace_rename, "{apfs:?}");
        assert!(apfs.link_counts_trusted, "{apfs:?}");
        let hfs = profile_of("hfs");
        assert!(!hfs.exchange && hfs.atomic_no_replace_rename, "{hfs:?}");
        let fat = profile_of("fat");
        assert!(!fat.exchange && !fat.atomic_no_replace_rename, "{fat:?}");
        assert!(!fat.link_counts_trusted, "{fat:?}");
        assert!(fat.two_second_mtimes, "{fat:?}");
    }
}

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
//!
//! Whether a close can report a write error (`TypeFacts::quiet_close`) is
//! kept out of the profile: a wrong answer there hides a failed write, so
//! each destination root reads it from its own filesystem.

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
#[cfg(target_os = "macos")]
use std::os::fd::RawFd;

#[cfg(target_os = "linux")]
use super::FileSystemKey;

/// What one `fstatfs` says about the filesystem a descriptor is on.
#[derive(Clone, Copy)]
pub(crate) struct FileSystem(libc::statfs);

/// The filesystem `file` is on: one `fstatfs`, retried while it is
/// interrupted, and nothing allocated. A failure is the caller's to treat
/// conservatively. On NFS each call is a request to the server, so a
/// per-file path should use what has already been read where it can.
pub(crate) fn file_system_of(file: &impl AsRawFd) -> io::Result<FileSystem> {
    let mut stats = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    // SAFETY: fstatfs writes only into the local structure, which is plain
    // data, zeroed and then filled by the call.
    crate::sys::retry_zero(|| unsafe { libc::fstatfs(file.as_raw_fd(), stats.as_mut_ptr()) })?;
    Ok(FileSystem(unsafe { stats.assume_init() }))
}

/// The filesystem `path` is on, from one `statfs`, retried while it is
/// interrupted.
fn file_system_at(path: &std::ffi::CStr) -> io::Result<FileSystem> {
    let mut stats = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    // SAFETY: statfs reads the NUL-terminated path and writes only into the
    // local structure.
    crate::sys::retry_zero(|| unsafe { libc::statfs(path.as_ptr(), stats.as_mut_ptr()) })?;
    Ok(FileSystem(unsafe { stats.assume_init() }))
}

impl FileSystem {
    /// The filesystem's type number.
    #[cfg(target_os = "linux")]
    pub(crate) fn magic(&self) -> u32 {
        self.0.f_type as u32
    }

    /// What syq relies on this type of filesystem for.
    #[cfg(target_os = "linux")]
    pub(crate) fn facts(&self) -> &'static TypeFacts {
        type_facts(self.magic())
    }

    /// The filesystem's type name.
    #[cfg(target_os = "macos")]
    pub(crate) fn kind(&self) -> &[u8] {
        // SAFETY: fstatfs NUL-terminates the type name within its array.
        unsafe { std::ffi::CStr::from_ptr(self.0.f_fstypename.as_ptr()) }.to_bytes()
    }

    /// Where the filesystem is mounted.
    #[cfg(target_os = "macos")]
    fn mount_point(&self) -> &std::ffi::CStr {
        // SAFETY: fstatfs NUL-terminates the mount point within its array.
        unsafe { std::ffi::CStr::from_ptr(self.0.f_mntonname.as_ptr()) }
    }

    /// The mount's flags (`MNT_*`).
    #[cfg(target_os = "macos")]
    fn flags(&self) -> u32 {
        self.0.f_flags
    }

    /// The filesystem ID the kernel reports, all zero where it has none.
    pub(crate) fn fsid(&self) -> &[u8] {
        // SAFETY: fsid_t is plain data; its fields are not public in libc.
        unsafe {
            std::slice::from_raw_parts(
                (&self.0.f_fsid as *const libc::fsid_t).cast::<u8>(),
                std::mem::size_of::<libc::fsid_t>(),
            )
        }
    }

    /// The filesystem's block size, at least one.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) fn block_size(&self) -> u64 {
        (self.0.f_bsize as u64).max(1)
    }
}

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
/// 9p's filesystem type, which libc does not name.
#[cfg(target_os = "linux")]
const V9FS_MAGIC: u32 = 0x0102_1997;
#[cfg(target_os = "linux")]
const EXT_SUPER_MAGIC: u32 = libc::EXT4_SUPER_MAGIC as u32;
#[cfg(target_os = "linux")]
const XFS_SUPER_MAGIC: u32 = libc::XFS_SUPER_MAGIC as u32;
#[cfg(target_os = "linux")]
pub(crate) const BTRFS_SUPER_MAGIC: u32 = libc::BTRFS_SUPER_MAGIC as u32;
#[cfg(target_os = "linux")]
const TMPFS_MAGIC: u32 = libc::TMPFS_MAGIC as u32;
#[cfg(target_os = "linux")]
const OVERLAYFS_SUPER_MAGIC: u32 = libc::OVERLAYFS_SUPER_MAGIC as u32;
#[cfg(target_os = "linux")]
pub(crate) const NFS_SUPER_MAGIC: u32 = libc::NFS_SUPER_MAGIC as u32;
#[cfg(target_os = "linux")]
pub(crate) const FUSE_SUPER_MAGIC: u32 = libc::FUSE_SUPER_MAGIC as u32;
#[cfg(target_os = "linux")]
pub(crate) const PROC_SUPER_MAGIC: u32 = libc::PROC_SUPER_MAGIC as u32;
#[cfg(target_os = "linux")]
const FAT_SUPER_MAGIC: u32 = libc::MSDOS_SUPER_MAGIC as u32;

/// Who the files on a filesystem show as their owners.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Owners {
    /// Each file keeps its own owner and mode.
    Kept,
    /// Every file shows an owner and mode set when the filesystem was
    /// mounted (`fixed_owners_and_modes`).
    Fixed,
    /// Either, as the mount table says: FUSE and 9p serve filesystems of
    /// both kinds.
    ByMount,
}

/// Whether a filesystem's rename handler may be given flags.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Renames {
    /// Not audited: no flag is tried (`Profile::audited` is false).
    NotAudited,
    /// The handler rejects every flag it does not implement with `EINVAL`
    /// (kernel 7.2 source; OpenZFS 2.4 for ZFS, whose releases before 2.2
    /// reject all flags), so a flag can be tried and a refusal falls back.
    /// The kernel itself rejects unknown flags (`do_renameat2` in
    /// fs/namei.c) and passes the rest to the handler. `atomic_no_replace`
    /// is false where the no-replace flag does not keep another client or
    /// node from the name.
    RefuseUnsupported { atomic_no_replace: bool },
    /// The handler implements no flag at all, so every flag is refused:
    /// none is tried.
    ImplementNone,
}

/// What a filesystem's link counts, inode numbers and symlink times show
/// (`Profile::link_counts_trusted`, `Profile::symlink_times`).
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Links {
    /// Counts and numbers can be relied on, and a symlink's own times set.
    Trusted,
    /// As `Trusted`, except that counts are not relied on where the mount
    /// has this option, or its options cannot be read.
    TrustedWithout(&'static [u8]),
    /// There are no hard links, so every count of one is true; symlink
    /// times are not known to be the link's own.
    OneNameEach,
    /// Nothing is relied on.
    Untrusted,
}

/// What syq relies on one Linux filesystem type for, by its type number.
/// Every choice syq makes by type is here, so that a type added for one
/// fact is weighed for the others; `type_facts_keep_their_answers` pins
/// each.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TypeFacts {
    pub(crate) magic: u32,
    /// The kind a receiver reports (`FilesystemHint::kind`).
    pub(crate) kind: &'static str,
    /// Each operation can wait for a network round trip: NFS, SMB, Ceph,
    /// or a FUSE mount such as SSHFS. Local disk and memory filesystems are
    /// not.
    pub(crate) network: bool,
    /// A read lease shows every write to a file (`leases_show_writers`).
    pub(crate) leases_show_writers: bool,
    /// A file this process creates shows as owned by the account it runs
    /// as (`reports_owners_faithfully`).
    pub(crate) reports_owners_faithfully: bool,
    pub(crate) owners: Owners,
    pub(crate) renames: Renames,
    pub(crate) links: Links,
    /// Concurrent range writes to one file are taken one at a time
    /// (`Profile::serialized_writes`).
    pub(crate) serialized_writes: bool,
    /// Whole-file copies here may use userspace ranges. Unknown and
    /// network-backed filesystems keep adaptive ranges; tmpfs provides a
    /// real cross-filesystem control.
    pub(crate) local_userspace_copy: bool,
    /// A source here is within the independently measured ext-family/XFS
    /// to NFS scope.
    pub(crate) measured_local_source: bool,
    /// Direct I/O was exercised here, for kernels that do not report its
    /// alignment.
    pub(crate) direct_io_tested: bool,
    /// Replacing files is bounded per filesystem (`Root::replacement_turn`).
    pub(crate) bounds_replacement: bool,
    /// Closing a descriptor reports no write error here, so a written file
    /// need not be checked by closing a duplicate of its descriptor
    /// (`Root::close_reports_writes_on`). `close` returns only what the
    /// filesystem's `flush` file operation returns (`filp_flush` in
    /// fs/open.c). NFS, SMB, FUSE and OrangeFS write out there and report
    /// what failed, and overlayfs and eCryptfs pass on what the filesystem
    /// below them reports. This is set only for local types whose file
    /// operations have no `flush`, read in Linux 4.19, 5.4, 6.12 and 7.2
    /// where each exists and in OpenZFS 2.4 (`zpl_file_operations`), and
    /// for f2fs, whose `f2fs_file_flush` only rolls back an exiting
    /// process's atomic write and returns 0. Set it for each type by name,
    /// never through a shared base: overlayfs shares one with them.
    pub(crate) quiet_close: bool,
}

/// A filesystem type syq knows nothing about.
#[cfg(target_os = "linux")]
pub(crate) const UNKNOWN_TYPE: TypeFacts = TypeFacts {
    magic: 0,
    kind: "other",
    network: false,
    leases_show_writers: false,
    reports_owners_faithfully: false,
    owners: Owners::Kept,
    renames: Renames::NotAudited,
    links: Links::Untrusted,
    serialized_writes: true,
    local_userspace_copy: false,
    measured_local_source: false,
    direct_io_tested: false,
    bounds_replacement: true,
    quiet_close: false,
};

/// A filesystem whose rename handler refuses the flags it lacks, with
/// nothing else known.
#[cfg(target_os = "linux")]
const REFUSES_RENAME_FLAGS: TypeFacts = TypeFacts {
    renames: Renames::RefuseUnsupported {
        atomic_no_replace: true,
    },
    ..UNKNOWN_TYPE
};

/// A tested local filesystem: every write breaks a lease, this process's
/// files show as its own, rename flags are tried, and counts and symlink
/// times are kept.
#[cfg(target_os = "linux")]
const LOCAL_TYPE: TypeFacts = TypeFacts {
    leases_show_writers: true,
    reports_owners_faithfully: true,
    links: Links::Trusted,
    ..REFUSES_RENAME_FLAGS
};

/// A network filesystem whose rename handler implements no flag.
#[cfg(target_os = "linux")]
const NETWORK_WITHOUT_RENAME_FLAGS: TypeFacts = TypeFacts {
    network: true,
    renames: Renames::ImplementNone,
    ..UNKNOWN_TYPE
};

/// SMB: fixed owners, and a no-replace target checked in the client before
/// the server is asked to replace (smb2inode.c).
#[cfg(target_os = "linux")]
const SMB_TYPE: TypeFacts = TypeFacts {
    network: true,
    owners: Owners::Fixed,
    renames: Renames::RefuseUnsupported {
        atomic_no_replace: false,
    },
    ..UNKNOWN_TYPE
};

/// `base` for filesystem type `magic`.
#[cfg(target_os = "linux")]
const fn of_type(magic: u32, base: TypeFacts) -> TypeFacts {
    TypeFacts { magic, ..base }
}

/// Every Linux filesystem type syq treats specially.
///
/// Link counts and symlink times are relied on where there is evidence:
/// - tested: ext4, XFS, btrfs, tmpfs, overlayfs, ZFS;
/// - source: f2fs and ntfs3 count links (f2fs_i_links_write, ntfs_link)
///   and keep stable inode numbers, and the kernel sets a symlink's own
///   times on local filesystems (fs/utimes.c follows no link);
/// - NFS: the server keeps counts and file IDs, and SETATTR acts on the
///   object a file handle names, the link itself. An open revalidates a
///   file's attributes; with `nocto` it does not, and a count can be as
///   stale as the attribute cache allows;
/// - CephFS: the MDS keeps counts (ceph_fill_inode) and sets attributes
///   on the inode named; `ino32` folds inode numbers so they can collide;
/// - FAT and exFAT have no hard links, so every count is one, and a file
///   keeps the number iunique gave it while its inode is in use
///   (fs/fat/inode.c:609, fs/exfat/inode.c:432).
///
/// SMB counts are not relied on: a listing marks counts unknown
/// (readdir.c:207), which gives a new inode a count of one (inode.c:165),
/// and so does the CREATE response of an open (smb2pdu.c:3383); the real
/// count arrives only when the attribute cache next expires. The client
/// can also stop using the server's file IDs mid-mount
/// (cifs_autodisable_serverino), and whether a server follows a symlink
/// when setting its times is not known.
///
/// Leases are trusted on ext4, XFS, Btrfs, tmpfs and OpenZFS 2.4 (whose
/// `zpl_file.c` uses `generic_setlease`): tests show that an open for
/// writing or a truncate breaks a lease, and that a file open for writing,
/// or mapped writable and shared, is refused one. Network filesystems, FUSE
/// and overlayfs are not trusted: another client, a FUSE server or a write
/// to an overlay's layers changes a file without opening it here, and FUSE
/// grants leases that such writes leave intact.
#[cfg(target_os = "linux")]
const KNOWN_TYPES: [TypeFacts; 31] = [
    // ext2, ext3, ext4: ext4_rename2
    TypeFacts {
        magic: EXT_SUPER_MAGIC,
        kind: "ext",
        local_userspace_copy: true,
        measured_local_source: true,
        direct_io_tested: true,
        quiet_close: true,
        ..LOCAL_TYPE
    },
    // xfs_vn_rename. XFS frees inodes per allocation group and replaces
    // files faster with every worker, so replacing is not bounded there.
    TypeFacts {
        magic: XFS_SUPER_MAGIC,
        kind: "xfs",
        local_userspace_copy: true,
        measured_local_source: true,
        direct_io_tested: true,
        bounds_replacement: false,
        quiet_close: true,
        ..LOCAL_TYPE
    },
    // btrfs_rename2
    TypeFacts {
        magic: BTRFS_SUPER_MAGIC,
        kind: "btrfs",
        quiet_close: true,
        ..LOCAL_TYPE
    },
    // shmem_rename2
    TypeFacts {
        magic: TMPFS_MAGIC,
        kind: "tmpfs",
        local_userspace_copy: true,
        quiet_close: true,
        ..LOCAL_TYPE
    },
    // ovl_rename_start
    TypeFacts {
        magic: OVERLAYFS_SUPER_MAGIC,
        kind: "overlay",
        leases_show_writers: false,
        ..LOCAL_TYPE
    },
    // ZFS locks only the ranges written, so its writes run concurrently.
    TypeFacts {
        magic: ZFS_SUPER_MAGIC,
        kind: "zfs",
        serialized_writes: false,
        quiet_close: true,
        ..LOCAL_TYPE
    },
    TypeFacts {
        magic: F2FS_SUPER_MAGIC,
        kind: "f2fs",
        leases_show_writers: false,
        quiet_close: true,
        ..LOCAL_TYPE
    },
    TypeFacts {
        magic: NTFS3_SUPER_MAGIC,
        kind: "ntfs3",
        owners: Owners::Fixed,
        links: Links::Trusted,
        quiet_close: true,
        ..REFUSES_RENAME_FLAGS
    },
    TypeFacts {
        magic: EXFAT_SUPER_MAGIC,
        kind: "exfat",
        owners: Owners::Fixed,
        links: Links::OneNameEach,
        quiet_close: true,
        ..REFUSES_RENAME_FLAGS
    },
    // vfat_rename2, msdos_rename. FAT keeps modification times in
    // two-second steps; exFAT keeps 10 ms, which the ordinary comparison
    // of significant digits already covers.
    TypeFacts {
        magic: FAT_SUPER_MAGIC,
        kind: FAT_KIND,
        owners: Owners::Fixed,
        links: Links::OneNameEach,
        quiet_close: true,
        ..REFUSES_RENAME_FLAGS
    },
    of_type(0x4244, REFUSES_RENAME_FLAGS),      // HFS
    of_type(0x482b, REFUSES_RENAME_FLAGS),      // HFS+
    of_type(0x3153_464a, REFUSES_RENAME_FLAGS), // JFS
    of_type(0x3434, REFUSES_RENAME_FLAGS),      // NILFS
    of_type(0x1501_3346, REFUSES_RENAME_FLAGS), // UDF
    of_type(0x0001_1954, REFUSES_RENAME_FLAGS), // UFS
    TypeFacts {
        magic: 0x7461_636f, // OCFS2: refuses every flag
        renames: Renames::ImplementNone,
        ..UNKNOWN_TYPE
    },
    // GFS2 drops the no-replace flag after the local check, so it does not
    // keep another node from the name.
    TypeFacts {
        magic: GFS2_SUPER_MAGIC,
        renames: Renames::RefuseUnsupported {
            atomic_no_replace: false,
        },
        ..UNKNOWN_TYPE
    },
    // CephFS refuses every rename flag.
    TypeFacts {
        magic: CEPH_SUPER_MAGIC,
        kind: "ceph",
        links: Links::TrustedWithout(b"ino32"),
        ..NETWORK_WITHOUT_RENAME_FLAGS
    },
    // NFS refuses every rename flag.
    TypeFacts {
        magic: NFS_SUPER_MAGIC,
        kind: "nfs",
        links: Links::TrustedWithout(b"nocto"),
        ..NETWORK_WITHOUT_RENAME_FLAGS
    },
    of_type(CIFS_SUPER_MAGIC, SMB_TYPE),
    of_type(SMB2_SUPER_MAGIC, SMB_TYPE),
    // The old SMB client's type, whose rename handler was not audited.
    TypeFacts {
        magic: libc::SMB_SUPER_MAGIC as u32,
        network: true,
        owners: Owners::Fixed,
        ..UNKNOWN_TYPE
    },
    // 9p refuses every rename flag. WSL 2 mounts Windows drives (drvfs) as
    // 9p, with fixed owners.
    TypeFacts {
        magic: V9FS_MAGIC,
        owners: Owners::ByMount,
        renames: Renames::ImplementNone,
        ..UNKNOWN_TYPE
    },
    // AFS gives flags only to YFS servers, else ENOTSUPP.
    of_type(0x6b41_4653, REFUSES_RENAME_FLAGS),
    of_type(0x5346_414f, REFUSES_RENAME_FLAGS), // AFS
    of_type(0x2405_1905, REFUSES_RENAME_FLAGS), // UBIFS
    of_type(0x72b6, REFUSES_RENAME_FLAGS),      // JFFS2
    TypeFacts {
        magic: 0x7375_7245, // Coda: refuses every flag
        renames: Renames::ImplementNone,
        ..UNKNOWN_TYPE
    },
    TypeFacts {
        magic: 0x786f_4256, // vboxsf: refuses every flag
        owners: Owners::Fixed,
        renames: Renames::ImplementNone,
        ..UNKNOWN_TYPE
    },
    // FUSE (also virtiofs) passes rename flags to a userspace server, which
    // could ignore them. Block devices it serves (`fuseblk`: ntfs-3g,
    // exfat-fuse) have fixed owners.
    TypeFacts {
        magic: FUSE_SUPER_MAGIC,
        network: true,
        owners: Owners::ByMount,
        ..UNKNOWN_TYPE
    },
];

/// The facts of filesystem type `magic`, or those of an unknown type.
#[cfg(target_os = "linux")]
pub(crate) fn type_facts(magic: u32) -> &'static TypeFacts {
    KNOWN_TYPES
        .iter()
        .find(|facts| facts.magic == magic)
        .unwrap_or(&UNKNOWN_TYPE)
}

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
    /// (`write_gate`): on most filesystems a buffered write holds the
    /// file's inode lock, so writes to one file run one at a time anyway and
    /// contend inside the filesystem, and serializing them saves CPU at the
    /// same speed (measured on local disk and NFS). Only the write requests
    /// are serialized, never the zero scan of a sparse write. ZFS locks only
    /// the ranges written, so there they run concurrently, which is faster.
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
    let Ok(file_system) = file_system_of(file) else {
        return false;
    };
    #[cfg(target_os = "linux")]
    {
        file_system.facts().reports_owners_faithfully
    }
    #[cfg(target_os = "macos")]
    {
        matches!(file_system.kind(), b"apfs" | b"hfs")
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = file_system;
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
    let Ok(file_system) = file_system_at(&path) else {
        return false;
    };
    #[cfg(target_os = "linux")]
    {
        match file_system.facts().owners {
            Owners::Kept => false,
            Owners::Fixed => true,
            Owners::ByMount => mount_fields_at(&path)
                .is_some_and(|(kind, options)| linux_mount_fixes_owners_and_modes(&kind, &options)),
        }
    }
    #[cfg(target_os = "macos")]
    {
        macos_fixed_owners_and_modes(file_system.kind(), file_system.flags())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = file_system;
        false
    }
}

/// Whether a read lease on `file` shows every write to it (`leases`): the
/// filesystem grants leases, and its files change only through opens in
/// this kernel, which break them (`TypeFacts::leases_show_writers`).
#[cfg(target_os = "linux")]
pub(crate) fn leases_show_writers(file: &File) -> bool {
    file_system_of(file).is_ok_and(|file_system| leases_trusted(file_system.facts()))
}

/// Whether leases are trusted on a filesystem with these facts. Debug
/// builds given `SYQ_TEST_LEASES=unsupported` trust no filesystem.
#[cfg(target_os = "linux")]
pub(crate) fn leases_trusted(facts: &TypeFacts) -> bool {
    #[cfg(debug_assertions)]
    if std::env::var_os("SYQ_TEST_LEASES").is_some_and(|value| value == "unsupported") {
        return false;
    }
    facts.leases_show_writers
}

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
    profile_of_type(type_facts(file_system_type), |option| {
        mount_has_option(file, key, option)
    })
}

/// The profile of a filesystem type, given whether its mount has an option.
#[cfg(target_os = "linux")]
fn profile_of_type(facts: &TypeFacts, mount_has_option: impl FnOnce(&[u8]) -> bool) -> Profile {
    let (exchange, atomic_no_replace_rename) = match facts.renames {
        Renames::RefuseUnsupported { atomic_no_replace } => (true, atomic_no_replace),
        Renames::NotAudited | Renames::ImplementNone => (false, false),
    };
    let (link_counts_trusted, symlink_times) = match facts.links {
        Links::Trusted => (true, true),
        Links::TrustedWithout(option) => (!mount_has_option(option), true),
        Links::OneNameEach => (true, false),
        Links::Untrusted => (false, false),
    };
    Profile {
        exchange,
        atomic_no_replace_rename,
        hard_links: facts.links != Links::OneNameEach,
        link_counts_trusted,
        symlink_times,
        two_second_mtimes: facts.kind == FAT_KIND,
        audited: facts.renames != Renames::NotAudited,
        serialized_writes: facts.serialized_writes,
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
    // SAFETY: the caller's descriptor stays open for this call.
    let file = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
    let file_system = file_system_of(&file).ok()?;
    let mount = file_system.mount_point();
    let kind = file_system.kind();
    let mut identity = file_system.fsid().to_vec();
    identity.extend_from_slice(mount.to_bytes_with_nul());
    identity.extend_from_slice(kind);
    Some(Volume {
        identity,
        mount: mount.to_owned(),
        kind: kind.to_vec(),
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

    /// Every filesystem type syq treats specially, and a few it does not,
    /// with what each implies, as the separate lists that `KNOWN_TYPES`
    /// replaced gave it. Columns: type, reported kind; network, leases show
    /// writers, owners reported faithfully, owners fixed, owners decided
    /// by the mount; userspace copy ranges, measured local source, direct
    /// I/O tested, replacement bounded, a close that reports no write
    /// error; then the profile on a mount without
    /// `nocto` or `ino32`: exchange, atomic no-replace rename, hard links,
    /// link counts trusted, symlink times, two-second times, audited,
    /// serialized writes.
    #[cfg(target_os = "linux")]
    type PinnedRow = (
        u32,
        &'static str,
        u8,
        u8,
        u8,
        u8,
        u8,
        u8,
        u8,
        u8,
        u8,
        u8,
        [u8; 8],
    );

    #[cfg(target_os = "linux")]
    #[rustfmt::skip]
    const PINNED: [PinnedRow; 35] = [
    (0x0000ef53, "ext", 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, [1, 1, 1, 1, 1, 0, 1, 1]),
    (0x58465342, "xfs", 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, [1, 1, 1, 1, 1, 0, 1, 1]),
    (0x9123683e, "btrfs", 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, [1, 1, 1, 1, 1, 0, 1, 1]),
    (0x01021994, "tmpfs", 0, 1, 1, 0, 0, 1, 0, 0, 1, 1, [1, 1, 1, 1, 1, 0, 1, 1]),
    (0x794c7630, "overlay", 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, [1, 1, 1, 1, 1, 0, 1, 1]),
    (0x2fc12fc1, "zfs", 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, [1, 1, 1, 1, 1, 0, 1, 0]),
    (0xf2f52010, "f2fs", 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, [1, 1, 1, 1, 1, 0, 1, 1]),
    (0x7366746e, "ntfs3", 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, [1, 1, 1, 1, 1, 0, 1, 1]),
    (0x2011bab0, "exfat", 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, [1, 1, 0, 1, 0, 0, 1, 1]),
    (0x00004d44, "fat", 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, [1, 1, 0, 1, 0, 1, 1, 1]),
    (0x00004244, "other", 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, [1, 1, 1, 0, 0, 0, 1, 1]),
    (0x0000482b, "other", 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, [1, 1, 1, 0, 0, 0, 1, 1]),
    (0x3153464a, "other", 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, [1, 1, 1, 0, 0, 0, 1, 1]),
    (0x00003434, "other", 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, [1, 1, 1, 0, 0, 0, 1, 1]),
    (0x15013346, "other", 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, [1, 1, 1, 0, 0, 0, 1, 1]),
    (0x00011954, "other", 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, [1, 1, 1, 0, 0, 0, 1, 1]),
    (0x7461636f, "other", 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, [0, 0, 1, 0, 0, 0, 1, 1]),
    (0x01161970, "other", 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, [1, 0, 1, 0, 0, 0, 1, 1]),
    (0x00c36400, "ceph", 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, [0, 0, 1, 1, 1, 0, 1, 1]),
    (0x00006969, "nfs", 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, [0, 0, 1, 1, 1, 0, 1, 1]),
    (0xff534d42, "other", 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, [1, 0, 1, 0, 0, 0, 1, 1]),
    (0xfe534d42, "other", 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, [1, 0, 1, 0, 0, 0, 1, 1]),
    (0x01021997, "other", 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, [0, 0, 1, 0, 0, 0, 1, 1]),
    (0x6b414653, "other", 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, [1, 1, 1, 0, 0, 0, 1, 1]),
    (0x5346414f, "other", 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, [1, 1, 1, 0, 0, 0, 1, 1]),
    (0x24051905, "other", 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, [1, 1, 1, 0, 0, 0, 1, 1]),
    (0x000072b6, "other", 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, [1, 1, 1, 0, 0, 0, 1, 1]),
    (0x73757245, "other", 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, [0, 0, 1, 0, 0, 0, 1, 1]),
    (0x786f4256, "other", 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, [0, 0, 1, 0, 0, 0, 1, 1]),
    (0x65735546, "other", 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, [0, 0, 1, 0, 0, 0, 0, 1]),
    (0x0000517b, "other", 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, [0, 0, 1, 0, 0, 0, 0, 1]),
    (0x00009fa0, "other", 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, [0, 0, 1, 0, 0, 0, 0, 1]),
    (0x5346544e, "other", 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, [0, 0, 1, 0, 0, 0, 0, 1]),
    (0xca451a4e, "other", 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, [0, 0, 1, 0, 0, 0, 0, 1]),
    (0x12345678, "other", 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, [0, 0, 1, 0, 0, 0, 0, 1]),
    ];

    #[cfg(target_os = "linux")]
    #[test]
    fn type_facts_keep_their_answers() {
        for (
            magic,
            kind,
            network,
            leases,
            faithful,
            fixed,
            by_mount,
            userspace,
            measured,
            direct,
            bounds,
            quiet,
            profile,
        ) in PINNED
        {
            let facts = type_facts(magic);
            let bit = |value: bool| u8::from(value);
            let read = profile_of_type(facts, |_| false);
            assert_eq!(
                (
                    facts.kind,
                    bit(facts.network),
                    bit(facts.leases_show_writers),
                    bit(facts.reports_owners_faithfully),
                    bit(facts.owners == Owners::Fixed),
                    bit(facts.owners == Owners::ByMount),
                    bit(facts.local_userspace_copy),
                    bit(facts.measured_local_source),
                    bit(facts.direct_io_tested),
                    bit(facts.bounds_replacement),
                    bit(facts.quiet_close),
                    [
                        bit(read.exchange),
                        bit(read.atomic_no_replace_rename),
                        bit(read.hard_links),
                        bit(read.link_counts_trusted),
                        bit(read.symlink_times),
                        bit(read.two_second_mtimes),
                        bit(read.audited),
                        bit(read.serialized_writes),
                    ],
                ),
                (
                    kind, network, leases, faithful, fixed, by_mount, userspace, measured, direct,
                    bounds, quiet, profile
                ),
                "{magic:#x}"
            );
        }
        // Each known type is listed once and pinned above.
        for facts in KNOWN_TYPES {
            assert_eq!(
                KNOWN_TYPES
                    .iter()
                    .filter(|other| other.magic == facts.magic)
                    .count(),
                1,
                "{:#x}",
                facts.magic
            );
            assert!(
                PINNED.iter().any(|row| row.0 == facts.magic),
                "{:#x}",
                facts.magic
            );
        }
        // A mount option that makes counts unreliable is honoured.
        assert!(
            !profile_of_type(type_facts(NFS_SUPER_MAGIC), |option| option == b"nocto")
                .link_counts_trusted
        );
        assert!(
            !profile_of_type(type_facts(CEPH_SUPER_MAGIC), |option| option == b"ino32")
                .link_counts_trusted
        );
        // Leases are trusted only on local filesystems that break them.
        let trusted: Vec<_> = KNOWN_TYPES
            .iter()
            .filter(|facts| leases_trusted(facts))
            .map(|facts| facts.kind)
            .collect();
        assert_eq!(trusted, ["ext", "xfs", "btrfs", "tmpfs", "zfs"]);
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

    /// A close is trusted to report nothing on exactly the local types
    /// audited for it. Every filesystem that flushes at close, or sits on
    /// one that may, and every type not listed keeps the check of its
    /// writes.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_close_is_quiet_only_on_the_audited_local_types() {
        let mut quiet: Vec<u32> = KNOWN_TYPES
            .iter()
            .filter(|facts| facts.quiet_close)
            .map(|facts| facts.magic)
            .collect();
        quiet.sort_unstable();
        let mut audited = [
            EXT_SUPER_MAGIC,
            XFS_SUPER_MAGIC,
            BTRFS_SUPER_MAGIC,
            TMPFS_MAGIC,
            ZFS_SUPER_MAGIC,
            F2FS_SUPER_MAGIC,
            NTFS3_SUPER_MAGIC,
            EXFAT_SUPER_MAGIC,
            FAT_SUPER_MAGIC,
        ];
        audited.sort_unstable();
        assert_eq!(quiet, audited);
        for checked in [
            NFS_SUPER_MAGIC,
            FUSE_SUPER_MAGIC,
            CIFS_SUPER_MAGIC,
            SMB2_SUPER_MAGIC,
            OVERLAYFS_SUPER_MAGIC,
            CEPH_SUPER_MAGIC,
            V9FS_MAGIC,
            libc::ECRYPTFS_SUPER_MAGIC as u32,
            0x2011_3221, // OrangeFS
            0x1234_5678,
        ] {
            assert!(!type_facts(checked).quiet_close, "{checked:#x}");
        }
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
        for kind in ["ext", "xfs", "tmpfs", "btrfs", "overlay", "zfs", "nfs"] {
            assert!(kind_sets_symlink_times(kind), "{kind}");
            assert!(linux_kind_profile_sets_symlink_times(kind), "{kind}");
        }
        assert!(!kind_sets_symlink_times("other"));
        assert!(!kind_sets_symlink_times(FAT_KIND));
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

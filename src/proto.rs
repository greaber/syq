//! Wire protocol: message types and length-prefixed framing.
//!
//! Every connection (control or data) speaks the same request/response
//! protocol. Frames are `u32 len | u8 flags | payload`, payload is postcard;
//! flag bit 0 means the payload is zstd-compressed. Each writer decides
//! independently whether to compress, readers always accept both.

use crate::descriptor_broker::{DescriptorTicket, RegisteredRootId};
use anyhow::{bail, Result};
use serde::{Deserialize, Deserializer, Serialize};
use std::io::{self, BufReader, BufWriter, Read, Write};

pub const MAX_FRAME: usize = 256 * 1024 * 1024;
pub const MIN_HASH_BLOCK_BYTES: u64 = 64 * 1024;
pub const MAX_HASH_BLOCK_BYTES: u64 = 64 * 1024 * 1024;
const HASH_RESPONSE_BYTES_PER_ENTRY: u64 = 32;
const HASH_RESPONSE_OVERHEAD: u64 = 24;
const COMPRESS_MIN: usize = 512;
const COMPRESS_LEVEL: i32 = 1;
#[cfg(target_os = "linux")]
const MODE_SYMLINK: u32 = libc::S_IFLNK;
#[cfg(not(target_os = "linux"))]
const MODE_SYMLINK: u32 = libc::S_IFLNK as u32;

pub fn hash_response_fits(block: u64, len: u64) -> bool {
    if !(MIN_HASH_BLOCK_BYTES..=MAX_HASH_BLOCK_BYTES).contains(&block) {
        return false;
    }
    let entries = len.div_ceil(block);
    entries
        .checked_mul(HASH_RESPONSE_BYTES_PER_ENTRY)
        .and_then(|bytes| bytes.checked_add(HASH_RESPONSE_OVERHEAD))
        .is_some_and(|bytes| bytes < MAX_FRAME as u64)
}

/// Path bytes, as given by the user (absolute, or relative to the server's cwd).
pub type PathBytes = Vec<u8>;

/// A syntactically strict descriptor-relative source path.
///
/// Source discovery and stat operations use this reference as their authority;
/// the parallel legacy pathname is only a display/compatibility spelling.
#[derive(Serialize, Clone, Debug, Eq, PartialEq)]
pub struct RegisteredPath {
    pub(crate) root: RegisteredRootId,
    pub relative: PathBytes,
}

impl RegisteredPath {
    pub(crate) fn new(root: RegisteredRootId, relative: PathBytes) -> Result<Self> {
        validate_relative_path(&relative)?;
        Ok(Self { root, relative })
    }

    pub(crate) fn root(&self) -> RegisteredRootId {
        self.root
    }

    pub(crate) fn join(&self, relative: &[u8]) -> Result<Self> {
        validate_relative_path(relative)?;
        let mut joined = self.relative.clone();
        if !joined.is_empty() && !relative.is_empty() {
            joined.push(b'/');
        }
        joined.extend_from_slice(relative);
        Self::new(self.root, joined)
    }
}

impl<'de> Deserialize<'de> for RegisteredPath {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct WirePath {
            root: RegisteredRootId,
            relative: PathBytes,
        }
        let wire = WirePath::deserialize(deserializer)?;
        RegisteredPath::new(wire.root, wire.relative).map_err(serde::de::Error::custom)
    }
}

fn validate_relative_path(path: &[u8]) -> Result<()> {
    if path.starts_with(b"/") {
        bail!("registered path must be relative");
    }
    if path.contains(&0) {
        bail!("registered path contains NUL");
    }
    if path.is_empty() {
        return Ok(());
    }
    if path
        .split(|byte| *byte == b'/')
        .any(|component| component.is_empty() || component == b"." || component == b"..")
    {
        bail!("registered path contains an unsafe component");
    }
    Ok(())
}
/// Full BLAKE3 digest used whenever content equality affects copy behavior.
pub type ContentDigest = [u8; 32];

/// Stable identifier for one logical copy command. Destination partial names
/// include this value so unrelated commands never write the same staged inode.
pub type PartialId = [u8; 16];

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Dir,
    File,
    Symlink,
    Fifo,
    Socket,
    CharDev,
    BlockDev,
    Other,
}

/// How a directly supplied endpoint pathname treats symlink components.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum OperatorSymlinkPolicy {
    /// Native default: refuse every symlink that resolution would traverse.
    Refuse,
    /// Rsync compatibility: follow links owned by root or the endpoint euid.
    TrustedOwner,
    /// Explicit convenience mode: follow links regardless of ownership.
    FollowAll,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Entry {
    /// Relative to the scan root; empty means the root itself.
    pub path: PathBytes,
    pub kind: Kind,
    pub size: u64,
    pub mtime: i64,
    pub mtime_nsec: u32,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u64,
    /// Device and inode, for detecting src==dst (same file / hardlink / alias).
    pub dev: u64,
    pub ino: u64,
    /// Status-change time completes the identity fingerprint used to detect an
    /// unlink/recreate race that happens to reuse the same inode number.
    pub ctime: i64,
    pub ctime_nsec: u32,
    pub link: Option<PathBytes>,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum NativeRemoveKind {
    Any,
    Contents,
    File,
    Directory,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NativeRemoveSelection {
    pub path: PathBytes,
    pub kind: NativeRemoveKind,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NativeRemoveOutcome {
    /// Diagnostic spelling rooted at the selector base, never a pathname used
    /// to rediscover the selected object.
    pub path: PathBytes,
    pub error: Option<String>,
}

impl Entry {
    pub fn meta(&self) -> Meta {
        Meta {
            mode: self.mode,
            uid: self.uid,
            gid: self.gid,
            mtime: self.mtime,
            mtime_nsec: self.mtime_nsec,
        }
    }
}

/// A target condition carried to the receiver that performs the mutation.
/// `Absent` is enforced with no-replace creation/publication; the matching
/// variants bind an existing-target operation to the object the planner saw.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum TargetCondition {
    #[default]
    Any,
    Absent,
    Matches {
        dev: u64,
        ino: u64,
    },
    MatchesFingerprint {
        dev: u64,
        ino: u64,
        ctime: i64,
        ctime_nsec: u32,
    },
}

/// Stable authority boundary for every descendant mutation in a guarded
/// native placement.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct ContainerGuard {
    pub root: PathBytes,
    pub dev: u64,
    pub ino: u64,
}

/// One whole-file read in the pipelined small-file path.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SmallRead {
    pub path: PathBytes,
    /// Authoritative source capability. `path` is only a diagnostic/legacy
    /// spelling when this is present; omission is reserved for the explicit
    /// rsync `--insecure-links` compatibility path.
    pub source: Option<RegisteredPath>,
    pub attempt: u32,
    pub len: u32,
}

/// One whole-file publication in the pipelined small-file path.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SmallPut {
    pub path: PathBytes,
    pub partial_id: PartialId,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
    pub hash: ContentDigest,
    pub meta: Meta,
    pub flags: u8,
    /// Write the final name directly. This is used only for the caller's
    /// explicit --inplace policy; the default keeps atomic sidecar publication.
    pub inplace: bool,
    pub condition: TargetCondition,
    pub guard: Option<ContainerGuard>,
}

/// Contents and integrity hash for one successful `SmallRead`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SmallBlock {
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
    pub hash: ContentDigest,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub struct Meta {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: i64,
    pub mtime_nsec: u32,
}

/// Which parts of a `Meta` to apply.
pub mod flags {
    pub const MODE: u8 = 1;
    pub const OWNER: u8 = 2;
    pub const GROUP: u8 = 4;
    pub const TIMES: u8 = 8;
    /// A mode proposed by ordinary destination creation/restoration semantics,
    /// rather than source-mode preservation requested with `-p`. Restricted
    /// receivers replace it with a mode derived from receiver state and umask,
    /// including any receiver-observed directory setgid inheritance.
    pub const RECEIVER_MODE: u8 = 16;
    pub const MODE_MASK: u8 = MODE | RECEIVER_MODE;
}

/// Best-effort kernel counters for one end of a TCP data socket. `None` means
/// the platform or returned kernel structure does not expose that field; a
/// reported zero is therefore a genuine measurement.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct TcpSocketStats {
    pub congestion_control: Option<String>,
    pub bytes_sent: Option<u64>,
    pub bytes_retransmitted: Option<u64>,
    pub segments_sent: Option<u64>,
    pub segments_received: Option<u64>,
    pub retransmissions: Option<u64>,
    pub rtt_us: Option<u64>,
    pub rtt_variance_us: Option<u64>,
    pub min_rtt_us: Option<u64>,
    pub send_cwnd_bytes: Option<u64>,
    pub delivery_rate: Option<u64>,
    pub busy_time_us: Option<u64>,
    pub receive_window_limited_us: Option<u64>,
    pub send_buffer_limited_us: Option<u64>,
    pub ecn_ce_delivered: Option<u64>,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum Which {
    Final,
    Partial,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Op {
    Mkdir {
        path: PathBytes,
        mode: u32,
        condition: TargetCondition,
    },
    Symlink {
        path: PathBytes,
        target: PathBytes,
        condition: TargetCondition,
    },
    Mknod {
        path: PathBytes,
        mode: u32,
        rdev: u64,
        condition: TargetCondition,
    },
    SetMeta {
        path: PathBytes,
        meta: Meta,
        flags: u8,
        condition: TargetCondition,
    },
    /// Apply metadata to a regular file only if the path still satisfies the
    /// planner's condition.
    SetFileMetaIfSame {
        path: PathBytes,
        condition: TargetCondition,
        meta: Meta,
        flags: u8,
    },
    /// Remove whatever currently occupies the path, recursively when it is a
    /// directory. Planned deletion uses Unlink/Rmdir instead.
    Remove { path: PathBytes },
    /// Remove an empty directory.
    Rmdir { path: PathBytes },
    /// Remove a non-directory; a directory that has appeared there is an
    /// error, never recursed into (used by --delete for planned leaves).
    Unlink { path: PathBytes },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DestinationRoot {
    pub ticket: DescriptorTicket,
    pub request_prefix: PathBytes,
}

/// Serialized identity of one exact non-directory source selection. The
/// descriptor session and every initialized worker keep the originally opened
/// object alive while workers use this identity to reject a replaced name
/// beneath the retained parent. Symlink targets are snapshotted through that
/// opened object and are never reread through the mutable name.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct SourceLeafIdentity {
    pub dev: u64,
    pub ino: u64,
    pub file_type: u32,
    pub symlink_target: Option<PathBytes>,
}

/// One operator source selection registered by the endpoint control session.
/// `selection` is either empty beneath a selected directory or a literal leaf
/// beneath its selected parent.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RegisteredSourceRoot {
    pub ticket: DescriptorTicket,
    /// Present only for an exact non-directory selection. This typed ticket
    /// names the original selected object, not its containing directory.
    pub leaf_ticket: Option<DescriptorTicket>,
    pub selection: RegisteredPath,
    /// Present only for an exact leaf. Every worker acquires and retains its
    /// own clone of `leaf_ticket` before acknowledging readiness, preventing
    /// identity reuse even if the control connection exits first.
    pub expected_leaf: Option<SourceLeafIdentity>,
    /// Permit this explicitly opted-in rsync session to use legacy unconfined
    /// source pathnames for `--insecure-links` compatibility.
    pub allow_unconfined_paths: bool,
}

impl RegisteredSourceRoot {
    pub(crate) fn validate(&self) -> Result<()> {
        if !self.ticket.is_directory() {
            bail!("source root requires a directory descriptor ticket");
        }
        if self.ticket.root_id() != self.selection.root() {
            bail!("source root ticket and registered path identify different roots");
        }
        let exact_leaf = !self.selection.relative.is_empty();
        if exact_leaf != self.expected_leaf.is_some() || exact_leaf != self.leaf_ticket.is_some() {
            bail!("source root leaf selection and expected identity disagree");
        }
        if exact_leaf && self.selection.relative.contains(&b'/') {
            bail!("exact source leaf selection must be one literal component");
        }
        if let Some(expected) = &self.expected_leaf {
            let is_symlink = expected.file_type == MODE_SYMLINK;
            if is_symlink != expected.symlink_target.is_some() {
                bail!("source leaf type and symlink target disagree");
            }
            if expected
                .symlink_target
                .as_ref()
                .is_some_and(|target| target.len() > libc::PATH_MAX as usize * 2)
            {
                bail!("registered source symlink target is too long");
            }
        }
        if let Some(ticket) = &self.leaf_ticket {
            if !ticket.is_source_leaf() {
                bail!("source leaf requires an exact-object descriptor ticket");
            }
            if ticket.root_id() != self.selection.root() {
                bail!("source leaf ticket and registered path identify different roots");
            }
            if !ticket.same_session(&self.ticket) {
                bail!("source parent and leaf tickets belong to different endpoint sessions");
            }
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SourceRootSelection {
    pub path: PathBytes,
    pub follow_root: bool,
}

/// One endpoint-local base for a batch of operator source selections. `None`
/// means the endpoint process's working directory. A confined base is the
/// native `--root` boundary; an unconfined base is native `--cwd` or the
/// process working directory.
#[derive(Serialize, Deserialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct SourceRootBase {
    pub path: Option<PathBytes>,
    pub confined: bool,
}

impl SourceRootBase {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.confined && self.path.is_none() {
            bail!("a confined source base requires an explicit path");
        }
        if let Some(path) = &self.path {
            if path.is_empty() {
                bail!("source base may not be empty");
            }
            if path.contains(&0) {
                bail!("source base contains NUL");
            }
        }
        Ok(())
    }
}

/// Compare effective destination directories beneath the receiver's retained
/// operator selection with one exact source-directory capability. `suffixes`
/// are operator-relative spellings rather than transfer paths: an empty value
/// names the selected destination directory, and `.` or `..` retain their
/// ordinary component semantics.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DirectoryAncestryCheck {
    pub source_root: DescriptorTicket,
    pub suffixes: Vec<PathBytes>,
}

/// Relationship of one effective destination directory to its source root.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryRelation {
    Separate,
    Same,
    Descendant,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum ConnectionRole {
    /// The one connection allowed to create endpoint-session capabilities and
    /// start its TCP data listener.
    Control,
    /// A data connection reserved for reading a source endpoint. Discovery
    /// metadata, block/file hashes, and range/small reads are confined to the
    /// registered roots unless the registration explicitly permits the rsync
    /// `--insecure-links` compatibility path.
    SourceWorker {
        /// Every registered parent and exact-object descriptor is acquired
        /// before HelloOk. Local and same-process TCP workers clone in process;
        /// a fresh SSH helper finishes SCM_RIGHTS receipt while single-threaded.
        roots: Vec<RegisteredSourceRoot>,
    },
    /// A data connection used to mutate a destination endpoint. Unrestricted
    /// receivers require an exact registered root; restricted receivers derive
    /// their confinement from the signed grant and reject a supplied ticket.
    /// A same-machine worker may additionally receive source capabilities for
    /// `CopyLocal`; no other destination request may use them.
    DestinationWorker {
        destination: Option<DestinationRoot>,
        copy_sources: Vec<RegisteredSourceRoot>,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Request {
    Hello {
        identity: String,
        compress: bool,
        debug: bool,
        token: Vec<u8>,
        role: ConnectionRole,
    },
    /// Ask the server to accept data connections over TCP (see crypto.rs).
    /// `key` is None for plaintext; `token` authenticates plaintext connections.
    TcpListen {
        key: Option<Vec<u8>>,
        token: Vec<u8>,
        port_lo: u16,
        port_hi: u16,
        congestion_control: Option<String>,
    },
    /// `ignore`: gitignore-style patterns relative to `root` (see scan.rs).
    /// `report_ignored`: also send the paths the patterns pruned (ScanIgnored).
    Scan {
        root: PathBytes,
        /// Authoritative registered source reference. Its parallel `root`
        /// spelling is used only by the explicit `--insecure-links` opt-out.
        source: Option<RegisteredPath>,
        follow_root: bool,
        ignore: Vec<String>,
        report_ignored: bool,
        guard: Option<ContainerGuard>,
    },
    /// Resolve all native removal selectors to endpoint-owned handles before
    /// mutation, then remove through those handles using an endpoint-local
    /// worker pool.
    NativeRemove {
        cwd: Option<PathBytes>,
        root: Option<PathBytes>,
        selections: Vec<NativeRemoveSelection>,
        follow_symlinks: bool,
        dry_run: bool,
        workers: usize,
    },
    /// lstat each path; with `follow`, stat through symlinks instead.
    StatMany {
        paths: Vec<PathBytes>,
        /// Authoritative registered source references. Parallel `paths` are
        /// used only outside a source session or by `--insecure-links`.
        sources: Option<Vec<RegisteredPath>>,
        follow: bool,
        guard: Option<ContainerGuard>,
    },
    /// Resolve an operator-supplied directory component by component. A
    /// missing suffix is accepted only when requested.
    CheckOperatorDirectory {
        path: PathBytes,
        allow_missing: bool,
        symlink_policy: OperatorSymlinkPolicy,
    },
    /// Compare candidate directories beneath the retained operator selection
    /// with exact source-directory descriptors. This is a control-only safety
    /// query and never reopens either operator pathname.
    CheckOperatorDirectoryAncestry {
        checks: Vec<DirectoryAncestryCheck>,
    },
    /// Resolve every operator source selection, then atomically register its
    /// opened directory or parent descriptor. Only a control connection may
    /// create these endpoint-session capabilities, and it may do so only once
    /// so every issued worker identity keeps its original pins alive.
    RegisterSourceRoots {
        base: SourceRootBase,
        selections: Vec<SourceRootSelection>,
        symlink_policy: OperatorSymlinkPolicy,
        /// Explicit rsync compatibility opt-out. It permits legacy unconfined
        /// source discovery only for the session created by this registration.
        allow_unconfined_paths: bool,
        /// Maximum source workers that can share the control helper process.
        /// Zero still budgets the registry and control connection themselves.
        shared_workers: usize,
        /// Maximum concurrent independent-worker claims against the control
        /// process's private descriptor broker.
        independent_claim_workers: usize,
    },
    /// Create the missing suffix retained by CheckOperatorDirectory, then
    /// return the selected directory's stable identity.
    CreateOperatorDirectory {
        mode: u32,
        /// Refuse a concurrently-created final directory instead of reusing
        /// it. Intermediate directories may still be shared safely.
        require_absent: bool,
    },
    /// Register the destination directory retained by the preceding operator
    /// walk. Only the control connection may create this session capability.
    AnchorDestination {
        expected_dev: u64,
        expected_ino: u64,
        request_prefix: PathBytes,
    },
    /// Inspect the filesystem containing the receiver's retained destination
    /// directory. `target` selects an observed descendant directory when
    /// exact placement retains its parent rather than the directory itself.
    DestinationFilesystemInfo {
        /// Only meaningful for an existing selected destination directory.
        /// Failure to prove emptiness is reported as None, not as an error.
        check_empty: bool,
        target: Option<DestinationFilesystemTarget>,
    },
    /// Compute the exact receiver-side sidecar names for collision preflight.
    PartialPaths {
        paths: Vec<PathBytes>,
        partial_id: PartialId,
        guard: Option<ContainerGuard>,
    },
    Apply {
        ops: Vec<Op>,
        guard: Option<ContainerGuard>,
    },
    /// Resolve sidecar names and inspect an existing destination batch in one
    /// turn. Leaf stats are returned only when every directory is still a
    /// directory, so callers can preserve parent-before-child replacement.
    PlanBatch {
        partial_paths: Vec<PathBytes>,
        partial_id: PartialId,
        directories: Vec<PathBytes>,
        others: Vec<PathBytes>,
        guard: Option<ContainerGuard>,
    },
    /// Return the size of the deterministic sidecar, if it is a regular file.
    /// The planner has already statted the final path.
    ProbePartial {
        path: PathBytes,
        partial_id: PartialId,
        guard: Option<ContainerGuard>,
    },
    /// Inspect and, when requested, create/adjust the write target for `path`.
    /// Returns PartialSize with the size observed before any adjustment. A
    /// false `create_if_missing` lets content-identical final files complete
    /// without ever allocating a sidecar.
    /// `mode` is the creation mode for `--inplace`; resumable sidecars remain
    /// private until final metadata is applied immediately before publication.
    Prepare {
        path: PathBytes,
        size: u64,
        inplace: bool,
        partial_id: PartialId,
        mode: u32,
        attempt: u32,
        create_if_missing: bool,
        guard: Option<ContainerGuard>,
    },
    /// Hash an existing final file and retain that open inode as the repair
    /// basis until FinishBasis or SeedBasis consumes it.
    HashAndHold {
        path: PathBytes,
        partial_id: PartialId,
        block: u64,
        len: u64,
        condition: TargetCondition,
        guard: Option<ContainerGuard>,
    },
    /// Apply metadata through the retained basis descriptor. If another job
    /// renamed over the final path meanwhile, its complete file remains the
    /// winner and this only touches the now-unlinked old inode.
    FinishBasis {
        path: PathBytes,
        partial_id: PartialId,
        meta: Meta,
        flags: u8,
        condition: TargetCondition,
        guard: Option<ContainerGuard>,
    },
    /// Seed this job's sidecar from the retained basis descriptor.
    SeedBasis {
        path: PathBytes,
        partial_id: PartialId,
        len: u64,
        attempt: u32,
        guard: Option<ContainerGuard>,
    },
    /// Receiver-side copy of a same-machine file (copy_file_range when
    /// possible, optionally a sequential userspace fallback for a local
    /// source and asynchronous NFS destination). `CopyLocalUnsupported`
    /// tells the caller to use the normal streaming path.
    CopyLocal {
        source: RegisteredPath,
        dst: PathBytes,
        inplace: bool,
        allow_sequential_nfs_fallback: bool,
        partial_id: PartialId,
        size: u64,
        mode: u32,
    },
    HashBlocks {
        path: PathBytes,
        /// Authoritative for source hashing when present. Destination hashing
        /// omits it; a confined source session rejects an omission.
        source: Option<RegisteredPath>,
        which: Which,
        partial_id: PartialId,
        block: u64,
        len: u64,
        attempt: u32,
        guard: Option<ContainerGuard>,
    },
    ReadRange {
        path: PathBytes,
        /// Authoritative source capability. A confined source session rejects
        /// an omission instead of falling back to `path`.
        source: Option<RegisteredPath>,
        attempt: u32,
        off: u64,
        len: u32,
    },
    /// Read a complete small-file batch in one frame and response.
    ReadSmallBatch(Vec<SmallRead>),
    WriteRange {
        path: PathBytes,
        inplace: bool,
        partial_id: PartialId,
        attempt: u32,
        off: u64,
        hash: ContentDigest,
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
        guard: Option<ContainerGuard>,
    },
    Finalize {
        path: PathBytes,
        inplace: bool,
        partial_id: PartialId,
        meta: Meta,
        flags: u8,
        condition: TargetCondition,
        guard: Option<ContainerGuard>,
    },
    /// Verify and atomically publish a complete small-file batch in one frame.
    PutSmallBatch(Vec<SmallPut>),
    FileHash {
        path: PathBytes,
        /// Authoritative for source hashing when present. Destination hashing
        /// omits it; a confined source session rejects an omission.
        source: Option<RegisteredPath>,
        guard: Option<ContainerGuard>,
    },
    /// Absolute, normalized form of a path on this endpoint (symlinks in the
    /// existing prefix resolved), for a stable job identity.
    Canonicalize {
        path: PathBytes,
        guard: Option<ContainerGuard>,
    },
    /// Kernel TCP_INFO/TCP_CONNECTION_INFO for this end of a direct data
    /// socket. SSH data transports report None at the coordinator instead of
    /// sending this request.
    TransportStats,
    /// Ask a command-restricted receiver for its signed receipt. Issuing it
    /// ends the grant's mutation authority.
    Receipt,
    Shutdown,
}

impl Request {
    /// Requests an authenticated source-worker connection may execute. Keep
    /// this protocol boundary shared by remote dispatch and the in-process
    /// adapter so choosing a local endpoint cannot grant mutation authority.
    pub(crate) fn allowed_on_source_worker(&self) -> bool {
        matches!(
            self,
            Request::Scan { .. }
                | Request::StatMany { .. }
                | Request::HashBlocks { .. }
                | Request::ReadRange { .. }
                | Request::ReadSmallBatch(_)
                | Request::FileHash { .. }
                | Request::TransportStats
                | Request::Shutdown
        )
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Response {
    HelloOk {
        identity: String,
        platform: String,
    },
    /// Each advertised data address with its interface link speed in Mbps
    /// (0 = unknown). The address the client's ssh session arrived on is first.
    TcpListening {
        port: u16,
        addrs: Vec<(String, u32)>,
        congestion_control: Option<String>,
    },
    /// The peer understood the requested per-socket override but its kernel
    /// could not honor it. Keep this distinct from ordinary TCP reachability
    /// failures, for which the coordinator may safely fall back to SSH.
    TcpCongestionRejected(String),
    ScanBatch(Vec<Entry>),
    ScanWarn(String),
    /// Paths (relative to the root) pruned by the ignore patterns.
    ScanIgnored(Vec<PathBytes>),
    ScanDone,
    NativeRemoveTrace(Vec<String>),
    /// An empty batch is an attached native-rm liveness frame.
    NativeRemoveBatch(Vec<NativeRemoveOutcome>),
    NativeRemoveDone,
    Stats(Vec<Option<Entry>>),
    /// Absolute operator spelling plus device/inode of the securely opened
    /// directory, or None when an allowed missing suffix was reached.
    DirectorySelection(Option<DirectoryAnchor>),
    DirectoryRelations(Vec<Vec<DirectoryRelation>>),
    DestinationRegistered(DescriptorTicket),
    SourceRootsRegistered(Vec<RegisteredSourceRoot>),
    DestinationFilesystemInfo(DestinationFilesystemInfo),
    PathResults(Vec<std::result::Result<PathBytes, String>>),
    BatchPlan {
        partial_paths: Vec<std::result::Result<PathBytes, String>>,
        directories: Vec<Option<Entry>>,
        /// None means a directory was missing or a non-directory, so the
        /// caller must apply directory changes before inspecting leaves.
        others: Option<Vec<Option<Entry>>>,
    },
    Applied(Vec<Option<WireError>>),
    PartialSize(Option<u64>),
    Hashes(Vec<ContentDigest>),
    HeldHashes {
        hashes: Vec<ContentDigest>,
        len: u64,
    },
    Block {
        off: u64,
        hash: ContentDigest,
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
    },
    SmallBlocks(Vec<std::result::Result<SmallBlock, String>>),
    FileHash {
        size: u64,
        hash: ContentDigest,
    },
    Path(PathBytes),
    TransportStats(Option<TcpSocketStats>),
    /// One bounded frame of a signed receipt stream. The final frame is marked
    /// inside the canonical frame encoding.
    ReceiptV2(#[serde(with = "serde_bytes")] Vec<u8>),
    Ok,
    /// An endpoint operation failed with a preserved OS error number. Server
    /// and authorization protocol failures continue to use Err(String).
    EndpointError(WireError),
    Err(String),
    /// `CopyLocal` could not use the receiver-side direct-copy path. This is
    /// deliberately distinct from `Err`: filenames and other diagnostics are
    /// untrusted text and must never select a recovery path.
    CopyLocalUnsupported,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct DestinationFilesystemInfo {
    pub device: u64,
    pub available_bytes: u64,
    /// Filesystems that do not expose a meaningful inode population report
    /// None rather than a misleading zero.
    pub available_inodes: Option<u64>,
    pub empty: Option<bool>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct DestinationFilesystemTarget {
    /// Directory path relative to the retained destination root.
    pub relative_path: PathBytes,
    pub dev: u64,
    pub ino: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct WireError {
    pub message: String,
    /// Receiver-derived meaning. Numeric errno values are retained only for
    /// diagnostics because their values differ between operating systems.
    pub io_kind: Option<WireIoKind>,
    pub raw_os_error: Option<i32>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireIoKind {
    NotFound,
    PermissionDenied,
    AlreadyExists,
    InvalidInput,
    NoSpace,
    QuotaExceeded,
    ReadOnly,
    Other,
}

impl WireError {
    pub fn as_str(&self) -> &str {
        &self.message
    }
}

impl From<String> for WireError {
    fn from(message: String) -> Self {
        WireError {
            message,
            io_kind: None,
            raw_os_error: None,
        }
    }
}

impl From<&str> for WireError {
    fn from(message: &str) -> Self {
        message.to_owned().into()
    }
}

impl std::fmt::Display for WireError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for WireError {}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct DirectoryAnchor {
    pub path: PathBytes,
    pub dev: u64,
    pub ino: u64,
}

/// Rough serialized size, so big blocks are encoded without reallocation.
pub trait SizeHint {
    fn size_hint(&self) -> usize;
}

impl SizeHint for Request {
    fn size_hint(&self) -> usize {
        match self {
            Request::WriteRange { data, path, .. } => data.len() + path.len() + 64,
            Request::ReadSmallBatch(reads) => {
                reads.iter().map(|read| read.path.len() + 16).sum::<usize>() + 16
            }
            Request::PutSmallBatch(puts) => {
                puts.iter()
                    .map(|put| put.data.len() + put.path.len() + 96)
                    .sum::<usize>()
                    + 16
            }
            Request::StatMany { paths, .. } => {
                paths.iter().map(|p| p.len() + 8).sum::<usize>() + 16
            }
            Request::PartialPaths { paths, .. } => {
                paths.iter().map(|path| path.len() + 8).sum::<usize>() + 32
            }
            Request::PlanBatch {
                partial_paths,
                directories,
                others,
                ..
            } => {
                partial_paths
                    .iter()
                    .chain(directories)
                    .chain(others)
                    .map(|path| path.len() + 8)
                    .sum::<usize>()
                    + 48
            }
            Request::Apply { ops, .. } => ops.len() * 128 + 16,
            Request::NativeRemove { selections, .. } => {
                selections
                    .iter()
                    .map(|selection| selection.path.len() + 8)
                    .sum::<usize>()
                    + 64
            }
            _ => 256,
        }
    }
}

impl SizeHint for Response {
    fn size_hint(&self) -> usize {
        match self {
            Response::Block { data, .. } => data.len() + 64,
            Response::SmallBlocks(blocks) => {
                blocks
                    .iter()
                    .map(|block| match block {
                        Ok(block) => block.data.len() + 40,
                        Err(error) => error.len() + 8,
                    })
                    .sum::<usize>()
                    + 16
            }
            Response::ScanBatch(v) => v.len() * 160 + 16,
            Response::NativeRemoveBatch(v) => {
                v.iter()
                    .map(|outcome| {
                        outcome.path.len() + outcome.error.as_ref().map_or(0, String::len) + 16
                    })
                    .sum::<usize>()
                    + 16
            }
            Response::Stats(v) => v.len() * 96 + 16,
            Response::BatchPlan {
                partial_paths,
                directories,
                others,
            } => {
                partial_paths.len() * 96
                    + directories.len() * 96
                    + others.as_ref().map_or(0, |items| items.len() * 96)
                    + 32
            }
            Response::Hashes(v) | Response::HeldHashes { hashes: v, .. } => v.len() * 32 + 24,
            Response::ReceiptV2(v) => v.len() + 16,
            _ => 256,
        }
    }
}

pub struct FrameWriter<W: Write> {
    w: BufWriter<W>,
    pub compress: bool,
}

impl<W: Write> FrameWriter<W> {
    pub fn new(w: W, compress: bool) -> Self {
        FrameWriter {
            w: BufWriter::with_capacity(1 << 20, w),
            compress,
        }
    }

    pub fn write_msg<T: Serialize + SizeHint>(&mut self, msg: &T) -> io::Result<()> {
        let payload = postcard::to_extend(msg, Vec::with_capacity(msg.size_hint()))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let mut flag = 0u8;
        let mut body = payload;
        if self.compress && body.len() > COMPRESS_MIN {
            if let Ok(c) = zstd::bulk::compress(&body, COMPRESS_LEVEL) {
                if c.len() < body.len() {
                    body = c;
                    flag = 1;
                }
            }
        }
        let len = body
            .len()
            .checked_add(1)
            .filter(|len| *len <= MAX_FRAME)
            .and_then(|len| u32::try_from(len).ok())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "outgoing frame exceeds limit")
            })?;
        self.w.write_all(&len.to_le_bytes())?;
        self.w.write_all(&[flag])?;
        self.w.write_all(&body)?;
        self.w.flush()
    }
}

pub struct FrameReader<R: Read> {
    r: BufReader<R>,
}

impl<R: Read> FrameReader<R> {
    pub fn new(r: R) -> Self {
        FrameReader {
            r: BufReader::with_capacity(1 << 20, r),
        }
    }

    pub fn read_msg<T: for<'de> Deserialize<'de>>(&mut self) -> io::Result<T> {
        let mut hdr = [0u8; 4];
        self.r.read_exact(&mut hdr)?;
        let len = u32::from_le_bytes(hdr) as usize;
        if len == 0 || len > MAX_FRAME {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("bad frame length {len}"),
            ));
        }
        let mut flag = [0u8; 1];
        self.r.read_exact(&mut flag)?;
        let mut body = vec![0u8; len - 1];
        self.r.read_exact(&mut body)?;
        let payload = if flag[0] & 1 != 0 {
            {
                use std::io::Read as _;
                let mut dec = zstd::stream::read::Decoder::new(&body[..])?;
                let mut out = Vec::new();
                dec.by_ref()
                    .take(MAX_FRAME as u64 + 1)
                    .read_to_end(&mut out)?;
                if out.len() > MAX_FRAME {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "decompressed frame exceeds limit",
                    ));
                }
                out
            }
        } else {
            body
        };
        postcard::from_bytes(&payload).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block_frame(data: Vec<u8>, compress: bool) -> Vec<u8> {
        let mut frame = Vec::new();
        FrameWriter::new(&mut frame, compress)
            .write_msg(&Response::Block {
                off: 7,
                hash: [11; 32],
                data,
            })
            .unwrap();
        frame
    }

    #[test]
    fn compression_is_per_frame_and_never_expands_the_wire_payload() {
        let data = vec![b'a'; 64 * 1024];
        let compressed = block_frame(data.clone(), true);
        assert_eq!(compressed[4], 1, "compressible frame was not compressed");

        let decoded = FrameReader::new(compressed.as_slice())
            .read_msg::<Response>()
            .unwrap();
        match decoded {
            Response::Block {
                off,
                hash,
                data: decoded,
            } => {
                assert_eq!((off, hash), (7, [11; 32]));
                assert_eq!(decoded, data);
            }
            other => panic!("unexpected response {other:?}"),
        }

        let disabled = block_frame(data, false);
        assert_eq!(disabled[4], 0, "disabled compression changed the frame");

        let mut random = vec![0u8; 64 * 1024];
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for byte in &mut random {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = state as u8;
        }
        let incompressible = block_frame(random, true);
        assert_eq!(
            incompressible[4], 0,
            "an expanded compressed representation was selected"
        );
    }

    #[test]
    fn registered_paths_reject_unsafe_wire_components() {
        let temporary = tempfile::tempdir().unwrap();
        let session = crate::descriptor_broker::DescriptorSessionSlot::default();
        let ticket = session
            .register(std::fs::File::open(temporary.path()).unwrap())
            .unwrap();
        let root = ticket.root_id();
        assert_eq!(
            RegisteredPath::new(root, b"safe/non-utf8-\xff".to_vec())
                .unwrap()
                .relative,
            b"safe/non-utf8-\xff"
        );
        for relative in [
            b"/absolute".as_slice(),
            b"a//b",
            b".",
            b"a/../b",
            b"nul\0byte",
        ] {
            let invalid = RegisteredPath {
                root,
                relative: relative.to_vec(),
            };
            let encoded = postcard::to_allocvec(&invalid).unwrap();
            assert!(postcard::from_bytes::<RegisteredPath>(&encoded).is_err());
        }
    }

    #[test]
    fn copy_local_fallback_has_a_structured_wire_response() {
        let mut frame = Vec::new();
        FrameWriter::new(&mut frame, false)
            .write_msg(&Response::CopyLocalUnsupported)
            .unwrap();
        assert!(matches!(
            FrameReader::new(frame.as_slice())
                .read_msg::<Response>()
                .unwrap(),
            Response::CopyLocalUnsupported
        ));
    }
}

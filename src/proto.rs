//! Wire protocol: build-identified preambles, message types, and framing.
//!
//! Every connection (control or data) begins each direction with a plain-byte
//! preamble containing a fixed magic string and the sender's build identity.
//! Only after that identity matches do frames begin. Frames are
//! `u32 len | u8 flags | payload`, payload is postcard; flag bit 0 means the
//! payload is zstd-compressed. Each writer decides independently whether to
//! compress, readers always accept both.

use crate::descriptor_broker::{DescriptorTicket, RegisteredRootId};
use anyhow::{bail, Result};
use serde::{Deserialize, Deserializer, Serialize};
use std::io::{self, BufReader, BufWriter, Read, Write};

// 64 MiB data/batch tuning remains supported, with room for its metadata.
pub const MAX_FRAME: usize = 65 * 1024 * 1024;
/// Largest single `ReadRange` length and largest total `ReadSmallBatch`
/// payload a server accepts. A longer read could never fit in a `MAX_FRAME`
/// response, so it is rejected before the server allocates anything.
pub const MAX_READ_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_HANDSHAKE_FRAME: usize = 1024 * 1024;
const MAX_METADATA_FRAME: usize = 8 * 1024 * 1024;
pub const MIN_HASH_BLOCK_BYTES: u64 = 64 * 1024;
pub const MAX_HASH_BLOCK_BYTES: u64 = 64 * 1024 * 1024;
const HASH_RESPONSE_BYTES_PER_ENTRY: u64 = 32;
const HASH_RESPONSE_OVERHEAD: u64 = 24;
const COMPRESS_MIN: usize = 512;
const COMPRESS_LEVEL: i32 = 1;
const WIRE_PREAMBLE_MAGIC: &[u8; 8] = b"SYQWIRE\0";
const WIRE_PREAMBLE_FIXED_LEN: usize = WIRE_PREAMBLE_MAGIC.len() + 2;
const MAX_BUILD_IDENTITY_BYTES: usize = 512;
pub(crate) const WIRE_PREAMBLE_PROTOCOL_ERROR: &str = "wire preamble protocol error";
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

/// Fresh nonce for one invocation. Workers derive private per-file names from it.
pub type CopyId = [u8; 16];

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

/// One raw directory entry returned for interactive shell completion.
///
/// Completion deliberately needs only the entry name and whether another
/// path component can follow it. Keeping this separate from `Entry` avoids a
/// recursive scan or unnecessary metadata on every press of Tab.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct CompletionEntry {
    pub name: PathBytes,
    pub directory: bool,
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
    Partials,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NativeRemoveSelection {
    pub path: PathBytes,
    pub kind: NativeRemoveKind,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NativeRemoveOutcome {
    /// Zero-based occurrence in the caller's ordered selector list. Repeated
    /// and overlapping selectors deliberately retain distinct identities.
    pub selector: u64,
    /// Diagnostic spelling rooted at the selector base, never a pathname used
    /// to rediscover the selected object.
    pub path: PathBytes,
    /// Absent only when the selected name itself is missing.
    pub kind: Option<Kind>,
    pub disposition: NativeRemoveDisposition,
    /// Live removal attempts, including internal directory retries. Selection
    /// and dry-run records have no attempts.
    pub attempts: Option<u64>,
    pub failure: Option<NativeRemoveFailure>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeRemoveDisposition {
    Resolved,
    Missing,
    WouldRemove,
    Removed,
    AlreadyAbsent,
    Failed,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct NativeRemoveFailure {
    pub error: WireError,
    pub class: NativeRemoveErrorClass,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeRemoveErrorClass {
    Io,
    Conflict,
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
    pub copy_id: CopyId,
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

/// An existing private output and an optional donor are separate states.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct Preparation {
    pub partial_size: Option<u64>,
    pub has_candidates: bool,
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
    /// List at most one bounded page of names in a single directory. This is
    /// a read-only control-connection operation used by shell completion.
    ListDir {
        directory: PathBytes,
        /// When present, the resolved directory must remain beneath this root.
        confined_root: Option<PathBytes>,
        prefix: PathBytes,
        limit: u16,
        symlink_policy: OperatorSymlinkPolicy,
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
        independent_handoff_workers: usize,
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
        copy_id: CopyId,
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
        copy_id: CopyId,
        directories: Vec<PathBytes>,
        others: Vec<PathBytes>,
        guard: Option<ContainerGuard>,
    },
    /// Return the size of this invocation's partial, if it is a regular file.
    /// The planner has already statted the final path.
    ProbePartial {
        path: PathBytes,
        copy_id: CopyId,
        guard: Option<ContainerGuard>,
    },
    /// Inspect and, when requested, create/adjust the write target for `path`.
    /// Returns Prepared with the private size observed before adjustment and
    /// whether donor discovery deferred creation to SeedBasis. A
    /// false `create_if_missing` lets content-identical final files complete
    /// without ever allocating a sidecar.
    /// `mode` is the creation mode for `--inplace`; resumable sidecars remain
    /// private until final metadata is applied immediately before publication.
    Prepare {
        path: PathBytes,
        size: u64,
        inplace: bool,
        copy_id: CopyId,
        mode: u32,
        attempt: u32,
        create_if_missing: bool,
        guard: Option<ContainerGuard>,
    },
    /// Hash an existing final file and retain that open inode as the repair
    /// basis until FinishBasis or SeedBasis consumes it.
    HashAndHold {
        path: PathBytes,
        copy_id: CopyId,
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
        copy_id: CopyId,
        meta: Meta,
        flags: u8,
        condition: TargetCondition,
        guard: Option<ContainerGuard>,
    },
    /// Copy one optional donor into the private sidecar and return hashes of
    /// the exact buffers written. The controller must repair differing blocks
    /// before publication. An existing private sidecar is hashed without copying.
    SeedBasis {
        path: PathBytes,
        copy_id: CopyId,
        len: u64,
        block: u64,
        attempt: u32,
        guard: Option<ContainerGuard>,
    },
    /// Receiver-side copy of a same-machine file (copy_file_range when
    /// possible, otherwise an eligible sequential userspace fallback).
    /// Local and NFS fallback policies are independent. `CopyLocalUnsupported`
    /// tells the caller to use the normal streaming path.
    CopyLocal {
        source: RegisteredPath,
        dst: PathBytes,
        inplace: bool,
        allow_sequential_nfs_fallback: bool,
        /// The planner has multiple files, so whole-file writers can run in
        /// parallel. A single local file retains adaptive range copying.
        allow_sequential_local_fallback: bool,
        copy_id: CopyId,
        size: u64,
        mode: u32,
    },
    HashBlocks {
        path: PathBytes,
        /// Authoritative for source hashing when present. Destination hashing
        /// omits it; a confined source session rejects an omission.
        source: Option<RegisteredPath>,
        which: Which,
        copy_id: CopyId,
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
        copy_id: CopyId,
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
        copy_id: CopyId,
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
    /// existing prefix resolved).
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
    /// One turn for a bounded push of regular files on a fresh control
    /// session: retain and register the destination directory, quick-check
    /// existing files, repair metadata and publish changed content through
    /// the ordinary staged path. See `SmallCopyRequest`.
    CopySmallFiles(SmallCopyRequest),
    /// On-demand completion metadata. Appended to preserve existing wire tags.
    ListDirDetails {
        directory: PathBytes,
        confined_root: Option<PathBytes>,
        prefix: PathBytes,
        limit: u16,
        symlink_policy: OperatorSymlinkPolicy,
    },
    /// Experimental source-only stream. Start replies Ok, then emits Block
    /// frames (or one error). StopReadStream is required even at the end of the
    /// interval; ReadStreamDone fences every frame belonging to this stream.
    ReadStream(ReadStreamRequest),
    StopReadStream,
    /// No filesystem operation: fence replies to preceding streaming writes.
    WriteStreamFence,
    /// One-way, monotonic reduction of an active source stream's read limit.
    /// Keep original frame boundaries: a final block may straddle this limit.
    /// StopReadStream is still required, even if the source has passed `end`.
    ShrinkReadStream {
        end: u64,
    },
    /// Removal completion classifies final symlinks as non-directories while
    /// retaining the requested following policy for the directory being listed.
    ListDirNoFollowFinal {
        directory: PathBytes,
        confined_root: Option<PathBytes>,
        prefix: PathBytes,
        limit: u16,
        symlink_policy: OperatorSymlinkPolicy,
        detailed: bool,
    },
    /// Install a signed mapping on the restricted control connection before filesystem requests.
    MappingChunk {
        offset: u64,
        data: Vec<u8>,
        finish: bool,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ReadStreamRequest {
    pub path: PathBytes,
    pub source: Option<RegisteredPath>,
    pub attempt: u32,
    pub off: u64,
    pub end: u64,
    pub block: u32,
}

impl ReadStreamRequest {
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.off < self.end,
            "read stream requires a nonempty increasing interval"
        );
        anyhow::ensure!(
            self.end <= i64::MAX as u64,
            "read stream offset exceeds the file offset limit"
        );
        anyhow::ensure!(
            (512..=64 << 20).contains(&self.block),
            "read stream block must be between 512 bytes and 64 MiB"
        );
        Ok(())
    }

    pub(crate) fn next_request(&self) -> Request {
        Request::ReadRange {
            path: self.path.clone(),
            source: self.source.clone(),
            attempt: self.attempt,
            off: self.off,
            len: (self.end - self.off).min(u64::from(self.block)) as u32,
        }
    }
}

/// Bounds for one-turn small pushes. The receiver enforces them independently
/// of the coordinator's eligibility check.
pub const SMALL_COPY_MAX_FILES: usize = 64;
pub const SMALL_COPY_MAX_FILE_BYTES: u64 = 1 << 20;
pub const SMALL_COPY_MAX_TOTAL_BYTES: u64 = 4 << 20;

/// Fresh invocation identity and optional exact destination leaf for a small push.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SmallCopyIdentity {
    pub copy_id: CopyId,
    pub dst_leaf: Option<PathBytes>,
}

/// One file of a small push. `path` is spelled as the ordinary engine would
/// send it: beneath the request prefix, one component below the selected
/// directory.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SmallCopyFile {
    pub path: PathBytes,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
    pub hash: ContentDigest,
    pub meta: Meta,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SmallCopyRequest {
    /// The operator directory: the `--into` directory, or the parent of an
    /// `--as` leaf. It must already exist.
    pub directory: PathBytes,
    pub symlink_policy: OperatorSymlinkPolicy,
    /// What `AnchorDestination` would register as the request prefix.
    pub request_prefix: PathBytes,
    pub identity: SmallCopyIdentity,
    /// Publication metadata flags, as for `SmallPut`.
    pub flags: u8,
    pub files: Vec<SmallCopyFile>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum SmallCopyOutcome {
    /// Every file was attempted; one result per file in request order.
    Published(Vec<SmallCopyFileResult>),
    /// At least one target is not a regular file. Nothing was written and the
    /// session holds no selection or root, so the ordinary engine can
    /// continue on this connection.
    UnsupportedTarget,
    /// The fresh-destination capacity preflight would refuse this copy.
    /// Nothing was written and the session is untouched; the engine repeats
    /// the preflight and reports the shortage itself.
    CapacityShort,
    /// Staging failed before any final file was published. Sidecars may
    /// remain for resume, and the session now holds the destination root,
    /// so the engine needs a fresh control session to continue.
    StagingFailed(WireError),
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmallCopyDisposition {
    Copied,
    /// Size/mtime matched at planning time; no later source recheck.
    QuickChecked,
    /// Content was read and matched; the source must still be rechecked.
    ContentMatched,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SmallCopyFileResult {
    pub disposition: SmallCopyDisposition,
    pub error: Option<WireError>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SmallCopyResponse {
    pub anchor: DirectoryAnchor,
    pub outcome: SmallCopyOutcome,
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
                | Request::ReadStream(_)
                | Request::StopReadStream
                | Request::ShrinkReadStream { .. }
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
        supports_confined_socket_nodes: bool,
        /// One live restricted copy's SSH worker admission, sent only on its control channel.
        ssh_worker_ticket: Option<Result<String, String>>,
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
    /// Paths (relative to the root) skipped because the ignore patterns matched them.
    ScanIgnored(Vec<PathBytes>),
    ScanDone,
    DirectoryEntries {
        entries: Vec<CompletionEntry>,
        truncated: bool,
    },
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
    Receipt(#[serde(with = "serde_bytes")] Vec<u8>),
    Ok,
    /// An endpoint operation failed with a preserved OS error number. Server
    /// and authorization protocol failures continue to use Err(String).
    EndpointError(WireError),
    Err(String),
    /// `CopyLocal` could not use the receiver-side direct-copy path. This is
    /// deliberately distinct from `Err`: filenames and other diagnostics are
    /// untrusted text and must never select a recovery path.
    CopyLocalUnsupported,
    SmallFilesCopied(SmallCopyResponse),
    /// Parallel entries and endpoint-formatted, terminal-safe metadata columns.
    DetailedDirectoryEntries {
        entries: Vec<CompletionEntry>,
        details: Vec<String>,
        truncated: bool,
    },
    /// All data/error frames for the stopped source stream precede this marker.
    ReadStreamDone,
    WriteStreamDone,
    Prepared(Preparation),
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
    fn frame_limit(&self) -> usize;
    /// Two passes are cheap for a block's byte slice, but substantially more
    /// expensive for metadata encoded one field/byte at a time. Measurements
    /// of CopySmallFiles, PutSmallBatch, and SmallBlocks found mixed results:
    /// larger payloads can benefit, but tiny-file and path-heavy batches slow
    /// down. Keep those variants buffered rather than opting in whole batches.
    fn direct_payload(&self) -> bool {
        false
    }
}

impl SizeHint for Request {
    fn direct_payload(&self) -> bool {
        matches!(self, Request::WriteRange { .. })
    }
    fn frame_limit(&self) -> usize {
        match self {
            Request::Hello { .. } => MAX_HANDSHAKE_FRAME,
            Request::WriteRange { .. } | Request::PutSmallBatch(_) | Request::CopySmallFiles(_) => {
                MAX_FRAME
            }
            _ => MAX_METADATA_FRAME,
        }
    }
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
            Request::ListDir {
                directory,
                confined_root,
                prefix,
                ..
            } => directory.len() + confined_root.as_ref().map_or(0, Vec::len) + prefix.len() + 32,
            _ => 256,
        }
    }
}

impl SizeHint for Response {
    fn direct_payload(&self) -> bool {
        matches!(self, Response::Block { .. })
    }
    fn frame_limit(&self) -> usize {
        match self {
            Response::HelloOk { .. } => MAX_HANDSHAKE_FRAME,
            Response::Block { .. }
            | Response::SmallBlocks(_)
            | Response::Hashes(_)
            | Response::HeldHashes { .. } => MAX_FRAME,
            _ => MAX_METADATA_FRAME,
        }
    }
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
                        outcome.path.len()
                            + outcome
                                .failure
                                .as_ref()
                                .map_or(0, |failure| failure.error.message.len())
                            + 48
                    })
                    .sum::<usize>()
                    + 16
            }
            Response::DirectoryEntries { entries, .. } => {
                entries
                    .iter()
                    .map(|entry| entry.name.len() + 8)
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
            Response::Receipt(v) => v.len() + 16,
            _ => 256,
        }
    }
}

// Keep transport errors intact: postcard's stock I/O flavor replaces them
// with SerializeBufferFull. Also enforce the length announced in the header.
struct MessageOutput<'a, W> {
    writer: &'a mut W,
    remaining: usize,
    error: &'a mut Option<io::Error>,
}

impl<W: Write> postcard::ser_flavors::Flavor for MessageOutput<'_, W> {
    type Output = ();

    fn try_push(&mut self, byte: u8) -> postcard::Result<()> {
        self.try_extend(&[byte])
    }

    fn try_extend(&mut self, bytes: &[u8]) -> postcard::Result<()> {
        let result = if bytes.len() > self.remaining {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "serialized message length changed",
            ))
        } else {
            self.writer.write_all(bytes)
        };
        if let Err(error) = result {
            *self.error = Some(error);
            return Err(postcard::Error::SerializeBufferFull);
        }
        self.remaining -= bytes.len();
        Ok(())
    }

    fn finalize(self) -> postcard::Result<()> {
        if self.remaining != 0 {
            *self.error = Some(io::Error::new(
                io::ErrorKind::InvalidData,
                "serialized message length changed",
            ));
            return Err(postcard::Error::SerializeBufferFull);
        }
        Ok(())
    }
}

pub struct FrameWriter<W: Write> {
    w: BufWriter<W>,
    pub compress: bool,
    preamble_written: bool,
}

impl<W: Write> FrameWriter<W> {
    pub fn new(w: W, compress: bool) -> Self {
        FrameWriter {
            w: BufWriter::with_capacity(1 << 20, w),
            compress,
            preamble_written: false,
        }
    }

    /// A writer for a stream whose preamble another process already sent:
    /// a control session taken from the session pool.
    pub fn with_preamble_written(w: W, compress: bool) -> Self {
        FrameWriter {
            w: BufWriter::with_capacity(1 << 20, w),
            compress,
            preamble_written: true,
        }
    }

    pub fn write_preamble(&mut self) -> io::Result<()> {
        if self.preamble_written {
            return Ok(());
        }
        let identity = crate::identity::build().as_bytes();
        let identity_len = u16::try_from(identity.len())
            .ok()
            .filter(|length| usize::from(*length) <= MAX_BUILD_IDENTITY_BYTES)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "{WIRE_PREAMBLE_PROTOCOL_ERROR}: local build identity exceeds the supported limit"
                    ),
                )
            })?;
        self.w.write_all(WIRE_PREAMBLE_MAGIC)?;
        self.w.write_all(&identity_len.to_be_bytes())?;
        self.w.write_all(identity)?;
        self.w.flush()?;
        self.preamble_written = true;
        Ok(())
    }

    fn check_message_size(size: usize, limit: usize) -> io::Result<()> {
        if size >= limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "outgoing message exceeds its size limit",
            ));
        }
        Ok(())
    }

    fn write_frame_header(&mut self, body_size: usize, flag: u8) -> io::Result<()> {
        let len = body_size
            .checked_add(1)
            .filter(|len| *len <= MAX_FRAME)
            .and_then(|len| u32::try_from(len).ok())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "outgoing frame exceeds limit")
            })?;
        self.w.write_all(&len.to_le_bytes())?;
        self.w.write_all(&[flag])
    }

    pub fn write_msg<T: Serialize + SizeHint>(&mut self, msg: &T) -> io::Result<()> {
        self.write_preamble()?;
        if !self.compress && msg.direct_payload() {
            // serde_bytes payloads contribute their length without visiting
            // each byte. The second pass writes those slices directly.
            let size = postcard::experimental::serialized_size(msg)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            Self::check_message_size(size, msg.frame_limit())?;
            self.write_frame_header(size, 0)?;
            let mut error = None;
            let result = postcard::serialize_with_flavor(
                msg,
                MessageOutput {
                    writer: &mut self.w,
                    remaining: size,
                    error: &mut error,
                },
            );
            result.map_err(|serialization_error| {
                error.unwrap_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, serialization_error)
                })
            })?;
            return self.w.flush();
        }
        let payload = postcard::to_extend(msg, Vec::with_capacity(msg.size_hint()))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Self::check_message_size(payload.len(), msg.frame_limit())?;
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
        self.write_frame_header(body.len(), flag)?;
        self.w.write_all(&body)?;
        self.w.flush()
    }
}

pub struct FrameReader<R: Read> {
    r: BufReader<R>,
    preamble_read: bool,
    limit: usize,
}

impl<R: Read> FrameReader<R> {
    pub fn new(r: R) -> Self {
        FrameReader {
            r: BufReader::with_capacity(16 << 10, r),
            preamble_read: false,
            limit: MAX_FRAME,
        }
    }

    pub(crate) fn set_limit(&mut self, limit: usize) {
        self.limit = limit.min(MAX_FRAME);
    }

    fn read_preamble(&mut self) -> io::Result<()> {
        if self.preamble_read {
            return Ok(());
        }
        let mut fixed = [0u8; WIRE_PREAMBLE_FIXED_LEN];
        self.r.read_exact(&mut fixed).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "{WIRE_PREAMBLE_PROTOCOL_ERROR}: read header from remote syq: {error}; remote may be incompatible with local build {}",
                    crate::identity::build()
                ),
            )
        })?;
        if &fixed[..WIRE_PREAMBLE_MAGIC.len()] != WIRE_PREAMBLE_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{WIRE_PREAMBLE_PROTOCOL_ERROR}: magic mismatch; remote syq may predate the build-identified preamble (local {})",
                    crate::identity::build()
                ),
            ));
        }
        let identity_len = u16::from_be_bytes(
            fixed[WIRE_PREAMBLE_MAGIC.len()..]
                .try_into()
                .expect("fixed preamble length"),
        ) as usize;
        if identity_len == 0 || identity_len > MAX_BUILD_IDENTITY_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{WIRE_PREAMBLE_PROTOCOL_ERROR}: remote syq build identity length {identity_len} is invalid"
                ),
            ));
        }
        let mut identity = vec![0u8; identity_len];
        self.r.read_exact(&mut identity).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("{WIRE_PREAMBLE_PROTOCOL_ERROR}: read remote syq build identity: {error}"),
            )
        })?;
        let identity = std::str::from_utf8(&identity).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{WIRE_PREAMBLE_PROTOCOL_ERROR}: remote syq build identity is not UTF-8: {error}"
                ),
            )
        })?;
        if identity != crate::identity::build() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{WIRE_PREAMBLE_PROTOCOL_ERROR}: build identity mismatch (remote {identity}, local {})",
                    crate::identity::build()
                ),
            ));
        }
        self.preamble_read = true;
        Ok(())
    }

    #[cfg(test)]
    pub fn read_msg<T: for<'de> Deserialize<'de> + SizeHint>(&mut self) -> io::Result<T> {
        self.read_budgeted()
            .map(crate::wire_budget::Budgeted::into_inner)
    }

    pub(crate) fn read_budgeted<T: for<'de> Deserialize<'de> + SizeHint>(
        &mut self,
    ) -> io::Result<crate::wire_budget::Budgeted<T>> {
        self.read_preamble()?;
        let mut hdr = [0u8; 4];
        self.r.read_exact(&mut hdr)?;
        let len = u32::from_le_bytes(hdr) as usize;
        if len == 0 || len > self.limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("bad frame length {len}; limit {}", self.limit),
            ));
        }
        let mut flag = [0u8; 1];
        self.r.read_exact(&mut flag)?;
        if flag[0] > 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unknown frame flags",
            ));
        }
        // Encoded bytes and decompression are bounded by this reader's frame
        // limit. Their queue count is bounded by the connection's read-ahead.
        let mut body = vec![0u8; len - 1];
        self.r.read_exact(&mut body)?;
        let payload = if flag[0] == 1 {
            // Bound zstd's advertised window as well as its output. Level-1
            // frames from the released writer use windows below this ceiling.
            let mut decoder = zstd::stream::read::Decoder::new(&body[..])?;
            decoder.window_log_max(23)?;
            let mut output = Vec::new();
            let mut chunk = [0u8; 16 << 10];
            loop {
                let n = decoder.read(&mut chunk)?;
                if n == 0 {
                    break;
                }
                if output.len() + n >= self.limit {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "decompressed frame exceeds limit",
                    ));
                }
                // Keep output capacity close to the bounded decoded length.
                output.try_reserve_exact(n).map_err(io::Error::other)?;
                output.extend_from_slice(&chunk[..n]);
            }
            output
        } else {
            body
        };
        let decoded = crate::wire_budget::decode::<T>(&payload)?;
        if payload.len() >= decoded.value.frame_limit() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "incoming message exceeds its size limit",
            ));
        }
        Ok(decoded)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn streaming_request_bounds_are_checked_before_starting() {
        let valid = super::ReadStreamRequest {
            path: Vec::new(),
            source: None,
            attempt: 0,
            off: 0,
            end: 1,
            block: 512,
        };
        valid.validate().unwrap();
        for (off, end, block) in [
            (0, 0, 512),
            (2, 1, 512),
            (0, u64::MAX, 512),
            (0, 1, 0),
            (0, 1, 511),
            (0, 1, (64 << 20) + 1),
        ] {
            assert!(super::ReadStreamRequest {
                off,
                end,
                block,
                ..valid.clone()
            }
            .validate()
            .is_err());
        }
        super::ReadStreamRequest {
            off: i64::MAX as u64 - 1,
            end: i64::MAX as u64,
            block: 64 << 20,
            ..valid
        }
        .validate()
        .unwrap();
    }
    use super::*;

    fn local_preamble_len() -> usize {
        WIRE_PREAMBLE_FIXED_LEN + crate::identity::build().len()
    }

    fn block_message(data: Vec<u8>) -> Response {
        Response::Block {
            off: 7,
            hash: [11; 32],
            data,
        }
    }

    fn block_frame(data: Vec<u8>, compress: bool) -> Vec<u8> {
        let mut frame = Vec::new();
        FrameWriter::new(&mut frame, compress)
            .write_msg(&block_message(data))
            .unwrap();
        frame
    }

    fn raw_frame(body: &[u8], flag: u8) -> Vec<u8> {
        let mut bytes = Vec::new();
        FrameWriter::new(&mut bytes, false)
            .write_preamble()
            .unwrap();
        bytes.extend_from_slice(&((body.len() + 1) as u32).to_le_bytes());
        bytes.push(flag);
        bytes.extend_from_slice(body);
        bytes
    }

    #[test]
    fn direct_frames_preserve_buffered_encoding_and_released_payloads() {
        // The previous writer (also in v0.5.1) materializes postcard bytes
        // before adding this header. Compare entire consecutive frames.
        let mut actual = Vec::new();
        let mut expected = Vec::new();
        FrameWriter::new(&mut expected, false)
            .write_preamble()
            .unwrap();
        {
            let mut writer = FrameWriter::new(&mut actual, false);
            for size in [0, 127, 128, 16384, (1 << 20) - 40, 1 << 20, 4 << 20] {
                let response = Response::Block {
                    off: 1234567,
                    hash: [11; 32],
                    data: vec![0xab; size],
                };
                let payload = postcard::to_stdvec(&response).unwrap();
                expected.extend_from_slice(&raw_frame(&payload, 0)[local_preamble_len()..]);
                writer.write_msg(&response).unwrap();
            }
        }
        assert_eq!(actual, expected);
        let fixture = include_bytes!("../tests/fixtures/completion/list-dir-v0.3.2.bin");
        let request: Request = postcard::from_bytes(fixture).unwrap();
        let mut actual = Vec::new();
        FrameWriter::new(&mut actual, false)
            .write_msg(&request)
            .unwrap();
        assert_eq!(
            &actual[local_preamble_len()..],
            &raw_frame(fixture, 0)[local_preamble_len()..]
        );
    }

    #[test]
    fn direct_frame_passes_large_payload_to_transport_without_copying() {
        struct ObservePayload {
            pointer: *const u8,
            length: usize,
            seen: bool,
        }
        impl Write for ObservePayload {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if bytes.as_ptr() == self.pointer && bytes.len() == self.length {
                    self.seen = true;
                }
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let data = vec![17; 4 << 20];
        let mut output = ObservePayload {
            pointer: data.as_ptr(),
            length: data.len(),
            seen: false,
        };
        FrameWriter::new(&mut output, false)
            .write_msg(&Response::Block {
                off: 0,
                hash: [0; 32],
                data,
            })
            .unwrap();
        assert!(
            output.seen,
            "transport did not receive the original payload slice"
        );
    }

    #[test]
    fn metadata_keeps_single_pass_serialization() {
        struct Metadata(std::cell::Cell<usize>);
        impl Serialize for Metadata {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                self.0.set(self.0.get() + 1);
                serializer.serialize_u8(0)
            }
        }
        impl SizeHint for Metadata {
            fn size_hint(&self) -> usize {
                1
            }
            fn frame_limit(&self) -> usize {
                MAX_FRAME
            }
        }
        let message = Metadata(std::cell::Cell::new(0));
        FrameWriter::new(io::sink(), false)
            .write_msg(&message)
            .unwrap();
        assert_eq!(message.0.get(), 1);
        assert!(!Response::ScanBatch(Vec::new()).direct_payload());
        assert!(!Request::PutSmallBatch(Vec::new()).direct_payload());
    }

    #[test]
    fn frames_check_uncompressed_size_before_writing_header() {
        #[derive(Serialize)]
        struct Limited {
            #[serde(skip)]
            direct: bool,
            #[serde(with = "serde_bytes")]
            data: Vec<u8>,
        }
        impl SizeHint for Limited {
            fn direct_payload(&self) -> bool {
                self.direct
            }
            fn size_hint(&self) -> usize {
                self.data.len() + 2
            }
            fn frame_limit(&self) -> usize {
                1024
            }
        }
        for direct in [false, true] {
            for compress in [false, true] {
                // The encoded length is exactly the exclusive limit. Even
                // though these bytes compress well, reject before the header.
                let message = Limited {
                    direct,
                    data: vec![0; 1022],
                };
                assert_eq!(
                    postcard::experimental::serialized_size(&message).unwrap(),
                    1024
                );
                let mut bytes = Vec::new();
                let error = FrameWriter::new(&mut bytes, compress)
                    .write_msg(&message)
                    .unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
                assert!(error.to_string().contains("size limit"));
                assert_eq!(bytes.len(), local_preamble_len());
            }
        }
    }

    #[test]
    fn direct_frame_preserves_payload_io_error() {
        struct FailPayload;
        impl Write for FailPayload {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if bytes.len() >= 1 << 20 {
                    Err(io::Error::from_raw_os_error(libc::EPIPE))
                } else {
                    Ok(bytes.len())
                }
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let error = FrameWriter::new(FailPayload, false)
            .write_msg(&Response::Block {
                off: 0,
                hash: [0; 32],
                data: vec![0; 2 << 20],
            })
            .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EPIPE));
    }

    #[test]
    fn direct_frame_handles_short_writes_and_flush_errors() {
        struct ShortWriter {
            bytes: Vec<u8>,
            fail_flush: bool,
        }
        impl Write for ShortWriter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                let n = bytes.len().min(31);
                self.bytes.extend_from_slice(&bytes[..n]);
                Ok(n)
            }
            fn flush(&mut self) -> io::Result<()> {
                if self.fail_flush {
                    Err(io::Error::from_raw_os_error(libc::EIO))
                } else {
                    Ok(())
                }
            }
        }
        let mut output = ShortWriter {
            bytes: Vec::new(),
            fail_flush: false,
        };
        FrameWriter::new(&mut output, false)
            .write_msg(&block_message(vec![4; 2 << 20]))
            .unwrap();
        assert_eq!(output.bytes, block_frame(vec![4; 2 << 20], false));
        output.fail_flush = true;
        let error = FrameWriter::with_preamble_written(&mut output, false)
            .write_msg(&block_message(vec![4; 2 << 20]))
            .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
    }

    #[test]
    fn direct_frame_bounds_a_serializer_that_changes_length() {
        struct Changing(std::cell::Cell<bool>, bool);
        impl Serialize for Changing {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let second = self.0.replace(true);
                serializer.serialize_bytes(if second == self.1 { b"long" } else { b"s" })
            }
        }
        impl SizeHint for Changing {
            fn direct_payload(&self) -> bool {
                true
            }
            fn size_hint(&self) -> usize {
                16
            }
            fn frame_limit(&self) -> usize {
                MAX_FRAME
            }
        }
        for grows in [false, true] {
            let mut bytes = Vec::new();
            let error = FrameWriter::new(&mut bytes, false)
                .write_msg(&Changing(std::cell::Cell::new(false), grows))
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert!(error.to_string().contains("length changed"));
            let offset = local_preamble_len();
            let announced =
                u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
            assert!(bytes.len() < offset + 4 + announced);
        }
    }

    #[test]
    fn oversized_handshake_is_rejected_before_reading_its_body() {
        let mut bytes = Vec::new();
        FrameWriter::new(&mut bytes, false)
            .write_preamble()
            .unwrap();
        bytes.extend_from_slice(&((MAX_HANDSHAKE_FRAME + 1) as u32).to_le_bytes());
        let mut reader = FrameReader::new(bytes.as_slice());
        reader.set_limit(MAX_HANDSHAKE_FRAME);
        let error = reader.read_msg::<Request>().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("bad frame length"));
    }

    #[test]
    fn compressed_handshake_cannot_expand_past_its_limit() {
        let payload = postcard::to_stdvec(&Response::Err("x".repeat(4096))).unwrap();
        let compressed = zstd::bulk::compress(&payload, 1).unwrap();
        let bytes = raw_frame(&compressed, 1);
        let mut reader = FrameReader::new(bytes.as_slice());
        reader.set_limit(1024);
        assert!(reader
            .read_msg::<Response>()
            .unwrap_err()
            .to_string()
            .contains("decompressed frame exceeds"));
    }

    #[test]
    fn compressed_metadata_still_obeys_its_message_limit() {
        let payload = postcard::to_stdvec(&Response::Err("x".repeat(MAX_METADATA_FRAME))).unwrap();
        let compressed = zstd::bulk::compress(&payload, 1).unwrap();
        let bytes = raw_frame(&compressed, 1);
        let error = FrameReader::new(bytes.as_slice())
            .read_msg::<Response>()
            .unwrap_err();
        assert!(error.to_string().contains("message exceeds its size limit"));
    }

    #[test]
    fn bounded_decoder_preserves_released_completion_payloads() {
        let request = include_bytes!("../tests/fixtures/completion/list-dir-v0.3.2.bin");
        let response = include_bytes!("../tests/fixtures/completion/directory-entries-v0.3.2.bin");
        let decoded = crate::wire_budget::decode::<Request>(request)
            .unwrap()
            .into_inner();
        assert_eq!(postcard::to_stdvec(&decoded).unwrap(), request);
        let decoded = crate::wire_budget::decode::<Response>(response)
            .unwrap()
            .into_inner();
        assert_eq!(postcard::to_stdvec(&decoded).unwrap(), response);
    }

    #[test]
    fn compression_is_per_frame_and_never_expands_the_wire_payload() {
        let data = vec![b'a'; 64 * 1024];
        let compressed = block_frame(data.clone(), true);
        assert_eq!(
            compressed[local_preamble_len() + 4],
            1,
            "compressible frame was not compressed"
        );

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
        assert_eq!(
            disabled[local_preamble_len() + 4],
            0,
            "disabled compression changed the frame"
        );

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
            incompressible[local_preamble_len() + 4],
            0,
            "an expanded compressed representation was selected"
        );
    }

    #[test]
    fn captured_old_format_handshake_is_rejected_before_postcard_decode() {
        // Captured pre-preamble frame for Request::Hello { identity: "v0.1.8",
        // compress: false, debug: false, token: [], role: Control }.
        const OLD_FORMAT_HELLO: &[u8] = &[
            0x0d, 0x00, 0x00, 0x00, // frame length
            0x00, // frame flags
            0x00, // Request::Hello
            0x06, b'v', b'0', b'.', b'1', b'.', b'8', // identity
            0x00, 0x00, // compress, debug
            0x00, // empty token
            0x00, // ConnectionRole::Control
        ];

        let error = FrameReader::new(OLD_FORMAT_HELLO)
            .read_msg::<Request>()
            .unwrap_err();
        let diagnostic = error.to_string();
        assert!(diagnostic.contains(WIRE_PREAMBLE_PROTOCOL_ERROR));
        assert!(diagnostic.contains("magic mismatch"));
        assert!(diagnostic.contains("may predate"));
    }

    #[test]
    fn released_v040_preamble_keeps_its_build_identity_boundary() {
        // v0.4.0's fixed preamble: magic, big-endian identity length, identity.
        // Kept independent of the current encoder and current enum variants.
        const V040: &[u8] = b"SYQWIRE\0\0\x06v0.4.0";
        let result = FrameReader::new(V040).read_preamble();
        if crate::identity::build() == "v0.4.0" {
            result.unwrap();
        } else {
            let message = result.unwrap_err().to_string();
            assert!(message.contains("build identity mismatch"), "{message}");
            assert!(message.contains("remote v0.4.0"), "{message}");
        }
    }

    #[test]
    fn released_v052_preamble_rejects_new_transfer_messages_before_decoding() {
        // Literal v0.5.2 preamble, independent of today's enum encodings.
        const V052: &[u8] = b"SYQWIRE\0\0\x06v0.5.2";
        if crate::identity::build() != "v0.5.2" {
            let error = FrameReader::new(V052).read_msg::<Response>().unwrap_err();
            assert!(
                error.to_string().contains("build identity mismatch"),
                "{error}"
            );
        }
    }

    #[test]
    fn every_malformed_build_identity_is_a_preamble_protocol_error() {
        let preamble = |length: u16, identity: &[u8]| {
            let mut input = Vec::new();
            input.extend_from_slice(WIRE_PREAMBLE_MAGIC);
            input.extend_from_slice(&length.to_be_bytes());
            input.extend_from_slice(identity);
            input
        };
        let cases = [
            (preamble(0, b""), "length 0 is invalid"),
            (
                preamble((MAX_BUILD_IDENTITY_BYTES + 1) as u16, b""),
                "length 513 is invalid",
            ),
            (preamble(4, b"ab"), "read remote syq build identity"),
            (preamble(1, &[0xff]), "not UTF-8"),
        ];

        for (input, expected) in cases {
            let error = FrameReader::new(input.as_slice())
                .read_msg::<Response>()
                .unwrap_err();
            let diagnostic = error.to_string();
            assert!(
                diagnostic.contains(WIRE_PREAMBLE_PROTOCOL_ERROR),
                "{diagnostic}"
            );
            assert!(diagnostic.contains(expected), "{diagnostic}");
        }
    }

    #[test]
    fn build_identity_mismatch_is_reported_before_frame_decode() {
        let remote_identity = b"v0.0.0+different-build";
        let mut input = Vec::new();
        input.extend_from_slice(WIRE_PREAMBLE_MAGIC);
        input.extend_from_slice(&(remote_identity.len() as u16).to_be_bytes());
        input.extend_from_slice(remote_identity);
        input.extend_from_slice(b"not a postcard frame");

        let error = FrameReader::new(input.as_slice())
            .read_msg::<Response>()
            .unwrap_err();
        let diagnostic = error.to_string();
        assert!(diagnostic.contains("build identity mismatch"));
        assert!(diagnostic.contains("remote v0.0.0+different-build"));
        assert!(diagnostic.contains(crate::identity::build()));
    }

    #[test]
    fn registered_paths_reject_unsafe_wire_components() {
        let temporary = crate::test_support::tempdir().unwrap();
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

#[cfg(test)]
mod completion_compat_tests {
    use super::*;
    #[test]
    fn released_v032_completion_messages_keep_their_wire_encoding() {
        // Generated with unchanged src/proto.rs from tag v0.3.2. Do not regenerate
        // these when editing the current writer or reader.
        let bytes = include_bytes!("../tests/fixtures/completion/list-dir-v0.3.2.bin");
        let request: Request = postcard::from_bytes(bytes).unwrap();
        assert!(
            matches!(&request, Request::ListDir { directory, prefix, limit: 1000, symlink_policy: OperatorSymlinkPolicy::Refuse, confined_root: None } if directory == b"/data" && prefix == b"al")
        );
        assert_eq!(postcard::to_stdvec(&request).unwrap(), bytes);
        let bytes = include_bytes!("../tests/fixtures/completion/directory-entries-v0.3.2.bin");
        let response: Response = postcard::from_bytes(bytes).unwrap();
        assert!(
            matches!(&response, Response::DirectoryEntries { entries, truncated: false } if entries.len() == 1 && entries[0].name == b"alpha" && !entries[0].directory)
        );
        assert_eq!(postcard::to_stdvec(&response).unwrap(), bytes);
    }
}

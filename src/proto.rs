//! Wire protocol: message types and length-prefixed framing.
//!
//! Every connection (control or data) speaks the same request/response
//! protocol. Frames are `u32 len | u8 flags | payload`, payload is postcard;
//! flag bit 0 means the payload is zstd-compressed. Each writer decides
//! independently whether to compress, readers always accept both.

use serde::{Deserialize, Serialize};
use std::io::{self, BufReader, BufWriter, Read, Write};

pub const MAX_FRAME: usize = 256 * 1024 * 1024;
pub const MIN_HASH_BLOCK_BYTES: u64 = 64 * 1024;
pub const MAX_HASH_BLOCK_BYTES: u64 = 64 * 1024 * 1024;
const HASH_RESPONSE_BYTES_PER_ENTRY: u64 = 32;
const HASH_RESPONSE_OVERHEAD: u64 = 24;
const COMPRESS_MIN: usize = 512;
const COMPRESS_LEVEL: i32 = 1;

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
pub enum Request {
    Hello {
        identity: String,
        compress: bool,
        debug: bool,
        token: Vec<u8>,
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
    /// Create the missing suffix retained by CheckOperatorDirectory, then
    /// return the selected directory's stable identity.
    CreateOperatorDirectory {
        mode: u32,
        /// Refuse a concurrently-created final directory instead of reusing
        /// it. Intermediate directories may still be shared safely.
        require_absent: bool,
    },
    /// Retain and enter the selected destination directory for this
    /// connection. The control connection reuses its checked descriptor;
    /// independent workers securely reopen `path` and verify its identity.
    AnchorDestination {
        path: Option<PathBytes>,
        expected_dev: u64,
        expected_ino: u64,
        request_prefix: PathBytes,
        symlink_policy: OperatorSymlinkPolicy,
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
    /// source and asynchronous NFS destination). Err("EXDEV") tells the
    /// caller to use the normal streaming path.
    CopyLocal {
        src: PathBytes,
        dst: PathBytes,
        inplace: bool,
        allow_sequential_nfs_fallback: bool,
        partial_id: PartialId,
        size: u64,
        mode: u32,
    },
    HashBlocks {
        path: PathBytes,
        which: Which,
        partial_id: PartialId,
        block: u64,
        len: u64,
        attempt: u32,
        guard: Option<ContainerGuard>,
    },
    ReadRange {
        path: PathBytes,
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
}

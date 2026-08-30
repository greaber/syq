//! Wire protocol: message types and length-prefixed framing.
//!
//! Every connection (control or data) speaks the same request/response
//! protocol. Frames are `u32 len | u8 flags | payload`, payload is postcard;
//! flag bit 0 means the payload is zstd-compressed. Each writer decides
//! independently whether to compress, readers always accept both.

use serde::{Deserialize, Serialize};
use std::io::{self, BufReader, BufWriter, Read, Write};

pub const MAX_FRAME: usize = 256 * 1024 * 1024;
const COMPRESS_MIN: usize = 512;
const COMPRESS_LEVEL: i32 = 1;

/// Path bytes, as given by the user (absolute, or relative to the server's cwd).
pub type PathBytes = Vec<u8>;

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
    pub link: Option<PathBytes>,
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
}

/// Best-effort kernel counters for one end of a TCP data socket. `None` means
/// the platform or returned kernel structure does not expose that field; a
/// reported zero is therefore a genuine measurement.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default)]
pub struct TcpSocketStats {
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
    },
    Symlink {
        path: PathBytes,
        target: PathBytes,
    },
    Mknod {
        path: PathBytes,
        mode: u32,
        rdev: u64,
    },
    SetMeta {
        path: PathBytes,
        meta: Meta,
        flags: u8,
    },
    /// Apply metadata to a regular file only if the path still names the inode
    /// observed by the planner. A concurrent rename makes this a no-op.
    SetFileMetaIfSame {
        path: PathBytes,
        expected_dev: u64,
        expected_ino: u64,
        meta: Meta,
        flags: u8,
    },
    Remove {
        path: PathBytes,
    },
    /// Remove an empty directory.
    Rmdir {
        path: PathBytes,
    },
    /// Remove a non-directory; a directory that has appeared there is an
    /// error, never recursed into (used by --delete for planned leaves).
    Unlink {
        path: PathBytes,
    },
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
    },
    /// `ignore`: gitignore-style patterns relative to `root` (see scan.rs).
    /// `report_ignored`: also send the paths the patterns pruned (ScanIgnored).
    Scan {
        root: PathBytes,
        follow_root: bool,
        ignore: Vec<String>,
        report_ignored: bool,
    },
    /// lstat each path; with `follow`, stat through symlinks instead.
    StatMany {
        paths: Vec<PathBytes>,
        follow: bool,
    },
    /// Resolve an operator-supplied destination directory component by
    /// component, following only symlinks owned by root or this endpoint's
    /// effective uid. A missing suffix is accepted only when requested.
    CheckOperatorDirectory {
        path: PathBytes,
        allow_missing: bool,
        insecure_links: bool,
    },
    /// Create the missing suffix retained by CheckOperatorDirectory, then
    /// return the selected directory's stable identity.
    CreateOperatorDirectory {
        mode: u32,
    },
    /// Retain and enter the selected destination directory for this
    /// connection. The control connection reuses its checked descriptor;
    /// independent workers securely reopen `path` and verify its identity.
    AnchorDestination {
        path: Option<PathBytes>,
        expected_dev: u64,
        expected_ino: u64,
        request_prefix: PathBytes,
        insecure_links: bool,
    },
    /// Compute the exact receiver-side sidecar names for collision preflight.
    PartialPaths {
        paths: Vec<PathBytes>,
        partial_id: PartialId,
    },
    Apply(Vec<Op>),
    /// Return the size of the deterministic sidecar, if it is a regular file.
    /// The planner has already statted the final path.
    ProbePartial {
        path: PathBytes,
        partial_id: PartialId,
    },
    /// Create/adjust the write target for `path` with the given final size.
    /// `mode` is the creation mode for `--inplace`; resumable sidecars remain
    /// private until final metadata is applied immediately before publication.
    Prepare {
        path: PathBytes,
        size: u64,
        inplace: bool,
        partial_id: PartialId,
        mode: u32,
    },
    /// Hash an existing final file and retain that open inode as the repair
    /// basis until FinishBasis or SeedBasis consumes it.
    HashAndHold {
        path: PathBytes,
        partial_id: PartialId,
        block: u64,
        len: u64,
    },
    /// Apply metadata through the retained basis descriptor. If another job
    /// renamed over the final path meanwhile, its complete file remains the
    /// winner and this only touches the now-unlinked old inode.
    FinishBasis {
        path: PathBytes,
        partial_id: PartialId,
        meta: Meta,
        flags: u8,
    },
    /// Seed this job's sidecar from the retained basis descriptor.
    SeedBasis {
        path: PathBytes,
        partial_id: PartialId,
        len: u64,
    },
    /// In-kernel copy of a same-machine file (copy_file_range: reflink / NFS
    /// server-side copy when possible). Err("EXDEV") tells the caller to fall
    /// back to the normal read/write path.
    CopyLocal {
        src: PathBytes,
        dst: PathBytes,
        inplace: bool,
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
    },
    ReadRange {
        path: PathBytes,
        attempt: u32,
        off: u64,
        len: u32,
    },
    WriteRange {
        path: PathBytes,
        inplace: bool,
        partial_id: PartialId,
        attempt: u32,
        off: u64,
        hash: u64,
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
    },
    Finalize {
        path: PathBytes,
        inplace: bool,
        partial_id: PartialId,
        meta: Meta,
        flags: u8,
    },
    /// Whole small file in one request: verify, write a sidecar, then rename it
    /// atomically over the final path. This preserves small-file pipelining
    /// without exposing partial final-named files.
    PutSmall {
        path: PathBytes,
        partial_id: PartialId,
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
        hash: u64,
        meta: Meta,
        flags: u8,
    },
    FileHash {
        path: PathBytes,
    },
    /// Absolute, normalized form of a path on this endpoint (symlinks in the
    /// existing prefix resolved), for a stable job identity.
    Canonicalize {
        path: PathBytes,
    },
    /// Kernel TCP_INFO/TCP_CONNECTION_INFO for this end of a direct data
    /// socket. SSH data transports report None at the orchestrator instead of
    /// sending this request.
    TransportStats,
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
    },
    ScanBatch(Vec<Entry>),
    ScanWarn(String),
    /// Paths (relative to the root) pruned by the ignore patterns.
    ScanIgnored(Vec<PathBytes>),
    ScanDone,
    Stats(Vec<Option<Entry>>),
    /// Absolute operator spelling plus device/inode of the securely opened
    /// directory, or None when an allowed missing suffix was reached.
    DirectorySelection(Option<DirectoryAnchor>),
    PathResults(Vec<std::result::Result<PathBytes, String>>),
    Applied(Vec<Option<String>>),
    PartialSize(Option<u64>),
    Hashes(Vec<u64>),
    HeldHashes {
        hashes: Vec<u64>,
        len: u64,
    },
    Block {
        off: u64,
        hash: u64,
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
    },
    FileHash {
        size: u64,
        hash: u128,
    },
    Path(PathBytes),
    TransportStats(Option<TcpSocketStats>),
    Ok,
    Err(String),
}

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
            Request::PutSmall { data, path, .. } => data.len() + path.len() + 96,
            Request::StatMany { paths, .. } => {
                paths.iter().map(|p| p.len() + 8).sum::<usize>() + 16
            }
            Request::Apply(v) => v.len() * 128 + 16,
            _ => 256,
        }
    }
}

impl SizeHint for Response {
    fn size_hint(&self) -> usize {
        match self {
            Response::Block { data, .. } => data.len() + 64,
            Response::ScanBatch(v) => v.len() * 160 + 16,
            Response::Stats(v) => v.len() * 96 + 16,
            Response::Hashes(v) | Response::HeldHashes { hashes: v, .. } => v.len() * 9 + 24,
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
        let len = (body.len() + 1) as u32;
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
                hash: 11,
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
                assert_eq!((off, hash), (7, 11));
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

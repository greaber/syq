//! Wire protocol: message types and length-prefixed framing.
//!
//! Every connection (control or data) speaks the same request/response
//! protocol. Frames are `u32 len | u8 flags | payload`, payload is postcard;
//! flag bit 0 means the payload is zstd-compressed. Each writer decides
//! independently whether to compress, readers always accept both.

use serde::{Deserialize, Serialize};
use std::io::{self, BufReader, BufWriter, Read, Write};

// 5: Scan.report_ignored + ScanIgnored (--delete); bumped past master's 4.
pub const VERSION: u32 = 5;
pub const MAX_FRAME: usize = 256 * 1024 * 1024;
const COMPRESS_MIN: usize = 512;

/// Path bytes, as given by the user (absolute, or relative to the server's cwd).
pub type PathBytes = Vec<u8>;

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
    Remove {
        path: PathBytes,
    },
    /// Remove an empty directory.
    Rmdir {
        path: PathBytes,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Request {
    Hello {
        version: u32,
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
    Apply(Vec<Op>),
    /// What exists at `path` on the receiving side: the final file and/or a partial.
    Probe {
        path: PathBytes,
    },
    /// Create/adjust the write target for `path` with the given final size.
    /// `mode`: create new files with this mode so no separate chmod is needed.
    Prepare {
        path: PathBytes,
        size: u64,
        inplace: bool,
        from_final: bool,
        mode: u32,
    },
    /// In-kernel copy of a same-machine file (copy_file_range: reflink / NFS
    /// server-side copy when possible). Err("EXDEV") tells the caller to fall
    /// back to the normal read/write path.
    CopyLocal {
        src: PathBytes,
        dst: PathBytes,
        inplace: bool,
        size: u64,
        mode: u32,
    },
    HashBlocks {
        path: PathBytes,
        which: Which,
        block: u64,
        len: u64,
    },
    ReadRange {
        path: PathBytes,
        off: u64,
        len: u32,
    },
    WriteRange {
        path: PathBytes,
        inplace: bool,
        off: u64,
        hash: u64,
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
    },
    Finalize {
        path: PathBytes,
        inplace: bool,
        meta: Meta,
        flags: u8,
        fsync: bool,
    },
    /// Whole small file in one request: verify, then write it straight to its
    /// final path (no preallocation, no rename). An interrupted write leaves a
    /// short file the next run re-transfers; see put_small for the rationale.
    PutSmall {
        path: PathBytes,
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
        hash: u64,
        meta: Meta,
        flags: u8,
        fsync: bool,
    },
    FileHash {
        path: PathBytes,
    },
    Shutdown,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Response {
    HelloOk {
        version: u32,
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
    Applied(Vec<Option<String>>),
    Probed {
        partial_size: Option<u64>,
        final_entry: Option<Entry>,
    },
    Hashes(Vec<u64>),
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
    Ok,
    Err(String),
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
            Response::Hashes(v) => v.len() * 9 + 16,
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
            if let Ok(c) = zstd::bulk::compress(&body, 3) {
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

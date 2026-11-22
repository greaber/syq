//! The body of an ordinary file upload: each 1 MiB chunk of the range is read
//! with `pread` on the blocking pool, straight into a buffer reused from a
//! process-wide pool.
//!
//! The SDK's own file body reads through `tokio::fs::File`, which reads into
//! its own buffer and copies every byte into a fresh 1 MiB allocation per
//! chunk. With syq's allocator tuning (see `tune_allocator` in `main.rs`)
//! buffers that size come from per-thread glibc arenas that are never
//! trimmed, and those allocations land on hundreds of worker and blocking
//! threads, so a large upload kept over a gigabyte of freed memory. Reused
//! buffers bound the allocations to the most chunks ever in use at once.
//!
//! A body reads one chunk ahead: as it hands a chunk to hyper it starts
//! reading the next, so the disk read overlaps sending the one before. It
//! holds at most that one chunk being read, and hyper holds only about one
//! more until the socket takes it, so live memory stays near three chunks
//! per request in flight. An empty pool never blocks a read: it allocates a
//! new buffer, which joins the pool when released if the pool has room.
//!
//! A file small enough to keep in memory is read once, into [`Held`]
//! contents taken from the same pool, which both hash it and send it.
use super::local::Source;
use aws_smithy_types::body::SdkBody;
use bytes::Bytes;
use std::{
    fs::File,
    future::Future,
    os::unix::fs::FileExt,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

const CHUNK: usize = 1024 * 1024;

/// Idle buffers kept for reuse: three per request at the default ceiling of
/// 256 requests in flight. Idle buffers were all in use at once at some
/// point, so the cap only limits what a burst above it leaves behind.
static POOL: Pool = Pool::new(768);

struct Pool {
    idle: Mutex<Vec<Vec<u8>>>,
    max_idle: usize,
}
impl Pool {
    const fn new(max_idle: usize) -> Self {
        Self {
            idle: Mutex::new(Vec::new()),
            max_idle,
        }
    }
    fn idle(&self) -> std::sync::MutexGuard<'_, Vec<Vec<u8>>> {
        // A buffer holds no invariant a panic could break.
        self.idle.lock().unwrap_or_else(|e| e.into_inner())
    }
    fn take(&'static self) -> Buffer {
        // Release the lock before allocating a new buffer.
        let idle = self.idle().pop();
        let buffer = idle.unwrap_or_else(|| vec![0; CHUNK]);
        Buffer {
            buffer,
            len: 0,
            pool: Some(self),
        }
    }
}

/// A whole pooled chunk to read a file through, for a pass that hashes it
/// rather than sending it: dropping it returns the buffer to the pool that
/// upload bodies use, so hashing reuses their buffers rather than
/// allocating and zeroing a new one for every file or part.
pub(super) struct Scratch(Buffer);

/// A [`Scratch`] buffer of 1 MiB.
pub(super) fn scratch() -> Scratch {
    Scratch(POOL.take())
}
impl std::ops::Deref for Scratch {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0.buffer
    }
}
impl std::ops::DerefMut for Scratch {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0.buffer
    }
}

/// A chunk's bytes. Dropping it, wherever that happens, returns a pooled
/// buffer to its pool.
struct Buffer {
    buffer: Vec<u8>,
    len: usize,
    pool: Option<&'static Pool>,
}
impl Buffer {
    /// A buffer of `n` bytes of its own, for less than a chunk.
    fn exact(n: usize) -> Self {
        Self {
            buffer: vec![0; n],
            len: 0,
            pool: None,
        }
    }
}
impl AsRef<[u8]> for Buffer {
    fn as_ref(&self) -> &[u8] {
        &self.buffer[..self.len]
    }
}
impl Drop for Buffer {
    fn drop(&mut self) {
        if let Some(pool) = self.pool {
            let mut idle = pool.idle();
            if idle.len() < pool.max_idle {
                idle.push(std::mem::take(&mut self.buffer));
            }
        }
    }
}

/// A source opened once for its whole upload: every part, every attempt, and
/// any Content-MD5 read it with `pread`. `file` must come from
/// `source.open()`, which checked that the selected path still names the
/// selected file.
pub(super) struct Opened {
    pub file: File,
    pub source: Source,
}
impl Opened {
    pub fn new(source: Source, file: File) -> Arc<Self> {
        Arc::new(Self { file, source })
    }
    /// The Content-MD5 of `length` bytes from `offset`, failing if the source
    /// no longer matches what was selected once they are read.
    pub fn md5(&self, offset: u64, length: u64) -> anyhow::Result<String> {
        let mut hash = super::checksum::Algorithm::Md5.hasher().unwrap();
        let mut buffer = scratch();
        let mut done = 0;
        while done < length {
            let n = buffer.len().min((length - done) as usize);
            self.file.read_exact_at(&mut buffer[..n], offset + done)?;
            hash.update(&buffer[..n]);
            done += n as u64;
        }
        self.source.check(&self.file)?;
        Ok(hash.finish())
    }
}

/// The upload body for `length` bytes of the opened source from `offset`.
/// Each copy the SDK makes of the body starts again at `offset`. A body fails
/// rather than finish once the source no longer matches what was selected: a
/// short read, or a changed size or timestamp when the last chunk has been
/// read. That failure is marked [`super::retry::Permanent`], so the upload is
/// not retried.
pub(super) fn body(opened: &Arc<Opened>, offset: u64, length: u64) -> SdkBody {
    let opened = opened.clone();
    SdkBody::retryable(move || {
        SdkBody::from_body_1_x(Chunks::new(opened.clone(), offset, length, &POOL))
    })
}

/// The memory, in bytes, that [`Held::read`] takes for `length` bytes: whole
/// pooled chunks, or the exact length below one chunk, and at least one byte
/// so that even an empty file takes part of a budget.
pub(super) fn held_size(length: u64) -> u32 {
    let size = if length >= CHUNK as u64 {
        length.next_multiple_of(CHUNK as u64)
    } else {
        length.max(1)
    };
    u32::try_from(size).unwrap_or(u32::MAX)
}

/// Contents read once and kept to send: whole chunks from the pool with a
/// possibly short last one, or one buffer of their exact size when shorter
/// than a chunk. Clones, the bodies made from them, and the frames those
/// bodies yield share the bytes; dropping the last returns the chunks to the
/// pool and releases `hold`.
#[derive(Clone)]
pub(super) struct Held(Arc<HeldChunks>);
struct HeldChunks {
    chunks: Vec<Buffer>,
    _hold: Box<dyn std::any::Any + Send + Sync>,
}
impl Held {
    /// Read `length` bytes of `file` from its start. The caller checks the
    /// source afterwards.
    pub fn read(
        file: &File,
        length: u64,
        hold: impl std::any::Any + Send + Sync,
    ) -> std::io::Result<Self> {
        Self::read_from(file, length, Box::new(hold), &POOL)
    }
    fn read_from(
        file: &File,
        length: u64,
        hold: Box<dyn std::any::Any + Send + Sync>,
        pool: &'static Pool,
    ) -> std::io::Result<Self> {
        let mut chunks = Vec::with_capacity(length.div_ceil(CHUNK as u64) as usize);
        let mut offset = 0;
        while offset < length {
            let n = (length - offset).min(CHUNK as u64) as usize;
            let mut buffer = if length >= CHUNK as u64 {
                pool.take()
            } else {
                Buffer::exact(n)
            };
            file.read_exact_at(&mut buffer.buffer[..n], offset)?;
            buffer.len = n;
            chunks.push(buffer);
            offset += n as u64;
        }
        Ok(Self(Arc::new(HeldChunks {
            chunks,
            _hold: hold,
        })))
    }
    /// Bytes already in memory, such as a symbolic link's target.
    pub fn from_vec(bytes: Vec<u8>) -> Self {
        let len = bytes.len();
        let chunks = if len == 0 {
            Vec::new()
        } else {
            vec![Buffer {
                buffer: bytes,
                len,
                pool: None,
            }]
        };
        Self(Arc::new(HeldChunks {
            chunks,
            _hold: Box::new(()),
        }))
    }
    /// The number of bytes held.
    pub fn size(&self) -> u64 {
        self.0.chunks.iter().map(|chunk| chunk.len as u64).sum()
    }
    pub fn chunks(&self) -> impl Iterator<Item = &[u8]> {
        self.0.chunks.iter().map(Buffer::as_ref)
    }
    /// A body sending the contents. Each copy the SDK makes starts again at
    /// the first byte.
    pub fn body(&self) -> SdkBody {
        let held = self.clone();
        SdkBody::retryable(move || {
            SdkBody::from_body_1_x(HeldBody {
                held: held.clone(),
                next: 0,
            })
        })
    }
}

struct HeldBody {
    held: Held,
    next: usize,
}
/// One chunk of [`Held`] contents, sent without a copy.
struct HeldChunk {
    held: Held,
    index: usize,
}
impl AsRef<[u8]> for HeldChunk {
    fn as_ref(&self) -> &[u8] {
        self.held.0.chunks[self.index].as_ref()
    }
}
impl http_body::Body for HeldBody {
    type Data = Bytes;
    type Error = aws_smithy_runtime_api::box_error::BoxError;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        let index = self.next;
        if index >= self.held.0.chunks.len() {
            return Poll::Ready(None);
        }
        self.next += 1;
        let chunk = HeldChunk {
            held: self.held.clone(),
            index,
        };
        Poll::Ready(Some(Ok(http_body::Frame::data(Bytes::from_owner(chunk)))))
    }
    fn is_end_stream(&self) -> bool {
        self.next >= self.held.0.chunks.len()
    }
    fn size_hint(&self) -> http_body::SizeHint {
        let rest = self.held.0.chunks[self.next.min(self.held.0.chunks.len())..]
            .iter()
            .map(|chunk| chunk.len as u64)
            .sum();
        http_body::SizeHint::with_exact(rest)
    }
}

type Read = tokio::task::JoinHandle<std::io::Result<Buffer>>;

struct Chunks {
    opened: Arc<Opened>,
    offset: u64,
    end: u64,
    /// Bodies shorter than a chunk use one buffer of their own size.
    pool: Option<&'static Pool>,
    /// The read of the chunk at `offset`, started when the chunk before it
    /// was handed on.
    pending: Option<Read>,
}
impl Chunks {
    fn new(opened: Arc<Opened>, offset: u64, length: u64, pool: &'static Pool) -> Self {
        Self {
            opened,
            offset,
            end: offset + length,
            pool: (length >= CHUNK as u64).then_some(pool),
            pending: None,
        }
    }
    fn read(&self) -> Read {
        let n = (self.end - self.offset).min(CHUNK as u64) as usize;
        let (opened, offset, pool) = (self.opened.clone(), self.offset, self.pool);
        let last = offset + n as u64 == self.end;
        tokio::task::spawn_blocking(move || {
            let mut buffer = match pool {
                Some(pool) => pool.take(),
                None => Buffer::exact(n),
            };
            let read = opened.file.read_exact_at(&mut buffer.buffer[..n], offset);
            // A short read shows that the file shrank, even before its
            // metadata does; name that, not the EOF. A confirmed change is
            // final, but an error reading the metadata may pass.
            let short = matches!(&read, Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof);
            let changed = if short {
                Err(opened.source.changed())
            } else if read.is_err() || last {
                opened.source.check(&opened.file)
            } else {
                Ok(())
            };
            changed.map_err(|e| {
                if e.is::<super::local::SourceChanged>() {
                    std::io::Error::other(super::retry::Permanent::new(e))
                } else {
                    std::io::Error::other(e)
                }
            })?;
            read?;
            buffer.len = n;
            Ok(buffer)
        })
    }
}
impl http_body::Body for Chunks {
    type Data = Bytes;
    type Error = aws_smithy_runtime_api::box_error::BoxError;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        if self.offset >= self.end {
            return Poll::Ready(None);
        }
        if self.pending.is_none() {
            self.pending = Some(self.read());
        }
        let read = self.pending.as_mut().expect("read started");
        let result = std::task::ready!(Pin::new(read).poll(cx));
        self.pending = None;
        let buffer = result??;
        self.offset += buffer.len as u64;
        if self.offset < self.end {
            self.pending = Some(self.read());
        }
        Poll::Ready(Some(Ok(http_body::Frame::data(Bytes::from_owner(buffer)))))
    }
    fn is_end_stream(&self) -> bool {
        self.offset >= self.end
    }
    fn size_hint(&self) -> http_body::SizeHint {
        http_body::SizeHint::with_exact(self.end - self.offset)
    }
}

#[cfg(test)]
mod tests;

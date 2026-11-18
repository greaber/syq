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
//! Each body holds at most one chunk being read, and hyper holds only about
//! one more until the socket takes it, so live memory stays near two chunks
//! per request in flight. An empty pool never blocks a read: it allocates a
//! new buffer, which joins the pool when released if the pool has room.
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

/// Idle buffers kept for reuse: two per request at the default ceiling of 256
/// requests in flight. Idle buffers were all in use at once at some point,
/// so the cap only limits what a burst above it leaves behind.
static POOL: Pool = Pool::new(512);

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

/// A chunk's bytes. Dropping it, wherever that happens, returns a pooled
/// buffer to its pool.
struct Buffer {
    buffer: Vec<u8>,
    len: usize,
    pool: Option<&'static Pool>,
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

struct Opened {
    file: File,
    source: Source,
}

/// The upload body for `length` bytes of `file` from `offset`. `file` must
/// come from `source.open()`. Each copy the SDK makes of the body starts
/// again at `offset`. A body fails rather than finish once the source no
/// longer matches what was selected: a short read, or a changed size or
/// timestamp when the last chunk has been read. That failure is marked
/// [`super::retry::Permanent`], so the upload is not retried.
pub(super) fn body(source: Source, file: File, offset: u64, length: u64) -> SdkBody {
    let opened = Arc::new(Opened { file, source });
    SdkBody::retryable(move || {
        SdkBody::from_body_1_x(Chunks::new(opened.clone(), offset, length, &POOL))
    })
}

type Read = tokio::task::JoinHandle<std::io::Result<Buffer>>;

struct Chunks {
    opened: Arc<Opened>,
    offset: u64,
    end: u64,
    /// Bodies shorter than a chunk use one buffer of their own size.
    pool: Option<&'static Pool>,
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
                None => Buffer {
                    buffer: vec![0; n],
                    len: 0,
                    pool: None,
                },
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

//! One bounded queue per destination keeps range downloads from competing on
//! the same inode's buffered-write locks. Errors cross the completion barrier.
use anyhow::{Context, Result};
use std::{
    fs::File,
    os::unix::fs::FileExt,
    sync::{Arc, OnceLock},
};
use tokio::sync::{mpsc, oneshot};

enum Message {
    Write(bytes::Bytes, u64),
    WriteBatch(Vec<bytes::Bytes>, u64),
    Barrier(oneshot::Sender<Result<(), String>>),
}
#[derive(Clone)]
pub(super) struct Writer {
    send: Arc<OnceLock<mpsc::Sender<Message>>>,
    direct: Option<Arc<File>>,
    file: Arc<File>,
    size: u64,
}
impl Writer {
    pub fn with_readback(file: Arc<File>, size: u64, readback: bool) -> Result<Self> {
        let direct = if readback {
            None
        } else {
            direct_file(&file, size)?.map(Arc::new)
        };
        Ok(Self {
            send: Arc::new(OnceLock::new()),
            direct,
            file,
            size,
        })
    }
    // Downloads waiting for network data must not reserve blocking threads.
    // Clones share the queue once the first buffered write needs it.
    fn sender(&self) -> &mpsc::Sender<Message> {
        self.send.get_or_init(|| {
            let file = self.file.clone();
            // At most eight batches of 128 KiB queued per destination. SDK chunks can share
            // larger backing allocations with the active response reader.
            let (send, mut recv) = mpsc::channel::<Message>(8);
            tokio::spawn(async move {
                let mut error = None;
                while let Some(message) = recv.recv().await {
                    let file = file.clone();
                    // Drain ready writes in order, but never hold a blocking
                    // thread while waiting for network data or verification.
                    let result = tokio::task::spawn_blocking(move || {
                        let mut next = Some(message);
                        while let Some(message) = next {
                            match message {
                                Message::Write(bytes, offset) if error.is_none() => {
                                    let started = super::diagnostics::start();
                                    if let Err(e) = file.write_all_at(&bytes, offset) {
                                        error = Some(e.to_string());
                                    }
                                    super::diagnostics::elapsed(
                                        started,
                                        "buffered_write",
                                        bytes.len() as u64,
                                    );
                                }
                                Message::WriteBatch(bytes, offset) if error.is_none() => {
                                    let started = super::diagnostics::start();
                                    let length = bytes.iter().map(|b| b.len() as u64).sum();
                                    if let Err(e) = write_batch(&file, &bytes, offset) {
                                        error = Some(e.to_string());
                                    }
                                    super::diagnostics::elapsed(started, "buffered_write", length);
                                }
                                Message::Write(_, _) | Message::WriteBatch(_, _) => {}
                                Message::Barrier(reply) => {
                                    let _ = reply.send(error.clone().map_or(Ok(()), Err));
                                }
                            }
                            next = recv.try_recv().ok();
                        }
                        (recv, error)
                    })
                    .await;
                    let Ok((receiver, write_error)) = result else {
                        // Dropping the receiver reports failure to senders and
                        // any outstanding completion barriers.
                        return;
                    };
                    recv = receiver;
                    error = write_error;
                }
            });
            send
        })
    }
    pub fn direct(&self) -> bool {
        self.direct.is_some()
    }
    pub async fn write_direct(
        &self,
        buffer: Aligned,
        offset: u64,
        length: usize,
    ) -> Result<Aligned> {
        let file = self
            .direct
            .as_ref()
            .context("direct writer unavailable")?
            .clone();
        tokio::task::spawn_blocking(move || {
            let started = super::diagnostics::start();
            file.write_all_at(&buffer.bytes()[..length], offset)?;
            super::diagnostics::elapsed(started, "direct_write", length as u64);
            Ok(buffer)
        })
        .await?
    }
    pub async fn write(&self, bytes: bytes::Bytes, offset: u64) -> Result<()> {
        self.sender()
            .send(Message::Write(bytes, offset))
            .await
            .context("S3 destination writer stopped")
    }
    pub async fn write_batch(&self, mut bytes: Vec<bytes::Bytes>, offset: u64) -> Result<()> {
        if bytes.len() == 1 {
            return self.write(bytes.pop().unwrap(), offset).await;
        }
        self.sender()
            .send(Message::WriteBatch(bytes, offset))
            .await
            .context("S3 destination writer stopped")
    }
    pub async fn finish(&self) -> Result<()> {
        // No queue means no buffered write was submitted. In particular,
        // direct writes never need an idle blocking receiver of their own.
        if let Some(send) = self.send.get() {
            let (reply, done) = oneshot::channel();
            send.send(Message::Barrier(reply))
                .await
                .context("S3 destination writer stopped")?;
            done.await
                .context("S3 destination writer failed")?
                .map_err(anyhow::Error::msg)?;
        }
        if self.direct.is_some() {
            self.file.set_len(self.size)?;
        }
        Ok(())
    }
}

// Each batch contains at most 16 slices, the POSIX minimum IOV_MAX.
fn write_batch(file: &File, bytes: &[bytes::Bytes], offset: u64) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    if let [bytes] = bytes {
        return file.write_all_at(bytes, offset);
    }
    write_batch_with(bytes, offset, |vectors, offset| {
        // The slices stay alive for this call; pwritev only reads their data.
        let result = unsafe {
            libc::pwritev(
                file.as_raw_fd(),
                vectors.as_ptr(),
                vectors.len() as i32,
                offset,
            )
        };
        if result < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(result as usize)
        }
    })
}

fn write_batch_with(
    bytes: &[bytes::Bytes],
    mut offset: u64,
    mut write: impl FnMut(&[libc::iovec], libc::off_t) -> std::io::Result<usize>,
) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind};
    assert!(bytes.len() <= 16);
    let mut index = 0;
    let mut consumed = 0;
    while index < bytes.len() {
        if consumed == bytes[index].len() {
            index += 1;
            consumed = 0;
            continue;
        }
        let mut vectors = [libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 0,
        }; 16];
        for (i, bytes) in bytes[index..].iter().enumerate() {
            let start = if i == 0 { consumed } else { 0 };
            vectors[i] = libc::iovec {
                iov_base: bytes[start..].as_ptr().cast_mut().cast(),
                iov_len: bytes.len() - start,
            };
        }
        let position = libc::off_t::try_from(offset)
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "S3 write offset is too large"))?;
        let written = match write(&vectors[..bytes.len() - index], position) {
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            result => result?,
        };
        if written == 0 {
            return Err(Error::new(
                ErrorKind::WriteZero,
                "S3 vectored write returned zero",
            ));
        }
        offset += written as u64;
        consumed += written;
        while index < bytes.len() && consumed >= bytes[index].len() {
            consumed -= bytes[index].len();
            index += 1;
        }
    }
    Ok(())
}

pub(super) fn allocate(file: &File, size: u64) -> Result<()> {
    file.set_len(size)?;
    #[cfg(target_os = "linux")]
    if size > 0 {
        use std::os::fd::AsRawFd;
        let length = libc::off_t::try_from(size).context("S3 destination is too large")?;
        if unsafe { libc::fallocate(file.as_raw_fd(), 0, 0, length) } != 0 {
            let error = std::io::Error::last_os_error();
            if !matches!(
                error.raw_os_error(),
                Some(libc::EOPNOTSUPP | libc::ENOSYS | libc::EINVAL)
            ) {
                return Err(error).context("allocate S3 destination");
            }
        }
    }
    Ok(())
}

// Direct writes are used only when the filesystem explicitly advertises an
// alignment this implementation supports. Other filesystems keep queued writes.
fn direct_file(file: &File, size: u64) -> Result<Option<File>> {
    #[cfg(target_os = "linux")]
    if size >= 256 * 1024 * 1024 {
        use std::os::{
            fd::AsRawFd,
            unix::fs::{MetadataExt, OpenOptionsExt},
        };
        let mut stat = std::mem::MaybeUninit::<libc::statx>::zeroed();
        let rc = unsafe {
            libc::statx(
                file.as_raw_fd(),
                c"".as_ptr(),
                libc::AT_EMPTY_PATH,
                libc::STATX_DIOALIGN,
                stat.as_mut_ptr(),
            )
        };
        let stat = unsafe { stat.assume_init() };
        let reported = rc == 0 && stat.stx_mask & libc::STATX_DIOALIGN != 0;
        if reported {
            let mem = stat.stx_dio_mem_align;
            let off = stat.stx_dio_offset_align;
            if mem == 0 || off == 0 || 4096 % mem != 0 || 4096 % off != 0 {
                return Ok(None);
            }
        } else {
            // Linux before 6.1 lacks STATX_DIOALIGN. Restrict the probe to the
            // two filesystems exercised by this implementation, on our new file.
            let mut fs = std::mem::MaybeUninit::<libc::statfs>::zeroed();
            if unsafe { libc::fstatfs(file.as_raw_fd(), fs.as_mut_ptr()) } != 0 {
                return Ok(None);
            }
            let fs = unsafe { fs.assume_init() };
            if fs.f_type != libc::XFS_SUPER_MAGIC && fs.f_type != libc::EXT4_SUPER_MAGIC {
                return Ok(None);
            }
        }
        let output = match std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_DIRECT)
            .open(format!("/proc/self/fd/{}", file.as_raw_fd()))
        {
            Ok(file) => file,
            Err(e)
                if matches!(
                    e.raw_os_error(),
                    Some(libc::EOPNOTSUPP | libc::EINVAL | libc::ENOENT)
                ) =>
            {
                return Ok(None)
            }
            Err(e) => return Err(e).context("open direct S3 destination"),
        };
        let a = file.metadata()?;
        let b = output.metadata()?;
        anyhow::ensure!(
            (a.dev(), a.ino()) == (b.dev(), b.ino()),
            "direct destination identity differs"
        );
        if !reported {
            let probe = Aligned::new(4096)?;
            if let Err(e) = output.write_all_at(probe.bytes(), 0) {
                if matches!(e.raw_os_error(), Some(libc::EINVAL | libc::EOPNOTSUPP)) {
                    return Ok(None);
                }
                return Err(e).context("probe direct S3 destination alignment");
            }
        }
        return Ok(Some(output));
    }
    let _ = (file, size);
    Ok(None)
}

pub(super) struct Aligned {
    pointer: std::ptr::NonNull<u8>,
    size: usize,
}
// Sole owner; mutable access requires &mut, and no references escape that borrow.
unsafe impl Send for Aligned {}
impl Aligned {
    pub fn new(size: usize) -> Result<Self> {
        let mut pointer = std::ptr::null_mut();
        let rc = unsafe { libc::posix_memalign(&mut pointer, 4096, size) };
        anyhow::ensure!(rc == 0, "aligned download buffer allocation failed: {rc}");
        let pointer = std::ptr::NonNull::new(pointer.cast()).context("null download buffer")?;
        unsafe { std::ptr::write_bytes(pointer.as_ptr(), 0, size) };
        Ok(Self { pointer, size })
    }
    pub fn bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.pointer.as_ptr(), self.size) }
    }
    pub fn bytes_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.pointer.as_ptr(), self.size) }
    }
}
impl Drop for Aligned {
    fn drop(&mut self) {
        unsafe { libc::free(self.pointer.as_ptr().cast()) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_download_waiting_for_data_does_not_occupy_the_only_blocking_worker() {
        let dir = crate::test_support::tempdir().unwrap();
        let idle_file = Arc::new(File::create(dir.path().join("idle")).unwrap());
        let active_path = dir.path().join("active");
        let active_file = Arc::new(File::create(&active_path).unwrap());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        let result = runtime.block_on(async {
            let idle = Writer::with_readback(idle_file, 4, true).unwrap();
            let active = Writer::with_readback(active_file, 4, true).unwrap();
            let copied = tokio::time::timeout(std::time::Duration::from_secs(1), async {
                // A flush before any data must also leave the worker available.
                idle.finish().await?;
                idle.write(bytes::Bytes::from_static(b"12"), 0).await?;
                idle.finish().await?;
                tokio::task::spawn_blocking(|| ()).await?;
                active.write(bytes::Bytes::from_static(b"ab"), 0).await?;
                active
                    .clone()
                    .write(bytes::Bytes::from_static(b"cd"), 2)
                    .await?;
                active.finish().await?;
                idle.write(bytes::Bytes::from_static(b"34"), 2).await?;
                idle.finish().await
            })
            .await;
            // Release queues even on failure, so runtime shutdown cannot hang.
            drop(active);
            drop(idle);
            copied
        });
        runtime.shutdown_timeout(std::time::Duration::from_secs(1));
        result
            .expect("an idle download starved the ready writer")
            .unwrap();
        assert_eq!(std::fs::read(active_path).unwrap(), b"abcd");
        assert_eq!(std::fs::read(dir.path().join("idle")).unwrap(), b"1234");
    }

    #[test]
    fn vectored_writes_preserve_offsets_across_short_and_interrupted_calls() {
        let chunks = [
            bytes::Bytes::from_static(b"abc"),
            bytes::Bytes::new(),
            bytes::Bytes::from_static(b"defgh"),
            bytes::Bytes::from_static(b"ij"),
        ];
        let mut output = vec![b'_'; 17];
        let mut calls = 0;
        let mut offsets = Vec::new();
        write_batch_with(&chunks, 4, |vectors, offset| {
            calls += 1;
            offsets.push(offset);
            if calls == 1 {
                return Err(std::io::ErrorKind::Interrupted.into());
            }
            let available: Vec<u8> = vectors
                .iter()
                .flat_map(|v| unsafe {
                    // The helper supplies live slices from chunks.
                    std::slice::from_raw_parts(v.iov_base.cast::<u8>(), v.iov_len)
                })
                .copied()
                .collect();
            let length = available.len().min(if calls == 2 { 5 } else { 3 });
            let offset = offset as usize;
            output[offset..offset + length].copy_from_slice(&available[..length]);
            Ok(length)
        })
        .unwrap();
        assert_eq!(output, b"____abcdefghij___");
        assert_eq!(offsets, [4, 4, 9, 12]);
    }

    #[test]
    fn vectored_writes_report_zero_and_io_errors() {
        let bytes = [bytes::Bytes::from_static(b"data")];
        assert_eq!(
            write_batch_with(&bytes, 0, |_, _| Ok(0))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::WriteZero
        );
        assert_eq!(
            write_batch_with(
                &bytes,
                0,
                |_, _| Err(std::io::ErrorKind::StorageFull.into())
            )
            .unwrap_err()
            .kind(),
            std::io::ErrorKind::StorageFull
        );
        write_batch_with(&[], 0, |_, _| panic!("empty batch should not write")).unwrap();
    }

    #[tokio::test]
    async fn write_failure_crosses_completion_barrier() {
        for batched in [false, true] {
            let dir = crate::test_support::tempdir().unwrap();
            let path = dir.path().join("output");
            std::fs::write(&path, b"original").unwrap();
            let file = Arc::new(File::open(&path).unwrap());
            let writer = Writer::with_readback(file, 8, false).unwrap();
            if batched {
                writer
                    .write_batch(
                        vec![
                            bytes::Bytes::from_static(b"replace"),
                            bytes::Bytes::from_static(b"ment"),
                        ],
                        0,
                    )
                    .await
                    .unwrap();
            } else {
                writer
                    .write(bytes::Bytes::from_static(b"replacement"), 0)
                    .await
                    .unwrap();
            }
            assert!(writer.finish().await.is_err());
            // Failure stays sticky after a barrier and another drain of the queue.
            writer
                .write(bytes::Bytes::from_static(b"later"), 0)
                .await
                .unwrap();
            assert!(writer.finish().await.is_err());
            assert_eq!(std::fs::read(path).unwrap(), b"original");
        }
    }
}

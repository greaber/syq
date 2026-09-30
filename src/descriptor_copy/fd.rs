//! Caller-owned descriptors retain their shared file status flags. Exclusively
//! owned payload ends use nonblocking I/O so a cancelled entry can retire them.
use anyhow::{bail, Context, Result};
use std::{
    fs::File,
    io::Write,
    os::fd::{AsRawFd, FromRawFd},
    sync::{
        atomic::{AtomicBool, Ordering::Relaxed},
        Arc,
    },
};

// A small kernel pipe forces frequent producer/consumer wakeups and tiny
// network requests even when both ends are fast. This bounded, best-effort
// hint changes capacity only, never shared file status flags. Keep a larger
// caller-selected capacity and keep copying if the per-user quota refuses it.
#[cfg(target_os = "linux")]
fn enlarge_pipe(file: &File) {
    let size = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETPIPE_SZ) };
    if size > 0 && size < 1 << 20 {
        unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETPIPE_SZ, 1 << 20) };
    }
}

// macOS poll can miss FIFO readability while a large blocking write is
// pending, leaving both ends asleep despite buffered data. select wakes for
// that data. Keep bounded waits so owned streams can still be cancelled.
#[cfg(target_os = "macos")]
fn stream_ready(fd: i32, events: i16, timeout_ms: i32) -> i32 {
    unsafe extern "C" {
        // The _DARWIN_UNLIMITED_SELECT entry point accepts descriptors above
        // FD_SETSIZE when supplied with a sufficiently large bitmap.
        #[link_name = "select$DARWIN_EXTSN"]
        fn select_unlimited(
            nfds: libc::c_int,
            read: *mut libc::fd_set,
            write: *mut libc::fd_set,
            error: *mut libc::fd_set,
            timeout: *mut libc::timeval,
        ) -> libc::c_int;
    }
    debug_assert!(fd >= 0);
    debug_assert!(events == libc::POLLIN || events == libc::POLLOUT);
    // Use the stack for ordinary descriptors, and contiguous fd_set blocks
    // for high descriptors. FD_SET itself only sees an index within one block.
    let mut stack = [unsafe { std::mem::zeroed::<libc::fd_set>() }];
    let mut heap;
    let block = fd as usize / libc::FD_SETSIZE;
    let sets = if block == 0 {
        &mut stack[..]
    } else {
        heap = vec![stack[0]; block + 1];
        &mut heap[..]
    };
    unsafe { libc::FD_SET(fd % libc::FD_SETSIZE as i32, &mut sets[block]) };
    let mut timeout = libc::timeval {
        tv_sec: (timeout_ms / 1000).into(),
        tv_usec: ((timeout_ms % 1000) * 1000).into(),
    };
    let null = std::ptr::null_mut();
    let (read, write) = if events == libc::POLLIN {
        (sets.as_mut_ptr(), null)
    } else {
        (null, sets.as_mut_ptr())
    };
    unsafe { select_unlimited(fd + 1, read, write, null, &mut timeout) }
}

#[cfg(not(target_os = "macos"))]
fn stream_ready(fd: i32, events: i16, timeout_ms: i32) -> i32 {
    let mut poll = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    unsafe { libc::poll(&mut poll, 1, timeout_ms) }
}

/// A caller-owned descriptor, or an explicitly selected local FIFO.
#[derive(Clone, Debug)]
pub(crate) enum Source {
    Descriptor(i32),
    Pipe {
        path: std::path::PathBuf,
        follow: bool,
        root: Option<Vec<u8>>,
    },
}
impl Source {
    pub async fn open(self, cancelled: Arc<AtomicBool>) -> Result<Descriptor> {
        match self {
            Self::Descriptor(number) => Descriptor::open(number, true, cancelled),
            Self::Pipe { path, follow, root } => {
                tokio::task::spawn_blocking(move || {
                    use crate::rooted::PinnedPath;
                    use std::os::unix::{
                        ffi::OsStrExt,
                        fs::{FileTypeExt, MetadataExt},
                    };
                    let selected = super::resolve_source(
                        path.as_os_str().as_bytes(),
                        root.as_deref(),
                        follow,
                    )?;
                    let PinnedPath::Leaf(leaf) = selected else {
                        bail!("pipe source is not a FIFO");
                    };
                    anyhow::ensure!(leaf.metadata().is_fifo(), "pipe source is not a FIFO");
                    let (parent, name, expected, _object) = leaf.into_parts();
                    // This owned open waits for a writer. It runs outside the async
                    // executor so SIGINT/SIGTERM can still cancel a quiet FIFO.
                    let number = unsafe {
                        libc::openat(
                            parent.as_raw_fd(),
                            name.as_ptr(),
                            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NOCTTY,
                        )
                    };
                    if number < 0 {
                        return Err(std::io::Error::last_os_error()).context("open source FIFO");
                    }
                    let file = unsafe { File::from_raw_fd(number) };
                    let actual = file.metadata()?;
                    anyhow::ensure!(
                        actual.file_type().is_fifo()
                            && actual.dev() == expected.dev
                            && actual.ino() == expected.ino,
                        "source FIFO changed while opening"
                    );
                    Descriptor::owned(file, true, cancelled)
                })
                .await?
            }
        }
    }
}

pub(crate) struct CancelOnDrop(pub Arc<AtomicBool>);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Relaxed);
    }
}

#[derive(Default)]
pub(crate) struct Retirement {
    done: AtomicBool,
    changed: tokio::sync::Notify,
}
impl Retirement {
    pub(crate) async fn wait(&self) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.done.load(std::sync::atomic::Ordering::Acquire) {
                return;
            }
            changed.await;
        }
    }
}

pub(crate) struct Descriptor {
    file: File,
    retired: Arc<Retirement>,
    metadata: Option<std::fs::Metadata>,
    original: i32,
    descriptor_flags: i32,
    cancelled: Arc<AtomicBool>,
}
impl Descriptor {
    /// For a pipe/socket whose open-file description is exclusively owned by
    /// syq (including SDK payload ends). Caller-owned FDs use `open` instead.
    pub(crate) fn owned(file: File, upload: bool, cancelled: Arc<AtomicBool>) -> Result<Self> {
        let mut result = Self::open(file.as_raw_fd(), upload, cancelled)?;
        if result.metadata.is_none() {
            let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
            if flags < 0
                || unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) }
                    < 0
            {
                return Err(std::io::Error::last_os_error())
                    .context("make owned stream cancellable");
            }
        }
        // The original is now ours to close, not a caller descriptor whose
        // close-on-exec flags must be restored when the duplicate is dropped.
        result.original = -1;
        Ok(result)
    }
    pub(crate) fn retirement(&self) -> Option<Arc<Retirement>> {
        (self.original == -1).then(|| self.retired.clone())
    }
    pub fn open(fd: i32, upload: bool, cancelled: Arc<AtomicBool>) -> Result<Self> {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            bail!("descriptor {fd} is not open");
        }
        let mode = flags & libc::O_ACCMODE;
        if (upload && mode == libc::O_WRONLY) || (!upload && mode == libc::O_RDONLY) {
            bail!(
                "descriptor {fd} is not open for {}",
                if upload { "reading" } else { "writing" }
            );
        }
        let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        if duplicate < 0 {
            return Err(std::io::Error::last_os_error()).context("duplicate stream descriptor");
        }
        let file = unsafe { File::from_raw_fd(duplicate) };
        let metadata = file.metadata()?;
        use std::os::unix::fs::FileTypeExt;
        let kind = metadata.file_type();
        if !(kind.is_file() || kind.is_fifo() || kind.is_socket() || kind.is_char_device()) {
            bail!("descriptor {fd} must refer to a file, pipe, socket, or character device");
        }
        #[cfg(target_os = "linux")]
        if kind.is_fifo() {
            enlarge_pipe(&file);
        }
        let descriptor_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        let result = Self {
            file,
            retired: Arc::default(),
            metadata: kind.is_file().then_some(metadata),
            original: fd,
            descriptor_flags,
            cancelled,
        };
        if fd > 2
            && unsafe { libc::fcntl(fd, libc::F_SETFD, descriptor_flags | libc::FD_CLOEXEC) } < 0
        {
            return Err(std::io::Error::last_os_error())
                .context("protect stream descriptor inheritance");
        }
        Ok(result)
    }
    pub(crate) fn remaining_len(&self) -> Result<Option<u64>> {
        let Some(metadata) = &self.metadata else {
            return Ok(None);
        };
        let offset = unsafe { libc::lseek(self.file.as_raw_fd(), 0, libc::SEEK_CUR) };
        if offset < 0 {
            return Err(std::io::Error::last_os_error()).context("inspect stream offset");
        }
        Ok(Some(metadata.len().saturating_sub(offset as u64)))
    }
    pub(crate) fn metadata(&self) -> Option<crate::proto::Meta> {
        self.metadata.as_ref().map(super::metadata::from_file)
    }
    pub(crate) fn metadata_file(&self) -> Result<Option<File>> {
        self.metadata
            .as_ref()
            .map(|_| self.file.try_clone())
            .transpose()
            .map_err(Into::into)
    }
    pub(crate) fn apply_metadata(
        &self,
        policy: super::metadata::Policy,
        source: Option<crate::proto::Meta>,
    ) -> Result<()> {
        if self.metadata.is_some() {
            policy.apply(&self.file, source)?;
        }
        Ok(())
    }
    fn check_cancelled(&self) -> Result<()> {
        if self.cancelled.load(Relaxed) {
            bail!("stream cancelled");
        }
        Ok(())
    }
    // Owned payload ends and already-nonblocking inherited FDs can retire
    // without changing any caller's shared file status flags.
    fn wait(&self, events: i16) -> Result<()> {
        loop {
            if self.cancelled.load(Relaxed) {
                bail!("stream cancelled");
            }
            let rc = stream_ready(self.file.as_raw_fd(), events, 100);
            if rc > 0 {
                return Ok(());
            }
            if rc < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() != std::io::ErrorKind::Interrupted {
                    return Err(e.into());
                }
            }
        }
    }
    pub async fn read_chunk(self, size: usize) -> Result<(Self, bytes::Bytes)> {
        self.read(size, true).await
    }
    /// Return available bytes promptly; only the first read waits for input.
    pub async fn read_available(self, size: usize) -> Result<(Self, bytes::Bytes)> {
        self.read(size, false).await
    }
    async fn read(mut self, size: usize, fill: bool) -> Result<(Self, bytes::Bytes)> {
        tokio::task::spawn_blocking(move || {
            let data = self.read_bytes(size, fill)?;
            Ok((self, bytes::Bytes::from(data)))
        })
        .await?
    }
    pub(crate) fn read_bytes(&mut self, size: usize, fill: bool) -> Result<Vec<u8>> {
        self.read_reusing(size, fill, Vec::new())
    }
    pub(crate) fn read_reusing(
        &mut self,
        size: usize,
        fill: bool,
        mut bytes: Vec<u8>,
    ) -> Result<Vec<u8>> {
        bytes.clear();
        bytes
            .try_reserve_exact(size)
            .context("allocate stream part")?;
        while bytes.len() < size {
            self.check_cancelled()?;
            if !bytes.is_empty() && !fill {
                let ready = stream_ready(self.file.as_raw_fd(), libc::POLLIN, 0);
                if ready == 0 {
                    break;
                }
                if ready < 0 {
                    let e = std::io::Error::last_os_error();
                    if e.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(e.into());
                }
            }
            let used = bytes.len();
            // read initializes exactly the returned number of bytes in spare
            // capacity. Unread capacity is never exposed, hashed or sent.
            let n = unsafe {
                libc::read(
                    self.file.as_raw_fd(),
                    bytes.as_mut_ptr().add(used).cast(),
                    size - used,
                )
            };
            if n == 0 {
                break;
            }
            if n > 0 {
                unsafe {
                    bytes.set_len(used + n as usize);
                }
            } else {
                let e = std::io::Error::last_os_error();
                match e.kind() {
                    std::io::ErrorKind::Interrupted => continue,
                    std::io::ErrorKind::WouldBlock => self.wait(libc::POLLIN)?,
                    _ => return Err(e).context("read input stream"),
                }
            }
        }
        Ok(bytes)
    }
    pub async fn write_chunk(mut self, bytes: bytes::Bytes) -> Result<Self> {
        tokio::task::spawn_blocking(move || {
            let mut remaining = &bytes[..];
            while !remaining.is_empty() {
                self.check_cancelled()?;
                match self.file.write(remaining) {
                    Ok(0) => bail!("output stream made no progress"),
                    Ok(n) => remaining = &remaining[n..],
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        self.wait(libc::POLLOUT)?;
                    }
                    Err(e) => return Err(e).context("write output stream"),
                }
            }
            Ok(self)
        })
        .await?
    }
}
impl Drop for Descriptor {
    fn drop(&mut self) {
        self.retired
            .done
            .store(true, std::sync::atomic::Ordering::Release);
        self.retired.changed.notify_waiters();
        unsafe {
            if self.original > 2 {
                libc::fcntl(self.original, libc::F_SETFD, self.descriptor_flags);
            }
        }
    }
}

/// The SDK sends C followed by EOF only after its producer succeeds. A
/// disconnect, exception, or malformed completion message aborts publication.
pub(crate) async fn await_commit(control: Option<Descriptor>) -> Result<()> {
    if let Some(control) = control {
        let (_, message) = control.read_chunk(2).await?;
        anyhow::ensure!(
            &message[..] == b"C",
            "stream producer did not commit the upload"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::unix::net::UnixStream;
    #[test]
    fn stream_descriptor_preserves_flags_and_reads_blocking_or_nonblocking_input() {
        for nonblocking in [false, true] {
            let (source, mut producer) = UnixStream::pair().unwrap();
            source.set_nonblocking(nonblocking).unwrap();
            let original = unsafe { libc::fcntl(source.as_raw_fd(), libc::F_GETFL) };
            let inherited_flags = unsafe { libc::fcntl(source.as_raw_fd(), libc::F_GETFD) };
            let input = Descriptor::open(source.as_raw_fd(), true, Arc::default()).unwrap();
            assert_eq!(
                unsafe { libc::fcntl(source.as_raw_fd(), libc::F_GETFL) },
                original
            );
            let runtime = tokio::runtime::Runtime::new().unwrap();
            runtime.block_on(async {
                let read = input.read_chunk(1024);
                let write = async {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    producer.write_all(b"payload").unwrap();
                    producer.shutdown(std::net::Shutdown::Write).unwrap();
                };
                let (result, ()) = tokio::join!(read, write);
                let (input, data) = result.unwrap();
                assert_eq!(&data[..], b"payload");
                drop(input);
            });
            assert_eq!(
                unsafe { libc::fcntl(source.as_raw_fd(), libc::F_GETFD) },
                inherited_flags
            );
            assert_eq!(
                unsafe { libc::fcntl(source.as_raw_fd(), libc::F_GETFL) },
                original
            );
        }
    }
    #[test]
    fn owned_fifo_reads_large_writes_and_eof() {
        use std::os::unix::{ffi::OsStrExt, fs::OpenOptionsExt};
        use std::sync::mpsc;
        use std::time::Duration;

        let temp = crate::test_support::tempdir().unwrap();
        let path = temp.path().join("input");
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let file = File::options()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&path)
            .unwrap();
        let cancelled = Arc::new(AtomicBool::new(false));
        let mut input = Descriptor::owned(file, true, cancelled.clone()).unwrap();
        // Exceed the FIFO buffer so the writer must wait for reads. Keep the
        // write in one call, as a producer feeding an S3 multipart upload does.
        let payload = vec![0x5a; 5 * 1024 * 1024 + 11];
        let expected = payload.clone();
        let (connected, writer_ready) = mpsc::channel();
        let writer = std::thread::spawn(move || {
            let mut file = File::options().write(true).open(path).unwrap();
            connected.send(()).unwrap();
            file.write_all(&payload)
        });
        // Do not read a FIFO with no writer: that would be immediate EOF.
        writer_ready.recv_timeout(Duration::from_secs(5)).unwrap();
        let (finished, result) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            let bytes = input.read_bytes(6 * 1024 * 1024, true);
            let _ = finished.send(bytes);
        });
        let bytes = result.recv_timeout(Duration::from_secs(5));
        // On failure, retire the reader and release a blocked writer before
        // asserting, so a regression cannot leave either thread behind.
        cancelled.store(true, Relaxed);
        reader.join().unwrap();
        let written = writer.join().unwrap();
        let bytes = bytes.expect("large FIFO read stalled").unwrap();
        written.unwrap();
        assert_eq!(bytes, expected);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn readiness_handles_descriptors_above_fd_setsize() {
        // macOS shells can start with a soft limit below FD_SETSIZE. Raise it
        // for this test, without changing the hard limit, and restore on drop.
        struct RestoreLimit(libc::rlimit);
        impl Drop for RestoreLimit {
            fn drop(&mut self) {
                assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &self.0) }, 0);
            }
        }
        let mut limit = unsafe { std::mem::zeroed::<libc::rlimit>() };
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
            0
        );
        let _restore = RestoreLimit(limit);
        limit.rlim_cur = limit.rlim_cur.max((libc::FD_SETSIZE + 32) as libc::rlim_t);
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
        let (source, mut writer) = UnixStream::pair().unwrap();
        let high = unsafe {
            libc::fcntl(
                source.as_raw_fd(),
                libc::F_DUPFD_CLOEXEC,
                libc::FD_SETSIZE as i32,
            )
        };
        assert!(high >= libc::FD_SETSIZE as i32);
        let mut source = unsafe { File::from_raw_fd(high) };
        assert_eq!(stream_ready(high, libc::POLLIN, 0), 0);
        assert_eq!(stream_ready(high, libc::POLLOUT, 0), 1);
        writer.write_all(b"x").unwrap();
        assert_eq!(stream_ready(high, libc::POLLIN, 100), 1);
        let mut byte = [0];
        source.read_exact(&mut byte).unwrap();
        assert_eq!(&byte, b"x");
        assert_eq!(stream_ready(high, libc::POLLIN, 0), 0);
        drop(writer);
        assert_eq!(stream_ready(high, libc::POLLIN, 100), 1);
        assert_eq!(source.read(&mut byte).unwrap(), 0);
    }

    #[test]
    fn stream_descriptor_uses_current_offset_without_truncation() {
        use std::io::{Seek, SeekFrom};
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(b"0123456789").unwrap();
        file.seek(SeekFrom::Start(3)).unwrap();
        let descriptor = Descriptor::open(file.as_raw_fd(), false, Arc::default()).unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        drop(
            runtime
                .block_on(descriptor.write_chunk(bytes::Bytes::from_static(b"abc")))
                .unwrap(),
        );
        assert_eq!(file.stream_position().unwrap(), 6);
        file.rewind().unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"012abc6789");
    }
}

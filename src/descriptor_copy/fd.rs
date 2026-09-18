//! Inherited byte streams without changing shared file status flags. Blocking
//! workers may outlive cancellation; the CLI exits after network cleanup.
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
                    Ok(Descriptor {
                        file,
                        original: -1,
                        descriptor_flags: 0,
                        cancelled,
                    })
                })
                .await?
            }
        }
    }
}

pub(crate) struct Descriptor {
    file: File,
    original: i32,
    descriptor_flags: i32,
    cancelled: Arc<AtomicBool>,
}
impl Descriptor {
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
        let descriptor_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        let result = Self {
            file,
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
    fn check_cancelled(&self) -> Result<()> {
        if self.cancelled.load(Relaxed) {
            bail!("stream cancelled");
        }
        Ok(())
    }
    // Only already-nonblocking descriptors need poll. Process exit ends a quiet
    // wait, just as it ends a blocking read/write; no periodic wakeup is needed.
    fn wait(&self, events: i16) -> Result<()> {
        loop {
            if self.cancelled.load(Relaxed) {
                bail!("stream cancelled");
            }
            let mut poll = libc::pollfd {
                fd: self.file.as_raw_fd(),
                events,
                revents: 0,
            };
            let rc = unsafe { libc::poll(&mut poll, 1, -1) };
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
        let mut bytes = Vec::<u8>::new();
        bytes
            .try_reserve_exact(size)
            .context("allocate stream part")?;
        while bytes.len() < size {
            self.check_cancelled()?;
            if !bytes.is_empty() && !fill {
                let mut poll = libc::pollfd {
                    fd: self.file.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                let ready = unsafe { libc::poll(&mut poll, 1, 0) };
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

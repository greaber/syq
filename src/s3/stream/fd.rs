//! Inherited byte streams. Nonblocking I/O lets cancellation interrupt a quiet
//! pipe or a stopped consumer. Status flags belong to the open file description,
//! so restore them before returning ownership to an embedding caller.
use anyhow::{bail, Context, Result};
use std::{
    fs::File,
    io::{Read, Write},
    os::fd::{AsRawFd, FromRawFd},
    sync::{
        atomic::{AtomicBool, Ordering::Relaxed},
        Arc,
    },
};

pub(super) struct Descriptor {
    file: File,
    flags: i32,
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
        if unsafe { libc::fcntl(duplicate, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(std::io::Error::last_os_error())
                .context("make stream descriptor nonblocking");
        }
        let descriptor_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        let result = Self {
            file,
            original: fd,
            descriptor_flags,
            flags,
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
            let rc = unsafe { libc::poll(&mut poll, 1, 100) };
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
    pub async fn read_chunk(mut self, size: usize) -> Result<(Self, bytes::Bytes)> {
        tokio::task::spawn_blocking(move || {
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(size)
                .context("allocate stream part")?;
            bytes.resize(size, 0);
            let mut used = 0;
            while used < size {
                self.wait(libc::POLLIN)?;
                match self.file.read(&mut bytes[used..]) {
                    Ok(0) => break,
                    Ok(n) => used += n,
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                        ) => {}
                    Err(e) => return Err(e).context("read input stream"),
                }
            }
            bytes.truncate(used);
            Ok((self, bytes::Bytes::from(bytes)))
        })
        .await?
    }
    pub async fn write_chunk(mut self, bytes: bytes::Bytes) -> Result<Self> {
        tokio::task::spawn_blocking(move || {
            let mut remaining = &bytes[..];
            while !remaining.is_empty() {
                self.wait(libc::POLLOUT)?;
                match self.file.write(remaining) {
                    Ok(0) => bail!("output stream made no progress"),
                    Ok(n) => remaining = &remaining[n..],
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                        ) => {}
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
            libc::fcntl(self.file.as_raw_fd(), libc::F_SETFL, self.flags);
            if self.original > 2 {
                libc::fcntl(self.original, libc::F_SETFD, self.descriptor_flags);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    #[test]
    fn stream_descriptor_cancellation_restores_flags() {
        let (source, _producer) = UnixStream::pair().unwrap();
        let original = unsafe { libc::fcntl(source.as_raw_fd(), libc::F_GETFL) };
        let inherited_flags = unsafe { libc::fcntl(source.as_raw_fd(), libc::F_GETFD) };
        let cancelled = Arc::new(AtomicBool::new(false));
        let input = Descriptor::open(source.as_raw_fd(), true, cancelled.clone()).unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let read = input.read_chunk(1024);
            let cancel = async {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                cancelled.store(true, Relaxed);
            };
            let (result, ()) = tokio::time::timeout(std::time::Duration::from_secs(3), async {
                tokio::join!(read, cancel)
            })
            .await
            .unwrap();
            assert!(result.is_err());
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

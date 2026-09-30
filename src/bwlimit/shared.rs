//! A copy's source helpers share only a pacing counter, never payload buffers.
//! The unlinked file is handed out through the existing authenticated descriptor
//! broker. It lives only until the last helper releases its mapping.
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, AtomicU64};

const MAGIC: u64 = 0x5359514257303031;
#[repr(C, align(64))]
struct Layout {
    magic: u64,
    rate: u64,
    next: AtomicU64,
    closed: AtomicBool,
}

pub(super) struct Shared {
    address: NonNull<Layout>,
}
// All mutable shared fields are native, aligned, lock-free atomics on syq's
// supported 64-bit platforms. The mapping stays valid for this object's life.
unsafe impl Send for Shared {}
unsafe impl Sync for Shared {}

impl Shared {
    pub(super) fn create(rate: u64) -> io::Result<(Self, File)> {
        let file = tempfile::tempfile()?;
        file.set_len(size_of::<Layout>() as u64)?;
        let mapping = Self::map(&file)?;
        unsafe {
            mapping.address.as_ptr().write(Layout {
                magic: MAGIC,
                rate,
                next: AtomicU64::new(0),
                closed: AtomicBool::new(false),
            });
        }
        Ok((mapping, file))
    }

    pub(super) fn open(file: &File) -> io::Result<Self> {
        if file.metadata()?.len() != size_of::<Layout>() as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid bandwidth budget size",
            ));
        }
        let mapping = Self::map(file)?;
        if mapping.layout().magic != MAGIC || mapping.layout().rate == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid bandwidth budget header",
            ));
        }
        Ok(mapping)
    }

    fn map(file: &File) -> io::Result<Self> {
        let address = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size_of::<Layout>(),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                0,
            )
        };
        if address == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            address: NonNull::new(address.cast()).expect("mmap returned null"),
        })
    }
    fn layout(&self) -> &Layout {
        unsafe { self.address.as_ref() }
    }
    pub(super) fn rate(&self) -> u64 {
        self.layout().rate
    }
    pub(super) fn next(&self) -> &AtomicU64 {
        &self.layout().next
    }
    pub(super) fn closed(&self) -> &AtomicBool {
        &self.layout().closed
    }
}
impl Drop for Shared {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.address.as_ptr().cast(), size_of::<Layout>());
        }
    }
}

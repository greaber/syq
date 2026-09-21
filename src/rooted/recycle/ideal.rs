//! Unsafe experiment: exclusively controlled, equal-size, ordinary files only.
//! No per-file eligibility/identity/reader checks. Never enable for user data.
use super::*;
use std::sync::atomic::{AtomicU32, AtomicU64};

const NAME: &CStr = c"ideal";
const MASK: u64 = (1 << SLOTS) - 1;
#[repr(C, align(64))]
struct Cell(AtomicU64);
#[repr(C)]
struct Header {
    free: Cell,
    ready: Cell,
    size: Cell,
    closed: Cell,
    files: Cell,
    bytes: Cell,
    expected: Cell,
    started: Cell,
    drained: Cell,
    epoch: AtomicU32,
}

pub(super) struct Ideal {
    header: std::ptr::NonNull<Header>,
    names: [CString; SLOTS],
}
// The mapping is shared by processes; every mutable field is an atomic.
unsafe impl Send for Ideal {}
unsafe impl Sync for Ideal {}
impl Drop for Ideal {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.header.as_ptr().cast(), std::mem::size_of::<Header>()) };
    }
}
impl Ideal {
    fn map(file: &File) -> Result<Self> {
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                std::mem::size_of::<Header>(),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                0,
            )
        };
        anyhow::ensure!(
            p != libc::MAP_FAILED,
            "map ideal pool: {}",
            io::Error::last_os_error()
        );
        Ok(Self {
            header: std::ptr::NonNull::new(p.cast()).unwrap(),
            names: std::array::from_fn(|i| CString::new(i.to_string()).unwrap()),
        })
    }
    fn h(&self) -> &Header {
        unsafe { self.header.as_ref() }
    }
    pub(super) fn create(directory: &File) -> Result<()> {
        let expected = std::env::var("SYQ_EXPERIMENT_DRAIN_FILES")
            .ok()
            .map(|s| s.parse::<u64>())
            .transpose()?
            .unwrap_or(0);
        let file = open_at(
            directory.as_raw_fd(),
            NAME,
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
            0o600,
        )?;
        file.set_len(std::mem::size_of::<Header>() as u64)?;
        let map = Self::map(&file)?;
        // Initialization precedes publishing the pool descriptor to workers.
        unsafe {
            map.header.as_ptr().write(Header {
                free: Cell(AtomicU64::new(MASK)),
                ready: Cell(AtomicU64::new(0)),
                size: Cell(AtomicU64::new(0)),
                closed: Cell(AtomicU64::new(0)),
                files: Cell(AtomicU64::new(0)),
                bytes: Cell(AtomicU64::new(0)),
                expected: Cell(AtomicU64::new(expected)),
                started: Cell(AtomicU64::new(0)),
                drained: Cell(AtomicU64::new(0)),
                epoch: AtomicU32::new(0),
            });
        }
        Ok(())
    }
    pub(super) fn open(directory: &File) -> Result<Option<Self>> {
        match open_at(
            directory.as_raw_fd(),
            NAME,
            libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0,
        ) {
            Ok(file) => {
                anyhow::ensure!(
                    file.metadata()?.len() == std::mem::size_of::<Header>() as u64,
                    "invalid ideal pool header"
                );
                Self::map(&file).map(Some)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
    pub(super) fn close(&self, directory: &File) -> Result<()> {
        self.h().closed.0.store(1, Ordering::Release);
        self.wake(i32::MAX);
        unlink_at(directory.as_raw_fd(), NAME, 0)?;
        Ok(())
    }
    pub(super) fn draining_enabled(&self) -> bool {
        self.h().expected.0.load(Ordering::Acquire) != 0
    }
    fn wake(&self, count: i32) {
        self.h().epoch.fetch_add(1, Ordering::Release);
        // Shared, not PRIVATE: transfer workers may live in other processes.
        unsafe {
            libc::syscall(
                libc::SYS_futex,
                &self.h().epoch as *const AtomicU32,
                libc::FUTEX_WAKE,
                count,
            );
        }
    }
    pub(super) fn drain(self, directory: File) -> Result<()> {
        loop {
            let h = self.h();
            let epoch = h.epoch.load(Ordering::Acquire);
            let closed = h.closed.0.load(Ordering::Acquire) != 0;
            if self.drain_one(&directory)? {
                continue;
            }
            if closed {
                return Ok(());
            }
            let result = unsafe {
                libc::syscall(
                    libc::SYS_futex,
                    &h.epoch as *const AtomicU32,
                    libc::FUTEX_WAIT,
                    epoch,
                    std::ptr::null::<libc::timespec>(),
                )
            };
            if result == -1 {
                let error = io::Error::last_os_error();
                if !matches!(error.raw_os_error(), Some(libc::EAGAIN | libc::EINTR)) {
                    return Err(error.into());
                }
            }
        }
    }
    fn drain_one(&self, directory: &File) -> Result<bool> {
        let h = self.h();
        if h.closed.0.load(Ordering::Acquire) == 0
            && h.started.0.load(Ordering::Acquire) < h.expected.0.load(Ordering::Acquire)
        {
            return Ok(false);
        }
        let Some(slot) = claim(&h.ready.0, MASK) else {
            return Ok(false);
        };
        unlink_at(directory.as_raw_fd(), &self.names[slot], 0)?;
        h.drained.0.fetch_add(1, Ordering::Relaxed);
        h.free.0.fetch_or(1 << slot, Ordering::Release);
        Ok(true)
    }
    pub(super) fn report_drain(&self) {
        eprintln!(
            "syq: experimental drain: started={}, expected={}, removed={}",
            self.h().started.0.load(Ordering::Acquire),
            self.h().expected.0.load(Ordering::Acquire),
            self.h().drained.0.load(Ordering::Acquire)
        );
    }
    pub(super) fn stats(&self) -> crate::proto::RecyclingStats {
        crate::proto::RecyclingStats {
            files: self.h().files.0.load(Ordering::Relaxed),
            bytes: self.h().bytes.0.load(Ordering::Relaxed),
        }
    }
    pub(super) fn take(
        &self,
        pool: &Pool,
        parent: &ResolvedParent<'_>,
        size: u64,
    ) -> Result<Option<File>> {
        let result = self.take_inner(pool, parent, size);
        if result.is_ok() && self.draining_enabled() {
            // Experiment-only oracle: each equal-size fixture file calls take
            // once. Signal only AFTER taking its staging inode, so reclamation
            // cannot steal the final file's reuse opportunity.
            let started = self.h().started.0.fetch_add(1, Ordering::AcqRel) + 1;
            anyhow::ensure!(
                started <= self.h().expected.0.load(Ordering::Acquire),
                "more staging acquisitions than the drain experiment expected"
            );
            if started == self.h().expected.0.load(Ordering::Acquire) {
                self.wake(i32::MAX);
            }
        }
        result
    }
    fn take_inner(
        &self,
        pool: &Pool,
        parent: &ResolvedParent<'_>,
        size: u64,
    ) -> Result<Option<File>> {
        let h = self.h();
        if h.closed.0.load(Ordering::Acquire) != 0 {
            return Ok(None);
        }
        let expected = h
            .size
            .0
            .compare_exchange(0, size, Ordering::AcqRel, Ordering::Acquire)
            .unwrap_or_else(|s| s);
        anyhow::ensure!(
            expected == 0 || expected == size,
            "ideal experiment requires equal file sizes"
        );
        let Some(slot) = claim(&h.ready.0, MASK) else {
            return Ok(None);
        };
        let name = &self.names[slot];
        // Open replaces the ordinary fresh-staging open; rename is additional.
        let result = (|| {
            let file = open_at(
                pool.directory.as_raw_fd(),
                name,
                libc::O_RDWR | libc::O_CLOEXEC,
                0,
            )?;
            retry_zero(|| unsafe {
                libc::renameat2(
                    pool.directory.as_raw_fd(),
                    name.as_ptr(),
                    parent.directory.as_raw_fd(),
                    parent.leaf.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            })?;
            Ok(file)
        })();
        match result {
            Ok(file) => {
                h.free.0.fetch_or(1 << slot, Ordering::Release);
                h.files.0.fetch_add(1, Ordering::Relaxed);
                h.bytes.0.fetch_add(size, Ordering::Relaxed);
                Ok(Some(file))
            }
            Err(e) => {
                h.ready.0.fetch_or(1 << slot, Ordering::Release);
                Err(e)
            }
        }
    }
    pub(super) fn publish(
        &self,
        pool: &Pool,
        source: &ResolvedParent<'_>,
        target: &ResolvedParent<'_>,
    ) -> Result<bool> {
        let h = self.h();
        if h.closed.0.load(Ordering::Acquire) != 0 {
            return Ok(false);
        }
        let size = h.size.0.load(Ordering::Acquire);
        if size == 0 {
            return Ok(false);
        }
        let count = (pool.max_bytes / size).min(SLOTS as u64);
        let allowed = (1u64 << count) - 1;
        let Some(slot) = claim(&h.free.0, allowed) else {
            return Ok(false);
        };
        let name = &self.names[slot];
        let linked = retry_zero(|| unsafe {
            libc::linkat(
                target.directory.as_raw_fd(),
                target.leaf.as_ptr(),
                pool.directory.as_raw_fd(),
                name.as_ptr(),
                0,
            )
        });
        if let Err(e) = linked {
            h.free.0.fetch_or(1 << slot, Ordering::Release);
            if e.kind() == io::ErrorKind::NotFound {
                return Ok(false);
            }
            return Err(e.into());
        }
        let result = retry_zero(|| unsafe {
            libc::renameat(
                source.directory.as_raw_fd(),
                source.leaf.as_ptr(),
                target.directory.as_raw_fd(),
                target.leaf.as_ptr(),
            )
        });
        if let Err(e) = result {
            unlink_at(pool.directory.as_raw_fd(), name, 0)?;
            h.free.0.fetch_or(1 << slot, Ordering::Release);
            return Err(e.into());
        }
        // Publish only after the previous destination name has been replaced.
        h.ready.0.fetch_or(1 << slot, Ordering::Release);
        if self.draining_enabled()
            && h.started.0.load(Ordering::Acquire) >= h.expected.0.load(Ordering::Acquire)
        {
            self.wake(1);
        }
        Ok(true)
    }
}

fn claim(bits: &AtomicU64, allowed: u64) -> Option<usize> {
    bits.fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
        let usable = current & allowed;
        (usable != 0).then(|| current & !(1 << usable.trailing_zeros()))
    })
    .ok()
    .map(|previous| (previous & allowed).trailing_zeros() as usize)
}

#[cfg(test)]
mod drain_tests {
    use super::*;

    #[test]
    fn reclamation_waits_for_the_last_staging_acquisition() {
        let temp = tempfile::tempdir_in(crate::test_support::temp_dir()).unwrap();
        let directory = File::open(temp.path()).unwrap();
        Ideal::create(&directory).unwrap();
        let ideal = Ideal::open(&directory).unwrap().unwrap();
        ideal.h().expected.0.store(2, Ordering::Release);
        std::fs::write(temp.path().join("0"), b"old contents").unwrap();
        ideal.h().free.0.fetch_and(!1, Ordering::Release);
        ideal.h().ready.0.store(1, Ordering::Release);
        ideal.h().started.0.store(1, Ordering::Release);
        assert!(!ideal.drain_one(&directory).unwrap());
        assert!(temp.path().join("0").exists());
        ideal.h().started.0.store(2, Ordering::Release);
        assert!(ideal.drain_one(&directory).unwrap());
        assert!(!temp.path().join("0").exists());
        assert_eq!(ideal.h().drained.0.load(Ordering::Acquire), 1);
        assert_eq!(ideal.h().free.0.load(Ordering::Acquire), MASK);
        assert!(!ideal.drain_one(&directory).unwrap());
    }

    #[test]
    fn closing_wakes_a_drainer_even_before_the_expected_file_count() {
        let temp = tempfile::tempdir_in(crate::test_support::temp_dir()).unwrap();
        let directory = File::open(temp.path()).unwrap();
        Ideal::create(&directory).unwrap();
        let ideal = Ideal::open(&directory).unwrap().unwrap();
        ideal.h().expected.0.store(2, Ordering::Release);
        let worker = Ideal::open(&directory).unwrap().unwrap();
        let worker_directory = directory.try_clone().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            tx.send(worker.drain(worker_directory)).unwrap();
        });
        ideal.close(&directory).unwrap();
        rx.recv_timeout(std::time::Duration::from_secs(2))
            .unwrap()
            .unwrap();
        thread.join().unwrap();
    }
}

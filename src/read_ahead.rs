//! Bounded source-page preparation, independent of copy operation and transport.
//!
//! The caller owns an explicit contiguous range and decides when preparation
//! is useful. Drop this state before releasing or reassigning that range. A
//! sparse-range scheduler supplies a separate window for each owned interval;
//! this component never assumes that the rest of the file should be read.
use std::fs::File;
use std::ops::Range;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread::JoinHandle;

const BLOCK: u64 = 1 << 20;
const LOOKAHEAD: u64 = 4 * BLOCK;
// Large WILLNEED requests can be truncated to the device's readahead window.
// Submit smaller requests so the helper prepares the entire bounded window.
const REQUEST: u64 = 128 << 10;

struct Budget {
    active: AtomicUsize,
    limit: usize,
}

impl Budget {
    fn acquire(self: &Arc<Self>) -> Option<Permit> {
        self.active
            .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |active| {
                (active < self.limit).then_some(active + 1)
            })
            .ok()
            .map(|_| Permit(self.clone()))
    }
}

struct Permit(Arc<Budget>);
impl Drop for Permit {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Release);
    }
}

fn budget() -> &'static Arc<Budget> {
    static BUDGET: OnceLock<Arc<Budget>> = OnceLock::new();
    BUDGET.get_or_init(|| {
        Arc::new(Budget {
            active: AtomicUsize::new(0),
            // Scale helpers with available CPUs, with at least one for I/O
            // overlap. Cap explicit prefetch at eight helpers / 32 MiB ahead.
            limit: (std::thread::available_parallelism().map_or(1, usize::from) / 2).clamp(1, 8),
        })
    })
}

#[derive(Default)]
struct Progress {
    copied: u64,
    stopped: bool,
}

struct Worker {
    progress: Arc<(Mutex<Progress>, Condvar)>,
    thread: Option<JoinHandle<()>>,
    _permit: Permit,
}

impl Worker {
    fn start(source: File, copied: u64, size: u64, permit: Permit) -> std::io::Result<Self> {
        let progress = Arc::new((
            Mutex::new(Progress {
                copied,
                stopped: false,
            }),
            Condvar::new(),
        ));
        let shared = progress.clone();
        let thread = std::thread::Builder::new()
            .name("syq-read-ahead".into())
            .spawn(move || {
                let mut offset = copied;
                while offset < size {
                    let (lock, wake) = &*shared;
                    let mut progress = lock.lock().unwrap_or_else(|e| e.into_inner());
                    while !progress.stopped && offset >= progress.copied.saturating_add(LOOKAHEAD) {
                        progress = wake.wait(progress).unwrap_or_else(|e| e.into_inner());
                    }
                    if progress.stopped {
                        break;
                    }
                    // Never prefetch data the writer has already consumed.
                    offset = offset.max(progress.copied);
                    let end = size.min(progress.copied.saturating_add(LOOKAHEAD));
                    drop(progress);
                    let len = REQUEST.min(end.saturating_sub(offset));
                    if len == 0 {
                        break;
                    }
                    // SAFETY: source owns the live, already-authorized fd. The
                    // syscall only advises reads and never accesses user memory.
                    let error = unsafe {
                        libc::posix_fadvise(
                            source.as_raw_fd(),
                            offset as libc::off_t,
                            len as libc::off_t,
                            libc::POSIX_FADV_WILLNEED,
                        )
                    };
                    if error != 0 {
                        // Advisory failure must not replace the writer's actual
                        // read/write result. Stop trying, leaving normal copying.
                        break;
                    }
                    offset += len;
                }
            })?;
        Ok(Self {
            progress,
            thread: Some(thread),
            _permit: permit,
        })
    }

    fn advance(&self, copied: u64) {
        let (lock, wake) = &*self.progress;
        lock.lock().unwrap_or_else(|e| e.into_inner()).copied = copied;
        wake.notify_one();
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        let (lock, wake) = &*self.progress;
        lock.lock().unwrap_or_else(|e| e.into_inner()).stopped = true;
        wake.notify_one();
        // No helper retains the source or issues further advice after the copy
        // succeeds, fails, or unwinds. The helper never writes the destination.
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub(crate) struct ReadAhead {
    range: Range<u64>,
    worker: Option<Worker>,
    attempted: bool,
}

impl ReadAhead {
    pub(crate) fn new(range: Range<u64>) -> Self {
        Self {
            range,
            worker: None,
            attempted: false,
        }
    }

    pub(crate) fn advance(
        &mut self,
        source: &File,
        copied: u64,
        should_prepare: impl FnOnce() -> bool,
    ) {
        if copied < self.range.start || copied >= self.range.end {
            return;
        }
        if let Some(worker) = &self.worker {
            worker.advance(copied);
            return;
        }
        if self.attempted {
            return;
        }
        if !should_prepare() {
            return;
        }
        let Some(permit) = budget().acquire() else {
            return;
        };
        self.attempted = true;
        // Descriptor/thread allocation is optional optimization work. Failure
        // leaves the authorized kernel copy running normally.
        let Ok(source) = source.try_clone() else {
            return;
        };
        self.worker = Worker::start(source, copied, self.range.end, permit).ok();
        if self.worker.is_some() && std::env::var_os("SYQ_DEBUG").is_some() {
            eprintln!("syq: local read-ahead started: {copied}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_budget_is_released_after_stop() {
        let budget = Arc::new(Budget {
            active: AtomicUsize::new(0),
            limit: 1,
        });
        let permit = budget.acquire().unwrap();
        assert!(budget.acquire().is_none());
        let temp = crate::test_support::tempdir().unwrap();
        let source = File::create(temp.path().join("source")).unwrap();
        // The slot remains reserved even when prefetch reaches EOF before
        // the writer: those pages still consume the copy's lookahead budget.
        let mut worker = Worker::start(source, 0, 0, permit).unwrap();
        worker.thread.take().unwrap().join().unwrap();
        assert!(budget.acquire().is_none());
        drop(worker);
        assert!(budget.acquire().is_some());
        assert_eq!(
            std::fs::metadata(temp.path().join("source")).unwrap().len(),
            0
        );
    }

    #[test]
    fn preparation_is_limited_to_the_callers_range_and_signal() {
        let temp = crate::test_support::tempdir().unwrap();
        let source = File::create(temp.path().join("source")).unwrap();
        let mut preparation = ReadAhead::new(4096..8192);
        for offset in [0, 4095, 8192, 16384] {
            preparation.advance(&source, offset, || panic!("outside owned range"));
        }
        let mut consulted = false;
        preparation.advance(&source, 4096, || {
            consulted = true;
            false
        });
        assert!(consulted);
        assert!(preparation.worker.is_none());
    }

    #[test]
    fn completed_copy_never_starts_a_helper() {
        let temp = crate::test_support::tempdir().unwrap();
        let source = File::create(temp.path().join("source")).unwrap();
        let mut read_ahead = ReadAhead::new(0..1);
        read_ahead.advance(&source, 1, || {
            panic!("finished ranges need no activation check")
        });
        assert!(read_ahead.worker.is_none());
    }
}

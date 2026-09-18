//! Source-page preparation for already-owned read ranges. No transport or
//! payload queue lives here. Dropping a range fences all its advisory work;
//! the bounded helper can be reused for another range, file, or attempt.
use std::fs::File;
use std::ops::Range;
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread::JoinHandle;

pub(crate) const BLOCK: u64 = 1 << 20;
const LOOKAHEAD: u64 = 4 * BLOCK;
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

struct Window {
    source: Arc<File>,
    copied: u64,
    offset: u64,
    end: u64,
}

#[derive(Default)]
struct State {
    window: Option<Window>,
    in_flight: bool,
    stopped: bool,
}

struct Worker {
    shared: Arc<(Mutex<State>, Condvar)>,
    thread: Option<JoinHandle<()>>,
    _permit: Permit,
}

impl Worker {
    fn start(
        permit: Permit,
        observation: Option<Arc<crate::transfer_observations::Actor>>,
    ) -> std::io::Result<Self> {
        struct EndObservation(Option<Arc<crate::transfer_observations::Actor>>);
        impl Drop for EndObservation {
            fn drop(&mut self) {
                if let Some(actor) = &self.0 {
                    actor.finish_thread();
                }
            }
        }
        let end_observation = EndObservation(observation.clone());
        let observing = observation.clone();
        Self::start_with(permit, move |fd, offset, len| {
            let _keep_until_thread_exit = &end_observation;
            let span = observing
                .as_ref()
                .map(|a| a.span(crate::transfer_observations::Stage::PrefetchAdvice));
            if let Some(span) = &span {
                span.bytes(len);
            }
            // SAFETY: the caller holds the authorized descriptor and a checked
            // off_t range until this advisory operation returns.
            unsafe {
                libc::posix_fadvise(
                    fd,
                    offset as libc::off_t,
                    len as libc::off_t,
                    libc::POSIX_FADV_WILLNEED,
                )
            }
        })
    }

    fn start_with(
        permit: Permit,
        advise: impl Fn(i32, u64, u64) -> i32 + Send + 'static,
    ) -> std::io::Result<Self> {
        let shared = Arc::new((Mutex::new(State::default()), Condvar::new()));
        let background = shared.clone();
        let thread = std::thread::Builder::new()
            .name("syq-read-ahead".into())
            .spawn(move || {
                let (lock, wake) = &*background;
                let mut state = lock.lock().unwrap_or_else(|e| e.into_inner());
                loop {
                    if state.stopped {
                        break;
                    }
                    let request = state.window.as_mut().and_then(|window| {
                        window.offset = window.offset.max(window.copied);
                        let end = window.end.min(window.copied.saturating_add(LOOKAHEAD));
                        let len = REQUEST.min(end.saturating_sub(window.offset));
                        if len == 0 {
                            return None;
                        }
                        let request = (window.source.clone(), window.offset, len);
                        window.offset += len;
                        Some(request)
                    });
                    let Some((source, offset, len)) = request else {
                        state = wake.wait(state).unwrap_or_else(|e| e.into_inner());
                        continue;
                    };
                    state.in_flight = true;
                    drop(state);
                    let error = advise(source.as_raw_fd(), offset, len);
                    drop(source);
                    state = lock.lock().unwrap_or_else(|e| e.into_inner());
                    state.in_flight = false;
                    if error != 0 {
                        state.window = None;
                    }
                    wake.notify_all();
                }
            })?;
        Ok(Self {
            shared,
            thread: Some(thread),
            _permit: permit,
        })
    }

    fn begin(&self, source: File, copied: u64, end: u64) {
        let (lock, wake) = &*self.shared;
        let mut state = lock.lock().unwrap_or_else(|e| e.into_inner());
        debug_assert!(state.window.is_none() && !state.in_flight);
        state.window = Some(Window {
            source: Arc::new(source),
            copied,
            offset: copied,
            end,
        });
        wake.notify_one();
    }

    fn advance(&self, copied: u64) {
        let (lock, wake) = &*self.shared;
        if let Some(window) = &mut lock.lock().unwrap_or_else(|e| e.into_inner()).window {
            window.copied = copied;
        }
        wake.notify_one();
    }

    fn finish(&self) {
        let (lock, wake) = &*self.shared;
        let mut state = lock.lock().unwrap_or_else(|e| e.into_inner());
        state.window = None;
        while state.in_flight {
            state = wake.wait(state).unwrap_or_else(|e| e.into_inner());
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.finish();
        let (lock, wake) = &*self.shared;
        lock.lock().unwrap_or_else(|e| e.into_inner()).stopped = true;
        wake.notify_one();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Includes idle helpers in the process-wide budget: connection reuse must
/// never accumulate an unbounded number of sleeping helper threads.
#[derive(Default)]
pub(crate) struct ReadAhead {
    worker: Option<Worker>,
    stream: Option<Stream>,
    observation: Option<Arc<crate::transfer_observations::Actor>>,
    helper_observation: Option<Arc<crate::transfer_observations::Actor>>,
}

struct Stream {
    range: Range<u64>,
    active: bool,
    attempted: bool,
}

impl ReadAhead {
    pub(crate) fn observed(
        registry: Arc<crate::transfer_observations::Registry>,
        operation: Arc<crate::transfer_observations::Actor>,
    ) -> Self {
        Self {
            observation: Some(operation),
            helper_observation: Some(registry.actor("prefetch")),
            ..Self::default()
        }
    }
    /// The caller already owns this interval. Demand may survive individual
    /// reads, but must be fenced before the stream stops or releases a suffix.
    pub(crate) fn begin_stream(&mut self, range: Range<u64>) {
        self.end_stream();
        self.stream = Some(Stream {
            range,
            active: false,
            attempted: false,
        });
    }

    pub(crate) fn shrink_stream(&mut self, end: u64) {
        if let Some(stream) = &mut self.stream {
            if end < stream.range.end {
                if stream.active {
                    let _wait = self
                        .observation
                        .as_ref()
                        .map(|a| a.span(crate::transfer_observations::Stage::PrefetchFence));
                    self.worker.as_ref().unwrap().finish();
                }
                stream.range.end = end;
                stream.active = false;
                stream.attempted = false;
            }
        }
    }

    pub(crate) fn end_stream(&mut self) {
        if self.stream.take().is_some_and(|stream| stream.active) {
            let _wait = self
                .observation
                .as_ref()
                .map(|a| a.span(crate::transfer_observations::Stage::PrefetchFence));
            self.worker.as_ref().unwrap().finish();
        }
    }

    pub(crate) fn range<'a>(
        &'a mut self,
        source: &'a File,
        range: Range<u64>,
    ) -> PreparedRange<'a> {
        PreparedRange {
            preparation: self,
            source,
            range,
            active: false,
            attempted: false,
            preserve: false,
        }
    }

    /// Read into the caller's existing payload buffer. A physical input or a
    /// voluntary wait during the read admits preparation of its remaining
    /// bytes. The latter also covers filesystems such as NFS whose reads may
    /// not charge ru_inblock. No socket/hash/writer time enters this sample.
    pub(crate) fn read_exact_at(
        &mut self,
        source: &File,
        data: &mut [u8],
        off: u64,
    ) -> std::io::Result<()> {
        let end = off
            .checked_add(data.len() as u64)
            .filter(|end| *end <= i64::MAX as u64)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "source range exceeds file offsets",
                )
            })?;
        let observation = self.observation.clone();
        let mut range = if let Some(stream) = &self.stream {
            let (bounds, active, attempted) =
                (stream.range.clone(), stream.active, stream.attempted);
            PreparedRange {
                preparation: self,
                source,
                range: bounds,
                active,
                attempted,
                preserve: false,
            }
        } else {
            self.range(source, off..end)
        };
        let mut copied = off;
        for chunk in data.chunks_mut(BLOCK as usize) {
            let before = (range.needs_observation()
                && copied + (chunk.len() as u64) < range.range.end)
                .then(Activity::sample);
            {
                let read = observation
                    .as_ref()
                    .map(|a| a.span(crate::transfer_observations::Stage::SourceRead));
                source.read_exact_at(chunk, copied)?;
                if let Some(read) = read {
                    read.bytes(chunk.len() as u64);
                }
            }
            copied += chunk.len() as u64;
            let prepare = before.is_some_and(|before| Activity::sample().read_wait_since(before));
            range.advance(copied, prepare);
        }
        range.preserve_stream();
        Ok(())
    }
}

pub(crate) struct PreparedRange<'a> {
    preparation: &'a mut ReadAhead,
    source: &'a File,
    range: Range<u64>,
    active: bool,
    attempted: bool,
    preserve: bool,
}

impl PreparedRange<'_> {
    fn preserve_stream(&mut self) {
        if let Some(stream) = &mut self.preparation.stream {
            stream.active = self.active;
            stream.attempted = self.attempted;
            self.preserve = true;
        }
    }

    pub(crate) fn needs_observation(&self) -> bool {
        !self.active && !self.attempted
    }
    pub(crate) fn advance(&mut self, copied: u64, should_prepare: bool) {
        if copied < self.range.start || copied >= self.range.end || self.range.end > i64::MAX as u64
        {
            return;
        }
        if self.active {
            self.preparation.worker.as_ref().unwrap().advance(copied);
            return;
        }
        #[cfg(debug_assertions)]
        let should_prepare =
            should_prepare || std::env::var_os("SYQ_TEST_LOCAL_READ_AHEAD").is_some();
        if self.attempted || !should_prepare {
            return;
        }
        if self.preparation.worker.is_none() {
            let Some(permit) = budget().acquire() else {
                return;
            };
            self.attempted = true;
            self.preparation.worker =
                Worker::start(permit, self.preparation.helper_observation.clone()).ok();
        }
        self.attempted = true;
        let Some(worker) = &self.preparation.worker else {
            return;
        };
        let Ok(source) = self.source.try_clone() else {
            return;
        };
        worker.begin(source, copied, self.range.end);
        self.active = true;
        if crate::output::debug() {
            eprintln!(
                "syq: source read-ahead started: {copied}..{}",
                self.range.end
            );
        }
    }
}

impl Drop for PreparedRange<'_> {
    fn drop(&mut self) {
        if !self.preserve {
            if self.active {
                let _wait = self
                    .preparation
                    .observation
                    .as_ref()
                    .map(|a| a.span(crate::transfer_observations::Stage::PrefetchFence));
                self.preparation.worker.as_ref().unwrap().finish();
            }
            if let Some(stream) = &mut self.preparation.stream {
                stream.active = false;
                stream.attempted = false;
            }
        }
    }
}

#[derive(Clone, Copy, Default)]
pub(crate) struct Activity {
    input: Option<libc::c_long>,
    waits: Option<libc::c_long>,
}
impl Activity {
    pub(crate) fn sample() -> Self {
        let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
        // SAFETY: getrusage initializes usage on success.
        if unsafe { libc::getrusage(libc::RUSAGE_THREAD, usage.as_mut_ptr()) } != 0 {
            return Self::default();
        }
        let usage = unsafe { usage.assume_init() };
        Self {
            input: Some(usage.ru_inblock),
            waits: Some(usage.ru_nvcsw),
        }
    }
    pub(crate) fn input_since(self, before: Self) -> bool {
        before.input.zip(self.input).is_some_and(|(a, b)| b > a)
    }
    pub(crate) fn read_wait_since(self, before: Self) -> bool {
        self.input_since(before) || before.waits.zip(self.waits).is_some_and(|(a, b)| b > a)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn completed_or_unowned_ranges_do_not_start_helpers() {
        let source = tempfile::tempfile().unwrap();
        let mut preparation = ReadAhead::default();
        {
            let mut range = preparation.range(&source, 4096..8192);
            for off in [0, 4095, 8192, 16384] {
                range.advance(off, true);
            }
        }
        assert!(preparation.worker.is_none());
    }
    #[test]
    fn finished_ranges_release_the_source_and_reuse_a_bounded_helper() {
        let budget = Arc::new(Budget {
            active: AtomicUsize::new(0),
            limit: 1,
        });
        let worker = Worker::start(budget.acquire().unwrap(), None).unwrap();
        for start in [4096, 65536] {
            worker.begin(tempfile::tempfile().unwrap(), start, start + 4096);
            worker.finish();
            let state = worker.shared.0.lock().unwrap();
            assert!(state.window.is_none() && !state.in_flight);
            assert!(budget.acquire().is_none());
        }
        drop(worker);
        assert!(budget.acquire().is_some());
    }
    #[test]
    fn advice_stays_inside_demand_and_finish_fences_inflight_work() {
        use std::sync::mpsc;
        use std::time::Duration;
        let budget = Arc::new(Budget {
            active: AtomicUsize::new(0),
            limit: 1,
        });
        let (entered, requests) = mpsc::channel();
        let (release, proceed) = mpsc::channel();
        let worker = Arc::new(
            Worker::start_with(budget.acquire().unwrap(), move |_, off, len| {
                entered.send((off, len)).unwrap();
                proceed.recv_timeout(Duration::from_secs(5)).unwrap();
                0
            })
            .unwrap(),
        );
        let source = tempfile::tempfile().unwrap();
        worker.begin(source, 4096, 8192);
        assert_eq!(
            requests.recv_timeout(Duration::from_secs(5)).unwrap(),
            (4096, 4096)
        );
        let (finished, done) = mpsc::channel();
        let finisher = worker.clone();
        let join = std::thread::spawn(move || {
            finisher.finish();
            finished.send(()).unwrap();
        });
        assert!(done.recv_timeout(Duration::from_millis(30)).is_err());
        release.send(()).unwrap();
        done.recv_timeout(Duration::from_secs(5)).unwrap();
        join.join().unwrap();
        assert!(requests.try_recv().is_err());
        // A disjoint new request must not advise the gap or the old source.
        worker.begin(tempfile::tempfile().unwrap(), 65536, 65537);
        assert_eq!(
            requests.recv_timeout(Duration::from_secs(5)).unwrap(),
            (65536, 1)
        );
        release.send(()).unwrap();
        worker.finish();
        assert!(requests.try_recv().is_err());
    }

    #[test]
    fn stream_preparation_survives_a_response_but_stops_on_shrink_and_read_error() {
        let source = tempfile::tempfile().unwrap();
        source.set_len(8 * BLOCK).unwrap();
        let mut preparation = ReadAhead::default();
        preparation.begin_stream(0..8 * BLOCK);
        {
            let mut range = preparation.range(&source, 0..8 * BLOCK);
            range.advance(BLOCK, true);
            range.preserve_stream();
        }
        assert!(preparation.stream.as_ref().unwrap().active);
        preparation.shrink_stream(2 * BLOCK);
        assert_eq!(preparation.stream.as_ref().unwrap().range.end, 2 * BLOCK);
        assert!(preparation
            .worker
            .as_ref()
            .unwrap()
            .shared
            .0
            .lock()
            .unwrap()
            .window
            .is_none());
        {
            let mut range = preparation.range(&source, BLOCK..2 * BLOCK);
            range.advance(BLOCK, true);
            range.preserve_stream();
        }
        source.set_len(0).unwrap();
        let error = preparation
            .read_exact_at(&source, &mut [0; 16], BLOCK)
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
        assert!(!preparation.stream.as_ref().unwrap().active);
        assert!(preparation
            .worker
            .as_ref()
            .unwrap()
            .shared
            .0
            .lock()
            .unwrap()
            .window
            .is_none());
        preparation.end_stream();
        assert!(preparation.stream.is_none());
    }

    #[test]
    fn source_wait_admission_does_not_require_block_input_accounting() {
        let before = Activity {
            input: Some(0),
            waits: Some(10),
        };
        assert!(!before.read_wait_since(before));
        let after = Activity {
            waits: Some(11),
            ..before
        };
        assert!(after.read_wait_since(before));
        assert!(!after.input_since(before));
        assert!(!Activity::default().read_wait_since(before));
    }

    #[test]
    fn failed_reads_end_preparation_and_preserve_read_errors() {
        let source = tempfile::tempfile().unwrap();
        let mut preparation = ReadAhead::default();
        let error = preparation
            .read_exact_at(&source, &mut [0; 16], 4096)
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
        assert!(preparation.worker.is_none());
    }
}

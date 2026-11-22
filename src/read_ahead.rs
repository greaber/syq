//! Source-page preparation for already-owned read ranges. No transport or
//! payload queue lives here. Dropping a range fences all its advisory work
//! and frees the helper for other transfers.
use std::fs::File;
use std::ops::Range;
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread::JoinHandle;

pub(crate) const BLOCK: u64 = 1 << 20;
const LOOKAHEAD: u64 = 4 * BLOCK;
// Recheck long cached reads occasionally in case the next region needs I/O.
const PROBE_INTERVAL: u64 = 64 * BLOCK;

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
    #[cfg(debug_assertions)]
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
                        // Linux may clip a WILLNEED request to the device's
                        // readahead size. Advise each read block so one clipped
                        // request cannot skip most of the lookahead window.
                        let len = BLOCK.min(end.saturating_sub(window.offset));
                        if len == 0 || (len < BLOCK && end < window.end) {
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
                    #[cfg(debug_assertions)]
                    {
                        state.in_flight = true;
                    }
                    drop(state);
                    let error = advise(source.as_raw_fd(), offset, len);
                    drop(source);
                    state = lock.lock().unwrap_or_else(|e| e.into_inner());
                    if error != 0 {
                        state.window = None;
                    }
                    #[cfg(debug_assertions)]
                    {
                        state.in_flight = false;
                        wake.notify_all();
                    }
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
        #[cfg(debug_assertions)]
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

    /// Wait until the helper has advised the window that `begin` opened at
    /// `copied`, or has given it up. Tests that observe the helper use this:
    /// otherwise a starved helper may first run once the reader has passed
    /// the whole range.
    #[cfg(debug_assertions)]
    fn wait_for_first_advice(&self, copied: u64) {
        let (lock, wake) = &*self.shared;
        let mut state = lock.lock().unwrap_or_else(|e| e.into_inner());
        while state.in_flight
            || state
                .window
                .as_ref()
                .is_some_and(|window| window.offset == copied)
        {
            state = wake.wait(state).unwrap_or_else(|e| e.into_inner());
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        let (lock, wake) = &*self.shared;
        lock.lock().unwrap_or_else(|e| e.into_inner()).stopped = true;
        wake.notify_one();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// A helper owns a permit only for the lifetime of its range. An idle
/// connection keeps the observation state but has no helper thread.
#[derive(Default)]
pub(crate) struct ReadAhead {
    worker: Option<Worker>,
    stream: Option<Stream>,
    bytes_until_probe: u64,
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
        self.bytes_until_probe = 0;
        self.stream = Some(Stream {
            range,
            active: false,
            attempted: false,
        });
    }

    pub(crate) fn shrink_stream(&mut self, end: u64) {
        if let Some(stream) = &mut self.stream {
            if end < stream.range.end {
                stream.range.end = end;
                stream.active = false;
                stream.attempted = false;
                self.stop_worker();
                self.bytes_until_probe = 0;
            }
        }
    }

    pub(crate) fn end_stream(&mut self) {
        self.stream = None;
        self.stop_worker();
    }

    fn stop_worker(&mut self) {
        if let Some(worker) = self.worker.take() {
            let _wait = self
                .observation
                .as_ref()
                .map(|a| a.span(crate::transfer_observations::Stage::PrefetchFence));
            drop(worker);
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
        let observation = self.observation.clone();
        self.read_exact_at_with(source, data, off, Activity::sample, |chunk, copied| {
            let read = observation
                .as_ref()
                .map(|a| a.span(crate::transfer_observations::Stage::SourceRead));
            source.read_exact_at(chunk, copied)?;
            if let Some(read) = read {
                read.bytes(chunk.len() as u64);
            }
            Ok(())
        })
    }

    fn read_exact_at_with(
        &mut self,
        source: &File,
        mut data: &mut [u8],
        off: u64,
        mut sample: impl FnMut() -> Activity,
        mut read: impl FnMut(&mut [u8], u64) -> std::io::Result<()>,
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
        if off == 0 {
            self.bytes_until_probe = 0;
        }
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
        let mut sampled = false;
        while !data.is_empty() {
            let block = data.len().min(BLOCK as usize);
            let probe = !sampled
                && range.needs_observation()
                && range.preparation.bytes_until_probe == 0
                && copied + (block as u64) < range.range.end;
            // A short first read can start prefetch before the rest of the
            // request. Once cached, issue full reads between samples. Active
            // readers advance by blocks so the helper can replenish ahead.
            let len = if probe || range.active {
                block
            } else {
                data.len()
            };
            let (chunk, remaining) = data.split_at_mut(len);
            let before = probe.then(&mut sample);
            read(chunk, copied)?;
            copied += len as u64;
            let prepare = before.is_some_and(|before| sample().read_wait_since(before));
            range.advance(copied, prepare);
            if probe {
                sampled = true;
                if !prepare && !range.active {
                    range.preparation.bytes_until_probe = PROBE_INTERVAL;
                }
            }
            range.preparation.bytes_until_probe = range
                .preparation
                .bytes_until_probe
                .saturating_sub(len as u64);
            data = remaining;
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
        let Some(permit) = budget().acquire() else {
            return;
        };
        self.attempted = true;
        let Ok(source) = self.source.try_clone() else {
            return;
        };
        let Ok(worker) = Worker::start(permit, self.preparation.helper_observation.clone()) else {
            return;
        };
        worker.begin(source, copied, self.range.end);
        #[cfg(debug_assertions)]
        if std::env::var_os("SYQ_TEST_READ_AHEAD_FIRST_ADVICE").is_some() {
            worker.wait_for_first_advice(copied);
        }
        self.preparation.worker = Some(worker);
        self.active = true;
        if crate::output::debug() {
            crate::output::diagnostic!(
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
                self.preparation.stop_worker();
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
    fn cached_reads_use_full_requests_between_probes() {
        use std::cell::Cell;

        let source = tempfile::tempfile().unwrap();
        let mut data = vec![0; LOOKAHEAD as usize];
        for streamed in [false, true] {
            let mut preparation = ReadAhead::default();
            if streamed {
                preparation.begin_stream(0..PROBE_INTERVAL + LOOKAHEAD);
            }
            for off in (0..=PROBE_INTERVAL).step_by(data.len()) {
                let samples = Cell::new(0);
                let mut reads = Vec::new();
                preparation
                    .read_exact_at_with(
                        &source,
                        &mut data,
                        off,
                        || {
                            samples.set(samples.get() + 1);
                            Activity::default()
                        },
                        |chunk, copied| {
                            reads.push((copied, chunk.len() as u64));
                            Ok(())
                        },
                    )
                    .unwrap();
                if off == 0 || off == PROBE_INTERVAL {
                    assert_eq!(samples.get(), 2);
                    assert_eq!(reads, [(off, BLOCK), (off + BLOCK, LOOKAHEAD - BLOCK)]);
                } else {
                    assert_eq!(samples.get(), 0);
                    assert_eq!(reads, [(off, LOOKAHEAD)]);
                }
                assert!(preparation.worker.is_none());
            }
        }
    }

    #[test]
    fn advice_uses_blocks_and_stream_end_fences_work_and_releases_the_permit() {
        use std::sync::mpsc;
        use std::time::Duration;
        let budget = Arc::new(Budget {
            active: AtomicUsize::new(0),
            limit: 1,
        });
        let (entered, requests) = mpsc::channel();
        let (release, proceed) = mpsc::channel();
        let worker = Worker::start_with(budget.acquire().unwrap(), move |_, off, len| {
            entered.send((off, len)).unwrap();
            proceed.recv_timeout(Duration::from_secs(5)).unwrap();
            0
        })
        .unwrap();
        let start = 4096;
        let tail = BLOCK / 2;
        let end = start + LOOKAHEAD + tail;
        worker.begin(tempfile::tempfile().unwrap(), start, end);
        for off in (start..start + LOOKAHEAD).step_by(BLOCK as usize) {
            assert_eq!(
                requests.recv_timeout(Duration::from_secs(5)).unwrap(),
                (off, BLOCK)
            );
            if off + BLOCK == start + LOOKAHEAD {
                worker.advance(start + tail);
            }
            release.send(()).unwrap();
        }
        assert_eq!(
            requests.recv_timeout(Duration::from_secs(5)).unwrap(),
            (start + LOOKAHEAD, tail)
        );

        let mut preparation = ReadAhead::default();
        preparation.begin_stream(start..end);
        preparation.worker = Some(worker);
        preparation.stream.as_mut().unwrap().active = true;
        let (finished, done) = mpsc::channel();
        let join = std::thread::spawn(move || {
            preparation.end_stream();
            assert!(preparation.worker.is_none());
            assert!(preparation.stream.is_none());
            finished.send(()).unwrap();
        });
        assert!(done.recv_timeout(Duration::from_millis(30)).is_err());
        assert!(budget.acquire().is_none());
        release.send(()).unwrap();
        done.recv_timeout(Duration::from_secs(5)).unwrap();
        join.join().unwrap();
        assert!(requests.try_recv().is_err());
        assert!(budget.acquire().is_some());
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
        assert!(preparation.worker.is_none());
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
        assert!(preparation.worker.is_none());
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

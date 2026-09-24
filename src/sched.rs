//! Work queue with largest-first file scheduling and range work-stealing.

use crate::proto::{ContainerGuard, Entry, PathBytes, RegisteredPath};
use std::borrow::{Borrow, BorrowMut};
use std::cmp::Reverse;
use std::collections::{BTreeSet, BinaryHeap, HashMap, HashSet, VecDeque};
use std::ops::{Deref, DerefMut, Index, IndexMut};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::Duration;

/// The values used by the tuner's remaining-work gate. No paths or file identities.
#[derive(Clone, Copy, Debug, serde::Serialize)]
pub(crate) struct TuningWork {
    pub scan_done: bool,
    pub remaining_bytes: u64,
    pub queued_files: usize,
    pub work_units: usize,
    pub minimum_split: u64,
    pub workers: usize,
    pub activity: u64,
    pub minimum_activity: u64,
    pub parallel: bool,
    pub sufficient: bool,
}

#[derive(Clone, Debug)]
pub struct FileJob<D = Option<Entry>, S = FileJobData> {
    pub data: S,
    pub dst_entry: D,
}

impl<D, S: Borrow<FileJobData>> Deref for FileJob<D, S> {
    type Target = FileJobData;
    fn deref(&self) -> &Self::Target {
        self.data.borrow()
    }
}

impl<D, S: BorrowMut<FileJobData>> DerefMut for FileJob<D, S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.data.borrow_mut()
    }
}

#[derive(Clone, Debug)]
pub struct FileJobData {
    pub src: PathBytes,
    /// Descriptor-session authority corresponding to `src`. Source workers,
    /// and Linux destination workers using CopyLocal, claim its root during
    /// authenticated initialization and use it for content opens.
    pub source: RegisteredPath,
    pub dst: PathBytes,
    pub rel: String,
    pub entry: Entry,
    /// Placement-root condition enforced by the receiver at publication.
    pub target_condition: crate::proto::TargetCondition,
    /// Opened directory identity that anchors descendant target mutations.
    pub container_guard: Option<ContainerGuard>,
    pub attempt: u32,
    /// Rsync's fresh-file permissions derived from the destination parent.
    /// None keeps native creation and explicit preservation behavior unchanged.
    pub creation_mode: Option<u16>,
    /// Bytes of this file in place on the destination (transferred or matched).
    pub done: Arc<AtomicU64>,
    /// Written directly to the final path (no partial + rename).
    pub inplace: bool,
    /// Destination-root-relative path, used in machine-readable results.
    pub rel_bytes: PathBytes,
    /// --mapping: the entry's source path relative to the source base, kept
    /// so `--results` records round-trip as retry mapping entries.
    pub src_rel: Option<PathBytes>,
}

// Snapshots retain a chunk or a private retry version, preserving worker
// views while metadata changes.
#[derive(Clone, Debug)]
pub enum SnapshotData {
    Shared(Arc<FileJobData>),
    Chunk {
        slots: Arc<Vec<OnceLock<FileJobData>>>,
        slot: usize,
    },
}

impl Borrow<FileJobData> for SnapshotData {
    fn borrow(&self) -> &FileJobData {
        match self {
            Self::Shared(data) => data,
            Self::Chunk { slots, slot } => slots[*slot].get().unwrap(),
        }
    }
}

pub type WorkerJob = FileJob<Option<Arc<Entry>>, SnapshotData>;
const JOBS_PER_CHUNK: usize = 1024;

/// Published slots never change. OnceLock permits appending jobs to a partial
/// chunk while workers hold earlier slots, without unsafe aliasing or chunk COW.
/// Retry versions are sparse and owned independently of the original chunk.
#[derive(Default)]
pub struct Jobs {
    chunks: Vec<Arc<Vec<OnceLock<FileJobData>>>>,
    destinations: Vec<Option<Arc<Entry>>>,
    retries: HashMap<usize, Arc<FileJobData>>,
}

/// A borrowed current version also identifies the owner needed by snapshots.
enum CurrentJob<'a> {
    Retry(&'a Arc<FileJobData>),
    Chunk(&'a Arc<Vec<OnceLock<FileJobData>>>, usize),
}

impl<'a> CurrentJob<'a> {
    fn data(self) -> &'a FileJobData {
        match self {
            Self::Retry(data) => data,
            Self::Chunk(slots, slot) => slots[slot].get().unwrap(),
        }
    }

    fn snapshot(self) -> SnapshotData {
        match self {
            Self::Retry(data) => SnapshotData::Shared(data.clone()),
            Self::Chunk(slots, slot) => SnapshotData::Chunk {
                slots: slots.clone(),
                slot,
            },
        }
    }
}

impl Jobs {
    fn locate(idx: usize) -> (usize, usize) {
        (idx / JOBS_PER_CHUNK, idx % JOBS_PER_CHUNK)
    }

    fn current(&self, idx: usize) -> CurrentJob<'_> {
        match self.retries.get(&idx) {
            Some(data) => CurrentJob::Retry(data),
            None => {
                let (chunk, slot) = Self::locate(idx);
                CurrentJob::Chunk(&self.chunks[chunk], slot)
            }
        }
    }

    fn push(&mut self, job: FileJob) {
        let (chunk, slot) = Self::locate(self.destinations.len());
        if slot == 0 {
            self.chunks.push(Arc::new(
                (0..JOBS_PER_CHUNK).map(|_| OnceLock::new()).collect(),
            ));
        }
        self.chunks[chunk][slot]
            .set(job.data)
            .expect("job slot published twice");
        self.destinations.push(job.dst_entry.map(Arc::new));
    }

    fn get_mut(&mut self, idx: usize) -> &mut FileJobData {
        // Only a changed job acquires a private allocation. Existing worker
        // snapshots retain their previous version, including across retries.
        let (chunk, slot) = Self::locate(idx);
        let chunks = &self.chunks;
        Arc::make_mut(
            self.retries
                .entry(idx)
                .or_insert_with(|| Arc::new(chunks[chunk][slot].get().unwrap().clone())),
        )
    }

    pub fn len(&self) -> usize {
        self.destinations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn iter(&self) -> impl Iterator<Item = &FileJobData> {
        (0..self.len()).map(|idx| &self[idx])
    }

    pub fn snapshot(&self, idx: usize) -> WorkerJob {
        FileJob {
            data: self.current(idx).snapshot(),
            dst_entry: self.destinations[idx].clone(),
        }
    }

    pub fn destination(&self, idx: usize) -> Option<&Entry> {
        self.destinations[idx].as_deref()
    }

    pub fn set_destination(&mut self, idx: usize, entry: Entry) {
        self.destinations[idx] = Some(Arc::new(entry));
    }

    fn release(&mut self) {
        *self = Self::default();
    }
}

impl Index<usize> for Jobs {
    type Output = FileJobData;
    fn index(&self, idx: usize) -> &Self::Output {
        self.current(idx).data()
    }
}

impl IndexMut<usize> for Jobs {
    fn index_mut(&mut self, idx: usize) -> &mut Self::Output {
        self.get_mut(idx)
    }
}

pub struct RangeState {
    pub idx: usize,
    /// Next offset to claim for reading. Only ever moves forward.
    pub pos: u64,
    /// Exclusive end; a stealer may move it down (never below `pos`).
    pub end: u64,
}

pub type RangeHandle = Arc<Mutex<RangeState>>;

pub struct FastBatchState {
    files: Vec<(u64, usize)>,
    groups: VecDeque<std::ops::Range<usize>>,
    owned: Vec<bool>,
}

impl FastBatchState {
    /// Claim immediately before issuing the source request. Once claimed, a
    /// group cannot be stolen, even while its read or write is outstanding.
    pub fn claim(&mut self) -> Option<std::ops::Range<usize>> {
        self.groups.pop_front()
    }
}

pub type FastBatchHandle = Arc<Mutex<FastBatchState>>;

pub enum Item {
    File(usize),
    Range(RangeHandle),
    Finish { idx: usize, matched: bool },
    Exit,
}

/// Cancellation status and an optional immediately issuable same-file range.
pub enum RangeWork {
    Cancelled,
    Ready(Option<RangeHandle>),
}

/// Keep one global maximum per file. The file index supports both largest-first
/// scheduling and short same-file claims without storing every range twice.
#[derive(Default)]
struct RangeQueue {
    largest: BTreeSet<(u64, usize, u64)>,
    by_file: HashMap<usize, BTreeSet<(u64, u64)>>,
    len: usize,
    bytes: u64,
}

impl RangeQueue {
    fn push(&mut self, (idx, off, end): (usize, u64, u64)) {
        self.extend(idx, &[(off, end)]);
    }

    /// Publish a file's newly compared ranges with one global maximum update.
    /// Preserve the existing offset order for both large and short claims.
    fn extend(&mut self, idx: usize, ranges: &[(u64, u64)]) {
        if ranges.is_empty() {
            return;
        }
        let file = self.by_file.entry(idx).or_default();
        let previous = file.last().copied();
        for &(off, end) in ranges {
            assert!(file.insert((end - off, off)));
            self.bytes += end - off;
        }
        let maximum = file.last().copied();
        if previous != maximum {
            if let Some((len, off)) = previous {
                assert!(self.largest.remove(&(len, idx, off)));
            }
            let (len, off) = maximum.expect("inserted ranges");
            assert!(self.largest.insert((len, idx, off)));
        }
        self.len += ranges.len();
    }

    fn remove(&mut self, len: u64, idx: usize, off: u64) -> (usize, u64, u64) {
        let file = self.by_file.get_mut(&idx).expect("queued file");
        let was_maximum = file.last() == Some(&(len, off));
        assert!(file.remove(&(len, off)));
        if was_maximum {
            assert!(self.largest.remove(&(len, idx, off)));
            if let Some(&(next_len, next_off)) = file.last() {
                assert!(self.largest.insert((next_len, idx, next_off)));
            }
        }
        if file.is_empty() {
            self.by_file.remove(&idx);
        }
        self.len -= 1;
        self.bytes -= len;
        (idx, off, off + len)
    }

    fn pop(&mut self) -> Option<(usize, u64, u64)> {
        let &(len, idx, off) = self.largest.last()?;
        Some(self.remove(len, idx, off))
    }

    fn take_short(&mut self, idx: usize, max_size: u64) -> Option<(usize, u64, u64)> {
        let &(len, off) = self.by_file.get(&idx)?.first()?;
        (len <= max_size).then(|| self.remove(len, idx, off))
    }

    fn len(&self) -> usize {
        self.len
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[cfg(test)]
    fn iter(&self) -> impl Iterator<Item = (usize, u64, u64)> + '_ {
        self.by_file
            .iter()
            .flat_map(|(&idx, ranges)| ranges.iter().map(move |&(len, off)| (idx, off, off + len)))
    }

    #[cfg(test)]
    fn contains(&self, &(idx, off, end): &(usize, u64, u64)) -> bool {
        self.by_file
            .get(&idx)
            .is_some_and(|ranges| ranges.contains(&(end - off, off)))
    }
}

/// Tie-break equal-sized files by spreading out their planning indices.
/// Scans usually group neighboring files by directory; taking those neighbors
/// together makes workers contend on the same directory's create/rename locks.
/// Bit reversal interleaves distant parts of that order without extra queue
/// storage or changing the jobs' stable indices. File size remains primary.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct FileOrder(usize);

impl FileOrder {
    fn new(idx: usize) -> Self {
        Self(idx.reverse_bits())
    }

    fn index(self) -> usize {
        self.0.reverse_bits()
    }
}

/// Keep queue size accounting at the mutation boundary for tuner samples.
#[derive(Default)]
struct FileQueue {
    heap: BinaryHeap<(u64, Reverse<FileOrder>)>,
    bytes: u64,
}

impl FileQueue {
    fn push(&mut self, item: (u64, Reverse<FileOrder>)) {
        self.heap.push(item);
        self.bytes += item.0;
    }

    fn pop(&mut self) -> Option<(u64, Reverse<FileOrder>)> {
        let item = self.heap.pop()?;
        self.bytes -= item.0;
        Some(item)
    }

    fn peek(&self) -> Option<&(u64, Reverse<FileOrder>)> {
        self.heap.peek()
    }

    fn len(&self) -> usize {
        self.heap.len()
    }

    fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }
}

struct Inner {
    files: FileQueue,
    ranges: RangeQueue,
    finishes: Vec<(usize, bool)>,
    inflight: Vec<RangeHandle>,
    outstanding: HashMap<usize, u32>,
    failed: HashSet<usize>,
    probing: usize,
    /// Workers asleep in `next`, including notified peers until they reacquire the lock.
    waiting_workers: usize,
    /// Files owned by the pipelined small-file path. Unlike ordinary probes,
    /// these will not expose ranges another worker can steal.
    fast_probing: usize,
    /// Workers currently processing one pipelined small-file batch.
    fast_batches: usize,
    fast_groups: Vec<FastBatchHandle>,
    /// Planning has observed at least one regular file, before destination
    /// namespace checks and directory creation make it runnable.
    file_work_anticipated: bool,
    scan_done: bool,
    /// Source-wide preflights passed; more validated jobs may still arrive.
    work_released: bool,
    abort: bool,
}

impl Inner {
    fn claim_range(&mut self, idx: usize, off: u64, end: u64) -> RangeHandle {
        let handle = Arc::new(Mutex::new(RangeState { idx, pos: off, end }));
        self.inflight.push(handle.clone());
        handle
    }

    fn finished(&self) -> bool {
        self.scan_done
            && self.probing == 0
            && self.inflight.is_empty()
            && self.files.is_empty()
            && self.ranges.is_empty()
            && self.finishes.is_empty()
    }
}

pub struct Sched {
    inner: Mutex<Inner>,
    cv: Condvar,
    tune_cv: Condvar,
    direct_fallback_workers: AtomicUsize,
    initial_range_workers: AtomicUsize,
    tune_request: AtomicUsize,
    pub jobs: Mutex<Jobs>,
    pub block: u64,
    pub min_split: u64,
}

impl Sched {
    pub fn new(block: u64, min_split: u64) -> Self {
        Sched {
            inner: Mutex::new(Inner {
                files: FileQueue::default(),
                ranges: RangeQueue::default(),
                finishes: Vec::new(),
                inflight: Vec::new(),
                outstanding: HashMap::new(),
                failed: HashSet::new(),
                probing: 0,
                waiting_workers: 0,
                fast_probing: 0,
                fast_batches: 0,
                fast_groups: Vec::new(),
                file_work_anticipated: false,
                scan_done: false,
                work_released: false,
                abort: false,
            }),
            cv: Condvar::new(),
            tune_cv: Condvar::new(),
            direct_fallback_workers: AtomicUsize::new(0),
            initial_range_workers: AtomicUsize::new(0),
            tune_request: AtomicUsize::new(0),
            jobs: Mutex::new(Jobs::default()),
            block,
            min_split: min_split.max(2 * block),
        }
    }

    pub fn push_file(&self, job: FileJob) -> usize {
        let size = job.entry.size;
        let idx = {
            let mut jobs = self.jobs.lock().unwrap();
            jobs.push(job);
            jobs.len() - 1
        };
        let mut inner = self.inner.lock().unwrap();
        inner.files.push((size, Reverse(FileOrder::new(idx))));
        // New batches can run once the source-wide preflights have passed.
        let runnable = inner.scan_done || inner.work_released;
        drop(inner);
        if runnable {
            self.cv.notify_one();
        }
        idx
    }

    /// File jobs and queues are index-addressed while workers are active. Once
    /// every worker and the tuner have joined, release their retained capacity
    /// before deletion, deferred metadata, and receipt settlement continue.
    pub fn clear_finished_work(&self) {
        self.jobs.lock().unwrap().release();
        let mut inner = self.inner.lock().unwrap();
        inner.files = FileQueue::default();
        inner.ranges = RangeQueue::default();
        inner.finishes = Vec::new();
        inner.inflight = Vec::new();
        inner.fast_groups = Vec::new();
        inner.outstanding = HashMap::new();
        inner.failed = HashSet::new();
    }

    /// Wake the tuner when a speculative low-concurrency start discovers
    /// more parallel work (a local-copy fallback or a resumable basis).
    pub fn request_worker_count(&self, workers: usize) {
        // Share the scheduler mutex with the tuning wait predicate so a
        // request cannot land between the driver's check and its sleep.
        let _guard = self.inner.lock().unwrap();
        self.tune_request.fetch_max(workers, Relaxed);
        self.tune_cv.notify_one();
    }

    pub fn arm_direct_fallback(&self, workers: usize) {
        self.direct_fallback_workers.store(workers, Relaxed);
    }

    pub fn reserve_initial_ranges(&self, workers: usize) {
        // Reserve runnable work, not workers: an early connection can take
        // another queued range if its peers are still connecting.
        self.initial_range_workers.store(workers, Relaxed);
    }

    pub fn request_direct_fallback(&self) {
        let workers = self.direct_fallback_workers.load(Relaxed);
        if workers > 0 {
            self.request_worker_count(workers);
        }
    }

    pub fn take_worker_count_request(&self) -> usize {
        self.tune_request.swap(0, Relaxed)
    }

    pub fn wait_for_tuning(&self, timeout: Duration) {
        let guard = self.inner.lock().unwrap();
        if self.tune_request.load(Relaxed) == 0 && !guard.abort && !guard.finished() {
            drop(
                self.tune_cv
                    .wait_timeout_while(guard, timeout, |inner| {
                        self.tune_request.load(Relaxed) == 0 && !inner.abort && !inner.finished()
                    })
                    .unwrap(),
            );
        }
    }

    /// Let speculative TCP workers warm while the planner performs remote
    /// namespace and directory work for a batch that contains regular files.
    pub fn anticipate_file_work(&self) {
        let mut inner = self.inner.lock().unwrap();
        let first = !inner.file_work_anticipated;
        inner.file_work_anticipated = true;
        drop(inner);
        if first {
            self.cv.notify_all();
        }
    }

    /// Wait to learn whether planning found any regular files. False means the
    /// scan ended or aborted without one, so an eager worker need not connect.
    pub fn wait_for_anticipated_file_work(&self) -> bool {
        let mut inner = self.inner.lock().unwrap();
        loop {
            if inner.file_work_anticipated {
                return true;
            }
            if inner.scan_done || inner.abort {
                return false;
            }
            inner = self.cv.wait(inner).unwrap();
        }
    }

    pub fn requeue(&self, idx: usize) {
        let size = self.jobs.lock().unwrap()[idx].entry.size;
        self.inner
            .lock()
            .unwrap()
            .files
            .push((size, Reverse(FileOrder::new(idx))));
        self.cv.notify_one();
    }

    /// Release validated jobs while the planner finishes preparing later
    /// batches. An empty queue is still a wait, not EOF, until scan_done.
    pub fn release_preflighted_work(&self) {
        // Path-specific fixtures need the complete file population before any
        // worker chooses a copy path. scan_done releases all workers after
        // buffered replay, preserving their configured concurrency.
        #[cfg(debug_assertions)]
        if std::env::var_os("SYQ_TEST_COPY_AFTER_PLANNING").is_some() {
            return;
        }
        self.inner.lock().unwrap().work_released = true;
        self.cv.notify_all();
    }

    pub fn scan_done(&self) {
        self.inner.lock().unwrap().scan_done = true;
        self.cv.notify_all();
        self.tune_cv.notify_one();
    }

    pub fn abort(&self) {
        self.inner.lock().unwrap().abort = true;
        self.cv.notify_all();
        self.tune_cv.notify_one();
    }

    pub fn is_aborted(&self) -> bool {
        self.inner.lock().unwrap().abort
    }

    /// Record failure before retiring work or reporting it. The return value
    /// elects one caller to report the error when several workers fail together.
    pub fn fail_file(&self, idx: usize) -> bool {
        self.inner.lock().unwrap().failed.insert(idx)
    }

    pub fn is_failed(&self, idx: usize) -> bool {
        self.inner.lock().unwrap().failed.contains(&idx)
    }

    /// All work handed out and finished (what makes `next` return Exit).
    pub fn finished(&self) -> bool {
        self.inner.lock().unwrap().finished()
    }

    /// Whether queued work, unread file groups, or an ordinary file probe can
    /// use another worker. Already-issued small-file requests cannot be stolen.
    pub fn needs_worker_capacity(&self) -> bool {
        let g = self.inner.lock().unwrap();
        !g.files.is_empty()
            || !g.ranges.is_empty()
            || !g.finishes.is_empty()
            || g.probing > g.fast_probing
            || g.fast_groups
                .iter()
                .any(|h| !h.lock().unwrap().groups.is_empty())
            || g.inflight.iter().any(|handle| {
                let range = handle.lock().unwrap();
                range.pos < range.end
            })
    }

    /// Mark the first file of a fast batch and choose a balanced total batch
    /// size. Existing owners are subtracted from `active`, leaving each worker
    /// that has not yet claimed a batch a comparable share of the queue. The
    /// WAN ceiling remains useful without letting early local workers drain it.
    pub fn begin_fast_batch(&self, active: usize, max_n: usize) -> usize {
        let mut g = self.inner.lock().unwrap();
        debug_assert!(g.probing > g.fast_probing);
        let available_workers = active.saturating_sub(g.fast_batches).max(1);
        let available_files = g.files.len() + 1;
        let target = available_files.div_ceil(available_workers).clamp(1, max_n);
        g.fast_probing += 1;
        g.fast_batches += 1;
        target
    }

    /// Further files claimed by a worker may include slow-path entries; mark
    /// only those that survived its fast-path eligibility check.
    pub fn mark_fast(&self, n: usize) {
        let mut g = self.inner.lock().unwrap();
        g.fast_probing += n;
        debug_assert!(g.fast_probing <= g.probing);
    }

    /// Share only unread groups. The first group stays with the original
    /// owner, which must retire at least one file and one fast-batch slot.
    pub fn share_fast_groups(
        &self,
        files: Vec<(u64, usize)>,
        mut groups: VecDeque<std::ops::Range<usize>>,
    ) -> (std::ops::Range<usize>, FastBatchHandle) {
        let first = groups.pop_front().expect("nonempty fast batch");
        let shareable = !groups.is_empty();
        let handle = Arc::new(Mutex::new(FastBatchState {
            owned: vec![true; files.len()],
            files,
            groups,
        }));
        if shareable {
            self.inner.lock().unwrap().fast_groups.push(handle.clone());
            self.cv.notify_all();
        }
        (first, handle)
    }

    /// Stop stealing before the caller checks sources, reports results, or
    /// retries after an error. Only still-owned files belong to that caller.
    pub fn finish_fast_groups(&self, handle: &FastBatchHandle) -> Vec<bool> {
        let mut g = self.inner.lock().unwrap();
        g.fast_groups.retain(|h| !Arc::ptr_eq(h, handle));
        handle.lock().unwrap().owned.clone()
    }

    fn steal_fast_group(&self, g: &mut Inner) -> Option<usize> {
        for handle in &g.fast_groups {
            let mut batch = handle.lock().unwrap();
            let Some(group) = batch.groups.pop_back() else {
                continue;
            };
            batch.owned[group.clone()].fill(false);
            let files = &batch.files[group];
            // All files were already counted as probes for the old owner.
            // Keep the returned file as a probe; return its siblings to the
            // ordinary queue and remove every stolen file from fast ownership.
            g.fast_probing -= files.len();
            g.probing -= files.len() - 1;
            let (_, first) = files[0];
            for &(size, idx) in &files[1..] {
                g.files.push((size, Reverse(FileOrder::new(idx))));
            }
            self.cv.notify_all();
            return Some(first);
        }
        None
    }

    /// Finish all scheduler bookkeeping for one fast batch at once.
    pub fn complete_fast_batch(&self, n: usize) {
        let mut g = self.inner.lock().unwrap();
        debug_assert!(n > 0);
        debug_assert!(g.probing >= n && g.fast_probing >= n && g.fast_batches > 0);
        g.probing -= n;
        g.fast_probing -= n;
        g.fast_batches -= 1;
        self.cv.notify_all();
    }

    /// Whether enough splittable activity remains to measure `n` workers.
    /// `minimum_activity` is derived from the observed aggregate rate and the
    /// time needed for a complete sampling window; queued files add the same
    /// completion credit the tuner uses for small-file workloads.
    pub fn work_left_for(&self, n: usize, minimum_activity: u64, file_credit: u64) -> bool {
        self.tuning_work(n, minimum_activity, file_credit)
            .sufficient
    }

    pub(crate) fn tuning_work(
        &self,
        n: usize,
        minimum_activity: u64,
        file_credit: u64,
    ) -> TuningWork {
        let g = self.inner.lock().unwrap();
        let mut evidence = TuningWork {
            scan_done: g.scan_done,
            remaining_bytes: 0,
            queued_files: 0,
            work_units: 0,
            minimum_split: self.min_split,
            workers: n,
            activity: 0,
            minimum_activity,
            parallel: false,
            sufficient: false,
        };
        // While scanning, the queue is incomplete and none of its totals qualify
        // a probe. Preserve the existing early return and mark that explicitly.
        if !g.scan_done {
            return evidence;
        }
        let mut bytes = g.files.bytes + g.ranges.bytes;
        bytes += g
            .inflight
            .iter()
            .map(|h| {
                let r = h.lock().unwrap();
                r.end.saturating_sub(r.pos)
            })
            .sum::<u64>();
        evidence.remaining_bytes = bytes;
        evidence.queued_files = g.files.len();
        evidence.activity =
            bytes.saturating_add((g.files.len() as u64).saturating_mul(file_credit));
        evidence.work_units = g.files.len() + g.ranges.len() + g.inflight.len();
        evidence.parallel =
            evidence.work_units >= n || bytes >= (n as u64).saturating_mul(self.min_split);
        evidence.sufficient = evidence.parallel && evidence.activity >= minimum_activity;
        evidence
    }

    /// Hand the unread remainder of an in-flight range back to the queue (a
    /// worker being parked). The caller's range ends at its current position
    /// and drains normally.
    pub fn release_rest(&self, h: &RangeHandle) {
        let mut g = self.inner.lock().unwrap();
        let mut r = h.lock().unwrap();
        if r.end <= r.pos {
            return;
        }
        let (idx, pos, end) = (r.idx, r.pos, r.end);
        r.end = pos;
        drop(r);
        *g.outstanding.entry(idx).or_insert(0) += 1;
        g.ranges.push((idx, pos, end));
        self.cv.notify_all();
    }

    pub fn next(&self) -> Item {
        let mut g = self.inner.lock().unwrap();
        loop {
            if g.abort {
                self.tune_cv.notify_one();
                return Item::Exit;
            }
            if g.scan_done || g.work_released {
                if let Some((idx, off, end)) = g.ranges.pop() {
                    return Item::Range(g.claim_range(idx, off, end));
                }
                if let Some((idx, matched)) = g.finishes.pop() {
                    return Item::Finish { idx, matched };
                }
                if let Some((_, Reverse(order))) = g.files.pop() {
                    let idx = order.index();
                    g.probing += 1;
                    return Item::File(idx);
                }
                if let Some(h) = self.steal(&mut g) {
                    return Item::Range(h);
                }
                if let Some(idx) = self.steal_fast_group(&mut g) {
                    return Item::File(idx);
                }
            }
            if g.scan_done && g.probing == 0 && g.inflight.is_empty() {
                self.tune_cv.notify_one();
                return Item::Exit;
            }
            g.waiting_workers += 1;
            g = self.cv.wait(g).unwrap();
            g.waiting_workers -= 1;
        }
    }

    fn steal(&self, g: &mut Inner) -> Option<RangeHandle> {
        let mut best: Option<(u64, usize)> = None;
        for (i, h) in g.inflight.iter().enumerate() {
            let r = h.lock().unwrap();
            let rem = r.end.saturating_sub(r.pos);
            if rem >= 2 * self.min_split && best.is_none_or(|(b, _)| rem > b) {
                best = Some((rem, i));
            }
        }
        let (_, i) = best?;
        let victim = g.inflight[i].clone();
        let mut r = victim.lock().unwrap();
        let rem = r.end - r.pos;
        let split = (r.pos + rem / 2).div_ceil(self.block) * self.block;
        if split >= r.end || split <= r.pos {
            return None;
        }
        let (idx, old_end) = (r.idx, r.end);
        r.end = split;
        drop(r);
        *g.outstanding.entry(idx).or_insert(0) += 1;
        Some(g.claim_range(idx, split, old_end))
    }

    /// Pop further queued files no larger than `max_size` (largest-first order
    /// means once the top is small, everything left is). Each is marked as
    /// being probed, like `Item::File`.
    pub fn take_small(&self, max_size: u64, max_n: usize, max_bytes: u64) -> Vec<usize> {
        let mut g = self.inner.lock().unwrap();
        let mut out = Vec::new();
        let mut bytes = 0u64;
        while out.len() < max_n {
            match g.files.peek() {
                Some(&(size, _)) if size <= max_size && bytes + size <= max_bytes => {
                    let (size, Reverse(order)) = g.files.pop().unwrap();
                    let idx = order.index();
                    bytes += size;
                    g.probing += 1;
                    out.push(idx);
                }
                _ => break,
            }
        }
        out
    }

    /// Claim one same-file range only when a worker can issue its next read.
    /// Leave work for peers waiting in `next`, without reserving another range
    /// for workers already busy. A peer returning to the queue competes normally
    /// with these bounded, immediately issued claims.
    pub fn take_short_range(&self, idx: usize, max_size: u64) -> Option<RangeHandle> {
        if max_size == 0 {
            return None;
        }
        match self.range_work(idx, Some(max_size)) {
            RangeWork::Cancelled => None,
            RangeWork::Ready(next) => next,
        }
    }

    /// Combine the pipeline's failure, abort and optional refill probes. A
    /// draining window still observes cancellation without three lock visits.
    pub fn range_work(&self, idx: usize, max_size: Option<u64>) -> RangeWork {
        let mut g = self.inner.lock().unwrap();
        if g.abort || g.failed.contains(&idx) {
            return RangeWork::Cancelled;
        }
        let next = max_size.filter(|size| *size > 0).and_then(|size| {
            if g.ranges.len() <= g.waiting_workers {
                return None;
            }
            let (idx, off, end) = g.ranges.take_short(idx, size)?;
            Some(g.claim_range(idx, off, end))
        });
        RangeWork::Ready(next)
    }

    /// After probing a file: register its ranges. Returns the handle for the
    /// first range (already marked in flight) or None if nothing to transfer.
    pub fn ranges_ready(&self, idx: usize, mut ranges: Vec<(u64, u64)>) -> Option<RangeHandle> {
        let mut g = self.inner.lock().unwrap();
        g.probing -= 1;
        let workers = self.initial_range_workers.swap(0, Relaxed) as u64;
        // Preserve the split floor while exposing the initial parallelism
        // before any worker's progress makes balanced stealing impossible.
        if workers > 1 && g.files.is_empty() && ranges.len() == 1 {
            let (start, end) = ranges[0];
            if start.is_multiple_of(self.block) {
                let blocks = (end - start) / self.block;
                let parts = workers
                    .min(blocks / self.min_split.div_ceil(self.block))
                    .max(1);
                if parts > 1 {
                    ranges.clear();
                    let mut off = start;
                    for part in 0..parts {
                        let n = blocks / parts + u64::from(part < blocks % parts);
                        let limit = if part + 1 == parts {
                            end
                        } else {
                            off + n * self.block
                        };
                        ranges.push((off, limit));
                        off = limit;
                    }
                }
            }
        }
        if !ranges.is_empty() {
            g.outstanding.insert(idx, ranges.len() as u32);
        }
        let mut it = ranges.into_iter();
        let first = it.next().map(|(off, end)| g.claim_range(idx, off, end));
        g.ranges.extend(idx, it.as_slice());
        self.cv.notify_all();
        first
    }

    /// Mark a range finished; true if this completed the file.
    pub fn range_done(&self, h: &RangeHandle) -> bool {
        let mut g = self.inner.lock().unwrap();
        g.inflight.retain(|x| !Arc::ptr_eq(x, h));
        let idx = h.lock().unwrap().idx;
        let n = g.outstanding.get_mut(&idx).expect("outstanding");
        *n -= 1;
        let done = *n == 0;
        if done {
            g.outstanding.remove(&idx);
        }
        self.cv.notify_all();
        done && !g.abort && !g.failed.contains(&idx)
    }

    /// A connection died with this range's acknowledgements uncertain. Put
    /// its whole claimed interval back without changing `outstanding`: the
    /// replacement carries the failed handle's existing share.
    pub fn retry_range(&self, h: &RangeHandle, start: u64) {
        let mut g = self.inner.lock().unwrap();
        g.inflight.retain(|candidate| !Arc::ptr_eq(candidate, h));
        let range = h.lock().unwrap();
        if start < range.end {
            g.ranges.push((range.idx, start, range.end));
        } else {
            let n = g.outstanding.get_mut(&range.idx).expect("outstanding");
            *n -= 1;
            if *n == 0 {
                g.outstanding.remove(&range.idx);
                g.finishes.push((range.idx, false));
            }
        }
        self.cv.notify_all();
    }

    /// Final publication is separate from range accounting so a lost
    /// Finalize response can be retried on a fresh connection.
    pub fn requeue_finish(&self, idx: usize, matched: bool) {
        self.inner.lock().unwrap().finishes.push((idx, matched));
        self.cv.notify_one();
    }
}

#[cfg(test)]
pub(crate) mod tests;

//! Work queue with largest-first file scheduling and range work-stealing.

use crate::proto::{ContainerGuard, Entry, PathBytes, RegisteredPath};
use crate::transfer_tuning::JobStorage;
use std::borrow::{Borrow, BorrowMut};
use std::cmp::Reverse;
use std::collections::{BTreeSet, BinaryHeap, HashMap, HashSet};
use std::ops::{Deref, DerefMut, Index, IndexMut};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::Duration;

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

// Compatibility modes own a deep copy. Combined snapshots retain a chunk or
// a private retry version, preserving worker views while metadata changes.
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum SnapshotData {
    Owned(FileJobData),
    Shared(Arc<FileJobData>),
    Chunk {
        slots: Arc<Vec<OnceLock<FileJobData>>>,
        slot: usize,
    },
}

impl Borrow<FileJobData> for SnapshotData {
    fn borrow(&self) -> &FileJobData {
        match self {
            Self::Owned(data) => data,
            Self::Shared(data) => data,
            Self::Chunk { slots, slot } => slots[*slot].get().unwrap(),
        }
    }
}

// Keep compatibility snapshots owned without adding an allocation for the
// record itself; the default mode shares immutable destination metadata.
#[derive(Clone, Debug)]
pub enum SnapshotEntry {
    Owned(Entry),
    Shared(Arc<Entry>),
}

impl Deref for SnapshotEntry {
    type Target = Entry;
    fn deref(&self) -> &Entry {
        match self {
            Self::Owned(entry) => entry,
            Self::Shared(entry) => entry,
        }
    }
}

pub type WorkerJob = FileJob<Option<SnapshotEntry>, SnapshotData>;
const JOBS_PER_CHUNK: usize = 1024;

/// Select the retained representation once per command. Workers always receive
/// a stable snapshot, so all layouts use identical transfer and retry logic.
#[allow(clippy::vec_box)]
pub enum Jobs {
    Compact(Vec<Box<FileJob<Option<Box<Entry>>>>>),
    Inline(Vec<FileJob>),
    Combined(SharedChunks),
}

/// Published slots never change. OnceLock permits appending jobs to a partial
/// chunk while workers hold earlier slots, without unsafe aliasing or chunk COW.
/// Retry versions are sparse and owned independently of the original chunk.
#[derive(Default)]
pub struct SharedChunks {
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

impl SharedChunks {
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
}

impl Jobs {
    fn new(storage: JobStorage) -> Self {
        match storage {
            JobStorage::Compact => Self::Compact(Vec::new()),
            JobStorage::Inline => Self::Inline(Vec::new()),
            JobStorage::Combined => Self::Combined(SharedChunks::default()),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Compact(jobs) => jobs.len(),
            Self::Inline(jobs) => jobs.len(),
            Self::Combined(jobs) => jobs.destinations.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn iter(&self) -> impl Iterator<Item = &FileJobData> {
        (0..self.len()).map(|idx| &self[idx])
    }

    fn push(&mut self, job: FileJob) {
        match self {
            Self::Compact(jobs) => jobs.push(Box::new(FileJob {
                data: job.data,
                dst_entry: job.dst_entry.map(Box::new),
            })),
            Self::Inline(jobs) => jobs.push(job),
            Self::Combined(jobs) => jobs.push(job),
        }
    }

    pub fn snapshot(&self, idx: usize) -> WorkerJob {
        FileJob {
            data: match self {
                Self::Combined(jobs) => jobs.current(idx).snapshot(),
                _ => SnapshotData::Owned(self[idx].clone()),
            },
            dst_entry: match self {
                Self::Combined(jobs) => jobs.destinations[idx]
                    .as_ref()
                    .map(|entry| SnapshotEntry::Shared(entry.clone())),
                _ => self.destination(idx).cloned().map(SnapshotEntry::Owned),
            },
        }
    }

    pub fn destination(&self, idx: usize) -> Option<&Entry> {
        match self {
            Self::Compact(jobs) => jobs[idx].dst_entry.as_deref(),
            Self::Inline(jobs) => jobs[idx].dst_entry.as_ref(),
            Self::Combined(jobs) => jobs.destinations[idx].as_deref(),
        }
    }

    pub fn set_destination(&mut self, idx: usize, entry: Entry) {
        match self {
            Self::Compact(jobs) => jobs[idx].dst_entry = Some(Box::new(entry)),
            Self::Inline(jobs) => jobs[idx].dst_entry = Some(entry),
            Self::Combined(jobs) => jobs.destinations[idx] = Some(Arc::new(entry)),
        }
    }

    fn release(&mut self) {
        match self {
            Self::Compact(jobs) => *jobs = Vec::new(),
            Self::Inline(jobs) => *jobs = Vec::new(),
            Self::Combined(jobs) => *jobs = SharedChunks::default(),
        }
    }
}

impl Index<usize> for Jobs {
    type Output = FileJobData;
    fn index(&self, idx: usize) -> &Self::Output {
        match self {
            Self::Compact(jobs) => &jobs[idx].data,
            Self::Inline(jobs) => &jobs[idx].data,
            Self::Combined(jobs) => jobs.current(idx).data(),
        }
    }
}

impl IndexMut<usize> for Jobs {
    fn index_mut(&mut self, idx: usize) -> &mut Self::Output {
        match self {
            Self::Compact(jobs) => &mut jobs[idx].data,
            Self::Inline(jobs) => &mut jobs[idx].data,
            Self::Combined(jobs) => jobs.get_mut(idx),
        }
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

pub enum Item {
    File(usize),
    Range(RangeHandle),
    Finish { idx: usize, matched: bool },
    Exit,
}

/// Keep one global maximum per file. The file index supports both largest-first
/// scheduling and short same-file claims without storing every range twice.
#[derive(Default)]
struct RangeQueue {
    largest: BTreeSet<(u64, usize, u64)>,
    by_file: HashMap<usize, BTreeSet<(u64, u64)>>,
    len: usize,
}

impl RangeQueue {
    fn push(&mut self, (idx, off, end): (usize, u64, u64)) {
        let key = (end - off, off);
        let file = self.by_file.entry(idx).or_default();
        let previous = file.last().copied();
        assert!(file.insert(key));
        if previous.is_none_or(|maximum| key > maximum) {
            if let Some((len, off)) = previous {
                assert!(self.largest.remove(&(len, idx, off)));
            }
            assert!(self.largest.insert((key.0, idx, key.1)));
        }
        self.len += 1;
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

struct Inner {
    files: BinaryHeap<(u64, Reverse<FileOrder>)>,
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
    /// Planning has observed at least one regular file, before destination
    /// namespace checks and directory creation make it runnable.
    file_work_anticipated: bool,
    scan_done: bool,
    abort: bool,
}

impl Inner {
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
    #[cfg(test)]
    pub fn new(block: u64, min_split: u64) -> Self {
        Self::with_job_storage(block, min_split, JobStorage::default())
    }

    pub fn with_job_storage(block: u64, min_split: u64, storage: JobStorage) -> Self {
        Sched {
            inner: Mutex::new(Inner {
                files: BinaryHeap::new(),
                ranges: RangeQueue::default(),
                finishes: Vec::new(),
                inflight: Vec::new(),
                outstanding: HashMap::new(),
                failed: HashSet::new(),
                probing: 0,
                waiting_workers: 0,
                fast_probing: 0,
                fast_batches: 0,
                file_work_anticipated: false,
                scan_done: false,
                abort: false,
            }),
            cv: Condvar::new(),
            tune_cv: Condvar::new(),
            direct_fallback_workers: AtomicUsize::new(0),
            initial_range_workers: AtomicUsize::new(0),
            tune_request: AtomicUsize::new(0),
            jobs: Mutex::new(Jobs::new(storage)),
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
        self.inner
            .lock()
            .unwrap()
            .files
            .push((size, Reverse(FileOrder::new(idx))));
        self.cv.notify_one();
        idx
    }

    /// File jobs and queues are index-addressed while workers are active. Once
    /// every worker and the tuner have joined, release their retained capacity
    /// before deletion, deferred metadata, and receipt settlement continue.
    pub fn clear_finished_work(&self) {
        self.jobs.lock().unwrap().release();
        let mut inner = self.inner.lock().unwrap();
        inner.files = BinaryHeap::new();
        inner.ranges = RangeQueue::default();
        inner.finishes = Vec::new();
        inner.inflight = Vec::new();
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
        self.inner.lock().unwrap().file_work_anticipated = true;
        self.cv.notify_all();
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

    /// Whether useful capacity is queued or about to emerge from an ordinary
    /// large-file probe. A pipelined small-file batch already has an owner and
    /// will never expose ranges, so it does not justify replacing a worker
    /// that retired after draining the queue.
    pub fn needs_worker_capacity(&self) -> bool {
        let g = self.inner.lock().unwrap();
        !g.files.is_empty()
            || !g.ranges.is_empty()
            || !g.finishes.is_empty()
            || g.probing > g.fast_probing
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
        let g = self.inner.lock().unwrap();
        if !g.scan_done {
            return false;
        }
        let mut bytes: u64 = g.files.iter().map(|(s, _)| *s).sum();
        bytes += g.ranges.iter().map(|(_, o, e)| e - o).sum::<u64>();
        bytes += g
            .inflight
            .iter()
            .map(|h| {
                let r = h.lock().unwrap();
                r.end.saturating_sub(r.pos)
            })
            .sum::<u64>();
        let activity = bytes.saturating_add((g.files.len() as u64).saturating_mul(file_credit));
        let work_units = g.files.len() + g.ranges.len() + g.inflight.len();
        let parallel = work_units >= n || bytes >= (n as u64).saturating_mul(self.min_split);
        parallel && activity >= minimum_activity
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
            if g.scan_done {
                if let Some((idx, off, end)) = g.ranges.pop() {
                    let h = Arc::new(Mutex::new(RangeState { idx, pos: off, end }));
                    g.inflight.push(h.clone());
                    return Item::Range(h);
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
        let h = Arc::new(Mutex::new(RangeState {
            idx,
            pos: split,
            end: old_end,
        }));
        g.inflight.push(h.clone());
        Some(h)
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
        let mut g = self.inner.lock().unwrap();
        if g.abort
            || g.failed.contains(&idx)
            || g.outstanding.get(&idx).copied().unwrap_or(0) <= 1
            || g.ranges.len() <= g.waiting_workers
        {
            return None;
        }
        let (idx, off, end) = g.ranges.take_short(idx, max_size)?;
        let h = Arc::new(Mutex::new(RangeState { idx, pos: off, end }));
        g.inflight.push(h.clone());
        Some(h)
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
        let first = it.next().map(|(off, end)| {
            let h = Arc::new(Mutex::new(RangeState { idx, pos: off, end }));
            g.inflight.push(h.clone());
            h
        });
        for (off, end) in it {
            g.ranges.push((idx, off, end));
        }
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
mod tests {
    use super::*;

    fn test_job(size: u64) -> FileJob {
        FileJob {
            data: FileJobData {
                src: b"source".to_vec(),
                source: RegisteredPath::new(serde_json::from_str("0").unwrap(), b"source".to_vec())
                    .unwrap(),
                dst: b"destination".to_vec(),
                rel: "destination".into(),
                rel_bytes: b"destination".to_vec(),
                src_rel: None,
                entry: Entry {
                    path: Vec::new(),
                    kind: crate::proto::Kind::File,
                    size,
                    mtime: 0,
                    mtime_nsec: 0,
                    mode: 0o644,
                    uid: 0,
                    gid: 0,
                    rdev: 0,
                    dev: 1,
                    ino: 1,
                    ctime: 0,
                    ctime_nsec: 0,
                    link: None,
                },
                target_condition: crate::proto::TargetCondition::Any,
                container_guard: None,
                attempt: 0,
                done: Arc::new(AtomicU64::new(0)),
                inplace: false,
            },
            dst_entry: None,
        }
    }

    #[test]
    fn equal_size_files_spread_across_directory_groups() {
        let sched = Sched::new(64, 128);
        // Model a scan of sixteen directories, sixteen files in each.
        for _ in 0..256 {
            sched.push_file(test_job(4096));
        }
        sched.scan_done();
        let mut directories = HashSet::new();
        for _ in 0..16 {
            let Item::File(idx) = sched.next() else {
                panic!("missing file")
            };
            directories.insert(idx / 16);
            sched.ranges_ready(idx, Vec::new());
        }
        assert_eq!(
            directories.len(),
            16,
            "workers should start in distinct directory groups"
        );
    }

    #[test]
    fn reordered_batches_preserve_size_priority_limits_and_every_index() {
        let sched = Sched::new(64, 128);
        // Include zero-length files, repeated sizes, and a non-power-of-two count.
        let sizes: Vec<_> = (0..257).map(|i| (i % 7) * 1024).collect();
        for &size in &sizes {
            sched.push_file(test_job(size));
        }
        sched.scan_done();
        assert!(sched.take_small(4096, 10, u64::MAX).is_empty());
        let mut seen = HashSet::new();
        let mut previous = u64::MAX;
        while let Item::File(first) = sched.next() {
            let mut batch = vec![first];
            let extra = sched.take_small(sizes[first], 11, 8192);
            assert!(extra.len() <= 11);
            assert!(extra.iter().map(|&idx| sizes[idx]).sum::<u64>() <= 8192);
            batch.extend(extra);
            for idx in batch {
                assert!(seen.insert(idx), "duplicate job {idx}");
                assert!(
                    sizes[idx] <= previous,
                    "file size must remain the primary priority"
                );
                previous = sizes[idx];
                sched.ranges_ready(idx, Vec::new());
            }
        }
        assert_eq!(seen.len(), sizes.len());
        assert!(sched.finished());
    }

    #[test]
    fn requeued_files_keep_their_identity_with_concurrent_batch_consumers() {
        let sched = Arc::new(Sched::new(64, 128));
        for idx in 0..257 {
            let mut job = test_job(4096);
            job.done.store(idx as u64, Relaxed);
            job.rel = idx.to_string();
            sched.push_file(job);
        }
        sched.scan_done();
        let seen = Mutex::new(Vec::new());
        let retried = std::sync::atomic::AtomicBool::new(false);
        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    while let Item::File(first) = sched.next() {
                        let mut batch = vec![first];
                        batch.extend(sched.take_small(4096, 3, 3 * 4096));
                        for idx in batch {
                            let jobs = sched.jobs.lock().unwrap();
                            assert_eq!(jobs[idx].rel, idx.to_string());
                            assert_eq!(jobs[idx].done.load(Relaxed), idx as u64);
                            drop(jobs);
                            seen.lock().unwrap().push(idx);
                            if idx == 17 && !retried.swap(true, Relaxed) {
                                sched.requeue(idx);
                            }
                            sched.ranges_ready(idx, Vec::new());
                        }
                    }
                });
            }
        });
        let mut seen = seen.into_inner().unwrap();
        seen.sort_unstable();
        let mut expected: Vec<_> = (0..257).chain(std::iter::once(17)).collect();
        expected.sort_unstable();
        assert_eq!(seen, expected);
        assert!(sched.finished());
    }

    #[test]
    fn combined_destination_snapshots_share_and_preserve_replaced_versions() {
        let mut jobs = Jobs::new(JobStorage::Combined);
        let mut job = test_job(7);
        let mut original = job.entry.clone();
        original.path = b"destination/original".to_vec();
        job.dst_entry = Some(original.clone());
        jobs.push(job);
        let first = jobs.snapshot(0);
        let second = jobs.snapshot(0);
        let (Some(SnapshotEntry::Shared(a)), Some(SnapshotEntry::Shared(b))) =
            (&first.dst_entry, &second.dst_entry)
        else {
            panic!("destination was deep-cloned");
        };
        assert!(Arc::ptr_eq(a, b));
        assert!(std::ptr::eq(a.as_ref(), jobs.destination(0).unwrap()));
        let old = Arc::downgrade(a);
        let mut replacement = original;
        replacement.path = b"destination/replacement".to_vec();
        replacement.size = 11;
        jobs.set_destination(0, replacement);
        let latest = jobs.snapshot(0);
        assert_eq!(first.dst_entry.as_ref().unwrap().size, 7);
        assert_eq!(
            first.dst_entry.as_ref().unwrap().path,
            b"destination/original"
        );
        assert_eq!(latest.dst_entry.as_ref().unwrap().size, 11);
        jobs.release();
        assert_eq!(
            latest.dst_entry.as_ref().unwrap().path,
            b"destination/replacement"
        );
        drop(first);
        assert!(old.upgrade().is_some());
        drop(second);
        assert!(old.upgrade().is_none());
    }

    #[test]
    fn combined_chunks_allow_append_retry_and_release_with_live_snapshots() {
        let mut jobs = Jobs::new(JobStorage::Combined);
        jobs.push(test_job(7));
        let first = jobs.snapshot(0);
        let SnapshotData::Chunk { slots, .. } = &first.data else {
            panic!("expected chunk");
        };
        let owner = Arc::downgrade(slots);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                for _ in 0..10_000 {
                    assert_eq!(first.entry.size, 7);
                }
            });
            for _ in 0..(2 * JOBS_PER_CHUNK) {
                jobs.push(test_job(9));
            }
        });
        let second = jobs.snapshot(1);
        let SnapshotData::Chunk {
            slots: second_slots,
            ..
        } = &second.data
        else {
            panic!("expected chunk");
        };
        assert!(Arc::ptr_eq(slots, second_slots));
        let Jobs::Combined(storage) = &jobs else {
            unreachable!()
        };
        assert!(storage.retries.is_empty());
        assert_eq!(storage.chunks.len(), 3);
        jobs[0].entry.size = 11;
        let retry = jobs.snapshot(0);
        jobs[0].entry.size = 13;
        assert_eq!(first.entry.size, 7);
        assert_eq!(second.entry.size, 9);
        assert_eq!(retry.entry.size, 11);
        assert_eq!(jobs[0].entry.size, 13);
        jobs.release();
        assert_eq!(first.entry.size, 7);
        assert_eq!(retry.entry.size, 11);
        drop(first);
        assert!(owner.upgrade().is_some());
        drop(second);
        assert!(owner.upgrade().is_none());
    }

    #[test]
    fn job_storage_preserves_indexes_snapshots_retries_and_releases_capacity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file");
        std::fs::write(&path, b"payload").unwrap();
        let entry = crate::fsops::lstat_entry(b"file".to_vec(), &path).unwrap();
        for mode in [
            JobStorage::Compact,
            JobStorage::Inline,
            JobStorage::Combined,
        ] {
            let sched = Sched::with_job_storage(4, 8, mode);
            for i in 0..(2 * JOBS_PER_CHUNK + 1) {
                let idx = sched.push_file(FileJob {
                    dst_entry: (i % 2 == 0).then(|| entry.clone()),
                    data: FileJobData {
                        src: b"src/file".to_vec(),
                        source: RegisteredPath::new(
                            serde_json::from_str("0").unwrap(),
                            b"file".to_vec(),
                        )
                        .unwrap(),
                        dst: b"dst/file".to_vec(),
                        rel: i.to_string(),
                        entry: entry.clone(),
                        target_condition: crate::proto::TargetCondition::Any,
                        container_guard: None,
                        attempt: 0,
                        done: Arc::new(AtomicU64::new(0)),
                        inplace: false,
                        rel_bytes: i.to_string().into_bytes(),
                        src_rel: None,
                    },
                });
                assert_eq!(idx, i);
            }
            let mut jobs = sched.jobs.lock().unwrap();
            assert_eq!(jobs.len(), 2 * JOBS_PER_CHUNK + 1);
            for i in 0..jobs.len() {
                assert_eq!(jobs[i].rel, i.to_string());
                assert_eq!(jobs.destination(i).is_some(), i % 2 == 0);
            }
            let before = jobs.snapshot(1);
            jobs[1].entry.size = 99;
            jobs[1].attempt = 1;
            jobs[1].inplace = true;
            jobs[1].done.store(3, Relaxed);
            jobs.set_destination(1, entry.clone());
            let retry = jobs.snapshot(1);
            assert_eq!(before.entry.size, 7);
            assert_eq!(before.attempt, 0);
            assert!(!before.inplace);
            assert!(before.dst_entry.is_none());
            assert_eq!(retry.entry.size, 99);
            assert_eq!(retry.attempt, 1);
            assert!(retry.inplace);
            assert_eq!(retry.dst_entry.unwrap().size, 7);
            assert_eq!(before.done.load(Relaxed), 3);
            drop(jobs);
            sched.clear_finished_work();
            let jobs = sched.jobs.lock().unwrap();
            assert!(jobs.is_empty());
            match &*jobs {
                Jobs::Compact(jobs) => assert_eq!(jobs.capacity(), 0),
                Jobs::Inline(jobs) => assert_eq!(jobs.capacity(), 0),
                Jobs::Combined(jobs) => {
                    assert_eq!(jobs.chunks.capacity(), 0);
                    assert_eq!(jobs.destinations.capacity(), 0);
                    assert_eq!(jobs.retries.capacity(), 0);
                }
            }
        }
    }

    #[test]
    fn failed_or_aborted_ranges_never_elect_a_publisher() {
        for abort in [false, true] {
            let sched = Sched::new(4, 8);
            sched.inner.lock().unwrap().probing = 1;
            let first = sched.ranges_ready(0, vec![(0, 4), (4, 8)]).unwrap();
            sched.scan_done();
            let Item::Range(last) = sched.next() else {
                panic!("missing range")
            };
            if abort {
                sched.abort();
            } else {
                assert!(sched.fail_file(0));
                assert!(!sched.fail_file(0), "report each failed file once");
            }
            assert!(!sched.range_done(&first));
            assert!(!sched.range_done(&last));
        }
    }

    #[test]
    fn short_range_claim_preserves_other_files_limits_and_shares() {
        let sched = Sched::new(512, 8192);
        sched.inner.lock().unwrap().probing = 2;
        let first = sched
            .ranges_ready(0, vec![(0, 512), (1024, 1536), (2048, 2560), (4096, 8192)])
            .unwrap();
        let other = sched.ranges_ready(1, vec![(0, 512), (1024, 1536)]).unwrap();
        assert!(sched.take_short_range(0, 0).is_none());
        sched.inner.lock().unwrap().waiting_workers = 4;
        assert!(sched.take_short_range(0, 512).is_none());
        sched.inner.lock().unwrap().waiting_workers = 3;
        let extra = sched.take_short_range(0, 512).unwrap();
        assert_eq!(extra.lock().unwrap().pos, 1024);
        assert_eq!(sched.inner.lock().unwrap().outstanding[&0], 4);
        assert!(!sched.range_done(&extra));
        assert!(sched.take_short_range(0, 512).is_none());
        sched.inner.lock().unwrap().waiting_workers = 0;
        let extra = sched.take_short_range(0, 512).unwrap();
        assert!(!sched.range_done(&extra));
        assert!(sched.take_short_range(0, 512).is_none());
        sched.release_rest(&first);
        assert!(!sched.range_done(&first));
        assert!(!sched.range_done(&other));
        let inner = sched.inner.lock().unwrap();
        assert!(inner.ranges.contains(&(1, 1024, 1536)));
        assert!(inner.ranges.contains(&(0, 4096, 8192)));
        assert!(inner.ranges.contains(&(0, 0, 512)));
        drop(inner);
        sched.fail_file(0);
        assert!(sched.take_short_range(0, 512).is_none());
        sched.abort();
        assert!(sched.take_short_range(1, 512).is_none());
    }

    #[test]
    fn short_range_tail_is_available_while_other_workers_are_busy() {
        let sched = Sched::new(512, 8192);
        sched.inner.lock().unwrap().probing = 2;
        let primary = sched.ranges_ready(0, vec![(0, 512), (1024, 1536)]).unwrap();
        let busy_peer = sched.ranges_ready(1, vec![(0, 8192)]).unwrap();
        // Both workers own work; the sole queued range can fill the first
        // worker's pipeline instead of waiting for it to drain and call next.
        let extra = sched.take_short_range(0, 512).unwrap();
        assert_eq!(extra.lock().unwrap().pos, 1024);
        assert!(!sched.range_done(&extra));
        assert!(sched.range_done(&primary));
        assert!(sched.range_done(&busy_peer));
    }

    #[test]
    fn short_range_claim_leaves_a_share_for_a_waiting_worker() {
        let sched = Arc::new(Sched::new(512, 8192));
        sched.inner.lock().unwrap().probing = 1;
        let primary = sched.ranges_ready(0, vec![(0, 512)]).unwrap();
        sched.scan_done();
        let (tx, rx) = std::sync::mpsc::channel();
        let peer = {
            let sched = sched.clone();
            std::thread::spawn(move || tx.send(sched.next()).unwrap())
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let waiting = sched.inner.lock().unwrap().waiting_workers;
            if waiting == 1 {
                break;
            }
            if std::time::Instant::now() >= deadline {
                sched.abort();
                peer.join().unwrap();
                panic!("worker did not wait for work: waiting_workers={waiting}");
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        {
            let mut inner = sched.inner.lock().unwrap();
            // Publish without notifying yet: the owner can claim an extra,
            // but must leave another share for the sleeping peer.
            inner.ranges.push((0, 1024, 1536));
            inner.ranges.push((0, 2048, 2560));
            *inner.outstanding.get_mut(&0).unwrap() += 2;
        }
        let extra = sched.take_short_range(0, 512).unwrap();
        assert!(sched.take_short_range(0, 512).is_none());
        sched.cv.notify_all();
        let item = rx.recv_timeout(Duration::from_secs(2));
        if item.is_err() {
            sched.abort();
        }
        peer.join().unwrap();
        let Item::Range(other) = item.expect("waiting worker must receive its share") else {
            panic!("waiting worker exited without a range")
        };
        assert_eq!(sched.inner.lock().unwrap().waiting_workers, 0);
        assert_ne!(extra.lock().unwrap().pos, other.lock().unwrap().pos);
        assert!(!sched.range_done(&extra));
        assert!(!sched.range_done(&other));
        assert!(sched.range_done(&primary));
        assert!(sched.finished());
    }

    #[test]
    fn range_queue_updates_file_maxima_and_preserves_equal_length_order() {
        let mut queue = RangeQueue::default();
        for range in [
            (0, 0, 512),
            (0, 1024, 3072),
            (0, 4096, 6144),
            (1, 0, 2048),
            (2, 0, 512),
        ] {
            queue.push(range);
        }
        assert_eq!(queue.len(), 5);
        assert_eq!(queue.largest.len(), 3);
        assert_eq!(queue.iter().count(), 5);
        assert_eq!(queue.pop(), Some((1, 0, 2048)));
        assert_eq!(queue.take_short(0, 512), Some((0, 0, 512)));
        assert_eq!(queue.take_short(2, 512), Some((2, 0, 512)));
        assert_eq!(queue.largest.len(), 1);
        assert_eq!(queue.take_short(0, 512), None);
        queue.push((0, 8192, 12288));
        queue.push((1, 8192, 10240));
        assert_eq!(queue.pop(), Some((0, 8192, 12288)));
        assert_eq!(queue.pop(), Some((1, 8192, 10240)));
        assert_eq!(queue.pop(), Some((0, 4096, 6144)));
        assert_eq!(queue.pop(), Some((0, 1024, 3072)));
        assert!(queue.is_empty());
        assert!(queue.by_file.is_empty());
        assert!(queue.largest.is_empty());
    }

    #[test]
    fn range_queue_indexes_agree_after_interleaved_claims() {
        let mut queue = RangeQueue::default();
        for idx in 0..200 {
            for i in 0..1000 {
                queue.push((idx, i * 8192, i * 8192 + 512 * (1 + i % 8)));
            }
        }
        assert_eq!(queue.len(), 200_000);
        assert_eq!(queue.largest.len(), 200);
        for idx in (0..200).rev() {
            for _ in 0..125 {
                let (_, off, end) = queue.take_short(idx, 512).unwrap();
                assert_eq!(end - off, 512);
            }
            assert!(queue.take_short(idx, 512).is_none());
        }
        let mut previous = u64::MAX;
        while let Some((_, off, end)) = queue.pop() {
            assert!(end - off <= previous);
            previous = end - off;
        }
        assert!(queue.by_file.is_empty());
    }

    #[test]
    fn initial_ranges_preserve_coverage_alignment_and_split_floor() {
        for size in [
            1,
            31 << 20,
            32 << 20,
            63 << 20,
            64 << 20,
            256 << 20,
            (257 << 20) + 7,
        ] {
            for workers in [0, 1, 2, 8, 16] {
                let sched = Sched::new(4 << 20, 32 << 20);
                sched.inner.lock().unwrap().probing = 1;
                sched.reserve_initial_ranges(workers);
                let first = sched.ranges_ready(0, vec![(0, size)]).unwrap();
                let mut spans = {
                    let r = first.lock().unwrap();
                    vec![(r.pos, r.end)]
                };
                let inner = sched.inner.lock().unwrap();
                spans.extend(inner.ranges.iter().map(|(_, off, end)| (off, end)));
                spans.sort_unstable();
                let count = workers.min((size / sched.min_split) as usize).max(1);
                assert_eq!(spans.len(), count);
                assert_eq!(inner.outstanding[&0] as usize, count);
                let mut end = 0;
                for (off, limit) in spans {
                    assert_eq!(off, end);
                    assert_eq!(off % sched.block, 0);
                    assert!(count == 1 || limit - off >= sched.min_split);
                    end = limit;
                }
                assert_eq!(end, size);
            }
        }
    }

    #[test]
    fn initial_ranges_remain_available_after_the_first_worker_advances() {
        let sched = Sched::new(4 << 20, 32 << 20);
        sched.inner.lock().unwrap().probing = 1;
        sched.reserve_initial_ranges(8);
        let first = sched.ranges_ready(0, vec![(0, 256 << 20)]).unwrap();
        first.lock().unwrap().pos += 4 << 20;
        sched.scan_done();
        for _ in 1..8 {
            let Item::Range(range) = sched.next() else {
                panic!("missing reserved range")
            };
            assert!(!sched.range_done(&range));
        }
        assert!(sched.range_done(&first));
        assert!(matches!(sched.next(), Item::Exit));
    }

    #[test]
    fn initial_ranges_leave_diff_ranges_and_other_files_alone() {
        for queued_file in [false, true] {
            let sched = Sched::new(4 << 20, 32 << 20);
            {
                let mut inner = sched.inner.lock().unwrap();
                inner.probing = 1;
                if queued_file {
                    inner.files.push((64 << 20, Reverse(FileOrder::new(1))));
                }
            }
            sched.reserve_initial_ranges(8);
            let spans = if queued_file {
                vec![(0, 256 << 20)]
            } else {
                vec![(0, 64 << 20), (128 << 20, 256 << 20)]
            };
            let first = sched.ranges_ready(0, spans.clone()).unwrap();
            let range = first.lock().unwrap();
            assert_eq!((range.pos, range.end), spans[0]);
            let inner = sched.inner.lock().unwrap();
            assert_eq!(inner.outstanding[&0] as usize, spans.len());
            assert_eq!(sched.initial_range_workers.load(Relaxed), 0);
        }
    }

    #[test]
    fn tuning_split_threshold_controls_when_idle_workers_can_help() {
        for (threshold, can_split) in [(8 << 20, true), (32 << 20, false)] {
            let tuning: crate::transfer_tuning::TransferTuning =
                format!("split-min-size={threshold}").parse().unwrap();
            let sched = Sched::new(4 << 20, tuning.split_min_size(4 << 20));
            let mut inner = sched.inner.lock().unwrap();
            inner.inflight.push(Arc::new(Mutex::new(RangeState {
                idx: 0,
                pos: 0,
                end: 48 << 20,
            })));
            let stolen = sched.steal(&mut inner);
            assert_eq!(stolen.is_some(), can_split);
            if let Some(stolen) = stolen {
                let stolen = stolen.lock().unwrap();
                assert_eq!((stolen.pos, stolen.end), (24 << 20, 48 << 20));
            }
        }
    }

    #[test]
    fn worker_exit_wakes_the_tuning_wait() {
        let sched = Arc::new(Sched::new(64, 128));
        {
            let mut inner = sched.inner.lock().unwrap();
            inner.scan_done = true;
            inner.probing = 1;
        }
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let waiter = {
            let sched = sched.clone();
            std::thread::spawn(move || {
                started_tx.send(()).unwrap();
                let started = std::time::Instant::now();
                sched.wait_for_tuning(Duration::from_secs(2));
                started.elapsed()
            })
        };
        started_rx.recv().unwrap();
        std::thread::sleep(Duration::from_millis(20));
        assert!(sched.ranges_ready(0, Vec::new()).is_none());
        assert!(matches!(sched.next(), Item::Exit));

        let elapsed = waiter.join().unwrap();
        assert!(
            elapsed < Duration::from_millis(500),
            "worker exit left the tuner asleep for {elapsed:?}"
        );
    }

    #[test]
    fn eager_connections_wait_for_a_planned_file_and_skip_empty_scans() {
        let with_file = Arc::new(Sched::new(64, 128));
        let waiter = {
            let sched = with_file.clone();
            std::thread::spawn(move || sched.wait_for_anticipated_file_work())
        };
        with_file.anticipate_file_work();
        assert!(waiter.join().unwrap());

        let empty = Arc::new(Sched::new(64, 128));
        let waiter = {
            let sched = empty.clone();
            std::thread::spawn(move || sched.wait_for_anticipated_file_work())
        };
        empty.scan_done();
        assert!(!waiter.join().unwrap());
    }

    #[test]
    fn tail_gate_combines_bytes_file_credit_and_duration_requirement() {
        let sched = Sched::new(64, 128);
        {
            let mut inner = sched.inner.lock().unwrap();
            inner.scan_done = true;
            inner.files.push((100, Reverse(FileOrder::new(0))));
            inner.files.push((100, Reverse(FileOrder::new(1))));
        }
        assert!(sched.work_left_for(2, 1_200, 512));
        assert!(!sched.work_left_for(2, 1_300, 512));
        assert!(!sched.work_left_for(3, 1_000, 512));
    }

    #[test]
    fn claimed_small_files_do_not_request_replacement_capacity() {
        let sched = Sched::new(64, 128);
        {
            let mut inner = sched.inner.lock().unwrap();
            inner.scan_done = true;
            inner.probing = 2;
            inner.fast_probing = 2;
            inner.fast_batches = 1;
        }
        assert!(!sched.finished());
        assert!(!sched.needs_worker_capacity());

        // A regular file probe will soon expose transferable ranges, so its
        // spare connection should warm while hashing/preparation is underway.
        sched.inner.lock().unwrap().probing += 1;
        assert!(sched.needs_worker_capacity());
        sched.inner.lock().unwrap().probing -= 1;

        sched
            .inner
            .lock()
            .unwrap()
            .files
            .push((100, Reverse(FileOrder::new(0))));
        assert!(sched.needs_worker_capacity());
    }

    #[test]
    fn fast_batches_share_the_queue_across_active_workers() {
        let sched = Sched::new(4096, 8192);
        {
            let mut inner = sched.inner.lock().unwrap();
            inner.scan_done = true;
            for idx in 0..2000 {
                inner.files.push((4096, Reverse(FileOrder::new(idx))));
            }
        }

        assert!(matches!(sched.next(), Item::File(_)));
        let first_target = sched.begin_fast_batch(32, 128);
        assert_eq!(first_target, 63);
        let first_extra = sched.take_small(4096, first_target - 1, u64::MAX);
        sched.mark_fast(first_extra.len());
        assert_eq!(first_extra.len() + 1, 63);

        assert!(matches!(sched.next(), Item::File(_)));
        let second_target = sched.begin_fast_batch(32, 128);
        assert_eq!(second_target, 63);
    }

    #[test]
    fn retry_range_replaces_the_failed_inflight_share() {
        let sched = Sched::new(64, 128);
        let range = Arc::new(Mutex::new(RangeState {
            idx: 4,
            pos: 192,
            end: 256,
        }));
        {
            let mut inner = sched.inner.lock().unwrap();
            inner.inflight.push(range.clone());
            inner.outstanding.insert(4, 1);
        }
        sched.retry_range(&range, 128);
        let inner = sched.inner.lock().unwrap();
        assert!(inner.inflight.is_empty());
        assert_eq!(inner.ranges.iter().collect::<Vec<_>>(), vec![(4, 128, 256)]);
        assert_eq!(inner.outstanding.get(&4), Some(&1));
    }

    #[test]
    fn retry_of_an_empty_claim_preserves_finalization() {
        let sched = Sched::new(64, 128);
        let range = Arc::new(Mutex::new(RangeState {
            idx: 5,
            pos: 256,
            end: 256,
        }));
        {
            let mut inner = sched.inner.lock().unwrap();
            inner.inflight.push(range.clone());
            inner.outstanding.insert(5, 1);
        }
        sched.retry_range(&range, 256);
        let inner = sched.inner.lock().unwrap();
        assert!(!inner.outstanding.contains_key(&5));
        assert_eq!(inner.finishes, vec![(5, false)]);
    }
}

//! Work queue with largest-first file scheduling and range work-stealing.

use crate::proto::{ContainerGuard, Entry, PathBytes, RegisteredPath};
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct FileJob {
    pub src: PathBytes,
    /// Descriptor-session authority corresponding to `src`. Source workers,
    /// and Linux destination workers using CopyLocal, claim its root during
    /// authenticated initialization and use it for content opens.
    pub source: RegisteredPath,
    pub dst: PathBytes,
    pub rel: String,
    pub entry: Entry,
    pub dst_entry: Option<Entry>,
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

struct Inner {
    files: BinaryHeap<(u64, Reverse<usize>)>,
    ranges: Vec<(usize, u64, u64)>,
    finishes: Vec<(usize, bool)>,
    inflight: Vec<RangeHandle>,
    outstanding: HashMap<usize, u32>,
    failed: HashSet<usize>,
    probing: usize,
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
    tune_request: AtomicUsize,
    pub jobs: Mutex<Vec<FileJob>>,
    pub block: u64,
    pub min_split: u64,
}

impl Sched {
    pub fn new(block: u64, min_split: u64) -> Self {
        Sched {
            inner: Mutex::new(Inner {
                files: BinaryHeap::new(),
                ranges: Vec::new(),
                finishes: Vec::new(),
                inflight: Vec::new(),
                outstanding: HashMap::new(),
                failed: HashSet::new(),
                probing: 0,
                fast_probing: 0,
                fast_batches: 0,
                file_work_anticipated: false,
                scan_done: false,
                abort: false,
            }),
            cv: Condvar::new(),
            tune_cv: Condvar::new(),
            direct_fallback_workers: AtomicUsize::new(0),
            tune_request: AtomicUsize::new(0),
            jobs: Mutex::new(Vec::new()),
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
        self.inner.lock().unwrap().files.push((size, Reverse(idx)));
        self.cv.notify_one();
        idx
    }

    /// File jobs and queues are index-addressed while workers are active. Once
    /// every worker and the tuner have joined, release their retained capacity
    /// before deletion, deferred metadata, and receipt settlement continue.
    pub fn clear_finished_work(&self) {
        *self.jobs.lock().unwrap() = Vec::new();
        let mut inner = self.inner.lock().unwrap();
        inner.files = BinaryHeap::new();
        inner.ranges = Vec::new();
        inner.finishes = Vec::new();
        inner.inflight = Vec::new();
        inner.outstanding = HashMap::new();
        inner.failed = HashSet::new();
    }

    /// Wake the tuner when a speculative direct local copy discovers that it
    /// needs the ordinary parallel userspace path after all.
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
        self.inner.lock().unwrap().files.push((size, Reverse(idx)));
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

    pub fn fail_file(&self, idx: usize) {
        self.inner.lock().unwrap().failed.insert(idx);
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
        g.ranges.sort_by_key(|(_, o, e)| e - o);
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
                if let Some((_, Reverse(idx))) = g.files.pop() {
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
            g = self.cv.wait(g).unwrap();
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
                    let (size, Reverse(idx)) = g.files.pop().unwrap();
                    bytes += size;
                    g.probing += 1;
                    out.push(idx);
                }
                _ => break,
            }
        }
        out
    }

    /// After probing a file: register its ranges. Returns the handle for the
    /// first range (already marked in flight) or None if nothing to transfer.
    pub fn ranges_ready(&self, idx: usize, ranges: Vec<(u64, u64)>) -> Option<RangeHandle> {
        let mut g = self.inner.lock().unwrap();
        g.probing -= 1;
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
        // Largest ranges first for the queue (pop takes from the back).
        g.ranges.sort_by_key(|(_, o, e)| e - o);
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
        done
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
            g.ranges.sort_by_key(|(_, off, end)| end - off);
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
            inner.files.push((100, Reverse(0)));
            inner.files.push((100, Reverse(1)));
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

        sched.inner.lock().unwrap().files.push((100, Reverse(0)));
        assert!(sched.needs_worker_capacity());
    }

    #[test]
    fn fast_batches_share_the_queue_across_active_workers() {
        let sched = Sched::new(4096, 8192);
        {
            let mut inner = sched.inner.lock().unwrap();
            inner.scan_done = true;
            for idx in 0..2000 {
                inner.files.push((4096, Reverse(idx)));
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
        assert_eq!(inner.ranges, vec![(4, 128, 256)]);
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

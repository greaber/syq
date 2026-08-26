//! Work queue with largest-first file scheduling and range work-stealing.

use crate::proto::{Entry, PathBytes};
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Condvar, Mutex};

#[derive(Clone, Debug)]
pub struct FileJob {
    pub src: PathBytes,
    pub dst: PathBytes,
    pub rel: String,
    pub entry: Entry,
    pub dst_entry: Option<Entry>,
    pub attempts: u32,
    /// Bytes of this file in place on the destination (transferred or matched).
    pub done: Arc<AtomicU64>,
    /// Written directly to the final path (no partial + rename).
    pub inplace: bool,
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
    Exit,
}

struct Inner {
    files: BinaryHeap<(u64, Reverse<usize>)>,
    ranges: Vec<(usize, u64, u64)>,
    inflight: Vec<RangeHandle>,
    outstanding: HashMap<usize, u32>,
    failed: HashSet<usize>,
    probing: usize,
    scan_done: bool,
    abort: bool,
}

pub struct Sched {
    inner: Mutex<Inner>,
    cv: Condvar,
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
                inflight: Vec::new(),
                outstanding: HashMap::new(),
                failed: HashSet::new(),
                probing: 0,
                scan_done: false,
                abort: false,
            }),
            cv: Condvar::new(),
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

    pub fn requeue(&self, idx: usize) {
        let size = self.jobs.lock().unwrap()[idx].entry.size;
        self.inner.lock().unwrap().files.push((size, Reverse(idx)));
        self.cv.notify_one();
    }

    pub fn scan_done(&self) {
        self.inner.lock().unwrap().scan_done = true;
        self.cv.notify_all();
    }

    pub fn abort(&self) {
        self.inner.lock().unwrap().abort = true;
        self.cv.notify_all();
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

    pub fn next(&self) -> Item {
        let mut g = self.inner.lock().unwrap();
        loop {
            if g.abort {
                return Item::Exit;
            }
            if let Some((idx, off, end)) = g.ranges.pop() {
                let h = Arc::new(Mutex::new(RangeState { idx, pos: off, end }));
                g.inflight.push(h.clone());
                return Item::Range(h);
            }
            if let Some((_, Reverse(idx))) = g.files.pop() {
                g.probing += 1;
                return Item::File(idx);
            }
            if let Some(h) = self.steal(&mut g) {
                return Item::Range(h);
            }
            if g.scan_done && g.probing == 0 && g.inflight.is_empty() {
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
            if rem >= 2 * self.min_split && best.map_or(true, |(b, _)| rem > b) {
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
        let h = Arc::new(Mutex::new(RangeState { idx, pos: split, end: old_end }));
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
}

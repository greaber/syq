//! Automatic tuning of the number of parallel workers / connections.
//!
//! When `-j` is not given, syq starts with a modest (or previously learned)
//! count and measures. Progress (bytes, plus a small credit per completed
//! file so small-file transfers count too) is sampled every few seconds; a
//! worker count has been *measured* once the rate has stopped changing. A
//! successful move keeps exploring in the same direction. A failed move
//! returns to the last good count and leaves a measured bound that later
//! probes can refine one integer at a time. Independent per-direction aging
//! and backoff decide when evidence is stale enough to probe again; when both
//! directions are equally informative, upward wins the tie because transfer
//! curves are usually concave or saturating and an extra connection therefore
//! tends to have lower throughput regret than removing a useful one.
//!
//! Candidate workers are connected while the current count remains active.
//! They become active only when the whole candidate set is ready. Surplus
//! workers are retired after a decision instead of retaining every connection
//! ever tried (except that count one retains one ready spare for a cheap 1→2
//! probe). Parking takes effect within one block even in a huge range: the
//! worker hands the rest of its range back to the scheduler.
//!
//! [`Sampler`] turns raw samples into stable measurements and [`Policy`] is
//! the decision state machine; both are pure and unit tested. [`Gate`] is the
//! shared switch the workers consult; [`run`] is the driver.

use crate::conn::{DataTransport, Endpoint};
use crate::sched::Sched;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

/// Workers to start with when auto-tuning over ssh: handshakes can take seconds
/// on a long path, so start modestly and let the tuner earn more.
pub const START_SSH: usize = 8;
/// Workers to start with when every remote endpoint has a TCP data path.
/// TCP data connections are cheap once the ssh control connection is up.
pub const START_TCP: usize = 16;
/// Workers to start with when both ends are local: threads are free, network
/// filesystems like the concurrency, and short bursts never reach the first
/// measurement. If it's too many for a spinning disk the ramp-down finds out.
pub const START_LOCAL: usize = 32;
/// Never auto-tune beyond this many workers.
pub const MAX: usize = 64;
/// Never auto-tune below this many.
pub const MIN: usize = 1;
/// Multiplicative step between worker counts, up or down.
pub const STEP: f64 = 1.3;
/// Prefer the smallest measured count whose throughput is this close to the
/// recent best. Probe scheduling handles noise independently from this
/// objective; acceptance must not impose a stricter, contradictory threshold.
const NEAR_BEST_TOLERANCE: f64 = 0.05;
/// Measurements in the hold phase between probes. Each failed probe in a
/// direction doubles only that direction's wait (up to
/// 2^PROBE_BACKOFF_MAX times), so a sharp knee — a disk that collapses one
/// step up — isn't paid for every few measurements forever.
const PROBE_EVERY: usize = 6;
const PROBE_BACKOFF_MAX: u32 = 3;
/// Old high-water measurements must not permanently prevent adaptation when
/// the path changes during a long transfer.
const EVIDENCE_MAX_AGE: usize = PROBE_EVERY * 4;
/// How often progress is sampled.
pub const SAMPLE: Duration = Duration::from_millis(2500);
/// Two consecutive samples this close count as a stable rate.
const STABLE_WITHIN: f64 = 0.10;
/// Give up waiting for stability after this many samples and use what we have.
const MAX_SAMPLES: usize = 8;
/// Don't judge a worker count unless each worker has at least this much left
/// to do: in the tail of a transfer, idle workers say nothing about the path.
const TAIL_BYTES_PER_WORKER: u64 = 64 << 20;
/// A completed file counts as this many bytes, so small-file transfers
/// (where bytes are negligible) still produce a usable signal.
pub const FILE_CREDIT: u64 = 512 * 1024;

#[derive(Debug, Default, Serialize, Deserialize)]
struct TuningCache {
    /// Deliberately only path+transport → last settled count. Volatile facts
    /// such as RTT, loss, workload and filesystem are telemetry, not key
    /// dimensions: a stale count is merely a cheap starting hint.
    paths: BTreeMap<String, usize>,
}

fn endpoint_key(endpoint: &Endpoint) -> String {
    match endpoint {
        Endpoint::Local => "local".into(),
        Endpoint::Remote(spec) => spec.label(),
    }
}

fn transport_key(endpoint: &Endpoint) -> Option<&'static str> {
    match endpoint {
        Endpoint::Local => None,
        Endpoint::Remote(spec) => Some(match spec.data_transport() {
            DataTransport::Ssh => "ssh",
            DataTransport::EncryptedTcp | DataTransport::PlaintextTcp => "tcp",
        }),
    }
}

/// Stable identity for the directional data path. TCP and ssh results never
/// seed one another. Local-only work is intentionally not persisted: its best
/// count is primarily a property of whichever filesystems happen to be used.
pub fn path_key(src: &Endpoint, dst: &Endpoint) -> Option<String> {
    if !src.is_remote() && !dst.is_remote() {
        return None;
    }
    let transport = [transport_key(src), transport_key(dst)]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join("+");
    Some(format!(
        "v1|{}>{}|{transport}",
        endpoint_key(src),
        endpoint_key(dst)
    ))
}

fn cache_path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("SYQ_TUNING_CACHE") {
        return (!path.is_empty()).then(|| PathBuf::from(path));
    }
    std::env::var_os("XDG_CACHE_HOME")
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .filter(|path| !path.is_empty())
                .map(|home| PathBuf::from(home).join(".cache"))
        })
        .map(|root| root.join("syq/tuning-v1.json"))
}

fn lock_file(path: &Path, exclusive: bool) -> std::io::Result<std::fs::File> {
    let lock_path = path.with_extension("json.lock");
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(lock_path)?;
    let operation = if exclusive {
        libc::LOCK_EX
    } else {
        libc::LOCK_SH
    };
    if unsafe { libc::flock(lock.as_raw_fd(), operation) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(lock)
}

fn read_cache(path: &Path) -> TuningCache {
    std::fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn cached_at(path: &Path, key: &str) -> Option<usize> {
    let _lock = lock_file(path, false).ok()?;
    read_cache(path)
        .paths
        .get(key)
        .copied()
        .map(|n| n.clamp(MIN, MAX))
}

fn remember_at(path: &Path, key: &str, connections: usize) -> std::io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let _lock = lock_file(path, true)?;
    let mut cache = read_cache(path);
    cache
        .paths
        .insert(key.to_string(), connections.clamp(MIN, MAX));
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("tuning"),
        std::process::id()
    ));
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)?;
    file.write_all(&serde_json::to_vec_pretty(&cache)?)?;
    file.sync_all()?;
    std::fs::rename(temporary, path)?;
    Ok(())
}

pub fn cached(key: &str) -> Option<usize> {
    cached_at(&cache_path()?, key)
}

pub fn remember(key: &str, connections: usize) {
    let Some(path) = cache_path() else {
        return;
    };
    if let Err(error) = remember_at(&path, key, connections) {
        if crate::transfer::debug() {
            eprintln!("syq: tuning cache {}: {error}", path.display());
        }
    }
}

/// Next count up / down by `factor`, always moving by at least one.
pub fn step_up_by(n: usize, factor: f64) -> usize {
    ((n as f64 * factor).round() as usize).max(n + 1)
}
pub fn step_up(n: usize) -> usize {
    step_up_by(n, STEP)
}
pub fn step_down(n: usize) -> usize {
    ((n as f64 / STEP).round() as usize).min(n.saturating_sub(1))
}

/// Turns per-sample rates into one score per *stable* stretch: the first
/// sample after a change is discarded (connections coming up, congestion
/// control adapting), then samples are collected until two in a row agree
/// within STABLE_WITHIN, or MAX_SAMPLES have passed. The score is the mean
/// of the last two samples.
#[derive(Debug, Default)]
pub struct Sampler {
    samples: Vec<f64>,
    discard: bool,
}

impl Sampler {
    /// The worker count just changed: start over, ignoring the next sample.
    pub fn reset(&mut self) {
        self.samples.clear();
        self.discard = true;
    }

    /// Feed one sample; returns a score once the rate is stable.
    pub fn push(&mut self, rate: f64) -> Option<f64> {
        if self.discard {
            self.discard = false;
            return None;
        }
        self.samples.push(rate);
        let n = self.samples.len();
        if n < 2 {
            return None;
        }
        let (a, b) = (self.samples[n - 2], self.samples[n - 1]);
        let stable = (a - b).abs() <= STABLE_WITHIN * a.max(b) || (a == 0.0 && b == 0.0);
        if stable || n >= MAX_SAMPLES {
            self.samples.clear();
            Some(0.5 * (a + b))
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    Down,
    Up,
}

impl Direction {
    fn index(self) -> usize {
        match self {
            Direction::Down => 0,
            Direction::Up => 1,
        }
    }

    fn opposite(self) -> Self {
        match self {
            Direction::Down => Direction::Up,
            Direction::Up => Direction::Down,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum State {
    /// Waiting for the starting count's first useful measurement.
    Initial,
    /// Measuring `n` against the last accepted count and its frozen score.
    Explore {
        from: usize,
        base: f64,
        direction: Direction,
    },
    /// The last decision is settled; wait until evidence in either direction
    /// is old enough to be worth another probe.
    Hold,
}

#[derive(Debug, Clone, Copy)]
struct Point {
    score: f64,
    measured_at: usize,
}

/// Pure decision logic. Feed it one stable score per worker count; it
/// returns the number of workers that should be active from now on.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Candidate count. It can be ahead of `active` while workers warm.
    pub n: usize,
    pub min: usize,
    pub max: usize,
    /// Highest count that was actually activated, not merely requested.
    pub peak: usize,
    active: usize,
    state: State,
    points: BTreeMap<usize, Point>,
    /// Consecutive failed probes up / down.
    fails: [u32; 2],
    /// Stable-measurement number when each direction may next be probed.
    due: [usize; 2],
    tick: usize,
    comparisons: usize,
    /// Counts actually activated, for --stats / debug.
    pub history: Vec<usize>,
}

impl Policy {
    pub fn new(start: usize, min: usize, max: usize) -> Self {
        let n = start.clamp(min, max);
        Policy {
            n,
            min,
            max,
            peak: n,
            active: n,
            state: State::Initial,
            points: BTreeMap::new(),
            fails: [0, 0],
            due: [PROBE_EVERY, PROBE_EVERY],
            tick: 0,
            comparisons: 0,
            history: vec![n],
        }
    }

    /// The count the policy considers right: `n`, unless a probe is in
    /// progress, in which case the count it will return to if the probe fails.
    pub fn settled(&self) -> usize {
        match self.state {
            State::Explore { from, .. } => from,
            _ => self.n,
        }
    }

    /// Record that the candidate count has become active. Warming a candidate
    /// does not inflate the peak or the decision history.
    pub fn activated(&mut self) {
        if self.active == self.n {
            return;
        }
        self.active = self.n;
        self.peak = self.peak.max(self.n);
        self.history.push(self.n);
    }

    pub fn active(&self) -> usize {
        self.active
    }

    /// True only after at least two worker counts were genuinely measured.
    /// This is the minimum evidence worth persisting as a future start hint.
    pub fn measured(&self) -> bool {
        self.comparisons > 0
    }

    fn probe_base(&self) -> Option<f64> {
        match self.state {
            State::Explore { base, .. } => Some(base),
            _ => None,
        }
    }

    /// Cancel a candidate that has not yet been activated (normally because
    /// the transfer entered its tail before enough workers finished warming).
    pub fn cancel_unapplied(&mut self) {
        if self.active == self.n {
            return;
        }
        if let State::Explore {
            from, direction, ..
        } = self.state
        {
            self.n = from;
            self.state = State::Hold;
            // Provisioning is not throughput evidence, but retrying the same
            // unavailable candidate on the very next measurement is wasteful.
            self.due[direction.index()] = self.tick + PROBE_EVERY;
        }
    }

    /// Change the candidate count (clamped). Returns true if it changed.
    fn set_candidate(&mut self, n: usize) -> bool {
        let n = n.clamp(self.min, self.max);
        if n == self.n {
            return false;
        }
        self.n = n;
        true
    }

    fn retry_after(&self, direction: Direction) -> usize {
        let backoff = self.fails[direction.index()].min(PROBE_BACKOFF_MAX);
        PROBE_EVERY << backoff
    }

    fn record(&mut self, n: usize, score: f64) {
        self.points
            .entry(n)
            .and_modify(|point| {
                point.score = 0.5 * point.score + 0.5 * score;
                point.measured_at = self.tick;
            })
            .or_insert(Point {
                score,
                measured_at: self.tick,
            });
    }

    /// Pick an unmeasured integer inside the nearest bound before taking
    /// another geometric step. This is what turns measurements at 10 and 13
    /// into a later probe at 11 rather than needlessly re-testing 10.
    fn target(&self, direction: Direction) -> usize {
        match direction {
            Direction::Down => {
                if self.n <= self.min {
                    return self.n;
                }
                if let Some((&lower, point)) = self.points.range(self.min..self.n).next_back() {
                    if self.n - lower > 1 {
                        return lower + (self.n - lower) / 2;
                    }
                    if self.tick.saturating_sub(point.measured_at) <= EVIDENCE_MAX_AGE
                        && point.score < self.recent_best() * (1.0 - NEAR_BEST_TOLERANCE)
                    {
                        return self.n;
                    }
                    return lower;
                }
                step_down(self.n).max(self.min)
            }
            Direction::Up => {
                if self.n >= self.max {
                    return self.n;
                }
                if let Some((&upper, point)) = self
                    .points
                    .range((
                        std::ops::Bound::Excluded(self.n),
                        std::ops::Bound::Included(self.max),
                    ))
                    .next()
                {
                    if upper - self.n > 1 {
                        return self.n + (upper - self.n).div_ceil(2);
                    }
                    let current = self.points.get(&self.n).map_or(0.0, |point| point.score);
                    let best = self.recent_best().max(point.score);
                    if self.tick.saturating_sub(point.measured_at) <= EVIDENCE_MAX_AGE
                        && current >= best * (1.0 - NEAR_BEST_TOLERANCE)
                    {
                        return self.n;
                    }
                    return upper;
                }
                step_up(self.n).min(self.max)
            }
        }
    }

    fn begin(&mut self, direction: Direction, base: f64) -> bool {
        let from = self.n;
        let target = self.target(direction);
        if !self.set_candidate(target) {
            self.due[direction.index()] = if (direction == Direction::Down && self.n == self.min)
                || (direction == Direction::Up && self.n == self.max)
            {
                usize::MAX
            } else {
                self.tick + self.retry_after(direction)
            };
            return false;
        }
        self.state = State::Explore {
            from,
            base,
            direction,
        };
        true
    }

    fn begin_due_probe(&mut self, base: f64) {
        let down = self.due[Direction::Down.index()] <= self.tick && self.n > self.min;
        let up = self.due[Direction::Up.index()] <= self.tick && self.n < self.max;
        // Up is the deterministic tie-break. It is a prior, not an invariant:
        // a failed upward probe backs off independently, allowing down to win.
        let direction = match (down, up) {
            (_, true) => Some(Direction::Up),
            (true, false) => Some(Direction::Down),
            (false, false) => None,
        };
        if let Some(direction) = direction {
            self.begin(direction, base);
        }
    }

    fn recent_best(&self) -> f64 {
        self.points
            .values()
            .filter(|point| self.tick.saturating_sub(point.measured_at) <= EVIDENCE_MAX_AGE)
            .map(|point| point.score)
            .fold(0.0, f64::max)
    }

    /// One stable measurement of the current count. Returns the worker count
    /// to prepare or apply next (`self.n` when nothing changes).
    pub fn observe(&mut self, score: f64) -> usize {
        debug_assert_eq!(
            self.active, self.n,
            "candidate must be active before measuring"
        );
        self.tick += 1;
        self.record(self.n, score);
        match self.state {
            State::Initial => {
                if score > 0.0 {
                    // A first 1.3× upward step discovers paths that can use
                    // more workers without greedily opening twice the start.
                    if !self.begin(Direction::Up, score) {
                        self.begin(Direction::Down, score);
                    }
                }
            }
            State::Hold => self.begin_due_probe(score),
            State::Explore {
                from,
                base,
                direction,
            } => {
                if base <= 0.0 && score <= 0.0 {
                    return self.n;
                }
                let best = self.recent_best();
                let floor = best * (1.0 - NEAR_BEST_TOLERANCE);
                let keep = match direction {
                    // Keep the larger count only when it is near-best and the
                    // smaller baseline is not. If both qualify, the objective
                    // explicitly prefers the smaller one.
                    Direction::Up => {
                        let from_score = self.points.get(&from).map_or(base, |point| point.score);
                        score >= floor && from_score < floor
                    }
                    Direction::Down => score >= floor,
                };
                self.comparisons += 1;
                let idx = direction.index();
                let inverse = direction.opposite().index();
                if keep {
                    self.fails[idx] = 0;
                    self.due[inverse] = self.due[inverse].max(self.tick + PROBE_EVERY);
                    self.state = State::Hold;
                    // Success is direct evidence that there may be more gain
                    // in the same direction, so continue immediately.
                    self.begin(direction, score);
                } else {
                    self.fails[idx] += 1;
                    self.due[idx] = self.tick + self.retry_after(direction);
                    // Do not mechanically bounce to the opposite side after
                    // a failed probe. Let current throughput settle first.
                    self.due[inverse] = self.due[inverse].max(self.tick + PROBE_EVERY);
                    self.set_candidate(from);
                    self.state = State::Hold;
                }
            }
        }
        self.n
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlotPhase {
    Absent,
    Warming,
    Ready,
    Failed,
}

#[derive(Debug, Clone)]
struct Slot {
    phase: SlotPhase,
}

impl Default for Slot {
    fn default() -> Self {
        Self {
            phase: SlotPhase::Absent,
        }
    }
}

/// The worker lifecycle shared by the tuner and workers. `active` controls who
/// may take work; `retain` controls who keeps a connection while parked. Slot
/// state distinguishes a genuinely ready connection from one still warming or
/// one whose setup failed.
pub struct Gate {
    active: AtomicUsize,
    retain: AtomicUsize,
    slots: Mutex<Vec<Slot>>,
    cv: Condvar,
}

impl Gate {
    pub fn new(active: usize) -> Arc<Self> {
        Arc::new(Gate {
            active: AtomicUsize::new(active),
            retain: AtomicUsize::new(active),
            slots: Mutex::new(Vec::new()),
            cv: Condvar::new(),
        })
    }

    pub fn allowed(&self, id: usize) -> bool {
        id < self.active.load(Relaxed)
    }

    pub fn active(&self) -> usize {
        self.active.load(Relaxed)
    }

    pub fn set_active(&self, n: usize) {
        let _g = self.slots.lock().unwrap();
        self.active.store(n, Relaxed);
        self.retain.fetch_max(n, Relaxed);
        self.cv.notify_all();
    }

    pub fn set_retain(&self, n: usize) {
        let _g = self.slots.lock().unwrap();
        self.retain.store(n.max(self.active()), Relaxed);
        self.cv.notify_all();
    }

    /// Claim absent slots through `n` for connection setup.
    pub fn begin_warming(&self, n: usize) -> Vec<usize> {
        let mut slots = self.slots.lock().unwrap();
        slots.resize_with(n, Slot::default);
        let mut ids = Vec::new();
        for (id, slot) in slots.iter_mut().take(n).enumerate() {
            if slot.phase == SlotPhase::Absent {
                slot.phase = SlotPhase::Warming;
                ids.push(id);
            }
        }
        ids
    }

    pub fn mark_ready(&self, id: usize) {
        let mut slots = self.slots.lock().unwrap();
        slots.resize_with(id + 1, Slot::default);
        slots[id].phase = SlotPhase::Ready;
        self.cv.notify_all();
    }

    pub fn mark_warming(&self, id: usize) {
        let mut slots = self.slots.lock().unwrap();
        slots.resize_with(id + 1, Slot::default);
        slots[id].phase = SlotPhase::Warming;
        self.cv.notify_all();
    }

    /// Mark a cleanly retired worker reusable immediately.
    pub fn mark_absent(&self, id: usize) {
        let mut slots = self.slots.lock().unwrap();
        slots.resize_with(id + 1, Slot::default);
        slots[id] = Slot::default();
        self.cv.notify_all();
    }

    /// Mark setup or repeated connection loss after bounded retries.
    pub fn mark_failed(&self, id: usize) {
        let mut slots = self.slots.lock().unwrap();
        slots.resize_with(id + 1, Slot::default);
        slots[id].phase = SlotPhase::Failed;
        self.cv.notify_all();
    }

    pub fn retained(&self, id: usize) -> bool {
        id < self.retain.load(Relaxed)
    }

    pub fn ready_through(&self, n: usize) -> bool {
        let slots = self.slots.lock().unwrap();
        slots.len() >= n
            && slots
                .iter()
                .take(n)
                .all(|slot| slot.phase == SlotPhase::Ready)
    }

    pub fn permanent_failure_through(&self, n: usize) -> bool {
        self.slots
            .lock()
            .unwrap()
            .iter()
            .take(n)
            .any(|slot| slot.phase == SlotPhase::Failed)
    }

    pub fn clear_failed_from(&self, first: usize) {
        let mut slots = self.slots.lock().unwrap();
        for slot in slots.iter_mut().skip(first) {
            if slot.phase == SlotPhase::Failed {
                *slot = Slot::default();
            }
        }
    }

    /// Block until `id` is allowed again. Returns false if the transfer is
    /// over or this surplus connection should be retired.
    pub fn park(&self, id: usize, done: impl Fn() -> bool) -> bool {
        let mut slots = self.slots.lock().unwrap();
        loop {
            if self.allowed(id) {
                return true;
            }
            if done() || id >= self.retain.load(Relaxed) {
                return false;
            }
            slots = self
                .cv
                .wait_timeout(slots, Duration::from_millis(250))
                .unwrap()
                .0;
        }
    }
}

/// Progress counters the tuner scores.
pub trait Meter: Send + Sync {
    fn bytes(&self) -> u64;
    fn files(&self) -> u64;
    fn set_active(&self, n: usize);
}

fn activity_rate(last: (u64, u64), now: (u64, u64), seconds: f64) -> Option<f64> {
    let bytes = now.0.checked_sub(last.0)?;
    let files = now.1.checked_sub(last.1)?;
    Some((bytes as f64 + files as f64 * FILE_CREDIT as f64) / seconds)
}

/// Drive the policy: sample progress, hand stable scores to the policy,
/// apply its decisions to the gate and spawn workers that don't exist yet.
/// Returns the final policy (for stats).
pub fn run(
    policy: Policy,
    gate: Arc<Gate>,
    sched: Arc<Sched>,
    meter: Arc<dyn Meter>,
    mut spawn: impl FnMut(usize),
) -> Policy {
    let mut policy = policy;
    let mut sampler = Sampler::default();
    sampler.reset();
    let mut last = (meter.bytes(), meter.files());
    let mut sample_start = std::time::Instant::now();
    let mut active = policy.active();
    let mut collapse_samples = 0;
    meter.set_active(policy.n);
    loop {
        std::thread::sleep(Duration::from_millis(250));
        if sched.is_aborted() || sched.finished() {
            break;
        }

        // Apply reductions immediately. An increase leaves the current set
        // active while its candidate workers connect in the background.
        if policy.n < active {
            let before = active;
            gate.set_active(policy.n);
            active = policy.n;
            policy.activated();
            meter.set_active(active);
            gate.set_retain(if active == 1 { 2 } else { active });
            sampler.reset();
            collapse_samples = 0;
            last = (meter.bytes(), meter.files());
            sample_start = std::time::Instant::now();
            if crate::transfer::debug() {
                eprintln!(
                    "syq: tune: {before} -> {active} workers (state {:?})",
                    policy.state
                );
            }
            continue;
        }
        if policy.n > active {
            if !sched.work_left_for(policy.n, TAIL_BYTES_PER_WORKER) {
                policy.cancel_unapplied();
                gate.set_retain(if active == 1 { 2 } else { active });
                continue;
            }
            gate.set_retain(policy.n);
            for id in gate.begin_warming(policy.n) {
                spawn(id);
            }
            if gate.permanent_failure_through(policy.n) {
                if gate.permanent_failure_through(active) {
                    sched.abort();
                    break;
                }
                // Failure to provision an optional upward probe is not a
                // throughput result and must not fail the copy.
                policy.cancel_unapplied();
                gate.set_retain(if active == 1 { 2 } else { active });
                gate.clear_failed_from(active);
                continue;
            }
            if gate.ready_through(policy.n) {
                let before = active;
                gate.set_active(policy.n);
                active = policy.n;
                policy.activated();
                meter.set_active(active);
                sampler.reset();
                collapse_samples = 0;
                last = (meter.bytes(), meter.files());
                sample_start = std::time::Instant::now();
                if crate::transfer::debug() {
                    eprintln!(
                        "syq: tune: {before} -> {active} workers (candidate ready, state {:?})",
                        policy.state
                    );
                }
            }
            // Provisioning time is not a throughput measurement.
            continue;
        }

        // Heal an unexpectedly missing active slot. At one active worker keep
        // exactly one ready spare so the important 1→2 probe is instantaneous.
        let retain = if active == 1 { 2 } else { active };
        gate.set_retain(retain);
        for id in gate.begin_warming(retain) {
            spawn(id);
        }
        if gate.permanent_failure_through(active) {
            sched.abort();
            break;
        }
        if sample_start.elapsed() < SAMPLE {
            continue;
        }
        let now = (meter.bytes(), meter.files());
        let secs = sample_start.elapsed().as_secs_f64();
        sample_start = std::time::Instant::now();
        // Only judge a configuration once every requested worker is actually
        // connected (ssh sessions can take seconds each), and only while there
        // is enough work left — in the tail, idle workers say nothing.
        if !gate.ready_through(active) || !sched.work_left_for(active, TAIL_BYTES_PER_WORKER) {
            last = now;
            sampler.reset();
            continue;
        }
        // Per second, so jitter in the sample length doesn't masquerade as a
        // throughput change.
        let Some(rate) = activity_rate(last, now, secs) else {
            // Progress can be retracted after uncertain acknowledgements. The
            // production meter is monotonic, but keep the generic driver safe
            // and discard any interval from a regressing implementation.
            last = now;
            sampler.reset();
            collapse_samples = 0;
            continue;
        };
        last = now;
        if policy
            .probe_base()
            .is_some_and(|base| base > 0.0 && rate < 0.5 * base)
        {
            collapse_samples += 1;
        } else {
            collapse_samples = 0;
        }
        if collapse_samples >= 2 {
            policy.observe(rate);
            sampler.reset();
            collapse_samples = 0;
            continue;
        }
        let Some(score) = sampler.push(rate) else {
            continue;
        };
        let before = policy.n;
        policy.observe(score);
        if policy.n != before {
            sampler.reset();
            if crate::transfer::debug() {
                eprintln!(
                    "syq: tune: candidate {before} -> {} workers (measured {:.1} MB/s at {before}, state {:?})",
                    policy.n,
                    score / 1e6,
                    policy.state
                );
            }
        }
    }
    policy
}

#[cfg(test)]
mod tests {
    use super::*;

    fn remote(host: &str, tcp: bool) -> Endpoint {
        Endpoint::Remote(crate::conn::RemoteSpec {
            user: Some("user".into()),
            host: host.into(),
            rsh: vec!["ssh".into()],
            syq_path: None,
            auto_helper: false,
            helper_install: Default::default(),
            quiet: true,
            tcp: std::sync::Arc::new(std::sync::Mutex::new(tcp.then(|| crate::conn::TcpInfo {
                addrs: vec!["127.0.0.1".into()],
                port: 1,
                key: Some(vec![0; 32]),
                token: vec![],
                failed: false,
                failure: None,
                next: Default::default(),
            }))),
            diagnostics: Default::default(),
        })
    }

    fn temporary_cache(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "syq-tune-test-{}-{name}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn measure(p: &mut Policy, score: f64) {
        p.observe(score);
        p.activated();
    }

    /// Feed the policy a model where throughput rises linearly with workers
    /// up to `cap` workers and is flat after.
    fn simulate(start: usize, cap: usize, rounds: usize, noise: impl Fn(usize) -> f64) -> Policy {
        let mut p = Policy::new(start, MIN, MAX);
        for i in 0..rounds {
            let eff = p.n.min(cap) as f64;
            measure(&mut p, eff * 10e6 * noise(i));
        }
        p
    }

    #[test]
    fn steps_are_geometric_and_move() {
        assert_eq!(step_up(8), 10);
        assert_eq!(step_up(2), 3);
        assert_eq!(step_down(8), 6);
        assert_eq!(step_down(2), 1);
        let mut n = START_SSH;
        let mut steps = 0;
        while n < MAX {
            n = step_up(n);
            steps += 1;
        }
        assert!((7..=9).contains(&steps), "{steps} steps");
    }

    #[test]
    fn first_probe_is_modest_instead_of_doubling() {
        let mut p = Policy::new(START_SSH, MIN, MAX);
        measure(&mut p, 80.0);
        assert_eq!(p.n, 10);
        assert_eq!(p.history, vec![8, 10]);
    }

    #[test]
    fn upward_acceptance_uses_the_near_best_objective() {
        let mut worthwhile = Policy::new(10, MIN, MAX);
        measure(&mut worthwhile, 100.0);
        measure(&mut worthwhile, 107.0);
        assert_eq!(worthwhile.settled(), 13);

        let mut unnecessary = Policy::new(10, MIN, MAX);
        measure(&mut unnecessary, 100.0);
        measure(&mut unnecessary, 104.0);
        assert_eq!(unnecessary.settled(), 10);
    }

    #[test]
    fn activity_rate_discards_a_regressing_sample() {
        assert_eq!(activity_rate((100, 2), (90, 3), 1.0), None);
        assert_eq!(activity_rate((100, 2), (110, 1), 1.0), None);
        assert_eq!(
            activity_rate((100, 2), (110, 3), 2.0),
            Some((10.0 + FILE_CREDIT as f64) / 2.0)
        );
    }

    #[test]
    fn successful_direction_continues_to_the_plateau() {
        let p = simulate(START_SSH, 32, 80, |_| 1.0);
        assert_eq!(&p.history[..6], &[8, 10, 13, 17, 22, 29]);
        // 31 is the smallest integer within 5% of the observed best (32).
        assert_eq!(p.settled(), 31, "history {:?}", p.history);
    }

    #[test]
    fn a_gain_at_the_cap_holds_at_the_cap() {
        let p = simulate(START_LOCAL, 200, 40, |_| 1.0);
        // Once the cap establishes the best score, downward refinement finds
        // the smallest integer within the 5% near-best tolerance.
        assert_eq!(p.settled(), 61, "history {:?}", p.history);
        assert_eq!(p.peak, MAX);
    }

    #[test]
    fn a_failed_up_probe_does_not_immediately_bounce_down() {
        let mut p = Policy::new(10, MIN, MAX);
        measure(&mut p, 100.0); // 10 -> 13
        measure(&mut p, 130.0); // 13 paid; try 17
        measure(&mut p, 130.0); // 17 did not; return to 13
        assert_eq!(p.n, 13);
        for _ in 0..PROBE_EVERY - 1 {
            measure(&mut p, 130.0);
            assert_eq!(p.n, 13, "history {:?}", p.history);
        }
        measure(&mut p, 130.0);
        // The later down probe refines the measured 10..13 bracket.
        assert_eq!(p.n, 11, "history {:?}", p.history);
    }

    #[test]
    fn refines_to_the_smallest_near_best_integer() {
        let mut p = Policy::new(10, MIN, MAX);
        measure(&mut p, 100.0);
        measure(&mut p, 130.0);
        measure(&mut p, 130.0);
        for _ in 0..PROBE_EVERY {
            measure(&mut p, 130.0);
        }
        assert_eq!(p.n, 11);
        measure(&mut p, 129.0);
        // 10 is a fresh lower bound and was materially slower; do not retest
        // it immediately just because the probe at 11 succeeded.
        assert_eq!(p.settled(), 11);
        assert_eq!(p.n, 11);
    }

    #[test]
    fn descends_all_the_way_to_one_when_one_saturates_the_link() {
        let p = simulate(START_SSH, 1, 80, |_| 1.0);
        assert_eq!(p.settled(), 1, "history {:?}", p.history);
    }

    #[test]
    fn backs_off_when_more_workers_hurt() {
        let score = |n: usize| {
            if n <= 8 {
                n as f64 * 12.5e6
            } else {
                30e6
            }
        };
        let mut p = Policy::new(START_SSH, MIN, MAX);
        for _ in 0..80 {
            let n = p.n;
            measure(&mut p, score(n));
        }
        assert_eq!(p.settled(), 8, "history {:?}", p.history);
        assert!(p.history.len() < 20, "history {:?}", p.history);
    }

    #[test]
    fn ignores_noise_within_tolerance() {
        let p = simulate(START_SSH, 32, 60, |i| if i % 2 == 0 { 1.0 } else { 0.93 });
        assert!((20..=42).contains(&p.settled()), "history {:?}", p.history);
    }

    #[test]
    fn silence_is_not_a_signal() {
        let mut p = Policy::new(START_SSH, MIN, MAX);
        for _ in 0..10 {
            measure(&mut p, 0.0);
        }
        assert_eq!(p.history, vec![START_SSH]);
    }

    #[test]
    fn a_short_run_has_no_cacheable_comparison() {
        let mut p = Policy::new(START_SSH, MIN, MAX);
        measure(&mut p, 80.0);
        assert!(!p.measured());
        measure(&mut p, 80.0);
        assert!(p.measured());
    }

    #[test]
    fn cache_remembers_only_the_named_path_and_clamps_values() {
        let dir = temporary_cache("roundtrip");
        let path = dir.join("tuning.json");
        remember_at(&path, "a>b|tcp", 13).unwrap();
        remember_at(&path, "a>b|ssh", MAX + 100).unwrap();
        assert_eq!(cached_at(&path, "a>b|tcp"), Some(13));
        assert_eq!(cached_at(&path, "a>b|ssh"), Some(MAX));
        assert_eq!(cached_at(&path, "b>a|tcp"), None);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn cache_key_separates_direction_and_transport() {
        let local = Endpoint::Local;
        let ssh = remote("host", false);
        let tcp = remote("host", true);
        assert_ne!(path_key(&local, &ssh), path_key(&ssh, &local));
        assert_ne!(path_key(&local, &ssh), path_key(&local, &tcp));
        assert_eq!(path_key(&local, &local), None);
    }

    #[test]
    fn tcp_fallback_changes_the_cache_key() {
        let local = Endpoint::Local;
        let remote = remote("host", true);
        let initial = path_key(&local, &remote);
        let Endpoint::Remote(spec) = &remote else {
            unreachable!()
        };
        spec.tcp.lock().unwrap().as_mut().unwrap().failed = true;
        assert_ne!(path_key(&local, &remote), initial);
    }

    #[test]
    fn corrupt_cache_is_ignored_and_replaced() {
        let dir = temporary_cache("corrupt");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("tuning.json");
        std::fs::write(&path, b"not json").unwrap();
        assert_eq!(cached_at(&path, "a>b|tcp"), None);
        remember_at(&path, "a>b|tcp", 7).unwrap();
        assert_eq!(cached_at(&path, "a>b|tcp"), Some(7));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn sampler_waits_for_a_stable_rate() {
        let mut s = Sampler::default();
        s.reset();
        assert_eq!(
            s.push(50.0),
            None,
            "first sample after a change is discarded"
        );
        // A burst that gets throttled: 100, 60, 40, 39 -> stable at ~40.
        assert_eq!(s.push(100.0), None);
        assert_eq!(s.push(60.0), None);
        assert_eq!(s.push(40.0), None);
        assert_eq!(s.push(39.0), Some(39.5));
        // A link that ramps up: 10, 20, 30, 31 -> stable at ~30.
        assert_eq!(s.push(10.0), None);
        assert_eq!(s.push(20.0), None);
        assert_eq!(s.push(30.0), None);
        assert_eq!(s.push(31.0), Some(30.5));
    }

    #[test]
    fn sampler_gives_up_eventually() {
        let mut s = Sampler::default();
        let mut out = None;
        for i in 0..MAX_SAMPLES {
            out = s.push(100.0 * (i as f64 + 1.0)); // never stable
        }
        assert!(out.is_some(), "no score after {MAX_SAMPLES} samples");
    }

    #[test]
    fn gate_parks_and_releases() {
        let g = Gate::new(2);
        assert!(g.allowed(1));
        assert!(!g.allowed(2));
        g.set_retain(3);
        let g2 = g.clone();
        let t = std::thread::spawn(move || g2.park(2, || false));
        std::thread::sleep(Duration::from_millis(50));
        g.set_active(3);
        assert!(t.join().unwrap());
        let g3 = g.clone();
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let d = done.clone();
        let t = std::thread::spawn(move || g3.park(5, || d.load(Relaxed)));
        done.store(true, Relaxed);
        assert!(!t.join().unwrap());
    }

    #[test]
    fn gate_distinguishes_warming_ready_active_and_retired() {
        let gate = Gate::new(2);
        assert_eq!(gate.begin_warming(2), vec![0, 1]);
        assert!(!gate.ready_through(2));
        gate.mark_ready(0);
        assert!(!gate.ready_through(2));
        gate.mark_ready(1);
        assert!(gate.ready_through(2));

        gate.set_active(1);
        gate.set_retain(1);
        assert!(gate.allowed(0));
        assert!(!gate.allowed(1));
        assert!(!gate.park(1, || false), "surplus slot should retire");
        gate.mark_absent(1);
        assert_eq!(gate.begin_warming(2), vec![1]);
    }

    #[test]
    fn optional_provisioning_failure_does_not_poison_active_slots() {
        let gate = Gate::new(2);
        assert_eq!(gate.begin_warming(3), vec![0, 1, 2]);
        gate.mark_ready(0);
        gate.mark_ready(1);
        gate.mark_failed(2);
        assert!(!gate.permanent_failure_through(2));
        assert!(gate.permanent_failure_through(3));

        gate.clear_failed_from(2);
        assert_eq!(gate.begin_warming(3), vec![2]);
        assert!(gate.ready_through(2));
    }
}

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
/// Workers to start with when both ends are local and the process has more
/// than two CPUs available. Network filesystems like the concurrency, and
/// short bursts never reach the first measurement.
pub const START_LOCAL: usize = 32;
/// A gentle reduction for CPU-constrained machines. Sixteen still leaves
/// enough I/O concurrency for high-latency filesystems while avoiding half of
/// the speculative worker setup on one- and two-CPU systems.
pub const START_LOCAL_LOW_CPU: usize = 16;
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
/// Settled sampling interval. Initial experiments use a shorter interval,
/// growing toward this one as their direction backs off.
pub const SAMPLE: Duration = Duration::from_millis(2500);
/// One discarded warm-up interval plus the two samples needed for stability.
const MEASUREMENT_SAMPLES: f64 = 3.0;
/// Two consecutive samples this close count as a stable rate.
const STABLE_WITHIN: f64 = 0.10;
/// Conservative requirement before the first rate sample. Every real probe is
/// based on a measured duration estimate; this is only a startup fallback.
const TAIL_FALLBACK_BYTES_PER_WORKER: u64 = 64 << 20;
/// A completed file counts as this many bytes, so small-file transfers
/// (where bytes are negligible) still produce a usable signal.
pub const FILE_CREDIT: u64 = 512 * 1024;

fn local_start_for_parallelism(parallelism: usize) -> usize {
    if parallelism <= 2 {
        START_LOCAL_LOW_CPU
    } else {
        START_LOCAL
    }
}

/// Initial local worker count, respecting CPU affinity and container limits
/// exposed by `available_parallelism`. If the platform cannot report a limit,
/// retain the established local default.
pub fn start_local() -> usize {
    std::thread::available_parallelism()
        .map(|parallelism| local_start_for_parallelism(parallelism.get()))
        .unwrap_or(START_LOCAL)
}

fn sample_interval() -> Duration {
    #[cfg(debug_assertions)]
    if let Some(milliseconds) = std::env::var_os("SYQ_TEST_TUNE_SAMPLE_MS")
        .and_then(|value| value.to_string_lossy().parse::<u64>().ok())
        .filter(|value| *value > 0)
    {
        return Duration::from_millis(milliseconds);
    }
    SAMPLE
}

fn required_remaining_activity(rate: Option<f64>, workers: usize, sample: Duration) -> u64 {
    match rate.filter(|rate| rate.is_finite() && *rate >= 0.0) {
        Some(rate) => (rate * sample.as_secs_f64() * MEASUREMENT_SAMPLES)
            .ceil()
            .clamp(0.0, u64::MAX as f64) as u64,
        None => (workers as u64).saturating_mul(TAIL_FALLBACK_BYTES_PER_WORKER),
    }
}

fn enough_work(sched: &Sched, workers: usize, rate: Option<f64>, sample: Duration) -> bool {
    sched.work_left_for(
        workers,
        required_remaining_activity(rate, workers, sample),
        FILE_CREDIT,
    )
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct TuningCache {
    /// Deliberately only path+transport → last settled count. Volatile facts
    /// such as RTT, loss, workload and filesystem are telemetry, not key
    /// dimensions: a stale count is merely a cheap starting hint.
    paths: BTreeMap<String, usize>,
}

fn endpoint_key(endpoint: &Endpoint) -> String {
    match endpoint {
        Endpoint::Local { .. } => "local".into(),
        Endpoint::Remote(spec) if spec.local_process => "local".into(),
        Endpoint::Remote(spec) => spec.label(),
    }
}

fn transport_label(endpoint: &Endpoint) -> Option<&'static str> {
    match endpoint {
        Endpoint::Local { .. } => None,
        Endpoint::Remote(spec) if spec.local_process => None,
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
    let transport = [transport_label(src), transport_label(dst)]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join("+");
    Some(format!(
        "{}>{}|{transport}",
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
        .map(|root| root.join("syq/tuning.json"))
}

fn lock_file(path: &Path, exclusive: bool) -> std::io::Result<std::fs::File> {
    let lock_path = path.with_extension("json.lock");
    use std::os::unix::fs::OpenOptionsExt;
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .mode(0o600)
        .open(lock_path)?;
    if !lock.metadata()?.is_file() {
        return Err(std::io::Error::other(
            "tuning cache lock is not a regular file",
        ));
    }
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
    // The cache is replaced by rename, so a read without the lock still sees
    // a complete file. Not being able to create the lock, as on a read-only
    // home, must not hide a cache that is there.
    let _lock = lock_file(path, false).ok();
    read_cache(path).paths.get(key).copied().map(|n| n.max(MIN))
}

fn remember_at(path: &Path, key: &str, connections: usize) -> std::io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let _lock = lock_file(path, true)?;
    let mut cache = read_cache(path);
    cache.paths.insert(key.to_string(), connections.max(MIN));
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
        if crate::output::debug() {
            crate::output::diagnostic!("syq: tuning cache {}: {error}", path.display());
        }
    }
}

/// Next count up / down by `factor`, always moving by at least one.
pub fn step_up_by(n: usize, factor: f64) -> usize {
    ((n as f64 * factor).round() as usize).max(n.saturating_add(1))
}
pub fn step_up(n: usize) -> usize {
    step_up_by(n, STEP)
}
pub fn step_down(n: usize) -> usize {
    ((n as f64 / STEP).round() as usize).min(n.saturating_sub(1))
}

/// A bounded observation can finish without evidence worth comparing.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Observation {
    Stable(f64),
    Inconclusive,
}

/// Ignore one settling interval, then wait for two similar rates. Never turn
/// an unstable window into a score merely because its time budget expired.
pub(crate) struct Sampler {
    previous: Option<(f64, Duration)>,
    elapsed: Duration,
    limit: Duration,
    discard: bool,
}

impl Sampler {
    pub(crate) fn new(limit: Duration) -> Self {
        Self {
            previous: None,
            elapsed: Duration::ZERO,
            limit,
            discard: true,
        }
    }

    pub(crate) fn reset(&mut self) {
        self.previous = None;
        self.elapsed = Duration::ZERO;
        self.discard = true;
    }

    pub(crate) fn next_interval(&self, preferred: Duration) -> Duration {
        preferred.min(self.limit.saturating_sub(self.elapsed))
    }

    pub(crate) fn push(&mut self, rate: f64, duration: Duration) -> Option<Observation> {
        self.elapsed += duration;
        let previous = self.previous;
        if self.discard {
            self.discard = false;
        } else {
            self.previous = Some((rate, duration));
            if let Some((a, a_duration)) = previous {
                let stable = (a - rate).abs() <= STABLE_WITHIN * a.max(rate);
                if stable {
                    let score = (a * a_duration.as_secs_f64() + rate * duration.as_secs_f64())
                        / (a_duration + duration).as_secs_f64();
                    self.previous = None;
                    self.elapsed = Duration::ZERO;
                    return Some(Observation::Stable(score));
                }
            }
        }
        if self.elapsed >= self.limit {
            self.reset();
            return Some(Observation::Inconclusive);
        }
        None
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
    /// Measuring `n` against the last accepted count and its baseline score.
    /// An upward baseline may refresh while candidate workers are warming.
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

    /// Refresh an upward probe's comparison while its extra workers warm. The
    /// settled count remains active, so this is baseline evidence rather than
    /// a new policy tick or worker-count comparison.
    fn refresh_warming_baseline(&mut self, score: f64) -> bool {
        let from = match &mut self.state {
            State::Explore {
                from,
                base,
                direction: Direction::Up,
            } if *from == self.active => {
                *base = score;
                Some(*from)
            }
            _ => None,
        };
        if let Some(from) = from {
            self.points.insert(
                from,
                Point {
                    score,
                    measured_at: self.tick,
                },
            );
            true
        } else {
            false
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

    /// First experiments take at least three seconds (one discarded interval
    /// and two agreeing rates). A doubled retry wait grows their duration by
    /// sqrt(2), capped at the settled 7.5-second observation window. Keep hold
    /// sampling unchanged so shorter experiments do not accelerate later probes.
    pub(crate) fn observation_interval(&self, settled_interval: Duration) -> Duration {
        let failures = match self.state {
            State::Initial => 0,
            State::Explore { direction, .. } => self.fails[direction.index()],
            State::Hold => return settled_interval,
        };
        let factor = (0.4 * 2.0_f64.powf(failures.min(PROBE_BACKOFF_MAX) as f64 / 2.0)).min(1.0);
        settled_interval.mul_f64(factor)
    }

    /// Abandon an unstable experiment without recording a throughput bound or
    /// making its candidate cacheable. Back off retries just as for an unhelpful
    /// probe, giving the next experiment longer to settle.
    pub(crate) fn inconclusive(&mut self) {
        if let State::Explore {
            from, direction, ..
        } = self.state
        {
            let index = direction.index();
            self.fails[index] = self.fails[index].saturating_add(1);
            self.due[index] = self.tick + self.retry_after(direction);
            let inverse = direction.opposite().index();
            self.due[inverse] = self.due[inverse].max(self.tick + PROBE_EVERY);
            self.n = from;
            self.state = State::Hold;
        }
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
                    Direction::Up => score >= floor && base < floor,
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
                    self.fails[idx] = self.fails[idx].saturating_add(1);
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

/// Extend the slot table so `id`s below `n` exist. Slots are never dropped:
/// `Vec::resize_with` would truncate a longer table, and a worker that marked
/// itself ready after a higher-numbered one would then erase that worker's
/// slot. The tuner would read the erased slots as absent and spawn duplicate
/// workers for ids that are still running.
fn grow_to(slots: &mut Vec<Slot>, n: usize) {
    if slots.len() < n {
        slots.resize_with(n, Slot::default);
    }
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
        grow_to(&mut slots, n);
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
        grow_to(&mut slots, id + 1);
        slots[id].phase = SlotPhase::Ready;
        self.cv.notify_all();
    }

    pub fn mark_warming(&self, id: usize) {
        let mut slots = self.slots.lock().unwrap();
        grow_to(&mut slots, id + 1);
        slots[id].phase = SlotPhase::Warming;
        self.cv.notify_all();
    }

    /// Mark a cleanly retired worker reusable immediately.
    pub fn mark_absent(&self, id: usize) {
        let mut slots = self.slots.lock().unwrap();
        grow_to(&mut slots, id + 1);
        slots[id] = Slot::default();
        self.cv.notify_all();
    }

    /// Mark setup or repeated connection loss after bounded retries.
    pub fn mark_failed(&self, id: usize) {
        let mut slots = self.slots.lock().unwrap();
        grow_to(&mut slots, id + 1);
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
    let sample = sample_interval();
    let mut sampler = Sampler::new(sample.mul_f64(MEASUREMENT_SAMPLES));
    let mut last = (meter.bytes(), meter.files());
    let mut sample_start = std::time::Instant::now();
    let mut active = policy.active();
    let mut collapse_samples = 0;
    let poll = Duration::from_millis(250).min(sample);
    let mut last_rate = None;
    meter.set_active(policy.n);
    loop {
        sched.wait_for_tuning(poll);
        if sched.is_aborted() || sched.finished() {
            break;
        }

        // A same-machine single-file copy starts with one cheap kernel copy
        // probe. If the receiver reports a partial or unsupported kernel
        // offload, skip the measurement ramp and restore the ordinary local
        // starting count before userspace ranges become the bottleneck.
        let requested = sched.take_worker_count_request().min(policy.max);
        if requested > active {
            let before = active;
            policy = Policy::new(requested, policy.min, policy.max);
            active = requested;
            gate.set_retain(requested);
            for id in gate.begin_warming(requested) {
                spawn(id);
            }
            gate.set_active(requested);
            meter.set_active(requested);
            sampler.reset();
            last = (meter.bytes(), meter.files());
            sample_start = std::time::Instant::now();
            if crate::output::debug() {
                crate::output::diagnostic!(
                    "syq: tune: {before} -> {requested} workers (direct copy needs userspace transfer)"
                );
            }
            continue;
        }

        let interval = policy.observation_interval(sample);

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
            if crate::output::debug() {
                crate::output::diagnostic!(
                    "syq: tune: {before} -> {active} workers (state {:?})",
                    policy.state
                );
            }
            continue;
        }
        if policy.n > active {
            if !enough_work(&sched, policy.n, last_rate, interval) {
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
                if crate::output::debug() {
                    crate::output::diagnostic!(
                        "syq: tune: {before} -> {active} workers (candidate ready, state {:?})",
                        policy.state
                    );
                }
                continue;
            }

            // The settled workers keep providing a fresh comparison while an
            // upward candidate connects. This prevents handshake delay from
            // turning unrelated path drift into an apparent candidate effect.
            if sample_start.elapsed() >= sampler.next_interval(interval) {
                let now = (meter.bytes(), meter.files());
                let duration = sample_start.elapsed();
                let secs = duration.as_secs_f64();
                sample_start = std::time::Instant::now();
                if !gate.ready_through(active) {
                    last = now;
                    sampler.reset();
                    continue;
                }
                let Some(rate) = activity_rate(last, now, secs) else {
                    last = now;
                    sampler.reset();
                    continue;
                };
                last = now;
                last_rate = Some(rate);
                if !enough_work(&sched, policy.n, last_rate, interval) {
                    policy.cancel_unapplied();
                    gate.set_retain(if active == 1 { 2 } else { active });
                    sampler.reset();
                    continue;
                }
                if let Some(Observation::Stable(score)) = sampler.push(rate, duration) {
                    policy.refresh_warming_baseline(score);
                    if crate::output::debug() {
                        crate::output::diagnostic!(
                            "syq: tune: refreshed {active}-worker baseline to {:.1} MB/s while {} workers warm",
                            score / 1e6,
                            policy.n
                        );
                    }
                }
            }
            continue;
        }

        // Heal an unexpectedly missing active slot. At one active worker keep
        // exactly one ready spare so the important 1→2 probe is instantaneous.
        let retain = if active == 1 {
            2.min(policy.max)
        } else {
            active
        };
        gate.set_retain(retain);
        // A pipelined whole-file batch is already owned and cannot be stolen.
        // Do not repeatedly reconnect slots that drained the queue while the
        // remaining owners finish. Queued/retried work or an ordinary
        // large-file probe re-enables healing on the next poll.
        if sched.needs_worker_capacity() {
            for id in gate.begin_warming(retain) {
                spawn(id);
            }
        }
        if gate.permanent_failure_through(active) {
            sched.abort();
            break;
        }
        if sample_start.elapsed() < sampler.next_interval(interval) {
            continue;
        }
        let now = (meter.bytes(), meter.files());
        let duration = sample_start.elapsed();
        let secs = duration.as_secs_f64();
        sample_start = std::time::Instant::now();
        // Only judge a configuration once every requested worker is actually
        // connected (ssh sessions can take seconds each).
        if !gate.ready_through(active) {
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
        last_rate = Some(rate);
        // Estimate the time left at the rate just observed. In the tail, idle
        // workers say nothing; unlike a fixed byte threshold this remains
        // useful on both very slow and very fast paths.
        if !enough_work(&sched, active, last_rate, interval) {
            sampler.reset();
            collapse_samples = 0;
            continue;
        }
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
        let Some(observation) = sampler.push(rate, duration) else {
            continue;
        };
        let before = policy.n;
        let score = match observation {
            Observation::Stable(score) => score,
            Observation::Inconclusive => {
                policy.inconclusive();
                if crate::output::debug() {
                    crate::output::diagnostic!(
                        "syq: tune: inconclusive observation at {active} workers; returning to {}",
                        policy.n
                    );
                }
                continue;
            }
        };
        policy.observe(score);
        if policy.n != before {
            sampler.reset();
            if crate::output::debug() {
                crate::output::diagnostic!(
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
mod tests;

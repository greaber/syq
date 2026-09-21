//! Automatic tuning of the number of parallel workers / connections.
//!
//! When `-j` is not given, syq starts with a modest (or previously learned)
//! count and measures. Progress (bytes, plus a small credit per completed
//! file so small-file transfers count too) is sampled every few seconds; a
//! worker count has been *measured* once the rate has stopped changing. A
//! fresh start doubles while upward moves pay, then refines the measured
//! bounds. Strongly matched plateau hints use smaller steps. An inconclusive
//! increase keeps the larger count but pauses growth; a clearly worse move
//! returns to the last good count and leaves a measured bound that later
//! probes can refine one integer at a time. Independent per-direction aging
//! and backoff decide when evidence is stale enough to probe again; when both
//! directions are equally informative, upward wins the tie because transfer
//! curves are usually concave or saturating and an extra connection therefore
//! tends to have lower throughput regret than removing a useful one.
//!
//! Candidate workers are connected while the current count remains active.
//! They become active only when the whole candidate set is ready. Connected
//! workers park when no longer active. The driver prepares likely upward
//! candidates ahead of decisions and retains rollback capacity during probes.
//! Between probes, surplus connections can close when there is enough time
//! to reopen them using the measured setup time plus a margin. Parking takes effect within one block
//! even in a huge range: the worker hands its remainder back to the scheduler.
//!
//! [`Sampler`] turns raw samples into stable measurements and [`Policy`] is
//! the decision state machine; both are pure and unit tested. [`Gate`] is the
//! shared switch the workers consult; [`run`] is the driver.

pub(crate) mod history;
mod network;
pub(crate) mod trace;

use crate::conn::{DataTransport, Endpoint};
use crate::sched::Sched;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

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
/// Policy mechanics version recorded in transfer history.
pub const POLICY_VERSION: u32 = 6;
const STARTUP_STEP: usize = 2;

/// Multiplicative step after discovery, or with a closely matched plateau hint.
pub const STEP: f64 = 1.3;
/// Throughput tolerance for upward comparisons and plateau evidence. An
/// inconclusive increase within this tolerance of its own baseline keeps the
/// larger count without continuing growth. Reductions require a measured gain.
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
/// One discarded warm-up interval plus the two samples needed for stability.
const MEASUREMENT_SAMPLES: f64 = 3.0;
/// Two consecutive samples this close count as a stable rate.
const STABLE_WITHIN: f64 = 0.10;
/// Give up waiting for stability after this many samples and use what we have.
const MAX_SAMPLES: usize = 8;
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

#[derive(Debug, Default, Serialize, Deserialize)]
struct TuningCache {
    /// Legacy path+transport → last settled count. Keep the released format;
    /// filesystem-specific evidence lives in the separate history store.
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
/// seed one another. This legacy cache excludes local-only work; the history
/// store can reuse local results when both filesystems are known.
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

/// Network-aware keys are additive: released binaries keep reading/writing
/// their own unscoped entries in the unchanged legacy paths map.
pub fn network_path_key(src: &Endpoint, dst: &Endpoint) -> Option<String> {
    let key = path_key(src, dst)?;
    if transport_label(src).is_none() && transport_label(dst).is_none() {
        return Some(key);
    }
    Some(network_key(&key, network::fingerprint().as_deref()))
}

fn network_key(key: &str, network: Option<&str>) -> String {
    format!("{key}|network-v1={}", network.unwrap_or("unknown"))
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

/// Turns per-sample rates into one score per *stable* stretch: the first
/// sample after a change is discarded (connections coming up, congestion
/// control adapting), then samples are collected until two in a row agree
/// within STABLE_WITHIN, or MAX_SAMPLES have passed. The score is the mean
/// of the last two samples.
#[derive(Debug, Default)]
pub struct Sampler {
    samples: Vec<f64>,
    discard: bool,
    pub(crate) last_status: &'static str,
}

impl Sampler {
    /// The worker count just changed: start over, ignoring the next sample.
    pub fn reset(&mut self) {
        self.samples.clear();
        self.discard = true;
        self.last_status = "warmup_pending";
    }

    /// Earliest next decision, even if future samples stabilize immediately.
    fn earliest_score_in(&self, sample: Duration, elapsed: Duration) -> Duration {
        let remaining = if self.discard {
            3
        } else {
            2usize.saturating_sub(self.samples.len()).max(1)
        };
        sample.saturating_sub(elapsed) + sample * (remaining - 1) as u32
    }

    /// Feed one sample; returns a score once the rate is stable.
    pub fn push(&mut self, rate: f64) -> Option<f64> {
        if self.discard {
            self.discard = false;
            self.last_status = "warmup_excluded";
            return None;
        }
        self.last_status = "collecting";
        self.samples.push(rate);
        let n = self.samples.len();
        if n < 2 {
            return None;
        }
        let (a, b) = (self.samples[n - 2], self.samples[n - 1]);
        let stable = (a - b).abs() <= STABLE_WITHIN * a.max(b) || (a == 0.0 && b == 0.0);
        if stable || n >= MAX_SAMPLES {
            self.last_status = if stable { "stable" } else { "sample_limit" };
            self.samples.clear();
            Some(0.5 * (a + b))
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
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

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
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

#[derive(Debug, Clone, Copy, Serialize)]
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
    /// Starting count justified for future copies, excluding inconclusive increases.
    recommended: usize,
    /// Initial discovery doubles unless closely matched evidence supports refinement.
    startup_doubling: bool,
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
            recommended: n,
            startup_doubling: true,
            state: State::Initial,
            points: BTreeMap::new(),
            fails: [0, 0],
            due: [PROBE_EVERY, PROBE_EVERY],
            tick: 0,
            comparisons: 0,
            history: vec![n],
        }
    }

    pub fn refine(start: usize, min: usize, max: usize) -> Self {
        Self {
            startup_doubling: false,
            ..Self::new(start, min, max)
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

    /// Count to save for future copies. Keeping an inconclusive increase live
    /// does not justify making that increase the next copy's starting point.
    pub fn recommended(&self) -> usize {
        self.recommended
    }

    /// Connections required now (including rollback), and the earliest
    /// measurement at which a larger set could be selected. This is a
    /// preparation forecast, not a throughput decision. Hold uses the up
    /// deadline even when a down probe might happen first, conservatively.
    fn connection_forecast(&self) -> (usize, Option<(usize, usize)>) {
        let required = self.n.max(self.active).max(self.settled());
        let ticks = match self.state {
            State::Initial
            | State::Explore {
                direction: Direction::Up,
                ..
            } => 1,
            State::Explore {
                direction: Direction::Down,
                ..
            } => return (required, None),
            State::Hold => self.due[Direction::Up.index()]
                .saturating_sub(self.tick)
                .max(1),
        };
        // A nearest measured bound can make the next step larger than STEP.
        // Ignore score-based suppression: a new measurement can change it.
        let candidate = self
            .points
            .range((
                std::ops::Bound::Excluded(self.n),
                std::ops::Bound::Included(self.max),
            ))
            .next()
            .map_or_else(
                || self.upward_step(),
                |(&upper, _)| self.n + (upper - self.n).div_ceil(2),
            );
        (
            required,
            (candidate > required).then_some((candidate, ticks)),
        )
    }

    fn connection_plan(
        &self,
        sampler: &Sampler,
        sample: Duration,
        elapsed: Duration,
        lead: Duration,
        speculate: bool,
    ) -> ConnectionPlan {
        let (required, forecast) = self.connection_forecast();
        let mut plan = ConnectionPlan {
            connect: required,
            // While exploring, another decision can follow immediately.
            // Only a settled wait gives us a useful retirement deadline.
            keep: if matches!(self.state, State::Hold) {
                required
            } else {
                usize::MAX
            },
        };
        // Preserve the existing 1 -> 2 startup spare even before the first
        // connection is ready. Waiting for its setup measurement would miss
        // the first probe when an SSH handshake takes longer than a sample.
        // Settled single-worker copies still use the expiry schedule below.
        if matches!(self.state, State::Initial) && self.n == 1 {
            plan.connect = self.max.min(2);
        }
        if let Some((candidate, ticks)) = forecast {
            let first_score = if self.n != self.active {
                // Samples while the candidate connects only refresh its
                // baseline. Activation starts a fresh measurement period.
                let mut candidate_sampler = Sampler::default();
                candidate_sampler.reset();
                candidate_sampler.earliest_score_in(sample, Duration::ZERO)
            } else {
                sampler.earliest_score_in(sample, elapsed)
            };
            let until = first_score.saturating_add(
                sample
                    .saturating_mul(2)
                    .saturating_mul(u32::try_from(ticks.saturating_sub(1)).unwrap_or(u32::MAX)),
            );
            if speculate && until <= lead {
                plan.connect = candidate;
            }
            // Hysteresis avoids closing and immediately reopening connections.
            if until <= lead.saturating_mul(2) {
                plan.keep = usize::MAX;
            }
        }
        plan
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

    /// A starting guess is useful before discovery finishes. Smaller startup
    /// probes need more: the settled count must be near the recent best and a
    /// nearby higher count must have failed to improve it. A rejected doubling
    /// alone leaves too wide a bracket; cancelled warmups and hitting a ceiling
    /// are not plateau measurements either.
    pub fn discovery_complete(&self) -> bool {
        let settled = self.settled();
        // Plateau evidence for the live count must not be attached to a
        // different recommendation retained after an inconclusive increase.
        if settled != self.recommended {
            return false;
        }
        let Some(current) = self.points.get(&settled) else {
            return false;
        };
        let recent =
            |point: &Point| self.tick.saturating_sub(point.measured_at) <= EVIDENCE_MAX_AGE;
        current.score > 0.0
            && recent(current)
            && current.score >= self.recent_best() * (1.0 - NEAR_BEST_TOLERANCE)
            && self
                .points
                .range((
                    std::ops::Bound::Excluded(settled),
                    std::ops::Bound::Unbounded,
                ))
                .next()
                .is_some_and(|(&higher, point)| {
                    higher <= step_up(settled)
                        && recent(point)
                        && current.score >= point.score * (1.0 - NEAR_BEST_TOLERANCE)
                })
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
            self.startup_doubling = false;
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

    fn upward_step(&self) -> usize {
        if self.startup_doubling {
            self.n.saturating_mul(STARTUP_STEP).min(self.max)
        } else {
            step_up(self.n).min(self.max)
        }
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
                self.upward_step()
            }
        }
    }

    fn begin(&mut self, direction: Direction, base: f64) -> bool {
        if direction == Direction::Down {
            self.startup_doubling = false;
        }
        let from = self.n;
        let target = self.target(direction);
        if !self.set_candidate(target) {
            self.startup_doubling = false;
            // Bounds suppress probes in begin_due_probe, but the count can
            // later move away from a bound. Keep a finite retry deadline so
            // that direction can become eligible again, with normal backoff.
            self.due[direction.index()] = self.tick + self.retry_after(direction);
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
                if score > 0.0 && !self.begin(Direction::Up, score) {
                    self.begin(Direction::Down, score);
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
                    // Continue upward only when the larger count is near-best
                    // and its smaller baseline is not. An inconclusive result
                    // is handled separately below.
                    Direction::Up => score >= floor && base < floor,
                    Direction::Down => score > base,
                };
                self.comparisons += 1;
                let idx = direction.index();
                let inverse = direction.opposite().index();
                if direction == Direction::Up
                    && !keep
                    && base > 0.0
                    && score >= base * (1.0 - NEAR_BEST_TOLERANCE)
                {
                    // Uncertainty is not evidence to remove workers, nor to
                    // keep growing. Stop the ramp and wait before probing.
                    self.startup_doubling = false;
                    self.fails[idx] += 1;
                    self.due[idx] = self.tick + self.retry_after(direction);
                    self.due[inverse] = self.due[inverse].max(self.tick + PROBE_EVERY);
                    self.state = State::Hold;
                    return self.n;
                }
                if keep {
                    self.recommended = match direction {
                        Direction::Up => self.n,
                        // A partial reduction of an inconclusive increase is
                        // not evidence to raise the future starting count.
                        Direction::Down => self.recommended.min(self.n),
                    };
                    self.fails[idx] = 0;
                    self.due[inverse] = self.due[inverse].max(self.tick + PROBE_EVERY);
                    self.state = State::Hold;
                    // Success is direct evidence that there may be more gain
                    // in the same direction, so continue immediately.
                    self.begin(direction, score);
                } else {
                    let refine_startup = self.startup_doubling;
                    self.startup_doubling = false;
                    self.fails[idx] += 1;
                    self.due[idx] = self.tick + self.retry_after(direction);
                    // Do not mechanically bounce to the opposite side after
                    // a failed probe. Let current throughput settle first.
                    self.due[inverse] = self.due[inverse].max(self.tick + PROBE_EVERY);
                    self.set_candidate(from);
                    self.state = State::Hold;
                    if refine_startup {
                        // The failed doubling bounds the useful range. Try
                        // its midpoint now rather than waiting out backoff
                        // at a potentially much slower starting count.
                        self.begin(Direction::Up, base);
                    }
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
    Retiring,
}

#[derive(Debug, Clone)]
struct Slot {
    phase: SlotPhase,
    setup_started: Option<Instant>,
}

impl Default for Slot {
    fn default() -> Self {
        Self {
            phase: SlotPhase::Absent,
            setup_started: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ConnectionPlan {
    connect: usize,
    keep: usize,
}

/// The worker lifecycle shared by the tuner and workers. `active` controls who
/// may take work; `connect_target` controls who should establish or recover a
/// connection. The ordinary-copy driver separately controls which parked
/// connections to keep. Slot state distinguishes ready, retiring and failed
/// connections, so a retiring connection cannot be mistaken for a ready one.
pub struct Gate {
    active: AtomicUsize,
    connect_target: AtomicUsize,
    keep_target: AtomicUsize,
    setup_micros: AtomicU64,
    slots: Mutex<Vec<Slot>>,
    cv: Condvar,
    history: std::sync::OnceLock<history::Recorder>,
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
            connect_target: AtomicUsize::new(active),
            // Drivers without anticipatory preparation retain their existing
            // lifecycle; descriptor copies return connections to Session.
            keep_target: AtomicUsize::new(usize::MAX),
            setup_micros: AtomicU64::new(0),
            slots: Mutex::new(Vec::new()),
            cv: Condvar::new(),
            history: std::sync::OnceLock::new(),
        })
    }

    pub(crate) fn set_history(&self, history: history::Recorder) {
        let _ = self.history.set(history);
    }

    fn counts(&self) -> (usize, usize, usize) {
        let slots = self.slots.lock().unwrap();
        (
            slots.iter().filter(|s| s.phase == SlotPhase::Ready).count(),
            slots
                .iter()
                .filter(|s| s.phase == SlotPhase::Warming)
                .count(),
            slots
                .iter()
                .filter(|s| s.phase == SlotPhase::Failed)
                .count(),
        )
    }

    fn record_slot(&self, id: usize, state: &str) {
        if let Some(history) = self.history.get() {
            history.event(
                "worker",
                serde_json::json!({"worker":id,"state":state,"active":self.active()}),
            );
        }
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
        self.connect_target.fetch_max(n, Relaxed);
        self.cv.notify_all();
    }

    /// Limit setup/recovery without closing already-connected parked workers.
    pub fn set_connect_target(&self, n: usize) {
        let _g = self.slots.lock().unwrap();
        self.connect_target.store(n.max(self.active()), Relaxed);
        self.cv.notify_all();
    }

    fn prepare(&self, plan: ConnectionPlan) {
        let _slots = self.slots.lock().unwrap();
        let connect = plan.connect.max(self.active());
        self.connect_target.store(connect, Relaxed);
        self.keep_target.store(plan.keep.max(connect), Relaxed);
        self.cv.notify_all();
    }

    /// Include connection retries, not just the successful handshake.
    /// A high-water mark with 2x headroom avoids learning an optimistic lead
    /// from one fast connection. The extra second covers polling jitter.
    fn setup_lead(&self) -> Duration {
        Duration::from_micros(self.setup_micros.load(Relaxed))
            .saturating_mul(2)
            .saturating_add(Duration::from_secs(1))
    }

    /// Reserve absent slots through `n`. Workers start timing with
    /// `mark_warming` when they can connect, after any wait for planning.
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
        drop(slots);
        for id in &ids {
            self.record_slot(*id, "warming");
        }
        ids
    }

    pub fn mark_ready(&self, id: usize) {
        let mut slots = self.slots.lock().unwrap();
        grow_to(&mut slots, id + 1);
        if let Some(started) = slots[id].setup_started.take() {
            self.setup_micros.fetch_max(
                u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
                Relaxed,
            );
        }
        slots[id].phase = SlotPhase::Ready;
        self.cv.notify_all();
        drop(slots);
        self.record_slot(id, "ready");
    }

    /// Begin connection setup, preserving the start across retries/backoff.
    pub fn mark_warming(&self, id: usize) {
        let mut slots = self.slots.lock().unwrap();
        grow_to(&mut slots, id + 1);
        slots[id].phase = SlotPhase::Warming;
        slots[id].setup_started.get_or_insert_with(Instant::now);
        self.cv.notify_all();
        drop(slots);
        self.record_slot(id, "warming");
    }

    /// Mark a cleanly retired worker reusable immediately.
    pub fn mark_absent(&self, id: usize) {
        let mut slots = self.slots.lock().unwrap();
        grow_to(&mut slots, id + 1);
        slots[id] = Slot::default();
        self.cv.notify_all();
        drop(slots);
        self.record_slot(id, "absent");
    }

    /// Mark setup or repeated connection loss after bounded retries.
    pub fn mark_failed(&self, id: usize) {
        let mut slots = self.slots.lock().unwrap();
        grow_to(&mut slots, id + 1);
        slots[id].phase = SlotPhase::Failed;
        self.cv.notify_all();
        drop(slots);
        self.record_slot(id, "failed");
    }

    pub fn connection_needed(&self, id: usize) -> bool {
        id < self.connect_target.load(Relaxed)
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
    /// over or the driver has released this spare outside the preparation
    /// horizon. Mark retirement before releasing the lock so a tuner cannot
    /// activate a connection whose worker has already decided to exit.
    pub fn park(&self, id: usize, done: impl Fn() -> bool) -> bool {
        let mut slots = self.slots.lock().unwrap();
        loop {
            if self.allowed(id) {
                return true;
            }
            if done() || id >= self.keep_target.load(Relaxed) {
                grow_to(&mut slots, id + 1);
                slots[id].phase = SlotPhase::Retiring;
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
    fn history(&self) -> Option<history::Recorder> {
        None
    }
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
    let mut trace = trace::Trace::new(meter.history(), &policy, sample_interval());
    let mut sampler = Sampler::default();
    sampler.reset();
    let mut last = (meter.bytes(), meter.files());
    let mut sample_start = std::time::Instant::now();
    let mut active = policy.active();
    let mut collapse_samples = 0;
    let sample = sample_interval();
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
            trace.sample(
                last,
                (meter.bytes(), meter.files()),
                sample_start.elapsed().as_secs_f64(),
                &policy,
                &gate,
                "partial_before_reset",
                None,
            );
            policy = Policy {
                // Resumable SSH data also requests this reset after a limited
                // start. Keep cached/fine search fine, rather than restarting
                // uncached doubling when the available work changes.
                startup_doubling: policy.startup_doubling,
                ..Policy::new(requested, policy.min, policy.max)
            };
            active = requested;
            trace.transition(&policy, "direct_copy_needs_userspace_transfer");
            gate.set_connect_target(requested);
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

        let (_, forecast) = policy.connection_forecast();
        let preparation_count = forecast.map_or(policy.n, |(count, _)| count);
        let lead = gate.setup_lead();
        let preparation_activity =
            required_remaining_activity(last_rate, preparation_count, sample).saturating_add(
                last_rate.map_or(0, |rate| (rate * lead.as_secs_f64()).ceil() as u64),
            );
        let plan = policy.connection_plan(
            &sampler,
            sample,
            sample_start.elapsed(),
            lead,
            gate.ready_through(active)
                && sched.work_left_for(preparation_count, preparation_activity, FILE_CREDIT),
        );
        gate.prepare(plan);
        if sched.needs_worker_capacity() {
            let warming = gate.begin_warming(plan.connect);
            if crate::output::debug() && !warming.is_empty() && plan.connect > policy.n {
                crate::output::diagnostic!(
                    "syq: tune: preparing {} connections ahead of probe ({} active, {:.2}s setup lead)",
                    plan.connect, active, gate.setup_lead().as_secs_f64()
                );
            }
            for id in warming {
                spawn(id);
            }
        }

        // Apply reductions immediately. An increase leaves the current set
        // active while its candidate workers connect in the background.
        if policy.n < active {
            let before = active;
            trace.sample(
                last,
                (meter.bytes(), meter.files()),
                sample_start.elapsed().as_secs_f64(),
                &policy,
                &gate,
                "partial_before_activation",
                None,
            );
            gate.set_active(policy.n);
            active = policy.n;
            policy.activated();
            trace.transition(&policy, "decrease_activated");
            meter.set_active(active);
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
            if !trace.enough_work(&sched, policy.n, last_rate, sample) {
                trace.cancel(
                    &mut policy,
                    "insufficient_remaining_work",
                    last_rate,
                    sample,
                );
                continue;
            }
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
                trace.cancel(&mut policy, "candidate_setup_failed", last_rate, sample);
                gate.clear_failed_from(active);
                continue;
            }
            if gate.ready_through(policy.n) {
                let before = active;
                trace.sample(
                    last,
                    (meter.bytes(), meter.files()),
                    sample_start.elapsed().as_secs_f64(),
                    &policy,
                    &gate,
                    "partial_before_activation",
                    None,
                );
                gate.set_active(policy.n);
                active = policy.n;
                policy.activated();
                trace.transition(&policy, "candidate_ready");
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

            trace.waiting("candidate_connecting", &policy);

            // The settled workers keep providing a fresh comparison while an
            // upward candidate connects. This prevents handshake delay from
            // turning unrelated path drift into an apparent candidate effect.
            if sample_start.elapsed() >= sample {
                let now = (meter.bytes(), meter.files());
                let secs = sample_start.elapsed().as_secs_f64();
                sample_start = std::time::Instant::now();
                if !gate.ready_through(active) {
                    trace.sample(
                        last,
                        now,
                        secs,
                        &policy,
                        &gate,
                        "active_workers_connecting",
                        None,
                    );
                    last = now;
                    sampler.reset();
                    continue;
                }
                let Some(rate) = activity_rate(last, now, secs) else {
                    trace.sample(last, now, secs, &policy, &gate, "counter_regressed", None);
                    last = now;
                    sampler.reset();
                    continue;
                };
                let sample_previous = last;
                last = now;
                last_rate = Some(rate);
                if !trace.enough_work(&sched, policy.n, last_rate, sample) {
                    trace.sample(
                        sample_previous,
                        now,
                        secs,
                        &policy,
                        &gate,
                        "insufficient_remaining_work",
                        None,
                    );
                    trace.cancel(
                        &mut policy,
                        "insufficient_remaining_work",
                        last_rate,
                        sample,
                    );
                    sampler.reset();
                    continue;
                }
                let score = sampler.push(rate);
                trace.sample(
                    sample_previous,
                    now,
                    secs,
                    &policy,
                    &gate,
                    sampler.last_status,
                    score,
                );
                if let Some(score) = score {
                    trace.refresh_baseline(&mut policy, score);
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

        if gate.permanent_failure_through(active) {
            sched.abort();
            break;
        }
        if sample_start.elapsed() < sample {
            continue;
        }
        let now = (meter.bytes(), meter.files());
        let secs = sample_start.elapsed().as_secs_f64();
        sample_start = std::time::Instant::now();
        // Only judge a configuration once every requested worker is actually
        // connected (ssh sessions can take seconds each).
        if !gate.ready_through(active) {
            trace.sample(
                last,
                now,
                secs,
                &policy,
                &gate,
                "active_workers_connecting",
                None,
            );
            trace.waiting("active_workers_connecting", &policy);
            last = now;
            sampler.reset();
            continue;
        }
        // Per second, so jitter in the sample length doesn't masquerade as a
        // throughput change.
        let Some(rate) = activity_rate(last, now, secs) else {
            trace.sample(last, now, secs, &policy, &gate, "counter_regressed", None);
            // Progress can be retracted after uncertain acknowledgements. The
            // production meter is monotonic, but keep the generic driver safe
            // and discard any interval from a regressing implementation.
            last = now;
            sampler.reset();
            collapse_samples = 0;
            continue;
        };
        let sample_previous = last;
        last = now;
        last_rate = Some(rate);
        // Estimate the time left at the rate just observed. In the tail, idle
        // workers say nothing; unlike a fixed byte threshold this remains
        // useful on both very slow and very fast paths.
        if !trace.enough_work(&sched, active, last_rate, sample) {
            trace.sample(
                sample_previous,
                now,
                secs,
                &policy,
                &gate,
                "insufficient_remaining_work",
                None,
            );
            trace.waiting("insufficient_remaining_work", &policy);
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
            trace.sample(
                sample_previous,
                now,
                secs,
                &policy,
                &gate,
                "collapse_guard",
                Some(rate),
            );
            trace.observe(&mut policy, rate, "collapse_guard");
            sampler.reset();
            collapse_samples = 0;
            continue;
        }
        let score = sampler.push(rate);
        trace.sample(
            sample_previous,
            now,
            secs,
            &policy,
            &gate,
            sampler.last_status,
            score,
        );
        let Some(score) = score else {
            continue;
        };
        let before = policy.n;
        trace.observe(&mut policy, score, sampler.last_status);
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
    trace.sample(
        last,
        (meter.bytes(), meter.files()),
        sample_start.elapsed().as_secs_f64(),
        &policy,
        &gate,
        "final_partial",
        None,
    );
    trace.end(&policy, sched.is_aborted());
    policy
}

#[cfg(test)]
mod sim;
#[cfg(test)]
mod tests;

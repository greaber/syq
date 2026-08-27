//! Automatic tuning of the number of parallel workers / connections.
//!
//! When `-j` is not given, pcp does not guess: it starts with a few workers
//! and measures. Progress (bytes, plus a small credit per completed file so
//! small-file transfers count too) is sampled every few seconds; a worker
//! count has been *measured* once the rate has stopped changing — two
//! consecutive samples agree — so a burst credit running out, or a link that
//! is still ramping up, is waited out rather than attributed to the last
//! change. Each measured count is compared with the previous one: the count
//! grows by [`STEP`] while that pays at least a third of what linear scaling
//! would give, shrinks by [`STEP`] while that costs nothing, and then holds.
//! It never stops watching: in the hold phase it periodically probes a step
//! down (if throughput doesn't drop, fewer connections were enough — this is
//! what saves a spinning disk from seek thrash) and a step up (the route or a
//! shared NAS may have freed up).
//!
//! Workers are never killed. Surplus ones are *parked* — they keep their
//! connections open and simply stop taking work — so un-parking is instant.
//! Parking takes effect within one block even in the middle of a huge range:
//! the worker hands the rest of its range back to the scheduler.
//!
//! [`Sampler`] turns raw samples into stable measurements and [`Policy`] is
//! the decision state machine; both are pure and unit tested. [`Gate`] is the
//! shared switch the workers consult; [`run`] is the driver.

use crate::sched::Sched;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

/// Workers to start with when auto-tuning over the network: each is an ssh
/// handshake (seconds on a long path) or a TCP connection, so start modestly
/// and let the tuner earn more.
pub const START: usize = 8;
/// Workers to start with when both ends are local: threads are free, network
/// filesystems like the concurrency, and short bursts never reach the first
/// measurement. If it's too many for a spinning disk the ramp-down finds out.
pub const START_LOCAL: usize = 32;
/// Never auto-tune beyond this many workers.
pub const MAX: usize = 64;
/// Never auto-tune below this many.
pub const MIN: usize = 2;
/// Multiplicative step between worker counts, up or down.
pub const STEP: f64 = 1.3;
/// The initial ramp-up uses this coarser step, so a path that wants many
/// connections gets them in a few steps; once a coarse step stops paying,
/// the ramp goes back to the last good count and refines with STEP.
pub const COARSE_STEP: f64 = 2.0;
/// A step up is kept if it gains at least this fraction of what linear
/// scaling would have given (STEP - 1). Lenient on purpose: a false "no
/// gain" strands a window-capped ssh path at half speed, while a false
/// "gain" costs a few idle connections that the next down-probe reclaims.
const GAIN_FRACTION: f64 = 1.0 / 3.0;
/// A step down is kept unless throughput fell by more than this.
const DOWN_TOLERANCE: f64 = 0.05;
/// Measurements in the hold phase between probes. Each failed probe in a
/// direction doubles the wait before that direction is tried again (up to
/// 2^PROBE_BACKOFF_MAX times), so a sharp knee — a disk that collapses one
/// step up — isn't paid for every few measurements forever.
const PROBE_EVERY: usize = 6;
const PROBE_BACKOFF_MAX: u32 = 3;
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

#[derive(Debug, Clone, Copy, PartialEq)]
enum State {
    /// Stepping up while each step pays (`up`; by COARSE_STEP first, then
    /// STEP), or down while each step costs nothing (`!up`).
    Ramp { up: bool, coarse: bool },
    /// Steady; counting measurements until the next probe.
    Hold { measured: usize, next_up: bool },
    /// Trying a different count; `from` is where to go back to.
    Probe { from: usize, up: bool },
}

/// Pure decision logic. Feed it one stable score per worker count; it
/// returns the number of workers that should be active from now on.
#[derive(Debug, Clone)]
pub struct Policy {
    pub n: usize,
    pub min: usize,
    pub max: usize,
    pub peak: usize,
    state: State,
    /// The count before the last change.
    prev: usize,
    /// Score of the count we compare against.
    base: Option<f64>,
    /// Consecutive failed probes up / down.
    fails: [u32; 2],
    /// Decision log, for --stats / debug.
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
            state: State::Ramp {
                up: true,
                coarse: true,
            },
            prev: n,
            base: None,
            fails: [0, 0],
            history: vec![n],
        }
    }

    /// The count the policy considers right: `n`, unless a probe is in
    /// progress, in which case the count it will return to if the probe fails.
    pub fn settled(&self) -> usize {
        match self.state {
            State::Probe { from, .. } => from,
            _ => self.n,
        }
    }

    /// Change the count (clamped). Returns true if it actually changed.
    fn set(&mut self, n: usize) -> bool {
        let n = n.clamp(self.min, self.max);
        if n == self.n {
            return false;
        }
        self.prev = self.n;
        self.n = n;
        self.peak = self.peak.max(n);
        self.history.push(n);
        true
    }

    fn hold(&mut self, next_up: bool) {
        self.state = State::Hold {
            measured: 0,
            next_up,
        };
    }

    /// The gain a step up by `factor` must show to be kept.
    fn gain_needed(factor: f64) -> f64 {
        1.0 + (factor - 1.0) * GAIN_FRACTION
    }

    /// One stable measurement of the current count. Returns the worker count
    /// to apply from now on (`self.n` when nothing changes).
    pub fn observe(&mut self, score: f64) -> usize {
        let Some(base) = self.base else {
            self.base = Some(score);
            if let State::Ramp { up: true, coarse } = self.state {
                if score > 0.0 {
                    // First real measurement: try a step up right away.
                    let f = if coarse { COARSE_STEP } else { STEP };
                    self.set(step_up_by(self.n, f));
                }
            }
            return self.n;
        };
        if base <= 0.0 && score <= 0.0 {
            return self.n; // nothing is moving; no information
        }
        let ratio = if base > 0.0 {
            score / base
        } else {
            f64::INFINITY
        };
        match self.state {
            State::Ramp { up: true, coarse } => {
                let factor = if coarse { COARSE_STEP } else { STEP };
                let p = self.prev.min(self.n);
                if ratio > Self::gain_needed(factor) {
                    self.base = Some(score);
                    if self.n < self.max {
                        self.set(step_up_by(self.n, factor));
                    } else {
                        // It paid all the way up to the cap: stay there.
                        self.hold(false);
                    }
                } else if coarse && step_up(p) < self.n {
                    // The doubling from `p` didn't pay as a whole, but the
                    // best count may lie between p and 2p: go back to p and
                    // refine upward in finer steps, judged against p's score.
                    self.set(step_up(p));
                    self.prev = p;
                    self.state = State::Ramp {
                        up: true,
                        coarse: false,
                    };
                } else if p > self.min && step_down(p) >= self.min {
                    // Even a fine step from `p` bought nothing (or hurt):
                    // `p` did the same work for less. Maybe fewer still
                    // does — ramp down, judging each step against p's score
                    // (`base`), going there directly.
                    self.set(step_down(p));
                    self.prev = p;
                    self.state = State::Ramp {
                        up: false,
                        coarse: false,
                    };
                } else {
                    self.set(p);
                    self.base = Some(score);
                    self.hold(false);
                }
            }
            State::Ramp { up: false, .. } => {
                if ratio >= 1.0 - DOWN_TOLERANCE {
                    // Fewer kept up: keep it, try fewer again.
                    self.base = Some(score);
                    if self.n > self.min && step_down(self.n) >= self.min {
                        self.set(step_down(self.n));
                    } else {
                        self.hold(true);
                    }
                } else {
                    // Too few: go back to the last count that kept up.
                    self.set(self.prev);
                    self.hold(true);
                }
            }
            State::Hold { measured, next_up } => {
                // Track the baseline slowly so a drifting route doesn't make
                // every later comparison meaningless.
                self.base = Some(0.5 * base + 0.5 * score);
                let measured = measured + 1;
                let backoff = self.fails[usize::from(!next_up)].min(PROBE_BACKOFF_MAX);
                if measured < PROBE_EVERY << backoff {
                    self.state = State::Hold { measured, next_up };
                } else {
                    let target = if next_up {
                        step_up(self.n)
                    } else {
                        step_down(self.n)
                    };
                    let from = self.n;
                    if self.set(target) {
                        self.state = State::Probe { from, up: next_up };
                    } else {
                        // Can't move that way; try the other direction next time.
                        self.hold(!next_up);
                    }
                }
            }
            State::Probe { from, up } => {
                let keep = if up {
                    ratio > Self::gain_needed(STEP)
                } else {
                    ratio >= 1.0 - DOWN_TOLERANCE
                };
                if keep {
                    // A successful move: try further in the same direction
                    // sooner than usual.
                    self.fails[usize::from(!up)] = 0;
                    self.base = Some(score);
                    self.state = State::Hold {
                        measured: PROBE_EVERY / 2,
                        next_up: up,
                    };
                } else {
                    self.fails[usize::from(!up)] += 1;
                    self.set(from);
                    self.hold(!up);
                }
            }
        }
        self.n
    }
}

/// The switch workers consult: worker `id` may work iff `id < limit`.
pub struct Gate {
    limit: AtomicUsize,
    /// Workers whose connections are up (parked or not).
    pub connected: AtomicUsize,
    m: Mutex<()>,
    cv: Condvar,
}

impl Gate {
    pub fn new(limit: usize) -> Arc<Self> {
        Arc::new(Gate {
            limit: AtomicUsize::new(limit),
            connected: AtomicUsize::new(0),
            m: Mutex::new(()),
            cv: Condvar::new(),
        })
    }

    pub fn allowed(&self, id: usize) -> bool {
        id < self.limit.load(Relaxed)
    }

    pub fn set_limit(&self, n: usize) {
        let _g = self.m.lock().unwrap();
        self.limit.store(n, Relaxed);
        self.cv.notify_all();
    }

    /// Block until `id` is allowed again. Returns false if the transfer is
    /// over (`done` became true) and the worker should exit instead.
    pub fn park(&self, id: usize, done: impl Fn() -> bool) -> bool {
        let mut g = self.m.lock().unwrap();
        loop {
            if self.allowed(id) {
                return true;
            }
            if done() {
                return false;
            }
            g = self
                .cv
                .wait_timeout(g, Duration::from_millis(250))
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

/// Drive the policy: sample progress, hand stable scores to the policy,
/// apply its decisions to the gate and spawn workers that don't exist yet.
/// Returns the final policy (for stats).
pub fn run(
    policy: Policy,
    gate: Arc<Gate>,
    sched: Arc<Sched>,
    meter: Arc<dyn Meter>,
    mut spawn: impl FnMut(usize),
    mut spawned: usize,
) -> Policy {
    let mut policy = policy;
    let mut sampler = Sampler::default();
    sampler.reset();
    let mut last = (meter.bytes(), meter.files());
    let mut sample_start = std::time::Instant::now();
    meter.set_active(policy.n);
    loop {
        std::thread::sleep(Duration::from_millis(250));
        if sched.is_aborted() || sched.finished() {
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
        let all_up = gate.connected.load(Relaxed) >= policy.n.min(spawned);
        if !all_up || !sched.work_left_for(policy.n, TAIL_BYTES_PER_WORKER) {
            last = now;
            sampler.reset();
            continue;
        }
        // Per second, so jitter in the sample length doesn't masquerade as a
        // throughput change.
        let rate = ((now.0 - last.0) as f64 + (now.1 - last.1) as f64 * FILE_CREDIT as f64) / secs;
        last = now;
        let Some(score) = sampler.push(rate) else {
            continue;
        };
        let before = policy.n;
        let n = policy.observe(score);
        if n != before {
            while spawned < n {
                spawn(spawned);
                spawned += 1;
            }
            gate.set_limit(n);
            meter.set_active(n);
            sampler.reset();
            if crate::transfer::debug() {
                eprintln!(
                    "pcp: tune: {before} -> {n} workers (measured {:.1} MB/s at {before}, state {:?})",
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

    /// Feed the policy a model where throughput rises linearly with workers
    /// up to `cap` workers and is flat after.
    fn simulate(start: usize, cap: usize, rounds: usize, noise: impl Fn(usize) -> f64) -> Policy {
        let mut p = Policy::new(start, MIN, MAX);
        for i in 0..rounds {
            let eff = p.n.min(cap) as f64;
            p.observe(eff * 10e6 * noise(i));
        }
        p
    }

    #[test]
    fn steps_are_geometric_and_move() {
        assert_eq!(step_up(8), 10);
        assert_eq!(step_up(2), 3);
        assert_eq!(step_down(8), 6);
        assert_eq!(step_down(3), 2);
        let mut n = START;
        let mut steps = 0;
        while n < MAX {
            n = step_up(n);
            steps += 1;
        }
        assert!((7..=9).contains(&steps), "{steps} steps");
    }

    #[test]
    fn ramps_to_the_plateau_and_holds() {
        let p = simulate(START, 32, 40, |_| 1.0);
        // Doubles up to the knee, overshoots once, refines, and stays.
        assert_eq!(
            &p.history[..5],
            &[8, 16, 32, 64, 42],
            "history {:?}",
            p.history
        );
        assert!((25..=42).contains(&p.settled()), "history {:?}", p.history);
    }

    #[test]
    fn a_gain_at_the_cap_holds_at_the_cap() {
        // Linear all the way past MAX (e.g. a fast NAS): 32 -> 64 doubles
        // throughput, and 64 is the cap, so it must stay at 64.
        let p = simulate(START_LOCAL, 200, 30, |_| 1.0);
        assert_eq!(&p.history[..2], &[32, 64], "history {:?}", p.history);
        assert_eq!(p.settled(), MAX, "history {:?}", p.history);
        assert!(
            p.history[1..].iter().all(|&n| n >= 48),
            "history {:?}",
            p.history
        );
    }

    #[test]
    fn coarse_ramp_refines_between_doublings() {
        // Scales linearly up to 24 workers: 16 -> 32 as a whole gains only
        // 50% of the 100% linear would give... which is above a third, so
        // model a sharper case: flat past 20. 16 -> 32 gains 25% (< 33%),
        // so it goes back to 16 and refines: 21 (+25% of 30%: kept), 27
        // (flat), back to 21, then descends 16 (worse), settles 21.
        let p = simulate(START, 20, 40, |_| 1.0);
        assert_eq!(
            &p.history[..5],
            &[8, 16, 32, 21, 27],
            "history {:?}",
            p.history
        );
        assert_eq!(p.settled(), 21, "history {:?}", p.history);
    }

    #[test]
    fn does_not_grow_when_it_never_pays() {
        // One worker already saturates the link (TCP on a clean path).
        let p = simulate(START, 1, 40, |_| 1.0);
        // The doubling fails, the fine step fails, then it walks down since
        // nothing drops.
        assert!(p.settled() < START, "history {:?}", p.history);
        assert_eq!(&p.history[..3], &[8, 16, 10]);
    }

    #[test]
    fn backs_off_when_more_workers_hurt() {
        // A spinning disk: scales to 8 workers, collapses past that.
        let score = |n: usize| {
            if n <= 8 {
                n as f64 * 12.5e6
            } else {
                30e6
            }
        };
        let mut p = Policy::new(START, MIN, MAX);
        for _ in 0..40 {
            p.observe(score(p.n));
        }
        assert_eq!(p.settled(), 8, "history {:?}", p.history);
        // 16 hurt; refine: 10 hurt too; 6 (judged against 8) was too few; back to 8.
        assert_eq!(&p.history[..5], &[8, 16, 10, 6, 8]);
        // Probes back off: far fewer than one excursion per 6 measurements.
        assert!(p.history.len() <= 12, "history {:?}", p.history);
    }

    #[test]
    fn descends_quickly_from_a_high_local_start() {
        // Same disk, started at the local default of 32.
        let score = |n: usize| {
            if n <= 8 {
                n as f64 * 12.5e6
            } else {
                30e6
            }
        };
        let mut p = Policy::new(START_LOCAL, MIN, MAX);
        let mut settled_at = None;
        for i in 0..60 {
            p.observe(score(p.n));
            if settled_at.is_none() && (7..=8).contains(&p.settled()) && p.n == p.settled() {
                settled_at = Some(i + 1);
            }
        }
        // The 1.3x grid around the knee is 7 / 9, so 7 is the best it can do.
        assert!((7..=8).contains(&p.settled()), "history {:?}", p.history);
        // 32 -> 64 (hurt) -> 42 (hurt) -> 25 -> 19 -> 15 -> 12 -> 9 -> 7 -> 5
        // (worse) -> 7: one measurement per step.
        assert!(
            settled_at.unwrap() <= 13,
            "took {:?}: {:?}",
            settled_at,
            p.history
        );
        assert_eq!(&p.history[..4], &[32, 64, 42, 25]);
    }

    #[test]
    fn ignores_noise_within_tolerance() {
        let p = simulate(START, 32, 60, |i| if i % 2 == 0 { 1.0 } else { 0.93 });
        assert!((20..=42).contains(&p.settled()), "history {:?}", p.history);
    }

    #[test]
    fn silence_is_not_a_signal() {
        let mut p = Policy::new(START, MIN, MAX);
        for _ in 0..10 {
            p.observe(0.0);
        }
        assert_eq!(p.history, vec![START]);
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
        let g2 = g.clone();
        let t = std::thread::spawn(move || g2.park(2, || false));
        std::thread::sleep(Duration::from_millis(50));
        g.set_limit(3);
        assert!(t.join().unwrap());
        let g3 = g.clone();
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let d = done.clone();
        let t = std::thread::spawn(move || g3.park(5, || d.load(Relaxed)));
        done.store(true, Relaxed);
        assert!(!t.join().unwrap());
    }
}

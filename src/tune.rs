//! Automatic tuning of the number of parallel workers / connections.
//!
//! When `-j` is not given, pcp does not guess: it starts with a few workers
//! and measures. Every window it compares progress (bytes, plus a small credit
//! per completed file so small-file transfers count too) with the previous
//! window, doubles the worker count while that pays, and when a doubling
//! buys nothing it halves while *that* costs nothing, then holds. It never
//! stops watching: in the hold phase it periodically probes
//! a step down (if throughput doesn't drop, fewer connections were enough —
//! this is what saves a spinning disk from seek thrash) and a step up (the
//! route or a shared NAS may have freed up).
//!
//! Workers are never killed. Surplus ones are *parked* — they keep their
//! connections open and simply stop taking work — so un-parking is instant.
//! Parking takes effect within one block even in the middle of a huge range:
//! the worker hands the rest of its range back to the scheduler.
//!
//! The policy is a pure state machine ([`Policy`]) so it can be unit tested;
//! [`Gate`] is the shared switch the workers consult; [`run`] is the driver.

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
/// window. If it's too many for a spinning disk the ramp-down finds out.
pub const START_LOCAL: usize = 32;
/// Never auto-tune beyond this many workers.
pub const MAX: usize = 64;
/// Never auto-tune below this many.
pub const MIN: usize = 2;
/// Measurement window. Long enough for BBR to settle on a 250 ms path.
pub const WINDOW: Duration = Duration::from_secs(5);
/// Relative gain that justifies more workers.
const GAIN: f64 = 0.15;
/// A step down is kept unless throughput fell by more than this.
const DOWN_TOLERANCE: f64 = 0.05;
/// Hold windows between probes (6 × 5 s = 30 s).
const PROBE_EVERY: usize = 6;
/// Don't judge a worker count unless each worker has at least this much left
/// to do: in the tail of a transfer, idle workers say nothing about the path.
const TAIL_BYTES_PER_WORKER: u64 = 64 << 20;
/// A completed file counts as this many bytes, so small-file transfers
/// (where bytes are negligible) still produce a usable signal.
pub const FILE_CREDIT: u64 = 512 * 1024;

#[derive(Debug, Clone, Copy, PartialEq)]
enum State {
    /// Doubling while each step pays (`up`), or halving while each step
    /// costs nothing (`!up`).
    Ramp { up: bool },
    /// Steady; counting windows until the next probe.
    Hold { windows: usize, next_up: bool },
    /// Trying a different count; `from` is where to go back to.
    Probe { from: usize, up: bool },
}

/// Pure decision logic. Feed it one score per window; it returns the number
/// of workers that should be active from now on.
#[derive(Debug, Clone)]
pub struct Policy {
    pub n: usize,
    pub min: usize,
    pub max: usize,
    pub peak: usize,
    state: State,
    /// Score of the window(s) at the current baseline.
    base: Option<f64>,
    /// The first window after a change is spent settling; ignore it.
    settle: bool,
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
            state: State::Ramp { up: true },
            base: None,
            // The first window is warm-up (connections, congestion control
            // ramping); don't let the first doubling take credit for it.
            settle: true,
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

    fn set(&mut self, n: usize) {
        let n = n.clamp(self.min, self.max);
        if n != self.n {
            self.n = n;
            self.peak = self.peak.max(n);
            self.settle = true;
            self.base = None;
            self.history.push(n);
        }
    }

    /// One measurement window has passed with `score` units of progress.
    /// Returns the worker count to apply (unchanged when it returns `self.n`).
    pub fn observe(&mut self, score: f64) -> usize {
        if self.settle {
            self.settle = false;
            return self.n;
        }
        let Some(base) = self.base else {
            self.base = Some(score);
            if self.state == (State::Ramp { up: true }) && score > 0.0 && self.n < self.max {
                // First real measurement: try doubling right away.
                self.set(self.n * 2);
                self.base = Some(score);
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
            State::Ramp { up: true } => {
                if ratio > 1.0 + GAIN && self.n < self.max {
                    self.set(self.n * 2);
                    // Judge the doubled count against what we just measured.
                    self.base = Some(score);
                } else {
                    // The doubling from p bought nothing (or hurt): p did the
                    // same work for less. Maybe p/2 does too — ramp down,
                    // judging each halving against p's score (`base`).
                    let p = if self.history.len() > 1 {
                        self.n / 2
                    } else {
                        self.n
                    };
                    if p / 2 >= self.min && p < self.n {
                        self.set(p / 2);
                        self.base = Some(base);
                        self.state = State::Ramp { up: false };
                    } else {
                        self.set(p);
                        self.base = Some(score);
                        self.state = State::Hold {
                            windows: 0,
                            next_up: false,
                        };
                    }
                }
            }
            State::Ramp { up: false } => {
                if ratio >= 1.0 - DOWN_TOLERANCE {
                    // Halving didn't cost anything: keep it, try halving again.
                    self.base = Some(score);
                    if self.n / 2 >= self.min && self.n > self.min {
                        self.set(self.n / 2);
                        self.base = Some(score);
                    } else {
                        self.state = State::Hold {
                            windows: 0,
                            next_up: true,
                        };
                    }
                } else {
                    // Too few: go back to the last count that kept up.
                    self.set(self.n * 2);
                    self.base = Some(base);
                    self.state = State::Hold {
                        windows: 0,
                        next_up: true,
                    };
                }
            }
            State::Hold { windows, next_up } => {
                // Track the baseline slowly so a drifting route doesn't make
                // every later comparison meaningless.
                self.base = Some(0.5 * base + 0.5 * score);
                let windows = windows + 1;
                if windows < PROBE_EVERY {
                    self.state = State::Hold { windows, next_up };
                } else {
                    let step = (self.n / 4).max(1);
                    let target = if next_up {
                        self.n + step
                    } else {
                        self.n.saturating_sub(step)
                    };
                    let target = target.clamp(self.min, self.max);
                    if target == self.n {
                        // Can't move that way; try the other direction next time.
                        self.state = State::Hold {
                            windows: 0,
                            next_up: !next_up,
                        };
                    } else {
                        let from = self.n;
                        let keep_base = self.base;
                        self.set(target);
                        self.base = keep_base; // compare the probe against the hold baseline
                        self.state = State::Probe { from, up: next_up };
                    }
                }
            }
            State::Probe { from, up } => {
                let keep = if up {
                    ratio > 1.0 + GAIN
                } else {
                    ratio >= 1.0 - DOWN_TOLERANCE
                };
                if keep {
                    // A successful move: try further in the same direction next.
                    self.base = Some(score);
                    self.state = State::Hold {
                        windows: PROBE_EVERY / 2,
                        next_up: up,
                    };
                } else {
                    let keep_base = self.base;
                    self.set(from);
                    self.base = keep_base;
                    self.state = State::Hold {
                        windows: 0,
                        next_up: !up,
                    };
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

/// Drive the policy: measure every WINDOW, apply decisions to the gate and
/// spawn workers that don't exist yet. Returns the final policy (for stats).
pub fn run(
    policy: Policy,
    gate: Arc<Gate>,
    sched: Arc<Sched>,
    meter: Arc<dyn Meter>,
    mut spawn: impl FnMut(usize),
    mut spawned: usize,
) -> Policy {
    let mut policy = policy;
    let mut last = (meter.bytes(), meter.files());
    let mut window_start = std::time::Instant::now();
    meter.set_active(policy.n);
    loop {
        std::thread::sleep(Duration::from_millis(250));
        if sched.is_aborted() || sched.finished() {
            break;
        }
        if window_start.elapsed() < WINDOW {
            continue;
        }
        let now = (meter.bytes(), meter.files());
        let secs = window_start.elapsed().as_secs_f64();
        window_start = std::time::Instant::now();
        // Only judge a configuration once every requested worker is actually
        // connected (ssh sessions can take seconds each), and only while there
        // is queued work — in the tail, idle workers say nothing about the path.
        let all_up = gate.connected.load(Relaxed) >= policy.n.min(spawned);
        if !all_up || !sched.work_left_for(policy.n, TAIL_BYTES_PER_WORKER) {
            last = now;
            continue;
        }
        // Per second, so sleep jitter in the window length doesn't masquerade
        // as a throughput change.
        let score = ((now.0 - last.0) as f64 + (now.1 - last.1) as f64 * FILE_CREDIT as f64) / secs;
        last = now;
        let before = policy.n;
        let n = policy.observe(score);
        if n != before {
            while spawned < n {
                spawn(spawned);
                spawned += 1;
            }
            gate.set_limit(n);
            meter.set_active(n);
            if crate::transfer::debug() {
                eprintln!(
                    "pcp: tune: {before} -> {n} workers (window {:.1} MB/s, state {:?})",
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
    fn simulate(cap: usize, windows: usize, noise: impl Fn(usize) -> f64) -> Policy {
        let mut p = Policy::new(START, MIN, MAX);
        for i in 0..windows {
            let eff = p.n.min(cap) as f64;
            let score = eff * 10e6 * noise(i);
            p.observe(score);
        }
        p
    }

    #[test]
    fn ramps_to_the_plateau_and_holds() {
        let p = simulate(32, 40, |_| 1.0);
        // 8 -> 16 -> 32 pays; 64 does not (flat), so it holds at 32; a later
        // down-probe to 24 costs throughput and is undone.
        assert_eq!(p.n, 32, "history {:?}", p.history);
        assert!(p.history.contains(&16) && p.history.contains(&32));
    }

    #[test]
    fn does_not_grow_when_it_never_pays() {
        // One worker already saturates the link (TCP on a clean path).
        let p = simulate(1, 40, |_| 1.0);
        assert!(p.n <= START, "history {:?}", p.history);
        // Down-probes keep succeeding (throughput never drops), so it walks down.
        assert!(p.n < START, "history {:?}", p.history);
    }

    #[test]
    fn backs_off_when_more_workers_hurt() {
        // A spinning disk: scales to 8 workers, collapses past that.
        let mut p = Policy::new(START, MIN, MAX);
        let score = |n: usize| {
            if n <= 8 {
                n as f64 * 12.5e6
            } else {
                30e6
            }
        };
        for _ in 0..40 {
            p.observe(score(p.n));
        }
        assert_eq!(p.settled(), 8, "history {:?}", p.history);
        // 16 hurt; 4 (judged against 8) was too few; back to 8.
        assert_eq!(&p.history[..4], &[8, 16, 4, 8]);
        // Every later excursion away from 8 was a probe that came straight back.
        assert!(p.history.iter().all(|&n| (4..=16).contains(&n)));
    }

    #[test]
    fn descends_quickly_from_a_high_local_start() {
        // Same disk, started at the local default of 32.
        let mut p = Policy::new(START_LOCAL, MIN, MAX);
        let score = |n: usize| {
            if n <= 8 {
                n as f64 * 12.5e6
            } else {
                30e6
            }
        };
        let mut windows_to_settle = None;
        for i in 0..40 {
            p.observe(score(p.n));
            if windows_to_settle.is_none() && p.settled() == 8 && p.n == 8 {
                windows_to_settle = Some(i + 1);
            }
        }
        assert_eq!(p.settled(), 8, "history {:?}", p.history);
        // 32 -> 64 (hurt) -> 16 (same as 32) -> 8 (better) -> 4 (worse) -> 8:
        // each step is a settle window plus a measured one.
        assert!(
            windows_to_settle.unwrap() <= 12,
            "took {:?}: {:?}",
            windows_to_settle,
            p.history
        );
    }

    #[test]
    fn ignores_noise_within_tolerance() {
        let p = simulate(32, 60, |i| if i % 2 == 0 { 1.0 } else { 0.92 });
        assert!(p.n >= 24 && p.n <= 40, "history {:?}", p.history);
    }

    #[test]
    fn silence_is_not_a_signal() {
        let mut p = Policy::new(START, MIN, MAX);
        for _ in 0..10 {
            p.observe(0.0);
        }
        assert_eq!(p.n, START);
        assert_eq!(p.history, vec![START]);
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

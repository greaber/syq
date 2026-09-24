//! Discrete-time simulation of [`Policy`] and [`Sampler`] against synthetic
//! throughput curves. It answers statistical questions that a handful of
//! hardware runs cannot: how often a rule helps, how much throughput the
//! search costs, and whether the remembered count drifts across copies.
//!
//! This coarse model does not model the fine-grained sequential evidence in
//! [`run`]; it is not a validation of the production observation pipeline.
//! It exercises policy decisions without threads or a clock:
//! reductions apply at once, increases wait for connection setup while the
//! settled count refreshes its baseline, the tail stops measuring, and two
//! collapsed samples short-circuit a probe. It does not model handshakes
//! competing with the transfer or connections warming up after activation.
//! Initial connections are ready at time zero; elapsed time excludes their
//! setup. Connection planning is checked every 250ms; activation and retirement
//! are instantaneous. File credit, connection failures, and scheduler limits
//! are not modeled. `prepare=true` uses the production connection planner;
//! `false` is a counterfactual that closes spare connections immediately. The oracle can select the instantaneous
//! best count in 1..=LIMIT without setup cost and sees the same wall-clock noise.
//! Results are only as good as the curves and noise fed in; check those
//! against real transfers before trusting a small difference.
//!
//! `cargo test --bin syq tune::sim::report -- --ignored --nocapture` prints
//! the comparison tables. `tune::sim::sweep` prints a reproducible CSV grid,
//! and `tune::sim::diagnostics` prints decision traces for selected cases.
//! First-hit times are conditional on reaching the near-best band; time spent
//! in that band is also reported because a path shift can invalidate a hit.

use super::*;

const SAMPLE_SECS: f64 = SAMPLE.as_secs_f64();
const LIMIT: usize = 64;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn unit(&mut self) -> f64 {
        ((self.next() >> 11) as f64 + 0.5) / (1u64 << 53) as f64
    }

    fn normal(&mut self) -> f64 {
        (-2.0 * self.unit().ln()).sqrt() * (std::f64::consts::TAU * self.unit()).cos()
    }
}

/// True throughput by worker count, before measurement noise.
#[derive(Clone, Copy)]
enum Curve {
    /// Each worker adds `per_worker` until a shared `cap`.
    Knee { per_worker: f64, cap: f64 },
    /// As `Knee`, but each doubling past the knee loses `loss` of the cap
    /// (receiver CPU or disk contention).
    Decline {
        per_worker: f64,
        cap: f64,
        loss: f64,
    },
    /// The shared cap changes once during the copy.
    Shift {
        per_worker: f64,
        before: f64,
        after: f64,
        at: f64,
    },
}

impl Curve {
    fn rate(self, n: usize, t: f64) -> f64 {
        let n = n as f64;
        match self {
            Curve::Knee { per_worker, cap } => (n * per_worker).min(cap),
            Curve::Decline {
                per_worker,
                cap,
                loss,
            } => {
                let knee = cap / per_worker;
                if n <= knee {
                    n * per_worker
                } else {
                    cap * (1.0 - loss).powf((n / knee).log2())
                }
            }
            Curve::Shift {
                per_worker,
                before,
                after,
                at,
            } => (n * per_worker).min(if t < at { before } else { after }),
        }
    }

    fn best(self, t: f64) -> f64 {
        match self {
            Curve::Decline {
                per_worker, cap, ..
            } => {
                let knee = cap / per_worker;
                self.rate((knee.floor() as usize).clamp(1, LIMIT), t)
                    .max(self.rate((knee.ceil() as usize).clamp(1, LIMIT), t))
            }
            _ => self.rate(LIMIT, t),
        }
    }

    /// Smallest count within the policy's own tolerance of the best rate.
    fn smallest_near_best(self, t: f64) -> usize {
        let floor = self.best(t) * (1.0 - NEAR_BEST_TOLERANCE);
        (1..=LIMIT).find(|&n| self.rate(n, t) >= floor).unwrap()
    }

    fn ideal_elapsed(self, total: f64) -> f64 {
        match self {
            Curve::Shift { at, .. } if self.best(0.0) * at < total => {
                at + (total - self.best(0.0) * at) / self.best(at)
            }
            _ => total / self.best(0.0),
        }
    }
}

#[derive(Clone, Copy)]
struct Scenario {
    name: &'static str,
    curve: Curve,
    /// Payload size in seconds at the initial, noiseless best rate.
    /// A capacity shift changes the oracle duration for that fixed payload.
    ideal_secs: f64,
    start: usize,
    /// Log-normal per-sample noise, with AR(1) correlation between samples.
    sigma: f64,
    rho: f64,
    setup_secs: f64,
    /// Use the production preparation/retirement plan. False is a comparison
    /// that opens only requested workers and immediately retires spare ones.
    prepare: bool,
}

struct Outcome {
    elapsed: f64,
    ideal_elapsed: f64,
    near_secs: f64,
    tail_rollback_blocked: bool,
    reached_near_best: Option<f64>,
    connection_secs: f64,
    handshakes: usize,
    policy: Policy,
}

fn copy(s: &Scenario, policy: Policy, rng: &mut Rng) -> Outcome {
    copy_observing(s, policy, rng, |_, _| {})
}

fn copy_observing(
    s: &Scenario,
    mut policy: Policy,
    rng: &mut Rng,
    mut observe: impl FnMut(f64, &Policy),
) -> Outcome {
    let total = s.curve.best(0.0) * s.ideal_secs;
    let (mut t, mut done) = (0.0f64, 0.0f64);
    let mut active = policy.active();
    // Initial connections are already ready: elapsed time starts with copying.
    let mut connections = vec![0.0f64; active];
    let mut open = active;
    let mut handshakes = active;
    let mut connection_secs = 0.0;
    let mut sampler = Sampler::default();
    sampler.reset();
    let (mut sample_start, mut sample_bytes) = (0.0f64, 0.0f64);
    let mut noise_end = SAMPLE_SECS;
    let (mut ideal_done, mut ideal_elapsed, mut near_secs) = (0.0, None, 0.0);
    let mut collapsed = 0;
    let mut last_rate: Option<f64> = None;
    let mut reached = None;
    let mut tail_rollback_blocked = false;
    let mut drift = rng.normal();
    let mut noise = (s.sigma * drift - 0.5 * s.sigma * s.sigma).exp();

    for _ in 0..1_000_000 {
        assert!(t < 1_000_000.0, "simulation deadline: {}", s.name);
        policy.advance_time(Duration::from_secs_f64(t), SAMPLE);
        observe(t, &policy);
        let needs = last_rate.map_or(0.0, |rate| rate * SAMPLE_SECS * MEASUREMENT_SAMPLES);
        // All initial connections have already completed the same deterministic
        // setup, so the driver's measured high-water setup lead is known.
        let lead = Duration::from_secs_f64(s.setup_secs * 2.0 + 1.0);
        let wanted = if s.prepare {
            let plan = policy.connection_plan(
                &sampler,
                SAMPLE,
                Duration::from_secs_f64(t - sample_start),
                lead,
                total - done >= needs + last_rate.unwrap_or(0.0) * lead.as_secs_f64(),
            );
            open.min(plan.keep.max(plan.connect).max(active))
                .max(plan.connect)
                .max(active)
        } else {
            let needed = policy.n.max(active);
            if needed == 1 {
                2.min(policy.max)
            } else {
                needed
            }
        };
        handshakes += wanted.saturating_sub(open);
        connections.resize(wanted, t + s.setup_secs);
        open = wanted;
        if policy.n < active {
            active = policy.n;
            policy.activated();
            sampler.reset();
            (sample_start, sample_bytes, collapsed) = (t, 0.0, 0);
            continue;
        }
        let tail_blocks_increase = policy.n > active
            && matches!(policy.state, State::Explore { .. })
            && total - done < needs;
        if tail_blocks_increase {
            policy.cancel_unapplied();
            if policy.n <= active {
                continue;
            }
            tail_rollback_blocked = true;
            // A rollback from a failed downward probe is already Hold;
            // cancel_unapplied does not change it. Production keeps copying
            // at the lower active count while polling the tail guard.
        }
        let ready_at = (policy.n > active && !tail_blocks_increase)
            .then(|| connections[..policy.n].iter().copied().fold(t, f64::max));
        if reached.is_none()
            && s.curve.rate(active, t) >= s.curve.best(t) * (1.0 - NEAR_BEST_TOLERANCE)
        {
            reached = Some(t);
        }

        let rate = s.curve.rate(active, t) * noise;
        let sample_end = sample_start + SAMPLE_SECS;
        let mut until = ready_at.map_or(sample_end, |ready| ready.min(sample_end));
        until = until.min(noise_end).min(((t / 0.25).floor() + 1.0) * 0.25);
        if let Curve::Shift { at, .. } = s.curve {
            if t < at {
                until = until.min(at);
            }
        }
        let dt = (until - t).max(0.0).min((total - done) / rate);
        let ideal_rate = s.curve.best(t) * noise;
        if ideal_elapsed.is_none() && ideal_done + ideal_rate * dt >= total {
            ideal_elapsed = Some(t + (total - ideal_done) / ideal_rate);
        }
        ideal_done += ideal_rate * dt;
        if s.curve.rate(active, t) >= s.curve.best(t) * (1.0 - NEAR_BEST_TOLERANCE) {
            near_secs += dt;
        }
        done += rate * dt;
        sample_bytes += rate * dt;
        connection_secs += open as f64 * dt;
        t += dt;
        if done >= total {
            return Outcome {
                elapsed: t,
                ideal_elapsed: ideal_elapsed.unwrap_or(t),
                near_secs,
                tail_rollback_blocked,
                reached_near_best: reached,
                connection_secs,
                handshakes,
                policy,
            };
        }
        // Noise is an external wall-clock process, independent of activations
        // and sample resets. The oracle sees exactly the same realization.
        if t >= noise_end {
            drift = s.rho * drift + (1.0 - s.rho * s.rho).sqrt() * rng.normal();
            noise = (s.sigma * drift - 0.5 * s.sigma * s.sigma).exp();
            noise_end += SAMPLE_SECS;
        }

        if ready_at.is_some_and(|ready| ready <= t) {
            active = policy.n;
            policy.activated();
            sampler.reset();
            (sample_start, sample_bytes, collapsed) = (t, 0.0, 0);
            continue;
        }

        if t < sample_end {
            continue;
        }
        if tail_blocks_increase {
            (sample_start, sample_bytes) = (t, 0.0);
            continue;
        }
        let measured = sample_bytes / SAMPLE_SECS;
        (sample_start, sample_bytes) = (t, 0.0);
        last_rate = Some(measured);
        let enough = total - done >= measured * SAMPLE_SECS * MEASUREMENT_SAMPLES;
        if policy.n > active {
            if !enough {
                policy.cancel_unapplied();
                sampler.reset();
            } else if let Some(score) = sampler.push(measured) {
                policy.refresh_warming_baseline(score);
            }
            continue;
        }
        if !enough {
            sampler.reset();
            collapsed = 0;
            continue;
        }
        if policy
            .probe_base()
            .is_some_and(|base| base > 0.0 && measured < 0.5 * base)
        {
            collapsed += 1;
        } else {
            collapsed = 0;
        }
        if collapsed >= 2 {
            policy.observe(measured);
            sampler.reset();
            collapsed = 0;
            continue;
        }
        if let Some(score) = sampler.push(measured) {
            let before = policy.n;
            policy.observe(score);
            if policy.n != before {
                sampler.reset();
            }
        }
    }
    panic!("simulation event limit: {} at {t}s", s.name);
}

fn quantile(values: &mut [f64], q: f64) -> f64 {
    values.sort_by(f64::total_cmp);
    values[((values.len() - 1) as f64 * q).round() as usize]
}

fn curves() -> Vec<(&'static str, Curve, usize)> {
    vec![
        (
            "knee at 32",
            Curve::Knee {
                per_worker: 4.0,
                cap: 128.0,
            },
            8,
        ),
        (
            "knee at 12",
            Curve::Knee {
                per_worker: 10.0,
                cap: 120.0,
            },
            8,
        ),
        (
            "flat from 1",
            Curve::Knee {
                per_worker: 100.0,
                cap: 100.0,
            },
            8,
        ),
        (
            "linear past 64",
            Curve::Knee {
                per_worker: 2.0,
                cap: 1000.0,
            },
            8,
        ),
        (
            "knee 8, -4%/doubling",
            Curve::Decline {
                per_worker: 12.5,
                cap: 100.0,
                loss: 0.04,
            },
            8,
        ),
        (
            "knee 4, -30%/doubling",
            Curve::Decline {
                per_worker: 25.0,
                cap: 100.0,
                loss: 0.30,
            },
            8,
        ),
        (
            "cap 60 -> 120 at 60s",
            Curve::Shift {
                per_worker: 4.0,
                before: 60.0,
                after: 120.0,
                at: 60.0,
            },
            8,
        ),
    ]
}

#[test]
#[ignore = "prints comparison tables; run explicitly"]
fn report() {
    const SEEDS: u64 = 2000;
    println!("\nSlowdown uses a same-noise oracle; near50 is conditional on reaching; reach% is the fraction of copies reaching the band.");
    println!(
        "\n{:<24}{:>6}{:>6}{:>5} |{:>8}{:>8}{:>8}{:>6}{:>8}{:>8}{:>7}{:>8}",
        "curve",
        "noise",
        "setup",
        "prep",
        "slow50",
        "slow90",
        "near50",
        "n*",
        "settle",
        "open",
        "shakes",
        "reach%"
    );
    for (name, curve, start) in curves() {
        for sigma in [0.03, 0.10] {
            for setup_secs in [0.3, 2.5] {
                for prepare in [false, true] {
                    let s = Scenario {
                        name,
                        curve,
                        ideal_secs: 180.0,
                        start,
                        sigma,
                        rho: 0.5,
                        setup_secs,
                        prepare,
                    };
                    let total = curve.best(0.0) * s.ideal_secs;
                    let ideal = curve.ideal_elapsed(total);
                    let (mut slow, mut near, mut settled) = (Vec::new(), Vec::new(), Vec::new());
                    let (mut open, mut shakes) = (0.0, 0.0);
                    for seed in 0..SEEDS {
                        let mut rng = Rng(seed);
                        let out = copy(&s, Policy::new(s.start, 1, LIMIT), &mut rng);
                        slow.push(100.0 * (out.elapsed / out.ideal_elapsed - 1.0));
                        if let Some(t) = out.reached_near_best {
                            near.push(t);
                        }
                        settled.push(out.policy.settled() as f64);
                        open += out.connection_secs / out.elapsed / SEEDS as f64;
                        shakes += out.handshakes as f64 / SEEDS as f64;
                    }
                    println!(
                        "{:<24}{:>6.2}{:>6.1}{:>5} |{:>7.1}%{:>7.1}%{:>7.1}s{:>6}{:>8.0}{:>8.1}{:>7.1}{:>8.1}",
                        s.name,
                        sigma,
                        setup_secs,
                        if prepare { "yes" } else { "no" },
                        quantile(&mut slow, 0.5),
                        quantile(&mut slow, 0.9),
                        if near.is_empty() { f64::NAN } else { quantile(&mut near, 0.5) },
                        curve.smallest_near_best(ideal),
                        quantile(&mut settled, 0.5),
                        open,
                        shakes,
                        100.0 * near.len() as f64 / SEEDS as f64,
                    );
                }
            }
        }
    }

    // Repeated medium-length copies that start from the remembered count.
    println!("\nremembered count across six 40s copies (median, 90th percentile)");
    for (name, curve, start) in curves() {
        let s = Scenario {
            name,
            curve,
            ideal_secs: 40.0,
            start,
            sigma: 0.05,
            rho: 0.5,
            setup_secs: 0.3,
            prepare: true,
        };
        let mut remembered = vec![Vec::new(); 6];
        for seed in 0..SEEDS {
            let mut rng = Rng(seed);
            let mut next = Policy::new(s.start, 1, LIMIT);
            for run in remembered.iter_mut() {
                let start = next.active();
                let policy = copy(&s, next, &mut rng).policy;
                let count = if policy.measured() {
                    policy.recommended()
                } else {
                    start
                };
                run.push(count as f64);
                next = if policy.measured() && policy.discovery_complete() {
                    Policy::refine(count, 1, LIMIT)
                } else {
                    Policy::new(count, 1, LIMIT)
                };
            }
        }
        let row: Vec<String> = remembered
            .iter_mut()
            .map(|run| format!("{:>3.0}/{:<3.0}", quantile(run, 0.5), quantile(run, 0.9)))
            .collect();
        println!(
            "{:<24} n*={:<3} {}",
            name,
            curve.smallest_near_best(0.0),
            row.join(" ")
        );
    }
}

#[test]
fn noiseless_knee_is_found_and_the_copy_completes() {
    let (name, curve, start) = curves()[0];
    let s = Scenario {
        name,
        curve,
        ideal_secs: 600.0,
        start,
        sigma: 0.0,
        rho: 0.0,
        setup_secs: 0.3,
        prepare: false,
    };
    let out = copy(&s, Policy::new(start, 1, LIMIT), &mut Rng(1));
    // This checks discovery, not the final live count: the policy may be in
    // a probe or have aged out its earlier best by the end of a long copy.
    assert!(out.reached_near_best.is_some_and(|t| t < 20.0));
    assert!(out.elapsed < 600.0 * 1.25, "{}", out.elapsed);
    assert!(out.reached_near_best.is_some());
}

/// A deterministic Cartesian sweep, including wrong remembered starting counts,
/// steep contention, non-power-of-two knees, short copies, and changing paths.
/// Each row is reproducible without retaining generated input files.
#[test]
#[ignore = "prints a scenario sweep; run explicitly"]
fn sweep() {
    println!("family,knee,start,seconds,noise,rho,setup,slow50,slow90,near_time_pct,settled_rate_pct,miss_pct,tail_rollback_pct");
    for family in ["knee", "decline", "rise", "fall"] {
        for knee in [1, 4, 12, 32] {
            let curve = match family {
                "knee" => Curve::Knee {
                    per_worker: 100.0 / knee as f64,
                    cap: 100.0,
                },
                "decline" => Curve::Decline {
                    per_worker: 100.0 / knee as f64,
                    cap: 100.0,
                    loss: 0.5,
                },
                "rise" => Curve::Shift {
                    per_worker: 100.0 / knee as f64,
                    before: 100.0,
                    after: 400.0,
                    at: 37.0,
                },
                _ => Curve::Shift {
                    per_worker: 100.0 / knee as f64,
                    before: 400.0,
                    after: 100.0,
                    at: 37.0,
                },
            };
            for start in [1, 8, 32, 64] {
                for ideal_secs in [40.0, 180.0, 600.0] {
                    for (sigma, rho) in [(0.0, 0.0), (0.1, 0.5), (0.3, 0.9)] {
                        for setup_secs in [0.3, 10.0] {
                            let s = Scenario {
                                name: family,
                                curve,
                                ideal_secs,
                                start,
                                sigma,
                                rho,
                                setup_secs,
                                prepare: true,
                            };
                            let mut slow = Vec::new();
                            let (mut near, mut settled_rate, mut misses) = (0.0, 0.0, 0);
                            let mut rollbacks = 0;
                            let seeds = if sigma == 0.0 { 1 } else { 100 };
                            for seed in 0..seeds {
                                let out = copy(&s, Policy::new(start, 1, LIMIT), &mut Rng(seed));
                                slow.push(100.0 * (out.elapsed / out.ideal_elapsed - 1.0));
                                near += out.near_secs / out.elapsed;
                                settled_rate += curve.rate(out.policy.settled(), out.elapsed)
                                    / curve.best(out.elapsed);
                                rollbacks += usize::from(out.tail_rollback_blocked);
                                misses += usize::from(out.reached_near_best.is_none());
                            }
                            println!("{family},{knee},{start},{ideal_secs},{sigma},{rho},{setup_secs},{:.2},{:.2},{:.2},{:.2},{:.2},{:.2}",
                                quantile(&mut slow, 0.5), quantile(&mut slow, 0.9),
                                100.0 * near / seeds as f64, 100.0 * settled_rate / seeds as f64, 100.0 * misses as f64 / seeds as f64, 100.0 * rollbacks as f64 / seeds as f64);
                        }
                    }
                }
            }
        }
    }
}

fn fixture(curve: Curve) -> Scenario {
    Scenario {
        name: "fixture",
        curve,
        ideal_secs: 40.0,
        start: 8,
        sigma: 0.0,
        rho: 0.0,
        setup_secs: 0.3,
        prepare: true,
    }
}

#[test]
fn oracle_integrates_a_shift_between_sample_boundaries() {
    let curve = Curve::Shift {
        per_worker: 100.0,
        before: 100.0,
        after: 200.0,
        at: 3.7,
    };
    let s = fixture(curve);
    let out = copy(&s, Policy::new(8, 8, 8), &mut Rng(1));
    let expected = curve.ideal_elapsed(curve.best(0.0) * s.ideal_secs);
    assert!((out.elapsed - expected).abs() < 1e-9);
    assert!((out.ideal_elapsed - expected).abs() < 1e-9);
}

#[test]
fn noisy_optimum_has_zero_regret_against_the_same_noise() {
    let mut s = fixture(Curve::Knee {
        per_worker: 100.0,
        cap: 100.0,
    });
    s.sigma = 0.3;
    s.rho = 0.9;
    for seed in 0..100 {
        let out = copy(&s, Policy::new(8, 8, 8), &mut Rng(seed));
        assert!((out.elapsed - out.ideal_elapsed).abs() < 1e-9);
        assert!((out.near_secs - out.elapsed).abs() < 1e-9);
    }
}

#[test]
fn unreachable_optimum_is_not_reported_as_reached() {
    let s = fixture(Curve::Knee {
        per_worker: 1.0,
        cap: 64.0,
    });
    let out = copy(&s, Policy::new(8, 8, 8), &mut Rng(1));
    assert!(out.reached_near_best.is_none());
    assert_eq!(out.near_secs, 0.0);
    assert!((out.elapsed / out.ideal_elapsed - 8.0).abs() < 1e-9);
}

#[test]
fn preparation_waits_for_actual_connection_readiness() {
    let mut s = fixture(Curve::Knee {
        per_worker: 1.0,
        cap: 16.0,
    });
    s.prepare = true;
    s.ideal_secs = 600.0;
    s.setup_secs = 30.0;
    let out = copy(&s, Policy::new(8, 1, LIMIT), &mut Rng(1));
    assert_eq!(out.reached_near_best, Some(30.0));
    s.prepare = false;
    let out = copy(&s, Policy::new(8, 1, LIMIT), &mut Rng(1));
    assert_eq!(out.reached_near_best, Some(37.5));
}

#[test]
#[ignore = "prints decision traces; run explicitly"]
fn diagnostics() {
    let cases = [
        (
            "capacity rises",
            Curve::Shift {
                per_worker: 100.0 / 12.0,
                before: 100.0,
                after: 400.0,
                at: 37.0,
            },
            8,
            600.0,
        ),
        (
            "narrow optimum",
            Curve::Decline {
                per_worker: 100.0 / 12.0,
                cap: 100.0,
                loss: 0.5,
            },
            64,
            600.0,
        ),
        (
            "overprovisioned start",
            Curve::Decline {
                per_worker: 100.0,
                cap: 100.0,
                loss: 0.5,
            },
            8,
            40.0,
        ),
    ];
    for (name, curve, start, ideal_secs) in cases.into_iter().chain([
        ("capacity rises, long run", cases[0].1, 8, 6000.0),
        ("below ceiling", cases[1].1, 63, 600.0),
        (
            "steady path, long run",
            Curve::Knee {
                per_worker: 100.0 / 32.0,
                cap: 100.0,
            },
            8,
            1800.0,
        ),
    ]) {
        let s = Scenario {
            name,
            start,
            ideal_secs,
            ..fixture(curve)
        };
        println!("\n{name}: start={start}, initial-rate seconds={ideal_secs}");
        let mut previous = None;
        let out = copy_observing(&s, Policy::new(start, 1, LIMIT), &mut Rng(0), |t, p| {
            let key = (p.active(), p.n);
            if previous != Some(key) {
                println!(
                    "t={t:.1} active={} candidate={} settled={} tick={} due={:?} state={:?}",
                    p.active(),
                    p.n,
                    p.settled(),
                    p.tick,
                    p.due,
                    p.state
                );
                previous = Some(key);
            }
        });
        println!(
            "elapsed={:.2} oracle={:.2} near={:.1}% settled_rate={:.1}%",
            out.elapsed,
            out.ideal_elapsed,
            100.0 * out.near_secs / out.elapsed,
            100.0 * curve.rate(out.policy.settled(), out.elapsed) / curve.best(out.elapsed)
        );
    }
}

#[test]
fn rollback_is_not_blocked_by_probe_admission() {
    let mut s = fixture(Curve::Knee {
        per_worker: 1.0,
        cap: 2.0,
    });
    s.prepare = false;
    s.ideal_secs = 2.0;
    s.setup_secs = 30.0;
    // The driver has just rejected a one-worker downward probe and asked to
    // restore two workers. Reconnecting takes longer than the remaining copy.
    let mut policy = Policy::new(1, 1, LIMIT);
    policy.n = 2;
    policy.state = State::Hold;
    let out = copy(&s, policy, &mut Rng(0));
    assert!(!out.tail_rollback_blocked);
    assert_eq!(out.policy.active(), 1);
    assert_eq!(out.elapsed, 4.0);
    assert_eq!(out.ideal_elapsed, 2.0);
}

#[test]
fn analytic_optimum_matches_exhaustive_worker_search() {
    let extra = [
        Curve::Decline {
            per_worker: 7.0,
            cap: 100.0,
            loss: 0.5,
        },
        Curve::Decline {
            per_worker: 100.0,
            cap: 1.0,
            loss: 0.5,
        },
        Curve::Decline {
            per_worker: 1.0,
            cap: 1000.0,
            loss: 0.5,
        },
    ];
    for curve in curves().into_iter().map(|(_, curve, _)| curve).chain(extra) {
        for t in [0.0, 37.0, 60.0, 600.0] {
            let exhaustive = (1..=LIMIT).map(|n| curve.rate(n, t)).fold(0.0, f64::max);
            assert!((curve.best(t) - exhaustive).abs() < 1e-9);
        }
    }
}

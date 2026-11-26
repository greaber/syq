//! Discrete-time simulation of [`Policy`] and the live measurement window against synthetic
//! throughput curves. It answers statistical questions that a handful of
//! hardware runs cannot: how often a rule helps, how much throughput the
//! search costs, and whether the remembered count drifts across copies.
//!
//! The simulation feeds half-second intervals to the live measurement window.
//! Reductions apply at once and increases wait for connection setup while the
//! settled count refreshes its baseline. It does not model handshakes competing
//! with the transfer, partial counters, or congestion after activation.
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
    /// Gentle scaling with a fixed fractional gain on every doubling.
    Gentle { base: f64, gain_per_doubling: f64 },
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
            Curve::Gentle {
                base,
                gain_per_doubling,
            } => base * (1.0 + gain_per_doubling).powf(n.log2()),
        }
    }

    fn best_for(self, t: f64, limit: usize) -> f64 {
        match self {
            Curve::Decline {
                per_worker, cap, ..
            } => {
                let knee = cap / per_worker;
                self.rate((knee.floor() as usize).clamp(1, limit), t)
                    .max(self.rate((knee.ceil() as usize).clamp(1, limit), t))
            }
            _ => self.rate(limit, t),
        }
    }

    fn best(self, t: f64) -> f64 {
        self.best_for(t, LIMIT)
    }

    /// Smallest count within the policy's own tolerance of the best rate.
    fn smallest_near_best_for(self, t: f64, limit: usize) -> usize {
        let floor = self.best_for(t, limit) * (1.0 - NEAR_BEST_TOLERANCE);
        (1..=limit).find(|&n| self.rate(n, t) >= floor).unwrap()
    }

    fn smallest_near_best(self, t: f64) -> usize {
        self.smallest_near_best_for(t, LIMIT)
    }

    fn ideal_elapsed_for(self, total: f64, limit: usize) -> f64 {
        match self {
            Curve::Shift { at, .. } if self.best_for(0.0, limit) * at < total => {
                at + (total - self.best_for(0.0, limit) * at) / self.best_for(at, limit)
            }
            _ => total / self.best_for(0.0, limit),
        }
    }

    fn ideal_elapsed(self, total: f64) -> f64 {
        self.ideal_elapsed_for(total, LIMIT)
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
    /// Measured (active workers, rate) samples, as history would record them.
    observations: Vec<(usize, f64, f64)>,
}

fn copy(s: &Scenario, policy: Policy, rng: &mut Rng) -> Outcome {
    copy_observing(s, policy, rng, |_, _| {})
}

fn copy_observing(
    s: &Scenario,
    policy: Policy,
    rng: &mut Rng,
    observe: impl FnMut(f64, &Policy),
) -> Outcome {
    copy_with_options(s, policy, rng, LIMIT, 0.0, observe)
}

fn copy_with_options(
    s: &Scenario,
    mut policy: Policy,
    rng: &mut Rng,
    limit: usize,
    ramp_secs: f64,
    mut observe: impl FnMut(f64, &Policy),
) -> Outcome {
    let total = s.curve.best_for(0.0, limit) * s.ideal_secs;
    let (mut t, mut done) = (0.0f64, 0.0f64);
    let mut active = policy.active();
    let mut ramp: Option<(usize, f64)> = None;
    // Initial connections are already ready: elapsed time starts with copying.
    let mut connections = vec![0.0f64; active];
    let mut open = active;
    let mut handshakes = active;
    let mut connection_secs = 0.0;
    let mut evidence = evidence::Evidence::default();
    let (mut sample_start, mut sample_bytes) = (0.0f64, 0.0f64);
    let mut noise_end = SAMPLE_SECS;
    let (mut ideal_done, mut ideal_elapsed, mut near_secs) = (0.0, None, 0.0);
    let mut last_rate: Option<f64> = None;
    let mut reached = None;
    let mut tail_rollback_blocked = false;
    let mut observations = Vec::new();
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
                &evidence,
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
            ramp = None;
            policy.activated();
            evidence.clear();
            (sample_start, sample_bytes) = (t, 0.0);
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
        let best_now = s.curve.best_for(t, limit);
        if reached.is_none() && s.curve.rate(active, t) >= best_now * (1.0 - NEAR_BEST_TOLERANCE) {
            reached = Some(t);
        }

        let base_rate = s.curve.rate(active, t);
        let eff_rate = match ramp {
            Some((prev, r_start)) if ramp_secs > 0.0 && t - r_start < ramp_secs => {
                let prev_rate = s.curve.rate(prev, t);
                let frac = 0.2 + 0.8 * ((t - r_start) / ramp_secs).clamp(0.0, 1.0);
                prev_rate + (base_rate - prev_rate) * frac
            }
            _ => base_rate,
        };
        let rate = eff_rate * noise;
        let sample_end = sample_start + 0.5;
        let mut until = ready_at.map_or(sample_end, |ready| ready.min(sample_end));
        until = until.min(noise_end).min(((t / 0.25).floor() + 1.0) * 0.25);
        if let Curve::Shift { at, .. } = s.curve {
            if t < at {
                until = until.min(at);
            }
        }
        let dt = (until - t).max(0.0).min((total - done) / rate);
        let ideal_rate = best_now * noise;
        if ideal_elapsed.is_none() && ideal_done + ideal_rate * dt >= total {
            ideal_elapsed = Some(t + (total - ideal_done) / ideal_rate);
        }
        ideal_done += ideal_rate * dt;
        if s.curve.rate(active, t) >= best_now * (1.0 - NEAR_BEST_TOLERANCE) {
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
                observations,
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
            let prev = active;
            active = policy.n;
            if active > prev && ramp_secs > 0.0 {
                ramp = Some((prev, t));
            }
            policy.activated();
            evidence.clear();
            (sample_start, sample_bytes) = (t, 0.0);
            continue;
        }

        if t < sample_end {
            continue;
        }
        if tail_blocks_increase {
            (sample_start, sample_bytes) = (t, 0.0);
            continue;
        }
        let seconds = t - sample_start;
        let measured = sample_bytes / seconds;
        (sample_start, sample_bytes) = (t, 0.0);
        last_rate = Some(measured);
        let enough = total - done >= measured * SAMPLE_SECS * MEASUREMENT_SAMPLES;
        if enough {
            observations.push((active, measured, seconds));
        }
        if policy.n > active && !enough {
            policy.cancel_unapplied();
            evidence.clear();
            continue;
        }
        let base = if policy.n == active {
            policy.probe_base()
        } else {
            None
        };
        if let Some(score) = evidence.push(measured, seconds, base.unwrap_or_default()) {
            evidence.clear();
            if policy.n > active {
                policy.refresh_warming_baseline(score.rate);
            } else {
                policy.observe(score.rate);
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
        let key = history::tests::key("a");
        // Each copy writes a real history store, so use fewer seeds here.
        for seed in 0..SEEDS / 10 {
            let mut rng = Rng(seed);
            let temp = crate::test_support::tempdir().unwrap();
            let path = temp.path().join("history.sqlite");
            for run in remembered.iter_mut() {
                // Start each copy as production does, from the recorded history.
                let writer = history::tests::recorder(&path);
                let next = match writer.starting_count(&key, false, s.start) {
                    Some(hint) if hint.refine => Policy::refine(hint.workers, 1, LIMIT),
                    Some(hint) => Policy::new(hint.workers, 1, LIMIT),
                    None => Policy::new(s.start, 1, LIMIT),
                };
                let out = copy(&s, next, &mut rng);
                writer.context(&key);
                writer.event(
                    "learning_context",
                    serde_json::json!({"consistent":true,"automatic":true}),
                );
                let mut segment = None;
                for &(workers, rate, seconds) in &out.observations {
                    if segment != Some(workers) {
                        writer.event("transition", serde_json::json!({}));
                        segment = Some(workers);
                    }
                    writer.event(
                        "observation",
                        serde_json::json!({"active":workers,"seconds":seconds,
                            "rate":rate,"usable":true}),
                    );
                }
                writer.complete(true, serde_json::json!({}));
                let count = writer
                    .starting_count(&key, false, s.start)
                    .map_or(s.start, |hint| hint.workers);
                run.push(count as f64);
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
    assert_eq!(out.reached_near_best, Some(s.setup_secs + SAMPLE_SECS));
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
        Curve::Gentle {
            base: 100.0,
            gain_per_doubling: 0.08,
        },
    ];
    for curve in curves().into_iter().map(|(_, curve, _)| curve).chain(extra) {
        for t in [0.0, 37.0, 60.0, 600.0] {
            let exhaustive = (1..=LIMIT).map(|n| curve.rate(n, t)).fold(0.0, f64::max);
            assert!((curve.best(t) - exhaustive).abs() < 1e-9);
        }
    }
}

fn record_sqlite_observations(
    writer: &history::Recorder,
    key: &history::ContextKey,
    observations: &[(usize, f64, f64)],
) {
    writer.context(key);
    writer.event(
        "learning_context",
        serde_json::json!({"consistent":true,"automatic":true}),
    );
    let mut segment = None;
    for &(workers, rate, seconds) in observations {
        if segment != Some(workers) {
            writer.event("transition", serde_json::json!({}));
            segment = Some(workers);
        }
        writer.event(
            "observation",
            serde_json::json!({"active":workers,"seconds":seconds,"rate":rate,"usable":true}),
        );
    }
    writer.complete(true, serde_json::json!({}));
}

#[test]
fn noisy_flat_copies_do_not_ratchet_across_repeated_runs() {
    let s = Scenario {
        name: "flat",
        curve: Curve::Knee {
            per_worker: 100.0,
            cap: 100.0,
        },
        ideal_secs: 40.0,
        start: 8,
        sigma: 0.05,
        rho: 0.5,
        setup_secs: 0.3,
        prepare: true,
    };
    let key = history::tests::key("a");
    let mut final_starts = Vec::new();
    for seed in 0..30 {
        let mut rng = Rng(seed);
        let temp = crate::test_support::tempdir().unwrap();
        let path = temp.path().join("history.sqlite");
        let mut last = 8;
        for _ in 0..20 {
            let writer = history::tests::recorder(&path);
            let policy = match writer.starting_count(&key, false, s.start) {
                Some(hint) => {
                    last = hint.workers;
                    if hint.refine {
                        Policy::refine(hint.workers, 1, 256)
                    } else {
                        Policy::new(hint.workers, 1, 256)
                    }
                }
                None => Policy::new(8, 1, 256),
            };
            let out = copy_with_options(&s, policy, &mut rng, 256, 0.0, |_, _| {});
            record_sqlite_observations(&writer, &key, &out.observations);
        }
        final_starts.push(last as f64);
    }
    let med = quantile(&mut final_starts, 0.5);
    let p90 = quantile(&mut final_starts, 0.9);
    assert!(
        (6.0..=8.0).contains(&med) && p90 <= 12.0,
        "med={med} p90={p90}"
    );
}

#[test]
fn flat_large_file_history_does_not_slow_later_small_file_copies() {
    let flat = Scenario {
        name: "large-flat",
        curve: Curve::Knee {
            per_worker: 100.0,
            cap: 100.0,
        },
        ideal_secs: 40.0,
        start: super::START_SSH,
        sigma: 0.05,
        rho: 0.5,
        setup_secs: 0.3,
        prepare: true,
    };
    let small_files = Scenario {
        name: "small-files",
        curve: Curve::Knee {
            per_worker: 100.0 / 16.0,
            cap: 100.0,
        },
        ideal_secs: 40.0,
        start: super::START_SSH,
        sigma: 0.05,
        rho: 0.5,
        setup_secs: 0.3,
        prepare: true,
    };
    let key = history::tests::key("a");
    let mut rng = Rng(0);
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("history.sqlite");
    for _ in 0..5 {
        let writer = history::tests::recorder(&path);
        let hint = writer.starting_count(&key, false, super::START_SSH);
        let start = hint.map_or(super::START_SSH, |h| h.workers);
        let out = copy_with_options(
            &flat,
            Policy::new(start, 1, 64),
            &mut rng,
            64,
            0.0,
            |_, _| {},
        );
        record_sqlite_observations(&writer, &key, &out.observations);
    }
    let writer = history::tests::recorder(&path);
    let next_start = writer
        .starting_count(&key, false, super::START_SSH)
        .map_or(super::START_SSH, |h| h.workers);
    assert!(next_start >= super::START_SSH, "start={next_start}");
    let out = copy_with_options(
        &small_files,
        Policy::new(next_start, 1, 64),
        &mut rng,
        64,
        0.0,
        |_, _| {},
    );
    assert!(
        out.policy.settled() >= 16,
        "settled={}",
        out.policy.settled()
    );
    assert!(
        out.elapsed / out.ideal_elapsed < 1.15,
        "slowdown={:.2}%",
        100.0 * (out.elapsed / out.ideal_elapsed - 1.0)
    );
}

#[test]
fn inflated_start_self_heals_toward_knee_with_sqlite_history() {
    let s = Scenario {
        name: "knee-12-heals",
        curve: Curve::Knee {
            per_worker: 100.0 / 12.0,
            cap: 100.0,
        },
        ideal_secs: 40.0,
        start: 64,
        sigma: 0.05,
        rho: 0.5,
        setup_secs: 0.3,
        prepare: true,
    };
    let key = history::tests::key("a");
    let mut final_starts = Vec::new();
    for seed in 0..20 {
        let mut rng = Rng(seed);
        let temp = crate::test_support::tempdir().unwrap();
        let path = temp.path().join("history.sqlite");
        let mut last = 64;
        for _ in 0..20 {
            let writer = history::tests::recorder(&path);
            let policy = match writer.starting_count(&key, false, super::START_SSH) {
                Some(hint) => {
                    last = hint.workers;
                    if hint.refine {
                        Policy::refine(hint.workers, 1, 256)
                    } else {
                        Policy::new(hint.workers, 1, 256)
                    }
                }
                None => Policy::new(64, 1, 256),
            };
            let out = copy_with_options(&s, policy, &mut rng, 256, 0.0, |_, _| {});
            record_sqlite_observations(&writer, &key, &out.observations);
        }
        final_starts.push(last as f64);
    }
    let med = quantile(&mut final_starts, 0.5);
    let p90 = quantile(&mut final_starts, 0.9);
    assert!(med <= 16.0 && p90 <= 32.0, "med={med} p90={p90}");
}

#[test]
fn slow_connection_ramp_reaches_knee_and_oversized_starts_recover() {
    let ramp = Scenario {
        name: "knee16-ramp",
        curve: Curve::Knee {
            per_worker: 100.0 / 16.0,
            cap: 100.0,
        },
        ideal_secs: 180.0,
        start: 1,
        sigma: 0.0,
        rho: 0.0,
        setup_secs: 1.0,
        prepare: true,
    };
    let out = copy_with_options(
        &ramp,
        Policy::new(1, 1, 64),
        &mut Rng(0),
        64,
        3.5,
        |_, _| {},
    );
    assert!(
        out.policy.settled() >= 16,
        "settled={}",
        out.policy.settled()
    );
    assert!(
        out.elapsed / out.ideal_elapsed < 1.08,
        "slowdown={:.2}%",
        100.0 * (out.elapsed / out.ideal_elapsed - 1.0)
    );

    let flat_hi = Scenario {
        name: "flat-hi",
        curve: Curve::Knee {
            per_worker: 100.0,
            cap: 100.0,
        },
        ideal_secs: 40.0,
        start: 32,
        sigma: 0.0,
        rho: 0.0,
        setup_secs: 0.3,
        prepare: true,
    };
    let out = copy_with_options(
        &flat_hi,
        Policy::new(32, 1, 64),
        &mut Rng(0),
        64,
        0.0,
        |_, _| {},
    );
    assert_eq!(out.policy.settled(), 32);

    let decline_hi = Scenario {
        name: "decline-hi",
        curve: Curve::Decline {
            per_worker: 25.0,
            cap: 100.0,
            loss: 0.5,
        },
        ideal_secs: 40.0,
        start: 32,
        sigma: 0.0,
        rho: 0.0,
        setup_secs: 0.3,
        prepare: true,
    };
    let out = copy_with_options(
        &decline_hi,
        Policy::new(32, 1, 64),
        &mut Rng(0),
        64,
        0.0,
        |_, _| {},
    );
    assert_eq!(out.policy.settled(), 4);
}

#[test]
#[ignore = "prints expanded production benchmarks including SQLite history and stress curves"]
fn production_stress_report() {
    println!("\n=== SINGLE-COPY STRESS BENCHMARK (100 seeds, sigma=0.05, rho=0.5, limit=64) ===");
    for (name, curve, start, ideal_secs, setup_secs, ramp_secs, sigma, rho) in [
        (
            "knee 16 (1) 180s",
            Curve::Knee {
                per_worker: 100.0 / 16.0,
                cap: 100.0,
            },
            1,
            180.0,
            0.3,
            0.0,
            0.05,
            0.5,
        ),
        (
            "knee 12 (8) 180s",
            Curve::Knee {
                per_worker: 10.0,
                cap: 120.0,
            },
            8,
            180.0,
            0.3,
            0.0,
            0.05,
            0.5,
        ),
        (
            "flat (1) 180s",
            Curve::Knee {
                per_worker: 100.0,
                cap: 100.0,
            },
            1,
            180.0,
            0.3,
            0.0,
            0.05,
            0.5,
        ),
        (
            "decline at 8 (1) 180s",
            Curve::Decline {
                per_worker: 12.5,
                cap: 100.0,
                loss: 0.04,
            },
            1,
            180.0,
            0.3,
            0.0,
            0.05,
            0.5,
        ),
        (
            "rise 100->400 (8) 180s",
            Curve::Shift {
                per_worker: 4.0,
                before: 100.0,
                after: 400.0,
                at: 37.0,
            },
            8,
            180.0,
            0.3,
            0.0,
            0.05,
            0.5,
        ),
        (
            "fall 400->100 (8) 180s",
            Curve::Shift {
                per_worker: 8.0,
                before: 400.0,
                after: 100.0,
                at: 37.0,
            },
            8,
            180.0,
            0.3,
            0.0,
            0.05,
            0.5,
        ),
        (
            "flat hi (32) 40s",
            Curve::Knee {
                per_worker: 100.0,
                cap: 100.0,
            },
            32,
            40.0,
            0.3,
            0.0,
            0.05,
            0.5,
        ),
        (
            "decline0.5 hi (32) 40s",
            Curve::Decline {
                per_worker: 25.0,
                cap: 100.0,
                loss: 0.5,
            },
            32,
            40.0,
            0.3,
            0.0,
            0.05,
            0.5,
        ),
        (
            "knee16 ramp3.5s (1) 180s",
            Curve::Knee {
                per_worker: 100.0 / 16.0,
                cap: 100.0,
            },
            1,
            180.0,
            1.0,
            3.5,
            0.05,
            0.5,
        ),
        (
            "gentle +5%/dbl (8) 180s",
            Curve::Gentle {
                base: 100.0,
                gain_per_doubling: 0.05,
            },
            8,
            180.0,
            0.3,
            0.0,
            0.05,
            0.5,
        ),
        (
            "gentle +8%/dbl (8) 180s",
            Curve::Gentle {
                base: 100.0,
                gain_per_doubling: 0.08,
            },
            8,
            180.0,
            0.3,
            0.0,
            0.05,
            0.5,
        ),
        (
            "gentle +15%/dbl (8) 180s",
            Curve::Gentle {
                base: 100.0,
                gain_per_doubling: 0.15,
            },
            8,
            180.0,
            0.3,
            0.0,
            0.05,
            0.5,
        ),
        (
            "knee 12 (8) sigma=0.3 180s",
            Curve::Knee {
                per_worker: 10.0,
                cap: 120.0,
            },
            8,
            180.0,
            0.3,
            0.0,
            0.30,
            0.9,
        ),
        (
            "knee 32 (8) sigma=0.3 180s",
            Curve::Knee {
                per_worker: 100.0 / 32.0,
                cap: 100.0,
            },
            8,
            180.0,
            0.3,
            0.0,
            0.30,
            0.9,
        ),
        (
            "linear 64 (8) sigma=0.3 180s",
            Curve::Knee {
                per_worker: 2.0,
                cap: 1e9,
            },
            8,
            180.0,
            0.3,
            0.0,
            0.30,
            0.9,
        ),
        (
            "knee 16 (1) setup=10s 180s",
            Curve::Knee {
                per_worker: 100.0 / 16.0,
                cap: 100.0,
            },
            1,
            180.0,
            10.0,
            0.0,
            0.05,
            0.5,
        ),
        (
            "knee 16 ramp=6s (1) 180s",
            Curve::Knee {
                per_worker: 100.0 / 16.0,
                cap: 100.0,
            },
            1,
            180.0,
            1.0,
            6.0,
            0.05,
            0.5,
        ),
    ] {
        let s = Scenario {
            name,
            curve,
            ideal_secs,
            start,
            sigma,
            rho,
            setup_secs,
            prepare: true,
        };
        let (mut slow, mut settled) = (Vec::new(), Vec::new());
        let mut open = 0.0;
        for seed in 0..100 {
            let out = copy_with_options(
                &s,
                Policy::new(start, 1, 64),
                &mut Rng(seed),
                64,
                ramp_secs,
                |_, _| {},
            );
            slow.push(100.0 * (out.elapsed / out.ideal_elapsed - 1.0));
            settled.push(out.policy.settled() as f64);
            open += out.connection_secs / out.elapsed / 100.0;
        }
        println!(
            "{:<28} | slow {:>5.1}/{:<5.1}% st={:>3.0} open={:>5.1}",
            name,
            quantile(&mut slow, 0.5),
            quantile(&mut slow, 0.9),
            quantile(&mut settled, 0.5),
            open
        );
    }

    println!("\n=== PRODUCTION SQLITE 100-COPY SIMULATION (25 seeds, 40s copies, sigma=0.05, rho=0.5) ===");
    let key = history::tests::key("a");
    let check_at = [0usize, 7, 29, 99];
    for (name, curve, start, default_start, limit) in [
        (
            "flat (start 8)",
            Curve::Knee {
                per_worker: 100.0,
                cap: 100.0,
            },
            8,
            super::START_SSH,
            256,
        ),
        (
            "knee 12 (start 8)",
            Curve::Knee {
                per_worker: 100.0 / 12.0,
                cap: 100.0,
            },
            8,
            super::START_SSH,
            256,
        ),
        (
            "knee 12 (start 64)",
            Curve::Knee {
                per_worker: 100.0 / 12.0,
                cap: 100.0,
            },
            64,
            super::START_SSH,
            256,
        ),
        (
            "knee 32 (start 8)",
            Curve::Knee {
                per_worker: 100.0 / 32.0,
                cap: 100.0,
            },
            8,
            super::START_SSH,
            256,
        ),
        (
            "decline4 (start 32)",
            Curve::Decline {
                per_worker: 25.0,
                cap: 100.0,
                loss: 0.5,
            },
            32,
            32,
            64,
        ),
        (
            "gentle +8%/dbl (8)",
            Curve::Gentle {
                base: 100.0,
                gain_per_doubling: 0.08,
            },
            8,
            super::START_SSH,
            256,
        ),
        (
            "gentle +15%/dbl (8)",
            Curve::Gentle {
                base: 100.0,
                gain_per_doubling: 0.15,
            },
            8,
            super::START_SSH,
            256,
        ),
    ] {
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
        let mut starts = [Vec::new(), Vec::new(), Vec::new(), Vec::new()];
        let mut slows = [Vec::new(), Vec::new(), Vec::new(), Vec::new()];
        for seed in 0..25 {
            let mut rng = Rng(seed);
            let temp = crate::test_support::tempdir().unwrap();
            let path = temp.path().join("history.sqlite");
            for c in 0..100 {
                let writer = history::tests::recorder(&path);
                let hint = writer.starting_count(&key, false, default_start);
                let cur_start = hint.as_ref().map_or(start, |h| h.workers);
                let policy = match hint {
                    Some(h) if h.refine => Policy::refine(h.workers, 1, limit),
                    Some(h) => Policy::new(h.workers, 1, limit),
                    None => Policy::new(start, 1, limit),
                };
                let out = copy_with_options(&s, policy, &mut rng, limit, 0.0, |_, _| {});
                record_sqlite_observations(&writer, &key, &out.observations);
                if let Some(pos) = check_at.iter().position(|&k| k == c) {
                    starts[pos].push(cur_start as f64);
                    slows[pos].push(100.0 * (out.elapsed / out.ideal_elapsed - 1.0));
                }
            }
        }
        let cols: Vec<String> = (0..4)
            .map(|i| {
                format!(
                    "{:.0}/{:.0}({:.1}%)",
                    quantile(&mut starts[i], 0.5),
                    quantile(&mut starts[i], 0.9),
                    quantile(&mut slows[i], 0.5),
                )
            })
            .collect();
        println!("{:<22} {:>3} | {}", name, limit, cols.join(" "));
    }
}

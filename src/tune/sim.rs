//! Discrete-time simulation of [`Policy`] and [`Sampler`] against synthetic
//! throughput curves. It answers statistical questions that a handful of
//! hardware runs cannot: how often a rule helps, how much throughput the
//! search costs, and whether the remembered count drifts across copies.
//!
//! The loop mirrors the decisions in [`run`] without threads or a clock:
//! reductions apply at once, increases wait for connection setup while the
//! settled count refreshes its baseline, the tail stops measuring, and two
//! collapsed samples short-circuit a probe. It does not model handshakes
//! competing with the transfer or connections warming up after activation.
//! Results are only as good as the curves and noise fed in; check those
//! against real transfers before trusting a small difference.
//!
//! `cargo test --bin syq tune::sim::report -- --ignored --nocapture` prints
//! the comparison tables.

use super::*;

const SAMPLE_SECS: f64 = 2.5;
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
        (1..=LIMIT).map(|n| self.rate(n, t)).fold(0.0, f64::max)
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
    /// Copy length as seconds at the best rate.
    ideal_secs: f64,
    start: usize,
    /// Log-normal per-sample noise, with AR(1) correlation between samples.
    sigma: f64,
    rho: f64,
    setup_secs: f64,
    /// Open the likely next increase during a measurement and keep rollback
    /// connections through a probe, as connection preparation does.
    prepare: bool,
}

struct Outcome {
    elapsed: f64,
    reached_near_best: Option<f64>,
    connection_secs: f64,
    handshakes: usize,
    policy: Policy,
}

fn connections_wanted(policy: &Policy, active: usize, open: usize, prepare: bool) -> usize {
    let needed = policy.n.max(active);
    if !prepare {
        return if needed == 1 { 2 } else { needed };
    }
    let needed = needed.max(policy.settled());
    match policy.state {
        State::Initial
        | State::Explore {
            direction: Direction::Up,
            ..
        } => open.max(needed).max(policy.target(Direction::Up)),
        State::Explore { .. } => open.max(needed),
        State::Hold if policy.due[Direction::Up.index()] <= policy.tick + 1 => {
            needed.max(policy.target(Direction::Up))
        }
        State::Hold => needed,
    }
}

fn copy(s: &Scenario, mut policy: Policy, rng: &mut Rng) -> Outcome {
    let total = s.curve.best(0.0) * s.ideal_secs;
    let (mut t, mut done) = (0.0f64, 0.0f64);
    let mut active = policy.active();
    let mut open = active;
    let mut handshakes = active;
    let mut connection_secs = 0.0;
    let mut sampler = Sampler::default();
    sampler.reset();
    let (mut sample_start, mut sample_bytes) = (0.0f64, 0.0f64);
    let mut ready_at: Option<f64> = None;
    let mut collapsed = 0;
    let mut last_rate: Option<f64> = None;
    let mut reached = None;
    let mut drift = rng.normal();
    let mut noise = (s.sigma * drift - 0.5 * s.sigma * s.sigma).exp();

    loop {
        let wanted = connections_wanted(&policy, active, open, s.prepare);
        handshakes += wanted.saturating_sub(open);
        let candidate_prepared = policy.n <= open;
        open = wanted;

        if policy.n < active {
            active = policy.n;
            policy.activated();
            sampler.reset();
            (sample_start, sample_bytes, collapsed) = (t, 0.0, 0);
            continue;
        }
        if policy.n > active && ready_at.is_none() {
            let needs = last_rate.map_or(0.0, |rate| rate * SAMPLE_SECS * MEASUREMENT_SAMPLES);
            if total - done < needs {
                policy.cancel_unapplied();
                continue;
            }
            ready_at = Some(if candidate_prepared {
                t
            } else {
                t + s.setup_secs
            });
        }
        if reached.is_none()
            && s.curve.rate(active, t) >= s.curve.best(t) * (1.0 - NEAR_BEST_TOLERANCE)
        {
            reached = Some(t);
        }

        let rate = s.curve.rate(active, t) * noise;
        let sample_end = sample_start + SAMPLE_SECS;
        let until = ready_at.map_or(sample_end, |ready| ready.min(sample_end));
        let dt = (until - t).max(0.0);
        if done + rate * dt >= total {
            let last = (total - done) / rate;
            connection_secs += open as f64 * last;
            t += last;
            break;
        }
        done += rate * dt;
        sample_bytes += rate * dt;
        connection_secs += open as f64 * dt;
        t = until;

        if ready_at.is_some_and(|ready| ready <= t) {
            ready_at = None;
            active = policy.n;
            policy.activated();
            sampler.reset();
            (sample_start, sample_bytes, collapsed) = (t, 0.0, 0);
            continue;
        }

        let measured = sample_bytes / SAMPLE_SECS;
        (sample_start, sample_bytes) = (t, 0.0);
        drift = s.rho * drift + (1.0 - s.rho * s.rho).sqrt() * rng.normal();
        noise = (s.sigma * drift - 0.5 * s.sigma * s.sigma).exp();
        last_rate = Some(measured);
        let enough = total - done >= measured * SAMPLE_SECS * MEASUREMENT_SAMPLES;
        if ready_at.is_some() {
            if !enough {
                policy.cancel_unapplied();
                ready_at = None;
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
    Outcome {
        elapsed: t,
        reached_near_best: reached,
        connection_secs,
        handshakes,
        policy,
    }
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
    println!(
        "\n{:<24}{:>6}{:>6}{:>5} |{:>8}{:>8}{:>8}{:>6}{:>8}{:>8}{:>7}",
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
        "shakes"
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
                        slow.push(100.0 * (out.elapsed / ideal - 1.0));
                        near.push(out.reached_near_best.unwrap_or(out.elapsed));
                        settled.push(out.policy.settled() as f64);
                        open += out.connection_secs / out.elapsed / SEEDS as f64;
                        shakes += out.handshakes as f64 / SEEDS as f64;
                    }
                    println!(
                        "{:<24}{:>6.2}{:>6.1}{:>5} |{:>7.1}%{:>7.1}%{:>7.1}s{:>6}{:>8.0}{:>8.1}{:>7.1}",
                        s.name,
                        sigma,
                        setup_secs,
                        if prepare { "yes" } else { "no" },
                        quantile(&mut slow, 0.5),
                        quantile(&mut slow, 0.9),
                        quantile(&mut near, 0.5),
                        curve.smallest_near_best(ideal),
                        quantile(&mut settled, 0.5),
                        open,
                        shakes,
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
            prepare: false,
        };
        let mut remembered = vec![Vec::new(); 6];
        for seed in 0..SEEDS {
            let mut rng = Rng(seed);
            let mut next = Policy::new(s.start, 1, LIMIT);
            for run in remembered.iter_mut() {
                let start = next.active();
                let policy = copy(&s, next, &mut rng).policy;
                let count = if policy.measured() {
                    policy.settled()
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
    let best = curve.smallest_near_best(0.0);
    assert!(
        (best..=best + 2).contains(&out.policy.settled()),
        "settled {} for smallest near-best {best}",
        out.policy.settled()
    );
    assert!(out.elapsed < 600.0 * 1.25, "{}", out.elapsed);
    assert!(out.reached_near_best.is_some());
}

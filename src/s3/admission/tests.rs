use super::*;

fn exercise(controller: &mut Controller, optimum: usize) {
    for _ in 0..500 {
        let active = controller.limit;
        let rate = if active <= optimum {
            active as f64
        } else {
            (optimum * optimum) as f64 / active as f64
        };
        controller.observe(rate, active, 10000, 16, 0.0);
    }
    let settled = controller
        .probe
        .as_ref()
        .map_or(controller.limit, |probe| probe.from);
    assert!(
        settled.abs_diff(optimum) <= (optimum / 10).max(1),
        "optimum {optimum}, settled {settled}, active {}",
        controller.limit
    );
}

#[test]
fn resetting_measurements_excludes_the_previous_setting() {
    let mut window = Controller::new(7, 256, false).sampler;
    assert!(window.push(100.0, 100.0, SAMPLE).is_none());
    assert!(window.push(10000.0, 10000.0, SAMPLE).is_none());
    window.reset();
    assert!(window.push(20000.0, 20000.0, SAMPLE).is_none());
    assert!(window.push(10.0, 10.0, SAMPLE).is_none());
    assert_eq!(window.push(20.0, 20.0, SAMPLE), Some((15.0, 15.0)));
}

#[test]
fn old_response_bursts_cannot_accept_a_losing_increase() {
    let mut controller = Controller::new(256, 512, true);
    controller.upper = 512;
    for _ in 0..3 {
        controller.observe(302.6, 256, 10000, 16, 0.0);
    }
    assert_eq!(controller.limit, 384);
    // These rates reproduce a delayed old response wave followed by slower
    // fresh completions. Including 452.5 would falsely accept the increase.
    assert_eq!(controller.observe(150.7, 384, 10000, 16, 150.7), 384);
    assert_eq!(controller.observe(452.5, 384, 10000, 16, 452.5), 384);
    assert_eq!(controller.observe(184.2, 384, 10000, 16, 0.0), 384);
    assert_eq!(controller.observe(193.9, 384, 10000, 16, 0.0), 256);
}

#[test]
fn a_quiet_fresh_window_can_be_part_of_a_useful_probe() {
    let mut controller = Controller::new(256, 1024, true);
    for _ in 0..3 {
        controller.observe(280.0, 256, 10000, 16, 0.0);
    }
    assert_eq!(controller.limit, 512);
    // A healthy HTTP fixture returned 32 fresh responses in one window,
    // then 224 in the next. Rejecting its first window below half the
    // baseline cut useful concurrency and increased the copy time.
    controller.observe(300.0, 512, 10000, 16, 300.0);
    assert_eq!(controller.observe(75.5, 512, 10000, 16, 0.0), 512);
    assert!(controller.probe.is_some());
    assert_eq!(controller.observe(527.0, 512, 10000, 16, 0.0), 512);
    assert!(controller.probe.is_none());
    assert_eq!(controller.lower, 256);
}

#[test]
fn old_only_windows_cannot_reject_an_unmeasured_probe() {
    let mut controller = Controller::new(256, 512, true);
    controller.upper = 512;
    for _ in 0..3 {
        controller.observe(300.0, 256, 10000, 16, 0.0);
    }
    for _ in 0..4 {
        assert_eq!(controller.observe(100.0, 384, 10000, 16, 100.0), 384);
        assert!(controller.probe.is_some());
    }
    controller.observe(360.0, 384, 10000, 16, 0.0);
    assert_eq!(controller.observe(360.0, 384, 10000, 16, 0.0), 384);
    assert!(controller.probe.is_none());
}

#[test]
fn sparse_old_completions_do_not_delay_clear_decisions() {
    let mut controller = Controller::new(256, 512, true);
    controller.upper = 512;
    controller.sampler.seed(300.0, SAMPLE);
    assert_eq!(controller.observe(300.0, 256, 10000, 16, 300.0), 256);
    assert_eq!(controller.observe(300.0, 256, 10000, 16, 2.0), 384);
    assert_eq!(controller.observe(300.0, 384, 10000, 16, 300.0), 384);
    assert_eq!(controller.observe(120.0, 384, 10000, 16, 0.0), 384);
    assert_eq!(controller.observe(115.0, 384, 10000, 16, 5.0), 256);
}

#[test]
fn uncertain_old_work_does_not_reject_a_useful_increase() {
    let mut controller = Controller::new(256, 512, true);
    controller.upper = 512;
    for _ in 0..3 {
        controller.observe(300.0, 256, 10000, 16, 0.0);
    }
    assert_eq!(controller.limit, 384);
    controller.observe(300.0, 384, 10000, 16, 300.0);
    controller.observe(360.0, 384, 10000, 16, 120.0);
    controller.observe(360.0, 384, 10000, 16, 0.0);
    assert!(controller.probe.is_some());
    assert_eq!(controller.observe(360.0, 384, 10000, 16, 0.0), 384);
    assert!(controller.probe.is_none());
}

#[tokio::test(start_paused = true)]
async fn tuning_continues_while_an_old_job_is_still_pending() {
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let copy_peak = peak.clone();
    let copy_gate = gate.clone();
    let copy = tokio::spawn(async move {
        parallel(
            (0..2048).collect(),
            Concurrency {
                initial: 4,
                maximum: Some(16),
                initial_probe_up: true,
                requests: None,
                checking: None,
                outage: None,
            },
            move |job, _| {
                let active = active.clone();
                let peak = copy_peak.clone();
                let gate = copy_gate.clone();
                async move {
                    peak.fetch_max(active.fetch_add(1, SeqCst) + 1, SeqCst);
                    if job == 0 {
                        let _permit = gate.acquire().await.unwrap();
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    active.fetch_sub(1, SeqCst);
                    Ok(Some(1024))
                }
            },
        )
        .await
    });
    tokio::time::sleep(Duration::from_secs(2)).await;
    let peak_before_old_job_finished = peak.load(SeqCst);
    gate.add_permits(1);
    copy.await.unwrap().unwrap();
    assert!(peak_before_old_job_finished > 4);
}

#[test]
fn inherited_request_score_still_excludes_the_handoff_warmup() {
    let mut controller = Controller::new(32, 256, true);
    controller.sampler.seed(1000.0, SAMPLE);
    assert_eq!(controller.observe(100000.0, 32, 10000, 16, 0.0), 32);
    assert_eq!(controller.observe(1000.0, 32, 10000, 16, 0.0), 64);
    assert_eq!(controller.probe.as_ref().unwrap().baseline, 1000.0);
}

#[test]
fn a_short_burst_cannot_outweigh_a_long_slow_window() {
    for reverse in [false, true] {
        let mut samples = [(960.0, SAMPLE), (16.0 / 1.5, Duration::from_millis(1500))];
        if reverse {
            samples.reverse();
        }
        let mut sampler = RateWindow::default();
        assert!(sampler
            .push(samples[0].0, samples[0].0 * 0.5, samples[0].1)
            .is_none());
        let (total, fresh) = sampler
            .push(samples[1].0, samples[1].0 * 0.5, samples[1].1)
            .unwrap();
        assert!((total - 256.0 / 1.75).abs() < 1e-9);
        assert!((fresh - 128.0 / 1.75).abs() < 1e-9);
    }
    let mut controller = Controller::new(256, 1024, true);
    for _ in 0..3 {
        controller.observe(475.0, 256, 10000, 16, 0.0);
    }
    assert_eq!(controller.limit, 512);
    controller.observe(475.0, 512, 10000, 16, 475.0); // Warmup.
    controller.observe_window(960.0, 512, 10000, 16, 0.0, SAMPLE);
    assert_eq!(
        controller.observe_window(16.0 / 1.5, 512, 10000, 16, 0.0, Duration::from_millis(1500)),
        256
    );
}

#[test]
fn scores_include_partial_completion_batches() {
    let mut sampler = Controller::new(7, 256, false).sampler;
    assert!(sampler.push(0.0, 0.0, SAMPLE).is_none()); // Discard the warmup observation.
    let counts = [28.0, 35.0, 35.0, 28.0, 35.0, 35.0];
    let scores: Vec<_> = counts
        .into_iter()
        .filter_map(|rate| sampler.push(rate, rate, SAMPLE))
        .collect();
    assert_eq!(scores.len(), 3);
    let measured = scores.iter().map(|(score, _)| score).sum::<f64>() / scores.len() as f64;
    let delivered = counts.iter().sum::<f64>() / counts.len() as f64;
    assert!((measured - delivered).abs() < 1e-9);
}

#[test]
fn learns_different_optima_and_revisits_changed_conditions() {
    for optimum in [3, 4, 9, 16, 24, 42, 64, 96, 128] {
        for initial_probe_up in [false, true] {
            exercise(&mut Controller::new(32, 256, initial_probe_up), optimum);
        }
    }
    let mut controller = Controller::new(32, 256, false);
    for optimum in [16, 64, 4] {
        exercise(&mut controller, optimum);
    }
}

// A fluid request model: requests finish at the aggregate rate, and a
// reduction must drain the excess before the next setting can be measured.
// Noise changes delivery, not just the controller's reported score.
struct PathModel {
    active: usize,
    completions: f64,
    random: u64,
}

impl PathModel {
    fn sample(&mut self, controller: &mut Controller, optimum: usize, noise: f64) -> f64 {
        self.random ^= self.random << 13;
        self.random ^= self.random >> 7;
        self.random ^= self.random << 17;
        let jitter = 1.0 + noise * (2.0 * self.random as f64 / u64::MAX as f64 - 1.0);
        let rate = if self.active <= optimum {
            self.active as f64
        } else {
            (optimum * optimum) as f64 / self.active as f64
        } * 16.0
            * jitter;
        controller.observe(rate, self.active, 1_000_000, 16, 0.0);
        if controller.limit >= self.active {
            self.active = controller.limit;
        } else {
            self.completions += rate * SAMPLE.as_secs_f64();
            let completed = self.completions.floor() as usize;
            self.completions -= completed as f64;
            self.active = self.active.saturating_sub(completed).max(controller.limit);
        }
        rate / (optimum as f64 * 16.0 * jitter)
    }
}

#[test]
fn small_upward_gains_refine_the_interval_before_growing_again() {
    for (probe_rate, later_rate, next) in [
        (1040.0, 1040.0, 96),
        (1300.0, 1040.0, 96),
        (1400.0, 1400.0, 192),
        (1600.0, 1040.0, 192),
    ] {
        let mut controller = Controller::new(64, 256, true);
        for _ in 0..3 {
            controller.observe(1000.0, 64, 10000, 16, 0.0);
        }
        assert_eq!(controller.limit, 128);
        for _ in 0..3 {
            controller.observe(probe_rate, 128, 10000, 16, 0.0);
        }
        // Both gains are kept. Only the next search direction differs.
        assert_eq!(controller.limit, 128);
        assert!(controller.probe.is_none());
        assert_eq!(controller.lower, 64);
        controller.observe(later_rate, 128, 10000, 16, 0.0);
        assert_eq!(controller.observe(later_rate, 128, 10000, 16, 0.0), next);
    }
}

#[test]
fn partial_fresh_waves_cannot_accept_a_gain_but_can_reject_a_loss() {
    for (rate, expected_probe, expected_limit) in [(190.0, true, 96), (120.0, false, 64)] {
        let mut controller = Controller::new(64, 256, true);
        controller.upper = 128;
        for _ in 0..3 {
            controller.observe(128.0, 64, 10000, 16, 0.0);
        }
        assert_eq!(controller.limit, 96);
        controller.observe_window(128.0, 96, 10000, 16, 128.0, SAMPLE);
        for _ in 0..2 {
            controller.probe_completed += 40;
            controller.observe_window(rate, 96, 10000, 16, 0.0, SAMPLE);
        }
        assert_eq!(controller.probe.is_some(), expected_probe);
        assert_eq!(controller.limit, expected_limit);
        if expected_probe {
            // More replies complete the count at a useful sustained rate.
            controller.probe_completed += 16;
            controller.observe_window(160.0, 96, 10000, 16, 0.0, SAMPLE);
            assert!(controller.probe.is_none());
            assert_eq!(controller.limit, 96);
        }
    }
}

#[test]
fn intermediate_optimum_is_found_before_repeated_upward_probes() {
    let mut controller = Controller::new(64, 256, false);
    controller.lower = 32;
    controller.upper = 128;
    let mut model = PathModel {
        active: 64,
        completions: 0.0,
        random: 251,
    };
    // The request ramp rejected 128, but the optimum lies above 64.
    // Finding a small gain at 96 should lead to testing 80, rather than
    // spending a short copy probing 112 and returning to 96.
    let found = (0..20).any(|_| model.sample(&mut controller, 80, 0.0) >= 0.99);
    assert!(found, "intermediate optimum was not found promptly");
}

#[test]
fn stationary_paths_spend_little_work_on_repeated_probes() {
    for optimum in [1, 2, 3, 4, 8, 32, 128, 256] {
        let mut controller = Controller::new(32, 256, false);
        let mut model = PathModel {
            active: 32,
            completions: 0.0,
            random: 17,
        };
        // Separate initial learning from the recurring cost under review.
        for _ in 0..1000 {
            model.sample(&mut controller, optimum, 0.0);
        }
        let fraction: f64 = (0..4000)
            .map(|_| model.sample(&mut controller, optimum, 0.0))
            .sum::<f64>()
            / 4000.0;
        assert!(
            fraction > 0.97,
            "optimum {optimum}: useful fraction {fraction}"
        );
    }
}

#[test]
fn an_inherited_request_bound_can_reopen() {
    let mut controller = Controller::new(64, 256, false);
    controller.upper = 128;
    let mut model = PathModel {
        active: 64,
        completions: 0.0,
        random: 251,
    };
    // A request probe previously rejected 128. If the path now has more
    // capacity, that hint must not become a permanent request cap.
    let recovered = (0..400).any(|_| model.sample(&mut controller, 256, 0.0) >= 0.9);
    assert!(recovered);
    assert!(controller.limit > 128);
}

#[test]
fn an_inherited_slower_setting_does_not_prevent_decreasing_concurrency() {
    let mut controller = Controller::new(256, 256, false);
    controller.lower = 128;
    let mut model = PathModel {
        active: 256,
        completions: 0.0,
        random: 251,
    };
    // The request ramp established that 128 was slower than 256. The
    // first object probe should refine that interval rather than halve
    // concurrency again. A later capacity loss must still escape it.
    for _ in 0..3 {
        model.sample(&mut controller, 256, 0.0);
    }
    assert!(controller.limit > 128);
    let recovered = (0..400).any(|_| model.sample(&mut controller, 32, 0.0) >= 0.9);
    assert!(
        recovered,
        "an inherited lower bound must remain revisitable"
    );
    let fraction = (0..1000)
        .map(|_| model.sample(&mut controller, 32, 0.0))
        .sum::<f64>()
        / 1000.0;
    assert!(fraction > 0.95, "must sustain the recovery: {fraction}");
}

#[test]
fn probes_discover_capacity_increases_without_a_rate_drop() {
    let mut controller = Controller::new(4, 256, false);
    let mut model = PathModel {
        active: 4,
        completions: 0.0,
        random: 251,
    };
    for _ in 0..2000 {
        model.sample(&mut controller, 4, 0.0);
    }
    // Increasing capacity does not change the rate at the old optimum.
    let recovered = (0..400).any(|_| model.sample(&mut controller, 128, 0.0) >= 0.9);
    assert!(recovered, "periodic probes must discover unused capacity");
    let fraction = (0..1000)
        .map(|_| model.sample(&mut controller, 128, 0.0))
        .sum::<f64>()
        / 1000.0;
    assert!(fraction > 0.95, "must sustain the improvement: {fraction}");
}

#[test]
fn an_ambiguous_revisit_can_fail_its_confirmation() {
    let mut controller = Controller::new(32, 256, false);
    controller.limit = 36;
    controller.rate_variation = 0.1;
    controller.probe = Some(Probe {
        from: 32,
        baseline: 1000.0,
        upward: true,
        revisit: true,
        confirming: false,
    });
    // The first stable score looks 3% better, within the observed variation.
    for _ in 0..3 {
        assert_eq!(controller.observe(1030.0, 36, 10000, 16, 0.0), 36);
    }
    assert!(controller.probe.as_ref().unwrap().confirming);
    // A subsequent score reverses that finding. Restore the accepted limit.
    controller.observe(990.0, 36, 10000, 16, 0.0);
    assert_eq!(controller.observe(990.0, 36, 10000, 16, 0.0), 32);
    assert!(controller.probe.is_none());
}

#[test]
fn probes_discover_modest_capacity_changes() {
    for (before, after) in [(7, 8), (8, 9), (9, 8), (32, 36)] {
        let mut controller = Controller::new(32, 256, false);
        let mut model = PathModel {
            active: 32,
            completions: 0.0,
            random: 17,
        };
        for _ in 0..1000 {
            model.sample(&mut controller, before, 0.0);
        }
        // A modest change can put the optimum between the settled limit
        // and a broad probe. Repeatedly jumping over it must not strand us.
        for _ in 0..1000 {
            model.sample(&mut controller, after, 0.0);
        }
        let fraction = (0..1000)
            .map(|_| model.sample(&mut controller, after, 0.0))
            .sum::<f64>()
            / 1000.0;
        assert!(
            fraction > 0.97,
            "capacity {before}->{after}: useful fraction {fraction}"
        );
    }
}

#[test]
fn adapts_to_noisy_changes_and_drains_decreases() {
    for seed in [17, 251, 902, 1009, 65537] {
        let mut controller = Controller::new(32, 256, false);
        let mut model = PathModel {
            active: 32,
            completions: 0.0,
            random: seed,
        };
        let mut delivered = 0.0;
        let mut possible = 0.0;
        for optimum in [96, 9, 42, 3] {
            for _ in 0..1000 {
                delivered += model.sample(&mut controller, optimum, 0.2) * optimum as f64;
                possible += optimum as f64;
            }
        }
        assert!(
            delivered / possible > 0.8,
            "seed {seed}: useful fraction {}",
            delivered / possible
        );
    }
}

#[test]
fn draining_and_tail_samples_do_not_advance_the_policy() {
    let mut controller = Controller::new(32, 256, false);
    for _ in 0..50 {
        assert_eq!(controller.observe(1000.0, 33, 10000, 16, 0.0), 32);
        assert_eq!(controller.observe(1000.0, 32, 2, 16, 0.0), 32);
    }
    assert!(controller.probe.is_none());
}

#[tokio::test(start_paused = true)]
async fn scheduler_learns_when_timer_processing_jitter_shortens_intervals() {
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let copy = parallel(
        (0..1024).collect(),
        Concurrency {
            initial: 4,
            maximum: Some(16),
            initial_probe_up: true,
            requests: None,
            checking: None,
            outage: None,
        },
        |_, _| {
            let active = active.clone();
            let peak = peak.clone();
            async move {
                peak.fetch_max(active.fetch_add(1, SeqCst) + 1, SeqCst);
                tokio::time::sleep(Duration::from_millis(10)).await;
                active.fetch_sub(1, SeqCst);
                Ok(Some(1024))
            }
        },
    );
    tokio::pin!(copy);
    assert!(futures_util::poll!(&mut copy).is_pending());
    // Poll slightly after each timer deadline. The lateness diminishes
    // across successive deadlines, so their measured spacing is just
    // below 250ms despite the ticker maintaining its intended cadence.
    for _ in 0..900 {
        tokio::time::advance(Duration::from_micros(999)).await;
        assert!(futures_util::poll!(&mut copy).is_pending());
    }
    assert!(
        peak.load(SeqCst) >= 8,
        "three scheduled samples should suffice for the first probe"
    );
    copy.await.unwrap();
    assert_eq!(active.load(SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn adaptive_scheduler_grows_without_losing_or_duplicating_jobs() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering::SeqCst},
        Arc,
    };
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new((0..16384).map(|_| AtomicUsize::new(0)).collect::<Vec<_>>());
    parallel(
        (0..16384).collect(),
        Concurrency {
            initial: 4,
            maximum: Some(16),
            initial_probe_up: false,
            requests: None,
            checking: None,
            outage: None,
        },
        |n, _| {
            let active = active.clone();
            let peak = peak.clone();
            let seen = seen.clone();
            async move {
                peak.fetch_max(active.fetch_add(1, SeqCst) + 1, SeqCst);
                tokio::time::sleep(Duration::from_millis(2)).await;
                seen[n].fetch_add(1, SeqCst);
                active.fetch_sub(1, SeqCst);
                Ok(Some(1024))
            }
        },
    )
    .await
    .unwrap();
    assert!(peak.load(SeqCst) > 4 && peak.load(SeqCst) <= 16);
    assert_eq!(active.load(SeqCst), 0);
    assert!(seen.iter().all(|count| count.load(SeqCst) == 1));
}

#[tokio::test]
async fn fixed_limit_and_failure_drain_started_jobs() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering::SeqCst},
        Arc,
    };
    let started = Arc::new(AtomicUsize::new(0));
    let finished = Arc::new(AtomicUsize::new(0));
    let error = parallel(
        (0..20).collect(),
        Concurrency {
            initial: 2,
            maximum: None,
            initial_probe_up: false,
            requests: None,
            checking: None,
            outage: None,
        },
        |n, _| {
            let started = started.clone();
            let finished = finished.clone();
            async move {
                started.fetch_add(1, SeqCst);
                if n == 0 {
                    anyhow::bail!("fixture failure");
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
                finished.fetch_add(1, SeqCst);
                Ok(Some(1))
            }
        },
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("fixture failure"));
    assert_eq!(started.load(SeqCst), 2);
    assert_eq!(finished.load(SeqCst), 1);
}

/// Runs a copy whose objects take `check` to check and, when `transfers`
/// selects them, claim a slot and take `transfer` more. Returns the peak
/// number of objects in progress and of objects transferring, each as
/// (first objects, objects from `late` on).
async fn checked_copy(
    jobs: usize,
    concurrency: Concurrency,
    late: usize,
    transfers: impl Fn(usize) -> bool + Copy + Send + 'static,
) -> ((usize, usize), (usize, usize)) {
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
    let counters: Arc<[AtomicUsize; 6]> = Arc::default();
    let seen = Arc::new((0..jobs).map(|_| AtomicUsize::new(0)).collect::<Vec<_>>());
    parallel((0..jobs).collect(), concurrency, |n, mut slot| {
        let counters = counters.clone();
        let seen = seen.clone();
        async move {
            let [active, transferring, peak, late_peak, transfer_peak, late_transfer_peak] =
                &*counters;
            let now = active.fetch_add(1, SeqCst) + 1;
            if n >= late { late_peak } else { peak }.fetch_max(now, SeqCst);
            tokio::time::sleep(Duration::from_millis(20)).await;
            seen[n].fetch_add(1, SeqCst);
            let result = if transfers(n) {
                slot.claim().await;
                let now = transferring.fetch_add(1, SeqCst) + 1;
                if n >= late {
                    late_transfer_peak
                } else {
                    transfer_peak
                }
                .fetch_max(now, SeqCst);
                tokio::time::sleep(Duration::from_millis(20)).await;
                transferring.fetch_sub(1, SeqCst);
                Some(1024)
            } else {
                None
            };
            active.fetch_sub(1, SeqCst);
            Ok(result)
        }
    })
    .await
    .unwrap();
    assert!(seen.iter().all(|count| count.load(SeqCst) == 1));
    let [active, transferring, peak, late_peak, transfer_peak, late_transfer_peak] = &*counters;
    assert_eq!((active.load(SeqCst), transferring.load(SeqCst)), (0, 0));
    (
        (peak.load(SeqCst), late_peak.load(SeqCst)),
        (transfer_peak.load(SeqCst), late_transfer_peak.load(SeqCst)),
    )
}

fn checked(initial: usize, maximum: Option<usize>, checking: Option<usize>) -> Concurrency {
    Concurrency {
        initial,
        maximum,
        initial_probe_up: false,
        requests: None,
        checking: checking.map(|maximum| Checking { maximum }),
        outage: Some(Arc::default()),
    }
}

#[tokio::test(start_paused = true)]
async fn unchanged_objects_are_checked_beyond_the_transfer_limit() {
    // With or without a transfer controller, which unchanged objects give
    // no samples.
    for maximum in [None, Some(16)] {
        let ((peak, _), _) =
            checked_copy(20_000, checked(4, maximum, Some(64)), 20_000, |_| false).await;
        assert!((33..=64).contains(&peak), "peak {peak}");
    }
    // Without a checking ceiling the transfer limit bounds them, as before.
    let ((peak, _), _) = checked_copy(2_000, checked(4, None, None), 2_000, |_| false).await;
    assert_eq!(peak, 4);
}

#[tokio::test(start_paused = true)]
async fn transfers_keep_their_limit_while_more_objects_are_checked() {
    // One object in 64 transfers: far fewer than the four slots can carry.
    let ((peak, _), (transferring, _)) =
        checked_copy(20_000, checked(4, None, Some(64)), 20_000, |n| n % 64 == 0).await;
    assert!((33..=64).contains(&peak), "peak {peak}");
    assert!(
        (1..=4).contains(&transferring),
        "transferring {transferring}"
    );
}

#[tokio::test(start_paused = true)]
async fn a_copy_that_transfers_every_object_admits_none_beyond_the_limit() {
    let ((peak, _), (transferring, _)) =
        checked_copy(2_000, checked(4, None, Some(64)), 2_000, |_| true).await;
    assert_eq!((peak, transferring), (4, 4));
}

#[tokio::test(start_paused = true)]
async fn checking_returns_to_the_transfer_limit_once_objects_need_transfers() {
    // Unchanged objects raise the number in progress; the changed ones
    // that follow then queue for the four transfer slots.
    let ((peak, late_peak), (_, transferring)) = checked_copy(
        12_000,
        checked(4, None, Some(64)),
        // Leave the queue of checked objects time to drain.
        9_000,
        |n| n >= 8_000,
    )
    .await;
    assert!((33..=64).contains(&peak), "peak {peak}");
    assert_eq!((late_peak, transferring), (4, 4));
}

#[tokio::test(start_paused = true)]
async fn the_transfer_limit_is_tuned_again_after_checking_falls_back() {
    let ((peak, _), (_, transferring)) =
        checked_copy(40_000, checked(4, Some(16), Some(64)), 8_000, |n| {
            n >= 8_000
        })
        .await;
    assert!((33..=64).contains(&peak), "peak {peak}");
    // The controller raises the limit once transfers are what it measures.
    assert!(
        (5..=16).contains(&transferring),
        "transferring {transferring}"
    );
}

#[test]
fn checking_searches_only_above_the_transfer_limit() {
    for optimum in [1, 8, 32, 100, 256] {
        let mut controller = Controller::checking(32, 256);
        for _ in 0..500 {
            let active = controller.limit;
            assert!((32..=256).contains(&active));
            let rate = if active <= optimum {
                active as f64
            } else {
                (optimum * optimum) as f64 / active as f64
            };
            controller.observe(rate, active, 10000, 16, 0.0);
        }
        let settled = controller
            .probe
            .as_ref()
            .map_or(controller.limit, |probe| probe.from);
        let expected = optimum.max(32);
        assert!(
            settled.abs_diff(expected) <= expected / 10,
            "optimum {optimum}, settled {settled}"
        );
    }
    // A ceiling at or below the transfer limit leaves nothing to search.
    let mut controller = Controller::checking(32, 16);
    for _ in 0..100 {
        assert_eq!(controller.observe(16.0, 16, 10000, 16, 0.0), 16);
    }
}

#[test]
fn a_checking_increase_must_earn_a_quarter_of_its_share() {
    // Checking 64 objects at once instead of 32 is kept for 28% more
    // unchanged objects found, not for 22%; transfers keep a 2% gain.
    for (rate_at_64, checking, kept) in
        [(41.0, true, true), (39.0, true, false), (39.0, false, true)]
    {
        let mut controller = if checking {
            Controller::checking(32, 256)
        } else {
            Controller::new(32, 256, true)
        };
        for _ in 0..200 {
            let active = controller.limit;
            let rate = 32.0 + (rate_at_64 - 32.0) * (active.min(64) as f64 - 32.0) / 32.0;
            controller.observe(rate, active, 10000, 16, 0.0);
        }
        let settled = controller
            .probe
            .as_ref()
            .map_or(controller.limit, |probe| probe.from);
        assert_eq!(
            settled >= 60,
            kept,
            "rate {rate_at_64}, checking {checking}: settled {settled}"
        );
    }
}

#[test]
fn checking_follows_the_transfer_limit_until_it_has_grown() {
    let mut controller = Controller::checking(32, 256);
    controller.follow(64);
    assert_eq!((controller.limit, controller.minimum), (64, 64));
    controller.follow(16);
    assert_eq!((controller.limit, controller.minimum), (16, 16));
    // Grown beyond the transfer limit, it keeps its own limit while that
    // limit moves beneath it, and starts again where it is overtaken.
    exercise(&mut controller, 128);
    let grown = controller.limit;
    assert!(grown > 100);
    controller.follow(32);
    assert_eq!((controller.limit, controller.minimum), (grown, 32));
    controller.follow(200);
    assert_eq!((controller.limit, controller.minimum), (200, 200));
    assert!(controller.probe.is_none());
    // Above the ceiling there is nothing for it to add.
    controller.follow(1000);
    assert_eq!(controller.limit, 256);
    controller.follow(1000);
    assert_eq!(controller.limit, 256);
}

#[test]
fn a_moving_transfer_limit_does_not_bring_a_rejected_increase_back() {
    for transfers in [40, 24] {
        let mut controller = Controller::checking(32, 256);
        exercise(&mut controller, 256);
        assert_eq!(controller.reject(), 32);
        controller.follow(transfers);
        assert_eq!(
            (controller.limit, controller.minimum),
            (transfers, transfers)
        );
        let mut waited = 0;
        while controller.observe(transfers as f64, transfers, 10000, 16, 0.0) == transfers {
            waited += 1;
            assert!(waited < 200, "checking never retried");
        }
        assert!(waited >= 16, "retried after {waited} samples");
    }
}

#[test]
fn rejected_checking_returns_to_the_transfer_limit_and_retries_later() {
    let mut controller = Controller::checking(32, 256);
    exercise(&mut controller, 256);
    assert!(controller.limit > 200);
    assert_eq!(controller.reject(), 32);
    assert!(controller.probe.is_none());
    // The same conditions do not bring the increase back at once...
    let mut waited = 0;
    while controller.observe(32.0, 32, 10000, 16, 0.0) == 32 {
        waited += 1;
        assert!(waited < 200, "checking never retried");
    }
    assert!(waited >= 16, "retried after {waited} samples");
    // ...and a retry that is rejected again waits longer.
    assert_eq!(controller.reject(), 32);
    let mut waited_again = 0;
    while controller.observe(32.0, 32, 10000, 16, 0.0) == 32 {
        waited_again += 1;
        assert!(waited_again < 400, "checking never retried");
    }
    assert!(waited_again > waited, "{waited_again} after {waited}");
    // Rejected at the transfer limit, it still puts the next increase off.
    let mut idle = Controller::checking(32, 256);
    assert_eq!(idle.reject(), 32);
    for _ in 0..16 {
        assert_eq!(idle.observe(32.0, 32, 10000, 16, 0.0), 32);
    }
}

#[test]
fn throttling_halves_the_room_checking_may_use() {
    let mut controller = Controller::checking(32, 256);
    exercise(&mut controller, 256);
    let reached = controller.limit;
    assert!(reached > 200);
    // It continues from halfway, and never again goes higher.
    let halved = 32 + (reached - 32) / 2;
    assert_eq!(controller.throttled(), halved);
    assert_eq!(controller.maximum, halved);
    assert!(controller.probe.is_none());
    for _ in 0..500 {
        let active = controller.limit;
        assert!((32..=halved).contains(&active));
        controller.observe(active as f64, active, 10000, 16, 0.0);
    }
    assert!(controller.limit > halved * 9 / 10, "{}", controller.limit);
    // Repeated throttling brings it down to the transfer limit, where it
    // has no room left to give up.
    for _ in 0..8 {
        controller.throttled();
    }
    assert_eq!((controller.limit, controller.maximum), (32, 32));
    for _ in 0..100 {
        assert_eq!(controller.observe(32.0, 32, 10000, 16, 0.0), 32);
    }
    // Throttled before it has grown, it keeps its room and waits.
    let mut idle = Controller::checking(32, 256);
    assert_eq!(idle.throttled(), 32);
    assert_eq!(idle.maximum, 256);
    for _ in 0..16 {
        assert_eq!(idle.observe(32.0, 32, 10000, 16, 0.0), 32);
    }
}

#[test]
fn a_waiter_that_gives_up_passes_its_transfer_slot_on() {
    use std::{future::Future, task::Context};
    let gate = Arc::new(Gate {
        state: Mutex::new(GateState {
            limit: 1,
            active: 0,
            waiting: 0,
            waiting_since: None,
        }),
        changed: tokio::sync::Notify::new(),
    });
    let slot = || TransferSlot {
        gate: gate.clone(),
        held: false,
    };
    let waker = futures_util::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut holder = slot();
    assert!(Box::pin(holder.claim()).as_mut().poll(&mut cx).is_ready());
    // Claiming again neither waits nor takes a second slot.
    assert!(Box::pin(holder.claim()).as_mut().poll(&mut cx).is_ready());
    assert_eq!(gate.active(), 1);
    // A limit is in force only while objects beyond it are in progress.
    assert!(holder.beyond_limit());
    gate.set_limit(usize::MAX);
    assert!(!holder.beyond_limit());
    gate.set_limit(1);
    let (mut cancelled, mut next, mut last) = (slot(), slot(), slot());
    {
        let mut cancelled = Box::pin(cancelled.claim());
        let mut next = Box::pin(next.claim());
        assert!(cancelled.as_mut().poll(&mut cx).is_pending());
        assert!(next.as_mut().poll(&mut cx).is_pending());
        drop(holder);
        // The released slot woke the first waiter, which is dropped unpolled.
        drop(cancelled);
        assert!(next.as_mut().poll(&mut cx).is_ready());
    }
    assert_eq!(gate.active(), 1);
    // A later object does not overtake one already waiting.
    {
        let mut last = Box::pin(last.claim());
        assert!(last.as_mut().poll(&mut cx).is_pending());
        gate.set_limit(2);
        let mut overtaking = slot();
        let mut overtaking = Box::pin(overtaking.claim());
        assert!(overtaking.as_mut().poll(&mut cx).is_pending());
        assert!(last.as_mut().poll(&mut cx).is_ready());
    }
    drop((next, last));
    assert_eq!(gate.active(), 0);
    assert_eq!(gate.state.lock().unwrap().waiting, 0);
}

#[tokio::test(start_paused = true)]
async fn throttling_responses_stop_checking_from_adding_requests() {
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
    // (objects in progress above which the service throttles, expected peak)
    for (threshold, expected) in [(0, 4..=4), (16, 17..=32)] {
        let outage = Arc::new(crate::s3::outage::Outage::default());
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let mut concurrency = checked(4, None, Some(64));
        concurrency.outage = Some(outage.clone());
        parallel((0..40_000).collect(), concurrency, |_: usize, _| {
            let (outage, active, peak) = (outage.clone(), active.clone(), peak.clone());
            async move {
                let now = active.fetch_add(1, SeqCst) + 1;
                peak.fetch_max(now, SeqCst);
                if now > threshold {
                    outage.throttled();
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
                active.fetch_sub(1, SeqCst);
                Ok(None)
            }
        })
        .await
        .unwrap();
        let peak = peak.load(SeqCst);
        assert!(
            expected.contains(&peak),
            "threshold {threshold}: peak {peak}"
        );
        if threshold != 0 {
            // Each sample above the threshold halves how far checking goes.
            let throttled = outage.throttled_responses();
            assert!((1..1_000).contains(&throttled), "throttled {throttled}");
        }
    }
}

#[tokio::test(start_paused = true)]
async fn transfer_controller_backs_off_on_throttling_and_can_recover() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
    let outage = Arc::new(crate::s3::outage::Outage::default());
    let throttling = Arc::new(AtomicBool::new(true));
    let active = Arc::new(AtomicUsize::new(0));
    let settled_peak = Arc::new(AtomicUsize::new(0));
    let late_peak = Arc::new(AtomicUsize::new(0));
    parallel(
        (0..40_000usize).collect(),
        Concurrency {
            initial: 32,
            maximum: Some(64),
            initial_probe_up: false,
            requests: None,
            checking: None,
            outage: Some(outage.clone()),
        },
        |job, _| {
            let outage = outage.clone();
            let throttling = throttling.clone();
            let active = active.clone();
            let settled_peak = settled_peak.clone();
            let late_peak = late_peak.clone();
            async move {
                // Stop throttling once 10,000 jobs are done so the controller
                // can demonstrate recovery via periodic revisits.
                if job == 10_000 {
                    throttling.store(false, SeqCst);
                }
                let now = active.fetch_add(1, SeqCst) + 1;
                // After initial cuts drain (before the first revisit probe),
                // concurrency stays at or below the throttling threshold.
                if (1_000..3_000).contains(&job) {
                    settled_peak.fetch_max(now, SeqCst);
                }
                if job >= 30_000 {
                    late_peak.fetch_max(now, SeqCst);
                }
                if throttling.load(SeqCst) && now > 8 {
                    outage.throttled();
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
                active.fetch_sub(1, SeqCst);
                Ok(Some(1024))
            }
        },
    )
    .await
    .unwrap();
    // Under throttling above 8, concurrency backed off from 32 down to <= 8.
    assert!(
        settled_peak.load(SeqCst) <= 8,
        "settled_peak {}",
        settled_peak.load(SeqCst)
    );
    // Once throttling stopped, revisits recovered above the throttled level.
    assert!(
        late_peak.load(SeqCst) > 8,
        "late_peak {}",
        late_peak.load(SeqCst)
    );
}

#[test]
fn transfer_throttled_halves_and_preserves_maximum() {
    let mut controller = Controller::new(64, 256, true);
    assert_eq!(controller.transfer_throttled(), 32);
    assert_eq!(controller.maximum, 256);
    assert_eq!(controller.upper, 33);
    assert_eq!(controller.candidate(), 32);
    assert_eq!(controller.transfer_throttled(), 16);
    assert_eq!(controller.maximum, 256);
    assert_eq!(controller.upper, 17);
}

#[tokio::test(start_paused = true)]
async fn pre_handoff_single_throttle_cuts_once_not_twice() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
    let outage = Arc::new(crate::s3::outage::Outage::default());
    let args = crate::cli::Args::parse_args(&[
        std::ffi::OsString::from("cp"),
        std::ffi::OsString::from("--from"),
        std::ffi::OsString::from("s3://bucket"),
        std::ffi::OsString::from("a"),
        std::ffi::OsString::from("--as"),
        std::ffi::OsString::from("b"),
    ])
    .unwrap();
    let options = args.s3.clone().unwrap();
    let tuning = crate::s3::tuning::Tuning::new(
        &options,
        &args,
        Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX)),
        outage.clone(),
    );
    tuning.configure(false, 64, 16);
    let budget = tuning.requests.clone();
    let fired = Arc::new(AtomicBool::new(false));
    let active = Arc::new(AtomicUsize::new(0));
    let post_throttle_peak = Arc::new(AtomicUsize::new(0));
    parallel(
        (0..200usize).collect(),
        Concurrency {
            initial: 32,
            maximum: Some(64),
            initial_probe_up: false,
            requests: Some(budget.clone()),
            checking: None,
            outage: Some(outage.clone()),
        },
        |job, _| {
            let outage = outage.clone();
            let budget = budget.clone();
            let fired = fired.clone();
            let active = active.clone();
            let post_throttle_peak = post_throttle_peak.clone();
            async move {
                let permit = budget.acquire().await;
                let now = active.fetch_add(1, SeqCst) + 1;
                if (40..120).contains(&job) {
                    post_throttle_peak.fetch_max(now, SeqCst);
                }
                if job == 0 && !fired.swap(true, SeqCst) {
                    outage.throttled();
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
                budget.completed(1024);
                active.fetch_sub(1, SeqCst);
                drop(permit);
                Ok(Some(1024))
            }
        },
    )
    .await
    .unwrap();
    // One pre-handoff throttle should halve 16 -> 8, not double-cut to 4.
    assert!(
        post_throttle_peak.load(SeqCst) >= 8,
        "post_throttle_peak {} indicates double cut below 8",
        post_throttle_peak.load(SeqCst)
    );
}

#[tokio::test(start_paused = true)]
async fn throttled_checking_above_transfer_limit_leaves_budget_untouched() {
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
    let outage = Arc::new(crate::s3::outage::Outage::default());
    let args = crate::cli::Args::parse_args(&[
        std::ffi::OsString::from("cp"),
        std::ffi::OsString::from("a"),
        std::ffi::OsString::from("--to"),
        std::ffi::OsString::from("s3://bucket"),
        std::ffi::OsString::from("--as"),
        std::ffi::OsString::from("b"),
    ])
    .unwrap();
    let options = args.s3.clone().unwrap();
    let tuning = crate::s3::tuning::Tuning::new(
        &options,
        &args,
        Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX)),
        outage.clone(),
    );
    tuning.configure(false, 64, 16);
    let budget = tuning.requests.clone();
    let checking_active = Arc::new(AtomicUsize::new(0));
    parallel(
        (0..4_000usize).collect(),
        Concurrency {
            initial: 16,
            maximum: None,
            initial_probe_up: false,
            requests: Some(budget.clone()),
            checking: Some(Checking { maximum: 64 }),
            outage: Some(outage.clone()),
        },
        |job, mut slot| {
            let outage = outage.clone();
            let budget = budget.clone();
            let checking_active = checking_active.clone();
            async move {
                let now = checking_active.fetch_add(1, SeqCst) + 1;
                if now > 20 {
                    outage.throttled();
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
                checking_active.fetch_sub(1, SeqCst);
                if job % 50 == 0 {
                    slot.claim().await;
                    let permit = budget.acquire().await;
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    budget.completed(1024);
                    drop(permit);
                    Ok(Some(1024))
                } else {
                    Ok(None)
                }
            }
        },
    )
    .await
    .unwrap();
    assert!(
        outage.throttled_responses() > 0,
        "expected checking requests above transfer limit to trigger throttling"
    );
    assert_eq!(
        tuning.request_limit(),
        16,
        "throttling while checking is above transfer limit must not halve the request budget"
    );
}

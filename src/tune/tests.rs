use super::*;

// A finite domain for the existing policy simulations, not a runtime limit.
const MAX: usize = 64;

#[test]
fn cache_lock_refuses_symlinks_and_non_regular_files() {
    let dir = crate::test_support::tempdir().unwrap();
    let cache = dir.path().join("tuning.json");
    let lock = cache.with_extension("json.lock");
    let victim = dir.path().join("victim");
    std::fs::write(&victim, b"untouched").unwrap();
    std::os::unix::fs::symlink(&victim, &lock).unwrap();
    assert!(lock_file(&cache, true).is_err());
    assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
    std::fs::remove_file(&lock).unwrap();
    std::fs::create_dir(&lock).unwrap();
    assert!(lock_file(&cache, false).is_err());
    std::fs::remove_dir(&lock).unwrap();
    assert!(lock_file(&cache, true).is_ok());
}

#[test]
fn local_start_reduces_only_for_one_or_two_cpus() {
    assert_eq!(local_start_for_parallelism(1), START_LOCAL_LOW_CPU);
    assert_eq!(local_start_for_parallelism(2), START_LOCAL_LOW_CPU);
    assert_eq!(local_start_for_parallelism(3), START_LOCAL);
    assert_eq!(local_start_for_parallelism(128), START_LOCAL);
}

fn remote(host: &str, tcp: bool) -> Endpoint {
    Endpoint::Remote(crate::conn::RemoteSpec {
        local_process: false,
        user: Some("user".into()),
        host: host.into(),
        port: None,
        rsh: vec!["ssh".into()],
        syq_path: None,
        bootstrap_helper: false,
        restricted_grant: None,
        helper_install: Default::default(),
        ssh_multiplexer: None,
        quiet: true,
        tcp: std::sync::Arc::new(std::sync::Mutex::new(tcp.then(|| crate::conn::TcpInfo {
            reverse: None,
            addrs: vec!["127.0.0.1".into()],
            port: 1,
            key: Some(vec![0; 32]),
            token: vec![],
            congestion_control: None,
            failed: false,
            failure: None,
            next: Default::default(),
        }))),
        diagnostics: Default::default(),
        primed_control: Default::default(),
        forwarded: None,
        read_ahead: crate::transfer_tuning::DEFAULT_PIPELINE_DEPTH,
    })
}

fn temporary_cache(name: &str) -> PathBuf {
    crate::test_support::temp_dir().join(format!(
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
    simulate_policy(Policy::new(start, MIN, MAX), cap, rounds, noise)
}

fn simulate_policy(
    mut p: Policy,
    cap: usize,
    rounds: usize,
    noise: impl Fn(usize) -> f64,
) -> Policy {
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
    assert_eq!(step_up(usize::MAX), usize::MAX);
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
fn automatic_growth_can_explore_above_64() {
    let mut policy = Policy::new(START_SSH, MIN, usize::MAX);
    for _ in 0..100 {
        let rate = policy.n.min(128) as f64 * 10e6;
        measure(&mut policy, rate);
    }
    assert!(policy.settled() >= 128, "{:?}", policy.history);
    assert!(policy.history.iter().any(|&count| count > 64));
}

#[test]
fn explicit_ceiling_above_64_bounds_automatic_growth() {
    let mut policy = Policy::new(START_SSH, MIN, 1000);
    for _ in 0..100 {
        let rate = policy.n as f64 * 10e6;
        measure(&mut policy, rate);
    }
    assert!(policy.history.contains(&1000), "{:?}", policy.history);
    assert!(policy.history.iter().all(|&count| count <= 1000));
}

#[test]
fn uncached_start_doubles_until_the_ceiling_then_stops_coarse_search() {
    let mut p = Policy::new(8, MIN, 32);
    for _ in 0..3 {
        let rate = p.n as f64;
        measure(&mut p, rate);
    }
    assert_eq!(p.history, vec![8, 16, 32]);
    assert_eq!(p.n, 32);
    assert!(!p.startup_doubling);
    let mut capped = Policy::new(usize::MAX / 2 + 1, MIN, usize::MAX);
    measure(&mut capped, 100.0);
    assert_eq!(capped.n, usize::MAX);
}

#[test]
fn unsuccessful_doubling_refines_immediately_then_uses_normal_backoff() {
    let mut p = Policy::new(8, MIN, 64);
    measure(&mut p, 80.0); // 8 -> 16
    measure(&mut p, 160.0); // 16 -> 32
    measure(&mut p, 150.0); // 32 hurt: try the 16..32 midpoint now
    assert_eq!(p.n, 24);
    assert_eq!(p.settled(), 16);
    assert!(!p.startup_doubling);
    measure(&mut p, 200.0); // 24 paid: refine the remaining 24..32 bracket
    assert_eq!(p.n, 28);
    measure(&mut p, 180.0); // 28 clearly hurts: return to 24 and wait
    assert_eq!(p.n, 24);
    assert!(matches!(p.state, State::Hold));
    assert!(p.due[Direction::Up.index()] > p.tick);
}

#[test]
fn cancelled_startup_doubling_does_not_change_active_workers_or_repeat_coarse_search() {
    let mut p = Policy::new(8, MIN, 64);
    p.observe(80.0);
    assert_eq!(p.n, 16);
    p.cancel_unapplied();
    assert_eq!(p.n, 8);
    assert_eq!(p.history, vec![8]);
    assert!(!p.startup_doubling);
    assert_eq!(p.target(Direction::Up), 10);
}

#[test]
fn resume_worker_reset_preserves_cached_and_uncached_startup_modes() {
    struct StopAfterReset(Arc<Sched>);
    impl Meter for StopAfterReset {
        fn bytes(&self) -> u64 {
            0
        }
        fn files(&self) -> u64 {
            0
        }
        fn set_active(&self, n: usize) {
            if n == 8 {
                self.0.abort();
            }
        }
    }

    let mut refined = Policy::new(2, MIN, MAX);
    measure(&mut refined, 20.0);
    measure(&mut refined, 20.0); // inconclusive doubling has stopped coarse search
    for (policy, expected_next) in [
        (Policy::refine(2, MIN, MAX), 10),
        (Policy::new(2, MIN, MAX), 16),
        (refined, 10),
    ] {
        let sched = Arc::new(Sched::new(4 << 20, 32 << 20));
        // The same request made when a worker discovers a resumable basis:
        // two size-limited initial workers restore the remembered eight.
        sched.arm_direct_fallback(8);
        sched.request_direct_fallback();
        let gate = Gate::new(policy.active());
        let meter = Arc::new(StopAfterReset(sched.clone()));
        let mut reset = run(policy, gate.clone(), sched, meter, |id| gate.mark_ready(id));
        assert_eq!(reset.active(), 8);
        assert_eq!(reset.history, vec![8]);
        assert!(gate.ready_through(8));
        measure(&mut reset, 80.0);
        assert_eq!(reset.n, expected_next);
    }
}

#[test]
fn plateau_hint_keeps_modest_probes() {
    let mut p = Policy::refine(START_SSH, MIN, MAX);
    measure(&mut p, 80.0);
    assert_eq!(p.n, 10);
    assert_eq!(p.history, vec![8, 10]);
}

#[test]
fn measured_search_and_cancelled_probe_do_not_imply_a_plateau() {
    let mut p = Policy::new(8, MIN, MAX);
    assert!(!p.discovery_complete());
    measure(&mut p, 80.0);
    p.observe(160.0); // 16 helped; 32 is still only a proposal.
    assert!(p.measured());
    assert!(!p.discovery_complete());
    p.cancel_unapplied();
    assert!(!p.discovery_complete());

    let mut capped = Policy::new(8, MIN, 16);
    measure(&mut capped, 80.0);
    measure(&mut capped, 160.0);
    assert!(!capped.discovery_complete());
}

#[test]
fn plateau_evidence_requires_a_nearby_recent_upper_measurement() {
    let mut wide = Policy::new(8, MIN, MAX);
    measure(&mut wide, 80.0);
    measure(&mut wide, 80.0); // 16 did not help, but 8..16 still needs refinement.
    assert!(!wide.discovery_complete());

    let mut close = Policy::refine(8, MIN, MAX);
    measure(&mut close, 80.0);
    measure(&mut close, 60.0); // 10 clearly hurt: a nearby completed comparison.
    assert_eq!(close.settled(), 8);
    assert!(close.discovery_complete());
    let mut slower = close.clone();
    slower.observe(1.0);
    assert!(!slower.discovery_complete());
    close.tick += EVIDENCE_MAX_AGE + 1;
    assert!(!close.discovery_complete());
}

#[test]
fn doubling_a_weak_start_reaches_the_plateau_before_premature_refinement() {
    // Controlled worker/throughput model, not a wall-clock transfer benchmark.
    // The cache may supply the same count as a default; only strong evidence
    // should change how quickly we move away from a count below the plateau.
    fn measurements_to_plateau(mut p: Policy) -> usize {
        for measurements in 1..=16 {
            let score = p.active().min(64) as f64;
            if score >= 64.0 * (1.0 - NEAR_BEST_TOLERANCE) {
                return measurements;
            }
            measure(&mut p, score);
        }
        panic!("did not reach plateau: {:?}", p.history);
    }
    let weak = measurements_to_plateau(Policy::new(8, MIN, 128));
    let premature_refinement = measurements_to_plateau(Policy::refine(8, MIN, 128));
    assert_eq!(weak, 4);
    assert_eq!(premature_refinement, 9);
    assert_eq!(measurements_to_plateau(Policy::refine(64, MIN, 128)), 1);
}

#[test]
fn upward_gain_continues_but_inconclusive_result_holds() {
    let mut worthwhile = Policy::refine(10, MIN, MAX);
    measure(&mut worthwhile, 100.0);
    measure(&mut worthwhile, 107.0);
    assert_eq!(worthwhile.settled(), 13);

    let mut unnecessary = Policy::refine(10, MIN, MAX);
    measure(&mut unnecessary, 100.0);
    measure(&mut unnecessary, 104.0);
    assert_eq!(unnecessary.settled(), 13);
    assert_eq!(unnecessary.state, State::Hold);
    assert!(!unnecessary.discovery_complete());
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
fn remaining_work_requirement_scales_with_rate_not_worker_count() {
    let slow = required_remaining_activity(Some(1_000_000.0), 8, SAMPLE);
    let fast = required_remaining_activity(Some(1_000_000_000.0), 8, SAMPLE);
    assert_eq!(slow, 7_500_000);
    assert_eq!(fast, 7_500_000_000);
    assert_eq!(
        required_remaining_activity(None, 8, SAMPLE),
        8 * TAIL_FALLBACK_BYTES_PER_WORKER
    );
}

#[test]
fn upward_probe_refreshes_its_baseline_while_warming() {
    let mut policy = Policy::refine(10, MIN, MAX);
    policy.observe(100.0);
    assert_eq!(policy.active(), 10);
    assert_eq!(policy.n, 13);
    assert!(policy.refresh_warming_baseline(70.0));
    assert_eq!(policy.probe_base(), Some(70.0));

    policy.activated();
    policy.observe(75.0);
    assert_eq!(policy.settled(), 13);
}

#[test]
fn cached_successful_direction_continues_to_the_plateau() {
    let mut p = Policy::refine(START_SSH, MIN, MAX);
    let mut reached_full_rate = false;
    for _ in 0..80 {
        let rate = p.n.min(32) as f64 * 10e6;
        measure(&mut p, rate);
        reached_full_rate |= p.settled() >= 32;
    }
    assert_eq!(&p.history[..6], &[8, 10, 13, 17, 22, 29]);
    assert!(reached_full_rate, "history {:?}", p.history);
}

#[test]
fn cached_gain_at_the_cap_holds_at_the_cap() {
    let p = simulate_policy(Policy::refine(START_LOCAL, MIN, MAX), 200, 40, |_| 1.0);
    // Even a one-worker reduction is slower on this linear curve.
    assert_eq!(p.settled(), MAX, "history {:?}", p.history);
    assert_eq!(p.peak, MAX);
}

#[test]
fn uncached_start_reaches_full_rate_without_accepting_slower_reductions() {
    for (start, cap) in [(8, 32), (32, 64)] {
        let mut p = simulate(start, cap, 3, |_| 1.0);
        assert_eq!(p.settled(), cap, "history {:?}", p.history);
        for _ in 0..128 {
            let rate = p.n.min(cap) as f64 * 10e6;
            measure(&mut p, rate);
            assert!(p.settled() >= cap, "history {:?}", p.history);
            assert_eq!(p.recommended(), cap);
        }
    }
}

#[test]
fn a_failed_up_probe_does_not_immediately_bounce_down() {
    let mut p = Policy::refine(10, MIN, MAX);
    measure(&mut p, 100.0); // 10 -> 13
    measure(&mut p, 130.0); // 13 paid; try 17
    measure(&mut p, 90.0); // 17 clearly hurt; return to 13
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
fn rejects_a_slightly_slower_downward_probe() {
    let mut p = Policy::refine(10, MIN, MAX);
    measure(&mut p, 100.0);
    measure(&mut p, 130.0);
    measure(&mut p, 90.0); // clear loss at 17 leaves the 10..13 bracket
    for _ in 0..PROBE_EVERY {
        measure(&mut p, 130.0);
    }
    assert_eq!(p.n, 11);
    measure(&mut p, 129.0);
    assert_eq!(p.settled(), 13);
    assert_eq!(p.n, 13);
}

#[test]
fn flat_throughput_does_not_justify_a_reduction() {
    let mut p = Policy::new(START_SSH, MIN, MAX);
    for _ in 0..200 {
        measure(&mut p, 100.0);
        assert!(p.settled() >= START_SSH, "history {:?}", p.history);
        assert_eq!(p.recommended(), START_SSH);
    }
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
fn alternating_noise_keeps_settled_throughput_at_the_plateau() {
    let p = simulate(START_SSH, 32, 60, |i| if i % 2 == 0 { 1.0 } else { 0.93 });
    // Equal-speed counts may stay live; judge throughput rather than trimming.
    assert!(p.settled() >= 32, "history {:?}", p.history);
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
fn cache_preserves_counts_above_64_and_clamps_only_zero() {
    let dir = temporary_cache("roundtrip");
    let path = dir.join("tuning.json");
    remember_at(&path, "a>b|tcp", 13).unwrap();
    remember_at(&path, "a>b|ssh", MAX + 100).unwrap();
    assert_eq!(cached_at(&path, "a>b|tcp"), Some(13));
    assert_eq!(cached_at(&path, "a>b|ssh"), Some(MAX + 100));
    remember_at(&path, "zero", 0).unwrap();
    assert_eq!(cached_at(&path, "zero"), Some(MIN));
    assert_eq!(cached_at(&path, "b>a|tcp"), None);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn cache_key_separates_direction_and_transport() {
    let local = Endpoint::local();
    let ssh = remote("host", false);
    let tcp = remote("host", true);
    assert_ne!(path_key(&local, &ssh), path_key(&ssh, &local));
    assert_ne!(path_key(&local, &ssh), path_key(&local, &tcp));
    assert_eq!(path_key(&local, &local), None);
}

#[test]
fn tcp_fallback_changes_the_cache_key() {
    let local = Endpoint::local();
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
fn cache_is_read_when_its_lock_cannot_be_created() {
    use std::os::unix::fs::PermissionsExt;
    if unsafe { libc::geteuid() } == 0 {
        return; // root ignores directory permissions
    }
    let dir = temporary_cache("readonly");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("tuning.json");
    remember_at(&path, "a>b|tcp", 9).unwrap();
    std::fs::remove_file(path.with_extension("json.lock")).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    let cached = cached_at(&path, "a>b|tcp");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(cached, Some(9));
    assert!(!path.with_extension("json.lock").exists());
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
    g.set_connect_target(3);
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
fn parked_connections_survive_lower_targets_and_reactivate_without_setup() {
    let gate = Gate::new(2);
    assert_eq!(gate.begin_warming(2), vec![0, 1]);
    gate.mark_ready(0);
    assert!(!gate.ready_through(2));
    gate.mark_ready(1);
    gate.set_active(1);
    gate.set_connect_target(1);
    assert!(!gate.allowed(1));
    assert!(!gate.connection_needed(1), "unneeded recovery can stop");

    let (parked_tx, parked_rx) = std::sync::mpsc::channel();
    let (resumed_tx, resumed_rx) = std::sync::mpsc::channel();
    let worker_gate = gate.clone();
    let worker = std::thread::spawn(move || {
        let resumed = worker_gate.park(1, || {
            parked_tx.send(()).unwrap();
            false
        });
        resumed_tx.send(resumed).unwrap();
    });
    parked_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    // A further policy update must not close the parked connection either.
    gate.set_connect_target(1);
    assert!(resumed_rx.recv_timeout(Duration::from_millis(50)).is_err());
    assert!(gate.ready_through(2));
    assert!(gate.begin_warming(2).is_empty(), "reuse, not a new worker");
    gate.set_active(2);
    assert!(resumed_rx.recv_timeout(Duration::from_secs(5)).unwrap());
    worker.join().unwrap();
}

#[test]
fn parked_connections_exit_when_the_copy_finishes_or_aborts() {
    let gate = Gate::new(2);
    gate.mark_ready(1);
    gate.set_active(1);
    gate.set_connect_target(1);
    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (parked_tx, parked_rx) = std::sync::mpsc::channel();
    let (exit_tx, exit_rx) = std::sync::mpsc::channel();
    let worker_gate = gate.clone();
    let worker_done = done.clone();
    let worker = std::thread::spawn(move || {
        let resumed = worker_gate.park(1, || {
            parked_tx.send(()).unwrap();
            worker_done.load(Relaxed)
        });
        exit_tx.send(resumed).unwrap();
    });
    parked_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    done.store(true, Relaxed);
    assert!(!exit_rx.recv_timeout(Duration::from_secs(5)).unwrap());
    worker.join().unwrap();
}

#[test]
fn cancelled_connection_setup_does_not_discard_a_ready_slot() {
    let gate = Gate::new(1);
    gate.set_connect_target(3);
    assert_eq!(gate.begin_warming(3), vec![0, 1, 2]);
    gate.mark_ready(0);
    gate.mark_ready(1);
    gate.set_connect_target(1);
    assert!(!gate.connection_needed(2));
    gate.mark_absent(2);
    // Revisit the larger count: only the cancelled attempt needs setup.
    assert_eq!(gate.begin_warming(3), vec![2]);
    assert!(gate.ready_through(2));
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

#[test]
fn out_of_order_readiness_keeps_every_warming_slot() {
    // Workers connect in any order. A lower id reporting ready after a
    // higher one must not erase the higher slots, or the tuner's healing
    // poll would respawn duplicates of workers that are still running.
    let gate = Gate::new(4);
    assert_eq!(gate.begin_warming(4), vec![0, 1, 2, 3]);
    gate.mark_ready(3);
    gate.mark_ready(0);
    gate.mark_warming(2);
    gate.mark_ready(1);
    gate.mark_ready(2);
    assert!(gate.ready_through(4));
    assert!(gate.begin_warming(4).is_empty());

    // Shrinking the warming target must not forget higher candidates.
    gate.set_connect_target(6);
    assert_eq!(gate.begin_warming(6), vec![4, 5]);
    gate.mark_ready(5);
    assert!(gate.begin_warming(4).is_empty());
    gate.mark_ready(4);
    assert!(gate.ready_through(6));
    assert!(gate.begin_warming(6).is_empty());
}

#[test]
fn preparation_precedes_the_first_decision_without_activating_workers() {
    for (mut policy, candidate) in [
        (Policy::new(16, 1, 64), 32),
        (Policy::refine(16, 1, 64), 21),
    ] {
        let mut sampler = Sampler::default();
        sampler.reset();
        let lead = Duration::from_secs(12);
        let plan = policy.connection_plan(&sampler, SAMPLE, Duration::ZERO, lead, true);
        assert_eq!(plan.connect, candidate);
        assert_eq!(policy.n, 16);
        assert_eq!(policy.active(), 16);
        assert_eq!(policy.history, vec![16]);
        assert_eq!(policy.peak, 16);

        let gate = Gate::new(16);
        gate.prepare(plan);
        for id in gate.begin_warming(plan.connect) {
            gate.mark_ready(id);
        }
        assert!(gate.ready_through(candidate));
        assert!(!gate.allowed(16));
        assert_eq!(policy.observe(100.0), candidate);
        assert!(gate.begin_warming(policy.n).is_empty());
        gate.set_active(policy.n);
        policy.activated();
        assert!(gate.allowed(candidate - 1));
    }
}

#[test]
fn preparation_uses_earliest_sample_boundary_and_keeps_rollback_ready() {
    let mut sampler = Sampler::default();
    sampler.reset();
    assert_eq!(
        sampler.earliest_score_in(SAMPLE, Duration::ZERO),
        SAMPLE * 3
    );
    assert_eq!(sampler.push(100.0), None);
    assert_eq!(sampler.push(100.0), None);
    assert_eq!(
        sampler.earliest_score_in(SAMPLE, Duration::from_secs(2)),
        Duration::from_millis(500)
    );
    let mut policy = Policy::refine(16, 1, 64);
    let plan = policy.connection_plan(
        &sampler,
        SAMPLE,
        Duration::from_secs(2),
        Duration::from_secs(1),
        true,
    );
    assert_eq!(plan.connect, 21);
    policy.observe(100.0);
    policy.activated();
    policy.observe(70.0); // reject a clearly slower 21 and settle at 16
    policy.activated();
    assert_eq!(policy.n, 16);
    assert!(policy.begin(Direction::Down, 100.0));
    policy.activated();
    let plan = policy.connection_plan(
        &sampler,
        SAMPLE,
        Duration::ZERO,
        Duration::from_secs(1),
        true,
    );
    assert_eq!(plan.connect, 16, "keep rollback despite lower active count");
    assert!(plan.keep >= 16);
}

#[test]
fn distant_probe_releases_spares_then_prepares_before_it_is_due() {
    let mut policy = Policy::refine(16, 1, 64);
    policy.state = State::Hold;
    policy.due = [60, 60];
    let sampler = Sampler::default();
    let lead = Duration::from_secs(21); // measured ten seconds, doubled plus margin
    let plan = policy.connection_plan(&sampler, SAMPLE, Duration::ZERO, lead, true);
    assert_eq!(
        plan,
        ConnectionPlan {
            connect: 16,
            keep: 16
        }
    );
    policy.tick = 55; // 25 seconds until earliest probe: retain, not yet open
    let plan = policy.connection_plan(&sampler, SAMPLE, Duration::ZERO, lead, true);
    assert_eq!(plan.connect, 16);
    assert!(plan.keep >= 21);
    policy.tick = 56; // 20 seconds: open now, before the policy changes
    let plan = policy.connection_plan(&sampler, SAMPLE, Duration::ZERO, lead, true);
    assert_eq!(plan.connect, 21);
    assert_eq!(policy.n, 16);
    assert_eq!(policy.tick, 56);
}

#[test]
fn preparation_respects_limits_and_skips_speculation_at_the_tail() {
    let policy = Policy::new(16, 1, 18);
    let sampler = Sampler::default();
    let lead = Duration::from_secs(30);
    let plan = policy.connection_plan(&sampler, SAMPLE, Duration::ZERO, lead, true);
    assert_eq!(plan.connect, 18);
    let plan = policy.connection_plan(&sampler, SAMPLE, Duration::ZERO, lead, false);
    assert_eq!(plan.connect, 16);
    let fixed = Policy::new(16, 16, 16);
    assert_eq!(fixed.connection_forecast(), (16, None));
}

#[test]
fn retired_connection_is_not_ready_or_duplicated_before_worker_cleanup() {
    let gate = Gate::new(1);
    for id in gate.begin_warming(2) {
        gate.mark_ready(id);
    }
    gate.prepare(ConnectionPlan {
        connect: 1,
        keep: 1,
    });
    assert!(!gate.park(1, || false));
    assert!(!gate.ready_through(2));
    gate.prepare(ConnectionPlan {
        connect: 2,
        keep: 2,
    });
    assert!(
        gate.begin_warming(2).is_empty(),
        "wait for old worker cleanup"
    );
    gate.mark_absent(1);
    assert_eq!(gate.begin_warming(2), vec![1]);
    gate.mark_ready(1);
    assert!(gate.ready_through(2));
}

#[test]
fn warming_forecast_waits_for_candidate_measurements_not_baseline_refresh() {
    for (mut policy, candidate, following) in [
        (Policy::new(16, 1, 64), 32, 64),
        (Policy::refine(16, 1, 64), 21, 27),
    ] {
        assert_eq!(policy.observe(100.0), candidate);
        assert_eq!(policy.active(), 16);
        let mut baseline = Sampler::default();
        assert_eq!(baseline.push(100.0), None);
        // The next baseline score is due now, but the candidate still needs a
        // discarded sample plus two measured samples after activation.
        let plan = policy.connection_plan(&baseline, SAMPLE, SAMPLE, Duration::from_secs(6), true);
        assert_eq!(plan.connect, candidate);
        assert!(plan.keep >= candidate);
        assert!(policy.refresh_warming_baseline(100.0));
        let plan = policy.connection_plan(&baseline, SAMPLE, SAMPLE, Duration::from_secs(6), true);
        assert_eq!(plan.connect, candidate);
        // Truly slow setup can still justify overlapping preparation, using the
        // earliest post-activation decision rather than a baseline refresh.
        let plan = policy.connection_plan(&baseline, SAMPLE, SAMPLE, Duration::from_secs(10), true);
        assert_eq!(plan.connect, following);
        policy.activated();
        let plan = policy.connection_plan(&baseline, SAMPLE, SAMPLE, Duration::from_secs(6), true);
        assert_eq!(plan.connect, following);
    }
}

#[test]
fn setup_clock_starts_at_connection_not_worker_reservation() {
    let gate = Gate::new(1);
    assert_eq!(gate.begin_warming(1), vec![0]);
    // An initial worker may remain here throughout a slow source listing.
    // Reserving it must not start a clock that can include that wait.
    assert_eq!(gate.slots.lock().unwrap()[0].phase, SlotPhase::Warming);
    assert_eq!(gate.slots.lock().unwrap()[0].setup_started, None);
    assert_eq!(gate.setup_lead(), Duration::from_secs(1));
    assert!(!gate.ready_through(1));

    let connecting = Instant::now();
    gate.mark_warming(0);
    let started = gate.slots.lock().unwrap()[0].setup_started.unwrap();
    assert!(started >= connecting);
    gate.mark_warming(0);
    assert_eq!(gate.slots.lock().unwrap()[0].setup_started, Some(started));
    gate.mark_ready(0);
    assert!(gate.ready_through(1));
    assert_eq!(gate.slots.lock().unwrap()[0].setup_started, None);
}

#[test]
fn setup_lead_includes_retries_and_does_not_shrink_after_one_fast_setup() {
    let gate = Gate::new(1);
    gate.begin_warming(1);
    let started = Instant::now() - Duration::from_secs(10);
    gate.slots.lock().unwrap()[0].setup_started = Some(started);
    gate.mark_warming(0);
    assert_eq!(gate.slots.lock().unwrap()[0].setup_started, Some(started));
    gate.mark_ready(0);
    assert!(gate.setup_lead() >= Duration::from_secs(21));
    gate.begin_warming(2);
    gate.mark_warming(1);
    gate.mark_ready(1);
    assert!(gate.setup_lead() >= Duration::from_secs(21));
}

#[test]
fn missed_preparation_still_waits_for_ready_connections_and_optional_failure_isolated() {
    let mut policy = Policy::refine(16, 1, 64);
    let gate = Gate::new(16);
    for id in gate.begin_warming(16) {
        gate.mark_ready(id);
    }
    let plan = policy.connection_plan(
        &Sampler::default(),
        SAMPLE,
        Duration::ZERO,
        Duration::from_secs(10),
        true,
    );
    gate.prepare(plan);
    assert_eq!(
        gate.begin_warming(plan.connect),
        (16..21).collect::<Vec<_>>()
    );
    assert_eq!(policy.observe(100.0), 21);
    assert!(!gate.ready_through(policy.n));
    assert_eq!(gate.active(), 16);
    assert_eq!(policy.history, vec![16]);
    gate.mark_failed(20);
    assert!(gate.permanent_failure_through(21));
    assert!(!gate.permanent_failure_through(16));
    policy.cancel_unapplied();
    assert_eq!(policy.n, 16);
    assert_eq!(policy.peak, 16);
    assert!(gate.ready_through(16));
}

#[test]
fn a_preparation_pause_does_not_close_imminently_needed_spares() {
    let mut policy = Policy::refine(16, 1, 64);
    policy.state = State::Hold;
    policy.due = [1, 1];
    let plan = policy.connection_plan(
        &Sampler::default(),
        SAMPLE,
        Duration::ZERO,
        Duration::from_secs(10),
        false,
    );
    assert_eq!(plan.connect, 16);
    assert!(
        plan.keep >= 21,
        "no new setup, but don't discard ready capacity"
    );
}

#[test]
fn one_worker_start_prepares_spare_before_initial_connection_is_ready() {
    let gate = Gate::new(1);
    assert_eq!(gate.begin_warming(1), vec![0]);
    assert!(!gate.ready_through(1));
    let mut sampler = Sampler::default();
    sampler.reset();
    let mut policy = Policy::new(1, 1, 8);
    let plan = policy.connection_plan(
        &sampler,
        SAMPLE,
        Duration::ZERO,
        Duration::from_secs(1),
        false,
    );
    gate.prepare(plan);
    assert_eq!(gate.begin_warming(plan.connect), vec![1]);
    gate.mark_ready(1);
    gate.mark_ready(0);
    assert_eq!(policy.observe(100.0), 2);
    assert!(gate.ready_through(2));
    assert!(gate.begin_warming(2).is_empty());
    let fixed = Policy::new(1, 1, 1);
    assert_eq!(
        fixed
            .connection_plan(
                &sampler,
                SAMPLE,
                Duration::ZERO,
                Duration::from_secs(1),
                false
            )
            .connect,
        1
    );
}

#[test]
fn inconclusive_doubling_keeps_capacity_without_another_increase() {
    for score in [95.0, 100.0, 104.0] {
        let mut policy = Policy::new(8, 1, 64);
        measure(&mut policy, 100.0);
        assert_eq!(policy.n, 16);
        measure(&mut policy, score);
        assert_eq!(policy.n, 16);
        assert_eq!(policy.state, State::Hold);
        assert!(!policy.startup_doubling);
        assert!(policy.measured());
        assert!(!policy.discovery_complete());
        assert_eq!(
            policy.due[Direction::Up.index()],
            policy.tick + 2 * PROBE_EVERY
        );
        for _ in 0..PROBE_EVERY - 1 {
            measure(&mut policy, score);
            assert_eq!(policy.n, 16);
        }
    }
}

#[test]
fn downward_gain_requirement_preserves_clear_upward_loss_rollback() {
    let mut policy = Policy::refine(8, 1, 64);
    measure(&mut policy, 100.0);
    measure(&mut policy, 94.0);
    assert_eq!(policy.n, 8);
    for (score, keep_smaller) in [(101.0, true), (100.0, false), (95.0, false)] {
        let mut policy = Policy::refine(16, 1, 64);
        policy.record(16, 100.0);
        assert!(policy.begin(Direction::Down, 100.0));
        policy.activated();
        let lower = policy.n;
        measure(&mut policy, score);
        assert_eq!(policy.settled(), if keep_smaller { lower } else { 16 });
    }
}

#[test]
fn repeated_inconclusive_copies_do_not_raise_the_recommended_start() {
    // End copies before or after downward probes. Neither keeping a larger
    // count nor partially reducing it should ratchet the next start upward.
    for refine in [false, true] {
        for loss_per_doubling in [1.0_f64, 0.97] {
            for measurements in 2..=60 {
                let mut start = 8;
                for _ in 0..6 {
                    let mut policy = if refine {
                        Policy::refine(start, 1, 256)
                    } else {
                        Policy::new(start, 1, 256)
                    };
                    for _ in 0..measurements {
                        let score = 100.0 * loss_per_doubling.powf((policy.n as f64 / 8.0).log2());
                        measure(&mut policy, score);
                    }
                    assert!(policy.measured());
                    assert!(
                        policy.recommended() <= start,
                        "start={start}, samples={measurements}, refine={refine}, \
                         loss={loss_per_doubling}, policy={policy:?}"
                    );
                    start = policy.recommended();
                }
            }
        }
    }
}

#[test]
fn recommendation_changes_only_with_justified_growth_or_reduction() {
    let mut policy = Policy::new(8, 1, 64);
    measure(&mut policy, 100.0); // Proposed 16 is not a recommendation yet.
    assert_eq!(policy.recommended(), 8);
    measure(&mut policy, 200.0); // Clear gain at 16; propose 32.
    assert_eq!(policy.recommended(), 16);
    measure(&mut policy, 200.0); // Keep 32 live, but not for the next copy.
    assert_eq!(policy.settled(), 32);
    assert_eq!(policy.recommended(), 16);

    assert!(policy.begin(Direction::Down, 200.0));
    policy.activated();
    assert_eq!(policy.n, 24);
    measure(&mut policy, 201.0);
    assert_eq!(policy.settled(), 24);
    assert_eq!(policy.recommended(), 16); // Partial rollback must not save 24.
                                          // Allow earlier, slower lower-count measurements to age before retrying.
    for _ in 0..EVIDENCE_MAX_AGE * 4 {
        if policy.settled() < 16 {
            break;
        }
        let score = 300.0 - policy.n as f64;
        measure(&mut policy, score);
    }
    assert!(policy.recommended() < 16);
    assert_eq!(policy.recommended(), policy.settled());
    let lower = policy.recommended();
    policy.cancel_unapplied();
    assert_eq!(policy.recommended(), lower);
}

#[test]
fn ceiling_does_not_prevent_upward_recovery_after_descending() {
    let mut p = Policy::new(MAX, MIN, MAX);
    for _ in 0..200 {
        // A sharp optimum between the geometric steps on the way down.
        let rate = if p.n <= 12 {
            p.n as f64 / 12.0
        } else {
            12.0 / p.n as f64
        };
        measure(&mut p, rate * 100.0);
    }
    assert!(
        p.history.contains(&12),
        "never explored optimum: {:?}",
        p.history
    );
}

#[test]
fn floor_does_not_prevent_downward_recovery_after_growing() {
    let mut p = Policy::refine(1, 1, 4);
    // Reaching the lower boundary must not permanently disable this direction.
    assert!(!p.begin(Direction::Down, 100.0));
    for _ in 0..20 {
        let rate = p.n as f64 * 100.0;
        measure(&mut p, rate);
    }
    assert_eq!(p.settled(), 4);
    let after_growth = p.history.len();
    // All counts now provide the same rate; downward probes should resume.
    for _ in 0..200 {
        measure(&mut p, 100.0);
    }
    assert!(
        p.history[after_growth..].iter().any(|&n| n < 4),
        "never resumed downward probing: {:?}",
        p.history
    );
}

#[test]
fn downward_probe_requires_a_measured_speed_increase() {
    for score in [94.0, 95.0, 99.0, 100.0, 100.001, 101.0] {
        let mut policy = Policy::refine(32, MIN, MAX);
        policy.record(32, 100.0);
        assert!(policy.begin(Direction::Down, 100.0));
        policy.activated();
        let lower = policy.n;
        measure(&mut policy, score);
        assert_eq!(
            policy.settled(),
            if score > 100.0 { lower } else { 32 },
            "score={score}"
        );
        assert_eq!(policy.recommended(), policy.settled());
    }
}

#[test]
fn aging_evidence_does_not_make_a_slower_reduction_acceptable() {
    let mut p = Policy::refine(32, MIN, MAX);
    for _ in 0..1000 {
        let score = p.n.min(32) as f64 * 100.0 / 32.0;
        measure(&mut p, score);
        assert!(p.settled() >= 32, "settled below full speed: {p:?}");
        assert_eq!(p.recommended(), 32);
    }
}

#[test]
fn network_keys_preserve_the_v060_legacy_map() {
    let dir = crate::test_support::tempdir().unwrap();
    let path = dir.path().join("tuning.json");
    let fixture = br#"{"paths":{"local>user@host|tcp":128,"user@host>local|ssh":4}}"#;
    std::fs::write(&path, fixture).unwrap();
    let old = "local>user@host|tcp";
    let home = network_key(old, Some("home"));
    let office = network_key(old, Some("office"));
    let unknown = network_key(old, None);
    assert_eq!(cached_at(&path, &home), None);
    assert_eq!(cached_at(&path, &unknown), Some(128));
    remember_at(&path, &home, 8).unwrap();
    remember_at(&path, &office, 32).unwrap();
    assert_eq!(cached_at(&path, old), Some(128));
    assert_eq!(cached_at(&path, &home), Some(8));
    assert_eq!(cached_at(&path, &office), Some(32));
    remember_at(&path, old, 64).unwrap();
    assert_eq!(cached_at(&path, &home), Some(8));
    assert_eq!(cached_at(&path, &office), Some(32));
}

#[test]
fn upward_gain_uses_live_baseline_despite_higher_historical_scores() {
    for (historical_count, age) in [(32, 0), (10, 0), (10, EVIDENCE_MAX_AGE + 1)] {
        let mut p = Policy::refine(8, MIN, MAX);
        measure(&mut p, 64.0);
        assert_eq!(p.n, 10);
        p.tick += age;
        p.points.insert(
            historical_count,
            Point {
                score: 100.0,
                measured_at: p.tick - age,
            },
        );
        p.fails[Direction::Up.index()] = 2;
        measure(&mut p, 70.0);
        assert_eq!(p.recommended(), 10);
        assert_eq!(p.fails[Direction::Up.index()], 0);
        assert!(p.n > 10, "a current gain must continue upward: {p:?}");
        assert_eq!(p.probe_base(), Some(70.0));
    }
}

#[test]
fn smaller_upward_gain_does_not_resume_growth_below_old_high_water() {
    let mut p = Policy::refine(8, MIN, MAX);
    measure(&mut p, 64.0);
    p.points.insert(
        32,
        Point {
            score: 100.0,
            measured_at: p.tick,
        },
    );
    measure(&mut p, 66.0);
    assert_eq!(p.n, 10);
    assert_eq!(p.recommended(), 8);
    assert!(matches!(p.state, State::Hold));
}

#[test]
fn whole_file_reductions_wait_for_excess_writers_to_finish() {
    let gate = Gate::new(4);
    for id in 0..4 {
        gate.mark_ready(id);
    }
    let kept = gate.whole_file(0);
    let excess = gate.whole_file(3);
    assert!(!gate.whole_files_draining(4));
    gate.set_active(2);
    assert!(gate.ready_through(2));
    assert!(gate.whole_files_draining(2));
    drop(excess);
    assert!(!gate.whole_files_draining(2));
    // Work in the retained configuration does not delay its own measurement.
    drop(kept);
    assert!(!gate.whole_files_draining(2));
}

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
    assert!(
        (65..=128).contains(&policy.settled()),
        "{:?}",
        policy.history
    );
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
    let mut policy = Policy::new(10, MIN, MAX);
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
    let mut policy = Policy::new(16, 1, 64);
    let mut sampler = Sampler::default();
    sampler.reset();
    let lead = Duration::from_secs(12);
    let plan = policy.connection_plan(&sampler, SAMPLE, Duration::ZERO, lead, true);
    assert_eq!(plan.connect, 21);
    assert_eq!(policy.n, 16);
    assert_eq!(policy.active(), 16);
    assert_eq!(policy.history, vec![16]);
    assert_eq!(policy.peak, 16);

    let gate = Gate::new(16);
    gate.prepare(plan);
    for id in gate.begin_warming(plan.connect) {
        gate.mark_ready(id);
    }
    assert!(gate.ready_through(21));
    assert!(!gate.allowed(16));
    assert_eq!(policy.observe(100.0), 21);
    assert!(gate.begin_warming(policy.n).is_empty());
    gate.set_active(policy.n);
    policy.activated();
    assert!(gate.allowed(20));
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
    let mut policy = Policy::new(16, 1, 64);
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
    policy.observe(100.0); // reject 21 and settle at 16
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
    let mut policy = Policy::new(16, 1, 64);
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
    gate.mark_ready(1);
    assert!(gate.setup_lead() >= Duration::from_secs(21));
}

#[test]
fn missed_preparation_still_waits_for_ready_connections_and_optional_failure_isolated() {
    let mut policy = Policy::new(16, 1, 64);
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
    let mut policy = Policy::new(16, 1, 64);
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

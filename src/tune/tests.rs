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
    assert_eq!(slow, 1_500_000);
    assert_eq!(fast, 1_500_000_000);
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
    g.set_retain(3);
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
fn gate_distinguishes_warming_ready_active_and_retired() {
    let gate = Gate::new(2);
    assert_eq!(gate.begin_warming(2), vec![0, 1]);
    assert!(!gate.ready_through(2));
    gate.mark_ready(0);
    assert!(!gate.ready_through(2));
    gate.mark_ready(1);
    assert!(gate.ready_through(2));

    gate.set_active(1);
    gate.set_retain(1);
    assert!(gate.allowed(0));
    assert!(!gate.allowed(1));
    assert!(!gate.park(1, || false), "surplus slot should retire");
    gate.mark_absent(1);
    assert_eq!(gate.begin_warming(2), vec![1]);
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
    gate.set_retain(6);
    assert_eq!(gate.begin_warming(6), vec![4, 5]);
    gate.mark_ready(5);
    assert!(gate.begin_warming(4).is_empty());
    gate.mark_ready(4);
    assert!(gate.ready_through(6));
    assert!(gate.begin_warming(6).is_empty());
}

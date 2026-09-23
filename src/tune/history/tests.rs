use super::*;

pub(super) fn recorder(path: &Path) -> Recorder {
    Recorder::at(
        path,
        Instant::now(),
        json!({"policy_version":1}),
        DEFAULT_BUDGET,
    )
    .unwrap()
}
pub(super) fn key(destination: &str) -> ContextKey {
    ContextKey {
        route: "route".into(),
        source_filesystem: Some("source".into()),
        destination_filesystem: Some(destination.into()),
        mode: "default".into(),
        ..Default::default()
    }
}

#[test]
fn filesystem_hint_survives_other_destination_and_incomplete_runs() {
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("history.sqlite");
    let first = recorder(&path);
    first.context(&key("a"));
    first.finish(true, true, Some(8), json!({}));
    let second = recorder(&path);
    second.context(&key("b"));
    second.finish(true, true, Some(32), json!({}));
    let short = recorder(&path);
    short.context(&key("a"));
    short.finish(true, false, None, json!({"bytes":123}));
    let failed = recorder(&path);
    failed.context(&key("a"));
    failed.finish(false, true, Some(64), json!({}));
    let next = recorder(&path);
    assert_eq!(next.hint(&key("a"), true).unwrap().workers, 8);
    assert_eq!(next.hint(&key("b"), true).unwrap().workers, 32);
    assert_eq!(next.hint(&key("unknown"), true).unwrap().matched, "route");
    assert!(next.hint(&key("unknown"), false).is_none());
    let mut other_mode = key("a");
    other_mode.mode = "bandwidth_limited".into();
    assert!(next.hint(&other_mode, true).is_none());
}

#[test]
fn only_completed_plateau_with_exact_filesystems_allows_refinement() {
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("history.sqlite");
    let old = recorder(&path);
    old.context(&key("a"));
    // Unchanged old summary: still a useful hint, with no discovery evidence.
    old.finish(true, true, Some(8), json!({"elapsed_ms":1000,"bytes":123}));
    let hint = old.hint(&key("a"), false).unwrap();
    assert_eq!(hint.workers, 8);
    assert!(!hint.refine);

    let weak = recorder(&path);
    weak.context(&key("a"));
    weak.recommend(16, false);
    weak.complete(true, json!({}));
    let hint = weak.hint(&key("a"), false).unwrap();
    assert_eq!(hint.workers, 16);
    assert!(!hint.refine);

    let strong = recorder(&path);
    strong.context(&key("a"));
    strong.recommend(24, true);
    // A recommendation has no effect until the whole transfer succeeds.
    assert_eq!(strong.hint(&key("a"), false).unwrap().workers, 16);
    strong.complete(true, json!({}));
    let hint = strong.hint(&key("a"), false).unwrap();
    assert_eq!(hint.workers, 24);
    assert!(hint.refine);
    let broad = strong.hint(&key("different-filesystem"), true).unwrap();
    assert_eq!(broad.workers, 24);
    assert!(!broad.refine);
    let mut other_mode = key("a");
    other_mode.mode = "other settings".into();
    assert!(strong.hint(&other_mode, true).is_none());

    let failed = recorder(&path);
    failed.context(&key("a"));
    failed.recommend(32, true);
    failed.complete(false, json!({}));
    assert_eq!(failed.hint(&key("a"), false).unwrap().workers, 24);
}

#[test]
fn partial_history_is_durable_without_a_successful_finish() {
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("history.sqlite");
    let id;
    {
        let writer = recorder(&path);
        id = writer.0.lock().unwrap().id;
        writer.event(
            "sample",
            json!({"bytes":100,"files":2,"disposition":"warmup_excluded"}),
        );
    }
    let db = open(&path).unwrap();
    assert_eq!(command::read_run(&db, id).unwrap()["status"], "incomplete");
    let events = command::read_events(&db, id).unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[1]["data"]["bytes"], 100);
    assert_eq!(events[1]["sequence"], 1);
}

#[test]
fn legacy_v060_cache_remains_byte_for_byte_unchanged() {
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("tuning.json");
    // Unchanged v0.6.0 paths map, including a count above the older test ceiling.
    let fixture = br#"{"paths":{"local>user@host|tcp":128,"user@host>local|ssh":4}}"#;
    std::fs::write(&path, fixture).unwrap();
    let writer = recorder(&path.with_extension("history-v1.sqlite"));
    writer.context(&key("a"));
    writer.finish(true, true, Some(16), json!({}));
    assert_eq!(std::fs::read(&path).unwrap(), fixture);
    assert_eq!(
        super::super::cached_at(&path, "local>user@host|tcp"),
        Some(128)
    );
    // Old writers still update their own file without erasing new evidence.
    super::super::remember_at(&path, "local>user@host|tcp", 8).unwrap();
    assert_eq!(writer.hint(&key("a"), true).unwrap().workers, 16);
}

#[test]
fn tokens_are_stable_locally_and_different_between_stores() {
    let temp = crate::test_support::tempdir().unwrap();
    let one = recorder(&temp.path().join("one.sqlite"));
    let same = recorder(&temp.path().join("one.sqlite"));
    let other = recorder(&temp.path().join("other.sqlite"));
    assert_eq!(
        one.token("route", "private-host"),
        same.token("route", "private-host")
    );
    assert_ne!(
        one.token("route", "private-host"),
        other.token("route", "private-host")
    );
    assert_ne!(
        one.token("route", "private-host"),
        one.token("filesystem", "private-host")
    );
    assert!(!one.token("route", "private-host").contains("private-host"));
}

#[test]
fn retention_removes_whole_old_runs_and_keeps_current_and_active() {
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("history.sqlite");
    let old = recorder(&path);
    old.finish(true, false, None, json!({}));
    let active = recorder(&path);
    let current = recorder(&path);
    current.finish(true, false, None, json!({}));
    let db = open(&path).unwrap();
    prune(&db, 1, current.0.lock().unwrap().id).unwrap();
    assert!(command::read_run(&db, old.0.lock().unwrap().id).is_err());
    assert!(command::read_events(&db, old.0.lock().unwrap().id)
        .unwrap()
        .is_empty());
    assert!(command::read_run(&db, active.0.lock().unwrap().id).is_ok());
    assert!(command::read_run(&db, current.0.lock().unwrap().id).is_ok());
}

#[test]
fn lock_contention_keeps_samples_and_context_for_later_flush() {
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("history.sqlite");
    let writer = recorder(&path);
    writer.context(&key("a"));
    let other = open(&path).unwrap();
    other.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut mixed = key("a");
    mixed.destination_filesystem = None;
    writer.context(&mixed);
    writer.event("sample", json!({"bytes":123}));
    writer.flush();
    assert_eq!(writer.0.lock().unwrap().pending.len(), 1);
    other.execute_batch("COMMIT").unwrap();
    writer.finish(true, true, Some(8), json!({}));
    assert!(writer.0.lock().unwrap().pending.is_empty());
    assert!(writer.0.lock().unwrap().pending_context.is_none());
    assert!(writer.hint(&key("a"), false).is_none());
    let run = command::read_run(&other, writer.0.lock().unwrap().id).unwrap();
    assert_eq!(run["context"]["destination_filesystem"], Value::Null);
    assert_eq!(run["recommendation_eligible"], true);
    assert_eq!(
        command::read_events(&other, writer.0.lock().unwrap().id)
            .unwrap()
            .len(),
        3
    );
}

#[test]
fn final_save_preserves_pending_evidence_and_restores_nonblocking_writes() {
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("history.sqlite");
    let recorder = recorder(&path);
    let other = open(&path).unwrap();
    other.execute_batch("BEGIN IMMEDIATE").unwrap();
    recorder.context(&key("a"));
    recorder.event("sample", json!({"bytes":123}));
    let mut writer = recorder.0.lock().unwrap();
    let error = writer.finish(true, true, Some(8), json!({})).unwrap_err();
    assert!(matches!(
        error.downcast_ref::<rusqlite::Error>(),
        Some(rusqlite::Error::SqliteFailure(error, _))
            if error.code == rusqlite::ErrorCode::DatabaseBusy
    ));
    let timeout: i64 = writer
        .db
        .pragma_query_value(None, "busy_timeout", |r| r.get(0))
        .unwrap();
    assert_eq!(timeout, 0);
    assert!(!writer.pending.is_empty());
    assert!(writer.pending_context.is_some());
    other.execute_batch("COMMIT").unwrap();
    assert_eq!(
        command::read_run(&other, writer.id).unwrap()["status"],
        "incomplete"
    );

    writer
        .finish(true, true, Some(8), json!({"files":1}))
        .unwrap();
    let timeout: i64 = writer
        .db
        .pragma_query_value(None, "busy_timeout", |r| r.get(0))
        .unwrap();
    assert_eq!(timeout, 0);
    assert!(writer.pending.is_empty());
    assert!(writer.pending_context.is_none());
    let run = command::read_run(&other, writer.id).unwrap();
    assert_eq!(run["status"], "success");
    assert_eq!(run["selected_workers"], 8);
    assert_eq!(run["context"]["destination_filesystem"], "a");
    assert_eq!(run["recommendation_eligible"], true);
    assert!(command::read_events(&other, writer.id)
        .unwrap()
        .iter()
        .any(|e| e["kind"] == "sample"));
}

#[test]
fn failed_final_save_does_not_publish_partial_context_or_samples() {
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("history.sqlite");
    let recorder = recorder(&path);
    let mut writer = recorder.0.lock().unwrap();
    writer.pending_context = Some(key("a"));
    writer
        .pending
        .push(json!({"sequence":1,"elapsed_us":1,"kind":"sample","data":{}}));
    writer.db.execute_batch("CREATE TRIGGER fail_completion BEFORE UPDATE OF status ON runs BEGIN SELECT RAISE(ABORT,'injected failure'); END;").unwrap();
    assert!(writer.finish(true, true, Some(8), json!({})).is_err());
    let run = command::read_run(&writer.db, writer.id).unwrap();
    assert_eq!(run["status"], "incomplete");
    assert_eq!(run["context"], json!({}));
    assert_eq!(
        command::read_events(&writer.db, writer.id).unwrap().len(),
        1
    );
    assert!(!writer.pending.is_empty());
    assert!(writer.pending_context.is_some());
}

#[test]
fn decisions_include_comparison_evidence_and_unapplied_candidates() {
    use super::super::{trace::Trace, Gate, Policy};
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("history.sqlite");
    let writer = recorder(&path);
    let mut policy = Policy::new(8, 1, 64);
    let gate = Gate::new(8);
    let mut trace = Trace::new(Some(writer.clone()), &policy, super::super::SAMPLE);
    trace.sample((0, 0), (100, 1), 2.5, &policy, &gate, "stable", Some(100.0));
    trace.observe(&mut policy, 100.0, "stable");
    assert_eq!(policy.n, 16);
    assert_eq!(policy.active(), 8);
    trace.cancel(
        &mut policy,
        "insufficient_remaining_work",
        Some(100.0),
        Duration::from_secs(2),
    );
    trace.sample(
        (100, 1),
        (110, 1),
        0.1,
        &policy,
        &gate,
        "final_partial",
        None,
    );
    trace.end(&policy, false);
    writer.finish(true, false, None, json!({}));
    let db = open(&path).unwrap();
    let events = command::read_events(&db, writer.0.lock().unwrap().id).unwrap();
    let start = events.iter().find(|e| e["kind"] == "policy_start").unwrap();
    assert_eq!(
        start["data"]["policy_version"],
        super::super::POLICY_VERSION
    );
    assert_eq!(start["data"]["startup_step"], 2);
    assert_eq!(start["data"]["policy"]["startup_doubling"], true);
    let decision = events.iter().find(|e| e["kind"] == "decision").unwrap();
    assert_eq!(decision["data"]["reason"], "probe_proposed");
    assert_eq!(decision["data"]["score"], 100.0);
    assert_eq!(decision["data"]["sample_ids"], json!([1]));
    assert_eq!(decision["data"]["after"]["requested"], 16);
    let end = events.iter().find(|e| e["kind"] == "policy_end").unwrap();
    assert_eq!(end["data"]["policy"]["startup_doubling"], false);
    assert!(events
        .iter()
        .any(|e| e["data"]["reason"] == "insufficient_remaining_work"));
    assert!(events
        .iter()
        .any(|e| e["data"]["disposition"] == "final_partial"));
    assert!(writer.hint(&key("a"), true).is_none());
}

#[test]
fn concurrent_initialization_shares_one_identity_key() {
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("history.sqlite");
    let barrier = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..2)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    let writer = recorder(&path);
                    writer.token("endpoint", "same-endpoint")
                })
            })
            .collect();
        let tokens: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(tokens[0], tokens[1]);
    });
    assert_eq!(
        open(&path)
            .unwrap()
            .query_row("SELECT count(*) FROM runs", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        2
    );
}

#[test]
fn invalid_zero_worker_hint_does_not_hide_an_older_valid_hint() {
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("history.sqlite");
    let valid = recorder(&path);
    valid.context(&key("a"));
    valid.finish(true, true, Some(8), json!({}));
    let invalid = recorder(&path);
    invalid.context(&key("a"));
    invalid.finish(true, true, Some(0), json!({}));
    assert_eq!(invalid.hint(&key("a"), false).unwrap().workers, 8);
}

#[test]
fn trace_distinguishes_acceptance_rejection_and_pending_comparison() {
    use super::super::{trace::Trace, Gate, Policy};
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("history.sqlite");
    let writer = recorder(&path);
    let mut policy = Policy::refine(8, 1, 64);
    let gate = Gate::new(8);
    let mut trace = Trace::new(Some(writer.clone()), &policy, super::super::SAMPLE);
    trace.observe(&mut policy, 100.0, "stable");
    policy.activated();
    trace.transition(&policy, "candidate_ready");
    trace.sample((0, 0), (300, 0), 2.5, &policy, &gate, "stable", Some(120.0));
    trace.observe(&mut policy, 120.0, "stable");
    assert_eq!(policy.settled(), 10);
    policy.activated();
    trace.transition(&policy, "candidate_ready");
    trace.sample(
        (300, 0),
        (600, 0),
        2.5,
        &policy,
        &gate,
        "stable",
        Some(80.0),
    );
    trace.observe(&mut policy, 80.0, "stable");
    assert_eq!(policy.settled(), 10);
    trace.end(&policy, false);
    let events = command::read_events(&open(&path).unwrap(), writer.0.lock().unwrap().id).unwrap();
    let decisions: Vec<_> = events.iter().filter(|e| e["kind"] == "decision").collect();
    assert_eq!(decisions[0]["data"]["before"]["startup_doubling"], false);
    assert_eq!(decisions[0]["data"]["after"]["requested"], 10);
    assert_eq!(decisions[1]["data"]["reason"], "probe_accepted");
    assert_eq!(
        decisions[1]["data"]["before"]["state"]["Explore"]["base"],
        100.0
    );
    assert_eq!(
        decisions[1]["data"]["after"]["historical_near_best_floor"],
        114.0
    );
    assert_eq!(decisions[2]["data"]["reason"], "probe_rejected");
    assert_eq!(decisions[2]["data"]["sample_ids"], json!([2]));
    assert_eq!(events.last().unwrap()["data"]["pending_comparison"], false);
}

#[test]
fn filesystem_tokens_can_be_related_across_transfer_directions() {
    let temp = crate::test_support::tempdir().unwrap();
    let writer = recorder(&temp.path().join("history.sqlite"));
    let endpoint = crate::conn::Endpoint::local();
    let forward = context_key(
        &writer,
        &endpoint,
        &endpoint,
        Some("a"),
        Some("b"),
        "default".into(),
    );
    let reverse = context_key(
        &writer,
        &endpoint,
        &endpoint,
        Some("b"),
        Some("a"),
        "default".into(),
    );
    assert_eq!(forward.source_filesystem, reverse.destination_filesystem);
    assert_eq!(forward.destination_filesystem, reverse.source_filesystem);
    assert_ne!(forward.source_filesystem, forward.destination_filesystem);
}

#[test]
fn tcp_preflight_preserves_evidence_without_storing_addresses() {
    use crate::conn::{DataAddressSource, TcpCandidate, TcpProbe};
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("history.sqlite");
    let first = recorder(&path);
    let probe = TcpProbe {
        port: 47600,
        encrypted: true,
        congestion_control: Some("cubic".into()),
        candidates: vec![
            TcpCandidate {
                address: "192.0.2.10".into(),
                speed_mbps: 100_000,
                source: DataAddressSource::RemoteInterface,
                reachable: Some(true),
                selected: true,
            },
            TcpCandidate {
                address: "example.invalid".into(),
                speed_mbps: 0,
                source: DataAddressSource::SshTarget,
                reachable: Some(false),
                selected: false,
            },
            TcpCandidate {
                address: "2001:db8::10".into(),
                speed_mbps: 0,
                source: DataAddressSource::RemoteInterface,
                reachable: None,
                selected: false,
            },
        ],
    };
    first.context(&key("a"));
    first.tcp_probe("destination", "user@example.invalid", &probe);
    first.finish(true, true, Some(8), json!({}));
    let second = recorder(&path);
    second.tcp_probe("source", "user@example.invalid", &probe);
    second.flush();
    let db = open(&path).unwrap();
    let first_events = command::read_events(&db, 1).unwrap();
    let second_events = command::read_events(&db, 2).unwrap();
    let data = &first_events[1]["data"];
    assert_eq!(first_events[1]["kind"], "tcp_preflight");
    assert_eq!(data["role"], "destination");
    assert_eq!(data["encrypted"], true);
    assert_eq!(data["congestion_control"], "cubic");
    let candidates = &data["candidates"];
    assert_eq!(candidates[0]["reported_speed_mbps"], 100_000);
    assert_eq!(candidates[0]["selected"], true);
    assert_eq!(candidates[0]["reachable"], true);
    assert_eq!(candidates[1]["source"], "ssh_target");
    assert!(candidates[1]["reported_speed_mbps"].is_null());
    assert_eq!(candidates[1]["selected"], false);
    assert_eq!(candidates[1]["reachable"], false);
    assert!(candidates[2]["reachable"].is_null());
    assert_eq!(candidates[2]["selected"], false);
    assert_eq!(candidates, &second_events[1]["data"]["candidates"]);
    assert_eq!(second.hint(&key("a"), true).unwrap().workers, 8);
    let exported = serde_json::to_string(&first_events).unwrap();
    assert!(!exported.contains("192.0.2.10"));
    assert!(!exported.contains("example.invalid"));
    assert!(!exported.contains("2001:db8::10"));
    let other = recorder(&temp.path().join("other.sqlite"));
    assert_ne!(
        first.token("tcp_address", "same"),
        other.token("tcp_address", "same")
    );
}

#[test]
fn trace_records_inconclusive_upward_hold_without_claiming_a_plateau() {
    use super::super::{trace::Trace, Policy};
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("history.sqlite");
    let writer = recorder(&path);
    let mut policy = Policy::new(8, 1, 64);
    let mut trace = Trace::new(Some(writer.clone()), &policy, super::super::SAMPLE);
    trace.observe(&mut policy, 100.0, "stable");
    policy.activated();
    trace.observe(&mut policy, 100.0, "stable");
    trace.end(&policy, false);
    let events = command::read_events(&open(&path).unwrap(), writer.0.lock().unwrap().id).unwrap();
    let decision = events
        .iter()
        .rev()
        .find(|e| e["kind"] == "decision")
        .unwrap();
    assert_eq!(decision["data"]["reason"], "probe_inconclusive");
    assert_eq!(decision["data"]["after"]["requested"], 16);
    assert_eq!(decision["data"]["after"]["state"], "Hold");
    let end = events.last().unwrap();
    assert_eq!(end["data"]["completed_comparison"], true);
    assert_eq!(end["data"]["last_accepted"], 16);
    assert!(end["data"].get("recommended").is_none());
    assert!(end["data"].get("discovery_complete").is_none());
}

#[test]
fn repeated_inconclusive_copies_preserve_history_and_legacy_start() {
    use super::super::{cached_at, remember_at, Policy};
    for use_history in [false, true] {
        let temp = crate::test_support::tempdir().unwrap();
        let history_path = temp.path().join("history.sqlite");
        let cache_path = temp.path().join("tuning.json");
        for run in 0..6 {
            let writer = recorder(&history_path);
            let context = key("a");
            writer.context(&context);
            let hint = use_history.then(|| writer.hint(&context, true)).flatten();
            if run > 0 && use_history {
                assert!(
                    hint.is_some(),
                    "exercise history precedence over legacy cache"
                );
            }
            let start = hint
                .as_ref()
                .map(|h| h.workers)
                .or_else(|| cached_at(&cache_path, "path"))
                .unwrap_or(8);
            assert_eq!(start, 8);
            let mut policy = if hint.is_some_and(|h| h.refine) {
                Policy::refine(start, 1, 256)
            } else {
                Policy::new(start, 1, 256)
            };
            policy.observe(100.0);
            policy.activated();
            policy.observe(97.0);
            policy.activated();
            assert_eq!(policy.active(), 16);
            assert!(policy.measured());
            assert_eq!(policy.recommended(), 8);
            writer.recommend(policy.recommended(), policy.discovery_complete());
            writer.complete(true, json!({}));
            remember_at(&cache_path, "path", policy.recommended()).unwrap();
            assert_eq!(cached_at(&cache_path, "path"), Some(8));
            let saved = writer.hint(&context, true).unwrap();
            assert_eq!(saved.workers, 8);
            assert!(!saved.refine);
        }
    }
}

#[test]
fn network_scoped_hints_separate_known_networks_and_preserve_unknown_fallback() {
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("history.sqlite");
    let network_key = |network: Option<&str>| {
        let mut key = key("a");
        key.source_transport = "Local".into();
        key.destination_transport = "Ssh".into();
        key.route = super::super::network_key(&key.route, network);
        key.network = network.map(str::to_owned);
        key
    };
    // An unchanged pre-fingerprint context remains the fallback when the OS
    // cannot identify a network, but does not seed known-network contexts.
    let old = recorder(&path);
    old.context(&key("a"));
    old.recommend(64, true);
    old.complete(true, json!({}));
    let home = recorder(&path);
    assert!(home.hint(&network_key(Some("home")), true).is_none());
    home.context(&network_key(Some("home")));
    home.recommend(8, true);
    home.complete(true, json!({}));
    let office = recorder(&path);
    assert!(office.hint(&network_key(Some("office")), true).is_none());
    office.context(&network_key(Some("office")));
    office.recommend(32, true);
    office.complete(true, json!({}));
    let next = recorder(&path);
    let hint = next.hint(&network_key(Some("home")), true).unwrap();
    assert_eq!(hint.workers, 8);
    assert!(hint.refine);
    assert_eq!(
        next.hint(&network_key(Some("office")), true)
            .unwrap()
            .workers,
        32
    );
    assert_eq!(next.hint(&network_key(None), true).unwrap().workers, 64);
    next.context(&network_key(None));
    next.recommend(16, true);
    next.complete(true, json!({}));
    let hint = next.hint(&network_key(None), true).unwrap();
    assert_eq!(hint.workers, 16);
    assert!(hint.refine);
    // An old selector shares the unscoped fallback, but cannot overwrite the
    // known-network entries, even after publishing another recommendation.
    assert_eq!(next.hint(&key("a"), true).unwrap().workers, 16);
    assert_eq!(
        next.hint(&network_key(Some("home")), true).unwrap().workers,
        8
    );
}

#[test]
fn trace_clock_units_match_the_driver() {
    for elapsed in [false, true] {
        let temp = crate::test_support::tempdir().unwrap();
        let path = temp.path().join("history.sqlite");
        let writer = recorder(&path);
        let mut policy = super::super::Policy::new(8, 1, 64);
        if elapsed {
            policy.advance_time(Duration::ZERO, super::super::SAMPLE);
        }
        let trace =
            super::super::trace::Trace::new(Some(writer.clone()), &policy, super::super::SAMPLE);
        trace.end(&policy, false);
        let events =
            command::read_events(&open(&path).unwrap(), writer.0.lock().unwrap().id).unwrap();
        let start = &events.iter().find(|e| e["kind"] == "policy_start").unwrap()["data"];
        assert_eq!(
            start["clock_unit"],
            if elapsed {
                "elapsed_sample_intervals"
            } else {
                "accepted_measurements"
            }
        );
        assert_eq!(
            start["upward_max_wait_ms"],
            if elapsed { json!(30000) } else { Value::Null }
        );
    }
}

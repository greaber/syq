use super::*;

fn recorder(path: &Path) -> Recorder {
    Recorder::at(
        path,
        Instant::now(),
        json!({"policy_version":1}),
        DEFAULT_BUDGET,
    )
    .unwrap()
}
fn key(destination: &str) -> ContextKey {
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
fn lock_contention_keeps_samples_for_later_flush() {
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("history.sqlite");
    let writer = recorder(&path);
    let other = open(&path).unwrap();
    other.execute_batch("BEGIN IMMEDIATE").unwrap();
    writer.event("sample", json!({"bytes":123}));
    writer.flush();
    assert_eq!(writer.0.lock().unwrap().pending.len(), 1);
    other.execute_batch("COMMIT").unwrap();
    writer.flush();
    assert!(writer.0.lock().unwrap().pending.is_empty());
    assert_eq!(
        command::read_events(&other, writer.0.lock().unwrap().id)
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn decisions_include_comparison_evidence_and_unapplied_candidates() {
    use super::super::{trace::Trace, Gate, Policy};
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("history.sqlite");
    let writer = recorder(&path);
    let mut policy = Policy::new(8, 1, 64);
    let gate = Gate::new(8);
    let mut trace = Trace::new(Some(writer.clone()), &policy);
    trace.sample((0, 0), (100, 1), 2.5, &policy, &gate, "stable", Some(100.0));
    trace.observe(&mut policy, 100.0, "stable");
    assert_eq!(policy.n, 10);
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
    let decision = events.iter().find(|e| e["kind"] == "decision").unwrap();
    assert_eq!(decision["data"]["reason"], "probe_proposed");
    assert_eq!(decision["data"]["score"], 100.0);
    assert_eq!(decision["data"]["sample_ids"], json!([1]));
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
    let mut policy = Policy::new(8, 1, 64);
    let gate = Gate::new(8);
    let mut trace = Trace::new(Some(writer.clone()), &policy);
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
        Some(120.0),
    );
    trace.observe(&mut policy, 120.0, "stable");
    assert_eq!(policy.settled(), 10);
    trace.end(&policy, false);
    let events = command::read_events(&open(&path).unwrap(), writer.0.lock().unwrap().id).unwrap();
    let decisions: Vec<_> = events.iter().filter(|e| e["kind"] == "decision").collect();
    assert_eq!(decisions[1]["data"]["reason"], "probe_accepted");
    assert_eq!(
        decisions[1]["data"]["before"]["state"]["Explore"]["base"],
        100.0
    );
    assert_eq!(decisions[1]["data"]["after"]["acceptance_floor"], 114.0);
    assert_eq!(decisions[2]["data"]["reason"], "probe_rejected");
    assert_eq!(decisions[2]["data"]["sample_ids"], json!([2]));
    assert_eq!(events.last().unwrap()["data"]["pending_comparison"], false);
}

use super::*;

pub(in crate::tune) fn recorder(path: &Path) -> Recorder {
    let recorder = Recorder::at(
        path,
        Instant::now(),
        json!({"policy_version":1}),
        DEFAULT_BUDGET,
    );
    let mut state = recorder.0.lock().unwrap();
    // A test asks for a periodic save when it wants one, so that a slow
    // machine does not add one a second into it.
    state.next_write = Instant::now() + Duration::from_secs(3600);
    // Nor does the history open in the background, racing the connections
    // that a test opens to the same file.
    assert!(state.ready());
    drop(state);
    recorder
}
/// Save what `writer` has recorded so far, as a copy more than a second old
/// does on its next event, and return its run.
pub(in crate::tune) fn saved(writer: &Recorder) -> i64 {
    let mut state = writer.0.lock().unwrap();
    state.save().unwrap();
    state.id.expect("a saved run has a row")
}

fn run_count(db: &Connection) -> i64 {
    db.query_row("SELECT count(*) FROM runs", [], |r| r.get(0))
        .unwrap()
}

pub(in crate::tune) fn key(destination: &str) -> ContextKey {
    ContextKey {
        route: "route".into(),
        source_filesystem: Some("source".into()),
        destination_filesystem: Some(destination.into()),
        mode: "default".into(),
        ..Default::default()
    }
}

#[test]
fn partial_history_is_durable_without_a_successful_finish() {
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("history.sqlite");
    {
        // A copy that stops without recording an outcome, as when it panics,
        // saves what it has as it is dropped.
        let writer = recorder(&path);
        writer.event(
            "sample",
            json!({"bytes":100,"files":2,"disposition":"warmup_excluded"}),
        );
    }
    let db = open(&path).unwrap();
    let id = 1;
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
    writer.complete(true, json!({}));
    assert_eq!(std::fs::read(&path).unwrap(), fixture);
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
    old.complete(true, json!({}));
    let active = recorder(&path);
    let active = saved(&active);
    let current = recorder(&path);
    current.complete(true, json!({}));
    let (old, current) = (saved(&old), saved(&current));
    let db = open(&path).unwrap();
    prune(&db, 1, current).unwrap();
    assert!(command::read_run(&db, old).is_err());
    assert!(command::read_events(&db, old).unwrap().is_empty());
    assert!(command::read_run(&db, active).is_ok());
    assert!(command::read_run(&db, current).is_ok());
}

#[test]
fn retention_shrinks_a_history_far_over_budget_and_returns_its_space() {
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("history.sqlite");
    recorder(&path).complete(true, json!({}));
    let db = open(&path).unwrap();
    // About 2 MiB of finished runs, as a larger budget could have kept.
    db.execute_batch(
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<512)
         INSERT INTO runs(day,updated_day,build,status,summary)
         SELECT 0,0,'old','success',printf('%.4096c','x') FROM n;",
    )
    .unwrap();
    let current = recorder(&path);
    let current_id = saved(&current);
    let budget = 256 << 10;
    prune_within(&db, budget, current_id, Duration::from_secs(60)).unwrap();
    let pages: i64 = db
        .pragma_query_value(None, "page_count", |r| r.get(0))
        .unwrap();
    let free: i64 = db
        .pragma_query_value(None, "freelist_count", |r| r.get(0))
        .unwrap();
    let page_size: i64 = db
        .pragma_query_value(None, "page_size", |r| r.get(0))
        .unwrap();
    assert!(
        (pages - free) * page_size <= budget as i64,
        "{pages} {free}"
    );
    assert!(
        free * page_size <= budget as i64,
        "free space returned: {free}"
    );
    let (kept, oldest): (i64, i64) = db
        .query_row("SELECT count(*), min(id) FROM runs", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert!(kept > 1 && kept < 100, "{kept}");
    assert!(oldest > 1, "the oldest runs go first");
    assert!(command::read_run(&db, current_id).is_ok());
}

/// A history holding `runs` copies from today that never recorded an
/// outcome, about 4.5 KiB each, after one finished run. This is what copies
/// leave when their final save finds the history locked, or when they are
/// killed.
fn unfinished_history(path: &Path, runs: i64) -> Connection {
    recorder(path).complete(true, json!({}));
    let db = open(path).unwrap();
    db.execute(
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<?2)
         INSERT INTO runs(day,updated_day,build,context)
         SELECT ?1,?1,'unfinished',printf('%.400c','x') FROM n",
        params![day(), runs],
    )
    .unwrap();
    db.execute_batch(
        "INSERT INTO events
         SELECT id,0,0,printf('%.2048c','x') FROM runs WHERE status='incomplete'",
    )
    .unwrap();
    db
}

/// How many pages this connection has read from the history so far.
pub(super) fn pages_read(db: &Connection) -> i64 {
    let (mut current, mut highest) = (0, 0);
    // SAFETY: the handle belongs to this open connection, and both outputs
    // are valid for the call.
    let code = unsafe {
        rusqlite::ffi::sqlite3_db_status(
            db.handle(),
            rusqlite::ffi::SQLITE_DBSTATUS_CACHE_MISS,
            &mut current,
            &mut highest,
            0,
        )
    };
    assert_eq!(code, rusqlite::ffi::SQLITE_OK);
    i64::from(current)
}

fn used_bytes(db: &Connection) -> i64 {
    let pragma = |name| -> i64 { db.pragma_query_value(None, name, |r| r.get(0)).unwrap() };
    (pragma("page_count") - pragma("freelist_count")) * pragma("page_size")
}

fn file_bytes(db: &Connection) -> i64 {
    let pragma = |name| -> i64 { db.pragma_query_value(None, name, |r| r.get(0)).unwrap() };
    pragma("page_count") * pragma("page_size")
}

fn run_ids(db: &Connection) -> Vec<i64> {
    db.prepare("SELECT id FROM runs ORDER BY id")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

#[test]
fn a_prune_step_reads_a_bounded_part_of_a_history_it_cannot_shrink_by_age() {
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("history.sqlite");
    let runs = 6000;
    let db = unfinished_history(&path, runs);
    // Leave nothing that finished: every run is one a copy may be recording.
    db.execute("DELETE FROM runs WHERE status!='incomplete'", [])
        .unwrap();
    let table: i64 = db
        .query_row("SELECT count(*) FROM dbstat WHERE name='runs'", [], |r| {
            r.get(0)
        })
        .unwrap();
    let current = recorder(&path);
    let current_id = saved(&current);
    // A connection that has read nothing yet, as a copy's is for these pages.
    let db = open(&path).unwrap();
    let before = pages_read(&db);
    // No time allows exactly one step, which must still delete something.
    prune_within(&db, 1 << 20, current_id, Duration::ZERO).unwrap();
    let read = pages_read(&db) - before;
    let kept = run_ids(&db);
    assert_eq!(kept.len() as i64, runs, "one run deleted");
    assert_eq!(kept[0], 3, "the oldest run goes first");
    // The step reads its window of the oldest runs and the run it deletes,
    // not every run, however many the history holds.
    assert!(
        read <= 100 && table >= 5 * read,
        "{read} pages read of {table} holding runs"
    );
}

#[test]
fn a_finishing_copy_reads_little_of_a_history_full_of_unfinished_runs() {
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("history.sqlite");
    let runs = 6000;
    let observer = unfinished_history(&path, runs);
    let writer = Recorder::at(&path, Instant::now(), json!({}), 1 << 20);
    writer.context(&key("a"));
    writer.complete(true, json!({}));
    let mut state = writer.0.lock().unwrap();
    let read = pages_read(state.db());
    let deleted = runs + 2 - run_ids(&observer).len() as i64;
    assert!(deleted > 0, "every copy shrinks a history over its budget");
    assert_eq!(
        command::read_run(&observer, state.id.unwrap()).unwrap()["status"],
        "success"
    );
    // Opening, recording and choosing what to delete read a fixed number of
    // pages; deleting a run reads that run. Nothing reads the whole history.
    assert!(
        read <= 150 + 3 * deleted,
        "{read} pages read while deleting {deleted} runs"
    );
}

#[test]
fn unfinished_runs_go_oldest_first_once_nothing_else_can_and_the_newest_stay() {
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("history.sqlite");
    let db = unfinished_history(&path, 2000);
    let current = recorder(&path);
    let current_id = saved(&current);
    let budget = 2 << 20;
    assert!(used_bytes(&db) > 4 * budget);
    prune_within(&db, budget as u64, current_id, Duration::from_secs(60)).unwrap();
    assert!(used_bytes(&db) <= budget, "{}", used_bytes(&db));
    let kept = run_ids(&db);
    // More than the protected runs fit, and what is kept is the newest.
    assert!(kept.len() as i64 > ACTIVE_RUNS + 1, "{}", kept.len());
    assert_eq!(*kept.last().unwrap(), current_id);
    assert_eq!(
        kept.len() as i64,
        current_id - kept[0] + 1,
        "kept runs are the newest ones"
    );
    // However small the budget, a run this close behind the finishing copy
    // may still be recording and stays.
    prune_within(&db, 1, current_id, Duration::from_secs(60)).unwrap();
    assert_eq!(
        run_ids(&db),
        (current_id - ACTIVE_RUNS..=current_id).collect::<Vec<_>>()
    );
    // A later copy's step finds nothing it may delete, and reads no further.
    let db = open(&path).unwrap();
    let before = pages_read(&db);
    prune_within(&db, 1, current_id, Duration::from_secs(60)).unwrap();
    assert!(pages_read(&db) - before <= 100);
}

#[test]
fn an_unfinished_run_outlives_finished_ones_among_the_oldest() {
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("history.sqlite");
    // A long copy still recording, followed by far more finished runs than
    // separate it from the newest.
    let long = recorder(&path);
    let long_id = saved(&long);
    let db = open(&path).unwrap();
    db.execute_batch(
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<1000)
         INSERT INTO runs(day,updated_day,build,status,summary)
         SELECT 0,0,'old','success',printf('%.4096c','x') FROM n;",
    )
    .unwrap();
    let current = recorder(&path);
    let current_id = saved(&current);
    assert!(long_id < current_id - ACTIVE_RUNS);
    let budget = 1 << 20;
    prune_within(&db, budget as u64, current_id, Duration::from_secs(60)).unwrap();
    assert!(used_bytes(&db) <= budget);
    let kept = run_ids(&db);
    assert_eq!(kept[0], long_id, "the unfinished run stays");
    assert!(kept[1] > long_id + 500, "finished runs went: {}", kept[1]);
    long.event("sample", json!({"bytes":1}));
    long.complete(true, json!({}));
    assert_eq!(
        command::read_run(&db, long_id).unwrap()["status"],
        "success"
    );
}

#[test]
fn pruning_leaves_room_so_the_next_copies_only_check_the_size() {
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("history.sqlite");
    recorder(&path).complete(true, json!({}));
    let db = open(&path).unwrap();
    let budget: i64 = 1 << 20;
    // Finished runs up to just over the budget, as a steady stream leaves.
    while used_bytes(&db) <= budget {
        db.execute_batch(
            "INSERT INTO runs(day,updated_day,build,status,summary)
             VALUES (0,0,'old','success',printf('%.4096c','x'));",
        )
        .unwrap();
    }
    let full = run_ids(&db).len();
    let first = Recorder::at(&path, Instant::now(), json!({}), budget as u64);
    let first_id = saved(&first);
    prune_within(&db, budget as u64, first_id, Duration::from_secs(60)).unwrap();
    let used = used_bytes(&db);
    assert!(used <= budget - budget / PRUNE_SLACK, "{used}");
    assert!(
        used > budget - 2 * budget / PRUNE_SLACK,
        "only a little more than the excess goes: {used}"
    );
    let pruned = run_ids(&db).len();
    assert!(pruned < full);
    // The free pages stay for later runs, except those over the budget.
    let file = file_bytes(&db);
    assert!(file <= budget && file > used, "{file} {used}");
    first.complete(true, json!({}));
    for _ in 0..4 {
        Recorder::at(&path, Instant::now(), json!({}), budget as u64).complete(true, json!({}));
    }
    assert_eq!(run_ids(&db).len(), pruned + 4, "nothing more deleted");
    assert_eq!(file_bytes(&db), file, "new runs reuse the free pages");
}

#[test]
fn returning_free_pages_keeps_its_progress_when_the_deadline_cuts_it_short() {
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("history.sqlite");
    let db = unfinished_history(&path, 200);
    db.execute("DELETE FROM runs WHERE status='incomplete'", [])
        .unwrap();
    let before = file_bytes(&db);
    assert!(before - used_bytes(&db) > 64 * 4096, "many free pages");
    // What `prune_within` does when its deadline passes after one step:
    // the statement is dropped before it has returned every page.
    {
        let mut vacuum = db.prepare("PRAGMA incremental_vacuum(64)").unwrap();
        let mut rows = vacuum.raw_query();
        assert!(rows.next().unwrap().is_some());
    }
    // Another connection sees the smaller file, so the step was committed
    // and the copies which follow continue from it.
    let after = file_bytes(&open(&path).unwrap());
    assert!(after < before, "{after} {before}");
    assert!(after > used_bytes(&db), "only part was returned");
}

#[test]
fn a_run_deleted_while_its_copy_records_stops_recording() {
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("history.sqlite");
    let writer = recorder(&path);
    let id = saved(&writer);
    let other = open(&path).unwrap();
    // As another copy's pruning or `tuning-cache clear` does.
    other.execute("DELETE FROM runs WHERE id=?1", [id]).unwrap();
    writer.event("sample", json!({"bytes":1}));
    saved(&writer);
    {
        let state = writer.0.lock().unwrap();
        assert!(state.finished && state.pending.is_empty());
    }
    // Later events and the outcome are dropped without touching the history,
    // which another copy may have locked.
    other.execute_batch("BEGIN IMMEDIATE").unwrap();
    let before = pages_read(writer.0.lock().unwrap().db());
    writer.context(&key("a"));
    writer.event("sample", json!({"bytes":2}));
    saved(&writer);
    writer.complete(true, json!({}));
    {
        let mut state = writer.0.lock().unwrap();
        assert!(state.pending.is_empty() && state.pending_context.is_none());
        assert_eq!(pages_read(state.db()), before);
    }
    other.execute_batch("COMMIT").unwrap();
    drop(writer);
    assert!(command::read_run(&other, id).is_err());
    assert!(command::read_events(&other, id).unwrap().is_empty());
}

#[test]
fn lock_contention_keeps_samples_and_context_for_a_later_save() {
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("history.sqlite");
    let writer = recorder(&path);
    writer.context(&key("a"));
    let id = saved(&writer);
    let other = open(&path).unwrap();
    other.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut mixed = key("a");
    mixed.destination_filesystem = None;
    writer.context(&mixed);
    writer.event("sample", json!({"bytes":123}));
    {
        // A periodic save does not wait for the lock: it fails at once and
        // leaves the history alone for a while.
        let before = Instant::now();
        writer.0.lock().unwrap().next_write = before;
        writer.event("sample", json!({"bytes":456}));
        let state = writer.0.lock().unwrap();
        assert_eq!(state.pending.len(), 2);
        assert!(state.retry >= before + WRITE_RETRY);
    }
    other.execute_batch("COMMIT").unwrap();
    writer.complete(true, json!({}));
    assert!(writer.0.lock().unwrap().pending.is_empty());
    assert!(writer.0.lock().unwrap().pending_context.is_none());
    let run = command::read_run(&other, id).unwrap();
    assert_eq!(run["status"], "success");
    assert_eq!(run["context"]["destination_filesystem"], Value::Null);
    assert_eq!(command::read_events(&other, id).unwrap().len(), 4);
}

#[test]
fn a_final_save_that_finds_the_history_locked_writes_nothing() {
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("history.sqlite");
    let recorder = recorder(&path);
    let other = open(&path).unwrap();
    other.execute_batch("BEGIN IMMEDIATE").unwrap();
    recorder.context(&key("a"));
    recorder.event("sample", json!({"bytes":123}));
    let mut writer = recorder.0.lock().unwrap();
    let error = writer.finish(true, json!({})).unwrap_err();
    assert!(matches!(
        error.downcast_ref::<rusqlite::Error>(),
        Some(rusqlite::Error::SqliteFailure(error, _))
            if error.code == rusqlite::ErrorCode::DatabaseBusy
    ));
    assert!(!writer.pending.is_empty());
    assert!(writer.pending_context.is_some());
    other.execute_batch("COMMIT").unwrap();
    assert_eq!(run_count(&other), 0, "no run left without its outcome");

    // Nothing was half-saved: the same save succeeds once the lock is free.
    writer.finish(true, json!({"files":1})).unwrap();
    assert!(writer.pending.is_empty());
    assert!(writer.pending_context.is_none());
    let run = command::read_run(&other, writer.id.unwrap()).unwrap();
    assert_eq!(run["status"], "success");
    assert_eq!(run["context"]["destination_filesystem"], "a");
    assert!(command::read_events(&other, writer.id.unwrap())
        .unwrap()
        .iter()
        .any(|e| e["kind"] == "sample"));
}

#[test]
fn a_copy_that_cannot_save_its_run_at_its_end_leaves_no_run() {
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("history.sqlite");
    let writer = recorder(&path);
    writer.context(&key("a"));
    writer.event("sample", json!({"bytes":123}));
    let other = open(&path).unwrap();
    other.execute_batch("BEGIN IMMEDIATE").unwrap();
    writer.complete(true, json!({}));
    // Nor does it try again when it is dropped.
    let before = pages_read(writer.0.lock().unwrap().db());
    other.execute_batch("COMMIT").unwrap();
    writer.event("sample", json!({"bytes":456}));
    assert_eq!(pages_read(writer.0.lock().unwrap().db()), before);
    drop(writer);
    assert_eq!(run_count(&other), 0);
}

#[test]
fn a_failed_final_save_does_not_publish_partial_context_or_samples() {
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("history.sqlite");
    // A copy that ends before its first periodic save writes all or nothing.
    {
        let recorder = recorder(&path);
        let mut writer = recorder.0.lock().unwrap();
        writer.pending_context = Some(key("a"));
        writer.db().execute_batch("CREATE TRIGGER fail_event BEFORE INSERT ON events WHEN NEW.sequence=0 BEGIN SELECT RAISE(ABORT,'injected failure'); END;").unwrap();
        assert!(writer.finish(true, json!({})).is_err());
        assert_eq!(run_count(writer.db()), 0);
        assert!(writer.id.is_none() && !writer.pending.is_empty());
        writer
            .db()
            .execute_batch("DROP TRIGGER fail_event")
            .unwrap();
        writer.finished = true;
    }
    // A longer copy keeps what its earlier saves wrote, and no more.
    let recorder = recorder(&path);
    let id = saved(&recorder);
    let mut writer = recorder.0.lock().unwrap();
    writer.pending_context = Some(key("a"));
    writer
        .pending
        .push(json!({"sequence":1,"elapsed_us":1,"kind":"sample","data":{}}));
    writer.db().execute_batch("CREATE TRIGGER fail_completion BEFORE UPDATE OF status ON runs BEGIN SELECT RAISE(ABORT,'injected failure'); END;").unwrap();
    assert!(writer.finish(true, json!({})).is_err());
    let run = command::read_run(writer.db(), id).unwrap();
    assert_eq!(run["status"], "incomplete");
    assert_eq!(run["context"], json!({}));
    assert_eq!(command::read_events(writer.db(), id).unwrap().len(), 1);
    assert!(!writer.pending.is_empty());
    assert!(writer.pending_context.is_some());
}

#[test]
fn a_copy_writes_nothing_until_it_ends_and_then_writes_once() {
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("history.sqlite");
    measured_run(&path, &key("a"), &[(8, 100.0), (16, 200.0)]);
    let other = open(&path).unwrap();
    // Another copy holds the writer lock while this one starts and records:
    // none of that waits for it, or takes it.
    other.execute_batch("BEGIN IMMEDIATE").unwrap();
    let writer = recorder(&path);
    writer.context(&key("a"));
    writer.event("context", json!({"stage":"source_registered"}));
    // Its connection waits for no lock, so a starting count that it reads
    // was read without waiting for the writer.
    assert_eq!(
        writer
            .starting_count(&key("a"), false, 1, crate::tune::TransportProfile::Ssh)
            .unwrap()
            .workers,
        16
    );
    for bytes in 0..100 {
        writer.event("sample", json!({"bytes":bytes}));
    }
    other.execute_batch("COMMIT").unwrap();
    assert_eq!(run_ids(&other), [1], "the copy has no run before it ends");
    let writes = |db: &Connection| -> i64 {
        db.query_row("SELECT total_changes()", [], |r| r.get(0))
            .unwrap()
    };
    assert_eq!(writes(writer.0.lock().unwrap().db()), 0);
    writer.complete(true, json!({"files":1}));
    let run = command::read_run(&other, 2).unwrap();
    assert_eq!(run["status"], "success");
    assert_eq!(run["context"]["destination_filesystem"], "a");
    assert_eq!(run["summary"]["files"], 1);
    // The start event, the context event, the samples and the finish.
    assert_eq!(command::read_events(&other, 2).unwrap().len(), 103);
}

#[test]
fn a_copy_whose_history_opens_late_writes_nothing_as_it_starts() {
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("history.sqlite");
    // The copy's clock started well before its history opened, as when
    // choosing its authorization first connected to a server.
    let start = Instant::now()
        .checked_sub(Duration::from_secs(30))
        .expect("the machine has been up for half a minute");
    let writer = Recorder::at(&path, start, json!({}), DEFAULT_BUDGET);
    writer.context(&key("a"));
    writer.event("context", json!({"stage":"source_registered"}));
    {
        let mut state = writer.0.lock().unwrap();
        assert!(state.next_write > Instant::now());
        assert!(state.id.is_none() && state.pending.len() == 2);
        // Keep this test's own pace out of the rest.
        state.next_write = Instant::now() + Duration::from_secs(3600);
    }
    writer.complete(true, json!({}));
    let db = open(&path).unwrap();
    let events = command::read_events(&db, 1).unwrap();
    assert_eq!(events.len(), 3);
    assert!(events[0]["elapsed_us"].as_u64().unwrap() >= 30_000_000);
}

#[test]
fn a_save_that_found_the_history_locked_leaves_it_alone_for_a_while() {
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("history.sqlite");
    let writer = recorder(&path);
    let db = open(&path).unwrap();
    {
        // As after a save that found the lock taken, with a save now due.
        let mut state = writer.0.lock().unwrap();
        state.retry = Instant::now() + Duration::from_secs(3600);
        state.next_write = Instant::now();
    }
    for worker in 0..WRITE_EVENTS + 1 {
        writer.event("worker", json!({"worker":worker}));
    }
    // The lock is free, yet nothing tried it: neither the save that is due
    // nor the one that many unsaved events ask for.
    assert_eq!(run_count(&db), 0);
    writer.0.lock().unwrap().retry = Instant::now();
    writer.event("worker", json!({}));
    assert_eq!(
        command::read_events(&db, 1).unwrap().len(),
        WRITE_EVENTS + 3
    );
}

#[test]
fn a_long_copy_saves_its_timeline_while_it_runs() {
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("history.sqlite");
    let start = Instant::now();
    let writer = Recorder::at(&path, start, json!({}), DEFAULT_BUDGET);
    // The first save is due a second after the history opened. Keep this
    // test's own pace out of it from here on.
    {
        let mut state = writer.0.lock().unwrap();
        assert!(state.next_write >= start + FIRST_WRITE);
        assert!(state.next_write <= Instant::now() + FIRST_WRITE);
        state.next_write = start + Duration::from_secs(3600);
        // Let the history open before another connection races it.
        assert!(state.ready());
    }
    let db = open(&path).unwrap();
    writer.context(&key("a"));
    writer.event("sample", json!({"bytes":1}));
    assert_eq!(run_count(&db), 0, "nothing before the first save is due");
    // The copy's first event after that saves everything so far.
    let due = Instant::now();
    writer.0.lock().unwrap().next_write = due;
    writer.event("sample", json!({"bytes":2}));
    let run = command::read_run(&db, 1).unwrap();
    assert_eq!(run["status"], "incomplete");
    assert_eq!(run["context"]["destination_filesystem"], "a");
    assert_eq!(command::read_events(&db, 1).unwrap().len(), 3);
    // Later events wait for the next save.
    assert!(writer.0.lock().unwrap().next_write >= due + WRITE_INTERVAL);
    writer.0.lock().unwrap().next_write = due + Duration::from_secs(3600);
    writer.event("sample", json!({"bytes":3}));
    assert_eq!(command::read_events(&db, 1).unwrap().len(), 3);
    writer.0.lock().unwrap().next_write = Instant::now();
    writer.event("sample", json!({"bytes":4}));
    assert_eq!(command::read_events(&db, 1).unwrap().len(), 5);
    writer.complete(true, json!({}));
    assert_eq!(command::read_run(&db, 1).unwrap()["status"], "success");
    assert_eq!(command::read_events(&db, 1).unwrap().len(), 6);
    assert_eq!(run_count(&db), 1);
}

#[test]
fn many_unsaved_events_are_saved_whatever_the_copy_s_age() {
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("history.sqlite");
    let writer = recorder(&path);
    let db = open(&path).unwrap();
    // The start event is the first of them.
    for worker in 1..WRITE_EVENTS - 1 {
        writer.event("worker", json!({"worker":worker}));
    }
    assert_eq!(run_count(&db), 0);
    writer.event("worker", json!({"worker":WRITE_EVENTS}));
    assert_eq!(
        command::read_events(&db, 1).unwrap().len(),
        WRITE_EVENTS,
        "saved before any could be dropped"
    );
    assert_eq!(writer.0.lock().unwrap().lost, 0);
}

#[test]
fn a_finishing_copy_waits_for_the_history_no_longer_than_it_ran() {
    assert_eq!(finish_wait(Duration::ZERO), Duration::ZERO);
    assert_eq!(
        finish_wait(Duration::from_millis(8)),
        Duration::from_millis(8)
    );
    assert_eq!(finish_wait(Duration::from_secs(1)), FINISH_LOCK_WAIT);
    assert_eq!(finish_wait(Duration::from_secs(3600)), FINISH_LOCK_WAIT);
}

#[test]
fn taking_the_writer_lock_waits_for_it_no_longer_than_allowed() {
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("history.sqlite");
    let writer = recorder(&path);
    let mut state = writer.0.lock().unwrap();
    let other = open(&path).unwrap();
    other.execute_batch("BEGIN IMMEDIATE").unwrap();
    let busy = |result: Result<rusqlite::Transaction<'_>>| {
        matches!(
            result.unwrap_err().downcast_ref::<rusqlite::Error>(),
            Some(rusqlite::Error::SqliteFailure(error, _))
                if error.code == rusqlite::ErrorCode::DatabaseBusy
        )
    };
    assert!(busy(begin_within(state.db(), Duration::ZERO)));
    let started = Instant::now();
    let wait = Duration::from_millis(30);
    assert!(busy(begin_within(state.db(), wait)));
    assert!(started.elapsed() >= wait, "{:?}", started.elapsed());
    // It takes the lock as soon as the other connection lets go.
    std::thread::scope(|scope| {
        scope.spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            other.execute_batch("COMMIT").unwrap();
        });
        begin_within(state.db(), Duration::from_secs(60)).unwrap();
    });
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
    writer.complete(true, json!({}));
    let db = open(&path).unwrap();
    let events = command::read_events(&db, saved(&writer)).unwrap();
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
    assert!(writer
        .starting_count(&key("a"), true, 1, crate::tune::TransportProfile::Ssh)
        .is_none());
}

#[test]
fn opening_existing_history_needs_no_writer_lock() {
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("history.sqlite");
    let db = open(&path).unwrap();
    // A released history has only the original indexes. Keep another writer
    // active: opening it must not attempt a schema change over the old runs.
    db.execute_batch(
        "DROP INDEX IF EXISTS measured_filesystems;
        DROP INDEX IF EXISTS measured_routes;
        BEGIN IMMEDIATE;",
    )
    .unwrap();
    let opened = open(&path);
    db.execute_batch("ROLLBACK").unwrap();
    assert!(
        opened.is_ok(),
        "opening history needed a write lock: {opened:?}"
    );
}

/// While the history opens it holds no descriptor of its own on the file,
/// only SQLite's, even while it waits for another run's lock: a copy counts
/// its open descriptors as the history opens in the background
/// (`require_source_descriptor_capacity`). Linux only: it tells which file a
/// descriptor is on through `/proc/self/fd`, which macOS's `/dev/fd` does not.
#[cfg(target_os = "linux")]
#[test]
fn opening_the_history_holds_only_sqlite_descriptors_while_it_waits() {
    use std::os::unix::fs::MetadataExt;
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("history.sqlite");
    let holder = open(&path).unwrap();
    let file = std::fs::metadata(&path).unwrap();
    let on_file = || {
        std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .flatten()
            .filter(|entry| {
                std::fs::metadata(entry.path())
                    .is_ok_and(|m| (m.dev(), m.ino()) == (file.dev(), file.ino()))
            })
            .count()
    };
    // Another run holds the history, so the opening waits for it.
    holder
        .execute_batch("PRAGMA locking_mode=EXCLUSIVE; BEGIN EXCLUSIVE;")
        .unwrap();
    let before = on_file();
    std::thread::scope(|scope| {
        let opening = scope.spawn(|| open_waiting(&path, Duration::from_secs(30)));
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut most = 0;
        while most == 0 {
            assert!(Instant::now() < deadline, "the history never opened");
            std::thread::sleep(Duration::from_millis(1));
            most = on_file() - before;
        }
        let sampled = Instant::now();
        while sampled.elapsed() < Duration::from_millis(300) {
            most = most.max(on_file() - before);
            std::thread::sleep(Duration::from_millis(1));
        }
        // Closing the other run's connection lets the opening through.
        drop(holder);
        opening.join().unwrap().unwrap();
        assert_eq!(most, 1, "descriptors on the history while it opened");
    });
}

#[test]
fn concurrent_initialization_shares_one_identity_key() {
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("history.sqlite");
    let barrier = std::sync::Barrier::new(2);
    // A run waits only 100 ms for another's lock, then goes without history.
    // That budget is not what this test is about, and a loaded host can stall
    // the lock holder for longer: give both openings ample time to take their
    // turns, so that they always race on the new database and both succeed.
    let open_recorder = || {
        let details = json!({"policy_version":1});
        Recorder::at_waiting(
            &path,
            Instant::now(),
            details,
            DEFAULT_BUDGET,
            Duration::from_secs(30),
        )
    };
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..2)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    let writer = open_recorder();
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
            .query_row("SELECT count(*) FROM metadata", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
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
    let events = command::read_events(&open(&path).unwrap(), saved(&writer)).unwrap();
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
                same_as_ssh_target: false,
            },
            TcpCandidate {
                address: "example.invalid".into(),
                speed_mbps: 0,
                source: DataAddressSource::SshTarget,
                reachable: Some(false),
                selected: false,
                same_as_ssh_target: false,
            },
            TcpCandidate {
                address: "2001:db8::10".into(),
                speed_mbps: 0,
                source: DataAddressSource::RemoteInterface,
                reachable: None,
                selected: false,
                same_as_ssh_target: false,
            },
        ],
    };
    first.context(&key("a"));
    first.tcp_probe("destination", "user@example.invalid", &probe);
    first.complete(true, json!({}));
    let second = recorder(&path);
    second.tcp_probe("source", "user@example.invalid", &probe);
    saved(&second);
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
    assert_eq!(command::read_run(&db, 1).unwrap()["status"], "success");
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
    let events = command::read_events(&open(&path).unwrap(), saved(&writer)).unwrap();
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

/// Record a successful run with two observations at each (workers, rate).
pub(in crate::tune) fn measured_run(
    path: &Path,
    key: &ContextKey,
    points: &[(usize, f64)],
) -> Recorder {
    let writer = unfinished_run(path, key, points);
    writer.complete(true, json!({}));
    writer
}

fn unfinished_run(path: &Path, key: &ContextKey, points: &[(usize, f64)]) -> Recorder {
    let writer = recorder(path);
    writer.context(key);
    writer.event(
        "learning_context",
        json!({"consistent":true,"automatic":true}),
    );
    for &(workers, rate) in points {
        writer.event("transition", json!({}));
        for _ in 0..2 {
            writer.event(
                "observation",
                json!({"active":workers,"seconds":2.5,"rate":rate,"usable":true}),
            );
        }
    }
    writer
}

#[test]
fn exact_filesystem_starts_survive_other_destinations_and_unfinished_runs() {
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("history.sqlite");
    // Each run's other count is nearly as fast, so an exact match may refine
    // and starts from the fewer workers.
    measured_run(&path, &key("a"), &[(8, 200.0), (16, 195.0)]);
    measured_run(&path, &key("b"), &[(32, 200.0), (16, 195.0)]);
    let failed = unfinished_run(&path, &key("a"), &[(64, 200.0), (32, 100.0)]);
    failed.complete(false, json!({}));
    drop(unfinished_run(
        &path,
        &key("a"),
        &[(64, 200.0), (32, 100.0)],
    ));
    let next = recorder(&path);
    let exact = next
        .starting_count(&key("a"), false, 1, crate::tune::TransportProfile::Ssh)
        .unwrap();
    assert_eq!((exact.workers, exact.matched.as_str()), (8, "filesystems"));
    assert!(exact.refine);
    assert_eq!(
        next.starting_count(&key("b"), false, 1, crate::tune::TransportProfile::Ssh)
            .unwrap()
            .workers,
        16
    );
    // Another filesystem pair falls back to the route only when allowed,
    // and a route-level match never skips the startup doubling.
    assert!(next
        .starting_count(
            &key("unknown"),
            false,
            1,
            crate::tune::TransportProfile::Ssh
        )
        .is_none());
    let route = next
        .starting_count(&key("unknown"), true, 1, crate::tune::TransportProfile::Ssh)
        .unwrap();
    assert_eq!(route.matched, "route");
    assert!(!route.refine);
    let mut other_mode = key("a");
    other_mode.mode = "bandwidth_limited".into();
    assert!(next
        .starting_count(&other_mode, true, 1, crate::tune::TransportProfile::Ssh)
        .is_none());
}

fn starts_over_copies(ratio: impl Fn(usize, usize, usize) -> f64) -> Vec<usize> {
    use super::super::Policy;
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("history.sqlite");
    let context = key("a");
    let mut starts = Vec::new();
    for run in 0..6 {
        let hint =
            recorder(&path).starting_count(&context, false, 8, crate::tune::TransportProfile::Ssh);
        assert_eq!(hint.is_some(), run > 0);
        let start = hint.as_ref().map_or(8, |hint| hint.workers);
        starts.push(start);
        let mut policy = if hint.is_some_and(|h| h.refine) {
            Policy::refine(start, 1, 256)
        } else {
            Policy::new(start, 1, 256)
        };
        policy.observe(100.0);
        policy.activated();
        let larger = policy.active();
        let rate = 100.0 * ratio(run, start, larger);
        policy.observe(rate);
        // The live copy keeps the inconclusive increase.
        assert_eq!(policy.settled(), larger);
        let writer = measured_run(&path, &context, &[(start, 100.0), (larger, rate)]);
        let run = command::read_run(&open(&path).unwrap(), saved(&writer)).unwrap();
        assert_eq!(run["recommendation_eligible"], true);
    }
    starts
}

#[test]
fn repeated_inconclusive_copies_do_not_raise_the_starting_count() {
    assert_eq!(starts_over_copies(|_, _, _| 0.97), [8; 6]);
    assert_eq!(starts_over_copies(|_, _, _| 1.01), [8; 6]);
    assert_eq!(
        starts_over_copies(|_, start, larger| (larger as f64 / start as f64).powf(0.055)),
        [8; 6]
    );
    assert_eq!(
        starts_over_copies(|run, _, _| if run % 2 == 0 { 1.01 } else { 0.99 }),
        [8; 6]
    );
}

#[test]
fn repeated_clear_gains_keep_raising_the_starting_count() {
    for ratio in [1.08, 1.3] {
        assert_eq!(
            starts_over_copies(|_, _, _| ratio),
            [8, 16, 32, 64, 128, 256],
            "{ratio}"
        );
    }
}

#[test]
fn network_scoped_starts_separate_known_networks_and_preserve_unknown_fallback() {
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
    measured_run(&path, &key("a"), &[(64, 200.0), (32, 100.0)]);
    let home = recorder(&path);
    assert!(home
        .starting_count(
            &network_key(Some("home")),
            true,
            1,
            crate::tune::TransportProfile::Ssh
        )
        .is_none());
    measured_run(
        &path,
        &network_key(Some("home")),
        &[(8, 200.0), (16, 100.0)],
    );
    let office = recorder(&path);
    assert!(office
        .starting_count(
            &network_key(Some("office")),
            true,
            1,
            crate::tune::TransportProfile::Ssh
        )
        .is_none());
    measured_run(
        &path,
        &network_key(Some("office")),
        &[(32, 200.0), (64, 100.0)],
    );
    let next = recorder(&path);
    let start = |network| {
        next.starting_count(
            &network_key(network),
            true,
            1,
            crate::tune::TransportProfile::Ssh,
        )
        .unwrap()
        .workers
    };
    assert_eq!(start(Some("home")), 8);
    assert_eq!(start(Some("office")), 32);
    assert_eq!(start(None), 64);
}

#[test]
fn finish_learning_excludes_runs_after_transport_or_network_changes() {
    use crate::conn::Endpoint;
    for network_changed in [false, true] {
        let temp = crate::test_support::tempdir().unwrap();
        let path = temp.path().join("history.sqlite");
        let writer = recorder(&path);
        let src = Endpoint::local();
        let dst = super::super::tests::remote("host", true);
        let mut key = context_key(&writer, &src, &dst, None, None, "default".into());
        if network_changed {
            key.network = Some("earlier network".into());
        }
        writer.context(&key);
        for workers in [4, 8] {
            writer.event(
                "observation",
                json!({"active":workers,"seconds":2.5,"rate":100,"usable":true}),
            );
        }
        if !network_changed {
            let Endpoint::Remote(spec) = &dst else {
                unreachable!()
            };
            spec.tcp.lock().unwrap().as_mut().unwrap().failed = true;
        }
        writer.finish_learning(&key, &src, &dst, true);
        writer.complete(true, json!({}));
        let db = open(&path).unwrap();
        let events = command::read_events(&db, 1).unwrap();
        let context = events
            .iter()
            .find(|e| e["kind"] == "learning_context")
            .unwrap();
        assert_eq!(context["data"]["consistent"], false);
        let eligible: i64 = db
            .query_row("SELECT eligible FROM runs WHERE id=1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(eligible, 0);
    }
}

#[test]
fn routes_separate_direction_transport_and_tcp_fallback() {
    use crate::conn::Endpoint;
    let temp = crate::test_support::tempdir().unwrap();
    let writer = recorder(&temp.path().join("history.sqlite"));
    let route = |src: &Endpoint, dst: &Endpoint| {
        context_key(&writer, src, dst, None, None, "default".into()).route
    };
    let local = Endpoint::local();
    let ssh = super::super::tests::remote("host", false);
    let tcp = super::super::tests::remote("host", true);
    assert_ne!(route(&local, &ssh), route(&ssh, &local));
    assert_ne!(route(&local, &ssh), route(&local, &tcp));
    let initial = route(&local, &tcp);
    let Endpoint::Remote(spec) = &tcp else {
        unreachable!()
    };
    spec.tcp.lock().unwrap().as_mut().unwrap().failed = true;
    assert_ne!(route(&local, &tcp), initial);
}

#[test]
fn trace_clock_units_match_the_driver() {
    use super::super::TransportProfile;
    for elapsed in [false, true] {
        for (profile, expected_wait) in [
            (None, 30000),
            (Some(TransportProfile::Tcp), 60000),
            (Some(TransportProfile::Local), 60000),
            (Some(TransportProfile::Ssh), 120000),
        ] {
            let temp = crate::test_support::tempdir().unwrap();
            let path = temp.path().join("history.sqlite");
            let writer = recorder(&path);
            let mut policy = super::super::Policy::new(8, 1, 64);
            if let Some(profile) = profile {
                policy = policy.with_transport(profile);
            }
            if elapsed {
                policy.advance_time(Duration::ZERO, super::super::SAMPLE);
            }
            let trace = super::super::trace::Trace::new(
                Some(writer.clone()),
                &policy,
                super::super::SAMPLE,
            );
            trace.end(&policy, false);
            let events = command::read_events(&open(&path).unwrap(), saved(&writer)).unwrap();
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
                if elapsed {
                    json!(expected_wait)
                } else {
                    Value::Null
                }
            );
        }
    }
}

#[test]
fn driver_excludes_draining_writers_and_the_first_interval_after_drain() {
    use crate::tune::{Gate, Meter, Policy, State, WorkGuard};
    use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
    struct Progress {
        history: Recorder,
        sched: Arc<crate::sched::Sched>,
        start: Instant,
        excess: Mutex<Option<WorkGuard>>,
        drained: AtomicBool,
    }
    impl Meter for Progress {
        fn history(&self) -> Option<Recorder> {
            Some(self.history.clone())
        }
        fn files(&self) -> u64 {
            0
        }
        fn set_active(&self, _: usize) {}
        fn bytes(&self) -> u64 {
            let elapsed = self.start.elapsed().as_secs_f64();
            if elapsed >= 3.0 && !self.drained.swap(true, Relaxed) {
                self.excess.lock().unwrap().take();
            }
            if elapsed >= 6.5 {
                self.sched.abort();
            }
            (elapsed * 1_000_000.0) as u64
        }
    }
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("history.sqlite");
    let history = recorder(&path);
    let sched = Arc::new(crate::sched::Sched::new(4 << 20, 32 << 20));
    sched.push_file(crate::sched::tests::test_job(b"pending", 1 << 30));
    sched.scan_done();
    let gate = Gate::new(4);
    for id in 0..4 {
        gate.mark_ready(id);
    }
    let excess = gate.work(3);
    gate.set_active(2);
    let mut policy = Policy::new(2, 1, 4);
    policy.state = State::Explore {
        from: 4,
        base: 100_000.0,
        direction: crate::tune::Direction::Down,
    };
    let progress = Arc::new(Progress {
        history: history.clone(),
        sched: sched.clone(),
        start: Instant::now(),
        excess: Mutex::new(Some(excess)),
        drained: AtomicBool::new(false),
    });
    crate::tune::run(policy, gate, sched, progress, |_| {
        panic!("workers already ready")
    });
    history.complete(true, json!({}));
    let db = Connection::open(path).unwrap();
    let events: Vec<Value> = db
        .prepare("SELECT data FROM events ORDER BY sequence")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(|r| serde_json::from_str(&r.unwrap()).unwrap())
        .collect();
    let observations: Vec<_> = events
        .iter()
        .filter(|e| e["kind"] == "observation")
        .collect();
    let first_settled = observations
        .iter()
        .position(|e| e["data"]["settled"] == true)
        .unwrap();
    assert!(first_settled >= 2);
    assert!(observations[..=first_settled]
        .iter()
        .all(|e| e["data"]["usable"] == false));
    assert!(observations[first_settled + 1..]
        .iter()
        .any(|e| e["data"]["usable"] == true));
    let first_clean_id = observations[first_settled + 1]["data"]["observation"]
        .as_u64()
        .unwrap();
    let decisions: Vec<_> = events
        .iter()
        .filter(|e| e["kind"] == "sequential_evidence")
        .collect();
    assert!(
        !decisions.is_empty(),
        "clean observations must eventually permit a decision"
    );
    for decision in decisions {
        let data = &decision["data"];
        let end = data["ending_observation"].as_u64().unwrap();
        let count = data["score"]["intervals"].as_u64().unwrap();
        assert!(
            end + 1 - count >= first_clean_id,
            "decision used draining-writer evidence"
        );
    }
}

#[test]
fn rejected_counter_interval_does_not_discard_the_next_clean_interval() {
    use crate::tune::{Gate, Meter, Policy};
    struct Progress {
        history: Recorder,
        sched: Arc<crate::sched::Sched>,
        start: Instant,
    }
    impl Meter for Progress {
        fn history(&self) -> Option<Recorder> {
            Some(self.history.clone())
        }
        fn files(&self) -> u64 {
            0
        }
        fn set_active(&self, _: usize) {}
        fn bytes(&self) -> u64 {
            let elapsed = self.start.elapsed().as_secs_f64();
            if elapsed >= 5.5 {
                self.sched.abort();
            }
            // A failed whole-file operation retracts its provisional credit.
            (elapsed * 100_000.0) as u64 + if elapsed < 1.0 { 1_000_000 } else { 0 }
        }
    }
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("history.sqlite");
    let history = recorder(&path);
    let sched = Arc::new(crate::sched::Sched::new(4 << 20, 32 << 20));
    sched.push_file(crate::sched::tests::test_job(b"pending", 1 << 30));
    sched.scan_done();
    let gate = Gate::new(1);
    gate.mark_ready(0);
    let progress = Arc::new(Progress {
        history: history.clone(),
        sched: sched.clone(),
        start: Instant::now(),
    });
    crate::tune::run(Policy::new(1, 1, 1), gate, sched, progress, |_| {
        panic!("no new workers")
    });
    history.complete(true, json!({}));
    let db = Connection::open(path).unwrap();
    let statuses: Vec<String> = db.prepare("SELECT json_extract(data,'$.data.disposition') FROM events WHERE json_extract(data,'$.kind')='observation' ORDER BY sequence").unwrap()
        .query_map([], |r| r.get(0)).unwrap().map(Result::unwrap).collect();
    let regressed = statuses
        .iter()
        .position(|s| s == "counter_regressed")
        .unwrap();
    assert_eq!(
        statuses[regressed + 1],
        "measured",
        "clean interval must reach the window: {statuses:?}"
    );
}

#[test]
fn schema_v1_upgrade_keeps_old_events_without_backfilling_measurements() {
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("old.sqlite");
    let db = Connection::open(&path).unwrap();
    // Unchanged schema-v1 tables from #548. No measurement table existed.
    db.execute_batch(r#"CREATE TABLE metadata (key TEXT PRIMARY KEY, value BLOB NOT NULL);
        CREATE TABLE runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, day INTEGER NOT NULL,
            updated_day INTEGER NOT NULL, build TEXT NOT NULL, context TEXT NOT NULL DEFAULT '{}',
            route TEXT, source_fs TEXT, destination_fs TEXT, mode TEXT,
            status TEXT NOT NULL DEFAULT 'incomplete', eligible INTEGER NOT NULL DEFAULT 0,
            workers INTEGER, summary TEXT, lost INTEGER NOT NULL DEFAULT 0);
        CREATE INDEX by_filesystems ON runs(route,mode,source_fs,destination_fs,eligible,id DESC);
        CREATE INDEX by_route ON runs(route,mode,eligible,id DESC);
        CREATE TABLE events (
            run INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
            sequence INTEGER NOT NULL, elapsed_us INTEGER NOT NULL, data TEXT NOT NULL,
            PRIMARY KEY(run,sequence));
        PRAGMA user_version=1;
        INSERT INTO runs(day,updated_day,build,status,eligible,summary) VALUES(1,1,'old','success',2,'{}');
        INSERT INTO events VALUES(1,0,500000,'{"kind":"observation","data":{"active":8,"seconds":0.5,"rate":100.0,"usable":true}}');"#).unwrap();
    let old_event: String = db
        .query_row("SELECT data FROM events", [], |r| r.get(0))
        .unwrap();
    drop(db);
    let upgraded = open(&path).unwrap();
    assert_eq!(
        upgraded
            .pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
            .unwrap(),
        2
    );
    assert_eq!(
        upgraded
            .query_row::<i64, _, _>("SELECT count(*) FROM measurements", [], |r| r.get(0))
            .unwrap(),
        0
    );
    assert_eq!(
        upgraded
            .query_row::<String, _, _>("SELECT data FROM events", [], |r| r.get(0))
            .unwrap(),
        old_event
    );
    assert!(inference::starting_count(
        &upgraded,
        &key("a"),
        false,
        1,
        crate::tune::TransportProfile::Ssh,
    )
    .unwrap()
    .is_none());
}

#[test]
fn measurement_rows_retry_and_prune_with_their_events() {
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("history.sqlite");
    let writer = recorder(&path);
    let db = open(&path).unwrap();
    db.execute_batch("BEGIN IMMEDIATE").unwrap();
    writer.event(
        "observation",
        json!({"active":8,"seconds":0.5,"rate":100.0,"usable":true}),
    );
    assert!(writer.0.lock().unwrap().save().is_err());
    assert_eq!(
        db.query_row::<i64, _, _>("SELECT count(*) FROM measurements", [], |r| r.get(0))
            .unwrap(),
        0
    );
    db.execute_batch("COMMIT").unwrap();
    saved(&writer);
    saved(&writer);
    assert_eq!(
        db.query_row::<i64, _, _>("SELECT count(*) FROM measurements", [], |r| r.get(0))
            .unwrap(),
        1
    );
    assert_eq!(db.query_row::<i64,_,_>("SELECT count(*) FROM measurements m JOIN events e ON m.run=e.run AND m.sequence=e.sequence",[],|r| r.get(0)).unwrap(),1);
    writer.complete(true, json!({}));
    let current = recorder(&path);
    prune(&db, 1, saved(&current)).unwrap();
    assert_eq!(
        db.query_row::<i64, _, _>("SELECT count(*) FROM measurements", [], |r| r.get(0))
            .unwrap(),
        0
    );
}

#[test]
fn a_copy_starts_without_waiting_for_its_history_to_open() {
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("history.sqlite");
    // A history without its identity key yet: the first copy to open it
    // writes the key, and so waits for another copy's write to end.
    let other = open(&path).unwrap();
    other.execute_batch("BEGIN IMMEDIATE").unwrap();
    // Opening would wait up to a minute for the lock; the copy goes on.
    let writer = Recorder::at_waiting(
        &path,
        Instant::now(),
        json!({"policy_version":1}),
        DEFAULT_BUDGET,
        Duration::from_secs(60),
    );
    // A periodic save would wait for the open, and so for `other`.
    writer.0.lock().unwrap().next_write = Instant::now() + Duration::from_secs(3600);
    writer.event("planned", json!({"files":2}));
    other.execute_batch("COMMIT").unwrap();
    writer.context(&key("a"));
    writer.complete(true, json!({}));
    let kinds: Vec<String> = other
        .prepare("SELECT json_extract(data,'$.kind') FROM events ORDER BY sequence")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(kinds, ["start", "planned", "finish"]);
    let (status, destination): (String, String) = other
        .query_row("SELECT status,destination_fs FROM runs", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!((status.as_str(), destination.as_str()), ("success", "a"));
}

#[test]
fn finishing_an_unmeasured_single_file_copy_never_waits_for_the_open() {
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("history.sqlite");
    let db = open(&path).unwrap();
    db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let writer = Recorder::at_waiting(
        &path,
        Instant::now(),
        json!({}),
        DEFAULT_BUDGET,
        Duration::from_secs(60),
    );
    writer.event("planned", json!({"files":1}));
    writer.complete(true, json!({"files":1}));
    // The identity key cannot be created until the lock is released. The
    // recorder completed without joining that thread or creating a run.
    assert!(matches!(writer.0.lock().unwrap().store, Store::Opening(_)));
    db.execute_batch("COMMIT").unwrap();
    assert_eq!(run_count(&db), 0);
    writer.0.lock().unwrap().store.ready().unwrap();
}

#[test]
fn a_history_that_cannot_open_records_nothing() {
    let temp = crate::test_support::tempdir().unwrap();
    // Its directory cannot be created under a file.
    std::fs::write(temp.path().join("file"), b"").unwrap();
    let path = temp.path().join("file/history.sqlite");
    let writer = Recorder::at(&path, Instant::now(), json!({}), DEFAULT_BUDGET);
    writer.context(&key("a"));
    assert_eq!(
        writer.token("endpoint", "x"),
        writer.token("endpoint", "x"),
        "a copy's keys still compare"
    );
    assert!(writer
        .starting_count(&key("a"), true, 1, crate::tune::TransportProfile::Ssh)
        .is_none());
    writer.event("planned", json!({}));
    writer.complete(true, json!({}));
    let state = writer.0.lock().unwrap();
    assert!(state.finished && state.pending.is_empty());
    assert!(!path.exists());
}

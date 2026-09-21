use super::*;

#[cfg(debug_assertions)]
#[test]
fn self_copy_guard_does_not_reject_a_destination_outside_the_moved_source() {
    let t = Tmp::new();
    write(&t.path("src/original"), b"original");
    let ready = t.path("source-ready");
    let continuation = t.path("continue");
    let source = format!("{}/", t.s("src"));
    let destination = format!("{}/", t.s("src/out"));

    let mut child = compat_command()
        .args([
            "-a",
            "--performance-tuning",
            "workers=1",
            &source,
            &destination,
            "--no-progress",
        ])
        .env("SYQ_TEST_SOURCE_ROOTS_REGISTERED_FILE", &ready)
        .env("SYQ_TEST_SOURCE_ROOTS_CONTINUE_FILE", &continuation)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .start()
        .unwrap();

    wait_for_confinement_marker(&mut child, &ready, "source roots");

    fs::rename(t.path("src"), t.path("selected-and-moved")).unwrap();
    fs::create_dir(t.path("src")).unwrap();

    release_confinement_barrier(&continuation);
    let output = child.wait_with_output().unwrap();
    assert_output_ok(&output);
    assert_eq!(read(&t.path("src/out/original")), b"original");
}

// The expected tuner trajectory depends on measured loopback throughput and
// is calibrated for Linux runners.
#[cfg(all(debug_assertions, target_os = "linux"))]
#[test]
fn live_warming_retirement_and_post_sample_recovery_stay_consistent() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    t.expose_remote_syq();
    let data: Vec<u8> = (0..2 * 1024 * 1024)
        .map(|offset| (offset % 251) as u8)
        .collect();
    fs::create_dir_all(t.path("src")).unwrap();
    for index in 0..10 {
        write(&t.path(&format!("src/file-{index}")), &data);
    }
    let remote = format!("fake:{}", t.s("dst"));
    let marker = t.path("drop-after-samples");
    let cache = t.path("tuning.json");
    write(
        &cache,
        serde_json::to_string_pretty(&serde_json::json!({
            "paths": { "local>fake|ssh": 2 }
        }))
        .unwrap()
        .as_bytes(),
    );

    let out = compat_command()
        .arg("-e")
        .arg(&rsh)
        .args([
            "--syq-no-tcp",
            "-a",
            "--syq-no-bootstrap",
            "--block-size=64K",
            "--resource-limits=bandwidth=4M",
            "--stats",
            &t.s("src/"),
            &remote,
            "--no-progress",
        ])
        .env("FAKE_REMOTE_HOME", t.path("remote-home"))
        .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
        .env("FAKE_RSH_LOG", t.path("rsh.log"))
        .env("XDG_CONFIG_HOME", t.path("config"))
        .env("SYQ_TUNING_CACHE", &cache)
        .env("SYQ_DEBUG", "1")
        .env("SYQ_TEST_TUNE_SAMPLE_MS", "50")
        .env("SYQ_TEST_DROP_AFTER_REQUEST", "write")
        .env("SYQ_TEST_DROP_AFTER_N_REQUESTS", "32")
        .env("SYQ_TEST_DROP_MARKER", &marker)
        .run()
        .unwrap();

    assert_output_ok(&out);
    assert!(marker.exists());
    for index in 0..10 {
        assert_eq!(read(&t.path(&format!("dst/file-{index}"))), data);
    }
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("connection dropped; reopening"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    // The legacy count is a weak starting guess: discover with doubling, then
    // retire the excess workers as the measured bandwidth plateau is refined.
    assert!(
        stderr.contains("2 -> 4 workers (candidate ready"),
        "{stderr}"
    );
    let preparation = stderr
        .find("preparing 4 connections ahead of probe")
        .expect("prepare the upward candidate while still measuring two workers");
    let decision = stderr
        .find("candidate 2 -> 4 workers")
        .expect("the later measurement should select four workers");
    assert!(preparation < decision, "{stderr}");
    assert!(stderr.contains("4 -> 3 workers"), "{stderr}");
    assert!(stderr.contains("3 -> 2 workers"), "{stderr}");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("connections: auto:"),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn dir_into_missing_dest_creates_basename() {
    let t = Tmp::new();
    make_tree(&t.path("src"));
    run_ok(&["-a", &t.s("src"), &t.s("dst")]);
    assert!(t.path("dst/src").is_dir(), "expected dst/src to be created");
    assert_same_tree(&t.path("src"), &t.path("dst/src"));
}

#[test]
fn trailing_slash_copies_contents() {
    let t = Tmp::new();
    make_tree(&t.path("src"));
    run_ok(&["-a", &t.s("src/"), &t.s("dst")]);
    assert!(t.path("dst/hello.txt").is_file());
    assert!(!t.path("dst/src").exists());
    assert_same_tree(&t.path("src"), &t.path("dst"));
}

#[test]
fn single_file_to_new_name() {
    let t = Tmp::new();
    write(&t.path("src/f.txt"), b"data");
    set_mtime(&t.path("src/f.txt"), 1_600_000_000);
    let output = run_ok(&["-a", "--stats", &t.s("src/f.txt"), &t.s("out.txt")]);
    assert!(
        output.contains("connections: auto: settled at 1 (path 1, peak 1)"),
        "{output}"
    );
    assert_eq!(read(&t.path("out.txt")), b"data");
    assert_same_tree(&t.path("src/f.txt"), &t.path("out.txt"));
}

#[test]
fn multiple_sources_into_new_dest() {
    let t = Tmp::new();
    write(&t.path("src/f.txt"), b"data");
    write(&t.path("src/d/x"), b"x");
    write(&t.path("src/d/y/z"), b"z");
    run_ok(&["-a", &t.s("src/f.txt"), &t.s("src/d"), &t.s("dst")]);
    assert!(t.path("dst").is_dir());
    assert_eq!(read(&t.path("dst/f.txt")), b"data");
    assert_same_tree(&t.path("src/d"), &t.path("dst/d"));
}

#[test]
fn multiple_sources_require_dir_dest() {
    let t = Tmp::new();
    write(&t.path("src/f.txt"), b"data");
    write(&t.path("src/g.txt"), b"data");
    write(&t.path("dst"), b"a file");
    let out = syq(&["-a", &t.s("src/f.txt"), &t.s("src/g.txt"), &t.s("dst")]);
    assert!(!out.status.success());
    assert_eq!(read(&t.path("dst")), b"a file");
}

#[test]
fn rerun_transfers_nothing() {
    let t = Tmp::new();
    make_tree(&t.path("src"));
    let out = run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    assert!(transferred(&out) > 0);
    let out = run_ok(&["-av", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(
        transferred(&out),
        0,
        "second run should transfer nothing: {out}"
    );
    assert_same_tree(&t.path("src"), &t.path("dst"));
}

#[test]
fn unreadable_source_reports_error_but_continues() {
    if unsafe { libc::geteuid() } == 0 {
        return; // root can read anything
    }
    let t = Tmp::new();
    write(&t.path("src/ok.txt"), b"fine");
    write(&t.path("src/secret.txt"), b"nope");
    write(&t.path("src/also_ok.txt"), b"fine too");
    fs::set_permissions(t.path("src/secret.txt"), fs::Permissions::from_mode(0o000)).unwrap();
    let out = syq(&["-a", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(
        out.status.code(),
        Some(23),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("secret.txt"), "{err}");
    assert_eq!(read(&t.path("dst/ok.txt")), b"fine");
    assert_eq!(read(&t.path("dst/also_ok.txt")), b"fine too");
    assert!(!t.path("dst/secret.txt").exists());
}

#[test]
fn file_over_nonempty_destination_directory_reports_error_without_panicking() {
    let t = Tmp::new();
    write(&t.path("src/foo"), b"source");
    write(&t.path("dest/foo/keep"), b"keep");

    let out = syq(&[
        "--performance-tuning",
        "workers=1",
        &t.s("src/foo"),
        &t.s("dest"),
    ]);

    assert_eq!(out.status.code(), Some(23));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("cannot replace directory"), "{err}");
    assert!(!err.contains("panicked"), "{err}");
    assert_eq!(read(&t.path("dest/foo/keep")), b"keep");
}

#[test]
fn file_onto_itself_is_allowed_noop() {
    let t = Tmp::new();
    write(&t.path("f"), b"hello");
    run_ok(&["-a", "--inplace", &t.s("f"), &t.s("f")]);
    assert_eq!(read(&t.path("f")), b"hello");
}

#[test]
fn untransferred_entries_yield_to_another_source() {
    let t = Tmp::new();
    std::os::unix::fs::symlink(
        "nowhere",
        t.path("a/x")
            .parent()
            .map(|p| {
                fs::create_dir_all(p).unwrap();
                t.path("a/x")
            })
            .unwrap(),
    )
    .unwrap();
    write(&t.path("b/x"), b"hi");
    // No -l: a/x is skipped and must not block b/x (either order).
    run_ok(&["-r", &t.s("a/"), &t.s("b/"), &t.s("dst")]);
    assert_eq!(read(&t.path("dst/x")), b"hi");
    run_ok(&["-r", &t.s("b/"), &t.s("a/"), &t.s("dst2")]);
    assert_eq!(read(&t.path("dst2/x")), b"hi");
    // But a real conflict is still one.
    write(&t.path("c/x"), b"other");
    let out = syq(&["-r", &t.s("b/"), &t.s("c/"), &t.s("dst3")]);
    assert_eq!(out.status.code(), Some(1));
}

// Ordinary copies keep no historical completion state: the current destination
// determines what a later invocation repairs.
#[test]
fn ordinary_rerun_reconciles_destination() {
    let t = Tmp::new();
    write(&t.path("src/f.bin"), b"hello world");
    set_mtime(&t.path("src/f.bin"), 1_600_000_000);
    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    fs::remove_file(t.path("dst/f.bin")).unwrap();
    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(read(&t.path("dst/f.bin")), b"hello world");
}

#[test]
fn ordinary_copy_needs_no_writable_history_directory() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"data");
    // A regular file cannot contain an application state directory. Ordinary
    // copies must ignore both locations because they keep no history.
    write(&t.path("not-a-directory"), b"occupied");
    let out = compat_command()
        .args(["-a", "--no-progress", &t.s("src/"), &t.s("dst/")])
        .env("XDG_STATE_HOME", t.s("not-a-directory"))
        .env("HOME", t.s("not-a-directory"))
        .run()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(read(&t.path("dst/f")), b"data");
}

#[cfg(all(debug_assertions, target_os = "linux"))]
#[test]
fn copy_local_unsupported_filesystems_retain_ranges() {
    let t = Tmp::new();
    write(&t.path("src/file"), &prng(5 << 20, 460));
    write(&t.path("src/other"), &prng(5 << 20, 461));
    let out = compat_command()
        .args(["-a", "--no-progress", &t.s("src/"), &t.s("dst/")])
        .env("SYQ_DEBUG", "1")
        .env("SYQ_TEST_COPY_LOCAL_EXDEV", "1")
        .env("SYQ_TEST_COPY_LOCAL_FS", "unsupported")
        .run()
        .unwrap();
    assert_output_ok(&out);
    assert_same_tree(&t.path("src"), &t.path("dst"));
    let observed = tuning_observed(&out);
    assert_eq!(observed["local_whole_files"], 0);
    assert!(observed["range_requests"].as_u64().unwrap() > 0);
    assert!(partial_files(&t.0).is_empty());
}

#[cfg(all(debug_assertions, target_os = "linux"))]
#[test]
fn copy_local_disk_source_shrink_is_not_published() {
    let t = Tmp::new();
    write(&t.path("src/small"), b"parallel file work");
    write(&t.path("src/file"), &prng(8 << 20, 457));
    let ready = t.path("written");
    let resume = t.path("continue");
    let mut child = compat_command()
        .args(["-a", "--no-progress", &t.s("src/"), &t.s("dst/")])
        .env("SYQ_TEST_COPY_LOCAL_EXDEV", "1")
        .env("SYQ_TEST_COPY_LOCAL_FS", "local")
        .env("SYQ_TEST_COPY_LOCAL_WRITTEN_FILE", &ready)
        .env("SYQ_TEST_COPY_LOCAL_CONTINUE_FILE", &resume)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .start()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !ready.exists() && std::time::Instant::now() < deadline {
        assert!(child.try_wait().unwrap().is_none());
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(ready.exists(), "copy did not reach the first-write barrier");
    File::create(t.path("src/file")).unwrap();
    write(&resume, b"continue");
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(23), "{out:?}");
    assert!(stderr_of(&out).contains("source shortened while copying"));
    assert!(!t.path("dst/file").exists());
    assert_eq!(partial_files(&t.path("dst")).len(), 1);
}

#[test]
fn copy_onto_itself_among_sources_is_order_independent() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"a");
    write(&t.path("dst/a"), b"a");
    // Naming the destination file as a source, together with a different file
    // for the same path, is a conflict in either order: dst/a would be lost.
    write(&t.path("src/a"), b"changed");
    for args in [
        [&t.s("src/"), &t.s("dst/a"), &t.s("dst/")],
        [&t.s("dst/a"), &t.s("src/"), &t.s("dst/")],
    ] {
        let out = syq(&["-r", args[0], args[1], args[2]]);
        assert_eq!(out.status.code(), Some(1), "{}", stderr_of(&out));
        assert_eq!(read(&t.path("dst/a")), b"a", "untouched");
    }
    // The destination file alone, given twice over two sources, is a no-op.
    fs::create_dir_all(t.path("h")).unwrap();
    fs::hard_link(t.path("dst/a"), t.path("h/a")).unwrap();
    run_ok(&["-r", &t.s("dst/a"), &t.s("h/"), &t.s("dst/")]);
    assert_eq!(read(&t.path("dst/a")), b"a");
    // Two different files onto one destination is still a collision.
    write(&t.path("src2/a"), b"different");
    let out = syq(&["-r", &t.s("src/"), &t.s("src2/"), &t.s("dst3/")]);
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn cross_source_collision_is_detected_before_any_change() {
    let t = Tmp::new();
    fs::create_dir_all(t.path("a")).unwrap();
    std::os::unix::fs::symlink("nowhere", t.path("a/x")).unwrap();
    write(&t.path("a/other"), b"o");
    write(&t.path("b/x/inside"), b"i");
    write(&t.path("dst/x"), b"precious file");
    let out = syq(&["-a", &t.s("a/"), &t.s("b/"), &t.s("dst")]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr_of(&out));
    assert!(stderr_of(&out).contains("refusing to clobber"));
    assert_eq!(
        read(&t.path("dst/x")),
        b"precious file",
        "nothing was written"
    );
    assert!(
        !t.path("dst/other").exists(),
        "nothing from either source was applied"
    );
}

#[test]
fn destination_walk_errors_disable_deletion() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"a");
    write(&t.path("dst/gone"), b"an ordinary extra");
    write(&t.path("dst/dark/inside"), b"unknown contents");
    fs::set_permissions(t.path("dst/dark"), fs::Permissions::from_mode(0o000)).unwrap();
    let src_arg = t.s("src/");
    let dst_arg = t.s("dst");
    for flags in [vec!["-rt", "-n"], vec!["-rt"]] {
        let mut args = flags.clone();
        args.extend(["--delete", &src_arg, &dst_arg]);
        let out = syq(&args);
        assert_eq!(
            out.status.code(),
            Some(23),
            "{flags:?}: {}",
            stderr_of(&out)
        );
        assert!(
            stderr_of(&out).contains("destination walk reported errors; skipping deletions"),
            "{flags:?}: {}",
            stderr_of(&out)
        );
    }
    fs::set_permissions(t.path("dst/dark"), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(t.path("dst/gone").exists(), "nothing may be deleted");
    assert!(t.path("dst/dark/inside").exists());
}

#[test]
fn absent_user_config_environment_keeps_ordinary_commands_nonpersistent() {
    let t = Tmp::new();
    write(&t.path("src"), b"no home required");
    let output = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["cp", "--src"])
        .arg(t.path("src"))
        .args(["--as"])
        .arg(t.path("dst"))
        .arg("-q")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_RUNTIME_DIR")
        .env_remove("HOME")
        .run()
        .unwrap();
    assert_output_ok(&output);
    assert_eq!(read(&t.path("dst")), b"no home required");
}

#[cfg(debug_assertions)]
#[test]
fn one_worker_hint_prepares_spare_before_slow_connection_is_ready() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    t.expose_remote_syq();
    // Hold worker zero until another worker records a completed connection.
    // Without the early spare this reaches the barrier's bounded timeout;
    // scheduler delays cannot make the first connection race ahead.
    let worker_events = t.path("worker-events");
    let data: Vec<u8> = (0..4 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    write(&t.path("src/one"), &data);
    write(&t.path("src/two"), &data);
    let cache = t.path("tuning.json");
    write(&cache, br#"{"paths":{"local>fake|ssh":1}}"#);
    let remote = format!("fake:{}", t.s("dst"));
    let out = compat_command()
        .arg("-e")
        .arg(&rsh)
        .args([
            "--syq-no-tcp",
            "-a",
            "--syq-no-bootstrap",
            "--block-size=64K",
            "--resource-limits=bandwidth=4M",
            "--no-progress",
            &t.s("src/"),
            &remote,
        ])
        .env("FAKE_REMOTE_HOME", t.path("remote-home"))
        .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
        .env("FAKE_RSH_LOG", t.path("rsh.log"))
        .env("XDG_CONFIG_HOME", t.path("config"))
        .env("SYQ_TUNING_CACHE", &cache)
        .env("SYQ_DEBUG", "1")
        .env("SYQ_TEST_TUNE_SAMPLE_MS", "50")
        .env(
            "SYQ_TEST_WORKER_CONNECT_READY_FILE",
            t.path("worker-zero-waiting"),
        )
        .env("SYQ_TEST_WORKER_CONNECT_CONTINUE_FILE", &worker_events)
        .env("SYQ_TEST_WORKER_EVENTS", &worker_events)
        .run()
        .unwrap();
    assert_output_ok(&out);
    let events = fs::read_to_string(&worker_events).unwrap();
    assert_eq!(events.lines().next(), Some("connected 1 0"), "{events}");
    assert_eq!(read(&t.path("dst/one")), data);
    assert_eq!(read(&t.path("dst/two")), data);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let prepare = stderr
        .find("preparing 2 connections ahead of probe")
        .unwrap_or_else(|| panic!("missing startup spare: {stderr}"));
    let first_ready = stderr
        .find("worker 0 connected")
        .unwrap_or_else(|| panic!("missing first connection: {stderr}"));
    assert!(prepare < first_ready, "{stderr}");
}

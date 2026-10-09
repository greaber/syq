use super::*;

#[test]
fn error_if_different_leaves_contents_and_metadata_alone() {
    let t = Tmp::new();
    write(&t.path("src"), b"source");
    write(&t.path("dst"), b"target");
    set_mtime(&t.path("src"), 123);
    set_mtime(&t.path("dst"), 456);
    fs::set_permissions(t.path("src"), fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o640)).unwrap();
    for extra in ["--hash", "--dry-run"] {
        let output = native_syq(&[
            "cp",
            &t.s("src"),
            "--as",
            &t.s("dst"),
            "--copy-metadata=mtime,permissions",
            "--if-exists=error-if-different",
            extra,
        ]);
        assert!(!output.status.success(), "{output:?}");
        assert_eq!(read(&t.path("dst")), b"target");
        let meta = fs::metadata(t.path("dst")).unwrap();
        assert_eq!(meta.mtime(), 456);
        assert_eq!(meta.mode() & 0o777, 0o640);
    }
}

#[test]
fn error_keep_and_update_are_distinct_policies() {
    let t = Tmp::new();
    write(&t.path("src"), b"same");
    write(&t.path("dst"), b"same");
    let error = native_syq(&["cp", &t.s("src"), "--as", &t.s("dst"), "--if-exists=error"]);
    assert!(!error.status.success());
    write(&t.path("src"), b"changed source");
    run_native_ok(&[
        "cp",
        &t.s("src"),
        "--as",
        &t.s("dst"),
        "--if-exists=keep",
        "--copy-metadata=mtime",
    ]);
    assert_eq!(read(&t.path("dst")), b"same");
    run_native_ok(&["cp", &t.s("src"), "--as", &t.s("dst"), "--if-exists=update"]);
    assert_eq!(read(&t.path("dst")), b"changed source");
}

#[test]
fn update_if_older_keeps_newer_destinations_and_compares_ties() {
    let t = Tmp::new();
    write(&t.path("src"), b"new bytes");
    write(&t.path("dst"), b"old bytes");
    set_mtime(&t.path("src"), 123);
    for time in [124, 125] {
        set_mtime(&t.path("dst"), time);
        run_native_ok(&[
            "cp",
            &t.s("src"),
            "--as",
            &t.s("dst"),
            "--if-exists=update-if-older",
            "--hash",
        ]);
        assert_eq!(read(&t.path("dst")), b"old bytes");
    }
    set_mtime(&t.path("dst"), 123);
    run_native_ok(&[
        "cp",
        &t.s("src"),
        "--as",
        &t.s("dst"),
        "--if-exists=update-if-older",
        "--hash",
    ]);
    assert_eq!(read(&t.path("dst")), b"new bytes");
    // Different sizes do not need hashing to establish a difference on a tie.
    write(&t.path("dst"), b"short");
    set_mtime(&t.path("dst"), 123);
    run_native_ok(&[
        "cp",
        &t.s("src"),
        "--as",
        &t.s("dst"),
        "--if-exists=update-if-older",
    ]);
    assert_eq!(read(&t.path("dst")), b"new bytes");
    assert_eq!(fs::metadata(t.path("dst")).unwrap().mtime(), 123);
}

#[test]
fn existing_directories_are_containers_even_for_error_policy() {
    let t = Tmp::new();
    write(&t.path("src/nested/file"), b"new");
    fs::create_dir_all(t.path("dst/nested")).unwrap();
    run_native_ok(&[
        "cp",
        "--srcs-in",
        &t.s("src"),
        "--into",
        &t.s("dst"),
        "--if-exists=error",
    ]);
    assert_eq!(read(&t.path("dst/nested/file")), b"new");
    let repeated = native_syq(&[
        "cp",
        "--srcs-in",
        &t.s("src"),
        "--into",
        &t.s("dst"),
        "--if-exists=error",
    ]);
    assert!(!repeated.status.success());
    assert_eq!(read(&t.path("dst/nested/file")), b"new");
}

#[test]
fn matching_symlink_is_accepted_and_different_target_is_rejected() {
    let t = Tmp::new();
    std::os::unix::fs::symlink("first", t.path("src")).unwrap();
    std::os::unix::fs::symlink("first", t.path("dst")).unwrap();
    run_native_ok(&[
        "cp",
        "--if-exists=error-if-different",
        &t.s("src"),
        "--as",
        &t.s("dst"),
    ]);
    fs::remove_file(t.path("src")).unwrap();
    std::os::unix::fs::symlink("second", t.path("src")).unwrap();
    let output = native_syq(&[
        "cp",
        "--if-exists=error-if-different",
        &t.s("src"),
        "--as",
        &t.s("dst"),
    ]);
    assert!(!output.status.success());
    assert_eq!(fs::read_link(t.path("dst")).unwrap(), Path::new("first"));
}

#[test]
fn update_if_older_applies_to_symlink_targets() {
    let t = Tmp::new();
    std::os::unix::fs::symlink("source", t.path("src")).unwrap();
    std::os::unix::fs::symlink("destination", t.path("dst")).unwrap();
    set_mtime(&t.path("src"), 123);
    for time in [124, 123, 122] {
        set_mtime(&t.path("dst"), time);
        run_native_ok(&[
            "cp",
            &t.s("src"),
            "--as",
            &t.s("dst"),
            "--if-exists=update-if-older",
        ]);
        assert_eq!(
            fs::read_link(t.path("dst")).unwrap(),
            Path::new(if time <= 123 { "source" } else { "destination" })
        );
    }
}

#[test]
fn hardlink_followers_reject_different_contents_in_preview_and_copy() {
    for (preview, inplace) in [(false, false), (true, false), (false, true), (true, true)] {
        let t = Tmp::new();
        write(&t.path("src/a"), b"source");
        fs::hard_link(t.path("src/a"), t.path("src/b")).unwrap();
        write(&t.path("dst/a"), b"source");
        write(&t.path("dst/b"), b"target");
        let src = t.s("src");
        let dst = t.s("dst");
        let mut args = vec![
            "cp",
            "--srcs-in",
            &src,
            "--into",
            &dst,
            "--hash",
            "--copy-metadata=hardlinks",
            "--if-exists=error-if-different",
        ];
        if preview {
            args.push("--dry-run");
        }
        if inplace {
            args.push("--inplace");
        }
        let output = native_syq(&args);
        assert!(!output.status.success(), "{output:?}");
        assert!(
            stderr_of(&output).contains("destination contents differ"),
            "{output:?}"
        );
        assert_eq!(read(&t.path("dst/a")), b"source");
        assert_eq!(read(&t.path("dst/b")), b"target");
    }
}

#[test]
fn new_placement_stays_strict_when_updates_are_allowed() {
    for placement in ["--as-new", "--into-new"] {
        let t = Tmp::new();
        write(&t.path("src"), b"replacement");
        let protected = if placement == "--as-new" {
            "dst"
        } else {
            "dst/src"
        };
        write(&t.path(protected), b"original");
        let output = native_syq(&[
            "cp",
            &t.s("src"),
            placement,
            &t.s("dst"),
            "--if-exists=update",
        ]);
        assert!(!output.status.success(), "{output:?}");
        assert_eq!(read(&t.path(protected)), b"original");
    }
}

#[test]
fn previous_partials_remain_reusable_without_an_option() {
    let t = Tmp::new();
    let contents = vec![b'a'; 5 << 20];
    write(&t.path("src"), &contents);
    let partial = t.path(".out.syq-tmp.abcdefghijklmnop");
    write(&partial, &contents[..3 << 20]);
    run_native_ok(&[
        "cp",
        &t.s("src"),
        "--as",
        &t.s("out"),
        "--hash",
        "--results",
        &t.s("results.jsonl"),
        "--performance-tuning=copy-path=ranges,request-size=1M",
        "--performance-tuning=comparison-block-size=1M",
    ]);
    assert_eq!(read(&t.path("out")), contents);
    let data = fs::read_to_string(t.path("results.jsonl")).unwrap();
    let result: serde_json::Value = serde_json::from_str(data.lines().last().unwrap()).unwrap();
    assert_eq!(result["bytes_unchanged"], 3 << 20, "{result}");
}

#[test]
fn default_updates_selected_files_and_prunes_independently() {
    for extra in [
        vec![],
        vec!["--prune"],
        vec!["--copy-if", "src.size > 0B"],
        vec!["--inplace"],
    ] {
        let t = Tmp::new();
        write(&t.path("src/file"), b"replacement");
        write(&t.path("dst/file"), b"old");
        write(&t.path("dst/extra"), b"extra");
        set_mtime(&t.path("src/file"), 123);
        let src = t.s("src");
        let dst = t.s("dst");
        let mut args = vec!["cp", "--srcs-in", &src, "--into", &dst];
        args.extend_from_slice(&extra);
        run_native_ok(&args);
        assert_eq!(read(&t.path("dst/file")), b"replacement");
        assert_eq!(fs::metadata(t.path("dst/file")).unwrap().mtime(), 123);
        assert_eq!(t.path("dst/extra").exists(), !extra.contains(&"--prune"));
    }
}

#[test]
fn prune_does_not_require_permission_to_replace_source_matches() {
    let t = Tmp::new();
    write(&t.path("src/new"), b"new");
    write(&t.path("dst/extra"), b"extra");
    run_native_ok(&[
        "cp",
        "--srcs-in",
        &t.s("src"),
        "--into",
        &t.s("dst"),
        "--if-exists=error",
        "--prune",
    ]);
    assert_eq!(read(&t.path("dst/new")), b"new");
    assert!(!t.path("dst/extra").exists());
}

/// In place, the name is written as it is opened, so `--only-existing` opens
/// only the file the scan found; an `--as-new` file must be new, and the copy
/// refuses a name that exists.
#[test]
fn inplace_files_open_their_names_as_the_existing_file_policy_requires() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"new a");
    write(&t.path("src/b"), b"new b");
    write(&t.path("dst/a"), b"old");
    let inode = fs::metadata(t.path("dst/a")).unwrap().ino();
    run_native_ok(&[
        "cp",
        "--inplace",
        "--only-existing",
        "--srcs-in",
        &t.s("src"),
        "--into",
        &t.s("dst"),
    ]);
    assert_eq!(read(&t.path("dst/a")), b"new a");
    assert_eq!(fs::metadata(t.path("dst/a")).unwrap().ino(), inode);
    assert!(!t.path("dst/b").exists());

    run_native_ok(&[
        "cp",
        "--inplace",
        &t.s("src/b"),
        "--as-new",
        &t.s("dst/new"),
    ]);
    assert_eq!(read(&t.path("dst/new")), b"new b");
    let refused = native_syq(&["cp", "--inplace", &t.s("src/b"), "--as-new", &t.s("dst/a")]);
    assert!(!refused.status.success(), "{refused:?}");
    assert_eq!(read(&t.path("dst/a")), b"new a");
}

/// With `--inplace`, a file that must be new is staged: nothing is at its
/// name until it is published, and nothing would be in place to update.
#[cfg(debug_assertions)]
#[test]
fn a_file_that_must_be_new_is_staged_under_inplace() {
    let t = Tmp::new();
    write(&t.path("src/file"), b"new contents");
    fs::create_dir_all(t.path("dst")).unwrap();
    let ready = t.path("ready");
    let continuation = t.path("continue");
    let mut child = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "cp",
            "-q",
            "--inplace",
            "--performance-tuning",
            "copy-path=ranges",
        ])
        .arg(t.path("src/file"))
        .arg("--as-new")
        .arg(t.path("dst/new"))
        .env("SYQ_TEST_SOURCE_RECHECK_READY_FILE", &ready)
        .env("SYQ_TEST_SOURCE_RECHECK_CONTINUE_FILE", &continuation)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    wait_for_confinement_marker(&mut child, &ready, "source recheck before publication");
    assert!(!t.path("dst/new").exists());
    release_confinement_barrier(&continuation);
    let output = child.wait_with_output().unwrap();
    assert_output_ok(&output);
    assert_eq!(read(&t.path("dst/new")), b"new contents");
}

/// An `--as-new --inplace` file whose worker connection is lost, right after
/// its preparation or after its first write, is finished through a new
/// receiver process: the file must be new, so it is staged, and the new
/// process resumes it.
#[test]
fn an_as_new_inplace_file_is_finished_by_another_receiver_process() {
    for request in ["prepare", "write"] {
        let t = Tmp::new();
        let rsh = fake_rsh(&t);
        fs::create_dir(t.path("remote-home")).unwrap();
        let data = prng(4 << 20, 61);
        write(&t.path("src/file"), &data);
        let output = Command::new(env!("CARGO_BIN_EXE_syq"))
            .args(["cp", "--rsh"])
            .arg(&rsh)
            .args(["--syq-path", env!("CARGO_BIN_EXE_syq")])
            .args([
                "--no-tcp",
                "--no-progress",
                "--inplace",
                "--performance-tuning",
                "workers=1,copy-path=ranges,request-size=1M",
            ])
            .arg(t.path("src/file"))
            .args(["--to", "fake", "--as-new"])
            .arg(t.path("dst"))
            .env("FAKE_REMOTE_HOME", t.path("remote-home"))
            .env("FAKE_RSH_LOG", t.path("rsh.log"))
            .env("XDG_CONFIG_HOME", t.path("config"))
            .env("XDG_CACHE_HOME", t.path("cache"))
            .env("SYQ_TEST_DROP_AFTER_REQUEST", request)
            .env("SYQ_TEST_DROP_MARKER", t.path("dropped"))
            .run()
            .unwrap();
        assert!(
            t.path("dropped").exists(),
            "{request}: no connection was lost"
        );
        assert_output_ok(&output);
        assert!(read(&t.path("dst")) == data, "{request}");
        // The control session, the first worker and its replacement.
        let sessions = fs::read_to_string(t.path("rsh.log"))
            .unwrap()
            .lines()
            .count();
        assert_eq!(sessions, 3, "{request}");
    }
}

/// Under `--if-exists=error` or `error-if-different`, a new `--inplace` file
/// is staged and published without replacing anything: a worker connection
/// lost right after the file's preparation is retried through a new
/// receiver process, and the copy completes.
#[test]
fn a_protected_new_inplace_file_survives_a_lost_worker_connection() {
    for policy in ["error", "error-if-different"] {
        let t = Tmp::new();
        let rsh = fake_rsh(&t);
        fs::create_dir(t.path("remote-home")).unwrap();
        let data = prng(4 << 20, 62);
        write(&t.path("src/file"), &data);
        fs::create_dir(t.path("dst")).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_syq"))
            .args(["cp", "--rsh"])
            .arg(&rsh)
            .args(["--syq-path", env!("CARGO_BIN_EXE_syq")])
            .args([
                "--no-tcp",
                "--no-progress",
                "--inplace",
                &format!("--if-exists={policy}"),
                "--performance-tuning",
                "workers=1,copy-path=ranges,request-size=1M",
                "--srcs-in",
            ])
            .arg(t.path("src"))
            .args(["--to", "fake", "--into"])
            .arg(t.path("dst"))
            .env("FAKE_REMOTE_HOME", t.path("remote-home"))
            .env("FAKE_RSH_LOG", t.path("rsh.log"))
            .env("XDG_CONFIG_HOME", t.path("config"))
            .env("XDG_CACHE_HOME", t.path("cache"))
            .env("SYQ_TEST_DROP_AFTER_REQUEST", "prepare")
            .env("SYQ_TEST_DROP_MARKER", t.path("dropped"))
            .run()
            .unwrap();
        assert!(
            t.path("dropped").exists(),
            "{policy}: no connection was lost"
        );
        assert_output_ok(&output);
        assert!(read(&t.path("dst/file")) == data, "{policy}");
    }
}

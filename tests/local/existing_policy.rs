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

/// A hard link is made under the conditions its name would be published
/// under as a file: under the error policies, a name that appears after the
/// scan is refused rather than replaced, while the default policy replaces
/// it, as it replaces files.
#[cfg(debug_assertions)]
#[test]
fn hard_links_meet_the_existing_file_policy_of_their_names() {
    for policy in [
        Some("--if-exists=error"),
        Some("--if-exists=error-if-different"),
        None,
    ] {
        let t = Tmp::new();
        write(&t.path("src/a"), b"source");
        fs::hard_link(t.path("src/a"), t.path("src/b")).unwrap();
        fs::create_dir_all(t.path("dst")).unwrap();
        let ready = t.path("ready");
        let continuation = t.path("continue");
        let (src, dst) = (t.s("src"), t.s("dst"));
        let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
        command.args([
            "cp",
            "-q",
            "--srcs-in",
            &src,
            "--into",
            &dst,
            "--copy-metadata=hardlinks",
        ]);
        command.args(policy);
        let mut child = command
            .env("SYQ_TEST_FINALIZATION_READY_FILE", &ready)
            .env("SYQ_TEST_FINALIZATION_CONTINUE_FILE", &continuation)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        wait_for_confinement_marker(&mut child, &ready, "copy finalization");
        // The name the link would take appears after the scan.
        let (linked, appeared) = if t.path("dst/a").exists() {
            ("a", "b")
        } else {
            ("b", "a")
        };
        write(&t.path(&format!("dst/{appeared}")), b"appeared");
        release_confinement_barrier(&continuation);
        let output = child.wait_with_output().unwrap();
        let linked = fs::metadata(t.path(&format!("dst/{linked}"))).unwrap();
        let appeared_metadata = fs::metadata(t.path(&format!("dst/{appeared}"))).unwrap();
        if policy.is_some() {
            assert!(!output.status.success(), "{policy:?}: {output:?}");
            assert_eq!(read(&t.path(&format!("dst/{appeared}"))), b"appeared");
            assert_ne!(linked.ino(), appeared_metadata.ino());
        } else {
            assert!(output.status.success(), "{output:?}");
            assert_eq!(linked.ino(), appeared_metadata.ino());
        }
    }
}

use super::*;

#[cfg(debug_assertions)]
#[test]
fn self_copy_guard_rejects_a_destination_inside_the_moved_source() {
    let t = Tmp::new();
    write(&t.path("src/original"), b"original");
    let ready = t.path("source-ready");
    let continuation = t.path("continue");
    let source = format!("{}/", t.s("src"));
    let destination = format!("{}/", t.s("selected-and-moved/out"));

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
    assert!(!output.status.success(), "unexpected success: {output:?}");
    assert!(
        stderr_of(&output).contains("maps inside source"),
        "{}",
        stderr_of(&output)
    );
    assert!(!t.path("selected-and-moved/out").exists());
}

#[test]
fn native_copy_enforces_placement_preconditions_before_mutation() {
    let t = Tmp::new();
    write(&t.path("src"), b"source");
    write(&t.path("occupied/keep"), b"keep");

    for args in [
        vec!["cp", &t.s("src"), "--into-new", &t.s("occupied")],
        vec![
            "cp",
            &t.s("src"),
            "--into-existing",
            &t.s("missing-container"),
        ],
        vec!["cp", &t.s("src"), "--as-new", &t.s("occupied/keep")],
        vec!["cp", &t.s("src"), "--as-existing", &t.s("missing-exact")],
    ] {
        let out = native_syq(&args);
        assert!(!out.status.success(), "unexpected success for {args:?}");
    }
    assert_eq!(read(&t.path("occupied/keep")), b"keep");
    assert!(!t.path("missing-container").exists());
    assert!(!t.path("missing-exact").exists());

    write(&t.path("existing-exact"), b"old");
    let before = fs::metadata(t.path("existing-exact")).unwrap();
    run_native_ok(&["cp", &t.s("src"), "--as-existing", &t.s("existing-exact")]);
    let after = fs::metadata(t.path("existing-exact")).unwrap();
    assert_eq!(read(&t.path("existing-exact")), b"source");
    assert_ne!((after.dev(), after.ino()), (before.dev(), before.ino()));

    let missing_source_target = t.s("missing-source-target");
    let missing_source = native_syq(&["cp", &t.s("absent"), "--into-new", &missing_source_target]);
    assert!(!missing_source.status.success());
    assert!(!Path::new(&missing_source_target).exists());

    let contents_target = t.s("bad-contents-target");
    let not_a_directory = native_syq(&[
        "cp",
        "--srcs-in",
        &t.s("src"),
        "--into-new",
        &contents_target,
    ]);
    assert!(!not_a_directory.status.success());
    assert!(!Path::new(&contents_target).exists());
}

#[test]
fn native_copy_requires_sources_before_the_destination() {
    let t = Tmp::new();
    write(&t.path("source"), b"data");

    for args in [
        vec!["cp", "--into", &t.s("bare-target"), &t.s("source")],
        vec![
            "cp",
            "--into",
            &t.s("selector-target"),
            "--src",
            &t.s("source"),
        ],
        vec![
            "cp",
            "--into",
            &t.s("mapping-target"),
            "--mapping",
            "missing.ndjson",
        ],
    ] {
        let output = native_syq(&args);
        assert!(!output.status.success(), "unexpected success for {args:?}");
        assert!(
            stderr_of(&output).contains("must appear before destination arguments"),
            "{}",
            stderr_of(&output)
        );
    }

    assert!(!t.path("bare-target").exists());
    assert!(!t.path("selector-target").exists());
    assert!(!t.path("mapping-target").exists());

    run_native_ok(&[
        "cp",
        &t.s("source"),
        "--into",
        &t.s("valid-target"),
        "--dry-run",
    ]);
    assert!(!t.path("valid-target").exists());
}

#[test]
fn native_copy_accepts_copy_only_operational_controls() {
    let t = Tmp::new();
    write(&t.path("src/file"), b"payload");

    let output = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "cp",
            "--src-non-dir",
            &t.s("src/file"),
            "--as-new",
            &t.s("copied"),
            "--resource-limits",
            "bandwidth=1G",
            "--no-compress",
            "--stats",
            "--no-progress",
        ])
        .run()
        .unwrap();
    assert_output_ok(&output);
    assert_eq!(read(&t.path("copied")), b"payload");
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("scanned entries:"),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );

    let invalid = native_syq(&[
        "cp",
        &t.s("src/file"),
        "--as-new",
        &t.s("invalid"),
        "--resource-limits",
        "bandwidth=fast",
    ]);
    assert_eq!(invalid.status.code(), Some(2));
    assert!(stderr_of(&invalid).contains("bad bandwidth"));
    assert!(!t.path("invalid").exists());
}

#[test]
fn native_comparison_blocks_reuse_only_verified_matching_bytes() {
    let t = Tmp::new();
    let block = 64 * 1024;
    let original = vec![17; 8 * block + 7];
    let mut edited = original.clone();
    for index in [1, 3, 4, 7] {
        edited[index * block] = 91;
    }
    write(&t.path("src"), &edited);
    write(&t.path("dst"), &original);
    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "cp",
            "--hash",
            "--stats",
            "--performance-tuning=comparison-block-size=64K,request-size=4M,copy-path=ranges",
            &t.s("src"),
            "--as",
            &t.s("dst"),
        ])
        .arg("--no-progress")
        .run()
        .unwrap();
    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), edited);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("bytes transferred: 262,144"), "{stdout}");
    assert!(stdout.contains("bytes unchanged: 262,151"), "{stdout}");
    assert!(partial_files(&t.0).is_empty());
}

#[test]
fn top_level_rsync_syntax_is_rejected_without_mutation() {
    let t = Tmp::new();
    write(&t.path("src"), b"data");
    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["-a", &t.s("src"), &t.s("dst")])
        .run()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unrecognized command or option"),
        "{stderr}"
    );
    assert!(stderr.contains("syq --help"), "{stderr}");
    assert!(!t.path("dst").exists());
}

#[test]
fn rsync_surface_rejects_top_level_lifecycle_options() {
    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["rsync", "--self-update"])
        .run()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr_of(&out).contains("top-level syq options"));
}

#[test]
fn duplicate_destination_rejected() {
    let t = Tmp::new();
    write(&t.path("a/same"), b"A");
    write(&t.path("b/same"), b"B");
    fs::create_dir_all(t.path("dest")).unwrap();
    let out = syq(&["-a", &t.s("a/same"), &t.s("b/same"), &t.s("dest/")]);
    assert!(
        !out.status.success(),
        "two sources named 'same' must be rejected"
    );
    assert!(!t.path("dest/same").exists());
}

#[test]
fn exactly_repeated_sources_are_deduplicated_without_changing_placement() {
    let t = Tmp::new();
    write(&t.path("tree/name1"), b"data");
    std::os::unix::fs::symlink("name1", t.path("tree/name2")).unwrap();
    let tree = t.s("tree/");
    let so = run_ok(&["-avv", &tree, &tree, &tree, &t.s("tree-dest/")]);
    assert_eq!(transferred(&so), 1, "{so}");
    assert_eq!(read(&t.path("tree-dest/name1")), b"data");
    assert_eq!(
        fs::read_link(t.path("tree-dest/name2")).unwrap(),
        std::path::Path::new("name1")
    );

    // Deduplicating the work must not turn an originally multi-source command
    // into single-source placement: repeated files still land inside a
    // directory destination, including when that destination is missing.
    write(&t.path("one/file"), b"one");
    let file = t.s("one/file");
    run_ok(&["-a", &file, &file, &t.s("file-dest")]);
    assert!(t.path("file-dest").is_dir());
    assert_eq!(read(&t.path("file-dest/file")), b"one");
}

#[test]
fn dir_vs_file_destination_collision_rejected() {
    let t = Tmp::new();
    write(&t.path("A/x"), b"aaa"); // A/x is a file
    write(&t.path("B/x/y"), b"yyy"); // B/x is a directory
    fs::create_dir_all(t.path("dest")).unwrap();
    let out = syq(&[
        "-a",
        &format!("{}/", t.s("A")),
        &format!("{}/", t.s("B")),
        &format!("{}/", t.s("dest")),
    ]);
    assert!(
        !out.status.success(),
        "conflicting file-vs-dir destination must be rejected"
    );
}

#[test]
fn rejects_copying_directory_into_itself() {
    let t = Tmp::new();
    write(&t.path("src/file"), b"hi");
    let out = syq(&[
        "-a",
        &format!("{}/", t.s("src")),
        &format!("{}/", t.s("src/dst")),
    ]);
    assert!(!out.status.success(), "dest inside source must be rejected");
    // src must be untouched (no dst subtree created)
    assert!(!t.path("src/dst").exists());
}

#[test]
fn native_cp_matches_rsync_rlt() {
    let t = Tmp::new();
    write(&t.path("src/sub/file"), b"contents");
    set_mtime(&t.path("src/sub/file"), 1_600_000_003);
    std::os::unix::fs::symlink("sub/file", t.path("src/link")).unwrap();

    run_ok(&["-rlt", &t.s("src/"), &t.s("rsync/")]);
    run_native_ok(&["cp", "--srcs-in", &t.s("src"), "--into", &t.s("native")]);

    assert_eq!(listing(&t.path("native")), listing(&t.path("rsync")));
    assert_eq!(read(&t.path("native/sub/file")), b"contents");
    assert_eq!(
        fs::metadata(t.path("native/sub/file")).unwrap().mtime(),
        fs::metadata(t.path("rsync/sub/file")).unwrap().mtime()
    );
    assert_eq!(
        fs::read_link(t.path("native/link")).unwrap(),
        fs::read_link(t.path("rsync/link")).unwrap()
    );
}

#[test]
fn native_copy_supports_all_six_placements() {
    let t = Tmp::new();
    for source in [
        "into",
        "into-new",
        "into-existing",
        "as",
        "as-new",
        "as-existing",
    ] {
        write(&t.path(&format!("sources/{source}")), source.as_bytes());
    }
    fs::create_dir_all(t.path("targets/into-existing")).unwrap();
    write(&t.path("targets/as-existing"), b"old");

    for (source, placement, target) in [
        ("into", "--into", "targets/into"),
        ("into-new", "--into-new", "targets/into-new"),
        ("into-existing", "--into-existing", "targets/into-existing"),
        ("as", "--as", "targets/as"),
        ("as-new", "--as-new", "targets/as-new"),
        ("as-existing", "--as-existing", "targets/as-existing"),
    ] {
        run_native_ok(&[
            "cp",
            "--src",
            &t.s(&format!("sources/{source}")),
            placement,
            &t.s(target),
        ]);
    }

    for (path, expected) in [
        ("targets/into/into", b"into".as_slice()),
        ("targets/into-new/into-new", b"into-new".as_slice()),
        (
            "targets/into-existing/into-existing",
            b"into-existing".as_slice(),
        ),
        ("targets/as", b"as".as_slice()),
        ("targets/as-new", b"as-new".as_slice()),
        ("targets/as-existing", b"as-existing".as_slice()),
    ] {
        assert_eq!(read(&t.path(path)), expected, "{path}");
    }
}

#[test]
fn unknown_root_option_reports_standalone_options_and_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_syq"))
        .arg("--self-updat")
        .run()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let error = stderr_of(&output);
    assert!(
        error.contains("unrecognized command or option \"--self-updat\""),
        "{error}"
    );
    assert!(error.contains("--self-update"), "{error}");
    assert!(error.contains("syq --help"), "{error}");
    assert!(!error.contains("rsync-shaped"), "{error}");
}

#[test]
fn native_rejects_positional_destinations_implicit_verbs_and_compat_flags() {
    let positional = native_syq(&["cp", "foo", "bar", "dst"]);
    assert!(!positional.status.success());
    assert!(
        String::from_utf8_lossy(&positional.stderr).contains("requires one of --into"),
        "{}",
        String::from_utf8_lossy(&positional.stderr)
    );

    let implicit = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["foo", "bar", "dst"])
        .run()
        .unwrap();
    assert_eq!(implicit.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&implicit.stderr).contains("unrecognized command or option"));

    let removed = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["cp-prune", "source", "--into", "dest"])
        .run()
        .unwrap();
    assert_eq!(removed.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&removed.stderr).contains("unrecognized command or option"));

    for args in [
        ["cp", "-a", "source", "--into", "dest"].as_slice(),
        ["cp", "--delete", "source", "--into", "dest"].as_slice(),
        ["cp", "-B", "64K", "source", "--into", "dest"].as_slice(),
        ["cp", "--block-size", "64K", "source", "--into", "dest"].as_slice(),
        ["rm", "--syq-no-tcp", "source", "", ""].as_slice(),
        ["rm", "--bwlimit", "1M", "source", ""].as_slice(),
        ["rm", "--no-compress", "source", "", ""].as_slice(),
        ["rm", "--hash", "source", "", ""].as_slice(),
        ["rm", "--stats", "source", "", ""].as_slice(),
    ] {
        let args: Vec<_> = args.iter().copied().filter(|arg| !arg.is_empty()).collect();
        let out = native_syq(&args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("unexpected argument"),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let max_delete_without_prune =
        native_syq(&["cp", "--max-delete", "0", "source", "--into", "dest"]);
    assert_eq!(max_delete_without_prune.status.code(), Some(2));
    assert!(stderr_of(&max_delete_without_prune).contains("--prune"));
}

#[cfg(target_os = "linux")]
#[test]
fn rsync_control_input_accepts_an_inherited_procfs_pipe() {
    use std::os::fd::{AsRawFd, FromRawFd};

    let t = Tmp::new();
    write(&t.path("src/keep"), b"keep");
    write(&t.path("src/drop"), b"drop");
    let mut descriptors = [0; 2];
    assert_eq!(unsafe { libc::pipe(descriptors.as_mut_ptr()) }, 0);
    let reader = unsafe { File::from_raw_fd(descriptors[0]) };
    let mut writer = unsafe { File::from_raw_fd(descriptors[1]) };
    writer.write_all(b"drop\n").unwrap();
    drop(writer);
    let rules = format!("/proc/self/fd/{}", reader.as_raw_fd());

    let output = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["rsync", "-a", "--syq-ignore-from", &rules])
        .arg(t.s("src/"))
        .arg(t.path("dst"))
        .arg("--no-progress")
        .run()
        .unwrap();
    assert_output_ok(&output);
    assert_eq!(listing(&t.path("dst")), ["keep"]);
}

#[test]
fn rsync_rejects_invalid_comparison_blocks_before_reading_inputs() {
    let t = Tmp::new();
    let out = syq(&[
        "-B",
        "32K",
        "--files-from",
        &t.s("missing-manifest"),
        &t.s("src/"),
        &t.s("dst/"),
    ]);
    let error = stderr_of(&out);
    assert_eq!(out.status.code(), Some(2), "{error}");
    assert!(!error.contains("missing-manifest"), "{error}");
    assert!(!t.path("dst").exists());
}

// Unsupported rsync flags get a helpful, specific error (not clap's generic
// "unexpected argument"), and the filter family points at --syq-ignore.
#[test]
fn unsupported_rsync_flags_explain_themselves() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"x");

    let out = syq(&[
        "-a",
        "--exclude",
        "node_modules",
        &t.s("src/"),
        &t.s("dst/"),
    ]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("--syq-ignore"),
        "should point to --syq-ignore: {err}"
    );
    assert!(err.contains("gitignore"), "should mention gitignore: {err}");

    let out = syq(&["-a", "-i", &t.s("src/"), &t.s("itemized-dst/")]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("itemize-changes"),
        "should explain rsync -i: {err}"
    );
    assert!(
        err.contains("--syq-verify-only"),
        "should name syq's nearest comparison operation: {err}"
    );
    assert!(!t.path("itemized-dst").exists());

    let out = syq(&["-a", "--delete-during", &t.s("src/"), &t.s("dst/")]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("after the transfer"));

    // Bundled short flags from a pasted `rsync -aHz` are caught too (the
    // unsupported letter is found inside the cluster).
    let out = syq(&["-aHz", &t.s("src/"), &t.s("dst/")]);
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("hard links"),
        "bundled -H should be explained: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Every rsync mode that would traverse a descendant source or destination
    // symlink is classified explicitly. In particular, --insecure-links is an
    // operator-path/race-safety opt-out, not an alias for any of these modes.
    for (flag, expected) in [
        ("-aL", "source descendant-link traversal"),
        ("-ak", "source descendant-link traversal"),
        ("--copy-unsafe-links", "source descendant-link traversal"),
        ("-aK", "existing destination directory symlinks"),
        ("--keep-dirlinks", "existing destination directory symlinks"),
    ] {
        let out = syq(&[flag, "--insecure-links", &t.s("src/"), &t.s("link-dst/")]);
        assert!(!out.status.success(), "{flag} unexpectedly succeeded");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains(expected), "{flag}: {err}");
        assert!(
            !t.path("link-dst").exists(),
            "{flag} mutated its destination"
        );
    }

    for (flag, expected) in [
        ("--safe-links", "without classifying"),
        ("--munge-links", "preserved unchanged"),
    ] {
        let out = syq(&["-a", flag, &t.s("src/"), &t.s("link-dst/")]);
        assert!(!out.status.success(), "{flag} unexpectedly succeeded");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains(expected), "{flag}: {err}");
        assert!(
            !t.path("link-dst").exists(),
            "{flag} mutated its destination"
        );
    }
}

#[test]
fn removed_fsync_option_is_rejected() {
    let t = Tmp::new();
    write(&t.path("src"), b"data");
    let output = syq(&["--fsync", &t.s("src"), &t.s("dst")]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unexpected argument '--fsync'"), "{stderr}");
    assert!(!t.path("dst").exists());
}

#[test]
fn removed_checkpoint_option_is_rejected_without_creating_state() {
    let t = Tmp::new();
    write(&t.path("src"), b"data");
    let output = syq(&["--checkpoint", &t.s("state"), &t.s("src"), &t.s("dst")]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unexpected argument '--checkpoint'"),
        "{stderr}"
    );
    assert!(!t.path("state").exists());
    assert!(!t.path("dst").exists());
}

// Compatibility no-ops are accepted and change nothing.
#[test]
fn rsync_compat_noops_are_accepted() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"hello");
    // --numeric-ids, --partial, -P, -h are all no-ops here.
    run_ok(&[
        "-a",
        "--numeric-ids",
        "--partial",
        "-P",
        "-h",
        &t.s("src/"),
        &t.s("dst/"),
    ]);
    assert_eq!(read(&t.path("dst/f")), b"hello");
}

#[test]
fn conflicting_sources_leave_no_destination_behind() {
    let t = Tmp::new();
    write(&t.path("a/x"), b"1");
    write(&t.path("b/x"), b"2");
    let out = syq(&["-r", &t.s("a/"), &t.s("b/"), &t.s("dst/")]);
    assert_eq!(out.status.code(), Some(1));
    assert!(!t.path("dst").exists(), "destination must not be created");
    // And a clean multi-source copy into a missing destination still works.
    write(&t.path("c/y"), b"3");
    run_ok(&["-r", &t.s("a/"), &t.s("c/"), &t.s("dst2/")]);
    assert_eq!(listing(&t.path("dst2")), ["x", "y"]);
}

#[test]
fn constrained_agent_forwarding_requires_openssh_8_9() {
    let t = Tmp::new();
    let ssh = fake_ssh(&t);
    write(&t.path("src/file"), b"data");
    let run = |version: &str| {
        Command::new(env!("CARGO_BIN_EXE_syq"))
            .args([
                "cp",
                "--srcs-in",
                "/src",
                "--from",
                "hosta",
                "--to",
                "hostb",
                "--into",
                "/dst",
            ])
            .env("FAKE_SSH_VERSION", version)
            .env("FAKE_RSH_LOG", t.path("rsh.log"))
            .env("FAKE_REMOTE_HOME", t.path("remote-home"))
            .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", ssh.parent().unwrap().to_string_lossy()),
            )
            .run()
            .unwrap()
    };
    let old = run("8.2p1");
    assert!(!old.status.success());
    let stderr = String::from_utf8_lossy(&old.stderr);
    assert!(
        stderr.contains("needs OpenSSH 8.9 or newer on this machine, but ssh is OpenSSH 8.2"),
        "{stderr}"
    );
    assert!(stderr.contains("--peer-auth own-credentials"), "{stderr}");
    // The version probe must not have been mistaken for a connection.
    assert!(!t.path("rsh.log").exists(), "{stderr}");

    // A new enough client proceeds to the next step, which is reading the
    // real OpenSSH configuration that this fake cannot answer.
    let new = run("8.9p1");
    let stderr = String::from_utf8_lossy(&new.stderr);
    assert!(!stderr.contains("needs OpenSSH 8.9"), "{stderr}");
}

#[test]
fn native_local_exact_bare_home_expands_before_identity_check() {
    let t = Tmp::new();
    fs::create_dir_all(t.path("home")).unwrap();
    write(&t.path("src/file"), b"home destination");
    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["cp", "--src", &t.s("src"), "--as", "~", "-q"])
        .env("HOME", t.path("home"))
        .run()
        .expect("copy to a local bare-home destination");
    assert_output_ok(&out);
    assert_eq!(read(&t.path("home/file")), b"home destination");
}

#[test]
fn native_overwrite_policies_apply_per_entry() {
    for policy in ["--only-new", "--only-existing", "--skip-newer"] {
        let t = Tmp::new();
        write(&t.path("src/present"), b"source");
        write(&t.path("src/new"), b"new");
        write(&t.path("src/dir/child"), b"child");
        write(&t.path("src/nested/new"), b"nested");
        write(&t.path("dst/present"), b"destination");
        write(&t.path("dst/dir"), b"keep non-directory");
        fs::create_dir_all(t.path("dst/nested")).unwrap();
        set_mtime(&t.path("src/present"), 1_600_000_000);
        set_mtime(&t.path("dst/present"), 1_700_000_000);
        let out = native_syq(&[
            "cp",
            policy,
            "--srcs-in",
            &t.s("src"),
            "--into",
            &t.s("dst"),
        ]);
        assert_eq!(
            out.status.code(),
            Some(if policy == "--skip-newer" { 23 } else { 0 }),
            "{out:?}"
        );
        if policy == "--skip-newer" {
            assert!(stderr_of(&out).contains("cannot replace non-directory"));
        }
        let updates = policy == "--only-existing";
        assert_eq!(
            read(&t.path("dst/present")),
            if updates {
                b"source" as &[u8]
            } else {
                b"destination"
            }
        );
        assert_eq!(t.path("dst/new").exists(), policy != "--only-existing");
        assert_eq!(
            t.path("dst/nested/new").exists(),
            policy != "--only-existing"
        );
        assert_eq!(read(&t.path("dst/dir")), b"keep non-directory");
    }
    let t = Tmp::new();
    write(&t.path("source"), b"source");
    run_native_ok(&[
        "cp",
        "--only-existing",
        &t.s("source"),
        "--into",
        &t.s("missing"),
    ]);
    assert!(!t.path("missing").exists());
}

#[test]
fn native_copy_policy_conflicts_refuse_before_writing() {
    let t = Tmp::new();
    write(&t.path("source"), b"source");
    for pair in [
        ["--verify-only", "--prune"],
        ["--verify-only", "--dry-run"],
        ["--verify-only", "--inplace"],
        ["--verify-only", "--only-new"],
        ["--verify-only", "--only-existing"],
        ["--verify-only", "--skip-newer"],
        ["--only-new", "--only-existing"],
        ["--only-new", "--skip-newer"],
        ["--only-new", "--inplace"],
        ["--skip-newer", "--inplace"],
    ] {
        let out = native_syq(&[
            "cp",
            pair[0],
            pair[1],
            &t.s("source"),
            "--into",
            &t.s("dst"),
        ]);
        assert_eq!(out.status.code(), Some(2), "{pair:?}: {}", stderr_of(&out));
        assert!(!t.path("dst").exists());
    }
}

#[test]
fn environment_options_apply_to_the_command_and_never_reach_children() {
    let t = Tmp::new();
    fs::create_dir_all(t.path("source")).unwrap();
    fs::write(t.path("source/file"), b"payload").unwrap();

    // A dry run from the environment leaves the destination absent.
    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["cp", &t.s("source"), "--into", &t.s("local")])
        .env("SYQ_CP_OPTIONS", "--dry-run --quiet")
        .run()
        .unwrap();
    assert_output_ok(&out);
    assert!(!t.path("local").exists(), "{out:?}");

    // Unbalanced quoting is a usage error before any work starts.
    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["cp", &t.s("source"), "--into", &t.s("local")])
        .env("SYQ_CP_OPTIONS", "--quiet 'oops")
        .run()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(
        stderr_of(&out).contains("SYQ_CP_OPTIONS is not a valid shell word list"),
        "{out:?}"
    );
    assert!(!t.path("local").exists());

    // Over a remote shell the options still apply, and neither the command's
    // own variable nor another command's variable reaches the child.
    let fake_rsh = fake_rsh(&t);
    t.expose_remote_syq();
    let recorder = t.path("recording-rsh");
    executable(
        &recorder,
        format!(
            "#!/bin/sh\nenv > \"$RSH_ENV_DUMP\"\nexec {} \"$@\"\n",
            shell_words::quote(&fake_rsh.to_string_lossy())
        )
        .as_bytes(),
    );
    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "cp",
            &t.s("source"),
            "--to",
            "host",
            "--into",
            &t.s("remote"),
        ])
        .args([
            "--rsh",
            &recorder.to_string_lossy(),
            "--no-bootstrap",
            "--no-tcp",
        ])
        .env("SYQ_CP_OPTIONS", "--performance-tuning workers=1 --quiet")
        .env("SYQ_RM_OPTIONS", "--dry-run")
        .env("RSH_ENV_DUMP", t.path("rsh.env"))
        .env("FAKE_REMOTE_HOME", t.path("remote-home"))
        .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
        .env("FAKE_RSH_LOG", t.path("rsh.log"))
        .env("XDG_CONFIG_HOME", t.path("config"))
        .env("XDG_CACHE_HOME", t.path("cache"))
        .run()
        .unwrap();
    assert_output_ok(&out);
    assert_eq!(read(&t.path("remote/source/file")), b"payload");
    let child_env = fs::read_to_string(t.path("rsh.env")).unwrap();
    assert!(child_env.contains("RSH_ENV_DUMP="), "{child_env}");
    assert!(!child_env.contains("SYQ_CP_OPTIONS"), "{child_env}");
    assert!(!child_env.contains("SYQ_RM_OPTIONS"), "{child_env}");
}

#[test]
fn environment_options_never_reach_internal_server_entry_points() {
    for argv in [vec!["rsync", "--server"], vec!["--server"]] {
        let out = Command::new(env!("CARGO_BIN_EXE_syq"))
            .args(&argv)
            .env("SYQ_RSYNC_OPTIONS", "--quiet")
            .env("SYQ_CP_OPTIONS", "--quiet")
            .stdin(std::process::Stdio::null())
            .run()
            .unwrap();
        // The server announces itself before reading the client's preamble;
        // an argument error would exit 2 without doing so.
        assert!(out.stdout.starts_with(b"SYQWIRE"), "{argv:?}: {out:?}");
        assert_ne!(out.status.code(), Some(2), "{argv:?}: {out:?}");
        assert!(
            !stderr_of(&out).contains("unexpected argument"),
            "{argv:?}: {out:?}"
        );
    }
}

#[test]
fn managed_descriptor_upload_requires_commit() {
    let output = Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/support/managed-streams.py"
        ))
        .arg(env!("CARGO_BIN_EXE_syq"))
        .output()
        .expect("run managed stream fixture");
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn stream_placement_and_source_roots() {
    let t = Tmp::new();
    write(&t.path("payload"), b"stream");
    mkfifo(&t.path("pipe"));
    let rsh = fake_rsh(&t);

    // Tiny payloads keep captured output below pipe capacity. Bound failures
    // so opening a FIFO before checking placement cannot hang the test suite.
    let cp = |args: &[&str]| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
        for (name, _) in std::env::vars_os() {
            if name.to_string_lossy().starts_with("SYQ_") {
                command.env_remove(name);
            }
        }
        command
            .current_dir(&t.0)
            .env("HOME", &t.0)
            .env("FAKE_REMOTE_HOME", &t.0)
            .env("FAKE_RSH_LOG", t.path("rsh.log"))
            .args(["cp", "--rsh"])
            .arg(&rsh)
            .args(["--syq-path", env!("CARGO_BIN_EXE_syq")])
            .args(args)
            .stdin(File::open(t.path("payload")).unwrap())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        let mut child = command.start().unwrap();
        let started = std::time::Instant::now();
        let mut next_progress = 1;
        while child.try_wait().unwrap().is_none() {
            let elapsed = started.elapsed().as_secs();
            if elapsed >= 15 {
                unsafe {
                    libc::kill(-(child.id() as i32), libc::SIGKILL);
                }
                let output = child.wait_with_output().unwrap();
                panic!("stream copy timed out: {args:?}: {}", stderr_of(&output));
            }
            if elapsed >= next_progress {
                eprintln!("waiting for stream copy ({elapsed}s): {args:?}");
                next_progress += 1;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        child.wait_with_output().unwrap()
    };
    let succeeds = |args: &[&str]| {
        let output = cp(args);
        assert!(output.status.success(), "{args:?}: {}", stderr_of(&output));
        output
    };
    let fails = |args: &[&str], message: &str| {
        let output = cp(args);
        assert!(!output.status.success(), "{args:?}");
        assert!(
            stderr_of(&output).contains(message),
            "{args:?}: {}",
            stderr_of(&output)
        );
    };

    succeeds(&["--src-fd", "0", "--as-new", "target"]);
    write(&t.path("target"), b"old");
    // No writer: these must reject placement without even opening the pipe.
    for (flag, target) in [
        ("--as-new", "target"),
        ("--as-existing", "absent/file"),
        ("--into-new", "."),
        ("--into-existing", "absent"),
    ] {
        fails(&["pipe", flag, target], "existence condition failed");
    }
    assert_eq!(read(&t.path("target")), b"old");
    assert!(!t.path("absent").exists());
    // One helper case covers ordering across connection setup. The complete
    // placement matrix need not be repeated over the same filesystem code.
    fails(
        &["pipe", "--to", "fixture", "--as-new", &t.s("target")],
        "existence condition failed",
    );
    succeeds(&["--src-fd", "0", "--as-existing", "target"]);
    assert_eq!(read(&t.path("target")), b"stream");

    // Existence refers to the destination entry, including symlinks. Replacing
    // one must leave its referent intact; a dangling link is still an entry.
    write(&t.path("referent"), b"keep");
    std::os::unix::fs::symlink("referent", t.path("link")).unwrap();
    succeeds(&["--src-fd", "0", "--as-existing", "link"]);
    assert!(fs::symlink_metadata(t.path("link")).unwrap().is_file());
    assert_eq!(read(&t.path("link")), b"stream");
    assert_eq!(read(&t.path("referent")), b"keep");
    std::os::unix::fs::symlink("missing-referent", t.path("dangling")).unwrap();
    fails(
        &["--src-fd", "0", "--as-new", "dangling"],
        "existence condition failed",
    );
    assert_eq!(
        fs::read_link(t.path("dangling")).unwrap(),
        Path::new("missing-referent")
    );
    assert!(!t.path("missing-referent").exists());

    write(&t.path("directory/keep"), b"keep");
    for flag in ["--as", "--as-new", "--as-existing"] {
        let output = cp(&["--src-fd", "0", flag, "directory"]);
        assert!(!output.status.success(), "{flag} accepted a directory");
        assert_eq!(read(&t.path("directory/keep")), b"keep");
    }

    std::os::unix::fs::symlink("container", t.path("container-link")).unwrap();
    for (flag, destination, follow) in [
        ("--into-new", "container", false),
        ("--into-existing", "container", false),
        ("--into-existing", "container-link", true),
    ] {
        let fifo = t.path("pipe");
        let writer = std::thread::spawn(move || {
            File::options()
                .write(true)
                .open(fifo)
                .and_then(|mut file| file.write_all(b"fifo"))
        });
        let mut args = vec!["--root", ".", "--src-non-dir", "pipe", flag, destination];
        if follow {
            args.push("--follow-dst");
        }
        let output = cp(&args);
        // Release the owned writer even if a regression rejected the copy.
        let _rescue = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(t.path("pipe"))
            .unwrap();
        writer.join().unwrap().unwrap();
        assert!(output.status.success(), "{}", stderr_of(&output));
        assert_eq!(read(&t.path("container/pipe")), b"fifo");
        fs::remove_file(t.path("container/pipe")).unwrap();
    }
    fails(&["pipe", "--into-existing", "container-link"], "symlink");
    assert_eq!(
        fs::read_link(t.path("container-link")).unwrap(),
        Path::new("container")
    );
    assert!(!t.path("container/pipe").exists());
    fails(
        &["--src-fd", "0", "--into-new", "unnamed"],
        "needs a source name",
    );

    write(&t.path("source/data"), b"read me");
    std::os::unix::fs::symlink("data", t.path("source/inside")).unwrap();
    std::os::unix::fs::symlink("../target", t.path("source/escape")).unwrap();
    for base in ["--cwd", "--root"] {
        assert_eq!(
            succeeds(&[base, "source", "data", "--as-fd", "1"]).stdout,
            b"read me"
        );
    }
    for path in ["../target", "escape"] {
        let output = cp(&["--root", "source", "--follow-src", path, "--as-fd", "1"]);
        assert!(!output.status.success(), "{path}");
        assert!(output.stdout.is_empty());
    }
    assert_eq!(
        succeeds(&["--root", "source", "--follow-src", "inside", "--as-fd", "1"]).stdout,
        b"read me"
    );
    fails(
        &["--root", "source", "--src-fd", "0", "--as", "target"],
        "cannot confine an inherited descriptor",
    );
}

#[test]
fn stream_controls_check_hashes_pace_and_keep_payload_clean() {
    let t = Tmp::new();
    let payload = vec![73; 128 << 10];
    write(&t.path("source"), &payload);
    let digest = format!(
        "sha256:{}",
        Sha256::digest(&payload)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    let cp = |args: &[&str], inherited: &str| {
        Command::new(env!("CARGO_BIN_EXE_syq"))
            .current_dir(&t.0)
            .env("SYQ_CP_OPTIONS", inherited)
            .arg("cp")
            .args(args)
            .stdin(File::open(t.path("source")).unwrap())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .start()
            .unwrap()
            .wait_with_output()
            .unwrap()
    };
    let start = std::time::Instant::now();
    let out = cp(
        &[
            "--src-fd",
            "0",
            "--as",
            "target",
            "--expected-hash",
            &digest,
            "--resource-limits",
            "bandwidth=512K,workers=1",
            "--performance-tuning",
            "request-size=16K,pipeline-depth=2,bw-pacing=25ms",
            "--stats",
            "-v",
        ],
        "",
    );
    assert_output_ok(&out);
    assert!(
        start.elapsed().as_millis() >= 240,
        "upload ignored bandwidth limit"
    );
    assert!(out.stdout.is_empty());
    assert_eq!(read(&t.path("target")), payload);
    assert!(
        stderr_of(&out).contains("131072 bytes"),
        "{}",
        stderr_of(&out)
    );
    for algorithm in ["blake3", "sha256", "md5", "xxh3-128"] {
        let out = cp(
            &[
                "--src-fd",
                "0",
                "--as",
                "target",
                "--integrity-checking",
                &format!("transfer={algorithm}"),
                "--performance-tuning",
                "request-size=8K,pipeline-depth=3",
            ],
            "",
        );
        assert_output_ok(&out);
        let out = cp(
            &[
                "target",
                "--as-fd",
                "1",
                "--expected-hash",
                &digest,
                "--integrity-checking",
                &format!("transfer={algorithm}"),
                "--progress-json",
            ],
            "",
        );
        assert_output_ok(&out);
        assert_eq!(out.stdout, payload);
        let progress: serde_json::Value =
            serde_json::from_str(stderr_of(&out).lines().last().unwrap()).unwrap();
        assert_eq!(progress["bytes_done"], payload.len());
        assert_eq!(progress["files_done"], 1);
    }
    let start = std::time::Instant::now();
    let out = cp(
        &[
            "target",
            "--as-fd",
            "1",
            "--resource-limits",
            "bandwidth=512K",
            "-vv",
        ],
        "",
    );
    assert_output_ok(&out);
    assert_eq!(out.stdout, payload);
    assert_eq!(
        stderr_of(&out).matches(" ready (local)").count(),
        2,
        "two-range paced download opened idle workers: {}",
        stderr_of(&out)
    );
    assert!(
        start.elapsed().as_millis() >= 240,
        "download ignored bandwidth limit"
    );
    write(&t.path("target"), b"old");
    let wrong = format!("sha256:{}", "0".repeat(64));
    let out = cp(
        &["--src-fd", "0", "--as", "target", "--expected-hash", &wrong],
        "",
    );
    assert!(!out.status.success());
    assert!(
        stderr_of(&out).contains("expected sha256 hash"),
        "{}",
        stderr_of(&out)
    );
    assert_eq!(read(&t.path("target")), b"old");
    assert!(!fs::read_dir(&t.0).unwrap().any(|e| e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".syq-stream-")));
    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .current_dir(&t.0)
        .env("SYQ_CP_OPTIONS", "--stats --performance-tuning workers=2")
        .args(["cp", "source", "--as-fd", "1", "-vv"])
        .run()
        .unwrap();
    assert_output_ok(&out);
    assert_eq!(out.stdout, payload);
    assert!(stderr_of(&out).contains("131072 bytes"));
    assert_eq!(
        stderr_of(&out).matches(" ready (local)").count(),
        2,
        "explicit worker count was changed: {}",
        stderr_of(&out)
    );
}

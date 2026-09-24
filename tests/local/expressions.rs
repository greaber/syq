use super::*;

#[test]
fn selection_traverses_unselected_directories_and_protects_pruning() {
    let t = Tmp::new();
    write(&t.path("src/nested/keep.txt"), b"selected");
    write(&t.path("src/nested/tiny.txt"), b"x");
    write(&t.path("src/ignored/keep.txt"), b"ignored");
    write(&t.path("dst/nested/tiny.txt"), b"protected");
    write(&t.path("dst/extra"), b"remove");
    run_native_ok(&[
        "cp",
        "--srcs-in",
        &t.s("src"),
        "--into",
        &t.s("dst"),
        "--ignore",
        "ignored/",
        "--where",
        "src.kind = 'file' and src.size >= 4B and src.name glob '*.txt'",
        "--prune",
    ]);
    assert_eq!(read(&t.path("dst/nested/keep.txt")), b"selected");
    assert_eq!(read(&t.path("dst/nested/tiny.txt")), b"protected");
    assert!(!t.path("dst/extra").exists());
    assert!(!t.path("dst/ignored").exists());
}

#[test]
fn destination_conditions_apply_before_content_and_metadata_updates() {
    let t = Tmp::new();
    write(&t.path("src/grow"), b"longer source");
    write(&t.path("dst/grow"), b"x");
    write(&t.path("src/keep"), b"x");
    write(&t.path("dst/keep"), b"longer destination");
    write(&t.path("src/new"), b"new file");
    fs::set_permissions(t.path("src/keep"), fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(t.path("dst/keep"), fs::Permissions::from_mode(0o644)).unwrap();
    run_native_ok(&[
        "cp",
        "--srcs-in",
        &t.s("src"),
        "--into",
        &t.s("dst"),
        "--preserve=permissions",
        "--copy-if",
        "not dst.exists or (src.kind = 'file' and dst.kind = 'file' and src.size > dst.size)",
    ]);
    assert_eq!(read(&t.path("dst/grow")), b"longer source");
    assert_eq!(read(&t.path("dst/keep")), b"longer destination");
    assert_eq!(
        fs::metadata(t.path("dst/keep")).unwrap().mode() & 0o777,
        0o644
    );
    assert_eq!(read(&t.path("dst/new")), b"new file");
}

#[test]
fn invalid_expression_fails_before_creating_destination() {
    let t = Tmp::new();
    write(&t.path("src"), b"contents");
    for expression in [
        "src.size > 3s",
        "src.mtime > 'yesterday'",
        "dst.exists",
        "src.nonexistent = 1",
        "true or src.mode = 'bad'",
    ] {
        let out = native_syq(&[
            "cp",
            &t.s("src"),
            "--as",
            &t.s("dst"),
            "--where",
            expression,
        ]);
        assert!(!out.status.success(), "{expression}");
        assert!(!t.path("dst").exists());
    }
}

#[test]
fn explicit_file_name_and_renamed_destination_are_available() {
    let t = Tmp::new();
    write(&t.path("original.txt"), b"contents");
    run_native_ok(&[
        "cp",
        &t.s("original.txt"),
        "--as",
        &t.s("renamed.dat"),
        "--where",
        "src.name = 'original.txt'",
        "--copy-if",
        "dst.name = 'renamed.dat' and not dst.exists",
    ]);
    assert_eq!(read(&t.path("renamed.dat")), b"contents");
}

#[test]
fn dry_run_and_hash_comparison_respect_eligibility() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"new");
    write(&t.path("dst/a"), b"old");
    run_native_ok(&[
        "cp",
        "--srcs-in",
        &t.s("src"),
        "--into",
        &t.s("dst"),
        "--copy-if",
        "false",
        "--hash",
    ]);
    assert_eq!(read(&t.path("dst/a")), b"old");
    let out = native_syq(&[
        "cp",
        "--srcs-in",
        &t.s("src"),
        "--into",
        &t.s("dst"),
        "--copy-if",
        "true",
        "--hash",
        "--dry-run",
        "-v",
    ]);
    assert!(out.status.success(), "{}", stderr_of(&out));
    assert_eq!(read(&t.path("dst/a")), b"old");
    run_native_ok(&[
        "cp",
        "--srcs-in",
        &t.s("src"),
        "--into",
        &t.s("dst"),
        "--copy-if",
        "true",
        "--hash",
    ]);
    assert_eq!(read(&t.path("dst/a")), b"new");
}

#[test]
fn evaluation_errors_are_visible_and_prevent_pruning() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"new");
    write(&t.path("dst/extra"), b"keep");
    let out = native_syq(&[
        "cp",
        "--srcs-in",
        &t.s("src"),
        "--into",
        &t.s("dst"),
        "--copy-if",
        "1 / 0 = 1",
        "--prune",
    ]);
    assert!(!out.status.success());
    assert!(
        stderr_of(&out).contains("division by zero"),
        "{}",
        stderr_of(&out)
    );
    assert_eq!(read(&t.path("dst/extra")), b"keep");
}

#[test]
fn symlinks_can_be_selected_by_target_without_following() {
    let t = Tmp::new();
    write(&t.path("src/file"), b"data");
    std::os::unix::fs::symlink("file", t.path("src/link")).unwrap();
    run_native_ok(&[
        "cp",
        "--srcs-in",
        &t.s("src"),
        "--into",
        &t.s("dst"),
        "--where",
        "src.kind = 'symlink' and src.link_target = 'file'",
    ]);
    assert_eq!(
        fs::read_link(t.path("dst/link")).unwrap(),
        Path::new("file")
    );
    assert!(!t.path("dst/file").exists());
}

#[test]
fn remote_push_and_pull_apply_expressions_over_ssh_and_tcp() {
    for pull in [false, true] {
        for tcp in [false, true] {
            let t = Tmp::new();
            let rsh = fake_rsh(&t);
            t.expose_remote_syq();
            write(&t.path("src/nested/keep"), b"selected payload");
            write(&t.path("src/nested/tiny"), b"x");
            write(&t.path("dst/nested/keep"), b"old");
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_syq"));
            cmd.arg("cp");
            if pull {
                cmd.args(["--from", "127.0.0.1"]);
            }
            cmd.args(["--srcs-in", &t.s("src")]);
            if !pull {
                cmd.args(["--to", "127.0.0.1"]);
            }
            cmd.args([
                "--into",
                &t.s("dst"),
                "--where",
                "src.kind = 'file' and src.size > 1B",
                "--copy-if",
                "not dst.exists or src.size > dst.size",
                "--rsh",
                rsh.to_str().unwrap(),
                "--no-bootstrap",
                "--tcp-ports",
                EPHEMERAL_TCP_PORTS,
                "--no-progress",
            ])
            .env("FAKE_REMOTE_HOME", t.path("remote-home"))
            .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
            .env("XDG_CACHE_HOME", t.path("cache"));
            if !tcp {
                cmd.arg("--no-tcp");
            }
            let out = cmd.run().unwrap();
            assert_output_ok(&out);
            assert_eq!(read(&t.path("dst/nested/keep")), b"selected payload");
            assert!(!t.path("dst/nested/tiny").exists());
        }
    }
}

#[test]
fn expressions_reject_streams_and_copy_if_rejects_inplace() {
    let t = Tmp::new();
    write(&t.path("src"), b"unchanged");
    for options in [
        vec!["--src-fd", "0", "--where", "true"],
        vec!["--src-fd", "0", "--copy-if", "true"],
        vec!["--src", &t.s("src"), "--copy-if", "true", "--inplace"],
    ] {
        let mut args = vec!["cp"];
        args.extend(options);
        let dst = t.s("dst");
        args.extend(["--as", &dst]);
        let out = native_syq(&args);
        assert!(!out.status.success());
        assert!(!t.path("dst").exists());
    }
}

#[test]
fn where_filters_leaves_and_copy_if_controls_directory_metadata() {
    let t = Tmp::new();
    write(&t.path("src/private/keep.jpg"), b"selected");
    write(&t.path("src/private/skip.txt"), b"excluded");
    fs::create_dir_all(t.path("src/empty")).unwrap();
    fs::set_permissions(t.path("src/private"), fs::Permissions::from_mode(0o700)).unwrap();
    for run in 0..2 {
        // Cover both fresh and existing destination directories.
        run_native_ok(&[
            "cp",
            "--srcs-in",
            &t.s("src"),
            "--into",
            &t.s("dst"),
            "--preserve=permissions",
            "--where",
            "src.extension = 'jpg'",
        ]);
        assert_eq!(
            fs::metadata(t.path("dst/private")).unwrap().mode() & 0o777,
            0o700
        );
        assert_eq!(read(&t.path("dst/private/keep.jpg")), b"selected");
        assert!(!t.path("dst/private/skip.txt").exists());
        assert!(t.path("dst/empty").is_dir());
        if run == 0 {
            fs::set_permissions(t.path("dst/private"), fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
    fs::set_permissions(t.path("dst/private"), fs::Permissions::from_mode(0o755)).unwrap();
    run_native_ok(&[
        "cp",
        "--srcs-in",
        &t.s("src"),
        "--into",
        &t.s("dst"),
        "--preserve=permissions",
        "--where",
        "src.extension = 'jpg'",
        "--copy-if",
        "src.kind != 'dir'",
    ]);
    assert_eq!(
        fs::metadata(t.path("dst/private")).unwrap().mode() & 0o777,
        0o755
    );
    run_native_ok(&[
        "cp",
        "--srcs-in",
        &t.s("src"),
        "--into",
        &t.s("dst"),
        "--preserve=permissions",
        "--where",
        "false",
        "--copy-if",
        "src.kind = 'dir'",
    ]);
    assert_eq!(
        fs::metadata(t.path("dst/private")).unwrap().mode() & 0o777,
        0o700
    );
}

#[test]
fn merged_directories_keep_each_sources_expression_result() {
    let t = Tmp::new();
    write(&t.path("first/shared/one"), b"one");
    write(&t.path("second/shared/two"), b"two");
    fs::create_dir_all(t.path("dst/shared")).unwrap();
    for (path, mode) in [
        ("first/shared", 0o750),
        ("second/shared", 0o700),
        ("dst/shared", 0o755),
    ] {
        fs::set_permissions(t.path(path), fs::Permissions::from_mode(mode)).unwrap();
    }
    run_native_ok(&[
        "cp",
        "--srcs-in",
        &t.s("first"),
        "--srcs-in",
        &t.s("second"),
        "--into",
        &t.s("dst"),
        "--preserve=permissions",
        "--copy-if",
        "src.kind = 'file' or src.mode = 0o750",
    ]);
    assert_eq!(
        fs::metadata(t.path("dst/shared")).unwrap().mode() & 0o777,
        0o750
    );
    assert_eq!(read(&t.path("dst/shared/one")), b"one");
    assert_eq!(read(&t.path("dst/shared/two")), b"two");
}

#[test]
fn unselected_containers_use_receiver_umask_and_inheritance() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    let script = fs::read_to_string(&rsh).unwrap();
    executable(
        &rsh,
        script
            .replace("#!/bin/sh\n", "#!/bin/sh\numask 077\n")
            .as_bytes(),
    );
    t.expose_remote_syq();
    write(&t.path("src/nested/keep"), b"selected");
    fs::create_dir_all(t.path("dst")).unwrap();
    fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o2775)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "cp",
            "--srcs-in",
            &t.s("src"),
            "--to",
            "127.0.0.1",
            "--into",
            &t.s("dst"),
            "--where",
            "src.kind = 'file'",
            "--copy-if",
            "src.kind != 'dir'",
            "--rsh",
            rsh.to_str().unwrap(),
            "--no-bootstrap",
            "--no-tcp",
            "--no-progress",
        ])
        .env("FAKE_REMOTE_HOME", t.path("remote-home"))
        .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
        .env("XDG_CACHE_HOME", t.path("cache"))
        .run()
        .unwrap();
    assert_output_ok(&output);
    assert_eq!(read(&t.path("dst/nested/keep")), b"selected");
    assert_eq!(
        fs::metadata(t.path("dst/nested")).unwrap().mode() & 0o777,
        0o700
    );
    #[cfg(target_os = "linux")]
    assert_eq!(
        fs::metadata(t.path("dst/nested")).unwrap().mode() & 0o2000,
        0o2000
    );
}

#[test]
fn unselected_readonly_containers_reopen_and_restore_their_modes() {
    let t = Tmp::new();
    write(&t.path("src/nested/keep"), b"selected");
    fs::create_dir_all(t.path("dst/nested")).unwrap();
    fs::set_permissions(t.path("dst/nested"), fs::Permissions::from_mode(0o555)).unwrap();
    let output = native_syq(&[
        "cp",
        "--srcs-in",
        &t.s("src"),
        "--into",
        &t.s("dst"),
        "--where",
        "src.kind = 'file'",
        "--copy-if",
        "src.kind != 'dir'",
        "--preserve=permissions",
    ]);
    let mode = fs::metadata(t.path("dst/nested")).unwrap().mode() & 0o7777;
    fs::set_permissions(t.path("dst/nested"), fs::Permissions::from_mode(0o755)).unwrap();
    assert_output_ok(&output);
    assert_eq!(mode, 0o555);
    assert_eq!(read(&t.path("dst/nested/keep")), b"selected");
}

#[test]
fn destination_inspection_errors_are_not_missing_entries() {
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("permission-denied fixture requires a non-root user");
        return;
    }
    for remote in [false, true] {
        let t = Tmp::new();
        fs::create_dir_all(t.path("src/nested")).unwrap();
        fs::create_dir_all(t.path("dst/nested")).unwrap();
        std::os::unix::fs::symlink("source-target", t.path("src/nested/link")).unwrap();
        std::os::unix::fs::symlink("destination-target", t.path("dst/nested/link")).unwrap();
        fs::set_permissions(t.path("dst/nested"), fs::Permissions::from_mode(0o000)).unwrap();
        let rsh = fake_rsh(&t);
        t.expose_remote_syq();
        let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
        command.args([
            "cp",
            "--srcs-in",
            &t.s("src"),
            "--into",
            &t.s("dst"),
            "--where",
            "src.kind = 'symlink'",
            "--copy-if",
            "dst.exists",
            "--only-new",
            "--no-progress",
        ]);
        if remote {
            command
                .args([
                    "--to",
                    "127.0.0.1",
                    "--rsh",
                    rsh.to_str().unwrap(),
                    "--no-bootstrap",
                    "--no-tcp",
                ])
                .env("FAKE_REMOTE_HOME", t.path("remote-home"))
                .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
                .env("XDG_CACHE_HOME", t.path("cache"));
        }
        let output = command.run().unwrap();
        fs::set_permissions(t.path("dst/nested"), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(!output.status.success(), "{output:?}");
        assert!(
            stderr_of(&output).contains("Permission denied"),
            "{output:?}"
        );
        assert_eq!(
            fs::read_link(t.path("dst/nested/link")).unwrap(),
            Path::new("destination-target")
        );
    }
}

#[cfg(debug_assertions)]
#[test]
fn fresh_dry_run_estimates_count_copy_if_selected_leaves() {
    for existing in [false, true] {
        for (condition, bytes) in [
            ("not dst.exists and src.path = 'nested/tiny'", "3 B"),
            ("dst.exists", "0 B"),
        ] {
            let t = Tmp::new();
            write(&t.path("src/nested/tiny"), b"abc");
            write(&t.path("src/nested/large"), b"longer contents");
            if existing {
                fs::create_dir(t.path("dst")).unwrap();
            }
            let out = Command::new(env!("CARGO_BIN_EXE_syq"))
                .args([
                    "cp",
                    "--srcs-in",
                    &t.s("src"),
                    "--into",
                    &t.s("dst"),
                    "--dry-run",
                    "--copy-if",
                    condition,
                    "--no-progress",
                ])
                .env("SYQ_TEST_AVAILABLE_BYTES", "1")
                .run()
                .unwrap();
            assert_output_ok(&out);
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(
                stdout.contains(&format!("capacity: {bytes} logical data required")),
                "{stdout}"
            );
            assert!(!t.path("dst/nested").exists());
        }
    }
}

#[cfg(debug_assertions)]
#[test]
fn tiny_expression_pushes_use_fused_copy_and_preserve_excluded_files() {
    for force_planner in [false, true] {
        let t = Tmp::new();
        let rsh = fake_rsh(&t);
        t.expose_remote_syq();
        write(&t.path("src/keep"), b"new contents");
        write(&t.path("src/skip"), b"rejected source");
        write(&t.path("src/existing"), b"replace?");
        write(&t.path("dst/existing"), b"keep destination unchanged");
        fs::set_permissions(t.path("src/existing"), fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(t.path("dst/existing"), fs::Permissions::from_mode(0o644)).unwrap();
        let results = t.s("results.jsonl");
        let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
        command
            .args([
                "cp",
                &t.s("src/keep"),
                &t.s("src/skip"),
                &t.s("src/existing"),
                "--to",
                "host",
                "--into",
                &t.s("dst"),
                "--where",
                "src.name != 'skip' and src.kind = 'file'",
                "--copy-if",
                "not dst.exists or src.size > dst.size",
                "--preserve=permissions",
                "--results",
                &results,
                "--rsh",
                rsh.to_str().unwrap(),
                "--no-bootstrap",
                "--no-tcp",
                "--no-progress",
            ])
            .env("FAKE_REMOTE_HOME", t.path("remote-home"))
            .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
            .env("XDG_CACHE_HOME", t.path("cache"))
            .env("SYQ_DEBUG", "1");
        if force_planner {
            command.env("SYQ_TEST_DISABLE_SMALL_COPY", "1");
        }
        let output = command.run().unwrap();
        assert_output_ok(&output);
        assert_eq!(
            stderr_of(&output).contains("small copy: published"),
            !force_planner,
            "{}",
            stderr_of(&output)
        );
        assert_eq!(read(&t.path("dst/keep")), b"new contents");
        assert!(!t.path("dst/skip").exists());
        assert_eq!(read(&t.path("dst/existing")), b"keep destination unchanged");
        assert_eq!(
            fs::metadata(t.path("dst/existing")).unwrap().mode() & 0o777,
            0o644
        );
        let records: Vec<serde_json::Value> = fs::read_to_string(results)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let terminal = records.last().unwrap();
        assert_eq!(terminal["files_excluded"], 2, "{terminal}");
        assert_eq!(terminal["files_transferred"], 1, "{terminal}");
    }
}

#[test]
fn tiny_copy_if_sees_original_source_and_renamed_destination() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    t.expose_remote_syq();
    write(&t.path("original"), b"contents");
    write(&t.path("renamed"), b"x");
    fs::set_permissions(t.path("original"), fs::Permissions::from_mode(0o400)).unwrap();
    // The source mode must remain 0400 in the expression, even though normal
    // staging adds owner-write permission to the publication metadata.
    let meta = fs::metadata(t.path("original")).unwrap();
    let predicate = format!("src.name = 'original' and dst.path = 'renamed' and dst.exists and src.mode = 0o400 and src.inode = {} and src.nlink = 1 and src.ctime <= now and src.size > dst.size", meta.ino());
    let output = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "cp",
            &t.s("original"),
            "--to",
            "host",
            "--as",
            &t.s("renamed"),
            "--copy-if",
            &predicate,
            "--rsh",
            rsh.to_str().unwrap(),
            "--no-bootstrap",
            "--no-tcp",
            "--no-progress",
        ])
        .env("FAKE_REMOTE_HOME", t.path("remote-home"))
        .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
        .env("XDG_CACHE_HOME", t.path("cache"))
        .env("SYQ_DEBUG", "1")
        .run()
        .unwrap();
    assert_output_ok(&output);
    assert!(
        stderr_of(&output).contains("small copy: published"),
        "{}",
        stderr_of(&output)
    );
    assert_eq!(read(&t.path("renamed")), b"contents");
}

#[test]
fn tiny_copy_if_rejection_and_errors_leave_missing_targets_absent() {
    for predicate in ["dst.exists", "dst.exists or 1 / 0 = 0"] {
        let t = Tmp::new();
        let rsh = fake_rsh(&t);
        t.expose_remote_syq();
        write(&t.path("source"), b"contents");
        fs::create_dir(t.path("dst")).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_syq"))
            .args([
                "cp",
                &t.s("source"),
                "--to",
                "host",
                "--into",
                &t.s("dst"),
                "--copy-if",
                predicate,
                "--rsh",
                rsh.to_str().unwrap(),
                "--no-bootstrap",
                "--no-tcp",
                "--no-progress",
            ])
            .env("FAKE_REMOTE_HOME", t.path("remote-home"))
            .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
            .env("XDG_CACHE_HOME", t.path("cache"))
            .env("SYQ_DEBUG", "1")
            .run()
            .unwrap();
        if predicate == "dst.exists" {
            assert_output_ok(&output);
            assert!(
                stderr_of(&output).contains("small copy: published"),
                "{}",
                stderr_of(&output)
            );
        } else {
            assert!(!output.status.success(), "{}", stderr_of(&output));
            assert!(
                stderr_of(&output).contains("division by zero"),
                "{}",
                stderr_of(&output)
            );
        }
        assert!(!t.path("dst/source").exists());
        assert_eq!(fs::read_dir(t.path("dst")).unwrap().count(), 0);
    }
}

#[cfg(debug_assertions)]
#[test]
fn remote_copy_if_batches_directory_and_leaf_observations() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    t.expose_remote_syq();
    write(&t.path("src/nested/keep"), b"longer new contents");
    write(&t.path("src/nested/skip"), b"x");
    write(&t.path("dst/nested/keep"), b"old");
    write(&t.path("dst/nested/skip"), b"keep old contents");
    let output = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "cp",
            "--srcs-in",
            &t.s("src"),
            "--to",
            "host",
            "--into",
            &t.s("dst"),
            "--copy-if",
            "not dst.exists or src.size > dst.size",
            "--rsh",
            rsh.to_str().unwrap(),
            "--no-bootstrap",
            "--no-tcp",
            "--no-progress",
        ])
        .env("FAKE_REMOTE_HOME", t.path("remote-home"))
        .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
        .env("XDG_CACHE_HOME", t.path("cache"))
        .env("SYQ_TEST_DESTINATION_LOOKUPS", t.path("lookups"))
        .run()
        .unwrap();
    assert_output_ok(&output);
    assert_eq!(read(&t.path("dst/nested/keep")), b"longer new contents");
    assert_eq!(read(&t.path("dst/nested/skip")), b"keep old contents");
    let lookups = fs::read_to_string(t.path("lookups")).unwrap();
    assert!(
        lookups
            .lines()
            .any(|line| line.starts_with("batch ") && line.ends_with(" 2 true")),
        "{lookups}"
    );
    assert!(
        !lookups.lines().any(|line| line.starts_with("lookup ")),
        "{lookups}"
    );
}

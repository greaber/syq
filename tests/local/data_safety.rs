use super::*;

fn timestamp(path: &Path, seconds: u64, nanos: u32) {
    File::open(path)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(
            std::time::SystemTime::UNIX_EPOCH + std::time::Duration::new(seconds, nanos),
        ))
        .unwrap();
}

#[test]
fn native_copy_detects_subsecond_and_older_timestamp_edits() {
    for size in [8, 128 << 10] {
        let t = Tmp::new();
        write(&t.path("src/file"), &vec![b'a'; size]);
        timestamp(&t.path("src/file"), 1_700_000_000, 100_000_000);
        let args = [
            "cp",
            "--if-exists=update",
            "--srcs-in",
            &t.s("src"),
            "--into",
            &t.s("dst"),
        ];
        run_native_ok(&args);
        for (byte, seconds, nanos) in [
            (b'b', 1_700_000_000, 200_000_000),
            (b'c', 1_699_999_000, 300_000_000),
        ] {
            write(&t.path("src/file"), &vec![byte; size]);
            timestamp(&t.path("src/file"), seconds, nanos);
            run_native_ok(&args);
            assert_eq!(read(&t.path("dst/file")), vec![byte; size]);
        }
    }
}

#[test]
fn prune_refuses_a_destination_containing_its_source() {
    let t = Tmp::new();
    write(&t.path("backup/import/file"), b"source contents");
    write(&t.path("backup/old"), b"old contents");
    let out = native_syq(&[
        "cp",
        "--prune",
        "--srcs-in",
        &t.s("backup/import"),
        "--into",
        &t.s("backup"),
    ]);
    assert!(!out.status.success());
    assert!(stderr_of(&out).contains("contains source"), "{out:?}");
    assert_eq!(read(&t.path("backup/import/file")), b"source contents");
    assert_eq!(read(&t.path("backup/old")), b"old contents");
    assert!(!t.path("backup/file").exists());
}

#[cfg(debug_assertions)]
#[test]
fn prune_is_suppressed_after_an_ordinary_file_read_failure() {
    let t = Tmp::new();
    write(&t.path("src/file"), &vec![b'n'; 128 << 10]);
    write(&t.path("dst/file"), b"previous complete file");
    write(&t.path("dst/extra"), b"keep after failure");
    let out = compat_command()
        .args([
            "-a",
            "--delete",
            "--performance-tuning=copy-path=ranges",
            &t.s("src/"),
            &t.s("dst/"),
        ])
        .env("SYQ_TEST_FAIL_READ_RANGE", "1")
        .run()
        .unwrap();
    assert!(!out.status.success());
    assert!(stderr_of(&out).contains("skipping deletions"), "{out:?}");
    assert_eq!(read(&t.path("dst/file")), b"previous complete file");
    assert_eq!(read(&t.path("dst/extra")), b"keep after failure");
}

#[test]
fn prune_preserves_equivalent_existing_filename_spelling() {
    for dry_run in [true, false] {
        let t = Tmp::new();
        write(&t.path("src/sub/report.txt"), b"contents");
        write(&t.path("dst/SUB/REPORT.TXT"), b"contents");
        if !t.path("dst/sub/report.txt").exists() {
            eprintln!("skipping: test filesystem distinguishes case");
            return;
        }
        timestamp(&t.path("src/sub/report.txt"), 1_700_000_000, 0);
        timestamp(&t.path("dst/SUB/REPORT.TXT"), 1_700_000_000, 0);
        std::os::unix::fs::symlink("missing-target", t.path("src/sub/link")).unwrap();
        std::os::unix::fs::symlink("missing-target", t.path("dst/SUB/LINK")).unwrap();
        fs::create_dir_all(t.path("dst/EXTRA/nested")).unwrap();
        fs::hard_link(
            t.path("dst/SUB/REPORT.TXT"),
            t.path("dst/EXTRA/nested/other-link"),
        )
        .unwrap();
        write(&t.path("dst/EXTRA/extra"), b"extra");
        write(&t.path("dst/SUB/extra"), b"extra");
        let src = t.s("src");
        let dst = t.s("dst");
        let mut args = vec!["cp", "--prune", "--srcs-in", &src, "--into", &dst];
        if dry_run {
            args.push("--dry-run");
        }
        run_native_ok(&args);
        assert_eq!(read(&t.path("dst/sub/report.txt")), b"contents");
        assert_eq!(
            fs::read_link(t.path("dst/sub/link")).unwrap(),
            Path::new("missing-target")
        );
        // An alternate spelling cannot distinguish this extra hard link by
        // inode. Keep both possible matches, rather than risk deleting one.
        assert_eq!(read(&t.path("dst/EXTRA/nested/other-link")), b"contents");
        assert_eq!(t.path("dst/SUB/extra").exists(), dry_run);
        assert_eq!(t.path("dst/EXTRA/extra").exists(), dry_run);
    }
}

#[test]
fn prune_removes_extra_hardlinks_when_selected_spelling_matches() {
    let t = Tmp::new();
    write(&t.path("src/file"), b"contents");
    write(&t.path("dst/file"), b"contents");
    timestamp(&t.path("src/file"), 1_700_000_000, 0);
    timestamp(&t.path("dst/file"), 1_700_000_000, 0);
    fs::hard_link(t.path("dst/file"), t.path("dst/extra-link")).unwrap();
    run_native_ok(&[
        "cp",
        "--prune",
        "--srcs-in",
        &t.s("src"),
        "--into",
        &t.s("dst"),
    ]);
    assert_eq!(read(&t.path("dst/file")), b"contents");
    assert!(!t.path("dst/extra-link").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn copy_and_prune_preserve_distinct_unix_filename_bytes() {
    let names = [
        b"Makefile".as_slice(),
        b"makefile",
        "é".as_bytes(),
        "e\u{301}".as_bytes(),
        "fullwidth-Ａ".as_bytes(),
        b"fullwidth-A",
        b"trailing",
        b"trailing.",
        b"trailing ",
        b"raw-\xff",
    ];
    for mode in ["auto", "ranges"] {
        let t = Tmp::new();
        let names: Vec<_> = names
            .iter()
            .map(|name| std::ffi::OsString::from_vec(name.to_vec()))
            .collect();
        for (i, name) in names.iter().enumerate() {
            write(&t.path("src").join(name), &[i as u8]);
        }
        // Includes the fused small-file path and the general planner, then
        // pruning on an existing tree. Run on the caller's test filesystem.
        let src = t.s("src");
        let dst = t.s("dst");
        let tuning = format!("--performance-tuning=copy-path={mode}");
        let mut args = vec!["cp", &tuning, "--srcs-in", &src, "--into", &dst];
        run_native_ok(&args);
        write(&t.path("dst/extra"), b"extra");
        args.push("--prune");
        run_native_ok(&args);
        for (i, name) in names.iter().enumerate() {
            assert_eq!(read(&t.path("dst").join(name)), [i as u8]);
        }
        assert!(!t.path("dst/extra").exists());
    }
}

#[test]
fn prune_refuses_destination_containing_source() {
    let t = Tmp::new();
    write(&t.path("backup/import/file"), b"source contents");
    let out = compat_command()
        .args(["-a", "--delete"])
        .arg(t.path("backup/import/"))
        .arg(t.path("backup/"))
        .run()
        .unwrap();
    assert!(!out.status.success());
    assert!(stderr_of(&out).contains("contains source"), "{out:?}");
    assert_eq!(read(&t.path("backup/import/file")), b"source contents");
    assert!(!t.path("backup/file").exists());
}

#[test]
fn prune_protects_an_exact_source_beneath_another_sources_destination() {
    let t = Tmp::new();
    write(&t.path("external/other"), b"other source");
    write(&t.path("backup/import/file"), b"selected source");
    let out = compat_command()
        .args(["-a", "--delete"])
        .args([t.s("external/"), t.s("backup/import/file"), t.s("backup/")])
        .run()
        .unwrap();
    assert!(!out.status.success());
    assert!(stderr_of(&out).contains("contains source"), "{out:?}");
    assert_eq!(read(&t.path("backup/import/file")), b"selected source");
    assert!(!t.path("backup/other").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn prune_rechecks_names_after_destination_permissions_are_repaired() {
    let t = Tmp::new();
    write(&t.path("src/Report.txt"), b"keep these contents");
    write(&t.path("dst/extra"), b"remove this extra");
    fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o311)).unwrap();
    run_native_ok(&[
        "cp",
        "--prune",
        "--temporarily-widen-dir-permissions",
        "--srcs-in",
        &t.s("src"),
        "--into",
        &t.s("dst"),
    ]);
    assert_eq!(read(&t.path("dst/Report.txt")), b"keep these contents");
    assert!(!t.path("dst/extra").exists());
}

#[test]
fn copy_repairs_destination_directories_without_search_permission() {
    for directory in ["sub", "parent/sub"] {
        for mode in [0o600, 0o000] {
            for prune in [false, true] {
                let t = Tmp::new();
                let source = format!("src/{directory}/Report.txt");
                let destination = format!("dst/{directory}");
                write(&t.path(&source), b"copied contents");
                write(&t.path(&format!("{destination}/extra")), b"extra contents");
                fs::set_permissions(t.path(&destination), fs::Permissions::from_mode(mode))
                    .unwrap();
                let src = t.s("src");
                let dst = t.s("dst");
                let mut args = vec![
                    "cp",
                    "--temporarily-widen-dir-permissions",
                    "--srcs-in",
                    &src,
                    "--into",
                    &dst,
                ];
                if prune {
                    args.push("--prune");
                }
                let out = native_syq(&args);
                // The temporary repair must restore the existing mode when
                // permissions are not being copied from the source.
                let after = fs::metadata(t.path(&destination)).unwrap().mode() & 0o777;
                fs::set_permissions(t.path(&destination), fs::Permissions::from_mode(0o755))
                    .unwrap();
                assert_eq!(after, mode);
                if cfg!(target_os = "macos") && mode == 0 {
                    // Darwin's O_EVTONLY metadata handles still need read
                    // access. This is the pre-existing repair limitation;
                    // failure must leave both existing and source data alone.
                    assert!(!out.status.success(), "{out:?}");
                    assert!(stderr_of(&out).contains("Permission denied"), "{out:?}");
                    assert!(!t.path(&format!("{destination}/Report.txt")).exists());
                    assert_eq!(
                        read(&t.path(&format!("{destination}/extra"))),
                        b"extra contents"
                    );
                    assert_eq!(read(&t.path(&source)), b"copied contents");
                    continue;
                }
                assert_output_ok(&out);
                assert_eq!(
                    read(&t.path(&format!("{destination}/Report.txt"))),
                    b"copied contents"
                );
                assert_eq!(t.path(&format!("{destination}/extra")).exists(), !prune);
            }
        }
    }
}

/// A preview never widens: an owned directory it cannot search is reported
/// as not inspected instead of claiming its contents are missing.
#[test]
fn dry_run_leaves_unsearchable_destination_permissions_unchanged() {
    let root = unsafe { libc::geteuid() } == 0;
    for mode in [0o600, 0o000] {
        let t = Tmp::new();
        write(&t.path("src/sub/file"), b"new contents");
        write(&t.path("dst/sub/file"), b"old contents");
        fs::set_permissions(t.path("dst/sub"), fs::Permissions::from_mode(mode)).unwrap();
        let before = fs::metadata(t.path("dst/sub")).unwrap();
        let out = native_syq(&[
            "cp",
            "--dry-run",
            "-v",
            "--srcs-in",
            &t.s("src"),
            "--into",
            &t.s("dst"),
        ]);
        let after = fs::metadata(t.path("dst/sub")).unwrap();
        fs::set_permissions(t.path("dst/sub"), fs::Permissions::from_mode(0o755)).unwrap();
        if root {
            assert_output_ok(&out);
        } else {
            assert_eq!(out.status.code(), Some(23), "{out:?}");
            let stderr = stderr_of(&out);
            assert!(stderr.contains("sub: not inspected"), "{out:?}");
            assert!(
                stderr.contains("--temporarily-widen-dir-permissions"),
                "{out:?}"
            );
            assert!(
                !String::from_utf8_lossy(&out.stdout).contains("sub/file"),
                "{out:?}"
            );
        }
        assert_eq!(after.mode(), before.mode());
        assert_eq!(
            (after.ctime(), after.ctime_nsec()),
            (before.ctime(), before.ctime_nsec()),
            "dry-run filename inspection changed destination permissions"
        );
        assert_eq!(read(&t.path("dst/sub/file")), b"old contents");
    }
}

#[test]
fn directory_type_conflicts_preserve_destination_and_prevent_prune() {
    for native in [false, true] {
        for dry_run in [false, true] {
            for (source_dir, destination_kind) in [
                (true, "file"),
                (true, "symlink"),
                (false, "empty_directory"),
                (false, "unreadable_directory"),
                (false, "nonempty_directory"),
            ] {
                for source_link in [false, true] {
                    if source_dir && source_link {
                        continue;
                    }
                    let t = Tmp::new();
                    fs::create_dir(t.path("src")).unwrap();
                    if source_dir {
                        write(&t.path("src/item/sub/file"), b"source contents");
                        fs::set_permissions(t.path("src/item"), fs::Permissions::from_mode(0o555))
                            .unwrap();
                    } else if source_link {
                        std::os::unix::fs::symlink("source-target", t.path("src/item")).unwrap();
                    } else {
                        write(&t.path("src/item"), b"source contents");
                    }
                    write(&t.path("dst/extra"), b"keep after failure");
                    write(&t.path("outside/sub/file"), b"outside contents");
                    match destination_kind {
                        "file" => write(&t.path("dst/item"), b"old contents"),
                        "symlink" => {
                            std::os::unix::fs::symlink(t.path("outside"), t.path("dst/item"))
                                .unwrap()
                        }
                        _ => fs::create_dir(t.path("dst/item")).unwrap(),
                    }
                    if destination_kind == "unreadable_directory" {
                        fs::set_permissions(t.path("dst/item"), fs::Permissions::from_mode(0o0))
                            .unwrap();
                    } else if destination_kind == "nonempty_directory" {
                        write(&t.path("dst/item/child"), b"keep child");
                    }
                    let before = fs::symlink_metadata(t.path("dst/item")).unwrap();
                    let out = if native {
                        let mut args =
                            vec!["cp", "--prune", "--copy-metadata=permissions", "--srcs-in"];
                        let src = t.s("src");
                        let dst = t.s("dst");
                        args.extend([&src, "--into", &dst]);
                        if dry_run {
                            args.push("--dry-run");
                        }
                        native_syq(&args)
                    } else {
                        syq(&[
                            if dry_run { "-an" } else { "-a" },
                            "--delete",
                            &t.s("src/"),
                            &t.s("dst/"),
                        ])
                    };
                    let after = fs::symlink_metadata(t.path("dst/item")).unwrap();
                    if destination_kind == "unreadable_directory" {
                        fs::set_permissions(t.path("dst/item"), fs::Permissions::from_mode(0o700))
                            .unwrap();
                    }
                    assert_eq!(out.status.code(), Some(23), "native={native}, dry={dry_run}, source_link={source_link}, dst={destination_kind}: {out:?}");
                    let stderr = stderr_of(&out);
                    assert!(stderr.contains("cannot replace"), "{stderr}");
                    assert!(!stderr.contains("Permission denied"), "{stderr}");
                    assert_eq!((before.ino(), before.mode()), (after.ino(), after.mode()));
                    assert_eq!(read(&t.path("dst/extra")), b"keep after failure");
                    assert_eq!(read(&t.path("outside/sub/file")), b"outside contents");
                    if destination_kind == "file" {
                        assert_eq!(read(&t.path("dst/item")), b"old contents");
                    } else if destination_kind == "nonempty_directory" {
                        assert_eq!(read(&t.path("dst/item/child")), b"keep child");
                    }
                }
            }
        }
    }
}

#[test]
fn prune_named_directory_inside_source_ancestor_is_safe() {
    let t = Tmp::new();
    write(&t.path("b/2024/photos/file"), b"source contents");
    write(&t.path("b/photos/extra"), b"remove this extra");
    write(&t.path("b/unrelated"), b"keep sibling");
    run_native_ok(&["cp", "--prune", &t.s("b/2024/photos"), "--into", &t.s("b")]);
    assert_eq!(read(&t.path("b/photos/file")), b"source contents");
    assert_eq!(read(&t.path("b/2024/photos/file")), b"source contents");
    assert_eq!(read(&t.path("b/unrelated")), b"keep sibling");
    assert!(!t.path("b/photos/extra").exists());
}

#[test]
fn prune_named_directory_cannot_remove_another_selected_source() {
    let t = Tmp::new();
    write(&t.path("external/photos/file"), b"external source");
    write(&t.path("b/photos/import/selected"), b"selected source");
    let out = native_syq(&[
        "cp",
        "--prune",
        &t.s("external/photos"),
        &t.s("b/photos/import"),
        "--into",
        &t.s("b"),
    ]);
    assert!(!out.status.success(), "{out:?}");
    assert!(stderr_of(&out).contains("contains source"), "{out:?}");
    assert_eq!(
        read(&t.path("b/photos/import/selected")),
        b"selected source"
    );
    assert!(!t.path("b/photos/file").exists());
}

#[test]
fn prune_preserves_replacement_recovery_entries_and_their_contents() {
    let t = Tmp::new();
    write(&t.path("src/file"), b"current contents");
    write(&t.path("dst/nested/.syq-swap-123-1"), b"old file");
    write(
        &t.path("dst/nested/.syq-swap-123-2/child/file"),
        b"old directory contents",
    );
    std::os::unix::fs::symlink("old-target", t.path("dst/.syq-swap-123-3")).unwrap();
    write(&t.path("dst/extra"), b"remove extra");
    write(&t.path("dst/.syq-swap-not-a-recovery"), b"ordinary extra");
    run_native_ok(&[
        "cp",
        "--prune",
        "--srcs-in",
        &t.s("src"),
        "--into",
        &t.s("dst"),
    ]);
    assert_eq!(read(&t.path("dst/nested/.syq-swap-123-1")), b"old file");
    assert_eq!(
        read(&t.path("dst/nested/.syq-swap-123-2/child/file")),
        b"old directory contents"
    );
    assert_eq!(
        fs::read_link(t.path("dst/.syq-swap-123-3")).unwrap(),
        Path::new("old-target")
    );
    assert!(!t.path("dst/extra").exists());
    assert!(!t.path("dst/.syq-swap-not-a-recovery").exists());
}

#[test]
fn resume_accepts_pre_path_hash_partial_filename() {
    let t = Tmp::new();
    let data = prng(4 * 1024 * 1024, 327);
    write(&t.path("src/file"), &data);
    // Unchanged master 8618cf3 filename for basename "file" and copy ID [7; 16].
    // Kept literal so this test never regenerates the old writer's format.
    let partial = t.path("dst/.file.syq-tmp.hduynbiimayar6tk");
    write(&partial, &data);
    fs::set_permissions(&partial, fs::Permissions::from_mode(0o600)).unwrap();
    run_native_ok(&[
        "cp",
        "--results",
        &t.s("results"),
        "--performance-tuning=copy-path=ranges",
        "--srcs-in",
        &t.s("src"),
        "--into",
        &t.s("dst"),
    ]);
    assert_eq!(read(&t.path("dst/file")), data);
    assert_eq!(read(&partial), data);
    let records = fs::read_to_string(t.path("results")).unwrap();
    let result: serde_json::Value = serde_json::from_str(records.lines().last().unwrap()).unwrap();
    assert_eq!(result["bytes_transferred"], 0);
    assert_eq!(result["bytes_unchanged"], data.len() as u64);
}

#[cfg(debug_assertions)]
#[test]
fn prune_ancestry_permission_error_names_source_and_explains_skipping() {
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipping permission denial: running as root");
        return;
    }
    let t = Tmp::new();
    write(&t.path("ancestor/src/file"), b"source contents");
    write(&t.path("dst/extra"), b"keep");
    let ready = t.path("ready");
    let continuation = t.path("continue");
    let child = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "cp",
            "--prune",
            "--srcs-in",
            &t.s("ancestor/src"),
            "--into",
            &t.s("dst"),
        ])
        .env("SYQ_TEST_SOURCE_ROOTS_REGISTERED_FILE", &ready)
        .env("SYQ_TEST_SOURCE_ROOTS_CONTINUE_FILE", &continuation)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .start()
        .unwrap();
    wait_for(
        "source registration",
        std::time::Duration::from_secs(10),
        || ready.exists(),
    );
    fs::set_permissions(t.path("ancestor"), fs::Permissions::from_mode(0o000)).unwrap();
    fs::write(&continuation, b"continue").unwrap();
    let out = child.wait_with_output().unwrap();
    fs::set_permissions(t.path("ancestor"), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(!out.status.success());
    let stderr = stderr_of(&out);
    assert!(stderr.contains(&t.s("ancestor/src")), "{stderr}");
    assert!(
        stderr.contains("source ancestry could not be checked; skipping deletions"),
        "{stderr}"
    );
    assert!(!stderr.contains("copy reported errors"), "{stderr}");
    assert_eq!(read(&t.path("dst/file")), b"source contents");
    assert_eq!(read(&t.path("dst/extra")), b"keep");
}

#[cfg(debug_assertions)]
#[test]
fn prune_before_removes_extras_before_a_copy_failure() {
    for before in [false, true] {
        let t = Tmp::new();
        write(&t.path("src/file"), &vec![b'n'; 128 << 10]);
        write(&t.path("dst/file"), b"previous complete file");
        write(&t.path("dst/extra"), b"extra");
        let out = Command::new(env!("CARGO_BIN_EXE_syq"))
            .args([
                "cp",
                if before { "--prune-before" } else { "--prune" },
                "--performance-tuning=copy-path=ranges",
                "--srcs-in",
                &t.s("src"),
                "--into",
                &t.s("dst"),
            ])
            .env("SYQ_TEST_FAIL_READ_RANGE", "1")
            .run()
            .unwrap();
        assert!(!out.status.success(), "{out:?}");
        assert_eq!(t.path("dst/extra").exists(), !before, "{out:?}");
        assert_eq!(read(&t.path("dst/file")), b"previous complete file");
    }
}

#[test]
fn prune_before_honors_preview_limits_and_protected_paths() {
    for extra in [vec![], vec!["--dry-run"], vec!["--max-delete", "0"]] {
        let t = Tmp::new();
        write(&t.path("src/new"), b"new");
        write(&t.path("dst/extra/old"), b"old");
        write(&t.path("dst/ignored/keep"), b"keep");
        let mut args = vec!["cp", "--prune-before", "--ignore=ignored", "--srcs-in"];
        let src = t.s("src");
        let dst = t.s("dst");
        args.extend([src.as_str(), "--into", dst.as_str()]);
        args.extend(extra.clone());
        let out = native_syq(&args);
        assert_eq!(
            out.status.code(),
            Some(if extra.contains(&"--max-delete") {
                25
            } else {
                0
            }),
            "{out:?}"
        );
        assert_eq!(
            t.path("dst/extra/old").exists(),
            !extra.is_empty(),
            "{out:?}"
        );
        assert_eq!(read(&t.path("dst/ignored/keep")), b"keep");
        assert_eq!(t.path("dst/new").exists(), !extra.contains(&"--dry-run"));
    }
}

#[test]
fn prune_before_preserves_extras_when_source_selection_fails() {
    let t = Tmp::new();
    write(&t.path("a/same"), b"one");
    write(&t.path("b/same"), b"two");
    write(&t.path("dst/extra"), b"keep");
    for source in [t.s("missing"), t.s("b/same")] {
        let out = native_syq(&[
            "cp",
            "--prune-before",
            &t.s("a/same"),
            &source,
            "--into",
            &t.s("dst"),
        ]);
        assert!(!out.status.success(), "{out:?}");
        assert_eq!(read(&t.path("dst/extra")), b"keep");
    }
}

#[test]
fn native_copy_leaves_existing_directory_permissions_alone_by_default() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    for pruning in [None, Some("--prune"), Some("--prune-before")] {
        let t = Tmp::new();
        write(&t.path("src/new"), &vec![b'n'; 128 << 10]);
        write(&t.path("dst/extra"), b"keep");
        fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o500)).unwrap();
        let src = t.s("src");
        let dst = t.s("dst");
        let mut args = vec![
            "cp",
            "--performance-tuning=copy-path=ranges",
            "--srcs-in",
            &src,
            "--into",
            &dst,
        ];
        args.extend(pruning);
        let out = native_syq(&args);
        assert!(!out.status.success(), "{out:?}");
        assert_eq!(fs::metadata(t.path("dst")).unwrap().mode() & 0o777, 0o500);
        assert_eq!(read(&t.path("dst/extra")), b"keep");
        assert!(!t.path("dst/new").exists());
        assert!(
            stderr_of(&out).contains("--temporarily-widen-dir-permissions"),
            "{out:?}"
        );
    }
}

#[test]
fn temporary_directory_permissions_restore_nested_parents_after_copy_and_prune() {
    for pruning in [None, Some("--prune"), Some("--prune-before")] {
        let t = Tmp::new();
        write(&t.path("src/p/q/new"), b"new");
        write(&t.path("dst/p/q/extra"), b"extra");
        for name in ["dst/p/q", "dst/p"] {
            fs::set_permissions(t.path(name), fs::Permissions::from_mode(0o500)).unwrap();
        }
        let src = t.s("src");
        let dst = t.s("dst");
        let mut args = vec![
            "cp",
            "--temporarily-widen-dir-permissions",
            "--srcs-in",
            &src,
            "--into",
            &dst,
        ];
        args.extend(pruning);
        let out = native_syq(&args);
        assert!(out.status.success(), "{out:?}");
        assert_eq!(read(&t.path("dst/p/q/new")), b"new");
        assert_eq!(t.path("dst/p/q/extra").exists(), pruning.is_none());
        for name in ["dst/p", "dst/p/q"] {
            assert_eq!(fs::metadata(t.path(name)).unwrap().mode() & 0o777, 0o500);
        }
    }
}

#[cfg(debug_assertions)]
#[test]
fn copy_does_not_restore_a_directory_it_never_widened() {
    for native in [false, true] {
        let t = Tmp::new();
        write(&t.path("src/new"), b"new");
        fs::create_dir(t.path("dst")).unwrap();
        fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o755)).unwrap();
        let ready = t.path("ready");
        let continuation = t.path("continue");
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_syq"));
        if native {
            cmd.args([
                "cp",
                "--temporarily-widen-dir-permissions",
                "--srcs-in",
                &t.s("src"),
                "--into",
                &t.s("dst"),
            ]);
        } else {
            cmd.args(["rsync", "-r", &format!("{}/", t.s("src")), &t.s("dst")]);
        }
        let child = cmd
            .env("SYQ_TEST_FINALIZATION_READY_FILE", &ready)
            .env("SYQ_TEST_FINALIZATION_CONTINUE_FILE", &continuation)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        wait_for(
            "copy finalization",
            std::time::Duration::from_secs(10),
            || ready.exists(),
        );
        fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(&continuation, b"continue").unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success(), "{out:?}");
        assert_eq!(fs::metadata(t.path("dst")).unwrap().mode() & 0o777, 0o700);
    }
}

#[cfg(debug_assertions)]
#[test]
fn temporary_directory_permissions_restore_after_copy_failure() {
    let t = Tmp::new();
    write(&t.path("src/new"), &vec![b'n'; 128 << 10]);
    fs::create_dir(t.path("dst")).unwrap();
    fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o500)).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "cp",
            "--temporarily-widen-dir-permissions",
            "--performance-tuning=copy-path=ranges",
            "--srcs-in",
            &t.s("src"),
            "--into",
            &t.s("dst"),
        ])
        .env("SYQ_TEST_FAIL_READ_RANGE", "1")
        .run()
        .unwrap();
    assert!(!out.status.success(), "{out:?}");
    assert!(
        stderr_of(&out).contains("test read-range failure"),
        "{out:?}"
    );
    assert_eq!(fs::metadata(t.path("dst")).unwrap().mode() & 0o777, 0o500);
}

/// The option widens the destination directory a file is copied into, but
/// never the parent of an exact placement: that directory lies outside the
/// copy, so the copy fails and the parent keeps its mode and change time.
#[test]
fn explicit_directory_access_covers_file_destination_containers() {
    let root = unsafe { libc::geteuid() } == 0;
    let modes: &[u32] = if cfg!(target_os = "macos") {
        &[0o500, 0o600]
    } else {
        &[0o000, 0o200, 0o400, 0o500, 0o600]
    };
    for &mode in modes {
        for placement in ["--into", "--as"] {
            for size in [3, 128 << 10] {
                let t = Tmp::new();
                let data = vec![b'n'; size];
                write(&t.path("src/file"), &data);
                fs::create_dir(t.path("dst")).unwrap();
                fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(mode)).unwrap();
                let before = fs::metadata(t.path("dst")).unwrap();
                let destination = if placement == "--into" {
                    "dst"
                } else {
                    "dst/file"
                };
                let out = native_syq(&[
                    "cp",
                    "--temporarily-widen-dir-permissions",
                    &t.s("src/file"),
                    placement,
                    &t.s(destination),
                ]);
                let after = fs::metadata(t.path("dst")).unwrap();
                fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o700)).unwrap();
                let case = format!("mode {mode:o}, {placement}, size {size}");
                assert_eq!(after.mode() & 0o777, mode, "{case}");
                if placement == "--into" || root {
                    assert!(out.status.success(), "{case}: {out:?}");
                    assert_eq!(read(&t.path("dst/file")), data);
                } else {
                    assert!(!out.status.success(), "{case}: {out:?}");
                    assert!(stderr_of(&out).contains("Permission denied"), "{out:?}");
                    assert_eq!(
                        (after.ctime(), after.ctime_nsec()),
                        (before.ctime(), before.ctime_nsec()),
                        "{case}"
                    );
                    assert!(!t.path("dst/file").exists(), "{case}");
                }
            }
        }
    }
}

#[test]
fn directory_access_does_not_widen_ancestors_of_a_destination_container() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    for interface in ["cp", "rsync"] {
        for dry_run in [false, true] {
            let t = Tmp::new();
            write(&t.path("src/file"), b"new contents");
            write(&t.path("parent/dst/sentinel"), b"keep contents");
            fs::set_permissions(t.path("parent"), fs::Permissions::from_mode(0o600)).unwrap();
            let before = fs::metadata(t.path("parent")).unwrap();
            let src = t.s("src/file");
            let dst = t.s("parent/dst/");
            let mut args = vec![interface];
            if interface == "cp" {
                args.extend(["--temporarily-widen-dir-permissions", &src, "--into", &dst]);
            } else {
                args.extend([src.as_str(), dst.as_str()]);
            }
            if dry_run {
                args.push("--dry-run");
            }
            let out = native_syq(&args);
            let after = fs::metadata(t.path("parent")).unwrap();
            fs::set_permissions(t.path("parent"), fs::Permissions::from_mode(0o700)).unwrap();
            assert!(!out.status.success(), "{interface}, dry={dry_run}: {out:?}");
            assert!(stderr_of(&out).contains("Permission denied"), "{out:?}");
            assert_eq!(after.mode() & 0o777, 0o600);
            assert_eq!(
                (after.ctime(), after.ctime_nsec()),
                (before.ctime(), before.ctime_nsec()),
                "{interface}, dry={dry_run}: the ancestor must not be chmodded"
            );
            assert_eq!(read(&t.path("parent/dst/sentinel")), b"keep contents");
            assert!(!t.path("parent/dst/file").exists());
        }
    }
}

#[test]
fn readonly_container_allows_inplace_updates_without_widening() {
    let t = Tmp::new();
    write(&t.path("src/file"), b"updated contents");
    write(&t.path("dst/file"), b"old");
    fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o100)).unwrap();
    let out = native_syq(&[
        "cp",
        "--inplace",
        &t.s("src/file"),
        "--as",
        &t.s("dst/file"),
    ]);
    let mode = fs::metadata(t.path("dst")).unwrap().mode() & 0o777;
    fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(out.status.success(), "{out:?}");
    assert_eq!(mode, 0o100);
    assert_eq!(read(&t.path("dst/file")), b"updated contents");
}

#[test]
fn rsync_permission_failures_do_not_suggest_a_native_only_option() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let t = Tmp::new();
    write(&t.path("src/file"), &vec![b'n'; 128 << 10]);
    fs::create_dir(t.path("dst")).unwrap();
    fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o500)).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["rsync", &t.s("src/file"), &t.s("dst/")])
        .run()
        .unwrap();
    fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(!out.status.success(), "{out:?}");
    assert!(
        !stderr_of(&out).contains("--temporarily-widen-dir-permissions"),
        "{out:?}"
    );
}

/// In-place lengths of interest beside a new length that is not a multiple
/// of any block: longer, equal and shorter old files.
#[cfg(all(debug_assertions, target_os = "linux"))]
const INPLACE_NEW_LEN: usize = (3 << 20) + 123;
#[cfg(all(debug_assertions, target_os = "linux"))]
const INPLACE_OLD_LENS: [usize; 3] = [5 << 20, INPLACE_NEW_LEN, 1 << 20];

#[cfg(all(debug_assertions, target_os = "linux"))]
#[test]
fn inplace_local_copy_failure_keeps_old_data_within_the_new_length() {
    for old_len in INPLACE_OLD_LENS {
        // The kernel copy is refused, and then whatever replaces it fails:
        // the range writes, or the userspace copy after its first write.
        for userspace in [false, true] {
            let t = Tmp::new();
            let new = prng(INPLACE_NEW_LEN, 71);
            let old = prng(old_len, 72);
            write(&t.path("src/file"), &new);
            // A distinct time, so that an equally long file is copied.
            set_mtime(&t.path("src/file"), 1_700_000_000);
            write(&t.path("dst/file"), &old);
            let inode = fs::metadata(t.path("dst/file")).unwrap().ino();
            let mut command = compat_command();
            command
                .args(["-a", "--inplace", "--no-progress"])
                .args([t.s("src/"), t.s("dst/")])
                .env("SYQ_TEST_COPY_LOCAL_EXDEV", "1");
            if userspace {
                // A second file lets a refused kernel copy fall back to
                // the userspace copy rather than to ranges.
                write(&t.path("src/small"), b"another file");
                command
                    .env("SYQ_TEST_COPY_LOCAL_FS", "local")
                    .env("SYQ_TEST_FAIL_COPY_LOCAL_AFTER_WRITE", "1");
            } else {
                command
                    .env("SYQ_TEST_COPY_LOCAL_FS", "unsupported")
                    .env("SYQ_TEST_FAIL_WRITE_RANGE_NAME", "file");
            }
            let out = command.run().unwrap();
            let context = format!("old {old_len}, userspace {userspace}");
            assert!(!out.status.success(), "{context}: {}", stderr_of(&out));
            assert_eq!(fs::metadata(t.path("dst/file")).unwrap().ino(), inode);
            // Old bytes within the new length survive until new data
            // replaces them; only bytes past the new end may go early.
            let after = read(&t.path("dst/file"));
            let kept = old_len.min(INPLACE_NEW_LEN);
            let written = if userspace { (1 << 20).min(kept) } else { 0 };
            assert!(after.len() >= kept, "{context}: {} bytes left", after.len());
            assert!(after[..written] == new[..written], "{context}");
            assert!(
                after[written..kept] == old[written..kept],
                "{context}: old data within the new length was lost"
            );
            assert!(partial_files(&t.0).is_empty(), "{context}");
        }
    }
}

#[cfg(all(debug_assertions, target_os = "linux"))]
#[test]
fn inplace_local_copies_end_at_the_new_length() {
    // The kernel copy, a clone where this filesystem has one, the userspace
    // copy and the range copy each write over the old file.
    let paths: [(&str, &[(&str, &str)]); 4] = [
        ("kernel", &[]),
        ("clone", &[("SYQ_TEST_COPY_LOCAL_FS", "local")]),
        (
            "userspace",
            &[
                ("SYQ_TEST_COPY_LOCAL_FS", "local"),
                ("SYQ_TEST_COPY_LOCAL_EXDEV", "1"),
            ],
        ),
        (
            "ranges",
            &[
                ("SYQ_TEST_COPY_LOCAL_FS", "unsupported"),
                ("SYQ_TEST_COPY_LOCAL_EXDEV", "1"),
            ],
        ),
    ];
    for (path, environment) in paths {
        for old_len in INPLACE_OLD_LENS.into_iter().chain([0]) {
            let t = Tmp::new();
            let new = prng(INPLACE_NEW_LEN, 73);
            write(&t.path("src/file"), &new);
            write(&t.path("src/small"), b"another file");
            set_mtime(&t.path("src/file"), 1_700_000_000);
            write(&t.path("dst/file"), &prng(old_len, 74));
            let inode = fs::metadata(t.path("dst/file")).unwrap().ino();
            let out = compat_command()
                .args(["-a", "--inplace", "--no-progress"])
                .args([t.s("src/"), t.s("dst/")])
                .envs(environment.iter().copied())
                .run()
                .unwrap();
            assert_output_ok(&out);
            let context = format!("{path}, old {old_len}");
            assert!(read(&t.path("dst/file")) == new, "{context}");
            let metadata = fs::metadata(t.path("dst/file")).unwrap();
            assert_eq!(metadata.ino(), inode, "{context}");
            assert_eq!(metadata.mtime(), 1_700_000_000, "{context}");
            assert!(partial_files(&t.0).is_empty(), "{context}");
        }
    }
}

/// Whether this filesystem clones a file with an unaligned length over the
/// start of an equally long one, as an in-place clone of a shrinking file
/// does once the file is cut to its new length.
#[cfg(all(debug_assertions, target_os = "linux"))]
fn clones_unaligned_files(directory: &Path) -> bool {
    use std::os::fd::AsRawFd;
    write(&directory.join("probe-source"), &prng(1_000_000, 1));
    write(&directory.join("probe-destination"), &prng(1_000_000, 2));
    let source = File::open(directory.join("probe-source")).unwrap();
    let destination = OpenOptions::new()
        .write(true)
        .open(directory.join("probe-destination"))
        .unwrap();
    let range = libc::file_clone_range {
        src_fd: source.as_raw_fd().into(),
        src_offset: 0,
        src_length: 1_000_000,
        dest_offset: 0,
    };
    let cloned = unsafe { libc::ioctl(destination.as_raw_fd(), libc::FICLONERANGE, &range) } == 0;
    fs::remove_file(directory.join("probe-source")).unwrap();
    fs::remove_file(directory.join("probe-destination")).unwrap();
    cloned
}

#[cfg(all(debug_assertions, target_os = "linux"))]
#[test]
fn inplace_clone_of_a_shrinking_unaligned_file_still_clones() {
    let t = Tmp::new();
    fs::create_dir_all(t.path("dst")).unwrap();
    if !clones_unaligned_files(&t.path("dst")) {
        return;
    }
    // A clone of an unaligned length cannot end inside a longer file, so
    // the file is cut to its new length before the clone.
    let new = prng(1_000_000, 75);
    write(&t.path("src/file"), &new);
    write(&t.path("dst/file"), &prng(2_000_000, 76));
    let inode = fs::metadata(t.path("dst/file")).unwrap().ino();
    let out = compat_command()
        .args(["-a", "--inplace", "--no-progress"])
        .args([t.s("src/file"), t.s("dst/file")])
        .env("SYQ_TEST_COPY_LOCAL_FS", "local")
        .env("SYQ_TEST_COPY_LOCAL_CLONES", t.path("clones"))
        .run()
        .unwrap();
    assert_output_ok(&out);
    assert!(read(&t.path("dst/file")) == new);
    assert_eq!(fs::metadata(t.path("dst/file")).unwrap().ino(), inode);
    assert_eq!(
        fs::read_to_string(t.path("clones")).unwrap(),
        "clone 1000000\n"
    );
}

#[cfg(debug_assertions)]
#[test]
fn inplace_small_files_write_before_cutting_and_keep_old_data_on_failure() {
    for fail in [false, true] {
        for old_len in [60_000, 20_000, 0] {
            let t = Tmp::new();
            let new = prng(20_000, 77);
            let old = prng(old_len, 78);
            write(&t.path("src/file"), &new);
            set_mtime(&t.path("src/file"), 1_700_000_000);
            write(&t.path("dst/file"), &old);
            let inode = fs::metadata(t.path("dst/file")).unwrap().ino();
            let mut command = compat_command();
            command
                .args(["-a", "--inplace", "--no-progress"])
                .args([t.s("src/"), t.s("dst/")]);
            if fail {
                command.env("SYQ_TEST_FAIL_INPLACE_PUT", "1");
            }
            let out = command.run().unwrap();
            let context = format!("old {old_len}, fail {fail}");
            assert_eq!(
                out.status.success(),
                !fail,
                "{context}: {}",
                stderr_of(&out)
            );
            let expected = if fail { &old } else { &new };
            assert!(read(&t.path("dst/file")) == *expected, "{context}");
            assert_eq!(fs::metadata(t.path("dst/file")).unwrap().ino(), inode);
            assert!(partial_files(&t.0).is_empty(), "{context}");
        }
    }
}

/// A tree's own destination root is part of the copy: with the option, a live
/// copy can enter, fill and prune an owned root without search permission and
/// restores its mode, unless copied permissions take precedence.
#[test]
fn explicit_directory_access_covers_tree_roots() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    for placement in ["contents", "as", "into"] {
        for pruning in [None, Some("--prune"), Some("--prune-before")] {
            let t = Tmp::new();
            write(&t.path("src/sub/file"), b"new contents");
            write(&t.path("src/existing"), b"changed contents");
            let copied = if placement == "into" {
                "dst/src"
            } else {
                "dst"
            };
            write(&t.path(&format!("{copied}/extra")), b"extra");
            write(&t.path(&format!("{copied}/existing")), b"old");
            fs::set_permissions(
                t.path(&format!("{copied}/existing")),
                fs::Permissions::from_mode(0o400),
            )
            .unwrap();
            fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o600)).unwrap();
            let src = t.s("src");
            let dst = t.s("dst");
            let mut args = vec![
                "cp",
                "--temporarily-widen-dir-permissions",
                "--copy-metadata=permissions",
            ];
            match placement {
                "contents" => args.extend(["--srcs-in", &src, "--into", &dst]),
                "as" => args.extend([&src, "--as", &dst]),
                _ => args.extend([&src, "--into", &dst]),
            }
            args.extend(pruning);
            let out = native_syq(&args);
            let mode = fs::metadata(t.path("dst")).unwrap().mode() & 0o777;
            fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o700)).unwrap();
            assert_output_ok(&out);
            if placement == "into" {
                assert_eq!(mode, 0o600, "{placement}, {pruning:?}");
            }
            assert_eq!(
                read(&t.path(&format!("{copied}/sub/file"))),
                b"new contents"
            );
            assert_eq!(
                t.path(&format!("{copied}/extra")).exists(),
                pruning.is_none()
            );
            assert_eq!(
                read(&t.path(&format!("{copied}/existing"))),
                b"changed contents"
            );
        }
    }
}

/// --if-exists=keep honors the option: it adds new entries to a read-only
/// directory, keeps existing files and restores the mode.
#[test]
fn keep_existing_policy_honors_temporary_directory_access() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    for widen in [false, true] {
        let t = Tmp::new();
        write(&t.path("src/sub/new"), b"new contents");
        write(&t.path("src/sub/kept"), b"source contents");
        write(&t.path("dst/sub/kept"), b"destination contents");
        fs::set_permissions(t.path("dst/sub"), fs::Permissions::from_mode(0o500)).unwrap();
        let src = t.s("src");
        let dst = t.s("dst");
        let mut args = vec!["cp", "--if-exists=keep", "--srcs-in", &src, "--into", &dst];
        if widen {
            args.push("--temporarily-widen-dir-permissions");
        }
        let out = native_syq(&args);
        let mode = fs::metadata(t.path("dst/sub")).unwrap().mode() & 0o777;
        fs::set_permissions(t.path("dst/sub"), fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(mode, 0o500, "widen={widen}");
        assert_eq!(read(&t.path("dst/sub/kept")), b"destination contents");
        if widen {
            assert_output_ok(&out);
            assert_eq!(read(&t.path("dst/sub/new")), b"new contents");
        } else {
            assert_eq!(out.status.code(), Some(23), "{out:?}");
            assert!(
                stderr_of(&out).contains("--temporarily-widen-dir-permissions"),
                "{out:?}"
            );
            assert!(!t.path("dst/sub/new").exists());
        }
    }
}

#[test]
fn ancestry_rejection_restores_search_permission() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    for dry_run in [false, true] {
        for widen in [false, true] {
            let t = Tmp::new();
            write(&t.path("src/file"), b"source contents");
            write(&t.path("src/dst/keep"), b"existing contents");
            fs::set_permissions(t.path("src/dst"), fs::Permissions::from_mode(0o600)).unwrap();
            let before = fs::metadata(t.path("src/dst")).unwrap();
            let src = t.s("src");
            let dst = t.s("src/dst");
            let mut args = vec!["cp", "--srcs-in", &src, "--into", &dst];
            if dry_run {
                args.push("--dry-run");
            }
            if widen {
                args.push("--temporarily-widen-dir-permissions");
            }
            let out = native_syq(&args);
            let after = fs::metadata(t.path("src/dst")).unwrap();
            fs::set_permissions(t.path("src/dst"), fs::Permissions::from_mode(0o700)).unwrap();
            assert!(!out.status.success(), "{out:?}");
            assert_eq!(after.mode() & 0o777, 0o600);
            if widen && !dry_run {
                assert!(stderr_of(&out).contains("maps inside source"), "{out:?}");
            } else {
                assert_eq!(
                    (before.ctime(), before.ctime_nsec()),
                    (after.ctime(), after.ctime_nsec())
                );
            }
            assert_eq!(read(&t.path("src/dst/keep")), b"existing contents");
            assert!(!t.path("src/dst/file").exists());
        }
    }
}

#[test]
fn destination_widening_does_not_change_source_permissions() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    for dry_run in [false, true] {
        let t = Tmp::new();
        write(&t.path("src/file"), b"source contents");
        fs::create_dir(t.path("dst")).unwrap();
        fs::set_permissions(t.path("src"), fs::Permissions::from_mode(0o600)).unwrap();
        let before = fs::metadata(t.path("src")).unwrap();
        let src = t.s("src");
        let dst = t.s("dst");
        let mut args = vec![
            "cp",
            "--temporarily-widen-dir-permissions",
            "--srcs-in",
            &src,
            "--into",
            &dst,
        ];
        if dry_run {
            args.push("--dry-run");
        }
        let out = native_syq(&args);
        let after = fs::metadata(t.path("src")).unwrap();
        fs::set_permissions(t.path("src"), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(!out.status.success(), "{out:?}");
        assert_eq!(after.mode(), before.mode());
        assert_eq!(
            (after.ctime(), after.ctime_nsec()),
            (before.ctime(), before.ctime_nsec())
        );
        assert!(!t.path("dst/file").exists());
    }
}

#[test]
fn dry_run_compares_requested_modes_with_original_directory_permissions() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    for source_mode in [0o500, 0o700] {
        let t = Tmp::new();
        fs::create_dir(t.path("src")).unwrap();
        fs::create_dir(t.path("dst")).unwrap();
        for (path, mode) in [("src", source_mode), ("dst", 0o500)] {
            timestamp(&t.path(path), 1_700_000_000, 0);
            fs::set_permissions(t.path(path), fs::Permissions::from_mode(mode)).unwrap();
        }
        let out = Command::new(env!("CARGO_BIN_EXE_syq"))
            .args([
                "cp",
                &t.s("src"),
                "--as",
                &t.s("dst"),
                "--dry-run",
                "-v",
                "--temporarily-widen-dir-permissions",
                "--copy-metadata=permissions",
            ])
            .run()
            .unwrap();
        assert_output_ok(&out);
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).contains("requested directory metadata differs"),
            source_mode != 0o500,
            "{out:?}"
        );
        assert_eq!(fs::metadata(t.path("dst")).unwrap().mode() & 0o777, 0o500);
        fs::set_permissions(t.path("src"), fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o700)).unwrap();
    }
}

/// Dry runs never change permissions, native or rsync, with or without the
/// option: every mode and change time stays as it was, whatever the preview
/// could or could not inspect.
#[test]
fn dry_runs_never_change_directory_permissions() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    for restricted in ["dst", "dst/sub"] {
        for mode in [0o000, 0o100, 0o300, 0o400, 0o500, 0o600] {
            for selection in [
                "single",
                "tree",
                "contents",
                "prune",
                "rsync",
                "rsync-prune",
                "files-from",
            ] {
                for widen in [false, true] {
                    if widen && (selection.starts_with("rsync") || selection == "files-from") {
                        continue;
                    }
                    let t = Tmp::new();
                    write(&t.path("src/sub/file"), b"new");
                    write(&t.path("dst/sub/file"), b"old");
                    write(&t.path("dst/sub/extra"), b"extra");
                    write(&t.path("manifest"), b"sub/file\n");
                    let path = t.path(restricted);
                    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
                    let before = fs::metadata(&path).unwrap();
                    let src = t.s("src");
                    let src_contents = format!("{}/", t.s("src"));
                    let dst = t.s("dst");
                    let manifest = t.s("manifest");
                    let source_file = t.s("src/sub/file");
                    let destination_file = t.s("dst/sub/file");
                    let mut args = vec!["cp", "--dry-run"];
                    if widen {
                        args.push("--temporarily-widen-dir-permissions");
                    }
                    match selection {
                        "single" => args.extend([&source_file, "--as", &destination_file]),
                        "tree" => args.extend([&src, "--as", &dst]),
                        "contents" => args.extend(["--srcs-in", &src, "--into", &dst]),
                        "prune" => args.extend(["--srcs-in", &src, "--into", &dst, "--prune"]),
                        "rsync" => args = vec!["rsync", "-rn", &src_contents, &dst],
                        "rsync-prune" => {
                            args = vec!["rsync", "-rn", "--delete", &src_contents, &dst]
                        }
                        _ => args = vec!["rsync", "-rn", "--files-from", &manifest, &src, &dst],
                    }
                    let output = native_syq(&args);
                    let after = fs::metadata(&path).unwrap();
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
                    let case =
                        format!("{restricted} {mode:o}, {selection}, widen={widen}: {output:?}");
                    assert_eq!(after.mode(), before.mode(), "{case}");
                    assert_eq!(
                        (after.ctime(), after.ctime_nsec()),
                        (before.ctime(), before.ctime_nsec()),
                        "{case}"
                    );
                    assert_eq!(read(&t.path("dst/sub/file")), b"old", "{case}");
                    assert_eq!(
                        listing(&t.path("dst")),
                        ["sub", "sub/extra", "sub/file"],
                        "{case}"
                    );
                }
            }
        }
    }
}

// Observed with upstream rsync 3.2.7 and 3.5.1 as a non-root owner.
#[test]
fn rsync_single_file_does_not_widen_its_destination_container() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    for mode in [0o100, 0o300, 0o500] {
        for dry_run in [false, true] {
            let t = Tmp::new();
            write(&t.path("src/file"), b"new contents");
            write(&t.path("dst/file"), b"old");
            fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(mode)).unwrap();
            let before = fs::metadata(t.path("dst")).unwrap();
            let src = t.s("src/file");
            let dst = t.s("dst/");
            let mut args = vec!["-a", &src, &dst];
            if dry_run {
                args.push("--dry-run");
            }
            let out = syq(&args);
            let after = fs::metadata(t.path("dst")).unwrap();
            fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o700)).unwrap();
            let writable = mode & 0o200 != 0;
            assert_eq!(
                out.status.code(),
                Some(if dry_run || writable { 0 } else { 23 }),
                "{mode:o}, dry={dry_run}: {out:?}"
            );
            assert_eq!(after.mode(), before.mode());
            if dry_run || !writable {
                assert_eq!(
                    (after.ctime(), after.ctime_nsec()),
                    (before.ctime(), before.ctime_nsec())
                );
            }
            assert_eq!(
                read(&t.path("dst/file")),
                if dry_run || !writable {
                    b"old".as_slice()
                } else {
                    b"new contents".as_slice()
                }
            );
        }
    }
}

#[test]
fn rsync_refuses_unsearchable_destination_roots_without_chmod() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    for selection in ["single", "contents", "files-from"] {
        for dry_run in [false, true] {
            let t = Tmp::new();
            write(&t.path("src/file"), b"new contents");
            write(&t.path("dst/file"), b"old");
            write(&t.path("list"), b"file\n");
            fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o600)).unwrap();
            let before = fs::metadata(t.path("dst")).unwrap();
            let src = t.s(if selection == "single" {
                "src/file"
            } else {
                "src/"
            });
            let dst = t.s("dst/");
            let list = t.s("list");
            let mut args = vec!["-a", &src, &dst];
            if selection == "files-from" {
                args.extend(["--files-from", &list]);
            }
            if dry_run {
                args.push("--dry-run");
            }
            let out = syq(&args);
            let after = fs::metadata(t.path("dst")).unwrap();
            fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o700)).unwrap();
            assert!(!out.status.success(), "{selection}, dry={dry_run}: {out:?}");
            assert!(stderr_of(&out).contains("Permission denied"), "{out:?}");
            assert_eq!(after.mode(), before.mode());
            assert_eq!(
                (after.ctime(), after.ctime_nsec()),
                (before.ctime(), before.ctime_nsec())
            );
            assert_eq!(read(&t.path("dst/file")), b"old");
        }
    }
}

#[test]
fn rsync_widens_copied_directories_but_never_during_previews() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    // Both releases widen implied --files-from parents. With a read-only
    // copied directory lacking search access, 3.5.1 also completes without
    // 3.2.7's late cleanup error. Follow the current release for that case.
    for selection in ["named", "files-from"] {
        for mode in [0o400, 0o500] {
            for preserve in [false, true] {
                for dry_run in [false, true] {
                    let t = Tmp::new();
                    write(&t.path("src/sub/file"), b"new contents");
                    write(&t.path("dst/sub/file"), b"old");
                    write(&t.path("list"), b"sub/file\n");
                    fs::set_permissions(t.path("src/sub"), fs::Permissions::from_mode(0o750))
                        .unwrap();
                    fs::set_permissions(t.path("dst/sub"), fs::Permissions::from_mode(mode))
                        .unwrap();
                    let before = fs::metadata(t.path("dst/sub")).unwrap();
                    let src = t.s(if selection == "named" {
                        "src/sub"
                    } else {
                        "src/"
                    });
                    let dst = t.s("dst/");
                    let list = t.s("list");
                    let mut args = vec![if preserve { "-a" } else { "-r" }, &src, &dst];
                    if selection == "files-from" {
                        args.extend(["--files-from", &list]);
                    }
                    if dry_run {
                        args.push("--dry-run");
                    }
                    let out = syq(&args);
                    let after = fs::metadata(t.path("dst/sub")).unwrap();
                    fs::set_permissions(t.path("dst/sub"), fs::Permissions::from_mode(0o700))
                        .unwrap();
                    assert_eq!(
                        out.status.success(),
                        !dry_run || mode & 0o100 != 0,
                        "{selection}, {mode:o}, preserve={preserve}, dry={dry_run}: {out:?}"
                    );
                    assert_eq!(
                        after.mode() & 0o777,
                        if preserve && !dry_run { 0o750 } else { mode }
                    );
                    if dry_run {
                        assert_eq!(
                            (after.ctime(), after.ctime_nsec()),
                            (before.ctime(), before.ctime_nsec())
                        );
                    }
                    assert_eq!(
                        read(&t.path("dst/sub/file")),
                        if dry_run {
                            b"old".as_slice()
                        } else {
                            b"new contents".as_slice()
                        }
                    );
                }
            }
        }
    }
}

/// With the option, pruning widens owned destination-only directories it
/// must enter or empty, and removes them; a directory it keeps gets its mode
/// back. syq rsync, like rsync, empties readable ones but does not enter
/// unreadable ones. Dry runs and blocked deletions change nothing for good.
#[test]
fn pruning_widens_destination_only_directories_it_must_enter_or_empty() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    // Darwin opens a directory to change its mode only with read access, so
    // there unreadable directories stay unlisted, as copies into them do.
    let unreadable = cfg!(target_os = "linux");
    let tree = |t: &Tmp, unreadable: bool| {
        write(&t.path("src/a"), b"a");
        write(&t.path("dst/kept/ignored.tmp"), b"ignored");
        write(&t.path("dst/kept/extra"), b"extra");
        write(&t.path("dst/e555/in/f"), b"f");
        write(&t.path("dst/e555/g"), b"g");
        let mut modes = vec![
            ("dst/e555/in", 0o555),
            ("dst/e555", 0o555),
            ("dst/kept", 0o555),
        ];
        if unreadable {
            write(&t.path("dst/e300/f"), b"f");
            write(&t.path("dst/e100/n300/f"), b"f");
            modes.extend([
                ("dst/e300", 0o300),
                ("dst/e100/n300", 0o300),
                ("dst/e100", 0o100),
            ]);
        }
        for (path, mode) in &modes {
            fs::set_permissions(t.path(path), fs::Permissions::from_mode(*mode)).unwrap();
        }
        modes
    };
    let restore = |t: &Tmp| {
        for path in [
            "dst/e100",
            "dst/e100/n300",
            "dst/e300",
            "dst/e555",
            "dst/e555/in",
            "dst/kept",
        ] {
            let _ = fs::set_permissions(t.path(path), fs::Permissions::from_mode(0o700));
        }
    };
    for pruning in ["--prune", "--prune-before"] {
        // Native copy with the option: everything extra goes.
        let t = Tmp::new();
        tree(&t, unreadable);
        let out = native_syq(&[
            "cp",
            "--temporarily-widen-dir-permissions",
            pruning,
            "--ignore",
            "*.tmp",
            "--srcs-in",
            &t.s("src"),
            "--into",
            &t.s("dst"),
        ]);
        let kept = fs::metadata(t.path("dst/kept")).unwrap().mode() & 0o777;
        restore(&t);
        assert_output_ok(&out);
        assert_eq!(kept, 0o555, "{pruning}");
        assert_eq!(
            listing(&t.path("dst")),
            ["a", "kept", "kept/ignored.tmp"],
            "{pruning}"
        );

        // Without the option nothing changes.
        let t = Tmp::new();
        let modes = tree(&t, unreadable);
        let out = native_syq(&[
            "cp",
            pruning,
            "--ignore",
            "*.tmp",
            "--srcs-in",
            &t.s("src"),
            "--into",
            &t.s("dst"),
        ]);
        let after: Vec<_> = modes
            .iter()
            .rev()
            .map(|(path, _)| fs::metadata(t.path(path)).unwrap().mode() & 0o777)
            .collect();
        restore(&t);
        assert_eq!(out.status.code(), Some(23), "{out:?}");
        assert_eq!(
            after,
            modes
                .iter()
                .rev()
                .map(|(_, mode)| *mode)
                .collect::<Vec<_>>()
        );
        assert!(t.path("dst/e555/g").exists());
        assert_eq!(t.path("dst/e300/f").exists(), unreadable);
    }

    // syq rsync empties readable directories, as rsync does.
    let t = Tmp::new();
    tree(&t, false);
    let out = syq(&["-r", "--delete", &format!("{}/", t.s("src")), &t.s("dst")]);
    restore(&t);
    assert_output_ok(&out);
    assert_eq!(listing(&t.path("dst")), ["a"]);
    // It does not enter unreadable ones, so nothing is deleted.
    let t = Tmp::new();
    tree(&t, true);
    let out = syq(&["-r", "--delete", &format!("{}/", t.s("src")), &t.s("dst")]);
    let e300 = fs::metadata(t.path("dst/e300")).unwrap().mode() & 0o777;
    restore(&t);
    assert_eq!(out.status.code(), Some(23), "{out:?}");
    assert_eq!(e300, 0o300);
    assert!(t.path("dst/e555/g").exists());

    // A dry run and a deletion limit leave every mode as it was.
    for extra in [vec!["--dry-run"], vec!["--max-delete", "1"]] {
        let t = Tmp::new();
        let modes = tree(&t, unreadable);
        let before: Vec<_> = modes
            .iter()
            .rev()
            .map(|(path, _)| fs::metadata(t.path(path)).unwrap())
            .collect();
        let mut args = vec![
            "cp",
            "--temporarily-widen-dir-permissions",
            "--prune",
            "--srcs-in",
        ];
        let src = t.s("src");
        let dst = t.s("dst");
        args.extend([src.as_str(), "--into", dst.as_str()]);
        args.extend(extra.iter().copied());
        let out = native_syq(&args);
        let after: Vec<_> = modes
            .iter()
            .rev()
            .map(|(path, _)| fs::metadata(t.path(path)).unwrap())
            .collect();
        restore(&t);
        assert_eq!(
            out.status.success(),
            !unreadable && extra[0] == "--dry-run",
            "{extra:?}: {out:?}"
        );
        for (before, after) in before.iter().zip(&after) {
            assert_eq!(after.mode(), before.mode(), "{extra:?}");
            if extra[0] == "--dry-run" {
                assert_eq!(
                    (after.ctime(), after.ctime_nsec()),
                    (before.ctime(), before.ctime_nsec())
                );
            }
        }
        assert_eq!(t.path("dst/e300/f").exists(), unreadable);
        assert!(t.path("dst/e555/in/f").exists());
    }
}

/// A dry run names each owned directory a real copy could not change without
/// the option, once, using the modes its scan read. A real copy reports each
/// one once too, before its per-file errors, and still copies what it can.
#[test]
fn copies_name_each_directory_that_needs_temporary_access_once() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let note = "dst/ro: you own this directory, but it lacks owner write permission; \
                --temporarily-widen-dir-permissions may help";
    for dry_run in [true, false] {
        for widen in [false, true] {
            let t = Tmp::new();
            for name in ["a", "b", "c"] {
                write(&t.path(&format!("src/ro/{name}")), b"new");
            }
            write(&t.path("src/open/file"), b"new");
            fs::create_dir_all(t.path("dst/ro")).unwrap();
            fs::create_dir_all(t.path("dst/open")).unwrap();
            // A read-only directory with nothing to change needs no access.
            fs::create_dir_all(t.path("src/idle")).unwrap();
            fs::create_dir_all(t.path("dst/idle")).unwrap();
            for path in ["dst/ro", "dst/idle"] {
                fs::set_permissions(t.path(path), fs::Permissions::from_mode(0o555)).unwrap();
            }
            let src = t.s("src");
            let dst = t.s("dst");
            let mut args = vec!["cp", "--srcs-in", &src, "--into", &dst];
            if dry_run {
                args.push("--dry-run");
            }
            if widen {
                args.push("--temporarily-widen-dir-permissions");
            }
            let out = native_syq(&args);
            let modes: Vec<_> = ["dst/ro", "dst/idle"]
                .iter()
                .map(|path| fs::metadata(t.path(path)).unwrap().mode() & 0o777)
                .collect();
            for path in ["dst/ro", "dst/idle"] {
                fs::set_permissions(t.path(path), fs::Permissions::from_mode(0o755)).unwrap();
            }
            let stderr = stderr_of(&out);
            let case = format!("dry={dry_run}, widen={widen}: {out:?}");
            assert_eq!(modes, [0o555, 0o555], "{case}");
            assert_eq!(stderr.matches(note).count(), usize::from(!widen), "{case}");
            // The per-file errors that follow do not repeat the hint.
            assert_eq!(
                stderr
                    .matches("--temporarily-widen-dir-permissions")
                    .count(),
                usize::from(!widen),
                "{case}"
            );
            assert!(!stderr.contains("dst/idle:"), "{case}");
            if dry_run || widen {
                assert_output_ok(&out);
            } else {
                assert_eq!(out.status.code(), Some(23), "{case}");
                // The note comes before the per-file errors it explains.
                assert!(
                    stderr.find(note) < stderr.find("Permission denied"),
                    "{case}"
                );
            }
            assert_eq!(t.path("dst/open/file").exists(), !dry_run, "{case}");
            assert_eq!(t.path("dst/ro/a").exists(), !dry_run && widen, "{case}");
        }
    }
}

/// The option cannot widen the directory above an exact placement, so a
/// failure there does not suggest it; an `--into` target still does.
#[test]
fn exact_placement_failures_do_not_suggest_temporary_access() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    for (placement, size) in [("--as", 3), ("--as", 128 << 10), ("--into", 3)] {
        let t = Tmp::new();
        write(&t.path("src/file"), &vec![b'n'; size]);
        fs::create_dir(t.path("dst")).unwrap();
        fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o555)).unwrap();
        let destination = if placement == "--as" {
            t.s("dst/file")
        } else {
            t.s("dst")
        };
        let out = native_syq(&["cp", &t.s("src/file"), placement, &destination]);
        fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(!out.status.success(), "{out:?}");
        assert_eq!(
            stderr_of(&out).contains("--temporarily-widen-dir-permissions"),
            placement == "--into",
            "{placement}, {size}: {out:?}"
        );
    }
}

/// Several sources can reach the same directories in different batches:
/// each directory is still named once, and an in-place update needs no
/// directory write.
#[test]
fn directory_access_notes_stay_once_across_sources_and_skip_inplace_updates() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    for dry_run in [true, false] {
        let t = Tmp::new();
        write(&t.path("one/ro/a"), b"new");
        write(&t.path("two/ro/b"), b"new");
        write(&t.path("one/closed/c"), b"new");
        write(&t.path("two/closed/d"), b"new");
        fs::create_dir_all(t.path("dst/ro")).unwrap();
        fs::create_dir_all(t.path("dst/closed")).unwrap();
        fs::set_permissions(t.path("dst/ro"), fs::Permissions::from_mode(0o555)).unwrap();
        fs::set_permissions(t.path("dst/closed"), fs::Permissions::from_mode(0o600)).unwrap();
        let (one, two, dst) = (t.s("one"), t.s("two"), t.s("dst"));
        let mut args = vec!["cp", "--srcs-in", &one, "--srcs-in", &two, "--into", &dst];
        if dry_run {
            args.push("--dry-run");
        }
        let out = native_syq(&args);
        for path in ["dst/ro", "dst/closed"] {
            fs::set_permissions(t.path(path), fs::Permissions::from_mode(0o755)).unwrap();
        }
        let stderr = stderr_of(&out);
        assert_eq!(
            stderr.matches("dst/ro: you own this directory").count(),
            1,
            "{out:?}"
        );
        let closed = if dry_run {
            "dst/closed: not inspected"
        } else {
            "dst/closed: you own this directory"
        };
        assert_eq!(stderr.matches(closed).count(), 1, "{out:?}");
    }

    let t = Tmp::new();
    write(&t.path("src/ro/file"), b"newer");
    write(&t.path("dst/ro/file"), b"old");
    fs::set_permissions(t.path("dst/ro"), fs::Permissions::from_mode(0o555)).unwrap();
    for dry_run in [true, false] {
        let (src, dst) = (t.s("src"), t.s("dst"));
        let mut args = vec!["cp", "--inplace", "--srcs-in", &src, "--into", &dst];
        if dry_run {
            args.push("--dry-run");
        }
        let out = native_syq(&args);
        assert_output_ok(&out);
        assert!(!stderr_of(&out).contains("dst/ro:"), "{out:?}");
    }
    fs::set_permissions(t.path("dst/ro"), fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(read(&t.path("dst/ro/file")), b"newer");
}

/// A preview names a directory that needs the option wherever it finds a
/// change there: a content comparison, a hard link, or an `--as` target
/// that is an existing directory.
#[test]
fn previews_name_directories_needing_access_for_compared_and_linked_files() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let note = |dir: &str| {
        format!(
            "{dir}: you own this directory, but it lacks owner write permission; \
             --temporarily-widen-dir-permissions may help"
        )
    };
    // Equal sizes and times: only the --hash comparison finds the change.
    let t = Tmp::new();
    write(&t.path("src/ro/file"), b"new1");
    write(&t.path("dst/ro/file"), b"old1");
    for path in ["src/ro/file", "dst/ro/file"] {
        timestamp(&t.path(path), 1_700_000_000, 0);
    }
    fs::set_permissions(t.path("dst/ro"), fs::Permissions::from_mode(0o555)).unwrap();
    let (src, dst, ro) = (t.s("src"), t.s("dst"), t.s("dst/ro"));
    let out = native_syq(&[
        "cp",
        "--hash",
        "--dry-run",
        "--srcs-in",
        &src,
        "--into",
        &dst,
    ]);
    let exact = native_syq(&["cp", "--hash", "--dry-run", &t.s("src/ro"), "--as", &ro]);
    fs::set_permissions(t.path("dst/ro"), fs::Permissions::from_mode(0o755)).unwrap();
    for out in [&out, &exact] {
        assert_output_ok(out);
        assert_eq!(stderr_of(out).matches(&note(&ro)).count(), 1, "{out:?}");
    }

    // Hard links into a read-only directory, previewed and copied.
    let t = Tmp::new();
    write(&t.path("src/ro/one"), b"linked");
    fs::hard_link(t.path("src/ro/one"), t.path("src/ro/two")).unwrap();
    fs::create_dir_all(t.path("dst/ro")).unwrap();
    fs::set_permissions(t.path("dst/ro"), fs::Permissions::from_mode(0o555)).unwrap();
    let (src, dst, ro) = (t.s("src"), t.s("dst"), t.s("dst/ro"));
    for dry_run in [true, false] {
        let mut args = vec![
            "cp",
            "--copy-metadata=hardlinks",
            "--srcs-in",
            &src,
            "--into",
            &dst,
        ];
        if dry_run {
            args.push("--dry-run");
        }
        let out = native_syq(&args);
        assert_eq!(stderr_of(&out).matches(&note(&ro)).count(), 1, "{out:?}");
        assert_eq!(
            stderr_of(&out)
                .matches("--temporarily-widen-dir-permissions")
                .count(),
            1,
            "{out:?}"
        );
    }
    fs::set_permissions(t.path("dst/ro"), fs::Permissions::from_mode(0o755)).unwrap();
}

/// An existing directory named by `--as` belongs to the copy, so when it
/// cannot be searched the failure suggests the option, which then works.
#[test]
fn exact_placement_onto_an_unsearchable_directory_suggests_and_takes_access() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let t = Tmp::new();
    write(&t.path("src/a/file"), b"new");
    fs::create_dir_all(t.path("dst/a")).unwrap();
    fs::set_permissions(t.path("dst/a"), fs::Permissions::from_mode(0o600)).unwrap();
    let (src, dst) = (t.s("src/a"), t.s("dst/a"));
    let out = native_syq(&["cp", &src, "--as", &dst]);
    assert!(!out.status.success(), "{out:?}");
    assert!(
        stderr_of(&out).contains("--temporarily-widen-dir-permissions"),
        "{out:?}"
    );
    let out = native_syq(&[
        "cp",
        "--temporarily-widen-dir-permissions",
        &src,
        "--as",
        &dst,
    ]);
    let mode = fs::metadata(t.path("dst/a")).unwrap().mode() & 0o777;
    fs::set_permissions(t.path("dst/a"), fs::Permissions::from_mode(0o700)).unwrap();
    assert_output_ok(&out);
    assert_eq!(mode, 0o600);
    assert_eq!(read(&t.path("dst/a/file")), b"new");
}

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
        let args = ["cp", "--srcs-in", &t.s("src"), "--into", &t.s("dst")];
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
            "--tuning-options=copy-path=ranges",
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
        fs::hard_link(t.path("dst/SUB/REPORT.TXT"), t.path("dst/SUB/other-link")).unwrap();
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
        assert_eq!(read(&t.path("dst/SUB/other-link")), b"contents");
        assert_eq!(t.path("dst/SUB/extra").exists(), dry_run);
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
        let tuning = format!("--tuning-options=copy-path={mode}");
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
fn prune_checks_source_overlap_across_endpoint_spellings() {
    let t = Tmp::new();
    write(&t.path("backup/import/file"), b"source contents");
    let shell = fake_rsh(&t);
    let out = compat_command()
        .args(["-a", "--delete", "-e"])
        .arg(shell)
        .args([
            "--syq-no-bootstrap",
            "--rsync-path",
            env!("CARGO_BIN_EXE_syq"),
        ])
        .arg(format!("fake:{}", t.s("backup/import/")))
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
                let mut args = vec!["cp", "--srcs-in", &src, "--into", &dst];
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

#[test]
fn dry_run_leaves_unsearchable_destination_permissions_unchanged() {
    for mode in [0o600, 0o000] {
        let t = Tmp::new();
        write(&t.path("src/sub/file"), b"new contents");
        write(&t.path("dst/sub/file"), b"old contents");
        fs::set_permissions(t.path("dst/sub"), fs::Permissions::from_mode(mode)).unwrap();
        let before = fs::metadata(t.path("dst/sub")).unwrap();
        let out = native_syq(&[
            "cp",
            "--dry-run",
            "--srcs-in",
            &t.s("src"),
            "--into",
            &t.s("dst"),
        ]);
        let after = fs::metadata(t.path("dst/sub")).unwrap();
        fs::set_permissions(t.path("dst/sub"), fs::Permissions::from_mode(0o755)).unwrap();
        if cfg!(target_os = "macos") && mode == 0 {
            assert!(!out.status.success(), "{out:?}");
            assert!(stderr_of(&out).contains("Permission denied"), "{out:?}");
        } else {
            assert_output_ok(&out);
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
                        let mut args = vec!["cp", "--prune", "--preserve=permissions", "--srcs-in"];
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

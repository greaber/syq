use super::*;

#[test]
fn native_preserve_specials_copies_or_visibly_skips_socket_nodes() {
    let t = Tmp::new();
    write(&t.path("src/nested/ordinary"), b"ordinary");
    let _source_socket =
        std::os::unix::net::UnixListener::bind(t.path("src/nested/socket")).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "cp",
            "--preserve=specials",
            "--srcs-in",
            &t.s("src"),
            "--into",
            &t.s("dst"),
            "--no-progress",
        ])
        .run()
        .unwrap();
    assert_output_ok(&output);
    assert_eq!(read(&t.path("dst/nested/ordinary")), b"ordinary");

    #[cfg(target_os = "linux")]
    assert!(fs::symlink_metadata(t.path("dst/nested/socket"))
        .unwrap()
        .file_type()
        .is_socket());

    #[cfg(target_os = "macos")]
    {
        assert!(!t.path("dst/nested/socket").exists());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("skipping socket"), "{stderr}");
        assert!(stderr.contains("confined destination"), "{stderr}");
    }
}

// Pinning a mode-000 file without opening it needs Linux `O_PATH`; macOS
// `O_EVTONLY` still fails the permission check, so the copy fails visibly.
#[cfg(target_os = "linux")]
#[test]
fn archive_copies_mode_zero_empty_file_without_opening_source() {
    let t = Tmp::new();
    let src = t.path("src/empty");
    write(&src, b"");
    fs::set_permissions(&src, fs::Permissions::from_mode(0o000)).unwrap();

    let output = run_ok(&["-a", "--stats", &t.s("src/empty"), &t.s("dst/empty")]);

    let dst = fs::metadata(t.path("dst/empty")).unwrap();
    assert_eq!(dst.len(), 0);
    assert_eq!(dst.mode() & 0o777, 0);
    assert!(
        output.contains("connections: auto: settled at 1 (path 1, peak 1)"),
        "{output}"
    );
}

#[test]
fn metadata_preserved_with_archive() {
    let t = Tmp::new();
    make_tree(&t.path("src"));
    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    let d = t.path("dst");
    // Explicit spot checks in addition to the tree comparison.
    let md = fs::metadata(d.join("hello.txt")).unwrap();
    assert_eq!(md.mode() & 0o777, 0o640);
    assert_eq!(md.mtime(), 1_577_934_245);
    assert_eq!(fs::metadata(d.join("a")).unwrap().mode() & 0o777, 0o750);
    assert_eq!(
        fs::read_link(d.join("badlink")).unwrap(),
        PathBuf::from("/nonexistent/target")
    );
    assert_eq!(
        fs::read_link(d.join("link")).unwrap(),
        PathBuf::from("hello.txt")
    );
    assert!(std::os::unix::fs::FileTypeExt::is_fifo(
        &fs::symlink_metadata(d.join("fifo")).unwrap().file_type()
    ));
    assert_eq!(fs::metadata(d.join("a/b/c/zero")).unwrap().len(), 0);
    assert!(d.join("empty").is_dir());
    assert_eq!(fs::read_dir(d.join("empty")).unwrap().count(), 0);
    // Directory mtimes survive their children being written.
    assert_eq!(
        fs::metadata(d.join("a")).unwrap().mtime(),
        1_577_934_245 + 5
    );
    assert_eq!(
        fs::metadata(d.join("a/b")).unwrap().mtime(),
        1_577_934_245 + 4
    );
    assert_eq!(
        fs::metadata(d.join("a/b/c")).unwrap().mtime(),
        1_577_934_245 + 3
    );
    assert_eq!(
        fs::metadata(d.join("empty")).unwrap().mtime(),
        1_577_934_245 + 6
    );
    assert_eq!(fs::metadata(&d).unwrap().mtime(), 1_577_934_245 + 7);
    assert_same_tree(&t.path("src"), &d);
}

#[test]
fn no_op_copy_does_not_mutate_directory_metadata() {
    let t = Tmp::new();
    write(&t.path("src/nested/file"), b"same");
    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    let before: Vec<(i64, i64)> = [
        t.path("dst"),
        t.path("dst/nested"),
        t.path("dst/nested/file"),
    ]
    .iter()
    .map(|path| {
        let metadata = fs::symlink_metadata(path).unwrap();
        (metadata.ctime(), metadata.ctime_nsec())
    })
    .collect();

    std::thread::sleep(std::time::Duration::from_millis(10));
    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    let after: Vec<(i64, i64)> = [
        t.path("dst"),
        t.path("dst/nested"),
        t.path("dst/nested/file"),
    ]
    .iter()
    .map(|path| {
        let metadata = fs::symlink_metadata(path).unwrap();
        (metadata.ctime(), metadata.ctime_nsec())
    })
    .collect();

    assert_eq!(after, before);
}

#[test]
fn skip_reconciles_mode() {
    let t = Tmp::new();
    write(&t.path("src"), b"data");
    fs::set_permissions(t.path("src"), fs::Permissions::from_mode(0o600)).unwrap();
    fs::copy(t.path("src"), t.path("dst")).unwrap();
    fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o644)).unwrap();
    set_mtime(&t.path("src"), 1_000_000_000);
    set_mtime(&t.path("dst"), 1_000_000_000);
    // content is skipped, but -a must still fix the mode
    run_ok(&["-a", &t.s("src"), &t.s("dst")]);
    let m = fs::symlink_metadata(t.path("dst")).unwrap().mode() & 0o777;
    assert_eq!(m, 0o600, "mode should be reconciled on skip");
}

#[test]
fn archive_into_readonly_dest_dir() {
    let t = Tmp::new();
    write(&t.path("src/sub/f"), b"hi");
    run_ok(&["-a", &t.s("src"), &t.s("d")]);
    fs::set_permissions(t.path("d/src"), fs::Permissions::from_mode(0o555)).unwrap();
    write(&t.path("src/sub/g"), b"more");
    run_ok(&["-a", &t.s("src/"), &t.s("d/src/")]);
    assert_eq!(read(&t.path("d/src/sub/g")), b"more");
}

#[test]
fn control_file_names_preserve_non_utf8_bytes() {
    if !filesystem_accepts_non_utf8_names() {
        eprintln!("skipping: this filesystem rejects file names that are not valid UTF-8");
        return;
    }
    let t = Tmp::new();
    write(&t.path("src/keep"), b"keep");
    write(&t.path("src/drop"), b"drop");
    let rules = t
        .path("")
        .join(std::ffi::OsString::from_vec(b"rules-\xff".to_vec()));
    let list = t
        .path("")
        .join(std::ffi::OsString::from_vec(b"list-\xfe".to_vec()));
    write(&rules, b"drop\n");
    write(&list, b"keep\n");

    let native = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["cp", "--ignore-from"])
        .arg(&rules)
        .arg("--srcs-in")
        .arg(t.path("src"))
        .arg("--into")
        .arg(t.path("native"))
        .arg("-q")
        .run()
        .unwrap();
    assert_output_ok(&native);
    assert_eq!(listing(&t.path("native")), ["keep"]);

    let compatible = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["rsync", "-a", "--syq-ignore-from"])
        .arg(&rules)
        .arg(t.s("src/"))
        .arg(t.path("compatible"))
        .arg("--no-progress")
        .run()
        .unwrap();
    assert_output_ok(&compatible);
    assert_eq!(listing(&t.path("compatible")), ["keep"]);

    let listed = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["rsync", "-a", "--files-from"])
        .arg(&list)
        .arg(t.path("src"))
        .arg(t.path("listed"))
        .arg("--no-progress")
        .run()
        .unwrap();
    assert_output_ok(&listed);
    assert_eq!(listing(&t.path("listed")), ["keep"]);
}

// A read-only source root: the copy succeeds, the root ends up 0555, and a
// rerun into the now read-only destination works too.
#[test]
fn readonly_root_copies_and_reruns() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"data");
    fs::set_permissions(t.path("src"), fs::Permissions::from_mode(0o555)).unwrap();
    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(fs::metadata(t.path("dst")).unwrap().mode() & 0o777, 0o555);
    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(fs::metadata(t.path("dst")).unwrap().mode() & 0o777, 0o555);
    // No implicit history: deleting a destination file makes the next run
    // restore it from the read-only source.
    fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o755)).unwrap();
    fs::remove_file(t.path("dst/f")).unwrap();
    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(read(&t.path("dst/f")), b"data");
}

// Several content sources map onto the destination root; the last one's
// metadata wins, as for any other directory.
#[test]
fn multiple_content_sources_root_meta() {
    let t = Tmp::new();
    write(&t.path("A/a"), b"a");
    write(&t.path("B/b"), b"b");
    fs::set_permissions(t.path("A"), fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(t.path("B"), fs::Permissions::from_mode(0o555)).unwrap();
    run_ok(&["-a", &t.s("A/"), &t.s("B/"), &t.s("dest/")]);
    assert_eq!(fs::metadata(t.path("dest")).unwrap().mode() & 0o777, 0o555);
    assert_eq!(read(&t.path("dest/a")), b"a");
    assert_eq!(read(&t.path("dest/b")), b"b");
}

// Directories syq had to open up (no owner write bit) get their own mode back
// at the end when nothing else sets it (no -p); with -p the source mode wins.
#[test]
fn opened_up_directories_get_their_mode_back() {
    let t = Tmp::new();
    write(&t.path("src/sub/f"), b"data");
    fs::set_permissions(t.path("src/sub"), fs::Permissions::from_mode(0o755)).unwrap();
    fs::create_dir_all(t.path("dst/sub")).unwrap();
    fs::set_permissions(t.path("dst/sub"), fs::Permissions::from_mode(0o555)).unwrap();
    fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o555)).unwrap();
    run_ok(&["-r", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(read(&t.path("dst/sub/f")), b"data");
    assert_eq!(
        fs::metadata(t.path("dst/sub")).unwrap().mode() & 0o777,
        0o555
    );
    assert_eq!(fs::metadata(t.path("dst")).unwrap().mode() & 0o777, 0o555);
    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(
        fs::metadata(t.path("dst/sub")).unwrap().mode() & 0o777,
        0o755
    );
}

// A directory metadata failure is a copy error (exit 23), not a footnote.
#[cfg(debug_assertions)]
#[test]
fn root_meta_failure_is_visible() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"data");
    let out = compat_command()
        .args(["-a", "--no-progress", &t.s("src/"), &t.s("dst")])
        .env("SYQ_TEST_FAIL_SETMETA", "dst")
        .run()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(23), "stderr: {err}");
    assert!(err.contains("injected"), "stderr: {err}");
    assert_eq!(read(&t.path("dst/f")), b"data");
}

// A dry run creates nothing, not even the destination directory.
#[test]
fn dry_run_creates_nothing() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"data");
    let out = syq(&["-a", "-n", &t.s("src/"), &t.s("dst/")]);
    assert!(out.status.success());
    assert!(
        !t.path("dst").exists(),
        "--dry-run must not create the destination"
    );
}

#[test]
fn three_claimants_are_validated_as_a_group() {
    let t = Tmp::new();
    write(&t.path("dst/x"), b"dest content");
    fs::create_dir_all(t.path("a")).unwrap();
    fs::hard_link(t.path("dst/x"), t.path("a/x")).unwrap();
    write(&t.path("b/x"), b"from b");
    write(&t.path("c/x"), b"from c");
    // a/x is the destination file; b/x and c/x are two different contents.
    let out = syq(&["-r", &t.s("a/"), &t.s("b/"), &t.s("c/"), &t.s("dst")]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr_of(&out));
    assert!(stderr_of(&out).contains("3 sources map to the same destination"));
    assert_eq!(read(&t.path("dst/x")), b"dest content");
    // Even one other content is a conflict: dst/x was named as a source.
    let out = syq(&["-r", &t.s("b/"), &t.s("a/"), &t.s("dst")]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(read(&t.path("dst/x")), b"dest content");
}

#[test]
fn native_cp_activity_covers_short_copies_and_preserves_terminal_order() {
    let t = Tmp::new();
    write(&t.path("src/a"), &vec![7; 2 * 1024 * 1024]);
    let out = syq_cp_in(
        &t.path(""),
        &[
            "--srcs-in",
            "src",
            "--into",
            "dst",
            "--results",
            "activity.ndjson",
            "--stats",
            "-q",
        ],
        None,
    );
    assert!(out.status.success(), "{}", stderr_of(&out));
    assert_eq!(read(&t.path("src/a")), read(&t.path("dst/a")));
    let content = String::from_utf8(read(&t.path("activity.ndjson"))).unwrap();
    assert_automation_stream(&automation_validator(), &content, "activity copy");
    let records: Vec<serde_json::Value> = content
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(records.last().unwrap()["type"], "result");
    let activity = &records
        .iter()
        .rev()
        .find(|r| r["type"] == "progress")
        .unwrap()["activity"];
    assert!(activity["workers"]["observed"].as_u64().unwrap() > 0);
    assert_eq!(activity["workers"]["active"], 0);
    let fractions = activity["workers"]["cumulative_fractions"]
        .as_object()
        .unwrap();
    assert!((fractions.values().map(|v| v.as_f64().unwrap()).sum::<f64>() - 1.0).abs() < 1e-9);
    assert!(activity["endpoints"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["actors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["observed_ns"].as_u64().unwrap() > 0)));
    let stderr = stderr_of(&out);
    assert!(stderr.contains("Observed worker time:"));
    assert!(stderr.contains("worker 0 (process "), "{stderr}");
    assert!(stderr.contains("bytes"), "{stderr}");
    assert!(stderr.contains("CPU: user"), "{stderr}");
    assert!(!stderr.contains("1 workers"), "{stderr}");
}

#[test]
fn forgetting_offline_owner_recreates_missing_lock() {
    let t = Tmp::new();
    write(&t.path(".syq-destinations-v3/laptop.owner"), b"{}");
    fs::set_permissions(
        t.path(".syq-destinations-v3"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["persist", "destinations", "forget", "laptop"])
        .env("HOME", t.path(""))
        .env("SYQ_NO_UPDATE_CHECK", "1")
        .capture_output()
        .unwrap();
    assert_output_ok(&output);
    assert!(!t.path(".syq-destinations-v3/laptop.owner").exists());
    assert_eq!(
        fs::metadata(t.path(".syq-destinations-v3/laptop.lock"))
            .unwrap()
            .mode()
            & 0o777,
        0o600
    );
}

#[test]
fn native_only_new_stamps_its_new_destination_root() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    for deferred in [false, true] {
        let t = Tmp::new();
        write(&t.path("src/sub/file"), b"new");
        for path in ["src", "src/sub"] {
            fs::set_permissions(t.path(path), fs::Permissions::from_mode(0o750)).unwrap();
            set_mtime(&t.path(path), 1_500_000_000);
        }
        let src = t.s("src");
        let dst = t.s("dst");
        let extra = t.s("extra");
        let mut args = vec![
            "cp",
            "--only-new",
            "--preserve=permissions",
            "--srcs-in",
            &src,
            "--into",
            &dst,
        ];
        if deferred {
            write(&t.path("extra"), b"extra");
            args.splice(5..5, ["--src", &extra]);
        }
        run_native_ok(&args);
        for path in ["dst", "dst/sub"] {
            let metadata = fs::metadata(t.path(path)).unwrap();
            assert_eq!(metadata.mode() & 0o777, 0o750, "{path}");
            assert_eq!(metadata.mtime(), 1_500_000_000, "{path}");
        }
        fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o711)).unwrap();
        set_mtime(&t.path("dst"), 1_600_000_000);
        run_native_ok(&args);
        let metadata = fs::metadata(t.path("dst")).unwrap();
        assert_eq!(metadata.mode() & 0o777, 0o711);
        assert_eq!(metadata.mtime(), 1_600_000_000);
    }
}

#[test]
fn native_only_new_later_sources_stamp_directories_created_by_this_copy() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let t = Tmp::new();
    for (source, mode, time) in [("a", 0o750, 1_500_000_000), ("b", 0o711, 1_600_000_000)] {
        write(
            &t.path(&format!("{source}/shared/{source}")),
            source.as_bytes(),
        );
        for dir in [source.to_owned(), format!("{source}/shared")] {
            fs::set_permissions(t.path(&dir), fs::Permissions::from_mode(mode)).unwrap();
            set_mtime(&t.path(&dir), time);
        }
    }
    for only_new in [false, true] {
        let dst = if only_new { "missing-only" } else { "ordinary" };
        let a = t.s("a");
        let b = t.s("b");
        let destination = t.s(dst);
        let mut args = vec![
            "cp",
            "--preserve=permissions",
            "--srcs-in",
            &a,
            "--srcs-in",
            &b,
            "--into",
            &destination,
        ];
        if only_new {
            args.insert(1, "--only-new");
        }
        run_native_ok(&args);
        for dir in [dst.to_owned(), format!("{dst}/shared")] {
            let meta = fs::metadata(t.path(&dir)).unwrap();
            assert_eq!(meta.mode() & 0o777, 0o711, "{dir}");
            assert_eq!(meta.mtime(), 1_600_000_000, "{dir}");
        }
        for source in ["a", "b"] {
            assert_eq!(
                read(&t.path(&format!("{dst}/shared/{source}"))),
                source.as_bytes()
            );
        }
    }
}

#[test]
fn native_mtime_uses_destination_decimal_precision() {
    // Different same-size bytes make an accidental copy/skip observable. Set
    // exact timestamps to emulate destination truncation without mounting a FS.
    for (source_nsec, destination_nsec, source_seconds, same_size, skipped) in [
        (123_456_789, 123_456_789, 10, true, true),
        (123_456_789, 123_456_788, 10, true, false),
        (123_456_789, 123_456_700, 10, true, true),
        (123_456_789, 123_456_800, 10, true, false),
        (123_456_789, 120_000_000, 10, true, true),
        (129_999_999, 120_000_000, 10, true, true),
        (130_000_000, 120_000_000, 10, true, false),
        (120_000_000, 123_456_789, 10, true, false),
        (999_999_999, 0, 10, true, true),
        (0, 0, 10, true, true),
        (123_456_789, 0, 11, true, false),
        (123_456_789, 0, 9, true, false),
        (123_456_789, 120_000_000, 10, false, false),
    ] {
        let t = Tmp::new();
        write(&t.path("src"), b"new");
        write(&t.path("dst"), if same_size { b"old" } else { b"older" });
        for (name, seconds, nanos) in [
            ("src", source_seconds, source_nsec),
            ("dst", 10, destination_nsec),
        ] {
            let time = std::time::UNIX_EPOCH + std::time::Duration::new(seconds, nanos);
            File::options()
                .write(true)
                .open(t.path(name))
                .unwrap()
                .set_times(fs::FileTimes::new().set_modified(time))
                .unwrap();
        }
        run_native_ok(&["cp", &t.s("src"), "--as", &t.s("dst")]);
        assert_eq!(
            read(&t.path("dst")),
            if skipped { b"old" } else { b"new" },
            "source={source_seconds}.{source_nsec:09}, destination=10.{destination_nsec:09}"
        );
        if skipped {
            // Content verification must bypass the inferred-precision shortcut.
            run_native_ok(&["cp", "--hash", &t.s("src"), "--as", &t.s("dst")]);
            assert_eq!(read(&t.path("dst")), b"new");
        }
    }
}

#[test]
fn descriptor_copies_preserve_bytes_offsets_flags_and_publication() {
    let output = Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/support/descriptor-copies.py"
        ))
        .arg(env!("CARGO_BIN_EXE_syq"))
        .capture_output()
        .expect("run descriptor-copy fixture");
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn fresh_descendants_preserve_existing_root_metadata() {
    for direction in ["local", "push", "pull"] {
        let t = Tmp::new();
        let rsh = fake_rsh(&t);
        t.expose_remote_syq();
        write(&t.path("source/nested/file"), b"payload");
        fs::set_permissions(t.path("source"), fs::Permissions::from_mode(0o711)).unwrap();
        for (label, options, expected_root_mode) in
            [("default", "-rlt", 0o750), ("perms", "-rlpt", 0o711)]
        {
            let fresh = format!("{label}-fresh");
            let reference = format!("{label}-reference");
            for destination in [&fresh, &reference] {
                fs::create_dir(t.path(destination)).unwrap();
                fs::set_permissions(t.path(destination), fs::Permissions::from_mode(0o750))
                    .unwrap();
            }
            // Force the reference through ordinary destination lookup.
            write(&t.path(&format!("{reference}/sentinel")), b"keep");
            for destination in [&fresh, &reference] {
                let source = t.s("source/");
                let destination = format!("{}/", t.s(destination));
                if direction != "local" {
                    let source = if direction == "pull" {
                        format!("host:{source}")
                    } else {
                        source
                    };
                    let destination = if direction == "push" {
                        format!("host:{destination}")
                    } else {
                        destination
                    };
                    let output = remote_syq_command(
                        &t,
                        &rsh,
                        &["--syq-no-bootstrap", options, &source, &destination],
                    )
                    .run()
                    .unwrap();
                    assert_output_ok(&output);
                } else {
                    run_ok(&[options, &source, &destination]);
                }
            }
            assert_eq!(
                fs::metadata(t.path(&fresh)).unwrap().mode() & 0o777,
                expected_root_mode
            );
            for name in ["", "nested", "nested/file"] {
                let a = fs::metadata(t.path(&format!("{fresh}/{name}"))).unwrap();
                let b = fs::metadata(t.path(&format!("{reference}/{name}"))).unwrap();
                assert_eq!(
                    (a.mode(), a.mtime(), a.mtime_nsec()),
                    (b.mode(), b.mtime(), b.mtime_nsec())
                );
            }
            assert_eq!(read(&t.path(&format!("{fresh}/nested/file"))), b"payload");
            assert_eq!(read(&t.path(&format!("{reference}/sentinel"))), b"keep");
        }
    }
}

fn set_access_time(path: &Path, seconds: i64, nanos: i64) {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    let times = [
        libc::timespec {
            tv_sec: seconds as _,
            tv_nsec: nanos as _,
        },
        libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_OMIT as _,
        },
    ];
    assert_eq!(
        unsafe {
            libc::utimensat(
                libc::AT_FDCWD,
                path.as_ptr(),
                times.as_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        },
        0,
        "{}",
        std::io::Error::last_os_error()
    );
}

fn access_time(path: &Path) -> (i64, i64) {
    let m = fs::symlink_metadata(path).unwrap();
    (m.atime(), m.atime_nsec())
}

#[test]
fn unchanged_symlink_access_time_is_restored_after_target_comparison() {
    let t = Tmp::new();
    fs::create_dir(t.path("source")).unwrap();
    std::os::unix::fs::symlink("missing", t.path("source/link")).unwrap();
    for _ in 0..2 {
        set_access_time(&t.path("source/link"), 700_000_000, 123_456_789);
        let expected = access_time(&t.path("source/link"));
        // On a rerun the destination already has this time, but reading its
        // target can update it after the planner's initial stat (e.g. on XFS).
        run_ok(&["-aHU", &t.s("source/"), &t.s("destination/")]);
        assert_eq!(access_time(&t.path("destination/link")), expected);
    }
}

#[test]
fn access_times_survive_copy_updates_checksums_and_hardlinks() {
    let t = Tmp::new();
    write(&t.path("src/small"), b"small file");
    write(&t.path("src/nested/large"), &vec![43; 4 * 1024 * 1024]);
    fs::hard_link(t.path("src/nested/large"), t.path("src/alias")).unwrap();
    std::os::unix::fs::symlink("small", t.path("src/link")).unwrap();
    mkfifo(&t.path("src/fifo"));
    let paths = [
        "small",
        "nested/large",
        "alias",
        "link",
        "fifo",
        "nested",
        "",
    ];
    for phase in 0..4 {
        if phase == 1 {
            write(&t.path("src/small"), b"changed file");
        }
        let mut expected = Vec::new();
        for path in paths {
            set_access_time(
                &t.path(&format!("src/{path}")),
                1_000_000_000 + phase,
                123_456_789,
            );
            expected.push(access_time(&t.path(&format!("src/{path}"))));
        }
        let mut args = vec!["-aHU", "--performance-tuning=batch-bytes=64K"];
        if phase == 2 {
            args.push("--checksum");
        }
        if phase == 3 {
            args.pop(); // range copies do not use small-file batch controls
            args.extend([
                "--inplace",
                "--checksum",
                "--performance-tuning=copy-path=ranges",
            ]);
        }
        let src = t.s("src/");
        let dst = t.s("dst/");
        args.extend([src.as_str(), dst.as_str()]);
        run_ok(&args);
        // Verify timestamps before any content or readlink checks can change them.
        for (path, expected) in paths.iter().zip(expected) {
            assert_eq!(
                access_time(&t.path(&format!("dst/{path}"))),
                expected,
                "phase {phase}: {path}"
            );
        }
        assert_eq!(
            fs::metadata(t.path("dst/alias")).unwrap().ino(),
            fs::metadata(t.path("dst/nested/large")).unwrap().ino()
        );
        assert_eq!(
            read(&t.path("dst/small")),
            if phase == 0 {
                b"small file".as_slice()
            } else {
                b"changed file".as_slice()
            }
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn repeated_atimes_and_native_noatime_leave_source_file_access_time_unchanged() {
    let t = Tmp::new();
    write(&t.path("src/file"), &vec![29; 2 * 1024 * 1024]);
    for (index, options) in [
        vec!["-aUU"],
        vec![
            "-aUU",
            "--checksum",
            "--performance-tuning=copy-path=ranges",
        ],
    ]
    .iter()
    .enumerate()
    {
        set_access_time(&t.path("src/file"), 900_000_000 + index as i64, 321_000_000);
        let expected = access_time(&t.path("src/file"));
        let src = t.s("src/");
        let dst = t.s("dst/");
        let mut args = options.clone();
        args.extend([src.as_str(), dst.as_str()]);
        run_ok(&args);
        assert_eq!(access_time(&t.path("src/file")), expected);
        assert_eq!(access_time(&t.path("dst/file")), expected);
    }
    set_access_time(&t.path("src/file"), 800_000_000, 111_000_000);
    let expected = access_time(&t.path("src/file"));
    let output = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "cp",
            "--open-noatime",
            "--preserve=atimes",
            "--srcs-in",
            &t.s("src"),
            "--into",
            &t.s("native"),
            "--no-progress",
        ])
        .run()
        .unwrap();
    assert_output_ok(&output);
    assert_eq!(access_time(&t.path("src/file")), expected);
    assert_eq!(access_time(&t.path("native/file")), expected);
}

#[test]
fn access_times_are_opt_in_and_dry_run_does_not_restore_them() {
    let t = Tmp::new();
    write(&t.path("src/file"), b"same");
    set_access_time(&t.path("src/file"), 800_000_000, 0);
    let source_time = access_time(&t.path("src/file"));
    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    assert_ne!(access_time(&t.path("dst/file")), source_time);
    set_access_time(&t.path("src/file"), source_time.0, source_time.1);
    let destination_time = access_time(&t.path("dst/file"));
    run_ok(&["-aUn", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(access_time(&t.path("dst/file")), destination_time);
    run_ok(&["-aU", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(access_time(&t.path("dst/file")), source_time);
}

#[cfg(debug_assertions)]
#[test]
fn access_time_restored_after_lost_finalize_reply_and_resume() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    t.expose_remote_syq();
    let data = vec![31; 2 * 1024 * 1024];
    write(&t.path("src"), &data);
    set_access_time(&t.path("src"), 800_000_000, 333_000_000);
    let expected = access_time(&t.path("src"));
    let remote = format!("fake:{}", t.s("dst"));
    let marker = t.path("drop-finalize-once");
    let out = remote_syq_command(
        &t,
        &rsh,
        &[
            "-aU",
            "--syq-no-bootstrap",
            "--block-size=64K",
            &t.s("src"),
            &remote,
        ],
    )
    .env("SYQ_TEST_DROP_AFTER_REQUEST", "finalize")
    .env("SYQ_TEST_DROP_MARKER", &marker)
    .run()
    .unwrap();
    assert_output_ok(&out);
    assert!(marker.exists());
    assert_eq!(access_time(&t.path("dst")), expected);
    assert_eq!(read(&t.path("dst")), data);

    write(&t.path("small"), b"staged bytes");
    set_access_time(&t.path("small"), 700_000_000, 444_000_000);
    let args = ["-aUU", &t.s("small"), &t.s("resumed")];
    let out = compat_command()
        .args(args)
        .env("SYQ_TEST_FAIL_PUT_SMALL_BEFORE_RENAME", "resumed")
        .run()
        .unwrap();
    assert!(!out.status.success());
    assert!(!t.path("resumed").exists());
    assert!(!partial_files(&t.0).is_empty());
    // macOS cannot prevent the failed attempt from updating the source atime.
    // A rerun preserves the value observed at the start of that rerun.
    let expected = access_time(&t.path("small"));
    run_ok(&args);
    assert_eq!(access_time(&t.path("resumed")), expected);
    assert_eq!(read(&t.path("resumed")), b"staged bytes");
}

#[cfg(target_os = "linux")]
#[test]
fn birth_times_reject_linux_destination_before_creation() {
    let t = Tmp::new();
    write(&t.path("source"), b"data");
    let out = syq(&["-aN", &t.s("source"), &t.s("rsync-copy")]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr)
        .contains("birth-time preservation requires a macOS destination"));
    assert!(!t.path("rsync-copy").exists());
    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "cp",
            "--preserve=crtimes",
            &t.s("source"),
            "--as",
            &t.s("native-copy"),
        ])
        .run()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr)
        .contains("birth-time preservation requires a macOS destination"));
    assert!(!t.path("native-copy").exists());
}

#[cfg(target_os = "macos")]
fn set_birth_time(path: &Path, seconds: i64, nanos: i64) {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    let mut attributes = libc::attrlist {
        bitmapcount: libc::ATTR_BIT_MAP_COUNT as _,
        reserved: 0,
        commonattr: libc::ATTR_CMN_CRTIME,
        volattr: 0,
        dirattr: 0,
        fileattr: 0,
        forkattr: 0,
    };
    let mut time = libc::timespec {
        tv_sec: seconds as _,
        tv_nsec: nanos as _,
    };
    assert_eq!(
        unsafe {
            libc::setattrlist(
                path.as_ptr(),
                (&mut attributes as *mut libc::attrlist).cast(),
                (&mut time as *mut libc::timespec).cast(),
                std::mem::size_of_val(&time),
                libc::FSOPT_NOFOLLOW as _,
            )
        },
        0,
        "{}",
        std::io::Error::last_os_error()
    );
}

#[cfg(target_os = "macos")]
#[test]
fn birth_times_follow_mtime_and_survive_reruns_and_inode_types() {
    let t = Tmp::new();
    write(&t.path("src/nested/file"), &vec![37; 2 * 1024 * 1024]);
    write(&t.path("src/small"), b"small");
    fs::hard_link(t.path("src/nested/file"), t.path("src/alias")).unwrap();
    std::os::unix::fs::symlink("small", t.path("src/link")).unwrap();
    mkfifo(&t.path("src/fifo"));
    let paths = [
        "nested/file",
        "alias",
        "small",
        "link",
        "fifo",
        "nested",
        "",
    ];
    for phase in 0..3 {
        if phase == 1 {
            write(&t.path("src/small"), b"updated");
        }
        let mut expected = Vec::new();
        for path in paths {
            let path = t.path(&format!("src/{path}"));
            set_mtime(&path, 800_000_000 + phase);
            set_birth_time(&path, 1_000_000_000 + phase, 123_456_789);
            expected.push(fs::symlink_metadata(path).unwrap().created().unwrap());
        }
        let src = t.s("src/");
        let dst = t.s("dst/");
        let mut args = vec!["-aHUN", "--performance-tuning=batch-bytes=64K", &src, &dst];
        if phase == 2 {
            args.extend(["--checksum", "--inplace"]);
        }
        run_ok(&args);
        for (path, expected) in paths.iter().zip(expected) {
            assert_eq!(
                fs::symlink_metadata(t.path(&format!("dst/{path}")))
                    .unwrap()
                    .created()
                    .unwrap(),
                expected,
                "phase {phase}: {path}"
            );
        }
    }
}

#[test]
fn access_time_of_explicit_symlink_is_captured_before_reading_its_target() {
    let t = Tmp::new();
    std::os::unix::fs::symlink("missing", t.path("link")).unwrap();
    for native in [false, true] {
        set_access_time(&t.path("link"), 700_000_000, 123_456_789);
        let expected = access_time(&t.path("link"));
        let out = if native {
            Command::new(env!("CARGO_BIN_EXE_syq"))
                .args([
                    "cp",
                    "--preserve=atimes",
                    &t.s("link"),
                    "--as",
                    &t.s("native-link"),
                ])
                .run()
                .unwrap()
        } else {
            syq(&["-lU", &t.s("link"), &t.s("rsync-link")])
        };
        assert_output_ok(&out);
        assert_eq!(
            access_time(&t.path(if native { "native-link" } else { "rsync-link" })),
            expected
        );
    }
}

#[cfg(debug_assertions)]
#[test]
fn incompatible_acl_models_are_rejected_before_destination_creation() {
    let t = Tmp::new();
    fs::create_dir(t.path("source")).unwrap();
    let rsh = fake_rsh(&t);
    t.expose_remote_syq();
    let remote = format!("fake:{}", t.s("destination"));
    let other = if cfg!(target_os = "macos") {
        "linux-x86_64"
    } else {
        "macos-aarch64"
    };
    let output = remote_syq_command(
        &t,
        &rsh,
        &["-aA", "--syq-no-bootstrap", &t.s("source/"), &remote],
    )
    .env("FAKE_REMOTE_PLATFORM", other)
    .run()
    .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("ACL conversion is unsupported"),
        "{output:?}"
    );
    assert!(!t.path("destination").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn inplace_local_copy_finalizes_a_new_readonly_file() {
    let t = Tmp::new();
    let data = prng(2 << 20, 94);
    write(&t.path("source"), &data);
    fs::set_permissions(t.path("source"), fs::Permissions::from_mode(0o400)).unwrap();
    set_mtime(&t.path("source"), 1_577_934_245);
    let args = ["-a", "--inplace", &t.s("source"), &t.s("destination")];
    run_ok(&args);
    assert_eq!(read(&t.path("destination")), data);
    let metadata = fs::metadata(t.path("destination")).unwrap();
    assert_eq!(metadata.mode() & 0o7777, 0o400);
    assert_eq!(metadata.mtime(), 1_577_934_245);

    // Keeping the creation descriptor must not bypass write permissions on
    // an existing destination in a later invocation.
    fs::set_permissions(t.path("destination"), fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(t.path("destination"), b"existing read-only data").unwrap();
    fs::set_permissions(t.path("destination"), fs::Permissions::from_mode(0o400)).unwrap();
    let output = syq(&args);
    if unsafe { libc::geteuid() } != 0 {
        assert!(!output.status.success());
        assert_eq!(read(&t.path("destination")), b"existing read-only data");
    } else {
        assert_output_ok(&output);
        assert_eq!(read(&t.path("destination")), data);
    }
}

#[test]
fn checksum_inplace_rerun_accepts_matching_readonly_destination() {
    let t = Tmp::new();
    let data = prng(2 << 20, 95);
    write(&t.path("source"), &data);
    write(&t.path("destination"), &data);
    for name in ["source", "destination"] {
        fs::set_permissions(t.path(name), fs::Permissions::from_mode(0o400)).unwrap();
        set_mtime(&t.path(name), 1_577_934_245);
    }
    let inode = fs::metadata(t.path("destination")).unwrap().ino();
    run_ok(&["-ac", "--inplace", &t.s("source"), &t.s("destination")]);
    assert_eq!(read(&t.path("destination")), data);
    let metadata = fs::metadata(t.path("destination")).unwrap();
    assert_eq!(metadata.ino(), inode);
    assert_eq!(metadata.mode() & 0o7777, 0o400);
    assert_eq!(metadata.mtime(), 1_577_934_245);
}

fn check_new_readonly_inplace_copy(native: bool, fallback: bool, umask: libc::mode_t) {
    let t = Tmp::new();
    fs::create_dir(t.path("dst")).unwrap();
    let data = prng(16 << 20, 96);
    // Two files also cover the cached unsupported-filesystem result after
    // the first CopyLocal probe falls back to ranges.
    for name in ["a", "b"] {
        let path = t.path(&format!("src/{name}"));
        write(&path, &data);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        set_mtime(&path, 1_577_934_245);
    }
    let mut command = if native {
        let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
        command.args([
            "cp",
            "--no-tcp",
            "--srcs-in",
            &t.s("src"),
            "--into",
            &t.s("dst"),
        ]);
        command
    } else {
        let mut command = compat_command();
        command.args(["-a", "--syq-no-tcp", &t.s("src/"), &t.s("dst/")]);
        command
    };
    command.args([
        "--inplace",
        "--performance-tuning=comparison-block-size=1M",
        "--no-progress",
    ]);
    if fallback {
        command
            .arg("--performance-tuning=workers=1")
            .env("SYQ_TEST_COPY_LOCAL_EXDEV", "1")
            .env("SYQ_TEST_COPY_LOCAL_FS", "unsupported");
    } else {
        command.arg("--performance-tuning=copy-path=ranges,workers=4,split-min-size=1M");
    }
    // Set only the child umask; other tests keep their process-wide setting.
    unsafe {
        command.pre_exec(move || {
            libc::umask(umask);
            Ok(())
        });
    }
    let output = command.env("SYQ_DEBUG", "1").run().unwrap();
    assert_output_ok(&output);
    let observed = tuning_observed(&output);
    assert_eq!(observed["local_whole_files"], 0);
    assert!(observed["range_requests"].as_u64().unwrap() > 1);
    for name in ["a", "b"] {
        let destination = t.path(&format!("dst/{name}"));
        assert_eq!(read(&destination), data);
        let metadata = fs::metadata(&destination).unwrap();
        assert_eq!(metadata.mode() & 0o7777, 0o400);
        assert_eq!(metadata.mtime(), 1_577_934_245);
    }
    // Temporary write permission belongs only to fresh files. A later copy
    // cannot use it to overwrite an existing read-only destination.
    fs::set_permissions(t.path("src/a"), fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(t.path("src/a"), b"changed source").unwrap();
    if unsafe { libc::geteuid() } != 0 {
        let output = command.run().unwrap();
        assert!(!output.status.success(), "{output:?}");
        assert_eq!(read(&t.path("dst/a")), data);
        assert_eq!(
            fs::metadata(t.path("dst/a")).unwrap().mode() & 0o7777,
            0o400
        );
    }
}

#[test]
fn inplace_ranges_create_readonly_files_with_parallel_writers() {
    for native in [false, true] {
        for umask in [0o022, 0o222] {
            check_new_readonly_inplace_copy(native, false, umask);
        }
    }
}

#[cfg(all(debug_assertions, target_os = "linux"))]
#[test]
fn inplace_copy_local_fallback_creates_readonly_files() {
    for native in [false, true] {
        for umask in [0o022, 0o222] {
            check_new_readonly_inplace_copy(native, true, umask);
        }
    }
}

#[test]
fn rsync_new_remote_files_use_receiver_umask() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    let wrapper = t.path("receiver");
    executable(
        &wrapper,
        format!(
            "#!/bin/sh\numask 077\nexec '{}' \"$@\"\n",
            env!("CARGO_BIN_EXE_syq")
        )
        .as_bytes(),
    );
    write(&t.path("src/file"), &prng(2 << 20, 772));
    write(&t.path("src/program"), b"program");
    fs::set_permissions(t.path("src/file"), fs::Permissions::from_mode(0o666)).unwrap();
    fs::set_permissions(t.path("src/program"), fs::Permissions::from_mode(0o777)).unwrap();
    let mut command = remote_syq_command(
        &t,
        &rsh,
        &[
            "-r",
            "--rsync-path",
            wrapper.to_str().unwrap(),
            &t.s("src/file"),
            &t.s("src/program"),
            &format!("fake:{}/", t.s("dst")),
        ],
    );
    unsafe {
        command.pre_exec(|| {
            libc::umask(0o022);
            Ok(())
        });
    }
    assert_output_ok(&command.run().unwrap());
    for (name, mode) in [("", 0o700), ("file", 0o600), ("program", 0o700)] {
        assert_eq!(
            fs::metadata(t.path(&format!("dst/{name}"))).unwrap().mode() & 0o777,
            mode,
            "{name}"
        );
    }
    assert_eq!(read(&t.path("dst/file")), read(&t.path("src/file")));
}

#[test]
fn native_mtime_opt_out_keeps_write_times_and_other_preservation() {
    let t = Tmp::new();
    write(&t.path("src/nested/file"), b"contents");
    fs::create_dir_all(t.path("src/empty")).unwrap();
    std::os::unix::fs::symlink("nested/file", t.path("src/link")).unwrap();
    for path in [
        "src",
        "src/nested",
        "src/nested/file",
        "src/empty",
        "src/link",
    ] {
        set_mtime(&t.path(path), 123);
    }
    fs::set_permissions(t.path("src/nested/file"), fs::Permissions::from_mode(0o600)).unwrap();
    for (dest, option, preserved) in [
        ("default", "--preserve=permissions", true),
        ("disabled", "--preserve=permissions,-mtime", false),
    ] {
        run_native_ok(&["cp", &t.s("src"), "--as", &t.s(dest), option]);
        for path in ["", "/nested", "/nested/file", "/empty", "/link"] {
            let m = fs::symlink_metadata(t.path(&format!("{dest}{path}"))).unwrap();
            assert_eq!(m.mtime() == 123, preserved, "{dest}{path}");
        }
        assert_eq!(
            fs::metadata(t.path(&format!("{dest}/nested/file")))
                .unwrap()
                .mode()
                & 0o777,
            0o600
        );
    }
    // Content-based no-op copies must not restore the disabled timestamp either.
    set_mtime(&t.path("disabled/nested/file"), 456);
    run_native_ok(&[
        "cp",
        &t.s("src/nested/file"),
        "--as",
        &t.s("disabled/nested/file"),
        "--hash",
        "--preserve=-mtime",
    ]);
    assert_eq!(
        fs::metadata(t.path("disabled/nested/file"))
            .unwrap()
            .mtime(),
        456
    );
}

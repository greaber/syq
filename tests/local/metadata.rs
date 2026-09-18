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

// The read-only modes create nothing, not even the destination directory.
#[test]
fn readonly_modes_create_nothing() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"data");
    let out = syq(&["-a", "--syq-verify-only", &t.s("src/"), &t.s("dst/")]);
    assert!(
        !t.path("dst").exists(),
        "--syq-verify-only must not create the destination"
    );
    assert!(!out.status.success(), "everything is missing");
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
        .output()
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
        .output()
        .expect("run descriptor-copy fixture");
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

use super::*;

#[test]
fn native_hash_repairs_equal_metadata_content_mismatches() {
    let t = Tmp::new();
    let expected = vec![b'a'; 5 * 1024 * 1024];
    let mut corrupted = expected.clone();
    corrupted[2_500_000] = b'b';
    write(&t.path("src/file"), &expected);
    set_mtime(&t.path("src/file"), 1_600_000_000);

    for (prune, destination) in [(false, "copied"), (true, "pruned")] {
        write(&t.path(&format!("{destination}/file")), &corrupted);
        set_mtime(&t.path(&format!("{destination}/file")), 1_600_000_000);
        if prune {
            write(&t.path(&format!("{destination}/extra")), b"remove");
        }

        let source = t.s("src");
        let target = t.s(destination);
        let mut args = vec!["cp"];
        if prune {
            args.push("--prune");
        }
        args.extend(["--srcs-in", &source, "--into-existing", &target]);
        run_native_ok(&args);
        assert_eq!(read(&t.path(&format!("{destination}/file"))), corrupted);
        if prune {
            write(&t.path(&format!("{destination}/extra")), b"remove");
        }

        args.insert(1, "--hash");
        run_native_ok(&args);
        assert_eq!(read(&t.path(&format!("{destination}/file"))), expected);
        if prune {
            assert!(!t.path(&format!("{destination}/extra")).exists());
        }
    }
}

#[test]
fn checksum_repairs_silent_corruption() {
    let t = Tmp::new();
    let data = prng(5 * 1024 * 1024, 7);
    write(&t.path("src/f.bin"), &data);
    set_mtime(&t.path("src/f.bin"), 1_600_000_000);
    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    // Corrupt one byte in the middle, keeping size and mtime.
    let mut bad = data.clone();
    bad[2_500_000] ^= 0xff;
    write(&t.path("dst/f.bin"), &bad);
    set_mtime(&t.path("dst/f.bin"), 1_600_000_000);

    let out = run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(transferred(&out), 0, "quick check should skip: {out}");
    assert!(
        read(&t.path("dst/f.bin")) == bad,
        "without -c the file must be left alone"
    );

    let out = run_ok(&["-ac", "-B1M", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(transferred(&out), 1, "{out}");
    assert!(read(&t.path("dst/f.bin")) == data, "-c should repair");
    assert!(
        out.contains("(1.00 MiB)"),
        "only one block should be resent: {out}"
    );
    assert_same_tree(&t.path("src"), &t.path("dst"));
}

#[test]
#[cfg(debug_assertions)]
fn hash_policy_verify_only_expected_mismatch_exits() {
    let t = Tmp::new();
    write(&t.path("source"), b"abc");
    write(&t.path("destination"), b"abc");
    let child = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "cp",
            &t.s("source"),
            "--as",
            &t.s("destination"),
            "--verify-only",
            "--expected-hash",
            "md5:00000000000000000000000000000000",
            "--results",
            &t.s("results.ndjson"),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .start()
        .unwrap();
    let output = wait_for_control_path_output(child);
    assert_eq!(output.status.code(), Some(23), "{}", stderr_of(&output));
    assert!(
        stderr_of(&output).contains("expected md5 hash"),
        "{}",
        stderr_of(&output)
    );
    assert_eq!(read(&t.path("destination")), b"abc");
    let records = fs::read_to_string(t.path("results.ndjson")).unwrap();
    let terminal: serde_json::Value =
        serde_json::from_str(records.lines().last().unwrap()).unwrap();
    assert_eq!(terminal["type"], "result");
    assert_eq!(terminal["status"], "partial");
}

#[test]
fn hash_policy_independent_compare_and_payload_hashes_cross_transports() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    let data = prng(5 * 1024 * 1024 + 13, 999);
    write(&t.path("source"), &data);
    for tcp in [false, true] {
        for path in ["ranges", "streaming"] {
            let destination = format!("destination-{tcp}-{path}");
            let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
            command.args([
                "cp",
                &t.s("source"),
                "--to",
                "fake",
                "--as",
                &t.s(&destination),
                "--rsh",
                rsh.to_str().unwrap(),
                "--syq-path",
                env!("CARGO_BIN_EXE_syq"),
                "--performance-tuning",
                &format!("workers=2,copy-path={path}"),
                "--integrity-checking=compare=xxh3-128,transfer=sha256",
                "--tcp-ports",
                EPHEMERAL_TCP_PORTS,
                "--no-progress",
            ]);
            if !tcp {
                command.arg("--no-tcp");
            }
            let output = command.run().unwrap();
            assert_output_ok(&output);
            assert!(read(&t.path(&destination)) == data);
        }
    }
}

#[test]
fn hash_policy_independent_hashes_reuse_unchanged_blocks() {
    let t = Tmp::new();
    // Three default 4 MiB hash blocks; only the last block differs.
    let contents = prng(12 << 20, 1000);
    write(&t.path("source"), &contents);
    for (compare, transfer) in [("blake3", "sha256"), ("xxh3-128", "blake3")] {
        let results = t.s(&format!("results-{compare}-{transfer}.ndjson"));
        let mut previous = contents.clone();
        *previous.last_mut().unwrap() ^= 1;
        write(&t.path("destination"), &previous);
        let output = native_syq(&[
            "cp",
            &t.s("source"),
            "--as",
            &t.s("destination"),
            "--performance-tuning=workers=1,copy-path=ranges",
            &format!("--integrity-checking=compare={compare},transfer={transfer}"),
            "--results",
            &results,
        ]);
        assert_output_ok(&output);
        assert_eq!(read(&t.path("destination")), contents);
        let records = fs::read_to_string(results).unwrap();
        let summary: serde_json::Value =
            serde_json::from_str(records.lines().last().unwrap()).unwrap();
        assert_eq!(summary["bytes_transferred"], 4 << 20, "{summary}");
        assert_eq!(summary["bytes_unchanged"], 8 << 20, "{summary}");
    }
}

#[test]
fn hash_policy_expected_match_skips_copy_and_repairs_corruption() {
    let t = Tmp::new();
    write(&t.path("source"), b"abc");
    write(&t.path("destination"), b"abc");
    set_mtime(&t.path("source"), 1_700_000_000);
    set_mtime(&t.path("destination"), 1_700_000_000);
    fs::set_permissions(t.path("source"), fs::Permissions::from_mode(0o640)).unwrap();
    fs::set_permissions(t.path("destination"), fs::Permissions::from_mode(0o600)).unwrap();
    let inode = fs::metadata(t.path("destination")).unwrap().ino();
    let copy = |results: &str| {
        let output = native_syq(&[
            "cp",
            &t.s("source"),
            "--as",
            &t.s("destination"),
            "--preserve=permissions",
            "--expected-hash",
            "md5:900150983cd24fb0d6963f7d28e17f72",
            "--results",
            &t.s(results),
        ]);
        assert_output_ok(&output);
        let records = fs::read_to_string(t.path(results)).unwrap();
        serde_json::from_str::<serde_json::Value>(records.lines().last().unwrap()).unwrap()
    };
    let summary = copy("match.jsonl");
    assert_eq!(summary["files_unchanged"], 1);
    assert_eq!(summary["bytes_transferred"], 0);
    let metadata = fs::metadata(t.path("destination")).unwrap();
    assert_eq!(metadata.ino(), inode, "matching destination was replaced");
    assert_eq!(metadata.mode() & 0o777, 0o640);
    // Equal size and mtime must not hide differing bytes.
    write(&t.path("destination"), b"bad");
    set_mtime(&t.path("destination"), 1_700_000_000);
    let summary = copy("repair.jsonl");
    assert_eq!(summary["bytes_transferred"], 3);
    assert_eq!(read(&t.path("destination")), b"abc");
    // --hash must still compare source contents even when the expectation
    // matches the destination and metadata agrees.
    write(&t.path("source"), b"bad");
    set_mtime(&t.path("source"), 1_700_000_000);
    let output = native_syq(&[
        "cp",
        "--hash",
        &t.s("source"),
        "--as",
        &t.s("destination"),
        "--expected-hash",
        "md5:900150983cd24fb0d6963f7d28e17f72",
    ]);
    assert_eq!(output.status.code(), Some(23), "{}", stderr_of(&output));
    assert_eq!(read(&t.path("destination")), b"abc");
}

#[cfg(all(debug_assertions, any(target_os = "linux", target_os = "macos")))]
#[test]
fn hash_policy_integrity_preserves_local_copy_and_expected_validation() {
    #[cfg(target_os = "macos")]
    if !macos_clone_support::available() {
        return;
    }
    let t = Tmp::new();
    let contents = prng(5 << 20, 993);
    write(&t.path("source"), &contents);
    let correct = format!("blake3:{}", blake3::hash(&contents).to_hex());
    let wrong = format!("blake3:{}", "0".repeat(64));
    for (name, expected, succeeds) in [
        ("plain", None, true),
        ("expected", Some(correct.as_str()), true),
        ("mismatch", Some(wrong.as_str()), false),
    ] {
        write(&t.path(name), b"previous contents");
        let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
        command.args([
            "cp",
            &t.s("source"),
            "--as",
            &t.s(name),
            "--integrity-checking=transfer=xxh3-128",
        ]);
        if let Some(expected) = expected {
            command.args(["--expected-hash", expected]);
        }
        let output = command
            .env("SYQ_DEBUG", "1")
            .env("SYQ_TEST_FAIL_READ_RANGE", "1")
            .run()
            .unwrap();
        if succeeds {
            assert_output_ok(&output);
            assert_eq!(read(&t.path(name)), contents);
            let observed = tuning_observed(&output);
            assert_eq!(observed["local_whole_files"], 1);
            assert_eq!(observed["range_requests"], 0);
        } else {
            assert_eq!(output.status.code(), Some(23), "{}", stderr_of(&output));
            assert!(
                stderr_of(&output).contains("expected blake3 hash"),
                "{}",
                stderr_of(&output)
            );
            assert_eq!(read(&t.path(name)), b"previous contents");
        }
    }
}

#[test]
fn hash_policy_expected_mismatch_preserves_destination() {
    for size in [3, 5 * 1024 * 1024] {
        let t = Tmp::new();
        write(&t.path("source"), &vec![b'n'; size]);
        write(&t.path("destination"), b"previous contents");
        let output = native_syq(&[
            "cp",
            "--src",
            &t.s("source"),
            "--as",
            &t.s("destination"),
            "--expected-hash",
            "md5:00000000000000000000000000000000",
            "--results",
            &t.s("results.ndjson"),
        ]);
        assert_eq!(output.status.code(), Some(23), "{}", stderr_of(&output));
        assert!(
            stderr_of(&output).contains("expected"),
            "{}",
            stderr_of(&output)
        );
        assert_eq!(read(&t.path("destination")), b"previous contents");
        let results = fs::read_to_string(t.path("results.ndjson")).unwrap();
        assert_automation_stream(
            &automation_validator(),
            &results,
            "expected digest mismatch",
        );
        let failed: serde_json::Value = results
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .find(|record| {
                record["type"] == "operation_result" && record["disposition"] == "failed"
            })
            .unwrap();
        assert_eq!(
            failed["expected_digest"],
            serde_json::json!({"algorithm": "md5", "value": "0".repeat(32)})
        );
    }
}

#[test]
fn hash_policy_expected_empty_file_is_checked_before_publication() {
    let t = Tmp::new();
    write(&t.path("empty"), b"");
    run_native_ok(&[
        "cp",
        "--src",
        &t.s("empty"),
        "--as",
        &t.s("good"),
        "--expected-hash",
        "md5:d41d8cd98f00b204e9800998ecf8427e",
        "--integrity-checking",
        "compare=xxh3-128",
        "--integrity-checking=transfer=blake3",
    ]);
    assert_eq!(read(&t.path("good")), b"");
    let output = native_syq(&[
        "cp",
        "--src",
        &t.s("empty"),
        "--as",
        &t.s("bad"),
        "--expected-hash",
        "md5:00000000000000000000000000000000",
    ]);
    assert_eq!(output.status.code(), Some(23), "{}", stderr_of(&output));
    assert!(
        !t.path("bad").exists(),
        "a mismatching empty file must not be published"
    );
}

#[test]
fn hash_policy_xxh3_compares_repairs_and_verifies() {
    let t = Tmp::new();
    let contents = prng(5 * 1024 * 1024, 992);
    let mut bad = contents.clone();
    bad[1_234_567] ^= 1;
    write(&t.path("source"), &contents);
    write(&t.path("destination"), &bad);
    set_mtime(&t.path("source"), 1_600_000_000);
    set_mtime(&t.path("destination"), 1_600_000_000);
    // The default metadata comparison cannot detect this same-size, same-time edit.
    run_native_ok(&["cp", "--src", &t.s("source"), "--as", &t.s("destination")]);
    assert_eq!(read(&t.path("destination")), bad);
    run_native_ok(&[
        "cp",
        "--src",
        &t.s("source"),
        "--as",
        &t.s("destination"),
        "--integrity-checking",
        "compare=xxh3-128",
        "--integrity-checking=transfer=blake3",
    ]);
    assert_eq!(read(&t.path("destination")), contents);
    run_native_ok(&[
        "cp",
        "--verify-only",
        "--src",
        &t.s("source"),
        "--as",
        &t.s("destination"),
        "--integrity-checking",
        "compare=xxh3-128",
    ]);
    write(&t.path("destination"), &bad);
    let output = native_syq(&[
        "cp",
        "--verify-only",
        "--src",
        &t.s("source"),
        "--as",
        &t.s("destination"),
        "--integrity-checking",
        "compare=xxh3-128",
    ]);
    assert_eq!(output.status.code(), Some(23), "{}", stderr_of(&output));
    assert_eq!(
        read(&t.path("destination")),
        bad,
        "verification must not repair"
    );
}

#[test]
fn verify_only_detects_differences() {
    let t = Tmp::new();
    make_tree(&t.path("src"));
    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    let out = syq(&["-a", "--syq-verify-only", &t.s("src/"), &t.s("dst/")]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let mut bad = read(&t.path("dst/a/med.bin"));
    bad[1000] ^= 1;
    write(&t.path("dst/a/med.bin"), &bad);
    set_mtime(
        &t.path("dst/a/med.bin"),
        fs::metadata(t.path("src/a/med.bin")).unwrap().mtime(),
    );
    fs::remove_file(t.path("dst/hello.txt")).unwrap();

    let out = syq(&["-a", "--syq-verify-only", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(out.status.code(), Some(23));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("DIFFERS a/med.bin"), "{err}");
    assert!(err.contains("MISSING hello.txt"), "{err}");
    // verify-only must not modify anything
    assert!(read(&t.path("dst/a/med.bin")) == bad);
    assert!(!t.path("dst/hello.txt").exists());
}

#[test]
fn checksum_repair_shrinks_longer_destination() {
    let t = Tmp::new();
    write(&t.path("src"), b"abc");
    write(&t.path("dst"), b"ABCDEFG");
    set_mtime(&t.path("dst"), 1_000_000_000);
    set_mtime(&t.path("src"), 1_000_000_000);
    run_ok(&["-ac", &t.s("src"), &t.s("dst")]);
    assert_eq!(read(&t.path("dst")), b"abc");
}

#[test]
fn quick_skipped_file_still_claims_destination() {
    let t = Tmp::new();
    write(&t.path("A/x"), b"aaa"); // A/x is a file
    write(&t.path("B/x/y"), b"yyy"); // B/x is a directory
                                     // Pre-populate dest/x identical to A/x so A/x is quick-skipped.
    write(&t.path("dest/x"), b"aaa");
    set_mtime(&t.path("A/x"), 1_000_000_000);
    set_mtime(&t.path("dest/x"), 1_000_000_000);
    let out = syq(&[
        "-a",
        &format!("{}/", t.s("A")),
        &format!("{}/", t.s("B")),
        &format!("{}/", t.s("dest")),
    ]);
    // The skipped file must still claim dest/x, so B's directory is rejected.
    assert!(
        !out.status.success(),
        "quick-skipped file must still block a colliding directory"
    );
}

#[test]
fn verify_only_flags_missing_directory() {
    let t = Tmp::new();
    write(&t.path("s/sub/f"), b"f");
    fs::create_dir_all(t.path("d")).unwrap(); // d exists but d/sub does not
    let out = syq(&[
        "-a",
        "--syq-verify-only",
        &format!("{}/", t.s("s")),
        &format!("{}/", t.s("d")),
    ]);
    assert_eq!(out.status.code(), Some(23));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("MISSING")
            && String::from_utf8_lossy(&out.stderr)
                .to_lowercase()
                .contains("director")
    );
}

#[test]
fn verify_only_flags_missing_special() {
    let t = Tmp::new();
    fs::create_dir_all(t.path("s")).unwrap();
    fs::create_dir_all(t.path("d")).unwrap();
    // create a fifo in the source
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(t.path("s/pipe").as_os_str().as_bytes()).unwrap();
    unsafe {
        assert_eq!(libc::mkfifo(c.as_ptr(), 0o644), 0);
    }
    let out = syq(&[
        "-a",
        "--syq-verify-only",
        &format!("{}/", t.s("s")),
        &format!("{}/", t.s("d")),
    ]);
    assert_eq!(out.status.code(), Some(23));
    assert!(String::from_utf8_lossy(&out.stderr).contains("special"));
}

/// Quick checks use the scan-time snapshot in both transfer paths, even if
/// the source changes while the receiver is repairing destination metadata.
#[cfg(debug_assertions)]
#[test]
fn small_push_quick_check_uses_the_same_source_snapshot_as_the_engine() {
    for engine in [false, true] {
        let t = Tmp::new();
        let ssh = fake_ssh(&t);
        write(&t.path("source"), b"old");
        write(&t.path("remote-home/dest/source"), b"old");
        for path in ["source", "remote-home/dest/source"] {
            set_mtime(&t.path(path), 1_700_000_000);
        }
        fs::set_permissions(t.path("source"), fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(
            t.path("remote-home/dest/source"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        let ready = t.path("ready");
        let continuation = t.path("continue");
        let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
        command
            .args([
                "cp",
                "--syq-path",
                env!("CARGO_BIN_EXE_syq"),
                "--preserve=permissions",
                "--no-progress",
            ])
            .arg(t.path("source"))
            .args(["--to", "fake.example", "--into", &t.s("remote-home/dest")])
            .args(["--results", &t.s("results.ndjson")])
            .env("XDG_CONFIG_HOME", t.path("config"))
            .env("FAKE_REMOTE_HOME", t.path("remote-home"))
            .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
            .env("FAKE_RSH_LOG", t.path("rsh.log"))
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", ssh.parent().unwrap().display()),
            )
            .env("SYQ_TEST_QUICK_META_READY_FILE", &ready)
            .env("SYQ_TEST_QUICK_META_CONTINUE_FILE", &continuation)
            .env("SYQ_DEBUG", "1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if engine {
            command.env("SYQ_TEST_DISABLE_SMALL_COPY", "1");
        }
        let mut child = command.start().unwrap();
        wait_for_confinement_marker(&mut child, &ready, "quick metadata repair");
        write(&t.path("source"), b"new contents");
        set_mtime(&t.path("source"), 1_700_000_001);
        release_confinement_barrier(&continuation);
        let output = child.wait_with_output().unwrap();
        assert_output_ok(&output);
        assert_eq!(read(&t.path("remote-home/dest/source")), b"old");
        assert_eq!(
            fs::metadata(t.path("remote-home/dest/source"))
                .unwrap()
                .mode()
                & 0o7777,
            0o600
        );
        let records: Vec<serde_json::Value> = fs::read_to_string(t.path("results.ndjson"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let terminal = records.last().unwrap();
        assert_eq!(terminal["files_unchanged"], 1);
        assert_eq!(terminal["bytes_unchanged"], 3);
        assert_eq!(terminal["files_transferred"], 0);
        assert_eq!(terminal["errors"], 0);
        assert!(!records
            .iter()
            .any(|record| record["type"] == "operation_result"));
        assert_eq!(
            stderr_of(&output).contains("small copy: published"),
            !engine
        );
    }
}

#[test]
fn files_from_treats_hash_and_semicolon_entries_as_comments() {
    let t = Tmp::new();
    for f in ["ordinary", "#literal", ";literal"] {
        write(&t.path("src").join(f), f.as_bytes());
    }

    // A comment-looking name is still reachable through an explicit `./`.
    write(
        &t.path("list"),
        b"# ignored\n; ignored too\nordinary\n./#literal\n./;literal\n",
    );
    run_ok(&["-a", "--files-from", &t.s("list"), &t.s("src"), &t.s("dst")]);
    assert_eq!(
        listing(&t.path("dst")),
        ["#literal", ";literal", "ordinary"]
    );

    // rsync applies the same comment rule when entries are NUL-separated.
    write(
        &t.path("list0"),
        b"# ignored\0; ignored too\0ordinary\0./#literal\0./;literal\0",
    );
    run_ok(&[
        "-a",
        "--from0",
        "--files-from",
        &t.s("list0"),
        &t.s("src"),
        &t.s("dst0"),
    ]);
    assert_eq!(
        listing(&t.path("dst0")),
        ["#literal", ";literal", "ordinary"]
    );
}

// Repairing metadata on an unreadable destination file needs a Linux
// `O_PATH` handle; macOS cannot open the file at all and reports the error.
#[cfg(target_os = "linux")]
#[test]
fn quick_check_repairs_mode_without_destination_read_permission() {
    let t = Tmp::new();
    write(&t.path("src"), b"same contents");
    write(&t.path("dst"), b"same contents");
    fs::set_permissions(t.path("src"), fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o000)).unwrap();
    set_mtime(&t.path("src"), 1_600_000_000);
    set_mtime(&t.path("dst"), 1_600_000_000);

    let output = run_ok(&["-a", &t.s("src"), &t.s("dst")]);

    assert_eq!(transferred(&output), 0, "{output}");
    assert_eq!(fs::metadata(t.path("dst")).unwrap().mode() & 0o777, 0o600);
    assert_eq!(read(&t.path("dst")), b"same contents");
}

#[test]
fn checksum_identical_file_preserves_destination_inode() {
    let t = Tmp::new();
    let contents = vec![b'a'; 8 * 1024 * 1024];
    write(&t.path("src"), &contents);
    write(&t.path("dst"), &contents);
    fs::hard_link(t.path("dst"), t.path("alias")).unwrap();
    fs::set_permissions(t.path("src"), fs::Permissions::from_mode(0o600)).unwrap();
    set_mtime(&t.path("src"), 1_600_000_001);
    set_mtime(&t.path("dst"), 1_600_000_000);
    let before = fs::metadata(t.path("dst")).unwrap();

    let output = run_ok(&[
        "-ac",
        "--resource-limits",
        "bandwidth=1G",
        &t.s("src"),
        &t.s("dst"),
    ]);

    assert_eq!(transferred(&output), 0, "{output}");
    let after = fs::metadata(t.path("dst")).unwrap();
    assert_eq!(after.dev(), before.dev());
    assert_eq!(after.ino(), before.ino());
    assert_eq!(fs::metadata(t.path("alias")).unwrap().ino(), before.ino());
    assert_eq!(after.mode() & 0o777, 0o600);
    assert_eq!(after.mtime(), 1_600_000_001);
    assert!(partial_files(&t.0).is_empty());
}

#[test]
fn verify_only_checks_the_filtered_scope() {
    let t = Tmp::new();
    write(&t.path("src/big"), b"abc");
    write(&t.path("dst/big"), b"xyz");
    let out = syq(&["-a", "--syq-verify-only", &t.s("src/"), &t.s("dst")]);
    assert_eq!(out.status.code(), Some(23));
    let so = run_ok(&[
        "-a",
        "--syq-verify-only",
        "--max-size",
        "1",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert!(so.contains("verified 0 files"), "{so}");
    set_mtime(&t.path("src/big"), 1000);
    set_mtime(&t.path("dst/big"), 2000);
    let so = run_ok(&["-a", "--syq-verify-only", "-u", &t.s("src/"), &t.s("dst")]);
    assert!(so.contains("verified 0 files"), "{so}");
}

#[test]
fn native_verify_only_compares_contents_without_mutations() {
    let t = Tmp::new();
    write(&t.path("src/same"), b"same");
    write(&t.path("src/different"), b"AAAA");
    write(&t.path("src/missing"), b"missing");
    fs::create_dir_all(t.path("src/empty")).unwrap();
    std::os::unix::fs::symlink("same", t.path("src/link")).unwrap();
    write(&t.path("dst/same"), b"same");
    write(&t.path("dst/different"), b"BBBB");
    write(&t.path("dst/extra"), b"extra");
    std::os::unix::fs::symlink("different", t.path("dst/link")).unwrap();
    for path in ["src/same", "src/different", "dst/same", "dst/different"] {
        set_mtime(&t.path(path), 1_600_000_000);
    }
    let before = fs::metadata(t.path("dst/different")).unwrap();
    let out = native_syq(&[
        "cp",
        "--verify-only",
        "--stats",
        "--srcs-in",
        &t.s("src"),
        "--into",
        &t.s("dst"),
        "--results",
        &t.s("results"),
    ]);
    assert_eq!(out.status.code(), Some(23), "{}", stderr_of(&out));
    assert!(stderr_of(&out).contains("DIFFERS"));
    assert!(stderr_of(&out).contains("MISSING"));
    assert_eq!(read(&t.path("dst/different")), b"BBBB");
    assert_eq!(read(&t.path("dst/extra")), b"extra");
    assert!(!t.path("dst/missing").exists());
    assert!(!t.path("dst/empty").exists());
    assert_eq!(
        fs::read_link(t.path("dst/link")).unwrap(),
        Path::new("different")
    );
    let after = fs::metadata(t.path("dst/different")).unwrap();
    assert_eq!(
        (before.ino(), before.mtime(), before.mode()),
        (after.ino(), after.mtime(), after.mode())
    );
    let records: Vec<serde_json::Value> = fs::read_to_string(t.path("results"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../schemas/automation.schema.json")).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    for record in &records {
        assert!(
            validator.is_valid(record),
            "invalid verification record: {record}"
        );
    }
    assert_eq!(records[0]["verify_only"], true);
    let result = records.last().unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(result["files_transferred"], 0);
    assert_eq!(result["bytes_transferred"], 0);
    assert_eq!(result["files_unchanged"], 1);
    assert_eq!(result["bytes_unchanged"], 4);
    assert_eq!(result["directories_created"], 0);
    assert_eq!(result["symlinks_created"], 0);
    assert!(!records.iter().any(|r| r["type"] == "operation_result"));

    // Filtering is selection, not verification of the entire destination tree.
    let filtered = native_syq(&[
        "cp",
        "--verify-only",
        "--ignore",
        "different",
        "--ignore",
        "missing",
        "--ignore",
        "empty",
        "--ignore",
        "link",
        "--srcs-in",
        &t.s("src"),
        "--into",
        &t.s("dst"),
    ]);
    assert_output_ok(&filtered);

    // A missing destination container must not be created, even for an exact placement.
    for placement in ["--into", "--as"] {
        let out = native_syq(&[
            "cp",
            "--verify-only",
            &t.s("src"),
            placement,
            &t.s("absent"),
        ]);
        assert!(!out.status.success());
        assert!(!t.path("absent").exists());
    }
}

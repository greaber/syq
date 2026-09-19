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
fn hash_policy_independent_compare_and_payload_hashes_cross_transports() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    let data = prng(5 * 1024 * 1024 + 13, 999);
    write(&t.path("src/source"), &data);
    for tcp in [false, true] {
        for path in ["ranges", "streaming"] {
            let destination = format!("destination-{tcp}-{path}");
            let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
            command.args([
                "cp",
                &t.s("src/source"),
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
    write(&t.path("src/source"), &contents);
    for (compare, transfer) in [("blake3", "sha256"), ("xxh3-128", "blake3")] {
        let results = t.s(&format!("results-{compare}-{transfer}.ndjson"));
        let mut previous = contents.clone();
        *previous.last_mut().unwrap() ^= 1;
        write(&t.path("destination"), &previous);
        let output = native_syq(&[
            "cp",
            &t.s("src/source"),
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
    write(&t.path("src/source"), b"abc");
    write(&t.path("destination"), b"abc");
    set_mtime(&t.path("src/source"), 1_700_000_000);
    set_mtime(&t.path("destination"), 1_700_000_000);
    fs::set_permissions(t.path("src/source"), fs::Permissions::from_mode(0o640)).unwrap();
    fs::set_permissions(t.path("destination"), fs::Permissions::from_mode(0o600)).unwrap();
    let inode = fs::metadata(t.path("destination")).unwrap().ino();
    let copy = |results: &str| {
        let output = native_syq(&[
            "cp",
            "--mapping",
            &expected_mapping(
                &t,
                "source",
                "destination",
                Some("md5:900150983cd24fb0d6963f7d28e17f72"),
            ),
            "-C",
            &t.s("src"),
            "--into",
            &t.s(""),
            "--preserve=permissions",
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
    write(&t.path("src/source"), b"bad");
    set_mtime(&t.path("src/source"), 1_700_000_000);
    let output = native_syq(&[
        "cp",
        "--hash",
        "--mapping",
        &expected_mapping(
            &t,
            "source",
            "destination",
            Some("md5:900150983cd24fb0d6963f7d28e17f72"),
        ),
        "-C",
        &t.s("src"),
        "--into",
        &t.s(""),
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
    write(&t.path("src/source"), &contents);
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
            "--mapping",
            &expected_mapping(&t, "source", name, expected),
            "-C",
            &t.s("src"),
            "--into",
            &t.s(""),
            "--integrity-checking=transfer=xxh3-128",
        ]);
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
        write(&t.path("src/source"), &vec![b'n'; size]);
        write(&t.path("destination"), b"previous contents");
        let output = native_syq(&[
            "cp",
            "--mapping",
            &expected_mapping(
                &t,
                "source",
                "destination",
                Some("md5:00000000000000000000000000000000"),
            ),
            "-C",
            &t.s("src"),
            "--into",
            &t.s(""),
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
            failed["expected_hash"],
            serde_json::json!({"algorithm": "md5", "value": "0".repeat(32)})
        );
    }
}

#[test]
fn hash_policy_expected_empty_file_is_checked_before_publication() {
    let t = Tmp::new();
    write(&t.path("src/empty"), b"");
    run_native_ok(&[
        "cp",
        "--mapping",
        &expected_mapping(
            &t,
            "empty",
            "good",
            Some("md5:d41d8cd98f00b204e9800998ecf8427e"),
        ),
        "-C",
        &t.s("src"),
        "--into",
        &t.s(""),
        "--integrity-checking",
        "compare=xxh3-128",
        "--integrity-checking=transfer=blake3",
    ]);
    assert_eq!(read(&t.path("good")), b"");
    let output = native_syq(&[
        "cp",
        "--mapping",
        &expected_mapping(
            &t,
            "empty",
            "bad",
            Some("md5:00000000000000000000000000000000"),
        ),
        "-C",
        &t.s("src"),
        "--into",
        &t.s(""),
    ]);
    assert_eq!(output.status.code(), Some(23), "{}", stderr_of(&output));
    assert!(
        !t.path("bad").exists(),
        "a mismatching empty file must not be published"
    );
}

#[test]
fn hash_policy_xxh3_compares_repairs_and_previews() {
    let t = Tmp::new();
    let contents = prng(5 * 1024 * 1024, 992);
    let mut bad = contents.clone();
    bad[1_234_567] ^= 1;
    write(&t.path("src/source"), &contents);
    write(&t.path("destination"), &bad);
    set_mtime(&t.path("src/source"), 1_600_000_000);
    set_mtime(&t.path("destination"), 1_600_000_000);
    // The default metadata comparison cannot detect this same-size, same-time edit.
    run_native_ok(&[
        "cp",
        "--src",
        &t.s("src/source"),
        "--as",
        &t.s("destination"),
    ]);
    assert_eq!(read(&t.path("destination")), bad);
    run_native_ok(&[
        "cp",
        "--src",
        &t.s("src/source"),
        "--as",
        &t.s("destination"),
        "--integrity-checking",
        "compare=xxh3-128",
        "--integrity-checking=transfer=blake3",
    ]);
    assert_eq!(read(&t.path("destination")), contents);
    let preview = |name: &str, changed: bool| {
        let output = native_syq(&[
            "cp",
            "--dry-run",
            "--src",
            &t.s("src/source"),
            "--as",
            &t.s("destination"),
            "--integrity-checking",
            "compare=xxh3-128",
            "--results",
            &t.s(name),
        ]);
        assert_output_ok(&output);
        let records: Vec<serde_json::Value> = fs::read_to_string(t.path(name))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let terminal = records.last().unwrap();
        assert_eq!(terminal["type"], "result");
        assert_eq!(terminal["status"], "success");
        assert_eq!(terminal["files_transferred"], u64::from(changed));
        assert_eq!(terminal["files_unchanged"], u64::from(!changed));
        let traces: Vec<_> = records.iter().filter(|r| r["type"] == "trace").collect();
        assert_eq!(traces.len(), usize::from(changed), "{records:?}");
        if changed {
            assert_eq!(traces[0]["dst"]["value"], "");
            assert_eq!(traces[0]["reason"], "content_differs");
            assert_eq!(traces[0]["bytes"], contents.len());
        }
    };
    preview("matching.ndjson", false);
    write(&t.path("destination"), &bad);
    preview("different.ndjson", true);
    assert_eq!(read(&t.path("destination")), bad, "preview must not repair");
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

pub(super) fn expected_mapping(
    t: &Tmp,
    source: &str,
    destination: &str,
    expected: Option<&str>,
) -> String {
    let mut entry = serde_json::json!({
        "src": {"encoding": "utf-8", "value": source},
        "dst": {"encoding": "utf-8", "value": destination}, "kind": "file"
    });
    if let Some(expected) = expected {
        let (algorithm, value) = expected.split_once(':').unwrap();
        entry["expected_hash"] = serde_json::json!({"algorithm": algorithm, "value": value});
    }
    let path = format!("{destination}.mapping");
    write(&t.path(&path), entry.to_string().as_bytes());
    t.s(&path)
}

#[test]
fn dry_run_hash_compares_contents_and_metadata_without_writing() {
    for route in [
        "local", "push-tcp", "push-ssh", "pull-tcp", "pull-ssh", "relay",
    ] {
        let t = Tmp::new();
        for (name, source, destination) in [
            ("same", b"same".as_slice(), Some(b"same".as_slice())),
            ("corrupt", b"aaaa", Some(b"bbbb".as_slice())),
            ("metadata", b"bytes", Some(b"bytes".as_slice())),
            ("missing", b"new", None),
            ("size", b"new", Some(b"old data".as_slice())),
            ("ignored", b"x", Some(b"z".as_slice())),
        ] {
            write(&t.path(&format!("src/{name}")), source);
            set_mtime(&t.path(&format!("src/{name}")), 1_700_000_000);
            if let Some(bytes) = destination {
                write(&t.path(&format!("dst/{name}")), bytes);
                set_mtime(&t.path(&format!("dst/{name}")), 1_700_000_000);
            }
        }
        fs::set_permissions(t.path("src/metadata"), fs::Permissions::from_mode(0o640)).unwrap();
        fs::set_permissions(t.path("dst/metadata"), fs::Permissions::from_mode(0o600)).unwrap();
        set_mtime(&t.path("dst/metadata"), 1_700_000_001);
        let before = fs::metadata(t.path("dst/metadata")).unwrap();
        let rsh = fake_rsh(&t);
        let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
        command.args([
            "cp",
            "--dry-run",
            "--hash",
            "--preserve=permissions",
            "--ignore=ignored",
            "--performance-tuning=workers=2",
            "--rsh",
            rsh.to_str().unwrap(),
            "--syq-path",
            env!("CARGO_BIN_EXE_syq"),
            "--tcp-ports",
            EPHEMERAL_TCP_PORTS,
        ]);
        if route.ends_with("ssh") {
            command.arg("--no-tcp");
        }
        if route.starts_with("pull") || route == "relay" {
            command.args(["--from", "source"]);
        }
        command.args(["--srcs-in", &t.s("src")]);
        if route.starts_with("push") || route == "relay" {
            command.args(["--to", "destination"]);
        }
        if route == "relay" {
            command.args(["--coordinate-at", "local"]);
        }
        command.args([
            "--into",
            &t.s("dst"),
            "--results",
            &t.s("result.ndjson"),
            "-v",
        ]);
        let output = command.run().unwrap();
        assert_output_ok(&output);
        let text = fs::read_to_string(t.path("result.ndjson")).unwrap();
        assert_automation_stream(&automation_validator(), &text, route);
        let records: Vec<serde_json::Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let summary = records.last().unwrap();
        assert_eq!(summary["files_transferred"], 3, "{route}: {summary}");
        assert_eq!(summary["bytes_transferred"], 10, "{route}: {summary}");
        assert_eq!(summary["files_unchanged"], 2, "{route}: {summary}");
        assert_eq!(summary["bytes_unchanged"], 9, "{route}: {summary}");
        assert_eq!(
            summary["files_excluded"], 0,
            "ignore exclusions use paths_ignored"
        );
        assert!(!records.iter().any(|r| r["type"] == "operation_result"));
        for (name, reason, bytes) in [
            ("corrupt", "content_differs", Some(4)),
            ("size", "content_differs", Some(3)),
            ("missing", "destination_missing", Some(3)),
            ("metadata", "metadata_differs", None),
        ] {
            let trace = records
                .iter()
                .find(|r| r["type"] == "trace" && r["dst"]["value"] == name)
                .unwrap();
            assert_eq!(trace["reason"], reason, "{route}: {trace}");
            assert_eq!(trace.get("bytes").and_then(|b| b.as_u64()), bytes);
        }
        assert!(!records.iter().any(|r| r["type"] == "trace"
            && ["same", "ignored"].contains(&r["dst"]["value"].as_str().unwrap_or(""))));
        assert_eq!(read(&t.path("dst/corrupt")), b"bbbb");
        assert_eq!(read(&t.path("dst/size")), b"old data");
        assert_eq!(read(&t.path("dst/ignored")), b"z");
        assert!(!t.path("dst/missing").exists());
        let after = fs::metadata(t.path("dst/metadata")).unwrap();
        assert_eq!(
            (after.ino(), after.mode(), after.mtime(), after.mtime_nsec()),
            (
                before.ino(),
                before.mode(),
                before.mtime(),
                before.mtime_nsec()
            )
        );
        assert!(partial_files(&t.0).is_empty());
    }
}

#[test]
fn dry_run_hash_mapping_reports_source_names_and_timestamp_only_changes() {
    let t = Tmp::new();
    write(&t.path("src/input"), b"abc");
    write(&t.path("output"), b"abc");
    set_mtime(&t.path("src/input"), 1_700_000_000);
    set_mtime(&t.path("output"), 1_700_000_001);
    for hash in [false, true] {
        let results = t.s(if hash { "hash.ndjson" } else { "quick.ndjson" });
        let mapping = expected_mapping(&t, "input", "output", None);
        let source = t.s("src");
        let destination = t.s("");
        let mut args = vec![
            "cp",
            "--dry-run",
            "--mapping",
            &mapping,
            "-C",
            &source,
            "--into",
            &destination,
            "--results",
            &results,
        ];
        if hash {
            args.push("--integrity-checking=compare=md5");
        }
        let output = native_syq(&args);
        assert_output_ok(&output);
        let records: Vec<serde_json::Value> = fs::read_to_string(results)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let trace = records
            .iter()
            .find(|r| r["type"] == "trace" && r["kind"] == "file")
            .unwrap();
        assert_eq!(trace["src"]["value"], "input");
        assert_eq!(trace["dst"]["value"], "output");
        assert_eq!(trace["reason"], "metadata_differs");
        assert_eq!(
            trace.get("bytes").and_then(|b| b.as_u64()),
            if hash { None } else { Some(3) }
        );
        assert_eq!(
            records.last().unwrap()["files_transferred"],
            u64::from(!hash)
        );
        assert_eq!(records.last().unwrap()["files_unchanged"], u64::from(hash));
        assert_eq!(
            fs::metadata(t.path("output")).unwrap().mtime(),
            1_700_000_001
        );
    }
}

use super::*;

#[cfg(debug_assertions)]
#[test]
fn results_replacement_symlinks_cannot_redirect_creation_or_truncation() {
    use std::os::unix::fs::symlink;

    for initially_exists in [false, true] {
        let t = Tmp::new();
        write(&t.path("src"), b"data");
        let selected = t.path("results.ndjson");
        let outside = t.path("outside-results");
        write(&outside, b"do not replace");
        if initially_exists {
            write(&selected, b"old results");
        }
        let destination = t.path("dst");
        let ready = t.path("control-ready");
        let continuation = t.path("control-continue");
        let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
        command
            .args(["cp", "--results"])
            .arg(&selected)
            .arg(t.path("src"))
            .arg("--as")
            .arg(&destination)
            .arg("-q");
        let mut child = start_held_control_path(&mut command, &selected, &ready, &continuation);
        wait_for_control_path_selection(&mut child, &ready);

        if initially_exists {
            fs::rename(&selected, t.path("original-results")).unwrap();
        }
        symlink(&outside, &selected).unwrap();

        release_confinement_barrier(&continuation);
        let output = child.wait_with_output().unwrap();
        assert!(
            !output.status.success(),
            "results {} followed a replacement symlink",
            if initially_exists {
                "truncation"
            } else {
                "creation"
            }
        );
        assert!(stderr_of(&output).contains("--results"));
        assert_eq!(read(&outside), b"do not replace");
        assert!(!destination.exists());
        if initially_exists {
            assert_eq!(read(&t.path("original-results")), b"old results");
        }
    }
}

#[test]
fn named_results_refuse_fifos_devices_and_trailing_slashes() {
    let t = Tmp::new();
    write(&t.path("src"), b"data");
    let fifo = t.path("results-fifo");
    mkfifo(&fifo);
    let mut fifo_reader = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&fifo)
        .unwrap();

    for (label, selected) in [("fifo", fifo), ("device", PathBuf::from("/dev/null"))] {
        let destination = t.path(&format!("{label}-destination"));
        let output = Command::new(env!("CARGO_BIN_EXE_syq"))
            .args(["cp", "--results"])
            .arg(&selected)
            .arg(t.path("src"))
            .arg("--as")
            .arg(&destination)
            .arg("-q")
            .run()
            .unwrap();
        assert!(!output.status.success(), "named results accepted {label}");
        assert!(stderr_of(&output).contains("already exists"));
        assert!(!destination.exists());
    }
    let mut fifo_bytes = Vec::new();
    fifo_reader.read_to_end(&mut fifo_bytes).unwrap();
    assert!(fifo_bytes.is_empty(), "the refused FIFO was written");

    let trailing = format!("{}/", t.s("missing-results"));
    let output = native_syq(&[
        "cp",
        "--results",
        &trailing,
        &t.s("src"),
        "--as",
        &t.s("trailing-destination"),
    ]);
    assert!(!output.status.success());
    assert!(stderr_of(&output).contains("trailing slash"));
    assert!(!t.path("missing-results").exists());
    assert!(!t.path("trailing-destination").exists());
}

#[cfg(debug_assertions)]
#[test]
fn followed_results_referent_stays_pinned_when_the_link_is_replaced() {
    use std::os::unix::fs::symlink;

    let t = Tmp::new();
    write(&t.path("src"), b"data");
    write(&t.path("outside-results"), b"do not replace");
    let selected = t.path("results-link");
    symlink("intended-results", &selected).unwrap();
    let ready = t.path("control-ready");
    let continuation = t.path("control-continue");
    let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
    command
        .args(["cp", "--follow", "--results"])
        .arg(&selected)
        .arg(t.path("src"))
        .arg("--as")
        .arg(t.path("dst"))
        .arg("-q");
    let mut child = start_held_control_path(&mut command, &selected, &ready, &continuation);
    wait_for_control_path_selection(&mut child, &ready);

    fs::remove_file(&selected).unwrap();
    symlink(t.path("outside-results"), &selected).unwrap();

    release_confinement_barrier(&continuation);
    let output = child.wait_with_output().unwrap();
    assert_output_ok(&output);
    assert_eq!(read(&t.path("outside-results")), b"do not replace");
    let intended = read(&t.path("intended-results"));
    assert!(
        String::from_utf8_lossy(&intended).contains("\"type\":\"result\""),
        "{}",
        String::from_utf8_lossy(&intended)
    );
    assert_eq!(read(&t.path("dst")), b"data");
}

#[test]
fn hash_policy_automation_digest_schema_checks_algorithm_and_width() {
    let validator = automation_validator();
    let mut record = serde_json::json!({
        "schema": "syq.automation", "schema_version": 2, "seq": 1,
        "type": "operation_result", "action": "transfer_file", "kind": "file",
        "dst": {"encoding": "utf-8", "value": "file"}, "disposition": "failed",
    });
    assert!(
        validator.is_valid(&record),
        "old records need no expectation"
    );
    for (algorithm, length) in [
        ("blake3", 64),
        ("sha256", 64),
        ("md5", 32),
        ("xxh3-128", 32),
    ] {
        record["expected_hash"] =
            serde_json::json!({"algorithm": algorithm, "value": "a".repeat(length)});
        assert!(validator.is_valid(&record), "{record}");
        record["expected_hash"]["value"] = "a".repeat(if length == 64 { 32 } else { 64 }).into();
        assert!(!validator.is_valid(&record), "{record}");
        record["expected_hash"]["value"] = "g".repeat(length).into();
        assert!(!validator.is_valid(&record), "{record}");
    }
    record["expected_hash"] = serde_json::json!({"algorithm": "rolling", "value": "a".repeat(32)});
    assert!(!validator.is_valid(&record));
}

#[test]
fn progress_bar_does_not_mix_with_json_progress() {
    let t = Tmp::new();
    write(&t.path("src"), &prng(1024 * 1024, 452));
    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "cp",
            &t.s("src"),
            "--as",
            &t.s("dst"),
            "--progress",
            "--progress-json",
            "--resource-limits",
            "bandwidth=1M",
        ])
        .run()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(!stderr.is_empty());
    for line in stderr.lines() {
        let value: serde_json::Value =
            serde_json::from_str(line).expect("JSON without a terminal bar");
        assert!(value["bytes_done"].is_u64(), "{line}");
    }
}

#[cfg(all(target_os = "linux", debug_assertions))]
#[test]
fn fallocate_quota_error_is_preserved_in_results() {
    let t = Tmp::new();
    write(&t.path("src/file"), &vec![b'x'; 5 * 1024 * 1024]);
    write(&t.path("dst/existing"), b"make this an update");

    let output = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "cp",
            "--srcs-in",
            "src",
            "--into-existing",
            "dst",
            "--resource-limits",
            "bandwidth=1G",
            "--performance-tuning",
            "workers=1",
            "--results",
            "results.ndjson",
            "-q",
        ])
        .current_dir(&t.0)
        .env("SYQ_TEST_FALLOCATE_ERRNO", "quota")
        .run()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        t.path("results.ndjson").exists(),
        "results stream was not created:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let records: Vec<serde_json::Value> = String::from_utf8(read(&t.path("results.ndjson")))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(
        records
            .iter()
            .any(|record| record["os_kind"] == "quota_exceeded"),
        "quota classification missing from {records:#?}"
    );
}

/// Human output failures must leave the small-copy result and receipt intact.
#[test]
fn small_push_preserves_results_with_closed_human_streams() {
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;

    let broken_output = || {
        let (reader, writer) = UnixStream::pair().unwrap();
        drop(reader);
        Stdio::from(OwnedFd::from(writer))
    };
    for broken_stderr in [false, true] {
        let t = Tmp::new();
        let ssh = fake_ssh(&t);
        fs::create_dir_all(t.path("remote-home/dest")).unwrap();
        write(&t.path("source"), b"small copy survives broken output");
        let output = Command::new(env!("CARGO_BIN_EXE_syq"))
            .args([
                "cp",
                "--syq-path",
                env!("CARGO_BIN_EXE_syq"),
                "-vv",
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
            .env("SYQ_DEBUG", "1")
            .stdin(Stdio::null())
            .stdout(broken_output())
            .stderr(if broken_stderr {
                broken_output()
            } else {
                Stdio::piped()
            })
            .start()
            .unwrap()
            .wait_with_output()
            .unwrap();
        assert_output_ok(&output);
        assert_eq!(
            read(&t.path("remote-home/dest/source")),
            read(&t.path("source"))
        );
        let records = fs::read_to_string(t.path("results.ndjson")).unwrap();
        let terminal: serde_json::Value =
            serde_json::from_str(records.lines().last().unwrap()).unwrap();
        assert_eq!(terminal["type"], "result");
        assert_eq!(terminal["exit_code"], 0);
        assert_eq!(terminal["files_transferred"], 1);
        assert_eq!(
            fs::read_to_string(t.path("rsh.log"))
                .unwrap()
                .lines()
                .count(),
            1
        );
        if !broken_stderr {
            assert!(stderr_of(&output).contains("small copy: published"));
        }
    }
}

#[test]
fn native_detach_rejects_an_unattached_results_stream() {
    let t = Tmp::new();
    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "cp",
            "--rsh",
            "ssh",
            "--detach",
            "--from",
            "hostA",
            "--src",
            "/source",
            "--to",
            "hostB",
            "--as",
            &t.s("dst"),
            "--results",
            "r1.ndjson",
            "-q",
        ])
        .run()
        .expect("reject detached streamed results");

    assert!(!out.status.success());
    assert!(
        stderr_of(&out).contains("result stream would not remain attached"),
        "{}",
        stderr_of(&out)
    );
    assert!(!t.path("dst").exists());
}

#[test]
fn native_cp_results_copying_interval_covers_paced_content_but_not_unchanged_files() {
    let t = Tmp::new();
    write(&t.path("src/data"), &vec![42; 2 * 1024 * 1024]);
    for (result, moved) in [("first.ndjson", true), ("second.ndjson", false)] {
        let out = syq_cp_in(
            &t.path(""),
            &[
                "--srcs-in",
                "src",
                "--into",
                "dst",
                "--results",
                result,
                "--resource-limits",
                "bandwidth=1M",
                "--stats",
                "--no-progress",
            ],
            None,
        );
        assert!(out.status.success(), "{}", stderr_of(&out));
        let contents = String::from_utf8(read(&t.path(result))).unwrap();
        let terminal: serde_json::Value =
            serde_json::from_str(contents.lines().last().unwrap()).unwrap();
        if moved {
            let interval = terminal["copying_elapsed_ms"]
                .as_u64()
                .expect("copy timing");
            assert!(interval >= 1_000, "paced copy interval: {interval}ms");
            assert!(interval <= terminal["elapsed_ms"].as_u64().unwrap());
            assert!(String::from_utf8_lossy(&out.stdout).contains("copying interval:"));
        } else {
            assert!(terminal.get("copying_elapsed_ms").is_none());
        }
        assert_eq!(read(&t.path("src/data")), read(&t.path("dst/data")));
    }
}

#[test]
fn native_cp_results_stream_success_and_partial() {
    let t = Tmp::new();
    write(&t.path("src/a.txt"), b"abc");
    std::os::unix::fs::symlink("a.txt", t.path("src/l")).unwrap();
    let manifest = format!(
        "{}{}{}",
        entry_line("a.txt", "x/a.txt", Some("file")),
        entry_line("l", "l", Some("symlink")),
        entry_line("gone.txt", "g.txt", None),
    );
    let out = syq_cp_in(
        &t.path(""),
        &[
            "--mapping",
            "-",
            "-C",
            "src",
            "--into",
            "dst",
            "--results",
            "r1.ndjson",
            "-q",
        ],
        Some(manifest.as_bytes()),
    );
    assert_eq!(out.status.code(), Some(23));
    let lines: Vec<serde_json::Value> = String::from_utf8(read(&t.path("r1.ndjson")))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).expect("results line is JSON"))
        .collect();
    // Envelope: schema v1, strictly increasing seq, run first, result last.
    for (i, v) in lines.iter().enumerate() {
        assert_eq!(v["schema"], "syq.automation");
        assert_eq!(v["schema_version"], 2);
        assert_eq!(v["seq"], i as u64);
    }
    assert_eq!(lines[0]["type"], "run");
    assert_eq!(lines[0]["mapping"], true);
    assert_eq!(lines[0]["mode"], "cp");
    assert_eq!(lines[0]["dry_run"], false);
    assert_eq!(lines[0]["run_id"].as_str().unwrap().len(), 32);
    assert!(lines[0]["started_at"].as_i64().unwrap() > 0);
    let endpoints = lines[0]["endpoints"].as_array().unwrap();
    assert_eq!(endpoints.len(), 2);
    assert_eq!(endpoints[0]["role"], "source");
    assert_eq!(endpoints[0]["kind"], "local");
    assert_eq!(endpoints[1]["role"], "destination");
    let last = lines.last().unwrap();
    assert_eq!(last["type"], "result");
    assert_eq!(last["status"], "partial");
    assert_eq!(last["exit_code"], 23);
    assert_eq!(last["files_transferred"], 1);
    assert_eq!(last["symlinks_created"], 1);
    assert!(last["directories_created"].as_u64().unwrap() >= 1);
    assert_eq!(last["errors"], 1);
    let ops: Vec<&serde_json::Value> = lines
        .iter()
        .filter(|v| v["type"] == "operation_result")
        .collect();
    let find = |dst: &str| {
        *ops.iter()
            .find(|v| v["dst"]["value"] == dst)
            .unwrap_or_else(|| panic!("no operation_result for {dst}"))
    };
    let file = find("x/a.txt");
    assert_eq!(file["action"], "transfer_file");
    assert_eq!(file["disposition"], "succeeded");
    assert_eq!(file["kind"], "file");
    assert_eq!(file["bytes"], 3);
    assert_eq!(file["src"]["value"], "a.txt");
    let dir = find("x");
    assert_eq!(dir["action"], "create_directory");
    assert_eq!(dir["disposition"], "succeeded");
    let link = find("l");
    assert_eq!(link["action"], "create_symlink");
    assert_eq!(link["disposition"], "succeeded");
    let failed = find("g.txt");
    assert_eq!(failed["disposition"], "failed");
    assert_eq!(failed["retryable"], "unknown");
    assert_eq!(failed["src"]["value"], "gone.txt");
    // A failed record round-trips as a retry mapping entry.
    let retry = format!(
        "{{\"src\":{},\"dst\":{},\"kind\":{}}}\n",
        failed["src"], failed["dst"], failed["kind"]
    );
    write(&t.path("src/gone.txt"), b"late");
    let out = syq_cp_in(
        &t.path(""),
        &[
            "--mapping",
            "-",
            "-C",
            "src",
            "--into",
            "dst",
            "--results",
            "r2.ndjson",
            "-q",
        ],
        Some(retry.as_bytes()),
    );
    assert!(
        out.status.success(),
        "retry failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(read(&t.path("dst/g.txt")), b"late");
    let last: serde_json::Value = String::from_utf8(read(&t.path("r2.ndjson")))
        .unwrap()
        .lines()
        .last()
        .map(|line| serde_json::from_str(line).unwrap())
        .unwrap();
    assert_eq!(last["status"], "success");
    assert_eq!(last["exit_code"], 0);
    // An error record accompanied the failure in the first run, classified
    // like its adjacent operation record.
    let error = lines
        .iter()
        .find(|v| v["type"] == "error" && v["message"].as_str().unwrap().contains("does not exist"))
        .expect("classified error record");
    assert_eq!(error["class"], "io");
    assert_eq!(error["os_kind"], "not_found");
}

#[test]
fn native_cp_results_dry_run_emits_traces() {
    let t = Tmp::new();
    write(&t.path("src/f.txt"), b"data");
    write(&t.path("src/sub/g.txt"), b"gg");
    std::os::unix::fs::symlink("f.txt", t.path("src/l")).unwrap();
    let out = syq_cp_in(
        &t.path(""),
        &[
            "--srcs-in",
            "src",
            "--into",
            "dst",
            "--results",
            "r1.ndjson",
            "-n",
            "-q",
        ],
        None,
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!t.path("dst/f.txt").exists(), "dry run must not write");
    let lines: Vec<serde_json::Value> = String::from_utf8(read(&t.path("r1.ndjson")))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(lines[0]["type"], "run");
    assert_eq!(lines[0]["dry_run"], true);
    let trace = lines
        .iter()
        .find(|v| v["type"] == "trace" && v["dst"]["value"] == "f.txt")
        .expect("trace record for the planned file");
    assert_eq!(trace["action"], "transfer_file");
    assert_eq!(trace["kind"], "file");
    assert_eq!(trace["reason"], "destination_missing");
    assert_eq!(trace["bytes"], 4);
    assert!(
        !lines.iter().any(|v| v["type"] == "operation_result"),
        "dry runs settle nothing"
    );
    let last = lines.last().unwrap();
    assert_eq!(last["type"], "result");
    assert_eq!(last["dry_run"], true);
    assert_eq!(last["status"], "success");
    assert_eq!(last["files_transferred"], 2, "planned, per dry_run: true");
    // Planned non-file work comes from the traced changes, not the live
    // mutation counters (which a dry run never moves).
    assert!(last["directories_created"].as_u64().unwrap() >= 1);
    assert_eq!(last["symlinks_created"], 1);
}

#[test]
fn native_cp_results_preexisting_directory_is_not_reported_created() {
    let t = Tmp::new();
    write(&t.path("src/sub/f.txt"), b"f");
    fs::create_dir_all(t.path("dst/sub")).unwrap();
    fs::set_permissions(t.path("dst/sub"), fs::Permissions::from_mode(0o555)).unwrap();
    let out = syq_cp_in(
        &t.path(""),
        &[
            "--srcs-in",
            "src",
            "--into",
            "dst",
            "--results",
            "r1.ndjson",
            "-q",
        ],
        None,
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(read(&t.path("dst/sub/f.txt")), b"f");
    let lines: Vec<serde_json::Value> = String::from_utf8(read(&t.path("r1.ndjson")))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(
        !lines
            .iter()
            .any(|v| v["type"] == "operation_result" && v["action"] == "create_directory"),
        "reopening an existing directory for writability is not a creation"
    );
    assert_eq!(lines.last().unwrap()["directories_created"], 0);
}

#[test]
fn native_cp_results_fatal_failure_emits_terminal_record() {
    let t = Tmp::new();
    let out = syq_cp_in(
        &t.path(""),
        &[
            "--srcs-in",
            "absent",
            "--into",
            "dst",
            "--results",
            "r1.ndjson",
            "-q",
        ],
        None,
    );
    assert_eq!(out.status.code(), Some(1));
    let lines: Vec<serde_json::Value> = String::from_utf8(read(&t.path("r1.ndjson")))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(lines[0]["type"], "run");
    let last = lines.last().unwrap();
    assert_eq!(last["type"], "result");
    assert_eq!(last["status"], "failed");
    assert_eq!(last["exit_code"], 1);
}

#[test]
fn native_cp_prune_results_cover_deletions() {
    let t = Tmp::new();
    write(&t.path("src/keep.txt"), b"k");
    write(&t.path("dst/keep.txt"), b"k");
    write(&t.path("dst/extra.txt"), b"x");
    std::os::unix::fs::symlink("keep.txt", t.path("dst/extra-link")).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "cp",
            "--prune",
            "--srcs-in",
            "src",
            "--into",
            "dst",
            "--results",
            "r1.ndjson",
            "-q",
        ])
        .current_dir(t.path(""))
        .run()
        .expect("run cp --prune");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!t.path("dst/extra.txt").exists());
    let lines: Vec<serde_json::Value> = String::from_utf8(read(&t.path("r1.ndjson")))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(lines[0]["mode"], "cp");
    assert_eq!(lines[0]["prune"], true);
    let delete = lines
        .iter()
        .find(|v| {
            v["type"] == "operation_result"
                && v["action"] == "delete"
                && v["dst"]["value"] == "extra.txt"
        })
        .expect("delete record");
    assert_eq!(delete["disposition"], "succeeded");
    assert_eq!(delete["kind"], "file");
    let link_delete = lines
        .iter()
        .find(|v| {
            v["type"] == "operation_result"
                && v["action"] == "delete"
                && v["dst"]["value"] == "extra-link"
        })
        .expect("symlink delete record");
    assert_eq!(link_delete["kind"], "symlink", "leaf kinds are preserved");
    let last = lines.last().unwrap();
    assert_eq!(last["deletions_planned"], 2);
    assert_eq!(last["deletions_completed"], 2);
    assert_eq!(last["deletions_blocked"], 0);
    // --max-delete 0 refuses: blocked records, refused status, exit 25.
    write(&t.path("dst/extra2.txt"), b"x");
    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "cp",
            "--prune",
            "--srcs-in",
            "src",
            "--into",
            "dst",
            "--results",
            "r2.ndjson",
            "--max-delete",
            "0",
            "-q",
        ])
        .current_dir(t.path(""))
        .run()
        .expect("run cp --prune");
    assert_eq!(out.status.code(), Some(25));
    assert!(t.path("dst/extra2.txt").exists());
    let lines: Vec<serde_json::Value> = String::from_utf8(read(&t.path("r2.ndjson")))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let blocked = lines
        .iter()
        .find(|v| v["type"] == "operation_result" && v["disposition"] == "blocked")
        .expect("blocked record");
    assert_eq!(blocked["action"], "delete");
    assert_eq!(blocked["class"], "safety_limit");
    let last = lines.last().unwrap();
    assert_eq!(last["status"], "refused");
    assert_eq!(last["exit_code"], 25);
    assert_eq!(last["deletions_blocked"], 1);
    // A dry run stays trace-only even when --max-delete blocks: the fact
    // lives in the aggregates.
    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "cp",
            "--prune",
            "--srcs-in",
            "src",
            "--into",
            "dst",
            "--results",
            "r3.ndjson",
            "--max-delete",
            "0",
            "-n",
            "-q",
        ])
        .current_dir(t.path(""))
        .run()
        .expect("run cp --prune");
    assert_eq!(out.status.code(), Some(25));
    let lines: Vec<serde_json::Value> = String::from_utf8(read(&t.path("r3.ndjson")))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(
        !lines.iter().any(|v| v["type"] == "operation_result"),
        "dry runs emit no operation records"
    );
    let last = lines.last().unwrap();
    assert_eq!(last["status"], "refused");
    assert_eq!(last["dry_run"], true);
    assert_eq!(last["deletions_blocked"], 1);
}

#[test]
fn native_cp_results_implicit_dir_failure_is_not_a_retry_entry() {
    let t = Tmp::new();
    write(&t.path("src/a.txt"), b"abc");
    fs::create_dir_all(t.path("dst")).unwrap();
    fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o555)).unwrap();
    let manifest = entry_line("a.txt", "sub/a.txt", None);
    let out = syq_cp_in(
        &t.path(""),
        &[
            "--mapping",
            "-",
            "-C",
            "src",
            "--into",
            "dst",
            "--results",
            "r1.ndjson",
            "-q",
        ],
        Some(manifest.as_bytes()),
    );
    assert_eq!(
        out.status.code(),
        Some(23),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let lines: Vec<serde_json::Value> = String::from_utf8(read(&t.path("r1.ndjson")))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let dir = lines
        .iter()
        .find(|v| v["type"] == "operation_result" && v["dst"]["value"] == "sub")
        .expect("implicit dir record");
    assert_eq!(dir["disposition"], "failed");
    assert_eq!(dir["retryable"], "no");
    assert!(dir.get("src").is_none(), "implicit dirs have no source");
    // The documented retry filter selects only records that are valid
    // mapping entries: failed, retryable, carrying a src.
    let retryable: Vec<&serde_json::Value> = lines
        .iter()
        .filter(|v| {
            v["type"] == "operation_result"
                && v["disposition"] == "failed"
                && v["retryable"] != "no"
        })
        .collect();
    assert!(!retryable.is_empty(), "the file failure is retryable");
    for v in &retryable {
        assert!(v.get("src").is_some(), "retry candidates carry src: {v}");
    }
}

#[test]
fn native_cp_results_dry_and_live_directory_totals_agree() {
    let t = Tmp::new();
    write(&t.path("src/sub/f.txt"), b"f");
    for (mode, extra) in [("dry", vec!["-n"]), ("live", vec![])] {
        let dst = format!("dst-{mode}");
        let results = format!("r-{mode}.ndjson");
        let mut args = vec![
            "--srcs-in",
            "src",
            "--into",
            &dst,
            "--results",
            &results,
            "-q",
        ];
        args.extend(extra);
        let out = syq_cp_in(&t.path(""), &args, None);
        assert!(
            out.status.success(),
            "{mode}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let last: serde_json::Value = String::from_utf8(read(&t.path(&results)))
            .unwrap()
            .lines()
            .last()
            .map(|line| serde_json::from_str(line).unwrap())
            .unwrap();
        // The missing container is outside per-entry accounting on both
        // sides; sub is the one counted directory either way, and dry
        // aggregates mean planned work — bytes included.
        assert_eq!(last["directories_created"], 1, "{mode}");
        assert_eq!(last["files_transferred"], 1, "{mode}");
        assert_eq!(last["bytes_transferred"], 1, "{mode}");
    }
}

#[test]
fn native_cp_results_non_tty_run_emits_progress_records() {
    let t = Tmp::new();
    write(&t.path("src/big.bin"), &vec![7u8; 64 * 1024]);
    let out = syq_cp_in(
        &t.path(""),
        &[
            "--srcs-in",
            "src",
            "--into",
            "dst",
            "--resource-limits",
            "bandwidth=32",
            "--results",
            "r1.ndjson",
            "-q",
        ],
        None,
    );
    assert!(out.status.success(), "stderr: {}", stderr_of(&out));
    let progress_records = String::from_utf8(read(&t.path("r1.ndjson")))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .filter(|v| v["type"] == "progress")
        .inspect(|v| {
            assert!(
                v.get("activity").is_none(),
                "plain results must not enable telemetry: {v}"
            )
        })
        .count();
    // ~2s at the rate limit: the ticker samples once immediately and then
    // at least once more at the one-second throttle, TTY or not.
    assert!(progress_records >= 2, "saw {progress_records}");
}

#[test]
fn automation_fixtures_validate_against_schema() {
    let validator = automation_validator();
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/automation");
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .expect("fixture dir")
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            "dry-run.ndjson",
            "failed.ndjson",
            "partial.ndjson",
            "refused.ndjson",
            "rm-dry-partial.ndjson",
            "rm-dry-run.ndjson",
            "rm-failed.ndjson",
            "rm-partial.ndjson",
            "rm-success.ndjson",
            "success.ndjson"
        ]
    );
    for name in names {
        let content = String::from_utf8(read(&dir.join(&name))).unwrap();
        assert_automation_stream(&validator, &content, &name);
    }
    // The strictness is the point: a shape change must fail, not slide by.
    let mut record: serde_json::Value = serde_json::from_str(
        String::from_utf8(read(&dir.join("success.ndjson")))
            .unwrap()
            .lines()
            .next()
            .unwrap(),
    )
    .unwrap();
    assert!(validator.validate(&record).is_ok());
    record["surprise"] = serde_json::json!(true);
    assert!(
        validator.validate(&record).is_err(),
        "an unknown field must fail validation"
    );
    assert!(
        validator
            .validate(&serde_json::json!({
                "schema": "syq.automation", "schema_version": 2, "seq": 0, "type": "run"
            }))
            .is_err(),
        "missing required fields must fail validation"
    );
}

#[test]
fn automation_live_streams_validate_against_schema() {
    let validator = automation_validator();
    let manifest = format!(
        "{}{}",
        entry_line("Berlin/IMG.JPG", "berlin/2024/img.jpg", Some("file")),
        entry_line("Notes.TXT", "notes.txt", None),
    );

    // success (mapping) and its dry run.
    for (name, extra) in [("success", &[][..]), ("dry-run", &["-n"][..])] {
        let t = Tmp::new();
        write(&t.path("src/Berlin/IMG.JPG"), b"img");
        write(&t.path("src/Notes.TXT"), b"hello");
        let mut args = vec!["-C", "src", "--mapping", "-", "--into", "dst"];
        args.extend_from_slice(extra);
        let results = format!("r-{name}.ndjson");
        args.extend_from_slice(&["--results", &results, "-q"]);
        let out = syq_cp_in(&t.path(""), &args, Some(manifest.as_bytes()));
        assert!(out.status.success(), "{name}: {}", stderr_of(&out));
        let content = String::from_utf8(read(&t.path(&results))).unwrap();
        assert_automation_stream(&validator, &content, name);
    }

    // partial: one mapping entry fails. Exit 23.
    {
        let t = Tmp::new();
        write(&t.path("src/Notes.TXT"), b"hello");
        let out = syq_cp_in(
            &t.path(""),
            &[
                "-C",
                "src",
                "--mapping",
                "-",
                "--into",
                "dst",
                "--results",
                "r.ndjson",
                "-q",
            ],
            Some(manifest.as_bytes()),
        );
        assert_eq!(out.status.code(), Some(23), "{}", stderr_of(&out));
        let content = String::from_utf8(read(&t.path("r.ndjson"))).unwrap();
        assert_automation_stream(&validator, &content, "partial");
    }

    // refused: --max-delete blocks the deletion pass. Exit 25.
    {
        let t = Tmp::new();
        write(&t.path("src/keep.txt"), b"k");
        write(&t.path("dst/keep.txt"), b"k");
        write(&t.path("dst/extra-1.txt"), b"x");
        write(&t.path("dst/extra-2.txt"), b"x");
        let out = syq_cp_in(
            &t.path(""),
            &[
                "--prune",
                "--max-delete",
                "1",
                "--srcs-in",
                "src",
                "--into",
                "dst",
                "--results",
                "r.ndjson",
                "-q",
            ],
            None,
        );
        assert_eq!(out.status.code(), Some(25), "{}", stderr_of(&out));
        let content = String::from_utf8(read(&t.path("r.ndjson"))).unwrap();
        assert_automation_stream(&validator, &content, "refused");
    }

    // failed: fatal setup failure still yields a valid stream. Exit 1.
    {
        let t = Tmp::new();
        let out = syq_cp_in(
            &t.path(""),
            &[
                "--srcs-in",
                "missing",
                "--into",
                "dst",
                "--results",
                "r.ndjson",
                "-q",
            ],
            None,
        );
        assert_eq!(out.status.code(), Some(1), "{}", stderr_of(&out));
        let content = String::from_utf8(read(&t.path("r.ndjson"))).unwrap();
        assert_automation_stream(&validator, &content, "failed");
    }

    // Native removal has command-specific selector, trace, outcome, and
    // terminal shapes under the same versioned envelope.
    for (name, dry_run) in [("rm-live", false), ("rm-dry-run", true)] {
        let t = Tmp::new();
        write(&t.path("tree/file"), b"remove");
        let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
        command
            .args(["rm", "--cwd", &t.s(""), "--src-dir", "tree"])
            .args(["--results", &t.s("r.ndjson"), "-q"]);
        if dry_run {
            command.arg("--dry-run");
        }
        let out = command.run().unwrap();
        assert_output_ok(&out);
        let content = String::from_utf8(read(&t.path("r.ndjson"))).unwrap();
        assert_automation_stream(&validator, &content, name);
        assert_eq!(t.path("tree").exists(), dry_run);
    }
}

#[test]
fn native_cp_dry_summary_and_terminal_record_count_the_same_directories() {
    let t = Tmp::new();
    write(&t.path("src/sub/f.txt"), b"f");
    // Human summary (no --results): the missing destination container is
    // outside per-entry accounting, so one directory, matching the record.
    let human = syq_cp_in(
        &t.path(""),
        &["--srcs-in", "src", "--into", "dst", "-n"],
        None,
    );
    assert!(human.status.success(), "{}", stderr_of(&human));
    let stdout = String::from_utf8(human.stdout).unwrap();
    assert!(
        stdout.contains("1 directory"),
        "summary should count one directory: {stdout}"
    );
    let machine = syq_cp_in(
        &t.path(""),
        &[
            "--srcs-in",
            "src",
            "--into",
            "dst2",
            "-n",
            "--results",
            "r1.ndjson",
        ],
        None,
    );
    assert!(machine.status.success(), "{}", stderr_of(&machine));
    let terminal: serde_json::Value = String::from_utf8(read(&t.path("r1.ndjson")))
        .unwrap()
        .lines()
        .last()
        .map(|line| serde_json::from_str(line).unwrap())
        .unwrap();
    assert_eq!(terminal["directories_created"], 1);
}

#[test]
fn native_cp_results_refuses_an_existing_file() {
    let t = Tmp::new();
    write(&t.path("src/f.txt"), b"data");
    write(&t.path("r.ndjson"), b"yesterday's run");
    let out = syq_cp_in(
        &t.path(""),
        &["--srcs-in", "src", "--into", "dst", "--results", "r.ndjson"],
        None,
    );
    assert!(!out.status.success());
    let stderr = stderr_of(&out);
    assert!(stderr.contains("already exists"), "{stderr}");
    // Refused before anything ran: yesterday's stream and the destination
    // are untouched.
    assert_eq!(read(&t.path("r.ndjson")), b"yesterday's run");
    assert!(!t.path("dst").exists());
}

#[test]
fn native_cp_results_fd_streams_to_a_caller_opened_descriptor() {
    let t = Tmp::new();
    write(&t.path("src/f.txt"), b"data");
    // The caller opens fd 3 (`3>fd.ndjson`); syq only ever writes to it.
    let out = Command::new("/bin/sh")
        .arg("-c")
        .arg("exec \"$1\" cp --srcs-in src --into dst --results-fd 3 -q 3>fd.ndjson")
        .arg("sh")
        .arg(env!("CARGO_BIN_EXE_syq"))
        .current_dir(t.path(""))
        .run()
        .unwrap();
    assert!(out.status.success(), "{}", stderr_of(&out));
    let lines: Vec<serde_json::Value> = String::from_utf8(read(&t.path("fd.ndjson")))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(lines.first().unwrap()["type"], "run");
    assert_eq!(lines.last().unwrap()["status"], "success");
    // Human stdout is untouched by the stream.
    assert!(out.stdout.is_empty() || !String::from_utf8_lossy(&out.stdout).contains("schema"));
}

#[test]
fn native_cp_results_fd_refusals() {
    let t = Tmp::new();
    write(&t.path("src/f.txt"), b"data");
    // A descriptor nobody connected fails loudly at startup.
    let out = syq_cp_in(
        &t.path(""),
        &["--srcs-in", "src", "--into", "dst", "--results-fd", "37"],
        None,
    );
    assert!(!out.status.success());
    assert!(stderr_of(&out).contains("not open"), "{}", stderr_of(&out));
    assert!(!t.path("dst").exists());
    // A read-only descriptor would swallow every record silently.
    let out = Command::new("/bin/sh")
        .arg("-c")
        .arg("exec \"$1\" cp --srcs-in src --into dst --results-fd 3 3</dev/null")
        .arg("sh")
        .arg(env!("CARGO_BIN_EXE_syq"))
        .current_dir(t.path(""))
        .run()
        .unwrap();
    assert!(!out.status.success());
    assert!(stderr_of(&out).contains("read-only"), "{}", stderr_of(&out));
    assert!(!t.path("dst").exists());
    // Slots 0-2 belong to stdin/stdout/stderr.
    let out = syq_cp_in(
        &t.path(""),
        &["--srcs-in", "src", "--into", "dst", "--results-fd", "1"],
        None,
    );
    assert!(!out.status.success());
    assert!(stderr_of(&out).contains("above 2"), "{}", stderr_of(&out));
}

#[test]
fn native_results_on_remote_coordinators_need_a_receiver_or_explicit_relay() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    write(&t.path("src"), b"local results");
    // Without a command-restricted receiver there is no verified channel to
    // carry records home from a remote coordinator: the run fails, but the
    // stream still settles with a failed terminal record.
    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["cp", "--rsh"])
        .arg(&rsh)
        .args(["--syq-path", env!("CARGO_BIN_EXE_syq")])
        .args([
            "--no-tcp",
            "--performance-tuning",
            "workers=1",
            "--from",
            "hostA",
            "--src",
            &t.s("src"),
        ])
        .args([
            "--to",
            "hostB",
            "--coordinate-at",
            "dst",
            "--as",
            &t.s("dst-remote"),
        ])
        .args(["--results", "r-remote.ndjson"])
        .current_dir(t.path(""))
        .env("FAKE_REMOTE_HOME", t.path("remote-home"))
        .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
        .env("FAKE_RSH_LOG", t.path("rsh.log"))
        .run()
        .expect("refuse results without a receiver");
    assert_eq!(out.status.code(), Some(1));
    let stderr = stderr_of(&out);
    assert!(stderr.contains("command-restricted receiver"), "{stderr}");
    assert!(stderr.contains("--coordinate-at local"), "{stderr}");
    let records: Vec<serde_json::Value> = String::from_utf8(read(&t.path("r-remote.ndjson")))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(records.first().unwrap()["type"], "run");
    let terminal = records.last().unwrap();
    assert_eq!(terminal["type"], "result");
    assert_eq!(terminal["status"], "failed");
}

#[test]
fn native_remote_dry_run_results_need_a_local_coordinator() {
    let t = Tmp::new();
    write(&t.path("src"), b"data");
    // Traces and planned totals exist only on the coordinator; until its
    // stream can be relayed home, a remote dry-run stream is refused in
    // the usage lane.
    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["cp", "-n", "--from", "hostA", "--src", &t.s("src")])
        .args(["--to", "hostB", "--as", &t.s("dst")])
        .args(["--results", "r.ndjson"])
        .current_dir(t.path(""))
        .run()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let stderr = stderr_of(&out);
    assert!(stderr.contains("--coordinate-at local"), "{stderr}");
    assert!(!t.path("r.ndjson").exists());
}

#[test]
fn native_verify_only_remote_results_require_local_coordination() {
    let t = Tmp::new();
    let out = native_syq(&[
        "cp",
        "--verify-only",
        "--from",
        "source.invalid",
        "--srcs-in",
        "data",
        "--to",
        "destination.invalid",
        "--into",
        "data",
        "--results",
        &t.s("results"),
    ]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr_of(&out));
    assert!(stderr_of(&out).contains("--coordinate-at local"));
    assert!(!t.path("results").exists());
}

#[test]
fn persistence_status_escapes_peer_errors_but_json_preserves_them() {
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixListener;
    let t = Tmp::new();
    fs::create_dir(t.runtime()).unwrap();
    let command = |args: &[&str]| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
        command
            .args(args)
            .env("XDG_RUNTIME_DIR", t.runtime())
            .env("XDG_CONFIG_HOME", t.path("config"));
        command
    };
    let output = command(&["persist", "on", "--ephemeral"]).run().unwrap();
    assert_output_ok(&output);
    let scope = PathBuf::from(String::from_utf8(output.stdout).unwrap().trim());
    let digest = Sha256::digest(b"@example");
    let key = format!(
        "cm-{}",
        digest[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    write(
        &scope.join(format!("{key}.json")),
        br#"{"user":null,"host":"example","port":null}"#,
    );
    let listener = UnixListener::bind(scope.join(format!("{key}.recv"))).unwrap();
    let error = "peer: \x1b]52;c;bad\x07\r\u{2028}\u{200f}";
    let response = serde_json::to_vec(&serde_json::json!({
        "version": 2, "identity": "old-daemon-fixture", "pid": 1,
        "endpoint": "example", "name": "laptop",
        "connection": {"phase": "failed", "error": error, "ssh_pid": null}
    }))
    .unwrap();
    let server = std::thread::spawn(move || {
        for _ in 0..4 {
            let mut ready = libc::pollfd {
                fd: listener.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            assert_eq!(
                unsafe { libc::poll(&mut ready, 1, 5000) },
                1,
                "status client did not connect within five seconds"
            );
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut length = [0; 4];
            socket.read_exact(&mut length).unwrap();
            let mut request = vec![0; u32::from_be_bytes(length) as usize];
            socket.read_exact(&mut request).unwrap();
            socket
                .write_all(&(response.len() as u32).to_be_bytes())
                .unwrap();
            socket.write_all(&response).unwrap();
        }
    });
    for args in [
        vec!["persist", "status", "--pscope", scope.to_str().unwrap()],
        vec!["persist", "receive", "status"],
    ] {
        let output = command(&args).run().unwrap();
        assert_output_ok(&output);
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(
            text.contains("peer: \\u{1b}]52;c;bad\\u{7}\\r\\u{2028}\\u{200f}"),
            "{text}"
        );
    }
    let output = command(&["persist", "receive", "status", "--json"])
        .run()
        .unwrap();
    assert_output_ok(&output);
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["connections"][0]["connection"]["error"], error);
    let output = command(&[
        "persist",
        "status",
        "--json",
        "--pscope",
        scope.to_str().unwrap(),
    ])
    .run()
    .unwrap();
    assert_output_ok(&output);
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["connections"][0]["receiving"]["error"], error);
    server.join().unwrap();
}

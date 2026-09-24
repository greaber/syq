use super::*;

#[cfg(debug_assertions)]
#[test]
fn off_skips_comparison_but_keeps_parallel_ranges() {
    for inplace in [false, true] {
        let t = Tmp::new();
        let source = prng(128 << 20, 831);
        let mut old = source.clone();
        old[..4096].fill(b'x');
        write(&t.path("src"), &source);
        write(&t.path("dst"), &old);
        set_mtime(&t.path("dst"), 1);
        let run = |reuse: &str| {
            let mut command = compat_command();
            command.args([
                "-a",
                "--stats",
                "--no-progress",
                // Leave time for both workers to consume their pre-split ranges.
                "--bwlimit=64M",
                "--performance-tuning",
                &format!("copy-path=ranges,workers=2,block-reuse={reuse}"),
                &t.s("src"),
                &t.s("dst"),
            ]);
            if inplace {
                command.arg("--inplace");
            }
            command
                .env("SYQ_DEBUG", "1")
                .env("SYQ_TEST_FAIL_BLOCK_COMPARISON", "1")
                .env("SYQ_TEST_WORKER_EVENTS", t.path("workers"));
            command.run().unwrap()
        };
        // Prove the fault hook catches the normal comparison path.
        let failed = run("auto");
        assert!(!failed.status.success());
        assert!(stderr_of(&failed).contains("injected block-comparison failure"));
        assert_eq!(read(&t.path("dst")), old);
        fs::remove_file(t.path("workers")).unwrap();
        let output = run("off");
        assert_output_ok(&output);
        assert_eq!(read(&t.path("dst")), source);
        assert_eq!(tuning_observed(&output)["range_requests"], 32);
        assert_eq!(tuning_observed(&output)["local_whole_files"], 0);
        let events = fs::read_to_string(t.path("workers")).unwrap();
        assert_eq!(
            events
                .lines()
                .filter(|line| line.starts_with("connected "))
                .count(),
            2,
            "{events}"
        );
        let mut range_workers = std::collections::BTreeSet::new();
        let mut transferred = 0u64;
        for event in events.lines().filter(|line| line.starts_with("range ")) {
            let fields: Vec<_> = event.split_whitespace().collect();
            let bytes: u64 = fields[3].parse().unwrap();
            assert!(bytes > 0, "{event}");
            range_workers.insert(fields[1]);
            transferred += bytes;
        }
        assert_eq!(range_workers.len(), 2, "{events}");
        assert_eq!(transferred, source.len() as u64, "{events}");
        assert!(partial_files(&t.0).is_empty());
    }
}

#[cfg(debug_assertions)]
#[test]
fn off_ignores_prior_partial_without_hashing_it() {
    let t = Tmp::new();
    let source = prng(8 << 20, 832);
    write(&t.path("src"), &source);
    let args = [
        "-a",
        "--syq-no-tcp",
        "--performance-tuning=copy-path=ranges,block-reuse=off,workers=2",
        &t.s("src"),
        &t.s("dst"),
    ];
    let partial = interrupted_partial(&args, &t.0);
    // An oversized donor must not contribute stale bytes to the new output.
    write(&partial, &vec![b'z'; 12 << 20]);
    let out = compat_command()
        .args(args)
        .env("SYQ_TEST_FAIL_BLOCK_COMPARISON", "1")
        .env("SYQ_DEBUG", "1")
        .run()
        .unwrap();
    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), source);
    assert_eq!(tuning_observed(&out)["range_requests"], 2);
    // A previous invocation's donor belongs to that invocation, not this one.
    assert_eq!(read(&partial), vec![b'z'; 12 << 20]);
    assert_eq!(partial_files(&t.0), vec![partial]);
}

#[test]
fn off_keeps_quick_checks_and_explicit_checksum_semantics() {
    for inplace in [false, true] {
        let t = Tmp::new();
        let source = prng(8 << 20, 833);
        let mut old = source.clone();
        old[0] ^= 1;
        write(&t.path("src"), &source);
        write(&t.path("dst"), &old);
        set_mtime(&t.path("src"), 1_600_000_000);
        set_mtime(&t.path("dst"), 1_600_000_000);
        let run = |checksum: bool| {
            let mut cmd = compat_command();
            cmd.args([
                "-a",
                "--no-progress",
                "--performance-tuning=copy-path=ranges,block-reuse=off",
                &t.s("src"),
                &t.s("dst"),
            ])
            .env("SYQ_DEBUG", "1");
            if checksum {
                cmd.arg("--checksum");
            }
            if inplace {
                cmd.arg("--inplace");
            }
            let out = cmd.run().unwrap();
            assert_output_ok(&out);
            out
        };
        let skipped = run(false);
        assert_eq!(read(&t.path("dst")), old);
        assert_eq!(tuning_observed(&skipped)["range_requests"], 0);
        let repaired = run(true);
        assert_eq!(read(&t.path("dst")), source);
        assert_eq!(tuning_observed(&repaired)["range_requests"], 2);
        let matched = run(true);
        assert_eq!(tuning_observed(&matched)["range_requests"], 0);
        assert!(partial_files(&t.0).is_empty());
    }
}

#[cfg(debug_assertions)]
#[test]
fn off_remote_update_uses_full_ranges_with_payload_checks() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    let source = prng(8 << 20, 834);
    write(&t.path("src"), &source);
    write(&t.path("dst"), &vec![b'x'; 8 << 20]);
    set_mtime(&t.path("dst"), 1);
    let out = remote_syq_command(
        &t,
        &rsh,
        &[
            "-a",
            "--rsync-path",
            env!("CARGO_BIN_EXE_syq"),
            "--syq-no-bootstrap",
            "--performance-tuning=copy-path=ranges,block-reuse=off",
            "--integrity-checking=transfer=blake3",
            &t.s("src"),
            &format!("fake:{}", t.s("dst")),
        ],
    )
    .env("SYQ_TEST_FAIL_BLOCK_COMPARISON", "1")
    .env("SYQ_DEBUG", "1")
    .run()
    .unwrap();
    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), source);
    assert_eq!(tuning_observed(&out)["range_requests"], 2);
}

#[test]
fn off_preserves_expected_hash_failure_and_old_destination() {
    let t = Tmp::new();
    write(&t.path("src/source"), &prng(5 << 20, 835));
    write(&t.path("destination"), b"old contents");
    let wrong = format!("blake3:{}", "0".repeat(64));
    let output = native_syq(&[
        "cp",
        "--mapping",
        &hashing::expected_mapping(&t, "source", "destination", Some(&wrong)),
        "-C",
        &t.s("src"),
        "--into",
        &t.s(""),
        "--performance-tuning=copy-path=ranges,block-reuse=off,workers=2",
    ]);
    assert!(!output.status.success());
    assert!(stderr_of(&output).contains("hash"), "{output:?}");
    assert_eq!(read(&t.path("destination")), b"old contents");
}

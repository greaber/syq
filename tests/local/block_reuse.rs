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
        let failed = run("on");
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
fn local_default_and_off_preserve_partial_resume_without_reusing_final() {
    for reuse in ["auto", "off"] {
        let t = Tmp::new();
        let source = prng(8 << 20, 832);
        write(&t.path("src"), &source);
        let tuning = format!("copy-path=ranges,block-reuse={reuse},workers=1");
        let src = t.s("src");
        let dst = t.s("dst");
        let args = [
            "-a",
            "--syq-no-tcp",
            "--performance-tuning",
            &tuning,
            &src,
            &dst,
        ];
        let partial = interrupted_partial(&args, &t.0);
        // The partial matches only the first block; the final matches only
        // the second. Only the partial may contribute bytes with reuse off.
        let mut donor = source.clone();
        donor[4 << 20..].fill(b'z');
        write(&partial, &donor);
        let mut old = source.clone();
        old[..4 << 20].fill(b'x');
        write(&t.path("dst"), &old);
        set_mtime(&t.path("dst"), 1);
        let out = compat_command()
            .args(args)
            .env("SYQ_DEBUG", "1")
            .run()
            .unwrap();
        assert_output_ok(&out);
        assert_eq!(read(&t.path("dst")), source);
        assert_eq!(tuning_observed(&out)["range_requests"], 1);
        assert_eq!(read(&partial), donor);
        assert_eq!(partial_files(&t.0), vec![partial]);
    }
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

#[test]
fn local_default_replaces_blocks_and_on_overrides_whole_file_copy() {
    for inplace in [false, true] {
        for reuse in [None, Some("auto"), Some("on"), Some("off")] {
            let t = Tmp::new();
            let source = prng(8 << 20, 836);
            let mut old = source.clone();
            old[..4 << 20].fill(b'x');
            write(&t.path("src"), &source);
            write(&t.path("dst"), &old);
            set_mtime(&t.path("dst"), 1);
            // On must reach comparison even without forcing the range path.
            let mut tuning = if reuse == Some("on") {
                "workers=1"
            } else {
                "copy-path=ranges,workers=1"
            }
            .to_string();
            if let Some(reuse) = reuse {
                tuning.push_str(&format!(",block-reuse={reuse}"));
            }
            let mut cmd = compat_command();
            cmd.args([
                "-a",
                "--syq-no-tcp",
                "--performance-tuning",
                &tuning,
                &t.s("src"),
                &t.s("dst"),
            ])
            .env("SYQ_DEBUG", "1");
            if inplace {
                cmd.arg("--inplace");
            }
            let out = cmd.run().unwrap();
            assert_output_ok(&out);
            assert_eq!(read(&t.path("dst")), source);
            assert_eq!(
                tuning_observed(&out)["range_requests"],
                if reuse == Some("on") { 1 } else { 2 }
            );
            assert_eq!(tuning_observed(&out)["local_whole_files"], 0);
            assert!(stderr_of(&out).contains(if reuse == Some("on") {
                "(effective on)"
            } else {
                "(effective off)"
            }));
            assert!(partial_files(&t.0).is_empty());
        }
    }
}

#[test]
fn remote_defaults_reuse_blocks_for_push_and_pull() {
    for pull in [false, true] {
        let t = Tmp::new();
        let rsh = fake_rsh(&t);
        let source = prng(8 << 20, 837);
        let mut old = source.clone();
        old[..4 << 20].fill(b'x');
        write(&t.path("src"), &source);
        write(&t.path("dst"), &old);
        set_mtime(&t.path("dst"), 1);
        let src = if pull {
            format!("fake:{}", t.s("src"))
        } else {
            t.s("src")
        };
        let dst = if pull {
            t.s("dst")
        } else {
            format!("fake:{}", t.s("dst"))
        };
        let out = remote_syq_command(
            &t,
            &rsh,
            &[
                "-a",
                "--rsync-path",
                env!("CARGO_BIN_EXE_syq"),
                "--syq-no-bootstrap",
                "--performance-tuning=copy-path=ranges",
                &src,
                &dst,
            ],
        )
        .env("SYQ_DEBUG", "1")
        .run()
        .unwrap();
        assert_output_ok(&out);
        assert_eq!(read(&t.path("dst")), source);
        assert_eq!(tuning_observed(&out)["range_requests"], 1);
        assert!(stderr_of(&out).contains("block-reuse=auto (effective on)"));
    }
}

#[cfg(all(debug_assertions, target_os = "linux"))]
#[test]
fn on_keeps_whole_file_copy_for_fresh_files_in_a_mixed_batch() {
    for fallback in [false, true] {
        let t = Tmp::new();
        let source = prng(8 << 20, 838);
        write(&t.path("src/fresh"), &source);
        write(&t.path("src/existing"), &source);
        let mut old = source.clone();
        old[..4 << 20].fill(b'x');
        write(&t.path("dst/existing"), &old);
        set_mtime(&t.path("dst/existing"), 1);
        let mut cmd = compat_command();
        cmd.args([
            "-a",
            "--syq-no-tcp",
            "--performance-tuning=workers=1,block-reuse=on",
            &t.s("src/"),
            &t.s("dst/"),
        ])
        .env("SYQ_DEBUG", "1")
        // Permit the userspace whole-file fallback even on test filesystems
        // without kernel offload. Exercise normal offload and forced fallback.
        .env("SYQ_TEST_COPY_LOCAL_FS", "local");
        if fallback {
            cmd.env("SYQ_TEST_COPY_LOCAL_EXDEV", "1");
        }
        let out = cmd.run().unwrap();
        assert_output_ok(&out);
        assert_eq!(read(&t.path("dst/fresh")), source);
        assert_eq!(read(&t.path("dst/existing")), source);
        assert_eq!(tuning_observed(&out)["local_whole_files"], 1);
        assert_eq!(tuning_observed(&out)["range_requests"], 1);
        assert!(partial_files(&t.path("dst")).is_empty());
    }
}

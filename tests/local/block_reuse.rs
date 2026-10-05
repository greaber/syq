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
                "copy-path=ranges,workers=2",
                if reuse == "aligned-block" {
                    "--no-whole-file"
                } else {
                    "--whole-file"
                },
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
        let failed = run("aligned-block");
        assert!(!failed.status.success());
        assert!(stderr_of(&failed).contains("injected block-comparison failure"));
        assert_eq!(read(&t.path("dst")), old);
        fs::remove_file(t.path("workers")).unwrap();
        let output = run("whole-file");
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
    for whole_file in [false, true] {
        let t = Tmp::new();
        let source = prng(8 << 20, 832);
        write(&t.path("src"), &source);
        let tuning = "copy-path=ranges,workers=1";
        let src = t.s("src");
        let dst = t.s("dst");
        let mut args = vec![
            "-a",
            "--syq-no-tcp",
            "--performance-tuning",
            tuning,
            &src,
            &dst,
        ];
        if whole_file {
            args.push("--whole-file");
        }
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
                "--performance-tuning=copy-path=ranges",
                "--whole-file",
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
            "--performance-tuning=copy-path=ranges",
            "--whole-file",
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
    let observed = tuning_observed(&out);
    // Automatic payloads can be smaller than the 4 MiB request ceiling.
    // Still use ordinary ranges for all bytes, without block comparison.
    assert!(observed["range_requests"].as_u64().unwrap() >= 2);
    assert!((512..=4 << 20).contains(&observed["max_request_bytes"].as_u64().unwrap()));
    assert_eq!(observed["streaming_ranges"], 0);
}

#[test]
fn off_preserves_expected_hash_failure_and_old_destination() {
    let t = Tmp::new();
    write(&t.path("src/source"), &prng(5 << 20, 835));
    write(&t.path("destination"), b"old contents");
    let wrong = format!("blake3:{}", "0".repeat(64));
    let output = native_syq(&[
        "cp",
        "--if-exists=update",
        "--mapping",
        &hashing::expected_mapping(&t, "source", "destination", Some(&wrong)),
        "-C",
        &t.s("src"),
        "--into",
        &t.s(""),
        "--performance-tuning=copy-path=ranges,workers=2",
        "--transfer-strategy=whole-file",
    ]);
    assert!(!output.status.success());
    assert!(stderr_of(&output).contains("hash"), "{output:?}");
    assert_eq!(read(&t.path("destination")), b"old contents");
}

#[test]
fn local_default_replaces_blocks_and_on_overrides_whole_file_copy() {
    for inplace in [false, true] {
        for reuse in [None, Some("aligned-block"), Some("whole-file")] {
            let t = Tmp::new();
            let source = prng(8 << 20, 836);
            let mut old = source.clone();
            old[..4 << 20].fill(b'x');
            write(&t.path("src"), &source);
            write(&t.path("dst"), &old);
            set_mtime(&t.path("dst"), 1);
            // On must reach comparison even without forcing the range path.
            let tuning = if reuse == Some("aligned-block") {
                "workers=1"
            } else {
                "copy-path=ranges,workers=1"
            }
            .to_string();
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
            if let Some(reuse) = reuse {
                cmd.arg(if reuse == "aligned-block" {
                    "--no-whole-file"
                } else {
                    "--whole-file"
                });
            }
            if inplace {
                cmd.arg("--inplace");
            }
            let out = cmd.run().unwrap();
            assert_output_ok(&out);
            assert_eq!(read(&t.path("dst")), source);
            // With block reuse, a file this size is patched in a group, or
            // in place on the per-file path.
            let observed = tuning_observed(&out);
            let grouped = reuse == Some("aligned-block") && !inplace;
            assert_eq!(observed["patched_files"], u64::from(grouped));
            assert_eq!(
                observed["range_requests"],
                match reuse {
                    Some("aligned-block") => u64::from(inplace),
                    _ => 2,
                }
            );
            assert_eq!(tuning_observed(&out)["local_whole_files"], 0);
            assert!(stderr_of(&out).contains(if reuse == Some("aligned-block") {
                "(block reuse on)"
            } else {
                "(block reuse off)"
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
        assert!(stderr_of(&out).contains("transfer-strategy=locality (block reuse on)"));
    }
}

#[cfg(all(debug_assertions, target_os = "linux"))]
#[test]
fn small_replacements_are_compared_in_batches_and_files_that_already_match_are_kept() {
    // Local copies with reuse forced on, then remote push and pull, where
    // reuse is the default.
    for remote in [None, Some(false), Some(true)] {
        let t = Tmp::new();
        write(&t.path("src/changed"), b"new contents");
        write(&t.path("src/same"), b"same contents");
        write(&t.path("src/fresh"), b"fresh");
        write(&t.path("dst/changed"), b"old contents");
        write(&t.path("dst/same"), b"same contents");
        set_mtime(&t.path("dst/changed"), 1);
        set_mtime(&t.path("dst/same"), 1);
        let inode = |name: &str| fs::metadata(t.path(name)).unwrap().ino();
        let (same, changed) = (inode("dst/same"), inode("dst/changed"));
        let out = match remote {
            None => compat_command()
                .args([
                    "-a",
                    "--no-progress",
                    "--performance-tuning=workers=1",
                    "--no-whole-file",
                    &t.s("src/"),
                    &t.s("dst/"),
                ])
                .env("SYQ_DEBUG", "1")
                .run()
                .unwrap(),
            Some(pull) => {
                let rsh = fake_rsh(&t);
                let (src, dst) = if pull {
                    (format!("fake:{}", t.s("src/")), t.s("dst/"))
                } else {
                    (t.s("src/"), format!("fake:{}", t.s("dst/")))
                };
                remote_syq_command(
                    &t,
                    &rsh,
                    &[
                        "-a",
                        "--rsync-path",
                        env!("CARGO_BIN_EXE_syq"),
                        "--syq-no-bootstrap",
                        &src,
                        &dst,
                    ],
                )
                .env("SYQ_DEBUG", "1")
                .run()
                .unwrap()
            }
        };
        assert_output_ok(&out);
        for name in ["changed", "same", "fresh"] {
            assert_eq!(
                read(&t.path(&format!("dst/{name}"))),
                read(&t.path(&format!("src/{name}"))),
                "{name} {remote:?}"
            );
        }
        // The matching file was kept and given the source's times; the
        // changed one was replaced by a new file.
        assert_eq!(inode("dst/same"), same, "{remote:?}");
        assert_ne!(inode("dst/changed"), changed, "{remote:?}");
        assert_eq!(
            fs::metadata(t.path("dst/same")).unwrap().mtime(),
            fs::metadata(t.path("src/same")).unwrap().mtime(),
            "{remote:?}"
        );
        let observed = tuning_observed(&out);
        assert_eq!(observed["range_requests"], 0, "{remote:?}");
        assert!(
            observed["small_batches"].as_u64().unwrap() > 0,
            "{remote:?}"
        );
        assert!(partial_files(&t.path("dst")).is_empty());
    }
}

#[test]
fn bandwidth_limited_copies_send_only_the_small_files_that_differ() {
    let t = Tmp::new();
    let mut same = Vec::new();
    for n in 0..16 {
        let contents = prng(64 << 10, 7000 + n);
        let (src, dst) = (format!("src/same{n}"), format!("dst/same{n}"));
        write(&t.path(&src), &contents);
        write(&t.path(&dst), &contents);
        set_mtime(&t.path(&dst), 1);
        let inode = fs::metadata(t.path(&dst)).unwrap().ino();
        same.push((src, dst, inode));
    }
    write(&t.path("src/changed"), b"new");
    write(&t.path("dst/changed"), b"old");
    set_mtime(&t.path("dst/changed"), 1);
    let rsh = fake_rsh(&t);
    let start = std::time::Instant::now();
    // 1 KiB/s: sending the matching files would take over 16 minutes.
    let out = remote_syq_command(
        &t,
        &rsh,
        &[
            "-a",
            "--bwlimit=1",
            "--rsync-path",
            env!("CARGO_BIN_EXE_syq"),
            "--syq-no-bootstrap",
            &t.s("src/"),
            &format!("fake:{}", t.s("dst/")),
        ],
    )
    .run()
    .unwrap();
    assert_output_ok(&out);
    assert!(
        start.elapsed() < std::time::Duration::from_secs(60),
        "{out:?}"
    );
    for (src, dst, inode) in same {
        assert_eq!(read(&t.path(&dst)), read(&t.path(&src)));
        assert_eq!(fs::metadata(t.path(&dst)).unwrap().ino(), inode);
    }
    assert_eq!(read(&t.path("dst/changed")), b"new");
    assert!(partial_files(&t.path("dst")).is_empty());
}

#[test]
fn a_file_of_which_more_differs_than_a_patch_carries_is_compared_per_file() {
    // A grouped patch carries at most 16 MiB of a file's new data, so that
    // no more is held at once. A file that differs by more is compared again
    // on its own, in 4 MiB blocks, and only those that differ are sent; one
    // within the limit is patched in its group.
    for remote in [false, true] {
        let t = Tmp::new();
        let source = prng(32 << 20, 881);
        for (name, changed) in [("within", 16 << 20), ("over", (16 << 20) + (64 << 10))] {
            let mut old = source.clone();
            old[..changed].fill(b'x');
            write(&t.path(&format!("src/{name}")), &source);
            write(&t.path(&format!("dst/{name}")), &old);
            set_mtime(&t.path(&format!("dst/{name}")), 1);
        }
        let mut args = vec!["-a", "--no-whole-file"];
        let (source_dir, destination_dir) = (t.s("src/"), t.s("dst/"));
        let remote_destination = format!("fake:{destination_dir}");
        let mut command = if remote {
            let rsh = fake_rsh(&t);
            args.extend([
                "--rsync-path",
                env!("CARGO_BIN_EXE_syq"),
                "--syq-no-bootstrap",
                source_dir.as_str(),
                remote_destination.as_str(),
            ]);
            remote_syq_command(&t, &rsh, &args)
        } else {
            args.extend([
                "--no-progress",
                "--performance-tuning=workers=1",
                source_dir.as_str(),
                destination_dir.as_str(),
            ]);
            let mut command = compat_command();
            command.args(&args);
            command
        };
        let out = command.env("SYQ_DEBUG", "1").run().unwrap();
        assert_output_ok(&out);
        for name in ["within", "over"] {
            assert_eq!(
                read(&t.path(&format!("dst/{name}"))),
                source,
                "{name} remote={remote}"
            );
        }
        let observed = tuning_observed(&out);
        assert_eq!(observed["compared_files"], 2, "remote={remote}");
        assert_eq!(observed["patched_files"], 1, "remote={remote}");
        // The five 4 MiB blocks that differ.
        assert_eq!(observed["range_requests"], 5, "remote={remote}");
        assert!(partial_files(&t.path("dst")).is_empty());
    }
}

#[test]
fn by_default_only_replaced_files_of_unchanged_size_are_compared() {
    for explicit in [false, true] {
        let t = Tmp::new();
        let source = prng(2 << 20, 873);
        let mut edited = source.clone();
        edited[5] ^= 1;
        write(&t.path("src/grown"), &source);
        write(&t.path("dst/grown"), &source[..1 << 20]);
        write(&t.path("src/edited"), &source);
        write(&t.path("dst/edited"), &edited);
        for name in ["grown", "edited"] {
            set_mtime(&t.path(&format!("dst/{name}")), 1);
        }
        let rsh = fake_rsh(&t);
        let destination = format!("fake:{}", t.s("dst/"));
        let mut args = vec![
            "-a",
            "--rsync-path",
            env!("CARGO_BIN_EXE_syq"),
            "--syq-no-bootstrap",
        ];
        if explicit {
            args.push("--no-W");
        }
        let source_dir = t.s("src/");
        args.extend([source_dir.as_str(), destination.as_str()]);
        let out = remote_syq_command(&t, &rsh, &args)
            .env("SYQ_DEBUG", "1")
            .run()
            .unwrap();
        assert_output_ok(&out);
        for name in ["grown", "edited"] {
            assert_eq!(read(&t.path(&format!("dst/{name}"))), source, "{name}");
        }
        // A file whose size changed is copied whole without reading the old
        // one, unless block reuse was chosen explicitly.
        let observed = tuning_observed(&out);
        let compared = if explicit { 2 } else { 1 };
        assert_eq!(observed["compared_files"], compared, "explicit={explicit}");
        assert_eq!(observed["patched_files"], compared, "explicit={explicit}");
    }
}

#[cfg(debug_assertions)]
#[test]
fn a_patch_whose_payload_fails_its_check_is_copied_whole() {
    // With transfer integrity, the receiver checks the differing blocks a
    // patch carries against the payload hash the source sent. Here one
    // payload check fails, as for data corrupted in transit: the patch is
    // refused and the file is copied whole instead.
    for (remote, cloning) in [(false, true), (false, false), (true, true)] {
        let t = Tmp::new();
        let source = prng(8 << 20, 874);
        let mut old = source.clone();
        old[4 << 20] ^= 1;
        write(&t.path("src/file"), &source);
        write(&t.path("dst/file"), &old);
        set_mtime(&t.path("dst/file"), 1);
        let marker = t.path("corrupted-once");
        let (source_dir, destination_dir) = (t.s("src/"), t.s("dst/"));
        let remote_destination = format!("fake:{destination_dir}");
        let mut args = vec![
            "-a",
            "--no-whole-file",
            "--integrity-checking=transfer=blake3",
        ];
        let mut command = if remote {
            let rsh = fake_rsh(&t);
            args.extend([
                "--rsync-path",
                env!("CARGO_BIN_EXE_syq"),
                "--syq-no-bootstrap",
                source_dir.as_str(),
                remote_destination.as_str(),
            ]);
            remote_syq_command(&t, &rsh, &args)
        } else {
            args.extend([source_dir.as_str(), destination_dir.as_str()]);
            let mut command = compat_command();
            command.args(&args).arg("--no-progress");
            command
        };
        command
            .env("SYQ_DEBUG", "1")
            .env("SYQ_TEST_CORRUPT_PAYLOAD_ONCE", &marker);
        if !cloning {
            command.env("SYQ_TEST_BASIS_CLONE_UNSUPPORTED", "1");
        }
        let out = command.run().unwrap();
        assert_output_ok(&out);
        let case = format!("remote={remote} cloning={cloning}");
        assert!(marker.exists(), "{case}: the payload check never ran");
        assert_eq!(read(&t.path("dst/file")), source, "{case}");
        let observed = tuning_observed(&out);
        assert_eq!(observed["compared_files"], 1, "{case}");
        assert_eq!(observed["patched_files"], 0, "{case}");
        assert!(partial_files(&t.path("dst")).is_empty(), "{case}");
    }
}

#[test]
fn a_leftover_partial_sends_a_replaced_file_to_the_resuming_path() {
    let t = Tmp::new();
    let source = prng(8 << 20, 871);
    let mut old = source.clone();
    old[..4 << 20].fill(b'x');
    write(&t.path("src"), &source);
    write(&t.path("dst"), &old);
    set_mtime(&t.path("dst"), 1);
    // An interrupted earlier run left the new first half.
    write(&t.path(".dst.syq-tmp.abcdefghijklmnop"), &source[..4 << 20]);
    let out = compat_command()
        .args([
            "-a",
            "--no-progress",
            "--performance-tuning=workers=1",
            "--no-whole-file",
            &t.s("src"),
            &t.s("dst"),
        ])
        .env("SYQ_DEBUG", "1")
        .run()
        .unwrap();
    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), source);
    // Compared in a group, then copied on the per-file path, which resumes
    // from partials.
    let observed = tuning_observed(&out);
    assert_eq!(observed["compared_files"], 1);
    assert_eq!(observed["patched_files"], 0);
    assert!(observed["range_requests"].as_u64().unwrap() > 0);
}

#[cfg(debug_assertions)]
#[test]
fn a_small_destination_that_grows_while_compared_is_replaced_not_kept() {
    let t = Tmp::new();
    let contents = vec![b'a'; 64 << 10];
    write(&t.path("src"), &contents);
    write(&t.path("dst"), &contents);
    set_mtime(&t.path("src"), 1_600_000_001);
    set_mtime(&t.path("dst"), 1_600_000_000);
    let ready = t.path("compared");
    let continuation = t.path("continue");
    let mut child = compat_command()
        .args([
            "-a",
            "--performance-tuning",
            "workers=1",
            "--no-whole-file",
            "--no-progress",
            &t.s("src"),
            &t.s("dst"),
        ])
        .env("SYQ_TEST_SMALL_COMPARED_READY_FILE", &ready)
        .env("SYQ_TEST_SMALL_COMPARED_CONTINUE_FILE", &continuation)
        .start()
        .unwrap();
    wait_for_confinement_marker(&mut child, &ready, "small-file comparison");
    OpenOptions::new()
        .append(true)
        .open(t.path("dst"))
        .unwrap()
        .write_all(b"trailing data")
        .unwrap();
    release_confinement_barrier(&continuation);
    assert!(child.wait().unwrap().success());
    assert_eq!(read(&t.path("dst")), contents);
    assert!(partial_files(&t.0).is_empty());
}

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
            "--performance-tuning=workers=1",
            "--no-whole-file",
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
        assert_eq!(tuning_observed(&out)["range_requests"], 0);
        assert_eq!(tuning_observed(&out)["patched_files"], 1);
        assert!(partial_files(&t.path("dst")).is_empty());
    }
}

#[cfg(debug_assertions)]
#[test]
fn pipeline_restarts_after_mismatch_and_skips_identical_contents() {
    for matching in [0, 1, 2] {
        let t = Tmp::new();
        let source = prng((8 << 20) + 17, 839);
        let mut old = source.clone();
        if matching < 2 {
            old[4 << 20..].fill(b'x');
        }
        if matching == 0 {
            old[..4 << 20].fill(b'y');
        }
        write(&t.path("src"), &source);
        write(&t.path("dst"), &old);
        set_mtime(&t.path("dst"), 1);
        let out = compat_command()
            .args([
                "-a",
                "--no-progress",
                "--performance-tuning=workers=1,copy-path=ranges",
                "--no-whole-file",
                &t.s("src"),
                &t.s("dst"),
            ])
            .env("SYQ_DEBUG", "1")
            .env("SYQ_TEST_SOURCE_READ_EVENTS", t.path("reads"))
            .env("SYQ_TEST_BASIS_CLONE_UNSUPPORTED", "1")
            .run()
            .unwrap();
        assert_output_ok(&out);
        assert_eq!(read(&t.path("dst")), source);
        let events = fs::read_to_string(t.path("reads")).unwrap_or_default();
        let mut next = 0u64;
        for event in events.lines() {
            let fields: Vec<_> = event.split_whitespace().collect();
            assert_eq!(fields[1].parse::<u64>().unwrap(), next, "{events}");
            next += fields[2].parse::<u64>().unwrap();
        }
        assert_eq!(
            next,
            if matching == 2 {
                0
            } else {
                source.len() as u64
            }
        );
        assert_eq!(tuning_observed(&out)["range_requests"], [3, 2, 0][matching]);
        assert!(partial_files(&t.0).is_empty());
    }
}

#[cfg(debug_assertions)]
#[test]
fn pipeline_handles_final_mutation_after_staging() {
    let t = Tmp::new();
    let source = prng(8 << 20, 840);
    let mut old = source.clone();
    old[4 << 20..].fill(b'x');
    write(&t.path("src"), &source);
    write(&t.path("dst"), &old);
    set_mtime(&t.path("dst"), 1);
    let ready = t.path("ready");
    let continuation = t.path("continue");
    let mut child = compat_command()
        .args([
            "-a",
            "--performance-tuning=workers=1,copy-path=ranges",
            "--no-whole-file",
            &t.s("src"),
            &t.s("dst"),
        ])
        .env("SYQ_TEST_STAGED_BASIS_READY_FILE", &ready)
        .env("SYQ_TEST_STAGED_BASIS_CONTINUE_FILE", &continuation)
        .start()
        .unwrap();
    wait_for_confinement_marker(&mut child, &ready, "private comparison basis");
    // Change the same donor inode after staging. A clone preserves the old
    // bytes; without cloning, comparison must detect the new donor bytes.
    write(&t.path("dst"), &vec![b'z'; source.len()]);
    release_confinement_barrier(&continuation);
    assert!(child.wait().unwrap().success());
    assert_eq!(read(&t.path("dst")), source);
}

#[cfg(debug_assertions)]
#[test]
fn pipeline_parallel_copy_ranges_read_each_source_byte_once() {
    let t = Tmp::new();
    let source = prng(128 << 20, 841);
    let mut old = source.clone();
    for block in old.chunks_mut(4 << 20).step_by(2) {
        block.fill(b'x');
    }
    write(&t.path("src"), &source);
    write(&t.path("dst"), &old);
    set_mtime(&t.path("dst"), 1);
    let out = compat_command()
        .args([
            "-a",
            "--no-progress",
            "--bwlimit=64M",
            "--performance-tuning=workers=2",
            "--no-whole-file",
            &t.s("src"),
            &t.s("dst"),
        ])
        .env("SYQ_TEST_SOURCE_READ_EVENTS", t.path("reads"))
        .env("SYQ_TEST_BASIS_CLONE_UNSUPPORTED", "1")
        .env("SYQ_TEST_WORKER_EVENTS", t.path("workers"))
        .run()
        .unwrap();
    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), source);
    let events = fs::read_to_string(t.path("reads")).unwrap();
    let mut reads: Vec<(u64, u64)> = events
        .lines()
        .map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            (fields[1].parse().unwrap(), fields[2].parse().unwrap())
        })
        .collect();
    reads.sort_unstable();
    let mut next = 0;
    for (off, len) in reads {
        assert_eq!(off, next, "{events}");
        next += len;
    }
    assert_eq!(next, source.len() as u64);
    let workers = fs::read_to_string(t.path("workers")).unwrap();
    let ids: std::collections::BTreeSet<_> = workers
        .lines()
        .filter(|line| line.starts_with("compare-range "))
        .map(|line| line.split_whitespace().nth(1).unwrap())
        .collect();
    assert_eq!(ids.len(), 2, "{workers}");
}

#[cfg(debug_assertions)]
#[test]
fn pipeline_recovers_dropped_write_with_matching_prefix() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    t.expose_remote_syq();
    let source = prng(24 << 20, 842);
    let mut old = source.clone();
    old[4 << 20..].fill(b'x');
    write(&t.path("src"), &source);
    write(&t.path("dst/file"), &old);
    set_mtime(&t.path("dst/file"), 1);
    let out = remote_syq_command(
        &t,
        &rsh,
        &[
            "-a",
            "--stats",
            "--performance-tuning=pipeline-depth=4,copy-path=ranges",
            &t.s("src"),
            &format!("fake:{}/file", t.s("dst")),
        ],
    )
    .env("SYQ_TEST_BASIS_CLONE_UNSUPPORTED", "1")
    .env("SYQ_TEST_DROP_AFTER_REQUEST", "write")
    .env("SYQ_TEST_DROP_AFTER_N_REQUESTS", "2")
    .env("SYQ_TEST_DROP_MARKER", t.path("dropped"))
    .run()
    .unwrap();
    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst/file")), source);
    assert!(t.path("dropped").exists());
    assert!(String::from_utf8_lossy(&out.stderr).contains("connection dropped; reopening"));
    assert!(partial_files(&t.path("dst")).is_empty());
}

#[test]
fn pipeline_handles_growing_shrinking_and_empty_files() {
    for (source_len, destination_len) in [
        (9 << 20, 5 << 20),
        (5 << 20, 9 << 20),
        (0, 5 << 20),
        (5 << 20, 0),
    ] {
        let t = Tmp::new();
        let contents = prng(source_len.max(destination_len), 843);
        write(&t.path("src"), &contents[..source_len]);
        write(&t.path("dst"), &contents[..destination_len]);
        set_mtime(&t.path("dst"), 1);
        let output = compat_command()
            .args([
                "-a",
                "--performance-tuning=workers=1",
                "--no-whole-file",
                &t.s("src"),
                &t.s("dst"),
            ])
            .env("SYQ_TEST_BASIS_CLONE_UNSUPPORTED", "1")
            .run()
            .unwrap();
        assert_output_ok(&output);
        assert_eq!(read(&t.path("dst")), &contents[..source_len]);
        assert!(partial_files(&t.0).is_empty());
    }
}

#[test]
fn pipeline_equality_probe_spans_windows_and_handles_late_difference() {
    for mismatch in [None, Some((76 << 20) + 3)] {
        let t = Tmp::new();
        let source = vec![b's'; (80 << 20) + 17];
        let mut old = source.clone();
        if let Some(offset) = mismatch {
            old[offset] = b'x';
        }
        write(&t.path("src"), &source);
        write(&t.path("dst"), &old);
        set_mtime(&t.path("dst"), 1);
        let before = fs::metadata(t.path("dst")).unwrap();
        let out = compat_command()
            .args([
                "-a",
                "--no-progress",
                "--performance-tuning=workers=1",
                "--no-whole-file",
                &t.s("src"),
                &t.s("dst"),
            ])
            .env("SYQ_DEBUG", "1")
            .env("SYQ_TEST_BASIS_CLONE_UNSUPPORTED", "1")
            .run()
            .unwrap();
        assert_output_ok(&out);
        assert_eq!(read(&t.path("dst")), source);
        let after = fs::metadata(t.path("dst")).unwrap();
        if mismatch.is_none() {
            assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
            assert_eq!(tuning_observed(&out)["range_requests"], 0);
        } else {
            assert_eq!(tuning_observed(&out)["range_requests"], 1);
        }
        let src = fs::metadata(t.path("src")).unwrap();
        assert_eq!(
            (src.mtime(), src.mtime_nsec()),
            (after.mtime(), after.mtime_nsec())
        );
        assert!(partial_files(&t.0).is_empty());
    }
}

#[test]
fn stale_partial_does_not_replace_an_identical_final_with_different_metadata() {
    for capped_pull in [false, true] {
        for donor_len in [5, 8 << 20] {
            let t = Tmp::new();
            let source = prng(8 << 20, 864);
            write(&t.path("src"), &source);
            write(&t.path("dst"), &source);
            let donor = t.path(".dst.syq-tmp.abcdefghijklmnop");
            write(&donor, &vec![b'z'; donor_len]);
            let inode = fs::metadata(t.path("dst")).unwrap().ino();
            let rsh = fake_rsh(&t);
            // Leftover donors persist. Neither this run nor a subsequent
            // metadata repair should rewrite an already matching final file.
            for _ in 0..2 {
                set_mtime(&t.path("dst"), 1);
                let mut command = if capped_pull {
                    remote_syq_command(
                        &t,
                        &rsh,
                        &[
                            "-a",
                            "--rsync-path",
                            env!("CARGO_BIN_EXE_syq"),
                            "--syq-no-bootstrap",
                            "--bwlimit=64M",
                            "--no-whole-file",
                            &format!("fake:{}", t.s("src")),
                            &t.s("dst"),
                        ],
                    )
                } else {
                    let mut command = compat_command();
                    command.args([
                        "-a",
                        "--no-progress",
                        "--performance-tuning=workers=1",
                        "--no-whole-file",
                        &t.s("src"),
                        &t.s("dst"),
                    ]);
                    command
                };
                let out = command.env("SYQ_DEBUG", "1").run().unwrap();
                assert_output_ok(&out);
                assert_eq!(read(&t.path("dst")), source);
                assert_eq!(fs::metadata(t.path("dst")).unwrap().ino(), inode);
                assert_eq!(tuning_observed(&out)["range_requests"], 0);
                assert_eq!(read(&donor), vec![b'z'; donor_len]);
            }
        }
    }
}

#[test]
fn bandwidth_limited_pulls_transfer_only_differing_blocks() {
    for pacing in ["average", "125ms"] {
        for changed in [0, 1 << 19, 1 << 20] {
            let t = Tmp::new();
            let rsh = fake_rsh(&t);
            let source = prng(1 << 20, 863);
            let mut old = source.clone();
            old[..changed].fill(0);
            write(&t.path("src"), &source);
            write(&t.path("dst"), &old);
            set_mtime(&t.path("dst"), 1);
            let src = format!("fake:{}", t.s("src"));
            let tuning = format!(
                "copy-path=ranges,request-size=128K,comparison-block-size=256K,bw-pacing={pacing}"
            );
            let out = remote_syq_command(
                &t,
                &rsh,
                &[
                    "-a",
                    "--rsync-path",
                    env!("CARGO_BIN_EXE_syq"),
                    "--syq-no-bootstrap",
                    "--bwlimit=1M",
                    "--performance-tuning",
                    &tuning,
                    &src,
                    &t.s("dst"),
                ],
            )
            .env("SYQ_DEBUG", "1")
            .run()
            .unwrap();
            assert_output_ok(&out);
            assert_eq!(read(&t.path("dst")), source);
            assert_eq!(
                tuning_observed(&out)["range_requests"],
                changed / (128 << 10)
            );
            assert!(partial_files(&t.0).is_empty());
        }
    }
}

#[test]
fn bandwidth_limited_relays_transfer_only_differing_blocks() {
    for changed in [0, 1 << 19, 1 << 20] {
        let t = Tmp::new();
        let rsh = fake_rsh(&t);
        let source = prng(1 << 20, 865);
        let mut old = source.clone();
        old[..changed].fill(0);
        write(&t.path("src"), &source);
        write(&t.path("dst"), &old);
        set_mtime(&t.path("dst"), 1);
        let out = Command::new(env!("CARGO_BIN_EXE_syq"))
            .args(["cp", "--rsh"]).arg(&rsh)
            .args(["--syq-path", env!("CARGO_BIN_EXE_syq"), "--no-tcp",
                "--no-progress", "--resource-limits=bandwidth=1M",
                "--performance-tuning=workers=1,copy-path=ranges,request-size=128K,comparison-block-size=256K,bw-pacing=average",
                "--from", "hostA", &t.s("src"), "--to", "hostB",
                "--coordinate-at", "local", "--as", &t.s("dst")])
            .env("FAKE_REMOTE_HOME", t.path("remote-home"))
            .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
            .env("FAKE_RSH_LOG", t.path("rsh.log"))
            .env("SYQ_DEBUG", "1")
            .run().unwrap();
        assert_output_ok(&out);
        assert_eq!(read(&t.path("dst")), source);
        assert_eq!(
            tuning_observed(&out)["range_requests"],
            changed / (128 << 10)
        );
        assert!(partial_files(&t.0).is_empty());
    }
}

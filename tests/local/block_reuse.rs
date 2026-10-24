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
            // With block reuse, a file this size is patched in a group, and
            // with --inplace updated in place there.
            let observed = tuning_observed(&out);
            let grouped = reuse == Some("aligned-block");
            assert_eq!(observed["patched_files"], u64::from(grouped));
            assert_eq!(
                observed["range_requests"],
                match reuse {
                    Some("aligned-block") => 0,
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

/// The byte counts `--stats` printed for `label`.
fn stats_bytes(out: &Output, label: &str) -> u64 {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout
        .lines()
        .find_map(|line| line.trim().strip_prefix(&format!("{label}: ")))
        .unwrap_or_else(|| panic!("missing {label} in {stdout}"));
    line.replace(',', "").parse().unwrap()
}

#[test]
fn stats_show_grouped_comparison_reads_and_hashing() {
    // Edited files compared in groups: the destination reads and hashes
    // each file it would replace, and the source hashes its own.
    let t = Tmp::new();
    let (files, size) = (4, 4 << 20);
    for i in 0..files {
        let source = prng(size, 900 + i as u64);
        let mut old = source.clone();
        old[1 << 20..(1 << 20) + 100].fill(b'x');
        write(&t.path(&format!("src/f{i}")), &source);
        write(&t.path(&format!("dst/f{i}")), &old);
        set_mtime(&t.path(&format!("dst/f{i}")), 1);
    }
    let out = native_syq(&[
        "cp",
        "--transfer-strategy",
        "aligned-block",
        "--stats",
        "--no-progress",
        "--results",
        &t.s("results"),
        "--srcs-in",
        &t.s("src"),
        "--into",
        &t.s("dst"),
    ]);
    assert_output_ok(&out);
    for i in 0..files {
        assert_eq!(
            read(&t.path(&format!("src/f{i}"))),
            read(&t.path(&format!("dst/f{i}")))
        );
    }
    let records: Vec<serde_json::Value> = fs::read_to_string(t.path("results"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let activity = records
        .iter()
        .rev()
        .find_map(|record| record.get("activity"))
        .expect("activity with --stats");
    // Each endpoint's filesystem operations over the whole copy: whether
    // they hashed, and the bytes they read.
    let observed = |endpoint: &str| -> (bool, u64) {
        activity["endpoints"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["label"].as_str().unwrap().starts_with(endpoint))
            .flat_map(|row| row["cumulative_actors"].as_array().unwrap())
            .filter(|actor| actor["role"] == "filesystem")
            .fold((false, 0), |(hashed, read), actor| {
                (
                    hashed || actor["fractions"].get("hashing").is_some(),
                    read + actor["bytes"]["source_read"].as_u64().unwrap_or(0),
                )
            })
    };
    let (hashed, read_bytes) = observed("destination worker");
    assert!(hashed, "destination hashing: {activity}");
    assert!(
        read_bytes >= (files * size) as u64,
        "destination reads {read_bytes}: {activity}"
    );
    assert!(observed("source worker").0, "source hashing: {activity}");
}

/// Files of 32 MiB, one of which differs by 16 MiB, as much as one patch
/// carries, and one by more, written to `src` and `dst`. Returns the source
/// contents.
fn large_differences(t: &Tmp) -> Vec<u8> {
    let source = prng(32 << 20, 881);
    for (name, changed) in [("within", 16 << 20), ("over", (16 << 20) + (64 << 10))] {
        let mut old = source.clone();
        old[..changed].fill(b'x');
        write(&t.path(&format!("src/{name}")), &source);
        write(&t.path(&format!("dst/{name}")), &old);
        set_mtime(&t.path(&format!("dst/{name}")), 1);
    }
    source
}

/// A copy of `src/` into `dst/` that reuses blocks: in-process, pushed to a
/// remote destination, or pulled from a remote source.
fn reusing_copy(t: &Tmp, route: &str, extra: &[&str]) -> Command {
    let (source_dir, destination_dir) = (t.s("src/"), t.s("dst/"));
    let mut args = vec!["-a", "--no-whole-file", "--stats"];
    args.extend(extra);
    if route == "local" {
        let mut command = compat_command();
        command.args(&args).args([
            "--no-progress",
            "--performance-tuning=workers=1",
            source_dir.as_str(),
            destination_dir.as_str(),
        ]);
        return command;
    }
    let rsh = fake_rsh(t);
    let remote = |path: &str| format!("fake:{path}");
    let (source, destination) = if route == "push" {
        (source_dir.clone(), remote(&destination_dir))
    } else {
        (remote(&source_dir), destination_dir.clone())
    };
    args.extend([
        "--rsync-path",
        env!("CARGO_BIN_EXE_syq"),
        "--syq-no-bootstrap",
        source.as_str(),
        destination.as_str(),
    ]);
    remote_syq_command(t, &rsh, &args)
}

#[test]
fn a_file_of_which_more_differs_than_a_patch_carries_streams_its_patch() {
    // A grouped patch carries at most 16 MiB of a file's new data, so that
    // no more is held at once. A file that differs by more streams its
    // patch: its differing blocks follow in pieces as they are read, and
    // only they are sent.
    for route in ["local", "push", "pull"] {
        let t = Tmp::new();
        let source = large_differences(&t);
        let out = reusing_copy(&t, route, &[])
            .env("SYQ_DEBUG", "1")
            .run()
            .unwrap();
        assert_output_ok(&out);
        for name in ["within", "over"] {
            assert_eq!(
                read(&t.path(&format!("dst/{name}"))),
                source,
                "{name} {route}"
            );
        }
        let observed = tuning_observed(&out);
        assert_eq!(observed["compared_files"], 2, "{route}");
        assert_eq!(observed["patched_files"], 2, "{route}");
        assert_eq!(observed["streamed_patches"], 1, "{route}");
        assert_eq!(observed["range_requests"], 0, "{route}");
        let sent = (32 << 20) + (64 << 10);
        assert_eq!(stats_bytes(&out, "bytes transferred"), sent, "{route}");
        assert_eq!(
            stats_bytes(&out, "bytes unchanged"),
            (64 << 20) - sent,
            "{route}"
        );
        assert!(partial_files(&t.path("dst")).is_empty(), "{route}");
    }
}

#[cfg(debug_assertions)]
#[test]
fn a_streamed_patch_checks_each_piece_and_one_that_fails_is_copied_whole() {
    for (route, corrupted) in [("local", false), ("local", true), ("push", true)] {
        let case = format!("{route} corrupted={corrupted}");
        let t = Tmp::new();
        let source = prng(32 << 20, 882);
        let mut old = source.clone();
        old[(8 << 20)..(28 << 20)].fill(b'y');
        write(&t.path("src/file"), &source);
        write(&t.path("dst/file"), &old);
        set_mtime(&t.path("dst/file"), 1);
        let marker = t.path("corrupted-once");
        let mut command = reusing_copy(&t, route, &["--integrity-checking=transfer=blake3"]);
        command.env("SYQ_DEBUG", "1");
        if corrupted {
            command.env("SYQ_TEST_CORRUPT_PAYLOAD_ONCE", &marker);
        }
        let out = command.run().unwrap();
        assert_output_ok(&out);
        assert_eq!(read(&t.path("dst/file")), source, "{case}");
        assert_eq!(marker.exists(), corrupted, "{case}");
        let observed = tuning_observed(&out);
        assert_eq!(observed["compared_files"], 1, "{case}");
        let streamed = u64::from(!corrupted);
        assert_eq!(observed["patched_files"], streamed, "{case}");
        assert_eq!(observed["streamed_patches"], streamed, "{case}");
        assert!(partial_files(&t.path("dst")).is_empty(), "{case}");
    }
}

#[cfg(debug_assertions)]
#[test]
fn a_streamed_patch_whose_source_changes_while_it_is_read_is_not_published() {
    let t = Tmp::new();
    let source = prng(32 << 20, 883);
    let mut old = source.clone();
    old[..20 << 20].fill(b'z');
    write(&t.path("src/file"), &source);
    write(&t.path("dst/file"), &old);
    set_mtime(&t.path("dst/file"), 1);
    let ready = t.path("read");
    let continuation = t.path("continue");
    let mut child = reusing_copy(&t, "local", &[])
        .env("SYQ_DEBUG", "1")
        .env("SYQ_TEST_PATCH_STREAM_RECHECK_READY_FILE", &ready)
        .env("SYQ_TEST_PATCH_STREAM_RECHECK_CONTINUE_FILE", &continuation)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .start()
        .unwrap();
    wait_for_confinement_marker(&mut child, &ready, "streamed patch source check");
    // Every piece has been read; the source then changes.
    let changed = prng(32 << 20, 884);
    write(&t.path("src/file"), &changed);
    set_mtime(&t.path("src/file"), 1_700_000_000);
    release_confinement_barrier(&continuation);
    let out = child.wait_with_output().unwrap();
    assert_output_ok(&out);
    assert!(
        stderr_of(&out).contains("changed during transfer, retrying"),
        "{}",
        stderr_of(&out)
    );
    // The patch was abandoned and the file copied again from its new source.
    assert_eq!(read(&t.path("dst/file")), changed);
    assert_eq!(tuning_observed(&out)["streamed_patches"], 0);
    assert!(partial_files(&t.path("dst")).is_empty());
}

#[cfg(debug_assertions)]
#[test]
fn a_streamed_patch_whose_source_shrinks_is_retried_at_its_new_size() {
    // The source shrinks once compared, so the pieces past its new end
    // cannot be read. The file is retried as one whose source changed, at
    // its new size, rather than replaced whole at the size it was planned.
    let t = Tmp::new();
    let source = prng(32 << 20, 887);
    let mut old = source.clone();
    old[..20 << 20].fill(b'v');
    write(&t.path("src/file"), &source);
    write(&t.path("dst/file"), &old);
    set_mtime(&t.path("dst/file"), 1);
    let ready = t.path("compared");
    let continuation = t.path("continue");
    let mut child = reusing_copy(&t, "local", &[])
        .env("SYQ_DEBUG", "1")
        .env("SYQ_TEST_PATCH_STREAM_READY_FILE", &ready)
        .env("SYQ_TEST_PATCH_STREAM_CONTINUE_FILE", &continuation)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .start()
        .unwrap();
    wait_for_confinement_marker(&mut child, &ready, "streamed patch pieces");
    OpenOptions::new()
        .write(true)
        .open(t.path("src/file"))
        .unwrap()
        .set_len(10 << 20)
        .unwrap();
    release_confinement_barrier(&continuation);
    let out = child.wait_with_output().unwrap();
    assert_output_ok(&out);
    assert!(
        stderr_of(&out).contains("changed during transfer, retrying"),
        "{}",
        stderr_of(&out)
    );
    assert_eq!(read(&t.path("dst/file")), &source[..10 << 20]);
    // The retry copies what the source now holds, once.
    assert_eq!(stats_bytes(&out, "bytes transferred"), 10 << 20);
    assert_eq!(tuning_observed(&out)["streamed_patches"], 0);
    assert!(partial_files(&t.path("dst")).is_empty());
}

#[cfg(debug_assertions)]
#[test]
fn a_streamed_patch_that_fails_at_its_begin_is_copied_whole() {
    // The receiver fails the patch as it begins, over a real pipe: the
    // file is then copied whole and ends correct, with nothing left
    // behind. How many pieces can go out before the failure's reply
    // arrives depends on timing here; the early stop itself is checked
    // exactly by `transfer::tests::a_streamed_patch_that_fails_at_its_begin_sends_none_of_its_pieces`.
    let t = Tmp::new();
    let source = prng(32 << 20, 888);
    let mut old = source.clone();
    old[..20 << 20].fill(b'u');
    write(&t.path("src/file"), &source);
    write(&t.path("dst/file"), &old);
    set_mtime(&t.path("dst/file"), 1);
    let out = reusing_copy(&t, "push", &[])
        .env("SYQ_DEBUG", "1")
        .env("SYQ_TEST_FAIL_PATCH_STREAM_BEGIN", "1")
        .run()
        .unwrap();
    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst/file")), source);
    let observed = tuning_observed(&out);
    assert_eq!(observed["compared_files"], 1);
    assert_eq!(observed["patched_files"], 0);
    assert_eq!(observed["streamed_patches"], 0);
    // Only the whole copy counts as transferred.
    assert_eq!(stats_bytes(&out, "bytes transferred"), 32 << 20);
    assert!(partial_files(&t.path("dst")).is_empty());
}

#[cfg(debug_assertions)]
#[test]
fn a_streamed_patch_publishes_over_a_destination_changed_before_its_end() {
    let t = Tmp::new();
    let source = large_differences(&t);
    let ready = t.path("written");
    let continuation = t.path("continue");
    let mut child = reusing_copy(&t, "local", &[])
        .env("SYQ_DEBUG", "1")
        .env("SYQ_TEST_PATCH_STREAM_END_READY_FILE", &ready)
        .env("SYQ_TEST_PATCH_STREAM_END_CONTINUE_FILE", &continuation)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .start()
        .unwrap();
    wait_for_confinement_marker(&mut child, &ready, "streamed patch publication");
    // The stage holds its reused blocks already; the file it replaces is
    // rewritten, as by another writer, before it is published.
    write(&t.path("dst/over"), b"rewritten meanwhile");
    release_confinement_barrier(&continuation);
    let out = child.wait_with_output().unwrap();
    assert_output_ok(&out);
    for name in ["within", "over"] {
        assert_eq!(read(&t.path(&format!("dst/{name}"))), source, "{name}");
    }
    assert_eq!(tuning_observed(&out)["streamed_patches"], 1);
    assert!(partial_files(&t.path("dst")).is_empty());
}

#[cfg(debug_assertions)]
#[test]
fn a_streamed_patch_that_fails_leaves_no_partial_file() {
    // The patch fails as it would be published, or its connection drops
    // after one of its pieces; the file is copied again.
    for (route, failure) in [("local", "publish"), ("push", "publish"), ("push", "drop")] {
        let case = format!("{route} {failure}");
        let t = Tmp::new();
        let source = large_differences(&t);
        let mut command = reusing_copy(&t, route, &[]);
        command.env("SYQ_DEBUG", "1");
        if failure == "publish" {
            command.env("SYQ_TEST_FAIL_PUT_SMALL_BEFORE_RENAME", "over");
        } else {
            command
                .env("SYQ_TEST_DROP_AFTER_REQUEST", "patch-data")
                .env("SYQ_TEST_DROP_MARKER", t.path("dropped"));
        }
        let out = command.run().unwrap();
        assert_output_ok(&out);
        for name in ["within", "over"] {
            assert_eq!(
                read(&t.path(&format!("dst/{name}"))),
                source,
                "{case} {name}"
            );
        }
        // A patch that failed as it was published is copied whole; one
        // whose connection dropped is compared and streamed again.
        let streamed = if failure == "drop" {
            assert!(t.path("dropped").exists(), "{case}");
            assert!(
                stderr_of(&out).contains("connection dropped; reopening"),
                "{case}: {}",
                stderr_of(&out)
            );
            1
        } else {
            0
        };
        assert_eq!(
            tuning_observed(&out)["streamed_patches"],
            streamed,
            "{case}"
        );
        assert!(partial_files(&t.path("dst")).is_empty(), "{case}");
    }
}

#[test]
fn a_relayed_copy_streams_its_patch_through_the_coordinator() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    let source = prng(32 << 20, 885);
    let mut old = source.clone();
    old[4 << 20..24 << 20].fill(0);
    write(&t.path("src"), &source);
    write(&t.path("dst"), &old);
    set_mtime(&t.path("dst"), 1);
    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["cp", "--rsh"])
        .arg(&rsh)
        .args([
            "--syq-path",
            env!("CARGO_BIN_EXE_syq"),
            "--no-tcp",
            "--no-progress",
            "--stats",
            "--integrity-checking=transfer=blake3",
            "--performance-tuning=workers=1",
            "--from",
            "hostA",
            &t.s("src"),
            "--to",
            "hostB",
            "--coordinate-at",
            "local",
            "--as",
            &t.s("dst"),
        ])
        .env("FAKE_REMOTE_HOME", t.path("remote-home"))
        .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
        .env("SYQ_DEBUG", "1")
        .run()
        .unwrap();
    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), source);
    assert_eq!(tuning_observed(&out)["streamed_patches"], 1);
    assert_eq!(stats_bytes(&out, "bytes transferred"), 20 << 20);
    assert!(partial_files(&t.0).is_empty());
}

#[cfg(debug_assertions)]
#[test]
fn a_streamed_patch_whose_stage_is_refused_for_want_of_descriptors_is_staged_again() {
    let t = Tmp::new();
    let source = prng(32 << 20, 886);
    let mut old = source.clone();
    old[..20 << 20].fill(b'w');
    write(&t.path("src/file"), &source);
    write(&t.path("dst/file"), &old);
    set_mtime(&t.path("dst/file"), 1);
    let out = reusing_copy(&t, "local", &[])
        .env("SYQ_TEST_STAGING_LIMIT", "0")
        .env("SYQ_DEBUG", "1")
        .run()
        .unwrap();
    assert_output_ok(&out);
    assert!(
        stderr_of(&out).contains("reducing small-file staging"),
        "{}",
        stderr_of(&out)
    );
    assert_eq!(read(&t.path("dst/file")), source);
    assert_eq!(tuning_observed(&out)["streamed_patches"], 1);
    assert!(partial_files(&t.path("dst")).is_empty());
}

#[test]
fn by_default_remote_copies_compare_replaced_files_of_any_size() {
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
        // As rsync does by default, a file whose size changed is compared
        // too, whether or not block reuse was chosen explicitly.
        let observed = tuning_observed(&out);
        assert_eq!(observed["compared_files"], 2, "explicit={explicit}");
        assert_eq!(observed["patched_files"], 2, "explicit={explicit}");
    }
}

#[test]
fn by_default_an_appended_remote_file_reuses_its_old_blocks() {
    // A remote copy compares a file that grew with the one it replaces:
    // the blocks the destination already holds are reused, and only the
    // appended data is sent. So too on the per-file path, which a file too
    // large to compare in groups takes.
    for per_file in [false, true] {
        let t = Tmp::new();
        let rsh = fake_rsh(&t);
        t.expose_remote_syq();
        let old = prng(3 << 20, 885);
        let appended = prng((1 << 20) + 12345, 886);
        let source = [&old[..], &appended[..]].concat();
        write(&t.path("src/file"), &source);
        write(&t.path("dst/file"), &old);
        set_mtime(&t.path("dst/file"), 1);
        let results = t.path("results.jsonl");
        let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
        command
            .args(["cp", "--no-progress", "--srcs-in", &t.s("src")])
            .args(["--to", "fake", "--no-tcp", "--no-bootstrap", "--rsh"])
            .arg(&rsh)
            .args(["--into", &t.s("dst"), "--results"])
            .arg(&results)
            .env("FAKE_REMOTE_HOME", t.path("remote-home"))
            .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
            .env("XDG_CACHE_HOME", t.path("cache"));
        if per_file {
            // The per-file path compares the default 4 MiB blocks; the old
            // file holds whole blocks of 1 MiB.
            command
                .arg("--performance-tuning=comparison-block-size=1M")
                .env("SYQ_TEST_PER_FILE_COMPARISON", "1");
        }
        let out = command.run().unwrap();
        assert_output_ok(&out);
        assert_eq!(read(&t.path("dst/file")), source, "per_file={per_file}");
        let records = fs::read_to_string(&results).unwrap();
        let summary: serde_json::Value =
            serde_json::from_str(records.lines().last().unwrap()).unwrap();
        assert_eq!(
            summary["bytes_transferred"],
            appended.len() as u64,
            "per_file={per_file}: {summary}"
        );
        assert_eq!(
            summary["bytes_unchanged"],
            old.len() as u64,
            "per_file={per_file}: {summary}"
        );
    }
}

#[cfg(debug_assertions)]
#[test]
fn a_patch_whose_payload_fails_its_check_is_copied_whole() {
    // With transfer integrity, the receiver checks the differing blocks a
    // patch carries against the payload hash the source sent. Here one
    // payload check fails, as for data corrupted in transit: the patch is
    // refused and the file is copied whole instead. With --inplace, nothing
    // of the patch is written into the file, which is then updated in place
    // on the per-file path and keeps its inode.
    for (remote, cloning, inplace) in [
        (false, true, false),
        (false, false, false),
        (true, true, false),
        (false, true, true),
        (true, true, true),
    ] {
        let t = Tmp::new();
        let source = prng(8 << 20, 874);
        let mut old = source.clone();
        old[4 << 20] ^= 1;
        write(&t.path("src/file"), &source);
        write(&t.path("dst/file"), &old);
        set_mtime(&t.path("dst/file"), 1);
        let before = fs::metadata(t.path("dst/file")).unwrap().ino();
        let marker = t.path("corrupted-once");
        let (source_dir, destination_dir) = (t.s("src/"), t.s("dst/"));
        let remote_destination = format!("fake:{destination_dir}");
        let mut args = vec![
            "-a",
            "--no-whole-file",
            "--integrity-checking=transfer=blake3",
        ];
        if inplace {
            args.push("--inplace");
        }
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
        let case = format!("remote={remote} cloning={cloning} inplace={inplace}");
        assert!(marker.exists(), "{case}: the payload check never ran");
        assert_eq!(read(&t.path("dst/file")), source, "{case}");
        if inplace {
            assert_eq!(
                fs::metadata(t.path("dst/file")).unwrap().ino(),
                before,
                "{case}"
            );
        }
        let observed = tuning_observed(&out);
        assert_eq!(observed["compared_files"], 1, "{case}");
        assert_eq!(observed["patched_files"], 0, "{case}");
        assert!(partial_files(&t.path("dst")).is_empty(), "{case}");
    }
}

/// What vouched for each compared file, and for the blocks its stage took
/// from it, as the receiver recorded them (`SYQ_TEST_REUSE_GUARDS`): one
/// line per event, the event and then the file's name.
#[cfg(all(debug_assertions, target_os = "linux"))]
fn reuse_guards(events: &Path) -> Vec<String> {
    fs::read_to_string(events)
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

/// Whether the receiver trusted leases on the test filesystem. It does not
/// on network and overlay filesystems, where a file keeps only its
/// fingerprint to vouch for it, as before leases.
#[cfg(all(debug_assertions, target_os = "linux"))]
fn leases_trusted(events: &[String], case: &str) -> bool {
    let trusted = !events.iter().any(|event| event.starts_with("untrusted "));
    if !trusted {
        eprintln!("note: {case}: the test filesystem's leases are not trusted");
    }
    trusted
}

/// A file the copy replaces that differs from its source in its first
/// `changed` bytes, of `len` bytes in all, at `src/name` and `dst/name`.
/// Returns the source's contents.
#[cfg(all(debug_assertions, target_os = "linux"))]
fn replaced_file(t: &Tmp, name: &str, len: usize, changed: usize, seed: u64) -> Vec<u8> {
    let source = prng(len, seed);
    let mut old = source.clone();
    old[..changed].fill(b'x');
    write(&t.path(&format!("src/{name}")), &source);
    write(&t.path(&format!("dst/{name}")), &old);
    set_mtime(&t.path(&format!("dst/{name}")), 1);
    source
}

/// A copy that reuses blocks, one worker at a time, held once its first
/// group has been compared (`ready`, `continuation`), on a filesystem whose
/// change times are too coarse to show a write, recording what vouched for
/// each file in `events`.
#[cfg(all(debug_assertions, target_os = "linux"))]
fn held_after_comparison(t: &Tmp, route: &str, extra: &[&str]) -> (Command, PathBuf, PathBuf) {
    let mut command = reusing_copy(t, route, extra);
    let (ready, continuation) = (t.path("hashed"), t.path("continue"));
    command
        .env("SYQ_TEST_SMALL_HASHED_READY_FILE", &ready)
        .env("SYQ_TEST_SMALL_HASHED_CONTINUE_FILE", &continuation)
        .env("SYQ_TEST_REUSE_GUARDS", t.path("guards"))
        .env("SYQ_TEST_COARSE_CHANGE_TIMES", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    (command, ready, continuation)
}

#[cfg(all(debug_assertions, target_os = "linux"))]
#[test]
fn a_reused_block_written_after_its_comparison_does_not_reach_the_published_file() {
    // A file the copy replaces is leased before it is compared. A program
    // that then writes a block its patch reuses, keeping the file's length
    // and, where change times are coarse, its fingerprint, breaks the lease
    // and waits only until the receiver lets it go. The patch's stage, which
    // took a copy of the file, is read back, and the published file has the
    // source's bytes. So for a patch sent in a batch and for one streamed;
    // an unchanged file of the same group is kept.
    use std::os::unix::fs::FileExt as _;
    for route in ["local", "push"] {
        for streamed in [false, true] {
            let case = format!("{route} streamed={streamed}");
            let t = Tmp::new();
            // A streamed patch carries more than 16 MiB, and reuses at least
            // half its file, for its stage to take a copy of it.
            let (len, changed, planted_at) = if streamed {
                (48 << 20, 20 << 20, (40 << 20) + 5)
            } else {
                (2 << 20, 1 << 16, (1 << 20) + 5)
            };
            let source = replaced_file(&t, "file", len, changed, 990);
            let same = prng((1 << 20) + 4096, 991);
            if !streamed {
                write(&t.path("src/same"), &same);
                write(&t.path("dst/same"), &same);
                set_mtime(&t.path("dst/same"), 1);
            }
            let (mut command, ready, continuation) = held_after_comparison(&t, route, &[]);
            let mut child = command.start().unwrap();
            wait_for_confinement_marker(&mut child, &ready, "the comparison");
            let started = std::time::Instant::now();
            let writer = OpenOptions::new()
                .write(true)
                .open(t.path("dst/file"))
                .unwrap();
            let waited = started.elapsed();
            writer.write_all_at(b"planted", planted_at).unwrap();
            drop(writer);
            release_confinement_barrier(&continuation);
            let out = child.wait_with_output().unwrap();
            assert_output_ok(&out);
            let events = reuse_guards(&t.path("guards"));
            if !leases_trusted(&events, &case) {
                continue;
            }
            assert!(
                read(&t.path("dst/file")) == source,
                "{case}: the planted bytes reached the published file"
            );
            // Far less than the kernel's break time, 45 s by default.
            assert!(
                waited < std::time::Duration::from_secs(5),
                "{case}: the writer waited {waited:?}"
            );
            eprintln!("{case}: the writer's open waited {waited:?}");
            assert!(events.contains(&"leased file".into()), "{case}: {events:?}");
            assert!(
                events.contains(&"checked file".into()),
                "{case}: {events:?}"
            );
            if !streamed {
                assert!(events.contains(&"leased same".into()), "{case}: {events:?}");
                assert!(read(&t.path("dst/same")) == same, "{case}");
            }
            assert!(partial_files(&t.path("dst")).is_empty(), "{case}");
        }
    }
}

#[cfg(all(debug_assertions, target_os = "linux"))]
#[test]
fn a_store_through_a_mapping_made_before_the_comparison_does_not_reach_the_published_file() {
    // A program that has had the file mapped writable and shared since
    // before the comparison stores into a block the patch reuses. Such a
    // store changes nothing `stat` shows, but the mapping keeps the file's
    // lease from being granted, so the patch's stage is read back, and the
    // published file has the source's bytes.
    use std::os::fd::AsRawFd as _;
    for route in ["local", "push"] {
        let t = Tmp::new();
        let len = 2 << 20;
        let source = replaced_file(&t, "file", len, 1 << 16, 992);
        let mapped = OpenOptions::new()
            .read(true)
            .write(true)
            .open(t.path("dst/file"))
            .unwrap();
        // SAFETY: a fresh shared mapping of the whole file, unmapped below;
        // only this test stores through it.
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                mapped.as_raw_fd(),
                0,
            )
        };
        assert_ne!(mapping, libc::MAP_FAILED);
        drop(mapped);
        let (mut command, ready, continuation) = held_after_comparison(&t, route, &[]);
        let mut child = command.start().unwrap();
        wait_for_confinement_marker(&mut child, &ready, "the comparison");
        let planted_at = (1 << 20) + 5;
        // SAFETY: within the mapping made above.
        unsafe {
            std::ptr::copy_nonoverlapping(
                b"planted".as_ptr(),
                mapping.cast::<u8>().add(planted_at),
                7,
            );
        }
        release_confinement_barrier(&continuation);
        let out = child.wait_with_output().unwrap();
        // SAFETY: the mapping made above.
        assert_eq!(unsafe { libc::munmap(mapping, len) }, 0);
        assert_output_ok(&out);
        let events = reuse_guards(&t.path("guards"));
        if !leases_trusted(&events, route) {
            continue;
        }
        assert!(
            read(&t.path("dst/file")) == source,
            "{route}: the planted bytes reached the published file"
        );
        assert!(
            events.contains(&"refused file".into()),
            "{route}: {events:?}"
        );
        assert!(
            events.contains(&"checked file".into()),
            "{route}: {events:?}"
        );
        assert!(partial_files(&t.path("dst")).is_empty(), "{route}");
    }
}

#[cfg(all(debug_assertions, target_os = "linux"))]
#[test]
fn a_file_whose_lease_is_refused_has_its_stage_read_back() {
    // A receiver may not lease a file another account owns, unless it has
    // CAP_LEASE (here simulated). The blocks the patch's stage takes are
    // read back, so a write after the comparison does not reach the
    // published file; with no lease to break, the writer does not wait.
    use std::os::unix::fs::FileExt as _;
    let t = Tmp::new();
    let source = replaced_file(&t, "file", 2 << 20, 1 << 16, 993);
    let (mut command, ready, continuation) = held_after_comparison(&t, "local", &[]);
    command.env("SYQ_TEST_LEASES", "refuse");
    let mut child = command.start().unwrap();
    wait_for_confinement_marker(&mut child, &ready, "the comparison");
    OpenOptions::new()
        .write(true)
        .open(t.path("dst/file"))
        .unwrap()
        .write_all_at(b"planted", (1 << 20) + 5)
        .unwrap();
    release_confinement_barrier(&continuation);
    let out = child.wait_with_output().unwrap();
    assert_output_ok(&out);
    let events = reuse_guards(&t.path("guards"));
    if !leases_trusted(&events, "refused") {
        return;
    }
    assert!(
        read(&t.path("dst/file")) == source,
        "the planted bytes reached the published file"
    );
    assert_eq!(events, ["refused file", "checked file"]);
    assert!(partial_files(&t.path("dst")).is_empty());
}

#[cfg(all(debug_assertions, target_os = "linux"))]
#[test]
fn where_leases_are_not_trusted_a_files_fingerprint_vouches_for_it_as_before() {
    // On a filesystem whose files can change without an open in this
    // kernel, such as NFS, FUSE or overlayfs (here simulated), no lease is
    // taken, and a stage built from a file that keeps its fingerprint is
    // kept unread.
    for route in ["local", "push"] {
        let t = Tmp::new();
        let source = replaced_file(&t, "file", 2 << 20, 1 << 16, 994);
        let out = reusing_copy(&t, route, &[])
            .env("SYQ_TEST_LEASES", "unsupported")
            .env("SYQ_TEST_REUSE_GUARDS", t.path("guards"))
            .run()
            .unwrap();
        assert_output_ok(&out);
        assert_eq!(
            reuse_guards(&t.path("guards")),
            ["untrusted file", "fingerprint file"],
            "{route}"
        );
        assert!(read(&t.path("dst/file")) == source, "{route}");
    }
}

#[cfg(all(debug_assertions, target_os = "linux"))]
#[test]
fn a_file_its_lease_vouches_for_is_trusted_unread() {
    // With no writer, the lease is intact once the stage holds its copy of
    // the file, which is kept unread; files under 1 MiB take no lease.
    for route in ["local", "push"] {
        let t = Tmp::new();
        let source = replaced_file(&t, "file", 2 << 20, 1 << 16, 995);
        let small = replaced_file(&t, "small", 512 << 10, 4096, 996);
        let out = reusing_copy(&t, route, &[])
            .env("SYQ_TEST_REUSE_GUARDS", t.path("guards"))
            .run()
            .unwrap();
        assert_output_ok(&out);
        let events = reuse_guards(&t.path("guards"));
        if !leases_trusted(&events, route) {
            continue;
        }
        assert_eq!(events, ["leased file", "trusted file"], "{route}");
        assert!(read(&t.path("dst/file")) == source, "{route}");
        assert!(read(&t.path("dst/small")) == small, "{route}");
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

#[cfg(debug_assertions)]
#[test]
fn staging_recovery_preserves_patch_sources() {
    // Patches carry no payload hash of their own: with transfer integrity
    // on, the recovery path must still publish them rather than refuse them.
    for (network, integrity) in [(false, false), (true, false), (false, true), (true, true)] {
        let t = Tmp::new();
        // A comparison group must fit more than two files so the failure
        // leaves two staged patches to write on the network worker threads.
        // Groups carry at most 4 MiB of source, so the files are 1 MiB.
        let source = prng(1 << 20, 8317);
        let mut old = source.clone();
        old[..512 << 10].fill(b'x');
        for index in 0..8 {
            write(&t.path(&format!("src/f{index}")), &source);
            write(&t.path(&format!("dst/f{index}")), &old);
            set_mtime(&t.path(&format!("dst/f{index}")), 1);
        }
        let mut command = compat_command();
        command
            .args([
                "-a",
                "--no-progress",
                "--no-whole-file",
                "--performance-tuning=workers=2,batch-files=8",
                &t.s("src/"),
                &t.s("dst/"),
            ])
            .env("SYQ_TEST_STAGING_LIMIT", "2")
            .env("SYQ_DEBUG", "1");
        if network {
            command.env("SYQ_TEST_NETWORK_FILESYSTEM", "1");
        }
        if integrity {
            command.arg("--integrity-checking=transfer=blake3");
        }
        let out = command.run().unwrap();
        assert_output_ok(&out);
        assert!(
            stderr_of(&out).contains("reducing small-file staging"),
            "{}",
            stderr_of(&out)
        );
        assert_eq!(tuning_observed(&out)["patched_files"], 8);
        for index in 0..8 {
            assert_eq!(read(&t.path(&format!("dst/f{index}"))), source);
        }
        assert!(partial_files(&t.path("dst")).is_empty());
    }
}

/// A file whose block hashes do not fit one response is still compared
/// whole, in windows: in place, with or without `--hash`, and against a
/// protected destination. Under `--hash` a differing one is staged and
/// compared in windows rather than seeded from all its hashes. Debug builds
/// shrink the response to four blocks.
#[cfg(debug_assertions)]
#[test]
fn whole_file_comparisons_of_files_beyond_one_hash_response_use_windows() {
    let block = 64 << 10;
    let size = 10 * block + 17;
    for (options, differs) in [
        (&["--in-place=update"][..], true),
        (&["--hash", "--in-place=update"][..], false),
        (&["--hash", "--in-place=update"][..], true),
        (&["--if-exists=error-if-different"][..], false),
        (&["--hash"][..], true),
    ] {
        let t = Tmp::new();
        let source = prng(size, 912);
        let mut old = source.clone();
        if differs {
            old[7 * block + 5] ^= 0xff;
        }
        write(&t.path("src/file"), &source);
        write(&t.path("dst/file"), &old);
        // Different times, so that a matching size does not settle it.
        set_mtime(&t.path("dst/file"), 1);
        let out = Command::new(env!("CARGO_BIN_EXE_syq"))
            .args(["cp", "--no-progress", "--performance-tuning"])
            .arg("workers=1,comparison-block-size=64K")
            .arg("--transfer-strategy=aligned-block")
            .args(options)
            .arg(t.path("src/file"))
            .arg("--into")
            .arg(t.path("dst"))
            // Compared through the worker, not copied by the receiver.
            .env("SYQ_TEST_COPY_LOCAL_EXDEV", "1")
            .env("SYQ_TEST_COPY_LOCAL_FS", "unsupported")
            .env("SYQ_TEST_PER_FILE_COMPARISON", "1")
            .env("SYQ_TEST_HASH_WINDOW_BLOCKS", "4")
            .env("SYQ_TEST_BASIS_HASH_EVENTS", t.path("hashes"))
            .env("SYQ_DEBUG", "1")
            .run()
            .unwrap();
        assert_output_ok(&out);
        let copied = read(&t.path("dst/file"));
        assert!(
            copied == source,
            "{options:?}: first difference at {:?}",
            copied.iter().zip(&source).position(|(a, b)| a != b),
        );
        let hashes = fs::read_to_string(t.path("hashes")).unwrap();
        let windows: Vec<_> = hashes.lines().collect();
        assert_eq!(
            windows,
            [
                format!("hash 0 {}", 4 * block),
                format!("hash {} {}", 4 * block, 4 * block),
                format!("hash {} {}", 8 * block, 2 * block + 17),
            ],
            "{options:?}"
        );
        if differs {
            // Only the differing block was sent.
            assert_eq!(tuning_observed(&out)["range_requests"], 1, "{options:?}");
        }
        assert!(partial_files(&t.0).is_empty());
    }
}

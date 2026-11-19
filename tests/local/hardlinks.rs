use super::*;

fn identity(path: &Path) -> (u64, u64) {
    let metadata = fs::symlink_metadata(path).unwrap();
    (metadata.dev(), metadata.ino())
}

fn linked_tree(t: &Tmp, bytes: &[u8]) {
    write(&t.path("src/a"), bytes);
    fs::create_dir_all(t.path("src/nested")).unwrap();
    fs::hard_link(t.path("src/a"), t.path("src/nested/b")).unwrap();
    fs::hard_link(t.path("src/a"), t.path("outside")).unwrap();
    write(&t.path("src/independent"), bytes);
}

fn verify(t: &Tmp, bytes: &[u8]) {
    assert_eq!(read(&t.path("dst/a")), bytes);
    assert_eq!(read(&t.path("dst/nested/b")), bytes);
    assert_eq!(
        identity(&t.path("dst/a")),
        identity(&t.path("dst/nested/b"))
    );
    assert_ne!(identity(&t.path("src/a")), identity(&t.path("dst/a")));
    assert_ne!(
        identity(&t.path("dst/a")),
        identity(&t.path("dst/independent"))
    );
    assert!(!t.path("dst/outside").exists());
}

#[test]
fn hardlinks_fresh_rerun_update_and_missing_alias() {
    for extra in [
        vec![],
        vec!["--inplace"],
        vec!["--performance-tuning=copy-path=ranges"],
    ] {
        let t = Tmp::new();
        linked_tree(&t, b"first contents");
        let mut args = vec!["-aH"];
        args.extend(extra);
        let source = t.s("src/");
        let destination = t.s("dst/");
        args.extend([source.as_str(), destination.as_str()]);
        run_ok(&args);
        verify(&t, b"first contents");
        let before = identity(&t.path("dst/a"));
        run_ok(&args);
        verify(&t, b"first contents");
        assert_eq!(before, identity(&t.path("dst/a")));
        fs::remove_file(t.path("dst/nested/b")).unwrap();
        run_ok(&args);
        verify(&t, b"first contents");
        write(&t.path("src/a"), b"longer changed contents");
        run_ok(&args);
        verify(&t, b"longer changed contents");
    }
}

#[test]
fn hardlinks_reconcile_independent_matching_files_and_preserve_defaults() {
    let t = Tmp::new();
    linked_tree(&t, b"contents");
    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    assert_ne!(
        identity(&t.path("dst/a")),
        identity(&t.path("dst/nested/b"))
    );
    run_native_ok(&[
        "cp",
        "--copy-metadata=hardlinks,permissions",
        "--srcs-in",
        &t.s("src"),
        "--into",
        &t.s("dst"),
    ]);
    verify(&t, b"contents");
}

#[test]
fn hardlinks_overwrite_policies_leave_skipped_names_alone() {
    // Rsync 3.2.7 -aH differential fixtures: skipped names do not join a
    // group, even when their bytes match. Either selected name may be missing.
    for policy in ["--ignore-existing", "--existing", "--update"] {
        for name in ["a", "b"] {
            let t = Tmp::new();
            write(&t.path("src/a"), b"source");
            fs::hard_link(t.path("src/a"), t.path("src/b")).unwrap();
            set_mtime(&t.path("src/a"), 1_000_000_000);
            write(&t.path(&format!("dst/{name}")), b"target");
            set_mtime(&t.path(&format!("dst/{name}")), 1_000_000_100);
            run_ok(&["-aH", policy, &t.s("src/"), &t.s("dst/")]);
            let other = if name == "a" { "b" } else { "a" };
            if policy == "--existing" {
                assert_eq!(read(&t.path(&format!("dst/{name}"))), b"source");
                assert!(!t.path(&format!("dst/{other}")).exists());
            } else {
                assert_eq!(read(&t.path(&format!("dst/{name}"))), b"target");
                assert_eq!(read(&t.path(&format!("dst/{other}"))), b"source");
                assert_ne!(identity(&t.path("dst/a")), identity(&t.path("dst/b")));
            }
        }
    }
}

#[test]
fn hardlinks_dry_run_and_multiple_roots() {
    let t = Tmp::new();
    write(&t.path("one/a"), b"data");
    fs::create_dir(t.path("two")).unwrap();
    fs::hard_link(t.path("one/a"), t.path("two/b")).unwrap();
    run_ok(&["-naH", &t.s("one"), &t.s("two"), &t.s("dst/")]);
    assert!(!t.path("dst").exists());
    run_ok(&["-aH", &t.s("one"), &t.s("two"), &t.s("dst/")]);
    assert_eq!(
        identity(&t.path("dst/one/a")),
        identity(&t.path("dst/two/b"))
    );
}

/// A dry run previews a hard-link representative as it does a plain file,
/// and counts each linked name once, as a metadata-only entry.
#[test]
fn hardlinks_dry_run_previews_representative_like_a_file() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"data");
    fs::hard_link(t.path("src/a"), t.path("src/b")).unwrap();
    write(&t.path("src/c"), b"x");
    let preview = |args: &[&str]| {
        let out = syq(args);
        assert!(out.status.success(), "{}", stderr_of(&out));
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    };

    let out = preview(&["-naHv", &t.s("src/"), &t.s("dst/")]);
    assert!(
        out.contains(&format!(
            "create file {} (destination missing)",
            t.s("dst/a")
        )),
        "{out}"
    );
    assert!(
        out.contains("changes: 2 regular files; 1 metadata-only entry\n"),
        "{out}"
    );
    assert!(!t.path("dst").exists());

    fs::create_dir(t.path("dst")).unwrap();
    std::os::unix::fs::symlink("elsewhere", t.path("dst/a")).unwrap();
    let out = preview(&["-naHv", &t.s("src/"), &t.s("dst/")]);
    assert!(
        out.contains(&format!(
            "replace with file {} (destination is symlink)",
            t.s("dst/a")
        )),
        "{out}"
    );
    // The destination folder's own metadata may differ too.
    assert!(out.contains("changes: 2 regular files; "), "{out}");
    assert!(out.contains("; 1 type replacement among them"), "{out}");
}

#[test]
fn hardlinks_reject_nonregular_groups_before_copying() {
    let t = Tmp::new();
    fs::create_dir(t.path("src")).unwrap();
    std::os::unix::fs::symlink("absent", t.path("src/a")).unwrap();
    fs::hard_link(t.path("src/a"), t.path("src/b")).unwrap();
    let output = syq(&["-aH", &t.s("src/"), &t.s("dst/")]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("regular files only"));
    assert!(!t.path("dst/a").exists());
}

#[cfg(debug_assertions)]
#[test]
fn failed_hardlink_representative_never_links_followers_and_rerun_repairs_them() {
    let t = Tmp::new();
    linked_tree(&t, b"payload");
    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    fs::set_permissions(t.path("src/a"), fs::Permissions::from_mode(0o640)).unwrap();
    let output = compat_command()
        .args([
            "-aH",
            "--no-progress",
            &t.s("src/a"),
            &t.s("src/nested/b"),
            &t.s("dst/"),
        ])
        .env("SYQ_TEST_FAIL_SETMETA", "/a")
        .run()
        .unwrap();
    assert!(!output.status.success());
    assert_ne!(
        identity(&t.path("dst/a")),
        identity(&t.path("dst/nested/b"))
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("representative did not complete"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!t.path("dst/b").exists());
    run_ok(&["-aH", &t.s("src/"), &t.s("dst/")]);
    verify(&t, b"payload");
    assert_eq!(fs::metadata(t.path("dst/a")).unwrap().mode() & 0o777, 0o640);
}

#[test]
fn hardlink_mapping_conflicting_metadata_fails_before_payload_copy() {
    for padding in [0, 4500] {
        let t = Tmp::new();
        write(&t.path("src/a"), b"payload");
        fs::hard_link(t.path("src/a"), t.path("src/b")).unwrap();
        let entry = |source: &str, destination: &str, mode: u32| {
            serde_json::json!({"src":{"encoding":"utf-8","value":source},"dst":{"encoding":"utf-8","value":destination},"metadata":{"mode":mode}}).to_string()
        };
        let mut entries = vec![entry("a", "a", 0o600)];
        // Put the conflicting alias in a later planning batch. Local replay
        // can overlap ordinary copies, but must not publish this group early.
        for index in 0..padding {
            entries.push(entry("a", &format!("padding-{index:04}"), 0o600));
        }
        entries.push(entry("b", "b", 0o644));
        let manifest = entries.join("\n");
        let output = syq_cp_in(
            &t.path(""),
            &[
                "--copy-metadata=hardlinks",
                "--mapping",
                "-",
                "-C",
                "src",
                "--into",
                "dst",
            ],
            Some(manifest.as_bytes()),
        );
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("conflicting destination metadata"),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!t.path("dst/a").exists());
        assert!(!t.path("dst/b").exists());
    }
}

#[cfg(debug_assertions)]
#[test]
fn hardlinks_never_use_a_representative_replaced_after_publication() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"source");
    fs::hard_link(t.path("src/a"), t.path("src/b")).unwrap();
    let ready = t.path("ready");
    let continuation = t.path("continue");
    let mut child = compat_command()
        .args([
            "-aH",
            "--no-progress",
            "--performance-tuning=copy-path=ranges,workers=1",
            &t.s("src/a"),
            &t.s("src/b"),
            &t.s("dst/"),
        ])
        .env("SYQ_TEST_FINALIZE_READY_FILE", &ready)
        .env("SYQ_TEST_FINALIZE_CONTINUE_FILE", &continuation)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    wait_for_confinement_marker(&mut child, &ready, "hardlink representative publication");
    fs::rename(t.path("dst/a"), t.path("original-publication")).unwrap();
    write(&t.path("dst/a"), b"racing");
    release_confinement_barrier(&continuation);
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert_eq!(read(&t.path("dst/a")), b"racing");
    assert!(!t.path("dst/b").exists());
    assert!(String::from_utf8_lossy(&output.stderr).contains("representative"));
}

/// Unlike rsync, `--inplace` writes no existing file, so it reaches no
/// other name of one: each existing name is replaced, and a source group's
/// names are linked to the file that replaces its representative.
#[test]
fn hardlinks_inplace_replaces_existing_aliases_name_by_name() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"aaaa");
    fs::hard_link(t.path("src/a"), t.path("src/b")).unwrap();
    write(&t.path("src/c"), b"ccccc");
    write(&t.path("dst/a"), b"stale");
    fs::hard_link(t.path("dst/a"), t.path("dst/c")).unwrap();
    for name in ["src/a", "src/c"] {
        set_mtime(&t.path(name), 1_700_000_000);
    }
    set_mtime(&t.path("dst/a"), 1_600_000_000);
    run_ok(&[
        "-aH",
        "--inplace",
        "--performance-tuning=workers=1",
        &t.s("src/"),
        &t.s("dst/"),
    ]);
    assert_eq!(identity(&t.path("dst/a")), identity(&t.path("dst/b")));
    assert_ne!(identity(&t.path("dst/a")), identity(&t.path("dst/c")));
    assert_eq!(read(&t.path("dst/a")), b"aaaa");
    assert_eq!(read(&t.path("dst/c")), b"ccccc");
}

#[cfg(all(debug_assertions, any(target_os = "linux", target_os = "macos")))]
#[test]
fn hardlink_representatives_keep_the_local_copy_path() {
    let t = Tmp::new();
    let data = prng(4 << 20, 72);
    write(&t.path("src/a"), &data);
    fs::hard_link(t.path("src/a"), t.path("src/b")).unwrap();
    fs::set_permissions(t.path("src/a"), fs::Permissions::from_mode(0o440)).unwrap();
    set_mtime(&t.path("src/a"), 1_600_000_000);
    let output = compat_command()
        .args([
            "-aH",
            "--no-progress",
            "--performance-tuning=batch-bytes=64K",
            &t.s("src/"),
            &t.s("dst/"),
        ])
        .env("SYQ_DEBUG", "1")
        .env("SYQ_TEST_FAIL_READ_RANGE", "1")
        .run()
        .unwrap();
    assert_output_ok(&output);
    assert_eq!(read(&t.path("dst/a")), data);
    assert_eq!(identity(&t.path("dst/a")), identity(&t.path("dst/b")));
    assert_ne!(identity(&t.path("src/a")), identity(&t.path("dst/a")));
    let destination = fs::metadata(t.path("dst/b")).unwrap();
    assert_eq!(destination.mode() & 0o777, 0o440);
    assert_eq!(destination.mtime(), 1_600_000_000);
    assert_eq!(tuning_observed(&output)["local_whole_files"], 1);
    assert_eq!(tuning_observed(&output)["range_requests"], 0);
}

fn hash_manifest(expected: &[Option<(&str, String)>]) -> String {
    expected
        .iter()
        .enumerate()
        .map(|(index, hash)| {
            let name = format!("file-{index}");
            let mut entry = serde_json::json!({
                "src": {"encoding":"utf-8", "value":name},
                "dst": {"encoding":"utf-8", "value":name}, "kind":"file"
            });
            if let Some((algorithm, value)) = hash {
                entry["expected_hash"] = serde_json::json!({"algorithm":algorithm,"value":value});
            }
            entry.to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn hardlink_hash_assertions_accept_omitted_repeated_and_mixed_algorithms() {
    use sha2::Digest as _;
    let bytes = prng(2 * 1024 * 1024 + 53, 318);
    let sha = (
        "sha256",
        sha2::Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
    );
    let blake = ("blake3", blake3::hash(&bytes).to_hex().to_string());
    for hashes in [
        vec![None, Some(sha.clone())],
        vec![Some(sha.clone()), None],
        vec![Some(sha.clone()), Some(sha.clone())],
        vec![None, Some(sha.clone()), Some(blake), Some(sha.clone())],
    ] {
        for extra in [
            &[][..],
            &["--performance-tuning=copy-path=ranges"],
            &["--in-place=new"],
        ] {
            let t = Tmp::new();
            write(&t.path("src/file-0"), &bytes);
            for index in 1..hashes.len() {
                fs::hard_link(t.path("src/file-0"), t.path(&format!("src/file-{index}"))).unwrap();
            }
            let manifest = hash_manifest(&hashes);
            let mut args = vec![
                "--if-exists=update",
                "--copy-metadata=hardlinks",
                "--mapping",
                "-",
                "-C",
                "src",
                "--into",
                "dst",
                "--results",
                "results.ndjson",
            ];
            args.extend_from_slice(extra);
            for phase in 0..4 {
                if phase > 0 {
                    fs::remove_file(t.path("results.ndjson")).unwrap();
                }
                if phase == 2 {
                    fs::remove_file(t.path("dst/file-1")).unwrap();
                } else if phase == 3 {
                    // Same size and mtime must not hide a failed assertion,
                    // including when only a follower supplied the requirement.
                    let metadata = fs::metadata(t.path("dst/file-0")).unwrap();
                    write(&t.path("dst/file-0"), &vec![0; bytes.len()]);
                    fs::File::open(t.path("dst/file-0"))
                        .unwrap()
                        .set_times(fs::FileTimes::new().set_modified(metadata.modified().unwrap()))
                        .unwrap();
                }
                let output = syq_cp_in(&t.path(""), &args, Some(manifest.as_bytes()));
                assert_output_ok(&output);
                for index in 0..hashes.len() {
                    let path = t.path(&format!("dst/file-{index}"));
                    assert_eq!(read(&path), bytes);
                    assert_eq!(identity(&path), identity(&t.path("dst/file-0")));
                }
                if phase == 0 {
                    let records: Vec<serde_json::Value> =
                        fs::read_to_string(t.path("results.ndjson"))
                            .unwrap()
                            .lines()
                            .map(|line| serde_json::from_str(line).unwrap())
                            .collect();
                    for (index, expected) in hashes.iter().enumerate() {
                        let name = format!("file-{index}");
                        let record = records
                            .iter()
                            .find(|r| r["type"] == "operation_result" && r["dst"]["value"] == name)
                            .unwrap();
                        match expected {
                            Some((algorithm, value)) => assert_eq!(
                                record["expected_hash"],
                                serde_json::json!({"algorithm":algorithm,"value":value})
                            ),
                            None => assert!(record.get("expected_hash").is_none()),
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn hardlink_hash_conflicts_and_failed_alias_assertions_do_not_publish_the_group() {
    let correct = blake3::hash(b"source").to_hex().to_string();
    for hashes in [
        vec![
            Some(("blake3", correct.clone())),
            Some(("blake3", "0".repeat(64))),
        ],
        vec![Some(("blake3", correct)), Some(("sha256", "0".repeat(64)))],
        vec![None, Some(("sha256", "0".repeat(64)))],
    ] {
        for existing in [false, true] {
            let t = Tmp::new();
            write(&t.path("src/file-0"), b"source");
            fs::hard_link(t.path("src/file-0"), t.path("src/file-1")).unwrap();
            if existing {
                write(&t.path("dst/file-0"), b"old first");
                write(&t.path("dst/file-1"), b"old second");
            }
            let manifest = hash_manifest(&hashes);
            let output = syq_cp_in(
                &t.path(""),
                &[
                    "--if-exists=update",
                    "--copy-metadata=hardlinks",
                    "--mapping",
                    "-",
                    "-C",
                    "src",
                    "--into",
                    "dst",
                ],
                Some(manifest.as_bytes()),
            );
            assert!(!output.status.success(), "{output:?}");
            assert!(stderr_of(&output).contains("expected"), "{output:?}");
            if existing {
                assert_eq!(read(&t.path("dst/file-0")), b"old first");
                assert_eq!(read(&t.path("dst/file-1")), b"old second");
            } else {
                assert!(!t.path("dst/file-0").exists());
                assert!(!t.path("dst/file-1").exists());
            }
        }
    }
}

#[cfg(debug_assertions)]
#[test]
fn hardlink_mixed_hashes_cross_transports_and_recover_lost_publication_reply() {
    use sha2::Digest as _;
    let data = prng(2 * 1024 * 1024 + 17, 319);
    let sha = sha2::Sha256::digest(&data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let manifest = hash_manifest(&[
        None,
        Some(("sha256", sha)),
        Some(("blake3", blake3::hash(&data).to_hex().to_string())),
    ]);
    for tcp in [false, true] {
        for pull in [false, true] {
            let t = Tmp::new();
            let rsh = fake_rsh(&t);
            write(&t.path("src/file-0"), &data);
            for index in 1..3 {
                fs::hard_link(t.path("src/file-0"), t.path(&format!("src/file-{index}"))).unwrap();
            }
            write(&t.path("mapping.ndjson"), manifest.as_bytes());
            let marker = t.path("drop-finalize-once");
            for _ in 0..2 {
                let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
                command.arg("cp");
                if pull {
                    command.args(["--from", "fake"]);
                }
                command.args([
                    "--if-exists=update",
                    "--copy-metadata=hardlinks",
                    "--mapping",
                    &t.s("mapping.ndjson"),
                    "-C",
                    &t.s("src"),
                    "--into",
                    &t.s("dst"),
                    "--rsh",
                    rsh.to_str().unwrap(),
                    "--syq-path",
                    env!("CARGO_BIN_EXE_syq"),
                    "--tcp-ports",
                    EPHEMERAL_TCP_PORTS,
                    "--performance-tuning=workers=1,copy-path=ranges",
                    "--no-progress",
                ]);
                if !pull {
                    command.args(["--to", "fake"]);
                }
                if !tcp {
                    command.arg("--no-tcp");
                }
                command
                    .env("SYQ_TEST_DROP_AFTER_REQUEST", "finalize")
                    .env("SYQ_TEST_DROP_MARKER", &marker);
                assert_output_ok(&command.run().unwrap());
                assert!(marker.exists(), "publication reply was not dropped");
                for index in 0..3 {
                    let path = t.path(&format!("dst/file-{index}"));
                    assert_eq!(read(&path), data);
                    assert_eq!(identity(&path), identity(&t.path("dst/file-0")));
                }
                assert!(partial_files(&t.0).is_empty());
            }
        }
    }
}

/// `syq rsync -aH OPTIONS src/ dst/` to a local destination, or to the same
/// one through a remote shell, recording what hard-link completion does
/// (`hardlink_events`).
#[cfg(debug_assertions)]
fn copy_recording_hardlinks(t: &Tmp, options: &[&str], remote: bool) -> Command {
    let (src, dst) = (t.s("src/"), t.s("dst/"));
    let mut command = if remote {
        let host_dst = format!("host:{dst}");
        let mut args = vec!["-aH", "--rsync-path", env!("CARGO_BIN_EXE_syq")];
        args.extend(options);
        args.extend([src.as_str(), host_dst.as_str()]);
        remote_syq_command(t, &fake_rsh(t), &args)
    } else {
        let mut command = compat_command();
        command
            .args(["-aH", "--no-progress"])
            .args(options)
            .args([&src, &dst]);
        command
    };
    let _ = fs::remove_file(t.path("hardlink-events"));
    command.env("SYQ_TEST_HARDLINK_EVENTS", t.path("hardlink-events"));
    command
}

/// What the last recorded copy did: how many representatives the planner
/// kept, and gave to a worker to replace, and for each link request in order, how many links
/// it makes and how many earlier requests were still unanswered when it
/// was sent.
#[cfg(debug_assertions)]
fn hardlink_events(t: &Tmp) -> (usize, usize, Vec<(usize, usize)>) {
    let (mut kept, mut replaced, mut requests) = (0, 0, Vec::new());
    for line in fs::read_to_string(t.path("hardlink-events"))
        .unwrap_or_default()
        .lines()
    {
        let mut words = line.split(' ');
        match words.next().unwrap() {
            "kept" => kept += 1,
            "replaced" => replaced += 1,
            // Counted by the tests that expect them.
            "worker" | "copied" | "retried" | "failed" | "check" => {}
            "link" => requests.push((
                words.next().unwrap().parse().unwrap(),
                words.next().unwrap().parse().unwrap(),
            )),
            other => panic!("unexpected event {other}"),
        }
    }
    (kept, replaced, requests)
}

/// The destination identity of every name in a tree of `groups` two-name
/// groups `dNNN/a` and `dNNN/b`, checking that each pair shares one file
/// that is not the source's.
#[cfg(debug_assertions)]
fn linked_pairs(t: &Tmp, groups: usize) -> Vec<(u64, u64)> {
    (0..groups)
        .map(|index| {
            let a = identity(&t.path(&format!("dst/d{index:03}/a")));
            assert_eq!(a, identity(&t.path(&format!("dst/d{index:03}/b"))));
            assert_ne!(a, identity(&t.path(&format!("src/d{index:03}/a"))));
            assert_eq!(
                read(&t.path(&format!("dst/d{index:03}/b"))),
                format!("group {index}").as_bytes()
            );
            a
        })
        .collect()
}

#[cfg(debug_assertions)]
#[test]
fn hardlink_reruns_keep_representatives_in_the_planner_and_send_links_ahead() {
    // 600 two-name groups take three link requests of at most 256 links.
    // The receiver, a process of its own even for a local destination, is
    // sent all three before the first is answered. An unchanged rerun
    // keeps every representative without a worker, and links again what a
    // name lost.
    for remote in [true, false] {
        let t = Tmp::new();
        for index in 0..600 {
            write(
                &t.path(&format!("src/d{index:03}/a")),
                format!("group {index}").as_bytes(),
            );
            fs::hard_link(
                t.path(&format!("src/d{index:03}/a")),
                t.path(&format!("src/d{index:03}/b")),
            )
            .unwrap();
        }
        let expected = vec![(256, 0), (256, 1), (88, 2)];
        assert_output_ok(&copy_recording_hardlinks(&t, &[], remote).run().unwrap());
        assert_eq!(
            hardlink_events(&t),
            (0, 0, expected.clone()),
            "remote={remote}"
        );
        let first = linked_pairs(&t, 600);

        assert_output_ok(&copy_recording_hardlinks(&t, &[], remote).run().unwrap());
        assert_eq!(
            hardlink_events(&t),
            (600, 0, expected.clone()),
            "remote={remote}"
        );
        assert_eq!(linked_pairs(&t, 600), first);

        // A name that lost its link, and a representative whose mode
        // differs, are repaired around the kept file.
        fs::remove_file(t.path("dst/d007/b")).unwrap();
        write(&t.path("dst/d300/b.new"), b"group 300");
        fs::rename(t.path("dst/d300/b.new"), t.path("dst/d300/b")).unwrap();
        fs::remove_file(t.path("dst/d500/b")).unwrap();
        fs::set_permissions(t.path("dst/d500/a"), fs::Permissions::from_mode(0o600)).unwrap();
        assert_output_ok(&copy_recording_hardlinks(&t, &[], remote).run().unwrap());
        // The representative whose mode changes is left to a worker.
        assert_eq!(hardlink_events(&t), (599, 0, expected), "remote={remote}");
        assert_eq!(linked_pairs(&t, 600), first);
        assert_eq!(
            fs::metadata(t.path("dst/d500/a")).unwrap().mode() & 0o777,
            fs::metadata(t.path("src/d500/a")).unwrap().mode() & 0o777
        );
    }
}

#[cfg(debug_assertions)]
#[test]
fn a_kept_representative_the_receiver_then_refuses_is_copied_and_linked() {
    // The planner keeps an unchanged representative, whose other name is
    // missing. The receiver refuses to keep it (its owner check, as
    // `SYQ_TEST_REFUSE_REPRESENTATIVE` makes it): a worker copies the file
    // again, the group is linked to the new file, and a name outside the
    // copy keeps the old one.
    let t = Tmp::new();
    write(&t.path("src/a"), b"payload");
    fs::hard_link(t.path("src/a"), t.path("src/b")).unwrap();
    run_ok(&["-aH", &t.s("src/"), &t.s("dst/")]);
    fs::remove_file(t.path("dst/b")).unwrap();
    fs::hard_link(t.path("dst/a"), t.path("outside")).unwrap();
    let before = identity(&t.path("dst/a"));
    let output = copy_recording_hardlinks(&t, &[], false)
        .env("SYQ_TEST_REFUSE_REPRESENTATIVE", "/a")
        .run()
        .unwrap();
    assert_output_ok(&output);
    assert_eq!(hardlink_events(&t), (0, 1, vec![(1, 0)]));
    assert_eq!(identity(&t.path("dst/a")), identity(&t.path("dst/b")));
    assert_ne!(identity(&t.path("dst/a")), before);
    assert_eq!(identity(&t.path("outside")), before);
    assert_eq!(read(&t.path("dst/b")), b"payload");
}

#[cfg(debug_assertions)]
#[test]
fn a_kept_representative_whose_source_changes_is_copied_again() {
    // Both representatives are kept by the planner. While the receiver
    // holds their metadata checks, both sources change: one is a group of
    // two selected names, the other a single selected name whose other
    // name is outside the copy. Before the workers finish, both are found
    // changed and copied again, as a worker retries a file whose source
    // changed, and the group is linked to the new file.
    let t = Tmp::new();
    write(&t.path("src/a"), b"first");
    fs::hard_link(t.path("src/a"), t.path("src/b")).unwrap();
    write(&t.path("src/single"), b"first");
    fs::hard_link(t.path("src/single"), t.path("outside")).unwrap();
    for name in ["src/a", "src/single"] {
        set_mtime(&t.path(name), 1_600_000_000);
    }
    run_ok(&["-aH", &t.s("src/"), &t.s("dst/")]);
    let ready = t.path("ready");
    let continuation = t.path("continue");
    let mut child = copy_recording_hardlinks(&t, &[], false)
        .env("SYQ_TEST_QUICK_META_READY_FILE", &ready)
        .env("SYQ_TEST_QUICK_META_CONTINUE_FILE", &continuation)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    wait_for_confinement_marker(&mut child, &ready, "representative metadata check");
    for name in ["src/a", "src/single"] {
        write(&t.path(name), b"second, longer");
    }
    release_confinement_barrier(&continuation);
    let output = child.wait_with_output().unwrap();
    assert_output_ok(&output);
    let (kept, replaced, requests) = hardlink_events(&t);
    assert_eq!((kept, replaced, requests), (2, 0, vec![(1, 0)]));
    let events = fs::read_to_string(t.path("hardlink-events")).unwrap();
    assert_eq!(events.matches("retried").count(), 2, "{events}");
    assert_eq!(
        stderr_of(&output)
            .matches("changed during transfer, retrying")
            .count(),
        2,
        "{}",
        stderr_of(&output)
    );
    for name in ["dst/a", "dst/b", "dst/single"] {
        assert_eq!(read(&t.path(name)), b"second, longer");
    }
    assert_eq!(identity(&t.path("dst/a")), identity(&t.path("dst/b")));
}

#[cfg(debug_assertions)]
#[test]
fn a_kept_representative_the_existing_policy_skips_is_skipped() {
    // `--existing` holds the copy to the file the scan found. The planner
    // keeps the representative, but before the receiver checks it, another
    // program puts a different file at its name: the representative is
    // skipped, as a worker skips it, and the copy succeeds.
    let t = Tmp::new();
    write(&t.path("src/a"), b"payload");
    fs::hard_link(t.path("src/a"), t.path("outside")).unwrap();
    run_ok(&["-aH", &t.s("src/"), &t.s("dst/")]);
    let ready = t.path("ready");
    let continuation = t.path("continue");
    let mut child = copy_recording_hardlinks(&t, &["--existing"], false)
        .env("SYQ_TEST_QUICK_META_READY_FILE", &ready)
        .env("SYQ_TEST_QUICK_META_CONTINUE_FILE", &continuation)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    wait_for_confinement_marker(&mut child, &ready, "representative metadata check");
    write(&t.path("dst/a.new"), b"another");
    fs::rename(t.path("dst/a.new"), t.path("dst/a")).unwrap();
    release_confinement_barrier(&continuation);
    let output = child.wait_with_output().unwrap();
    assert_output_ok(&output);
    assert!(
        stderr_of(&output).contains("replaced or removed during the copy; skipping it"),
        "{}",
        stderr_of(&output)
    );
    assert!(!fs::read_to_string(t.path("hardlink-events"))
        .unwrap_or_default()
        .contains("kept"));
    assert_eq!(read(&t.path("dst/a")), b"another");
}

/// Start `syq` with `args` in `dir`, held at the receiver's first quick
/// metadata check, and wait until it is held; the returned path releases it
/// (`release_confinement_barrier`).
#[cfg(debug_assertions)]
fn held_at_metadata_check(
    t: &Tmp,
    mut command: Command,
) -> (std::process::Child, std::path::PathBuf) {
    let ready = t.path("ready");
    let continuation = t.path("continue");
    let mut child = command
        .env("SYQ_TEST_QUICK_META_READY_FILE", &ready)
        .env("SYQ_TEST_QUICK_META_CONTINUE_FILE", &continuation)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    wait_for_confinement_marker(&mut child, &ready, "representative metadata check");
    (child, continuation)
}

#[cfg(debug_assertions)]
#[test]
fn a_kept_representative_rewritten_in_its_time_still_fails_its_links() {
    // Same size and time, other contents: no worker would copy it on size
    // and time, so the source's change is found only before linking, which
    // refuses the group's other names, as it did before the planner kept
    // representatives.
    let t = Tmp::new();
    write(&t.path("src/a"), b"first");
    fs::hard_link(t.path("src/a"), t.path("src/b")).unwrap();
    set_mtime(&t.path("src/a"), 1_600_000_000);
    run_ok(&["-aH", &t.s("src/"), &t.s("dst/")]);
    fs::remove_file(t.path("dst/b")).unwrap();
    let (child, continuation) =
        held_at_metadata_check(&t, copy_recording_hardlinks(&t, &[], false));
    write(&t.path("src/a"), b"other");
    set_mtime(&t.path("src/a"), 1_600_000_000);
    release_confinement_barrier(&continuation);
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(
        stderr_of(&output).contains("source hardlink group changed during the copy"),
        "{}",
        stderr_of(&output)
    );
    assert!(!t.path("dst/b").exists());
}

#[cfg(debug_assertions)]
#[test]
fn a_kept_representative_whose_named_source_vanishes_fails_alone() {
    // Two named sources: a kept representative, and a new file. The
    // representative's source is removed while the receiver checks it; it
    // fails, and the new file is still copied.
    let t = Tmp::new();
    write(&t.path("src/a"), b"payload");
    fs::hard_link(t.path("src/a"), t.path("outside")).unwrap();
    run_ok(&["-aH", &t.s("src/a"), &t.s("dst/")]);
    write(&t.path("src/new"), b"new file");
    let mut command = compat_command();
    command.args([
        "-aH",
        "--no-progress",
        &t.s("src/a"),
        &t.s("src/new"),
        &t.s("dst/"),
    ]);
    let (child, continuation) = held_at_metadata_check(&t, command);
    fs::remove_file(t.path("src/a")).unwrap();
    release_confinement_barrier(&continuation);
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(23), "{}", stderr_of(&output));
    assert_eq!(read(&t.path("dst/new")), b"new file");
}

#[cfg(debug_assertions)]
#[test]
fn a_mapped_representative_whose_source_vanishes_is_reported_with_its_source_name() {
    // A mapping copies `alpha` to `stored`. The kept representative's
    // source vanishes during the copy, and its failure names the
    // manifest's source.
    let t = Tmp::new();
    write(&t.path("src/alpha"), b"payload");
    fs::hard_link(t.path("src/alpha"), t.path("outside")).unwrap();
    let manifest = serde_json::json!({
        "src": {"encoding": "utf-8", "value": "alpha"},
        "dst": {"encoding": "utf-8", "value": "stored"},
    })
    .to_string();
    write(&t.path("manifest.jsonl"), manifest.as_bytes());
    let mapped = |results: &str| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
        command.current_dir(t.path("")).args([
            "cp",
            "--no-progress",
            "--copy-metadata=hardlinks",
            "--mapping",
            "manifest.jsonl",
            "-C",
            "src",
            "--into",
            "dst",
            "--results",
            results,
        ]);
        command
    };
    assert_output_ok(&mapped("first.ndjson").run().unwrap());
    assert_eq!(read(&t.path("dst/stored")), b"payload");
    let (child, continuation) = held_at_metadata_check(&t, mapped("results.ndjson"));
    fs::remove_file(t.path("src/alpha")).unwrap();
    release_confinement_barrier(&continuation);
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(23), "{}", stderr_of(&output));
    let failed: Vec<serde_json::Value> = fs::read_to_string(t.path("results.ndjson"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .filter(|record| record["type"] == "operation_result" && record["disposition"] == "failed")
        .collect();
    assert_eq!(failed.len(), 1, "{failed:?}");
    assert_eq!(failed[0]["dst"]["value"], "stored");
    assert_eq!(failed[0]["src"]["value"], "alpha");
}

/// Start `command`, held before the planner rechecks the representatives
/// it kept, and wait until it is held.
#[cfg(debug_assertions)]
fn held_at_recheck(t: &Tmp, mut command: Command) -> (std::process::Child, std::path::PathBuf) {
    let ready = t.path("recheck-ready");
    let continuation = t.path("recheck-continue");
    let mut child = command
        .env("SYQ_TEST_HARDLINK_RECHECK_READY_FILE", &ready)
        .env("SYQ_TEST_HARDLINK_RECHECK_CONTINUE_FILE", &continuation)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    wait_for_confinement_marker(&mut child, &ready, "representative recheck");
    (child, continuation)
}

#[cfg(debug_assertions)]
#[test]
fn a_kept_representative_rewritten_within_its_second_is_copied_whole() {
    // The source's contents change and its time moves by a millisecond,
    // within the same second, before the planner rechecks it. The change
    // is seen, and the file is copied whole rather than matched on size
    // and time again, so the name the group gains gets the new contents.
    let t = Tmp::new();
    write(&t.path("src/a"), b"first");
    fs::hard_link(t.path("src/a"), t.path("src/b")).unwrap();
    set_mtime(&t.path("src/a"), 1_600_000_000);
    run_ok(&["-aH", &t.s("src/"), &t.s("dst/")]);
    fs::remove_file(t.path("dst/b")).unwrap();
    let (child, continuation) = held_at_recheck(&t, copy_recording_hardlinks(&t, &[], false));
    write(&t.path("src/a"), b"other");
    let file = fs::File::options()
        .write(true)
        .open(t.path("src/a"))
        .unwrap();
    file.set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_millis(1_600_000_000_001))
        .unwrap();
    drop(file);
    release_confinement_barrier(&continuation);
    let output = child.wait_with_output().unwrap();
    assert_output_ok(&output);
    let events = fs::read_to_string(t.path("hardlink-events")).unwrap();
    assert!(events.contains("copied"), "{events}");
    assert_eq!(read(&t.path("dst/a")), b"other");
    assert_eq!(read(&t.path("dst/b")), b"other");
    assert_eq!(identity(&t.path("dst/a")), identity(&t.path("dst/b")));
}

#[cfg(debug_assertions)]
#[test]
fn a_changed_kept_representative_whose_destination_went_is_not_created_under_existing() {
    // `--existing` creates no file. After the receiver accepted the
    // representative, its source grows and its destination is removed. A
    // copy would be published at the name whatever it holds, so the
    // representative is not copied again: it fails, as a worker that had
    // kept it fails it, and the name stays absent.
    let t = Tmp::new();
    write(&t.path("src/a"), b"payload");
    fs::hard_link(t.path("src/a"), t.path("outside")).unwrap();
    run_ok(&["-aH", &t.s("src/"), &t.s("dst/")]);
    let (child, continuation) =
        held_at_recheck(&t, copy_recording_hardlinks(&t, &["--existing"], false));
    write(&t.path("src/a"), b"a longer payload");
    fs::remove_file(t.path("dst/a")).unwrap();
    release_confinement_barrier(&continuation);
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(23), "{}", stderr_of(&output));
    assert!(
        stderr_of(&output).contains("source changed during transfer"),
        "{}",
        stderr_of(&output)
    );
    assert!(!t.path("dst/a").exists());
}

#[cfg(debug_assertions)]
#[test]
fn a_kept_representative_on_a_full_destination_is_reported() {
    // The destination is full when the receiver checks the representative
    // the planner kept: the copy ends, and the representative is reported
    // with the capacity error, as a worker reported it.
    let t = Tmp::new();
    write(&t.path("src/a"), b"payload");
    fs::hard_link(t.path("src/a"), t.path("outside")).unwrap();
    let copy = |results: &str| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
        command.args([
            "cp",
            "--no-progress",
            "--copy-metadata=hardlinks",
            "--results",
            &t.s(results),
            "--srcs-in",
            &t.s("src"),
            "--into",
            &t.s("dst"),
        ]);
        command
    };
    assert_output_ok(&copy("first.ndjson").run().unwrap());
    let output = copy("results.ndjson")
        .env("SYQ_TEST_FAIL_APPLY_ENOSPC", "/a")
        .run()
        .unwrap();
    assert!(!output.status.success(), "{}", stderr_of(&output));
    let records: Vec<serde_json::Value> = fs::read_to_string(t.path("results.ndjson"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(
        records
            .iter()
            .any(|record| record["type"] == "operation_result"
                && record["action"] == "transfer_file"
                && record["disposition"] == "failed"
                && record["dst"]["value"] == "a"
                && record["os_kind"] == "no_space"),
        "{records:?}"
    );
}

#[cfg(debug_assertions)]
#[test]
fn a_kept_representative_rewritten_within_its_second_is_updated_in_place() {
    // As above, under `--in-place=update`, with a destination the receiver
    // may write in place (one name, owned by the receiving account): the
    // new contents are written into it, rather than replacing it.
    let t = Tmp::new();
    write(&t.path("src/a"), b"first");
    fs::hard_link(t.path("src/a"), t.path("src/b")).unwrap();
    set_mtime(&t.path("src/a"), 1_600_000_000);
    let copy = || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
        command.args([
            "cp",
            "--no-progress",
            "--copy-metadata=mtime,hardlinks",
            "--in-place=update",
            "--srcs-in",
            &t.s("src"),
            "--into",
            &t.s("dst"),
        ]);
        command
    };
    assert_output_ok(&copy().run().unwrap());
    fs::remove_file(t.path("dst/b")).unwrap();
    let before = identity(&t.path("dst/a"));
    let (child, continuation) = held_at_recheck(&t, copy());
    write(&t.path("src/a"), b"other");
    let file = fs::File::options()
        .write(true)
        .open(t.path("src/a"))
        .unwrap();
    file.set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_millis(1_600_000_000_001))
        .unwrap();
    drop(file);
    release_confinement_barrier(&continuation);
    let output = child.wait_with_output().unwrap();
    assert_output_ok(&output);
    assert_eq!(identity(&t.path("dst/a")), before);
    assert_eq!(identity(&t.path("dst/b")), before);
    assert_eq!(read(&t.path("dst/a")), b"other");
}

#[cfg(debug_assertions)]
#[test]
fn every_kept_representative_in_a_batch_that_fills_the_destination_is_reported() {
    // In one batch, one representative's check fails and another's finds
    // the destination full: the copy ends, and both are reported.
    let t = Tmp::new();
    for name in ["a-meta", "z-full"] {
        write(&t.path(&format!("src/{name}")), b"payload");
        fs::hard_link(
            t.path(&format!("src/{name}")),
            t.path(&format!("outside-{name}")),
        )
        .unwrap();
    }
    let copy = |results: &str| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
        command.args([
            "cp",
            "--no-progress",
            "--copy-metadata=hardlinks",
            "--results",
            &t.s(results),
            "--srcs-in",
            &t.s("src"),
            "--into",
            &t.s("dst"),
        ]);
        command
    };
    assert_output_ok(&copy("first.ndjson").run().unwrap());
    let output = copy("results.ndjson")
        .env("SYQ_TEST_FAIL_SETMETA", "/a-meta")
        .env("SYQ_TEST_FAIL_APPLY_ENOSPC", "/z-full")
        .run()
        .unwrap();
    assert!(!output.status.success(), "{}", stderr_of(&output));
    let failed: Vec<String> = fs::read_to_string(t.path("results.ndjson"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .filter(|record| record["type"] == "operation_result" && record["disposition"] == "failed")
        .map(|record| record["dst"]["value"].as_str().unwrap().to_owned())
        .collect();
    assert!(failed.contains(&"a-meta".to_owned()), "{failed:?}");
    assert!(failed.contains(&"z-full".to_owned()), "{failed:?}");
}

#[cfg(debug_assertions)]
#[test]
fn a_kept_representative_that_failed_is_reported_when_a_later_batch_fills_the_destination() {
    // Two named sources go in successive batches: the first one's check
    // fails, and the second one's finds the destination full. The copy
    // ends, and both are reported.
    let t = Tmp::new();
    for name in ["a-meta", "z-full"] {
        write(&t.path(&format!("src/{name}")), b"payload");
        fs::hard_link(
            t.path(&format!("src/{name}")),
            t.path(&format!("outside-{name}")),
        )
        .unwrap();
    }
    let copy = |results: &str| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
        command.args([
            "cp",
            "--no-progress",
            "--performance-tuning=workers=1",
            "--copy-metadata=mtime,hardlinks",
            "--results",
            &t.s(results),
            &t.s("src/a-meta"),
            &t.s("src/z-full"),
            "--into",
            &t.s("dst"),
        ]);
        command
    };
    assert_output_ok(&copy("first.ndjson").run().unwrap());
    let output = copy("results.ndjson")
        .env("SYQ_TEST_FAIL_SETMETA", "/a-meta")
        .env("SYQ_TEST_FAIL_APPLY_ENOSPC", "/z-full")
        .run()
        .unwrap();
    assert!(!output.status.success(), "{}", stderr_of(&output));
    let failed: Vec<String> = fs::read_to_string(t.path("results.ndjson"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .filter(|record| record["type"] == "operation_result" && record["disposition"] == "failed")
        .map(|record| record["dst"]["value"].as_str().unwrap().to_owned())
        .collect();
    assert!(failed.contains(&"a-meta".to_owned()), "{failed:?}");
    assert!(failed.contains(&"z-full".to_owned()), "{failed:?}");
}

#[test]
fn a_mapping_with_conflicting_metadata_leaves_an_existing_representative_alone() {
    // The destination already holds the representative, with matching
    // contents and time. A later alias asks for other metadata, so the copy
    // is refused, and refused before it changed anything: the existing
    // file keeps its mode, wherever the conflicting alias comes.
    for padding in [0, 4500] {
        let t = Tmp::new();
        write(&t.path("src/a"), b"payload");
        fs::hard_link(t.path("src/a"), t.path("src/b")).unwrap();
        set_mtime(&t.path("src/a"), 1_600_000_000);
        write(&t.path("dst/a"), b"payload");
        set_mtime(&t.path("dst/a"), 1_600_000_000);
        fs::set_permissions(t.path("dst/a"), fs::Permissions::from_mode(0o640)).unwrap();
        let entry = |source: &str, destination: &str, mode: u32| {
            serde_json::json!({"src":{"encoding":"utf-8","value":source},"dst":{"encoding":"utf-8","value":destination},"metadata":{"mode":mode}}).to_string()
        };
        let mut entries = vec![entry("a", "a", 0o600)];
        for index in 0..padding {
            entries.push(entry("a", &format!("padding-{index:04}"), 0o600));
        }
        entries.push(entry("b", "b", 0o644));
        let manifest = entries.join("\n");
        let output = syq_cp_in(
            &t.path(""),
            &[
                "--copy-metadata=mtime,hardlinks",
                "--if-exists=update",
                "--mapping",
                "-",
                "-C",
                "src",
                "--into",
                "dst",
            ],
            Some(manifest.as_bytes()),
        );
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("conflicting destination metadata"),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            fs::metadata(t.path("dst/a")).unwrap().mode() & 0o777,
            0o640,
            "padding {padding}"
        );
        assert!(!t.path("dst/b").exists());
    }
}

#[cfg(debug_assertions)]
#[test]
fn a_source_whose_mode_changes_between_its_names_leaves_the_existing_file_alone() {
    // The scan sees the source's first name with one mode and, once the
    // mode changes, its second name with another: the group's metadata
    // conflicts and the copy is refused, before any name of the group is
    // changed. The existing destination file keeps its mode, whether it
    // needed a change (0640 here) or already matched the first name.
    for existing in [0o640, 0o600] {
        let t = Tmp::new();
        write(&t.path("src/a"), b"payload");
        fs::create_dir_all(t.path("src/later/nested")).unwrap();
        fs::hard_link(t.path("src/a"), t.path("src/later/nested/b")).unwrap();
        fs::set_permissions(t.path("src/a"), fs::Permissions::from_mode(0o600)).unwrap();
        set_mtime(&t.path("src/a"), 1_600_000_000);
        write(&t.path("dst/a"), b"payload");
        set_mtime(&t.path("dst/a"), 1_600_000_000);
        fs::set_permissions(t.path("dst/a"), fs::Permissions::from_mode(existing)).unwrap();
        let ready = t.path("ready");
        let continuation = t.path("continue");
        let mut child = compat_command()
            .args(["-aH", "--no-progress", &t.s("src/"), &t.s("dst/")])
            .env("SYQ_TEST_HOLD_SOURCE_SCAN_DIRECTORY", "later")
            .env("SYQ_TEST_SOURCE_SCAN_DIRECTORY_READY_FILE", &ready)
            .env(
                "SYQ_TEST_SOURCE_SCAN_DIRECTORY_CONTINUE_FILE",
                &continuation,
            )
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        wait_for_confinement_marker(&mut child, &ready, "source scan of later");
        fs::set_permissions(t.path("src/a"), fs::Permissions::from_mode(0o660)).unwrap();
        release_confinement_barrier(&continuation);
        let output = child.wait_with_output().unwrap();
        assert!(!output.status.success(), "{}", stderr_of(&output));
        assert!(
            stderr_of(&output).contains("conflicting destination metadata"),
            "{}",
            stderr_of(&output)
        );
        assert_eq!(
            fs::metadata(t.path("dst/a")).unwrap().mode() & 0o777,
            existing,
            "{existing:o}"
        );
        assert!(!t.path("dst/later/nested/b").exists());
    }
}

#[cfg(debug_assertions)]
#[test]
fn kept_representatives_of_separately_named_sources_are_checked_together() {
    // Each named source is planned in a batch of its own; the checks of
    // the representatives the planner keeps wait for none of them, and go
    // together once planning ends.
    let t = Tmp::new();
    for name in ["a", "b", "c"] {
        write(&t.path(&format!("src/{name}")), name.as_bytes());
        fs::hard_link(
            t.path(&format!("src/{name}")),
            t.path(&format!("outside-{name}")),
        )
        .unwrap();
    }
    let copy = || {
        let mut command = compat_command();
        command.args([
            "-aH",
            "--no-progress",
            &t.s("src/a"),
            &t.s("src/b"),
            &t.s("src/c"),
            &t.s("dst/"),
        ]);
        let _ = fs::remove_file(t.path("hardlink-events"));
        command.env("SYQ_TEST_HARDLINK_EVENTS", t.path("hardlink-events"));
        command
    };
    assert_output_ok(&copy().run().unwrap());
    assert_output_ok(&copy().run().unwrap());
    let events = fs::read_to_string(t.path("hardlink-events")).unwrap();
    assert_eq!(
        events
            .lines()
            .filter(|line| line.starts_with("check"))
            .collect::<Vec<_>>(),
        ["check 3"],
        "{events}"
    );
    assert_eq!(events.matches("kept").count(), 3, "{events}");
}

#[cfg(debug_assertions)]
#[test]
fn a_kept_representative_whose_source_vanished_is_not_handed_on() {
    // The source of a kept representative is gone when the planner checks
    // it again. It fails there: given to a worker as the scan found it, a
    // file that then took its name with the same size and time would be
    // kept.
    let t = Tmp::new();
    write(&t.path("src/a"), b"first");
    fs::hard_link(t.path("src/a"), t.path("outside")).unwrap();
    run_ok(&["-aH", &t.s("src/"), &t.s("dst/")]);
    let (child, continuation) = held_at_recheck(&t, copy_recording_hardlinks(&t, &[], false));
    fs::rename(t.path("src/a"), t.path("moved")).unwrap();
    release_confinement_barrier(&continuation);
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(23), "{}", stderr_of(&output));
    assert!(
        stderr_of(&output).contains("source changed during transfer (or vanished)"),
        "{}",
        stderr_of(&output)
    );
    let events = fs::read_to_string(t.path("hardlink-events")).unwrap();
    assert!(
        events.contains("kept") && events.contains("failed"),
        "{events}"
    );
    assert!(!events.contains("worker"), "{events}");
    assert_eq!(read(&t.path("dst/a")), b"first");
}

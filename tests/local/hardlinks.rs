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
        "--preserve=hardlinks,permissions",
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
    let t = Tmp::new();
    write(&t.path("src/a"), b"payload");
    fs::hard_link(t.path("src/a"), t.path("src/b")).unwrap();
    let manifest = [
        serde_json::json!({"src":{"encoding":"utf-8","value":"a"},"dst":{"encoding":"utf-8","value":"a"},"metadata":{"mode":384}}),
        serde_json::json!({"src":{"encoding":"utf-8","value":"b"},"dst":{"encoding":"utf-8","value":"b"},"metadata":{"mode":420}}),
    ].map(|v| v.to_string()).join("\n");
    let output = syq_cp_in(
        &t.path(""),
        &[
            "--preserve=hardlinks",
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

#[test]
fn hardlinks_inplace_keeps_existing_alias_write_semantics() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"aaaa");
    fs::hard_link(t.path("src/a"), t.path("src/b")).unwrap();
    write(&t.path("src/c"), b"ccccc");
    write(&t.path("dst/a"), b"stale");
    fs::hard_link(t.path("dst/a"), t.path("dst/c")).unwrap();
    run_ok(&[
        "-aH",
        "--inplace",
        "--performance-tuning=workers=1",
        &t.s("src/"),
        &t.s("dst/"),
    ]);
    assert_eq!(identity(&t.path("dst/a")), identity(&t.path("dst/b")));
    assert_eq!(identity(&t.path("dst/a")), identity(&t.path("dst/c")));
    let bytes = read(&t.path("dst/a"));
    assert!(bytes == b"aaaa" || bytes == b"ccccc");
    assert_eq!(bytes, read(&t.path("dst/c")));
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
            &["--inplace"],
        ] {
            let t = Tmp::new();
            write(&t.path("src/file-0"), &bytes);
            for index in 1..hashes.len() {
                fs::hard_link(t.path("src/file-0"), t.path(&format!("src/file-{index}"))).unwrap();
            }
            let manifest = hash_manifest(&hashes);
            let mut args = vec![
                "--preserve=hardlinks",
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
                    "--preserve=hardlinks",
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
                    "--preserve=hardlinks",
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

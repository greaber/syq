use super::*;

#[test]
fn remembered_path_count_seeds_auto_tuning_but_fixed_count_does_not_rewrite_it() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    let cache = t.path("tuning.json");
    write(
        &cache,
        serde_json::to_string_pretty(&serde_json::json!({
            "paths": { "local>fake|ssh": 1 }
        }))
        .unwrap()
        .as_bytes(),
    );
    let run = |destination: &str, fixed: Option<usize>, limited: bool| {
        let mut command = compat_command();
        command
            .arg("-e")
            .arg(&rsh)
            .arg("--rsync-path")
            .arg(env!("CARGO_BIN_EXE_syq"))
            .args(["--syq-no-tcp", "--stats", "-avv"]);
        if limited {
            command.arg("--resource-limits=bandwidth=1M");
        }
        if let Some(fixed) = fixed {
            command.args(["--performance-tuning", &format!("workers={fixed}")]);
        }
        command
            .arg(t.s("src"))
            .arg(format!("fake:{}", t.s(destination)))
            .arg("--no-progress")
            .env("FAKE_REMOTE_HOME", t.path("remote-home"))
            .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
            .env("FAKE_RSH_LOG", t.path("rsh.log"))
            .env("SYQ_TUNING_CACHE", &cache)
            .run()
            .unwrap()
    };
    write(&t.path("src"), b"remembered start");

    let automatic = run("auto", None, false);
    assert_output_ok(&automatic);
    assert!(
        String::from_utf8_lossy(&automatic.stderr)
            .contains("starting with 1 connections remembered for this path"),
        "{}",
        String::from_utf8_lossy(&automatic.stderr)
    );
    assert!(
        String::from_utf8_lossy(&automatic.stdout)
            .contains("connections: auto: settled at 1 (path 1, peak 1)"),
        "{}",
        String::from_utf8_lossy(&automatic.stdout)
    );

    let limited = run("limited", None, true);
    assert_output_ok(&limited);
    assert!(
        String::from_utf8_lossy(&limited.stderr)
            .contains("starting with 1 connections remembered for this path"),
        "{}",
        String::from_utf8_lossy(&limited.stderr)
    );
    assert_eq!(read(&t.path("limited")), read(&t.path("src")));

    let fixed = run("fixed", Some(3), true);
    assert_output_ok(&fixed);
    let cached: serde_json::Value = serde_json::from_slice(&read(&cache)).unwrap();
    assert_eq!(cached["paths"]["local>fake|ssh"], 1);
}

#[cfg(debug_assertions)]
#[test]
fn resume_from_partial() {
    let t = Tmp::new();
    let data = prng(6 * 1024 * 1024 + 123, 42);
    write(&t.path("src/big.bin"), &data);
    set_mtime(&t.path("src/big.bin"), 1_600_000_000);
    fs::create_dir_all(t.path("dst")).unwrap();
    let src = t.s("src/big.bin");
    let dst = t.s("dst/");
    let args = [
        "-a",
        "--block-size",
        "1M",
        "--resource-limits",
        "bandwidth=1G",
        &src,
        &dst,
    ];
    // Fake an interrupted transfer: first half present, rest preallocated.
    let partial = interrupted_partial(&args, &t.path("dst"));
    {
        let f = File::create(&partial).unwrap();
        (&f).write_all(&data[..data.len() / 2]).unwrap();
        f.set_len(data.len() as u64).unwrap();
    }
    let out = run_ok(&args);
    assert!(read(&t.path("dst/big.bin")) == data);
    assert!(
        partial.exists(),
        "the candidate remains available to other copies"
    );
    assert_same_tree(&t.path("src/big.bin"), &t.path("dst/big.bin"));
    // Roughly half should have been reused.
    assert!(out.contains("unchanged"), "{out}");
}

#[cfg(debug_assertions)]
#[test]
fn checksum_toggle_accepts_prior_partial_candidates() {
    let t = Tmp::new();
    let data = prng(6 * 1024 * 1024, 43);
    write(&t.path("src"), &data);
    set_mtime(&t.path("src"), 1_600_000_000);
    let src = t.s("src");
    let dst = t.s("dst");
    let initial = [
        "-a",
        "--block-size",
        "1M",
        "--resource-limits",
        "bandwidth=1G",
        &src,
        &dst,
    ];
    let partial = interrupted_partial(&initial, &t.0);

    run_ok(&[
        "-ac",
        "--block-size",
        "1M",
        "--resource-limits",
        "bandwidth=1G",
        &src,
        &dst,
    ]);

    assert_eq!(read(&t.path("dst")), data);
    assert!(
        partial.exists(),
        "changing -c must leave another invocation's partial alone"
    );
    assert_eq!(partial_files(&t.0), vec![partial]);
}

#[test]
fn hash_policy_inplace_mismatch_reports_changed_contents() {
    let t = Tmp::new();
    let contents = prng(5 * 1024 * 1024, 991);
    write(&t.path("src/source"), &contents);
    write(&t.path("destination"), &vec![b'o'; contents.len()]);
    let inode = fs::metadata(t.path("destination")).unwrap().ino();
    let output = native_syq(&[
        "cp",
        "--inplace",
        "--mapping",
        &super::hashing::expected_mapping(
            &t,
            "source",
            "destination",
            Some("md5:00000000000000000000000000000000"),
        ),
        "-C",
        &t.s("src"),
        "--into",
        &t.s(""),
    ]);
    assert_eq!(output.status.code(), Some(23), "{}", stderr_of(&output));
    assert_eq!(read(&t.path("destination")), contents);
    assert_eq!(fs::metadata(t.path("destination")).unwrap().ino(), inode);
    assert!(partial_files(&t.0).is_empty());
}

#[cfg(debug_assertions)]
#[test]
fn hash_policy_expected_hash_covers_resumed_bytes_after_algorithm_change() {
    let t = Tmp::new();
    let contents = prng(9 * 1024 * 1024 + 123, 993);
    write(&t.path("src/source"), &contents);
    let partial = interrupted_partial(
        &[
            "-a",
            "--block-size",
            "4M",
            "--resource-limits",
            "bandwidth=1G",
            &t.s("src/source"),
            &t.s("destination"),
        ],
        &t.0,
    );
    let reused = 4 * 1024 * 1024;
    {
        let file = File::create(&partial).unwrap();
        (&file).write_all(&contents[..reused]).unwrap();
        file.set_len(contents.len() as u64).unwrap();
    }
    let expected = format!(
        "sha256:{}",
        Sha256::digest(&contents)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    run_native_ok(&[
        "cp",
        "--mapping",
        &super::hashing::expected_mapping(&t, "source", "destination", Some(&expected)),
        "-C",
        &t.s("src"),
        "--into",
        &t.s(""),
        "--integrity-checking",
        "compare=xxh3-128",
        "--resource-limits",
        "bandwidth=1G",
        "--results",
        &t.s("results.ndjson"),
    ]);
    assert_eq!(read(&t.path("destination")), contents);
    assert!(
        partial.exists(),
        "another invocation's partial remains untouched"
    );
    let records = fs::read_to_string(t.path("results.ndjson")).unwrap();
    let summary: serde_json::Value = serde_json::from_str(records.lines().last().unwrap()).unwrap();
    assert!(
        summary["bytes_unchanged"].as_u64().unwrap() >= reused as u64,
        "{summary}"
    );
}

#[test]
fn copy_paths_inplace_preserve_hardlinks() {
    for engine in ["auto", "ranges"] {
        let t = Tmp::new();
        write(&t.path("source"), &prng(4194, 351));
        write(&t.path("destination"), b"old destination");
        fs::hard_link(t.path("destination"), t.path("alias")).unwrap();
        let inode = fs::metadata(t.path("destination")).unwrap().ino();
        let out = Command::new(env!("CARGO_BIN_EXE_syq"))
            .args([
                "cp",
                &t.s("source"),
                "--as",
                &t.s("destination"),
                "--inplace",
                "--no-progress",
                "--performance-tuning",
                "workers=2",
                &format!("--performance-tuning=copy-path={engine}"),
            ])
            .run()
            .unwrap();
        assert_output_ok(&out);
        assert_eq!(fs::metadata(t.path("destination")).unwrap().ino(), inode);
        assert_eq!(read(&t.path("alias")), read(&t.path("source")));
    }
}

#[cfg(debug_assertions)]
#[test]
fn streaming_and_default_copies_share_resume_partials() {
    for (before, after) in [("ranges", "streaming"), ("streaming", "auto")] {
        let t = Tmp::new();
        let data = prng(6 << 20, 945);
        write(&t.path("source"), &data);
        set_mtime(&t.path("source"), 1_600_000_000);
        let (src, dst) = (t.s("source"), t.s("destination"));
        let partial = interrupted_partial(
            &[
                "-a",
                "--block-size=1M",
                "--resource-limits=bandwidth=1G",
                &format!("--performance-tuning=copy-path={before}"),
                &src,
                &dst,
            ],
            &t.0,
        );
        let file = File::create(&partial).unwrap();
        (&file).write_all(&data[..3 << 20]).unwrap();
        file.set_len(data.len() as u64).unwrap();
        drop(file);
        let out = run_ok(&[
            "-a",
            "--block-size=1M",
            "--resource-limits=bandwidth=1G",
            &format!("--performance-tuning=copy-path={after},request-size=128K,bw-pacing=average"),
            &src,
            &dst,
        ]);
        assert_eq!(read(&t.path("destination")), data);
        assert!(
            partial.exists(),
            "switching mode must not consume a candidate"
        );
        assert!(
            out.contains("1 files (3.00 MiB), 3.00 MiB unchanged"),
            "{out}"
        );
    }
}

#[cfg(debug_assertions)]
#[test]
fn tuning_options_preserve_partial_identity_and_reused_hash_blocks() {
    let t = Tmp::new();
    let data = prng(6 * 1024 * 1024, 905);
    write(&t.path("source"), &data);
    set_mtime(&t.path("source"), 1_600_000_000);
    let src = t.s("source");
    let dst = t.s("destination");
    let initial = [
        "-a",
        "--block-size=1M",
        "--resource-limits=bandwidth=1G",
        &src,
        &dst,
    ];
    let partial = interrupted_partial(&initial, &t.0);
    let f = File::create(&partial).unwrap();
    (&f).write_all(&data[..3 * 1024 * 1024]).unwrap();
    f.set_len(data.len() as u64).unwrap();
    drop(f);
    let out = run_ok(&[
        "-a",
        "--block-size=1M",
        "--resource-limits=bandwidth=1G",
        "--performance-tuning=request-size=128K,pipeline-depth=8,copy-path=ranges,split-min-size=2M,bw-pacing=average",
        &src,
        &dst,
    ]);
    assert_eq!(read(&t.path("destination")), data);
    assert!(partial.exists(), "overrides must not consume a candidate");
    assert!(
        out.contains("1 files (3.00 MiB), 3.00 MiB unchanged"),
        "{out}"
    );
}

#[test]
fn inplace_leaves_no_partial() {
    let t = Tmp::new();
    let data = prng(3 * 1024 * 1024, 5);
    write(&t.path("src/f.bin"), &data);
    set_mtime(&t.path("src/f.bin"), 1_600_000_000);
    run_ok(&["-a", "--inplace", &t.s("src/"), &t.s("dst/")]);
    assert!(read(&t.path("dst/f.bin")) == data);
    assert!(partial_files(&t.path("dst")).is_empty());
    // Update in place when the destination differs.
    let data2 = prng(3 * 1024 * 1024 + 10, 6);
    write(&t.path("src/f.bin"), &data2);
    set_mtime(&t.path("src/f.bin"), 1_600_000_001);
    run_ok(&["-a", "--inplace", &t.s("src/"), &t.s("dst/")]);
    assert!(read(&t.path("dst/f.bin")) == data2);
    assert!(partial_files(&t.path("dst")).is_empty());
    assert_same_tree(&t.path("src"), &t.path("dst"));
}

#[test]
fn inplace_self_copy_preserves_source() {
    let t = Tmp::new();
    write(&t.path("f"), b"hello world data");
    // Copying a file onto itself must never truncate it.
    let out = syq(&["-a", "--inplace", &t.s("f"), &t.s("f")]);
    assert!(out.status.success());
    assert_eq!(read(&t.path("f")), b"hello world data");
}

#[test]
fn inplace_hardlink_alias_preserves_source() {
    let t = Tmp::new();
    write(&t.path("a"), b"aaaa");
    fs::hard_link(t.path("a"), t.path("b")).unwrap();
    let out = syq(&["-a", "--inplace", &t.s("a"), &t.s("b")]);
    assert!(out.status.success());
    assert_eq!(read(&t.path("a")), b"aaaa");
    assert_eq!(read(&t.path("b")), b"aaaa");
}

#[test]
fn small_files_atomic_no_partials() {
    let t = Tmp::new();
    for i in 0..200 {
        write(&t.path(&format!("sm/f{i}")), format!("data-{i}").as_bytes());
    }
    run_ok(&[
        "-a",
        &format!("{}/", t.s("sm")),
        &format!("{}/", t.s("smd")),
    ]);
    assert!(partial_files(&t.path("smd")).is_empty());
    assert_eq!(read(&t.path("smd/f7")), b"data-7");
}

#[cfg(debug_assertions)]
#[test]
fn small_inplace_files_use_one_batched_worker() {
    let t = Tmp::new();
    for i in 0..3 {
        write(
            &t.path(&format!("src/f{i}")),
            format!("contents-{i}").as_bytes(),
        );
    }
    let events = t.path("worker-events");
    let output = compat_command()
        .args([
            "-a",
            "--inplace",
            "--performance-tuning",
            "workers=32",
            "--no-progress",
            &t.s("src/"),
            &t.s("dst/"),
        ])
        .env("SYQ_TEST_WORKER_EVENTS", &events)
        .run()
        .unwrap();
    assert!(output.status.success(), "{}", stderr_of(&output));
    // Worker events are separate from inherited helper stderr, where debug
    // messages from TCP probes can interleave with coordinator diagnostics.
    assert_eq!(
        fs::read_to_string(events).unwrap(),
        "connected 0 0\nbatch 0 3\n"
    );
    assert_eq!(read(&t.path("dst/f2")), b"contents-2");
    assert!(partial_files(&t.path("dst")).is_empty());
}

#[cfg(debug_assertions)]
#[test]
fn small_file_failure_never_publishes_partial_contents() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"complete contents");
    let out = compat_command()
        .args(["-a", "--no-progress", &t.s("src/"), &t.s("dst/")])
        .env("SYQ_TEST_FAIL_PUT_SMALL_BEFORE_RENAME", "/f")
        .run()
        .unwrap();
    assert_eq!(out.status.code(), Some(23));
    assert!(
        !t.path("dst/f").exists(),
        "the final name must not appear before the atomic rename"
    );
    let partials = partial_files(&t.path("dst"));
    assert_eq!(partials.len(), 1);
    let partial = &partials[0];
    assert_eq!(read(partial), b"complete contents");

    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(read(&t.path("dst/f")), b"complete contents");
    assert!(partial.exists());
}

#[cfg(debug_assertions)]
#[test]
fn hardlinked_partial_does_not_corrupt_external_file() {
    let t = Tmp::new();
    write(&t.path("src"), &vec![9u8; 5 * 1024 * 1024]);
    write(&t.path("external"), b"EXTERNAL-DO-NOT-TOUCH");
    let src = t.s("src");
    let dst = t.s("out");
    let args = ["-a", "--resource-limits", "bandwidth=1G", &src, &dst];
    let partial = interrupted_partial(&args, &t.0);
    fs::remove_file(&partial).unwrap();
    // A partial hardlinked to an external file (as a dedup/backup tool might make).
    fs::hard_link(t.path("external"), partial).unwrap();
    run_ok(&args);
    assert_eq!(read(&t.path("external")), b"EXTERNAL-DO-NOT-TOUCH");
    assert_eq!(read(&t.path("out")).len(), 5 * 1024 * 1024);
    // out and external must be different inodes
    let mo = fs::metadata(t.path("out")).unwrap();
    let me = fs::metadata(t.path("external")).unwrap();
    assert!(!(mo.dev() == me.dev() && mo.ino() == me.ino()));
}

#[cfg(debug_assertions)]
#[test]
fn delete_preserves_partial_candidates() {
    // 1. The file is still in the source (here even up to date): the sidecar
    //    is resume state and stays.
    let t = Tmp::new();
    write(&t.path("src/ok"), &vec![7u8; 8 << 20]);
    fs::create_dir_all(t.path("dst")).unwrap();
    let partial = interrupted_partial(
        &[
            "-a",
            "--resource-limits",
            "bandwidth=1G",
            &t.s("src/"),
            &t.s("dst"),
        ],
        &t.path("dst"),
    );
    assert!(partial.exists());
    fs::copy(t.path("src/ok"), t.path("dst/ok")).unwrap();
    set_mtime(&t.path("src/ok"), 1_600_000_000);
    set_mtime(&t.path("dst/ok"), 1_600_000_000);
    let so = run_ok(&["-a", "--delete", &t.s("src/"), &t.s("dst")]);
    assert!(partial.exists(), "{so}");
    assert!(so.contains("0 deleted"), "{so}");

    // 2. A missing source does not establish that its partial is abandoned.
    let t = Tmp::new();
    write(&t.path("src/gone"), &vec![7u8; 8 << 20]);
    fs::create_dir_all(t.path("dst")).unwrap();
    let partial = interrupted_partial(
        &[
            "-a",
            "--resource-limits",
            "bandwidth=1G",
            &t.s("src/"),
            &t.s("dst"),
        ],
        &t.path("dst"),
    );
    fs::remove_file(t.path("src/gone")).unwrap();
    let so = run_ok(&["-a", "--delete", &t.s("src/"), &t.s("dst")]);
    assert!(partial.exists());
    assert!(so.contains("0 deleted"), "{so}");

    // 3. Failed this run: still in the source, kept.
    let t = Tmp::new();
    write(&t.path("src/bad"), &vec![7u8; 8 << 20]);
    fs::create_dir_all(t.path("dst")).unwrap();
    let partial = interrupted_partial(
        &[
            "-a",
            "--resource-limits",
            "bandwidth=1G",
            &t.s("src/"),
            &t.s("dst"),
        ],
        &t.path("dst"),
    );
    fs::set_permissions(t.path("src/bad"), fs::Permissions::from_mode(0o000)).unwrap();
    let out = syq(&["-a", "--delete", &t.s("src/"), &t.s("dst")]);
    assert_eq!(out.status.code(), Some(23), "{}", stderr_of(&out));
    assert!(partial.exists());

    // 4. Preserve other recognized partials too.
    let t = Tmp::new();
    write(&t.path("src/a"), b"a");
    let other = format!("dst/.gone.syq-tmp.{}", "a".repeat(16));
    write(&t.path(&other), b"unclaimed, whoever wrote it");
    run_ok(&["-a", "--delete", &t.s("src/"), &t.s("dst")]);
    assert!(t.path(&other).exists());
}

#[test]
fn delete_preserves_recognized_partial_files() {
    let t = Tmp::new();
    write(&t.path("src/.notes.syq-tmp.aaaaaaaaaaaaaaaa"), b"mine");
    write(&t.path("src/real"), b"r");
    write(&t.path("dst/.notes.syq-tmp.aaaaaaaaaaaaaaaa"), b"mine");
    write(&t.path("dst/.syq-tmp.notes"), b"odd name, not a sidecar");
    write(&t.path("dst/.gone.syq-tmp.aaaaaaaaaaaaaaaa"), b"leftover");
    for dry_run in [true, false] {
        let out = syq(&[
            if dry_run { "-anv" } else { "-av" },
            "--delete",
            &t.s("src/"),
            &t.s("dst"),
        ]);
        assert_output_ok(&out);
        let diagnostic = stderr_of(&out);
        assert!(
            diagnostic.contains("not deleting .gone.syq-tmp.aaaaaaaaaaaaaaaa:"),
            "{diagnostic}"
        );
        assert!(
            diagnostic.contains("name matches syq's partial-file format"),
            "{diagnostic}"
        );
        assert!(diagnostic.contains("syq clean-partials"), "{diagnostic}");
        // A matching source payload is not an extra kept by the partial rule.
        assert!(
            !diagnostic.contains("not deleting .notes.syq-tmp."),
            "{diagnostic}"
        );
        assert_eq!(t.path("dst/.syq-tmp.notes").exists(), dry_run);
        if !dry_run {
            assert!(
                String::from_utf8_lossy(&out.stdout).contains("1 deleted"),
                "{out:?}"
            );
        }
    }
    // Recognized partials stay; an unrecognized spelling is an ordinary extra.
    assert_eq!(
        listing(&t.path("dst")),
        [
            ".gone.syq-tmp.aaaaaaaaaaaaaaaa",
            ".notes.syq-tmp.aaaaaaaaaaaaaaaa",
            "real"
        ]
    );
}

#[cfg(debug_assertions)]
#[test]
fn delete_keeps_partials_of_filtered_files() {
    // A file this run chose not to send (--max-size here) keeps its partial:
    // it is the resume state of a transfer that hasn't happened yet.
    let t = Tmp::new();
    write(&t.path("src/big"), &vec![7u8; 8 << 20]);
    fs::create_dir_all(t.path("dst")).unwrap();
    let partial = interrupted_partial(
        &[
            "-a",
            "--resource-limits",
            "bandwidth=1G",
            &t.s("src/"),
            &t.s("dst"),
        ],
        &t.path("dst"),
    );
    run_ok(&[
        "-a",
        "--delete",
        "--max-size",
        "10",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert!(partial.exists());
    assert!(!t.path("dst/big").exists());
    // Same for -u.
    let t = Tmp::new();
    write(&t.path("src/f"), &vec![7u8; 8 << 20]);
    fs::create_dir_all(t.path("dst")).unwrap();
    let partial = interrupted_partial(
        &[
            "-a",
            "--resource-limits",
            "bandwidth=1G",
            &t.s("src/"),
            &t.s("dst"),
        ],
        &t.path("dst"),
    );
    write(&t.path("dst/f"), b"newer on dst");
    set_mtime(&t.path("src/f"), 1000);
    set_mtime(&t.path("dst/f"), 2000);
    run_ok(&["-a", "--delete", "-u", &t.s("src/"), &t.s("dst")]);
    assert!(partial.exists());
    assert_eq!(read(&t.path("dst/f")), b"newer on dst");
}

#[test]
fn source_partials_are_copied_and_warned_about() {
    let t = Tmp::new();
    let id = "a".repeat(16);
    let file = format!(".payload.syq-tmp.{id}");
    let dir = format!(".directory.syq-tmp.{id}");
    write(&t.path(&format!("src/{file}")), b"partial payload");
    write(&t.path(&format!("src/{dir}/child")), b"nested payload");
    write(&t.path("src/.ordinary.syq-partial"), b"ordinary payload");

    let output = syq(&["-a", &t.s("src/"), &t.s("dst/")]);
    assert_output_ok(&output);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("warning: source contains 2 recognizable SYQ partial paths"),
        "{stderr}"
    );
    assert!(
        stderr.contains("they are treated as ordinary payload"),
        "{stderr}"
    );
    assert!(
        !stderr.to_ascii_lowercase().contains("copying"),
        "warning must not promise that a dry run, verification, or failed run will copy: {stderr}"
    );
    assert_eq!(read(&t.path(&format!("dst/{file}"))), b"partial payload");
    assert_eq!(
        read(&t.path(&format!("dst/{dir}/child"))),
        b"nested payload"
    );
    assert_eq!(
        read(&t.path("dst/.ordinary.syq-partial")),
        b"ordinary payload"
    );

    let quiet = syq(&["-q", "-v", "-a", &t.s("src/"), &t.s("quiet-dst/")]);
    assert_output_ok(&quiet);
    assert!(
        quiet.stdout.is_empty(),
        "{}",
        String::from_utf8_lossy(&quiet.stdout)
    );
    assert!(
        quiet.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&quiet.stderr)
    );
    assert_eq!(
        read(&t.path(&format!("quiet-dst/{file}"))),
        b"partial payload"
    );

    let dry = syq(&["-n", "-a", &t.s("src/"), &t.s("dry-dst/")]);
    assert_output_ok(&dry);
    let dry_stderr = String::from_utf8_lossy(&dry.stderr);
    assert!(
        dry_stderr.contains("treated as ordinary payload"),
        "{dry_stderr}"
    );
    assert!(!dry_stderr.to_ascii_lowercase().contains("copying"));
    assert!(!t.path("dry-dst").exists());
}

#[cfg(debug_assertions)]
#[test]
fn previous_partial_name_can_be_copied_as_payload() {
    let t = Tmp::new();
    write(&t.path("src/file"), &vec![b'x'; 5 * 1024 * 1024]);
    let src = t.s("src/");
    let dst = t.s("dst/");
    let args = [
        "-a",
        "--block-size",
        "1M",
        "--resource-limits",
        "bandwidth=1G",
        &src,
        &dst,
    ];
    let partial = interrupted_partial(&args, &t.path("dst"));
    let collision_name = partial.file_name().unwrap().to_owned();
    fs::remove_file(&partial).unwrap();
    write(
        &t.path("src").join(&collision_name),
        b"deliberate collision",
    );

    let output = syq(&args);

    assert_output_ok(&output);
    assert_eq!(read(&t.path("dst/file")), read(&t.path("src/file")));
    assert_eq!(
        read(&t.path("dst").join(collision_name)),
        b"deliberate collision"
    );
}

#[cfg(debug_assertions)]
#[test]
fn previous_partial_name_can_be_copied_with_dot_destination() {
    let t = Tmp::new();
    write(&t.path("src/file"), &vec![b'x'; 5 * 1024 * 1024]);
    fs::create_dir(t.path("dst")).unwrap();
    let src = t.s("src/");
    let args = [
        "-a",
        "--block-size",
        "1M",
        "--resource-limits",
        "bandwidth=1G",
        &src,
        ".",
    ];
    let partial = interrupted_partial_from(&args, &t.path("dst"), Some(&t.path("dst")));
    let collision_name = partial.file_name().unwrap().to_owned();
    fs::remove_file(&partial).unwrap();
    write(
        &t.path("src").join(&collision_name),
        b"deliberate collision",
    );

    let mut command = compat_command();
    let output = command
        .args(args)
        .arg("--no-progress")
        .current_dir(t.path("dst"))
        .run()
        .unwrap();

    assert_output_ok(&output);
    assert_eq!(read(&t.path("dst/file")), read(&t.path("src/file")));
    assert_eq!(
        read(&t.path("dst").join(collision_name)),
        b"deliberate collision"
    );
}

// Two ordinary copies into one tree behave like rsync: the union lands, and a
// later invocation checks current destination state rather than hidden history.
#[test]
fn concurrent_copies_union() {
    let t = Tmp::new();
    for i in 0..200 {
        write(&t.path(&format!("A/a{i}")), b"a");
        write(&t.path(&format!("B/b{i}")), b"b");
    }
    let spawn = |src: &str| {
        compat_command()
            .args(["-a", "--no-progress", &t.s(src), &t.s("dest/")])
            .start()
            .unwrap()
    };
    let (mut a, mut b) = (spawn("A/"), spawn("B/"));
    assert!(a.wait().unwrap().success());
    assert!(b.wait().unwrap().success());
    for i in 0..200 {
        assert_eq!(read(&t.path(&format!("dest/a{i}"))), b"a");
        assert_eq!(read(&t.path(&format!("dest/b{i}"))), b"b");
    }
    fs::remove_file(t.path("dest/a7")).unwrap();
    run_ok(&["-a", &t.s("A/"), &t.s("dest/")]);
    assert_eq!(read(&t.path("dest/a7")), b"a");
}

#[cfg(debug_assertions)]
#[test]
fn different_jobs_use_distinct_partial_inodes() {
    let t = Tmp::new();
    let first_contents = vec![b'a'; 8 * 1024 * 1024];
    let second_contents = vec![b'b'; 8 * 1024 * 1024];
    write(&t.path("first"), &first_contents);
    write(&t.path("second"), &second_contents);

    let ready = t.path("partial-ready");
    let continuation = t.path("partial-continue");
    let mut first = compat_command()
        .args([
            "-a",
            "--performance-tuning",
            "workers=1",
            "--resource-limits",
            "bandwidth=1G",
            "--no-progress",
            &t.s("first"),
            &t.s("out"),
        ])
        .env("SYQ_TEST_PARTIAL_READY_FILE", &ready)
        .env("SYQ_TEST_PARTIAL_CONTINUE_FILE", &continuation)
        .start()
        .unwrap();
    wait_for_confinement_marker(&mut first, &ready, "partial preparation");
    let partials = partial_files(&t.0);
    assert_eq!(partials.len(), 1);
    let first_partial = &partials[0];

    let second = syq(&[
        "-a",
        "--performance-tuning",
        "workers=1",
        "--resource-limits",
        "bandwidth=1G",
        &t.s("second"),
        &t.s("out"),
    ]);
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert_eq!(read(&t.path("out")), second_contents);
    assert!(
        first_partial.exists(),
        "the second job must not rename the first job's partial"
    );
    release_confinement_barrier(&continuation);
    assert!(first.wait().unwrap().success());
    assert_eq!(read(&t.path("out")), first_contents);
    assert!(partial_files(&t.0).is_empty());
}

#[cfg(debug_assertions)]
#[test]
fn final_hash_and_partial_seed_use_one_inode_snapshot() {
    let t = Tmp::new();
    let mut first_contents = vec![0u8; 8 * 1024 * 1024];
    first_contents[4 * 1024 * 1024..].fill(b'a');
    let second_contents = vec![b'b'; 8 * 1024 * 1024];
    write(&t.path("basis"), &vec![0u8; 8 * 1024 * 1024]);
    write(&t.path("first"), &first_contents);
    write(&t.path("second"), &second_contents);
    set_mtime(&t.path("basis"), 1_600_000_000);
    set_mtime(&t.path("first"), 1_600_000_001);
    set_mtime(&t.path("second"), 1_600_000_002);
    let ready = t.path("basis-ready");
    let continuation = t.path("basis-continue");

    let mut first = compat_command()
        .args([
            "-a",
            "--performance-tuning",
            "workers=1",
            "--resource-limits",
            "bandwidth=1G",
            "--no-progress",
            &t.s("first"),
            &t.s("basis"),
        ])
        .env("SYQ_TEST_BASIS_READY_FILE", &ready)
        .env("SYQ_TEST_BASIS_CONTINUE_FILE", &continuation)
        .start()
        .unwrap();
    wait_for_confinement_marker(&mut first, &ready, "destination basis retention");
    assert!(
        partial_files(&t.0).is_empty(),
        "hashing alone must not create a sidecar"
    );

    let second = syq(&[
        "-a",
        "--performance-tuning",
        "workers=1",
        "--resource-limits",
        "bandwidth=1G",
        &t.s("second"),
        &t.s("basis"),
    ]);
    assert_output_ok(&second);
    assert_eq!(read(&t.path("basis")), second_contents);
    // Publish the second copy before allowing the first to seed its partial
    // from the retained inode, regardless of how long the second copy takes.
    release_confinement_barrier(&continuation);
    assert!(first.wait().unwrap().success());
    assert_eq!(read(&t.path("basis")), first_contents);
    assert!(partial_files(&t.0).is_empty());
}

#[cfg(debug_assertions)]
#[test]
fn retained_basis_growth_is_not_treated_as_an_exact_match() {
    let t = Tmp::new();
    let contents = vec![b'a'; 2 * 1024 * 1024];
    write(&t.path("src"), &contents);
    write(&t.path("basis"), &contents);
    set_mtime(&t.path("src"), 1_600_000_001);
    set_mtime(&t.path("basis"), 1_600_000_000);
    let ready = t.path("basis-ready");
    let continuation = t.path("continue");

    let mut child = compat_command()
        .args([
            "-a",
            "--performance-tuning",
            "workers=1",
            "--resource-limits",
            "bandwidth=1G",
            "--no-progress",
            &t.s("src"),
            &t.s("basis"),
        ])
        .env("SYQ_TEST_BASIS_READY_FILE", &ready)
        .env("SYQ_TEST_BASIS_CONTINUE_FILE", &continuation)
        .start()
        .unwrap();
    wait_for_confinement_marker(&mut child, &ready, "basis");

    OpenOptions::new()
        .append(true)
        .open(t.path("basis"))
        .unwrap()
        .write_all(b"trailing data")
        .unwrap();

    release_confinement_barrier(&continuation);
    assert!(child.wait().unwrap().success());
    assert_eq!(read(&t.path("basis")), contents);
    assert!(partial_files(&t.0).is_empty());
}

#[cfg(debug_assertions)]
#[test]
fn content_identical_basis_never_mixes_contents_and_metadata() {
    let t = Tmp::new();
    let first_contents = vec![b'a'; 8 * 1024 * 1024];
    let second_contents = vec![b'b'; 8 * 1024 * 1024];
    write(&t.path("basis"), &first_contents);
    write(&t.path("first"), &first_contents);
    write(&t.path("second"), &second_contents);
    fs::set_permissions(t.path("first"), fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(t.path("second"), fs::Permissions::from_mode(0o640)).unwrap();
    set_mtime(&t.path("basis"), 1_600_000_000);
    set_mtime(&t.path("first"), 1_600_000_001);
    set_mtime(&t.path("second"), 1_600_000_002);
    let ready = t.path("basis-ready");
    let continuation = t.path("continue");

    let mut first = compat_command()
        .args([
            "-a",
            "--performance-tuning",
            "workers=1",
            "--resource-limits",
            "bandwidth=1G",
            "--no-progress",
            &t.s("first"),
            &t.s("basis"),
        ])
        .env("SYQ_TEST_BASIS_READY_FILE", &ready)
        .env("SYQ_TEST_BASIS_CONTINUE_FILE", &continuation)
        .start()
        .unwrap();
    wait_for_confinement_marker(&mut first, &ready, "basis");
    assert!(
        partial_files(&t.0).is_empty(),
        "content comparison must not allocate a full sidecar"
    );

    let second = syq(&[
        "-a",
        "--performance-tuning",
        "workers=1",
        "--resource-limits",
        "bandwidth=1G",
        &t.s("second"),
        &t.s("basis"),
    ]);
    assert_output_ok(&second);
    assert_eq!(read(&t.path("basis")), second_contents);
    let published = fs::metadata(t.path("basis")).unwrap();
    assert_eq!(published.mode() & 0o777, 0o640);
    assert_eq!(published.mtime(), 1_600_000_002);

    release_confinement_barrier(&continuation);
    assert!(first.wait().unwrap().success());
    // The second job renamed a complete file over the descriptor retained by
    // the first. Metadata applied through the old descriptor cannot leak onto
    // the second job's contents, so the second whole-file publication wins.
    assert_eq!(read(&t.path("basis")), second_contents);
    let published = fs::metadata(t.path("basis")).unwrap();
    assert_eq!(published.mode() & 0o777, 0o640);
    assert_eq!(published.mtime(), 1_600_000_002);
    assert!(partial_files(&t.0).is_empty());
}

#[cfg(debug_assertions)]
#[test]
fn quick_check_metadata_repair_does_not_touch_a_concurrent_publication() {
    let t = Tmp::new();
    write(&t.path("basis"), b"aaaa");
    write(&t.path("first"), b"aaaa");
    write(&t.path("second"), b"bbbb");
    fs::set_permissions(t.path("basis"), fs::Permissions::from_mode(0o644)).unwrap();
    fs::set_permissions(t.path("first"), fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(t.path("second"), fs::Permissions::from_mode(0o640)).unwrap();
    set_mtime(&t.path("basis"), 1_600_000_000);
    set_mtime(&t.path("first"), 1_600_000_000);
    set_mtime(&t.path("second"), 1_600_000_001);
    let ready = t.path("quick-meta-ready");
    let continuation = t.path("continue");

    let mut first = compat_command()
        .args(["-a", "--no-progress", &t.s("first"), &t.s("basis")])
        .env("SYQ_TEST_QUICK_META_READY_FILE", &ready)
        .env("SYQ_TEST_QUICK_META_CONTINUE_FILE", &continuation)
        .start()
        .unwrap();
    wait_for_confinement_marker(&mut first, &ready, "quick meta");

    let second = syq(&["-a", &t.s("second"), &t.s("basis")]);
    assert_output_ok(&second);
    assert_eq!(read(&t.path("basis")), b"bbbb");
    let published = fs::metadata(t.path("basis")).unwrap();
    assert_eq!(published.mode() & 0o777, 0o640);
    assert_eq!(published.mtime(), 1_600_000_001);

    release_confinement_barrier(&continuation);
    assert_eq!(first.wait().unwrap().code(), Some(23));
    assert_eq!(read(&t.path("basis")), b"bbbb");
    let published = fs::metadata(t.path("basis")).unwrap();
    assert_eq!(published.mode() & 0o777, 0o640);
    assert_eq!(published.mtime(), 1_600_000_001);
}

#[cfg(debug_assertions)]
#[test]
fn quick_check_metadata_open_reports_concurrent_fifo_without_blocking() {
    use std::os::unix::fs::FileTypeExt;

    let t = Tmp::new();
    write(&t.path("basis"), b"same");
    write(&t.path("first"), b"same");
    mkfifo(&t.path("second"));
    fs::set_permissions(t.path("basis"), fs::Permissions::from_mode(0o644)).unwrap();
    fs::set_permissions(t.path("first"), fs::Permissions::from_mode(0o600)).unwrap();
    set_mtime(&t.path("basis"), 1_600_000_000);
    set_mtime(&t.path("first"), 1_600_000_000);
    let ready = t.path("quick-meta-ready");
    let continuation = t.path("continue");

    let mut first = compat_command()
        .args(["-a", "--no-progress", &t.s("first"), &t.s("basis")])
        .env("SYQ_TEST_QUICK_META_READY_FILE", &ready)
        .env("SYQ_TEST_QUICK_META_CONTINUE_FILE", &continuation)
        .start()
        .unwrap();
    wait_for_confinement_marker(&mut first, &ready, "quick meta");

    assert_output_ok(&syq(&["-a", &t.s("second"), &t.s("basis")]));
    release_confinement_barrier(&continuation);
    let status = (0..300).find_map(|_| {
        let status = first.try_wait().unwrap();
        if status.is_none() {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        status
    });
    if status.is_none() {
        let _ = first.kill();
        let _ = first.wait();
        panic!("quick-check repair blocked while opening a concurrently published FIFO");
    }
    assert_eq!(status.unwrap().code(), Some(23));
    assert!(fs::symlink_metadata(t.path("basis"))
        .unwrap()
        .file_type()
        .is_fifo());
}

#[cfg(debug_assertions)]
#[test]
fn unreadable_interrupted_partials_are_left_alone() {
    let t = Tmp::new();
    let contents = vec![b'a'; 8 * 1024 * 1024];
    write(&t.path("src"), &contents);
    for (i, mode) in [0o444, 0o000].into_iter().enumerate() {
        let src = t.s("src");
        let dst = t.s(&format!("out-{i}"));
        let args = ["-a", "--resource-limits", "bandwidth=1G", &src, &dst];
        let partial = interrupted_partial(&args, &t.0);
        fs::set_permissions(&partial, fs::Permissions::from_mode(mode)).unwrap();

        run_ok(&args);
        assert_eq!(read(&t.path(&format!("out-{i}"))), contents);
        assert_eq!(fs::metadata(&partial).unwrap().mode() & 0o777, mode);
        fs::remove_file(partial).unwrap();
    }
}

#[cfg(debug_assertions)]
#[test]
fn unchmodable_interrupted_partial_is_left_alone() {
    let t = Tmp::new();
    let contents = vec![b'a'; 8 * 1024 * 1024];
    write(&t.path("src"), &contents);
    let src = t.s("src");
    let dst = t.s("dst");
    let args = ["-a", "--resource-limits", "bandwidth=1G", &src, &dst];
    let partial = interrupted_partial(&args, &t.0);
    fs::set_permissions(&partial, fs::Permissions::from_mode(0o000)).unwrap();

    let out = compat_command()
        .args(args)
        .arg("--no-progress")
        .env("SYQ_TEST_FAIL_PARTIAL_CHMOD", "1")
        .run()
        .unwrap();

    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), contents);
    assert!(partial.exists());
}

#[cfg(debug_assertions)]
#[test]
fn writable_interrupted_partial_is_left_unchanged() {
    let t = Tmp::new();
    let contents = vec![b'a'; 8 * 1024 * 1024];
    write(&t.path("src"), &contents);
    let src = t.s("src");
    let dst = t.s("dst");
    let args = ["-a", "--resource-limits", "bandwidth=1G", &src, &dst];
    let partial = interrupted_partial(&args, &t.0);
    write(&partial, &contents);
    fs::set_permissions(&partial, fs::Permissions::from_mode(0o644)).unwrap();
    run_ok(&args);
    assert_eq!(read(&t.path("dst")), contents);
    assert_eq!(read(&partial), contents);
    assert_eq!(fs::metadata(&partial).unwrap().mode() & 0o7777, 0o644);
}

#[cfg(all(debug_assertions, any(target_os = "linux", target_os = "macos")))]
#[test]
fn copy_local_exdev_fallback_leaves_no_partial() {
    let t = Tmp::new();
    let contents = vec![b'x'; 8 * 1024 * 1024];
    write(&t.path("src"), &contents);
    write(&t.path("dst"), &contents);
    set_mtime(&t.path("src"), 1_600_000_001);
    set_mtime(&t.path("dst"), 1_600_000_000);

    let out = compat_command()
        .args([
            "-a",
            "--performance-tuning",
            "workers=1",
            "--no-progress",
            &t.s("src"),
            &t.s("dst"),
        ])
        .env("SYQ_TEST_COPY_LOCAL_EXDEV", "1")
        .env("SYQ_TEST_CLONE_ERROR", "EXDEV")
        .env("SYQ_DEBUG", "1")
        .run()
        .unwrap();
    assert_output_ok(&out);
    assert_eq!(tuning_observed(&out)["local_whole_files"], 0);
    assert_eq!(read(&t.path("dst")), contents);
    assert!(partial_files(&t.0).is_empty());
}

#[cfg(all(debug_assertions, target_os = "linux"))]
#[test]
fn native_inplace_exdev_fallback_preserves_hardlink_aliases() {
    let t = Tmp::new();
    let contents = vec![b'n'; 8 * 1024 * 1024];
    write(&t.path("src"), &contents);
    write(&t.path("dst"), &vec![b'o'; contents.len()]);
    fs::hard_link(t.path("dst"), t.path("alias")).unwrap();
    set_mtime(&t.path("src"), 1_700_000_000);
    set_mtime(&t.path("dst"), 1_600_000_000);
    let original_inode = fs::metadata(t.path("dst")).unwrap().ino();

    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "cp",
            "--inplace",
            "--src",
            &t.s("src"),
            "--as",
            &t.s("dst"),
            "-q",
        ])
        .env("SYQ_TEST_COPY_LOCAL_EXDEV", "1")
        .output()
        .unwrap();

    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), contents);
    assert_eq!(read(&t.path("alias")), contents);
    assert_eq!(fs::metadata(t.path("dst")).unwrap().ino(), original_inode);
    assert_eq!(fs::metadata(t.path("alias")).unwrap().ino(), original_inode);
    assert!(partial_files(&t.0).is_empty());
}

#[cfg(all(debug_assertions, target_os = "linux"))]
#[test]
fn copy_local_disk_whole_files_write_concurrently() {
    let t = Tmp::new();
    for name in ["first", "second"] {
        write(&t.path(&format!("src/{name}")), &prng(8 << 20, 459));
    }
    let continuation = t.path("continue");
    let mut child = compat_command()
        .args([
            "-a",
            "--performance-tuning",
            "workers=2",
            "--no-progress",
            &t.s("src/"),
            &t.s("dst/"),
        ])
        .env("SYQ_DEBUG", "1")
        .env("SYQ_TEST_COPY_LOCAL_EXDEV", "1")
        .env("SYQ_TEST_COPY_LOCAL_FS", "local")
        .env("SYQ_TEST_COPY_LOCAL_WRITTEN_FILE", t.path("ready"))
        .env("SYQ_TEST_COPY_LOCAL_CONTINUE_FILE", &continuation)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .start()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut both_written = false;
    while std::time::Instant::now() < deadline {
        let partials = partial_files(&t.path("dst"));
        if partials.len() == 2
            && partials
                .iter()
                .all(|path| fs::metadata(path).is_ok_and(|metadata| metadata.len() == 1 << 20))
        {
            both_written = true;
            break;
        }
        if child.try_wait().unwrap().is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    // Release both workers before checking the result, including on failure.
    write(&continuation, b"continue");
    let out = child.wait_with_output().unwrap();
    assert!(both_written, "whole-file copies were serialized: {out:?}");
    assert_output_ok(&out);
    assert_same_tree(&t.path("src"), &t.path("dst"));
    let observed = tuning_observed(&out);
    assert_eq!(observed["local_whole_files"], 2);
    assert_eq!(observed["range_requests"], 0);
}

#[cfg(all(debug_assertions, target_os = "linux"))]
#[test]
fn copy_local_disk_write_failure_keeps_old_destination_and_resumes_changed_source() {
    let t = Tmp::new();
    write(&t.path("src/small"), b"parallel file work");
    let original = prng(8 << 20, 456);
    write(&t.path("src/file"), &original);
    write(&t.path("dst/file"), b"old destination");
    let out = compat_command()
        .args(["-a", "--no-progress", &t.s("src/"), &t.s("dst/")])
        .env("SYQ_DEBUG", "1")
        .env("SYQ_TEST_COPY_LOCAL_EXDEV", "1")
        .env("SYQ_TEST_COPY_LOCAL_FS", "local")
        .env("SYQ_TEST_FAIL_COPY_LOCAL_AFTER_WRITE", "1")
        .run()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(stderr_of(&out).contains("test local-copy write failure"));
    assert_eq!(read(&t.path("dst/file")), b"old destination");
    let partials = partial_files(&t.path("dst"));
    assert_eq!(partials.len(), 1);
    assert_eq!(fs::metadata(&partials[0]).unwrap().len(), 1 << 20);
    let observed = tuning_observed(&out);
    assert_eq!(observed["local_whole_files"], 0);
    assert_eq!(observed["range_requests"], 0);

    // The failed userspace write is a resumable basis, not authority to skip
    // checking bytes that changed in the source before the retry.
    let mut changed = original;
    changed[..1 << 20].fill(b'c');
    write(&t.path("src/file"), &changed);
    // ENOSPC can stop the companion before it completes. Reproduce that state
    // deterministically and select ranges so the retry exercises partial reuse
    // instead of the direct-copy fast path for multiple pending files.
    if t.path("dst/small").exists() {
        fs::remove_file(t.path("dst/small")).unwrap();
    }
    let out = compat_command()
        .args([
            "-a",
            "--performance-tuning=copy-path=ranges",
            "--no-progress",
            &t.s("src/"),
            &t.s("dst/"),
        ])
        .env("SYQ_DEBUG", "1")
        .env("SYQ_TEST_COPY_LOCAL_EXDEV", "1")
        .env("SYQ_TEST_COPY_LOCAL_FS", "local")
        .run()
        .unwrap();
    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst/file")), changed);
    let observed = tuning_observed(&out);
    assert_eq!(observed["local_whole_files"], 0);
    assert!(observed["range_requests"].as_u64().unwrap() > 0);
    assert_eq!(partial_files(&t.path("dst")), partials);
}

#[cfg(debug_assertions)]
#[test]
fn long_basename_partial_is_truncated_and_retry_copies_correctly() {
    let t = Tmp::new();
    let basename = "n".repeat(240);
    let contents = vec![b'z'; 5 * 1024 * 1024];
    write(&t.path(&format!("src/{basename}")), &contents);
    fs::create_dir_all(t.path("dst")).unwrap();
    let src = t.s(&format!("src/{basename}"));
    let dst = t.s("dst/");
    let args = ["-a", "--resource-limits", "bandwidth=1G", &src, &dst];
    let partial = interrupted_partial(&args, &t.path("dst"));
    assert!(partial.file_name().unwrap().as_encoded_bytes().len() <= 255);
    assert!(partial
        .file_name()
        .unwrap()
        .to_string_lossy()
        .contains(".syq-tmp."));

    run_ok(&args);
    assert_eq!(read(&t.path(&format!("dst/{basename}"))), contents);
    assert!(partial.exists());
}

#[test]
fn impossible_sidecar_name_fails_one_file_and_continues() {
    let t = Tmp::new();
    let mut deep = PathBuf::new();
    let target_parent_len = libc::PATH_MAX as usize - 20;
    loop {
        let current = t
            .path("dst")
            .join(&deep)
            .as_os_str()
            .as_encoded_bytes()
            .len();
        if current >= target_parent_len {
            break;
        }
        let component_len = (target_parent_len - current - 1).min(200);
        assert!(component_len > 0);
        deep.push("d".repeat(component_len));
    }
    assert!(
        t.path("dst")
            .join(&deep)
            .as_os_str()
            .as_encoded_bytes()
            .len()
            >= target_parent_len
    );

    write(&t.path("src/good"), b"copied");
    write(
        &t.path("src").join(&deep).join("x"),
        b"cannot fit a sidecar",
    );

    let output = syq(&["-a", &t.s("src/"), &t.s("dst/")]);

    assert_eq!(output.status.code(), Some(23));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cannot create a safe sidecar"), "{stderr}");
    assert_eq!(read(&t.path("dst/good")), b"copied");
    assert!(!t.path("dst").join(deep).join("x").exists());
}

#[cfg(debug_assertions)]
#[test]
fn changed_source_retry_uses_published_file_as_block_basis() {
    let t = Tmp::new();
    let original = vec![b'a'; 8 * 1024 * 1024];
    let mut changed = original.clone();
    changed[0] = b'b';
    write(&t.path("src/file"), &original);
    set_mtime(&t.path("src/file"), 1_600_000_000);

    write(&t.path("replacement"), &changed);
    set_mtime(&t.path("replacement"), 1_600_000_001);
    let ready = t.path("finalize-ready");
    let continuation = t.path("finalize-continue");
    let mut child = compat_command()
        .args([
            "-a",
            "--stats",
            "--resource-limits",
            "bandwidth=1G",
            "--no-progress",
            &t.s("src/"),
            &t.s("dst/"),
        ])
        .env("SYQ_TEST_FINALIZE_READY_FILE", &ready)
        .env("SYQ_TEST_FINALIZE_CONTINUE_FILE", &continuation)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .start()
        .unwrap();
    // Wait for an acknowledged publication, then release it after replacing
    // the source. The test must not race a fixed one-second sleep.
    let mut progress = std::time::Instant::now();
    wait_for(
        "first attempt to acknowledge finalization",
        std::time::Duration::from_secs(60),
        || {
            if ready.exists() {
                return true;
            }
            assert!(
                child.try_wait().unwrap().is_none(),
                "copy exited before finalization"
            );
            if progress.elapsed() >= std::time::Duration::from_secs(5) {
                eprintln!(
                    "waiting for copy {} to acknowledge finalization: no ready signal",
                    child.id()
                );
                progress = std::time::Instant::now();
            }
            false
        },
    );
    assert!(t.path("dst/file").exists());
    fs::rename(t.path("replacement"), t.path("src/file")).unwrap();
    release_confinement_barrier(&continuation);

    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(read(&t.path("dst/file")), changed);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("bytes transferred: 12,582,912"),
        "retry should send one changed 4 MiB block, not the full file: {stdout}"
    );
}

#[cfg(all(debug_assertions, target_os = "linux"))]
#[test]
fn changed_source_retry_still_uses_copy_file_range() {
    let t = Tmp::new();
    let original = vec![b'a'; 8 * 1024 * 1024];
    let changed = vec![b'b'; 8 * 1024 * 1024];
    write(&t.path("src/file"), &original);
    set_mtime(&t.path("src/file"), 1_600_000_000);

    write(&t.path("replacement"), &changed);
    set_mtime(&t.path("replacement"), 1_600_000_001);
    let ready = t.path("finalize-ready");
    let continuation = t.path("finalize-continue");
    let mut child = compat_command()
        .args(["-a", "--no-progress", &t.s("src/"), &t.s("dst/")])
        .env("SYQ_TEST_FINALIZE_READY_FILE", &ready)
        .env("SYQ_TEST_FINALIZE_CONTINUE_FILE", &continuation)
        .env("SYQ_TEST_FAIL_HASH_BASIS", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .start()
        .unwrap();
    let mut progress = std::time::Instant::now();
    wait_for(
        "first attempt to acknowledge finalization",
        std::time::Duration::from_secs(60),
        || {
            if ready.exists() {
                return true;
            }
            assert!(
                child.try_wait().unwrap().is_none(),
                "copy exited before finalization"
            );
            if progress.elapsed() >= std::time::Duration::from_secs(5) {
                eprintln!(
                    "waiting for copy {} to acknowledge finalization: no ready signal",
                    child.id()
                );
                progress = std::time::Instant::now();
            }
            false
        },
    );
    assert!(t.path("dst/file").exists());
    fs::rename(t.path("replacement"), t.path("src/file")).unwrap();
    release_confinement_barrier(&continuation);

    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(read(&t.path("dst/file")), changed);
}

#[cfg(debug_assertions)]
#[test]
fn truncated_sidecar_of_a_filtered_file_survives_delete() {
    // Truncated names are protected even when the full target name is unknown.
    let t = Tmp::new();
    let long = "n".repeat(240);
    write(&t.path(&format!("src/{long}")), &vec![7u8; 8 << 20]);
    fs::create_dir_all(t.path("dst")).unwrap();
    let partial = interrupted_partial(
        &[
            "-a",
            "--resource-limits",
            "bandwidth=1G",
            &t.s("src/"),
            &t.s("dst"),
        ],
        &t.path("dst"),
    );
    let so = run_ok(&[
        "-a",
        "--resource-limits",
        "bandwidth=1G",
        "--delete",
        "--max-size",
        "1K",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert!(partial.exists(), "{so}");
    assert!(so.contains("0 deleted"), "{so}");
    // Removing the source does not authorize deleting another run's partial.
    fs::remove_file(t.path(&format!("src/{long}"))).unwrap();
    run_ok(&[
        "-a",
        "--resource-limits",
        "bandwidth=1G",
        "--delete",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert!(partial.exists());
}

#[cfg(debug_assertions)]
#[test]
fn partial_survives_when_target_becomes_a_directory() {
    let t = Tmp::new();
    write(&t.path("src/x"), &vec![7u8; 8 << 20]);
    fs::create_dir_all(t.path("dst")).unwrap();
    let partial = interrupted_partial(
        &[
            "-a",
            "--resource-limits",
            "bandwidth=1G",
            &t.s("src/"),
            &t.s("dst"),
        ],
        &t.path("dst"),
    );
    fs::remove_file(t.path("src/x")).unwrap();
    write(&t.path("src/x/inside"), b"now a directory");
    run_ok(&[
        "-a",
        "--resource-limits",
        "bandwidth=1G",
        "--delete",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert!(
        partial.exists(),
        "only explicit cleanup removes abandoned candidates"
    );
    assert_eq!(read(&t.path("dst/x/inside")), b"now a directory");
}

#[test]
fn partial_candidates_protect_containing_directories() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"a");
    let foreign = format!("dst/extra/deep/.f.syq-tmp.{}", "a".repeat(16));
    write(&t.path(&foreign), b"unclaimed");
    write(&t.path("dst/extra/gone"), b"an ordinary extra");
    let so = run_ok(&["-a", "-n", "-v", "--delete", &t.s("src/"), &t.s("dst")]);
    assert!(!so.contains("delete extra/ (destination only)"), "{so}");
    let out = syq(&["-a", "-v", "--delete", &t.s("src/"), &t.s("dst")]);
    assert!(out.status.success(), "{}", stderr_of(&out));
    assert!(t.path(&foreign).exists());
    assert!(!t.path("dst/extra/gone").exists());
    let diagnostic = stderr_of(&out);
    assert!(diagnostic.contains(".f.syq-tmp."), "{diagnostic}");
    assert!(diagnostic.contains("syq clean-partials"), "{diagnostic}");
    assert!(!diagnostic.contains("ignored paths"), "{diagnostic}");
}

#[cfg(debug_assertions)]
#[test]
fn live_sidecar_survives_delete_with_dotted_destination_spelling() {
    // `dst/.` and `dst//` must produce the same keys as `dst`: the receiver
    // rebuilds sidecar paths through Path (which normalizes), the delete walk
    // joins bytes (which doesn't), and a spelling mismatch classified the
    // job's own live sidecar as an orphan.
    for spelling in ["/.", "//"] {
        let t = Tmp::new();
        write(&t.path("src/f"), &vec![7u8; 8 << 20]);
        fs::create_dir_all(t.path("dst")).unwrap();
        let dst = format!("{}{spelling}", t.s("dst"));
        let partial = interrupted_partial(
            &[
                "-a",
                "--resource-limits",
                "bandwidth=1G",
                &t.s("src/"),
                &dst,
            ],
            &t.path("dst"),
        );
        // Filtered target: the sidecar is resume state and must survive, in
        // this spelling and cross-spelling alike.
        let so = run_ok(&[
            "-a",
            "--resource-limits",
            "bandwidth=1G",
            "--delete",
            "--max-size",
            "10",
            &t.s("src/"),
            &dst,
        ]);
        assert!(partial.exists(), "{spelling}: {so}");
        let so = run_ok(&[
            "-a",
            "--resource-limits",
            "bandwidth=1G",
            "--delete",
            "--max-size",
            "10",
            &t.s("src/"),
            &t.s("dst"),
        ]);
        assert!(partial.exists(), "cross-spelling {spelling}: {so}");
    }
}

#[test]
fn clean_partials_selects_only_current_regular_files() {
    let help = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["clean-partials", "--help"])
        .run()
        .unwrap();
    assert_output_ok(&help);
    let help = String::from_utf8_lossy(&help.stdout);
    for option in ["--dry-run", "--on", "--root", "--cwd"] {
        assert!(help.contains(option), "{help}");
    }
    let t = Tmp::new();
    let current = ".file.syq-tmp.abcdefghijklmnop";
    let compact = ".syq-tmp.abcdefghijklmnop";
    // Unchanged v0.5.2 spelling: the old format is deliberately unsupported.
    let old = ".file.syq-part.aaaaaaaaaaaaaaaaaaaaaaaaaa";
    write(&t.path(&format!("tree/{current}")), b"unfinished");
    write(&t.path(&format!("tree/nested/{compact}")), b"unfinished");
    write(&t.path(&format!("tree/{old}")), b"old format");
    write(&t.path("tree/ordinary"), b"keep");
    write(&t.path("tree/.file.syq-tmp.notes"), b"keep");
    fs::create_dir_all(t.path(&format!("tree/named/{current}"))).unwrap();
    write(&t.path(&format!("outside/{current}")), b"keep");
    std::os::unix::fs::symlink(t.path("outside"), t.path("tree/link")).unwrap();
    std::os::unix::fs::symlink("ordinary", t.path(&format!("tree/nested/{current}"))).unwrap();
    let before = listing(&t.path("tree"));
    let preview = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "clean-partials",
            "--dry-run",
            "-v",
            "--root",
            &t.s(""),
            "tree",
        ])
        .run()
        .unwrap();
    assert_output_ok(&preview);
    let preview = String::from_utf8_lossy(&preview.stdout);
    assert!(preview.contains("would remove 2 entries"), "{preview}");
    assert_eq!(listing(&t.path("tree")), before);
    run_native_ok(&[
        "clean-partials",
        "--performance-tuning",
        "workers=4",
        "--root",
        &t.s(""),
        "tree",
    ]);
    assert!(!t.path(&format!("tree/{current}")).exists());
    assert!(!t.path(&format!("tree/nested/{compact}")).exists());
    assert_eq!(read(&t.path(&format!("tree/{old}"))), b"old format");
    assert_eq!(read(&t.path("tree/ordinary")), b"keep");
    assert!(t.path(&format!("tree/named/{current}")).is_dir());
    assert!(t.path(&format!("tree/nested/{current}")).is_symlink());
    assert_eq!(read(&t.path(&format!("outside/{current}"))), b"keep");
    run_native_ok(&["clean-partials", &t.s("tree")]);
}

#[cfg(debug_assertions)]
#[test]
fn resume_uses_the_verified_buffer_when_candidate_changes_or_disappears() {
    for remove in [false, true] {
        let t = Tmp::new();
        let data = vec![b'a'; 2 << 20];
        write(&t.path("src"), &data);
        let candidate = t.path(".out.syq-tmp.abcdefghijklmnop");
        write(&candidate, &data);
        let ready = t.path("ready");
        let continuation = t.path("continue");
        let mut child = compat_command()
            .args([
                "-ac",
                "--block-size",
                "1M",
                "--resource-limits",
                "bandwidth=1G",
                "--no-progress",
                &t.s("src"),
                &t.s("out"),
            ])
            .env("SYQ_TEST_REUSE_READY_FILE", &ready)
            .env("SYQ_TEST_REUSE_CONTINUE_FILE", &continuation)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .start()
            .unwrap();
        wait_for_confinement_marker(&mut child, &ready, "verified candidate buffer");
        if remove {
            fs::remove_file(&candidate).unwrap();
        } else {
            write(&candidate, &vec![b'b'; data.len()]);
        }
        release_confinement_barrier(&continuation);
        let output = child.wait_with_output().unwrap();
        assert_output_ok(&output);
        assert_eq!(read(&t.path("out")), data);
        if !remove {
            assert_eq!(read(&candidate), vec![b'b'; data.len()]);
        }
        assert_eq!(partial_files(&t.0).len(), usize::from(!remove));
    }
}

#[cfg(debug_assertions)]
#[test]
fn concurrent_small_pushes_publish_independent_files() {
    for existing in [false, true] {
        let t = Tmp::new();
        let ssh = fake_ssh(&t);
        fs::create_dir_all(t.path("remote-home/dst")).unwrap();
        write(&t.path("first"), b"first complete file");
        write(&t.path("second"), b"second complete file");
        set_mtime(&t.path("first"), 1_600_000_001);
        set_mtime(&t.path("second"), 1_600_000_002);
        if existing {
            write(&t.path("remote-home/dst/file"), b"old");
        }
        let command = |source: &str| {
            let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
            command
                .args([
                    "cp",
                    "--syq-path",
                    env!("CARGO_BIN_EXE_syq"),
                    "--no-progress",
                    &t.s(source),
                    "--to",
                    "fake.example",
                    "--as",
                    &t.s("remote-home/dst/file"),
                ])
                .env("XDG_CONFIG_HOME", t.path("config"))
                .env("FAKE_REMOTE_HOME", t.path("remote-home"))
                .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
                .env("FAKE_RSH_LOG", t.path("rsh.log"))
                .env(
                    "PATH",
                    format!("{}:/usr/bin:/bin", ssh.parent().unwrap().display()),
                )
                .env("SYQ_DEBUG", "1");
            command
        };
        let ready = t.path("ready");
        let continuation = t.path("continue");
        let mut first = command("first")
            .env("SYQ_TEST_SMALL_COPY_READY_FILE", &ready)
            .env("SYQ_TEST_SMALL_COPY_CONTINUE_FILE", &continuation)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .start()
            .unwrap();
        wait_for_confinement_marker(&mut first, &ready, "small push staging");
        let second = command("second").run().unwrap();
        release_confinement_barrier(&continuation);
        let first = first.wait_with_output().unwrap();
        assert_output_ok(&second);
        assert_output_ok(&first);
        assert!(stderr_of(&first).contains("small copy: published"));
        assert!(stderr_of(&second).contains("small copy: published"));
        assert_eq!(
            read(&t.path("remote-home/dst/file")),
            b"first complete file"
        );
        assert!(partial_files(&t.path("remote-home/dst")).is_empty());

        write(
            &t.path("remote-home/dst/.file.syq-tmp.abcdefghijklmnop"),
            b"abandoned",
        );
        let cleanup = Command::new(env!("CARGO_BIN_EXE_syq"))
            .args([
                "clean-partials",
                "--on",
                "fake.example",
                "--syq-path",
                env!("CARGO_BIN_EXE_syq"),
                "--results",
                &t.s("removed.ndjson"),
                &t.s("remote-home/dst"),
            ])
            .env("XDG_CONFIG_HOME", t.path("config"))
            .env("FAKE_REMOTE_HOME", t.path("remote-home"))
            .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
            .env("FAKE_RSH_LOG", t.path("rsh.log"))
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", ssh.parent().unwrap().display()),
            )
            .run()
            .unwrap();
        assert_output_ok(&cleanup);
        assert!(partial_files(&t.path("remote-home/dst")).is_empty());
        assert_eq!(
            read(&t.path("remote-home/dst/file")),
            b"first complete file"
        );
        let records: Vec<serde_json::Value> = fs::read_to_string(t.path("removed.ndjson"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(records.last().unwrap()["status"], "success");
        assert_eq!(records.last().unwrap()["entries_removed"], 1);
    }
}

#[test]
fn concurrent_default_tree_copies_keep_every_file_whole() {
    let t = Tmp::new();
    fs::create_dir_all(t.path("dst")).unwrap();
    for index in 0..12 {
        let name = format!("nested/file-{index}");
        write(
            &t.path(&format!("first/{name}")),
            &vec![index as u8; (2 << 20) + index],
        );
        write(
            &t.path(&format!("second/{name}")),
            &vec![index as u8 + 32; (3 << 20) + index],
        );
        if index % 2 == 0 {
            write(&t.path(&format!("dst/{name}")), b"old destination");
        }
    }
    let start = |source: &str| {
        Command::new(env!("CARGO_BIN_EXE_syq"))
            .args([
                "cp",
                "--no-progress",
                "--srcs-in",
                &t.s(source),
                "--into-existing",
                &t.s("dst"),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .start()
            .unwrap()
    };
    let first = start("first");
    let second = start("second");
    let first = first.wait_with_output().unwrap();
    let second = second.wait_with_output().unwrap();
    assert_output_ok(&first);
    assert_output_ok(&second);
    assert_eq!(listing(&t.path("dst")), listing(&t.path("first")));
    for index in 0..12 {
        let name = format!("nested/file-{index}");
        let result = read(&t.path(&format!("dst/{name}")));
        assert!(
            result == read(&t.path(&format!("first/{name}")))
                || result == read(&t.path(&format!("second/{name}"))),
            "mixed contents in {name}"
        );
    }
}

#[cfg(all(target_os = "linux", debug_assertions))]
#[test]
fn partial_candidates_do_not_disable_local_whole_file_copies() {
    let t = Tmp::new();
    for name in ["file", "file-other", "unrelated"] {
        write(&t.path(&format!("src/{name}")), &vec![b'a'; 5 << 20]);
    }
    write(&t.path("dst/.file.syq-tmp.abcdefghijklmnop"), b"stale");
    write(&t.path("dst/.syq-tmp.abcdefghijklmnop"), b"ambiguous");
    let out = compat_command()
        .args(["-a", "--no-progress", &t.s("src/"), &t.s("dst/")])
        .env("SYQ_DEBUG", "1")
        .env("SYQ_TEST_COPY_LOCAL_EXDEV", "1")
        .env("SYQ_TEST_COPY_LOCAL_FS", "local")
        .run()
        .unwrap();
    assert_output_ok(&out);
    let observed = tuning_observed(&out);
    assert_eq!(observed["local_whole_files"], 3);
    assert_eq!(observed["range_requests"], 0);
    for name in ["file", "file-other", "unrelated"] {
        assert_eq!(
            read(&t.path(&format!("src/{name}"))),
            read(&t.path(&format!("dst/{name}")))
        );
    }
}

#[cfg(all(target_os = "linux", debug_assertions))]
#[test]
fn seeding_preallocates_before_copying_donor_bytes() {
    for existing in [false, true] {
        let t = Tmp::new();
        write(&t.path("src"), &vec![b'a'; 5 << 20]);
        if existing {
            write(&t.path("out"), b"old contents");
        }
        write(&t.path(".out.syq-tmp.abcdefghijklmnop"), b"donor");
        let out = compat_command()
            .args([
                "-ac",
                "--resource-limits",
                "bandwidth=1G",
                "--no-progress",
                &t.s("src"),
                &t.s("out"),
            ])
            .env("SYQ_TEST_FALLOCATE_ERRNO", "no_space")
            .run()
            .unwrap();
        assert!(!out.status.success());
        assert!(
            stderr_of(&out).contains("preallocate destination file"),
            "{}",
            stderr_of(&out)
        );
        if existing {
            assert_eq!(read(&t.path("out")), b"old contents");
        } else {
            assert!(!t.path("out").exists());
        }
        assert_eq!(read(&t.path(".out.syq-tmp.abcdefghijklmnop")), b"donor");
    }
}

#[test]
fn resume_prefers_a_partial_to_the_old_destination_contents() {
    let t = Tmp::new();
    let contents = vec![b'a'; 5 << 20];
    write(&t.path("src"), &contents);
    write(&t.path("out"), &vec![b'b'; contents.len()]);
    write(
        &t.path(".out.syq-tmp.abcdefghijklmnop"),
        &contents[..3 << 20],
    );
    let out = run_ok(&[
        "-ac",
        "--block-size=1M",
        "--resource-limits=bandwidth=1G",
        &t.s("src"),
        &t.s("out"),
    ]);
    assert_eq!(read(&t.path("out")), contents);
    assert!(
        out.contains("1 files (2.00 MiB), 3.00 MiB unchanged"),
        "{out}"
    );
    assert_eq!(partial_files(&t.0).len(), 1);
}

#[cfg(all(debug_assertions, target_os = "linux"))]
#[test]
fn local_read_ahead_preserves_staged_and_inplace_contents() {
    for force_read_ahead in [false, true] {
        for inplace in [false, true] {
            let t = Tmp::new();
            let data = prng((17 << 20) + 73, 918);
            write(&t.path("source"), &data);
            write(&t.path("destination"), b"old destination");
            let inode = fs::metadata(t.path("destination")).unwrap().ino();
            let mut command = compat_command();
            command.args(["-a", "--no-progress", &t.s("source"), &t.s("destination")]);
            if inplace {
                command.arg("--inplace");
            }
            if force_read_ahead {
                command.env("SYQ_TEST_LOCAL_READ_AHEAD", "1");
            }
            let out = command
                .env("SYQ_TEST_COPY_LOCAL_FS", "local")
                .env("SYQ_DEBUG", "1")
                .run()
                .unwrap();
            assert_output_ok(&out);
            if force_read_ahead {
                assert!(stderr_of(&out).contains("source read-ahead started"));
            }
            assert_eq!(read(&t.path("destination")), data);
            if inplace {
                assert_eq!(fs::metadata(t.path("destination")).unwrap().ino(), inode);
            }
            assert!(partial_files(&t.0).is_empty());
        }
    }
}

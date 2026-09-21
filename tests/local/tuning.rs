use super::*;

#[test]
fn source_fd_budget_handles_deep_tree_with_96_slots() {
    let t = Tmp::new();
    let mut deepest = t.path("source");
    let mut destination_leaf = t.path("destination");
    for index in 0..80 {
        let component = format!("d{index:02}");
        deepest.push(&component);
        destination_leaf.push(component);
    }
    write(&deepest.join("leaf"), b"deep");
    destination_leaf.push("leaf");

    let mut command = compat_command();
    command.args([
        "-a",
        "--performance-tuning",
        "workers=1",
        "--no-progress",
        &t.s("source/"),
        &t.s("destination/"),
    ]);
    command.env("SYQ_DEBUG", "1");
    set_child_nofile_limit(&mut command, 96);
    let output = command.run().unwrap();
    assert!(output.status.success(), "{}", stderr_of(&output));
    assert_eq!(read(&destination_leaf), b"deep");
}

#[test]
fn source_fd_budget_handles_ten_exact_sources_with_128_slots() {
    let t = Tmp::new();
    let mut sources = Vec::new();
    for index in 0..10 {
        let relative = format!("source-{index:02}");
        write(&t.path(&relative), relative.as_bytes());
        sources.push(t.s(&relative));
    }

    let mut command = compat_command();
    command.args(["-a", "--performance-tuning", "workers=1", "--no-progress"]);
    command.args(&sources);
    command.arg(t.s("destination/"));
    command.env("SYQ_DEBUG", "1");
    set_child_nofile_limit(&mut command, 128);
    let output = command.run().unwrap();
    assert!(output.status.success(), "{}", stderr_of(&output));
    for index in 0..sources.len() {
        let name = format!("source-{index:02}");
        assert_eq!(
            read(&t.path(&format!("destination/{name}"))),
            name.as_bytes()
        );
    }
}

#[test]
fn automatic_worker_ceiling_does_not_reserve_hypothetical_descriptors() {
    let t = Tmp::new();
    write(
        &t.path("source"),
        b"a large ceiling does not open more files",
    );
    for (label, limit) in [("default", None), ("large-ceiling", Some("workers=65536"))] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
        command.args(["cp", "--no-progress", &t.s("source"), "--as", &t.s(label)]);
        if let Some(limit) = limit {
            command.args(["--resource-limits", limit]);
        }
        command.env("SYQ_TUNING_CACHE", "");
        set_child_nofile_limit(&mut command, 512);
        let output = command.run().unwrap();
        assert_output_ok(&output);
        assert_eq!(read(&t.path(label)), read(&t.path("source")));
    }
}

#[cfg(debug_assertions)]
#[test]
fn automatic_workers_can_start_above_64_from_the_cache() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    let data = prng(5 * 1024 * 1024 + 123, 806);
    for file in ["one", "two"] {
        write(&t.path(&format!("source/{file}")), &data);
    }
    for (label, limit, expected) in [("default", None, 80), ("capped", Some(72), 72)] {
        write(
            &t.path("tuning.json"),
            br#"{"paths":{"local>host|tcp":80}}"#,
        );
        let events = t.path(&format!("events-{label}"));
        let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
        command.args([
            "cp",
            "--srcs-in",
            &t.s("source"),
            "--to",
            "host",
            "--into",
            &t.s(label),
            "--rsh",
            rsh.to_str().unwrap(),
            "--syq-path",
            env!("CARGO_BIN_EXE_syq"),
            "--tcp-ports",
            EPHEMERAL_TCP_PORTS,
            "--no-progress",
            "-vv",
            "--resource-limits",
            "bandwidth=4M",
        ]);
        if let Some(limit) = limit {
            command.args(["--resource-limits", &format!("workers={limit}")]);
        }
        let output = command
            .env("SYQ_TUNING_CACHE", t.path("tuning.json"))
            .env("SYQ_TEST_WORKER_EVENTS", &events)
            .env("SYQ_TEST_REQUIRE_TCP", "1")
            .env("FAKE_REMOTE_HOME", t.path("remote-home"))
            .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
            .env("FAKE_RSH_LOG", t.path("rsh.log"))
            .env("FAKE_SSH_CONNECTION", "127.0.0.1 40000 127.0.0.1 22")
            .env("XDG_CONFIG_HOME", t.path("config"))
            .env("XDG_CACHE_HOME", t.path("cache"))
            .run()
            .unwrap();
        assert_output_ok(&output);
        assert!(
            stderr_of(&output).contains(&format!(
                "starting with {expected} connections remembered for this path"
            )),
            "{output:?}"
        );
        for file in ["one", "two"] {
            assert_eq!(read(&t.path(&format!("{label}/{file}"))), data);
        }
        let observed = fs::read_to_string(&events).unwrap();
        let ids: Vec<usize> = observed
            .lines()
            .filter(|line| line.starts_with("connected "))
            .map(|line| line.split_whitespace().nth(1).unwrap().parse().unwrap())
            .collect();
        assert!(ids.iter().any(|&id| id >= 64), "{label}: {observed}");
        if let Some(limit) = limit {
            assert!(ids.iter().all(|&id| id < limit), "{label}: {observed}");
        }
    }
}

#[test]
fn source_fd_preflight_rejects_shared_worker_boundary_before_destination_creation() {
    let t = Tmp::new();
    write(&t.path("source"), &vec![b'x'; 8 * 1024 * 1024]);
    let mut command = compat_command();
    command.args([
        "-a",
        "--performance-tuning",
        "workers=64",
        "--no-progress",
        &t.s("source"),
        &t.s("destination"),
    ]);
    // Local and remote-TCP sources feed the same shared-worker count into FD
    // admission. At 64 workers the conservative exact-leaf model plus the 64
    // cross-session destination claims requires current_open + 1764 slots. Use
    // a portable low limit here to verify that admission fails before
    // destination creation; the exact per-worker arithmetic, including the
    // uncached hash descriptor, is asserted in the FsOps unit test. The child
    // must retain the lowered hard limit because syq
    // normally raises a
    // low soft limit to the inherited hard limit during startup. Never try to
    // raise an inherited hard limit: supported environments commonly cap it
    // at 1024. getrlimit/setrlimit are async-signal-safe on supported Unix.
    unsafe {
        command.pre_exec(|| {
            let mut inherited = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::getrlimit(libc::RLIMIT_NOFILE, &mut inherited) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let low_limit = inherited.rlim_max.min(128);
            let limit = libc::rlimit {
                rlim_cur: low_limit,
                rlim_max: low_limit,
            };
            if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let output = command.run().unwrap();
    assert!(!output.status.success(), "unexpected success: {output:?}");
    let stderr = stderr_of(&output);
    assert!(stderr.contains("source setup needs about"), "{stderr}");
    let required: usize = stderr
        .split("source setup needs about ")
        .nth(1)
        .and_then(|tail| tail.split(" open-file slots").next())
        .unwrap()
        .parse()
        .unwrap();
    let current_open: usize = stderr
        .split(" open-file slots (")
        .nth(1)
        .and_then(|tail| tail.split(" currently open)").next())
        .unwrap()
        .parse()
        .unwrap();
    // Conservatively budget every selector as parent + exact object for the
    // registry, control, and all 64 shared workers, plus worker/cache reserve.
    // Linux still reserves its direct-copy claims. macOS disables optional
    // clone claims under descriptor pressure before ordinary admission fails.
    let copy_local_claims = if cfg!(target_os = "linux") { 64 * 3 } else { 0 };
    assert_eq!(
        required,
        current_open + 1572 + copy_local_claims,
        "{stderr}"
    );
    assert!(
        !t.path("destination").exists(),
        "source FD admission failed after destination creation"
    );
}

#[cfg(debug_assertions)]
#[test]
fn large_file_parallel_chunks() {
    let t = Tmp::new();
    let data = prng(200 * 1024 * 1024 + 4321, 99);
    write(&t.path("src/huge.bin"), &data);
    set_mtime(&t.path("src/huge.bin"), 1_600_000_000);
    run_ok(&[
        "-a",
        "--performance-tuning",
        "workers=8",
        "--block-size",
        "1M",
        &t.s("src/"),
        &t.s("dst/"),
    ]);
    assert!(read(&t.path("dst/huge.bin")) == data);
    assert_same_tree(&t.path("src/huge.bin"), &t.path("dst/huge.bin"));
    assert!(partial_files(&t.path("dst")).is_empty());
    // And partial resume of the same big file with parallel chunks.
    let src = t.s("src/");
    let dst = t.s("dst/");
    let args = [
        "-a",
        "--performance-tuning",
        "workers=8",
        "--block-size",
        "1M",
        "--resource-limits",
        "bandwidth=1G",
        &src,
        &dst,
    ];
    fs::remove_file(t.path("dst/huge.bin")).unwrap();
    let partial = interrupted_partial(&args, &t.path("dst"));
    {
        let f = File::create(&partial).unwrap();
        (&f).write_all(&data[..50 * 1024 * 1024]).unwrap();
        f.set_len(data.len() as u64).unwrap();
    }
    run_ok(&args);
    assert!(read(&t.path("dst/huge.bin")) == data);
}

#[test]
fn tuning_options_force_ranges_for_small_and_whole_local_files() {
    let t = Tmp::new();
    for (file, size) in [("small", 1024), ("large", 6 << 20), ("empty", 0)] {
        write(&t.path(&format!("source/{file}")), &prng(size, 909));
    }
    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "cp",
            "--srcs-in",
            &t.s("source"),
            "--into",
            &t.s("destination"),
            "--performance-tuning=copy-path=ranges,request-size=1M,split-min-size=1M",
            "--performance-tuning",
            "workers=2",
            "-v",
            "--no-progress",
            "--preserve=permissions",
        ])
        .run()
        .unwrap();
    assert_output_ok(&out);
    let observed = tuning_observed(&out);
    assert!(observed["range_requests"].as_u64().unwrap() >= 7);
    assert_eq!(observed["max_request_bytes"], 1 << 20);
    assert_eq!(observed["local_whole_files"], 0);
    assert_eq!(observed["small_batches"], 0);
    assert!(stderr_of(&out).contains("split-min-size=8388608"));
    assert_same_tree(&t.path("source"), &t.path("destination"));
}

#[test]
#[cfg(debug_assertions)]
fn automatic_streaming_pull_preserves_average_bandwidth_pacing() {
    for tcp in [false, true] {
        let t = Tmp::new();
        let rsh = fake_rsh(&t);
        // Require the SSH arrival address even where Linux interface discovery
        // could otherwise hide an incomplete fake SSH session.
        executable(&t.path("remote-bin/ip"), b"#!/bin/sh\nexit 1\n");
        let data = prng(1 << 20, 967);
        write(&t.path("source"), &data);
        let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
        command
            .args([
                "cp",
                "-v",
                "--stats",
                "--no-compress",
                "--resource-limits=bandwidth=512K",
                "--performance-tuning=workers=1",
                "--no-progress",
                "--rsh",
                rsh.to_str().unwrap(),
                "--syq-path",
                env!("CARGO_BIN_EXE_syq"),
                "--tcp-ports",
                EPHEMERAL_TCP_PORTS,
                "--results",
                &t.s("result.jsonl"),
                "--from",
                "host",
                &t.s("source"),
                "--as",
                &t.s("destination"),
            ])
            .env("SYQ_DEBUG", "1")
            .env("FAKE_REMOTE_HOME", t.path("remote-home"))
            .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
            .env("FAKE_RSH_LOG", t.path("rsh.log"))
            .env("FAKE_SSH_CONNECTION", "127.0.0.1 40000 127.0.0.1 22")
            .env("XDG_CONFIG_HOME", t.path("config"))
            .env("XDG_CACHE_HOME", t.path("cache"));
        if tcp {
            command.env("SYQ_TEST_REQUIRE_TCP", "1");
        } else {
            command.arg("--no-tcp");
        }
        let out = command.run().unwrap();
        assert_output_ok(&out);
        assert_eq!(read(&t.path("destination")), data);
        let results = fs::read_to_string(t.path("result.jsonl")).unwrap();
        let terminal: serde_json::Value =
            serde_json::from_str(results.lines().last().unwrap()).unwrap();
        assert!(
            terminal["copying_elapsed_ms"].as_u64().unwrap() >= 1800,
            "{terminal}"
        );
        let observed = tuning_observed(&out);
        assert!(
            observed["streaming_ranges"].as_u64().unwrap() > 0,
            "{out:?}"
        );
        assert_eq!(observed["range_requests"], 0, "{out:?}");
        assert_eq!(observed["max_request_bytes"], 64 << 10, "{out:?}");
        assert!(
            stderr_of(&out).contains("streaming above 262144 bytes"),
            "{out:?}"
        );
        // This verifies the whole-copy average, not a socket-ingress burst cap:
        // the source streams ahead while this worker paces destination writes.
    }
}

#[cfg(debug_assertions)]
#[test]
fn ordinary_range_errors_do_not_poison_the_next_auto_streamed_file() {
    for failure in ["read", "write"] {
        for blocks in [2, 4] {
            let t = Tmp::new();
            let rsh = fake_rsh(&t);
            let original = prng(2 << 20, 968);
            let mut changed = original.clone();
            changed[..blocks * (64 << 10)].fill(b'x');
            write(&t.path("source/bad"), &changed);
            write(&t.path("destination/bad"), &original);
            let good = prng(1 << 20, 969);
            write(&t.path("source/good"), &good);
            // Largest-first scheduling gives bad a short ordinary delta before
            // good's fresh, automatically streamed range on the SAME worker.
            // Cover both a tail drain and an error at the full write window.
            let source = if failure == "read" {
                format!("fake:{}/", t.s("source"))
            } else {
                t.s("source/")
            };
            let destination = if failure == "write" {
                format!("fake:{}/", t.s("destination"))
            } else {
                t.s("destination/")
            };
            let out = remote_syq_command(
                &t,
                &rsh,
                &[
                    "-ac",
                    "-B64K",
                    "-v",
                    "--stats",
                    "--no-compress",
                    &source,
                    &destination,
                ],
            )
            .env("SYQ_DEBUG", "1")
            .env(
                if failure == "read" {
                    "SYQ_TEST_FAIL_READ_RANGE_NAME"
                } else {
                    "SYQ_TEST_FAIL_WRITE_RANGE_NAME"
                },
                "bad",
            )
            .run()
            .unwrap();
            assert_eq!(out.status.code(), Some(23), "{out:?}");
            assert!(
                stderr_of(&out).contains(if failure == "read" {
                    "test read-range failure"
                } else {
                    "test range write failure"
                }),
                "{out:?}"
            );
            assert!(
                !stderr_of(&out).contains("connection dropped; reopening"),
                "{out:?}"
            );
            assert!(!stderr_of(&out).contains("unexpected response"), "{out:?}");
            assert!(
                !stderr_of(&out).contains("completion fence/count mismatch"),
                "{out:?}"
            );
            assert_eq!(read(&t.path("destination/bad")), original);
            assert_eq!(read(&t.path("destination/good")), good);
            let observed = tuning_observed(&out);
            assert!(observed["range_requests"].as_u64().unwrap() > 0, "{out:?}");
            assert!(
                observed["streaming_ranges"].as_u64().unwrap() > 0,
                "{out:?}"
            );
        }
    }
}

#[cfg(debug_assertions)]
#[test]
fn streaming_read_errors_do_not_publish_a_file() {
    let t = Tmp::new();
    let data = prng(1 << 20, 954);
    write(&t.path("src"), &data);
    let args = [
        "-a",
        "--performance-tuning=workers=1",
        "--performance-tuning=copy-path=streaming,request-size=64K",
        &t.s("src"),
        &t.s("dst"),
    ];
    let failed = compat_command()
        .args(args)
        .env("SYQ_TEST_FAIL_READ_RANGE", "1")
        .run()
        .unwrap();
    assert!(!failed.status.success(), "{failed:?}");
    assert!(!t.path("dst").exists());
    let recovered = compat_command().args(args).run().unwrap();
    assert_output_ok(&recovered);
    assert_eq!(read(&t.path("dst")), data);
}

#[test]
fn tuning_options_batch_limits_include_the_first_file() {
    let t = Tmp::new();
    // Stay inside the local tiny-file ceiling while exercising both batch limits.
    for i in 0..7 {
        write(&t.path(&format!("source/{i}")), &prng(60 << 10, i));
    }
    for (files, bytes, expected_files) in [(3, 200 << 10, 3), (10, 100 << 10, 1)] {
        let destination = t.s(&format!("destination-{files}"));
        let out = Command::new(env!("CARGO_BIN_EXE_syq"))
            .args([
                "cp",
                "--srcs-in",
                &t.s("source"),
                "--into",
                &destination,
                "--performance-tuning",
                &format!("batch-files={files},batch-bytes={bytes}"),
                "--performance-tuning",
                "workers=1",
                "-v",
                "--no-progress",
                "--preserve=permissions",
            ])
            .run()
            .unwrap();
        assert_output_ok(&out);
        let observed = tuning_observed(&out);
        assert_eq!(observed["max_batch_files"], expected_files, "{observed}");
        assert!(observed["max_batch_bytes"].as_u64().unwrap() <= bytes);
        assert_eq!(observed["range_requests"], 0);
        assert_same_tree(&t.path("source"), Path::new(&destination));
    }
}

#[test]
fn tuning_options_control_the_native_small_copy_shortcut() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    write(&t.path("source"), b"native small copy");
    for options in [
        "copy-path=auto",
        "copy-path=auto-streaming",
        "copy-path=ranges",
        "batch-files=2,batch-bytes=512",
    ] {
        let destination = t.s(&format!("destination-{}", options.len()));
        let out = Command::new(env!("CARGO_BIN_EXE_syq"))
            .args([
                "cp",
                &t.s("source"),
                "--to",
                "host",
                "--as",
                &destination,
                "--rsh",
                rsh.to_str().unwrap(),
                "--syq-path",
                env!("CARGO_BIN_EXE_syq"),
                "--no-tcp",
                "--performance-tuning",
                "workers=1",
                "-v",
                "--no-progress",
                "--performance-tuning",
                options,
            ])
            .env("FAKE_REMOTE_HOME", t.path("remote-home"))
            .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
            .env("FAKE_RSH_LOG", t.path("rsh.log"))
            .env("XDG_CONFIG_HOME", t.path("config"))
            .env("XDG_CACHE_HOME", t.path("cache"))
            .run()
            .unwrap();
        assert_output_ok(&out);
        let observed = tuning_observed(&out);
        let counter = match options {
            "copy-path=auto" | "copy-path=auto-streaming" => "native_small_copies",
            "copy-path=ranges" => "range_requests",
            _ => "small_batches",
        };
        assert_eq!(observed[counter], 1, "{observed}");
        assert_eq!(read(Path::new(&destination)), b"native small copy");
    }
}

#[test]
fn tuning_options_average_pacing_pays_for_one_large_request() {
    let t = Tmp::new();
    let data = prng(2 << 20, 910);
    write(&t.path("source"), &data);
    for (pacing, expected_max) in [("average", 2 << 20), ("25ms", 52_428)] {
        let start = std::time::Instant::now();
        let out = Command::new(env!("CARGO_BIN_EXE_syq"))
            .args([
                "cp",
                &t.s("source"),
                "--as",
                &t.s(pacing),
                "--performance-tuning",
                "workers=1",
                "-v",
                "--no-progress",
                "--resource-limits=bandwidth=2M",
                "--performance-tuning",
                &format!("copy-path=ranges,request-size=2M,bw-pacing={pacing}"),
            ])
            .run()
            .unwrap();
        assert_output_ok(&out);
        assert!(
            start.elapsed() >= std::time::Duration::from_millis(900),
            "{out:?}"
        );
        let observed = tuning_observed(&out);
        assert_eq!(observed["max_request_bytes"], expected_max, "{observed}");
        if pacing == "average" {
            assert_eq!(observed["range_requests"], 1);
        }
        assert_eq!(read(&t.path(pacing)), data);
    }
}

#[test]
fn tuning_options_are_in_full_help_and_validate_before_copying() {
    let t = Tmp::new();
    write(&t.path("source"), b"source");
    for interface in ["cp", "rsync"] {
        let help = Command::new(env!("CARGO_BIN_EXE_syq"))
            .args([interface, "--help"])
            .run()
            .unwrap();
        assert_output_ok(&help);
        assert!(!String::from_utf8_lossy(&help.stdout).contains("--performance-tuning"));
        let help = Command::new(env!("CARGO_BIN_EXE_syq"))
            .args([interface, "--help-all"])
            .run()
            .unwrap();
        assert_output_ok(&help);
        let text = String::from_utf8_lossy(&help.stdout);
        assert!(
            text.contains("--performance-tuning") && text.contains("pipeline-depth"),
            "{text}"
        );
        assert!(!text.contains("job-storage"), "{text}");
        for options in [
            "typo=4",
            "job-storage=combined",
            "job-storage=compact",
            "job-storage=inline",
            "pipeline-depth=0",
            "request-size=65M",
            "pipeline-depth=4,pipeline-depth=8",
            "copy-path=ranges,batch-files=1",
            "copy-path=streaming,batch-files=1",
            "copy-path=streaming,pipeline-depth=4",
            "bw-pacing=average",
        ] {
            let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
            command.args([interface, "--performance-tuning", options, &t.s("source")]);
            if interface == "cp" {
                command.arg("--as");
            }
            let out = command.arg(t.s("destination")).run().unwrap();
            assert!(!out.status.success(), "{out:?}");
            assert!(stderr_of(&out).contains("--performance-tuning"), "{out:?}");
            assert!(!t.path("destination").exists());
        }
    }
}

#[test]
fn tuning_options_keep_the_aggregate_bandwidth_limit() {
    let t = Tmp::new();
    let data = prng(2 * 1024 * 1024, 906);
    write(&t.path("source"), &data);
    let start = std::time::Instant::now();
    let out = run_ok(&[
        "-a",
        "--resource-limits=bandwidth=1M",
        "--performance-tuning=workers=4",
        "--performance-tuning=request-size=64M,pipeline-depth=64",
        &t.s("source"),
        &t.s("destination"),
    ]);
    assert!(
        start.elapsed() >= std::time::Duration::from_millis(1600),
        "{out}"
    );
    assert_eq!(read(&t.path("destination")), data);
}

#[test]
fn bwlimit_is_aggregate_across_workers() {
    let t = Tmp::new();
    for i in 0..4 {
        write(
            &t.path(&format!("src/{i}.bin")),
            &prng(512 * 1024, i as u64 + 100),
        );
    }

    // Four independent files keep four workers active. At 1 MiB/s, their
    // aggregate 2 MiB must take about two seconds (minus the initial burst). A
    // mistakenly per-worker limiter would finish in well under one second.
    let start = std::time::Instant::now();
    run_ok(&[
        "-a",
        "--performance-tuning",
        "workers=4",
        "--resource-limits",
        "bandwidth=1M",
        &t.s("src/"),
        &t.s("dst/"),
    ]);
    let elapsed = start.elapsed();
    assert!(
        elapsed >= std::time::Duration::from_millis(1600),
        "aggregate 2 MiB copy completed too quickly: {elapsed:?}"
    );
    assert_same_tree(&t.path("src"), &t.path("dst"));
}

#[test]
fn bwlimit_rejects_invalid_rates() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"x");
    let out = syq(&[
        "-a",
        "--resource-limits",
        "bandwidth=fast",
        &t.s("src/"),
        &t.s("dst/"),
    ]);
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("bad bandwidth"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[cfg(all(target_os = "linux", debug_assertions))]
#[test]
fn fallocate_no_space_is_fatal_and_stops_later_files() {
    let t = Tmp::new();
    write(&t.path("src/a-large"), &vec![b'x'; 256 * 1024]);
    write(
        &t.path("src/z-small"),
        b"must not be copied after disk-full",
    );
    write(&t.path("dst/existing"), b"make this an update");

    let output = compat_command()
        .args([
            "-a",
            "--block-size",
            "64K",
            "--resource-limits",
            "bandwidth=1G",
            "--performance-tuning",
            "workers=1",
            &t.s("src/"),
            &t.s("dst"),
            "--no-progress",
        ])
        .env("SYQ_TEST_FALLOCATE_ERRNO", "no_space")
        .run()
        .unwrap();

    assert!(
        !output.status.success(),
        "injected ENOSPC unexpectedly succeeded:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("preallocate destination file"), "{stderr}");
    assert!(!t.path("dst/a-large").exists());
    assert!(
        !t.path("dst/z-small").exists(),
        "disk-full must abort the transfer instead of continuing per-file"
    );
}

#[cfg(all(target_os = "linux", debug_assertions))]
#[test]
fn fallocate_unsupported_filesystem_still_uses_sparse_fallback() {
    let t = Tmp::new();
    write(&t.path("src/file"), &vec![b'x'; 256 * 1024]);
    write(&t.path("dst/existing"), b"make this an update");

    let output = compat_command()
        .args([
            "-a",
            "--block-size",
            "64K",
            "--resource-limits",
            "bandwidth=1G",
            "--performance-tuning",
            "workers=1",
            &t.s("src/"),
            &t.s("dst"),
            "--no-progress",
        ])
        .env("SYQ_TEST_FALLOCATE_ERRNO", "unsupported")
        .run()
        .unwrap();

    assert_output_ok(&output);
    assert_eq!(read(&t.path("dst/file")), vec![b'x'; 256 * 1024]);
}

#[test]
fn small_pushes_take_one_turn_and_match_the_engine() {
    let t = Tmp::new();
    let ssh = fake_ssh(&t);
    fs::create_dir_all(t.path("remote-home")).unwrap();
    write(&t.path("src/one.txt"), b"one");
    write(&t.path("src/two.txt"), b"");
    write(&t.path("src/three.bin"), &[7u8; 4096]);
    fs::set_permissions(t.path("src/one.txt"), fs::Permissions::from_mode(0o640)).unwrap();
    set_mtime(&t.path("src/one.txt"), 1_700_000_000);
    let sources = [t.s("src/one.txt"), t.s("src/two.txt"), t.s("src/three.bin")];
    let push = |label: &str, engine: bool, sources: &[String], placement: &[&str]| {
        let results = t.s(&format!("{label}.ndjson"));
        let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
        command
            .current_dir(t.path("remote-home"))
            .args([
                "cp",
                "--syq-path",
                env!("CARGO_BIN_EXE_syq"),
                "--no-progress",
                "-v",
                "--results",
                &results,
            ])
            .args(sources)
            .args(["--to", "fake.example"])
            .args(placement)
            .env("XDG_CONFIG_HOME", t.path("config"))
            .env("FAKE_REMOTE_HOME", t.path("remote-home"))
            .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
            .env("FAKE_RSH_LOG", t.path(&format!("{label}.rsh.log")))
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", ssh.parent().unwrap().display()),
            )
            .env("SYQ_DEBUG", "1");
        if engine {
            command.env("SYQ_TEST_DISABLE_SMALL_COPY", "1");
        }
        let output = command.run().unwrap();
        let records: Vec<serde_json::Value> = String::from_utf8(read(Path::new(&results)))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        (output, records)
    };
    // The comparable part of a results stream: operation records as a set,
    // because worker order is not deterministic, and the terminal record
    // without its timing. Periodic progress records are not part of it.
    let comparable = |records: &[serde_json::Value]| {
        let mut operations: Vec<String> = records
            .iter()
            .filter(|record| record["type"] == "operation_result")
            .map(|record| {
                let mut record = record.clone();
                record.as_object_mut().unwrap().remove("seq");
                record.to_string()
            })
            .collect();
        operations.sort();
        let mut terminal = records.last().unwrap().clone();
        if terminal["bytes_transferred"].as_u64().unwrap() > 0 {
            let span = terminal["copying_elapsed_ms"]
                .as_u64()
                .expect("copy timing");
            assert!(span <= terminal["elapsed_ms"].as_u64().unwrap());
        }
        for key in ["seq", "elapsed_ms", "copying_elapsed_ms"] {
            terminal.as_object_mut().unwrap().remove(key);
        }
        assert_eq!(terminal["type"], "result");
        (operations, terminal)
    };
    // The summary line without its elapsed time and rate.
    let summary = |output: &Output| {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let line = stdout
            .lines()
            .find(|line| line.starts_with("syq: transferred"))
            .unwrap_or_else(|| panic!("no summary in {stdout}"));
        let (head, _) = line.rsplit_once(" at ").unwrap();
        head.rsplit_once(", ").unwrap().0.to_string()
    };

    fs::create_dir_all(t.path("dest-fast")).unwrap();
    fs::create_dir_all(t.path("dest-engine")).unwrap();
    let (fast, fast_records) = push("fast", false, &sources, &["--into", &t.s("dest-fast")]);
    let (engine, engine_records) = push("engine", true, &sources, &["--into", &t.s("dest-engine")]);
    assert_output_ok(&fast);
    assert_output_ok(&engine);
    assert!(
        stderr_of(&fast).contains("small copy: published"),
        "{}",
        stderr_of(&fast)
    );
    assert!(
        !stderr_of(&engine).contains("small copy"),
        "{}",
        stderr_of(&engine)
    );
    assert_eq!(
        summary(&fast),
        "syq: transferred 3 files (4.00 KiB), 0 B unchanged (0 files), 0 dirs created"
    );
    assert_eq!(summary(&fast), summary(&engine));
    assert_eq!(comparable(&fast_records), comparable(&engine_records));
    for name in ["one.txt", "two.txt", "three.bin"] {
        let (a, b) = (
            t.path("dest-fast").join(name),
            t.path("dest-engine").join(name),
        );
        assert_eq!(read(&a), read(&t.path("src").join(name)));
        assert_eq!(read(&a), read(&b));
        let (ma, mb) = (fs::metadata(&a).unwrap(), fs::metadata(&b).unwrap());
        assert_eq!(ma.mode() & 0o7777, mb.mode() & 0o7777, "{name}");
        assert_eq!(ma.mtime(), mb.mtime(), "{name}");
    }
    assert_eq!(
        fs::metadata(t.path("dest-fast/one.txt")).unwrap().mtime(),
        1_700_000_000
    );
    let listed: Vec<String> = String::from_utf8_lossy(&fast.stdout)
        .lines()
        .filter(|line| !line.starts_with("syq:"))
        .map(str::to_string)
        .collect();
    assert_eq!(listed, ["one.txt", "two.txt", "three.bin"]);
    // One ssh session carried the whole copy: no route probe, no data worker.
    assert_eq!(
        fs::read_to_string(t.path("fast.rsh.log"))
            .unwrap()
            .lines()
            .count(),
        1
    );

    // Exact placement of one file, in both paths.
    let (exact, exact_records) = push(
        "exact",
        false,
        &sources[..1],
        &["--as", &t.s("dest-fast/renamed.txt")],
    );
    let (exact_engine, exact_engine_records) = push(
        "exact-engine",
        true,
        &sources[..1],
        &["--as", &t.s("dest-engine/renamed.txt")],
    );
    assert_output_ok(&exact);
    assert_output_ok(&exact_engine);
    assert!(stderr_of(&exact).contains("small copy: published"));
    assert_eq!(read(&t.path("dest-fast/renamed.txt")), b"one");
    assert_eq!(summary(&exact), summary(&exact_engine));
    assert_eq!(
        comparable(&exact_records),
        comparable(&exact_engine_records)
    );

    // Changed existing files keep destination permissions by default.
    for dir in ["dest-fast", "dest-engine"] {
        fs::set_permissions(
            t.path(&format!("{dir}/renamed.txt")),
            fs::Permissions::from_mode(0o604),
        )
        .unwrap();
        write(&t.path(&format!("{dir}/renamed.txt")), b"old contents");
    }
    let (fast, _) = push(
        "kept-mode",
        false,
        &sources[..1],
        &["--as", &t.s("dest-fast/renamed.txt")],
    );
    let (engine, _) = push(
        "kept-mode-engine",
        true,
        &sources[..1],
        &["--as", &t.s("dest-engine/renamed.txt")],
    );
    assert_output_ok(&fast);
    assert_output_ok(&engine);
    for dir in ["dest-fast", "dest-engine"] {
        assert_eq!(
            fs::metadata(t.path(&format!("{dir}/renamed.txt")))
                .unwrap()
                .mode()
                & 0o7777,
            0o604
        );
    }
    // Explicit source-mode preservation repairs a quick-checked file in place.
    let (fast, fast_records) = push(
        "repair-mode",
        false,
        &sources[..1],
        &[
            "--as",
            &t.s("dest-fast/renamed.txt"),
            "--preserve=permissions",
        ],
    );
    let (engine, engine_records) = push(
        "repair-mode-engine",
        true,
        &sources[..1],
        &[
            "--as",
            &t.s("dest-engine/renamed.txt"),
            "--preserve=permissions",
        ],
    );
    assert_output_ok(&fast);
    assert_output_ok(&engine);
    assert_eq!(comparable(&fast_records), comparable(&engine_records));
    for dir in ["dest-fast", "dest-engine"] {
        assert_eq!(
            fs::metadata(t.path(&format!("{dir}/renamed.txt")))
                .unwrap()
                .mode()
                & 0o7777,
            0o640
        );
    }

    // Relative exact placement uses the same request-prefix spelling as the
    // receiver. A plain leaf must not cost a declined request and fallback.
    for (label, prefix) in [("relative", ""), ("dot-relative", "./")] {
        let fast_name = format!("{prefix}{label}-fast.txt");
        let engine_name = format!("{prefix}{label}-engine.txt");
        let (fast, fast_records) = push(label, false, &sources[..1], &["--as", &fast_name]);
        let (engine, engine_records) = push(
            &format!("{label}-engine"),
            true,
            &sources[..1],
            &["--as", &engine_name],
        );
        assert_output_ok(&fast);
        assert_output_ok(&engine);
        assert!(
            stderr_of(&fast).contains("small copy: published"),
            "{}",
            stderr_of(&fast)
        );
        assert_eq!(read(&t.path("remote-home").join(&fast_name)), b"one");
        assert_eq!(summary(&fast), summary(&engine));
        assert_eq!(comparable(&fast_records), comparable(&engine_records));
        assert_eq!(
            fs::read_to_string(t.path(&format!("{label}.rsh.log")))
                .unwrap()
                .lines()
                .count(),
            1,
        );
    }

    // A mixed update and quick-check finishes without TCP discovery or
    // additional SSH data sessions, and matches the general engine.
    write(&t.path("dest-fast/one.txt"), b"stale");
    write(&t.path("dest-engine/one.txt"), b"stale");
    let (fast_existing, fast_existing_records) = push(
        "fast-existing",
        false,
        &sources,
        &["--into", &t.s("dest-fast")],
    );
    let (engine_existing, engine_existing_records) = push(
        "engine-existing",
        true,
        &sources,
        &["--into", &t.s("dest-engine")],
    );
    assert_output_ok(&fast_existing);
    assert_output_ok(&engine_existing);
    let declined = stderr_of(&fast_existing);
    assert!(declined.contains("small copy: published"), "{declined}");
    assert!(!declined.contains("TCP route probes started"), "{declined}");
    assert_eq!(
        fs::read_to_string(t.path("fast-existing.rsh.log"))
            .unwrap()
            .lines()
            .count(),
        1
    );
    assert_eq!(summary(&fast_existing), summary(&engine_existing));
    assert_eq!(
        comparable(&fast_existing_records),
        comparable(&engine_existing_records)
    );
    assert_eq!(read(&t.path("dest-fast/one.txt")), b"one");

    for (label, change_mtime, change_mode) in [
        ("unchanged", false, false),
        ("same-content", true, false),
        ("metadata", false, true),
    ] {
        let before = fs::metadata(t.path("dest-fast/one.txt")).unwrap().ino();
        if change_mtime {
            set_mtime(&t.path("src/one.txt"), 1_700_000_100);
        }
        if change_mode {
            fs::set_permissions(t.path("src/one.txt"), fs::Permissions::from_mode(0o600)).unwrap();
        }
        let (fast, fast_records) = push(label, false, &sources, &["--into", &t.s("dest-fast")]);
        let (engine, engine_records) = push(
            &format!("{label}-engine"),
            true,
            &sources,
            &["--into", &t.s("dest-engine")],
        );
        assert_output_ok(&fast);
        assert_output_ok(&engine);
        assert_eq!(summary(&fast), summary(&engine), "{label}");
        assert_eq!(
            comparable(&fast_records),
            comparable(&engine_records),
            "{label}"
        );
        assert_eq!(
            fs::metadata(t.path("dest-fast/one.txt")).unwrap().ino(),
            before
        );
        assert_eq!(
            fs::metadata(t.path("dest-fast/one.txt")).unwrap().mtime(),
            fs::metadata(t.path("dest-engine/one.txt")).unwrap().mtime()
        );
        assert!(stderr_of(&fast).contains("small copy: published"));
        assert!(!stderr_of(&fast).contains("TCP route probes started"));
        assert_eq!(
            fs::read_to_string(t.path(format!("{label}.rsh.log").as_str()))
                .unwrap()
                .lines()
                .count(),
            1
        );
    }

    // A missing directory is the engine's to create after the receiver
    // declines the one-turn request.
    let (missing, _) = push(
        "missing",
        false,
        &sources[..1],
        &["--into", &t.s("dest-fast/new")],
    );
    assert_output_ok(&missing);
    assert!(
        stderr_of(&missing).contains("small copy declined"),
        "{}",
        stderr_of(&missing)
    );
    assert_eq!(read(&t.path("dest-fast/new/one.txt")), b"one");
}

/// The one-turn push refuses, fails, warns, and explains itself exactly as
/// the engine does: the fresh-destination capacity preflight, a staging
/// failure that publishes nothing, a source named like a sidecar, and the
/// -vv route report.
#[test]
fn small_push_refusals_and_failures_match_the_engine() {
    let t = Tmp::new();
    let ssh = fake_ssh(&t);
    write(&t.path("src/one.txt"), b"one");
    write(&t.path("src/two.txt"), b"two");
    write(&t.path("src/three.txt"), b"three");
    let sources = [t.s("src/one.txt"), t.s("src/two.txt"), t.s("src/three.txt")];
    let push = |label: &str,
                engine: bool,
                env: &[(&str, &str)],
                extra: &[&str],
                sources: &[String],
                placement: &[&str]| {
        let results = t.s(&format!("{label}.ndjson"));
        let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
        command
            .args([
                "cp",
                "--syq-path",
                env!("CARGO_BIN_EXE_syq"),
                "--no-progress",
                "--results",
                &results,
            ])
            .args(extra)
            .args(sources)
            .args(["--to", "fake.example"])
            .args(placement)
            .env("XDG_CONFIG_HOME", t.path("config"))
            .env("FAKE_REMOTE_HOME", t.path("remote-home"))
            .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
            .env("FAKE_RSH_LOG", t.path(&format!("{label}.rsh.log")))
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", ssh.parent().unwrap().display()),
            )
            .env("SYQ_DEBUG", "1");
        for (key, value) in env {
            command.env(key, value);
        }
        if engine {
            command.env("SYQ_TEST_DISABLE_SMALL_COPY", "1");
        }
        let output = command.run().unwrap();
        let records: Vec<serde_json::Value> = String::from_utf8(read(Path::new(results.as_str())))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        (output, records)
    };
    // Records compare with the destination directory's own name masked,
    // since a failure message names the path it failed on.
    let comparable = |records: &[serde_json::Value], dir: &str| {
        let mut operations: Vec<String> = records
            .iter()
            .filter(|record| record["type"] == "operation_result")
            .map(|record| {
                let mut record = record.clone();
                record.as_object_mut().unwrap().remove("seq");
                record.to_string().replace(&t.s(dir), "<destination>")
            })
            .collect();
        operations.sort();
        let mut terminal = records.last().unwrap().clone();
        if terminal["bytes_transferred"].as_u64().unwrap() > 0 {
            let span = terminal["copying_elapsed_ms"]
                .as_u64()
                .expect("copy timing");
            assert!(span <= terminal["elapsed_ms"].as_u64().unwrap());
        }
        for key in ["seq", "elapsed_ms", "copying_elapsed_ms"] {
            terminal.as_object_mut().unwrap().remove(key);
        }
        assert_eq!(terminal["type"], "result");
        (operations, terminal)
    };

    // An empty destination directory is fresh, so the capacity preflight
    // applies; with no space reported, both refuse before writing anything.
    for dir in ["cap-fast", "cap-engine"] {
        fs::create_dir_all(t.path(dir)).unwrap();
    }
    let no_space = [("SYQ_TEST_AVAILABLE_BYTES", "0")];
    let (fast, fast_records) = push(
        "cap-fast",
        false,
        &no_space,
        &[],
        &sources,
        &["--into", &t.s("cap-fast")],
    );
    let (engine, engine_records) = push(
        "cap-engine",
        true,
        &no_space,
        &[],
        &sources,
        &["--into", &t.s("cap-engine")],
    );
    assert_eq!(fast.status.code(), Some(1));
    assert_eq!(engine.status.code(), Some(1));
    for output in [&fast, &engine] {
        assert!(
            stderr_of(output).contains("fresh destination capacity preflight failed"),
            "{}",
            stderr_of(output)
        );
    }
    assert!(
        stderr_of(&fast).contains("capacity preflight would refuse"),
        "{}",
        stderr_of(&fast)
    );
    assert_eq!(
        comparable(&fast_records, "cap-fast"),
        comparable(&engine_records, "cap-engine")
    );
    for dir in ["cap-fast", "cap-engine"] {
        assert!(fs::read_dir(t.path(dir)).unwrap().next().is_none(), "{dir}");
    }

    // A staging failure publishes no final files; the engine then reports
    // the same failure, keeps its partial, and publishes the rest.
    for dir in ["stage-fast", "stage-engine"] {
        fs::create_dir_all(t.path(dir)).unwrap();
    }
    let injected = [("SYQ_TEST_FAIL_PUT_SMALL_BEFORE_RENAME", "/two.txt")];
    let (fast, fast_records) = push(
        "stage-fast",
        false,
        &injected,
        &[],
        &sources,
        &["--into", &t.s("stage-fast")],
    );
    let (engine, engine_records) = push(
        "stage-engine",
        true,
        &injected,
        &[],
        &sources,
        &["--into", &t.s("stage-engine")],
    );
    assert!(
        stderr_of(&fast).contains("staging failed"),
        "{}",
        stderr_of(&fast)
    );
    assert_eq!(fast.status.code(), Some(23));
    assert_eq!(engine.status.code(), Some(23));
    assert_eq!(
        comparable(&fast_records, "stage-fast"),
        comparable(&engine_records, "stage-engine")
    );
    for dir in ["stage-fast", "stage-engine"] {
        assert_eq!(read(&t.path(dir).join("one.txt")), b"one", "{dir}");
        assert_eq!(read(&t.path(dir).join("three.txt")), b"three", "{dir}");
        assert!(!t.path(dir).join("two.txt").exists(), "{dir}");
        assert_eq!(partial_files(&t.path(dir)).len(), 1, "{dir}");
    }

    // A source named like a sidecar reaches the engine, which warns.
    let sidecar = partial_files(&t.path("stage-engine")).pop().unwrap();
    fs::create_dir_all(t.path("side")).unwrap();
    let (side, _) = push(
        "side",
        false,
        &[],
        &[],
        &[sidecar.to_string_lossy().into_owned()],
        &["--into", &t.s("side")],
    );
    assert_output_ok(&side);
    assert!(
        !stderr_of(&side).contains("small copy: sending"),
        "{}",
        stderr_of(&side)
    );
    assert!(
        stderr_of(&side).contains("recognizable SYQ partial path"),
        "{}",
        stderr_of(&side)
    );

    // Retry without the staging fault: the fallback engine must complete
    // the remaining file, preserving the candidate and prior successes.
    for dir in ["stage-fast", "stage-engine"] {
        let (retried, records) = push(
            &format!("{dir}-retry"),
            false,
            &[],
            &[],
            &sources,
            &["--into", &t.s(dir)],
        );
        assert_output_ok(&retried);
        assert_eq!(records.last().unwrap()["status"], "success");
        for (name, data) in [
            ("one.txt", b"one".as_slice()),
            ("two.txt", b"two"),
            ("three.txt", b"three"),
        ] {
            assert_eq!(read(&t.path(dir).join(name)), data, "{dir}/{name}");
        }
        assert_eq!(partial_files(&t.path(dir)).len(), 1, "{dir}");
    }

    // -vv explains the helper and the route.
    fs::create_dir_all(t.path("verbose")).unwrap();
    let (verbose, _) = push(
        "verbose",
        false,
        &[],
        &["-vv"],
        &sources,
        &["--into", &t.s("verbose")],
    );
    assert_output_ok(&verbose);
    let report = stderr_of(&verbose);
    assert!(report.contains("small copy: published"), "{report}");
    for line in [
        "  helper: ",
        "  transport: control connection",
        "syq: concurrency: no data connections",
    ] {
        assert!(report.contains(line), "{line} missing from:\n{report}");
    }
}

#[test]
fn files_from_repeats_and_late_listed_dirs_across_chunks() {
    let t = Tmp::new();
    write(&t.path("src/d/inner"), b"i");
    write(&t.path("src/d/sub/deep"), b"x");
    let mut list = String::from("d/inner\n");
    for i in 0..1200 {
        write(&t.path(&format!("src/many/f{i}")), b"f");
        list.push_str(&format!("many/f{i}\n"));
    }
    // After the 1000-entry boundary: repeat a path, and list `d` (so far only
    // an implied parent) explicitly so -r walks it.
    list.push_str("d/inner\nd\n");
    write(&t.path("list"), list.as_bytes());
    let so = run_ok(&[
        "-a",
        "-r",
        "--files-from",
        &t.s("list"),
        &t.s("src"),
        &t.s("dst"),
    ]);
    assert_eq!(transferred(&so), 1202);
    assert!(t.path("dst/d/sub/deep").is_file());
    assert!(t.path("dst/many/f1199").is_file());
}

#[cfg(all(debug_assertions, target_os = "linux"))]
#[test]
fn copy_local_exdev_auto_fallback_restores_parallel_workers() {
    let t = Tmp::new();
    let contents = vec![b'x'; 8 * 1024 * 1024];
    write(&t.path("src"), &contents);

    let out = compat_command()
        .args(["-a", "--stats", "--no-progress", &t.s("src"), &t.s("dst")])
        .env("SYQ_TEST_COPY_LOCAL_EXDEV", "1")
        .env("SYQ_TEST_COPY_LOCAL_SOURCE_NFS", "1")
        .run()
        .unwrap();
    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), contents);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(&format!(
            "connections: auto: settled at {0} (path {0}, peak {0})",
            expected_local_start()
        )),
        "{stdout}"
    );
}

#[cfg(all(debug_assertions, target_os = "linux"))]
#[test]
fn copy_local_disk_exdev_uses_parallel_whole_file_workers() {
    for connections in [None, Some("2")] {
        let t = Tmp::new();
        for index in 0..4 {
            write(&t.path(&format!("src/file{index}")), &prng(5 << 20, index));
        }
        write(&t.path("src/small"), b"small file batch");
        let mut command = compat_command();
        command.args(["-a", "--no-progress", &t.s("src/"), &t.s("dst/")]);
        if let Some(connections) = connections {
            command.args(["--performance-tuning", &format!("workers={connections}")]);
        }
        let out = command
            .env("SYQ_DEBUG", "1")
            .env("SYQ_TEST_COPY_LOCAL_EXDEV", "1")
            .env("SYQ_TEST_COPY_LOCAL_FS", "local")
            .run()
            .unwrap();
        assert_output_ok(&out);
        assert_same_tree(&t.path("src"), &t.path("dst"));
        let observed = tuning_observed(&out);
        assert_eq!(observed["local_whole_files"], 4);
        assert_eq!(observed["range_requests"], 0);
        assert!(observed["small_batches"].as_u64().unwrap() > 0);
        assert!(partial_files(&t.0).is_empty());
    }
}

#[cfg(all(debug_assertions, target_os = "linux"))]
#[test]
fn copy_local_disk_single_file_retains_parallel_ranges() {
    for connections in [None, Some("2")] {
        let t = Tmp::new();
        let contents = prng(8 << 20, 458);
        write(&t.path("src"), &contents);
        let mut command = compat_command();
        command.args(["-a", "--stats", "--no-progress", &t.s("src"), &t.s("dst")]);
        if let Some(connections) = connections {
            command.args(["--performance-tuning", &format!("workers={connections}")]);
        }
        let out = command
            .env("SYQ_DEBUG", "1")
            .env("SYQ_TEST_COPY_LOCAL_EXDEV", "1")
            .env("SYQ_TEST_COPY_LOCAL_FS", "local")
            .run()
            .unwrap();
        assert_output_ok(&out);
        assert_eq!(read(&t.path("dst")), contents);
        let observed = tuning_observed(&out);
        assert_eq!(observed["local_whole_files"], 0);
        assert!(observed["range_requests"].as_u64().unwrap() > 0);
        if connections.is_none() {
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(
                stdout.contains(&format!(
                    "connections: auto: settled at {0} (path {0}, peak {0})",
                    expected_local_start()
                )),
                "{stdout}"
            );
        }
    }
}

#[cfg(all(debug_assertions, target_os = "linux"))]
#[test]
fn copy_local_nfs_exdev_keeps_automatic_parallel_cases() {
    let cases: &[(&[&str], Option<&str>)] = &[
        (&[], Some("SYQ_TEST_COPY_LOCAL_SOURCE_NFS")),
        (&[], Some("SYQ_TEST_COPY_LOCAL_NFS_SYNC")),
        (&["--performance-tuning", "workers=2"], None),
    ];
    for (extra_args, extra_env) in cases {
        let t = Tmp::new();
        let contents = vec![b'x'; 8 * 1024 * 1024];
        write(&t.path("src"), &contents);
        let src = t.s("src");
        let dst = t.s("dst");
        let mut command = compat_command();
        command
            .args(["-a", "--no-progress"])
            .args(*extra_args)
            .args([&src, &dst])
            .env("SYQ_TEST_COPY_LOCAL_EXDEV", "1")
            .env("SYQ_TEST_COPY_LOCAL_NFS", "1")
            .env("SYQ_TEST_COPY_LOCAL_SOURCE_DISK", "1")
            .env("SYQ_TEST_FAIL_READ_RANGE", "1");
        if let Some(name) = extra_env {
            command.env(name, "1");
        }
        let out = command.run().unwrap();
        assert!(!out.status.success(), "case unexpectedly used one writer");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("test read-range failure"),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[cfg(all(debug_assertions, target_os = "linux"))]
#[test]
fn local_read_ahead_shrink_keeps_old_destination() {
    {
        let t = Tmp::new();
        write(&t.path("source"), &prng(17 << 20, 919));
        write(&t.path("destination"), b"old destination");
        let ready = t.path("ready");
        let resume = t.path("continue");
        let mut child = compat_command()
            .args(["-a", "--no-progress", &t.s("source"), &t.s("destination")])
            .env("SYQ_TEST_LOCAL_READ_AHEAD", "1")
            .env("SYQ_TEST_COPY_LOCAL_FS", "local")
            .env("SYQ_TEST_OVERLAP_READY", &ready)
            .env("SYQ_TEST_OVERLAP_CONTINUE", &resume)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .start()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !ready.exists() && std::time::Instant::now() < deadline {
            assert!(child.try_wait().unwrap().is_none());
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(
            ready.exists(),
            "overlap copy did not reach its first-block barrier"
        );
        File::create(t.path("source")).unwrap();
        write(&resume, b"continue");
        let out = child.wait_with_output().unwrap();
        assert!(!out.status.success(), "{out:?}");
        assert_eq!(read(&t.path("destination")), b"old destination");
        let changed = prng(17 << 20, 920);
        write(&t.path("source"), &changed);
        let out = compat_command()
            .args([
                "-a",
                "--no-progress",
                "--performance-tuning=copy-path=ranges",
                &t.s("source"),
                &t.s("destination"),
            ])
            .run()
            .unwrap();
        assert_output_ok(&out);
        assert_eq!(read(&t.path("destination")), changed);
    }
}

fn history_command(t: &Tmp) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
    command.env("SYQ_TUNING_CACHE", t.path("legacy.json"));
    command.env("SYQ_TUNING_HISTORY", t.path("history.sqlite"));
    command
}

#[test]
fn tuning_history_records_short_copy_and_exports_interactive_timeline() {
    let t = Tmp::new();
    for n in 0..32 {
        write(
            &t.path(&format!("private-source/secret-{n}")),
            &prng(8192, n),
        );
    }
    let output = history_command(&t)
        .args([
            "cp",
            "--srcs-in",
            &t.s("private-source"),
            "--into",
            &t.s("private-destination"),
            "--no-progress",
        ])
        .run()
        .unwrap();
    assert_output_ok(&output);
    let output = history_command(&t)
        .args(["tuning-cache", "export"])
        .run()
        .unwrap();
    assert_output_ok(&output);
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(!text.contains("private-source"));
    assert!(!text.contains("secret-"));
    assert!(!text.contains("private-destination"));
    let records: Vec<serde_json::Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(records[0]["run"]["status"], "success");
    assert!(records[0]["run"]["selected_workers"].is_null());
    assert!(records
        .iter()
        .any(|r| r["event"]["data"]["disposition"] == "final_partial"));
    assert!(records
        .iter()
        .any(|r| r["event"]["kind"] == "workers_start"));
    assert_eq!(
        fs::metadata(t.path("history.sqlite")).unwrap().mode() & 0o777,
        0o600
    );
    let id = records[0]["run"]["id"].as_i64().unwrap().to_string();
    let html = history_command(&t)
        .args(["tuning-cache", "show", &id, "--html"])
        .run()
        .unwrap();
    assert_output_ok(&html);
    let html = String::from_utf8(html.stdout).unwrap();
    assert!(html.contains("<svg"));
    assert!(html.contains("final_partial"));
    assert!(!html.contains("__HISTORY_DATA__"));
    let cleared = history_command(&t)
        .args(["tuning-cache", "clear"])
        .run()
        .unwrap();
    assert_output_ok(&cleared);
    let empty = history_command(&t)
        .args(["tuning-cache", "export"])
        .run()
        .unwrap();
    assert_output_ok(&empty);
    assert!(empty.stdout.is_empty());
}

#[test]
fn tuning_history_records_failed_copy_without_recommending_it() {
    let t = Tmp::new();
    let output = history_command(&t)
        .args([
            "cp",
            &t.s("missing"),
            "--as",
            &t.s("destination"),
            "--no-progress",
        ])
        .run()
        .unwrap();
    assert!(!output.status.success());
    let output = history_command(&t)
        .args(["tuning-cache", "export"])
        .run()
        .unwrap();
    assert_output_ok(&output);
    let text = String::from_utf8(output.stdout).unwrap();
    let record: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
    assert_eq!(record["run"]["status"], "failed");
    assert!(record["run"]["selected_workers"].is_null());
}

#[test]
fn disabling_tuning_cache_also_disables_history() {
    let t = Tmp::new();
    write(&t.path("source"), b"copy without persistence");
    let output = history_command(&t)
        .env("SYQ_TUNING_CACHE", "")
        .args([
            "cp",
            &t.s("source"),
            "--as",
            &t.s("destination"),
            "--no-progress",
        ])
        .run()
        .unwrap();
    assert_output_ok(&output);
    assert!(!t.path("history.sqlite").exists());
    assert!(!t.path("legacy.json").exists());
}

#[test]
fn tuning_history_uses_filesystem_hint_and_honors_explicit_controls() {
    let t = Tmp::new();
    for n in 0..32 {
        write(&t.path(&format!("source/file-{n}")), &prng(8192, n));
    }
    let copy = |name: &str, controls: &[&str]| {
        history_command(&t)
            .args([
                "cp",
                "--srcs-in",
                &t.s("source"),
                "--into",
                &t.s(name),
                "--no-progress",
            ])
            .args(controls)
            .run()
            .unwrap()
    };
    assert_output_ok(&copy("first", &[]));
    // Supply an old measured result; the transfer itself is deliberately short.
    let db = rusqlite::Connection::open(t.path("history.sqlite")).unwrap();
    let startup_doubling = |run: i64| {
        db.query_row(
            "SELECT json_extract(data,'$.data.policy.startup_doubling') FROM events WHERE run=?1 AND json_extract(data,'$.kind')='policy_start'",
            [run],
            |row| row.get::<_, bool>(0),
        ).unwrap()
    };
    assert!(startup_doubling(1));
    let fs: Option<String> = db
        .query_row("SELECT source_fs FROM runs LIMIT 1", [], |row| row.get(0))
        .unwrap();
    assert!(fs.is_some(), "test filesystem did not provide an identity");
    db.execute("UPDATE runs SET eligible=1,workers=3", [])
        .unwrap();
    assert_output_ok(&copy("second", &[]));
    assert!(!startup_doubling(2));
    let event: String = db
        .query_row(
            "SELECT data FROM events WHERE run=2 AND json_extract(data,'$.kind')='starting_count'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let event: serde_json::Value = serde_json::from_str(&event).unwrap();
    assert_eq!(event["data"]["workers"], 3);
    assert_eq!(event["data"]["hint"]["matched"], "filesystems");
    assert_output_ok(&copy("capped", &["--resource-limits", "workers=2"]));
    assert!(!startup_doubling(3));
    let event: String = db
        .query_row(
            "SELECT data FROM events WHERE run=3 AND json_extract(data,'$.kind')='starting_count'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let event: serde_json::Value = serde_json::from_str(&event).unwrap();
    assert_eq!(event["data"]["workers"], 2);
    assert_output_ok(&copy("fixed", &["--performance-tuning", "workers=1"]));
    let event: String = db
        .query_row(
            "SELECT data FROM events WHERE run=4 AND json_extract(data,'$.kind')='starting_count'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let event: serde_json::Value = serde_json::from_str(&event).unwrap();
    assert_eq!(event["data"]["workers"], 1);
    assert_eq!(event["data"]["reason"], "explicit");
}

use super::*;

#[test]
fn verbose_copy_escapes_peer_filename_control_characters() {
    let t = Tmp::new();
    let name = "file\x1b]52;c;ZXZpbA==\x07\nline\r";
    write(&t.path(&format!("src/{name}")), b"payload");
    let out = syq(&["-av", &t.s("src/"), &t.s("dst/")]);
    assert_output_ok(&out);
    assert_eq!(read(&t.path(&format!("dst/{name}"))), b"payload");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains('\x1b'));
    assert!(!stdout.contains('\x07'));
    assert!(stdout.contains("\\nline\\r"), "{stdout}");
}

#[test]
fn janky_cat_concatenates_files_and_stdin() {
    let t = Tmp::new();
    // Cross several bursts, including a short final one, without changing bytes.
    let first: Vec<u8> = (0..=255).cycle().take(1300).collect();
    write(&t.path("first"), &first);
    write(&t.path("last"), b"\nlast");

    let mut child = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["cat", &t.s("first"), "-", &t.s("last")])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .start()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"middle").unwrap();
    let output = child.wait_with_output().unwrap();

    assert_output_ok(&output);
    assert_eq!(output.stdout, [first.as_slice(), b"middle\nlast"].concat());
}

#[test]
fn janky_cat_reports_missing_inputs_and_keeps_going() {
    let t = Tmp::new();
    write(&t.path("present"), b"still here");

    let output = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["cat", &t.s("missing"), &t.s("present")])
        .run()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout, b"still here");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(&t.s("missing")),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn janky_cat_is_slow_and_absent_from_help() {
    let t = Tmp::new();
    write(&t.path("one-byte"), b"x");

    let started = std::time::Instant::now();
    let output = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["cat", &t.s("one-byte")])
        .run()
        .unwrap();
    let elapsed = started.elapsed();

    assert_output_ok(&output);
    assert_eq!(output.stdout, b"x");
    assert!(
        elapsed >= std::time::Duration::from_millis(60),
        "cat finished suspiciously quickly in {elapsed:?}"
    );

    let help = Command::new(env!("CARGO_BIN_EXE_syq"))
        .arg("--help")
        .run()
        .unwrap();
    assert_output_ok(&help);
    assert!(
        !String::from_utf8_lossy(&help.stdout).contains("\n  cat"),
        "{}",
        String::from_utf8_lossy(&help.stdout)
    );
}

#[test]
fn remote_helper_integrity_mismatch_warns_and_uploads_verified_binary() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    setup_release_bootstrap(&t);
    let mut corrupt = read(&t.path("release.gz"));
    let middle = corrupt.len() / 2;
    corrupt[middle] ^= 1;
    write(&t.path("corrupt-release.gz"), &corrupt);
    let corrupt_digest = sha256_hex(&corrupt);

    write(&t.path("src"), b"integrity fallback");
    let remote = format!("fake:{}", t.s("dst"));
    let mut cmd = remote_syq_command(&t, &rsh, &["-a", "-q", &t.s("src"), &remote]);
    let out = cmd
        .env("FAKE_REMOTE_RELEASE_ARCHIVE", t.path("corrupt-release.gz"))
        .run()
        .unwrap();

    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), b"integrity fallback");
    assert_eq!(
        read(&t.path("remote-home/.local/bin/syq")),
        read(&cached_remote_helper(&t))
    );
    assert_eq!(
        read(&cached_remote_helper(&t)),
        read(Path::new(env!("CARGO_BIN_EXE_syq")))
    );
    assert_eq!(
        read(&cached_local_helper(&t)),
        read(Path::new(env!("CARGO_BIN_EXE_syq")))
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("installed syq"),
        "quiet hides optional installation notices"
    );
    assert!(
        stderr.contains("remote helper download failed integrity verification"),
        "{stderr}"
    );
    assert!(stderr.contains("expected SHA-256"), "{stderr}");
    assert!(stderr.contains(&corrupt_digest), "{stderr}");
    assert!(
        stderr.contains("uploading the verified helper over SSH"),
        "{stderr}"
    );
    assert!(!stderr.contains("checksum mismatch"), "{stderr}");
    assert_eq!(read(&t.path("curl.log")), b"fetch\nfetch\n");
    let cache_entries: Vec<_> = fs::read_dir(cached_remote_helper(&t).parent().unwrap())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(cache_entries, ["syq"]);
}

#[test]
fn helper_install_and_upload_fallback_survive_broken_stderr() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    setup_release_bootstrap(&t);
    executable(&t.path("remote-bin/curl"), b"#!/bin/sh\nexit 22\n");
    write(
        &t.path("src"),
        b"helper installed despite missing diagnostics",
    );
    let remote = format!("fake:{}", t.s("dst"));
    let (reader, writer) = std::os::unix::net::UnixStream::pair().unwrap();
    drop(reader);
    let output = remote_syq_command(&t, &rsh, &["-a", &t.s("src"), &remote])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::from(std::os::fd::OwnedFd::from(writer)))
        .start()
        .unwrap()
        .wait_with_output()
        .unwrap();
    assert_output_ok(&output);
    assert_eq!(read(&t.path("dst")), read(&t.path("src")));
    assert_eq!(
        read(&cached_remote_helper(&t)),
        read(Path::new(env!("CARGO_BIN_EXE_syq")))
    );
}

#[test]
fn double_verbose_dry_run_reports_tcp_without_extra_connection() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    write(&t.path("src"), b"diagnose");
    let remote = format!("127.0.0.1:{}", t.s("dst"));

    let out = compat_command()
        .arg("-e")
        .arg(&rsh)
        .arg("--rsync-path")
        .arg(env!("CARGO_BIN_EXE_syq"))
        .args(["--syq-tcp-ports", EPHEMERAL_TCP_PORTS])
        .args(["--dry-run", "-vv", "-a"])
        .arg(t.s("src"))
        .arg(&remote)
        .arg("--no-progress")
        .env("FAKE_REMOTE_HOME", t.path("remote-home"))
        .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
        .env("FAKE_RSH_LOG", t.path("rsh.log"))
        .env("XDG_CONFIG_HOME", t.path("config"))
        .env("XDG_CACHE_HOME", t.path("cache"))
        .run()
        .expect("run double-verbose dry-run over TCP");

    assert_output_ok(&out);
    assert!(!t.path("dst").exists());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(&format!(
            "control: connected via fake-rsh; remote {}-",
            std::env::consts::OS
        )),
        "{stderr}"
    );
    assert!(
        stderr.contains(&format!(
            "helper: {} (--rsync-path)",
            binary_identity("--build-identity")
        )),
        "{stderr}"
    );
    assert!(
        stderr.contains("TCP ") && stderr.contains(": reachable"),
        "{stderr}"
    );
    assert!(
        stderr.contains(
            "transport: encrypted TCP planned for a real transfer (reachability preflight passed)"
        ),
        "{stderr}"
    );
    assert!(
        stderr.contains(
            "a real transfer would start with 16 connections (auto-tuned); dry-run starts no workers"
        ),
        "{stderr}"
    );
    assert_eq!(
        fs::read_to_string(t.path("rsh.log"))
            .unwrap()
            .lines()
            .count(),
        1,
        "-vv must not add a remote-shell connection during dry-run"
    );
}

#[test]
fn double_verbose_dry_run_reports_ssh_fallback_without_extra_connection() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    executable(
        &t.path("remote-bin/ip"),
        b"#!/bin/sh\nprintf invoked > \"$FAKE_IP_LOG\"\nprintf '2: eth9 inet 192.0.2.1/24 scope global eth9\\n'\n",
    );
    write(&t.path("src"), b"fallback");
    let remote = format!("diagnostic.invalid:{}", t.s("dst"));

    let out = compat_command()
        .arg("-e")
        .arg(&rsh)
        .arg("--rsync-path")
        .arg(env!("CARGO_BIN_EXE_syq"))
        .args(["--syq-tcp-ports", EPHEMERAL_TCP_PORTS])
        .args(["--dry-run", "-vv", "-a"])
        .arg(t.s("src"))
        .arg(&remote)
        .arg("--no-progress")
        .env("FAKE_REMOTE_HOME", t.path("remote-home"))
        .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
        .env("FAKE_RSH_LOG", t.path("rsh.log"))
        .env("FAKE_IP_LOG", t.path("ip.log"))
        .env("FAKE_SSH_CONNECTION", "192.0.2.2 40000 192.0.2.1 22")
        .env("SYQ_TEST_NO_INTERFACE_ADDRESSES", "1")
        .env("XDG_CONFIG_HOME", t.path("config"))
        .run()
        .expect("run double-verbose dry-run with TCP fallback");

    assert_output_ok(&out);
    assert!(!t.path("dst").exists());
    assert_eq!(
        t.path("ip.log").exists(),
        cfg!(target_os = "linux"),
        "only Linux receivers may spawn the iproute2 probe"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("TCP 192.0.2.1:") && stderr.contains("not reachable"),
        "{stderr}"
    );
    assert!(
        stderr.contains("transport: SSH planned for a real transfer (TCP unavailable:"),
        "{stderr}"
    );
    assert!(
        stderr.contains("target 8 connections (auto-tuned); dry-run starts no workers"),
        "{stderr}"
    );
    assert_eq!(
        fs::read_to_string(t.path("rsh.log"))
            .unwrap()
            .lines()
            .count(),
        1,
        "-vv must not verify fallback with an extra connection"
    );
}

#[test]
fn double_verbose_dry_run_reports_ipv6_arrival_address_as_reachable() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    // Suppress discovery so this specifically exercises the IPv6 SSH arrival
    // address. It must be listened on and selected.
    executable(&t.path("remote-bin/ip"), b"#!/bin/sh\nexit 1\n");
    write(&t.path("src"), b"v6");
    let remote = format!("diagnostic.invalid:{}", t.s("dst"));

    let out = compat_command()
        .arg("-e")
        .arg(&rsh)
        .arg("--rsync-path")
        .arg(env!("CARGO_BIN_EXE_syq"))
        .args(["--syq-tcp-ports", EPHEMERAL_TCP_PORTS])
        .args(["--dry-run", "-vv", "-a"])
        .arg(t.s("src"))
        .arg(&remote)
        .arg("--no-progress")
        .env("FAKE_REMOTE_HOME", t.path("remote-home"))
        .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
        .env("FAKE_RSH_LOG", t.path("rsh.log"))
        .env("FAKE_SSH_CONNECTION", "::1 40000 ::1 22")
        .env("SYQ_TEST_NO_INTERFACE_ADDRESSES", "1")
        .env("XDG_CONFIG_HOME", t.path("config"))
        .run()
        .expect("run double-verbose dry-run over IPv6");

    assert_output_ok(&out);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("TCP [::1]:")
            && stderr.contains(": reachable, link speed unknown, selected by preflight"),
        "{stderr}"
    );
    assert!(
        stderr.contains(
            "transport: encrypted TCP planned for a real transfer (reachability preflight passed)"
        ),
        "{stderr}"
    );
}

#[test]
fn single_verbose_keeps_file_listing_semantics() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    write(&t.path("src"), b"listed");
    let remote = format!("fake:{}", t.s("dst"));

    let out = compat_command()
        .arg("-e")
        .arg(&rsh)
        .arg("--rsync-path")
        .arg(env!("CARGO_BIN_EXE_syq"))
        .args([
            "--syq-no-tcp",
            "-v",
            "-a",
            "--performance-tuning",
            "workers=1",
        ])
        .arg(t.s("src"))
        .arg(&remote)
        .arg("--no-progress")
        .env("FAKE_REMOTE_HOME", t.path("remote-home"))
        .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
        .env("FAKE_RSH_LOG", t.path("rsh.log"))
        .env("XDG_CONFIG_HOME", t.path("config"))
        .run()
        .expect("run single-verbose remote copy");

    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), b"listed");
    assert!(String::from_utf8_lossy(&out.stdout).contains("src"));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("  control:"), "{stderr}");
    assert!(!stderr.contains("syq: concurrency:"), "{stderr}");
}

#[test]
fn progress_bar_slow_copy_stays_on_one_line_and_leaves_final_counts() {
    let t = Tmp::new();
    let data = prng(2 * 1024 * 1024, 451);
    write(&t.path("src"), &data);
    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "cp",
            &t.s("src"),
            "--as",
            &t.s("dst"),
            "--progress",
            "--performance-tuning",
            "workers=4",
            "--resource-limits",
            "bandwidth=1M",
        ])
        .run()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert_eq!(read(&t.path("dst")), data);
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("100%  done  2.00 MiB/2.00 MiB"),
        "{stderr:?}"
    );
    assert_eq!(
        stderr.matches('\n').count(),
        1,
        "only final frame ends a line: {stderr:?}"
    );
    assert!(
        !stderr
            .replace("\x1b[K", "")
            .replace("\x1b[2K", "")
            .contains("\x1b"),
        "no screen clearing or cursor-up: {stderr:?}"
    );
    assert!(
        stderr
            .split('\r')
            .filter(|frame| frame.starts_with('['))
            .count()
            > 2,
        "{stderr:?}"
    );
}

#[test]
fn progress_bar_is_opt_in_for_pipes_and_disabled_by_no_progress() {
    let t = Tmp::new();
    write(&t.path("src"), b"payload");
    for (dst, flags) in [
        ("default", vec![]),
        ("disabled", vec!["--progress", "--no-progress"]),
        ("quiet", vec!["--progress", "--quiet"]),
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_syq"))
            .args(["cp", &t.s("src"), "--as", &t.s(dst)])
            .args(flags)
            .run()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        assert!(out.stderr.is_empty(), "{dst}: {out:?}");
    }
}

#[test]
fn dry_run_reports_typed_preflight_summary() {
    let t = Tmp::new();
    write(&t.path("src/send"), b"new");
    write(&t.path("src/same"), b"same");
    write(&t.path("src/too-big"), b"123456");
    write(&t.path("src/skip.log"), b"ignored");
    write(&t.path("dst/same"), b"same");
    write(&t.path("dst/extra"), b"delete me");
    set_mtime(&t.path("src/same"), 1_600_000_000);
    set_mtime(&t.path("dst/same"), 1_600_000_000);
    set_mtime(&t.path("src"), 1_600_000_100);
    set_mtime(&t.path("dst"), 1_600_000_100);

    let out = run_ok(&[
        "-an",
        "--delete",
        "--max-size",
        "5",
        "--syq-ignore",
        "*.log",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert!(out.contains("syq: dry-run summary"), "{out}");
    assert!(
        out.contains(&format!(
            "mapping: {} -> {} (directory contents)",
            t.s("src/"),
            t.s("dst")
        )),
        "{out}"
    );
    assert!(out.contains("changes: 1 regular file"), "{out}");
    assert!(
        out.contains(
            "logical data: 3 B in 1 file needing content work (upper bound); 4 B in 1 file with unchanged content"
        ),
        "{out}"
    );
    assert!(
        out.contains("exclusions: 1 path/subtree skipped by ignore rules; 1 other entry"),
        "{out}"
    );
    assert!(
        out.contains("deletions: 1 entry planned after a successful copy"),
        "{out}"
    );
    assert!(
        out.contains(&format!(
            "route: local filesystem; {} initial workers (auto-tuned)",
            expected_local_start()
        )),
        "{out}"
    );
    assert!(t.path("dst/extra").exists());
}

#[test]
fn dry_run_summary_resolves_path_semantics() {
    let t = Tmp::new();
    write(&t.path("src/file"), b"data");

    let child = run_ok(&["-an", &t.s("src"), &t.s("child-target")]);
    assert!(
        child.contains(&format!(
            "mapping: {} -> {} (directory as child)",
            t.s("src"),
            t.s("child-target/src")
        )),
        "{child}"
    );

    let contents = run_ok(&["-an", &t.s("src/"), &t.s("contents-target/")]);
    assert!(
        contents.contains(&format!(
            "mapping: {} -> {} (directory contents)",
            t.s("src/"),
            t.s("contents-target")
        )),
        "{contents}"
    );

    let exact = run_ok(&["-an", &t.s("src/file"), &t.s("exact-target")]);
    assert!(
        exact.contains(&format!(
            "mapping: {} -> {} (exact destination path)",
            t.s("src/file"),
            t.s("exact-target")
        )),
        "{exact}"
    );
}

/// A native push of a few small local files into a remote directory travels
/// as one control-connection request. Its destination state, summary, and
/// results records must match the ordinary engine's for the same copy, and
/// anything the one-turn path declines must reach the engine unchanged.
#[test]
fn small_push_mtime_precision_matches_stats_dry_run_and_hash() {
    for (source_seconds, source_nsec, destination_nsec, same_size, matches) in [
        (10, 123_456_789, 120_000_000, true, true),
        (10, 123_456_789, 123_456_700, true, true),
        (10, 123_456_789, 0, true, true),
        (10, 130_000_000, 120_000_000, true, false),
        (10, 120_000_000, 123_456_789, true, false),
        (11, 123_456_789, 120_000_000, true, false),
        (10, 123_456_789, 120_000_000, false, false),
    ] {
        for option in [None, Some("--stats"), Some("--dry-run"), Some("--hash")] {
            let t = Tmp::new();
            let ssh = fake_ssh(&t);
            write(&t.path("source"), b"new");
            let old: &[u8] = if same_size { b"old" } else { b"older" };
            write(&t.path("remote-home/dest/source"), old);
            for (path, seconds, nanos) in [
                ("source", source_seconds, source_nsec),
                ("remote-home/dest/source", 10, destination_nsec),
            ] {
                File::open(t.path(path))
                    .unwrap()
                    .set_times(fs::FileTimes::new().set_modified(
                        std::time::UNIX_EPOCH + std::time::Duration::new(seconds, nanos),
                    ))
                    .unwrap();
            }
            let before = fs::metadata(t.path("remote-home/dest/source")).unwrap();
            let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
            command
                .args([
                    "cp",
                    "--syq-path",
                    env!("CARGO_BIN_EXE_syq"),
                    "--no-progress",
                    "--results",
                    &t.s("results.ndjson"),
                    &t.s("source"),
                    "--to",
                    "fake.example",
                    "--into",
                    &t.s("remote-home/dest"),
                ])
                .env("FAKE_REMOTE_HOME", t.path("remote-home"))
                .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
                .env("FAKE_RSH_LOG", t.path("rsh.log"))
                .env(
                    "PATH",
                    format!("{}:/usr/bin:/bin", ssh.parent().unwrap().display()),
                )
                .env("SYQ_DEBUG", "1");
            if let Some(option) = option {
                command.arg(option);
            }
            let output = command.run().unwrap();
            assert_output_ok(&output);
            assert_eq!(
                stderr_of(&output).contains("small copy: published"),
                option.is_none(),
                "wrong dispatch for {option:?}: {}",
                stderr_of(&output)
            );
            let skipped = matches && option != Some("--hash");
            let unchanged = skipped || option == Some("--dry-run");
            assert_eq!(read(&t.path("remote-home/dest/source")), if unchanged { old } else { b"new" },
                "option={option:?}, source={source_seconds}.{source_nsec:09}, destination=10.{destination_nsec:09}");
            if unchanged {
                let after = fs::metadata(t.path("remote-home/dest/source")).unwrap();
                assert_eq!(after.ino(), before.ino());
                assert_eq!(
                    (after.mtime(), after.mtime_nsec()),
                    (before.mtime(), before.mtime_nsec())
                );
            }
            let records = fs::read_to_string(t.path("results.ndjson")).unwrap();
            let result: serde_json::Value =
                serde_json::from_str(records.lines().last().unwrap()).unwrap();
            assert_eq!(result["status"], "success");
            assert_eq!(result["files_unchanged"], u64::from(skipped), "{records}");
            assert_eq!(
                result["bytes_transferred"],
                if skipped { 0 } else { 3 },
                "{records}"
            );
        }
    }
}

#[test]
fn quiet_suppresses_notices_but_not_errors() {
    let t = Tmp::new();
    fs::create_dir(t.path("src")).unwrap();

    let notice = syq(&["-q", &t.s("src"), &t.s("dst")]);
    assert_output_ok(&notice);
    assert!(
        notice.stdout.is_empty(),
        "{}",
        String::from_utf8_lossy(&notice.stdout)
    );
    assert!(
        notice.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&notice.stderr)
    );

    let error = syq(&["-q", &t.s("missing"), &t.s("dst")]);
    assert!(!error.status.success());
    assert!(
        error.stdout.is_empty(),
        "{}",
        String::from_utf8_lossy(&error.stdout)
    );
    assert!(
        !error.stderr.is_empty(),
        "quiet mode must still report errors"
    );
}

#[test]
fn stats_report_connection_tuning_mode() {
    let t = Tmp::new();
    std::fs::create_dir_all(t.path("src")).unwrap();
    for i in 0..20 {
        std::fs::write(t.path(&format!("src/f{i}")), vec![b'x'; 1000]).unwrap();
    }
    // A tiny all-small-file job needs only one batch worker. Auto statistics
    // report that settled count; fixed statistics continue to report the
    // caller's configured ceiling.
    let out = run_ok(&["-a", "--stats", &t.s("src/"), &t.s("auto/")]);
    assert!(
        out.contains("connections: auto: settled at 1 (path 1, peak 1)"),
        "{out}"
    );
    let out = run_ok(&[
        "-a",
        "--stats",
        "--performance-tuning",
        "workers=3",
        &t.s("src/"),
        &t.s("fixed/"),
    ]);
    assert!(out.contains("connections: 3\n"), "{out}");
}

#[test]
fn initial_ssh_failure_is_reported_once_with_debug_diagnostics() {
    let t = Tmp::new();
    let ssh = t.path("bin/ssh");
    executable(
        &ssh,
        br#"#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_RSH_LOG"
printf 'ssh: test control socket could not be created\n' >&2
exit 255
"#,
    );
    write(&t.path("source"), b"payload");
    let output = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["cp", "--no-bootstrap"])
        .arg(t.path("source"))
        .args(["--to", "fake.example", "--into", "."])
        .env(
            "PATH",
            format!("{}:/usr/bin:/bin", ssh.parent().unwrap().display()),
        )
        .env("XDG_CONFIG_HOME", t.path("config"))
        .env("FAKE_RSH_LOG", t.path("rsh.log"))
        .env("SYQ_DEBUG", "1")
        .run()
        .unwrap();
    assert!(!output.status.success());
    let log = fs::read_to_string(t.path("rsh.log")).unwrap();
    assert_eq!(log.lines().count(), 1, "{log}");
    assert!(log.split_whitespace().any(|arg| arg == "-v"), "{log}");
    let diagnostic = stderr_of(&output);
    assert!(
        diagnostic.contains("ssh: test control socket could not be created"),
        "{diagnostic}"
    );
    assert!(diagnostic.contains("exit status: 255"), "{diagnostic}");
    assert!(!diagnostic.contains("attempt"), "{diagnostic}");
}

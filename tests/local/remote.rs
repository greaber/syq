use super::*;

#[cfg(debug_assertions)]
fn confinement_remote_command(t: &Tmp, tcp: bool) -> Command {
    let rsh = fake_rsh(t);
    t.expose_remote_syq();

    let mut command = compat_command();
    command
        .arg("-e")
        .arg(rsh)
        .args(["--syq-no-bootstrap", "--performance-tuning", "workers=1"])
        .env("FAKE_REMOTE_HOME", t.path("remote-home"))
        .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
        .env("FAKE_RSH_LOG", t.path("rsh.log"))
        .env("XDG_CONFIG_HOME", t.path("config"))
        .env("XDG_CACHE_HOME", t.path("cache"));
    if tcp {
        command.env("SYQ_TEST_REQUIRE_TCP", "1");
    } else {
        command.arg("--syq-no-tcp");
    }
    command
}

#[test]
fn source_fd_preflight_accounts_for_independent_ssh_broker_claims() {
    let t = Tmp::new();
    let ssh = fake_ssh(&t);
    t.expose_remote_syq();
    write(&t.path("source"), &vec![b'x'; 8 * 1024 * 1024]);
    let remote = format!("fake:{}", t.s("source"));
    let mut command = compat_command();
    command
        .arg("-e")
        .arg(&ssh)
        .args([
            "--syq-no-bootstrap",
            "--syq-no-tcp",
            "--performance-tuning=workers=64",
            "--no-progress",
            &remote,
            &t.s("destination"),
        ])
        .env("FAKE_REMOTE_HOME", t.path("remote-home"))
        .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
        .env("FAKE_RSH_LOG", t.path("rsh.log"))
        .env("XDG_CONFIG_HOME", t.path("config"))
        .env("SYQ_TUNING_CACHE", "");
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
    assert!(stderr.contains("32 independent workers"), "{stderr}");
    assert!(
        !t.path("destination").exists(),
        "independent-claim FD admission failed after destination creation"
    );
}

#[cfg(debug_assertions)]
#[test]
fn confinement_matrix_remote_source_root_is_pinned_for_tcp_and_ssh() {
    for tcp in [true, false] {
        let t = Tmp::new();
        write(&t.path("src/original"), b"original");
        write(&t.path("outside/replacement"), b"replacement");
        let ready = t.path("source-ready");
        let continuation = t.path("source-continue");
        let source = format!("127.0.0.1:{}/", t.s("src"));

        let mut child = confinement_remote_command(&t, tcp)
            .arg("-a")
            .arg(&source)
            .arg(t.s("dst/"))
            .arg("--no-progress")
            .env("SYQ_TEST_SOURCE_ROOTS_REGISTERED_FILE", &ready)
            .env("SYQ_TEST_SOURCE_ROOTS_CONTINUE_FILE", &continuation)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .start()
            .unwrap();
        wait_for_confinement_marker(&mut child, &ready, "remote source registration");

        fs::rename(t.path("src"), t.path("selected-and-moved")).unwrap();
        std::os::unix::fs::symlink(t.path("outside"), t.path("src")).unwrap();
        release_confinement_barrier(&continuation);

        let output = child.wait_with_output().unwrap();
        assert_output_ok(&output);
        assert_eq!(read(&t.path("dst/original")), b"original", "tcp={tcp}");
        assert!(!t.path("dst/replacement").exists(), "tcp={tcp}");
    }
}

#[cfg(debug_assertions)]
#[test]
fn confinement_matrix_remote_exact_source_replacement_is_rejected_for_tcp_and_ssh() {
    for tcp in [true, false] {
        let t = Tmp::new();
        write(&t.path("selected"), b"original");
        let ready = t.path("source-ready");
        let continuation = t.path("source-continue");
        let source = format!("127.0.0.1:{}", t.s("selected"));

        let mut child = confinement_remote_command(&t, tcp)
            .arg("-a")
            .arg(&source)
            .arg(t.s("destination"))
            .arg("--no-progress")
            .env("SYQ_TEST_SOURCE_ROOTS_REGISTERED_FILE", &ready)
            .env("SYQ_TEST_SOURCE_ROOTS_CONTINUE_FILE", &continuation)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .start()
            .unwrap();
        wait_for_confinement_marker(&mut child, &ready, "remote exact-source registration");

        fs::rename(t.path("selected"), t.path("selected-original")).unwrap();
        write(&t.path("selected"), b"replacement");
        release_confinement_barrier(&continuation);

        let output = child.wait_with_output().unwrap();
        assert!(!output.status.success(), "tcp={tcp}: {output:?}");
        assert!(
            stderr_of(&output).contains("registered source leaf changed identity"),
            "tcp={tcp}: {}",
            stderr_of(&output)
        );
        assert!(!t.path("destination").exists(), "tcp={tcp}");
    }
}

#[cfg(debug_assertions)]
#[test]
fn confinement_matrix_remote_destination_root_is_pinned_for_tcp_and_ssh() {
    for tcp in [true, false] {
        let t = Tmp::new();
        write(&t.path("src/file"), b"payload");
        fs::create_dir_all(t.path("dst")).unwrap();
        fs::create_dir_all(t.path("outside")).unwrap();
        let ready = t.path("destination-ready");
        let continuation = t.path("destination-continue");
        let destination = format!("127.0.0.1:{}/", t.s("dst"));

        let mut child = confinement_remote_command(&t, tcp)
            .arg("-a")
            .arg(t.s("src/"))
            .arg(&destination)
            .arg("--no-progress")
            .env("SYQ_TEST_DESTINATION_ANCHORED_FILE", &ready)
            .env("SYQ_TEST_DESTINATION_ANCHOR_CONTINUE_FILE", &continuation)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .start()
            .unwrap();
        wait_for_confinement_marker(&mut child, &ready, "remote destination anchoring");

        fs::rename(t.path("dst"), t.path("selected-and-moved")).unwrap();
        std::os::unix::fs::symlink(t.path("outside"), t.path("dst")).unwrap();
        release_confinement_barrier(&continuation);

        let output = child.wait_with_output().unwrap();
        assert_output_ok(&output);
        assert_eq!(
            read(&t.path("selected-and-moved/file")),
            b"payload",
            "tcp={tcp}"
        );
        assert!(!t.path("outside/file").exists(), "tcp={tcp}");
    }
}

#[cfg(debug_assertions)]
#[test]
fn confinement_matrix_remote_destination_parent_swap_is_confined_for_tcp_and_ssh() {
    for tcp in [true, false] {
        let t = Tmp::new();
        write(&t.path("src/victim/file"), &vec![b'x'; 8 * 1024 * 1024]);
        fs::create_dir_all(t.path("dst/victim")).unwrap();
        write(&t.path("outside/sentinel"), b"outside");
        let ready = t.path("partial-ready");
        let continuation = t.path("partial-continue");
        let destination = format!("127.0.0.1:{}/", t.s("dst"));

        let mut child = confinement_remote_command(&t, tcp)
            .args(["-a", "--resource-limits", "bandwidth=1G"])
            .arg(t.s("src/"))
            .arg(&destination)
            .arg("--no-progress")
            .env("SYQ_TEST_PARTIAL_READY_FILE", &ready)
            .env("SYQ_TEST_PARTIAL_CONTINUE_FILE", &continuation)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .start()
            .unwrap();
        wait_for_confinement_marker(&mut child, &ready, "remote sidecar preparation");
        assert_eq!(
            partial_files(&t.path("dst/victim")).len(),
            1,
            "tcp={tcp}: sidecar missing at acknowledged preparation barrier"
        );

        fs::rename(t.path("dst/victim"), t.path("displaced-victim")).unwrap();
        std::os::unix::fs::symlink(t.path("outside"), t.path("dst/victim")).unwrap();
        release_confinement_barrier(&continuation);

        let output = child.wait_with_output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(23),
            "tcp={tcp}: {}",
            stderr_of(&output)
        );
        assert_eq!(read(&t.path("outside/sentinel")), b"outside");
        assert!(!t.path("outside/file").exists(), "tcp={tcp}");
        assert!(!t.path("displaced-victim/file").exists(), "tcp={tcp}");
        assert_eq!(partial_files(&t.path("displaced-victim")).len(), 1);
    }
}

#[cfg(debug_assertions)]
#[test]
fn confinement_matrix_tcp_requirement_refuses_ssh_transport() {
    let t = Tmp::new();
    write(&t.path("src"), b"payload");
    let destination = format!("127.0.0.1:{}", t.s("dst"));

    let output = confinement_remote_command(&t, false)
        .env("SYQ_TEST_REQUIRE_TCP", "1")
        .arg("-a")
        .arg(t.s("src"))
        .arg(destination)
        .arg("--no-progress")
        .run()
        .unwrap();

    assert!(!output.status.success(), "{output:?}");
    assert!(
        stderr_of(&output).contains("TCP data transport required by test"),
        "{}",
        stderr_of(&output)
    );
    assert!(!t.path("dst").exists());
}

#[test]
fn native_copy_uses_explicit_endpoints_cwd_and_attached_option_like_selectors() {
    let t = Tmp::new();
    write(&t.path("base/foo"), b"cwd");
    write(&t.path("base/--into"), b"option-looking");
    write(&t.path("base/host:path"), b"colon-local");

    run_native_ok(&[
        "cp",
        "--cwd",
        &t.s("base"),
        "--src",
        "foo",
        "--src=--into",
        "host:path",
        "--into",
        &t.s("dst"),
    ]);
    assert_eq!(read(&t.path("dst/foo")), b"cwd");
    assert_eq!(read(&t.path("dst/--into")), b"option-looking");
    assert_eq!(read(&t.path("dst/host:path")), b"colon-local");

    let split = native_syq(&[
        "cp",
        "--from",
        "host:/mistaken/path",
        "foo",
        "--into",
        &t.s("never"),
    ]);
    assert!(!split.status.success());
    assert!(String::from_utf8_lossy(&split.stderr).contains("pass paths separately"));
    assert!(!t.path("never").exists());

    let no_basename = native_syq(&["cp", "..", "--into", &t.s("no-basename")]);
    assert!(!no_basename.status.success());
    assert!(String::from_utf8_lossy(&no_basename.stderr).contains("no target basename"));
    assert!(!t.path("no-basename").exists());
}

#[cfg(debug_assertions)]
#[test]
fn native_remote_destination_socket_policy_uses_handshake_capability() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    write(&t.path("src/nested/ordinary"), b"ordinary");
    let _source_socket =
        std::os::unix::net::UnixListener::bind(t.path("src/nested/socket")).unwrap();

    let command = |platform: &str, socket_capability: &str, destination: &str| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
        command
            .args(["cp", "--rsh"])
            .arg(&rsh)
            .args(["--syq-path", env!("CARGO_BIN_EXE_syq")])
            .args([
                "--no-tcp",
                "--performance-tuning",
                "workers=1",
                "--preserve=specials",
            ])
            .args(["--srcs-in", &t.s("src"), "--to", "fake", "--into"])
            .arg(t.path(destination))
            .arg("--no-progress")
            .env("FAKE_REMOTE_HOME", t.path("remote-home"))
            .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
            .env("FAKE_RSH_LOG", t.path("rsh.log"))
            .env("FAKE_REMOTE_PLATFORM", platform)
            .env("FAKE_REMOTE_CONFINED_SOCKET_NODES", socket_capability);
        command
    };

    // A Linux coordinator must honor a macOS receiver's inability to create
    // confined socket nodes. The warning is a fidelity diagnostic and remains
    // visible even when ordinary output is quiet.
    let mut macos_destination = command("macos-aarch64", "0", "dst-macos");
    let output = macos_destination.arg("--quiet").run().unwrap();
    assert_output_ok(&output);
    assert_eq!(read(&t.path("dst-macos/nested/ordinary")), b"ordinary");
    assert!(!t.path("dst-macos/nested/socket").exists());
    let stderr = stderr_of(&output);
    assert!(stderr.contains("skipping socket"), "{stderr}");
    assert!(stderr.contains("confined destination"), "{stderr}");

    // A macOS coordinator must not suppress a socket headed to a capable
    // Linux receiver. Dry-run proves the receiver operation is planned without
    // asking a macOS test host to execute Linux's mknodat behavior.
    let mut linux_destination = command("linux-x86_64", "1", "dst-linux");
    let output = linux_destination
        .args(["--dry-run", "--verbose"])
        .run()
        .unwrap();
    assert_output_ok(&output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("create socket"), "{stdout}");
    assert!(!stderr_of(&output).contains("skipping socket"));
    assert!(!t.path("dst-linux").exists());
}

#[test]
fn native_rejects_unknown_relay_option() {
    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["cp", "--relay", "source", "--into", "target"])
        .run()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("unexpected argument"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn add_remote_tool(t: &Tmp, name: &str) {
    let destination = t.path(&format!("remote-bin/{name}"));
    if destination.exists() {
        return;
    }
    let source = [
        Path::new("/usr/bin").join(name),
        Path::new("/bin").join(name),
    ]
    .into_iter()
    .find(|path| path.exists())
    .unwrap_or_else(|| panic!("test host has no {name}"));
    std::os::unix::fs::symlink(source, destination).unwrap();
}

#[test]
fn failed_remote_download_falls_back_to_verified_upload() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    let script = fs::read_to_string(&rsh).unwrap();
    executable(
        &rsh,
        script
            .replace("#!/bin/sh\n", "#!/bin/sh\numask 027\n")
            .as_bytes(),
    );
    setup_release_bootstrap(&t);
    executable(
        &t.path("remote-bin/curl"),
        br#"#!/bin/sh
printf 'fetch\n' >> "$FAKE_CURL_LOG"
exit 22
"#,
    );

    write(&t.path("src"), b"download fallback");
    let remote = format!("fake:{}", t.s("dst"));
    let out = remote_syq(&t, &rsh, &["-a", &t.s("src"), &remote]);

    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), b"download fallback");
    for directory in ["remote-home/.local", "remote-home/.local/bin"] {
        assert_eq!(
            fs::metadata(t.path(directory)).unwrap().mode() & 0o777,
            0o750
        );
    }
    assert_eq!(
        fs::metadata(cached_remote_helper(&t)).unwrap().mode() & 0o777,
        0o700
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("remote download unavailable"), "{stderr}");
    assert!(
        stderr.contains("uploading the verified helper over SSH"),
        "{stderr}"
    );
    assert!(!stderr.contains("warning:"), "{stderr}");
    assert_eq!(read(&t.path("curl.log")), b"fetch\n");
}

#[test]
fn missing_remote_hasher_skips_download_and_uploads_verified_binary() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    setup_release_bootstrap(&t);
    for tool in ["sh", "uname", "mkdir", "rm", "cat", "chmod", "mv", "gzip"] {
        add_remote_tool(&t, tool);
    }

    write(&t.path("src"), b"capability fallback");
    let remote = format!("fake:{}", t.s("dst"));
    let mut cmd = remote_syq_command(&t, &rsh, &["-a", &t.s("src"), &remote]);
    let out = cmd
        .env("FAKE_REMOTE_PATH", t.path("remote-bin"))
        .run()
        .unwrap();

    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), b"capability fallback");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("remote download prerequisites unavailable"),
        "{stderr}"
    );
    assert!(
        stderr.contains("uploading the verified helper over SSH"),
        "{stderr}"
    );
    assert!(!t.path("curl.log").exists());
}

#[test]
fn broken_remote_hasher_falls_back_to_verified_upload() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    setup_release_bootstrap(&t);
    executable(
        &t.path("remote-bin/sha256sum"),
        br#"#!/bin/sh
exit 1
"#,
    );

    write(&t.path("src"), b"hasher fallback");
    let remote = format!("fake:{}", t.s("dst"));
    let out = remote_syq(&t, &rsh, &["-a", &t.s("src"), &remote]);

    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), b"hasher fallback");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("remote helper hashing with sha256sum failed"),
        "{stderr}"
    );
    assert!(
        stderr.contains("uploading the verified helper over SSH"),
        "{stderr}"
    );
    assert_eq!(read(&t.path("curl.log")), b"fetch\nfetch\n");
}

#[test]
fn remote_download_write_failure_does_not_retry_with_upload() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    setup_release_bootstrap(&t);
    executable(
        &t.path("remote-bin/curl"),
        br#"#!/bin/sh
printf 'fetch\n' >> "$FAKE_CURL_LOG"
exit 23
"#,
    );

    write(&t.path("src"), b"must fail");
    let remote = format!("fake:{}", t.s("dst"));
    let out = remote_syq(&t, &rsh, &["-a", &t.s("src"), &remote]);

    assert!(
        !out.status.success(),
        "remote write failure unexpectedly succeeded"
    );
    assert!(!t.path("dst").exists());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("remote helper download could not write its temporary file"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("uploading the verified helper"),
        "{stderr}"
    );
    assert_eq!(read(&t.path("curl.log")), b"fetch\n");
    assert!(!cached_local_helper(&t).exists());
}

#[test]
fn rsync_subcommand_wrapper_can_start_the_remote_server() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    let wrapper = t.path("syq-rsync");
    executable(
        &wrapper,
        format!(
            "#!/bin/sh\nexec '{}' rsync \"$@\"\n",
            env!("CARGO_BIN_EXE_syq")
        )
        .as_bytes(),
    );

    write(&t.path("src"), b"compatibility wrapper");
    let remote = format!("fake:{}", t.s("dst"));
    let out = remote_syq_command(
        &t,
        &rsh,
        &[
            "-a",
            "--rsync-path",
            wrapper.to_str().unwrap(),
            &t.s("src"),
            &remote,
        ],
    )
    .run()
    .expect("run through an rsync-prefixed remote wrapper");

    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), b"compatibility wrapper");
}

#[test]
fn remote_retained_basis_handles_matching_and_changed_files() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    t.expose_remote_syq();
    let original = vec![b'a'; 5 * 1024 * 1024];
    let mut changed = original.clone();
    changed[2 * 1024 * 1024] = b'b';
    write(&t.path("src"), &original);
    write(&t.path("dst"), &original);
    set_mtime(&t.path("src"), 1_600_000_001);
    set_mtime(&t.path("dst"), 1_600_000_000);
    let inode = fs::metadata(t.path("dst")).unwrap().ino();
    let remote = format!("fake:{}", t.s("dst"));

    let matching = remote_syq(
        &t,
        &rsh,
        &["-ac", "--syq-no-bootstrap", &t.s("src"), &remote],
    );
    assert_output_ok(&matching);
    assert_eq!(fs::metadata(t.path("dst")).unwrap().ino(), inode);

    write(&t.path("src"), &changed);
    set_mtime(&t.path("src"), 1_600_000_002);
    let repair = remote_syq(
        &t,
        &rsh,
        &["-a", "--syq-no-bootstrap", &t.s("src"), &remote],
    );
    assert_output_ok(&repair);
    assert_eq!(read(&t.path("dst")), changed);
    assert!(partial_files(&t.0).is_empty());
}

#[test]
fn tcp_copy_auto_tuning_starts_with_sixteen_connections() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    write(&t.path("src"), b"tcp default");
    let remote = format!("127.0.0.1:{}", t.s("dst"));

    let dry = compat_command()
        .arg("-e")
        .arg(&rsh)
        .arg("--rsync-path")
        .arg(env!("CARGO_BIN_EXE_syq"))
        .args(["--syq-tcp-ports", EPHEMERAL_TCP_PORTS])
        .args(["--dry-run", "-a"])
        .arg(t.s("src"))
        .arg(&remote)
        .arg("--no-progress")
        .env("FAKE_REMOTE_HOME", t.path("remote-home"))
        .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
        .env("FAKE_RSH_LOG", t.path("rsh.log"))
        .env("XDG_CONFIG_HOME", t.path("config"))
        .run()
        .expect("dry-run syq over encrypted TCP through fake remote shell");
    assert_output_ok(&dry);
    assert!(!t.path("dst").exists());
    let stdout = String::from_utf8_lossy(&dry.stdout);
    assert!(
        stdout.contains("route: encrypted TCP to 127.0.0.1; 16 initial connections (auto-tuned)"),
        "{stdout}"
    );

    let out = compat_command()
        .arg("-e")
        .arg(&rsh)
        .arg("--rsync-path")
        .arg(env!("CARGO_BIN_EXE_syq"))
        .args(["--syq-tcp-ports", EPHEMERAL_TCP_PORTS])
        .args(["--syq-tcp-plain", "--stats", "-avv"])
        .arg(t.s("src"))
        .arg(&remote)
        .arg("--no-progress")
        .env("FAKE_REMOTE_HOME", t.path("remote-home"))
        .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
        .env("FAKE_RSH_LOG", t.path("rsh.log"))
        .env("XDG_CONFIG_HOME", t.path("config"))
        .env("XDG_CACHE_HOME", t.path("cache"))
        .run()
        .expect("run syq over TCP through fake remote shell");

    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), b"tcp default");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("connections: auto: settled at 16 (path 16, peak 16)"),
        "{stdout}"
    );
    assert!(
        stdout.contains("tcp retransmissions (loss signal):"),
        "{stdout}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("transport: plaintext TCP planned (reachability preflight passed)"),
        "{stderr}"
    );
    assert!(
        stderr.contains("concurrency: starting with 16 connections (auto-tuned)"),
        "{stderr}"
    );
}

#[test]
fn inplace_copy_to_missing_remote_destination_waits_for_planned_work() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    write(&t.path("src"), b"in-place over reachable TCP");
    let remote = format!("127.0.0.1:{}", t.s("dst"));

    let out = compat_command()
        .arg("-e")
        .arg(&rsh)
        .arg("--rsync-path")
        .arg(env!("CARGO_BIN_EXE_syq"))
        .args(["--syq-tcp-ports", EPHEMERAL_TCP_PORTS])
        .args([
            "--syq-tcp-plain",
            "--inplace",
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
        .env("XDG_CACHE_HOME", t.path("cache"))
        .run()
        .expect("run in-place copy over reachable TCP");

    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), b"in-place over reachable TCP");
}

#[test]
fn automatic_ssh_starts_only_workers_that_can_help_the_file() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    let content = prng(64 << 20, 3241);
    write(&t.path("src"), &content);
    for (label, fixed, nonempty, single_file) in [
        ("auto", false, false, false),
        ("fixed", true, false, false),
        ("nonempty", false, true, false),
        ("single", false, false, true),
        ("single-fixed", true, false, true),
        ("single-update", false, true, true),
    ] {
        let directory = t.path(&format!("dst-{label}"));
        fs::create_dir_all(&directory).unwrap();
        if nonempty {
            write(&directory.join("src"), b"old destination contents");
        }
        let destination = if single_file {
            format!("host:{}/src", directory.display())
        } else {
            format!("host:{}/", directory.display())
        };
        let events = t.path(&format!("events-{label}"));
        let mut command = compat_command();
        command
            .arg("-e")
            .arg(&rsh)
            .arg("--rsync-path")
            .arg(env!("CARGO_BIN_EXE_syq"))
            .args(["--syq-no-tcp", "-a", "-vv", "--no-progress"])
            .arg(t.s("src"))
            .arg(destination)
            .env("SYQ_TEST_WORKER_EVENTS", &events)
            .env("XDG_CONFIG_HOME", t.path("config"))
            .env("XDG_CACHE_HOME", t.path(label));
        if fixed {
            command.args(["--performance-tuning", "workers=8"]);
        }
        let out = command.run().unwrap();
        assert_output_ok(&out);
        assert_eq!(
            stderr_of(&out).contains("SSH startup limited to 2 workers"),
            !fixed && !nonempty,
            "{label}: {out:?}"
        );
        assert!(!stderr_of(&out).contains("initial count limited by available work"));
        assert_eq!(read(&directory.join("src")), content);
        let connected = fs::read_to_string(events)
            .unwrap()
            .lines()
            .filter(|line| line.starts_with("connected "))
            .count();
        assert_eq!(
            connected,
            if fixed || nonempty { 8 } else { 2 },
            "{label}: {out:?}"
        );
    }
}

#[cfg(debug_assertions)]
#[test]
fn automatic_ssh_restores_workers_for_a_single_file_partial() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    let content = prng(64 << 20, 3242);
    write(&t.path("src"), &content);
    fs::create_dir_all(t.path("dest")).unwrap();
    let destination = format!("host:{}/file", t.path("dest").display());
    let source = t.s("src");
    let args = [
        "-e",
        rsh.to_str().unwrap(),
        "--rsync-path",
        env!("CARGO_BIN_EXE_syq"),
        "--syq-no-tcp",
        "-a",
        "-vv",
        source.as_str(),
        destination.as_str(),
    ];
    let failed = compat_command()
        .args(args)
        .env("SYQ_TEST_FAIL_READ_RANGE", "1")
        .env("XDG_CONFIG_HOME", t.path("config"))
        .env("XDG_CACHE_HOME", t.path("failed-cache"))
        .run()
        .unwrap();
    assert_eq!(failed.status.code(), Some(23), "{failed:?}");
    assert!(!t.path("dest/file").exists());
    let partials = partial_files(&t.path("dest"));
    assert_eq!(partials.len(), 1, "{failed:?}");
    let partial = partials[0].clone();
    // Eight disjoint missing blocks: size-based startup alone would leave
    // only two workers, even though every missing block is independent work.
    let mut resumed = content.clone();
    for block in (0..16).step_by(2) {
        resumed[block * (4 << 20)..(block + 1) * (4 << 20)].fill(0);
    }
    write(&partial, &resumed);
    write(&t.path("tuning.json"), br#"{"paths":{"local>host|ssh":8}}"#);
    let events = t.path("events");
    let out = compat_command()
        .args(args)
        .arg("--no-progress")
        .env("SYQ_TEST_WORKER_EVENTS", &events)
        .env("SYQ_TUNING_CACHE", t.path("tuning.json"))
        // Match the unscoped legacy cache fixture regardless of the host network.
        .env("SYQ_TEST_TUNING_NETWORK", "")
        .env("XDG_CONFIG_HOME", t.path("config"))
        .env("XDG_CACHE_HOME", t.path("cache"))
        .run()
        .unwrap();
    assert_output_ok(&out);
    assert!(stderr_of(&out).contains("starting with 8 connections remembered for this path"));
    assert_eq!(read(&t.path("dest/file")), content);
    assert!(partial.exists());
    let connected = fs::read_to_string(events)
        .unwrap()
        .lines()
        .filter(|line| line.starts_with("connected "))
        .count();
    assert_eq!(connected, 8, "{out:?}");
    assert!(stderr_of(&out).contains("SSH startup limited to 2 workers"));
}

#[cfg(target_os = "linux")]
#[test]
fn tcp_congestion_override_is_applied_on_both_socket_ends_and_reported() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    write(&t.path("src"), b"per-socket congestion control");
    let remote = format!("127.0.0.1:{}", t.s("dst"));

    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .arg("rsync")
        .arg("-e")
        .arg(&rsh)
        .arg("--rsync-path")
        .arg(env!("CARGO_BIN_EXE_syq"))
        .args(["--syq-tcp-ports", EPHEMERAL_TCP_PORTS])
        .args([
            "--syq-tcp-plain",
            "--syq-tcp-congestion=reno",
            "--stats",
            "-avv",
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
        .expect("run syq with a per-socket TCP congestion override");

    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), b"per-socket congestion control");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("tcp congestion control: reno (2 socket ends)"),
        "{stdout}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr
            .contains("congestion control: remote listener reno; local data sockets request reno"),
        "{stderr}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn rejected_tcp_congestion_override_is_fatal_instead_of_falling_back() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    write(&t.path("src"), b"must not silently fall back");
    let remote = format!("127.0.0.1:{}", t.s("dst"));

    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .arg("rsync")
        .arg("-e")
        .arg(&rsh)
        .arg("--rsync-path")
        .arg(env!("CARGO_BIN_EXE_syq"))
        .args(["--syq-tcp-ports", EPHEMERAL_TCP_PORTS])
        .args([
            "--syq-tcp-congestion=syq_missing_cc",
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
        .expect("run syq with an unavailable TCP congestion override");

    assert!(!out.status.success());
    assert!(!t.path("dst").exists());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("could not apply --syq-tcp-congestion syq_missing_cc"),
        "{stderr}"
    );
    assert!(stderr.contains("kernel rejected"), "{stderr}");
    assert!(
        stderr.contains("tcp_allowed_congestion_control"),
        "{stderr}"
    );
    assert!(!stderr.contains("data over ssh"), "{stderr}");
}

#[cfg(target_os = "linux")]
#[test]
fn ordinary_tcp_setup_failure_still_falls_back_with_congestion_notice() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    write(&t.path("src"), b"fallback remains available");
    let remote = format!("127.0.0.1:{}", t.s("dst"));
    let held_port = std::net::TcpListener::bind(("0.0.0.0", 0)).unwrap();
    let port = held_port.local_addr().unwrap().port();

    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .arg("rsync")
        .arg("-e")
        .arg(&rsh)
        .arg("--rsync-path")
        .arg(env!("CARGO_BIN_EXE_syq"))
        .args([
            "--syq-tcp-congestion=reno",
            &format!("--syq-tcp-ports={port}-{port}"),
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
        .expect("run syq when the requested direct TCP port is occupied");

    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), b"fallback remains available");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("data over ssh"), "{stderr}");
    assert!(
        stderr.contains("requested congestion control reno is not used by the SSH fallback"),
        "{stderr}"
    );
}

#[cfg(debug_assertions)]
#[test]
fn dropped_write_connection_is_reopened_and_uncertain_range_is_retried() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    t.expose_remote_syq();
    let data: Vec<u8> = (0..2 * 1024 * 1024)
        .map(|offset| (offset % 251) as u8)
        .collect();
    write(&t.path("src"), &data);
    let remote = format!("fake:{}", t.s("dst"));
    let marker = t.path("drop-write-once");

    let out = remote_syq_command(
        &t,
        &rsh,
        &[
            "-a",
            "--syq-no-bootstrap",
            "--block-size=64K",
            &t.s("src"),
            &remote,
        ],
    )
    .env("SYQ_TEST_DROP_AFTER_REQUEST", "write")
    .env("SYQ_TEST_DROP_MARKER", &marker)
    .run()
    .unwrap();

    assert_output_ok(&out);
    assert!(marker.exists());
    assert_eq!(read(&t.path("dst")), data);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("connection dropped; reopening"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[cfg(debug_assertions)]
#[test]
fn lost_finalize_response_is_verified_after_reconnect() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    t.expose_remote_syq();
    let data = vec![b'z'; 2 * 1024 * 1024];
    write(&t.path("src"), &data);
    let remote = format!("fake:{}", t.s("dst"));
    let marker = t.path("drop-finalize-once");

    let out = remote_syq_command(
        &t,
        &rsh,
        &[
            "-a",
            "--syq-no-bootstrap",
            "--block-size=64K",
            &t.s("src"),
            &remote,
        ],
    )
    .env("SYQ_TEST_DROP_AFTER_REQUEST", "finalize")
    .env("SYQ_TEST_DROP_MARKER", &marker)
    .run()
    .unwrap();

    assert_output_ok(&out);
    assert!(marker.exists());
    assert_eq!(read(&t.path("dst")), data);
    assert!(partial_files(&t.0).is_empty());
}

#[test]
fn hash_errors_do_not_desynchronize_worker_connections() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }

    let t = Tmp::new();
    write(&t.path("src/bad"), &vec![b'b'; 8192]);
    write(&t.path("src/good"), &vec![b'g'; 4096]);
    write(&t.path("dst/bad"), &vec![b'x'; 8192]);
    write(&t.path("dst/good"), &vec![b'x'; 4096]);
    fs::set_permissions(t.path("src/bad"), fs::Permissions::from_mode(0o000)).unwrap();

    // Largest-first scheduling makes the unreadable file fail first. The
    // receiver still answers its already-issued hash request; that response
    // must be drained before this worker proceeds to `good`.
    let copy = syq(&[
        "-a",
        "-c",
        "--performance-tuning",
        "workers=1",
        &t.s("src/"),
        &t.s("dst/"),
    ]);
    assert_eq!(copy.status.code(), Some(23));
    let copy_stderr = String::from_utf8_lossy(&copy.stderr);
    assert!(
        !copy_stderr.contains("unexpected response"),
        "{copy_stderr}"
    );
    assert_eq!(read(&t.path("dst/good")), vec![b'g'; 4096]);
}

#[test]
fn auto_streaming_preserves_shortcuts_and_streams_remote_large_files() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    for (name, size) in [("large", (17 << 20) + 123), ("small", 777), ("empty", 0)] {
        write(&t.path(&format!("source/{name}")), &prng(size, 943));
    }
    for route in ["local", "push", "pull"] {
        for mode in ["auto", "auto-streaming"] {
            let destination = t.s(&format!("dst-{route}-{mode}"));
            let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
            command.args([
                "cp",
                "--rsh",
                rsh.to_str().unwrap(),
                "--syq-path",
                env!("CARGO_BIN_EXE_syq"),
                "--performance-tuning",
                "workers=2",
                "--no-progress",
                "--no-tcp",
                "--stats",
                "--preserve=permissions",
                "-v",
                "--performance-tuning",
                &format!("copy-path={mode},request-size=1M"),
            ]);
            if route == "pull" {
                command.args(["--from", "host"]);
            }
            command.args(["--srcs-in", &t.s("source")]);
            if route == "push" {
                command.args(["--to", "host"]);
            }
            let out = command
                .args(["--into", &destination])
                .env("FAKE_REMOTE_HOME", t.path("remote-home"))
                .env("XDG_CONFIG_HOME", t.path("config"))
                .env("XDG_CACHE_HOME", t.path("cache"))
                .run()
                .unwrap();
            assert_output_ok(&out);
            assert_same_tree(&t.path("source"), Path::new(&destination));
            let observed = tuning_observed(&out);
            assert!(
                observed["small_batches"].as_u64().unwrap() > 0,
                "{route}/{mode}: {out:?}"
            );
            if mode == "auto" && route == "local" {
                assert_eq!(observed["streaming_ranges"], 0);
            } else {
                if mode == "auto-streaming" {
                    assert_eq!(observed["range_requests"], 0);
                }
                if route != "local" {
                    assert!(
                        observed["streaming_ranges"].as_u64().unwrap() > 0,
                        "{out:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn automatic_streaming_needs_no_tuning_flags_and_keeps_short_remote_ranges() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    for (label, size) in [("short", 16 << 20), ("long", (20 << 20) + 123)] {
        write(&t.path(label), &prng(size, 947));
        for route in ["local", "push", "pull"] {
            let destination = t.s(&format!("dst-{label}-{route}"));
            let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
            command.args([
                "cp",
                "--rsh",
                rsh.to_str().unwrap(),
                "--syq-path",
                env!("CARGO_BIN_EXE_syq"),
                "--performance-tuning",
                "workers=1",
                "--no-progress",
                "--no-tcp",
                "--stats",
                "-v",
            ]);
            if route == "pull" {
                command.args(["--from", "host"]);
            }
            command.arg(t.s(label));
            if route == "push" {
                command.args(["--to", "host"]);
            }
            let out = command
                .args(["--as", &destination])
                .env("SYQ_DEBUG", "1")
                .env("FAKE_REMOTE_HOME", t.path("remote-home"))
                .env("XDG_CONFIG_HOME", t.path("config"))
                .env("XDG_CACHE_HOME", t.path("cache"))
                .run()
                .unwrap();
            assert_output_ok(&out);
            assert_eq!(
                fs::read(t.path(label)).unwrap(),
                fs::read(&destination).unwrap()
            );
            let observed = tuning_observed(&out);
            assert!(
                stderr_of(&out).contains(if route == "local" {
                    "pipeline-depth=4(ordinary ranges only)"
                } else {
                    "pipeline-depth=4(ordinary ranges only; streaming above 16777216 bytes)"
                }),
                "{out:?}"
            );
            assert_eq!(
                observed["streaming_ranges"].as_u64().unwrap() > 0,
                label == "long" && route != "local",
                "{out:?}"
            );
            if route != "local" {
                assert!(stderr_of(&out).contains("streaming-block-size=2097152 bytes"));
                if label == "short" {
                    assert_eq!(observed["range_requests"], 4, "{out:?}");
                    assert_eq!(observed["max_request_bytes"], 4 << 20, "{out:?}");
                } else {
                    assert_eq!(observed["range_requests"], 0, "{out:?}");
                    assert_eq!(observed["max_request_bytes"], 2 << 20, "{out:?}");
                    assert_eq!(observed["streamed_blocks"], 11, "{out:?}");
                }
            }
        }
    }
}

#[test]
fn streaming_copies_local_trees_and_remote_ranges() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    executable(&t.path("remote-bin/ip"), b"#!/bin/sh\nexit 1\n");
    for (name, size) in [("large", (17 << 20) + 123), ("small", 777), ("empty", 0)] {
        write(&t.path(&format!("source/{name}")), &prng(size, 941));
    }
    for route in ["local", "ssh-push", "ssh-pull", "tcp-push", "tcp-pull"] {
        for (workers, request) in [(1, "128K"), (4, "3M")] {
            let destination = t.s(&format!("dst-{route}-{workers}"));
            let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
            command.args([
                "cp",
                "--rsh",
                rsh.to_str().unwrap(),
                "--syq-path",
                env!("CARGO_BIN_EXE_syq"),
                "--performance-tuning",
                &format!("workers={workers}"),
                "--no-progress",
                "--preserve=permissions",
                "-v",
                "--tcp-ports",
                EPHEMERAL_TCP_PORTS,
                "--performance-tuning",
                &format!("copy-path=streaming,request-size={request},split-min-size=1M"),
            ]);
            if route.starts_with("ssh") {
                command.arg("--no-tcp");
            }
            if route.starts_with("tcp") {
                command.env("SYQ_TEST_REQUIRE_TCP", "1");
            }
            if route.ends_with("pull") {
                command.args(["--from", "host"]);
            }
            command.args(["--srcs-in", &t.s("source")]);
            if route.ends_with("push") {
                command.args(["--to", "host"]);
            }
            command
                .args(["--into", &destination])
                .env("FAKE_REMOTE_HOME", t.path("remote-home"))
                .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
                .env("FAKE_RSH_LOG", t.path("rsh.log"))
                .env("FAKE_SSH_CONNECTION", "127.0.0.1 40000 127.0.0.1 22")
                .env("XDG_CONFIG_HOME", t.path("config"))
                .env("XDG_CACHE_HOME", t.path("cache"));
            let out = command.run().unwrap();
            assert_output_ok(&out);
            let observed = tuning_observed(&out);
            assert!(
                observed["streaming_ranges"].as_u64().unwrap() >= 2,
                "{route}: {out:?}"
            );
            assert!(
                observed["streamed_blocks"].as_u64().unwrap() >= 7,
                "{route}: {out:?}"
            );
            assert_eq!(observed["range_requests"], 0);
            assert_eq!(observed["small_batches"], 0);
            assert_eq!(observed["local_whole_files"], 0);
            assert!(stderr_of(&out).contains("pipeline-depth=unused(streaming)"));
            assert_same_tree(&t.path("source"), Path::new(&destination));
        }
    }
}

#[cfg(debug_assertions)]
#[test]
fn streaming_reopens_a_dropped_write_connection() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    t.expose_remote_syq();
    let data = prng(2 << 20, 953);
    write(&t.path("src"), &data);
    let marker = t.path("drop-streaming-write-once");
    let out = remote_syq_command(
        &t,
        &rsh,
        &[
            "-a",
            "--syq-no-bootstrap",
            "--performance-tuning=copy-path=streaming,request-size=64K",
            &t.s("src"),
            &format!("fake:{}", t.s("dst")),
        ],
    )
    .env("SYQ_TEST_DROP_AFTER_REQUEST", "write")
    .env("SYQ_TEST_DROP_AFTER_N_REQUESTS", "3")
    .env("SYQ_TEST_DROP_MARKER", &marker)
    .run()
    .unwrap();
    assert_output_ok(&out);
    assert!(marker.exists());
    assert_eq!(read(&t.path("dst")), data);
    assert!(
        stderr_of(&out).contains("connection dropped; reopening"),
        "{out:?}"
    );
}

#[cfg(debug_assertions)]
#[test]
fn resource_worker_ceiling_bounds_local_tcp_and_ssh_workers() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    let data = prng(9 * 1024 * 1024 + 123, 905);
    write(&t.path("source"), &data);
    for route in ["local", "tcp", "ssh"] {
        for (remembered, limit, network) in [
            (64, 1, "test-network"),
            (64, 3, "test-network"),
            (2, 3, "test-network"),
            (2, 3, "other-network"),
            (2, 3, ""),
        ] {
            // Keep the cache format, with network-scoped keys; cover hints
            // above and below the cap without depending on the host network.
            let cache = format!(
                r#"{{"paths":{{"local>host|tcp|network-v1=test-network":{remembered},"local>host|ssh|network-v1=test-network":{remembered},"local>host|tcp":96,"local>host|ssh":96}}}}"#
            );
            write(&t.path("tuning.json"), cache.as_bytes());
            let label = format!("{route}-{remembered}-{limit}-{network}");
            let events = t.path(&format!("events-{label}"));
            let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
            command.args([
                "cp",
                "--no-progress",
                "--stats",
                "-vv",
                "--resource-limits",
                &format!("workers={limit},bandwidth=16M"),
            ]);
            command.arg(t.s("source"));
            if route != "local" {
                command.args([
                    "--to",
                    "host",
                    "--rsh",
                    rsh.to_str().unwrap(),
                    "--syq-path",
                    env!("CARGO_BIN_EXE_syq"),
                    "--tcp-ports",
                    EPHEMERAL_TCP_PORTS,
                ]);
                if route == "ssh" {
                    command.arg("--no-tcp");
                } else {
                    command.env("SYQ_TEST_REQUIRE_TCP", "1");
                }
            }
            command
                .args(["--as", &t.s(&label)])
                .env("SYQ_TEST_WORKER_EVENTS", &events)
                .env("SYQ_TEST_TUNE_SAMPLE_MS", "20")
                .env("SYQ_TUNING_CACHE", t.path("tuning.json"))
                .env("SYQ_TEST_TUNING_NETWORK", network)
                .env("FAKE_REMOTE_HOME", t.path("remote-home"))
                .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
                .env("FAKE_RSH_LOG", t.path("rsh.log"))
                .env("FAKE_SSH_CONNECTION", "127.0.0.1 40000 127.0.0.1 22")
                .env("XDG_CONFIG_HOME", t.path("config"))
                .env("XDG_CACHE_HOME", t.path("cache"));
            let out = command.run().unwrap();
            assert_output_ok(&out);
            assert!(stderr_of(&out).contains("auto-tuned"), "{out:?}");
            if route != "local" && network == "other-network" {
                assert!(
                    !stderr_of(&out).contains("connections remembered for this path"),
                    "{out:?}"
                );
            }
            if route != "local" && network != "other-network" {
                let start = if network.is_empty() { 96 } else { remembered }.min(limit);
                assert!(
                    stderr_of(&out).contains(&format!(
                        "starting with {start} connections remembered for this path"
                    )),
                    "{out:?}"
                );
            }
            assert_eq!(read(&t.path(&label)), data);
            let observed = fs::read_to_string(&events).unwrap();
            let connected: Vec<_> = observed
                .lines()
                .filter(|line| line.starts_with("connected "))
                .collect();
            assert!(!connected.is_empty(), "{label}: {observed}");
            for line in connected {
                let id: usize = line.split_whitespace().nth(1).unwrap().parse().unwrap();
                assert!(id < limit, "{label}: {observed}");
            }
            assert_eq!(read(&t.path("tuning.json")), cache.as_bytes());
        }
    }
}

#[test]
fn tuning_options_copy_remote_ranges_over_tcp_and_ssh() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    // Exercise the SSH arrival address even where Linux interface discovery
    // could otherwise mask a missing address in the fake SSH session.
    executable(&t.path("remote-bin/ip"), b"#!/bin/sh\nexit 1\n");
    let data = prng(9 * 1024 * 1024 + 123, 904);
    write(&t.path("source"), &data);
    for tcp in [false, true] {
        for pull in [false, true] {
            for (size, depth) in [(64 << 10, 1), (1 << 20, 8), (64 << 10, 64), (8 << 20, 8)] {
                let destination = t.s(&format!("dst-{tcp}-{pull}-{size}-{depth}"));
                let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
                command.args([
                    "cp",
                    "--rsh",
                    rsh.to_str().unwrap(),
                    "--syq-path",
                    env!("CARGO_BIN_EXE_syq"),
                    "--performance-tuning",
                    "workers=1",
                    "--no-progress",
                    "--stats",
                    "--tcp-ports",
                    EPHEMERAL_TCP_PORTS,
                    "--performance-tuning",
                    &format!("request-size={size},pipeline-depth={depth}"),
                ]);
                if !tcp {
                    command.arg("--no-tcp");
                } else {
                    command.env("SYQ_TEST_REQUIRE_TCP", "1");
                }
                if pull {
                    command.args(["--from", "host"]);
                }
                command.arg(t.s("source"));
                if !pull {
                    command.args(["--to", "host"]);
                }
                command
                    .args(["--as", &destination])
                    .env("FAKE_REMOTE_HOME", t.path("remote-home"))
                    .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
                    .env("FAKE_RSH_LOG", t.path("rsh.log"))
                    .env("FAKE_SSH_CONNECTION", "127.0.0.1 40000 127.0.0.1 22")
                    .env("XDG_CONFIG_HOME", t.path("config"))
                    .env("XDG_CACHE_HOME", t.path("cache"));
                let out = command.run().unwrap();
                assert_output_ok(&out);
                let diagnostic = stderr_of(&out);
                assert!(
                    diagnostic.contains(&format!("request-size={size} bytes")),
                    "{diagnostic}"
                );
                assert!(
                    diagnostic.contains(&format!("pipeline-depth={depth}")),
                    "{diagnostic}"
                );
                assert!(
                    diagnostic.contains("hash-block-size=4194304 bytes"),
                    "{diagnostic}"
                );
                assert_eq!(read(Path::new(&destination)), data);
            }
        }
    }
}

#[cfg(debug_assertions)]
#[test]
fn buffered_remote_scan_overlaps_tcp_setup() {
    for (case, existing, tcp, detached, reachable, require_tcp) in [
        ("empty", true, true, false, true, true),
        ("missing", false, true, false, true, true),
        ("ssh", true, false, false, true, false),
        ("detached", true, true, true, true, true),
        ("fallback", true, true, false, false, false),
        ("required-failure", true, true, false, false, true),
    ] {
        let t = Tmp::new();
        let rsh = fake_rsh(&t);
        executable(&t.path("remote-bin/ip"), b"#!/bin/sh\nexit 1\n");
        for i in 0..3 {
            write(
                &t.path(&format!("src/f{i}")),
                format!("contents-{i}").as_bytes(),
            );
        }
        if existing {
            fs::create_dir_all(t.path("dst")).unwrap();
        }
        let events = t.path("setup-events");
        let mut command = compat_command();
        command
            .arg("-e")
            .arg(&rsh)
            .arg("--rsync-path")
            .arg(env!("CARGO_BIN_EXE_syq"))
            .args([
                "--syq-tcp-ports",
                EPHEMERAL_TCP_PORTS,
                "-a",
                "--no-progress",
            ])
            .arg(t.s("src/"))
            .arg(format!("setup.invalid:{}", t.s("dst/")))
            .env("FAKE_REMOTE_HOME", t.path("remote-home"))
            .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
            .env("FAKE_RSH_LOG", t.path("rsh.log"))
            .env(
                "FAKE_SSH_CONNECTION",
                if reachable {
                    "127.0.0.1 40000 127.0.0.1 22"
                } else {
                    "192.0.2.1 40000 192.0.2.1 22"
                },
            )
            .env("XDG_CONFIG_HOME", t.path("config"))
            .env("SYQ_TEST_SETUP_EVENTS", &events)
            .env("SYQ_TEST_NO_INTERFACE_ADDRESSES", "1");
        if require_tcp {
            command.env("SYQ_TEST_REQUIRE_TCP", "1");
        }
        if !tcp {
            command.arg("--syq-no-tcp");
        }
        if detached {
            command.env("SYQ_INTERNAL_DETACH_READY", t.path("ready"));
        }
        let output = command.run().unwrap();
        if require_tcp && !reachable {
            assert!(!output.status.success(), "{case}");
            assert!(stderr_of(&output).contains("TCP data transport required by test"));
            assert_eq!(fs::read_to_string(events).unwrap(), "scan_complete\n");
            assert_eq!(fs::read_dir(t.path("dst")).unwrap().count(), 0);
            continue;
        }
        assert!(output.status.success(), "{case}: {}", stderr_of(&output));
        assert_eq!(
            fs::read_to_string(events).unwrap(),
            if existing && tcp && !detached {
                "scan_complete\ntransport_ready\n"
            } else {
                "transport_ready\nscan_complete\n"
            },
            "{case}"
        );
        for i in 0..3 {
            assert_eq!(
                read(&t.path(&format!("dst/f{i}"))),
                format!("contents-{i}").as_bytes()
            );
        }
        assert!(partial_files(&t.path("dst")).is_empty(), "{case}");
        if detached {
            assert_eq!(read(&t.path("ready")), b"ready\n");
        }
    }
}

#[test]
fn native_remote_copy_omitted_placement_uses_destination_base() {
    let t = Tmp::new();
    let ssh = fake_ssh(&t);
    // Real SSH starts commands in the remote user's home directory.
    let script = fs::read_to_string(&ssh)
        .unwrap()
        .replace("exec /bin/sh -c", "cd \"$HOME\" || exit 1\nexec /bin/sh -c");
    executable(&ssh, script.as_bytes());
    fs::create_dir_all(t.path("remote-home")).unwrap();
    fs::create_dir_all(t.path("local-dest")).unwrap();
    // Exercise both the small-copy optimization and the full engine.
    for engine in [false, true] {
        let name = if engine { "engine" } else { "small" };
        write(&t.path(&format!("sources/{name}")), b"uploaded");
        let run = |args: &[&str]| {
            let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
            command
                .current_dir(t.path("local-dest"))
                .args([
                    "cp",
                    "--syq-path",
                    env!("CARGO_BIN_EXE_syq"),
                    "--no-tcp",
                    "-q",
                ])
                .args(args)
                .env("XDG_CONFIG_HOME", t.path("config"))
                .env("FAKE_REMOTE_HOME", t.path("remote-home"))
                .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
                .env("FAKE_RSH_LOG", t.path("rsh.log"))
                .env(
                    "PATH",
                    format!("{}:/usr/bin:/bin", ssh.parent().unwrap().display()),
                );
            if engine {
                command.env("SYQ_TEST_DISABLE_SMALL_COPY", "1");
            }
            let output = command.run().unwrap();
            assert!(output.status.success(), "{}", stderr_of(&output));
        };
        run(&["-C", &t.s("sources"), name, "--to", "fake.example"]);
        assert_eq!(read(&t.path(&format!("remote-home/{name}"))), b"uploaded");
        run(&[name, "--from", "fake.example"]);
        assert_eq!(read(&t.path(&format!("local-dest/{name}"))), b"uploaded");
        write(
            &t.path(&format!("remote-home/tree-{name}/child")),
            b"contents",
        );
        run(&[
            "--from",
            "fake.example",
            "--srcs-in",
            &format!("tree-{name}"),
        ]);
        assert_eq!(read(&t.path("local-dest/child")), b"contents");
    }
}

/// Rsync's `--insecure-links` is local only and is never sent to the remote
/// side. A remote source therefore keeps the confined default even when the
/// operator passed the flag, and the flag still opts out locally in the same
/// invocation.
#[test]
fn insecure_links_never_reaches_a_remote_endpoint() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    t.expose_remote_syq();
    write(&t.path("outside/secret"), b"secret");
    fs::create_dir_all(t.path("src/a")).unwrap();
    std::os::unix::fs::symlink("../outside", t.path("src/link")).unwrap();
    write(&t.path("src/a/listed"), b"l");
    write(&t.path("list"), b"link/secret\na/listed\n");

    // Remote source: the symlinked ancestor stays refused.
    let remote_src = format!("fake:{}", t.s("src"));
    let out = remote_syq(
        &t,
        &rsh,
        &[
            "-a",
            "-r",
            "--syq-no-bootstrap",
            "--insecure-links",
            "--files-from",
            &t.s("list"),
            &remote_src,
            &t.s("dst"),
        ],
    );
    assert_eq!(out.status.code(), Some(23), "{}", stderr_of(&out));
    assert!(
        stderr_of(&out).contains("link is not a directory"),
        "{}",
        stderr_of(&out)
    );
    assert_eq!(listing(&t.path("dst")), ["a", "a/listed"]);
    assert!(!t.path("dst/link").exists());

    // Local source, remote destination: descendant traversal stays refused.
    let remote_dst = format!("fake:{}", t.s("dst-remote"));
    let out = remote_syq(
        &t,
        &rsh,
        &[
            "-a",
            "-r",
            "--syq-no-bootstrap",
            "--insecure-links",
            "--files-from",
            &t.s("list"),
            &t.s("src"),
            &remote_dst,
        ],
    );
    assert_eq!(out.status.code(), Some(23), "{}", stderr_of(&out));
    assert_eq!(listing(&t.path("dst-remote")), ["a", "a/listed"]);
    assert!(!t.path("dst-remote/link/secret").exists());
}

#[test]
fn rsync_rejects_remote_to_remote() {
    for (source, destination) in [
        ("host-a.invalid:source", "host-b.invalid:destination"),
        ("same.invalid:source", "same.invalid:destination"),
    ] {
        let started = std::time::Instant::now();
        let out = syq(&["-B", "64K", source, destination]);
        assert_eq!(out.status.code(), Some(2), "{}", stderr_of(&out));
        assert!(
            stderr_of(&out).contains("source and destination cannot both be remote"),
            "{}",
            stderr_of(&out)
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }
}

#[test]
fn native_direct_remote_to_remote_forwards_copy_policies() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    let helper = cached_remote_helper(&t);
    fs::create_dir_all(helper.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_syq"), &helper).unwrap();

    let contents = vec![7u8; 5 << 20];
    write(&t.path("src/keep"), &contents);
    write(&t.path("src/skip.tmp"), b"excluded");
    fs::set_permissions(t.path("src/keep"), fs::Permissions::from_mode(0o640)).unwrap();
    write(&t.path("dst/keep"), b"old");
    write(&t.path("dst/extra"), b"remove");
    let original_inode = fs::metadata(t.path("dst/keep")).unwrap().ino();

    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["cp", "--rsh"])
        .arg(&rsh)
        .args([
            "--tcp-ports",
            EPHEMERAL_TCP_PORTS,
            "--from",
            "fake",
            "--follow-src",
            "--follow-dst",
            "--root",
            &t.s("src"),
            "--srcs-in",
            ".",
            "--to",
            "fake",
            "--ignore=*.tmp",
            "--preserve=permissions",
            "--inplace",
            "--prune",
            "--max-delete=1",
            "--resource-limits=workers=2",
            "--performance-tuning=request-size=1M",
            "--into-existing",
            &t.s("dst"),
            "-q",
        ])
        .env("FAKE_REMOTE_HOME", t.path("remote-home"))
        .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
        .env("FAKE_RSH_LOG", t.path("rsh.log"))
        .run()
        .expect("run native direct transfer through fake remote shell");

    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst/keep")), contents);
    let metadata = fs::metadata(t.path("dst/keep")).unwrap();
    assert_eq!(
        metadata.ino(),
        original_inode,
        "--inplace was not forwarded"
    );
    assert_eq!(metadata.mode() & 0o777, 0o640);
    assert!(!t.path("dst/skip.tmp").exists());
    assert!(!t.path("dst/extra").exists());
    let log = fs::read_to_string(t.path("rsh.log")).unwrap();
    for option in [
        "--follow-src",
        "--follow-dst",
        "--root",
        "--ignore=*.tmp",
        "--preserve=permissions",
        "--inplace",
        "--prune",
        "--max-delete=1",
        "--resource-limits=workers=2",
        "--performance-tuning=request-size=1048576",
    ] {
        assert!(
            log.contains(option),
            "source command omitted {option}: {log}"
        );
    }
}

#[test]
fn native_coordinate_at_dst_reverses_the_remote_ssh_edge() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    write(&t.path("src/file"), b"pulled");

    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["cp", "--rsh"])
        .arg(&rsh)
        .args(["--syq-path", env!("CARGO_BIN_EXE_syq")])
        .args([
            "--no-tcp",
            "--tcp-ports=49000-49002",
            "--performance-tuning",
            "workers=1",
            "--from",
            "hostA",
            "--srcs-in",
            &t.s("src"),
            "--to",
            "hostB",
            "--coordinate-at",
            "dst",
            "--into",
            &t.s("dst"),
            "-q",
        ])
        .env("FAKE_REMOTE_HOME", t.path("remote-home"))
        .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
        .env("FAKE_RSH_LOG", t.path("rsh.log"))
        .run()
        .expect("run native pull through fake remote shell");

    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst/file")), b"pulled");
    let log = fs::read_to_string(t.path("rsh.log")).unwrap();
    let mut invocations = log.lines();
    let target_command = invocations.next().expect("target coordinator launch");
    assert!(target_command.contains("--from hostA"), "{target_command}");
    assert!(target_command.contains("--no-tcp"), "{target_command}");
    assert!(
        target_command.contains("--tcp-ports=49000-49002"),
        "{target_command}"
    );
    assert!(
        invocations.next().is_some(),
        "the target coordinator never opened the reversed edge to hostA: {log}"
    );
}

#[test]
fn native_target_dry_run_labels_the_real_endpoints_and_ports() {
    let t = Tmp::new();
    let ssh = fake_ssh(&t);
    write(&t.path("src/file"), b"planned");

    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["cp", "--rsh"])
        .arg(&ssh)
        .args(["--syq-path", env!("CARGO_BIN_EXE_syq")])
        .args([
            "--no-tcp",
            "--dry-run",
            "--from",
            "hostA:2200",
            "--srcs-in",
            &t.s("src"),
            "--to",
            "hostB:2222",
            "--coordinate-at",
            "dst",
            "--into",
            &t.s("dst"),
        ])
        .env("FAKE_REMOTE_HOME", t.path("remote-home"))
        .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
        .env("FAKE_RSH_LOG", t.path("rsh.log"))
        .run()
        .expect("run target-side native dry-run");

    assert_output_ok(&out);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(&format!(
            "mapping: hostA:2200:{} -> hostB:2222:{}",
            t.s("src"),
            t.s("dst")
        )),
        "{stdout}"
    );
    assert!(!stdout.contains("-> hostA:2200:"), "{stdout}");
    let ssh_log = fs::read_to_string(t.path("rsh.log")).unwrap();
    assert!(
        ssh_log.lines().any(|line| line.contains("-p 2222")),
        "{ssh_log}"
    );
    assert!(
        ssh_log.lines().any(|line| line.contains("-p 2200")),
        "{ssh_log}"
    );
}

#[test]
fn native_coordinate_at_local_relays_between_remote_endpoints() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    write(&t.path("src/file"), b"relayed");
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
            "--srcs-in",
            &t.s("src"),
            "--to",
            "hostB",
            "--coordinate-at",
            "local",
            "--into",
            &t.s("dst"),
            "-q",
        ])
        .env("FAKE_REMOTE_HOME", t.path("remote-home"))
        .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
        .env("FAKE_RSH_LOG", t.path("rsh.log"))
        .run()
        .expect("run native relay through fake remote shell");
    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst/file")), b"relayed");
    assert!(
        fs::read_to_string(t.path("rsh.log"))
            .unwrap()
            .lines()
            .count()
            >= 2,
        "relay did not connect to both endpoints"
    );
}

#[test]
fn native_endpoint_port_reaches_ssh() {
    let t = Tmp::new();
    let ssh = fake_ssh(&t);
    write(&t.path("src"), b"first");
    let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
    command
        .arg("cp")
        .args(["--syq-path", env!("CARGO_BIN_EXE_syq")])
        .args([
            "--no-tcp",
            "--performance-tuning",
            "workers=1",
            &t.s("src"),
            "--to",
            "backup.example:2222",
            "--as",
            &t.s("dst"),
            "-q",
        ])
        .env("XDG_CONFIG_HOME", t.path("config"))
        .env("FAKE_REMOTE_HOME", t.path("remote-home"))
        .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
        .env("FAKE_RSH_LOG", t.path("rsh.log"))
        .env(
            "PATH",
            format!("{}:/usr/bin:/bin", ssh.parent().unwrap().to_string_lossy()),
        );
    assert_output_ok(&command.run().unwrap());
    assert_eq!(read(&t.path("dst")), b"first");
    let log = fs::read_to_string(t.path("rsh.log")).unwrap();
    assert!(log.lines().all(|line| line.contains("-p 2222")), "{log}");

    assert!(log.contains("ControlMaster=yes"), "{log}");
    assert!(log.contains("ControlPersist=no"), "{log}");
}

#[test]
fn native_remote_exact_bare_home_expands_before_identity_check() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    fs::create_dir_all(t.path("remote-home")).unwrap();
    write(&t.path("src/file"), b"home destination");

    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["cp", "--rsh"])
        .arg(&rsh)
        .args(["--syq-path", env!("CARGO_BIN_EXE_syq")])
        .args([
            "--no-tcp",
            "--performance-tuning",
            "workers=1",
            "--src",
            &t.s("src"),
            "--to",
            "fake",
            "--as",
            "~",
            "-q",
        ])
        .env("FAKE_REMOTE_HOME", t.path("remote-home"))
        .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
        .env("FAKE_RSH_LOG", t.path("rsh.log"))
        .run()
        .expect("copy to a remote bare-home destination");

    assert_output_ok(&out);
    assert_eq!(read(&t.path("remote-home/file")), b"home destination");
}

#[test]
fn explicit_pscope_is_refused_for_remote_coordinators() {
    let t = Tmp::new();
    fs::create_dir(t.runtime()).unwrap();
    let scope = ephemeral_scope(&t);
    let scope = scope.to_str().unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "rsync",
            "-a",
            "--syq-pscope",
            scope,
            "hostA:src/",
            "hostB:dst/",
            "--no-progress",
        ])
        .env("XDG_CONFIG_HOME", t.path("config"))
        .env("XDG_RUNTIME_DIR", t.runtime())
        .run()
        .unwrap();
    assert!(!out.status.success());
    assert!(stderr_of(&out).contains("source and destination cannot both be remote"));

    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "cp",
            "--pscope",
            scope,
            "--from",
            "hostA",
            "--srcs-in",
            "src",
            "--to",
            "hostB",
            "--coordinate-at",
            "dst",
            "--into",
            "dst",
            "-q",
        ])
        .env("XDG_CONFIG_HOME", t.path("config"))
        .env("XDG_RUNTIME_DIR", t.runtime())
        .run()
        .unwrap();
    assert!(!out.status.success());
    let stderr = stderr_of(&out);
    assert!(stderr.contains("remote transfer coordinator"), "{stderr}");
    assert!(stderr.contains("--coordinate-at local"), "{stderr}");
}

#[test]
fn native_remote_to_remote_carries_any_path_bytes_directly() {
    if !filesystem_accepts_non_utf8_names() {
        eprintln!("skipping: this filesystem rejects file names that are not valid UTF-8");
        return;
    }
    use std::os::unix::ffi::OsStrExt;
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    // Non-UTF-8 path bytes ride the delegated command line as encoded
    // operands: the direct topology works for every filename, with no
    // implicit relay through this machine.
    let base_name = std::ffi::OsStr::from_bytes(b"base-\xfd");
    let name = std::ffi::OsStr::from_bytes(b"src-\xff");
    let source_base = t.path("").join(base_name);
    write(&source_base.join(name), b"raw bytes travel");
    let mut destination = t.path("").into_os_string();
    destination.push("/dst-\u{1}");
    let mut destination_bytes = t.s("").into_bytes();
    destination_bytes.extend_from_slice(b"dst-\xfe");
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
            "--root",
        ])
        .arg(&source_base)
        .arg("--src")
        .arg(name)
        .args(["--to", "hostB", "--as"])
        .arg(std::ffi::OsStr::from_bytes(&destination_bytes))
        .env("FAKE_REMOTE_HOME", t.path("remote-home"))
        .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
        .env("FAKE_RSH_LOG", t.path("rsh.log"))
        .run()
        .unwrap();
    assert!(out.status.success(), "{}", stderr_of(&out));
    let stderr = stderr_of(&out);
    assert!(!stderr.contains("relaying"), "no implicit relay: {stderr}");
    assert_eq!(
        read(Path::new(std::ffi::OsStr::from_bytes(&destination_bytes))),
        b"raw bytes travel"
    );
}

#[test]
fn native_direct_remote_forwards_overwrite_policies() {
    for policy in ["--only-new", "--only-existing", "--skip-newer"] {
        let t = Tmp::new();
        let rsh = fake_rsh(&t);
        let helper = cached_remote_helper(&t);
        fs::create_dir_all(helper.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_syq"), &helper).unwrap();
        write(&t.path("src/file"), b"source");
        write(&t.path("dst/file"), b"destination");
        write(&t.path("src/new"), b"new");
        set_mtime(&t.path("src/file"), 1_600_000_000);
        set_mtime(&t.path("dst/file"), 1_700_000_000);
        let out = Command::new(env!("CARGO_BIN_EXE_syq"))
            .args(["cp", "--rsh"])
            .arg(&rsh)
            .args([
                "--tcp-ports",
                EPHEMERAL_TCP_PORTS,
                "--from",
                "fake",
                "--srcs-in",
                &t.s("src"),
                "--to",
                "fake",
                "--into",
                &t.s("dst"),
                policy,
                "-q",
            ])
            .env("FAKE_REMOTE_HOME", t.path("remote-home"))
            .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
            .env("FAKE_RSH_LOG", t.path("rsh.log"))
            .run()
            .unwrap();
        assert_eq!(out.status.code(), Some(0), "{policy}: {}", stderr_of(&out));
        assert_eq!(
            read(&t.path("dst/file")),
            if policy == "--only-existing" {
                b"source" as &[u8]
            } else {
                b"destination"
            }
        );
        assert_eq!(
            t.path("dst/new").exists(),
            matches!(policy, "--only-new" | "--skip-newer")
        );
        assert!(fs::read_to_string(t.path("rsh.log"))
            .unwrap()
            .contains(policy));
    }
}

#[test]
fn native_ignores_internal_rsh_environment() {
    for explicit_rsh in [false, true] {
        let t = Tmp::new();
        let ssh = fake_ssh(&t);
        let rsh = fake_rsh(&t);
        t.expose_remote_syq();
        write(&t.path("source"), b"data");
        let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
        command.args([
            "cp",
            "--from",
            "example",
            "--src",
            &t.s("source"),
            "--as",
            &t.s("dest"),
            "--syq-path",
            "syq",
            "--no-tcp",
        ]);
        if explicit_rsh {
            command.arg("--rsh").arg(&rsh);
        }
        let output = command
            .env("SYQ_INTERNAL_NATIVE_RSH", "/missing-internal-rsh")
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", ssh.parent().unwrap().display()),
            )
            .env("FAKE_REMOTE_HOME", &t.0)
            .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
            .env("FAKE_RSH_LOG", t.path("rsh.log"))
            .run()
            .unwrap();
        assert_output_ok(&output);
        assert_eq!(read(&t.path("dest")), b"data");
    }
}

#[cfg(all(debug_assertions, target_os = "linux"))]
#[test]
fn source_read_ahead_runs_for_tcp_and_ssh_ranges_and_streams() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    let data = prng(17 * 1024 * 1024 + 123, 357);
    write(&t.path("source"), &data);
    for tcp in [false, true] {
        for pull in [false, true] {
            for stream in [false, true] {
                let destination = t.s(&format!("dst-{tcp}-{pull}-{stream}"));
                let result_path = t.s(&format!("activity-{tcp}-{pull}-{stream}.ndjson"));
                let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
                command.args([
                    "cp",
                    "--rsh",
                    rsh.to_str().unwrap(),
                    "--syq-path",
                    env!("CARGO_BIN_EXE_syq"),
                    "--performance-tuning",
                    "workers=1",
                    "--no-progress",
                    "--results",
                    &result_path,
                    "--tcp-ports",
                    EPHEMERAL_TCP_PORTS,
                    "--performance-tuning",
                    if stream {
                        "copy-path=streaming,request-size=4194304"
                    } else {
                        "copy-path=ranges,request-size=4194304,pipeline-depth=8"
                    },
                ]);
                if tcp {
                    command.env("SYQ_TEST_REQUIRE_TCP", "1");
                } else {
                    command.arg("--no-tcp");
                }
                if pull {
                    command.args(["--from", "host"]);
                }
                command.arg(t.s("source"));
                if !pull {
                    command.args(["--to", "host"]);
                }
                let out = command
                    .args(["--as", &destination])
                    .env("SYQ_DEBUG", "1")
                    .env("SYQ_TEST_LOCAL_READ_AHEAD", "1")
                    .env("FAKE_REMOTE_HOME", t.path("remote-home"))
                    .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
                    .env("FAKE_RSH_LOG", t.path("rsh.log"))
                    .env("FAKE_SSH_CONNECTION", "127.0.0.1 40000 127.0.0.1 22")
                    .env("XDG_CONFIG_HOME", t.path("config"))
                    .env("XDG_CACHE_HOME", t.path("cache"))
                    .run()
                    .unwrap();
                assert_output_ok(&out);
                let stderr = stderr_of(&out);
                assert!(
                    stderr.contains("source read-ahead started"),
                    "tcp={tcp} pull={pull} stream={stream}: {stderr}"
                );
                if stream {
                    assert_eq!(
                        stderr.matches("source read-ahead started").count(),
                        1,
                        "stream should keep one preparation interval: {stderr}"
                    );
                }
                assert_eq!(read(Path::new(&destination)), data);
                let content = fs::read_to_string(&result_path).unwrap();
                assert_automation_stream(&automation_validator(), &content, "remote activity");
                let records: Vec<serde_json::Value> = content
                    .lines()
                    .map(|l| serde_json::from_str(l).unwrap())
                    .collect();
                let samples: Vec<_> = records.iter().filter_map(|r| r.get("activity")).collect();
                assert!(samples
                    .iter()
                    .any(|s| s["endpoints"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|e| e["actors"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|a| a["fractions"].get("source_read").is_some()))));
                assert!(samples.iter().any(|s| s["processes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|p| p["local"] == false && p["cpu"].is_object())));
                assert!(
                    samples.iter().any(|sample| sample["endpoints"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(
                            |endpoint| endpoint["actors"].as_array().unwrap().iter().any(|actor| {
                                actor["role"] == "prefetch"
                                    && actor["bytes"]["prefetch_advice"]
                                        .as_u64()
                                        .is_some_and(|n| n > 0)
                                    && actor["helper_cpu"].is_object()
                            })
                        )),
                    "helper advice and CPU must be observable: {samples:?}"
                );
                if tcp {
                    assert!(samples.iter().any(|s| s["endpoints"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|e| e["peer_tcp"].is_object())));
                }
            }
        }
    }
}

#[cfg(debug_assertions)]
#[test]
fn rejected_telemetry_subscription_does_not_fail_remote_copy() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    let data = prng(64 * 1024 + 123, 359);
    write(&t.path("source"), &data);
    for (stats, debug, failure) in [
        (false, false, "reject"),
        (true, false, "reject"),
        (false, true, "reject"),
        (true, false, "disconnect"),
        (false, true, "disconnect"),
    ] {
        let destination = t.s(&format!("destination-{stats}-{debug}-{failure}"));
        let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
        command.args([
            "cp",
            "--rsh",
            rsh.to_str().unwrap(),
            "--syq-path",
            env!("CARGO_BIN_EXE_syq"),
            "--performance-tuning",
            "workers=1",
            "--no-tcp",
            "--no-progress",
            "--results",
            &t.s(&format!("results-{stats}-{debug}-{failure}")),
        ]);
        if stats {
            command.arg("--stats");
        }
        if debug {
            command.env("SYQ_DEBUG", "1");
        } else {
            command.env_remove("SYQ_DEBUG");
        }
        let out = command
            .arg(t.s("source"))
            .args(["--to", "host", "--as", &destination])
            .env("SYQ_TEST_REJECT_TELEMETRY", failure)
            .env("FAKE_REMOTE_HOME", t.path("remote-home"))
            .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
            .env("FAKE_RSH_LOG", t.path("rsh.log"))
            .env("XDG_CONFIG_HOME", t.path("config"))
            .env("XDG_CACHE_HOME", t.path("cache"))
            .run()
            .unwrap();
        assert_output_ok(&out);
        if debug && failure == "reject" {
            assert!(stderr_of(&out).contains("small copy: published"), "{out:?}");
        }
        assert_eq!(read(Path::new(&destination)), data);
        assert_eq!(
            stderr_of(&out).contains(if failure == "reject" {
                "telemetry unavailable; continuing copy"
            } else {
                "recovering without remote telemetry"
            }),
            stats || debug,
            "{out:?}"
        );
    }
}

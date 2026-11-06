use super::*;

#[cfg(all(debug_assertions, target_os = "linux"))]
#[test]
fn insecure_links_does_not_delegate_unconfined_names_to_copy_local() {
    let t = Tmp::new();
    let contents = vec![b'u'; 8 << 20];
    fs::create_dir_all(t.path("src")).unwrap();
    write(&t.path("outside/secret"), &contents);
    std::os::unix::fs::symlink("../outside", t.path("src/link")).unwrap();
    write(&t.path("list"), b"link/secret\n");
    let copy_local_ready = t.path("copy-local-ready");

    let output = compat_command()
        .args([
            "-a",
            "-r",
            "--insecure-links",
            "--files-from",
            &t.s("list"),
            &t.s("src"),
            &t.s("dst"),
            "--no-progress",
        ])
        .env("SYQ_TEST_COPY_LOCAL_READY_FILE", &copy_local_ready)
        .run()
        .unwrap();

    assert_eq!(output.status.code(), Some(23));
    assert!(!copy_local_ready.exists());
    assert!(!t.path("dst/link/secret").exists());
}

#[test]
fn native_copy_distinguishes_named_contents_and_exact_placement() {
    let t = Tmp::new();
    write(&t.path("src/sub/file"), b"data");

    let many_slashes = format!("{}///", t.s("src"));
    run_native_ok(&["cp", &many_slashes, "--into", &t.s("named")]);
    assert_eq!(read(&t.path("named/src/sub/file")), b"data");

    run_native_ok(&["cp", "--srcs-in", &t.s("src"), "--into", &t.s("contents")]);
    assert_eq!(read(&t.path("contents/sub/file")), b"data");
    assert!(!t.path("contents/src").exists());

    run_native_ok(&["cp", &t.s("src"), "--as", &t.s("exact")]);
    assert_eq!(read(&t.path("exact/sub/file")), b"data");
    assert!(!t.path("exact/src").exists());

    // Existing target state does not change either placement mapping.
    fs::create_dir_all(t.path("named-existing")).unwrap();
    fs::create_dir_all(t.path("exact-existing")).unwrap();
    run_native_ok(&["cp", &t.s("src"), "--into-existing", &t.s("named-existing")]);
    run_native_ok(&["cp", &t.s("src"), "--as-existing", &t.s("exact-existing")]);
    assert_eq!(read(&t.path("named-existing/src/sub/file")), b"data");
    assert_eq!(read(&t.path("exact-existing/sub/file")), b"data");
    assert!(!t.path("exact-existing/src").exists());

    let output = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "cp",
            "--dry-run",
            &t.s("src"),
            "--as",
            &t.s("planned-exact"),
        ])
        .run()
        .unwrap();
    assert_output_ok(&output);
    let plan = String::from_utf8_lossy(&output.stdout);
    assert!(plan.contains("(exact destination path)"), "{plan}");

    run_native_ok(&[
        "cp",
        "--cwd",
        &t.s("src"),
        ".",
        "--as-new",
        &t.s("dot-exact"),
    ]);
    assert_eq!(read(&t.path("dot-exact/sub/file")), b"data");
}

#[test]
fn native_copy_named_root_symlink_needs_follow_or_src_non_dir() {
    use std::os::unix::fs::symlink;

    let t = Tmp::new();
    write(&t.path("real/file"), b"data");
    symlink("real", t.path("link")).unwrap();

    let link_with_slashes = format!("{}///", t.s("link"));
    for (source, placement) in [
        (t.s("link"), "refused"),
        (link_with_slashes.clone(), "refused-with-slashes"),
    ] {
        let refused = native_syq(&["cp", "--src", &source, "--into", &t.s(placement)]);
        assert!(!refused.status.success());
        assert!(
            stderr_of(&refused).contains("--follow-src"),
            "{}",
            stderr_of(&refused)
        );
        assert!(!t.path(placement).exists());
    }

    run_native_ok(&[
        "cp",
        "--src-non-dir",
        &t.s("link"),
        "--into",
        &t.s("preserved"),
    ]);
    assert_eq!(
        fs::read_link(t.path("preserved/link")).unwrap(),
        Path::new("real")
    );

    run_native_ok(&[
        "cp",
        "--src-non-dir",
        &link_with_slashes,
        "--into",
        &t.s("preserved-with-slashes"),
    ]);
    assert_eq!(
        fs::read_link(t.path("preserved-with-slashes/link")).unwrap(),
        Path::new("real")
    );
}

#[cfg(target_os = "macos")]
#[test]
fn named_fifo_control_input_fails_before_destination_mutation() {
    let t = Tmp::new();
    write(&t.path("src/keep"), b"data");
    let selected = t.path("selected-control");
    mkfifo(&selected);
    let output = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["cp", "--ignore-from"])
        .arg(&selected)
        .arg("--srcs-in")
        .arg(t.path("src"))
        .arg("--into")
        .arg(t.path("dst"))
        .arg("-q")
        .run()
        .unwrap();
    assert!(!output.status.success());
    assert!(stderr_of(&output).contains("exact descriptor"));
    assert!(!t.path("dst").exists());
}

#[test]
fn receiver_is_one_subcommand_with_its_verbs_beneath_it() {
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_syq"))
            .args(args)
            .run()
            .unwrap()
    };
    let help = run(&["receiver", "--help"]);
    assert!(help.status.success());
    let text = String::from_utf8_lossy(&help.stdout);
    for verb in ["enroll", "list", "revoke"] {
        assert!(text.contains(verb), "{text}");
    }
    let bare = run(&["receiver"]);
    assert_eq!(bare.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&bare.stderr).contains("Usage: syq receiver"));
    let bogus = run(&["receiver", "rotate"]);
    assert!(!bogus.status.success());
    assert!(String::from_utf8_lossy(&bogus.stderr).contains("unrecognized subcommand"));
    for verb in ["enroll", "list", "revoke"] {
        let verb_help = run(&["receiver", verb, "--help"]);
        assert!(verb_help.status.success(), "{verb}");
        assert!(
            String::from_utf8_lossy(&verb_help.stdout).contains(&format!("syq receiver {verb}")),
            "{verb}"
        );
    }
    // The old top-level spellings are gone.
    for old in [
        &["enroll", "host:dst"][..],
        &["enrollments"],
        &["enrollment", "list"],
        &["revoke", "id"],
    ] {
        let out = run(old);
        assert!(!out.status.success(), "{old:?}");
    }
}

#[test]
fn native_receiver_ceilings_apply_only_to_direct_remote_copies() {
    let t = Tmp::new();
    write(&t.path("src/file"), b"data");
    for option in ["--receiver-max-entries=5", "--receiver-max-bytes=1M"] {
        let out = Command::new(env!("CARGO_BIN_EXE_syq"))
            .args([
                "cp",
                option,
                "--srcs-in",
                &t.s("src"),
                "--into",
                &t.s("dst"),
            ])
            .run()
            .unwrap();
        assert!(!out.status.success(), "{option}");
        assert!(
            String::from_utf8_lossy(&out.stderr)
                .contains("apply only to direct remote-to-remote copies"),
            "{option}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(!t.path("dst").exists(), "{option} copied anyway");
    }
}

#[test]
fn delete_treats_partial_named_directory_as_ordinary_extra() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"a");
    write(&t.path("dst/.d.syq-tmp.aaaaaaaaaaaaaaaa/x"), b"x");
    write(&t.path("dst/.d.syq-tmp.aaaaaaaaaaaaaaaa/keep.log"), b"k");
    let so = run_ok(&[
        "-a",
        "-v",
        "--delete",
        "--syq-ignore",
        "*.log",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert_eq!(
        listing(&t.path("dst")),
        [
            ".d.syq-tmp.aaaaaaaaaaaaaaaa",
            ".d.syq-tmp.aaaaaaaaaaaaaaaa/keep.log",
            "a"
        ]
    );
    assert!(so.contains("1 deleted") && !so.contains("errors"), "{so}");
}

#[cfg(all(debug_assertions, target_os = "linux"))]
#[test]
fn copy_local_nfs_exdev_uses_sequential_receiver_fallback() {
    let t = Tmp::new();
    let contents = vec![b'x'; 8 * 1024 * 1024];
    write(&t.path("src"), &contents);

    let out = compat_command()
        .args(["-a", "--no-progress", &t.s("src"), &t.s("dst")])
        .env("SYQ_TEST_COPY_LOCAL_EXDEV", "1")
        .env("SYQ_TEST_COPY_LOCAL_NFS", "1")
        .env("SYQ_TEST_COPY_LOCAL_SOURCE_DISK", "1")
        .env("SYQ_TEST_FAIL_READ_RANGE", "1")
        .run()
        .unwrap();
    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), contents);
    assert!(partial_files(&t.0).is_empty());
}

#[test]
fn partial_named_symlink_is_a_symlink_not_a_leftover() {
    let t = Tmp::new();
    write(&t.path("a/target"), b"t");
    std::os::unix::fs::symlink("target", t.path("a/.x.syq-tmp.aaaaaaaaaaaaaaaa")).unwrap();
    write(&t.path("b/other"), b"o");
    std::os::unix::fs::symlink("target", t.path("b/.x.syq-tmp.aaaaaaaaaaaaaaaa")).unwrap();
    run_ok(&["-a", &t.s("a/"), &t.s("dst")]);
    assert!(t
        .path("dst/.x.syq-tmp.aaaaaaaaaaaaaaaa")
        .symlink_metadata()
        .unwrap()
        .is_symlink());
    // Without -l the symlinks are skipped, and two sources skipping the same
    // path is not a collision.
    run_ok(&["-r", &t.s("a/"), &t.s("b/"), &t.s("dst2")]);
    assert!(!t.path("dst2/.x.syq-tmp.aaaaaaaaaaaaaaaa").exists());
    assert!(t.path("dst2/target").is_file() && t.path("dst2/other").is_file());
}

#[test]
fn sidecar_named_source_directory_is_payload() {
    // A sidecar-looking name in the source is ordinary payload (with one
    // warning); it uses another job's id, so it can't collide with this job's
    // own sidecar for `name`, and later updates of `name` still stage fine.
    let t = Tmp::new();
    let sidecar_dir = format!("src/.name.syq-tmp.{}", "a".repeat(16));
    write(&t.path(&format!("{sidecar_dir}/inside")), b"i");
    write(&t.path("src/name"), b"v1");
    let out = syq(&["-a", &t.s("src/"), &t.s("dst")]);
    assert!(out.status.success(), "{}", stderr_of(&out));
    assert!(
        stderr_of(&out).contains("recognizable SYQ partial path"),
        "{}",
        stderr_of(&out)
    );
    let sidecar_rel = &sidecar_dir["src/".len()..];
    assert_eq!(
        listing(&t.path("dst")),
        [sidecar_rel, &format!("{sidecar_rel}/inside"), "name"]
    );
    write(&t.path("src/name"), &vec![7u8; 8 << 20]);
    run_ok(&["-a", &t.s("src/"), &t.s("dst")]);
    assert_eq!(read(&t.path("dst/name")), vec![7u8; 8 << 20]);
    assert_eq!(listing(&t.path("dst")).len(), 3);
}

#[test]
fn inplace_conflicts_with_receiver_state_filters() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"data");
    for filter in ["-u", "--ignore-existing"] {
        let out = syq(&["-a", "--inplace", filter, &t.s("src/"), &t.s("dst")]);
        assert!(!out.status.success(), "{filter}");
        assert!(
            stderr_of(&out).contains("cannot be used with"),
            "{filter}: {}",
            stderr_of(&out)
        );
    }
    assert!(!t.path("dst").exists());
}

#[test]
fn native_coordinate_at_dst_fails_closed_without_read_enrollment_support() {
    let t = Tmp::new();
    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "cp",
            "--from",
            "hostA",
            "--src",
            &t.s("src"),
            "--to",
            "hostB",
            "--coordinate-at",
            "dst",
            "--into",
            &t.s("dst"),
        ])
        .run()
        .expect("reject unavailable default pull mode");

    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr_of(&out).contains("read-restricted source enrollment"),
        "{}",
        stderr_of(&out)
    );
    assert!(!t.path("dst").exists());
}

#[test]
fn persist_connect_failure_announces_policy_and_status_survives_bad_receive_settings() {
    let t = Tmp::new();
    fs::create_dir(t.runtime()).unwrap();
    let ssh = t.path("bin/ssh");
    executable(&ssh, b"#!/bin/sh\necho 'test key rejected' >&2\nexit 255\n");
    let output = persistence_command(&t, &["connect", "test-server", "--no-bootstrap"])
        .env("HOME", &t.0)
        .env(
            "PATH",
            format!("{}:/usr/bin:/bin", ssh.parent().unwrap().display()),
        )
        .run()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("kept on if connecting fails"));
    assert!(stderr_of(&output).contains("test key rejected"));
    let policy: serde_json::Value =
        serde_json::from_slice(&read(&t.path("config/syq/persistence.json"))).unwrap();
    assert_eq!(policy["enabled"], true);

    let receive = t.path("config/syq/receive.json");
    for (contents, mode, missing_home) in [
        (&b"{}"[..], 0o644, false),
        (&b"not json"[..], 0o600, false),
        (&b"{}"[..], 0o000, false),
        (&b""[..], 0o600, true),
    ] {
        if receive.exists() {
            fs::set_permissions(&receive, fs::Permissions::from_mode(0o600)).unwrap();
            fs::remove_file(&receive).unwrap();
        }
        if !missing_home {
            write(&receive, contents);
            fs::set_permissions(&receive, fs::Permissions::from_mode(mode)).unwrap();
        }
        for json in [false, true] {
            let mut command = persistence_command(&t, &["status"]);
            command.env("HOME", &t.0);
            if missing_home {
                command.env_remove("HOME");
            }
            if json {
                command.arg("--json");
            }
            let output = command.run().unwrap();
            assert_output_ok(&output);
            if json {
                let status: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
                assert_eq!(status["connections"][0]["endpoint"], "test-server");
                assert_eq!(status["connections"][0]["state"], "failed");
                assert!(status["connections"][0]["receiving_enabled"].is_null());
                assert!(status["receiving_error"]
                    .as_str()
                    .is_some_and(|s| !s.is_empty()));
            } else {
                let text = String::from_utf8_lossy(&output.stdout);
                assert!(text.contains("test-server  failed"), "{text}");
                assert!(text.contains("Receiving configuration failed:"), "{text}");
            }
        }
    }
    assert_output_ok(&persistence_command(&t, &["off"]).run().unwrap());
}

#[test]
fn persist_connect_domains_isolate_receiving_and_report_setup_errors_once() {
    let t = Tmp::new();
    fs::create_dir(t.runtime()).unwrap();
    let ssh = fake_ssh(&t);
    let connect = |scope: Option<&Path>, log: &str| {
        let mut cmd = persistence_command(&t, &["connect", "test-server", "--timeout", "1"]);
        cmd.args(["--syq-path", env!("CARGO_BIN_EXE_syq")])
            .env_remove("HOME")
            .env("XDG_CACHE_HOME", t.path("cache"))
            .env("FAKE_REMOTE_HOME", t.path("remote-home"))
            .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
            .env("FAKE_RSH_LOG", t.path(log))
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", ssh.parent().unwrap().display()),
            );
        if let Some(scope) = scope {
            cmd.arg("--pscope").arg(scope);
        }
        cmd.run().unwrap()
    };
    // Invalid global preferences must not affect a fresh explicit domain.
    let receive = t.path("config/syq/receive.json");
    write(&receive, b"not json");
    fs::set_permissions(&receive, fs::Permissions::from_mode(0o600)).unwrap();
    let scope = ephemeral_scope(&t);
    let output = connect(Some(&scope), "rsh.log");
    assert_output_ok(&output);
    assert!(String::from_utf8_lossy(&output.stdout).contains("ready"));
    assert!(!t.path("config/syq/persistence.json").exists());
    assert_eq!(read(&receive), b"not json");
    let settings: serde_json::Value =
        serde_json::from_slice(&read(&scope.join("receive.json"))).unwrap();
    assert_eq!(settings["profiles"][0]["enabled"], false);
    let log = fs::read_to_string(t.path("rsh.log")).unwrap();
    assert!(log.contains("ControlPersist=300"), "{log}");
    assert!(!log.contains("ControlPersist=yes"), "{log}");
    let output = persistence_command(&t, &["status", "--pscope", scope.to_str().unwrap()])
        .env_remove("HOME")
        .run()
        .unwrap();
    assert_output_ok(&output);
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("receiving disabled"), "{text}");
    assert!(
        text.contains(&format!(
            "run syq persist connect test-server --pscope {}",
            scope.display()
        )),
        "{text}"
    );
    assert_output_ok(
        &persistence_command(&t, &["off", "--pscope", scope.to_str().unwrap()])
            .run()
            .unwrap(),
    );

    // Successful forward setup followed by invalid receiving settings reports
    // one error, with no best-effort setup attempt before the explicit one.
    let output = connect(None, "rsh.log");
    assert!(!output.status.success());
    let error = stderr_of(&output);
    assert_eq!(error.matches("expected ident").count(), 1, "{error}");
    assert!(!error.contains("background receiving through"), "{error}");
    let status = persistence_command(&t, &["status", "--json"])
        .run()
        .unwrap();
    assert_output_ok(&status);
    let status: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    let global = Path::new(status["scope"].as_str().unwrap());
    write(
        &t.path("config/syq/persistence.json"),
        b"{\"enabled\":false}\n",
    );
    // Earlier connections leave a pool that can still write to rsh.log.
    // Only this invocation can write to the rejection log.
    let rejected = connect(Some(global), "rejected-rsh.log");
    assert!(!rejected.status.success());
    assert!(stderr_of(&rejected).contains("expected ident"));
    assert_eq!(read(&receive), b"not json");
    assert_output_ok(&persistence_command(&t, &["off"]).run().unwrap());
}

#[cfg(target_os = "linux")]
#[test]
fn receiver_wait_and_list_do_not_block_on_a_full_listen_queue() {
    use socket2::{Domain, SockAddr, Socket, Type};
    use std::time::{Duration, Instant};
    let t = Tmp::new();
    let registry = t.path(".syq-destinations-v3");
    fs::create_dir(&registry).unwrap();
    fs::set_permissions(&registry, fs::Permissions::from_mode(0o700)).unwrap();
    let socket_path = t.path("receiver.sock");
    let address = SockAddr::unix(&socket_path).unwrap();
    let listener = Socket::new(Domain::UNIX, Type::STREAM, None).unwrap();
    listener.bind(&address).unwrap();
    listener.listen(0).unwrap();
    let mut queued = Vec::new();
    let mut full = false;
    for _ in 0..16 {
        let client = Socket::new(Domain::UNIX, Type::STREAM, None).unwrap();
        client.set_nonblocking(true).unwrap();
        match client.connect(&address) {
            Ok(()) => queued.push(client),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                full = true;
                break;
            }
            Err(error) => panic!("fill listen queue: {error}"),
        }
    }
    assert!(full, "test did not fill the listen queue");
    let path = registry.join("stuck.json");
    write(
        &path,
        &serde_json::to_vec(&serde_json::json!({
            "version":3,"identity":"test-build","socket":socket_path,
            "secret":"test","program":env!("CARGO_BIN_EXE_syq").as_bytes(),
        }))
        .unwrap(),
    );
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    // A hard watchdog unblocks even the old blocking implementation, so a
    // regression fails the latency assertion instead of hanging the test suite.
    let (stop, stopped) = std::sync::mpsc::channel();
    let watchdog = std::thread::spawn(move || {
        let _ = stopped.recv_timeout(Duration::from_secs(4));
        drop(listener);
        drop(queued);
    });
    let start = Instant::now();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_syq"))
            .args(args)
            .env("HOME", t.path(""))
            .env("SYQ_NO_UPDATE_CHECK", "1")
            .capture_output()
            .unwrap()
    };
    let wait = run(&["persist", "destinations", "wait", "stuck", "--timeout", "1"]);
    let list = run(&["persist", "destinations", "list"]);
    let elapsed = start.elapsed();
    let _ = stop.send(());
    watchdog.join().unwrap();
    assert!(!wait.status.success());
    assert!(
        stderr_of(&wait).contains("timed out waiting"),
        "{}",
        stderr_of(&wait)
    );
    assert_output_ok(&list);
    assert_eq!(list.stdout, b"@stuck\toffline\n");
    assert!(
        elapsed < Duration::from_secs(2),
        "wait/list took {elapsed:?}"
    );
}

#[test]
fn owned_receiver_wait_respects_deadline_with_partial_identity_reply() {
    use std::os::unix::net::UnixListener;
    let t = Tmp::new();
    let registry = t.path(".syq-destinations-v3");
    fs::create_dir(&registry).unwrap();
    fs::set_permissions(&registry, fs::Permissions::from_mode(0o700)).unwrap();
    let socket_path = t.path("receiver.sock");
    let listener = UnixListener::bind(&socket_path).unwrap();
    listener.set_nonblocking(true).unwrap();
    let key = ssh_key::PrivateKey::new(
        ssh_key::private::Ed25519Keypair::from_seed(&[1; 32]).into(),
        "test",
    )
    .unwrap();
    for (extension, value) in [
        (
            "json",
            serde_json::json!({"version":3,"identity":"test-build",
            "socket":socket_path,"secret":"test","program":env!("CARGO_BIN_EXE_syq").as_bytes()}),
        ),
        (
            "owner",
            serde_json::json!({"version":1,"public_key":key.public_key().to_openssh().unwrap()}),
        ),
    ] {
        let path = registry.join(format!("laptop.{extension}"));
        write(&path, &serde_json::to_vec(&value).unwrap());
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let (stop_tx, stop_rx) = std::sync::mpsc::channel();
    let responder = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut socket = loop {
            match listener.accept() {
                Ok((socket, _)) => {
                    // BSD accepted sockets inherit the listener's nonblocking mode.
                    socket.set_nonblocking(false).unwrap();
                    break socket;
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        && std::time::Instant::now() < deadline =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(10))
                }
                Err(e) => panic!("receiver accept: {e}"),
            }
        };
        // Keep making partial framing progress beyond the one-second deadline.
        for byte in 100u32.to_be_bytes() {
            if socket.write_all(&[byte]).is_err() {
                break;
            }
            if stop_rx
                .recv_timeout(std::time::Duration::from_millis(400))
                .is_ok()
            {
                return;
            }
        }
        let _ = stop_rx.recv_timeout(std::time::Duration::from_secs(2));
    });
    let start = std::time::Instant::now();
    let output = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "persist",
            "destinations",
            "wait",
            "laptop",
            "--timeout",
            "1",
        ])
        .env("HOME", t.path(""))
        .env("SYQ_NO_UPDATE_CHECK", "1")
        .capture_output()
        .unwrap();
    let elapsed = start.elapsed();
    // The reply stays incomplete until the client exits; fixture cleanup does
    // not need to consume the rest of the artificial server delay.
    let _ = stop_tx.send(());
    responder.join().unwrap();
    assert!(!output.status.success());
    assert!(
        stderr_of(&output).contains("timed out waiting"),
        "{}",
        stderr_of(&output)
    );
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "wait took {elapsed:?}"
    );
}

#[test]
fn receiving_preferences_are_durable_default_on_and_distinguish_cwd_from_root() {
    let t = Tmp::new();
    let _persistence = PersistenceOff(&t);
    fs::create_dir(t.path("downloads")).unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_syq"))
            .args(args)
            .env("HOME", t.path(""))
            .env("XDG_CONFIG_HOME", t.path("config"))
            .env("XDG_RUNTIME_DIR", t.runtime())
            .env("SYQ_NO_UPDATE_CHECK", "1")
            .current_dir(t.path(""))
            .capture_output()
            .unwrap()
    };
    let status = || {
        let output = run(&["persist", "receive", "status", "--json"]);
        assert_output_ok(&output);
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };
    let defaults = status();
    assert_eq!(defaults["settings"]["enabled"], true);
    assert!(defaults["settings"]["auto_approve_root"].is_null());
    assert_eq!(defaults["settings"]["cwd_explicit"], false);
    assert_eq!(defaults["settings"]["notifications"], "desktop");
    assert_eq!(
        defaults["settings"]["cwd"],
        fs::canonicalize(t.path("")).unwrap().to_str().unwrap()
    );
    assert!(defaults["settings"]["root"].is_null());
    assert!(!t.path("config").exists(), "status created configuration");
    assert!(!t.runtime().exists(), "status created a runtime scope");
    fs::create_dir(t.runtime()).unwrap();
    assert_output_ok(&run(&[
        "persist",
        "receive",
        "on",
        "--name",
        "laptop",
        "--root",
        "downloads",
    ]));
    assert_eq!(status()["settings"]["root"], t.s("downloads"));
    assert_output_ok(&run(&[
        "persist",
        "receive",
        "on",
        "--cwd",
        ".",
        "--no-root",
    ]));
    assert!(status()["settings"]["root"].is_null());
    assert_eq!(status()["settings"]["name"], "laptop");
    assert_output_ok(&run(&[
        "persist",
        "receive",
        "on",
        "--auto-approve-root",
        "downloads",
        "--notify",
        "off",
    ]));
    assert_eq!(status()["settings"]["auto_approve_root"], t.s("downloads"));
    assert_eq!(status()["settings"]["notifications"], "off");
    assert_output_ok(&run(&["persist", "receive", "on", "--max-entries", "500"]));
    assert_eq!(status()["settings"]["auto_approve_root"], t.s("downloads"));
    assert_output_ok(&run(&[
        "persist",
        "receive",
        "on",
        "--no-auto-approve-root",
    ]));
    assert!(status()["settings"]["auto_approve_root"].is_null());
    assert_output_ok(&run(&["persist", "receive", "off"]));
    assert_eq!(status()["settings"]["enabled"], false);
    let persistence: serde_json::Value =
        serde_json::from_slice(&read(&t.path("config/syq/persistence.json"))).unwrap();
    assert_eq!(persistence["enabled"], true);
    assert_eq!(
        fs::metadata(t.path("config/syq/receive.json"))
            .unwrap()
            .mode()
            & 0o777,
        0o600
    );
    assert!(!run(&[
        "persist",
        "receive",
        "on",
        "--cwd",
        ".",
        "--root",
        "downloads"
    ])
    .status
    .success());
}

#[test]
fn receiving_automatic_cwd_and_server_scope_are_independent() {
    let t = Tmp::new();
    fs::create_dir(t.runtime()).unwrap();
    let _persistence = PersistenceOff(&t);
    fs::create_dir_all(t.path("root/inbox")).unwrap();
    fs::create_dir_all(t.path("root/explicit")).unwrap();
    executable_support::write_executable(&t.path("bin/ssh"), b"#!/bin/sh\nif [ \"$1\" = -V ]; then echo OpenSSH_9.2p1 >&2; exit 0; fi\nprintf '%s\\n' \"$*\" >> \"$SSH_LOG\"\necho fixture connection unavailable >&2\nexit 42\n", 0o700);
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_syq"))
            .args(["persist", "receive"])
            .args(args)
            .env("HOME", t.path(""))
            .env("XDG_CONFIG_HOME", t.path("config"))
            .env("XDG_RUNTIME_DIR", t.runtime())
            .env("SYQ_NO_UPDATE_CHECK", "1")
            .env("SSH_LOG", t.path("ssh.log"))
            .env("PATH", format!("{}:/usr/bin:/bin", t.path("bin").display()))
            .current_dir(t.path(""))
            .capture_output()
            .unwrap()
    };
    let state = || {
        let output = run(&["status", "--json"]);
        assert_output_ok(&output);
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()["settings"].clone()
    };
    let configured = |args: &[&str]| {
        let output = run(args);
        if !args.contains(&"--connection") {
            assert_output_ok(&output);
        } else {
            assert!(!output.status.success());
            assert!(
                stderr_of(&output).contains("receiving settings saved"),
                "{}",
                stderr_of(&output)
            );
        }
    };
    configured(&[
        "on",
        "--auto-approve-root",
        "root/inbox",
        "--connection",
        "work",
        "--connection",
        "alice@lab:2222",
    ]);
    assert_eq!(state()["cwd"], t.s("root/inbox"));
    assert_eq!(state()["cwd_explicit"], false);
    assert_eq!(
        state()["servers"],
        serde_json::json!(["work", "alice@lab:2222"])
    );
    // Preserve a genuine endpoint record and a stopped receiving supervisor's
    // saved spec. Neither is a request to dial the dormant connection again.
    let scope = t
        .runtime()
        .join(format!("syq-persist-{}/global", unsafe { libc::geteuid() }));
    let record = fs::read_dir(&scope)
        .unwrap()
        .filter_map(Result::ok)
        .find_map(|entry| {
            let path = entry.path();
            if path.file_name()?.to_str()?.starts_with("cm-")
                && path.extension()?.to_str()? == "json"
            {
                let endpoint: serde_json::Value =
                    serde_json::from_slice(&fs::read(&path).ok()?).ok()?;
                (endpoint["host"] == "work").then_some((path, endpoint))
            } else {
                None
            }
        })
        .expect("failed explicit connect should leave its endpoint record");
    let build = Command::new(env!("CARGO_BIN_EXE_syq"))
        .arg("--build-identity")
        .capture_output()
        .unwrap();
    assert_output_ok(&build);
    let spec = record.0.with_extension("recv-json");
    fs::write(
        &spec,
        serde_json::to_vec(&serde_json::json!({
            "version":2, "identity":String::from_utf8(build.stdout).unwrap().trim(),
            "endpoint":record.1, "program":env!("CARGO_BIN_EXE_syq")
        }))
        .unwrap(),
    )
    .unwrap();
    fs::set_permissions(&spec, fs::Permissions::from_mode(0o600)).unwrap();
    let connections = fs::read(t.path("ssh.log")).unwrap();
    assert!(
        !connections.is_empty(),
        "explicit connections did not run SSH"
    );
    let before = fs::read(t.path("config/syq/receive.json")).unwrap();
    configured(&["on"]);
    assert_eq!(fs::read(t.path("config/syq/receive.json")).unwrap(), before);
    configured(&["on", "--notify", "off"]);
    assert_eq!(
        state()["servers"],
        serde_json::json!(["work", "alice@lab:2222"])
    );
    assert_output_ok(&run(&["off"]));
    configured(&["on"]);
    assert!(!run(&["wait", "work", "--timeout", "1"]).status.success());
    let output = run(&["status", "--json"]);
    assert_output_ok(&output);
    let status: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let dormant = status["connections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|state| state["endpoint"] == "work")
        .unwrap();
    assert_eq!(dormant["connection"]["phase"], "inactive");
    assert_eq!(fs::read(t.path("ssh.log")).unwrap(), connections);
    assert!(!run(&["wait", "other", "--timeout", "1"]).status.success());
    configured(&["on", "--root", "root"]);
    assert_eq!(state()["cwd"], t.s("root"));
    configured(&["on", "--cwd", "root/explicit"]);
    assert_eq!(state()["root"], t.s("root"));
    configured(&["on", "--no-auto-approve-root"]);
    assert_eq!(state()["cwd"], t.s("root/explicit"));
    configured(&["on", "--auto-cwd", "--auto-approve-root", "root/inbox"]);
    assert_eq!(state()["cwd"], t.s("root"));
    configured(&["on", "--no-root"]);
    assert_eq!(state()["cwd"], t.s("root/inbox"));
    configured(&["on", "--no-auto-approve-root", "--all-connections"]);
    assert_eq!(
        state()["cwd"],
        fs::canonicalize(t.path("")).unwrap().to_str().unwrap()
    );
    assert_eq!(state()["servers"], serde_json::json!([]));
    assert_eq!(fs::read(t.path("ssh.log")).unwrap(), connections);
    let before = fs::read(t.path("config/syq/receive.json")).unwrap();
    for args in [
        vec!["on", "--auto-approve-root", "missing"],
        vec!["on", "--connection", ""],
        vec!["on", "--cwd", ".", "--root", "root"],
        vec!["on", "--auto-approve-root", "/"],
        vec!["on", "--approve", "always"],
    ] {
        assert!(!run(&args).status.success(), "{args:?}");
        assert_eq!(fs::read(t.path("config/syq/receive.json")).unwrap(), before);
    }
}

#[test]
fn receiver_destinations_require_sigil_and_never_fall_back() {
    use std::os::unix::net::UnixListener;
    let t = Tmp::new();
    write(&t.path("source"), b"source");
    executable_support::write_executable(&t.path("bin/ssh"), b"#!/bin/sh\nif [ \"$1\" = -V ]; then echo OpenSSH_9.2p1 >&2; exit 0; fi\n: > \"$SSH_MARKER\"\nexit 55\n", 0o700);
    let mut path = vec![t.path("bin")];
    path.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    let path = std::env::join_paths(path).unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_syq"))
            .args(args)
            .env("HOME", t.path(""))
            .env("XDG_CONFIG_HOME", t.path("config"))
            .env("XDG_RUNTIME_DIR", t.path("runtime"))
            .env("PATH", &path)
            .env("SSH_MARKER", t.path("ssh-used"))
            .env("SYQ_NO_UPDATE_CHECK", "1")
            .current_dir(t.path(""))
            .capture_output()
            .unwrap()
    };
    let identity = String::from_utf8(run(&["--build-identity"]).stdout).unwrap();
    let registry = t.path(".syq-destinations-v3");
    fs::create_dir(&registry).unwrap();
    fs::set_permissions(&registry, fs::Permissions::from_mode(0o700)).unwrap();
    let socket_path = t.path("return.sock");
    let registration = serde_json::json!({"version":3,"identity":identity.trim(),"socket":socket_path,"secret":"test","program":env!("CARGO_BIN_EXE_syq").as_bytes()});
    write(
        &registry.join("laptop.json"),
        &serde_json::to_vec(&registration).unwrap(),
    );
    fs::set_permissions(
        registry.join("laptop.json"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let offline = run(&[
        "cp",
        "source",
        "--to",
        "laptop",
        "--syq-path",
        "/test/helper",
    ]);
    assert!(!offline.status.success());
    assert!(
        t.path("ssh-used").exists(),
        "offline bare name did not use SSH: {}",
        stderr_of(&offline)
    );
    fs::remove_file(t.path("ssh-used")).unwrap();
    let explicit = run(&["cp", "source", "--to", "@laptop"]);
    assert!(!explicit.status.success());
    let error = stderr_of(&explicit);
    assert!(
        error.contains("could not reach the receiving machine"),
        "{error}"
    );
    assert!(!error.contains("offline"), "{error}");
    assert!(
        error.contains("run `syq persist connect HOST` on that machine"),
        "{error}"
    );
    assert!(!t.path("ssh-used").exists());
    // An older process can hand a selected bare receiver to this helper.
    // Reject that spelling rather than reinterpret its pinned destination as SSH.
    let guard_registration = format!(
        r#"{{"version":3,"identity":{},"socket":{},"secret":"test","program":{}}}"#,
        serde_json::to_string(identity.trim()).unwrap(),
        serde_json::to_string(&socket_path).unwrap(),
        serde_json::to_string(env!("CARGO_BIN_EXE_syq").as_bytes()).unwrap(),
    );
    let guard = serde_json::json!({"name":"laptop","identity":identity.trim(),
        "kind":"Copy","registration":blake3::hash(guard_registration.as_bytes()).to_hex().to_string()})
    .to_string();
    let handed_off = run(&[
        "--return-handoff-v1",
        &guard,
        "cp",
        "source",
        "--to",
        "laptop",
    ]);
    assert!(!handed_off.status.success());
    assert!(
        stderr_of(&handed_off).contains("receiver destinations require @NAME"),
        "{}",
        stderr_of(&handed_off)
    );
    assert!(!t.path("ssh-used").exists());
    let listener = UnixListener::bind(&socket_path).unwrap();
    listener.set_nonblocking(true).unwrap();
    let bare = run(&["cp", "source", "--to", "laptop", "--no-tcp"]);
    assert!(!bare.status.success());
    assert!(t.path("ssh-used").exists());
    fs::remove_file(t.path("ssh-used")).unwrap();
    let responder = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        for response in [serde_json::json!({"Error":"copy denied by test policy"})] {
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => {
                        // BSD accepted sockets inherit the listener's nonblocking mode.
                        socket.set_nonblocking(false).unwrap();
                        break socket;
                    }
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            && std::time::Instant::now() < deadline =>
                    {
                        std::thread::sleep(std::time::Duration::from_millis(10))
                    }
                    Err(e) => panic!("return test connection: {e}"),
                }
            };
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
            let mut length = [0; 4];
            socket.read_exact(&mut length).unwrap();
            let length = u32::from_be_bytes(length) as usize;
            assert!(length < 256 * 1024);
            let mut request = vec![0; length];
            socket.read_exact(&mut request).unwrap();
            let response = serde_json::to_vec(&response).unwrap();
            socket
                .write_all(&(response.len() as u32).to_be_bytes())
                .unwrap();
            socket.write_all(&response).unwrap();
        }
    });
    let denied = run(&["cp", "source", "--to", "@laptop"]);
    responder.join().unwrap();
    assert!(!denied.status.success());
    assert!(
        stderr_of(&denied).contains("copy denied by test policy"),
        "{}",
        stderr_of(&denied)
    );
    assert!(
        !t.path("ssh-used").exists(),
        "a denied return copy switched to SSH"
    );
}

/// A leading `@NAME` is a receiving name in every command, never an SSH login
/// with an empty user name. An unknown name, or a command that cannot use a
/// receiving machine, fails at once and says what to do, without running ssh.
#[test]
fn unknown_receiving_names_never_reach_ssh_and_say_what_to_do() {
    let t = Tmp::new();
    write(&t.path("source"), b"source");
    let recorder = b"#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$SSH_MARKER\"\nexit 255\n";
    executable_support::write_executable(&t.path("bin/ssh"), recorder, 0o700);
    executable_support::write_executable(&t.path("bin/record-rsh"), recorder, 0o700);
    let rsh = t.s("bin/record-rsh");
    let mut path = vec![t.path("bin")];
    path.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    let path = std::env::join_paths(path).unwrap();
    let syq = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_syq"))
            .args(args)
            .env("HOME", t.path(""))
            .env("XDG_CONFIG_HOME", t.path("config"))
            .env("XDG_STATE_HOME", t.path("state"))
            .env("XDG_CACHE_HOME", t.path("cache"))
            .env("XDG_RUNTIME_DIR", t.runtime())
            .env("PATH", &path)
            .env("SSH_MARKER", t.path("ssh-used"))
            .env("SYQ_NO_UPDATE_CHECK", "1")
            .env_remove("SYQ_AUTH_FROM")
            .current_dir(t.path(""))
            .stdin(Stdio::null())
            .capture_output()
            .unwrap()
    };
    // Refused before receiving settings are saved.
    let refused = syq(&["persist", "receive", "on", "--connection", "@master"]);
    assert!(!refused.status.success());
    assert!(
        stderr_of(&refused).contains("@master is a receiving name, not an SSH server: --connection takes the SSH server this machine should connect to"),
        "{}",
        stderr_of(&refused)
    );
    assert!(!t.path("config").exists(), "receiving settings were saved");
    // Control: the same commands with an SSH host do reach both recorders.
    for args in [
        &["cp", ".kube", "--from", "server"][..],
        &["rsync", "-e", &rsh, "server:.kube", "copy/"],
    ] {
        let output = syq(args);
        assert!(!output.status.success(), "{args:?}");
        assert!(
            t.path("ssh-used").exists(),
            "{args:?} did not run ssh: {}",
            stderr_of(&output)
        );
        fs::remove_file(t.path("ssh-used")).unwrap();
    }
    let run = |args: &[&str]| {
        let output = syq(args);
        let error = stderr_of(&output);
        assert!(!output.status.success(), "{args:?} succeeded: {error}");
        assert!(
            !t.path("ssh-used").exists(),
            "{args:?} ran ssh: {}\n{error}",
            String::from_utf8_lossy(&fs::read(t.path("ssh-used")).unwrap())
        );
        error
    };
    let copy_from = [
        "cannot copy from receiving machine @master",
        "run `syq cp PATH --to HOST` on it, where HOST is how it reaches this server",
    ];
    for args in [
        &["cp", ".kube", "--from", "@master"][..],
        &["cp", ".kube", "--from", "@master", "--rsh", &rsh],
        &["cp", ".kube", "--from", "@master", "--to", "server"],
        &["rsync", "-e", &rsh, "@master:.kube", "copy/"],
    ] {
        let error = run(args);
        for expected in copy_from {
            assert!(error.contains(expected), "{args:?}: {error}");
        }
    }
    let error = run(&["rsync", "-e", &rsh, "source", "@master:copy"]);
    assert!(
        error.contains("receiving machine @master cannot be used with syq rsync")
            && error.contains("`syq cp SOURCE --to @master`"),
        "{error}"
    );
    for (args, command) in [
        (&["rm", "--on", "@master", "x"][..], "syq rm"),
        (&["map", "--from", "@master", "x"], "syq map"),
    ] {
        let error = run(args);
        assert!(
            error.contains(&format!(
                "receiving machine @master cannot be used with {command}"
            )) && error.contains("`syq exec --on @master -- COMMAND`"),
            "{error}"
        );
    }
    let error = run(&["ssh", "@master"]);
    assert!(
        error.contains("@master is a receiving name, not an SSH server")
            && error.contains("`syq exec --on @master -- COMMAND`"),
        "{error}"
    );
    let error = run(&["persist", "connect", "@master"]);
    assert!(
        error.contains("@master is a receiving name, not an SSH server: run `syq persist connect HOST` on the receiving machine itself"),
        "{error}"
    );
    // A supported command with an unknown name says which names exist and
    // how the receiving machine connects.
    let unknown = |registered: &str| {
        for args in [
            &["cp", "source", "--to", "@master"][..],
            &["cp", "source", "--to", "@master", "--rsh", &rsh],
            &["exec", "--on", "@master", "--", "true"],
        ] {
            let error = run(args);
            assert!(
                error.contains(&format!(
                    "no receiving machine named @master is connected to this server account{registered}"
                )),
                "{args:?}: {error}"
            );
            assert!(
                error.contains("To connect a receiving machine, run `syq persist connect HOST` on it (for example your laptop), where HOST is how it reaches this server"),
                "{error}"
            );
            assert!(!error.contains("restarted"), "{error}");
        }
    };
    unknown(".");
    // Looking up a name creates the private registry directory.
    let registry = t.path(".syq-destinations-v3");
    fs::create_dir_all(&registry).unwrap();
    fs::set_permissions(&registry, fs::Permissions::from_mode(0o700)).unwrap();
    write(&registry.join("laptop.json"), b"{}");
    unknown("; did you mean @laptop?");
    write(&registry.join("desk.json"), b"{}");
    unknown(". Names registered here: @desk, @laptop.");
}

#[test]
fn receive_preferences_under_a_relative_config_home_are_ignored() {
    let t = Tmp::new();
    // A directory the command runs in could supply receive preferences with an
    // automatic-approval root, which a relative config root would load.
    fs::create_dir_all(t.path("work/inbox")).unwrap();
    fs::create_dir(t.path("home")).unwrap();
    let planted = t.path("work/config/syq/receive.json");
    let preferences = serde_json::json!({
        "version": 5,
        "profiles": [{
            "version": 5,
            "enabled": true,
            "name": "planted",
            "cwd": t.s("work/inbox"),
            "root": null,
            "auto_approve_root": t.s("work/inbox"),
            "servers": [],
            "max_bytes": 1000,
            "max_entries": 10,
            "max_delete": 0
        }]
    });
    write(&planted, &serde_json::to_vec(&preferences).unwrap());
    fs::set_permissions(&planted, fs::Permissions::from_mode(0o600)).unwrap();
    let status = |config: &str| {
        let output = Command::new(env!("CARGO_BIN_EXE_syq"))
            .args(["persist", "receive", "status", "--json"])
            .current_dir(t.path("work"))
            .env("HOME", t.path("home"))
            .env("XDG_CONFIG_HOME", config)
            .env("XDG_RUNTIME_DIR", t.runtime())
            .env("SYQ_NO_UPDATE_CHECK", "1")
            .capture_output()
            .unwrap();
        assert_output_ok(&output);
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };
    // The planted file is valid: an absolute config root loads it.
    let absolute = status(&t.s("work/config"));
    assert_eq!(absolute["settings"]["auto_approve_root"], t.s("work/inbox"));
    let relative = status("config");
    assert!(
        relative["settings"]["auto_approve_root"].is_null(),
        "{relative}"
    );
    assert_ne!(relative["settings"]["name"], "planted");
}

#[test]
fn receiving_v2_preferences_migrate_without_retaining_implicit_approval() {
    let t = Tmp::new();
    fs::create_dir(t.runtime()).unwrap();
    let _persistence = PersistenceOff(&t);
    let path = t.path("config/syq/receive.json");
    // Exact output of the PR #233 binary at 34eba8d, not regenerated by this writer.
    let old = include_bytes!("../fixtures/receive-v2.json");
    write(&path, old);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_syq"))
            .args(args)
            .env("HOME", t.path(""))
            .env("XDG_CONFIG_HOME", t.path("config"))
            .env("XDG_RUNTIME_DIR", t.runtime())
            .env("SYQ_NO_UPDATE_CHECK", "1")
            .capture_output()
            .unwrap()
    };
    let output = run(&["persist", "receive", "status", "--json"]);
    assert_output_ok(&output);
    let status: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(status["settings"]["auto_approve_root"].is_null());
    assert_eq!(
        fs::read(&path).unwrap(),
        old,
        "read-only status mutated old state"
    );
    assert_output_ok(&run(&["persist", "receive", "on"]));
    let migrated: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let original: serde_json::Value = serde_json::from_slice(old).unwrap();
    for field in [
        "enabled",
        "name",
        "cwd",
        "root",
        "max_bytes",
        "max_entries",
        "max_delete",
    ] {
        assert_eq!(migrated["profiles"][0][field], original[field], "{field}");
    }
    assert_eq!(migrated["version"], 5);
    assert!(migrated["profiles"][0]["auto_approve_root"].is_null());
    assert_eq!(migrated["profiles"][0]["notifications"], "desktop");
    let persistence: serde_json::Value =
        serde_json::from_slice(&read(&t.path("config/syq/persistence.json"))).unwrap();
    assert_eq!(persistence["enabled"], true);
    assert_output_ok(&run(&["persist", "receive", "off"]));
}

#[test]
fn return_via_requires_approval_and_rejects_unsupported_routes() {
    let t = Tmp::new();
    write(&t.path("source"), b"payload");
    executable(
        &t.path("bin/ssh"),
        b"#!/bin/sh\ntouch \"$HOME/ssh-used\"\nexit 99\n",
    );
    for option in ["--auth-from"] {
        for extra in [
            vec![],
            vec!["--no-tcp"],
            vec!["--no-tcp-encryption"],
            vec!["--detach"],
            vec!["--rsh", "ssh"],
            vec!["--syq-path", "/opt/syq"],
            vec!["--no-bootstrap"],
            vec!["--coordinate-at", "dst"],
            vec!["--peer-auth", "full-agent"],
        ] {
            let output = Command::new(env!("CARGO_BIN_EXE_syq"))
                .args(["cp", "source", "--to", "backup", option, "@laptop"])
                .args(extra)
                .current_dir(t.path(""))
                .env("HOME", t.path(""))
                .env("XDG_CONFIG_HOME", t.path("config"))
                .env("XDG_RUNTIME_DIR", t.path("runtime"))
                .env("PATH", t.path("bin"))
                .env("SYQ_NO_UPDATE_CHECK", "1")
                .capture_output()
                .unwrap();
            assert!(!output.status.success(), "{:?}", output);
            assert!(
                !t.path("ssh-used").exists(),
                "--via attempted ordinary SSH: {:?}",
                output
            );
        }
    }
    assert_eq!(fs::read(t.path("source")).unwrap(), b"payload");
}

#[test]
fn remote_copy_addition_preserves_approval_preferences_from_f752ee8() {
    let t = Tmp::new();
    let path = t.path("config/syq/receive.json");
    // Produced by the unchanged PR #240 f752ee8 executable, not this writer.
    let old = include_bytes!("../fixtures/receive-v3-f752ee8.json");
    write(&path, old);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["persist", "receive", "status", "--json"])
        .env("HOME", t.path(""))
        .env("XDG_CONFIG_HOME", t.path("config"))
        .env("XDG_RUNTIME_DIR", t.path("runtime"))
        .env("SYQ_NO_UPDATE_CHECK", "1")
        .capture_output()
        .unwrap();
    assert_output_ok(&output);
    let status: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let previous: serde_json::Value = serde_json::from_slice(old).unwrap();
    for key in [
        "name",
        "cwd",
        "root",
        "max_bytes",
        "max_entries",
        "max_delete",
        "notifications",
    ] {
        assert_eq!(status["settings"][key], previous[key]);
    }
    assert!(status["settings"]["auto_approve_root"].is_null());
    assert_eq!(status["settings"]["cwd_explicit"], true);
    assert_eq!(fs::read(path).unwrap(), old);
}

#[test]
fn automatic_authorization_reuses_working_ssh_without_contacting_receivers() {
    use std::os::unix::net::UnixListener;
    let t = Tmp::new();
    write(&t.path("source"), b"payload");
    let script = t.path("bin/ssh");
    executable(&script, b"#!/bin/sh\nif [ \"$1\" = -V ]; then echo OpenSSH_9.2p1 >&2; exit 0; fi\necho connect >> \"$HOME/ssh-used\"\nif [ -n \"$SYQ_TEST_SSH_READY\" ]; then\n  : > \"$SYQ_TEST_SSH_READY\"\n  n=0\n  while [ ! -e \"$SYQ_TEST_SSH_CONTINUE\" ]; do\n    n=$((n + 1))\n    if [ \"$n\" -ge 50 ]; then echo \"SSH fixture timed out waiting for release\" >&2; exit 1; fi\n    if [ \"$((n % 10))\" -eq 0 ]; then echo \"SSH fixture waiting for release\" >&2; fi\n    sleep 0.1\n  done\nfi\nsleep 0.2\nexec \"$SYQ_TEST_REMOTE_BINARY\" --server\n");
    let mut paths = vec![t.path("bin")];
    paths.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap()));
    let paths = std::env::join_paths(paths).unwrap();
    let command = |args: &[&str]| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
        command
            .args(args)
            .env("HOME", t.path(""))
            .env("XDG_CONFIG_HOME", t.path("config"))
            .env("XDG_RUNTIME_DIR", t.runtime())
            .env("PATH", &paths)
            .env("SYQ_TEST_REMOTE_BINARY", env!("CARGO_BIN_EXE_syq"))
            .env("SYQ_NO_UPDATE_CHECK", "1")
            .current_dir(t.path(""));
        command
    };
    let run = |args: &[&str]| command(args).capture_output().unwrap();
    let identity = String::from_utf8(run(&["--build-identity"]).stdout).unwrap();
    let registry = t.path(".syq-destinations-v3");
    fs::create_dir(&registry).unwrap();
    fs::set_permissions(&registry, fs::Permissions::from_mode(0o700)).unwrap();
    let socket_path = t.path("return.sock");
    let registration = serde_json::json!({"version":3,"identity":identity.trim(),
        "socket":socket_path,"secret":"test","program":env!("CARGO_BIN_EXE_syq").as_bytes()});
    let file = registry.join("laptop.json");
    write(&file, &serde_json::to_vec(&registration).unwrap());
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    let listener = UnixListener::bind(socket_path).unwrap();
    listener.set_nonblocking(true).unwrap();

    for compression in [None, Some("--no-compress")] {
        let destination = t.s("destination");
        let mut args = vec![
            "cp",
            "source",
            "--to",
            "127.0.0.1",
            "--as",
            &destination,
            "--tcp-ports",
            EPHEMERAL_TCP_PORTS,
            "--performance-tuning=workers=1",
            "--results=result.ndjson",
        ];
        args.extend(compression);
        let output = run(&args);
        assert_output_ok(&output);
        let terminal: serde_json::Value = serde_json::from_str(
            fs::read_to_string(t.path("result.ndjson"))
                .unwrap()
                .lines()
                .last()
                .unwrap(),
        )
        .unwrap();
        assert!(
            terminal["timings"]["total_ms"].as_u64().unwrap() >= 175,
            "SSH setup disappeared from elapsed time: {terminal}"
        );
        assert!(
            terminal["timings"]["setup_ms"].as_u64().unwrap() >= 175,
            "SSH authorization connection disappeared from setup time: {terminal}"
        );
        assert_eq!(fs::read(t.path("destination")).unwrap(), b"payload");
        assert_eq!(
            fs::read_to_string(t.path("ssh-used")).unwrap(),
            "connect\n",
            "the successful SSH connection must be reused"
        );
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        fs::remove_file(t.path("destination")).unwrap();
        fs::remove_file(t.path("ssh-used")).unwrap();
        fs::remove_file(t.path("result.ndjson")).unwrap();
    }
    // Both starts must reach their barriers before either is released. Keep
    // the registered directory when its display path is replaced while SSH
    // connects; repeat operands must not register a second root.
    #[cfg(debug_assertions)]
    {
        write(&t.path("tree/original"), b"pinned source");
        write(&t.path("outside/replacement"), b"outside");
        let ready = t.path("source-ready");
        let continuation = t.path("source-continue");
        let ssh_ready = t.path("ssh-ready");
        let ssh_continue = t.path("ssh-continue");
        let mut child = command(&[
            "cp",
            "tree",
            "tree",
            "--to",
            "127.0.0.1",
            "--into",
            &t.s("overlap"),
            "--performance-tuning=workers=1",
            "--tcp-ports",
            EPHEMERAL_TCP_PORTS,
        ])
        .env("SYQ_TEST_SOURCE_ROOTS_REGISTERED_FILE", &ready)
        .env("SYQ_TEST_SOURCE_ROOTS_CONTINUE_FILE", &continuation)
        .env("SYQ_TEST_SSH_READY", &ssh_ready)
        .env("SYQ_TEST_SSH_CONTINUE", &ssh_continue)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .start()
        .unwrap();
        wait_for_confinement_marker(&mut child, &ssh_ready, "destination SSH start");
        wait_for_confinement_marker(&mut child, &ready, "source registration during SSH setup");
        fs::rename(t.path("tree"), t.path("selected-tree")).unwrap();
        std::os::unix::fs::symlink(t.path("outside"), t.path("tree")).unwrap();
        release_confinement_barrier(&continuation);
        release_confinement_barrier(&ssh_continue);
        let output = wait_for_child_output(child, std::time::Duration::from_secs(10));
        assert_output_ok(&output);
        assert_eq!(
            fs::read(t.path("overlap/tree/original")).unwrap(),
            b"pinned source"
        );
        assert!(!t.path("overlap/tree/replacement").exists());
        fs::remove_file(t.path("ssh-used")).unwrap();
    }
    // Successful authentication does not permit switching authority after a
    // destination filesystem error.
    write(&t.path("parent-is-file"), b"unchanged");
    let failed = run(&[
        "cp",
        "source",
        "--to",
        "127.0.0.1",
        "--as",
        &t.s("parent-is-file/child"),
    ]);
    assert!(!failed.status.success());
    assert_eq!(fs::read(t.path("parent-is-file")).unwrap(), b"unchanged");
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );

    for diagnostic in [
        "ssh: connect to host backup port 22: Connection timed out",
        "Connection timed out during banner exchange",
        "ssh: Could not resolve hostname backup: Operation timed out",
        "ssh: Could not resolve hostname backup: Temporary failure in name resolution",
        "ssh: Could not resolve hostname backup: Try again",
        "ssh: connect to host backup port 22: Network is unreachable",
        "ssh: connect to host backup port 22: Permission denied",
        "user@backup: Permission denied (publickey).\nConnection to backup timed out",
        "",
    ] {
        executable(
            &script,
            br#"#!/bin/sh
if [ "$1" = -V ]; then echo OpenSSH_9.2p1 >&2; exit 0; fi
printf '%s\n' "$@" > "$HOME/ssh-arguments"
printf '%s\n' "$SYQ_TEST_SSH_FAILURE" >&2
exit 255
"#,
        );
        let failed = command(&["cp", "source", "--to", "backup"])
            .env("SYQ_TEST_SSH_FAILURE", diagnostic)
            .capture_output()
            .unwrap();
        assert!(!failed.status.success());
        assert!(
            stderr_of(&failed).contains(diagnostic),
            "{}",
            stderr_of(&failed)
        );
        assert!(!stderr_of(&failed).contains("waiting up to"));
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        let arguments = fs::read_to_string(t.path("ssh-arguments")).unwrap();
        assert!(!arguments.contains("BatchMode"), "{arguments}");
        assert!(!arguments.contains("ConnectTimeout"), "{arguments}");
    }

    // A helper that exits unsuccessfully is not an SSH authentication failure.
    executable(&script, b"#!/bin/sh\nsleep 0.2\nexit 42\n");
    let failed = run(&[
        "cp",
        "source",
        "--to",
        "127.0.0.1",
        "--results=failed.ndjson",
    ]);
    assert!(!failed.status.success());
    let terminal: serde_json::Value = serde_json::from_str(
        fs::read_to_string(t.path("failed.ndjson"))
            .unwrap()
            .lines()
            .last()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(terminal["status"], "failed");
    assert!(
        terminal["timings"]["total_ms"].as_u64().unwrap() >= 175,
        "failed SSH setup disappeared from elapsed time: {terminal}"
    );
    assert!(
        terminal["timings"]["setup_ms"].as_u64().unwrap() >= 175,
        "{terminal}"
    );
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn automatic_authorization_tries_ssh_before_live_names_and_stops_after_a_refusal() {
    use std::os::unix::net::UnixListener;
    use std::time::{Duration, Instant};
    let t = Tmp::new();
    fs::create_dir(t.path("runtime")).unwrap();
    write(&t.path("source"), b"payload");
    executable_support::write_executable(&t.path("bin/ssh"), b"#!/bin/sh\nif [ \"$1\" = -V ]; then echo OpenSSH_8.9p1 >&2; exit 0; fi\nif [ \"$1\" = -G ]; then printf 'user fixture-user\\nhostname resolved-backup\\nport 2222\\nhostkeyalgorithms ssh-ed25519\\n'; exit 0; fi\necho connect >> \"$HOME/ssh-used\"\nprintf '%s\\n' \"${SYQ_TEST_SSH_FAILURE:-Permission denied (publickey).}\" >&2\nexit 255\n", 0o700);
    let mut paths = vec![t.path("bin")];
    paths.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap()));
    let paths = std::env::join_paths(paths).unwrap();
    let command = |args: &[&str]| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
        command
            .args(args)
            .env("HOME", t.path(""))
            .env("XDG_CONFIG_HOME", t.path("config"))
            .env("XDG_RUNTIME_DIR", t.path("runtime"))
            .env("PATH", &paths)
            .env("SYQ_NO_UPDATE_CHECK", "1")
            .env_remove("SSH_AUTH_SOCK")
            .env_remove("SYQ_AUTH_FROM")
            .env_remove("TMUX")
            .current_dir(t.path(""));
        command
    };
    let run = |args: &[&str]| command(args).capture_output().unwrap();
    let identity = String::from_utf8(run(&["--build-identity"]).stdout).unwrap();
    let registry = t.path(".syq-destinations-v3");
    fs::create_dir(&registry).unwrap();
    fs::set_permissions(&registry, fs::Permissions::from_mode(0o700)).unwrap();
    let socket_path = t.path("return.sock");
    for name in ["a-offline", "b-invalid", "laptop", "ssh", "z-other"] {
        let registration = serde_json::json!({
            "version": if name == "b-invalid" { 0 } else { 3 },
            "identity": identity.trim(),
            "program": env!("CARGO_BIN_EXE_syq").as_bytes(),
            "socket": if name == "a-offline" { t.path("absent.sock") } else { socket_path.clone() },
            "secret": name,
        });
        let file = registry.join(format!("{name}.json"));
        write(&file, &serde_json::to_vec(&registration).unwrap());
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let listener = UnixListener::bind(&socket_path).unwrap();
    listener.set_nonblocking(true).unwrap();
    let ssh_marker = t.path("ssh-used");
    let key = ssh_key::PrivateKey::new(
        ssh_key::private::Ed25519Keypair::from_seed(&[9; 32]).into(),
        "",
    )
    .unwrap()
    .public_key()
    .to_openssh()
    .unwrap();
    let resolved = serde_json::json!({
        "endpoint": {"user": "fixture-user", "host": "resolved-backup", "port": 2222},
        "host_algorithms": "ssh-ed25519",
        "known_hosts": format!("syq-approved-peer {key}\n"),
    });
    let responder = std::thread::spawn(move || {
        let mut messages = Vec::new();
        for _ in 0..12 {
            // The client first tries SSH, and later exercises commands that
            // must not contact this listener at all. Their process startup
            // time is not part of the authorization-ordering assertion.
            let deadline = Instant::now() + Duration::from_secs(60);
            let mut progress = Instant::now() + Duration::from_secs(5);
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => {
                        // BSD accepted sockets inherit the listener's nonblocking mode.
                        socket.set_nonblocking(false).unwrap();
                        break socket;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            Instant::now() < deadline,
                            "authorizer expected another request; saw {messages:?}"
                        );
                        if Instant::now() >= progress {
                            eprintln!("Waiting for authorization request; saw {messages:?}");
                            progress += Duration::from_secs(5);
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("{error}"),
                }
            };
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut length = [0; 4];
            socket.read_exact(&mut length).unwrap();
            let mut bytes = vec![0; u32::from_be_bytes(length) as usize];
            socket.read_exact(&mut bytes).unwrap();
            let envelope: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            let responses = if envelope["message"] == "Ping" {
                assert!(ssh_marker.exists(), "discovery preceded the SSH attempt");
                vec![serde_json::json!("Ready")]
            } else if let Some(target) = envelope["message"].get("ResolveLocalSsh") {
                assert_eq!(
                    target,
                    &serde_json::json!({
                        "requested": {"user": null, "host": "backup", "port": null},
                        "endpoint": {"user": "fixture-user", "host": "resolved-backup", "port": 2222},
                        "host_key_alias": null,
                    }),
                    "{envelope}"
                );
                assert!(
                    !ssh_marker.exists(),
                    "explicit account resolution tried native SSH"
                );
                vec![serde_json::json!("Ready"), resolved.clone()]
            } else if let Some(account) = envelope["message"].get("LocalSsh") {
                assert_eq!(
                    account["target"]["requested"]["host"], "backup",
                    "{envelope}"
                );
                assert_eq!(
                    account["target"]["endpoint"], resolved["endpoint"],
                    "{envelope}"
                );
                assert_eq!(account["expected"], resolved, "{envelope}");
                assert!(
                    !ssh_marker.exists(),
                    "explicit account selection tried native SSH"
                );
                vec![serde_json::json!({"Error": "account denied by fixture"})]
            } else {
                assert!(envelope["message"].get("Forward").is_some(), "{envelope}");
                vec![serde_json::json!({"Error": "copy denied by fixture"})]
            };
            messages.push(envelope);
            for response in responses {
                let bytes = serde_json::to_vec(&response).unwrap();
                socket
                    .write_all(&(bytes.len() as u32).to_be_bytes())
                    .unwrap();
                socket.write_all(&bytes).unwrap();
            }
        }
        messages
    });
    let refused = run(&[
        "cp",
        "source",
        "--to",
        "backup",
        "--if-exists=update-if-older",
        "--results",
        "result.ndjson",
    ]);
    assert!(
        stderr_of(&refused).contains("copy denied by fixture"),
        "{}",
        stderr_of(&refused)
    );
    assert!(!refused.status.success());
    assert_eq!(fs::read_to_string(t.path("ssh-used")).unwrap(), "connect\n");
    // This machine has no SSH credentials at all: asking the laptop is the
    // ordinary way to authorize the copy, so syq says only that it waits.
    assert!(
        !stderr_of(&refused).contains("asking @laptop"),
        "{}",
        stderr_of(&refused)
    );
    assert!(
        stderr_of(&refused).lines().any(|line| line
            == "syq: waiting up to 5 minutes for @laptop to approve this copy to backup; approve it there in the desktop prompt or with `syq persist receive pending`"),
        "{}",
        stderr_of(&refused)
    );
    fs::remove_file(t.path("ssh-used")).unwrap();
    let records: Vec<serde_json::Value> = fs::read_to_string(t.path("result.ndjson"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(records.last().unwrap()["status"], "failed");

    for (diagnostic, reason) in [
        (
            "Host key verification failed.",
            "host key verification failed on the source machine",
        ),
        (
            "ssh: Could not resolve hostname backup: Name or service not known",
            "destination hostname could not be resolved",
        ),
        (
            "ssh: connect to host backup port 22: Connection refused",
            "connection was refused",
        ),
    ] {
        let refused = command(&["cp", "source", "--to", "backup"])
            .env("SYQ_TEST_SSH_FAILURE", diagnostic)
            .capture_output()
            .unwrap();
        let stderr = stderr_of(&refused);
        assert!(!refused.status.success());
        assert!(stderr.contains("copy denied by fixture"), "{stderr}");
        assert!(stderr.contains(reason), "{stderr}");
        assert_eq!(fs::read_to_string(t.path("ssh-used")).unwrap(), "connect\n");
        fs::remove_file(t.path("ssh-used")).unwrap();
    }

    // Explicit SSH never asks a receiving machine.
    let output = run(&["cp", "source", "--to", "backup", "--auth-from", "ssh"]);
    assert!(!output.status.success());
    assert!(t.path("ssh-used").exists(), "{}", stderr_of(&output));
    fs::remove_file(t.path("ssh-used")).unwrap();
    let selected = run(&["cp", "source", "--to", "backup", "--auth-from", "@z-other"]);
    assert!(!selected.status.success());
    assert!(
        stderr_of(&selected).contains("account denied by fixture"),
        "{}",
        stderr_of(&selected)
    );
    assert!(!t.path("ssh-used").exists());

    // Captured from the unchanged released v0.4.0 SDK, not this CLI/SDK writer.
    let old: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/copy-via-v0.4.0.json")).unwrap();
    let argv: Vec<_> = old["argv"]
        .as_array()
        .unwrap()
        .iter()
        .map(|arg| arg.as_str().unwrap())
        .collect();
    let legacy = run(&argv);
    assert!(
        stderr_of(&legacy).contains("unexpected argument '--via'"),
        "{}",
        stderr_of(&legacy)
    );
    assert!(!t.path("ssh-used").exists());
    // The released fixture stays unchanged: its bare receiver reference is
    // explicitly rejected; --auth-from with an explicit @NAME is the recovery path.
    let explicit = run(&[
        "cp",
        "source",
        "--to",
        "backup",
        "--auth-from",
        "@ssh",
        "--into",
        "out",
    ]);
    assert!(!explicit.status.success());
    assert!(
        stderr_of(&explicit).contains("account denied by fixture"),
        "{}",
        stderr_of(&explicit)
    );
    assert!(!t.path("ssh-used").exists());
    let messages = responder.join().unwrap();
    assert_eq!(messages[0]["secret"], "laptop");
    assert_eq!(messages[0]["message"], "Ping");
    assert_eq!(messages[1]["secret"], "laptop");
    // The request carries the command, from which the laptop derives the
    // rules, and only what the command read from files beside it.
    let forward = &messages[1]["message"]["Forward"];
    assert_eq!(forward["command"][0], serde_json::json!(b"cp"));
    assert_eq!(forward["inputs"]["ignore"], serde_json::json!([]));
    assert!(forward.get("request").is_none(), "{forward}");
    for pair in messages[2..8].chunks_exact(2) {
        assert_eq!(pair[0]["secret"], "laptop");
        assert_eq!(pair[0]["message"], "Ping");
        assert!(pair[1]["message"].get("Forward").is_some());
    }
    for (pair, name) in messages[8..12].chunks_exact(2).zip(["z-other", "ssh"]) {
        assert_eq!(pair[0]["secret"], name);
        assert_eq!(pair[1]["secret"], name);
        assert_eq!(
            pair[0]["message"]["ResolveLocalSsh"]["requested"]["host"],
            "backup"
        );
        assert_eq!(
            pair[1]["message"]["LocalSsh"]["target"]["endpoint"],
            pair[0]["message"]["ResolveLocalSsh"]["endpoint"]
        );
    }
    // The registry remains, but every socket is now unavailable. Discovery
    // must allow ordinary SSH instead of treating stale names as reservations.
    let offline = run(&["cp", "source", "--to", "backup"]);
    assert!(!offline.status.success());
    assert_eq!(
        fs::read_to_string(t.path("ssh-used")).unwrap(),
        "connect\n",
        "SSH should be attempted once when no receiver answers: {}",
        stderr_of(&offline),
    );
    fs::remove_file(t.path("ssh-used")).unwrap();
    let host_key = command(&["cp", "source", "--to", "backup"])
        .env("SYQ_TEST_SSH_FAILURE", "Host key verification failed.")
        .capture_output()
        .unwrap();
    assert!(!host_key.status.success());
    let stderr = stderr_of(&host_key);
    assert!(
        stderr.lines().any(|line| line.starts_with("syq:")
            && line.contains("host key verification failed on the source machine")),
        "{stderr}"
    );
    assert_eq!(fs::read_to_string(t.path("ssh-used")).unwrap(), "connect\n");
}

/// A receiving machine for `auto` fallback tests: it answers discovery,
/// and holds each copy request until the test releases it, then refuses it.
struct HeldLaptop {
    t: Tmp,
    paths: std::ffi::OsString,
    requests: std::sync::mpsc::Receiver<serde_json::Value>,
    release: std::sync::mpsc::Sender<()>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Whether requests wait for the test, as for a person, or are refused
    /// at once, as a remembered decision would answer.
    holding: std::sync::Arc<std::sync::atomic::AtomicBool>,
    responder: Option<std::thread::JoinHandle<()>>,
}

impl HeldLaptop {
    fn new() -> Self {
        use std::os::unix::net::UnixListener;
        use std::time::Duration;
        let t = Tmp::new();
        fs::create_dir(t.path("runtime")).unwrap();
        write(&t.path("source"), b"payload");
        // ssh -G reports the default identity file; logging in is refused.
        executable_support::write_executable(
            &t.path("bin/ssh"),
            b"#!/bin/sh\nif [ \"$1\" = -V ]; then echo OpenSSH_8.9p1 >&2; exit 0; fi\nfor argument; do\n  if [ \"$argument\" = -G ]; then printf 'user fixture-user\\nhostname resolved-backup\\nport 2222\\nhostkeyalgorithms ssh-ed25519\\nidentityfile ~/.ssh/id_ed25519\\n'; exit 0; fi\ndone\nprintf '%s\\n' \"${SSH_AUTH_SOCK-unset}\" >> \"$HOME/ssh-used\"\necho 'fixture-user@backup: Permission denied (publickey).' >&2\nexit 255\n",
            0o700,
        );
        let mut paths = vec![t.path("bin")];
        paths.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap()));
        let paths = std::env::join_paths(paths).unwrap();
        let mut laptop = Self {
            t,
            paths,
            requests: std::sync::mpsc::channel().1,
            release: std::sync::mpsc::channel().0,
            stop: Default::default(),
            holding: std::sync::Arc::new(true.into()),
            responder: None,
        };
        let identity = String::from_utf8(
            laptop
                .command(&["--build-identity"])
                .capture_output()
                .unwrap()
                .stdout,
        )
        .unwrap();
        let registry = laptop.t.path(".syq-destinations-v3");
        fs::create_dir(&registry).unwrap();
        fs::set_permissions(&registry, fs::Permissions::from_mode(0o700)).unwrap();
        let socket_path = laptop.t.path("return.sock");
        let registration = serde_json::json!({
            "version": 3,
            "identity": identity.trim(),
            "program": env!("CARGO_BIN_EXE_syq").as_bytes(),
            "socket": socket_path,
            "secret": "laptop",
        });
        let file = registry.join("laptop.json");
        write(&file, &serde_json::to_vec(&registration).unwrap());
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        let listener = UnixListener::bind(&socket_path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let (request_sender, requests) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel::<()>();
        let stop = laptop.stop.clone();
        let holding = laptop.holding.clone();
        // What the laptop's SSH configuration says about backup, for
        // account access.
        let key = ssh_key::PrivateKey::new(
            ssh_key::private::Ed25519Keypair::from_seed(&[9; 32]).into(),
            "",
        )
        .unwrap()
        .public_key()
        .to_openssh()
        .unwrap();
        let resolved = serde_json::json!({
            "endpoint": {"user": "fixture-user", "host": "resolved-backup", "port": 2222},
            "host_algorithms": "ssh-ed25519",
            "known_hosts": format!("syq-approved-peer {key}\n"),
        });
        laptop.responder = Some(std::thread::spawn(move || {
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let mut socket = match listener.accept() {
                    Ok((socket, _)) => socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                    Err(error) => panic!("{error}"),
                };
                socket.set_nonblocking(false).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut length = [0; 4];
                socket.read_exact(&mut length).unwrap();
                let mut bytes = vec![0; u32::from_be_bytes(length) as usize];
                socket.read_exact(&mut bytes).unwrap();
                let envelope: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                let responses = if envelope["message"] == "Ping" {
                    vec![serde_json::json!("Ready")]
                } else if envelope["message"].get("ResolveLocalSsh").is_some() {
                    vec![serde_json::json!("Ready"), resolved.clone()]
                } else {
                    // A copy, or account access: what a person approves.
                    let hold = holding.load(std::sync::atomic::Ordering::Relaxed);
                    request_sender.send(envelope).unwrap();
                    if hold {
                        released
                            .recv_timeout(Duration::from_secs(60))
                            .expect("the test releases each held request");
                    }
                    vec![serde_json::json!({"Error": "denied by fixture"})]
                };
                for response in responses {
                    let bytes = serde_json::to_vec(&response).unwrap();
                    let _ = socket.write_all(&(bytes.len() as u32).to_be_bytes());
                    let _ = socket.write_all(&bytes);
                }
            }
        }));
        laptop.requests = requests;
        laptop.release = release;
        laptop
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
        command
            .args(args)
            .env("HOME", self.t.path(""))
            .env("XDG_CONFIG_HOME", self.t.path("config"))
            .env("XDG_RUNTIME_DIR", self.t.path("runtime"))
            .env("PATH", &self.paths)
            .env("SYQ_NO_UPDATE_CHECK", "1")
            .env_remove("SSH_AUTH_SOCK")
            .env_remove("SYQ_AUTH_FROM")
            .env_remove("TMUX")
            .current_dir(self.t.path(""));
        command
    }

    /// Run `command` without a terminal. When it asks for approval, check
    /// that it has already said on stderr that it waits, while the request is
    /// still held, then release the request. Returns the exit status, all of
    /// stderr, and the requests made.
    fn run(
        &self,
        command: &mut Command,
    ) -> (std::process::ExitStatus, String, Vec<serde_json::Value>) {
        use std::time::{Duration, Instant};
        let (mut child, lines, reader) = Self::start(command);
        let mut seen = Vec::new();
        let mut requests = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(60);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < deadline, "syq did not finish: {seen:?}");
            seen.extend(lines.try_iter());
            if let Ok(request) = self.requests.recv_timeout(Duration::from_millis(10)) {
                if !self.holding.load(std::sync::atomic::Ordering::Relaxed) {
                    requests.push(request);
                    continue;
                }
                let waiting = Instant::now() + Duration::from_secs(10);
                while !seen
                    .iter()
                    .any(|line| line.contains("waiting up to 5 minutes for @laptop"))
                {
                    assert!(
                        Instant::now() < waiting,
                        "syq did not say that it waits for approval while it waited: {seen:?}"
                    );
                    if let Ok(line) = lines.recv_timeout(Duration::from_millis(10)) {
                        seen.push(line);
                    }
                }
                requests.push(request);
                self.release.send(()).unwrap();
            }
        };
        reader.join().unwrap();
        seen.extend(lines.try_iter());
        (status, seen.join("\n"), requests)
    }

    /// Start `command` without a terminal, passing its stderr lines on.
    fn start(
        command: &mut Command,
    ) -> (
        std::process::Child,
        std::sync::mpsc::Receiver<String>,
        std::thread::JoinHandle<()>,
    ) {
        use std::io::BufRead;
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .start()
            .unwrap();
        let stderr = child.stderr.take().unwrap();
        let (line_sender, lines) = std::sync::mpsc::channel::<String>();
        let reader = std::thread::spawn(move || {
            for line in std::io::BufReader::new(stderr).lines() {
                let _ = line_sender.send(line.unwrap());
            }
        });
        (child, lines, reader)
    }

    /// Wait up to ten seconds for a line containing `text`, keeping the
    /// lines read on the way in `seen`.
    fn expect_line(lines: &std::sync::mpsc::Receiver<String>, seen: &mut Vec<String>, text: &str) {
        use std::time::{Duration, Instant};
        let deadline = Instant::now() + Duration::from_secs(10);
        while !seen.iter().any(|line| line.contains(text)) {
            assert!(Instant::now() < deadline, "no line with {text:?}: {seen:?}");
            if let Ok(line) = lines.recv_timeout(Duration::from_millis(10)) {
                seen.push(line);
            }
        }
    }
}

impl Drop for HeldLaptop {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        // A request still held after a failed check is released at once.
        self.release = std::sync::mpsc::channel().0;
        if let Some(responder) = self.responder.take() {
            let _ = responder.join();
        }
    }
}

#[test]
fn automatic_fallback_explains_failed_credentials_and_says_at_once_that_it_waits() {
    use std::os::unix::net::UnixListener;
    let laptop = HeldLaptop::new();
    let t = &laptop.t;
    let asking = "asking @laptop to approve this copy to backup";
    let upload = || laptop.command(&["cp", "source", "--to", "backup"]);

    // No agent and no key files: asking the laptop is the ordinary way to
    // authorize this copy, so syq says only that it waits for approval.
    let (status, stderr, requests) = laptop.run(&mut upload());
    assert!(!status.success());
    assert_eq!(requests.len(), 1, "{stderr}");
    assert!(requests[0]["message"].get("Forward").is_some());
    assert!(!stderr.contains(asking), "{stderr}");
    assert!(
        stderr.lines().any(|line| line
            == "syq: waiting up to 5 minutes for @laptop to approve this copy to backup; approve it there in the desktop prompt or with `syq persist receive pending`"),
        "{stderr}"
    );
    assert!(stderr.contains("denied by fixture"), "{stderr}");

    // A key file that did not get this machine in.
    write(&t.path(".ssh/id_ed25519"), b"fixture key");
    let (status, stderr, requests) = laptop.run(&mut upload());
    assert!(!status.success());
    assert_eq!(requests.len(), 1, "{stderr}");
    assert!(
        stderr.lines().any(|line| line
            == format!("syq: this machine could not log in to backup with its SSH keys; {asking}. To avoid this, make sure this machine's key is authorized on backup and available to its SSH agent")),
        "{stderr}"
    );
    fs::remove_file(t.path(".ssh/id_ed25519")).unwrap();

    // An agent socket where nothing answers, outside tmux.
    let dead = t.path("dead-agent.sock");
    let (status, stderr, requests) = laptop.run(upload().env("SSH_AUTH_SOCK", &dead));
    assert!(!status.success());
    assert_eq!(requests.len(), 1, "{stderr}");
    assert!(
        stderr.lines().any(|line| line
            == format!("syq: SSH_AUTH_SOCK names {}, where no SSH agent answers, so this machine could not log in to backup; {asking}. To fix this, point SSH_AUTH_SOCK at a running agent, or unset it", dead.display())),
        "{stderr}"
    );
    assert_eq!(
        fs::read_to_string(t.path("ssh-used")).unwrap(),
        format!("unset\nunset\n{}\n", dead.display())
    );

    // An agent that refuses to list its keys has not shown that this
    // machine has none.
    let sockets = test_support::short_tempdir().unwrap();
    let socket = sockets.path().join("agent");
    let listener = UnixListener::bind(&socket).unwrap();
    let agent = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0; 5];
        stream.read_exact(&mut request).unwrap();
        // SSH_AGENT_FAILURE
        stream.write_all(&[0, 0, 0, 1, 5]).unwrap();
    });
    let (status, stderr, requests) = laptop.run(upload().env("SSH_AUTH_SOCK", &socket));
    agent.join().unwrap();
    assert!(!status.success());
    assert_eq!(requests.len(), 1, "{stderr}");
    assert!(
        stderr.lines().any(|line| line
            == format!("syq: this machine could not log in to backup, and the SSH agent at {} refused to list its keys; {asking}. To fix this, restart that agent", socket.display())),
        "{stderr}"
    );
}

#[test]
fn account_access_says_when_it_waits_for_the_laptop() {
    let laptop = HeldLaptop::new();
    // The keeper that asks for account access has no stderr of its own; the
    // command says that it waits once the request has gone a second without
    // an answer.
    for command in [
        laptop.command(&["cp", "source", "--to", "backup", "--auth-from", "@laptop"]),
        {
            let mut command = laptop.command(&["cp", "source", "--to", "backup"]);
            command.env("SYQ_AUTH_FROM", "@laptop");
            command
        },
    ] {
        let mut command = command;
        let (status, stderr, requests) = laptop.run(&mut command);
        assert!(!status.success());
        assert_eq!(requests.len(), 1, "{stderr}");
        assert!(requests[0]["message"].get("LocalSsh").is_some(), "{stderr}");
        assert!(
            stderr.lines().any(|line| line
                == "syq: waiting up to 5 minutes for @laptop to approve SSH access to backup; approve it there in the desktop prompt or with `syq persist receive pending`"),
            "{stderr}"
        );
        assert!(stderr.contains("denied by fixture"), "{stderr}");
        assert!(!stderr.contains("still setting up"), "{stderr}");
        assert!(!laptop.t.path("ssh-used").exists(), "{stderr}");
    }

    // A decision the laptop remembered answers at once: nobody is asked,
    // so the command does not say it waits.
    laptop
        .holding
        .store(false, std::sync::atomic::Ordering::Relaxed);
    let (status, stderr, requests) = laptop.run(&mut laptop.command(&[
        "cp",
        "source",
        "--to",
        "backup",
        "--auth-from",
        "@laptop",
    ]));
    assert!(!status.success());
    assert_eq!(requests.len(), 1, "{stderr}");
    assert!(stderr.contains("denied by fixture"), "{stderr}");
    assert!(!stderr.contains("waiting up to"), "{stderr}");
    laptop
        .holding
        .store(true, std::sync::atomic::Ordering::Relaxed);

    // A second command for the same account waits for the first one's
    // request, and says so.
    let account = ["cp", "source", "--to", "backup", "--auth-from", "@laptop"];
    let (mut first, first_lines, first_reader) = HeldLaptop::start(&mut laptop.command(&account));
    let request = laptop
        .requests
        .recv_timeout(std::time::Duration::from_secs(30))
        .unwrap();
    assert!(request["message"].get("LocalSsh").is_some());
    let (mut second, second_lines, second_reader) =
        HeldLaptop::start(&mut laptop.command(&account));
    let mut seen = Vec::new();
    HeldLaptop::expect_line(
        &second_lines,
        &mut seen,
        "syq: waiting up to 5 minutes for another command to finish setting up SSH access to backup; if it still needs approval, approve it on @laptop in the desktop prompt or with `syq persist receive pending`",
    );
    // The first request is refused; the second command then asks itself.
    laptop.release.send(()).unwrap();
    assert!(!first.wait().unwrap().success());
    first_reader.join().unwrap();
    let mut first_seen: Vec<_> = first_lines.try_iter().collect();
    HeldLaptop::expect_line(&first_lines, &mut first_seen, "denied by fixture");
    let request = laptop
        .requests
        .recv_timeout(std::time::Duration::from_secs(30))
        .unwrap();
    assert!(request["message"].get("LocalSsh").is_some());
    HeldLaptop::expect_line(
        &second_lines,
        &mut seen,
        "syq: waiting up to 5 minutes for @laptop to approve SSH access to backup;",
    );
    laptop.release.send(()).unwrap();
    assert!(!second.wait().unwrap().success());
    second_reader.join().unwrap();
}

#[test]
fn receiving_profiles_preserve_independent_settings_and_select_names() {
    let t = Tmp::new();
    fs::create_dir(t.runtime()).unwrap();
    let _persistence = PersistenceOff(&t);
    fs::create_dir(t.path("project")).unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_syq"))
            .args(args)
            .env("HOME", t.path(""))
            .env("XDG_CONFIG_HOME", t.path("config"))
            .env("XDG_RUNTIME_DIR", t.runtime())
            .env("SYQ_NO_UPDATE_CHECK", "1")
            .current_dir(t.path(""))
            .capture_output()
            .unwrap()
    };
    let status = || {
        let output = run(&["persist", "receive", "status", "--json"]);
        assert_output_ok(&output);
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };
    assert_output_ok(&run(&[
        "persist",
        "receive",
        "on",
        "--name",
        "laptop",
        "--auto-approve-root",
        "project",
    ]));
    let first = status()["profiles"][0].clone();
    assert_output_ok(&run(&[
        "persist", "receive", "on", "--name", "project", "--root", "project",
    ]));
    let state = status();
    assert_eq!(state["profiles"].as_array().unwrap().len(), 2);
    assert_eq!(state["profiles"][0], first);
    assert!(state["profiles"][1]["auto_approve_root"].is_null());
    assert_eq!(state["profiles"][1]["root"], t.s("project"));
    assert_output_ok(&run(&["persist", "receive", "off", "--name", "project"]));
    assert_eq!(status()["profiles"][0], first);
    assert_eq!(status()["profiles"][1]["enabled"], false);
    let before = fs::read(t.path("config/syq/receive.json")).unwrap();
    for args in [
        vec!["off", "--name", "typo"],
        vec!["remove", "typo"],
        vec!["on", "--name", "../bad"],
        vec!["status", "--name", "typo"],
    ] {
        let mut command = vec!["persist", "receive"];
        command.extend(args);
        assert!(!run(&command).status.success());
        assert_eq!(fs::read(t.path("config/syq/receive.json")).unwrap(), before);
    }
    assert_output_ok(&run(&["persist", "receive", "on", "--name", "project"]));
    assert_eq!(status()["profiles"][1]["root"], t.s("project"));
    let completion = run(&[
        "completion",
        "__complete",
        "fish",
        "5",
        "--",
        "syq",
        "persist",
        "receive",
        "off",
        "--name",
        "proj",
    ]);
    assert_output_ok(&completion);
    assert_eq!(completion.stdout, b"project\0");
    assert_output_ok(&run(&["persist", "receive", "remove", "laptop"]));
    assert_eq!(status()["settings"]["name"], "project");
    assert!(!run(&["persist", "receive", "remove", "project"])
        .status
        .success());
    assert_output_ok(&run(&["persist", "receive", "off"]));
    assert_eq!(status()["settings"]["enabled"], false);
}

#[test]
fn receiving_profiles_reject_explicit_files_without_overwriting_saved_settings() {
    let t = Tmp::new();
    fs::create_dir(t.runtime()).unwrap();
    let _persistence = PersistenceOff(&t);
    fs::create_dir(t.path("project")).unwrap();
    fs::write(t.path("file"), b"not a directory").unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_syq"))
            .args(["persist", "receive"])
            .args(args)
            .env("HOME", t.path(""))
            .env("XDG_CONFIG_HOME", t.path("config"))
            .env("XDG_RUNTIME_DIR", t.runtime())
            .env("SYQ_NO_UPDATE_CHECK", "1")
            .current_dir(t.path(""))
            .capture_output()
            .unwrap()
    };
    assert_output_ok(&run(&["on", "--name", "project", "--root", "project"]));
    let before = fs::read(t.path("config/syq/receive.json")).unwrap();
    for name in ["project", "new-profile"] {
        for option in ["--cwd", "--root"] {
            let output = run(&["on", "--name", name, option, "file"]);
            assert!(!output.status.success());
            assert!(
                String::from_utf8_lossy(&output.stderr)
                    .contains(&format!("{option} must name a directory")),
                "{output:?}"
            );
            assert_eq!(fs::read(t.path("config/syq/receive.json")).unwrap(), before);
        }
    }
    // Losing a saved directory must not prevent inspecting or disabling profiles.
    fs::remove_dir(t.path("project")).unwrap();
    assert_output_ok(&run(&["status", "--json"]));
    assert_eq!(fs::read(t.path("config/syq/receive.json")).unwrap(), before);
    assert_output_ok(&run(&["off", "--name", "project"]));
}

#[test]
fn receiving_profiles_migrate_unchanged_v051_preferences_and_reject_duplicates() {
    let t = Tmp::new();
    fs::create_dir(t.runtime()).unwrap();
    let _persistence = PersistenceOff(&t);
    let path = t.path("config/syq/receive.json");
    // Captured from the released v0.5.1 executable, not generated by this writer.
    let old = include_bytes!("../fixtures/receive-v3-v0.5.1.json");
    write(&path, old);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_syq"))
            .args(args)
            .env("HOME", t.path(""))
            .env("XDG_CONFIG_HOME", t.path("config"))
            .env("XDG_RUNTIME_DIR", t.runtime())
            .env("SYQ_NO_UPDATE_CHECK", "1")
            .capture_output()
            .unwrap()
    };
    assert_output_ok(&run(&["persist", "receive", "status", "--json"]));
    assert_eq!(fs::read(&path).unwrap(), old);
    assert_output_ok(&run(&["persist", "receive", "on", "--name", "new-profile"]));
    let mut saved: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let original: serde_json::Value = serde_json::from_slice(old).unwrap();
    assert_eq!(saved["version"], 5);
    for key in [
        "name",
        "cwd",
        "root",
        "max_bytes",
        "max_entries",
        "max_delete",
        "notifications",
    ] {
        assert_eq!(saved["profiles"][0][key], original[key]);
    }
    assert!(saved["profiles"][0]["auto_approve_root"].is_null());
    assert!(saved["profiles"][1]["auto_approve_root"].is_null());
    saved["profiles"][1]["name"] = saved["profiles"][0]["name"].clone();
    write(&path, &serde_json::to_vec(&saved).unwrap());
    let failed = run(&["persist", "receive", "status", "--json"]);
    assert!(!failed.status.success());
    assert!(stderr_of(&failed).contains("duplicate receiving profile"));
}

#[test]
fn receiving_daemon_survives_clients_closed_before_accept() {
    use socket2::{Domain, SockAddr, Socket, Type};
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

    fn wait_for(label: &str, mut ready: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut progress = Instant::now();
        while !ready() {
            assert!(Instant::now() < deadline, "timed out waiting for {label}");
            if Instant::now() >= progress {
                eprintln!("Waiting for {label}");
                progress = Instant::now() + Duration::from_secs(1);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    fn connect(path: &Path) -> std::io::Result<UnixStream> {
        let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
        socket.set_read_timeout(Some(Duration::from_secs(5)))?;
        socket.set_write_timeout(Some(Duration::from_secs(5)))?;
        socket.connect(&SockAddr::unix(path)?)?;
        Ok(UnixStream::from(OwnedFd::from(socket)))
    }
    fn request(stream: &mut UnixStream, stop: bool) {
        let bytes = serde_json::to_vec(&serde_json::json!({"version":2, "stop":stop})).unwrap();
        stream
            .write_all(&(bytes.len() as u32).to_be_bytes())
            .unwrap();
        stream.write_all(&bytes).unwrap();
    }
    fn response(stream: &mut UnixStream) -> serde_json::Value {
        let mut length = [0; 4];
        stream.read_exact(&mut length).unwrap();
        let length = u32::from_be_bytes(length) as usize;
        assert!(length < 1024 * 1024);
        let mut bytes = vec![0; length];
        stream.read_exact(&mut bytes).unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    let t = Tmp::new();
    fs::create_dir(t.runtime()).unwrap();
    let _persistence = PersistenceOff(&t);
    let command = |args: &[&str]| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
        command
            .args(args)
            .env("HOME", t.path(""))
            .env("XDG_CONFIG_HOME", t.path("config"))
            .env("XDG_RUNTIME_DIR", t.runtime());
        command
    };
    let enabled = command(&["persist", "on"]).run().unwrap();
    assert_output_ok(&enabled);
    let scope = String::from_utf8(enabled.stdout)
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("scope: ").map(PathBuf::from))
        .unwrap();
    // Keep the real supervisor running without starting any SSH workers.
    assert_output_ok(&command(&["persist", "receive", "on"]).run().unwrap());
    let settings_path = t.path("config/syq/receive.json");
    let mut settings: serde_json::Value = serde_json::from_slice(&read(&settings_path)).unwrap();
    settings["profiles"][0]["servers"] = serde_json::json!(["other.invalid"]);
    fs::write(&settings_path, serde_json::to_vec(&settings).unwrap()).unwrap();
    let identity = command(&["--build-identity"]).run().unwrap();
    assert_output_ok(&identity);
    let identity = String::from_utf8(identity.stdout).unwrap();
    let control = scope.join("cm-0123456789abcdef");
    let socket_path = control.with_extension("recv");
    let record = control.with_extension("recv-json");
    fs::write(
        &record,
        serde_json::to_vec(&serde_json::json!({
            "version":2, "identity":identity.trim(),
            "endpoint":{"user":null, "host":"socket-test.invalid", "port":null},
            "program":env!("CARGO_BIN_EXE_syq")
        }))
        .unwrap(),
    )
    .unwrap();
    fs::set_permissions(&record, fs::Permissions::from_mode(0o600)).unwrap();
    let mut daemon = crate::process_group::ProcessGroup::spawn(
        command(&["--receive-service", control.to_str().unwrap()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit()),
    )
    .unwrap();
    let pid = daemon.child.id() as libc::pid_t;
    let mut first = None;
    wait_for("receiving control socket", || {
        assert!(
            daemon.poll().unwrap().is_none(),
            "receiving daemon exited during startup"
        );
        first = connect(&socket_path).ok();
        first.is_some()
    });
    let mut first = first.unwrap();
    request(&mut first, false);
    assert_eq!(response(&mut first)["pid"], pid);
    drop(first);

    // Stop the owner before connecting, so every test client has already closed
    // when accept returns. Close the descriptor: shutdown alone does not trigger
    // macOS's socket-option rejection. No sleep determines the interleaving.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGSTOP) }, 0);
    wait_for("receiving daemon to stop", || {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe {
                libc::waitid(
                    libc::P_PID,
                    pid as libc::id_t,
                    &mut info,
                    libc::WSTOPPED | libc::WNOHANG | libc::WNOWAIT,
                )
            },
            0
        );
        info.si_signo != 0 && info.si_code == libc::CLD_STOPPED
    });
    for partial in [false, true] {
        let mut client = connect(&socket_path).unwrap();
        if partial {
            client.write_all(&[0, 0]).unwrap();
        }
        drop(client);
    }
    let mut healthy = connect(&socket_path).unwrap();
    request(&mut healthy, false);
    assert_eq!(unsafe { libc::kill(pid, libc::SIGCONT) }, 0);
    assert_eq!(
        response(&mut healthy)["pid"],
        pid,
        "same daemon must serve the next client"
    );
    assert!(daemon.poll().unwrap().is_none());
    let mut stop = connect(&socket_path).unwrap();
    request(&mut stop, true);
    assert_eq!(response(&mut stop)["pid"], pid);
    wait_for("receiving daemon to exit", || {
        daemon.poll().unwrap().is_some()
    });
    assert!(daemon.close().unwrap().success());
    assert!(!socket_path.exists());
}

/// Run `syq persist receive ...` in this fixture's isolated persistence domain.
fn receive_command(t: &Tmp, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["persist", "receive"])
        .args(args)
        .env("HOME", t.path(""))
        .env("XDG_CONFIG_HOME", t.path("config"))
        .env("XDG_RUNTIME_DIR", t.runtime())
        .env("SYQ_NO_UPDATE_CHECK", "1")
        .current_dir(t.path(""))
        .capture_output()
        .unwrap()
}

/// The local SSH authorization provider reported by `persist receive status`.
fn local_provider(t: &Tmp) -> serde_json::Value {
    let output = receive_command(t, &["status", "--json"]);
    assert_output_ok(&output);
    serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()["provider"].clone()
}

/// On Linux, syq starts its background services from the running image
/// through /proc/self/exe. They still show syq's name and path to ps, pgrep
/// and pkill, as when started from the file.
#[cfg(target_os = "linux")]
#[test]
fn background_provider_keeps_the_syq_process_name_and_path() {
    let t = Tmp::new();
    fs::create_dir(t.runtime()).unwrap();
    let _persistence = PersistenceOff(&t);
    fs::create_dir_all(t.path("root")).unwrap();
    assert_output_ok(&receive_command(
        &t,
        &["on", "--root", "root", "--notify", "off"],
    ));
    let pid = local_provider(&t)["pid"].as_u64().unwrap();
    assert_eq!(
        fs::read_to_string(format!("/proc/{pid}/comm")).unwrap(),
        "syq\n"
    );
    // syq names itself by its symlink-resolved path, as the kernel reports it.
    let expected = fs::canonicalize(env!("CARGO_BIN_EXE_syq")).unwrap();
    let cmdline = fs::read(format!("/proc/{pid}/cmdline")).unwrap();
    assert_eq!(
        cmdline.split(|byte| *byte == 0).next().unwrap(),
        std::os::unix::ffi::OsStrExt::as_bytes(expected.as_os_str())
    );
}

const OTHER_BUILD: &str = "v0.0.1+other-build";

/// Read one length-prefixed JSON message of the local provider protocol.
fn read_provider_frame(stream: &mut std::os::unix::net::UnixStream) -> serde_json::Value {
    let mut length = [0u8; 4];
    stream.read_exact(&mut length).unwrap();
    let mut message = vec![0; u32::from_be_bytes(length) as usize];
    stream.read_exact(&mut message).unwrap();
    serde_json::from_slice(&message).unwrap()
}

fn write_provider_frame(stream: &mut std::os::unix::net::UnixStream, message: serde_json::Value) {
    let message = serde_json::to_vec(&message).unwrap();
    stream
        .write_all(&(message.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(&message).unwrap();
}

/// Replace this fixture's provider with one from an older build, as after an
/// upgrade. It answers status and stop requests and closes the connection on
/// a reload, as a provider that cannot read newer settings does. It returns
/// the requests it received once it has been stopped.
fn replace_with_other_build_provider(t: &Tmp) -> std::thread::JoinHandle<Vec<String>> {
    let pid = local_provider(t)["pid"].as_u64().unwrap();
    unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    let domain = t
        .runtime()
        .join(format!("syq-persist-{}/global", unsafe { libc::geteuid() }));
    let socket = domain.join("provider-v1.sock");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let lock = loop {
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .open(domain.join("provider-v1.lock"))
            .unwrap();
        if unsafe {
            libc::flock(
                std::os::fd::AsRawFd::as_raw_fd(&lock),
                libc::LOCK_EX | libc::LOCK_NB,
            )
        } == 0
            && !socket.exists()
        {
            break lock;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the provider from this build did not stop"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    listener.set_nonblocking(true).unwrap();
    std::thread::spawn(move || {
        let mut requests = Vec::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            let mut stream = match listener.accept() {
                Ok((stream, _)) => stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "the old provider was not stopped: {requests:?}"
                    );
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
                Err(error) => panic!("{error}"),
            };
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            read_provider_frame(&mut stream);
            write_provider_frame(
                &mut stream,
                serde_json::json!({"version": 1, "build": OTHER_BUILD}),
            );
            let request = read_provider_frame(&mut stream);
            let request = request.as_str().unwrap_or("other").to_owned();
            requests.push(request.clone());
            if request != "Status" && request != "Stop" {
                continue;
            }
            write_provider_frame(
                &mut stream,
                serde_json::json!({
                    "build": OTHER_BUILD,
                    "pid": 0,
                    "profiles": [],
                    "decision_error": null,
                }),
            );
            if request == "Stop" {
                // Like a provider, remove the socket before releasing the lock.
                fs::remove_file(&socket).unwrap();
                drop(lock);
                return requests;
            }
        }
    })
}

/// After an upgrade, a provider from the old build cannot read the new
/// settings. Every settings command replaces it with one from this build for
/// the profiles that stay enabled, instead of failing or leaving it running.
#[test]
fn settings_commands_replace_a_provider_from_another_build() {
    let build = Command::new(env!("CARGO_BIN_EXE_syq"))
        .arg("--build-identity")
        .capture_output()
        .unwrap();
    assert_output_ok(&build);
    let build = String::from_utf8(build.stdout).unwrap();
    for command in [
        &["on", "--name", "first"][..],
        &["off", "--name", "first"],
        &["remove", "first"],
    ] {
        let t = Tmp::new();
        fs::create_dir(t.runtime()).unwrap();
        let _persistence = PersistenceOff(&t);
        fs::create_dir_all(t.path("root")).unwrap();
        for name in ["first", "second"] {
            assert_output_ok(&receive_command(
                &t,
                &["on", "--name", name, "--root", "root", "--notify", "off"],
            ));
        }
        let old = replace_with_other_build_provider(&t);
        assert_output_ok(&receive_command(&t, command));
        assert_eq!(old.join().unwrap(), ["Status", "Stop"], "{command:?}");
        let provider = local_provider(&t);
        assert_eq!(provider["build"], build.trim(), "{command:?}");
        let names: Vec<_> = provider["profiles"]
            .as_array()
            .unwrap()
            .iter()
            .map(|profile| profile["settings"]["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"second"), "{command:?}: {provider}");
    }
}

/// Turning off the last enabled profile stops a provider from another build
/// and starts none.
#[test]
fn turning_off_the_last_profile_leaves_no_provider_after_another_build() {
    let t = Tmp::new();
    fs::create_dir(t.runtime()).unwrap();
    let _persistence = PersistenceOff(&t);
    fs::create_dir_all(t.path("root")).unwrap();
    for name in ["first", "second"] {
        assert_output_ok(&receive_command(
            &t,
            &["on", "--name", name, "--root", "root", "--notify", "off"],
        ));
    }
    assert_output_ok(&receive_command(&t, &["off", "--name", "second"]));
    let old = replace_with_other_build_provider(&t);
    assert_output_ok(&receive_command(&t, &["off", "--name", "first"]));
    assert_eq!(old.join().unwrap(), ["Stop"]);
    assert!(local_provider(&t).is_null());
}

/// Turns a scoped domain off when dropped, even if the test fails.
struct ScopeOff<'a>(&'a Tmp, PathBuf);

impl Drop for ScopeOff<'_> {
    fn drop(&mut self) {
        let _ = persistence_command(self.0, &["off", "--pscope", self.1.to_str().unwrap()]).run();
    }
}

/// After an upgrade, a receiving connection from the old build refuses to
/// start helpers on macOS and names `syq persist connect SERVER --pscope
/// PATH`. Running that replaces the old connection with one from this build
/// and keeps the domain and its settings. The fake ssh cannot forward the
/// return socket, so each connect reports that the connection failed after
/// the service starts; the real-SSH suite runs the same steps to "online".
#[test]
fn connecting_again_replaces_a_receiving_connection_from_another_build() {
    let t = Tmp::new();
    fs::create_dir(t.runtime()).unwrap();
    fs::create_dir(t.path("root")).unwrap();
    fs::create_dir(t.path("home")).unwrap();
    let ssh = fake_ssh(&t);
    let scope = ephemeral_scope(&t);
    let _off = ScopeOff(&t, scope.clone());
    let run = |args: &[&str]| {
        persistence_command(&t, args)
            .args(["--pscope", scope.to_str().unwrap()])
            .env("HOME", t.path("home"))
            .env("XDG_CACHE_HOME", t.path("cache"))
            .env("FAKE_REMOTE_HOME", t.path("remote-home"))
            .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
            .env("FAKE_RSH_LOG", t.path("rsh.log"))
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", ssh.parent().unwrap().display()),
            )
            .run()
            .unwrap()
    };
    let connect = || {
        let output = run(&[
            "connect",
            "test-server",
            "--timeout",
            "20",
            "--syq-path",
            env!("CARGO_BIN_EXE_syq"),
        ]);
        let stderr = stderr_of(&output);
        assert!(
            stderr.contains("server rejected return connection"),
            "{stderr}"
        );
    };
    assert_output_ok(&run(&[
        "receive",
        "on",
        "--notify",
        "off",
        "--root",
        &t.s("root"),
        "--all-connections",
    ]));
    connect();
    let settings = read(&scope.join("receive.json"));

    // The control of the connection to test-server, and its service.
    let control = fs::read_dir(&scope)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.to_str().unwrap().ends_with(".recv-json"))
        .expect("receiving record");
    let control = PathBuf::from(
        control
            .to_str()
            .unwrap()
            .strip_suffix(".recv-json")
            .unwrap(),
    );
    let suffixed = |suffix: &str| PathBuf::from(format!("{}{suffix}", control.display()));
    let status = |stop: bool| {
        let mut stream = std::os::unix::net::UnixStream::connect(suffixed(".recv")).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        write_provider_frame(&mut stream, serde_json::json!({"version": 2, "stop": stop}));
        read_provider_frame(&mut stream)
    };
    let build = Command::new(env!("CARGO_BIN_EXE_syq"))
        .arg("--build-identity")
        .capture_output()
        .unwrap();
    let build = String::from_utf8(build.stdout).unwrap();
    assert_eq!(status(false)["identity"], build.trim());

    // Replace it with a connection from another build, as after an upgrade.
    let pid = status(false)["pid"].as_u64().unwrap();
    unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let lock = loop {
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .open(suffixed(".recv-lock"))
            .unwrap();
        if unsafe {
            libc::flock(
                std::os::fd::AsRawFd::as_raw_fd(&lock),
                libc::LOCK_EX | libc::LOCK_NB,
            )
        } == 0
            && !suffixed(".recv").exists()
        {
            break lock;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the receiving connection from this build did not stop"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    let socket = suffixed(".recv");
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let old = std::thread::spawn(move || {
        let mut requests = Vec::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        loop {
            let mut stream = match listener.accept() {
                Ok((stream, _)) => stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "the old receiving connection was not stopped: {requests:?}"
                    );
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
                Err(error) => panic!("{error}"),
            };
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let stop = read_provider_frame(&mut stream)["stop"] == true;
            requests.push(if stop { "stop" } else { "status" });
            write_provider_frame(
                &mut stream,
                serde_json::json!({
                    "version": 2, "identity": "other-build", "pid": 0,
                    "endpoint": "test-server", "name": "",
                    "connection": {"phase": "online", "error": null, "ssh_pid": null}
                }),
            );
            if stop {
                // Like the service, remove the socket before the lock.
                fs::remove_file(&socket).unwrap();
                drop(lock);
                return requests;
            }
        }
    });

    // The step the refusal names.
    connect();
    assert_eq!(old.join().unwrap().last(), Some(&"stop"));
    assert_eq!(status(false)["identity"], build.trim());
    assert_eq!(read(&scope.join("receive.json")), settings);
}

/// An ssh stand-in for receiving: a receiving connection's ssh (`-R`)
/// reports ready at once and stays up, so its service has a live
/// connection with a local socket requests arrive on. Other commands run
/// locally, as `fake_ssh` runs them.
fn receiving_ssh(t: &Tmp) -> PathBuf {
    let path = t.path("receiving-bin/ssh");
    executable(
        &path,
        br#"#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_RSH_LOG"
if [ -n "${FAKE_SSH_PIDS:-}" ]; then
    echo $$ >> "$FAKE_SSH_PIDS"
fi
# Hang, as ssh waiting for a key or a network does.
if [ -n "${FAKE_SSH_HANG:-}" ] && [ "$1" != -V ]; then
    echo $$ > "$FAKE_SSH_HANG"
    exec sleep 600
fi
if [ -n "${FAKE_SSH_REJECT:-}" ] && [ "$1" != -V ]; then
    echo 'syq@test-server: Permission denied (publickey).' >&2
    exit 255
fi
if [ -n "${FAKE_SSH_REFUSE:-}" ] && [ "$1" != -V ]; then
    echo 'ssh: connect to host test-server port 22: Connection refused' >&2
    exit 255
fi
# A login of its own, as a receiving connection makes, that the server
# rejects, while the control connection and helper setup still work.
case " $* " in
    *" ControlPath=none "*" PermitLocalCommand=no "*|*" PermitLocalCommand=no "*" ControlPath=none "*)
        # Wait, as for a touch of a security key that nobody gives, with a
        # process of its own, as a ProxyJump ssh or ssh-sk-helper.
        if [ -n "${FAKE_SSH_HANG_DIRECT:-}" ]; then
            sleep 600 &
            echo $! > "$FAKE_SSH_HANG_DIRECT.child"
            echo $$ > "$FAKE_SSH_HANG_DIRECT"
            exec sleep 600
        fi
        if [ -n "${FAKE_SSH_REJECT_DIRECT:-}" ]; then
            echo 'syq@test-server: Permission denied (publickey).' >&2
            exit 255
        fi
        if [ -n "${FAKE_SSH_DIRECT_MARK:-}" ]; then
            : > "$FAKE_SSH_DIRECT_MARK"
        fi
        ;;
esac
for argument in "$@"; do
    if [ "$argument" = -R ]; then
        printf '\000\000\000\007"Ready"'
        exec sleep 600
    fi
done
if [ "$1" = -V ]; then
    printf 'OpenSSH_9.9p1, fake\n' >&2
    exit 0
fi
while [ "$#" -gt 0 ]; do
    case "$1" in
        -O) if [ "$2" = check ]; then exit 0; fi; shift 2 ;;
        -o|-l|-p|-S) shift 2 ;;
        -a|-A|-x|-k|-T) shift ;;
        --) shift; break ;;
        -*) shift ;;
        *) break ;;
    esac
done
shift
HOME="$FAKE_REMOTE_HOME"
PATH="$FAKE_REMOTE_BIN:/usr/bin:/bin"
export HOME PATH
unset SSH_CONNECTION
exec /bin/sh -c "$1"
"#,
    );
    path
}

/// The receiving fixture the update tests share: syq installed at
/// `bin/syq`, from which receiving through test-server runs, in a scope of
/// its own.
struct Installed<'a> {
    t: &'a Tmp,
    syq: PathBuf,
    scope: PathBuf,
    ssh: PathBuf,
}

impl Installed<'_> {
    fn new(t: &Tmp) -> Installed<'_> {
        fs::create_dir(t.runtime()).unwrap();
        fs::create_dir_all(t.path("root")).unwrap();
        fs::create_dir_all(t.path("home")).unwrap();
        fs::create_dir_all(t.path("remote-home")).unwrap();
        fs::set_permissions(t.path("remote-home"), fs::Permissions::from_mode(0o700)).unwrap();
        let syq = t.path("bin/syq");
        executable_support::copy_executable(Path::new(env!("CARGO_BIN_EXE_syq")), &syq, 0o755);
        // Nobody else may write where syq follows it from.
        fs::set_permissions(t.path("bin"), fs::Permissions::from_mode(0o755)).unwrap();
        let ssh = receiving_ssh(t);
        let scope = ephemeral_scope(t);
        Installed { t, syq, scope, ssh }
    }

    /// `program persist ARGS --pscope SCOPE`, with short waits for following
    /// an update.
    fn command(&self, program: &Path, args: &[&str]) -> Command {
        let t = self.t;
        let mut command = Command::new(program);
        command
            .args(args)
            .env("HOME", t.path("home"))
            .env("XDG_CONFIG_HOME", t.path("config"))
            .env("XDG_RUNTIME_DIR", t.runtime())
            .env("XDG_CACHE_HOME", t.path("cache"))
            .env("FAKE_REMOTE_HOME", t.path("remote-home"))
            .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
            .env("FAKE_RSH_LOG", t.path("rsh.log"))
            .env("SYQ_NO_UPDATE_CHECK", "1")
            .env("SYQ_TEST_SWITCH_CHECK_MS", "100")
            .env("SYQ_TEST_SWITCH_QUIET_MS", "500")
            .env("SYQ_TEST_SWITCH_RETRY_MS", "600000")
            // Stand-in services on a slow runner may answer late.
            .env("SYQ_TEST_REFRESH_ANSWER_MS", "5000")
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.ssh.parent().unwrap().display()),
            );
        command
    }

    fn persist(&self, program: &Path, args: &[&str]) -> Output {
        let mut full = vec!["persist"];
        full.extend_from_slice(args);
        full.extend(["--pscope", self.scope.to_str().unwrap()]);
        self.command(program, &full).run().unwrap()
    }

    /// Receive through test-server, started from the installed syq.
    fn connect(&self) {
        assert_output_ok(&self.persist(
            &self.syq,
            &[
                "receive",
                "on",
                "--notify",
                "off",
                "--root",
                &self.t.s("root"),
                "--all-connections",
            ],
        ));
        let connected = self.persist(
            &self.syq,
            &[
                "connect",
                "test-server",
                "--timeout",
                "20",
                "--syq-path",
                env!("CARGO_BIN_EXE_syq"),
            ],
        );
        assert_output_ok(&connected);
        assert!(
            String::from_utf8_lossy(&connected.stdout).contains("test-server ready"),
            "{}",
            String::from_utf8_lossy(&connected.stdout)
        );
    }

    /// The receiving service's control path.
    fn control(&self) -> PathBuf {
        let record = fs::read_dir(&self.scope)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| path.to_str().unwrap().ends_with(".recv-json"))
            .expect("receiving record");
        PathBuf::from(record.to_str().unwrap().strip_suffix(".recv-json").unwrap())
    }

    /// Send one control request to the receiving service.
    fn request(&self, request: serde_json::Value) -> serde_json::Value {
        let mut stream =
            std::os::unix::net::UnixStream::connect(format!("{}.recv", self.control().display()))
                .unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        write_provider_frame(&mut stream, request);
        read_provider_frame(&mut stream)
    }

    /// Replace the installed syq with a stand-in for another build: it
    /// reports `build` and records the commands it is given in `log`. Like
    /// an installer, write a new file and rename it over the old one.
    fn update(&self, build: &str, log: &Path) {
        let new = self.t.path("bin/syq.new");
        executable_support::write_executable(
            &new,
            format!(
                "#!/bin/sh\nif [ \"$1\" = --build-identity ]; then echo {build}; exit 0; fi\n\
                 printf '%s\\n' \"$*\" >> '{}'\n",
                log.display()
            ),
            0o755,
        );
        fs::rename(&new, &self.syq).unwrap();
    }
}

/// After an update replaces the syq a receiving service was started from,
/// the service switches to the new build by itself, by running its
/// `persist connect` without prompts, but only once nothing is in progress.
/// A request held open on its connection keeps it waiting, and it says so in
/// its status; a request to stop it once idle is refused meanwhile.
#[test]
fn a_receiving_service_switches_to_a_new_build_at_its_path_once_idle() {
    let t = Tmp::new();
    let installed = Installed::new(&t);
    let _off = ScopeOff(&t, installed.scope.clone());
    installed.connect();
    let status = || installed.request(serde_json::json!({"version": 2, "stop": false}));
    let state = status();
    assert_eq!(state["started_from"], installed.syq.to_str().unwrap());
    assert_eq!(
        state["busy"],
        serde_json::json!({"requests": 0, "pending": 0, "accounts": 0})
    );
    assert!(state.get("switch").is_none(), "{state}");

    // Hold a request open on the connection's local socket, as a copy would.
    let log = fs::read_to_string(t.path("rsh.log")).unwrap();
    let forward = log
        .lines()
        .find_map(|line| line.split(" -R ").nth(1))
        .expect("receiving connection");
    let broker = forward
        .split_whitespace()
        .next()
        .unwrap()
        .split_once(':')
        .unwrap()
        .1;
    let mut request = std::os::unix::net::UnixStream::connect(broker).unwrap();
    request.write_all(&[0, 0]).unwrap();
    wait_for(
        "the request to count",
        std::time::Duration::from_secs(5),
        || status()["busy"]["requests"] == 1,
    );

    let switched = t.path("switched.log");
    // The provider follows the same file and switches as soon as it can;
    // only the receiving service's switch connects to test-server.
    let connects = || {
        fs::read_to_string(&switched)
            .unwrap_or_default()
            .lines()
            .filter(|line| line.starts_with("persist connect "))
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    installed.update("v99.0.0-switch-test", &switched);
    wait_for(
        "the service to wait",
        std::time::Duration::from_secs(10),
        || status()["switch"]["phase"] == "waiting",
    );
    assert_eq!(status()["switch"]["to"], "v99.0.0-switch-test");
    let shown = persistence_command(
        &t,
        &["status", "--pscope", installed.scope.to_str().unwrap()],
    )
    .run()
    .unwrap();
    assert_output_ok(&shown);
    let shown = String::from_utf8_lossy(&shown.stdout);
    assert!(
        shown.contains("receiving switches to syq v99.0.0-switch-test once idle"),
        "{shown}"
    );
    // Busy: neither the service nor a request to stop once idle switches it.
    let answer =
        installed.request(serde_json::json!({"version": 2, "stop": false, "stop_if_idle": true}));
    assert!(answer.get("stopping").is_none(), "{answer}");
    std::thread::sleep(std::time::Duration::from_secs(1));
    let state = status();
    assert_eq!(state["busy"]["requests"], 1, "{state}");
    assert!(connects().is_empty(), "{:?}: {state}", connects());

    // Once the request ends and a quiet while passes, it runs the new
    // build's connect, for this server and scope, without prompts.
    drop(request);
    wait_for("the switch", std::time::Duration::from_secs(20), || {
        !connects().is_empty()
    });
    assert_eq!(
        connects(),
        [format!(
            "persist connect test-server --auth-from ssh --when-idle --pscope {}",
            installed.scope.display()
        )]
    );
    // The new build stops it once idle.
    let answer =
        installed.request(serde_json::json!({"version": 2, "stop": false, "stop_if_idle": true}));
    assert_eq!(answer["stopping"], true, "{answer}");
    let socket = PathBuf::from(format!("{}.recv", installed.control().display()));
    wait_for(
        "the service to stop",
        std::time::Duration::from_secs(15),
        || !socket.exists(),
    );
}

/// Replace the fixture's receiving service with a stand-in for one an
/// older syq left running: its record names the older build, and it
/// answers as an older service does, with `pending` requests and without
/// saying what else it has in progress or what it follows. It returns the
/// requests it received once stopped.
fn older_service(
    installed: &Installed,
    pending: serde_json::Value,
) -> std::thread::JoinHandle<Vec<serde_json::Value>> {
    other_service(installed, pending, None, None)
}

/// Stop the fixture's receiving service and record its control as an older
/// build's, holding its lock as that service would. Returns the control
/// socket's path, where a stand-in may listen, and the lock.
fn retire_service(installed: &Installed) -> (PathBuf, File) {
    let control = installed.control();
    let suffixed = |suffix: &str| PathBuf::from(format!("{}{suffix}", control.display()));
    let pid = installed.request(serde_json::json!({"version": 2, "stop": false}))["pid"]
        .as_u64()
        .unwrap();
    unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let lock = loop {
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .open(suffixed(".recv-lock"))
            .unwrap();
        if unsafe {
            libc::flock(
                std::os::fd::AsRawFd::as_raw_fd(&lock),
                libc::LOCK_EX | libc::LOCK_NB,
            )
        } == 0
            && !suffixed(".recv").exists()
        {
            break lock;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the service did not stop"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    let mut record: serde_json::Value =
        serde_json::from_slice(&read(&suffixed(".recv-json"))).unwrap();
    record["identity"] = "v0.7.1".into();
    fs::write(suffixed(".recv-json"), serde_json::to_vec(&record).unwrap()).unwrap();
    fs::set_permissions(suffixed(".recv-json"), fs::Permissions::from_mode(0o600)).unwrap();
    (suffixed(".recv"), lock)
}

/// As `older_service`; with `busy`, it reports what it has in progress as
/// services do since syq follows updates, and agrees to stop when idle.
/// With `pending_once`, its `pending` requests appear once that file exists.
fn other_service(
    installed: &Installed,
    pending: serde_json::Value,
    busy: Option<serde_json::Value>,
    pending_once: Option<PathBuf>,
) -> std::thread::JoinHandle<Vec<serde_json::Value>> {
    let (socket, lock) = retire_service(installed);
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    std::thread::spawn(move || {
        let mut requests = Vec::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        loop {
            let mut stream = match listener.accept() {
                Ok((stream, _)) => stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "the older service was not replaced: {requests:?}"
                    );
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
                Err(error) => panic!("{error}"),
            };
            // A client may have given up and left already; macOS then
            // refuses socket options.
            if stream.set_nonblocking(false).is_err()
                || stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .is_err()
            {
                continue;
            }
            let request = read_provider_frame(&mut stream);
            let pending = match &pending_once {
                Some(file) if !file.exists() => serde_json::json!([]),
                _ => pending.clone(),
            };
            let mut answer = serde_json::json!({
                "version": 2, "identity": "v0.7.1", "pid": 0,
                "endpoint": "test-server", "name": "",
                "connection": {"phase": "online", "error": null, "ssh_pid": null},
                "pending": pending
            });
            let stop =
                request["stop"] == true || (busy.is_some() && request["stop_if_idle"] == true);
            if let Some(busy) = &busy {
                answer["busy"] = busy.clone();
                answer["stopping"] = stop.into();
            }
            requests.push(request);
            write_provider_frame(&mut stream, answer);
            if stop {
                fs::remove_file(&socket).unwrap();
                drop(lock);
                return requests;
            }
        }
    })
}

/// The build of the syq under test.
fn this_build() -> String {
    let build = Command::new(env!("CARGO_BIN_EXE_syq"))
        .arg("--build-identity")
        .capture_output()
        .unwrap();
    String::from_utf8(build.stdout).unwrap().trim().to_owned()
}

/// The SSH authorization provider follows an update of the syq it was
/// started from too: once no login or request is in progress, it runs the
/// new build's command to replace it.
#[test]
fn the_provider_switches_to_a_new_build_at_its_path_once_idle() {
    let t = Tmp::new();
    let installed = Installed::new(&t);
    let _off = ScopeOff(&t, installed.scope.clone());
    assert_output_ok(&installed.persist(
        &installed.syq,
        &["receive", "on", "--notify", "off", "--root", &t.s("root")],
    ));
    let provider = || {
        let status = installed.persist(
            Path::new(env!("CARGO_BIN_EXE_syq")),
            &["receive", "status", "--json"],
        );
        assert_output_ok(&status);
        serde_json::from_slice::<serde_json::Value>(&status.stdout).unwrap()["provider"].clone()
    };
    assert_eq!(provider()["started_from"], installed.syq.to_str().unwrap());
    assert_eq!(provider()["busy"], 0);
    let switched = t.path("switched.log");
    installed.update("v99.0.0-switch-test", &switched);
    wait_for("the switch", std::time::Duration::from_secs(20), || {
        switched.exists()
    });
    assert_eq!(
        fs::read_to_string(&switched).unwrap(),
        format!(
            "persist receive switch-provider --pscope {}\n",
            installed.scope.display()
        )
    );
}

/// A Homebrew-style install: syq runs through a link in a group writable
/// directory, as `/opt/homebrew/bin` is, and an update only points the link
/// at another version's directory. The service follows the link.
#[test]
fn a_receiving_service_follows_a_link_that_an_update_repoints() {
    let t = Tmp::new();
    let installed = Installed::new(&t);
    let _off = ScopeOff(&t, installed.scope.clone());
    fs::create_dir_all(t.path("Cellar/1")).unwrap();
    fs::create_dir_all(t.path("Cellar/2")).unwrap();
    fs::rename(&installed.syq, t.path("Cellar/1/syq")).unwrap();
    std::os::unix::fs::symlink("../Cellar/1/syq", &installed.syq).unwrap();
    fs::set_permissions(t.path("bin"), fs::Permissions::from_mode(0o775)).unwrap();
    installed.connect();
    let state = installed.request(serde_json::json!({"version": 2, "stop": false}));
    assert_eq!(state["started_from"], installed.syq.to_str().unwrap());

    let switched = t.path("switched.log");
    executable_support::write_executable(
        &t.path("Cellar/2/syq"),
        format!(
            "#!/bin/sh\nif [ \"$1\" = --build-identity ]; then echo v99.0.0-link-test; exit 0; fi\n\
             printf '%s\\n' \"$*\" >> '{}'\n",
            switched.display()
        ),
        0o755,
    );
    std::os::unix::fs::symlink("../Cellar/2/syq", t.path("bin/syq.new")).unwrap();
    fs::rename(t.path("bin/syq.new"), &installed.syq).unwrap();
    wait_for("the switch", std::time::Duration::from_secs(20), || {
        fs::read_to_string(&switched)
            .unwrap_or_default()
            .lines()
            .any(|line| line.starts_with("persist connect test-server "))
    });
}

/// A switch whose new receiving connection could not log in, though the
/// control connection works, as when a key was unloaded from the agent,
/// leaves the old service receiving. It says it waits for a syq command to
/// the server, and commands wait before trying again.
#[test]
fn a_switch_that_cannot_log_in_leaves_the_old_service_receiving() {
    let t = Tmp::new();
    let installed = Installed::new(&t);
    let _off = ScopeOff(&t, installed.scope.clone());
    installed.connect();
    let old = other_service(
        &installed,
        serde_json::json!([]),
        Some(serde_json::json!({"requests": 0, "pending": 0})),
        None,
    );
    let syq = Path::new(env!("CARGO_BIN_EXE_syq"));
    let mut command = installed.command(
        syq,
        &[
            "persist",
            "connect",
            "test-server",
            "--auth-from",
            "ssh",
            "--when-idle",
            "--pscope",
            installed.scope.to_str().unwrap(),
        ],
    );
    let switched = command.env("FAKE_SSH_REJECT_DIRECT", "1").run().unwrap();
    assert_eq!(switched.status.code(), Some(78), "{switched:?}");
    assert!(
        stderr_of(&switched).contains("logging in to test-server needs you"),
        "{}",
        stderr_of(&switched)
    );
    // The old service was only asked for its status, and still answers.
    let state = installed.request(serde_json::json!({"version": 2, "stop": false}));
    assert_eq!(state["identity"], "v0.7.1");
    let status = installed.persist(syq, &["status", "--json"]);
    assert_output_ok(&status);
    let status: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    let switch = &status["connections"][0]["receiving_switch"];
    assert_eq!(switch["phase"], "login", "{status}");
    assert_eq!(switch["to"], this_build(), "{status}");
    let shown = installed.persist(syq, &["status"]);
    assert!(
        String::from_utf8_lossy(&shown.stdout).contains(
            "when you next run a syq copy or ssh command, or syq persist status, in a terminal"
        ),
        "{}",
        String::from_utf8_lossy(&shown.stdout)
    );
    // A command without a terminal does not try again: the user is not
    // there to unlock or touch a key.
    fs::write(t.path("source"), b"data").unwrap();
    let copied = installed
        .command(
            syq,
            &[
                "cp",
                "--pscope",
                installed.scope.to_str().unwrap(),
                &t.s("source"),
                "--as",
                &t.s("copy"),
            ],
        )
        .run()
        .unwrap();
    assert_output_ok(&copied);
    assert!(
        !stderr_of(&copied).contains("switching"),
        "{}",
        stderr_of(&copied)
    );
    // A switch the service started leaves the user's next command in a
    // terminal free to try again; one a command started holds commands off
    // for ten minutes, since each attempt is a failed login on the server.
    let record = PathBuf::from(format!("{}.json", installed.control().display()));
    let next_claim = || fs::metadata(&record).unwrap().modified().unwrap();
    assert!(next_claim() <= std::time::SystemTime::now(), "deferred");
    let mut by_command = installed.command(
        syq,
        &[
            "persist",
            "connect",
            "test-server",
            "--auth-from",
            "ssh",
            "--when-idle",
            "--pscope",
            installed.scope.to_str().unwrap(),
        ],
    );
    let switched = by_command
        .env("FAKE_SSH_REJECT_DIRECT", "1")
        .env("SYQ_SWITCH_BY_COMMAND", "1")
        .run()
        .unwrap();
    assert_eq!(switched.status.code(), Some(78), "{switched:?}");
    assert!(
        next_claim() >= std::time::SystemTime::now() + std::time::Duration::from_secs(9 * 60),
        "not deferred"
    );
    installed.request(serde_json::json!({"version": 2, "stop": true}));
    let requests = old.join().unwrap();
    assert!(
        requests[..requests.len() - 1]
            .iter()
            .all(|request| request == &serde_json::json!({"version": 2, "stop": false})),
        "{requests:?}"
    );
}

/// A request that begins waiting for approval while a switch checks its
/// login keeps an older service, which reports only such requests, running.
#[test]
fn a_request_waiting_for_approval_during_the_login_check_keeps_the_old_service() {
    let t = Tmp::new();
    let installed = Installed::new(&t);
    let _off = ScopeOff(&t, installed.scope.clone());
    installed.connect();
    let checked = t.path("login-checked");
    let old = other_service(
        &installed,
        serde_json::json!([{
            "id": "0123456789abcdef0123456789abcdef", "from": "test-server",
            "expires_at": 4102444800u64, "notification": "none",
            "destination": "/inbox", "permission": "write", "max_bytes": 1,
            "max_entries": 1, "max_delete": 0, "preserve_permissions": false
        }]),
        None,
        Some(checked.clone()),
    );
    let syq = Path::new(env!("CARGO_BIN_EXE_syq"));
    let switched = installed
        .command(
            syq,
            &[
                "persist",
                "connect",
                "test-server",
                "--auth-from",
                "ssh",
                "--when-idle",
                "--pscope",
                installed.scope.to_str().unwrap(),
            ],
        )
        .env("FAKE_SSH_DIRECT_MARK", &checked)
        .run()
        .unwrap();
    assert_output_ok(&switched);
    assert!(checked.exists(), "the login was not checked");
    assert!(
        String::from_utf8_lossy(&switched.stdout)
            .contains("keeps running syq v0.7.1 for now, with 1 request waiting for approval"),
        "{switched:?}"
    );
    installed.request(serde_json::json!({"version": 2, "stop": true}));
    let requests = old.join().unwrap();
    assert!(
        requests[..requests.len() - 1]
            .iter()
            .all(|request| request == &serde_json::json!({"version": 2, "stop": false})),
        "{requests:?}"
    );
}

/// A switch a command started in the background says in status how it
/// went, even for a service that cannot report it.
#[test]
fn a_background_switch_that_fails_shows_why_in_status() {
    let t = Tmp::new();
    let installed = Installed::new(&t);
    let _off = ScopeOff(&t, installed.scope.clone());
    installed.connect();
    let _old = older_service(&installed, serde_json::json!([]));
    let syq = Path::new(env!("CARGO_BIN_EXE_syq"));
    fs::write(t.path("source"), b"data").unwrap();
    let copied = installed
        .command(
            syq,
            &[
                "cp",
                "--pscope",
                installed.scope.to_str().unwrap(),
                &t.s("source"),
                "--as",
                &t.s("copy"),
            ],
        )
        .env("FAKE_SSH_REFUSE", "1")
        .run()
        .unwrap();
    assert_output_ok(&copied);
    assert!(stderr_of(&copied).contains("switching receiving through test-server"));
    let switch = || {
        let status = installed.persist(syq, &["status", "--json"]);
        assert_output_ok(&status);
        let status: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
        status["connections"][0]["receiving_switch"].clone()
    };
    wait_for(
        "the failed switch",
        std::time::Duration::from_secs(30),
        || switch()["phase"] == "failed",
    );
    let switch = switch();
    assert_eq!(switch["to"], this_build());
    assert!(
        switch["error"].as_str().unwrap().contains("test-server"),
        "{switch}"
    );
    installed.request(serde_json::json!({"version": 2, "stop": true}));
}

/// `syq ssh --pscope PATH` switches the services in that domain, not the
/// default domain's.
#[test]
fn ssh_switches_services_in_its_own_domain() {
    let t = Tmp::new();
    let installed = Installed::new(&t);
    let _off = ScopeOff(&t, installed.scope.clone());
    installed.connect();
    let old = older_service(&installed, serde_json::json!([]));
    let syq = Path::new(env!("CARGO_BIN_EXE_syq"));
    // The default domain, with persistence off, switches nothing.
    let plain = installed
        .command(syq, &["ssh", "other.invalid", "--", "true"])
        .run()
        .unwrap();
    assert!(
        !stderr_of(&plain).contains("switching"),
        "{}",
        stderr_of(&plain)
    );
    let scoped = installed
        .command(
            syq,
            &[
                "ssh",
                "--pscope",
                installed.scope.to_str().unwrap(),
                "other.invalid",
                "--",
                "true",
            ],
        )
        .run()
        .unwrap();
    assert!(
        stderr_of(&scoped).contains("switching receiving through test-server"),
        "{}",
        stderr_of(&scoped)
    );
    let requests = old.join().unwrap();
    assert_eq!(
        requests.last().unwrap(),
        &serde_json::json!({"version": 2, "stop": true})
    );
}

/// A switch to a new build never turns persistence back on: with it off,
/// as after `syq persist off`, `persist connect --when-idle` does nothing.
#[test]
fn a_switch_does_not_turn_persistence_back_on() {
    let t = Tmp::new();
    fs::create_dir(t.runtime()).unwrap();
    let _persistence = PersistenceOff(&t);
    let ssh = fake_ssh(&t);
    let connect = || {
        persistence_command(
            &t,
            &[
                "connect",
                "test-server",
                "--auth-from",
                "ssh",
                "--when-idle",
            ],
        )
        .env("HOME", t.path(""))
        .env("FAKE_RSH_LOG", t.path("rsh.log"))
        .env(
            "PATH",
            format!("{}:/usr/bin:/bin", ssh.parent().unwrap().display()),
        )
        .run()
        .unwrap()
    };
    let enabled = || {
        let status = persistence_command(&t, &["status", "--json"])
            .run()
            .unwrap();
        assert_output_ok(&status);
        serde_json::from_slice::<serde_json::Value>(&status.stdout).unwrap()["enabled"].clone()
    };
    // Never turned on, and turned off.
    for off in [false, true] {
        if off {
            assert_output_ok(&persistence_command(&t, &["off"]).run().unwrap());
        }
        let switched = connect();
        assert_output_ok(&switched);
        assert!(switched.stdout.is_empty(), "{switched:?}");
        assert_eq!(enabled(), false);
        assert!(!t.path("rsh.log").exists(), "it logged in");
    }
}

/// Run a no-op local copy in the fixture's scope, which looks at its stale
/// service with the usual short budget, and return how long it took.
fn local_copy(t: &Tmp, installed: &Installed) -> std::time::Duration {
    fs::write(t.path("source"), b"data").unwrap();
    let started = std::time::Instant::now();
    let mut command = installed.command(
        Path::new(env!("CARGO_BIN_EXE_syq")),
        &[
            "cp",
            "--pscope",
            installed.scope.to_str().unwrap(),
            &t.s("source"),
            "--as",
            &t.s("copy"),
        ],
    );
    let copied = command
        .env_remove("SYQ_TEST_REFRESH_ANSWER_MS")
        .run()
        .unwrap();
    assert_output_ok(&copied);
    started.elapsed()
}

/// A command waits only briefly for a stale service that accepts its status
/// request but never answers: it gives up on the connection within its
/// short budget rather than a socket timeout's second.
#[test]
fn a_silent_stale_service_holds_a_command_only_briefly() {
    let t = Tmp::new();
    let installed = Installed::new(&t);
    let _off = ScopeOff(&t, installed.scope.clone());
    installed.connect();
    let (socket, lock) = retire_service(&installed);
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let silent = std::thread::spawn(move || {
        let (mut client, _) = listener.accept().unwrap();
        let accepted = std::time::Instant::now();
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        // Read the request and wait, never answering, until the client
        // gives up.
        let _ = std::io::copy(&mut client, &mut std::io::sink());
        let held = accepted.elapsed();
        fs::remove_file(&socket).unwrap();
        drop(lock);
        held
    });
    local_copy(&t, &installed);
    let held = silent.join().unwrap();
    assert!(held < std::time::Duration::from_millis(500), "{held:?}");
}

/// A stale service whose control socket's listen queue is full does not
/// block a command: it does not wait to connect.
#[test]
fn a_stale_service_with_a_full_queue_does_not_block_a_command() {
    use socket2::{Domain, SockAddr, Socket, Type};
    let t = Tmp::new();
    let installed = Installed::new(&t);
    let _off = ScopeOff(&t, installed.scope.clone());
    installed.connect();
    let (socket, lock) = retire_service(&installed);
    let listener = Socket::new(Domain::UNIX, Type::STREAM, None).unwrap();
    listener.bind(&SockAddr::unix(&socket).unwrap()).unwrap();
    listener.listen(1).unwrap();
    let mut queued = Vec::new();
    loop {
        let client = Socket::new(Domain::UNIX, Type::STREAM, None).unwrap();
        client.set_nonblocking(true).unwrap();
        match client.connect(&SockAddr::unix(&socket).unwrap()) {
            Ok(()) => queued.push(client),
            Err(_) => break,
        }
        assert!(queued.len() < 1024, "the listen queue did not fill");
    }
    // Without its own deadline, the command's connect would wait here for
    // as long as nothing accepts.
    let (done, finished) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            local_copy(&t, &installed);
            done.send(()).unwrap();
        });
        finished
            .recv_timeout(std::time::Duration::from_secs(20))
            .expect("the command waited on a full listen queue");
    });
    drop(queued);
    drop(listener);
    fs::remove_file(&socket).unwrap();
    drop(lock);
}

/// A switch that runs too long after logging in, as while installing the
/// helper over a slow link, ends itself, with the ssh it started, and says
/// so in status.
#[test]
fn a_switch_that_runs_too_long_ends_with_what_it_started() {
    let t = Tmp::new();
    let installed = Installed::new(&t);
    let _off = ScopeOff(&t, installed.scope.clone());
    installed.connect();
    let old = older_service(&installed, serde_json::json!([]));
    let syq = Path::new(env!("CARGO_BIN_EXE_syq"));
    let started = t.path("ssh.pids");
    // As a service or command starts it: leading its own process group.
    let mut switch = installed.command(
        syq,
        &[
            "persist",
            "connect",
            "test-server",
            "--auth-from",
            "ssh",
            "--when-idle",
            "--pscope",
            installed.scope.to_str().unwrap(),
        ],
    );
    // Its login, which ends 2 s before the switch's time does, is done
    // long before then.
    let mut switch = switch
        .env("FAKE_SSH_PIDS", &started)
        .env("SYQ_TEST_SWITCH_STALL_MS", "60000")
        .env("SYQ_TEST_SWITCH_TIMEOUT_MS", "6000")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .unwrap();
    let status = switch.wait().unwrap();
    assert_eq!(
        std::os::unix::process::ExitStatusExt::signal(&status),
        Some(libc::SIGKILL)
    );
    let ssh: Vec<libc::pid_t> = fs::read_to_string(&started)
        .unwrap()
        .lines()
        .map(|pid| pid.parse().unwrap())
        .collect();
    assert!(!ssh.is_empty());
    wait_for("ssh to end", std::time::Duration::from_secs(10), || {
        ssh.iter().all(|&pid| ended(pid))
    });
    let shown = installed.persist(syq, &["status", "--json"]);
    assert_output_ok(&shown);
    let shown: serde_json::Value = serde_json::from_slice(&shown.stdout).unwrap();
    let switched = &shown["connections"][0]["receiving_switch"];
    assert_eq!(switched["phase"], "failed", "{shown}");
    assert!(
        switched["error"]
            .as_str()
            .unwrap()
            .contains("switching took longer than"),
        "{shown}"
    );
    installed.request(serde_json::json!({"version": 2, "stop": true}));
    old.join().unwrap();
}

/// Whether process `pid` has ended, though perhaps not yet been reaped.
fn ended(pid: libc::pid_t) -> bool {
    let gone = unsafe { libc::kill(pid, 0) } != 0;
    gone || fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
        stat.rsplit_once(") ")
            .is_some_and(|(_, fields)| fields.starts_with('Z'))
    })
}

/// A switch's control connection whose login gets no answer in time, as
/// when ssh waits for a touch of a security key that nobody gives, ends the
/// switch before its time is up, with that ssh, as one that needs the user,
/// as does a login the server rejects: only a command at a terminal tries
/// it again, so the key does not ask again unattended.
#[test]
fn a_switch_whose_control_login_needs_the_user_waits_for_the_user() {
    let t = Tmp::new();
    let installed = Installed::new(&t);
    let _off = ScopeOff(&t, installed.scope.clone());
    installed.connect();
    let old = older_service(&installed, serde_json::json!([]));
    let syq = Path::new(env!("CARGO_BIN_EXE_syq"));
    let switch = || {
        let mut switch = installed.command(
            syq,
            &[
                "persist",
                "connect",
                "test-server",
                "--auth-from",
                "ssh",
                "--when-idle",
                "--pscope",
                installed.scope.to_str().unwrap(),
            ],
        );
        switch
            .env("SYQ_TEST_SWITCH_TIMEOUT_MS", "6000")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .process_group(0);
        switch
    };
    let phase = || {
        let shown = installed.persist(syq, &["status", "--json"]);
        assert_output_ok(&shown);
        let shown: serde_json::Value = serde_json::from_slice(&shown.stdout).unwrap();
        shown["connections"][0]["receiving_switch"].clone()
    };

    // Rejected.
    let rejected = switch().env("FAKE_SSH_REJECT", "1").output().unwrap();
    assert_eq!(rejected.status.code(), Some(78), "{rejected:?}");
    assert!(
        stderr_of(&rejected).contains("logging in to test-server needs you"),
        "{}",
        stderr_of(&rejected)
    );
    assert_eq!(phase()["phase"], "login");

    // No answer.
    let hung = t.path("ssh.pid");
    let started = std::time::Instant::now();
    let mut waiting = switch().env("FAKE_SSH_HANG", &hung).spawn().unwrap();
    wait_for(
        "its login to start",
        std::time::Duration::from_secs(20),
        || fs::read_to_string(&hung).is_ok_and(|pid| !pid.trim().is_empty()),
    );
    let ssh: libc::pid_t = fs::read_to_string(&hung).unwrap().trim().parse().unwrap();
    let mut stderr = String::new();
    std::io::Read::read_to_string(waiting.stderr.as_mut().unwrap(), &mut stderr).unwrap();
    let status = waiting.wait().unwrap();
    assert_eq!(status.code(), Some(78), "{status:?}: {stderr}");
    assert!(started.elapsed() < std::time::Duration::from_secs(6));
    assert!(stderr.contains("did not finish logging in"), "{stderr}");
    wait_for("ssh to end", std::time::Duration::from_secs(10), || {
        ended(ssh)
    });
    let switched = phase();
    assert_eq!(switched["phase"], "login", "{switched}");
    assert!(
        switched["error"]
            .as_str()
            .unwrap()
            .contains("did not finish logging in"),
        "{switched}"
    );
    // The old service still receives.
    let state = installed.request(serde_json::json!({"version": 2, "stop": false}));
    assert_eq!(state["identity"], "v0.7.1");
    installed.request(serde_json::json!({"version": 2, "stop": true}));
    old.join().unwrap();
}

/// A switch whose own login gets no answer in time, as when ssh waits for
/// a touch of a security key that nobody gives, ends before its time is up,
/// with that ssh, as one that needs the user: only a command at a terminal
/// tries it again, so the key does not ask again unattended. Its ssh runs in
/// the switch's process group, so that it ends with the switch whenever
/// that ends.
#[test]
fn a_switch_whose_login_gets_no_answer_waits_for_the_user() {
    let t = Tmp::new();
    let installed = Installed::new(&t);
    let _off = ScopeOff(&t, installed.scope.clone());
    installed.connect();
    let old = older_service(&installed, serde_json::json!([]));
    let syq = Path::new(env!("CARGO_BIN_EXE_syq"));
    let hung = t.path("ssh.pid");
    let switch = |timeout: &str| {
        let _ = fs::remove_file(&hung);
        let mut switch = installed.command(
            syq,
            &[
                "persist",
                "connect",
                "test-server",
                "--auth-from",
                "ssh",
                "--when-idle",
                "--pscope",
                installed.scope.to_str().unwrap(),
            ],
        );
        let switch = switch
            .env("FAKE_SSH_HANG_DIRECT", &hung)
            .env("SYQ_TEST_SWITCH_TIMEOUT_MS", timeout)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .unwrap();
        wait_for(
            "its login to start",
            std::time::Duration::from_secs(20),
            || fs::read_to_string(&hung).is_ok_and(|pid| !pid.trim().is_empty()),
        );
        let pid = |path: &Path| -> libc::pid_t {
            fs::read_to_string(path).unwrap().trim().parse().unwrap()
        };
        (switch, pid(&hung), pid(&hung.with_extension("pid.child")))
    };
    let (mut first, ssh, child) = switch("8000");
    let started = std::time::Instant::now();
    let status = first.wait().unwrap();
    assert_eq!(status.code(), Some(78), "{status:?}");
    assert!(started.elapsed() < std::time::Duration::from_secs(8));
    // The switch ends its ssh's own processes too, though nobody ends its
    // group after it, as when the command that started it is gone.
    wait_for("ssh to end", std::time::Duration::from_secs(10), || {
        ended(ssh) && ended(child)
    });
    let shown = installed.persist(syq, &["status", "--json"]);
    assert_output_ok(&shown);
    let shown: serde_json::Value = serde_json::from_slice(&shown.stdout).unwrap();
    let switched = &shown["connections"][0]["receiving_switch"];
    assert_eq!(switched["phase"], "login", "{shown}");
    assert!(
        switched["error"]
            .as_str()
            .unwrap()
            .contains("did not finish logging in"),
        "{shown}"
    );
    // The old service still receives.
    let state = installed.request(serde_json::json!({"version": 2, "stop": false}));
    assert_eq!(state["identity"], "v0.7.1");

    // Ending the switch's group, as its time limit or the service that
    // started it does, ends its login with it.
    let (mut second, ssh, child) = switch("60000");
    unsafe { libc::kill(-(second.id() as libc::pid_t), libc::SIGKILL) };
    second.wait().unwrap();
    wait_for("ssh to end", std::time::Duration::from_secs(10), || {
        ended(ssh) && ended(child)
    });
    installed.request(serde_json::json!({"version": 2, "stop": true}));
    old.join().unwrap();
}

/// A service that an older syq left running cannot follow an update by
/// itself. Any syq command run here replaces it with this build once it is
/// idle, in the background, and says so; the service's settings stay.
#[test]
fn commands_replace_an_idle_service_an_older_syq_left_running() {
    let t = Tmp::new();
    let installed = Installed::new(&t);
    let _off = ScopeOff(&t, installed.scope.clone());
    installed.connect();
    let settings = read(&installed.scope.join("receive.json"));
    let old = older_service(&installed, serde_json::json!([]));

    // A local copy, which talks to no server.
    fs::write(t.path("source"), b"data").unwrap();
    let copied = installed
        .command(
            Path::new(env!("CARGO_BIN_EXE_syq")),
            &[
                "cp",
                "--pscope",
                installed.scope.to_str().unwrap(),
                &t.s("source"),
                "--as",
                &t.s("copy"),
            ],
        )
        .run()
        .unwrap();
    assert_output_ok(&copied);
    // An older service cannot say whether a copy is in progress.
    assert!(
        stderr_of(&copied).contains(
            "switching receiving through test-server, which runs syq v0.7.1, to this version of syq in the background (a copy in progress through it would be interrupted)"
        ),
        "{}",
        stderr_of(&copied)
    );
    let requests = old.join().unwrap();
    // It never sent the older service a request it cannot read.
    assert!(
        requests
            .iter()
            .all(|request| request.get("stop_if_idle").is_none()),
        "{requests:?}"
    );
    assert_eq!(
        requests.last().unwrap(),
        &serde_json::json!({"version": 2, "stop": true})
    );
    let socket = PathBuf::from(format!("{}.recv", installed.control().display()));
    wait_for(
        "this build's service",
        std::time::Duration::from_secs(20),
        || {
            std::os::unix::net::UnixStream::connect(&socket).is_ok()
                && installed.request(serde_json::json!({"version": 2, "stop": false}))["identity"]
                    == this_build()
        },
    );
    assert_eq!(read(&installed.scope.join("receive.json")), settings);
}

/// After an update, the `persist` commands the user types replace an idle
/// service that an older syq left running at once, in the foreground, and
/// say so: `persist receive on` used to stop it without starting this
/// build's, and `persist on` and `persist status` left it running.
#[test]
fn persist_commands_replace_an_idle_older_service_at_once() {
    let t = Tmp::new();
    let installed = Installed::new(&t);
    let _off = ScopeOff(&t, installed.scope.clone());
    installed.connect();
    let syq = Path::new(env!("CARGO_BIN_EXE_syq"));
    let socket = PathBuf::from(format!("{}.recv", installed.control().display()));
    for command in [
        &["status"][..],
        &["on"],
        &["receive", "on"],
        &["receive", "status"],
    ] {
        let old = older_service(&installed, serde_json::json!([]));
        let output = installed.persist(syq, command);
        assert_output_ok(&output);
        assert!(
            stderr_of(&output).contains(
                "switching receiving through test-server, which runs syq v0.7.1, to this version of syq (a copy in progress through it would be interrupted)\n"
            ),
            "{command:?}: {}",
            stderr_of(&output)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("test-server ready; receiving as @"),
            "{command:?}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        // An older service has only an unconditional stop.
        assert_eq!(
            old.join().unwrap().last().unwrap(),
            &serde_json::json!({"version": 2, "stop": true}),
            "{command:?}"
        );
        // This build receives when the command returns.
        assert!(std::os::unix::net::UnixStream::connect(&socket).is_ok());
        assert_eq!(
            installed.request(serde_json::json!({"version": 2, "stop": false}))["identity"],
            this_build(),
            "{command:?}"
        );
    }
    // Structured status, which scripts poll, never logs in.
    let old = older_service(&installed, serde_json::json!([]));
    let output = installed.persist(syq, &["status", "--json"]);
    assert_output_ok(&output);
    assert!(
        !stderr_of(&output).contains("switching"),
        "{}",
        stderr_of(&output)
    );
    installed.request(serde_json::json!({"version": 2, "stop": true}));
    old.join().unwrap();
}

/// Without a terminal, a `persist` command's switch never asks for a login.
/// One that needs the user is recorded as such, and the next command
/// without a terminal leaves it, rather than failing to log in again.
#[test]
fn a_switch_without_a_terminal_that_needs_a_login_is_not_retried() {
    let t = Tmp::new();
    let installed = Installed::new(&t);
    let _off = ScopeOff(&t, installed.scope.clone());
    installed.connect();
    let old = older_service(&installed, serde_json::json!([]));
    let syq = Path::new(env!("CARGO_BIN_EXE_syq"));
    let status = || {
        let mut command = installed.command(
            syq,
            &[
                "persist",
                "status",
                "--pscope",
                installed.scope.to_str().unwrap(),
            ],
        );
        command.env("FAKE_SSH_REJECT", "1").run().unwrap()
    };
    let before = fs::read_to_string(t.path("rsh.log")).unwrap();
    let shown = status();
    assert_output_ok(&shown);
    assert!(
        stderr_of(&shown).contains("could not switch receiving through test-server"),
        "{}",
        stderr_of(&shown)
    );
    let logged = fs::read_to_string(t.path("rsh.log")).unwrap();
    // ssh was told never to ask, and not to wait long for the server.
    assert!(
        logged[before.len()..]
            .contains("-o BatchMode=yes -o ConnectTimeout=10 -o ControlMaster=auto"),
        "{}",
        &logged[before.len()..]
    );
    assert!(
        String::from_utf8_lossy(&shown.stdout).contains("in a terminal"),
        "{}",
        String::from_utf8_lossy(&shown.stdout)
    );
    let json = installed.persist(syq, &["status", "--json"]);
    let json: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(
        json["connections"][0]["receiving_switch"]["phase"], "login",
        "{json}"
    );
    // The old service still receives, and the next status leaves it.
    let state = installed.request(serde_json::json!({"version": 2, "stop": false}));
    assert_eq!(state["identity"], "v0.7.1");
    let again = status();
    assert_output_ok(&again);
    assert!(
        !stderr_of(&again).contains("switch"),
        "{}",
        stderr_of(&again)
    );
    assert_eq!(fs::read_to_string(t.path("rsh.log")).unwrap(), logged);
    installed.request(serde_json::json!({"version": 2, "stop": true}));
    old.join().unwrap();
}

/// A `persist` command's switch logs in as the new receiving service will,
/// apart from the live control connection, before it stops the old one:
/// when that login fails, the old service keeps receiving.
#[test]
fn a_foreground_switch_that_cannot_log_in_leaves_the_old_service_receiving() {
    let t = Tmp::new();
    let installed = Installed::new(&t);
    let _off = ScopeOff(&t, installed.scope.clone());
    installed.connect();
    let old = older_service(&installed, serde_json::json!([]));
    let syq = Path::new(env!("CARGO_BIN_EXE_syq"));
    let mut command = installed.command(
        syq,
        &[
            "persist",
            "status",
            "--pscope",
            installed.scope.to_str().unwrap(),
        ],
    );
    let shown = command.env("FAKE_SSH_REJECT_DIRECT", "1").run().unwrap();
    assert_output_ok(&shown);
    assert!(
        stderr_of(&shown).contains("logging in to test-server needs you"),
        "{}",
        stderr_of(&shown)
    );
    let state = installed.request(serde_json::json!({"version": 2, "stop": false}));
    assert_eq!(state["identity"], "v0.7.1");
    installed.request(serde_json::json!({"version": 2, "stop": true}));
    let requests = old.join().unwrap();
    // Only the test's own stop.
    assert_eq!(
        requests
            .iter()
            .filter(|request| request["stop"] == true)
            .count(),
        1,
        "{requests:?}"
    );
}

/// A `persist` command leaves a connection whose switch another command
/// started, and never stops a service that took over the connection after
/// it decided to switch: here this build's, busy, which replaced the old
/// one just before the stop.
#[test]
fn a_foreground_switch_never_stops_a_service_that_took_over() {
    let t = Tmp::new();
    let installed = Installed::new(&t);
    let _off = ScopeOff(&t, installed.scope.clone());
    installed.connect();
    let syq = Path::new(env!("CARGO_BIN_EXE_syq"));
    let status = |mark: Option<&Path>| {
        let mut command = installed.command(
            syq,
            &[
                "persist",
                "status",
                "--pscope",
                installed.scope.to_str().unwrap(),
            ],
        );
        if let Some(mark) = mark {
            command.env("FAKE_SSH_DIRECT_MARK", mark);
        }
        command.run().unwrap()
    };

    // Another switch holds the endpoint record's lock.
    let (socket, lock) = retire_service(&installed);
    let record = OpenOptions::new()
        .read(true)
        .open(format!("{}.json", installed.control().display()))
        .unwrap();
    assert_eq!(
        unsafe {
            libc::flock(
                std::os::fd::AsRawFd::as_raw_fd(&record),
                libc::LOCK_EX | libc::LOCK_NB,
            )
        },
        0
    );
    let mark = t.path("logged-in");
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let served = {
        let seen = seen.clone();
        let socket = socket.clone();
        let mark = mark.clone();
        let build = this_build();
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        std::thread::spawn(move || {
            let _lock = lock;
            let mut requests = Vec::new();
            let mut after_login = 0;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
            loop {
                let mut stream = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(std::time::Instant::now() < deadline, "{requests:?}");
                        std::thread::sleep(std::time::Duration::from_millis(10));
                        continue;
                    }
                    Err(error) => panic!("{error}"),
                };
                if stream.set_nonblocking(false).is_err()
                    || stream
                        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                        .is_err()
                {
                    continue;
                }
                let request = read_provider_frame(&mut stream);
                // Once the command has logged in as the new service will,
                // and asked once more, this build's service owns the
                // connection, busy: between the command's last look and its
                // stop.
                let taken_over = mark.exists() && {
                    after_login += 1;
                    after_login > 1
                };
                let answer = if taken_over {
                    serde_json::json!({
                        "version": 2, "identity": build, "pid": 0,
                        "endpoint": "test-server", "name": "",
                        "connection": {"phase": "online", "error": null, "ssh_pid": null},
                        "pending": [], "busy": {"requests": 1, "pending": 0, "accounts": 0},
                        "stopping": false
                    })
                } else {
                    serde_json::json!({
                        "version": 2, "identity": "v0.7.1", "pid": 0,
                        "endpoint": "test-server", "name": "",
                        "connection": {"phase": "online", "error": null, "ssh_pid": null},
                        "pending": []
                    })
                };
                let stop = request["stop"] == true;
                seen.lock().unwrap().push(request.clone());
                requests.push(request);
                write_provider_frame(&mut stream, answer);
                if stop {
                    fs::remove_file(&socket).unwrap();
                    return requests;
                }
            }
        })
    };
    let shown = status(None);
    assert_output_ok(&shown);
    assert!(
        stderr_of(&shown).contains("a switch to this version is already under way"),
        "{}",
        stderr_of(&shown)
    );
    assert!(
        !stderr_of(&shown).contains("Connecting"),
        "{}",
        stderr_of(&shown)
    );
    drop(record);

    let shown = status(Some(&mark));
    assert_output_ok(&shown);
    assert!(mark.exists(), "{}", stderr_of(&shown));
    // Nothing stopped the service that took over.
    assert!(
        seen.lock()
            .unwrap()
            .iter()
            .all(|request| request["stop"] != true),
        "{:?}: {}",
        seen.lock().unwrap(),
        stderr_of(&shown)
    );
    installed.request(serde_json::json!({"version": 2, "stop": true}));
    let requests = served.join().unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request["stop"] == true)
            .count(),
        1,
        "{requests:?}"
    );
}

/// Settings that no longer allow a connection stop the service an older
/// syq left on it, as for any service, without logging in to its server.
#[test]
fn settings_that_drop_a_connection_stop_its_older_service_without_a_login() {
    let t = Tmp::new();
    let installed = Installed::new(&t);
    let _off = ScopeOff(&t, installed.scope.clone());
    installed.connect();
    let old = older_service(&installed, serde_json::json!([]));
    let syq = Path::new(env!("CARGO_BIN_EXE_syq"));
    let logged = fs::read_to_string(t.path("rsh.log")).unwrap();
    let mut command = installed.command(
        syq,
        &[
            "persist",
            "receive",
            "on",
            "--connection",
            "elsewhere",
            "--pscope",
            installed.scope.to_str().unwrap(),
        ],
    );
    let output = command.env("FAKE_SSH_REFUSE", "1").run().unwrap();
    // Connecting elsewhere fails, and only that is reported.
    assert!(!output.status.success());
    assert!(
        stderr_of(&output).contains("some connections are not ready: elsewhere: "),
        "{}",
        stderr_of(&output)
    );
    assert!(
        !stderr_of(&output).contains("switching receiving through test-server"),
        "{}",
        stderr_of(&output)
    );
    assert_eq!(
        old.join().unwrap().last().unwrap(),
        &serde_json::json!({"version": 2, "stop": true})
    );
    let logged_now = fs::read_to_string(t.path("rsh.log")).unwrap();
    assert!(
        !logged_now[logged.len()..].contains("test-server"),
        "{}",
        &logged_now[logged.len()..]
    );
}

/// A service an older syq left running with a request waiting for approval
/// keeps running: a command leaves it, and a switch says why it waits.
/// `persist connect` run by hand replaces it at once and says what that
/// cuts off.
#[test]
fn a_busy_service_is_replaced_only_by_hand_saying_what_that_cuts_off() {
    let t = Tmp::new();
    let installed = Installed::new(&t);
    let _off = ScopeOff(&t, installed.scope.clone());
    installed.connect();
    let old = older_service(
        &installed,
        serde_json::json!([{
            "id": "0123456789abcdef0123456789abcdef", "from": "test-server",
            "expires_at": 4102444800u64, "notification": "none",
            "destination": "/inbox", "permission": "write", "max_bytes": 1,
            "max_entries": 1, "max_delete": 0, "preserve_permissions": false
        }]),
    );
    let syq = Path::new(env!("CARGO_BIN_EXE_syq"));
    fs::write(t.path("source"), b"data").unwrap();
    let copied = installed
        .command(
            syq,
            &[
                "cp",
                "--pscope",
                installed.scope.to_str().unwrap(),
                &t.s("source"),
                "--as",
                &t.s("copy"),
            ],
        )
        .run()
        .unwrap();
    assert_output_ok(&copied);
    assert!(
        !stderr_of(&copied).contains("switching"),
        "{}",
        stderr_of(&copied)
    );
    let waiting = installed.persist(
        syq,
        &[
            "connect",
            "test-server",
            "--auth-from",
            "ssh",
            "--when-idle",
        ],
    );
    assert_output_ok(&waiting);
    assert_eq!(
        String::from_utf8_lossy(&waiting.stdout),
        "receiving through test-server keeps running syq v0.7.1 for now, with 1 request waiting for approval; once nothing is in progress, a syq command run here switches it to this version\n"
    );
    // Status leaves it too, and says why it has not switched.
    let shown = installed.persist(syq, &["status"]);
    assert_output_ok(&shown);
    assert!(
        String::from_utf8_lossy(&shown.stdout).contains(
            "receiving runs syq v0.7.1 for now, with 1 request waiting for approval; a syq command run here switches it to this version once idle"
        ),
        "{}",
        String::from_utf8_lossy(&shown.stdout)
    );
    assert!(
        stderr_of(&shown).contains(
            "receiving through test-server keeps running syq v0.7.1 for now, with 1 request waiting for approval"
        ),
        "{}",
        stderr_of(&shown)
    );

    let replaced = installed.persist(
        syq,
        &[
            "connect",
            "test-server",
            "--timeout",
            "20",
            "--syq-path",
            env!("CARGO_BIN_EXE_syq"),
        ],
    );
    assert_output_ok(&replaced);
    assert!(
        stderr_of(&replaced).contains(
            "replacing receiving through test-server, which runs syq v0.7.1, cuts off 1 request waiting for approval"
        ),
        "{}",
        stderr_of(&replaced)
    );
    let requests = old.join().unwrap();
    assert!(
        requests
            .iter()
            .all(|request| request.get("stop_if_idle").is_none()),
        "{requests:?}"
    );
    assert_eq!(
        installed.request(serde_json::json!({"version": 2, "stop": false}))["identity"],
        this_build()
    );
}

/// A server that refuses remote forwarding cannot carry receiving, however
/// often syq dials it: the connection fails with a status saying why,
/// instead of logging in again every half minute for as long as receiving
/// stays enabled.
#[test]
fn a_server_refusing_remote_forwarding_is_not_redialed() {
    refused_receiving_is_not_redialed(
        "Error: remote port forwarding failed for listen path /tmp/syq-return-test.sock",
        "refuses remote forwarding",
        "then run syq persist connect test-server",
    );
}

/// A server that rejects this machine's SSH login, as after its key was
/// removed there, is tried again only after 30 seconds and then less and
/// less often, rather than every half minute: it may only be an agent still
/// locked after sleep. The status says why meanwhile.
#[test]
fn a_server_rejecting_the_login_is_redialed_less_often() {
    for ssh_error in [
        "syq@test-server: Permission denied (publickey).",
        "Host key verification failed.",
    ] {
        refused_receiving_is_not_redialed(
            ssh_error,
            "cannot log in to test-server",
            " s, or run syq persist connect test-server to try now",
        );
    }
}

/// Other commands that connect to the server try a rejected login again too,
/// but no sooner than a while after the last attempt, so commands that come
/// every few seconds, such as completion, do not log in again each time; and
/// they wake the waiting connection rather than start it over, so its waits
/// keep growing. `persist connect` tries again at once whenever it runs.
#[cfg(debug_assertions)]
#[test]
fn commands_retry_a_rejected_login_no_more_than_once_a_while() {
    let t = Tmp::new();
    fs::create_dir(t.runtime()).unwrap();
    fs::create_dir(t.path("root")).unwrap();
    fs::create_dir(t.path("home")).unwrap();
    write(&t.path("file"), b"copied");
    let ssh = fake_ssh(&t);
    executable(
        &t.path("refusing-bin/ssh"),
        format!(
            "#!/bin/sh\n\
             for argument in \"$@\"; do\n\
             \x20   if [ \"$argument\" = -R ]; then\n\
             \x20       echo dialed >> \"$FAKE_FORWARD_LOG\"\n\
             \x20       echo 'syq@test-server: Permission denied (publickey).' >&2\n\
             \x20       exit 255\n\
             \x20   fi\n\
             done\n\
             exec {} \"$@\"\n",
            ssh.display()
        )
        .as_bytes(),
    );
    let scope = ephemeral_scope(&t);
    let _off = ScopeOff(&t, scope.clone());
    let environment = |command: &mut Command| {
        command
            .env("HOME", t.path("home"))
            .env("XDG_CONFIG_HOME", t.path("config"))
            .env("XDG_RUNTIME_DIR", t.runtime())
            .env("XDG_CACHE_HOME", t.path("cache"))
            .env("FAKE_REMOTE_HOME", t.path("remote-home"))
            .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
            .env("FAKE_RSH_LOG", t.path("rsh.log"))
            .env("FAKE_FORWARD_LOG", t.path("forward.log"))
            .env("SYQ_TEST_COMMAND_RETRY_MS", "8000")
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", t.path("refusing-bin").display()),
            );
    };
    let run = |args: &[&str]| {
        let mut command = persistence_command(&t, args);
        command.args(["--pscope", scope.to_str().unwrap()]);
        environment(&mut command);
        command.run().unwrap()
    };
    assert_output_ok(&run(&[
        "receive",
        "on",
        "--notify",
        "off",
        "--root",
        &t.s("root"),
        "--all-connections",
    ]));
    let connect = || {
        let output = run(&[
            "connect",
            "test-server",
            "--timeout",
            "20",
            "--syq-path",
            env!("CARGO_BIN_EXE_syq"),
        ]);
        assert!(!output.status.success(), "{output:?}");
        assert!(
            stderr_of(&output).contains("cannot log in to test-server"),
            "{output:?}"
        );
    };
    // A copy to the server, which connects through the same persistence.
    let copy = |name: &str| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
        command
            .args(["cp", &t.s("file"), "--to", "test-server", "--as"])
            .arg(t.s(name))
            .args(["--pscope", scope.to_str().unwrap()])
            .args(["--syq-path", env!("CARGO_BIN_EXE_syq"), "-q"]);
        environment(&mut command);
        assert_output_ok(&command.run().unwrap());
        assert_eq!(read(&t.path(name)), b"copied");
    };
    let dials = || fs::read(t.path("forward.log")).unwrap().len() / b"dialed\n".len();
    let retry_in = || {
        let status = run(&["receive", "status", "--json"]);
        let status: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
        let error = status["connections"][0]["connection"]["error"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        // None while an attempt is under way, before it has failed again.
        error
            .split_once("trying again in ")
            .and_then(|(_, rest)| rest.split_once(" s,"))
            .and_then(|(seconds, _)| seconds.parse::<u64>().ok())
    };
    connect();
    assert_eq!(dials(), 1);
    // Soon after, a copy neither logs in for receiving again nor waits.
    copy("first");
    assert_eq!(dials(), 1);
    // persist connect tries again at once, starting over.
    connect();
    assert_eq!(dials(), 2);
    assert!(retry_in().is_some_and(|seconds| seconds <= 30));
    // Once the interval has passed, a copy wakes the connection, which
    // tries at once and then waits longer than it did before.
    std::thread::sleep(std::time::Duration::from_secs(9));
    copy("second");
    wait_for(
        "the woken retry",
        std::time::Duration::from_secs(20),
        || dials() == 3,
    );
    wait_for(
        "the longer wait",
        std::time::Duration::from_secs(20),
        || retry_in().is_some_and(|seconds| seconds > 40),
    );
}

/// It does try again by itself, as an agent unlocked after sleep needs.
#[cfg(debug_assertions)]
#[test]
fn a_rejected_receiving_login_is_retried_by_itself() {
    let t = Tmp::new();
    fs::create_dir(t.runtime()).unwrap();
    fs::create_dir(t.path("root")).unwrap();
    fs::create_dir(t.path("home")).unwrap();
    let ssh = fake_ssh(&t);
    executable(
        &t.path("refusing-bin/ssh"),
        format!(
            "#!/bin/sh\n\
             for argument in \"$@\"; do\n\
             \x20   if [ \"$argument\" = -R ]; then\n\
             \x20       echo dialed >> \"$FAKE_FORWARD_LOG\"\n\
             \x20       echo 'syq@test-server: Permission denied (publickey).' >&2\n\
             \x20       exit 255\n\
             \x20   fi\n\
             done\n\
             exec {} \"$@\"\n",
            ssh.display()
        )
        .as_bytes(),
    );
    let scope = ephemeral_scope(&t);
    let _off = ScopeOff(&t, scope.clone());
    let run = |args: &[&str]| {
        persistence_command(&t, args)
            .args(["--pscope", scope.to_str().unwrap()])
            .env("HOME", t.path("home"))
            .env("XDG_CACHE_HOME", t.path("cache"))
            .env("FAKE_REMOTE_HOME", t.path("remote-home"))
            .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
            .env("FAKE_RSH_LOG", t.path("rsh.log"))
            .env("FAKE_FORWARD_LOG", t.path("forward.log"))
            .env("SYQ_TEST_LOGIN_RETRY_MS", "1000")
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", t.path("refusing-bin").display()),
            )
            .run()
            .unwrap()
    };
    assert_output_ok(&run(&[
        "receive",
        "on",
        "--notify",
        "off",
        "--root",
        &t.s("root"),
        "--all-connections",
    ]));
    let connect = run(&[
        "connect",
        "test-server",
        "--timeout",
        "20",
        "--syq-path",
        env!("CARGO_BIN_EXE_syq"),
    ]);
    assert!(!connect.status.success(), "{connect:?}");
    // Dialed at once, after 1 s, then after 2 s more.
    wait_for(
        "three dials of the rejected login",
        std::time::Duration::from_secs(20),
        || fs::read(t.path("forward.log")).is_ok_and(|log| log.len() >= b"dialed\n".len() * 3),
    );
    // Between attempts the status says why; during one it is connecting.
    wait_for(
        "the rejected login's status",
        std::time::Duration::from_secs(20),
        || {
            let status = run(&["receive", "status", "--json"]);
            let status: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
            let connection = &status["connections"][0]["connection"];
            connection["phase"] == "failed"
                && connection["error"]
                    .as_str()
                    .is_some_and(|error| error.contains("cannot log in to test-server"))
        },
    );
}

/// Turn receiving on for a fake `test-server` whose receiving connection
/// fails with `ssh_error`, and check that it is dialed once and then fails
/// with a status containing `reason` and `detail`, not dialed again by
/// itself within a few seconds, and dialed again at once by `persist
/// connect`.
fn refused_receiving_is_not_redialed(ssh_error: &str, reason: &str, detail: &str) {
    let t = Tmp::new();
    fs::create_dir(t.runtime()).unwrap();
    fs::create_dir(t.path("root")).unwrap();
    fs::create_dir(t.path("home")).unwrap();
    let ssh = fake_ssh(&t);
    // The receiving connection asks for its return socket with -R; this
    // server fails it the way OpenSSH reports it.
    executable(
        &t.path("refusing-bin/ssh"),
        format!(
            "#!/bin/sh\n\
             for argument in \"$@\"; do\n\
             \x20   if [ \"$argument\" = -R ]; then\n\
             \x20       echo dialed >> \"$FAKE_FORWARD_LOG\"\n\
             \x20       echo '{ssh_error}' >&2\n\
             \x20       exit 255\n\
             \x20   fi\n\
             done\n\
             exec {} \"$@\"\n",
            ssh.display()
        )
        .as_bytes(),
    );
    let scope = ephemeral_scope(&t);
    let _off = ScopeOff(&t, scope.clone());
    let run = |args: &[&str]| {
        persistence_command(&t, args)
            .args(["--pscope", scope.to_str().unwrap()])
            .env("HOME", t.path("home"))
            .env("XDG_CACHE_HOME", t.path("cache"))
            .env("FAKE_REMOTE_HOME", t.path("remote-home"))
            .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
            .env("FAKE_RSH_LOG", t.path("rsh.log"))
            .env("FAKE_FORWARD_LOG", t.path("forward.log"))
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", t.path("refusing-bin").display()),
            )
            .run()
            .unwrap()
    };
    assert_output_ok(&run(&[
        "receive",
        "on",
        "--notify",
        "off",
        "--root",
        &t.s("root"),
        "--all-connections",
    ]));
    for dials in [b"dialed\n".as_slice(), b"dialed\ndialed\n"] {
        let started = std::time::Instant::now();
        let connect = run(&[
            "connect",
            "test-server",
            "--timeout",
            "20",
            "--syq-path",
            env!("CARGO_BIN_EXE_syq"),
        ]);
        assert!(!connect.status.success(), "{connect:?}");
        let stderr = stderr_of(&connect);
        assert!(stderr.contains(reason), "{stderr}");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(15),
            "connect waited for its whole timeout: {stderr}"
        );
        // A redial on the reconnecting schedule would come one second
        // after the refusal, then two more.
        std::thread::sleep(std::time::Duration::from_secs(4));
        assert_eq!(read(&t.path("forward.log")), dials, "{ssh_error}");
        let status = run(&["receive", "status", "--json"]);
        assert_output_ok(&status);
        let status: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
        let connection = &status["connections"][0]["connection"];
        assert_eq!(connection["phase"], "failed", "{status}");
        let error = connection["error"].as_str().unwrap();
        assert!(error.contains(reason) && error.contains(detail), "{status}");
    }
}

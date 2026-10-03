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
fn native_copy_named_selector_preserves_a_root_symlink() {
    use std::os::unix::fs::symlink;

    let t = Tmp::new();
    write(&t.path("real/file"), b"data");
    symlink("real", t.path("link")).unwrap();

    run_native_ok(&["cp", "--src", &t.s("link"), "--into", &t.s("preserved")]);
    assert_eq!(
        fs::read_link(t.path("preserved/link")).unwrap(),
        Path::new("real")
    );

    let link_with_slashes = format!("{}///", t.s("link"));
    run_native_ok(&[
        "cp",
        "--src",
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
    for option in [
        "--receiver-max-entries=5",
        "--receiver-max-bytes=1M",
        "--receiver-receipt=sizes",
    ] {
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
fn persist_connect_scopes_skip_receiving_and_setup_errors_are_reported_once() {
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
    // Invalid preferences must not affect a forward-only script scope.
    let receive = t.path("config/syq/receive.json");
    write(&receive, b"not json");
    fs::set_permissions(&receive, fs::Permissions::from_mode(0o600)).unwrap();
    let scope = ephemeral_scope(&t);
    let output = connect(Some(&scope), "rsh.log");
    assert_output_ok(&output);
    assert!(String::from_utf8_lossy(&output.stdout)
        .contains("ready; ephemeral scopes do not support receiving"));
    assert!(!t.path("config/syq/persistence.json").exists());
    assert_eq!(read(&receive), b"not json");
    assert!(fs::read_dir(&scope).unwrap().all(|entry| !entry
        .unwrap()
        .file_name()
        .as_encoded_bytes()
        .windows(5)
        .any(|s| s == b".recv")));
    let log = fs::read_to_string(t.path("rsh.log")).unwrap();
    assert!(log.contains("ControlPersist=300"), "{log}");
    assert!(!log.contains("ControlPersist=yes"), "{log}");
    let output = persistence_command(&t, &["status", "--pscope", scope.to_str().unwrap()])
        .env_remove("HOME")
        .run()
        .unwrap();
    assert_output_ok(&output);
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains("ephemeral scope; receiving not supported"),
        "{text}"
    );
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
    assert!(stderr_of(&rejected).contains("without --pscope"));
    assert!(
        !t.path("rejected-rsh.log").exists(),
        "invalid scope reached SSH"
    );
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
    fs::create_dir(t.path("downloads")).unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_syq"))
            .args(args)
            .env("HOME", t.path(""))
            .env("XDG_CONFIG_HOME", t.path("config"))
            .env("XDG_RUNTIME_DIR", t.path("runtime"))
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
    assert!(
        !t.path("runtime").exists(),
        "status created a runtime scope"
    );
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
    assert!(!t.path("config/syq/persistence.json").exists());
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
    fs::create_dir_all(t.path("root/inbox")).unwrap();
    fs::create_dir_all(t.path("root/explicit")).unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_syq"))
            .args(["persist", "receive"])
            .args(args)
            .env("HOME", t.path(""))
            .env("XDG_CONFIG_HOME", t.path("config"))
            .env("XDG_RUNTIME_DIR", t.path("runtime"))
            .env("SYQ_NO_UPDATE_CHECK", "1")
            .current_dir(t.path(""))
            .capture_output()
            .unwrap()
    };
    let state = || {
        let output = run(&["status", "--json"]);
        assert_output_ok(&output);
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()["settings"].clone()
    };
    assert_output_ok(&run(&[
        "on",
        "--auto-approve-root",
        "root/inbox",
        "--connection",
        "work",
        "--connection",
        "alice@lab:2222",
    ]));
    assert_eq!(state()["cwd"], t.s("root/inbox"));
    assert_eq!(state()["cwd_explicit"], false);
    assert_eq!(
        state()["servers"],
        serde_json::json!(["work", "alice@lab:2222"])
    );
    assert!(!run(&["wait", "other", "--timeout", "1"]).status.success());
    assert_output_ok(&run(&["on", "--root", "root"]));
    assert_eq!(state()["cwd"], t.s("root"));
    assert_output_ok(&run(&["on", "--cwd", "root/explicit"]));
    assert_eq!(state()["root"], t.s("root"));
    assert_output_ok(&run(&["on", "--no-auto-approve-root"]));
    assert_eq!(state()["cwd"], t.s("root/explicit"));
    assert_output_ok(&run(&[
        "on",
        "--auto-cwd",
        "--auto-approve-root",
        "root/inbox",
    ]));
    assert_eq!(state()["cwd"], t.s("root"));
    assert_output_ok(&run(&["on", "--no-root"]));
    assert_eq!(state()["cwd"], t.s("root/inbox"));
    assert_output_ok(&run(&["on", "--no-auto-approve-root", "--all-connections"]));
    assert_eq!(
        state()["cwd"],
        fs::canonicalize(t.path("")).unwrap().to_str().unwrap()
    );
    assert_eq!(state()["servers"], serde_json::json!([]));
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
    write(&t.path("bin/ssh"), b"#!/bin/sh\nif [ \"$1\" = -V ]; then echo OpenSSH_9.2p1 >&2; exit 0; fi\n: > \"$SSH_MARKER\"\nexit 55\n");
    fs::set_permissions(t.path("bin/ssh"), fs::Permissions::from_mode(0o700)).unwrap();
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
        error.contains("could not connect to receiving machine"),
        "{error}"
    );
    assert!(!error.contains("offline"), "{error}");
    assert!(error.contains("syq persist connect SERVER"), "{error}");
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

#[test]
fn receiving_v2_preferences_migrate_without_retaining_implicit_approval() {
    let t = Tmp::new();
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
            .env("XDG_RUNTIME_DIR", t.path("runtime"))
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
    assert!(!t.path("config/syq/persistence.json").exists());
    assert_output_ok(&run(&["persist", "receive", "off"]));
}

#[test]
fn return_via_requires_approval_and_rejects_unsupported_routes() {
    let t = Tmp::new();
    write(&t.path("source"), b"payload");
    write(
        &t.path("bin/ssh"),
        b"#!/bin/sh\ntouch \"$HOME/ssh-used\"\nexit 99\n",
    );
    fs::set_permissions(t.path("bin/ssh"), fs::Permissions::from_mode(0o755)).unwrap();
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
        assert!(!stderr_of(&failed).contains("requesting permission"));
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
    write(
        &t.path("bin/ssh"),
        b"#!/bin/sh\nif [ \"$1\" = -V ]; then echo OpenSSH_8.9p1 >&2; exit 0; fi\necho connect >> \"$HOME/ssh-used\"\nprintf '%s\\n' \"${SYQ_TEST_SSH_FAILURE:-Permission denied (publickey).}\" >&2\nexit 255\n",
    );
    fs::set_permissions(t.path("bin/ssh"), fs::Permissions::from_mode(0o700)).unwrap();
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
    let responder = std::thread::spawn(move || {
        let mut messages = Vec::new();
        for _ in 0..10 {
            let deadline = Instant::now() + Duration::from_secs(10);
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
            let response = if envelope["message"] == "Ping" {
                assert!(ssh_marker.exists(), "discovery preceded the SSH attempt");
                serde_json::json!("Ready")
            } else if let Some(account) = envelope["message"].get("Ssh") {
                assert_eq!(account["mode"], "Account", "{envelope}");
                assert_eq!(account["target"]["host"], "backup", "{envelope}");
                assert!(
                    !ssh_marker.exists(),
                    "explicit account selection tried native SSH"
                );
                serde_json::json!({"Error": "account denied by fixture"})
            } else {
                assert!(envelope["message"].get("Forward").is_some(), "{envelope}");
                serde_json::json!({"Error": "copy denied by fixture"})
            };
            messages.push(envelope);
            let bytes = serde_json::to_vec(&response).unwrap();
            socket
                .write_all(&(bytes.len() as u32).to_be_bytes())
                .unwrap();
            socket.write_all(&bytes).unwrap();
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
    assert!(
        stderr_of(&refused).lines().any(|line| line
            == "syq: backup: SSH connection failed (exit status: 255): credentials were rejected; trying authorization through @laptop"),
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

    // Unsupported options and explicit SSH never ask a receiving machine.
    for extra in [
        vec!["--auth-from", "ssh"],
        vec!["--copy-metadata", "ownership"],
        vec!["--inplace"],
        vec!["--prune", "--into", "out"],
        vec!["--into", "~//archive"],
    ] {
        let mut args = vec!["cp", "source", "--to", "backup"];
        args.extend(extra);
        let output = run(&args);
        assert!(!output.status.success());
        assert!(
            t.path("ssh-used").exists(),
            "{args:?}: {}",
            stderr_of(&output)
        );
        fs::remove_file(t.path("ssh-used")).unwrap();
    }
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
    assert_eq!(
        messages[1]["message"]["Forward"]["request"]["copy"]["policy"]["existing"],
        "Replace"
    );
    for pair in messages[2..8].chunks_exact(2) {
        assert_eq!(pair[0]["secret"], "laptop");
        assert_eq!(pair[0]["message"], "Ping");
        assert!(pair[1]["message"].get("Forward").is_some());
    }
    assert_eq!(messages[8]["secret"], "z-other");
    assert_eq!(messages[9]["secret"], "ssh");
    for request in &messages[8..10] {
        assert_eq!(request["message"]["Ssh"]["mode"], "Account");
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

#[test]
fn receiving_profiles_preserve_independent_settings_and_select_names() {
    let t = Tmp::new();
    fs::create_dir(t.path("project")).unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_syq"))
            .args(args)
            .env("HOME", t.path(""))
            .env("XDG_CONFIG_HOME", t.path("config"))
            .env("XDG_RUNTIME_DIR", t.path("runtime"))
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
    fs::create_dir(t.path("project")).unwrap();
    fs::write(t.path("file"), b"not a directory").unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_syq"))
            .args(["persist", "receive"])
            .args(args)
            .env("HOME", t.path(""))
            .env("XDG_CONFIG_HOME", t.path("config"))
            .env("XDG_RUNTIME_DIR", t.path("runtime"))
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
            .env("XDG_RUNTIME_DIR", t.path("runtime"))
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
    assert_output_ok(
        &command(&["persist", "receive", "on", "--connection", "other.invalid"])
            .run()
            .unwrap(),
    );
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

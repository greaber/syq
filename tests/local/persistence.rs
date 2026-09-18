use super::*;

/// An ssh-shaped remote shell that accepts the control session, rejects every
/// multiplexed worker like an sshd with `MaxSessions 1`, and accepts workers
/// that disable `ControlPath`.
fn fake_ssh_rejecting_multiplexed_workers(t: &Tmp) -> PathBuf {
    let path = t.path("bin/ssh");
    executable(
        &path,
        br#"#!/bin/sh
if [ "$1" = -V ]; then
    printf 'OpenSSH_9.9p1, fake\n' >&2
    exit 0
fi
control_master=unset
control_path=unset
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o)
            option=$2
            shift 2
            case "$option" in
                ControlMaster=*) control_master=${option#ControlMaster=} ;;
                ControlPath=*) control_path=${option#ControlPath=} ;;
            esac
            ;;
        -l)
            shift 2
            ;;
        -S)
            control_path=$2
            shift 2
            ;;
        --)
            shift
            break
            ;;
        *)
            exit 98
            ;;
    esac
done
shift
printf '%s|%s\n' "$control_master" "$control_path" >> "$FAKE_RSH_LOG"
if [ "$control_master" = no ] && [ "$control_path" != none ]; then
    exit 255
fi
HOME="$FAKE_REMOTE_HOME"
PATH=/usr/bin:/bin
export HOME PATH
if [ -n "${FAKE_SSH_CONNECTION:-}" ]; then
    SSH_CONNECTION="$FAKE_SSH_CONNECTION"
    export SSH_CONNECTION
else
    unset SSH_CONNECTION
fi
exec /bin/sh -c "$1"
"#,
    );
    path
}

#[test]
fn multiplexed_worker_refusal_falls_back_to_independent_ssh() {
    let t = Tmp::new();
    fake_ssh_rejecting_multiplexed_workers(&t);
    write(&t.path("src"), b"independent SSH fallback");
    let remote = format!("fake:{}", t.s("dst"));

    let out = compat_command()
        .arg("--rsync-path")
        .arg(env!("CARGO_BIN_EXE_syq"))
        .args(["--syq-no-tcp", "-a", "--performance-tuning", "workers=1"])
        .arg(t.s("src"))
        .arg(&remote)
        .arg("--no-progress")
        .env("FAKE_REMOTE_HOME", t.path("remote-home"))
        .env("FAKE_RSH_LOG", t.path("rsh.log"))
        .env("PATH", format!("{}:/usr/bin:/bin", t.s("bin")))
        .env("XDG_CONFIG_HOME", t.path("config"))
        .run()
        .expect("run copy when the SSH server rejects multiplexed workers");

    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), b"independent SSH fallback");
    let invocations = fs::read_to_string(t.path("rsh.log")).unwrap();
    assert!(
        invocations
            .lines()
            .any(|line| line.starts_with("yes|") && !line.ends_with("|none")),
        "control connection did not enable its private socket:\n{invocations}"
    );
    assert!(
        invocations
            .lines()
            .any(|line| line.starts_with("no|") && !line.ends_with("|none")),
        "no multiplexed worker was attempted:\n{invocations}"
    );
    assert!(
        invocations.lines().any(|line| line == "no|none"),
        "no independent worker fallback was attempted:\n{invocations}"
    );
}

#[test]
fn local_copy_does_not_read_the_global_persistence_configuration() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"data");
    // An eligible implicit SSH endpoint would report this malformed policy,
    // but a local copy has no persistence decision to make.
    write(&t.path("config/syq/persistence.json"), b"not valid JSON");
    let out = compat_command()
        .args(["-a", "--no-progress", &t.s("src/"), &t.s("dst/")])
        .env("XDG_CONFIG_HOME", t.path("config"))
        .run()
        .unwrap();
    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst/f")), b"data");
}

#[test]
fn native_detach_waits_for_coordinator_readiness() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    write(&t.path("src"), b"detached");
    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["cp", "--rsh"])
        .arg(&rsh)
        .args(["--syq-path", env!("CARGO_BIN_EXE_syq")])
        .args([
            "--no-tcp",
            "--performance-tuning",
            "workers=1",
            "--detach",
            "--from",
            "hostA",
            "--src",
            &t.s("src"),
            "--to",
            "hostB",
            "--as",
            &t.s("dst"),
            "-q",
        ])
        .env("FAKE_REMOTE_HOME", t.path("remote-home"))
        .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
        .env("FAKE_RSH_LOG", t.path("rsh.log"))
        .run()
        .expect("launch detached native transfer");
    assert_output_ok(&out);
    let log_target = String::from_utf8(out.stdout).unwrap();
    assert!(log_target.starts_with("hostA:"), "{log_target}");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !t.path("dst").exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert_eq!(read(&t.path("dst")), b"detached");
    let ready_files = fs::read_dir(t.path("remote-home/.syq"))
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().ends_with(".ready"))
        .count();
    assert_eq!(ready_files, 0, "launcher left its readiness marker behind");
}

#[test]
fn native_detach_does_not_report_an_immediate_setup_failure_as_started() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    let started = std::time::Instant::now();
    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["cp", "--rsh"])
        .arg(&rsh)
        .args(["--syq-path", env!("CARGO_BIN_EXE_syq")])
        .args([
            "--no-tcp",
            "--detach",
            "--from",
            "hostA",
            "--src",
            &t.s("missing"),
            "--to",
            "hostB",
            "--as",
            &t.s("dst"),
            "-q",
        ])
        .env("FAKE_REMOTE_HOME", t.path("remote-home"))
        .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
        .env("FAKE_RSH_LOG", t.path("rsh.log"))
        .run()
        .expect("reject failed detached launch");
    assert!(!out.status.success());
    assert!(
        out.stdout.is_empty(),
        "failed launch returned a follow target"
    );
    assert!(stderr_of(&out).contains("source"), "{}", stderr_of(&out));
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "immediate setup failure waited for the full readiness timeout"
    );
    assert!(!t.path("dst").exists());
}

#[test]
fn native_detach_broken_stdout_reports_running_job_without_panicking() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    write(&t.path("src"), b"detached");
    let (reader, writer) = std::os::unix::net::UnixStream::pair().unwrap();
    drop(reader);
    let output = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["cp", "--rsh"])
        .arg(&rsh)
        .args([
            "--syq-path",
            env!("CARGO_BIN_EXE_syq"),
            "--no-tcp",
            "--performance-tuning",
            "workers=1",
            "--detach",
            "--from",
            "hostA",
            "--src",
            &t.s("src"),
            "--to",
            "hostB",
            "--as",
            &t.s("dst"),
            "-q",
        ])
        .env("FAKE_REMOTE_HOME", t.path("remote-home"))
        .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
        .env("FAKE_RSH_LOG", t.path("rsh.log"))
        .stdin(Stdio::null())
        .stdout(Stdio::from(std::os::fd::OwnedFd::from(writer)))
        .stderr(Stdio::piped())
        .start()
        .unwrap()
        .wait_with_output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{}", stderr_of(&output));
    let stderr = stderr_of(&output);
    assert!(stderr.contains("job started on hostA, log "), "{stderr}");
    assert!(
        stderr.contains("writing its location to stdout failed"),
        "{stderr}"
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while fs::read(t.path("dst")).ok().as_deref() != Some(b"detached".as_slice())
        && std::time::Instant::now() < deadline
    {
        eprintln!("waiting for detached job after handoff output failure");
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    assert_eq!(read(&t.path("dst")), b"detached");
}

#[test]
fn persistence_policy_and_ephemeral_scopes_have_separate_lifecycles() {
    let t = Tmp::new();
    fs::create_dir(t.runtime()).unwrap();

    let status = persistence_command(&t, &["status"]).run().unwrap();
    assert_output_ok(&status);
    assert!(String::from_utf8_lossy(&status.stdout).contains("is off"));

    let enabled = persistence_command(&t, &["on"]).run().unwrap();
    assert_output_ok(&enabled);
    let global_scope = String::from_utf8(enabled.stdout)
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("scope: "))
        .map(PathBuf::from)
        .expect("global scope path");
    assert!(global_scope.is_dir());

    let scope = ephemeral_scope(&t);
    assert!(scope.is_dir());
    assert_ne!(scope, global_scope);
    assert_eq!(
        fs::metadata(&scope).unwrap().permissions().mode() & 0o777,
        0o700
    );
    write(&t.path("src/a.txt"), b"a");
    let copy = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["cp", "--pscope"])
        .arg(&scope)
        .args(["--srcs-in", &t.s("src"), "--into", &t.s("out"), "-q"])
        .env("XDG_CONFIG_HOME", t.path("config"))
        .env("XDG_RUNTIME_DIR", t.runtime())
        .run()
        .unwrap();
    assert_output_ok(&copy);
    assert_eq!(read(&t.path("out/a.txt")), b"a");

    let scoped_status = persistence_command(&t, &["status", "--pscope", scope.to_str().unwrap()])
        .run()
        .unwrap();
    assert_output_ok(&scoped_status);
    assert!(String::from_utf8_lossy(&scoped_status.stdout).contains("connections: 0"));

    let closed = persistence_command(&t, &["off", "--pscope", scope.to_str().unwrap()])
        .run()
        .unwrap();
    assert_output_ok(&closed);
    assert!(!scope.exists());
    assert!(global_scope.exists(), "ephemeral off changed global scope");

    let disabled = persistence_command(&t, &["off"]).run().unwrap();
    assert_output_ok(&disabled);
    assert!(!global_scope.exists());
    let status = persistence_command(&t, &["status"]).run().unwrap();
    assert_output_ok(&status);
    assert!(String::from_utf8_lossy(&status.stdout).contains("is off"));
}

/// The session pool's own ssh invocations, as the fake logs them: a master
/// check, or a spare opened with every authentication method disabled.
fn pool_lines(log: &str) -> (Vec<&str>, Vec<&str>) {
    let checks = log
        .lines()
        .filter(|line| line.contains("-O check"))
        .collect();
    let spares = log
        .lines()
        .filter(|line| line.contains("PubkeyAuthentication=no") && line.contains("--server"))
        .collect();
    (checks, spares)
}

/// With persistence on, the first command starts a session pool for its
/// endpoint. The pool opens a spare without authenticating, later commands
/// take it instead of opening an ssh session of their own, and `persist off`
/// stops the pool with the scope.
#[test]
fn session_pool_serves_later_commands_without_new_ssh_sessions() {
    let t = Tmp::new();
    fs::create_dir(t.runtime()).unwrap();
    fs::create_dir_all(t.path("remote-home/data/nested")).unwrap();
    write(&t.path("remote-home/data/name"), b"remote");
    write(&t.path("local.txt"), b"hello");
    fs::create_dir_all(t.path("remote-home/dest")).unwrap();
    let ssh = fake_ssh(&t);
    let scope = ephemeral_scope(&t);
    let scope_text = scope.to_str().unwrap().to_string();
    let executable = env!("CARGO_BIN_EXE_syq");
    let path = format!("{}/n", t.s("remote-home/data"));
    let complete = |t: &Tmp| {
        completion_command(
            t,
            &[
                "__complete",
                "bash",
                "8",
                "--",
                "syq",
                "cp",
                "--pscope",
                &scope_text,
                "--syq-path",
                executable,
                "--from",
                "fake.example",
                &path,
            ],
        )
        .env("FAKE_REMOTE_HOME", t.path("remote-home"))
        .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
        .env("FAKE_RSH_LOG", t.path("rsh.log"))
        .env(
            "PATH",
            format!("{}:/usr/bin:/bin", ssh.parent().unwrap().display()),
        )
        .env("SYQ_COMPLETION_DEBUG", "1")
        .run()
        .unwrap()
    };
    let log = |t: &Tmp| fs::read_to_string(t.path("rsh.log")).unwrap_or_default();

    let first = complete(&t);
    assert_output_ok(&first);
    assert_eq!(completion_values(&first.stdout).len(), 2);
    assert!(log(&t).contains("ControlMaster=auto"), "{}", log(&t));
    wait_for(
        "the pool's first spare",
        std::time::Duration::from_secs(15),
        || !pool_lines(&log(&t)).1.is_empty(),
    );
    let warmed = log(&t);
    let (checks, spares) = pool_lines(&warmed);
    assert!(!checks.is_empty(), "{warmed}");
    for option in [
        "ControlMaster=no",
        "ProxyJump=none",
        "ProxyCommand=false",
        "ForwardAgent=no",
        "ForwardX11=no",
        "ClearAllForwardings=yes",
        "PermitLocalCommand=no",
        "GSSAPIDelegateCredentials=no",
        "RequestTTY=no",
        "BatchMode=yes",
        "PubkeyAuthentication=no",
        "PasswordAuthentication=no",
        "KbdInteractiveAuthentication=no",
        "GSSAPIAuthentication=no",
        "HostbasedAuthentication=no",
    ] {
        assert!(
            spares[0].contains(option),
            "{option} missing: {}",
            spares[0]
        );
    }
    assert!(!spares[0].contains("ControlPersist"), "{}", spares[0]);
    let status = persistence_command(&t, &["status", "--json", "--pscope", &scope_text])
        .run()
        .unwrap();
    assert_output_ok(&status);
    let state: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert!(
        state["connections"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["session_pool"] == true),
        "{state}"
    );

    // The next completion takes the spare: no session of its own.
    write(&t.path("rsh.log"), b"");
    let second = complete(&t);
    assert_output_ok(&second);
    assert_eq!(
        completion_values(&second.stdout),
        completion_values(&first.stdout)
    );
    assert!(!log(&t).contains("ControlMaster=auto"), "{}", log(&t));
    wait_for(
        "the pool's replacement spare",
        std::time::Duration::from_secs(15),
        || !pool_lines(&log(&t)).1.is_empty(),
    );

    // So does a copy, which says so under SYQ_DEBUG.
    write(&t.path("rsh.log"), b"");
    let copy = Command::new(executable)
        .args([
            "cp",
            "--pscope",
            &scope_text,
            "--syq-path",
            executable,
            "-q",
        ])
        .arg(t.path("local.txt"))
        .args(["--to", "fake.example", "--into", &t.s("remote-home/dest")])
        .env("FAKE_REMOTE_HOME", t.path("remote-home"))
        .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
        .env("FAKE_RSH_LOG", t.path("rsh.log"))
        .env(
            "PATH",
            format!("{}:/usr/bin:/bin", ssh.parent().unwrap().display()),
        )
        .env("XDG_CONFIG_HOME", t.path("config"))
        .env("XDG_RUNTIME_DIR", t.runtime())
        .env("SYQ_DEBUG", "1")
        .run()
        .unwrap();
    assert_output_ok(&copy);
    assert!(
        stderr_of(&copy).contains("control connection from the session pool"),
        "{}",
        stderr_of(&copy)
    );
    assert_eq!(read(&t.path("remote-home/dest/local.txt")), b"hello");
    assert!(!log(&t).contains("ControlMaster=auto"), "{}", log(&t));

    // Closing the scope stops the pool and removes its files with the rest.
    let closed = persistence_command(&t, &["off", "--pscope", &scope_text])
        .run()
        .unwrap();
    assert_output_ok(&closed);
    assert!(!scope.exists());
    wait_for(
        "the pool process to exit",
        std::time::Duration::from_secs(10),
        || {
            !Command::new("pgrep")
                .args(["-f", &scope_text])
                .run()
                .map(|output| output.status.success())
                .unwrap_or(false)
        },
    );
}

/// An SSH child can start successfully and only then refuse its exec
/// channel. Such failures need the same delay as a failed master check.
#[test]
fn session_pool_backs_off_when_a_live_master_refuses_sessions() {
    let t = Tmp::new();
    fs::create_dir(t.runtime()).unwrap();
    let scope = ephemeral_scope(&t);
    let ssh = t.path("bin/ssh");
    executable(
        &ssh,
        br#"#!/bin/sh
case " $* " in
    *" -O check "*) exit 0 ;;
esac
# Wait for the pool's hello so this is an asynchronous session failure.
dd bs=1 count=1 >/dev/null 2>&1
sleep 0.05
printf 'refused\n' >> "$FAKE_RSH_LOG"
exit 255
"#,
    );
    let output = Command::new(env!("CARGO_BIN_EXE_syq"))
        .arg("--session-pool")
        .arg(scope.join("cm-00112233aabbccdd"))
        .args(["", "fake.example", "", "unused --server"])
        .env(
            "PATH",
            format!("{}:/usr/bin:/bin", ssh.parent().unwrap().display()),
        )
        .env("FAKE_RSH_LOG", t.path("rsh.log"))
        .env("SYQ_TEST_POOL_IDLE_SECS", "8")
        .run()
        .unwrap();
    assert_output_ok(&output);
    let log = fs::read_to_string(t.path("rsh.log")).unwrap();
    assert_eq!(
        log.lines().count(),
        2,
        "a refused spare should retry after five seconds: {log}"
    );
    assert!(!scope.join("cm-00112233aabbccdd.pool").exists());
    assert!(!scope.join("cm-00112233aabbccdd.pool.lock").exists());
}

/// A pool never opens a session on its own authority: when the master is
/// gone the check fails, no spare is opened, and commands connect directly.
#[test]
fn session_pool_stays_empty_without_a_live_master() {
    let t = Tmp::new();
    fs::create_dir(t.runtime()).unwrap();
    fs::create_dir_all(t.path("remote-home/data")).unwrap();
    write(&t.path("remote-home/data/name"), b"remote");
    let ssh = fake_ssh(&t);
    let scope = ephemeral_scope(&t);
    let scope_text = scope.to_str().unwrap().to_string();
    let executable = env!("CARGO_BIN_EXE_syq");
    let path = format!("{}/n", t.s("remote-home/data"));
    let complete = |t: &Tmp| {
        completion_command(
            t,
            &[
                "__complete",
                "bash",
                "8",
                "--",
                "syq",
                "cp",
                "--pscope",
                &scope_text,
                "--syq-path",
                executable,
                "--from",
                "fake.example",
                &path,
            ],
        )
        .env("FAKE_REMOTE_HOME", t.path("remote-home"))
        .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
        .env("FAKE_RSH_LOG", t.path("rsh.log"))
        .env("FAKE_SSH_CHECK_STATUS", "255")
        .env("SYQ_TEST_POOL_IDLE_SECS", "1")
        .env(
            "PATH",
            format!("{}:/usr/bin:/bin", ssh.parent().unwrap().display()),
        )
        .env("SYQ_COMPLETION_DEBUG", "1")
        .run()
        .unwrap()
    };
    let log = |t: &Tmp| fs::read_to_string(t.path("rsh.log")).unwrap_or_default();

    let first = complete(&t);
    assert_output_ok(&first);
    wait_for(
        "the pool's master check",
        std::time::Duration::from_secs(15),
        || !pool_lines(&log(&t)).0.is_empty(),
    );
    let second = complete(&t);
    assert_output_ok(&second);
    assert_eq!(completion_values(&second.stdout).len(), 1);
    let checked = log(&t);
    let (_, spares) = pool_lines(&checked);
    assert!(spares.is_empty(), "{checked}");
    assert_eq!(
        log(&t)
            .lines()
            .filter(|line| line.contains("ControlMaster=auto"))
            .count(),
        2,
        "{}",
        log(&t)
    );

    // Idle, the pool leaves on its own; the scope's own files remain.
    wait_for(
        "the idle pool to exit",
        std::time::Duration::from_secs(15),
        || {
            !scope.read_dir().unwrap().any(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".pool.lock")
            })
        },
    );
    let status = persistence_command(&t, &["status", "--json", "--pscope", &scope_text])
        .run()
        .unwrap();
    assert_output_ok(&status);
    let state: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert!(
        state["connections"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["session_pool"] == false),
        "{state}"
    );
    let closed = persistence_command(&t, &["off", "--pscope", &scope_text])
        .run()
        .unwrap();
    assert_output_ok(&closed);
    assert!(!scope.exists());
}

#[test]
fn remote_coordinator_does_not_resolve_local_persistence() {
    let t = Tmp::new();
    fs::create_dir(t.runtime()).unwrap();
    write(&t.path("config/syq/persistence.json"), b"not valid JSON");
    let ssh = t.path("bin/ssh");
    executable(
        &ssh,
        br#"#!/bin/sh
: > "$FAKE_RSH_MARKER"
exit 23
"#,
    );
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_syq"))
            .args([
                "cp",
                "--peer-auth",
                "own-credentials",
                "--from",
                "hostA",
                "--srcs-in",
                "src",
                "--to",
                "hostB",
                "--into",
                "dst",
                "--no-progress",
            ])
            .env("XDG_CONFIG_HOME", t.path("config"))
            .env("XDG_RUNTIME_DIR", t.runtime())
            .env("FAKE_RSH_MARKER", t.path("ssh-called"))
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", ssh.parent().unwrap().to_string_lossy()),
            )
            .run()
            .unwrap()
    };

    let output = run();
    assert_eq!(output.status.code(), Some(23), "{}", stderr_of(&output));
    assert!(t.path("ssh-called").exists());
    assert!(!stderr_of(&output).contains("persistence configuration"));

    let enabled = persistence_command(&t, &["on"]).run().unwrap();
    assert_output_ok(&enabled);
    let global_scope = String::from_utf8(enabled.stdout)
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("scope: "))
        .map(PathBuf::from)
        .unwrap();
    let output = run();
    assert_eq!(output.status.code(), Some(23), "{}", stderr_of(&output));
    assert!(
        fs::read_dir(&global_scope)
            .unwrap()
            .flatten()
            .all(|entry| !entry.file_name().to_string_lossy().ends_with(".json")),
        "remote-coordinator handoff recorded inactive local endpoints"
    );
    assert_output_ok(&persistence_command(&t, &["off"]).run().unwrap());
}

#[test]
fn persistence_rejects_long_socket_paths_before_enabling() {
    let t = Tmp::new();
    let runtime = t.path(&"r".repeat(100));
    fs::create_dir(&runtime).unwrap();
    for args in [&["on"][..], &["on", "--ephemeral"][..]] {
        let output = persistence_command(&t, args)
            .env("XDG_RUNTIME_DIR", &runtime)
            .run()
            .unwrap();
        assert!(!output.status.success());
        let diagnostic = stderr_of(&output);
        assert!(
            diagnostic.contains("SSH control socket path"),
            "{diagnostic}"
        );
        assert!(
            diagnostic.contains("OpenSSH's temporary suffix"),
            "{diagnostic}"
        );
        assert!(!t.path("config/syq/persistence.json").exists());
    }
}

#[cfg(target_os = "macos")]
#[test]
fn macos_default_persistence_avoids_long_tmpdir() {
    let t = Tmp::new();
    let temporary = t.path(&"t".repeat(80));
    fs::create_dir(&temporary).unwrap();
    let output = persistence_command(&t, &["on", "--ephemeral"])
        .env_remove("XDG_RUNTIME_DIR")
        .env("TMPDIR", &temporary)
        .run()
        .unwrap();
    assert_output_ok(&output);
    let scope = String::from_utf8(output.stdout).unwrap();
    let scope = scope.trim();
    assert!(scope.starts_with("/tmp/syq-persist-"), "{scope}");
    let closed = persistence_command(&t, &["off", "--pscope", scope])
        .env_remove("XDG_RUNTIME_DIR")
        .env("TMPDIR", &temporary)
        .run()
        .unwrap();
    assert_output_ok(&closed);
}

#[test]
fn ephemeral_persistence_refuses_openssh_expanding_runtime_paths() {
    let t = Tmp::new();
    let runtime = t.path("runtime-${HOME}");
    let output = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["persist", "on", "--ephemeral"])
        .env("XDG_CONFIG_HOME", t.path("config"))
        .env("XDG_RUNTIME_DIR", &runtime)
        .run()
        .unwrap();
    assert!(!output.status.success());
    assert!(stderr_of(&output).contains("OpenSSH expansion syntax"));
    assert!(!runtime.exists(), "unsafe runtime path was created");
}

#[test]
fn durable_and_ephemeral_policies_reach_implicit_ssh_connections() {
    let t = Tmp::new();
    fs::create_dir(t.runtime()).unwrap();
    let ssh = fake_ssh(&t);
    write(&t.path("src"), b"persistent");

    let enabled = persistence_command(&t, &["on"]).run().unwrap();
    assert_output_ok(&enabled);
    let global_scope = String::from_utf8(enabled.stdout)
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("scope: "))
        .unwrap()
        .to_owned();
    let mut copy = Command::new(env!("CARGO_BIN_EXE_syq"));
    copy.args(["cp", "--syq-path", env!("CARGO_BIN_EXE_syq")])
        .args(["--no-tcp", "--performance-tuning", "workers=1"])
        .arg(t.path("src"))
        .args(["--to", "backup.example:2222", "--as"])
        .arg(t.path("global-dst"))
        .arg("-q")
        .env("XDG_CONFIG_HOME", t.path("config"))
        .env("XDG_RUNTIME_DIR", t.runtime())
        .env("FAKE_REMOTE_HOME", t.path("remote-home"))
        .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
        .env("FAKE_RSH_LOG", t.path("rsh.log"))
        .env(
            "PATH",
            format!("{}:/usr/bin:/bin", ssh.parent().unwrap().to_string_lossy()),
        );
    let output = copy.run().unwrap();
    assert_output_ok(&output);
    let log = fs::read_to_string(t.path("rsh.log")).unwrap();
    assert!(log.contains("ControlMaster=auto"), "{log}");
    assert!(log.contains("ControlPersist=yes"), "{log}");
    assert!(log.contains(&format!("-S {global_scope}/cm-")), "{log}");
    let status = persistence_command(&t, &["status"]).run().unwrap();
    assert_output_ok(&status);
    assert!(String::from_utf8_lossy(&status.stdout).contains("backup.example:2222"));

    // Stand in for the OpenSSH master at the recorded socket and verify that
    // `persist off` asks that exact endpoint to exit before removing the scope.
    let record = fs::read_dir(&global_scope)
        .unwrap()
        .flatten()
        .find(|entry| entry.file_name().to_string_lossy().ends_with(".json"))
        .expect("endpoint record");
    let socket_name = record
        .file_name()
        .to_string_lossy()
        .strip_suffix(".json")
        .unwrap()
        .to_owned();
    let socket_path = Path::new(&global_scope).join(socket_name);
    let _master = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
    let close_ssh = t.path("close-bin/ssh");
    executable(
        &close_ssh,
        br#"#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_CLOSE_LOG"
exit 0
"#,
    );
    let mut off = persistence_command(&t, &["off"]);
    off.env(
        "PATH",
        format!(
            "{}:/usr/bin:/bin",
            close_ssh.parent().unwrap().to_string_lossy()
        ),
    )
    .env("FAKE_CLOSE_LOG", t.path("close.log"));
    assert_output_ok(&off.run().unwrap());
    let close_log = fs::read_to_string(t.path("close.log")).unwrap();
    assert!(close_log.contains("-O exit"), "{close_log}");
    assert!(close_log.contains("-p 2222"), "{close_log}");
    assert!(close_log.ends_with("-- backup.example\n"), "{close_log}");
    assert!(!Path::new(&global_scope).exists());

    let scope = ephemeral_scope(&t);
    fs::write(t.path("rsh.log"), b"").unwrap();
    let mut scoped_copy = Command::new(env!("CARGO_BIN_EXE_syq"));
    scoped_copy
        .args(["cp", "--pscope"])
        .arg(&scope)
        .args(["--syq-path", env!("CARGO_BIN_EXE_syq")])
        .args(["--no-tcp", "--performance-tuning", "workers=1"])
        .arg(t.path("src"))
        .args(["--to", "backup.example:2222", "--as"])
        .arg(t.path("scoped-dst"))
        .arg("-q")
        .env("XDG_CONFIG_HOME", t.path("config"))
        .env("XDG_RUNTIME_DIR", t.runtime())
        .env("FAKE_REMOTE_HOME", t.path("remote-home"))
        .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
        .env("FAKE_RSH_LOG", t.path("rsh.log"))
        .env(
            "PATH",
            format!("{}:/usr/bin:/bin", ssh.parent().unwrap().to_string_lossy()),
        );
    let output = scoped_copy.run().unwrap();
    assert_output_ok(&output);
    let log = fs::read_to_string(t.path("rsh.log")).unwrap();
    assert!(log.contains("ControlPersist=300"), "{log}");
    assert!(!log.contains("--destination-register"), "{log}");
    assert!(
        log.contains(&format!("-S {}/cm-", scope.display())),
        "{log}"
    );
    assert_output_ok(
        &persistence_command(&t, &["off", "--pscope", scope.to_str().unwrap()])
            .run()
            .unwrap(),
    );
}

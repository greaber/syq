//! Failures at the local build handoff must precede approval and SSH fallback.
#[allow(dead_code)]
#[path = "../src/process.rs"]
mod process;
use crate::process::CommandExt as _;
#[path = "support/executable.rs"]
mod executable_support;
#[path = "support/temp.rs"]
mod test_support;

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

struct Fixture {
    temp: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let temp = crate::test_support::tempdir().unwrap();
        fs::create_dir(temp.path().join(".syq-destinations-v3")).unwrap();
        fs::set_permissions(
            temp.path().join(".syq-destinations-v3"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        fs::write(temp.path().join("source"), b"payload").unwrap();
        Self { temp }
    }

    fn registration(&self, program: &str, identity: &str) {
        let value = serde_json::json!({
            "version": 3, "identity": identity,
            "socket": self.temp.path().join("absent.sock"),
            "secret": "private-test-credential", "program": program.as_bytes(),
        });
        let path = self.temp.path().join(".syq-destinations-v3/laptop.json");
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
        command
            .args(args)
            .current_dir(self.temp.path())
            .env("HOME", self.temp.path())
            .env("XDG_CONFIG_HOME", self.temp.path().join("config"))
            .env("XDG_RUNTIME_DIR", self.temp.path().join("runtime"))
            .env("SYQ_NO_UPDATE_CHECK", "1")
            .env_remove("SSH_AUTH_SOCK")
            .env_remove("SYQ_AUTH_FROM")
            .env_remove("TMUX");
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command(args).capture_output().unwrap()
    }

    /// Automatic source authorization follows one native authentication refusal
    /// and receiver discovery. Explicit @NAME now selects account authorization.
    fn source_fallback(&self, args: &[&str]) -> Output {
        let bin = self.temp.path().join("bin");
        fs::create_dir(&bin).unwrap();
        fs::create_dir(self.temp.path().join("runtime")).unwrap();
        let ssh = bin.join("ssh");
        // `ssh -G` inspects the configuration without connecting.
        executable_support::write_executable(&ssh, b"#!/bin/sh\nif [ \"$1\" = -V ]; then echo OpenSSH_8.9p1 >&2; exit 0; fi\nfor argument; do [ \"$argument\" = -G ] && exit 0; done\nprintf 'connect\\n' >> \"$HOME/ssh-used\"\nprintf 'Permission denied (publickey).\\n' >&2\nexit 255\n", 0o700);
        let listener = UnixListener::bind(self.temp.path().join("absent.sock")).unwrap();
        listener.set_nonblocking(true).unwrap();
        let marker = self.temp.path().join("ssh-used");
        let responder = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut progress = Instant::now() + Duration::from_secs(2);
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            Instant::now() < deadline,
                            "source fallback never sent its discovery Ping"
                        );
                        if Instant::now() >= progress {
                            eprintln!("Waiting for source fallback discovery Ping");
                            progress += Duration::from_secs(2);
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("source discovery failed: {error}"),
                }
            };
            // BSD sockets may inherit the listener's nonblocking mode.
            socket.set_nonblocking(false).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut length = [0; 4];
            socket.read_exact(&mut length).unwrap();
            let length = u32::from_be_bytes(length) as usize;
            assert!(length <= 4096, "oversized discovery envelope");
            let mut bytes = vec![0; length];
            socket.read_exact(&mut bytes).unwrap();
            let envelope: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(envelope["message"], "Ping");
            assert_eq!(
                fs::read(&marker).unwrap(),
                b"connect\n",
                "discovery must follow exactly one native attempt"
            );
            let response = br#""Ready""#;
            socket
                .write_all(&(response.len() as u32).to_be_bytes())
                .unwrap();
            socket.write_all(response).unwrap();
            // No copy/account authorization service is available: the handoff
            // must finish its helper capability check before requesting either.
        });
        let output = self
            .command(args)
            .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
            .capture_output()
            .unwrap();
        responder.join().unwrap();
        assert_eq!(
            fs::read(self.temp.path().join("ssh-used")).unwrap(),
            b"connect\n"
        );
        output
    }

    fn script(&self, body: &str) -> String {
        let path = self.temp.path().join("helper");
        executable_support::write_executable(&path, format!("#!/usr/bin/python3\n{body}"), 0o700);
        path.to_str().unwrap().into()
    }
}

fn assert_failure(output: &Output, text: &str) {
    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(text), "{stderr}");
    assert!(!stderr.contains("private-test-credential"), "{stderr}");
    assert!(!stderr.contains("waiting up to"), "{stderr}");
}

#[test]
fn missing_handoff_helper_settles_copy_results_without_requesting_permission() {
    let fixture = Fixture::new();
    fixture.registration("/no/such/syq-handoff-helper", "another-build");
    let output = fixture.run(&["cp", "source", "--to", "@laptop", "--results", "results"]);
    assert_failure(&output, "start matching return helper");
    let records: Vec<serde_json::Value> = fs::read_to_string(fixture.temp.path().join("results"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(records.last().unwrap()["type"], "result");
    assert_eq!(records.last().unwrap()["status"], "failed");
    assert_failure(
        &fixture.run(&["exec", "--on", "@laptop", "--", "true"]),
        "start matching return helper",
    );
}

#[test]
fn replaced_helper_fails_the_build_guard_instead_of_reexecuting_forever() {
    let fixture = Fixture::new();
    // The registered identity differs but its executable was replaced by this
    // build. The second process must reject the guard before touching a socket.
    fixture.registration(env!("CARGO_BIN_EXE_syq"), "another-build");
    assert_failure(
        &fixture.run(&["cp", "source", "--to", "@laptop", "--results", "results"]),
        "registered return helper has a different build",
    );
    let results = fs::read_to_string(fixture.temp.path().join("results")).unwrap();
    let terminal: serde_json::Value =
        serde_json::from_str(results.lines().last().unwrap()).unwrap();
    assert_eq!(terminal["status"], "failed");
    assert_failure(
        &fixture.run(&["exec", "--on", "@laptop", "--", "true"]),
        "registered return helper has a different build",
    );
}

#[test]
fn changed_registration_is_rejected_before_dispatch() {
    let fixture = Fixture::new();
    let identity = String::from_utf8(fixture.run(&["--build-identity"]).stdout).unwrap();
    let helper = fixture.script(&format!(
        r#"
import json, os, sys
guard = json.loads(sys.argv[2])
guard['identity'] = {identity:?}.strip()
path = '.syq-destinations-v3/laptop.json'
with open(path) as f: registration = json.load(f)
registration['secret'] = 'replaced-credential'
with open(path, 'w') as f: json.dump(registration, f)
os.execv({binary:?}, [{binary:?}, sys.argv[1], json.dumps(guard), *sys.argv[3:]])
"#,
        binary = env!("CARGO_BIN_EXE_syq")
    ));
    fixture.registration(&helper, "another-build");
    assert_failure(
        &fixture.run(&["exec", "--on", "@laptop", "--", "true"]),
        "return registration changed during handoff",
    );
}

#[test]
fn pre_handoff_registry_is_ignored_without_rewriting_it() {
    let fixture = Fixture::new();
    let directory = fixture.temp.path().join(".syq-destinations-v2");
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    // Frozen old registration shape. The user authorized restarting these
    // transient connections; this namespace is neither migrated nor executed.
    let old = br#"{"version":2,"identity":"v0.4.1","socket":"/tmp/old.sock","secret":"old"}"#;
    fs::write(directory.join("laptop.json"), old).unwrap();
    let output = fixture.run(&["persist", "destinations", "list"]);
    assert!(output.status.success(), "{output:?}");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("laptop"));
    assert_eq!(fs::read(directory.join("laptop.json")).unwrap(), old);
    assert_failure(
        &fixture.run(&["cp", "source", "--to", "@laptop"]),
        "no receiving machine named @laptop is connected",
    );
}

#[test]
fn handoff_precedes_stdin_consumption_and_result_file_opening() {
    let fixture = Fixture::new();
    let helper = fixture.script(
        r#"
import json, pathlib, sys
assert sys.argv[1] == '--return-handoff-v1', sys.argv
guard = json.loads(sys.argv[2])
assert guard['name'] == 'laptop' and 'secret' not in guard, guard
assert sys.argv[3:] == ['cp', '--mapping', '-', '--to', '@laptop', '--results', 'results'], sys.argv
assert pathlib.Path('results').read_bytes() == b'untouched'
sys.stdout.buffer.write(sys.stdin.buffer.read())
sys.exit(23)
"#,
    );
    fixture.registration(&helper, "another-build");
    fs::write(fixture.temp.path().join("results"), b"untouched").unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "cp",
            "--mapping",
            "-",
            "--to",
            "@laptop",
            "--results",
            "results",
        ])
        .current_dir(fixture.temp.path())
        .env("HOME", fixture.temp.path())
        .env("SYQ_NO_UPDATE_CHECK", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn_guarded()
        .unwrap();
    let input = b"original stdin\n\x00\xff";
    child.stdin.take().unwrap().write_all(input).unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(23), "{output:?}");
    assert_eq!(output.stdout, input);
    // It says which version runs the command instead of falling back silently.
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "syq: @laptop is connected with syq another-build, so this command runs as syq another-build\n"
    );
}

#[test]
fn handoff_passes_environment_options_as_arguments_and_drops_the_variable() {
    let fixture = Fixture::new();
    let helper = fixture.script(
        r#"
import os, sys
assert sys.argv[1] == '--return-handoff-v1', sys.argv
assert sys.argv[3:] == ['cp', '--dry-run', '--quiet', 'source', '--to', '@laptop', '--into', 'dst'], sys.argv
assert 'SYQ_CP_OPTIONS' not in os.environ and 'SYQ_RM_OPTIONS' not in os.environ
sys.exit(23)
"#,
    );
    fixture.registration(&helper, "another-build");
    let output = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["cp", "source", "--to", "@laptop", "--into", "dst"])
        .current_dir(fixture.temp.path())
        .env("HOME", fixture.temp.path())
        .env("SYQ_NO_UPDATE_CHECK", "1")
        .env("SYQ_CP_OPTIONS", "--dry-run --quiet")
        .env("SYQ_RM_OPTIONS", "--dry-run")
        .capture_output()
        .unwrap();
    assert_eq!(output.status.code(), Some(23), "{output:?}");
    // --quiet leaves out the notice about the version that runs it.
    assert!(output.stderr.is_empty(), "{output:?}");
}

#[cfg(target_os = "linux")]
#[test]
fn handoff_does_not_read_ignore_sources_in_the_invoking_build() {
    let fixture = Fixture::new();
    let helper = fixture.script(
        r#"
import json, pathlib, sys
assert sys.argv[1] == '--return-handoff-v1', sys.argv
assert json.loads(sys.argv[2])['name'] == 'laptop'
assert pathlib.Path('results').read_bytes() == b'untouched'
sys.stdout.buffer.write(sys.stdin.buffer.read())
sys.exit(23)
"#,
    );
    fixture.registration(&helper, "another-build");
    fs::write(fixture.temp.path().join("results"), b"untouched").unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "cp",
            "source",
            "--ignore",
            "!keep.tmp",
            "--follow",
            "--ignore-from",
            "/dev/stdin",
            "--ignore",
            "!last.tmp",
            "--to",
            "@laptop",
            "--results",
            "results",
        ])
        .current_dir(fixture.temp.path())
        .env("HOME", fixture.temp.path())
        .env("SYQ_NO_UPDATE_CHECK", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn_guarded()
        .unwrap();
    let input = b"*.tmp\n";
    child.stdin.take().unwrap().write_all(input).unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(23), "{output:?}");
    assert_eq!(output.stdout, input);
}

#[test]
fn ignore_input_errors_keep_the_argument_error_lane_and_do_not_open_results() {
    let fixture = Fixture::new();
    fs::write(fixture.temp.path().join("results"), b"untouched").unwrap();
    let output = fixture.run(&[
        "cp",
        "source",
        "--ignore-from",
        "missing-rules",
        "--as",
        "destination",
        "--results",
        "results",
    ]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("--ignore-from"));
    assert_eq!(
        fs::read(fixture.temp.path().join("results")).unwrap(),
        b"untouched"
    );
    assert!(!fixture.temp.path().join("destination").exists());
}

#[test]
fn source_handoff_probes_older_helper_before_sending_the_new_guard() {
    let fixture = Fixture::new();
    let helper = fixture.script(
        r#"
import pathlib, sys
assert sys.argv[1:] == ['--return-source-probe'], sys.argv
pathlib.Path('probed').write_text('yes')
sys.exit(2)
"#,
    );
    fixture.registration(&helper, "released-old-build");
    let output = fixture.source_fallback(&[
        "cp",
        "--from",
        "backup",
        "--src",
        "selected",
        "--as",
        "output",
        "--auth-from",
        "auto",
    ]);
    assert_failure(&output, "does not support source authorization");
    assert!(String::from_utf8_lossy(&output.stderr).contains("update syq"));
    assert_eq!(
        fs::read_to_string(fixture.temp.path().join("probed")).unwrap(),
        "yes"
    );
    assert!(!fixture.temp.path().join("output").exists());
}

#[test]
fn source_handoff_keeps_the_selected_route_for_a_capable_helper() {
    let fixture = Fixture::new();
    let helper = fixture.script(
        r#"
import json, sys
if sys.argv[1:] == ['--return-source-probe']:
    sys.exit(0)
assert sys.argv[1] == '--return-handoff-v1', sys.argv
guard = json.loads(sys.argv[2])
assert guard['kind'] == 'Pull' and guard['name'] == 'laptop', guard
assert sys.argv[3:6] == ['cp', '--from', 'backup'], sys.argv
sys.exit(23)
"#,
    );
    fixture.registration(&helper, "another-build");
    let output = fixture.source_fallback(&[
        "cp",
        "--from",
        "backup",
        "--src",
        "selected",
        "--as",
        "output",
        "--auth-from",
        "auto",
    ]);
    assert_eq!(output.status.code(), Some(23), "{output:?}");
}

/// Point `@laptop` at `socket`, as a receiving connection of build
/// `identity` registers itself.
fn register_at(home: &std::path::Path, socket: &std::path::Path, identity: &str, secret: &str) {
    let value = serde_json::json!({
        "version": 3, "identity": identity, "socket": socket,
        "secret": secret, "program": b"/no/such/helper".to_vec(),
    });
    let path = home.join(".syq-destinations-v3/laptop.json");
    let new = path.with_extension("new");
    fs::write(&new, serde_json::to_vec(&value).unwrap()).unwrap();
    fs::set_permissions(&new, fs::Permissions::from_mode(0o600)).unwrap();
    fs::rename(new, path).unwrap();
}

/// A copy to `@laptop` whose receiving connection switches to build
/// `switched_to` while the command reads its mapping from a FIFO, after it
/// chose `@laptop`'s registration. Returns the command's output and the
/// requests the new connection received; it refuses each. The FIFO shows
/// when the command reads its input; macOS copies take no FIFO mapping.
#[cfg(not(target_os = "macos"))]
fn copy_while_the_receiver_switches(switched_to: &str) -> (Output, Vec<serde_json::Value>) {
    use std::os::unix::fs::OpenOptionsExt;
    let fixture = Fixture::new();
    let build = String::from_utf8(fixture.run(&["--build-identity"]).stdout).unwrap();
    let build = build.trim();
    let sockets = crate::test_support::short_tempdir().unwrap();
    // The connection the command chooses, gone by the time it asks.
    register_at(
        fixture.temp.path(),
        &sockets.path().join("old.sock"),
        build,
        "old-secret",
    );
    let listener = UnixListener::bind(sockets.path().join("new.sock")).unwrap();
    listener.set_nonblocking(true).unwrap();
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let finished = done.clone();
    let receiver = std::thread::spawn(move || {
        let mut requests = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(30);
        while !finished.load(std::sync::atomic::Ordering::Acquire) {
            assert!(Instant::now() < deadline, "the copy did not finish");
            let mut socket = match listener.accept() {
                Ok((socket, _)) => socket,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(error) => panic!("{error}"),
            };
            socket.set_nonblocking(false).unwrap();
            let mut length = [0; 4];
            socket.read_exact(&mut length).unwrap();
            let mut bytes = vec![0; u32::from_be_bytes(length) as usize];
            socket.read_exact(&mut bytes).unwrap();
            requests.push(serde_json::from_slice::<serde_json::Value>(&bytes).unwrap());
            let reply = br#"{"Error":"refused by the test"}"#;
            socket
                .write_all(&(reply.len() as u32).to_be_bytes())
                .unwrap();
            socket.write_all(reply).unwrap();
        }
        requests
    });
    let fifo = fixture.temp.path().join("mapping");
    let status = Command::new("mkfifo").arg(&fifo).status().unwrap();
    assert!(status.success());
    let mut child = fixture
        .command(&[
            "cp",
            "--mapping",
            fifo.to_str().unwrap(),
            "--to",
            "@laptop",
            "--into",
            "dst",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn_guarded()
        .unwrap();
    // Opening the FIFO for writing succeeds once the command reads it,
    // which is after it chose @laptop's registration.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut mapping = loop {
        match fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&fifo)
        {
            Ok(file) => break file,
            Err(error) if error.raw_os_error() == Some(libc::ENXIO) => {
                if child.try_wait().unwrap().is_some() {
                    done.store(true, std::sync::atomic::Ordering::Release);
                    panic!(
                        "the copy ended before it read its mapping: {:?}",
                        child.wait_with_output().unwrap()
                    );
                }
                assert!(Instant::now() < deadline, "the copy never read its mapping");
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("{error}"),
        }
    };

    register_at(
        fixture.temp.path(),
        &sockets.path().join("new.sock"),
        switched_to,
        "new-secret",
    );
    mapping
        .write_all(br#"{"src":{"encoding":"utf-8","value":"source"},"dst":{"encoding":"utf-8","value":"copied"}}"#)
        .unwrap();
    mapping.write_all(b"\n").unwrap();
    drop(mapping);
    let output = child.wait_with_output().unwrap();
    done.store(true, std::sync::atomic::Ordering::Release);
    (output, receiver.join().unwrap())
}

/// The copy failed with `text`, after asking for approval (which says it
/// waits), never naming a registration's secret.
fn assert_switched_failure(output: &Output, text: &str) {
    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(text), "{stderr}");
    assert!(!stderr.contains("secret"), "{stderr}");
}

/// A receiving connection that switched to this build while the copy read
/// its input gets the copy's request: the command asks the new connection
/// once, before copying anything.
#[cfg(not(target_os = "macos"))]
#[test]
fn a_copy_asks_the_new_connection_once_after_its_receiver_switched() {
    let build = String::from_utf8(Fixture::new().run(&["--build-identity"]).stdout).unwrap();
    let (output, requests) = copy_while_the_receiver_switches(build.trim());
    assert_switched_failure(&output, "receiving machine: refused by the test");
    assert_eq!(requests.len(), 1, "{requests:?}");
    assert_eq!(requests[0]["secret"], "new-secret");
    assert!(
        requests[0]["message"].get("Request").is_some(),
        "{requests:?}"
    );
}

/// One that switched to another build cannot take this build's request:
/// the command says so and asks to be run again.
#[cfg(not(target_os = "macos"))]
#[test]
fn a_copy_whose_receiver_switched_to_another_build_asks_to_run_it_again() {
    let (output, requests) = copy_while_the_receiver_switches("another-build");
    assert_switched_failure(
        &output,
        "@laptop switched to syq another-build while this command was starting; run the command again",
    );
    assert!(requests.is_empty(), "{requests:?}");
}

/// A copy refused by a receiving connection that is stopping for a switch
/// waits a little for the new connection to register, then asks it once.
#[test]
fn a_copy_refused_while_its_receiver_switches_asks_the_new_connection() {
    let fixture = Fixture::new();
    let build = String::from_utf8(fixture.run(&["--build-identity"]).stdout).unwrap();
    let build = build.trim().to_owned();
    let sockets = crate::test_support::short_tempdir().unwrap();
    let home = fixture.temp.path().to_path_buf();
    register_at(
        &home,
        &sockets.path().join("old.sock"),
        &build,
        "old-secret",
    );
    // Serve one request on `socket`, answering `reply`, then run `then`.
    let serve =
        |socket: std::path::PathBuf, reply: &'static [u8], then: Box<dyn FnOnce() + Send>| {
            let listener = UnixListener::bind(socket).unwrap();
            listener.set_nonblocking(true).unwrap();
            std::thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(30);
                let mut socket = loop {
                    match listener.accept() {
                        Ok((socket, _)) => break socket,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < deadline, "no request came");
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Err(error) => panic!("{error}"),
                    }
                };
                socket.set_nonblocking(false).unwrap();
                let mut length = [0; 4];
                socket.read_exact(&mut length).unwrap();
                let mut bytes = vec![0; u32::from_be_bytes(length) as usize];
                socket.read_exact(&mut bytes).unwrap();
                socket
                    .write_all(&(reply.len() as u32).to_be_bytes())
                    .unwrap();
                socket.write_all(reply).unwrap();
                drop(socket);
                then();
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
            })
        };
    let new = serve(
        sockets.path().join("new.sock"),
        br#"{"Error":"refused by the test"}"#,
        Box::new(|| {}),
    );
    // The old connection refuses while it stops; the new one registers a
    // moment later.
    let (new_socket, registered_build) = (sockets.path().join("new.sock"), build.clone());
    let old = serve(
        sockets.path().join("old.sock"),
        br#"{"Error":"receiving is switching to another syq version; retry in a moment"}"#,
        Box::new(move || {
            std::thread::sleep(Duration::from_millis(1500));
            register_at(&home, &new_socket, &registered_build, "new-secret");
        }),
    );
    let output = fixture.run(&["cp", "source", "--to", "@laptop", "--into", "dst"]);
    assert_switched_failure(&output, "receiving machine: refused by the test");
    assert_eq!(old.join().unwrap()["secret"], "old-secret");
    let request = new.join().unwrap();
    assert_eq!(request["secret"], "new-secret");
    assert!(request["message"].get("Request").is_some(), "{request}");
}

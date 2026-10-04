//! Native SSH persistence must remain an optional connection optimization.
use super::*;
use std::time::Duration;

fn setup() -> Tmp {
    let temporary = Tmp::new();
    fs::create_dir(temporary.runtime()).unwrap();
    executable(
        &temporary.path("bin/ssh"),
        br#"#!/bin/sh
printf '%s\n' "$@" > "$HOME/ssh-arguments"
printf native-output
printf native-error >&2
exit 17
"#,
    );
    temporary
}

fn command(temporary: &Tmp) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
    command
        .args(["ssh", "--auth-from", "ssh"])
        .env("HOME", temporary.path("home"))
        .env("XDG_CONFIG_HOME", temporary.path("config"))
        .env("XDG_RUNTIME_DIR", temporary.runtime())
        .env("PATH", format!("{}:/usr/bin:/bin", temporary.s("bin")))
        .env("SYQ_NO_UPDATE_CHECK", "1");
    fs::create_dir_all(temporary.path("home")).unwrap();
    command
}

#[test]
fn native_ssh_warns_and_runs_once_when_optional_persistence_settings_are_invalid() {
    let temporary = setup();
    write(
        &temporary.path("config/syq/persistence.json"),
        b"not valid JSON",
    );
    let result = command(&temporary)
        .args(["host", "--", "exit 17"])
        .run()
        .unwrap();
    assert_eq!(result.status.code(), Some(17));
    assert_eq!(result.stdout, b"native-output");
    assert!(stderr_of(&result).contains("continuing without persistence"));
    let arguments = read(&temporary.path("home/ssh-arguments"));
    assert_eq!(arguments, b"--\nhost\nexit 17\n");
}

#[test]
fn native_ssh_endpoint_failure_falls_back_only_when_scope_was_omitted() {
    let temporary = setup();
    assert_output_ok(&persistence_command(&temporary, &["on"]).run().unwrap());
    let result = command(&temporary).arg("host").run().unwrap();
    assert_eq!(result.status.code(), Some(17));
    let arguments = fs::read_to_string(temporary.path("home/ssh-arguments")).unwrap();
    let mut words = arguments.lines();
    let control = PathBuf::from(
        words
            .find(|word| *word == "-S")
            .and_then(|_| words.next())
            .unwrap(),
    );
    write(&control.with_extension("json"), b"invalid endpoint record");
    let result = command(&temporary).arg("host").run().unwrap();
    assert_eq!(result.status.code(), Some(17));
    assert!(stderr_of(&result).contains("continuing without persistence"));
    assert_eq!(read(&temporary.path("home/ssh-arguments")), b"--\nhost\n");
    fs::remove_file(temporary.path("home/ssh-arguments")).unwrap();
    // Explicitly naming even the default scope keeps setup errors strict.
    let result = command(&temporary)
        .arg("--pscope")
        .arg(control.parent().unwrap())
        .arg("host")
        .run()
        .unwrap();
    assert_eq!(result.status.code(), Some(255));
    assert!(!stderr_of(&result).contains("continuing without persistence"));
    assert!(!temporary.path("home/ssh-arguments").exists());
}

#[test]
fn native_ssh_never_escapes_a_closed_explicit_scope() {
    let temporary = setup();
    let scope = ephemeral_scope(&temporary);
    write(&scope.join(".syq-persistence-closing"), b"");
    let result = command(&temporary)
        .arg("--pscope")
        .arg(scope)
        .arg("host")
        .run()
        .unwrap();
    assert_eq!(result.status.code(), Some(255));
    assert!(stderr_of(&result).contains("scope is closing"));
    assert!(!temporary.path("home/ssh-arguments").exists());
}

#[test]
fn native_persistent_master_cannot_keep_the_callers_stderr_pipe_open() {
    let temporary = setup();
    let scope = ephemeral_scope(&temporary);
    executable(
        &temporary.path("bin/ssh"),
        br#"#!/bin/sh
# Model OpenSSH's independent master retaining stderr after its client exits.
sleep 30 >/dev/null &
printf native-output
printf 'native-error\000\377' >&2
exit 17
"#,
    );
    let mut command = command(&temporary);
    command
        .arg("--pscope")
        .arg(scope)
        .arg("host")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Keep the group leader unreaped until cleanup, so even a regression with
    // an inherited pipe cannot leak the disposable background writer.
    let mut group = {
        let _spawning = PROCESS_IMAGE_LOCK
            .read()
            .unwrap_or_else(|error| error.into_inner());
        process_group::ProcessGroup::spawn(&mut command).unwrap()
    };
    let mut stdout = group.child.stdout.take().unwrap();
    let mut stderr = group.child.stderr.take().unwrap();
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let reader = std::thread::spawn(move || {
        let mut output = Vec::new();
        let mut errors = Vec::new();
        stdout.read_to_end(&mut output).unwrap();
        stderr.read_to_end(&mut errors).unwrap();
        let _ = sender.send((output, errors));
    });
    let result = receiver.recv_timeout(Duration::from_secs(5));
    let status = group.close().unwrap();
    reader.join().unwrap();
    let (stdout, stderr) =
        result.expect("native master retained the caller's stderr after SSH exited");
    assert_eq!(status.code(), Some(17));
    assert_eq!(stdout, b"native-output");
    assert_eq!(stderr, b"native-error\0\xff");
}

//! Failures at the local build handoff must precede approval and SSH fallback.
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Output, Stdio};

struct Fixture {
    temp: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
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

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_syq"))
            .args(args)
            .current_dir(self.temp.path())
            .env("HOME", self.temp.path())
            .env("XDG_CONFIG_HOME", self.temp.path().join("config"))
            .env("XDG_RUNTIME_DIR", self.temp.path().join("runtime"))
            .env("SYQ_NO_UPDATE_CHECK", "1")
            .output()
            .unwrap()
    }

    fn script(&self, body: &str) -> String {
        let path = self.temp.path().join("helper");
        fs::write(&path, format!("#!/usr/bin/python3\n{body}")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path.to_str().unwrap().into()
    }
}

fn assert_failure(output: &Output, text: &str) {
    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(text), "{stderr}");
    assert!(!stderr.contains("private-test-credential"), "{stderr}");
    assert!(!stderr.contains("requesting permission"), "{stderr}");
    assert!(
        !stderr.contains("requesting command permission"),
        "{stderr}"
    );
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
        &fixture.run(&["exec", "--on", "laptop", "--", "true"]),
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
        "unavailable",
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
        .spawn()
        .unwrap();
    let input = b"original stdin\n\x00\xff";
    child.stdin.take().unwrap().write_all(input).unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(23), "{output:?}");
    assert_eq!(output.stdout, input);
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
        .spawn()
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

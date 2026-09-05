//! Output failures must not replace filesystem outcomes or freeze telemetry.

use std::fs;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn broken_output() -> Stdio {
    let (reader, writer) = UnixStream::pair().unwrap();
    drop(reader);
    Stdio::from(OwnedFd::from(writer))
}

fn command(directory: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
    command
        .current_dir(directory)
        .env("SYQ_NO_UPDATE_CHECK", "1")
        .env("XDG_CONFIG_HOME", directory.join("config"))
        .stdin(Stdio::null());
    command
}

fn terminal(path: &std::path::Path) -> serde_json::Value {
    let text = fs::read_to_string(path).unwrap();
    serde_json::from_str(text.lines().last().unwrap()).unwrap()
}

#[test]
fn closed_human_streams_preserve_copy_and_removal_results() {
    for broken_stderr in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        fs::write(root.join("src"), b"output failure must not lose this").unwrap();
        for (mode, args, result) in [
            (
                "copy",
                vec!["cp", "--src", "src", "--as", "dst", "-v", "--progress-json"],
                "copy.json",
            ),
            (
                "remove",
                vec!["rm", "dst", "--progress-json"],
                "remove.json",
            ),
        ] {
            let output = command(&root)
                .args(args)
                .args(["--results", result])
                .stdout(broken_output())
                .stderr(if broken_stderr {
                    broken_output()
                } else {
                    Stdio::piped()
                })
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{mode}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let record = terminal(&root.join(result));
            assert_eq!(record["type"], "result");
            assert_eq!(record["exit_code"], 0);
            if mode == "copy" {
                assert_eq!(
                    fs::read(root.join("dst")).unwrap(),
                    fs::read(root.join("src")).unwrap()
                );
            } else {
                assert!(!root.join("dst").exists());
            }
            if !broken_stderr {
                let stderr = String::from_utf8_lossy(&output.stderr);
                assert_eq!(
                    stderr
                        .matches("could not write human output to stdout")
                        .count(),
                    1,
                    "{stderr}"
                );
            }
        }
    }
}

#[test]
fn closed_stderr_preserves_failure_exit_status() {
    let directory = tempfile::tempdir().unwrap();
    let output = command(directory.path())
        .args([
            "cp",
            "--src",
            "missing",
            "--as",
            "dst",
            "--results",
            "result.json",
        ])
        .stderr(broken_output())
        .output()
        .unwrap();
    let code = output.status.code().unwrap();
    assert_ne!(code, 0);
    assert_ne!(code, 101);
    assert_eq!(
        terminal(&directory.path().join("result.json"))["exit_code"],
        code
    );
}

#[test]
fn full_stdout_keeps_results_progress_running() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    fs::write(root.join("src"), b"data").unwrap();
    let (mut reader, mut writer) = UnixStream::pair().unwrap();
    // Fill the sink before starting syq, then restore blocking writes. A
    // verbose dry run will block on its first stdout line deterministically.
    writer.set_nonblocking(true).unwrap();
    let bytes = [0; 8192];
    loop {
        match writer.write(&bytes) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("fill stdout: {error}"),
        }
    }
    writer.set_nonblocking(false).unwrap();
    let mut child = command(&root)
        .args([
            "cp",
            "--src",
            "src",
            "--as",
            "dst",
            "-nv",
            "--results",
            "result.json",
        ])
        .stdout(Stdio::from(OwnedFd::from(writer)))
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut sampled_times = std::collections::BTreeSet::new();
    let mut last_report = Instant::now();
    while Instant::now() < deadline {
        if let Ok(text) = fs::read_to_string(root.join("result.json")) {
            for line in text.lines() {
                if let Ok(record) = serde_json::from_str::<serde_json::Value>(line) {
                    if record["type"] == "progress" {
                        sampled_times.insert(record["elapsed_ms"].as_u64().unwrap());
                    }
                }
            }
        }
        // Three samples span at least two seconds while stdout remains full.
        if sampled_times.len() >= 3 || child.try_wait().unwrap().is_some() {
            break;
        }
        if last_report.elapsed() >= Duration::from_secs(1) {
            eprintln!("waiting for progress with full stdout: {sampled_times:?}");
            last_report = Instant::now();
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    // Release the sink even on a regression, so the child and ticker can exit.
    let drain = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
    });
    let output = child.wait_with_output().unwrap();
    drain.join().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        sampled_times.len() >= 3,
        "ticker stalled; last observed samples: {sampled_times:?}"
    );
    assert_eq!(terminal(&root.join("result.json"))["exit_code"], 0);
}

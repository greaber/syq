//! Named jobs retain command scope and allow a new attempt after an error.
#[path = "support/temp.rs"]
mod test_support;
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

fn run(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_syq"))
        .current_dir(root)
        .env("XDG_CACHE_HOME", root.join("cache"))
        .env_remove("SYQ_OPTIONS")
        .args(args)
        .output()
        .unwrap()
}
fn job_id(root: &Path, results: &str) -> String {
    let text = fs::read_to_string(root.join(results)).unwrap();
    let run: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
    run["job_id"].as_str().unwrap().to_owned()
}
fn assert_success(output: Output) {
    assert!(output.status.success(), "{output:?}");
}

#[test]
fn resume_keeps_scope_allows_limit_increase_and_removes_completed_job() {
    let temp = test_support::tempdir().unwrap();
    let root = temp.path();
    fs::create_dir(root.join("source")).unwrap();
    fs::create_dir(root.join("destination")).unwrap();
    fs::write(root.join("source/file"), b"copied").unwrap();
    fs::write(root.join("destination/stale"), b"stale").unwrap();
    let first = run(
        root,
        &[
            "cp",
            "--srcs-in",
            "source",
            "--into",
            "destination",
            "--prune",
            "--max-delete",
            "0",
            "--if-exists",
            "error",
            "--results",
            "first.jsonl",
        ],
    );
    assert_eq!(first.status.code(), Some(25), "{first:?}");
    assert_eq!(fs::read(root.join("destination/file")).unwrap(), b"copied");
    let id = job_id(root, "first.jsonl");
    let changed = run(root, &["cp", "--resume", &id, "--as", "elsewhere"]);
    assert_eq!(changed.status.code(), Some(2), "{changed:?}");
    assert!(!root.join("elsewhere").exists());
    // A dry run neither performs the removal nor consumes the saved command.
    assert_success(run(
        root,
        &["cp", "--resume", &id, "--max-delete", "1", "--dry-run"],
    ));
    assert!(root.join("destination/stale").exists());
    assert_success(
        Command::new(env!("CARGO_BIN_EXE_syq"))
            .current_dir(root)
            .env("XDG_CACHE_HOME", root.join("cache"))
            .env("SYQ_CP_OPTIONS", "--if-exists=keep --ignore=*")
            .args([
                "cp",
                "--resume",
                &id,
                "--max-delete",
                "1",
                "--results",
                "second.jsonl",
            ])
            .output()
            .unwrap(),
    );
    assert_eq!(job_id(root, "second.jsonl"), id);
    assert!(!root.join("destination/stale").exists());
    assert_eq!(fs::read(root.join("destination/file")).unwrap(), b"copied");
    let finished = run(root, &["cp", "--resume", &id]);
    assert_eq!(finished.status.code(), Some(2), "{finished:?}");
}

#[test]
fn missing_job_and_bare_resume_fail_without_copying() {
    let temp = test_support::tempdir().unwrap();
    for args in [
        vec!["cp", "--resume"],
        vec!["rm", "--resume", "00000000000000000000000000000000"],
    ] {
        let output = run(temp.path(), &args);
        assert_eq!(output.status.code(), Some(2), "{output:?}");
    }
    assert!(!temp.path().join("cache/syq/jobs").exists());
}

#[test]
fn unavailable_recording_does_not_prevent_copy_or_removal() {
    let temp = test_support::tempdir().unwrap();
    let root = temp.path();
    // A regular file in the cache directory position works even when tests run as root.
    fs::write(root.join("cache"), b"not a directory").unwrap();
    fs::write(root.join("source"), b"copied").unwrap();
    assert_success(run(root, &["cp", "source", "--as", "destination"]));
    assert_eq!(fs::read(root.join("destination")).unwrap(), b"copied");
    assert_success(run(root, &["rm", "destination"]));
    assert!(!root.join("destination").exists());
}

#[cfg(debug_assertions)]
#[test]
fn interrupted_copy_restores_pending_directory_metadata_and_protected_placement() {
    check_interrupted_directory(true);
    check_interrupted_directory(false);
}

#[cfg(debug_assertions)]
fn check_interrupted_directory(copy_permissions: bool) {
    use std::os::unix::{fs::PermissionsExt, process::CommandExt};
    use std::time::{Duration, Instant};
    struct Running(std::process::Child);
    impl Drop for Running {
        fn drop(&mut self) {
            unsafe {
                libc::kill(-(self.0.id() as i32), libc::SIGKILL);
            }
            let _ = self.0.wait();
        }
    }
    let temp = test_support::tempdir().unwrap();
    let root = temp.path();
    fs::create_dir_all(root.join("source/nested")).unwrap();
    fs::write(root.join("source/nested/payload"), vec![42; 1024 * 1024]).unwrap();
    fs::set_permissions(
        root.join("source/nested"),
        fs::Permissions::from_mode(0o500),
    )
    .unwrap();
    let mut baseline = vec![
        "cp",
        "--srcs-in",
        "source",
        "--into-new",
        "baseline",
        "--if-exists=error",
    ];
    if copy_permissions {
        baseline.push("--copy-metadata=permissions");
    }
    assert_success(run(root, &baseline));
    let expected_mode = fs::metadata(root.join("baseline/nested"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    let ready = root.join("ready");
    let log = fs::File::create(root.join("interrupted.log")).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
    if copy_permissions {
        command.arg("cp").arg("--copy-metadata=permissions");
    } else {
        command.arg("cp");
    }
    let mut child = Running(
        command
            .current_dir(root)
            .env("XDG_CACHE_HOME", root.join("cache"))
            .env(
                if copy_permissions {
                    "SYQ_TEST_PARTIAL_READY_FILE"
                } else {
                    "SYQ_TEST_FINALIZE_READY_FILE"
                },
                &ready,
            )
            .env(
                if copy_permissions {
                    "SYQ_TEST_PARTIAL_CONTINUE_FILE"
                } else {
                    "SYQ_TEST_FINALIZE_CONTINUE_FILE"
                },
                root.join("continue"),
            )
            .args([
                "--srcs-in",
                "source",
                "--into-new",
                "destination",
                "--if-exists=error",
                "--resource-limits=bandwidth=1M",
                "--results",
                "first.jsonl",
                "--no-progress",
            ])
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .process_group(0)
            .spawn()
            .unwrap(),
    );
    let started = Instant::now();
    let mut next_progress = 1;
    while !ready.exists() {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "copy exited: {}",
            fs::read_to_string(root.join("interrupted.log")).unwrap()
        );
        let elapsed = started.elapsed().as_secs();
        assert!(
            elapsed < 20,
            "partial barrier was not reached; copy still running"
        );
        if elapsed >= next_progress {
            eprintln!("waiting for interrupted copy partial ({elapsed}s)");
            next_progress += 1;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let group = -(child.0.id() as i32);
    unsafe {
        libc::kill(group, libc::SIGKILL);
    }
    child.0.wait().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while unsafe { libc::kill(group, 0) } == 0 {
        assert!(
            Instant::now() < deadline,
            "copy process group survived termination"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ESRCH)
    );
    let id = job_id(root, "first.jsonl");
    assert_success(run(
        root,
        &["cp", "--resume", &id, "--resource-limits=bandwidth=1G"],
    ));
    assert_eq!(
        fs::read(root.join("destination/nested/payload")).unwrap(),
        vec![42; 1024 * 1024]
    );
    assert_eq!(
        fs::metadata(root.join("destination/nested"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        expected_mode
    );
    for directory in ["source/nested", "destination/nested", "baseline/nested"] {
        fs::set_permissions(root.join(directory), fs::Permissions::from_mode(0o700)).unwrap();
    }
}

#[test]
fn resume_uses_saved_mapping_when_the_original_manifest_is_replaced() {
    let temp = test_support::tempdir().unwrap();
    let root = temp.path();
    fs::create_dir(root.join("destination")).unwrap();
    fs::create_dir(root.join("source")).unwrap();
    for name in ["a", "b", "unrelated"] {
        fs::write(root.join("source").join(name), name.as_bytes()).unwrap();
    }
    fs::write(root.join("destination/b"), b"obstacle").unwrap();
    let line = |name: &str| {
        serde_json::json!({
            "src": {"encoding":"utf-8", "value":name},
            "dst": {"encoding":"utf-8", "value":name},
        })
        .to_string()
            + "\n"
    };
    fs::write(root.join("mapping"), line("a") + &line("b")).unwrap();
    let first = run(
        root,
        &[
            "cp",
            "-C",
            "source",
            "--mapping",
            "mapping",
            "--into",
            "destination",
            "--if-exists=error",
            "--results",
            "first.jsonl",
        ],
    );
    assert!(!first.status.success(), "{first:?}");
    let id = job_id(root, "first.jsonl");
    fs::write(root.join("mapping"), line("unrelated")).unwrap();
    fs::remove_file(root.join("destination/b")).unwrap();
    assert_success(run(root, &["cp", "--resume", &id]));
    assert_eq!(fs::read(root.join("destination/a")).unwrap(), b"a");
    assert_eq!(fs::read(root.join("destination/b")).unwrap(), b"b");
    assert!(!root.join("destination/unrelated").exists());
}

#[test]
fn delegated_copy_does_not_advertise_a_source_owned_job() {
    let temp = test_support::tempdir().unwrap();
    let root = temp.path();
    fs::write(root.join("source"), b"copied").unwrap();
    // Internal remote coordinator argv carries base64 path operands.
    let output = run(
        root,
        &[
            "cp",
            "--delegated-operands-b64",
            "c291cmNl",
            "--as",
            "ZGVzdGluYXRpb24",
            "--results",
            "result.jsonl",
        ],
    );
    assert_success(output);
    assert_eq!(fs::read(root.join("destination")).unwrap(), b"copied");
    let text = fs::read_to_string(root.join("result.jsonl")).unwrap();
    let run: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
    assert!(run.get("job_id").is_none_or(serde_json::Value::is_null));
    assert!(!root.join("cache/syq/jobs").exists());
}

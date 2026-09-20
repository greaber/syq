use super::*;

#[cfg(target_os = "linux")]
fn exercise_recycling(remote: Option<bool>) {
    let t = Tmp::new();
    let rsh = remote.map(|_| fake_rsh(&t));
    fs::create_dir_all(t.path("dst")).unwrap();
    // Different lengths exercise both shrinking and extending reused storage.
    for i in 0..24 {
        let name = format!("file-{i:02}");
        let source = prng(512 * 1024 + i * 7919, i as u64 + 1);
        write(&t.path(&format!("src/{name}")), &source);
        write(
            &t.path(&format!("dst/{name}")),
            &vec![0; 700 * 1024 - i * 997],
        );
        fs::set_permissions(
            t.path(&format!("src/{name}")),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        fs::set_permissions(
            t.path(&format!("dst/{name}")),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
    }
    let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
    command
        .args(["cp", "--srcs-in"])
        .arg(t.path("src"))
        .args(["--into"])
        .arg(t.path("dst"))
        .args([
            "--hash",
            "--preserve=permissions",
            "--stats",
            "--no-progress",
            "--no-compress",
            "--recycle-staging=4M",
            "--performance-tuning=workers=2",
        ]);
    if let Some(tcp) = remote {
        command
            .args(["--to", "fake", "--rsh"])
            .arg(rsh.as_ref().unwrap())
            .arg("--syq-path")
            .arg(env!("CARGO_BIN_EXE_syq"))
            .args(["--tcp-ports", EPHEMERAL_TCP_PORTS])
            .env("FAKE_REMOTE_HOME", t.path("remote-home"))
            .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
            .env("FAKE_RSH_LOG", t.path("rsh.log"));
        if !tcp {
            command.arg("--no-tcp");
        }
    }
    let output = command.run().unwrap();
    assert_output_ok(&output);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stats = stderr
        .lines()
        .find(|line| line.starts_with("syq: recycled staging:"))
        .expect("recycling statistics");
    assert!(
        !stats.contains(": 0 files,"),
        "no storage was reused: {stderr}"
    );
    for i in 0..24 {
        let name = format!("file-{i:02}");
        assert_eq!(
            read(&t.path(&format!("src/{name}"))),
            read(&t.path(&format!("dst/{name}")))
        );
        assert_eq!(
            fs::metadata(t.path(&format!("dst/{name}"))).unwrap().mode() & 0o7777,
            0o644
        );
    }
    // Explicit completion must include deletion, even with detached TCP workers.
    let names: Vec<_> = fs::read_dir(t.path("dst"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(
        names.len(),
        24,
        "staging or pool entries survived completion: {names:?}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn local_copy_recycles_public_files_and_cleans_before_returning() {
    exercise_recycling(None);
}

#[cfg(target_os = "linux")]
#[test]
fn ssh_workers_share_one_invocation_pool_and_cleanup() {
    exercise_recycling(Some(false));
}

#[cfg(target_os = "linux")]
#[test]
fn encrypted_tcp_workers_share_one_invocation_pool_and_cleanup() {
    exercise_recycling(Some(true));
}

#[test]
fn recycling_is_explicit_conflicts_with_inplace_and_dry_run_does_not_create_pool() {
    let t = Tmp::new();
    write(&t.path("source"), b"source");
    fs::create_dir_all(t.path("destination")).unwrap();
    for extra in [
        vec!["--inplace", "--recycle-staging=1M"],
        vec!["--recycle-staging=0"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_syq"))
            .args(["cp"])
            .arg(t.path("source"))
            .arg("--into")
            .arg(t.path("destination"))
            .args(extra)
            .run()
            .unwrap();
        assert!(!output.status.success());
        assert_eq!(fs::read_dir(t.path("destination")).unwrap().count(), 0);
    }
    let output = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["cp"])
        .arg(t.path("source"))
        .arg("--into")
        .arg(t.path("destination"))
        .args(["--dry-run", "--recycle-staging=1M"])
        .run()
        .unwrap();
    assert_output_ok(&output);
    assert_eq!(fs::read_dir(t.path("destination")).unwrap().count(), 0);
}

#[cfg(all(target_os = "linux", debug_assertions))]
#[test]
fn handled_write_failure_cleans_pool_and_resume_works_without_recycling() {
    let t = Tmp::new();
    for i in 0..8 {
        write(&t.path(&format!("src/file-{i}")), &prng(256 * 1024, i + 1));
        write(&t.path(&format!("dst/file-{i}")), &vec![0; 256 * 1024]);
    }
    let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
    command
        .args(["cp", "--srcs-in"])
        .arg(t.path("src"))
        .arg("--into")
        .arg(t.path("dst"))
        .args([
            "--hash",
            "--no-progress",
            "--performance-tuning=workers=1,copy-path=ranges",
        ]);
    let failed = command
        .arg("--recycle-staging=1M")
        .env("SYQ_TEST_FAIL_WRITE_RANGE_NAME", "file-7")
        .run()
        .unwrap();
    assert!(!failed.status.success());
    assert_eq!(read(&t.path("dst/file-7")), vec![0; 256 * 1024]);
    assert!(fs::read_dir(t.path("dst")).unwrap().all(|entry| !entry
        .unwrap()
        .file_name()
        .as_encoded_bytes()
        .starts_with(b".syq-recycle-")));
    let resumed = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["cp", "--srcs-in"])
        .arg(t.path("src"))
        .arg("--into")
        .arg(t.path("dst"))
        .args(["--hash", "--no-progress"])
        .run()
        .unwrap();
    assert_output_ok(&resumed);
    for i in 0..8 {
        assert_eq!(
            read(&t.path(&format!("src/file-{i}"))),
            read(&t.path(&format!("dst/file-{i}")))
        );
    }
}

#[cfg(target_os = "macos")]
#[test]
fn explicit_recycling_requires_linux_destination() {
    let t = Tmp::new();
    write(&t.path("source"), b"source");
    fs::create_dir_all(t.path("destination")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["cp"])
        .arg(t.path("source"))
        .arg("--into")
        .arg(t.path("destination"))
        .args(["--recycle-staging=1M", "--no-progress"])
        .run()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("requires a Linux receiver"));
    assert_eq!(fs::read_dir(t.path("destination")).unwrap().count(), 0);
}

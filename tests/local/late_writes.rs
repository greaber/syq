use super::*;

fn copy_command(t: &Tmp, route: &str, tuning: &str) -> Command {
    let rsh = fake_rsh(t);
    let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
    command.args([
        "cp",
        "--no-progress",
        "--rsh",
        rsh.to_str().unwrap(),
        "--syq-path",
        env!("CARGO_BIN_EXE_syq"),
        "--tcp-ports",
        EPHEMERAL_TCP_PORTS,
        "--performance-tuning",
        tuning,
    ]);
    command
        .env("FAKE_REMOTE_HOME", t.path("remote-home"))
        .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
        .env("FAKE_RSH_LOG", t.path("rsh.log"));
    if route.ends_with("ssh") {
        command.arg("--no-tcp");
    }
    if route.starts_with("pull") || route == "relay" {
        command.args(["--from", "source"]);
    }
    command.arg(t.s("src/late-error"));
    if route.starts_with("push") || route == "relay" {
        command.args(["--to", "destination"]);
    }
    if route == "relay" {
        command.args(["--coordinate-at", "local"]);
    }
    command
}

fn late_close_preserves_staged_copy(route: &str) {
    for (size, tuning) in [
        (1024, "workers=1"),
        (1 << 20, "workers=1"),
        (1 << 20, "workers=4,copy-path=ranges,comparison-block-size=64K,request-size=64K,split-min-size=128K"),
    ] {
        for existing in [false, true] {
            let t = Tmp::new();
            let bytes = vec![b'x'; size];
            write(&t.path("src/late-error"), &bytes);
            set_mtime(&t.path("src/late-error"), 1_600_000_000);
            fs::create_dir_all(t.path("dst")).unwrap();
            if existing {
                write(&t.path("dst/late-error"), b"previous good copy");
                set_mtime(&t.path("dst/late-error"), 1_500_000_000);
            }
            let before = fs::metadata(t.path("dst/late-error")).ok();
            let mut command = copy_command(&t, route, tuning);
            command
                .args(["--as", &t.s("dst/late-error"), "--results", &t.s("results.ndjson")])
                .env("SYQ_TEST_FAIL_WRITER_CLOSE", "late-error");
            let output = command.run().unwrap();
            let context = format!("{route}, size={size}, {tuning}, existing={existing}");
            assert!(!output.status.success(), "{context}: {output:?}");
            let error = stderr_of(&output);
            assert!(error.contains("close destination writer"), "{context}: {error}");
            assert!(error.contains("late-error"), "{context}: {error}");
            if let Some(before) = before {
                let after = fs::metadata(t.path("dst/late-error")).unwrap();
                assert_eq!(read(&t.path("dst/late-error")), b"previous good copy", "{context}");
                assert_eq!((after.ino(), after.mtime(), after.mode()),
                           (before.ino(), before.mtime(), before.mode()), "{context}");
            } else {
                assert!(!t.path("dst/late-error").exists(), "{context}");
            }
            let records = fs::read_to_string(t.path("results.ndjson")).unwrap();
            let summary: serde_json::Value = serde_json::from_str(records.lines().last().unwrap()).unwrap();
            assert_eq!(summary["files_transferred"], 0, "{context}: {summary}");
            // A reported close error must not turn the retained sidecar into a
            // successful final file. A later copy can still resume and publish.
            fs::remove_file(t.path("results.ndjson")).unwrap();
            let retry = command.env_remove("SYQ_TEST_FAIL_WRITER_CLOSE").run().unwrap();
            assert_output_ok(&retry);
            assert_eq!(read(&t.path("dst/late-error")), bytes, "{context}");
        }
    }
}

#[test]
fn late_close_preserves_local_staged_copies() {
    late_close_preserves_staged_copy("local");
}

#[test]
fn late_close_preserves_remote_staged_copies() {
    for route in ["push-tcp", "push-ssh", "pull-tcp", "pull-ssh", "relay"] {
        late_close_preserves_staged_copy(route);
    }
}

#[test]
fn late_close_does_not_report_inplace_writes_as_success() {
    for (size, tuning) in [(1024, "workers=1"), (1 << 20, "workers=1,copy-path=ranges")] {
        {
            let t = Tmp::new();
            write(&t.path("src/late-error"), &vec![b'x'; size]);
            set_mtime(&t.path("src/late-error"), 1_600_000_000);
            write(&t.path("dst/late-error"), b"previous good copy");
            set_mtime(&t.path("dst/late-error"), 1_500_000_000);
            let before = fs::metadata(t.path("dst/late-error")).unwrap();
            let mut command = copy_command(&t, "local", tuning);
            command.args(["--as-existing", &t.s("dst/late-error")]);
            command.arg("--inplace");
            // In-place copies have already changed the final inode, but must
            // still report a close error rather than claim completion.
            let output = command
                .env("SYQ_TEST_FAIL_WRITER_CLOSE", "/dst/late-error")
                .run()
                .unwrap();
            assert!(!output.status.success(), "size={size}: {output:?}");
            let error = stderr_of(&output);
            assert!(error.contains("close destination writer"), "{error}");
            let after = fs::metadata(t.path("dst/late-error")).unwrap();
            assert_eq!(after.ino(), before.ino());
            assert_ne!(
                after.mtime(),
                1_600_000_000,
                "failed write must not claim source mtime"
            );
        }
    }
}

use super::*;

#[cfg(debug_assertions)]
#[test]
fn fresh_copy_uses_actual_allocations_instead_of_capacity_estimates() {
    for existing in [false, true] {
        for exact in [false, true] {
            let t = Tmp::new();
            write(&t.path("src/file"), b"payload");
            if existing {
                fs::create_dir(t.path("dst")).unwrap();
            }
            let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
            command.args(["cp", &t.s("src")]);
            command.args([if exact { "--as" } else { "--into" }, &t.s("dst"), "-q"]);
            let output = command
                .env("SYQ_TEST_AVAILABLE_BYTES", "0")
                .env("SYQ_TEST_AVAILABLE_INODES", "0")
                .run()
                .unwrap();
            assert_output_ok(&output);
            assert_eq!(
                read(&t.path(if exact { "dst/file" } else { "dst/src/file" })),
                b"payload"
            );
        }
    }
    let t = Tmp::new();
    write(&t.path("source"), b"payload");
    let output = compat_command()
        .args(["-a", &t.s("source"), &t.s("missing/parent/file")])
        .env("SYQ_TEST_AVAILABLE_BYTES", "0")
        .run()
        .unwrap();
    assert_output_ok(&output);
    assert_eq!(read(&t.path("missing/parent/file")), b"payload");
}

#[cfg(debug_assertions)]
#[test]
fn nonempty_destination_skips_the_whole_copy_capacity_estimate() {
    let t = Tmp::new();
    write(&t.path("src/file"), b"payload");
    write(&t.path("dst/existing"), b"keep");

    let output = compat_command()
        .args(["-a", &t.s("src/"), &t.s("dst"), "--no-progress"])
        .env("SYQ_TEST_AVAILABLE_BYTES", "0")
        .env("SYQ_TEST_AVAILABLE_INODES", "0")
        .run()
        .unwrap();

    assert_output_ok(&output);
    assert_eq!(read(&t.path("dst/file")), b"payload");
    assert_eq!(read(&t.path("dst/existing")), b"keep");
}

#[cfg(debug_assertions)]
#[test]
fn fresh_destination_dry_run_reports_capacity_sanity_check() {
    let t = Tmp::new();
    write(&t.path("src/file"), b"payload");

    let output = compat_command()
        .args(["-an", &t.s("src/"), &t.s("dst"), "--no-progress"])
        .env("SYQ_TEST_AVAILABLE_BYTES", "1048576")
        .env("SYQ_TEST_AVAILABLE_INODES", "100")
        .run()
        .unwrap();

    assert_output_ok(&output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("capacity: 7 B logical data required"),
        "{stdout}"
    );
    assert!(stdout.contains("100 inodes available"), "{stdout}");
    assert!(stdout.contains("appears sufficient"), "{stdout}");
    assert!(!t.path("dst").exists());
}

#[cfg(debug_assertions)]
#[test]
fn fresh_destination_dry_run_reports_insufficient_capacity_as_advisory() {
    let t = Tmp::new();
    write(&t.path("src/file"), b"payload");

    let output = compat_command()
        .args(["-an", &t.s("src/"), &t.s("dst"), "--no-progress"])
        .env("SYQ_TEST_AVAILABLE_BYTES", "1")
        .run()
        .unwrap();

    assert_output_ok(&output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("capacity: 7 B logical data required"),
        "{stdout}"
    );
    assert!(stdout.contains("(insufficient; estimate only)"), "{stdout}");
    assert!(!t.path("dst").exists());
}

#[cfg(debug_assertions)]
#[test]
fn capacity_failure_reports_other_settled_apply_outcomes_before_aborting() {
    let t = Tmp::new();
    fs::create_dir_all(t.path("src")).unwrap();
    std::os::unix::fs::symlink("good-target", t.path("src/a-good")).unwrap();
    std::os::unix::fs::symlink("full-target", t.path("src/z-full")).unwrap();
    write(&t.path("dst/existing"), b"make this an update");

    let output = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "cp",
            "--srcs-in",
            "src",
            "--into-existing",
            "dst",
            "--results",
            "results.ndjson",
            "-q",
        ])
        .current_dir(&t.0)
        .env("SYQ_TEST_FAIL_APPLY_ENOSPC", "z-full")
        .run()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        fs::read_link(t.path("dst/a-good")).unwrap(),
        Path::new("good-target")
    );
    assert!(!t.path("dst/z-full").exists());
    let records: Vec<serde_json::Value> = String::from_utf8(read(&t.path("results.ndjson")))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let operation = |name: &str| {
        records
            .iter()
            .find(|record| record["type"] == "operation_result" && record["dst"]["value"] == name)
            .unwrap_or_else(|| panic!("missing operation result for {name}: {records:#?}"))
    };
    assert_eq!(operation("a-good")["disposition"], "succeeded");
    assert_eq!(operation("z-full")["disposition"], "failed");
    assert_eq!(operation("z-full")["os_kind"], "no_space");
    let terminal = records.last().unwrap();
    assert_eq!(terminal["status"], "aborted");
    assert_eq!(terminal["symlinks_created"], 1);
}

#[cfg(all(debug_assertions, target_os = "linux"))]
#[test]
fn copy_local_disk_exdev_preserves_range_controls() {
    for (args, synchronous) in [
        (vec!["--checksum"], false),
        (vec!["--resource-limits", "bandwidth=1G"], false),
        (vec![], true),
    ] {
        let t = Tmp::new();
        write(&t.path("src/small"), b"parallel file work");
        write(&t.path("src/file"), &prng(5 << 20, 455));
        let out = compat_command()
            .args(["-a", "--no-progress", &t.s("src/"), &t.s("dst/")])
            .args(args)
            .env("SYQ_DEBUG", "1")
            .env("SYQ_TEST_COPY_LOCAL_EXDEV", "1")
            .env("SYQ_TEST_COPY_LOCAL_FS", "local")
            .envs(synchronous.then_some(("SYQ_TEST_COPY_LOCAL_NFS_SYNC", "1")))
            .run()
            .unwrap();
        assert_output_ok(&out);
        assert_eq!(read(&t.path("src/file")), read(&t.path("dst/file")));
        let observed = tuning_observed(&out);
        assert_eq!(observed["local_whole_files"], 0);
        assert!(observed["range_requests"].as_u64().unwrap() > 0);
    }
}

#[cfg(debug_assertions)]
#[test]
fn streaming_capacity_failure_keeps_completed_files_and_reports_abort() {
    let t = Tmp::new();
    for index in 0..6000 {
        write(&t.path(&format!("src/tree/f{index:04}")), b"payload");
    }
    std::os::unix::fs::symlink("missing", t.path("src/tree/z-full")).unwrap();
    let ready = t.path("ready");
    let continuation = t.path("continue");
    write(&t.path("selection"), b"tree\n");
    let mut child = compat_command()
        .args([
            "-rlpt",
            "--files-from",
            &t.s("selection"),
            &t.s("src/"),
            &t.s("dst/"),
            "--no-progress",
        ])
        .env("SYQ_TEST_PLANNED_BATCH_READY_FILE", &ready)
        .env("SYQ_TEST_PLANNED_BATCH_CONTINUE_FILE", &continuation)
        .env("SYQ_TEST_FAIL_APPLY_ENOSPC", "z-full")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .start()
        .unwrap();
    wait_for_confinement_marker(&mut child, &ready, "streaming first batch");
    wait_for_confinement_marker(
        &mut child,
        &t.path("dst/tree/f0000"),
        "completed file before scan ends",
    );
    release_confinement_barrier(&continuation);
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(read(&t.path("dst/tree/f0000")), b"payload");
    assert!(!t.path("dst/tree/z-full").exists());
    assert!(
        stderr_of(&output).contains("No space left on device"),
        "{}",
        stderr_of(&output)
    );
    for entry in fs::read_dir(t.path("dst/tree")).unwrap() {
        let entry = entry.unwrap();
        if entry.file_name().to_string_lossy().starts_with('f') {
            assert_eq!(read(&entry.path()), b"payload");
        }
    }
}

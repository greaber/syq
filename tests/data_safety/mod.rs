use super::*;

fn timestamp(path: &Path, seconds: u64, nanos: u32) {
    File::open(path)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(
            std::time::SystemTime::UNIX_EPOCH + std::time::Duration::new(seconds, nanos),
        ))
        .unwrap();
}

#[test]
fn native_copy_detects_subsecond_and_older_timestamp_edits() {
    for size in [8, 128 << 10] {
        let t = Tmp::new();
        write(&t.path("src/file"), &vec![b'a'; size]);
        timestamp(&t.path("src/file"), 1_700_000_000, 100_000_000);
        let args = ["cp", "--srcs-in", &t.s("src"), "--into", &t.s("dst")];
        run_native_ok(&args);
        for (byte, seconds, nanos) in [
            (b'b', 1_700_000_000, 200_000_000),
            (b'c', 1_699_999_000, 300_000_000),
        ] {
            write(&t.path("src/file"), &vec![byte; size]);
            timestamp(&t.path("src/file"), seconds, nanos);
            run_native_ok(&args);
            assert_eq!(read(&t.path("dst/file")), vec![byte; size]);
        }
    }
}

#[test]
fn prune_refuses_a_destination_containing_its_source() {
    let t = Tmp::new();
    write(&t.path("backup/import/file"), b"source contents");
    write(&t.path("backup/old"), b"old contents");
    let out = native_syq(&[
        "cp",
        "--prune",
        "--srcs-in",
        &t.s("backup/import"),
        "--into",
        &t.s("backup"),
    ]);
    assert!(!out.status.success());
    assert!(stderr_of(&out).contains("contains source"), "{out:?}");
    assert_eq!(read(&t.path("backup/import/file")), b"source contents");
    assert_eq!(read(&t.path("backup/old")), b"old contents");
    assert!(!t.path("backup/file").exists());
}

#[cfg(debug_assertions)]
#[test]
fn prune_is_suppressed_after_an_ordinary_file_read_failure() {
    let t = Tmp::new();
    write(&t.path("src/file"), &vec![b'n'; 128 << 10]);
    write(&t.path("dst/file"), b"previous complete file");
    write(&t.path("dst/extra"), b"keep after failure");
    let out = compat_command()
        .args([
            "-a",
            "--delete",
            "--tuning-options=copy-path=ranges",
            &t.s("src/"),
            &t.s("dst/"),
        ])
        .env("SYQ_TEST_FAIL_READ_RANGE", "1")
        .run()
        .unwrap();
    assert!(!out.status.success());
    assert!(stderr_of(&out).contains("skipping deletions"), "{out:?}");
    assert_eq!(read(&t.path("dst/file")), b"previous complete file");
    assert_eq!(read(&t.path("dst/extra")), b"keep after failure");
}

#[cfg(target_os = "macos")]
#[test]
fn prune_preserves_equivalent_existing_filename_spelling() {
    let t = Tmp::new();
    write(&t.path("src/report.txt"), b"contents");
    write(&t.path("dst/REPORT.TXT"), b"contents");
    if !t.path("dst/report.txt").exists() {
        return;
    }
    timestamp(&t.path("src/report.txt"), 1_700_000_000, 0);
    timestamp(&t.path("dst/REPORT.TXT"), 1_700_000_000, 0);
    run_native_ok(&[
        "cp",
        "--prune",
        "--srcs-in",
        &t.s("src"),
        "--into",
        &t.s("dst"),
    ]);
    assert_eq!(read(&t.path("dst/report.txt")), b"contents");
}

#[cfg(target_os = "macos")]
#[test]
fn copy_refuses_sources_that_collapse_to_one_destination_name() {
    let t = Tmp::new();
    write(&t.path("dst/probe"), b"");
    if !t.path("dst/PROBE").exists() {
        return;
    }
    fs::remove_file(t.path("dst/probe")).unwrap();
    write(&t.path("one/report.txt"), b"first source");
    write(&t.path("two/REPORT.TXT"), b"second source");
    let output = native_syq(&[
        "cp",
        &t.s("one/report.txt"),
        &t.s("two/REPORT.TXT"),
        "--into",
        &t.s("dst"),
    ]);
    assert!(!output.status.success());
    assert!(
        stderr_of(&output).contains("cannot safely be distinguished"),
        "{output:?}"
    );
    assert_eq!(fs::read_dir(t.path("dst")).unwrap().count(), 0);
}

#[test]
fn prune_checks_source_overlap_across_endpoint_spellings() {
    let t = Tmp::new();
    write(&t.path("backup/import/file"), b"source contents");
    let shell = fake_rsh(&t);
    let out = compat_command()
        .args(["-a", "--delete", "-e"])
        .arg(shell)
        .args([
            "--syq-no-bootstrap",
            "--rsync-path",
            env!("CARGO_BIN_EXE_syq"),
        ])
        .arg(format!("fake:{}", t.s("backup/import/")))
        .arg(t.path("backup/"))
        .run()
        .unwrap();
    assert!(!out.status.success());
    assert!(stderr_of(&out).contains("contains source"), "{out:?}");
    assert_eq!(read(&t.path("backup/import/file")), b"source contents");
    assert!(!t.path("backup/file").exists());
}

#[test]
fn prune_protects_an_exact_source_beneath_another_sources_destination() {
    let t = Tmp::new();
    write(&t.path("external/other"), b"other source");
    write(&t.path("backup/import/file"), b"selected source");
    let out = compat_command()
        .args(["-a", "--delete"])
        .args([t.s("external/"), t.s("backup/import/file"), t.s("backup/")])
        .run()
        .unwrap();
    assert!(!out.status.success());
    assert!(stderr_of(&out).contains("contains source"), "{out:?}");
    assert_eq!(read(&t.path("backup/import/file")), b"selected source");
    assert!(!t.path("backup/other").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn prune_rechecks_names_after_destination_permissions_are_repaired() {
    let t = Tmp::new();
    write(&t.path("src/Report.txt"), b"keep these contents");
    write(&t.path("dst/extra"), b"remove this extra");
    fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o311)).unwrap();
    run_native_ok(&[
        "cp",
        "--prune",
        "--srcs-in",
        &t.s("src"),
        "--into",
        &t.s("dst"),
    ]);
    assert_eq!(read(&t.path("dst/Report.txt")), b"keep these contents");
    assert!(!t.path("dst/extra").exists());
}

#[test]
fn copy_repairs_destination_directories_without_search_permission() {
    for directory in ["sub", "parent/sub"] {
        for mode in [0o600, 0o000] {
            for prune in [false, true] {
                let t = Tmp::new();
                let source = format!("src/{directory}/Report.txt");
                let destination = format!("dst/{directory}");
                write(&t.path(&source), b"copied contents");
                write(&t.path(&format!("{destination}/extra")), b"extra contents");
                fs::set_permissions(t.path(&destination), fs::Permissions::from_mode(mode))
                    .unwrap();
                let src = t.s("src");
                let dst = t.s("dst");
                let mut args = vec!["cp", "--srcs-in", &src, "--into", &dst];
                if prune {
                    args.push("--prune");
                }
                let out = native_syq(&args);
                // The temporary repair must restore the existing mode when
                // permissions are not being copied from the source.
                let after = fs::metadata(t.path(&destination)).unwrap().mode() & 0o777;
                fs::set_permissions(t.path(&destination), fs::Permissions::from_mode(0o755))
                    .unwrap();
                assert_output_ok(&out);
                assert_eq!(after, mode);
                assert_eq!(
                    read(&t.path(&format!("{destination}/Report.txt"))),
                    b"copied contents"
                );
                assert_eq!(t.path(&format!("{destination}/extra")).exists(), !prune);
            }
        }
    }
}

#[test]
fn dry_run_leaves_unsearchable_destination_permissions_unchanged() {
    for mode in [0o600, 0o000] {
        let t = Tmp::new();
        write(&t.path("src/sub/file"), b"new contents");
        write(&t.path("dst/sub/file"), b"old contents");
        fs::set_permissions(t.path("dst/sub"), fs::Permissions::from_mode(mode)).unwrap();
        let before = fs::metadata(t.path("dst/sub")).unwrap();
        let out = native_syq(&[
            "cp",
            "--dry-run",
            "--srcs-in",
            &t.s("src"),
            "--into",
            &t.s("dst"),
        ]);
        let after = fs::metadata(t.path("dst/sub")).unwrap();
        fs::set_permissions(t.path("dst/sub"), fs::Permissions::from_mode(0o755)).unwrap();
        assert_output_ok(&out);
        assert_eq!(after.mode(), before.mode());
        assert_eq!(
            (after.ctime(), after.ctime_nsec()),
            (before.ctime(), before.ctime_nsec()),
            "dry-run filename inspection changed destination permissions"
        );
        assert_eq!(read(&t.path("dst/sub/file")), b"old contents");
    }
}

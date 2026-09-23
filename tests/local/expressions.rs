use super::*;

#[test]
fn selection_traverses_unselected_directories_and_protects_pruning() {
    let t = Tmp::new();
    write(&t.path("src/nested/keep.txt"), b"selected");
    write(&t.path("src/nested/tiny.txt"), b"x");
    write(&t.path("src/ignored/keep.txt"), b"ignored");
    write(&t.path("dst/nested/tiny.txt"), b"protected");
    write(&t.path("dst/extra"), b"remove");
    run_native_ok(&[
        "cp",
        "--srcs-in",
        &t.s("src"),
        "--into",
        &t.s("dst"),
        "--ignore",
        "ignored/",
        "--where",
        "src.kind = 'file' and src.size >= 4B and src.name glob '*.txt'",
        "--prune",
    ]);
    assert_eq!(read(&t.path("dst/nested/keep.txt")), b"selected");
    assert_eq!(read(&t.path("dst/nested/tiny.txt")), b"protected");
    assert!(!t.path("dst/extra").exists());
    assert!(!t.path("dst/ignored").exists());
}

#[test]
fn destination_conditions_apply_before_content_and_metadata_updates() {
    let t = Tmp::new();
    write(&t.path("src/grow"), b"longer source");
    write(&t.path("dst/grow"), b"x");
    write(&t.path("src/keep"), b"x");
    write(&t.path("dst/keep"), b"longer destination");
    write(&t.path("src/new"), b"new file");
    fs::set_permissions(t.path("src/keep"), fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(t.path("dst/keep"), fs::Permissions::from_mode(0o644)).unwrap();
    run_native_ok(&[
        "cp",
        "--srcs-in",
        &t.s("src"),
        "--into",
        &t.s("dst"),
        "--preserve=permissions",
        "--copy-if",
        "not dst.exists or (src.kind = 'file' and dst.kind = 'file' and src.size > dst.size)",
    ]);
    assert_eq!(read(&t.path("dst/grow")), b"longer source");
    assert_eq!(read(&t.path("dst/keep")), b"longer destination");
    assert_eq!(
        fs::metadata(t.path("dst/keep")).unwrap().mode() & 0o777,
        0o644
    );
    assert_eq!(read(&t.path("dst/new")), b"new file");
}

#[test]
fn invalid_expression_fails_before_creating_destination() {
    let t = Tmp::new();
    write(&t.path("src"), b"contents");
    for expression in [
        "src.size > 3s",
        "src.mtime > 'yesterday'",
        "dst.exists",
        "src.nonexistent = 1",
        "true or src.mode = 'bad'",
    ] {
        let out = native_syq(&[
            "cp",
            &t.s("src"),
            "--as",
            &t.s("dst"),
            "--where",
            expression,
        ]);
        assert!(!out.status.success(), "{expression}");
        assert!(!t.path("dst").exists());
    }
}

#[test]
fn explicit_file_name_and_renamed_destination_are_available() {
    let t = Tmp::new();
    write(&t.path("original.txt"), b"contents");
    run_native_ok(&[
        "cp",
        &t.s("original.txt"),
        "--as",
        &t.s("renamed.dat"),
        "--where",
        "src.name = 'original.txt'",
        "--copy-if",
        "dst.name = 'renamed.dat' and not dst.exists",
    ]);
    assert_eq!(read(&t.path("renamed.dat")), b"contents");
}

#[test]
fn dry_run_and_hash_comparison_respect_eligibility() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"new");
    write(&t.path("dst/a"), b"old");
    run_native_ok(&[
        "cp",
        "--srcs-in",
        &t.s("src"),
        "--into",
        &t.s("dst"),
        "--copy-if",
        "false",
        "--hash",
    ]);
    assert_eq!(read(&t.path("dst/a")), b"old");
    let out = native_syq(&[
        "cp",
        "--srcs-in",
        &t.s("src"),
        "--into",
        &t.s("dst"),
        "--copy-if",
        "true",
        "--hash",
        "--dry-run",
        "-v",
    ]);
    assert!(out.status.success(), "{}", stderr_of(&out));
    assert_eq!(read(&t.path("dst/a")), b"old");
    run_native_ok(&[
        "cp",
        "--srcs-in",
        &t.s("src"),
        "--into",
        &t.s("dst"),
        "--copy-if",
        "true",
        "--hash",
    ]);
    assert_eq!(read(&t.path("dst/a")), b"new");
}

#[test]
fn evaluation_errors_are_visible_and_prevent_pruning() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"new");
    write(&t.path("dst/extra"), b"keep");
    let out = native_syq(&[
        "cp",
        "--srcs-in",
        &t.s("src"),
        "--into",
        &t.s("dst"),
        "--copy-if",
        "1 / 0 = 1",
        "--prune",
    ]);
    assert!(!out.status.success());
    assert!(
        stderr_of(&out).contains("division by zero"),
        "{}",
        stderr_of(&out)
    );
    assert_eq!(read(&t.path("dst/extra")), b"keep");
}

#[test]
fn symlinks_can_be_selected_by_target_without_following() {
    let t = Tmp::new();
    write(&t.path("src/file"), b"data");
    std::os::unix::fs::symlink("file", t.path("src/link")).unwrap();
    run_native_ok(&[
        "cp",
        "--srcs-in",
        &t.s("src"),
        "--into",
        &t.s("dst"),
        "--where",
        "src.kind = 'symlink' and src.link_target = 'file'",
    ]);
    assert_eq!(
        fs::read_link(t.path("dst/link")).unwrap(),
        Path::new("file")
    );
    assert!(!t.path("dst/file").exists());
}

#[test]
fn remote_push_and_pull_apply_expressions_over_ssh_and_tcp() {
    for pull in [false, true] {
        for tcp in [false, true] {
            let t = Tmp::new();
            let rsh = fake_rsh(&t);
            t.expose_remote_syq();
            write(&t.path("src/nested/keep"), b"selected payload");
            write(&t.path("src/nested/tiny"), b"x");
            write(&t.path("dst/nested/keep"), b"old");
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_syq"));
            cmd.arg("cp");
            if pull {
                cmd.args(["--from", "127.0.0.1"]);
            }
            cmd.args(["--srcs-in", &t.s("src")]);
            if !pull {
                cmd.args(["--to", "127.0.0.1"]);
            }
            cmd.args([
                "--into",
                &t.s("dst"),
                "--where",
                "src.kind = 'file' and src.size > 1B",
                "--copy-if",
                "not dst.exists or src.size > dst.size",
                "--rsh",
                rsh.to_str().unwrap(),
                "--no-bootstrap",
                "--tcp-ports",
                EPHEMERAL_TCP_PORTS,
                "--no-progress",
            ])
            .env("FAKE_REMOTE_HOME", t.path("remote-home"))
            .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
            .env("XDG_CACHE_HOME", t.path("cache"));
            if !tcp {
                cmd.arg("--no-tcp");
            }
            let out = cmd.run().unwrap();
            assert_output_ok(&out);
            assert_eq!(read(&t.path("dst/nested/keep")), b"selected payload");
            assert!(!t.path("dst/nested/tiny").exists());
        }
    }
}

#[test]
fn expressions_reject_streams_and_copy_if_rejects_inplace() {
    let t = Tmp::new();
    write(&t.path("src"), b"unchanged");
    for options in [
        vec!["--src-fd", "0", "--where", "true"],
        vec!["--src-fd", "0", "--copy-if", "true"],
        vec!["--src", &t.s("src"), "--copy-if", "true", "--inplace"],
    ] {
        let mut args = vec!["cp"];
        args.extend(options);
        let dst = t.s("dst");
        args.extend(["--as", &dst]);
        let out = native_syq(&args);
        assert!(!out.status.success());
        assert!(!t.path("dst").exists());
    }
}

#[test]
fn selected_directory_metadata_is_independent_of_descendants() {
    let t = Tmp::new();
    write(&t.path("src/child/file"), b"contents");
    write(&t.path("dst/child/old"), b"existing");
    fs::set_permissions(t.path("src/child"), fs::Permissions::from_mode(0o750)).unwrap();
    fs::set_permissions(t.path("dst/child"), fs::Permissions::from_mode(0o755)).unwrap();
    run_native_ok(&[
        "cp",
        "--srcs-in",
        &t.s("src"),
        "--into",
        &t.s("dst"),
        "--preserve=permissions",
        "--where",
        "src.kind = 'file'",
    ]);
    assert_eq!(
        fs::metadata(t.path("dst/child")).unwrap().mode() & 0o777,
        0o755
    );
    assert_eq!(read(&t.path("dst/child/file")), b"contents");
    run_native_ok(&[
        "cp",
        "--srcs-in",
        &t.s("src"),
        "--into",
        &t.s("dst"),
        "--preserve=permissions",
        "--where",
        "src.kind = 'dir'",
    ]);
    assert_eq!(
        fs::metadata(t.path("dst/child")).unwrap().mode() & 0o777,
        0o750
    );
}

#[test]
fn merged_directories_keep_each_sources_expression_result() {
    let t = Tmp::new();
    write(&t.path("first/shared/one"), b"one");
    write(&t.path("second/shared/two"), b"two");
    fs::create_dir_all(t.path("dst/shared")).unwrap();
    for (path, mode) in [
        ("first/shared", 0o750),
        ("second/shared", 0o700),
        ("dst/shared", 0o755),
    ] {
        fs::set_permissions(t.path(path), fs::Permissions::from_mode(mode)).unwrap();
    }
    run_native_ok(&[
        "cp",
        "--srcs-in",
        &t.s("first"),
        "--srcs-in",
        &t.s("second"),
        "--into",
        &t.s("dst"),
        "--preserve=permissions",
        "--where",
        "src.kind = 'file' or src.mode = 0o750",
    ]);
    assert_eq!(
        fs::metadata(t.path("dst/shared")).unwrap().mode() & 0o777,
        0o750
    );
    assert_eq!(read(&t.path("dst/shared/one")), b"one");
    assert_eq!(read(&t.path("dst/shared/two")), b"two");
}

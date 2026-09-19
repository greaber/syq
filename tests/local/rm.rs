use super::*;

#[test]
fn native_rm_refuses_an_intermediate_symlink_before_mutating_any_selector() {
    use std::os::unix::fs::symlink;

    let t = Tmp::new();
    write(&t.path("real/file"), b"keep");
    write(&t.path("victim"), b"keep");
    symlink("real", t.path("link")).unwrap();

    let output = native_syq(&[
        "rm",
        "--cwd",
        &t.s(""),
        "--src",
        "victim",
        "--src",
        "link/file",
    ]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--follow-src for source paths"), "{stderr}");
    assert_eq!(read(&t.path("victim")), b"keep");
    assert_eq!(read(&t.path("real/file")), b"keep");
    assert!(t.path("link").is_symlink());
}

#[test]
fn native_rm_without_follow_unlinks_selected_symlinks_and_preserves_referents() {
    use std::os::unix::fs::symlink;

    let t = Tmp::new();
    write(&t.path("real-dir/file"), b"keep");
    write(&t.path("real-file"), b"keep");
    symlink("real-dir", t.path("dir-link")).unwrap();
    symlink("real-file", t.path("file-link")).unwrap();
    symlink("missing", t.path("dangling-link")).unwrap();

    run_native_ok(&[
        "rm",
        "--cwd",
        &t.s(""),
        "--src",
        "dir-link",
        "--src-non-dir",
        "file-link",
        "--src",
        "dangling-link",
    ]);

    assert!(!t.path("dir-link").is_symlink());
    assert!(!t.path("file-link").is_symlink());
    assert!(!t.path("dangling-link").is_symlink());
    assert_eq!(read(&t.path("real-dir/file")), b"keep");
    assert_eq!(read(&t.path("real-file")), b"keep");
}

#[test]
fn native_rm_directory_selector_rejects_a_selected_symlink_before_mutation() {
    use std::os::unix::fs::symlink;

    let t = Tmp::new();
    write(&t.path("real/file"), b"keep");
    write(&t.path("victim"), b"keep");
    symlink("real", t.path("link")).unwrap();

    let output = native_syq(&[
        "rm",
        "--cwd",
        &t.s(""),
        "--src",
        "victim",
        "--src-dir",
        "link",
    ]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("must resolve to a directory"));
    assert_eq!(read(&t.path("victim")), b"keep");
    assert_eq!(read(&t.path("real/file")), b"keep");
    assert!(t.path("link").is_symlink());
}

#[test]
fn native_rm_follow_preserves_final_symlink_identity() {
    use std::os::unix::fs::symlink;
    for follow in ["--follow", "--follow-src"] {
        let t = Tmp::new();
        write(&t.path("real/file"), b"keep");
        symlink("real", t.path("link")).unwrap();
        for selector in ["--src-dir", "--srcs-in"] {
            let out = native_syq(&["rm", "--root", &t.s(""), follow, selector, "link"]);
            assert!(!out.status.success());
            assert!(stderr_of(&out).contains("final symlinks are never followed"));
            assert!(stderr_of(&out).contains("name the target directory explicitly"));
            assert_eq!(read(&t.path("real/file")), b"keep");
            assert!(t.path("link").is_symlink());
        }
        run_native_ok(&["rm", "--root", &t.s(""), follow, "--src-non-dir", "link"]);
        assert!(!t.path("link").is_symlink());
        assert_eq!(read(&t.path("real/file")), b"keep");
        for selector in [None, Some("--src")] {
            symlink("real", t.path("link")).unwrap();
            let root = t.s("");
            let mut args = vec!["rm", "--root", &root, follow];
            args.extend(selector);
            args.push("link");
            run_native_ok(&args);
            assert!(!t.path("link").is_symlink());
            assert_eq!(read(&t.path("real/file")), b"keep");
        }
        symlink("real", t.path("parent")).unwrap();
        run_native_ok(&["rm", "--root", &t.s(""), follow, "parent/file"]);
        assert!(t.path("parent").is_symlink());
        assert!(!t.path("real/file").exists());
    }
}

#[test]
fn native_rm_never_follows_symlinks_found_inside_a_selected_directory() {
    use std::os::unix::fs::symlink;

    let t = Tmp::new();
    write(&t.path("outside/keep"), b"keep");
    write(&t.path("tree/file"), b"remove");
    symlink("../outside", t.path("tree/link")).unwrap();

    run_native_ok(&["rm", "--cwd", &t.s(""), "--src-dir", "tree"]);

    assert!(!t.path("tree").exists());
    assert_eq!(read(&t.path("outside/keep")), b"keep");
}

#[test]
fn native_rm_duplicate_selectors_are_idempotent_without_deduplication() {
    let t = Tmp::new();
    write(&t.path("duplicate"), b"data");
    let output = native_syq(&[
        "rm",
        "--cwd",
        &t.s(""),
        "--src",
        "duplicate",
        "--src",
        "duplicate",
        "--results",
        &t.s("results.ndjson"),
    ]);
    assert_output_ok(&output);
    assert!(!t.path("duplicate").exists());
    let records: Vec<serde_json::Value> = String::from_utf8(read(&t.path("results.ndjson")))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let selectors: Vec<u64> = records
        .iter()
        .filter(|record| record["type"] == "selection_result")
        .map(|record| record["selector"].as_u64().unwrap())
        .collect();
    assert_eq!(selectors, [0, 1], "{records:?}");
    let terminal = records.last().unwrap();
    // Linux orders the two unlinks so exactly one succeeds. macOS lets two
    // concurrent unlinks of one name both report success (measured on a
    // macOS 14 runner: 685 of 3000 races), so the split there is not fixed.
    let removed = terminal["entries_removed"].as_u64().unwrap();
    let absent = terminal["entries_already_absent"].as_u64().unwrap();
    if cfg!(target_os = "linux") {
        assert_eq!((removed, absent), (1, 1), "{records:?}");
    } else {
        assert!(removed >= 1 && removed + absent == 2, "{records:?}");
    }
}

#[test]
fn native_rm_missing_selectors_succeed() {
    let t = Tmp::new();
    run_native_ok(&["rm", "--cwd", &t.s(""), "--src", "absent"]);
}

#[test]
fn native_rm_results_preserve_non_utf8_paths() {
    if !filesystem_accepts_non_utf8_names() {
        eprintln!("skipping: this filesystem rejects file names that are not valid UTF-8");
        return;
    }
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let t = Tmp::new();
    let raw_name = b"remove-\xff";
    write(&t.path("").join(OsStr::from_bytes(raw_name)), b"data");
    let output = Command::new(env!("CARGO_BIN_EXE_syq"))
        .arg("rm")
        .arg("--cwd")
        .arg(t.path(""))
        .arg("--src-non-dir")
        .arg(OsStr::from_bytes(raw_name))
        .args(["--results", &t.s("results.ndjson"), "-q"])
        .run()
        .unwrap();
    assert_output_ok(&output);
    let records: Vec<serde_json::Value> = String::from_utf8(read(&t.path("results.ndjson")))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let removal = records
        .iter()
        .find(|record| record["type"] == "removal_result")
        .unwrap();
    assert_eq!(removal["path"]["encoding"], "base64");
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(removal["path"]["value"].as_str().unwrap())
            .unwrap(),
        raw_name
    );
}

#[test]
fn native_rm_cwd_may_escape_while_root_confines_dotdot() {
    let t = Tmp::new();
    fs::create_dir_all(t.path("base/nested")).unwrap();
    write(&t.path("base/inside"), b"inside");
    write(&t.path("outside/remove"), b"outside");

    run_native_ok(&["rm", "--cwd", &t.s("base"), "--src", "../outside/remove"]);
    assert!(!t.path("outside/remove").exists());

    write(&t.path("outside/absolute"), b"absolute");
    run_native_ok(&[
        "rm",
        "--cwd",
        &t.s("missing-base"),
        "--src",
        &t.s("outside/absolute"),
    ]);
    assert!(!t.path("outside/absolute").exists());

    write(&t.path("outside/keep"), b"outside");
    let escape = native_syq(&[
        "rm",
        "--root",
        &t.s("base"),
        "--src",
        "inside",
        "--src",
        "../outside/keep",
    ]);
    assert!(!escape.status.success());
    assert_eq!(read(&t.path("base/inside")), b"inside");
    assert_eq!(read(&t.path("outside/keep")), b"outside");

    let absolute_escape = native_syq(&[
        "rm",
        "--root",
        &t.s("base"),
        "--src",
        "inside",
        "--src",
        &t.s("outside/keep"),
    ]);
    assert!(!absolute_escape.status.success());
    assert_eq!(read(&t.path("base/inside")), b"inside");
    assert_eq!(read(&t.path("outside/keep")), b"outside");

    run_native_ok(&["rm", "--root", &t.s("base"), "--src", "nested/../inside"]);
    assert!(!t.path("base/inside").exists());

    write(&t.path("base/a"), b"a");
    write(&t.path("base/sub/b"), b"b");
    run_native_ok(&["rm", "--root", &t.s("base"), "--srcs-in", "."]);
    assert!(t.path("base").is_dir());
    assert!(listing(&t.path("base")).is_empty());
}

#[test]
fn native_rm_root_uses_the_common_follow_policy_and_still_confines_selectors() {
    use std::os::unix::fs::symlink;

    let t = Tmp::new();
    write(&t.path("root/victim"), b"keep");
    write(&t.path("root/inside/child"), b"inside");
    write(&t.path("outside/child"), b"outside");
    symlink("root", t.path("root-link")).unwrap();
    symlink("../outside", t.path("root/escape")).unwrap();
    symlink("../root/inside", t.path("root/reentry")).unwrap();

    let base_link = native_syq(&["rm", "--root", &t.s("root-link"), "--src", "victim"]);
    assert!(!base_link.status.success());
    assert_eq!(read(&t.path("root/victim")), b"keep");

    run_native_ok(&[
        "rm",
        "--root",
        &t.s("root-link"),
        "--follow",
        "--src",
        "victim",
    ]);
    assert!(!t.path("root/victim").exists());
    write(&t.path("root/victim"), b"keep");

    // Follow a parent link, not a final directory selector: refusal must be
    // confinement, not the independent rule rejecting final directory links.
    for follow in ["--follow", "--follow-src"] {
        for selector in ["escape/child", "reentry/child"] {
            let excursion = native_syq(&[
                "rm",
                "--root",
                &t.s("root"),
                follow,
                "--src",
                "victim",
                "--src",
                selector,
            ]);
            assert!(!excursion.status.success());
            assert!(
                stderr_of(&excursion).contains("outside its confined root"),
                "{}",
                stderr_of(&excursion)
            );
            assert_eq!(read(&t.path("root/victim")), b"keep");
            assert_eq!(read(&t.path("outside/child")), b"outside");
            assert_eq!(read(&t.path("root/inside/child")), b"inside");
        }
    }
}

#[test]
fn native_rm_root_allows_following_a_symlink_that_stays_inside() {
    use std::os::unix::fs::symlink;

    let t = Tmp::new();
    write(&t.path("root/inside/file"), b"remove");
    symlink("inside", t.path("root/link")).unwrap();

    run_native_ok(&[
        "rm",
        "--root",
        &t.s("root"),
        "--follow",
        "--src",
        "link/file",
    ]);
    assert!(t.path("root/link").is_symlink());
    assert!(listing(&t.path("root/inside")).is_empty());
}

#[test]
fn native_rm_cwd_and_root_are_mutually_exclusive() {
    let output = native_syq(&["rm", "--cwd", ".", "--root", ".", "--src", "victim"]);
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn native_rm_typed_selectors_check_every_type_before_mutation() {
    let t = Tmp::new();
    write(&t.path("file"), b"data");
    write(&t.path("directory/child"), b"data");
    write(&t.path("victim"), b"keep");

    let wrong = native_syq(&[
        "rm",
        "--cwd",
        &t.s(""),
        "--src",
        "victim",
        "--src-non-dir",
        "directory",
    ]);
    assert!(!wrong.status.success());
    assert_eq!(read(&t.path("victim")), b"keep");

    run_native_ok(&[
        "rm",
        "--cwd",
        &t.s(""),
        "--src-non-dir",
        "file",
        "--src-dir",
        "directory",
    ]);
    assert!(!t.path("file").exists());
    assert!(!t.path("directory").exists());
}

#[test]
fn native_rm_accepts_bulk_typed_selectors() {
    let t = Tmp::new();
    write(&t.path("base/file-a"), b"a");
    write(&t.path("base/file-b"), b"b");
    write(&t.path("base/dir-a/child"), b"a");
    write(&t.path("base/dir-b/child"), b"b");

    run_native_ok(&[
        "rm",
        "--cwd",
        &t.s("base"),
        "--src-non-dirs",
        "file-a",
        "file-b",
        "--src-dirs",
        "dir-a",
        "dir-b",
        "--no-progress",
    ]);
    assert!(listing(&t.path("base")).is_empty());
}

#[test]
fn native_rm_overlapping_pinned_selections_are_idempotent() {
    let t = Tmp::new();
    write(&t.path("tree/child/file"), b"data");
    write(&t.path("tree/sibling"), b"data");
    run_native_ok(&[
        "rm",
        "--cwd",
        &t.s(""),
        "--src-dir",
        "tree",
        "--src-dir",
        "tree/child",
    ]);
    assert!(!t.path("tree").exists());
}

#[test]
fn native_rm_overlapping_dry_run_does_not_deduplicate() {
    let t = Tmp::new();
    write(&t.path("tree/child/file"), b"data");
    write(&t.path("tree/sibling"), b"data");

    let output = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "rm",
            "--dry-run",
            "--cwd",
            &t.s(""),
            "--src-dir",
            "tree",
            "--src-dir",
            "tree/child",
        ])
        .run()
        .unwrap();
    assert_output_ok(&output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("would remove 6 entries"), "{stdout}");
    assert!(t.path("tree/child/file").exists());
    assert!(t.path("tree/sibling").exists());
}

#[test]
fn progress_bar_reports_entry_removal() {
    let t = Tmp::new();
    write(&t.path("dst"), b"data");
    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["rm", "--progress", &t.s("dst")])
        .run()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("100%  done  1/1 entries"), "{stderr:?}");
    assert!(!t.path("dst").exists());
}

#[test]
fn native_rm_explicit_tree_and_contents_keep_their_root_distinction() {
    let t = Tmp::new();
    for root in ["native", "contents"] {
        write(&t.path(&format!("{root}/sub/file")), b"data");
    }

    run_native_ok(&["rm", "--cwd", &t.s(""), "--src-dir", "native"]);
    run_native_ok(&["rm", "--cwd", &t.s(""), "--srcs-in", "contents"]);

    assert!(!t.path("native").exists());
    assert!(t.path("contents").is_dir());
    assert!(listing(&t.path("contents")).is_empty());
}

#[test]
fn native_remote_rm_uses_explicit_or_path_selected_helpers() {
    let t = Tmp::new();
    let ssh = fake_ssh(&t);
    for name in ["explicit", "path"] {
        write(&t.path(&format!("{name}/file")), b"remove");
    }
    t.expose_remote_syq();

    let run = |helper: &[&str], selected: &str| {
        let results = t.s(&format!("{selected}-results.ndjson"));
        let output = Command::new(env!("CARGO_BIN_EXE_syq"))
            .arg("rm")
            .args(helper)
            .args(["--on", "fake", "--cwd", &t.s(""), "--src-dir", selected])
            .args(["--results", &results, "-q"])
            .env("FAKE_REMOTE_HOME", t.path("remote-home"))
            .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
            .env("FAKE_RSH_LOG", t.path("rsh.log"))
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", ssh.parent().unwrap().to_string_lossy()),
            )
            .run()
            .expect("run native remote removal");
        assert_output_ok(&output);
        assert!(!t.path(selected).exists());
        let records: Vec<serde_json::Value> = String::from_utf8(read(Path::new(&results)))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(records[0]["mode"], "rm");
        assert_eq!(records[0]["endpoints"][0]["kind"], "ssh");
        assert_eq!(records.last().unwrap()["status"], "success");
    };
    run(&["--syq-path", env!("CARGO_BIN_EXE_syq")], "explicit");
    run(&["--no-bootstrap"], "path");

    let log = fs::read_to_string(t.path("rsh.log")).unwrap();
    assert!(log.contains(env!("CARGO_BIN_EXE_syq")), "{log}");
    assert!(log.contains("syq --server"), "{log}");
}

#[test]
fn native_rm_rejects_conflicting_or_local_remote_helper_selection() {
    let t = Tmp::new();
    write(&t.path("keep"), b"keep");
    let conflict = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "rm",
            "--on",
            "fake",
            "--syq-path",
            "/opt/syq",
            "--no-bootstrap",
            "keep",
        ])
        .run()
        .unwrap();
    assert_eq!(conflict.status.code(), Some(2));
    assert!(stderr_of(&conflict).contains("cannot be used with"));

    let local = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["rm", "--cwd", &t.s(""), "--syq-path", "/opt/syq", "keep"])
        .run()
        .unwrap();
    assert_eq!(local.status.code(), Some(2));
    assert!(stderr_of(&local).contains("only to a remote removal endpoint"));
    assert_eq!(read(&t.path("keep")), b"keep");
}

#[test]
fn native_rm_contents_requires_a_directory() {
    let t = Tmp::new();
    write(&t.path("file"), b"keep");
    let out = native_syq(&["rm", "--cwd", &t.s(""), "--srcs-in", "file"]);
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("must resolve to a directory"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(read(&t.path("file")), b"keep");
}

#[test]
fn native_rm_reports_each_failed_entry_once_without_rescanning_known_failures() {
    let t = Tmp::new();
    write(&t.path("tree/file"), b"keep");
    fs::set_permissions(t.path("tree"), fs::Permissions::from_mode(0o500)).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "rm",
            "--cwd",
            &t.s(""),
            "--src-dir",
            "tree",
            "--results",
            &t.s("results.ndjson"),
            "-q",
        ])
        .run()
        .unwrap();
    fs::set_permissions(t.path("tree"), fs::Permissions::from_mode(0o700)).unwrap();

    assert_eq!(output.status.code(), Some(23), "{}", stderr_of(&output));
    let records: Vec<serde_json::Value> = String::from_utf8(read(&t.path("results.ndjson")))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let failed_paths = records
        .iter()
        .filter(|record| record["type"] == "removal_result" && record["disposition"] == "failed")
        .map(|record| record["path"]["value"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(failed_paths, ["tree/file", "tree"]);
    let terminal = records.last().unwrap();
    assert_eq!(terminal["entries_failed"], 2);
    assert_eq!(terminal["errors"], 2);
}

#[test]
fn native_rm_endpoint_conflicts_have_the_same_local_and_remote_classification() {
    let t = Tmp::new();
    let ssh = fake_ssh(&t);
    fs::create_dir_all(t.path("remote-bin")).unwrap();

    for (name, remote) in [("local-file", false), ("remote-file", true)] {
        write(&t.path(name), b"keep");
        let results = t.s(&format!("{name}.ndjson"));
        let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
        command.args([
            "rm",
            "--cwd",
            &t.s(""),
            "--src-dir",
            name,
            "--results",
            &results,
            "-q",
        ]);
        if remote {
            command.args(["--on", "fake", "--syq-path", env!("CARGO_BIN_EXE_syq")]);
            command
                .env("FAKE_REMOTE_HOME", t.path("remote-home"))
                .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
                .env("FAKE_RSH_LOG", t.path("rsh.log"))
                .env(
                    "PATH",
                    format!("{}:/usr/bin:/bin", ssh.parent().unwrap().to_string_lossy()),
                );
        }

        let output = command.run().unwrap();
        assert_eq!(output.status.code(), Some(1), "{}", stderr_of(&output));
        assert_eq!(read(&t.path(name)), b"keep");
        let records: Vec<serde_json::Value> = String::from_utf8(read(Path::new(&results)))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let error = records
            .iter()
            .find(|record| record["type"] == "error")
            .unwrap();
        assert_eq!(error["class"], "conflict", "{name}: {error}");
        assert!(error.get("os_kind").is_none(), "{name}: {error}");
    }
}

#[test]
fn native_rm_double_verbose_logs_base_symlink_hops_and_final_identity() {
    use std::os::unix::fs::symlink;

    let t = Tmp::new();
    write(&t.path("real/file"), b"keep");
    symlink("real", t.path("link")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "rm",
            "--dry-run",
            "-vv",
            "--cwd",
            &t.s(""),
            "--follow",
            "--src-non-dir",
            "link/file",
        ])
        .run()
        .unwrap();
    assert_output_ok(&output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--cwd") && stdout.contains("pinned as"),
        "{stdout}"
    );
    assert!(
        stdout.contains("symlink") && stdout.contains("->"),
        "{stdout}"
    );
    assert!(stdout.contains("resolved to non-directory"), "{stdout}");
    assert_eq!(read(&t.path("real/file")), b"keep");
}

#[test]
fn native_rm_follows_multiple_parent_symlink_hops() {
    use std::os::unix::fs::symlink;
    for follow in ["--follow", "--follow-src"] {
        let t = Tmp::new();
        write(&t.path("real/file"), b"remove");
        symlink("real", t.path("link-b")).unwrap();
        symlink("link-b", t.path("link-a")).unwrap();
        run_native_ok(&["rm", "--root", &t.s(""), follow, "--src", "link-a/file"]);
        assert!(!t.path("real/file").exists());
        assert_eq!(
            fs::read_link(t.path("link-a")).unwrap(),
            Path::new("link-b")
        );
        assert_eq!(fs::read_link(t.path("link-b")).unwrap(), Path::new("real"));
    }
}

#[test]
fn native_rm_named_directories_are_rejected_before_any_mutation_locally_and_remotely() {
    for remote in [false, true] {
        for dry_run in [false, true] {
            for selector in [None, Some("--src"), Some("--srcs")] {
                let t = Tmp::new();
                write(&t.path("tree/nested/child"), b"keep");
                write(&t.path("victim"), b"keep");
                let ssh = fake_ssh(&t);
                let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
                command.args(["rm", "--cwd", &t.s(""), "--src", "victim"]);
                if remote {
                    command.args(["--on", "fake", "--syq-path", env!("CARGO_BIN_EXE_syq")]);
                    command.env(
                        "PATH",
                        format!("{}:/usr/bin:/bin", ssh.parent().unwrap().display()),
                    );
                }
                if dry_run {
                    command.arg("--dry-run");
                }
                if let Some(selector) = selector {
                    command.arg(selector);
                }
                let out = command.arg("tree").run().unwrap();
                assert!(
                    !out.status.success(),
                    "remote={remote}, dry_run={dry_run}, selector={selector:?}"
                );
                assert!(stderr_of(&out).contains("--src-dir"), "{}", stderr_of(&out));
                assert_eq!(read(&t.path("tree/nested/child")), b"keep");
                assert_eq!(read(&t.path("victim")), b"keep");
            }
        }
    }
}

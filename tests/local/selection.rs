use super::*;

#[test]
fn native_hyphen_prefixed_selector_values_require_equals() {
    let t = Tmp::new();
    write(&t.path("base/-/file"), b"literal hyphen directory");
    write(&t.path("base/foo"), b"ordinary source");

    let option_looking = native_syq(&[
        "cp",
        "--cwd",
        &t.s("base"),
        "--src-dir",
        "--dry-run",
        "--into",
        &t.s("option-looking"),
    ]);
    assert!(!option_looking.status.success());
    assert!(
        stderr_of(&option_looking).contains("a value is required for '--src-dir <DIR>'"),
        "{}",
        stderr_of(&option_looking)
    );
    assert!(!t.path("option-looking").exists());

    let detached = native_syq(&[
        "cp",
        "--cwd",
        &t.s("base"),
        "--src-dir",
        "-",
        "--into",
        &t.s("detached"),
    ]);
    assert!(!detached.status.success());
    assert!(
        stderr_of(&detached).contains("use --src-dir=-"),
        "{}",
        stderr_of(&detached)
    );
    assert!(!t.path("detached").exists());

    for (selector_args, destination) in [
        (&["--srcs", "foo", "-"][..], "detached-bulk"),
        (&["--srcs=foo", "-"][..], "detached-inline-bulk"),
    ] {
        let base = t.s("base");
        let destination_path = t.s(destination);
        let mut args = vec!["cp", "--cwd", base.as_str()];
        args.extend_from_slice(selector_args);
        args.extend_from_slice(&["--into", destination_path.as_str()]);
        let detached_bulk = native_syq(&args);
        assert!(!detached_bulk.status.success());
        assert!(
            stderr_of(&detached_bulk).contains("use --srcs=-"),
            "{}",
            stderr_of(&detached_bulk)
        );
        assert!(!t.path(destination).exists());
    }

    run_native_ok(&[
        "cp",
        "--cwd",
        &t.s("base"),
        "--src-dir=-",
        "--into",
        &t.s("attached"),
    ]);
    assert_eq!(
        read(&t.path("attached/-/file")),
        b"literal hyphen directory"
    );

    run_native_ok(&[
        "cp",
        "--cwd",
        &t.s("base"),
        "--srcs",
        "foo",
        "--srcs=-",
        "--into",
        &t.s("attached-bulk"),
    ]);
    assert_eq!(read(&t.path("attached-bulk/foo")), b"ordinary source");
    assert_eq!(
        read(&t.path("attached-bulk/-/file")),
        b"literal hyphen directory"
    );
}

#[test]
fn native_copy_typed_selectors_are_source_preconditions() {
    use std::os::unix::fs::symlink;

    let t = Tmp::new();
    write(&t.path("src/file"), b"file");
    write(&t.path("src/dir/child"), b"child");
    symlink("dir", t.path("src/link")).unwrap();

    run_native_ok(&[
        "cp",
        "--cwd",
        &t.s("src"),
        "--src-non-dir",
        "file",
        "--src-dir",
        "dir",
        "--src-non-dir",
        "link",
        "--into-new",
        &t.s("copied"),
    ]);
    assert_eq!(read(&t.path("copied/file")), b"file");
    assert_eq!(read(&t.path("copied/dir/child")), b"child");
    assert_eq!(
        fs::read_link(t.path("copied/link")).unwrap(),
        Path::new("dir")
    );

    run_native_ok(&[
        "cp",
        "--src-non-dir",
        &t.s("src/file"),
        "--as-new",
        &t.s("exact"),
    ]);
    assert_eq!(read(&t.path("exact")), b"file");

    let wrong_directory = native_syq(&[
        "cp",
        "--src-dir",
        &t.s("src/file"),
        "--into-new",
        &t.s("wrong-directory"),
    ]);
    assert!(!wrong_directory.status.success());
    assert!(stderr_of(&wrong_directory).contains("--src-dir selector"));
    assert!(!t.path("wrong-directory").exists());

    let followed_link = native_syq(&[
        "cp",
        "--src-dir",
        &t.s("src/link"),
        "--into-new",
        &t.s("followed-link"),
    ]);
    assert!(!followed_link.status.success());
    assert!(stderr_of(&followed_link).contains("pass --follow"));
    assert!(!t.path("followed-link").exists());

    run_native_ok(&[
        "cp",
        "--follow",
        "--src-dir",
        &t.s("src/link"),
        "--into-new",
        &t.s("followed-link"),
    ]);
    assert_eq!(read(&t.path("followed-link/link/child")), b"child");
}

#[test]
fn native_cp_with_prune_checks_all_typed_sources_before_mutation() {
    let t = Tmp::new();
    write(&t.path("src/good"), b"new");
    write(&t.path("src/not-a-file/child"), b"child");
    write(&t.path("dst/good"), b"old");
    write(&t.path("dst/extra"), b"keep");

    let output = native_syq(&[
        "cp",
        "--prune",
        "--src-non-dir",
        &t.s("src/good"),
        "--src-non-dir",
        &t.s("src/not-a-file"),
        "--into-existing",
        &t.s("dst"),
    ]);
    assert!(!output.status.success());
    assert!(stderr_of(&output).contains("--src-non-dir selector"));
    assert_eq!(read(&t.path("dst/good")), b"old");
    assert_eq!(read(&t.path("dst/extra")), b"keep");
}

#[test]
fn native_filters_apply_to_copy_and_protect_pruned_paths() {
    let t = Tmp::new();
    write(&t.path("src/keep"), b"keep");
    write(&t.path("src/discard.tmp"), b"new-discard");
    write(&t.path("src/important.tmp"), b"important");

    run_native_ok(&[
        "cp",
        "--ignore",
        "*.tmp",
        "--srcs-in",
        &t.s("src"),
        "--into",
        &t.s("copied"),
    ]);
    assert_eq!(listing(&t.path("copied")), ["keep"]);

    write(&t.path("patterns"), b"*.tmp\n");
    write(&t.path("pruned/discard.tmp"), b"protected-old-copy");
    write(&t.path("pruned/extra"), b"remove");
    run_native_ok(&[
        "cp",
        "--prune",
        "--ignore-from",
        &t.s("patterns"),
        "--ignore",
        "!important.tmp",
        "--srcs-in",
        &t.s("src"),
        "--into-existing",
        &t.s("pruned"),
    ]);
    assert_eq!(read(&t.path("pruned/keep")), b"keep");
    assert_eq!(read(&t.path("pruned/important.tmp")), b"important");
    assert_eq!(read(&t.path("pruned/discard.tmp")), b"protected-old-copy");
    assert!(!t.path("pruned/extra").exists());
}

#[test]
fn native_preserve_policy_controls_permissions_and_special_files() {
    let t = Tmp::new();
    write(&t.path("src/file"), b"new");
    fs::set_permissions(t.path("src/file"), fs::Permissions::from_mode(0o751)).unwrap();
    mkfifo(&t.path("src/fifo"));
    write(&t.path("dst/file"), b"old");
    fs::set_permissions(t.path("dst/file"), fs::Permissions::from_mode(0o600)).unwrap();
    set_mtime(&t.path("src/file"), 1_700_000_000);
    set_mtime(&t.path("dst/file"), 1_600_000_000);

    run_native_ok(&[
        "cp",
        "--preserve=permissions,specials",
        "--srcs-in",
        &t.s("src"),
        "--into-existing",
        &t.s("dst"),
    ]);

    assert_eq!(read(&t.path("dst/file")), b"new");
    assert_eq!(
        fs::metadata(t.path("dst/file")).unwrap().mode() & 0o777,
        0o751
    );
    assert!(fs::symlink_metadata(t.path("dst/fifo"))
        .unwrap()
        .file_type()
        .is_fifo());
}

#[test]
fn native_copy_preserves_non_utf8_selector_bytes() {
    if !filesystem_accepts_non_utf8_names() {
        eprintln!("skipping: this filesystem rejects file names that are not valid UTF-8");
        return;
    }
    let t = Tmp::new();
    let mut name = b"non-utf8-".to_vec();
    name.push(0xff);
    let name = std::ffi::OsString::from_vec(name);
    let source = t.path("").join(&name);
    write(Path::new(&source), b"raw path");

    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .arg("cp")
        .arg(&source)
        .arg("--as-new")
        .arg(t.path("copied"))
        .arg("-q")
        .run()
        .unwrap();
    assert_output_ok(&out);
    assert_eq!(read(&t.path("copied")), b"raw path");

    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .arg("rm")
        .arg("--cwd")
        .arg(t.path(""))
        .arg("--src")
        .arg(&name)
        .arg("-q")
        .run()
        .unwrap();
    assert_output_ok(&out);
    assert!(!Path::new(&source).exists());
}

#[test]
fn native_cp_with_prune_removes_only_target_extras_after_copy() {
    let t = Tmp::new();
    write(&t.path("src/keep"), b"new content");
    write(&t.path("dst/keep"), b"old");
    write(&t.path("dst/extra"), b"extra");

    run_native_ok(&[
        "cp",
        "--prune",
        "--srcs-in",
        &t.s("src"),
        "--into-existing",
        &t.s("dst"),
    ]);
    assert_eq!(read(&t.path("src/keep")), b"new content");
    assert_eq!(read(&t.path("dst/keep")), b"new content");
    assert!(!t.path("dst/extra").exists());
}

#[test]
fn dir_into_existing_dir() {
    let t = Tmp::new();
    make_tree(&t.path("src"));
    fs::create_dir(t.path("dst")).unwrap();
    run_ok(&["-a", &t.s("src"), &t.s("dst")]);
    assert_same_tree(&t.path("src"), &t.path("dst/src"));
}

#[test]
fn single_file_into_existing_dir() {
    let t = Tmp::new();
    write(&t.path("src/f.txt"), b"data");
    fs::create_dir(t.path("dst")).unwrap();
    run_ok(&["-a", &t.s("src/f.txt"), &t.s("dst")]);
    assert_eq!(read(&t.path("dst/f.txt")), b"data");
    run_ok(&["-a", &t.s("src/f.txt"), &t.s("dst2/")]);
    assert_eq!(read(&t.path("dst2/f.txt")), b"data");
}

#[test]
fn dry_run_creates_nothing() {
    let t = Tmp::new();
    make_tree(&t.path("src"));
    let out = run_ok(&["-an", &t.s("src"), &t.s("dst")]);
    assert!(
        !t.path("dst").exists(),
        "dry run must not create the destination"
    );
    assert!(out.contains("syq: dry-run summary"), "{out}");
    assert!(out.contains("regular files"), "{out}");
    assert!(out.contains("directories"), "{out}");
    assert!(out.contains("symlinks"), "{out}");
    assert!(out.contains("special file"), "{out}");
    assert!(out.contains("logical data:"), "{out}");
}

#[test]
fn dry_run_does_not_apply_metadata_repairs() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"same");
    write(&t.path("dst/f"), b"same");
    fs::set_permissions(t.path("src/f"), fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(t.path("dst/f"), fs::Permissions::from_mode(0o644)).unwrap();
    set_mtime(&t.path("src/f"), 1_600_000_000);
    set_mtime(&t.path("dst/f"), 1_600_000_000);
    set_mtime(&t.path("src"), 1_600_000_100);
    set_mtime(&t.path("dst"), 1_600_000_100);

    let out = run_ok(&["-anv", &t.s("src/"), &t.s("dst")]);
    assert_eq!(
        fs::symlink_metadata(t.path("dst/f")).unwrap().mode() & 0o777,
        0o644,
        "dry run changed destination permissions\n{out}"
    );
    assert!(out.contains("changes: 1 metadata-only entry"), "{out}");
    assert!(
        out.contains(&format!(
            "update metadata {} (requested file metadata differs)",
            t.s("dst/f")
        )),
        "{out}"
    );
    assert!(
        out.contains("4 B in 1 file with unchanged content"),
        "{out}"
    );

    run_ok(&["-a", &t.s("src/"), &t.s("dst")]);
    assert_eq!(
        fs::symlink_metadata(t.path("dst/f")).unwrap().mode() & 0o777,
        0o600,
        "the corresponding real run must still repair metadata"
    );
}

#[test]
fn dry_run_rejects_bare_directory_into_existing_file() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"source");
    write(&t.path("destination"), b"keep me");

    let skipped = syq(&["-n", &t.s("src"), &t.s("destination")]);
    assert!(skipped.status.success(), "{}", stderr_of(&skipped));
    assert!(stderr_of(&skipped).contains("skipping directory"));

    let existing_dry = syq(&["-an", "--existing", &t.s("src"), &t.s("destination")]);
    assert!(
        existing_dry.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&existing_dry.stdout),
        stderr_of(&existing_dry)
    );
    assert!(
        String::from_utf8_lossy(&existing_dry.stdout).contains("changes: none"),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&existing_dry.stdout),
        stderr_of(&existing_dry)
    );
    assert_eq!(read(&t.path("destination")), b"keep me");

    let existing_actual = syq(&["-a", "--existing", &t.s("src"), &t.s("destination")]);
    assert!(
        existing_actual.status.success(),
        "{}",
        stderr_of(&existing_actual)
    );
    assert_eq!(read(&t.path("destination")), b"keep me");

    let dry = syq(&["-an", &t.s("src"), &t.s("destination")]);
    assert!(!dry.status.success());
    assert!(
        stderr_of(&dry).contains(&format!(
            "destination {} is not a directory; cannot place directory {} inside it",
            t.s("destination"),
            t.s("src")
        )),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&dry.stdout),
        stderr_of(&dry)
    );
    assert!(
        !String::from_utf8_lossy(&dry.stdout).contains("syq: dry-run summary"),
        "a rejected mapping must not print a successful summary"
    );
    assert_eq!(read(&t.path("destination")), b"keep me");

    let actual = syq(&["-a", &t.s("src"), &t.s("destination")]);
    assert_eq!(actual.status.code(), Some(23), "{}", stderr_of(&actual));
    assert_eq!(read(&t.path("destination")), b"keep me");
}

#[test]
fn no_perms_preserves_existing_dest_mode() {
    let t = Tmp::new();
    write(&t.path("src"), b"x");
    fs::copy(t.path("src"), t.path("dst")).unwrap();
    fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o666)).unwrap();
    write(&t.path("src"), b"y"); // change content so it transfers
    set_mtime(&t.path("dst"), 1_000_000_000);
    set_mtime(&t.path("src"), 1_000_000_500); // newer -> not skipped
    run_ok(&["-t", &t.s("src"), &t.s("dst")]); // no -p
    let m = fs::symlink_metadata(t.path("dst")).unwrap().mode() & 0o777;
    assert_eq!(m, 0o666, "existing dest mode must be preserved without -p");
    assert_eq!(read(&t.path("dst")), b"y");
}

/// Tree for the --syq-ignore tests.
fn make_ignore_tree(root: &Path) {
    for f in [
        "hello.txt",
        "x.o",
        "a/y.o",
        "a/b/z.jpg",
        "a/pic.jpg",
        "node_modules/x/m.js",
        "a/node_modules/n.js",
        "build/out",
        "a/build/out2",
        "logs/l1",
        "logs/keep/k",
    ] {
        write(&root.join(f), f.as_bytes());
    }
    fs::create_dir_all(root.join("empty")).unwrap();
}

#[test]
fn native_cp_with_prune_matches_rsync_delete() {
    let t = Tmp::new();
    write(&t.path("src/keep"), b"source");
    for destination in ["rsync", "native"] {
        write(&t.path(&format!("{destination}/keep")), b"old");
        write(&t.path(&format!("{destination}/extra")), b"extra");
    }

    run_ok(&["-rlt", "--delete", &t.s("src/"), &t.s("rsync/")]);
    run_native_ok(&[
        "cp",
        "--prune",
        "--srcs-in",
        &t.s("src"),
        "--into-existing",
        &t.s("native"),
    ]);

    assert_eq!(listing(&t.path("native")), listing(&t.path("rsync")));
    assert_eq!(read(&t.path("native/keep")), b"source");
}

#[test]
fn native_selectors_support_bulk_mixing_and_late_modifiers() {
    let t = Tmp::new();
    write(&t.path("sources/a"), b"a");
    write(&t.path("sources/tree/f"), b"tree");
    write(&t.path("sources/contents/b"), b"b");
    write(&t.path("sources/file-a"), b"file-a");
    write(&t.path("sources/file-b"), b"file-b");
    write(&t.path("sources/dir-a/c"), b"dir-a");
    write(&t.path("sources/dir-b/d"), b"dir-b");
    write(&t.path("sources/z"), b"z");

    run_native_ok(&[
        "cp",
        "a",
        "--srcs",
        "tree",
        "--srcs-in",
        "contents",
        "--src-non-dirs",
        "file-a",
        "file-b",
        "--src-dirs",
        "dir-a",
        "dir-b",
        "--src",
        "z",
        "--cwd",
        &t.s("sources"),
        "--performance-tuning",
        "workers=1",
        "--into",
        &t.s("dest"),
    ]);

    assert_eq!(
        listing(&t.path("dest")),
        [
            "a", "b", "dir-a", "dir-a/c", "dir-b", "dir-b/d", "file-a", "file-b", "tree", "tree/f",
            "z",
        ]
    );
}

#[test]
fn native_cp_with_prune_keeps_placement_siblings_and_honors_max_delete() {
    let t = Tmp::new();
    write(&t.path("source/tree/keep"), b"keep");
    write(&t.path("named/tree/keep"), b"old");
    write(&t.path("named/tree/extra"), b"extra");
    write(&t.path("named/outside"), b"outside");
    run_native_ok(&[
        "cp",
        "--prune",
        "--src",
        &t.s("source/tree"),
        "--into-existing",
        &t.s("named"),
    ]);
    assert!(!t.path("named/tree/extra").exists());
    assert!(t.path("named/outside").is_file());

    write(&t.path("contents/extra"), b"extra");
    let refused = native_syq(&[
        "cp",
        "--prune",
        "--max-delete",
        "0",
        "--srcs-in",
        &t.s("source/tree"),
        "--into-existing",
        &t.s("contents"),
    ]);
    assert_eq!(refused.status.code(), Some(25));
    assert!(t.path("contents/extra").is_file());
}

#[test]
fn native_as_file_over_directory_fails_the_same_in_dry_run_and_execution() {
    let t = Tmp::new();
    write(&t.path("source"), b"new");
    write(&t.path("target/keep"), b"keep");

    for dry_run in [true, false] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
        command.args([
            "cp",
            "--src",
            &t.s("source"),
            "--as-existing",
            &t.s("target"),
        ]);
        if dry_run {
            command.arg("--dry-run");
        }
        let output = command.run().unwrap();
        assert!(!output.status.success(), "dry_run={dry_run}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("existing directory"), "{stderr}");
        assert_eq!(read(&t.path("target/keep")), b"keep");
        assert!(partial_files(&t.0).is_empty());
    }
}

#[test]
fn ignore_patterns_prune_dirs_and_files() {
    let t = Tmp::new();
    make_ignore_tree(&t.path("src"));
    // `node_modules` at any depth, `*.o` anywhere, `/build` only at the root.
    run_ok(&[
        "-a",
        "--syq-ignore",
        "node_modules",
        "--syq-ignore",
        "*.o",
        "--syq-ignore",
        "/build",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert_eq!(
        listing(&t.path("dst")),
        [
            "a",
            "a/b",
            "a/b/z.jpg",
            "a/build",
            "a/build/out2",
            "a/pic.jpg",
            "empty",
            "hello.txt",
            "logs",
            "logs/keep",
            "logs/keep/k",
            "logs/l1",
        ]
    );
}

#[test]
fn ignore_only_idiom_and_empty_dirs() {
    let t = Tmp::new();
    make_ignore_tree(&t.path("src"));
    // The gitignore "only *.jpg" idiom: directories are still all created.
    run_ok(&[
        "-a",
        "--syq-ignore",
        "*",
        "--syq-ignore",
        "!*/",
        "--syq-ignore",
        "!*.jpg",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    let l = listing(&t.path("dst"));
    assert!(l.contains(&"a/b/z.jpg".to_string()));
    assert!(l.contains(&"a/pic.jpg".to_string()));
    assert!(l.contains(&"empty".to_string()));
    assert!(l.contains(&"node_modules/x".to_string()));
    assert!(!l
        .iter()
        .any(|p| p.ends_with(".o") || p.ends_with(".txt") || p.ends_with(".js")));
    // Without any pattern, empty dirs are copied too.
    run_ok(&["-a", &t.s("src/"), &t.s("dst2")]);
    assert!(t.path("dst2/empty").is_dir());
}

#[test]
fn ignore_from_file_and_later_negation_wins() {
    let t = Tmp::new();
    make_ignore_tree(&t.path("src"));
    write(&t.path("pats"), b"# comment\nnode_modules\n\n*.o\r\n");
    run_ok(&[
        "-a",
        "--syq-ignore-from",
        &t.s("pats"),
        "--syq-ignore",
        "!x.o",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    let l = listing(&t.path("dst"));
    assert!(
        l.contains(&"x.o".to_string()),
        "later --syq-ignore '!x.o' must override file"
    );
    assert!(!l.contains(&"a/y.o".to_string()));
    assert!(!l.iter().any(|p| p.contains("node_modules")));
    // And the other order: the file's `*.o` comes last, so x.o stays ignored.
    run_ok(&[
        "-a",
        "--syq-ignore",
        "!x.o",
        "--syq-ignore-from",
        &t.s("pats"),
        &t.s("src/"),
        &t.s("dst2"),
    ]);
    assert!(!t.path("dst2/x.o").exists());
    // Missing file is an error.
    let out = syq(&[
        "-a",
        "--syq-ignore-from",
        &t.s("nope"),
        &t.s("src/"),
        &t.s("dst3"),
    ]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--syq-ignore-from"));
}

#[test]
fn ignore_applies_per_source_root_and_dry_run() {
    let t = Tmp::new();
    make_ignore_tree(&t.path("s1"));
    make_ignore_tree(&t.path("s2"));
    fs::create_dir(t.path("dst")).unwrap();
    // `/build` is anchored at each source's root, not the destination.
    run_ok(&[
        "-a",
        "--syq-ignore",
        "/build",
        &t.s("s1"),
        &t.s("s2"),
        &t.s("dst"),
    ]);
    assert!(!t.path("dst/s1/build").exists());
    assert!(!t.path("dst/s2/build").exists());
    assert!(t.path("dst/s1/a/build/out2").is_file());
    // Dry run with the root itself matching a pattern: the root is never ignored.
    let out = run_ok(&[
        "-an",
        "--syq-ignore",
        "s1",
        "--syq-ignore",
        "*.o",
        &t.s("s1"),
        &t.s("dst2"),
    ]);
    assert!(!t.path("dst2").exists());
    assert!(out.contains("in 9 files needing content work"), "{out}");
}

#[test]
fn ignore_reinclude_subdir_idiom() {
    let t = Tmp::new();
    make_ignore_tree(&t.path("src"));
    // Everything directly under logs/ except the keep/ directory (git idiom).
    run_ok(&[
        "-a",
        "--syq-ignore",
        "logs/*",
        "--syq-ignore",
        "!logs/keep/",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert!(t.path("dst/logs/keep/k").is_file());
    assert!(!t.path("dst/logs/l1").exists());
}

#[test]
fn ignore_from_strips_bom_and_hyphen_patterns_work() {
    let t = Tmp::new();
    make_ignore_tree(&t.path("src"));
    write(&t.path("-dash"), b"d");
    write(&t.path("src/-secret"), b"s");
    write(&t.path("pats"), "\u{feff}*.o\n".as_bytes());
    run_ok(&[
        "-a",
        "--syq-ignore-from",
        &t.s("pats"),
        "--syq-ignore",
        "-secret",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert!(
        !t.path("dst/x.o").exists(),
        "BOM must not hide the first rule"
    );
    assert!(!t.path("dst/-secret").exists());
    assert!(t.path("dst/hello.txt").is_file());
}

#[test]
fn delete_removes_extras_and_protects_ignored() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"a");
    write(&t.path("src/d/b"), b"b");
    write(&t.path("dst/a"), b"old");
    write(&t.path("dst/d/b"), b"b");
    write(&t.path("dst/c"), b"extra");
    write(&t.path("dst/extra/x/y"), b"extra");
    write(&t.path("dst/keep/k.log"), b"protected");
    write(&t.path("dst/keep/gone"), b"not protected");
    std::os::unix::fs::symlink("nowhere", t.path("dst/dangling")).unwrap();

    // Dry run: everything listed, nothing removed.
    let out = syq(&[
        "-a",
        "-n",
        "-v",
        "--delete",
        "--syq-ignore",
        "*.log",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert!(out.status.success());
    let so = String::from_utf8_lossy(&out.stdout);
    for l in [
        "delete c (destination only)",
        "delete extra/x/y (destination only)",
        "delete extra/x/ (destination only)",
        "delete extra/ (destination only)",
        "delete keep/gone (destination only)",
        "delete dangling (destination only)",
    ] {
        assert!(so.contains(l), "missing {l:?} in {so}");
    }
    assert!(!so.contains("k.log"), "{so}");
    assert!(!so.contains("delete keep/ (destination only)"), "{so}");
    assert!(
        so.contains("deletions: 6 entries planned after a successful copy"),
        "{so}"
    );
    assert!(
        stderr_of(&out).contains("not deleting keep/"),
        "{}",
        stderr_of(&out)
    );
    assert!(t.path("dst/c").exists() && t.path("dst/extra/x/y").exists());

    let out = syq(&[
        "-a",
        "-v",
        "--delete",
        "--syq-ignore",
        "*.log",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert!(out.status.success(), "{}", stderr_of(&out));
    assert_eq!(
        listing(&t.path("dst")),
        ["a", "d", "d/b", "keep", "keep/k.log"]
    );
    assert_eq!(read(&t.path("dst/a")), b"a");
    let so = String::from_utf8_lossy(&out.stdout);
    assert!(so.contains("6 deleted"), "{so}");
    // keep/ stays because it holds a protected file: reported, not an error.
    let se = stderr_of(&out);
    assert!(se.contains("not deleting keep/"), "{se}");
}

#[test]
fn delete_is_skipped_when_the_source_scan_has_errors() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"a");
    write(&t.path("src/locked/inner"), b"x");
    write(&t.path("dst/extra"), b"extra");
    fs::set_permissions(t.path("src/locked"), fs::Permissions::from_mode(0o000)).unwrap();
    let out = syq(&["-a", "--delete", &t.s("src/"), &t.s("dst")]);
    assert_eq!(out.status.code(), Some(23));
    assert!(t.path("dst/extra").exists(), "nothing may be deleted");
    assert!(
        stderr_of(&out).contains("skipping deletions"),
        "{}",
        stderr_of(&out)
    );
}

#[test]
fn ignore_existing_and_existing() {
    let t = Tmp::new();
    write(&t.path("src/have"), b"new content");
    write(&t.path("src/new"), b"n");
    write(&t.path("src/sub/deep"), b"d");
    write(&t.path("dst/have"), b"old content");
    set_mtime(&t.path("src/have"), 2000);
    set_mtime(&t.path("dst/have"), 1000);

    let so = run_ok(&["-a", "--ignore-existing", &t.s("src/"), &t.s("dst")]);
    assert_eq!(transferred(&so), 2);
    assert_eq!(read(&t.path("dst/have")), b"old content");
    assert!(t.path("dst/new").is_file() && t.path("dst/sub/deep").is_file());

    let t = Tmp::new();
    write(&t.path("src/have"), b"new content");
    write(&t.path("src/new"), b"n");
    write(&t.path("src/sub/deep"), b"d");
    write(&t.path("dst/have"), b"old content");
    set_mtime(&t.path("src/have"), 2000);
    set_mtime(&t.path("dst/have"), 1000);
    let so = run_ok(&["-a", "--existing", &t.s("src/"), &t.s("dst")]);
    assert_eq!(transferred(&so), 1);
    assert_eq!(read(&t.path("dst/have")), b"new content");
    assert_eq!(listing(&t.path("dst")), ["have"]);
    // --existing --delete still removes extras.
    write(&t.path("dst/extra"), b"e");
    run_ok(&["-a", "--existing", "--delete", &t.s("src/"), &t.s("dst")]);
    assert_eq!(listing(&t.path("dst")), ["have"]);
}

#[test]
fn size_limits_filter_files_and_protect_them_from_delete() {
    let t = Tmp::new();
    write(&t.path("src/small"), &[0u8; 10]);
    write(&t.path("src/mid"), &[0u8; 2048]);
    write(&t.path("src/big"), &[0u8; 8192]);
    write(&t.path("dst/big"), b"stays");
    let so = run_ok(&[
        "-a",
        "--delete",
        "--max-size",
        "4K",
        "--min-size",
        "1K",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert_eq!(transferred(&so), 1);
    assert_eq!(listing(&t.path("dst")), ["big", "mid"]);
    assert_eq!(read(&t.path("dst/big")), b"stays");
}

#[test]
fn files_from_copies_listed_paths_with_their_parents() {
    let t = Tmp::new();
    for f in ["a/1", "a/2", "b/c/3", "b/c/4", "d/5", "top"] {
        write(&t.path("src").join(f), f.as_bytes());
    }
    write(&t.path("list"), b"a/1\n\n./b/c/3\n/top\nb/c/\nmissing/x\n");
    let out = syq(&["-a", "--files-from", &t.s("list"), &t.s("src"), &t.s("dst")]);
    // The missing entry is an error but the rest is copied.
    assert_eq!(out.status.code(), Some(23), "{}", stderr_of(&out));
    assert!(stderr_of(&out).contains("missing/x"));
    // b/c is listed as a directory but -r wasn't given explicitly: no contents
    // beyond what the list names.
    assert_eq!(
        listing(&t.path("dst")),
        ["a", "a/1", "b", "b/c", "b/c/3", "top"]
    );
    assert_eq!(read(&t.path("dst/b/c/3")), b"b/c/3");

    // Explicit -r walks listed directories; --from0 takes NUL separators.
    write(&t.path("list0"), b"b/c\0d\0");
    run_ok(&[
        "-a",
        "-r",
        "--files-from",
        &t.s("list0"),
        "--from0",
        &t.s("src/"),
        &t.s("dst2"),
    ]);
    assert_eq!(
        listing(&t.path("dst2")),
        ["b", "b/c", "b/c/3", "b/c/4", "d", "d/5"]
    );

    // Alternate spellings of one path are one path: no double scheduling.
    write(&t.path("list-dup"), b"a/1\na//1\n./a/./1/\n");
    let so = run_ok(&[
        "-a",
        "--files-from",
        &t.s("list-dup"),
        &t.s("src"),
        &t.s("dst4"),
    ]);
    assert_eq!(transferred(&so), 1);
    assert_eq!(listing(&t.path("dst4")), ["a", "a/1"]);

    // A `..` component is rejected before anything happens.
    write(&t.path("bad"), b"../etc\n");
    let out = syq(&["-a", "--files-from", &t.s("bad"), &t.s("src"), &t.s("dst3")]);
    assert!(!out.status.success());
    assert!(!t.path("dst3").exists());
}

#[test]
fn delete_never_removes_paths_the_source_has_but_skips() {
    let t = Tmp::new();
    write(&t.path("src/plain"), b"p");
    write(&t.path("src/hard"), b"h");
    fs::create_dir_all(t.path("dst")).unwrap();
    fs::hard_link(t.path("src/hard"), t.path("dst/hard")).unwrap();
    std::os::unix::fs::symlink("plain", t.path("src/link")).unwrap();
    std::os::unix::fs::symlink("plain", t.path("dst/link")).unwrap();
    write(&t.path("dst/extra"), b"x");
    // No -l: the symlink is skipped, but it is the source's, so it stays.
    // The hardlinked file is "the same file" and skipped, and stays.
    let so = run_ok(&["-rt", "--delete", &t.s("src/"), &t.s("dst")]);
    assert_eq!(listing(&t.path("dst")), ["hard", "link", "plain"]);
    // Skipped files are not reported as directories; the existing
    // destination root means nothing was created.
    assert!(so.contains(", 0 dirs created"), "{so}");
    write(&t.path("src2/big"), b"bb");
    let so = run_ok(&["-a", "--max-size", "1", &t.s("src2/"), &t.s("dst2")]);
    assert!(
        so.contains("transferred 0 files") && so.contains(", 1 dirs created"),
        "{so}"
    );
}

#[test]
fn existing_never_creates_the_destination_root() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"f");
    let so = run_ok(&["-a", "--existing", &t.s("src/"), &t.s("dst/")]);
    assert!(!t.path("dst").exists(), "{so}");
    write(&t.path("src2/g"), b"g");
    let so = run_ok(&["-a", "--existing", &t.s("src"), &t.s("src2"), &t.s("dst2")]);
    assert!(!t.path("dst2").exists(), "{so}");
}

#[test]
fn existing_dry_run_reports_no_missing_directory_changes() {
    let t = Tmp::new();
    write(&t.path("src/there/f"), b"f");
    write(&t.path("src/missing/g"), b"g");
    fs::create_dir_all(t.path("dst/there")).unwrap();
    let so = run_ok(&["-a", "-n", "-v", "--existing", &t.s("src/"), &t.s("dst")]);
    assert!(!so.contains("create directory"), "{so}");
    assert!(!so.contains(&t.s("dst/missing")), "{so}");
    assert!(!so.contains("there/f"), "--existing creates no files: {so}");
}

#[test]
fn existing_leaves_a_file_where_a_source_directory_would_go() {
    let t = Tmp::new();
    write(&t.path("src/d/inner"), b"i");
    write(&t.path("dst/d"), b"a file, not a directory");
    let so = run_ok(&["-a", "--existing", &t.s("src/"), &t.s("dst")]);
    assert_eq!(read(&t.path("dst/d")), b"a file, not a directory");
    assert_eq!(listing(&t.path("dst")), ["d"]);
    let so2 = run_ok(&["-a", "-n", "-v", "--existing", &t.s("src/"), &t.s("dst")]);
    assert!(!so2.contains("dst/d/"), "{so2}\n{so}");
}

#[test]
fn files_from_creates_listed_and_implied_dirs_without_r() {
    let t = Tmp::new();
    write(&t.path("src/a/1"), b"1");
    fs::create_dir_all(t.path("src/b/inner")).unwrap();
    fs::set_permissions(t.path("src/a"), fs::Permissions::from_mode(0o750)).unwrap();
    fs::set_permissions(t.path("src/b"), fs::Permissions::from_mode(0o710)).unwrap();
    write(&t.path("list"), b"a/1\nb\n");
    // -t only: no -r, no -a. Directories must still be created, with metadata.
    run_ok(&[
        "-pt",
        "--files-from",
        &t.s("list"),
        &t.s("src"),
        &t.s("dst"),
    ]);
    assert_eq!(listing(&t.path("dst")), ["a", "a/1", "b"]);
    assert_eq!(fs::metadata(t.path("dst/a")).unwrap().mode() & 0o777, 0o750);
    assert_eq!(fs::metadata(t.path("dst/b")).unwrap().mode() & 0o777, 0o710);
}

#[test]
fn delete_with_nested_roots_deletes_once() {
    let t = Tmp::new();
    write(&t.path("a/x"), b"x");
    write(&t.path("b/y"), b"y");
    write(&t.path("dst/a/extra/deep"), b"e");
    write(&t.path("dst/stray"), b"s");
    let so = run_ok(&["-a", "-v", "--delete", &t.s("a"), &t.s("b/"), &t.s("dst")]);
    assert_eq!(listing(&t.path("dst")), ["a", "a/x", "y"]);
    assert!(so.contains("3 deleted"), "{so}");
    assert!(!so.contains("errors"), "{so}");
}

#[test]
fn unreadable_source_root_disables_delete() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"a");
    write(&t.path("dst/precious"), b"p");
    fs::set_permissions(t.path("src"), fs::Permissions::from_mode(0o000)).unwrap();
    // -rt rather than -a, so dst doesn't faithfully inherit the 000 mode.
    let out = syq(&["-rt", "--delete", &t.s("src/"), &t.s("dst")]);
    fs::set_permissions(t.path("src"), fs::Permissions::from_mode(0o755)).unwrap();
    assert_ne!(out.status.code(), Some(0));
    assert!(t.path("dst/precious").exists(), "{}", stderr_of(&out));
    // Linux opens the unreadable root with `O_PATH` and reaches the deletion
    // decision; macOS cannot open it and fails at source registration.
    if cfg!(target_os = "linux") {
        assert!(
            stderr_of(&out).contains("skipping deletions"),
            "{}",
            stderr_of(&out)
        );
    }
}

#[test]
fn delete_nested_roots_keep_their_own_anchored_ignores() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"a");
    write(&t.path("src2/foo/g"), b"g");
    write(&t.path("src2/b"), b"b");
    write(&t.path("dst/src2/foo/g"), b"g");
    write(&t.path("dst/src2/junk"), b"j");
    write(&t.path("dst/foo/h"), b"h");
    let so = run_ok(&[
        "-a",
        "-v",
        "--delete",
        "--syq-ignore",
        "/foo",
        &t.s("src/"),
        &t.s("src2"),
        &t.s("dst"),
    ]);
    // /foo is anchored at each root: dst/src2/foo is protected (ignored on
    // both sides of the src2 mapping), dst/foo likewise for src/; junk goes.
    assert_eq!(
        listing(&t.path("dst")),
        [
            "a",
            "foo",
            "foo/h",
            "src2",
            "src2/b",
            "src2/foo",
            "src2/foo/g"
        ]
    );
    assert!(so.contains("1 deleted"), "{so}");
}

#[test]
fn no_recursive_skips_every_batch_of_a_directory_source() {
    let t = Tmp::new();
    for i in 0..1500 {
        write(&t.path(&format!("src/f{i}")), b"f");
    }
    let so = run_ok(&["-t", &t.s("src/"), &t.s("dst")]);
    assert_eq!(transferred(&so), 0);
    assert!(!t.path("dst/f1400").exists());
}

#[test]
fn delete_leaves_directory_contents_under_a_skipped_source_path() {
    let t = Tmp::new();
    write(&t.path("src/big"), &[0u8; 100]);
    std::os::unix::fs::symlink("nowhere", t.path("src/lnk")).unwrap();
    write(&t.path("src/real"), b"r");
    write(&t.path("dst/big/inside"), b"i");
    write(&t.path("dst/lnk/deep/inside"), b"i");
    write(&t.path("dst/extra"), b"e");
    let so = run_ok(&[
        "-rt",
        "--delete",
        "--max-size",
        "10",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert_eq!(
        listing(&t.path("dst")),
        [
            "big",
            "big/inside",
            "lnk",
            "lnk/deep",
            "lnk/deep/inside",
            "real"
        ]
    );
    assert!(so.contains("1 deleted"), "{so}");
}

// A value that happens to look like an unsupported flag is not misread.
#[test]
fn flag_like_ignore_pattern_is_not_rejected() {
    let t = Tmp::new();
    write(&t.path("src/keep"), b"k");
    // `--syq-ignore --exclude` means "ignore a pattern literally named --exclude"; it must
    // not trip the --exclude rejection.
    run_ok(&[
        "-a",
        "--syq-ignore",
        "--exclude",
        &t.s("src/"),
        &t.s("dst/"),
    ]);
    assert_eq!(read(&t.path("dst/keep")), b"k");
}

#[test]
fn bad_size_limits_fail_before_anything_connects() {
    let t = Tmp::new();
    write(&t.path("src"), b"data");
    for value in ["12Q", "-1", "18446744073709551616", "1e999"] {
        let t0 = std::time::Instant::now();
        let max_size = format!("--max-size={value}");
        let out = syq(&["-a", &max_size, &t.s("src"), &t.s("dst")]);
        assert!(!out.status.success(), "accepted {value:?}");
        assert!(
            stderr_of(&out).contains("bad size"),
            "{value:?}: {}",
            stderr_of(&out)
        );
        assert!(t0.elapsed() < std::time::Duration::from_secs(2));
    }
}

#[test]
fn files_from_leaves_no_ancestors_behind_on_a_bad_chain() {
    let t = Tmp::new();
    write(&t.path("src/a/b"), b"b is a file");
    write(&t.path("list"), b"a/b/c\n");
    let out = syq(&["-a", "--files-from", &t.s("list"), &t.s("src"), &t.s("dst")]);
    assert_eq!(out.status.code(), Some(23));
    assert_eq!(listing(&t.path("dst")), Vec::<String>::new());
}

#[test]
fn delete_after_and_delay_are_synonyms() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"a");
    for flag in ["--delete-after", "--delete-delay"] {
        write(&t.path("dst/extra"), b"x");
        run_ok(&["-a", flag, &t.s("src/"), &t.s("dst")]);
        assert!(!t.path("dst/extra").exists(), "{flag}");
    }
    let out = syq(&["-a", "--delete-before", &t.s("src/"), &t.s("dst")]);
    assert!(!out.status.success());
    assert!(stderr_of(&out).contains("after the transfer"));
}

#[test]
fn delete_excluded_removes_ignored_destination_paths() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"a");
    write(&t.path("src/junk.log"), b"src log, never copied");
    write(&t.path("dst/keep/k.log"), b"k");
    write(&t.path("dst/junk.log"), b"old");
    // Protected without the flag...
    run_ok(&[
        "-a",
        "--delete",
        "--syq-ignore",
        "*.log",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert_eq!(
        listing(&t.path("dst")),
        ["a", "junk.log", "keep", "keep/k.log"]
    );
    // ...extras with it, including the directory that only held them.
    let so = run_ok(&[
        "-a",
        "--delete",
        "--delete-excluded",
        "--syq-ignore",
        "*.log",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert_eq!(listing(&t.path("dst")), ["a"]);
    assert!(so.contains("3 deleted"), "{so}");
    assert!(
        !t.path("dst/junk.log").exists(),
        "source's ignored file is not copied either"
    );
}

#[test]
fn max_delete_refuses_everything_past_the_limit() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"a");
    for i in 0..5 {
        write(&t.path(&format!("dst/extra{i}")), b"x");
    }
    let dry = syq(&[
        "-an",
        "--delete",
        "--max-delete",
        "3",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert_eq!(dry.status.code(), Some(25), "{}", stderr_of(&dry));
    let dry_stdout = String::from_utf8_lossy(&dry.stdout);
    assert!(
        dry_stdout.contains("deletions: 5 entries planned; blocked by --max-delete 3"),
        "{dry_stdout}"
    );
    assert_eq!(listing(&t.path("dst")).len(), 5, "dry run changed files");

    let out = syq(&[
        "-a",
        "--delete",
        "--max-delete",
        "3",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert_eq!(out.status.code(), Some(25), "{}", stderr_of(&out));
    assert!(
        stderr_of(&out).contains("5 deletions planned"),
        "{}",
        stderr_of(&out)
    );
    assert_eq!(listing(&t.path("dst")).len(), 6, "nothing deleted");
    assert_eq!(
        read(&t.path("dst/a")),
        b"a",
        "the copy itself still happened"
    );
    run_ok(&[
        "-a",
        "--delete",
        "--max-delete",
        "5",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert_eq!(listing(&t.path("dst")), ["a"]);
    // As in rsync, --max-delete without --delete is accepted and has no effect.
    write(&t.path("dst/extra"), b"keep");
    run_ok(&["-a", "--max-delete", "5", &t.s("src/"), &t.s("dst")]);
    assert!(t.path("dst/extra").exists());

    // Zero is rsync's useful report-without-deleting idiom. Its historical -1
    // spelling has the same effect and is accepted for command compatibility.
    for value in ["0", "-1"] {
        let out = syq(&[
            "-a",
            "--delete",
            "--max-delete",
            value,
            &t.s("src/"),
            &t.s("dst"),
        ]);
        assert_eq!(out.status.code(), Some(25), "{value}: {}", stderr_of(&out));
        assert!(t.path("dst/extra").exists());
    }
}

#[test]
fn files_from_onto_a_file_destination_is_refused() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"a");
    write(&t.path("list"), b"a\n");
    write(&t.path("dst"), b"a precious file");
    let out = syq(&["-a", "--files-from", &t.s("list"), &t.s("src"), &t.s("dst")]);
    assert!(!out.status.success());
    assert!(
        stderr_of(&out).contains("needs a directory destination"),
        "{}",
        stderr_of(&out)
    );
    assert_eq!(read(&t.path("dst")), b"a precious file");
}

#[test]
fn files_from_rejections_and_stdin() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"a");
    write(&t.path("src/b"), b"b");
    write(&t.path("list"), b"a\n");
    // `-` reads the list from stdin.
    let mut child = compat_command()
        .args([
            "-a",
            "--files-from",
            "-",
            "--no-progress",
            &t.s("src"),
            &t.s("dst"),
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .start()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"b\n").unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    assert_eq!(listing(&t.path("dst")), ["b"]);
    // Cannot combine with --syq-ignore / --syq-ignore-from / --delete (clap-level errors).
    for extra in [
        ["--syq-ignore", "x"],
        ["--syq-ignore-from", "list"],
        ["--delete", "-v"],
    ] {
        let out = syq(&[
            "-a",
            "--files-from",
            &t.s("list"),
            extra[0],
            extra[1],
            &t.s("src"),
            &t.s("dst2"),
        ]);
        assert!(!out.status.success(), "{extra:?}");
        assert!(
            stderr_of(&out).contains("cannot be used with"),
            "{extra:?}: {}",
            stderr_of(&out)
        );
    }
    assert!(!t.path("dst2").exists());
    // Like rsync generally, a file-list copy cannot have two remote endpoints.
    let t0 = std::time::Instant::now();
    let out = syq(&[
        "-a",
        "--files-from",
        &t.s("list"),
        "nohost-a.invalid:x",
        "nohost-b.invalid:y",
    ]);
    assert!(!out.status.success());
    assert!(
        stderr_of(&out).contains("source and destination cannot both be remote"),
        "{}",
        stderr_of(&out)
    );
    assert!(t0.elapsed() < std::time::Duration::from_secs(2));
}

#[test]
fn size_arguments_reject_negative_nan_and_overflow() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"data");
    for (flag, bad) in [
        ("--max-size", "-1"),
        ("--max-size", "-1K"),
        ("--min-size", "nan"),
        ("--max-size", "inf"),
        ("--max-size", "1e30"),
        ("--block-size", "-4M"),
    ] {
        let arg = format!("{flag}={bad}");
        let out = syq(&["-a", &arg, &t.s("src/"), &t.s("dst")]);
        assert!(!out.status.success(), "{arg}");
        assert!(
            stderr_of(&out).to_lowercase().contains("size"),
            "{arg}: {}",
            stderr_of(&out)
        );
        assert!(!t.path("dst/f").exists(), "{arg}: nothing may be copied");
    }
    // Fractional sizes keep working.
    let so = run_ok(&["-a", "--max-size", "1.5K", &t.s("src/"), &t.s("dst")]);
    assert_eq!(transferred(&so), 1);
}

#[test]
fn files_from_leaves_unlisted_destination_root_metadata_alone() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"a");
    fs::set_permissions(t.path("src"), fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir_all(t.path("dst")).unwrap();
    fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o755)).unwrap();
    write(&t.path("list"), b"a\n");
    run_ok(&["-a", "--files-from", &t.s("list"), &t.s("src"), &t.s("dst")]);
    fs::set_permissions(t.path("src"), fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(read(&t.path("dst/a")), b"a");
    assert_eq!(
        fs::metadata(t.path("dst")).unwrap().mode() & 0o777,
        0o755,
        "the unlisted root keeps its own mode"
    );
    // An empty list still creates a missing destination (syq's choice:
    // rsync 3.2.7 creates it only when spelled with a trailing slash).
    write(&t.path("empty"), b"");
    run_ok(&[
        "-a",
        "--files-from",
        &t.s("empty"),
        &t.s("src"),
        &t.s("dst2"),
    ]);
    assert!(t.path("dst2").is_dir());
}

#[test]
fn ignore_existing_keeps_a_file_where_a_source_directory_maps() {
    let t = Tmp::new();
    write(&t.path("src/d/inner"), b"i");
    write(&t.path("src/plain"), b"p");
    fs::create_dir_all(t.path("dst")).unwrap();
    write(&t.path("dst/d"), b"precious");
    // Dry run and real run agree; the existing file survives; the rest copies.
    let so = run_ok(&["-r", "-n", "--ignore-existing", &t.s("src/"), &t.s("dst")]);
    assert!(so.contains("1 B in 1 file needing content work"), "{so}");
    let out = syq(&["-r", "--ignore-existing", &t.s("src/"), &t.s("dst")]);
    assert!(out.status.success(), "{}", stderr_of(&out));
    assert!(
        stderr_of(&out).contains("keeping existing"),
        "{}",
        stderr_of(&out)
    );
    assert_eq!(read(&t.path("dst/d")), b"precious");
    assert_eq!(read(&t.path("dst/plain")), b"p");
    // An existing *directory* is still descended into — the flag stays useful.
    fs::create_dir_all(t.path("dst2/d")).unwrap();
    run_ok(&["-r", "--ignore-existing", &t.s("src/"), &t.s("dst2")]);
    assert_eq!(read(&t.path("dst2/d/inner")), b"i");
}

#[test]
fn files_from_empty_list_leaves_an_existing_destination_untouched() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"a");
    fs::create_dir_all(t.path("dst")).unwrap();
    fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o711)).unwrap();
    set_mtime(&t.path("dst"), 1_000);
    set_mtime(&t.path("src"), 2_000);
    write(&t.path("empty"), b"");
    run_ok(&[
        "-a",
        "--files-from",
        &t.s("empty"),
        &t.s("src"),
        &t.s("dst"),
    ]);
    let md = fs::metadata(t.path("dst")).unwrap();
    assert_eq!(md.mode() & 0o777, 0o711);
    assert_eq!(md.mtime(), 1_000, "nothing created, nothing stamped");
}

#[test]
fn files_from_unwritable_destination_root_fails_and_is_left_alone() {
    // Ordinary copies open up and restore an unwritable root; --files-from
    // deliberately doesn't (the root isn't listed), so it fails per file.
    let t = Tmp::new();
    write(&t.path("src/a"), b"a");
    fs::create_dir_all(t.path("dst")).unwrap();
    fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o500)).unwrap();
    write(&t.path("list"), b"a\n");
    let out = syq(&["-a", "--files-from", &t.s("list"), &t.s("src"), &t.s("dst")]);
    let mode = fs::metadata(t.path("dst")).unwrap().mode() & 0o777;
    fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(out.status.code(), Some(23), "{}", stderr_of(&out));
    assert_eq!(mode, 0o500, "the unlisted root keeps its mode");
    assert!(!t.path("dst/a").exists());
}

#[test]
fn native_cp_prune_fatal_failure_reports_deletion_aggregates() {
    let t = Tmp::new();
    write(&t.path("dst/keep.txt"), b"k");
    let out = syq_cp_in(
        &t.path(""),
        &[
            "--prune",
            "--srcs-in",
            "missing",
            "--into",
            "dst",
            "--results",
            "r1.ndjson",
            "-q",
        ],
        None,
    );
    assert!(!out.status.success());
    let terminal: serde_json::Value = String::from_utf8(read(&t.path("r1.ndjson")))
        .unwrap()
        .lines()
        .last()
        .map(|line| serde_json::from_str(line).unwrap())
        .unwrap();
    assert_eq!(terminal["status"], "failed");
    // The run record says prune: true, so the terminal record carries the
    // deletion aggregates even on a fatal failure: zeros, because the run
    // died before the deletion pass.
    assert_eq!(terminal["deletions_planned"], 0);
    assert_eq!(terminal["deletions_completed"], 0);
    assert_eq!(terminal["deletions_blocked"], 0);
}

#[test]
fn native_only_new_preserves_existing_directory_metadata() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    for mapping in [false, true] {
        let t = Tmp::new();
        write(&t.path("src/existing/new/file"), b"new");
        fs::create_dir_all(t.path("src/unchanged")).unwrap();
        fs::create_dir_all(t.path("dst/existing")).unwrap();
        fs::create_dir_all(t.path("dst/unchanged")).unwrap();
        for path in ["src/existing", "src/unchanged", "src/existing/new"] {
            fs::set_permissions(t.path(path), fs::Permissions::from_mode(0o750)).unwrap();
            set_mtime(&t.path(path), 1_500_000_000);
        }
        for path in ["dst/existing", "dst/unchanged"] {
            fs::set_permissions(t.path(path), fs::Permissions::from_mode(0o711)).unwrap();
            set_mtime(&t.path(path), 1_600_000_000);
        }
        if mapping {
            let map = Command::new(env!("CARGO_BIN_EXE_syq"))
                .args(["map", "--srcs-in", &t.s("src")])
                .run()
                .unwrap();
            assert_output_ok(&map);
            write(&t.path("mapping"), &map.stdout);
        }
        let mut args = vec!["cp", "--only-new", "--preserve=permissions", "--cwd"];
        let base = t.s("src");
        let manifest = t.s("mapping");
        let dest = t.s("dst");
        args.push(&base);
        if mapping {
            args.extend(["--mapping", &manifest]);
        } else {
            args.extend(["--srcs-in", "."]);
        }
        args.extend(["--into", &dest]);
        let mut preview = args.clone();
        preview.extend(["--dry-run", "-v"]);
        let out = native_syq(&preview);
        assert_output_ok(&out);
        assert!(!String::from_utf8_lossy(&out.stdout).contains("update metadata"));
        run_native_ok(&args);
        for path in ["dst/existing", "dst/unchanged"] {
            assert_eq!(fs::metadata(t.path(path)).unwrap().mode() & 0o777, 0o711);
        }
        assert_eq!(
            fs::metadata(t.path("dst/unchanged")).unwrap().mtime(),
            1_600_000_000
        );
        assert_eq!(
            fs::metadata(t.path("dst/existing/new")).unwrap().mode() & 0o777,
            0o750
        );
        assert_eq!(
            fs::metadata(t.path("dst/existing/new")).unwrap().mtime(),
            1_500_000_000
        );
        assert_eq!(read(&t.path("dst/existing/new/file")), b"new");
    }
}

#[test]
fn directory_dry_run_uses_destination_timestamp_precision() {
    for (source_ns, destination_ns, differs) in [
        (123_456_789, 120_000_000, false),
        (123_456_789, 0, false),
        (123_456_789, 130_000_000, true),
        (120_000_000, 123_456_789, true),
    ] {
        let t = Tmp::new();
        fs::create_dir_all(t.path("src/sub")).unwrap();
        fs::create_dir_all(t.path("dst/sub")).unwrap();
        set_mtime(&t.path("src"), 10);
        set_mtime(&t.path("dst"), 10);
        for (name, nanos) in [("src/sub", source_ns), ("dst/sub", destination_ns)] {
            File::open(t.path(name))
                .unwrap()
                .set_times(
                    fs::FileTimes::new()
                        .set_modified(std::time::UNIX_EPOCH + std::time::Duration::new(10, nanos)),
                )
                .unwrap();
        }
        let out = syq_cp_in(
            &t.path(""),
            &["src", "--as", "dst", "--dry-run", "-v"],
            None,
        );
        assert_output_ok(&out);
        let stderr = String::from_utf8_lossy(&out.stdout);
        assert_eq!(stderr.contains("metadata"), differs, "{stderr}");
    }
}

#[test]
fn delete_many_roots_keeps_claims_in_their_own_scope() {
    let t = Tmp::new();
    let mut sources = Vec::new();
    for i in 0..40 {
        let name = format!("group-{i:02}");
        write(&t.path(&format!("src/{name}/keep")), b"keep");
        write(&t.path(&format!("dst/{name}/keep")), b"keep");
        write(&t.path(&format!("dst/{name}/extra")), b"extra");
        sources.push(t.s(&format!("src/{name}")));
    }
    let destination = t.s("dst");
    for dry in [true, false] {
        // This checks selector scope, not automatic worker scaling. Keep the
        // 40-root fixture within ordinary per-process descriptor limits.
        let mut args = vec![
            if dry { "-an" } else { "-a" },
            "--delete",
            "--performance-tuning=workers=2",
        ];
        args.extend(sources.iter().map(String::as_str));
        args.push(&destination);
        run_ok(&args);
        for i in 0..40 {
            assert_eq!(read(&t.path(&format!("dst/group-{i:02}/keep"))), b"keep");
            assert_eq!(t.path(&format!("dst/group-{i:02}/extra")).exists(), dry);
        }
    }
}

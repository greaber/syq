use super::*;

#[cfg(debug_assertions)]
#[test]
fn source_scan_uses_registered_root_after_operator_path_replacement() {
    for insecure in [false, true] {
        let t = Tmp::new();
        write(&t.path("src/original"), b"original");
        write(&t.path("outside/replacement"), b"replacement");
        let ready = t.path("source-ready");
        let continuation = t.path("continue");

        let mut child = compat_command()
            .args(insecure.then_some("--insecure-links"))
            .args([
                "-anv",
                "--performance-tuning",
                "workers=1",
                &t.s("src/"),
                &t.s("dst/"),
                "--no-progress",
            ])
            .env("SYQ_TEST_SOURCE_ROOTS_REGISTERED_FILE", &ready)
            .env("SYQ_TEST_SOURCE_ROOTS_CONTINUE_FILE", &continuation)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .start()
            .unwrap();

        wait_for_confinement_marker(&mut child, &ready, "source roots");

        fs::rename(t.path("src"), t.path("selected-and-moved")).unwrap();
        std::os::unix::fs::symlink(t.path("outside"), t.path("src")).unwrap();

        release_confinement_barrier(&continuation);
        let output = child.wait_with_output().unwrap();
        assert_output_ok(&output);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("/original (destination missing)"),
            "{stdout}"
        );
        assert!(
            !stdout.contains("/replacement (destination missing)"),
            "{stdout}"
        );
        assert!(
            !t.path("dst").exists(),
            "dry run unexpectedly created output"
        );
    }
}

#[cfg(debug_assertions)]
#[test]
fn exact_regular_source_replacement_is_rejected_after_registration() {
    let t = Tmp::new();
    write(&t.path("selected"), b"original");
    let ready = t.path("source-ready");
    let continuation = t.path("continue");

    let mut child = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "cp",
            "--src-non-dir",
            &t.s("selected"),
            "--as-new",
            &t.s("destination"),
            "--no-progress",
        ])
        .env("SYQ_TEST_SOURCE_ROOTS_REGISTERED_FILE", &ready)
        .env("SYQ_TEST_SOURCE_ROOTS_CONTINUE_FILE", &continuation)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .start()
        .unwrap();

    wait_for_confinement_marker(&mut child, &ready, "source roots");
    fs::rename(t.path("selected"), t.path("selected-original")).unwrap();
    write(&t.path("selected"), b"replacement");

    release_confinement_barrier(&continuation);
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success(), "unexpected success: {output:?}");
    assert!(
        stderr_of(&output).contains("registered source leaf changed identity"),
        "{}",
        stderr_of(&output)
    );
    assert!(!t.path("destination").exists());
}

#[cfg(debug_assertions)]
#[test]
fn exact_symlink_source_replacement_is_rejected_after_registration() {
    let t = Tmp::new();
    write(&t.path("target-a"), b"a");
    write(&t.path("target-b"), b"b");
    std::os::unix::fs::symlink("target-a", t.path("selected")).unwrap();
    let ready = t.path("source-ready");
    let continuation = t.path("continue");

    let mut child = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "cp",
            "--src-non-dir",
            &t.s("selected"),
            "--as-new",
            &t.s("destination"),
            "--no-progress",
        ])
        .env("SYQ_TEST_SOURCE_ROOTS_REGISTERED_FILE", &ready)
        .env("SYQ_TEST_SOURCE_ROOTS_CONTINUE_FILE", &continuation)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .start()
        .unwrap();

    wait_for_confinement_marker(&mut child, &ready, "source roots");
    fs::rename(t.path("selected"), t.path("selected-original")).unwrap();
    std::os::unix::fs::symlink("target-b", t.path("selected")).unwrap();

    release_confinement_barrier(&continuation);
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success(), "unexpected success: {output:?}");
    assert!(
        stderr_of(&output).contains("registered source leaf changed identity"),
        "{}",
        stderr_of(&output)
    );
    assert!(!t.path("destination").exists());
}

#[cfg(debug_assertions)]
#[test]
fn source_small_and_range_reads_use_registered_root_after_path_replacement() {
    for insecure in [false, true] {
        let t = Tmp::new();
        let original_large = vec![b'o'; 5 << 20];
        write(&t.path("src/small"), b"original");
        write(&t.path("src/large"), &original_large);
        write(&t.path("outside/small"), b"replaced");
        write(&t.path("outside/large"), &vec![b'r'; 5 << 20]);
        let ready = t.path("source-content-ready");
        let continuation = t.path("continue");

        let mut child = compat_command()
            .args(insecure.then_some("--insecure-links"))
            .args([
                "-a",
                "--performance-tuning",
                "workers=1",
                &t.s("src/"),
                &t.s("dst/"),
                "--no-progress",
            ])
            // Keep the test on the ranged transport path instead of the excluded
            // same-machine CopyLocal optimization.
            .env("SYQ_TEST_COPY_LOCAL_EXDEV", "1")
            .env("SYQ_TEST_CLONE_ERROR", "EXDEV")
            .env("SYQ_DEBUG", "1")
            .env("SYQ_TEST_COPY_LOCAL_SOURCE_NFS", "1")
            .env("SYQ_TEST_SOURCE_ROOTS_REGISTERED_FILE", &ready)
            .env("SYQ_TEST_SOURCE_ROOTS_CONTINUE_FILE", &continuation)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .start()
            .unwrap();

        wait_for_confinement_marker(&mut child, &ready, "source roots");

        fs::rename(t.path("src"), t.path("selected-and-moved")).unwrap();
        std::os::unix::fs::symlink(t.path("outside"), t.path("src")).unwrap();

        release_confinement_barrier(&continuation);
        let output = child.wait_with_output().unwrap();
        assert_output_ok(&output);
        assert_eq!(tuning_observed(&output)["local_whole_files"], 0);
        assert!(tuning_observed(&output)["range_requests"].as_u64().unwrap() > 0);
        assert_eq!(read(&t.path("dst/small")), b"original");
        assert_eq!(read(&t.path("dst/large")), original_large);
    }
}

#[cfg(all(debug_assertions, any(target_os = "linux", target_os = "macos")))]
#[test]
fn copy_local_uses_registered_source_after_path_replacement() {
    #[cfg(target_os = "macos")]
    if !macos_clone_support::available() {
        return;
    }
    for userspace in [false, true]
        .into_iter()
        .filter(|userspace| !userspace || cfg!(target_os = "linux"))
    {
        let t = Tmp::new();
        let original = vec![b'o'; 8 << 20];
        write(&t.path("src/file"), &original);
        write(&t.path("src/other"), &vec![b'o'; 5 << 20]);
        write(&t.path("outside/file"), &vec![b'r'; original.len()]);
        let ready = t.path("source-capability-ready");
        let continuation = t.path("continue");

        let mut child = compat_command()
            .args([
                "-a",
                "--performance-tuning",
                "workers=1",
                &t.s("src/"),
                &t.s("dst/"),
                "--no-progress",
            ])
            .env("SYQ_TEST_SOURCE_ROOTS_REGISTERED_FILE", &ready)
            .env("SYQ_TEST_SOURCE_ROOTS_CONTINUE_FILE", &continuation)
            // A pathname fallback would read through the replacement below. A
            // streaming fallback fails instead of hiding that CopyLocal was not
            // exercised.
            .env("SYQ_TEST_FAIL_READ_RANGE", "1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .envs(userspace.then_some(("SYQ_TEST_COPY_LOCAL_EXDEV", "1")))
            .envs(userspace.then_some(("SYQ_TEST_COPY_LOCAL_FS", "local")))
            .start()
            .unwrap();

        wait_for_confinement_marker(&mut child, &ready, "source roots");

        fs::rename(t.path("src"), t.path("selected-and-moved")).unwrap();
        std::os::unix::fs::symlink(t.path("outside"), t.path("src")).unwrap();

        release_confinement_barrier(&continuation);
        let output = child.wait_with_output().unwrap();
        assert_output_ok(&output);
        assert_eq!(read(&t.path("dst/file")), original);
    }
}

#[cfg(all(debug_assertions, any(target_os = "linux", target_os = "macos")))]
#[test]
fn copy_local_refuses_a_replaced_destination_parent() {
    for userspace in [false, true]
        .into_iter()
        .filter(|userspace| !userspace || cfg!(target_os = "linux"))
    {
        let t = Tmp::new();
        write(&t.path("src/tree/file"), &vec![b's'; 8 << 20]);
        write(&t.path("src/tree/other"), &vec![b'o'; 5 << 20]);
        fs::create_dir_all(t.path("dst/tree")).unwrap();
        write(&t.path("outside/sentinel"), b"unchanged");
        let ready = t.path("copy-local-ready");
        let continuation = t.path("continue");

        let mut child = compat_command()
            .args([
                "-a",
                "--performance-tuning",
                "workers=1",
                &t.s("src/"),
                &t.s("dst/"),
                "--no-progress",
            ])
            .env("SYQ_TEST_COPY_LOCAL_READY_FILE", &ready)
            .env("SYQ_TEST_COPY_LOCAL_OPEN_CONTINUE_FILE", &continuation)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .envs(userspace.then_some(("SYQ_TEST_COPY_LOCAL_EXDEV", "1")))
            .envs(userspace.then_some(("SYQ_TEST_COPY_LOCAL_FS", "local")))
            .start()
            .unwrap();

        wait_for_confinement_marker(&mut child, &ready, "copy local");

        fs::rename(t.path("dst/tree"), t.path("dst/tree-original")).unwrap();
        std::os::unix::fs::symlink(t.path("outside"), t.path("dst/tree")).unwrap();

        release_confinement_barrier(&continuation);
        let output = child.wait_with_output().unwrap();
        assert!(!output.status.success(), "unexpected success: {output:?}");
        assert_eq!(read(&t.path("outside/sentinel")), b"unchanged");
        assert!(!t.path("outside/file").exists());
    }
}

#[cfg(all(debug_assertions, target_os = "linux"))]
#[test]
fn inplace_copy_local_replaces_a_raced_destination_symlink() {
    for userspace in [false, true] {
        let t = Tmp::new();
        let contents = vec![b's'; 8 << 20];
        write(&t.path("src/file"), &contents);
        write(&t.path("src/other"), &vec![b'o'; 5 << 20]);
        write(&t.path("dst/file"), &vec![b'd'; contents.len()]);
        write(&t.path("outside"), b"unchanged");
        set_mtime(&t.path("src/file"), 1_700_000_000);
        set_mtime(&t.path("dst/file"), 1_600_000_000);
        let ready = t.path("copy-local-ready");
        let continuation = t.path("continue");

        let mut child = compat_command()
            .args([
                "-a",
                "--inplace",
                "--performance-tuning",
                "workers=1",
                &t.s("src/"),
                &t.s("dst/"),
                "--no-progress",
            ])
            .env("SYQ_TEST_COPY_LOCAL_READY_FILE", &ready)
            .env("SYQ_TEST_COPY_LOCAL_OPEN_CONTINUE_FILE", &continuation)
            .env("SYQ_TEST_FAIL_READ_RANGE", "1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .envs(userspace.then_some(("SYQ_TEST_COPY_LOCAL_EXDEV", "1")))
            .envs(userspace.then_some(("SYQ_TEST_COPY_LOCAL_FS", "local")))
            .start()
            .unwrap();

        wait_for_confinement_marker(&mut child, &ready, "copy local");

        fs::remove_file(t.path("dst/file")).unwrap();
        std::os::unix::fs::symlink("../outside", t.path("dst/file")).unwrap();

        release_confinement_barrier(&continuation);
        let output = child.wait_with_output().unwrap();
        assert_output_ok(&output);
        assert_eq!(read(&t.path("outside")), b"unchanged");
        assert!(fs::symlink_metadata(t.path("dst/file")).unwrap().is_file());
        assert_eq!(read(&t.path("dst/file")), contents);
    }
}

#[test]
fn native_copy_cwd_may_escape_while_root_confines_component_resolution() {
    use std::os::unix::fs::symlink;

    let t = Tmp::new();
    write(&t.path("base/inside"), b"inside");
    fs::create_dir_all(t.path("base/nested")).unwrap();
    write(&t.path("outside/external"), b"outside");

    run_native_ok(&[
        "cp",
        "--cwd",
        &t.s("base"),
        "--src",
        "../outside/external",
        "--into-new",
        &t.s("cwd-destination"),
    ]);
    assert_eq!(read(&t.path("cwd-destination/external")), b"outside");

    run_native_ok(&[
        "cp",
        "--cwd",
        &t.s("missing-base"),
        "--src",
        &t.s("outside/external"),
        "--as-new",
        &t.s("absolute-source"),
    ]);
    assert_eq!(read(&t.path("absolute-source")), b"outside");

    let escape = native_syq(&[
        "cp",
        "--root",
        &t.s("base"),
        "--src",
        "inside",
        "--src",
        "../outside/external",
        "--into-new",
        &t.s("root-escape"),
    ]);
    assert!(!escape.status.success());
    assert!(stderr_of(&escape).contains("outside its confined root"));
    assert!(!t.path("root-escape").exists());

    run_native_ok(&[
        "cp",
        "--root",
        &t.s("base"),
        "--src",
        "nested/../inside",
        "--into-new",
        &t.s("root-destination"),
    ]);
    assert_eq!(read(&t.path("root-destination/inside")), b"inside");

    run_native_ok(&[
        "cp",
        "--root",
        &t.s("base"),
        "--src",
        ".",
        "--as-new",
        &t.s("exact-root-copy"),
    ]);
    assert_eq!(read(&t.path("exact-root-copy/inside")), b"inside");

    write(&t.path("base/file"), b"file");
    let non_directory = native_syq(&[
        "cp",
        "--root",
        &t.s("base"),
        "--src",
        "file/.",
        "--into-new",
        &t.s("non-directory"),
    ]);
    assert!(!non_directory.status.success());
    assert!(!t.path("non-directory").exists());

    symlink("nested", t.path("base/link")).unwrap();
    let no_follow = native_syq(&[
        "cp",
        "--root",
        &t.s("base"),
        "--src",
        "link/../inside",
        "--into-new",
        &t.s("no-follow"),
    ]);
    assert!(!no_follow.status.success());
    assert!(!t.path("no-follow").exists());

    run_native_ok(&[
        "cp",
        "--root",
        &t.s("base"),
        "--follow-src",
        "--src",
        "link/../inside",
        "--into-new",
        &t.s("followed"),
    ]);
    assert_eq!(read(&t.path("followed/inside")), b"inside");

    symlink("base", t.path("base-link")).unwrap();
    let linked_base = native_syq(&[
        "cp",
        "--root",
        &t.s("base-link"),
        "--src",
        "inside",
        "--into-new",
        &t.s("linked-base-refused"),
    ]);
    assert!(!linked_base.status.success());
    assert!(!t.path("linked-base-refused").exists());
    run_native_ok(&[
        "cp",
        "--root",
        &t.s("base-link"),
        "--follow-src",
        "--src",
        "inside",
        "--into-new",
        &t.s("linked-base-followed"),
    ]);
    assert_eq!(read(&t.path("linked-base-followed/inside")), b"inside");
}

#[test]
fn native_copy_follow_resolves_source_links_but_default_refuses_traversal() {
    use std::os::unix::fs::symlink;

    let t = Tmp::new();
    write(&t.path("real/file"), b"data");
    symlink("real", t.path("link")).unwrap();

    let refused = native_syq(&["cp", "--srcs-in", &t.s("link"), "--into", &t.s("refused")]);
    assert!(!refused.status.success());
    assert!(stderr_of(&refused).contains("pass --follow"));
    assert!(!t.path("refused").exists());

    run_native_ok(&[
        "cp",
        "--follow",
        "--srcs-in",
        &t.s("link"),
        "--into",
        &t.s("followed"),
    ]);
    assert_eq!(read(&t.path("followed/file")), b"data");

    run_native_ok(&[
        "cp",
        "--follow",
        "--src",
        &t.s("link"),
        "--into",
        &t.s("named-followed"),
    ]);
    assert_eq!(read(&t.path("named-followed/link/file")), b"data");
    assert!(!t.path("named-followed/real").exists());

    fs::create_dir(t.path("through-link")).unwrap();
    symlink("../real", t.path("through-link/parent")).unwrap();
    let refused = native_syq(&[
        "cp",
        "--src",
        &t.s("through-link/parent/file"),
        "--as",
        &t.s("never-created"),
    ]);
    assert!(!refused.status.success());
    let stderr = stderr_of(&refused);
    assert!(stderr.contains("--follow-src for source paths"), "{stderr}");
    assert!(
        stderr.contains("--follow-dst for destination paths"),
        "{stderr}"
    );
    assert!(
        stderr.contains("--follow for all directly supplied filesystem paths"),
        "{stderr}"
    );
    assert!(!t.path("never-created").exists());
}

#[test]
fn native_directional_follow_keeps_source_destination_and_control_authority_separate() {
    use std::os::unix::fs::symlink;

    let t = Tmp::new();
    write(&t.path("real-source/file"), b"data");
    symlink("real-source", t.path("source-link")).unwrap();
    fs::create_dir(t.path("real-destination")).unwrap();
    symlink("real-destination", t.path("destination-link")).unwrap();

    run_native_ok(&[
        "cp",
        "--follow-src",
        "--srcs-in",
        &t.s("source-link"),
        "--into",
        &t.s("source-followed"),
    ]);
    assert_eq!(read(&t.path("source-followed/file")), b"data");

    let destination_refused = native_syq(&[
        "cp",
        "--follow-src",
        "--srcs-in",
        &t.s("real-source"),
        "--into-existing",
        &t.s("destination-link"),
    ]);
    assert!(!destination_refused.status.success());
    assert!(stderr_of(&destination_refused).contains("--follow-dst"));
    assert!(!t.path("real-destination/file").exists());

    let source_refused = native_syq(&[
        "cp",
        "--follow-dst",
        "--srcs-in",
        &t.s("source-link"),
        "--into",
        &t.s("source-refused"),
    ]);
    assert!(!source_refused.status.success());
    assert!(stderr_of(&source_refused).contains("--follow-src"));
    assert!(!t.path("source-refused").exists());

    run_native_ok(&[
        "cp",
        "--follow-dst",
        "--srcs-in",
        &t.s("real-source"),
        "--into-existing",
        &t.s("destination-link"),
    ]);
    assert_eq!(read(&t.path("real-destination/file")), b"data");

    write(&t.path("rules"), b"*.tmp\n");
    symlink("rules", t.path("rules-link")).unwrap();
    let control_refused = native_syq(&[
        "cp",
        "--follow-src",
        "--follow-dst",
        "--ignore-from",
        &t.s("rules-link"),
        "--srcs-in",
        &t.s("real-source"),
        "--into",
        &t.s("control-refused"),
    ]);
    assert!(!control_refused.status.success());
    let stderr = stderr_of(&control_refused);
    assert!(
        stderr.contains("--follow for all directly supplied filesystem paths"),
        "{stderr}"
    );
    assert!(!t.path("control-refused").exists());
}

#[test]
fn native_copy_placement_links_follow_containers_but_not_exact_names() {
    use std::os::unix::fs::symlink;

    let t = Tmp::new();
    write(&t.path("source"), b"new");
    write(&t.path("referent"), b"old");
    symlink("referent", t.path("exact-link")).unwrap();

    run_native_ok(&["cp", &t.s("source"), "--as-existing", &t.s("exact-link")]);
    assert_eq!(read(&t.path("exact-link")), b"new");
    assert_eq!(read(&t.path("referent")), b"old");
    assert!(!t.path("exact-link").is_symlink());

    write(&t.path("referent"), b"old-again");
    fs::remove_file(t.path("exact-link")).unwrap();
    symlink("referent", t.path("exact-link")).unwrap();
    run_native_ok(&[
        "cp",
        "--follow",
        &t.s("source"),
        "--as-existing",
        &t.s("exact-link"),
    ]);
    assert_eq!(read(&t.path("exact-link")), b"new");
    assert_eq!(read(&t.path("referent")), b"old-again");
    assert!(!t.path("exact-link").is_symlink());

    symlink("never-created", t.path("dangling-existing-link")).unwrap();
    run_native_ok(&[
        "cp",
        "--follow",
        &t.s("source"),
        "--as-existing",
        &t.s("dangling-existing-link"),
    ]);
    assert_eq!(read(&t.path("dangling-existing-link")), b"new");
    assert!(!t.path("never-created").exists());

    symlink("also-never-created", t.path("dangling-new-link")).unwrap();
    let refused = native_syq(&[
        "cp",
        "--follow",
        &t.s("source"),
        "--as-new",
        &t.s("dangling-new-link"),
    ]);
    assert!(!refused.status.success());
    assert!(stderr_of(&refused).contains("already exists"));
    assert!(t.path("dangling-new-link").is_symlink());
    assert!(!t.path("also-never-created").exists());

    fs::create_dir_all(t.path("links")).unwrap();
    write(&t.path("elsewhere/relative-referent"), b"old-relative");
    symlink(
        "../elsewhere/relative-referent",
        t.path("links/relative-link"),
    )
    .unwrap();
    run_native_ok(&[
        "cp",
        "--follow",
        &t.s("source"),
        "--as-existing",
        &t.s("links/relative-link"),
    ]);
    assert_eq!(read(&t.path("links/relative-link")), b"new");
    assert_eq!(
        read(&t.path("elsewhere/relative-referent")),
        b"old-relative"
    );
    assert!(!t.path("links/relative-link").is_symlink());

    let absolute_referent = t.path("elsewhere/absolute-referent");
    write(&absolute_referent, b"old-absolute");
    symlink(&absolute_referent, t.path("links/absolute-link")).unwrap();
    run_native_ok(&[
        "cp",
        "--follow",
        &t.s("source"),
        "--as-existing",
        &t.s("links/absolute-link"),
    ]);
    assert_eq!(read(&t.path("links/absolute-link")), b"new");
    assert_eq!(read(&absolute_referent), b"old-absolute");
    assert!(!t.path("links/absolute-link").is_symlink());

    symlink(
        "../elsewhere/never-created-external-referent",
        t.path("links/dangling-external-link"),
    )
    .unwrap();
    let refused = native_syq(&[
        "cp",
        "--follow",
        &t.s("source"),
        "--as-new",
        &t.s("links/dangling-external-link"),
    ]);
    assert!(!refused.status.success());
    assert!(t.path("links/dangling-external-link").is_symlink());
    assert!(!t.path("elsewhere/never-created-external-referent").exists());

    fs::create_dir(t.path("real-parent")).unwrap();
    symlink("real-parent", t.path("parent-link")).unwrap();
    let refused = native_syq(&["cp", &t.s("source"), "--as", &t.s("parent-link/exact-name")]);
    assert!(!refused.status.success());
    let stderr = stderr_of(&refused);
    assert!(
        stderr.contains("--follow-dst for destination paths"),
        "{stderr}"
    );
    assert!(!t.path("real-parent/exact-name").exists());
    run_native_ok(&[
        "cp",
        "--follow-dst",
        &t.s("source"),
        "--as",
        &t.s("parent-link/exact-name"),
    ]);
    assert_eq!(read(&t.path("real-parent/exact-name")), b"new");

    write(&t.path("source-tree/file"), b"tree");
    symlink("source-tree", t.path("source-tree-link")).unwrap();
    let refused = native_syq(&[
        "cp",
        "--follow",
        "--src-dir",
        &t.s("source-tree"),
        "--as-existing",
        &t.s("source-tree-link"),
    ]);
    assert_eq!(refused.status.code(), Some(23), "{refused:?}");
    assert!(stderr_of(&refused).contains("cannot replace non-directory"));
    assert!(t.path("source-tree-link").is_symlink());
    assert_eq!(read(&t.path("source-tree-link/file")), b"tree");
    assert_eq!(read(&t.path("source-tree/file")), b"tree");

    fs::create_dir(t.path("real-container")).unwrap();
    symlink("real-container", t.path("container-link")).unwrap();
    let refused = native_syq(&[
        "cp",
        &t.s("source"),
        "--into-existing",
        &t.s("container-link"),
    ]);
    assert!(!refused.status.success());
    assert!(!t.path("real-container/source").exists());
    run_native_ok(&[
        "cp",
        "--follow",
        &t.s("source"),
        "--into-existing",
        &t.s("container-link"),
    ]);
    assert_eq!(read(&t.path("real-container/source")), b"new");
}

#[test]
fn native_copy_control_file_paths_use_the_common_follow_policy() {
    use std::os::unix::fs::symlink;

    let t = Tmp::new();
    write(&t.path("src/keep"), b"data");
    write(&t.path("rules"), b"*.tmp\n");
    symlink("rules", t.path("rules-link")).unwrap();

    let refused = native_syq(&[
        "cp",
        "--ignore-from",
        &t.s("rules-link"),
        "--srcs-in",
        &t.s("src"),
        "--into",
        &t.s("ignored-output"),
    ]);
    assert!(!refused.status.success());
    assert!(stderr_of(&refused).contains("pass --follow"));
    assert!(!t.path("ignored-output").exists());

    run_native_ok(&[
        "cp",
        "--follow",
        "--ignore-from",
        &t.s("rules-link"),
        "--srcs-in",
        &t.s("src"),
        "--into",
        &t.s("followed-output"),
    ]);
    assert_eq!(read(&t.path("followed-output/keep")), b"data");

    write(
        &t.path("manifest"),
        entry_line("keep", "renamed", None).as_bytes(),
    );
    symlink("manifest", t.path("manifest-link")).unwrap();
    let refused = native_syq(&[
        "cp",
        "--mapping",
        &t.s("manifest-link"),
        "--cwd",
        &t.s("src"),
        "--into",
        &t.s("mapping-output"),
    ]);
    assert!(!refused.status.success());
    assert!(stderr_of(&refused).contains("pass --follow"));
    assert!(!t.path("mapping-output").exists());
    run_native_ok(&[
        "cp",
        "--follow",
        "--mapping",
        &t.s("manifest-link"),
        "--cwd",
        &t.s("src"),
        "--into",
        &t.s("mapping-output"),
    ]);
    assert_eq!(read(&t.path("mapping-output/renamed")), b"data");
    symlink("real-results", t.path("results-link")).unwrap();
    let refused = native_syq(&[
        "cp",
        "--results",
        &t.s("results-link"),
        &t.s("src/keep"),
        "--as",
        &t.s("results-output"),
    ]);
    assert!(!refused.status.success());
    assert!(stderr_of(&refused).contains("pass --follow"));
    assert!(!t.path("real-results").exists());

    run_native_ok(&[
        "cp",
        "--follow",
        "--results",
        &t.s("results-link"),
        &t.s("src/keep"),
        "--as",
        &t.s("results-output"),
    ]);
    assert!(!read(&t.path("real-results")).is_empty());

    run_native_ok(&[
        "cp",
        "--ignore-from",
        "/dev/null",
        "--srcs-in",
        &t.s("src"),
        "--into",
        &t.s("device-input-output"),
    ]);
    assert_eq!(read(&t.path("device-input-output/keep")), b"data");
}

#[cfg(debug_assertions)]
#[test]
fn control_input_replacement_symlinks_cannot_redirect_reads() {
    use std::os::unix::fs::symlink;

    for family in ["native-ignore", "rsync-ignore", "files-from", "mapping"] {
        let t = Tmp::new();
        write(&t.path("src/keep"), b"data");
        let selected = t.path("selected-control");
        let outside = t.path("outside-control");
        let control_contents = if family == "mapping" {
            entry_line("keep", "keep", None)
        } else if family == "files-from" {
            "keep\n".to_string()
        } else {
            "# no exclusions\n".to_string()
        };
        write(&selected, control_contents.as_bytes());
        write(&outside, control_contents.as_bytes());
        let destination = t.path("dst");
        let ready = t.path("control-ready");
        let continuation = t.path("control-continue");
        let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
        match family {
            "native-ignore" => {
                command
                    .args(["cp", "--ignore-from"])
                    .arg(&selected)
                    .arg("--srcs-in")
                    .arg(t.path("src"))
                    .arg("--into")
                    .arg(&destination)
                    .arg("-q");
            }
            "rsync-ignore" => {
                command
                    .args(["rsync", "-a", "--syq-ignore-from"])
                    .arg(&selected)
                    .arg(t.s("src/"))
                    .arg(&destination)
                    .arg("--no-progress");
            }
            "files-from" => {
                command
                    .args(["rsync", "-a", "--files-from"])
                    .arg(&selected)
                    .arg(t.path("src"))
                    .arg(&destination)
                    .arg("--no-progress");
            }
            "mapping" => {
                command
                    .args(["cp", "--mapping"])
                    .arg(&selected)
                    .arg("-C")
                    .arg(t.path("src"))
                    .arg("--into")
                    .arg(&destination)
                    .arg("-q");
            }
            _ => unreachable!(),
        }
        let mut child = start_held_control_path(&mut command, &selected, &ready, &continuation);
        wait_for_control_path_selection(&mut child, &ready);

        fs::rename(&selected, t.path("original-control")).unwrap();
        symlink(&outside, &selected).unwrap();

        release_confinement_barrier(&continuation);
        let output = wait_for_control_path_output(child);
        assert!(
            !output.status.success(),
            "{family} followed a replacement symlink"
        );
        assert!(
            stderr_of(&output).contains("operator file"),
            "{family}: {}",
            stderr_of(&output)
        );
        assert!(
            !destination.exists(),
            "{family} mutated its destination after the control-path race"
        );
    }
}

#[cfg(debug_assertions)]
#[test]
fn regular_control_input_raced_to_fifo_fails_without_blocking() {
    let t = Tmp::new();
    write(&t.path("src/keep"), b"data");
    let selected = t.path("selected-control");
    write(&selected, b"# no exclusions\n");
    let destination = t.path("dst");
    let ready = t.path("control-ready");
    let continuation = t.path("control-continue");
    let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
    command
        .args(["cp", "--ignore-from"])
        .arg(&selected)
        .arg("--srcs-in")
        .arg(t.path("src"))
        .arg("--into")
        .arg(&destination)
        .arg("-q");
    let mut child = start_held_control_path(&mut command, &selected, &ready, &continuation);
    wait_for_control_path_selection(&mut child, &ready);

    fs::rename(&selected, t.path("original-control")).unwrap();
    mkfifo(&selected);

    release_confinement_barrier(&continuation);
    let output = wait_for_control_path_output(child);
    assert!(!output.status.success());
    assert!(
        stderr_of(&output).contains("changed identity"),
        "{}",
        stderr_of(&output)
    );
    assert!(!destination.exists());
}

#[cfg(all(debug_assertions, target_os = "linux"))]
#[test]
fn selected_fifo_replacement_reads_the_retained_fifo() {
    use std::sync::mpsc;

    let t = Tmp::new();
    write(&t.path("src/keep"), b"data");
    let selected = t.path("selected-control");
    mkfifo(&selected);
    let destination = t.path("dst");
    let ready = t.path("control-ready");
    let continuation = t.path("control-continue");
    let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
    command
        .args(["cp", "--ignore-from"])
        .arg(&selected)
        .arg("--srcs-in")
        .arg(t.path("src"))
        .arg("--into")
        .arg(&destination)
        .arg("-q");
    let mut child = start_held_control_path(&mut command, &selected, &ready, &continuation);
    wait_for_control_path_selection(&mut child, &ready);

    let original = t.path("original-control");
    fs::rename(&selected, &original).unwrap();
    mkfifo(&selected);
    let (writer_tx, writer_rx) = mpsc::sync_channel(1);
    let writer = std::thread::spawn(move || {
        let result = File::options()
            .write(true)
            .open(original)
            .and_then(|mut file| file.write_all(b"# no exclusions\n"));
        writer_tx.send(result).unwrap();
    });

    release_confinement_barrier(&continuation);
    let output = wait_for_control_path_output(child);
    let used_retained_fifo = match writer_rx.recv_timeout(std::time::Duration::from_secs(2)) {
        Ok(result) => {
            result.expect("retained FIFO writer failed");
            true
        }
        Err(_) => {
            // Unblock the owned writer so a failed assertion never leaks a thread.
            let _rescue = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(t.path("original-control"))
                .unwrap();
            writer_rx
                .recv_timeout(std::time::Duration::from_secs(1))
                .expect("FIFO writer did not finish after rescue")
                .unwrap();
            false
        }
    };
    writer.join().unwrap();
    assert!(
        used_retained_fifo,
        "syq opened the replacement FIFO instead of its retained selection"
    );
    assert_output_ok(&output);
    assert_eq!(read(&t.path("dst/keep")), b"data");
}

#[cfg(all(debug_assertions, target_os = "linux"))]
#[test]
fn trusted_control_symlink_target_is_read_from_the_opened_link() {
    use std::os::unix::fs::symlink;

    let t = Tmp::new();
    write(&t.path("src/keep"), b"keep");
    write(&t.path("src/drop"), b"drop");
    write(&t.path("original-rules"), b"drop\n");
    write(&t.path("replacement-rules"), b"keep\n");
    let selected = t.path("selected-control-link");
    symlink("original-rules", &selected).unwrap();
    let destination = t.path("dst");
    let ready = t.path("symlink-ready");
    let release = t.path("symlink-release");

    let mut child = compat_command()
        .args(["-a", "--syq-ignore-from"])
        .arg(&selected)
        .arg(t.s("src/"))
        .arg(&destination)
        .arg("--no-progress")
        .env(
            "SYQ_TEST_OPERATOR_SYMLINK_COMPONENT",
            "selected-control-link",
        )
        .env("SYQ_TEST_OPERATOR_SYMLINK_READY_FILE", &ready)
        .env("SYQ_TEST_OPERATOR_SYMLINK_RELEASE_FILE", &release)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .start()
        .unwrap();
    wait_for_control_path_selection(&mut child, &ready);

    fs::rename(&selected, t.path("moved-control-link")).unwrap();
    symlink("replacement-rules", &selected).unwrap();
    write(&release, b"continue");

    let output = wait_for_control_path_output(child);
    assert_output_ok(&output);
    assert_eq!(listing(&destination), ["keep"]);
}

#[test]
fn dry_run_accounts_for_changed_symlinks_and_type_replacements() {
    let t = Tmp::new();
    fs::create_dir_all(t.path("src")).unwrap();
    fs::create_dir_all(t.path("dst")).unwrap();
    std::os::unix::fs::symlink("new-target", t.path("src/link")).unwrap();
    std::os::unix::fs::symlink("old-target", t.path("dst/link")).unwrap();
    write(&t.path("src/replaced"), b"file");
    std::os::unix::fs::symlink("old-target", t.path("dst/replaced")).unwrap();
    set_mtime(&t.path("src"), 1_600_000_100);
    set_mtime(&t.path("dst"), 1_600_000_100);

    let out = run_ok(&["-anv", &t.s("src/"), &t.s("dst")]);
    assert!(
        out.contains("changes: 1 regular file; 1 symlink; 1 type replacement among them"),
        "{out}"
    );
    assert!(
        out.contains(&format!(
            "update symlink {} -> new-target (target differs)",
            t.s("dst/link")
        )),
        "{out}"
    );
    assert!(
        out.contains(&format!(
            "replace with file {} (destination is symlink)",
            t.s("dst/replaced")
        )),
        "{out}"
    );
    assert!(
        out.contains("4 B in 1 file needing content work (upper bound)"),
        "{out}"
    );
    assert_eq!(
        fs::read_link(t.path("dst/link")).unwrap(),
        PathBuf::from("old-target")
    );
    assert!(t
        .path("dst/replaced")
        .symlink_metadata()
        .unwrap()
        .is_symlink());
}

#[test]
fn dry_run_directory_conflict_does_not_inspect_symlink_descendants() {
    let t = Tmp::new();
    write(&t.path("src/d/sub/f"), b"source");
    write(&t.path("outside/sub/f"), b"keep");
    fs::create_dir_all(t.path("dst")).unwrap();
    std::os::unix::fs::symlink(t.path("outside"), t.path("dst/d")).unwrap();

    for flags in ["-anv", "-av"] {
        let out = syq(&[flags, &t.s("src/"), &t.s("dst")]);
        assert_eq!(out.status.code(), Some(23), "{out:?}");
        assert!(
            stderr_of(&out).contains("cannot replace non-directory"),
            "{out:?}"
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(!stdout.contains("create file"), "{stdout}");
        assert!(t.path("dst/d").symlink_metadata().unwrap().is_symlink());
        assert_eq!(read(&t.path("outside/sub/f")), b"keep");
    }
}

#[test]
fn inplace_replaces_symlink_dest_not_its_target() {
    let t = Tmp::new();
    write(&t.path("src"), b"SRCDATA");
    write(&t.path("external"), b"EXTERNAL");
    std::os::unix::fs::symlink("external", t.path("link")).unwrap();
    run_ok(&["-a", "--inplace", &t.s("src"), &t.s("link")]);
    // The symlink target must be untouched; the dest is now a regular file.
    assert_eq!(read(&t.path("external")), b"EXTERNAL");
    assert!(fs::symlink_metadata(t.path("link"))
        .unwrap()
        .file_type()
        .is_file());
    assert_eq!(read(&t.path("link")), b"SRCDATA");
}

#[test]
fn many_symlinks_no_setmeta_race() {
    let t = Tmp::new();
    fs::create_dir_all(t.path("ln")).unwrap();
    for i in 0..100 {
        std::os::unix::fs::symlink(format!("/target{i}"), t.path(&format!("ln/l{i}"))).unwrap();
    }
    run_ok(&["-a", &t.s("ln"), &t.s("dst")]);
    let n = fs::read_dir(t.path("dst/ln")).unwrap().count();
    assert_eq!(n, 100);
}

#[cfg(debug_assertions)]
#[test]
fn partial_symlink_is_not_followed() {
    let t = Tmp::new();
    write(&t.path("src"), &vec![7u8; 5 * 1024 * 1024]);
    write(&t.path("external"), b"EXTERNAL-DO-NOT-TOUCH");
    let src = t.s("src");
    let dst = t.s("out");
    let args = ["-a", "--resource-limits", "bandwidth=1G", &src, &dst];
    let partial = interrupted_partial(&args, &t.0);
    fs::remove_file(&partial).unwrap();
    // A malicious/stale partial symlink pointing outside must not be followed.
    std::os::unix::fs::symlink("external", &partial).unwrap();
    run_ok(&args);
    assert_eq!(read(&t.path("external")), b"EXTERNAL-DO-NOT-TOUCH");
    assert!(fs::symlink_metadata(t.path("out"))
        .unwrap()
        .file_type()
        .is_file());
    assert_eq!(read(&t.path("out")).len(), 5 * 1024 * 1024);
}

#[test]
fn verify_only_detects_symlink_difference() {
    let t = Tmp::new();
    fs::create_dir_all(t.path("s")).unwrap();
    fs::create_dir_all(t.path("d")).unwrap();
    std::os::unix::fs::symlink("target-a", t.path("s/l")).unwrap();
    std::os::unix::fs::symlink("target-b", t.path("d/l")).unwrap();
    let out = syq(&[
        "-a",
        "--syq-verify-only",
        &format!("{}/", t.s("s")),
        &format!("{}/", t.s("d")),
    ]);
    assert_eq!(out.status.code(), Some(23));
    assert!(String::from_utf8_lossy(&out.stderr).contains("DIFFERS"));
}

#[test]
fn rsync_control_inputs_follow_links_owned_by_the_effective_user() {
    use std::os::unix::fs::symlink;

    let t = Tmp::new();
    write(&t.path("src/keep"), b"keep");
    write(&t.path("src/drop"), b"drop");
    write(&t.path("patterns"), b"drop\n");
    write(&t.path("list"), b"keep\n");
    symlink("patterns", t.path("patterns-link")).unwrap();
    symlink("list", t.path("list-link")).unwrap();

    run_ok(&[
        "-a",
        "--syq-ignore-from",
        &t.s("patterns-link"),
        &t.s("src/"),
        &t.s("ignored"),
    ]);
    assert_eq!(listing(&t.path("ignored")), ["keep"]);

    run_ok(&[
        "-a",
        "--files-from",
        &t.s("list-link"),
        &t.s("src"),
        &t.s("listed"),
    ]);
    assert_eq!(listing(&t.path("listed")), ["keep"]);
}

#[test]
fn files_from_rejects_symlinked_ancestors_and_recurses_only_listed_dirs() {
    let t = Tmp::new();
    write(&t.path("outside/secret"), b"secret");
    fs::create_dir_all(t.path("src/a")).unwrap();
    std::os::unix::fs::symlink("../outside", t.path("src/link")).unwrap();
    write(&t.path("src/a/listed"), b"l");
    write(&t.path("src/a/unlisted"), b"u");
    write(&t.path("list"), b"link/secret\na/listed\n");
    let out = syq(&[
        "-a",
        "-r",
        "--files-from",
        &t.s("list"),
        &t.s("src"),
        &t.s("dst"),
    ]);
    // SYQ deliberately refuses this earlier than hardened rsync 3.5: neither
    // follows the implied source ancestor and both exit 23, but SYQ also avoids
    // emitting the implied destination directory. Other valid paths complete.
    assert_eq!(out.status.code(), Some(23));
    assert!(stderr_of(&out).contains("link is not a directory"));
    assert_eq!(listing(&t.path("dst")), ["a", "a/listed"]);
    assert!(!t.path("dst/link/secret").exists());

    // The ownership opt-out keeps descendant traversal confined too.
    let out = syq(&[
        "-a",
        "-r",
        "--insecure-links",
        "--files-from",
        &t.s("list"),
        &t.s("src"),
        &t.s("dst-insecure"),
    ]);
    assert_eq!(out.status.code(), Some(23));
    assert_eq!(listing(&t.path("dst-insecure")), ["a", "a/listed"]);
    assert!(!t.path("dst-insecure/link/secret").exists());

    // An ancestor that resolves to a file, or dangles, is an error.
    std::os::unix::fs::symlink("a/listed", t.path("src/tofile")).unwrap();
    std::os::unix::fs::symlink("nowhere", t.path("src/dangling")).unwrap();
    write(&t.path("list2"), b"tofile/x\ndangling/y\n");
    let out = syq(&[
        "-a",
        "--insecure-links",
        "--files-from",
        &t.s("list2"),
        &t.s("src"),
        &t.s("dst2"),
    ]);
    assert_eq!(out.status.code(), Some(23));
    let se = stderr_of(&out);
    assert!(
        se.contains("tofile is not a directory") && se.contains("dangling is not a directory"),
        "{se}"
    );
    assert_eq!(listing(&t.path("dst2")), Vec::<String>::new());

    // Listing a symlink itself and a path through it conflicts; the path is
    // refused rather than written through the destination symlink.
    write(&t.path("list3"), b"link\nlink/secret\n");
    let out = syq(&[
        "-a",
        "--insecure-links",
        "--files-from",
        &t.s("list3"),
        &t.s("src"),
        &t.s("dst3"),
    ]);
    assert_eq!(out.status.code(), Some(23));
    assert!(stderr_of(&out).contains("link is not a directory"));
    assert!(t.path("dst3/link").symlink_metadata().unwrap().is_symlink());
    assert!(!t.path("outside/secret2").exists());
}

#[test]
fn delete_with_inplace_replacing_many_symlinks() {
    let t = Tmp::new();
    fs::create_dir_all(t.path("dst")).unwrap();
    for i in 0..3000 {
        write(&t.path(&format!("src/f{i}")), b"file now");
        std::os::unix::fs::symlink("nowhere", t.path(&format!("dst/f{i}"))).unwrap();
    }
    let so = run_ok(&[
        "-a",
        "--inplace",
        "--delete",
        "--performance-tuning",
        "workers=16",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert!(!so.contains("errors"), "{so}");
    assert_eq!(read(&t.path("dst/f2999")), b"file now");
}

#[test]
fn existing_does_not_write_through_a_destination_symlink_dir() {
    // An in-tree destination symlink is a payload conflict (replaced in a
    // normal run, never traversed); --existing replaces nothing, so it and
    // everything below it are left alone.
    let t = Tmp::new();
    write(&t.path("src/d/f"), b"new");
    write(&t.path("src/d/sub/g"), b"new");
    write(&t.path("elsewhere/f"), b"old");
    write(&t.path("elsewhere/sub/g"), b"old");
    fs::create_dir_all(t.path("dst")).unwrap();
    std::os::unix::fs::symlink(t.path("elsewhere"), t.path("dst/d")).unwrap();
    set_mtime(&t.path("src/d/f"), 2000);
    set_mtime(&t.path("elsewhere/f"), 1000);
    let so = run_ok(&["-a", "--existing", &t.s("src/"), &t.s("dst")]);
    assert_eq!(read(&t.path("elsewhere/f")), b"old", "{so}");
    assert_eq!(read(&t.path("elsewhere/sub/g")), b"old", "{so}");
    assert!(t.path("dst/d").symlink_metadata().unwrap().is_symlink());
    let so = run_ok(&["-a", "-n", "--existing", &t.s("src/"), &t.s("dst")]);
    assert!(so.contains("0 files needing content work"), "{so}");
}

#[test]
fn files_from_root_may_be_a_symlink_and_root_lines_are_rejected() {
    let t = Tmp::new();
    write(&t.path("real/f"), b"f");
    std::os::unix::fs::symlink(t.path("real"), t.path("link")).unwrap();
    write(&t.path("list"), b"f\n");
    run_ok(&[
        "-a",
        "--files-from",
        &t.s("list"),
        &t.s("link"),
        &t.s("dst"),
    ]);
    assert_eq!(read(&t.path("dst/f")), b"f");
    write(&t.path("bad"), b"././//\n");
    let out = syq(&[
        "-a",
        "--files-from",
        &t.s("bad"),
        &t.s("real"),
        &t.s("dst2"),
    ]);
    assert!(!out.status.success());
    assert!(
        stderr_of(&out).contains("names the source root"),
        "{}",
        stderr_of(&out)
    );
}

// A destination given as a symlink to a directory is that directory, whether
// or not it's spelled with a trailing slash: the link survives, the payload
// lands in its target.
#[test]
fn symlink_destination_is_followed() {
    for spelling in ["link", "link/"] {
        let t = Tmp::new();
        write(&t.path("src/f"), b"hi");
        fs::create_dir_all(t.path("real")).unwrap();
        std::os::unix::fs::symlink("real", t.path("link")).unwrap();
        run_ok(&["-a", &t.s("src/"), &t.s(spelling)]);
        assert!(
            fs::symlink_metadata(t.path("link"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "{spelling}: the symlink must survive"
        );
        assert_eq!(read(&t.path("real/f")), b"hi", "{spelling}");
    }
    let t = Tmp::new();
    write(&t.path("src/f"), b"hi");
    fs::create_dir_all(t.path("real")).unwrap();
    std::os::unix::fs::symlink("real", t.path("link")).unwrap();
    run_ok(&["-a", &t.s("src"), &t.s("link")]);
    assert!(fs::symlink_metadata(t.path("link"))
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(read(&t.path("real/src/f")), b"hi");
}

#[test]
fn foreign_owned_destination_root_symlink_is_refused() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let t = Tmp::new();
    write(&t.path("src/f"), b"payload");
    fs::create_dir_all(t.path("outside")).unwrap();
    std::os::unix::fs::symlink(t.path("outside"), t.path("dst")).unwrap();
    let foreign_uid = 65_534;
    std::os::unix::fs::lchown(t.path("dst"), Some(foreign_uid), Some(foreign_uid)).unwrap();

    let refused = syq(&["-a", &t.s("src/"), &t.s("dst/")]);
    assert!(!refused.status.success(), "foreign-owned link was followed");
    assert!(
        stderr_of(&refused).contains("refusing symlink component"),
        "{}",
        stderr_of(&refused)
    );
    assert!(!t.path("outside/f").exists());

    let opted_out = syq(&["-a", "--insecure-links", &t.s("src/"), &t.s("dst/")]);
    assert_output_ok(&opted_out);
    assert_eq!(read(&t.path("outside/f")), b"payload");

    // The opt-out is local only: a remote destination keeps refusing the link.
    fs::remove_file(t.path("outside/f")).unwrap();
    let rsh = fake_rsh(&t);
    t.expose_remote_syq();
    let remote = format!("fake:{}/", t.s("dst"));
    let refused = remote_syq(
        &t,
        &rsh,
        &[
            "-a",
            "--syq-no-bootstrap",
            "--insecure-links",
            &t.s("src/"),
            &remote,
        ],
    );
    assert!(
        !refused.status.success(),
        "remote foreign-owned link was followed"
    );
    assert!(
        stderr_of(&refused).contains("refusing symlink component"),
        "{}",
        stderr_of(&refused)
    );
    assert!(!t.path("outside/f").exists());
}

#[cfg(debug_assertions)]
#[test]
fn destination_root_replacement_after_selection_cannot_redirect_worker() {
    for no_tcp in [false, true] {
        let t = Tmp::new();
        write(&t.path("src/f"), b"payload");
        fs::create_dir_all(t.path("dst")).unwrap();
        fs::create_dir_all(t.path("outside")).unwrap();
        let ready = t.path("anchor-ready");
        let continuation = t.path("continue");

        let mut command = compat_command();
        command.args([
            "-a",
            "--performance-tuning",
            "workers=1",
            &t.s("src/"),
            &t.s("dst/"),
        ]);
        if no_tcp {
            command.arg("--syq-no-tcp");
        }
        let mut child = command
            .arg("--no-progress")
            .env("SYQ_TEST_DESTINATION_ANCHORED_FILE", &ready)
            .env("SYQ_TEST_DESTINATION_ANCHOR_CONTINUE_FILE", &continuation)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .start()
            .unwrap();

        wait_for_confinement_marker(&mut child, &ready, "destination anchor");

        fs::rename(t.path("dst"), t.path("selected-and-moved")).unwrap();
        std::os::unix::fs::symlink(t.path("outside"), t.path("dst")).unwrap();

        release_confinement_barrier(&continuation);
        let output = child.wait_with_output().unwrap();
        assert_output_ok(&output);
        assert_eq!(read(&t.path("selected-and-moved/f")), b"payload");
        assert!(!t.path("outside/f").exists());
        assert!(fs::symlink_metadata(t.path("dst"))
            .unwrap()
            .file_type()
            .is_symlink());
    }
}

#[cfg(debug_assertions)]
#[test]
fn destination_file_write_refuses_descendant_symlink_swap() {
    for no_tcp in [false, true] {
        let t = Tmp::new();
        let contents = vec![b'x'; 8 * 1024 * 1024];
        write(&t.path("src/victim/file"), &contents);
        fs::create_dir_all(t.path("dst/victim")).unwrap();
        write(&t.path("outside/sentinel"), b"outside");

        let ready = t.path("partial-ready");
        let continuation = t.path("partial-continue");
        let mut command = compat_command();
        command.args([
            "-a",
            "--resource-limits",
            "bandwidth=1G",
            "--performance-tuning",
            "workers=1",
            &t.s("src/"),
            &t.s("dst/"),
        ]);
        if no_tcp {
            command.arg("--syq-no-tcp");
        }
        let mut child = command
            .arg("--no-progress")
            .env("SYQ_TEST_PARTIAL_READY_FILE", &ready)
            .env("SYQ_TEST_PARTIAL_CONTINUE_FILE", &continuation)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .start()
            .unwrap();

        wait_for_confinement_marker(&mut child, &ready, "partial preparation");
        assert_eq!(partial_files(&t.path("dst/victim")).len(), 1);

        fs::rename(t.path("dst/victim"), t.path("displaced-victim")).unwrap();
        std::os::unix::fs::symlink(t.path("outside"), t.path("dst/victim")).unwrap();

        release_confinement_barrier(&continuation);
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(23), "{}", stderr_of(&output));
        assert_eq!(read(&t.path("outside/sentinel")), b"outside");
        assert!(!t.path("outside/file").exists());
        assert!(!t.path("displaced-victim/file").exists());
        assert_eq!(partial_files(&t.path("displaced-victim")).len(), 1);
        assert!(fs::symlink_metadata(t.path("dst/victim"))
            .unwrap()
            .file_type()
            .is_symlink());
    }
}

#[cfg(debug_assertions)]
#[test]
fn destination_prune_scan_uses_retained_root_after_replacement() {
    for no_tcp in [false, true] {
        let t = Tmp::new();
        fs::create_dir_all(t.path("src")).unwrap();
        write(&t.path("dst/extra"), b"extra");
        write(&t.path("outside/sentinel"), b"outside");
        let ready = t.path("anchor-ready");
        let continuation = t.path("continue");

        let mut command = compat_command();
        command.args([
            "-a",
            "--delete",
            "--performance-tuning",
            "workers=1",
            &t.s("src/"),
            &t.s("dst/"),
        ]);
        if no_tcp {
            command.arg("--syq-no-tcp");
        }
        let mut child = command
            .arg("--no-progress")
            .env("SYQ_TEST_DESTINATION_ANCHORED_FILE", &ready)
            .env("SYQ_TEST_DESTINATION_ANCHOR_CONTINUE_FILE", &continuation)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .start()
            .unwrap();

        wait_for_confinement_marker(&mut child, &ready, "destination anchor");

        fs::rename(t.path("dst"), t.path("selected-and-moved")).unwrap();
        std::os::unix::fs::symlink(t.path("outside"), t.path("dst")).unwrap();

        release_confinement_barrier(&continuation);
        let output = child.wait_with_output().unwrap();
        assert_output_ok(&output);
        assert!(!t.path("selected-and-moved/extra").exists());
        assert_eq!(read(&t.path("outside/sentinel")), b"outside");
        assert!(fs::symlink_metadata(t.path("dst"))
            .unwrap()
            .file_type()
            .is_symlink());
    }
}

#[cfg(debug_assertions)]
#[test]
fn destination_prune_scan_refuses_descendant_symlink_swap() {
    for no_tcp in [false, true] {
        let t = Tmp::new();
        fs::create_dir_all(t.path("src/victim")).unwrap();
        write(&t.path("dst/victim/extra"), b"extra");
        write(&t.path("outside/sentinel"), b"outside");
        let ready = t.path("scan-ready");
        let continuation = t.path("continue");

        let mut command = compat_command();
        command.args([
            "-a",
            "--delete",
            "--performance-tuning",
            "workers=1",
            &t.s("src/"),
            &t.s("dst/"),
        ]);
        if no_tcp {
            command.arg("--syq-no-tcp");
        }
        let mut child = command
            .arg("--no-progress")
            .env("SYQ_TEST_HOLD_DESTINATION_SCAN_DIRECTORY", "victim")
            .env("SYQ_TEST_DESTINATION_SCAN_DIRECTORY_READY_FILE", &ready)
            .env(
                "SYQ_TEST_DESTINATION_SCAN_DIRECTORY_CONTINUE_FILE",
                &continuation,
            )
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .start()
            .unwrap();

        wait_for_confinement_marker(&mut child, &ready, "destination scan directory");

        fs::rename(t.path("dst/victim"), t.path("displaced-victim")).unwrap();
        std::os::unix::fs::symlink(t.path("outside"), t.path("dst/victim")).unwrap();

        release_confinement_barrier(&continuation);
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(23), "{}", stderr_of(&output));
        assert!(
            stderr_of(&output).contains("delete victim/extra"),
            "{}",
            stderr_of(&output)
        );
        assert_eq!(read(&t.path("outside/sentinel")), b"outside");
        assert_eq!(read(&t.path("displaced-victim/extra")), b"extra");
        assert!(fs::symlink_metadata(t.path("dst/victim"))
            .unwrap()
            .file_type()
            .is_symlink());
    }
}

#[test]
fn in_tree_destination_symlink_blocks_directory_copy() {
    let t = Tmp::new();
    write(&t.path("src/sub/f"), b"payload");
    fs::create_dir_all(t.path("dst")).unwrap();
    fs::create_dir_all(t.path("elsewhere")).unwrap();
    std::os::unix::fs::symlink("../elsewhere", t.path("dst/sub")).unwrap();

    let out = syq(&["-a", &t.s("src/"), &t.s("dst/")]);

    assert_eq!(out.status.code(), Some(23), "{out:?}");
    assert!(stderr_of(&out).contains("cannot replace non-directory"));
    assert!(fs::symlink_metadata(t.path("dst/sub"))
        .unwrap()
        .is_symlink());
    assert!(!t.path("elsewhere/f").exists());
}

#[test]
fn destination_root_symlink_preserves_target_metadata_for_both_spellings() {
    for spelling in ["link", "link/"] {
        let t = Tmp::new();
        write(&t.path("src/f"), b"payload");
        fs::set_permissions(t.path("src"), fs::Permissions::from_mode(0o555)).unwrap();
        set_mtime(&t.path("src"), 1_600_000_000);
        fs::create_dir_all(t.path("real")).unwrap();
        std::os::unix::fs::symlink("real", t.path("link")).unwrap();

        run_ok(&["-a", &t.s("src/"), &t.s(spelling)]);

        let metadata = fs::metadata(t.path("real")).unwrap();
        assert_eq!(metadata.mode() & 0o777, 0o555, "{spelling}");
        assert_eq!(metadata.mtime(), 1_600_000_000, "{spelling}");
        assert_eq!(read(&t.path("real/f")), b"payload", "{spelling}");
        assert!(fs::symlink_metadata(t.path("link"))
            .unwrap()
            .file_type()
            .is_symlink());
    }
}

// The copy-into-itself guard resolves paths the way the kernel does: `..`
// after a symlink pops the link's target, so a destination that physically
// lands inside the source is refused even when it lexically looks elsewhere.
#[test]
fn self_copy_guard_sees_through_symlinks() {
    let t = Tmp::new();
    write(&t.path("src/inner/f"), b"x");
    std::os::unix::fs::symlink(t.path("src/inner"), t.path("link")).unwrap();
    // link/../out == src/out: inside the source.
    let out = syq(&["-a", &t.s("src/"), &t.s("link/../out/")]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("into itself"), "stderr: {err}");
    assert!(!t.path("src/out").exists());
}

#[test]
fn existing_opens_up_readonly_dirs_even_after_a_symlinked_dir() {
    let t = Tmp::new();
    write(&t.path("src/s/x"), b"x");
    write(&t.path("src/r/y"), b"new");
    write(&t.path("elsewhere/x"), b"x");
    write(&t.path("dst/r/y"), b"old");
    set_mtime(&t.path("src/r/y"), 2000);
    set_mtime(&t.path("dst/r/y"), 1000);
    // `s` sorts before `r`? No — make the symlinked dir sort first explicitly.
    fs::rename(t.path("src/s"), t.path("src/a")).unwrap();
    std::os::unix::fs::symlink(t.path("elsewhere"), t.path("dst/a")).unwrap();
    fs::set_permissions(t.path("dst/r"), fs::Permissions::from_mode(0o500)).unwrap();
    let so = run_ok(&["-rt", "--existing", &t.s("src/"), &t.s("dst")]);
    assert_eq!(read(&t.path("dst/r/y")), b"new", "{so}");
    assert_eq!(read(&t.path("elsewhere/x")), b"x");
}

#[test]
fn files_from_symlink_conflict_is_order_independent() {
    let t = Tmp::new();
    write(&t.path("outside/secret"), b"s");
    fs::create_dir_all(t.path("src")).unwrap();
    std::os::unix::fs::symlink("../outside", t.path("src/link")).unwrap();
    for (n, list) in [("1", "link\nlink/secret\n"), ("2", "link/secret\nlink\n")] {
        write(&t.path(&format!("list{n}")), list.as_bytes());
        let out = syq(&[
            "-a",
            "--files-from",
            &t.s(&format!("list{n}")),
            &t.s("src"),
            &t.s(&format!("dst{n}")),
        ]);
        assert_eq!(
            out.status.code(),
            Some(23),
            "order {n}: {}",
            stderr_of(&out)
        );
        let md = t.path(&format!("dst{n}/link")).symlink_metadata().unwrap();
        // The listed symlink itself is preserved in either order, while the
        // path through it is rejected before any implied directory is emitted.
        assert!(md.is_symlink());
        assert!(!t.path("outside/secret2").exists());
    }
}

#[test]
fn files_from_self_copy_through_symlinked_root_is_rejected() {
    let t = Tmp::new();
    write(&t.path("real/a"), b"a");
    fs::create_dir_all(t.path("real/dstdir")).unwrap();
    std::os::unix::fs::symlink(t.path("real"), t.path("link")).unwrap();
    write(&t.path("list"), b"a\n");
    let out = syq(&[
        "-a",
        "-r",
        "--files-from",
        &t.s("list"),
        &t.s("link"),
        &t.s("real/dstdir"),
    ]);
    assert!(!out.status.success(), "{}", stderr_of(&out));
    assert!(
        stderr_of(&out).contains("maps inside source")
            || stderr_of(&out).contains("same directory"),
        "{}",
        stderr_of(&out)
    );
    assert_eq!(listing(&t.path("real")), ["a", "dstdir"], "nothing copied");
}

#[test]
fn pscope_is_shared_by_transfer_surfaces_and_refuses_unrelated_directories() {
    let t = Tmp::new();
    fs::create_dir(t.runtime()).unwrap();
    let scope = ephemeral_scope(&t);
    write(&t.path("src/a"), b"a");

    let old_spelling = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["rsync", "-a", "--pscope"])
        .arg(&scope)
        .args([&t.s("src/"), &t.s("old-spelling"), "--no-progress"])
        .run()
        .unwrap();
    assert_eq!(old_spelling.status.code(), Some(2));
    assert!(stderr_of(&old_spelling).contains("unexpected argument '--pscope'"));

    let compat = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["rsync", "-a", "--syq-pscope"])
        .arg(&scope)
        .args([&t.s("src/"), &t.s("compat"), "--no-progress"])
        .env("XDG_CONFIG_HOME", t.path("config"))
        .env("XDG_RUNTIME_DIR", t.runtime())
        .run()
        .unwrap();
    assert_output_ok(&compat);
    assert_eq!(read(&t.path("compat/a")), b"a");

    write(&t.path("remove-me"), b"gone");
    let removal = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["rm", "--pscope"])
        .arg(&scope)
        .args(["--src", "remove-me", "-q"])
        .current_dir(&t.0)
        .env("XDG_CONFIG_HOME", t.path("config"))
        .env("XDG_RUNTIME_DIR", t.runtime())
        .run()
        .unwrap();
    assert_output_ok(&removal);
    assert!(!t.path("remove-me").exists());

    let map = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["map", "--pscope"])
        .arg(&scope)
        .args(["--src", &t.s("src/a")])
        .run()
        .unwrap();
    assert!(!map.status.success());
    assert!(
        stderr_of(&map).contains("unexpected argument '--pscope'"),
        "{}",
        stderr_of(&map)
    );

    let victim = t.path("victim");
    fs::create_dir(&victim).unwrap();
    fs::set_permissions(&victim, fs::Permissions::from_mode(0o755)).unwrap();
    let attack = t.path("not-a-scope");
    std::os::unix::fs::symlink(&victim, &attack).unwrap();
    let refused = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["cp", "--pscope"])
        .arg(&attack)
        .args([
            "--src",
            &t.s("src/a"),
            "--to",
            "backup.example",
            "--as",
            &t.s("no-copy"),
            "-q",
        ])
        .env("XDG_CONFIG_HOME", t.path("config"))
        .env("XDG_RUNTIME_DIR", t.runtime())
        .run()
        .unwrap();
    assert!(!refused.status.success());
    assert_eq!(
        fs::metadata(&victim).unwrap().permissions().mode() & 0o777,
        0o755
    );
}

#[test]
fn partial_candidates_do_not_break_empty_replacement_or_unchanged_files() {
    for candidate in [".out.syq-tmp.abcdefghijklmnop", ".syq-tmp.abcdefghijklmnop"] {
        for empty in [true, false] {
            let t = Tmp::new();
            let source = if empty { vec![] } else { vec![b'a'; 5 << 20] };
            write(&t.path("src"), &source);
            write(
                &t.path("out"),
                if empty { b"old contents" } else { &source },
            );
            write(&t.path(candidate), b"stale");
            let before = fs::metadata(t.path("out")).unwrap().ino();
            run_native_ok(&["cp", "--hash", &t.s("src"), "--as", &t.s("out")]);
            assert_eq!(read(&t.path("out")), source);
            if !empty {
                assert_eq!(fs::metadata(t.path("out")).unwrap().ino(), before);
            }
            assert_eq!(read(&t.path(candidate)), b"stale");
            assert_eq!(partial_files(&t.0).len(), 1);
        }
    }
}

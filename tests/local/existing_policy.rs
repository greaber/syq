use super::*;

#[test]
fn default_errors_on_different_contents_without_changing_metadata() {
    let t = Tmp::new();
    write(&t.path("src"), b"source");
    write(&t.path("dst"), b"target");
    set_mtime(&t.path("src"), 123);
    set_mtime(&t.path("dst"), 456);
    fs::set_permissions(t.path("src"), fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o640)).unwrap();
    for extra in ["--hash", "--dry-run"] {
        let output = native_syq(&[
            "cp",
            &t.s("src"),
            "--as",
            &t.s("dst"),
            "--copy-metadata=mtime,permissions",
            extra,
        ]);
        assert!(!output.status.success(), "{output:?}");
        assert_eq!(read(&t.path("dst")), b"target");
        let meta = fs::metadata(t.path("dst")).unwrap();
        assert_eq!(meta.mtime(), 456);
        assert_eq!(meta.mode() & 0o777, 0o640);
    }
}

#[test]
fn error_keep_and_update_are_distinct_policies() {
    let t = Tmp::new();
    write(&t.path("src"), b"same");
    write(&t.path("dst"), b"same");
    let error = native_syq(&["cp", &t.s("src"), "--as", &t.s("dst"), "--if-exists=error"]);
    assert!(!error.status.success());
    write(&t.path("src"), b"changed source");
    run_native_ok(&[
        "cp",
        &t.s("src"),
        "--as",
        &t.s("dst"),
        "--if-exists=keep",
        "--copy-metadata=mtime",
    ]);
    assert_eq!(read(&t.path("dst")), b"same");
    run_native_ok(&["cp", &t.s("src"), "--as", &t.s("dst"), "--if-exists=update"]);
    assert_eq!(read(&t.path("dst")), b"changed source");
}

#[test]
fn update_if_older_keeps_ties_and_newer_destinations() {
    let t = Tmp::new();
    write(&t.path("src"), b"new bytes");
    write(&t.path("dst"), b"old bytes");
    set_mtime(&t.path("src"), 123);
    for time in [123, 124] {
        set_mtime(&t.path("dst"), time);
        run_native_ok(&[
            "cp",
            &t.s("src"),
            "--as",
            &t.s("dst"),
            "--if-exists=update-if-older",
            "--hash",
        ]);
        assert_eq!(read(&t.path("dst")), b"old bytes");
    }
    set_mtime(&t.path("dst"), 122);
    run_native_ok(&[
        "cp",
        &t.s("src"),
        "--as",
        &t.s("dst"),
        "--if-exists=update-if-older",
    ]);
    assert_eq!(read(&t.path("dst")), b"new bytes");
    assert_eq!(fs::metadata(t.path("dst")).unwrap().mtime(), 123);
}

#[test]
fn existing_directories_are_containers_even_for_error_policy() {
    let t = Tmp::new();
    write(&t.path("src/nested/file"), b"new");
    fs::create_dir_all(t.path("dst/nested")).unwrap();
    run_native_ok(&[
        "cp",
        "--srcs-in",
        &t.s("src"),
        "--into",
        &t.s("dst"),
        "--if-exists=error",
    ]);
    assert_eq!(read(&t.path("dst/nested/file")), b"new");
    run_native_ok(&[
        "cp",
        "--srcs-in",
        &t.s("src"),
        "--into",
        &t.s("dst"),
        "--if-exists=error",
        "--resume",
    ]);
}

#[test]
fn matching_symlink_is_accepted_and_different_target_is_rejected() {
    let t = Tmp::new();
    std::os::unix::fs::symlink("first", t.path("src")).unwrap();
    std::os::unix::fs::symlink("first", t.path("dst")).unwrap();
    run_native_ok(&["cp", &t.s("src"), "--as", &t.s("dst")]);
    fs::remove_file(t.path("src")).unwrap();
    std::os::unix::fs::symlink("second", t.path("src")).unwrap();
    let output = native_syq(&["cp", &t.s("src"), "--as", &t.s("dst")]);
    assert!(!output.status.success());
    assert_eq!(fs::read_link(t.path("dst")).unwrap(), Path::new("first"));
}

#[test]
fn update_if_older_applies_to_symlink_targets() {
    let t = Tmp::new();
    std::os::unix::fs::symlink("source", t.path("src")).unwrap();
    std::os::unix::fs::symlink("destination", t.path("dst")).unwrap();
    set_mtime(&t.path("src"), 123);
    for time in [124, 123, 122] {
        set_mtime(&t.path("dst"), time);
        run_native_ok(&[
            "cp",
            &t.s("src"),
            "--as",
            &t.s("dst"),
            "--if-exists=update-if-older",
        ]);
        assert_eq!(
            fs::read_link(t.path("dst")).unwrap(),
            Path::new(if time < 123 { "source" } else { "destination" })
        );
    }
}

#[test]
fn hardlink_followers_reject_different_contents_in_preview_and_copy() {
    for preview in [true, false] {
        let t = Tmp::new();
        write(&t.path("src/a"), b"source");
        fs::hard_link(t.path("src/a"), t.path("src/b")).unwrap();
        write(&t.path("dst/a"), b"source");
        write(&t.path("dst/b"), b"target");
        let src = t.s("src");
        let dst = t.s("dst");
        let mut args = vec![
            "cp",
            "--srcs-in",
            &src,
            "--into",
            &dst,
            "--hash",
            "--copy-metadata=hardlinks",
        ];
        if preview {
            args.push("--dry-run");
        }
        let output = native_syq(&args);
        assert!(!output.status.success(), "{output:?}");
        assert_eq!(read(&t.path("dst/a")), b"source");
        assert_eq!(read(&t.path("dst/b")), b"target");
    }
}

#[test]
fn previous_partials_are_used_only_with_resume() {
    for resume in [false, true] {
        let t = Tmp::new();
        let contents = vec![b'a'; 5 << 20];
        write(&t.path("src"), &contents);
        let partial = t.path(".out.syq-tmp.abcdefghijklmnop");
        write(&partial, &contents[..3 << 20]);
        let src = t.s("src");
        let dst = t.s("out");
        let results = t.s("results.jsonl");
        let mut args = vec![
            "cp",
            &src,
            "--as",
            &dst,
            "--hash",
            "--results",
            &results,
            "--performance-tuning=copy-path=ranges,request-size=1M",
            "--performance-tuning=comparison-block-size=1M",
        ];
        if resume {
            args.push("--resume");
        }
        let output = native_syq(&args);
        assert_output_ok(&output);
        assert_eq!(read(&t.path("out")), contents);
        assert!(partial.exists());
        let data = fs::read_to_string(results).unwrap();
        let result: serde_json::Value = serde_json::from_str(data.lines().last().unwrap()).unwrap();
        assert_eq!(
            result["bytes_unchanged"],
            if resume { 3 << 20 } else { 0 },
            "{result}"
        );
    }
}

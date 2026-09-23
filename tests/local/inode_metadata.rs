use super::*;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;

fn attr(path: &Path, name: &str) -> Option<Vec<u8>> {
    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    let name = CString::new(name).unwrap();
    let mut value = vec![0u8; 65536];
    let count = unsafe {
        libc::lgetxattr(
            path.as_ptr(),
            name.as_ptr(),
            value.as_mut_ptr().cast(),
            value.len(),
        )
    };
    if count < 0 {
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ENODATA)
        );
        return None;
    }
    value.truncate(count as usize);
    Some(value)
}

fn set_attr(path: &Path, name: &str, value: &[u8]) {
    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    let name = CString::new(name).unwrap();
    assert_eq!(
        unsafe {
            libc::lsetxattr(
                path.as_ptr(),
                name.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
            )
        },
        0,
        "{}",
        std::io::Error::last_os_error()
    );
}

fn remove_attr(path: &Path, name: &str) {
    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    let name = CString::new(name).unwrap();
    assert_eq!(
        unsafe { libc::lremovexattr(path.as_ptr(), name.as_ptr()) },
        0
    );
}

// Linux's public POSIX ACL xattr format: version, followed by tag/perms/id.
fn acl(named_permissions: u16, mask: u16) -> Vec<u8> {
    let mut bytes = 2u32.to_le_bytes().to_vec();
    for (tag, permissions, id) in [
        (1u16, 7u16, u32::MAX),
        (2, named_permissions, 12345),
        (4, 5, u32::MAX),
        (16, mask, u32::MAX),
        (32, 0, u32::MAX),
    ] {
        bytes.extend(tag.to_le_bytes());
        bytes.extend(permissions.to_le_bytes());
        bytes.extend(id.to_le_bytes());
    }
    bytes
}

fn verify_metadata(source: &Path, destination: &Path) {
    for name in ["user.binary", "user.empty", "system.posix_acl_access"] {
        assert_eq!(
            attr(source, name),
            attr(destination, name),
            "{}: {name}",
            destination.display()
        );
    }
    let a = fs::symlink_metadata(source).unwrap();
    let b = fs::symlink_metadata(destination).unwrap();
    assert_eq!(a.mode() & 0o7777, b.mode() & 0o7777);
    assert_eq!((a.uid(), a.gid()), (b.uid(), b.gid()));
    assert_eq!((a.mtime(), a.mtime_nsec()), (b.mtime(), b.mtime_nsec()));
}

#[test]
fn archival_metadata_covers_batches_local_copy_ranges_and_inplace() {
    for options in [
        vec![],
        vec!["--performance-tuning=copy-path=ranges"],
        vec!["--inplace"],
    ] {
        let t = Tmp::new();
        write(&t.path("src/small"), b"binary data");
        write(&t.path("src/large"), &prng(5 << 20, 5));
        fs::hard_link(t.path("src/large"), t.path("src/alias")).unwrap();
        for name in ["small", "large"] {
            set_attr(
                &t.path(&format!("src/{name}")),
                "user.binary",
                &[0, 255, 2, 0, 3],
            );
            set_attr(&t.path(&format!("src/{name}")), "user.empty", b"");
            set_attr(
                &t.path(&format!("src/{name}")),
                "system.posix_acl_access",
                &acl(6, 4),
            );
        }
        set_attr(&t.path("src"), "system.posix_acl_default", &acl(4, 4));
        let from = t.s("src/");
        let to = t.s("dst/");
        let mut command = vec!["-aHAX", "--numeric-ids"];
        command.extend(options);
        command.extend([from.as_str(), to.as_str()]);
        run_ok(&command);
        for name in ["small", "large", "alias"] {
            verify_metadata(
                &t.path(&format!("src/{name}")),
                &t.path(&format!("dst/{name}")),
            );
        }
        assert_eq!(
            fs::metadata(t.path("dst/large")).unwrap().ino(),
            fs::metadata(t.path("dst/alias")).unwrap().ino()
        );
        assert_eq!(
            attr(&t.path("src"), "system.posix_acl_default"),
            attr(&t.path("dst"), "system.posix_acl_default")
        );
        for name in ["small", "large"] {
            set_attr(&t.path(&format!("dst/{name}")), "user.stale", b"remove me");
            set_attr(
                &t.path(&format!("src/{name}")),
                "user.binary",
                b"new metadata only",
            );
            set_attr(
                &t.path(&format!("src/{name}")),
                "system.posix_acl_access",
                &acl(7, 5),
            );
        }
        run_ok(&command);
        for name in ["small", "large", "alias"] {
            verify_metadata(
                &t.path(&format!("src/{name}")),
                &t.path(&format!("dst/{name}")),
            );
            assert_eq!(attr(&t.path(&format!("dst/{name}")), "user.stale"), None);
        }
        write(&t.path("src/large"), &prng(6 << 20, 7));
        run_ok(&command);
        assert_eq!(read(&t.path("dst/alias")), read(&t.path("src/large")));
        verify_metadata(&t.path("src/large"), &t.path("dst/large"));
    }
}

#[test]
fn basic_acl_reconciliation_removes_stale_and_inherited_entries() {
    let t = Tmp::new();
    write(&t.path("src/unchanged"), b"same");
    write(&t.path("src/new"), b"new");
    fs::create_dir(t.path("dst")).unwrap();
    set_attr(&t.path("dst"), "system.posix_acl_default", &acl(7, 7));
    run_ok(&["-a", &t.s("src/unchanged"), &t.s("dst/")]);
    assert!(attr(&t.path("dst/unchanged"), "system.posix_acl_access").is_some());
    run_ok(&["-aA", &t.s("src/"), &t.s("dst/")]);
    for name in ["unchanged", "new"] {
        assert_eq!(
            attr(&t.path(&format!("dst/{name}")), "system.posix_acl_access"),
            None
        );
        verify_metadata(
            &t.path(&format!("src/{name}")),
            &t.path(&format!("dst/{name}")),
        );
    }
    assert_eq!(attr(&t.path("dst"), "system.posix_acl_default"), None);
}

#[test]
fn xattr_selection_reconciles_empty_values_and_keeps_acl_scope_separate() {
    let t = Tmp::new();
    write(&t.path("src/file"), b"data");
    set_attr(&t.path("src/file"), "user.empty", b"");
    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(attr(&t.path("dst/file"), "user.empty"), None);
    set_attr(&t.path("dst/file"), "system.posix_acl_access", &acl(7, 7));
    run_ok(&["-aX", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(attr(&t.path("dst/file"), "user.empty"), Some(Vec::new()));
    assert!(attr(&t.path("dst/file"), "system.posix_acl_access").is_some());
    remove_attr(&t.path("src/file"), "user.empty");
    run_ok(&["-aX", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(attr(&t.path("dst/file"), "user.empty"), None);
}

#[test]
fn xattr_only_change_is_visible_in_dry_run_without_mutation() {
    let t = Tmp::new();
    write(&t.path("src/file"), b"data");
    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    set_attr(&t.path("src/file"), "user.binary", b"new");
    let output = syq(&["-naX", &t.s("src/"), &t.s("dst/")]);
    assert_output_ok(&output);
    assert_eq!(attr(&t.path("dst/file"), "user.binary"), None);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(text.contains("metadata-only"), "{text}");
}

#[test]
fn rich_metadata_is_batched_and_unchanged_reruns_are_empty() {
    let t = Tmp::new();
    // Every value fits even filesystems with one small xattr block, while the
    // whole scan/stat population exceeds the metadata frame size.
    for i in 0..5000 {
        let path = t.path(&format!("src/{i:05}"));
        write(&path, b"x");
        set_attr(&path, "user.binary", &vec![(i % 251) as u8; 2048]);
    }
    run_ok(&["-aX", &t.s("src/"), &t.s("dst/")]);
    for i in 0..5000 {
        let name = format!("{i:05}");
        assert_eq!(
            attr(&t.path(&format!("dst/{name}")), "user.binary"),
            Some(vec![(i % 251) as u8; 2048])
        );
    }
    let output = syq(&["-naX", &t.s("src/"), &t.s("dst/")]);
    assert_output_ok(&output);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(text.contains("changes: none"), "{text}");
}

#[test]
fn acl_mapping_mode_controls_mask_and_rerun_comparison() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"data");
    set_attr(&t.path("src/a"), "system.posix_acl_access", &acl(7, 7));
    let manifest=serde_json::json!({"src":{"encoding":"utf-8","value":"a"},"dst":{"encoding":"utf-8","value":"a"},"metadata":{"mode":416}}).to_string();
    let output = syq_cp_in(
        &t.path(""),
        &[
            "--preserve=acls",
            "--mapping",
            "-",
            "-C",
            "src",
            "--into",
            "dst",
        ],
        Some(manifest.as_bytes()),
    );
    assert_output_ok(&output);
    assert_eq!(fs::metadata(t.path("dst/a")).unwrap().mode() & 0o777, 0o640);
    let acl = attr(&t.path("dst/a"), "system.posix_acl_access").unwrap();
    assert_eq!(&acl[4 + 8..4 + 16], &[2, 0, 7, 0, 57, 48, 0, 0]);
    let output = syq_cp_in(
        &t.path(""),
        &[
            "--dry-run",
            "--preserve=acls",
            "--mapping",
            "-",
            "-C",
            "src",
            "--into",
            "dst",
        ],
        Some(manifest.as_bytes()),
    );
    assert_output_ok(&output);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(text.contains("changes: none"), "{text}");
}

#[test]
fn xattrs_preserve_readonly_files_and_directory_permissions() {
    let t = Tmp::new();
    write(&t.path("src/file"), b"data");
    for name in ["src", "src/file"] {
        set_attr(&t.path(name), "user.binary", b"readonly");
    }
    fs::set_permissions(t.path("src/file"), fs::Permissions::from_mode(0o440)).unwrap();
    fs::set_permissions(t.path("src"), fs::Permissions::from_mode(0o550)).unwrap();
    run_ok(&["-aX", &t.s("src/"), &t.s("dst/")]);
    for name in ["", "file"] {
        assert_eq!(
            attr(&t.path(&format!("dst/{name}")), "user.binary"),
            Some(b"readonly".to_vec())
        );
        assert_eq!(
            fs::metadata(t.path(&format!("src/{name}"))).unwrap().mode() & 0o777,
            fs::metadata(t.path(&format!("dst/{name}"))).unwrap().mode() & 0o777
        );
    }
    // Keep a named destination ACL while reconciling only user attributes.
    fs::set_permissions(t.path("src"), fs::Permissions::from_mode(0o750)).unwrap();
    fs::set_permissions(t.path("src/file"), fs::Permissions::from_mode(0o640)).unwrap();
    set_attr(&t.path("src/file"), "user.binary", b"updated");
    fs::set_permissions(t.path("src/file"), fs::Permissions::from_mode(0o440)).unwrap();
    set_attr(&t.path("dst/file"), "system.posix_acl_access", &acl(4, 4));
    fs::set_permissions(t.path("dst/file"), fs::Permissions::from_mode(0o440)).unwrap();
    let before = attr(&t.path("dst/file"), "system.posix_acl_access");
    run_ok(&["-aX", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(
        attr(&t.path("dst/file"), "user.binary"),
        Some(b"updated".to_vec())
    );
    assert_eq!(attr(&t.path("dst/file"), "system.posix_acl_access"), before);
    fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o750)).unwrap();
}

#[test]
fn symlink_metadata_never_comes_from_its_target() {
    let t = Tmp::new();
    write(&t.path("outside"), b"outside");
    fs::create_dir(t.path("src")).unwrap();
    set_attr(&t.path("outside"), "user.binary", b"outside attribute");
    std::os::unix::fs::symlink("../outside", t.path("src/link")).unwrap();
    run_ok(&["-aAX", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(
        fs::read_link(t.path("dst/link")).unwrap(),
        Path::new("../outside")
    );
    assert_eq!(attr(&t.path("dst/link"), "user.binary"), None);
    assert_eq!(
        attr(&t.path("outside"), "user.binary"),
        Some(b"outside attribute".to_vec())
    );
}

#[cfg(debug_assertions)]
#[test]
fn xattr_repair_refuses_a_destination_replaced_with_a_symlink() {
    let t = Tmp::new();
    write(&t.path("src/file"), b"data");
    write(&t.path("outside"), b"outside");
    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    set_attr(&t.path("src/file"), "user.binary", b"source");
    set_attr(&t.path("outside"), "user.binary", b"outside");
    let ready = t.path("ready");
    let continuation = t.path("continue");
    let mut child = compat_command()
        .args(["-aX", "--no-progress", &t.s("src/"), &t.s("dst/")])
        .env("SYQ_TEST_QUICK_META_READY_FILE", &ready)
        .env("SYQ_TEST_QUICK_META_CONTINUE_FILE", &continuation)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    wait_for_confinement_marker(&mut child, &ready, "xattr metadata repair");
    fs::remove_file(t.path("dst/file")).unwrap();
    std::os::unix::fs::symlink(t.path("outside"), t.path("dst/file")).unwrap();
    release_confinement_barrier(&continuation);
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert_eq!(
        attr(&t.path("outside"), "user.binary"),
        Some(b"outside".to_vec())
    );
}

#[cfg(debug_assertions)]
#[test]
fn inode_metadata_keeps_local_copy_and_recovers_after_interruption() {
    let t = Tmp::new();
    let data = prng(5 << 20, 83);
    write(&t.path("src/companion"), b"another scheduled file");
    write(&t.path("src/file"), &data);
    fs::hard_link(t.path("src/file"), t.path("src/alias")).unwrap();
    set_attr(&t.path("src/file"), "user.binary", b"before retry");
    set_attr(&t.path("src/file"), "system.posix_acl_access", &acl(6, 4));
    let arguments = [
        "-aHAX",
        "--no-progress",
        "--performance-tuning=batch-bytes=64K",
        &t.s("src/"),
        &t.s("dst/"),
    ];
    let failed = compat_command()
        .args(arguments)
        .env("SYQ_TEST_COPY_LOCAL_EXDEV", "1")
        .env("SYQ_TEST_COPY_LOCAL_FS", "local")
        .env("SYQ_TEST_FAIL_COPY_LOCAL_AFTER_WRITE", "1")
        .run()
        .unwrap();
    assert!(!failed.status.success(), "{failed:?}");
    assert!(stderr_of(&failed).contains("test local-copy write failure"));
    assert!(!t.path("dst/alias").exists());
    assert!(!t.path("dst/file").exists());
    let partials = partial_files(&t.path("dst"));
    assert_eq!(partials.len(), 1);
    assert_eq!(fs::metadata(&partials[0]).unwrap().len(), 1 << 20);
    // Resume must use current source metadata, independently of reusable bytes.
    set_attr(&t.path("src/file"), "user.binary", b"after retry");
    let mut resume = arguments.to_vec();
    resume[2] = "--performance-tuning=copy-path=ranges";
    let resumed = compat_command()
        .args(resume)
        .env("SYQ_DEBUG", "1")
        .run()
        .unwrap();
    assert_output_ok(&resumed);
    assert!(
        tuning_observed(&resumed)["range_requests"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert_eq!(read(&t.path("dst/file")), data);
    verify_metadata(&t.path("src/file"), &t.path("dst/file"));
    assert_eq!(
        fs::metadata(t.path("dst/file")).unwrap().ino(),
        fs::metadata(t.path("dst/alias")).unwrap().ino()
    );
    fs::remove_file(t.path("src/companion")).unwrap();
    let copied = compat_command()
        .args([
            "-aHAX",
            "--no-progress",
            "--performance-tuning=batch-bytes=64K",
            &t.s("src/"),
            &t.s("cloned/"),
        ])
        .env("SYQ_DEBUG", "1")
        .env("SYQ_TEST_FAIL_READ_RANGE", "1")
        .run()
        .unwrap();
    assert_output_ok(&copied);
    assert_eq!(tuning_observed(&copied)["local_whole_files"], 1);
    assert_eq!(tuning_observed(&copied)["range_requests"], 0);
    verify_metadata(&t.path("src/file"), &t.path("cloned/file"));
}

#[test]
fn posix_acls_cover_fifo_inodes() {
    let t = Tmp::new();
    fs::create_dir(t.path("src")).unwrap();
    let path = CString::new(t.s("src/fifo")).unwrap();
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o640) }, 0);
    set_attr(&t.path("src/fifo"), "system.posix_acl_access", &acl(6, 4));
    run_ok(&["-aAX", &t.s("src/"), &t.s("dst/")]);
    verify_metadata(&t.path("src/fifo"), &t.path("dst/fifo"));
    remove_attr(&t.path("src/fifo"), "system.posix_acl_access");
    run_ok(&["-aAX", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(attr(&t.path("dst/fifo"), "system.posix_acl_access"), None);
}

#[test]
fn xattrs_preserve_long_listings_and_large_and_empty_values() {
    let t = Tmp::new();
    write(&t.path("source"), b"payload");
    // Exceed the 256-byte read buffer while keeping the full attribute set
    // within filesystems that store all xattrs in a single 4 KiB block.
    let large = prng(1024, 811);
    for index in 0..40 {
        set_attr(
            &t.path("source"),
            &format!("user.attribute_{index:02}"),
            b"small",
        );
    }
    set_attr(&t.path("source"), "user.large", &large);
    set_attr(&t.path("source"), "user.empty", b"");
    let command = ["-aAX", &t.s("source"), &t.s("destination")];
    run_ok(&command);
    for index in 0..40 {
        let name = format!("user.attribute_{index:02}");
        assert_eq!(
            attr(&t.path("source"), &name),
            attr(&t.path("destination"), &name)
        );
    }
    assert_eq!(attr(&t.path("destination"), "user.large"), Some(large));
    assert_eq!(attr(&t.path("destination"), "user.empty"), Some(Vec::new()));
    remove_attr(&t.path("source"), "user.large");
    run_ok(&command);
    assert_eq!(attr(&t.path("destination"), "user.large"), None);
    assert_eq!(attr(&t.path("destination"), "user.empty"), Some(Vec::new()));
}

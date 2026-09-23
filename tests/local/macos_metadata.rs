use super::*;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;

fn set_attr(path: &Path, name: &str, value: &[u8]) {
    let original = fs::symlink_metadata(path).unwrap();
    let restore = !original.file_type().is_symlink() && original.mode() & 0o200 == 0;
    if restore {
        fs::set_permissions(path, fs::Permissions::from_mode(original.mode() | 0o200)).unwrap();
    }
    let pathname = path;
    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    let name = CString::new(name).unwrap();
    assert_eq!(
        unsafe {
            libc::setxattr(
                path.as_ptr(),
                name.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
                libc::XATTR_NOFOLLOW,
            )
        },
        0,
        "{}",
        std::io::Error::last_os_error()
    );
    if restore {
        fs::set_permissions(pathname, original.permissions()).unwrap();
    }
}
fn attr(path: &Path, name: &str) -> Option<Vec<u8>> {
    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    let name = CString::new(name).unwrap();
    let mut value = vec![0; 1024 * 1024];
    let count = unsafe {
        libc::getxattr(
            path.as_ptr(),
            name.as_ptr(),
            value.as_mut_ptr().cast(),
            value.len(),
            0,
            libc::XATTR_NOFOLLOW,
        )
    };
    if count < 0 {
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ENOATTR)
        );
        None
    } else {
        value.truncate(count as usize);
        Some(value)
    }
}
fn chmod(path: &Path, arguments: &[&str]) {
    // Apple's chmod opens FIFO ACL targets for reading. Keep both ends open
    // while constructing the fixture so that utility cannot wait for a writer.
    let _fifo = if fs::symlink_metadata(path).unwrap().file_type().is_fifo() {
        Some(
            OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(path)
                .unwrap(),
        )
    } else {
        None
    };
    let output = Command::new("/bin/chmod")
        .args(arguments)
        .arg(path)
        .run()
        .unwrap();
    assert_output_ok(&output);
}
fn acl(path: &Path) -> Vec<String> {
    let output = Command::new("/bin/ls").arg("-lde").arg(path).run().unwrap();
    assert_output_ok(&output);
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .skip(1)
        .map(str::to_owned)
        .collect()
}
fn verify(source: &Path, destination: &Path) {
    assert_eq!(
        acl(source),
        acl(destination),
        "ACL {}",
        destination.display()
    );
    for name in [
        "org.syq.binary",
        "org.syq.empty",
        "user.literal",
        "com.apple.ResourceFork",
        "com.apple.FinderInfo",
    ] {
        assert_eq!(
            attr(source, name),
            attr(destination, name),
            "{} {name}",
            destination.display()
        );
    }
    let (a, b) = (
        fs::symlink_metadata(source).unwrap(),
        fs::symlink_metadata(destination).unwrap(),
    );
    assert_eq!(a.mode() & 0o7777, b.mode() & 0o7777);
    assert_eq!((a.mtime(), a.mtime_nsec()), (b.mtime(), b.mtime_nsec()));
}

#[test]
fn native_acl_and_xattrs_cover_clones_ranges_hardlinks_and_reconciliation() {
    for tuning in ["copy-path=auto", "copy-path=ranges"] {
        let t = Tmp::new();
        write(&t.path("src/nested/large"), &prng(5 << 20, 11));
        write(&t.path("src/small"), b"small");
        fs::hard_link(t.path("src/nested/large"), t.path("src/alias")).unwrap();
        // Directory inheritance is observable independently through chmod/ls.
        chmod(&t.path("src/nested"), &["+a", "everyone allow read,readattr,readextattr,readsecurity,file_inherit,directory_inherit"]);
        for name in ["nested/large", "small"] {
            let path = t.path(&format!("src/{name}"));
            chmod(&path, &["+a", "everyone deny execute"]);
            chmod(
                &path,
                &[
                    "+a",
                    "everyone allow read,readattr,readextattr,readsecurity",
                ],
            );
            set_attr(&path, "org.syq.binary", &[0, 255, 4, 0]);
            set_attr(&path, "org.syq.empty", b"");
            set_attr(&path, "user.literal", b"namespace stays literal on macOS");
            set_attr(&path, "com.apple.ResourceFork", &prng(8192, 73));
            set_attr(&path, "com.apple.FinderInfo", &[37; 32]);
            fs::set_permissions(&path, fs::Permissions::from_mode(0o440)).unwrap();
        }
        let from = t.s("src/");
        let to = t.s("dst/");
        let tuning = format!("--performance-tuning={tuning}");
        let args = ["-aHAX", &tuning, &from, &to];
        run_ok(&args);
        for name in ["nested", "nested/large", "small", "alias"] {
            verify(
                &t.path(&format!("src/{name}")),
                &t.path(&format!("dst/{name}")),
            );
        }
        assert_eq!(
            fs::metadata(t.path("dst/alias")).unwrap().ino(),
            fs::metadata(t.path("dst/nested/large")).unwrap().ino()
        );
        let before = fs::metadata(t.path("dst/nested/large")).unwrap();
        set_attr(&t.path("dst/small"), "org.syq.stale", b"remove");
        chmod(&t.path("src/small"), &["-N"]);
        chmod(&t.path("src/nested"), &["-N"]);
        set_attr(&t.path("src/small"), "org.syq.binary", b"metadata only");
        run_ok(&args);
        assert_eq!(attr(&t.path("dst/small"), "org.syq.stale"), None);
        for name in ["nested", "nested/large", "small"] {
            verify(
                &t.path(&format!("src/{name}")),
                &t.path(&format!("dst/{name}")),
            );
        }
        assert_eq!(
            before.ino(),
            fs::metadata(t.path("dst/nested/large")).unwrap().ino()
        );
        fs::set_permissions(t.path("src/small"), fs::Permissions::from_mode(0o640)).unwrap();
        fs::set_permissions(t.path("dst/small"), fs::Permissions::from_mode(0o640)).unwrap();
        write(&t.path("src/small"), b"changed bytes");
        run_ok(&["-aHAXc", "--inplace", &from, &to]);
        assert_eq!(read(&t.path("dst/small")), b"changed bytes");
        verify(&t.path("src/small"), &t.path("dst/small"));
    }
}

#[test]
fn native_metadata_on_links_fifos_and_inherited_directories() {
    let t = Tmp::new();
    write(&t.path("src/target"), b"target");
    fs::create_dir(t.path("src/empty")).unwrap();
    std::os::unix::fs::symlink("target", t.path("src/link")).unwrap();
    mkfifo(&t.path("src/fifo"));
    for name in ["link", "fifo", "empty", ""] {
        let path = t.path(&format!("src/{name}"));
        set_attr(&path, "org.syq.binary", &[7, 0, 255]);
        chmod(
            &path,
            &[
                "-h",
                "+a",
                "everyone allow readattr,readextattr,readsecurity",
            ],
        );
    }
    fs::create_dir(t.path("dst")).unwrap();
    chmod(
        &t.path("dst"),
        &[
            "+a",
            "everyone allow read,readattr,file_inherit,directory_inherit",
        ],
    );
    run_ok(&["-aAX", &t.s("src/"), &t.s("dst/")]);
    for name in ["link", "fifo", "empty", "target", ""] {
        verify(
            &t.path(&format!("src/{name}")),
            &t.path(&format!("dst/{name}")),
        );
    }
    assert_eq!(
        fs::read_link(t.path("dst/link")).unwrap(),
        Path::new("target")
    );
    assert!(fs::metadata(t.path("dst/fifo"))
        .unwrap()
        .file_type()
        .is_fifo());
}

#[cfg(debug_assertions)]
#[test]
fn native_metadata_survives_lost_publication_reply_and_plain_copy_does_not_select_it() {
    let t = Tmp::new();
    write(&t.path("source"), &prng(2 << 20, 55));
    set_attr(&t.path("source"), "org.syq.binary", &[9, 0, 8]);
    chmod(&t.path("source"), &["+a", "everyone allow read,readattr"]);
    run_ok(&["-a", &t.s("source"), &t.s("plain")]);
    assert_eq!(attr(&t.path("plain"), "org.syq.binary"), None);
    assert!(acl(&t.path("plain")).is_empty());
    let rsh = fake_rsh(&t);
    t.expose_remote_syq();
    let remote = format!("fake:{}", t.s("remote"));
    let marker = t.path("drop-once");
    let output = remote_syq_command(
        &t,
        &rsh,
        &[
            "-aAX",
            "--performance-tuning=copy-path=ranges",
            "--syq-no-bootstrap",
            &t.s("source"),
            &remote,
        ],
    )
    .env("SYQ_TEST_DROP_AFTER_REQUEST", "finalize")
    .env("SYQ_TEST_DROP_MARKER", &marker)
    .run()
    .unwrap();
    assert_output_ok(&output);
    assert!(marker.exists());
    verify(&t.path("source"), &t.path("remote"));
    assert_eq!(read(&t.path("source")), read(&t.path("remote")));
}

#[test]
fn compressed_storage_is_excluded_and_resource_fork_conflicts_fail_without_corruption() {
    use std::os::macos::fs::MetadataExt;
    let t = Tmp::new();
    let data = b"compressible metadata test\n".repeat(200_000);
    write(&t.path("original"), &data);
    let output = Command::new("/usr/bin/ditto")
        .arg("--hfsCompression")
        .args([&t.s("original"), &t.s("compressed")])
        .run()
        .unwrap();
    assert_output_ok(&output);
    assert_ne!(
        fs::metadata(t.path("compressed")).unwrap().st_flags() & libc::UF_COMPRESSED,
        0
    );
    set_attr(&t.path("compressed"), "org.syq.binary", b"public attribute");
    run_ok(&["-aAX", &t.s("compressed"), &t.s("copy")]);
    assert_eq!(read(&t.path("copy")), data);
    assert_eq!(
        fs::metadata(t.path("copy")).unwrap().st_flags() & libc::UF_COMPRESSED,
        0
    );
    assert_eq!(
        attr(&t.path("copy"), "org.syq.binary"),
        Some(b"public attribute".to_vec())
    );
    set_attr(
        &t.path("original"),
        "com.apple.ResourceFork",
        b"user resource fork",
    );
    let output = compat_command()
        .args(["-aXc", &t.s("original"), &t.s("compressed")])
        .run()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("resource fork on a compressed destination"),
        "{output:?}"
    );
    assert_eq!(read(&t.path("compressed")), data);
}

#[test]
fn an_acl_denying_deletion_can_be_published() {
    let t = Tmp::new();
    write(&t.path("source"), b"protected content");
    chmod(&t.path("source"), &["+a", "everyone deny delete"]);
    let expected = acl(&t.path("source"));
    let output = compat_command()
        .args(["-aA", &t.s("source"), &t.s("copy")])
        .run()
        .unwrap();
    let copied = t.path("copy").exists().then(|| acl(&t.path("copy")));
    // Remove the fixture's deletion denial even when publication failed.
    chmod(&t.path("source"), &["-N"]);
    if copied.is_some() {
        chmod(&t.path("copy"), &["-N"]);
    }
    assert_output_ok(&output);
    assert_eq!(copied, Some(expected));
    assert_eq!(read(&t.path("copy")), b"protected content");
}

#[test]
fn hardlinks_with_deletion_denial_can_be_published() {
    let t = Tmp::new();
    write(&t.path("src/one"), b"protected content");
    fs::hard_link(t.path("src/one"), t.path("src/two")).unwrap();
    chmod(&t.path("src/one"), &["+a", "everyone deny delete"]);
    let expected = acl(&t.path("src/one"));
    let output = compat_command()
        .args(["-aHA", &t.s("src/"), &t.s("dst")])
        .run()
        .unwrap();
    let copied = t.path("dst/one").exists().then(|| acl(&t.path("dst/one")));
    chmod(&t.path("src/one"), &["-N"]);
    // Clearing the representative also clears any temporary follower alias.
    for name in ["dst/one", "dst/two"] {
        if t.path(name).exists() {
            chmod(&t.path(name), &["-N"]);
        }
    }
    assert_output_ok(&output);
    assert_eq!(copied, Some(expected));
    assert_eq!(
        fs::metadata(t.path("dst/one")).unwrap().ino(),
        fs::metadata(t.path("dst/two")).unwrap().ino()
    );
}

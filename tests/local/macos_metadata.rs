use super::*;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;

fn set_attr(path: &Path, name: &str, value: &[u8]) {
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
        &["-aAX", "--syq-no-bootstrap", &t.s("source"), &remote],
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

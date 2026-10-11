//! Copies onto filesystems that lack atomic rename flags or hard links, set a
//! symlink's target when asked to set the link's times, or keep two-second
//! modification times. Debug builds stand in for those filesystems.

use super::*;
use std::os::unix::ffi::OsStrExt;

fn native_with_env(args: &[&str], env: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
    command.args(args).arg("--no-progress");
    for name in env {
        command.env(name, "1");
    }
    command.run().expect("run native syq")
}

fn set_link_mtime(link: &Path, seconds: i64) {
    let c = std::ffi::CString::new(link.as_os_str().as_bytes()).unwrap();
    let time = libc::timespec {
        tv_sec: seconds,
        tv_nsec: 0,
    };
    let times = [time, time];
    assert_eq!(
        unsafe {
            libc::utimensat(
                libc::AT_FDCWD,
                c.as_ptr(),
                times.as_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        },
        0
    );
}

fn assert_ok(output: &Output) {
    assert!(
        output.status.success(),
        "status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn names(directory: &Path) -> Vec<String> {
    let mut names: Vec<_> = fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// `--if-exists=error` publishes new files without replacing anything, even
/// where neither a no-replace rename nor a hard link is available (FAT,
/// exFAT, rclone mounts), and leaves no staging files behind either way.
#[test]
fn no_replace_publication_works_without_rename_flags_or_links() {
    for env in [
        &[][..],
        &["SYQ_TEST_NO_RENAME_NOREPLACE"][..],
        &["SYQ_TEST_NO_RENAME_NOREPLACE", "SYQ_TEST_NO_HARD_LINKS"][..],
        &[
            "SYQ_TEST_NO_RENAME_NOREPLACE",
            "SYQ_TEST_UNTRUSTED_LINK_COUNTS",
        ][..],
    ] {
        let t = Tmp::new();
        fs::create_dir(t.path("src")).unwrap();
        write(&t.path("src/small"), b"small");
        write(&t.path("src/large"), &vec![7u8; 3 << 20]);
        fs::create_dir(t.path("dst")).unwrap();
        let output = native_with_env(
            &[
                "cp",
                "--if-exists=error",
                "--srcs-in",
                &t.s("src"),
                "--into",
                &t.s("dst"),
            ],
            env,
        );
        assert_ok(&output);
        assert_eq!(read(&t.path("dst/small")), b"small", "{env:?}");
        assert_eq!(read(&t.path("dst/large")), vec![7u8; 3 << 20], "{env:?}");
        assert_eq!(names(&t.path("dst")), ["large", "small"], "{env:?}");

        // An existing file is refused and kept, and the refused copy leaves
        // no staging file.
        write(&t.path("dst/small"), b"kept");
        write(&t.path("src/small"), b"changed");
        let output = native_with_env(
            &[
                "cp",
                "--if-exists=error",
                &t.s("src/small"),
                "--into",
                &t.s("dst"),
            ],
            env,
        );
        assert!(!output.status.success(), "{env:?}: {output:?}");
        assert_eq!(read(&t.path("dst/small")), b"kept", "{env:?}");
        assert_eq!(names(&t.path("dst")), ["large", "small"], "{env:?}");
    }
}

/// Hard links publish where each name reports its own inode number and one
/// link (SSHFS), and without exchange or no-replace renames.
#[test]
fn hard_links_publish_where_link_counts_are_untrusted() {
    for env in [
        &["SYQ_TEST_UNTRUSTED_LINK_COUNTS"][..],
        &[
            "SYQ_TEST_UNTRUSTED_LINK_COUNTS",
            "SYQ_TEST_NO_RENAME_EXCHANGE",
            "SYQ_TEST_NO_RENAME_NOREPLACE",
        ][..],
    ] {
        let t = Tmp::new();
        fs::create_dir(t.path("src")).unwrap();
        write(&t.path("src/a"), b"linked");
        fs::hard_link(t.path("src/a"), t.path("src/b")).unwrap();
        fs::create_dir(t.path("dst")).unwrap();
        // An existing separate file at one name is replaced by the link.
        write(&t.path("dst/b"), b"old");
        let output = native_with_env(&["rsync", "-rtH", &t.s("src/"), &t.s("dst/")], env);
        assert_ok(&output);
        let a = fs::metadata(t.path("dst/a")).unwrap();
        let b = fs::metadata(t.path("dst/b")).unwrap();
        assert_eq!(a.ino(), b.ino(), "{env:?}");
        assert_eq!(names(&t.path("dst")), ["a", "b"], "{env:?}");
    }
}

/// Where setting a symlink's times would set its target's (SSHFS), the
/// link's times are left alone: the copy succeeds, a dangling link does not
/// fail it, and the target keeps its own time.
#[test]
fn symlink_times_are_left_where_setting_them_follows_the_link() {
    let t = Tmp::new();
    fs::create_dir(t.path("src")).unwrap();
    write(&t.path("src/file"), b"file");
    set_mtime(&t.path("src/file"), 1_000_000_000);
    std::os::unix::fs::symlink("file", t.path("src/link")).unwrap();
    std::os::unix::fs::symlink("missing", t.path("src/dangling")).unwrap();
    set_link_mtime(&t.path("src/link"), 1_200_000_000);
    fs::create_dir(t.path("dst")).unwrap();
    let output = native_with_env(
        &["cp", "--srcs-in", &t.s("src"), "--into", &t.s("dst")],
        &["SYQ_TEST_SYMLINK_TIMES_FOLLOW"],
    );
    assert_ok(&output);
    assert_eq!(
        fs::metadata(t.path("dst/file")).unwrap().mtime(),
        1_000_000_000
    );
    assert_eq!(
        fs::read_link(t.path("dst/link")).unwrap(),
        Path::new("file")
    );
    assert_ne!(
        fs::symlink_metadata(t.path("dst/link")).unwrap().mtime(),
        1_200_000_000
    );
    assert_eq!(
        fs::read_link(t.path("dst/dangling")).unwrap(),
        Path::new("missing")
    );
    assert_eq!(names(&t.path("dst")), ["dangling", "file", "link"]);
}

/// The probe for that behavior runs on a filesystem that sets the link
/// itself, finds so, sets the link's time and leaves no names behind.
#[test]
fn symlink_time_probe_finds_a_local_filesystem_sets_the_link() {
    let t = Tmp::new();
    fs::create_dir(t.path("src")).unwrap();
    write(&t.path("src/file"), b"file");
    std::os::unix::fs::symlink("file", t.path("src/link")).unwrap();
    let link_time = 1_100_000_000;
    set_link_mtime(&t.path("src/link"), link_time);
    fs::create_dir(t.path("dst")).unwrap();
    let output = native_with_env(
        &["cp", "--srcs-in", &t.s("src"), "--into", &t.s("dst")],
        &["SYQ_TEST_NETWORK_FILESYSTEM"],
    );
    assert_ok(&output);
    assert_eq!(
        fs::symlink_metadata(t.path("dst/link")).unwrap().mtime(),
        link_time
    );
    assert_eq!(names(&t.path("dst")), ["file", "link"]);
}

/// On FAT, which keeps two-second modification times, a file whose time
/// was rounded to an even second counts as unchanged; elsewhere it does not.
#[test]
fn fat_modification_times_compare_at_two_seconds() {
    let t = Tmp::new();
    fs::create_dir(t.path("src")).unwrap();
    write(&t.path("src/odd"), b"odd");
    set_mtime(&t.path("src/odd"), 1_000_000_001);
    fs::create_dir(t.path("dst")).unwrap();
    write(&t.path("dst/odd"), b"odd");
    // What FAT keeps after a copy writes the source's time.
    set_mtime(&t.path("dst/odd"), 1_000_000_000);
    let transferred = |env: &[&str]| {
        let output = native_with_env(
            &["cp", "-v", "--srcs-in", &t.s("src"), "--into", &t.s("dst")],
            env,
        );
        assert_ok(&output);
        String::from_utf8_lossy(&output.stdout).contains("odd")
    };
    assert!(!transferred(&["SYQ_TEST_TWO_SECOND_MTIMES"]));
    assert_eq!(
        fs::metadata(t.path("dst/odd")).unwrap().mtime(),
        1_000_000_000
    );
    // Two seconds apart is a change even there.
    set_mtime(&t.path("dst/odd"), 1_000_000_003);
    assert!(transferred(&["SYQ_TEST_TWO_SECOND_MTIMES"]));
    set_mtime(&t.path("dst/odd"), 1_000_000_000);
    assert!(transferred(&[]));
}

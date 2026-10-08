use super::*;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;

struct RestrictedDirectory(PathBuf);
impl RestrictedDirectory {
    fn new(path: PathBuf, mode: u32) -> Self {
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        Self(path)
    }
}
impl Drop for RestrictedDirectory {
    fn drop(&mut self) {
        let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700));
    }
}

/// A denied lookup is never an absent target, and the parent of an exact
/// placement lies outside the copy: it is not widened, so the download fails
/// without changing the directory or the file in it.
#[test]
fn download_named_files_fail_without_widening_their_parent() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let server = Server::start("existing-policy");
    for dry_run in [false, true] {
        for widening in [false, true] {
            for (placement, present) in [
                ("--as-new", true),
                ("--as-new", false),
                ("--as-existing", true),
                ("--as-existing", false),
                ("--as", true),
            ] {
                let temp = crate::test_support::tempdir().unwrap();
                let directory = temp.path().join("dst");
                fs::create_dir(&directory).unwrap();
                let file = directory.join("file");
                if present {
                    fs::write(&file, b"sentinel").unwrap();
                }
                let restricted = RestrictedDirectory::new(directory.clone(), 0o600);
                let before = fs::metadata(&directory).unwrap();
                let mut args = vec!["--from", "s3://bucket", "data", placement, "dst/file"];
                if placement == "--as" {
                    args.push("--if-exists=keep");
                }
                if widening {
                    args.push("--temporarily-widen-dir-permissions");
                }
                if dry_run {
                    args.push("--dry-run");
                }
                let output = server.cp(temp.path(), &args);
                assert!(
                    !output.status.success(),
                    "{args:?}: {}",
                    output_text(&output)
                );
                let after = fs::metadata(&directory).unwrap();
                assert_eq!(after.mode() & 0o7777, 0o600, "{args:?}");
                assert_eq!(
                    (before.ctime(), before.ctime_nsec()),
                    (after.ctime(), after.ctime_nsec()),
                    "{args:?}"
                );
                drop(restricted);
                if present {
                    assert_eq!(fs::read(&file).unwrap(), b"sentinel");
                } else {
                    assert!(!file.exists());
                }
            }
        }
    }
}

#[test]
fn download_dry_runs_never_change_directory_permissions() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    for mode in [0o500, 0o600] {
        for pruning in [None, Some("--prune"), Some("--prune-before")] {
            let server = Server::start("prefix-ok");
            let temp = crate::test_support::tempdir().unwrap();
            let directory = temp.path().join("dst");
            fs::create_dir(&directory).unwrap();
            fs::write(directory.join("extra"), b"keep").unwrap();
            let restricted = RestrictedDirectory::new(directory.clone(), mode);
            let before = fs::metadata(&directory).unwrap();
            let mut args = vec![
                "--from",
                "s3://bucket",
                "--srcs-in",
                "data",
                "--into",
                "dst",
                "--dry-run",
                "--temporarily-widen-dir-permissions",
                "--copy-metadata=permissions,mtime",
            ];
            args.extend(pruning);
            let output = server.cp(temp.path(), &args);
            let after = fs::metadata(&directory).unwrap();
            drop(restricted);
            if mode == 0o500 {
                assert!(output.status.success(), "{}", output_text(&output));
            }
            assert_eq!(after.mode(), before.mode(), "{args:?}");
            assert_eq!(
                (before.ctime(), before.ctime_nsec()),
                (after.ctime(), after.ctime_nsec()),
                "{args:?}"
            );
            assert_eq!(fs::read(directory.join("extra")).unwrap(), b"keep");
            assert!(!directory.join("file").exists());
        }
    }
}

#[test]
fn download_keep_existing_policy_still_allows_temporary_container_access() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let server = Server::start("prefix-ok");
    let temp = crate::test_support::tempdir().unwrap();
    let directory = temp.path().join("dst");
    fs::create_dir(&directory).unwrap();
    fs::write(directory.join("keep"), b"keep").unwrap();
    let restricted = RestrictedDirectory::new(directory.clone(), 0o500);
    let output = server.cp(
        temp.path(),
        &[
            "--from",
            "s3://bucket",
            "--srcs-in",
            "data",
            "--into",
            "dst",
            "--if-exists=keep",
            "--temporarily-widen-dir-permissions",
        ],
    );
    assert!(output.status.success(), "{}", output_text(&output));
    assert_eq!(fs::metadata(&directory).unwrap().mode() & 0o7777, 0o500);
    drop(restricted);
    assert_eq!(fs::read(directory.join("keep")).unwrap(), b"keep");
    assert_eq!(fs::read(directory.join("file")).unwrap(), vec![b'x'; 65536]);
}

#[test]
fn download_dry_run_leaves_requested_directory_metadata_unapplied() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let server = Server::start("copy-root-marker");
    let temp = crate::test_support::tempdir().unwrap();
    let directory = temp.path().join("dst");
    fs::create_dir(&directory).unwrap();
    let restricted = RestrictedDirectory::new(directory.clone(), 0o500);
    let before = fs::metadata(&directory).unwrap();
    let output = server.cp(
        temp.path(),
        &[
            "--from",
            "s3://source",
            "--src-dir",
            "data",
            "--as",
            "dst",
            "--dry-run",
            "--temporarily-widen-dir-permissions",
            "--copy-metadata=permissions,mtime",
        ],
    );
    assert!(output.status.success(), "{}", output_text(&output));
    let after = fs::metadata(&directory).unwrap();
    assert_eq!(after.mode(), before.mode());
    assert_eq!(
        (
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec()
        ),
        (
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec()
        )
    );
    drop(restricted);
    assert!(!directory.join("child").exists());
}

#[test]
fn search_only_download_preview_does_not_widen_a_named_container() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let server = Server::start("existing-policy");
    let temp = crate::test_support::tempdir().unwrap();
    let directory = temp.path().join("dst");
    fs::create_dir(&directory).unwrap();
    fs::write(directory.join("file"), b"keep").unwrap();
    let restricted = RestrictedDirectory::new(directory.clone(), 0o100);
    let before = fs::metadata(&directory).unwrap();
    for widen in [false, true] {
        let mut args = vec![
            "--from",
            "s3://bucket",
            "data",
            "--as",
            "dst/file",
            "--dry-run",
        ];
        if widen {
            args.push("--temporarily-widen-dir-permissions");
        }
        let output = server.cp(temp.path(), &args);
        assert!(output.status.success(), "{}", output_text(&output));
        let after = fs::metadata(&directory).unwrap();
        assert_eq!(after.mode(), before.mode());
        assert_eq!(
            (after.ctime(), after.ctime_nsec()),
            (before.ctime(), before.ctime_nsec())
        );
    }
    drop(restricted);
    assert_eq!(fs::read(directory.join("file")).unwrap(), b"keep");
}

/// Pruning a download widens owned destination-only directories it must
/// enter or empty, and removes them; without the option nothing changes.
#[test]
fn download_pruning_widens_destination_only_directories() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    for pruning in ["--prune", "--prune-before"] {
        for widen in [false, true] {
            let server = Server::start("prefix-ok");
            let temp = crate::test_support::tempdir().unwrap();
            let dst = temp.path().join("dst");
            // Darwin opens a directory to change its mode only with read
            // access, so there unreadable directories stay unlisted.
            let mut modes = vec![("e555/in", 0o555), ("e555", 0o555)];
            if cfg!(target_os = "linux") {
                modes.extend([("e300", 0o300), ("e100/n300", 0o300), ("e100", 0o100)]);
            }
            for (directory, _) in &modes {
                fs::create_dir_all(dst.join(directory)).unwrap();
                fs::write(dst.join(directory).join("f"), b"extra").unwrap();
            }
            let restricted: Vec<_> = modes
                .into_iter()
                .map(|(path, mode)| RestrictedDirectory::new(dst.join(path), mode))
                .collect();
            let mut args = vec![
                "--from",
                "s3://bucket",
                "--srcs-in",
                "data",
                "--into",
                "dst",
                pruning,
            ];
            if widen {
                args.push("--temporarily-widen-dir-permissions");
            }
            let output = server.cp(temp.path(), &args);
            let e555 = fs::symlink_metadata(dst.join("e555")).ok();
            drop(restricted);
            let mut names: Vec<_> = fs::read_dir(&dst)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                .collect();
            names.sort();
            if widen {
                assert!(
                    output.status.success(),
                    "{args:?}: {}",
                    output_text(&output)
                );
                assert_eq!(names, ["file"], "{args:?}");
            } else {
                assert!(
                    !output.status.success(),
                    "{args:?}: {}",
                    output_text(&output)
                );
                assert_eq!(e555.unwrap().mode() & 0o777, 0o555);
                assert!(names.contains(&"e555".to_owned()), "{names:?}");
            }
        }
    }
}

/// A directory pruning keeps because it is ignored is never widened.
#[test]
fn download_pruning_leaves_ignored_directories_alone() {
    if unsafe { libc::geteuid() } == 0 || !cfg!(target_os = "linux") {
        return;
    }
    let server = Server::start("prefix-ok");
    let temp = crate::test_support::tempdir().unwrap();
    let ignored = temp.path().join("dst/kept.tmp");
    fs::create_dir_all(&ignored).unwrap();
    fs::write(ignored.join("f"), b"keep").unwrap();
    let restricted = RestrictedDirectory::new(ignored.clone(), 0o000);
    let before = fs::metadata(&ignored).unwrap();
    let output = server.cp(
        temp.path(),
        &[
            "--from",
            "s3://bucket",
            "--srcs-in",
            "data",
            "--into",
            "dst",
            "--prune",
            "--ignore",
            "*.tmp",
            "--temporarily-widen-dir-permissions",
        ],
    );
    let after = fs::metadata(&ignored).unwrap();
    drop(restricted);
    assert!(output.status.success(), "{}", output_text(&output));
    assert_eq!(after.mode(), before.mode());
    assert_eq!(
        (after.ctime(), after.ctime_nsec()),
        (before.ctime(), before.ctime_nsec())
    );
    assert_eq!(fs::read(ignored.join("f")).unwrap(), b"keep");
}

/// Local names need not be UTF-8: pruning widens and removes such a
/// directory too, and restores nothing it removed.
#[test]
fn download_pruning_widens_directories_with_non_utf8_names() {
    use std::os::unix::ffi::OsStrExt;
    if unsafe { libc::geteuid() } == 0 || !cfg!(target_os = "linux") {
        return;
    }
    let server = Server::start("prefix-ok");
    let temp = crate::test_support::tempdir().unwrap();
    let dst = temp.path().join("dst");
    let extra = dst.join(std::ffi::OsStr::from_bytes(b"extra-\xff"));
    fs::create_dir_all(extra.join("inner")).unwrap();
    fs::write(extra.join("inner/f"), b"extra").unwrap();
    fs::write(extra.join("g"), b"extra").unwrap();
    let restricted = [
        RestrictedDirectory::new(extra.join("inner"), 0o555),
        RestrictedDirectory::new(extra.clone(), 0o555),
    ];
    let output = server.cp(
        temp.path(),
        &[
            "--from",
            "s3://bucket",
            "--srcs-in",
            "data",
            "--into",
            "dst",
            "--prune",
            "--temporarily-widen-dir-permissions",
        ],
    );
    drop(restricted);
    assert!(output.status.success(), "{}", output_text(&output));
    assert!(!extra.exists());
    assert_eq!(fs::read(dst.join("file")).unwrap(), vec![b'x'; 65536]);
}

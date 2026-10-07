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

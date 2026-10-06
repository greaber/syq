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

#[test]
fn download_permission_mode_covers_named_files_and_existence_checks() {
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
                if widening {
                    args.push("--temporarily-widen-dir-permissions");
                }
                if dry_run {
                    args.push("--dry-run");
                }
                let output = server.cp(temp.path(), &args);
                let expected = widening && ((placement == "--as-existing") == present);
                assert_eq!(
                    output.status.success(),
                    expected,
                    "{args:?}: {}",
                    output_text(&output)
                );
                let after = fs::metadata(&directory).unwrap();
                assert_eq!(after.mode() & 0o7777, 0o600, "{args:?}");
                if !widening {
                    assert_eq!(
                        (before.ctime(), before.ctime_nsec()),
                        (after.ctime(), after.ctime_nsec())
                    );
                }
                drop(restricted);
                if expected && !dry_run {
                    assert_eq!(fs::read(&file).unwrap(), b"stored");
                } else if present {
                    assert_eq!(fs::read(&file).unwrap(), b"sentinel");
                } else {
                    assert!(!file.exists());
                }
            }
        }
    }
}

#[test]
fn download_dry_run_widens_for_pruning_and_restores_without_other_changes() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    for pruning in ["--prune", "--prune-before"] {
        let server = Server::start("prefix-ok");
        let temp = crate::test_support::tempdir().unwrap();
        let directory = temp.path().join("dst");
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("extra"), b"keep").unwrap();
        let restricted = RestrictedDirectory::new(directory.clone(), 0o600);
        let before = fs::metadata(&directory).unwrap();
        let output = server.cp(
            temp.path(),
            &[
                "--from",
                "s3://bucket",
                "--srcs-in",
                "data",
                "--into",
                "dst",
                pruning,
                "--dry-run",
                "--temporarily-widen-dir-permissions",
                "--copy-metadata=permissions,mtime",
            ],
        );
        assert!(output.status.success(), "{}", output_text(&output));
        let after = fs::metadata(&directory).unwrap();
        assert_eq!(after.mode() & 0o7777, 0o600);
        assert_eq!(
            (before.mtime(), before.mtime_nsec()),
            (after.mtime(), after.mtime_nsec())
        );
        drop(restricted);
        assert_eq!(fs::read(directory.join("extra")).unwrap(), b"keep");
        assert!(!directory.join("file").exists());
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

use super::*;
use std::ffi::OsString;
use std::fs;

fn names(directory: &Path) -> Vec<OsString> {
    let mut names: Vec<_> = fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    names.sort();
    names
}

#[test]
fn replace_publishes_whole_contents_with_the_requested_mode() {
    let directory = crate::test_support::tempdir().unwrap();
    let path = directory.path().join("state.json");
    for durability in [
        Durability::RenameOnly,
        Durability::FileSynced,
        Durability::Synced,
    ] {
        assert!(write_atomic(&path, b"one", 0o600, Publish::Replace, durability).unwrap());
        assert!(write_atomic(&path, b"two", 0o600, Publish::Replace, durability).unwrap());
        assert_eq!(fs::read(&path).unwrap(), b"two");
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o600);
    }
    let executable = directory.path().join("tool");
    assert!(write_atomic(
        &executable,
        b"x",
        0o700,
        Publish::Replace,
        Durability::Synced
    )
    .unwrap());
    assert_eq!(fs::metadata(&executable).unwrap().mode() & 0o7777, 0o700);
    // A mode the creation call cannot give (it creates owner-only) is set
    // afterwards, so the file gets exactly the requested mode.
    let shared = directory.path().join("shared");
    assert!(write_atomic(
        &shared,
        b"x",
        0o640,
        Publish::Replace,
        Durability::RenameOnly
    )
    .unwrap());
    assert_eq!(fs::metadata(&shared).unwrap().mode() & 0o7777, 0o640);
    assert_eq!(names(directory.path()), ["shared", "state.json", "tool"]);
}

#[test]
fn no_clobber_keeps_the_existing_file_and_leaves_no_temporary() {
    let directory = crate::test_support::tempdir().unwrap();
    let path = directory.path().join("record");
    for durability in [
        Durability::RenameOnly,
        Durability::FileSynced,
        Durability::Synced,
    ] {
        let _ = fs::remove_file(&path);
        assert!(write_atomic(&path, b"first", 0o600, Publish::NoClobber, durability).unwrap());
        assert!(!write_atomic(&path, b"second", 0o600, Publish::NoClobber, durability).unwrap());
        assert_eq!(fs::read(&path).unwrap(), b"first");
        assert_eq!(fs::metadata(&path).unwrap().nlink(), 1);
        assert_eq!(names(directory.path()), ["record"]);
    }
}

#[test]
fn replace_does_not_follow_or_write_through_a_symlink() {
    let directory = crate::test_support::tempdir().unwrap();
    let target = directory.path().join("target");
    fs::write(&target, b"keep").unwrap();
    let link = directory.path().join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    write_atomic(
        &link,
        b"new",
        0o600,
        Publish::Replace,
        Durability::RenameOnly,
    )
    .unwrap();
    assert_eq!(fs::read(&target).unwrap(), b"keep");
    assert!(fs::symlink_metadata(&link).unwrap().is_file());
}

#[test]
fn temporary_names_are_recognized() {
    for name in [".syq-tmp-123-00ff00ff00ff00ff", ".tmpAb12Z9"] {
        assert!(is_own_temp_name(OsStr::new(name)), "{name}");
    }
    for name in [
        ".syq-tmp-",
        ".syq-tmp-12X",
        ".tmp12345",
        ".tmp1234567",
        ".tmp12-456",
        "state.json",
        ".syq-persistence",
    ] {
        assert!(!is_own_temp_name(OsStr::new(name)), "{name}");
    }
    // The writer's own names match.
    let directory = crate::test_support::tempdir().unwrap();
    let opened = File::open(directory.path()).unwrap();
    let (name, _file) = create_temporary(&opened, 0o600).unwrap();
    assert!(is_own_temp_name(OsStr::from_bytes(name.as_bytes())));
}

#[test]
fn reads_check_the_rule_bound_and_absence() {
    let directory = crate::test_support::tempdir().unwrap();
    let path = directory.path().join("state");
    assert!(read_private(&path, "state", 8, FileRule::Exact0600)
        .unwrap()
        .is_none());
    fs::write(&path, b"12345678").unwrap();
    for (mode, rule, ok) in [
        (0o600, FileRule::Exact0600, true),
        (0o400, FileRule::Exact0600, false),
        (0o640, FileRule::NoGroupOther, false),
        (0o400, FileRule::NoGroupOther, true),
        (0o644, FileRule::NoGroupOtherWrite, true),
        (0o620, FileRule::NoGroupOtherWrite, false),
        (0o666, FileRule::Owned, true),
        (0o666, FileRule::Regular, true),
    ] {
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        let result = read_private(&path, "state", 8, rule);
        assert_eq!(result.is_ok(), ok, "{mode:o} {rule:?}");
        if ok {
            assert_eq!(result.unwrap().unwrap(), b"12345678");
        }
    }
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let error = read_private(&path, "state", 7, FileRule::Exact0600).unwrap_err();
    assert!(
        format!("{error:#}").contains("exceeds 7 bytes"),
        "{error:#}"
    );

    let link = directory.path().join("link");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(read_private(&link, "state", 8, FileRule::Regular).is_err());
    let opened = File::open(directory.path()).unwrap();
    assert!(read_private_at(&opened, OsStr::new("link"), "state", 8, FileRule::Regular).is_err());
    assert_eq!(
        read_private_at(
            &opened,
            OsStr::new("state"),
            "state",
            8,
            FileRule::Exact0600
        )
        .unwrap()
        .unwrap(),
        b"12345678"
    );
    assert!(fs::create_dir(directory.path().join("dir")).is_ok());
    assert!(read_private(&directory.path().join("dir"), "state", 8, FileRule::Regular).is_err());
}

#[test]
fn private_directories_are_created_checked_or_tightened() {
    let root = crate::test_support::tempdir().unwrap();
    let path = root.path().join("private");
    assert!(open_private_dir(&path, "state", false, DirRule::Exact0700)
        .unwrap()
        .is_none());
    open_private_dir(&path, "state", true, DirRule::Exact0700)
        .unwrap()
        .unwrap();
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o700);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o750)).unwrap();
    assert!(open_private_dir(&path, "state", false, DirRule::Exact0700).is_err());
    assert!(open_private_dir(&path, "state", false, DirRule::NoGroupOther).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o500)).unwrap();
    assert!(open_private_dir(&path, "state", false, DirRule::Exact0700).is_err());
    open_private_dir(&path, "state", false, DirRule::NoGroupOther)
        .unwrap()
        .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    open_private_dir(&path, "state", false, DirRule::Tighten)
        .unwrap()
        .unwrap();
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o700);

    let link = root.path().join("link");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(open_private_dir(&link, "state", false, DirRule::NoGroupOther).is_err());
    assert!(open_private_dir(&link, "state", true, DirRule::NoGroupOther).is_err());
}

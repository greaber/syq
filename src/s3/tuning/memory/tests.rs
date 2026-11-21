use super::{cgroup_room, objects_within, MemoryRoom::*};
use std::{fs, path::Path};

fn level(dir: &Path, max: Option<&str>, current: Option<&str>) {
    fs::create_dir_all(dir).unwrap();
    if let Some(max) = max {
        fs::write(dir.join("memory.max"), format!("{max}\n")).unwrap();
    }
    if let Some(current) = current {
        fs::write(dir.join("memory.current"), format!("{current}\n")).unwrap();
    }
}

fn room(entry: &str, build: impl FnOnce(&Path)) -> super::MemoryRoom {
    let temp = crate::test_support::tempdir().unwrap();
    let root = temp.path().join("cgroup");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("cgroup.controllers"), "cpu memory\n").unwrap();
    build(&root);
    let proc = temp.path().join("proc-cgroup");
    fs::write(&proc, entry).unwrap();
    cgroup_room(&proc, &root)
}

#[test]
fn the_tightest_limit_on_the_path_sets_the_room() {
    // The process's own cgroup sets a limit.
    assert_eq!(
        room("0::/a/b\n", |root| {
            level(&root.join("a"), Some("max"), Some("900"));
            level(&root.join("a/b"), Some("1000"), Some("400"));
        }),
        Limited(600)
    );
    // An ancestor's limit applies to everything below it.
    assert_eq!(
        room("0::/a/b\n", |root| {
            level(&root.join("a"), Some("1000"), Some("900"));
            level(&root.join("a/b"), Some("max"), Some("100"));
        }),
        Limited(100)
    );
    // Usage at or above the limit leaves nothing.
    assert_eq!(
        room("0::/a\n", |root| level(
            &root.join("a"),
            Some("1000"),
            Some("1200")
        )),
        Limited(0)
    );
    // Inside a cgroup namespace the process's cgroup is the visible root.
    assert_eq!(
        room("0::/\n", |root| level(root, Some("1000"), Some("250"))),
        Limited(750)
    );
}

#[test]
fn no_limit_anywhere_is_unlimited() {
    assert_eq!(
        room("0::/a/b\n", |root| {
            // The host root has no memory files; a level without the memory
            // controller has none either.
            level(&root.join("a"), None, None);
            level(&root.join("a/b"), Some("max"), Some("100"));
        }),
        Unlimited
    );
}

#[test]
fn anything_unreadable_is_unknown() {
    let limited = |root: &Path| level(&root.join("a"), Some("1000"), Some("1"));
    // Version 1 and hybrid hierarchies.
    assert_eq!(room("4:memory:/a\n", limited), Unknown);
    assert_eq!(room("4:memory:/a\n0::/a\n", limited), Unknown);
    // The process sits outside the visible part of its cgroup namespace.
    assert_eq!(room("0::/../a\n", limited), Unknown);
    // The cgroup does not exist where the hierarchy is mounted.
    assert_eq!(room("0::/elsewhere\n", limited), Unknown);
    // A limit without readable usage, or an unparsable limit.
    assert_eq!(
        room("0::/a\n", |root| level(&root.join("a"), Some("1000"), None)),
        Unknown
    );
    assert_eq!(
        room("0::/a\n", |root| level(
            &root.join("a"),
            Some("lots"),
            Some("1")
        )),
        Unknown
    );
    // No unified hierarchy mounted at the root.
    let temp = crate::test_support::tempdir().unwrap();
    let proc = temp.path().join("proc-cgroup");
    fs::write(&proc, "0::/\n").unwrap();
    assert_eq!(cgroup_room(&proc, temp.path()), Unknown);
    assert_eq!(
        cgroup_room(&temp.path().join("missing"), temp.path()),
        Unknown
    );
}

#[test]
fn objects_fit_in_half_the_room() {
    let mib = 1024 * 1024;
    assert_eq!(objects_within(400 * mib, 64 * 1024), 1066);
    assert_eq!(objects_within(400 * mib, 8 * 1024), 1505);
    assert_eq!(objects_within(0, 8 * 1024), 0);
}

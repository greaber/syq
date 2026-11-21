use super::{cgroup_room, objects_within, MemoryRoom, MemoryRoom::*, INITIAL_NAMESPACE};
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

/// A `/proc/self/mountinfo` line mounting a hierarchy from `source` at `root`.
fn mount(source: &str, root: &Path, kind: &str) -> String {
    format!(
        "38 28 0:32 {source} {} rw,nosuid shared:10 - {kind} {kind} rw,nsdelegate\n",
        root.display()
    )
}

/// The answer for a hierarchy built under a temporary root, as `view`
/// (namespace and mount table) shows it.
fn room_in(
    entry: &str,
    view: impl FnOnce(&Path) -> (Option<&'static str>, String),
    build: impl FnOnce(&Path),
) -> MemoryRoom {
    let temp = crate::test_support::tempdir().unwrap();
    let root = temp.path().join("cgroup");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("cgroup.controllers"), "cpu memory\n").unwrap();
    build(&root);
    let (namespace, mounts) = view(&root);
    cgroup_room(entry, namespace, &mounts, &root)
}

/// Seen from the initial namespace with the whole hierarchy mounted.
fn room(entry: &str, build: impl FnOnce(&Path)) -> MemoryRoom {
    room_in(
        entry,
        |root| (Some(INITIAL_NAMESPACE), mount("/", root, "cgroup2")),
        build,
    )
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
}

#[test]
fn no_limit_anywhere_is_unlimited_only_when_every_level_is_visible() {
    let unlimited = |root: &Path| {
        // The host root has no memory files; a level without the memory
        // controller has none either.
        level(&root.join("a"), None, None);
        level(&root.join("a/b"), Some("max"), Some("100"));
    };
    assert_eq!(room("0::/a/b\n", unlimited), Unlimited);
    // In another cgroup namespace, or with the namespace unreadable,
    // ancestors above its root may limit memory too: only a visible limit
    // counts.
    let other = |root: &Path| (Some("cgroup:[4026535099]"), mount("/", root, "cgroup2"));
    let unreadable = |root: &Path| (None, mount("/", root, "cgroup2"));
    assert_eq!(room_in("0::/a/b\n", other, unlimited), Unknown);
    assert_eq!(room_in("0::/a/b\n", unreadable, unlimited), Unknown);
    // A container's view: its own cgroup is the visible root.
    assert_eq!(
        room_in("0::/\n", other, |root| level(
            root,
            Some("1000"),
            Some("250")
        )),
        Limited(750)
    );
}

#[test]
fn anything_unreadable_or_unmapped_is_unknown() {
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
    // A mount of a subtree or of a root outside the namespace does not map
    // the process's path; neither does a version 1 mount, a later mount over
    // the hierarchy, or no mount at all.
    for view in [
        |root: &Path| {
            (
                Some(INITIAL_NAMESPACE),
                mount("/system.slice", root, "cgroup2"),
            )
        },
        |root: &Path| (Some(INITIAL_NAMESPACE), mount("/../..", root, "cgroup2")),
        |root: &Path| (Some(INITIAL_NAMESPACE), mount("/", root, "cgroup")),
        |root: &Path| {
            let first = mount("/", root, "cgroup2");
            (Some(INITIAL_NAMESPACE), first + &mount("/", root, "tmpfs"))
        },
        |_: &Path| (Some(INITIAL_NAMESPACE), String::new()),
    ] {
        assert_eq!(room_in("0::/a\n", view, limited), Unknown);
    }
    // No unified hierarchy at the mount point.
    let temp = crate::test_support::tempdir().unwrap();
    let mounts = mount("/", temp.path(), "cgroup2");
    assert_eq!(
        cgroup_room("0::/\n", Some(INITIAL_NAMESPACE), &mounts, temp.path()),
        Unknown
    );
}

#[test]
fn memory_room_off_linux_is_unknown() {
    let room = super::memory_room();
    if !cfg!(target_os = "linux") {
        assert_eq!(room, Unknown);
    }
}

#[test]
fn objects_fit_in_half_the_room() {
    let mib = 1024 * 1024;
    assert_eq!(objects_within(400 * mib, 64 * 1024), 1066);
    assert_eq!(objects_within(400 * mib, 8 * 1024), 1505);
    assert_eq!(objects_within(0, 8 * 1024), 0);
}

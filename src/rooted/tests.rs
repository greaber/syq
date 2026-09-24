use super::*;
use crate::process::CommandExt as _;
use std::ffi::OsStr;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

static NEXT_TEST: AtomicU64 = AtomicU64::new(0);

struct TestDir(PathBuf);

impl TestDir {
    fn new(name: &str) -> Self {
        let n = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
        let path = crate::test_support::temp_dir()
            .join(format!("syq-rooted-{name}-{}-{n}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn relative(path: &[u8]) -> RelativePath {
    RelativePath::new(path).unwrap()
}

#[cfg(target_os = "macos")]
#[test]
fn apfs_clone_is_private_independent_and_never_replaces_a_partial() {
    if !macos_clone_support::available() {
        return;
    }
    use std::os::unix::fs::PermissionsExt;
    let t = TestDir::new("clone");
    // A setgid destination may pass its group and setgid bit to the
    // private directory; that does not make the directory public.
    fs::set_permissions(t.path(), fs::Permissions::from_mode(0o2700)).unwrap();
    let source_path = t.path().join("source");
    fs::write(&source_path, b"original data").unwrap();
    fs::set_permissions(&source_path, fs::Permissions::from_mode(0o444)).unwrap();
    let source = File::open(&source_path).unwrap();
    let root = Root::open(t.path()).unwrap();
    assert_eq!(
        root.clone_file(
            &source,
            &source.metadata().unwrap(),
            &relative(b"partial"),
            13,
        )
        .unwrap(),
        CopyLocalOutcome::Copied
    );
    let clone = OpenOptions::new()
        .read(true)
        .write(true)
        .open(t.path().join("partial"))
        .unwrap();
    assert_eq!(clone.metadata().unwrap().mode() & 0o7777, 0o600);
    assert_ne!(
        source.metadata().unwrap().ino(),
        clone.metadata().unwrap().ino()
    );
    assert_eq!(
        root.clone_file(
            &source,
            &source.metadata().unwrap(),
            &relative(b"partial"),
            13
        )
        .unwrap(),
        CopyLocalOutcome::Unsupported
    );
    (&clone).write_all(b"changed clone").unwrap();
    assert_eq!(fs::read(&source_path).unwrap(), b"original data");
    assert_eq!(fs::read_dir(t.path()).unwrap().count(), 2);
    for planned_size in [12, 14] {
        assert_eq!(
            root.clone_file(
                &source,
                &source.metadata().unwrap(),
                &relative(b"wrong-size"),
                planned_size
            )
            .unwrap(),
            CopyLocalOutcome::Unsupported
        );
    }
    assert!(!t.path().join("wrong-size").exists());
    assert_eq!(fs::read_dir(t.path()).unwrap().count(), 2);
}

#[cfg(target_os = "macos")]
#[test]
fn apfs_clone_strips_xattrs_and_user_flags_without_changing_source() {
    use std::os::macos::fs::MetadataExt;
    if !macos_clone_support::available() {
        return;
    }
    let t = TestDir::new("clone-metadata");
    let source_path = t.path().join("source");
    fs::write(&source_path, b"data").unwrap();
    let source = File::open(&source_path).unwrap();
    let root = Root::open(t.path()).unwrap();
    for (name, value) in [
        (c"com.apple.quarantine", b"0081;66000000;syq;".as_slice()),
        (
            c"com.apple.FinderInfo",
            b"TEXTttxt000000000000000000000000".as_slice(),
        ),
    ] {
        assert_eq!(
            unsafe {
                libc::fsetxattr(
                    source.as_raw_fd(),
                    name.as_ptr(),
                    value.as_ptr().cast(),
                    value.len(),
                    0,
                    0,
                )
            },
            0
        );
    }
    for flags in [libc::UF_NODUMP, libc::UF_IMMUTABLE, libc::UF_APPEND] {
        assert_eq!(unsafe { libc::fchflags(source.as_raw_fd(), flags) }, 0);
        let result = root.clone_file(
            &source,
            &source.metadata().unwrap(),
            &relative(b"partial"),
            4,
        );
        let source_flags = source.metadata().unwrap().st_flags();
        // Restore fixture mutability even if cloning failed.
        assert_eq!(unsafe { libc::fchflags(source.as_raw_fd(), 0) }, 0);
        assert_eq!(result.unwrap(), CopyLocalOutcome::Copied);
        let clone = OpenOptions::new()
            .read(true)
            .write(true)
            .open(t.path().join("partial"))
            .unwrap();
        assert_eq!(source_flags, flags);
        assert_eq!(clone.metadata().unwrap().st_flags(), 0);
        // macOS can add its own provenance attribute after publication,
        // including on byte copies. Check the source attributes by name.
        for (name, value) in [
            (c"com.apple.quarantine", b"0081;66000000;syq;".as_slice()),
            (
                c"com.apple.FinderInfo",
                b"TEXTttxt000000000000000000000000".as_slice(),
            ),
        ] {
            macos_clone_support::assert_xattr(&clone, name, None);
            macos_clone_support::assert_xattr(&source, name, Some(value));
        }
        (&clone).write_all(b"copy").unwrap();
        assert_eq!(fs::read(&source_path).unwrap(), b"data");
        fs::remove_file(t.path().join("partial")).unwrap();
    }
    assert_eq!(fs::read_dir(t.path()).unwrap().count(), 1);
}

#[cfg(target_os = "macos")]
#[test]
fn apfs_clone_refuses_compression_added_after_source_snapshot() {
    if !macos_clone_support::available() {
        return;
    }
    use std::os::macos::fs::MetadataExt;
    let t = TestDir::new("clone-raced-compression");
    let original = t.path().join("original");
    let compressed = t.path().join("compressed");
    let data = b"compressible test data\n".repeat(250_000);
    fs::write(&original, &data).unwrap();
    let snapshot = fs::metadata(&original).unwrap();
    assert!(Command::new("/usr/bin/ditto")
        .arg("--hfsCompression")
        .arg(&original)
        .arg(&compressed)
        .status_guarded()
        .unwrap()
        .success());
    let source = File::open(&compressed).unwrap();
    assert_ne!(
        source.metadata().unwrap().st_flags() & libc::UF_COMPRESSED,
        0
    );
    // Model a source compressed between the prelude stat and cloning.
    let root = Root::open(t.path()).unwrap();
    assert_eq!(
        root.clone_file(&source, &snapshot, &relative(b"partial"), data.len() as u64)
            .unwrap(),
        CopyLocalOutcome::Unsupported
    );
    assert_eq!(fs::read(&compressed).unwrap(), data);
    assert_eq!(fs::read_dir(t.path()).unwrap().count(), 2);
}

#[cfg(target_os = "macos")]
#[test]
fn apfs_clone_falls_back_for_destination_acl_inheritance() {
    if !macos_clone_support::available() {
        return;
    }
    let t = TestDir::new("clone-acl");
    fs::write(t.path().join("source"), b"data").unwrap();
    let source = File::open(t.path().join("source")).unwrap();
    let root = Root::open(t.path()).unwrap();
    for rule in [
        "everyone allow read,readattr,readextattr,readsecurity,file_inherit",
        "everyone allow read,readattr,readextattr,readsecurity,directory_inherit",
    ] {
        assert!(Command::new("/bin/chmod")
            .args(["+a", "everyone deny delete"])
            .arg(t.path())
            .status_guarded()
            .unwrap()
            .success());
        assert_eq!(
            root.clone_file(
                &source,
                &source.metadata().unwrap(),
                &relative(b"noninherited"),
                4
            )
            .unwrap(),
            CopyLocalOutcome::Copied
        );
        fs::remove_file(t.path().join("noninherited")).unwrap();
        assert!(Command::new("/bin/chmod")
            .args(["+a", rule])
            .arg(t.path())
            .status_guarded()
            .unwrap()
            .success());
        assert_eq!(
            root.clone_file(
                &source,
                &source.metadata().unwrap(),
                &relative(b"partial"),
                4
            )
            .unwrap(),
            CopyLocalOutcome::Unsupported
        );
        assert_eq!(fs::read_dir(t.path()).unwrap().count(), 1);
        assert!(Command::new("/bin/chmod")
            .arg("-N")
            .arg(t.path())
            .status_guarded()
            .unwrap()
            .success());
        // Ineligibility is per-directory, never cached for the volume.
        assert_eq!(
            root.clone_file(
                &source,
                &source.metadata().unwrap(),
                &relative(b"after-acl"),
                4
            )
            .unwrap(),
            CopyLocalOutcome::Copied
        );
        fs::remove_file(t.path().join("after-acl")).unwrap();
    }
}

#[cfg(target_os = "macos")]
#[test]
fn apfs_clone_normalizes_mode_before_opening() {
    if !macos_clone_support::available() {
        return;
    }
    let t = TestDir::new("clone-owner-mode");
    let path = t.path().join("source");
    fs::write(&path, b"data").unwrap();
    // ACL read access lets us reproduce a caller-readable source whose
    // owner bits forbid reading, without requiring a second OS account.
    assert!(Command::new("/bin/chmod")
        .args(["+a", "everyone allow read"])
        .arg(&path)
        .status_guarded()
        .unwrap()
        .success());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o044)).unwrap();
    let source = File::open(&path).unwrap();
    let root = Root::open(t.path()).unwrap();
    assert!(Command::new("/bin/chmod")
        .arg("-N")
        .arg(&path)
        .status_guarded()
        .unwrap()
        .success());
    assert!(Command::new("/bin/chmod")
        .args([
            "+a",
            "everyone allow read,readattr,readextattr,readsecurity"
        ])
        .arg(&path)
        .status_guarded()
        .unwrap()
        .success());
    assert_eq!(
        unsafe { libc::fchflags(source.as_raw_fd(), libc::UF_IMMUTABLE) },
        0
    );
    let locked = root.clone_file(
        &source,
        &source.metadata().unwrap(),
        &relative(b"locked"),
        4,
    );
    assert_eq!(unsafe { libc::fchflags(source.as_raw_fd(), 0) }, 0);
    assert_eq!(locked.unwrap(), CopyLocalOutcome::Copied);
    let locked = OpenOptions::new()
        .read(true)
        .write(true)
        .open(t.path().join("locked"))
        .unwrap();
    assert_eq!(locked.metadata().unwrap().mode() & 0o777, 0o600);
    fs::remove_file(t.path().join("locked")).unwrap();
    assert_eq!(
        root.clone_file(
            &source,
            &source.metadata().unwrap(),
            &relative(b"partial"),
            4,
        )
        .unwrap(),
        CopyLocalOutcome::Copied
    );
    let clone = OpenOptions::new()
        .read(true)
        .write(true)
        .open(t.path().join("partial"))
        .unwrap();
    assert_eq!(clone.metadata().unwrap().mode() & 0o777, 0o600);
    (&clone).write_all(b"copy").unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"data");
}

#[cfg(target_os = "macos")]
#[test]
fn apfs_clone_noownercopy_does_not_copy_source_acl() {
    if !macos_clone_support::available() {
        return;
    }
    let t = TestDir::new("clone-source-acl");
    let path = t.path().join("source");
    fs::write(&path, b"data").unwrap();
    for rule in [
        "everyone deny write,append",
        "everyone allow read,readattr,readextattr,readsecurity",
    ] {
        assert!(Command::new("/bin/chmod")
            .args(["+a", rule])
            .arg(&path)
            .status_guarded()
            .unwrap()
            .success());
    }
    let source = File::open(&path).unwrap();
    let parent = File::open(t.path()).unwrap();
    // Independent API check, before syq performs any normalization.
    assert_eq!(
        unsafe {
            libc::fclonefileat(
                source.as_raw_fd(),
                parent.as_raw_fd(),
                c"raw-clone".as_ptr(),
                2,
            )
        },
        0
    );
    let source_acl = Command::new("/bin/ls")
        .arg("-le")
        .arg(&path)
        .capture_output()
        .unwrap();
    let clone_acl = Command::new("/bin/ls")
        .arg("-le")
        .arg(t.path().join("raw-clone"))
        .capture_output()
        .unwrap();
    assert!(source_acl.status.success() && clone_acl.status.success());
    let source_acl = String::from_utf8(source_acl.stdout).unwrap();
    let clone_acl = String::from_utf8(clone_acl.stdout).unwrap();
    eprintln!("source ACL:\n{source_acl}raw CLONE_NOOWNERCOPY clone:\n{clone_acl}");
    assert!(source_acl.contains("deny") && source_acl.contains("allow"));
    assert!(
        !clone_acl.contains("deny") && !clone_acl.contains("allow"),
        "{clone_acl}"
    );
    OpenOptions::new()
        .write(true)
        .open(t.path().join("raw-clone"))
        .unwrap();
    let root = Root::open(t.path()).unwrap();
    assert_eq!(
        root.clone_file(
            &source,
            &source.metadata().unwrap(),
            &relative(b"normalized"),
            4,
        )
        .unwrap(),
        CopyLocalOutcome::Copied
    );
    let clone = OpenOptions::new()
        .read(true)
        .write(true)
        .open(t.path().join("normalized"))
        .unwrap();
    (&clone).write_all(b"copy").unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"data");
}

#[cfg(target_os = "linux")]
fn require_test_openat2(result: io::Result<File>) -> Option<File> {
    match result {
        Ok(file) => Some(file),
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(libc::ENOSYS | libc::EPERM | libc::EACCES)
            ) =>
        {
            // Production retains the secure component walker when the
            // running kernel or its syscall policy does not allow openat2.
            None
        }
        Err(error) => panic!("openat2 fast path failed unexpectedly: {error}"),
    }
}

#[cfg(target_os = "macos")]
#[test]
fn name_limit_queries_traverse_search_only_directories_without_chmod() {
    let tree = TestDir::new("search-only-naming");
    let parent = tree.path().join("parent");
    fs::create_dir_all(parent.join("child")).unwrap();
    fs::write(parent.join("child/file"), b"contents").unwrap();
    let root = Root::open(tree.path()).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o111)).unwrap();
    let before = fs::metadata(&parent).unwrap();
    let path = relative(b"parent/child/file");
    let limit = root.name_max_for_parent(&path);
    let after = fs::metadata(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(limit.unwrap() >= 4);
    assert_eq!(after.mode(), before.mode());
    assert_eq!(
        (after.ctime(), after.ctime_nsec()),
        (before.ctime(), before.ctime_nsec())
    );
}

#[test]
fn staged_type_replacements_preserve_old_entries_on_failure() {
    let tree = TestDir::new("staged-types");
    fs::write(tree.path().join("item"), b"previous contents").unwrap();
    let root = Root::open(tree.path()).unwrap();
    let path = relative(b"item");
    let error = root.replace_entry(&path, |_, _| {
        Err(io::Error::from_raw_os_error(libc::ENOSPC))
    });
    assert!(error.is_err());
    assert_eq!(
        fs::read(tree.path().join("item")).unwrap(),
        b"previous contents"
    );
    root.replace_symlink(&path, b"target").unwrap();
    assert_eq!(
        fs::read_link(tree.path().join("item")).unwrap(),
        Path::new("target")
    );
    fs::create_dir(tree.path().join("directory")).unwrap();
    let directory = relative(b"directory");
    fs::set_permissions(
        tree.path().join("directory"),
        fs::Permissions::from_mode(0o0),
    )
    .unwrap();
    let before = fs::metadata(tree.path().join("directory")).unwrap();
    let error = root.replace_symlink(&directory, b"other").unwrap_err();
    assert!(
        error.to_string().contains("cannot replace directory"),
        "{error:#}"
    );
    let after = fs::metadata(tree.path().join("directory")).unwrap();
    assert_eq!((before.ino(), before.mode()), (after.ino(), after.mode()));
    fs::set_permissions(
        tree.path().join("directory"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::write(tree.path().join("directory/child"), b"keep").unwrap();
    assert!(root.replace_symlink(&directory, b"other").is_err());
    assert_eq!(
        fs::read(tree.path().join("directory/child")).unwrap(),
        b"keep"
    );
}

#[test]
fn rooted_name_max_queries_each_filesystem_once() {
    let tree = TestDir::new("name-max-cache");
    fs::create_dir_all(tree.path().join("first")).unwrap();
    fs::create_dir_all(tree.path().join("second")).unwrap();
    let root = Root::open(tree.path()).unwrap();
    let cache = Mutex::new(HashMap::new());
    let queries = AtomicUsize::new(0);
    let query = |_directory: &File| {
        queries.fetch_add(1, Ordering::Relaxed);
        Ok(143)
    };

    assert_eq!(
        root.name_max_for_parent_cached(&relative(b"first/missing/file"), &cache, &query,)
            .unwrap(),
        143
    );
    assert_eq!(
        root.name_max_for_parent_cached(&relative(b"second/file"), &cache, &query)
            .unwrap(),
        143
    );
    // Direct children and a completely missing parent suffix both use
    // the retained root, whose filesystem identity is already known.
    for path in [b"file".as_slice(), b"missing/parent/file"] {
        assert_eq!(
            root.name_max_for_parent_cached(&relative(path), &cache, &query)
                .unwrap(),
            143
        );
    }
    assert_eq!(queries.load(Ordering::Relaxed), 1);
}

#[cfg(target_os = "linux")]
#[test]
fn openat2_directory_walk_matches_component_walk() {
    let tree = TestDir::new("openat2-directory-walk");
    fs::create_dir_all(tree.path().join("first/second/third")).unwrap();
    let base = File::open(tree.path()).unwrap();
    let components = relative(b"first/second/third").components;

    let Some(fast) = require_test_openat2(open_directory_components_openat2(&base, &components))
    else {
        return;
    };
    let component_walk = open_directory_components_one_at_a_time(&base, &components).unwrap();
    let fast_metadata = fast.metadata().unwrap();
    let component_metadata = component_walk.metadata().unwrap();

    assert_eq!(fast_metadata.dev(), component_metadata.dev());
    assert_eq!(fast_metadata.ino(), component_metadata.ino());
}

#[cfg(target_os = "linux")]
#[test]
fn openat2_directory_walk_refuses_intermediate_symlink() {
    let tree = TestDir::new("openat2-directory-symlink");
    fs::create_dir_all(tree.path().join("real/child")).unwrap();
    symlink("real", tree.path().join("link")).unwrap();
    let base = File::open(tree.path()).unwrap();
    let supported = relative(b"real/child").components;
    if require_test_openat2(open_directory_components_openat2(&base, &supported)).is_none() {
        return;
    }
    let components = relative(b"link/child").components;

    assert!(open_directory_components_openat2(&base, &components).is_err());
    let component_error = open_directory_components_one_at_a_time(&base, &components).unwrap_err();
    let selected_error = open_directory_components(&base, &components).unwrap_err();
    assert_eq!(
        selected_error.raw_os_error(),
        component_error.raw_os_error()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn openat2_directory_walk_allows_nested_mounts() {
    if !Path::new("/proc/sys").is_dir() {
        return;
    }
    let base = File::open("/").unwrap();
    let components = relative(b"proc/sys").components;

    let Some(fast) = require_test_openat2(open_directory_components_openat2(&base, &components))
    else {
        return;
    };
    let component_walk = open_directory_components_one_at_a_time(&base, &components).unwrap();
    let fast_metadata = fast.metadata().unwrap();
    let component_metadata = component_walk.metadata().unwrap();

    assert_eq!(fast_metadata.dev(), component_metadata.dev());
    assert_eq!(fast_metadata.ino(), component_metadata.ino());
}

#[test]
fn operator_resolver_selects_a_last_component_symlink_without_following_it() {
    let tree = TestDir::new("operator-leaf-link");
    let outside = tree.path().join("outside");
    fs::write(&outside, b"outside").unwrap();
    let selected = tree.path().join("selected");
    symlink(&outside, &selected).unwrap();
    let original = fs::symlink_metadata(&selected).unwrap();

    let base = File::open(tree.path()).unwrap();
    let resolver = OperatorResolver::beneath(&base, true, OperatorSymlinkPolicy::Refuse).unwrap();
    let mut hops = Vec::new();
    let result = resolver
        .resolve(
            b"selected",
            OperatorFinalComponent::Entry {
                follow_symlink: false,
            },
            false,
            &mut hops,
        )
        .unwrap();
    let PinnedPath::Leaf(leaf) = result else {
        panic!("last-component symlink was not selected as a leaf");
    };
    assert!(leaf.metadata().is_symlink());
    let (_, name, _, object) = leaf.into_parts();
    assert_eq!(name.as_bytes(), b"selected");
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let object = object.expect("supported platform should pin the symlink object");
        fs::rename(&selected, tree.path().join("moved")).unwrap();
        symlink("replacement", &selected).unwrap();
        let pinned = object.metadata().unwrap();
        let replacement = fs::symlink_metadata(&selected).unwrap();
        assert_eq!(
            (pinned.dev(), pinned.ino()),
            (original.dev(), original.ino())
        );
        assert_ne!(
            (pinned.dev(), pinned.ino()),
            (replacement.dev(), replacement.ino())
        );
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    assert!(object.is_none());
    assert!(hops.is_empty());
    assert_eq!(fs::read(&outside).unwrap(), b"outside");
}

#[test]
fn operator_resolver_follows_only_components_requested_by_the_caller() {
    let tree = TestDir::new("operator-follow");
    let real = tree.path().join("real");
    fs::create_dir(&real).unwrap();
    let outside = tree.path().join("outside");
    fs::write(&outside, b"outside").unwrap();
    symlink("real", tree.path().join("container")).unwrap();
    symlink(&outside, real.join("leaf")).unwrap();
    let base = File::open(tree.path()).unwrap();

    let mut hops = Vec::new();
    let refusing = OperatorResolver::beneath(&base, true, OperatorSymlinkPolicy::Refuse).unwrap();
    assert!(refusing
        .resolve(
            b"container/leaf",
            OperatorFinalComponent::Entry {
                follow_symlink: false,
            },
            false,
            &mut hops,
        )
        .is_err());

    let following =
        OperatorResolver::beneath(&base, true, OperatorSymlinkPolicy::FollowAll).unwrap();
    let result = following
        .resolve(
            b"container/leaf",
            OperatorFinalComponent::Entry {
                follow_symlink: false,
            },
            false,
            &mut hops,
        )
        .unwrap();
    let PinnedPath::Leaf(leaf) = result else {
        panic!("last-component symlink was unexpectedly followed");
    };
    assert!(leaf.metadata().is_symlink());
    assert_eq!(hops.len(), 1);
    assert_eq!(hops[0].component, b"container");
    assert_eq!(hops[0].target, b"real");
}

#[test]
fn operator_resolver_reports_the_missing_suffix_from_a_retained_parent() {
    let tree = TestDir::new("operator-missing");
    let base = File::open(tree.path()).unwrap();
    let resolver = OperatorResolver::beneath(&base, true, OperatorSymlinkPolicy::Refuse).unwrap();
    let mut hops = Vec::new();
    let result = resolver
        .resolve(
            b"new/nested",
            OperatorFinalComponent::Directory,
            true,
            &mut hops,
        )
        .unwrap();
    let PinnedPath::Missing(missing) = result else {
        panic!("missing suffix was not returned");
    };
    let (directory, components) = missing.into_parts();
    let metadata = directory.metadata().unwrap();
    let expected = fs::metadata(tree.path()).unwrap();
    assert_eq!(
        (metadata.dev(), metadata.ino()),
        (expected.dev(), expected.ino())
    );
    assert_eq!(
        components,
        VecDeque::from([b"new".to_vec(), b"nested".to_vec()])
    );
    assert!(hops.is_empty());
}

#[test]
fn operator_symlink_trust_is_root_or_receiver_ownership() {
    assert!(operator_symlink_owner_is_trusted(0, 1000));
    assert!(operator_symlink_owner_is_trusted(1000, 1000));
    assert!(!operator_symlink_owner_is_trusted(1001, 1000));
    assert!(!operator_symlink_owner_is_trusted(1000, 0));
}

#[test]
fn trusted_owner_never_falls_back_to_a_second_pathname_lookup() {
    assert!(require_operator_link_fallback_allowed(OperatorSymlinkPolicy::TrustedOwner).is_err());
    assert!(require_operator_link_fallback_allowed(OperatorSymlinkPolicy::FollowAll).is_ok());
}

#[cfg(target_os = "linux")]
#[test]
fn selected_fifo_reopens_exactly_and_waits_for_a_writer() {
    use std::sync::mpsc;
    use std::time::Duration;

    let tree = TestDir::new("operator-fifo-read");
    let fifo = tree.path().join("rules");
    let fifo_name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
    let base = File::open(tree.path()).unwrap();
    let resolver = OperatorResolver::beneath(&base, true, OperatorSymlinkPolicy::Refuse).unwrap();
    let selected = resolver
        .resolve(
            b"rules",
            OperatorFinalComponent::ReadableEntry {
                follow_symlink: true,
            },
            false,
            &mut Vec::new(),
        )
        .unwrap();
    let PinnedPath::Leaf(leaf) = selected else {
        panic!("FIFO was not selected as a leaf");
    };

    let (opened_tx, opened_rx) = mpsc::sync_channel(1);
    let opener = std::thread::spawn(move || opened_tx.send(leaf.open_read()).unwrap());
    assert!(matches!(
        opened_rx.recv_timeout(Duration::from_millis(100)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));

    let mut writer = File::options().write(true).open(&fifo).unwrap();
    writer.write_all(b"drop\n").unwrap();
    drop(writer);
    let mut reader = opened_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("exact FIFO reopen did not rendezvous with its writer")
        .unwrap();
    let mut contents = Vec::new();
    reader.read_to_end(&mut contents).unwrap();
    assert_eq!(contents, b"drop\n");
    opener.join().unwrap();
}

#[cfg(target_os = "macos")]
#[test]
fn selected_fifo_fails_closed_without_an_exact_reopen() {
    let tree = TestDir::new("operator-fifo-cutout");
    let fifo = tree.path().join("rules");
    let fifo_name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
    let base = File::open(tree.path()).unwrap();
    let resolver = OperatorResolver::beneath(&base, true, OperatorSymlinkPolicy::Refuse).unwrap();
    let selected = resolver
        .resolve(
            b"rules",
            OperatorFinalComponent::ReadableEntry {
                follow_symlink: true,
            },
            false,
            &mut Vec::new(),
        )
        .unwrap();
    let PinnedPath::Leaf(leaf) = selected else {
        panic!("FIFO was not selected as a leaf");
    };
    let error = leaf.open_read().unwrap_err().to_string();
    assert!(error.contains("exact descriptor"), "{error}");
}

#[test]
fn selecting_fifo_metadata_does_not_connect_a_writer() {
    let tree = TestDir::new("operator-fifo-metadata");
    let fifo = CString::new(tree.path().join("pipe").as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    let base = File::open(tree.path()).unwrap();
    let resolver = OperatorResolver::beneath(&base, true, OperatorSymlinkPolicy::Refuse).unwrap();
    for final_component in [
        OperatorFinalComponent::Entry {
            follow_symlink: false,
        },
        OperatorFinalComponent::StreamSource {
            follow_symlink: false,
        },
        OperatorFinalComponent::ReadableEntry {
            follow_symlink: false,
        },
    ] {
        let selected = resolver
            .resolve(b"pipe", final_component, false, &mut Vec::new())
            .unwrap();
        assert!(matches!(&selected, PinnedPath::Leaf(leaf) if leaf.metadata().is_fifo()));
        // Holding a metadata selection must not let a producer connect.
        let writer = unsafe {
            libc::open(
                fifo.as_ptr(),
                libc::O_WRONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        let error = io::Error::last_os_error();
        if writer >= 0 {
            unsafe {
                libc::close(writer);
            }
        }
        assert_eq!(writer, -1, "{final_component:?} connected a FIFO reader");
        assert_eq!(error.raw_os_error(), Some(libc::ENXIO));
        drop(selected);
    }
}

#[test]
fn confined_operator_resolver_rejects_relative_and_absolute_link_escapes() {
    let tree = TestDir::new("operator-confined");
    let base_path = tree.path().join("base");
    let outside = tree.path().join("outside");
    fs::create_dir(&base_path).unwrap();
    fs::create_dir(&outside).unwrap();
    symlink("../outside", base_path.join("relative")).unwrap();
    symlink(&outside, base_path.join("absolute")).unwrap();
    let base = File::open(&base_path).unwrap();
    let resolver =
        OperatorResolver::beneath(&base, true, OperatorSymlinkPolicy::FollowAll).unwrap();

    let mut hops = Vec::new();
    assert!(resolver
        .resolve(
            b"/absolute-input",
            OperatorFinalComponent::Directory,
            false,
            &mut hops,
        )
        .is_err());

    for selected in [&b"relative"[..], &b"absolute"[..]] {
        let mut hops = Vec::new();
        assert!(resolver
            .resolve(
                selected,
                OperatorFinalComponent::Directory,
                false,
                &mut hops,
            )
            .is_err());
    }
    assert!(resolver
        .resolve(
            b"../outside",
            OperatorFinalComponent::Directory,
            false,
            &mut Vec::new(),
        )
        .is_err());
}

#[test]
fn unconfined_operator_resolver_tracks_exit_and_reentry() {
    let tree = TestDir::new("operator-unconfined-relative");
    let base_path = tree.path().join("base");
    let inside = base_path.join("inside");
    let outside = tree.path().join("outside");
    fs::create_dir_all(&inside).unwrap();
    fs::create_dir(&outside).unwrap();
    symlink(&inside, base_path.join("absolute-reentry")).unwrap();
    let base = File::open(&base_path).unwrap();
    let resolver =
        OperatorResolver::beneath(&base, false, OperatorSymlinkPolicy::FollowAll).unwrap();

    let select_directory = |path: &[u8]| {
        let selected = resolver
            .resolve(
                path,
                OperatorFinalComponent::Directory,
                false,
                &mut Vec::new(),
            )
            .unwrap();
        let PinnedPath::Directory(directory) = selected else {
            panic!("directory was not selected");
        };
        directory.resolved_relative().map(<[u8]>::to_vec)
    };

    assert_eq!(select_directory(b"../outside"), None);
    assert_eq!(
        select_directory(b"../base/inside"),
        Some(b"inside".to_vec())
    );
    assert_eq!(
        select_directory(b"absolute-reentry"),
        Some(b"inside".to_vec())
    );
}

#[test]
fn confined_process_root_accepts_parent_components_that_stay_at_root() {
    let base = File::open("/").unwrap();
    let resolver = OperatorResolver::beneath(&base, true, OperatorSymlinkPolicy::Refuse).unwrap();
    let selected = resolver
        .resolve(
            b"..",
            OperatorFinalComponent::Directory,
            false,
            &mut Vec::new(),
        )
        .unwrap();
    let PinnedPath::Directory(directory) = selected else {
        panic!("process root was not selected as a directory");
    };
    assert_eq!(directory.resolved_relative(), Some(&b""[..]));
}

#[cfg(target_os = "linux")]
#[test]
fn operator_directory_identity_does_not_conflate_mount_contexts() {
    let identity = OperatorDirectoryIdentity {
        dev: 7,
        ino: 11,
        mount_id: Some(13),
    };
    assert!(!operator_directory_identities_match(
        identity,
        OperatorDirectoryIdentity {
            mount_id: Some(17),
            ..identity
        }
    ));
    assert!(!operator_directory_identities_match(
        identity,
        OperatorDirectoryIdentity {
            mount_id: None,
            ..identity
        }
    ));
}

#[test]
fn selected_operator_directory_remains_pinned_after_rename() {
    let tree = TestDir::new("operator-directory-pin");
    let selected = tree.path().join("selected");
    fs::create_dir(&selected).unwrap();
    let original = fs::metadata(&selected).unwrap();
    let base = File::open(tree.path()).unwrap();
    let resolver = OperatorResolver::beneath(&base, true, OperatorSymlinkPolicy::Refuse).unwrap();
    let mut hops = Vec::new();
    let result = resolver
        .resolve(
            b"selected/.",
            OperatorFinalComponent::Directory,
            false,
            &mut hops,
        )
        .unwrap();
    let PinnedPath::Directory(directory) = result else {
        panic!("directory was not selected");
    };

    fs::rename(&selected, tree.path().join("moved")).unwrap();
    fs::create_dir(&selected).unwrap();
    let replacement = fs::metadata(&selected).unwrap();
    let (directory, entry) = directory.into_parts();
    let pinned = directory.metadata().unwrap();
    assert_eq!(
        (pinned.dev(), pinned.ino()),
        (original.dev(), original.ino())
    );
    assert_ne!(
        (pinned.dev(), pinned.ino()),
        (replacement.dev(), replacement.ino())
    );
    assert!(entry.is_some());
}

#[test]
fn operator_resolver_handles_deep_path_with_low_fd_limit() {
    const CHILD_ENV: &str = "SYQ_TEST_OPERATOR_RESOLVER_LOW_FD_CHILD";
    const TEST_NAME: &str = "rooted::tests::operator_resolver_handles_deep_path_with_low_fd_limit";

    if std::env::var_os(CHILD_ENV).is_none() {
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST_NAME, "--nocapture"])
            .env(CHILD_ENV, "1")
            .status_guarded()
            .unwrap();
        assert!(status.success(), "low-FD resolver subprocess failed");
        return;
    }

    let tree = TestDir::new("operator-low-fd");
    let path = (0..40)
        .map(|index| format!("component-{index:02}"))
        .collect::<Vec<_>>()
        .join("/");
    fs::create_dir_all(tree.path().join(&path)).unwrap();
    let base = File::open(tree.path()).unwrap();

    let mut limits = crate::fsops::nofile_limits().unwrap();
    assert!(
        limits.rlim_max >= 64,
        "hard file-descriptor limit is below 64"
    );
    limits.rlim_cur = 64;
    crate::fsops::set_nofile_limits(&limits).unwrap();

    let resolver = OperatorResolver::beneath(&base, true, OperatorSymlinkPolicy::Refuse).unwrap();
    let result = resolver
        .resolve(
            path.as_bytes(),
            OperatorFinalComponent::Directory,
            false,
            &mut Vec::new(),
        )
        .unwrap();
    let PinnedPath::Directory(directory) = result else {
        panic!("deep directory was not selected");
    };
    assert!(directory.metadata().is_dir());
}

#[test]
fn validates_raw_relative_components() {
    assert_eq!(relative(b"").components, Vec::<Vec<u8>>::new());
    assert_eq!(
        relative(b"safe/name").components,
        vec![b"safe".to_vec(), b"name".to_vec()]
    );
    assert_eq!(relative(b"non-utf8-\xff").components[0], b"non-utf8-\xff");

    for unsafe_path in [
        &b"/absolute"[..],
        &b"."[..],
        &b".."[..],
        &b"a/../b"[..],
        &b"a/./b"[..],
        &b"a//b"[..],
        &b"a/"[..],
        &b"nul\0name"[..],
    ] {
        assert!(
            RelativePath::new(unsafe_path).is_err(),
            "accepted {:?}",
            String::from_utf8_lossy(unsafe_path)
        );
    }
}

#[test]
fn opened_directory_apis_reject_non_component_names() {
    let tree = TestDir::new("opened-directory-name");
    let root = Root::open(tree.path()).unwrap();
    let empty = relative(b"");
    let directory = root.open_directory(&empty).unwrap();
    let expected = root.metadata(&empty).unwrap();

    for unsafe_name in [
        &b""[..],
        &b"."[..],
        &b".."[..],
        &b"child/grandchild"[..],
        &b"nul\0name"[..],
    ] {
        assert!(root.metadata_in_directory(&directory, unsafe_name).is_err());
        assert!(root
            .read_link_in_directory(&directory, unsafe_name)
            .is_err());
        assert!(root
            .open_child_directory_verified(&directory, unsafe_name, expected)
            .is_err());
    }
}

#[test]
fn follows_only_the_explicit_root_symlink() {
    let tree = TestDir::new("root-symlink");
    let real = tree.path().join("real");
    fs::create_dir(&real).unwrap();
    fs::write(real.join("inside"), b"data").unwrap();
    symlink(&real, tree.path().join("selected")).unwrap();

    let root = Root::open(&tree.path().join("selected")).unwrap();
    let mut file = root.open_regular_read(&relative(b"inside")).unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"data");

    let outside = tree.path().join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("sentinel"), b"unchanged").unwrap();
    symlink(&outside, real.join("escape")).unwrap();
    assert!(root
        .open_regular_read(&relative(b"escape/sentinel"))
        .is_err());
    assert_eq!(fs::read(outside.join("sentinel")).unwrap(), b"unchanged");
}

#[test]
fn root_identity_detects_path_replacement_but_open_root_stays_stable() {
    let tree = TestDir::new("identity");
    let selected = tree.path().join("selected");
    fs::create_dir(&selected).unwrap();
    fs::write(selected.join("old"), b"old").unwrap();
    let root = Root::open(&selected).unwrap();
    let identity = root.identity();

    fs::rename(&selected, tree.path().join("moved")).unwrap();
    fs::create_dir(&selected).unwrap();
    fs::write(selected.join("new"), b"new").unwrap();

    assert!(Root::open_verified(&selected, identity).is_err());
    let mut old = root.open_regular_read(&relative(b"old")).unwrap();
    let mut bytes = Vec::new();
    old.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"old");
    assert!(root.open_regular_read(&relative(b"new")).is_err());
}

#[test]
fn adopted_operator_descriptor_stays_stable_and_can_be_enumerated_repeatedly() {
    let tree = TestDir::new("adopted-root");
    let selected = tree.path().join("selected");
    fs::create_dir(&selected).unwrap();
    fs::write(selected.join("first"), b"first").unwrap();
    fs::write(selected.join("second"), b"second").unwrap();
    let pinned = OperatorResolver::resolve_process(
        selected.as_os_str().as_bytes(),
        OperatorSymlinkPolicy::Refuse,
        OperatorFinalComponent::Directory,
        false,
        &mut Vec::new(),
    )
    .unwrap();
    let PinnedPath::Directory(directory) = pinned else {
        panic!("operator directory was not pinned");
    };
    let root = Root::from_directory(directory.into_parts().0).unwrap();

    fs::rename(&selected, tree.path().join("moved")).unwrap();
    fs::create_dir(&selected).unwrap();
    fs::write(selected.join("replacement"), b"replacement").unwrap();

    let mut first = root.read_directory(&relative(b"")).unwrap();
    let mut second = root.read_directory(&relative(b"")).unwrap();
    first.sort();
    second.sort();
    assert_eq!(first, [b"first".to_vec(), b"second".to_vec()]);
    assert_eq!(second, first);
    assert!(root.metadata(&relative(b"replacement")).is_err());
}

#[test]
fn descendant_traversal_needs_search_but_not_read_permission() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let tree = TestDir::new("search-only");
    let child = tree.path().join("child");
    fs::create_dir(&child).unwrap();
    fs::write(child.join("file"), b"contents").unwrap();
    let root = Root::open(tree.path()).unwrap();
    fs::set_permissions(&child, fs::Permissions::from_mode(0o111)).unwrap();

    let metadata = root.metadata(&relative(b"child/file")).unwrap();
    assert!(metadata.is_file());
    let mut file = root.open_regular_read(&relative(b"child/file")).unwrap();
    let mut contents = Vec::new();
    file.read_to_end(&mut contents).unwrap();
    assert_eq!(contents, b"contents");

    fs::set_permissions(&child, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn confined_primitives_round_trip_non_utf8_names() {
    if !crate::test_support::filesystem_accepts_non_utf8_names() {
        eprintln!("skipping: this filesystem rejects file names that are not valid UTF-8");
        return;
    }
    let tree = TestDir::new("primitives");
    let root = Root::open(tree.path()).unwrap();
    root.create_directory(&relative(b"dir"), 0o700).unwrap();

    let raw_name = std::ffi::OsString::from_vec(b"stage-\xff".to_vec());
    let stage_path = tree.path().join("dir").join(&raw_name);
    let mut stage = root
        .create_file(&relative(b"dir/stage-\xff"), 0o600)
        .unwrap();
    stage.write_all(b"payload").unwrap();
    stage.flush().unwrap();
    assert_eq!(fs::read(&stage_path).unwrap(), b"payload");

    root.rename(&relative(b"dir/stage-\xff"), &relative(b"dir/final"))
        .unwrap();
    assert!(!stage_path.exists());
    let mut final_file = root
        .open_regular_write(&relative(b"dir/final"), false)
        .unwrap();
    final_file.seek(SeekFrom::End(0)).unwrap();
    final_file.write_all(b"-more").unwrap();
    drop(final_file);
    assert_eq!(
        fs::read(tree.path().join("dir/final")).unwrap(),
        b"payload-more"
    );

    root.unlink(&relative(b"dir/final")).unwrap();
    root.remove_directory(&relative(b"dir")).unwrap();
    assert!(!tree.path().join("dir").exists());
}

#[test]
fn owner_write_only_regular_file_can_be_written_without_escaping_root() {
    let tree = TestDir::new("write-only");
    let root_path = tree.path().join("root");
    let outside = tree.path().join("outside");
    fs::create_dir(&root_path).unwrap();
    fs::create_dir(&outside).unwrap();

    let inside = root_path.join("inside");
    let sentinel = outside.join("sentinel");
    fs::write(&inside, b"initial").unwrap();
    fs::write(&sentinel, b"outside").unwrap();
    fs::set_permissions(&inside, fs::Permissions::from_mode(0o200)).unwrap();
    fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o200)).unwrap();
    assert_eq!(fs::metadata(&inside).unwrap().uid(), unsafe {
        libc::geteuid()
    });
    symlink(&outside, root_path.join("escape")).unwrap();

    let root = Root::open(&root_path).unwrap();
    let mut file = root
        .open_regular_write(&relative(b"inside"), false)
        .unwrap();
    let descriptor_flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    assert_ne!(descriptor_flags, -1);
    assert_eq!(descriptor_flags & libc::O_ACCMODE, libc::O_WRONLY);
    file.write_all(b"updated").unwrap();
    drop(file);
    assert!(root
        .open_regular_write(&relative(b"escape/sentinel"), false)
        .is_err());

    fs::set_permissions(&inside, fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(fs::read(&inside).unwrap(), b"updated");
    assert_eq!(fs::read(&sentinel).unwrap(), b"outside");
}

#[test]
fn missing_entries_and_exclusive_collisions_preserve_errno_and_contents() {
    let tree = TestDir::new("expected-open-failures");
    let root = Root::open(tree.path()).unwrap();
    fs::create_dir(tree.path().join("parent")).unwrap();
    fs::write(tree.path().join("parent/existing"), b"preserve").unwrap();
    symlink("existing", tree.path().join("parent/link")).unwrap();
    for path in [b"parent/missing".as_slice(), b"absent/child"] {
        for error in [
            root.open_regular_read(&relative(path)).unwrap_err(),
            root.open_directory(&relative(path)).unwrap_err(),
        ] {
            assert_eq!(
                error.downcast_ref::<io::Error>().unwrap().raw_os_error(),
                Some(libc::ENOENT)
            );
        }
    }
    for path in [b"parent/existing".as_slice(), b"parent/link", b"parent"] {
        let error = root.create_file(&relative(path), 0o600).unwrap_err();
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().raw_os_error(),
            Some(libc::EEXIST)
        );
    }
    assert_eq!(
        fs::read(tree.path().join("parent/existing")).unwrap(),
        b"preserve"
    );
    assert!(fs::symlink_metadata(tree.path().join("parent/link"))
        .unwrap()
        .is_symlink());
}

#[test]
fn regular_opens_walk_paths_longer_than_one_syscall_accepts() {
    let tree = TestDir::new("long-regular-open");
    let root = Root::open(tree.path()).unwrap();
    let mut components = Vec::new();
    // Create via held descriptors, so setup does not itself rely on a
    // process pathname longer than PATH_MAX being accepted.
    let mut directory = root.open_directory(&relative(b"")).unwrap();
    for index in 0..24 {
        let name = format!("{index:02}-{}", "x".repeat(197)).into_bytes();
        let c_name = component_cstring(&name);
        assert_eq!(
            unsafe { libc::mkdirat(directory.as_raw_fd(), c_name.as_ptr(), 0o700) },
            0
        );
        directory = open_directory_at(&directory, &name).unwrap();
        components.push(name);
    }
    components.push(b"file".to_vec());
    let path = RelativePath { components };
    let mut file = root.create_file(&path, 0o600).unwrap();
    file.write_all(b"long path").unwrap();
    drop(file);
    let mut file = root.open_regular_read(&path).unwrap();
    let mut contents = Vec::new();
    file.read_to_end(&mut contents).unwrap();
    assert_eq!(contents, b"long path");
    root.unlink(&path).unwrap();
}

#[test]
fn regular_opens_refuse_special_leaves_and_preserve_open_flags() {
    let tree = TestDir::new("regular-open-flags");
    fs::create_dir(tree.path().join("nested")).unwrap();
    fs::write(tree.path().join("nested/file"), b"contents").unwrap();
    symlink("file", tree.path().join("nested/link")).unwrap();
    let fifo = CString::new(tree.path().join("nested/fifo").as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    let root = Root::open(tree.path()).unwrap();
    for path in [b"nested".as_slice(), b"nested/link", b"nested/fifo"] {
        assert!(root.open_regular_read(&relative(path)).is_err());
        assert!(root.open_regular_write(&relative(path), true).is_err());
        assert!(root.create_file(&relative(path), 0o600).is_err());
    }
    assert_eq!(
        fs::read(tree.path().join("nested/file")).unwrap(),
        b"contents"
    );
    let file = root
        .open_regular_write(&relative(b"nested/file"), true)
        .unwrap();
    assert_eq!(file.metadata().unwrap().len(), 0);
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    assert_ne!(flags, -1);
    assert_eq!(flags & libc::O_ACCMODE, libc::O_WRONLY);
    assert_eq!(flags & libc::O_NONBLOCK, 0);
    let descriptor_flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
    assert_ne!(descriptor_flags, -1);
    assert_ne!(descriptor_flags & libc::FD_CLOEXEC, 0);
}

#[test]
fn exclusive_creation_returns_a_blocking_cloexec_regular_file() {
    let tree = TestDir::new("exclusive-create-flags");
    let root = Root::open(tree.path()).unwrap();
    let mut file = root.create_file(&relative(b"new"), 0o600).unwrap();
    assert!(file.metadata().unwrap().is_file());
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    assert_ne!(flags, -1);
    assert_eq!(flags & libc::O_ACCMODE, libc::O_RDWR);
    assert_eq!(flags & libc::O_NONBLOCK, 0);
    let descriptor_flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
    assert_ne!(descriptor_flags, -1);
    assert_ne!(descriptor_flags & libc::FD_CLOEXEC, 0);
    file.write_all(b"created").unwrap();
    assert!(root.create_file(&relative(b"new"), 0o600).is_err());
    assert_eq!(fs::read(tree.path().join("new")).unwrap(), b"created");
}

#[test]
fn publication_parent_stays_pinned_when_its_name_is_replaced() {
    let tree = TestDir::new("borrowed-publication-parent");
    fs::create_dir(tree.path().join("gate")).unwrap();
    let root = Root::open(tree.path()).unwrap();
    let source = relative(b"gate/partial");
    let target = relative(b"gate/final");
    let file = root.create_file(&source, 0o600).unwrap();
    let source_parent = root.resolve_parent(&source).unwrap();
    fs::rename(tree.path().join("gate"), tree.path().join("moved")).unwrap();
    fs::create_dir(tree.path().join("gate")).unwrap();
    fs::write(tree.path().join("gate/final"), b"replacement").unwrap();
    let target_parent = root
        .resolve_publish_target(&source, &source_parent, &target)
        .unwrap();
    assert_eq!(
        target_parent.directory.metadata().unwrap().ino(),
        source_parent.directory.metadata().unwrap().ino()
    );
    assert!(metadata_at(target_parent.directory.as_raw_fd(), &target_parent.leaf).is_err());
    assert_eq!(
        metadata_at(source_parent.directory.as_raw_fd(), &source_parent.leaf)
            .unwrap()
            .ino,
        file.metadata().unwrap().ino()
    );
    assert_eq!(
        fs::read(tree.path().join("gate/final")).unwrap(),
        b"replacement"
    );
    // A later independent operation resolves the replacement afresh.
    assert_eq!(root.metadata(&target).unwrap().len, 11);
}

#[test]
fn held_parent_does_not_follow_a_replacement_symlink() {
    let tree = TestDir::new("held-parent");
    let root_path = tree.path().join("root");
    let outside = tree.path().join("outside");
    fs::create_dir(&root_path).unwrap();
    fs::create_dir(root_path.join("gate")).unwrap();
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("sentinel"), b"unchanged").unwrap();
    let root = Root::open(&root_path).unwrap();

    let path = relative(b"gate/created");
    let parent = root.resolve_parent(&path).unwrap();
    fs::rename(root_path.join("gate"), root_path.join("parked")).unwrap();
    symlink(&outside, root_path.join("gate")).unwrap();

    let mut file = open_at(
        parent.directory.as_raw_fd(),
        &parent.leaf,
        libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
        0o600,
    )
    .unwrap();
    file.write_all(b"inside").unwrap();
    drop(file);

    assert_eq!(fs::read(outside.join("sentinel")).unwrap(), b"unchanged");
    assert!(!outside.join("created").exists());
    assert_eq!(
        fs::read(root_path.join("parked/created")).unwrap(),
        b"inside"
    );
    assert!(root.create_file(&path, 0o600).is_err());
}

#[test]
fn concurrent_intermediate_swaps_never_touch_outside_sentinel() {
    let tree = TestDir::new("swap-race");
    let root_path = tree.path().join("root");
    let outside = tree.path().join("outside");
    fs::create_dir(&root_path).unwrap();
    fs::create_dir(root_path.join("gate")).unwrap();
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("sentinel"), b"unchanged").unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let attacker_stop = stop.clone();
    let attacker_root = root_path.clone();
    let attacker_outside = outside.clone();
    let attacker = std::thread::spawn(move || {
        while !attacker_stop.load(Ordering::Relaxed) {
            if fs::rename(attacker_root.join("gate"), attacker_root.join("parked")).is_ok() {
                let _ = symlink(&attacker_outside, attacker_root.join("gate"));
                let _ = fs::remove_file(attacker_root.join("gate"));
                let _ = fs::rename(attacker_root.join("parked"), attacker_root.join("gate"));
            }
        }
    });

    let root = Root::open(&root_path).unwrap();
    let temp = relative(b"gate/work");
    let final_path = relative(b"gate/final");
    for _ in 0..2_000 {
        if let Ok(mut file) = root.create_file(&temp, 0o600) {
            let _ = file.write_all(b"inside");
            drop(file);
            let _ = root.rename(&temp, &final_path);
            let _ = root.unlink(&final_path);
            let _ = root.unlink(&temp);
        }
    }
    stop.store(true, Ordering::Relaxed);
    attacker.join().unwrap();

    assert_eq!(fs::read(outside.join("sentinel")).unwrap(), b"unchanged");
    assert!(!outside.join("work").exists());
    assert!(!outside.join("final").exists());
}

#[test]
fn leaf_symlink_is_never_opened_but_can_be_unlinked() {
    let tree = TestDir::new("leaf-symlink");
    let root_path = tree.path().join("root");
    let outside = tree.path().join("outside");
    fs::create_dir(&root_path).unwrap();
    fs::write(&outside, b"unchanged").unwrap();
    symlink(&outside, root_path.join("leaf")).unwrap();
    let root = Root::open(&root_path).unwrap();

    assert!(root.open_regular_read(&relative(b"leaf")).is_err());
    assert!(root.open_regular_write(&relative(b"leaf"), true).is_err());
    assert_eq!(fs::read(&outside).unwrap(), b"unchanged");
    root.unlink(&relative(b"leaf")).unwrap();
    assert_eq!(fs::read(&outside).unwrap(), b"unchanged");
}

#[test]
fn same_type_symlink_and_special_replacement_exchange_the_expected_inode() {
    let tree = TestDir::new("same-type-replacement");
    let root = Root::open(tree.path()).unwrap();

    let link = relative(b"link");
    root.create_symlink(&link, b"old").unwrap();
    let old_link = root.metadata(&link).unwrap();
    root.replace_symlink_if_same(&link, b"new", old_link.dev, old_link.ino)
        .unwrap();
    let new_link = root.metadata(&link).unwrap();
    assert!(new_link.is_symlink());
    assert_ne!(new_link.ino, old_link.ino);
    assert_eq!(
        fs::read_link(tree.path().join("link")).unwrap(),
        Path::new("new")
    );

    let fifo = relative(b"fifo");
    root.create_node(&fifo, MODE_FIFO | 0o644, 0).unwrap();
    let old_fifo = root.metadata(&fifo).unwrap();
    root.replace_node_if_same(&fifo, MODE_FIFO | 0o600, 0, old_fifo.dev, old_fifo.ino)
        .unwrap();
    let new_fifo = root.metadata(&fifo).unwrap();
    assert_eq!(new_fifo.file_type(), MODE_FIFO);
    assert_ne!(new_fifo.ino, old_fifo.ino);
}

#[test]
fn any_publication_never_rolls_back_a_later_writer() {
    let tree = TestDir::new("any-publication-race");
    let root = Root::open(tree.path()).unwrap();
    let staged = relative(b"staged");
    let target = relative(b"target");
    fs::write(tree.path().join("staged"), b"staged").unwrap();
    fs::write(tree.path().join("target"), b"old").unwrap();
    let staged_file = File::open(tree.path().join("staged")).unwrap();
    let metadata = staged_file.metadata().unwrap();

    let target_path = tree.path().join("target");
    let _hook = install_publication_test_hook(
        root.identity(),
        &target,
        PublicationTestPoint::AfterAnyRename,
        move || {
            fs::remove_file(&target_path).unwrap();
            fs::write(&target_path, b"later").unwrap();
        },
    );
    root.rename_regular_if_same(&staged, &target, (metadata.dev(), metadata.ino()))
        .unwrap();
    assert_eq!(fs::read(tree.path().join("target")).unwrap(), b"later");
    assert!(!tree.path().join("staged").exists());
    assert_eq!(metadata.ino(), staged_file.metadata().unwrap().ino());
}

#[test]
fn absent_publication_never_unlinks_a_later_writer() {
    let tree = TestDir::new("absent-publication-race");
    let root = Root::open(tree.path()).unwrap();
    let staged = relative(b"staged");
    let target = relative(b"target");
    fs::write(tree.path().join("staged"), b"staged").unwrap();
    let metadata = fs::metadata(tree.path().join("staged")).unwrap();

    let target_path = tree.path().join("target");
    let _hook = install_publication_test_hook(
        root.identity(),
        &target,
        PublicationTestPoint::AfterAbsentLink,
        move || {
            fs::remove_file(&target_path).unwrap();
            fs::write(&target_path, b"later").unwrap();
        },
    );
    let error = root
        .publish_new_regular(&staged, &target, (metadata.dev(), metadata.ino()))
        .unwrap_err();

    assert!(format!("{error:#}").contains("changed during publication"));
    assert_eq!(fs::read(tree.path().join("target")).unwrap(), b"later");
    assert_eq!(fs::read(tree.path().join("staged")).unwrap(), b"staged");
}

#[test]
fn matched_publication_authenticates_the_held_staged_inode() {
    let tree = TestDir::new("matched-publication-staged-identity");
    let root = Root::open(tree.path()).unwrap();
    let staged = relative(b"staged");
    let target = relative(b"target");
    fs::write(tree.path().join("staged"), b"staged").unwrap();
    fs::write(tree.path().join("target"), b"old").unwrap();
    let staged_file = File::open(tree.path().join("staged")).unwrap();
    let staged_metadata = staged_file.metadata().unwrap();
    let target_metadata = root.metadata(&target).unwrap();

    fs::rename(tree.path().join("staged"), tree.path().join("held-staged")).unwrap();
    fs::write(tree.path().join("staged"), b"impostor").unwrap();
    let error = root
        .replace_regular_if_same(
            &staged,
            &target,
            (staged_metadata.dev(), staged_metadata.ino()),
            target_metadata.dev,
            target_metadata.ino,
            None,
        )
        .unwrap_err();

    assert!(format!("{error:#}").contains("not the expected singly-linked regular file"));
    assert_eq!(fs::read(tree.path().join("target")).unwrap(), b"old");
    assert_eq!(fs::read(tree.path().join("staged")).unwrap(), b"impostor");
    assert_eq!(
        staged_metadata.ino(),
        fs::metadata(tree.path().join("held-staged")).unwrap().ino()
    );
}

#[test]
fn matched_publication_detects_a_staged_race_during_exchange() {
    let tree = TestDir::new("matched-publication-staged-race");
    let root = Root::open(tree.path()).unwrap();
    let staged = relative(b"staged");
    let target = relative(b"target");
    fs::write(tree.path().join("staged"), b"staged").unwrap();
    fs::write(tree.path().join("target"), b"old").unwrap();
    let staged_file = File::open(tree.path().join("staged")).unwrap();
    let staged_metadata = staged_file.metadata().unwrap();
    let target_metadata = root.metadata(&target).unwrap();

    let staged_path = tree.path().join("staged");
    let held_staged_path = tree.path().join("held-staged");
    let _before_exchange = install_publication_test_hook(
        root.identity(),
        &target,
        PublicationTestPoint::BeforeMatchedExchange,
        move || {
            fs::rename(&staged_path, &held_staged_path).unwrap();
            fs::write(&staged_path, b"impostor").unwrap();
        },
    );
    let error = root
        .replace_regular_if_same(
            &staged,
            &target,
            (staged_metadata.dev(), staged_metadata.ino()),
            target_metadata.dev,
            target_metadata.ino,
            None,
        )
        .unwrap_err();

    assert!(format!("{error:#}").contains("staged path staged changed during publication"));
    assert_eq!(fs::read(tree.path().join("target")).unwrap(), b"impostor");
    assert_eq!(fs::read(tree.path().join("staged")).unwrap(), b"old");
    assert_eq!(
        fs::read(tree.path().join("held-staged")).unwrap(),
        b"staged"
    );
}

#[test]
fn matched_publication_never_rolls_back_a_later_writer() {
    let tree = TestDir::new("matched-publication-race");
    let root = Root::open(tree.path()).unwrap();
    let staged = relative(b"staged");
    let target = relative(b"target");
    fs::write(tree.path().join("staged"), b"staged").unwrap();
    fs::write(tree.path().join("target"), b"old").unwrap();
    let staged_metadata = fs::metadata(tree.path().join("staged")).unwrap();
    let target_metadata = root.metadata(&target).unwrap();

    let target_path = tree.path().join("target");
    let old_target_path = tree.path().join("old-target");
    let _before_exchange = install_publication_test_hook(
        root.identity(),
        &target,
        PublicationTestPoint::BeforeMatchedExchange,
        move || {
            fs::rename(&target_path, &old_target_path).unwrap();
            fs::write(&target_path, b"raced-before-exchange").unwrap();
        },
    );
    let target_path = tree.path().join("target");
    let published_staged_path = tree.path().join("published-staged");
    let _after_exchange = install_publication_test_hook(
        root.identity(),
        &target,
        PublicationTestPoint::AfterMatchedExchange,
        move || {
            fs::rename(&target_path, &published_staged_path).unwrap();
            fs::write(&target_path, b"later").unwrap();
        },
    );
    let error = root
        .replace_regular_if_same(
            &staged,
            &target,
            (staged_metadata.dev(), staged_metadata.ino()),
            target_metadata.dev,
            target_metadata.ino,
            None,
        )
        .unwrap_err();

    assert!(format!("{error:#}").contains("changed during publication"));
    assert_eq!(fs::read(tree.path().join("target")).unwrap(), b"later");
    assert_eq!(
        fs::read(tree.path().join("staged")).unwrap(),
        b"raced-before-exchange"
    );
    assert_eq!(fs::read(tree.path().join("old-target")).unwrap(), b"old");
    assert_eq!(
        fs::read(tree.path().join("published-staged")).unwrap(),
        b"staged"
    );
}

#[test]
fn matched_leaf_replacement_never_rolls_back_a_later_writer() {
    let tree = TestDir::new("matched-leaf-race");
    let root = Root::open(tree.path()).unwrap();
    let target = relative(b"target");
    root.create_symlink(&target, b"old").unwrap();
    let target_metadata = root.metadata(&target).unwrap();

    let target_path = tree.path().join("target");
    let old_target_path = tree.path().join("old-target");
    let _before_exchange = install_publication_test_hook(
        root.identity(),
        &target,
        PublicationTestPoint::BeforeMatchedExchange,
        move || {
            fs::rename(&target_path, &old_target_path).unwrap();
            symlink("raced-before-exchange", &target_path).unwrap();
        },
    );
    let target_path = tree.path().join("target");
    let published_replacement_path = tree.path().join("published-replacement");
    let _after_exchange = install_publication_test_hook(
        root.identity(),
        &target,
        PublicationTestPoint::AfterMatchedExchange,
        move || {
            fs::rename(&target_path, &published_replacement_path).unwrap();
            symlink("later", &target_path).unwrap();
        },
    );
    let error = root
        .replace_symlink_if_same(
            &target,
            b"replacement",
            target_metadata.dev,
            target_metadata.ino,
        )
        .unwrap_err();

    assert!(format!("{error:#}").contains("changed during replacement"));
    assert_eq!(
        fs::read_link(tree.path().join("target")).unwrap(),
        Path::new("later")
    );
    assert_eq!(
        fs::read_link(tree.path().join("old-target")).unwrap(),
        Path::new("old")
    );
    assert_eq!(
        fs::read_link(tree.path().join("published-replacement")).unwrap(),
        Path::new("replacement")
    );
}

#[test]
fn root_path_cannot_be_used_as_a_mutating_leaf() {
    let tree = TestDir::new("empty-leaf");
    let root = Root::open(tree.path()).unwrap();
    let empty = relative(b"");
    assert!(root.create_file(&empty, 0o600).is_err());
    assert!(root.create_directory(&empty, 0o700).is_err());
    assert!(root.unlink(&empty).is_err());
    assert!(root.remove_directory(&empty).is_err());
    assert!(root.rename(&empty, &relative(b"other")).is_err());
    assert!(root.open_directory(&empty).is_ok());
}

#[test]
fn os_string_conversion_in_test_is_byte_exact() {
    let name = OsStr::from_bytes(b"byte-\xff");
    assert_eq!(name.as_bytes(), b"byte-\xff");
}

#[test]
fn creating_parent_handle_rejects_links_and_keeps_selected_directory() {
    let tree = TestDir::new("creating-parent");
    let outside = TestDir::new("creating-parent-outside");
    let root = Root::open(tree.path()).unwrap();
    let parent = root
        .resolve_parent_creating(&relative(b"a/b/leaf"), 0o755)
        .unwrap();
    fs::rename(tree.path().join("a/b"), tree.path().join("held")).unwrap();
    symlink(outside.path(), tree.path().join("a/b")).unwrap();
    parent.create_directory(0o755).unwrap();
    assert!(tree.path().join("held/leaf").is_dir());
    assert!(!outside.path().join("leaf").exists());
    assert!(root
        .resolve_parent_creating(&relative(b"a/b/other"), 0o755)
        .is_err());
    root.resolve_parent_creating(&relative(b"top"), 0o755)
        .unwrap()
        .create_directory(0o755)
        .unwrap();
    assert!(tree.path().join("top").is_dir());
}

#[test]
fn hardlink_publication_is_confined_and_rejects_a_replaced_representative() {
    let tree = TestDir::new("hardlinks");
    let root = Root::open(tree.path()).unwrap();
    fs::write(tree.path().join("source"), b"payload").unwrap();
    fs::write(tree.path().join("outside"), b"untouched").unwrap();
    symlink("outside", tree.path().join("target")).unwrap();
    let source = relative(b"source");
    let target = relative(b"target");
    let original = root.metadata(&source).unwrap();
    let identity = (original.dev, original.ino);
    root.publish_hardlink(&source, &target, identity).unwrap();
    root.publish_hardlink(&source, &target, identity).unwrap();
    assert_eq!(root.metadata(&target).unwrap().ino, original.ino);
    assert_eq!(fs::read(tree.path().join("outside")).unwrap(), b"untouched");
    fs::remove_file(tree.path().join("source")).unwrap();
    symlink("outside", tree.path().join("source")).unwrap();
    assert!(root
        .publish_hardlink(&source, &relative(b"other"), identity)
        .is_err());
    assert!(!tree.path().join("other").exists());
    fs::create_dir(tree.path().join("directory")).unwrap();
    assert!(root
        .publish_hardlink(&target, &relative(b"directory"), identity)
        .is_err());
    assert!(tree.path().join("directory").is_dir());
}

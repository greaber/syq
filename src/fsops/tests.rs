#[test]
fn replacement_names_preserve_existing_recovery_format() {
    assert_eq!(recovery_name(123, 456), ".syq-swap-123-456");
    // Literal old names stay protected; never regenerate this inventory.
    for name in [
        ".syq-swap-123-456",
        ".syq-swap-0-0",
        ".syq-swap-4294967295-18446744073709551615",
    ] {
        assert!(is_recovery_name(OsStr::new(name)));
    }
    for name in [
        ".syq-swap-",
        ".syq-swap-123-",
        ".syq-swap--456",
        ".syq-swap-123-456-extra",
        ".syq-swap-123-x",
    ] {
        assert!(!is_recovery_name(OsStr::new(name)));
    }
}

#[test]
fn prune_lookup_distinguishes_missing_paths_from_inspection_errors() {
    use std::os::unix::fs::PermissionsExt;
    let tree = crate::test_support::tempdir().unwrap();
    let root = tree.path();
    fs::create_dir(root.join("sub")).unwrap();
    fs::write(root.join("sub/file"), b"contents").unwrap();
    let mut ops = FsOps::new();
    ops.destination_root = Some(Arc::new(Root::open(root).unwrap()));
    let stats = ops
        .prune_lookup(&[b"missing/child".to_vec(), b"sub/file".to_vec()], None)
        .unwrap();
    assert!(stats[0].is_none());
    assert_eq!(stats[1].as_ref().unwrap().size, 8);
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipping permission denial: running as root");
        return;
    }
    fs::set_permissions(root.join("sub"), fs::Permissions::from_mode(0o000)).unwrap();
    let denied = ops.prune_lookup(&[b"sub/file".to_vec()], None);
    fs::set_permissions(root.join("sub"), fs::Permissions::from_mode(0o700)).unwrap();
    let error = denied.unwrap_err();
    assert_eq!(
        error.downcast_ref::<io::Error>().unwrap().kind(),
        io::ErrorKind::PermissionDenied
    );
}

use super::*;
use std::ffi::OsString;
use std::os::unix::fs::{symlink, FileTypeExt};
use std::sync::atomic::{AtomicU64, Ordering};

#[test]
fn selected_hash_is_independent_of_payload_integrity() {
    use crate::hashing::{HashAlgorithm, HashPolicy};
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source");
    fs::write(&path, b"file contents").unwrap();
    for algorithm in [
        HashAlgorithm::Blake3,
        HashAlgorithm::Sha256,
        HashAlgorithm::Md5,
        HashAlgorithm::Xxh3,
    ] {
        let mut operations = FsOps::new();
        operations.set_hash_policy(HashPolicy {
            algorithm,
            transfer_integrity: false,
            transfer_hash_type: None,
        });
        let response = operations
            .read_range(path.as_os_str().as_bytes(), None, 0, 0, 13)
            .unwrap();
        assert!(matches!(response, Response::Block { hash, .. } if hash == [0;32]));
        let response = operations
            .file_hash(path.as_os_str().as_bytes(), None, None)
            .unwrap();
        assert!(
            matches!(response, Response::FileHash { hash, .. } if hash == algorithm.hash(b"file contents"))
        );
        operations.set_hash_policy(HashPolicy {
            algorithm,
            transfer_integrity: true,
            transfer_hash_type: None,
        });
        let response = operations
            .read_range(path.as_os_str().as_bytes(), None, 0, 0, 13)
            .unwrap();
        assert!(
            matches!(response, Response::Block { hash, .. } if hash == algorithm.hash(b"file contents"))
        );
    }
}

#[test]
fn payload_integrity_checks_are_explicit() {
    use crate::hashing::{HashAlgorithm, HashPolicy};
    let directory = tempfile::tempdir().unwrap();
    let path = b"target";
    let copy_id = [3; 16];
    let mut operations = destination_ops(directory.path());
    operations.set_hash_policy(HashPolicy::default());
    operations
        .prepare(
            PartialTarget {
                path,
                id: &copy_id,
                guard: None,
            },
            PrepareOptions {
                size: 3,
                inplace: false,
                mode: 0o600,
                attempt: 0,
                create_if_missing: true,
            },
        )
        .unwrap();
    operations
        .write_range(
            PartialTarget {
                path,
                id: &copy_id,
                guard: None,
            },
            false,
            0,
            0,
            [19; 32],
            b"old",
        )
        .unwrap();
    for algorithm in [
        HashAlgorithm::Blake3,
        HashAlgorithm::Sha256,
        HashAlgorithm::Md5,
        HashAlgorithm::Xxh3,
    ] {
        operations.set_hash_policy(HashPolicy {
            algorithm,
            transfer_integrity: true,
            transfer_hash_type: None,
        });
        assert!(operations
            .write_range(
                PartialTarget {
                    path,
                    id: &copy_id,
                    guard: None
                },
                false,
                0,
                0,
                [19; 32],
                b"new"
            )
            .is_err());
        operations
            .write_range(
                PartialTarget {
                    path,
                    id: &copy_id,
                    guard: None,
                },
                false,
                0,
                0,
                algorithm.hash(b"new"),
                b"new",
            )
            .unwrap();
    }
}

#[test]
fn expected_digest_failure_preserves_existing_destination() {
    use crate::hashing::{Digest, HashAlgorithm, HashPolicy};
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("target");
    fs::write(&target, b"old").unwrap();
    let path = b"target";
    let copy_id = [7; 16];
    let mut operations = destination_ops(directory.path());
    operations.set_hash_policy(HashPolicy::default());
    operations
        .prepare(
            PartialTarget {
                path,
                id: &copy_id,
                guard: None,
            },
            PrepareOptions {
                size: 3,
                inplace: false,
                mode: 0o600,
                attempt: 0,
                create_if_missing: true,
            },
        )
        .unwrap();
    operations
        .write_range(
            PartialTarget {
                path,
                id: &copy_id,
                guard: None,
            },
            false,
            0,
            0,
            [0; 32],
            b"new",
        )
        .unwrap();
    let meta = Meta {
        mode: 0o600,
        uid: 0,
        gid: 0,
        mtime: 0,
        mtime_nsec: 0,
    };
    let expected = Digest::hash_bytes(HashAlgorithm::Md5, b"bad");
    assert!(operations
        .finalize_expected(
            Some(&expected),
            path,
            false,
            &copy_id,
            &meta,
            0,
            TargetMutation {
                condition: TargetCondition::Any,
                guard: None
            }
        )
        .is_err());
    assert_eq!(fs::read(&target).unwrap(), b"old");
    let expected = Digest::hash_bytes(HashAlgorithm::Md5, b"new");
    operations
        .finalize_expected(
            Some(&expected),
            path,
            false,
            &copy_id,
            &meta,
            0,
            TargetMutation {
                condition: TargetCondition::Any,
                guard: None,
            },
        )
        .unwrap();
    assert_eq!(fs::read(&target).unwrap(), b"new");
}

fn test_dir() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    crate::test_support::temp_dir().join(format!(
        "syq-fsops-test-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

/// A worker whose destination root is the existing directory `root`,
/// reached by that spelling. Its methods take paths relative to `root`.
fn destination_ops(root: &Path) -> FsOps {
    let mut ops = FsOps::new();
    ops.destination_root = Some(Arc::new(Root::open(root).unwrap()));
    ops.destination_prefix = Some(path_bytes(root));
    ops
}

fn make_fifo(path: &Path, mode: libc::mode_t) {
    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), mode) }, 0);
}

fn registered_source_worker(
    selections: &[&Path],
    allow_unconfined_paths: bool,
) -> (FsOps, Vec<RegisteredPath>, FsOps) {
    let session = DescriptorSessionSlot::default();
    let mut control = FsOps::with_descriptor_session(session.clone());
    let response = control.handle(&Request::RegisterSourceRoots {
        base: SourceRootBase::default(),
        selections: selections
            .iter()
            .map(|path| SourceRootSelection {
                path: path.as_os_str().as_bytes().to_vec(),
                follow_root: false,
            })
            .collect(),
        symlink_policy: OperatorSymlinkPolicy::Refuse,
        allow_unconfined_paths,
        shared_workers: 0,
        independent_handoff_workers: 0,
    });
    let Response::SourceRootsRegistered(roots) = response else {
        panic!("unexpected source registration response: {response:?}")
    };
    let selections = roots.iter().map(|root| root.selection.clone()).collect();
    let mut worker = FsOps::with_descriptor_session(session);
    worker.initialize_sources(&roots).unwrap();
    // Return the control endpoint so tests retain the complete session
    // lifecycle in addition to each worker's own root and leaf clones.
    (worker, selections, control)
}

#[cfg(target_os = "macos")]
#[test]
fn macos_receiver_refuses_inplace_copy_without_touching_files() {
    let temporary = crate::test_support::tempdir().unwrap();
    let source = temporary.path().join("source");
    let destination = temporary.path().join("destination");
    fs::write(&source, b"new bytes").unwrap();
    fs::create_dir(&destination).unwrap();
    let existing = destination.join("existing");
    fs::write(&existing, b"old bytes").unwrap();
    let original_inode = existing.metadata().unwrap().ino();
    let (mut worker, sources, _control) = registered_source_worker(&[&source], false);
    worker.destination_root = Some(Arc::new(Root::open(&destination).unwrap()));
    for name in [b"existing".as_slice(), b"missing"] {
        let response = worker.handle(&Request::CopyLocal {
            source: sources[0].clone(),
            dst: name.to_vec(),
            inplace: true,
            allow_sequential_nfs_fallback: false,
            allow_sequential_local_fallback: false,
            copy_id: [38; 16],
            size: 9,
            mode: 0o600,
        });
        assert!(
            matches!(response, Response::CopyLocalUnsupported),
            "{response:?}"
        );
    }
    assert_eq!(fs::read(&existing).unwrap(), b"old bytes");
    assert_eq!(existing.metadata().unwrap().ino(), original_inode);
    assert_eq!(fs::read_dir(&destination).unwrap().count(), 1);
    assert_eq!(fs::read(&source).unwrap(), b"new bytes");
}

#[cfg(target_os = "linux")]
#[test]
fn direct_copy_rejects_eof_before_the_planned_size() {
    let temporary = crate::test_support::tempdir().unwrap();
    let source = temporary.path().join("source");
    let destination = temporary.path().join("destination");
    fs::write(&source, b"short").unwrap();
    fs::create_dir(&destination).unwrap();
    fs::write(destination.join("file"), b"old complete file").unwrap();
    let (mut worker, sources, _control) = registered_source_worker(&[&source], false);
    worker.destination_root = Some(Arc::new(Root::open(&destination).unwrap()));
    let result = worker.copy_local(
        &sources[0],
        b"file",
        CopyLocalPolicy {
            inplace: false,
            allow_sequential_nfs_fallback: false,
            allow_sequential_local_fallback: true,
        },
        &[37; 16],
        100,
        0o600,
    );
    assert!(result.is_err(), "a short copy cannot be finalized");
    assert_eq!(
        fs::read(destination.join("file")).unwrap(),
        b"old complete file"
    );
}

#[test]
fn oversized_reads_are_rejected_before_allocation() {
    let temporary = crate::test_support::tempdir().unwrap();
    let selected = temporary.path().join("selected");
    fs::create_dir(&selected).unwrap();
    fs::write(selected.join("marker"), b"original").unwrap();
    let (mut worker, selections, _control) = registered_source_worker(&[&selected], false);
    let marker = selections[0].join(b"marker").unwrap();
    let path = selected.join("marker").as_os_str().as_bytes().to_vec();

    let response = worker.handle(&Request::ReadRange {
        path: path.clone(),
        source: Some(marker.clone()),
        attempt: 0,
        off: 0,
        len: u32::MAX,
    });
    assert!(
        matches!(&response, Response::EndpointError(error) if error.message.contains("exceed")),
        "{response:?}"
    );

    // Each read stays under the limit; together they exceed it.
    let half = u32::try_from(MAX_READ_BYTES / 2 + 1).unwrap();
    let read = SmallRead {
        path: path.clone(),
        source: Some(marker.clone()),
        attempt: 0,
        len: half,
    };
    let response = worker.handle(&Request::ReadSmallBatch(vec![read.clone(), read]));
    assert!(
        matches!(&response, Response::EndpointError(error) if error.message.contains("exceed")),
        "{response:?}"
    );

    // A read within the limit still reaches the file.
    let response = worker.handle(&Request::ReadRange {
        path,
        source: Some(marker),
        attempt: 0,
        off: 0,
        len: 8,
    });
    assert!(matches!(response, Response::Block { data, .. } if data == b"original"));
}

#[test]
fn existing_regular_open_does_not_follow_leaf_symlinks() {
    let dir = test_dir();
    fs::create_dir(&dir).unwrap();
    let file = dir.join("file");
    let link = dir.join("link");
    fs::write(&file, b"data").unwrap();
    symlink(&file, &link).unwrap();

    let regular_opened = open_existing_regular(&file, false).is_ok();
    let link_rejected = open_existing_regular(&link, false).is_err();
    fs::remove_dir_all(&dir).unwrap();

    assert!(regular_opened);
    assert!(link_rejected);
}

#[test]
fn guarded_inplace_updates_are_confined_and_keep_the_target_inode() {
    let dir = test_dir();
    let root_path = dir.join("root");
    let outside = dir.join("outside");
    fs::create_dir_all(&root_path).unwrap();
    fs::create_dir_all(&outside).unwrap();
    let target = root_path.join("file");
    let sentinel = outside.join("sentinel");
    fs::write(&target, b"old").unwrap();
    fs::write(&sentinel, b"outside").unwrap();
    symlink(&outside, root_path.join("escape")).unwrap();

    let root = Root::open(&root_path).unwrap();
    let identity = root.identity();
    let guard = ContainerGuard {
        root: root_path.as_os_str().as_bytes().to_vec(),
        dev: identity.dev,
        ino: identity.ino,
    };
    let target_bytes = target.as_os_str().as_bytes();
    let copy_id = [7; 16];
    let inode = fs::metadata(&target).unwrap().ino();
    let mut operations = FsOps::new();
    operations
        .prepare(
            PartialTarget {
                path: target_bytes,
                id: &copy_id,
                guard: Some(&guard),
            },
            PrepareOptions {
                size: 3,
                inplace: true,
                mode: 0o600,
                attempt: 0,
                create_if_missing: true,
            },
        )
        .unwrap();
    operations
        .write_range(
            PartialTarget {
                path: target_bytes,
                id: &copy_id,
                guard: Some(&guard),
            },
            true,
            0,
            0,
            content_digest(b"new"),
            b"new",
        )
        .unwrap();
    operations
        .finalize(
            target_bytes,
            true,
            &copy_id,
            &Meta {
                mode: 0o600,
                uid: 0,
                gid: 0,
                mtime: 0,
                mtime_nsec: 0,
            },
            0,
            TargetMutation {
                condition: TargetCondition::Any,
                guard: Some(&guard),
            },
        )
        .unwrap();

    assert_eq!(fs::read(&target).unwrap(), b"new");
    assert_eq!(fs::metadata(&target).unwrap().ino(), inode);
    let escaped = root_path.join("escape/sentinel");
    assert!(operations
        .prepare(
            PartialTarget {
                path: escaped.as_os_str().as_bytes(),
                id: &copy_id,
                guard: Some(&guard),
            },
            PrepareOptions {
                size: 1,
                inplace: true,
                mode: 0o600,
                attempt: 0,
                create_if_missing: true,
            },
        )
        .is_err());
    assert_eq!(fs::read(&sentinel).unwrap(), b"outside");
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn confinement_matrix_guarded_receiver_refuses_root_and_parent_swaps() {
    const CHILD_ENV: &str = "SYQ_TEST_GUARDED_MUTATION_CHILD";
    const ROOT_ENV: &str = "SYQ_TEST_GUARDED_MUTATION_ROOT";
    const TEST_NAME: &str =
        "fsops::tests::confinement_matrix_guarded_receiver_refuses_root_and_parent_swaps";

    if std::env::var_os(CHILD_ENV).is_some() {
        let root_path = PathBuf::from(std::env::var_os(ROOT_ENV).unwrap());
        let identity = Root::open(&root_path).unwrap().identity();
        let guard = ContainerGuard {
            root: root_path.as_os_str().as_bytes().to_vec(),
            dev: identity.dev,
            ino: identity.ino,
        };
        let target = root_path.join("target/parent/escaped");
        let errors = FsOps::new().apply(
            &[Op::Mkdir {
                path: target.as_os_str().as_bytes().to_vec(),
                mode: 0o755,
                condition: TargetCondition::Any,
            }],
            Some(&guard),
        );
        assert!(
            errors[0].is_some(),
            "guarded mutation followed a raced namespace"
        );
        return;
    }

    for swap_root in [false, true] {
        let temporary = crate::test_support::tempdir().unwrap();
        let root_path = temporary.path().join("root");
        let outside = temporary.path().join("outside");
        fs::create_dir_all(root_path.join("target/parent")).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("sentinel"), b"outside").unwrap();
        let ready = temporary.path().join("guarded-ready");
        let continuation = temporary.path().join("guarded-continue");

        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST_NAME, "--nocapture"])
            .env(CHILD_ENV, "1")
            .env(ROOT_ENV, &root_path)
            .env("SYQ_TEST_GUARDED_MUTATION_SUFFIX", "parent/escaped")
            .env("SYQ_TEST_GUARDED_MUTATION_READY_FILE", &ready)
            .env("SYQ_TEST_GUARDED_MUTATION_CONTINUE_FILE", &continuation)
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !ready.exists() && std::time::Instant::now() < deadline {
            assert!(
                child.try_wait().unwrap().is_none(),
                "guarded-mutation child exited before its race window"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(ready.exists(), "guarded-mutation race window timed out");

        if swap_root {
            fs::rename(&root_path, temporary.path().join("displaced-root")).unwrap();
            symlink(&outside, &root_path).unwrap();
        } else {
            fs::rename(
                root_path.join("target/parent"),
                root_path.join("target/displaced-parent"),
            )
            .unwrap();
            symlink(&outside, root_path.join("target/parent")).unwrap();
        }
        fs::write(&continuation, b"continue").unwrap();

        assert!(
            child.wait().unwrap().success(),
            "guarded-mutation child failed for swap_root={swap_root}"
        );
        assert_eq!(fs::read(outside.join("sentinel")).unwrap(), b"outside");
        assert!(!outside.join("escaped").exists());
    }
}

#[test]
fn operator_directory_walk_follows_owned_links_and_reports_missing_suffixes() {
    let dir = test_dir();
    let real = dir.join("real/nested");
    fs::create_dir_all(&real).unwrap();
    symlink("real", dir.join("relative-link")).unwrap();
    symlink(dir.join("real"), dir.join("absolute-link")).unwrap();

    let expected = fs::metadata(&real).unwrap();
    for selected in [
        dir.join("relative-link/nested"),
        dir.join("absolute-link/nested"),
    ] {
        let (_, anchor) = select_operator_directory(
            selected.as_os_str().as_bytes(),
            false,
            OperatorSymlinkPolicy::TrustedOwner,
        )
        .unwrap();
        let anchor = anchor.unwrap();
        assert_eq!((anchor.dev, anchor.ino), (expected.dev(), expected.ino()));
    }
    assert!(select_operator_directory(
        dir.join("relative-link/missing/deeper")
            .as_os_str()
            .as_bytes(),
        true,
        OperatorSymlinkPolicy::TrustedOwner,
    )
    .unwrap()
    .1
    .is_none());
    assert!(select_operator_directory(
        dir.join("relative-link/missing").as_os_str().as_bytes(),
        false,
        OperatorSymlinkPolicy::TrustedOwner,
    )
    .is_err());

    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn operator_directory_walk_can_refuse_every_symlink() {
    let dir = test_dir();
    fs::create_dir_all(dir.join("real")).unwrap();
    symlink("real", dir.join("link")).unwrap();

    let error = select_operator_directory(
        dir.join("link").as_os_str().as_bytes(),
        false,
        OperatorSymlinkPolicy::Refuse,
    )
    .err()
    .expect("no-follow policy must refuse an owned symlink");
    assert!(error.to_string().contains("pass --follow"), "{error:#}");

    let (_, anchor) = select_operator_directory(
        dir.join("link").as_os_str().as_bytes(),
        false,
        OperatorSymlinkPolicy::FollowAll,
    )
    .unwrap();
    assert!(anchor.is_some());
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn ancestry_requires_an_available_source_directory() {
    let temp = crate::test_support::tempdir().unwrap();
    let session = DescriptorSessionSlot::default();
    let ticket = session.register(File::open(temp.path()).unwrap()).unwrap();
    let mut ops = FsOps::new();
    ops.check_operator_directory(
        temp.path().as_os_str().as_bytes(),
        false,
        OperatorSymlinkPolicy::Refuse,
    )
    .unwrap();
    let check = || {
        ops.check_operator_directory_ancestry(&[DirectoryAncestryCheck {
            source_root: ticket.clone(),
            source_is_directory: true,
            suffixes: vec![Vec::new()],
        }])
    };
    assert_eq!(check().unwrap(), vec![vec![DirectoryRelation::Same]]);

    if unsafe { libc::geteuid() } != 0 {
        let socket = ticket.broker_path();
        let parent = socket.parent().unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o000)).unwrap();
        let result = check();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(error_is_kind(
            &result.unwrap_err(),
            io::ErrorKind::PermissionDenied
        ));
    } else {
        eprintln!("skipping permission denial: running as root");
    }

    session.close();
    assert!(error_is_kind(
        &check().unwrap_err(),
        io::ErrorKind::NotFound
    ));
}

#[test]
fn retained_operator_directory_reports_source_ancestry_without_following_suffix_links() {
    let dir = test_dir();
    let source = dir.join("source");
    let child = source.join("child");
    let sibling = dir.join("sibling");
    fs::create_dir_all(&child).unwrap();
    fs::create_dir_all(&sibling).unwrap();
    symlink(&source, sibling.join("link-to-source")).unwrap();
    let source = File::open(&source).unwrap();

    let select = |path: &Path, allow_missing| {
        select_operator_directory(
            path.as_os_str().as_bytes(),
            allow_missing,
            OperatorSymlinkPolicy::Refuse,
        )
        .unwrap()
        .0
    };
    assert_eq!(
        select(&dir.join("source"), false)
            .relation_to_source(&source, b"")
            .unwrap(),
        DirectoryRelation::Same
    );
    assert_eq!(
        select(&child, false)
            .relation_to_source(&source, b"")
            .unwrap(),
        DirectoryRelation::Descendant
    );
    assert_eq!(
        select(&dir.join("source/missing/deeper"), true)
            .relation_to_source(&source, b"")
            .unwrap(),
        DirectoryRelation::Descendant
    );
    assert_eq!(
        select(&sibling, false)
            .relation_to_source(&source, b"link-to-source")
            .unwrap(),
        DirectoryRelation::Separate,
        "a generated destination suffix must not follow a symlink"
    );
    assert_eq!(
        select(&child, false)
            .relation_to_source(&source, b"..")
            .unwrap(),
        DirectoryRelation::Same
    );

    assert_eq!(
        select(&dir, false)
            .relation_to_source(&source, b"")
            .unwrap(),
        DirectoryRelation::Ancestor
    );

    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn missing_operator_directory_is_created_under_retained_ancestor() {
    let dir = test_dir();
    fs::create_dir_all(dir.join("parent")).unwrap();
    fs::create_dir_all(dir.join("outside")).unwrap();
    let (mut selection, anchor) = select_operator_directory(
        dir.join("parent/missing/deeper").as_os_str().as_bytes(),
        true,
        OperatorSymlinkPolicy::TrustedOwner,
    )
    .unwrap();
    assert!(anchor.is_none());

    fs::rename(dir.join("parent"), dir.join("selected-and-moved")).unwrap();
    symlink(dir.join("outside"), dir.join("parent")).unwrap();
    selection.create_missing(0o755, false).unwrap();

    assert!(dir.join("selected-and-moved/missing/deeper").is_dir());
    assert!(!dir.join("outside/missing").exists());
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn concurrent_operator_directory_creation_reuses_the_real_directory() {
    let dir = test_dir();
    fs::create_dir_all(dir.join("parent")).unwrap();
    let selected = dir.join("parent/missing/deeper");
    let (mut first, first_anchor) = select_operator_directory(
        selected.as_os_str().as_bytes(),
        true,
        OperatorSymlinkPolicy::TrustedOwner,
    )
    .unwrap();
    let (mut second, second_anchor) = select_operator_directory(
        selected.as_os_str().as_bytes(),
        true,
        OperatorSymlinkPolicy::TrustedOwner,
    )
    .unwrap();
    assert!(first_anchor.is_none());
    assert!(second_anchor.is_none());

    let first_anchor = first.create_missing(0o755, false).unwrap();
    let second_anchor = second.create_missing(0o755, false).unwrap();
    assert_eq!(
        (first_anchor.dev, first_anchor.ino),
        (second_anchor.dev, second_anchor.ino)
    );

    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn new_operator_directory_rejects_a_concurrently_created_final_component() {
    let dir = test_dir();
    fs::create_dir_all(dir.join("parent")).unwrap();
    let selected = dir.join("parent/new");
    let (mut selection, anchor) = select_operator_directory(
        selected.as_os_str().as_bytes(),
        true,
        OperatorSymlinkPolicy::TrustedOwner,
    )
    .unwrap();
    assert!(anchor.is_none());

    fs::create_dir(&selected).unwrap();
    let error = selection.create_missing(0o755, true).unwrap_err();
    assert!(error
        .to_string()
        .contains("appeared after the new-path precondition"));

    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn existing_regular_open_does_not_block_on_fifo() {
    let dir = test_dir();
    fs::create_dir(&dir).unwrap();
    let fifo = dir.join("fifo");
    make_fifo(&fifo, 0o600);

    let started = std::time::Instant::now();
    let read_result = open_existing_regular(&fifo, false);
    let write_result = open_existing_regular(&fifo, true);
    fs::remove_dir_all(&dir).unwrap();

    assert!(read_result.is_err());
    assert!(write_result.is_err());
    assert!(
        started.elapsed() < std::time::Duration::from_secs(2),
        "opening a FIFO must not wait for a reader"
    );
}

#[test]
fn matching_condition_can_replace_a_same_type_special_file() {
    let dir = test_dir();
    fs::create_dir(&dir).unwrap();
    let fifo = dir.join("fifo");
    make_fifo(&fifo, 0o644);
    let before = fs::symlink_metadata(&fifo).unwrap();

    let errors = destination_ops(&dir).apply(
        &[Op::Mknod {
            path: b"fifo".to_vec(),
            mode: file_type_bits(before.mode()) | 0o600,
            rdev: 0,
            condition: TargetCondition::Matches {
                dev: before.dev(),
                ino: before.ino(),
            },
        }],
        None,
    );
    let after = fs::symlink_metadata(&fifo).unwrap();
    fs::remove_dir_all(&dir).unwrap();

    assert_eq!(errors, vec![None]);
    assert!(after.file_type().is_fifo());
    assert_ne!(after.ino(), before.ino());
    assert_eq!(after.mode() & 0o777, 0o600);
}

#[test]
fn safe_partial_must_have_one_link() {
    let dir = test_dir();
    fs::create_dir(&dir).unwrap();
    let file = dir.join("partial");
    let alias = dir.join("alias");
    fs::write(&file, b"data").unwrap();
    fs::hard_link(&file, &alias).unwrap();

    let opened = open_existing_regular(&file, true).unwrap();
    let rejected = require_safe_partial(&opened, &file).is_err();
    drop(opened);
    fs::remove_dir_all(&dir).unwrap();

    assert!(rejected);
}

#[test]
fn unlink_never_recurses_into_a_directory() {
    let dir = crate::test_support::temp_dir().join(format!("syq-unlink-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("d/inside")).unwrap();
    fs::write(dir.join("f"), b"f").unwrap();
    let mut ops = destination_ops(&dir);
    let path = |n: &str| n.as_bytes().to_vec();
    let errs = ops.apply(
        &[
            Op::Unlink { path: path("d") },
            Op::Unlink { path: path("f") },
            Op::Unlink {
                path: path("missing"),
            },
        ],
        None,
    );
    assert!(errs[0]
        .as_ref()
        .map(WireError::as_str)
        .is_some_and(|e| e.contains("is now a directory")));
    assert!(
        dir.join("d/inside").is_dir(),
        "the directory and its contents survive"
    );
    assert!(errs[1].is_none() && !dir.join("f").exists());
    assert!(errs[2].is_none(), "a vanished leaf is not an error");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn plan_batch_only_stats_leaves_below_ready_directories() {
    let root = test_dir();
    let ready = root.join("ready");
    let leaf = ready.join("leaf");
    fs::create_dir_all(&ready).unwrap();
    fs::write(&leaf, b"data").unwrap();
    let mut ops = FsOps::new();
    let request = |directory: &Path| Request::PlanBatch {
        partial_paths: vec![path_bytes(&leaf)],
        copy_id: [7; 16],
        directories: vec![path_bytes(directory)],
        others: vec![path_bytes(&leaf)],
        guard: None,
    };

    let Response::BatchPlan {
        partial_paths,
        directories,
        others,
    } = ops.handle(&request(&ready))
    else {
        panic!("expected a batch plan");
    };
    assert!(partial_paths[0].is_ok());
    assert_eq!(directories[0].as_ref().unwrap().kind, Kind::Dir);
    assert_eq!(others.unwrap()[0].as_ref().unwrap().kind, Kind::File);

    let Response::BatchPlan {
        directories,
        others,
        ..
    } = ops.handle(&request(&root.join("missing")))
    else {
        panic!("expected a batch plan");
    };
    assert!(directories[0].is_none());
    assert!(
        others.is_none(),
        "leaf stats must wait for directory repair"
    );

    fs::set_permissions(&ready, fs::Permissions::from_mode(0o500)).unwrap();
    let Response::BatchPlan {
        directories,
        others,
        ..
    } = ops.handle(&request(&ready))
    else {
        panic!("expected a batch plan");
    };
    assert_eq!(directories[0].as_ref().unwrap().kind, Kind::Dir);
    assert!(
        others.is_none(),
        "leaf stats must wait until the directory is writable"
    );
    fs::set_permissions(&ready, fs::Permissions::from_mode(0o700)).unwrap();

    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn partial_name_is_private_and_fits_name_max() {
    let id = [7u8; 16];
    let short = partial_path(Path::new("file"), &id).unwrap();
    let short_name = short.file_name().unwrap();
    assert!(short_name.to_string_lossy().starts_with(".file.syq-tmp."));
    assert!(is_partial_name(short_name));

    let long = PathBuf::from("n".repeat(240));
    let partial = partial_path(&long, &id).unwrap();
    let name = partial.file_name().unwrap();
    assert!(name.as_bytes().len() <= COMMON_NAME_MAX);
    assert!(is_partial_name(name));
    assert_ne!(
        partial,
        partial_path_with_name_max(&long, &[9; 16], COMMON_NAME_MAX).unwrap()
    );
}

#[test]
fn partial_names_disambiguate_truncated_basenames_and_reject_old_format() {
    let first = PathBuf::from(format!("{}a", "n".repeat(240)));
    let second = PathBuf::from(format!("{}b", "n".repeat(240)));
    for limit in [25, 26, 80, 255] {
        let a = partial_path_with_name_max(&first, &[1; 16], limit).unwrap();
        let b = partial_path_with_name_max(&second, &[1; 16], limit).unwrap();
        assert_ne!(a, b);
        assert!(a.file_name().unwrap().as_bytes().len() <= limit);
        assert!(is_partial_name(a.file_name().unwrap()));
    }
    assert!(!is_partial_name(OsStr::new(
        ".file.syq-part.aaaaaaaaaaaaaaaaaaaaaaaaaa"
    )));
    assert!(!is_partial_name(OsStr::new(
        ".file.syq-tmp.aaaaaaaaaaaaaaa"
    )));
    assert!(!is_partial_name(OsStr::new(
        ".file.syq-tmp.aaaaaaaaaaaaaaa8"
    )));
}

#[test]
fn partial_names_distinguish_aliased_parent_spellings() {
    for (left, right) in [("sub/file", "SUB/file"), ("é/file", "e\u{301}/file")] {
        for limit in [25, 80, 255] {
            let a = partial_path_with_name_max(Path::new(left), &[7; 16], limit).unwrap();
            let b = partial_path_with_name_max(Path::new(right), &[7; 16], limit).unwrap();
            assert_ne!(
                a.file_name(),
                b.file_name(),
                "same leaf in aliased parents must have distinct staging names"
            );
        }
    }
}

#[test]
fn partial_name_honors_filesystems_with_smaller_name_max() {
    let id = [8u8; 16];
    let final_path = PathBuf::from("dir").join("n".repeat(120));
    let partial = partial_path_with_name_max(&final_path, &id, 143).unwrap();
    let name = partial.file_name().unwrap();
    assert!(name.as_bytes().len() <= 143);
    assert!(is_partial_name(name));
    assert_ne!(
        partial,
        partial_path_with_name_max(&final_path, &[9; 16], 143).unwrap()
    );
}

#[test]
fn shortened_partial_name_preserves_utf8_boundaries() {
    let id = [10u8; 16];
    let final_path = PathBuf::from("dir").join("界".repeat(80));
    let partial = partial_path_with_name_max(&final_path, &id, 143).unwrap();
    let name = partial.file_name().unwrap();

    assert!(name.as_bytes().len() <= 143);
    assert!(name.to_str().is_some());
    assert!(is_partial_name(name));
}

#[test]
fn destination_activation_does_not_change_process_cwd() {
    let dir = test_dir();
    fs::create_dir(&dir).unwrap();
    let before = std::env::current_dir().unwrap();
    let mut operations = FsOps::new();

    operations
        .install_destination(File::open(&dir).unwrap(), b"logical")
        .unwrap();

    assert_eq!(std::env::current_dir().unwrap(), before);
    let response = operations.handle(&Request::Canonicalize {
        path: b"logical".to_vec(),
        guard: None,
    });
    assert!(
        matches!(response, Response::EndpointError(error) if error.message.contains(
            "canonicalize is not valid after destination capability activation"
        ))
    );
    fs::remove_dir_all(&dir).unwrap();
}

/// A destination mutation is refused until the session holds an
/// authority for it: a registered root or a signed receiver's guard. The
/// same request is served once either exists.
#[test]
fn destination_mutations_need_a_registered_root_or_a_guard() {
    let dir = test_dir();
    fs::create_dir(&dir).unwrap();
    let target = dir.join("made");
    let target_bytes = target.as_os_str().as_bytes().to_vec();
    let mkdir = |path: PathBytes, guard: Option<ContainerGuard>| Request::Apply {
        ops: vec![Op::Mkdir {
            path,
            mode: 0o755,
            condition: TargetCondition::Any,
        }],
        guard,
    };
    let put = Request::PutSmallBatch(vec![SmallPut {
        path: target_bytes.clone(),
        copy_id: [3; 16],
        data: b"new".to_vec(),
        hash: content_digest(b"new"),
        meta: Meta {
            mode: 0o600,
            uid: 0,
            gid: 0,
            mtime: 0,
            mtime_nsec: 0,
        },
        flags: 0,
        inplace: false,
        condition: TargetCondition::Absent,
        guard: None,
    }]);

    let mut unrooted = FsOps::new();
    for request in [mkdir(target_bytes.clone(), None), put] {
        let response = unrooted.handle(&request);
        assert!(
            matches!(
                &response,
                Response::Err(message) if message.contains("before a destination root")
            ),
            "{response:?}"
        );
    }
    let errors = unrooted.apply(
        &[Op::Mkdir {
            path: target_bytes.clone(),
            mode: 0o755,
            condition: TargetCondition::Any,
        }],
        None,
    );
    assert_eq!(
        errors[0].as_ref().map(WireError::as_str),
        Some(UNROOTED_MUTATION)
    );
    assert!(!target.exists());

    let root = Root::open(&dir).unwrap();
    let identity = root.identity();
    let guard = ContainerGuard {
        root: dir.as_os_str().as_bytes().to_vec(),
        dev: identity.dev,
        ino: identity.ino,
    };
    let response = unrooted.handle(&mkdir(target_bytes.clone(), Some(guard)));
    assert!(
        matches!(&response, Response::Applied(errors) if errors == &vec![None]),
        "{response:?}"
    );
    assert!(target.is_dir());
    fs::remove_dir(&target).unwrap();

    let mut rooted = FsOps::new();
    rooted
        .install_destination(File::open(&dir).unwrap(), b"logical")
        .unwrap();
    let response = rooted.handle(&mkdir(b"logical/made".to_vec(), None));
    assert!(
        matches!(&response, Response::Applied(errors) if errors == &vec![None]),
        "{response:?}"
    );
    assert!(target.is_dir());
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn put_small_stages_with_final_mode_and_truncates_reused_sidecar() {
    let dir = tempfile::tempdir().unwrap();
    let mut rooted = FsOps::new();
    rooted
        .install_destination(File::open(dir.path()).unwrap(), b"logical")
        .unwrap();
    let copy_id: CopyId = [7; 16];
    // A sidecar left by an interrupted run must be truncated before the new
    // content is written, since the new content can be shorter.
    let sidecar = partial_path_with_name_max(Path::new("logical/file"), &copy_id, 255).unwrap();
    let stale = dir.path().join(sidecar.file_name().unwrap());
    fs::write(&stale, b"stale content that is longer").unwrap();
    fs::set_permissions(&stale, fs::Permissions::from_mode(0o600)).unwrap();
    let put = |path: &[u8], mode: u32, flags: u8| SmallPut {
        path: path.to_vec(),
        copy_id,
        data: b"new".to_vec(),
        hash: content_digest(b"new"),
        meta: Meta {
            mode,
            uid: 0,
            gid: 0,
            mtime: 0,
            mtime_nsec: 0,
        },
        flags,
        inplace: false,
        condition: TargetCondition::Any,
        guard: None,
    };
    let response = rooted.handle(&Request::PutSmallBatch(vec![
        put(b"logical/file", 0o640, flags::RECEIVER_MODE),
        put(b"logical/private", 0o640, 0),
    ]));
    assert!(
        matches!(&response, Response::Applied(errors) if errors == &vec![None, None]),
        "{response:?}"
    );
    assert!(!stale.exists(), "stale sidecar must be published away");
    let file = dir.path().join("file");
    assert_eq!(fs::read(&file).unwrap(), b"new");
    assert_eq!(fs::metadata(&file).unwrap().mode() & 0o7777, 0o640);
    // Without a requested mode the sidecar's private mode is published.
    let private = dir.path().join("private");
    assert_eq!(fs::read(&private).unwrap(), b"new");
    assert_eq!(fs::metadata(&private).unwrap().mode() & 0o7777, 0o600);
}

#[test]
fn staged_file_mode_withholds_bits_that_could_widen_access_before_publication() {
    let meta = |mode: u32| Meta {
        mode,
        uid: 0,
        gid: 0,
        mtime: 0,
        mtime_nsec: 0,
    };
    // Without group preservation the sidecar carries the final bits, so
    // publication needs no chmod.
    assert_eq!(staged_file_mode(&meta(0o640), flags::RECEIVER_MODE), 0o640);
    assert_eq!(staged_file_mode(&meta(0o644), flags::MODE), 0o644);
    // Special bits wait until the content is written.
    assert_eq!(staged_file_mode(&meta(0o4755), flags::MODE), 0o755);
    // Group preservation can change the group after creation, so group
    // bits must not be granted to the group the kernel assigns.
    assert_eq!(
        staged_file_mode(&meta(0o640), flags::RECEIVER_MODE | flags::GROUP),
        PRIVATE_PARTIAL_MODE
    );
    // Without a requested mode the sidecar stays private.
    assert_eq!(staged_file_mode(&meta(0o640), 0), PRIVATE_PARTIAL_MODE);
    assert_eq!(
        staged_file_mode(&meta(0o640), flags::TIMES),
        PRIVATE_PARTIAL_MODE
    );
}

#[test]
fn small_copy_leaf_accepts_root_and_relative_prefixes_without_nested_paths() {
    for (prefix, path) in [
        (&b"/"[..], &b"/file"[..]),
        (b"/directory/", b"/directory/file"),
        (b".", b"./file"),
        (b"directory", b"directory/file"),
        (b"", b"file"),
    ] {
        assert_eq!(small_copy_leaf(prefix, path).unwrap(), b"file");
    }
    for (prefix, path) in [
        (&b"/"[..], &b"/nested/file"[..]),
        (b"/", b"//file"),
        (b"/", b"/.."),
        (b"/", b"/"),
        (b".", b"../file"),
        (b"directory", b"directory-other/file"),
        (b"directory", b"directory/nested/file"),
    ] {
        assert!(
            small_copy_leaf(prefix, path).is_err(),
            "{prefix:?}: {path:?}"
        );
    }
}

#[test]
fn small_copy_staging_failure_keeps_all_partials_for_retry() {
    const CHILD_ENV: &str = "SYQ_TEST_SMALL_COPY_STAGING_CHILD";
    if std::env::var_os(CHILD_ENV).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "fsops::tests::small_copy_staging_failure_keeps_all_partials_for_retry",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_ENV, "1")
            .env("SYQ_TEST_FAIL_PUT_SMALL_BEFORE_RENAME", "/two")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "staging test child failed: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    // macOS temp paths can traverse /var, a symlink to /private/var.
    // Exercise staging failure with a path the refusal policy accepts.
    let canonical = dir.path().canonicalize().unwrap();
    let prefix = canonical.as_os_str().as_bytes().to_vec();
    let request = SmallCopyRequest {
        directory: prefix.clone(),
        symlink_policy: OperatorSymlinkPolicy::Refuse,
        request_prefix: prefix.clone(),
        identity: SmallCopyIdentity {
            copy_id: [7; 16],
            dst_leaf: None,
        },
        flags: flags::TIMES,
        files: ["one", "two"]
            .into_iter()
            .map(|name| SmallCopyFile {
                path: join(&prefix, name.as_bytes()),
                data: name.as_bytes().to_vec(),
                hash: content_digest(name.as_bytes()),
                meta: Meta {
                    mode: 0o600,
                    uid: 0,
                    gid: 0,
                    mtime: 1_700_000_000,
                    mtime_nsec: 0,
                },
            })
            .collect(),
    };
    // The child alone injects failure after the second sidecar is
    // complete. Timestamp rejection differs between Linux and macOS.
    let response = FsOps::new().handle(&Request::CopySmallFiles(request.clone()));
    assert!(
        matches!(
            response,
            Response::SmallFilesCopied(SmallCopyResponse {
                outcome: SmallCopyOutcome::StagingFailed(_),
                ..
            })
        ),
        "{response:?}"
    );
    let mut contents: Vec<_> = fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            assert!(is_partial_name(&entry.file_name()));
            fs::read(entry.path()).unwrap()
        })
        .collect();
    contents.sort();
    assert_eq!(contents, vec![b"one".to_vec(), b"two".to_vec()]);
    assert!(!dir.path().join("one").exists());
    assert!(!dir.path().join("two").exists());

    // A fresh control session can finish the same copy with the partials
    // present, without publishing duplicates or leaving temporary files.
    std::env::remove_var("SYQ_TEST_FAIL_PUT_SMALL_BEFORE_RENAME");
    let response = FsOps::new().handle(&Request::CopySmallFiles(request));
    match response {
        Response::SmallFilesCopied(SmallCopyResponse {
            outcome: SmallCopyOutcome::Published(results),
            ..
        }) => assert_eq!(
            results,
            vec![
                SmallCopyFileResult {
                    disposition: SmallCopyDisposition::Copied,
                    error: None
                };
                2
            ]
        ),
        other => panic!("{other:?}"),
    }
    assert_eq!(fs::read(dir.path().join("one")).unwrap(), b"one");
    assert_eq!(fs::read(dir.path().join("two")).unwrap(), b"two");
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
}

/// The bounded copy stages regular files and leaves the session anchored;
/// a non-file target declines without mutations. The receiver enforces
/// bounds and leaf names, independently of coordinator eligibility.
#[test]
fn small_copy_publishes_regular_files_and_declines_other_types() {
    let dir = test_dir();
    fs::create_dir(&dir).unwrap();
    let prefix = dir.as_os_str().as_bytes().to_vec();
    let file = |name: &str, data: &[u8]| SmallCopyFile {
        path: join(&prefix, name.as_bytes()),
        data: data.to_vec(),
        hash: content_digest(data),
        meta: Meta {
            mode: 0o640,
            uid: 0,
            gid: 0,
            mtime: 1_700_000_000,
            mtime_nsec: 0,
        },
    };
    let request = |directory: PathBytes, files: Vec<SmallCopyFile>| {
        Request::CopySmallFiles(SmallCopyRequest {
            directory,
            symlink_policy: OperatorSymlinkPolicy::Refuse,
            request_prefix: prefix.clone(),
            identity: SmallCopyIdentity {
                copy_id: [7; 16],
                dst_leaf: None,
            },
            flags: flags::MODE | flags::TIMES,
            files,
        })
    };
    let message = |response: &Response| match response {
        Response::Err(message) => message.clone(),
        Response::EndpointError(error) => error.message.clone(),
        other => panic!("{other:?}"),
    };

    let mut operations = FsOps::new();
    let response = operations.handle(&request(
        prefix.clone(),
        vec![file("one", b"first"), file("two", b"")],
    ));
    match response {
        Response::SmallFilesCopied(SmallCopyResponse {
            anchor,
            outcome: SmallCopyOutcome::Published(results),
        }) => {
            assert_eq!(
                results,
                vec![
                    SmallCopyFileResult {
                        disposition: SmallCopyDisposition::Copied,
                        error: None
                    };
                    2
                ]
            );
            assert_eq!(anchor.ino, fs::metadata(&dir).unwrap().ino());
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(fs::read(dir.join("one")).unwrap(), b"first");
    assert_eq!(fs::read(dir.join("two")).unwrap(), b"");
    let metadata = fs::metadata(dir.join("one")).unwrap();
    assert_eq!(metadata.mode() & 0o7777, 0o640);
    assert_eq!(metadata.mtime(), 1_700_000_000);
    let leftovers: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .filter(|name| name != "one" && name != "two")
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
    assert!(operations.destination_root.is_some());
    let again = operations.handle(&request(prefix.clone(), vec![file("three", b"x")]));
    assert!(
        message(&again).contains("fresh control session"),
        "{again:?}"
    );
    assert!(!dir.join("three").exists());

    fs::create_dir(dir.join("directory")).unwrap();
    let mut declined = FsOps::new();
    let response = declined.handle(&request(
        prefix.clone(),
        vec![file("three", b"x"), file("directory", b"replaced")],
    ));
    assert!(
        matches!(
            &response,
            Response::SmallFilesCopied(SmallCopyResponse {
                outcome: SmallCopyOutcome::UnsupportedTarget,
                ..
            })
        ),
        "{response:?}"
    );
    assert!(!dir.join("three").exists());
    assert_eq!(fs::read(dir.join("one")).unwrap(), b"first");
    assert!(declined.destination_root.is_none() && declined.operator_selection.is_none());
    let canonical = declined.handle(&Request::Canonicalize {
        path: prefix.clone(),
        guard: None,
    });
    assert!(matches!(canonical, Response::Path(_)), "{canonical:?}");

    let nested = SmallCopyFile {
        path: join(&prefix, b"sub/deep"),
        ..file("x", b"x")
    };
    let response = FsOps::new().handle(&request(prefix.clone(), vec![nested]));
    assert!(
        message(&response).contains("one entry beneath"),
        "{response:?}"
    );
    let response = FsOps::new().handle(&request(
        prefix.clone(),
        vec![file("dup", b"a"), file("dup", b"b")],
    ));
    assert!(message(&response).contains("twice"), "{response:?}");
    let response = FsOps::new().handle(&request(prefix.clone(), Vec::new()));
    assert!(message(&response).contains("limit"), "{response:?}");
    let response = FsOps::new().handle(&request(join(&prefix, b"absent"), vec![file("x", b"x")]));
    assert!(!message(&response).is_empty());
    assert!(!dir.join("absent").exists() && !dir.join("x").exists());
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn destination_observation_uses_the_adopted_root_not_its_old_name() {
    let dir = test_dir();
    let selected = dir.join("selected");
    fs::create_dir_all(&selected).unwrap();
    fs::write(selected.join("marker"), b"original").unwrap();
    let root = Arc::new(Root::from_directory(File::open(&selected).unwrap()).unwrap());
    let mut operations = FsOps::new();
    operations.destination_root = Some(root);
    operations.destination_prefix = Some(b"logical".to_vec());

    fs::rename(&selected, dir.join("moved")).unwrap();
    fs::create_dir(&selected).unwrap();
    fs::write(selected.join("marker"), b"replacement").unwrap();

    let stats = operations.stat_many(&[b"marker".to_vec()], false, None);
    assert_eq!(stats[0].as_ref().unwrap().size, 8);
    let Response::FileHash { size, hash } = operations.file_hash(b"marker", None, None).unwrap()
    else {
        panic!("unexpected hash response");
    };
    assert_eq!(size, 8);
    assert_eq!(hash, content_digest(b"original"));

    let partial = operations.partial_paths(&[b"missing/deeper/marker".to_vec()], &[12; 16], None);
    assert!(partial[0]
        .as_ref()
        .unwrap()
        .starts_with(b"missing/deeper/.marker.syq-tmp."));
    assert!(operations.partial_paths(&[b"../outside".to_vec()], &[12; 16], None)[0].is_err());
    assert!(operations.file_hash(b"../outside", None, None).is_err());
    assert!(operations.stat_many(&[b"../outside".to_vec()], false, None)[0].is_none());

    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn unmatched_basis_creates_private_empty_stage_without_copying_old_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("basis");
    fs::write(&path, b"old contents").unwrap();
    let copy_id = [42; 16];
    let mut operations = destination_ops(directory.path());
    operations
        .hash_and_hold(
            b"basis",
            &copy_id,
            MIN_HASH_BLOCK_BYTES,
            12,
            TargetCondition::Any,
            None,
        )
        .unwrap();
    operations
        .seed_basis(
            PartialTarget {
                path: b"basis",
                id: &copy_id,
                guard: None,
            },
            12,
            MIN_HASH_BLOCK_BYTES,
            Some(&[] as &[(u64, u64)]),
            0,
        )
        .unwrap();
    let partial = partial_path(&path, &copy_id).unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"old contents");
    assert_eq!(fs::read(&partial).unwrap(), vec![0; 12]);
    assert_eq!(
        fs::metadata(&partial).unwrap().permissions().mode() & 0o777,
        PRIVATE_PARTIAL_MODE
    );
    assert!(operations.held_basis.is_none());
}

#[test]
fn destination_file_state_uses_the_adopted_root_and_refuses_symlink_parents() {
    let dir = test_dir();
    let selected = dir.join("selected");
    let moved = dir.join("moved");
    let outside = dir.join("outside");
    fs::create_dir_all(&selected).unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::write(selected.join("basis"), b"held").unwrap();
    fs::write(selected.join("inplace"), b"original").unwrap();
    let root = Arc::new(Root::from_directory(File::open(&selected).unwrap()).unwrap());
    let mut operations = FsOps::new();
    operations.destination_root = Some(root);
    operations.destination_prefix = Some(path_bytes(&selected));

    fs::rename(&selected, &moved).unwrap();
    fs::create_dir(&selected).unwrap();
    fs::write(selected.join("basis"), b"replacement").unwrap();
    fs::write(selected.join("inplace"), b"replacement").unwrap();

    let copy_id = [31; 16];
    let (hashes, held_len) = operations
        .hash_and_hold(
            b"basis",
            &copy_id,
            MIN_HASH_BLOCK_BYTES,
            4,
            TargetCondition::Any,
            None,
        )
        .unwrap();
    assert_eq!(hashes, vec![content_digest(b"held")]);
    assert_eq!(held_len, 4);
    operations
        .seed_basis(
            PartialTarget {
                path: b"basis",
                id: &copy_id,
                guard: None,
            },
            4,
            MIN_HASH_BLOCK_BYTES,
            None,
            0,
        )
        .unwrap();
    let basis_name = partial_path(&selected.join("basis"), &copy_id).unwrap();
    let basis_partial = moved.join(basis_name.file_name().unwrap());
    assert_eq!(fs::read(&basis_partial).unwrap(), b"held");
    let Response::PartialSize(partial_size) =
        operations.probe_partial(b"basis", &copy_id, None).unwrap()
    else {
        panic!("unexpected partial probe response");
    };
    assert_eq!(partial_size, Some(4));
    assert_eq!(
        operations
            .hash_blocks(
                HashTarget {
                    path: b"basis",
                    source: None,
                    guard: None,
                },
                HashOptions {
                    which: Which::Partial,
                    block: MIN_HASH_BLOCK_BYTES,
                    len: 4,
                    attempt: 0,
                },
                &copy_id,
            )
            .unwrap(),
        vec![content_digest(b"held")]
    );

    operations
        .hash_and_hold(
            b"basis",
            &copy_id,
            MIN_HASH_BLOCK_BYTES,
            4,
            TargetCondition::Any,
            None,
        )
        .unwrap();
    operations
        .finish_basis(
            b"basis",
            &copy_id,
            &Meta {
                mode: 0o600,
                uid: 0,
                gid: 0,
                mtime: 0,
                mtime_nsec: 0,
            },
            flags::MODE,
            TargetCondition::Any,
            None,
        )
        .unwrap();
    assert_eq!(
        fs::metadata(moved.join("basis")).unwrap().mode() & 0o777,
        0o600
    );
    assert_ne!(
        fs::metadata(selected.join("basis")).unwrap().mode() & 0o777,
        0o600
    );

    let stale_name = partial_path(&selected.join("inplace"), &copy_id).unwrap();
    let stale = moved.join(stale_name.file_name().unwrap());
    fs::write(&stale, b"stale").unwrap();
    operations
        .prepare(
            PartialTarget {
                path: b"inplace",
                id: &copy_id,
                guard: None,
            },
            PrepareOptions {
                size: 2,
                inplace: true,
                mode: 0o600,
                attempt: 0,
                create_if_missing: true,
            },
        )
        .unwrap();
    assert_eq!(fs::metadata(moved.join("inplace")).unwrap().len(), 2);
    assert!(!stale.exists());
    assert_eq!(fs::read(selected.join("inplace")).unwrap(), b"replacement");

    symlink(&outside, moved.join("redirect")).unwrap();
    assert!(operations
        .prepare(
            PartialTarget {
                path: b"redirect/escaped",
                id: &copy_id,
                guard: None,
            },
            PrepareOptions {
                size: 1,
                inplace: false,
                mode: 0o600,
                attempt: 0,
                create_if_missing: true,
            },
        )
        .is_err());
    assert!(operations
        .hash_blocks(
            HashTarget {
                path: b"redirect/escaped",
                source: None,
                guard: None,
            },
            HashOptions {
                which: Which::Final,
                block: MIN_HASH_BLOCK_BYTES,
                len: 1,
                attempt: 0,
            },
            &copy_id,
        )
        .is_err());
    assert!(!outside.join("escaped").exists());
    assert!(operations
        .probe_partial(b"../outside", &copy_id, None)
        .is_err());

    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn destination_writes_publish_inside_the_adopted_root() {
    let dir = test_dir();
    let selected = dir.join("selected");
    let moved = dir.join("moved");
    let outside = dir.join("outside");
    fs::create_dir_all(&selected).unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::write(selected.join("existing"), b"old").unwrap();
    fs::write(selected.join("inplace"), b"old").unwrap();
    let root = Arc::new(Root::from_directory(File::open(&selected).unwrap()).unwrap());
    let mut operations = FsOps::new();
    operations.destination_root = Some(root);
    operations.destination_prefix = Some(path_bytes(&selected));

    fs::rename(&selected, &moved).unwrap();
    fs::create_dir(&selected).unwrap();
    fs::write(selected.join("small"), b"replacement-root").unwrap();
    fs::write(selected.join("existing"), b"replacement-root").unwrap();
    fs::write(selected.join("inplace"), b"replacement-root").unwrap();

    let meta = Meta {
        mode: 0o600,
        uid: 0,
        gid: 0,
        mtime: 0,
        mtime_nsec: 0,
    };
    let copy_id = [41; 16];
    operations
        .put_small(&SmallPut {
            path: b"small".to_vec(),
            copy_id,
            data: b"small-data".to_vec(),
            hash: content_digest(b"small-data"),
            meta,
            flags: 0,
            inplace: false,
            condition: TargetCondition::Absent,
            guard: None,
        })
        .unwrap();
    assert_eq!(fs::read(moved.join("small")).unwrap(), b"small-data");
    assert_eq!(
        fs::read(selected.join("small")).unwrap(),
        b"replacement-root"
    );

    let existing = fs::metadata(moved.join("existing")).unwrap();
    operations
        .put_small(&SmallPut {
            path: b"existing".to_vec(),
            copy_id,
            data: b"new".to_vec(),
            hash: content_digest(b"new"),
            meta,
            flags: 0,
            inplace: false,
            condition: TargetCondition::Matches {
                dev: existing.dev(),
                ino: existing.ino(),
            },
            guard: None,
        })
        .unwrap();
    assert_eq!(fs::read(moved.join("existing")).unwrap(), b"new");
    assert_eq!(
        fs::metadata(moved.join("existing")).unwrap().ino(),
        existing.ino()
    );
    assert_eq!(
        fs::read(selected.join("existing")).unwrap(),
        b"replacement-root"
    );

    operations
        .prepare(
            PartialTarget {
                path: b"ranged",
                id: &copy_id,
                guard: None,
            },
            PrepareOptions {
                size: 6,
                inplace: false,
                mode: 0o600,
                attempt: 0,
                create_if_missing: true,
            },
        )
        .unwrap();
    operations
        .write_range(
            PartialTarget {
                path: b"ranged",
                id: &copy_id,
                guard: None,
            },
            false,
            0,
            0,
            content_digest(b"ranged"),
            b"ranged",
        )
        .unwrap();
    operations
        .finalize(
            b"ranged",
            false,
            &copy_id,
            &meta,
            0,
            TargetMutation {
                condition: TargetCondition::Absent,
                guard: None,
            },
        )
        .unwrap();
    assert_eq!(fs::read(moved.join("ranged")).unwrap(), b"ranged");
    assert!(!selected.join("ranged").exists());

    operations
        .prepare(
            PartialTarget {
                path: b"inplace",
                id: &copy_id,
                guard: None,
            },
            PrepareOptions {
                size: 7,
                inplace: true,
                mode: 0o600,
                attempt: 0,
                create_if_missing: true,
            },
        )
        .unwrap();
    operations
        .write_range(
            PartialTarget {
                path: b"inplace",
                id: &copy_id,
                guard: None,
            },
            true,
            0,
            0,
            content_digest(b"inplace"),
            b"inplace",
        )
        .unwrap();
    operations
        .finalize(
            b"inplace",
            true,
            &copy_id,
            &meta,
            0,
            TargetMutation {
                condition: TargetCondition::Any,
                guard: None,
            },
        )
        .unwrap();
    assert_eq!(fs::read(moved.join("inplace")).unwrap(), b"inplace");
    assert_eq!(
        fs::read(selected.join("inplace")).unwrap(),
        b"replacement-root"
    );

    symlink(&outside, moved.join("redirect")).unwrap();
    assert!(operations
        .put_small(&SmallPut {
            path: b"redirect/escaped".to_vec(),
            copy_id,
            data: b"bad".to_vec(),
            hash: content_digest(b"bad"),
            meta,
            flags: 0,
            inplace: false,
            condition: TargetCondition::Absent,
            guard: None,
        })
        .is_err());
    assert!(!outside.join("escaped").exists());

    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn rooted_ranged_write_does_not_follow_a_swapped_parent() {
    let dir = test_dir();
    let root_path = dir.join("root");
    let outside = dir.join("outside");
    fs::create_dir_all(root_path.join("parent")).unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("file"), b"outside").unwrap();
    let root = Arc::new(Root::open(&root_path).unwrap());
    let mut operations = FsOps::new();
    operations.destination_root = Some(root);
    operations.destination_prefix = Some(path_bytes(&root_path));
    let copy_id = [42; 16];

    operations
        .prepare(
            PartialTarget {
                path: b"parent/file",
                id: &copy_id,
                guard: None,
            },
            PrepareOptions {
                size: 4,
                inplace: false,
                mode: 0o600,
                attempt: 0,
                create_if_missing: true,
            },
        )
        .unwrap();
    operations
        .write_range(
            PartialTarget {
                path: b"parent/file",
                id: &copy_id,
                guard: None,
            },
            false,
            0,
            0,
            content_digest(b"safe"),
            b"safe",
        )
        .unwrap();
    fs::rename(root_path.join("parent"), root_path.join("parked")).unwrap();
    symlink(&outside, root_path.join("parent")).unwrap();

    // The cached descriptor remains the parked sidecar, while reopening
    // the swapped parent for finalization fails rather than following it.
    operations
        .write_range(
            PartialTarget {
                path: b"parent/file",
                id: &copy_id,
                guard: None,
            },
            false,
            0,
            0,
            content_digest(b"held"),
            b"held",
        )
        .unwrap();
    assert!(operations
        .finalize(
            b"parent/file",
            false,
            &copy_id,
            &Meta {
                mode: 0o600,
                uid: 0,
                gid: 0,
                mtime: 0,
                mtime_nsec: 0,
            },
            0,
            TargetMutation {
                condition: TargetCondition::Absent,
                guard: None,
            },
        )
        .is_err());
    let original_partial = partial_path(&root_path.join("parent/file"), &copy_id).unwrap();
    let parked_partial = root_path
        .join("parked")
        .join(original_partial.file_name().unwrap());
    assert_eq!(fs::read(parked_partial).unwrap(), b"held");
    assert_eq!(fs::read(outside.join("file")).unwrap(), b"outside");
    assert_eq!(fs::read_dir(&outside).unwrap().count(), 1);

    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn rooted_finalize_rejects_replacement_of_the_opened_partial() {
    let dir = test_dir();
    let root_path = dir.join("root");
    fs::create_dir_all(&root_path).unwrap();
    let root = Arc::new(Root::open(&root_path).unwrap());
    let mut operations = FsOps::new();
    operations.destination_root = Some(root);
    operations.destination_prefix = Some(path_bytes(&root_path));
    let copy_id = [43; 16];

    operations
        .prepare(
            PartialTarget {
                path: b"file",
                id: &copy_id,
                guard: None,
            },
            PrepareOptions {
                size: 4,
                inplace: false,
                mode: 0o600,
                attempt: 0,
                create_if_missing: true,
            },
        )
        .unwrap();
    operations
        .write_range(
            PartialTarget {
                path: b"file",
                id: &copy_id,
                guard: None,
            },
            false,
            0,
            0,
            content_digest(b"safe"),
            b"safe",
        )
        .unwrap();
    let partial = partial_path(&root_path.join("file"), &copy_id).unwrap();
    let displaced = root_path.join("displaced-partial");
    fs::rename(&partial, &displaced).unwrap();
    fs::write(&partial, b"attacker").unwrap();

    assert!(operations
        .finalize(
            b"file",
            false,
            &copy_id,
            &Meta {
                mode: 0o600,
                uid: 0,
                gid: 0,
                mtime: 0,
                mtime_nsec: 0,
            },
            0,
            TargetMutation {
                condition: TargetCondition::Absent,
                guard: None,
            },
        )
        .is_err());
    assert!(!root_path.join("file").exists());
    assert_eq!(fs::read(&partial).unwrap(), b"attacker");
    assert_eq!(fs::read(&displaced).unwrap(), b"safe");

    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn rooted_partial_hash_rejects_opened_and_named_inode_mismatch() {
    let dir = test_dir();
    fs::create_dir(&dir).unwrap();
    let named = dir.join("partial");
    fs::write(&named, b"old").unwrap();
    let root = Root::open(&dir).unwrap();
    let relative = RelativePath::new(b"partial").unwrap();
    let opened = root.open_regular_read(&relative).unwrap();

    fs::rename(&named, dir.join("old-partial")).unwrap();
    fs::write(&named, b"new").unwrap();

    assert!(require_safe_rooted_named_partial(&root, &relative, &named, &opened).is_err());
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn rooted_descriptor_cache_distinguishes_roots_with_the_same_relative_name() {
    let dir = test_dir();
    let first = dir.join("first");
    let second = dir.join("second");
    fs::create_dir_all(&first).unwrap();
    fs::create_dir_all(&second).unwrap();
    fs::write(first.join("same"), b"first").unwrap();
    fs::write(second.join("same"), b"second").unwrap();
    let first_root = Root::open(&first).unwrap();
    let second_root = Root::open(&second).unwrap();
    let relative = RelativePath::new(b"same").unwrap();
    let mut operations = FsOps::new();

    let first_inode = operations
        .cached_rooted(Path::new("same"), &first_root, &relative, 0, false)
        .unwrap()
        .file()
        .metadata()
        .unwrap()
        .ino();
    let second_inode = operations
        .cached_rooted(Path::new("same"), &second_root, &relative, 0, false)
        .unwrap()
        .file()
        .metadata()
        .unwrap()
        .ino();

    assert_ne!(first_inode, second_inode);
    assert_eq!(operations.fds.len(), 2);
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn retained_basis_cannot_be_consumed_under_another_root() {
    let dir = test_dir();
    let first = dir.join("first");
    let second = dir.join("second");
    fs::create_dir_all(&first).unwrap();
    fs::create_dir_all(&second).unwrap();
    fs::write(first.join("basis"), b"same").unwrap();
    fs::write(second.join("basis"), b"same").unwrap();
    let first_root = Arc::new(Root::open(&first).unwrap());
    let second_root = Arc::new(Root::open(&second).unwrap());
    let mut operations = FsOps::new();
    operations.destination_root = Some(first_root);
    operations.destination_prefix = Some(b"logical".to_vec());
    let copy_id = [32; 16];

    operations
        .hash_and_hold(
            b"basis",
            &copy_id,
            MIN_HASH_BLOCK_BYTES,
            4,
            TargetCondition::Any,
            None,
        )
        .unwrap();
    operations.destination_root = Some(second_root);
    assert!(operations
        .finish_basis(
            b"basis",
            &copy_id,
            &Meta {
                mode: 0o600,
                uid: 0,
                gid: 0,
                mtime: 0,
                mtime_nsec: 0,
            },
            flags::MODE,
            TargetCondition::Any,
            None,
        )
        .is_err());
    assert_ne!(
        fs::metadata(first.join("basis")).unwrap().mode() & 0o777,
        0o600
    );
    assert_ne!(
        fs::metadata(second.join("basis")).unwrap().mode() & 0o777,
        0o600
    );

    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn destination_apply_uses_the_adopted_root_not_its_old_name() {
    let dir = test_dir();
    let selected = dir.join("selected");
    fs::create_dir_all(selected.join("empty")).unwrap();
    fs::write(selected.join("remove"), b"remove").unwrap();
    fs::write(selected.join("repair"), b"repair").unwrap();
    let repair_before = fs::symlink_metadata(selected.join("repair")).unwrap();
    let (selection, anchor) = select_operator_directory(
        selected.as_os_str().as_bytes(),
        false,
        OperatorSymlinkPolicy::Refuse,
    )
    .unwrap();
    assert!(anchor.is_some());
    let root = Arc::new(Root::from_directory(selection.directory).unwrap());
    let mut operations = FsOps::new();
    operations.destination_root = Some(root);
    operations.destination_prefix = Some(path_bytes(&selected));

    let moved = dir.join("moved");
    fs::rename(&selected, &moved).unwrap();
    fs::create_dir(&selected).unwrap();
    fs::write(selected.join("sentinel"), b"replacement").unwrap();

    let meta = |mode| Meta {
        mode,
        uid: 0,
        gid: 0,
        mtime: 1_700_000_000,
        mtime_nsec: 123_456_789,
    };
    let errors = operations.apply(
        &[
            Op::Mkdir {
                path: b"created".to_vec(),
                mode: 0o755,
                condition: TargetCondition::Any,
            },
            Op::Mkdir {
                path: b"nested/parent/created".to_vec(),
                mode: 0o755,
                condition: TargetCondition::Any,
            },
            Op::Symlink {
                path: b"link".to_vec(),
                target: b"target".to_vec(),
                condition: TargetCondition::Any,
            },
            Op::Mknod {
                path: b"pipe".to_vec(),
                mode: MODE_FIFO | 0o600,
                rdev: 0,
                condition: TargetCondition::Any,
            },
            Op::Unlink {
                path: b"remove".to_vec(),
            },
            Op::Rmdir {
                path: b"empty".to_vec(),
            },
            Op::SetFileMetaIfSame {
                path: b"repair".to_vec(),
                condition: TargetCondition::MatchesFingerprint {
                    dev: repair_before.dev(),
                    ino: repair_before.ino(),
                    ctime: repair_before.ctime(),
                    ctime_nsec: repair_before.ctime_nsec() as u32,
                },
                meta: meta(0o640),
                flags: flags::MODE,
            },
            Op::SetMeta {
                path: b"link".to_vec(),
                meta: meta(0),
                flags: flags::TIMES,
                condition: TargetCondition::Any,
            },
            Op::SetMeta {
                path: Vec::new(),
                meta: meta(0o701),
                flags: flags::MODE | flags::TIMES,
                condition: TargetCondition::Any,
            },
        ],
        None,
    );
    assert_eq!(errors, vec![None; 9]);

    assert!(moved.join("created").is_dir());
    assert!(moved.join("nested/parent/created").is_dir());
    assert_eq!(
        fs::read_link(moved.join("link")).unwrap(),
        Path::new("target")
    );
    assert!(fs::symlink_metadata(moved.join("pipe"))
        .unwrap()
        .file_type()
        .is_fifo());
    assert!(!moved.join("remove").exists());
    assert!(!moved.join("empty").exists());
    assert_eq!(
        fs::symlink_metadata(moved.join("repair")).unwrap().mode() & 0o777,
        0o640
    );
    assert_eq!(fs::symlink_metadata(&moved).unwrap().mode() & 0o777, 0o701);
    assert_eq!(fs::read(selected.join("sentinel")).unwrap(), b"replacement");
    assert_eq!(fs::read_dir(&selected).unwrap().count(), 1);

    let outside = dir.join("outside");
    fs::write(&outside, b"outside").unwrap();
    let errors = operations.apply(
        &[
            Op::Unlink {
                path: b"../outside".to_vec(),
            },
            Op::Remove {
                path: b"created".to_vec(),
            },
        ],
        None,
    );
    assert!(errors.iter().all(Option::is_some));
    assert_eq!(fs::read(&outside).unwrap(), b"outside");
    assert!(moved.join("created").is_dir());

    let outside_directory = dir.join("outside-directory");
    fs::create_dir(&outside_directory).unwrap();
    symlink(&outside_directory, moved.join("redirect")).unwrap();
    let errors = operations.apply(
        &[Op::Mkdir {
            path: b"redirect/escaped".to_vec(),
            mode: 0o755,
            condition: TargetCondition::Any,
        }],
        None,
    );
    assert!(errors[0].is_some());
    assert!(!outside_directory.join("escaped").exists());

    fs::set_permissions(&moved, fs::Permissions::from_mode(0o700)).unwrap();
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn rooted_mkdir_race_accepts_only_an_existing_real_directory() {
    let dir = test_dir();
    let selected = dir.join("selected");
    let outside = dir.join("outside");
    fs::create_dir_all(selected.join("winner")).unwrap();
    fs::create_dir_all(&outside).unwrap();
    symlink(&outside, selected.join("link")).unwrap();
    let root = Arc::new(Root::from_directory(File::open(&selected).unwrap()).unwrap());
    let target = |path: &[u8]| RootedTarget {
        root: root.clone(),
        relative: RelativePath::new(path).unwrap(),
        label: PathBuf::from(OsStr::from_bytes(path)),
        create_missing_parents: true,
        query_partial_name_limit: false,
    };

    assert!(create_rooted_directory_or_existing(&target(b"winner"), 0o755).is_ok());
    assert!(create_rooted_directory_or_existing(&target(b"link"), 0o755).is_err());
    assert!(fs::read_dir(&outside).unwrap().next().is_none());

    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn name_limit_discovery_does_not_follow_an_intermediate_symlink() {
    let dir = test_dir();
    fs::create_dir(&dir).unwrap();
    let target = dir.join("symlink-target");
    let existing = target.join("existing");
    let link = dir.join("in-tree-link");
    fs::create_dir_all(&existing).unwrap();
    symlink(&target, &link).unwrap();
    let cache = Mutex::new(NameMaxCache::default());
    let queried = Mutex::new(Vec::new());
    let expected = fs::metadata(&dir).unwrap();

    let limit = name_max_cached(&link.join("existing"), &cache, |candidate, directory| {
        let metadata = directory.metadata().unwrap();
        queried
            .lock()
            .unwrap()
            .push((candidate.to_path_buf(), metadata.dev(), metadata.ino()));
        143
    });

    assert_eq!(limit, 143);
    assert_eq!(
        *queried.lock().unwrap(),
        vec![(lexical_absolute(&dir), expected.dev(), expected.ino())]
    );
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn name_limit_discovery_uses_the_nearest_existing_directory() {
    let dir = test_dir();
    fs::create_dir(&dir).unwrap();
    let cache = Mutex::new(NameMaxCache::default());
    let queried = Mutex::new(Vec::new());

    let limit = name_max_cached(
        &dir.join("not-yet-created/deeper"),
        &cache,
        |candidate, _directory| {
            queried.lock().unwrap().push(candidate.to_path_buf());
            143
        },
    );

    assert_eq!(limit, 143);
    assert_eq!(*queried.lock().unwrap(), vec![lexical_absolute(&dir)]);
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn seed_basis_copies_only_selected_final_blocks_and_hashes_current_bytes() {
    let block = MIN_HASH_BLOCK_BYTES;
    for truncate in [false, true] {
        let temporary = crate::test_support::tempdir().unwrap();
        let path = temporary.path().join("file");
        let id = [12; 16];
        let len = 4 * block + 7;
        let mut data = vec![17; len as usize];
        fs::write(&path, &data).unwrap();
        let mut ops = destination_ops(temporary.path());
        ops.hash_and_hold(b"file", &id, block, len, TargetCondition::Any, None)
            .unwrap();
        // The hint is stale: hashes must describe the buffers copied now.
        data[block as usize..2 * block as usize].fill(91);
        let donor = File::options().write(true).open(&path).unwrap();
        donor
            .write_all_at(&data[block as usize..2 * block as usize], block)
            .unwrap();
        if truncate {
            donor.set_len(2 * block).unwrap();
        }
        let selected = [(block, 2 * block), (3 * block, len)];
        let reused = ops
            .seed_basis(
                PartialTarget {
                    path: b"file",
                    id: &id,
                    guard: None,
                },
                len,
                block,
                Some(&selected),
                0,
            )
            .unwrap();
        assert!(reused.selected_final);
        let mut expected = vec![0; len as usize];
        expected[block as usize..2 * block as usize]
            .copy_from_slice(&data[block as usize..2 * block as usize]);
        let mut hashes = vec![content_digest(&data[block as usize..2 * block as usize])];
        if !truncate {
            expected[3 * block as usize..].copy_from_slice(&data[3 * block as usize..]);
            hashes.extend(
                data[3 * block as usize..]
                    .chunks(block as usize)
                    .map(content_digest),
            );
        }
        assert_eq!(reused.hashes, hashes);
        assert_eq!(
            fs::read(partial_path(&path, &id).unwrap()).unwrap(),
            expected
        );
    }
}

#[test]
fn seed_basis_final_hint_does_not_limit_partial_donors() {
    let temporary = crate::test_support::tempdir().unwrap();
    let path = temporary.path().join("file");
    let id = [13; 16];
    fs::write(&path, b"wrong final").unwrap();
    let donor = temporary.path().join(".file.syq-tmp.abcdefghijklmnop");
    fs::write(&donor, b"valid donor").unwrap();
    fs::set_permissions(&donor, fs::Permissions::from_mode(0o600)).unwrap();
    let mut ops = destination_ops(temporary.path());
    for attempt in 0..2 {
        let reused = ops
            .seed_basis(
                PartialTarget {
                    path: b"file",
                    id: &id,
                    guard: None,
                },
                11,
                MIN_HASH_BLOCK_BYTES,
                Some(&[]),
                attempt,
            )
            .unwrap();
        assert!(!reused.selected_final);
        assert_eq!(reused.hashes, vec![content_digest(b"valid donor")]);
        assert_eq!(
            fs::read(partial_path(&path, &id).unwrap()).unwrap(),
            b"valid donor"
        );
    }
}

#[test]
fn seed_basis_rejects_invalid_ranges_before_creating_a_partial() {
    let temporary = crate::test_support::tempdir().unwrap();
    let path = temporary.path().join("file");
    let id = [14; 16];
    let block = MIN_HASH_BLOCK_BYTES;
    let mut ops = destination_ops(temporary.path());
    for ranges in [
        vec![(0, 0)],
        vec![(1, block)],
        vec![(0, block + 1)],
        vec![(0, 4 * block)],
        vec![(block, 2 * block), (0, block)],
        vec![(0, 2 * block), (block, 3 * block)],
    ] {
        assert!(
            ops.seed_basis(
                PartialTarget {
                    path: b"file",
                    id: &id,
                    guard: None
                },
                3 * block,
                block,
                Some(&ranges),
                0
            )
            .is_err(),
            "{ranges:?}"
        );
        assert!(!partial_path(&path, &id).unwrap().exists());
    }
}

#[test]
fn seed_basis_ignores_a_previous_jobs_hold() {
    let temporary = crate::test_support::tempdir().unwrap();
    let earlier = temporary.path().join("earlier");
    let later = temporary.path().join("later");
    fs::write(&earlier, b"earlier bytes").unwrap();
    fs::write(
        temporary.path().join(".later.syq-tmp.abcdefghijklmnop"),
        b"later bytes",
    )
    .unwrap();
    let mut ops = destination_ops(temporary.path());
    let id = [8; 16];
    ops.hash_and_hold(
        b"earlier",
        &id,
        MIN_HASH_BLOCK_BYTES,
        13,
        TargetCondition::Any,
        None,
    )
    .unwrap();
    // A source-side failure would leave this earlier hold unconsumed.
    let hashes = ops
        .seed_basis(
            PartialTarget {
                path: b"later",
                id: &id,
                guard: None,
            },
            11,
            MIN_HASH_BLOCK_BYTES,
            None,
            0,
        )
        .unwrap();
    assert_eq!(hashes.hashes, vec![content_digest(b"later bytes")]);
    assert_eq!(
        fs::read(partial_path(&later, &id).unwrap()).unwrap(),
        b"later bytes"
    );
}

#[test]
fn seed_basis_without_a_usable_donor_returns_no_reusable_blocks() {
    for unsuitable in [false, true] {
        let temporary = crate::test_support::tempdir().unwrap();
        let target = temporary.path().join("file");
        let donor = temporary.path().join(".file.syq-tmp.abcdefghijklmnop");
        fs::write(&donor, b"old bytes").unwrap();
        let mut ops = FsOps::new();
        ops.destination_root = Some(Arc::new(
            Root::from_directory(File::open(temporary.path()).unwrap()).unwrap(),
        ));
        ops.destination_prefix = Some(path_bytes(temporary.path()));
        let path = b"file".to_vec();
        let id = [10; 16];
        let len = 2 * MIN_HASH_BLOCK_BYTES;
        let preparation = ops
            .prepare(
                PartialTarget {
                    path: &path,
                    id: &id,
                    guard: None,
                },
                PrepareOptions {
                    size: len,
                    inplace: false,
                    mode: 0o600,
                    attempt: 0,
                    create_if_missing: true,
                },
            )
            .unwrap();
        assert!(preparation.has_candidates);
        fs::remove_file(&donor).unwrap();
        if unsuitable {
            fs::create_dir(&donor).unwrap();
        }
        let hashes = ops
            .seed_basis(
                PartialTarget {
                    path: &path,
                    id: &id,
                    guard: None,
                },
                len,
                MIN_HASH_BLOCK_BYTES,
                None,
                0,
            )
            .unwrap();
        assert!(
            hashes.hashes.is_empty(),
            "fresh zero-filled output is not a donor"
        );
        let partial = partial_path(&target, &id).unwrap();
        assert_eq!(fs::metadata(&partial).unwrap().len(), len);
        assert!(!target.exists());
        // On a retry the existing private output is a real basis,
        // including blocks whose contents happen to be all zeros.
        let hashes = ops
            .seed_basis(
                PartialTarget {
                    path: &path,
                    id: &id,
                    guard: None,
                },
                len,
                MIN_HASH_BLOCK_BYTES,
                None,
                1,
            )
            .unwrap();
        assert_eq!(
            hashes.hashes,
            vec![content_digest(&vec![0; MIN_HASH_BLOCK_BYTES as usize]); 2]
        );
    }
}

#[test]
fn seed_basis_hashes_retry_bytes_without_rewriting_them() {
    let temporary = crate::test_support::tempdir().unwrap();
    let target = temporary.path().join("file");
    let id = [9; 16];
    let partial = partial_path(&target, &id).unwrap();
    fs::write(&partial, b"retry bytes").unwrap();
    fs::set_permissions(&partial, fs::Permissions::from_mode(0o600)).unwrap();
    let modified = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_600_000_000);
    File::options()
        .write(true)
        .open(&partial)
        .unwrap()
        .set_modified(modified)
        .unwrap();
    let before = fs::metadata(&partial).unwrap();
    let mut ops = destination_ops(temporary.path());
    // Retried bytes are compared with source block hashes, independently
    // of the hash used to check transported payloads.
    ops.set_hash_policy(crate::hashing::HashPolicy {
        algorithm: crate::hashing::HashAlgorithm::Blake3,
        transfer_integrity: true,
        transfer_hash_type: Some(crate::hashing::HashAlgorithm::Sha256),
    });
    let hashes = ops
        .seed_basis(
            PartialTarget {
                path: b"file",
                id: &id,
                guard: None,
            },
            11,
            MIN_HASH_BLOCK_BYTES,
            None,
            1,
        )
        .unwrap();
    let after = fs::metadata(&partial).unwrap();
    assert_eq!(hashes.hashes, vec![content_digest(b"retry bytes")]);
    assert_eq!(after.modified().unwrap(), before.modified().unwrap());
    assert_eq!(after.ino(), before.ino());
    assert_eq!(fs::read(partial).unwrap(), b"retry bytes");
}

#[test]
fn partial_discovery_is_exact_and_directory_cache_is_bounded() {
    let temporary = crate::test_support::tempdir().unwrap();
    let mut ops = destination_ops(temporary.path());
    for index in 0..PARTIAL_DIRECTORY_CACHE_MAX + 2 {
        let directory = temporary.path().join(index.to_string());
        fs::create_dir(&directory).unwrap();
        let candidate = format!("{index}/.file.syq-tmp.abcdefghijklmnop").into_bytes();
        fs::write(directory.join(".file.syq-tmp.abcdefghijklmnop"), b"donor").unwrap();
        fs::write(directory.join(".syq-tmp.abcdefghijklmnop"), b"ambiguous").unwrap();
        let target = |name: &str| {
            ops.destination_mutation_target(format!("{index}/{name}").as_bytes(), None)
                .unwrap()
        };
        let (file, other) = (target("file"), target("file-other"));
        assert_eq!(ops.candidate_partials(&file), vec![candidate]);
        assert!(ops.candidate_partials(&other).is_empty());
        assert!(ops.partial_candidates.len() <= PARTIAL_DIRECTORY_CACHE_MAX);
        assert!(ops.partial_directory_order.len() <= PARTIAL_DIRECTORY_CACHE_MAX);
    }
}

#[test]
fn observation_only_prepare_does_not_create_a_sidecar() {
    let dir = test_dir();
    fs::create_dir(&dir).unwrap();
    let target = dir.join("file");
    let copy_id = [11; 16];
    let partial = partial_path(&target, &copy_id).unwrap();
    let mut operations = destination_ops(&dir);

    let observed = operations
        .prepare(
            PartialTarget {
                path: b"file",
                id: &copy_id,
                guard: None,
            },
            PrepareOptions {
                size: 1024,
                inplace: false,
                mode: 0o600,
                attempt: 0,
                create_if_missing: false,
            },
        )
        .unwrap();
    assert_eq!(observed.partial_size, None);
    assert!(!partial.exists());

    operations
        .prepare(
            PartialTarget {
                path: b"file",
                id: &copy_id,
                guard: None,
            },
            PrepareOptions {
                size: 1024,
                inplace: false,
                mode: 0o600,
                attempt: 0,
                create_if_missing: true,
            },
        )
        .unwrap();
    assert!(partial.exists());
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn observation_only_prepare_preserves_unsafe_sidecars() {
    let dir = test_dir();
    fs::create_dir(&dir).unwrap();
    let target = dir.join("file");
    let copy_id = [12; 16];
    let partial = partial_path(&target, &copy_id).unwrap();
    let external = dir.join("external");
    fs::write(&external, b"sentinel").unwrap();
    let mut operations = destination_ops(&dir);
    let observe = |operations: &mut FsOps| {
        operations
            .prepare(
                PartialTarget {
                    path: b"file",
                    id: &copy_id,
                    guard: None,
                },
                PrepareOptions {
                    size: 1024,
                    inplace: false,
                    mode: 0o600,
                    attempt: 0,
                    create_if_missing: false,
                },
            )
            .unwrap()
    };

    symlink(&external, &partial).unwrap();
    let before = fs::symlink_metadata(&partial).unwrap();
    assert_eq!(observe(&mut operations).partial_size, None);
    let after = fs::symlink_metadata(&partial).unwrap();
    assert!(after.file_type().is_symlink());
    assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));
    assert_eq!(fs::read_link(&partial).unwrap(), external);
    fs::remove_file(&partial).unwrap();

    fs::hard_link(&external, &partial).unwrap();
    let before = fs::symlink_metadata(&partial).unwrap();
    assert_eq!(before.nlink(), 2);
    assert_eq!(observe(&mut operations).partial_size, None);
    let after = fs::symlink_metadata(&partial).unwrap();
    assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));
    assert_eq!(after.nlink(), 2);
    assert_eq!(fs::read(&external).unwrap(), b"sentinel");
    fs::remove_file(&partial).unwrap();

    make_fifo(&partial, 0o600);
    let before = fs::symlink_metadata(&partial).unwrap();
    assert!(before.file_type().is_fifo());
    assert_eq!(observe(&mut operations).partial_size, None);
    let after = fs::symlink_metadata(&partial).unwrap();
    assert!(after.file_type().is_fifo());
    assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));

    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn observation_only_rooted_prepare_preserves_an_unsafe_sidecar() {
    let dir = test_dir();
    let root_path = dir.join("root");
    fs::create_dir_all(&root_path).unwrap();
    let root = Root::open(&root_path).unwrap();
    let identity = root.identity();
    let guard = ContainerGuard {
        root: root_path.as_os_str().as_bytes().to_vec(),
        dev: identity.dev,
        ino: identity.ino,
    };
    let target = root_path.join("file");
    let copy_id = [13; 16];
    let partial = partial_path(&target, &copy_id).unwrap();
    symlink("unsafe-target", &partial).unwrap();
    let before = fs::symlink_metadata(&partial).unwrap();
    let mut operations = FsOps::new();

    let observed = operations
        .prepare(
            PartialTarget {
                path: target.as_os_str().as_bytes(),
                id: &copy_id,
                guard: Some(&guard),
            },
            PrepareOptions {
                size: 1024,
                inplace: false,
                mode: 0o600,
                attempt: 0,
                create_if_missing: false,
            },
        )
        .unwrap();

    assert_eq!(observed.partial_size, None);
    let after = fs::symlink_metadata(&partial).unwrap();
    assert!(after.file_type().is_symlink());
    assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));
    assert_eq!(fs::read_link(&partial).unwrap(), Path::new("unsafe-target"));
    fs::remove_dir_all(&dir).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn fresh_nfs_partial_is_not_allocated_or_sized_before_writes() {
    let dir = test_dir();
    fs::create_dir(&dir).unwrap();
    let path = dir.join("partial");
    let file = File::create(&path).unwrap();
    preallocate_new_file(
        &file,
        1024 * 1024,
        FileSystemTraits {
            is_nfs: true,
            ..FileSystemTraits::default()
        },
    )
    .unwrap();
    assert_eq!(file.metadata().unwrap().len(), 0);

    file.write_all_at(b"payload", 1024).unwrap();
    assert_eq!(file.metadata().unwrap().len(), 1031);
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn guarded_root_metadata_updates_once_then_becomes_a_noop() {
    let dir = test_dir();
    fs::create_dir(&dir).unwrap();
    let root = Root::open(&dir).unwrap();
    let identity = root.identity();
    let guard = ContainerGuard {
        root: dir.as_os_str().as_bytes().to_vec(),
        dev: identity.dev,
        ino: identity.ino,
    };
    let target = guarded_target(dir.as_os_str().as_bytes(), &guard)
        .unwrap()
        .as_rooted();
    let current = fs::symlink_metadata(&dir).unwrap();
    let meta = Meta {
        mode: current.mode(),
        uid: current.uid(),
        gid: current.gid(),
        mtime: 1_600_000_000,
        mtime_nsec: 0,
    };

    set_meta_rooted(
        &target,
        &meta,
        flags::MODE | flags::TIMES,
        TargetCondition::Any,
    )
    .unwrap();
    let before = fs::symlink_metadata(&dir).unwrap();
    assert_eq!((before.mtime(), before.mtime_nsec()), (meta.mtime, 0));

    std::thread::sleep(std::time::Duration::from_millis(10));
    set_meta_rooted(
        &target,
        &meta,
        flags::MODE | flags::TIMES,
        TargetCondition::Any,
    )
    .unwrap();
    let after = fs::symlink_metadata(&dir).unwrap();
    assert_eq!(
        (after.ctime(), after.ctime_nsec()),
        (before.ctime(), before.ctime_nsec())
    );
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn compact_partial_name_is_recognized() {
    let name = OsStr::from_bytes(b".syq-tmp.aaaaaaaaaaaaaaaa");
    assert!(is_partial_name(name));
    assert!(!is_partial_name(OsStr::from_bytes(b".syq-tmp.notes")));

    let id = [9u8; 16];
    let parent_len = libc::PATH_MAX as usize - 27;
    let final_path = PathBuf::from("a".repeat(parent_len)).join("x");
    let partial = partial_path(&final_path, &id).unwrap();
    assert_eq!(partial.file_name().unwrap().as_bytes().len(), 25);
    assert!(is_partial_name(partial.file_name().unwrap()));

    let too_deep = PathBuf::from("a".repeat(parent_len + 1)).join("x");
    assert!(partial_path(&too_deep, &id).is_err());
}

#[test]
fn shared_block_hasher_handles_short_readers_consistently() {
    let block = MIN_HASH_BLOCK_BYTES as usize;
    let mut data = vec![b'a'; block];
    data.extend(vec![b'b'; block]);
    data.extend(b"tail");
    let hashes = hash_reader(&mut &data[..], block as u64, (block * 4) as u64).unwrap();
    assert_eq!(
        hashes,
        vec![
            content_digest(&vec![b'a'; block]),
            content_digest(&vec![b'b'; block]),
            content_digest(b"tail"),
            content_digest(b""),
        ]
    );
    assert!(hash_reader(&mut &b"x"[..], 0, 1).is_err());
    assert!(hash_reader(&mut &b"x"[..], 1, 1).is_err());
}

#[test]
fn content_digest_is_full_blake3() {
    assert_eq!(
        content_digest(b""),
        [
            0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6, 0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc,
            0xc9, 0x49, 0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7, 0xcc, 0x9a, 0x93, 0xca,
            0xe4, 0x1f, 0x32, 0x62,
        ]
    );
}

#[test]
fn source_workers_adopt_registered_descriptor_after_path_replacement() {
    let temporary = crate::test_support::tempdir().unwrap();
    let selected = temporary.path().join("selected");
    fs::create_dir(&selected).unwrap();
    fs::write(selected.join("original"), b"original").unwrap();
    let identity = fs::metadata(&selected).unwrap();
    let session = DescriptorSessionSlot::default();
    let mut control = FsOps::with_descriptor_session(session.clone());
    let response = control.handle(&crate::test_support::register_source_roots(&[&selected], 0));
    let Response::SourceRootsRegistered(roots) = response else {
        panic!("unexpected source registration response: {response:?}")
    };
    let id = roots[0].selection.root();

    let moved = temporary.path().join("moved");
    let replacement = temporary.path().join("replacement");
    fs::rename(&selected, &moved).unwrap();
    fs::create_dir(&replacement).unwrap();
    fs::write(replacement.join("replacement"), b"replacement").unwrap();
    std::os::unix::fs::symlink(&replacement, &selected).unwrap();

    let mut shared = FsOps::with_descriptor_session(session);
    shared.initialize_sources(&roots).unwrap();
    let mut fresh = FsOps::new();
    fresh.initialize_sources(&roots).unwrap();
    for worker in [&mut shared, &mut fresh] {
        let adopted = worker.source_root_identity(id).unwrap();
        assert_eq!((adopted.dev, adopted.ino), (identity.dev(), identity.ino()));
        let original = roots[0].selection.join(b"original").unwrap();
        let response = worker.handle(&Request::StatMany {
            paths: vec![selected.join("original").as_os_str().as_bytes().to_vec()],
            sources: Some(vec![original]),
            follow: false,
            guard: None,
        });
        assert!(matches!(response, Response::Stats(stats) if stats[0].is_some()));
        let replacement = roots[0].selection.join(b"replacement").unwrap();
        let response = worker.handle(&Request::StatMany {
            paths: vec![selected.join("replacement").as_os_str().as_bytes().to_vec()],
            sources: Some(vec![replacement]),
            follow: false,
            guard: None,
        });
        assert!(matches!(response, Response::Stats(stats) if stats[0].is_none()));
    }
    assert_ne!(
        (
            fs::metadata(&replacement).unwrap().dev(),
            fs::metadata(&replacement).unwrap().ino()
        ),
        (identity.dev(), identity.ino())
    );
}

#[cfg(target_os = "linux")]
#[test]
fn destination_worker_claims_copy_sources_from_the_foreign_session() {
    let temporary = crate::test_support::tempdir().unwrap();
    let source = temporary.path().join("source");
    let destination = temporary.path().join("destination");
    fs::create_dir(&source).unwrap();
    fs::create_dir(&destination).unwrap();
    fs::write(source.join("file"), b"source").unwrap();
    fs::write(destination.join("file"), b"destination").unwrap();

    let source_session = DescriptorSessionSlot::default();
    let mut source_control = FsOps::with_descriptor_session(source_session);
    let response =
        source_control.handle(&crate::test_support::register_source_roots(&[&source], 1));
    let Response::SourceRootsRegistered(roots) = response else {
        panic!("unexpected source registration response: {response:?}")
    };

    // Initialize an unrelated endpoint session so the copy worker cannot
    // accidentally clone the source root from its own registry.
    let destination_session = DescriptorSessionSlot::default();
    destination_session
        .register(File::open(&destination).unwrap())
        .unwrap();
    let mut worker = FsOps::with_descriptor_session(destination_session);
    worker.destination_root = Some(Arc::new(Root::open(&destination).unwrap()));
    worker.destination_prefix = Some(b".".to_vec());
    worker.initialize_copy_sources(&roots).unwrap();

    assert_eq!(worker.source_roots.len(), 1);
    assert_eq!(
        worker.source_root_identity(roots[0].selection.root()),
        source_control.source_root_identity(roots[0].selection.root())
    );
    let response = worker.handle(&Request::FileHash {
        path: b"file".to_vec(),
        source: None,
        guard: None,
    });
    assert!(
        matches!(response, Response::FileHash { size: 11, hash } if hash == content_digest(b"destination"))
    );
}

#[test]
fn source_initialization_rejects_mismatched_bad_and_excess_roots_atomically() {
    let temporary = crate::test_support::tempdir().unwrap();
    let first = temporary.path().join("first");
    let second = temporary.path().join("second");
    fs::create_dir(&first).unwrap();
    fs::create_dir(&second).unwrap();
    let session = DescriptorSessionSlot::default();
    let mut control = FsOps::with_descriptor_session(session.clone());
    let response = control.handle(&crate::test_support::register_source_roots(
        &[&first, &second],
        0,
    ));
    let Response::SourceRootsRegistered(roots) = response else {
        panic!("unexpected source registration response: {response:?}")
    };

    let mut mismatched = roots[0].clone();
    mismatched.selection = roots[1].selection.clone();
    let mut worker = FsOps::with_descriptor_session(session.clone());
    assert!(worker.initialize_sources(&[mismatched]).is_err());
    assert!(worker.source_roots.is_empty());

    let mut malformed = roots[0].clone();
    malformed.expected_leaf = Some(SourceLeafIdentity {
        dev: 1,
        ino: 2,
        file_type: 0,
        symlink_target: None,
    });
    assert!(worker.initialize_sources(&[malformed]).is_err());
    assert!(worker.source_roots.is_empty());

    session.close();
    assert!(worker.initialize_sources(&roots).is_err());
    assert!(worker.source_roots.is_empty());

    let excess = vec![roots[0].clone(); DEFAULT_MAX_ROOTS + 1];
    let error = worker.initialize_sources(&excess).unwrap_err();
    assert!(error.to_string().contains("root count"));
    assert!(worker.source_roots.is_empty());
}

#[test]
fn source_initialization_rejects_missing_mistyped_and_cross_session_leaf_tickets() {
    let temporary = crate::test_support::tempdir().unwrap();
    let first = temporary.path().join("first");
    let second = temporary.path().join("second");
    fs::write(&first, b"first").unwrap();
    fs::write(&second, b"second").unwrap();
    let register = |control: &mut FsOps, path: &Path| {
        let response = control.handle(&crate::test_support::register_source_roots(&[&path], 0));
        let Response::SourceRootsRegistered(roots) = response else {
            panic!("unexpected source registration response: {response:?}")
        };
        roots.into_iter().next().unwrap()
    };

    let mut first_control = FsOps::new();
    let first_root = register(&mut first_control, &first);
    let mut second_control = FsOps::new();
    let second_root = register(&mut second_control, &second);
    assert_eq!(
        first_root.selection.root(),
        second_root.selection.root(),
        "independent registries should exercise coincident numeric IDs"
    );

    let mut worker = FsOps::new();
    let mut missing = first_root.clone();
    missing.leaf_ticket = None;
    assert!(worker.initialize_sources(&[missing]).is_err());
    assert!(worker.source_roots.is_empty());

    let mut mistyped = first_root.clone();
    mistyped.leaf_ticket = Some(mistyped.ticket.clone());
    assert!(worker.initialize_sources(&[mistyped]).is_err());
    assert!(worker.source_roots.is_empty());

    let mut nested = first_root.clone();
    nested.selection =
        RegisteredPath::new(nested.selection.root(), b"nested/leaf".to_vec()).unwrap();
    assert!(worker.initialize_sources(&[nested]).is_err());
    assert!(worker.source_roots.is_empty());

    let mut impossible_target = first_root.clone();
    impossible_target
        .expected_leaf
        .as_mut()
        .unwrap()
        .symlink_target = Some(b"not-a-regular-file-property".to_vec());
    assert!(worker.initialize_sources(&[impossible_target]).is_err());
    assert!(worker.source_roots.is_empty());

    let mut cross_session_pair = first_root.clone();
    cross_session_pair.leaf_ticket = second_root.leaf_ticket.clone();
    assert!(worker.initialize_sources(&[cross_session_pair]).is_err());
    assert!(worker.source_roots.is_empty());

    // All roots in one Hello must come from the same endpoint session,
    // even when each root/leaf pair is internally consistent.
    assert!(worker
        .initialize_sources(&[first_root, second_root])
        .is_err());
    assert!(worker.source_roots.is_empty());
}

#[test]
fn independent_source_worker_keeps_exact_object_after_control_and_broker_close() {
    let temporary = crate::test_support::tempdir().unwrap();
    let selected = temporary.path().join("selected");
    fs::write(&selected, b"original").unwrap();
    let session = DescriptorSessionSlot::default();
    let mut control = FsOps::with_descriptor_session(session.clone());
    let response = control.handle(&crate::test_support::register_source_roots(&[&selected], 1));
    let Response::SourceRootsRegistered(roots) = response else {
        panic!("unexpected source registration response: {response:?}")
    };
    let expected = roots[0].expected_leaf.clone().unwrap();

    // An empty slot exercises the independent-worker broker claim path.
    let mut worker = FsOps::new();
    worker.initialize_sources(&roots).unwrap();
    drop(control);
    session.close();

    let original = temporary.path().join("original-unlinked");
    fs::rename(&selected, &original).unwrap();
    fs::remove_file(&original).unwrap();
    fs::write(&selected, b"replacement").unwrap();
    let held = worker.source_roots[&roots[0].selection.root()]
        ._leaf_object
        .as_ref()
        .unwrap()
        .metadata()
        .unwrap();
    assert_eq!((held.dev(), held.ino()), (expected.dev, expected.ino));
    assert_eq!(held.nlink(), 0);

    let response = worker.handle(&Request::StatMany {
        paths: vec![selected.as_os_str().as_bytes().to_vec()],
        sources: Some(vec![roots[0].selection.clone()]),
        follow: false,
        guard: None,
    });
    assert!(matches!(
        response,
        Response::EndpointError(error) if error.message.contains("registered source leaf changed identity")
    ));
}

#[test]
fn repeated_source_registration_keeps_the_original_root_and_leaf_pin() {
    let temporary = crate::test_support::tempdir().unwrap();
    let first = temporary.path().join("first");
    let second = temporary.path().join("second");
    fs::write(&first, b"first").unwrap();
    fs::write(&second, b"second").unwrap();
    let mut control = FsOps::new();
    let register = |path: &Path| crate::test_support::register_source_roots(&[&path], 0);
    let response = control.handle(&register(&first));
    let Response::SourceRootsRegistered(roots) = response else {
        panic!("unexpected source registration response: {response:?}")
    };
    let original_id = roots[0].selection.root();
    let expected = roots[0].expected_leaf.clone().unwrap();
    assert_eq!(control.source_roots.len(), 1);
    assert!(control.source_roots[&original_id]._leaf_object.is_some());

    let response = control.handle(&register(&second));
    assert!(matches!(
        response,
        Response::EndpointError(error) if error.message.contains("already registered")
    ));
    assert_eq!(control.source_roots.len(), 1);
    let pin = control.source_roots[&original_id]
        ._leaf_object
        .as_ref()
        .unwrap();
    let metadata = pin.metadata().unwrap();
    assert_eq!(
        (metadata.dev(), metadata.ino()),
        (expected.dev, expected.ino)
    );

    let response = control.handle(&Request::StatMany {
        paths: vec![first.as_os_str().as_bytes().to_vec()],
        sources: Some(vec![roots[0].selection.clone()]),
        follow: false,
        guard: None,
    });
    assert!(matches!(response, Response::Stats(stats) if stats[0].is_some()));
}

#[test]
fn source_stat_enforces_exact_leaf_authority_and_ignores_parallel_path() {
    let temporary = crate::test_support::tempdir().unwrap();
    let selected = temporary.path().join("selected");
    fs::write(&selected, b"selected").unwrap();
    fs::write(temporary.path().join("sibling"), b"sibling").unwrap();
    let session = DescriptorSessionSlot::default();
    let mut control = FsOps::with_descriptor_session(session.clone());
    let response = control.handle(&crate::test_support::register_source_roots(&[&selected], 0));
    let Response::SourceRootsRegistered(roots) = response else {
        panic!("unexpected source registration response: {response:?}")
    };
    assert_eq!(roots[0].selection.relative(), b"selected");
    assert!(roots[0].expected_leaf.is_some());
    assert!(control.source_roots[&roots[0].selection.root()]
        ._leaf_object
        .is_some());

    let mut worker = FsOps::with_descriptor_session(session);
    worker.initialize_sources(&roots).unwrap();
    let response = worker.handle(&Request::StatMany {
        // A contradictory display spelling cannot redirect the registered
        // selected leaf.
        paths: vec![temporary
            .path()
            .join("sibling")
            .as_os_str()
            .as_bytes()
            .to_vec()],
        sources: Some(vec![roots[0].selection.clone()]),
        follow: false,
        guard: None,
    });
    assert!(matches!(response, Response::Stats(stats) if stats[0].is_some()));

    let sibling = RegisteredPath::new(roots[0].selection.root(), b"sibling".to_vec()).unwrap();
    let response = worker.handle(&Request::StatMany {
        paths: vec![temporary
            .path()
            .join("sibling")
            .as_os_str()
            .as_bytes()
            .to_vec()],
        sources: Some(vec![sibling]),
        follow: false,
        guard: None,
    });
    assert!(
        matches!(response, Response::EndpointError(error) if error.message.contains("does not authorize"))
    );

    let response = worker.handle(&Request::StatMany {
        paths: vec![selected.as_os_str().as_bytes().to_vec()],
        sources: None,
        follow: false,
        guard: None,
    });
    assert!(
        matches!(response, Response::EndpointError(error) if error.message.contains("omitted"))
    );

    fs::rename(&selected, temporary.path().join("selected-original")).unwrap();
    fs::write(&selected, b"replacement").unwrap();
    let response = worker.handle(&Request::StatMany {
        paths: vec![selected.as_os_str().as_bytes().to_vec()],
        sources: Some(vec![roots[0].selection.clone()]),
        follow: false,
        guard: None,
    });
    assert!(matches!(
        response,
        Response::EndpointError(error) if error.message.contains("registered source leaf changed identity")
    ));
}

#[test]
fn source_scan_rejects_a_replaced_exact_symlink() {
    let temporary = crate::test_support::tempdir().unwrap();
    fs::write(temporary.path().join("target-a"), b"a").unwrap();
    fs::write(temporary.path().join("target-b"), b"b").unwrap();
    let selected = temporary.path().join("selected");
    std::os::unix::fs::symlink("target-a", &selected).unwrap();
    let session = DescriptorSessionSlot::default();
    let mut control = FsOps::with_descriptor_session(session);
    let response = control.handle(&crate::test_support::register_source_roots(&[&selected], 0));
    let Response::SourceRootsRegistered(roots) = response else {
        panic!("unexpected source registration response: {response:?}")
    };
    assert!(control.source_roots[&roots[0].selection.root()]
        ._leaf_object
        .is_some());

    let mut worker = FsOps::new();
    worker.initialize_sources(&roots).unwrap();
    fs::rename(&selected, temporary.path().join("selected-original")).unwrap();
    std::os::unix::fs::symlink("target-b", &selected).unwrap();
    let source = worker
        .source_scan_root(Some(&roots[0].selection))
        .unwrap()
        .unwrap();
    let error = crate::scan::scan_descriptor(
        source.root,
        &source.relative,
        source.expected_leaf,
        false,
        false,
        &[],
        false,
        &mut |_| Ok(()),
        &mut |_| Ok(()),
        &mut |_| {},
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("registered source leaf changed identity"),
        "{error:#}"
    );
}

#[test]
fn exact_symlink_scan_uses_the_descriptor_bound_raw_target_snapshot() {
    let temporary = crate::test_support::tempdir().unwrap();
    let selected = temporary.path().join("selected");
    let target = OsString::from_vec(b"raw-target-\xff".to_vec());
    symlink(Path::new(&target), &selected).unwrap();
    let session = DescriptorSessionSlot::default();
    let mut control = FsOps::with_descriptor_session(session);
    let response = control.handle(&crate::test_support::register_source_roots(&[&selected], 1));
    let Response::SourceRootsRegistered(roots) = response else {
        panic!("unexpected source registration response: {response:?}")
    };
    assert_eq!(
        roots[0]
            .expected_leaf
            .as_ref()
            .unwrap()
            .symlink_target
            .as_deref(),
        Some(target.as_bytes())
    );

    let mut worker = FsOps::new();
    worker.initialize_sources(&roots).unwrap();
    // Temporarily replace the name, then restore the original symlink
    // object. The emitted target belongs to that pinned object; discovery
    // never obtains it with readlinkat(parent, name).
    let original = temporary.path().join("selected-original");
    fs::rename(&selected, &original).unwrap();
    symlink("different-target", &selected).unwrap();
    fs::remove_file(&selected).unwrap();
    fs::rename(&original, &selected).unwrap();

    let source = worker
        .source_scan_root(Some(&roots[0].selection))
        .unwrap()
        .unwrap();
    let mut entries = Vec::new();
    crate::scan::scan_descriptor(
        source.root,
        &source.relative,
        source.expected_leaf,
        false,
        false,
        &[],
        false,
        &mut |batch| {
            entries.extend(batch);
            Ok(())
        },
        &mut |_| Ok(()),
        &mut |_| {},
    )
    .unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].kind, Kind::Symlink);
    assert_eq!(entries[0].link.as_deref(), Some(target.as_bytes()));
}

#[test]
fn metadata_parent_cache_distinguishes_opened_roots_with_same_inode() {
    let temporary = crate::test_support::tempdir().unwrap();
    let base = temporary.path();
    fs::create_dir(base.join("parent")).unwrap();
    fs::write(base.join("parent/file"), b"old").unwrap();
    let first = Arc::new(Root::open(base).unwrap());
    let second = Arc::new(Root::open(base).unwrap());
    assert_eq!(first.identity(), second.identity());
    let mut parent = None;
    assert_eq!(
        stat_with_parent(&first, &mut parent, b"parent/file")
            .unwrap()
            .size,
        3
    );
    // Force the held parent to differ from a fresh lookup without requiring
    // mount privileges. The second opened root must start a new lookup even
    // though its device/inode match: bind-mount views can differ this way too.
    fs::rename(base.join("parent"), base.join("old-parent")).unwrap();
    fs::create_dir(base.join("parent")).unwrap();
    fs::write(base.join("parent/file"), b"replacement").unwrap();
    assert_eq!(
        stat_with_parent(&second, &mut parent, b"parent/file")
            .unwrap()
            .size,
        11
    );
    // The second root keeps its own parent pinned across sibling lookups.
    fs::rename(base.join("parent"), base.join("second-parent")).unwrap();
    fs::create_dir(base.join("parent")).unwrap();
    fs::write(base.join("parent/file"), b"new").unwrap();
    assert_eq!(
        stat_with_parent(&second, &mut parent, b"parent/file")
            .unwrap()
            .size,
        11
    );
}

#[test]
fn metadata_chunk_pins_parent_and_new_request_resolves_replacement() {
    let temporary = crate::test_support::tempdir().unwrap();
    let base = temporary.path();
    fs::create_dir(base.join("parent")).unwrap();
    fs::write(base.join("parent/file"), b"original").unwrap();
    symlink("original-target", base.join("parent/link")).unwrap();
    let root = Arc::new(Root::open(base).unwrap());
    let mut parent = None;
    let original = stat_with_parent(&root, &mut parent, b"parent/file").unwrap();
    fs::rename(base.join("parent"), base.join("moved")).unwrap();
    fs::create_dir(base.join("parent")).unwrap();
    fs::write(base.join("parent/file"), b"replacement").unwrap();
    symlink("replacement-target", base.join("parent/link")).unwrap();
    assert_eq!(
        stat_with_parent(&root, &mut parent, b"parent/file")
            .unwrap()
            .ino,
        original.ino
    );
    assert_eq!(
        stat_with_parent(&root, &mut parent, b"parent/link")
            .unwrap()
            .link
            .as_deref(),
        Some(b"original-target".as_slice())
    );
    let mut ops = FsOps::new();
    ops.destination_root = Some(root);
    let paths = vec![b"parent/file".to_vec(), b"parent/link".to_vec()];
    let entries = ops.stat_many(&paths, false, None);
    assert_ne!(entries[0].as_ref().unwrap().ino, original.ino);
    assert_eq!(
        entries[1].as_ref().unwrap().link.as_deref(),
        Some(b"replacement-target".as_slice())
    );
    fs::remove_dir_all(base.join("parent")).unwrap();
    symlink("moved", base.join("parent")).unwrap();
    assert!(ops
        .stat_many(&paths, false, None)
        .iter()
        .all(Option::is_none));
}

#[test]
fn metadata_chunks_keep_input_order_and_do_not_reuse_a_different_parent() {
    let temporary = crate::test_support::tempdir().unwrap();
    let base = temporary.path();
    for directory in ["a", "b"] {
        fs::create_dir(base.join(directory)).unwrap();
        fs::write(base.join(directory).join("file"), directory.as_bytes()).unwrap();
    }
    let root = Arc::new(Root::open(base).unwrap());
    let mut ops = FsOps::new();
    ops.destination_root = Some(root.clone());
    // Exercise raw filename bytes only where the filesystem accepts them.
    let raw_path = if crate::test_support::filesystem_accepts_non_utf8_names() {
        b"a/raw-\xff".as_slice()
    } else {
        b"a/raw-plain".as_slice()
    };
    fs::write(base.join(OsStr::from_bytes(raw_path)), b"raw").unwrap();
    let names = [
        b"a/file".as_slice(),
        b"a/missing",
        b"b/file",
        b"absent/file",
        b"a",
        b"",
        b"../a/file",
        b"a//file",
        b"/a",
        b"/a/file",
        b"/",
        b"a/.",
        b"a/..",
        b"a/file/",
        b"a\0/file",
        b"a/f\0",
        raw_path,
    ];
    let paths: Vec<_> = names
        .iter()
        .cycle()
        .take(1024)
        .map(|p| p.to_vec())
        .collect();
    let expected: Vec<_> = paths
        .iter()
        .map(|path| {
            let relative = RelativePath::new(path).ok()?;
            let metadata = root.metadata(&relative).ok()?;
            rooted_entry(&root, &relative, Vec::new(), metadata).ok()
        })
        .collect();
    let actual = ops.stat_many(&paths, false, None);
    assert_eq!(
        serde_json::to_value(actual).unwrap(),
        serde_json::to_value(expected).unwrap()
    );
}

#[test]
fn partial_name_limits_keep_roots_parents_and_errors_separate() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = Arc::new(Root::open(temporary.path()).unwrap());
    let reopened = Arc::new(Root::open(temporary.path()).unwrap());
    assert_eq!(root.identity(), reopened.identity());
    let mut limits = PartialNameLimits::default();
    let parent = Path::new("parent");
    assert_eq!(limits.get_or_query(&root, parent, || Ok(143)).unwrap(), 143);
    assert_eq!(
        limits
            .get_or_query(&root, parent, || panic!("sibling repeated query"))
            .unwrap(),
        143
    );
    // Distinct authorities must not share a result, even with the same
    // device/inode and relative spelling.
    assert_eq!(
        limits.get_or_query(&reopened, parent, || Ok(255)).unwrap(),
        255
    );
    assert_eq!(
        limits
            .get_or_query(&root, Path::new("other"), || Ok(100))
            .unwrap(),
        100
    );
    assert!(limits
        .get_or_query(&root, parent, || bail!("transient failure"))
        .is_err());
    assert_eq!(limits.get_or_query(&root, parent, || Ok(120)).unwrap(), 120);
    // The next batch starts a fresh observation.
    assert_eq!(
        PartialNameLimits::default()
            .get_or_query(&root, parent, || Ok(200))
            .unwrap(),
        200
    );
}

#[test]
fn partial_path_batches_preserve_names_errors_and_order() {
    let temporary = crate::test_support::tempdir().unwrap();
    fs::create_dir(temporary.path().join("parent")).unwrap();
    fs::write(temporary.path().join("not-directory"), b"file").unwrap();
    std::os::unix::fs::symlink("parent", temporary.path().join("link")).unwrap();
    let mut operations = FsOps::new();
    operations
        .install_destination(File::open(temporary.path()).unwrap(), b"logical")
        .unwrap();
    let id = [17; 16];
    let mut cases: Vec<PathBytes> = [
        b"file".as_slice(),
        b"",
        b"other",
        b"parent/a",
        b"parent/b",
        b"missing/deeper/a",
        b"missing/deeper/b",
        b"not-directory/child",
        b"link/child",
        b"../outside",
        b"parent//bad",
        b"parent/..",
        b"/absolute",
        b"parent/nul\0",
        b"parent/raw-\xff",
    ]
    .into_iter()
    .map(<[u8]>::to_vec)
    .collect();
    cases.push(format!("parent/{}", "x".repeat(255)).into_bytes());
    for count in [3, 31, 32, 65, 128] {
        let paths: Vec<_> = cases.iter().cycle().take(count).cloned().collect();
        let expected: Vec<_> = paths
            .iter()
            .map(|path| {
                (|| -> Result<PathBytes> {
                    let target = operations.rooted_destination_target(path, None)?.unwrap();
                    let (_, label) = rooted_partial_target(&target, &id)?;
                    let parent = Path::new(OsStr::from_bytes(path))
                        .parent()
                        .unwrap_or_else(|| Path::new(""));
                    Ok(path_bytes(&parent.join(label.file_name().unwrap())))
                })()
                .map_err(|error| format!("{error:#}"))
            })
            .collect();
        assert_eq!(
            operations.partial_paths(&paths, &id, None),
            expected,
            "batch size {count}"
        );
    }
    // After a namespace change, use the same resolution/fallback rules as
    // an individual query (a symlink can select the nearest real ancestor).
    assert!(operations.partial_paths(&[b"parent/a".to_vec()], &id, None)[0].is_ok());
    fs::rename(
        temporary.path().join("parent"),
        temporary.path().join("moved"),
    )
    .unwrap();
    std::os::unix::fs::symlink("moved", temporary.path().join("parent")).unwrap();
    let target = operations
        .rooted_destination_target(b"parent/a", None)
        .unwrap()
        .unwrap();
    let expected = rooted_partial_target(&target, &id)
        .map(|(_, label)| path_bytes(&Path::new("parent").join(label.file_name().unwrap())))
        .map_err(|error| format!("{error:#}"));
    assert_eq!(
        operations.partial_paths(&[b"parent/a".to_vec()], &id, None),
        vec![expected]
    );
}

fn checked_metadata_batch_threads(items: &[usize]) -> Vec<std::thread::ThreadId> {
    let observations = parallel_map(items, |&index| {
        let thread = std::thread::current();
        (
            index,
            thread.id(),
            thread.name().map(str::to_owned),
            rayon::current_num_threads(),
        )
    });
    // Assert on the calling test thread so diagnostics reach this test's
    // capture buffer, regardless of which test initialized the static pool.
    assert_eq!(observations.len(), items.len());
    // Catch accidentally selecting a single-thread or host-sized pool.
    // Its size is static within the batch, so inspect it only once.
    assert_eq!(
        observations[0].3, PAR_THREADS,
        "metadata pool must retain its configured parallelism"
    );
    observations
        .into_iter()
        .zip(items)
        .map(|((index, thread, name, _), expected)| {
            assert_eq!(index, *expected);
            // Catch bypassing the dedicated metadata pool.
            assert!(
                name.as_deref()
                    .is_some_and(|name| name.starts_with("syq-metadata-")),
                "unexpected metadata thread name: {name:?}"
            );
            thread
        })
        .collect()
}

#[test]
fn small_metadata_batches_run_inline() {
    let caller = std::thread::current().id();
    assert_eq!(
        parallel_map(&[(); PAR_MIN - 1], |_| std::thread::current().id()),
        vec![caller; PAR_MIN - 1]
    );
}

#[test]
fn parallel_metadata_batches_share_a_bounded_pool() {
    let mut threads = std::collections::HashSet::new();
    let items: Vec<_> = (0..PAR_MIN).collect();
    // Rust ThreadIds are never reused, even after threads exit. Each nonempty
    // call contributes at least one ID, so PAR_THREADS + 1 calls must exceed
    // this bound with per-call pools. Passing proves reuse across calls
    // without assumptions about scheduling or native thread-ID recycling.
    for _ in 0..=PAR_THREADS {
        threads.extend(checked_metadata_batch_threads(&items));
    }
    assert!(
        threads.len() <= PAR_THREADS,
        "metadata batches must reuse a bounded shared pool"
    );
}

#[test]
fn parallel_metadata_batches_propagate_panics_and_remain_usable() {
    let items: Vec<_> = (0..128).collect();
    let panic = std::panic::catch_unwind(|| {
        parallel_map(&items, |&index| {
            if index == 64 {
                std::panic::panic_any("metadata test panic");
            }
            index
        })
    })
    .expect_err("worker panics must reach the caller");
    assert_eq!(panic.downcast_ref::<&str>(), Some(&"metadata test panic"));
    checked_metadata_batch_threads(&items);
}

#[test]
fn source_stat_batches_preserve_order_across_sizes() {
    let temporary = crate::test_support::tempdir().unwrap();
    let (mut worker, selections, _control) = registered_source_worker(&[temporary.path()], false);
    for parent in 0..4 {
        fs::create_dir(temporary.path().join(format!("p{parent}"))).unwrap();
    }
    for idx in 0..129 {
        fs::write(
            temporary.path().join(format!("p{}/f{idx}", idx % 4)),
            vec![0; idx],
        )
        .unwrap();
    }
    for count in [31, 32, 65, 128, 7, 129] {
        let sources: Vec<_> = (0..count)
            .map(|idx| {
                selections[0]
                    .join(format!("p{}/f{idx}", idx % 4).as_bytes())
                    .unwrap()
            })
            .collect();
        let response = worker.handle(&Request::StatMany {
            paths: vec![b"/display/path/is/not/authority".to_vec(); count],
            sources: Some(sources),
            follow: true,
            guard: None,
        });
        let Response::Stats(entries) = response else {
            panic!("unexpected response: {response:?}");
        };
        assert_eq!(entries.len(), count);
        for (idx, entry) in entries.into_iter().enumerate() {
            assert_eq!(entry.map(|e| e.size), Some(idx as u64));
        }
    }
}

#[test]
fn source_stat_batches_isolate_roots_and_refresh_parents_between_requests() {
    let temporary = crate::test_support::tempdir().unwrap();
    let roots: Vec<_> = ["first", "second"]
        .iter()
        .map(|name| temporary.path().join(name))
        .collect();
    for (index, root) in roots.iter().enumerate() {
        fs::create_dir_all(root.join("parent")).unwrap();
        fs::write(root.join("parent/file"), vec![0; index + 1]).unwrap();
        symlink(format!("target-{index}"), root.join("parent/link")).unwrap();
    }
    let (mut worker, selections, _control) =
        registered_source_worker(&[&roots[0], &roots[1]], false);
    // Adjacent siblings exercise reuse; identical relative parents under
    // distinct source roots must never share the held directory. Cover
    // both paths with misleading labels.
    let parallel_count = 386;
    assert!(parallel_count >= PAR_MIN);
    for count in [parallel_count, 12] {
        let sources: Vec<_> = (0..count)
            .map(|index| {
                selections[(index / 3) % 2]
                    .join(if count >= PAR_MIN {
                        // Every boundary lookup must find a file, so a
                        // cached wrong root cannot hide as None == None.
                        b"parent/file".as_slice()
                    } else {
                        [b"parent/file".as_slice(), b"parent/link", b"parent/missing"][index % 3]
                    })
                    .unwrap()
            })
            .collect();
        if count == parallel_count {
            let chunk = sources.len().div_ceil(PAR_THREADS).max(1);
            let first_root_count = sources
                .iter()
                .filter(|source| source.root() == selections[0].root())
                .count();
            assert_ne!(
                first_root_count % chunk,
                0,
                "the root boundary must fall inside a parallel chunk"
            );
        }
        let paths = vec![b"/ignored/display/path".to_vec(); count];
        let expected: Vec<_> = sources
            .iter()
            .map(|source| {
                let target = worker.registered_source_target(source).unwrap();
                let metadata = target.root.metadata(&target.relative).ok()?;
                rooted_entry(&target.root, &target.relative, Vec::new(), metadata).ok()
            })
            .collect();
        let actual = worker
            .stat_many_request(&paths, Some(&sources), true, None)
            .unwrap();
        assert_eq!(actual.len(), expected.len());
        for (index, (actual, expected)) in actual.into_iter().zip(expected).enumerate() {
            assert_eq!(
                serde_json::to_value(actual).unwrap(),
                serde_json::to_value(expected).unwrap(),
                "batch of {count}, item {index}"
            );
        }
    }
    let sources = vec![selections[0].join(b"parent/file").unwrap(); 64];
    let paths = vec![b"ignored".to_vec(); sources.len()];
    fs::rename(roots[0].join("parent"), roots[0].join("moved")).unwrap();
    fs::create_dir(roots[0].join("parent")).unwrap();
    fs::write(roots[0].join("parent/file"), b"replacement").unwrap();
    let actual = worker
        .stat_many_request(&paths, Some(&sources), false, None)
        .unwrap();
    assert!(actual
        .iter()
        .all(|entry| entry.as_ref().is_some_and(|entry| entry.size == 11)));
    fs::remove_dir_all(roots[0].join("parent")).unwrap();
    symlink("moved", roots[0].join("parent")).unwrap();
    let actual = worker
        .stat_many_request(&paths, Some(&sources), true, None)
        .unwrap();
    assert!(actual.iter().all(Option::is_none));
}

#[test]
fn source_stat_grouping_reports_the_first_error_in_request_order() {
    let temporary = crate::test_support::tempdir().unwrap();
    let first = temporary.path().join("first");
    let second = temporary.path().join("second");
    fs::write(&first, b"first").unwrap();
    fs::write(&second, b"second").unwrap();
    let (mut worker, selections, _control) = registered_source_worker(&[&first, &second], false);
    fs::rename(&first, temporary.path().join("held-first")).unwrap();
    fs::write(&first, b"replacement").unwrap();
    fs::remove_file(&second).unwrap();
    // Sorting processes the lower registered root first, but its identity
    // failure must not mask the missing-file error requested first.
    let sources = vec![selections[1].clone(), selections[0].clone()];
    let error = worker
        .stat_many_request(&vec![b"ignored".to_vec(); 2], Some(&sources), false, None)
        .unwrap_err();
    assert_eq!(error.to_string(), "inspect registered source leaf");
    assert_eq!(
        error.downcast_ref::<io::Error>().unwrap().kind(),
        io::ErrorKind::NotFound
    );
}

#[test]
fn source_stat_batches_report_missing_sources_and_accept_restored_files() {
    let temporary = crate::test_support::tempdir().unwrap();
    let path = temporary.path().join("selected");
    fs::write(&path, b"original").unwrap();
    let (mut worker, selections, _control) = registered_source_worker(&[&path], false);
    let request = Request::StatMany {
        paths: vec![b"ignored".to_vec(); 64],
        sources: Some(vec![selections[0].clone(); 64]),
        follow: false,
        guard: None,
    };
    let response = worker.handle(&request);
    assert!(
        matches!(&response, Response::Stats(entries) if entries.len() == 64),
        "unexpected initial response: {response:?}"
    );

    fs::rename(&path, temporary.path().join("original")).unwrap();
    let response = worker.handle(&request);
    let Response::EndpointError(error) = response else {
        panic!("expected missing-source error: {response:?}");
    };
    assert!(
        error.message.contains("inspect registered source leaf"),
        "{error:?}"
    );
    assert_eq!(error.io_kind, Some(WireIoKind::NotFound), "{error:?}");

    fs::rename(temporary.path().join("original"), &path).unwrap();
    let response = worker.handle(&request);
    let Response::Stats(entries) = response else {
        panic!("expected restored-file metadata: {response:?}");
    };
    assert_eq!(entries.len(), 64);
    assert!(
        entries
            .iter()
            .all(|entry| entry.as_ref().is_some_and(|e| e.size == 8)),
        "{entries:?}"
    );
}

#[test]
fn source_stat_does_not_follow_intermediate_symlinks() {
    let temporary = crate::test_support::tempdir().unwrap();
    let selected = temporary.path().join("selected");
    let outside = temporary.path().join("outside");
    fs::create_dir(&selected).unwrap();
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("secret"), b"secret").unwrap();
    std::os::unix::fs::symlink("../outside", selected.join("link")).unwrap();
    let session = DescriptorSessionSlot::default();
    let mut control = FsOps::with_descriptor_session(session.clone());
    let response = control.handle(&crate::test_support::register_source_roots(&[&selected], 0));
    let Response::SourceRootsRegistered(roots) = response else {
        panic!("unexpected source registration response: {response:?}")
    };
    let secret = roots[0].selection.join(b"link/secret").unwrap();
    let mut worker = FsOps::with_descriptor_session(session);
    worker.initialize_sources(&roots).unwrap();
    let response = worker.handle(&Request::StatMany {
        paths: vec![selected.join("link/secret").as_os_str().as_bytes().to_vec()],
        sources: Some(vec![secret]),
        follow: true,
        guard: None,
    });
    assert!(matches!(response, Response::Stats(stats) if stats.len() == 1 && stats[0].is_none()));
}

#[test]
fn source_content_uses_registered_directory_after_name_replacement() {
    let temporary = crate::test_support::tempdir().unwrap();
    let selected = temporary.path().join("selected");
    let replacement = temporary.path().join("replacement");
    fs::create_dir(&selected).unwrap();
    fs::create_dir(&replacement).unwrap();
    fs::write(selected.join("marker"), b"original").unwrap();
    fs::write(replacement.join("marker"), b"replacement").unwrap();
    // Exercise a raw byte name where the filesystem allows one.
    let raw_name = OsString::from_vec(
        if crate::test_support::filesystem_accepts_non_utf8_names() {
            b"raw-\xff".to_vec()
        } else {
            b"raw-plain".to_vec()
        },
    );
    fs::write(selected.join(&raw_name), b"raw-original").unwrap();

    let (mut worker, selections, _control) = registered_source_worker(&[&selected], false);
    let marker = selections[0].join(b"marker").unwrap();
    let raw = selections[0].join(raw_name.as_bytes()).unwrap();
    fs::rename(&selected, temporary.path().join("moved")).unwrap();
    symlink(&replacement, &selected).unwrap();
    let parallel_marker = selected.join("marker").as_os_str().as_bytes().to_vec();
    assert_eq!(fs::read(selected.join("marker")).unwrap(), b"replacement");

    let response = worker.handle(&Request::ReadRange {
        path: parallel_marker.clone(),
        source: Some(marker.clone()),
        attempt: 0,
        off: 0,
        len: 8,
    });
    assert!(matches!(response, Response::Block { data, .. } if data == b"original"));

    let response = worker.handle(&Request::ReadSmallBatch(vec![SmallRead {
        path: parallel_marker.clone(),
        source: Some(marker.clone()),
        attempt: 0,
        len: 8,
    }]));
    assert!(matches!(
        response,
        Response::SmallBlocks(blocks)
            if matches!(&blocks[..], [Ok(SmallBlock { data, .. })] if data == b"original")
    ));

    let response = worker.handle(&Request::HashBlocks {
        path: parallel_marker.clone(),
        source: Some(marker.clone()),
        which: Which::Final,
        copy_id: [0; 16],
        block: MIN_HASH_BLOCK_BYTES,
        len: 8,
        attempt: 0,
        guard: None,
    });
    assert!(
        matches!(response, Response::Hashes(hashes) if hashes == vec![content_digest(b"original")])
    );

    let response = worker.handle(&Request::FileHash {
        path: parallel_marker,
        source: Some(marker),
        guard: None,
    });
    assert!(
        matches!(response, Response::FileHash { size: 8, hash } if hash == content_digest(b"original"))
    );

    let response = worker.handle(&Request::ReadRange {
        path: b"/parallel/path/is/not/authority".to_vec(),
        source: Some(raw),
        attempt: 0,
        off: 0,
        len: 12,
    });
    assert!(matches!(response, Response::Block { data, .. } if data == b"raw-original"));
}

#[test]
fn source_content_rejects_a_replaced_exact_leaf() {
    let temporary = crate::test_support::tempdir().unwrap();
    let selected = temporary.path().join("selected");
    fs::write(&selected, b"original").unwrap();
    let (mut worker, selections, _control) = registered_source_worker(&[&selected], false);
    fs::rename(&selected, temporary.path().join("selected-original")).unwrap();
    fs::write(&selected, b"replaced").unwrap();

    for response in [
        worker.handle(&Request::ReadRange {
            path: selected.as_os_str().as_bytes().to_vec(),
            source: Some(selections[0].clone()),
            attempt: 0,
            off: 0,
            len: 8,
        }),
        worker.handle(&Request::HashBlocks {
            path: selected.as_os_str().as_bytes().to_vec(),
            source: Some(selections[0].clone()),
            which: Which::Final,
            copy_id: [0; 16],
            block: MIN_HASH_BLOCK_BYTES,
            len: 8,
            attempt: 0,
            guard: None,
        }),
        worker.handle(&Request::FileHash {
            path: selected.as_os_str().as_bytes().to_vec(),
            source: Some(selections[0].clone()),
            guard: None,
        }),
    ] {
        assert!(
            matches!(response, Response::EndpointError(error) if error.message.contains("registered source leaf changed identity"))
        );
    }
    let response = worker.handle(&Request::ReadSmallBatch(vec![SmallRead {
        path: selected.as_os_str().as_bytes().to_vec(),
        source: Some(selections[0].clone()),
        attempt: 0,
        len: 8,
    }]));
    assert!(
        matches!(response, Response::SmallBlocks(blocks) if matches!(&blocks[..], [Err(error)] if error.contains("registered source leaf changed identity")))
    );
}

#[test]
fn source_content_refuses_symlink_intermediates() {
    let temporary = crate::test_support::tempdir().unwrap();
    let selected = temporary.path().join("selected");
    let outside = temporary.path().join("outside");
    fs::create_dir(&selected).unwrap();
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("secret"), b"secret").unwrap();
    symlink("../outside", selected.join("link")).unwrap();
    let (mut worker, selections, _control) = registered_source_worker(&[&selected], false);
    let secret = selections[0].join(b"link/secret").unwrap();
    let label = selected.join("link/secret").as_os_str().as_bytes().to_vec();

    for response in [
        worker.handle(&Request::ReadRange {
            path: label.clone(),
            source: Some(secret.clone()),
            attempt: 0,
            off: 0,
            len: 6,
        }),
        worker.handle(&Request::HashBlocks {
            path: label.clone(),
            source: Some(secret.clone()),
            which: Which::Final,
            copy_id: [0; 16],
            block: MIN_HASH_BLOCK_BYTES,
            len: 6,
            attempt: 0,
            guard: None,
        }),
        worker.handle(&Request::FileHash {
            path: label.clone(),
            source: Some(secret.clone()),
            guard: None,
        }),
    ] {
        assert!(matches!(response, Response::EndpointError(_)));
    }
    let response = worker.handle(&Request::ReadSmallBatch(vec![SmallRead {
        path: label,
        source: Some(secret),
        attempt: 0,
        len: 6,
    }]));
    assert!(matches!(response, Response::SmallBlocks(blocks) if matches!(&blocks[..], [Err(_)])));
    assert_eq!(fs::read(outside.join("secret")).unwrap(), b"secret");
}

#[test]
fn source_read_cache_keys_root_and_attempt() {
    let temporary = crate::test_support::tempdir().unwrap();
    let first = temporary.path().join("first");
    let second = temporary.path().join("second");
    fs::create_dir(&first).unwrap();
    fs::create_dir(&second).unwrap();
    fs::write(first.join("same"), b"first").unwrap();
    fs::write(second.join("same"), b"other").unwrap();
    let (mut worker, selections, _control) = registered_source_worker(&[&first, &second], false);
    let first_source = selections[0].join(b"same").unwrap();
    let second_source = selections[1].join(b"same").unwrap();

    for (source, expected) in [
        (&first_source, &b"first"[..]),
        (&second_source, &b"other"[..]),
    ] {
        let response = worker.handle(&Request::ReadRange {
            path: b"same-parallel-label".to_vec(),
            source: Some(source.clone()),
            attempt: 0,
            off: 0,
            len: 5,
        });
        assert!(matches!(response, Response::Block { data, .. } if data == expected));
    }

    fs::rename(first.join("same"), first.join("old")).unwrap();
    fs::write(first.join("same"), b"newer").unwrap();
    let same_attempt = worker.handle(&Request::ReadRange {
        path: Vec::new(),
        source: Some(first_source.clone()),
        attempt: 0,
        off: 0,
        len: 5,
    });
    assert!(matches!(same_attempt, Response::Block { data, .. } if data == b"first"));
    let retry = worker.handle(&Request::ReadRange {
        path: Vec::new(),
        source: Some(first_source),
        attempt: 1,
        off: 0,
        len: 5,
    });
    assert!(matches!(retry, Response::Block { data, .. } if data == b"newer"));
}

#[test]
fn confined_source_content_requires_exact_registered_references() {
    let temporary = crate::test_support::tempdir().unwrap();
    let selected = temporary.path().join("selected");
    fs::write(&selected, b"selected").unwrap();
    fs::write(temporary.path().join("sibling"), b"sibling!").unwrap();
    let (mut worker, selections, _control) = registered_source_worker(&[&selected], false);
    let forged = RegisteredPath::new(selections[0].root(), b"sibling".to_vec()).unwrap();

    for source in [None, Some(forged)] {
        let response = worker.handle(&Request::ReadRange {
            path: selected.as_os_str().as_bytes().to_vec(),
            source,
            attempt: 0,
            off: 0,
            len: 8,
        });
        assert!(matches!(response, Response::EndpointError(_)));
    }

    for response in [
        worker.handle(&Request::HashBlocks {
            path: selected.as_os_str().as_bytes().to_vec(),
            source: None,
            which: Which::Final,
            copy_id: [0; 16],
            block: MIN_HASH_BLOCK_BYTES,
            len: 8,
            attempt: 0,
            guard: None,
        }),
        worker.handle(&Request::FileHash {
            path: selected.as_os_str().as_bytes().to_vec(),
            source: None,
            guard: None,
        }),
    ] {
        assert!(
            matches!(response, Response::EndpointError(error) if error.message.contains("omitted"))
        );
    }
    let response = worker.handle(&Request::ReadSmallBatch(vec![SmallRead {
        path: selected.as_os_str().as_bytes().to_vec(),
        source: None,
        attempt: 0,
        len: 8,
    }]));
    assert!(
        matches!(response, Response::SmallBlocks(blocks) if matches!(&blocks[..], [Err(error)] if error.contains("omitted")))
    );

    let response = worker.handle(&Request::HashBlocks {
        path: selected.as_os_str().as_bytes().to_vec(),
        source: Some(selections[0].clone()),
        which: Which::Partial,
        copy_id: [0; 16],
        block: MIN_HASH_BLOCK_BYTES,
        len: 8,
        attempt: 0,
        guard: None,
    });
    assert!(
        matches!(response, Response::EndpointError(error) if error.message.contains("only valid for the final source"))
    );
}

#[test]
fn unconfined_source_content_uses_only_the_explicit_legacy_path() {
    let temporary = crate::test_support::tempdir().unwrap();
    let selected = temporary.path().join("selected");
    let sibling = temporary.path().join("sibling");
    fs::write(&selected, b"selected").unwrap();
    fs::write(&sibling, b"legacy!!").unwrap();
    let (mut worker, _, _control) = registered_source_worker(&[&selected], true);
    let response = worker.handle(&Request::ReadRange {
        path: sibling.as_os_str().as_bytes().to_vec(),
        source: None,
        attempt: 0,
        off: 0,
        len: 8,
    });
    assert!(matches!(response, Response::Block { data, .. } if data == b"legacy!!"));

    let response = worker.handle(&Request::HashBlocks {
        path: sibling.as_os_str().as_bytes().to_vec(),
        source: None,
        which: Which::Final,
        copy_id: [0; 16],
        block: MIN_HASH_BLOCK_BYTES,
        len: 8,
        attempt: 0,
        guard: None,
    });
    assert!(
        matches!(response, Response::Hashes(hashes) if hashes == vec![content_digest(b"legacy!!")])
    );
    let response = worker.handle(&Request::FileHash {
        path: sibling.as_os_str().as_bytes().to_vec(),
        source: None,
        guard: None,
    });
    assert!(
        matches!(response, Response::FileHash { size: 8, hash } if hash == content_digest(b"legacy!!"))
    );
}

#[test]
fn destination_worker_rejects_source_only_content_requests() {
    let temporary = crate::test_support::tempdir().unwrap();
    fs::write(temporary.path().join("marker"), b"marker").unwrap();
    let mut worker = FsOps::new();
    worker.destination_root = Some(Arc::new(Root::open(temporary.path()).unwrap()));
    worker.destination_prefix = Some(b".".to_vec());

    let response = worker.handle(&Request::ReadRange {
        path: b"marker".to_vec(),
        source: None,
        attempt: 0,
        off: 0,
        len: 6,
    });
    assert!(
        matches!(response, Response::EndpointError(error) if error.message.contains("destination worker"))
    );
    let response = worker.handle(&Request::ReadSmallBatch(vec![SmallRead {
        path: b"marker".to_vec(),
        source: None,
        attempt: 0,
        len: 6,
    }]));
    assert!(
        matches!(response, Response::SmallBlocks(blocks) if matches!(&blocks[..], [Err(error)] if error.contains("destination worker")))
    );
}

#[test]
fn source_legacy_stat_requires_explicit_unconfined_registration() {
    let temporary = crate::test_support::tempdir().unwrap();
    let selected = temporary.path().join("selected");
    let sibling = temporary.path().join("sibling");
    fs::write(&selected, b"selected").unwrap();
    fs::write(&sibling, b"sibling").unwrap();
    let session = DescriptorSessionSlot::default();
    let mut control = FsOps::with_descriptor_session(session.clone());
    let response = control.handle(&Request::RegisterSourceRoots {
        base: SourceRootBase::default(),
        selections: vec![SourceRootSelection {
            path: selected.as_os_str().as_bytes().to_vec(),
            follow_root: false,
        }],
        symlink_policy: OperatorSymlinkPolicy::Refuse,
        allow_unconfined_paths: true,
        shared_workers: 0,
        independent_handoff_workers: 0,
    });
    let Response::SourceRootsRegistered(roots) = response else {
        panic!("unexpected source registration response: {response:?}")
    };
    let mut worker = FsOps::with_descriptor_session(session);
    worker.initialize_sources(&roots).unwrap();
    let response = worker.handle(&Request::StatMany {
        paths: vec![sibling.as_os_str().as_bytes().to_vec()],
        sources: None,
        follow: false,
        guard: None,
    });
    assert!(matches!(response, Response::Stats(stats) if stats.len() == 1 && stats[0].is_some()));
}

#[test]
fn source_descriptor_budget_accounts_for_registry_control_and_workers() {
    assert_eq!(SOURCE_SHARED_WORKER_FD_RESERVE, 16 + 5 + 1);
    assert_eq!(
        source_descriptor_requirement(7, 4, 3, 2).unwrap(),
        7 + SOURCE_FD_RESERVE + 2 * 4 * 5 + SOURCE_SHARED_WORKER_FD_RESERVE * 3 + 3 * 2
    );
    assert!(source_descriptor_requirement(0, usize::MAX, usize::MAX, usize::MAX).is_err());
}

#[test]
fn live_descriptor_snapshot_includes_this_process() {
    let limits = nofile_limits().unwrap();
    if limits.rlim_cur != libc::RLIM_INFINITY {
        assert!(current_open_descriptor_count(limits.rlim_cur).unwrap() >= 3);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn proc_status_umask_parses_only_the_kernel_line() {
    assert_eq!(
        parse_proc_status_umask("Name:\tsyq\nUmask:\t0022\nState:\tR (running)\n"),
        Some(0o022)
    );
    assert_eq!(parse_proc_status_umask("Umask:\t0077\n"), Some(0o077));
    assert_eq!(parse_proc_status_umask("Name:\tsyq\n"), None);
    assert_eq!(parse_proc_status_umask("Umask:\t8\n"), None);
    assert_eq!(parse_proc_status_umask("Umask:\t01777\n"), None);
}

#[test]
fn process_umask_matches_file_creation() {
    let temp = crate::test_support::tempdir().unwrap();
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o777)
        .open(temp.path().join("probe"))
        .unwrap();
    let created = file.metadata().unwrap().mode() & 0o777;
    assert_eq!(created, 0o777 & !process_umask());
}

#[test]
fn partial_collision_reservation_covers_shortened_names() {
    let path = PathBuf::from("parent").join("x".repeat(255));
    let id = [9; 16];
    let full = partial_path_with_name_max(&path, &id, 255).unwrap();
    let key = partial_reservation_key(full.as_os_str().as_bytes());
    for limit in [255, 143, 100, 26, 25] {
        let partial = partial_path_with_name_max(&path, &id, limit).unwrap();
        assert_eq!(partial_reservation_key(partial.as_os_str().as_bytes()), key);
    }
    let other = Path::new("other").join(full.file_name().unwrap());
    assert_ne!(partial_reservation_key(other.as_os_str().as_bytes()), key);
    let other_id = partial_path_with_name_max(&path, &[8; 16], 255).unwrap();
    assert_ne!(
        partial_reservation_key(other_id.as_os_str().as_bytes()),
        key
    );
}

#[test]
fn registered_fifo_keeps_identity_checks_without_connecting_a_writer() {
    let temporary = crate::test_support::tempdir().unwrap();
    let fifo = temporary.path().join("pipe");
    let regular = temporary.path().join("file");
    make_fifo(&fifo, 0o600);
    fs::write(&regular, b"data").unwrap();
    let session = DescriptorSessionSlot::default();
    let mut control = FsOps::with_descriptor_session(session.clone());
    let response = control.handle(&crate::test_support::register_source_roots(
        &[&fifo, &regular],
        0,
    ));
    let Response::SourceRootsRegistered(roots) = response else {
        panic!("unexpected source registration response: {response:?}");
    };
    // Existing pinned records and the FIFO-only exception use the same wire
    // representation; all peers must match build identities before decoding.
    let encoded = postcard::to_stdvec(&roots).unwrap();
    let roots: Vec<RegisteredSourceRoot> = postcard::from_bytes(&encoded).unwrap();
    let mut worker = FsOps::with_descriptor_session(session.clone());
    worker.initialize_sources(&roots).unwrap();
    let name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    let writer = unsafe {
        libc::open(
            name.as_ptr(),
            libc::O_WRONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    let error = io::Error::last_os_error();
    if writer >= 0 {
        unsafe {
            libc::close(writer);
        }
    }
    assert_eq!(writer, -1, "source registration connected a FIFO reader");
    assert_eq!(error.raw_os_error(), Some(libc::ENXIO));

    // Only FIFOs may omit an exact-object ticket; regular files still need one.
    let mut unpinned = roots[0].clone();
    unpinned.leaf_ticket = None;
    unpinned.validate().unwrap();
    let mut unpinned_regular = roots[1].clone();
    unpinned_regular.leaf_ticket = None;
    assert!(unpinned_regular.validate().is_err());

    fs::rename(&fifo, temporary.path().join("original")).unwrap();
    make_fifo(&fifo, 0o600);
    let mut fresh = FsOps::with_descriptor_session(session);
    assert!(
        fresh.initialize_sources(&[unpinned]).is_err(),
        "worker accepted a replaced FIFO"
    );
    let response = worker.handle(&Request::StatMany {
        paths: vec![b"ignored".to_vec()],
        sources: Some(vec![roots[0].selection.clone()]),
        follow: false,
        guard: None,
    });
    assert!(
        matches!(response, Response::EndpointError(_)),
        "worker accepted a replaced FIFO: {response:?}"
    );
}

use super::*;

fn put(path: &[u8]) -> SmallPut {
    let data = vec![42; 256 * 1024];
    SmallPut {
        path: path.to_vec(),
        copy_id: [9; 16],
        hash: content_digest(&data),
        data,
        meta: Meta {
            inode_metadata: None,
            mode: 0o600,
            uid: 0,
            gid: 0,
            mtime: 0,
            mtime_nsec: 0,
        },
        flags: 0,
        inplace: false,
        condition: TargetCondition::Any,
        guard: None,
    }
}

fn rooted(dir: &Path) -> FsOps {
    let mut ops = FsOps::new();
    ops.install_destination(File::open(dir).unwrap(), b"logical", None)
        .unwrap();
    ops
}

#[test]
fn mapping_keeps_batch_and_range_payload_allocations() {
    let dir = crate::test_support::tempdir().unwrap();
    for prefix in [false, true] {
        let ops = if prefix {
            rooted(dir.path())
        } else {
            FsOps::new()
        };
        let mut request = Request::PutSmallBatch(vec![put(b"logical/one"), put(b"logical/two")]);
        let Request::PutSmallBatch(puts) = &request else {
            unreachable!()
        };
        let batch = puts.as_ptr();
        let payloads: Vec<_> = puts
            .iter()
            .map(|p| (p.data.as_ptr(), p.data.capacity(), p.hash))
            .collect();
        ops.map_request(&mut request).unwrap();
        let Request::PutSmallBatch(puts) = &request else {
            unreachable!()
        };
        assert_eq!(puts.as_ptr(), batch);
        for (i, p) in puts.iter().enumerate() {
            assert_eq!((p.data.as_ptr(), p.data.capacity(), p.hash), payloads[i]);
            assert_eq!(content_digest(&p.data), p.hash);
        }
        assert_eq!(
            puts[0].path,
            if prefix {
                b"one".as_slice()
            } else {
                b"logical/one".as_slice()
            }
        );

        let data = vec![73; 256 * 1024];
        let pointer = data.as_ptr();
        let mut request = Request::WriteRange {
            path: b"logical/range".to_vec(),
            inplace: false,
            copy_id: [9; 16],
            attempt: 0,
            off: 0,
            hash: content_digest(&data),
            data: data.into(),
            guard: None,
        };
        ops.map_request(&mut request).unwrap();
        let Request::WriteRange { path, data, .. } = &request else {
            unreachable!()
        };
        assert_eq!(data.as_ptr(), pointer);
        assert_eq!(
            path,
            if prefix {
                b"range".as_slice()
            } else {
                b"logical/range".as_slice()
            }
        );
    }
}

#[test]
fn dispatch_validates_before_mapping_or_writing() {
    let dir = crate::test_support::tempdir().unwrap();
    let mut ops = FsOps::new();
    // Set only a prefix so mapping would fail if it ran before validation.
    ops.destination_prefix = Some(b"logical".to_vec());
    let mut request = Request::PutSmallBatch(vec![put(b"outside/file")]);
    let response = ops.handle_in_place(&mut request);
    assert!(
        matches!(response, Response::Err(message) if message.contains("before a destination root"))
    );
    let Request::PutSmallBatch(puts) = request else {
        unreachable!()
    };
    assert_eq!(puts[0].path, b"outside/file");
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn invalid_later_batch_path_prevents_all_writes() {
    let dir = crate::test_support::tempdir().unwrap();
    let mut ops = rooted(dir.path());
    let mut request = Request::PutSmallBatch(vec![put(b"logical/valid"), put(b"outside/invalid")]);
    assert!(matches!(
        ops.handle_in_place(&mut request),
        Response::EndpointError(_)
    ));
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn mapped_batch_preserves_hash_checks_conditions_and_publication() {
    let dir = crate::test_support::tempdir().unwrap();
    let mut ops = rooted(dir.path());
    fs::write(dir.path().join("bad-hash"), b"old").unwrap();
    fs::write(dir.path().join("exists"), b"old").unwrap();
    let mut bad_hash = put(b"logical/bad-hash");
    bad_hash.hash = [0; 32];
    let mut exists = put(b"logical/exists");
    exists.condition = TargetCondition::Absent;
    let mut request = Request::PutSmallBatch(vec![put(b"logical/good"), bad_hash, exists]);
    let Request::PutSmallBatch(puts) = &request else {
        unreachable!()
    };
    let pointer = puts[0].data.as_ptr();
    let Response::Applied(errors) = ops.handle_in_place(&mut request) else {
        panic!("expected batch response")
    };
    assert!(errors[0].is_none());
    assert!(errors[1].is_some());
    assert!(errors[2].is_some());
    let Request::PutSmallBatch(puts) = &request else {
        unreachable!()
    };
    assert_eq!(puts[0].data.as_ptr(), pointer);
    assert_eq!(fs::read(dir.path().join("good")).unwrap(), puts[0].data);
    assert_eq!(fs::read(dir.path().join("bad-hash")).unwrap(), b"old");
    assert_eq!(fs::read(dir.path().join("exists")).unwrap(), b"old");
    let sidecar = partial_path_with_name_max(Path::new("good"), &[9; 16], 255).unwrap();
    assert!(!dir.path().join(sidecar).exists());
}

#[test]
fn guarded_batch_keeps_absolute_paths_and_rejects_mixed_authority() {
    let dir = crate::test_support::tempdir().unwrap();
    let root = Root::open(dir.path()).unwrap();
    let identity = root.identity();
    let path = dir.path().join("guarded");
    let mut item = put(path.as_os_str().as_bytes());
    item.guard = Some(ContainerGuard {
        root: dir.path().as_os_str().as_bytes().to_vec(),
        dev: identity.dev,
        ino: identity.ino,
    });
    let mut request = Request::PutSmallBatch(vec![item]);
    let Response::Applied(errors) = rooted(dir.path()).handle_in_place(&mut request) else {
        panic!("expected batch response")
    };
    assert!(errors[0].is_some());
    assert!(!path.exists());
    let Request::PutSmallBatch(puts) = &request else {
        unreachable!()
    };
    assert_eq!(puts[0].path, path.as_os_str().as_bytes());
    let Response::Applied(errors) = FsOps::new().handle_in_place(&mut request) else {
        panic!("expected batch response")
    };
    assert!(errors[0].is_none());
    assert_eq!(fs::read(path).unwrap(), vec![42; 256 * 1024]);
}

#[cfg(target_os = "linux")]
#[test]
fn optimistic_partial_batch_retries_only_the_rejected_file() {
    let dir = crate::test_support::tempdir().unwrap();
    fs::create_dir(dir.path().join("nested")).unwrap();
    let mut ops = rooted(dir.path());
    let root = ops.destination_root.as_ref().unwrap().clone();
    root.test_name_limit
        .store(143, std::sync::atomic::Ordering::Relaxed);
    let names = ["short".to_owned(), "x".repeat(120), "y".repeat(120)];
    let mut request = Request::PutSmallBatch(
        names
            .iter()
            .map(|name| put(format!("logical/nested/{name}").as_bytes()))
            .collect(),
    );
    let Response::Applied(errors) = ops.handle_in_place(&mut request) else {
        panic!("expected batch result");
    };
    assert_eq!(errors.len(), 3);
    assert!(errors.iter().all(Option::is_none), "{errors:?}");
    for name in names {
        assert_eq!(
            fs::read(dir.path().join("nested").join(name)).unwrap(),
            vec![42; 256 * 1024]
        );
    }
    assert_eq!(fs::read_dir(dir.path().join("nested")).unwrap().count(), 3);
    assert_eq!(
        root.test_name_queries
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
}

#[cfg(target_os = "linux")]
#[test]
fn ordinary_partial_planning_and_copy_do_not_query_name_limits() {
    let dir = crate::test_support::tempdir().unwrap();
    fs::create_dir(dir.path().join("nested")).unwrap();
    let mut ops = rooted(dir.path());
    let root = ops.destination_root.as_ref().unwrap().clone();
    let names = ["short".to_owned(), "x".repeat(255)];
    let paths: Vec<_> = names
        .iter()
        .map(|name| format!("nested/{name}").into_bytes())
        .collect();
    assert!(ops
        .partial_paths(&paths, &[9; 16], None)
        .iter()
        .all(Result::is_ok));
    let mut request = Request::PutSmallBatch(
        names
            .iter()
            .map(|name| put(format!("logical/nested/{name}").as_bytes()))
            .collect(),
    );
    let Response::Applied(errors) = ops.handle_in_place(&mut request) else {
        panic!("expected batch result");
    };
    assert!(errors.iter().all(Option::is_none), "{errors:?}");
    assert_eq!(
        root.test_name_queries
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
    for name in names {
        assert_eq!(
            fs::read(dir.path().join("nested").join(name)).unwrap(),
            vec![42; 256 * 1024]
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn optimistic_partial_reopens_legacy_short_name_across_workers() {
    let dir = crate::test_support::tempdir().unwrap();
    let name = "x".repeat(120);
    // Exact name produced at d695902d with NAME_MAX=143, logical/<120 x's>,
    // and copy id [9;16]. Keep this fixture independent of the new resolver.
    let legacy = format!(".{}.syq-tmp.z6xlpz5jq2rgx7pp", "x".repeat(117));
    fs::write(dir.path().join(&legacy), b"old data").unwrap();
    fs::set_permissions(dir.path().join(&legacy), fs::Permissions::from_mode(0o600)).unwrap();
    let path = format!("logical/{name}").into_bytes();
    let setup = || {
        let ops = rooted(dir.path());
        ops.destination_root
            .as_ref()
            .unwrap()
            .test_name_limit
            .store(143, std::sync::atomic::Ordering::Relaxed);
        ops
    };
    let mut first = setup();
    let reply = first.handle_in_place(&mut Request::ProbePartial {
        path: path.clone(),
        copy_id: [9; 16],
        guard: None,
    });
    assert!(matches!(reply, Response::PartialSize(Some(8))), "{reply:?}");
    let mut prepared = setup();
    let reply = prepared.handle_in_place(&mut Request::Prepare {
        path: path.clone(),
        size: 8,
        inplace: false,
        copy_id: [9; 16],
        mode: 0o600,
        attempt: 0,
        create_if_missing: false,
        guard: None,
    });
    assert!(matches!(reply, Response::Prepared(_)), "{reply:?}");
    let mut reader = setup();
    let reply = reader.handle_in_place(&mut Request::HashBlocks {
        path: path.clone(),
        source: None,
        which: Which::Partial,
        copy_id: [9; 16],
        block: 64 * 1024,
        len: 8,
        attempt: 0,
        guard: None,
    });
    assert!(matches!(reply, Response::Hashes(_)), "{reply:?}");
    let mut writer = setup();
    let reply = writer.handle_in_place(&mut Request::WriteRange {
        path: path.clone(),
        inplace: false,
        copy_id: [9; 16],
        attempt: 0,
        off: 0,
        hash: content_digest(b"new data"),
        data: b"new data".to_vec().into(),
        guard: None,
    });
    assert!(matches!(reply, Response::Ok), "{reply:?}");
    assert_eq!(fs::read(dir.path().join(&legacy)).unwrap(), b"new data");
    let mut publisher = setup();
    let reply = publisher.handle_in_place(&mut Request::Finalize {
        path,
        inplace: false,
        copy_id: [9; 16],
        meta: put(b"unused").meta,
        flags: 0,
        condition: TargetCondition::Absent,
        guard: None,
        expected_hash: None,
    });
    assert!(matches!(reply, Response::Ok), "{reply:?}");
    assert_eq!(fs::read(dir.path().join(&name)).unwrap(), b"new data");
    assert!(!dir.path().join(&legacy).exists());
    for ops in [&first, &prepared, &reader, &writer, &publisher] {
        assert_eq!(
            ops.destination_root
                .as_ref()
                .unwrap()
                .test_name_queries
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn learned_conservative_limit_does_not_change_a_successful_partial_name() {
    let dir = crate::test_support::tempdir().unwrap();
    let ops = rooted(dir.path());
    let target = ops
        .rooted_destination_target("x".repeat(120).as_bytes(), None)
        .unwrap()
        .unwrap();
    target
        .root
        .test_name_limit
        .store(143, std::sync::atomic::Ordering::Relaxed);
    let (before, _, ()) = with_rooted_partial(&target, &[9; 16], |_, _| Ok(())).unwrap();
    // Another, longer filename failed and populated the shared parent limit.
    assert_eq!(
        target
            .root
            .rejected_partial_name_max(&target.relative)
            .unwrap(),
        143
    );
    let (after, _, ()) = with_rooted_partial(&target, &[9; 16], |_, _| Ok(())).unwrap();
    assert_eq!(before, after);
    assert!(after.to_path_buf().as_os_str().len() > 143);
}

#[cfg(target_os = "linux")]
#[test]
fn guarded_partials_keep_the_authoritys_exact_name_selection() {
    let dir = crate::test_support::tempdir().unwrap();
    let root = Arc::new(Root::open(dir.path()).unwrap());
    root.test_name_limit
        .store(143, std::sync::atomic::Ordering::Relaxed);
    let target = GuardedTarget {
        root: root.clone(),
        relative: RelativePath::new("x".repeat(120).as_bytes()).unwrap(),
        label: PathBuf::from(format!("logical/{}", "x".repeat(120))),
    }
    .as_rooted();
    // Accept any candidate, as a filesystem may accept names longer than its
    // conservative pathconf limit. The quota checker still derives this exact
    // pre-change spelling, so a successful optimistic open would be wrong.
    let (relative, _, ()) = with_rooted_partial(&target, &[9; 16], |_, _| Ok(())).unwrap();
    assert_eq!(
        relative.to_path_buf(),
        PathBuf::from(format!(".{}.syq-tmp.z6xlpz5jq2rgx7pp", "x".repeat(117)))
    );
    assert_eq!(
        root.test_name_queries
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
}

#[cfg(target_os = "linux")]
#[test]
fn optimistic_partial_does_not_retry_unrelated_or_unchanged_names() {
    let dir = crate::test_support::tempdir().unwrap();
    let ops = rooted(dir.path());
    let target = ops
        .rooted_destination_target(b"short", None)
        .unwrap()
        .unwrap();
    target
        .root
        .test_name_limit
        .store(143, std::sync::atomic::Ordering::Relaxed);
    let mut calls = 0;
    let result: Result<(_, _, ())> = with_rooted_partial(&target, &[9; 16], |_, _| {
        calls += 1;
        Err(io::Error::from_raw_os_error(libc::EACCES).into())
    });
    assert_eq!(
        result
            .unwrap_err()
            .downcast_ref::<io::Error>()
            .unwrap()
            .raw_os_error(),
        Some(libc::EACCES)
    );
    assert_eq!(calls, 1);
    assert_eq!(
        target
            .root
            .test_name_queries
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
    let result: Result<(_, _, ())> = with_rooted_partial(&target, &[9; 16], |_, _| {
        calls += 1;
        Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG).into())
    });
    assert_eq!(
        result
            .unwrap_err()
            .downcast_ref::<io::Error>()
            .unwrap()
            .raw_os_error(),
        Some(libc::ENAMETOOLONG)
    );
    assert_eq!(calls, 2, "an unchanged name must not be retried");
    assert_eq!(
        target
            .root
            .test_name_queries
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
}

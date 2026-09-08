use super::*;

fn put(path: &[u8]) -> SmallPut {
    let data = vec![42; 256 * 1024];
    SmallPut {
        path: path.to_vec(),
        copy_id: [9; 16],
        hash: content_digest(&data),
        data,
        meta: Meta {
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
    ops.install_destination(File::open(dir).unwrap(), b"logical")
        .unwrap();
    ops
}

#[test]
fn mapping_keeps_batch_and_range_payload_allocations() {
    let dir = tempfile::tempdir().unwrap();
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
            data,
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
    let dir = tempfile::tempdir().unwrap();
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
    let dir = tempfile::tempdir().unwrap();
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
    let dir = tempfile::tempdir().unwrap();
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
    let dir = tempfile::tempdir().unwrap();
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

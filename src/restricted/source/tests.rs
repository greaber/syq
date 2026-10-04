use super::*;
use crate::proto::{ContainerGuard, Op, ReadStreamRequest, SmallRead};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::time::Duration;

fn policy(path: &Path) -> SourcePolicy {
    SourcePolicy {
        base: SourceRootBase::default(),
        selections: vec![SourceRootSelection {
            path: path.as_os_str().as_bytes().to_vec(),
            follow_root: false,
        }],
        selection_types: vec![crate::cli::SourceSelection::Named],
        symlink_policy: OperatorSymlinkPolicy::Refuse,
        hashing: Default::default(),
        preservation: Default::default(),
        sparse: false,
        compressed: false,
        tcp: None,
        send_rate: None,
        limits: CopyLimits {
            max_entries: 100,
            max_total_bytes: 1024,
            max_file_bytes: 1024,
            hash_block_bytes: crate::proto::MIN_HASH_BLOCK_BYTES,
            max_connections: 4,
            max_deletions: 0,
        },
        deadline: Instant::now() + Duration::from_secs(30),
    }
}

fn registration(policy: &SourcePolicy) -> Request {
    Request::RegisterSourceRoots {
        base: policy.base.clone(),
        selections: policy.selections.clone(),
        symlink_policy: policy.symlink_policy,
        allow_unconfined_paths: false,
        shared_workers: 0,
        independent_handoff_workers: 0,
    }
}

struct Fixture {
    authority: Arc<SourceAuthority>,
    control: SourceConnection,
    ops: FsOps,
    roots: Vec<RegisteredSourceRoot>,
}

impl Fixture {
    fn new(policy: SourcePolicy) -> Self {
        let request = registration(&policy);
        let authority = SourceAuthority::new(policy).unwrap();
        let control = authority.acquire(&ConnectionRole::Control, false).unwrap();
        let mut ops = FsOps::new();
        let response = control.register(&mut ops, &request).unwrap();
        let Response::SourceRootsRegistered(roots) = response else {
            panic!("unexpected registration: {response:?}")
        };
        Self {
            authority,
            control,
            ops,
            roots,
        }
    }

    fn worker(&self) -> SourceConnection {
        self.authority.acquire(&self.role(), false).unwrap()
    }

    fn role(&self) -> ConnectionRole {
        ConnectionRole::SourceWorker {
            roots: self.roots.clone(),
            send_budget: None,
        }
    }

    fn source(&self) -> RegisteredPath {
        self.roots[0].selection.clone()
    }
}

fn read(source: Option<RegisteredPath>, len: u32) -> Request {
    Request::ReadRange {
        path: b"/untrusted/display/path".to_vec(),
        source,
        attempt: 0,
        off: 0,
        len,
    }
}

fn error_response(response: &Response) -> bool {
    matches!(response, Response::Err(_) | Response::EndpointError(_))
}

#[test]
fn registration_checks_approved_selectors_before_opening_paths() {
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("approved");
    fs::write(&path, b"approved").unwrap();
    let policy = policy(&path);
    let request = registration(&policy);
    let authority = SourceAuthority::new(policy).unwrap();
    let control = authority.acquire(&ConnectionRole::Control, false).unwrap();
    let mut ops = FsOps::new();
    for changed in 0..5 {
        let mut altered = request.clone();
        let Request::RegisterSourceRoots {
            base,
            selections,
            symlink_policy,
            allow_unconfined_paths,
            ..
        } = &mut altered
        else {
            unreachable!()
        };
        match changed {
            0 => base.path = Some(b"/".to_vec()),
            1 => selections[0].path = b"/unapproved/path".to_vec(),
            2 => selections[0].follow_root = true,
            3 => *allow_unconfined_paths = true,
            _ => *symlink_policy = OperatorSymlinkPolicy::FollowAll,
        }
        assert!(control.register(&mut ops, &altered).is_err());
    }
    let mut excess = request.clone();
    if let Request::RegisterSourceRoots { shared_workers, .. } = &mut excess {
        *shared_workers = 4;
    }
    assert!(control.register(&mut ops, &excess).is_err());
    assert!(matches!(
        control.register(&mut ops, &request).unwrap(),
        Response::SourceRootsRegistered(_)
    ));
    assert!(control.register(&mut ops, &request).is_err());
    assert_eq!(fs::read(&path).unwrap(), b"approved");
}

#[test]
fn worker_admission_binds_the_exact_approved_descriptor_session() {
    let temp = crate::test_support::tempdir().unwrap();
    let approved = temp.path().join("approved");
    let secret = temp.path().join("secret");
    fs::write(&approved, b"approved").unwrap();
    fs::write(&secret, b"secret").unwrap();
    let mut fixture = Fixture::new(policy(&approved));
    let foreign = Fixture::new(policy(&secret));
    assert!(fixture
        .authority
        .acquire(&ConnectionRole::Control, false)
        .is_err());
    assert!(fixture.authority.acquire(&fixture.role(), true).is_err());
    assert!(fixture.authority.acquire(&foreign.role(), false).is_err());
    assert!(fixture
        .authority
        .acquire(
            &ConnectionRole::DestinationWorker {
                destination: None,
                copy_sources: Vec::new(),
            },
            false
        )
        .is_err());

    let worker = fixture.worker();
    assert!(worker
        .register(&mut fixture.ops, &registration(&policy(&secret)))
        .is_err());
    let mut widened = fixture.roots.clone();
    widened[0].selection = RegisteredPath::new(widened[0].selection.root(), Vec::new()).unwrap();
    widened[0].expected_leaf = None;
    widened[0].leaf_ticket = None;
    assert!(fixture
        .authority
        .acquire(
            &ConnectionRole::SourceWorker {
                roots: widened,
                send_budget: None,
            },
            false
        )
        .is_err());
}

#[test]
fn exact_leaf_reads_ignore_display_paths_and_refuse_siblings_and_guards() {
    let temp = crate::test_support::tempdir().unwrap();
    let approved = temp.path().join("approved");
    let secret = temp.path().join("secret");
    fs::write(&approved, b"approved").unwrap();
    fs::write(&secret, b"secret").unwrap();
    let mut fixture = Fixture::new(policy(&approved));
    let worker = fixture.worker();
    let request = read(Some(fixture.source()), 8);
    worker.authorize(&request).unwrap();
    let response = fixture.ops.handle(&request);
    fixture.authority.check_response(&response).unwrap();
    assert!(matches!(response, Response::Block { data, .. } if data == b"approved"));
    let sibling = RegisteredPath::new(fixture.source().root(), b"secret".to_vec()).unwrap();
    assert!(worker.authorize(&read(Some(sibling), 6)).is_err());
    assert!(worker.authorize(&read(None, 6)).is_err());
    let guarded = Request::FileHash {
        path: secret.as_os_str().as_bytes().to_vec(),
        source: Some(fixture.source()),
        guard: Some(ContainerGuard {
            root: b"/".to_vec(),
            dev: 0,
            ino: 0,
        }),
    };
    assert!(worker.authorize(&guarded).is_err());
    fs::rename(&approved, temp.path().join("old")).unwrap();
    fs::write(&approved, b"replaced").unwrap();
    // The existing read descriptor still names the approved inode. A fresh
    // attempt must not open the replacement now occupying its old pathname.
    assert!(
        matches!(fixture.ops.handle(&request), Response::Block { data, .. } if data == b"approved")
    );
    let mut reopened = request;
    if let Request::ReadRange { attempt, .. } = &mut reopened {
        *attempt = 1;
    }
    assert!(error_response(&fixture.ops.handle(&reopened)));
}

#[test]
fn directory_reads_and_scans_keep_pinned_roots_and_refuse_symlink_escapes() {
    let temp = crate::test_support::tempdir().unwrap();
    let directory = temp.path().join("approved");
    let outside = temp.path().join("outside");
    fs::create_dir(&directory).unwrap();
    fs::create_dir(&outside).unwrap();
    fs::write(directory.join("file"), b"approved").unwrap();
    fs::write(outside.join("file"), b"secret!!").unwrap();
    symlink(&outside, directory.join("escape")).unwrap();
    let mut fixture = Fixture::new(policy(&directory));
    let worker = fixture.worker();
    let escape = read(Some(fixture.source().join(b"escape/file").unwrap()), 8);
    worker.authorize(&escape).unwrap();
    assert!(error_response(&fixture.ops.handle(&escape)));
    assert!(fixture.source().join(b"../outside/file").is_err());

    fs::rename(&directory, temp.path().join("moved")).unwrap();
    symlink(&outside, &directory).unwrap();
    let request = read(Some(fixture.source().join(b"file").unwrap()), 8);
    worker.authorize(&request).unwrap();
    assert!(
        matches!(fixture.ops.handle(&request), Response::Block { data, .. } if data == b"approved")
    );

    let root = fixture.source();
    let scan = Request::Scan {
        root: outside.as_os_str().as_bytes().to_vec(),
        source: Some(root.clone()),
        follow_root: true,
        ignore: Vec::new(),
        report_ignored: false,
        guard: None,
    };
    worker.authorize(&scan).unwrap();
    let source = fixture.ops.source_scan_root(Some(&root)).unwrap().unwrap();
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
            fixture
                .control
                .record_scan(&root, batch.iter().map(|entry| entry.path.as_slice()))?;
            entries.extend(batch);
            Ok(())
        },
        &mut |_| Ok(()),
        &mut |_| {},
    )
    .unwrap();
    assert!(entries
        .iter()
        .any(|entry| entry.path == b"escape" && entry.kind == crate::proto::Kind::Symlink));
    assert!(!entries.iter().any(|entry| entry.path == b"escape/file"));
}

#[test]
fn followed_operator_symlinks_work_but_never_escape_a_hard_root() {
    let temp = crate::test_support::tempdir().unwrap();
    let root = temp.path().join("root");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("file"), b"approved").unwrap();
    fs::write(temp.path().join("secret"), b"secret").unwrap();
    symlink("file", root.join("inside")).unwrap();
    symlink("../secret", root.join("escape")).unwrap();
    let mut approved = policy(&root.join("inside"));
    approved.symlink_policy = OperatorSymlinkPolicy::FollowAll;
    approved.selections[0].follow_root = true;
    approved.base = SourceRootBase {
        path: Some(root.as_os_str().as_bytes().to_vec()),
        confined: true,
    };
    approved.selections[0].path = b"inside".to_vec();
    let mut fixture = Fixture::new(approved);
    let worker = fixture.worker();
    let request = read(Some(fixture.source()), 8);
    worker.authorize(&request).unwrap();
    assert!(
        matches!(fixture.ops.handle(&request), Response::Block { data, .. } if data == b"approved")
    );

    let mut escaped = policy(&root);
    escaped.symlink_policy = OperatorSymlinkPolicy::FollowAll;
    escaped.base = SourceRootBase {
        path: Some(root.as_os_str().as_bytes().to_vec()),
        confined: true,
    };
    escaped.selections[0] = SourceRootSelection {
        path: b"escape".to_vec(),
        follow_root: true,
    };
    let request = registration(&escaped);
    let authority = SourceAuthority::new(escaped).unwrap();
    let control = authority.acquire(&ConnectionRole::Control, false).unwrap();
    assert!(error_response(
        &control.register(&mut FsOps::new(), &request).unwrap()
    ));
}

#[test]
fn approved_sources_never_admit_mutation_or_pathname_authority() {
    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("file");
    fs::write(&path, b"unchanged").unwrap();
    let fixture = Fixture::new(policy(&path));
    let requests = [
        Request::Apply {
            ops: vec![Op::Remove {
                path: path.as_os_str().as_bytes().to_vec(),
            }],
            guard: None,
        },
        Request::Canonicalize {
            path: b"/".to_vec(),
            guard: None,
        },
        Request::CheckOperatorDirectory {
            path: b"/".to_vec(),
            allow_missing: true,
            symlink_policy: OperatorSymlinkPolicy::FollowAll,
        },
        Request::ListDir {
            directory: b"/".to_vec(),
            confined_root: None,
            prefix: Vec::new(),
            limit: 1000,
            symlink_policy: OperatorSymlinkPolicy::FollowAll,
        },
        Request::CreateSendBudget { rate: 1 },
        Request::TcpListen {
            key: None,
            token: Vec::new(),
            port_lo: 0,
            port_hi: 0,
            congestion_control: None,
            send_rate: None,
        },
        Request::Receipt,
    ];
    for request in requests {
        assert!(fixture.control.authorize(&request).is_err(), "{request:?}");
        assert!(fixture.worker().authorize(&request).is_err(), "{request:?}");
    }
    assert_eq!(fs::read(&path).unwrap(), b"unchanged");
}

#[test]
fn source_byte_connection_and_entry_limits_are_shared_and_atomic() {
    let temp = crate::test_support::tempdir().unwrap();
    let mut approved = policy(temp.path());
    approved.limits.max_connections = 3;
    approved.limits.max_total_bytes = 10;
    approved.limits.max_entries = 2;
    let fixture = Fixture::new(approved);
    let first = fixture.worker();
    let second = fixture.worker();
    assert!(fixture.authority.acquire(&fixture.role(), false).is_err());
    first
        .authorize(&read(Some(fixture.source().join(b"one").unwrap()), 6))
        .unwrap();
    second
        .authorize(&read(Some(fixture.source().join(b"two").unwrap()), 4))
        .unwrap();
    assert!(first
        .authorize(&read(Some(fixture.source().join(b"one").unwrap()), 1))
        .is_err());
    assert!(second
        .record_scan(&fixture.source(), [b"three".as_slice()])
        .is_err());
    first
        .record_scan(&fixture.source(), [b"one".as_slice(), b"two".as_slice()])
        .unwrap();
    assert_eq!(fixture.authority.state.lock().unwrap().paths.len(), 2);
    assert_eq!(fixture.authority.state.lock().unwrap().requested_bytes, 10);
    drop(second);
    assert!(fixture.authority.acquire(&fixture.role(), false).is_ok());
}

#[test]
fn rejected_batches_do_not_consume_authority_and_streams_charge_each_chunk() {
    let temp = crate::test_support::tempdir().unwrap();
    let mut approved = policy(temp.path());
    approved.limits.max_total_bytes = 8;
    let fixture = Fixture::new(approved);
    let worker = fixture.worker();
    let reference = fixture.source().join(b"file").unwrap();
    let bad = Request::ReadSmallBatch(vec![
        SmallRead {
            path: Vec::new(),
            source: Some(reference.clone()),
            attempt: 0,
            len: 4,
        },
        SmallRead {
            path: Vec::new(),
            source: None,
            attempt: 0,
            len: 4,
        },
    ]);
    assert!(worker.authorize(&bad).is_err());
    assert_eq!(fixture.authority.state.lock().unwrap().requested_bytes, 0);
    assert!(fixture.authority.state.lock().unwrap().paths.is_empty());
    let stream = ReadStreamRequest {
        path: Vec::new(),
        source: Some(reference.clone()),
        attempt: 0,
        off: 0,
        end: 8,
        block: 512,
    };
    worker
        .authorize(&Request::ReadStream(stream.clone()))
        .unwrap();
    assert_eq!(fixture.authority.state.lock().unwrap().requested_bytes, 0);
    worker.authorize(&stream.next_request()).unwrap();
    assert!(worker.authorize(&read(Some(reference), 1)).is_err());
}

#[test]
fn control_close_and_expiry_revoke_existing_workers_and_pending_output() {
    let temp = crate::test_support::tempdir().unwrap();
    let fixture = Fixture::new(policy(temp.path()));
    let worker = fixture.worker();
    let source = fixture.source();
    drop(fixture.control);
    assert!(worker.authorize(&read(Some(source.clone()), 1)).is_err());
    assert!(worker.record_scan(&source, [b"file".as_slice()]).is_err());
    assert!(worker.authority.check_response(&Response::Ok).is_err());
    worker.authorize(&Request::StopReadStream).unwrap();
    worker
        .authority
        .check_response(&Response::ReadStreamDone)
        .unwrap();
    let mut expired = policy(temp.path());
    expired.deadline = Instant::now() - Duration::from_secs(1);
    let authority = SourceAuthority::new(expired).unwrap();
    assert!(authority.acquire(&ConnectionRole::Control, false).is_err());
}

#[test]
fn hashing_and_metadata_stay_within_the_approved_read_policy() {
    let temp = crate::test_support::tempdir().unwrap();
    let file = temp.path().join("file");
    fs::write(&file, b"approved").unwrap();
    let mut fixture = Fixture::new(policy(&file));
    let hash = Request::FileHash {
        path: b"/unused".to_vec(),
        source: Some(fixture.source()),
        guard: None,
    };
    assert!(matches!(
        fixture.control.file_hash(&mut fixture.ops, &hash).unwrap(),
        Response::FileHash { size: 8, .. }
    ));
    assert!(fixture
        .control
        .authorize(&Request::ConfigurePreservation {
            selection: Default::default(),
            sparse: false,
            destination: true,
        })
        .is_err());
    assert!(fixture
        .control
        .authorize(&Request::ConfigurePreservation {
            selection: crate::inode_metadata::Selection {
                xattrs: true,
                ..Default::default()
            },
            sparse: false,
            destination: false,
        })
        .is_err());
    fs::write(&file, vec![0; 1025]).unwrap();
    assert!(fixture.control.file_hash(&mut fixture.ops, &hash).is_err());
    assert!(fixture
        .control
        .authorize(&read(Some(fixture.source()), 1025))
        .is_err());
}

#[test]
fn checked_whole_file_hash_stops_between_chunks() {
    let temp = crate::test_support::tempdir().unwrap();
    let file = temp.path().join("file");
    fs::write(&file, vec![0; 4 << 20]).unwrap();
    let fixture = Fixture::new(policy(&file));
    let mut ops = FsOps::new();
    ops.initialize_sources(&fixture.roots).unwrap();
    let mut largest = 0;
    let result =
        ops.file_hash_checked(b"/unused", Some(&fixture.source()), None, &mut |_, size| {
            largest = largest.max(size);
            if size > 0 {
                fixture.authority.close();
            }
            fixture
                .authority
                .check_open(&fixture.authority.state.lock().unwrap())
        });
    assert!(result.is_err());
    assert_eq!(largest, 1 << 20);
}

#[test]
fn typed_source_selections_cannot_gain_a_different_read_scope() {
    let directory = crate::test_support::tempdir().unwrap();
    let file = directory.path().join("file");
    fs::write(&file, b"payload").unwrap();
    for (path, kind) in [
        (directory.path(), crate::cli::SourceSelection::File),
        (file.as_path(), crate::cli::SourceSelection::Directory),
        (file.as_path(), crate::cli::SourceSelection::Contents),
    ] {
        let mut policy = policy(path);
        policy.selection_types = vec![kind];
        let request = registration(&policy);
        let authority = SourceAuthority::new(policy).unwrap();
        let control = authority.acquire(&ConnectionRole::Control, false).unwrap();
        assert!(control.register(&mut FsOps::new(), &request).is_err());
        assert!(authority.state.lock().unwrap().roots.is_empty());
    }
    assert_eq!(fs::read(file).unwrap(), b"payload");
}

#[test]
fn overlapping_native_descriptor_estimates_keep_the_live_worker_limit() {
    let directory = crate::test_support::tempdir().unwrap();
    let mut policy = policy(directory.path());
    policy.limits.max_connections = 3; // Two workers and one control.
    let mut request = registration(&policy);
    if let Request::RegisterSourceRoots {
        shared_workers,
        independent_handoff_workers,
        ..
    } = &mut request
    {
        // Native TCP registration estimates both its shared workers and the
        // independent handoffs those same workers may need for SSH fallback.
        *shared_workers = 2;
        *independent_handoff_workers = 2;
    }
    let authority = SourceAuthority::new(policy).unwrap();
    let control = authority.acquire(&ConnectionRole::Control, false).unwrap();
    let mut ops = FsOps::new();
    let Response::SourceRootsRegistered(roots) = control.register(&mut ops, &request).unwrap()
    else {
        panic!("registration failed");
    };
    let role = ConnectionRole::SourceWorker {
        roots,
        send_budget: None,
    };
    let _first = authority.acquire(&role, false).unwrap();
    let _second = authority.acquire(&role, false).unwrap();
    assert!(authority.acquire(&role, false).is_err());
}

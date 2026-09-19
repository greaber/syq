use super::*;
use crate::sched::tests::test_job as pipeline_job;

#[test]
fn seeded_hashes_preserve_selected_positions_and_require_actual_matches() {
    let source = [[1; 32], [2; 32], [3; 32], [4; 32], [5; 32]];
    let selected = [(10, 20), (30, 43)];
    for (hashes, expected) in [
        (
            vec![source[1], source[3], source[4]],
            vec![(0, 10), (20, 30)],
        ),
        // A changed donor block must be sent again, despite the hint.
        (vec![[9; 32], source[3], source[4]], vec![(0, 30)]),
        // A truncated donor returns only a prefix, not hashes shifted left.
        (vec![source[1]], vec![(0, 10), (20, 43)]),
        (vec![], vec![(0, 43)]),
    ] {
        let reused = SeededBasis {
            hashes,
            selected_final: true,
        };
        assert_eq!(
            Worker::different_seeded_ranges(&source, &reused, &selected, 10, 43).unwrap(),
            expected
        );
    }
    let partial = SeededBasis {
        hashes: source.to_vec(),
        selected_final: false,
    };
    assert!(
        Worker::different_seeded_ranges(&source, &partial, &[], 10, 43)
            .unwrap()
            .is_empty()
    );
    let too_many = SeededBasis {
        hashes: source.to_vec(),
        selected_final: true,
    };
    assert!(Worker::different_seeded_ranges(&source, &too_many, &selected, 10, 43).is_err());
}

#[test]
fn source_block_must_match_the_requested_range() {
    assert!(validate_range_reply(4096, 1024, 4096, 1024).is_ok());
    for (off, len) in [
        (0, 1024),
        (8192, 1024),
        (4096, 0),
        (4096, 1023),
        (4096, 1025),
        (u64::MAX, 1024),
    ] {
        assert!(validate_range_reply(4096, 1024, off, len).is_err());
    }
    assert!(validate_range_reply(u64::MAX, 1, u64::MAX, 1).is_err());
}

#[derive(Default)]
struct PipelineState {
    requests: Vec<Request>,
    replies: std::collections::VecDeque<Response>,
    received: usize,
    progress: Option<Arc<Progress>>,
    progress_at_receive: Vec<(u64, u64)>,
    tuning_at_receive: Vec<u64>,
    sent_at_receive: Vec<usize>,
    peer: Option<Arc<Mutex<PipelineState>>>,
    peer_sent_at_receive: Vec<usize>,
    synchronous: bool,
    fail_receive: Option<usize>,
    gate_changes: Vec<(usize, Arc<Gate>, usize)>,
    steal_on_receive: Option<Arc<Sched>>,
    stolen_file: Option<usize>,
    reply_start_wait: Option<std::time::Duration>,
    rtt_us: Option<u64>,
    dead: bool,
    max_pending: usize,
    latency: Option<std::time::Duration>,
    ready: std::collections::VecDeque<std::time::Instant>,
    abort_on_receive: Option<Arc<Sched>>,
}

struct PipelineConn(Arc<Mutex<PipelineState>>);

impl Conn for PipelineConn {
    fn supports_request_pipelining(&self) -> bool {
        {
            let state = self.0.lock().unwrap();
            !state.synchronous
        }
    }
    fn tcp_rtt_us(&self) -> Option<u64> {
        self.0.lock().unwrap().rtt_us
    }
    fn is_dead(&self) -> bool {
        self.0.lock().unwrap().dead
    }
    fn begin_streaming_writes(&mut self) -> Result<()> {
        Ok(())
    }
    fn check_streaming_writes(&mut self) -> Result<()> {
        Ok(())
    }
    fn send(&mut self, request: Request) -> Result<()> {
        let mut state = self.0.lock().unwrap();
        state.requests.push(request);
        if let Some(latency) = state.latency {
            state.ready.push_back(std::time::Instant::now() + latency);
        }
        state.max_pending = state.max_pending.max(state.requests.len() - state.received);
        Ok(())
    }
    fn recv_with_wait(&mut self) -> Result<(Response, std::time::Duration)> {
        let start = std::time::Instant::now();
        let response = self.recv()?;
        let waited = self
            .0
            .lock()
            .unwrap()
            .reply_start_wait
            .unwrap_or_else(|| start.elapsed());
        Ok((response, waited))
    }
    fn recv(&mut self) -> Result<Response> {
        let mut state = self.0.lock().unwrap();
        anyhow::ensure!(!state.dead, "injected dead connection");
        state.received += 1;
        if let Some(progress) = &state.progress {
            let snapshot = (
                progress.bytes_done.load(Relaxed),
                progress.files_done.load(Relaxed),
            );
            let tuning = crate::tune::Meter::files(&**progress);
            state.progress_at_receive.push(snapshot);
            state.tuning_at_receive.push(tuning);
        }
        if let Some(sched) = state.steal_on_receive.take() {
            let Item::File(idx) = sched.next() else {
                panic!("expected unread file group")
            };
            state.stolen_file = Some(idx);
        }
        for (at, gate, active) in &state.gate_changes {
            if *at == state.received {
                gate.set_active(*active);
            }
        }
        let sent = state.requests.len();
        state.sent_at_receive.push(sent);
        if let Some(peer) = &state.peer {
            let sent = peer.lock().unwrap().requests.len();
            state.peer_sent_at_receive.push(sent);
        }
        if state.fail_receive == Some(state.received) {
            state.dead = true;
            bail!("injected connection loss");
        }
        if let Some(ready) = state.ready.pop_front() {
            std::thread::sleep(ready.saturating_duration_since(std::time::Instant::now()));
        }
        if let Some(sched) = state.abort_on_receive.take() {
            sched.abort();
        }
        Ok(state.replies.pop_front().expect("unexpected receive"))
    }
    fn scan(
        &mut self,
        _: &[u8],
        _: Option<&RegisteredPath>,
        _: bool,
        _: &[String],
        _: bool,
        _: &mut dyn FnMut(Vec<Entry>) -> Result<()>,
        _: &mut dyn FnMut(Vec<PathBytes>) -> Result<()>,
        _: &mut dyn FnMut(String),
    ) -> Result<()> {
        unreachable!()
    }
    fn native_remove(
        &mut self,
        _: Option<&[u8]>,
        _: Option<&[u8]>,
        _: &[NativeRemoveSelection],
        _: bool,
        _: bool,
        _: usize,
        _: &mut dyn FnMut(Vec<String>) -> Result<()>,
        _: &mut dyn FnMut(Vec<NativeRemoveOutcome>) -> Result<()>,
    ) -> Result<()> {
        unreachable!()
    }
}

fn pipeline_snapshot(job: FileJob) -> WorkerJob {
    WorkerJob {
        data: crate::sched::SnapshotData::Shared(Arc::new(job.data)),
        dst_entry: job.dst_entry.map(Arc::new),
    }
}

fn pipeline_ranges(spans: &[(u64, u64)]) -> (Arc<Sched>, RangeHandle, FileJob) {
    let sched = Arc::new(Sched::new(512, 8192));
    let job = pipeline_job(b"source", spans.last().unwrap().1);
    sched.push_file(job.clone());
    sched.scan_done();
    assert!(matches!(sched.next(), Item::File(0)));
    let handle = sched.ranges_ready(0, spans.to_vec()).unwrap();
    (sched, handle, job)
}

fn pipeline_worker(
    sched: &Arc<Sched>,
    src: &Arc<Mutex<PipelineState>>,
    dst: &Arc<Mutex<PipelineState>>,
    streaming: bool,
) -> Worker {
    let opts = Arc::new(Opts {
        local_copy_fd_budget: true,
        hash_policy: Default::default(),
        mapping_expected_hashes: Default::default(),
        block: 512,
        tuning: crate::transfer_tuning::TransferTuning {
            copy_path: (!streaming).then_some(crate::transfer_tuning::CopyPath::Ranges),
            pipeline_depth: (!streaming).then_some(4),
            ..Default::default()
        },
        benchmark: None,
        flags: 0,
        recursive: true,
        links: false,
        perms: false,
        devices: false,
        checksum: false,
        precise_mtime: true,
        verify_only: false,
        inplace: false,
        same_host: false,
        allow_sequential_nfs_fallback: false,
        dst_remote: true,
        restricted_receiver: false,
        dry_run: false,
        dry_run_metadata_files: AtomicU64::new(0),
        quiet: true,
        verbose: 0,
        umask: 0,
        copy_id: [0; 16],
        ignore: Vec::new(),
        delete: false,
        delete_excluded: false,
        max_delete: None,
        update: false,
        ignore_existing: false,
        preserve_existing_directory_metadata: false,
        existing: false,
        operator_symlink_policy: OperatorSymlinkPolicy::Refuse,
        max_size: None,
        min_size: None,
    });
    Worker {
        id: 0,
        src: Box::new(PipelineConn(src.clone())),
        dst: Box::new(PipelineConn(dst.clone())),
        sched: sched.clone(),
        progress: Progress::new(false, false, None, false),
        opts,
        bwlimit: None,
        gate: Gate::new(1),
        observation: None,
        benchmark: Default::default(),
        fast_batch_files: 1,
        setup_elapsed: std::time::Duration::ZERO,
    }
}

#[test]
fn prune_index_preserves_root_boundaries() {
    let seen: std::collections::HashMap<_, _> = [
        "dst",
        "dst/file",
        "dst/sub",
        "dst/sub/file",
        "dst/submarine/file",
        "dst2/file",
        "/file",
    ]
    .into_iter()
    .map(|p| (p.as_bytes().to_vec(), Claim::Leaf))
    .collect();
    let mut sorted: Vec<_> = seen.keys().collect();
    sorted.sort_unstable();
    for root in [
        b"dst".as_slice(),
        b"dst/",
        b"dst/sub",
        b"dst/sub/",
        b"missing",
        b"/",
        b"",
    ] {
        assert_eq!(
            PruneWalk::new(&seen, root, None).unmatched,
            PruneWalk::new(&seen, root, Some(&sorted)).unmatched
        );
    }
}

#[test]
#[ignore = "manual planner timing; run with --release --ignored --nocapture"]
fn prune_index_timing() {
    use std::time::Instant;
    let count = 200_000;
    for roots in [1, 2, 10, 16, 32, 100] {
        let seen: std::collections::HashMap<_, _> = (0..count)
            .map(|i| {
                (
                    format!("destination/root-{:03}/directory/file-{i:08}", i % roots).into_bytes(),
                    Claim::Leaf,
                )
            })
            .collect();
        let root_paths: Vec<_> = (0..roots)
            .map(|i| format!("destination/root-{i:03}").into_bytes())
            .collect();
        let start = Instant::now();
        for root in &root_paths {
            std::hint::black_box(PruneWalk::new(&seen, root, None));
        }
        let original = start.elapsed();
        let start = Instant::now();
        let mut sorted: Vec<_> = seen.keys().collect();
        sorted.sort_unstable();
        let sorting = start.elapsed();
        for root in &root_paths {
            std::hint::black_box(PruneWalk::new(&seen, root, Some(&sorted)));
        }
        eprintln!(
            "claims={count} roots={roots} scan={original:?} index_total={:?} sorting={sorting:?}",
            start.elapsed()
        );
    }
}

#[test]
#[ignore = "manual simulated-latency timing; run with --ignored --nocapture"]
fn prune_pipeline_timing() {
    let directory = crate::test_support::tempdir().unwrap();
    let candidate = crate::fsops::lstat_entry(b"extra".to_vec(), directory.path()).unwrap();
    let seen = (0..4096)
        .map(|i| (format!("dst/file-{i}").into_bytes(), Claim::Leaf))
        .collect();
    let mut walk = PruneWalk::new(&seen, b"dst", None);
    walk.push(candidate, b"dst", &[]);
    for synchronous in [true, false] {
        let state = Arc::new(Mutex::new(PipelineState {
            synchronous,
            latency: Some(std::time::Duration::from_millis(20)),
            ..Default::default()
        }));
        state
            .lock()
            .unwrap()
            .replies
            .extend((0..8).map(|_| Response::Stats(vec![None; 512])));
        let start = std::time::Instant::now();
        lookup_prune_aliases(&mut PipelineConn(state.clone()), &walk, None).unwrap();
        eprintln!(
            "simulated RTT=20ms paths=4096 sequential={synchronous} elapsed={:?}",
            start.elapsed()
        );
        assert_eq!(
            state.lock().unwrap().max_pending,
            if synchronous { 1 } else { 4 }
        );
    }
}

#[test]
fn prune_walk_drops_synced_entries_and_skips_empty_candidate_lookups() {
    let directory = crate::test_support::tempdir().unwrap();
    let file = directory.path().join("file");
    std::fs::write(&file, b"contents").unwrap();
    let template = crate::fsops::lstat_entry(Vec::new(), &file).unwrap();
    let seen: std::collections::HashMap<_, _> = (0..10_000)
        .map(|index| (format!("dst/file-{index}").into_bytes(), Claim::Leaf))
        .collect();
    let mut walk = PruneWalk::new(&seen, b"dst", None);
    for index in 0..9_000 {
        let mut entry = template.clone();
        entry.path = format!("file-{index}").into_bytes();
        walk.push(entry, b"dst", &[]);
        assert!(walk.entries.is_empty(), "exact matches must not accumulate");
    }
    walk.finish_scan(b"dst");
    assert_eq!(walk.unmatched.len(), 1_000);
    let state = Arc::new(Mutex::new(PipelineState::default()));
    let aliases = lookup_prune_aliases(&mut PipelineConn(state.clone()), &walk, None).unwrap();
    assert!(aliases.is_empty());
    assert!(state.lock().unwrap().requests.is_empty());
}

#[test]
fn prune_walk_keeps_shields_recovery_and_nested_scopes() {
    let directory = crate::test_support::tempdir().unwrap();
    let mut entry = crate::fsops::lstat_entry(Vec::new(), directory.path()).unwrap();
    let seen = [(b"dst/blocked".to_vec(), Claim::Weak)]
        .into_iter()
        .collect();
    let mut walk = PruneWalk::new(&seen, b"dst", None);
    // The child deliberately arrives before its claimed directory.
    for path in [
        "blocked/child",
        "blocked",
        "nested/extra",
        "old/.syq-swap-123-4/data",
        "extra",
    ] {
        entry.path = path.as_bytes().to_vec();
        walk.push(entry.clone(), b"dst", &[b"dst/nested".to_vec()]);
    }
    walk.finish_scan(b"dst");
    assert!(walk.unmatched.is_empty());
    assert_eq!(walk.entries.len(), 1);
    assert_eq!(walk.entries[0].path, b"dst/extra");
    assert!(walk.recovery_parents.contains(b"dst/old".as_slice()));
}

#[test]
fn prune_alias_lookups_are_bounded_and_keep_only_candidate_identities() {
    let directory = crate::test_support::tempdir().unwrap();
    let file = directory.path().join("file");
    std::fs::write(&file, b"contents").unwrap();
    let mut candidate = crate::fsops::lstat_entry(b"stored-name".to_vec(), &file).unwrap();
    candidate.ino = 42;
    let seen: std::collections::HashMap<_, _> = (0..3_073)
        .map(|index| (format!("dst/claim-{index}").into_bytes(), Claim::Leaf))
        .collect();
    let mut walk = PruneWalk::new(&seen, b"dst", None);
    walk.push(candidate.clone(), b"dst", &[]);
    let mut unrelated = candidate.clone();
    unrelated.ino = 43;
    let state = Arc::new(Mutex::new(PipelineState::default()));
    state.lock().unwrap().replies.extend([
        Response::Stats(vec![Some(unrelated); 512]),
        Response::Stats(vec![None; 512]),
        Response::Stats(vec![None; 512]),
        Response::Stats(vec![None; 512]),
        Response::Stats(vec![None; 512]),
        Response::Stats(vec![None; 512]),
        Response::Stats(vec![Some(candidate.clone())]),
    ]);
    let aliases = lookup_prune_aliases(&mut PipelineConn(state.clone()), &walk, None).unwrap();
    assert_eq!(aliases.len(), 1);
    assert_eq!(aliases[&(candidate.dev, candidate.ino)], Claim::Leaf);
    assert_eq!(state.lock().unwrap().requests.len(), 7);
    assert_eq!(state.lock().unwrap().max_pending, 4);
    assert!(state.lock().unwrap().replies.is_empty());

    let malformed = Arc::new(Mutex::new(PipelineState::default()));
    malformed.lock().unwrap().replies.extend([
        Response::Stats(vec![]),
        Response::Stats(vec![None; 512]),
        Response::Stats(vec![None; 512]),
        Response::Stats(vec![None; 512]),
    ]);
    assert!(lookup_prune_aliases(&mut PipelineConn(malformed.clone()), &walk, None).is_err());
    assert!(malformed.lock().unwrap().replies.is_empty());
}

#[test]
fn cancelled_range_drains_without_reporting_or_publishing_an_innocent_file() {
    let (sched, range, _) = pipeline_ranges(&[(0, 4096)]);
    let src = Arc::new(Mutex::new(PipelineState {
        abort_on_receive: Some(sched.clone()),
        ..Default::default()
    }));
    for i in 0..4 {
        let data = vec![0; 512];
        src.lock().unwrap().replies.push_back(Response::Block {
            off: i * 512,
            hash: content_digest(&data),
            data,
        });
    }
    let dst = Arc::new(Mutex::new(PipelineState::default()));
    dst.lock().unwrap().replies.push_back(Response::Ok);
    let mut worker = pipeline_worker(&sched, &src, &dst, false);
    worker.transfer_range(&range, &mut 0).unwrap();
    assert!(!sched.range_done(&range));
    worker.finish_file(0).unwrap();
    assert!(!sched.is_failed(0));
    assert!(src.lock().unwrap().replies.is_empty());
    let destination = dst.lock().unwrap();
    assert!(destination.replies.is_empty());
    assert!(destination
        .requests
        .iter()
        .all(|r| matches!(r, Request::WriteRange { .. })));
    assert_eq!(worker.progress.errors.load(Relaxed), 0);
}

#[test]
fn range_mismatch_aborts_worker_with_both_pipelines_outstanding() {
    // Exercise both callers of transfer_range: initial file work and a
    // queued range. Another file is ready when the malicious reply arrives.
    for streaming in [false, true] {
        for queued_range in [false, true] {
            for wrong_length in [false, true] {
                let sched = Arc::new(Sched::new(512, 8192));
                let job = pipeline_job(b"first", 4096);
                sched.push_file(job.clone());
                let mut next = job;
                next.src = b"second".to_vec();
                next.dst = b"second-dst".to_vec();
                sched.push_file(next);
                sched.scan_done();
                if queued_range {
                    assert!(matches!(sched.next(), Item::File(0)));
                    let range = sched.ranges_ready(0, vec![(0, 4096)]).unwrap();
                    sched.retry_range(&range, 0);
                }
                let src = Arc::new(Mutex::new(PipelineState::default()));
                src.lock().unwrap().replies.push_back(Response::Ok); // ConfigureHashing
                if streaming {
                    src.lock().unwrap().replies.push_back(Response::Ok);
                }
                for i in 0..5 {
                    let data = vec![0; if i == 1 && wrong_length { 511 } else { 512 }];
                    src.lock().unwrap().replies.push_back(Response::Block {
                        off: if i == 1 && !wrong_length {
                            999
                        } else {
                            i * 512
                        },
                        hash: content_digest(&data),
                        data,
                    });
                }
                let dst = Arc::new(Mutex::new(PipelineState::default()));
                dst.lock().unwrap().replies.push_back(Response::Ok); // ConfigureHashing
                if !queued_range {
                    dst.lock()
                        .unwrap()
                        .replies
                        .push_back(Response::Prepared(Preparation::default()));
                }
                dst.lock().unwrap().replies.push_back(Response::Ok);
                let mut worker = pipeline_worker(&sched, &src, &dst, streaming);
                let error = worker.run().unwrap_err();
                assert!(error.is::<RangeReplyMismatch>(), "{error:#}");
                assert!(sched.is_aborted());
                assert!(
                    !worker.transport_dead(),
                    "protocol failure, not a lost socket"
                );
                let source = src.lock().unwrap();
                assert_eq!(source.received, 3 + usize::from(streaming));
                assert!(matches!(source.requests[0], Request::ConfigureHashing(_)));
                assert_eq!(source.replies.len(), 3);
                if streaming {
                    assert_eq!(source.requests.len(), 2);
                    assert!(
                        matches!(&source.requests[1], Request::ReadStream(stream) if stream.path == b"first")
                    );
                } else {
                    assert_eq!(source.requests.len(), 6);
                    assert!(source.requests[1..].iter().all(|request| matches!(
                        request, Request::ReadRange { path, .. } if path == b"first"
                    )));
                }
                let destination = dst.lock().unwrap();
                assert_eq!(destination.received, 1 + usize::from(!queued_range));
                assert!(matches!(
                    destination.requests[0],
                    Request::ConfigureHashing(_)
                ));
                assert_eq!(
                    destination.replies.len(),
                    1,
                    "write ack remains outstanding"
                );
                let writes: Vec<_> = destination
                    .requests
                    .iter()
                    .filter(|request| matches!(request, Request::WriteRange { .. }))
                    .collect();
                assert_eq!(writes.len(), 1);
                assert!(
                    matches!(writes[0], Request::WriteRange { off: 0, path, .. } if path == b"first-dst")
                );
                assert_eq!(destination.requests.len(), 2 + usize::from(!queued_range));
            }
        }
    }
}

#[test]
fn whole_file_groups_overlap_and_drain_both_endpoint_windows() {
    for (source_sync, destination_sync) in [(false, false), (true, false), (false, true)] {
        for failure in [
            "none",
            "read-file",
            "write-file",
            "read-error",
            "write-error",
            "source-drop",
            "destination-drop",
        ] {
            let jobs: Vec<_> = (0..8)
                .map(|i| pipeline_snapshot(pipeline_job(format!("file{i}").as_bytes(), 512)))
                .collect();
            let groups = [0..2, 2..4, 4..6, 6..8];
            let dst = Arc::new(Mutex::new(PipelineState {
                synchronous: destination_sync,
                fail_receive: (failure == "destination-drop").then_some(2),
                ..Default::default()
            }));
            let src = Arc::new(Mutex::new(PipelineState {
                synchronous: source_sync,
                peer: Some(dst.clone()),
                fail_receive: (failure == "source-drop").then_some(3),
                ..Default::default()
            }));
            for group in 0..4 {
                let mut blocks = Vec::new();
                for file in 0..2 {
                    let data = vec![group as u8; 512];
                    blocks.push(if failure == "read-file" && group == 1 && file == 0 {
                        Err("injected file read error".into())
                    } else {
                        Ok(SmallBlock {
                            hash: content_digest(&data),
                            data,
                        })
                    });
                }
                src.lock()
                    .unwrap()
                    .replies
                    .push_back(if failure == "read-error" && group == 1 {
                        Response::Err("injected batch read error".into())
                    } else {
                        Response::SmallBlocks(blocks)
                    });
                let count = if failure == "read-file" && group == 1 {
                    1
                } else {
                    2
                };
                let applied = (0..count)
                    .map(|file| {
                        (failure == "write-file" && group == 1 && file == 0)
                            .then(|| "injected file write error".into())
                    })
                    .collect();
                dst.lock()
                    .unwrap()
                    .replies
                    .push_back(if failure == "write-error" && group == 1 {
                        Response::Err("injected batch write error".into())
                    } else {
                        Response::Applied(applied)
                    });
            }
            let mut worker = pipeline_worker(&Arc::new(Sched::new(512, 8192)), &src, &dst, false);
            let mut results = (0..jobs.len()).map(|_| None).collect::<Vec<_>>();
            let result = worker.transfer_small_batches(&jobs, groups.into_iter(), &mut results);
            if matches!(failure, "none" | "read-file" | "write-file") {
                result.unwrap();
                assert_eq!(results.len(), 8);
                for (i, result) in results.iter().enumerate() {
                    assert_eq!(
                        result.as_ref().expect("completed file").is_err(),
                        failure != "none" && i == 2,
                        "{failure} file{i}: {result:?}"
                    );
                }
                let source = src.lock().unwrap();
                let destination = dst.lock().unwrap();
                assert_eq!(
                    source.peer_sent_at_receive,
                    [0, 1, 2, 3],
                    "write each group before receiving the next"
                );
                assert_eq!(source.sent_at_receive[0], if source_sync { 1 } else { 4 });
                assert_eq!(
                    destination.sent_at_receive[0],
                    if destination_sync { 1 } else { 4 }
                );
            } else {
                assert_eq!(
                    result.is_err(),
                    worker.transport_dead(),
                    "{failure}: {result:?}"
                );
                if !worker.transport_dead() {
                    assert!(
                        results[..2].iter().all(|r| matches!(r, Some(Ok(())))),
                        "earlier acknowledged files survive {failure}: {results:?}"
                    );
                    assert!(
                        results[2..4].iter().all(|r| matches!(r, Some(Err(_)))),
                        "only the failed group is failed: {failure}: {results:?}"
                    );
                    let source = src.lock().unwrap();
                    let destination = dst.lock().unwrap();
                    assert_eq!(source.received, source.requests.len(), "{failure}");
                    assert_eq!(
                        destination.received,
                        destination.requests.len(),
                        "{failure}"
                    );
                }
            }
        }
    }
}

#[test]
fn small_batch_reports_acknowledged_bytes_and_rolls_back_uncertain_credit() {
    for failure in [
        "none",
        "destination-drop",
        "stat-drop",
        "changed",
        "changed-retry",
    ] {
        let sched = Arc::new(Sched::new(512, 8192));
        let jobs: Vec<_> = (0..6)
            .map(|i| {
                let mut job = pipeline_job(format!("file{i}").as_bytes(), 1 << 20);
                if failure == "changed" {
                    job.attempt = MAX_ATTEMPTS - 1;
                }
                job
            })
            .collect();
        for job in &jobs {
            sched.push_file(job.clone());
        }
        sched.scan_done();
        assert!(matches!(sched.next(), Item::File(0)));
        assert_eq!(sched.begin_fast_batch(1, 6), 6);
        let mut batch = vec![0];
        batch.extend(sched.take_small(1 << 20, 5, u64::MAX));
        sched.mark_fast(5);
        let src = Arc::new(Mutex::new(PipelineState {
            fail_receive: (failure == "stat-drop").then_some(7),
            ..Default::default()
        }));
        let dst = Arc::new(Mutex::new(PipelineState {
            fail_receive: (failure == "destination-drop").then_some(6),
            ..Default::default()
        }));
        for _ in 0..6 {
            let data = vec![0; 1 << 20];
            src.lock()
                .unwrap()
                .replies
                .push_back(Response::SmallBlocks(vec![Ok(SmallBlock {
                    hash: content_digest(&data),
                    data,
                })]));
            dst.lock()
                .unwrap()
                .replies
                .push_back(Response::Applied(vec![None]));
        }
        let mut entries: Vec<_> = batch
            .iter()
            .map(|&idx| Some(jobs[idx].entry.clone()))
            .collect();
        if failure.starts_with("changed") {
            entries[0].as_mut().unwrap().mtime += 1;
        }
        src.lock()
            .unwrap()
            .replies
            .push_back(Response::Stats(entries));
        let mut worker = pipeline_worker(&sched, &src, &dst, false);
        // Other workers' progress must survive rollback of this batch.
        worker.progress.add_bytes(123);
        worker.progress.add_files(7);
        src.lock().unwrap().progress = Some(worker.progress.clone());
        dst.lock().unwrap().progress = Some(worker.progress.clone());
        let result = worker.fast_batch(&mut batch);
        let dropped = failure.ends_with("drop");
        assert_eq!(result.is_err(), dropped, "{failure}: {result:?}");
        let expected_files = if dropped {
            0
        } else if failure.starts_with("changed") {
            5
        } else {
            6
        };
        assert_eq!(
            worker.progress.bytes_done.load(Relaxed),
            123 + (expected_files << 20),
            "{failure}"
        );
        assert_eq!(
            worker.progress.files_done.load(Relaxed),
            7 + expected_files,
            "{failure}"
        );
        let acknowledged = if failure == "destination-drop" { 5 } else { 6 };
        assert_eq!(
            crate::tune::Meter::files(&*worker.progress),
            7 + acknowledged
        );
        for (i, &files) in dst.lock().unwrap().tuning_at_receive.iter().enumerate() {
            assert_eq!(files, 7 + i as u64, "{failure}: tuner before ack {i}");
        }
        // Retrying uncertain files must not produce a second burst of credit.
        worker
            .progress
            .add_tuning_files(acknowledged - expected_files);
        assert_eq!(
            crate::tune::Meter::files(&*worker.progress),
            7 + acknowledged
        );
        worker.progress.add_files(1);
        assert_eq!(
            crate::tune::Meter::files(&*worker.progress),
            8 + acknowledged
        );
        let snapshots = &dst.lock().unwrap().progress_at_receive;
        for (i, &(bytes, files)) in snapshots.iter().enumerate() {
            assert_eq!(bytes, 123 + ((i as u64) << 20), "{failure}: ack {i}");
            assert_eq!(files, 7, "no file completes before the source recheck");
        }
        if !dropped {
            assert_eq!(
                src.lock().unwrap().progress_at_receive.last(),
                Some(&(123 + (6 << 20), 7))
            );
        }
        assert_eq!(
            jobs[0].done.load(Relaxed),
            if expected_files == 6 { 1 << 20 } else { 0 }
        );
        assert_eq!(sched.is_failed(0), failure == "changed");
        if failure == "changed-retry" {
            assert_eq!(sched.jobs.lock().unwrap()[0].attempt, 1);
        }
    }
}

#[test]
fn small_batch_tuning_counts_empty_files_but_not_failed_publications() {
    use crate::tune::Meter;
    let sched = Arc::new(Sched::new(512, 8192));
    let src = Arc::new(Mutex::new(PipelineState::default()));
    let dst = Arc::new(Mutex::new(PipelineState::default()));
    let mut worker = pipeline_worker(&sched, &src, &dst, false);
    let jobs = [0, 8, 0]
        .into_iter()
        .enumerate()
        .map(|(i, size)| {
            let job = pipeline_job(format!("file{i}").as_bytes(), size);
            sched.push_file(job);
            worker.job(i)
        })
        .collect::<Vec<_>>();
    dst.lock()
        .unwrap()
        .replies
        .push_back(Response::Applied(vec![
            None,
            Some(crate::fsops::wire_error(&anyhow::anyhow!(
                "publication failed"
            ))),
            None,
        ]));
    let mut results = vec![None, None, None];
    assert!(worker
        .receive_small_batch(vec![0, 1, 2], &jobs, &mut results)
        .unwrap());
    assert_eq!(Meter::files(&*worker.progress), 2);
    assert_eq!(Meter::bytes(&*worker.progress), 0);
    assert_eq!(worker.progress.files_done.load(Relaxed), 0);
    assert!(results[1].as_ref().unwrap().is_err());

    dst.lock()
        .unwrap()
        .replies
        .push_back(Response::Applied(vec![]));
    assert!(!worker
        .receive_small_batch(vec![1], &jobs, &mut results)
        .unwrap());
    assert_eq!(
        Meter::files(&*worker.progress),
        2,
        "malformed replies earn no credit"
    );
}

#[test]
fn later_batch_read_error_keeps_publications_and_requeues_unwritten_files() {
    let sched = Arc::new(Sched::new(512, 8192));
    let jobs: Vec<_> = (0..8)
        .map(|i| pipeline_job(format!("file{i}").as_bytes(), 1 << 20))
        .collect();
    for job in &jobs {
        sched.push_file(job.clone());
    }
    sched.scan_done();
    assert!(matches!(sched.next(), Item::File(0)));
    assert_eq!(sched.begin_fast_batch(1, 8), 8);
    let mut batch = vec![0];
    batch.extend(sched.take_small(1 << 20, 7, u64::MAX));
    sched.mark_fast(7);
    let original = batch.clone();
    let src = Arc::new(Mutex::new(PipelineState {
        synchronous: true,
        ..Default::default()
    }));
    let dst = Arc::new(Mutex::new(PipelineState::default()));
    for _ in 0..4 {
        let data = vec![42; 1 << 20];
        src.lock()
            .unwrap()
            .replies
            .push_back(Response::SmallBlocks(vec![Ok(SmallBlock {
                hash: content_digest(&data),
                data,
            })]));
        dst.lock()
            .unwrap()
            .replies
            .push_back(Response::Applied(vec![None]));
    }
    src.lock()
        .unwrap()
        .replies
        .push_back(Response::EndpointError(WireError {
            message: "injected read denial after publishing earlier files".into(),
            io_kind: Some(crate::proto::WireIoKind::PermissionDenied),
            raw_os_error: None,
        }));
    src.lock().unwrap().replies.push_back(Response::Stats(
        original[..4]
            .iter()
            .map(|&idx| Some(jobs[idx].entry.clone()))
            .collect(),
    ));
    let mut worker = pipeline_worker(&sched, &src, &dst, false);
    worker.fast_batch(&mut batch).unwrap();
    assert_eq!(batch, original);
    assert_eq!(worker.progress.files_done.load(Relaxed), 4);
    assert_eq!(worker.progress.bytes_done.load(Relaxed), 4 << 20);
    assert_eq!(worker.progress.errors.load(Relaxed), 1);
    for &idx in &original[..4] {
        assert_eq!(jobs[idx].done.load(Relaxed), 1 << 20);
        assert!(!sched.is_failed(idx));
    }
    assert!(sched.is_failed(original[4]));
    let source = src.lock().unwrap();
    let Some(Request::StatMany { paths, .. }) = source.requests.last() else {
        panic!("source recheck");
    };
    assert_eq!(
        paths,
        &original[..4]
            .iter()
            .map(|&idx| jobs[idx].src.clone())
            .collect::<Vec<_>>()
    );
    drop(source);
    let destination = dst.lock().unwrap();
    assert_eq!(
        destination.received, 4,
        "drained acknowledgments remain successful"
    );
    drop(destination);
    sched.complete_fast_batch(batch.len());
    let mut remaining: std::collections::BTreeSet<_> = original[5..].iter().copied().collect();
    while !remaining.is_empty() {
        let Item::File(idx) = sched.next() else {
            panic!("unwritten file was not requeued");
        };
        assert!(remaining.remove(&idx));
        assert!(!sched.is_failed(idx));
        assert!(sched.ranges_ready(idx, vec![]).is_none());
    }
    assert!(sched.finished());
}

#[test]
fn stolen_file_groups_are_excluded_from_results_and_transport_retries() {
    for failure in ["none", "source-drop", "destination-drop"] {
        let sched = Arc::new(Sched::new(512, 8192));
        let jobs: Vec<_> = (0..12)
            .map(|i| pipeline_job(format!("file{i}").as_bytes(), 256 << 10))
            .collect();
        for job in &jobs {
            sched.push_file(job.clone());
        }
        sched.scan_done();
        assert!(matches!(sched.next(), Item::File(0)));
        assert_eq!(sched.begin_fast_batch(1, 12), 12);
        let mut batch = vec![0];
        batch.extend(sched.take_small(256 << 10, 11, u64::MAX));
        let owned = batch[..8].to_vec();
        let stolen = batch[8];
        let siblings = batch[9..].to_vec();
        sched.mark_fast(11);
        let src = Arc::new(Mutex::new(PipelineState {
            synchronous: true,
            steal_on_receive: Some(sched.clone()),
            fail_receive: (failure == "source-drop").then_some(2),
            ..Default::default()
        }));
        let dst = Arc::new(Mutex::new(PipelineState {
            fail_receive: (failure == "destination-drop").then_some(1),
            ..Default::default()
        }));
        for _ in 0..2 {
            src.lock().unwrap().replies.push_back(Response::SmallBlocks(
                (0..4)
                    .map(|_| {
                        let data = vec![0; 256 << 10];
                        Ok(SmallBlock {
                            hash: content_digest(&data),
                            data,
                        })
                    })
                    .collect(),
            ));
            dst.lock()
                .unwrap()
                .replies
                .push_back(Response::Applied(vec![None; 4]));
        }
        src.lock().unwrap().replies.push_back(Response::Stats(
            owned
                .iter()
                .map(|&idx| Some(jobs[idx].entry.clone()))
                .collect(),
        ));
        let mut worker = pipeline_worker(&sched, &src, &dst, false);
        let result = worker.fast_batch(&mut batch);
        assert_eq!(result.is_ok(), failure == "none", "{failure}: {result:?}");
        assert_eq!(src.lock().unwrap().stolen_file, Some(stolen));
        assert_eq!(batch, owned);
        assert_eq!(
            worker.progress.bytes_done.load(Relaxed),
            if failure == "none" { 2 << 20 } else { 0 }
        );
        assert_eq!(
            worker.progress.files_done.load(Relaxed),
            if failure == "none" { 8 } else { 0 }
        );
        if failure == "none" {
            let source = src.lock().unwrap();
            let Some(Request::StatMany { paths, .. }) = source.requests.last() else {
                panic!("source recheck")
            };
            assert_eq!(
                paths,
                &owned
                    .iter()
                    .map(|&idx| jobs[idx].src.clone())
                    .collect::<Vec<_>>()
            );
        }
        sched.complete_fast_batch(batch.len());
        if result.is_err() {
            for idx in batch {
                sched.requeue(idx);
            }
        }
        // The peer owns the first file of the stolen group. Its siblings were returned
        // to the file queue; no retry may duplicate that ownership.
        assert!(sched.ranges_ready(stolen, vec![]).is_none());
        let mut expected: std::collections::BTreeSet<_> = siblings.into_iter().collect();
        if failure != "none" {
            expected.extend(owned);
        }
        while !expected.is_empty() {
            let Item::File(idx) = sched.next() else {
                panic!("expected queued file")
            };
            assert!(expected.remove(&idx), "duplicate or stolen file {idx}");
            assert!(sched.ranges_ready(idx, vec![]).is_none());
        }
        assert!(sched.finished());
    }
}

#[test]
fn stalled_source_drains_read_ahead_before_claiming_more_file_groups() {
    // Inject reply-start waits so scheduling delays cannot change which
    // side of the stall allowance a case exercises.
    for (rtt_us, setup_ms, reply_wait_ms, expected) in [
        (None, 0, 125, [4, 4, 4, 4, 5, 6, 7, 8]),
        (Some(10_000), 0, 125, [4, 5, 6, 7, 8, 8, 8, 8]),
        (None, 200, 125, [4, 5, 6, 7, 8, 8, 8, 8]),
        // Payload time does not contribute to the reported reply-start wait.
        (None, 0, 0, [4, 5, 6, 7, 8, 8, 8, 8]),
    ] {
        let jobs: Vec<_> = (0..8)
            .map(|i| pipeline_snapshot(pipeline_job(format!("file{i}").as_bytes(), 512)))
            .collect();
        let src = Arc::new(Mutex::new(PipelineState {
            rtt_us,
            reply_start_wait: Some(std::time::Duration::from_millis(reply_wait_ms)),
            ..Default::default()
        }));
        let dst = Arc::new(Mutex::new(PipelineState::default()));
        for _ in &jobs {
            let data = vec![0; 512];
            src.lock()
                .unwrap()
                .replies
                .push_back(Response::SmallBlocks(vec![Ok(SmallBlock {
                    hash: content_digest(&data),
                    data,
                })]));
            dst.lock()
                .unwrap()
                .replies
                .push_back(Response::Applied(vec![None]));
        }
        let mut worker = pipeline_worker(&Arc::new(Sched::new(512, 8192)), &src, &dst, false);
        worker.gate.set_active(2);
        worker.setup_elapsed = std::time::Duration::from_millis(setup_ms);
        let mut results = (0..jobs.len()).map(|_| None).collect::<Vec<_>>();
        worker
            .transfer_small_batches(&jobs, (0..8).map(|i| i..i + 1), &mut results)
            .unwrap();
        assert!(results.iter().all(|r| matches!(r, Some(Ok(())))));
        assert_eq!(src.lock().unwrap().sent_at_receive, expected);
    }
}

#[test]
fn empty_file_groups_need_no_source_reads() {
    let jobs = [pipeline_job(b"empty1", 0), pipeline_job(b"empty2", 0)].map(pipeline_snapshot);
    let src = Arc::new(Mutex::new(PipelineState::default()));
    let dst = Arc::new(Mutex::new(PipelineState::default()));
    dst.lock()
        .unwrap()
        .replies
        .push_back(Response::Applied(vec![None, None]));
    let mut worker = pipeline_worker(&Arc::new(Sched::new(512, 8192)), &src, &dst, false);
    let algorithm = crate::hashing::HashAlgorithm::Sha256;
    Arc::get_mut(&mut worker.opts)
        .unwrap()
        .hash_policy
        .algorithm = algorithm;
    let mut results = (0..jobs.len()).map(|_| None).collect::<Vec<_>>();
    worker
        .transfer_small_batches(&jobs, std::iter::once(0..2), &mut results)
        .unwrap();
    assert!(results.iter().all(|r| matches!(r, Some(Ok(())))));
    assert!(src.lock().unwrap().requests.is_empty());
    let destination = dst.lock().unwrap();
    let [Request::PutSmallBatch(puts)] = destination.requests.as_slice() else {
        panic!("expected one whole-file write batch")
    };
    assert!(puts
        .iter()
        .all(|put| put.data.is_empty() && put.hash == algorithm.hash(&[])));
}

#[test]
fn new_file_batch_limit_is_independent_of_comparison_blocks() {
    let sched = Arc::new(Sched::new(64 << 10, 32 << 20));
    let mut worker = pipeline_worker(&sched, &Default::default(), &Default::default(), false);
    let opts = Arc::get_mut(&mut worker.opts).unwrap();
    opts.block = 64 << 10;
    opts.tuning.request_size = Some(4 << 20);
    assert_eq!(fast_file_size_limit(opts, None), 4 << 20);
    opts.tuning.batch_bytes = Some(1 << 20);
    assert_eq!(fast_file_size_limit(opts, None), 1 << 20);
    opts.tuning.request_size = None;
    assert_eq!(fast_file_size_limit(opts, None), 64 << 10);
}

#[test]
fn scattered_ranges_pipeline_and_recover_with_bounded_ownership() {
    for (source_sync, destination_sync) in [(false, false), (true, false), (false, true)] {
        for failure in [
            "none",
            "source-error",
            "destination-error",
            "source-drop",
            "destination-drop",
            "mismatch",
        ] {
            let (sched, h, _) =
                pipeline_ranges(&[(0, 512), (1024, 1536), (2048, 2560), (3072, 3584)]);
            let src = Arc::new(Mutex::new(PipelineState {
                synchronous: source_sync,
                ..Default::default()
            }));
            let dst = Arc::new(Mutex::new(PipelineState {
                synchronous: destination_sync,
                ..Default::default()
            }));
            for (i, off) in [0, 1024, 2048, 3072].into_iter().enumerate() {
                let data = vec![i as u8; 512];
                src.lock()
                    .unwrap()
                    .replies
                    .push_back(if failure == "source-error" && i == 1 {
                        Response::Err("injected source error".into())
                    } else {
                        Response::Block {
                            off: if failure == "mismatch" && i == 1 {
                                999
                            } else {
                                off
                            },
                            hash: content_digest(&data),
                            data,
                        }
                    });
                dst.lock().unwrap().replies.push_back(
                    if failure == "destination-error" && i == 0 {
                        Response::Err("injected write error".into())
                    } else {
                        Response::Ok
                    },
                );
            }
            if failure == "source-drop" {
                src.lock().unwrap().fail_receive = Some(2);
            }
            if failure == "destination-drop" {
                dst.lock().unwrap().fail_receive = Some(1);
            }
            let mut worker = pipeline_worker(&sched, &src, &dst, false);

            let mut credited = 0;
            let result = worker.transfer_range(&h, &mut credited);
            assert_eq!(result.is_ok(), failure == "none", "{failure}: {result:?}");
            if failure == "none" {
                assert_eq!(credited, 512);
                assert_eq!(sched.jobs.lock().unwrap()[0].done.load(Relaxed), 2048);
                let source = src.lock().unwrap();
                let destination = dst.lock().unwrap();
                assert_eq!(source.requests.len(), 4);
                assert_eq!(destination.requests.len(), 4);
                assert_eq!(source.sent_at_receive[0], if source_sync { 1 } else { 4 });
                assert_eq!(
                    destination.sent_at_receive[0],
                    if destination_sync { 1 } else { 4 }
                );
                assert!(sched.range_done(&h));
                assert!(sched.finished());
            } else if worker.transport_dead() {
                worker.retry_credited_range(&h, 0, credited);
                let mut spans = Vec::new();
                for i in 0..4 {
                    let Item::Range(range) = sched.next() else {
                        panic!("lost retry range");
                    };
                    let r = range.lock().unwrap();
                    spans.push((r.pos, r.end));
                    drop(r);
                    assert_eq!(sched.range_done(&range), i == 3);
                }
                spans.sort_unstable();
                assert_eq!(
                    spans,
                    vec![(0, 512), (1024, 1536), (2048, 2560), (3072, 3584)]
                );
                assert_eq!(sched.jobs.lock().unwrap()[0].done.load(Relaxed), 0);
                assert!(sched.finished());
            } else {
                if failure == "mismatch" {
                    assert!(result.unwrap_err().is::<RangeReplyMismatch>());
                    assert_eq!(src.lock().unwrap().received, 2);
                } else {
                    let source = src.lock().unwrap();
                    let destination = dst.lock().unwrap();
                    assert_eq!(source.received, source.requests.len());
                    assert_eq!(destination.received, destination.requests.len());
                }
                sched.range_done(&h);
            }
        }
    }
}

#[test]
fn multiblock_ranges_refill_windows_and_retry_only_unfinished_shares() {
    for source_sync in [false, true] {
        // Each range needs three replies: reads 6 and 10 fail after zero
        // and two extra ranges, respectively, have been fully acknowledged.
        for (failure, completed_extras) in [(None, 0), (Some(6), 0), (Some(10), 2)] {
            let spans: Vec<_> = (0..12).map(|i| (i * 4096, i * 4096 + 1536)).collect();
            let (sched, h, job) = pipeline_ranges(&spans);
            let src = Arc::new(Mutex::new(PipelineState {
                synchronous: source_sync,
                fail_receive: failure,
                ..Default::default()
            }));
            // Immediate acknowledgements make the expected completed shares
            // independent of how many source requests were sent ahead.
            let dst = Arc::new(Mutex::new(PipelineState {
                synchronous: true,
                ..Default::default()
            }));
            for &(off, _) in &spans {
                for block in 0..3 {
                    let data = vec![block as u8; 512];
                    src.lock().unwrap().replies.push_back(Response::Block {
                        off: off + block * 512,
                        hash: content_digest(&data),
                        data,
                    });
                    dst.lock().unwrap().replies.push_back(Response::Ok);
                }
            }
            let mut worker = pipeline_worker(&sched, &src, &dst, false);
            let mut credited = 0;
            let result = worker.transfer_range(&h, &mut credited);
            assert_eq!(result.is_ok(), failure.is_none(), "{result:?}");
            if failure.is_some() {
                assert_eq!(
                    job.done.load(Relaxed),
                    (completed_extras as u64 + 1) * 1536,
                    "partially acknowledged extras must be rolled back before retry"
                );
                worker.retry_credited_range(&h, 0, credited);
                let mut retried = Vec::new();
                for i in 0..12 - completed_extras {
                    let Item::Range(range) = sched.next() else {
                        panic!("missing retry work")
                    };
                    let state = range.lock().unwrap();
                    retried.push((state.pos, state.end));
                    let n = state.end - state.pos;
                    drop(state);
                    worker.progress.add_bytes(n);
                    job.done.fetch_add(n, Relaxed);
                    assert!(job.done.load(Relaxed) <= 12 * 1536);
                    assert_eq!(sched.range_done(&range), i == 11 - completed_extras);
                }
                let mut expected = spans;
                expected.drain(1..1 + completed_extras);
                retried.sort_unstable();
                assert_eq!(retried, expected);
            } else {
                let source = src.lock().unwrap();
                assert_eq!(source.requests.len(), 36);
                for (i, &sent) in source.sent_at_receive.iter().enumerate() {
                    assert_eq!(
                        sent,
                        (i + if source_sync { 1 } else { 4 }).min(36),
                        "refill across range and window boundaries before receiving"
                    );
                }
                assert!(sched.range_done(&h));
            }
            assert_eq!(job.done.load(Relaxed), 12 * 1536);
            assert!(sched.finished());
        }
    }
}

#[test]
fn long_extras_follow_range_selection_and_only_reserve_for_ready_peers() {
    for (same_host, tuning) in [
        (true, "request-size=512"),
        (false, "copy-path=ranges,pipeline-depth=2"),
        (false, "pipeline-depth=8"),
    ] {
        let spans = [(0, 3072), (4096, 7168), (8192, 11264)];
        let (sched, h, job) = pipeline_ranges(&spans);
        let src = Arc::new(Mutex::new(PipelineState::default()));
        let dst = Arc::new(Mutex::new(PipelineState::default()));
        for (start, end) in spans {
            for off in (start..end).step_by(512) {
                let data = vec![0; 512];
                src.lock().unwrap().replies.push_back(Response::Block {
                    off,
                    hash: content_digest(&data),
                    data,
                });
                dst.lock().unwrap().replies.push_back(Response::Ok);
            }
        }
        let mut worker = pipeline_worker(&sched, &src, &dst, false);
        let opts = Arc::get_mut(&mut worker.opts).unwrap();
        opts.same_host = same_host;
        opts.tuning = tuning.parse().unwrap();
        // Other active slots are still connecting and cannot use the queue.
        worker.gate = Gate::new(3);
        worker.gate.mark_ready(0);
        let mut credited = 0;
        worker.transfer_range(&h, &mut credited).unwrap();
        assert_eq!(src.lock().unwrap().requests.len(), 18, "{tuning}");
        assert_eq!(credited, 3072);
        assert_eq!(job.done.load(Relaxed), 9216);
        assert!(sched.range_done(&h));
        assert!(sched.finished());
    }
}

#[test]
fn released_pipeline_does_not_reclaim_work_when_reenabled_during_drain() {
    let (sched, h, _) = pipeline_ranges(&[(0, 3072), (4096, 7168)]);
    let gate = Gate::new(1);
    let src = Arc::new(Mutex::new(PipelineState {
        gate_changes: vec![(1, gate.clone(), 0), (2, gate.clone(), 1)],
        ..Default::default()
    }));
    let dst = Arc::new(Mutex::new(PipelineState::default()));
    for off in (0..2048).step_by(512) {
        let data = vec![0; 512];
        src.lock().unwrap().replies.push_back(Response::Block {
            off,
            hash: content_digest(&data),
            data,
        });
        dst.lock().unwrap().replies.push_back(Response::Ok);
    }
    let mut worker = pipeline_worker(&sched, &src, &dst, false);
    worker.gate = gate;
    let mut credited = 0;
    worker.transfer_range(&h, &mut credited).unwrap();
    assert_eq!(credited, 2048);
    assert_eq!(src.lock().unwrap().requests.len(), 4);
    assert!(!sched.range_done(&h));
    let mut remaining = Vec::new();
    for _ in 0..2 {
        let Item::Range(handle) = sched.next() else {
            panic!("missing released work")
        };
        let range = handle.lock().unwrap();
        remaining.push((range.pos, range.end));
        drop(range);
        sched.range_done(&handle);
    }
    remaining.sort_unstable();
    assert_eq!(remaining, [(2048, 3072), (4096, 7168)]);
    assert!(sched.finished());
}

/// Enforce send-before-receive ordering while exercising the real local
/// receiver. Inject response failures to check that every reply is drained.
struct SetupConn {
    inner: Box<dyn Conn>,
    sent: usize,
    received: usize,
    fail_at: Option<usize>,
    requests: Vec<Request>,
}

impl Conn for SetupConn {
    fn send(&mut self, request: Request) -> Result<()> {
        self.sent += 1;
        self.requests.push(request.clone());
        self.inner.send(request)
    }
    fn recv(&mut self) -> Result<Response> {
        assert_eq!(self.sent, 3, "setup waited before sending every request");
        let response = self.inner.recv()?;
        let index = self.received;
        self.received += 1;
        if self.fail_at == Some(index) {
            Ok(Response::Err("injected setup error".into()))
        } else {
            Ok(response)
        }
    }
    fn scan(
        &mut self,
        _: &[u8],
        _: Option<&RegisteredPath>,
        _: bool,
        _: &[String],
        _: bool,
        _: &mut dyn FnMut(Vec<Entry>) -> Result<()>,
        _: &mut dyn FnMut(Vec<PathBytes>) -> Result<()>,
        _: &mut dyn FnMut(String),
    ) -> Result<()> {
        unreachable!()
    }
    fn native_remove(
        &mut self,
        _: Option<&[u8]>,
        _: Option<&[u8]>,
        _: &[NativeRemoveSelection],
        _: bool,
        _: bool,
        _: usize,
        _: &mut dyn FnMut(Vec<String>) -> Result<()>,
        _: &mut dyn FnMut(Vec<NativeRemoveOutcome>) -> Result<()>,
    ) -> Result<()> {
        unreachable!()
    }
}

#[test]
fn existing_destination_setup_pipelines_and_drains_failures() {
    for fail_at in [None, Some(0), Some(1), Some(2)] {
        let directory = crate::test_support::tempdir().unwrap();
        let path = directory.path().as_os_str().as_bytes();
        let entry = crate::fsops::lstat_entry(Vec::new(), directory.path()).unwrap();
        let mut conn = SetupConn {
            inner: Endpoint::local().connect_control(false).unwrap(),
            sent: 0,
            received: 0,
            fail_at,
            requests: Vec::new(),
        };
        let result = prepare_existing_destination(
            &mut conn,
            path,
            OperatorSymlinkPolicy::FollowAll,
            &entry,
            path.to_vec(),
        );
        // Unavailable filesystem counters are advisory, as before.
        assert_eq!(result.is_ok(), fail_at.is_none() || fail_at == Some(1));
        assert_eq!(conn.received, 3);
        if let Ok((selection, filesystem, anchor)) = result {
            assert_eq!(selection.unwrap().ino, entry.ino);
            assert_eq!(anchor.ino, entry.ino);
            assert_eq!(filesystem.is_none(), fail_at == Some(1));
        }
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
        assert!(matches!(
            conn.inner
                .call(Request::DestinationFilesystemInfo {
                    check_empty: true,
                    target: None,
                })
                .unwrap(),
            Response::DestinationFilesystemInfo(_)
        ));
    }
}

#[test]
fn existing_destination_setup_rejects_replaced_inode_without_writes() {
    let directory = crate::test_support::tempdir().unwrap();
    let destination = directory.path().join("destination");
    std::fs::create_dir(&destination).unwrap();
    let entry = crate::fsops::lstat_entry(Vec::new(), &destination).unwrap();
    std::fs::rename(&destination, directory.path().join("original")).unwrap();
    std::fs::create_dir(&destination).unwrap();
    let path = destination.as_os_str().as_bytes();
    let mut conn = SetupConn {
        inner: Endpoint::local().connect_control(false).unwrap(),
        sent: 0,
        received: 0,
        fail_at: None,
        requests: Vec::new(),
    };
    let result = prepare_existing_destination(
        &mut conn,
        path,
        OperatorSymlinkPolicy::FollowAll,
        &entry,
        path.to_vec(),
    );
    assert!(result.is_err());
    assert_eq!(conn.received, 3);
    assert_eq!(std::fs::read_dir(&destination).unwrap().count(), 0);
    assert_eq!(
        std::fs::read_dir(directory.path().join("original"))
            .unwrap()
            .count(),
        0
    );
}

#[test]
#[ignore = "set SYQ_V032_BINARY to the verified official v0.3.2 executable"]
fn existing_destination_setup_replays_on_v032_receiver() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    // This probe deliberately speaks the released client's identity. Real
    // clients retain exact build pinning; it is not a mixed-build bypass.
    let binary = std::env::var_os("SYQ_V032_BINARY").expect("SYQ_V032_BINARY");
    let directory = crate::test_support::tempdir().unwrap();
    let path = directory.path().as_os_str().as_bytes();
    let entry = crate::fsops::lstat_entry(Vec::new(), directory.path()).unwrap();
    let mut conn = SetupConn {
        inner: Endpoint::local().connect_control(false).unwrap(),
        sent: 0,
        received: 0,
        fail_at: None,
        requests: Vec::new(),
    };
    prepare_existing_destination(
        &mut conn,
        path,
        OperatorSymlinkPolicy::FollowAll,
        &entry,
        path.to_vec(),
    )
    .unwrap();
    struct Receiver(std::process::Child);
    impl Drop for Receiver {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut receiver = Receiver(
        Command::new(binary)
            .arg("--server")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut input = receiver.0.stdin.take().unwrap();
    let mut output = receiver.0.stdout.take().unwrap();
    let identity = b"v0.3.2";
    input.write_all(b"SYQWIRE\0").unwrap();
    input
        .write_all(&(identity.len() as u16).to_be_bytes())
        .unwrap();
    input.write_all(identity).unwrap();
    let mut writer = FrameWriter::with_preamble_written(input, false);
    writer
        .write_msg(&Request::Hello {
            identity: "v0.3.2".into(),
            compress: false,
            debug: false,
            token: Vec::new(),
            role: ConnectionRole::Control,
        })
        .unwrap();
    let mut header = [0u8; 10];
    output.read_exact(&mut header).unwrap();
    assert_eq!(&header[..8], b"SYQWIRE\0");
    let mut peer_identity = vec![0; u16::from_be_bytes([header[8], header[9]]) as usize];
    output.read_exact(&mut peer_identity).unwrap();
    assert_eq!(peer_identity, identity);
    fn response(output: &mut impl Read) -> Response {
        let mut length = [0u8; 4];
        output.read_exact(&mut length).unwrap();
        let length = u32::from_le_bytes(length) as usize;
        assert!((1..65536).contains(&length));
        let mut bytes = vec![0; length];
        output.read_exact(&mut bytes).unwrap();
        assert_eq!(bytes[0], 0, "compression was disabled");
        postcard::from_bytes(&bytes[1..]).unwrap()
    }
    assert!(matches!(response(&mut output), Response::HelloOk { .. }));
    for request in &conn.requests {
        writer.write_msg(request).unwrap();
    }
    assert!(matches!(
        response(&mut output),
        Response::DirectorySelection(Some(_))
    ));
    assert!(matches!(
        response(&mut output),
        Response::DestinationFilesystemInfo(_)
    ));
    assert!(matches!(
        response(&mut output),
        Response::DestinationRegistered(_)
    ));
    drop(writer);
    assert!(receiver.0.wait().unwrap().success());
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[test]
fn fresh_capacity_keeps_a_sixty_four_inode_margin() {
    let assessment = |objects, available_inodes| FreshCapacityAssessment {
        logical_bytes: 0,
        objects,
        available_bytes: 0,
        available_inodes: Some(available_inodes),
    };

    assert!(assessment(1, 64).inode_shortage());
    assert!(!assessment(1, 65).inode_shortage());
    assert!(!assessment(u64::MAX, u64::MAX).inode_shortage());
}

#[test]
fn restricted_remote_diagnostics_name_the_grant_helper() {
    let mut spec = RemoteSpec::local_receiver(false);
    spec.restricted_grant = Some("signed-grant".into());

    assert_eq!(
        remote_helper_mode(&spec, Interface::NativeCp),
        "restricted grant"
    );
}

#[test]
fn endpoint_semantic_error_kind_wins_over_numeric_errno() {
    let error = WireError {
        message: "receiver quota exhausted".into(),
        io_kind: Some(WireIoKind::QuotaExceeded),
        // Deliberately contradict the semantic kind. Numeric errno values
        // belong to the receiver ABI and must never drive coordinator
        // policy.
        raw_os_error: Some(libc::ENOSPC),
    };
    assert_eq!(wire_os_kind(&error), Some("quota_exceeded"));
    assert!(capacity_os_kind(wire_os_kind(&error)));
    assert_eq!(os_kind_of(&endpoint_error(error)), Some("quota_exceeded"));
}

#[test]
fn mkdir_apply_error_preserves_endpoint_os_kind() {
    let error = WireError {
        message: "destination is full".into(),
        io_kind: Some(WireIoKind::NoSpace),
        raw_os_error: Some(libc::ENOSPC),
    };
    let error = mkdir_apply_result(vec![None, Some(error)]).unwrap_err();
    assert_eq!(os_kind_of(&error), Some("no_space"));
    assert_eq!(format!("{error:#}"), "mkdir: destination is full");
}

#[test]
fn dry_run_location_labels_include_explicit_ssh_port() {
    let location = |host: &str, port| Location {
        user: Some("alice".into()),
        host: Some(host.into()),
        port: Some(port),
        path: b"/data".to_vec(),
        selection: SourceSelection::Named,
    };

    assert_eq!(
        display_location(&location("backup", 2200), b"/data"),
        "alice@backup:2200:/data"
    );
    assert_eq!(
        display_location(&location("2001:db8::1", 2222), b"/data"),
        "alice@[2001:db8::1]:2222:/data"
    );
}

#[test]
fn ssh_startup_workers_are_bounded_by_files_and_splittable_ranges() {
    const MIB: u64 = 1 << 20;
    for (bytes, expected) in [(0, 1), (32, 1), (63, 1), (64, 2), (128, 4), (512, 8)] {
        assert_eq!(initial_range_workers(8, [bytes * MIB], 32 * MIB), expected);
    }
    assert_eq!(initial_range_workers(8, [40 * MIB, 40 * MIB], 32 * MIB), 2);
    assert_eq!(initial_range_workers(8, [0, 0, 0, 0], 32 * MIB), 4);
    assert_eq!(initial_range_workers(8, [64 * MIB], 16 * MIB), 4);
    assert_eq!(initial_range_workers(8, [u64::MAX, u64::MAX], 1), 8);
    assert_eq!(initial_range_workers(1, [u64::MAX], 1), 1);
    assert_eq!(initial_range_workers(0, [u64::MAX], 1), 0);
    assert_eq!(initial_range_workers(8, [], 1), 1);
    for id in [0, 1, 2, 63, 64, 128, 1000] {
        assert_eq!(reuse_startup_ssh(id, true), id < 2);
        assert_eq!(reuse_startup_ssh(id, false), id == 0);
    }
}

#[test]
fn initial_fast_workers_preserve_startup_file_and_byte_budgets() {
    assert_eq!(
        initial_fast_workers(
            32,
            100,
            100 * (4 << 20),
            STARTUP_BATCH_FILES,
            crate::transfer_tuning::DEFAULT_BATCH_BYTES
        ),
        25
    );
    assert_eq!(
        initial_fast_workers(
            8,
            100,
            100 * (4 << 20),
            STARTUP_BATCH_FILES,
            crate::transfer_tuning::DEFAULT_BATCH_BYTES
        ),
        8
    );
    assert_eq!(
        initial_fast_workers(
            32,
            300,
            300,
            STARTUP_BATCH_FILES,
            crate::transfer_tuning::DEFAULT_BATCH_BYTES
        ),
        3
    );
}

#[test]
fn clean_root_pins_the_edge_cases() {
    for (given, want) in [
        ("/", "/"),
        ("//", "/"),
        ("/.", "/"),
        (".", "."),
        ("./", "."),
        ("././//", "."),
        ("dst", "dst"),
        ("dst/", "dst"),
        ("dst/.", "dst"),
        ("dst//x", "dst/x"),
        ("./dst/./x/", "dst/x"),
        ("~/x//y/.", "~/x/y"),
        ("/a//b/./c", "/a/b/c"),
    ] {
        assert_eq!(
            clean_root(given.as_bytes()),
            want.as_bytes(),
            "clean_root({given:?})"
        );
    }
}

#[test]
fn restricted_root_creation_uses_only_the_authorized_mode_policy() {
    let ordinary = mkdir_root_batches(b"/destination", TargetCondition::Absent, false, false);
    assert_eq!(ordinary.len(), 1);
    assert!(matches!(ordinary[0].as_slice(), [Op::Mkdir { .. }]));

    let preserving = mkdir_root_batches(b"/destination", TargetCondition::Absent, true, true);
    assert_eq!(preserving.len(), 1);
    assert!(matches!(
        preserving[0].as_slice(),
        [Op::Mkdir { mode: 0o755, .. }]
    ));

    let receiver_managed =
        mkdir_root_batches(b"/destination", TargetCondition::Absent, true, false);
    assert_eq!(receiver_managed.len(), 2);
    assert!(matches!(
        receiver_managed[0].as_slice(),
        [Op::Mkdir { mode: 0o755, .. }]
    ));
    assert!(matches!(
        receiver_managed[1].as_slice(),
        [Op::SetMeta {
            meta: Meta { mode: 0o755, .. },
            flags: flags::RECEIVER_MODE,
            ..
        }]
    ));
}

#[test]
fn restricted_directory_creation_batches_put_parents_before_children() {
    let mkdir = |path: &[u8]| Op::Mkdir {
        path: path.to_vec(),
        mode: 0o755,
        condition: TargetCondition::Any,
    };
    let ops = vec![
        mkdir(b"/destination/a/b"),
        mkdir(b"/destination/c"),
        mkdir(b"/destination/a"),
        mkdir(b"/destination/c/d"),
    ];

    let ordinary = directory_creation_batches(ops.clone(), false);
    assert_eq!(ordinary.len(), 1);
    assert_eq!(ordinary[0].len(), 4);

    let restricted = directory_creation_batches(ops, true);
    assert_eq!(restricted.len(), 2);
    fn paths(batch: &[Op]) -> Vec<&[u8]> {
        batch
            .iter()
            .map(|op| match op {
                Op::Mkdir { path, .. } => path.as_slice(),
                _ => unreachable!(),
            })
            .collect::<Vec<_>>()
    }
    assert_eq!(
        paths(&restricted[0]),
        vec![b"/destination/c".as_slice(), b"/destination/a".as_slice()]
    );
    assert_eq!(
        paths(&restricted[1]),
        vec![
            b"/destination/a/b".as_slice(),
            b"/destination/c/d".as_slice()
        ]
    );
}

#[test]
fn attested_outcome_summary_does_not_hide_coordinator_statistics() {
    let mut args = Args::parse_args(&[
        "cp".into(),
        "source".into(),
        "--as".into(),
        "destination".into(),
        "--stats".into(),
    ])
    .unwrap();
    assert!(show_statistics(&args));
    args.suppress_summary = true;
    assert!(!show_statistics(&args));
    args.restricted_grant = Some("coordinator grant".into());
    assert!(show_statistics(&args));
}

#[test]
fn tcp_stats_distinguish_unavailable_fields_from_zero() {
    let output = format_tcp_stats(
        &[TcpPairStats {
            label: "host".into(),
            local: Some(TcpSocketStats {
                bytes_sent: Some(100),
                bytes_retransmitted: Some(0),
                segments_sent: Some(10),
                retransmissions: None,
                rtt_us: Some(1_000),
                min_rtt_us: None,
                ecn_ce_delivered: None,
                ..TcpSocketStats::default()
            }),
            peer: None,
        }],
        false,
    );
    assert!(output.contains("unavailable packets, 0 (0.000% of sent) bytes"));
    assert!(output.contains("current average 1.00 ms, minimum unavailable"));
    assert!(output.contains("receive unavailable, send-buffer unavailable"));
    assert!(output.contains("tcp ECN CE deliveries: unavailable"));
}

#[test]
fn large_small_file_batches_bound_long_path_frames_and_preserve_every_file() {
    struct CheckedConn {
        entries: Arc<std::collections::HashMap<PathBytes, Entry>>,
        requests: Arc<Mutex<Vec<Request>>>,
        replies: std::collections::VecDeque<Response>,
    }
    impl Conn for CheckedConn {
        fn supports_request_pipelining(&self) -> bool {
            true
        }
        fn send(&mut self, request: Request) -> Result<()> {
            let mut wire = Vec::new();
            FrameWriter::new(&mut wire, false).write_msg(&request)?;
            let reply = match &request {
                Request::ReadSmallBatch(reads) => Response::SmallBlocks(
                    reads
                        .iter()
                        .map(|read| {
                            let data = vec![7; read.len as usize];
                            Ok(SmallBlock {
                                hash: content_digest(&data),
                                data,
                            })
                        })
                        .collect(),
                ),
                Request::PutSmallBatch(puts) => Response::Applied(vec![None; puts.len()]),
                Request::StatMany { paths, .. } => Response::Stats(
                    paths
                        .iter()
                        .map(|path| self.entries.get(path).cloned())
                        .collect(),
                ),
                other => panic!("unexpected request {other:?}"),
            };
            self.requests.lock().unwrap().push(request);
            self.replies.push_back(reply);
            Ok(())
        }
        fn recv(&mut self) -> Result<Response> {
            self.replies
                .pop_front()
                .ok_or_else(|| anyhow::anyhow!("missing reply"))
        }
        fn scan(
            &mut self,
            _: &[u8],
            _: Option<&RegisteredPath>,
            _: bool,
            _: &[String],
            _: bool,
            _: &mut dyn FnMut(Vec<Entry>) -> Result<()>,
            _: &mut dyn FnMut(Vec<PathBytes>) -> Result<()>,
            _: &mut dyn FnMut(String),
        ) -> Result<()> {
            unreachable!()
        }
        fn native_remove(
            &mut self,
            _: Option<&[u8]>,
            _: Option<&[u8]>,
            _: &[NativeRemoveSelection],
            _: bool,
            _: bool,
            _: usize,
            _: &mut dyn FnMut(Vec<String>) -> Result<()>,
            _: &mut dyn FnMut(Vec<NativeRemoveOutcome>) -> Result<()>,
        ) -> Result<()> {
            unreachable!()
        }
    }
    let prefix = format!("{}/", "a".repeat(250)).repeat(12);
    let jobs: Vec<_> = (0..2048)
        .map(|i| pipeline_job(format!("{prefix}{i:04}").as_bytes(), 1))
        .collect();
    // All names fit normal component/path limits, but a single request with
    // both spellings exceeds the metadata frame boundary.
    let oversized = Request::StatMany {
        paths: jobs.iter().map(|job| job.src.clone()).collect(),
        sources: Some(jobs.iter().map(|job| job.source.clone()).collect()),
        follow: false,
        guard: None,
    };
    assert!(FrameWriter::new(Vec::new(), false)
        .write_msg(&oversized)
        .is_err());
    let entries = Arc::new(
        jobs.iter()
            .map(|job| (job.src.clone(), job.entry.clone()))
            .collect(),
    );
    let sched = Arc::new(Sched::new(512, 8192));
    for job in &jobs {
        sched.push_file(job.clone());
    }
    sched.scan_done();
    assert!(matches!(sched.next(), Item::File(0)));
    assert_eq!(sched.begin_fast_batch(1, jobs.len()), jobs.len());
    let mut batch = vec![0];
    batch.extend(sched.take_small(1, jobs.len() - 1, u64::MAX));
    sched.mark_fast(batch.len() - 1);
    let source_requests = Arc::new(Mutex::new(Vec::new()));
    let destination_requests = Arc::new(Mutex::new(Vec::new()));
    let mut worker = pipeline_worker(
        &sched,
        &Arc::new(Mutex::new(PipelineState::default())),
        &Arc::new(Mutex::new(PipelineState::default())),
        false,
    );
    worker.src = Box::new(CheckedConn {
        entries: Arc::clone(&entries),
        requests: source_requests.clone(),
        replies: Default::default(),
    });
    worker.dst = Box::new(CheckedConn {
        entries,
        requests: destination_requests,
        replies: Default::default(),
    });
    worker.fast_batch(&mut batch).unwrap();
    sched.complete_fast_batch(batch.len());
    assert!(sched.finished());
    assert_eq!(worker.progress.files_done.load(Relaxed), jobs.len() as u64);
    assert_eq!(worker.progress.errors.load(Relaxed), 0);
    assert!(jobs.iter().all(|job| job.done.load(Relaxed) == 1));
    let requests = source_requests.lock().unwrap();
    assert!(
        requests
            .iter()
            .filter(|request| matches!(request, Request::ReadSmallBatch(_)))
            .count()
            > 1
    );
    assert!(
        requests
            .iter()
            .filter(|request| matches!(request, Request::StatMany { .. }))
            .count()
            > 1
    );
}

#[test]
fn dry_run_hash_errors_drain_both_endpoints_without_writes() {
    for source_fails in [false, true] {
        let sched = Arc::new(Sched::new(512, 8192));
        let mut job = pipeline_job(b"file", 3);
        job.dst_entry = Some(job.entry.clone());
        sched.push_file(job);
        sched.scan_done();
        assert!(matches!(sched.next(), Item::File(0)));
        let source = Arc::new(Mutex::new(PipelineState::default()));
        let destination = Arc::new(Mutex::new(PipelineState::default()));
        for (state, fails) in [(&source, source_fails), (&destination, !source_fails)] {
            state.lock().unwrap().replies.push_back(if fails {
                Response::Err("injected read error".into())
            } else {
                Response::FileHash {
                    size: 3,
                    hash: [1; 32],
                }
            });
        }
        let mut worker = pipeline_worker(&sched, &source, &destination, false);
        Arc::get_mut(&mut worker.opts).unwrap().dry_run = true;
        worker.progress.files_total.store(1, Relaxed);
        worker.progress.bytes_total.store(3, Relaxed);
        let error = worker.preview_file(0).unwrap_err();
        worker.file_error(0, error).unwrap();
        assert_eq!(worker.progress.errors.load(Relaxed), 1);
        assert_eq!(worker.progress.files_done.load(Relaxed), 0);
        assert!(sched.finished());
        for state in [&source, &destination] {
            let state = state.lock().unwrap();
            assert_eq!(state.received, 1);
            assert!(state.replies.is_empty());
            assert!(matches!(
                state.requests.as_slice(),
                [Request::FileHash { .. }]
            ));
        }
    }
}

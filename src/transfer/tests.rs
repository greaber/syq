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
    sent_at: Vec<std::time::Instant>,
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
    configuration_latency: Option<std::time::Duration>,
    ready: std::collections::VecDeque<std::time::Instant>,
    abort_on_receive: Option<Arc<Sched>>,
    abort_receive_number: Option<usize>,
    tuning_check: Option<(Arc<Sched>, Arc<Gate>, usize)>,
    tuning_snapshots: Vec<(crate::sched::TuningWork, bool)>,
    auto_ranges: bool,
    arrival_delay: Option<std::time::Duration>,
    early_range_acks: bool,
    steal_range_at: Option<(usize, Arc<Sched>)>,
    stolen_range: Option<RangeHandle>,
    auto_small_size: Option<u64>,
    reject_small_puts: bool,
    immediate_batch_receipts: Option<Arc<crate::conn::BatchReceipts>>,
}

struct PipelineConn(Arc<Mutex<PipelineState>>);

impl Conn for PipelineConn {
    fn track_small_batches(
        &mut self,
        progress: Arc<Progress>,
    ) -> Result<Option<crate::conn::BatchProgress>> {
        self.0
            .lock()
            .unwrap()
            .immediate_batch_receipts
            .as_ref()
            .map(|receipts| receipts.begin(progress))
            .transpose()
    }
    fn try_recv_with_arrival(&mut self) -> Option<Result<(Response, std::time::Instant)>> {
        let state = self.0.lock().unwrap();
        let ready = state.early_range_acks
            && !state.replies.is_empty()
            && state
                .ready
                .front()
                .is_none_or(|ready| *ready <= std::time::Instant::now());
        drop(state);
        ready.then(|| self.recv_with_arrival())
    }
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
    fn fence_streaming_writes(&mut self) -> Result<()> {
        assert!(self.0.lock().unwrap().auto_ranges);
        Ok(())
    }
    fn finish_streaming_writes(&mut self, sent: u64, fence: Result<()>) -> Result<()> {
        fence?;
        for _ in 0..sent {
            assert!(matches!(self.recv()?, Response::Ok));
        }
        Ok(())
    }
    fn send(&mut self, request: Request) -> Result<()> {
        let mut state = self.0.lock().unwrap();
        if let Some(size) = state.auto_small_size {
            let response = match &request {
                Request::ConfigureHashing(_) => {
                    assert_eq!(
                        state.requests.len(),
                        state.received,
                        "latency check requires drained requests"
                    );
                    Response::Ok
                }
                Request::ReadSmallBatch(reads) => Response::SmallBlocks(
                    reads
                        .iter()
                        .map(|read| {
                            let data = vec![42; read.len as usize];
                            Ok(SmallBlock {
                                source: Some(pipeline_job(&read.path, size).data.entry),
                                hash: content_digest(&data),
                                data,
                            })
                        })
                        .collect(),
                ),
                Request::PutSmallBatch(_) if state.reject_small_puts => {
                    Response::Err("denied".into())
                }
                Request::PutSmallBatch(puts) => Response::Applied(vec![None; puts.len()]),
                Request::StatMany { paths, .. } => Response::Stats(
                    paths
                        .iter()
                        .map(|path| Some(pipeline_job(path, size).data.entry))
                        .collect(),
                ),
                other => panic!("unexpected automatic small-batch request {other:?}"),
            };
            if let Some(receipts) = &state.immediate_batch_receipts {
                receipts.request(&request)?;
                receipts.response(&response);
            }
            state.replies.push_back(response);
        }
        if state.auto_ranges {
            match &request {
                Request::ConfigureHashing(_) => {
                    assert_eq!(
                        state.requests.len(),
                        state.received,
                        "range latency check requires drained requests"
                    );
                    state.replies.push_back(Response::Ok);
                }
                Request::ReadRange { off, len, .. }
                | Request::ReadComparedRange { off, len, .. } => {
                    let data = vec![42; *len as usize];
                    state.replies.push_back(Response::Block {
                        off: *off,
                        hash: content_digest(&data),
                        data,
                    });
                }
                Request::HashWindow { len, block, .. } => {
                    state.replies.push_back(Response::Hashes(vec![
                        [0; 32];
                        (*len as u64).div_ceil(*block)
                            as usize
                    ]))
                }
                Request::WriteRange { .. } => state.replies.push_back(Response::Ok),
                Request::ReadStream(stream) => {
                    state.replies.push_back(Response::Ok);
                    for off in (stream.off..stream.end).step_by(stream.block as usize) {
                        let data = vec![42; (stream.end - off).min(stream.block as u64) as usize];
                        state.replies.push_back(Response::Block {
                            off,
                            hash: content_digest(&data),
                            data,
                        });
                    }
                }
                Request::StopReadStream => state.replies.push_back(Response::ReadStreamDone),
                Request::ShrinkReadStream { .. } => {}
                other => panic!("unexpected automatic range request {other:?}"),
            }
        }
        let latency = if matches!(request, Request::ConfigureHashing(_)) {
            state.configuration_latency
        } else {
            state.latency
        };
        state.requests.push(request);
        state.sent_at.push(std::time::Instant::now());
        if let Some(latency) = latency {
            state.ready.push_back(std::time::Instant::now() + latency);
        }
        state.max_pending = state
            .max_pending
            .max(state.requests.len().saturating_sub(state.received));
        Ok(())
    }
    fn recv_with_arrival(&mut self) -> Result<(Response, std::time::Instant)> {
        let response = self.recv()?;
        let delay = self.0.lock().unwrap().arrival_delay.unwrap_or_default();
        Ok((response, std::time::Instant::now() + delay))
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
        if state
            .steal_range_at
            .as_ref()
            .is_some_and(|(at, _)| *at == state.received)
        {
            let (_, sched) = state.steal_range_at.take().unwrap();
            assert!(
                sched.tuning_work(2, 0, 0).sufficient,
                "a slow range must expose usable work to another worker"
            );
            let Item::Range(range) = sched.next() else {
                panic!("expected unread range")
            };
            state.stolen_range = Some(range);
        }
        if let Some(sched) = state.steal_on_receive.take() {
            assert!(
                sched.tuning_work(1, 0, 0).unread_batch_files > 0,
                "must leave shareable work before the peer claims it"
            );
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
        if let Some((sched, gate, active)) = &state.tuning_check {
            let snapshot = (
                sched.tuning_work(*active, 0, 0),
                gate.measurement_ready(*active),
            );
            state.tuning_snapshots.push(snapshot);
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
        if state
            .abort_receive_number
            .is_none_or(|at| at == state.received)
        {
            if let Some(sched) = state.abort_on_receive.take() {
                sched.abort();
            }
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
    ) -> Result<u64> {
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
        mapping_metadata: Default::default(),
        mapping_expected_hashes: Default::default(),
        hardlink_expected_hashes: Default::default(),
        block: 512,
        block_explicit: false,
        tuning: crate::transfer_tuning::TransferTuning {
            copy_path: (!streaming).then_some(crate::transfer_tuning::CopyPath::Ranges),
            pipeline_depth: (!streaming).then_some(4),
            ..Default::default()
        },
        benchmark: None,
        flags: 0,
        matching_flags: 0,
        if_exists: None,
        recursive: true,
        links: false,
        perms: false,
        rsync_creation: false,
        hardlinks: false,
        sparse: false,
        inode_preservation: Default::default(),
        hardlink_completions: Mutex::new(Default::default()),
        devices: false,
        checksum: false,
        precise_mtime: true,
        inplace: false,
        same_host: false,
        allow_sequential_nfs_fallback: false,
        src_remote: false,
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
        expressions: Default::default(),
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
        progress: Progress::new(false, false, None),
        opts,
        bwlimit: None,
        gate: Gate::new(1),
        observation: None,
        benchmark: Default::default(),
        fast_batch_files: 1,
        batch_budget: WorkBudget::default(),
        range_budget: None,
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
fn changed_source_exhausts_retries_without_publishing() {
    let sched = Arc::new(Sched::new(512, 8192));
    let mut job = pipeline_job(b"source", 4096);
    let mut destination = job.entry.clone();
    destination.mtime -= 1;
    job.dst_entry = Some(destination.clone());
    sched.push_file(job);
    sched.scan_done();
    let src = Arc::new(Mutex::new(PipelineState::default()));
    let dst = Arc::new(Mutex::new(PipelineState::default()));
    let mut worker = pipeline_worker(&sched, &src, &dst, false);
    for attempt in 0..MAX_ATTEMPTS {
        assert!(matches!(sched.next(), Item::File(0)));
        let job = worker.job(0);
        assert_eq!(job.attempt, attempt);
        job.done.store(job.entry.size, Relaxed);
        sched.ranges_ready(0, vec![]);
        let mut changed = job.entry.clone();
        changed.mtime += 1;
        src.lock()
            .unwrap()
            .replies
            .push_back(Response::Stats(vec![Some(changed)]));
        let result = worker.finish_file(0);
        if attempt + 1 == MAX_ATTEMPTS {
            assert!(result.unwrap_err().to_string().contains("source changed"));
        } else {
            result.unwrap();
            assert!(
                !worker.fast_eligible(0),
                "a smaller retry must keep staged publication"
            );
        }
        let current = worker.job(0);
        assert_eq!(current.dst_entry.as_ref().unwrap().mtime, destination.mtime);
        assert!(dst.lock().unwrap().requests.is_empty());
    }
    assert_eq!(src.lock().unwrap().requests.len(), MAX_ATTEMPTS as usize);
    assert_eq!(worker.progress.files_done.load(Relaxed), 0);
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
                let error = worker.run(None).unwrap_err();
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
                            source: Some(pipeline_job(b"source", data.len() as u64).entry.clone()),
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
            let result = worker.transfer_small_batches(
                &jobs,
                {
                    let mut groups = groups.into_iter();
                    move |_| groups.next()
                },
                &mut results,
            );
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
                        results[..2].iter().all(|r| matches!(r, Some(Ok(_)))),
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
        "source-drop",
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
            fail_receive: (failure == "source-drop").then_some(6),
            ..Default::default()
        }));
        let dst = Arc::new(Mutex::new(PipelineState {
            fail_receive: (failure == "destination-drop").then_some(6),
            ..Default::default()
        }));
        for i in 0..6 {
            let data = vec![0; 1 << 20];
            let mut source = jobs[batch[i]].entry.clone();
            let changed = i == 0 && failure.starts_with("changed");
            if changed {
                source.mtime += 1;
            }
            src.lock()
                .unwrap()
                .replies
                .push_back(Response::SmallBlocks(vec![Ok(SmallBlock {
                    source: Some(source),
                    hash: content_digest(&data),
                    data,
                })]));
            if !changed {
                dst.lock()
                    .unwrap()
                    .replies
                    .push_back(Response::Applied(vec![None]));
            }
        }
        let mut worker = pipeline_worker(&sched, &src, &dst, false);
        // Other workers' progress must survive rollback of this batch.
        worker.progress.bytes_total.store(6 << 20, Relaxed);
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
        let acknowledged = if failure == "none" { 6 } else { 5 };
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
        let writes = dst
            .lock()
            .unwrap()
            .requests
            .iter()
            .filter_map(|request| match request {
                Request::PutSmallBatch(puts) => Some(puts.len()),
                _ => None,
            })
            .sum::<usize>();
        assert_eq!(
            writes,
            if failure.starts_with("changed") || failure == "source-drop" {
                5
            } else {
                6
            }
        );
        let snapshots = &dst.lock().unwrap().progress_at_receive;
        for (i, &(bytes, files)) in snapshots.iter().enumerate() {
            assert_eq!(bytes, 123 + ((i as u64) << 20), "{failure}: ack {i}");
            assert_eq!(files, 7, "completion waits for the batch to drain");
        }
        assert_eq!(
            jobs[0].done.load(Relaxed),
            if expected_files == 6 { 1 << 20 } else { 0 }
        );
        assert_eq!(sched.is_failed(0), failure == "changed");
        if failure == "changed-retry" {
            assert_eq!(sched.jobs.lock().unwrap()[0].attempt, 1);
            assert_eq!(worker.progress.bytes_total.load(Relaxed), 6 << 20);
            assert!(sched.jobs.lock().unwrap().destination(0).is_none());
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
        .receive_small_batch(
            (vec![0, 1, 2], std::time::Instant::now()),
            &jobs,
            &mut results,
            None
        )
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
        .receive_small_batch(
            (vec![1], std::time::Instant::now()),
            &jobs,
            &mut results,
            None
        )
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
                source: Some(pipeline_job(b"source", data.len() as u64).entry.clone()),
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
    assert_eq!(
        source.requests.len(),
        5,
        "rechecks travel with whole-file reads"
    );
    assert!(source.replies.is_empty());
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
fn same_machine_batches_reach_the_receiver_in_groups_idle_workers_can_take() {
    // A same-machine copy reads in process and writes to a receiver process
    // over a pipelined data connection. Its batch is still split by files, so
    // a worker that took a large batch has groups to hand to idle workers; a
    // batch for another machine keeps only its byte limit.
    for same_host in [true, false] {
        let sched = Arc::new(Sched::new(512, 8192));
        let jobs: Vec<_> = (0..130)
            .map(|i| pipeline_job(format!("file{i}").as_bytes(), 512))
            .collect();
        for job in &jobs {
            sched.push_file(job.clone());
        }
        sched.scan_done();
        assert!(matches!(sched.next(), Item::File(0)));
        assert_eq!(sched.begin_fast_batch(1, 130), 130);
        let mut batch = vec![0];
        batch.extend(sched.take_small(512, 129, u64::MAX));
        assert_eq!(batch.len(), 130);
        sched.mark_fast(129);
        let expected_groups: Vec<usize> = if same_host {
            vec![64, 64, 2]
        } else {
            vec![130]
        };
        let src = Arc::new(Mutex::new(PipelineState {
            synchronous: true,
            ..Default::default()
        }));
        let dst = Arc::new(Mutex::new(PipelineState::default()));
        for &files in &expected_groups {
            src.lock().unwrap().replies.push_back(Response::SmallBlocks(
                (0..files)
                    .map(|_| {
                        let data = vec![0; 512];
                        Ok(SmallBlock {
                            source: Some(pipeline_job(b"source", data.len() as u64).entry.clone()),
                            hash: content_digest(&data),
                            data,
                        })
                    })
                    .collect(),
            ));
            dst.lock()
                .unwrap()
                .replies
                .push_back(Response::Applied(vec![None; files]));
        }

        let mut worker = pipeline_worker(&sched, &src, &dst, false);
        Arc::get_mut(&mut worker.opts).unwrap().same_host = same_host;
        worker.fast_batch(&mut batch).unwrap();
        let groups: Vec<usize> = dst
            .lock()
            .unwrap()
            .requests
            .iter()
            .filter_map(|request| match request {
                Request::PutSmallBatch(puts) => Some(puts.len()),
                _ => None,
            })
            .collect();
        assert_eq!(groups, expected_groups, "same_host={same_host}");
        assert_eq!(worker.progress.files_done.load(Relaxed), 130);
        sched.complete_fast_batch(batch.len());
        assert!(sched.finished());
    }
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
                            source: Some(pipeline_job(b"source", data.len() as u64).entry.clone()),
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
            let paths: Vec<_> = source
                .requests
                .iter()
                .flat_map(|request| match request {
                    Request::ReadSmallBatch(reads) => {
                        reads.iter().map(|read| read.path.clone()).collect()
                    }
                    _ => Vec::new(),
                })
                .collect();
            assert_eq!(
                paths,
                owned
                    .iter()
                    .map(|&idx| jobs[idx].src.clone())
                    .collect::<Vec<_>>()
            );
            assert!(source.replies.is_empty());
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
    for (adaptive, refreshed_ms, rtt_us, setup_ms, reply_wait_ms, expected) in [
        (false, 0, None, 0, 125, [4, 4, 4, 4, 5, 6, 7, 8]),
        (false, 0, Some(10_000), 0, 125, [4, 5, 6, 7, 8, 8, 8, 8]),
        (false, 0, None, 200, 125, [4, 5, 6, 7, 8, 8, 8, 8]),
        // Payload time does not contribute to the reported reply-start wait.
        (false, 0, None, 0, 0, [4, 5, 6, 7, 8, 8, 8, 8]),
        // The default adaptive group budget allows 250 ms of service.
        (true, 0, None, 0, 125, [4, 5, 6, 7, 8, 8, 8, 8]),
        (true, 0, None, 0, 300, [4, 4, 4, 4, 5, 6, 7, 8]),
        // A latency recheck also updates the source's stall allowance.
        (true, 300, None, 0, 500, [4, 5, 6, 7, 8, 8, 8, 8]),
        (true, 300, None, 0, 1300, [4, 4, 4, 4, 5, 6, 7, 8]),
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
                    source: Some(pipeline_job(b"source", data.len() as u64).entry.clone()),
                    hash: content_digest(&data),
                    data,
                })]));
            dst.lock()
                .unwrap()
                .replies
                .push_back(Response::Applied(vec![None]));
        }
        let mut worker = pipeline_worker(&Arc::new(Sched::new(512, 8192)), &src, &dst, false);
        if adaptive {
            Arc::get_mut(&mut worker.opts).unwrap().tuning = Default::default();
        }
        if refreshed_ms > 0 {
            worker.batch_budget.refreshed_latency(
                std::time::Duration::from_millis(refreshed_ms),
                std::time::Instant::now(),
            );
        }
        worker.gate.set_active(2);
        worker.setup_elapsed = std::time::Duration::from_millis(setup_ms);
        let mut results = (0..jobs.len()).map(|_| None).collect::<Vec<_>>();
        worker
            .transfer_small_batches(
                &jobs,
                {
                    let mut groups = (0..8).map(|i| i..i + 1);
                    move |_| groups.next()
                },
                &mut results,
            )
            .unwrap();
        assert!(results.iter().all(|r| matches!(r, Some(Ok(_)))));
        assert_eq!(src.lock().unwrap().sent_at_receive, expected);
    }
}

#[test]
fn empty_file_groups_only_request_metadata() {
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
    src.lock().unwrap().replies.push_back(Response::SmallBlocks(
        jobs.iter()
            .map(|job| {
                Ok(SmallBlock {
                    source: Some(job.entry.clone()),
                    data: Vec::new(),
                    hash: algorithm.hash(&[]),
                })
            })
            .collect(),
    ));
    let mut results = (0..jobs.len()).map(|_| None).collect::<Vec<_>>();
    worker
        .transfer_small_batches(
            &jobs,
            {
                let mut groups = std::iter::once(0..2);
                move |_| groups.next()
            },
            &mut results,
        )
        .unwrap();
    assert!(results.iter().all(|r| matches!(r, Some(Ok(_)))));
    let source = src.lock().unwrap();
    assert!(
        matches!(source.requests.as_slice(), [Request::ReadSmallBatch(reads)] if reads.iter().all(|read| read.len == 0))
    );
    assert!(source.replies.is_empty());
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
    ) -> Result<u64> {
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
fn fresh_capacity_keeps_a_sixty_four_inode_margin() {
    let assessment = |objects, available_inodes| FreshCapacityAssessment {
        check_bytes: true,
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
                                source: self.entries.get(&read.path).cloned(),
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
        ) -> Result<u64> {
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
    assert!(requests
        .iter()
        .all(|request| matches!(request, Request::ReadSmallBatch(_))));
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

#[test]
fn local_copy_progress_is_live_but_failure_retracts_completion_credit() {
    for failure in ["none", "error", "disconnect", "regression", "oversize"] {
        let sched = Arc::new(Sched::new(512, 8192));
        sched.push_file(pipeline_job(b"source", 4096));
        sched.scan_done();
        assert!(matches!(sched.next(), Item::File(0)));
        let src = Arc::new(Mutex::new(PipelineState::default()));
        let dst = Arc::new(Mutex::new(PipelineState::default()));
        let mut worker = pipeline_worker(&sched, &src, &dst, false);
        {
            let mut state = dst.lock().unwrap();
            state.progress = Some(worker.progress.clone());
            state.replies.extend([
                Response::CopyLocalProgress(1024),
                Response::CopyLocalProgress(match failure {
                    "regression" => 512,
                    "oversize" => 4097,
                    _ => 2048,
                }),
                if failure == "error" {
                    Response::Err("injected copy failure".into())
                } else {
                    Response::Ok
                },
                Response::Ok, // finalize
            ]);
            if failure == "disconnect" {
                state.fail_receive = Some(3);
            }
        }
        let job = worker.job(0);
        src.lock()
            .unwrap()
            .replies
            .push_back(Response::Stats(vec![Some(job.entry.clone())]));
        let result = worker.try_copy_local(0, &job);
        assert_eq!(result.is_ok(), failure == "none", "{failure}: {result:?}");
        assert_eq!(dst.lock().unwrap().progress_at_receive[1], (1024, 0));
        assert_eq!(
            worker.progress.bytes_done.load(Relaxed),
            if failure == "none" { 4096 } else { 0 }
        );
        assert_eq!(
            job.done.load(Relaxed),
            if failure == "none" { 4096 } else { 0 }
        );
        if matches!(failure, "regression" | "oversize") {
            assert!(result.unwrap_err().is::<RangeReplyMismatch>());
        }
        assert_eq!(
            dst.lock()
                .unwrap()
                .requests
                .iter()
                .filter(|r| matches!(r, Request::Finalize { .. }))
                .count(),
            usize::from(failure == "none")
        );
    }
}

#[test]
fn comparing_pull_pipelines_remote_reads_with_a_synchronous_destination() {
    for final_basis in [false, true] {
        for depth in [1, 4] {
            let (sched, handle, job) = pipeline_ranges(&[(0, 8192)]);
            {
                let mut jobs = sched.jobs.lock().unwrap();
                jobs[0].compare_ranges = true;
                jobs[0].compare_final = final_basis;
            }
            let src = Arc::new(Mutex::new(PipelineState {
                latency: Some(std::time::Duration::from_millis(20)),
                ..Default::default()
            }));
            let dst = Arc::new(Mutex::new(PipelineState {
                synchronous: true,
                ..Default::default()
            }));
            for window in (0..16).step_by(depth) {
                dst.lock()
                    .unwrap()
                    .replies
                    .push_back(Response::Hashes(vec![[0; 32]; depth]));
                for index in window..window + depth {
                    let off = index as u64 * 512;
                    let data = vec![1; 512];
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
            opts.dst_remote = false;
            opts.tuning.pipeline_depth = Some(depth);
            let start = std::time::Instant::now();
            let mut credited = 0;
            worker.transfer_range(&handle, &mut credited).unwrap();
            eprintln!(
                "compare pull: final={final_basis} depth={depth} RTT=20ms elapsed={:?}",
                start.elapsed()
            );
            assert_eq!(src.lock().unwrap().max_pending, depth);
            assert_eq!(credited, 8192);
            assert_eq!(job.done.load(Relaxed), 8192);
            assert_eq!(src.lock().unwrap().received, 16);
        }
    }
}

#[test]
fn bandwidth_limited_remote_sources_compare_before_pacing_only_differing_reads() {
    // A relay must pay before receiving data, just like a pull. Its local
    // forwarding write must not be the first place the limit is applied.
    for relay in [false, true] {
        for basis in [
            "final",
            "owned-partial",
            "candidate",
            "candidate-with-final",
            "candidate-reuse-off",
        ] {
            let sched = Arc::new(Sched::new(512, 8192));
            let mut job = pipeline_job(b"source", 1536);
            // Even a final file must not take precedence over an owned partial.
            if matches!(
                basis,
                "final" | "owned-partial" | "candidate-with-final" | "candidate-reuse-off"
            ) {
                job.dst_entry = Some(job.entry.clone());
            }
            sched.push_file(job.clone());
            sched.scan_done();
            assert!(matches!(sched.next(), Item::File(0)));
            let src = Arc::new(Mutex::new(PipelineState::default()));
            let dst = Arc::new(Mutex::new(PipelineState::default()));
            let data = vec![3; 512];
            src.lock().unwrap().replies.extend([
                Response::Hashes(vec![[1; 32], [2; 32], content_digest(&data)]),
                Response::Block {
                    off: 1024,
                    hash: content_digest(&data),
                    data,
                },
                Response::Stats(vec![Some(job.entry.clone())]),
            ]);
            dst.lock()
                .unwrap()
                .replies
                .push_back(Response::Prepared(Preparation {
                    partial_size: (basis == "owned-partial").then_some(1536),
                    has_candidates: basis.starts_with("candidate"),
                }));
            if matches!(basis, "final" | "candidate-with-final") {
                dst.lock().unwrap().replies.push_back(Response::HeldHashes {
                    hashes: vec![[1; 32], [2; 32], [9; 32]],
                    len: 1536,
                });
            }
            dst.lock().unwrap().replies.extend([
                Response::SeededBasis(SeededBasis {
                    hashes: if basis == "final" {
                        vec![[1; 32], [2; 32]]
                    } else {
                        vec![[1; 32], [2; 32], [9; 32]]
                    },
                    selected_final: basis == "final",
                }),
                Response::Ok, // write
                Response::Ok, // finalize
            ]);
            let mut worker = pipeline_worker(&sched, &src, &dst, false);
            let opts = Arc::get_mut(&mut worker.opts).unwrap();
            opts.src_remote = true;
            opts.dst_remote = relay;
            opts.tuning.bw_pacing = Some(crate::transfer_tuning::BwPacing::Average);
            if basis == "candidate-reuse-off" {
                opts.tuning.block_reuse = Some(crate::transfer_tuning::BlockReuse::Off);
            }
            worker.bwlimit = Some(Arc::new(BandwidthLimit::new(5120)));
            worker.progress.bytes_total.store(1536, Relaxed);
            worker.progress.files_total.store(1, Relaxed);
            worker.handle_file(0).unwrap();
            assert!(sched.finished());
            assert_eq!(worker.progress.bytes_unchanged.load(Relaxed), 1024);
            assert_eq!(worker.progress.bytes_done.load(Relaxed), 512);
            assert!(!worker.job(0).compare_ranges);
            let source = src.lock().unwrap();
            assert!(
                matches!(
                    source.requests.as_slice(),
                    [
                        Request::HashBlocks {
                            block: 512,
                            len: 1536,
                            ..
                        },
                        Request::ReadRange {
                            off: 1024,
                            len: 512,
                            ..
                        },
                        Request::StatMany { .. },
                    ]
                ),
                "{basis}: {:?}",
                source.requests
            );
            // The budget must be paid before sending the data request, not after
            // receiving its response. No upper bound assumes a quiet test machine.
            assert!(
                source.sent_at[1].duration_since(source.sent_at[0])
                    >= std::time::Duration::from_millis(100),
                "{basis}"
            );
            assert!(source.replies.is_empty());
            let destination = dst.lock().unwrap();
            assert!(destination.replies.is_empty());
            assert!(!destination
                .requests
                .iter()
                .any(|r| matches!(r, Request::StageBasis { .. } | Request::HashWindow { .. })));
            if !matches!(basis, "final" | "candidate-with-final") {
                assert!(destination.requests.iter().any(|r| matches!(r,
                    Request::SeedBasis { final_ranges: Some(ranges), .. } if ranges.is_empty()
                )));
            }
        }
    }
}

#[test]
fn retiring_small_batch_stops_issuing_and_excludes_its_draining_traffic() {
    for (synchronous_source, retirement) in [
        (true, "source"),
        (false, "source"),
        (true, "destination"),
        (false, "destination"),
        (true, "before"),
        (false, "before"),
    ] {
        let sched = Arc::new(Sched::new(4 << 20, 32 << 20));
        let jobs: Vec<_> = (0..512)
            .map(|i| pipeline_job(format!("file{i}").as_bytes(), 32 << 10))
            .collect();
        for job in &jobs {
            sched.push_file(job.clone());
        }
        sched.scan_done();
        assert!(matches!(sched.next(), Item::File(0)));
        // Worker 0 already owns its half. Dispatch worker 1 through the
        // production entry point so it claims the rest and owns the sole guard.
        let peer_count = sched.begin_fast_batch(2, jobs.len());
        let mut peer_batch = vec![0];
        peer_batch.extend(sched.take_small(32 << 10, peer_count - 1, u64::MAX));
        sched.mark_fast(peer_batch.len() - 1);
        let item = sched.next();
        assert!(matches!(item, Item::File(idx) if !peer_batch.contains(&idx)));
        let original: Vec<_> = (0..jobs.len())
            .filter(|idx| !peer_batch.contains(idx))
            .collect();
        let gate = Gate::new(2);
        gate.mark_ready(0);
        gate.mark_ready(1);
        if retirement == "before" {
            gate.set_active(1);
        }
        let src = Arc::new(Mutex::new(PipelineState {
            synchronous: synchronous_source,
            // Request retirement at either endpoint, or before the batch starts.
            gate_changes: if retirement == "source" {
                vec![(1, gate.clone(), 1)]
            } else {
                vec![]
            },
            tuning_check: Some((sched.clone(), gate.clone(), 1)),
            ..Default::default()
        }));
        let dst = Arc::new(Mutex::new(PipelineState {
            gate_changes: if retirement == "destination" {
                vec![(1, gate.clone(), 1)]
            } else {
                vec![]
            },
            tuning_check: Some((sched.clone(), gate.clone(), 1)),
            ..Default::default()
        }));
        let issued_groups = match (retirement, synchronous_source) {
            ("before", _) => 0,
            ("source", true) => 1,
            ("source", false) | ("destination", true) => 4,
            ("destination", false) => 7, // Four writes and three read-ahead groups.
            _ => unreachable!(),
        };
        let issued_files = issued_groups * 32;
        for _ in 0..issued_groups {
            src.lock().unwrap().replies.push_back(Response::SmallBlocks(
                (0..32)
                    .map(|_| {
                        let data = vec![42; 32 << 10];
                        Ok(SmallBlock {
                            source: Some(pipeline_job(b"source", data.len() as u64).entry.clone()),
                            hash: content_digest(&data),
                            data,
                        })
                    })
                    .collect(),
            ));
            dst.lock()
                .unwrap()
                .replies
                .push_back(Response::Applied(vec![None; 32]));
        }

        let mut worker = pipeline_worker(&sched, &src, &dst, false);
        worker.id = 1;
        worker.gate = gate.clone();
        worker.fast_batch_files = jobs.len();
        let opts = Arc::get_mut(&mut worker.opts).unwrap();
        opts.tuning.copy_path = None;
        opts.tuning.request_size = Some(4 << 20);
        worker.process_item(item).unwrap();
        assert_eq!(
            worker.progress.files_done.load(Relaxed),
            issued_files as u64
        );
        assert_eq!(
            worker.progress.bytes_done.load(Relaxed),
            (issued_files as u64) << 15
        );
        let source = src.lock().unwrap();
        let mut pending: std::collections::BTreeSet<_> = original.iter().copied().collect();
        for request in &source.requests {
            if let Request::ReadSmallBatch(reads) = request {
                for read in reads {
                    let idx = jobs.iter().position(|job| job.src == read.path).unwrap();
                    assert!(pending.remove(&idx), "read an unowned or duplicate file");
                }
            }
        }
        assert_eq!(pending.len(), original.len() - issued_files);
        assert_eq!(
            source.requests.len(),
            issued_groups,
            "rechecks travel with issued reads"
        );
        assert_eq!(
            source.received,
            source.requests.len(),
            "source replies drained"
        );
        assert!(source.tuning_snapshots.iter().all(|(_, ready)| !ready));
        drop(source);
        let destination = dst.lock().unwrap();
        assert_eq!(destination.requests.len(), issued_groups);
        assert_eq!(
            destination.received,
            destination.requests.len(),
            "destination replies drained"
        );
        assert!(destination.tuning_snapshots.iter().all(|(_, ready)| !ready));
        drop(destination);
        if retirement != "before" {
            let endpoint = if retirement == "source" { &src } else { &dst };
            let state = endpoint.lock().unwrap();
            let (work, ready) = &state.tuning_snapshots[0];
            assert_eq!(work.queued_files, 0);
            assert_eq!(work.unread_batch_files, original.len() - issued_files);
            assert!(work.parallel, "another worker can use the unread groups");
            assert!(!ready, "the retiring worker still contributes traffic");
        }
        assert!(
            gate.measurement_ready(1),
            "lower-count observations may begin after drain"
        );
        sched.complete_fast_batch(peer_batch.len());
        while !pending.is_empty() {
            let Item::File(idx) = sched.next() else {
                panic!("unissued work must remain available")
            };
            assert!(
                pending.remove(&idx),
                "no completed or duplicate file requeued"
            );
            assert!(sched.ranges_ready(idx, vec![]).is_none());
        }
        assert!(sched.finished());
    }
}

#[test]
fn range_dispatch_excludes_retiring_workers_through_both_endpoint_drains() {
    for path in ["ranges", "comparison", "streaming"] {
        for retire_at_source in [true, false] {
            let (sched, handle, job) = pipeline_ranges(&[(0, 16384), (32768, 33792)]);
            if path == "comparison" {
                sched.jobs.lock().unwrap()[0].compare_ranges = true;
            }
            let gate = Gate::new(2);
            gate.mark_ready(0);
            gate.mark_ready(1);
            let src = Arc::new(Mutex::new(PipelineState {
                auto_ranges: true,
                gate_changes: if retire_at_source {
                    vec![(if path == "streaming" { 2 } else { 1 }, gate.clone(), 1)]
                } else {
                    vec![]
                },
                tuning_check: Some((sched.clone(), gate.clone(), 1)),
                ..Default::default()
            }));
            let dst = Arc::new(Mutex::new(PipelineState {
                auto_ranges: true,
                gate_changes: if retire_at_source {
                    vec![]
                } else {
                    vec![(1, gate.clone(), 1)]
                },
                tuning_check: Some((sched.clone(), gate.clone(), 1)),
                ..Default::default()
            }));
            let mut worker = pipeline_worker(&sched, &src, &dst, path == "streaming");
            worker.id = 1;
            worker.gate = gate.clone();
            assert!(gate.measurement_ready(1));
            worker.process_item(Item::Range(handle)).unwrap();
            assert!(!gate.allowed(1));
            assert!(job.done.load(Relaxed) > 0, "path={path}");
            for endpoint in [&src, &dst] {
                let state = endpoint.lock().unwrap();
                assert!(!state.tuning_snapshots.is_empty(), "path={path}");
                assert!(
                    state.tuning_snapshots.iter().all(|(_, ready)| !ready),
                    "path={path}: retiring worker contributed traffic to the smaller count"
                );
                assert!(
                    state.replies.is_empty(),
                    "path={path}: replies left undrained"
                );
            }
            assert!(
                gate.measurement_ready(1),
                "path={path}: draining flag leaked"
            );
            assert!(!sched.finished(), "unread work remains for the kept worker");
        }
    }
}

#[test]
fn retired_dispatch_returns_unstarted_work_without_endpoint_requests() {
    for kind in ["file", "range", "finish", "matched-finish"] {
        let sched = Arc::new(Sched::new(512, 8192));
        sched.push_file(pipeline_job(b"source", 4096));
        sched.scan_done();
        let file = sched.next();
        assert!(matches!(file, Item::File(0)));
        let item = match kind {
            "file" => file,
            "range" => Item::Range(sched.ranges_ready(0, vec![(0, 4096)]).unwrap()),
            _ => {
                sched.ranges_ready(0, vec![]);
                sched.requeue_finish(0, kind == "matched-finish");
                sched.next()
            }
        };
        let gate = Gate::new(2);
        gate.mark_ready(0);
        gate.mark_ready(1);
        // Model a reduction after next() returns but before requests start.
        gate.set_active(1);
        let src = Arc::new(Mutex::new(PipelineState::default()));
        let dst = Arc::new(Mutex::new(PipelineState::default()));
        let mut worker = pipeline_worker(&sched, &src, &dst, false);
        worker.id = 1;
        worker.gate = gate.clone();
        assert!(
            !sched.finished(),
            "the tuner must see the claimed {kind} before the worker returns it"
        );
        worker.process_item(item).unwrap();
        assert!(!sched.finished(), "returned {kind} work remains runnable");
        assert!(src.lock().unwrap().requests.is_empty());
        assert!(dst.lock().unwrap().requests.is_empty());
        assert!(gate.measurement_ready(1));
        match sched.next() {
            Item::File(0) if kind == "file" => {
                sched.ranges_ready(0, vec![]);
            }
            Item::Range(handle) if kind == "range" => {
                let r = handle.lock().unwrap();
                assert_eq!((r.idx, r.pos, r.end), (0, 0, 4096));
                drop(r);
                assert!(sched.range_done(&handle));
            }
            Item::Finish { idx: 0, matched } if kind.ends_with("finish") => {
                assert_eq!(matched, kind == "matched-finish");
                assert!(!sched.finished(), "claimed publication is still live");
                sched.finish_done();
            }
            _ => panic!("lost or changed returned {kind} assignment"),
        }
        assert!(matches!(sched.next(), Item::Exit), "kind={kind}");
        assert!(sched.finished(), "kind={kind}");
    }
}

#[test]
fn publication_dispatch_excludes_retiring_workers_through_source_recheck() {
    for matched in [false, true] {
        for source_fails in [false, true] {
            let sched = Arc::new(Sched::new(512, 8192));
            let job = pipeline_job(b"source", 4096);
            job.done.store(4096, Relaxed);
            sched.push_file(job.clone());
            sched.scan_done();
            assert!(matches!(sched.next(), Item::File(0)));
            sched.ranges_ready(0, vec![]);
            let gate = Gate::new(2);
            gate.mark_ready(0);
            gate.mark_ready(1);
            let src = Arc::new(Mutex::new(PipelineState {
                replies: [if source_fails {
                    Response::Err("injected recheck failure".into())
                } else {
                    Response::Stats(vec![Some(job.entry.clone())])
                }]
                .into(),
                gate_changes: vec![(1, gate.clone(), 1)],
                tuning_check: Some((sched.clone(), gate.clone(), 1)),
                ..Default::default()
            }));
            let dst = Arc::new(Mutex::new(PipelineState {
                replies: if matched || source_fails {
                    Default::default()
                } else {
                    [Response::Ok].into()
                },
                gate_changes: vec![(1, gate.clone(), 1)],
                tuning_check: Some((sched.clone(), gate.clone(), 1)),
                ..Default::default()
            }));
            let mut worker = pipeline_worker(&sched, &src, &dst, false);
            worker.id = 1;
            worker.gate = gate.clone();
            worker.progress.files_total.store(1, Relaxed);
            sched.requeue_finish(0, matched);
            let item = sched.next();
            assert!(!sched.finished());
            worker.process_item(item).unwrap();
            assert!(
                sched.finished(),
                "publication claim leaked on success or failure"
            );
            assert!(!gate.allowed(1));
            assert!(gate.measurement_ready(1));
            assert_eq!(
                worker.progress.files_done.load(Relaxed),
                u64::from(!source_fails && !matched)
            );
            assert_eq!(
                worker.progress.files_unchanged.load(Relaxed),
                u64::from(!source_fails && matched)
            );
            assert_eq!(
                worker.progress.errors.load(Relaxed),
                u64::from(source_fails)
            );
            for endpoint in [&src, &dst] {
                let state = endpoint.lock().unwrap();
                assert!(state.tuning_snapshots.iter().all(|(_, ready)| !ready));
                assert!(state.replies.is_empty());
            }
            assert_eq!(src.lock().unwrap().received, 1, "source recheck ran");
            assert_eq!(
                dst.lock().unwrap().received,
                usize::from(!matched && !source_fails)
            );
        }
    }
}

#[test]
fn returned_last_publication_is_completed_by_the_remaining_worker() {
    for matched in [false, true] {
        let sched = Arc::new(Sched::new(512, 8192));
        let job = pipeline_job(b"source", 4096);
        job.done.store(4096, Relaxed);
        sched.push_file(job.clone());
        sched.scan_done();
        assert!(matches!(sched.next(), Item::File(0)));
        sched.ranges_ready(0, vec![]);
        sched.requeue_finish(0, matched);
        let item = sched.next();
        let gate = Gate::new(2);
        gate.mark_ready(0);
        gate.mark_ready(1);
        gate.set_active(1);
        // This is the reviewer's race: worker 1 has the last publication,
        // but is retired before dispatch. The tuner must not observe completion.
        assert!(!sched.finished());
        let src = Arc::new(Mutex::new(PipelineState {
            replies: [Response::Stats(vec![Some(job.entry.clone())])].into(),
            ..Default::default()
        }));
        let dst = Arc::new(Mutex::new(PipelineState {
            replies: if matched {
                Default::default()
            } else {
                [Response::Ok].into()
            },
            ..Default::default()
        }));
        let mut worker = pipeline_worker(&sched, &src, &dst, false);
        worker.id = 1;
        worker.gate = gate;
        worker.progress.files_total.store(1, Relaxed);
        worker.process_item(item).unwrap();
        assert!(!sched.finished());
        assert!(src.lock().unwrap().requests.is_empty());
        assert!(dst.lock().unwrap().requests.is_empty());
        worker.id = 0;
        worker.process_item(sched.next()).unwrap();
        assert!(sched.finished());
        assert!(matches!(sched.next(), Item::Exit));
        assert_eq!(
            worker.progress.files_done.load(Relaxed),
            u64::from(!matched)
        );
        assert_eq!(
            worker.progress.files_unchanged.load(Relaxed),
            u64::from(matched)
        );
    }
}

#[test]
fn publication_connection_failure_releases_claim_after_queuing_retry() {
    for matched in [false, true] {
        let sched = Arc::new(Sched::new(512, 8192));
        let job = pipeline_job(b"source", 4096);
        job.done.store(4096, Relaxed);
        sched.push_file(job.clone());
        sched.scan_done();
        assert!(matches!(sched.next(), Item::File(0)));
        sched.ranges_ready(0, vec![]);
        sched.requeue_finish(0, matched);
        let src = Arc::new(Mutex::new(PipelineState {
            fail_receive: Some(1),
            ..Default::default()
        }));
        let dst = Arc::new(Mutex::new(PipelineState {
            replies: if matched {
                Default::default()
            } else {
                [Response::Ok].into()
            },
            ..Default::default()
        }));
        let mut worker = pipeline_worker(&sched, &src, &dst, false);
        let error = worker.process_item(sched.next()).unwrap_err();
        assert!(error.to_string().contains("injected connection loss"));
        assert!(!sched.finished(), "retry is still runnable");
        // Replace the failed source connection, then consume the same publication.
        *src.lock().unwrap() = PipelineState {
            replies: [Response::Stats(vec![Some(job.entry.clone())])].into(),
            ..Default::default()
        };
        if !matched {
            dst.lock().unwrap().replies.push_back(Response::Ok);
        }
        worker.progress.files_total.store(1, Relaxed);
        worker.process_item(sched.next()).unwrap();
        assert!(
            sched.finished(),
            "failed claim must not leak into the retry"
        );
    }
}

#[test]
fn local_copy_dispatch_keeps_retirement_guard_through_progress_and_failures() {
    for failure in [
        "none",
        "copy-disconnect",
        "finalize-disconnect",
        "source-error",
    ] {
        let sched = Arc::new(Sched::new(512, 8192));
        // Above the local small-file threshold, so dispatch selects CopyLocal.
        let job = pipeline_job(b"source", 128 << 10);
        sched.push_file(job.clone());
        sched.scan_done();
        let item = sched.next();
        let gate = Gate::new(2);
        gate.mark_ready(0);
        gate.mark_ready(1);
        let src = Arc::new(Mutex::new(PipelineState {
            replies: [if failure == "source-error" {
                Response::Err("injected recheck failure".into())
            } else {
                Response::Stats(vec![Some(job.entry.clone())])
            }]
            .into(),
            tuning_check: Some((sched.clone(), gate.clone(), 1)),
            ..Default::default()
        }));
        let dst = Arc::new(Mutex::new(PipelineState {
            replies: [
                Response::CopyLocalProgress(64 << 10),
                Response::Ok,
                Response::Ok,
            ]
            .into(),
            fail_receive: match failure {
                "copy-disconnect" => Some(2),
                "finalize-disconnect" => Some(3),
                _ => None,
            },
            gate_changes: vec![(1, gate.clone(), 1)],
            tuning_check: Some((sched.clone(), gate.clone(), 1)),
            ..Default::default()
        }));
        let mut worker = pipeline_worker(&sched, &src, &dst, false);
        worker.id = 1;
        worker.gate = gate.clone();
        let opts = Arc::get_mut(&mut worker.opts).unwrap();
        opts.same_host = true;
        opts.dst_remote = false;
        opts.tuning.copy_path = None;
        let result = worker.process_item(item);
        assert_eq!(
            result.is_err(),
            failure.ends_with("disconnect"),
            "{failure}"
        );
        assert!(!gate.allowed(1));
        assert!(gate.measurement_ready(1), "guard leaked on {failure}");
        assert!(matches!(
            dst.lock().unwrap().requests[0],
            Request::CopyLocal { .. }
        ));
        for endpoint in [&src, &dst] {
            let state = endpoint.lock().unwrap();
            assert!(
                state.tuning_snapshots.iter().all(|(_, ready)| !ready),
                "{failure}: retired local-copy work leaked into a lower-count sample"
            );
        }
        assert_eq!(
            worker.progress.bytes_done.load(Relaxed),
            if failure == "copy-disconnect" {
                0
            } else {
                job.entry.size
            }
        );
        assert_eq!(
            worker.progress.files_done.load(Relaxed),
            u64::from(failure == "none")
        );
        assert_eq!(
            worker.progress.errors.load(Relaxed),
            u64::from(failure == "source-error")
        );
        assert_eq!(sched.finished(), !failure.ends_with("disconnect"));
    }
}

#[test]
fn adaptive_batches_leave_work_for_peers_including_empty_files() {
    for size in [0, 1024, 32 << 10] {
        let sched = Arc::new(Sched::new(4 << 20, 32 << 20));
        for i in 0..512 {
            sched.push_file(pipeline_job(format!("file{i}").as_bytes(), size));
        }
        sched.scan_done();
        let item = sched.next();
        let src = Arc::new(Mutex::new(PipelineState {
            auto_small_size: Some(size),
            ..Default::default()
        }));
        let dst = Arc::new(Mutex::new(PipelineState {
            auto_small_size: Some(size),
            steal_on_receive: Some(sched.clone()),
            ..Default::default()
        }));
        let mut owner = pipeline_worker(&sched, &src, &dst, false);
        let opts = Arc::get_mut(&mut owner.opts).unwrap();
        opts.tuning = Default::default();
        opts.block = 4 << 20;
        owner.fast_batch_files = 2048;
        owner.process_item(item).unwrap();
        let stolen = dst
            .lock()
            .unwrap()
            .stolen_file
            .expect("peer claimed unread work");
        let completed_by_owner = owner.progress.files_done.load(Relaxed);
        assert!(completed_by_owner > 0 && completed_by_owner < 512);
        owner.process_item(Item::File(stolen)).unwrap();
        owner.run_inner().unwrap();
        assert!(sched.finished());
        assert_eq!(owner.progress.files_done.load(Relaxed), 512);
        assert_eq!(owner.progress.bytes_done.load(Relaxed), 512 * size);
        let state = dst.lock().unwrap();
        let paths: Vec<_> = state
            .requests
            .iter()
            .filter_map(|r| match r {
                Request::PutSmallBatch(puts) => Some(puts),
                _ => None,
            })
            .flatten()
            .map(|put| put.path.clone())
            .collect();
        assert_eq!(paths.len(), 512);
        assert_eq!(
            paths.iter().collect::<std::collections::HashSet<_>>().len(),
            512,
            "every file published exactly once despite stealing"
        );
        assert!(state.replies.is_empty());
        assert!(src.lock().unwrap().replies.is_empty());
    }
}

#[test]
fn aged_batch_requests_drain_before_refill_at_either_endpoint() {
    for slow_source in [true, false] {
        let size = 1024;
        let delay = std::time::Duration::from_millis(600);
        let src = Arc::new(Mutex::new(PipelineState {
            auto_small_size: Some(size),
            latency: slow_source.then_some(delay),
            ..Default::default()
        }));
        let dst = Arc::new(Mutex::new(PipelineState {
            auto_small_size: Some(size),
            latency: (!slow_source).then_some(delay),
            ..Default::default()
        }));
        let mut worker =
            pipeline_worker(&Arc::new(Sched::new(4 << 20, 32 << 20)), &src, &dst, false);
        Arc::get_mut(&mut worker.opts).unwrap().tuning = Default::default();
        let jobs: Vec<_> = (0..512)
            .map(|i| pipeline_snapshot(pipeline_job(format!("file{i}").as_bytes(), size)))
            .collect();
        let mut next = 0;
        let mut limits = Vec::new();
        let mut results = (0..jobs.len()).map(|_| None).collect::<Vec<_>>();
        worker
            .transfer_small_batches(
                &jobs,
                |limit| {
                    if next == jobs.len() {
                        return None;
                    }
                    limits.push(limit);
                    let end = (next + limit.files.min((limit.bytes / size).max(1) as usize))
                        .min(jobs.len());
                    let group = next..end;
                    next = end;
                    Some(group)
                },
                &mut results,
            )
            .unwrap();
        assert!(results.iter().all(|r| matches!(r, Some(Ok(_)))));
        let source = src.lock().unwrap();
        if slow_source {
            assert_eq!(
                &source.sent_at_receive[..4],
                &[4, 4, 4, 4],
                "old reads stop refill before any acknowledgment"
            );
        } else {
            assert_eq!(
                &source.sent_at_receive[4..7],
                &[7, 7, 7],
                "old writes also stop source refill"
            );
        }
        assert!(
            limits
                .iter()
                .skip(4)
                .any(|limit| limit.bytes < (64 << 10) && limit.files < 64),
            "slow service shrinks both budgets: {limits:?}"
        );
        assert!(source.replies.is_empty());
        assert!(dst.lock().unwrap().replies.is_empty());
    }
}

#[test]
fn acknowledged_batch_writes_do_not_stall_source_refill() {
    let size = 32 << 10;
    let src = Arc::new(Mutex::new(PipelineState {
        auto_small_size: Some(size),
        latency: Some(std::time::Duration::from_millis(300)),
        ..Default::default()
    }));
    let dst = Arc::new(Mutex::new(PipelineState {
        auto_small_size: Some(size),
        immediate_batch_receipts: Some(Arc::new(crate::conn::BatchReceipts::default())),
        ..Default::default()
    }));
    let mut worker = pipeline_worker(&Arc::new(Sched::new(4 << 20, 32 << 20)), &src, &dst, false);
    Arc::get_mut(&mut worker.opts).unwrap().tuning = Default::default();
    let jobs: Vec<_> = (0..20)
        .map(|i| pipeline_snapshot(pipeline_job(format!("file{i}").as_bytes(), size)))
        .collect();
    let mut next = 0;
    let mut results = (0..jobs.len()).map(|_| None).collect::<Vec<_>>();
    worker
        .transfer_small_batches(
            &jobs,
            |_| {
                if next == jobs.len() {
                    return None;
                }
                let group = next..next + 1;
                next += 1;
                Some(group)
            },
            &mut results,
        )
        .unwrap();
    let source = src.lock().unwrap();
    assert_eq!(
        source.sent_at_receive,
        (0..jobs.len())
            .map(|i| (i + 4).min(jobs.len()))
            .collect::<Vec<_>>(),
        "source reads stay pipelined: queued but acknowledged writes are not overdue"
    );
    assert!(results.iter().all(|r| matches!(r, Some(Ok(_)))));
    assert_eq!(
        worker.progress.bytes_done.load(Relaxed),
        size * jobs.len() as u64
    );
    assert!(source.replies.is_empty());
    assert!(dst.lock().unwrap().replies.is_empty());
}

#[test]
fn received_batch_feedback_sizes_the_next_source_request() {
    for outcome in ["success", "rejected", "aborted"] {
        let sched = Arc::new(Sched::new(4 << 20, 32 << 20));
        let size = 32 << 10;
        let src = Arc::new(Mutex::new(PipelineState {
            auto_small_size: Some(size),
            ..Default::default()
        }));
        let dst = Arc::new(Mutex::new(PipelineState {
            auto_small_size: Some(size),
            immediate_batch_receipts: Some(Arc::new(crate::conn::BatchReceipts::default())),
            reject_small_puts: outcome == "rejected",
            abort_on_receive: (outcome == "aborted").then(|| sched.clone()),
            ..Default::default()
        }));
        let mut worker = pipeline_worker(&sched, &src, &dst, false);
        Arc::get_mut(&mut worker.opts).unwrap().tuning = Default::default();
        let jobs: Vec<_> = (0..12)
            .map(|i| pipeline_snapshot(pipeline_job(format!("file{i}").as_bytes(), size)))
            .collect();
        let mut next = 0;
        let mut limits = Vec::new();
        let mut results = (0..jobs.len()).map(|_| None).collect::<Vec<_>>();
        worker
            .transfer_small_batches(
                &jobs,
                |limit| {
                    if next == jobs.len() {
                        return None;
                    }
                    limits.push(limit);
                    let group = next..next + 1;
                    next += 1;
                    Some(group)
                },
                &mut results,
            )
            .unwrap();
        if outcome == "rejected" {
            assert_eq!(next, 4, "reject before claiming more source work");
            assert!(matches!(results[0], Some(Err(_))));
            assert!(results[1..].iter().all(Option::is_none));
            assert_eq!(worker.progress.bytes_done.load(Relaxed), 0);
            assert_eq!(dst.lock().unwrap().requests.len(), 1);
        } else if outcome == "aborted" {
            assert_eq!(
                next, 4,
                "an abort during receipt consumption stops new claims"
            );
            assert!(results[..4].iter().all(|r| matches!(r, Some(Ok(_)))));
            assert!(results[4..].iter().all(Option::is_none));
            assert_eq!(worker.progress.bytes_done.load(Relaxed), size * 4);
        } else {
            assert_eq!(
                limits[4].bytes,
                256 << 10,
                "first receipt updates the next claim"
            );
            assert!(results.iter().all(|r| matches!(r, Some(Ok(_)))));
            assert_eq!(
                worker.progress.bytes_done.load(Relaxed),
                size * jobs.len() as u64
            );
        }
        assert!(
            src.lock().unwrap().replies.is_empty(),
            "issued reads drained"
        );
        assert!(
            dst.lock().unwrap().replies.is_empty(),
            "issued writes drained"
        );
    }
}

#[test]
fn aborted_batches_stop_claiming_groups_and_drain_issued_requests() {
    let sched = Arc::new(Sched::new(4 << 20, 32 << 20));
    let size = 1024;
    for i in 0..512 {
        sched.push_file(pipeline_job(format!("file{i}").as_bytes(), size));
    }
    sched.scan_done();
    let src = Arc::new(Mutex::new(PipelineState {
        auto_small_size: Some(size),
        abort_on_receive: Some(sched.clone()),
        ..Default::default()
    }));
    let dst = Arc::new(Mutex::new(PipelineState {
        auto_small_size: Some(size),
        ..Default::default()
    }));
    let mut worker = pipeline_worker(&sched, &src, &dst, false);
    let opts = Arc::get_mut(&mut worker.opts).unwrap();
    opts.tuning = Default::default();
    opts.block = 4 << 20;
    worker.fast_batch_files = 2048;
    worker.process_item(sched.next()).unwrap();
    assert!(sched.is_aborted());
    let source = src.lock().unwrap();
    let reads: Vec<_> = source
        .requests
        .iter()
        .filter_map(|r| match r {
            Request::ReadSmallBatch(reads) => Some(reads),
            _ => None,
        })
        .collect();
    assert_eq!(
        reads.len(),
        4,
        "abort prevents refilling the initial read window"
    );
    assert_eq!(reads.iter().map(|r| r.len()).sum::<usize>(), 256);
    assert_eq!(worker.progress.bytes_done.load(Relaxed), 256 * size);
    assert_eq!(worker.progress.files_done.load(Relaxed), 256);
    assert_eq!(worker.progress.errors.load(Relaxed), 0);
    assert!(source.replies.is_empty(), "issued source replies drained");
    let destination = dst.lock().unwrap();
    assert!(
        destination.replies.is_empty(),
        "issued destination replies drained"
    );
    assert_eq!(destination.received, destination.requests.len());
    assert_eq!(
        sched.tuning_work(1, 0, 0).unread_batch_files,
        0,
        "no leaked batch ownership"
    );
}

#[test]
fn explicit_batch_request_and_pipeline_settings_keep_fixed_grouping() {
    for option in [
        "batch-files=128",
        "batch-bytes=2M",
        "request-size=1M",
        "pipeline-depth=8",
    ] {
        let sched = Arc::new(Sched::new(4 << 20, 32 << 20));
        for i in 0..512 {
            sched.push_file(pipeline_job(format!("file{i}").as_bytes(), 32 << 10));
        }
        sched.scan_done();
        let src = Arc::new(Mutex::new(PipelineState {
            auto_small_size: Some(32 << 10),
            ..Default::default()
        }));
        let dst = Arc::new(Mutex::new(PipelineState {
            auto_small_size: Some(32 << 10),
            ..Default::default()
        }));
        let mut worker = pipeline_worker(&sched, &src, &dst, false);
        let opts = Arc::get_mut(&mut worker.opts).unwrap();
        opts.tuning = option.parse().unwrap();
        opts.block = 4 << 20;
        worker.fast_batch_files = opts.tuning.batch_files.unwrap_or(2048);
        worker.process_item(sched.next()).unwrap();
        let source = src.lock().unwrap();
        let reads: Vec<_> = source
            .requests
            .iter()
            .filter_map(|request| match request {
                Request::ReadSmallBatch(reads) => Some(reads),
                _ => None,
            })
            .collect();
        assert!(!reads.is_empty());
        assert!(
            reads.iter().all(|reads| reads.len() == 32),
            "{option}: fixed 1 MiB groups, not adaptive 64 KiB startup groups"
        );
        assert_eq!(
            worker.progress.files_done.load(Relaxed),
            (32 * reads.len()) as u64
        );
        assert!(source.replies.is_empty());
        assert!(dst.lock().unwrap().replies.is_empty());
    }
}

#[test]
fn batch_latency_recheck_distinguishes_queue_delay_from_slow_file_work() {
    use std::time::{Duration, Instant};
    for network_delay in [true, false] {
        let size = 16 << 10;
        let src = Arc::new(Mutex::new(PipelineState {
            auto_small_size: Some(size),
            latency: Some(Duration::from_millis(300)),
            configuration_latency: network_delay.then_some(Duration::from_millis(300)),
            ..Default::default()
        }));
        let dst = Arc::new(Mutex::new(PipelineState {
            auto_small_size: Some(size),
            synchronous: true,
            immediate_batch_receipts: Some(Arc::new(crate::conn::BatchReceipts::default())),
            ..Default::default()
        }));
        let mut worker =
            pipeline_worker(&Arc::new(Sched::new(4 << 20, 32 << 20)), &src, &dst, false);
        Arc::get_mut(&mut worker.opts).unwrap().tuning = Default::default();
        worker.gate = Gate::new(8);
        worker
            .batch_budget
            .refreshed_latency(Duration::ZERO, Instant::now() - Duration::from_secs(60));
        let count = if network_delay { 128 } else { 24 };
        let jobs: Vec<_> = (0..count)
            .map(|i| pipeline_snapshot(pipeline_job(format!("file{i}").as_bytes(), size)))
            .collect();
        let mut next = 0;
        let mut results = (0..jobs.len()).map(|_| None).collect::<Vec<_>>();
        worker
            .transfer_small_batches(
                &jobs,
                |limit| {
                    if next == jobs.len() {
                        return None;
                    }
                    let end = (next + limit.files.min((limit.bytes / size).max(1) as usize))
                        .min(jobs.len());
                    let group = next..end;
                    next = end;
                    Some(group)
                },
                &mut results,
            )
            .unwrap();
        assert!(results.iter().all(|r| matches!(r, Some(Ok(_)))));
        let source = src.lock().unwrap();
        let probe = source
            .requests
            .iter()
            .position(|r| matches!(r, Request::ConfigureHashing(_)))
            .expect("rechecked latency");
        assert_eq!(
            source
                .requests
                .iter()
                .filter(|r| matches!(r, Request::ConfigureHashing(_)))
                .count(),
            1,
            "checks do not repeat for every late group"
        );
        assert!(source.max_pending <= 4 && source.replies.is_empty());
        let groups: Vec<_> = source.requests[probe + 1..]
            .iter()
            .filter_map(|r| match r {
                Request::ReadSmallBatch(reads) => Some(reads.len()),
                _ => None,
            })
            .collect();
        if network_delay {
            assert!(worker.batch_budget.latency_target() >= Duration::from_millis(1200));
            assert!(
                groups.iter().any(|&n| n > 4),
                "groups must recover beyond the startup budget: {groups:?}"
            );
        } else {
            assert_eq!(
                worker.batch_budget.latency_target(),
                Duration::from_millis(250)
            );
            assert!(
                groups.iter().all(|&n| n <= 4),
                "slow file work still leaves small groups: {groups:?}"
            );
        }
        let destination = dst.lock().unwrap();
        assert!(destination.replies.is_empty());
        assert_eq!(
            destination
                .requests
                .iter()
                .filter(|r| matches!(r, Request::ConfigureHashing(_)))
                .count(),
            1
        );
        assert_eq!(
            worker.progress.bytes_done.load(Relaxed),
            size * count as u64
        );
    }
}

#[test]
fn batch_latency_recheck_honors_abort_and_retirement_before_more_requests() {
    use std::time::{Duration, Instant};
    for abort in [true, false] {
        let size = 16 << 10;
        let sched = Arc::new(Sched::new(4 << 20, 32 << 20));
        let gate = Gate::new(2);
        let src = Arc::new(Mutex::new(PipelineState {
            auto_small_size: Some(size),
            latency: Some(Duration::from_millis(300)),
            abort_on_receive: abort.then(|| sched.clone()),
            abort_receive_number: Some(5),
            gate_changes: if abort {
                Vec::new()
            } else {
                vec![(5, gate.clone(), 1)]
            },
            ..Default::default()
        }));
        let dst = Arc::new(Mutex::new(PipelineState {
            auto_small_size: Some(size),
            synchronous: true,
            immediate_batch_receipts: Some(Arc::new(crate::conn::BatchReceipts::default())),
            ..Default::default()
        }));
        let mut worker = pipeline_worker(&sched, &src, &dst, false);
        Arc::get_mut(&mut worker.opts).unwrap().tuning = Default::default();
        worker.id = 1;
        worker.gate = gate;
        worker
            .batch_budget
            .refreshed_latency(Duration::ZERO, Instant::now() - Duration::from_secs(60));
        let jobs: Vec<_> = (0..64)
            .map(|i| pipeline_snapshot(pipeline_job(format!("file{i}").as_bytes(), size)))
            .collect();
        let mut next = 0;
        let mut results = (0..jobs.len()).map(|_| None).collect::<Vec<_>>();
        worker
            .transfer_small_batches(
                &jobs,
                |limit| {
                    if next == jobs.len() {
                        return None;
                    }
                    let end = (next + limit.files.min((limit.bytes / size).max(1) as usize))
                        .min(jobs.len());
                    let group = next..end;
                    next = end;
                    Some(group)
                },
                &mut results,
            )
            .unwrap();
        let source = src.lock().unwrap();
        assert_eq!(
            source.requests.len(),
            5,
            "four data groups, then the latency check"
        );
        assert!(matches!(
            source.requests.last(),
            Some(Request::ConfigureHashing(_))
        ));
        assert!(source.replies.is_empty());
        let destination = dst.lock().unwrap();
        assert_eq!(
            destination.requests.len(),
            4,
            "stop even before the other latency RPC"
        );
        assert!(destination.replies.is_empty());
        assert_eq!(next, 16, "no further work admitted");
        assert!(results[..16].iter().all(|r| matches!(r, Some(Ok(_)))));
        assert!(results[16..].iter().all(Option::is_none));
    }
}

#[test]
fn adaptive_ordinary_reads_expose_slow_unread_tails_to_peers() {
    let block = 4 << 20;
    let size = 16 << 20;
    let sched = Arc::new(Sched::new(block, 32 << 20));
    let idx = sched.push_file(pipeline_job(b"file", size));
    sched.scan_done();
    assert!(matches!(sched.next(), Item::File(_)));
    let range = sched.ranges_ready(idx, vec![(0, size)]).unwrap();
    let src = Arc::new(Mutex::new(PipelineState {
        auto_ranges: true,
        steal_range_at: Some((5, sched.clone())),
        ..Default::default()
    }));
    let dst = Arc::new(Mutex::new(PipelineState {
        auto_ranges: true,
        // Inject service time without a slow or timing-sensitive test.
        arrival_delay: Some(std::time::Duration::from_secs(1)),
        ..Default::default()
    }));
    let mut worker = pipeline_worker(&sched, &src, &dst, false);
    let opts = Arc::get_mut(&mut worker.opts).unwrap();
    opts.block = block;
    opts.tuning = Default::default();
    let mut credited = 0;
    worker.transfer_range(&range, &mut credited).unwrap();
    let peer_range = src
        .lock()
        .unwrap()
        .stolen_range
        .take()
        .expect("peer claimed tail");
    assert!(!sched.range_done(&range));
    let peer_src = Arc::new(Mutex::new(PipelineState {
        auto_ranges: true,
        ..Default::default()
    }));
    let peer_dst = Arc::new(Mutex::new(PipelineState {
        auto_ranges: true,
        ..Default::default()
    }));
    let mut peer = pipeline_worker(&sched, &peer_src, &peer_dst, false);
    Arc::get_mut(&mut peer.opts).unwrap().block = block;
    let mut peer_credited = 0;
    peer.transfer_range(&peer_range, &mut peer_credited)
        .unwrap();
    assert!(sched.range_done(&peer_range));
    assert!(matches!(sched.next(), Item::Exit));
    assert_eq!(credited + peer_credited, size);
    assert!(credited > 0 && peer_credited > 0);
    let mut writes = Vec::new();
    for endpoint in [&dst, &peer_dst] {
        let state = endpoint.lock().unwrap();
        assert_eq!(state.requests.len(), state.received);
        for request in &state.requests {
            if let Request::WriteRange { off, data, .. } = request {
                assert!(data.iter().all(|byte| *byte == 42));
                writes.push((*off, data.len() as u64));
            }
        }
    }
    writes.sort_unstable();
    let mut end = 0;
    for (off, len) in writes {
        assert_eq!(off, end);
        end += len;
    }
    assert_eq!(end, size, "each byte written exactly once across the steal");
}

#[test]
fn explicit_range_controls_preserve_fixed_requests() {
    let block = 4 << 20;
    for (options, legacy_block) in [
        ("request-size=4M", false),
        ("pipeline-depth=4", false),
        ("comparison-block-size=4M", false),
        ("split-min-size=32M", false),
        ("", true),
    ] {
        let sched = Arc::new(Sched::new(block, 32 << 20));
        let idx = sched.push_file(pipeline_job(b"file", 2 * block));
        sched.scan_done();
        assert!(matches!(sched.next(), Item::File(_)));
        let range = sched.ranges_ready(idx, vec![(0, 2 * block)]).unwrap();
        let src = Arc::new(Mutex::new(PipelineState {
            auto_ranges: true,
            ..Default::default()
        }));
        let dst = Arc::new(Mutex::new(PipelineState {
            auto_ranges: true,
            ..Default::default()
        }));
        let mut worker = pipeline_worker(&sched, &src, &dst, false);
        let opts = Arc::get_mut(&mut worker.opts).unwrap();
        opts.block = block;
        opts.block_explicit = legacy_block;
        opts.tuning = if options.is_empty() {
            Default::default()
        } else {
            options.parse().unwrap()
        };
        worker.transfer_range(&range, &mut 0).unwrap();
        assert!(range.lock().unwrap().split.is_none());
        let state = src.lock().unwrap();
        assert_eq!(state.requests.len(), 2, "{options} legacy={legacy_block}");
        assert!(state
            .requests
            .iter()
            .all(|r| matches!(r, Request::ReadRange { len, .. } if u64::from(*len)==block)));
    }
}

#[test]
fn adaptive_ordinary_ranges_drain_on_abort_and_retirement() {
    for abort in [false, true] {
        let block = 4 << 20;
        let sched = Arc::new(Sched::new(block, 32 << 20));
        let idx = sched.push_file(pipeline_job(b"file", 8 << 20));
        sched.scan_done();
        assert!(matches!(sched.next(), Item::File(_)));
        let range = sched.ranges_ready(idx, vec![(0, 8 << 20)]).unwrap();
        let src = Arc::new(Mutex::new(PipelineState {
            auto_ranges: true,
            ..Default::default()
        }));
        let dst = Arc::new(Mutex::new(PipelineState {
            auto_ranges: true,
            ..Default::default()
        }));
        let mut worker = pipeline_worker(&sched, &src, &dst, false);
        let opts = Arc::get_mut(&mut worker.opts).unwrap();
        opts.block = block;
        opts.tuning = Default::default();
        if abort {
            src.lock().unwrap().abort_on_receive = Some(sched.clone());
        } else {
            src.lock()
                .unwrap()
                .gate_changes
                .push((1, worker.gate.clone(), 0));
        }
        worker.transfer_range(&range, &mut 0).unwrap();
        let source = src.lock().unwrap();
        let destination = dst.lock().unwrap();
        assert_eq!(
            source.requests.len(),
            4,
            "stop refilling after cancellation"
        );
        assert_eq!(source.received, source.requests.len());
        assert_eq!(destination.received, destination.requests.len());
        drop(destination);
        drop(source);
        assert!(
            !sched.range_done(&range),
            "cancelled/returned work cannot publish"
        );
        if abort {
            assert!(matches!(sched.next(), Item::Exit));
        } else {
            let Item::Range(tail) = sched.next() else {
                panic!("unread tail returned")
            };
            assert_eq!(tail.lock().unwrap().pos, 4 * (1 << 20));
            assert!(sched.range_done(&tail));
        }
    }
}

#[test]
fn ordinary_range_latency_rechecks_preserve_ownership_on_stop() {
    use std::time::{Duration, Instant};
    for stop in ["none", "abort", "retire"] {
        let block = 4 << 20;
        let size = 16 << 20;
        let sched = Arc::new(Sched::new(block, 32 << 20));
        let idx = sched.push_file(pipeline_job(b"file", size));
        sched.scan_done();
        assert!(matches!(sched.next(), Item::File(_)));
        let range = sched.ranges_ready(idx, vec![(0, size)]).unwrap();
        let src = Arc::new(Mutex::new(PipelineState {
            auto_ranges: true,
            ..Default::default()
        }));
        let dst = Arc::new(Mutex::new(PipelineState {
            auto_ranges: true,
            ..Default::default()
        }));
        let mut worker = pipeline_worker(&sched, &src, &dst, false);
        let opts = Arc::get_mut(&mut worker.opts).unwrap();
        opts.block = block;
        opts.tuning = Default::default();
        let mut budget = WorkBudget::ranges(block, Duration::from_millis(600));
        budget.refreshed_latency(
            Duration::from_millis(150),
            Instant::now() - Duration::from_secs(60),
        );
        worker.range_budget = Some(budget);
        if stop == "abort" {
            src.lock().unwrap().abort_on_receive = Some(sched.clone());
        } else if stop == "retire" {
            src.lock()
                .unwrap()
                .gate_changes
                .push((1, worker.gate.clone(), 0));
        }
        let mut credited = 0;
        worker.transfer_range(&range, &mut credited).unwrap();
        let source = src.lock().unwrap();
        let destination = dst.lock().unwrap();
        assert!(matches!(
            source.requests.first(),
            Some(Request::ConfigureHashing(_))
        ));
        assert_eq!(source.requests.len(), source.received);
        assert_eq!(destination.requests.len(), destination.received);
        if stop == "none" {
            assert_eq!(credited, size);
            assert!(matches!(
                destination.requests.first(),
                Some(Request::ConfigureHashing(_))
            ));
            assert!(sched.range_done(&range));
        } else {
            assert_eq!(credited, 0);
            assert_eq!(
                source.requests.len(),
                1,
                "no reads after stop during recheck"
            );
            assert!(
                destination.requests.is_empty(),
                "no second configuration after stop"
            );
            assert!(!sched.range_done(&range));
            if stop == "retire" {
                let Item::Range(tail) = sched.next() else {
                    panic!("unread range returned")
                };
                assert_eq!(tail.lock().unwrap().pos, 0);
                assert!(sched.range_done(&tail));
            }
        }
        assert!(matches!(sched.next(), Item::Exit));
    }
}

#[test]
fn arrived_range_writes_update_progress_before_the_next_source_reply() {
    let block = 4 << 20;
    let size = 8 << 20;
    let sched = Arc::new(Sched::new(block, 32 << 20));
    let idx = sched.push_file(pipeline_job(b"file", size));
    sched.scan_done();
    assert!(matches!(sched.next(), Item::File(_)));
    let range = sched.ranges_ready(idx, vec![(0, size)]).unwrap();
    let src = Arc::new(Mutex::new(PipelineState {
        auto_ranges: true,
        ..Default::default()
    }));
    let dst = Arc::new(Mutex::new(PipelineState {
        auto_ranges: true,
        early_range_acks: true,
        arrival_delay: Some(std::time::Duration::from_secs(2)),
        ..Default::default()
    }));
    let mut worker = pipeline_worker(&sched, &src, &dst, false);
    let opts = Arc::get_mut(&mut worker.opts).unwrap();
    opts.block = block;
    opts.tuning = Default::default();
    src.lock().unwrap().progress = Some(worker.progress.clone());
    let mut credited = 0;
    worker.transfer_range(&range, &mut credited).unwrap();
    let source = src.lock().unwrap();
    assert_eq!(
        source.progress_at_receive[1].0,
        1 << 20,
        "ACK credited before receiving the second block"
    );
    assert!(
        matches!(&source.requests[4], Request::ReadRange { len, .. } if *len < 1 << 20),
        "slow ACK sizes the next read immediately"
    );
    assert_eq!(credited, size);
    assert_eq!(
        dst.lock().unwrap().max_pending,
        1,
        "arrived writes need not wait for the window to fill"
    );
    assert!(sched.range_done(&range));
}

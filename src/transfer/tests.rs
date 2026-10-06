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
fn only_a_single_fixed_tcp_port_waits_for_helpers() {
    assert!(!helpers_hold_the_only_tcp_port(None));
    assert!(!helpers_hold_the_only_tcp_port(Some((0, 0))));
    assert!(!helpers_hold_the_only_tcp_port(Some((47_600, 47_699))));
    assert!(helpers_hold_the_only_tcp_port(Some((47_600, 47_600))));
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
    arrival_delays: std::collections::VecDeque<std::time::Duration>,
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
        let mut state = self.0.lock().unwrap();
        let delay = state
            .arrival_delays
            .pop_front()
            .or(state.arrival_delay)
            .unwrap_or_default();
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
        transfer_strategy: Default::default(),
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
        hash_or_copy: false,
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
                opts.transfer_strategy = crate::cli::TransferStrategy::WholeFile;
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
    check_adaptive_range_handoff(false, 5);
}

#[test]
fn slow_ranges_become_shareable_before_draining_for_a_latency_check() {
    check_adaptive_range_handoff(true, 5);
}

#[test]
fn slow_ranges_keep_split_hints_current_while_draining() {
    check_adaptive_range_handoff(true, 6);
}

fn check_adaptive_range_handoff(recheck: bool, steal_at: usize) {
    let block = 4 << 20;
    let size = 16 << 20;
    let sched = Arc::new(Sched::new(block, 32 << 20));
    let idx = sched.push_file(pipeline_job(b"file", size));
    sched.scan_done();
    assert!(matches!(sched.next(), Item::File(_)));
    let range = sched.ranges_ready(idx, vec![(0, size)]).unwrap();
    let src = Arc::new(Mutex::new(PipelineState {
        auto_ranges: true,
        steal_range_at: Some((steal_at, sched.clone())),
        ..Default::default()
    }));
    let dst = Arc::new(Mutex::new(PipelineState {
        auto_ranges: true,
        // Inject service time without a slow or timing-sensitive test.
        arrival_delay: Some(std::time::Duration::from_secs(1)),
        // The second completion can reveal worse service during the drain.
        arrival_delays: if steal_at == 6 {
            [1, 4].map(std::time::Duration::from_secs).into()
        } else {
            Default::default()
        },
        ..Default::default()
    }));
    let mut worker = pipeline_worker(&sched, &src, &dst, false);
    let opts = Arc::get_mut(&mut worker.opts).unwrap();
    opts.block = block;
    opts.tuning = Default::default();
    if recheck {
        // The first slow completion makes a check due while three source
        // requests are still outstanding. The peer tries to steal during
        // that drain, before another read can publish a smaller split.
        let mut budget = WorkBudget::ranges(block, std::time::Duration::from_millis(250), None);
        budget.refreshed_latency(
            std::time::Duration::from_millis(10),
            std::time::Instant::now() - std::time::Duration::from_secs(60),
        );
        worker.range_budget = Some(budget);
    }
    let mut credited = 0;
    worker.transfer_range(&range, &mut credited).unwrap();
    if recheck {
        let state = src.lock().unwrap();
        assert_eq!(
            state.sent_at_receive[steal_at - 1],
            7,
            "no refill before the peer steals"
        );
        assert!(
            matches!(state.requests[7], Request::ConfigureHashing(_)),
            "the latency probe waits for all seven issued reads"
        );
    }
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
    let expected_start = peer_range.lock().unwrap().split.unwrap().minimum / 2;
    if steal_at == 6 {
        assert!(
            expected_start <= 128 << 10,
            "the peer must inherit the smaller hint from the second slow completion: {expected_start}"
        );
    }
    assert!(
        expected_start < 1 << 20,
        "the donor has measured slow service"
    );
    let opts = Arc::get_mut(&mut peer.opts).unwrap();
    opts.block = block;
    opts.tuning = Default::default();
    let mut peer_credited = 0;
    peer.transfer_range(&peer_range, &mut peer_credited)
        .unwrap();
    let state = peer_src.lock().unwrap();
    assert!(
        matches!(state.requests.first(), Some(Request::ReadRange { len, .. })
        if u64::from(*len) == expected_start)
    );
    assert!(
        state
            .requests
            .iter()
            .any(|r| matches!(r, Request::ReadRange { len, .. }
        if u64::from(*len) > expected_start)),
        "the faster peer grows beyond the hint"
    );
    drop(state);
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
fn inherited_requests_preserve_worker_measurements_ceilings_and_overrides() {
    use std::time::Duration;
    for (mode, ceiling, expected) in [
        ("fresh", 4 << 20, 64 << 10),
        ("learned", 4 << 20, 512 << 10),
        ("receiver", 32 << 10, 32 << 10),
        ("explicit", 4 << 20, 2 << 20),
    ] {
        let size = 2 << 20;
        let block = 4 << 20;
        let sched = Arc::new(Sched::new(block, 32 << 20));
        let idx = sched.push_file(pipeline_job(b"file", size));
        sched.scan_done();
        assert!(matches!(sched.next(), Item::File(_)));
        let range = sched.ranges_ready(idx, vec![(0, size)]).unwrap();
        range.lock().unwrap().split = Some(crate::sched::RangeSplit {
            block: 512,
            minimum: 128 << 10,
        });
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
        if mode == "explicit" {
            opts.tuning.pipeline_depth = Some(4);
        }
        if mode == "learned" {
            worker.range_budget = Some(WorkBudget::ranges(
                block,
                Duration::from_millis(250),
                Some(512 << 10),
            ));
        }
        let mut credited = 0;
        worker
            .transfer_range_pipeline(&worker.job(idx), &range, &mut credited, ceiling, 4, 4)
            .unwrap();
        let source = src.lock().unwrap();
        assert!(
            matches!(source.requests.first(), Some(Request::ReadRange { len, .. })
            if *len == expected),
            "{mode}"
        );
        assert!(
            source
                .requests
                .iter()
                .all(|r| !matches!(r, Request::ReadRange { len, .. }
            if u64::from(*len) > ceiling)),
            "{mode}"
        );
        assert_eq!(source.requests.len(), source.received);
        let destination = dst.lock().unwrap();
        assert_eq!(destination.requests.len(), destination.received);
        assert_eq!(credited, size);
        assert!(sched.range_done(&range));
        assert!(matches!(sched.next(), Item::Exit));
    }
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
    for (abort, starting_bytes) in [
        (false, 1 << 20),
        (true, 1 << 20),
        (false, 64 << 10),
        (true, 64 << 10),
    ] {
        let block = 4 << 20;
        let sched = Arc::new(Sched::new(block, 32 << 20));
        let idx = sched.push_file(pipeline_job(b"file", 8 << 20));
        sched.scan_done();
        assert!(matches!(sched.next(), Item::File(_)));
        let range = sched.ranges_ready(idx, vec![(0, 8 << 20)]).unwrap();
        if starting_bytes != 1 << 20 {
            range.lock().unwrap().split = Some(crate::sched::RangeSplit {
                block: 512,
                minimum: 2 * starting_bytes,
            });
        }
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
            assert_eq!(tail.lock().unwrap().pos, 4 * starting_bytes);
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
        let mut budget = WorkBudget::ranges(block, Duration::from_millis(600), None);
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

/// Answers each request as it is sent, in order.
struct AnsweringConn<F> {
    answer: F,
    replies: std::collections::VecDeque<Response>,
}

impl<F: FnMut(Request) -> Response + Send> Conn for AnsweringConn<F> {
    fn send(&mut self, request: Request) -> Result<()> {
        let reply = (self.answer)(request);
        self.replies.push_back(reply);
        Ok(())
    }
    fn recv(&mut self) -> Result<Response> {
        self.replies
            .pop_front()
            .ok_or_else(|| anyhow::anyhow!("missing reply"))
    }
    // Each reply arrives as its request is sent, as an in-process
    // endpoint's does.
    fn reply_ready(&self) -> bool {
        !self.replies.is_empty()
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

/// A source that reads each file whole from disk and reports it with its
/// planned entry.
fn reading_source(entries: std::collections::HashMap<PathBytes, Entry>) -> Box<dyn Conn> {
    let read = move |path: &PathBytes| {
        let contents = std::fs::read(OsStr::from_bytes(path)).unwrap();
        (contents, entries[path].clone())
    };
    Box::new(AnsweringConn {
        answer: move |request| match request {
            Request::ReadDifferingBatch { block, reads } => Response::DifferingBlocks(
                reads
                    .iter()
                    .map(|wanted| {
                        let (contents, entry) = read(&wanted.path);
                        let mut matching = Vec::new();
                        let mut data = Vec::new();
                        for (index, chunk) in contents.chunks(block as usize).enumerate() {
                            let same = wanted.expected.get(index) == Some(&content_digest(chunk));
                            if !same && !wanted.compare_only {
                                data.extend_from_slice(chunk);
                            }
                            matching.push(same);
                        }
                        Ok(DifferingBlocks {
                            source: Some(entry),
                            matching,
                            hash: content_digest(&data),
                            data,
                        })
                    })
                    .collect(),
            ),
            Request::ReadSmallBatch(reads) => Response::SmallBlocks(
                reads
                    .iter()
                    .map(|wanted| {
                        let (data, entry) = read(&wanted.path);
                        Ok(SmallBlock {
                            source: Some(entry),
                            hash: content_digest(&data),
                            data,
                        })
                    })
                    .collect(),
            ),
            other => panic!("unexpected source request {other:?}"),
        },
        replies: Default::default(),
    })
}

/// A source that reads with its own `FsOps`, answering each request as it is
/// sent: at once, as an in-process source does, when `in_process`, and
/// otherwise queueing its replies as a remote one does. It records the most
/// reads awaiting replies at once, and the most file data they held.
struct QueuingSource {
    ops: crate::fsops::FsOps,
    replies: std::collections::VecDeque<Response>,
    in_process: bool,
    most: Arc<Mutex<(usize, usize)>>,
}

impl Conn for QueuingSource {
    fn send(&mut self, mut request: Request) -> Result<()> {
        // Its files are read by path, as no source roots are registered.
        match &mut request {
            Request::ReadDifferingBatch { reads, .. } => {
                for read in reads {
                    read.source = None;
                }
            }
            Request::ReadRange { source, .. }
            | Request::ReadComparedRange { source, .. }
            | Request::HashBlocks { source, .. }
            | Request::FileHash { source, .. } => *source = None,
            Request::StatMany { sources, .. } => *sources = None,
            _ => {}
        }
        self.replies.push_back(self.ops.handle(&request));
        let data = self
            .replies
            .iter()
            .map(|reply| match reply {
                Response::DifferingBlocks(files) => {
                    files.iter().flatten().map(|file| file.data.len()).sum()
                }
                Response::Block { data, .. } => data.len(),
                _ => 0,
            })
            .sum();
        let mut most = self.most.lock().unwrap();
        *most = (most.0.max(self.replies.len()), most.1.max(data));
        Ok(())
    }
    fn recv(&mut self) -> Result<Response> {
        self.replies
            .pop_front()
            .ok_or_else(|| anyhow::anyhow!("missing reply"))
    }
    fn reply_ready(&self) -> bool {
        self.in_process && !self.replies.is_empty()
    }
    fn reply_queue(&self) -> Option<usize> {
        (!self.in_process).then_some(crate::transfer_tuning::DEFAULT_PIPELINE_DEPTH)
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
fn grouped_comparison_holds_one_in_process_read_and_queues_remote_ones() {
    use std::os::unix::fs::MetadataExt;
    // Rewritten files: twenty of 1 MiB, four to a group, and four of 12 MiB,
    // each a group of its own, whose reads return all their data.
    let files: Vec<(String, usize)> = (0..20)
        .map(|n| (format!("small{n}"), 1 << 20))
        .chain((0..4).map(|n| (format!("large{n}"), 12 << 20)))
        .collect();
    for in_process in [false, true] {
        let temporary = crate::test_support::tempdir().unwrap();
        let root = temporary.path();
        for directory in ["source", "target"] {
            std::fs::create_dir(root.join(directory)).unwrap();
        }
        let sched = Arc::new(Sched::new(512, 8192));
        for (n, (name, len)) in files.iter().enumerate() {
            let contents = |seed: usize| -> Vec<u8> {
                (0..*len).map(|i| ((i * 7 + seed) % 251) as u8).collect()
            };
            let (source, target) = (
                root.join("source").join(name),
                root.join("target").join(name),
            );
            std::fs::write(&source, contents(n)).unwrap();
            std::fs::write(&target, contents(n + 1)).unwrap();
            let mut job = pipeline_job(name.as_bytes(), 0);
            job.src = source.as_os_str().as_bytes().to_vec();
            job.dst = target.as_os_str().as_bytes().to_vec();
            let planned = std::fs::metadata(&source).unwrap();
            job.entry.size = planned.len();
            job.entry.mtime = planned.mtime();
            job.entry.mtime_nsec = planned.mtime_nsec() as u32;
            let existing = std::fs::metadata(&target).unwrap();
            job.dst_entry = Some(Entry {
                mtime: 0,
                dev: existing.dev(),
                ino: existing.ino(),
                ..job.entry.clone()
            });
            sched.push_file(job);
        }
        sched.scan_done();
        let most = Arc::new(Mutex::new((0, 0)));
        let unused = Arc::new(Mutex::new(PipelineState::default()));
        let mut worker = pipeline_worker(&sched, &unused, &unused, true);
        worker.src = Box::new(QueuingSource {
            ops: crate::fsops::FsOps::new(),
            replies: Default::default(),
            in_process,
            most: most.clone(),
        });
        let mut destination = crate::fsops::FsOps::test_destination(&root.join("target"));
        worker.dst = Box::new(AnsweringConn {
            answer: move |request: Request| destination.handle(&request),
            replies: Default::default(),
        });
        worker.fast_batch_files = files.len();
        Arc::get_mut(&mut worker.opts).unwrap().block = 4 << 20;
        run_workers(&sched, vec![worker]);
        for (name, _) in &files {
            assert!(
                std::fs::read(root.join("source").join(name)).unwrap()
                    == std::fs::read(root.join("target").join(name)).unwrap(),
                "{name}"
            );
        }
        let (reads, data) = *most.lock().unwrap();
        if in_process {
            // Each read's data moves on before the next read: no more than
            // one group's is held.
            assert_eq!((reads, data), (1, 12 << 20));
        } else {
            // Reads overlap, within the source's reply queue.
            assert!(
                (2..=crate::transfer_tuning::DEFAULT_PIPELINE_DEPTH).contains(&reads),
                "{reads} reads"
            );
        }
    }
}

/// Jobs copying each of `files`, a name, its length and the range its
/// source rewrites, from `root/source` into `root/target`, where an older
/// version of each lies.
fn differing_jobs(
    root: &std::path::Path,
    files: &[(&str, usize, std::ops::Range<usize>)],
) -> Arc<Sched> {
    use std::os::unix::fs::MetadataExt;
    for directory in ["source", "target"] {
        std::fs::create_dir_all(root.join(directory)).unwrap();
    }
    let sched = Arc::new(Sched::new(512, 8192));
    for (n, (name, len, changed)) in files.iter().enumerate() {
        let old: Vec<u8> = (0..*len).map(|i| ((i * 7 + n) % 251) as u8).collect();
        let mut new = old.clone();
        new[changed.clone()].fill(n as u8 + 1);
        let (source, target) = (
            root.join("source").join(name),
            root.join("target").join(name),
        );
        std::fs::write(&source, &new).unwrap();
        std::fs::write(&target, &old).unwrap();
        let mut job = pipeline_job(name.as_bytes(), 0);
        job.src = source.as_os_str().as_bytes().to_vec();
        job.dst = target.as_os_str().as_bytes().to_vec();
        let planned = std::fs::metadata(&source).unwrap();
        job.entry.size = planned.len();
        job.entry.mtime = planned.mtime();
        job.entry.mtime_nsec = planned.mtime_nsec() as u32;
        let existing = std::fs::metadata(&target).unwrap();
        job.dst_entry = Some(Entry {
            mtime: 0,
            dev: existing.dev(),
            ino: existing.ino(),
            nlink: existing.nlink(),
            ..job.entry.clone()
        });
        sched.push_file(job);
    }
    sched.scan_done();
    sched
}

#[test]
fn a_file_of_which_more_differs_than_a_patch_carries_streams_its_patch() {
    let block = 1 << 20;
    // Two files of which 18 MiB differ, and one of which 1 MiB does: the
    // first two stream their patches in pieces after the groups, the last
    // is patched in its group.
    let files: [(&str, usize, std::ops::Range<usize>); 3] = [
        ("first", 24 << 20, 2 << 20..20 << 20),
        ("second", 32 << 20, 14 << 20..32 << 20),
        ("small", 4 << 20, 1 << 20..2 << 20),
    ];
    // From a remote and an in-process source, into an ordinary and a
    // command-restricted receiver.
    for (in_process, restricted) in [(false, false), (true, false), (false, true)] {
        let case = format!("in_process={in_process} restricted={restricted}");
        let temporary = crate::test_support::tempdir().unwrap();
        let root = temporary.path();
        let sched = differing_jobs(root, &files);
        let most = Arc::new(Mutex::new((0, 0)));
        let unused = Arc::new(Mutex::new(PipelineState::default()));
        let mut worker = pipeline_worker(&sched, &unused, &unused, true);
        worker.src = Box::new(QueuingSource {
            ops: crate::fsops::FsOps::new(),
            replies: Default::default(),
            in_process,
            most: most.clone(),
        });
        let requests = Arc::new(Mutex::new(Vec::new()));
        let authority = Arc::new(crate::restricted::tests::time_preserving_test_authority_of(
            root,
            64 << 20,
        ));
        worker.dst = if restricted {
            restricted_destination(authority.clone(), requests.clone(), || {})
        } else {
            let mut destination = crate::fsops::FsOps::test_destination(&root.join("target"));
            let requests = requests.clone();
            Box::new(AnsweringConn {
                answer: move |request: Request| {
                    let response = destination.handle(&request);
                    requests.lock().unwrap().push(match request {
                        Request::PatchData { data, hash } => Request::PatchData {
                            data: vec![0; data.len()].into(),
                            hash,
                        },
                        request => request,
                    });
                    response
                },
                replies: Default::default(),
            })
        };
        worker.fast_batch_files = files.len();
        let opts = Arc::get_mut(&mut worker.opts).unwrap();
        opts.block = block;
        if restricted {
            opts.restricted_receiver = true;
            opts.flags = flags::TIMES;
            opts.matching_flags = flags::TIMES;
        }
        run_workers(&sched, vec![worker]);
        for (name, ..) in &files {
            assert!(
                std::fs::read(root.join("source").join(name)).unwrap()
                    == std::fs::read(root.join("target").join(name)).unwrap(),
                "{case} {name}"
            );
        }
        let requests = requests.lock().unwrap();
        let count = |kind: fn(&Request) -> bool| requests.iter().filter(|r| kind(r)).count();
        assert_eq!(
            count(|r| matches!(r, Request::PatchBegin { .. })),
            2,
            "{case}"
        );
        assert_eq!(
            count(|r| matches!(r, Request::PatchEnd { commit: true })),
            2,
            "{case}"
        );
        // Only the differing blocks were sent, in pieces of up to 4 MiB.
        let pieces: Vec<usize> = requests
            .iter()
            .filter_map(|request| match request {
                Request::PatchData { data, .. } => Some(data.len()),
                _ => None,
            })
            .collect();
        if !restricted {
            assert_eq!(pieces.iter().sum::<usize>(), 36 << 20, "{case}");
            assert!(pieces.iter().all(|piece| *piece <= 4 << 20), "{case}");
        }
        assert_eq!(pieces.len(), 10, "{case}");
        let (reads, data) = *most.lock().unwrap();
        if in_process {
            // Each piece moves on before the next is read.
            assert_eq!(reads, 1, "{case}");
            assert!(data <= 4 << 20, "{case}: {data} bytes");
        } else {
            // Pieces are read ahead, within the stream's buffer.
            assert!(reads >= 2, "{case}: {reads} reads");
            assert!(data <= 16 << 20, "{case}: {data} bytes");
        }
        if restricted {
            assert_eq!(authority.in_flight(), 0, "{case}");
        }
    }
}

#[test]
fn a_streamed_patch_that_fails_at_its_begin_sends_none_of_its_pieces() {
    // An in-process source's pieces are ready as soon as they are read, but
    // the sender still takes the receiver's replies first: a patch whose
    // begin failed or was refused sends no piece. A stale begin is compared
    // again and streamed once more; a refused one is copied whole, and the
    // receiver's grant refuses nothing further for it.
    use std::os::unix::fs::PermissionsExt;
    let files = [("file", 32 << 20, 4 << 20..28 << 20)];
    for refused in [false, true] {
        let temporary = crate::test_support::tempdir().unwrap();
        let root = temporary.path();
        let sched = differing_jobs(root, &files);
        let target = root.join("target/file");
        let unused = Arc::new(Mutex::new(PipelineState::default()));
        let mut worker = pipeline_worker(&sched, &unused, &unused, true);
        worker.src = Box::new(QueuingSource {
            ops: crate::fsops::FsOps::new(),
            replies: Default::default(),
            in_process: true,
            most: Default::default(),
        });
        let authority = Arc::new(crate::restricted::tests::time_preserving_test_authority_of(
            root,
            64 << 20,
        ));
        let executed = Arc::new(Mutex::new(Vec::new()));
        // The first begin goes stale: a metadata change, as keeping
        // another name of the file makes, changes its change time.
        let first = Arc::new(std::sync::atomic::AtomicBool::new(!refused));
        let stale = target.clone();
        let mut receiver = restricted_destination(authority.clone(), executed.clone(), move || {
            if first.swap(false, Relaxed) {
                std::thread::sleep(std::time::Duration::from_millis(20));
                std::fs::set_permissions(&stale, std::fs::Permissions::from_mode(0o640)).unwrap();
            }
        });
        // What the receiver was sent, and its refusals of streamed requests.
        let sent = Arc::new(Mutex::new(Vec::new()));
        let refusals = Arc::new(Mutex::new(0));
        let mut refuse_begin = refused;
        worker.dst = Box::new(AnsweringConn {
            answer: {
                let (sent, refusals) = (sent.clone(), refusals.clone());
                move |request: Request| {
                    let kind = match request {
                        Request::PatchBegin { .. } => "begin",
                        Request::PatchData { .. } => "piece",
                        Request::PatchEnd { .. } => "end",
                        _ => "other",
                    };
                    sent.lock().unwrap().push(kind);
                    // The grant refuses the first begin, as it would one it
                    // does not authorize.
                    if refuse_begin && matches!(request, Request::PatchBegin { .. }) {
                        refuse_begin = false;
                        *refusals.lock().unwrap() += 1;
                        return Response::Err("refused by the grant".into());
                    }
                    receiver.send(request).unwrap();
                    let reply = receiver.recv().unwrap();
                    if kind != "other" && matches!(reply, Response::Err(_)) {
                        *refusals.lock().unwrap() += 1;
                    }
                    reply
                }
            },
            replies: Default::default(),
        });
        worker.fast_batch_files = 1;
        let opts = Arc::get_mut(&mut worker.opts).unwrap();
        // The grant's hash block, which a whole copy's comparison uses.
        opts.block = 4 << 20;
        opts.restricted_receiver = true;
        opts.flags = flags::TIMES;
        opts.matching_flags = flags::TIMES;
        // A whole copy reads ordinary ranges, which the test source serves.
        opts.tuning.pipeline_depth = Some(crate::transfer_tuning::DEFAULT_PIPELINE_DEPTH);
        run_workers(&sched, vec![worker]);
        assert!(
            std::fs::read(root.join("source/file")).unwrap() == std::fs::read(&target).unwrap(),
            "refused={refused}"
        );
        let sent = sent.lock().unwrap();
        let count = |kind: &str| sent.iter().filter(|sent| **sent == kind).count();
        let counts = (count("begin"), count("piece"), count("end"));
        if refused {
            // Nothing followed the refused begin, which the file's whole
            // copy replaced; only the begin was refused.
            assert_eq!(counts, (1, 0, 0), "refused");
            assert_eq!(*refusals.lock().unwrap(), 1);
        } else {
            // The stale patch ended without a piece; the second streamed
            // its 24 MiB in six.
            assert_eq!(counts, (2, 6, 2), "stale");
            assert_eq!(*refusals.lock().unwrap(), 0);
        }
        assert_eq!(authority.in_flight(), 0, "refused={refused}");
    }
}

#[test]
fn grouped_comparison_counts_each_file_as_its_reply_settles_it() {
    // Two files patched in groups of their own, one kept, and two of which
    // more differs than a patch carries, whose patches stream after the
    // groups.
    let files: [(&str, usize, std::ops::Range<usize>); 5] = [
        ("first", 4 << 20, 1 << 20..2 << 20),
        ("second", 4 << 20, 2 << 20..3 << 20),
        ("same", 4 << 20, 0..0),
        ("streamed", 24 << 20, 2 << 20..20 << 20),
        ("also-streamed", 24 << 20, 4 << 20..22 << 20),
    ];
    let total: u64 = files.iter().map(|(_, len, _)| *len as u64).sum();
    // With the first streamed patch abandoned at its end, that file is
    // compared again and copied on the per-file path.
    for (in_process, abandon) in [(true, false), (false, false), (true, true)] {
        let case = format!("in_process={in_process} abandon={abandon}");
        let temporary = crate::test_support::tempdir().unwrap();
        let root = temporary.path();
        let sched = differing_jobs(root, &files);
        let unused = Arc::new(Mutex::new(PipelineState::default()));
        let mut worker = pipeline_worker(&sched, &unused, &unused, true);
        worker.src = Box::new(QueuingSource {
            ops: crate::fsops::FsOps::new(),
            replies: Default::default(),
            in_process,
            most: Default::default(),
        });
        // What progress showed as each request reached the receiver.
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut destination = crate::fsops::FsOps::test_destination(&root.join("target"));
        let (progress, recorded) = (worker.progress.clone(), seen.clone());
        let mut abandoning = abandon;
        worker.dst = Box::new(AnsweringConn {
            answer: move |request: Request| {
                let kind = match request {
                    Request::PatchSmallBatch(_) => "patch",
                    Request::PatchBegin { .. } => "begin",
                    Request::PatchEnd { .. } => "end",
                    _ => "other",
                };
                recorded.lock().unwrap().push((
                    kind,
                    progress.bytes_done.load(Relaxed),
                    progress.files_done.load(Relaxed),
                    progress.files_unchanged.load(Relaxed),
                ));
                match request {
                    Request::PatchEnd { .. } if std::mem::take(&mut abandoning) => {
                        destination.handle(&Request::PatchEnd { commit: false })
                    }
                    request => destination.handle(&request),
                }
            },
            replies: Default::default(),
        });
        worker.fast_batch_files = files.len();
        let opts = Arc::get_mut(&mut worker.opts).unwrap();
        opts.block = 1 << 20;
        // A file compared again reads ordinary ranges, which the test source
        // serves.
        opts.tuning.pipeline_depth = Some(crate::transfer_tuning::DEFAULT_PIPELINE_DEPTH);
        let progress = worker.progress.clone();
        run_workers(&sched, vec![worker]);
        for (name, ..) in &files {
            assert!(
                std::fs::read(root.join("source").join(name)).unwrap()
                    == std::fs::read(root.join("target").join(name)).unwrap(),
                "{case} {name}"
            );
        }
        let seen = seen.lock().unwrap();
        // Each group's patch reply is taken before the next group's patch
        // is sent, and the file it keeps or publishes counts at once.
        let patches: Vec<_> = seen.iter().filter(|seen| seen.0 == "patch").collect();
        assert_eq!(patches.len(), 3, "{case}");
        for (k, patch) in patches.iter().enumerate() {
            assert_eq!(patch.2 + patch.3, k as u64, "{case}: patch {k}");
        }
        let begins: Vec<_> = seen.iter().filter(|seen| seen.0 == "begin").collect();
        let ends: Vec<_> = seen.iter().filter(|seen| seen.0 == "end").collect();
        assert_eq!((begins.len(), ends.len()), (2, 2), "{case}");
        // Once the groups are done, before any patch streams, their files
        // count: two patched from 1 MiB each, and one kept.
        assert_eq!(
            (begins[0].1, begins[0].2, begins[0].3),
            (2 << 20, 2, 1),
            "{case}"
        );
        // A streamed patch's pieces count as the receiver acknowledges them,
        // all of them by its end.
        for (begin, end) in begins.iter().zip(&ends).take(if abandon { 1 } else { 2 }) {
            assert_eq!(end.1 - begin.1, 18 << 20, "{case}");
        }
        // Every file counts once, as sent or unchanged: an abandoned
        // patch's pieces no longer count when it is copied again.
        let (sent, unchanged) = (
            progress.bytes_done.load(Relaxed),
            progress.bytes_unchanged.load(Relaxed),
        );
        assert_eq!(sent + unchanged, total, "{case}");
        if !abandon {
            assert_eq!(sent, 38 << 20, "{case}");
        }
        assert_eq!(
            (
                progress.files_done.load(Relaxed),
                progress.files_unchanged.load(Relaxed)
            ),
            (4, 1),
            "{case}"
        );
    }
}

#[test]
fn an_aborted_copy_sends_nothing_further_for_groups_in_flight() {
    // Eight rewritten files of 4 MiB, each a group of its own: all are sent
    // to be hashed before any is read.
    let names: Vec<String> = (0..8).map(|n| format!("file{n}")).collect();
    let files: Vec<(&str, usize, std::ops::Range<usize>)> = names
        .iter()
        .map(|name| (name.as_str(), 4 << 20, 1 << 20..2 << 20))
        .collect();
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path();
    let sched = differing_jobs(root, &files);
    let unused = Arc::new(Mutex::new(PipelineState::default()));
    let mut worker = pipeline_worker(&sched, &unused, &unused, true);
    let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    worker.src = {
        let reads = reads.clone();
        let mut source = crate::fsops::FsOps::new();
        Box::new(AnsweringConn {
            answer: move |mut request: Request| {
                // Its files are read by path, as no source roots are
                // registered.
                if let Request::ReadDifferingBatch { reads: wanted, .. } = &mut request {
                    reads.fetch_add(1, Relaxed);
                    for read in wanted {
                        read.source = None;
                    }
                }
                source.handle(&request)
            },
            replies: Default::default(),
        })
    };
    // The copy is aborted, as by a fatal error elsewhere, as the first patch
    // reaches the receiver.
    let patches = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    worker.dst = {
        let (sched, patches) = (sched.clone(), patches.clone());
        let mut destination = crate::fsops::FsOps::test_destination(&root.join("target"));
        Box::new(AnsweringConn {
            answer: move |request: Request| {
                if let Request::PatchSmallBatch(_) = request {
                    patches.fetch_add(1, Relaxed);
                    sched.abort();
                }
                destination.handle(&request)
            },
            replies: Default::default(),
        })
    };
    worker.fast_batch_files = files.len();
    Arc::get_mut(&mut worker.opts).unwrap().block = 1 << 20;
    worker.process_item(sched.next()).unwrap();
    assert!(sched.is_aborted());
    // The groups in flight read and publish nothing more; their replies were
    // all taken.
    assert_eq!(
        (reads.load(Relaxed), patches.load(Relaxed)),
        (1, 1),
        "reads and patches sent"
    );
    assert!(!worker.src.reply_ready() && !worker.dst.reply_ready());
    let published = names
        .iter()
        .filter(|name| {
            std::fs::read(root.join("source").join(name)).unwrap()
                == std::fs::read(root.join("target").join(name)).unwrap()
        })
        .count();
    assert_eq!(published, 1);
    // The patch already sent settled its file, which counts.
    assert_eq!(worker.progress.files_done.load(Relaxed), 1);
}

/// A connection that fails, and stays dead, as a dropped one does: at its
/// `fail_recv`-th reply, or as it sends its `fail_patch`-th patch batch.
struct FailingConn {
    inner: Box<dyn Conn>,
    received: usize,
    fail_recv: Option<usize>,
    patches: usize,
    fail_patch: Option<usize>,
    dead: bool,
}

impl FailingConn {
    fn new(inner: Box<dyn Conn>) -> Self {
        Self {
            inner,
            received: 0,
            fail_recv: None,
            patches: 0,
            fail_patch: None,
            dead: false,
        }
    }
}

impl Conn for FailingConn {
    fn send(&mut self, request: Request) -> Result<()> {
        if let Request::PatchSmallBatch(_) = request {
            self.patches += 1;
            self.dead |= self.fail_patch == Some(self.patches);
        }
        anyhow::ensure!(!self.dead, "injected connection failure");
        self.inner.send(request)
    }
    fn recv(&mut self) -> Result<Response> {
        self.received += 1;
        self.dead |= self.fail_recv == Some(self.received);
        anyhow::ensure!(!self.dead, "injected connection failure");
        self.inner.recv()
    }
    fn reply_ready(&self) -> bool {
        !self.dead && self.inner.reply_ready()
    }
    fn is_dead(&self) -> bool {
        self.dead
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

/// Compare `files` from an in-process source into an ordinary receiver
/// until `fail` breaks one of the connections, and return the error and
/// the worker's progress.
fn compare_until_a_connection_fails(
    root: &std::path::Path,
    files: &[(&str, usize, std::ops::Range<usize>)],
    fail: impl FnOnce(&mut FailingConn, &mut FailingConn),
) -> (anyhow::Error, Arc<Progress>) {
    let sched = differing_jobs(root, files);
    let unused = Arc::new(Mutex::new(PipelineState::default()));
    let mut worker = pipeline_worker(&sched, &unused, &unused, true);
    let mut source = FailingConn::new(Box::new(QueuingSource {
        ops: crate::fsops::FsOps::new(),
        replies: Default::default(),
        in_process: true,
        most: Default::default(),
    }));
    let mut receiver = crate::fsops::FsOps::test_destination(&root.join("target"));
    let mut destination = FailingConn::new(Box::new(AnsweringConn {
        answer: move |request: Request| receiver.handle(&request),
        replies: Default::default(),
    }));
    fail(&mut source, &mut destination);
    (worker.src, worker.dst) = (Box::new(source), Box::new(destination));
    worker.fast_batch_files = files.len();
    Arc::get_mut(&mut worker.opts).unwrap().block = 1 << 20;
    let error = worker.process_item(sched.next()).unwrap_err();
    (error, worker.progress.clone())
}

#[test]
fn a_received_patch_reply_counts_although_the_source_then_fails() {
    // The first file's patch reply has arrived when the source's
    // connection fails as the second file's differing blocks are read.
    let files = [
        ("first", 4 << 20, 1 << 20..2 << 20),
        ("second", 4 << 20, 1 << 20..2 << 20),
    ];
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path();
    let (error, progress) = compare_until_a_connection_fails(root, &files, |source, _| {
        source.fail_recv = Some(2);
    });
    assert!(error.to_string().contains("injected connection failure"));
    // The file the receiver published counts, and only it.
    assert_eq!(read(root, "source/first"), read(root, "target/first"));
    assert_ne!(read(root, "source/second"), read(root, "target/second"));
    assert_eq!(progress.files_done.load(Relaxed), 1);
    assert_eq!(progress.bytes_done.load(Relaxed), 1 << 20);
}

#[test]
fn a_received_patch_reply_counts_although_a_later_patch_cannot_be_sent() {
    // The first file's patch reply has arrived when the receiver's
    // connection fails as the second file's patch is sent.
    let files = [
        ("first", 4 << 20, 1 << 20..2 << 20),
        ("second", 4 << 20, 1 << 20..2 << 20),
        ("third", 4 << 20, 1 << 20..2 << 20),
    ];
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path();
    let (error, progress) = compare_until_a_connection_fails(root, &files, |_, destination| {
        destination.fail_patch = Some(2);
    });
    assert!(error.to_string().contains("injected connection failure"));
    assert_eq!(read(root, "source/first"), read(root, "target/first"));
    for name in ["second", "third"] {
        assert_ne!(
            read(root, &format!("source/{name}")),
            read(root, &format!("target/{name}")),
            "{name}"
        );
    }
    assert_eq!(progress.files_done.load(Relaxed), 1);
    assert_eq!(progress.bytes_done.load(Relaxed), 1 << 20);
}

fn read(root: &std::path::Path, path: &str) -> Vec<u8> {
    std::fs::read(root.join(path)).unwrap()
}

/// A command-restricted receiver: each request is authorized, executed and
/// settled as its server does, and recorded once executed. `before_patch`
/// runs between a patch batch's or streamed begin's authorization and its
/// execution.
fn restricted_destination(
    authority: Arc<crate::restricted::RestrictedAuthority>,
    requests: Arc<Mutex<Vec<Request>>>,
    mut before_patch: impl FnMut() + Send + 'static,
) -> Box<dyn Conn> {
    let mut ops = crate::fsops::FsOps::new();
    let mut gate = crate::restricted::PatchStreamGate::new(authority);
    Box::new(AnsweringConn {
        answer: move |mut request: Request| {
            if (ops.patch_stream_open() || gate.is_open())
                && !matches!(
                    request,
                    Request::PatchData { .. } | Request::PatchEnd { .. }
                )
            {
                return Response::Err(crate::fsops::OPEN_PATCH_STREAM.into());
            }
            let settlement = match gate.authorize(&mut request, false) {
                Ok(settlement) => settlement,
                Err(error) => {
                    let error = format!("{error:#}");
                    match request {
                        Request::PatchData { .. } => ops.fail_patch_stream(&error),
                        Request::PatchEnd { .. } => {
                            ops.abandon_patch_stream();
                            gate.abandon(&error);
                        }
                        _ => {}
                    }
                    return Response::Err(error);
                }
            };
            if matches!(
                request,
                Request::PatchSmallBatch(_) | Request::PatchBegin { .. }
            ) {
                before_patch();
            }
            let response = ops.handle(&request);
            gate.settle(settlement, &response, ops.patch_stream_open());
            // Record what was executed, without the data of pieces.
            if let Request::PatchData { hash, .. } = request {
                request = Request::PatchData {
                    data: Vec::new().into(),
                    hash,
                };
            }
            requests.lock().unwrap().push(request);
            response
        },
        replies: Default::default(),
    })
}

/// Run `workers` on threads of their own until the copy ends, and check
/// that it finished without errors. A worker that panics, or a copy still
/// running after a minute, stops the others.
fn run_workers(sched: &Sched, workers: Vec<Worker>) {
    struct AbortOnPanic<'a>(&'a Sched);
    impl Drop for AbortOnPanic<'_> {
        fn drop(&mut self) {
            if std::thread::panicking() {
                self.0.abort();
            }
        }
    }
    let (done, ended) = std::sync::mpsc::channel::<()>();
    std::thread::scope(|scope| {
        scope.spawn(move || {
            if let Err(std::sync::mpsc::RecvTimeoutError::Timeout) =
                ended.recv_timeout(std::time::Duration::from_secs(60))
            {
                sched.abort();
            }
        });
        let running: Vec<_> = workers
            .into_iter()
            .map(|mut worker| {
                scope.spawn(move || {
                    let _abort = AbortOnPanic(sched);
                    loop {
                        match sched.next() {
                            Item::Exit => break,
                            item => worker.process_item(item).unwrap(),
                        }
                    }
                    worker.progress.errors.load(Relaxed)
                })
            })
            .collect();
        let results: Vec<_> = running.into_iter().map(|worker| worker.join()).collect();
        drop(done);
        for result in results {
            match result {
                Ok(errors) => assert_eq!(errors, 0),
                Err(panic) => std::panic::resume_unwind(panic),
            }
        }
    });
    assert!(sched.finished(), "the copy did not finish");
}

/// What a restricted receiver carried out for a copy: how many times it
/// compared each file, in the order the files were given, how many hash
/// requests it carried out, and how many batches of whole files it
/// published.
#[derive(Debug)]
struct Executed {
    compared: Vec<usize>,
    hash_batches: usize,
    whole: usize,
}

/// Copy each of `files`, a name and its source's modification time, from
/// `root/source` into `root/target` through a restricted receiver with
/// `workers` workers, preserving times, and return what the receiver
/// carried out. Each worker's connection runs `before_patch` between a
/// patch batch's authorization and its execution.
fn copy_through_restricted_receiver(
    root: &std::path::Path,
    files: &[(&str, i64)],
    workers: usize,
    before_patch: impl Fn() + Send + Sync + 'static,
) -> Executed {
    copy_through_restricted_receiver_with(root, files, workers, false, before_patch)
}

/// The same, also preserving the sources' permissions when `permissions`
/// is set.
fn copy_through_restricted_receiver_with(
    root: &std::path::Path,
    files: &[(&str, i64)],
    workers: usize,
    permissions: bool,
    before_patch: impl Fn() + Send + Sync + 'static,
) -> Executed {
    use std::os::unix::fs::MetadataExt;
    let sched = Arc::new(Sched::new(512, 8192));
    let mut entries = std::collections::HashMap::new();
    for &(name, mtime) in files {
        let source = root.join("source").join(name);
        let mut job = pipeline_job(name.as_bytes(), 0);
        job.src = source.as_os_str().as_bytes().to_vec();
        job.dst = root
            .join("target")
            .join(name)
            .as_os_str()
            .as_bytes()
            .to_vec();
        job.entry.size = std::fs::metadata(&source).unwrap().len();
        job.entry.mtime = mtime;
        let existing = std::fs::metadata(OsStr::from_bytes(&job.dst)).unwrap();
        job.dst_entry = Some(Entry {
            size: existing.len(),
            mtime: 0,
            dev: existing.dev(),
            ino: existing.ino(),
            nlink: existing.nlink(),
            ..job.entry.clone()
        });
        entries.insert(job.src.clone(), job.entry.clone());
        sched.push_file(job);
    }
    sched.scan_done();
    let authority = Arc::new(
        crate::restricted::tests::time_preserving_test_authority_for(
            root,
            64 << 20,
            files.len().max(8) as u64,
            permissions,
        ),
    );
    let requests = Arc::new(Mutex::new(Vec::new()));
    let before_patch = Arc::new(before_patch);
    let gate = Gate::new(workers);
    let unused = Arc::new(Mutex::new(PipelineState::default()));
    let workers = (0..workers)
        .map(|id| {
            let mut worker = pipeline_worker(&sched, &unused, &unused, true);
            worker.id = id;
            worker.gate = gate.clone();
            worker.src = reading_source(entries.clone());
            let before_patch = before_patch.clone();
            worker.dst =
                restricted_destination(authority.clone(), requests.clone(), move || before_patch());
            worker.fast_batch_files = files.len();
            let opts = Arc::get_mut(&mut worker.opts).unwrap();
            opts.restricted_receiver = true;
            // Comparisons use their own smaller block; a file copied whole
            // after all goes in a batch of whole files.
            opts.block = 1 << 20;
            opts.flags = flags::TIMES;
            opts.matching_flags = flags::TIMES;
            if permissions {
                opts.perms = true;
                opts.flags |= flags::MODE;
                opts.matching_flags |= flags::MODE;
            }
            worker
        })
        .collect();
    run_workers(&sched, workers);
    let requests = requests.lock().unwrap();
    let compared = files
        .iter()
        .map(|(name, _)| {
            let destination = root.join("target").join(name);
            let destination = destination.as_os_str().as_bytes();
            requests
                .iter()
                .map(|request| match request {
                    Request::HashExistingBatch { files, .. } => {
                        files.iter().filter(|file| file.path == destination).count()
                    }
                    _ => 0,
                })
                .sum()
        })
        .collect();
    let count = |kind: fn(&Request) -> bool| requests.iter().filter(|r| kind(r)).count();
    Executed {
        compared,
        hash_batches: count(|r| matches!(r, Request::HashExistingBatch { .. })),
        whole: count(|r| matches!(r, Request::PutSmallBatch(_))),
    }
}

#[test]
fn a_restricted_receiver_keeps_both_names_of_a_matching_destination() {
    use std::os::unix::fs::MetadataExt;
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path();
    for directory in ["source", "target"] {
        std::fs::create_dir(root.join(directory)).unwrap();
    }
    for name in ["a", "b"] {
        std::fs::write(root.join("source").join(name), b"same").unwrap();
    }
    let (a, b) = (root.join("target/a"), root.join("target/b"));
    std::fs::write(&a, b"same").unwrap();
    std::fs::hard_link(&a, &b).unwrap();
    let inode = std::fs::metadata(&a).unwrap().ino();
    // Keeping one name sets the times of the file both names share, which
    // changes its change time once the clock has moved on.
    std::thread::sleep(std::time::Duration::from_millis(50));
    let executed = copy_through_restricted_receiver(
        root,
        &[("a", 1_600_000_000), ("b", 1_600_000_000)],
        1,
        || {},
    );
    for path in [&a, &b] {
        let metadata = std::fs::metadata(path).unwrap();
        assert_eq!(
            (metadata.ino(), metadata.mtime()),
            (inode, 1_600_000_000),
            "{}",
            path.display()
        );
    }
    // Each name was compared once and neither was copied whole: the second
    // name's patch was authorized after the first name was kept, against
    // the file as keeping it left it.
    assert_eq!((executed.compared, executed.whole), (vec![1, 1], 0));
}

#[test]
fn a_restricted_receiver_compares_a_changed_destination_again_only_once() {
    use std::os::unix::fs::{FileExt, MetadataExt};
    let block = MIN_HASH_BLOCK_BYTES as usize;
    let contents: Vec<u8> = (0..2 * block).map(|i| (i % 251) as u8).collect();
    for changes in [1, 2] {
        let temporary = crate::test_support::tempdir().unwrap();
        let root = temporary.path();
        for directory in ["source", "target"] {
            std::fs::create_dir(root.join(directory)).unwrap();
        }
        std::fs::write(root.join("source/file"), &contents).unwrap();
        let destination = root.join("target/file");
        std::fs::write(&destination, &contents).unwrap();
        let inode = std::fs::metadata(&destination).unwrap().ino();
        // Each of the first `changes` patches finds the destination's second
        // block rewritten after the receiver authorized it.
        let patches = std::sync::atomic::AtomicUsize::new(0);
        let rewritten = destination.clone();
        let executed =
            copy_through_restricted_receiver(root, &[("file", 1_600_000_000)], 1, move || {
                let changed = patches.fetch_add(1, Relaxed) + 1;
                if changed <= changes {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    std::fs::OpenOptions::new()
                        .write(true)
                        .open(&rewritten)
                        .unwrap()
                        .write_all_at(&[changed as u8; 16], block as u64)
                        .unwrap();
                }
            });
        // The destination is never kept: it ends with the source's contents.
        let metadata = std::fs::metadata(&destination).unwrap();
        assert_eq!(std::fs::read(&destination).unwrap(), contents, "{changes}");
        assert_ne!(metadata.ino(), inode, "{changes}");
        assert_eq!(metadata.mtime(), 1_600_000_000, "{changes}");
        // It is compared again once; a second stale condition copies it
        // whole.
        assert_eq!(
            (executed.compared, executed.whole),
            (vec![2], changes - 1),
            "{changes}"
        );
    }
}

/// `names` names of one destination file holding `contents`, each with a
/// source holding the same contents: the names, and the inode they share.
fn linked_destination(root: &std::path::Path, names: usize, contents: &[u8]) -> (Vec<String>, u64) {
    use std::os::unix::fs::MetadataExt;
    for directory in ["source", "target"] {
        std::fs::create_dir(root.join(directory)).unwrap();
    }
    let names: Vec<String> = (0..names).map(|i| format!("name{i}")).collect();
    let first = root.join("target").join(&names[0]);
    std::fs::write(&first, contents).unwrap();
    for name in &names {
        std::fs::write(root.join("source").join(name), contents).unwrap();
        if *name != names[0] {
            std::fs::hard_link(&first, root.join("target").join(name)).unwrap();
        }
    }
    (names, std::fs::metadata(&first).unwrap().ino())
}

/// Give the destination file `name` `count` more names outside the copy, as
/// a backup snapshot tree gives its files.
fn link_outside(root: &std::path::Path, name: &str, count: usize) {
    let outside = root.join("snapshots");
    std::fs::create_dir_all(&outside).unwrap();
    for i in 0..count {
        std::fs::hard_link(
            root.join("target").join(name),
            outside.join(format!("{name}.{i}")),
        )
        .unwrap();
    }
}

#[test]
fn a_restricted_receiver_keeps_every_name_of_a_matching_destination() {
    use std::os::unix::fs::MetadataExt;
    for (count, workers, outside) in [(3, 1, 0), (8, 1, 0), (3, 3, 0), (5, 3, 0), (3, 3, 16)] {
        let temporary = crate::test_support::tempdir().unwrap();
        let root = temporary.path();
        let (names, inode) = linked_destination(root, count, b"same");
        // Names outside the copy are never kept or replaced, so they leave
        // no condition stale.
        link_outside(root, &names[0], outside);
        // Each name has a source time of its own, so keeping each name sets
        // new times on the file they all share. That changes its change
        // time, once the clock has moved on, and would leave stale the
        // conditions of the other names authorized before it.
        let files: Vec<_> = names
            .iter()
            .enumerate()
            .map(|(i, name)| (name.as_str(), 1_600_000_000 + i as i64))
            .collect();
        let executed = copy_through_restricted_receiver(root, &files, workers, || {
            std::thread::sleep(std::time::Duration::from_millis(50));
        });
        let case = format!("{count} names, {workers} workers, {outside} outside");
        for name in &names {
            let path = root.join("target").join(name);
            assert_eq!(
                std::fs::metadata(&path).unwrap().ino(),
                inode,
                "{case}: {name}"
            );
            assert_eq!(std::fs::read(&path).unwrap(), b"same", "{case}: {name}");
        }
        assert_eq!(executed.whole, 0, "{case}: a name was copied whole");
        // One worker patches the names in turn, each against the file as
        // the last left it, so each is compared once. Other workers' names
        // can still leave a name stale.
        if workers == 1 {
            assert_eq!(executed.compared, vec![1; count], "{case}");
        }
    }
}

#[test]
fn a_restricted_receiver_keeps_or_replaces_each_name_of_a_linked_destination() {
    use std::os::unix::fs::MetadataExt;
    // Two blocks: a changed name's patch sends the second and reuses the
    // first.
    let block = MIN_HASH_BLOCK_BYTES as usize;
    let old: Vec<u8> = (0..block + 16).map(|i| (i % 251) as u8).collect();
    let mut new = old.clone();
    new[block..].fill(7);
    let count = 8;
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path();
    let (names, inode) = linked_destination(root, count, &old);
    // The odd names' sources changed. Keeping the first even name sets the
    // times the even names share, and replacing an odd name takes a link
    // from the file: each changes its change time once the clock has moved
    // on.
    let files: Vec<_> = names
        .iter()
        .enumerate()
        .map(|(i, name)| {
            if i % 2 == 0 {
                (name.as_str(), 1_600_000_000)
            } else {
                std::fs::write(root.join("source").join(name), &new).unwrap();
                (name.as_str(), 1_600_000_000 + i as i64)
            }
        })
        .collect();
    let executed = copy_through_restricted_receiver(root, &files, 1, || {
        std::thread::sleep(std::time::Duration::from_millis(50));
    });
    let mut replaced = std::collections::HashSet::new();
    for (i, (name, mtime)) in files.iter().enumerate() {
        let path = root.join("target").join(name);
        let metadata = std::fs::metadata(&path).unwrap();
        assert_eq!(metadata.mtime(), *mtime, "{name}");
        if i % 2 == 0 {
            // A kept name still names the file the other kept names share.
            assert_eq!(metadata.ino(), inode, "{name}");
            assert_eq!(std::fs::read(&path).unwrap(), old, "{name}");
        } else {
            // A replaced name names a new file of its own.
            assert_ne!(metadata.ino(), inode, "{name}");
            assert!(replaced.insert(metadata.ino()), "{name}");
            assert_eq!(std::fs::read(&path).unwrap(), new, "{name}");
        }
    }
    // One worker patches the names in turn, each against the file as the
    // last left it: each is compared once, and none is copied whole.
    assert_eq!((executed.compared, executed.whole), (vec![1; count], 0));
}

#[test]
fn comparison_groups_hold_one_name_of_each_bound_file() {
    use super::small_compare::compare_groups;
    // Three names of one file, two of another, two of a third, and a file
    // without a bound: the first names go together, then the second, then
    // the third.
    let bound = [
        Some((1, 1)),
        Some((1, 1)),
        Some((1, 2)),
        Some((1, 2)),
        None,
        Some((1, 3)),
        Some((1, 3)),
        Some((1, 3)),
    ];
    assert_eq!(
        compare_groups(&[1; 8], &bound, 1 << 20),
        [vec![0, 2, 4, 5], vec![1, 3, 6], vec![7]]
    );
    // Without bounds, groups keep the batch's order and limits.
    assert_eq!(
        compare_groups(&[3; 5], &[None; 5], 6),
        [vec![0, 1], vec![2, 3], vec![4]]
    );
}

#[test]
fn a_restricted_receiver_compares_many_linked_pairs_in_few_requests() {
    use std::os::unix::fs::MetadataExt;
    // Files of two names each and of distinct sizes, in one directory: the
    // two names of each file are taken one after the other.
    let pairs = 32;
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path();
    for directory in ["source", "target"] {
        std::fs::create_dir(root.join(directory)).unwrap();
    }
    let mut names = Vec::new();
    let mut inodes = Vec::new();
    for i in 0..pairs {
        let contents = vec![b'a' + (i % 26) as u8; 16 + i];
        let first = root.join("target").join(format!("pair{i:02}a"));
        std::fs::write(&first, &contents).unwrap();
        let inode = std::fs::metadata(&first).unwrap().ino();
        for name in [format!("pair{i:02}a"), format!("pair{i:02}b")] {
            if name.ends_with('b') {
                std::fs::hard_link(&first, root.join("target").join(&name)).unwrap();
            }
            std::fs::write(root.join("source").join(&name), &contents).unwrap();
            names.push((name, contents.clone()));
            inodes.push(inode);
        }
    }
    // Each name has a source time of its own, so keeping either name of a
    // file changes the change time both share.
    let files: Vec<_> = names
        .iter()
        .enumerate()
        .map(|(i, (name, _))| (name.as_str(), 1_600_000_000 + i as i64))
        .collect();
    let executed = copy_through_restricted_receiver(root, &files, 1, || {
        std::thread::sleep(std::time::Duration::from_millis(50));
    });
    for ((name, contents), inode) in names.iter().zip(&inodes) {
        let path = root.join("target").join(name);
        assert_eq!(std::fs::metadata(&path).unwrap().ino(), *inode, "{name}");
        assert_eq!(&std::fs::read(&path).unwrap(), contents, "{name}");
    }
    // The first names share one request and the second names another, so
    // each name is compared once.
    assert_eq!(executed.compared, vec![1; 2 * pairs]);
    assert_eq!((executed.hash_batches, executed.whole), (2, 0));
}

#[test]
fn a_restricted_receiver_preserving_permissions_compares_linked_names_together() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    // Preserving the sources' permissions, the receiver chooses no mode, and
    // binds no patch to the change time its names share.
    let count = 8;
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path();
    let (names, inode) = linked_destination(root, count, b"same");
    std::fs::set_permissions(
        root.join("target").join(&names[0]),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let files: Vec<_> = names
        .iter()
        .enumerate()
        .map(|(i, name)| (name.as_str(), 1_600_000_000 + i as i64))
        .collect();
    let executed = copy_through_restricted_receiver_with(root, &files, 1, true, || {
        std::thread::sleep(std::time::Duration::from_millis(50));
    });
    for name in &names {
        let path = root.join("target").join(name);
        let metadata = std::fs::metadata(&path).unwrap();
        assert_eq!(metadata.ino(), inode, "{name}");
        assert_eq!(metadata.mode() & 0o7777, 0o644, "{name}");
        assert_eq!(std::fs::read(&path).unwrap(), b"same", "{name}");
    }
    // All the names share one request, and each is compared once.
    assert_eq!(executed.compared, vec![1; count]);
    assert_eq!((executed.hash_batches, executed.whole), (1, 0));
}

#[test]
fn a_restricted_receiver_keeps_a_linked_destination_mode_changed_outside() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let count = 3;
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path();
    let (names, inode) = linked_destination(root, count, b"same");
    let first = root.join("target").join(&names[0]);
    std::fs::set_permissions(&first, std::fs::Permissions::from_mode(0o644)).unwrap();
    let files: Vec<_> = names
        .iter()
        .enumerate()
        .map(|(i, name)| (name.as_str(), 1_600_000_000 + i as i64))
        .collect();
    // The receiver authorizes the first patch to keep the mode the file
    // has then. Before it is carried out, the mode changes outside the
    // copy.
    let patches = std::sync::atomic::AtomicUsize::new(0);
    let changed = first.clone();
    let executed = copy_through_restricted_receiver(root, &files, 1, move || {
        std::thread::sleep(std::time::Duration::from_millis(50));
        if patches.fetch_add(1, Relaxed) == 0 {
            std::fs::set_permissions(&changed, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    });
    for name in &names {
        let path = root.join("target").join(name);
        let metadata = std::fs::metadata(&path).unwrap();
        assert_eq!(metadata.ino(), inode, "{name}");
        assert_eq!(std::fs::read(&path).unwrap(), b"same", "{name}");
        // The mode the file had when each name was kept, not the mode
        // chosen before the change.
        assert_eq!(metadata.mode() & 0o7777, 0o600, "{name}");
    }
    // The first patch found its condition stale, and its name was compared
    // again; the others, authorized after the change, once.
    let mut compared = executed.compared;
    compared.sort_unstable();
    assert_eq!(compared, [1, 1, 2]);
    assert_eq!(executed.whole, 0);
}

#[test]
fn a_restricted_receiver_replaces_a_linked_destination_that_keeps_changing() {
    use std::os::unix::fs::{FileExt, MetadataExt};
    // A short second block keeps what the retried patches send, and the
    // grant charges, small.
    let block = MIN_HASH_BLOCK_BYTES as usize;
    let contents: Vec<u8> = (0..block + 16).map(|i| (i % 251) as u8).collect();
    // One worker: with several, a write could also land while another
    // worker copies a name whole, which the receiver refuses to publish.
    for count in [3, 5] {
        let temporary = crate::test_support::tempdir().unwrap();
        let root = temporary.path();
        let (names, _) = linked_destination(root, count, &contents);
        // Every patch finds the second block of the file the names share
        // rewritten after the receiver authorized it.
        let shared = std::fs::OpenOptions::new()
            .write(true)
            .open(root.join("target").join(&names[0]))
            .unwrap();
        let writes = std::sync::atomic::AtomicU8::new(0);
        let files: Vec<_> = names
            .iter()
            .map(|name| (name.as_str(), 1_600_000_000))
            .collect();
        let executed = copy_through_restricted_receiver(root, &files, 1, move || {
            std::thread::sleep(std::time::Duration::from_millis(50));
            let write = writes.fetch_add(1, Relaxed).wrapping_add(1);
            shared.write_all_at(&[write; 16], block as u64).unwrap();
        });
        for name in &names {
            let path = root.join("target").join(name);
            assert_eq!(std::fs::read(&path).unwrap(), contents, "{count}: {name}");
            assert_eq!(
                std::fs::metadata(&path).unwrap().mtime(),
                1_600_000_000,
                "{count}: {name}"
            );
        }
        // Compared again once for each name the file has, the names are then
        // copied whole.
        assert_eq!(executed.compared, vec![count + 1; count], "{count}");
        assert_ne!(executed.whole, 0, "{count}");
    }
}

#[test]
fn a_restricted_receiver_compares_a_changing_file_again_only_for_its_names_in_the_copy() {
    use std::os::unix::fs::{FileExt, MetadataExt};
    let block = MIN_HASH_BLOCK_BYTES as usize;
    let contents: Vec<u8> = (0..block + 16).map(|i| (i % 251) as u8).collect();
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path();
    // Two of the file's twenty names are in the copy.
    let (names, _) = linked_destination(root, 2, &contents);
    link_outside(root, &names[0], 18);
    let first = root.join("target").join(&names[0]);
    assert_eq!(std::fs::metadata(&first).unwrap().nlink(), 20);
    // Every patch finds the file's second block rewritten after the receiver
    // authorized it.
    let shared = std::fs::OpenOptions::new()
        .write(true)
        .open(&first)
        .unwrap();
    let writes = std::sync::atomic::AtomicU8::new(0);
    let files: Vec<_> = names
        .iter()
        .map(|name| (name.as_str(), 1_600_000_000))
        .collect();
    let executed = copy_through_restricted_receiver(root, &files, 1, move || {
        std::thread::sleep(std::time::Duration::from_millis(50));
        let write = writes.fetch_add(1, Relaxed).wrapping_add(1);
        shared.write_all_at(&[write; 16], block as u64).unwrap();
    });
    for name in &names {
        let path = root.join("target").join(name);
        assert_eq!(std::fs::read(&path).unwrap(), contents, "{name}");
        assert_eq!(
            std::fs::metadata(&path).unwrap().mtime(),
            1_600_000_000,
            "{name}"
        );
    }
    // Compared again once for each name in the copy, not for each of the
    // file's names, the names are then copied whole.
    assert_eq!(executed.compared, [3, 3]);
    assert_ne!(executed.whole, 0);
}

fn start_rule(workers: usize, network_destination: bool) -> StartRule {
    StartRule {
        workers,
        automatic: true,
        network_destination,
        batch_files: None,
        batch_bytes: crate::transfer_tuning::DEFAULT_BATCH_BYTES,
    }
}

#[test]
fn fast_destinations_keep_their_starting_counts() {
    const KIB: u64 = 1024;
    let rule = start_rule(32, false);
    // A worker per 128 batched files or per batch of bytes, as before.
    assert_eq!(rule.batched(1, 4 * KIB), 1);
    assert_eq!(rule.batched(128, 128 * 4 * KIB), 1);
    assert_eq!(rule.batched(129, 129 * 4 * KIB), 2);
    assert_eq!(rule.batched(512, 512 * 4 * KIB), 4);
    assert_eq!(rule.batched(100_000, 100_000 * 4 * KIB), 32);
    assert_eq!(rule.batched(10, 10 * 64 * KIB), 1);
    assert_eq!(rule.streaming(600, 600 * 4 * KIB, true), 5);
    assert_eq!(rule.streaming(600, 600 * 1024 * KIB, false), 32);
    assert_eq!(rule.streaming(600, 600 * 70 * KIB, false), 5);
}

#[test]
fn network_destinations_start_a_worker_per_eight_small_files() {
    const KIB: u64 = 1024;
    let rule = start_rule(32, true);
    assert_eq!(rule.batched(1, 4 * KIB), 1);
    assert_eq!(rule.batched(8, 8 * 4 * KIB), 1);
    assert_eq!(rule.batched(9, 9 * 4 * KIB), 2);
    assert_eq!(rule.batched(128, 128 * 4 * KIB), 16);
    assert_eq!(rule.batched(256, 256 * 4 * KIB), 32);
    assert_eq!(rule.batched(100_000, 100_000 * 4 * KIB), 32);
    assert_eq!(rule.streaming(600, 600 * 4 * KIB, true), 32);
    // Trees with files too large to batch start as on a fast destination.
    assert_eq!(rule.streaming(600, 600 * 1024 * KIB, false), 32);
    assert_eq!(rule.streaming(600, 600 * 70 * KIB, false), 5);
    // Route caps stay in force: 8 over SSH, 16 over TCP.
    for cap in [8, 16] {
        let rule = start_rule(cap, true);
        assert_eq!(rule.batched(128, 128 * 4 * KIB), cap);
        assert_eq!(rule.batched(16, 16 * 4 * KIB), 2);
    }
}

#[test]
fn starting_counts_respect_limits_history_and_explicit_settings() {
    const KIB: u64 = 1024;
    // Resource limits or a remembered count have already set `workers`; the
    // rule starts no more than that.
    let limited = start_rule(4, true);
    assert_eq!(limited.batched(128, 128 * 4 * KIB), 4);
    assert_eq!(start_rule(2, true).batched(128, 128 * 4 * KIB), 2);
    // An explicit batch size also sets the files per starting worker.
    let batch = StartRule {
        batch_files: Some(32),
        ..start_rule(32, true)
    };
    assert_eq!(batch.batched(128, 128 * 4 * KIB), 4);
    // An explicit worker count starts that many, except that small batched
    // files are never split: at most one worker per file.
    for network_destination in [false, true] {
        for workers in [1, 8, 64] {
            let explicit = StartRule {
                automatic: false,
                ..start_rule(workers, network_destination)
            };
            assert_eq!(explicit.batched(1, 4 * KIB), 1);
            assert_eq!(explicit.batched(3, 3 * 4 * KIB), workers.min(3));
            assert_eq!(explicit.batched(128, 128 * 4 * KIB), workers);
            assert_eq!(explicit.streaming(600, 600 * 1024 * KIB, false), workers);
            assert_eq!(explicit.streaming(600, 600 * 4 * KIB, true), workers);
        }
    }
}

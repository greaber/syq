use super::*;
use crate::conn::Conn;
use crate::proto::*;

struct FinishingConn {
    events: Arc<Mutex<Vec<&'static str>>>,
    fail_fence: bool,
    fail_source: bool,
    fail_destination: bool,
}

impl Conn for FinishingConn {
    fn send(&mut self, _: Request) -> anyhow::Result<()> {
        unreachable!()
    }
    fn recv(&mut self) -> anyhow::Result<Response> {
        unreachable!()
    }
    fn fence_streaming_writes(&mut self) -> anyhow::Result<()> {
        self.events.lock().unwrap().push("fence");
        anyhow::ensure!(!self.fail_fence, "fence failed");
        Ok(())
    }
    fn stop_read_stream(&mut self) -> anyhow::Result<u64> {
        let mut events = self.events.lock().unwrap();
        assert_eq!(
            *events,
            ["fence"],
            "source drained before destination fence"
        );
        events.push("source");
        anyhow::ensure!(!self.fail_source, "source failed");
        Ok(17)
    }
    fn finish_streaming_writes(
        &mut self,
        sent: u64,
        fence: anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        assert_eq!(sent, 3);
        let mut events = self.events.lock().unwrap();
        assert_eq!(*events, ["fence", "source"]);
        events.push("destination");
        assert_eq!(fence.is_err(), self.fail_fence);
        fence?;
        anyhow::ensure!(!self.fail_destination, "destination failed");
        Ok(())
    }
    fn scan(
        &mut self,
        _: &[u8],
        _: Option<&RegisteredPath>,
        _: bool,
        _: &[String],
        _: bool,
        _: &mut dyn FnMut(Vec<Entry>) -> anyhow::Result<()>,
        _: &mut dyn FnMut(Vec<PathBytes>) -> anyhow::Result<()>,
        _: &mut dyn FnMut(String),
    ) -> anyhow::Result<()> {
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
        _: &mut dyn FnMut(Vec<String>) -> anyhow::Result<()>,
        _: &mut dyn FnMut(Vec<NativeRemoveOutcome>) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        unreachable!()
    }
}

#[test]
fn finishing_starts_the_fence_before_source_drain_and_checks_both_failures() {
    for fail_fence in [false, true] {
        for fail_source in [false, true] {
            for fail_destination in [false, true] {
                let events = Arc::new(Mutex::new(Vec::new()));
                let mut source = FinishingConn {
                    events: events.clone(),
                    fail_fence,
                    fail_source,
                    fail_destination,
                };
                let mut destination = FinishingConn {
                    events: events.clone(),
                    fail_fence,
                    fail_source,
                    fail_destination,
                };
                let (source, destination, _) = finish_range(&mut source, &mut destination, 3);
                assert_eq!(source.is_err(), fail_source);
                if let Ok(discarded) = source {
                    assert_eq!(discarded, 17);
                }
                assert_eq!(destination.is_err(), fail_fence || fail_destination);
                assert_eq!(*events.lock().unwrap(), ["fence", "source", "destination"]);
            }
        }
    }
}

#[test]
fn streaming_limit_accepts_repeated_and_zero_limits_but_never_grows() {
    let mut limit = 4096;
    for end in [4096, 2048, 2048, 1, 0] {
        shrink_limit(&mut limit, end).unwrap();
        assert_eq!(limit, end);
    }
    for end in [1, u64::MAX] {
        assert!(shrink_limit(&mut limit, end).is_err());
        assert_eq!(limit, 0);
    }
}

#[test]
fn draining_counts_discarded_payload_and_preserves_the_next_response() {
    let mut responses = [
        Response::Block {
            off: 0,
            hash: [0; 32],
            data: vec![0; 7],
        },
        Response::Block {
            off: 7,
            hash: [0; 32],
            data: vec![0; 11],
        },
        Response::ReadStreamDone,
        Response::Ok,
    ]
    .into_iter();
    assert_eq!(drain_reads(|| Ok(responses.next().unwrap())).unwrap(), 18);
    assert!(matches!(responses.next(), Some(Response::Ok)));
    let mut responses = [
        Response::Err("read failed".into()),
        Response::ReadStreamDone,
        Response::Ok,
    ]
    .into_iter();
    assert!(drain_reads(|| Ok(responses.next().unwrap())).is_err());
    assert!(matches!(responses.next(), Some(Response::Ok)));
}

#[test]
fn streaming_claim_preserves_a_stolen_suffix_and_checks_its_hash() {
    let range = Arc::new(Mutex::new(crate::sched::RangeState {
        idx: 0,
        pos: 0,
        end: 5,
    }));
    let mut data = b"abcdefgh".to_vec();
    let mut bad_hash = [0; 32];
    assert!(claim_block(&range, 0, &mut bad_hash, &mut data).is_err());
    assert_eq!(range.lock().unwrap().pos, 0);
    assert_eq!(data, b"abcdefgh");
    assert_eq!(bad_hash, [0; 32]);
    let mut hash = crate::fsops::content_digest(&data);
    assert_eq!(claim_block(&range, 0, &mut hash, &mut data).unwrap(), 5);
    assert_eq!(data, b"abcde");
    assert_eq!(hash, crate::fsops::content_digest(b"abcde"));
    assert_eq!(range.lock().unwrap().pos, 5);
    assert_eq!(claim_block(&range, 5, &mut hash, &mut data).unwrap(), 0);
    assert!(claim_block(&range, 6, &mut hash, &mut data).is_err());
}

#[test]
fn split_hashing_unlocks_the_range_and_revalidates_a_further_steal() {
    let range = Arc::new(Mutex::new(crate::sched::RangeState {
        idx: 0,
        pos: 0,
        end: 5,
    }));
    let mut data = b"abcdefgh".to_vec();
    let mut hash = crate::fsops::content_digest(&data);
    let mut hashed_lengths = Vec::new();
    let claimed = claim_block_with_digest(&range, 0, &mut hash, &mut data, |bytes| {
        let mut assigned = range.try_lock().expect("hashing held the range mutex");
        assert_eq!(assigned.pos, 0);
        hashed_lengths.push(bytes.len());
        assigned.end = 3;
        crate::fsops::content_digest(bytes)
    })
    .unwrap();
    assert_eq!(hashed_lengths, [8, 5, 3]);
    assert_eq!(claimed, 3);
    assert_eq!(range.lock().unwrap().pos, 3);
    assert_eq!(data, b"abc");
    assert_eq!(hash, crate::fsops::content_digest(b"abc"));
}

#[test]
fn split_hashing_preserves_payload_when_cancelled_or_position_changes() {
    for changed_position in [false, true] {
        let range = Arc::new(Mutex::new(crate::sched::RangeState {
            idx: 0,
            pos: 0,
            end: 5,
        }));
        let mut data = b"abcdefgh".to_vec();
        let original_hash = crate::fsops::content_digest(&data);
        let mut hash = original_hash;
        let claimed = claim_block_with_digest(&range, 0, &mut hash, &mut data, |bytes| {
            let mut assigned = range.try_lock().expect("hashing held the range mutex");
            if bytes.len() == 5 {
                if changed_position {
                    assigned.pos = 2;
                } else {
                    assigned.end = 0;
                }
            }
            crate::fsops::content_digest(bytes)
        });
        if changed_position {
            assert!(claimed.is_err());
            assert_eq!(range.lock().unwrap().pos, 2);
        } else {
            assert_eq!(claimed.unwrap(), 0);
            assert_eq!(range.lock().unwrap().pos, 0);
        }
        assert_eq!(data, b"abcdefgh");
        assert_eq!(hash, original_hash);
    }
}

#[test]
fn unsplit_or_exhausted_blocks_need_no_extra_hash() {
    for end in [0, 8, 16] {
        let range = Arc::new(Mutex::new(crate::sched::RangeState {
            idx: 0,
            pos: 0,
            end,
        }));
        let mut data = b"abcdefgh".to_vec();
        let mut hash = crate::fsops::content_digest(&data);
        let claimed = claim_block_with_digest(&range, 0, &mut hash, &mut data, |_| {
            panic!("only split frames need a coordinator-side hash")
        })
        .unwrap();
        assert_eq!(claimed, end.min(8));
        assert_eq!(range.lock().unwrap().pos, claimed);
        assert_eq!(data, b"abcdefgh");
    }
}

#[test]
fn streaming_replies_drain_without_a_block_credit_window() {
    let (tx, rx) = mpsc::sync_channel(1);
    let replies = WriteReplies::spawn(rx, None);
    let (finished, done) = mpsc::channel();
    let sender = std::thread::spawn(move || {
        for _ in 0..10_000 {
            tx.send(queued(Response::Ok)).unwrap();
        }
        tx.send(queued(Response::WriteStreamDone)).unwrap();
        tx.send(queued(Response::Path(b"next operation".to_vec())))
            .unwrap();
        finished.send(()).unwrap();
    });
    done.recv_timeout(Duration::from_secs(5))
        .expect("reply collection blocked without worker receives");
    let (rx, state) = replies.finish(false);
    assert_eq!(state.count, 10_000);
    assert!(state.fenced && state.error.is_none());
    assert!(matches!(
        rx.recv().unwrap().unwrap().value,
        Response::Path(_)
    ));
    sender.join().unwrap();
}

#[test]
fn streaming_replies_preserve_errors_and_wait_for_the_fence() {
    let (tx, rx) = mpsc::channel();
    let replies = WriteReplies::spawn(rx, None);
    tx.send(queued(Response::Ok)).unwrap();
    tx.send(queued(Response::EndpointError(WireError {
        message: "disk full".into(),
        io_kind: Some(crate::proto::WireIoKind::NoSpace),
        raw_os_error: None,
    })))
    .unwrap();
    tx.send(queued(Response::Err("later error".into())))
        .unwrap();
    tx.send(queued(Response::WriteStreamDone)).unwrap();
    let (_, state) = replies.finish(false);
    assert_eq!(state.count, 3);
    assert!(state.fenced);
    assert!(
        matches!(state.error, Some(Failure::Endpoint(error)) if error.io_kind == Some(crate::proto::WireIoKind::NoSpace))
    );
}

#[test]
fn streaming_replies_eof_is_not_success_and_abort_wakes_a_quiet_collector() {
    let (tx, rx) = mpsc::channel();
    let replies = WriteReplies::spawn(rx, None);
    tx.send(queued(Response::Ok)).unwrap();
    drop(tx);
    let (_, state) = replies.finish(false);
    assert!(!state.fenced && matches!(state.error, Some(Failure::Transport(_))));
    let (_tx, rx) = mpsc::channel();
    let replies = WriteReplies::spawn(rx, None);
    let start = std::time::Instant::now();
    let _ = replies.finish(true);
    assert!(start.elapsed() < Duration::from_secs(2));
}

fn queued(value: Response) -> io::Result<crate::conn::ReceivedResponse> {
    Ok(crate::conn::ReceivedResponse::from_frame((
        crate::wire_budget::Budgeted {
            value,
            hold: crate::wire_budget::Hold::new(),
        },
        std::time::Instant::now(),
    )))
}

fn test_credit(block: u64, count: u64) -> Arc<WriteCredit> {
    let credit = WriteCredit::new(
        crate::progress::Progress::new(false, false, None),
        Arc::new(AtomicU64::new(0)),
        block,
    );
    for _ in 0..count {
        credit.submit(block).unwrap();
    }
    credit
}

#[test]
fn streaming_credit_waits_for_acknowledgments_and_counts_short_tail_exactly() {
    let progress = crate::progress::Progress::new(false, false, None);
    let done = Arc::new(AtomicU64::new(0));
    let credit = WriteCredit::new(progress.clone(), done.clone(), 4096);
    for n in [4096, 4096, 13] {
        credit.submit(n).unwrap();
    }
    assert_eq!(progress.bytes_done.load(Ordering::Relaxed), 0);
    let (tx, rx) = mpsc::channel();
    let replies = WriteReplies::spawn(rx, Some(credit.clone()));
    for _ in 0..3 {
        tx.send(queued(Response::Ok)).unwrap();
    }
    tx.send(queued(Response::WriteStreamDone)).unwrap();
    let (_, state) = replies.finish(false);
    assert!(state.error.is_none());
    assert_eq!(credit.acknowledged(), 8205);
    assert_eq!(progress.bytes_done.load(Ordering::Relaxed), 8205);
    assert_eq!(done.load(Ordering::Relaxed), 8205);
}

#[test]
fn failed_stream_credit_retracts_before_retry_and_never_scores_failed_writes() {
    use crate::tune::Meter;
    let progress = crate::progress::Progress::new(false, false, None);
    let done = Arc::new(AtomicU64::new(0));
    let credit = WriteCredit::new(progress.clone(), done.clone(), 4096);
    for n in [4096, 4096, 7] {
        credit.submit(n).unwrap();
    }
    let (tx, rx) = mpsc::channel();
    let replies = WriteReplies::spawn(rx, Some(credit.clone()));
    tx.send(queued(Response::Ok)).unwrap();
    tx.send(queued(Response::Err("disk full".into()))).unwrap();
    tx.send(queued(Response::Ok)).unwrap();
    tx.send(queued(Response::WriteStreamDone)).unwrap();
    let (_, state) = replies.finish(false);
    assert!(matches!(state.error, Some(Failure::Rejected(_))));
    assert_eq!(credit.acknowledged(), 4096);
    assert_eq!(progress.bytes_done.load(Ordering::Relaxed), 4096);
    drop(state);
    drop(credit);
    progress.bytes_done.fetch_sub(4096, Ordering::Relaxed);
    done.fetch_sub(4096, Ordering::Relaxed);
    assert_eq!(progress.bytes(), 4096);
    let credit = WriteCredit::new(progress.clone(), done.clone(), 4096);
    credit.submit(4096).unwrap();
    let mut completed = Completions::new(Some(credit.clone()));
    completed.record(Response::Ok);
    assert_eq!(
        progress.bytes(),
        4096,
        "retry is not fresh useful throughput"
    );
    credit.submit(11).unwrap();
    completed.record(Response::Ok);
    assert_eq!(progress.bytes(), 4107);
    assert_eq!(done.load(Ordering::Relaxed), 4107);
}

#[test]
fn cancelled_collector_cannot_credit_after_caller_recovers() {
    let progress = crate::progress::Progress::new(false, false, None);
    let credit = WriteCredit::new(progress.clone(), Arc::new(AtomicU64::new(0)), 4096);
    credit.submit(4096).unwrap();
    let (tx, rx) = mpsc::channel();
    let replies = WriteReplies::spawn(rx, Some(credit.clone()));
    let (rx, state) = replies.finish(true);
    tx.send(queued(Response::Ok)).unwrap();
    assert_eq!(credit.acknowledged(), 0);
    drop(rx);
    drop(state);
    drop(credit);
    assert_eq!(progress.bytes_done.load(Ordering::Relaxed), 0);
}

#[test]
fn streaming_credit_rejects_extra_acknowledgments_and_nonfinal_short_blocks() {
    let credit = test_credit(4096, 1);
    let mut completed = Completions::new(Some(credit.clone()));
    completed.record(Response::Ok);
    completed.record(Response::Ok);
    assert!(matches!(completed.error, Some(Failure::Transport(_))));
    assert_eq!(credit.acknowledged(), 4096);
    let credit = test_credit(4096, 0);
    assert!(credit.submit(0).is_err());
    assert!(credit.submit(4097).is_err());
    credit.submit(3).unwrap();
    assert!(credit.submit(4096).is_err());
}

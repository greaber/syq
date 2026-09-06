//! Experimental streaming's write-reply collector. Data still travels through
//! the ordinary checked WriteRange operation. Replies are consumed as they
//! arrive, with constant-sized bookkeeping instead of a block-credit window.

use crate::proto::{Response, WireError};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Start the destination fence before draining the source, so independent
/// remote round trips overlap. Always finish both boundaries, even if either
/// one fails. Return destination send/join time without charging source drain
/// time to the worker's destination-wait diagnostic.
pub(crate) fn finish_range(
    source: &mut dyn crate::conn::Conn,
    destination: &mut dyn crate::conn::Conn,
    sent: u64,
) -> (anyhow::Result<u64>, anyhow::Result<()>, Duration) {
    let start = Instant::now();
    let fence = destination.fence_streaming_writes();
    let fence_wait = start.elapsed();
    let source = source.stop_read_stream();
    let start = Instant::now();
    let destination = destination.finish_streaming_writes(sent, fence);
    (source, destination, fence_wait + start.elapsed())
}

/// Only reduce the read limit. A late update can be behind the source's
/// current offset; it stops future reads but cannot recall queued frames.
pub(crate) fn shrink_limit(limit: &mut u64, end: u64) -> anyhow::Result<()> {
    anyhow::ensure!(end <= *limit, "read stream limit cannot increase");
    *limit = end;
    Ok(())
}

/// Observe a steal at the next consumer block boundary, without doing network
/// I/O under the scheduler lock. No per-block message or reply is required.
pub(crate) fn notify_shrunk_range(
    range: &crate::sched::RangeHandle,
    announced_end: &mut u64,
    source: &mut dyn crate::conn::Conn,
) -> anyhow::Result<bool> {
    let end = range.lock().unwrap().end;
    if end >= *announced_end {
        return Ok(false);
    }
    source.send(crate::proto::Request::ShrinkReadStream { end })?;
    *announced_end = end;
    Ok(true)
}

/// Drain source payload through the stop fence. These bytes were received but
/// not written, not a count of transport headers or retries.
pub(crate) fn drain_reads(
    mut receive: impl FnMut() -> anyhow::Result<Response>,
) -> anyhow::Result<u64> {
    let mut discarded = 0u64;
    let mut error = None;
    loop {
        match receive()? {
            Response::ReadStreamDone => return error.map_or(Ok(discarded), Err),
            Response::Block { data, .. } => discarded += data.len() as u64,
            Response::EndpointError(e) => {
                error.get_or_insert_with(|| crate::conn::endpoint_error(e));
            }
            Response::Err(e) => {
                error.get_or_insert_with(|| anyhow::anyhow!(e));
            }
            _ => anyhow::bail!("unexpected response while stopping a read stream"),
        }
    }
}

/// Accept only the prefix still assigned to this worker. A concurrently
/// stolen suffix may already be in flight, but must never be written twice.
pub(crate) fn claim_block(
    range: &crate::sched::RangeHandle,
    off: u64,
    hash: &mut crate::proto::ContentDigest,
    data: &mut Vec<u8>,
) -> anyhow::Result<u64> {
    claim_block_with_digest(range, off, hash, data, crate::fsops::content_digest)
}

fn claim_block_with_digest(
    range: &crate::sched::RangeHandle,
    off: u64,
    hash: &mut crate::proto::ContentDigest,
    data: &mut Vec<u8>,
    mut digest: impl FnMut(&[u8]) -> crate::proto::ContentDigest,
) -> anyhow::Result<u64> {
    let mut assigned = range.lock().unwrap();
    let mut verified = false;
    loop {
        anyhow::ensure!(
            assigned.pos == off,
            "streamed block does not match the scheduler position"
        );
        let claimed = (data.len() as u64).min(assigned.end - assigned.pos);
        if claimed == 0 || claimed == data.len() as u64 {
            assigned.pos += claimed;
            return Ok(claimed);
        }

        // Steal holds the scheduler mutex while taking this range mutex.
        // Hash neither the full frame nor its prefix in that critical section.
        // Keep the original payload intact until the boundary is revalidated.
        drop(assigned);
        if !verified {
            anyhow::ensure!(
                digest(data) == *hash,
                "streamed block hash mismatch before splitting"
            );
            verified = true;
        }
        let prefix_hash = digest(&data[..claimed as usize]);
        assigned = range.lock().unwrap();
        anyhow::ensure!(
            assigned.pos == off,
            "streamed block does not match the scheduler position"
        );
        if claimed != (data.len() as u64).min(assigned.end - assigned.pos) {
            // A further steal or cancellation won the race with hashing.
            // Recompute only the smaller prefix, not the validated full frame.
            continue;
        }
        assigned.pos += claimed;
        drop(assigned);
        data.truncate(claimed as usize);
        *hash = prefix_hash;
        return Ok(claimed);
    }
}

pub(crate) type Responses = mpsc::Receiver<io::Result<Response>>;

#[derive(Clone, Debug)]
pub(crate) enum Failure {
    Endpoint(WireError),
    Rejected(String),
    Transport(String),
}

#[derive(Clone, Default)]
pub(crate) struct Completions {
    pub count: u64,
    pub error: Option<Failure>,
    pub fenced: bool,
}

impl Completions {
    pub fn record(&mut self, response: Response) {
        self.count += 1;
        let error = match response {
            Response::Ok => return,
            Response::EndpointError(error) => Failure::Endpoint(error),
            Response::Err(error) => Failure::Rejected(error),
            _ => Failure::Transport("unexpected response to a streaming write".into()),
        };
        self.error.get_or_insert(error);
    }
}

pub(crate) struct WriteReplies {
    state: Arc<Mutex<Completions>>,
    abort: Arc<AtomicBool>,
    thread: Option<JoinHandle<Responses>>,
}

impl WriteReplies {
    pub fn spawn(rx: Responses) -> Self {
        let state = Arc::new(Mutex::new(Completions::default()));
        let abort = Arc::new(AtomicBool::new(false));
        let (status, stopped) = (state.clone(), abort.clone());
        let thread = std::thread::spawn(move || {
            while !stopped.load(Ordering::Acquire) {
                // Normally woken by a reply, not a timer. The timeout only
                // lets a failed sender cancel without leaking a drain thread.
                match rx.recv_timeout(Duration::from_millis(50)) {
                    Ok(Ok(Response::WriteStreamDone)) => {
                        status.lock().unwrap().fenced = true;
                        break;
                    }
                    Ok(Ok(response)) => status.lock().unwrap().record(response),
                    Err(mpsc::RecvTimeoutError::Timeout) => continue,
                    message => {
                        let error = match message {
                            Ok(Err(error)) => error.to_string(),
                            _ => "streaming response reader stopped".into(),
                        };
                        // A dead connection overrides a prior operation error:
                        // the caller must not reuse an unfenced connection.
                        status.lock().unwrap().error = Some(Failure::Transport(error));
                        break;
                    }
                }
            }
            rx
        });
        Self {
            state,
            abort,
            thread: Some(thread),
        }
    }

    pub fn status(&self) -> Completions {
        self.state.lock().unwrap().clone()
    }

    pub fn finish(mut self, abort: bool) -> (Responses, Completions) {
        self.abort.store(abort, Ordering::Release);
        let rx = self
            .thread
            .take()
            .unwrap()
            .join()
            .expect("write reply reader panicked");
        (rx, self.status())
    }
}

impl Drop for WriteReplies {
    fn drop(&mut self) {
        self.abort.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
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
        let replies = WriteReplies::spawn(rx);
        let (finished, done) = mpsc::channel();
        let sender = std::thread::spawn(move || {
            for _ in 0..10_000 {
                tx.send(Ok(Response::Ok)).unwrap();
            }
            tx.send(Ok(Response::WriteStreamDone)).unwrap();
            tx.send(Ok(Response::Path(b"next operation".to_vec())))
                .unwrap();
            finished.send(()).unwrap();
        });
        done.recv_timeout(Duration::from_secs(5))
            .expect("reply collection blocked without worker receives");
        let (rx, state) = replies.finish(false);
        assert_eq!(state.count, 10_000);
        assert!(state.fenced && state.error.is_none());
        assert!(matches!(rx.recv().unwrap().unwrap(), Response::Path(_)));
        sender.join().unwrap();
    }

    #[test]
    fn streaming_replies_preserve_errors_and_wait_for_the_fence() {
        let (tx, rx) = mpsc::channel();
        let replies = WriteReplies::spawn(rx);
        tx.send(Ok(Response::Ok)).unwrap();
        tx.send(Ok(Response::EndpointError(WireError {
            message: "disk full".into(),
            io_kind: Some(crate::proto::WireIoKind::NoSpace),
            raw_os_error: None,
        })))
        .unwrap();
        tx.send(Ok(Response::Err("later error".into()))).unwrap();
        tx.send(Ok(Response::WriteStreamDone)).unwrap();
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
        let replies = WriteReplies::spawn(rx);
        tx.send(Ok(Response::Ok)).unwrap();
        drop(tx);
        let (_, state) = replies.finish(false);
        assert!(!state.fenced && matches!(state.error, Some(Failure::Transport(_))));
        let (_tx, rx) = mpsc::channel();
        let replies = WriteReplies::spawn(rx);
        let start = std::time::Instant::now();
        let _ = replies.finish(true);
        assert!(start.elapsed() < Duration::from_secs(2));
    }
}

//! Experimental streaming's write-reply collector. Data still travels through
//! the ordinary checked WriteRange operation. Replies are consumed as they
//! arrive, with constant-sized bookkeeping instead of a block-credit window.

use crate::proto::{Response, WireError};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

/// Accept only the prefix still assigned to this worker. A concurrently
/// stolen suffix may already be in flight, but must never be written twice.
pub(crate) fn claim_block(
    range: &crate::sched::RangeHandle,
    off: u64,
    hash: &mut crate::proto::ContentDigest,
    data: &mut Vec<u8>,
) -> anyhow::Result<u64> {
    let mut range = range.lock().unwrap();
    anyhow::ensure!(
        range.pos == off,
        "streamed block does not match the scheduler position"
    );
    let claimed = (data.len() as u64).min(range.end - range.pos);
    if claimed > 0 && claimed < data.len() as u64 {
        anyhow::ensure!(
            crate::fsops::content_digest(data) == *hash,
            "streamed block hash mismatch before splitting"
        );
        data.truncate(claimed as usize);
        *hash = crate::fsops::content_digest(data);
    }
    range.pos += claimed;
    Ok(claimed)
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
        let mut hash = crate::fsops::content_digest(&data);
        assert_eq!(claim_block(&range, 0, &mut hash, &mut data).unwrap(), 5);
        assert_eq!(data, b"abcde");
        assert_eq!(hash, crate::fsops::content_digest(b"abcde"));
        assert_eq!(range.lock().unwrap().pos, 5);
        assert_eq!(claim_block(&range, 5, &mut hash, &mut data).unwrap(), 0);
        assert!(claim_block(&range, 6, &mut hash, &mut data).is_err());
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

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
#[cfg(test)]
pub(crate) fn claim_block(
    range: &crate::sched::RangeHandle,
    off: u64,
    hash: &mut crate::proto::ContentDigest,
    data: &mut Vec<u8>,
) -> anyhow::Result<u64> {
    claim_block_with_digest(range, off, hash, data, crate::fsops::content_digest)
}

pub(crate) fn claim_block_with_digest(
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

pub(crate) type Responses = mpsc::Receiver<io::Result<crate::conn::ReceivedResponse>>;

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
                    Ok(Ok(message)) => {
                        let (response, _hold) = message.into_parts();
                        if matches!(response, Response::WriteStreamDone) {
                            status.lock().unwrap().fenced = true;
                            break;
                        }
                        status.lock().unwrap().record(response);
                    }
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
mod tests;

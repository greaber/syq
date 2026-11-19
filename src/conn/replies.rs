//! The replies a remote connection's reader thread has decoded and the worker
//! has not yet taken.
//!
//! The queue holds a fixed number of replies. A source worker's connection
//! also limits the file data its queued replies carry: once that passes the
//! limit, the reader stops reading the connection until the worker takes
//! some, so that a destination slower than the link holds the source back
//! rather than filling this process with replies. Replies without file data,
//! such as those of unchanged or slightly edited files, never stop it.
//!
//! The reader reads on, whatever the queue holds, while a request is being
//! sent. A source blocked writing its replies stops reading requests, so a
//! send that waited for the queue to drain would wait for itself.

use super::ReceivedResponse;
use std::io;
use std::sync::mpsc::{self, RecvError, RecvTimeoutError, TryRecvError};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

/// The file data a reply carries, which counts against the byte limit.
pub(super) fn file_bytes(response: &crate::proto::Response) -> usize {
    use crate::proto::Response;
    match response {
        Response::Block { data, .. } => data.len(),
        Response::SmallBlocks(blocks) => {
            blocks.iter().flatten().map(|block| block.data.len()).sum()
        }
        Response::DifferingBlocks(files) => {
            files.iter().flatten().map(|file| file.data.len()).sum()
        }
        _ => 0,
    }
}

/// File data in queued replies, shared by a reader and its queue.
pub(super) struct QueuedBytes {
    limit: usize,
    state: Mutex<State>,
    changed: Condvar,
}

#[derive(Default)]
struct State {
    queued: usize,
    sending: usize,
    closed: bool,
}

impl QueuedBytes {
    pub(super) fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            limit,
            state: Mutex::default(),
            changed: Condvar::new(),
        })
    }

    /// The reader queued a reply carrying `bytes`.
    pub(super) fn queued(&self, bytes: usize) {
        self.state.lock().unwrap().queued += bytes;
    }

    /// Wait, before reading another reply, until the queued replies carry
    /// less than the limit or a request is being sent. False once the queue
    /// is gone and the reader should stop.
    pub(super) fn wait_for_room(&self) -> bool {
        let mut state = self.state.lock().unwrap();
        while state.queued >= self.limit && state.sending == 0 && !state.closed {
            state = self.changed.wait(state).unwrap();
        }
        !state.closed
    }

    fn taken(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        let mut state = self.state.lock().unwrap();
        state.queued -= bytes;
        if state.queued < self.limit {
            self.changed.notify_all();
        }
    }

    fn close(&self) {
        self.state.lock().unwrap().closed = true;
        self.changed.notify_all();
    }
}

/// Lets the reader read on while it lives.
pub(crate) struct Sending(Arc<QueuedBytes>);

impl Drop for Sending {
    fn drop(&mut self) {
        self.0.state.lock().unwrap().sending -= 1;
    }
}

/// The receiving end of a reader's queue.
pub(crate) struct Replies {
    rx: mpsc::Receiver<io::Result<ReceivedResponse>>,
    bytes: Option<Arc<QueuedBytes>>,
}

type Reply = io::Result<ReceivedResponse>;

impl Replies {
    pub(super) fn new(
        rx: mpsc::Receiver<io::Result<ReceivedResponse>>,
        bytes: Option<Arc<QueuedBytes>>,
    ) -> Self {
        Self { rx, bytes }
    }

    pub(crate) fn recv(&self) -> Result<Reply, RecvError> {
        let reply = self.rx.recv();
        self.taken(reply.as_ref().ok());
        reply
    }

    pub(crate) fn try_recv(&self) -> Result<Reply, TryRecvError> {
        let reply = self.rx.try_recv();
        self.taken(reply.as_ref().ok());
        reply
    }

    pub(crate) fn recv_timeout(&self, timeout: Duration) -> Result<Reply, RecvTimeoutError> {
        let reply = self.rx.recv_timeout(timeout);
        self.taken(reply.as_ref().ok());
        reply
    }

    fn taken(&self, reply: Option<&Reply>) {
        if let (Some(bytes), Some(Ok(reply))) = (&self.bytes, reply) {
            bytes.taken(reply.bytes);
        }
    }

    #[cfg(test)]
    pub(super) fn queued_bytes(&self) -> usize {
        self.bytes
            .as_ref()
            .map_or(0, |bytes| bytes.state.lock().unwrap().queued)
    }

    /// Mark a request as being sent, for as long as the result lives.
    pub(crate) fn sending(&self) -> Option<Sending> {
        let bytes = self.bytes.clone()?;
        bytes.state.lock().unwrap().sending += 1;
        bytes.changed.notify_all();
        Some(Sending(bytes))
    }
}

impl From<mpsc::Receiver<io::Result<ReceivedResponse>>> for Replies {
    fn from(rx: mpsc::Receiver<io::Result<ReceivedResponse>>) -> Self {
        Self::new(rx, None)
    }
}

impl Drop for Replies {
    fn drop(&mut self) {
        if let Some(bytes) = &self.bytes {
            bytes.close();
        }
    }
}

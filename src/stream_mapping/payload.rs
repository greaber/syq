//! Callback admission and completion, independent of byte-stream EOF.
use super::channel::{Channel, Message};
use crate::descriptor_copy::fd::Descriptor;
use anyhow::Result;
use std::{
    fs::File,
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::net::UnixStream,
    },
    sync::{
        atomic::{AtomicBool, Ordering::Relaxed},
        Arc,
    },
};

pub(crate) struct Payload {
    channel: Arc<Channel>,
    id: u64,
    started: AtomicBool,
    completed: AtomicBool,
}
impl Payload {
    pub(super) fn new(channel: Arc<Channel>, id: u64) -> Self {
        Self {
            channel,
            id,
            started: AtomicBool::new(false),
            completed: AtomicBool::new(false),
        }
    }
    pub(crate) fn open(
        &self,
        upload: bool,
        cancelled: Arc<AtomicBool>,
    ) -> Result<(Descriptor, Descriptor)> {
        // Each payload has one direction. Pipes also reuse the descriptor
        // engine's bounded capacity hint, reducing producer/consumer wakeups.
        let (reader, writer) = std::io::pipe()?;
        let (reader, writer) = (
            File::from(OwnedFd::from(reader)),
            File::from(OwnedFd::from(writer)),
        );
        let (native, callback) = if upload {
            (reader, writer)
        } else {
            (writer, reader)
        };
        let (commit, acknowledge) = UnixStream::pair()?;
        let descriptor = Descriptor::owned(native, upload, cancelled.clone())?;
        let commit = Descriptor::owned(File::from(OwnedFd::from(commit)), true, cancelled)?;
        self.channel.send(
            Message::Start {
                entry: self.id,
                direction: if upload { "produce" } else { "consume" },
            },
            &[callback.as_raw_fd(), acknowledge.as_raw_fd()],
        )?;
        self.started.store(true, Relaxed);
        Ok((descriptor, commit))
    }
    pub(crate) fn transferred(&self, error: Option<&anyhow::Error>) -> Result<()> {
        if self.started.load(Relaxed) && !self.completed.swap(true, Relaxed) {
            self.channel.send(
                Message::Transferred {
                    entry: self.id,
                    error: error.map(|e| format!("{e:#}")),
                },
                &[],
            )?;
        }
        Ok(())
    }
}

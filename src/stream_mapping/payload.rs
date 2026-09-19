//! Callback admission and completion, independent of byte-stream EOF.
use super::channel::Channel;
use crate::descriptor_copy::fd::Descriptor;
use anyhow::Result;
use serde_json::json;
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
        let (native, callback) = UnixStream::pair()?;
        let (commit, acknowledge) = UnixStream::pair()?;
        let descriptor =
            Descriptor::owned(File::from(OwnedFd::from(native)), upload, cancelled.clone())?;
        let commit = Descriptor::owned(File::from(OwnedFd::from(commit)), true, cancelled)?;
        self.channel.send(
            json!({"type": "start", "entry": self.id,
            "direction": if upload { "produce" } else { "consume" }}),
            &[callback.as_raw_fd(), acknowledge.as_raw_fd()],
        )?;
        self.started.store(true, Relaxed);
        Ok((descriptor, commit))
    }
    pub(crate) fn transferred(&self, error: Option<&anyhow::Error>) -> Result<()> {
        if self.started.load(Relaxed) && !self.completed.swap(true, Relaxed) {
            self.channel.send(
                json!({"type": "transferred", "entry": self.id,
                "error": error.map(|e| format!("{e:#}"))}),
                &[],
            )?;
        }
        Ok(())
    }
}

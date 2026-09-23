//! Versioned subprocess control socket. Payload bytes use separately owned FDs.
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{Read, Write},
    os::fd::{AsRawFd, FromRawFd, RawFd},
    os::unix::net::UnixStream,
    sync::Mutex,
};

const VERSION: u64 = 1;
const MAX_FRAME: usize = 65536;

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(super) enum Message<'a> {
    Hello { version: u64 },
    Start { entry: u64, direction: &'a str },
    Transferred { entry: u64, error: Option<String> },
    End,
}
#[derive(Deserialize)]
struct Hello {
    version: u64,
}

pub(super) struct Channel(Mutex<UnixStream>);
impl Channel {
    pub fn connect(fd: RawFd) -> Result<Self> {
        // Take ownership before any helper can inherit the stream control socket.
        ensure!(
            fd > 2,
            "stream mapping control descriptor must be greater than 2"
        );
        ensure!(
            unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != -1,
            "protect stream mapping control descriptor: {}",
            std::io::Error::last_os_error()
        );
        let descriptor = unsafe { File::from_raw_fd(fd) };
        let socket = UnixStream::from(std::os::fd::OwnedFd::from(descriptor));
        socket
            .peer_addr()
            .context("stream mapping control descriptor must be a connected Unix socket")?;
        let channel = Self(Mutex::new(socket));
        channel.send(Message::Hello { version: VERSION }, &[])?;
        let mut socket = channel.0.lock().unwrap();
        let (marker, descriptors) = crate::descriptor_broker::receive_message(&socket, 1)?;
        ensure!(
            marker == b"S" && descriptors.is_empty(),
            "invalid stream mapping handshake"
        );
        let mut length = [0; 4];
        socket.read_exact(&mut length)?;
        let length = u32::from_be_bytes(length) as usize;
        ensure!(
            length > 0 && length <= MAX_FRAME,
            "invalid stream mapping handshake length"
        );
        let mut body = vec![0; length];
        socket.read_exact(&mut body)?;
        let hello: Hello = serde_json::from_slice(&body)?;
        ensure!(
            hello.version == VERSION,
            "unsupported stream mapping protocol version"
        );
        drop(socket);
        Ok(channel)
    }
    pub fn send(&self, message: Message<'_>, descriptors: &[RawFd]) -> Result<()> {
        let payload = serde_json::to_vec(&message)?;
        ensure!(
            payload.len() <= MAX_FRAME,
            "stream mapping control message is too large"
        );
        let mut socket = self.0.lock().unwrap();
        // Restrict recvmsg to this marker so stream reads cannot split or
        // accidentally consume the descriptors attached to the next frame.
        crate::descriptor_broker::send_message(socket.as_raw_fd(), b"S", descriptors)?;
        socket.write_all(&(payload.len() as u32).to_be_bytes())?;
        socket.write_all(&payload)?;
        Ok(())
    }
}

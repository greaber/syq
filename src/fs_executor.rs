//! Startup handoff for filesystem executors. The caller retains its selected
//! objects until SCM_RIGHTS has installed independent descriptors on the worker.
use anyhow::{Context, Result};
use std::fs::File;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd};
use std::os::unix::net::UnixStream;
use std::sync::mpsc;
use std::thread::JoinHandle;

/// Start an executor without moving any descriptor-owning Rust value between
/// tables. The only inherited descriptor it adopts is a private bootstrap socket.
///
/// # Safety
/// Neither closure may capture descriptor-owning values, or access foreign
/// descriptors in global state. `setup` receives only descriptors imported into
/// its own table. `run` and all destructors for its state execute on that table.
pub(crate) unsafe fn spawn<S: 'static>(
    name: String,
    require_private: bool,
    handles: &[&File],
    setup: impl FnOnce(Vec<File>) -> Result<S> + Send + 'static,
    run: impl FnOnce(S) + Send + 'static,
) -> Result<Option<JoinHandle<()>>> {
    fn above_stdio(socket: UnixStream) -> Result<UnixStream> {
        if socket.as_raw_fd() >= 3 {
            return Ok(socket);
        }
        let duplicate = unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
        if duplicate < 0 {
            return Err(std::io::Error::last_os_error()).context("duplicate bootstrap socket");
        }
        Ok(unsafe { UnixStream::from_raw_fd(duplicate) })
    }
    let (sender, inherited) = UnixStream::pair().context("create executor bootstrap socket")?;
    let sender = above_stdio(sender)?;
    let inherited = above_stdio(inherited)?;
    let socket_fd = inherited.as_raw_fd();
    let count = handles.len();
    let (table_ready, table_rx) = mpsc::sync_channel(1);
    let (initialized, initialized_rx) = mpsc::sync_channel(1);
    let thread = std::thread::Builder::new()
        .name(name)
        .spawn(move || {
            let bootstrap = (|| -> Result<Option<UnixStream>> {
                // SAFETY: only a borrowed numeric socket identifier is captured.
                // The caller keeps its owning value until table_ready acknowledges
                // that this thread has adopted a private copy or a shared-table dup.
                let private = unsafe { crate::sys::isolate_descriptor_table(Some(socket_fd))? };
                if !private && require_private {
                    let _ = table_ready.send(Ok(false));
                    return Ok(None);
                }
                let socket = if private {
                    unsafe { UnixStream::from_raw_fd(socket_fd) }
                } else {
                    let owned =
                        unsafe { BorrowedFd::borrow_raw(socket_fd) }.try_clone_to_owned()?;
                    UnixStream::from(owned)
                };
                table_ready
                    .send(Ok(true))
                    .map_err(|_| anyhow::anyhow!("executor bootstrap caller stopped"))?;
                Ok(Some(socket))
            })();
            let socket = match bootstrap {
                Ok(Some(socket)) => socket,
                Ok(None) => return,
                Err(error) => {
                    let _ = table_ready.send(Err(error));
                    return;
                }
            };
            let setup = (|| -> Result<S> {
                let mut handles = Vec::with_capacity(count);
                while handles.len() < count {
                    let (payload, files) = crate::descriptor_broker::receive_message(&socket, 1)?;
                    anyhow::ensure!(
                        payload == [1] && !files.is_empty() && handles.len() + files.len() <= count,
                        "invalid executor descriptor handoff"
                    );
                    handles.extend(files);
                }
                drop(socket);
                setup(handles)
            })();
            match setup {
                Ok(state) => {
                    if initialized.send(Ok(())).is_ok() {
                        run(state);
                    }
                }
                Err(error) => {
                    let _ = initialized.send(Err(error));
                }
            }
        })
        .context("start filesystem executor")?;
    let table = table_rx
        .recv()
        .context("executor stopped before table setup")
        .and_then(|result| result);
    drop(inherited);
    match table {
        Ok(true) => {}
        other => {
            drop(sender);
            let _ = thread.join();
            return other.map(|_| None);
        }
    }
    let sent = handles.chunks(3).try_for_each(|files| {
        let descriptors: Vec<_> = files.iter().map(|file| file.as_raw_fd()).collect();
        crate::descriptor_broker::send_message(sender.as_raw_fd(), &[1], &descriptors)
    });
    drop(sender);
    if let Err(error) = sent {
        let _ = thread.join();
        return Err(error).context("send executor descriptors");
    }
    match initialized_rx
        .recv()
        .context("executor stopped during initialization")
        .and_then(|result| result)
    {
        Ok(()) => Ok(Some(thread)),
        Err(error) => {
            let _ = thread.join();
            Err(error)
        }
    }
}

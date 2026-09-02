//! Shared lifecycle for private, bounded Unix-socket brokers.
//!
//! The socket lives in a mode-0700 temporary directory and is itself mode
//! 0600. Dropping the broker closes active clients, joins its listener and
//! client threads, and removes the directory. Signal cleanup removes private
//! broker directories before restoring the signal's default action.

use anyhow::{bail, Context, Result};
use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;

static SIGNAL_CLEANUP_PATHS: OnceLock<Arc<Mutex<HashSet<PathBuf>>>> = OnceLock::new();
static SIGNAL_CLEANUP_THREAD: OnceLock<io::Result<()>> = OnceLock::new();

fn register_signal_cleanup(path: &Path) -> Result<()> {
    let paths = SIGNAL_CLEANUP_PATHS
        .get_or_init(|| Arc::new(Mutex::new(HashSet::new())))
        .clone();
    let result = SIGNAL_CLEANUP_THREAD.get_or_init(|| {
        let mut signals = signal_hook::iterator::Signals::new([
            signal_hook::consts::SIGINT,
            signal_hook::consts::SIGTERM,
        ])?;
        let cleanup_paths = Arc::clone(&paths);
        thread::Builder::new()
            .name("syq-broker-signal-cleanup".into())
            .spawn(move || {
                if let Some(signal) = signals.forever().next() {
                    let paths: Vec<_> = cleanup_paths
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .iter()
                        .cloned()
                        .collect();
                    for path in paths {
                        let _ = std::fs::remove_dir_all(path);
                    }
                    let _ = signal_hook::low_level::emulate_default_handler(signal);
                }
            })?;
        Ok(())
    });
    if let Err(error) = result {
        return Err(io::Error::new(error.kind(), error.to_string()))
            .context("register private broker signal cleanup");
    }
    paths
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(path.to_path_buf());
    Ok(())
}

fn unregister_signal_cleanup(path: &Path) {
    if let Some(paths) = SIGNAL_CLEANUP_PATHS.get() {
        paths
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(path);
    }
}

pub(crate) struct PrivateBrokerConfig<'a> {
    pub(crate) directory_prefix: &'a str,
    pub(crate) socket_name: &'a str,
    pub(crate) listener_thread: &'a str,
    pub(crate) client_thread: &'a str,
    pub(crate) max_connections: usize,
    pub(crate) io_timeout: Duration,
}

/// A running private Unix-socket broker.
pub(crate) struct PrivateBroker {
    socket_path: PathBuf,
    shutdown: Arc<AtomicBool>,
    connections: Arc<ConnectionRegistry>,
    listener_thread: Option<JoinHandle<()>>,
    socket_dir: tempfile::TempDir,
}

impl PrivateBroker {
    pub(crate) fn start<F>(config: PrivateBrokerConfig<'_>, handler: F) -> Result<Self>
    where
        F: Fn(TrackedStream, Arc<ConnectionRegistry>) + Send + Sync + 'static,
    {
        if config.max_connections == 0 {
            bail!("private broker needs at least one connection slot");
        }
        let socket_dir = tempfile::Builder::new()
            .prefix(config.directory_prefix)
            .tempdir()
            .context("create private broker directory")?;
        std::fs::set_permissions(socket_dir.path(), std::fs::Permissions::from_mode(0o700))?;
        let socket_path = socket_dir.path().join(config.socket_name);
        let listener = UnixListener::bind(&socket_path)
            .with_context(|| format!("bind private broker at {}", socket_path.display()))?;
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        register_signal_cleanup(socket_dir.path())?;

        let shutdown = Arc::new(AtomicBool::new(false));
        let connections = Arc::new(ConnectionRegistry::new(config.io_timeout));
        let thread_shutdown = Arc::clone(&shutdown);
        let thread_connections = Arc::clone(&connections);
        let handler = Arc::new(handler);
        let max_connections = config.max_connections;
        let client_thread = config.client_thread.to_owned();
        let listener_thread = thread::Builder::new()
            .name(config.listener_thread.to_owned())
            .spawn(move || {
                accept_connections(
                    listener,
                    max_connections,
                    &client_thread,
                    thread_shutdown,
                    thread_connections,
                    handler,
                )
            });
        let listener_thread = match listener_thread {
            Ok(thread) => thread,
            Err(error) => {
                unregister_signal_cleanup(socket_dir.path());
                return Err(error).context("start private broker listener");
            }
        };

        Ok(Self {
            socket_path,
            shutdown,
            connections,
            listener_thread: Some(listener_thread),
            socket_dir,
        })
    }

    pub(crate) fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    #[cfg(test)]
    pub(crate) fn active_connections(&self) -> usize {
        self.connections.active()
    }
}

impl std::fmt::Debug for PrivateBroker {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PrivateBroker")
            .field("socket_path", &self.socket_path)
            .finish_non_exhaustive()
    }
}

impl Drop for PrivateBroker {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        self.connections.shutdown_all();
        // Wake accept immediately instead of waiting for the nonblocking poll.
        let _ = UnixStream::connect(&self.socket_path);
        if let Some(listener) = self.listener_thread.take() {
            let _ = listener.join();
        }
        unregister_signal_cleanup(self.socket_dir.path());
    }
}

fn accept_connections<F>(
    listener: UnixListener,
    max_connections: usize,
    client_thread: &str,
    shutdown: Arc<AtomicBool>,
    connections: Arc<ConnectionRegistry>,
    handler: Arc<F>,
) where
    F: Fn(TrackedStream, Arc<ConnectionRegistry>) + Send + Sync + 'static,
{
    let mut workers: Vec<JoinHandle<()>> = Vec::new();
    while !shutdown.load(Ordering::Acquire) {
        reap_workers(&mut workers);
        match listener.accept() {
            Ok((stream, _)) => {
                if workers.len() >= max_connections {
                    let _ = stream.shutdown(Shutdown::Both);
                    continue;
                }
                let Ok(stream) = connections.track(stream) else {
                    continue;
                };
                let worker_handler = Arc::clone(&handler);
                let worker_connections = Arc::clone(&connections);
                if let Ok(worker) = thread::Builder::new()
                    .name(client_thread.to_owned())
                    .spawn(move || worker_handler(stream, worker_connections))
                {
                    workers.push(worker);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(_) => break,
        }
    }
    connections.shutdown_all();
    for worker in workers {
        let _ = worker.join();
    }
}

fn reap_workers(workers: &mut Vec<JoinHandle<()>>) {
    let mut index = 0;
    while index < workers.len() {
        if workers[index].is_finished() {
            let worker = workers.swap_remove(index);
            let _ = worker.join();
        } else {
            index += 1;
        }
    }
}

pub(crate) struct ConnectionRegistry {
    next_id: AtomicU64,
    streams: Mutex<HashMap<u64, UnixStream>>,
    io_timeout: Duration,
}

impl ConnectionRegistry {
    pub(crate) fn new(io_timeout: Duration) -> Self {
        Self {
            next_id: AtomicU64::new(0),
            streams: Mutex::new(HashMap::new()),
            io_timeout,
        }
    }

    pub(crate) fn track(self: &Arc<Self>, stream: UnixStream) -> io::Result<TrackedStream> {
        stream.set_read_timeout(Some(self.io_timeout))?;
        stream.set_write_timeout(Some(self.io_timeout))?;
        let registered = stream.try_clone()?;
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.streams
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(id, registered);
        Ok(TrackedStream {
            stream,
            id,
            registry: Arc::clone(self),
        })
    }

    fn shutdown_all(&self) {
        let streams = self
            .streams
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for stream in streams.values() {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }

    #[cfg(test)]
    fn active(&self) -> usize {
        self.streams
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }
}

pub(crate) struct TrackedStream {
    stream: UnixStream,
    id: u64,
    registry: Arc<ConnectionRegistry>,
}

impl TrackedStream {
    #[cfg(test)]
    pub(crate) fn read_timeout(&self) -> io::Result<Option<Duration>> {
        self.stream.read_timeout()
    }

    #[cfg(test)]
    pub(crate) fn write_timeout(&self) -> io::Result<Option<Duration>> {
        self.stream.write_timeout()
    }
}

impl AsRawFd for TrackedStream {
    fn as_raw_fd(&self) -> RawFd {
        self.stream.as_raw_fd()
    }
}

impl Drop for TrackedStream {
    fn drop(&mut self) {
        self.registry
            .streams
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.id);
    }
}

impl Read for TrackedStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buffer)
    }
}

impl Write for TrackedStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.stream.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broker_uses_private_modes_and_removes_its_directory() {
        let broker = PrivateBroker::start(
            PrivateBrokerConfig {
                directory_prefix: "syq-private-broker-test-",
                socket_name: "broker.sock",
                listener_thread: "syq-private-test-listener",
                client_thread: "syq-private-test-client",
                max_connections: 1,
                io_timeout: Duration::from_secs(1),
            },
            |_, _| {},
        )
        .unwrap();
        let socket = broker.socket_path().to_path_buf();
        let directory = socket.parent().unwrap().to_path_buf();

        assert_eq!(
            std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
            0o600
        );

        drop(broker);
        assert!(!directory.exists());
    }
}

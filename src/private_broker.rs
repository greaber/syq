//! Shared lifecycle for private, bounded Unix-socket brokers.
//!
//! The socket lives in a mode-0700 directory of its own and is itself mode
//! 0600. Dropping the broker closes active clients, joins its listener and
//! client threads, and removes the directory. Signal cleanup removes private
//! broker directories before the signal ends the process.
//!
//! Other processes join a broker with a [`BrokerTicket`]: the name of the
//! broker's directory and its secret. The process acting on a ticket looks
//! for that name in a [`BrokerBase`] it chooses itself, never in a directory
//! the ticket's sender names.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;

static SIGNAL_CLEANUP_PATHS: OnceLock<Arc<Mutex<HashSet<PathBuf>>>> = OnceLock::new();
static SIGNAL_CLEANUP: OnceLock<io::Result<()>> = OnceLock::new();

fn register_signal_cleanup(path: &Path) -> Result<()> {
    let paths = SIGNAL_CLEANUP_PATHS
        .get_or_init(|| Arc::new(Mutex::new(HashSet::new())))
        .clone();
    let result = SIGNAL_CLEANUP.get_or_init(|| {
        let cleanup_paths = Arc::clone(&paths);
        // Removing a socket directory is quick; it runs before slower
        // cleanup, such as removing a copy's temporary files.
        let cleanup = crate::process::termination::add_first(move |_| {
            let paths: Vec<_> = cleanup_paths
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .iter()
                .cloned()
                .collect();
            for path in paths {
                let _ = std::fs::remove_dir_all(path);
            }
        })?;
        // Brokers come and go; the paths they leave registered are removed
        // whenever the process is interrupted.
        std::mem::forget(cleanup);
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

/// An owner-only temporary directory that is removed when it is dropped,
/// and also when a termination signal ends the process first.
#[derive(Debug)]
pub(crate) struct SignalCleanedDir(tempfile::TempDir);

impl SignalCleanedDir {
    pub(crate) fn new(prefix: &str) -> Result<Self> {
        let directory = private_temp_dir(prefix)?;
        register_signal_cleanup(directory.path())?;
        Ok(Self(directory))
    }

    pub(crate) fn path(&self) -> &Path {
        self.0.path()
    }
}

impl Drop for SignalCleanedDir {
    fn drop(&mut self) {
        unregister_signal_cleanup(self.0.path());
    }
}

/// Create an owner-only directory in the temporary directory.
pub(crate) fn private_temp_dir(prefix: &str) -> io::Result<tempfile::TempDir> {
    // Request the mode at creation: tempfile otherwise uses 0777 minus the
    // umask, which can let group members replace entries.
    tempfile::Builder::new()
        .prefix(prefix)
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
}

/// The socket's name in every directory a ticket names.
const TICKET_SOCKET: &str = "s";
/// Longest directory name a ticket carries.
const MAX_TICKET_NAME: usize = 32;
/// Bytes of a ticket's secret.
pub(crate) const TICKET_SECRET_LEN: usize = 32;

/// Where the directories that tickets name live. A ticket carries only a
/// directory's name; the process acting on it chooses the base itself, so
/// whoever sent the ticket cannot point it at a socket anywhere else.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BrokerBase {
    /// The current directory: the enrollment directory a restricted
    /// receiver checked and entered when it started, and keeps as its
    /// working directory while its brokers run. A copy through one
    /// enrollment cannot reach another enrollment's copies, or ordinary ones.
    Enrollment,
    /// `syq-UID` in the user's runtime directory, or else in the
    /// temporary directory: this account's directory for the sockets of
    /// its ordinary copies. It must belong to this account and have mode
    /// 0700, since in a shared `/tmp` another user could have made it first.
    Account,
}

/// The directory a base is in.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BaseParent {
    /// The base is the current directory itself.
    Current,
    /// The user's runtime directory, `XDG_RUNTIME_DIR`.
    Runtime,
    /// The temporary directory, `TMPDIR`, where other users can make the
    /// base first.
    Temporary,
}

impl BaseParent {
    /// The variable that moves this parent.
    fn variable(self) -> Option<&'static str> {
        match self {
            Self::Current => None,
            Self::Runtime => Some("XDG_RUNTIME_DIR"),
            Self::Temporary => Some("TMPDIR"),
        }
    }
}

impl BrokerBase {
    /// The base, and the directory it is in.
    fn locate(self) -> (PathBuf, BaseParent) {
        match self {
            Self::Enrollment => (PathBuf::from("."), BaseParent::Current),
            Self::Account => match account_parent(crate::user_dirs::runtime_dir()) {
                Some(runtime) => (account_directory(&runtime), BaseParent::Runtime),
                None => (
                    account_directory(&std::env::temp_dir()),
                    BaseParent::Temporary,
                ),
            },
        }
    }

    #[cfg(test)]
    fn path(self) -> PathBuf {
        self.locate().0
    }

    /// The checked base, for a broker to listen in, and the directory it is
    /// in. The account's directory is made when it is missing.
    fn prepare(self) -> Result<(PathBuf, BaseParent)> {
        let (path, parent) = self.locate();
        self.explain(check_base(&path, self == Self::Account), &path, parent)?;
        Ok((path, parent))
    }

    /// The checked base, for a ticket to be looked up in.
    fn existing(self) -> Result<PathBuf> {
        let (path, parent) = self.locate();
        self.explain(check_base(&path, false), &path, parent)?;
        Ok(path)
    }

    fn explain(
        self,
        checked: Result<(), BaseError>,
        path: &Path,
        parent: BaseParent,
    ) -> Result<()> {
        let error = match (self, checked) {
            (_, Ok(())) => return Ok(()),
            (
                Self::Enrollment,
                Err(BaseError::Unavailable(error) | BaseError::NotPrivate(error)),
            ) => return Err(error.context("check the enrollment directory")),
            (Self::Account, Err(BaseError::Unavailable(error))) => error,
            (Self::Account, Err(BaseError::NotPrivate(error))) => {
                let mut advice = format!(
                    "{} must be a directory of this account's with mode 0700",
                    path.display()
                );
                if parent == BaseParent::Temporary {
                    advice.push_str("; if another user made it, ask them or an administrator to remove it, or set TMPDIR to a directory of your own");
                }
                error.context(advice)
            }
        };
        Err(error.context(format!(
            "syq keeps the sockets of running copies in {}",
            path.display()
        )))
    }
}

/// The user's runtime directory `runtime`, when it is set and nobody else
/// can add to it: a directory of this account's that it, and only it, can
/// write to. Otherwise the account's directory goes in the temporary
/// directory.
fn account_parent(runtime: Option<PathBuf>) -> Option<PathBuf> {
    runtime.filter(|runtime| {
        std::fs::metadata(runtime).is_ok_and(|metadata| {
            metadata.is_dir()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o322 == 0o300
        })
    })
}

/// The account's directory for the sockets of ordinary copies in `parent`.
fn account_directory(parent: &Path) -> PathBuf {
    parent.join(format!("syq-{}", unsafe { libc::geteuid() }))
}

/// Why a base directory cannot be used.
#[derive(Debug)]
enum BaseError {
    /// It is missing, or could not be made or opened.
    Unavailable(anyhow::Error),
    /// Something is there that is not an owner-only directory of this
    /// account's: a link, another kind of file, another account's
    /// directory, or one with other permissions.
    NotPrivate(anyhow::Error),
}

/// Check that `path` is an owner-only directory of this account's, not a
/// link to one. With `create`, make it first when nothing is there; an
/// existing directory is never changed, only checked.
fn check_base(path: &Path, create: bool) -> Result<(), BaseError> {
    let created = create
        && match std::fs::DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => true,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => false,
            Err(error) => {
                return Err(BaseError::Unavailable(
                    anyhow::Error::new(error).context(format!("create {}", path.display())),
                ))
            }
        };
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| {
            // O_NOFOLLOW refuses a link with ELOOP, and O_DIRECTORY anything
            // else that is not a directory with ENOTDIR.
            let not_private = matches!(error.raw_os_error(), Some(libc::ELOOP | libc::ENOTDIR));
            let error = anyhow::Error::new(error).context(format!("open {}", path.display()));
            if not_private {
                BaseError::NotPrivate(error)
            } else {
                BaseError::Unavailable(error)
            }
        })?;
    // Only the umask can have narrowed the mode of a directory this call
    // made.
    if created && unsafe { libc::fchmod(directory.as_raw_fd(), 0o700) } != 0 {
        return Err(BaseError::Unavailable(
            anyhow::Error::new(io::Error::last_os_error())
                .context(format!("restrict {}", path.display())),
        ));
    }
    crate::delegation::validate_private_directory(&directory, path).map_err(BaseError::NotPrivate)
}

/// The longest socket path this system's `sockaddr_un` holds, without its
/// terminating NUL.
fn max_socket_path() -> usize {
    // SAFETY: an all-zero sockaddr_un is a valid value.
    let address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_path.len() - 1
}

/// The name of a broker's directory as a ticket carries it: letters, digits
/// and `-`, at most [`MAX_TICKET_NAME`] bytes. It can name only an entry
/// directly in the base directory, never `.`, `..` or a path.
#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(try_from = "String", into = "String")]
struct TicketName(String);

impl TryFrom<String> for TicketName {
    type Error = anyhow::Error;

    fn try_from(name: String) -> Result<Self> {
        if name.is_empty()
            || name.len() > MAX_TICKET_NAME
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            bail!("invalid broker ticket name");
        }
        Ok(Self(name))
    }
}

impl From<TicketName> for String {
    fn from(name: TicketName) -> Self {
        name.0
    }
}

/// What joins another process's broker: the name of its directory in a
/// [`BrokerBase`], and the secret the broker admits. The secret alone
/// authenticates; the name only finds the socket.
#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct BrokerTicket {
    name: TicketName,
    secret: [u8; TICKET_SECRET_LEN],
}

impl PartialEq for BrokerTicket {
    /// A peer's ticket is compared with this process's own, so the secrets
    /// are compared in constant time.
    fn eq(&self, other: &Self) -> bool {
        let secret = bool::from(subtle::ConstantTimeEq::ct_eq(
            self.secret.as_slice(),
            other.secret.as_slice(),
        ));
        secret & (self.name == other.name)
    }
}

impl Eq for BrokerTicket {}

impl std::fmt::Debug for BrokerTicket {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerTicket")
            .field("name", &self.name.0)
            .finish_non_exhaustive()
    }
}

impl BrokerTicket {
    fn new(name: &str, secret: [u8; TICKET_SECRET_LEN]) -> Result<Self> {
        Ok(Self {
            name: TicketName::try_from(name.to_owned())?,
            secret,
        })
    }

    /// Read a ticket written by [`BrokerTicket::encode`].
    pub(crate) fn parse(text: &str) -> Result<Self> {
        let parsed = (|| {
            let (name, encoded) = text.split_once(':')?;
            if encoded.len() != TICKET_SECRET_LEN * 2
                || !encoded
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return None;
            }
            let mut secret = [0u8; TICKET_SECRET_LEN];
            for (index, byte) in secret.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16).ok()?;
            }
            Self::new(name, secret).ok()
        })();
        parsed.context("invalid broker ticket")
    }

    /// The ticket as text: its name, `:`, and its secret in lowercase hex.
    pub(crate) fn encode(&self) -> String {
        let mut text = self.name.0.clone();
        text.push(':');
        for byte in self.secret {
            text.push_str(&format!("{byte:02x}"));
        }
        text
    }

    pub(crate) fn secret(&self) -> &[u8; TICKET_SECRET_LEN] {
        &self.secret
    }

    /// Connect to the broker this ticket names in `base`. The base and the
    /// broker's directory must both be owner-only directories of this
    /// account's; the broker then checks the secret.
    pub(crate) fn connect(&self, base: BrokerBase) -> Result<UnixStream> {
        self.connect_in(&base.existing()?)
    }

    fn connect_in(&self, base: &Path) -> Result<UnixStream> {
        let directory = base.join(&self.name.0);
        crate::delegation::validate_private_directory_path(&directory)?;
        let socket = directory.join(TICKET_SOCKET);
        UnixStream::connect(&socket).with_context(|| format!("connect to {}", socket.display()))
    }

    /// Where this ticket's socket is in `base`.
    #[cfg(test)]
    pub(crate) fn socket_path(&self, base: BrokerBase) -> PathBuf {
        base.path().join(&self.name.0).join(TICKET_SOCKET)
    }

    #[cfg(test)]
    pub(crate) fn name(&self) -> &str {
        &self.name.0
    }

    #[cfg(test)]
    pub(crate) fn secret_mut(&mut self) -> &mut [u8; TICKET_SECRET_LEN] {
        &mut self.secret
    }
}

/// Where a broker's directory goes.
pub(crate) enum BrokerDirectory<'a> {
    /// A new private directory in the temporary directory, named with
    /// `prefix`, holding the socket `socket`. For a broker whose socket path
    /// this process hands on itself.
    Temporary { prefix: &'a str, socket: &'a str },
    /// A new directory in `base` that tickets name: `prefix`, this
    /// process's ID, which tells which process a socket belongs to, and a
    /// random suffix.
    Ticketed { prefix: &'a str, base: BrokerBase },
}

pub(crate) struct PrivateBrokerConfig<'a> {
    pub(crate) directory: BrokerDirectory<'a>,
    pub(crate) listener_thread: &'a str,
    pub(crate) client_thread: &'a str,
    /// Only for bounded handlers that never wait for another broker client.
    pub(crate) inline_on_thread_failure: bool,
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
    /// The name tickets give this broker's directory, for a ticketed one.
    ticket_name: Option<TicketName>,
}

impl PrivateBroker {
    pub(crate) fn start<F>(config: PrivateBrokerConfig<'_>, handler: F) -> Result<Self>
    where
        F: Fn(TrackedStream, Arc<ConnectionRegistry>) + Send + Sync + 'static,
    {
        Self::start_inner(config, handler, true)
    }

    /// The caller owns signal handling and child cleanup.
    pub(crate) fn start_managed<F>(config: PrivateBrokerConfig<'_>, handler: F) -> Result<Self>
    where
        F: Fn(TrackedStream, Arc<ConnectionRegistry>) + Send + Sync + 'static,
    {
        Self::start_inner(config, handler, false)
    }

    fn start_inner<F>(
        config: PrivateBrokerConfig<'_>,
        handler: F,
        signal_cleanup: bool,
    ) -> Result<Self>
    where
        F: Fn(TrackedStream, Arc<ConnectionRegistry>) + Send + Sync + 'static,
    {
        if config.max_connections == 0 {
            bail!("private broker needs at least one connection slot");
        }
        let (socket_dir, socket_path, ticket_name) = match config.directory {
            BrokerDirectory::Temporary { prefix, socket } => {
                let socket_dir =
                    private_temp_dir(prefix).context("create private broker directory")?;
                let socket_path = socket_dir.path().join(socket);
                (socket_dir, socket_path, None)
            }
            BrokerDirectory::Ticketed { prefix, base } => {
                let (base, parent) = base.prepare()?;
                let socket_dir = tempfile::Builder::new()
                    .prefix(&format!("{prefix}{}-", std::process::id()))
                    .permissions(std::fs::Permissions::from_mode(0o700))
                    .tempdir_in(&base)
                    .context("create private broker directory")?;
                let name = socket_dir
                    .path()
                    .file_name()
                    .and_then(OsStr::to_str)
                    .context("broker directory name")?;
                let ticket_name = TicketName::try_from(name.to_owned())?;
                // In the enrollment directory the address stays relative,
                // so a long parent cannot exceed sun_path.
                let socket_path = base.join(name).join(TICKET_SOCKET);
                if socket_path.as_os_str().len() > max_socket_path() {
                    let advice = parent
                        .variable()
                        .map(|variable| format!("; set {variable} to a shorter directory"))
                        .unwrap_or_default();
                    bail!(
                        "the socket path {} is longer than this system allows ({} bytes){advice}",
                        socket_path.display(),
                        max_socket_path()
                    );
                }
                (socket_dir, socket_path, Some(ticket_name))
            }
        };
        std::fs::set_permissions(socket_dir.path(), std::fs::Permissions::from_mode(0o700))?;
        let listener = UnixListener::bind(&socket_path)
            .with_context(|| format!("bind private broker at {}", socket_path.display()))?;
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        if signal_cleanup {
            register_signal_cleanup(socket_dir.path())?;
        }

        let shutdown = Arc::new(AtomicBool::new(false));
        let connections = Arc::new(ConnectionRegistry::new(config.io_timeout));
        let thread_shutdown = Arc::clone(&shutdown);
        let thread_connections = Arc::clone(&connections);
        let handler = Arc::new(handler);
        let max_connections = config.max_connections;
        let client_threads = ClientThreads {
            name: config.client_thread.to_owned(),
            inline_on_failure: config.inline_on_thread_failure,
            #[cfg(debug_assertions)]
            refuse: std::env::var("SYQ_TEST_REFUSE_BROKER_THREAD").as_deref()
                == Ok(config.client_thread),
        };
        let listener_thread = thread::Builder::new()
            .name(config.listener_thread.to_owned())
            .spawn(move || {
                accept_connections(
                    listener,
                    max_connections,
                    client_threads,
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
            ticket_name,
        })
    }

    pub(crate) fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// The ticket that joins this ticketed broker with `secret`.
    pub(crate) fn ticket(&self, secret: [u8; TICKET_SECRET_LEN]) -> Result<BrokerTicket> {
        Ok(BrokerTicket {
            name: self
                .ticket_name
                .clone()
                .context("this broker has no ticket")?,
            secret,
        })
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

struct ClientThreads {
    name: String,
    inline_on_failure: bool,
    #[cfg(debug_assertions)]
    refuse: bool,
}

impl ClientThreads {
    fn spawn<F>(&self, handler: F) -> io::Result<JoinHandle<()>>
    where
        F: FnOnce() + Send + 'static,
    {
        #[cfg(debug_assertions)]
        if self.refuse {
            return Err(io::Error::from_raw_os_error(libc::EAGAIN));
        }
        thread::Builder::new()
            .name(self.name.clone())
            .spawn(handler)
    }
}

fn accept_connections<F>(
    listener: UnixListener,
    max_connections: usize,
    client_threads: ClientThreads,
    shutdown: Arc<AtomicBool>,
    connections: Arc<ConnectionRegistry>,
    handler: Arc<F>,
) where
    F: Fn(TrackedStream, Arc<ConnectionRegistry>) + Send + Sync + 'static,
{
    let mut workers: Vec<JoinHandle<()>> = Vec::new();
    while !shutdown.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _)) => {
                // A handler may finish while accept waits. Reap at admission,
                // so its stale handle cannot consume a connection slot.
                reap_workers(&mut workers);
                // BSD-derived kernels (macOS) hand accepted sockets the
                // listener's non-blocking flag; Linux does not. Workers read
                // with timeouts and need a blocking socket either way.
                if stream.set_nonblocking(false).is_err() {
                    continue;
                }
                if workers.len() >= max_connections {
                    let _ = stream.shutdown(Shutdown::Both);
                    continue;
                }
                let Ok(stream) = connections.track(stream) else {
                    continue;
                };
                // Drop can shut down the registry between accept and track.
                // Never start an inline handler after that shutdown pass.
                if shutdown.load(Ordering::Acquire) {
                    break;
                }
                let worker_handler = Arc::clone(&handler);
                let worker_connections = Arc::clone(&connections);
                if client_threads.inline_on_failure {
                    // Keep the accepted socket when spawn drops its closure on
                    // failure. Cloning it here would need another descriptor at
                    // the very moment the process may be running out of them.
                    let pending = Arc::new(Mutex::new(Some(stream)));
                    let worker_pending = Arc::clone(&pending);
                    match client_threads.spawn(move || {
                        let stream = worker_pending.lock().unwrap().take().unwrap();
                        worker_handler(stream, worker_connections);
                    }) {
                        Ok(worker) => workers.push(worker),
                        Err(_) => {
                            let stream = pending.lock().unwrap().take().unwrap();
                            handler(stream, Arc::clone(&connections));
                        }
                    }
                } else if let Ok(worker) =
                    client_threads.spawn(move || worker_handler(stream, worker_connections))
                {
                    workers.push(worker);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                reap_workers(&mut workers);
                // Wake as soon as a client or the shutdown connection arrives;
                // a sleep here delayed every descriptor claim and every close.
                crate::sys::wait_readable(listener.as_raw_fd(), Duration::from_millis(5));
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

    pub(crate) fn shutdown_all(&self) {
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

    /// Streams tracked so far, closed ones included.
    #[cfg(test)]
    pub(crate) fn opened(&self) -> u64 {
        self.next_id.load(Ordering::Relaxed)
    }
}

pub(crate) struct TrackedStream {
    stream: UnixStream,
    id: u64,
    registry: Arc<ConnectionRegistry>,
}

impl TrackedStream {
    pub(crate) fn try_clone(&self) -> io::Result<UnixStream> {
        self.stream.try_clone()
    }

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
    use crate::process::CommandExt as _;

    const SIGNAL_CHILD: &str = "SYQ_TEST_SIGNAL_CLEANED_DIR";
    const SIGNAL_MARKER: &str = "SYQ_TEST_SIGNAL_CLEANED_DIR_MARKER";

    /// The child of `a_signal_cleaned_dir_goes_when_a_termination_signal_ends_the_process`:
    /// it makes a directory as a coordinator does for its entry key, names
    /// it in the marker, and raises the signal it was given.
    #[test]
    fn signal_cleaned_dir_subprocess() {
        let Ok(signal) = std::env::var(SIGNAL_CHILD) else {
            return;
        };
        let directory = SignalCleanedDir::new("syq-signal-cleanup-test-").unwrap();
        std::fs::write(directory.path().join("entry-key"), b"key").unwrap();
        let marker = std::env::var_os(SIGNAL_MARKER).unwrap();
        std::fs::write(&marker, directory.path().as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::raise(signal.parse().unwrap()) }, 0);
        std::thread::sleep(Duration::from_secs(30));
        panic!("the signal did not end the process");
    }

    /// A coordinator's private directory, which holds the entry key, goes
    /// when SIGTERM, SIGINT or a hang-up ends the process, which still ends
    /// by that signal.
    #[test]
    fn a_signal_cleaned_dir_goes_when_a_termination_signal_ends_the_process() {
        use std::os::unix::process::ExitStatusExt;
        for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
            let temporary = crate::test_support::tempdir().unwrap();
            let marker = temporary.path().join("directory");
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "private_broker::tests::signal_cleaned_dir_subprocess",
                    "--nocapture",
                ])
                .env(SIGNAL_CHILD, signal.to_string())
                .env(SIGNAL_MARKER, &marker)
                // A busy runner must not let the cleanup's cap end the
                // child before the cleanup has run.
                .env("SYQ_TEST_TERMINATION_CAP_MS", "10000")
                // A directory a failed run leaves stays in this fixture.
                .env("TMPDIR", temporary.path());
            let output = crate::process::capture_output_bounded(
                &mut command,
                std::time::Instant::now() + Duration::from_secs(20),
                &|| false,
                64 * 1024,
            )
            .unwrap();
            let context = format!(
                "signal {signal}: status={:?}, stderr={}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(output.status.signal(), Some(signal), "{context}");
            let directory = PathBuf::from(std::fs::read_to_string(&marker).unwrap());
            assert!(directory.is_absolute(), "{context}");
            assert!(
                !directory.exists(),
                "{context}: {} remains",
                directory.display()
            );
        }
    }

    #[test]
    fn private_temp_dir_is_created_owner_only() {
        let directory = private_temp_dir("syq-test-").unwrap();
        let mode = std::fs::metadata(directory.path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn broker_uses_private_modes_and_removes_its_directory() {
        let broker = PrivateBroker::start(
            PrivateBrokerConfig {
                directory: BrokerDirectory::Temporary {
                    prefix: "syq-private-broker-test-",
                    socket: "broker.sock",
                },
                listener_thread: "syq-private-test-listener",
                client_thread: "syq-private-test-client",
                inline_on_thread_failure: false,
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

    fn mode(path: &Path) -> u32 {
        std::fs::symlink_metadata(path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    }

    fn ticket_text(name: &str) -> String {
        format!("{name}:{}", "0123456789abcdef".repeat(4))
    }

    #[test]
    fn tickets_carry_only_a_short_checked_name() {
        let ticket = BrokerTicket::parse(&ticket_text("fd-123-AbC9z0")).unwrap();
        assert_eq!(ticket.name(), "fd-123-AbC9z0");
        assert_eq!(ticket.secret()[..3], [0x01, 0x23, 0x45]);
        assert_eq!(ticket.encode(), ticket_text("fd-123-AbC9z0"));
        BrokerTicket::parse(&ticket_text(&"a".repeat(MAX_TICKET_NAME))).unwrap();
        for name in [
            "",
            "a/b",
            "/tmp/syq-fd-x",
            "..",
            ".",
            "w-1/../x",
            "a.b",
            "a b",
            "a\0b",
            "\u{e9}",
            &"a".repeat(MAX_TICKET_NAME + 1),
        ] {
            assert!(BrokerTicket::parse(&ticket_text(name)).is_err(), "{name:?}");
        }
        let hex = "0123456789abcdef".repeat(4);
        for secret in [
            hex[1..].to_owned(),
            format!("{hex}0"),
            hex.to_uppercase(),
            hex.replacen('0', "g", 1),
            format!("+{}", &hex[1..]),
            String::new(),
        ] {
            assert!(
                BrokerTicket::parse(&format!("fd-1:{secret}")).is_err(),
                "{secret:?}"
            );
        }
        assert!(BrokerTicket::parse("fd-1").is_err());
        assert!(BrokerTicket::parse(&format!("a:b:{hex}")).is_err());
    }

    #[test]
    fn decoded_tickets_check_their_names() {
        // What a peer writes for a ticket.
        #[derive(Serialize)]
        struct Written<'a> {
            name: &'a str,
            secret: [u8; TICKET_SECRET_LEN],
        }
        let ticket = BrokerTicket::parse(&ticket_text("fd-1-abc")).unwrap();
        let bytes = postcard::to_allocvec(&ticket).unwrap();
        assert_eq!(
            postcard::to_allocvec(&Written {
                name: "fd-1-abc",
                secret: *ticket.secret()
            })
            .unwrap(),
            bytes
        );
        assert_eq!(
            postcard::from_bytes::<BrokerTicket>(&bytes).unwrap(),
            ticket
        );
        for name in ["../fd-1-abc", "/tmp/syq-fd-x/broker.sock", "..", ""] {
            let bytes = postcard::to_allocvec(&Written {
                name,
                secret: [0; TICKET_SECRET_LEN],
            })
            .unwrap();
            assert!(
                postcard::from_bytes::<BrokerTicket>(&bytes).is_err(),
                "{name:?}"
            );
        }
    }

    /// A socket listening in `base/name`, as a ticketed broker's does.
    fn listening(base: &Path, name: &str) -> UnixListener {
        let directory = base.join(name);
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        UnixListener::bind(directory.join(TICKET_SOCKET)).unwrap()
    }

    #[test]
    fn tickets_reach_only_private_directories_in_their_base() {
        let root = crate::test_support::short_tempdir().unwrap();
        let base = root.path().join("base");
        check_base(&base, true).unwrap();
        let ticket = |name: &str| BrokerTicket::new(name, [7; TICKET_SECRET_LEN]).unwrap();
        let _good = listening(&base, "fd-1-good");
        ticket("fd-1-good").connect_in(&base).unwrap();
        // A broker's directory may not be a link, even to a broker's, nor
        // one other users can enter.
        std::os::unix::fs::symlink(base.join("fd-1-good"), base.join("fd-1-link")).unwrap();
        assert!(ticket("fd-1-link").connect_in(&base).is_err());
        let _open = listening(&base, "fd-1-open");
        std::fs::set_permissions(
            base.join("fd-1-open"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert!(ticket("fd-1-open").connect_in(&base).is_err());
        assert!(ticket("fd-1-missing").connect_in(&base).is_err());
    }

    #[test]
    fn a_base_directory_must_be_this_accounts_and_owner_only() {
        let root = crate::test_support::short_tempdir().unwrap();
        let base = root.path().join("base");
        assert!(matches!(
            check_base(&base, false),
            Err(BaseError::Unavailable(_))
        ));
        check_base(&base, true).unwrap();
        assert_eq!(mode(&base), 0o700);
        check_base(&base, true).unwrap();
        check_base(&base, false).unwrap();
        // A link, as another user could plant in a shared /tmp, is refused
        // even when it leads to a private directory.
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&base, &link).unwrap();
        assert!(matches!(
            check_base(&link, true),
            Err(BaseError::NotPrivate(_))
        ));
        assert!(matches!(
            check_base(&link, false),
            Err(BaseError::NotPrivate(_))
        ));
        // An existing directory that others can enter is refused and left
        // as it is.
        let open = root.path().join("open");
        std::fs::create_dir(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            check_base(&open, true),
            Err(BaseError::NotPrivate(_))
        ));
        assert_eq!(mode(&open), 0o755);
        let file = root.path().join("file");
        std::fs::write(&file, b"").unwrap();
        assert!(matches!(
            check_base(&file, true),
            Err(BaseError::NotPrivate(_))
        ));
        // Another account's directory is refused: `/` belongs to root.
        let Err(BaseError::NotPrivate(error)) = check_base(Path::new("/"), false) else {
            panic!("another account's directory was accepted");
        };
        if unsafe { libc::geteuid() } != 0 {
            assert!(
                format!("{error:#}").contains("must belong to this account"),
                "{error:#}"
            );
        }
    }

    const ACCOUNT_CHILD: &str = "SYQ_TEST_ACCOUNT_BROKERS";

    fn account_broker() -> Result<PrivateBroker> {
        PrivateBroker::start(
            PrivateBrokerConfig {
                directory: BrokerDirectory::Ticketed {
                    prefix: "fd-",
                    base: BrokerBase::Account,
                },
                listener_thread: "syq-account-test-listener",
                client_thread: "syq-account-test-client",
                inline_on_thread_failure: false,
                max_connections: 1,
                io_timeout: Duration::from_secs(1),
            },
            |_, _| {},
        )
    }

    /// The child of `ticketed_brokers_live_in_the_accounts_own_directory`,
    /// with `TMPDIR`, and perhaps `XDG_RUNTIME_DIR`, set to fixtures. The
    /// account's directory is expected in `SYQ_TEST_ACCOUNT_PARENT`.
    #[test]
    fn account_brokers_subprocess() {
        let Ok(case) = std::env::var(ACCOUNT_CHILD) else {
            return;
        };
        let parent = std::env::var_os("SYQ_TEST_ACCOUNT_PARENT").unwrap();
        let account = account_directory(Path::new(&parent));
        if let Some(variable) = case.strip_prefix("long-") {
            let error = format!("{:#}", account_broker().unwrap_err());
            assert!(
                error.contains(&format!("set {variable} to a shorter directory")),
                "{error}"
            );
            return;
        }
        if let Some(shared) = case.strip_prefix("refused-") {
            let error = format!("{:#}", account_broker().unwrap_err());
            assert!(error.contains(&account.display().to_string()), "{error}");
            assert_eq!(
                error.contains("another user"),
                shared == "temporary",
                "{error}"
            );
            let ticket = BrokerTicket::new("fd-1-abc", [0; TICKET_SECRET_LEN]).unwrap();
            assert!(ticket.connect(BrokerBase::Account).is_err());
            return;
        }
        // A missing directory is no sign of another user.
        let missing = BrokerTicket::new("fd-1-abc", [0; TICKET_SECRET_LEN]).unwrap();
        let error = format!("{:#}", missing.connect(BrokerBase::Account).unwrap_err());
        assert!(!error.contains("another user"), "{error}");
        let broker = account_broker().unwrap();
        let ticket = broker.ticket([1; TICKET_SECRET_LEN]).unwrap();
        assert!(ticket
            .name()
            .starts_with(&format!("fd-{}-", std::process::id())));
        let directory = account.join(ticket.name());
        assert_eq!(broker.socket_path(), directory.join(TICKET_SOCKET));
        assert_eq!(
            ticket.socket_path(BrokerBase::Account),
            broker.socket_path()
        );
        assert_eq!(mode(&account), 0o700);
        assert_eq!(mode(&directory), 0o700);
        assert_eq!(mode(broker.socket_path()), 0o600);
        ticket.connect(BrokerBase::Account).unwrap();
        drop(broker);
        assert!(!directory.exists());
        assert!(account.exists());
    }

    /// Run `account_brokers_subprocess` for `case` with `temporary` as
    /// `TMPDIR` and `runtime`, if any, as `XDG_RUNTIME_DIR`, expecting the
    /// account's directory in `parent`.
    fn run_account_case(temporary: &Path, runtime: Option<&Path>, parent: &Path, case: &str) {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "private_broker::tests::account_brokers_subprocess",
                "--nocapture",
            ])
            .env(ACCOUNT_CHILD, case)
            .env("SYQ_TEST_ACCOUNT_PARENT", parent)
            .env("TMPDIR", temporary);
        match runtime {
            Some(runtime) => command.env("XDG_RUNTIME_DIR", runtime),
            None => command.env_remove("XDG_RUNTIME_DIR"),
        };
        let output = command.capture_output().unwrap();
        assert!(
            output.status.success(),
            "{case}: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn private_fixture(path: &Path, mode: u32) {
        std::fs::create_dir(path).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// Ordinary copies' brokers go in `syq-UID` in the temporary directory,
    /// which is made owner-only, and never in one another user planted.
    #[test]
    fn ticketed_brokers_live_in_the_accounts_own_directory() {
        let fresh = crate::test_support::short_tempdir().unwrap();
        run_account_case(fresh.path(), None, fresh.path(), "fresh");

        let linked = crate::test_support::short_tempdir().unwrap();
        let elsewhere = linked.path().join("elsewhere");
        private_fixture(&elsewhere, 0o700);
        std::os::unix::fs::symlink(&elsewhere, account_directory(linked.path())).unwrap();
        run_account_case(linked.path(), None, linked.path(), "refused-temporary");
        assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);

        let open = crate::test_support::short_tempdir().unwrap();
        let account = account_directory(open.path());
        private_fixture(&account, 0o777);
        run_account_case(open.path(), None, open.path(), "refused-temporary");
        assert_eq!(mode(&account), 0o777);
        assert_eq!(std::fs::read_dir(&account).unwrap().count(), 0);
    }

    /// The user's runtime directory holds the account's directory when only
    /// this account can write to it; otherwise the temporary directory does.
    #[test]
    fn ticketed_brokers_prefer_a_private_runtime_directory() {
        let root = crate::test_support::short_tempdir().unwrap();
        let temporary = root.path().join("t");
        private_fixture(&temporary, 0o700);
        for (name, runtime_mode, used) in [
            ("p", 0o700, true),
            ("r", 0o755, true),
            ("o", 0o777, false),
            ("w", 0o500, false),
        ] {
            let runtime = root.path().join(name);
            private_fixture(&runtime, runtime_mode);
            let parent = if used { &runtime } else { &temporary };
            run_account_case(&temporary, Some(&runtime), parent, "fresh");
            assert_eq!(
                std::fs::read_dir(&runtime).unwrap().count(),
                usize::from(used),
                "{runtime_mode:o}"
            );
        }
        // A runtime directory that is missing is passed over too.
        run_account_case(
            &temporary,
            Some(&root.path().join("missing")),
            &temporary,
            "fresh",
        );
        // In the runtime directory nobody else can have made the account's
        // directory, so a bad one gets no advice about other users.
        let runtime = root.path().join("bad");
        private_fixture(&runtime, 0o700);
        private_fixture(&account_directory(&runtime), 0o755);
        run_account_case(&temporary, Some(&runtime), &runtime, "refused-runtime");
    }

    /// A socket path too long for `sockaddr_un` names the variable that
    /// chose its directory.
    #[test]
    fn a_socket_path_too_long_names_the_variable_to_shorten() {
        let root = crate::test_support::short_tempdir().unwrap();
        let long = root.path().join("d".repeat(60)).join("e".repeat(60));
        std::fs::create_dir_all(&long).unwrap();
        std::fs::set_permissions(&long, std::fs::Permissions::from_mode(0o700)).unwrap();
        let temporary = root.path().join("t");
        private_fixture(&temporary, 0o700);
        run_account_case(&temporary, Some(&long), &long, "long-XDG_RUNTIME_DIR");
        run_account_case(&long, None, &long, "long-TMPDIR");
    }

    #[test]
    fn only_a_runtime_directory_nobody_else_can_write_is_used() {
        let root = crate::test_support::short_tempdir().unwrap();
        assert_eq!(account_parent(None), None);
        for (name, runtime_mode, used) in [
            ("p", 0o700, true),
            ("r", 0o755, true),
            ("g", 0o770, false),
            ("o", 0o707, false),
            ("w", 0o500, false),
            ("x", 0o600, false),
        ] {
            let runtime = root.path().join(name);
            private_fixture(&runtime, runtime_mode);
            assert_eq!(
                account_parent(Some(runtime.clone())).is_some(),
                used,
                "{runtime_mode:o}"
            );
        }
        let file = root.path().join("file");
        std::fs::write(&file, b"").unwrap();
        assert_eq!(account_parent(Some(file)), None);
        assert_eq!(account_parent(Some(root.path().join("missing"))), None);
        if unsafe { libc::geteuid() } != 0 {
            assert_eq!(account_parent(Some(PathBuf::from("/"))), None);
        }
    }
}

//! Ready control sessions for persistent SSH endpoints.
//!
//! With persistence on, every command still opened an exec channel through
//! the OpenSSH master, launched the remote helper, and exchanged the hello
//! before its first useful request: three network turns. A session pool is a
//! small detached process, one per endpoint in a persistence scope, that
//! keeps one such session opened ahead of time and hands its pipes to the
//! next command over a Unix socket beside the control socket.
//!
//! Two invariants keep it simple and safe. The pool never reads from a
//! session: it writes the hello and checks the child for exit only, so a
//! taken session is byte-for-byte what a fresh one would be, and the command
//! completes the hello itself. And the pool never authenticates: a spare is
//! attached to a live master with every authentication method disabled, so a
//! dead master leaves the pool empty until the next foreground command shows
//! the ordinary OpenSSH prompt or warning.

use crate::descriptor_broker::{receive_message, send_message};
use crate::proto::{ConnectionRole, FrameWriter};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const SOCKET_SUFFIX: &[u8] = b".pool";
const LOCK_SUFFIX: &[u8] = b".pool.lock";
/// Spares kept ready per endpoint. One covers a person typing; a burst
/// takes the in-flight spare, whose hello it then finishes itself.
const DEPTH: usize = 1;
/// Exit after this long without a handoff. Spares are live channels, so
/// the master's own ControlPersist window begins only after this.
const IDLE: Duration = Duration::from_secs(300);
/// A failed spare open (usually a dead master) is not retried sooner.
const RETRY_AFTER_FAILURE: Duration = Duration::from_secs(5);
const HOUSEKEEPING: Duration = Duration::from_secs(1);
const CLIENT_IO_TIMEOUT: Duration = Duration::from_secs(2);
const STOP_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_MESSAGE: usize = 8192;

/// What the pool needs to open a session for one endpoint. The program is
/// the exact remote command a command would run itself, so a command that
/// would run something else (another `--syq-path`, say) gets no session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PoolEndpoint {
    pub user: Option<String>,
    pub host: String,
    pub port: Option<u16>,
    pub program: String,
}

/// A session handed over by the pool: the ssh client's three pipes. The
/// hello request has been written; its reply has not been read.
pub(crate) struct PooledSession {
    pub stdin: File,
    pub stdout: File,
    pub stderr: File,
}

#[derive(Serialize, Deserialize)]
struct ClientRequest {
    identity: String,
    #[serde(default)]
    program: Option<String>,
    #[serde(default)]
    exit: bool,
}

#[derive(Serialize, Deserialize)]
struct PoolReply {
    status: String,
    identity: String,
}

pub(crate) fn socket_path(control: &Path) -> PathBuf {
    suffixed(control, SOCKET_SUFFIX)
}

pub(crate) fn lock_path(control: &Path) -> PathBuf {
    suffixed(control, LOCK_SUFFIX)
}

fn suffixed(path: &Path, suffix: &[u8]) -> PathBuf {
    let mut bytes = path.as_os_str().as_bytes().to_vec();
    bytes.extend_from_slice(suffix);
    PathBuf::from(OsString::from_vec(bytes))
}

/// Whether a pool holds this endpoint's lock. Liveness is the lock, not the
/// socket file: a stale socket cannot claim to be alive, and two pools
/// cannot race each other's sockets. A `flock` lock is held by every copy of
/// its descriptor, so a process that forked while a pool held it keeps it
/// until it execs; that window is microseconds, and every caller tolerates
/// a briefly stale answer: `ensure` is best effort and `stop` waits.
pub(crate) fn is_running(control: &Path) -> bool {
    matches!(try_lock(control, false), Ok(None))
}

/// Take the lock, or report who holds it. `Ok(None)` means another pool has
/// it; `Err` means the lock file could not be opened.
fn try_lock(control: &Path, create: bool) -> Result<Option<File>> {
    let path = lock_path(control);
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(create)
        .create(create)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = match options.open(&path) {
        Ok(file) => file,
        Err(error) if !create && error.kind() == io::ErrorKind::NotFound => {
            bail!("no session pool lock");
        }
        Err(error) => {
            return Err(error).with_context(|| format!("open {}", path.display()));
        }
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != unsafe { libc::geteuid() } {
        bail!(
            "session pool lock {} must be a regular file owned by the current user",
            path.display()
        );
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(Some(file));
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::WouldBlock {
        return Ok(None);
    }
    Err(error).with_context(|| format!("lock {}", path.display()))
}

/// Start a pool for this endpoint unless one is running. Best effort and
/// off the critical path: the caller has just opened its own connection.
pub(crate) fn ensure(control: &Path, endpoint: &PoolEndpoint) {
    if is_running(control) {
        return;
    }
    let Ok(program) = std::env::current_exe() else {
        return;
    };
    let mut command = Command::new(program);
    command
        .arg("--session-pool")
        .arg(control)
        .arg(endpoint.user.as_deref().unwrap_or(""))
        .arg(&endpoint.host)
        .arg(
            endpoint
                .port
                .map(|port| port.to_string())
                .unwrap_or_default(),
        )
        .arg(&endpoint.program)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: setsid takes no arguments, touches no memory, and is safe to
    // call between fork and exec. It detaches the pool from the terminal so
    // a Ctrl-C or hangup meant for the command never reaches it.
    unsafe {
        command.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    if let Ok(mut child) = command.spawn() {
        // The pool outlives this process; reap it only if it exits first.
        std::thread::spawn(move || {
            let _ = child.wait();
        });
    }
}

/// Take a ready session for `program`, or nothing. Every failure is a
/// reason to connect directly, never an error for the command.
pub(crate) fn take(control: &Path, program: &str) -> Option<PooledSession> {
    let mut stream = UnixStream::connect(socket_path(control)).ok()?;
    stream.set_read_timeout(Some(CLIENT_IO_TIMEOUT)).ok()?;
    stream.set_write_timeout(Some(CLIENT_IO_TIMEOUT)).ok()?;
    let request = ClientRequest {
        identity: crate::identity::build().to_string(),
        program: Some(program.to_string()),
        exit: false,
    };
    let mut line = serde_json::to_vec(&request).ok()?;
    line.push(b'\n');
    stream.write_all(&line).ok()?;
    let (payload, mut descriptors) = receive_message(stream.as_raw_fd(), MAX_MESSAGE).ok()?;
    let reply: PoolReply = serde_json::from_slice(&payload).ok()?;
    if reply.status != "session" || reply.identity != crate::identity::build() {
        return None;
    }
    if descriptors.len() != 3
        || descriptors
            .iter()
            .any(|descriptor| !descriptor.metadata().is_ok_and(|m| m.file_type().is_fifo()))
    {
        return None;
    }
    let stderr = descriptors.pop()?;
    let stdout = descriptors.pop()?;
    let stdin = descriptors.pop()?;
    Some(PooledSession {
        stdin,
        stdout,
        stderr,
    })
}

/// Ask a running pool to exit, wait for it, and remove its files. A pool
/// that is not running leaves only stale files, which are removed too.
pub(crate) fn stop(control: &Path) -> Result<()> {
    let deadline = Instant::now() + STOP_TIMEOUT;
    let mut requested = false;
    while is_running(control) {
        if Instant::now() >= deadline {
            bail!(
                "session pool for {} did not exit",
                control.file_name().unwrap_or_default().to_string_lossy()
            );
        }
        // Startup holds the lock before binding the socket. Retry delivery
        // within the stop deadline instead of waiting on an unsent request.
        if !requested {
            if let Ok(mut stream) = UnixStream::connect(socket_path(control)) {
                let _ = stream.set_write_timeout(Some(CLIENT_IO_TIMEOUT));
                let request = ClientRequest {
                    identity: crate::identity::build().to_string(),
                    program: None,
                    exit: true,
                };
                let mut line = serde_json::to_vec(&request)?;
                line.push(b'\n');
                requested = stream.write_all(&line).is_ok();
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    for path in [socket_path(control), lock_path(control)] {
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_dir() => {
                bail!("refusing to remove unexpected directory {}", path.display())
            }
            Ok(_) => fs::remove_file(&path)
                .with_context(|| format!("remove session pool file {}", path.display()))?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).with_context(|| format!("inspect {}", path.display())),
        }
    }
    Ok(())
}

/// The names beside a control socket that belong to its pool, for the scope
/// inventory: `<key>.pool` and `<key>.pool.lock`.
pub(crate) fn owned_name(name: &[u8]) -> Option<&[u8]> {
    name.strip_suffix(LOCK_SUFFIX)
        .or_else(|| name.strip_suffix(SOCKET_SUFFIX))
}

struct Spare {
    child: Child,
    stdin: File,
    stdout: File,
    stderr: File,
}

struct Pool {
    endpoint: PoolEndpoint,
    control: PathBuf,
    socket: PathBuf,
    bound_ino: u64,
    listener: UnixListener,
    _lock: File,
    spares: Vec<Spare>,
    handed: Vec<Child>,
    last_handoff: Instant,
    last_failure: Option<Instant>,
    idle: Duration,
}

enum Verdict {
    Continue,
    Exit,
}

/// `syq --session-pool CONTROL USER HOST PORT PROGRAM`: the pool process.
pub(crate) fn run(argv: &[OsString]) -> Result<()> {
    let [control, user, host, port, program] = argv else {
        bail!("session pool takes exactly control-socket, user, host, port, and program arguments");
    };
    let control = PathBuf::from(control);
    let text = |value: &OsString| {
        value
            .to_str()
            .map(str::to_owned)
            .context("session pool arguments must be UTF-8")
    };
    let user = text(user)?;
    let port = text(port)?;
    let endpoint = PoolEndpoint {
        user: (!user.is_empty()).then_some(user),
        host: text(host)?,
        port: if port.is_empty() {
            None
        } else {
            Some(port.parse().context("session pool port")?)
        },
        program: text(program)?,
    };
    let scope = control
        .parent()
        .context("control socket path has no parent")?;
    crate::persistence::validate_scope(scope)?;
    let Some(lock) = try_lock(&control, true)? else {
        // Another pool serves this endpoint.
        return Ok(());
    };
    let socket = socket_path(&control);
    match fs::symlink_metadata(&socket) {
        Ok(metadata) if metadata.file_type().is_socket() => fs::remove_file(&socket)
            .with_context(|| format!("remove stale session pool socket {}", socket.display()))?,
        Ok(_) => bail!("unexpected entry at {}", socket.display()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).with_context(|| format!("inspect {}", socket.display())),
    }
    let listener =
        UnixListener::bind(&socket).with_context(|| format!("bind {}", socket.display()))?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    let bound_ino = fs::symlink_metadata(&socket)?.ino();
    let mut idle = IDLE;
    #[cfg(debug_assertions)]
    if let Some(seconds) = std::env::var_os("SYQ_TEST_POOL_IDLE_SECS")
        .and_then(|value| value.to_str()?.parse::<u64>().ok())
    {
        idle = Duration::from_secs(seconds);
    }
    let mut pool = Pool {
        endpoint,
        control,
        socket,
        bound_ino,
        listener,
        _lock: lock,
        spares: Vec::new(),
        handed: Vec::new(),
        last_handoff: Instant::now(),
        last_failure: None,
        idle,
    };
    let result = pool.serve();
    pool.shutdown();
    result
}

impl Pool {
    fn serve(&mut self) -> Result<()> {
        loop {
            if let Verdict::Exit = self.housekeeping() {
                return Ok(());
            }
            // Check child exits during housekeeping without consuming the
            // hello reply. Darwin does not monitor poll entries with events=0.
            let mut listener = libc::pollfd {
                fd: self.listener.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let ready =
                unsafe { libc::poll(&mut listener, 1, HOUSEKEEPING.as_millis() as libc::c_int) };
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error).context("poll session pool descriptors");
            }
            if listener.revents & libc::POLLIN != 0 {
                loop {
                    match self.listener.accept() {
                        Ok((stream, _)) => {
                            if let Verdict::Exit = self.handle_client(stream) {
                                return Ok(());
                            }
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        Err(error) => return Err(error).context("accept session pool client"),
                    }
                }
            }
        }
    }

    fn housekeeping(&mut self) -> Verdict {
        for index in (0..self.spares.len()).rev() {
            if matches!(self.spares[index].child.try_wait(), Ok(Some(_))) {
                self.spares.remove(index);
                // An SSH process can start and then refuse the session.
                self.last_failure = Some(Instant::now());
            }
        }
        self.handed
            .retain_mut(|child| !matches!(child.try_wait(), Ok(Some(_))));
        if self.last_handoff.elapsed() >= self.idle {
            return Verdict::Exit;
        }
        // The scope was closed, or someone replaced the socket: nothing that
        // connects there is ours to serve.
        match fs::symlink_metadata(&self.socket) {
            Ok(metadata) if metadata.ino() == self.bound_ino => {}
            _ => return Verdict::Exit,
        }
        if self.spares.len() < DEPTH
            && self
                .last_failure
                .is_none_or(|failure| failure.elapsed() >= RETRY_AFTER_FAILURE)
        {
            match self.open_spare() {
                Ok(spare) => self.spares.push(spare),
                Err(_) => self.last_failure = Some(Instant::now()),
            }
        }
        Verdict::Continue
    }

    /// The ssh command every spare shares: attach to the live master and
    /// nothing else. With a missing socket OpenSSH would otherwise fall back
    /// to an ordinary connection, and a configured ProxyCommand or ProxyJump
    /// could authenticate on its own even with target authentication off, so
    /// the proxy is pinned to a command that fails; and an idle session must
    /// not carry the user's agent, display, or forwardings to the remote.
    fn ssh(&self) -> Command {
        let mut command = Command::new("ssh");
        command
            .arg("-o")
            .arg("ControlMaster=no")
            .arg("-S")
            .arg(crate::persistence::openssh_control_path(&self.control))
            .args([
                "-o",
                "ProxyJump=none",
                "-o",
                "ProxyCommand=false",
                "-o",
                "ForwardAgent=no",
                "-o",
                "ForwardX11=no",
                "-o",
                "ClearAllForwardings=yes",
                "-o",
                "PermitLocalCommand=no",
                "-o",
                "GSSAPIDelegateCredentials=no",
                "-o",
                "RequestTTY=no",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=3",
                "-o",
                "ConnectionAttempts=1",
                "-o",
                "PubkeyAuthentication=no",
                "-o",
                "PasswordAuthentication=no",
                "-o",
                "KbdInteractiveAuthentication=no",
                "-o",
                "GSSAPIAuthentication=no",
                "-o",
                "HostbasedAuthentication=no",
                "-o",
                crate::conn::CIPHERS,
            ]);
        if let Some(user) = &self.endpoint.user {
            command.args(["-l", user]);
        }
        if let Some(port) = self.endpoint.port {
            command.args(["-p", &port.to_string()]);
        }
        command
    }

    fn open_spare(&self) -> Result<Spare> {
        let live = self
            .ssh()
            .args(["-O", "check", "--"])
            .arg(&self.endpoint.host)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .context("check the SSH master")?;
        if !live.success() {
            bail!("no live SSH master");
        }
        let mut child = self
            .ssh()
            .arg("--")
            .arg(&self.endpoint.host)
            .arg(&self.endpoint.program)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("start a spare session")?;
        match greet_spare(&mut child) {
            Ok((stdin, stdout, stderr)) => Ok(Spare {
                child,
                stdin,
                stdout,
                stderr,
            }),
            Err(error) => {
                // A refused or lost session is not left as a zombie.
                let _ = child.kill();
                let _ = child.wait();
                Err(error)
            }
        }
    }

    fn handle_client(&mut self, mut stream: UnixStream) -> Verdict {
        let _ = stream.set_write_timeout(Some(CLIENT_IO_TIMEOUT));
        if peer_uid(&stream).ok() != Some(unsafe { libc::geteuid() }) {
            return Verdict::Continue;
        }
        let Some(request) = read_request(&mut stream) else {
            return Verdict::Continue;
        };
        if request.exit {
            self.reply(&stream, "exiting", &[]);
            return Verdict::Exit;
        }
        if request.identity != crate::identity::build() {
            // A newer syq is in use; its next command starts its own pool.
            self.reply(&stream, "identity", &[]);
            return Verdict::Exit;
        }
        let Some(program) = request.program else {
            self.reply(&stream, "none", &[]);
            return Verdict::Continue;
        };
        if program != self.endpoint.program {
            // Serve what commands actually run; the spares opened for the
            // old command line are useless to them.
            self.endpoint.program = program;
            for mut spare in self.spares.drain(..) {
                let _ = spare.child.kill();
                let _ = spare.child.wait();
            }
            self.reply(&stream, "none", &[]);
            return Verdict::Continue;
        }
        let Some(spare) = self.spares.pop() else {
            self.reply(&stream, "none", &[]);
            return Verdict::Continue;
        };
        let Spare {
            child,
            stdin,
            stdout,
            stderr,
        } = spare;
        let sent = self.reply(
            &stream,
            "session",
            &[stdin.as_raw_fd(), stdout.as_raw_fd(), stderr.as_raw_fd()],
        );
        // Our copies close here, so the taker's end is the only one left.
        drop((stdin, stdout, stderr));
        if sent {
            self.last_handoff = Instant::now();
            self.handed.push(child);
        } else {
            let mut child = child;
            let _ = child.kill();
            let _ = child.wait();
        }
        Verdict::Continue
    }

    fn reply(&self, stream: &UnixStream, status: &str, descriptors: &[i32]) -> bool {
        let reply = PoolReply {
            status: status.to_string(),
            identity: crate::identity::build().to_string(),
        };
        let Ok(payload) = serde_json::to_vec(&reply) else {
            return false;
        };
        send_message(stream.as_raw_fd(), &payload, descriptors).is_ok()
    }

    fn shutdown(&mut self) {
        for mut spare in self.spares.drain(..) {
            let _ = spare.child.kill();
            let _ = spare.child.wait();
        }
        if let Ok(metadata) = fs::symlink_metadata(&self.socket) {
            if metadata.ino() == self.bound_ino {
                let _ = fs::remove_file(&self.socket);
            }
        }
        let _ = fs::remove_file(lock_path(&self.control));
    }
}

/// Take a spare's pipes and send the hello on it. The taker reads the reply;
/// a default command's flags are used so the receiver's writer matches them.
fn greet_spare(child: &mut Child) -> Result<(File, File, File)> {
    // SAFETY: each descriptor comes from a piped child stdio handle this
    // process owns and is wrapped exactly once.
    let stdin = child
        .stdin
        .take()
        .map(|pipe| unsafe { File::from_raw_fd(pipe.into_raw_fd()) })
        .context("spare session stdin was not piped")?;
    let stdout = child
        .stdout
        .take()
        .map(|pipe| unsafe { File::from_raw_fd(pipe.into_raw_fd()) })
        .context("spare session stdout was not piped")?;
    let stderr = child
        .stderr
        .take()
        .map(|pipe| unsafe { File::from_raw_fd(pipe.into_raw_fd()) })
        .context("spare session stderr was not piped")?;
    let mut writer = FrameWriter::new(&stdin, true);
    writer.write_msg(&crate::conn::hello_request(
        true,
        false,
        Vec::new(),
        ConnectionRole::Control,
    ))?;
    drop(writer);
    Ok((stdin, stdout, stderr))
}

/// One request line, read a byte at a time so nothing beyond it is consumed.
fn read_request(stream: &mut UnixStream) -> Option<ClientRequest> {
    // BSD accepts inherit the listener's nonblocking mode. The request can
    // arrive after accept, so use bounded blocking I/O on the client stream.
    stream.set_nonblocking(false).ok()?;
    stream.set_read_timeout(Some(CLIENT_IO_TIMEOUT)).ok()?;
    let mut line = Vec::new();
    let mut byte = [0u8];
    loop {
        match stream.read(&mut byte) {
            Ok(1) if byte[0] == b'\n' => break,
            Ok(1) => {
                line.push(byte[0]);
                if line.len() > MAX_MESSAGE {
                    return None;
                }
            }
            Ok(_) => return None,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
    }
    serde_json::from_slice(&line).ok()
}

#[cfg(target_os = "linux")]
fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: the buffer and its length describe one ucred that the kernel
    // fills for a connected Unix stream socket.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(credentials.uid)
}

#[cfg(not(target_os = "linux"))]
fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: getpeereid writes the peer's ids through the two pointers.
    let result = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(uid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_files_sit_beside_the_control_socket_and_are_recognized() {
        let control = Path::new("/run/user/1/scope/cm-00112233aabbccdd");
        assert_eq!(
            socket_path(control),
            Path::new("/run/user/1/scope/cm-00112233aabbccdd.pool")
        );
        assert_eq!(
            lock_path(control),
            Path::new("/run/user/1/scope/cm-00112233aabbccdd.pool.lock")
        );
        assert_eq!(
            owned_name(b"cm-00112233aabbccdd.pool"),
            Some(&b"cm-00112233aabbccdd"[..])
        );
        assert_eq!(
            owned_name(b"cm-00112233aabbccdd.pool.lock"),
            Some(&b"cm-00112233aabbccdd"[..])
        );
        assert_eq!(owned_name(b"cm-00112233aabbccdd"), None);
        assert_eq!(owned_name(b"cm-00112233aabbccdd.json"), None);
    }

    #[test]
    fn a_missing_lock_means_no_pool_and_a_held_lock_means_one() {
        let temporary = crate::test_support::tempdir().unwrap();
        let control = temporary.path().join("cm-00112233aabbccdd");
        assert!(!is_running(&control));
        let held = try_lock(&control, true).unwrap().unwrap();
        assert!(is_running(&control));
        assert!(try_lock(&control, true).unwrap().is_none());
        drop(held);
        // Another test in this process may be between fork and exec with a
        // copy of the descriptor, which keeps the lock for a moment.
        let deadline = Instant::now() + Duration::from_secs(5);
        while is_running(&control) {
            assert!(
                Instant::now() < deadline,
                "released lock still reported held"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        stop(&control).unwrap();
        assert!(!lock_path(&control).exists());
    }

    #[test]
    fn stop_waits_for_a_starting_pool_to_bind_its_socket() {
        let temporary = crate::test_support::tempdir().unwrap();
        let control = temporary.path().join("cm-00112233aabbccdd");
        let held = try_lock(&control, true).unwrap().unwrap();
        let socket = socket_path(&control);
        let starter = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            let listener = UnixListener::bind(socket).unwrap();
            listener.set_nonblocking(true).unwrap();
            let deadline = Instant::now() + STOP_TIMEOUT;
            loop {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        assert!(read_request(&mut stream).unwrap().exit);
                        break;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "no stop request arrived");
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("accept stop request: {error}"),
                }
            }
            drop(held);
        });
        let stopped = stop(&control);
        starter.join().unwrap();
        stopped.unwrap();
        assert!(!socket_path(&control).exists());
        assert!(!lock_path(&control).exists());
    }

    #[test]
    fn a_nonblocking_client_waits_for_the_rest_of_its_request() {
        let (mut server, mut client) = UnixStream::pair().unwrap();
        server.set_nonblocking(true).unwrap();
        client.write_all(b"{\"identity\":\"test\",").unwrap();
        let sender = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            client.write_all(b"\"exit\":true}\n").unwrap();
        });
        let request = read_request(&mut server).expect("complete delayed request");
        assert!(request.exit);
        assert_eq!(request.identity, "test");
        sender.join().unwrap();
    }

    #[test]
    fn the_client_gets_nothing_from_an_absent_pool() {
        let temporary = crate::test_support::tempdir().unwrap();
        let control = temporary.path().join("cm-00112233aabbccdd");
        assert!(take(&control, "syq --server").is_none());
    }
}

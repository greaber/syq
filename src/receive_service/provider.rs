//! Local approval/agent environment for ordinary SSH provider logins. An SSH
//! helper attaches here; it never creates this service from its login environment.
use super::*;
use crate::destination::ssh_auth::{self, AuthorizationContext, AuthorizationOrigin};
use crate::private_broker::{ConnectionRegistry, TrackedStream};
use crate::receive_approval::provider_accounts::ProviderIdentity;
use crate::receive_approval::Queue;
use std::collections::HashMap;
use std::sync::atomic::AtomicU64;

pub(crate) const SOCKET_FILE: &str = "provider-v1.sock";
pub(crate) const LOCK_FILE: &str = "provider-v1.lock";
const INTERNAL: &str = "--receive-provider-service";
const PROTOCOL: u16 = 1;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);
const IO_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_CLIENTS: usize = 256;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Hello {
    version: u16,
    build: String,
    control: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HelloReply {
    version: u16,
    build: String,
}
#[derive(Serialize, Deserialize)]
enum Control {
    Status,
    Refresh,
    Decide(Decision),
    Stop,
}
#[derive(Serialize, Deserialize)]
enum Access {
    Attach {
        profile: Option<String>,
    },
    Request {
        session: String,
        operation: Box<SessionRequest>,
    },
}
#[derive(Serialize, Deserialize)]
pub(crate) enum SessionRequest {
    ResolveLocal(ssh_auth::LocalTarget),
    LocalAccount(ssh_auth::LocalRequest),
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Ticket {
    pub(crate) session: String,
    pub(crate) profile: String,
    pub(crate) identity: ProviderIdentity,
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct ProfileSnapshot {
    pub(crate) settings: Settings,
    pub(crate) pending: Vec<crate::receive_approval::Summary>,
    pub(crate) sessions: usize,
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Snapshot {
    pub(crate) build: String,
    pub(crate) pid: u32,
    pub(crate) profiles: Vec<ProfileSnapshot>,
    pub(crate) decision_error: Option<String>,
}

/// Keep this object alive while any operation uses its session ticket. The
/// ticket has no authority after this attachment closes, even in the same UID.
pub(crate) struct Attachment {
    lifetime: UnixStream,
    ticket: Ticket,
    socket_path: PathBuf,
}
impl Attachment {
    pub(crate) fn ticket(&self) -> &Ticket {
        &self.ticket
    }
    pub(crate) fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}
impl AsRawFd for Attachment {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.lifetime.as_raw_fd()
    }
}
impl Drop for Attachment {
    fn drop(&mut self) {
        let _ = self.lifetime.shutdown(std::net::Shutdown::Both);
    }
}

/// The remote helper attaches only to the provider's default domain. A
/// requester's local --pscope is never interpreted as a path on this machine.
pub(crate) fn attach(profile: Option<&str>) -> Result<Attachment> {
    attach_in(&Domain::Global, profile)
}
fn attach_in(domain: &Domain, profile: Option<&str>) -> Result<Attachment> {
    if let Some(profile) = profile {
        crate::destination::validate_name(profile)?;
    }
    let mut stream = connect(domain, false)?;
    crate::destination::write_message(
        &mut stream,
        &Access::Attach {
            profile: profile.map(str::to_owned),
        },
    )?;
    let reply: std::result::Result<Ticket, String> = crate::destination::read_message(&mut stream)?;
    let ticket = reply.map_err(anyhow::Error::msg)?;
    validate_ticket(&ticket.session)?;
    stream.set_read_timeout(None)?;
    Ok(Attachment {
        lifetime: stream,
        ticket,
        socket_path: domain.runtime_path().join(SOCKET_FILE),
    })
}

/// Use the same exact-build protocol over an already connected SSH Unix forward.
pub(crate) fn open_forwarded(
    stream: UnixStream,
    session: &str,
    operation: SessionRequest,
) -> Result<UnixStream> {
    let stream = handshake(stream, false).context(
        "could not open the SSH authorization provider service; check that receiving is running there and sshd permits local forwarding with AllowTcpForwarding and AllowStreamLocalForwarding set to local or yes",
    )?;
    send_operation(stream, session, operation)
}
fn send_operation(
    mut stream: UnixStream,
    session: &str,
    operation: SessionRequest,
) -> Result<UnixStream> {
    validate_ticket(session)?;
    crate::destination::write_message(
        &mut stream,
        &Access::Request {
            session: session.into(),
            operation: Box::new(operation),
        },
    )?;
    stream.set_read_timeout(Some(
        crate::receive_approval::TIMEOUT + Duration::from_secs(30),
    ))?;
    Ok(stream)
}
fn validate_ticket(ticket: &str) -> Result<()> {
    anyhow::ensure!(
        ticket.len() == 64 && ticket.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid provider authorization session"
    );
    Ok(())
}
fn connect(domain: &Domain, control: bool) -> Result<UnixStream> {
    let path = domain.runtime_path().join(SOCKET_FILE);
    let metadata = fs::symlink_metadata(&path).with_context(|| format!(
        "SSH authorization provider is unavailable at {}; run syq persist receive on locally on the provider", path.display()))?;
    anyhow::ensure!(
        metadata.file_type().is_socket()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0,
        "provider control socket must be owned and private"
    );
    handshake(UnixStream::connect(&path)?, control)
}
fn handshake(mut stream: UnixStream, control: bool) -> Result<UnixStream> {
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;
    crate::destination::write_message(
        &mut stream,
        &Hello {
            version: PROTOCOL,
            build: crate::identity::build().into(),
            control,
        },
    )?;
    let reply: HelloReply = crate::destination::read_message(&mut stream)?;
    anyhow::ensure!(
        reply.version == PROTOCOL,
        "unsupported local provider protocol; restart receiving with its original syq build"
    );
    anyhow::ensure!(
        control || reply.build == crate::identity::build(),
        "SSH authorization provider service uses build {}, but this requester/helper uses {}; install the same syq build on the requester and provider, then run syq persist receive on locally on the provider to restart its service",
        reply.build,
        crate::identity::build()
    );
    Ok(stream)
}
fn query(domain: &Domain, operation: Control) -> Result<Snapshot> {
    let mut stream = connect(domain, true)?;
    crate::destination::write_message(&mut stream, &operation)?;
    crate::destination::read_framed(&mut stream, MAX_STATUS, "provider status")
}

pub(crate) fn snapshot(domain: &Domain) -> Result<Option<Snapshot>> {
    match query(domain, Control::Status) {
        Ok(state) => Ok(Some(state)),
        Err(error)
            if error.chain().any(|cause| {
                cause.downcast_ref::<std::io::Error>().is_some_and(|error| {
                    matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                    )
                })
            }) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}
pub(super) fn refresh(domain: &Domain) -> Result<()> {
    if is_running(domain)? {
        query(domain, Control::Refresh)?;
    }
    Ok(())
}
pub(super) fn decide(domain: &Domain, decision: Decision) -> Result<()> {
    let state = query(domain, Control::Decide(decision))?;
    if let Some(error) = state.decision_error {
        bail!("{error}");
    }
    Ok(())
}

struct Profile {
    settings: Settings,
    approvals: Arc<Queue>,
}
struct Session {
    profile: Arc<Profile>,
    identity: ProviderIdentity,
    closed: AtomicBool,
    admission: Mutex<()>,
    streams: Arc<ConnectionRegistry>,
    request_lock: Mutex<()>,
    active_count: AtomicU64,
    grants: Mutex<HashMap<String, u64>>,
}
impl Session {
    fn close(&self) {
        let _admission = self.admission.lock().unwrap();
        self.closed.store(true, Ordering::Release);
        self.grants.lock().unwrap().clear();
        self.streams.shutdown_all();
    }
    fn track(&self, stream: UnixStream) -> Result<TrackedStream> {
        let _admission = self.admission.lock().unwrap();
        anyhow::ensure!(
            !self.closed.load(Ordering::Acquire),
            "provider authorization session ended"
        );
        Ok(self.streams.track(stream)?)
    }
}
struct Inner {
    preferences: Preferences,
    profiles: HashMap<String, Arc<Profile>>,
    sessions: HashMap<String, Arc<Session>>,
}
struct Service {
    domain: Domain,
    domain_identity: (u64, u64),
    stop: Arc<AtomicBool>,
    streams: Arc<ConnectionRegistry>,
    inner: Mutex<Inner>,
}
impl Service {
    fn new(domain: Domain) -> Result<Self> {
        let preferences = preferences(&domain)?;
        let service = Self {
            domain_identity: domain.identity()?,
            domain,
            stop: Arc::new(AtomicBool::new(false)),
            streams: Arc::new(ConnectionRegistry::new(IO_TIMEOUT)),
            inner: Mutex::new(Inner {
                preferences,
                profiles: HashMap::new(),
                sessions: HashMap::new(),
            }),
        };
        service.refresh()?;
        Ok(service)
    }
    fn refresh(&self) -> Result<()> {
        let preferences = preferences(&self.domain)?;
        let mut inner = self.inner.lock().unwrap();
        inner.sessions.retain(|_, session| {
            let keep = preferences
                .profiles
                .iter()
                .any(|profile| profile.enabled && profile.same_access(&session.profile.settings));
            if !keep {
                session.close();
            }
            keep
        });
        inner.profiles.retain(|_, profile| {
            preferences
                .profiles
                .iter()
                .any(|settings| settings.enabled && settings.same_access(&profile.settings))
        });
        for settings in preferences
            .profiles
            .iter()
            .filter(|settings| settings.enabled)
        {
            let profile = inner
                .profiles
                .entry(settings.name.clone())
                .or_insert_with(|| {
                    Arc::new(Profile {
                        settings: settings.clone(),
                        approvals: Arc::new(Queue::new(self.domain.clone())),
                    })
                });
            profile.approvals.set_notifications(settings.notifications);
        }
        inner.preferences = preferences;
        Ok(())
    }
    fn admit(&self) -> Result<()> {
        anyhow::ensure!(
            self.domain.is_current(self.domain_identity) && self.domain.enabled()?,
            "provider persistence domain ended; run syq persist receive on locally"
        );
        self.refresh()?;
        anyhow::ensure!(
            !self.stop.load(Ordering::Acquire),
            "SSH authorization provider is stopping"
        );
        Ok(())
    }
    fn close(&self) {
        self.stop.store(true, Ordering::Release);
        let mut inner = self.inner.lock().unwrap();
        for (_, session) in inner.sessions.drain() {
            session.close();
        }
        self.streams.shutdown_all();
    }
    fn snapshot(&self, decision_error: Option<String>) -> Snapshot {
        let inner = self.inner.lock().unwrap();
        Snapshot {
            build: crate::identity::build().into(),
            pid: std::process::id(),
            decision_error,
            profiles: inner
                .preferences
                .profiles
                .iter()
                .filter_map(|settings| {
                    let profile = inner.profiles.get(&settings.name)?;
                    Some(ProfileSnapshot {
                        settings: settings.clone(),
                        pending: profile.approvals.snapshots(),
                        sessions: inner
                            .sessions
                            .values()
                            .filter(|session| Arc::ptr_eq(&session.profile, profile))
                            .count(),
                    })
                })
                .collect(),
        }
    }
    fn handle(&self, mut stream: TrackedStream) -> Result<()> {
        let socket = stream.try_clone()?;
        socket.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
        socket.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;
        let hello: Hello = crate::destination::read_message(&mut stream)?;
        crate::destination::write_message(
            &mut stream,
            &HelloReply {
                version: PROTOCOL,
                build: crate::identity::build().into(),
            },
        )?;
        anyhow::ensure!(
            hello.version == PROTOCOL,
            "unsupported local provider protocol"
        );
        if hello.control {
            let request: Control = crate::destination::read_message(&mut stream)?;
            let decision_error = match request {
                Control::Status => None,
                Control::Refresh => {
                    self.refresh()?;
                    None
                }
                Control::Stop => {
                    self.stop.store(true, Ordering::Release);
                    None
                }
                Control::Decide(decision) => {
                    // Decisions use the matching build's Summary/Kind semantics.
                    anyhow::ensure!(
                        hello.build == crate::identity::build(),
                        "update the local syq client before deciding provider requests"
                    );
                    let inner = self.inner.lock().unwrap();
                    inner
                        .profiles
                        .values()
                        .find(|profile| {
                            profile
                                .approvals
                                .snapshots()
                                .iter()
                                .any(|summary| summary.id == decision.id)
                        })
                        .context("approval is unknown, expired, or already answered")
                        .and_then(|profile| {
                            profile.approvals.decide_with_remember(
                                &decision.id,
                                decision.allow,
                                decision.kind,
                                decision.remember,
                            )
                        })
                        .err()
                        .map(|error| format!("{error:#}"))
                }
            };
            return crate::destination::write_framed(
                &mut stream,
                &self.snapshot(decision_error),
                MAX_STATUS,
                "provider status",
            );
        }
        // Do not deserialize account/resolution bytes from a different build.
        anyhow::ensure!(
            hello.build == crate::identity::build(),
            "local provider build changed"
        );
        let request: Access = crate::destination::read_message(&mut stream)?;
        socket.set_read_timeout(Some(IO_TIMEOUT))?;
        socket.set_write_timeout(Some(IO_TIMEOUT))?;
        match request {
            Access::Attach { profile } => {
                let opened = self.open(profile.as_deref());
                let (ticket, session) = match opened {
                    Ok(value) => value,
                    Err(error) => {
                        crate::destination::write_message(
                            &mut stream,
                            &Err::<Ticket, _>(format!("{error:#}")),
                        )?;
                        return Ok(());
                    }
                };
                self.hold_attachment(stream, socket, ticket, session)
            }

            Access::Request { session, operation } => {
                let result = (|| {
                    validate_ticket(&session)?;
                    self.admit()?;
                    let session = self
                        .inner
                        .lock()
                        .unwrap()
                        .sessions
                        .get(&session)
                        .cloned()
                        .context(
                            "provider authorization session ended; reconnect to the provider",
                        )?;
                    let tracked = session.track(socket.try_clone()?)?;
                    let cancelled = || {
                        self.stop.load(Ordering::Acquire)
                            || session.closed.load(Ordering::Acquire)
                            || disconnected(&socket)
                    };
                    let context = AuthorizationContext {
                        origin: AuthorizationOrigin::Provider {
                            profile: &session.profile.settings.name,
                            identity: &session.identity,
                        },
                        approvals: &session.profile.approvals,
                        notifications: session.profile.settings.notifications,
                        request_lock: &session.request_lock,
                        active_count: &session.active_count,
                        session_grants: &session.grants,
                    };
                    match *operation {
                        SessionRequest::ResolveLocal(target) => {
                            ssh_auth::resolve_local_and_reply(&target, &mut stream, &cancelled)
                        }
                        SessionRequest::LocalAccount(request) => {
                            ssh_auth::authorize_local_and_relay(
                                context, request, tracked, 0, &cancelled,
                            )
                        }
                    }
                })();
                if let Err(error) = result {
                    ssh_auth::reply_error(&mut stream, &error)?;
                }
                Ok(())
            }
        }
    }
    fn hold_attachment(
        &self,
        mut stream: TrackedStream,
        socket: UnixStream,
        ticket: Ticket,
        session: Arc<Session>,
    ) -> Result<()> {
        // Register before replying so off/disconnect also wakes the lifetime
        // read. Even a racing profile stop goes through the cleanup below.
        let result = (|| {
            let _lifetime = session.track(socket.try_clone()?)?;
            crate::destination::write_message(&mut stream, &Ok::<_, String>(&ticket))?;
            socket.set_read_timeout(None)?;
            let mut byte = [0];
            loop {
                match stream.read(&mut byte) {
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    _ => break,
                }
            }
            Ok(())
        })();
        session.close();
        self.inner.lock().unwrap().sessions.remove(&ticket.session);
        result
    }
    fn open(&self, selected: Option<&str>) -> Result<(Ticket, Arc<Session>)> {
        self.admit()?;
        self.open_identified(selected, local_identity)
    }
    fn open_identified(
        &self,
        selected: Option<&str>,
        identity: impl FnOnce() -> Result<ProviderIdentity>,
    ) -> Result<(Ticket, Arc<Session>)> {
        let mut inner = self.inner.lock().unwrap();
        anyhow::ensure!(
            !self.stop.load(Ordering::Acquire),
            "SSH authorization provider is stopping"
        );
        let index = inner.preferences.selected(selected)?;
        let settings = &inner.preferences.profiles[index];
        anyhow::ensure!(
            settings.enabled,
            "provider profile {} is off; enable it locally or select an enabled profile",
            settings.name
        );
        let profile = inner
            .profiles
            .get(&settings.name)
            .cloned()
            .context("provider profile is not ready")?;
        let identity = identity()?;
        let mut random = [0; 32];
        getrandom::fill(&mut random)
            .map_err(|error| anyhow::anyhow!("provider session ID: {error}"))?;
        let ticket = Ticket {
            session: random.iter().map(|byte| format!("{byte:02x}")).collect(),
            profile: settings.name.clone(),
            identity: identity.clone(),
        };
        let session = Arc::new(Session {
            profile,
            identity,
            closed: AtomicBool::new(false),
            admission: Mutex::new(()),
            streams: Arc::new(ConnectionRegistry::new(IO_TIMEOUT)),
            request_lock: Mutex::new(()),
            active_count: AtomicU64::new(0),
            grants: Mutex::new(HashMap::new()),
        });
        inner
            .sessions
            .insert(ticket.session.clone(), session.clone());
        Ok((ticket, session))
    }
}

fn disconnected(socket: &UnixStream) -> bool {
    let mut byte = 0u8;
    let result = unsafe {
        libc::recv(
            socket.as_raw_fd(),
            (&mut byte as *mut u8).cast(),
            1,
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    result == 0
        || (result < 0
            && !matches!(
                std::io::Error::last_os_error().kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            ))
}
fn local_identity() -> Result<ProviderIdentity> {
    let uid = unsafe { libc::geteuid() };
    let mut buffer = vec![0; 16 * 1024];
    loop {
        let mut record: libc::passwd = unsafe { std::mem::zeroed() };
        let mut found = std::ptr::null_mut();
        let result = unsafe {
            libc::getpwuid_r(
                uid,
                &mut record,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut found,
            )
        };
        if result == libc::ERANGE && buffer.len() < 1024 * 1024 {
            buffer.resize(buffer.len() * 2, 0);
            continue;
        }
        if result != 0 {
            return Err(std::io::Error::from_raw_os_error(result))
                .context("resolve provider's local account");
        }
        anyhow::ensure!(
            !found.is_null() && !record.pw_name.is_null(),
            "provider's effective UID has no account name"
        );
        let user = unsafe { std::ffi::CStr::from_ptr(record.pw_name) }
            .to_str()
            .context("provider account name is not UTF-8")?
            .to_owned();
        return ProviderIdentity::new(user, crate::destination::receiving_identity_fingerprint()?);
    }
}

struct Lock(File);
impl Drop for Lock {
    fn drop(&mut self) {
        unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}
fn acquire_lock(domain: &Domain, create: bool) -> Result<Option<Lock>> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(create)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(domain.runtime_path().join(LOCK_FILE))?;
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0,
        "provider lock must be owned and private"
    );
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(Some(Lock(file)));
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::WouldBlock {
        return Ok(None);
    }
    Err(error.into())
}
fn is_running(domain: &Domain) -> Result<bool> {
    match acquire_lock(domain, false) {
        Ok(lock) => Ok(lock.is_none()),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

/// Called only by explicit local receive-on, never by an inbound SSH helper.
pub(super) fn ensure(domain: &Domain) -> Result<()> {
    domain.ensure_runtime()?;
    if let Some(state) = snapshot(domain)? {
        if state.build == crate::identity::build() {
            return refresh(domain);
        }
        stop(domain)?;
    }
    let (mut startup, child_output) = crate::process::with_inheritance_guard(UnixStream::pair)?;
    startup.set_read_timeout(Some(STOP_TIMEOUT))?;
    let mut command = Command::new(std::env::current_exe()?);
    command
        .arg(INTERNAL)
        .arg(domain.runtime_path())
        .stdin(Stdio::null())
        .stdout(File::from(std::os::fd::OwnedFd::from(child_output)))
        .stderr(Stdio::null());
    crate::destination::ssh::persistent::protect_keeper_inheritance(&mut command)?;
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command
        .spawn_guarded()
        .context("start local SSH authorization provider")?;
    let ready: Result<std::result::Result<(), String>> =
        crate::destination::read_message(&mut startup);
    match ready {
        Ok(Ok(())) => {
            std::thread::spawn(move || {
                let _ = child.wait();
            });
            Ok(())
        }
        result => {
            // The leader has not been reaped; the process group remains ours.
            unsafe {
                libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL);
            }
            let _ = child.wait();
            // A simultaneous local receive-on may have started the owner.
            if snapshot(domain)?.is_some_and(|state| state.build == crate::identity::build()) {
                return refresh(domain);
            }
            match result {
                Ok(Err(error)) => Err(anyhow::Error::msg(error)),
                Err(error) => Err(error).context("local SSH authorization provider did not start"),
                Ok(Ok(())) => unreachable!(),
            }
        }
    }
}

pub(crate) fn stop(domain: &Domain) -> Result<()> {
    let deadline = Instant::now() + STOP_TIMEOUT;
    let mut progress = Instant::now();
    while is_running(domain)? {
        let _ = query(domain, Control::Stop);
        anyhow::ensure!(
            Instant::now() < deadline,
            "local SSH authorization provider did not stop in {}",
            domain.runtime_path().display()
        );
        if progress.elapsed() >= Duration::from_secs(5) {
            crate::output::diagnostic!("syq: waiting for local SSH authorization provider to stop");
            progress = Instant::now();
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(())
}

struct Runtime {
    _lock: Lock,
    _socket: SocketCleanup,
    listener: UnixListener,
    service: Arc<Service>,
}
impl Runtime {
    fn new(domain: Domain) -> Result<Self> {
        let scope = domain.ensure_runtime()?;
        anyhow::ensure!(
            domain.enabled()? && preferences(&domain)?.enabled(),
            "receiving is off in this domain"
        );
        let lock = acquire_lock(&domain, true)?
            .context("local SSH authorization provider is already running")?;
        let path = scope.join(SOCKET_FILE);
        match fs::symlink_metadata(&path) {
            Ok(metadata)
                if metadata.file_type().is_socket()
                    && metadata.uid() == unsafe { libc::geteuid() } =>
            {
                fs::remove_file(&path)?
            }
            Ok(_) => bail!("unexpected entry at provider socket {}", path.display()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let listener = UnixListener::bind(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        let socket_metadata = fs::symlink_metadata(&path)?;
        Ok(Self {
            _lock: lock,
            _socket: SocketCleanup {
                path,
                identity: (socket_metadata.dev(), socket_metadata.ino()),
            },
            listener,
            service: Arc::new(Service::new(domain)?),
        })
    }
    fn run(&self) -> Result<()> {
        let (mut wake, sender) = crate::process::with_inheritance_guard(UnixStream::pair)?;
        wake.set_nonblocking(true)?;
        sender.set_nonblocking(true)?;
        let sender = Arc::new(sender);
        let _signals = SignalWake::new(self.service.stop.clone(), &sender)?;
        let (completed, completions) = std::sync::mpsc::channel();
        let mut workers = Vec::<std::thread::JoinHandle<()>>::new();
        let result = (|| {
            while !self.service.stop.load(Ordering::Acquire) {
                // Completion is queued before waking poll; join also covers the
                // short interval between that wake and the thread's return.
                for id in completions.try_iter() {
                    if let Some(index) =
                        workers.iter().position(|worker| worker.thread().id() == id)
                    {
                        let _ = workers.swap_remove(index).join();
                    }
                }
                match self.listener.accept() {
                    Ok((stream, _)) => {
                        if workers.len() >= MAX_CLIENTS {
                            continue;
                        }
                        stream.set_nonblocking(false)?;
                        let stream = self.service.streams.track(stream)?;
                        let service = self.service.clone();
                        let completed = completed.clone();
                        let sender = sender.clone();
                        workers.push(std::thread::spawn(move || {
                            let _ = service.handle(stream);
                            let _ = completed.send(std::thread::current().id());
                            let _ = (&*sender).write(&[1]);
                        }));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        wait_for_event(&self.listener, &mut wake)?;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            Ok(())
        })();
        self.service.close();
        for worker in workers {
            let _ = worker.join();
        }
        result
    }
}

// Worker completion and control requests use the same event channel as signals.
// An idle service does no periodic configuration or filesystem reads.
fn wait_for_event(listener: &UnixListener, wake: &mut UnixStream) -> Result<()> {
    let mut descriptors = [
        libc::pollfd {
            fd: listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: wake.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    let result = unsafe { libc::poll(descriptors.as_mut_ptr(), descriptors.len() as _, -1) };
    if result < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
        return Err(std::io::Error::last_os_error().into());
    }
    loop {
        match wake.read(&mut [0; 128]) {
            Ok(0) => bail!("provider wake channel closed"),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) => return Err(error.into()),
        }
    }
}
struct SignalWake {
    _registrations: crate::process::signals::Owned<crate::process::signals::Registrations>,
}
impl SignalWake {
    fn new(stop: Arc<AtomicBool>, sender: &UnixStream) -> Result<Self> {
        let registrations = crate::process::signals::owned(&[libc::SIGINT, libc::SIGTERM], || {
            let mut registrations = crate::process::signals::Registrations::default();
            for signal in [libc::SIGINT, libc::SIGTERM] {
                registrations.push(signal_hook::flag::register(signal, stop.clone())?);
                registrations.push(signal_hook::low_level::pipe::register(
                    signal,
                    sender.try_clone()?,
                )?);
            }
            Ok(registrations)
        })?;
        Ok(Self {
            _registrations: registrations,
        })
    }
}

pub(super) fn dispatch(argv: &[OsString]) -> Option<Result<i32>> {
    if argv.get(1).and_then(|value| value.to_str()) != Some(INTERNAL) {
        return None;
    }
    Some((|| {
        anyhow::ensure!(
            argv.len() == 3,
            "local provider service needs its persistence domain path"
        );
        crate::fsops::reserve_startup_descriptors();
        let runtime = Domain::select(Some(Path::new(&argv[2]))).and_then(Runtime::new);
        let ready = runtime
            .as_ref()
            .map(|_| ())
            .map_err(|error| format!("{error:#}"));
        crate::destination::write_message(&mut std::io::stdout().lock(), &ready)?;
        runtime?.run()?;
        Ok(0)
    })())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, Domain, Preferences) {
        let root = fs::canonicalize("/tmp").unwrap();
        let directory = tempfile::tempdir_in(root).unwrap();
        let path = directory.path().join("domain");
        crate::persistence::initialize_scope(&path).unwrap();
        let domain = Domain::select(Some(&path)).unwrap();
        let mut first = default_settings(&domain).unwrap();
        first.name = "first".into();
        first.enabled = true;
        first.notifications = crate::receive_approval::Notifications::Off;
        first.cwd = path;
        let mut second = first.clone();
        second.name = "second".into();
        let preferences = Preferences {
            version: PREFERENCES_VERSION,
            profiles: vec![first, second],
        };
        save_settings(&domain, &preferences).unwrap();
        (directory, domain, preferences)
    }
    fn identity() -> Result<ProviderIdentity> {
        ProviderIdentity::new(
            "provider".into(),
            ssh_key::Fingerprint::Sha256([1; 32]).to_string(),
        )
    }
    fn pair(service: &Service) -> (UnixStream, TrackedStream) {
        let (client, server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        (client, service.streams.track(server).unwrap())
    }

    #[test]
    fn default_is_first_configured_profile_and_outbound_selection_is_not_incoming_identity() {
        let (_directory, domain, mut config) = fixture();
        config.profiles[0].enabled = false;
        config.profiles[1].servers = vec!["outbound-only".into()];
        save_settings(&domain, &config).unwrap();
        let service = Service::new(domain).unwrap();
        let error = service
            .open_identified(None, || panic!("disabled profile must not load identity"))
            .err()
            .unwrap();
        assert!(error.to_string().contains("first is off"));
        let (ticket, _) = service.open_identified(Some("second"), identity).unwrap();
        assert_eq!(ticket.profile, "second");
        assert_eq!(ticket.identity.user, "provider");
        assert!(service.open_identified(Some("missing"), identity).is_err());
        service.close();
    }

    #[test]
    fn provider_build_mismatch_names_both_builds_and_matching_restart() {
        let (client, mut server) = UnixStream::pair().unwrap();
        let reply = std::thread::spawn(move || {
            server
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let _: Hello = crate::destination::read_message(&mut server).unwrap();
            crate::destination::write_message(
                &mut server,
                &HelloReply {
                    version: PROTOCOL,
                    build: "provider-other-build".into(),
                },
            )
            .unwrap();
        });
        let error = handshake(client, false).unwrap_err();
        reply.join().unwrap();
        let error = error.to_string();
        assert!(error.contains("provider-other-build"));
        assert!(error.contains(crate::identity::build()));
        assert!(error.contains("install the same syq build on the requester and provider"));
        assert!(error.contains("persist receive on locally on the provider"));
    }

    #[test]
    fn build_is_checked_before_account_or_resolution_bytes_are_interpreted() {
        let (_directory, domain, _) = fixture();
        let service = Arc::new(Service::new(domain).unwrap());
        let (mut client, server) = pair(&service);
        let worker = std::thread::spawn(move || service.handle(server));
        crate::destination::write_message(
            &mut client,
            &Hello {
                version: PROTOCOL,
                build: "different-build".into(),
                control: false,
            },
        )
        .unwrap();
        let reply: HelloReply = crate::destination::read_message(&mut client).unwrap();
        assert_eq!(reply.build, crate::identity::build());
        // No Access frame is sent. Rejection must not wait to parse one.
        let error = worker.join().unwrap().unwrap_err();
        assert!(error.to_string().contains("build changed"));
    }

    #[test]
    fn attachment_eof_revokes_ticket_and_live_operations_but_not_other_sessions() {
        let (_directory, domain, _) = fixture();
        let service = Arc::new(Service::new(domain).unwrap());
        let (ticket, session) = service.open_identified(None, identity).unwrap();
        let (other_ticket, other) = service.open_identified(None, identity).unwrap();
        session.grants.lock().unwrap().insert("account".into(), 0);
        assert!(other.grants.lock().unwrap().is_empty());
        let (mut operation_client, operation_server) = UnixStream::pair().unwrap();
        operation_client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let _operation = session.track(operation_server).unwrap();
        let (mut client, server) = pair(&service);
        let socket = server.try_clone().unwrap();
        let thread_service = service.clone();
        let thread_session = session.clone();
        let expected = ticket.session.clone();
        let worker = std::thread::spawn(move || {
            thread_service.hold_attachment(server, socket, ticket, thread_session)
        });
        let received: std::result::Result<Ticket, String> =
            crate::destination::read_message(&mut client).unwrap();
        assert_eq!(received.unwrap().session, expected);
        drop(client);
        worker.join().unwrap().unwrap();
        assert!(session.closed.load(Ordering::Acquire));
        assert!(session.grants.lock().unwrap().is_empty());
        assert_eq!(operation_client.read(&mut [0]).unwrap(), 0);
        assert!(!service
            .inner
            .lock()
            .unwrap()
            .sessions
            .contains_key(&expected));
        assert!(service
            .inner
            .lock()
            .unwrap()
            .sessions
            .contains_key(&other_ticket.session));
        assert!(!other.closed.load(Ordering::Acquire));
        let (_, late) = UnixStream::pair().unwrap();
        assert!(session.track(late).is_err());
        service.close();
    }

    #[test]
    fn notification_refresh_preserves_attachment_grants_and_updates_future_prompts() {
        use crate::receive_approval::{
            accounts::AccountIdentity, provider_accounts::ProviderLoginPermission, AccountDecision,
            Kind, Notifications,
        };
        let (_directory, domain, mut config) = fixture();
        config.profiles[0].notifications = Notifications::Desktop;
        save_settings(&domain, &config).unwrap();
        let service = Service::new(domain.clone()).unwrap();
        let (ticket, session) = service.open_identified(None, identity).unwrap();
        let (mut client, server) = UnixStream::pair().unwrap();
        client
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut tracked = session.track(server).unwrap();
        session
            .grants
            .lock()
            .unwrap()
            .insert("existing-account".into(), 0);
        config.profiles[0].notifications = Notifications::Off;
        save_settings(&domain, &config).unwrap();
        service.refresh().unwrap();
        assert!(!session.closed.load(Ordering::Acquire));
        client.write_all(b"still connected").unwrap();
        let mut received = [0; 15];
        tracked.read_exact(&mut received).unwrap();
        assert_eq!(&received, b"still connected");
        assert!(service
            .inner
            .lock()
            .unwrap()
            .sessions
            .contains_key(&ticket.session));
        assert_eq!(
            session.grants.lock().unwrap().get("existing-account"),
            Some(&0)
        );
        assert_eq!(
            service.snapshot(None).profiles[0].settings.notifications,
            Notifications::Off
        );

        // The existing handler still carries its initial Desktop value. The
        // shared approval queue must apply the updated preference to this request.
        let permission = ProviderLoginPermission::new(
            "first".into(),
            identity().unwrap(),
            AccountIdentity::new(
                crate::cli::NativeEndpoint {
                    user: Some("destination-user".into()),
                    host: "destination".into(),
                    port: Some(22),
                },
                vec![ssh_key::Fingerprint::Sha256([2; 32]).to_string()],
            )
            .unwrap(),
        )
        .unwrap();
        let request_session = session.clone();
        let request = std::thread::spawn(move || {
            request_session.profile.approvals.request_provider_account(
                &[b"ssh".to_vec(), b"destination".to_vec()],
                "/reported",
                &permission,
                request_session.profile.settings.notifications,
                || request_session.closed.load(Ordering::Acquire),
            )
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        let pending = loop {
            if let Some(pending) = session
                .profile
                .approvals
                .snapshots()
                .into_iter()
                .find(|request| !request.notification.is_empty())
            {
                break pending;
            }
            assert!(
                Instant::now() < deadline,
                "provider approval did not become pending"
            );
            std::thread::sleep(Duration::from_millis(5));
        };
        assert!(
            pending.notification.starts_with("disabled;"),
            "{}",
            pending.notification
        );
        // A later delivery change also preserves an already pending request.
        config.profiles[0].notifications = Notifications::Desktop;
        save_settings(&domain, &config).unwrap();
        service.refresh().unwrap();
        assert!(!session.closed.load(Ordering::Acquire));
        assert_eq!(session.profile.approvals.snapshots()[0].id, pending.id);
        session
            .profile
            .approvals
            .decide(&pending.id, true, Kind::ProviderSsh)
            .unwrap();
        assert_eq!(request.join().unwrap().unwrap(), AccountDecision::Session);
        service.close();
    }

    #[test]
    fn profile_stop_closes_only_its_attachments_and_preserves_other_pending_authority() {
        let (_directory, domain, mut config) = fixture();
        let service = Service::new(domain.clone()).unwrap();
        let (first_ticket, first) = service.open_identified(Some("first"), identity).unwrap();
        let (second_ticket, second) = service.open_identified(Some("second"), identity).unwrap();
        second
            .grants
            .lock()
            .unwrap()
            .insert("other-account".into(), 0);
        let (mut client, server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let _lifetime = first.track(server).unwrap();
        config.profiles[0].enabled = false;
        save_settings(&domain, &config).unwrap();
        service.refresh().unwrap();
        assert_eq!(client.read(&mut [0]).unwrap(), 0);
        let inner = service.inner.lock().unwrap();
        assert!(!inner.sessions.contains_key(&first_ticket.session));
        assert!(inner.sessions.contains_key(&second_ticket.session));
        drop(inner);
        assert!(!second.closed.load(Ordering::Acquire));
        assert_eq!(second.grants.lock().unwrap().get("other-account"), Some(&0));
        service.close();
    }

    #[test]
    fn local_control_lists_and_decides_provider_requests_without_return_source_identity() {
        use crate::receive_approval::{
            accounts::AccountIdentity, provider_accounts::ProviderLoginPermission, AccountDecision,
            Kind, Notifications,
        };
        let (_directory, domain, _) = fixture();
        let service = Arc::new(Service::new(domain).unwrap());
        let (_, session) = service.open_identified(None, identity).unwrap();
        let permission = ProviderLoginPermission::new(
            "first".into(),
            identity().unwrap(),
            AccountIdentity::new(
                crate::cli::NativeEndpoint {
                    user: Some("destination-user".into()),
                    host: "destination".into(),
                    port: Some(22),
                },
                vec![ssh_key::Fingerprint::Sha256([2; 32]).to_string()],
            )
            .unwrap(),
        )
        .unwrap();
        let request_session = session.clone();
        let request = std::thread::spawn(move || {
            request_session.profile.approvals.request_provider_account(
                &[b"ssh".to_vec(), b"destination".to_vec()],
                "/reported",
                &permission,
                Notifications::Off,
                || request_session.closed.load(Ordering::Acquire),
            )
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        let pending = loop {
            if let Some(pending) = service
                .snapshot(None)
                .profiles
                .iter()
                .flat_map(|profile| &profile.pending)
                .next()
                .cloned()
            {
                break pending;
            }
            assert!(
                Instant::now() < deadline,
                "provider approval did not become pending"
            );
            std::thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(pending.kind(), Kind::ProviderSsh);
        assert!(pending.account().is_none());
        assert!(pending.can_remember());
        let (mut client, server) = pair(&service);
        let handler_service = service.clone();
        let handler = std::thread::spawn(move || handler_service.handle(server));
        crate::destination::write_message(
            &mut client,
            &Hello {
                version: PROTOCOL,
                build: crate::identity::build().into(),
                control: true,
            },
        )
        .unwrap();
        let _: HelloReply = crate::destination::read_message(&mut client).unwrap();
        crate::destination::write_message(
            &mut client,
            &Control::Decide(Decision {
                id: pending.id,
                allow: true,
                kind: Kind::ProviderSsh,
                remember: false,
            }),
        )
        .unwrap();
        let state: Snapshot =
            crate::destination::read_framed(&mut client, MAX_STATUS, "provider status").unwrap();
        assert!(state.decision_error.is_none());
        handler.join().unwrap().unwrap();
        assert_eq!(request.join().unwrap().unwrap(), AccountDecision::Session);
        service.close();
    }

    #[test]
    fn idle_runtime_stops_on_control_event_without_a_timer() {
        let (_directory, domain, _) = fixture();
        let runtime = Runtime::new(domain.clone()).unwrap();
        let (finished, completion) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let result = runtime.run();
            drop(runtime);
            let _ = finished.send(result);
        });
        let state = query(&domain, Control::Status).unwrap();
        assert_eq!(state.profiles.len(), 2);
        assert!(matches!(
            completion.recv_timeout(Duration::from_millis(30)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        stop(&domain).unwrap();
        completion
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap();
        worker.join().unwrap();
    }

    #[test]
    fn request_admission_checks_domain_and_current_profile_without_idle_polling() {
        let (_directory, domain, mut config) = fixture();
        let service = Service::new(domain.clone()).unwrap();
        let (ticket, session) = service.open_identified(None, identity).unwrap();
        config.profiles[0].enabled = false;
        save_settings(&domain, &config).unwrap();
        service.admit().unwrap();
        assert!(session.closed.load(Ordering::Acquire));
        assert!(!service
            .inner
            .lock()
            .unwrap()
            .sessions
            .contains_key(&ticket.session));
        fs::write(domain.runtime_path().join(CLOSING), b"").unwrap();
        assert!(service
            .admit()
            .unwrap_err()
            .to_string()
            .contains("domain ended"));
        service.close();
    }

    #[test]
    fn runtime_socket_is_private_and_domains_have_independent_services() {
        let (_first_dir, first_domain, _) = fixture();
        let (_second_dir, second_domain, _) = fixture();
        let first = Runtime::new(first_domain.clone()).unwrap();
        let second = Runtime::new(second_domain.clone()).unwrap();
        let path = first_domain.runtime_path().join(SOCKET_FILE);
        let metadata = fs::symlink_metadata(&path).unwrap();
        assert!(metadata.file_type().is_socket());
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        assert!(is_running(&first_domain).unwrap());
        assert!(is_running(&second_domain).unwrap());
        drop(first);
        assert!(!path.exists());
        assert!(!is_running(&first_domain).unwrap());
        assert!(is_running(&second_domain).unwrap());
        drop(second);
    }
}

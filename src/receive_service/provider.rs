//! Local approval/agent environment for ordinary SSH provider logins. An SSH
//! helper attaches here; it never creates this service from its login environment.
use super::*;
use crate::destination::ssh_auth::{self, AuthorizationContext, AuthorizationOrigin};
use crate::private_broker::{ConnectionRegistry, TrackedStream};
use crate::receive_approval::provider_accounts::ProviderIdentity;
use crate::receive_approval::Queue;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize};

pub(crate) const SOCKET_FILE: &str = "provider-v1.sock";
pub(crate) const LOCK_FILE: &str = "provider-v1.lock";
const INTERNAL: &str = "--receive-provider-service";
const PROTOCOL: u16 = 1;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);
const FORWARDED_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
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
    /// Stop only if nothing is in progress, to switch to another build.
    /// Only a provider whose status reports what it has in progress
    /// (`Snapshot::busy`) receives it.
    StopIfIdle,
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
    /// A copy between two other servers that the login asks this provider
    /// to approve, as a receiving machine approves one
    /// (`destination::forward::approve`).
    Forward(Box<crate::destination::forward::ForwardRequest>),
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
impl Snapshot {
    /// What it has in progress, as a receiving service reports it.
    pub(crate) fn busy(&self) -> Option<super::Busy> {
        let busy = self.busy?;
        let accounts = self.accounts.unwrap_or(0);
        Some(super::Busy {
            requests: busy.saturating_sub(accounts),
            pending: 0,
            accounts,
            accounts_in_use: self.accounts_in_use.unwrap_or(0),
        })
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Snapshot {
    pub(crate) build: String,
    pub(crate) pid: u32,
    pub(crate) profiles: Vec<ProfileSnapshot>,
    pub(crate) decision_error: Option<String>,
    /// Logins and requests in progress, absent from providers from before
    /// syq followed updates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) busy: Option<usize>,
    /// Of those, approved account connections open through it, which hold
    /// a request for as long as they live (`super::Busy::accounts`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) accounts: Option<usize>,
    /// Of those, the ones that say something uses them
    /// (`super::Busy::accounts_in_use`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) accounts_in_use: Option<usize>,
    /// The path the provider follows to switch to a new build (`switch`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) started_from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) switch: Option<super::switch::Report>,
    /// Whether it stops in answer to `StopIfIdle`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) stopping: bool,
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

/// Verify forwarding reaches this exact provider service without opening an
/// attachment, resolving policy, or requesting account approval.
pub(crate) fn probe_forwarded(
    stream: UnixStream,
    deadline: Instant,
    cancelled: &dyn Fn() -> bool,
) -> Result<()> {
    let stream = forwarded_handshake(stream, deadline, Some(cancelled))?;
    // Hello already succeeded. A peer closing first must not turn that into
    // failure (macOS reports ENOTCONN when shutting down a closed socket).
    let _ = stream.shutdown(std::net::Shutdown::Both);
    Ok(())
}

fn forwarded_handshake(
    mut stream: UnixStream,
    deadline: Instant,
    cancelled: Option<&dyn Fn() -> bool>,
) -> Result<UnixStream> {
    // This channel crosses SSH, unlike the local service socket. Use an
    // absolute network deadline and retain timeouts for the next Access write.
    stream.set_read_timeout(Some(FORWARDED_HANDSHAKE_TIMEOUT))?;
    stream.set_write_timeout(Some(FORWARDED_HANDSHAKE_TIMEOUT))?;
    exchange_hello(&mut crate::destination::DeadlineIo {
        inner: &mut stream,
        deadline: deadline.min(Instant::now() + FORWARDED_HANDSHAKE_TIMEOUT),
        cancelled,
    }, false).context(
        "could not open the SSH authorization provider service; check that receiving is running there and sshd permits local forwarding with AllowTcpForwarding and AllowStreamLocalForwarding set to local or yes",
    )?;
    Ok(stream)
}

/// Use the same exact-build protocol over an already connected SSH Unix forward.
pub(crate) fn open_forwarded(
    stream: UnixStream,
    session: &str,
    operation: SessionRequest,
) -> Result<UnixStream> {
    let stream = forwarded_handshake(stream, Instant::now() + FORWARDED_HANDSHAKE_TIMEOUT, None)?;
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
        metadata.file_type().is_socket() && metadata.uid() == unsafe { libc::geteuid() },
        "provider control socket must be owned and private"
    );
    if metadata.mode() & 0o077 != 0 {
        return Err(NotYetPrivate.into());
    }
    handshake(UnixStream::connect(&path)?, control)
}
/// The provider binds its socket before making it private. Never connect to
/// it before then; while the provider holds its lock, it is still starting.
#[derive(Debug)]
struct NotYetPrivate;
impl std::fmt::Display for NotYetPrivate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("provider control socket must be owned and private")
    }
}
impl std::error::Error for NotYetPrivate {}
fn handshake(mut stream: UnixStream, control: bool) -> Result<UnixStream> {
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;
    exchange_hello(&mut stream, control)?;
    Ok(stream)
}
fn exchange_hello(stream: &mut (impl Read + Write), control: bool) -> Result<()> {
    crate::destination::write_message(
        stream,
        &Hello {
            version: PROTOCOL,
            build: crate::identity::build().into(),
            control,
        },
    )?;
    let reply: HelloReply = crate::destination::read_message(stream)?;
    anyhow::ensure!(
        reply.version == PROTOCOL,
        "unsupported local provider protocol; restart receiving with its original syq build"
    );
    anyhow::ensure!(
        control || reply.build == crate::identity::build(),
        "SSH authorization provider service uses build {}, but this requester/helper uses {}; install the same syq build on the requester and provider, where the service switches to it by itself once idle",
        reply.build,
        crate::identity::build()
    );
    Ok(())
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
/// Query the provider holding the lock, giving one that is starting up to
/// `timeout` to answer: it takes the lock before it binds its socket and makes
/// that private. None once no provider holds the lock.
fn running(
    domain: &Domain,
    timeout: Duration,
    operation: impl Fn() -> Control,
) -> Result<Option<Snapshot>> {
    let deadline = Instant::now() + timeout;
    while is_running(domain)? {
        match query(domain, operation()) {
            Ok(state) => return Ok(Some(state)),
            Err(error) if unanswered(&error) || error.is::<NotYetPrivate>() => {
                if Instant::now() >= deadline {
                    return Err(error.context(format!(
                        "SSH authorization provider is running but not answering in {}",
                        domain.runtime_path().display()
                    )));
                }
                std::thread::sleep(ANSWER_POLL);
            }
            Err(error) => return Err(error),
        }
    }
    Ok(None)
}
/// The hidden `persist receive` subcommand a provider runs with a new build
/// at its path to switch to it (`switch`).
pub(crate) const SWITCH_PROVIDER: &str = "switch-provider";

/// Replace a provider from another build with one from this build once it
/// is idle, as a provider's switch to a new build asks. Leave one that
/// follows another installed syq file, as `Replace::WhenIdle` does.
///
/// A provider that agreed to stop is only waited for, never sent a stop:
/// another may start meanwhile, and is looked at in turn.
pub(super) fn switch_when_idle(domain: &Domain) -> Result<()> {
    if !domain.enabled()? || !preferences(domain)?.enabled() {
        return Ok(());
    }
    for _ in 0..4 {
        let Some(state) = running(domain, ANSWER_TIMEOUT, || Control::Status)? else {
            return start(domain);
        };
        if state.build == crate::identity::build() {
            return refresh(domain);
        }
        if super::switch::follows_other_file(state.started_from.as_deref()) {
            crate::output::command_human_stdout!(
                "The SSH authorization provider keeps running syq {}, which follows another installed syq",
                state.build
            );
            return Ok(());
        }
        let pid = if state.busy.is_none() {
            // One from before syq followed updates has only a stop.
            query(domain, Control::Stop)?.pid
        } else {
            let answer = query(domain, Control::StopIfIdle)?;
            if !answer.stopping {
                let mut fix = "syq persist receive on".to_owned();
                if let Some(scope) = domain.explicit_path() {
                    fix.push_str(&format!(
                        " --pscope {}",
                        shell_words::quote(&scope.to_string_lossy())
                    ));
                }
                let busy = answer.busy().unwrap_or_default();
                match busy.accounts_note(None, &fix) {
                    Some(accounts) if busy.requests == 0 => crate::output::command_human_stdout!(
                        "The SSH authorization provider keeps running syq {}: {accounts}",
                        state.build
                    ),
                    _ => crate::output::command_human_stdout!(
                        "The SSH authorization provider keeps running syq {} until its requests finish",
                        state.build
                    ),
                }
                return Ok(());
            }
            answer.pid
        };
        await_exit(domain, pid)?;
    }
    Ok(())
}

/// Replace a provider from another build that cannot follow updates by
/// itself, as `receive_service::switch_outdated_now` does for receiving:
/// one a command run with `--use-version` started from a release in the
/// binary store, replaced once idle, or one from before syq followed
/// updates, which cannot say whether it is idle and is stopped at once,
/// ending any request it is serving (`switch_when_idle`).
pub(super) fn switch_outdated(domain: &Domain) -> Result<()> {
    let Some(state) = running(domain, ANSWER_TIMEOUT, || Control::Status)? else {
        return Ok(());
    };
    if state.build == crate::identity::build()
        || super::switch::follows(state.started_from.as_deref()) != super::switch::Follows::Nothing
    {
        return Ok(());
    }
    switch_when_idle(domain)
}

/// Wait for provider process `pid`, which is stopping, to give up the
/// lock: until it has exited, or another provider answers.
fn await_exit(domain: &Domain, pid: u32) -> Result<()> {
    let deadline = Instant::now() + STOP_TIMEOUT;
    while is_running(domain)? {
        match query(domain, Control::Status) {
            Ok(state) if state.pid != pid => return Ok(()),
            Ok(_) => {}
            Err(_) if !process_alive(pid) => return Ok(()),
            Err(_) => {}
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "local SSH authorization provider did not stop in {}",
            domain.runtime_path().display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(())
}

/// Stop a provider from another build, and report whether there was one.
pub(super) fn stop_other_build(domain: &Domain) -> Result<bool> {
    if running(domain, ANSWER_TIMEOUT, || Control::Status)?
        .is_some_and(|state| state.build != crate::identity::build())
    {
        stop(domain)?;
        return Ok(true);
    }
    Ok(false)
}
pub(super) fn refresh(domain: &Domain) -> Result<()> {
    running(domain, ANSWER_TIMEOUT, || Control::Refresh)?;
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
    /// Copies between two servers this login asked for, waiting for
    /// approval or setup.
    forward_count: AtomicUsize,
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
    /// Requests being handled for attached logins, such as authorizing an
    /// account login; not the attachments themselves.
    requests: AtomicUsize,
    /// Of those, approved account logins whose agent requests it relays: an
    /// approved account connection holds one for as long as it lives.
    account_relays: AtomicU64,
    /// Of those, the ones that say whether anything uses them.
    account_links: ssh_auth::AccountLinks,
    /// Refusing new requests while it ends idle account connections to
    /// switch builds (`stop_if_idle`).
    switching: AtomicBool,
    /// Held by the one `stop_if_idle` running.
    stop_attempt: Mutex<()>,
    /// Notified when `stop_if_idle` decides; `admit` waits for that.
    switch_decided: (Mutex<()>, std::sync::Condvar),
    /// The path the provider follows, and its switch to a new build.
    started_from: Option<String>,
    switch: Mutex<Option<super::switch::Report>>,
}
/// One login or request being handled, until dropped.
struct Counted<'a>(&'a AtomicUsize);
impl Drop for Counted<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
impl Service {
    fn new(domain: Domain, started_from: Option<String>) -> Result<Self> {
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
            requests: AtomicUsize::new(0),
            account_relays: AtomicU64::new(0),
            account_links: Default::default(),
            switching: AtomicBool::new(false),
            stop_attempt: Mutex::new(()),
            switch_decided: Default::default(),
            started_from,
            switch: Mutex::new(None),
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
        // While a stop is tentative, wait for it to be decided.
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut decided = self.switch_decided.0.lock().unwrap();
        while self.switching.load(Ordering::SeqCst) && !self.stop.load(Ordering::SeqCst) {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            decided = self.switch_decided.1.wait_timeout(decided, left).unwrap().0;
        }
        anyhow::ensure!(
            !self.stop.load(Ordering::SeqCst) && !self.switching.load(Ordering::SeqCst),
            "SSH authorization provider is stopping"
        );
        Ok(())
    }
    /// Requests being handled and requests waiting for approval. Logins
    /// attached to the provider do not count: switching to another build
    /// ends them, and with them their session permissions (Allow), as any
    /// reconnect does; the requester attaches again on its next use. Nor
    /// do account connections that say nothing uses them, which a switch
    /// ends too (`stop_if_idle`).
    fn busy(&self) -> usize {
        // Links can only be fewer than the requests read before them.
        let requests = self.requests.load(Ordering::SeqCst);
        let idle = self.account_links.idle();
        let inner = self.inner.lock().unwrap();
        requests.saturating_sub(idle)
            + inner
                .profiles
                .values()
                .map(|profile| profile.approvals.snapshots().len())
                .sum::<usize>()
    }
    /// Stop if nothing is in progress (`busy`), after ending the account
    /// connections nothing uses; whether it did. One attempt runs at a
    /// time; another meanwhile does not stop it. New requests wait from
    /// before the decision, and are admitted if it does not stop.
    fn stop_if_idle(&self) -> bool {
        let Ok(_attempt) = self.stop_attempt.try_lock() else {
            return false;
        };
        {
            let _inner = self.inner.lock().unwrap();
            self.switching.store(true, Ordering::SeqCst);
        }
        let stopped = self.stop_admitted_if_idle();
        {
            let _decided = self.switch_decided.0.lock().unwrap();
            if stopped {
                self.stop.store(true, Ordering::SeqCst);
            }
            self.switching.store(false, Ordering::SeqCst);
        }
        self.switch_decided.1.notify_all();
        stopped
    }
    /// With no request admitted any more, whether every one left is an
    /// account connection nothing uses, and all of those ended.
    fn stop_admitted_if_idle(&self) -> bool {
        // A request admitted before counts here. Every link is a request,
        // counted from before it registers until after it is gone, so the
        // links can only be fewer than the requests read before them.
        let requests = self.requests.load(Ordering::SeqCst);
        let links = self.account_links.counts();
        let pending = self
            .inner
            .lock()
            .unwrap()
            .profiles
            .values()
            .any(|profile| !profile.approvals.snapshots().is_empty());
        if pending || requests != links.open || links.idle != links.open {
            return false;
        }
        // They are re-established on their next use.
        let deadline = Instant::now() + ssh_auth::CLOSE_WAIT;
        if !self.account_links.close_idle(deadline) {
            return false;
        }
        // Their requests end with them; a request refused meanwhile is
        // counted for a moment too.
        let deadline = deadline + Duration::from_millis(200);
        while self.requests.load(Ordering::SeqCst) != 0 {
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        true
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
        let links = self.account_links.counts();
        let busy = self.busy();
        let inner = self.inner.lock().unwrap();
        Snapshot {
            build: crate::identity::build().into(),
            pid: std::process::id(),
            busy: Some(busy),
            accounts: Some(
                (self.account_relays.load(Ordering::Acquire) as usize).saturating_sub(links.idle),
            ),
            accounts_in_use: Some(links.in_use),
            started_from: self.started_from.clone(),
            switch: self.switch.lock().unwrap().clone(),
            stopping: self.stop.load(Ordering::SeqCst),
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
        // Before Hello, local clients and SSH-forwarded clients share this
        // socket. Allow network latency for Hello and the following Access;
        // keep the shorter budget for requests identified as local control.
        socket.set_read_timeout(Some(FORWARDED_HANDSHAKE_TIMEOUT))?;
        socket.set_write_timeout(Some(FORWARDED_HANDSHAKE_TIMEOUT))?;
        let mut handshake = crate::destination::DeadlineIo {
            inner: &mut stream,
            deadline: Instant::now() + FORWARDED_HANDSHAKE_TIMEOUT,
            cancelled: None,
        };
        let hello: Hello = crate::destination::read_message(&mut handshake)?;
        crate::destination::write_message(
            &mut handshake,
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
            socket.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
            socket.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;
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
                Control::StopIfIdle => {
                    self.stop_if_idle();
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
        let request: Access =
            crate::destination::read_message(&mut crate::destination::DeadlineIo {
                inner: &mut stream,
                deadline: Instant::now() + FORWARDED_HANDSHAKE_TIMEOUT,
                cancelled: None,
            })?;
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
                self.requests.fetch_add(1, Ordering::SeqCst);
                let _counted = Counted(&self.requests);
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
                        relaying: &self.account_relays,
                        links: &self.account_links,
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
                        SessionRequest::Forward(request) => {
                            // Ending the session shuts this request down.
                            let _tracked = tracked;
                            // A completed copy request has no more bytes:
                            // any, like the requester going, cancel it, so
                            // that trailing data cannot hide its going.
                            let cancelled = || {
                                self.stop.load(Ordering::Acquire)
                                    || session.closed.load(Ordering::Acquire)
                                    || crate::destination::requester_closed(&socket)
                            };
                            let settings = &session.profile.settings;
                            let requester = crate::receive_approval::Requester::provider_login(
                                &session.identity.user,
                                &settings.name,
                            );
                            crate::destination::forward::Approver {
                                origin: crate::destination::forward::Origin::Provider,
                                requester: &requester,
                                approvals: &session.profile.approvals,
                                notifications: settings.notifications,
                                caps: crate::directive::Caps {
                                    max_bytes: settings.max_bytes,
                                    max_entries: settings.max_entries,
                                    max_delete: settings.max_delete,
                                },
                                request_lock: &session.request_lock,
                                forward_count: &session.forward_count,
                                cancelled: &cancelled,
                            }
                            .approve(*request, &mut stream)
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
            !self.stop.load(Ordering::Acquire) && !self.switching.load(Ordering::SeqCst),
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
            forward_count: AtomicUsize::new(0),
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

/// Called only by explicit local receiving commands, never by an inbound SSH
/// helper.
pub(super) fn ensure(domain: &Domain) -> Result<()> {
    domain.ensure_runtime()?;
    if let Some(state) = running(domain, ANSWER_TIMEOUT, || Control::Status)? {
        if state.build == crate::identity::build() {
            return refresh(domain);
        }
        stop(domain)?;
    }
    start(domain)
}

/// Start this build's provider; one that starts meanwhile from this build
/// serves instead.
fn start(domain: &Domain) -> Result<()> {
    domain.ensure_runtime()?;
    let (mut startup, child_output) = crate::process::with_inheritance_guard(UnixStream::pair)?;
    startup.set_read_timeout(Some(STOP_TIMEOUT))?;
    let mut command = crate::process::self_command()?;
    // Its own switches are not a command's (`switch::STARTED_BY_COMMAND`).
    command
        .arg(INTERNAL)
        .arg(domain.runtime_path())
        .env_remove(super::switch::STARTED_BY_COMMAND);
    if let Some(path) = crate::process::started_from() {
        command.arg(path);
    }
    command
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
            // A simultaneous local receive-on may have started the owner, which
            // can hold the lock before it answers.
            if running(domain, ANSWER_TIMEOUT, || Control::Status)?
                .is_some_and(|state| state.build == crate::identity::build())
            {
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
    follower: Option<super::switch::Follower>,
}
impl Runtime {
    /// `started_from` is the path the user runs syq by, which the provider
    /// follows to switch to a new build (`switch`).
    fn new(domain: Domain, started_from: Option<PathBuf>) -> Result<Self> {
        let scope = domain.ensure_runtime()?;
        anyhow::ensure!(
            domain.enabled()? && preferences(&domain)?.enabled(),
            "receiving is off in this domain"
        );
        let lock = lock_for_start(|| acquire_lock(&domain, true))?
            .context("local SSH authorization provider is already running")?;
        // Only a UTF-8 path can be reported in a status.
        let follower = started_from
            .filter(|path| path.to_str().is_some())
            .map(super::switch::Follower::new);
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
            service: Arc::new(Service::new(
                domain,
                follower
                    .as_ref()
                    .and_then(|follower| follower.path().to_str())
                    .map(str::to_owned),
            )?),
            follower,
        })
    }
    fn run(&mut self) -> Result<()> {
        let (mut wake, sender) = crate::process::with_inheritance_guard(UnixStream::pair)?;
        wake.set_nonblocking(true)?;
        sender.set_nonblocking(true)?;
        let sender = Arc::new(sender);
        let _signals = SignalWake::new(self.service.stop.clone(), &sender)?;
        let (completed, completions) = std::sync::mpsc::channel();
        let mut workers = Vec::<std::thread::JoinHandle<()>>::new();
        let mut switch_args: Vec<OsString> = ["persist", "receive", SWITCH_PROVIDER]
            .into_iter()
            .map(OsString::from)
            .collect();
        if let Some(scope) = self.service.domain.explicit_path() {
            switch_args.extend([OsString::from("--pscope"), scope.into()]);
        }
        let result = (|| {
            while !self.service.stop.load(Ordering::Acquire) {
                // With a path to follow, wake when it is next due.
                let mut wait = -1;
                if let Some(follower) = &mut self.follower {
                    let service = &self.service;
                    follower.tick(&|| service.busy() == 0, &switch_args);
                    *service.switch.lock().unwrap() = follower.report();
                    wait = follower.due().as_millis().clamp(1, 60_000) as i32;
                }
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
                        wait_for_event(&self.listener, &mut wake, wait)?;
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
// An idle service reads no configuration periodically; following its path to
// a new build, it wakes every `timeout` milliseconds.
fn wait_for_event(listener: &UnixListener, wake: &mut UnixStream, timeout: i32) -> Result<()> {
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
    let result = unsafe { libc::poll(descriptors.as_mut_ptr(), descriptors.len() as _, timeout) };
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
        // The domain, and the path the user runs syq by (`switch`).
        anyhow::ensure!(
            (3..=4).contains(&argv.len()),
            "local provider service needs its persistence domain path"
        );
        crate::fsops::reserve_startup_descriptors();
        let runtime = Domain::select(Some(Path::new(&argv[2])))
            .and_then(|domain| Runtime::new(domain, argv.get(3).map(PathBuf::from)));
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
        let directory = crate::test_support::short_tempdir().unwrap();
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
        let service = Service::new(domain, None).unwrap();
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

    /// An approved account connection served by `service`, counted as the
    /// request it is, whose keeper answers each request with `reply`.
    fn account_link(
        service: &Arc<Service>,
        reply: impl Fn(ssh_auth::LinkRequest) -> ssh_auth::LinkReply + Send + 'static,
    ) -> (
        std::thread::JoinHandle<()>,
        std::thread::JoinHandle<()>,
        UnixStream,
    ) {
        let (mut ours, mut theirs) = UnixStream::pair().unwrap();
        let end = ours.try_clone().unwrap();
        service.requests.fetch_add(1, Ordering::SeqCst);
        let serving = service.clone();
        let server = std::thread::spawn(move || {
            let _counted = Counted(&serving.requests);
            let _ = serving.account_links.serve(&mut ours, &|| false);
        });
        let keeper = std::thread::spawn(move || {
            crate::agent_broker::read_frame(&mut theirs)
                .unwrap()
                .unwrap();
            while let Ok(Some(frame)) = crate::agent_broker::read_frame(&mut theirs) {
                let answer = reply(serde_json::from_slice(&frame).unwrap());
                let frame = serde_json::to_vec(&answer).unwrap();
                if crate::agent_broker::write_frame(&mut theirs, &frame).is_err() {
                    return;
                }
            }
        });
        (server, keeper, end)
    }
    fn wait_until(what: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !what() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    /// Waits until the link has said it is idle.
    fn reported_idle(service: &Service) {
        wait_until(|| service.account_links.idle() == 1);
    }

    /// An idle account connection does not hide another request running:
    /// the provider stops only once every request left is such a
    /// connection, and then ends it.
    #[test]
    fn an_idle_account_connection_does_not_hide_another_request() {
        let (_directory, domain, _) = fixture();
        let service = Arc::new(Service::new(domain, None).unwrap());
        let (server, keeper, end) = account_link(&service, |request| match request {
            ssh_auth::LinkRequest::Query => ssh_auth::LinkReply::Idle,
            ssh_auth::LinkRequest::CloseIfIdle => ssh_auth::LinkReply::Closing,
        });
        reported_idle(&service);
        // Another request, say one authorizing a login.
        service.requests.fetch_add(1, Ordering::SeqCst);
        let other = Counted(&service.requests);
        assert!(!service.stop_if_idle());
        assert!(!service.stop.load(Ordering::SeqCst));
        assert_eq!(service.account_links.len(), 1);
        service.admit().unwrap();
        drop(other);
        assert!(service.stop_if_idle());
        assert!(service.admit().is_err());
        server.join().unwrap();
        drop(end);
        keeper.join().unwrap();
        assert_eq!(service.requests.load(Ordering::SeqCst), 0);
        service.close();
    }

    /// Status counts an account connection that says it is idle as not
    /// keeping the provider; one in use, or one that cannot tell, keeps it,
    /// and only the first counts as in use.
    #[test]
    fn status_tells_idle_used_and_unknown_account_connections_apart() {
        for (reply, accounts, in_use) in [
            (ssh_auth::LinkReply::Idle, 0, 0),
            (ssh_auth::LinkReply::InUse, 1, 1),
            (ssh_auth::LinkReply::Unknown, 1, 0),
        ] {
            let (_directory, domain, _) = fixture();
            let service = Arc::new(Service::new(domain, None).unwrap());
            // Its relay, which the link continues.
            service.account_relays.fetch_add(1, Ordering::SeqCst);
            let (server, keeper, end) = account_link(&service, move |request| match request {
                ssh_auth::LinkRequest::CloseIfIdle if reply == ssh_auth::LinkReply::Idle => {
                    ssh_auth::LinkReply::Closing
                }
                _ => reply,
            });
            wait_until(|| {
                let links = service.account_links.counts();
                links.open == 1
                    && links.idle + links.in_use
                        == usize::from(reply != ssh_auth::LinkReply::Unknown)
                    && (reply != ssh_auth::LinkReply::Unknown || {
                        std::thread::sleep(Duration::from_millis(100));
                        true
                    })
            });
            let snapshot = service.snapshot(None);
            assert_eq!(
                (snapshot.accounts, snapshot.accounts_in_use),
                (Some(accounts), Some(in_use)),
                "{reply:?}"
            );
            let busy = snapshot.busy().unwrap();
            assert_eq!((busy.accounts, busy.accounts_in_use), (accounts, in_use));
            assert_eq!(service.stop_if_idle(), accounts == 0);
            drop(end.shutdown(std::net::Shutdown::Both));
            server.join().unwrap();
            keeper.join().unwrap();
        }
    }

    /// One stop attempt runs at a time. While it waits for an account
    /// connection's answer, another neither stops the provider nor admits
    /// requests again, and a new request waits; an answer that comes too
    /// late ends that connection but stops nothing, and the request goes
    /// ahead.
    #[test]
    fn stop_attempts_do_not_overlap() {
        let (_directory, domain, _) = fixture();
        let service = Arc::new(Service::new(domain, None).unwrap());
        let (answer, answering) = std::sync::mpsc::channel::<()>();
        let answering = Mutex::new(answering);
        let (server, keeper, end) = account_link(&service, move |request| match request {
            ssh_auth::LinkRequest::Query => ssh_auth::LinkReply::Idle,
            ssh_auth::LinkRequest::CloseIfIdle => {
                // Answer only when the test says so.
                answering.lock().unwrap().recv().unwrap();
                ssh_auth::LinkReply::Closing
            }
        });
        reported_idle(&service);
        let first = {
            let service = service.clone();
            std::thread::spawn(move || service.stop_if_idle())
        };
        wait_until(|| service.switching.load(Ordering::SeqCst));
        // A request meanwhile waits for the decision.
        let waiting = {
            let service = service.clone();
            std::thread::spawn(move || service.admit().is_ok())
        };
        assert!(!service.stop_if_idle());
        assert!(
            service.switching.load(Ordering::SeqCst),
            "the second attempt reopened admission"
        );
        // The first gives up waiting, and the request goes ahead.
        assert!(!first.join().unwrap());
        assert!(waiting.join().unwrap());
        service.admit().unwrap();
        service.requests.fetch_add(1, Ordering::SeqCst);
        let admitted = Counted(&service.requests);
        // The late answer ends the connection, and stops nothing.
        answer.send(()).unwrap();
        server.join().unwrap();
        drop(end);
        keeper.join().unwrap();
        assert!(!service.stop.load(Ordering::SeqCst));
        assert!(!service.stop_if_idle());
        drop(admitted);
        assert!(service.stop_if_idle());
        service.close();
    }

    /// The provider stops to switch builds only with no request in
    /// progress. A login attached to it, held open by its requester's
    /// keeper, does not keep it: the switch ends it and its session
    /// permissions, as a reconnect does, and the provider admits nothing
    /// once it decided to stop.
    #[test]
    fn a_provider_with_an_attached_login_stops_to_switch_when_no_request_runs() {
        let (_directory, domain, _) = fixture();
        let service = Arc::new(Service::new(domain, None).unwrap());
        let (ticket, session) = service.open_identified(None, identity).unwrap();
        session.grants.lock().unwrap().insert("account".into(), 0);
        // The keeper holds the attachment open.
        let (mut keeper, server) = pair(&service);
        let socket = server.try_clone().unwrap();
        let (thread_service, thread_session, expected) =
            (service.clone(), session.clone(), ticket.session.clone());
        let attachment = std::thread::spawn(move || {
            thread_service.hold_attachment(server, socket, ticket, thread_session)
        });
        let received: std::result::Result<Ticket, String> =
            crate::destination::read_message(&mut keeper).unwrap();
        assert_eq!(received.unwrap().session, expected);
        assert_eq!(service.busy(), 0);
        // A request through the attached login keeps it.
        service.requests.fetch_add(1, Ordering::SeqCst);
        assert_eq!(service.busy(), 1);
        assert!(!service.stop_if_idle());
        service.requests.fetch_sub(1, Ordering::SeqCst);
        assert!(service.stop_if_idle());
        assert!(service.snapshot(None).stopping);
        let error = service.open_identified(None, identity).err().unwrap();
        assert!(error.to_string().contains("stopping"), "{error}");
        // Stopping ends the attachment and its permissions.
        service.close();
        attachment.join().unwrap().unwrap();
        assert_eq!(keeper.read(&mut [0]).unwrap(), 0);
        assert!(session.closed.load(Ordering::Acquire));
        assert!(session.grants.lock().unwrap().is_empty());
    }

    #[test]
    fn forwarded_readiness_only_exchanges_hello_without_creating_authority() {
        let (_directory, domain, _) = fixture();
        let service = Arc::new(Service::new(domain, None).unwrap());
        let (client, server) = pair(&service);
        let serving = service.clone();
        let worker = std::thread::spawn(move || serving.handle(server));
        probe_forwarded(client, Instant::now() + Duration::from_secs(2), &|| false).unwrap();
        // The deliberate EOF occurs where an Access operation would start.
        let error = worker.join().unwrap().unwrap_err();
        assert!(error.chain().any(|cause| cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::UnexpectedEof)));
        let state = service.snapshot(None);
        assert!(state
            .profiles
            .iter()
            .all(|profile| profile.sessions == 0 && profile.pending.is_empty()));
        service.close();
    }

    #[test]
    fn forwarded_readiness_rejects_a_denied_or_unresponsive_channel() {
        let (client, server) = UnixStream::pair().unwrap();
        server.shutdown(std::net::Shutdown::Both).unwrap();
        let error = probe_forwarded(client, Instant::now() + Duration::from_secs(2), &|| false)
            .unwrap_err();
        assert!(error.to_string().contains("sshd permits local forwarding"));

        let (client, _silent_server) = UnixStream::pair().unwrap();
        let started = Instant::now();
        let error = probe_forwarded(client, Instant::now() + Duration::from_secs(2), &|| false)
            .unwrap_err();
        assert!(error.to_string().contains("provider service"));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn forwarded_readiness_allows_ssh_latency_and_obeys_cancellation() {
        let (client, mut server) = UnixStream::pair().unwrap();
        let responder = std::thread::spawn(move || {
            let _: Hello = crate::destination::read_message(&mut server).unwrap();
            // Longer than the local-only service timeout.
            std::thread::sleep(HANDSHAKE_TIMEOUT + Duration::from_millis(100));
            crate::destination::write_message(
                &mut server,
                &HelloReply {
                    version: PROTOCOL,
                    build: crate::identity::build().into(),
                },
            )
            .unwrap();
        });
        probe_forwarded(
            client,
            Instant::now() + FORWARDED_HANDSHAKE_TIMEOUT,
            &|| false,
        )
        .unwrap();
        responder.join().unwrap();

        let (client, _server) = UnixStream::pair().unwrap();
        let started = Instant::now();
        let error =
            probe_forwarded(client, started + FORWARDED_HANDSHAKE_TIMEOUT, &|| true).unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(error.chain().any(|cause| cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::ConnectionAborted)));
    }

    #[test]
    fn service_allows_forwarding_latency_before_hello_and_access() {
        let (_directory, domain, _) = fixture();
        let service = Arc::new(Service::new(domain, None).unwrap());
        let (mut client, server) = pair(&service);
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let worker = std::thread::spawn(move || service.handle(server));
        let mut hello = Vec::new();
        crate::destination::write_message(
            &mut hello,
            &Hello {
                version: PROTOCOL,
                build: crate::identity::build().into(),
                control: false,
            },
        )
        .unwrap();
        // A partial Hello and a request following the Hello response can
        // each arrive more than the local two-second budget apart over SSH.
        client.write_all(&hello[..2]).unwrap();
        std::thread::sleep(HANDSHAKE_TIMEOUT + Duration::from_millis(100));
        client.write_all(&hello[2..]).unwrap();
        let _: HelloReply = crate::destination::read_message(&mut client).unwrap();
        std::thread::sleep(HANDSHAKE_TIMEOUT + Duration::from_millis(100));
        crate::destination::write_message(
            &mut client,
            &Access::Attach {
                profile: Some("missing".into()),
            },
        )
        .unwrap();
        let reply: std::result::Result<Ticket, String> =
            crate::destination::read_message(&mut client).unwrap();
        assert!(reply.unwrap_err().contains("missing"));
        worker.join().unwrap().unwrap();
    }

    #[test]
    fn provider_build_mismatch_names_both_builds_and_says_the_provider_follows() {
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
        let error = probe_forwarded(client, Instant::now() + Duration::from_secs(2), &|| false)
            .unwrap_err();
        reply.join().unwrap();
        let error = format!("{error:#}");
        assert!(error.contains("provider-other-build"));
        assert!(error.contains(crate::identity::build()));
        assert!(error.contains("install the same syq build on the requester and provider"));
        assert!(error.contains("switches to it by itself once idle"));
    }

    #[test]
    fn build_is_checked_before_account_or_resolution_bytes_are_interpreted() {
        let (_directory, domain, _) = fixture();
        let service = Arc::new(Service::new(domain, None).unwrap());
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
        let service = Arc::new(Service::new(domain, None).unwrap());
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
        let service = Service::new(domain.clone(), None).unwrap();
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
        let service = Service::new(domain.clone(), None).unwrap();
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
        let service = Arc::new(Service::new(domain, None).unwrap());
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

    /// Each login's request for a copy between two other servers waits for
    /// its own decision, and the answer goes only to the login that asked:
    /// denying one leaves the other pending, and ending the other login's
    /// attachment ends its request unanswered.
    #[test]
    fn a_copy_decision_reaches_only_the_login_that_asked() {
        let (_directory, domain, _) = fixture();
        let service = Arc::new(Service::new(domain, None).unwrap());
        let ask = |output: &str| {
            let (ticket, session) = service.open_identified(None, identity).unwrap();
            let (mut client, server) = pair(&service);
            client
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let handler_service = service.clone();
            let handler = std::thread::spawn(move || handler_service.handle(server));
            crate::destination::write_message(
                &mut client,
                &Hello {
                    version: PROTOCOL,
                    build: crate::identity::build().into(),
                    control: false,
                },
            )
            .unwrap();
            let _: HelloReply = crate::destination::read_message(&mut client).unwrap();
            let command = [
                "cp",
                "--from",
                "reader@source-host",
                "--srcs-in",
                "data",
                "--to",
                "backup",
                "--into",
                output,
            ]
            .map(|arg| arg.as_bytes().to_vec())
            .to_vec();
            crate::destination::write_message(
                &mut client,
                &Access::Request {
                    session: ticket.session,
                    operation: Box::new(SessionRequest::Forward(Box::new(
                        crate::destination::forward::ForwardRequest {
                            source: Some("reader@source-host".into()),
                            target: "backup".into(),
                            command,
                            cwd: "~".into(),
                            inputs: crate::directive::Inputs::default(),
                            results_key: Some([5; 32]),
                        },
                    ))),
                },
            )
            .unwrap();
            (session, client, handler)
        };
        let (first_session, mut first, first_handler) = ask("first-output");
        let (second_session, mut second, second_handler) = ask("second-output");
        let pending = || {
            service
                .snapshot(None)
                .profiles
                .iter()
                .flat_map(|profile| profile.pending.clone())
                .collect::<Vec<_>>()
        };
        wait_until(|| pending().len() == 2);
        let describe = |summary: &crate::receive_approval::Summary| {
            summary.description(&Domain::default(), str::to_owned)
        };
        let requests = pending();
        let first_request = requests
            .iter()
            .find(|summary| describe(summary).contains("first-output"))
            .unwrap();
        for summary in &requests {
            assert!(describe(summary).contains("syq can't confirm which server is asking"));
        }
        first_session
            .profile
            .approvals
            .decide(
                &first_request.id,
                false,
                crate::receive_approval::Kind::Copy,
            )
            .unwrap();
        let reply: serde_json::Value = crate::destination::read_message(&mut first).unwrap();
        assert!(reply.get("Error").is_some(), "{reply}");
        first_handler.join().unwrap().unwrap();
        // The other login's request is untouched.
        let left = pending();
        assert_eq!(left.len(), 1);
        assert!(describe(&left[0]).contains("second-output"));
        second_session.close();
        let reply = crate::destination::read_message::<serde_json::Value>(&mut second);
        assert!(
            reply
                .as_ref()
                .map_or(true, |reply| reply.get("Directive").is_none()),
            "{reply:?}"
        );
        // Closing the session shut its socket, so no reply may reach it.
        let _ = second_handler.join().unwrap();
        wait_until(|| pending().is_empty());
        assert_eq!(service.requests.load(Ordering::SeqCst), 0);
        service.close();
    }

    /// A copy request has nothing after it: a byte that follows cancels it,
    /// as the requester going does, so it cannot hide the requester going
    /// while its login stays attached.
    #[test]
    fn data_after_a_copy_request_cancels_it() {
        let (_directory, domain, _) = fixture();
        let service = Arc::new(Service::new(domain, None).unwrap());
        let (ticket, _session) = service.open_identified(None, identity).unwrap();
        let (mut client, server) = pair(&service);
        client
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let handler_service = service.clone();
        let handler = std::thread::spawn(move || handler_service.handle(server));
        crate::destination::write_message(
            &mut client,
            &Hello {
                version: PROTOCOL,
                build: crate::identity::build().into(),
                control: false,
            },
        )
        .unwrap();
        let _: HelloReply = crate::destination::read_message(&mut client).unwrap();
        let command = [
            "cp",
            "--from",
            "reader@source-host",
            "--srcs-in",
            "data",
            "--to",
            "backup",
            "--into",
            "output",
        ]
        .map(|arg| arg.as_bytes().to_vec())
        .to_vec();
        crate::destination::write_message(
            &mut client,
            &Access::Request {
                session: ticket.session,
                operation: Box::new(SessionRequest::Forward(Box::new(
                    crate::destination::forward::ForwardRequest {
                        source: Some("reader@source-host".into()),
                        target: "backup".into(),
                        command,
                        cwd: "~".into(),
                        inputs: crate::directive::Inputs::default(),
                        results_key: Some([5; 32]),
                    },
                ))),
            },
        )
        .unwrap();
        client.write_all(b"x").unwrap();
        // Refused without a decision; the login stays attached.
        let reply: serde_json::Value = crate::destination::read_message(&mut client).unwrap();
        assert!(reply.get("Error").is_some(), "{reply}");
        handler.join().unwrap().unwrap();
        assert!(service
            .snapshot(None)
            .profiles
            .iter()
            .all(|profile| profile.pending.is_empty()));
        assert_eq!(service.requests.load(Ordering::SeqCst), 0);
        service.close();
    }

    #[test]
    fn idle_runtime_stops_on_control_event_without_a_timer() {
        let (_directory, domain, _) = fixture();
        let mut runtime = Runtime::new(domain.clone(), None).unwrap();
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
        let service = Service::new(domain.clone(), None).unwrap();
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
        let first = Runtime::new(first_domain.clone(), None).unwrap();
        let second = Runtime::new(second_domain.clone(), None).unwrap();
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

    /// Model a provider another process is starting: it holds the lock, and
    /// 100 ms after `go` it binds its socket and makes it private. With
    /// `exposed`, the socket already exists before then but is not private.
    /// Then it answers `answers` connections.
    fn starting_provider(
        domain: &Domain,
        exposed: bool,
        answers: usize,
    ) -> (std::thread::JoinHandle<()>, std::sync::mpsc::Sender<()>) {
        let (go, started) = std::sync::mpsc::channel();
        let lock = acquire_lock(domain, true).unwrap().unwrap();
        let domain = domain.clone();
        let path = domain.runtime_path().join(SOCKET_FILE);
        let early = exposed.then(|| {
            let listener = UnixListener::bind(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
            listener
        });
        let provider = std::thread::spawn(move || {
            let _lock = lock;
            started.recv_timeout(Duration::from_secs(10)).unwrap();
            std::thread::sleep(Duration::from_millis(100));
            let listener = early.unwrap_or_else(|| UnixListener::bind(&path).unwrap());
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            listener.set_nonblocking(true).unwrap();
            let service = Service::new(domain, None).unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            for _ in 0..answers {
                let stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < deadline, "no provider query arrived");
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Err(error) => panic!("{error}"),
                    }
                };
                stream.set_nonblocking(false).unwrap();
                service
                    .handle(service.streams.track(stream).unwrap())
                    .unwrap();
            }
        });
        (provider, go)
    }

    #[test]
    fn refresh_waits_until_a_starting_provider_socket_is_private() {
        let (_directory, domain, _) = fixture();
        let (provider, go) = starting_provider(&domain, true, 1);
        assert!(matches!(
            connect(&domain, true).unwrap_err().downcast_ref(),
            Some(NotYetPrivate)
        ));
        go.send(()).unwrap();
        refresh(&domain).unwrap();
        provider.join().unwrap();
    }

    #[test]
    fn losing_a_start_race_waits_for_the_owner_to_answer() {
        let (_directory, domain, _) = fixture();
        // The losing receive-on finds the owner's lock held but no socket yet.
        let (provider, go) = starting_provider(&domain, false, 2);
        go.send(()).unwrap();
        let state = running(&domain, ANSWER_TIMEOUT, || Control::Status)
            .unwrap()
            .unwrap();
        assert_eq!(state.build, crate::identity::build());
        refresh(&domain).unwrap();
        provider.join().unwrap();
    }

    #[test]
    fn a_provider_that_never_answers_fails_within_its_bound() {
        let (_directory, domain, _) = fixture();
        let _lock = acquire_lock(&domain, true).unwrap().unwrap();
        let started = Instant::now();
        let Err(error) = running(&domain, Duration::from_millis(200), || Control::Status) else {
            panic!("a provider that never answered was reported");
        };
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_millis(200) && elapsed < Duration::from_secs(5),
            "{elapsed:?}"
        );
        let message = format!("{error:#}");
        assert!(
            message.starts_with("SSH authorization provider is running but not answering in "),
            "{message}"
        );
    }

    #[test]
    fn a_starting_provider_waits_out_a_status_probe_before_giving_up() {
        let (_directory, domain, _) = fixture();
        let _owner = acquire_lock(&domain, true).unwrap().unwrap();
        let started = Instant::now();
        let error = Runtime::new(domain.clone(), None).err().unwrap();
        assert!(started.elapsed() >= PROBE_GRACE, "{:?}", started.elapsed());
        assert!(error.to_string().contains("already running"), "{error:#}");
    }

    /// A provider of build `build` with process `pid`, holding `lock`,
    /// answering status, stop, and stop if idle, which it agrees to unless
    /// `busy`. Once it stops, it removes its socket and passes its lock to
    /// `then`, which drops it or hands it to a successor. Returns the
    /// requests it received.
    fn stand_in_provider(
        domain: &Domain,
        lock: Lock,
        build: &'static str,
        pid: u32,
        busy: usize,
        then: impl FnOnce(Lock) + Send + 'static,
    ) -> std::thread::JoinHandle<Vec<&'static str>> {
        let path = domain.runtime_path().join(SOCKET_FILE);
        let listener = UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        listener.set_nonblocking(true).unwrap();
        std::thread::spawn(move || {
            let mut seen = Vec::new();
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let mut stream = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "provider kept running: {seen:?}");
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => panic!("{error}"),
                };
                stream.set_nonblocking(false).unwrap();
                let _: Hello = crate::destination::read_message(&mut stream).unwrap();
                crate::destination::write_message(
                    &mut stream,
                    &HelloReply {
                        version: PROTOCOL,
                        build: build.into(),
                    },
                )
                .unwrap();
                let stopping = match crate::destination::read_message(&mut stream).unwrap() {
                    Control::Status => {
                        seen.push("status");
                        false
                    }
                    Control::Stop => {
                        seen.push("stop");
                        true
                    }
                    Control::StopIfIdle => {
                        seen.push("stop if idle");
                        busy == 0
                    }
                    Control::Refresh | Control::Decide(_) => panic!("unexpected request"),
                };
                let reply = Snapshot {
                    build: build.into(),
                    pid,
                    profiles: Vec::new(),
                    decision_error: None,
                    busy: Some(busy),
                    accounts: None,
                    accounts_in_use: None,
                    started_from: None,
                    switch: None,
                    stopping,
                };
                crate::destination::write_framed(
                    &mut stream,
                    &reply,
                    MAX_STATUS,
                    "provider status",
                )
                .unwrap();
                if stopping {
                    // Like a provider, remove the socket before the lock.
                    fs::remove_file(&path).unwrap();
                    then(lock);
                    return seen;
                }
            }
        })
    }

    /// Once a provider agreed to stop, another may start before the switch
    /// sees the lock free. That one is never sent a stop: the switch waits
    /// only for the provider that agreed, then looks at the next one, which
    /// is busy and keeps running.
    #[test]
    fn a_provider_that_takes_over_after_one_agreed_to_stop_is_not_stopped() {
        let (_directory, domain, _) = fixture();
        let successor = Arc::new(Mutex::new(None));
        let (started, next) = (successor.clone(), domain.clone());
        // The process that agreed lives on after it gives up the lock, as
        // this test's own does; the next one is another. It takes the lock
        // as the first lets go, before a probe of the switch could.
        let lock = acquire_lock(&domain, true).unwrap().unwrap();
        let first = stand_in_provider(
            &domain,
            lock,
            "v0.0.1+first",
            std::process::id(),
            0,
            move |lock| {
                *started.lock().unwrap() =
                    Some(stand_in_provider(&next, lock, "v0.0.1+next", 2222, 1, drop));
            },
        );
        switch_when_idle(&domain).unwrap();
        assert_eq!(first.join().unwrap(), ["status", "stop if idle"]);
        let next = successor.lock().unwrap().take().unwrap();
        assert!(is_running(&domain).unwrap());
        query(&domain, Control::Stop).unwrap();
        let seen = next.join().unwrap();
        assert!(!seen[..seen.len() - 1].contains(&"stop"), "{seen:?}");
        assert_eq!(seen.last(), Some(&"stop"));
    }

    /// A provider from an older build: it answers status and stop, and rejects
    /// a refresh by closing the connection, as one that cannot parse newer
    /// settings does. Returns the requests it received.
    fn other_build_provider(domain: &Domain) -> std::thread::JoinHandle<Vec<&'static str>> {
        const OTHER: &str = "v0.0.1+other";
        let lock = acquire_lock(domain, true).unwrap().unwrap();
        let path = domain.runtime_path().join(SOCKET_FILE);
        let listener = UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        listener.set_nonblocking(true).unwrap();
        std::thread::spawn(move || {
            let mut lock = Some(lock);
            let mut seen = Vec::new();
            let deadline = Instant::now() + Duration::from_secs(10);
            while lock.is_some() {
                let mut stream = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            Instant::now() < deadline,
                            "provider was not stopped: {seen:?}"
                        );
                        std::thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                    Err(error) => panic!("{error}"),
                };
                stream.set_nonblocking(false).unwrap();
                let _: Hello = crate::destination::read_message(&mut stream).unwrap();
                crate::destination::write_message(
                    &mut stream,
                    &HelloReply {
                        version: PROTOCOL,
                        build: OTHER.into(),
                    },
                )
                .unwrap();
                // As a provider from before syq followed updates answers.
                let reply = Snapshot {
                    build: OTHER.into(),
                    pid: 1,
                    profiles: Vec::new(),
                    decision_error: None,
                    busy: None,
                    accounts: None,
                    accounts_in_use: None,
                    started_from: None,
                    switch: None,
                    stopping: false,
                };
                match crate::destination::read_message(&mut stream).unwrap() {
                    Control::Status => seen.push("status"),
                    Control::Refresh => {
                        seen.push("refresh");
                        continue;
                    }
                    Control::Stop => {
                        seen.push("stop");
                        lock = None;
                    }
                    Control::Decide(_) => panic!("unexpected decision"),
                    Control::StopIfIdle => panic!("an older provider cannot read this"),
                }
                crate::destination::write_framed(
                    &mut stream,
                    &reply,
                    MAX_STATUS,
                    "provider status",
                )
                .unwrap();
            }
            seen
        })
    }

    #[test]
    fn a_provider_from_another_build_is_stopped_instead_of_refreshed() {
        let (_directory, domain, _) = fixture();
        let old = other_build_provider(&domain);
        assert!(stop_other_build(&domain).unwrap());
        assert_eq!(old.join().unwrap(), ["status", "stop"]);
        assert!(!is_running(&domain).unwrap());
        assert!(!stop_other_build(&domain).unwrap());
    }
}

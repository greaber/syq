//! Explicit destination-account authorization over an authenticated return channel.
use super::*;
use crate::agent_broker::{BrokerPolicy, ConstrainedAgentBroker, HostPolicy};
use crate::auth_from::Provider;
use crate::cli::NativeEndpoint;
use crate::persistence::Domain;
use crate::receive_approval::provider_accounts::{ProviderIdentity, ProviderLoginPermission};
use crate::receive_approval::{AccountDecision, AccountIdentity, AccountPermission, Queue};

const HOST_ALIAS: &str = "syq-approved-peer";
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(30);

/// A setup refusal that can clear without changing the approved authority.
#[derive(Debug)]
pub(crate) struct RetryableSetupError(pub(crate) String);
impl std::fmt::Display for RetryableSetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for RetryableSetupError {}

/// Only transport uncertainty and explicit temporary refusals justify another
/// setup attempt. Validation and protocol failures cannot improve on retry.
pub(crate) fn retryable_setup_error(error: &anyhow::Error) -> bool {
    if super::peer_bridge::is_setup_refusal(error) {
        return false;
    }
    error.chain().any(|cause| {
        cause.is::<RetryableSetupError>()
            || cause.downcast_ref::<std::io::Error>().is_some_and(|error| {
                // Synthetic ConnectionAborted marks deliberate cancellation;
                // the actual OS connection-aborted error is a transport failure.
                matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::Interrupted
                        | std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::UnexpectedEof
                ) || error.raw_os_error() == Some(libc::ECONNABORTED)
            })
    })
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum Mode {
    #[default]
    Once,
    Persistent,
    /// Reusable destination-account approval; the shown command is context only.
    Account,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    #[serde(default)]
    mode: Mode,
    target: NativeEndpoint,
    command: Vec<Vec<u8>>,
    cwd: String,
    #[serde(default)]
    expected: Option<ResolvedPolicy>,
}

impl Request {
    pub(crate) fn account(
        target: NativeEndpoint,
        command: Vec<Vec<u8>>,
        cwd: String,
        expected: Option<ResolvedPolicy>,
    ) -> Self {
        Self {
            mode: Mode::Account,
            target,
            command,
            cwd,
            expected,
        }
    }

    fn validate(&self, origin: &AuthorizationOrigin<'_>) -> Result<()> {
        if self.command.len() > 256 || self.command.iter().map(Vec::len).sum::<usize>() > 16 * 1024
        {
            bail!("SSH approval command exceeds its limits");
        }
        ssh::validate_endpoint(&self.target)?;
        if let Some(expected) = &self.expected {
            expected.validate()?;
        }
        if self.mode == Mode::Account {
            // The account is authoritative. Command text only describes intent.
            return Ok(());
        }
        let AuthorizationOrigin::Return { profile, .. } = origin else {
            bail!("SSH providers require an account authorization request");
        };
        let command: Vec<OsString> = self
            .command
            .iter()
            .cloned()
            .map(OsString::from_vec)
            .collect();
        let parsed = match self.mode {
            Mode::Once => {
                if command.first().is_none_or(|arg| arg != "ssh") {
                    bail!("SSH approval needs the requesting syq ssh command");
                }
                ssh::parse_for_approval(&command, profile)?
            }
            Mode::Persistent => crate::persistence::parse_account_connect(&command, profile)?,
            Mode::Account => unreachable!(),
        };
        if parsed.destination != self.target
            || parsed.provider != Provider::Return((*profile).into())
        {
            bail!("SSH destination or authorizer does not match the shown command");
        }
        Ok(())
    }
}

/// The requester selects the connection route; the provider independently
/// looks up trust by the original alias (or the explicit HostKeyAlias). No
/// requester-supplied host key can become authorization policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LocalTarget {
    requested: NativeEndpoint,
    endpoint: NativeEndpoint,
    host_key_alias: Option<String>,
}

impl LocalTarget {
    fn from_plan(plan: &ssh::local_config::LocalPlan) -> Result<Self> {
        plan.validate()?;
        let target = Self {
            requested: plan.requested.clone(),
            endpoint: plan.endpoint.clone(),
            host_key_alias: plan.host_key_alias.clone(),
        };
        target.validate()?;
        Ok(target)
    }

    fn validate(&self) -> Result<()> {
        ssh::validate_endpoint(&self.requested)?;
        ssh::validate_endpoint(&self.endpoint)?;
        anyhow::ensure!(
            self.endpoint.user.is_some() && self.endpoint.port.is_some(),
            "requester SSH configuration must select an explicit account and port"
        );
        if let Some(alias) = &self.host_key_alias {
            ssh::validate_host_key_alias(alias)?;
        }
        Ok(())
    }

    fn trust_name(&self) -> &str {
        self.host_key_alias
            .as_deref()
            .unwrap_or(&self.requested.host)
    }

    fn trust_port(&self) -> Option<u16> {
        // A port written in the target is part of that trust name. A port
        // obtained from requester configuration belongs only to its route.
        if self.host_key_alias.is_some() {
            None
        } else {
            self.requested.port
        }
    }
}

/// A distinct, build-pinned request keeps legacy provider-selected requests
/// and their persisted permissions readable without changing their meaning.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LocalRequest {
    target: LocalTarget,
    command: Vec<Vec<u8>>,
    cwd: String,
    expected: ResolvedPolicy,
    /// Worker logins may consume existing authority, but never ask for more.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    existing_account_only: bool,
}

impl LocalRequest {
    fn into_request(self) -> Result<(Request, LocalTarget, bool)> {
        self.target.validate()?;
        anyhow::ensure!(
            self.expected.endpoint == self.target.endpoint,
            "SSH approval expectation does not match the requester-selected account"
        );
        Ok((
            Request::account(
                self.target.endpoint.clone(),
                self.command,
                self.cwd,
                Some(self.expected),
            ),
            self.target,
            self.existing_account_only,
        ))
    }
}

/// Identity established by the transport adapter, never supplied by the
/// authorization request. Native provider logins do not prove a source host.
pub(crate) enum AuthorizationOrigin<'a> {
    Return {
        profile: &'a str,
        requester: &'a crate::receive_approval::Requester,
        source: &'a Mutex<std::result::Result<AccountIdentity, String>>,
    },
    Provider {
        profile: &'a str,
        identity: &'a ProviderIdentity,
    },
}

/// Borrowed state of one live authorization session. Its transport adapter
/// owns generation changes, stream shutdown and clearing session grants on
/// disconnect; a provider must not share these grants across unrelated logins.
pub(crate) struct AuthorizationContext<'a> {
    pub(crate) origin: AuthorizationOrigin<'a>,
    pub(crate) approvals: &'a Queue,
    pub(crate) notifications: crate::receive_approval::Notifications,
    pub(crate) request_lock: &'a Mutex<()>,
    pub(crate) active_count: &'a AtomicU64,
    pub(crate) session_grants: &'a Mutex<HashMap<String, u64>>,
}

/// Public connection metadata, not an authorization grant. The provider must
/// resolve its own trusted policy again before approving a new account login.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResolvedPolicy {
    pub(crate) endpoint: NativeEndpoint,
    pub(crate) host_algorithms: String,
    pub(crate) known_hosts: String,
}

impl ResolvedPolicy {
    pub(crate) fn new(
        endpoint: NativeEndpoint,
        known_hosts: &str,
        host_algorithms: &str,
    ) -> Result<Self> {
        let mut resolved = Self {
            endpoint,
            host_algorithms: host_algorithms.into(),
            known_hosts: known_hosts.into(),
        };
        resolved.validate()?;
        // Pin order and comments do not change trust. Both account and copy
        // peers use this representation when comparing selected resolutions.
        let mut lines = Vec::new();
        for line in known_hosts.lines() {
            let (_, key) = line.split_once(' ').context("invalid approved host key")?;
            let key = ssh_key::PublicKey::from_openssh(key)?;
            let key = ssh_key::PublicKey::new(key.key_data().clone(), "");
            lines.push(format!("{HOST_ALIAS} {}\n", key.to_openssh()?));
        }
        lines.sort_unstable();
        lines.dedup();
        resolved.known_hosts = lines.concat();
        Ok(resolved)
    }

    fn from_policy(policy: &HostPolicy) -> Result<Self> {
        Self::new(
            NativeEndpoint {
                user: Some(policy.login_user.clone()),
                host: policy.connection_host().into(),
                port: Some(policy.port()),
            },
            &policy.known_hosts(HOST_ALIAS)?,
            &policy.host_key_algorithms(),
        )
    }

    pub(crate) fn from_peer(peer: &super::forward::ssh::Peer) -> Result<Self> {
        peer.resolved_policy()
    }

    pub(crate) fn validate(&self) -> Result<()> {
        ssh::validate_endpoint(&self.endpoint)?;
        self.peer()?;
        Ok(())
    }

    pub(crate) fn peer(&self) -> Result<super::forward::ssh::Peer> {
        super::forward::ssh::Peer::from_approved(
            &self.endpoint,
            &self.known_hosts,
            &self.host_algorithms,
        )
    }

    fn check_expected(&self, expected: Option<&Self>) -> Result<()> {
        if let Some(expected) = expected {
            let expected = Self::new(
                expected.endpoint.clone(),
                &expected.known_hosts,
                &expected.host_algorithms,
            )?;
            anyhow::ensure!(
                *self == expected,
                "SSH provider configuration changed since this destination was resolved; retry the command"
            );
        }
        Ok(())
    }
}

/// One approved native SSH login. Keep the return channel alive until SSH exits,
/// including after OpenSSH closes its authentication-agent connection.
pub(crate) struct Session {
    stream: UnixStream,
    _broker: PrivateBroker,
    endpoint: NativeEndpoint,
    peer: super::forward::ssh::Peer,
    options: Vec<OsString>,
}

impl Session {
    pub(crate) fn endpoint(&self) -> &NativeEndpoint {
        &self.endpoint
    }

    pub(crate) fn peer(&self) -> &super::forward::ssh::Peer {
        &self.peer
    }

    pub(crate) fn options(&self) -> Vec<OsString> {
        self.options.clone()
    }

    pub(crate) fn cancelled(&self) -> bool {
        disconnected(&self.stream)
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
    // Authentication replies belong to the agent relay. Peeking must neither
    // consume them nor mistake a pending reply for session cancellation.
    result == 0
        || (result < 0
            && !matches!(
                std::io::Error::last_os_error().kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            ))
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
        // Closing the stream wakes any agent request before broker drop joins it.
    }
}

pub(crate) fn prepare(request: &ssh::SessionRequest) -> Result<()> {
    request.provider.validate()?;
    let Provider::Return(name) = &request.provider else {
        return Ok(());
    };
    let registration = read_registration(name)?;
    // The fast path reads only local state. Resolve and authorization still
    // authenticate the provider before trusting metadata or signing.
    let registration = if registration.identity == crate::identity::build() {
        registration
    } else {
        load_registration(name)?
    };
    let selection =
        handoff::Selection::new(name.clone(), registration, handoff::Kind::Account, None);
    handoff::maybe_exec(&selection)
}

pub(in crate::destination) fn registration_binding(registration: &Registration) -> Result<String> {
    Ok(blake3::hash(&serde_json::to_vec(registration)?)
        .to_hex()
        .to_string())
}

pub(crate) fn local_binding(domain: &Domain, provider: &Provider) -> Result<Option<String>> {
    provider.validate()?;
    match provider {
        Provider::Return(name) => read_existing_registration(name)?
            .map(|registration| registration_binding(&registration))
            .transpose(),
        Provider::Ssh { .. } => ssh::provider::local_binding(domain, provider),
    }
}

pub(crate) struct Resolved {
    pub(crate) binding: String,
    pub(crate) policy: ResolvedPolicy,
}

/// Metadata is returned together with the authenticated connection that
/// resolved it. Neither operation grants destination account access.
pub(crate) fn resolve(
    domain: &Domain,
    request: &ssh::SessionRequest,
    local: &ssh::local_config::LocalPlan,
) -> Result<Resolved> {
    let target = LocalTarget::from_plan(local)?;
    anyhow::ensure!(
        target.requested == request.destination,
        "SSH local plan target changed"
    );
    request.provider.validate()?;
    ssh::validate_endpoint(&request.destination)?;
    let (binding, mut stream, reply) = match &request.provider {
        Provider::Return(name) => {
            let registration = load_registration(name)?;
            let binding = registration_binding(&registration)?;
            let (stream, reply) = exchange(
                &registration,
                Message::ResolveLocalSsh(target.clone()),
                RESOLVE_TIMEOUT,
                Some(RESOLVE_TIMEOUT),
            )?;
            (binding, stream, reply)
        }
        Provider::Ssh { .. } => {
            let binding = ssh::provider::resolve_connection(domain, &request.provider)?;
            let mut stream = ssh::provider::open(
                domain,
                &request.provider,
                &binding,
                crate::receive_service::provider::SessionRequest::ResolveLocal(target.clone()),
            )?;
            let reply = read_message(&mut DeadlineSocket {
                socket: &mut stream,
                deadline: Instant::now() + RESOLVE_TIMEOUT,
            })?;
            (binding, stream, reply)
        }
    };
    match reply {
        Reply::Ready => {}
        Reply::Error(message) => bail!(message),
        Reply::RetryableError(message) => return Err(RetryableSetupError(message).into()),
        _ => bail!("unexpected SSH resolution response"),
    }
    let resolved: ResolvedPolicy = read_message(&mut DeadlineSocket {
        socket: &mut stream,
        deadline: Instant::now() + RESOLVE_TIMEOUT,
    })?;
    anyhow::ensure!(
        resolved.endpoint == target.endpoint,
        "SSH provider returned a different account than the requester selected"
    );
    Ok(Resolved {
        binding,
        policy: ResolvedPolicy::new(
            resolved.endpoint,
            &resolved.known_hosts,
            &resolved.host_algorithms,
        )?,
    })
}

pub(crate) fn authorize_expected(
    domain: &Domain,
    request: &ssh::SessionRequest,
    command: Vec<Vec<u8>>,
    provider_binding: &str,
    expected: &ResolvedPolicy,
    local: &ssh::local_config::LocalPlan,
) -> Result<Session> {
    authorize_expected_inner(
        domain,
        request,
        command,
        provider_binding,
        expected,
        local,
        false,
    )
}

pub(crate) fn authorize_worker_expected(
    domain: &Domain,
    request: &ssh::SessionRequest,
    command: Vec<Vec<u8>>,
    provider_binding: &str,
    expected: &ResolvedPolicy,
    local: &ssh::local_config::LocalPlan,
) -> Result<Session> {
    authorize_expected_inner(
        domain,
        request,
        command,
        provider_binding,
        expected,
        local,
        true,
    )
}

fn authorize_expected_inner(
    domain: &Domain,
    request: &ssh::SessionRequest,
    command: Vec<Vec<u8>>,
    provider_binding: &str,
    expected: &ResolvedPolicy,
    local: &ssh::local_config::LocalPlan,
    existing_account_only: bool,
) -> Result<Session> {
    let target = LocalTarget::from_plan(local)?;
    anyhow::ensure!(
        target.requested == request.destination,
        "SSH local plan target changed"
    );
    anyhow::ensure!(
        expected.endpoint == target.endpoint,
        "SSH local configuration changed; retry the command"
    );
    request.provider.validate()?;
    expected.validate()?;
    let algorithms = local.intersect_host_algorithms(&expected.host_algorithms)?;
    crate::conn::require_constrained_openssh("ssh", "on this machine")?;
    let operation = LocalRequest {
        target,
        command,
        cwd: crate::approval_command::current_directory(),
        expected: expected.clone(),
        existing_account_only,
    };
    if !existing_account_only {
        crate::output::diagnostic!(
            "syq: requesting SSH account access from {}; approve on that machine",
            request.provider.label()
        );
    }
    let (mut stream, reply) = match &request.provider {
        Provider::Return(name) => {
            let registration = load_registration(name)?;
            anyhow::ensure!(registration_binding(&registration)? == provider_binding,
                "SSH authorization provider changed since this destination was resolved; retry the command");
            anyhow::ensure!(
                registration.identity == crate::identity::build(),
                "receiving connection changed while starting the SSH login; retry the command"
            );
            exchange(
                &registration,
                Message::LocalSsh(operation),
                REQUEST_TIMEOUT + Duration::from_secs(30),
                Some(Duration::from_secs(120)),
            )?
        }
        Provider::Ssh { .. } => {
            let mut stream = ssh::provider::open(
                domain,
                &request.provider,
                provider_binding,
                crate::receive_service::provider::SessionRequest::LocalAccount(operation),
            )?;
            let reply = read_message(&mut stream)?;
            (stream, reply)
        }
    };
    match reply {
        Reply::Ready => {}
        Reply::Error(message) => bail!(message),
        Reply::RetryableError(message) => return Err(RetryableSetupError(message).into()),
        _ => bail!("unexpected SSH approval response"),
    }
    let approved: ResolvedPolicy = read_message(&mut stream)?;
    approved.validate()?;
    approved.check_expected(Some(expected))?;
    request.ssh_arguments(&approved.endpoint)?;
    let channel = Mutex::new(Some(stream.try_clone()?));
    let broker = PrivateBroker::start_managed(
        PrivateBrokerConfig {
            directory_prefix: "syq-ssh-",
            socket_name: "agent",
            listener_thread: "syq-ssh-agent",
            client_thread: "syq-ssh-sign",
            inline_on_thread_failure: false,
            max_connections: 1,
            io_timeout: Duration::from_secs(120),
        },
        move |mut local, registry| {
            let Some(remote) = channel.lock().unwrap().take() else {
                return;
            };
            if let Ok(mut remote) = registry.track(remote) {
                let _ = crate::agent_broker::relay_frames(&mut local, &mut remote);
            }
        },
    )?;
    let known_hosts = broker.socket_path().with_file_name("known_hosts");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&known_hosts)?;
    file.write_all(session_known_hosts(&approved, local)?.as_bytes())?;
    let options = ssh_options(
        broker.socket_path(),
        &known_hosts,
        &algorithms,
        local.host_key_alias.as_deref(),
    )?;
    Ok(Session {
        stream,
        _broker: broker,
        peer: approved.peer()?,
        endpoint: approved.endpoint,
        options,
    })
}

/// Serialized policies use a canonical label for equality. The native client
/// must use its own lookup name so HostKeyAlias and %k keep their SSH meaning.
fn session_known_hosts(
    approved: &ResolvedPolicy,
    local: &ssh::local_config::LocalPlan,
) -> Result<String> {
    local.validate()?;
    anyhow::ensure!(
        approved.endpoint == local.endpoint,
        "SSH session host-key policy changed its endpoint"
    );
    let label = local.host_key_alias.clone().unwrap_or_else(|| {
        if local.endpoint.port == Some(22) {
            local.endpoint.host.clone()
        } else {
            format!("[{}]:{}", local.endpoint.host, local.endpoint.port.unwrap())
        }
    });
    let mut hosts = String::new();
    for line in approved.known_hosts.lines() {
        let (_, key) = line.split_once(' ').context("invalid approved host key")?;
        hosts.push_str(&label);
        hosts.push(' ');
        hosts.push_str(key);
        hosts.push('\n');
    }
    Ok(hosts)
}

fn ssh_options(
    agent: &Path,
    known_hosts: &Path,
    algorithms: &str,
    host_key_alias: Option<&str>,
) -> Result<Vec<OsString>> {
    let agent = agent.to_str().context("agent socket path is not UTF-8")?;
    let known_hosts = known_hosts
        .to_str()
        .context("known-hosts path is not UTF-8")?;
    // OpenSSH expands configuration tokens even in command-line values. A
    // surprising temporary-directory spelling must fail instead of changing
    // the authentication socket or trusted host file.
    for path in [agent, known_hosts] {
        if !path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-+:@,=".contains(&b))
        {
            bail!(
                "SSH authorization requires a temporary-directory path without whitespace or SSH expansion tokens"
            );
        }
    }
    if algorithms.is_empty()
        || !algorithms
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_,.@".contains(&b))
    {
        bail!("invalid approved host-key algorithms");
    }
    let mut options: Vec<OsString> = ["-a", "-x", "-k"].into_iter().map(Into::into).collect();
    for option in [
        "PubkeyAuthentication=host-bound".to_owned(),
        "PreferredAuthentications=publickey".into(),
        "BatchMode=yes".into(),
        "ForwardAgent=no".into(),
        "ForwardX11=no".into(),
        "PermitLocalCommand=no".into(),
        "ClearAllForwardings=yes".into(),
        "ControlMaster=no".into(),
        "ControlPath=none".into(),
        "StrictHostKeyChecking=yes".into(),
        "GlobalKnownHostsFile=/dev/null".into(),
        "KnownHostsCommand=none".into(),
        "VerifyHostKeyDNS=no".into(),
        "NoHostAuthenticationForLocalhost=no".into(),
        "UpdateHostKeys=no".into(),
        "CheckHostIP=no".into(),
        "ServerAliveInterval=15".into(),
        "ServerAliveCountMax=3".into(),
        format!("IdentityAgent={agent}"),
        format!("UserKnownHostsFile={known_hosts}"),
        format!("HostKeyAlgorithms={algorithms}"),
    ] {
        options.extend(["-o".into(), option.into()]);
    }
    if let Some(alias) = host_key_alias {
        ssh::validate_host_key_alias(alias)?;
        options.extend(["-o".into(), format!("HostKeyAlias={alias}").into()]);
    }
    Ok(options)
}

fn resolve_policy(target: &NativeEndpoint, cancelled: &dyn Fn() -> bool) -> Result<HostPolicy> {
    ssh::validate_endpoint(target)?;
    crate::agent_broker::resolve_host_policy_at_bounded(
        "ssh",
        target.user.as_deref(),
        &target.host,
        target.port,
        Instant::now() + RESOLVE_TIMEOUT,
        cancelled,
    )
}

fn resolve_local_policy(target: &LocalTarget, cancelled: &dyn Fn() -> bool) -> Result<HostPolicy> {
    target.validate()?;
    crate::agent_broker::resolve_account_trust_bounded(
        "ssh",
        target
            .endpoint
            .user
            .as_deref()
            .context("missing selected SSH account")?,
        target.trust_name(),
        target.trust_port(),
        Instant::now() + RESOLVE_TIMEOUT,
        cancelled,
    )
}

fn resolved_local(target: &LocalTarget, policy: &HostPolicy) -> Result<ResolvedPolicy> {
    anyhow::ensure!(
        target.endpoint.user.as_deref() == Some(policy.login_user.as_str()),
        "SSH trust lookup changed the requester-selected account"
    );
    ResolvedPolicy::new(
        target.endpoint.clone(),
        &policy.known_hosts(HOST_ALIAS)?,
        &policy.host_key_algorithms(),
    )
}

fn resolve_local_target(
    target: &LocalTarget,
    cancelled: &dyn Fn() -> bool,
) -> Result<ResolvedPolicy> {
    if cancelled() {
        bail!("SSH resolution disconnected");
    }
    let resolved = resolved_local(target, &resolve_local_policy(target, cancelled)?)?;
    if cancelled() {
        bail!("SSH resolution disconnected");
    }
    Ok(resolved)
}

pub(crate) fn resolve_local_and_reply(
    target: &LocalTarget,
    writer: &mut impl Write,
    cancelled: &dyn Fn() -> bool,
) -> Result<()> {
    let resolved = resolve_local_target(target, cancelled)?;
    write_message(writer, &Reply::Ready)?;
    write_message(writer, &resolved)
}

pub(crate) fn reply_error(writer: &mut impl Write, error: &anyhow::Error) -> Result<()> {
    let message = format!("{error:#}");
    let reply = if error.downcast_ref::<RetryableSetupError>().is_some() {
        Reply::RetryableError(message)
    } else {
        Reply::Error(message)
    };
    write_message(writer, &reply)
}

enum AccountApproval<'a> {
    Return {
        requester: &'a crate::receive_approval::Requester,
        permission: AccountPermission,
    },
    Provider(ProviderLoginPermission),
}

impl<'a> AccountApproval<'a> {
    fn new(origin: &AuthorizationOrigin<'a>, destination: AccountIdentity) -> Result<Self> {
        Ok(match origin {
            AuthorizationOrigin::Return {
                profile,
                requester,
                source,
            } => Self::Return {
                requester,
                permission: AccountPermission::new(
                    (*profile).into(),
                    source.lock().unwrap().clone().map_err(anyhow::Error::msg)?,
                    destination,
                )?,
            },
            AuthorizationOrigin::Provider { profile, identity } => Self::Provider(
                ProviderLoginPermission::new((*profile).into(), (*identity).clone(), destination)?,
            ),
        })
    }

    fn id(&self) -> String {
        match self {
            Self::Return { permission, .. } => permission.id(),
            Self::Provider(permission) => permission.id(),
        }
    }

    fn remembered(&self, queue: &Queue) -> Result<bool> {
        match self {
            Self::Return { permission, .. } => queue.account_remembered(permission),
            Self::Provider(permission) => queue.provider_account_remembered(permission),
        }
    }

    fn request(
        &self,
        context: &AuthorizationContext<'_>,
        request: &Request,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<AccountDecision> {
        match self {
            Self::Return {
                requester,
                permission,
            } => context.approvals.request_account(
                requester,
                &request.command,
                &request.cwd,
                permission,
                context.notifications,
                cancelled,
            ),
            Self::Provider(permission) => context.approvals.request_provider_account(
                &request.command,
                &request.cwd,
                permission,
                context.notifications,
                cancelled,
            ),
        }
    }
}

fn approve_account(
    context: &AuthorizationContext<'_>,
    request: &Request,
    permission: &AccountApproval,
    generation: u64,
    existing_account_only: bool,
    cancelled: &dyn Fn() -> bool,
) -> Result<()> {
    let key = permission.id();
    let already_approved = || -> Result<bool> {
        let session_approved = context
            .session_grants
            .lock()
            .unwrap()
            .get(&key)
            .is_some_and(|approved_generation| *approved_generation == generation);
        Ok(session_approved || permission.remembered(context.approvals)?)
    };
    if already_approved()? {
        return Ok(());
    }
    anyhow::ensure!(!existing_account_only,
        "SSH account permission ended before a data connection could start; retry the command to request account access");
    // Serialize prompts, not policy lookup or authentications that already have
    // permission. Recheck after taking the lock: another request may just have
    // approved this same account while this request was looking it up.
    let _approval = context
        .request_lock
        .try_lock()
        .map_err(|_| anyhow::anyhow!("another request is awaiting approval"))?;
    if already_approved()? {
        return Ok(());
    }
    let decision = permission.request(context, request, cancelled)?;
    if cancelled() {
        bail!("SSH request disconnected before authorization");
    }
    if decision == AccountDecision::Session {
        context
            .session_grants
            .lock()
            .unwrap()
            .insert(key, generation);
    }
    Ok(())
}

/// The caller authenticates the transport, tracks its streams and captures a
/// live session generation before entering. The broker never trusts requested
/// pins: resolve again, compare the expectation, and sign only for that policy.
#[cfg(test)]
pub(crate) fn authorize_and_relay(
    context: AuthorizationContext<'_>,
    request: Request,
    stream: TrackedStream,
    generation: u64,
    cancelled: &dyn Fn() -> bool,
) -> Result<()> {
    authorize_and_relay_inner(context, request, None, false, stream, generation, cancelled)
}

pub(crate) fn authorize_local_and_relay(
    context: AuthorizationContext<'_>,
    request: LocalRequest,
    stream: TrackedStream,
    generation: u64,
    cancelled: &dyn Fn() -> bool,
) -> Result<()> {
    let (request, target, existing_account_only) = request.into_request()?;
    authorize_and_relay_inner(
        context,
        request,
        Some(target),
        existing_account_only,
        stream,
        generation,
        cancelled,
    )
}

fn authorize_and_relay_inner(
    context: AuthorizationContext<'_>,
    request: Request,
    local_target: Option<LocalTarget>,
    existing_account_only: bool,
    mut stream: TrackedStream,
    generation: u64,
    cancelled: &dyn Fn() -> bool,
) -> Result<()> {
    request.validate(&context.origin)?;
    let count = context.active_count.fetch_add(1, Ordering::AcqRel);
    struct Slot<'a>(&'a AtomicU64);
    impl Drop for Slot<'_> {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::AcqRel);
        }
    }
    let _slot = Slot(context.active_count);
    if count >= 64 {
        return Err(RetryableSetupError("too many active approved SSH connections (limit 64 per authorization session); reduce the worker count or finish another transfer".into()).into());
    }
    if cancelled() {
        bail!("SSH request disconnected before authorization");
    }
    let (policy, approved) = if let Some(target) = &local_target {
        let policy = resolve_local_policy(target, cancelled)?;
        let approved = resolved_local(target, &policy)?;
        (policy, approved)
    } else {
        let policy = resolve_policy(&request.target, cancelled)?;
        let approved = ResolvedPolicy::from_policy(&policy)?;
        (policy, approved)
    };
    approved.check_expected(request.expected.as_ref())?;
    if request.mode == Mode::Account {
        let destination = AccountIdentity::new(
            approved.endpoint.clone(),
            policy.pinned_host_key_fingerprints(),
        )?
        .with_trusted_host(policy.trusted_host_name())?;
        let permission = AccountApproval::new(&context.origin, destination)?;
        approve_account(
            &context,
            &request,
            &permission,
            generation,
            existing_account_only,
            cancelled,
        )?;
    } else {
        // Legacy requests are accepted only through the return adapter and
        // retain their explicit one-login/reusable-login approval wording.
        let AuthorizationOrigin::Return { requester, .. } = &context.origin else {
            bail!("SSH providers require an account authorization request");
        };
        let _approval = context
            .request_lock
            .try_lock()
            .map_err(|_| anyhow::anyhow!("another request is awaiting approval"))?;
        context.approvals.request_ssh(
            requester,
            &request.command,
            &request.cwd,
            &approved.endpoint,
            request.mode == Mode::Persistent,
            context.notifications,
            cancelled,
        )?;
    }
    if cancelled() {
        bail!("SSH request disconnected before authorization");
    }
    let broker = ConstrainedAgentBroker::start(BrokerPolicy::direct(policy), 1)?;
    let mut upstream = UnixStream::connect(broker.socket_path())?;
    upstream.set_read_timeout(Some(Duration::from_secs(120)))?;
    upstream.set_write_timeout(Some(Duration::from_secs(120)))?;
    // The adapter closes this tracked socket when its session ends, including
    // after authentication. Quiet approved sessions may otherwise remain open.
    let socket = stream.try_clone()?;
    socket.set_read_timeout(None)?;
    socket.set_write_timeout(Some(Duration::from_secs(120)))?;
    write_message(&mut stream, &Reply::Ready)?;
    write_message(&mut stream, &approved)?;
    crate::agent_broker::relay_frames(&mut stream, &mut upstream)
}

impl Receiver {
    pub(super) fn resolve_local_ssh(
        &self,
        target: LocalTarget,
        stream: TrackedStream,
    ) -> Result<()> {
        target.validate()?;
        self.resolve_ssh_with(target, stream, resolve_local_target)
    }

    fn resolve_ssh_with<T>(
        &self,
        target: T,
        mut stream: TrackedStream,
        resolve: impl FnOnce(&T, &dyn Fn() -> bool) -> Result<ResolvedPolicy>,
    ) -> Result<()> {
        let (generation, _tracked) = {
            let _sessions = self.sessions.lock().unwrap();
            (
                self.generation.load(Ordering::Acquire),
                self.active_streams.track(stream.try_clone()?)?,
            )
        };
        let socket = stream.try_clone()?;
        let cancelled = || {
            self.stop.load(Ordering::Acquire)
                || self.generation.load(Ordering::Acquire) != generation
                || requester_closed(&socket)
        };
        if cancelled() {
            bail!("SSH resolution disconnected");
        }
        let resolved = resolve(&target, &cancelled)?;
        if cancelled() {
            bail!("SSH resolution disconnected");
        }
        write_message(&mut stream, &Reply::Ready)?;
        write_message(&mut stream, &resolved)
    }

    pub(super) fn authorize_local_ssh(
        &self,
        request: LocalRequest,
        stream: TrackedStream,
    ) -> Result<()> {
        let (request, target, existing_account_only) = request.into_request()?;
        self.authorize_ssh_inner(request, Some(target), existing_account_only, stream)
    }

    fn authorize_ssh_inner(
        &self,
        request: Request,
        target: Option<LocalTarget>,
        existing_account_only: bool,
        stream: TrackedStream,
    ) -> Result<()> {
        let context = AuthorizationContext {
            origin: AuthorizationOrigin::Return {
                profile: &self.name,
                requester: &self.requester,
                source: &self.account_source,
            },
            approvals: &self.approvals,
            notifications: self.notifications,
            request_lock: &self.request_lock,
            active_count: &self.ssh_count,
            session_grants: &self.account_sessions,
        };
        let (generation, _tracked) = {
            let _sessions = self.sessions.lock().unwrap();
            (
                self.generation.load(Ordering::Acquire),
                self.active_streams.track(stream.try_clone()?)?,
            )
        };
        let socket = stream.try_clone()?;
        let cancelled = || {
            self.stop.load(Ordering::Acquire)
                || self.generation.load(Ordering::Acquire) != generation
                || requester_closed(&socket)
        };
        authorize_and_relay_inner(
            context,
            request,
            target,
            existing_account_only,
            stream,
            generation,
            &cancelled,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(seed: u8) -> ResolvedPolicy {
        let key = ssh_key::PrivateKey::new(
            ssh_key::private::Ed25519Keypair::from_seed(&[seed; 32]).into(),
            "",
        )
        .unwrap();
        ResolvedPolicy::new(
            NativeEndpoint {
                user: Some("account".into()),
                host: "destination".into(),
                port: Some(22),
            },
            &format!("{HOST_ALIAS} {}\n", key.public_key().to_openssh().unwrap()),
            "ssh-ed25519",
        )
        .unwrap()
    }

    fn provider_identity() -> ProviderIdentity {
        ProviderIdentity::new(
            "provider-user".into(),
            ssh_key::Fingerprint::Sha256([7; 32]).to_string(),
        )
        .unwrap()
    }

    #[test]
    fn optional_registration_read_creates_nothing_and_preserves_private_validation() {
        use std::os::unix::fs::PermissionsExt;
        let temporary = crate::test_support::tempdir().unwrap();
        let directory = temporary.path().join("registry");
        assert!(read_existing_registration_at(&directory, "laptop")
            .unwrap()
            .is_none());
        assert!(!directory.exists());
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        assert!(read_existing_registration_at(&directory, "laptop")
            .unwrap()
            .is_none());
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 0);
        let registration = Registration {
            version: REGISTRATION_VERSION,
            identity: crate::identity::build().into(),
            socket: directory.join("socket"),
            secret: "test-only".into(),
            program: b"/syq-helper".to_vec(),
        };
        let path = directory.join("laptop.json");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(&serde_json::to_vec(&registration).unwrap())
            .unwrap();
        assert!(read_existing_registration_at(&directory, "laptop")
            .unwrap()
            .is_some());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_existing_registration_at(&directory, "laptop").is_err());
        let alias = temporary.path().join("alias");
        std::os::unix::fs::symlink(&directory, &alias).unwrap();
        assert!(read_existing_registration_at(&alias, "laptop").is_err());
    }

    #[test]
    fn capacity_refusal_retains_retryability_in_wire_reply() {
        let error = anyhow::Error::new(RetryableSetupError("temporary capacity".into()))
            .context("authorize worker");
        let mut wire = Vec::new();
        reply_error(&mut wire, &error).unwrap();
        let reply: Reply = read_message(&mut wire.as_slice()).unwrap();
        assert!(
            matches!(reply, Reply::RetryableError(message) if message.contains("temporary capacity"))
        );
        wire.clear();
        reply_error(&mut wire, &anyhow::anyhow!("permission refused")).unwrap();
        let reply: Reply = read_message(&mut wire.as_slice()).unwrap();
        assert!(matches!(reply, Reply::Error(_)));
    }

    #[test]
    fn obsolete_provider_selected_requests_are_not_accepted() {
        for encoded in [
            r#"{"ResolveSsh":{"user":null,"host":"private-alias","port":null}}"#,
            r#"{"Ssh":{"target":{"user":null,"host":"private-alias","port":null},"command":[],"cwd":""}}"#,
        ] {
            assert!(serde_json::from_str::<Message>(encoded).is_err());
        }
    }

    #[test]
    fn provider_accepts_account_intent_without_parsing_return_commands() {
        let identity = provider_identity();
        let origin = AuthorizationOrigin::Provider {
            profile: "laptop",
            identity: &identity,
        };
        let mut request = Request::account(
            policy(1).endpoint,
            vec![b"rm".to_vec(), b"untrusted intent only".to_vec()],
            "/tmp".into(),
            None,
        );
        assert!(request.validate(&origin).is_ok());
        for mode in [Mode::Once, Mode::Persistent] {
            request.mode = mode;
            assert!(request
                .validate(&origin)
                .unwrap_err()
                .to_string()
                .contains("providers require an account authorization request"));
        }
        request.mode = Mode::Account;
        request.command = vec![vec![b'x'; 16 * 1024 + 1]];
        assert!(request.validate(&origin).is_err());
    }

    #[test]
    fn provider_permission_uses_local_identity_without_a_source_host() {
        let identity = provider_identity();
        let origin = AuthorizationOrigin::Provider {
            profile: "provider",
            identity: &identity,
        };
        let destination = AccountIdentity::new(
            policy(1).endpoint,
            vec![ssh_key::Fingerprint::Sha256([8; 32]).to_string()],
        )
        .unwrap();
        let AccountApproval::Provider(permission) =
            AccountApproval::new(&origin, destination.clone()).unwrap()
        else {
            panic!("provider login became a return permission");
        };
        assert_eq!(permission.provider, identity);
        assert_eq!(permission.profile, "provider");
        assert_eq!(permission.destination, destination);
        assert!(serde_json::to_value(&permission)
            .unwrap()
            .get("source")
            .is_none());
    }

    #[test]
    fn shared_authorization_releases_admission_on_cancel_or_full_capacity() {
        let identity = provider_identity();
        let approvals = Queue::default();
        let lock = Mutex::new(());
        let grants = Mutex::new(HashMap::new());
        let streams = Arc::new(crate::private_broker::ConnectionRegistry::new(
            Duration::from_secs(1),
        ));
        for (initial_count, cancelled) in [(0, true), (64, false)] {
            let count = AtomicU64::new(initial_count);
            let (server, _client) = UnixStream::pair().unwrap();
            let context = AuthorizationContext {
                origin: AuthorizationOrigin::Provider {
                    profile: "provider",
                    identity: &identity,
                },
                approvals: &approvals,
                notifications: crate::receive_approval::Notifications::Off,
                request_lock: &lock,
                active_count: &count,
                session_grants: &grants,
            };
            let request = Request::account(policy(1).endpoint, vec![], String::new(), None);
            let error =
                authorize_and_relay(context, request, streams.track(server).unwrap(), 0, &|| {
                    cancelled
                })
                .unwrap_err();
            assert!(error.to_string().contains(if cancelled {
                "disconnected"
            } else {
                "too many active"
            }));
            assert_eq!(count.load(Ordering::Acquire), initial_count);
            assert!(lock.try_lock().is_ok());
            assert!(grants.lock().unwrap().is_empty());
            assert!(approvals.snapshots().is_empty());
        }
    }

    #[test]
    fn account_permissions_bypass_pending_prompts_without_authorizing_missing_grants() {
        // Persistence scopes must fit OpenSSH's socket-path limit even though
        // this approval test does not itself open an SSH socket.
        let temporary = crate::test_support::short_tempdir().unwrap();
        crate::persistence::initialize_scope(temporary.path()).unwrap();
        let domain = Domain::select(Some(temporary.path())).unwrap();
        let approvals = Queue::new(domain.clone());
        let identity = provider_identity();
        let lock = Mutex::new(());
        let _other_approval = lock.lock().unwrap();
        let grants = Mutex::new(HashMap::new());
        let count = AtomicU64::new(0);
        let context = AuthorizationContext {
            origin: AuthorizationOrigin::Provider {
                profile: "provider",
                identity: &identity,
            },
            approvals: &approvals,
            notifications: crate::receive_approval::Notifications::Off,
            request_lock: &lock,
            active_count: &count,
            session_grants: &grants,
        };
        let resolved = policy(1);
        let permission = AccountApproval::new(
            &context.origin,
            AccountIdentity::new(
                resolved.endpoint.clone(),
                vec![ssh_key::Fingerprint::Sha256([8; 32]).to_string()],
            )
            .unwrap(),
        )
        .unwrap();
        let request = Request::account(resolved.endpoint, vec![], String::new(), None);
        for worker_only in [false, true] {
            for granted in [None, Some(4), Some(5)] {
                grants.lock().unwrap().clear();
                if let Some(generation) = granted {
                    grants.lock().unwrap().insert(permission.id(), generation);
                }
                let result =
                    approve_account(&context, &request, &permission, 5, worker_only, &|| false);
                assert_eq!(result.is_ok(), granted == Some(5));
                if let Err(error) = result {
                    assert!(
                        error.to_string().contains(if worker_only {
                            "permission ended"
                        } else {
                            "another request is awaiting approval"
                        }),
                        "{error:#}"
                    );
                }
                assert!(approvals.snapshots().is_empty());
            }
        }
        // Remembered account access also needs no UI lock, even after a new
        // authorization session has discarded its in-memory grants.
        grants.lock().unwrap().clear();
        let AccountApproval::Provider(remembered) = &permission else {
            unreachable!();
        };
        crate::receive_approval::provider_accounts::remember(&domain, remembered).unwrap();
        for worker_only in [false, true] {
            approve_account(&context, &request, &permission, 6, worker_only, &|| false).unwrap();
        }
        assert!(approvals.snapshots().is_empty());
        crate::receive_approval::provider_accounts::remove(&domain, &permission.id()).unwrap();
        assert!(approve_account(&context, &request, &permission, 6, false, &|| false).is_err());
        assert!(approvals.snapshots().is_empty());
    }

    #[test]
    fn worker_request_flag_is_explicit_and_old_local_requests_remain_normal() {
        let resolved = policy(1);
        let mut request = LocalRequest {
            target: LocalTarget {
                requested: resolved.endpoint.clone(),
                endpoint: resolved.endpoint.clone(),
                host_key_alias: None,
            },
            command: vec![],
            cwd: String::new(),
            expected: resolved,
            existing_account_only: false,
        };
        let old = serde_json::to_value(&request).unwrap();
        assert!(old.get("existing_account_only").is_none());
        assert!(
            !serde_json::from_value::<LocalRequest>(old)
                .unwrap()
                .existing_account_only
        );
        request.existing_account_only = true;
        let new = serde_json::to_value(&request).unwrap();
        assert_eq!(
            new.get("existing_account_only"),
            Some(&serde_json::Value::Bool(true))
        );
        assert!(
            serde_json::from_value::<LocalRequest>(new)
                .unwrap()
                .into_request()
                .unwrap()
                .2
        );
    }

    #[test]
    fn expected_resolution_rejects_account_pin_or_algorithm_changes() {
        let resolved = policy(1);
        assert!(resolved.check_expected(None).is_ok());
        assert!(resolved.check_expected(Some(&resolved)).is_ok());
        let mut changed = Vec::new();
        for endpoint in [
            NativeEndpoint {
                user: Some("other".into()),
                ..resolved.endpoint.clone()
            },
            NativeEndpoint {
                host: "other".into(),
                ..resolved.endpoint.clone()
            },
            NativeEndpoint {
                port: Some(2222),
                ..resolved.endpoint.clone()
            },
        ] {
            changed.push(ResolvedPolicy {
                endpoint,
                ..resolved.clone()
            });
        }
        changed.push(policy(2));
        changed.push(ResolvedPolicy {
            host_algorithms: "ssh-ed25519,rsa-sha2-512".into(),
            ..resolved.clone()
        });
        for expected in changed {
            let error = resolved.check_expected(Some(&expected)).unwrap_err();
            assert!(error.to_string().contains("provider configuration changed"));
            assert!(error.to_string().contains("retry the command"));
        }
    }

    #[test]
    fn resolved_policy_canonicalizes_pins_and_round_trips_copy_peers() {
        let first = policy(1);
        let second = policy(2);
        let keys = format!("{}{}", first.known_hosts, second.known_hosts);
        let resolved = ResolvedPolicy::new(first.endpoint.clone(), &keys, "ssh-ed25519").unwrap();
        let reordered = format!(
            "{}{}{}",
            second.known_hosts, first.known_hosts, first.known_hosts
        )
        .replace("syq-approved-peer", "syq-copy-peer")
        .replace('\n', " ignored-comment\n");
        let equivalent = ResolvedPolicy::new(first.endpoint, &reordered, "ssh-ed25519").unwrap();
        assert_eq!(resolved, equivalent);
        assert_eq!(
            ResolvedPolicy::from_peer(&resolved.peer().unwrap()).unwrap(),
            resolved
        );
        let encoded = serde_json::to_vec(&resolved).unwrap();
        assert_eq!(
            serde_json::from_slice::<ResolvedPolicy>(&encoded).unwrap(),
            resolved
        );
        let mut invalid = resolved;
        invalid.endpoint.user = None;
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn resolve_only_does_not_take_approval_lock_or_queue_account_access() {
        let temporary = crate::test_support::tempdir().unwrap();
        let (_broker, receiver, _registration, prompts) =
            super::super::tests::broker(temporary.path(), Approval::Ask);
        let _approval_lock = receiver.request_lock.lock().unwrap();
        let (server, mut client) = UnixStream::pair().unwrap();
        let stream = receiver.active_streams.track(server).unwrap();
        let resolved = policy(1);
        receiver
            .resolve_ssh_with(resolved.endpoint.clone(), stream, |target, cancelled| {
                assert_eq!(target, &resolved.endpoint);
                assert!(!cancelled());
                Ok(resolved.clone())
            })
            .unwrap();
        assert!(matches!(
            read_message::<Reply>(&mut client).unwrap(),
            Reply::Ready
        ));
        assert_eq!(
            read_message::<ResolvedPolicy>(&mut client).unwrap(),
            resolved
        );
        assert!(receiver.approvals.snapshots().is_empty());
        assert!(receiver.account_sessions.lock().unwrap().is_empty());
        assert_eq!(receiver.ssh_count.load(Ordering::Acquire), 0);
        assert!(prompts.try_recv().is_err());
    }

    #[test]
    fn resolve_only_stops_on_receiving_generation_change() {
        let temporary = crate::test_support::tempdir().unwrap();
        let (_broker, receiver, _registration, _prompts) =
            super::super::tests::broker(temporary.path(), Approval::Ask);
        let (server, _client) = UnixStream::pair().unwrap();
        let stream = receiver.active_streams.track(server).unwrap();
        let resolved = policy(1);
        let error = receiver
            .resolve_ssh_with(resolved.endpoint.clone(), stream, |_, cancelled| {
                receiver.revoke_all();
                assert!(cancelled());
                Ok(resolved)
            })
            .unwrap_err();
        assert!(error.to_string().contains("resolution disconnected"));
        assert!(receiver.approvals.snapshots().is_empty());
    }

    #[test]
    fn previous_ssh_request_without_expected_policy_still_deserializes() {
        let request: Request = serde_json::from_str(
            r#"{"target":{"user":null,"host":"destination","port":null},"command":[],"cwd":"/tmp"}"#,
        ).unwrap();
        assert!(request.mode == Mode::Once);
        assert!(request.expected.is_none());
    }

    #[test]
    fn requester_target_keeps_actual_route_separate_from_trust_lookup() {
        let mut target = LocalTarget {
            requested: NativeEndpoint {
                user: None,
                host: "work-alias".into(),
                port: Some(2200),
            },
            endpoint: NativeEndpoint {
                user: Some("selected-user".into()),
                host: "10.2.3.4".into(),
                port: Some(2222),
            },
            host_key_alias: None,
        };
        target.validate().unwrap();
        assert_eq!(target.trust_name(), "work-alias");
        assert_eq!(target.trust_port(), Some(2200));
        target.requested.port = None;
        assert_eq!(target.trust_port(), None); // resolved private port stays local
        target.host_key_alias = Some("stable-server".into());
        target.validate().unwrap();
        assert_eq!(target.trust_name(), "stable-server");
        target.requested.port = Some(2200);
        assert_eq!(target.trust_port(), None);
        target.host_key_alias = Some("[stable-server]:2200".into());
        target.validate().unwrap();
        assert_eq!(target.trust_name(), "[stable-server]:2200");
        assert_eq!(target.trust_port(), None);
        let expected = ResolvedPolicy::new(
            target.endpoint.clone(),
            &policy(31).known_hosts,
            "ssh-ed25519",
        )
        .unwrap();
        let encoded = serde_json::to_vec(&LocalRequest {
            target: target.clone(),
            command: Vec::new(),
            cwd: "/tmp".into(),
            expected: expected.clone(),
            existing_account_only: false,
        })
        .unwrap();
        assert!(serde_json::from_slice::<Request>(&encoded).is_err());
        let (request, decoded, existing_account_only) =
            serde_json::from_slice::<LocalRequest>(&encoded)
                .unwrap()
                .into_request()
                .unwrap();
        assert!(!existing_account_only);
        assert_eq!(decoded, target);
        assert_eq!(request.target, target.endpoint);
        assert!(request.mode == Mode::Account);
        let mut changed = expected;
        changed.endpoint.user = Some("different-account".into());
        assert!(LocalRequest {
            target: target.clone(),
            command: Vec::new(),
            cwd: String::new(),
            expected: changed,
            existing_account_only: false,
        }
        .into_request()
        .is_err());
        target.endpoint.port = None;
        assert!(target.validate().is_err());
        target.endpoint.port = Some(22);
        target.host_key_alias = Some("-oProxyCommand=anything".into());
        assert!(target.validate().is_err());
    }

    #[test]
    fn agent_replies_do_not_cancel_the_ssh_session() {
        let (mut local, mut remote) = UnixStream::pair().unwrap();
        assert!(!disconnected(&local));
        remote.write_all(b"reply").unwrap();
        assert!(!disconnected(&local));
        let mut reply = [0; 5];
        local.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"reply");
        assert!(!disconnected(&local));
        remote.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(disconnected(&local));
    }

    #[test]
    fn session_pins_preserve_native_host_key_alias_tokens() {
        for alias in [Some("stable-alias"), None] {
            let root = crate::test_support::tempdir().unwrap();
            let host_alias = "request-alias";
            let token = alias.unwrap_or(host_alias);
            let marker = root.path().join("proxy-token");
            let identity = root.path().join(format!("{token}.pub"));
            let config = root.path().join("config");
            let approved = policy(41);
            let key = approved
                .known_hosts
                .lines()
                .next()
                .unwrap()
                .split_once(' ')
                .unwrap()
                .1;
            std::fs::write(&identity, format!("{key}\n")).unwrap();
            let mut contents = format!("Host {host_alias}\n HostName destination\n User account\n Port 2200\n IdentityFile {}/%k.pub\n IdentitiesOnly yes\n ProxyCommand sh -c 'printf %%s \"$1\" > \"$2\"' sh '%k' {}\n",
                root.path().display(), shell_words::quote(marker.to_str().unwrap()));
            if let Some(alias) = alias {
                contents.push_str(&format!(" HostKeyAlias {alias}\n"));
            }
            std::fs::write(&config, contents).unwrap();
            let endpoint = NativeEndpoint {
                user: Some("account".into()),
                host: "destination".into(),
                port: Some(2200),
            };
            let local = ssh::local_config::LocalPlan {
                requested: NativeEndpoint {
                    user: None,
                    host: host_alias.into(),
                    port: None,
                },
                endpoint: endpoint.clone(),
                host_key_alias: alias.map(str::to_owned),
                config_digest: "a".repeat(64),
                route: ssh::local_config::Route::Direct,
                host_key_algorithms: "ssh-ed25519".into(),
                hop: None,
            };
            let approved =
                ResolvedPolicy::new(endpoint, &approved.known_hosts, &approved.host_algorithms)
                    .unwrap();
            let canonical = approved.known_hosts.clone();
            let hosts = root.path().join("known_hosts");
            std::fs::write(&hosts, session_known_hosts(&approved, &local).unwrap()).unwrap();
            assert_eq!(approved.known_hosts, canonical); // session spelling never mutates serialized authority
            let lookup = alias.unwrap_or("[destination]:2200");
            let mut keygen = std::process::Command::new("ssh-keygen");
            keygen.args(["-F", lookup, "-f"]).arg(&hosts);
            let found = crate::process::capture_output_bounded(
                &mut keygen,
                Instant::now() + Duration::from_secs(5),
                &|| false,
                64 * 1024,
            )
            .unwrap();
            assert!(
                found.status.success(),
                "{}",
                String::from_utf8_lossy(&found.stderr)
            );
            let mut command = std::process::Command::new("ssh");
            command
                .args(["-vvv", "-F"])
                .arg(&config)
                .args(
                    ssh_options(&root.path().join("agent"), &hosts, "ssh-ed25519", alias).unwrap(),
                )
                .args(["--", host_alias]);
            // The local proxy exits without a transport. No network or agent
            // is needed to observe OpenSSH's actual token/identity expansion.
            let output = crate::process::capture_output_bounded(
                &mut command,
                Instant::now() + Duration::from_secs(5),
                &|| false,
                64 * 1024,
            )
            .unwrap();
            assert!(!output.status.success());
            assert_eq!(
                std::fs::read_to_string(&marker).unwrap(),
                token,
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let diagnostics = String::from_utf8_lossy(&output.stderr);
            let prefix = format!("debug1: identity file {} type ", identity.display());
            let identity_type = diagnostics
                .lines()
                .find_map(|line| line.strip_prefix(&prefix))
                .unwrap_or_else(|| {
                    panic!("native SSH did not select the configured identity: {diagnostics}")
                });
            assert_ne!(
                identity_type, "-1",
                "native SSH did not load the public identity: {diagnostics}"
            );
        }
    }

    #[test]
    fn native_ssh_uses_only_the_approved_agent_and_host_policy() {
        let options = ssh_options(
            Path::new("/tmp/private/agent"),
            Path::new("/tmp/private/hosts"),
            "ssh-ed25519",
            None,
        )
        .unwrap();
        for required in [
            "IdentityAgent=/tmp/private/agent",
            "UserKnownHostsFile=/tmp/private/hosts",
            "ForwardAgent=no",
            "StrictHostKeyChecking=yes",
            "KnownHostsCommand=none",
            "VerifyHostKeyDNS=no",
            "NoHostAuthenticationForLocalhost=no",
            "PubkeyAuthentication=host-bound",
            "ControlPath=none",
        ] {
            assert!(options.iter().any(|value| value == required), "{required}");
        }
        for forbidden in [
            "-F",
            "IdentitiesOnly=no",
            "IdentityFile=none",
            "CertificateFile=none",
            "PKCS11Provider=none",
            "ProxyJump=none",
            "ProxyCommand=none",
            "HostKeyAlias=syq-approved-peer",
        ] {
            assert!(
                !options.iter().any(|value| value == forbidden),
                "{forbidden}"
            );
        }
        for path in ["/tmp/a b/agent", "/tmp/%h/agent", "/tmp/${HOME}/agent"] {
            assert!(ssh_options(
                Path::new(path),
                Path::new("/tmp/hosts"),
                "ssh-ed25519",
                None
            )
            .is_err());
        }
    }
}

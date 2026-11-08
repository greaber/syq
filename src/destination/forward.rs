//! Copies that a server starts to another server, or between two other
//! servers, and that the receiving machine approves: it signs directives
//! for the servers' enrolled receivers, and the servers connect to those
//! receivers directly.
use super::*;
use std::os::fd::AsRawFd;
use std::sync::atomic::AtomicUsize;

pub(super) const SETUP_TIMEOUT: Duration = Duration::from_secs(60);

pub(super) fn target_endpoint(target: &str) -> Result<crate::cli::NativeEndpoint> {
    if target.len() > 512 {
        bail!("destination SSH endpoint is too long");
    }
    let endpoint = crate::cli::parse_native_endpoint(Some(target))?.unwrap();
    // These values also enter the user's OpenSSH configuration substitutions.
    // Only endpoint text is accepted, never shell or SSH option syntax.
    if endpoint.host.starts_with('-')
        || !endpoint
            .host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-:".contains(&b))
        || endpoint.user.as_ref().is_some_and(|user| {
            user.starts_with('-')
                || !user
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
    {
        bail!("--auth-from requires an ordinary SSH destination with a plain host and login name");
    }
    Ok(endpoint)
}

pub(super) fn eligible_target(args: &crate::cli::Args) -> Result<String> {
    use crate::cli::{CoordinateAt, Interface, PeerAuth};
    let (destination, sources) = args
        .locations
        .split_last()
        .context("copy endpoints missing")?;
    if args.interface != Interface::NativeCp
        || sources.iter().any(|s| s.is_remote())
        || !destination.is_remote()
    {
        bail!("--auth-from requires syq cp with local sources and an SSH --to destination");
    }
    if args.rsh.is_some()
        || args.syq_path.is_some()
        || args.no_bootstrap
        || args.detach
        || args.restricted_grant.is_some()
        || args.peer_auth != PeerAuth::Restricted
        || args.coordinate_at != CoordinateAt::Auto
    {
        bail!("return authorization owns its SSH connection; it cannot be combined with --rsh, --syq-path, --no-bootstrap, --detach, --peer-auth, or --coordinate-at");
    }
    crate::directive::validate_restricted_args(args)?;
    let target = crate::remote_to_remote::endpoint_arg(destination, None, None);
    target_endpoint(&target)?;
    Ok(target)
}

/// The source and destination SSH endpoints of a copy between two servers
/// that a receiving machine approves, as the command names them.
pub(super) fn eligible_peer(args: &crate::cli::Args) -> Result<(String, String)> {
    let (source, destination) = crate::directive::coordinated_endpoints(args)?;
    let [source, target] = [source, destination].map(|location| {
        let endpoint = crate::remote_to_remote::endpoint_arg(location, None, None);
        target_endpoint(&endpoint).map(|_| endpoint)
    });
    Ok((source?, target?))
}

/// Whether `args` copies from one server to another.
pub(crate) fn between_servers(args: &crate::cli::Args) -> bool {
    args.locations
        .split_last()
        .is_some_and(|(destination, sources)| {
            destination.is_remote() && sources.first().is_some_and(|source| source.is_remote())
        })
}

pub(super) fn select(
    args: &mut crate::cli::Args,
    progress: Option<&crate::progress::Progress>,
) -> Result<Option<handoff::Selection>> {
    let explicit = match &args.auth_from {
        crate::cli::AuthFrom::Provider(crate::auth_from::Provider::Return(name)) => {
            Some(name.clone())
        }
        crate::cli::AuthFrom::Provider(crate::auth_from::Provider::Ssh { .. })
            if between_servers(args) =>
        {
            // The provider approves this copy once the command has read its
            // inputs (`prepare_through_provider`). Refuse here, before that,
            // what it would refuse in the command alone.
            eligible_peer(args)?;
            handoff::refuse_unsupported_preservation(args)?;
            return Ok(None);
        }
        crate::cli::AuthFrom::Provider(crate::auth_from::Provider::Ssh { .. }) => {
            bail!("this copy cannot use account authorization from an SSH provider; use a supported direct SSH copy or --auth-from @NAME for per-copy authorization");
        }
        _ => handoff::selected_name(handoff::Kind::Forward).map(str::to_owned),
    };
    if between_servers(args) {
        // A copy between two servers asks a receiving machine only when it
        // was chosen for it: this machine's own SSH access runs it otherwise.
        let Some(name) = explicit else {
            return Ok(None);
        };
        let (_, target) = eligible_peer(args)?;
        let registration = load_registration(&name)?;
        return Ok(Some(handoff::Selection::new(
            name,
            registration,
            handoff::Kind::Forward,
            Some(target),
        )));
    }
    let target = match eligible_target(args) {
        Ok(target) => target,
        Err(_) if explicit.is_none() => return Ok(None),
        Err(error) => return Err(error),
    };
    let (name, registration) = if let Some(name) = explicit {
        let registration = load_registration(&name)?;
        (name, registration)
    } else {
        let names = registered_names();
        if names.is_empty() {
            return Ok(None);
        }
        // Open the actual control connection before considering another
        // machine's access. Keep a successful connection for the transfer;
        // probing with a separate SSH command would add a login/round trip.
        // This must precede reading stdin and opening result files, because
        // selecting a receiving machine can exec its build-pinned helper.
        let crate::conn::Endpoint::Remote(spec) =
            crate::transfer::endpoint(args.locations.last().unwrap(), args)?
        else {
            unreachable!("eligible forwarding destination is remote");
        };
        let error = match crate::transfer::connect_for_authorization(args, &spec, progress) {
            Ok(connection) => {
                *spec.primed_control.lock().unwrap() =
                    crate::conn::PrimedControl::Checked(Some(Box::new(connection)));
                args.direct_destination = Some(Box::new(spec));
                return Ok(None);
            }
            Err(error) if crate::conn::is_per_copy_approval_fallback_error(&error) => error,
            Err(error) => return Err(error),
        };
        let Some(found) = names.into_iter().find_map(|name| {
            let registration = available(&name, Duration::from_secs(2)).ok()?;
            Some((name, registration))
        }) else {
            // Do not repeat the failed SSH attempt when no receiver responds.
            return Err(error);
        };
        super::notices::asking(&error, &spec, &found.0, &format!("this copy to {target}"));
        found
    };
    Ok(Some(handoff::Selection::new(
        name,
        registration,
        handoff::Kind::Forward,
        Some(target),
    )))
}

/// What the receiving machine returns for a server's copy to another
/// server: the directive it signed for the destination's enrolled receiver,
/// and how to reach that receiver.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Issued {
    /// The signed directive, base64url-encoded.
    directive: String,
    /// The enrollment's entry key, which only starts its receiver.
    entry_key: EntryKeyText,
    /// The account the enrollment is for.
    login: String,
    /// What this machine's known_hosts files say about the destination.
    known_hosts: String,
    /// What they leave out of its configuration, without its value, for a
    /// notice.
    known_hosts_left_out: Option<String>,
    /// The destination as the directive's rules name it.
    destination: Vec<u8>,
    /// This machine's deletion limit for the copy.
    max_delete: u64,
    /// For a copy between two other servers, the source's receiver, which
    /// runs the copy; the requester presents the destination's directive
    /// and entry key to it.
    coordinated: Option<Coordinated>,
}

/// The source's receiver of a copy between two other servers, which the
/// requester logs in to, and what the requester checks the destination's
/// results with.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Coordinated {
    /// The source's signed directive, base64url-encoded.
    directive: String,
    entry_key: EntryKeyText,
    /// The account the source's enrollment is for.
    login: String,
    /// What this machine's known_hosts files say about the source.
    known_hosts: String,
    known_hosts_left_out: Option<String>,
    /// The destination's results: who signs them, for which enrollment,
    /// request and directive.
    results_public_key: String,
    enrollment: crate::enrollment::EnrollmentId,
    request: crate::delegation::RequestId,
    digest: [u8; 32],
}

/// An entry key in OpenSSH form, wiped when dropped.
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub(super) struct EntryKeyText(String);

impl EntryKeyText {
    fn of(key: &ssh_key::PrivateKey) -> Result<Self> {
        Ok(Self(key.to_openssh(ssh_key::LineEnding::LF)?.to_string()))
    }

    pub(super) fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl Drop for EntryKeyText {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

impl std::fmt::Debug for Issued {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Issued")
            .field("login", &self.login)
            .finish_non_exhaustive()
    }
}

/// What the approving machine leaves out of the host-key checking it hands
/// on for a copy between two servers: for the source, which this machine
/// checks, and for the destination, which the source checks. Each omission
/// names only the kind of setting, never its configured value.
fn left_out_notices(
    (source, source_left_out): (&str, Option<&str>),
    (target, destination_left_out): (&str, Option<&str>),
) -> Vec<String> {
    let plain = |text: &str| {
        text.chars()
            .filter(|character| !character.is_control())
            .collect::<String>()
    };
    source_left_out
        .map(|left_out| {
            format!(
                "syq: checking {source}'s host key without some of what the approving machine knows about it: {}",
                plain(left_out)
            )
        })
        .into_iter()
        .chain(destination_left_out.map(|left_out| {
            format!(
                "syq: {source} checks {target}'s host key without some of what the approving machine knows about it: {}",
                plain(left_out)
            )
        }))
        .collect()
}

/// What approves a copy between two servers that this machine starts.
enum Approving {
    /// A receiving machine, by the name it registered here.
    Return {
        name: String,
        registration: Registration,
    },
    /// An SSH authorization provider, over this machine's own login to it.
    Provider(crate::auth_from::Provider),
}

impl Approving {
    fn label(&self) -> String {
        match self {
            Self::Return { name, .. } => format!("@{name}"),
            Self::Provider(provider) => provider.label(),
        }
    }

    /// Send `request` and read the reply, within what the approver may
    /// take to decide and set the accounts up.
    fn ask(&self, args: &crate::cli::Args, request: ForwardRequest) -> Result<Reply> {
        let timeout = REQUEST_TIMEOUT + SETUP_TIMEOUT + Duration::from_secs(10);
        match self {
            Self::Return { registration, .. } => {
                let (stream, reply) = exchange(
                    registration,
                    Message::Forward(Box::new(request)),
                    timeout,
                    None,
                )?;
                // The copy needs nothing more from the receiving machine.
                drop(stream);
                Ok(reply)
            }
            Self::Provider(provider) => crate::auth_from::selected_context(
                ask_provider(args, provider, request, Instant::now() + timeout),
                &args.auth_from,
                args.auth_from_explicit,
            ),
        }
    }
}

/// Ask `provider`, over this machine's login to it, to approve a copy
/// between two servers.
fn ask_provider(
    args: &crate::cli::Args,
    provider: &crate::auth_from::Provider,
    request: ForwardRequest,
    deadline: Instant,
) -> Result<Reply> {
    let domain = crate::persistence::Domain::select(args.pscope.as_deref())?;
    let binding = super::ssh::provider::resolve_connection(&domain, provider)?;
    let mut stream = super::ssh::provider::open(
        &domain,
        provider,
        &binding,
        crate::receive_service::provider::SessionRequest::Forward(Box::new(request)),
    )?;
    let reply = read_message(&mut super::DeadlineSocket {
        socket: &mut stream,
        deadline,
    })?;
    // The copy needs nothing more from the provider.
    drop(stream);
    match reply {
        Reply::Error(error) | Reply::RetryableError(error) => {
            bail!("SSH authorization provider {}: {error}", provider.label())
        }
        reply => Ok(reply),
    }
}

/// The SSH authorization provider that approves this copy between two
/// servers, if one does: the command selected it, explicitly or by a saved
/// choice, for a copy that runs on the source.
fn approving_provider(args: &crate::cli::Args) -> Option<crate::auth_from::Provider> {
    match &args.auth_from {
        crate::cli::AuthFrom::Provider(provider @ crate::auth_from::Provider::Ssh { .. })
            if args.interface == crate::cli::Interface::NativeCp
                && args.coordinate_at != crate::cli::CoordinateAt::Local
                && between_servers(args) =>
        {
            Some(provider.clone())
        }
        _ => None,
    }
}

/// Ask the SSH authorization provider the command selected to approve its
/// copy between two servers, if it selected one (`select` checked the
/// command), and set the copy up as `prepare_coordinated` does.
pub(super) fn prepare_through_provider(args: &mut crate::cli::Args) -> Result<()> {
    match approving_provider(args) {
        Some(provider) => prepare_coordinated(args, Approving::Provider(provider)),
        None => Ok(()),
    }
}

/// Ask the receiving machine or SSH authorization provider to approve a
/// copy between two servers, then set up this machine's connection to the
/// source's receiver, which runs the copy.
fn prepare_coordinated(args: &mut crate::cli::Args, approving: Approving) -> Result<()> {
    let (source, target) = eligible_peer(args)?;
    // Refused here as a local copy refuses it, before the receiving machine
    // is asked.
    crate::fsops::ensure_source_count(
        crate::transfer::distinct_native_sources(
            args.locations
                .split_last()
                .map_or(&[], |(_, sources)| sources),
        )
        .len(),
    )?;
    let command = crate::approval_command::copy_command(args)?;
    let inputs = crate::directive::Inputs {
        ignore: args.ignore_lines.clone(),
        mapping: crate::directive::mapping_authorization(args)?,
    };
    // This machine checks the destination's results itself, as it would
    // for a copy between two servers it started with its own access.
    let (secret, results_key) = crate::destination_results::generate_recipient()?;
    super::notices::waiting(
        &approving.label(),
        &format!("this copy from {source} to {target}"),
    );
    let reply = approving.ask(
        args,
        ForwardRequest {
            source: Some(source.clone()),
            target: target.clone(),
            command,
            cwd: crate::approval_command::current_directory(),
            inputs,
            results_key: Some(results_key),
        },
    )?;
    let Reply::Directive(issued) = reply else {
        bail!("unexpected remote copy approval response");
    };
    let Issued {
        directive,
        entry_key,
        known_hosts_left_out,
        coordinated,
        ..
    } = *issued;
    let coordinated = coordinated.context("unexpected remote copy approval response")?;
    if args.verbose > 0 {
        crate::output::diagnostic!(
            "syq: remote copy approved; connecting to the source's restricted receiver"
        );
    }
    if !args.quiet {
        for notice in left_out_notices(
            (&source, coordinated.known_hosts_left_out.as_deref()),
            (&target, known_hosts_left_out.as_deref()),
        ) {
            crate::output::diagnostic!("{notice}");
        }
    }
    let decode = |text: &str| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(text)
            .context("decode the copy's directive")
    };
    // This machine reaches the source's receiver as its own SSH
    // configuration reaches the source its command named, as the account
    // the approving machine enrolled, and checks its host key as its own
    // `ssh` would, also accepting what the approving machine knows.
    let endpoint = target_endpoint(&source)?;
    let receiver = crate::remote_to_remote::ReceiverSsh::prepare(
        &shell_words::split(&crate::remote_to_remote::receiver_rsh(endpoint.port))?,
        (Some(&coordinated.login), endpoint.port, &endpoint.host),
        &coordinated.known_hosts,
        coordinated.entry_key.0.as_bytes(),
        args.quiet,
    )?;
    args.coordinated_copy = Some(Arc::new(crate::remote_to_remote::CoordinatedCopy {
        receiver,
        login: coordinated.login.clone(),
        host: endpoint.host,
        source: decode(&coordinated.directive)?,
        destination: decode(&directive)?,
        destination_entry_key: zeroize::Zeroizing::new(entry_key.0.as_bytes().to_vec()),
        results: Mutex::new(Some(crate::destination_results::Expectation {
            public_key: coordinated.results_public_key,
            binding: crate::destination_results::Binding {
                enrollment_id: coordinated.enrollment,
                request_id: coordinated.request,
                grant_digest: coordinated.digest,
            },
            secret,
            records: args.native_results.is_some() || args.native_results_fd.is_some(),
        })),
    }));
    if let Approving::Return { name, .. } = approving {
        args.auth_from = crate::cli::AuthFrom::Provider(crate::auth_from::Provider::Return(name));
    }
    Ok(())
}

pub(super) fn prepare(args: &mut crate::cli::Args, selection: handoff::Selection) -> Result<()> {
    let handoff::Selection {
        name,
        registration,
        target,
        ..
    } = selection;
    if between_servers(args) {
        return prepare_coordinated(args, Approving::Return { name, registration });
    }
    let target = target.context("remote authorization target missing")?;
    // Refused with advice before anything is asked when an approval cannot
    // carry the command.
    let command = crate::approval_command::copy_command(args)?;
    // The rules come from the command; only what it read from files travels
    // beside it.
    let inputs = crate::directive::Inputs {
        ignore: args.ignore_lines.clone(),
        mapping: crate::directive::mapping_authorization(args)?,
    };
    super::notices::waiting(&format!("@{name}"), &format!("this copy to {target}"));
    let (stream, reply) = exchange(
        &registration,
        Message::Forward(Box::new(ForwardRequest {
            source: None,
            target: target.clone(),
            command,
            cwd: crate::approval_command::current_directory(),
            inputs,
            results_key: None,
        })),
        REQUEST_TIMEOUT + SETUP_TIMEOUT + Duration::from_secs(10),
        None,
    )?;
    // The copy needs nothing more from the receiving machine.
    drop(stream);
    let Reply::Directive(issued) = reply else {
        bail!("unexpected remote copy approval response");
    };
    if args.verbose > 0 {
        crate::output::diagnostic!(
            "syq: remote copy approved; connecting to the destination's restricted receiver"
        );
    }
    // This machine reaches the receiver as its own SSH configuration reaches
    // the target its command named, as the account the approving machine
    // enrolled, and checks its host key as its own `ssh` would, also
    // accepting what the approving machine knows.
    let endpoint = target_endpoint(&target)?;
    super::apply_deletion_limit(args, Some(issued.max_delete));
    let destination = args.locations.last_mut().unwrap();
    destination.path = issued.destination;
    destination.host = Some(endpoint.host);
    destination.user = Some(issued.login);
    destination.port = endpoint.port;
    args.auth_from = crate::cli::AuthFrom::Provider(crate::auth_from::Provider::Return(name));
    args.restricted_grant = Some(issued.directive);
    args.rsh = Some(crate::remote_to_remote::receiver_rsh(endpoint.port));
    if let Some(left_out) = issued.known_hosts_left_out.filter(|_| !args.quiet) {
        crate::output::diagnostic!(
            "syq: checking the destination's host key without some of what the approving machine knows about it: {}",
            left_out
                .chars()
                .filter(|character| !character.is_control())
                .collect::<String>()
        );
    }
    let keys = crate::remote_to_remote::prepare_receiver_ssh_with(
        args,
        &issued.known_hosts,
        issued.entry_key.0.as_bytes(),
    )?;
    args.receiver_keys = Some(Arc::new(keys));
    Ok(())
}

/// The login this machine's SSH configuration gives `target`.
fn ssh_login(target: &str, deadline: Instant, cancelled: &dyn Fn() -> bool) -> Result<String> {
    let output = read_ssh_configuration(
        target_spec(target)?.ssh_hostname_command(),
        deadline,
        cancelled,
    )?;
    output
        .lines()
        .find_map(|line| line.strip_prefix("user ")?.trim().to_owned().into())
        .filter(|user: &String| !user.is_empty())
        .with_context(|| format!("the SSH configuration for {target:?} did not report its user"))
}

pub(super) struct Slot<'a>(pub(super) &'a AtomicUsize);
impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// A server's request to approve a copy to another server, which this
/// machine approves with a directive for that server's enrolled receiver.
/// The server sends what its command read from files.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ForwardRequest {
    /// For a copy between two other servers, the source as the command
    /// names it; otherwise the files are on the server that asks.
    pub(crate) source: Option<String>,
    /// The destination as the command names it.
    pub(crate) target: String,
    pub(crate) command: Vec<Vec<u8>>,
    pub(crate) cwd: String,
    pub(crate) inputs: crate::directive::Inputs,
    /// For a copy between two other servers, the requester's key for the
    /// destination's results, which it checks.
    pub(crate) results_key: Option<[u8; 32]>,
}

/// An account this machine reaches with its own SSH, and what its records
/// say about the account's enrollment.
pub(super) struct Account {
    endpoint: crate::cli::NativeEndpoint,
    target: String,
    login: String,
    pub(super) enrollment: crate::restricted::EnrollmentState,
}

impl Account {
    /// Whether this machine's SSH configuration logs in to the account as
    /// root.
    pub(super) fn is_root(&self) -> bool {
        self.login == "root"
    }

    pub(super) fn label(&self) -> String {
        format!("{}@{}", self.login, self.endpoint.host)
    }

    /// The login this machine's SSH configuration gives `target`, and its
    /// enrollment. Reading the configuration contacts no server.
    pub(super) fn find(target: &str, cancelled: &dyn Fn() -> bool) -> Result<Self> {
        let endpoint = target_endpoint(target)?;
        let login = ssh_login(target, Instant::now() + SETUP_TIMEOUT, cancelled)?;
        let enrollment =
            crate::restricted::local_enrollment_state(&endpoint.host, endpoint.port, &login)?;
        Ok(Self {
            endpoint,
            target: target.to_owned(),
            login,
            enrollment,
        })
    }

    /// Restricted receivers do not write or run copies as root: refuse a
    /// copy `direction` ("to" or "from") such an account that would need
    /// one, before anything is asked or set up, with `advice` for what to do
    /// instead. An account with another name and user ID 0 is refused when
    /// enrolling, or by its receiver when already enrolled.
    pub(super) fn refuse_root(&self, direction: &str, advice: &str) -> Result<()> {
        if self.is_root() {
            bail!(
                "syq's restricted receiver does not write or run copies as root, so a copy {direction} {} cannot be approved for one copy; {advice}",
                self.label()
            );
        }
        Ok(())
    }

    /// A dry run never sets up or updates restricted copying.
    pub(super) fn ready_for_dry_run(&self) -> Result<()> {
        let account = self.label();
        match self.enrollment {
            crate::restricted::EnrollmentState::Ready => Ok(()),
            crate::restricted::EnrollmentState::Missing => bail!(
                "a dry run does not set up restricted copying on {account}; the first real copy does, or run `syq receiver enroll {account}` on the receiving machine"
            ),
            crate::restricted::EnrollmentState::Outdated => bail!(
                "a dry run does not update syq on {account} for this machine's build; the next real copy does, or run `syq receiver enroll {account}` on the receiving machine"
            ),
        }
    }

    /// The login enrollment uses and what this machine knows about the
    /// account's host key, which the server dialing it adds to what it
    /// knows.
    pub(super) fn policy(
        &self,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<crate::agent_broker::HostPolicy> {
        let policy = crate::agent_broker::resolve_known_policy_at_bounded(
            "ssh",
            self.endpoint.user.as_deref(),
            &self.endpoint.host,
            self.endpoint.port,
            Instant::now() + SETUP_TIMEOUT,
            &cancelled,
        )?;
        anyhow::ensure!(
            policy.login_user == self.login,
            "the SSH configuration for {:?} changed during approval",
            self.target
        );
        Ok(policy)
    }

    pub(super) fn setup(&self, policy: &crate::agent_broker::HostPolicy) -> SetupAccount {
        SetupAccount {
            host: self.endpoint.host.clone(),
            port: self.endpoint.port,
            login: self.login.clone(),
            agent: policy.agent_socket().map(Path::to_path_buf),
        }
    }
}

/// Where a request to approve a copy to another server arrives, which
/// decides what its command may select and how this machine reaches the
/// accounts.
pub(crate) enum Origin<'a> {
    /// A receiving connection to the server that asked, which its command
    /// selects by `name`. Enrolling can go through that server, `via` the
    /// login, host and port this machine's receiving connection uses.
    Receiving {
        name: &'a str,
        via: (Option<String>, String, Option<u16>),
    },
    /// A login to this SSH authorization provider, which cannot tell which
    /// server made it. It approves only copies between two other servers:
    /// an upload that selects a provider uses its account access instead.
    Provider,
}

/// Who approves a server's copy to another server here, and what it applies
/// to the copy: a receiving connection's profile, or an SSH authorization
/// provider's.
pub(crate) struct Approver<'a> {
    pub(crate) origin: Origin<'a>,
    /// Who asks, as the prompt names them.
    pub(crate) requester: &'a crate::receive_approval::Requester,
    pub(crate) approvals: &'a crate::receive_approval::Queue,
    pub(crate) notifications: crate::receive_approval::Notifications,
    pub(crate) caps: crate::directive::Caps,
    /// Held while a decision is pending, so that one is pending at a time.
    pub(crate) request_lock: &'a Mutex<()>,
    /// Copies to other servers waiting here for approval or setup.
    pub(crate) forward_count: &'a AtomicUsize,
    /// Whether the request ended: the server that asked went, or approving
    /// stopped.
    pub(crate) cancelled: &'a dyn Fn() -> bool,
}

impl Receiver {
    /// Approve a server's copy to another server, or between two other
    /// servers, as `approve` does, for as long as this receiving connection
    /// and its server last.
    pub(super) fn forward(&self, request: ForwardRequest, mut stream: TrackedStream) -> Result<()> {
        let (generation, _channel) = {
            // Serialize registration with revocation, including reconnects.
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
        Approver {
            origin: Origin::Receiving {
                name: &self.name,
                via: (
                    self.server_user.clone(),
                    self.tcp_peer.host.clone(),
                    self.tcp_peer.port,
                ),
            },
            requester: &self.requester,
            approvals: &self.approvals,
            notifications: self.notifications,
            caps: crate::directive::Caps {
                max_bytes: self.max_bytes,
                max_entries: self.max_entries,
                max_delete: self.max_delete,
            },
            request_lock: &self.request_lock,
            forward_count: &self.forward_count,
            cancelled: &cancelled,
        }
        .approve(request, &mut stream)
    }
}

impl Approver<'_> {
    /// Approve a server's copy to another server, or between two other
    /// servers: show the command, then, over this machine's own SSH, set up
    /// or refresh the accounts' enrollments and sign their directives, and
    /// reply on `stream`. The server connects to the receivers itself; this
    /// machine is not part of the copy after it replies.
    pub(crate) fn approve(&self, request: ForwardRequest, stream: &mut impl Write) -> Result<()> {
        let ForwardRequest {
            source,
            target,
            command,
            cwd,
            inputs,
            results_key,
        } = request;
        // The server waits this long for the reply, from when it asked: the
        // decision, then the setup. Cancellation ends the setup sooner when
        // the server goes.
        let budget = Instant::now() + REQUEST_TIMEOUT + SETUP_TIMEOUT;
        let request_lock = self.request_lock.try_lock().map_err(|_| {
            anyhow::anyhow!("another transfer is awaiting approval; retry after it is decided")
        })?;
        let via = match &self.origin {
            Origin::Receiving { name, via } => {
                crate::approval_command::check_authorizer(&command, name)?;
                Some(via.clone())
            }
            Origin::Provider => {
                anyhow::ensure!(
                    source.is_some(),
                    "an SSH authorization provider approves only copies between two other servers; this copy uses the provider's account access"
                );
                crate::approval_command::check_provider_authorizer(&command)?;
                None
            }
        };
        let args = crate::approval_command::parse(&command)?;
        match &source {
            None => anyhow::ensure!(
                eligible_target(&args)? == target,
                "the requesting command copies to a different server"
            ),
            Some(source) => anyhow::ensure!(
                eligible_peer(&args)? == (source.clone(), target.clone()),
                "the requesting command copies between different servers"
            ),
        }
        // Only the server that starts a copy between two others checks the
        // destination's results itself.
        anyhow::ensure!(
            results_key.is_some() == source.is_some(),
            "invalid request to approve a copy to another server"
        );
        let caps = self.caps;
        // The rules the receiver will derive, before the server's home is
        // known: the prompt names the destination as the command does.
        let preview = crate::directive::issue(
            crate::directive::Binding {
                enrollment: crate::enrollment::EnrollmentId::random(),
                generation: 1,
                account: "preview".into(),
                role: crate::directive::Role::Destination,
            },
            command.clone(),
            cwd.clone(),
            (inputs.clone(), Some(caps)),
            // Unused: the preview has no results.
            [1; 32],
        )?;
        let (rules, constraints) = crate::directive::destination_rules(
            &preview,
            Path::new(std::ffi::OsStr::from_bytes(REQUEST_ROOT)),
        )?;
        let max_delete = caps.deletion_ceiling(&rules.copy);
        let request = CopyRequest {
            destination: args
                .locations
                .last()
                .context("copy destination missing")?
                .path
                .clone(),
            copy: rules.copy,
            constraints,
        };
        let count = self.forward_count.fetch_add(1, Ordering::AcqRel);
        let _slot = Slot(self.forward_count);
        if count >= 8 {
            bail!("too many copies to other servers are waiting for approval or setup here; retry after one is decided");
        }
        let cancelled = self.cancelled;
        let destination = Account::find(&target, &cancelled)?;
        let source = source
            .as_deref()
            .map(|source| Account::find(source, &cancelled))
            .transpose()?;
        match &source {
            None => destination.refuse_root(
                "to",
                &format!(
                    "copy to an ordinary account on {host}, or use the requesting server's own SSH access, or account access approved with `syq persist connect {account} --auth-from @NAME`",
                    host = destination.endpoint.host,
                    account = destination.label()
                ),
            )?,
            Some(source) => {
                let advice = "use an ordinary account there, or copy through the requesting server with `--coordinate-at local`, which needs account access to both servers";
                source.refuse_root("from", advice)?;
                destination.refuse_root("to", advice)?;
            }
        }
        if args.dry_run {
            for account in source.iter().chain([&destination]) {
                account.ready_for_dry_run()?;
            }
        }
        // Automatic approval of writes to this machine does not authorize
        // use of its SSH credentials on another host.
        self.approvals.request_remote(
            self.requester,
            &command,
            &cwd,
            crate::receive_approval::Remote {
                target: &target,
                enrollment: destination.enrollment,
                source: source
                    .as_ref()
                    .map(|source| (source.target.as_str(), source.enrollment)),
            },
            &request,
            self.notifications,
            cancelled,
        )?;
        anyhow::ensure!(!cancelled(), "remote copy disconnected before setup");
        // This lock only serializes decisions, not enrollment.
        drop(request_lock);
        let destination_policy = destination.policy(&cancelled)?;
        let source_policy = source
            .as_ref()
            .map(|source| source.policy(&cancelled))
            .transpose()?;
        // The destination's known hosts go to the server that dials it: the
        // source, in its signed directive, or the server that asked.
        let destination_known_hosts = destination_policy.known_hosts_for_others()?;
        let mut setup = crate::process::self_command()?;
        setup.arg("--return-prepare");
        let prepared = prepare_in_child(
            setup,
            &Prepare {
                command,
                cwd,
                inputs,
                caps,
                accounts: match source.as_ref().zip(source_policy.as_ref()) {
                    None => Accounts::Destination(destination.setup(&destination_policy)),
                    Some((source, policy)) => Accounts::BetweenServers {
                        source: source.setup(policy),
                        destination: destination.setup(&destination_policy),
                        known_hosts: destination_known_hosts.clone(),
                    },
                },
                results_key,
                via,
                allow_enrollment: !args.dry_run,
            },
            // Setting restricted copying up can upload syq, which takes a
            // while on a slow link: give it what is left of the server's
            // wait, not only the time after the decision.
            budget,
            &cancelled,
        )
        .with_context(|| format!("approve the copy to {target:?}"))?;
        anyhow::ensure!(!cancelled(), "remote copy disconnected before setup");
        let coordinated = match (prepared.source, source_policy) {
            (Some(signed), Some(policy)) => Some(Coordinated {
                directive: signed.directive,
                entry_key: signed.entry_key,
                login: policy.login_user.clone(),
                known_hosts: policy.known_hosts_for_others()?,
                known_hosts_left_out: policy.left_out_kind().map(str::to_owned),
                results_public_key: signed.results.public_key,
                enrollment: signed.results.enrollment,
                request: signed.results.request,
                digest: signed.results.digest,
            }),
            (None, None) => None,
            _ => bail!("the copy's setup did not sign its source's directive"),
        };
        let issued = Issued {
            directive: prepared.directive,
            entry_key: prepared.entry_key,
            login: destination_policy.login_user.clone(),
            known_hosts: destination_known_hosts,
            // The configured value stays here: it can hold commands and paths.
            known_hosts_left_out: destination_policy.left_out_kind().map(str::to_owned),
            destination: prepared.destination,
            max_delete,
            coordinated,
        };
        write_message(stream, &Reply::Directive(Box::new(issued)))
    }
}

/// What the receiving service's setup child needs to set up or refresh the
/// accounts' enrollments and sign an approved copy's directives.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Prepare {
    pub(super) command: Vec<Vec<u8>>,
    pub(super) cwd: String,
    pub(super) inputs: crate::directive::Inputs,
    pub(super) caps: crate::directive::Caps,
    pub(super) accounts: Accounts,
    /// The requester's key for the destination's results, when it checks
    /// them.
    pub(super) results_key: Option<[u8; 32]>,
    /// The server that asked, as this machine's receiving connection logs
    /// in to it: its user, if named, host and port. None for an SSH
    /// authorization provider, which cannot tell which server asked.
    pub(super) via: Option<(Option<String>, String, Option<u16>)>,
    pub(super) allow_enrollment: bool,
}

/// The accounts an approved copy has directives for.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) enum Accounts {
    /// The destination of a copy from the server that asked.
    Destination(SetupAccount),
    /// A copy between two other servers: the source, which coordinates it,
    /// the destination, and what this machine's known_hosts files say about
    /// the destination, which the source's directive carries.
    BetweenServers {
        source: SetupAccount,
        destination: SetupAccount,
        known_hosts: String,
    },
    /// The source of a copy to the server that asked.
    Source(SetupAccount),
}

impl Accounts {
    fn all(&self) -> Vec<&SetupAccount> {
        match self {
            Self::Destination(account) | Self::Source(account) => vec![account],
            Self::BetweenServers {
                source,
                destination,
                ..
            } => vec![source, destination],
        }
    }
}

/// An account the setup child enrolls and signs a directive for.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SetupAccount {
    host: String,
    port: Option<u16>,
    login: String,
    agent: Option<PathBuf>,
}

impl SetupAccount {
    fn label(&self) -> String {
        format!("{}@{}", self.login, self.host)
    }
}

impl Prepare {
    fn issue<'a>(
        &'a self,
        account: &'a SetupAccount,
        role: crate::directive::Role,
    ) -> Result<crate::restricted::Issue<'a>> {
        Ok(crate::restricted::Issue {
            command: self.command.clone(),
            cwd: self.cwd.clone(),
            inputs: self.inputs.clone(),
            caps: Some(self.caps),
            host: &account.host,
            port: account.port,
            login: &account.login,
            // Enrolling goes through the server that asked when this
            // machine cannot reach the account along its own SSH
            // configuration's route, as a copy started on this machine goes
            // through its source. An upload needs that server to reach the
            // destination's SSH port anyway, and a download, or a copy
            // between two other servers, needs it to reach the source's; for
            // the destination of such a copy, the hop works only if it
            // reaches that too, as the docs say. A provider cannot tell which
            // server asked, so it enrolls only along its own route.
            jump: self
                .via
                .as_ref()
                .map(|(user, host, port)| {
                    crate::enrollment::SshEndpoint::from_host(user.as_deref(), host, *port)
                })
                .transpose()?,
            agent: account.agent.as_deref(),
            allow_enrollment: self.allow_enrollment,
            // This server's own syq connects to the receiver: a refusal for
            // its build is that server's, which no refresh here changes.
            retry_of: None,
            // No terminal: never prompt. Where the SSH configuration
            // would ask about a host key nobody knows, accept it the first
            // time, as `accept-new` does.
            batch: true,
            results_key: self.results_key,
            role,
        })
    }

    /// Set up or refresh the enrollments and sign the directives: for a
    /// copy between two other servers, the destination's first, which the
    /// source's names.
    fn sign(&self) -> Result<Signed> {
        use crate::directive::Role;
        let (account, known_hosts) = match &self.accounts {
            Accounts::Source(account) => {
                let source =
                    crate::restricted::prepare_transfer(self.issue(account, Role::Source)?)?;
                return Ok(Signed {
                    directive: source.directive,
                    entry_key: EntryKeyText::of(&source.entry_key)?,
                    destination: Vec::new(),
                    source: None,
                });
            }
            Accounts::Destination(account) => (account, None),
            Accounts::BetweenServers {
                destination,
                known_hosts,
                ..
            } => (destination, Some(known_hosts)),
        };
        let destination =
            crate::restricted::prepare_transfer(self.issue(account, Role::Destination)?)?;
        let source = match (&self.accounts, known_hosts) {
            (Accounts::BetweenServers { source, .. }, Some(known_hosts)) => {
                let peer = crate::directive::Peer {
                    enrollment: destination.enrollment_id,
                    generation: destination.generation,
                    account: account.login.clone(),
                    request: destination.request_id,
                    destination: destination.destination.clone(),
                    known_hosts: known_hosts.clone(),
                };
                let signed = crate::restricted::prepare_transfer(
                    self.issue(source, Role::CoordinatingSource(peer))?,
                )?;
                Some(SignedSource {
                    directive: signed.directive,
                    entry_key: EntryKeyText::of(&signed.entry_key)?,
                    results: Results {
                        public_key: destination.results_public_key.clone(),
                        enrollment: destination.enrollment_id,
                        request: destination.request_id,
                        digest: destination.digest,
                    },
                })
            }
            _ => None,
        };
        Ok(Signed {
            directive: destination.directive,
            entry_key: EntryKeyText::of(&destination.entry_key)?,
            destination: destination.destination,
            source,
        })
    }
}

/// The setup child's answer.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum Prepared {
    Signed(Signed),
    Refused(String),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Signed {
    pub(super) directive: String,
    pub(super) entry_key: EntryKeyText,
    /// Where the destination's rules write, for a destination's directive.
    destination: Vec<u8>,
    /// For a copy between two other servers, the source's directive.
    source: Option<SignedSource>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Results {
    public_key: String,
    enrollment: crate::enrollment::EnrollmentId,
    request: crate::delegation::RequestId,
    digest: [u8; 32],
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedSource {
    directive: String,
    entry_key: EntryKeyText,
    /// What the requester checks the destination's results with.
    results: Results,
}

/// Set up the enrollments and sign the directives in the setup child
/// `command`, until `deadline` or until `cancelled`. Then the child ends
/// with everything in its process group, its SSH logins included, which
/// releases the enrollment lock and any wait for the SSH agent with it.
pub(super) fn prepare_in_child(
    command: Command,
    request: &Prepare,
    deadline: Instant,
    cancelled: &dyn Fn() -> bool,
) -> Result<Signed> {
    let mut child = ForwardChild::spawn_command(command)?;
    let reply = (|| -> Result<Prepared> {
        let mut input = child.child.stdin.take().context("setup input missing")?;
        write_message(
            &mut DeadlineIo {
                inner: &mut input,
                deadline,
                cancelled: Some(cancelled),
            },
            request,
        )?;
        drop(input);
        read_message(&mut DeadlineIo {
            inner: child.child.stdout.as_mut().unwrap(),
            deadline,
            cancelled: Some(cancelled),
        })
    })();
    let status = child.close();
    // The setup's own SSH writes its errors, and the remote installer's,
    // here; its login's reasons are already in the reply.
    let wrote = !child.errors.lock().unwrap().is_empty();
    let output = if wrote {
        format!("; its output: {}", child.errors())
    } else {
        String::new()
    };
    match reply {
        Ok(Prepared::Signed(signed)) => Ok(signed),
        Ok(Prepared::Refused(error)) => Err(anyhow::anyhow!("{error}{output}")),
        Err(error) if Instant::now() >= deadline => {
            let accounts = request
                .accounts
                .all()
                .into_iter()
                .map(|account| format!("`syq receiver enroll {}`", account.label()))
                .collect::<Vec<_>>()
                .join(" and ");
            Err(error).with_context(|| {
                format!(
                    "the copy's setup did not finish while the server waited{output}. If it was setting up or updating restricted copying, run {accounts} on this machine, which has no time limit, then try the copy again"
                )
            })
        }
        Err(error) => Err(error)
            .with_context(|| format!("the copy's setup stopped ({status:?}): {}", child.errors())),
    }
}

/// The receiving service's setup child (`--return-prepare`): set up or
/// refresh the enrollments and sign the directives. Its parent ends it,
/// with its process group, at the setup deadline or when the requester
/// goes.
fn prepare_setup() -> Result<i32> {
    let request: Prepare = read_message(&mut std::io::stdin().lock())?;
    let reply = match request.sign() {
        Ok(signed) => Prepared::Signed(signed),
        Err(error) => Prepared::Refused(format!("{error:#}")),
    };
    let mut output = std::io::stdout().lock();
    write_message(&mut output, &reply)?;
    output.flush()?;
    Ok(0)
}

/// Kill before reaping, including bootstrap/ProxyCommand descendants. Capture
/// is bounded while the complete pipe is drained; diagnostics never block SSH.
pub(super) struct ForwardChild {
    pub(super) child: Child,
    errors: Arc<Mutex<Vec<u8>>>,
    capture: Option<std::thread::JoinHandle<()>>,
    closed: bool,
}
impl ForwardChild {
    pub(super) fn wait_for_exit(
        &mut self,
        deadline: Instant,
        cancelled: &impl Fn() -> bool,
    ) -> Result<std::process::ExitStatus> {
        loop {
            // Observe without reaping, so cleanup can still kill descendants
            // without allowing the leader's PID to be reused for another group.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let result = unsafe {
                libc::waitid(
                    libc::P_PID,
                    self.child.id(),
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if result < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error.into());
            }
            if info.si_signo != 0 {
                return Ok(self.close()?);
            }
            if cancelled() {
                let _ = self.close();
                bail!("return helper cancelled while waiting for its exit status");
            }
            if Instant::now() >= deadline {
                let _ = self.close();
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "return helper deadline expired while waiting for its exit status",
                )
                .into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    pub(super) fn spawn_command(mut command: Command) -> Result<Self> {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn_guarded()?;
        let mut stderr = child.stderr.take().unwrap();
        let errors = Arc::new(Mutex::new(Vec::new()));
        let captured = errors.clone();
        let capture = std::thread::spawn(move || {
            let mut bytes = [0; 1024];
            while let Ok(count) = stderr.read(&mut bytes) {
                if count == 0 {
                    break;
                }
                let mut output = captured.lock().unwrap();
                output.extend_from_slice(&bytes[..count]);
                if output.len() > 4096 {
                    let excess = output.len() - 4096;
                    output.drain(..excess);
                }
            }
        });
        Ok(Self {
            child,
            errors,
            capture: Some(capture),
            closed: false,
        })
    }
    fn close(&mut self) -> std::io::Result<std::process::ExitStatus> {
        if !self.closed {
            self.closed = true;
            unsafe {
                libc::kill(-(self.child.id() as i32), libc::SIGKILL);
            }
        }
        let status = self.child.wait();
        if let Some(capture) = self.capture.take() {
            let _ = capture.join();
        }
        status
    }
    pub(super) fn errors(&self) -> String {
        format!(
            "{:?}",
            String::from_utf8_lossy(&self.errors.lock().unwrap())
        )
    }
}
impl Drop for ForwardChild {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

pub(crate) struct DeadlineIo<'a, T> {
    pub(crate) inner: &'a mut T,
    pub(crate) deadline: Instant,
    pub(crate) cancelled: Option<&'a dyn Fn() -> bool>,
}
impl<T: Read + AsRawFd> Read for DeadlineIo<'_, T> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        wait_fd(
            self.inner.as_raw_fd(),
            libc::POLLIN,
            self.deadline,
            self.cancelled,
        )?;
        self.inner.read(bytes)
    }
}
impl<T: Write + AsRawFd> Write for DeadlineIo<'_, T> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        wait_fd(
            self.inner.as_raw_fd(),
            libc::POLLOUT,
            self.deadline,
            self.cancelled,
        )?;
        self.inner.write(&bytes[..bytes.len().min(512)])
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

pub(crate) struct HandshakeInput<R> {
    inner: R,
    pending: Arc<AtomicBool>,
    deadline: Instant,
    hello_timeout: Duration,
    started: bool,
}
impl<R> HandshakeInput<R> {
    pub(crate) fn new(
        inner: R,
        pending: Arc<AtomicBool>,
        start_timeout: Duration,
        hello_timeout: Duration,
    ) -> Self {
        Self {
            inner,
            pending,
            deadline: Instant::now() + start_timeout,
            hello_timeout,
            started: false,
        }
    }
}
impl<R: Read + AsRawFd> Read for HandshakeInput<R> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        if self.pending.load(Ordering::Acquire) {
            wait_fd(self.inner.as_raw_fd(), libc::POLLIN, self.deadline, None)?;
        }
        let count = self.inner.read(bytes)?;
        if count > 0 && !self.started {
            // Preparing the source and reaching us through the return relay is
            // separate from completing Hello. Neither phase can wait forever,
            // and subsequent partial bytes never extend the Hello deadline.
            self.started = true;
            self.deadline = Instant::now() + self.hello_timeout;
        }
        Ok(count)
    }
}

/// The SSH route this machine's configuration gives `target`, for reading
/// that configuration without contacting the server.
pub(super) fn target_spec(target: &str) -> Result<crate::conn::RemoteSpec> {
    let endpoint = target_endpoint(target)?;
    Ok(crate::conn::RemoteSpec {
        local_process: false,
        user: endpoint.user,
        host: endpoint.host,
        port: endpoint.port,
        // A return connection needs its explicit remote forwarding. This
        // outbound copy needs no forwarding and must not ask about host keys
        // from the background service. RemoteSpec disables multiplexing.
        rsh: std::iter::once("ssh")
            .chain(RETURN_SSH_OPTIONS.iter().copied())
            .chain([
                "-o",
                "ClearAllForwardings=yes",
                "-o",
                "StrictHostKeyChecking=yes",
            ])
            .map(str::to_owned)
            .collect(),
        syq_path: None,
        bootstrap_helper: true,
        restricted_grant: None,
        helper_install: Default::default(),
        ssh_multiplexer: None,
        quiet: true,
        pacing: Default::default(),
        tcp: Default::default(),
        diagnostics: Default::default(),
        primed_control: Default::default(),
        receiver_host: None,
        read_ahead: crate::transfer_tuning::DEFAULT_PIPELINE_DEPTH,
    })
}

/// What `ssh -G` prints for a target, within the setup's deadline.
fn read_ssh_configuration(
    command: Command,
    deadline: Instant,
    cancelled: &dyn Fn() -> bool,
) -> Result<String> {
    // Reuse helper process-group ownership, bounded stderr capture, and the
    // setup's absolute deadline. A local Match exec must not outlive revocation.
    let mut child = ForwardChild::spawn_command(command)?;
    drop(child.child.stdin.take());
    let mut output = Vec::new();
    DeadlineIo {
        inner: child.child.stdout.as_mut().unwrap(),
        deadline,
        cancelled: Some(cancelled),
    }
    .take(MAX_MESSAGE as u64 + 1)
    .read_to_end(&mut output)?;
    anyhow::ensure!(
        output.len() <= MAX_MESSAGE,
        "SSH configuration output is too large"
    );
    let status = child.wait_for_exit(deadline, &cancelled)?;
    anyhow::ensure!(
        status.success(),
        "resolve the SSH configuration: {}",
        child.errors()
    );
    String::from_utf8(output).context("SSH configuration is not UTF-8")
}

pub(super) fn dispatch(argv: &[OsString]) -> Option<Result<i32>> {
    match argv.get(1).and_then(|v| v.to_str())? {
        "--return-source-probe" | "--return-send-probe" if argv.len() == 2 => Some(Ok(0)),
        "--return-prepare" if argv.len() == 2 => Some(prepare_setup()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::destination::tests::{args, broker};

    fn prepare_request() -> Prepare {
        Prepare {
            command: vec![b"cp".to_vec()],
            cwd: "~".into(),
            inputs: Default::default(),
            caps: crate::directive::Caps {
                max_bytes: 1,
                max_entries: 1,
                max_delete: 0,
            },
            accounts: Accounts::Destination(SetupAccount {
                host: "backup".into(),
                port: None,
                login: "alice".into(),
                agent: None,
            }),
            results_key: None,
            via: Some((None, "server".into(), None)),
            allow_enrollment: true,
        }
    }

    /// Whether `pid` has ended: gone, or a zombie its new parent has not
    /// reaped yet.
    fn ended(pid: libc::pid_t) -> bool {
        if unsafe { libc::kill(pid, 0) } != 0 {
            return true;
        }
        Command::new("ps")
            .args(["-o", "stat=", "-p", &pid.to_string()])
            .output()
            .is_ok_and(|output| output.stdout.trim_ascii().starts_with(b"Z"))
    }

    #[test]
    fn the_setup_child_ends_with_its_group_at_the_deadline_or_when_the_requester_goes() {
        let temporary = crate::test_support::tempdir().unwrap();
        for requester_goes in [false, true] {
            // A child whose own login waits on a server that stopped
            // answering, as enrollment's SSH does in the child's group.
            let pid_file = temporary.path().join(format!("login-{requester_goes}"));
            let mut command = Command::new("sh");
            command.args([
                "-c",
                &format!(
                    "sleep 60 & echo $! > {}; wait",
                    shell_words::quote(pid_file.to_str().unwrap())
                ),
            ]);
            let started = Instant::now();
            let deadline = started
                + if requester_goes {
                    Duration::from_secs(60)
                } else {
                    Duration::from_millis(500)
                };
            let cancelled = || requester_goes && started.elapsed() >= Duration::from_millis(500);
            let error = prepare_in_child(command, &prepare_request(), deadline, &cancelled)
                .err()
                .unwrap();
            assert!(started.elapsed() < Duration::from_secs(10), "{error:#}");
            // Running out of time says how to set up without a time limit;
            // a requester that went needs nothing more.
            assert_eq!(
                format!("{error:#}")
                    .contains("run `syq receiver enroll alice@backup` on this machine"),
                !requester_goes,
                "{error:#}"
            );
            let pid: libc::pid_t = std::fs::read_to_string(&pid_file)
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            let waited = Instant::now();
            while !ended(pid) {
                assert!(
                    waited.elapsed() < Duration::from_secs(5),
                    "the child's login outlived it"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }

    #[test]
    fn a_refused_setup_keeps_what_the_child_wrote() {
        let temporary = crate::test_support::tempdir().unwrap();
        let reply = temporary.path().join("reply");
        let mut frame = Vec::new();
        write_message(
            &mut frame,
            &Prepared::Refused("restricted enrollment SSH to alice@backup failed".into()),
        )
        .unwrap();
        std::fs::write(&reply, frame).unwrap();
        let mut command = Command::new("sh");
        command.args([
            "-c",
            &format!(
                "cat > /dev/null; echo 'installer: no space left' >&2; cat {}",
                shell_words::quote(reply.to_str().unwrap())
            ),
        ]);
        let error = prepare_in_child(
            command,
            &prepare_request(),
            Instant::now() + Duration::from_secs(30),
            &|| false,
        )
        .err()
        .unwrap();
        let message = format!("{error:#}");
        assert!(
            message.starts_with("restricted enrollment SSH to alice@backup failed"),
            "{message}"
        );
        assert!(message.contains("installer: no space left"), "{message}");
    }

    #[test]
    fn the_setup_child_enrolls_without_prompts_and_through_the_server_that_asked() {
        let request = prepare_request();
        let account = &request.accounts.all()[0];
        let issue = request
            .issue(account, crate::directive::Role::Destination)
            .unwrap();
        assert!(issue.batch);
        assert_eq!(issue.caps, Some(request.caps));
        assert_eq!(issue.jump.unwrap().label(), "server");
        let mut named = prepare_request();
        named.via = Some((Some("alice".into()), "server".into(), Some(2222)));
        let issue = |request: &Prepare| {
            request
                .issue(request.accounts.all()[0], crate::directive::Role::Source)
                .map(|issue| issue.jump.unwrap().label())
        };
        assert_eq!(issue(&named).unwrap(), "alice@server:2222");
        named.via = Some((None, "-oProxyCommand=evil".into(), None));
        assert!(issue(&named).is_err());
    }

    #[test]
    fn hello_has_a_separate_start_budget_and_partial_bytes_do_not_extend_it() {
        let (reader, mut writer) = UnixStream::pair().unwrap();
        let pending = Arc::new(AtomicBool::new(true));
        let mut input = HandshakeInput::new(
            reader,
            pending,
            Duration::from_secs(2),
            Duration::from_millis(150),
        );
        // Source preparation may exceed the entire Hello budget.
        std::thread::sleep(Duration::from_millis(200));
        writer.write_all(b"a").unwrap();
        let mut byte = [0];
        input.read_exact(&mut byte).unwrap();
        assert_eq!(byte, *b"a");
        let sender = std::thread::spawn(move || {
            for _ in 0..8 {
                std::thread::sleep(Duration::from_millis(40));
                if writer.write_all(b"b").is_err() {
                    break;
                }
            }
        });
        let error = input.read_exact(&mut [0; 8]).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        drop(input);
        sender.join().unwrap();
    }

    #[test]
    fn an_idle_hello_expires_but_completed_transfers_have_no_hello_deadline() {
        let (reader, mut writer) = UnixStream::pair().unwrap();
        let pending = Arc::new(AtomicBool::new(true));
        let mut input = HandshakeInput::new(
            reader,
            pending.clone(),
            Duration::from_millis(20),
            Duration::from_millis(20),
        );
        assert_eq!(input.read(&mut []).unwrap(), 0);
        let error = input.read(&mut [0]).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        // Once the server has accepted Hello, the reader belongs to the copy.
        pending.store(false, Ordering::Release);
        writer.write_all(b"data").unwrap();
        let mut bytes = [0; 4];
        input.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"data");
    }

    #[test]
    fn helper_exit_status_and_stderr_survive_group_cleanup() {
        let mut command = Command::new("sh");
        // A descendant keeps stderr open after the launcher has exited.
        command.args(["-c", "sleep 30 & printf missing >&2; exit 125"]);
        let mut child = ForwardChild::spawn_command(command).unwrap();
        let status = child
            .wait_for_exit(Instant::now() + Duration::from_secs(2), &|| false)
            .unwrap();
        assert_eq!(
            status.code(),
            Some(crate::remote_helper::HELPER_MISSING_EXIT)
        );
        assert_eq!(child.errors(), "\"missing\"");
        assert_eq!(child.close().unwrap(), status);
    }

    #[test]
    fn helper_exit_wait_remains_bounded_and_cancellable() {
        for cancel in [false, true] {
            let mut command = Command::new("sh");
            command.args(["-c", "sleep 30"]);
            let mut child = ForwardChild::spawn_command(command).unwrap();
            let started = Instant::now();
            assert!(child
                .wait_for_exit(started + Duration::from_millis(20), &|| cancel)
                .is_err());
            assert!(started.elapsed() < Duration::from_secs(2));
            assert!(child.child.try_wait().unwrap().is_some());
        }
    }

    #[test]
    fn remote_targets_are_endpoints_not_shell_or_ssh_options() {
        for target in ["backup", "alice@backup:2222", "alice@[2001:db8::1]:22"] {
            assert!(target_endpoint(target).is_ok(), "{target}");
        }
        for target in [
            "@laptop",
            "-oProxyCommand=evil",
            "a$(id)",
            "user`id`@host",
            "user;id@host",
            "a\nHost *",
            "a/b",
            "x@host:0",
        ] {
            assert!(target_endpoint(target).is_err(), "{target}");
        }
    }

    #[test]
    fn return_authorization_uses_the_restricted_worker_limit() {
        let root = crate::test_support::tempdir().unwrap();
        let mut args = args(root.path(), "output");
        for workers in [1, 32, 64, 128] {
            args.connections_opt = Some(workers);
            args.connections = workers;
            assert_eq!(eligible_target(&args).unwrap(), "server");
        }
        args.connections_opt = Some(129);
        args.connections = 129;
        assert!(eligible_target(&args).is_err());
    }

    /// As on other routes to an ordinary account, ownership, special files
    /// and `--in-place=new` are accepted.
    #[test]
    fn return_authorization_accepts_ownership_special_files_and_in_place() {
        let root = crate::test_support::tempdir().unwrap();
        let mut args = args(root.path(), "output");
        args.owner = true;
        args.group = true;
        args.devices = true;
        assert_eq!(eligible_target(&args).unwrap(), "server");
        // Pruning states no limit of its own; the approving machine's applies.
        args.delete = true;
        assert_eq!(eligible_target(&args).unwrap(), "server");
        args.inplace = true;
        assert_eq!(eligible_target(&args).unwrap(), "server");
    }

    fn forward_command(source: &Path) -> Vec<Vec<u8>> {
        let source = source.as_os_str().as_bytes().to_vec();
        [b"cp".to_vec(), b"--src".to_vec(), source]
            .into_iter()
            .chain(
                ["--to", "backup", "--into", "output"]
                    .iter()
                    .map(|arg| arg.as_bytes().to_vec()),
            )
            .collect()
    }

    #[test]
    fn forward_validation_precedes_approval_and_outbound_ssh() {
        let root = crate::test_support::tempdir().unwrap();
        let (_broker, receiver, registration, _) = broker(root.path(), Approval::Always);
        let valid = forward_command(root.path());
        let with = |extra: &[&str]| {
            let mut command = valid.clone();
            command.extend(extra.iter().map(|arg| arg.as_bytes().to_vec()));
            command
        };
        let inputs = crate::directive::Inputs::default();
        let cases = [
            // Not a plain SSH endpoint.
            ("bad$(command)", valid.clone(), inputs.clone()),
            // The command copies to another server than the one named.
            ("elsewhere", valid.clone(), inputs.clone()),
            // Options this route refuses, and rules the receiver could
            // not derive.
            ("backup", with(&["--rsh", "ssh"]), inputs.clone()),
            (
                "backup",
                with(&["--receiver-max-entries", "0"]),
                inputs.clone(),
            ),
            // What the server read from files is bounded too.
            (
                "backup",
                with(&["--ignore", "*.tmp"]),
                crate::directive::Inputs {
                    ignore: vec!["a\0b".into()],
                    mapping: None,
                },
            ),
            (
                "backup",
                valid.clone(),
                crate::directive::Inputs {
                    ignore: Vec::new(),
                    mapping: Some(crate::mapping::Authorization {
                        bytes: 1,
                        digest: [0; 32],
                    }),
                },
            ),
        ];
        for (target, command, inputs) in cases {
            assert!(exchange(
                &registration,
                Message::Forward(Box::new(ForwardRequest {
                    source: None,
                    target: target.into(),
                    command: command.clone(),
                    cwd: String::new(),
                    inputs,
                    results_key: None,
                })),
                Duration::from_secs(2),
                Some(Duration::from_secs(2))
            )
            .is_err());
            assert!(receiver.approvals.snapshots().is_empty());
        }
        assert_eq!(receiver.forward_count.load(Ordering::Acquire), 0);
    }

    /// A root login on the destination is refused before anything is asked
    /// or set up, with advice that fits an upload.
    #[test]
    fn a_root_destination_is_refused_before_the_prompt() {
        let root = crate::test_support::tempdir().unwrap();
        let (_broker, receiver, registration, _) = broker(root.path(), Approval::Always);
        let source = root.path().as_os_str().as_bytes().to_vec();
        let command = [b"cp".to_vec(), b"--src".to_vec(), source]
            .into_iter()
            .chain(
                ["--to", "root@backup", "--into", "output"]
                    .iter()
                    .map(|arg| arg.as_bytes().to_vec()),
            )
            .collect();
        let error = exchange(
            &registration,
            Message::Forward(Box::new(ForwardRequest {
                source: None,
                target: "root@backup".into(),
                command,
                cwd: String::new(),
                inputs: crate::directive::Inputs::default(),
                results_key: None,
            })),
            Duration::from_secs(2),
            Some(Duration::from_secs(2)),
        )
        .err()
        .unwrap();
        let message = format!("{error:#}");
        for expected in [
            "does not write or run copies as root",
            "a copy to root@backup",
            "copy to an ordinary account on backup",
        ] {
            assert!(message.contains(expected), "{expected}: {message}");
        }
        assert!(!message.contains("--coordinate-at"), "{message}");
        assert!(receiver.approvals.snapshots().is_empty());
    }

    #[test]
    fn forward_always_requires_a_local_decision_and_revocation_cancels_it() {
        for revoke in [false, true] {
            let root = crate::test_support::tempdir().unwrap();
            let (_broker, receiver, registration, _) = broker(root.path(), Approval::Always);
            let command = forward_command(root.path());
            let task = std::thread::spawn(move || {
                exchange(
                    &registration,
                    Message::Forward(Box::new(ForwardRequest {
                        source: None,
                        target: "backup".into(),
                        command,
                        cwd: "~/rt-bench".into(),
                        inputs: crate::directive::Inputs::default(),
                        results_key: None,
                    })),
                    Duration::from_secs(3),
                    Some(Duration::from_secs(3)),
                )
            });
            let deadline = Instant::now() + Duration::from_secs(2);
            let pending = loop {
                if let Some(summary) = receiver.approvals.snapshots().first() {
                    break summary.clone();
                }
                if task.is_finished() {
                    panic!("forward request ended: {:?}", task.join().unwrap().err());
                }
                assert!(
                    Instant::now() < deadline,
                    "forward request did not become pending"
                );
                std::thread::sleep(Duration::from_millis(5));
            };
            let description =
                pending.description(&crate::persistence::Domain::default(), str::to_owned);
            assert!(description.contains("backup"));
            assert!(description.contains("output"));
            assert!(description.contains("SSH access"));
            if revoke {
                receiver.revoke_all();
            } else {
                receiver
                    .approvals
                    .decide(&pending.id, false, crate::receive_approval::Kind::Copy)
                    .unwrap();
            }
            assert!(task.join().unwrap().is_err());
            let deadline = Instant::now() + Duration::from_secs(2);
            while receiver.forward_count.load(Ordering::Acquire) != 0 {
                assert!(
                    Instant::now() < deadline,
                    "forward request did not release its slot"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            assert!(receiver.approvals.snapshots().is_empty());
        }
    }

    fn between_servers_command(extra: &[&str]) -> Vec<Vec<u8>> {
        [
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
        .iter()
        .chain(extra)
        .map(|arg| arg.as_bytes().to_vec())
        .collect()
    }

    /// A copy between two other servers is refused before any prompt when
    /// its request does not match its command, and only the server that
    /// started it, which checks the destination's results, sends a key for
    /// them.
    #[test]
    fn a_copy_between_servers_is_validated_before_approval() {
        let root = crate::test_support::tempdir().unwrap();
        let (_broker, receiver, registration, _) = broker(root.path(), Approval::Always);
        let request = |source: Option<&str>, target: &str, command, results_key| {
            Message::Forward(Box::new(ForwardRequest {
                source: source.map(str::to_owned),
                target: target.into(),
                command,
                cwd: String::new(),
                inputs: crate::directive::Inputs::default(),
                results_key,
            }))
        };
        let key = Some([5; 32]);
        let cases = [
            // Another source or destination than the command's.
            request(
                Some("elsewhere"),
                "backup",
                between_servers_command(&[]),
                key,
            ),
            request(
                Some("reader@source-host"),
                "elsewhere",
                between_servers_command(&[]),
                key,
            ),
            // No source, for a command that names one, and the reverse.
            request(None, "backup", between_servers_command(&[]), None),
            request(
                Some("reader@source-host"),
                "backup",
                forward_command(root.path()),
                key,
            ),
            // The results key only with a source, and always with one.
            request(
                Some("reader@source-host"),
                "backup",
                between_servers_command(&[]),
                None,
            ),
            request(None, "backup", forward_command(root.path()), key),
            // Options this route refuses.
            request(
                Some("reader@source-host"),
                "backup",
                between_servers_command(&["--detach"]),
                key,
            ),
            request(
                Some("reader@source-host"),
                "backup",
                between_servers_command(&["--coordinate-at", "dst"]),
                key,
            ),
            // A command that selects an SSH authorization provider.
            request(
                Some("reader@source-host"),
                "backup",
                between_servers_command(&["--auth-from", "alice@provider"]),
                key,
            ),
            // A mapping would choose which source files are read, unseen.
            Message::Forward(Box::new(ForwardRequest {
                source: Some("reader@source-host".into()),
                target: "backup".into(),
                command: [
                    "cp",
                    "--from",
                    "reader@source-host",
                    "--mapping",
                    "map",
                    "--to",
                    "backup",
                    "--into",
                    "output",
                ]
                .map(|arg| arg.as_bytes().to_vec())
                .to_vec(),
                cwd: String::new(),
                inputs: crate::directive::Inputs {
                    ignore: Vec::new(),
                    mapping: Some(crate::mapping::Authorization {
                        bytes: 1,
                        digest: [0; 32],
                    }),
                },
                results_key: key,
            })),
        ];
        for message in cases {
            assert!(exchange(
                &registration,
                message,
                Duration::from_secs(2),
                Some(Duration::from_secs(2))
            )
            .is_err());
            assert!(receiver.approvals.snapshots().is_empty());
        }
        assert_eq!(receiver.forward_count.load(Ordering::Acquire), 0);
    }

    /// The approving machine says which of its host-key settings each
    /// server's check goes without, naming which server checks, and nothing
    /// for a check that has everything.
    #[test]
    fn omitted_host_key_settings_name_the_server_that_checks() {
        assert!(left_out_notices(("hostB", None), ("hostC", None)).is_empty());
        assert_eq!(
            left_out_notices(("hostB", None), ("hostC", Some("KnownHostsCommand\n"))),
            ["syq: hostB checks hostC's host key without some of what the approving machine knows about it: KnownHostsCommand"]
        );
        assert_eq!(
            left_out_notices(("hostB", Some("RevokedHostKeys")), ("hostC", None)),
            ["syq: checking hostB's host key without some of what the approving machine knows about it: RevokedHostKeys"]
        );
        assert_eq!(
            left_out_notices(
                ("hostB", Some("RevokedHostKeys")),
                ("hostC", Some("KnownHostsCommand"))
            )
            .len(),
            2
        );
    }

    /// One prompt approves a copy between two other servers: it names both,
    /// the files on the source, and that the source runs the copy.
    #[test]
    fn a_copy_between_servers_asks_once_naming_both() {
        let root = crate::test_support::tempdir().unwrap();
        let (_broker, receiver, registration, _) = broker(root.path(), Approval::Always);
        let task = std::thread::spawn(move || {
            exchange(
                &registration,
                Message::Forward(Box::new(ForwardRequest {
                    source: Some("reader@source-host".into()),
                    target: "backup".into(),
                    command: between_servers_command(&[]),
                    cwd: "~".into(),
                    inputs: crate::directive::Inputs::default(),
                    results_key: Some([5; 32]),
                })),
                Duration::from_secs(3),
                Some(Duration::from_secs(3)),
            )
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        let pending = loop {
            if let Some(summary) = receiver.approvals.snapshots().first() {
                break summary.clone();
            }
            if task.is_finished() {
                panic!("request ended: {:?}", task.join().unwrap().err());
            }
            assert!(Instant::now() < deadline, "request did not become pending");
            std::thread::sleep(Duration::from_millis(5));
        };
        let description =
            pending.description(&crate::persistence::Domain::default(), str::to_owned);
        for expected in [
            "\"~/output\" on \"backup\"",
            "\"reader@source-host\" runs the copy",
            "--from reader@source-host --srcs-in data",
        ] {
            assert!(description.contains(expected), "{expected}: {description}");
        }
        assert_eq!(receiver.approvals.snapshots().len(), 1);
        receiver
            .approvals
            .decide(&pending.id, false, crate::receive_approval::Kind::Copy)
            .unwrap();
        assert!(task.join().unwrap().is_err());
        assert!(receiver.approvals.snapshots().is_empty());
    }

    /// Ask `approve` as an SSH authorization provider does, with prompts in
    /// `approvals`, for login `alice` on profile `laptop`. The returned
    /// socket is the requesting login's end.
    fn ask_provider_directly(
        approvals: Arc<crate::receive_approval::Queue>,
        count: Arc<AtomicUsize>,
        request: ForwardRequest,
    ) -> (std::thread::JoinHandle<Result<()>>, UnixStream) {
        let (client, mut server) = UnixStream::pair().unwrap();
        let task = std::thread::spawn(move || {
            let requester = crate::receive_approval::Requester::provider_login("alice", "laptop");
            let lock = Mutex::new(());
            let socket = server.try_clone().unwrap();
            let cancelled = || requester_closed(&socket);
            Approver {
                origin: Origin::Provider,
                requester: &requester,
                approvals: &approvals,
                notifications: crate::receive_approval::Notifications::Off,
                caps: crate::directive::Caps {
                    max_bytes: 1 << 30,
                    max_entries: 1000,
                    max_delete: 10,
                },
                request_lock: &lock,
                forward_count: &count,
                cancelled: &cancelled,
            }
            .approve(request, &mut server)
        });
        (task, client)
    }

    fn between_servers_request(command: Vec<Vec<u8>>) -> ForwardRequest {
        ForwardRequest {
            source: Some("reader@source-host".into()),
            target: "backup".into(),
            command,
            cwd: "~/work".into(),
            inputs: crate::directive::Inputs::default(),
            results_key: Some([5; 32]),
        }
    }

    /// A provider approves only copies between two other servers whose
    /// command selected it, by its address or by a saved choice, and
    /// refuses the rest before anything is asked: an upload, a command that
    /// selects a receiving machine or the server's own SSH, and a request
    /// that does not match its command.
    #[test]
    fn a_provider_refuses_uploads_and_other_authorizers_before_asking() {
        let root = crate::test_support::tempdir().unwrap();
        let approvals = Arc::new(crate::receive_approval::Queue::default());
        let count = Arc::new(AtomicUsize::new(0));
        let upload = ForwardRequest {
            source: None,
            target: "backup".into(),
            command: forward_command(root.path()),
            cwd: String::new(),
            inputs: crate::directive::Inputs::default(),
            results_key: None,
        };
        let mismatched = ForwardRequest {
            source: Some("elsewhere".into()),
            ..between_servers_request(between_servers_command(&["--auth-from", "alice@provider"]))
        };
        let cases = [
            (upload, "approves only copies between two other servers"),
            (
                between_servers_request(between_servers_command(&["--auth-from", "@laptop"])),
                "authorizes from a different machine",
            ),
            (
                between_servers_request(between_servers_command(&["--auth-from", "ssh"])),
                "authorizes from a different machine",
            ),
            (mismatched, "copies between different servers"),
        ];
        for (request, expected) in cases {
            let (task, _client) = ask_provider_directly(approvals.clone(), count.clone(), request);
            let error = task.join().unwrap().err().unwrap();
            assert!(
                format!("{error:#}").contains(expected),
                "{expected}: {error:#}"
            );
            assert!(approvals.snapshots().is_empty());
            assert_eq!(count.load(Ordering::Acquire), 0);
        }
    }

    /// A provider's prompt for a copy between two other servers says that it
    /// cannot confirm which server asks, names the provider account the login
    /// used, and never approves by itself; ending the request ends it.
    #[test]
    fn a_provider_prompt_says_it_cannot_confirm_the_server() {
        for command in [
            between_servers_command(&["--auth-from", "alice@provider:2222"]),
            // Selected by a saved choice, the command names no authorizer.
            between_servers_command(&[]),
        ] {
            let approvals = Arc::new(crate::receive_approval::Queue::default());
            let count = Arc::new(AtomicUsize::new(0));
            let (task, client) = ask_provider_directly(
                approvals.clone(),
                count.clone(),
                between_servers_request(command),
            );
            let deadline = Instant::now() + Duration::from_secs(5);
            let pending = loop {
                if let Some(summary) = approvals.snapshots().first() {
                    break summary.clone();
                }
                if task.is_finished() {
                    panic!("request ended: {:?}", task.join().unwrap().err());
                }
                assert!(Instant::now() < deadline, "request did not become pending");
                std::thread::sleep(Duration::from_millis(5));
            };
            assert_eq!(pending.kind(), crate::receive_approval::Kind::Copy);
            assert!(!pending.can_remember());
            let description =
                pending.description(&crate::persistence::Domain::default(), str::to_owned);
            for expected in [
                "From: \"a server logged in to provider account alice (receiving profile @laptop)\"",
                "syq can't confirm which server is asking: any machine that can log in to provider account alice over SSH can send this request",
                "\"reader@source-host\" runs the copy",
                "\"~/output\" on \"backup\"",
            ] {
                assert!(description.contains(expected), "{expected}: {description}");
            }
            // What `persist receive pending` gets from a provider is the
            // stored form, without the prompt's notes; it still says so.
            let stored: crate::receive_approval::Summary =
                serde_json::from_value(serde_json::to_value(&pending).unwrap()).unwrap();
            assert!(stored
                .description(&crate::persistence::Domain::default(), str::to_owned)
                .contains("syq can't confirm which server is asking"));
            // The requesting login goes: its request ends unanswered.
            drop(client);
            let error = task.join().unwrap().err().unwrap();
            assert!(!format!("{error:#}").contains("approved"), "{error:#}");
            assert!(approvals.snapshots().is_empty());
            assert_eq!(count.load(Ordering::Acquire), 0);
        }
    }

    /// The server that starts a copy between two others asks the SSH
    /// authorization provider its command selected only for a copy that
    /// runs on the source; `select` checks the command first and leaves the
    /// asking to `prepare`.
    #[test]
    fn a_copy_between_servers_selects_the_provider_its_command_names() {
        let parsed = |extra: &[&str]| {
            crate::approval_command::parse(&between_servers_command(extra)).unwrap()
        };
        let mut args = parsed(&["--auth-from", "alice@provider"]);
        assert_eq!(
            approving_provider(&args).map(|provider| provider.label()),
            Some("alice@provider".to_owned())
        );
        assert!(select(&mut args, None).unwrap().is_none());
        // Through this machine, the provider's account access runs it.
        let args = parsed(&["--auth-from", "alice@provider", "--coordinate-at", "local"]);
        assert!(approving_provider(&args).is_none());
        // A receiving machine, or none, is not a provider.
        assert!(approving_provider(&parsed(&["--auth-from", "@laptop"])).is_none());
        assert!(approving_provider(&parsed(&[])).is_none());
        // What the provider would refuse is refused before it is asked.
        for extra in [
            &["--rsh", "ssh"][..],
            &["--copy-metadata", "hardlinks"],
            &["--detach"],
        ] {
            let mut args = parsed(&[&["--auth-from", "alice@provider"], extra].concat());
            assert!(select(&mut args, None).is_err(), "{extra:?}");
        }
        // An upload that selects a provider uses its account access, not
        // this route.
        let root = crate::test_support::tempdir().unwrap();
        let mut upload = forward_command(root.path());
        upload.extend([b"--auth-from".to_vec(), b"alice@provider".to_vec()]);
        let args = crate::approval_command::parse(&upload).unwrap();
        assert!(approving_provider(&args).is_none());
    }

    #[test]
    fn setup_deadlines_cover_partial_frames_and_cancellation_is_not_retried() {
        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        writer.write_all(&[0, 0]).unwrap();
        let error = read_message::<Reply>(&mut DeadlineIo {
            inner: &mut reader,
            deadline: Instant::now() + Duration::from_millis(20),
            cancelled: None,
        })
        .err()
        .unwrap();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::TimedOut
        );
        let error = read_message::<Reply>(&mut DeadlineIo {
            inner: &mut reader,
            deadline: Instant::now() + Duration::from_secs(60),
            cancelled: Some(&|| true),
        })
        .err()
        .unwrap();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::ConnectionAborted
        );
    }
}

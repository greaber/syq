//! One approver for the copies a server asks this machine to approve. Every
//! request takes the same steps: one decision at a time, the authorizer the
//! command names, the route `route::classify` gives the command and that
//! route's checks, this machine's limits, the rules the end that enforces
//! the copy will derive, at most eight requests waiting, and the prompt.
//! Then this machine either serves the copy itself under a token (copies to
//! and from it) or signs directives for the servers' enrolled receivers
//! (uploads, downloads and copies between two servers).
use super::*;
use crate::route::Route;
use std::sync::atomic::AtomicUsize;

/// A copy a server asks this machine to approve, as one of the four
/// messages carries it.
pub(crate) struct Asked {
    pub(crate) command: Vec<Vec<u8>>,
    pub(crate) cwd: String,
    pub(crate) inputs: crate::directive::Inputs,
    pub(crate) ask: Ask,
}

/// Which message asked, with what the requester says the command
/// addresses. The approver recomputes each target from the command and
/// refuses a request whose targets differ.
pub(crate) enum Ask {
    /// `Message::Request`: a copy to this machine.
    Write,
    /// `Message::Send`: a copy of this machine's files to the server.
    Send,
    /// `Message::Pull`: a copy from the server `target` to the server.
    Pull { target: String },
    /// `Message::Forward`: a copy from the server to `target`, or between
    /// two other servers, `source` and `target`, whose destination's
    /// results the server checks with `results_key`.
    Forward {
        source: Option<String>,
        target: String,
        results_key: Option<[u8; 32]>,
    },
}

impl Ask {
    /// The route the message asks to approve.
    fn route(&self) -> Route {
        match self {
            Ask::Write => Route::ToNamed,
            Ask::Send => Route::FromNamed,
            Ask::Pull { .. } => Route::Download,
            Ask::Forward { source: None, .. } => Route::Upload,
            Ask::Forward {
                source: Some(_), ..
            } => Route::Between,
        }
    }
}

impl From<forward::ForwardRequest> for Asked {
    fn from(request: forward::ForwardRequest) -> Self {
        let forward::ForwardRequest {
            source,
            target,
            command,
            cwd,
            inputs,
            results_key,
        } = request;
        Asked {
            command,
            cwd,
            inputs,
            ask: Ask::Forward {
                source,
                target,
                results_key,
            },
        }
    }
}

/// Where a request to approve a copy arrives, which decides what its command
/// may select and how this machine reaches the accounts.
pub(crate) enum Origin<'a> {
    /// A receiving connection to the server that asked, which its command
    /// selects by the connection's name. Enrolling can go through that
    /// server, along the login, host and port this machine's receiving
    /// connection uses.
    Receiving(&'a Receiver),
    /// A login to this SSH authorization provider, which cannot tell which
    /// server made it. It approves only copies between two other servers:
    /// an upload that selects a provider uses its account access instead.
    Provider,
}

/// Who approves a server's copy here, and what it applies to the copy: a
/// receiving connection's profile, or an SSH authorization provider's.
pub(crate) struct Approver<'a> {
    pub(crate) origin: Origin<'a>,
    /// Who asks, as the prompt names them.
    pub(crate) requester: &'a crate::receive_approval::Requester,
    pub(crate) approvals: &'a crate::receive_approval::Queue,
    pub(crate) notifications: crate::receive_approval::Notifications,
    pub(crate) caps: crate::directive::Caps,
    /// Held while a decision is pending, so that one is pending at a time.
    pub(crate) request_lock: &'a Mutex<()>,
    /// Copies to or from other servers waiting here for approval or setup.
    pub(crate) forward_count: &'a AtomicUsize,
    /// Whether the request ended: the server that asked went, or approving
    /// stopped.
    pub(crate) cancelled: &'a dyn Fn() -> bool,
}

/// Counts one request against `forward_count` while it waits.
struct Slot<'a>(&'a AtomicUsize);
impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// What a copy may do, derived before anything is asked, as the end that
/// enforces it will derive it.
enum Preview {
    /// Files written here.
    Write(Box<WriteHere>),
    /// Files read here, with their paths resolved here.
    Send(Box<pull::PullRequest>),
    /// Files read on another server.
    Read(Box<pull::PullRequest>),
    /// Files written on another server.
    Remote {
        request: Box<CopyRequest>,
        max_delete: u64,
    },
}

/// A copy to this machine: where it writes, and the directive this machine
/// keeps for it rather than signs.
struct WriteHere {
    caps: crate::directive::Caps,
    destination: PathBuf,
    container: PathBuf,
    results_key: [u8; 32],
    issued: crate::directive::Directive,
    rules: (
        crate::delegation::Grant,
        crate::delegation::GrantConstraints,
    ),
    request: CopyRequest,
    max_delete: u64,
}

impl Receiver {
    /// Approve a copy one of the four copy messages asks for, as
    /// `Approver::approve` does, for as long as this receiving connection
    /// and its server last.
    pub(super) fn approve(&self, asked: Asked, mut stream: TrackedStream) -> Result<()> {
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
            origin: Origin::Receiving(self),
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
        .approve(asked, &mut stream)
    }
}

impl Approver<'_> {
    /// Approve a server's copy: check it, show it, then serve it here under
    /// a token, or, over this machine's own SSH, set up or refresh the
    /// accounts' enrollments and sign their directives. Reply on `stream`.
    /// For a signed copy, the server connects to the receivers itself; this
    /// machine is not part of the copy after it replies.
    pub(crate) fn approve(&self, asked: Asked, stream: &mut impl Write) -> Result<()> {
        let Asked {
            command,
            cwd,
            inputs,
            ask,
        } = asked;
        let route = ask.route();
        // The server waits this long for the reply, from when it asked: the
        // decision, then any setup. Cancellation ends the setup sooner when
        // the server goes.
        let budget = Instant::now() + REQUEST_TIMEOUT + forward::SETUP_TIMEOUT;
        if route == Route::ToNamed {
            // This process writes the copy itself.
            crate::restricted::refuse_privileged_approved_receiver()?;
        }
        let request_lock = self.request_lock.try_lock().map_err(|_| {
            anyhow::anyhow!("another transfer is awaiting approval; retry after it is decided")
        })?;
        // Parsed once, for the authorizer and the route's own checks.
        let args = crate::approval_command::parse(&command)?;
        let receiver = match self.origin {
            Origin::Receiving(receiver) => {
                // A copy from this machine names it as its source; its own
                // checks refuse another authorizer, with their own advice.
                if route != Route::FromNamed {
                    crate::approval_command::check_authorizer(&args, &receiver.name)?;
                }
                Some(receiver)
            }
            Origin::Provider => {
                anyhow::ensure!(
                    route == Route::Between,
                    "an SSH authorization provider approves only copies between two other servers; this copy uses the provider's account access"
                );
                crate::approval_command::check_provider_authorizer(&args)?;
                None
            }
        };
        // The route's own checks, which classify the command, and the
        // accounts it names, which must be the ones the server asked about.
        let name = || {
            receiver
                .map(|receiver| receiver.name.as_str())
                .context("only a receiving connection asks to copy to or from this machine")
        };
        match route {
            Route::ToNamed => crate::approval_command::check_receiving_command(&args, name()?)?,
            Route::FromNamed => send::check_sending(&args, name()?)?,
            _ => {}
        }
        let (source, destination, results_key) = match ask {
            Ask::Write | Ask::Send => (None, None, None),
            Ask::Pull { target } => {
                anyhow::ensure!(
                    pull::eligible_target(&args)? == target,
                    "the requesting command reads from a different server"
                );
                (Some(target), None, None)
            }
            Ask::Forward {
                source: None,
                target,
                results_key,
            } => {
                anyhow::ensure!(
                    forward::eligible_target(&args)? == target,
                    "the requesting command copies to a different server"
                );
                (None, Some(target), results_key)
            }
            Ask::Forward {
                source: Some(source),
                target,
                results_key,
            } => {
                anyhow::ensure!(
                    forward::eligible_peer(&args)? == (source.clone(), target.clone()),
                    "the requesting command copies between different servers"
                );
                (Some(source), Some(target), results_key)
            }
        };
        // Only the server that starts a copy between two others checks the
        // destination's results itself.
        anyhow::ensure!(
            results_key.is_some() == (route == Route::Between),
            "invalid request to approve a copy to another server"
        );
        let caps = crate::directive::Caps {
            // A source deletes nothing.
            max_delete: if matches!(route, Route::FromNamed | Route::Download) {
                0
            } else {
                self.caps.max_delete
            },
            ..self.caps
        };
        let preview = match route {
            Route::ToNamed => Preview::Write(Box::new(write_here(
                receiver.context("copy to this machine")?,
                &args,
                (&command, &cwd, &inputs),
                caps,
            )?)),
            Route::FromNamed => {
                let receiver = receiver.context("copy from this machine")?;
                let mut request = pull::source_request(&args, Some(&caps))?;
                send::resolve(&receiver.cwd, receiver.root.as_deref(), &mut request)?;
                request.validate()?;
                Preview::Send(Box::new(request))
            }
            Route::Download => {
                // What the source's receiver will allow, before its home is
                // known.
                let preview = preview_directive(
                    crate::directive::Role::Source,
                    (&command, &cwd, &inputs),
                    caps,
                )?;
                Preview::Read(Box::new(crate::directive::source_rules(
                    &preview,
                    Path::new(std::ffi::OsStr::from_bytes(REQUEST_ROOT)),
                )?))
            }
            Route::Upload | Route::Between | Route::Own => {
                // The rules the receiver will derive, before the server's
                // home is known: the prompt names the destination as the
                // command does.
                let preview = preview_directive(
                    crate::directive::Role::Destination,
                    (&command, &cwd, &inputs),
                    caps,
                )?;
                let (rules, constraints) = crate::directive::destination_rules(
                    &preview,
                    Path::new(std::ffi::OsStr::from_bytes(REQUEST_ROOT)),
                )?;
                let max_delete = caps.deletion_ceiling(&rules.copy);
                Preview::Remote {
                    request: Box::new(CopyRequest {
                        destination: args
                            .locations
                            .last()
                            .context("copy destination missing")?
                            .path
                            .clone(),
                        copy: rules.copy,
                        constraints,
                    }),
                    max_delete,
                }
            }
        };
        // At most eight requests wait here: copies this machine serves
        // itself under a token, by their sessions, and copies it signs for
        // other servers, by their count.
        let served_here = matches!(route, Route::ToNamed | Route::FromNamed);
        let _slot = match receiver.filter(|_| served_here) {
            Some(receiver) => {
                let mut sessions = receiver.sessions.lock().unwrap();
                sessions.retain(|_, s| s.opened || s.issued.elapsed() < START_TIMEOUT);
                if sessions.len() >= 8 {
                    bail!("too many active transfers; wait for one to finish");
                }
                None
            }
            None => {
                let count = self.forward_count.fetch_add(1, Ordering::AcqRel);
                let slot = Slot(self.forward_count);
                if count >= 8 {
                    bail!(
                        "too many copies {} other servers are waiting for approval or setup here; retry after one is decided",
                        if route == Route::Download { "from" } else { "to" }
                    );
                }
                Some(slot)
            }
        };
        let cancelled = self.cancelled;
        // The accounts this machine reaches with its own SSH, which it
        // refuses before asking when their receivers would refuse them: a
        // receiver writes and coordinates only as an ordinary account, but a
        // source that only reads can be root.
        let destination = destination
            .as_deref()
            .map(|target| forward::Account::find(target, &cancelled))
            .transpose()?;
        let source = source
            .as_deref()
            .map(|target| forward::Account::find(target, &cancelled))
            .transpose()?;
        match (&source, &destination) {
            (None, Some(destination)) => destination.refuse_root(
                "to",
                &format!(
                    "copy to an ordinary account on {host}, or use the requesting server's own SSH access, or account access approved with `syq persist connect {account} --auth-from @NAME`",
                    host = destination.host(),
                    account = destination.label()
                ),
            )?,
            (Some(source), Some(destination)) => {
                let advice = "use an ordinary account there, or copy through the requesting server with `--coordinate-at local`, which needs account access to both servers";
                source.refuse_root("from", advice)?;
                destination.refuse_root("to", advice)?;
            }
            _ => {}
        }
        if args.dry_run {
            for account in source.iter().chain(destination.iter()) {
                account.ready_for_dry_run()?;
            }
        }
        // Ask, then finish. Only a copy to this machine within its automatic
        // root is approved without asking: that approval does not authorize
        // reading this machine's files, or the use of its SSH credentials on
        // another host.
        let max_delete = match preview {
            Preview::Write(write) => {
                let receiver = receiver.context("copy to this machine")?;
                let (authority, approved) =
                    receiver.approve_write(*write, (&command, &cwd, &inputs), &cancelled)?;
                return receiver.serve_under_token(
                    crate::restricted::Checker::Destination(authority),
                    cancelled,
                    stream,
                    |token| Reply::Approved(Approved { token, ..approved }),
                );
            }
            Preview::Send(request) => {
                let receiver = receiver.context("copy from this machine")?;
                self.approvals.request_send(
                    self.requester,
                    &command,
                    &cwd,
                    &send::exact_paths(&request),
                    &receiver.cwd,
                    request
                        .base
                        .confined
                        .then_some(request.base.path.as_deref())
                        .flatten(),
                    request.symlink_policy != crate::proto::OperatorSymlinkPolicy::Refuse
                        || request
                            .selections
                            .iter()
                            .any(|selection| selection.follow_root),
                    (&request.limits, request.preview),
                    self.notifications,
                    cancelled,
                )?;
                // Start the authority's clock at approval, after a long
                // prompt.
                let mut policy = request.policy(Instant::now() + send::LIFETIME);
                policy.outer_root = receiver
                    .root
                    .as_ref()
                    .map(|root| root.as_os_str().as_bytes().to_vec());
                let authority = crate::restricted::source::SourceAuthority::new(policy)?;
                return receiver.serve_under_token(
                    crate::restricted::Checker::source(authority),
                    cancelled,
                    stream,
                    |token| {
                        Reply::SendApproved(Box::new(send::SendApproved::new(
                            token,
                            request.base,
                            request.selections,
                        )))
                    },
                );
            }
            Preview::Read(reads) => {
                let source = source.as_ref().context("copy source missing")?;
                self.approvals.request_source(
                    self.requester,
                    &command,
                    &cwd,
                    (&source.target, source.enrollment, source.is_root()),
                    &reads,
                    self.notifications,
                    cancelled,
                )?;
                0
            }
            Preview::Remote {
                request,
                max_delete,
            } => {
                let destination = destination.as_ref().context("copy destination missing")?;
                self.approvals.request_remote(
                    self.requester,
                    &command,
                    &cwd,
                    crate::receive_approval::Remote {
                        target: &destination.target,
                        enrollment: destination.enrollment,
                        source: source
                            .as_ref()
                            .map(|source| (source.target.as_str(), source.enrollment)),
                    },
                    &request,
                    self.notifications,
                    cancelled,
                )?;
                max_delete
            }
        };
        // Sign for the accounts: over this machine's own SSH, set up or
        // refresh their enrollments and sign their directives.
        let disconnected = if destination.is_some() {
            "remote copy disconnected before setup"
        } else {
            "source copy disconnected before setup"
        };
        anyhow::ensure!(!cancelled(), disconnected);
        // This lock only serializes decisions, not enrollment.
        drop(request_lock);
        let destination_policy = destination
            .as_ref()
            .map(|destination| destination.policy(&cancelled))
            .transpose()?;
        let source_policy = source
            .as_ref()
            .map(|source| source.policy(&cancelled))
            .transpose()?;
        // The destination's known hosts go to the server that dials it: the
        // source, in its signed directive, or the server that asked.
        let destination_known_hosts = destination_policy
            .as_ref()
            .map(|policy| policy.known_hosts_for_others())
            .transpose()?;
        let (accounts, about) = match (&source, &destination) {
            (Some(source), None) => (
                forward::Accounts::Source(source.setup(source_policy.as_ref().unwrap())),
                format!("approve the copy from {:?}", source.target),
            ),
            (None, Some(destination)) => (
                forward::Accounts::Destination(
                    destination.setup(destination_policy.as_ref().unwrap()),
                ),
                format!("approve the copy to {:?}", destination.target),
            ),
            (Some(source), Some(destination)) => (
                forward::Accounts::BetweenServers {
                    source: source.setup(source_policy.as_ref().unwrap()),
                    destination: destination.setup(destination_policy.as_ref().unwrap()),
                    known_hosts: destination_known_hosts.clone().unwrap(),
                },
                format!("approve the copy to {:?}", destination.target),
            ),
            (None, None) => bail!("the copy names no account to approve"),
        };
        let mut setup = crate::process::self_command()?;
        setup.arg("--return-prepare");
        let prepared = forward::prepare_in_child(
            setup,
            &forward::Prepare {
                command,
                cwd,
                inputs,
                caps,
                accounts,
                results_key,
                via: receiver.map(|receiver| {
                    (
                        receiver.server_user.clone(),
                        receiver.tcp_peer.host.clone(),
                        receiver.tcp_peer.port,
                    )
                }),
                allow_enrollment: !args.dry_run,
            },
            // Setting restricted copying up can upload syq, which takes a
            // while on a slow link: give it what is left of the server's
            // wait, not only the time after the decision.
            budget,
            &cancelled,
        )
        .context(about)?;
        anyhow::ensure!(!cancelled(), disconnected);
        let reply = match (destination_policy, destination_known_hosts) {
            (Some(policy), Some(known_hosts)) => Reply::Directive(Box::new(forward::Issued::new(
                prepared,
                &policy,
                known_hosts,
                max_delete,
                source_policy.as_ref(),
            )?)),
            _ => {
                let policy = source_policy.context("copy source missing")?;
                Reply::SourceDirective(Box::new(pull::Issued {
                    directive: prepared.directive,
                    entry_key: prepared.entry_key,
                    login: policy.login_user.clone(),
                    known_hosts: policy.known_hosts_for_others()?,
                    // The configured value stays here: it can hold commands
                    // and paths.
                    known_hosts_left_out: policy.left_out_kind().map(str::to_owned),
                }))
            }
        };
        write_message(stream, &reply)
    }
}

/// A directive whose rules preview what the end with `role` will allow,
/// before the account's home is known.
fn preview_directive(
    role: crate::directive::Role,
    (command, cwd, inputs): (&[Vec<u8>], &str, &crate::directive::Inputs),
    caps: crate::directive::Caps,
) -> Result<crate::directive::Directive> {
    crate::directive::issue(
        crate::directive::Binding {
            enrollment: crate::enrollment::EnrollmentId::random(),
            generation: 1,
            account: "preview".into(),
            role,
        },
        command.to_vec(),
        cwd.to_owned(),
        (inputs.clone(), Some(caps)),
        // Unused: the preview has no results.
        [1; 32],
    )
}

/// Where a copy to this machine writes, and the directive it keeps for the
/// copy, derived from its command.
fn write_here(
    receiver: &Receiver,
    args: &crate::cli::Args,
    (command, cwd, inputs): (&[Vec<u8>], &str, &crate::directive::Inputs),
    caps: crate::directive::Caps,
) -> Result<WriteHere> {
    // The command's own `--follow-dst` follows symlinks above the
    // destination, as for any copy.
    let follow = args.follows_native_destination_paths();
    // Only a path resolved without following, outside a root, starts in the
    // home.
    let home = (receiver.root.is_none() && !follow)
        .then(home_directory)
        .flatten();
    let named = args
        .locations
        .last()
        .context("copy destination missing")?
        .path
        .clone();
    let (destination, container) = resolve_destination(
        &receiver.cwd,
        receiver.root.as_deref(),
        &named,
        follow,
        home.as_ref()
            .map(|(named, real)| (named.as_path(), real.as_path())),
    )?;
    if receiver.root.as_ref() == Some(&destination) && args.placement == crate::cli::Placement::As {
        bail!("cannot replace the receiving root itself; use --into . or a child path");
    }
    // The coordinator on the requesting server reads every reply itself,
    // so nobody reads this machine's results.
    let (_, results_key) = crate::destination_results::generate_recipient()?;
    let (issued, rules) =
        receiver.issue_here((command, cwd, inputs), caps, results_key, &destination)?;
    let request = CopyRequest {
        destination: named,
        copy: rules.0.copy.clone(),
        constraints: rules.1.clone(),
    };
    // The most deletions the copy may make here: this machine's own
    // --max-delete, within the copy's entry limit. A pruning copy's rules
    // enforce it, or the sender's own --max-delete if lower. The approval
    // carries it to the sender, which refuses every deletion when it plans
    // more. A dry run deletes nothing, but its reply carries this too, so
    // the dry run plans against what a real run would get.
    let max_delete = caps.deletion_ceiling(&request.copy);
    Ok(WriteHere {
        caps,
        destination,
        container,
        results_key,
        issued,
        rules,
        request,
        max_delete,
    })
}

impl Receiver {
    /// A directive for a copy to this machine, writing at `destination`,
    /// issued now and kept here, and its rules.
    fn issue_here(
        &self,
        (command, cwd, inputs): (&[Vec<u8>], &str, &crate::directive::Inputs),
        caps: crate::directive::Caps,
        results_key: [u8; 32],
        destination: &Path,
    ) -> Result<(
        crate::directive::Directive,
        (
            crate::delegation::Grant,
            crate::delegation::GrantConstraints,
        ),
    )> {
        let directive = crate::directive::issue_here(
            crate::directive::Binding {
                enrollment: crate::enrollment::EnrollmentId::random(),
                generation: self.generation.load(Ordering::Acquire),
                account: format!("@{}", self.name),
                role: crate::directive::Role::Destination,
            },
            command.to_vec(),
            cwd.to_owned(),
            (inputs.clone(), Some(caps)),
            results_key,
            START_TIMEOUT,
        )?;
        let rules =
            crate::directive::receiving_rules(&directive, destination.as_os_str().as_bytes())?;
        Ok((directive, rules))
    }

    /// Make the authority of a copy to this machine, which validates the
    /// complete operation, ask, unless it is within the automatic root, and
    /// make the authority again to start its clocks at approval. Return it
    /// and what the server needs to open it, but its token.
    fn approve_write(
        &self,
        write: WriteHere,
        (command, cwd, inputs): (&[Vec<u8>], &str, &crate::directive::Inputs),
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(Arc<crate::restricted::RestrictedAuthority>, Approved)> {
        let WriteHere {
            caps,
            destination,
            mut container,
            results_key,
            issued,
            rules,
            request,
            max_delete,
        } = write;
        // ACLs, extended attributes and hard links reach beyond the files
        // being written, so they always ask, as does widening the directory
        // the copy goes into, and unencrypted TCP, which `receiving_rules`
        // refuses here before it gets this far.
        let extra = &request.constraints.extra_options;
        let automatic = !(extra.acls
            || extra.xattrs
            || extra.hardlinks
            || extra.widen_dirs == crate::delegation::DirectoryWidening::All
            || request.constraints.tcp == crate::delegation::TcpPermission::Unencrypted)
            && self.auto_approve_root.as_ref().is_some_and(|root| {
                destination.starts_with(root)
                    && !(destination == *root
                        && request.copy.policy.placement == DestinationPlacement::ExactPath)
            });
        if automatic {
            // Anchor the filesystem executor above the automatic root. Its
            // no-follow traversal and its scopes keep every operation
            // inside the selected destination, including during races.
            container = self
                .auto_approve_root
                .as_ref()
                .unwrap()
                .parent()
                .context("automatic approval root must not be filesystem root")?
                .to_path_buf();
        }
        // Every authority for this request works beneath the directory
        // opened here, before the prompt: one whose name leads elsewhere by
        // approval cannot redirect the copy.
        let container = crate::restricted::Container::open(&container)?;
        // Validate the complete operation before the local policy decision.
        let authority = crate::restricted::receiving_authority(&container, &issued, rules)?;
        drop(issued);
        self.authorize_request(command, cwd, &request, cancelled, automatic)?;
        // Start the directive's clocks at approval, including after a long
        // prompt.
        let authority = if automatic {
            authority
        } else {
            let (issued, rules) =
                self.issue_here((command, cwd, inputs), caps, results_key, &destination)?;
            crate::restricted::receiving_authority(&container, &issued, rules)?
        };
        Ok((
            authority,
            Approved {
                token: String::new(),
                destination: request.copy.destination,
                max_delete: Some(max_delete),
            },
        ))
    }

    /// Keep the authority of a copy this machine approved and serves itself
    /// under a token that opens the copy's control once, within
    /// `START_TIMEOUT`, and reply with the token.
    fn serve_under_token(
        &self,
        authority: crate::restricted::Checker,
        cancelled: &dyn Fn() -> bool,
        stream: &mut impl Write,
        reply: impl FnOnce(String) -> Reply,
    ) -> Result<()> {
        let mut sessions = self.sessions.lock().unwrap();
        if cancelled() {
            bail!("copy disconnected before approval could be used");
        }
        let token = random_token()?;
        sessions.insert(
            token.clone(),
            Session {
                tcp: None,
                authority,
                issued: Instant::now(),
                opened: false,
                channels: Arc::new(crate::private_broker::ConnectionRegistry::new(
                    Duration::from_secs(10),
                )),
            },
        );
        drop(sessions);
        write_message(stream, &reply(token))
    }
}

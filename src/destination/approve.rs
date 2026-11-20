//! One approver for the copies a server asks this machine to approve. Every
//! request takes the same steps: the route `route::classify` gives its
//! command, one decision at a time, the authorizer the command names, and
//! then the route's own steps. This machine either serves the copy itself
//! under a token (copies to and from it) or signs directives for the
//! servers' enrolled receivers (downloads, uploads and copies between two
//! servers). Each route's steps are its own checks, this machine's limits,
//! the rules the end that enforces the copy will derive, at most eight
//! requests waiting, and the prompt.
use super::*;
use crate::restricted::source::SourcePolicy;
use crate::route::Route;
use std::sync::atomic::AtomicUsize;

/// A copy a server asks this machine to approve, by its command, the
/// command's working directory, and what it read from files. The approver
/// trusts only the command: it classifies the route and names every end
/// from it.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Asked {
    pub(crate) command: Vec<Vec<u8>>,
    pub(crate) cwd: String,
    pub(crate) inputs: crate::directive::Inputs,
    /// For a copy between two other servers, the requester's key for the
    /// destination's results, which it checks.
    pub(crate) results_key: Option<[u8; 32]>,
}

impl Asked {
    fn parts(&self) -> (&[Vec<u8>], &str, &crate::directive::Inputs) {
        (&self.command, &self.cwd, &self.inputs)
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

/// What a copy this machine signs for may do, derived before anything is
/// asked, as the receiver that enforces it will derive it before the
/// account's home is known: the prompt names the paths as the command does.
enum Preview {
    /// A download: the source as the command names it, and what may be read
    /// there.
    Read {
        source: String,
        reads: Box<SourcePolicy>,
    },
    /// An upload, or a copy between two servers when `source` names the
    /// other: what may be written on the destination, and this machine's
    /// deletion limit for it.
    Write {
        source: Option<String>,
        destination: String,
        request: Box<CopyRequest>,
        max_delete: u64,
    },
}

impl Receiver {
    /// Approve the copy a server asks for, as `Approver::approve` does, for
    /// as long as this receiving connection and its server last.
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

    /// Refuse a ninth copy this machine serves itself under a token.
    fn check_session_room(&self) -> Result<()> {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|_, s| s.opened || s.issued.elapsed() < START_TIMEOUT);
        if sessions.len() >= 8 {
            bail!("too many active transfers; wait for one to finish");
        }
        Ok(())
    }
}

impl<'a> Approver<'a> {
    /// Approve a server's copy: check it, show it, then serve it here under
    /// a token, or sign for the accounts it names. Reply on `stream`. Only a
    /// copy to this machine within its automatic root is approved without
    /// asking: that approval does not authorize reading this machine's
    /// files, or the use of its SSH credentials on another host.
    pub(crate) fn approve(&self, asked: Asked, stream: &mut impl Write) -> Result<()> {
        // The server waits this long for the reply, from when it asked: the
        // decision, then any setup. Cancellation ends the setup sooner when
        // the server goes.
        let budget = Instant::now() + REQUEST_TIMEOUT + forward::SETUP_TIMEOUT;
        let args = crate::approval_command::parse(&asked.command)?;
        let route = crate::route::classify(&args);
        if route == Route::ToNamed {
            // This process writes the copy itself.
            crate::restricted::refuse_privileged_approved_receiver()?;
        }
        let request_lock = self.request_lock.try_lock().map_err(|_| {
            anyhow::anyhow!("another transfer is awaiting approval; retry after it is decided")
        })?;
        let receiver = self.check_origin(route, &args)?;
        // Only the server that starts a copy between two others checks the
        // destination's results itself.
        anyhow::ensure!(
            asked.results_key.is_some() == (route == Route::Between),
            "invalid request to approve a copy to another server"
        );
        match (route, receiver) {
            (Route::ToNamed, Some(receiver)) => self.receive(receiver, &args, &asked, stream),
            (Route::FromNamed, Some(receiver)) => self.send(receiver, &args, &asked, stream),
            (Route::Download | Route::Upload | Route::Between, _) => {
                let reply = self.sign(route, &args, asked, request_lock, budget, receiver)?;
                write_message(stream, &reply)
            }
            _ => bail!("the requesting command is not a copy that this machine approves"),
        }
    }

    /// Check the authorizer the command names against where the request
    /// arrived, and return the receiving connection it arrived on.
    fn check_origin(&self, route: Route, args: &crate::cli::Args) -> Result<Option<&'a Receiver>> {
        match self.origin {
            Origin::Receiving(receiver) => {
                // A copy from this machine names it as its source; its own
                // checks refuse another authorizer, with their own advice.
                if route != Route::FromNamed {
                    crate::approval_command::check_authorizer(args, &receiver.name)?;
                }
                Ok(Some(receiver))
            }
            Origin::Provider => {
                anyhow::ensure!(
                    route == Route::Between,
                    "an SSH authorization provider approves only copies between two other servers; this copy uses the provider's account access"
                );
                crate::approval_command::check_provider_authorizer(args)?;
                Ok(None)
            }
        }
    }

    /// A copy to this machine: check it as the machine that asked did,
    /// derive where it writes and the directive kept here, ask unless it is
    /// within the automatic root, and serve it under a token.
    fn receive(
        &self,
        receiver: &Receiver,
        args: &crate::cli::Args,
        asked: &Asked,
        stream: &mut impl Write,
    ) -> Result<()> {
        crate::approval_command::check_receiving_command(args, &receiver.name)?;
        let (authority, approved) =
            receiver.approve_write(args, asked.parts(), self.caps, self.cancelled)?;
        receiver.serve_under_token(
            crate::restricted::Checker::Destination(authority),
            self.cancelled,
            stream,
            |token| Reply::Approved(Approved { token, ..approved }),
        )
    }

    /// A copy of this machine's files: check it, resolve what it reads in
    /// the receiving profile, ask, and serve it under a token.
    fn send(
        &self,
        receiver: &Receiver,
        args: &crate::cli::Args,
        asked: &Asked,
        stream: &mut impl Write,
    ) -> Result<()> {
        send::check_sending(args, &receiver.name)?;
        let mut reads = pull::source_request(args, Some(&self.caps))?;
        send::resolve(&receiver.cwd, receiver.root.as_deref(), &mut reads)?;
        pull::validate(&reads)?;
        receiver.check_session_room()?;
        self.approvals.request_send(
            self.requester,
            &asked.command,
            &asked.cwd,
            &send::exact_paths(&reads),
            &receiver.cwd,
            reads
                .base
                .confined
                .then_some(reads.base.path.as_deref())
                .flatten(),
            reads.symlink_policy != crate::proto::OperatorSymlinkPolicy::Refuse
                || reads
                    .selections
                    .iter()
                    .any(|selection| selection.follow_root),
            (&reads.limits, reads.preview),
            self.notifications,
            self.cancelled,
        )?;
        let (base, selections) = (reads.base.clone(), reads.selections.clone());
        reads.outer_root = receiver
            .root
            .as_ref()
            .map(|root| root.as_os_str().as_bytes().to_vec());
        // Start the authority's clock at approval, after a long prompt.
        let authority = crate::restricted::source::SourceAuthority::new(
            reads,
            Instant::now() + send::LIFETIME,
        )?;
        receiver.serve_under_token(
            crate::restricted::Checker::source(authority),
            self.cancelled,
            stream,
            |token| Reply::SendApproved(Box::new(send::SendApproved::new(token, base, selections))),
        )
    }

    /// A download, upload or copy between two servers: check it, show it,
    /// then, over this machine's own SSH, set up or refresh the accounts'
    /// enrollments and sign their directives. The server connects to the
    /// receivers itself; this machine is not part of the copy after it
    /// replies.
    fn sign(
        &self,
        route: Route,
        args: &crate::cli::Args,
        asked: Asked,
        request_lock: std::sync::MutexGuard<'_, ()>,
        budget: Instant,
        receiver: Option<&Receiver>,
    ) -> Result<Reply> {
        let caps = crate::directive::Caps {
            // A source deletes nothing.
            max_delete: if route == Route::Download {
                0
            } else {
                self.caps.max_delete
            },
            ..self.caps
        };
        let preview = Preview::new(route, args, &asked, caps)?;
        let count = self.forward_count.fetch_add(1, Ordering::AcqRel);
        let _slot = Slot(self.forward_count);
        if count >= 8 {
            bail!(
                "too many copies {} other servers are waiting for approval or setup here; retry after one is decided",
                if route == Route::Download { "from" } else { "to" }
            );
        }
        let cancelled = self.cancelled;
        // The accounts this machine reaches with its own SSH, which it
        // refuses before asking when their receivers would refuse them: a
        // receiver writes and coordinates only as an ordinary account, but a
        // source that only reads can be root.
        let find = |target: &str| forward::Account::find(target, &cancelled);
        let (source, destination, max_delete, about) = match preview {
            Preview::Read { source, reads } => {
                let source = find(&source)?;
                if args.dry_run {
                    source.ready_for_dry_run()?;
                }
                self.approvals.request_source(
                    self.requester,
                    &asked.command,
                    &asked.cwd,
                    (&source.target, source.enrollment, source.is_root()),
                    &reads,
                    self.notifications,
                    cancelled,
                )?;
                let about = format!("approve the copy from {:?}", source.target);
                (Some(source), None, 0, about)
            }
            Preview::Write {
                source,
                destination,
                request,
                max_delete,
            } => {
                let destination = find(&destination)?;
                let source = source.as_deref().map(find).transpose()?;
                match &source {
                    None => destination.refuse_root(
                        "to",
                        &format!(
                            "copy to an ordinary account on {host}, or use the requesting server's own SSH access, or account access approved with `syq persist connect {account} --auth-from @NAME`",
                            host = destination.host(),
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
                self.approvals.request_remote(
                    self.requester,
                    &asked.command,
                    &asked.cwd,
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
                let about = format!("approve the copy to {:?}", destination.target);
                (source, Some(destination), max_delete, about)
            }
        };
        let disconnected = if destination.is_some() {
            "remote copy disconnected before setup"
        } else {
            "source copy disconnected before setup"
        };
        anyhow::ensure!(!cancelled(), disconnected);
        // This lock only serializes decisions, not enrollment.
        drop(request_lock);
        // The destination's known hosts go to the server that dials it: the
        // source, in its signed directive, or the server that asked.
        let reach = |account: forward::Account| -> Result<_> {
            let known_hosts = account.policy.known_hosts_for_others()?;
            Ok((account, known_hosts))
        };
        let destination = destination.map(reach).transpose()?;
        let source = source.map(reach).transpose()?;
        let mut setup = crate::process::self_command()?;
        setup.arg("--return-prepare");
        let signed = forward::prepare_in_child(
            setup,
            &forward::Prepare {
                command: asked.command,
                cwd: asked.cwd,
                inputs: asked.inputs,
                caps,
                accounts: forward::Accounts {
                    source: source.as_ref().map(|(account, _)| account.setup()),
                    destination: destination
                        .as_ref()
                        .map(|(account, known_hosts)| (account.setup(), known_hosts.clone())),
                },
                results_key: asked.results_key,
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
        Ok(Reply::Signed(Box::new(forward::Issued::new(
            signed,
            source.map(|(account, known_hosts)| (account.policy, known_hosts)),
            destination.map(|(account, known_hosts)| (account.policy, known_hosts)),
            max_delete,
        )?)))
    }
}

impl Preview {
    /// The route's own checks, which name the servers from the command, and
    /// what the copy may do on the one whose files it reads or writes.
    fn new(
        route: Route,
        args: &crate::cli::Args,
        asked: &Asked,
        caps: crate::directive::Caps,
    ) -> Result<Self> {
        let root = Path::new(std::ffi::OsStr::from_bytes(REQUEST_ROOT));
        let (source, destination) = match route {
            Route::Download => {
                let source = pull::eligible_target(args)?;
                let preview =
                    preview_directive(crate::directive::Role::Source, asked.parts(), caps)?;
                return Ok(Preview::Read {
                    source,
                    reads: Box::new(crate::directive::source_rules(&preview, root)?),
                });
            }
            Route::Upload => (None, forward::eligible_target(args)?),
            _ => {
                let (source, destination) = forward::eligible_peer(args)?;
                (Some(source), destination)
            }
        };
        let preview = preview_directive(crate::directive::Role::Destination, asked.parts(), caps)?;
        let rules = crate::directive::destination_rules(&preview, root)?;
        let max_delete = caps.deletion_ceiling(&rules.copy);
        Ok(Preview::Write {
            source,
            destination,
            request: Box::new(CopyRequest {
                destination: args
                    .locations
                    .last()
                    .context("copy destination missing")?
                    .path
                    .clone(),
                rules,
            }),
            max_delete,
        })
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
        crate::delegation::DestinationRules,
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

    /// Approve a copy to this machine: derive where it writes and the
    /// directive kept here for it, make its authority, which validates the
    /// complete operation, ask, unless it is within the automatic root, and
    /// make the authority again to start its clocks at approval. Return it
    /// and what the server needs to open it, but its token.
    fn approve_write(
        &self,
        args: &crate::cli::Args,
        (command, cwd, inputs): (&[Vec<u8>], &str, &crate::directive::Inputs),
        caps: crate::directive::Caps,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(Arc<crate::restricted::RestrictedAuthority>, Approved)> {
        // The command's own `--follow-dst` follows symlinks above the
        // destination, as for any copy.
        let follow = args.follows_native_destination_paths();
        // Only a path resolved without following, outside a root, starts in the
        // home.
        let home = (self.root.is_none() && !follow)
            .then(home_directory)
            .flatten();
        let named = args
            .locations
            .last()
            .context("copy destination missing")?
            .path
            .clone();
        let (destination, mut container) = resolve_destination(
            &self.cwd,
            self.root.as_deref(),
            &named,
            follow,
            home.as_ref()
                .map(|(named, real)| (named.as_path(), real.as_path())),
        )?;
        if self.root.as_ref() == Some(&destination) && args.placement == crate::cli::Placement::As {
            bail!("cannot replace the receiving root itself; use --into . or a child path");
        }
        // The coordinator on the requesting server reads every reply itself,
        // so nobody reads this machine's results.
        let (_, results_key) = crate::destination_results::generate_recipient()?;
        let (issued, rules) =
            self.issue_here((command, cwd, inputs), caps, results_key, &destination)?;
        let request = CopyRequest {
            destination: named,
            rules: rules.clone(),
        };
        // The most deletions the copy may make here: this machine's own
        // --max-delete, within the copy's entry limit. A pruning copy's rules
        // enforce it, or the sender's own --max-delete if lower. The approval
        // carries it to the sender, which refuses every deletion when it plans
        // more. A dry run deletes nothing, but its reply carries this too, so
        // the dry run plans against what a real run would get.
        let max_delete = caps.deletion_ceiling(&request.rules.copy);
        self.check_session_room()?;
        // ACLs, extended attributes and hard links reach beyond the files
        // being written, so they always ask, as does widening the directory
        // the copy goes into, and unencrypted TCP, which `receiving_rules`
        // refuses here before it gets this far.
        let options = &request.rules.copy.options;
        let automatic = !(options.acls
            || options.xattrs
            || options.hardlinks
            || options.widen_dirs == crate::delegation::DirectoryWidening::All
            || request.rules.tcp == crate::delegation::TcpPermission::Unencrypted)
            && self.auto_approve_root.as_ref().is_some_and(|root| {
                destination.starts_with(root)
                    && !(destination == *root
                        && request.rules.copy.policy.placement == DestinationPlacement::ExactPath)
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
                destination: request.rules.copy.destination,
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

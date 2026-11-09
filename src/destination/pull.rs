//! Copies from another server to the server that asks for them (`syq cp
//! --from hostB` on hostA), which the receiving machine approves: it signs a
//! source directive for hostB's enrolled receiver, and hostA logs in to that
//! receiver itself. The receiver serves only what the signed command reads.
use super::*;
use crate::proto::{OperatorSymlinkPolicy, SourceRootBase, SourceRootSelection};
use crate::restricted::source::{SourceAuthority, SourcePolicy, SourceTcpPolicy};

/// What a copy's sources may be read for: derived from its command where
/// they are read, by a source directive's receiver
/// (`directive::source_rules`) or by the receiving machine that sends them
/// (`send`), and never sent.
#[derive(Clone, Debug)]
pub(crate) struct PullRequest {
    pub base: SourceRootBase,
    pub selections: Vec<SourceRootSelection>,
    pub selection_types: Vec<crate::cli::SourceSelection>,
    pub symlink_policy: OperatorSymlinkPolicy,
    pub hashing: crate::hashing::HashPolicy,
    pub preservation: crate::inode_metadata::Selection,
    pub sparse: bool,
    pub compressed: bool,
    pub tcp_ports: (u16, u16),
    pub tcp_congestion: Option<String>,
    pub send_rate: Option<u64>,
    pub limits: crate::delegation::CopyLimits,
    /// Where `base` is on the server that reads, when it reads from another
    /// working directory than the command's (`SourcePolicy::resolved_base`).
    /// Only a source directive's rules set it.
    pub resolved_base: Option<Vec<u8>>,
    /// Whether the command lets the data go over TCP, and unencrypted.
    pub tcp: crate::delegation::TcpPermission,
}

/// A server's request to approve a copy from another server to itself,
/// which this machine approves with a source directive for that server's
/// enrolled receiver. The server sends what its command read from files.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReadRequest {
    /// The source as the command names it.
    pub(super) target: String,
    pub(super) command: Vec<Vec<u8>>,
    pub(super) cwd: String,
    pub(super) inputs: crate::directive::Inputs,
}

/// What the receiving machine returns for a server's copy from another
/// server: the directive it signed for the source's enrolled receiver, and
/// how to reach that receiver.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Issued {
    /// The signed directive, base64url-encoded.
    directive: String,
    /// The enrollment's entry key, which only starts its receiver.
    entry_key: forward::EntryKeyText,
    /// The account the enrollment is for.
    login: String,
    /// What this machine's known_hosts files say about the source.
    known_hosts: String,
    /// What they leave out of its configuration, without its value, for a
    /// notice.
    known_hosts_left_out: Option<String>,
}

impl std::fmt::Debug for Issued {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Issued")
            .field("login", &self.login)
            .finish_non_exhaustive()
    }
}

/// The source of `args`, a copy from one SSH server to this machine that a
/// receiving machine can approve, as the command names it.
pub(crate) fn eligible_target(args: &crate::cli::Args) -> Result<String> {
    use crate::cli::{CoordinateAt, Interface, PeerAuth};
    let (destination, sources) = args
        .locations
        .split_last()
        .context("copy endpoints missing")?;
    let source = sources.first().context("copy source missing")?;
    if args.interface != Interface::NativeCp
        || args.s3.is_some()
        || destination.is_remote()
        || !source.is_remote()
        || sources.iter().any(|other| {
            other.host != source.host || other.user != source.user || other.port != source.port
        })
    {
        bail!("source authorization requires syq cp from one SSH server to this machine");
    }
    if args.rsh.is_some()
        || args.syq_path.is_some()
        || args.no_bootstrap
        || args.detach
        || args.restricted_grant.is_some()
        || args.peer_auth != PeerAuth::Restricted
        || args.coordinate_at != CoordinateAt::Auto
    {
        bail!("a copy from another server that a receiving machine approves reads it through that server's restricted receiver; it cannot be combined with --rsh, --syq-path, --no-bootstrap, --detach, --peer-auth, or --coordinate-at");
    }
    anyhow::ensure!(args.descriptor_copy.is_none(), "source authorization requires pathname file selections; descriptor streams are not supported");
    let target = crate::remote_to_remote::endpoint_arg(source, None, None);
    forward::target_endpoint(&target)?;
    Ok(target)
}

/// The read permission a copy's sources need, wherever they are, within
/// `caps`, the limits of the machine that approves the reads, when it has
/// them. The machine that reads derives it from the command, as the server
/// that asks does to refuse early what that machine would refuse.
pub(crate) fn source_request(
    args: &crate::cli::Args,
    caps: Option<&crate::directive::Caps>,
) -> Result<PullRequest> {
    let sources =
        crate::transfer::distinct_native_sources(&args.locations[..args.locations.len() - 1]);
    let (base, selections, symlink_policy) = crate::transfer::source_registration(&sources, args);
    let max_total_bytes = args
        .receiver_max_bytes
        .unwrap_or(crate::directive::DEFAULT_MAX_BYTES);
    let max_file_bytes = args
        .max_size
        .as_deref()
        .map(crate::cli::parse_size)
        .transpose()?
        .unwrap_or(max_total_bytes)
        .min(max_total_bytes);
    let workers = if args.connections_opt.is_some() {
        args.connections
    } else {
        args.resource_limits
            .as_ref()
            .and_then(|limits| limits.workers)
            .unwrap_or(usize::from(crate::delegation::MAX_CONNECTIONS))
    };
    anyhow::ensure!(
        workers <= usize::from(crate::delegation::MAX_CONNECTIONS),
        "too many source workers"
    );
    let mut request = PullRequest {
        base,
        selections,
        selection_types: sources.iter().map(|source| source.selection).collect(),
        symlink_policy,
        hashing: crate::hashing::HashPolicy {
            algorithm: args.hash_algorithm,
            transfer_integrity: args.transfer_integrity,
            transfer_hash_type: args.transfer_hash_type,
        },
        preservation: crate::inode_metadata::Selection {
            acls: args.acls,
            xattrs: args.xattrs,
            atimes: args.atimes > 0,
            crtimes: args.crtimes,
            open_noatime: args.open_noatime || args.atimes > 1,
        },
        sparse: args.sparse,
        compressed: args.compress,
        tcp_ports: crate::conn::parse_ports(&args.tcp_ports)?,
        tcp_congestion: args.tcp_congestion.clone(),
        send_rate: (args.bwlimit_bytes != 0).then_some(args.bwlimit_bytes),
        limits: crate::delegation::CopyLimits {
            max_entries: args
                .receiver_max_entries
                .unwrap_or(crate::directive::DEFAULT_MAX_ENTRIES),
            max_total_bytes,
            max_file_bytes,
            hash_block_bytes: args.block_size,
            // The source authority counts its one control connection too.
            max_connections: u16::try_from(workers + 1)?,
            max_deletions: 0,
        },
        resolved_base: None,
        tcp: crate::delegation::TcpPermission::of(args),
    };
    // A source deletes nothing, so only the byte and entry limits apply.
    if let Some(caps) = caps {
        let limits = &mut request.limits;
        limits.max_total_bytes = limits.max_total_bytes.min(caps.max_bytes);
        limits.max_file_bytes = limits.max_file_bytes.min(limits.max_total_bytes);
        limits.max_entries = limits.max_entries.min(caps.max_entries);
    }
    request.validate()?;
    Ok(request)
}

impl PullRequest {
    pub(crate) fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.limits.max_total_bytes > 0
                && self.limits.max_total_bytes <= crate::delegation::MAX_COPY_BYTES
                && self.limits.max_entries > 0
                && self.limits.max_entries <= crate::delegation::MAX_ENTRIES
                && self.limits.max_file_bytes <= self.limits.max_total_bytes
                && self.limits.max_connections > 1
                && self.limits.max_connections <= crate::delegation::MAX_CONNECTIONS + 1
                && self.limits.max_deletions == 0,
            "invalid source read limits"
        );
        SourceAuthority::new(self.policy(Instant::now()))?;
        Ok(())
    }
    /// The reads this allows until `deadline`.
    pub(crate) fn policy(&self, deadline: Instant) -> SourcePolicy {
        SourcePolicy {
            base: self.base.clone(),
            selections: self.selections.clone(),
            selection_types: self.selection_types.clone(),
            resolved_base: self.resolved_base.clone(),
            symlink_policy: self.symlink_policy,
            hashing: self.hashing,
            preservation: self.preservation,
            sparse: self.sparse,
            compressed: self.compressed,
            tcp: SourceTcpPolicy {
                permission: self.tcp,
                port_lo: self.tcp_ports.0,
                port_hi: self.tcp_ports.1,
                congestion_control: self.tcp_congestion.clone(),
            },
            send_rate: self.send_rate,
            limits: self.limits.clone(),
            deadline,
            outer_root: None,
        }
    }
    /// Each selection, as `shown` names it, and what it may be. The source
    /// is not looked at before approval: its reader resolves each selection
    /// as a directory tree or an exact leaf after permission arrives.
    pub(crate) fn scopes(&self, shown: impl Fn(&[u8]) -> String) -> Vec<String> {
        self.selections
            .iter()
            .zip(&self.selection_types)
            .map(|(selection, kind)| {
                let scope = match kind {
                    crate::cli::SourceSelection::File => "exact non-directory entry",
                    crate::cli::SourceSelection::Directory
                    | crate::cli::SourceSelection::Contents => "directory tree",
                    _ => "directory tree or exact non-directory entry",
                };
                format!("{} ({scope})", shown(&selection.path))
            })
            .collect()
    }
}

pub(super) fn select(
    args: &mut crate::cli::Args,
    progress: Option<&crate::progress::Progress>,
) -> Result<Option<handoff::Selection>> {
    if args.auth_from == crate::cli::AuthFrom::Ssh {
        return Ok(None);
    }
    let explicit = match &args.auth_from {
        crate::cli::AuthFrom::Provider(crate::auth_from::Provider::Return(name)) => {
            Some(name.clone())
        }
        crate::cli::AuthFrom::Provider(crate::auth_from::Provider::Ssh { .. }) => {
            bail!("this copy cannot use account authorization from an SSH provider; use a supported direct SSH copy or --auth-from @NAME for per-copy authorization");
        }
        _ => handoff::selected_name(handoff::Kind::Pull).map(str::to_owned),
    };
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
        let crate::conn::Endpoint::Remote(spec) =
            crate::transfer::endpoint(&args.locations[0], args)?
        else {
            unreachable!()
        };
        let error = match crate::transfer::connect_for_authorization(args, &spec, progress) {
            Ok(connection) => {
                *spec.primed_control.lock().unwrap() =
                    crate::conn::PrimedControl::Checked(Some(Box::new(connection)));
                args.direct_source = Some(Box::new(spec));
                return Ok(None);
            }
            Err(error) if crate::conn::is_per_copy_approval_fallback_error(&error) => error,
            Err(error) => return Err(error),
        };
        let Some(found) = names.into_iter().find_map(|name| {
            available(&name, Duration::from_secs(2))
                .ok()
                .map(|registration| (name, registration))
        }) else {
            return Err(error);
        };
        super::notices::asking(&error, &spec, &found.0, &format!("this copy from {target}"));
        found
    };
    Ok(Some(handoff::Selection::new(
        name,
        registration,
        handoff::Kind::Pull,
        Some(target),
    )))
}

/// Ask the receiving machine to approve this copy, then set up this
/// machine's connections to the source's enrolled receiver.
pub(super) fn prepare(args: &mut crate::cli::Args, selection: handoff::Selection) -> Result<()> {
    let handoff::Selection {
        name,
        registration,
        target,
        ..
    } = selection;
    let target = target.context("source authorization target missing")?;
    // Refused with advice before anything is asked when an approval cannot
    // carry the command.
    let command = crate::approval_command::copy_command(args)?;
    let inputs = crate::directive::Inputs {
        ignore: args.ignore_lines.clone(),
        mapping: crate::directive::mapping_authorization(args)?,
    };
    super::notices::waiting(&format!("@{name}"), &format!("this copy from {target}"));
    let (stream, reply) = exchange(
        &registration,
        Message::Pull(Box::new(ReadRequest {
            target: target.clone(),
            command,
            cwd: crate::approval_command::current_directory(),
            inputs,
        })),
        REQUEST_TIMEOUT + forward::SETUP_TIMEOUT + Duration::from_secs(10),
        None,
    )?;
    // The copy needs nothing more from the receiving machine.
    drop(stream);
    let Reply::SourceDirective(issued) = reply else {
        bail!("unexpected source approval response");
    };
    let Issued {
        directive,
        entry_key,
        login,
        known_hosts,
        known_hosts_left_out,
    } = *issued;
    if args.verbose > 0 {
        crate::output::diagnostic!(
            "syq: source copy approved; connecting to the source's restricted receiver"
        );
    }
    if let Some(left_out) = known_hosts_left_out.filter(|_| !args.quiet) {
        crate::output::diagnostic!(
            "syq: checking the source's host key without some of what the approving machine knows about it: {}",
            left_out
                .chars()
                .filter(|character| !character.is_control())
                .collect::<String>()
        );
    }
    // This machine reaches the receiver as its own SSH configuration reaches
    // the source its command named, as the account the approving machine
    // enrolled, and checks its host key as its own `ssh` would, also
    // accepting what the approving machine knows.
    let endpoint = forward::target_endpoint(&target)?;
    let receiver = crate::remote_to_remote::ReceiverSsh::prepare(
        &shell_words::split(&crate::remote_to_remote::receiver_rsh(endpoint.port))?,
        (Some(&login), endpoint.port, &endpoint.host),
        &known_hosts,
        entry_key.as_bytes(),
        args.quiet,
    )?;
    let count = args.locations.len() - 1;
    for source in &mut args.locations[..count] {
        source.host = Some(endpoint.host.clone());
        source.user = Some(login.clone());
        source.port = endpoint.port;
    }
    args.auth_from = crate::cli::AuthFrom::Provider(crate::auth_from::Provider::Return(name));
    args.source_directive = Some(directive);
    args.rsh = Some(shell_words::join(receiver.command));
    args.receiver_host = Some(receiver.receiver_host);
    args.receiver_keys = Some(Arc::new(receiver.directory));
    Ok(())
}

impl Receiver {
    /// Approve a server's copy from another server to itself: show the
    /// command and what it reads, then, over this machine's own SSH, set up
    /// or refresh the source account's enrollment and sign its directive.
    /// The server connects to the source's receiver itself; this machine is
    /// not part of the copy after it replies.
    pub(super) fn pull(&self, request: ReadRequest, mut stream: TrackedStream) -> Result<()> {
        let ReadRequest {
            target,
            command,
            cwd,
            inputs,
        } = request;
        // The server waits this long for the reply, from when it asked.
        let budget = Instant::now() + REQUEST_TIMEOUT + forward::SETUP_TIMEOUT;
        let request_lock = self.request_lock.try_lock().map_err(|_| {
            anyhow::anyhow!("another transfer is awaiting approval; retry after it is decided")
        })?;
        forward::target_endpoint(&target)?;
        crate::approval_command::check_authorizer(&command, &self.name)?;
        let args = crate::approval_command::parse(&command)?;
        anyhow::ensure!(
            eligible_target(&args)? == target,
            "the requesting command reads from a different server"
        );
        // A source deletes nothing.
        let caps = crate::directive::Caps {
            max_bytes: self.max_bytes,
            max_entries: self.max_entries,
            max_delete: 0,
        };
        // What the source's receiver will allow, before its home is known.
        let preview = crate::directive::issue(
            crate::directive::Binding {
                enrollment: crate::enrollment::EnrollmentId::random(),
                generation: 1,
                account: "preview".into(),
                role: crate::directive::Role::Source,
            },
            command.clone(),
            cwd.clone(),
            (inputs.clone(), Some(caps)),
            // Unused: a source has no results.
            [1; 32],
        )?;
        let reads = crate::directive::source_rules(
            &preview,
            Path::new(std::ffi::OsStr::from_bytes(REQUEST_ROOT)),
        )?;
        let count = self.forward_count.fetch_add(1, Ordering::AcqRel);
        let _slot = forward::Slot(&self.forward_count);
        anyhow::ensure!(
            count < 8,
            "too many copies from other servers are waiting for approval or setup here; retry after one is decided"
        );
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
        let source = forward::Account::find(&target, &cancelled)?;
        // A source only reads, so a root login can serve a download too:
        // the receiver refuses root only where it would write.
        if args.dry_run {
            source.ready_for_dry_run()?;
        }
        // Automatic approval of writes to this machine does not authorize
        // use of its SSH credentials on another host.
        self.approvals.request_source(
            &self.requester,
            &command,
            &cwd,
            (&target, source.enrollment, source.is_root()),
            &reads,
            self.notifications,
            cancelled,
        )?;
        anyhow::ensure!(!cancelled(), "source copy disconnected before setup");
        // This lock only serializes decisions, not enrollment.
        drop(request_lock);
        let policy = source.policy(&cancelled)?;
        let mut setup = crate::process::self_command()?;
        setup.arg("--return-prepare");
        let prepared = forward::prepare_in_child(
            setup,
            &forward::Prepare {
                command,
                cwd,
                inputs,
                caps,
                accounts: forward::Accounts::Source(source.setup(&policy)),
                results_key: None,
                via: Some((
                    self.server_user.clone(),
                    self.tcp_peer.host.clone(),
                    self.tcp_peer.port,
                )),
                allow_enrollment: !args.dry_run,
            },
            budget,
            &cancelled,
        )
        .with_context(|| format!("approve the copy from {target:?}"))?;
        anyhow::ensure!(!cancelled(), "source copy disconnected before setup");
        let issued = Issued {
            directive: prepared.directive,
            entry_key: prepared.entry_key,
            login: policy.login_user.clone(),
            known_hosts: policy.known_hosts_for_others()?,
            // The configured value stays here: it can hold commands and paths.
            known_hosts_left_out: policy.left_out_kind().map(str::to_owned),
        };
        write_message(&mut stream, &Reply::SourceDirective(Box::new(issued)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::destination::tests::broker;

    fn command(extra: &[&str]) -> Vec<Vec<u8>> {
        ["cp", "--from", "backup"]
            .into_iter()
            .chain(extra.iter().copied())
            .chain(["--src", "selected", "--as", "output"])
            .map(|arg| arg.as_bytes().to_vec())
            .collect()
    }

    fn read_request(target: &str, command: Vec<Vec<u8>>) -> Message {
        Message::Pull(Box::new(ReadRequest {
            target: target.into(),
            command,
            cwd: "~/job".into(),
            inputs: crate::directive::Inputs::default(),
        }))
    }

    #[test]
    fn source_request_is_derived_from_native_selection_and_limits_include_control() {
        let command = command(&[
            "--root",
            "/approved",
            "--follow-src",
            "--performance-tuning",
            "workers=1",
            "--resource-limits",
            "bandwidth=4M",
        ]);
        let args = crate::approval_command::parse(&command).unwrap();
        eligible_target(&args).unwrap();
        let request = source_request(&args, None).unwrap();
        assert_eq!(request.base.path, Some(b"/approved".to_vec()));
        assert!(request.base.confined);
        assert_eq!(request.selections[0].path, b"selected");
        assert!(request.selections[0].follow_root);
        assert_eq!(request.symlink_policy, OperatorSymlinkPolicy::FollowAll);
        assert_eq!(request.limits.max_connections, 2);
        assert_eq!(request.send_rate, Some(4 << 20));
    }

    #[test]
    fn source_filters_narrow_copy_but_do_not_change_read_scopes() {
        let plain = source_request(
            &crate::approval_command::parse(&command(&[])).unwrap(),
            None,
        )
        .unwrap();
        let filtered = source_request(
            &crate::approval_command::parse(&command(&["--ignore", "*.private"])).unwrap(),
            None,
        )
        .unwrap();
        assert_eq!(format!("{plain:?}"), format!("{filtered:?}"));
        // SSH data and unencrypted TCP work through the source's receiver;
        // options that choose another route do not.
        let eligible = |extra: &[&str]| {
            eligible_target(&crate::approval_command::parse(&command(extra)).unwrap())
        };
        assert_eq!(eligible(&["--no-tcp"]).unwrap(), "backup");
        assert_eq!(eligible(&["--no-tcp-encryption"]).unwrap(), "backup");
        for refused in [
            &["--rsh", "ssh"][..],
            &["--detach"],
            &["--coordinate-at", "src"],
        ] {
            assert!(eligible(refused).is_err(), "{refused:?}");
        }
    }

    #[test]
    fn source_validation_precedes_approval_and_outbound_ssh() {
        let root = crate::test_support::tempdir().unwrap();
        let (_broker, receiver, registration, _) = broker(root.path(), Approval::Always);
        let cases = [
            // Not a plain SSH endpoint.
            read_request("bad$(command)", command(&[])),
            // The command reads from another server than the one named.
            read_request("elsewhere", command(&[])),
            // Options this route refuses, and limits no source allows.
            read_request("backup", command(&["--rsh", "ssh"])),
            read_request("backup", command(&["--receiver-max-entries", "0"])),
            // A copy to another server, not to the requester.
            read_request(
                "backup",
                [
                    "cp", "--from", "backup", "--src", "x", "--to", "other", "--as", "y",
                ]
                .map(|arg| arg.as_bytes().to_vec())
                .to_vec(),
            ),
            // What the server read from files must match its command.
            Message::Pull(Box::new(ReadRequest {
                target: "backup".into(),
                command: command(&[]),
                cwd: String::new(),
                inputs: crate::directive::Inputs {
                    ignore: Vec::new(),
                    mapping: Some(crate::mapping::Authorization {
                        bytes: 1,
                        digest: [0; 32],
                    }),
                },
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

    /// A root login on the source only reads, so its download is asked
    /// about like any other.
    #[test]
    fn a_root_source_is_asked_about() {
        let root = crate::test_support::tempdir().unwrap();
        let (_broker, receiver, registration, _) = broker(root.path(), Approval::Always);
        let task = std::thread::spawn(move || {
            let command = [
                "cp",
                "--from",
                "root@backup",
                "--src",
                "selected",
                "--as",
                "output",
            ]
            .iter()
            .map(|arg| arg.as_bytes().to_vec())
            .collect();
            exchange(
                &registration,
                read_request("root@backup", command),
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
                panic!(
                    "root source request ended: {:?}",
                    task.join().unwrap().err()
                );
            }
            assert!(
                Instant::now() < deadline,
                "root source approval did not become pending"
            );
            std::thread::sleep(Duration::from_millis(5));
        };
        use crate::receive_approval::Kind;
        assert_eq!(pending.kind(), Kind::Source);
        let description =
            pending.description(&crate::persistence::Domain::default(), str::to_owned);
        assert!(
            description.contains("as root, so file permissions there do not limit"),
            "{description}"
        );
        receiver
            .approvals
            .decide(&pending.id, false, Kind::Source)
            .unwrap();
        assert!(task.join().unwrap().is_err());
    }

    /// A read whose command sends the files unencrypted warns of it.
    #[test]
    fn source_approval_warns_of_unencrypted_tcp() {
        for (extra, warns) in [
            (&[][..], false),
            (&["--no-tcp-encryption"], true),
            (&["--no-tcp-encryption", "--no-tcp"], false),
        ] {
            let root = crate::test_support::tempdir().unwrap();
            let (_broker, receiver, registration, _) = broker(root.path(), Approval::Always);
            let task = std::thread::spawn(move || {
                exchange(
                    &registration,
                    read_request("backup", command(extra)),
                    Duration::from_secs(3),
                    Some(Duration::from_secs(3)),
                )
            });
            let deadline = Instant::now() + Duration::from_secs(2);
            let pending = loop {
                if let Some(summary) = receiver.approvals.snapshots().first() {
                    break summary.clone();
                }
                assert!(!task.is_finished(), "{extra:?}: source request ended");
                assert!(Instant::now() < deadline, "{extra:?}: not pending");
                std::thread::sleep(Duration::from_millis(5));
            };
            let description =
                pending.description(&crate::persistence::Domain::default(), str::to_owned);
            assert_eq!(
                description.contains("The files go over TCP without encryption"),
                warns,
                "{extra:?}: {description}"
            );
            receiver
                .approvals
                .decide(&pending.id, false, crate::receive_approval::Kind::Source)
                .unwrap();
            assert!(task.join().unwrap().is_err());
        }
    }

    #[test]
    fn source_needs_its_own_decision_even_when_copies_are_automatically_approved() {
        for revoke in [false, true] {
            let root = crate::test_support::tempdir().unwrap();
            let (_broker, receiver, registration, _) = broker(root.path(), Approval::Always);
            let task = std::thread::spawn(move || {
                exchange(
                    &registration,
                    read_request("backup", command(&[])),
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
                    panic!("source request ended: {:?}", task.join().unwrap().err());
                }
                assert!(
                    Instant::now() < deadline,
                    "source approval did not become pending"
                );
                std::thread::sleep(Duration::from_millis(5));
            };
            use crate::receive_approval::Kind;
            assert_eq!(pending.kind(), Kind::Source);
            let json = serde_json::to_value(&pending).unwrap();
            assert_eq!(json["kind"], "source");
            assert!(json.get("destination").is_none());
            let description =
                pending.description(&crate::persistence::Domain::default(), str::to_owned);
            assert!(description.contains("Filters narrow the copy"));
            assert!(description.contains("exact non-directory"));
            assert!(description.contains("restricted copying on \"backup\""));
            // Approving sets up the source, but the copy itself only reads.
            assert!(description.contains("The copy only reads"), "{description}");
            assert!(!description.contains("as root"), "{description}");
            assert!(!description.contains("is changed"), "{description}");
            for old in [Kind::Copy, Kind::Command, Kind::Ssh, Kind::Storage] {
                assert!(receiver.approvals.decide(&pending.id, true, old).is_err());
            }
            if revoke {
                receiver.generation.fetch_add(1, Ordering::AcqRel);
            } else {
                receiver
                    .approvals
                    .decide(&pending.id, false, Kind::Source)
                    .unwrap();
            }
            assert!(task.join().unwrap().is_err());
            let deadline = Instant::now() + Duration::from_secs(2);
            while receiver.forward_count.load(Ordering::Acquire) != 0 {
                assert!(
                    Instant::now() < deadline,
                    "source request did not release its slot"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            assert!(receiver.approvals.snapshots().is_empty());
        }
    }
}

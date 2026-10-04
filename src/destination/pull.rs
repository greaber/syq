//! Laptop-approved source reads. Control metadata crosses the return channel;
//! payload workers connect directly to the source and never use laptop credentials.
use super::*;
use crate::proto::{OperatorSymlinkPolicy, SourceRootBase, SourceRootSelection};
use crate::restricted::source::{SourceAuthority, SourcePolicy, SourceTcpPolicy};
use std::fs::File;
use std::os::fd::FromRawFd;

const HELPER_VERSION: u16 = 1;
const LIFETIME: Duration = Duration::from_secs(7 * 24 * 60 * 60);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HelperRequest {
    version: u16,
    identity: String,
    request: PullRequest,
}

pub(crate) fn eligible_target(args: &crate::cli::Args) -> Result<String> {
    use crate::cli::{CoordinateAt, Interface, PeerAuth};
    let (destination, sources) = args
        .locations
        .split_last()
        .context("copy endpoints missing")?;
    let source = sources.first().context("copy source missing")?;
    if args.interface != Interface::NativeCp
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
        || args.no_tcp
        || args.no_tcp_encryption
        || args.peer_auth != PeerAuth::Restricted
        || args.coordinate_at != CoordinateAt::Auto
    {
        bail!("source authorization owns its SSH control connection and requires encrypted direct TCP; it cannot be combined with --rsh, --syq-path, --no-bootstrap, --detach, --no-tcp, --no-tcp-encryption, --peer-auth, or --coordinate-at");
    }
    anyhow::ensure!(args.descriptor_copy.is_none(), "source authorization requires pathname file selections; descriptor streams are not supported");
    let target = crate::remote_to_remote::endpoint_arg(source, None, None);
    forward::target_endpoint(&target)?;
    Ok(target)
}

pub(crate) fn request(args: &crate::cli::Args) -> Result<PullRequest> {
    eligible_target(args)?;
    let sources =
        crate::transfer::distinct_native_sources(&args.locations[..args.locations.len() - 1]);
    let (base, selections, symlink_policy) = crate::transfer::source_registration(&sources, args);
    let max_total_bytes = args
        .receiver_max_bytes
        .unwrap_or(8 * 1024 * 1024 * 1024 * 1024);
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
    let request = PullRequest {
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
            max_entries: args.receiver_max_entries.unwrap_or(100_000_000),
            max_total_bytes,
            max_file_bytes,
            hash_block_bytes: args.block_size,
            // The source authority counts its one control connection too.
            max_connections: u16::try_from(workers + 1)?,
            max_deletions: 0,
        },
    };
    request.validate()?;
    Ok(request)
}

impl PullRequest {
    fn validate(&self) -> Result<()> {
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
        SourceAuthority::new(self.policy())?;
        Ok(())
    }
    fn policy(&self) -> SourcePolicy {
        SourcePolicy {
            base: self.base.clone(),
            selections: self.selections.clone(),
            selection_types: self.selection_types.clone(),
            symlink_policy: self.symlink_policy,
            hashing: self.hashing,
            preservation: self.preservation,
            sparse: self.sparse,
            compressed: self.compressed,
            tcp: Some(SourceTcpPolicy {
                port_lo: self.tcp_ports.0,
                port_hi: self.tcp_ports.1,
                congestion_control: self.tcp_congestion.clone(),
            }),
            send_rate: self.send_rate,
            limits: self.limits.clone(),
            deadline: Instant::now() + LIFETIME,
        }
    }
    /// Do not stat the source before approval. The native registration resolves
    /// each selection as a directory root or exact leaf after permission arrives.
    pub(crate) fn scopes(&self) -> Vec<String> {
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
                format!(
                    "{} ({scope})",
                    crate::approval_command::display_arg(&selection.path)
                )
            })
            .collect()
    }
}

pub(crate) fn check(command: &[Vec<u8>], target: &str, requested: &PullRequest) -> Result<()> {
    let args = crate::approval_command::parse(command)?;
    anyhow::ensure!(
        eligible_target(&args)? == target,
        "requesting command reads from a different server"
    );
    let derived = request(&args)?;
    anyhow::ensure!(
        serde_json::to_value(requested)? == serde_json::to_value(derived)?,
        "source request does not match the command that produced it"
    );
    Ok(())
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
            Err(error) if crate::conn::is_ssh_authorization_fallback_error(&error) => error,
            Err(error) => return Err(error),
        };
        let Some(found) = names.into_iter().find_map(|name| {
            available(&name, Duration::from_secs(2))
                .ok()
                .map(|registration| (name, registration))
        }) else {
            return Err(error);
        };
        crate::output::diagnostic!(
            "syq: {}; trying source authorization through @{}",
            error.root_cause(),
            found.0
        );
        found
    };
    Ok(Some(handoff::Selection::new(
        name,
        registration,
        handoff::Kind::Pull,
        Some(target),
    )))
}

pub(super) fn prepare(args: &mut crate::cli::Args, selection: handoff::Selection) -> Result<()> {
    let handoff::Selection {
        name,
        registration,
        target,
        ..
    } = selection;
    let target = target.context("source authorization target missing")?;
    let request = request(args)?;
    crate::output::diagnostic!("syq: requesting permission from @{name} to read from {target:?}; approve on that machine with its desktop prompt or syq persist receive pending");
    let (stream, reply) = exchange(
        &registration,
        Message::Pull {
            target,
            command: crate::approval_command::current()?,
            cwd: crate::approval_command::current_directory(),
            request: Box::new(request),
        },
        REQUEST_TIMEOUT + forward::SETUP_TIMEOUT + Duration::from_secs(10),
        None,
    )?;
    let Reply::SourceApproved {
        data_hostname: Some(data_hostname),
    } = reply
    else {
        bail!("source approval did not provide its resolved data hostname");
    };
    args.auth_from = crate::cli::AuthFrom::Provider(crate::auth_from::Provider::Return(name));
    args.return_source = Some(ReturnConnection::source(stream, data_hostname)?);
    Ok(())
}

impl Receiver {
    pub(super) fn pull(
        &self,
        target: String,
        command: Vec<Vec<u8>>,
        cwd: String,
        mut request: PullRequest,
        mut stream: TrackedStream,
    ) -> Result<()> {
        let request_lock = self.request_lock.try_lock().map_err(|_| {
            anyhow::anyhow!("another transfer is awaiting approval; retry after it is decided")
        })?;
        forward::target_endpoint(&target)?;
        crate::approval_command::check_authorizer(&command, &self.name)?;
        check(&command, &target, &request)?;
        request.limits.max_total_bytes = request.limits.max_total_bytes.min(self.max_bytes);
        request.limits.max_file_bytes = request
            .limits
            .max_file_bytes
            .min(request.limits.max_total_bytes);
        request.limits.max_entries = request.limits.max_entries.min(self.max_entries);
        request.validate()?;
        let count = self.forward_count.fetch_add(1, Ordering::AcqRel);
        let _slot = forward::Slot(&self.forward_count);
        anyhow::ensure!(
            count < 8,
            "too many active remote copies; wait for one to finish"
        );
        let (generation, _channel) = {
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
        };
        let setup_cancelled = || cancelled() || requester_closed(&socket);
        self.approvals.request_source(
            &self.requester,
            &command,
            &cwd,
            &target,
            &request,
            self.notifications,
            setup_cancelled,
        )?;
        anyhow::ensure!(!setup_cancelled(), "source copy disconnected before setup");
        drop(request_lock);
        // Resolve on the machine that owns the SSH alias, after approval. The
        // requester may have different config and cannot infer this address.
        let deadline = Instant::now() + forward::SETUP_TIMEOUT;
        let data_hostname = forward::source_data_hostname(
            &forward::target_spec(&target)?,
            deadline,
            &setup_cancelled,
        )?;
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(target.as_bytes());
        let (mut child, reply) = forward::ForwardChild::connect(
            &encoded,
            &HelperRequest {
                version: HELPER_VERSION,
                identity: crate::identity::build().into(),
                request,
            },
            "--return-source",
            deadline,
            &setup_cancelled,
        )?;
        anyhow::ensure!(
            matches!(reply, Reply::SourceApproved { .. }),
            "invalid source setup response"
        );
        let result = (|| {
            let input = child.child.stdin.take().unwrap();
            let output = child.child.stdout.take().unwrap();
            socket.set_read_timeout(None)?;
            socket.set_write_timeout(None)?;
            write_message(
                &mut stream,
                &Reply::SourceApproved {
                    data_hostname: Some(data_hostname),
                },
            )?;
            forward::relay(socket.try_clone()?, input, output, cancelled, &mut child)
        })();
        result.with_context(|| format!("copy via this machine from {target:?}: {}", child.errors()))
    }
}

pub(super) fn receive() -> Result<i32> {
    crate::fsops::reserve_startup_descriptors();
    let fd = unsafe { libc::dup(libc::STDIN_FILENO) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut input = unsafe { File::from_raw_fd(fd) };
    let setup = (|| {
        let request: HelperRequest = read_message(&mut forward::DeadlineIo {
            inner: &mut input,
            deadline: Instant::now() + Duration::from_secs(10),
            cancelled: None,
        })?;
        anyhow::ensure!(
            request.version == HELPER_VERSION && request.identity == crate::identity::build(),
            "return source helper build mismatch"
        );
        request.request.validate()?;
        SourceAuthority::new(request.request.policy())
    })();
    let authority = match setup {
        Ok(authority) => authority,
        Err(error) => {
            write_message(&mut std::io::stdout(), &Reply::Error(format!("{error:#}")))?;
            return Err(error);
        }
    };
    write_message(
        &mut std::io::stdout(),
        &Reply::SourceApproved {
            data_hostname: None,
        },
    )?;
    let pending = Arc::new(AtomicBool::new(true));
    crate::server::run_authorized_source(
        forward::HandshakeInput::new(
            input,
            pending.clone(),
            START_TIMEOUT,
            Duration::from_secs(10),
        ),
        std::io::stdout(),
        authority,
        crate::descriptor_broker::DescriptorSessionSlot::default(),
        Some(pending),
    )?;
    Ok(0)
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
        let request = request(&args).unwrap();
        assert_eq!(request.base.path, Some(b"/approved".to_vec()));
        assert!(request.base.confined);
        assert_eq!(request.selections[0].path, b"selected");
        assert!(request.selections[0].follow_root);
        assert_eq!(request.symlink_policy, OperatorSymlinkPolicy::FollowAll);
        assert_eq!(request.limits.max_connections, 2);
        assert_eq!(request.send_rate, Some(4 << 20));
        check(&command, "backup", &request).unwrap();
        let mut changed = request.clone();
        changed.base.path = Some(b"/outside".to_vec());
        assert!(check(&command, "backup", &changed).is_err());
        changed = request.clone();
        changed.selections[0].path = b"other".to_vec();
        assert!(check(&command, "backup", &changed).is_err());
        assert!(check(&command, "another-host", &request).is_err());
    }

    #[test]
    fn source_filters_narrow_copy_but_do_not_change_read_scopes() {
        let plain = request(&crate::approval_command::parse(&command(&[])).unwrap()).unwrap();
        let filtered =
            request(&crate::approval_command::parse(&command(&["--ignore", "*.private"])).unwrap())
                .unwrap();
        assert_eq!(
            serde_json::to_value(&plain).unwrap(),
            serde_json::to_value(&filtered).unwrap()
        );
        assert_eq!(
            plain.scopes(),
            vec!["selected (directory tree or exact non-directory entry)"]
        );
        let args = crate::approval_command::parse(&command(&["--no-tcp"])).unwrap();
        assert!(eligible_target(&args)
            .unwrap_err()
            .to_string()
            .contains("requires encrypted direct TCP"));
    }

    #[test]
    fn source_validation_precedes_approval_and_outbound_ssh() {
        let root = crate::test_support::tempdir().unwrap();
        let (_broker, receiver, registration, _) = broker(root.path(), Approval::Always);
        let command = command(&[]);
        let request = request(&crate::approval_command::parse(&command).unwrap()).unwrap();
        for case in 0..4 {
            let mut request = request.clone();
            let mut target = "backup".to_owned();
            match case {
                0 => target = "bad$(command)".into(),
                1 => request.selections[0].path = b"/unapproved".to_vec(),
                2 => request.limits.max_entries = 0,
                _ => request.symlink_policy = OperatorSymlinkPolicy::FollowAll,
            }
            assert!(exchange(
                &registration,
                Message::Pull {
                    target,
                    command: command.clone(),
                    cwd: String::new(),
                    request: Box::new(request)
                },
                Duration::from_secs(2),
                Some(Duration::from_secs(2))
            )
            .is_err());
            assert!(receiver.approvals.snapshots().is_empty());
        }
        assert_eq!(receiver.forward_count.load(Ordering::Acquire), 0);
    }

    #[test]
    fn source_needs_its_own_decision_even_when_copies_are_automatically_approved() {
        for revoke in [false, true] {
            let root = crate::test_support::tempdir().unwrap();
            let (_broker, receiver, registration, _) = broker(root.path(), Approval::Always);
            let command = command(&[]);
            let request = request(&crate::approval_command::parse(&command).unwrap()).unwrap();
            let task = std::thread::spawn(move || {
                exchange(
                    &registration,
                    Message::Pull {
                        target: "backup".into(),
                        command,
                        cwd: "~/job".into(),
                        request: Box::new(request),
                    },
                    Duration::from_secs(3),
                    Some(Duration::from_secs(3)),
                )
            });
            let deadline = Instant::now() + Duration::from_secs(2);
            let pending = loop {
                if let Some(summary) = receiver.approvals.snapshots().first() {
                    break summary.clone();
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
            assert!(receiver.approvals.snapshots().is_empty());
        }
    }
}

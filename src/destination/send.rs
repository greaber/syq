//! Copies from a receiving machine to the server that asks for them
//! (`syq cp --from @NAME`). The receiving machine shows the exact paths,
//! waits for its user's approval, then serves read-only access to them over
//! the same channels and reverse TCP that copies sent to it use.
use super::*;
use crate::proto::{SourceRootBase, SourceRootSelection};
use crate::restricted::source::SourceAuthority;

/// What the receiving machine approved: the token that opens the copy's
/// channels and the source base and selections its reads are confined to.
/// They can differ from what the command named: the machine resolves them
/// in its receiving profile's directory and inside its `--root`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SendApproved {
    token: String,
    base: SourceRootBase,
    selections: Vec<SourceRootSelection>,
}

/// The receiving name a copy's sources are on, when they are on one.
pub(crate) fn source_name(args: &crate::cli::Args) -> Option<&str> {
    let (_, sources) = args.locations.split_last()?;
    sources
        .iter()
        .find_map(|source| source.host.as_deref()?.strip_prefix('@'))
}

/// The receiving name of a copy from it to this machine, after checking
/// that its endpoints can be one. Parsing checks this, so a receiving name
/// never reaches ssh.
pub(crate) fn check_endpoints(args: &crate::cli::Args) -> Result<String> {
    let name = source_name(args).context("copy source is not a receiving machine")?;
    let (destination, sources) = args
        .locations
        .split_last()
        .context("copy endpoints missing")?;
    anyhow::ensure!(
        args.interface == crate::cli::Interface::NativeCp && args.s3.is_none(),
        "copies from receiving machine @{name} must use syq cp"
    );
    anyhow::ensure!(
        sources.iter().all(|source| {
            source.host.as_deref() == Some(&format!("@{name}"))
                && source.user.is_none()
                && source.port.is_none()
        }),
        "a copy from receiving machine @{name} takes all its sources from @{name}"
    );
    anyhow::ensure!(
        !destination.is_remote(),
        "a copy from receiving machine @{name} goes to this machine; leave out --to, or run syq on @{name} to copy its files elsewhere"
    );
    Ok(name.to_owned())
}

/// The receiving name of a copy from it to this machine, after checking
/// that the copy can be one.
pub(crate) fn eligible(args: &crate::cli::Args) -> Result<String> {
    let name = check_endpoints(args)?;
    if args.rsh.is_some()
        || args.syq_path.is_some()
        || args.detach
        || args.restricted_grant.is_some()
        || args.no_tcp_encryption
        || args.peer_auth != crate::cli::PeerAuth::Restricted
        || args.coordinate_at != crate::cli::CoordinateAt::Auto
    {
        bail!("copies from receiving machines own their connection; --rsh, --syq-path, --detach, --peer-auth, --coordinate-at, and --no-tcp-encryption cannot be combined with them");
    }
    anyhow::ensure!(
        args.descriptor_copy.is_none(),
        "copies from receiving machines take named files; --src-fd and --as-fd are not supported with them"
    );
    anyhow::ensure!(
        !matches!(&args.auth_from, crate::cli::AuthFrom::Provider(crate::auth_from::Provider::Return(other)) if *other != name),
        "a copy from @{name} is approved on @{name}; leave out --auth-from"
    );
    Ok(name)
}

pub(crate) fn request(args: &crate::cli::Args) -> Result<pull::PullRequest> {
    eligible(args)?;
    pull::source_request(args)
}

/// Check that `request` is what the command that produced it asks for.
fn check(command: &[Vec<u8>], name: &str, requested: &pull::PullRequest) -> Result<()> {
    let args = crate::approval_command::parse(command)?;
    anyhow::ensure!(
        eligible(&args)? == name,
        "the requesting command copies from a different machine"
    );
    let derived = request(&args)?;
    anyhow::ensure!(
        serde_json::to_value(requested)? == serde_json::to_value(derived)?,
        "the request does not match the command that produced it"
    );
    Ok(())
}

pub(super) fn select(args: &crate::cli::Args) -> Result<Option<handoff::Selection>> {
    // A copy already approved has its route.
    if source_name(args).is_none() || args.named_source.is_some() {
        return Ok(None);
    }
    let name = check_endpoints(args)?;
    let registration = load_registration(&name)?;
    eligible(args)?;
    Ok(Some(handoff::Selection::new(
        name,
        registration,
        handoff::Kind::Send,
        None,
    )))
}

pub(super) fn prepare(args: &mut crate::cli::Args, selection: handoff::Selection) -> Result<()> {
    let handoff::Selection {
        name, registration, ..
    } = selection;
    let command = crate::approval_command::copy_command(args)?;
    let request = request(args)?;
    notices::waiting(&format!("@{name}"), "sending these files");
    let (_, reply) = exchange(
        &registration,
        Message::Send {
            command,
            cwd: crate::approval_command::current_directory(),
            request: Box::new(request.clone()),
        },
        REQUEST_TIMEOUT + Duration::from_secs(10),
        None,
    )?;
    let Reply::SendApproved(approved) = reply else {
        bail!("unexpected response from @{name}");
    };
    apply(args, &request, *approved, registration)
}

/// Read the copy's sources as the receiving machine approved them.
fn apply(
    args: &mut crate::cli::Args,
    request: &pull::PullRequest,
    approved: SendApproved,
    registration: Registration,
) -> Result<()> {
    anyhow::ensure!(
        approved.selections.len() == request.selections.len()
            && approved
                .selections
                .iter()
                .zip(&request.selections)
                .all(|(approved, requested)| approved.follow_root == requested.follow_root),
        "the receiving machine approved other sources than this copy names"
    );
    let resolved: HashMap<Vec<u8>, Vec<u8>> = request
        .selections
        .iter()
        .zip(approved.selections)
        .map(|(requested, approved)| (requested.path.clone(), approved.path))
        .collect();
    let count = args.locations.len() - 1;
    for source in &mut args.locations[..count] {
        source.path = resolved
            .get(&source.path)
            .context("the receiving machine did not approve every source")?
            .clone();
    }
    (args.native_source_root, args.native_source_cwd) = if approved.base.confined {
        (approved.base.path, None)
    } else {
        (None, approved.base.path)
    };
    args.named_source = Some(format!(
        "{PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&Route {
            registration,
            token: approved.token,
        })?)
    ));
    Ok(())
}

/// Whether `path` names a home directory path, `~` or `~/...`, which
/// syq reads from the home directory wherever it is used.
fn from_home(path: &[u8]) -> bool {
    path == b"~" || path.starts_with(b"~/")
}

/// Whether `path` is relative and has no `..`, so that it stays inside the
/// directory it is relative to. A home directory path is not relative.
fn stays_inside(path: &[u8]) -> bool {
    !path.starts_with(b"/")
        && !from_home(path)
        && !path.split(|byte| *byte == b'/').any(|part| part == b"..")
}

/// `path` as reading it uses it: a home directory path becomes the absolute
/// path in this machine's home, as the source registration expands it.
fn expand_home(path: Vec<u8>) -> Vec<u8> {
    if from_home(&path) {
        crate::fsops::resolve(&path).into_os_string().into_vec()
    } else {
        path
    }
}

fn join(directory: &Path, path: &[u8]) -> Vec<u8> {
    let mut joined = directory.as_os_str().as_bytes().to_vec();
    let path = path
        .split(|byte| *byte == b'/')
        .filter(|part| !part.is_empty() && *part != b".")
        .collect::<Vec<_>>();
    for part in path {
        if joined.last() != Some(&b'/') {
            joined.push(b'/');
        }
        joined.extend_from_slice(part);
    }
    joined
}

/// Resolve the request in the receiving profile: relative paths start in
/// `cwd`, and with a `root`, every read stays inside it. There paths must be
/// relative and cannot contain `..`, as for copies sent to this machine.
///
/// Under a root, the command's own `--root` stays the confined base, and
/// reading resolves it beneath this machine's root (`SourcePolicy::outer_root`),
/// so both confine. Otherwise the base is this machine's root, confined, and
/// the command's `-C` becomes a prefix of each selection. Either way every
/// component resolves beneath the root's descriptor, so neither a symlink
/// nor a directory replaced during the copy leads outside it.
fn resolve(cwd: &Path, root: Option<&Path>, request: &mut pull::PullRequest) -> Result<()> {
    let Some(root) = root else {
        request.base.path = Some(match request.base.path.take().map(expand_home) {
            Some(path) if path.starts_with(b"/") => path,
            Some(path) => join(cwd, &path),
            None => cwd.as_os_str().as_bytes().to_vec(),
        });
        for selection in &mut request.selections {
            selection.path = expand_home(std::mem::take(&mut selection.path));
        }
        return Ok(());
    };
    // Before approval, say nothing about where the root is.
    let outside = || {
        anyhow::anyhow!("files sent from this machine must be inside its receiving root; name them with relative paths without '..' or '~'")
    };
    if let Some(path) = &request.base.path {
        anyhow::ensure!(stays_inside(path), outside());
    }
    for selection in &request.selections {
        anyhow::ensure!(stays_inside(&selection.path), outside());
    }
    if request.base.confined {
        request.base.path = Some(join(cwd, request.base.path.as_deref().unwrap_or_default()));
        return Ok(());
    }
    let start = join(cwd, request.base.path.as_deref().unwrap_or_default());
    let prefix = Path::new(std::ffi::OsStr::from_bytes(&start))
        .strip_prefix(root)
        .map_err(|_| outside())?
        .as_os_str()
        .as_bytes()
        .to_vec();
    for selection in &mut request.selections {
        if !prefix.is_empty() {
            selection.path = [&prefix[..], b"/", &selection.path].concat();
        }
    }
    request.base = SourceRootBase {
        path: Some(root.as_os_str().as_bytes().to_vec()),
        confined: true,
    };
    Ok(())
}

/// The exact paths a resolved request reads, each with what it may be.
/// `..` is resolved by name, as reading resolves it: past a directory the
/// path names, not past where a symlink led (`OperatorResolver`).
fn exact_paths(request: &pull::PullRequest) -> Vec<(Vec<u8>, &'static str)> {
    let base = request.base.path.as_deref().unwrap_or(b"/");
    request
        .selections
        .iter()
        .zip(&request.selection_types)
        .map(|(selection, kind)| {
            let path = if selection.path.starts_with(b"/") {
                selection.path.clone()
            } else {
                join(
                    Path::new(std::ffi::OsStr::from_bytes(base)),
                    &selection.path,
                )
            };
            let path =
                crate::fsops::lexical_absolute(Path::new(std::ffi::OsStr::from_bytes(&path)))
                    .into_os_string()
                    .into_vec();
            let scope = match kind {
                crate::cli::SourceSelection::File => "a file or other non-directory",
                crate::cli::SourceSelection::Directory => "a directory and everything in it",
                crate::cli::SourceSelection::Contents => "everything in this directory",
                _ => "a directory and everything in it, or a single file",
            };
            (path, scope)
        })
        .collect()
}

impl Receiver {
    pub(super) fn send(
        &self,
        command: Vec<Vec<u8>>,
        cwd: String,
        mut request: pull::PullRequest,
        mut stream: TrackedStream,
    ) -> Result<()> {
        let _request = self.request_lock.try_lock().map_err(|_| {
            anyhow::anyhow!("another transfer is awaiting approval; retry after it is decided")
        })?;
        check(&command, &self.name, &request)?;
        request.limits.max_total_bytes = request.limits.max_total_bytes.min(self.max_bytes);
        request.limits.max_file_bytes = request
            .limits
            .max_file_bytes
            .min(request.limits.max_total_bytes);
        request.limits.max_entries = request.limits.max_entries.min(self.max_entries);
        resolve(&self.cwd, self.root.as_deref(), &mut request)?;
        request.validate()?;
        {
            let mut sessions = self.sessions.lock().unwrap();
            sessions.retain(|_, s| s.opened || s.issued.elapsed() < START_TIMEOUT);
            if sessions.len() >= 8 {
                bail!("too many active transfers; wait for one to finish");
            }
        }
        let generation = self.generation.load(Ordering::Acquire);
        let socket = stream.try_clone()?;
        let cancelled = || {
            self.stop.load(Ordering::Acquire)
                || self.generation.load(Ordering::Acquire) != generation
                || requester_closed(&socket)
        };
        // Sending is never approved automatically: --auto-approve-root
        // governs only what servers may write here.
        self.approvals.request_send(
            &self.requester,
            &command,
            &cwd,
            &exact_paths(&request),
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
            &request.limits,
            self.notifications,
            cancelled,
        )?;
        // Start the authority's clock at approval, after a long prompt.
        let mut policy = request.policy();
        policy.outer_root = self
            .root
            .as_ref()
            .map(|root| root.as_os_str().as_bytes().to_vec());
        let authority = SourceAuthority::new(policy)?;
        let mut sessions = self.sessions.lock().unwrap();
        if cancelled() {
            bail!("copy disconnected before approval could be used");
        }
        let token = random_token()?;
        sessions.insert(
            token.clone(),
            Session {
                tcp: None,
                authority: SessionAuthority::Send {
                    authority,
                    descriptors: Default::default(),
                },
                issued: Instant::now(),
                opened: false,
                channels: Arc::new(crate::private_broker::ConnectionRegistry::new(
                    Duration::from_secs(10),
                )),
            },
        );
        drop(sessions);
        write_message(
            &mut stream,
            &Reply::SendApproved(Box::new(SendApproved {
                token,
                base: request.base,
                selections: request.selections,
            })),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::destination::tests::broker;
    use std::fs;

    fn command(options: &[&str]) -> Vec<Vec<u8>> {
        ["cp", "--from", "@laptop"]
            .iter()
            .chain(options)
            .chain(&["--tcp-ports", "0-0", "--resource-limits", "workers=2"])
            .map(|arg| arg.as_bytes().to_vec())
            .collect()
    }

    /// Ask `registration` to send what `command` names, approving or denying
    /// it on the receiving machine, and return what that machine showed.
    fn ask(
        receiver: &Arc<Receiver>,
        registration: &Registration,
        command: &[Vec<u8>],
        allow: bool,
    ) -> (Result<SendApproved>, crate::receive_approval::Summary) {
        let args = crate::approval_command::parse(command).unwrap();
        let request = request(&args).unwrap();
        let registration = registration.clone();
        let command = command.to_vec();
        let task = std::thread::spawn(move || {
            exchange(
                &registration,
                Message::Send {
                    command,
                    cwd: "~/job".into(),
                    request: Box::new(request),
                },
                Duration::from_secs(10),
                Some(Duration::from_secs(10)),
            )
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        let pending = loop {
            if let Some(summary) = receiver.approvals.snapshots().first() {
                break summary.clone();
            }
            assert!(Instant::now() < deadline, "sending did not become pending");
            std::thread::sleep(Duration::from_millis(5));
        };
        // Other kinds of decision cannot answer it.
        for other in [
            crate::receive_approval::Kind::Copy,
            crate::receive_approval::Kind::Source,
        ] {
            assert!(receiver.approvals.decide(&pending.id, true, other).is_err());
        }
        receiver
            .approvals
            .decide(&pending.id, allow, crate::receive_approval::Kind::Send)
            .unwrap();
        let reply = task.join().unwrap().and_then(|(_, reply)| match reply {
            Reply::SendApproved(approved) => Ok(*approved),
            _ => bail!("unexpected reply"),
        });
        (reply, pending)
    }

    /// One framed channel to an approved copy, as the coordinator opens it.
    struct Channel {
        reader: crate::proto::FrameReader<UnixStream>,
        writer: crate::proto::FrameWriter<UnixStream>,
        stream: UnixStream,
    }
    impl Channel {
        fn open(
            registration: &Registration,
            token: &str,
            role: crate::proto::ConnectionRole,
        ) -> Result<(Self, crate::proto::Response)> {
            let control = matches!(role, crate::proto::ConnectionRole::Control);
            let (stream, reply) = exchange(
                registration,
                Message::Open {
                    token: token.into(),
                    control,
                },
                Duration::from_secs(5),
                Some(Duration::from_secs(5)),
            )?;
            anyhow::ensure!(matches!(reply, Reply::Ready), "channel not opened");
            let mut channel = Self {
                reader: crate::proto::FrameReader::new(stream.try_clone()?),
                writer: crate::proto::FrameWriter::new(stream.try_clone()?, false),
                stream,
            };
            let hello = channel.call(crate::proto::Request::Hello {
                identity: crate::identity::build().into(),
                compress: false,
                debug: false,
                token: Vec::new(),
                role,
            })?;
            Ok((channel, hello))
        }
        fn call(&mut self, request: crate::proto::Request) -> Result<crate::proto::Response> {
            self.writer.write_msg(&request)?;
            Ok(self.reader.read_msg()?)
        }
    }

    fn read(source: &crate::proto::RegisteredPath) -> crate::proto::Request {
        crate::proto::Request::ReadRange {
            path: b"/ignored".to_vec(),
            source: Some(source.clone()),
            attempt: 0,
            off: 0,
            len: 8,
        }
    }

    /// The approved file can be read only by a worker of the copy's control,
    /// a token opens control once, and closing control ends the workers.
    #[test]
    fn an_approved_send_reads_only_its_files_while_its_control_lasts() {
        use crate::proto::{ConnectionRole, Request, Response};
        let temp = crate::test_support::tempdir().unwrap();
        let root = temp.path().join("laptop");
        fs::create_dir_all(root.join(".kube")).unwrap();
        fs::write(root.join(".kube/config"), b"clusters").unwrap();
        fs::write(root.join("secret"), b"secret").unwrap();
        // Receiving here is approved automatically; sending still asks.
        let (_broker, receiver, registration, _) = broker(&root, Approval::Always);
        let command = command(&[
            "--no-compress",
            "--src-non-dir",
            ".kube/config",
            "--into",
            "/server/out",
        ]);
        let (approved, pending) = ask(&receiver, &registration, &command, true);
        let approved = approved.unwrap();
        let json = serde_json::to_value(&pending).unwrap();
        assert_eq!(json["kind"], "send");
        let shown = root.join(".kube/config").display().to_string();
        assert!(
            json["paths"][0]
                .as_str()
                .unwrap()
                .starts_with(&format!("{shown:?} (")),
            "{json}"
        );
        let description =
            pending.description(&crate::persistence::Domain::default(), str::to_owned);
        assert!(description.contains("leave this machine"), "{description}");
        assert!(description.contains(&shown), "{description}");

        // The coordinator registers what was approved.
        let mut args = crate::approval_command::parse(&command).unwrap();
        let request = request(&args).unwrap();
        apply(&mut args, &request, approved.clone(), registration.clone()).unwrap();
        assert!(args.named_source.is_some());
        let (base, selections, symlink_policy) =
            crate::transfer::source_registration(&args.locations[..1], &args);
        let (mut control, hello) =
            Channel::open(&registration, &approved.token, ConnectionRole::Control).unwrap();
        assert!(matches!(hello, Response::HelloOk { .. }), "{hello:?}");
        assert!(
            Channel::open(&registration, &approved.token, ConnectionRole::Control).is_err(),
            "a token opened control twice"
        );
        let mut other = selections.clone();
        other[0].path = b"secret".to_vec();
        let register = |selections| Request::RegisterSourceRoots {
            base: base.clone(),
            selections,
            symlink_policy,
            allow_unconfined_paths: false,
            shared_workers: 1,
            independent_handoff_workers: 0,
        };
        assert!(matches!(
            control.call(register(other)).unwrap(),
            Response::Err(error) if error.contains("differs from approval")
        ));
        let roots = match control.call(register(selections)).unwrap() {
            Response::SourceRootsRegistered(roots) => roots,
            other => panic!("registration failed: {other:?}"),
        };
        let file = roots[0].selection.clone();
        // File data goes over workers only.
        assert!(matches!(
            control.call(read(&file)).unwrap(),
            Response::Err(_)
        ));
        let (mut worker, hello) = Channel::open(
            &registration,
            &approved.token,
            ConnectionRole::SourceWorker {
                roots: roots.clone(),
                send_budget: None,
            },
        )
        .unwrap();
        assert!(matches!(hello, Response::HelloOk { .. }), "{hello:?}");
        let block = worker.call(read(&file)).unwrap();
        assert!(
            matches!(&block, Response::Block { data, .. } if data == b"clusters"),
            "{block:?}"
        );
        // Nothing can be changed on the sending machine.
        assert!(matches!(
            worker
                .call(Request::Apply {
                    ops: vec![crate::proto::Op::Mkdir {
                        path: root.join("made").as_os_str().as_bytes().to_vec(),
                        mode: 0o755,
                        condition: crate::proto::TargetCondition::Any,
                    }],
                })
                .unwrap(),
            Response::Err(_)
        ));
        assert!(!root.join("made").exists());

        control.stream.shutdown(std::net::Shutdown::Both).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !receiver.sessions.lock().unwrap().is_empty() {
            assert!(
                Instant::now() < deadline,
                "the session outlived its control"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!matches!(
            worker.call(read(&file)),
            Ok(Response::Block { .. })
        ));
        assert!(Channel::open(
            &registration,
            &approved.token,
            ConnectionRole::SourceWorker {
                roots,
                send_budget: None
            },
        )
        .is_err());
    }

    /// Approve sending what `options` name from `receiver`, then open the
    /// copy's control and register its sources as the coordinator does.
    fn register(
        receiver: &Arc<Receiver>,
        registration: &Registration,
        options: &[&str],
    ) -> Result<(Channel, Vec<crate::proto::RegisteredSourceRoot>)> {
        use crate::proto::{ConnectionRole, Request, Response};
        let command = command(&[&["--no-compress"], options, &["--into", "/server/out"]].concat());
        let (approved, _) = ask(receiver, registration, &command, true);
        let approved = approved?;
        let mut args = crate::approval_command::parse(&command)?;
        let request = request(&args)?;
        apply(&mut args, &request, approved.clone(), registration.clone())?;
        let count = args.locations.len() - 1;
        let (base, selections, symlink_policy) =
            crate::transfer::source_registration(&args.locations[..count], &args);
        let (mut control, hello) =
            Channel::open(registration, &approved.token, ConnectionRole::Control)?;
        anyhow::ensure!(matches!(hello, Response::HelloOk { .. }), "{hello:?}");
        match control.call(Request::RegisterSourceRoots {
            base,
            selections,
            symlink_policy,
            allow_unconfined_paths: false,
            shared_workers: 1,
            independent_handoff_workers: 0,
        })? {
            Response::SourceRootsRegistered(roots) => Ok((control, roots)),
            other => bail!("registration refused: {other:?}"),
        }
    }

    fn worker(
        registration: &Registration,
        control: &Channel,
        roots: &[crate::proto::RegisteredSourceRoot],
        receiver: &Arc<Receiver>,
    ) -> Channel {
        let _ = control;
        let token = receiver
            .sessions
            .lock()
            .unwrap()
            .keys()
            .next()
            .unwrap()
            .clone();
        let (worker, hello) = Channel::open(
            registration,
            &token,
            crate::proto::ConnectionRole::SourceWorker {
                roots: roots.to_vec(),
                send_budget: None,
            },
        )
        .unwrap();
        assert!(
            matches!(hello, crate::proto::Response::HelloOk { .. }),
            "{hello:?}"
        );
        worker
    }

    /// Neither the command's own `--root` or `-C` nor a named path reaches
    /// outside the receiving root through a symlink, even with
    /// `--follow-src`, and a directory replaced after registration still
    /// reads what was registered.
    #[test]
    fn symlinks_and_replaced_directories_stay_inside_the_receiving_root() {
        let temp = crate::test_support::tempdir().unwrap();
        let root = temp.path().join("laptop");
        let outside = temp.path().join("outside");
        fs::create_dir_all(root.join("inside")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(root.join("inside/secret"), b"inside!!").unwrap();
        fs::write(outside.join("secret"), b"OUTSIDE!").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("absolute")).unwrap();
        std::os::unix::fs::symlink("../outside", root.join("relative")).unwrap();
        let (_broker, receiver, registration, _) = broker(&root, Approval::Always);
        for link in ["absolute", "relative"] {
            let named = format!("{link}/secret");
            for options in [
                &["--root", link, "--src-non-dir", "secret"][..],
                &["--root", link, "--follow-src", "--src-non-dir", "secret"],
                &["-C", link, "--src-non-dir", "secret"],
                &["-C", link, "--follow-src", "--src-non-dir", "secret"],
                &["--src-non-dir", &named],
                &["--follow-src", "--src-non-dir", &named],
            ] {
                assert!(
                    register(&receiver, &registration, options).is_err(),
                    "{options:?} registered a path outside the receiving root"
                );
                receiver.sessions.lock().unwrap().clear();
            }
        }
        // A symlink that stays inside the root is followed when asked.
        std::os::unix::fs::symlink("inside", root.join("within")).unwrap();
        for options in [
            &[
                "--root",
                "within",
                "--follow-src",
                "--src-non-dir",
                "secret",
            ][..],
            &["--root", "inside", "--src-non-dir", "secret"],
        ] {
            let (control, roots) = register(&receiver, &registration, options).unwrap();
            let mut worker = worker(&registration, &control, &roots, &receiver);
            let block = worker.call(read(&roots[0].selection)).unwrap();
            assert!(
                matches!(&block, crate::proto::Response::Block { data, .. } if data.starts_with(b"inside")),
                "{options:?}: {block:?}"
            );
            if options[1] == "inside" {
                // Replace the registered directory with a symlink out of the
                // root: reads keep using what was registered.
                fs::rename(root.join("inside"), root.join("moved")).unwrap();
                std::os::unix::fs::symlink(&outside, root.join("inside")).unwrap();
                let block = worker.call(read(&roots[0].selection)).unwrap();
                assert!(
                    !matches!(&block, crate::proto::Response::Block { data, .. } if data.starts_with(b"OUTSIDE")),
                    "{block:?}"
                );
            }
            drop(worker);
            drop(control);
            receiver.sessions.lock().unwrap().clear();
        }
    }

    /// The command's own `--root` still confines as it does for any copy:
    /// with `--follow-src`, a symlink in it to a sibling inside the
    /// receiving root is refused, while `-C` only says where paths start.
    #[test]
    fn the_commands_own_root_still_confines_inside_the_receiving_root() {
        let temp = crate::test_support::tempdir().unwrap();
        let root = temp.path().join("laptop");
        fs::create_dir_all(root.join("sub")).unwrap();
        fs::create_dir_all(root.join("private")).unwrap();
        fs::write(root.join("private/token"), b"private!").unwrap();
        std::os::unix::fs::symlink("../private", root.join("sub/escape")).unwrap();
        let (_broker, receiver, registration, _) = broker(&root, Approval::Always);
        for options in [
            &[
                "--root",
                "sub",
                "--follow-src",
                "--src-non-dir",
                "escape/token",
            ][..],
            &["--root", "sub", "--follow-src", "escape"],
            &["--root", "sub", "--src-non-dir", "escape/token"],
        ] {
            assert!(
                register(&receiver, &registration, options).is_err(),
                "{options:?} left the command's --root"
            );
            receiver.sessions.lock().unwrap().clear();
        }
        let (control, roots) = register(
            &receiver,
            &registration,
            &["-C", "sub", "--follow-src", "--src-non-dir", "escape/token"],
        )
        .unwrap();
        let mut worker = worker(&registration, &control, &roots, &receiver);
        assert!(matches!(
            worker.call(read(&roots[0].selection)).unwrap(),
            crate::proto::Response::Block { data, .. } if data == b"private!"
        ));
    }

    /// The receiving profile's byte and entry limits lower what the server
    /// asks for, the prompt shows the lowered limits, and reads obey them.
    #[test]
    fn the_receiving_profiles_limits_bound_what_is_sent() {
        use crate::proto::{Request, Response};
        let temp = crate::test_support::tempdir().unwrap();
        let root = temp.path().join("laptop");
        fs::create_dir_all(root.join("tree")).unwrap();
        for name in ["a", "b", "c", "d"] {
            fs::write(root.join("tree").join(name), b"12345678").unwrap();
        }
        let (_broker, receiver, registration, _) =
            crate::destination::tests::broker_with_limits(&root, Approval::Always, 0, 3);
        let command = command(&["tree", "--into", "/server/out"]);
        let (approved, pending) = ask(&receiver, &registration, &command, true);
        approved.unwrap();
        let json = serde_json::to_value(&pending).unwrap();
        assert_eq!(json["max_entries"], 3, "{json}");
        assert_eq!(json["max_bytes"], 10_000_000, "{json}");
        receiver.sessions.lock().unwrap().clear();

        let (mut control, roots) = register(&receiver, &registration, &["tree"]).unwrap();
        control
            .writer
            .write_msg(&Request::Scan {
                root: b"/ignored".to_vec(),
                source: Some(roots[0].selection.clone()),
                follow_root: false,
                ignore: Vec::new(),
                report_ignored: true,
            })
            .unwrap();
        loop {
            match control.reader.read_msg::<Response>().unwrap() {
                Response::ScanBatch(_) => {}
                Response::Err(error) => {
                    assert!(error.contains("entry limit"), "{error}");
                    break;
                }
                other => panic!("the scan passed the entry limit: {other:?}"),
            }
        }
        let mut worker = worker(&registration, &control, &roots, &receiver);
        let past = Request::ReadRange {
            path: b"/ignored".to_vec(),
            source: Some(roots[0].selection.clone()),
            attempt: 0,
            off: 10_000_000 - 4,
            len: 8,
        };
        assert!(
            matches!(worker.call(past).unwrap(), Response::Err(error) if error.contains("byte limit"))
        );
    }

    #[test]
    fn a_denied_send_issues_nothing() {
        let temp = crate::test_support::tempdir().unwrap();
        fs::write(temp.path().join("secret"), b"x").unwrap();
        let (_broker, receiver, registration, _) = broker(temp.path(), Approval::Always);
        let (approved, _) = ask(&receiver, &registration, &command(&["secret"]), false);
        assert!(approved.is_err());
        assert!(receiver.sessions.lock().unwrap().is_empty());
    }

    #[test]
    fn reads_stay_inside_the_receiving_root() {
        let root = Path::new("/home/me/shared");
        let cwd = root.join("work");
        let resolved = |options: &[&str]| {
            let mut request =
                request(&crate::approval_command::parse(&command(options)).unwrap()).unwrap();
            resolve(&cwd, Some(root), &mut request).map(|()| request)
        };
        let request = resolved(&["notes", "a/b"]).unwrap();
        assert_eq!(request.base.path.as_deref(), Some(&b"/home/me/shared"[..]));
        assert!(request.base.confined);
        let paths: Vec<_> = request.selections.iter().map(|s| s.path.clone()).collect();
        assert_eq!(paths, [b"work/notes".to_vec(), b"work/a/b".to_vec()]);
        assert_eq!(
            exact_paths(&request)
                .into_iter()
                .map(|(path, _)| path)
                .collect::<Vec<_>>(),
            [
                b"/home/me/shared/work/notes".to_vec(),
                b"/home/me/shared/work/a/b".to_vec()
            ]
        );
        let request = resolved(&["-C", "sub", "notes"]).unwrap();
        assert_eq!(request.selections[0].path, b"work/sub/notes");
        // The command's own --root stays its base; reading resolves it
        // beneath this machine's root.
        let request = resolved(&["--root", "sub", "notes"]).unwrap();
        assert_eq!(
            request.base.path.as_deref(),
            Some(&b"/home/me/shared/work/sub"[..])
        );
        assert!(request.base.confined);
        assert_eq!(request.selections[0].path, b"notes");
        for outside in [
            &["/etc/passwd"][..],
            &["../secret"],
            &["~/secret"],
            &["~"],
            &["-C", "..", "secret"],
            &["-C", "/etc", "passwd"],
            &["-C", "~", "secret"],
            &["--root", "/etc", "passwd"],
            &["--root", "~/elsewhere", "passwd"],
        ] {
            let error = resolved(outside).unwrap_err().to_string();
            assert!(
                error.contains("inside its receiving root"),
                "{outside:?}: {error}"
            );
            // Before approval, the server does not learn where the root is.
            assert!(!error.contains("/home/me"), "{error}");
        }
        // Without a root, relative paths start in the profile's directory
        // and others stay as named.
        let mut request = super::request(
            &crate::approval_command::parse(&command(&["/etc/hosts", "notes"])).unwrap(),
        )
        .unwrap();
        resolve(&cwd, None, &mut request).unwrap();
        assert_eq!(
            request.base.path.as_deref(),
            Some(&b"/home/me/shared/work"[..])
        );
        assert!(!request.base.confined);
        assert_eq!(
            exact_paths(&request)
                .into_iter()
                .map(|(path, _)| path)
                .collect::<Vec<_>>(),
            [
                b"/etc/hosts".to_vec(),
                b"/home/me/shared/work/notes".to_vec()
            ]
        );
        // The prompt shows `..` resolved, as reading resolves it: by name.
        let mut request = super::request(
            &crate::approval_command::parse(&command(&[
                "project/docs/../../.aws/credentials",
                "/srv/./data/../keys",
            ]))
            .unwrap(),
        )
        .unwrap();
        resolve(&cwd, None, &mut request).unwrap();
        assert_eq!(
            exact_paths(&request)
                .into_iter()
                .map(|(path, _)| path)
                .collect::<Vec<_>>(),
            [
                b"/home/me/shared/work/.aws/credentials".to_vec(),
                b"/srv/keys".to_vec()
            ]
        );
        // Home directory paths are shown and read in this machine's home,
        // not in the profile's directory.
        let home = std::env::var_os("HOME").unwrap().into_vec();
        let mut request = super::request(
            &crate::approval_command::parse(&command(&["-C", "~/projects", "~/token", "notes"]))
                .unwrap(),
        )
        .unwrap();
        resolve(&cwd, None, &mut request).unwrap();
        assert_eq!(
            request.base.path.as_deref(),
            Some(&[&home[..], b"/projects"].concat()[..])
        );
        let token = [&home[..], b"/token"].concat();
        assert_eq!(request.selections[0].path, token);
        assert_eq!(
            exact_paths(&request)
                .into_iter()
                .map(|(path, _)| path)
                .collect::<Vec<_>>(),
            [token, [&home[..], b"/projects/notes"].concat()]
        );
    }

    #[test]
    fn a_send_request_must_match_its_command() {
        let command = command(&["notes"]);
        let args = crate::approval_command::parse(&command).unwrap();
        let mut changed = request(&args).unwrap();
        check(&command, "laptop", &changed).unwrap();
        assert!(check(&command, "other", &changed).is_err());
        changed.selections[0].path = b"/etc".to_vec();
        assert!(check(&command, "laptop", &changed).is_err());
        // Parsing refuses endpoints a receiving name cannot have, before
        // anything could hand the name to ssh.
        for refused in [
            &["notes", "--to", "elsewhere"][..],
            &["notes", "--to", "@laptop"],
        ] {
            let argv: Vec<OsString> = ["cp", "--from", "@laptop"]
                .iter()
                .chain(refused)
                .map(OsString::from)
                .collect();
            assert!(crate::cli::Args::parse_args(&argv).is_err(), "{refused:?}");
        }
        for refused in [
            &["notes", "--rsh", "ssh"][..],
            &["notes", "--auth-from", "@other"],
        ] {
            let args = crate::approval_command::parse(
                &["cp", "--from", "@laptop"]
                    .iter()
                    .chain(refused)
                    .map(|word| word.as_bytes().to_vec())
                    .collect::<Vec<_>>(),
            )
            .unwrap();
            assert!(eligible(&args).is_err(), "{refused:?}");
        }
    }
}

use super::*;
use std::os::fd::AsFd;
use std::time::Duration;

/// The enrollment's state directory and its configuration, for the account
/// this receiver runs as.
fn receiver_state(id: EnrollmentId) -> Result<(PathBuf, ReceiverEnrollment)> {
    let (login, home) = current_account()?;
    let state = enrollment_state(&home, id);
    let config = read_receiver_config(&state)?.with_context(|| {
        format!("this server has no state for enrollment {id}; run `syq receiver enroll {login}@HOST` on your machine to set restricted copying up again")
    })?;
    if config.id != id {
        bail!("restricted receiver configuration does not match enrollment");
    }
    Ok((state, config))
}

/// How many sessions an entry key may have open on one enrollment before
/// they have shown a verified directive or a running copy's worker ticket.
/// Former coordinators keep the entry key, so this bounds what they can start
/// without a fresh directive.
const UNVERIFIED_SESSIONS: u64 = 8;
/// How long a session has to take one of those slots and send its first
/// frame.
const ADMISSION_TIMEOUT: Duration = Duration::from_secs(10);
/// The largest first frame a session may send.
const MAX_ADMISSION_BYTES: usize = crate::directive::MAX_SIGNED_BYTES + 64;

/// The first frame of every session an entry key starts, before any other
/// byte. The command a client asks sshd for is only data: the line's forced
/// command runs whatever it asked.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Admission {
    /// Start a copy with this signed directive.
    Copy(Vec<u8>),
    /// Join a running copy as an SSH worker, with its ticket.
    Worker(String),
}

impl Admission {
    /// The frame: a 4-byte big-endian length, then the postcard encoding.
    pub(crate) fn frame(&self) -> Result<Vec<u8>> {
        let body = postcard::to_stdvec(self).context("encode the admission frame")?;
        if body.len() > MAX_ADMISSION_BYTES {
            bail!("the admission frame exceeds its size limit");
        }
        Ok([(body.len() as u32).to_be_bytes().as_slice(), &body].concat())
    }

    /// Read exactly one frame from `input` by `deadline`, and nothing after
    /// it: what follows belongs to the session.
    pub(super) fn read(
        input: &mut (impl Read + std::os::fd::AsRawFd),
        deadline: Instant,
    ) -> Result<Self> {
        let mut input = crate::destination::DeadlineIo {
            inner: input,
            deadline,
            cancelled: None,
        };
        let mut length = [0u8; 4];
        input
            .read_exact(&mut length)
            .context("read the session's first frame")?;
        let length = u32::from_be_bytes(length) as usize;
        if length == 0 || length > MAX_ADMISSION_BYTES {
            bail!("the session's first frame has an unsupported length");
        }
        let mut body = vec![0; length];
        input
            .read_exact(&mut body)
            .context("read the session's first frame")?;
        let (admission, rest): (Self, &[u8]) =
            postcard::take_from_bytes(&body).context("decode the session's first frame")?;
        if !rest.is_empty() {
            bail!("the session's first frame has trailing bytes");
        }
        Ok(admission)
    }
}

/// One of the enrollment's slots for sessions that have not been verified
/// yet: a lock on one of the files `session-slot-N` in its state directory.
/// Dropping it closes the file, which releases the lock, as exiting does.
pub(super) struct UnverifiedSlot(#[allow(dead_code)] File);

impl UnverifiedSlot {
    /// Take a free slot of the `slots`, waiting for one until `deadline`.
    pub(super) fn take(state: &Path, slots: u64, deadline: Instant) -> Result<Self> {
        loop {
            for slot in 0..slots {
                let file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(state.join(format!("session-slot-{slot}")))
                    .context("open the enrollment's session slots")?;
                let metadata = file.metadata()?;
                if !metadata.is_file()
                    || metadata.nlink() != 1
                    || metadata.uid() != unsafe { libc::geteuid() }
                    || metadata.mode() & 0o7777 != 0o600
                {
                    bail!("the enrollment's session slots must be private, singly linked regular files");
                }
                // SAFETY: the descriptor stays open for the call.
                if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                    return Ok(Self(file));
                }
                let error = std::io::Error::last_os_error();
                if !matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) {
                    return Err(error).context("lock a session slot");
                }
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                bail!(
                    "{slots} other connections are already waiting to start a copy on this enrollment; try again, or replace its entry key with `syq receiver revoke` and enroll again if this persists"
                );
            }
            std::thread::sleep(remaining.min(Duration::from_millis(20)));
        }
    }
}

/// What a session the forced command started may go on to do.
pub(crate) enum Session {
    /// Serve a copy a verified directive allows.
    Copy(std::sync::Arc<RestrictedAuthority>),
    /// This session's input and output were handed to the running copy its
    /// worker ticket names, which has served them.
    Worker,
}

/// Admit a session of the forced command of syq's line,
/// `--restricted-receiver --enrollment=ID --generation=N`: take a slot,
/// read the first frame, and then either verify a new copy's directive or
/// hand the session to the running copy whose worker ticket it shows.
pub(crate) fn admit_session(enrollment: &str, generation: &str) -> Result<Session> {
    refuse_privileged_receiver(Some(enrollment))?;
    let enrollment = EnrollmentId::parse(enrollment)?;
    let generation: u64 = generation
        .parse()
        .context("restricted receiver generation must be a number")?;
    let deadline = Instant::now() + ADMISSION_TIMEOUT;
    let (state, config) = receiver_state(enrollment)?;
    let slot = UnverifiedSlot::take(&state, UNVERIFIED_SESSIONS, deadline)?;
    // Read exactly the frame from the session's input, unbuffered, so the
    // copy's own protocol after it stays where the server reads it.
    let mut input = File::from(
        std::io::stdin()
            .as_fd()
            .try_clone_to_owned()
            .context("take the session's input")?,
    );
    match Admission::read(&mut input, deadline)? {
        Admission::Worker(ticket) => {
            // A worker joins a copy that is already running, which continues
            // whatever has changed since it started.
            ssh::enter_state_directory(&state)?;
            let socket = ssh::join(&ticket)?;
            drop(slot);
            crate::descriptor_broker::hand_over_standard_streams(socket)
                .context("hand the restricted SSH worker to the receiver")?;
            Ok(Session::Worker)
        }
        Admission::Copy(directive) => {
            let authority = admit(
                &state,
                &config,
                (generation, crate::identity::build()),
                &directive,
            )?;
            drop(slot);
            Ok(Session::Copy(authority))
        }
    }
}

/// Admit a new copy's directive and set up its authority: refused by a
/// receiver of another generation or build, then checked against the
/// trusted login key and its policy, its rules derived from its command, and
/// only then recorded as used.
pub(super) fn admit(
    state: &Path,
    config: &ReceiverEnrollment,
    (generation, build): (u64, &str),
    directive: &[u8],
) -> Result<std::sync::Arc<RestrictedAuthority>> {
    let observed_state = fs::symlink_metadata(state).context("inspect receiver enrollment")?;
    let (_, home) = current_account()?;
    let canonical_home = fs::canonicalize(&home)
        .with_context(|| format!("resolve receiver home {}", home.display()))?;
    let protected = receiver_control_paths(&canonical_home, None, ControlPaths::Here)?;
    let ((grant, constraints), verified) =
        verify(state, config, (generation, build), directive, &home)?;
    let results_key = load_results_key(state)?;
    let root = ConfinedRoot::resolve(&grant.copy.destination, &protected)?;
    let authority = std::sync::Arc::new(RestrictedAuthority::new(
        root,
        grant,
        constraints,
        verified.digest,
        results_key,
        verified.execution_deadline,
        &protected,
    )?);
    ssh::enter_state_directory(state)?;
    // Verification does not hold the lifecycle lock or permit mutations. A
    // revoke during verification is caught when this receiver tries to enter.
    active::watch(
        &home,
        state,
        (observed_state.dev(), observed_state.ino()),
        verified.execution_deadline,
    )?;
    Ok(authority)
}

/// Verify a directive and derive its rules, recording it as used only when
/// everything passes.
pub(super) fn verify(
    state: &Path,
    config: &ReceiverEnrollment,
    (generation, build): (u64, &str),
    directive: &[u8],
    home: &Path,
) -> Result<((Grant, GrantConstraints), delegation::VerifiedDirective)> {
    require_current_receiver(config, generation, build)?;
    let replay = delegation::ReplayStore::open(&state.join("replay")).with_context(|| {
        format!(
            "this server cannot read its record of used authorizations for enrollment {}; run `syq receiver enroll {}@HOST` on your machine to recreate it",
            config.id, config.target_login
        )
    })?;
    let context = delegation::ReceiverContext {
        enrollment_id: config.id,
        generation: config.generation,
        target_login: &config.target_login,
        build,
        clock: delegation::ClockObservation {
            unix_seconds: crate::directive::now()?,
            monotonic: Instant::now(),
        },
        clock_skew_seconds: CLOCK_SKEW_SECONDS,
    };
    delegation::verify_and_redeem(directive, &context, &config.signer, &replay, |directive| {
        crate::directive::destination_rules(directive, home)
    })
}

/// A connection started from an older line still runs the forced command it
/// had: another generation, or another build. Refuse a new copy from it
/// before anything is recorded.
pub(super) fn require_current_receiver(
    config: &ReceiverEnrollment,
    generation: u64,
    build: &str,
) -> Result<()> {
    if config.generation != generation || config.release != build {
        bail!(
            "this connection runs an outdated receiver for enrollment {} (generation {generation} of {build}, now generation {} of {}); start a new connection",
            config.id,
            config.generation,
            config.release
        );
    }
    Ok(())
}

/// `[USER@]HOST` as `syq receiver enroll` takes it, with the login the
/// user's SSH configuration selects.
fn enrollment_account(value: &str) -> Result<(String, String)> {
    let endpoint = SshEndpoint::parse(value)?;
    let (user, host) = match endpoint.as_str().split_once('@') {
        Some((user, host)) => (Some(user), host),
        None => (None, endpoint.as_str()),
    };
    let policy = crate::agent_broker::resolve_host_policy("ssh", user, host)?;
    Ok((policy.login_user, host.to_owned()))
}

/// Where the documentation says how to remove enrollments from older
/// versions.
const RELEASED_ENROLLMENTS_DOCS: &str =
    "https://greaber.github.io/syq/remote-reference.html#enrollments-from-older-versions";

/// A notice when `home` holds state from enrollments syq 0.4.0 to 0.7.1
/// made, which this version neither lists nor removes: their enrolling
/// machine's records or a server's state.
pub(super) fn released_enrollment_notice(home: &Path) -> Option<String> {
    [".local/state/syq/restricted", ".local/share/syq/restricted"]
        .into_iter()
        .map(|path| home.join(path))
        .find(|path| path.exists())
        .map(|path| {
            format!(
                "syq: {} holds enrollments made by syq 0.4.0 to 0.7.1, which this version does not list or use; to remove them, see {RELEASED_ENROLLMENTS_DOCS}",
                path.display()
            )
        })
}

/// `syq receiver enroll|list|revoke`: the receiver enrollment system is one
/// subcommand with its verbs beneath it.
pub(crate) fn dispatch_receiver_command(argv: &[OsString]) -> Option<Result<i32>> {
    if argv.get(1)?.to_str()? != "receiver" {
        return None;
    }
    let matches = crate::help::receiver()
        .try_get_matches_from(
            std::iter::once(OsString::from("syq receiver")).chain(argv[2..].iter().cloned()),
        )
        .unwrap_or_else(|error| error.exit());
    crate::fsops::reserve_startup_descriptors();
    let (command, options) = matches.subcommand().expect("subcommand required");
    let via = || -> Result<Option<SshEndpoint>> {
        options
            .get_one::<String>("via")
            .map(|value| SshEndpoint::parse(value))
            .transpose()
    };
    match command {
        "list" => Some((|| {
            if let Some(notice) = released_enrollment_notice(&current_account()?.1) {
                crate::output::diagnostic!("{notice}");
            }
            let active = load_local_enrollments()?;
            let active_ids = active
                .iter()
                .map(|(metadata, _)| metadata.id)
                .collect::<HashSet<_>>();
            for (metadata, _) in active {
                let target = endpoint(&metadata.target_login, &metadata.host, metadata.port)?;
                println!(
                    "{}\tactive\t{}\t{}\t{}",
                    metadata.id,
                    target.label(),
                    metadata.release,
                    metadata.signer.fingerprint()?
                );
            }
            for (pending, _) in load_pending_enrollments()? {
                if !active_ids.contains(&pending.id) {
                    let target = endpoint(&pending.target_login, &pending.host, pending.port)?;
                    println!("{}\tpending\t{}", pending.id, target.label());
                }
            }
            Ok(0)
        })()),
        "enroll" => Some((|| {
            let account = options
                .get_one::<String>("account")
                .expect("account required");
            let (login, host) = enrollment_account(account)?;
            let via = via()?;
            let (metadata, _, _) = enroll(&host, None, &login, via.as_ref(), true, None)?;
            println!(
                "enrolled {} for {}",
                metadata.id,
                endpoint(&metadata.target_login, &metadata.host, metadata.port)?.label(),
            );
            Ok(0)
        })()),
        "revoke" => Some((|| {
            let id = EnrollmentId::parse(options.get_one::<String>("id").expect("ID required"))?;
            let via = via()?;
            let active = load_local_enrollments()?
                .into_iter()
                .find(|(metadata, _)| metadata.id == id);
            let (target_login, host, port, directory) = match active {
                Some((metadata, directory)) => (
                    metadata.target_login,
                    metadata.host,
                    metadata.port,
                    directory,
                ),
                None => {
                    let (pending, directory) = load_pending_enrollments()?
                        .into_iter()
                        .find(|(pending, _)| pending.id == id)
                        .context("no local enrollment has that ID")?;
                    (pending.target_login, pending.host, pending.port, directory)
                }
            };
            let entry_key = load_entry_key(&directory)?;
            let request = RevokeRequest {
                version: CONFIG_VERSION,
                id,
                target_login: target_login.clone(),
                entry_public_key: entry_key.public_key().to_openssh()?,
            };
            let target = endpoint(&target_login, &host, port)?;
            let encoded = serde_json::to_vec(&request)?;
            let direct = run_management_over_route(
                &target,
                EnrollmentRoute::Direct,
                id,
                ManagementAction::Revoke,
                &encoded,
            );
            match (direct, via.as_ref()) {
                (Ok(_), _) => {}
                (Err(direct_error), Some(via))
                    if is_enrollment_transport_failure(&direct_error) =>
                {
                    run_management_over_route(
                        &target,
                        EnrollmentRoute::ProxyJump { jump: via },
                        id,
                        ManagementAction::Revoke,
                        &encoded,
                    )
                    .with_context(|| format!("direct revocation also failed: {direct_error:#}"))?;
                }
                (Err(error), _) => return Err(error),
            }
            remove_local_enrollment(&directory)?;
            println!("revoked {id} from {}", target.label());
            Ok(0)
        })()),
        _ => unreachable!("receiver subcommand validated by clap"),
    }
}

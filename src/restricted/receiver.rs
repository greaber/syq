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
/// without a fresh directive. A coordinator sets up at most this many
/// workers at once, so one copy's workers never take more slots than there
/// are; a worker refused when several copies start at once is retried by its
/// coordinator.
const UNVERIFIED_SESSIONS: usize = crate::conn::MAX_CONCURRENT_CONNECTS;
/// How long a session has to send its first frame.
const ADMISSION_TIMEOUT: Duration = Duration::from_secs(10);
/// The largest first frame a session may send: a coordinating source's two
/// directives and the destination's entry key.
const MAX_ADMISSION_BYTES: usize =
    2 * crate::directive::MAX_SIGNED_BYTES + crate::remote_to_remote::MAX_ENTRY_KEY_BYTES + 1024;

/// The first frame of every session an entry key starts, before any other
/// byte. The command a client asks sshd for is only data: the line's forced
/// command runs whatever it asked.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Admission {
    /// Start a copy with this signed directive.
    Copy(Vec<u8>),
    /// Join a running copy as an SSH worker, with its ticket.
    Worker(String),
    /// Run a copy from this account to another server's receiver, as the
    /// copy's coordinator.
    Coordinate(Box<Coordinate>),
}

/// A copy between two servers that this account's receiver coordinates.
/// After the frame, the session's input carries the requester's marker, and
/// then nothing more until the requester ends.
#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Coordinate {
    /// This enrollment's signed directive.
    pub source: Vec<u8>,
    /// The destination's signed directive, which its own receiver verifies.
    pub destination: Vec<u8>,
    /// The destination's entry key, which only starts its receiver.
    pub entry_key: Vec<u8>,
    /// Marks the lines of the coordinator's output that carry its results,
    /// for the requester.
    pub results_token: String,
    /// The requester's terminal width, when it shows progress.
    pub progress_width: Option<u16>,
}

impl Drop for Coordinate {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.entry_key);
    }
}

impl fmt::Debug for Coordinate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Coordinate").finish_non_exhaustive()
    }
}

impl Admission {
    /// The frame: a 4-byte big-endian length, then the postcard encoding.
    /// A coordinating source's frame carries an entry key; the caller wipes
    /// the frame, and the encoding is wiped here.
    pub(crate) fn frame(&self) -> Result<Vec<u8>> {
        let body = zeroize::Zeroizing::new(
            postcard::to_stdvec(self).context("encode the admission frame")?,
        );
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
        // It can carry an entry key, wiped once decoded.
        let mut body = zeroize::Zeroizing::new(vec![0; length]);
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
    /// Take a free slot of the `slots`, or refuse the session at once when
    /// there is none. No session waits for a slot, so no more than `slots`
    /// unverified sessions run.
    pub(super) fn take(state: &Path, slots: usize) -> Result<Self> {
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
                bail!(
                    "the enrollment's session slots must be private, singly linked regular files"
                );
            }
            loop {
                // SAFETY: the descriptor stays open for the call.
                if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                    return Ok(Self(file));
                }
                let error = std::io::Error::last_os_error();
                match error.kind() {
                    std::io::ErrorKind::Interrupted => {}
                    std::io::ErrorKind::WouldBlock => break,
                    _ => return Err(error).context("lock a session slot"),
                }
            }
        }
        Err(SessionsFull(format!(
            "{slots} other connections are starting copies on this enrollment; try again shortly, or replace its entry key with `syq receiver revoke` and enroll again if this persists"
        ))
        .into())
    }
}

/// Every slot for unverified sessions was taken, so the session was refused.
/// The receiver exits with [`SESSIONS_FULL_EXIT`], and a coordinator that
/// sees it reports this error, which it retries soon: the slots free as
/// soon as other connections finish starting.
#[derive(Debug)]
pub(crate) struct SessionsFull(pub(crate) String);

impl fmt::Display for SessionsFull {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SessionsFull {}

/// The exit status of a session refused for [`SessionsFull`].
pub(crate) const SESSIONS_FULL_EXIT: i32 = 73;

/// A copy the receiver refused before serving it, so it wrote nothing. The
/// receiver prints the reason itself and exits with [`REFUSED_EXIT`].
#[derive(Debug)]
pub(crate) struct Refused(pub(crate) anyhow::Error);

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#}", self.0)
    }
}

impl std::error::Error for Refused {}

/// The exit status of a copy the receiver [`Refused`].
pub(crate) const REFUSED_EXIT: i32 = 74;

/// What the coordinator reports when the receiver exited with
/// [`REFUSED_EXIT`]: the receiver's own message, already shown, says why.
#[derive(Debug)]
pub(crate) struct CopyRefused(pub(crate) String);

impl fmt::Display for CopyRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CopyRefused {}

pub(crate) fn is_sessions_full(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| cause.is::<SessionsFull>())
}

/// What a session the forced command started may go on to do.
pub(crate) enum Session {
    /// Serve a copy a verified directive allows.
    Copy(std::sync::Arc<RestrictedAuthority>),
    /// Serve the reads a verified directive for this account as a copy's
    /// source allows, to the server that started the copy.
    Source(std::sync::Arc<super::source::SourceAuthority>),
    /// This session's input and output were handed to the running copy its
    /// worker ticket names, which has served them.
    Worker,
    /// Run the copy a verified directive for this account as a coordinating
    /// source allows.
    Coordinate(Box<Coordinating>),
}

/// A verified copy that this account's receiver coordinates.
pub(crate) struct Coordinating {
    /// The signed command, with the ignore rules it read from files.
    pub args: crate::cli::Args,
    pub peer: crate::directive::Peer,
    /// The approving machine's limits.
    pub caps: Option<crate::directive::Caps>,
    pub frame: Box<Coordinate>,
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
    // A revoked enrollment starts nothing, even while its revocation runs.
    active::require_not_revoked(&state)?;
    let slot = UnverifiedSlot::take(&state, UNVERIFIED_SESSIONS)?;
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
        Admission::Copy(directive) => admit(
            &state,
            &config,
            (generation, crate::identity::build()),
            &directive,
            slot,
        ),
        Admission::Coordinate(frame) => Ok(Session::Coordinate(admit_coordinator(
            &state,
            &config,
            (generation, crate::identity::build()),
            frame,
            slot,
        )?)),
    }
}

/// Admit a coordinating source's directive, and the destination's directive
/// presented with it: verified as [`admit`] verifies a destination's, and
/// recorded as used only when the destination's is the one approved with
/// it. The session's `slot` is released once it is verified.
fn admit_coordinator(
    state: &Path,
    config: &ReceiverEnrollment,
    receiver: (u64, &str),
    frame: Box<Coordinate>,
    slot: UnverifiedSlot,
) -> Result<Box<Coordinating>> {
    let observed_state = fs::symlink_metadata(state).context("inspect receiver enrollment")?;
    let (_, home) = current_account()?;
    let (coordinating, verified) = verify_coordination(state, config, receiver, &frame)?;
    drop(slot);
    let (args, peer, caps) = coordinating;
    // Revocation and the copy's finish-by time end this receiver and the
    // coordinator it runs, which stays in its process group.
    active::watch(
        &home,
        state,
        (observed_state.dev(), observed_state.ino()),
        verified.execution_deadline,
    )?;
    Ok(Box::new(Coordinating {
        args,
        peer,
        caps,
        frame,
    }))
}

/// What a verified coordinating source's directive allows: its command, the
/// destination's receiver and the approving machine's limits.
pub(super) type Coordination = (
    crate::cli::Args,
    crate::directive::Peer,
    Option<crate::directive::Caps>,
);

/// Verify a coordinating source's `frame`: its own directive as [`verify`]
/// verifies a destination's, recorded as used only when the destination's
/// directive is the one approved with it.
pub(super) fn verify_coordination(
    state: &Path,
    config: &ReceiverEnrollment,
    receiver: (u64, &str),
    frame: &Coordinate,
) -> Result<(Coordination, delegation::VerifiedDirective)> {
    if !crate::destination_results::relay::valid_token(&frame.results_token) {
        bail!("invalid results token");
    }
    if frame.entry_key.len() > crate::remote_to_remote::MAX_ENTRY_KEY_BYTES {
        bail!("the destination's entry key is too long");
    }
    crate::restricted::parse_entry_key(&frame.entry_key)?;
    let destination = crate::directive::Signed::decode(&frame.destination)
        .context("decode the destination's directive")?
        .directive;
    verify_with(state, config, receiver, &frame.source, |source| {
        let mut args = crate::directive::coordination(source, &destination)?;
        // The ignore rules the command read from files, which this machine
        // cannot read.
        args.ignore_lines = source.inputs.ignore.clone();
        let crate::directive::Role::CoordinatingSource(peer) = &source.binding.role else {
            unreachable!("coordination checks the role");
        };
        Ok((args, peer.clone(), source.caps))
    })
}

/// What a verified directive for one end of a copy allows.
pub(super) enum Rules {
    Destination(Box<(Grant, GrantConstraints)>),
    Source(crate::destination::pull::PullRequest),
}

/// Admit a new copy's directive and set up its authority: refused by a
/// receiver of another generation or build, then checked against the
/// trusted login key and its policy, its rules derived from its command for
/// the end of the copy it is signed for, and only then recorded as used. The
/// session's `slot` is released once the directive is verified.
fn admit(
    state: &Path,
    config: &ReceiverEnrollment,
    (generation, build): (u64, &str),
    directive: &[u8],
    slot: UnverifiedSlot,
) -> Result<Session> {
    let observed_state = fs::symlink_metadata(state).context("inspect receiver enrollment")?;
    let (_, home) = current_account()?;
    let canonical_home = fs::canonicalize(&home)
        .with_context(|| format!("resolve receiver home {}", home.display()))?;
    let protected = receiver_control_paths(&canonical_home, None, ControlPaths::Here)?;
    let (rules, verified) = verify_rules(
        state,
        config,
        (generation, build),
        directive,
        (&home, &canonical_home),
    )?;
    drop(slot);
    let (grant, constraints) = match rules {
        Rules::Destination(rules) => *rules,
        Rules::Source(reads) => {
            // Reads follow the signed command, as the account's own would:
            // the approving machine's prompt showed what it names.
            let authority =
                super::source::SourceAuthority::new(reads.policy(verified.execution_deadline))?;
            ssh::enter_state_directory(state)?;
            active::watch(
                &home,
                state,
                (observed_state.dev(), observed_state.ino()),
                verified.execution_deadline,
            )?;
            return Ok(Session::Source(authority));
        }
    };
    let results_key = load_results_key(state)?;
    let root = ConfinedRoot::resolve(
        &grant.copy.destination,
        &protected,
        constraints.extra_options.follow_dst,
        Some((&home, &canonical_home)),
    )?;
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
    Ok(Session::Copy(authority))
}

/// Verify a new copy's directive and derive its rules for the end of the
/// copy it is signed for, recording it as used only when everything passes.
/// A coordinating source's directive comes only with its destination's.
/// `home` is the account's home directory as it is named, and where it
/// really is, with symlinks resolved.
pub(super) fn verify_rules(
    state: &Path,
    config: &ReceiverEnrollment,
    receiver: (u64, &str),
    directive: &[u8],
    (home, canonical_home): (&Path, &Path),
) -> Result<(Rules, delegation::VerifiedDirective)> {
    verify_with(
        state,
        config,
        receiver,
        directive,
        |directive| match &directive.binding.role {
            crate::directive::Role::Destination => Ok(Rules::Destination(Box::new(
                crate::directive::destination_rules(directive, home)?,
            ))),
            crate::directive::Role::Source => Ok(Rules::Source(crate::directive::source_rules(
                directive,
                canonical_home,
            )?)),
            crate::directive::Role::CoordinatingSource(_) => {
                bail!("a coordinating source's directive comes with its destination's")
            }
        },
    )
}

/// Verify a destination's directive and derive its rules, recording it as
/// used only when everything passes.
#[cfg(test)]
pub(super) fn verify(
    state: &Path,
    config: &ReceiverEnrollment,
    (generation, build): (u64, &str),
    directive: &[u8],
    home: &Path,
) -> Result<((Grant, GrantConstraints), delegation::VerifiedDirective)> {
    verify_with(state, config, (generation, build), directive, |directive| {
        crate::directive::destination_rules(directive, home)
    })
}

/// Verify a directive as [`verify_rules`] does, deriving with `derive`.
fn verify_with<T>(
    state: &Path,
    config: &ReceiverEnrollment,
    (generation, build): (u64, &str),
    directive: &[u8],
    derive: impl FnOnce(&crate::directive::Directive) -> Result<T>,
) -> Result<(T, delegation::VerifiedDirective)> {
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
    delegation::verify_and_redeem(directive, &context, &config.signer, &replay, derive)
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
    // Only the login: enrolling checks the host's key as the user's `ssh`
    // does.
    let policy = crate::agent_broker::resolve_known_policy_at("ssh", user, host, None)?;
    Ok((policy.login_user, host.to_owned()))
}

/// A notice when `home` holds state from enrollments syq 0.7.1 and earlier
/// made, which this version neither lists nor removes: their enrolling
/// machine's records or a server's state. It says how to remove them; syq
/// does not remove them itself.
pub(super) fn released_enrollment_notice(home: &Path) -> Option<String> {
    let path = [".local/state/syq/restricted", ".local/share/syq/restricted"]
        .into_iter()
        .map(|path| home.join(path))
        .find(|path| path.exists())?;
    Some(format!(
        "syq: {} holds enrollments made by syq 0.7.1 and earlier, which this version does not list or use. \
         To remove them, revoke them with that older syq, or delete them by hand:\n\
         - On each server account, delete the lines in ~/.ssh/authorized_keys whose command runs \
         ~/.local/libexec/syq-receiver, written with the account's full home directory path \
         (keep the lines that run syq from ~/.local/lib/syq), then delete the directory \
         ~/.local/share/syq/restricted and the file ~/.local/libexec/syq-receiver.\n\
         - On the machine that enrolled them, delete the directory ~/.local/state/syq/restricted.",
        path.display()
    ))
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
        .unwrap_or_else(|error| crate::output::exit_with(error));
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
                crate::output::command_println!(
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
                    crate::output::command_println!("{}\tpending\t{}", pending.id, target.label());
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
            let (metadata, _, _) = enroll(&host, None, &login, (via.as_ref(), false), true, None)?;
            crate::output::command_println!(
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
            let configured = run_management_over_route(
                &target,
                EnrollmentRoute::Configured,
                id,
                ManagementAction::Revoke,
                &encoded,
            );
            match (configured, via.as_ref()) {
                (Ok(_), _) => {}
                (Err(configured_error), Some(via))
                    if is_enrollment_transport_failure(&configured_error) =>
                {
                    run_management_over_route(
                        &target,
                        EnrollmentRoute::ProxyJump { jump: via },
                        id,
                        ManagementAction::Revoke,
                        &encoded,
                    )
                    .with_context(|| {
                        format!("revoking along your SSH configuration's route also failed: {configured_error:#}")
                    })?;
                }
                (Err(error), _) => return Err(error),
            }
            remove_local_enrollment(&directory)?;
            crate::output::command_println!("revoked {id} from {}", target.label());
            Ok(0)
        })()),
        _ => unreachable!("receiver subcommand validated by clap"),
    }
}

use super::*;

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

/// The forced command of syq's line: `--restricted-receiver
/// --enrollment=ID --generation=N`.
pub(crate) fn run_receiver(enrollment: &str, generation: &str) -> Result<()> {
    refuse_privileged_receiver(Some(enrollment))?;
    let enrollment = EnrollmentId::parse(enrollment)?;
    let generation: u64 = generation
        .parse()
        .context("restricted receiver generation must be a number")?;
    let original = std::env::var("SSH_ORIGINAL_COMMAND")
        .context("restricted receiver requires SSH_ORIGINAL_COMMAND from sshd")?;
    if let Some(ticket) = ssh::worker_command(&original)? {
        // A worker joins a copy that is already running, which continues
        // whatever has changed since it started.
        let (_, home) = current_account()?;
        ssh::enter_state_directory(&enrollment_state(&home, enrollment))?;
        return ssh::connect(&ticket);
    }
    let envelope = decode_receiver_command(&original)?;
    let (state, config) = receiver_state(enrollment)?;
    require_current_receiver(&config, generation, crate::identity::build())?;
    let observed_state = fs::symlink_metadata(&state).context("inspect receiver enrollment")?;
    let (_, home) = current_account()?;
    let canonical_home = fs::canonicalize(&home)
        .with_context(|| format!("resolve receiver home {}", home.display()))?;
    let protected = receiver_control_paths(&canonical_home, None, ControlPaths::Here)?;
    let replay = delegation::ReplayStore::open(&state.join("replay"))?;
    let observed_at = Instant::now();
    let signer_name = signer_name(enrollment, config.generation);
    let context = delegation::ReceiverContext {
        enrollment_id: enrollment,
        target_login: &config.target_login,
        expected_signer: &signer_name,
        clock: delegation::ClockObservation {
            unix_seconds: now()?,
            monotonic: observed_at,
        },
        clock_skew_seconds: CLOCK_SKEW_SECONDS,
    };
    let verified = delegation::verify_and_redeem(&envelope, &context, &config.signer, &replay)?;
    let (grant, extensions, grant_digest, deadline) = verified.into_parts();
    let results_key = load_results_key(&state)?;
    let GrantOperation::Copy(copy) = &grant.operation;
    let root = ConfinedRoot::resolve(&copy.destination, &protected)?;
    let authority = std::sync::Arc::new(RestrictedAuthority::new(
        root,
        grant,
        extensions,
        grant_digest,
        results_key,
        deadline,
        &protected,
    )?);
    ssh::enter_state_directory(&state)?;
    // Verification does not hold the lifecycle lock or permit mutations. A
    // revoke during verification is caught when this receiver tries to enter.
    active::watch(
        &home,
        &state,
        (observed_state.dev(), observed_state.ino()),
        deadline,
    )?;
    crate::server::run_restricted(authority)
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

pub(super) fn decode_receiver_command(original: &str) -> Result<Vec<u8>> {
    if original.len() > 128 * 1024 {
        bail!("restricted receiver command exceeds size limit");
    }
    let words = shell_words::split(original).context("parse restricted receiver command")?;
    if words.len() != 3 || words[0] != "syq" || words[1] != "--server" {
        bail!("the entry key accepts only a syq server request with one signed grant");
    }
    let encoded = words[2]
        .strip_prefix("--restricted-grant=")
        .context("restricted receiver command is missing its signed grant")?;
    let envelope = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .context("decode restricted receiver grant")?;
    Ok(envelope)
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

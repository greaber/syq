use super::*;

pub(crate) fn receiver_config(id: EnrollmentId) -> Result<(ReceiverEnrollment, PathBuf, PathBuf)> {
    let (_, home) = current_account()?;
    let state = home
        .join(".local/share/syq/restricted")
        .join(id.to_string());
    let encoded = delegation::read_private_regular(
        &state.join("config.json"),
        "restricted receiver configuration",
        MAX_STATE_FILE,
    )?;
    let config: ReceiverEnrollment = serde_json::from_slice(&encoded)?;
    if config.version != CONFIG_VERSION || config.id != id {
        bail!("restricted receiver configuration does not match enrollment");
    }
    Ok((config, state.join("allowed-signers"), state.join("replay")))
}

pub(crate) fn run_receiver(enrollment: &str) -> Result<()> {
    let enrollment = EnrollmentId::parse(enrollment)?;
    let original = std::env::var("SSH_ORIGINAL_COMMAND")
        .context("restricted receiver requires SSH_ORIGINAL_COMMAND from sshd")?;
    if let Some(ticket) = ssh::worker_command(&original)? {
        let (_, _, replay) = receiver_config(enrollment)?;
        ssh::enter_state_directory(replay.parent().context("receiver state directory")?)?;
        return ssh::connect(&ticket);
    }
    let envelope = decode_receiver_command(&original)?;
    let (config, allowed_signers, replay_path) = receiver_config(enrollment)?;
    let state = replay_path.parent().context("receiver state directory")?;
    let observed_state = fs::symlink_metadata(state).context("inspect receiver enrollment")?;
    let (_, home) = current_account()?;
    let canonical_home = fs::canonicalize(&home)
        .with_context(|| format!("resolve receiver home {}", home.display()))?;
    let canonical_receiver = fs::canonicalize(&config.receiver_path).with_context(|| {
        format!(
            "resolve restricted receiver {}",
            Path::new(&config.receiver_path).display()
        )
    })?;
    let canonical_ssh_keygen = fs::canonicalize(&config.ssh_keygen).with_context(|| {
        format!(
            "resolve signature verifier {}",
            Path::new(&config.ssh_keygen).display()
        )
    })?;
    let protected = receiver_control_paths(
        &canonical_home,
        &canonical_receiver,
        Some(&canonical_ssh_keygen),
    )?;
    let replay = delegation::ReplayStore::open(&replay_path)?;
    let observed_at = Instant::now();
    let context = delegation::ReceiverContext {
        enrollment_id: enrollment,
        target_login: &config.target_login,
        expected_signer: &config.signer,
        clock: delegation::ClockObservation {
            unix_seconds: now()?,
            monotonic: observed_at,
        },
        clock_skew_seconds: CLOCK_SKEW_SECONDS,
    };
    let policy = delegation::SshsigPolicy {
        ssh_keygen: PathBuf::from(&config.ssh_keygen),
        allowed_signers,
        revocation_file: None,
    };
    let verified = delegation::verify_and_redeem(&envelope, &context, &policy, &replay)?;
    let (grant, extensions, grant_digest, deadline) = verified.into_parts();
    let receipt_key = load_receipt_key(replay_path.parent().context("receiver state directory")?)?;
    let authority = std::sync::Arc::new(RestrictedAuthority::new(
        &config,
        grant,
        extensions,
        grant_digest,
        receipt_key,
        deadline,
        &protected,
    )?);
    ssh::enter_state_directory(state)?;
    // Verification does not hold the lifecycle lock or permit mutations. A
    // revoke during verification is caught when this receiver tries to enter.
    active::watch(
        &home,
        state,
        (observed_state.dev(), observed_state.ino()),
        deadline,
    )?;
    crate::server::run_restricted(authority)
}

pub(super) fn decode_receiver_command(original: &str) -> Result<Vec<u8>> {
    if original.len() > 128 * 1024 {
        bail!("restricted receiver command exceeds size limit");
    }
    let words = shell_words::split(original).context("parse restricted receiver command")?;
    if words.len() != 3 || words[0] != "syq" || words[1] != "--server" {
        bail!("the enrollment key accepts only a syq server request with one signed grant");
    }
    let encoded = words[2]
        .strip_prefix("--restricted-grant=")
        .context("restricted receiver command is missing its signed grant")?;
    let envelope = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .context("decode restricted receiver grant")?;
    Ok(envelope)
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
    let (command, options) = matches.subcommand().expect("subcommand required");
    let via = || -> Result<Option<SshEndpoint>> {
        options
            .get_one::<String>("via")
            .map(|value| SshEndpoint::parse(value))
            .transpose()
    };
    match command {
        "list" => Some((|| {
            let active = load_local_enrollments()?;
            let active_ids = active
                .iter()
                .map(|(metadata, _)| metadata.id)
                .collect::<HashSet<_>>();
            for (metadata, _) in active {
                let target = endpoint(&metadata.target_login, &metadata.host, metadata.port)?;
                println!(
                    "{}\tactive\t{}\t{}",
                    metadata.id,
                    target.label(),
                    metadata.canonical_root
                );
            }
            for (pending, _) in load_pending_enrollments()? {
                if !active_ids.contains(&pending.id) {
                    let target = endpoint(&pending.target_login, &pending.host, pending.port)?;
                    println!(
                        "{}\tpending\t{}\t{}",
                        pending.id,
                        target.label(),
                        pending.requested_destination
                    );
                }
            }
            Ok(0)
        })()),
        "enroll" => Some((|| {
            let target = options
                .get_one::<String>("target")
                .expect("target required");
            let location = Location::parse(target)?;
            let host = location
                .host
                .as_deref()
                .context("enrollment target must be remote")?;
            let requested = std::str::from_utf8(&location.path)
                .context("enrollment destination is not UTF-8")?;
            let via = via()?;
            let policy =
                crate::agent_broker::resolve_host_policy("ssh", location.user.as_deref(), host)?;
            let (metadata, _, destination) = enroll(
                host,
                None,
                &policy.login_user,
                requested,
                via.as_ref(),
                true,
            )?;
            println!(
                "enrolled {} for {}:{}",
                metadata.id,
                endpoint(&metadata.target_login, &metadata.host, metadata.port)?.label(),
                String::from_utf8_lossy(&destination)
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
            let private_key = load_private_key(&directory)?;
            let request = RevokeRequest {
                version: CONFIG_VERSION,
                id,
                target_login: target_login.clone(),
                public_key: private_key.public_key().to_openssh()?,
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
            delegation::validate_private_directory_path(&directory)?;
            fs::remove_dir_all(&directory)
                .with_context(|| format!("remove local enrollment {}", directory.display()))?;
            println!("revoked {id} from {}", target.label());
            Ok(0)
        })()),
        _ => unreachable!("receiver subcommand validated by clap"),
    }
}

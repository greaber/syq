//! Approving copies: directives for enrolled receivers, and the per-copy
//! authority of a receiving machine.
use super::*;
use crate::directive::{self, Binding, Directive, Inputs, Role};

/// The destination path `directive`'s rules name on an account whose home is
/// `home`, refused when it would write a path the receiver protects. The
/// signing machine can tell from names alone; a destination reached through
/// a link into a protected path is refused only by the server, by identity.
pub(super) fn checked_destination(
    directive: &Directive,
    (home, receiving): (&Path, &[PathBuf]),
) -> Result<Vec<u8>> {
    let (grant, _) = directive::destination_rules(directive, home)?;
    let protected = receiver_control_paths(home, None, ControlPaths::Elsewhere(receiving))?;
    reject_control_plane_scopes(&grant.copy, &protected)?;
    Ok(grant.copy.destination)
}

/// Sign a directive for a copy to `destination` with the user's login key,
/// setting up the destination account's enrollment, refreshing it for this
/// build, or finding the login key again first when needed. `command` is
/// this machine's command as it was run. A dry run (`allow_enrollment`
/// false) changes nothing on the server.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_transfer(
    args: &Args,
    command: Vec<Vec<u8>>,
    sources: &[Location],
    destination: &Location,
    source_login: &str,
    destination_login: &str,
    destination_agent: Option<&Path>,
    allow_enrollment: bool,
) -> Result<PreparedTransfer> {
    directive::validate_restricted_args(args)?;
    let host = destination
        .host
        .as_deref()
        .context("destination host missing")?;
    let account = endpoint(destination_login, host, destination.port)?.label();
    let jump = endpoint(
        source_login,
        sources[0].host.as_deref().context("source host missing")?,
        sources[0].port,
    )?;
    let inputs = Inputs {
        ignore: args.ignore_lines.clone(),
        mapping: directive::mapping_authorization(args)?,
    };
    let (recipient_secret, recipient_public_key) =
        crate::destination_results::generate_recipient()?;
    let directive_for = |enrollment: EnrollmentId, generation: u64| {
        directive::issue(
            Binding {
                enrollment,
                generation,
                account: destination_login.to_owned(),
                role: Role::Destination,
            },
            command.clone(),
            crate::approval_command::current_directory(),
            inputs.clone(),
            recipient_public_key,
        )
    };
    // A destination the receiver would refuse is refused before anything
    // is set up or refreshed on the server, from the same rules.
    let check = |home: &Path, receiving: &[PathBuf]| {
        checked_destination(
            &directive_for(EnrollmentId::random(), 1)?,
            (home, receiving),
        )
        .map(drop)
    };
    let enroll_now = |refresh: bool| {
        enroll(
            host,
            destination.port,
            destination_login,
            Some(&jump),
            refresh,
            Some(&check),
        )
    };
    let found = load_local_enrollments()?.into_iter().find(|(metadata, _)| {
        metadata.host == host
            && metadata.port == destination.port
            && metadata.target_login == destination_login
    });
    if let Some((metadata, _)) = &found {
        check(Path::new(&metadata.remote_home), &metadata.receiving_state)?;
    }
    let (metadata, directory, signer) = match found {
        Some((metadata, directory)) if !needs_refresh(&metadata, &directory) => {
            (metadata, directory, None)
        }
        _ if !allow_enrollment => bail!(
            "a dry run does not set up restricted copying on {account} for this syq build; the next copy does, or run `syq receiver enroll {account}`"
        ),
        _ => enroll_now(false)?,
    };
    let signer = match signer {
        Some(signer) => Some(signer),
        None => LoginSigner::find(
            &metadata.signer,
            destination_agent,
            metadata.identity_file.as_deref(),
            directive::now()?,
        )?,
    };
    let (metadata, directory, signer) = match signer {
        Some(signer) => (metadata, directory, signer),
        None if !allow_enrollment => bail!(
            "the login key restricted copying on {account} trusts ({}) cannot sign: load it into your SSH agent, or let the next copy enroll your current login key",
            metadata.signer.fingerprint()?
        ),
        None => {
            // The recorded login key can no longer sign: enroll the current
            // login's key. That rewrites only the trusted signer; the entry
            // key, and so copies in flight, stay.
            drop((metadata, directory));
            let (metadata, directory, signer) = enroll_now(true)?;
            (
                metadata,
                directory,
                signer.context("enrollment did not find the login key")?,
            )
        }
    };
    let entry_key = load_entry_key(&directory)?;
    let directive = directive_for(metadata.id, metadata.generation)?;
    let destination_path = checked_destination(
        &directive,
        (Path::new(&metadata.remote_home), &metadata.receiving_state),
    )?;
    let request_id = directive.request_id;
    let signed = directive::sign(&directive, |payload| {
        let signature = signer.sign(directive::NAMESPACE, payload)?;
        // Check here what the receiver checks, so a FIDO policy or an
        // expired certificate fails before anything starts.
        metadata
            .signer
            .verify(directive::NAMESPACE, payload, &signature, directive::now()?)
            .context("check the directive's signature")?;
        Ok(signature)
    })?;
    let digest = directive::Signed::decode(&signed)?.digest();
    Ok(PreparedTransfer {
        entry_key,
        request_id,
        results_public_key: metadata.results_public_key.clone(),
        recipient_secret,
        digest,
        destination: destination_path,
        directive: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signed),
        enrollment_id: metadata.id,
    })
}

/// Whether `grant` is a signed directive for an enrolled receiver, whose
/// sender paces network bytes as for an ordinary copy, rather than the
/// marker of a route through a receiving machine. Connections that a
/// receiving machine approves are not paced at the transport, so those
/// requests carry the bandwidth limit and the receiver enforces it on file
/// data.
pub(crate) fn enrolled_grant(grant: &str) -> bool {
    !(crate::destination::is_named(&Some(grant.to_owned()))
        || grant == crate::destination::RETURN_GRANT
        || grant == crate::destination::peer_bridge::GRANT)
}

/// Build a request without trusting the source's eventual filesystem claims.
/// The receiving laptop separately confines and approves every mutation scope.
pub(crate) fn named_request(
    args: &Args,
    receipt_policy: crate::destination_results::ReceiptPolicy,
) -> Result<crate::destination::CopyRequest> {
    let (destination, sources) = args
        .locations
        .split_last()
        .context("copy endpoints missing")?;
    let mut checked = args.clone();
    // Named channels are encrypted by SSH or laptop-initiated TCP workers.
    checked.no_tcp = false;
    let path = crate::destination::request_path(b".")?;
    let copy = directive::copy_operation(&checked, sources, &path)?;
    Ok(crate::destination::CopyRequest {
        destination: destination.path.clone(),
        copy,
        constraints: GrantConstraints {
            tcp_congestion: args.tcp_congestion.clone(),
            mapping: directive::mapping_authorization(args)?,
            hashing: Some(crate::hashing::CopyHashing::from_args(args)),
            max_file_data_bytes_per_second: args.bwlimit_bytes,
            filters: FilterPolicy {
                ignore: args.ignore_lines.clone(),
                destination_roots: directive::filter_destination_roots(args, sources, &path)?,
                delete_excluded: args.delete_excluded,
            },
            root_existence: directive::root_existence_for(args.target_existence),
            receipt_policy,
            // A receiving machine does not follow a symlink at the
            // destination; the coordinator refuses one it finds there.
            extra_options: delegation::ExtraCopyOptions {
                follow_dst: false,
                ..directive::extra_copy_options(args)
            },
        },
    })
}

/// A fresh, in-memory authority made on the receiving machine after
/// approval. It shares the restricted executor, but never reads or changes an
/// enrollment, a record of used directives, or persistence preferences.
pub(crate) fn named_authority(
    root: &Path,
    request: crate::destination::CopyRequest,
) -> Result<(
    std::sync::Arc<RestrictedAuthority>,
    crate::destination::Approved,
)> {
    if request.constraints.extra_options.follow_dst {
        bail!("copies a receiving machine approves do not follow destination symlinks");
    }
    let (_, home) = current_account()?;
    let parent = root;
    let metadata = fs::metadata(parent)?;
    let id = EnrollmentId::random();
    let request_id = RequestId::fresh(directive::now()?)?;
    let copy = request.copy;
    let mut constraints = request.constraints;
    delegation::validate_rules(&copy, &mut constraints)?;
    let key = generate_results_key(id)?;
    // Binds the receiving machine's results to this approval.
    let mut digest = [0u8; 32];
    getrandom::fill(&mut digest).context("generate the approval's digest")?;
    let executable = fs::canonicalize(std::env::current_exe()?)?;
    let home = fs::canonicalize(home)?;
    let protected = receiver_control_paths(&home, Some(&executable), ControlPaths::Here)?;
    let confined = ConfinedRoot::opened(
        parent,
        RootIdentity {
            dev: metadata.dev(),
            ino: metadata.ino(),
        },
    )?;
    let approved = crate::destination::Approved {
        token: String::new(),
        destination: copy.destination.clone(),
        enrollment: id,
        request: request_id,
        digest,
        results_key: key.public_key().to_openssh()?,
        max_delete: None,
    };
    let authority = RestrictedAuthority::new(
        confined,
        Grant {
            enrollment_id: id,
            request_id,
            copy,
        },
        constraints,
        digest,
        key,
        Instant::now() + std::time::Duration::from_secs(FINISH_WINDOW_SECONDS as u64),
        &protected,
    )?;
    Ok((std::sync::Arc::new(authority), approved))
}

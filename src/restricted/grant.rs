use super::*;

pub(super) fn destination_for(
    metadata: &LocalEnrollment,
    requested: &[u8],
) -> Result<Option<Vec<u8>>> {
    use std::os::unix::ffi::OsStrExt as _;
    let normalized = normalize_absolute(
        std::ffi::OsStr::from_bytes(requested),
        Path::new(&metadata.remote_home),
    )?;
    if requested_parent(&normalized) != Path::new(&metadata.requested_parent) {
        return Ok(None);
    }
    let leaf = normalized
        .file_name()
        .context("restricted destination / is not supported")?;
    // The enrollment's canonical root is UTF-8 (it is administrative,
    // declared at enrollment time); the leaf may be any bytes.
    Ok(Some(
        Path::new(&metadata.canonical_root)
            .join(leaf)
            .as_os_str()
            .as_bytes()
            .to_vec(),
    ))
}

pub(super) fn now() -> Result<i64> {
    i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
        .context("current time exceeds signed grant range")
}

pub(super) fn root_existence_for(existence: Existence) -> RootExistence {
    match existence {
        Existence::Any => RootExistence::Any,
        Existence::New => RootExistence::New,
        Existence::Existing => RootExistence::Existing,
    }
}

pub(crate) fn validate_restricted_args(args: &Args) -> Result<()> {
    if let Some(input) = &args.mapping_contents {
        input.validate_restricted_bounds()?;
    }
    if args.tcp_plain {
        bail!("command-restricted transfers require encrypted data connections");
    }
    if args.recycle_staging.is_some() {
        bail!("--recycle-staging is not supported by command-restricted receivers");
    }
    if args.inplace
        && (args.only_new_native_entries()
            || args.existing
            || (args.target_existence == Existence::New && args.placement == Placement::As))
    {
        bail!(
            "--inplace cannot be combined with --only-new, --only-existing, or --as-new on the command-restricted path: in-place writes open the final pathname directly, so the receiver can neither make them no-replace nor pin them to an observed object"
        );
    }
    if !args.dry_run && args.delete && args.max_delete.is_none() {
        // The signed deletion count is the only bound on what a compromised
        // hostA can remove inside the scope, so make it an explicit choice
        // instead of a silent hundred-million default.
        bail!(
            "deletion through the command-restricted receiver needs an explicit --max-delete ceiling"
        );
    }
    // Range-check every ceiling here, before automatic enrollment can touch
    // hostB, rather than leaving it to grant validation after the fact.
    if args
        .receiver_max_entries
        .is_some_and(|entries| entries == 0 || entries > delegation::MAX_ENTRIES)
    {
        bail!(
            "--receiver-max-entries must be between 1 and {}",
            delegation::MAX_ENTRIES
        );
    }
    if args
        .receiver_max_bytes
        .is_some_and(|bytes| bytes == 0 || bytes > delegation::MAX_COPY_BYTES)
    {
        bail!("--receiver-max-bytes must be at least 1 byte");
    }
    if let Some(maximum) = args.max_size.as_deref() {
        if crate::cli::parse_size(maximum)? == 0 {
            bail!("--max-size must be at least 1 byte on the command-restricted path");
        }
    }
    if !args.files_from_lines.is_empty() || args.files_from.is_some() || args.min_size.is_some() {
        bail!(
            "--files-from and --min-size are not yet independently enforceable by the command-restricted receiver"
        );
    }
    if args.pscope_explicit {
        bail!(
            "--pscope is not available with the command-restricted receiver: its host-bound authentication is verified per fresh connection"
        );
    }
    if !args.dry_run && args.delete && args.max_size.is_some() {
        bail!(
            "--max-size with deletion is not yet independently enforceable by the command-restricted receiver"
        );
    }
    if args.connections_opt.is_some() && args.connections > usize::from(delegation::MAX_CONNECTIONS)
    {
        bail!(
            "command-restricted transfers support at most {} connections",
            usize::from(delegation::MAX_CONNECTIONS)
        );
    }
    crate::conn::parse_ports(&args.tcp_ports)?;
    if let Some(maximum) = args.max_size.as_deref() {
        crate::cli::parse_size(maximum)?;
    }
    Ok(())
}

pub(super) fn grant_for(
    args: &Args,
    sources: &[Location],
    id: EnrollmentId,
    login: &str,
    destination: &[u8],
) -> Result<Grant> {
    validate_restricted_args(args)?;
    let issued_at = now()?;
    let read_only = args.dry_run;
    // `--max-delete 0` means nothing may be deleted, which the grant states
    // directly as a forbidding policy rather than a zero budget.
    let deletion = if !read_only && args.delete && args.max_delete != Some(0) {
        DeletionPolicy::DeleteDestinationOnly
    } else {
        DeletionPolicy::Forbid
    };
    let max_entries = args.receiver_max_entries.unwrap_or(DEFAULT_MAX_ENTRIES);
    let max_total_bytes = args.receiver_max_bytes.unwrap_or(DEFAULT_MAX_BYTES);
    let max_file_bytes = args
        .max_size
        .as_deref()
        .map(crate::cli::parse_size)
        .transpose()?
        .unwrap_or(DEFAULT_MAX_BYTES)
        .min(max_total_bytes);
    let max_deletions = match deletion {
        DeletionPolicy::Forbid => 0,
        DeletionPolicy::DeleteDestinationOnly => args
            .max_delete
            .context("deletion through the command-restricted receiver needs --max-delete")?
            .min(max_entries),
    };
    let start_by = issued_at
        .checked_add(GRANT_VALIDITY_SECONDS - CLOCK_SKEW_SECONDS)
        .context("signed grant start-by overflow")?;
    let finish_by = issued_at
        .checked_add(FINISH_WINDOW_SECONDS)
        .context("signed grant finish-by overflow")?;
    let copies_contents = sources.iter().any(Location::copies_contents);
    let placement = match args.placement {
        Placement::As => DestinationPlacement::ExactPath,
        Placement::Into | Placement::Rsync if copies_contents => {
            DestinationPlacement::DirectoryContents
        }
        Placement::Into | Placement::Rsync => DestinationPlacement::DirectoryAsChild,
    };
    let destination_bytes = destination.to_vec();
    let mut mutation_scopes = match placement {
        DestinationPlacement::ExactPath | DestinationPlacement::DirectoryContents => {
            vec![MutationScope {
                path: destination_bytes.clone(),
                descendants: args.recursive,
            }]
        }
        DestinationPlacement::DirectoryAsChild => {
            let mut scopes = vec![MutationScope {
                path: destination_bytes.clone(),
                descendants: false,
            }];
            for source in sources {
                let basename = source.basename();
                if basename.is_empty() {
                    bail!("named source has no destination basename for signed scope");
                }
                scopes.push(MutationScope {
                    path: crate::fsops::join(&destination_bytes, &basename),
                    descendants: args.recursive,
                });
            }
            scopes
        }
    };
    mutation_scopes.sort_by(|left, right| left.path.cmp(&right.path));
    mutation_scopes.dedup_by(|left, right| left.path == right.path);
    // Per-object policy only. The placement root's own precondition
    // (`--into-existing` and friends) is the separate signed root-existence
    // field; folding it in here would forbid creating files inside an
    // existing directory.
    // Timestamp selection is a coordinator policy based on source metadata.
    // The receiver enforces only the independently observable write authority.
    let existing = if args.only_new_native_entries() {
        ExistingDestinationPolicy::Skip
    } else if args.existing {
        ExistingDestinationPolicy::MustExist
    } else {
        ExistingDestinationPolicy::Replace
    };
    let (tcp_port_lo, tcp_port_hi) = crate::conn::parse_ports(&args.tcp_ports)?;
    let grant = Grant {
        enrollment_id: id,
        target_login: login.to_owned(),
        signer: signer_name(id),
        request_id: RequestId::fresh(issued_at)?,
        issued_at,
        not_before: issued_at.saturating_sub(CLOCK_SKEW_SECONDS),
        start_by,
        finish_by,
        operation: GrantOperation::Copy(CopyOperation {
            destination: destination_bytes,
            mutation_scopes,
            policy: CopyPolicy {
                placement,
                existing,
                deletion,
                publication: if args.inplace {
                    PublicationPolicy::InPlace
                } else {
                    PublicationPolicy::AtomicStaged
                },
            },
            options: CopyOptions {
                recursive: args.recursive,
                preserve_symlinks: args.links,
                preserve_permissions: args.perms,
                receiver_managed_modes: !args.perms,
                preserve_times: args.times,
                preserve_owner: args.owner,
                preserve_group: args.group,
                preserve_devices: args.devices,
                compare_existing_by_content: args.checksum,
                dry_run: args.dry_run,
                verify_only: false,
                compressed_transport: args.compress,
                tcp_port_lo,
                tcp_port_hi,
            },
            limits: CopyLimits {
                max_entries,
                max_total_bytes,
                max_file_bytes,
                hash_block_bytes: args.block_size,
                max_connections: u16::try_from(if args.connections_opt.is_some() {
                    args.connections
                } else {
                    args.resource_limits
                        .as_ref()
                        .and_then(|limits| limits.workers)
                        .unwrap_or(usize::from(delegation::MAX_CONNECTIONS))
                        .min(usize::from(delegation::MAX_CONNECTIONS))
                })
                .context("connection maximum exceeds grant representation")?,
                max_deletions,
            },
        }),
    };
    Ok(grant)
}

pub(super) fn filter_destination_roots(
    args: &Args,
    sources: &[Location],
    destination: &[u8],
) -> Result<Vec<Vec<u8>>> {
    let mut roots = Vec::with_capacity(sources.len());
    for source in sources {
        if args.placement == Placement::As || source.copies_contents() {
            roots.push(destination.to_vec());
        } else {
            let basename = source.basename();
            if basename.is_empty() {
                bail!("named source has no destination basename for signed filters");
            }
            roots.push(crate::fsops::join(destination, &basename));
        }
    }
    roots.sort();
    roots.dedup();
    Ok(roots)
}

pub(super) fn mapping_authorization(args: &Args) -> Result<Option<crate::mapping::Authorization>> {
    args.mapping_contents
        .as_ref()
        .map(|input| input.authorization())
        .transpose()
}

pub(crate) fn prepare_transfer(
    args: &Args,
    sources: &[Location],
    destination: &Location,
    source_login: &str,
    destination_login: &str,
    allow_enrollment: bool,
) -> Result<PreparedTransfer> {
    validate_restricted_args(args)?;
    let host = destination
        .host
        .as_deref()
        .context("destination host missing")?;
    let requested = destination.path.as_slice();
    let mut selected = None;
    for (metadata, directory) in load_local_enrollments()? {
        if metadata.host == host
            && metadata.port == destination.port
            && metadata.target_login == destination_login
        {
            if let Some(canonical_destination) = destination_for(&metadata, requested)? {
                selected = Some((metadata, directory, canonical_destination));
                break;
            }
        }
    }
    let (metadata, directory, canonical_destination) = match selected {
        Some(selected) => selected,
        None => {
            if !allow_enrollment {
                bail!(
                    "read-only operations will not install a receiver enrollment; pre-enroll this destination with `syq receiver enroll` or explicitly use --peer-auth broker"
                );
            }
            let jump = endpoint(
                source_login,
                sources[0].host.as_deref().context("source host missing")?,
                sources[0].port,
            )?;
            enroll(
                host,
                destination.port,
                destination_login,
                // Automatic enrollment declares a new administrative scope,
                // which stays UTF-8; transfers against an existing
                // enrollment accept any destination bytes above.
                std::str::from_utf8(requested).context(
                    "automatic enrollment requires a UTF-8 destination; pre-enroll a scope with `syq receiver enroll` to copy to this path",
                )?,
                Some(&jump),
                false,
            )?
        }
    };
    let private_key = load_private_key(&directory)?;
    let receipt_public_key = metadata.receipt_public_key.clone();
    let grant = grant_for(
        args,
        sources,
        metadata.id,
        destination_login,
        &canonical_destination,
    )?;
    let protected = receiver_control_paths(
        Path::new(&metadata.remote_home),
        Path::new(&metadata.receiver_path),
        None,
    )?;
    let GrantOperation::Copy(copy) = &grant.operation;
    reject_control_plane_scopes(copy, &protected)?;
    let request_id = grant.request_id;
    let (receipt_recipient_secret, receipt_delivery) = if args.detach {
        (
            None,
            crate::receipt::ReceiptDelivery::DetachedSignedPlaintext,
        )
    } else {
        let (secret, public) = crate::receipt::generate_recipient()?;
        (
            Some(secret),
            crate::receipt::ReceiptDelivery::AttachedEncrypted {
                suite: crate::receipt::HpkeSuite::X25519HkdfSha256HkdfSha256ChaCha20Poly1305,
                recipient_public_key: public,
            },
        )
    };
    let receipt_policy = crate::receipt::ReceiptPolicy {
        required: true,
        hashed: args.receiver_receipt == Some(crate::cli::ReceiptDetail::Hashes),
        max_records: crate::receipt::DEFAULT_MAX_RECORDS,
        max_plaintext_bytes: crate::receipt::DEFAULT_MAX_PLAINTEXT_BYTES,
        delivery: receipt_delivery,
    };
    let grant = delegation::sign_grant(
        grant,
        GrantConstraints {
            tcp_congestion: args.tcp_congestion.clone(),
            mapping: mapping_authorization(args)?,
            hashing: Some(crate::hashing::CopyHashing::from_args(args)),
            max_file_data_bytes_per_second: args.bwlimit_bytes,
            filters: FilterPolicy {
                ignore: args.ignore_lines.clone(),
                destination_roots: filter_destination_roots(args, sources, &canonical_destination)?,
                delete_excluded: args.delete_excluded,
            },
            root_existence: root_existence_for(args.target_existence),
            receipt_policy: receipt_policy.clone(),
        },
        &private_key,
    )?;
    let grant_digest = delegation::signed_grant_digest(&grant)?;
    Ok(PreparedTransfer {
        private_key,
        request_id,
        receipt_public_key,
        receipt_recipient_secret,
        receipt_policy,
        grant_digest,
        canonical_destination,
        grant: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(grant),
        enrollment_id: metadata.id,
    })
}

/// Build a request without trusting the source's eventual filesystem claims.
/// The receiving laptop separately confines and approves every mutation scope.
pub(crate) fn named_request(
    args: &Args,
    receipt_policy: crate::receipt::ReceiptPolicy,
) -> Result<crate::destination::CopyRequest> {
    let (destination, sources) = args
        .locations
        .split_last()
        .context("copy endpoints missing")?;
    let mut checked = args.clone();
    // These channels are encrypted by the laptop-initiated SSH connection.
    checked.no_tcp = false;
    let path = crate::destination::request_path(b".")?;
    let grant = grant_for(
        &checked,
        sources,
        EnrollmentId::random(),
        "named-destination",
        &path,
    )?;
    let GrantOperation::Copy(copy) = grant.operation;
    Ok(crate::destination::CopyRequest {
        destination: destination.path.clone(),
        copy,
        constraints: GrantConstraints {
            tcp_congestion: args.tcp_congestion.clone(),
            mapping: mapping_authorization(args)?,
            hashing: Some(crate::hashing::CopyHashing::from_args(args)),
            max_file_data_bytes_per_second: args.bwlimit_bytes,
            filters: FilterPolicy {
                ignore: args.ignore_lines.clone(),
                destination_roots: filter_destination_roots(args, sources, &path)?,
                delete_excluded: args.delete_excluded,
            },
            root_existence: root_existence_for(args.target_existence),
            receipt_policy,
        },
    })
}

/// A fresh, in-memory authorization minted on the receiving machine after
/// approval. It shares the restricted executor, but never reads or changes an
/// SSH enrollment, a signed grant's replay store, or persistence preferences.
pub(crate) fn named_authority(
    root: &Path,
    request: crate::destination::CopyRequest,
) -> Result<(
    std::sync::Arc<RestrictedAuthority>,
    crate::destination::Approved,
)> {
    let (login, home) = current_account()?;
    let parent = root;
    let metadata = fs::metadata(parent)?;
    let id = EnrollmentId::random();
    let issued_at = now()?;
    let request_id = RequestId::fresh(issued_at)?;
    let grant = Grant {
        enrollment_id: id,
        target_login: login.clone(),
        signer: signer_name(id),
        request_id,
        issued_at,
        not_before: issued_at,
        start_by: issued_at + 60,
        finish_by: issued_at + FINISH_WINDOW_SECONDS,
        operation: GrantOperation::Copy(request.copy.clone()),
    };
    let key = generate_receipt_key(id)?;
    // Reuse the complete canonical grant validator. This ephemeral signature
    // is not sent to the requester as a redeemable enrollment credential.
    let signed = delegation::sign_grant(grant.clone(), request.constraints.clone(), &key)?;
    let digest = delegation::signed_grant_digest(&signed)?;
    let executable = fs::canonicalize(std::env::current_exe()?)?;
    let home = fs::canonicalize(home)?;
    let mut protected = receiver_control_paths(&home, &executable, None)?;
    for directory in [
        ".syq-receive-v1",
        ".syq-destinations-v1",
        ".syq-destinations-v2",
        ".syq-destinations-v3",
    ] {
        protected.push(ReceiverControlPath {
            path: home.join(directory).as_os_str().as_bytes().to_vec(),
            label: "named destination authority state",
        });
    }
    for path in [
        crate::destination::receiver_identity_directory()?,
        crate::receive_service::config_path()?
            .parent()
            .unwrap()
            .to_path_buf(),
        crate::persistence::runtime_parent_path(),
    ] {
        protected.push(ReceiverControlPath {
            path: path.as_os_str().as_bytes().to_vec(),
            label: "background receiving control state",
        });
    }
    let config = ReceiverEnrollment {
        version: CONFIG_VERSION,
        id,
        target_login: login,
        signer: signer_name(id),
        root: parent
            .to_str()
            .context("receiving directory must be UTF-8")?
            .into(),
        root_dev: metadata.dev(),
        root_ino: metadata.ino(),
        ssh_keygen: String::new(),
        receiver_path: executable.to_string_lossy().into_owned(),
    };
    let approved = crate::destination::Approved {
        token: String::new(),
        destination: request.copy.destination.clone(),
        enrollment: id,
        request: request_id,
        digest,
        receipt_key: key.public_key().to_openssh()?,
    };
    let authority = RestrictedAuthority::new(
        &config,
        grant,
        request.constraints,
        digest,
        key,
        Instant::now() + std::time::Duration::from_secs(FINISH_WINDOW_SECONDS as u64),
        &protected,
    )?;
    Ok((std::sync::Arc::new(authority), approved))
}

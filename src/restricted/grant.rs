use super::*;

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

/// The copy options a grant signs beyond its released `CopyOptions`.
pub(crate) fn extra_copy_options(args: &Args) -> delegation::ExtraCopyOptions {
    delegation::ExtraCopyOptions {
        hardlinks: args.hardlinks,
        acls: args.acls,
        xattrs: args.xattrs,
        atimes: args.atimes > 0,
        crtimes: args.crtimes,
        sparse: args.sparse,
        open_noatime: args.open_noatime || args.atimes > 1,
        widen_dirs: args.widen_dirs.into(),
        keep_files: args.ignore_existing && !args.only_new_native_entries(),
        follow_dst: args.follows_native_destination_paths()
            && args.placement == crate::cli::Placement::Into,
    }
}

pub(crate) fn validate_restricted_args(args: &Args) -> Result<()> {
    if let Some(input) = &args.mapping_contents {
        input.validate_restricted_bounds()?;
    }
    if args.no_tcp_encryption {
        bail!("command-restricted transfers require encrypted data connections");
    }
    if args.follows_native_destination_paths()
        && args.placement == crate::cli::Placement::Into
        && args.widen_dirs == crate::cli::WidenDirs::All
    {
        bail!("--widen-dirs all cannot be combined with --follow-dst on a command-restricted destination");
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

/// Whether `args` asks to delete destination extras. `--max-delete 0` means
/// nothing may be deleted, which a grant states directly as a forbidding
/// policy rather than a zero budget.
pub(crate) fn requests_pruning(args: &Args) -> bool {
    args.delete && args.max_delete != Some(0)
}

pub(super) fn grant_for(
    args: &Args,
    sources: &[Location],
    (id, generation): (EnrollmentId, u64),
    login: &str,
    destination: &[u8],
) -> Result<Grant> {
    validate_restricted_args(args)?;
    let issued_at = now()?;
    let read_only = args.dry_run;
    let deletion = if !read_only && requests_pruning(args) {
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
    // Without --max-delete, pruning may remove as many entries as the copy
    // may touch, as an ordinary copy's pruning is unlimited.
    let max_deletions = match deletion {
        DeletionPolicy::Forbid => 0,
        DeletionPolicy::DeleteDestinationOnly => {
            args.max_delete.unwrap_or(max_entries).min(max_entries)
        }
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
        signer: signer_name(id, generation),
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
                publication: if args.in_place_update {
                    PublicationPolicy::InPlaceUpdate
                } else if args.inplace {
                    PublicationPolicy::InPlaceNew
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
                // A ceiling the copy chose (`--resource-limits workers`), not
                // the count a benchmark fixes (`--performance-tuning workers`).
                max_connections: u16::try_from(
                    args.resource_limits
                        .as_ref()
                        .and_then(|limits| limits.workers)
                        .unwrap_or(usize::from(delegation::MAX_CONNECTIONS))
                        .min(usize::from(delegation::MAX_CONNECTIONS)),
                )
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

/// Sign a grant for a copy to `destination` with the user's login key,
/// setting up the destination account's enrollment, refreshing it for this
/// build, or finding the login key again first when needed. A dry run
/// (`allow_enrollment` false) changes nothing on the server.
pub(crate) fn prepare_transfer(
    args: &Args,
    sources: &[Location],
    destination: &Location,
    source_login: &str,
    destination_login: &str,
    destination_agent: Option<&Path>,
    allow_enrollment: bool,
) -> Result<PreparedTransfer> {
    validate_restricted_args(args)?;
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
    let enroll_now = |refresh: bool| {
        enroll(
            host,
            destination.port,
            destination_login,
            Some(&jump),
            refresh,
        )
    };
    let found = load_local_enrollments()?.into_iter().find(|(metadata, _)| {
        metadata.host == host
            && metadata.port == destination.port
            && metadata.target_login == destination_login
    });
    let (metadata, directory, signer) = match found {
        Some((metadata, directory)) if metadata.release == crate::identity::build() => {
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
            now()?,
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
    let destination_path = normalize_absolute(
        std::ffi::OsStr::from_bytes(&destination.path),
        Path::new(&metadata.remote_home),
    )?
    .into_os_string()
    .into_vec();
    let grant = grant_for(
        args,
        sources,
        (metadata.id, metadata.generation),
        destination_login,
        &destination_path,
    )?;
    let protected = receiver_control_paths(Path::new(&metadata.remote_home), None)?;
    let GrantOperation::Copy(copy) = &grant.operation;
    reject_control_plane_scopes(copy, &protected)?;
    let request_id = grant.request_id;
    let (recipient_secret, recipient_public_key) =
        crate::destination_results::generate_recipient()?;
    let grant = delegation::sign_grant_with(
        grant,
        GrantConstraints {
            tcp_congestion: args.tcp_congestion.clone(),
            mapping: mapping_authorization(args)?,
            hashing: Some(crate::hashing::CopyHashing::from_args(args)),
            // The sender paces network bytes, as for an ordinary copy: a
            // bandwidth limit is a preference, not part of the authorization.
            max_file_data_bytes_per_second: 0,
            filters: FilterPolicy {
                ignore: args.ignore_lines.clone(),
                destination_roots: filter_destination_roots(args, sources, &destination_path)?,
                delete_excluded: args.delete_excluded,
            },
            root_existence: root_existence_for(args.target_existence),
            receipt_policy: crate::destination_results::ReceiptPolicy::for_recipient(
                recipient_public_key,
            ),
            extra_options: extra_copy_options(args),
        },
        |payload| {
            let signature = signer.sign(delegation::SSHSIG_NAMESPACE, payload)?;
            // Check here what the receiver checks, so a FIDO policy or an
            // expired certificate fails before anything starts.
            metadata
                .signer
                .verify(delegation::SSHSIG_NAMESPACE, payload, &signature, now()?)
                .context("check the grant's signature")?;
            Ok(signature)
        },
    )?;
    let grant_digest = delegation::signed_grant_digest(&grant)?;
    Ok(PreparedTransfer {
        entry_key,
        request_id,
        results_public_key: metadata.results_public_key.clone(),
        recipient_secret,
        grant_digest,
        destination: destination_path,
        grant: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(grant),
        enrollment_id: metadata.id,
    })
}

/// Whether `grant` was signed for an enrolled receiver, whose sender paces
/// network bytes as for an ordinary copy. Connections that a receiving
/// machine approves are not paced at the transport, so those requests carry
/// the bandwidth limit and the receiver enforces it on file data.
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
    let grant = grant_for(
        &checked,
        sources,
        (EnrollmentId::random(), 1),
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
            // A receiving machine does not follow a symlink at the
            // destination; the coordinator refuses one it finds there.
            extra_options: delegation::ExtraCopyOptions {
                follow_dst: false,
                ..extra_copy_options(args)
            },
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
    if request.constraints.extra_options.follow_dst {
        bail!("copies a receiving machine approves do not follow destination symlinks");
    }
    let (login, home) = current_account()?;
    let parent = root;
    let metadata = fs::metadata(parent)?;
    let id = EnrollmentId::random();
    let issued_at = now()?;
    let request_id = RequestId::fresh(issued_at)?;
    let grant = Grant {
        enrollment_id: id,
        target_login: login,
        signer: signer_name(id, 1),
        request_id,
        issued_at,
        not_before: issued_at,
        start_by: issued_at + 60,
        finish_by: issued_at + FINISH_WINDOW_SECONDS,
        operation: GrantOperation::Copy(request.copy.clone()),
    };
    let key = generate_results_key(id)?;
    // Reuse the complete canonical grant validator. This ephemeral signature
    // is not sent to the requester as a redeemable enrollment credential.
    let signed = delegation::sign_grant(grant.clone(), request.constraints.clone(), &key)?;
    let digest = delegation::signed_grant_digest(&signed)?;
    let executable = fs::canonicalize(std::env::current_exe()?)?;
    let home = fs::canonicalize(home)?;
    let protected = receiver_control_paths(&home, Some(&executable))?;
    let confined = ConfinedRoot::opened(
        parent,
        RootIdentity {
            dev: metadata.dev(),
            ino: metadata.ino(),
        },
    )?;
    let approved = crate::destination::Approved {
        token: String::new(),
        destination: request.copy.destination.clone(),
        enrollment: id,
        request: request_id,
        digest,
        results_key: key.public_key().to_openssh()?,
        max_delete: None,
    };
    let authority = RestrictedAuthority::new(
        confined,
        grant,
        request.constraints,
        digest,
        key,
        Instant::now() + std::time::Duration::from_secs(FINISH_WINDOW_SECONDS as u64),
        &protected,
    )?;
    Ok((std::sync::Arc::new(authority), approved))
}

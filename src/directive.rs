//! The directive: the command one copy was approved for, bound to one
//! enrollment and signed by the user's login key.
//!
//! A directive carries the command as it was run, not rules: every party
//! derives the rules from it with the same parser and the same functions
//! below, so what a receiver enforces is what the command says. Facts the
//! command cannot state travel beside it: the ignore rules and the mapping it
//! read from files, which only narrow a copy, and the key that encrypts the
//! destination's results for the copy's initiator.
//!
//! The encoding is canonical postcard behind a fixed header. A receiver
//! decodes it, encodes it again and requires the same bytes, so there is one
//! spelling of each directive; unknown variants and trailing bytes are
//! refused. Verification and the record of used directives are in
//! `delegation`.

use crate::cli::{Args, Existence, Location, Placement};
use crate::delegation::{
    self, CopyLimits, CopyOperation, CopyOptions, CopyPolicy, DeletionPolicy, DestinationPlacement,
    ExistingDestinationPolicy, FilterPolicy, Grant, GrantConstraints, MutationScope,
    PublicationPolicy, RequestId, RootExistence,
};
use crate::enrollment::EnrollmentId;
use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// The SSHSIG namespace of directives. No login, Git signature or other syq
/// signature uses it.
pub(crate) const NAMESPACE: &str = "syq-directive@greaber.github";
const MAGIC: &[u8; 8] = b"SYQDIR1\0";
const HEADER_LEN: usize = MAGIC.len() + 4 + 4;
const MAX_BODY_BYTES: usize = 512 * 1024;
/// The longest signed directive a receiver reads.
pub(crate) const MAX_SIGNED_BYTES: usize =
    HEADER_LEN + MAX_BODY_BYTES + delegation::MAX_SIGNATURE_BYTES;
const MAX_BUILD_BYTES: usize = 256;
const MAX_CWD_BYTES: usize = 4096;
const MAX_IGNORE_RULES: usize = 4096;
const MAX_IGNORE_RULE_BYTES: usize = 4096;
/// A directive must be used within this long of being issued.
pub(crate) const VALIDITY_SECONDS: i64 = 24 * 60 * 60;
/// A copy must finish within this long of its directive being issued.
pub(crate) const FINISH_WINDOW_SECONDS: i64 = 7 * 24 * 60 * 60;
/// How far a receiver's clock may differ from the signing machine's.
pub(crate) const CLOCK_SKEW_SECONDS: i64 = 60;

/// One approved copy, as its initiator ran it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Directive {
    /// The build that signed it. A receiver of another build refuses it
    /// before recording anything.
    pub build: String,
    pub request_id: RequestId,
    pub issued_at: i64,
    pub not_before: i64,
    /// The copy must start by this wall-clock time.
    pub start_by: i64,
    /// The copy must finish by this wall-clock time.
    pub finish_by: i64,
    pub binding: Binding,
    /// The initiator's arguments after the program name, with options from
    /// its environment applied.
    pub command: Vec<Vec<u8>>,
    /// The initiator's working directory, for display only.
    pub cwd: String,
    pub inputs: Inputs,
    /// The approving machine's own limits, when it approved a server's
    /// command; a command run on the signing machine has none.
    pub caps: Option<Caps>,
    /// The initiator's key for this copy's results from the destination.
    pub results_key: [u8; 32],
}

/// What ties a directive to one receiver.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Binding {
    pub enrollment: EnrollmentId,
    /// The enrollment's generation when it was signed: a directive from
    /// before a refresh is refused after it.
    pub generation: u64,
    /// The server account.
    pub account: String,
    pub role: Role,
}

/// Which end of the copy the receiver is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Role {
    Destination,
}

/// What the command read from files, which a receiver cannot read. Both only
/// narrow the copy.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Inputs {
    /// The ordered ignore rules, from `--ignore` and `--ignore-from`.
    pub ignore: Vec<String>,
    /// The size and digest of the `--mapping` manifest.
    pub mapping: Option<crate::mapping::Authorization>,
}

/// An approving machine's limits on a copy it approved for a server: they
/// lower what the command asks for, never raise it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Caps {
    pub max_bytes: u64,
    pub max_entries: u64,
    /// The approving machine's `--max-delete`.
    pub max_delete: u64,
}

impl Caps {
    /// The most deletions `copy` may make under these limits: the
    /// approving machine's `--max-delete`, within the copy's entry limit.
    pub(crate) fn deletion_ceiling(&self, copy: &CopyOperation) -> u64 {
        self.max_delete.min(copy.limits.max_entries)
    }

    /// Fit `copy` within these limits, or refuse it. `dry_run_prunes` marks a
    /// dry run of a pruning copy, refused where pruning is off as the copy
    /// itself would be.
    pub(crate) fn apply(&self, copy: &mut CopyOperation, dry_run_prunes: bool) -> Result<()> {
        copy.limits.max_total_bytes = copy.limits.max_total_bytes.min(self.max_bytes);
        copy.limits.max_file_bytes = copy.limits.max_file_bytes.min(self.max_bytes);
        copy.limits.max_entries = copy.limits.max_entries.min(self.max_entries);
        let ceiling = self.deletion_ceiling(copy);
        copy.limits.max_deletions = copy.limits.max_deletions.min(ceiling);
        let prunes =
            dry_run_prunes || copy.policy.deletion == DeletionPolicy::DeleteDestinationOnly;
        if prunes && ceiling == 0 {
            bail!("pruning needs a positive --max-delete on the approving machine: `syq persist receive on --max-delete N`");
        }
        Ok(())
    }
}

impl Directive {
    /// Bounds a receiver checks before anything else.
    fn validate(&self) -> Result<()> {
        if self.build.is_empty() || self.build.len() > MAX_BUILD_BYTES {
            bail!("directive build is outside the supported range");
        }
        self.request_id.validate()?;
        self.binding.enrollment.validate()?;
        delegation::validate_identity("account", &self.binding.account)?;
        for (name, value) in [
            ("issued-at", self.issued_at),
            ("not-before", self.not_before),
            ("start-by", self.start_by),
            ("finish-by", self.finish_by),
        ] {
            if !(0..=delegation::MAX_UNIX_TIMESTAMP).contains(&value) {
                bail!("directive {name} time is out of range");
            }
        }
        if self.not_before > self.issued_at
            || self.issued_at > self.start_by
            || self.start_by > self.finish_by
        {
            bail!("directive times must satisfy not-before <= issued <= start-by <= finish-by");
        }
        let validity = self.start_by - self.not_before;
        if validity == 0 || validity > VALIDITY_SECONDS {
            bail!("a directive must be usable for between 1 second and 24 hours");
        }
        if self.finish_by - self.issued_at > FINISH_WINDOW_SECONDS {
            bail!("a directive's copy must finish within 7 days of its issue");
        }
        if self.command.is_empty()
            || self.command.iter().map(|arg| arg.len() + 1).sum::<usize>()
                > crate::approval_command::MAX_COMMAND_BYTES
        {
            bail!("directive command is outside the supported range");
        }
        if self.cwd.len() > MAX_CWD_BYTES {
            bail!("directive working directory is too long");
        }
        if self.inputs.ignore.len() > MAX_IGNORE_RULES
            || self
                .inputs
                .ignore
                .iter()
                .any(|rule| rule.len() > MAX_IGNORE_RULE_BYTES || rule.contains('\0'))
        {
            bail!("directive ignore rules are outside the supported range");
        }
        Ok(())
    }
}

/// The bytes the login key signs: the magic, then the canonical body.
fn payload(body: &[u8]) -> Vec<u8> {
    [MAGIC.as_slice(), body].concat()
}

/// Sign `directive` with `sign`, which signs the payload in [`NAMESPACE`],
/// and encode it for a receiver.
pub(crate) fn sign(
    directive: &Directive,
    sign: impl FnOnce(&[u8]) -> Result<Vec<u8>>,
) -> Result<Vec<u8>> {
    directive.validate()?;
    let body = postcard::to_stdvec(directive).context("encode the directive")?;
    if body.len() > MAX_BODY_BYTES {
        bail!("the directive exceeds {MAX_BODY_BYTES} bytes");
    }
    let signature = sign(&payload(&body))?;
    delegation::validate_canonical_sshsig(&signature)?;
    let mut out = Vec::with_capacity(HEADER_LEN + body.len() + signature.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&(signature.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    out.extend_from_slice(&signature);
    Ok(out)
}

/// A decoded directive with the bytes its signature covers. The signature
/// is not checked yet.
#[derive(Debug)]
pub(crate) struct Signed {
    pub directive: Directive,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}

impl Signed {
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_SIGNED_BYTES {
            bail!("the directive exceeds its size limit");
        }
        if bytes.len() < HEADER_LEN || &bytes[..MAGIC.len()] != MAGIC {
            bail!("not a syq directive");
        }
        let body_len = u32::from_be_bytes(bytes[8..12].try_into().expect("fixed header")) as usize;
        let signature_len =
            u32::from_be_bytes(bytes[12..16].try_into().expect("fixed header")) as usize;
        if body_len == 0
            || body_len > MAX_BODY_BYTES
            || signature_len == 0
            || signature_len > delegation::MAX_SIGNATURE_BYTES
            || bytes.len() != HEADER_LEN + body_len + signature_len
        {
            bail!("the directive's lengths are noncanonical");
        }
        let body = &bytes[HEADER_LEN..HEADER_LEN + body_len];
        let (directive, rest): (Directive, &[u8]) =
            postcard::take_from_bytes(body).context("decode the directive")?;
        if !rest.is_empty() || postcard::to_stdvec(&directive)? != body {
            bail!("the directive uses a noncanonical encoding");
        }
        directive.validate()?;
        let signature = bytes[HEADER_LEN + body_len..].to_vec();
        delegation::validate_canonical_sshsig(&signature)?;
        Ok(Self {
            directive,
            payload: payload(body),
            signature,
        })
    }

    /// The digest that binds the destination's results to this directive.
    pub(crate) fn digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"syq-directive-transcript@greaber.github\0");
        hasher.update(&(self.payload.len() as u64).to_be_bytes());
        hasher.update(&self.payload);
        *hasher.finalize().as_bytes()
    }
}

pub(crate) fn now() -> Result<i64> {
    i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
        .context("current time exceeds the signed time range")
}

/// A directive for `command` issued now, with the standard validity.
pub(crate) fn issue(
    binding: Binding,
    command: Vec<Vec<u8>>,
    cwd: String,
    (inputs, caps): (Inputs, Option<Caps>),
    results_key: [u8; 32],
) -> Result<Directive> {
    let issued_at = now()?;
    Ok(Directive {
        build: crate::identity::build().to_owned(),
        request_id: RequestId::fresh(issued_at)?,
        issued_at,
        not_before: issued_at.saturating_sub(CLOCK_SKEW_SECONDS),
        start_by: issued_at
            .checked_add(VALIDITY_SECONDS - CLOCK_SKEW_SECONDS)
            .context("directive start-by overflow")?,
        finish_by: issued_at
            .checked_add(FINISH_WINDOW_SECONDS)
            .context("directive finish-by overflow")?,
        binding,
        command,
        cwd,
        inputs,
        caps,
        results_key,
    })
}

/// The rules for the destination of `directive`, on an account whose home
/// is `home`. The receiver and the signing machine both call this, so the
/// signing machine checks exactly what the receiver will enforce.
pub(crate) fn destination_rules(
    directive: &Directive,
    home: &Path,
) -> Result<(Grant, GrantConstraints)> {
    let Role::Destination = directive.binding.role;
    let args = crate::approval_command::parse(&directive.command)?;
    ensure!(
        args.interface == crate::cli::Interface::NativeCp && args.s3.is_none(),
        "a directive's command must be a syq cp between file systems"
    );
    validate_restricted_args(&args)?;
    let (destination, sources) = args
        .locations
        .split_last()
        .context("the directive's command names no destination")?;
    ensure!(
        destination.is_remote(),
        "the directive's command copies to this machine, not to a server"
    );
    ensure!(
        args.native_mapping.is_some() == directive.inputs.mapping.is_some(),
        "the directive's mapping does not match its command"
    );
    let sources = crate::transfer::distinct_native_sources(sources);
    let destination_path = normalize_absolute(OsStr::from_bytes(&destination.path), home)?
        .into_os_string()
        .into_vec();
    let mut copy = copy_operation(&args, &sources, &destination_path)?;
    if let Some(caps) = &directive.caps {
        caps.apply(&mut copy, args.dry_run && requests_pruning(&args))?;
    }
    let mut constraints = GrantConstraints {
        tcp_congestion: args.tcp_congestion.clone(),
        mapping: directive.inputs.mapping.clone(),
        hashing: Some(crate::hashing::CopyHashing::from_args(&args)),
        // The sender paces network bytes, as for an ordinary copy: a
        // bandwidth limit is a preference, not part of the authorization.
        max_file_data_bytes_per_second: 0,
        filters: FilterPolicy {
            ignore: directive.inputs.ignore.clone(),
            destination_roots: filter_destination_roots(&args, &sources, &destination_path)?,
            delete_excluded: args.delete_excluded,
        },
        root_existence: root_existence_for(args.target_existence),
        receipt_policy: crate::destination_results::ReceiptPolicy::for_recipient(
            directive.results_key,
        ),
        extra_options: extra_copy_options(&args),
    };
    delegation::validate_rules(&copy, &mut constraints)?;
    Ok((
        Grant {
            enrollment_id: directive.binding.enrollment,
            request_id: directive.request_id,
            copy,
        },
        constraints,
    ))
}

/// `path` as an absolute path on an account whose home is `home`: `~`,
/// `~/…` and relative paths are in the home directory.
pub(crate) fn normalize_absolute(path: &OsStr, home: &Path) -> Result<std::path::PathBuf> {
    let bytes = path.as_bytes();
    let raw = if bytes == b"~" {
        home.to_path_buf()
    } else if let Some(rest) = bytes.strip_prefix(b"~/") {
        home.join(OsStr::from_bytes(rest))
    } else if bytes.starts_with(b"/") {
        std::path::PathBuf::from(path)
    } else {
        home.join(path)
    };
    let mut normalized = std::path::PathBuf::from("/");
    for component in raw.components() {
        match component {
            std::path::Component::RootDir | std::path::Component::CurDir => {}
            std::path::Component::Normal(component) => normalized.push(component),
            std::path::Component::ParentDir => {
                bail!("restricted destination must not contain .. components")
            }
            std::path::Component::Prefix(_) => bail!("unsupported destination prefix"),
        }
    }
    Ok(normalized)
}

pub(crate) fn root_existence_for(existence: Existence) -> RootExistence {
    match existence {
        Existence::Any => RootExistence::Any,
        Existence::New => RootExistence::New,
        Existence::Existing => RootExistence::Existing,
    }
}

/// The copy options a destination's rules include beyond `CopyOptions`.
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
        follow_dst: args.follows_native_destination_paths() && args.placement == Placement::Into,
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
        && args.placement == Placement::Into
        && args.widen_dirs == crate::cli::WidenDirs::All
    {
        bail!("--widen-dirs all cannot be combined with --follow-dst on a command-restricted destination");
    }
    // Range-check every ceiling here, before automatic enrollment can touch
    // the server, rather than leaving it to the receiver.
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
/// nothing may be deleted, which the rules state directly as a forbidding
/// policy rather than a zero budget.
pub(crate) fn requests_pruning(args: &Args) -> bool {
    args.delete && args.max_delete != Some(0)
}

pub(crate) const DEFAULT_MAX_ENTRIES: u64 = 100_000_000;
pub(crate) const DEFAULT_MAX_BYTES: u64 = 8 * 1024 * 1024 * 1024 * 1024;

/// What a copy of `sources` to `destination` may do there, as `args`
/// states it.
pub(crate) fn copy_operation(
    args: &Args,
    sources: &[Location],
    destination: &[u8],
) -> Result<CopyOperation> {
    validate_restricted_args(args)?;
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
                    bail!("named source has no destination basename");
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
    // (`--into-existing` and friends) is the separate root-existence rule;
    // folding it in here would forbid creating files inside an existing
    // directory. Timestamp selection is a coordinator policy based on source
    // metadata; the receiver enforces only the independently observable
    // write authority.
    let existing = if args.only_new_native_entries() {
        ExistingDestinationPolicy::Skip
    } else if args.existing {
        ExistingDestinationPolicy::MustExist
    } else {
        ExistingDestinationPolicy::Replace
    };
    let (tcp_port_lo, tcp_port_hi) = crate::conn::parse_ports(&args.tcp_ports)?;
    Ok(CopyOperation {
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
            .context("connection maximum exceeds the supported range")?,
            max_deletions,
        },
    })
}

pub(crate) fn filter_destination_roots(
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
                bail!("named source has no destination basename for filters");
            }
            roots.push(crate::fsops::join(destination, &basename));
        }
    }
    roots.sort();
    roots.dedup();
    Ok(roots)
}

pub(crate) fn mapping_authorization(args: &Args) -> Result<Option<crate::mapping::Authorization>> {
    args.mapping_contents
        .as_ref()
        .map(|input| input.authorization())
        .transpose()
}

#[cfg(test)]
mod tests;

//! The coordinator: scan, diff, schedule, and the per-worker transfer loop.

use crate::bwlimit::BandwidthLimit;
use crate::cli::{
    parse_rsh, parse_size, rsync_operator_symlink_policy, Args, CoordinateAt, Existence, Interface,
    Location, Placement, SourceSelection,
};
use crate::conn::{
    data_address, endpoint_error, ok, parse_ports, Conn, DataAddressSource, DataTransport,
    Endpoint, RemoteSpec, SshMultiplexer, TcpCandidate, TcpPairStats,
};
use crate::copy_policy::FreshCapacityAssessment;
#[cfg(test)]
use crate::fsops::content_digest;
use crate::fsops::{destination_fraction_matches, is_partial_name, is_recovery_name, join};
use crate::mapping::{read_mapping_manifest, DeclaredKind, ManifestEntry};
use crate::output::debug;
use crate::progress::{commas, human, Progress};
use crate::proto::DestinationRoot as RegisteredDestinationRoot;
use crate::proto::*;
use crate::sched::{FileJob, FileJobData, Item, RangeHandle, RangeWork, Sched, WorkerJob};
use crate::tune::{self, Gate};
use anyhow::{bail, ensure, Context, Result};
use std::ffi::OsStr;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
use std::sync::Mutex;

mod diagnostics;
mod dry_run;
mod planner;
mod worker;

use diagnostics::*;
use dry_run::*;
use planner::*;
use worker::*;

const MAX_ATTEMPTS: u32 = 3;
pub const LOCAL_DEFAULT_CONNECTIONS: usize = 32;
// Amortize metadata requests across enough files to keep their shared pool
// busy. The scheduler still divides queued files fairly among active workers,
// and the byte limit bounds each batch independently of this ceiling.
const FAST_BATCH_FILES: usize = 2048;
// Keep the startup worker budget independent of the larger batch ceiling.
// Larger batches must not leave small trees with fewer transfer workers.
const STARTUP_BATCH_FILES: usize = 128;
// Source requests carry both display paths and registered references. Leave
// room for framing within the metadata protocol's 8 MiB limit, even when a
// large batch contains long paths rather than substantial file data.
const SOURCE_BATCH_PATH_BYTES: usize = 4 << 20;

fn source_request_bytes(path: &[u8], source: Option<&RegisteredPath>) -> usize {
    path.len()
        .saturating_add(source.map_or(0, |source| source.relative().len()))
        .saturating_add(64)
}
const CONNECTION_RECOVERY_ATTEMPTS: u32 = 3;

// Bound a window of small-file groups independently of the logical batch.
const FAST_BATCH_READ_BYTES: u64 = 4 << 20;

/// Upper bound: each file needs one worker, and each simultaneous range must
/// contain at least min_split bytes. Balanced/aligned splitting can use fewer.
fn initial_range_workers(
    limit: usize,
    sizes: impl IntoIterator<Item = u64>,
    min_split: u64,
) -> usize {
    assert!(min_split > 0);
    let capacity = sizes.into_iter().fold(0u64, |total, size| {
        total.saturating_add((size / min_split).max(1))
    });
    limit.min((capacity.min(usize::MAX as u64) as usize).max(1))
}

fn reuse_startup_ssh(id: usize, autotune: bool) -> bool {
    id == 0 || (autotune && id == 1)
}

fn initial_fast_workers(
    max_connections: usize,
    file_jobs: usize,
    file_bytes: u64,
    batch_files: usize,
    batch_bytes: u64,
) -> usize {
    // A batch is independently bounded by its entry count and its payload.
    // Provision enough fixed workers for whichever ceiling yields more work;
    // automatic runs may still tune from this bounded starting point.
    let file_batches = file_jobs.div_ceil(batch_files);
    let byte_batches = usize::try_from(file_bytes.div_ceil(batch_bytes)).unwrap_or(usize::MAX);
    max_connections.min(file_batches.max(byte_batches).max(1))
}

// Keep tiny files batched, but let eligible local medium files reach the
// guarded receiver-side copy path without shrinking ordinary range requests.
const LOCAL_FAST_FILE_BYTES: u64 = 64 * 1024;

fn fast_file_size_limit(opts: &Opts, bwlimit: Option<&BandwidthLimit>) -> u64 {
    // New files have no comparison basis. Their batching ceiling follows
    // transfer payload and batch limits, independently of hash granularity.
    let request = opts
        .tuning
        .request_size(opts.block, bwlimit, opts.restricted_receiver);
    let limit = opts.tuning.batch_bytes().min(request);
    if opts.copy_policy(bwlimit.is_some()).prefer_whole_files() {
        limit.min(LOCAL_FAST_FILE_BYTES)
    } else {
        limit
    }
}

pub struct Opts {
    pub hash_policy: crate::hashing::HashPolicy,
    pub mapping_expected_hashes: std::collections::HashMap<PathBytes, crate::hashing::Digest>,
    pub block: u64,
    pub tuning: crate::transfer_tuning::TransferTuning,
    benchmark: Option<Mutex<crate::transfer_tuning::BenchmarkStats>>,
    /// Settled before sharing these options; clone claims must fit preflight.
    local_copy_fd_budget: bool,
    pub flags: u8,
    pub recursive: bool,
    pub links: bool,
    pub perms: bool,
    pub devices: bool,
    pub checksum: bool,
    pub precise_mtime: bool,
    pub verify_only: bool,
    pub inplace: bool,
    pub same_host: bool,
    /// Automatic copies and explicit -j1 may use one direct userspace writer
    /// for the proven local-filesystem -> asynchronous-NFS topology.
    pub allow_sequential_nfs_fallback: bool,
    pub dst_remote: bool,
    pub restricted_receiver: bool,
    pub dry_run: bool,
    dry_run_metadata_files: AtomicU64,
    pub quiet: bool,
    pub verbose: u8,
    pub umask: u32,
    pub copy_id: CopyId,
    /// gitignore-style patterns applied to every source (see scan.rs).
    pub ignore: Vec<String>,
    /// --delete: remove destination paths the source doesn't have (see Planner::plan_deletes).
    pub delete: bool,
    /// --delete-excluded: ignored destination paths are extras too.
    pub delete_excluded: bool,
    /// --max-delete: delete nothing if more than this many deletions are planned.
    pub max_delete: Option<u64>,
    /// -u: skip files that are newer on the destination.
    pub update: bool,
    /// --ignore-existing: never touch a destination path that already exists.
    pub ignore_existing: bool,
    /// Native missing-only copies leave existing directory metadata alone.
    pub preserve_existing_directory_metadata: bool,
    /// --existing: never create a destination path that doesn't exist.
    pub existing: bool,
    /// Symlink policy for the operator-selected destination path.
    pub operator_symlink_policy: OperatorSymlinkPolicy,
    /// --max-size / --min-size: regular files outside the range are not transferred.
    pub max_size: Option<u64>,
    pub min_size: Option<u64>,
}

impl Opts {
    fn metadata_fix_flags(&self, source: &Entry, destination: &Entry) -> u8 {
        let mut changes = 0;
        if self.flags & flags::TIMES != 0
            && (source.mtime != destination.mtime
                || (self.precise_mtime
                    && !destination_fraction_matches(source.mtime_nsec, destination.mtime_nsec)))
        {
            changes |= flags::TIMES;
        }
        if self.flags & flags::MODE != 0 && source.mode & 0o7777 != destination.mode & 0o7777 {
            changes |= flags::MODE;
        }
        if self.flags & flags::OWNER != 0 && source.uid != destination.uid {
            changes |= flags::OWNER;
        }
        if self.flags & flags::GROUP != 0 && source.gid != destination.gid {
            changes |= flags::GROUP;
        }
        changes
    }

    fn metadata_matches(&self, source: &Entry, destination: &Entry) -> bool {
        destination.kind == Kind::File
            && destination.size == source.size
            && self.flags & flags::TIMES != 0
            && destination.mtime == source.mtime
            && (!self.precise_mtime
                || destination_fraction_matches(source.mtime_nsec, destination.mtime_nsec))
    }

    fn expected_for(&self, path: &[u8]) -> Option<&crate::hashing::Digest> {
        self.mapping_expected_hashes.get(path)
    }
    fn copy_policy(&self, bandwidth_limited: bool) -> crate::copy_policy::CopyPolicy {
        crate::copy_policy::CopyPolicy {
            same_host: self.same_host,
            // Payload checks do not disable same-host copy shortcuts.
            checksum: self.checksum,
            force_ranges: self.tuning.force_ranges(),
            bandwidth_limited,
            receiver_copy_disabled: !cfg!(any(target_os = "linux", target_os = "macos"))
                || !self.local_copy_fd_budget
                || self.verify_only
                || self.dry_run
                || self.restricted_receiver
                || (cfg!(target_os = "macos") && self.inplace),
        }
    }
}

fn print_benchmark_observations(opts: &Opts) {
    if let Some(benchmark) = &opts.benchmark {
        crate::output::diagnostic!(
            "syq: tuning observed: {}",
            serde_json::to_string(&*benchmark.lock().unwrap())
                .expect("benchmark counters serialize")
        );
    }
}

pub fn endpoint(loc: &Location, args: &Args) -> Result<Endpoint> {
    Ok(match &loc.host {
        None => Endpoint::local(),
        Some(h) => {
            let rsh = parse_rsh(&args.rsh)?;
            if loc.port.is_some() && args.rsh.is_some() && !rsh[0].ends_with("ssh") {
                bail!(
                    "an explicit endpoint SSH port requires the default ssh or an --rsh command whose executable is ssh"
                );
            }
            let ssh_multiplexer = if args.rsh.is_some() {
                None
            } else if args.restricted_grant.is_some() {
                Some(Arc::new(SshMultiplexer::new()?))
            } else {
                match crate::persistence::scope_for_implicit_ssh(args.pscope.as_deref())? {
                    Some(scope) => Some(Arc::new(SshMultiplexer::persistent(
                        &scope,
                        loc.user.as_deref(),
                        h,
                        loc.port,
                    )?)),
                    None => Some(Arc::new(SshMultiplexer::new()?)),
                }
            };
            Endpoint::Remote(RemoteSpec {
                local_process: false,
                user: loc.user.clone(),
                host: h.clone(),
                port: loc.port,
                rsh,
                syq_path: args.syq_path.clone(),
                bootstrap_helper: args.restricted_grant.is_none()
                    && args.syq_path.is_none()
                    && !args.no_bootstrap,
                restricted_grant: args.restricted_grant.clone(),
                helper_install: Default::default(),
                ssh_multiplexer,
                quiet: args.quiet,
                tcp: Default::default(),
                diagnostics: Default::default(),
                primed_control: Default::default(),
                forwarded: args
                    .named_receipt
                    .clone()
                    .filter(|_| matches!(args.auth_from, crate::cli::AuthFrom::Return(_))),
                read_ahead: args.tuning_options.unwrap_or_default().pipeline_depth(),
            })
        }
    })
}

/// Rsync's `--insecure-links` is local only: it is never sent to the remote
/// side of a transfer, so a remote endpoint keeps the default trusted-owner
/// policy and the confined source paths even when the operator passed the
/// flag here. Rsync mode never places the coordinator remotely, so "this
/// machine" is the one the operator invoked syq on.
fn rsync_insecure_links(args: &Args, endpoint_is_local: bool) -> bool {
    args.interface == Interface::Rsync && args.insecure_links && endpoint_is_local
}

fn source_operator_symlink_policy(args: &Args, source_is_local: bool) -> OperatorSymlinkPolicy {
    if args.interface == Interface::Rsync {
        rsync_operator_symlink_policy(rsync_insecure_links(args, source_is_local))
    } else if args.follows_native_source_paths() {
        OperatorSymlinkPolicy::FollowAll
    } else {
        OperatorSymlinkPolicy::Refuse
    }
}

fn destination_operator_symlink_policy(
    args: &Args,
    destination_is_local: bool,
) -> OperatorSymlinkPolicy {
    if args.interface == Interface::Rsync {
        rsync_operator_symlink_policy(rsync_insecure_links(args, destination_is_local))
    } else if args.follows_native_destination_paths() {
        OperatorSymlinkPolicy::FollowAll
    } else {
        OperatorSymlinkPolicy::Refuse
    }
}

fn control_operator_symlink_policy(args: &Args) -> OperatorSymlinkPolicy {
    if args.interface == Interface::Rsync {
        rsync_operator_symlink_policy(args.insecure_links)
    } else if args.native_follow {
        OperatorSymlinkPolicy::FollowAll
    } else {
        OperatorSymlinkPolicy::Refuse
    }
}

/// Open a control connection. It bypasses the data-connection connect
/// limiter: the scan, and therefore every worker, waits on it.
pub fn connect_ctl(ep: &Endpoint, args: &Args) -> Result<Box<dyn Conn>> {
    let mut connection = match ep {
        Endpoint::Local { .. } => ep.connect_control(args.compress),
        Endpoint::Remote(spec) => spec
            .connect_with(args.compress, false)
            .map(|c| Box::new(c) as Box<dyn Conn>),
    }?;
    configure_hashing(
        &mut *connection,
        crate::hashing::HashPolicy {
            algorithm: args.hash_algorithm,
            transfer_integrity: args.transfer_integrity,
            transfer_hash_type: args.transfer_hash_type,
        },
    )?;
    Ok(connection)
}

fn configure_hashing(connection: &mut dyn Conn, policy: crate::hashing::HashPolicy) -> Result<()> {
    ok(
        connection.call(Request::ConfigureHashing(policy))?,
        "configure hashing",
    )?;
    Ok(())
}

struct DestinationRoot<'a> {
    path: &'a [u8],
    existed: bool,
    is_container: bool,
    entry_is_dir: bool,
    exact: bool,
}

struct SourceMapping<'a> {
    follow_root: bool,
    contents: bool,
    selection: SourceSelection,
    sub: &'a [u8],
}

pub(crate) fn validate_native_source_type(
    path: &[u8],
    selection: SourceSelection,
    kind: Kind,
) -> Result<()> {
    match selection {
        SourceSelection::Contents | SourceSelection::Directory if kind == Kind::Symlink => bail!(
            "selector {} is a symlink; pass --follow-src (or --follow) to resolve source symlinks",
            display(path)
        ),
        SourceSelection::Contents if kind != Kind::Dir => {
            bail!("contents selector {} is not a directory", display(path))
        }
        SourceSelection::Directory if kind != Kind::Dir => {
            bail!("--src-dir selector {} is not a directory", display(path))
        }
        SourceSelection::File if kind == Kind::Dir => {
            bail!("--src-non-dir selector {} is a directory", display(path))
        }
        SourceSelection::Rsync
        | SourceSelection::Named
        | SourceSelection::NamedNoFollow
        | SourceSelection::File
        | SourceSelection::Directory
        | SourceSelection::Contents => Ok(()),
    }
}

/// Mode a fresh destination file is created with: the source mode under -p,
/// otherwise the source mode minus the umask (rsync semantics).
fn fresh_file_mode(opts: &Opts, entry: &Entry) -> u32 {
    if opts.perms {
        entry.mode & 0o7777
    } else {
        entry.mode & 0o777 & !opts.umask
    }
}

/// Outcome of the one-turn small push attempted before the ordinary engine
/// starts its destination preflight.
enum SmallCopy {
    /// The copy completed on the control connection and the run is settled.
    Done(i32),
    /// Not applicable, not fresh, or refused by the receiver. Nothing was
    /// written and the control session is untouched, so the ordinary engine
    /// continues on the same connections and reports any error itself.
    Declined,
    /// Staging failed with nothing published, but the receiver now holds the
    /// destination root; the engine continues on a fresh control session and
    /// reports the failure itself.
    Reconnect,
}

/// Whether a native push of local files to a remote directory may try the
/// one-turn small copy. Everything the ordinary engine decides from flags
/// that the fused request does not carry stays with the engine.
fn small_copy_eligible(
    args: &Args,
    srcs: &[Location],
    dst: &Location,
    src_ep: &Endpoint,
    dst_ep: &Endpoint,
) -> bool {
    #[cfg(debug_assertions)]
    if std::env::var_os("SYQ_TEST_DISABLE_SMALL_COPY").is_some() {
        return false;
    }
    args.interface == Interface::NativeCp
        && !args.tuning_options.unwrap_or_default().force_ranges()
        && !args.tuning_options.unwrap_or_default().batch_override()
        && matches!(args.placement, Placement::Into | Placement::As)
        && args.target_existence == Existence::Any
        && dst.is_remote()
        && dst_ep.is_remote()
        && !src_ep.is_remote()
        && !srcs.iter().any(Location::is_remote)
        && args.restricted_grant.is_none()
        && !args.dry_run
        && !args.verify_only
        && !args.inplace
        && !args.delete
        && !args.update
        && !args.checksum
        && !args.ignore_existing
        && !args.existing
        && !args.stats
        && args.files_from.is_none()
        && args.native_mapping.is_none()
        && args.ignore_lines.is_empty()
        && args.bwlimit_bytes == 0
        && args.max_size.is_none()
        && args.min_size.is_none()
        && !args.follows_native_destination_paths()
        && !srcs.is_empty()
        && srcs.len() <= SMALL_COPY_MAX_FILES
        && srcs.iter().all(|source| !source.copies_contents())
        && (args.placement == Placement::Into || srcs.len() == 1)
        && clean_root(&dst.path) != b"~"
}

/// Push small regular files in one control-connection turn. Sources
/// are read through the same registered references the engine's workers
/// use; the receiver selects, anchors, checks, stages, and publishes in one
/// request. Every result record and the summary come from the same counters
/// the engine settles from.
#[allow(clippy::too_many_arguments)]
fn attempt_small_copy(
    args: &Args,
    opts: &Opts,
    srcs: &[Location],
    dst: &Location,
    src_ep: &Endpoint,
    dst_ep: &Endpoint,
    src_ctl: &mut dyn Conn,
    dst_ctl: &mut dyn Conn,
    roots: &[RegisteredSourceRoot],
    progress: &Progress,
    t0: std::time::Instant,
) -> Result<SmallCopy> {
    // A source named like a syq sidecar gets the engine's warning.
    if srcs
        .iter()
        .any(|source| is_partial_name(OsStr::from_bytes(&source.basename())))
    {
        return Ok(SmallCopy::Declined);
    }
    let follow = args.follows_native_source_paths();
    let mut entries = Vec::with_capacity(srcs.len());
    let mut total = 0u64;
    for (source, root) in srcs.iter().zip(roots) {
        // A missing or unusable source is the engine's to report.
        let Ok(Some(entry)) = stat_one_registered(
            src_ctl,
            &source.path,
            &root.selection,
            source.follows_root(follow),
        ) else {
            return Ok(SmallCopy::Declined);
        };
        if entry.kind != Kind::File
            || validate_native_source_type(&source.path, source.selection, entry.kind).is_err()
            || entry.size > SMALL_COPY_MAX_FILE_BYTES
        {
            return Ok(SmallCopy::Declined);
        }
        total += entry.size;
        if total > SMALL_COPY_MAX_TOTAL_BYTES {
            return Ok(SmallCopy::Declined);
        }
        entries.push(entry);
    }

    // Destination spellings exactly as the planner produces them.
    let operator_dst_root = clean_root(&dst.path);
    let (directory, dst_leaf) = match args.placement {
        Placement::Into => (operator_dst_root.clone(), None),
        Placement::As => {
            let Some(leaf) = operator_dst_root
                .rsplit(|byte| *byte == b'/')
                .next()
                .filter(|component| !component.is_empty())
            else {
                return Ok(SmallCopy::Declined);
            };
            (parent_path(&operator_dst_root), Some(leaf.to_vec()))
        }
        Placement::Rsync => return Ok(SmallCopy::Declined),
    };
    let request_prefix = directory.clone();
    let mut targets: Vec<(PathBytes, PathBytes, String)> = Vec::with_capacity(srcs.len());
    for source in srcs {
        let (dst_path, rel_bytes) = if args.placement == Placement::Into {
            let name = source.basename();
            (join(&operator_dst_root, &name), name)
        } else {
            (
                join(
                    &directory,
                    dst_leaf.as_ref().expect("exact destination leaf"),
                ),
                Vec::new(),
            )
        };
        if targets.iter().any(|(existing, _, _)| *existing == dst_path) {
            return Ok(SmallCopy::Declined);
        }
        let rel = display(&source.basename());
        targets.push((dst_path, rel_bytes, rel));
    }

    // Read through the engine's source-worker path.
    let Ok(mut reader) = src_ep.connect_with_sources(args.compress, roots.to_vec(), true) else {
        return Ok(SmallCopy::Declined);
    };
    let reads: Vec<SmallRead> = srcs
        .iter()
        .zip(roots)
        .zip(&entries)
        .filter(|(_, entry)| entry.size > 0)
        .map(|((source, root), entry)| SmallRead {
            path: source.path.clone(),
            source: Some(root.selection.clone()),
            attempt: 0,
            len: entry.size as u32,
        })
        .collect();
    configure_hashing(&mut *reader, opts.hash_policy)?;
    let native_actor = progress
        .observations
        .enabled
        .load(Relaxed)
        .then(|| progress.observations.workers.actor("worker"));
    if let Some(actor) = &native_actor {
        if reader
            .observe(&progress.observations, actor, true, 0)
            .is_err()
        {
            return Ok(SmallCopy::Declined);
        }
        if dst_ctl
            .observe(&progress.observations, actor, false, 0)
            .is_err()
        {
            // Nothing has been copied yet. Reopen the control connection before
            // entering the ordinary transfer path; never use lost framing.
            return Ok(SmallCopy::Reconnect);
        }
    }
    let _native_work = native_actor
        .as_ref()
        .map(|a| a.span(crate::transfer_observations::Stage::Work));
    let copying = progress.copying_interval();
    let mut blocks = if reads.is_empty() {
        Vec::new()
    } else {
        let count = reads.len();
        reader.send(Request::ReadSmallBatch(reads))?;
        match ok(reader.recv()?, "read small batch")? {
            Response::SmallBlocks(blocks) if blocks.len() == count => blocks,
            other => bail!("unexpected response {other:?}"),
        }
    }
    .into_iter();
    let flags = publication_metadata_flags(opts.flags);
    let mut files = Vec::with_capacity(srcs.len());
    for (entry, (dst_path, _, _)) in entries.iter().zip(&targets) {
        let (data, hash) = if entry.size == 0 {
            (Vec::new(), opts.hash_policy.payload_algorithm().hash(&[]))
        } else {
            match blocks.next() {
                Some(Ok(block)) if block.data.len() as u64 == entry.size => {
                    (block.data, block.hash)
                }
                // A read failure or a changed size is the engine's to
                // report or retry.
                _ => return Ok(SmallCopy::Declined),
            }
        };
        let mut meta = entry.meta();
        meta.mode = fresh_file_mode(opts, entry);
        files.push(SmallCopyFile {
            path: dst_path.clone(),
            data,
            hash,
            meta,
        });
    }

    let request = SmallCopyRequest {
        directory,
        symlink_policy: opts.operator_symlink_policy,
        request_prefix,
        identity: SmallCopyIdentity {
            copy_id: opts.copy_id,
            dst_leaf,
        },
        flags,
        files,
    };
    if debug() {
        crate::output::diagnostic!(
            "syq: small copy: sending {} files ({} bytes) in one turn at {:.2}s",
            srcs.len(),
            total,
            t0.elapsed().as_secs_f64()
        );
    }
    let results = match dst_ctl.call(Request::CopySmallFiles(request))? {
        Response::SmallFilesCopied(SmallCopyResponse {
            outcome: SmallCopyOutcome::Published(results),
            ..
        }) if results.len() == srcs.len() => results,
        Response::SmallFilesCopied(SmallCopyResponse {
            outcome: SmallCopyOutcome::UnsupportedTarget,
            ..
        }) => {
            if debug() {
                crate::output::diagnostic!(
                    "syq: small copy: a destination is not a regular file; using the ordinary engine"
                );
            }
            return Ok(SmallCopy::Declined);
        }
        Response::SmallFilesCopied(SmallCopyResponse {
            outcome: SmallCopyOutcome::CapacityShort,
            ..
        }) => {
            if debug() {
                crate::output::diagnostic!(
                    "syq: small copy: capacity preflight would refuse; using the ordinary engine"
                );
            }
            return Ok(SmallCopy::Declined);
        }
        Response::SmallFilesCopied(SmallCopyResponse {
            outcome: SmallCopyOutcome::StagingFailed(error),
            ..
        }) => {
            if debug() {
                crate::output::diagnostic!(
                    "syq: small copy: staging failed ({}); using the ordinary engine on a new control connection",
                    error.message
                );
            }
            return Ok(SmallCopy::Reconnect);
        }
        Response::SmallFilesCopied(_) => bail!("small copy returned a mismatched result count"),
        // The receiver could not select the directory; the engine's own
        // preflight reproduces and reports that condition.
        Response::Err(error) => {
            if debug() {
                crate::output::diagnostic!("syq: small copy declined: {error}");
            }
            return Ok(SmallCopy::Declined);
        }
        Response::EndpointError(error) => {
            if debug() {
                crate::output::diagnostic!("syq: small copy declined: {}", error.message);
            }
            return Ok(SmallCopy::Declined);
        }
        other => bail!("unexpected response {other:?}"),
    };
    if debug() {
        crate::output::diagnostic!(
            "syq: small copy: published at {:.2}s",
            t0.elapsed().as_secs_f64()
        );
    }
    announce_detached_ready()?;
    print_small_copy_diagnostics(args, dst_ep);

    // The engine's quick check is a planning-time decision, including
    // metadata-only repairs. Recheck only files whose content was copied or
    // compared, not those already skipped on size/mtime.
    let check_source: Vec<usize> = results
        .iter()
        .enumerate()
        .filter_map(|(i, result)| {
            (result.disposition != SmallCopyDisposition::QuickChecked).then_some(i)
        })
        .collect();
    let mut now = if check_source.is_empty() {
        Vec::new()
    } else {
        stat_many_registered(
            src_ctl,
            check_source.iter().map(|&i| srcs[i].path.clone()).collect(),
            Some(
                check_source
                    .iter()
                    .map(|&i| roots[i].selection.clone())
                    .collect(),
            ),
            false,
        )?
    }
    .into_iter();
    for ((entry, (_, rel_bytes, rel)), result) in entries.iter().zip(&targets).zip(results) {
        if result.disposition == SmallCopyDisposition::QuickChecked {
            progress.files_unchanged.fetch_add(1, Relaxed);
            progress.bytes_unchanged.fetch_add(entry.size, Relaxed);
            if let Some(error) = result.error {
                progress.error(&format!("syq: {}", endpoint_error(error)));
            }
            continue;
        }
        let now = now.next().expect("one stat per checked source");
        let source_changed = now.as_ref().is_none_or(|e| {
            e.kind != Kind::File
                || e.size != entry.size
                || e.mtime != entry.mtime
                || e.mtime_nsec != entry.mtime_nsec
        });
        if result.disposition == SmallCopyDisposition::ContentMatched && !source_changed {
            progress.files_unchanged.fetch_add(1, Relaxed);
            progress.bytes_unchanged.fetch_add(entry.size, Relaxed);
            if let Some(error) = result.error {
                progress.error(&format!("syq: {}", endpoint_error(error)));
            }
            continue;
        }
        progress.files_total.fetch_add(1, Relaxed);
        progress.bytes_total.fetch_add(entry.size, Relaxed);
        let failure = match result.error {
            Some(error) => {
                let error = endpoint_error(error).context("put");
                Some(("unknown", os_kind_of(&error), format!("{error:#}")))
            }
            None => source_changed.then(|| {
                (
                    "yes",
                    None,
                    "source changed during transfer (or vanished)".to_string(),
                )
            }),
        };
        if let Some((retryable, os_kind, message)) = failure {
            progress.error_classified(&format!("syq: {rel}: {message}"), Some("io"), os_kind);
            if let Some(results) = progress.results_writer() {
                results.emit_operation(&crate::results::OperationRecord {
                    action: "transfer_file",
                    dst: rel_bytes,
                    src: None,
                    kind: "file",
                    disposition: "failed",
                    bytes: None,
                    attempts: Some(1),
                    retryable: Some(retryable),
                    class: Some("io"),
                    os_kind,
                    message: Some(&message),
                });
            }
            continue;
        }
        progress.add_bytes(entry.size);
        progress.add_files(1);
        if let Some(results) = progress.results_writer() {
            results.emit_operation(&crate::results::OperationRecord {
                action: "transfer_file",
                dst: rel_bytes,
                src: None,
                kind: "file",
                disposition: "succeeded",
                bytes: Some(entry.size),
                attempts: Some(1),
                retryable: None,
                class: None,
                os_kind: None,
                message: None,
            });
        }
        if opts.verbose > 0 {
            progress.println(rel);
        }
    }

    progress.stop();
    progress.clear();
    let errors = progress.errors.load(Relaxed);
    let (status, exit_code) = if errors > 0 {
        ("partial", 23)
    } else {
        ("success", 0)
    };
    drop(copying);
    let terminal = crate::results::ResultRecord {
        status,
        exit_code,
        dry_run: false,
        files_transferred: progress.files_done.load(Relaxed),
        files_unchanged: progress.files_unchanged.load(Relaxed),
        files_excluded: 0,
        directories_created: 0,
        symlinks_created: 0,
        specials_created: 0,
        errors,
        bytes_transferred: progress.bytes_done.load(Relaxed),
        bytes_unchanged: progress.bytes_unchanged.load(Relaxed),
        copying_elapsed_ms: progress.copying_elapsed_ms(),
        elapsed_ms: progress.start.elapsed().as_millis() as u64,
        deletions_planned: None,
        deletions_completed: None,
        deletions_blocked: None,
    };
    if progress.observations.enabled.load(Relaxed) {
        reader.transport_stats();
        dst_ctl.transport_stats();
    }
    drop(_native_work);
    progress.finish(exit_code == 0);
    if !args.quiet && !args.suppress_summary {
        print_transfer_summary(&terminal, progress.start.elapsed().as_secs_f64(), "");
    }
    if let Some(results) = progress.results_writer() {
        results.emit_result(&terminal);
    }
    Ok(SmallCopy::Done(exit_code))
}

fn show_statistics(args: &Args) -> bool {
    // Restricted coordinators suppress their outcome summary because the
    // invoking machine prints the verified receipt. That receipt does not
    // contain diagnostics, so requested statistics still come from here.
    !args.suppress_summary || args.restricted_grant.is_some()
}

/// The one summary line a completed copy prints, rendered from the same
/// record the results stream settles with.
fn print_transfer_summary(terminal: &crate::results::ResultRecord, elapsed: f64, deletions: &str) {
    crate::output::human_stdout!(
        "syq: transferred {} files ({}), {} unchanged ({} files), {} dirs created{}{}{}",
        commas(terminal.files_transferred),
        human(terminal.bytes_transferred),
        human(terminal.bytes_unchanged),
        commas(terminal.files_unchanged),
        commas(terminal.directories_created),
        deletions,
        format_args!(
            ", {} at {}/s",
            crate::progress::hms(elapsed),
            human((terminal.bytes_transferred as f64 / elapsed.max(0.001)) as u64)
        ),
        if terminal.errors > 0 {
            format!(", {} errors", terminal.errors)
        } else {
            String::new()
        }
    );
}

#[derive(Clone, Debug)]
struct DestinationAnchor {
    destination: RegisteredDestinationRoot,
    dev: u64,
    ino: u64,
}
type DestinationAnchorSlot = std::sync::Arc<std::sync::OnceLock<DestinationAnchor>>;
type SourceRootsSlot = std::sync::Arc<std::sync::OnceLock<Vec<RegisteredSourceRoot>>>;

fn handle_tcp_setup_error(
    args: &Args,
    spec: &RemoteSpec,
    ports: (u16, u16),
    error: anyhow::Error,
    sched: &Sched,
    progress: &Progress,
) -> Result<()> {
    #[cfg(debug_assertions)]
    if std::env::var_os("SYQ_TEST_REQUIRE_TCP").is_some() {
        sched.abort();
        progress.stop();
        return Err(error).context("TCP data transport required by test");
    }
    if crate::conn::is_tcp_congestion_error(&error) {
        sched.abort();
        progress.stop();
        return Err(error).with_context(|| {
            format!(
                "{} could not apply {} {}",
                spec.label(),
                interface_option(args, "--tcp-congestion", "--syq-tcp-congestion"),
                args.tcp_congestion.as_deref().unwrap_or_default()
            )
        });
    }
    if spec.forwarded.is_some() {
        sched.abort();
        progress.stop();
        return Err(error).with_context(|| {
            let reason = "return authorization requires direct encrypted TCP data connections";
            format!("{}: {reason}", spec.label())
        });
    }
    if !args.quiet || debug() {
        let congestion_note =
            crate::conn::tcp_congestion_fallback_note(args.tcp_congestion.as_deref());
        if args.verbose >= 2 || debug() {
            crate::output::diagnostic!(
                "syq: {}: data over ssh (TCP ports {}-{} not reachable: {error:#}{congestion_note})",
                spec.label(),
                ports.0,
                ports.1
            );
        } else {
            crate::output::diagnostic!("syq: {}: data over ssh{congestion_note}", spec.label());
        }
    }
    Ok(())
}

fn announce_detached_ready() -> Result<()> {
    let Some(path) = std::env::var_os("SYQ_INTERNAL_DETACH_READY") else {
        return Ok(());
    };
    let path = std::path::PathBuf::from(path);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .with_context(|| format!("create detached-readiness marker {}", path.display()))?;
    use std::io::Write as _;
    file.write_all(b"ready\n")?;
    Ok(())
}

pub fn run(mut args: Args) -> Result<i32> {
    // Re-exec before consuming stdin or opening results. A failed handoff still
    // settles the normal automation stream below.
    let handoff = crate::destination::handoff::copy(&mut args);
    if handoff.is_ok() {
        // Finish input validation in the executing build, before opening results.
        // Preserve the argument-error exit status and absence of an automation
        // stream when reading an input fails.
        if let Err(error) = args.read_copy_inputs() {
            crate::output::diagnostic!("syq: {error:#}");
            return Ok(2);
        }
    }
    // Create results and progress before reporting any setup failure, so a
    // failure in this process settles with a terminal record (spec: automation
    // results). A successful exec hands that responsibility to the helper.
    let show_progress = !args.no_progress && !args.quiet && !args.dry_run;
    let progress = Progress::new(
        show_progress,
        args.progress,
        args.width,
        !args.quiet && args.progress_json,
    );
    if args.stats || debug() {
        progress
            .observations
            .human_summary
            .store(show_statistics(&args), Relaxed);
        progress.observations.enable();
    }
    // The detach and remote-coordinator combinations were refused at
    // argument parsing (exit 2, no stream); every request that reaches this
    // point settles with a terminal record.
    if let Some(writer) = crate::results::start(
        &args,
        crate::results::RunMode::Cp {
            prune: args.delete,
            mapping: args.native_mapping.is_some(),
        },
    )? {
        progress.set_results(writer);
    }
    let dry_run = args.dry_run;
    let verify_only = args.verify_only;
    let prune = args.delete;
    let outcome = handoff.and_then(|()| run_transfer(args, Arc::clone(&progress)));
    if outcome.is_err() {
        // run_transfer's ticker guard has stopped and joined on every return,
        // including failures in deferred metadata and deletion finalization.
        progress.stop();
        progress.finish(false);
        // The error text reaches stderr via main; the stream still gets its
        // terminal record so a consumer never mistakes a handled fatal for a
        // crash (only a real crash leaves the terminal record missing).
        if let Some(results) = progress.results_writer() {
            results.emit_result(&crate::results::ResultRecord {
                status: "failed",
                exit_code: 1,
                dry_run,
                files_transferred: if verify_only {
                    0
                } else {
                    progress.files_done.load(Relaxed)
                },
                files_unchanged: progress.files_unchanged.load(Relaxed),
                files_excluded: progress.files_excluded.load(Relaxed),
                // Mutations that settled (and streamed their records)
                // before the run died must not vanish from the aggregates.
                directories_created: progress.directories_created.load(Relaxed),
                symlinks_created: progress.symlinks_created.load(Relaxed),
                specials_created: progress.specials_created.load(Relaxed),
                errors: progress.errors.load(Relaxed),
                bytes_transferred: if verify_only {
                    0
                } else {
                    progress.bytes_done.load(Relaxed)
                },
                bytes_unchanged: progress.bytes_unchanged.load(Relaxed),
                copying_elapsed_ms: if verify_only || dry_run {
                    None
                } else {
                    progress.copying_elapsed_ms()
                },
                elapsed_ms: progress.start.elapsed().as_millis() as u64,
                // What the deletion pass did before the run died; zeros
                // mean it never got that far, and status "failed" already
                // marks every aggregate here as pre-failure state.
                deletions_planned: prune.then(|| progress.deletions_planned.load(Relaxed)),
                deletions_completed: prune.then(|| progress.deletions_completed.load(Relaxed)),
                deletions_blocked: prune.then(|| progress.deletions_blocked.load(Relaxed)),
            });
        }
    }
    outcome
}

pub(crate) fn uses_remote_coordinator(args: &Args, sources: &[Location], dst: &Location) -> bool {
    let Some(source) = sources.first() else {
        return false;
    };
    source.is_remote()
        && dst.is_remote()
        && !args.relay
        && (args.interface == Interface::Rsync || args.coordinate_at != CoordinateAt::Local)
}

fn os_kind_of(error: &anyhow::Error) -> Option<&'static str> {
    if let Some(error) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<WireError>())
    {
        return wire_os_kind(error);
    }
    let io = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<std::io::Error>())?;
    Some(match io.kind() {
        std::io::ErrorKind::NotFound => "not_found",
        std::io::ErrorKind::PermissionDenied => "permission_denied",
        std::io::ErrorKind::AlreadyExists => "already_exists",
        std::io::ErrorKind::InvalidInput => "invalid_input",
        _ => match io.raw_os_error() {
            Some(libc::ENOSPC) => "no_space",
            Some(libc::EDQUOT) => "quota_exceeded",
            Some(libc::EROFS) => "read_only",
            _ => "other",
        },
    })
}

fn wire_os_kind(error: &WireError) -> Option<&'static str> {
    Some(match error.io_kind? {
        WireIoKind::NotFound => "not_found",
        WireIoKind::PermissionDenied => "permission_denied",
        WireIoKind::AlreadyExists => "already_exists",
        WireIoKind::InvalidInput => "invalid_input",
        WireIoKind::NoSpace => "no_space",
        WireIoKind::QuotaExceeded => "quota_exceeded",
        WireIoKind::ReadOnly => "read_only",
        WireIoKind::Other => "other",
    })
}

fn capacity_os_kind(kind: Option<&str>) -> bool {
    matches!(kind, Some("no_space" | "quota_exceeded"))
}

fn first_capacity_error(errors: &[Option<WireError>]) -> Option<WireError> {
    errors
        .iter()
        .flatten()
        .find(|error| capacity_os_kind(wire_os_kind(error)))
        .cloned()
}

fn run_transfer(args: Args, progress: Arc<Progress>) -> Result<i32> {
    // Post-parse validation lives inside the wrapper's error coverage, so
    // its failures still settle the stream with a failed terminal record.
    let mut args = args;
    // The executing build consumes stdin once, then shares immutable bytes with
    // authorization and remote coordination. Neither may reopen the manifest.
    let mapping_entries = if let Some(mapping) = args.native_mapping.as_deref() {
        if args.detach {
            bail!("--mapping requires an attached copy");
        }
        let mut contents = Vec::new();
        if mapping == b"-" {
            std::io::stdin()
                .read_to_end(&mut contents)
                .context("--mapping -: read stdin")?;
        } else {
            crate::fsops::open_operator_file_read(mapping, control_operator_symlink_policy(&args))
                .and_then(|mut input| input.read_to_end(&mut contents).map_err(Into::into))
                .with_context(|| format!("--mapping {}", display(mapping)))?;
        }
        let parsed = read_mapping_manifest(contents)?;
        args.mapping_contents = Some(Arc::new(parsed.input));
        Some((parsed.entries, parsed.explicit_parents))
    } else {
        None
    };
    // Authorization failures settle the already-open automation stream too.
    if args.interface == Interface::NativeCp {
        crate::destination::prepare(&mut args)?;
    }
    let block = args.block_size;
    args.tuning_options
        .unwrap_or_default()
        .validate(args.bwlimit_bytes)?;
    let max_size = args.max_size.as_deref().map(parse_size).transpose()?;
    let min_size = args.min_size.as_deref().map(parse_size).transpose()?;
    let bwlimit = (args.bwlimit_bytes > 0)
        .then_some(args.bwlimit_bytes)
        .map(BandwidthLimit::new)
        .map(Arc::new);
    let native_locations = !args.locations.is_empty();
    let locs: Vec<Location> = if !native_locations {
        args.paths
            .iter()
            .map(|p| Location::parse(p))
            .collect::<Result<_>>()?
    } else {
        args.locations.clone()
    };
    if locs.len() < 2 {
        bail!("need at least one source and a destination");
    }
    let raw_source_operands = args
        .paths
        .split_last()
        .map(|(_, sources)| sources)
        .unwrap_or(&[]);
    let (dst, original_srcs) = locs.split_last().unwrap();
    if args.interface == Interface::Rsync && original_srcs[0].is_remote() && dst.is_remote() {
        bail!("syq rsync does not support remote-to-remote transfers");
    }
    let coordinator_is_remote = uses_remote_coordinator(&args, original_srcs, dst);
    let direct_remote_to_remote = original_srcs[0].is_remote()
        && dst.is_remote()
        && !original_srcs[0].same_host(dst)
        && !args.relay
        && args.coordinate_at != CoordinateAt::Local;
    if (args.detach || args.peer_auth != crate::cli::PeerAuth::Restricted)
        && !direct_remote_to_remote
    {
        bail!(
            "--detach and --peer-auth apply only to a direct copy between two different remote endpoints"
        );
    }
    if args.pscope_explicit && coordinator_is_remote {
        bail!(
            "--pscope is not supported with a remote transfer coordinator; use --coordinate-at local to keep the reusable connections on this machine"
        );
    }
    if args.restricted_grant.is_some()
        && (args.tcp_plain || original_srcs[0].is_remote() || !dst.is_remote())
    {
        bail!(
            "a signed receiver grant is valid only for a local-to-remote coordinator using encrypted data connections"
        );
    }
    for source in original_srcs {
        if !source.same_host(&original_srcs[0]) {
            bail!("all sources must be on the same host");
        }
    }
    let source_operand_count = if native_locations {
        original_srcs.len()
    } else {
        raw_source_operands.len()
    };
    if args.files_from.is_some() && source_operand_count > 1 {
        bail!("--files-from takes exactly one source directory");
    }
    // Rsync's file-list cleanup collapses an exactly repeated source. Key that
    // decision on the raw operands, before parsing has normalized spellings,
    // while retaining original multiplicity for destination placement:
    // `file file new-dest` still creates a directory like other multi-source
    // commands.
    let multiple_source_operands = source_operand_count > 1;
    let srcs: Vec<Location> = if native_locations {
        let mut seen_sources = std::collections::HashSet::new();
        original_srcs
            .iter()
            .filter(|source| seen_sources.insert((source.path.clone(), source.selection)))
            .cloned()
            .collect()
    } else {
        let mut seen_sources = std::collections::HashSet::new();
        raw_source_operands
            .iter()
            .zip(original_srcs)
            .filter(|(raw, _)| seen_sources.insert(raw.as_str()))
            .map(|(_, source)| source.clone())
            .collect()
    };
    let srcs = srcs.as_slice();
    let multiple_distinct_sources = srcs.len() > 1;
    // Reject up front when two sources would land on the same destination name
    // (e.g. a/same and b/same into dest/) — before any bytes are written.
    {
        let mut seen = std::collections::HashSet::new();
        for s in srcs {
            if !s.copies_contents() {
                let base = s.basename();
                if !base.is_empty() && !seen.insert(base.clone()) {
                    bail!(
                        "two sources named {:?} map to the same destination; rename one or copy them separately",
                        display(&base)
                    );
                }
            }
        }
    }
    // A remote coordinator owns both SSH edges. Hand off before constructing
    // local endpoints so the invoking machine neither reads its persistence
    // policy nor creates records for connections it will never open.
    if coordinator_is_remote {
        // The remote coordinator parses its own immutable input. Release this
        // process's preflight entries before waiting for the remote copy.
        drop(mapping_entries);
        if args.rsh.is_some() {
            let rsh = parse_rsh(&args.rsh)?;
            if !rsh[0].ends_with("ssh")
                && srcs
                    .iter()
                    .chain(std::iter::once(dst))
                    .any(|location| location.port.is_some())
            {
                bail!(
                    "an explicit endpoint SSH port requires the default ssh or an --rsh command whose executable is ssh"
                );
            }
        }
        if args.connections_default {
            args.connections = tune::START_SSH.min(args.automatic_worker_limit());
        }
        if args.interface != Interface::Rsync && args.coordinate_at == CoordinateAt::Dst {
            return crate::remote_to_remote::coordinate_at_dst(
                &args,
                srcs,
                dst,
                progress.results_writer().cloned(),
            );
        }
        return crate::remote_to_remote::run(&args, srcs, dst, progress.results_writer().cloned());
    }
    if srcs[0].is_remote() && dst.is_remote() {
        if args.interface != Interface::Rsync && args.coordinate_at == CoordinateAt::Local {
            args.relay = true;
        }
        // Delegated operands are base64 in the remote argv, so every
        // non-relay remote-to-remote copy took the direct return above; the
        // only way here is the operator's explicit --coordinate-at local.
        debug_assert!(args.relay);
        if !args.quiet {
            crate::output::diagnostic!(
                "syq: remote-to-remote transfer: relaying data through this machine"
            );
        }
    } else if args.interface != Interface::Rsync && args.coordinate_at != CoordinateAt::Auto {
        bail!("--coordinate-at currently applies only to copies between two remote endpoints");
    }
    let src_ep = endpoint(&srcs[0], &args)?;
    let mut dst_ep = endpoint(dst, &args)?;
    if args.tcp_congestion.is_some() && !src_ep.is_remote() && !dst_ep.is_remote() {
        bail!(
            "{} applies only to copies with a remote endpoint",
            interface_option(&args, "--tcp-congestion", "--syq-tcp-congestion")
        );
    }
    // Every destination worker runs in a receiver process. On Darwin this
    // also keeps foreign descriptor claims out of the spawning coordinator;
    // the receiver itself has no child-process launch paths on that platform.
    if matches!(dst_ep, Endpoint::Local { .. }) {
        let mut receiver = RemoteSpec::local_receiver(args.quiet);
        receiver.read_ahead = args.tuning_options.unwrap_or_default().pipeline_depth();
        dst_ep = Endpoint::Remote(receiver);
    }
    // TCP data connections are the default (auto-selecting the fastest reachable
    // NIC and falling back to ssh if unreachable); the interface's no-TCP
    // option forces SSH data.
    // A local receiver uses one child process and a loopback data listener so
    // every worker shares its retained destination cwd without changing the
    // coordinator process's cwd.
    let use_tcp = !args.no_tcp && (src_ep.has_data_server() || dst_ep.has_data_server());
    // Without -j the worker count is tuned while the transfer runs (see tune.rs);
    // start conservatively until TCP reachability has been established below.
    let autotune = args.connections_default;
    if autotune {
        args.connections = if src_ep.is_remote() || dst_ep.is_remote() {
            tune::START_SSH
        } else {
            tune::start_local()
        }
        .min(args.automatic_worker_limit());
    }
    #[cfg(not(target_os = "linux"))]
    if let Some(algorithm) = &args.tcp_congestion {
        bail!(
            "{} {algorithm} requires a Linux transfer coordinator and Linux remote endpoints",
            interface_option(&args, "--tcp-congestion", "--syq-tcp-congestion")
        );
    }

    let mut opts = Opts {
        local_copy_fd_budget: true,
        hash_policy: crate::hashing::HashPolicy {
            algorithm: args.hash_algorithm,
            transfer_integrity: args.transfer_integrity,
            transfer_hash_type: args.transfer_hash_type,
        },
        mapping_expected_hashes: mapping_entries
            .as_ref()
            .map(|(entries, _)| {
                entries
                    .iter()
                    .filter_map(|(_, entry)| {
                        entry
                            .expected_hash
                            .clone()
                            .map(|digest| (entry.dst.clone(), digest))
                    })
                    .collect()
            })
            .unwrap_or_default(),
        block,
        tuning: args.tuning_options.unwrap_or_default(),
        benchmark: ((args.tuning_options.is_some() || debug())
            && !args.quiet
            && (args.stats || args.verbose > 0 || debug()))
        .then(|| Mutex::new(crate::transfer_tuning::BenchmarkStats::default())),
        flags: args.meta_flags(),
        recursive: args.recursive,
        links: args.links,
        perms: args.perms,
        devices: args.devices,
        checksum: args.checksum,
        precise_mtime: !matches!(args.placement, Placement::Rsync),
        verify_only: args.verify_only,
        inplace: args.inplace,
        same_host: !src_ep.is_remote() && !dst_ep.is_remote(),
        allow_sequential_nfs_fallback: args.connections_default || args.connections == 1,
        dst_remote: dst_ep.is_remote(),
        restricted_receiver: args.restricted_grant.is_some(),
        dry_run: args.dry_run,
        dry_run_metadata_files: AtomicU64::new(0),
        quiet: args.quiet,
        verbose: if args.quiet { 0 } else { args.verbose },
        umask: crate::fsops::process_umask(),
        copy_id: crate::resume::fresh_copy_id()?,
        ignore: args.ignore_lines.clone(),
        delete: args.delete,
        delete_excluded: args.delete_excluded,
        max_delete: args.max_delete,
        update: args.update,
        ignore_existing: args.ignore_existing,
        preserve_existing_directory_metadata: args.only_new_native_entries(),
        existing: args.existing,
        operator_symlink_policy: destination_operator_symlink_policy(&args, !dst_ep.is_remote()),
        max_size,
        min_size,
    };
    if opts.benchmark.is_some() {
        crate::output::diagnostic!(
            "syq: tuning: request-size={} bytes (ordinary, after pacing and receiver limits), streaming-block-size={} bytes, pipeline-depth={}, hash-block-size={} bytes, copy-path={}, batch-files={}, batch-bytes={}, split-min-size={}, bw-pacing={}",
            opts.tuning.request_size(block, bwlimit.as_deref(), opts.restricted_receiver),
            opts.tuning.streaming_request_size(block, bwlimit.as_deref(), opts.restricted_receiver),
            opts.tuning.pipeline_label(opts.same_host, opts.tuning.request_size(block, bwlimit.as_deref(), opts.restricted_receiver)), block,
            opts.tuning.copy_path.unwrap_or_default(),
            opts.tuning.batch_files.unwrap_or(FAST_BATCH_FILES),
            opts.tuning.batch_bytes(), opts.tuning.split_min_size(block),
            if bwlimit.is_some() { opts.tuning.bw_pacing.unwrap_or_default().to_string() } else { "disabled".into() }
        );
    }
    let mapping_contents = args.mapping_contents.clone();
    let t0 = std::time::Instant::now();
    // Pooled sessions are received as descriptors; take them on this thread
    // before the parallel connect can spawn a child beside the receipt.
    for endpoint in [&src_ep, &dst_ep] {
        if let Endpoint::Remote(spec) = endpoint {
            spec.prime_pooled_control(args.compress);
        }
    }
    let (mut src_ctl, mut dst_ctl) = {
        let (a, b) = (src_ep.clone(), args.clone());
        let t = std::thread::spawn(move || connect_ctl(&a, &b));
        let dst_ctl = connect_ctl(&dst_ep, &args);
        let src_ctl = t
            .join()
            .map_err(|_| anyhow::anyhow!("connect thread panicked"))?;
        match (src_ctl, dst_ctl) {
            (Ok(a), Ok(b)) => (a, b),
            (Err(e), _) | (_, Err(e)) => {
                progress.stop();
                return Err(e);
            }
        }
    };
    if debug() {
        crate::output::diagnostic!(
            "syq: control connections up in {:.2}s",
            t0.elapsed().as_secs_f64()
        );
    }
    if args.restricted_grant.is_some() {
        if let Some(contents) = &mapping_contents {
            crate::mapping::send(&contents.contents, &mut *dst_ctl)?;
        }
    }
    let destination_supports_confined_socket_nodes = match &dst_ep {
        Endpoint::Remote(spec) => {
            spec.diagnostics()
                .peer
                .context("destination handshake did not report receiver capabilities")?
                .supports_confined_socket_nodes
        }
        Endpoint::Local { .. } => crate::identity::supports_confined_socket_nodes(),
    };
    let maximum_workers = if autotune {
        args.automatic_worker_limit()
    } else {
        args.connections
    };
    // Descriptor preflight is an estimate, not a reservation. For automatic
    // copies check the source roots and control session, not every worker the
    // tuner might someday try. Fixed counts retain their up-front estimate.
    let budgeted_workers = if autotune { 0 } else { args.connections };
    let source_shared_workers = match &src_ep {
        Endpoint::Local { .. } => budgeted_workers,
        Endpoint::Remote(_) if use_tcp => budgeted_workers,
        Endpoint::Remote(_) => 0,
    };
    // Only workers that can attempt local offload need foreign source claims.
    // Actual local destinations live in a separate receiver process.
    let mut copy_local_claim_workers = if opts.copy_policy(bwlimit.is_some()).allows_receiver_copy()
    {
        budgeted_workers
    } else {
        0
    };
    // macOS cloning is optional. Its source is in this process, so use the
    // same admission check as registration before reserving foreign claims.
    // If those claims do not fit, keep the normal worker budget and byte-copy
    // path on every filesystem, including APFS. Registration still rejects
    // a budget that cannot accommodate the ordinary copy itself.
    if cfg!(target_os = "macos")
        && copy_local_claim_workers > 0
        && crate::fsops::require_source_descriptor_capacity(
            srcs.len(),
            source_shared_workers,
            copy_local_claim_workers,
        )
        .is_err()
    {
        opts.local_copy_fd_budget = false;
        copy_local_claim_workers = 0;
        if debug() {
            crate::output::diagnostic!(
                "syq: macOS cloning disabled: source descriptor budget leaves no room for clone claims"
            );
        }
    }
    let source_independent_handoff_workers = copy_local_claim_workers
        .checked_add(match &src_ep {
            Endpoint::Local { .. } => 0,
            Endpoint::Remote(_) => budgeted_workers.min(crate::conn::MAX_CONCURRENT_CONNECTS),
        })
        .context("source worker count overflow")?;
    // Admission is complete before worker closures receive shared options.
    let opts = Arc::new(opts);
    let sched = Arc::new(Sched::new(block, opts.tuning.split_min_size(block)));

    // Workers connect on their own threads once the control connections are
    // up: everything waits on those, so they must never compete with worker
    // handshakes (at sshd's MaxStartups or a serialized ssh agent). The tuner
    // may spawn more workers later, so the handles live behind a mutex.
    let gate = Gate::new(args.connections);
    let destination_anchor: DestinationAnchorSlot = std::sync::Arc::new(std::sync::OnceLock::new());
    let source_roots: SourceRootsSlot = std::sync::Arc::new(std::sync::OnceLock::new());
    let destination_anchor_required = args.restricted_grant.is_none();
    let workers: Arc<Mutex<Vec<std::thread::JoinHandle<Result<()>>>>> =
        Arc::new(Mutex::new(Vec::new()));
    let connect_after_file_plan = Arc::new(AtomicBool::new(false));
    let transport_stats: Arc<Mutex<Vec<TcpPairStats>>> = Arc::new(Mutex::new(Vec::new()));
    let spawn_worker: Arc<dyn Fn(usize) + Send + Sync> = {
        let (
            src_ep,
            dst_ep,
            sched,
            progress,
            opts,
            gate,
            workers,
            destination_anchor,
            source_roots,
            bwlimit,
            transport_stats,
            connect_after_file_plan,
        ) = (
            src_ep.clone(),
            dst_ep.clone(),
            sched.clone(),
            progress.clone(),
            opts.clone(),
            gate.clone(),
            workers.clone(),
            destination_anchor.clone(),
            source_roots.clone(),
            bwlimit.clone(),
            transport_stats.clone(),
            connect_after_file_plan.clone(),
        );
        let compress = args.compress;
        let collect_tcp_stats = progress.observations.enabled.load(Relaxed);
        Arc::new(move |id: usize| {
            let (
                src_ep,
                dst_ep,
                sched,
                progress,
                opts,
                gate,
                destination_anchor,
                source_roots,
                bwlimit,
                transport_stats,
                connect_after_file_plan,
            ) = (
                src_ep.clone(),
                dst_ep.clone(),
                sched.clone(),
                progress.clone(),
                opts.clone(),
                gate.clone(),
                destination_anchor.clone(),
                source_roots.clone(),
                bwlimit.clone(),
                transport_stats.clone(),
                connect_after_file_plan.clone(),
            );
            let h = std::thread::spawn(move || -> Result<()> {
                if connect_after_file_plan.load(Relaxed) && !sched.wait_for_anticipated_file_work()
                {
                    gate.mark_absent(id);
                    return Ok(());
                }
                let initial_destination = if destination_anchor_required {
                    Some(
                        destination_anchor
                            .get()
                            .context("destination root was not anchored before workers started")?
                            .destination
                            .clone(),
                    )
                } else {
                    None
                };
                let initial_sources = source_roots
                    .get()
                    .context("source roots were not registered before workers started")?
                    .clone();
                let mut failures = 0u32;
                loop {
                    if !gate.retained(id) {
                        gate.mark_absent(id);
                        return Ok(());
                    }
                    let t0 = std::time::Instant::now();
                    // Automatic copies start two channels on the authenticated
                    // SSH transport so file ranges can run in parallel before
                    // the remaining independent connections finish logging in.
                    // TCP and custom remote shells keep their existing policy.
                    let reuse_control = reuse_startup_ssh(id, autotune);
                    let conns = src_ep
                        .connect_with_sources(compress, initial_sources.clone(), reuse_control)
                        .and_then(|src| {
                            let copy_sources =
                                if opts.copy_policy(bwlimit.is_some()).allows_receiver_copy() {
                                    initial_sources.clone()
                                } else {
                                    Vec::new()
                                };
                            Ok((
                                src,
                                dst_ep.connect_with_copy_capabilities(
                                    compress,
                                    initial_destination.clone(),
                                    copy_sources,
                                    reuse_control,
                                )?,
                            ))
                        });
                    let (src, dst) = match conns {
                        Ok(conns) => conns,
                        Err(error)
                            if crate::conn::is_tcp_congestion_error(&error)
                                || crate::conn::is_worker_initialization_error(&error) =>
                        {
                            gate.mark_failed(id);
                            return Err(error);
                        }
                        Err(error) => {
                            failures += 1;
                            if failures >= CONNECTION_RECOVERY_ATTEMPTS {
                                gate.mark_failed(id);
                                return if gate.allowed(id) { Err(error) } else { Ok(()) };
                            }
                            gate.mark_warming(id);
                            if !opts.quiet {
                                crate::output::diagnostic!(
                                    "syq: worker {id}: connection setup failed; retrying in {}s ({error:#})",
                                    1 << (failures - 1)
                                );
                            }
                            std::thread::sleep(std::time::Duration::from_secs(1 << (failures - 1)));
                            continue;
                        }
                    };
                    gate.mark_ready(id);
                    let fast_batch_files = opts.tuning.batch_files.unwrap_or(FAST_BATCH_FILES);
                    let mut worker = Worker {
                        id,
                        src,
                        dst,
                        sched: sched.clone(),
                        progress: progress.clone(),
                        opts: opts.clone(),
                        bwlimit: bwlimit.clone(),
                        gate: gate.clone(),
                        observation: None,
                        benchmark: Default::default(),
                        fast_batch_files,
                        setup_elapsed: t0.elapsed(),
                    };
                    #[cfg(debug_assertions)]
                    crate::fsops::record_test_event(
                        "SYQ_TEST_WORKER_EVENTS",
                        format_args!("connected {id} 0"),
                    )?;
                    if debug() {
                        crate::output::diagnostic!(
                            "syq: worker {id} connected in {:.2}s",
                            t0.elapsed().as_secs_f64()
                        );
                    }
                    let result = worker.run();
                    if let Some(benchmark) = &opts.benchmark {
                        benchmark.lock().unwrap().add(worker.benchmark);
                    }
                    let invalid_range = result
                        .as_ref()
                        .is_err_and(|error| error.is::<RangeReplyMismatch>());
                    if collect_tcp_stats && !invalid_range {
                        let stats = worker.collect_transport_stats();
                        transport_stats.lock().unwrap().extend(stats);
                    }
                    let dropped = result.is_err() && !invalid_range && worker.transport_dead();
                    match result {
                        Ok(()) => {
                            gate.mark_absent(id);
                            return Ok(());
                        }
                        Err(error) if dropped => {
                            failures += 1;
                            if failures >= CONNECTION_RECOVERY_ATTEMPTS {
                                gate.mark_failed(id);
                                return Err(error);
                            }
                            gate.mark_warming(id);
                            if !opts.quiet {
                                crate::output::diagnostic!(
                                    "syq: worker {id}: connection dropped; reopening in {}s ({error:#})",
                                    1 << (failures - 1)
                                );
                            }
                            std::thread::sleep(std::time::Duration::from_secs(1 << (failures - 1)));
                        }
                        Err(error) => {
                            gate.mark_failed(id);
                            return Err(error);
                        }
                    }
                }
            });
            workers.lock().unwrap().push(h);
        })
    };
    let tuner: Mutex<Option<std::thread::JoinHandle<tune::Policy>>> = Mutex::new(None);
    let spawn_workers = |initial: usize| {
        gate.set_active(initial);
        for id in gate.begin_warming(initial) {
            spawn_worker(id);
        }
        if autotune {
            let (gate, sched, progress, spawn_worker) = (
                gate.clone(),
                sched.clone(),
                progress.clone(),
                spawn_worker.clone(),
            );
            let n0 = initial;
            let policy = tune::Policy::new(n0, tune::MIN, maximum_workers);
            *tuner.lock().unwrap() = Some(std::thread::spawn(move || {
                tune::run(policy, gate, sched, progress, |id| spawn_worker(id))
            }));
        }
    };
    let registered_sources = register_source_roots(
        &mut *src_ctl,
        srcs,
        &args,
        source_shared_workers,
        source_independent_handoff_workers,
    )?;
    source_roots
        .set(registered_sources)
        .expect("source roots set once");
    // A native push of a few small local files needs no data worker and no
    // separate preflight: one control-connection turn selects, anchors,
    // checks, and publishes. Source registration above was local, so nothing
    // but the control handshake has crossed the network yet. Anything the
    // fused request declines continues below on the same connections.
    if small_copy_eligible(&args, srcs, dst, &src_ep, &dst_ep) {
        match attempt_small_copy(
            &args,
            &opts,
            srcs,
            dst,
            &src_ep,
            &dst_ep,
            &mut *src_ctl,
            &mut *dst_ctl,
            source_roots.get().expect("source roots registered"),
            &progress,
            t0,
        )? {
            SmallCopy::Done(code) => {
                if let Some(benchmark) = &opts.benchmark {
                    benchmark.lock().unwrap().native_small_copies += 1;
                }
                print_benchmark_observations(&opts);
                return Ok(code);
            }
            SmallCopy::Declined => {}
            SmallCopy::Reconnect => dst_ctl = connect_ctl(&dst_ep, &args)?,
        }
    }
    let tcp_ports = use_tcp.then(|| parse_ports(&args.tcp_ports)).transpose()?;
    let mut pending_tcp_setups = Vec::new();
    if let Some(ports) = tcp_ports {
        for (ep, ctl) in [(&src_ep, &mut src_ctl), (&dst_ep, &mut dst_ctl)] {
            if let Endpoint::Remote(spec) = ep {
                match spec.begin_tcp_setup(
                    &mut **ctl,
                    args.tcp_plain,
                    ports,
                    args.tcp_congestion.as_deref(),
                ) {
                    Ok(pending) => pending_tcp_setups.push((spec.clone(), pending)),
                    Err(error) => {
                        handle_tcp_setup_error(&args, spec, ports, error, &sched, &progress)?;
                    }
                }
            }
        }
    }
    if debug() {
        crate::output::diagnostic!(
            "syq: TCP route probes started at {:.2}s",
            t0.elapsed().as_secs_f64()
        );
    }
    // One spelling for the destination root: every derived key — claims,
    // delete roots, destination-walk paths, receiver-computed sidecar names —
    // flows from this, and the receiver rebuilds paths through `Path`, which
    // silently drops `.` components and duplicate slashes. Cleaning here
    // (lexically only; symlinks stay the self-copy guard's business) keeps
    // `dst`, `dst/`, `dst/.` and `dst//` from producing keys that disagree.
    let operator_dst_root = clean_root(&dst.path);
    // Only exact placement onto bare `~` needs the receiver's canonical
    // spelling: it names HOME rather than a literal leaf. Other placements
    // keep the operator's spelling; registration handles their path policy.
    let expand_exact_home = args.interface != Interface::Rsync
        && args.placement == Placement::As
        && args.restricted_grant.is_none()
        && operator_dst_root == b"~";
    let (dst_root, mut dst_root_entry) = if expand_exact_home {
        let (entry, canonical) = stat_and_canonicalize(&mut *dst_ctl, &operator_dst_root)?;
        (canonical.as_os_str().as_bytes().to_vec(), entry)
    } else {
        let entry = stat_one(&mut *dst_ctl, &operator_dst_root, false)?;
        // Rsync retains its destination-directory compatibility rule. Native
        // container placement follows links only under the destination policy;
        // exact placement preserves the final directory entry.
        if args.interface == Interface::Rsync {
            follow_dir_symlink(&mut *dst_ctl, &operator_dst_root, entry)?
        } else if args.follows_native_destination_paths() && args.placement == Placement::Into {
            follow_container_symlink(
                &mut *dst_ctl,
                &operator_dst_root,
                entry,
                args.target_existence != Existence::Existing,
            )?
        } else {
            (operator_dst_root.clone(), entry)
        }
    };
    if debug() {
        crate::output::diagnostic!(
            "syq: destination stat complete at {:.2}s",
            t0.elapsed().as_secs_f64()
        );
    }
    let mut dst_initially_missing = dst_root_entry.is_none();
    let mut dst_existed = dst_root_entry.is_some();
    let mut dst_entry_is_dir = dst_root_entry
        .as_ref()
        .is_some_and(|entry| entry.kind == Kind::Dir);
    match args.target_existence {
        Existence::Any => {}
        Existence::New if dst_existed => bail!(
            "target {} already exists, but the selected placement requires a new path",
            display(&dst_root)
        ),
        Existence::Existing if !dst_existed => bail!(
            "target {} does not exist, but the selected placement requires an existing path",
            display(&dst_root)
        ),
        Existence::New | Existence::Existing => {}
    }
    let dst_is_dir = match args.placement {
        Placement::Into => {
            if args.interface != Interface::Rsync
                && !args.follows_native_destination_paths()
                && dst_root_entry
                    .as_ref()
                    .is_some_and(|entry| entry.kind == Kind::Symlink)
            {
                bail!(
                    "--into destination {} is a symlink; pass --follow-dst (or --follow) to resolve destination symlinks",
                    display(&dst_root)
                );
            }
            if dst_existed && !dst_entry_is_dir {
                bail!(
                    "--into target {} exists but is not a directory",
                    display(&dst_root)
                );
            }
            true
        }
        Placement::As => false,
        Placement::Rsync => match &dst_root_entry {
            Some(e) if e.kind == Kind::Dir => true,
            Some(_) if multiple_source_operands => {
                bail!("destination must be a directory when copying multiple sources")
            }
            Some(_) => false,
            None => multiple_source_operands || dst.copies_contents() || args.files_from.is_some(),
        },
    };
    if args.placement == Placement::Into
        && args.target_existence == Existence::Existing
        && !dst_entry_is_dir
    {
        bail!(
            "--into-existing target {} is not an existing directory",
            display(&dst_root)
        );
    }
    if args.files_from.is_some() {
        if let Some(e) = dst_root_entry.as_ref().filter(|e| e.kind != Kind::Dir) {
            bail!(
                "--files-from needs a directory destination; {} is a {:?}",
                display(&dst_root),
                e.kind
            );
        }
    }
    if args.interface != Interface::Rsync {
        // Native selectors are structural: validate every selected root before
        // a missing --into target can be created. The registered selection is
        // authoritative here, so its operator path is not resolved again.
        for (source_index, source) in srcs.iter().enumerate() {
            match stat_one_registered(
                &mut *src_ctl,
                &source.path,
                &source_roots.get().expect("source roots registered")[source_index].selection,
                source.follows_root(args.follows_native_source_paths()),
            )? {
                Some(entry) => {
                    validate_native_source_type(&source.path, source.selection, entry.kind)?
                }
                None => bail!("source {} does not exist", display(&source.path)),
            }
        }
    }
    hold_after_target_precondition_for_test(&args)?;

    // Select and retain the receiver-side directory that gives the operator's
    // destination its meaning. Every connection later enters this exact inode
    // and receives only paths relative to it, so replacing the external
    // spelling after this check cannot redirect worker writes.
    // A signed receiver instead retains and verifies its pre-enrolled root fd
    // for every request; HostA is not authorized to manage this anchoring
    // state itself.
    let use_operator_anchor = args.restricted_grant.is_none();
    let operator_directory = if expand_exact_home {
        dst_root.clone()
    } else if dst_is_dir {
        operator_dst_root.clone()
    } else {
        // Exact placement always retains the parent of the command-line leaf.
        // Under destination following that walk may traverse parent symlinks,
        // but it never changes which final directory entry the command addresses.
        parent_path(&operator_dst_root)
    };
    let request_prefix = if expand_exact_home || dst_is_dir {
        dst_root.clone()
    } else {
        operator_directory.clone()
    };
    // A missing single-file destination can also have a missing parent. Keep
    // the nearest existing ancestor open so normal copies can create that
    // parent without giving an attacker a pathname-resolution window.
    let allow_missing = dst_root_entry.is_none();
    // For an existing remote container, the initial stat already gives the
    // identity anchoring must enforce. These receiver-local operations can run
    // in order without waiting for the client between them. Keep same-machine
    // copies on the path that performs ancestry checks before anchoring.
    let prepare_existing = use_operator_anchor
        && dst.is_remote()
        && !srcs[0].is_remote()
        && dst_is_dir
        && dst_entry_is_dir
        && !args.verify_only
        && !args.existing;
    let mut prepared_anchor = None;
    let mut prepared_filesystem = None;
    let mut directory_selection = if prepare_existing {
        let (selection, filesystem, anchor) = prepare_existing_destination(
            &mut *dst_ctl,
            &operator_directory,
            opts.operator_symlink_policy,
            dst_root_entry.as_ref().expect("existing destination"),
            request_prefix.clone(),
        )?;
        prepared_anchor = Some(anchor);
        prepared_filesystem = Some(filesystem);
        selection
    } else if use_operator_anchor {
        check_operator_directory(
            &mut *dst_ctl,
            &operator_directory,
            allow_missing,
            opts.operator_symlink_policy,
        )?
    } else {
        None
    };
    if debug() {
        crate::output::diagnostic!(
            "syq: destination selection complete at {:.2}s",
            t0.elapsed().as_secs_f64()
        );
    }
    if use_operator_anchor && dst_is_dir {
        let planned_identity = dst_root_entry.as_ref().map(|entry| (entry.dev, entry.ino));
        let selected_identity = directory_selection
            .as_ref()
            .map(|selection| (selection.dev, selection.ino));
        if selected_identity != planned_identity {
            // Another ordinary copy may create the same missing destination
            // between the initial stat and the descriptor-retaining walk.
            // Accept only the exact directory inode that the secure walk has
            // already retained; later operations stay anchored to that fd.
            let appeared = if planned_identity.is_none() {
                stat_one(&mut *dst_ctl, &operator_dst_root, true)?
            } else {
                None
            };
            let appeared_matches_selection = appeared.as_ref().is_some_and(|entry| {
                entry.kind == Kind::Dir && Some((entry.dev, entry.ino)) == selected_identity
            });
            if !appeared_matches_selection {
                bail!(
                    "destination directory {} changed while resolving it",
                    display(&operator_dst_root)
                );
            }
            dst_root_entry = appeared;
            dst_initially_missing = false;
            dst_existed = true;
            dst_entry_is_dir = true;
        }
    }
    // A missing target, or an existing empty container, has no destination
    // payload whose replacement could release space during this copy. That
    // makes its selected source population a useful whole-copy capacity
    // sanity check. Inspect the retained selection before anchoring or
    // creating the target; if the endpoint cannot expose reliable counters or
    // emptiness, simply retain the normal allocation-time checks.
    let exact_capacity_target = if dst_entry_is_dir
        && !dst_is_dir
        && !expand_exact_home
        && operator_directory != operator_dst_root
    {
        let entry = dst_root_entry
            .as_ref()
            .expect("known existing exact directory has metadata");
        let relative_path = operator_dst_root
            .rsplit(|byte| *byte == b'/')
            .next()
            .unwrap_or_default()
            .to_vec();
        (!matches!(relative_path.as_slice(), b"" | b"." | b"..")).then_some(
            DestinationFilesystemTarget {
                relative_path,
                dev: entry.dev,
                ino: entry.ino,
            },
        )
    } else {
        None
    };
    let can_inspect_existing_destination = dst_is_dir
        || expand_exact_home
        || operator_directory == operator_dst_root
        || exact_capacity_target.is_some();
    let initial_destination_filesystem = if use_operator_anchor
        && !args.verify_only
        && !args.existing
        && (dst_root_entry.is_none() || (dst_entry_is_dir && can_inspect_existing_destination))
    {
        let check_empty = dst_root_entry.is_some() && dst_entry_is_dir;
        match prepared_filesystem {
            Some(info) => info,
            None => destination_filesystem_info(
                &mut *dst_ctl,
                check_empty,
                exact_capacity_target.clone(),
            )?,
        }
    } else {
        None
    };
    // A missing single-file target may still have a resumable sidecar. Bound
    // its initial SSH workers speculatively, then restore concurrency if the
    // worker discovers a basis with potentially disjoint changed ranges.
    let fresh_destination = dst_root_entry.is_none()
        || (dst_entry_is_dir
            && initial_destination_filesystem
                .as_ref()
                .is_some_and(|info| info.empty == Some(true)));
    let fresh_capacity = initial_destination_filesystem.and_then(|info| {
        fresh_destination.then_some(FreshCapacityPlan {
            device: info.device,
            target: exact_capacity_target,
            root_existed: dst_root_entry.is_some(),
            logical_bytes: 0,
            objects: 0,
            overflowed: false,
        })
    });
    let defer_destination_mutations = multiple_distinct_sources
        || (fresh_capacity.is_some() && !args.dry_run && !args.verify_only);
    // Native new/existing forms are intentionally only the lightweight
    // pathname checks above. Once they pass, use the ordinary engine's target
    // conditions and publication behavior; this adapter does not add an
    // identity precondition or a mutation-time existence recheck.
    let exact_condition = TargetCondition::Any;
    let mut mutation_root_condition = TargetCondition::Any;
    let guard_containers = false;
    let mut container_guard = None;

    // Reject copying a directory into itself: if the effective destination is
    // (or is beneath) a source directory, the scanner would discover the
    // freshly-created destination and recurse. Compare the exact source and
    // retained destination descriptors; never re-resolve either operator
    // pathname for this decision. The descriptor handoff requires one kernel,
    // so attempt it only for local paths or matching SSH endpoints.
    let same_machine = (!srcs[0].is_remote() && !dst.is_remote())
        || (srcs[0].is_remote() && dst.is_remote() && srcs[0].same_host(dst));
    let mut prune_overlap_unsearchable = false;
    if same_machine {
        let roots = source_roots.get().expect("source roots registered");
        let mut source_checks = Vec::new();
        let mut ancestry_checks = Vec::new();
        let may_prune = opts.delete
            && roots
                .iter()
                .any(|root| root.selection.relative().is_empty());
        let primary_suffix = if expand_exact_home || dst_is_dir {
            Vec::new()
        } else {
            operator_dst_root
                .rsplit(|byte| *byte == b'/')
                .next()
                .unwrap_or_default()
                .to_vec()
        };
        let prune_suffixes: Vec<_> = if may_prune {
            srcs.iter()
                .zip(roots)
                .filter(|(_, root)| root.selection.relative().is_empty())
                .map(|(candidate, _)| {
                    if candidate.copies_contents()
                        || args.files_from.is_some()
                        || args.placement == Placement::As
                    {
                        primary_suffix.clone()
                    } else {
                        join(&primary_suffix, &candidate.basename())
                    }
                })
                .collect()
        } else {
            Vec::new()
        };
        for (source_index, (source, root)) in srcs.iter().zip(roots).enumerate() {
            // Registration represents every selected directory as an empty
            // path beneath that directory descriptor. Exact files and
            // symlinks cannot recurse, but pruning another source's copied
            // directory must not remove an exact source selected beneath it.
            let source_is_directory = root.selection.relative().is_empty();
            if !source_is_directory && !may_prune {
                continue;
            }
            let mut suffixes = vec![primary_suffix.clone()];
            if dst_is_dir && !source.copies_contents() && args.files_from.is_none() {
                let basename = source.basename();
                if !basename.is_empty() {
                    suffixes.push(basename);
                }
            }
            // Recursion checks include the destination container, but prune
            // overlap checks apply only to copied directory roots. Compare
            // every selected source with every such root: one source's prune
            // must not remove another selected source.
            for suffix in &prune_suffixes {
                if !suffixes.contains(suffix) {
                    suffixes.push(suffix.clone());
                }
            }
            let checked_for_prune = suffixes
                .iter()
                .map(|suffix| prune_suffixes.contains(suffix))
                .collect::<Vec<_>>();
            source_checks.push((source_index, checked_for_prune));
            ancestry_checks.push(DirectoryAncestryCheck {
                source_root: root.ticket.clone(),
                source_is_directory,
                suffixes,
            });
        }

        let relations = if ancestry_checks.is_empty() {
            Vec::new()
        } else {
            check_operator_directory_ancestry(&mut *dst_ctl, ancestry_checks)?
        };
        if relations.len() != source_checks.len() {
            bail!(
                "destination returned {} ancestry results for {} directory sources",
                relations.len(),
                source_checks.len()
            );
        }
        for ((source_index, checked_for_prune), relations) in
            source_checks.into_iter().zip(relations)
        {
            if relations.len() != checked_for_prune.len() {
                bail!(
                    "destination returned {} ancestry results for {} effective paths",
                    relations.len(),
                    checked_for_prune.len()
                );
            }
            let source = &srcs[source_index];
            for (relation, checks_prune) in relations.into_iter().zip(checked_for_prune) {
                match relation {
                    DirectoryRelation::Separate => {}
                    DirectoryRelation::SourceUnsearchable => {
                        if checks_prune {
                            prune_overlap_unsearchable = true;
                            progress.error(&format!(
                                "syq: cannot check pruning overlap for source {}: a source ancestor cannot be searched",
                                display(&source.path)
                            ));
                        }
                    }
                    DirectoryRelation::Ancestor if !checks_prune => {}
                    DirectoryRelation::Ancestor => bail!(
                        "cannot prune destination {:?}: it contains source {:?}",
                        display(&dst.path), display(&source.path)
                    ),
                    DirectoryRelation::Same => bail!(
                        "source and destination are the same directory {:?}",
                        display(&source.path)
                    ),
                    DirectoryRelation::Descendant => bail!(
                        "destination {:?} maps inside source {:?} — that would copy the directory into itself",
                        display(&dst.path), display(&source.path)
                    ),
                }
            }
        }
    }

    if debug() {
        crate::output::diagnostic!(
            "syq: source/destination ancestry checked at {:.2}s",
            t0.elapsed().as_secs_f64()
        );
    }

    // Settle restricted transport setup before destination creation. Return
    // authorization still requires direct TCP; enrolled receivers can instead
    // attach SSH workers to the already-authorized copy on the same route.
    if pending_tcp_setups
        .iter()
        .any(|(spec, _)| spec.restricted_grant.is_some())
    {
        for (spec, pending) in std::mem::take(&mut pending_tcp_setups) {
            if let Err(error) = spec.finish_tcp_setup(pending) {
                handle_tcp_setup_error(
                    &args,
                    &spec,
                    tcp_ports.expect("pending TCP setup has a port range"),
                    error,
                    &sched,
                    &progress,
                )?;
            }
        }
    }

    // Create a missing directory destination — never in the read-only modes,
    // and never under --existing. With several sources, or while a fresh-target
    // capacity check is pending, this waits until the complete scan has passed
    // its namespace and capacity preflights.
    let create_root = dst_root_entry.is_none()
        && dst_is_dir
        && !args.dry_run
        && !args.verify_only
        && !args.existing;
    let dry_run_creates_root =
        args.dry_run && dst_root_entry.is_none() && dst_is_dir && !args.existing;
    let root_create_condition = TargetCondition::Any;
    let defer_operator_directory_creation = use_operator_anchor
        && directory_selection.is_none()
        && !args.dry_run
        && !args.verify_only
        && !args.existing
        && defer_destination_mutations;
    if use_operator_anchor {
        let create_operator_directory_now = directory_selection.is_none()
            && !args.dry_run
            && !args.verify_only
            && !args.existing
            && !defer_operator_directory_creation;
        if create_operator_directory_now {
            let condition = if dst_is_dir {
                root_create_condition
            } else {
                TargetCondition::Any
            };
            directory_selection = Some(create_operator_directory(&mut *dst_ctl, condition)?);
        }
        if let Some(selection) = directory_selection.take() {
            let anchor = match prepared_anchor.take() {
                Some(anchor) => anchor,
                None => {
                    activate_control_destination(&mut *dst_ctl, selection, request_prefix.clone())?
                }
            };
            if create_root {
                mutation_root_condition = TargetCondition::Matches {
                    dev: anchor.dev,
                    ino: anchor.ino,
                };
                if guard_containers {
                    container_guard = Some(ContainerGuard {
                        root: dst_root.clone(),
                        dev: anchor.dev,
                        ino: anchor.ino,
                    });
                }
            }
            destination_anchor
                .set(anchor)
                .expect("destination anchor set once");
        }
    } else if create_root && !defer_destination_mutations {
        let created = mkdir_root(
            &mut *dst_ctl,
            &dst_root,
            root_create_condition,
            opts.restricted_receiver,
            opts.perms,
        )?;
        mutation_root_condition = target_identity(&created);
        if guard_containers {
            container_guard = Some(target_container(&dst_root, &created));
        }
    }
    if debug() {
        crate::output::diagnostic!(
            "syq: destination preflight complete at {:.2}s",
            t0.elapsed().as_secs_f64()
        );
    }

    let destination_tree_known_missing = dst.is_remote()
        && dst_initially_missing
        && !opts.ignore_existing
        && !opts.update
        && !opts.checksum;
    // Buffered planning performs no destination mutations and starts no
    // workers. Let route probes overlap that scan, while preserving the early
    // worker startup used for initially missing destination trees. Restricted
    // receivers already settled their probes before destination creation.
    // Detached copies keep their readiness notification ahead of the scan.
    let defer_transport_setup = defer_destination_mutations
        && !destination_tree_known_missing
        && std::env::var_os("SYQ_INTERNAL_DETACH_READY").is_none()
        && !pending_tcp_setups.is_empty();
    let mut finish_transport_setup = |args: &mut Args| -> Result<(bool, Option<String>)> {
        for (spec, pending) in std::mem::take(&mut pending_tcp_setups) {
            if let Err(error) = spec.finish_tcp_setup(pending) {
                handle_tcp_setup_error(
                    args,
                    &spec,
                    tcp_ports.expect("pending TCP setup has a port range"),
                    error,
                    &sched,
                    &progress,
                )?;
            }
            if debug() {
                crate::output::diagnostic!(
                    "syq: {}: tcp data port {:?}",
                    spec.label(),
                    spec.tcp
                        .lock()
                        .unwrap()
                        .as_ref()
                        .map(|info| (info.addrs.clone(), info.port))
                );
            }
        }
        #[cfg(debug_assertions)]
        if std::env::var_os("SYQ_TEST_REQUIRE_TCP").is_some() {
            let remote_specs: Vec<_> = [&src_ep, &dst_ep]
                .into_iter()
                .filter_map(real_remote_spec)
                .collect();
            if remote_specs.is_empty()
                || remote_specs
                    .iter()
                    .any(|spec| spec.data_transport() == DataTransport::Ssh)
            {
                sched.abort();
                progress.stop();
                bail!("TCP data transport required by test");
            }
        }
        if debug() {
            crate::output::diagnostic!(
                "syq: data transport setup complete at {:.2}s",
                t0.elapsed().as_secs_f64()
            );
        }
        #[cfg(debug_assertions)]
        crate::fsops::record_test_event("SYQ_TEST_SETUP_EVENTS", format_args!("transport_ready"))?;
        announce_detached_ready()?;
        let all_remote_endpoints_use_tcp = use_tcp
            && [&src_ep, &dst_ep]
                .into_iter()
                .all(|endpoint| match endpoint {
                    Endpoint::Local { .. } => true,
                    Endpoint::Remote(spec) => spec
                        .tcp
                        .lock()
                        .unwrap()
                        .as_ref()
                        .is_some_and(|info| !info.failed),
                });
        if autotune && all_remote_endpoints_use_tcp && (src_ep.is_remote() || dst_ep.is_remote()) {
            args.connections = tune::START_TCP.min(args.automatic_worker_limit());
            gate.set_active(args.connections);
        }
        let tuning_key = (autotune && args.tuning_options.is_none())
            .then(|| tune::path_key(&src_ep, &dst_ep))
            .flatten();
        let remembered_start = tuning_key
            .as_deref()
            .and_then(tune::cached)
            .map(|remembered| remembered.min(args.automatic_worker_limit()));
        if let Some(remembered) = remembered_start {
            args.connections = remembered;
            gate.set_active(remembered);
        }
        print_transport_diagnostics(args, &src_ep, &dst_ep);
        if args.verbose >= 2 {
            if let Some(remembered) = remembered_start {
                crate::output::diagnostic!(
                    "syq: auto-tuning: starting with {remembered} connections remembered for this path"
                );
            }
        }
        Ok((all_remote_endpoints_use_tcp, tuning_key))
    };
    let mut transport_setup = if defer_transport_setup {
        None
    } else {
        Some(finish_transport_setup(&mut args)?)
    };
    let mut workers_started = false;
    if transport_setup.as_ref().is_some_and(|(tcp, _)| *tcp)
        && destination_tree_known_missing
        && !opts.dry_run
        && !opts.inplace
        && !opts.verify_only
        && (!destination_anchor_required || destination_anchor.get().is_some())
    {
        // The planner signals as soon as a source batch contains regular files,
        // before remote sidecar resolution and directory creation. Empty trees
        // therefore open no data connections, while fresh file trees cover TCP
        // authentication with work the control connection must do anyway.
        connect_after_file_plan.store(true, Relaxed);
        spawn_workers(args.connections);
        workers_started = true;
    }

    let ticker = progress.spawn_ticker();

    let mut st = Planner {
        dst: &mut *dst_ctl,
        sched: &sched,
        progress: &progress,
        opts: &opts,
        destination_supports_confined_socket_nodes,
        destination_tree_known_missing,
        dst_seen: std::collections::HashMap::new(),
        missing_dirs: std::collections::HashSet::new(),
        blocked_directory_paths: std::collections::HashSet::new(),
        payload_paths: std::collections::HashMap::new(),
        sidecar_paths: std::collections::HashMap::new(),
        unusable_files: std::collections::HashSet::new(),
        deferred_payloads: Vec::new(),
        source_partials: 0,
        collision: false,
        deferred: Vec::new(),
        scan_warned: false,
        max_delete_hit: false,
        delete_walk_failed: false,
        dst_root: dst_root.clone(),
        exact_condition,
        mutation_root_condition,
        container_guard,
        guard_containers,
        buffer: if defer_destination_mutations {
            Some(Vec::new())
        } else {
            None
        },
        fresh_capacity,
        src_overrides: std::collections::HashMap::new(),
        implicit_dirs: std::collections::HashSet::new(),
        mapping_explicit_parents: std::collections::HashSet::new(),
        blocked_mapping_parents: std::collections::HashSet::new(),
        implicit_restorations: Vec::new(),
        // Deferred root creation must succeed before mapped entries are applied.
        created_dirs: if create_root && opts.preserve_existing_directory_metadata {
            std::collections::HashSet::from([dst_root.clone()])
        } else {
            std::collections::HashSet::new()
        },
        mapping_mode: false,
        create_root: if defer_operator_directory_creation {
            Some((
                request_prefix.clone(),
                if dst_is_dir {
                    root_create_condition
                } else {
                    TargetCondition::Any
                },
                dst_is_dir,
            ))
        } else if !use_operator_anchor && create_root && defer_destination_mutations {
            Some((dst_root.clone(), root_create_condition, true))
        } else {
            None
        },
        destination_anchor: &destination_anchor,
        use_operator_anchor,
        keep_dirs: args.files_from.is_some() || args.native_mapping.is_some(),
        delete_roots: Vec::new(),
        deletes: Deletes::default(),
        dry_run_changes: {
            let mut changes = DryRunChanges::default();
            if dry_run_creates_root {
                changes.directories.insert(dst_root.clone());
            }
            changes
        },
        active_source: None,
    };

    let mut scan_err = None;
    let mut fresh_capacity_assessment = None;
    let mut fresh_capacity_shortage = None;
    let mut dry_run_mappings = Vec::with_capacity(srcs.len());
    if let Some((mapping_entries, explicit_parents)) = mapping_entries {
        let src = &srcs[0];
        st.active_source = Some(
            source_roots.get().expect("source roots registered")[0]
                .selection
                .clone(),
        );
        match st.scan_mapping(
            &mut *src_ctl,
            &src.path,
            &dst_root,
            mapping_entries,
            explicit_parents,
        ) {
            Ok(()) => dry_run_mappings.push(DryRunMapping {
                target: dst_root.clone(),
                semantics: "entries selected by --mapping",
            }),
            Err(e) => scan_err = Some(e),
        }
    } else if args.files_from.is_some() {
        let src = &srcs[0];
        st.active_source = Some(
            source_roots.get().expect("source roots registered")[0]
                .selection
                .clone(),
        );
        match st.scan_files_from(
            &mut *src_ctl,
            &src.path,
            &dst_root,
            &args.files_from_lines,
            args.recursive_explicit,
        ) {
            Ok(()) => dry_run_mappings.push(DryRunMapping {
                target: dst_root.clone(),
                semantics: "paths selected by --files-from",
            }),
            Err(e) => scan_err = Some(e),
        }
    }
    for (source_index, src) in srcs
        .iter()
        .filter(|_| args.files_from.is_none() && args.native_mapping.is_none())
        .enumerate()
    {
        st.active_source = Some(
            source_roots.get().expect("source roots registered")[source_index]
                .selection
                .clone(),
        );
        let src_root = src.path.clone();
        let contents = src.copies_contents();
        let follow_root = src.follows_root(args.follows_native_source_paths());
        // A bare directory source goes to dest/basename even when dest doesn't
        // exist yet; a non-directory source only does so when dest is a directory
        // (decided once the root entry is seen).
        let sub = if contents || args.placement == Placement::As {
            Vec::new()
        } else {
            src.basename()
        };
        match st.scan_source(
            &mut *src_ctl,
            &src_root,
            SourceMapping {
                follow_root,
                contents,
                selection: src.selection,
                sub: &sub,
            },
            DestinationRoot {
                path: &dst_root,
                existed: dst_existed,
                is_container: dst_is_dir,
                entry_is_dir: dst_entry_is_dir,
                exact: args.placement == Placement::As,
            },
        ) {
            Ok(mapping) => dry_run_mappings.push(mapping),
            Err(e) => {
                scan_err = Some(e);
                break;
            }
        }
    }
    if scan_err.is_none() && !st.collision {
        if let Err(e) = st.finish_planning() {
            scan_err = Some(e);
        }
    }
    #[cfg(debug_assertions)]
    crate::fsops::record_test_event("SYQ_TEST_SETUP_EVENTS", format_args!("scan_complete"))?;
    if transport_setup.is_none() {
        transport_setup = Some(finish_transport_setup(&mut args)?);
    }
    let (all_remote_endpoints_use_tcp, tuning_key) =
        transport_setup.expect("transport setup completed before releasing planned work");
    // The complete buffered scan lets small trees keep the same bounded
    // starting count as normal scheduling. Open TCP workers while the control
    // connection rechecks capacity and inspects the destination; no jobs are
    // released until those preflights pass. A failed preflight aborts the idle
    // workers through the same scheduler path as any other planning failure.
    if scan_err.is_none()
        && !st.collision
        && !workers_started
        && dst_ep.is_remote()
        && !opts.same_host
        && all_remote_endpoints_use_tcp
        && destination_anchor.get().is_some()
        && st
            .fresh_capacity
            .as_ref()
            .is_some_and(|plan| plan.root_existed)
        && !opts.dry_run
        && !opts.verify_only
        && !opts.inplace
        && !opts.checksum
        && !opts.update
        && !opts.ignore_existing
        && !opts.tuning.force_ranges()
        && bwlimit.is_none()
    {
        let mut files = 0;
        let mut bytes = 0u64;
        let mut all_small = true;
        for planned in st.buffer.iter().flatten().flat_map(|mapped| &mapped.others) {
            let entry = &planned.e;
            if entry.kind == Kind::File
                && opts.max_size.is_none_or(|max| entry.size <= max)
                && opts.min_size.is_none_or(|min| entry.size >= min)
            {
                files += 1;
                bytes = bytes.saturating_add(entry.size);
                all_small &= entry.size <= fast_file_size_limit(&opts, bwlimit.as_deref());
            }
        }
        if files > 0 && all_small {
            spawn_workers(initial_fast_workers(
                args.connections,
                files,
                bytes,
                opts.tuning.batch_files.unwrap_or(STARTUP_BATCH_FILES),
                opts.tuning.batch_bytes(),
            ));
            workers_started = true;
        }
    }
    if scan_err.is_none() && !st.collision {
        match st.assess_fresh_capacity() {
            Ok(assessment) => {
                fresh_capacity_assessment = assessment;
                fresh_capacity_shortage = assessment.filter(|value| !value.sufficient());
                if let Some(assessment) = fresh_capacity_shortage.filter(|_| !args.dry_run) {
                    scan_err = Some(fresh_capacity_error(assessment));
                }
            }
            Err(error) => scan_err = Some(error),
        }
    }
    if scan_err.is_none() && !st.collision {
        if let Err(error) = st.replay_buffered() {
            scan_err = Some(error);
        }
    }
    // A dry run still completes its virtual replay so the summary remains a
    // truthful plan, then reports the same capacity refusal a real run would
    // hit. No destination operation occurs during that replay.
    if scan_err.is_none() && args.dry_run {
        if let Some(assessment) = fresh_capacity_shortage {
            scan_err = Some(fresh_capacity_error(assessment));
        }
    }
    if debug() {
        crate::output::diagnostic!(
            "syq: payload planning complete at {:.2}s",
            t0.elapsed().as_secs_f64()
        );
    }
    if st.source_partials > 0 && !args.quiet && scan_err.is_none() && !st.collision {
        let count = st.source_partials;
        progress.warning(
            "source_partials",
            count,
            &format!(
                "source contains {count} recognizable SYQ partial path{}; {} treated as ordinary payload",
                if count == 1 { "" } else { "s" },
                if count == 1 { "it is" } else { "they are" }
            ),
        );
    }
    let collision = st.collision;
    progress.scan_done.store(true, Relaxed);
    if let Some(e) = &scan_err {
        let os_kind = os_kind_of(e);
        progress.error_classified(&format!("syq: {e:#}"), os_kind.map(|_| "io"), os_kind);
        sched.abort();
    } else if collision {
        sched.abort();
    } else {
        let has_file_work = !sched.jobs.lock().unwrap().is_empty();
        if has_file_work {
            if use_operator_anchor && destination_anchor.get().is_none() {
                progress.error("syq: destination root is missing and cannot be anchored");
                sched.abort();
            } else {
                let (multiplex_small_files, file_jobs, file_bytes) = {
                    let jobs = sched.jobs.lock().unwrap();
                    (
                        !opts.verify_only
                            && !opts.dry_run
                            && !opts.tuning.force_ranges()
                            && bwlimit.is_none()
                            && jobs.iter().enumerate().all(|(idx, job)| {
                                job.entry.size <= fast_file_size_limit(&opts, bwlimit.as_deref())
                                    && jobs.destination(idx).is_none()
                                    && (!opts.inplace
                                        || (job.target_condition == TargetCondition::Any
                                            && job.container_guard.is_none()))
                            }),
                        jobs.len(),
                        jobs.iter()
                            .fold(0u64, |total, job| total.saturating_add(job.entry.size)),
                    )
                };
                if multiplex_small_files {
                    for spec in [&src_ep, &dst_ep]
                        .into_iter()
                        .filter_map(real_remote_spec)
                        .filter(|spec| spec.data_transport() == DataTransport::Ssh)
                    {
                        spec.set_ssh_multiplexing(true);
                    }
                }
                if !workers_started {
                    // A same-machine file normally completes wholly inside one
                    // small-file or receiver-side copy request (copy_file_range,
                    // or an eligible sequential userspace fallback). Starting
                    // 32 loopback connections cannot help that request. If a larger file
                    // instead discovers a partial or an unsupported offload,
                    // the first worker wakes the tuner to restore the ordinary
                    // local starting count immediately.
                    let single_direct_candidate =
                        autotune && opts.copy_policy(bwlimit.is_some()).allows_receiver_copy() && {
                            let jobs = sched.jobs.lock().unwrap();
                            jobs.len() == 1 && jobs[0].container_guard.is_none()
                        };
                    let mut initial = if multiplex_small_files {
                        initial_fast_workers(
                            args.connections,
                            file_jobs,
                            file_bytes,
                            opts.tuning.batch_files.unwrap_or(STARTUP_BATCH_FILES),
                            opts.tuning.batch_bytes(),
                        )
                    } else {
                        args.connections
                    };
                    if autotune
                        && fresh_destination
                        && !multiplex_small_files
                        && !all_remote_endpoints_use_tcp
                        && (src_ep.is_remote() || dst_ep.is_remote())
                    {
                        // A worker which cannot get a file or steal a range
                        // still costs an SSH login, and joining its setup can
                        // delay success after every byte has been copied.
                        let jobs = sched.jobs.lock().unwrap();
                        initial = initial_range_workers(
                            initial,
                            jobs.iter().map(|job| job.entry.size),
                            sched.min_split,
                        );
                        if initial < args.connections {
                            sched.arm_direct_fallback(args.connections);
                        }
                        if jobs.len() == 1 {
                            sched.reserve_initial_ranges(initial);
                        }
                        if args.verbose >= 2 && initial < args.connections {
                            crate::output::diagnostic!(
                                "syq: SSH startup limited to {initial} workers by available files and ranges"
                            );
                        }
                    }
                    if single_direct_candidate {
                        sched.arm_direct_fallback(args.connections);
                        initial = 1;
                    }
                    spawn_workers(initial);
                }
            }
        }
        // No worker opens a sidecar until every payload/sidecar namespace
        // collision is known and the receiving root has been retained.
        sched.scan_done();
    }

    // Join workers; the tuner may add more while we do, until it exits.
    loop {
        let batch: Vec<_> = std::mem::take(&mut *workers.lock().unwrap());
        if batch.is_empty() {
            let tuning = tuner
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|t| !t.is_finished());
            if !tuning {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
            continue;
        }
        for w in batch {
            match w.join() {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    progress.error(&format!("syq: worker: {e:#}"));
                    sched.abort();
                }
                Err(_) => progress.error("syq: worker thread panicked"),
            }
        }
    }
    let tuned = match tuner.lock().unwrap().take() {
        Some(thread) => match thread.join() {
            Ok(policy) => Some(policy),
            Err(_) => {
                progress.error("syq: auto-tuning thread panicked");
                sched.abort();
                None
            }
        },
        None => None,
    };
    if debug() {
        crate::output::diagnostic!(
            "syq: file workers complete at {:.2}s",
            t0.elapsed().as_secs_f64()
        );
    }

    let aborted = sched.is_aborted();
    if opts.dry_run {
        st.flush_dry_directory_traces();
    }
    sched.clear_finished_work();
    let mut deleted = 0u64;
    let mut delete_plan = if opts.delete {
        DeletePlan::Skipped("the copy plan did not complete")
    } else {
        DeletePlan::Disabled
    };
    // --delete runs once the workers are done, so the destination walk sees a
    // quiescent tree (no partials being renamed, no entries being replaced),
    // and before apply_deferred, since unlinking bumps directory mtimes. Any
    // source-side scan problem disables deletion: a directory we couldn't
    // read would otherwise look like one whose contents vanished.
    if !aborted && opts.delete && scan_err.is_none() && !collision {
        if st.scan_warned {
            delete_plan = DeletePlan::Skipped("source scan errors");
            progress.eprintln("syq: source scan reported errors; skipping deletions");
        } else if prune_overlap_unsearchable {
            delete_plan = DeletePlan::Skipped("source ancestry could not be checked");
            progress.eprintln("syq: source ancestry could not be checked; skipping deletions");
        } else if progress.errors.load(Relaxed) != 0 {
            delete_plan = DeletePlan::Skipped("copy errors");
            progress.eprintln("syq: copy reported errors; skipping deletions");
        } else {
            match st.assert_mutation_root().and_then(|_| st.plan_deletes()) {
                Ok(()) if st.delete_walk_failed => {
                    delete_plan = DeletePlan::Skipped("destination walk errors");
                    progress.eprintln("syq: destination walk reported errors; skipping deletions")
                }
                Ok(()) => {
                    delete_plan = DeletePlan::Planned(st.deletes.len());
                    st.assert_mutation_root()?;
                    deleted = st.run_deletes()?;
                }
                Err(e) => {
                    delete_plan = DeletePlan::Skipped("destination planning failed");
                    progress.error(&format!("syq: delete: {e:#}"));
                }
            }
        }
    }
    if !aborted && !opts.dry_run && !opts.verify_only {
        st.apply_deferred()?;
    }
    if debug() {
        crate::output::diagnostic!(
            "syq: deferred metadata complete at {:.2}s",
            t0.elapsed().as_secs_f64()
        );
    }
    let max_delete_hit = st.max_delete_hit;
    let mut dry_run_changes = std::mem::take(&mut st.dry_run_changes);
    if opts.dry_run {
        dry_run_changes.regular_files = progress.files_done.load(Relaxed);
        dry_run_changes.metadata_files += opts.dry_run_metadata_files.load(Relaxed);
    }
    // The destination container is created outside per-entry accounting in
    // live runs; drop it here so the terminal record and the human dry-run
    // summary count the same set (spec: summary renders from the record).
    dry_run_changes.directories.remove(&dst_root);
    let created_counts = (
        progress.directories_created.load(Relaxed),
        progress.symlinks_created.load(Relaxed),
        progress.specials_created.load(Relaxed),
    );
    drop(st);

    // With a command-restricted receiver, ask for its signed receipt now that
    // every mutation is settled, and hand its bounded frames to the invoking
    // machine as marked lines. That machine verifies it; this coordinator's
    // own report is not trusted for what landed.
    if let Some(receipt) = &args.named_receipt {
        if let Err(error) = crate::destination::finish_receipt(receipt, dst_ctl.as_mut()) {
            progress.error(&format!("syq: receipt: {error:#}"));
        }
    } else if args.restricted_grant.is_some() {
        use base64::Engine as _;
        if let Err(error) = dst_ctl.send(Request::Receipt) {
            progress.error(&format!("syq: receipt: {error:#}"));
        } else {
            loop {
                match dst_ctl.recv() {
                    Ok(Response::Receipt(frame)) => {
                        let terminal = match crate::receipt::receipt_frame_is_end(&frame) {
                            Ok(terminal) => terminal,
                            Err(error) => {
                                progress.error(&format!("syq: receipt: {error:#}"));
                                break;
                            }
                        };
                        if let Err(error) = crate::output::write_stdout(format_args!(
                            "{}{}",
                            crate::receipt::RECEIPT_LINE_PREFIX,
                            base64::engine::general_purpose::STANDARD_NO_PAD.encode(frame)
                        )) {
                            progress.error(&format!("syq: write receipt: {error}"));
                            break;
                        }
                        if terminal {
                            break;
                        }
                    }
                    Ok(Response::Err(error)) => {
                        progress.error(&format!("syq: receipt: {error}"));
                        break;
                    }
                    Ok(other) => {
                        progress.error(&format!("syq: receipt: unexpected response {other:?}"));
                        break;
                    }
                    Err(error) => {
                        progress.error(&format!("syq: receipt: {error:#}"));
                        break;
                    }
                }
            }
        }
    }

    progress.stop();
    if let Some(t) = ticker {
        let _ = t.join();
    }
    progress.clear();

    let errors = progress.errors.load(Relaxed);
    // One derivation for both, so status and exit code cannot disagree:
    // aborts trump entry errors, which trump a blocked deletion pass (its
    // fact survives in deletions_blocked).
    let (status, exit_code) = if aborted {
        ("aborted", 1)
    } else if errors > 0 {
        ("partial", 23)
    } else if max_delete_hit {
        ("refused", 25)
    } else {
        ("success", 0)
    };
    progress.finish(exit_code == 0);
    let (deletions_planned, deletions_completed, deletions_blocked) = if opts.delete {
        let planned = match delete_plan {
            DeletePlan::Planned(n) => n,
            _ => 0,
        };
        (
            Some(planned),
            Some(deleted),
            Some(if max_delete_hit { planned } else { 0 }),
        )
    } else {
        (None, None, None)
    };
    // Hard v1 rule: the human summary below renders from this same struct,
    // so the numbers a person reads and a machine parses cannot disagree.
    let terminal = crate::results::ResultRecord {
        status,
        exit_code,
        dry_run: opts.dry_run,
        files_transferred: if opts.verify_only {
            0
        } else {
            progress.files_done.load(Relaxed)
        },
        files_unchanged: progress.files_unchanged.load(Relaxed),
        files_excluded: progress.files_excluded.load(Relaxed),
        // Live counters only move when mutations run; a dry run reports the
        // planned work it traced instead.
        directories_created: if opts.dry_run {
            dry_run_changes.directories.len() as u64
        } else {
            created_counts.0
        },
        symlinks_created: if opts.dry_run {
            dry_run_changes.symlinks
        } else {
            created_counts.1
        },
        specials_created: if opts.dry_run {
            dry_run_changes.specials
        } else {
            created_counts.2
        },
        errors,
        bytes_transferred: if opts.verify_only {
            0
        } else {
            progress.bytes_done.load(Relaxed)
        },
        bytes_unchanged: progress.bytes_unchanged.load(Relaxed),
        copying_elapsed_ms: if opts.verify_only || opts.dry_run {
            None
        } else {
            progress.copying_elapsed_ms()
        },
        elapsed_ms: progress.start.elapsed().as_millis() as u64,
        deletions_planned,
        deletions_completed,
        deletions_blocked,
    };

    if !aborted
        && errors == 0
        && !opts.dry_run
        && !opts.verify_only
        && scan_err.is_none()
        && !collision
        // A capped run can use an unrestricted hint, but cannot replace it.
        && args
            .resource_limits
            .as_ref()
            .is_none_or(|limits| limits.workers.is_none())
    {
        if let Some(policy) = tuned.as_ref().filter(|policy| policy.measured()) {
            // A TCP failure affects later connections but leaves earlier TCP
            // workers alive, so a changed key means the measurements may mix
            // transports. Such a run is useful live evidence but not a safe
            // hint for either future pure path.
            if let Some(initial_key) = tuning_key.as_deref() {
                let final_key = tune::path_key(&src_ep, &dst_ep);
                if final_key.as_deref() == Some(initial_key) {
                    tune::remember(initial_key, policy.settled());
                } else if debug() {
                    crate::output::diagnostic!(
                        "syq: auto-tuning: transport changed during transfer; not updating cache"
                    );
                }
            }
        }
    }

    let elapsed = progress.start.elapsed().as_secs_f64();
    let done = progress.bytes_done.load(Relaxed);
    let capacity_only_dry_run_abort = opts.dry_run && fresh_capacity_shortage.is_some();
    if !args.quiet && (!aborted || capacity_only_dry_run_abort) && !args.suppress_summary {
        if opts.dry_run {
            if args.verbose > 0 && dry_run_creates_root {
                crate::output::human_stdout!(
                    "create directory {} (destination missing)",
                    display_directory(&dst_root)
                );
            }
            print_dry_run_summary(
                srcs,
                dst,
                &dry_run_mappings,
                &src_ep,
                &dst_ep,
                &args,
                &opts,
                &progress,
                delete_plan,
                &dry_run_changes,
                fresh_capacity_assessment,
            );
        } else if opts.verify_only {
            crate::output::human_stdout!(
                "syq: verified {} files match, {} differences or errors, checked {} in {}",
                commas(terminal.files_unchanged),
                errors,
                human(done),
                crate::progress::hms(elapsed)
            );
        } else {
            print_transfer_summary(
                &terminal,
                elapsed,
                &deletion_summary(delete_plan, deleted, opts.max_delete),
            );
        }
    }
    if args.stats && show_statistics(&args) && !args.quiet && !opts.verify_only && !opts.dry_run {
        if let Some(ms) = progress.copying_elapsed_ms() {
            crate::output::human_stdout!(
                "  copying interval: {:.3}s (may overlap planning)",
                ms as f64 / 1000.0
            );
        }
    }
    print_benchmark_observations(&opts);
    // --stats is additional human output, not the summary line the local
    // attested settlement re-renders; a delegated coordinator keeps it.
    if !args.quiet && (!aborted || capacity_only_dry_run_abort) && args.stats {
        let (files_label, unchanged_files_label, bytes_label, unchanged_bytes_label, bytes_work) =
            if opts.dry_run {
                (
                    "files needing content work",
                    "files with unchanged content",
                    "logical bytes needing content work",
                    "logical bytes with unchanged content",
                    progress.bytes_total.load(Relaxed),
                )
            } else if opts.verify_only {
                (
                    "regular files to compare",
                    "regular files matched",
                    "bytes checked",
                    "bytes matched",
                    done,
                )
            } else {
                (
                    "files to transfer",
                    "files unchanged",
                    "bytes transferred",
                    "bytes unchanged",
                    done,
                )
            };
        let has_ssh_data = [&src_ep, &dst_ep].into_iter().any(|endpoint| {
                matches!(endpoint, Endpoint::Remote(spec) if !spec.local_process && spec.data_transport() == DataTransport::Ssh)
            });
        let tcp_stats = format_tcp_stats(&transport_stats.lock().unwrap(), has_ssh_data);
        crate::output::human_stdout!(
                "  scanned entries: {}\n  {files_label}: {}\n  {unchanged_files_label}: {}\n  files excluded: {}\n  {bytes_label}: {}\n  {unchanged_bytes_label}: {}\n  elapsed: {:.2}s\n  connections: {}{}",
                commas(progress.scanned.load(Relaxed)),
                commas(progress.files_total.load(Relaxed)),
                commas(progress.files_unchanged.load(Relaxed)),
                commas(progress.files_excluded.load(Relaxed)),
                commas(bytes_work),
                commas(progress.bytes_unchanged.load(Relaxed)),
                elapsed,
                match &tuned {
                    Some(p) => format!(
                        "auto: settled at {} (path {}, peak {})",
                        p.settled(),
                        p.history
                            .iter()
                            .map(|n| n.to_string())
                            .collect::<Vec<_>>()
                            .join(" -> "),
                        p.peak
                    ),
                    None => args.connections.to_string(),
                },
                tcp_stats,
            );
    }
    if let Some(results) = progress.results_writer() {
        results.emit_result(&terminal);
    }
    Ok(exit_code)
}

/// lstat (or stat, with `follow`) each path on `conn`.
fn stat_many(
    conn: &mut dyn Conn,
    paths: Vec<PathBytes>,
    follow: bool,
) -> Result<Vec<Option<Entry>>> {
    stat_many_registered(conn, paths, None, follow)
}

#[derive(Debug)]
struct RangeReplyMismatch;

impl std::fmt::Display for RangeReplyMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("source range reply violates the protocol")
    }
}

impl std::error::Error for RangeReplyMismatch {}

fn validate_range_reply(expected_off: u64, expected_len: u64, off: u64, len: usize) -> Result<()> {
    if off != expected_off || len as u64 != expected_len || off.checked_add(len as u64).is_none() {
        return Err(anyhow::Error::new(RangeReplyMismatch).context(format!(
            "source block range ({off}, {len}) does not match requested range ({expected_off}, {expected_len})"
        )));
    }
    Ok(())
}

fn stat_many_registered(
    conn: &mut dyn Conn,
    mut paths: Vec<PathBytes>,
    mut sources: Option<Vec<RegisteredPath>>,
    follow: bool,
) -> Result<Vec<Option<Entry>>> {
    if paths.is_empty() {
        return Ok(Vec::new());
    }
    if let Some(sources) = &sources {
        if sources.len() != paths.len() {
            bail!("source stat capability count does not match path count");
        }
    }
    let path_bytes = paths.iter().enumerate().fold(0usize, |bytes, (i, path)| {
        bytes.saturating_add(source_request_bytes(
            path,
            sources.as_ref().map(|sources| &sources[i]),
        ))
    });
    if paths.len() > 1 && path_bytes > SOURCE_BATCH_PATH_BYTES {
        let middle = paths.len() / 2;
        let tail_paths = paths.split_off(middle);
        let tail_sources = sources.as_mut().map(|sources| sources.split_off(middle));
        let mut entries = stat_many_registered(conn, paths, sources, follow)?;
        entries.extend(stat_many_registered(
            conn,
            tail_paths,
            tail_sources,
            follow,
        )?);
        return Ok(entries);
    }
    match ok(
        conn.call(Request::StatMany {
            paths,
            sources,
            follow,
            guard: None,
        })?,
        "stat",
    )? {
        Response::Stats(v) => Ok(v),
        other => bail!("unexpected response {other:?}"),
    }
}

fn target_identity(entry: &Entry) -> TargetCondition {
    TargetCondition::Matches {
        dev: entry.dev,
        ino: entry.ino,
    }
}

fn target_container(root: &[u8], entry: &Entry) -> ContainerGuard {
    ContainerGuard {
        root: root.to_vec(),
        dev: entry.dev,
        ino: entry.ino,
    }
}

#[cfg(debug_assertions)]
fn hold_after_target_precondition_for_test(args: &Args) -> Result<()> {
    if args.interface != Interface::Rsync || args.target_existence == Existence::Any {
        return Ok(());
    }
    crate::fsops::test_race_barrier(
        "SYQ_TEST_TARGET_PRECONDITION_READY_FILE",
        "SYQ_TEST_TARGET_PRECONDITION_CONTINUE_FILE",
        "target precondition",
    )
}

#[cfg(not(debug_assertions))]
fn hold_after_target_precondition_for_test(_args: &Args) -> Result<()> {
    Ok(())
}

fn mkdir_root(
    conn: &mut dyn Conn,
    dst_root: &[u8],
    condition: TargetCondition,
    restricted_receiver: bool,
    preserve_permissions: bool,
) -> Result<Entry> {
    for ops in mkdir_root_batches(
        dst_root,
        condition,
        restricted_receiver,
        preserve_permissions,
    ) {
        match ok(conn.call(Request::Apply { ops, guard: None })?, "mkdir")? {
            Response::Applied(errs) => mkdir_apply_result(errs)?,
            other => bail!("unexpected response {other:?}"),
        }
    }
    stat_one(conn, dst_root, false)?
        .filter(|entry| entry.kind == Kind::Dir)
        .with_context(|| format!("created target {} is not a directory", display(dst_root)))
}

fn mkdir_apply_result(errors: Vec<Option<WireError>>) -> Result<()> {
    if let Some(error) = errors.into_iter().flatten().next() {
        return Err(endpoint_error(error)).context("mkdir");
    }
    Ok(())
}

fn mkdir_root_batches(
    dst_root: &[u8],
    condition: TargetCondition,
    restricted_receiver: bool,
    preserve_permissions: bool,
) -> Vec<Vec<Op>> {
    let mut batches = vec![vec![Op::Mkdir {
        path: dst_root.to_vec(),
        mode: 0o755,
        condition,
    }]];
    if restricted_receiver && !preserve_permissions {
        // Keep this in a later receiver call. The restricted authority must
        // observe the directory after Mkdir so it can distinguish HostB's
        // kernel-inherited setgid bit from HostA's untrusted mode proposal.
        batches.push(vec![Op::SetMeta {
            path: dst_root.to_vec(),
            meta: Meta {
                mode: 0o755,
                uid: 0,
                gid: 0,
                mtime: 0,
                mtime_nsec: 0,
            },
            flags: flags::RECEIVER_MODE,
            condition: TargetCondition::Any,
        }]);
    }
    batches
}

fn directory_creation_batches(ops: Vec<Op>, restricted_receiver: bool) -> Vec<Vec<Op>> {
    if ops.is_empty() {
        return Vec::new();
    }
    if !restricted_receiver {
        return vec![ops];
    }

    // A restricted receiver authorizes the whole request before executing any
    // operation in it. Send parents first so receiver-side mode policy can
    // inspect every child path without depending on an unexecuted Mkdir from
    // the same request. Siblings retain the existing parallel batch behavior.
    let mut by_depth: std::collections::BTreeMap<usize, Vec<Op>> =
        std::collections::BTreeMap::new();
    for op in ops {
        let Op::Mkdir { path, .. } = &op else {
            unreachable!("directory creation batch contains a non-Mkdir operation")
        };
        let depth = path.iter().filter(|&&byte| byte == b'/').count();
        by_depth.entry(depth).or_default().push(op);
    }
    by_depth.into_values().collect()
}

/// Lexically canonical spelling of a root path: `.` components and duplicate
/// or trailing slashes dropped (`dst/.` -> `dst`, `dst//x` -> `dst/x`), the
/// leading `/` or `~` kept, a path that is nothing but dots left as `.`.
/// Trailing-slash semantics are read off the Location before this runs.
fn clean_root(p: &[u8]) -> PathBytes {
    let absolute = p.starts_with(b"/");
    let mut out: PathBytes = if absolute { b"/".to_vec() } else { Vec::new() };
    for comp in p.split(|&b| b == b'/') {
        if comp.is_empty() || comp == b"." {
            continue;
        }
        if !out.is_empty() && !out.ends_with(b"/") {
            out.push(b'/');
        }
        out.extend_from_slice(comp);
    }
    if out.is_empty() {
        out.extend_from_slice(if absolute { b"/" } else { b"." });
    }
    out
}

fn stat_one(conn: &mut dyn Conn, path: &[u8], follow: bool) -> Result<Option<Entry>> {
    Ok(stat_many(conn, vec![path.to_vec()], follow)?
        .pop()
        .flatten())
}

fn stat_one_registered(
    conn: &mut dyn Conn,
    path: &[u8],
    source: &RegisteredPath,
    follow: bool,
) -> Result<Option<Entry>> {
    Ok(stat_many_registered(
        conn,
        vec![path.to_vec()],
        Some(vec![source.clone()]),
        follow,
    )?
    .pop()
    .flatten())
}

fn check_operator_directory(
    conn: &mut dyn Conn,
    path: &[u8],
    allow_missing: bool,
    symlink_policy: OperatorSymlinkPolicy,
) -> Result<Option<DirectoryAnchor>> {
    match ok(
        conn.call(Request::CheckOperatorDirectory {
            path: path.to_vec(),
            allow_missing,
            symlink_policy,
        })?,
        "operator path",
    )? {
        Response::DirectorySelection(selection) => Ok(selection),
        other => bail!("unexpected response {other:?}"),
    }
}

fn check_operator_directory_ancestry(
    conn: &mut dyn Conn,
    checks: Vec<DirectoryAncestryCheck>,
) -> Result<Vec<Vec<DirectoryRelation>>> {
    match ok(
        conn.call(Request::CheckOperatorDirectoryAncestry { checks })?,
        "destination ancestry",
    )? {
        Response::DirectoryRelations(relations) => Ok(relations),
        other => bail!("unexpected response {other:?}"),
    }
}

fn register_source_roots(
    conn: &mut dyn Conn,
    sources: &[Location],
    args: &Args,
    shared_workers: usize,
    independent_handoff_workers: usize,
) -> Result<Vec<RegisteredSourceRoot>> {
    let source_is_local = !sources.iter().any(Location::is_remote);
    let base = if let Some(path) = &args.native_source_root {
        SourceRootBase {
            path: Some(path.clone()),
            confined: true,
        }
    } else {
        SourceRootBase {
            path: args.native_source_cwd.clone(),
            confined: false,
        }
    };
    let selections = sources
        .iter()
        .map(|source| SourceRootSelection {
            path: source.path.clone(),
            // --files-from has always required its source operand to resolve
            // to a directory. Descendant-link policy remains unchanged and is
            // deliberately not encoded by this selected-root flag.
            follow_root: args.files_from.is_some()
                || source.follows_root(args.follows_native_source_paths()),
        })
        .collect();
    match ok(
        conn.call(Request::RegisterSourceRoots {
            base,
            selections,
            symlink_policy: source_operator_symlink_policy(args, source_is_local),
            allow_unconfined_paths: false,
            shared_workers,
            independent_handoff_workers,
        })?,
        "register source roots",
    )? {
        Response::SourceRootsRegistered(roots) if roots.len() == sources.len() => Ok(roots),
        Response::SourceRootsRegistered(roots) => bail!(
            "source endpoint registered {} roots for {} selections",
            roots.len(),
            sources.len()
        ),
        other => bail!("unexpected response {other:?}"),
    }
}

fn create_operator_directory(
    conn: &mut dyn Conn,
    condition: TargetCondition,
) -> Result<DirectoryAnchor> {
    match ok(
        conn.call(Request::CreateOperatorDirectory {
            mode: 0o755,
            require_absent: condition == TargetCondition::Absent,
        })?,
        "create destination directory",
    )? {
        Response::DirectorySelection(Some(selection)) => Ok(selection),
        other => bail!("unexpected response {other:?}"),
    }
}

fn destination_filesystem_info(
    conn: &mut dyn Conn,
    check_empty: bool,
    target: Option<DestinationFilesystemTarget>,
) -> Result<Option<DestinationFilesystemInfo>> {
    match conn.call(Request::DestinationFilesystemInfo {
        check_empty,
        target,
    })? {
        Response::DestinationFilesystemInfo(info) => Ok(Some(info)),
        // Not every filesystem or receiver topology can expose meaningful
        // capacity. Absence of the optimization must not block the copy.
        Response::EndpointError(_) | Response::Err(_) => Ok(None),
        other => bail!("unexpected response {other:?}"),
    }
}

fn activate_control_destination(
    conn: &mut dyn Conn,
    selection: DirectoryAnchor,
    request_prefix: PathBytes,
) -> Result<DestinationAnchor> {
    match ok(
        conn.call(Request::AnchorDestination {
            expected_dev: selection.dev,
            expected_ino: selection.ino,
            request_prefix: request_prefix.clone(),
        })?,
        "anchor destination root",
    )? {
        Response::DestinationRegistered(ticket) => Ok(DestinationAnchor {
            destination: RegisteredDestinationRoot {
                ticket,
                request_prefix,
            },
            dev: selection.dev,
            ino: selection.ino,
        }),
        other => bail!("unexpected response {other:?}"),
    }
}

/// Pipeline the existing v0.3.2 requests: selection and capacity inspection
/// are read-only, and anchoring registers a descriptor without changing files.
/// The receiver checks the observed inode before issuing the worker ticket.
fn prepare_existing_destination(
    conn: &mut dyn Conn,
    path: &[u8],
    symlink_policy: OperatorSymlinkPolicy,
    expected: &Entry,
    request_prefix: PathBytes,
) -> Result<(
    Option<DirectoryAnchor>,
    Option<DestinationFilesystemInfo>,
    DestinationAnchor,
)> {
    conn.send(Request::CheckOperatorDirectory {
        path: path.to_vec(),
        allow_missing: false,
        symlink_policy,
    })?;
    conn.send(Request::DestinationFilesystemInfo {
        check_empty: true,
        target: None,
    })?;
    conn.send(Request::AnchorDestination {
        expected_dev: expected.dev,
        expected_ino: expected.ino,
        request_prefix: request_prefix.clone(),
    })?;
    // Drain all replies even when a receiver check fails: pooled control
    // sessions must never keep an unread response from a preceding copy.
    let selection = conn.recv();
    let filesystem = conn.recv();
    let anchor = conn.recv();
    let selection = match ok(selection?, "operator path")? {
        Response::DirectorySelection(selection) => selection,
        other => bail!("unexpected response {other:?}"),
    };
    let filesystem = match filesystem? {
        Response::DestinationFilesystemInfo(info) => Some(info),
        Response::EndpointError(_) | Response::Err(_) => None,
        other => bail!("unexpected response {other:?}"),
    };
    let anchor = match ok(anchor?, "anchor destination root")? {
        Response::DestinationRegistered(ticket) => DestinationAnchor {
            destination: RegisteredDestinationRoot {
                ticket,
                request_prefix,
            },
            dev: expected.dev,
            ino: expected.ino,
        },
        other => bail!("unexpected response {other:?}"),
    };
    Ok((selection, filesystem, anchor))
}

fn ancestor_prefixes(path: &[u8]) -> impl Iterator<Item = &[u8]> {
    path.iter()
        .enumerate()
        .filter_map(|(index, byte)| (*byte == b'/').then_some(&path[..index]))
}

fn parent_path(path: &[u8]) -> PathBytes {
    match path.iter().rposition(|byte| *byte == b'/') {
        Some(0) => b"/".to_vec(),
        Some(index) => path[..index].to_vec(),
        None => b".".to_vec(),
    }
}

/// Fetch the destination root's entry and canonical spelling in one network
/// turn. They are independent read-only queries; sending both before waiting
/// avoids an extra RTT when expanding a remote bare-home destination.
fn stat_and_canonicalize(
    conn: &mut dyn Conn,
    path: &[u8],
) -> Result<(Option<Entry>, std::path::PathBuf)> {
    conn.send(Request::StatMany {
        paths: vec![path.to_vec()],
        sources: None,
        follow: false,
        guard: None,
    })?;
    conn.send(Request::Canonicalize {
        path: path.to_vec(),
        guard: None,
    })?;
    // Consume both replies before interpreting either endpoint error so the
    // reusable control stream cannot be left one response behind.
    let stat_response = conn.recv();
    let canonical_response = conn.recv();
    let entry = match ok(stat_response?, "stat")? {
        Response::Stats(mut entries) if entries.len() == 1 => entries.pop().flatten(),
        other => bail!("unexpected response {other:?}"),
    };
    let canonical = match ok(canonical_response?, "canonicalize")? {
        Response::Path(path) => crate::fsops::resolve(&path),
        other => bail!("unexpected response {other:?}"),
    };
    Ok((entry, canonical))
}

/// Run a source scan whose batches feed the planner, and remember whether it
/// reported any problem — `scan_warned` is what gates --delete, so every
/// source walk must go through here.
fn scan_into_planner(
    pl: &mut Planner<'_>,
    src: &mut dyn Conn,
    root: &[u8],
    source: Option<&RegisteredPath>,
    follow_root: bool,
    ignore: &[String],
    mut f: impl FnMut(&mut Planner<'_>, Vec<Entry>) -> Result<()>,
) -> Result<()> {
    let progress = pl.progress;
    let quiet = pl.opts.quiet;
    let report_ignored = pl.opts.dry_run;
    let warned = std::cell::Cell::new(false);
    let res = src.scan(
        root,
        source,
        follow_root,
        ignore,
        report_ignored,
        &mut |batch| f(pl, batch),
        &mut |paths| {
            progress
                .paths_ignored
                .fetch_add(paths.len() as u64, Relaxed);
            Ok(())
        },
        &mut |w| {
            // "skipping …" is a notice (nothing the copy owes is missing);
            // anything else from the scanner means an entry was lost.
            if w.starts_with("skipping ") {
                if !quiet {
                    progress.eprintln(&format!("syq: {w}"));
                }
            } else {
                warned.set(true);
                progress.error(&format!("syq: {w}"));
            }
        },
    );
    if warned.get() {
        pl.scan_warned = true;
    }
    res
}

/// If `entry` is a symlink whose (possibly chained) target is a directory,
/// return the target path and entry; otherwise return the original pair.
fn follow_dir_symlink(
    conn: &mut dyn Conn,
    path: &[u8],
    entry: Option<Entry>,
) -> Result<(PathBytes, Option<Entry>)> {
    let Some(first) = entry.as_ref().filter(|e| e.kind == Kind::Symlink) else {
        return Ok((path.to_vec(), entry));
    };
    let mut cur_path = path.to_vec();
    let mut cur = first.clone();
    for _ in 0..16 {
        let Some(target) = cur.link.clone() else {
            break;
        };
        let next_path = if target.starts_with(b"/") {
            target
        } else {
            let parent = cur_path
                .iter()
                .rposition(|&c| c == b'/')
                .map(|i| cur_path[..i].to_vec())
                .unwrap_or_default();
            join(&parent, &target)
        };
        match stat_one(conn, &next_path, false)? {
            Some(e) if e.kind == Kind::Dir => return Ok((next_path, Some(e))),
            Some(e) if e.kind == Kind::Symlink => {
                cur = e;
                cur_path = next_path;
            }
            _ => break,
        }
    }
    Ok((path.to_vec(), entry))
}

/// Resolve a symlink used as a directly supplied native container. Explicit
/// Destination following selects the referent regardless of its type; the caller then
/// requires the result to be a directory. Placement forms that allow a
/// missing target may create the referent of a dangling chain.
fn follow_container_symlink(
    conn: &mut dyn Conn,
    path: &[u8],
    entry: Option<Entry>,
    allow_missing: bool,
) -> Result<(PathBytes, Option<Entry>)> {
    let Some(mut current) = entry else {
        return Ok((path.to_vec(), None));
    };
    let mut current_path = path.to_vec();
    for _ in 0..40 {
        if current.kind != Kind::Symlink {
            return Ok((current_path, Some(current)));
        }
        let target = current
            .link
            .as_deref()
            .context("symlink entry did not include its target")?;
        current_path = if target.starts_with(b"/") {
            target.to_vec()
        } else {
            join(&parent_path(&current_path), target)
        };
        match stat_one(conn, &current_path, false)? {
            Some(entry) => current = entry,
            None if allow_missing => return Ok((current_path, None)),
            None => {
                bail!(
                    "operator path {} resolves through a dangling symlink",
                    display(path)
                )
            }
        }
    }
    bail!("too many symlink levels in operator path {}", display(path))
}

fn display(p: &[u8]) -> String {
    crate::completion_details::display_bytes(p)
}

fn display_directory(p: &[u8]) -> String {
    let mut shown = display(p);
    if !shown.ends_with('/') {
        shown.push('/');
    }
    shown
}

fn kind_label(kind: Kind) -> &'static str {
    match kind {
        Kind::Dir => "directory",
        Kind::File => "regular file",
        Kind::Symlink => "symlink",
        Kind::Fifo => "FIFO",
        Kind::Socket => "socket",
        Kind::CharDev => "character device",
        Kind::BlockDev => "block device",
        Kind::Other => "unsupported entry",
    }
}

fn special_creation_supported(destination_supports_sockets: bool, kind: Kind) -> bool {
    kind != Kind::Socket || destination_supports_sockets
}

fn metadata_differs(source: &Entry, destination: &Entry, flags: u8) -> bool {
    (flags & flags::MODE != 0 && source.mode & 0o7777 != destination.mode & 0o7777)
        || (flags & flags::OWNER != 0 && source.uid != destination.uid)
        || (flags & flags::GROUP != 0 && source.gid != destination.gid)
        || (flags & flags::TIMES != 0
            && (source.mtime != destination.mtime
                || !destination_fraction_matches(source.mtime_nsec, destination.mtime_nsec)))
}

fn publication_metadata_flags(requested: u8) -> u8 {
    if requested & flags::MODE != 0 {
        requested
    } else {
        requested | flags::RECEIVER_MODE
    }
}

fn display_location(loc: &Location, path: &[u8]) -> String {
    let path = display(path);
    let Some(host) = &loc.host else {
        return path;
    };
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.clone()
    };
    let endpoint = match &loc.user {
        Some(user) => format!("{user}@{host}"),
        None => host,
    };
    match loc.port {
        Some(port) => format!("{endpoint}:{port}:{path}"),
        None => format!("{endpoint}:{path}"),
    }
}

fn display_plan_source(loc: &Location, args: &Args) -> String {
    if !loc.is_remote() {
        if let Some(host) = &args.plan_source_host {
            return format!("{host}:{}", display(&loc.path));
        }
    }
    display_location(loc, &loc.path)
}

fn display_plan_target(loc: &Location, path: &[u8], args: &Args) -> String {
    if !loc.is_remote() {
        if let Some(host) = &args.plan_source_host {
            return format!("{host}:{}", display(path));
        }
    }
    display_location(loc, path)
}

fn remote_data_transport(spec: &RemoteSpec) -> &'static str {
    match spec.tcp.lock().unwrap().as_ref() {
        Some(info) if info.key.is_some() => "encrypted TCP",
        Some(_) => "plaintext TCP",
        None => "ssh",
    }
}

fn real_remote_spec(endpoint: &Endpoint) -> Option<&RemoteSpec> {
    match endpoint {
        Endpoint::Remote(spec) if !spec.local_process => Some(spec),
        Endpoint::Local { .. } | Endpoint::Remote(_) => None,
    }
}

fn selected_route(src: &Endpoint, dst: &Endpoint, args: &Args) -> String {
    let route = match (real_remote_spec(src), real_remote_spec(dst)) {
        (None, None) => args.plan_source_host.as_ref().map_or_else(
            || "local filesystem".to_string(),
            |host| format!("local filesystem on {host}"),
        ),
        (None, Some(spec)) => match &args.plan_source_host {
            Some(source) => format!(
                "{} from {source} to {}",
                remote_data_transport(spec),
                spec.label()
            ),
            None => format!("{} to {}", remote_data_transport(spec), spec.label()),
        },
        (Some(spec), None) => {
            format!("{} from {}", remote_data_transport(spec), spec.label())
        }
        (Some(source), Some(target)) => format!(
            "{} from {} through this machine, {} to {}",
            remote_data_transport(source),
            source.label(),
            remote_data_transport(target),
            target.label()
        ),
    };
    let remote = src.is_remote() || dst.is_remote();
    let unit = |n: usize| match (remote, n) {
        (true, 1) => "connection",
        (true, _) => "connections",
        (false, 1) => "worker",
        (false, _) => "workers",
    };
    let concurrency = if args.connections_default {
        format!(
            "{} initial {} (auto-tuned)",
            args.connections,
            unit(args.connections)
        )
    } else {
        format!("{} {} (fixed)", args.connections, unit(args.connections))
    };
    format!("{route}; {concurrency}")
}

#[derive(Clone)]
struct FreshCapacityPlan {
    device: u64,
    target: Option<DestinationFilesystemTarget>,
    root_existed: bool,
    logical_bytes: u64,
    objects: u64,
    overflowed: bool,
}

fn fresh_capacity_error(capacity: FreshCapacityAssessment) -> anyhow::Error {
    let mut shortages = Vec::new();
    if capacity.byte_shortage() {
        shortages.push(format!(
            "{} of logical file data is required but only {} is available",
            human(capacity.logical_bytes),
            human(capacity.available_bytes)
        ));
    }
    if capacity.inode_shortage() {
        shortages.push(format!(
            "{} destination objects are required but only {} inodes are available",
            commas(capacity.objects),
            commas(capacity.available_inodes.unwrap_or_default())
        ));
    }
    anyhow::Error::new(std::io::Error::from_raw_os_error(libc::ENOSPC)).context(format!(
        "fresh destination capacity preflight failed: {}",
        shortages.join("; ")
    ))
}

#[cfg(test)]
mod tests;

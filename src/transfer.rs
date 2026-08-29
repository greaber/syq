//! The orchestrator: scan, diff, schedule, and the per-worker transfer loop.

use crate::bwlimit::BandwidthLimit;
use crate::cli::{parse_rsh, parse_size, Args, Existence, Interface, Location, Placement};
use crate::conn::{
    ok, Conn, DataAddressSource, DataTransport, Endpoint, RemoteSpec, TcpCandidate, TcpPairStats,
};
use crate::fsops::{is_partial_name, join};
use crate::progress::{commas, human, Progress, WorkerStatus};
use crate::proto::*;
use crate::sched::{FileJob, Item, RangeHandle, Sched};
use crate::tune::{self, Gate};
use anyhow::{bail, Context, Result};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
use std::sync::Mutex;
use xxhash_rust::xxh3::xxh3_64;

const WINDOW: usize = 4;
const MAX_ATTEMPTS: u32 = 3;
pub const LOCAL_DEFAULT_CONNECTIONS: usize = 32;
const FAST_BATCH_FILES: usize = 128;
// Larger batches trade filesystem overlap for fewer request/ack turns. On the
// measured 262 ms path, 4,096 one-byte files at eight workers improved from a
// 9.68 s to an 8.72 s median at 512; keep the change confined to high RTT TCP.
const HIGH_RTT_FAST_BATCH_FILES: usize = 512;
const HIGH_RTT_US: u64 = 100_000;
const FAST_BATCH_BYTES: u64 = 16 << 20;
const CONNECTION_RECOVERY_ATTEMPTS: u32 = 3;

fn fast_batch_file_limit(src_rtt_us: Option<u64>, dst_rtt_us: Option<u64>) -> usize {
    if src_rtt_us
        .into_iter()
        .chain(dst_rtt_us)
        .any(|rtt| rtt >= HIGH_RTT_US)
    {
        HIGH_RTT_FAST_BATCH_FILES
    } else {
        FAST_BATCH_FILES
    }
}

pub struct Opts {
    pub block: u64,
    pub flags: u8,
    pub recursive: bool,
    pub links: bool,
    pub perms: bool,
    pub devices: bool,
    pub checksum: bool,
    pub verify_only: bool,
    pub inplace: bool,
    pub same_host: bool,
    pub dst_remote: bool,
    pub dry_run: bool,
    pub quiet: bool,
    pub verbose: u8,
    pub umask: u32,
    pub partial_id: std::sync::OnceLock<PartialId>,
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
    /// --existing: never create a destination path that doesn't exist.
    pub existing: bool,
    /// --max-size / --min-size: regular files outside the range are not transferred.
    pub max_size: Option<u64>,
    pub min_size: Option<u64>,
}

pub fn endpoint(loc: &Location, args: &Args) -> Result<Endpoint> {
    Ok(match &loc.host {
        None => Endpoint::Local,
        Some(h) => Endpoint::Remote(RemoteSpec {
            user: loc.user.clone(),
            host: h.clone(),
            rsh: parse_rsh(&args.rsh)?,
            syq_path: args.syq_path.clone(),
            auto_helper: args.syq_path.is_none() && !args.no_bootstrap,
            helper_install: Default::default(),
            quiet: args.quiet,
            tcp: Default::default(),
            diagnostics: Default::default(),
        }),
    })
}

/// Open a control connection. It bypasses the data-connection connect
/// limiter: the scan, and therefore every worker, waits on it.
pub fn connect_ctl(ep: &Endpoint, args: &Args) -> Result<Box<dyn Conn>> {
    match ep {
        Endpoint::Local => ep.connect(args.compress),
        Endpoint::Remote(spec) => spec
            .connect_with(args.compress, false)
            .map(|c| Box::new(c) as Box<dyn Conn>),
    }
}

fn parse_ports(s: &str) -> Result<(u16, u16)> {
    let (a, b) = s.split_once('-').unwrap_or((s, s));
    let lo: u16 = a
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("bad port range {s:?}"))?;
    let hi: u16 = b
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("bad port range {s:?}"))?;
    if hi < lo {
        bail!("bad port range {s:?}");
    }
    Ok((lo, hi))
}

fn data_address(address: &str, port: u16) -> String {
    if address.contains(':') {
        format!("[{address}]:{port}")
    } else {
        format!("{address}:{port}")
    }
}

fn link_speed(speed_mbps: u32) -> String {
    if speed_mbps == 0 {
        "link speed unknown".to_string()
    } else if speed_mbps.is_multiple_of(1000) {
        format!("{} Gbit/s advertised", speed_mbps / 1000)
    } else {
        format!("{speed_mbps} Mbit/s advertised")
    }
}

fn candidate_status(candidate: &TcpCandidate, fastest: u32) -> String {
    if !candidate.reachable {
        return "not reachable".to_string();
    }
    let speed = link_speed(candidate.speed_mbps);
    if candidate.selected {
        return format!("reachable, {speed}, selected by preflight");
    }
    let reason = if fastest == 0 {
        "link speeds unknown; first reachable path preferred"
    } else if candidate.speed_mbps == 0 {
        "a faster advertised path was available"
    } else {
        "less than half the fastest advertised link speed"
    };
    format!("reachable, {speed}, not selected ({reason})")
}

fn one_line(message: &str) -> String {
    message
        .lines()
        .map(str::trim)
        .collect::<Vec<_>>()
        .join("; ")
}

fn print_remote_diagnostics(spec: &RemoteSpec, args: &Args) {
    let diagnostics = spec.diagnostics();
    eprintln!("syq: {}:", spec.label());
    if let Some(peer) = &diagnostics.peer {
        eprintln!(
            "  control: connected via {}; remote {}",
            spec.remote_shell_name(),
            peer.platform
        );
        let helper_mode = if spec.auto_helper {
            if *spec.helper_install.lock().unwrap() {
                "managed; installed now"
            } else {
                "managed helper cache"
            }
        } else if spec.syq_path.is_some() {
            "--syq-path"
        } else {
            "remote PATH (--no-bootstrap)"
        };
        eprintln!("  helper: {} ({helper_mode})", peer.identity);
    }

    if let Some(probe) = &diagnostics.tcp_probe {
        let fastest = probe
            .candidates
            .iter()
            .filter(|candidate| candidate.reachable)
            .map(|candidate| candidate.speed_mbps)
            .max()
            .unwrap_or(0);
        for candidate in &probe.candidates {
            let source = if candidate.source == DataAddressSource::SshTarget {
                " (SSH target)"
            } else {
                ""
            };
            eprintln!(
                "  TCP {}{source}: {}",
                data_address(&candidate.address, probe.port),
                candidate_status(candidate, fastest)
            );
        }
        let remote = probe.congestion_control.as_deref().unwrap_or("unavailable");
        match &args.tcp_congestion {
            Some(requested) => eprintln!(
                "  congestion control: remote listener {remote}; local data sockets request {requested}"
            ),
            None => eprintln!("  congestion control: remote listener {remote} (host default)"),
        }
    }

    let route_state = if args.dry_run {
        "planned for a real transfer"
    } else {
        "planned"
    };
    let transport = spec.data_transport();
    match transport {
        DataTransport::EncryptedTcp | DataTransport::PlaintextTcp => {
            let name = if transport == DataTransport::EncryptedTcp {
                "encrypted TCP"
            } else {
                "plaintext TCP"
            };
            eprintln!("  transport: {name} {route_state} (reachability preflight passed)");
        }
        DataTransport::Ssh => {
            let tcp_failure = spec
                .tcp
                .lock()
                .unwrap()
                .as_ref()
                .and_then(|info| info.failure.clone())
                .or(diagnostics.tcp_setup_error.clone());
            if args.no_tcp {
                eprintln!("  transport: SSH {route_state} (--no-tcp)");
            } else if let Some(error) = tcp_failure {
                eprintln!(
                    "  transport: SSH {route_state} (TCP unavailable: {})",
                    one_line(&error)
                );
            } else {
                eprintln!("  transport: SSH {route_state}");
            }
        }
    }
}

fn print_transport_diagnostics(args: &Args, src: &Endpoint, dst: &Endpoint) {
    if args.quiet || args.verbose < 2 {
        return;
    }
    for endpoint in [src, dst] {
        if let Endpoint::Remote(spec) = endpoint {
            print_remote_diagnostics(spec, args);
        }
    }
    let remote = src.is_remote() || dst.is_remote();
    let unit = match (remote, args.connections) {
        (true, 1) => "connection",
        (true, _) => "connections",
        (false, 1) => "worker",
        (false, _) => "workers",
    };
    let policy = if args.connections_default {
        "auto-tuned"
    } else {
        "fixed"
    };
    if !remote {
        eprintln!("syq: transport: local filesystem");
    }
    if args.dry_run {
        eprintln!(
            "syq: concurrency: a real transfer would start with {} {unit} ({policy}); dry-run starts no workers",
            args.connections
        );
    } else {
        eprintln!(
            "syq: concurrency: starting with {} {unit} ({policy})",
            args.connections
        );
    }
}

fn format_tcp_stats(pairs: &[TcpPairStats], has_ssh_data: bool) -> String {
    let sockets: Vec<&TcpSocketStats> = pairs
        .iter()
        .flat_map(|pair| {
            [pair.local.as_ref(), pair.peer.as_ref()]
                .into_iter()
                .flatten()
        })
        .collect();
    if sockets.is_empty() {
        return if has_ssh_data {
            "\n  tcp statistics: unavailable (data used SSH)".into()
        } else {
            "\n  tcp statistics: unavailable on this platform/kernel".into()
        };
    }
    // Aggregates are meaningful only when every sampled socket exposes the
    // field. Do not turn an unsupported end into a genuine zero.
    let sum = |field: fn(&TcpSocketStats) -> Option<u64>| {
        sockets
            .iter()
            .map(|stats| field(stats))
            .sum::<Option<u64>>()
    };
    let values = |field: fn(&TcpSocketStats) -> Option<u64>| {
        sockets
            .iter()
            .map(|stats| field(stats))
            .collect::<Option<Vec<u64>>>()
    };
    let bytes_sent = sum(|stats| stats.bytes_sent);
    let bytes_retransmitted = sum(|stats| stats.bytes_retransmitted);
    let segments_sent = sum(|stats| stats.segments_sent);
    let retransmissions = sum(|stats| stats.retransmissions);
    let average_rtt =
        values(|stats| stats.rtt_us).map(|rtts| rtts.iter().sum::<u64>() / rtts.len() as u64);
    let min_rtt = values(|stats| stats.min_rtt_us).and_then(|rtts| rtts.into_iter().min());
    let loss = |amount: Option<u64>, sent: Option<u64>| match amount {
        None => "unavailable".into(),
        Some(amount) => match sent {
            Some(sent) if sent > 0 => format!(
                "{} ({:.3}% of sent)",
                commas(amount),
                amount as f64 * 100.0 / sent as f64
            ),
            _ => format!("{} (percentage unavailable)", commas(amount)),
        },
    };
    let average_congestion_window = values(|stats| stats.send_cwnd_bytes)
        .map(|windows| windows.iter().sum::<u64>() / windows.len() as u64);
    let delivery_rate = sum(|stats| stats.delivery_rate);
    let busy = sum(|stats| stats.busy_time_us);
    let receive_limited = sum(|stats| stats.receive_window_limited_us);
    let send_limited = sum(|stats| stats.send_buffer_limited_us);
    let limited_percent = |limited: Option<u64>| match (limited, busy) {
        (Some(limited), Some(busy)) if busy > 0 => {
            format!("{:.1}%", limited as f64 * 100.0 / busy as f64)
        }
        _ => "unavailable".into(),
    };
    let paths = pairs
        .iter()
        .map(|pair| pair.label.as_str())
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    let mut congestion_controls = std::collections::BTreeMap::<&str, usize>::new();
    let mut unavailable_congestion_controls = 0usize;
    for socket in &sockets {
        match socket.congestion_control.as_deref() {
            Some(algorithm) => *congestion_controls.entry(algorithm).or_default() += 1,
            None => unavailable_congestion_controls += 1,
        }
    }
    let mut congestion_control = congestion_controls
        .into_iter()
        .map(|(algorithm, count)| format!("{algorithm} ({count} socket ends)"))
        .collect::<Vec<_>>();
    if unavailable_congestion_controls > 0 {
        congestion_control.push(format!(
            "unavailable ({unavailable_congestion_controls} socket ends)"
        ));
    }
    let congestion_control = congestion_control.join(", ");
    let mut output = format!(
        "\n  tcp connection lifetimes sampled: {} across {} path(s) ({} socket ends)\n  tcp congestion control: {}\n  tcp retransmissions (loss signal): {} packets, {} bytes\n  tcp RTT: current average {}, minimum {}\n  tcp congestion: average send window {}, aggregate delivery rate {}\n  tcp window-limited time: receive {}, send-buffer {}\n  tcp ECN CE deliveries: {}",
        pairs.len(),
        paths,
        sockets.len(),
        congestion_control,
        loss(retransmissions, segments_sent),
        loss(bytes_retransmitted, bytes_sent),
        average_rtt.map_or_else(|| "unavailable".into(), |value| format!("{:.2} ms", value as f64 / 1000.0)),
        min_rtt.map_or_else(|| "unavailable".into(), |value| format!("{:.2} ms", value as f64 / 1000.0)),
        average_congestion_window.map_or_else(|| "unavailable".into(), human),
        delivery_rate.map_or_else(|| "unavailable".into(), |value| format!("{}/s", human(value))),
        limited_percent(receive_limited),
        limited_percent(send_limited),
        sum(|stats| stats.ecn_ce_delivered)
            .map_or_else(|| "unavailable".into(), commas),
    );
    if has_ssh_data {
        output.push_str("\n  ssh data connections: kernel TCP loss statistics unavailable");
    }
    output
}

/// The canonical form of a path (symlinks and `..` resolved the way the kernel
/// does), normalized by the endpoint that holds it. Used for the job identity —
/// so `host:dir`, `host:./dir` and `host:/home/u/dir` name one job — and for
/// the copy-into-itself check.
fn canonical_path(ctl: &mut dyn Conn, path: &[u8], remote: bool) -> Result<std::path::PathBuf> {
    if !remote {
        return Ok(crate::fsops::normalize(&crate::fsops::resolve(path)));
    }
    match ok(
        ctl.call(Request::Canonicalize {
            path: path.to_vec(),
        })?,
        "canonicalize",
    )? {
        Response::Path(p) => Ok(crate::fsops::resolve(&p)),
        other => bail!("unexpected response {other:?}"),
    }
}

/// Encode the content/metadata-affecting options into the job identity.
fn semantic_flags(opts: &Opts, args: &Args, srcs: &[Location]) -> String {
    let source_modes: Vec<&str> = srcs
        .iter()
        .map(|source| match source.selection {
            crate::cli::SourceSelection::Rsync => "rsync",
            crate::cli::SourceSelection::Named => "named-follow",
            crate::cli::SourceSelection::Contents => "contents-follow",
            crate::cli::SourceSelection::NamedNoFollow => "named-no-follow",
        })
        .collect();
    let mut flags = serde_json::json!({
        "partial_format": 1,
        "recursive": opts.recursive,
        "links": opts.links,
        "perms": opts.flags & flags::MODE != 0,
        "times": opts.flags & flags::TIMES != 0,
        "group": opts.flags & flags::GROUP != 0,
        "owner": opts.flags & flags::OWNER != 0,
        "devices": opts.devices,
        "inplace": args.inplace,
        "block_size": opts.block,
        "ignore": opts.ignore,
    });
    // Keep the established compatibility identity byte-for-byte stable so an
    // upgrade does not orphan resumable sidecars or checkpoints.
    if srcs
        .iter()
        .any(|source| source.selection != crate::cli::SourceSelection::Rsync)
    {
        flags["source_modes"] = serde_json::json!(source_modes);
    }
    flags.to_string()
}

/// The endpoint half of a job identity: `user@host` (the user matters — two
/// accounts on one host see different destinations), or `local`.
fn endpoint_identity(l: &Location) -> String {
    match (&l.user, &l.host) {
        (_, None) => "local".into(),
        (Some(u), Some(h)) => format!("{u}@{h}"),
        (None, Some(h)) => h.clone(),
    }
}

/// Load and, for a real copy, open the explicitly requested checkpoint.
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
    require_directory: bool,
    sub: &'a [u8],
}

fn copy_identity(
    args: &Args,
    srcs: &[Location],
    dst: &Location,
    src_ctl: &mut dyn Conn,
    dst_ctl: &mut dyn Conn,
    dst_canonical: Option<std::path::PathBuf>,
    opts: &Opts,
) -> Result<String> {
    let mut src_roots: Vec<(String, bool)> = Vec::with_capacity(srcs.len());
    for source in srcs {
        let path = canonical_path(src_ctl, &source.path, source.is_remote())?;
        src_roots.push((
            path.to_string_lossy().into_owned(),
            source.copies_contents(),
        ));
    }
    let dst_root = match dst_canonical {
        Some(path) => path,
        None => canonical_path(dst_ctl, &dst.path, dst.is_remote())?,
    }
    .to_string_lossy()
    .into_owned();
    Ok(crate::checkpoint::job_identity(
        &endpoint_identity(&srcs[0]),
        &src_roots,
        &endpoint_identity(dst),
        &dst_root,
        &semantic_flags(opts, args, srcs),
    ))
}

fn checkpoint_setup(
    args: &Args,
    srcs: &[Location],
    dst: DestinationRoot<'_>,
    dst_ctl: &mut dyn Conn,
    identity: &str,
) -> Result<Option<CheckpointState>> {
    use crate::checkpoint::Checkpoint;
    let Some(path) = args.checkpoint.as_deref().map(std::path::Path::new) else {
        return Ok(None);
    };
    let (checkpoint, loaded) = if args.dry_run {
        let loaded = Checkpoint::load(path)?;
        if let Some(ex) = &loaded.existing_identity {
            if ex != identity {
                bail!(
                    "checkpoint {} describes a different copy; choose another path or remove it",
                    path.display()
                );
            }
        }
        (None, loaded)
    } else {
        let (checkpoint, loaded) = Checkpoint::open(path, identity)?;
        (Some(checkpoint), loaded)
    };
    if !loaded.completed.is_empty() {
        if !dst.existed {
            bail!(
                "checkpoint {} records completed files, but destination {} is missing; remove the checkpoint to restart",
                path.display(),
                display(dst.path)
            );
        }
        if dst.entry_is_dir {
            for source in srcs.iter().filter(|source| !source.copies_contents()) {
                let basename = source.basename();
                if basename.is_empty() {
                    continue;
                }
                let prefix = basename.as_slice();
                let has_completed_path = loaded.completed.keys().any(|completed| {
                    completed == prefix
                        || completed
                            .strip_prefix(prefix)
                            .is_some_and(|suffix| suffix.starts_with(b"/"))
                });
                if has_completed_path {
                    let target = join(dst.path, prefix);
                    if stat_one(dst_ctl, &target, false)?.is_none() {
                        bail!(
                            "checkpoint {} records completed files, but destination target {} is missing; remove the checkpoint to restart",
                            path.display(),
                            display(&target)
                        );
                    }
                }
            }
        }
    }
    let checkpoint = checkpoint.map(|checkpoint| {
        let checkpoint = std::sync::Arc::new(checkpoint);
        checkpoint.spawn_flusher();
        checkpoint
    });
    Ok(Some(CheckpointState {
        checkpoint,
        completed: std::sync::Arc::new(loaded.completed),
    }))
}

/// Explicit checkpoint state for one transfer.
struct CheckpointState {
    checkpoint: Option<std::sync::Arc<crate::checkpoint::Checkpoint>>,
    completed: std::sync::Arc<std::collections::HashMap<PathBytes, crate::checkpoint::Completed>>,
}

impl Drop for CheckpointState {
    fn drop(&mut self) {
        if let Some(checkpoint) = &self.checkpoint {
            let _ = checkpoint.close();
        }
    }
}

/// Shared with workers after checkpoint setup and before planning enqueues work.
#[derive(Default)]
struct CheckpointShared {
    checkpoint: Option<std::sync::Arc<crate::checkpoint::Checkpoint>>,
}
type CheckpointSlot = std::sync::Arc<std::sync::OnceLock<CheckpointShared>>;

pub fn debug() -> bool {
    std::env::var_os("SYQ_DEBUG").is_some()
}

fn read_umask() -> u32 {
    unsafe {
        let m = libc::umask(0o022);
        libc::umask(m);
        m as u32
    }
}

pub fn run(args: Args) -> Result<i32> {
    let mut args = args;
    // A block becomes one WriteRange frame, so it must stay well under MAX_FRAME.
    let block = parse_size(&args.block_size)?.clamp(64 * 1024, 64 << 20);
    let min_split = parse_size(&args.min_split)?;
    let max_size = args.max_size.as_deref().map(parse_size).transpose()?;
    let min_size = args.min_size.as_deref().map(parse_size).transpose()?;
    let bwlimit = (args.bwlimit_bytes > 0)
        .then_some(args.bwlimit_bytes)
        .map(BandwidthLimit::new)
        .map(Arc::new);
    let locs: Vec<Location> = if args.locations.is_empty() {
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
    let (_, raw_source_operands) = args.paths.split_last().unwrap();
    let (dst, original_srcs) = locs.split_last().unwrap();
    let source_operand_count = args
        .direct_source_operand_count
        .unwrap_or_else(|| {
            if args.locations.is_empty() {
                raw_source_operands.len()
            } else {
                original_srcs.len()
            }
        });
    if source_operand_count < original_srcs.len() {
        bail!("invalid direct source-operand count");
    }
    for s in original_srcs {
        if !s.same_host(&original_srcs[0]) {
            bail!("all sources must be on the same host");
        }
    }
    if args.files_from.is_some() && source_operand_count > 1 {
        bail!("--files-from takes exactly one source directory");
    }
    // Rsync's file-list cleanup collapses an exactly repeated source. Key that
    // decision on the raw operands, before parsing has normalized spellings,
    // while retaining original multiplicity for destination placement:
    // `file file new-dest` still creates a directory like other multi-source
    // commands.
    let multiple_source_operands = source_operand_count > 1;
    let srcs: Vec<Location> = if args.interface != Interface::Rsync
        || args.direct_sources_prededuplicated
    {
        original_srcs.to_vec()
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
    if let Some(checkpoint) = args.checkpoint.as_deref() {
        let checkpoint = crate::fsops::normalize(std::path::Path::new(checkpoint));
        for source in srcs.iter().filter(|source| !source.is_remote()) {
            let root = crate::fsops::normalize(&crate::fsops::resolve(&source.path));
            if checkpoint.starts_with(&root) {
                bail!(
                    "checkpoint {} must not be inside local source {}",
                    checkpoint.display(),
                    root.display()
                );
            }
        }
        if !dst.is_remote() {
            let root = crate::fsops::normalize(&crate::fsops::resolve(&dst.path));
            if checkpoint.starts_with(&root) {
                bail!(
                    "checkpoint {} must not be inside local destination {}",
                    checkpoint.display(),
                    root.display()
                );
            }
        }
    }
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
    let src_ep = endpoint(&srcs[0], &args)?;
    let dst_ep = endpoint(dst, &args)?;
    if args.tcp_congestion.is_some() && !src_ep.is_remote() && !dst_ep.is_remote() {
        bail!("--tcp-congestion applies only to copies with a remote endpoint");
    }
    // TCP data connections are the default (auto-selecting the fastest reachable
    // NIC and falling back to ssh if unreachable); --no-tcp forces ssh data.
    // Local<->local needs no data plane at all.
    let use_tcp = !args.no_tcp && (src_ep.is_remote() || dst_ep.is_remote());
    // Without -j the worker count is tuned while the transfer runs (see tune.rs);
    // start conservatively until TCP reachability has been established below.
    let autotune = args.connections_default;
    if autotune {
        args.connections = if src_ep.is_remote() || dst_ep.is_remote() {
            tune::START_SSH
        } else {
            tune::START_LOCAL
        };
    }
    if src_ep.is_remote() && dst_ep.is_remote() {
        if !args.relay {
            // Let the remote orchestrator observe the original source count so
            // repeated file sources keep multi-source destination semantics.
            return crate::direct::run(&args, srcs, dst, source_operand_count);
        }
        if !args.quiet {
            eprintln!("syq: remote-to-remote transfer: relaying data through this machine");
        }
    }
    #[cfg(not(target_os = "linux"))]
    if let Some(algorithm) = &args.tcp_congestion {
        bail!(
            "--tcp-congestion {algorithm} requires a Linux transfer orchestrator and Linux remote endpoints"
        );
    }

    let opts = Arc::new(Opts {
        block,
        flags: args.meta_flags(),
        recursive: args.recursive,
        links: args.links,
        perms: args.perms,
        devices: args.devices,
        checksum: args.checksum,
        verify_only: args.verify_only,
        inplace: args.inplace,
        same_host: !src_ep.is_remote() && !dst_ep.is_remote(),
        dst_remote: dst_ep.is_remote(),
        dry_run: args.dry_run,
        quiet: args.quiet,
        verbose: if args.quiet { 0 } else { args.verbose },
        umask: read_umask(),
        partial_id: std::sync::OnceLock::new(),
        ignore: args.ignore_lines.clone(),
        delete: args.delete,
        delete_excluded: args.delete_excluded,
        max_delete: args.max_delete,
        update: args.update,
        ignore_existing: args.ignore_existing,
        existing: args.existing,
        max_size,
        min_size,
    });
    let show_progress = !args.no_progress && !args.quiet && !args.dry_run;
    let progress = Progress::new(
        args.connections,
        show_progress,
        args.progress,
        args.width,
        !args.quiet && args.progress_json,
    );
    let sched = Arc::new(Sched::new(block, min_split));

    // Workers connect on their own threads once the control connections are
    // up: everything waits on those, so they must never compete with worker
    // handshakes (at sshd's MaxStartups or a serialized ssh agent). The tuner
    // may spawn more workers later, so the handles live behind a mutex.
    let gate = Gate::new(args.connections);
    let checkpoint_slot: CheckpointSlot = std::sync::Arc::new(std::sync::OnceLock::new());
    let workers: Arc<Mutex<Vec<std::thread::JoinHandle<Result<()>>>>> =
        Arc::new(Mutex::new(Vec::new()));
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
            checkpoint_slot,
            bwlimit,
            transport_stats,
        ) = (
            src_ep.clone(),
            dst_ep.clone(),
            sched.clone(),
            progress.clone(),
            opts.clone(),
            gate.clone(),
            workers.clone(),
            checkpoint_slot.clone(),
            bwlimit.clone(),
            transport_stats.clone(),
        );
        let compress = args.compress;
        let collect_tcp_stats = args.stats;
        Arc::new(move |id: usize| {
            let (src_ep, dst_ep, sched, progress, opts, gate, checkpoint, bwlimit, transport_stats) = (
                src_ep.clone(),
                dst_ep.clone(),
                sched.clone(),
                progress.clone(),
                opts.clone(),
                gate.clone(),
                checkpoint_slot.clone(),
                bwlimit.clone(),
                transport_stats.clone(),
            );
            let h = std::thread::spawn(move || -> Result<()> {
                let mut failures = 0u32;
                loop {
                    if !gate.retained(id) {
                        gate.mark_absent(id);
                        return Ok(());
                    }
                    let t0 = std::time::Instant::now();
                    let conns = src_ep
                        .connect(compress)
                        .and_then(|src| Ok((src, dst_ep.connect(compress)?)));
                    let (src, dst) = match conns {
                        Ok(conns) => conns,
                        Err(error) if crate::conn::is_tcp_congestion_error(&error) => {
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
                                eprintln!(
                                    "syq: worker {id}: connection setup failed; retrying in {}s ({error:#})",
                                    1 << (failures - 1)
                                );
                            }
                            std::thread::sleep(std::time::Duration::from_secs(1 << (failures - 1)));
                            continue;
                        }
                    };
                    gate.mark_ready(id);
                    let fast_batch_files =
                        fast_batch_file_limit(src.tcp_rtt_us(), dst.tcp_rtt_us());
                    let mut worker = Worker {
                        id,
                        src,
                        dst,
                        sched: sched.clone(),
                        progress: progress.clone(),
                        opts: opts.clone(),
                        checkpoint: checkpoint.clone(),
                        bwlimit: bwlimit.clone(),
                        gate: gate.clone(),
                        t: [0.0; 4],
                        fast: FastTiming::default(),
                        fast_batch_files,
                    };
                    if debug() {
                        eprintln!(
                            "syq: worker {id} connected in {:.2}s",
                            t0.elapsed().as_secs_f64()
                        );
                    }
                    let result = worker.run();
                    if collect_tcp_stats {
                        let stats = worker.collect_transport_stats();
                        transport_stats.lock().unwrap().extend(stats);
                    }
                    let dropped = result.is_err() && worker.transport_dead();
                    match result {
                        Ok(()) => {
                            gate.mark_absent(id);
                            return Ok(());
                        }
                        Err(error) if dropped => {
                            failures += 1;
                            progress.set_worker(id, None);
                            if failures >= CONNECTION_RECOVERY_ATTEMPTS {
                                gate.mark_failed(id);
                                return Err(error);
                            }
                            gate.mark_warming(id);
                            if !opts.quiet {
                                eprintln!(
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
            let policy = tune::Policy::new(n0, tune::MIN, tune::MAX);
            *tuner.lock().unwrap() = Some(std::thread::spawn(move || {
                tune::run(policy, gate, sched, progress, |id| spawn_worker(id))
            }));
        }
    };
    let t0 = std::time::Instant::now();
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
                sched.abort();
                progress.stop();
                return Err(e);
            }
        }
    };
    if debug() {
        eprintln!(
            "syq: control connections up in {:.2}s",
            t0.elapsed().as_secs_f64()
        );
    }
    if use_tcp {
        let ports = parse_ports(&args.tcp_ports)?;
        for (ep, ctl) in [(&src_ep, &mut src_ctl), (&dst_ep, &mut dst_ctl)] {
            if let Endpoint::Remote(spec) = ep {
                if let Err(e) = spec.setup_tcp(
                    &mut **ctl,
                    args.tcp_plain,
                    ports,
                    args.tcp_congestion.as_deref(),
                ) {
                    if crate::conn::is_tcp_congestion_error(&e) {
                        return Err(e).with_context(|| {
                            format!(
                                "{} could not apply --tcp-congestion {}",
                                spec.label(),
                                args.tcp_congestion.as_deref().unwrap_or_default()
                            )
                        });
                    }
                    if !args.quiet || debug() {
                        let congestion_note = crate::conn::tcp_congestion_fallback_note(
                            args.tcp_congestion.as_deref(),
                        );
                        eprintln!(
                            "syq: {}: data over ssh (TCP ports {}-{} not reachable: {e:#}{congestion_note}); a Tailscale address or an open port is faster",
                            spec.label(),
                            ports.0,
                            ports.1
                        );
                    }
                    continue;
                }
                if debug() {
                    eprintln!(
                        "syq: {}: tcp data port {:?}",
                        spec.label(),
                        spec.tcp
                            .lock()
                            .unwrap()
                            .as_ref()
                            .map(|i| (i.addrs.clone(), i.port))
                    );
                }
            }
        }
    }
    let all_remote_endpoints_use_tcp = use_tcp
        && [&src_ep, &dst_ep].into_iter().all(|ep| match ep {
            Endpoint::Local => true,
            Endpoint::Remote(spec) => spec
                .tcp
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|info| !info.failed),
        });
    if autotune && all_remote_endpoints_use_tcp {
        args.connections = tune::START_TCP;
        gate.set_active(args.connections);
    }
    let tuning_key = autotune.then(|| tune::path_key(&src_ep, &dst_ep)).flatten();
    let remembered_start = tuning_key.as_deref().and_then(tune::cached);
    if let Some(remembered) = remembered_start {
        args.connections = remembered;
        gate.set_active(remembered);
    }
    print_transport_diagnostics(&args, &src_ep, &dst_ep);
    if args.verbose >= 2 {
        if let Some(remembered) = remembered_start {
            eprintln!(
                "syq: auto-tuning: starting with {remembered} connections remembered for this path"
            );
        }
    }
    if !opts.dry_run {
        spawn_workers(args.connections);
    }

    // One spelling for the destination root: every derived key — claims,
    // delete roots, destination-walk paths, receiver-computed sidecar names —
    // flows from this, and the receiver rebuilds paths through `Path`, which
    // silently drops `.` components and duplicate slashes. Cleaning here
    // (lexically only; symlinks stay the self-copy guard's business) keeps
    // `dst`, `dst/`, `dst/.` and `dst//` from producing keys that disagree.
    let dst_root = clean_root(&dst.path);
    let (dst_root_entry, dst_canonical) =
        stat_and_canonicalize(&mut *dst_ctl, &dst_root, &dst.path, dst.is_remote())?;
    // A destination that is a symlink to a directory is that directory (as
    // for rsync). Use the resolved target path for all planning and metadata,
    // so ordinary in-tree symlinks can still be replaced instead of followed.
    let (dst_root, dst_root_entry) = follow_dir_symlink(&mut *dst_ctl, &dst_root, dst_root_entry)?;
    let dst_initially_missing = dst_root_entry.is_none();
    let dst_existed = !dst_initially_missing;
    let dst_entry_is_dir = dst_root_entry
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
            None => {
                multiple_source_operands || dst.copies_contents() || args.files_from.is_some()
            }
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
        // a missing --into target can be created. Named selectors follow their
        // root unless --src-no-follow was used; contents selectors additionally
        // require the resolved object to be a directory.
        for source in srcs {
            match stat_one(&mut *src_ctl, &source.path, source.follows_root())? {
                Some(entry) if source.requires_directory() && entry.kind != Kind::Dir => {
                    bail!(
                        "contents selector {} is not a directory",
                        display(&source.path)
                    )
                }
                Some(_) => {}
                None => bail!("source {} does not exist", display(&source.path)),
            }
        }
    }

    // Reject copying a directory into itself: if the effective destination
    // resolves to (or inside) a source directory, the scanner would discover
    // the freshly-created destination and recurse. Now that both control
    // connections exist we can check the real source type and destination-dir
    // status, so a file copied onto itself is not misdiagnosed.
    let same_machine = (!srcs[0].is_remote() && !dst.is_remote())
        || (srcs[0].is_remote() && dst.is_remote() && srcs[0].same_host(dst));
    if same_machine {
        // Both ends are one machine, so either control connection resolves
        // paths the way that machine's kernel does (symlinks included).
        let remote = dst.is_remote();
        for s in srcs {
            // Only a directory source can trigger the recurse-into-itself trap.
            // Judge the source the way the scan will: --files-from and
            // trailing-slash sources are followed through a symlinked root.
            let follow_root = args.files_from.is_some() || s.follows_root();
            let src_is_dir = matches!(stat_one(&mut *src_ctl, &s.path, follow_root)?, Some(ref e) if e.kind == Kind::Dir);
            if !src_is_dir {
                continue;
            }
            let sn = canonical_path(&mut *src_ctl, &s.path, remote)?;
            // Effective destination(s): the destination itself, plus
            // destination/basename when placement uses it as a container.
            let mut effs = vec![canonical_path(&mut *src_ctl, &dst.path, remote)?];
            if dst_is_dir && !s.copies_contents() && args.files_from.is_none() {
                let base = s.basename();
                if !base.is_empty() {
                    let joined = join(dst.path.strip_suffix(b"/").unwrap_or(&dst.path), &base);
                    effs.push(canonical_path(&mut *src_ctl, &joined, remote)?);
                }
            }
            for eff in effs {
                if eff == sn {
                    bail!(
                        "source and destination are the same directory {:?}",
                        display(&s.path)
                    );
                } else if eff.starts_with(&sn) {
                    bail!(
                        "destination {:?} maps inside source {:?} — that would copy the directory into itself",
                        display(&dst.path), display(&s.path)
                    );
                }
            }
        }
    }

    let identity = copy_identity(
        &args,
        srcs,
        dst,
        &mut *src_ctl,
        &mut *dst_ctl,
        Some(dst_canonical),
        &opts,
    )?;
    opts.partial_id
        .set(crate::checkpoint::partial_id(&identity))
        .expect("partial identity set once");

    let checkpoint_state = checkpoint_setup(
        &args,
        srcs,
        DestinationRoot {
            path: &dst_root,
            existed: dst_existed,
            is_container: dst_is_dir,
            entry_is_dir: dst_entry_is_dir,
            exact: args.placement == Placement::As,
        },
        &mut *dst_ctl,
        &identity,
    )?;

    // Create a missing directory destination — never in the read-only modes,
    // and never under --existing. With several sources this waits until
    // their scans have been checked against each other, so a conflicting
    // command leaves nothing behind.
    let create_root = dst_root_entry.is_none()
        && dst_is_dir
        && !args.dry_run
        && !args.verify_only
        && !args.existing;
    let dry_run_creates_root =
        args.dry_run && dst_root_entry.is_none() && dst_is_dir && !args.existing;
    if create_root && !multiple_distinct_sources {
        mkdir_root(&mut *dst_ctl, &dst_root)?;
    }
    let checkpoint_completed = checkpoint_state
        .as_ref()
        .map(|state| state.completed.clone());
    let checkpoint_writer = checkpoint_state
        .as_ref()
        .and_then(|state| state.checkpoint.clone());
    if let Some(checkpoint) = &checkpoint_writer {
        let _ = checkpoint_slot.set(CheckpointShared {
            checkpoint: Some(checkpoint.clone()),
        });
    }

    let ticker = progress.spawn_ticker();

    let mut st = Planner {
        dst: &mut *dst_ctl,
        sched: &sched,
        progress: &progress,
        opts: &opts,
        completed: checkpoint_completed,
        checkpoint: checkpoint_writer,
        destination_tree_known_missing: dst.is_remote()
            && dst_initially_missing
            && !opts.ignore_existing
            && !opts.update
            && !opts.checksum,
        dst_seen: std::collections::HashMap::new(),
        missing_dirs: std::collections::HashSet::new(),
        dry_run_replaced_dirs: std::collections::HashSet::new(),
        payload_paths: std::collections::HashMap::new(),
        sidecar_paths: std::collections::HashMap::new(),
        live_sidecars: Vec::new(),
        unusable_files: std::collections::HashSet::new(),
        deferred_payloads: Vec::new(),
        source_partials: 0,
        collision: false,
        deferred: Vec::new(),
        dirs_created: 0,
        links_created: 0,
        specials_created: 0,
        scan_warned: false,
        max_delete_hit: false,
        delete_walk_failed: false,
        buffer: if multiple_distinct_sources {
            Some(Vec::new())
        } else {
            None
        },
        create_root: if create_root && multiple_distinct_sources {
            Some(dst_root.clone())
        } else {
            None
        },
        keep_dirs: args.files_from.is_some(),
        delete_roots: Vec::new(),
        deletes: Deletes::default(),
        dry_run_changes: {
            let mut changes = DryRunChanges::default();
            if dry_run_creates_root {
                changes.directories.insert(dst_root.clone());
            }
            changes
        },
    };

    let mut scan_err = None;
    let mut dry_run_mappings = Vec::with_capacity(srcs.len());
    if args.files_from.is_some() {
        let src = &srcs[0];
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
    for src in srcs.iter().filter(|_| args.files_from.is_none()) {
        let src_root = src.path.clone();
        let contents = src.copies_contents();
        let follow_root = src.follows_root();
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
                require_directory: src.requires_directory(),
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
        progress.error(&format!("syq: {e:#}"));
        sched.abort();
    } else if collision {
        sched.abort();
    } else {
        // Workers have connected in parallel with the scan, but no sidecar is
        // opened until every payload/sidecar namespace collision is known.
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

    let aborted = sched.is_aborted();
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
        } else {
            match st.plan_deletes() {
                Ok(()) if st.delete_walk_failed => {
                    delete_plan = DeletePlan::Skipped("destination walk errors");
                    progress.eprintln("syq: destination walk reported errors; skipping deletions")
                }
                Ok(()) => {
                    delete_plan = DeletePlan::Planned(st.deletes.len());
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
    let max_delete_hit = st.max_delete_hit;
    let dry_run_changes = std::mem::take(&mut st.dry_run_changes);
    drop(st);

    progress.stop();
    if let Some(t) = ticker {
        let _ = t.join();
    }
    progress.clear();

    let errors = progress.errors.load(Relaxed);

    if !aborted
        && errors == 0
        && !opts.dry_run
        && !opts.verify_only
        && scan_err.is_none()
        && !collision
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
                    eprintln!(
                        "syq: auto-tuning: transport changed during transfer; not updating cache"
                    );
                }
            }
        }
    }

    // Settle an explicit checkpoint. A recording failure only makes a retry
    // recheck more files. The user-selected state persists until they remove it.
    if let Some(state) = &checkpoint_state {
        let failed = state.checkpoint.as_ref().and_then(|checkpoint| {
            checkpoint
                .close()
                .err()
                .map(|e| format!("{e:#}"))
                .or_else(|| checkpoint.take_error())
        });
        // Error-class output: a real I/O failure that -q must not swallow,
        // even though the exit code still describes the (complete) copy.
        if let Some(e) = failed {
            eprintln!(
                "syq: warning: checkpoint recording stopped ({e}); a retry will recheck files completed after that point"
            );
        }
    }
    let elapsed = progress.start.elapsed().as_secs_f64();
    let done = progress.bytes_done.load(Relaxed);
    if !args.quiet && !aborted {
        if opts.dry_run {
            if args.verbose > 0 && dry_run_creates_root {
                println!(
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
            );
        } else if opts.verify_only {
            println!(
                "syq: verified {} files, {} differ/missing, {} in {}",
                commas(progress.files_done.load(Relaxed) + errors),
                errors,
                human(done),
                crate::progress::hms(elapsed)
            );
        } else {
            println!(
                "syq: transferred {} files ({}), {} unchanged ({} files), {} dirs{}{}{}",
                commas(progress.files_done.load(Relaxed)),
                human(done),
                human(progress.bytes_skipped.load(Relaxed)),
                commas(progress.files_skipped.load(Relaxed)),
                commas(st_dirs(&progress)),
                deletion_summary(delete_plan, deleted, opts.max_delete),
                format_args!(
                    ", {} at {}/s",
                    crate::progress::hms(elapsed),
                    human((done as f64 / elapsed.max(0.001)) as u64)
                ),
                if errors > 0 {
                    format!(", {errors} errors")
                } else {
                    String::new()
                }
            );
        }
        if args.stats {
            let (
                files_label,
                unchanged_files_label,
                bytes_label,
                unchanged_bytes_label,
                bytes_work,
            ) = if opts.dry_run {
                (
                    "files needing content work",
                    "files with unchanged content",
                    "logical bytes needing content work",
                    "logical bytes with unchanged content",
                    progress.bytes_total.load(Relaxed),
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
                matches!(endpoint, Endpoint::Remote(spec) if spec.data_transport() == DataTransport::Ssh)
            });
            let tcp_stats = format_tcp_stats(&transport_stats.lock().unwrap(), has_ssh_data);
            println!(
                "  scanned entries: {}\n  {files_label}: {}\n  {unchanged_files_label}: {}\n  files excluded: {}\n  {bytes_label}: {}\n  {unchanged_bytes_label}: {}\n  elapsed: {:.2}s\n  connections: {}{}",
                commas(progress.scanned.load(Relaxed)),
                commas(progress.files_total.load(Relaxed)),
                commas(progress.files_skipped.load(Relaxed)),
                commas(progress.files_excluded.load(Relaxed)),
                commas(bytes_work),
                commas(progress.bytes_skipped.load(Relaxed)),
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
    }
    Ok(if aborted {
        1
    } else if errors > 0 {
        23
    } else if max_delete_hit {
        25
    } else {
        0
    })
}

fn st_dirs(p: &Progress) -> u64 {
    p.scanned.load(Relaxed).saturating_sub(
        p.files_total.load(Relaxed)
            + p.files_skipped.load(Relaxed)
            + p.files_excluded.load(Relaxed),
    )
}

/// lstat (or stat, with `follow`) each path on `conn`.
fn stat_many(
    conn: &mut dyn Conn,
    paths: Vec<PathBytes>,
    follow: bool,
) -> Result<Vec<Option<Entry>>> {
    if paths.is_empty() {
        return Ok(Vec::new());
    }
    match ok(conn.call(Request::StatMany { paths, follow })?, "stat")? {
        Response::Stats(v) => Ok(v),
        other => bail!("unexpected response {other:?}"),
    }
}

fn mkdir_root(conn: &mut dyn Conn, dst_root: &[u8]) -> Result<()> {
    match ok(
        conn.call(Request::Apply(vec![Op::Mkdir {
            path: dst_root.to_vec(),
            mode: 0o755,
        }]))?,
        "mkdir",
    )? {
        Response::Applied(errs) => {
            if let Some(e) = errs.into_iter().flatten().next() {
                bail!("{e}");
            }
            Ok(())
        }
        other => bail!("unexpected response {other:?}"),
    }
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

/// Fetch the destination root's entry and canonical spelling in one network
/// turn. They are independent read-only queries; sending both before waiting
/// avoids an otherwise unnecessary RTT on every remote copy.
fn stat_and_canonicalize(
    conn: &mut dyn Conn,
    stat_path: &[u8],
    canonical_path: &[u8],
    remote: bool,
) -> Result<(Option<Entry>, std::path::PathBuf)> {
    if !remote {
        return Ok((
            stat_one(conn, stat_path, false)?,
            crate::fsops::normalize(&crate::fsops::resolve(canonical_path)),
        ));
    }
    conn.send(Request::StatMany {
        paths: vec![stat_path.to_vec()],
        follow: false,
    })?;
    conn.send(Request::Canonicalize {
        path: canonical_path.to_vec(),
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

fn display(p: &[u8]) -> String {
    String::from_utf8_lossy(p).into_owned()
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

fn metadata_differs(source: &Entry, destination: &Entry, flags: u8) -> bool {
    (flags & flags::MODE != 0 && source.mode & 0o7777 != destination.mode & 0o7777)
        || (flags & flags::OWNER != 0 && source.uid != destination.uid)
        || (flags & flags::GROUP != 0 && source.gid != destination.gid)
        || (flags & flags::TIMES != 0
            && (source.mtime, source.mtime_nsec) != (destination.mtime, destination.mtime_nsec))
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
    match &loc.user {
        Some(user) => format!("{user}@{host}:{path}"),
        None => format!("{host}:{path}"),
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

fn selected_route(src: &Endpoint, dst: &Endpoint, args: &Args) -> String {
    let route = match (src, dst) {
        (Endpoint::Local, Endpoint::Local) => args.plan_source_host.as_ref().map_or_else(
            || "local filesystem".to_string(),
            |host| format!("local filesystem on {host}"),
        ),
        (Endpoint::Local, Endpoint::Remote(spec)) => match &args.plan_source_host {
            Some(source) => format!(
                "{} from {source} to {}",
                remote_data_transport(spec),
                spec.label()
            ),
            None => format!("{} to {}", remote_data_transport(spec), spec.label()),
        },
        (Endpoint::Remote(spec), Endpoint::Local) => {
            format!("{} from {}", remote_data_transport(spec), spec.label())
        }
        (Endpoint::Remote(source), Endpoint::Remote(target)) => format!(
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

struct DryRunMapping {
    target: PathBytes,
    semantics: &'static str,
}

/// A typed summary of final-state mutations found during a dry run. Type
/// replacements overlap the primary categories; all others are disjoint.
#[derive(Default)]
struct DryRunChanges {
    regular_files: u64,
    directories: std::collections::HashSet<PathBytes>,
    symlinks: u64,
    specials: u64,
    metadata_files: u64,
    metadata_directories: std::collections::HashSet<PathBytes>,
    type_replacements: u64,
}

impl DryRunChanges {
    fn summary(&self) -> String {
        let mut categories = Vec::new();
        for (n, singular, plural) in [
            (self.regular_files, "regular file", "regular files"),
            (self.directories.len() as u64, "directory", "directories"),
            (self.symlinks, "symlink", "symlinks"),
            (self.specials, "special file", "special files"),
            (
                self.metadata_files + self.metadata_directories.len() as u64,
                "metadata-only entry",
                "metadata-only entries",
            ),
        ] {
            if n > 0 {
                categories.push(count_label(n, singular, plural));
            }
        }
        if categories.is_empty() {
            return "none".to_string();
        }
        if self.type_replacements > 0 {
            categories.push(format!(
                "{} among them",
                count_label(
                    self.type_replacements,
                    "type replacement",
                    "type replacements"
                )
            ));
        }
        categories.join("; ")
    }
}

#[derive(Clone, Copy)]
enum DeletePlan {
    Disabled,
    Planned(u64),
    Skipped(&'static str),
}

fn count_label(n: u64, singular: &str, plural: &str) -> String {
    format!("{} {}", commas(n), if n == 1 { singular } else { plural })
}

fn deletion_summary(plan: DeletePlan, deleted: u64, max: Option<u64>) -> String {
    match plan {
        DeletePlan::Disabled => String::new(),
        DeletePlan::Planned(n) => {
            if let Some(limit) = max.filter(|limit| n > *limit) {
                format!(
                    ", {} planned for deletion (blocked by --max-delete {limit})",
                    commas(n)
                )
            } else {
                format!(", {} deleted", commas(deleted))
            }
        }
        DeletePlan::Skipped(reason) => format!(", deletions skipped ({reason})"),
    }
}

#[allow(clippy::too_many_arguments)]
fn print_dry_run_summary(
    srcs: &[Location],
    dst: &Location,
    mappings: &[DryRunMapping],
    src_ep: &Endpoint,
    dst_ep: &Endpoint,
    args: &Args,
    opts: &Opts,
    progress: &Progress,
    deletes: DeletePlan,
    changes: &DryRunChanges,
) {
    println!("syq: dry-run summary");
    for (source, mapping) in srcs.iter().zip(mappings) {
        println!(
            "  mapping: {} -> {} ({})",
            display_plan_source(source, args),
            display_plan_target(dst, &mapping.target, args),
            mapping.semantics
        );
    }
    println!("  changes: {}", changes.summary());

    match deletes {
        DeletePlan::Disabled => println!("  deletions: disabled"),
        DeletePlan::Planned(n) => {
            if let Some(limit) = opts.max_delete.filter(|limit| n > *limit) {
                println!(
                    "  deletions: {} planned; blocked by --max-delete {limit}",
                    count_label(n, "entry", "entries")
                );
            } else {
                println!(
                    "  deletions: {} planned after a successful copy",
                    count_label(n, "entry", "entries")
                );
            }
        }
        DeletePlan::Skipped(reason) => println!("  deletions: skipped ({reason})"),
    }
    println!(
        "  logical data: {} in {} needing content work (upper bound); {} in {} with unchanged content",
        human(progress.bytes_total.load(Relaxed)),
        count_label(progress.files_total.load(Relaxed), "file", "files"),
        human(progress.bytes_skipped.load(Relaxed)),
        count_label(progress.files_skipped.load(Relaxed), "file", "files")
    );

    let ignored = progress.paths_ignored.load(Relaxed);
    let other = progress.files_excluded.load(Relaxed);
    let mut exclusions = Vec::new();
    if ignored > 0 {
        exclusions.push(format!(
            "{} pruned by ignore rules",
            count_label(ignored, "path/subtree", "paths/subtrees")
        ));
    }
    if other > 0 {
        exclusions.push(count_label(other, "other entry", "other entries"));
    }
    println!(
        "  exclusions: {}",
        if exclusions.is_empty() {
            if opts.ignore.is_empty() {
                "none".to_string()
            } else {
                "none matched (ignore rules active)".to_string()
            }
        } else {
            exclusions.join("; ")
        }
    );

    println!("  route: {}", selected_route(src_ep, dst_ep, args));
}

fn path_has_partial_component(path: &[u8]) -> bool {
    path.split(|&byte| byte == b'/')
        .any(|part| is_partial_name(OsStr::from_bytes(part)))
}

/// What to checkpoint for a quick-check-identical file once metadata repair succeeds.
type QuickCheckRecord = (PathBytes, Entry);

struct Planner<'a> {
    dst: &'a mut dyn Conn,
    sched: &'a Sched,
    progress: &'a Progress,
    opts: &'a Opts,
    /// Destination paths claimed by source entries (see `Claim`).
    dst_seen: std::collections::HashMap<PathBytes, Claim>,
    /// Directories this run will not create — --existing: they don't exist
    /// (or aren't directories); --ignore-existing: an existing non-directory
    /// sits at their path. Nothing under them is touched.
    missing_dirs: std::collections::HashSet<PathBytes>,
    /// Directories that a dry run would create over destination leaves. Until
    /// that virtual replacement exists, lstat would follow an old in-tree
    /// symlink in an intermediate component and inspect the wrong subtree.
    dry_run_replaced_dirs: std::collections::HashSet<PathBytes>,
    completed:
        Option<std::sync::Arc<std::collections::HashMap<PathBytes, crate::checkpoint::Completed>>>,
    checkpoint: Option<std::sync::Arc<crate::checkpoint::Checkpoint>>,
    /// Once syq has observed a missing remote destination root, every mapped
    /// path is missing too. Avoid WAN round trips for impossible descendants;
    /// local stats stay cheap and warm filesystem metadata for the writers.
    destination_tree_known_missing: bool,
    /// Mapped payload paths that look like current sidecars, and every
    /// sidecar path the current job may use. Their intersection is unsafe.
    /// Ordinary payload names cannot collide and do not need to stay in RAM.
    payload_paths: std::collections::HashMap<PathBytes, String>,
    sidecar_paths: std::collections::HashMap<PathBytes, String>,
    /// The keys of sidecar_paths, kept past finish_planning only for --delete
    /// (sorted, binary-searched: one path per regular file is the dominant
    /// resident cost of --delete on huge trees, so keep it lean).
    live_sidecars: Vec<PathBytes>,
    /// Files whose destination cannot accommodate a safe sidecar name. They
    /// fail individually while the rest of the scan and transfer continue.
    unusable_files: std::collections::HashSet<PathBytes>,
    /// Payload paths inside the sidecar-looking namespace, mapped and claimed
    /// like everything else but applied only after the collision preflight
    /// over every source has passed (see finish_planning).
    deferred_payloads: Vec<Mapped>,
    source_partials: u64,
    collision: bool,
    /// (dst path, meta, flags, depth) for directories, applied deepest-first at the end.
    deferred: Vec<(PathBytes, Meta, u8, usize)>,
    dirs_created: u64,
    links_created: u64,
    specials_created: u64,
    /// A source scan reported a non-fatal problem (unreadable directory, ...).
    scan_warned: bool,
    /// --max-delete stopped the deletions (exit 25, as rsync).
    max_delete_hit: bool,
    /// The destination walk reported errors: an unreadable directory there
    /// looks empty and would be rmdir'd over its unknown contents, so
    /// deletion is skipped entirely (the errors already count).
    delete_walk_failed: bool,
    /// Several sources: mapped batches waiting for all scans to finish
    /// (see `Mapped`). None with a single source, where batches stream.
    buffer: Option<Vec<Mapped>>,
    /// Several sources into a destination that doesn't exist yet: create it
    /// only once the scans have been validated against each other.
    create_root: Option<PathBytes>,
    /// --files-from: listed directories are created even without -r (which
    /// then only decides whether their contents are walked).
    keep_dirs: bool,
    /// (destination directory, its path relative to the transfer root) for every
    /// directory source; --delete removes extras inside these.
    delete_roots: Vec<(PathBytes, PathBytes)>,
    deletes: Deletes,
    dry_run_changes: DryRunChanges,
}

/// What a source entry asserts about its destination path. Two dirs merge;
/// a dir against a leaf, or two leaves, conflict. A `Weak` claim comes from
/// an entry syq will not transfer (a symlink without -l, a special file
/// without -D, an unknown type): it still marks the path as the source's —
/// so --delete leaves it alone — but yields to any real claim, so two
/// sources overlapping on such an entry are not a conflict.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Claim {
    Dir,
    /// A regular file syq intends to write; its identity, so a second
    /// claimant can be checked against "is one of us the destination file?".
    File {
        dev: u64,
        ino: u64,
    },
    /// A symlink or special file syq intends to create.
    Leaf,
    Weak,
}

/// Everything the planner decided about one source entry, made once in the
/// mapping loop so the directory pass and the per-kind arms can't disagree.
struct Planned {
    src: PathBytes,
    dst: PathBytes,
    dst_rel: PathBytes,
    rel: String,
    e: Entry,
    /// Another source already claimed `dst` as a regular file. Resolved once
    /// the destination is stat'ed: fine if that file *is* this file (a copy
    /// onto itself), a collision otherwise.
    contested: bool,
}

/// One scanned batch after the mapping loop: every destination claimed,
/// nothing touched yet. With several sources these are held until all of
/// them have been scanned, so a conflict between sources is reported before
/// the destination is changed at all.
struct Mapped {
    dst_root: PathBytes,
    dirs: Vec<(PathBytes, PathBytes, Entry)>,
    others: Vec<Planned>,
    dir_stats: Option<Vec<Option<Entry>>>,
    other_stats: Option<std::collections::HashMap<PathBytes, Option<Entry>>>,
}

/// What --delete found on the destination that the source doesn't have.
#[derive(Default)]
struct Deletes {
    /// (path, display name, destination-relative path) of files, symlinks and
    /// specials to unlink; the relative path is the journal's key.
    leaves: Vec<(PathBytes, String, PathBytes)>,
    /// Directories by depth, removed deepest-first once they are empty; the
    /// relative path is the journal's key, as for leaves.
    dirs: std::collections::BTreeMap<usize, Vec<(PathBytes, String, PathBytes)>>,
}

impl Deletes {
    fn len(&self) -> u64 {
        self.leaves.len() as u64
            + self
                .dirs
                .values()
                .map(|items| items.len() as u64)
                .sum::<u64>()
    }
}

impl Planner<'_> {
    fn scan_source(
        &mut self,
        src: &mut dyn Conn,
        src_root: &[u8],
        source: SourceMapping<'_>,
        destination: DestinationRoot<'_>,
    ) -> Result<DryRunMapping> {
        let SourceMapping {
            follow_root,
            contents,
            require_directory,
            sub,
        } = source;
        let dst_root = destination.path;
        let dst_is_dir = destination.is_container;
        let dst_existed = destination.existed;
        let mut first = true;
        let mut sub = sub.to_vec();
        let mut skip_all = false;
        let mut mapping = None;
        let ignore = self.opts.ignore.clone();
        scan_into_planner(self, src, src_root, follow_root, &ignore, |pl, batch| {
            if skip_all {
                return Ok(());
            }
            if first {
                first = false;
                if let Some(root) = batch.first() {
                    if require_directory && root.kind != Kind::Dir {
                        bail!("contents selector {} is not a directory", display(src_root));
                    }
                    if pl.opts.dry_run
                        && root.kind == Kind::Dir
                        && !contents
                        && pl.opts.recursive
                        && dst_existed
                        && !destination.entry_is_dir
                        && !destination.exact
                        && !pl.opts.existing
                    {
                        bail!(
                            "destination {} is not a directory; cannot place directory {} inside it",
                            display(dst_root),
                            display(src_root)
                        );
                    }
                    if root.kind != Kind::Dir && !dst_is_dir {
                        sub.clear();
                    }
                    mapping = Some(DryRunMapping {
                        target: join(dst_root, &sub),
                        semantics: if destination.exact {
                            "exact destination path"
                        } else {
                            match (root.kind, contents, dst_is_dir) {
                                (Kind::Dir, true, _) => "directory contents",
                                (Kind::Dir, false, _) => "directory as child",
                                (_, _, true) => "entry inside destination directory",
                                _ => "exact destination path",
                            }
                        },
                    });
                    if root.kind == Kind::Dir && !pl.opts.recursive {
                        if !pl.opts.quiet {
                            pl.progress
                                .eprintln(&format!("skipping directory {}", display(src_root)));
                        }
                        skip_all = true;
                        return Ok(());
                    }
                    if root.kind == Kind::Dir {
                        pl.delete_roots.push((join(dst_root, &sub), sub.clone()));
                    }
                }
            }
            pl.progress.scanned.fetch_add(batch.len() as u64, Relaxed);
            pl.handle_batch(batch, src_root, &sub, dst_root)
        })?;
        mapping.ok_or_else(|| anyhow::anyhow!("source scan returned no root entry"))
    }

    /// --files-from: instead of walking the source, stat each listed path (and
    /// the directories leading to it) and feed them to the planner as if a scan
    /// had produced them. Implied parents are stat'ed through symlinks and must
    /// resolve to directories; they become real directories on the destination,
    /// so nothing is ever written through a destination symlink. Listed
    /// directories — only those, not implied parents — are walked with an
    /// explicit -r.
    fn scan_files_from(
        &mut self,
        src: &mut dyn Conn,
        src_root: &[u8],
        dst_root: &[u8],
        lines: &[PathBytes],
        recurse: bool,
    ) -> Result<()> {
        use std::collections::{HashMap, HashSet};
        // Through a symlink: `syq --files-from L link dst` should work like `link/`.
        // Validate the root but never plan it: it isn't in the list, so an
        // existing destination is not stamped with source-root metadata
        // (creation-when-missing happened in run()).
        match stat_one(src, src_root, true)? {
            Some(e) if e.kind == Kind::Dir => {}
            Some(_) => bail!(
                "--files-from: source {} is not a directory",
                display(src_root)
            ),
            None => bail!("--files-from: source {} does not exist", display(src_root)),
        }
        self.progress.scanned.fetch_add(1, Relaxed);

        // Listed paths are lstat'ed (a listed symlink copies as a symlink).
        // Implied ancestors are stat'ed *through* symlinks and must resolve to
        // directories: the user named a path through them, and on the
        // destination they become real directories, so nothing is ever
        // written through a symlink there. Results are kept for the whole
        // list, since a later line may repeat a path or name one first seen
        // as a parent.
        let mut leaves: HashMap<PathBytes, Option<Entry>> = HashMap::new();
        let mut parents: HashMap<PathBytes, Option<Entry>> = HashMap::new();
        // What the planner has been given for each path (Dir or not).
        let mut emitted: HashMap<PathBytes, Kind> = HashMap::new();
        let mut recursed: HashSet<PathBytes> = HashSet::new();
        let ancestors = |line: &[u8]| -> Vec<PathBytes> {
            line.iter()
                .enumerate()
                .filter(|(_, &b)| b == b'/')
                .map(|(i, _)| line[..i].to_vec())
                .collect()
        };
        let stat = |src: &mut dyn Conn, paths: Vec<PathBytes>, follow: bool| {
            stat_many(
                src,
                paths.iter().map(|r| join(src_root, r)).collect(),
                follow,
            )
        };
        for chunk in lines.chunks(crate::scan::BATCH) {
            let mut want_parents: Vec<PathBytes> = Vec::new();
            let mut want_leaves: Vec<PathBytes> = Vec::new();
            // Per role: a path may be needed both as a followed ancestor and
            // as an lstat'ed leaf, with different answers.
            let mut wanted_parents: HashSet<PathBytes> = HashSet::new();
            let mut wanted_leaves: HashSet<PathBytes> = HashSet::new();
            for line in chunk {
                for anc in ancestors(line) {
                    if !parents.contains_key(&anc) && wanted_parents.insert(anc.clone()) {
                        want_parents.push(anc);
                    }
                }
                if !leaves.contains_key(line) && wanted_leaves.insert(line.clone()) {
                    want_leaves.push(line.clone());
                }
            }
            for (rel, st) in
                want_parents
                    .iter()
                    .cloned()
                    .zip(stat(src, want_parents.clone(), true)?)
            {
                parents.insert(
                    rel.clone(),
                    st.map(|mut e| {
                        e.path = rel;
                        e
                    }),
                );
            }
            for (rel, st) in want_leaves
                .iter()
                .cloned()
                .zip(stat(src, want_leaves.clone(), false)?)
            {
                leaves.insert(
                    rel.clone(),
                    st.map(|mut e| {
                        e.path = rel;
                        e
                    }),
                );
            }
            let mut batch: Vec<Entry> = Vec::new();
            let mut subtrees: Vec<PathBytes> = Vec::new();
            'line: for line in chunk {
                let shown = display(line);
                // Validate the whole chain before emitting any of it, so a bad
                // path leaves no half-created ancestors behind.
                let mut chain: Vec<Entry> = Vec::new();
                for anc in ancestors(line) {
                    match parents.get(&anc).and_then(|e| e.as_ref()) {
                        Some(e) if e.kind == Kind::Dir => match emitted.get(&anc) {
                            Some(Kind::Dir) => {}
                            Some(_) => {
                                self.progress.error(&format!(
                                    "syq: --files-from: {shown}: {} was listed as a non-directory",
                                    display(&anc)
                                ));
                                continue 'line;
                            }
                            None => {
                                if !chain.iter().any(|c| c.path == anc) {
                                    chain.push(e.clone());
                                }
                            }
                        },
                        Some(_) => {
                            self.progress.error(&format!(
                                "syq: --files-from: {shown}: {} is not a directory",
                                display(&anc)
                            ));
                            continue 'line;
                        }
                        None => {
                            self.progress.error(&format!(
                                "syq: --files-from: {shown}: no such file or directory"
                            ));
                            continue 'line;
                        }
                    }
                }
                let Some(e) = leaves.get(line).and_then(|e| e.as_ref()) else {
                    self.progress.error(&format!(
                        "syq: --files-from: {shown}: no such file or directory"
                    ));
                    continue;
                };
                for c in chain {
                    emitted.insert(c.path.clone(), Kind::Dir);
                    batch.push(c);
                }
                match emitted.get(line) {
                    None => {
                        emitted.insert(line.clone(), e.kind);
                        batch.push(e.clone());
                    }
                    Some(k) if *k == e.kind => {}
                    Some(_) => {
                        // Listed as a symlink (or file) after a path through it
                        // already made it a directory: the same conflict as the
                        // other order, refused the same way.
                        self.progress.error(&format!(
                            "syq: --files-from: {shown}: listed as a non-directory but already used as a directory"
                        ));
                        continue;
                    }
                }
                if e.kind == Kind::Dir && recurse && recursed.insert(line.clone()) {
                    subtrees.push(line.clone());
                }
            }
            self.progress.scanned.fetch_add(batch.len() as u64, Relaxed);
            self.handle_batch(batch, src_root, b"", dst_root)?;
            for rel in subtrees {
                self.scan_subtree(src, src_root, &rel, dst_root, &mut emitted)?;
            }
        }
        Ok(())
    }

    /// Walk `src_root/rel` and plan its entries under the same relative prefix.
    fn scan_subtree(
        &mut self,
        src: &mut dyn Conn,
        src_root: &[u8],
        rel: &[u8],
        dst_root: &[u8],
        emitted: &mut std::collections::HashMap<PathBytes, Kind>,
    ) -> Result<()> {
        scan_into_planner(self, src, &join(src_root, rel), false, &[], |pl, batch| {
            let batch: Vec<Entry> = batch
                .into_iter()
                .filter(|e| !e.path.is_empty())
                .map(|mut e| {
                    e.path = join(rel, &e.path);
                    e
                })
                .filter(|e| {
                    if emitted.contains_key(&e.path) {
                        false
                    } else {
                        emitted.insert(e.path.clone(), e.kind);
                        true
                    }
                })
                .collect();
            pl.progress.scanned.fetch_add(batch.len() as u64, Relaxed);
            pl.handle_batch(batch, src_root, b"", dst_root)
        })
    }

    fn handle_batch(
        &mut self,
        batch: Vec<Entry>,
        src_root: &[u8],
        sub: &[u8],
        dst_root: &[u8],
    ) -> Result<()> {
        let namespace_files = self.collect_namespace_files(&batch, src_root, sub, dst_root);
        if self.collision {
            return Ok(());
        }
        // Payloads inside the sidecar-looking namespace are mapped and claimed
        // now, like everything else, but applied only once the preflight over
        // every source has passed.
        let mut immediate = Vec::with_capacity(batch.len());
        let mut deferred = Vec::new();
        for entry in batch {
            let dst_rel = join(sub, &entry.path);
            let reserved_leaf = dst_rel.is_empty()
                && entry.kind != Kind::Dir
                && dst_root
                    .rsplit(|&byte| byte == b'/')
                    .next()
                    .is_some_and(|name| is_partial_name(OsStr::from_bytes(name)));
            if reserved_leaf || path_has_partial_component(&dst_rel) {
                deferred.push(entry);
            } else {
                immediate.push(entry);
            }
        }
        let mut mapped = self.map_batch(immediate, src_root, sub, dst_root);
        self.register_namespace(namespace_files, &mut mapped)?;
        if self.collision {
            return Ok(());
        }
        match &mut self.buffer {
            Some(buf) => buf.push(mapped),
            None => self.apply_mapped(mapped)?,
        }
        if !deferred.is_empty() {
            let mapped = self.map_batch(deferred, src_root, sub, dst_root);
            self.deferred_payloads.push(mapped);
        }
        Ok(())
    }

    /// All sources scanned and the sidecar namespace preflight passed: apply
    /// what was held back. With several sources that is every batch, after
    /// the cross-source claim check; otherwise only the deferred payloads.
    fn finish_planning(&mut self) -> Result<()> {
        // The preflight maps are dead now — except the sidecar set, which
        // --delete needs (only its keys) to tell a live sidecar from an
        // orphan. On multi-million-file trees these are the difference
        // between transient and resident gigabytes.
        self.payload_paths = std::collections::HashMap::new();
        let sidecars = std::mem::take(&mut self.sidecar_paths);
        if self.opts.delete {
            let mut keys: Vec<PathBytes> = sidecars.into_keys().collect();
            keys.sort_unstable();
            self.live_sidecars = keys;
        }
        let deferred = std::mem::take(&mut self.deferred_payloads);
        if let Some(buf) = &mut self.buffer {
            buf.extend(deferred);
            return self.replay_buffered();
        }
        for m in deferred {
            self.apply_mapped(m)?;
        }
        Ok(())
    }

    /// The mapping loop: decide and claim everything about each entry.
    fn map_batch(
        &mut self,
        batch: Vec<Entry>,
        src_root: &[u8],
        sub: &[u8],
        dst_root: &[u8],
    ) -> Mapped {
        let opts = self.opts;
        let mut dirs: Vec<(PathBytes, PathBytes, Entry)> = Vec::new();
        let mut others: Vec<Planned> = Vec::new();
        for e in batch {
            if e.kind == Kind::Dir && !opts.recursive && !self.keep_dirs {
                continue;
            }
            let dst_rel = join(sub, &e.path);
            let dst = join(dst_root, &dst_rel);
            let rel = self.rel_name(src_root, sub, &e.path);
            // Every source entry claims its destination here, before any
            // decision about it: that blocks two sources from mapping onto one
            // path, and it is what makes --delete safe — whatever happens
            // below (skip, filter, unsupported type, resumed from a journal),
            // a path the source has is never an extra.
            let claim = match e.kind {
                Kind::Dir => Claim::Dir,
                Kind::File => Claim::File {
                    dev: e.dev,
                    ino: e.ino,
                },
                Kind::Symlink if opts.links => Claim::Leaf,
                Kind::Fifo | Kind::Socket | Kind::CharDev | Kind::BlockDev if opts.devices => {
                    Claim::Leaf
                }
                _ => Claim::Weak,
            };
            let Some(contested) = self.claim_dst(&dst, &rel, claim) else {
                continue;
            };
            let src = join(src_root, &e.path);
            match claim {
                Claim::Dir => dirs.push((dst, dst_rel, e)),
                Claim::Weak if e.kind == Kind::Other => {
                    // Unknown type: never transferred.
                    self.progress.files_excluded.fetch_add(1, Relaxed);
                }
                Claim::Weak => {
                    // Symlink without -l, special without -D.
                    if opts.verbose > 0 {
                        self.progress
                            .eprintln(&format!("skipping non-regular file \"{rel}\""));
                    }
                    self.progress.files_excluded.fetch_add(1, Relaxed);
                }
                Claim::File { .. } | Claim::Leaf => others.push(Planned {
                    src,
                    dst,
                    dst_rel,
                    rel,
                    e,
                    contested,
                }),
            }
        }
        Mapped {
            dst_root: dst_root.to_vec(),
            dirs,
            others,
            dir_stats: None,
            other_stats: None,
        }
    }

    /// Several sources: every batch has been mapped and claimed, nothing
    /// applied. Contested claims (two sources naming one regular file) are
    /// fine only when one of them *is* the destination file; settle those
    /// with one stat pass, then apply everything if there was no conflict.
    fn replay_buffered(&mut self) -> Result<()> {
        let Some(mut buffered) = self.buffer.take() else {
            return Ok(());
        };
        // Every claimant of each contested destination, as a group: the first
        // (from dst_seen) plus all the contested ones. The group is fine only
        // if at most one *distinct* file among them is not the destination
        // file itself — otherwise two different contents want one path.
        let mut groups: std::collections::BTreeMap<PathBytes, (String, Vec<(u64, u64)>)> =
            std::collections::BTreeMap::new();
        for p in buffered
            .iter()
            .flat_map(|m| m.others.iter().filter(|p| p.contested))
        {
            let g = groups.entry(p.dst.clone()).or_insert_with(|| {
                let first = match self.dst_seen.get(&p.dst) {
                    Some(Claim::File { dev, ino }) => vec![(*dev, *ino)],
                    _ => Vec::new(),
                };
                (p.rel.clone(), first)
            });
            g.1.push((p.e.dev, p.e.ino));
        }
        if !groups.is_empty() {
            let stats = self.stat_many(groups.keys().cloned().collect())?;
            for ((dst, (rel, ids)), st) in groups.into_iter().zip(stats) {
                let dst_id = st.filter(|_| self.opts.same_host).map(|d| (d.dev, d.ino));
                // Every claimant must be the destination file itself (a copy
                // onto itself, written by nobody). One claimant being that
                // file does not license another to overwrite it: the user
                // named it as a source, and it would be lost.
                let total = ids.len();
                let mut distinct: Vec<(u64, u64)> =
                    ids.into_iter().filter(|id| Some(*id) != dst_id).collect();
                distinct.sort_unstable();
                distinct.dedup();
                if !distinct.is_empty() {
                    self.progress.error(&format!(
                        "syq: {rel}: {total} sources map to the same destination {} — refusing to clobber it",
                        display(&dst)
                    ));
                    self.collision = true;
                }
            }
        }
        if self.collision {
            return Ok(());
        }
        if let Some(root) = self.create_root.take() {
            mkdir_root(self.dst, &root)?;
        }
        // Validated: from here on they are ordinary entries (the one that is
        // the destination file skips itself; the other is written).
        for m in &mut buffered {
            for p in &mut m.others {
                p.contested = false;
            }
        }
        for m in buffered {
            self.apply_mapped(m)?;
        }
        Ok(())
    }

    /// Everything after the mapping loop: stat, create directories, filter,
    /// enqueue.
    fn apply_mapped(&mut self, mapped: Mapped) -> Result<()> {
        let opts = self.opts;
        let Mapped {
            dst_root,
            dirs,
            mut others,
            dir_stats,
            mut other_stats,
        } = mapped;
        let dst_root = &dst_root[..];

        // Directories: one stat pass decides everything about each one, and
        // the same filtered list drives creation, listing and deferred
        // metadata so they can't disagree.
        if !dirs.is_empty() {
            let stats = if self.destination_tree_known_missing {
                vec![None; dirs.len()]
            } else if let Some(stats) = dir_stats {
                stats
            } else {
                self.stat_directories_with_dry_run_overlay(&dirs, dst_root)?
            };
            let mut planned: Vec<(PathBytes, PathBytes, Entry, Option<Entry>)> = Vec::new();
            for ((p, dst_rel, e), mut st) in dirs.into_iter().zip(stats) {
                // Keep the parent-first overlay invariant explicit here too:
                // a directory below a replacement is missing in the virtual
                // destination tree.
                if opts.dry_run && Self::under_any(&self.dry_run_replaced_dirs, &p, dst_root) {
                    st = None;
                }
                let is_dir = matches!(st, Some(ref d) if d.kind == Kind::Dir);
                if opts.verify_only {
                    if !is_dir {
                        self.progress.error(&format!(
                            "{} {}/ (directory)",
                            if st.is_none() { "MISSING" } else { "DIFFERS" },
                            display(&p)
                        ));
                    }
                    continue;
                }
                // --existing creates nothing. A non-directory at the path (a
                // file, a symlink even to a directory — in-tree symlinks are
                // replaced, never traversed) counts as missing: we won't
                // replace it and won't write through it, and since entries
                // come parent-first, everything below is skipped too.
                // --ignore-existing never touches what exists either: an
                // existing non-directory where a directory maps stays, and the
                // mapped directory with its whole subtree is skipped, visibly
                // (rsync would unlink the file; see RSYNC-COMPAT.md).
                let conflict = opts.ignore_existing && !is_dir && st.is_some();
                if conflict
                    || (opts.existing && !is_dir)
                    || ((opts.existing || opts.ignore_existing)
                        && self.under_missing_dir(&p, dst_root))
                {
                    if conflict && !opts.quiet {
                        self.progress.eprintln(&format!(
                            "syq: keeping existing {}; skipping the directory mapped onto it",
                            display(&p)
                        ));
                    }
                    self.missing_dirs.insert(p);
                    continue;
                }
                if opts.dry_run && st.as_ref().is_some_and(|d| d.kind != Kind::Dir) {
                    self.dry_run_replaced_dirs.insert(p.clone());
                }
                planned.push((p, dst_rel, e, st));
            }
            if opts.dry_run {
                let mut meta_flags = opts.flags;
                if !opts.perms {
                    meta_flags &= !flags::MODE;
                }
                for (p, _, e, destination) in &planned {
                    match destination {
                        None => {
                            self.dry_run_changes.directories.insert(p.clone());
                            if opts.verbose > 0 {
                                self.progress.println(&format!(
                                    "create directory {} (destination missing)",
                                    display_directory(p)
                                ));
                            }
                        }
                        Some(d) if d.kind != Kind::Dir => {
                            if self.dry_run_changes.directories.insert(p.clone()) {
                                self.dry_run_changes.type_replacements += 1;
                            }
                            if opts.verbose > 0 {
                                self.progress.println(&format!(
                                    "replace with directory {} (destination is {})",
                                    display_directory(p),
                                    kind_label(d.kind)
                                ));
                            }
                        }
                        Some(d) if metadata_differs(e, d, meta_flags) => {
                            self.dry_run_changes.metadata_directories.insert(p.clone());
                            if opts.verbose > 0 {
                                self.progress.println(&format!(
                                    "update metadata {} (requested directory metadata differs)",
                                    display_directory(p)
                                ));
                            }
                        }
                        Some(_) => {}
                    }
                }
            } else if !opts.verify_only {
                // A directory about to occupy a checkpoint-complete file's
                // path needs a write-ahead invalidation (see the fn).
                planned.retain(|(_, dst_rel, _, _)| self.invalidate_completion(dst_rel));
                // Create new dirs; also "create" existing ones we can't yet
                // write into (0o700 not set) so apply() opens them up.
                let new_dirs: Vec<Op> = planned
                    .iter()
                    .filter(|(_, _, _, st)| {
                        !matches!(st, Some(d) if d.kind == Kind::Dir && d.mode & 0o700 == 0o700)
                    })
                    .map(|(p, _, e, _)| Op::Mkdir {
                        path: p.clone(),
                        mode: e.mode,
                    })
                    .collect();
                if !new_dirs.is_empty() {
                    let n = new_dirs.len();
                    let names: Vec<PathBytes> = new_dirs
                        .iter()
                        .map(|op| match op {
                            Op::Mkdir { path, .. } => path.clone(),
                            _ => unreachable!(),
                        })
                        .collect();
                    let errs = self.apply(new_dirs)?;
                    let mut failed = 0;
                    for (name, err) in names.iter().zip(errs) {
                        if let Some(err) = err {
                            failed += 1;
                            self.progress.error(&format!("syq: {err}"));
                        } else if opts.verbose > 0 {
                            self.progress.println(&format!("{}/", display(name)));
                        }
                    }
                    self.dirs_created += (n - failed) as u64;
                }
                let mut flags = opts.flags;
                if !opts.perms {
                    flags &= !flags::MODE;
                }
                for (p, _, e, s) in &planned {
                    let depth = p.iter().filter(|&&c| c == b'/').count();
                    let mut meta = e.meta();
                    let mut flags = flags;
                    // An existing directory we had to open up (u+rwx) gets its
                    // own mode back at the end when nothing else sets it.
                    if flags & flags::MODE == 0 {
                        if let Some(d) = s {
                            if d.kind == Kind::Dir && d.mode & 0o700 != 0o700 {
                                meta.mode = d.mode & 0o7777;
                                flags |= flags::MODE;
                            }
                        }
                    }
                    self.deferred.push((p.clone(), meta, flags, depth));
                }
            }
        }

        if others.is_empty() {
            return Ok(());
        }
        // An explicitly requested checkpoint may trust a matching source
        // fingerprint without a destination stat. This runs after the mapping
        // loop above, so a skipped file has already claimed its destination
        // (--delete never treats it as an extra).
        if self.completed.is_some() && !opts.checksum {
            let completed = self.completed.clone().unwrap();
            let mut kept = Vec::with_capacity(others.len());
            for p in others.into_iter() {
                let virtually_missing =
                    opts.dry_run && Self::under_any(&self.dry_run_replaced_dirs, &p.dst, dst_root);
                if p.e.kind == Kind::File && !virtually_missing {
                    if let Some(c) = completed.get(&p.dst_rel) {
                        if c.matches(&p.e, opts.flags) {
                            self.progress.files_skipped.fetch_add(1, Relaxed);
                            self.progress.bytes_skipped.fetch_add(p.e.size, Relaxed);
                            continue;
                        }
                    }
                }
                kept.push(p);
            }
            others = kept;
        }
        let stats = if self.destination_tree_known_missing {
            vec![None; others.len()]
        } else if let Some(stats) = &mut other_stats {
            others
                .iter()
                .map(|planned| {
                    stats
                        .remove(&planned.dst)
                        .expect("batch plan covered every mapped leaf")
                })
                .collect()
        } else {
            self.stat_many_with_dry_run_overlay(
                others.iter().map(|p| p.dst.clone()).collect(),
                dst_root,
            )?
        };
        let mut ops: Vec<Op> = Vec::new();
        let mut op_names: Vec<String> = Vec::new();
        // Metadata repairs for quick-check-identical files, each with the
        // checkpoint record once the repair has actually succeeded.
        let mut meta_fixes: Vec<(Op, Option<QuickCheckRecord>)> = Vec::new();
        for (p, dst_entry) in others.into_iter().zip(stats) {
            let Planned {
                src: src_path,
                dst: dst_path,
                dst_rel,
                rel,
                e,
                contested,
            } = p;
            if (opts.existing || opts.ignore_existing)
                && self.under_missing_dir(&dst_path, dst_root)
            {
                // Below a directory we won't create: nothing to do, even if the
                // destination has something reachable there through a symlink.
                self.progress.files_excluded.fetch_add(1, Relaxed);
                continue;
            }
            match e.kind {
                Kind::File => {
                    if self.unusable_files.contains(&dst_path) {
                        // register_namespace reported it; nothing can stage here.
                        continue;
                    }
                    // Never copy a file onto itself (same path, hardlink, or a
                    // symlinked alias) — with --inplace that would truncate the
                    // source. Only possible when both ends are the same machine.
                    // This is also what settles a contested claim: two sources
                    // may map onto one destination file only if one of them
                    // *is* that file (so nothing is actually written twice).
                    let same_file = opts.same_host
                        && dst_entry
                            .as_ref()
                            .is_some_and(|d| d.dev == e.dev && d.ino == e.ino);
                    if same_file {
                        if !opts.quiet {
                            self.progress.eprintln(&format!(
                                "skipping {rel}: source and destination are the same file"
                            ));
                        }
                        self.progress.files_excluded.fetch_add(1, Relaxed);
                        if !contested {
                            // Nothing will be written here; let another source have it.
                            self.dst_seen.insert(dst_path, Claim::Weak);
                        }
                        continue;
                    }
                    if contested {
                        self.progress.error(&format!(
                            "syq: {rel}: two sources map to the same destination {} — refusing to clobber it",
                            display(&dst_path)
                        ));
                        self.collision = true;
                        continue;
                    }
                    if opts.max_size.is_some_and(|m| e.size > m)
                        || opts.min_size.is_some_and(|m| e.size < m)
                        || self.skip_existing(&dst_entry)
                    {
                        self.progress.files_excluded.fetch_add(1, Relaxed);
                        continue;
                    }
                    let same = dst_entry.as_ref().is_some_and(|d| {
                        d.kind == Kind::File
                            && d.size == e.size
                            && (opts.flags & flags::TIMES != 0 && d.mtime == e.mtime)
                    });
                    let dst_newer = opts.update
                        && dst_entry.as_ref().is_some_and(|d| {
                            d.kind == Kind::File
                                && (d.mtime, d.mtime_nsec) > (e.mtime, e.mtime_nsec)
                        });
                    if dst_newer {
                        self.progress.files_excluded.fetch_add(1, Relaxed);
                        continue;
                    }
                    if opts.verify_only {
                        if dst_entry.as_ref().is_some_and(|d| d.kind == Kind::File) {
                            self.enqueue(
                                src_path.clone(),
                                dst_path.clone(),
                                rel.clone(),
                                dst_rel.clone(),
                                e.clone(),
                                dst_entry.clone(),
                            );
                        } else {
                            self.progress.error(&format!("MISSING {rel}"));
                        }
                    } else if same && !opts.checksum {
                        // Content is up to date, but still reconcile metadata
                        // (mode/owner/group) the way rsync does — a skipped file
                        // shouldn't keep stale permissions.
                        if let Some(d) = &dst_entry {
                            let mut ff = 0u8;
                            if opts.flags & flags::MODE != 0 && d.mode & 0o7777 != e.mode & 0o7777 {
                                ff |= flags::MODE;
                            }
                            if opts.flags & flags::OWNER != 0 && d.uid != e.uid {
                                ff |= flags::OWNER;
                            }
                            if opts.flags & flags::GROUP != 0 && d.gid != e.gid {
                                ff |= flags::GROUP;
                            }
                            if ff != 0 {
                                self.progress.files_skipped.fetch_add(1, Relaxed);
                                self.progress.bytes_skipped.fetch_add(e.size, Relaxed);
                                if opts.dry_run {
                                    self.dry_run_changes.metadata_files += 1;
                                    if opts.verbose > 0 {
                                        self.progress.println(&format!(
                                            "update metadata {} (requested file metadata differs)",
                                            display(&dst_path)
                                        ));
                                    }
                                    continue;
                                }
                                meta_fixes.push((
                                    Op::SetFileMetaIfSame {
                                        path: dst_path.clone(),
                                        expected_dev: d.dev,
                                        expected_ino: d.ino,
                                        meta: e.meta(),
                                        flags: ff,
                                    },
                                    self.checkpoint
                                        .as_ref()
                                        .map(|_| (dst_rel.clone(), e.clone())),
                                ));
                                continue;
                            }
                        }
                        self.progress.files_skipped.fetch_add(1, Relaxed);
                        self.progress.bytes_skipped.fetch_add(e.size, Relaxed);
                        if let Some(checkpoint) = &self.checkpoint {
                            checkpoint.record_complete(&dst_rel, &e, "quick-check");
                        }
                    } else if opts.dry_run {
                        self.progress.files_total.fetch_add(1, Relaxed);
                        self.progress.bytes_total.fetch_add(e.size, Relaxed);
                        self.progress.files_done.fetch_add(1, Relaxed);
                        self.dry_run_changes.regular_files += 1;
                        if dst_entry.as_ref().is_some_and(|d| d.kind != Kind::File) {
                            self.dry_run_changes.type_replacements += 1;
                        }
                        if opts.verbose > 0 {
                            let shown = display(&dst_path);
                            let action = match &dst_entry {
                                None => format!("create file {shown} (destination missing)"),
                                Some(d) if d.kind != Kind::File => format!(
                                    "replace with file {shown} (destination is {})",
                                    kind_label(d.kind)
                                ),
                                Some(d) if d.size != e.size => {
                                    format!("update file {shown} (size differs)")
                                }
                                Some(_) if opts.checksum => {
                                    format!("update file {shown} (content comparison requested)")
                                }
                                Some(d)
                                    if opts.flags & flags::TIMES != 0
                                        && (d.mtime, d.mtime_nsec) != (e.mtime, e.mtime_nsec) =>
                                {
                                    format!("update file {shown} (modification time differs)")
                                }
                                Some(_) => {
                                    format!("update file {shown} (content quick check unavailable)")
                                }
                            };
                            self.progress.println(&action);
                        }
                    } else {
                        self.enqueue(
                            src_path,
                            dst_path,
                            rel,
                            dst_rel.clone(),
                            e.clone(),
                            dst_entry,
                        );
                    }
                }
                Kind::Symlink => {
                    if self.skip_existing(&dst_entry) {
                        self.progress.files_excluded.fetch_add(1, Relaxed);
                        continue;
                    }
                    let target = e.link.clone().unwrap_or_default();
                    let same = dst_entry.as_ref().is_some_and(|d| {
                        d.kind == Kind::Symlink && d.link.as_deref() == Some(&target[..])
                    });
                    if opts.verify_only {
                        if !same {
                            self.progress.error(&format!("DIFFERS {rel} (symlink)"));
                        }
                        continue;
                    }
                    if same {
                        continue;
                    }
                    if opts.dry_run {
                        self.dry_run_changes.symlinks += 1;
                        if dst_entry.as_ref().is_some_and(|d| d.kind != Kind::Symlink) {
                            self.dry_run_changes.type_replacements += 1;
                        }
                        if opts.verbose > 0 {
                            let shown = display(&dst_path);
                            let action = match &dst_entry {
                                None => format!(
                                    "create symlink {shown} -> {} (destination missing)",
                                    display(&target)
                                ),
                                Some(d) if d.kind != Kind::Symlink => format!(
                                    "replace with symlink {shown} -> {} (destination is {})",
                                    display(&target),
                                    kind_label(d.kind)
                                ),
                                Some(_) => format!(
                                    "update symlink {shown} -> {} (target differs)",
                                    display(&target)
                                ),
                            };
                            self.progress.println(&action);
                        }
                        continue;
                    }
                    if !self.invalidate_completion(&dst_rel) {
                        continue;
                    }
                    op_names.push(format!("{rel} -> {}", display(&target)));
                    ops.push(Op::Symlink {
                        path: dst_path.clone(),
                        target,
                    });
                    ops.push(Op::SetMeta {
                        path: dst_path,
                        meta: e.meta(),
                        flags: opts.flags & !flags::MODE,
                    });
                    self.links_created += 1;
                }
                Kind::Fifo | Kind::Socket | Kind::CharDev | Kind::BlockDev => {
                    if self.skip_existing(&dst_entry) {
                        self.progress.files_excluded.fetch_add(1, Relaxed);
                        continue;
                    }
                    let same = dst_entry
                        .as_ref()
                        .is_some_and(|d| d.kind == e.kind && d.rdev == e.rdev);
                    if opts.verify_only {
                        if !same {
                            let what = if dst_entry.is_none() {
                                "MISSING"
                            } else {
                                "DIFFERS"
                            };
                            self.progress.error(&format!("{what} {rel} (special file)"));
                        }
                        continue;
                    }
                    if same || opts.dry_run {
                        if opts.dry_run && !same {
                            self.dry_run_changes.specials += 1;
                            if dst_entry.as_ref().is_some_and(|d| d.kind != e.kind) {
                                self.dry_run_changes.type_replacements += 1;
                            }
                            if opts.verbose > 0 {
                                let shown = display(&dst_path);
                                let action = match &dst_entry {
                                    None => format!(
                                        "create {} {shown} (destination missing)",
                                        kind_label(e.kind)
                                    ),
                                    Some(d) if d.kind != e.kind => format!(
                                        "replace with {} {shown} (destination is {})",
                                        kind_label(e.kind),
                                        kind_label(d.kind)
                                    ),
                                    Some(_) => format!(
                                        "update {} {shown} (device identity differs)",
                                        kind_label(e.kind)
                                    ),
                                };
                                self.progress.println(&action);
                            }
                        }
                        continue;
                    }
                    if !self.invalidate_completion(&dst_rel) {
                        continue;
                    }
                    op_names.push(rel);
                    ops.push(Op::Mknod {
                        path: dst_path.clone(),
                        mode: e.mode,
                        rdev: e.rdev,
                    });
                    ops.push(Op::SetMeta {
                        path: dst_path,
                        meta: e.meta(),
                        flags: opts.flags,
                    });
                    self.specials_created += 1;
                }
                Kind::Dir | Kind::Other => unreachable!("handled in the mapping loop"),
            }
        }
        if !meta_fixes.is_empty() {
            let (ops, records): (Vec<Op>, Vec<_>) = meta_fixes.into_iter().unzip();
            for (err, rec) in self.apply(ops)?.into_iter().zip(records) {
                match err {
                    Some(err) => self.progress.error(&format!("syq: {err}")),
                    None => {
                        // Only now is the file complete in every respect.
                        if let (Some(checkpoint), Some((rel, entry))) = (&self.checkpoint, rec) {
                            checkpoint.record_complete(&rel, &entry, "quick-check");
                        }
                    }
                }
            }
        }
        if !ops.is_empty() {
            let errs = self.apply(ops)?;
            // Two ops per item: creation then metadata.
            for (i, name) in op_names.iter().enumerate() {
                let e1 = errs.get(2 * i).cloned().flatten();
                let e2 = errs.get(2 * i + 1).cloned().flatten();
                if let Some(e) = e1.or(e2) {
                    self.progress.error(&format!("syq: {e}"));
                } else if opts.verbose > 0 {
                    self.progress.println(name);
                }
            }
        }
        Ok(())
    }

    fn collect_namespace_files(
        &mut self,
        batch: &[Entry],
        src_root: &[u8],
        sub: &[u8],
        dst_root: &[u8],
    ) -> Vec<(PathBytes, String)> {
        let mut files = Vec::new();
        for entry in batch {
            if !self.entry_is_payload(entry) {
                continue;
            }
            let source_name = if entry.path.is_empty() {
                src_root
                    .rsplit(|&byte| byte == b'/')
                    .next()
                    .unwrap_or(src_root)
            } else {
                entry
                    .path
                    .rsplit(|&byte| byte == b'/')
                    .next()
                    .unwrap_or(&entry.path)
            };
            if is_partial_name(OsStr::from_bytes(source_name)) {
                self.source_partials += 1;
            }
            let dst_rel = join(sub, &entry.path);
            let dst_path = join(dst_root, &dst_rel);
            let rel = self.rel_name(src_root, sub, &entry.path);
            let reserved_payload = dst_path
                .rsplit(|&byte| byte == b'/')
                .next()
                .is_some_and(|name| is_partial_name(OsStr::from_bytes(name)));
            if reserved_payload {
                if let Some(owner) = self.sidecar_paths.get(&dst_path) {
                    self.progress.error(&format!(
                        "syq: source payload {rel} maps to {}, which is the reserved sidecar for {owner}",
                        display(&dst_path)
                    ));
                    self.collision = true;
                }
                self.payload_paths
                    .entry(dst_path.clone())
                    .or_insert(rel.clone());
            }
            if entry.kind == Kind::File && !self.opts.inplace && !self.opts.verify_only {
                files.push((dst_path, rel));
            }
        }
        files
    }

    fn register_namespace(
        &mut self,
        files: Vec<(PathBytes, String)>,
        mapped: &mut Mapped,
    ) -> Result<()> {
        if files.is_empty() {
            return Ok(());
        }
        // Several sources are replayed only after every collision check, and
        // dry runs may need a depth-by-depth virtual overlay. Keep their stats
        // at the existing application point rather than caching stale or
        // unsafe observations. Sidecar resolution still uses this request.
        let pre_stat = self.opts.dst_remote
            && self.buffer.is_none()
            && !self.opts.dry_run
            && !self.destination_tree_known_missing;
        let directories: Vec<PathBytes> = if pre_stat {
            mapped
                .dirs
                .iter()
                .map(|(path, _, _)| path.clone())
                .collect()
        } else {
            Vec::new()
        };
        let other_paths: Vec<PathBytes> = if pre_stat {
            mapped
                .others
                .iter()
                .map(|planned| planned.dst.clone())
                .collect()
        } else {
            Vec::new()
        };
        // Sidecar resolution already costs a receiver turn for ordinary file
        // copies. Include the destination inspection in that same turn; the
        // receiver omits leaf stats when directory repair must happen first.
        let partial_paths = files.iter().map(|(path, _)| path.clone()).collect();
        let (sidecars, dir_stats, other_stats) = if pre_stat {
            let response = self.dst.call(Request::PlanBatch {
                partial_paths,
                partial_id: *self
                    .opts
                    .partial_id
                    .get()
                    .expect("partial identity initialized before planning"),
                directories: directories.clone(),
                others: other_paths.clone(),
            })?;
            match ok(response, "plan destination batch")? {
                Response::BatchPlan {
                    partial_paths,
                    directories: dir_stats,
                    others: other_stats,
                } if partial_paths.len() == files.len()
                    && dir_stats.len() == directories.len()
                    && other_stats
                        .as_ref()
                        .is_none_or(|stats| stats.len() == other_paths.len()) =>
                {
                    (partial_paths, dir_stats, other_stats)
                }
                other => bail!("unexpected response {other:?}"),
            }
        } else {
            (self.partial_paths(partial_paths)?, Vec::new(), None)
        };
        if pre_stat {
            mapped.dir_stats = Some(dir_stats);
            if let Some(stats) = other_stats {
                mapped.other_stats = Some(other_paths.into_iter().zip(stats).collect());
            }
        }
        for ((dst_path, file_rel), sidecar) in files.into_iter().zip(sidecars) {
            let sidecar = match sidecar {
                Ok(sidecar) => sidecar,
                Err(error) => {
                    self.progress.error(&format!(
                        "syq: {file_rel}: cannot create a safe sidecar beside {}: {error}",
                        display(&dst_path)
                    ));
                    self.unusable_files.insert(dst_path);
                    continue;
                }
            };
            if let Some(payload_rel) = self.payload_paths.get(&sidecar) {
                self.progress.error(&format!(
                    "syq: source payload {payload_rel} maps to {}, which is the reserved sidecar for {file_rel}",
                    display(&sidecar)
                ));
                self.collision = true;
            }
            if let Some(other) = self.sidecar_paths.insert(sidecar.clone(), file_rel.clone()) {
                if other != file_rel {
                    self.progress.error(&format!(
                        "syq: {other} and {file_rel} require the same sidecar {}",
                        display(&sidecar)
                    ));
                    self.collision = true;
                }
            }
        }
        Ok(())
    }

    fn entry_is_payload(&self, entry: &Entry) -> bool {
        match entry.kind {
            Kind::Dir => self.opts.recursive || self.keep_dirs,
            Kind::File => true,
            Kind::Symlink => self.opts.links,
            Kind::Fifo | Kind::Socket | Kind::CharDev | Kind::BlockDev => self.opts.devices,
            Kind::Other => false,
        }
    }

    /// Display name for a source entry: its destination-relative path, or the
    /// source's basename when a single file is copied to an exact destination.
    fn rel_name(&self, src_root: &[u8], sub_b: &[u8], path: &[u8]) -> String {
        let r = join(sub_b, path);
        if r.is_empty() {
            display(src_root.rsplit(|&c| c == b'/').next().unwrap_or(src_root))
        } else {
            display(&r)
        }
    }

    /// Record a leaf (file/symlink/special) destination; return false if this
    /// exact destination was already claimed by another source (a collision).
    /// Some(contested) if the claim stands; None on a conflict (reported).
    fn claim_dst(&mut self, dst: &PathBytes, rel: &str, claim: Claim) -> Option<bool> {
        match (self.dst_seen.get(dst), claim) {
            (Some(Claim::Dir), Claim::Dir) | (Some(_), Claim::Weak) => Some(false),
            (Some(Claim::Weak), c) => {
                self.dst_seen.insert(dst.clone(), c);
                Some(false)
            }
            (Some(Claim::File { .. }), Claim::File { .. }) => Some(true),
            (Some(_), _) => {
                self.progress.error(&format!(
                    "syq: {rel}: two sources map to the same destination {} with conflicting types — refusing to clobber it",
                    display(dst)
                ));
                self.collision = true;
                None
            }
            (None, c) => {
                self.dst_seen.insert(dst.clone(), c);
                Some(false)
            }
        }
    }

    /// --existing: is some directory between the destination root and `dst`
    /// one we decided not to create?
    fn under_missing_dir(&self, dst: &[u8], dst_root: &[u8]) -> bool {
        Self::under_any(&self.missing_dirs, dst, dst_root)
    }

    /// Is `dst`, or a directory between the destination root and it, in `set`?
    fn under_any(set: &std::collections::HashSet<PathBytes>, dst: &[u8], dst_root: &[u8]) -> bool {
        if set.is_empty() {
            return false;
        }
        // The root itself may be the missing one (e.g. a symlink to a
        // directory elsewhere, which we must neither replace nor write through).
        if set.contains(dst_root) {
            return true;
        }
        let mut end = dst.len();
        while let Some(i) = dst[..end].iter().rposition(|&c| c == b'/') {
            if i <= dst_root.len() {
                break;
            }
            if set.contains(&dst[..i]) {
                return true;
            }
            end = i;
        }
        false
    }

    fn enqueue(
        &mut self,
        src: PathBytes,
        dst: PathBytes,
        rel: String,
        rel_bytes: PathBytes,
        entry: Entry,
        dst_entry: Option<Entry>,
    ) {
        self.progress.files_total.fetch_add(1, Relaxed);
        self.progress.bytes_total.fetch_add(entry.size, Relaxed);
        self.sched.push_file(FileJob {
            src,
            dst,
            rel,
            rel_bytes,
            entry,
            dst_entry,
            attempts: 0,
            done: Arc::new(AtomicU64::new(0)),
            inplace: false,
        });
    }

    /// Write-ahead invalidation for a transfer-time type change: something
    /// non-regular is about to occupy a path the checkpoint recorded as a
    /// complete file. False = the intent could not be persisted; the caller
    /// must not create the entry (a checkpointed retry would otherwise trust
    /// the stale Complete record).
    fn invalidate_completion(&self, dst_rel: &[u8]) -> bool {
        let (Some(completed), Some(checkpoint)) = (&self.completed, &self.checkpoint) else {
            return true;
        };
        if dst_rel.is_empty() || !completed.contains_key(dst_rel) {
            return true;
        }
        if checkpoint
            .record_deleted_batch(std::iter::once(dst_rel))
            .is_ok()
        {
            true
        } else {
            self.progress.error(&format!(
                "syq: {}: cannot persist checkpoint invalidation; not replacing it",
                display(dst_rel)
            ));
            false
        }
    }

    /// --ignore-existing / --existing for a leaf, given what's on the destination.
    fn skip_existing(&self, dst_entry: &Option<Entry>) -> bool {
        (self.opts.ignore_existing && dst_entry.is_some())
            || (self.opts.existing && dst_entry.is_none())
    }

    /// Walk every destination directory the sources map onto and record what
    /// isn't claimed by a source entry. The same ignore patterns apply,
    /// anchored at the same roots, so an ignored path is out of scope on both
    /// sides and never deleted — and a directory holding one can't be deleted
    /// either, which is decided here (not by a failing rmdir) so -n and the
    /// real run agree. Partials are recorded separately: whether one is
    /// garbage depends on how its file fares this run.
    fn plan_deletes(&mut self) -> Result<()> {
        let mut roots = std::mem::take(&mut self.delete_roots);
        roots.sort();
        roots.dedup();
        let inside = |p: &[u8], r: &[u8]| {
            p.starts_with(r) && (r.ends_with(b"/") || p.get(r.len()) == Some(&b'/'))
        };
        for (root, sub) in roots.clone() {
            // Every root is walked with its own -i anchoring. A root nested in
            // this one (`syq rsync --delete a b/ dst`: dst/a inside dst) is left to
            // its own walk, so its patterns apply and nothing is deleted twice.
            let nested: Vec<PathBytes> = roots
                .iter()
                .filter(|(r, _)| *r != root && inside(r, &root))
                .map(|(r, _)| r.clone())
                .collect();
            // Not there yet (a dry run into a new destination): nothing to delete.
            if stat_one(self.dst, &root, false)?.is_none() {
                continue;
            }
            // --delete-excluded: walk without the patterns, so ignored paths
            // are ordinary unclaimed extras (and nothing is protected).
            let ignore = if self.opts.delete_excluded {
                Vec::new()
            } else {
                self.opts.ignore.clone()
            };
            let mut found = Deletes::default();
            // Destination directories that hold an ignored path, so must stay.
            let mut protected: std::collections::HashSet<PathBytes> =
                std::collections::HashSet::new();
            let seen = &self.dst_seen;
            let live_sidecars = &self.live_sidecars;
            // Destination directories whose path the source claims as a
            // non-directory (a file we chose not to send, a symlink skipped
            // without -l, ...). The source has that path, so syq doesn't touch
            // it — and gutting the directory underneath would be touching it.
            let mut shielded: std::collections::HashSet<PathBytes> =
                std::collections::HashSet::new();
            let res = self.dst.scan(
                &root,
                false,
                &ignore,
                true,
                &mut |batch: Vec<Entry>| {
                    for e in batch {
                        if e.path.is_empty() {
                            continue;
                        }
                        let full = join(&root, &e.path);
                        if nested.iter().any(|n| *n == full || inside(&full, n))
                            || Planner::under_any(&shielded, &full, &root)
                        {
                            continue;
                        }
                        match seen.get(&full) {
                            Some(Claim::Dir) => continue,
                            Some(_) => {
                                if e.kind == Kind::Dir {
                                    shielded.insert(full);
                                }
                                continue;
                            }
                            None => {}
                        }
                        let dst_rel = join(&sub, &e.path);
                        let rel = display(&dst_rel);
                        let name = e.path.rsplit(|&c| c == b'/').next().unwrap_or(&e.path);
                        // The only sidecar-patterned files that are not extras
                        // are this job's live ones — exactly those the
                        // namespace preflight listed. Membership is the whole
                        // test: a path is only in that set if the receiver
                        // generated it for this job, and the compact
                        // (near-PATH_MAX) form doesn't even embed the job id,
                        // so there is nothing valid to compare names against.
                        // Anything else matching the pattern is an ordinary
                        // extra: syq itself copies such names as payload now,
                        // so a foreign-looking name proves nothing, and a
                        // --delete run concurrent with another job would be
                        // deleting that job's unclaimed payload anyway.
                        if e.kind == Kind::File
                            && crate::fsops::is_partial_name(OsStr::from_bytes(name))
                            && live_sidecars.binary_search(&full).is_ok()
                        {
                            // Live resume state of this very command.
                        } else {
                            if e.kind == Kind::Dir {
                                let depth = full.iter().filter(|&&c| c == b'/').count();
                                found.dirs.entry(depth).or_default().push((
                                    full,
                                    format!("{rel}/"),
                                    dst_rel,
                                ));
                            } else {
                                found.leaves.push((full, rel, dst_rel));
                            }
                        }
                    }
                    Ok(())
                },
                &mut |paths: Vec<PathBytes>| {
                    for p in paths {
                        // Every ancestor of an ignored path is protected.
                        for (i, &c) in p.iter().enumerate() {
                            if c == b'/' {
                                protected.insert(join(&root, &p[..i]));
                            }
                        }
                    }
                    Ok(())
                },
                &mut |w| {
                    self.delete_walk_failed = true;
                    self.progress.error(&format!("syq: delete: {w}"))
                },
            );
            res?;
            self.deletes.leaves.append(&mut found.leaves);
            for (d, v) in found.dirs {
                for (path, rel, dst_rel) in v {
                    if protected.contains(&path) {
                        self.progress
                            .eprintln(&format!("syq: not deleting {rel}: it holds ignored paths"));
                    } else {
                        self.deletes
                            .dirs
                            .entry(d)
                            .or_default()
                            .push((path, rel, dst_rel));
                    }
                }
            }
        }
        Ok(())
    }

    /// Remove what plan_deletes found: leaves first, then directories deepest
    /// first. Returns the number of entries removed (or that would be, with -n).
    fn run_deletes(&mut self) -> Result<u64> {
        let opts = self.opts;
        let leaves = std::mem::take(&mut self.deletes.leaves);
        let dirs = std::mem::take(&mut self.deletes.dirs);
        let planned = leaves.len() as u64 + dirs.values().map(|v| v.len() as u64).sum::<u64>();
        if let Some(max) = opts.max_delete {
            if planned > max {
                self.progress.eprintln(&format!(
                    "syq: {planned} deletions planned, more than --max-delete {max}; deleting nothing"
                ));
                self.max_delete_hit = true;
                return Ok(0);
            }
        }
        let mut n = 0u64;
        let checkpoint = self.checkpoint.clone();
        let completed = self.completed.clone();
        let completion_recorded = move |dst_rel: &PathBytes| {
            completed
                .as_ref()
                .is_some_and(|map| map.contains_key(dst_rel))
        };
        // Set when deletion intents could not be made durable: from then on
        // nothing more is deleted — the checkpoint's stale Complete records
        // would otherwise outlive the files they describe.
        let intents_failed = std::cell::Cell::new(false);
        #[cfg(debug_assertions)]
        let mut held_after_delete = false;
        let mut run = |me: &mut Self,
                       items: &[(PathBytes, String, PathBytes)],
                       rmdir: bool|
         -> Result<()> {
            for chunk in items.chunks(1000) {
                if intents_failed.get() {
                    return Ok(());
                }
                if opts.dry_run {
                    for (_, rel, _) in chunk {
                        n += 1;
                        if opts.verbose > 0 {
                            me.progress
                                .println(&format!("delete {rel} (destination only)"));
                        }
                    }
                    continue;
                }
                // Write-ahead: the invalidation intents go into the checkpoint
                // before anything is removed — leaves and rmdirs alike (a dir
                // may sit where a complete file was recorded) — and gate it:
                // without a persisted intent the mutation must not happen.
                {
                    if let Some(c) = &checkpoint {
                        if let Err(e) = c.record_deleted_batch(
                            chunk
                                .iter()
                                .filter(|(_, _, dst_rel)| {
                                    !dst_rel.is_empty() && completion_recorded(dst_rel)
                                })
                                .map(|(_, _, dst_rel)| dst_rel.as_slice()),
                        ) {
                            me.progress.error(&format!(
                                    "syq: delete: could not persist deletion intents to the checkpoint ({e:#}); leaving the remaining extras in place"
                                ));
                            intents_failed.set(true);
                            return Ok(());
                        }
                    }
                }
                let ops: Vec<Op> = chunk
                    .iter()
                    .map(|(p, _, _)| {
                        if rmdir {
                            Op::Rmdir { path: p.clone() }
                        } else {
                            // Never Remove: that recurses into a directory
                            // that appeared here since the walk.
                            Op::Unlink { path: p.clone() }
                        }
                    })
                    .collect();
                let errs = me.apply(ops)?;
                #[cfg(debug_assertions)]
                if !held_after_delete {
                    held_after_delete = true;
                    if let Some(ms) = std::env::var_os("SYQ_TEST_HOLD_AFTER_DELETE_MS") {
                        if let Ok(ms) = ms.to_string_lossy().parse::<u64>() {
                            std::thread::sleep(std::time::Duration::from_millis(ms));
                        }
                    }
                }
                for ((_, rel, _), err) in chunk.iter().zip(errs) {
                    match err {
                        None => {
                            n += 1;
                            if opts.verbose > 0 {
                                me.progress.println(&format!("deleting {rel}"));
                            }
                        }
                        Some(e) => me.progress.error(&format!("syq: delete {rel}: {e}")),
                    }
                }
            }
            Ok(())
        };
        run(self, &leaves, false)?;
        for (_, items) in dirs.iter().rev() {
            run(self, items, true)?;
        }
        Ok(n)
    }

    fn stat_many(&mut self, paths: Vec<PathBytes>) -> Result<Vec<Option<Entry>>> {
        stat_many(self.dst, paths, false)
    }

    /// lstat paths that remain reachable after the directory replacements a
    /// dry run has already planned. Descendants of those replacements are
    /// virtually missing; querying them would follow the old intermediate
    /// leaf that the real run removes first.
    fn stat_many_with_dry_run_overlay(
        &mut self,
        paths: Vec<PathBytes>,
        dst_root: &[u8],
    ) -> Result<Vec<Option<Entry>>> {
        if !self.opts.dry_run || self.dry_run_replaced_dirs.is_empty() {
            return self.stat_many(paths);
        }
        let mut visible = Vec::new();
        let mut indexes = Vec::new();
        let mut results = vec![None; paths.len()];
        for (index, path) in paths.into_iter().enumerate() {
            if !Self::under_any(&self.dry_run_replaced_dirs, &path, dst_root) {
                indexes.push(index);
                visible.push(path);
            }
        }
        for (index, entry) in indexes.into_iter().zip(self.stat_many(visible)?) {
            results[index] = entry;
        }
        Ok(results)
    }

    /// Stat dry-run directories parent-depth first. Discovering a destination
    /// leaf at one depth makes its whole source-directory subtree virtually
    /// missing at deeper levels, so no request traverses the leaf that the
    /// real run would already have replaced.
    fn stat_directories_with_dry_run_overlay(
        &mut self,
        dirs: &[(PathBytes, PathBytes, Entry)],
        dst_root: &[u8],
    ) -> Result<Vec<Option<Entry>>> {
        if !self.opts.dry_run {
            return self.stat_many(dirs.iter().map(|(path, _, _)| path.clone()).collect());
        }
        let existing = self.opts.existing;
        let ignore_existing = self.opts.ignore_existing;
        let mut replaced = self.dry_run_replaced_dirs.clone();
        let mut missing = self.missing_dirs.clone();
        let mut by_depth: std::collections::BTreeMap<usize, Vec<usize>> =
            std::collections::BTreeMap::new();
        for (index, (_, dst_rel, _)) in dirs.iter().enumerate() {
            let depth = if dst_rel.is_empty() {
                0
            } else {
                1 + dst_rel.iter().filter(|&&byte| byte == b'/').count()
            };
            by_depth.entry(depth).or_default().push(index);
        }

        let mut results = vec![None; dirs.len()];
        for indexes in by_depth.into_values() {
            let mut visible = Vec::new();
            let mut visible_indexes = Vec::new();
            for &index in &indexes {
                let path = &dirs[index].0;
                let hidden_by_replacement = Self::under_any(&replaced, path, dst_root);
                let hidden_by_option =
                    (existing || ignore_existing) && Self::under_any(&missing, path, dst_root);
                if !hidden_by_replacement && !hidden_by_option {
                    visible_indexes.push(index);
                    visible.push(path.clone());
                }
            }
            for (index, entry) in visible_indexes.into_iter().zip(self.stat_many(visible)?) {
                results[index] = entry;
            }
            for index in indexes {
                let path = &dirs[index].0;
                let entry = &results[index];
                let is_dir = entry.as_ref().is_some_and(|item| item.kind == Kind::Dir);
                let conflict = ignore_existing && !is_dir && entry.is_some();
                if conflict
                    || (existing && !is_dir)
                    || ((existing || ignore_existing) && Self::under_any(&missing, path, dst_root))
                {
                    missing.insert(path.clone());
                } else if entry.as_ref().is_some_and(|item| item.kind != Kind::Dir) {
                    replaced.insert(path.clone());
                }
            }
        }
        Ok(results)
    }

    fn partial_paths(
        &mut self,
        paths: Vec<PathBytes>,
    ) -> Result<Vec<std::result::Result<PathBytes, String>>> {
        match ok(
            self.dst.call(Request::PartialPaths {
                paths,
                partial_id: *self
                    .opts
                    .partial_id
                    .get()
                    .expect("partial identity initialized before planning"),
            })?,
            "compute sidecar paths",
        )? {
            Response::PathResults(paths) => Ok(paths),
            other => bail!("unexpected response {other:?}"),
        }
    }

    fn apply(&mut self, ops: Vec<Op>) -> Result<Vec<Option<String>>> {
        match ok(self.dst.call(Request::Apply(ops))?, "apply")? {
            Response::Applied(v) => Ok(v),
            other => bail!("unexpected response {other:?}"),
        }
    }

    fn apply_deferred(&mut self) -> Result<()> {
        let mut d = std::mem::take(&mut self.deferred);
        d.sort_by(|a, b| b.3.cmp(&a.3));
        for chunk in d.chunks(1000) {
            let ops: Vec<Op> = chunk
                .iter()
                .map(|(p, m, f, _)| Op::SetMeta {
                    path: p.clone(),
                    meta: *m,
                    flags: *f,
                })
                .collect();
            for err in self.apply(ops)?.into_iter().flatten() {
                self.progress.error(&format!("syq: {err}"));
            }
        }
        Ok(())
    }
}

struct Worker {
    id: usize,
    src: Box<dyn Conn>,
    dst: Box<dyn Conn>,
    sched: Arc<Sched>,
    progress: Arc<Progress>,
    opts: Arc<Opts>,
    checkpoint: CheckpointSlot,
    bwlimit: Option<Arc<BandwidthLimit>>,
    gate: Arc<Gate>,
    /// Debug timing: seconds blocked in source recv, dest send, dest ack, idle in scheduler.
    t: [f64; 4],
    fast: FastTiming,
    fast_batch_files: usize,
}

#[derive(Default)]
struct FastTiming {
    batches: usize,
    files: usize,
    source: f64,
    dest_send: f64,
    dest_ack: f64,
    restat: f64,
    bookkeeping: f64,
}

struct BlockDiff {
    ranges: Vec<(u64, u64)>,
    held_len: Option<u64>,
}

impl Worker {
    fn run(&mut self) -> Result<()> {
        let r = self.run_inner();
        if r.is_err() && !self.transport_dead() {
            // Fatal local/protocol failures cannot be healed by reopening a
            // transport. Wake peers so the whole transfer unwinds.
            self.sched.abort();
        }
        r
    }

    fn transport_dead(&self) -> bool {
        self.src.is_dead() || self.dst.is_dead()
    }

    fn collect_transport_stats(&mut self) -> Vec<TcpPairStats> {
        let mut stats = Vec::new();
        if let Some(value) = self.src.transport_stats() {
            stats.push(value);
        }
        if let Some(value) = self.dst.transport_stats() {
            stats.push(value);
        }
        stats
    }

    fn run_inner(&mut self) -> Result<()> {
        loop {
            if !self.gate.allowed(self.id) {
                // Parked by the tuner: keep the connections, take no work.
                let sched = self.sched.clone();
                if !self
                    .gate
                    .park(self.id, || sched.is_aborted() || sched.finished())
                {
                    return Ok(());
                }
            }
            let t0 = std::time::Instant::now();
            let item = self.sched.next();
            self.t[3] += t0.elapsed().as_secs_f64();
            match item {
                Item::Exit => {
                    if debug() {
                        eprintln!(
                            "syq: worker {} blocked: src recv {:.2}s, dst send {:.2}s, dst ack {:.2}s, idle {:.2}s; small: {} files in {} batches, src {:.2}s, dst send {:.2}s, dst ack {:.2}s, restat {:.2}s, bookkeeping {:.2}s",
                            self.id,
                            self.t[0],
                            self.t[1],
                            self.t[2],
                            self.t[3],
                            self.fast.files,
                            self.fast.batches,
                            self.fast.source,
                            self.fast.dest_send,
                            self.fast.dest_ack,
                            self.fast.restat,
                            self.fast.bookkeeping,
                        );
                    }
                    return Ok(());
                }
                Item::File(idx) => {
                    if self.fast_eligible(idx) {
                        let target = self
                            .sched
                            .begin_fast_batch(self.gate.active(), self.fast_batch_files);
                        let mut batch = vec![idx];
                        // The fast path reads a whole batch before sending it.
                        // Keep rate-limited batches to one file so a push can't
                        // accumulate locally and then hit the network in a burst.
                        if self.bwlimit.is_none() {
                            batch.extend(self.sched.take_small(
                                self.opts.block,
                                target - batch.len(),
                                FAST_BATCH_BYTES,
                            ));
                        }
                        let (fast, slow): (Vec<usize>, Vec<usize>) =
                            batch.into_iter().partition(|&i| self.fast_eligible(i));
                        self.sched.mark_fast(fast.len() - 1);
                        let fast_result = self.fast_batch(&fast);
                        self.sched.complete_fast_batch(fast.len());
                        if let Err(e) = fast_result {
                            if self.transport_dead() {
                                for &i in &slow {
                                    self.sched.ranges_ready(i, vec![]);
                                }
                                for &i in fast.iter().chain(&slow) {
                                    self.sched.requeue(i);
                                }
                                return Err(e);
                            }
                            let message = format!("{e:#}");
                            for &i in &fast {
                                self.file_error(i, anyhow::anyhow!(message.clone()))?;
                            }
                        }
                        for (position, &i) in slow.iter().enumerate() {
                            if let Err(e) = self.handle_file(i) {
                                if self.transport_dead() {
                                    for &pending in &slow[position + 1..] {
                                        self.sched.ranges_ready(pending, vec![]);
                                        self.sched.requeue(pending);
                                    }
                                }
                                self.file_error(i, e)?;
                            }
                        }
                    } else {
                        let res = if self.opts.verify_only {
                            self.verify_file(idx)
                        } else {
                            self.handle_file(idx)
                        };
                        if let Err(e) = res {
                            self.file_error(idx, e)?;
                        }
                    }
                }
                Item::Range(h) => {
                    let (idx, start) = {
                        let range = h.lock().unwrap();
                        (range.idx, range.pos)
                    };
                    let mut credited = 0;
                    let res = self.transfer_range(&h, &mut credited);
                    if let Err(e) = res {
                        if self.transport_dead() {
                            self.undo_progress(idx, credited);
                            self.sched.retry_range(&h, start);
                            return Err(e);
                        }
                        self.sched.range_done(&h);
                        self.file_error(idx, e)?;
                        continue;
                    }
                    let done = self.sched.range_done(&h);
                    if done {
                        if let Err(e) = self.finish_file(idx) {
                            if self.transport_dead() {
                                self.sched.requeue_finish(idx, false);
                            }
                            self.file_error(idx, e)?;
                        }
                    }
                }
                Item::Finish { idx, matched } => {
                    let result = if matched {
                        self.finish_matched_file(idx)
                    } else {
                        self.finish_file(idx)
                    };
                    if let Err(e) = result {
                        if self.transport_dead() {
                            self.sched.requeue_finish(idx, matched);
                        }
                        self.file_error(idx, e)?;
                    }
                }
            }
            self.progress.set_worker(self.id, None);
        }
    }

    /// Small new files are sent without a per-file round trip: one pipelined
    /// burst of reads and one of atomic sidecar writes — a few RTTs for the
    /// whole batch.
    fn fast_eligible(&self, idx: usize) -> bool {
        let jobs = self.sched.jobs.lock().unwrap();
        let j = &jobs[idx];
        !self.opts.verify_only
            && !self.opts.inplace
            && j.entry.size <= self.transfer_block()
            && j.dst_entry.is_none()
    }

    fn fast_batch(&mut self, batch: &[usize]) -> Result<()> {
        self.fast.batches += 1;
        self.fast.files += batch.len();
        let jobs: Vec<FileJob> = {
            let all = self.sched.jobs.lock().unwrap();
            batch.iter().map(|&i| all[i].clone()).collect()
        };
        if let Some(j) = jobs.last() {
            self.progress.set_worker(
                self.id,
                Some(WorkerStatus {
                    path: format!("{} (+{} small files)", j.rel, jobs.len() - 1),
                    done: j.done.clone(),
                    total: j.entry.size,
                }),
            );
        }
        // Reads.
        let phase = std::time::Instant::now();
        for j in &jobs {
            if j.entry.size > 0 {
                self.limit(j.entry.size);
            }
        }
        // Empty files need no source access. Besides saving wire work, this
        // preserves the valid archive-copy case where an empty source is 000.
        let reads: Vec<SmallRead> = jobs
            .iter()
            .filter(|job| job.entry.size > 0)
            .map(|job| SmallRead {
                path: job.src.clone(),
                attempt: job.attempts,
                len: job.entry.size as u32,
            })
            .collect();
        let blocks = if reads.is_empty() {
            Vec::new()
        } else {
            let count = reads.len();
            self.src.send(Request::ReadSmallBatch(reads))?;
            match ok(self.src.recv()?, "read small batch")? {
                Response::SmallBlocks(blocks) if blocks.len() == count => blocks,
                other => bail!("unexpected response {other:?}"),
            }
        };
        let mut blocks = blocks.into_iter();
        let mut data: Vec<Result<Vec<u8>>> = jobs
            .iter()
            .map(|job| {
                if job.entry.size == 0 {
                    return Ok(Vec::new());
                }
                match blocks.next() {
                    Some(Ok(SmallBlock { data, hash }))
                        if data.len() as u64 == job.entry.size && xxh3_64(&data) == hash =>
                    {
                        Ok(data)
                    }
                    Some(Ok(_)) => Err(anyhow::anyhow!("block size or hash mismatch on read")),
                    Some(Err(error)) => Err(anyhow::anyhow!("read: {error}")),
                    None => Err(anyhow::anyhow!("missing block in read small batch")),
                }
            })
            .collect();
        self.fast.source += phase.elapsed().as_secs_f64();
        // One batch request: the server still publishes every file through its
        // own sidecar, but framing, compression and encryption are amortized.
        let phase = std::time::Instant::now();
        let flags = self.opts.flags | flags::MODE; // set the computed mode explicitly
        let mut sent: Vec<bool> = Vec::with_capacity(jobs.len());
        let mut puts = Vec::with_capacity(jobs.len());
        for (j, d) in jobs.iter().zip(data.iter_mut()) {
            let Ok(bytes) = d else {
                sent.push(false);
                continue;
            };
            let bytes = std::mem::take(bytes);
            let hash = xxh3_64(&bytes);
            let mut meta = j.entry.meta();
            meta.mode = self.create_mode(j);
            puts.push(SmallPut {
                path: j.dst.clone(),
                partial_id: self.partial_id(),
                data: bytes,
                hash,
                meta,
                flags,
            });
            sent.push(true);
        }
        if !puts.is_empty() {
            self.dst.send(Request::PutSmallBatch(puts))?;
        }
        self.fast.dest_send += phase.elapsed().as_secs_f64();
        let phase = std::time::Instant::now();
        let mut applied = if sent.iter().any(|sent| *sent) {
            match ok(self.dst.recv()?, "put small batch")? {
                Response::Applied(results)
                    if results.len() == sent.iter().filter(|sent| **sent).count() =>
                {
                    results.into_iter()
                }
                other => bail!("unexpected response {other:?}"),
            }
        } else {
            Vec::new().into_iter()
        };
        let mut results: Vec<Result<()>> = Vec::with_capacity(jobs.len());
        for (d, &was_sent) in data.iter_mut().zip(sent.iter()) {
            let res: Result<()> = if !was_sent {
                match d {
                    Ok(_) => Ok(()),
                    Err(e) => Err(anyhow::anyhow!("{e:#}")),
                }
            } else {
                match applied.next().flatten() {
                    None => Ok(()),
                    Some(error) => Err(anyhow::anyhow!("put: {error}")),
                }
            };
            results.push(res);
        }
        self.fast.dest_ack += phase.elapsed().as_secs_f64();
        // Did any source change while we were at it?
        let paths: Vec<PathBytes> = jobs.iter().map(|j| j.src.clone()).collect();
        let phase = std::time::Instant::now();
        let now = stat_many(&mut *self.src, paths, false)?;
        self.fast.restat += phase.elapsed().as_secs_f64();
        let phase = std::time::Instant::now();
        for ((idx, j), (res, now)) in batch
            .iter()
            .zip(jobs.iter())
            .zip(results.into_iter().zip(now.into_iter()))
        {
            if let Err(e) = res {
                self.progress.error(&format!("syq: {}: {e:#}", j.rel));
                self.sched.fail_file(*idx);
                continue;
            }
            let changed = match &now {
                Some(e) => {
                    e.kind != Kind::File
                        || e.size != j.entry.size
                        || e.mtime != j.entry.mtime
                        || e.mtime_nsec != j.entry.mtime_nsec
                }
                None => true,
            };
            if changed {
                if let (Some(e), true) = (now, j.attempts + 1 < MAX_ATTEMPTS) {
                    if !self.opts.quiet {
                        self.progress.eprintln(&format!(
                            "syq: {}: changed during transfer, retrying",
                            j.rel
                        ));
                    }
                    let published = self.published_entry(j);
                    let mut all = self.sched.jobs.lock().unwrap();
                    let job = &mut all[*idx];
                    self.progress.bytes_total.fetch_add(e.size, Relaxed);
                    job.entry = Entry {
                        path: job.entry.path.clone(),
                        ..e
                    };
                    job.attempts += 1;
                    job.dst_entry = Some(published);
                    drop(all);
                    self.sched.requeue(*idx);
                } else {
                    self.progress.error(&format!(
                        "syq: {}: source changed during transfer (or vanished)",
                        j.rel
                    ));
                    self.sched.fail_file(*idx);
                }
                continue;
            }
            self.progress.add_bytes(j.entry.size);
            j.done.store(j.entry.size, Relaxed);
            self.progress.files_done.fetch_add(1, Relaxed);
            self.record_done(&j.rel_bytes, &j.entry);
            if self.opts.verbose > 0 {
                self.progress.println(&j.rel);
            }
        }
        self.fast.bookkeeping += phase.elapsed().as_secs_f64();
        Ok(())
    }

    fn file_error(&mut self, idx: usize, e: anyhow::Error) -> Result<()> {
        if self.src.is_dead() || self.dst.is_dead() {
            return Err(e);
        }
        if !self.sched.is_failed(idx) {
            let rel = self.sched.jobs.lock().unwrap()[idx].rel.clone();
            self.progress.error(&format!("syq: {rel}: {e:#}"));
            self.sched.fail_file(idx);
        }
        Ok(())
    }

    fn job(&self, idx: usize) -> FileJob {
        self.sched.jobs.lock().unwrap()[idx].clone()
    }

    fn handle_file(&mut self, idx: usize) -> Result<()> {
        let job = self.job(idx);
        let size = job.entry.size;
        let opts = self.opts.clone();
        let _ = &opts;
        self.progress.set_worker(
            self.id,
            Some(WorkerStatus {
                path: job.rel.clone(),
                done: job.done.clone(),
                total: size,
            }),
        );

        let inplace = self.opts.inplace;
        // The planner already statted the final path. Only the deterministic
        // sidecar needs another lookup before choosing the transfer basis.
        // --inplace never uses that sidecar, so it avoids the lookup entirely.
        let partial_size = if inplace {
            None
        } else {
            let probed: Result<Option<u64>> = (|| match ok(
                self.dst.call(Request::ProbePartial {
                    path: job.dst.clone(),
                    partial_id: self.partial_id(),
                })?,
                "probe partial",
            )? {
                Response::PartialSize(size) => Ok(size),
                other => bail!("unexpected response {other:?}"),
            })();
            match probed {
                Ok(size) => size,
                Err(error) => {
                    self.sched.ranges_ready(idx, vec![]);
                    if self.transport_dead() {
                        self.sched.requeue(idx);
                    }
                    return Err(error);
                }
            }
        };
        // Same-machine copy: let the kernel move the bytes (reflink / NFS
        // server-side copy) instead of streaming them through userspace.
        // copy_file_range cannot be paced, so a limited same-machine transfer
        // uses the regular userspace path (also useful for mounted NFS paths).
        if self.opts.same_host
            && !self.opts.checksum
            && self.bwlimit.is_none()
            && job.entry.size > 0
            && partial_size.is_none()
        {
            match self.try_copy_local(idx, &job) {
                Ok(true) => {
                    self.sched.ranges_ready(idx, vec![]);
                    return Ok(());
                }
                Ok(false) => {} // not offloadable — fall through to streaming
                Err(e) => {
                    self.sched.ranges_ready(idx, vec![]);
                    if self.transport_dead() {
                        // try_copy_local queues publication recovery after it
                        // has credited the completed kernel copy. Earlier
                        // connection failures still need the whole probe.
                        if job.done.load(Relaxed) < job.entry.size {
                            self.sched.requeue(idx);
                        }
                    }
                    return Err(e);
                }
            }
        }
        // bool = a staged or in-place file still needs Finalize. A verified
        // content match applies metadata through its retained basis fd instead.
        let planned: Result<(Vec<(u64, u64)>, bool)> = (|| {
            let final_entry = job.dst_entry.clone();
            if let Some(f) = &final_entry {
                if f.kind == Kind::Dir {
                    bail!("destination is a directory");
                }
            }
            let final_is_file = final_entry.as_ref().is_some_and(|f| f.kind == Kind::File);
            let full = || if size > 0 { vec![(0, size)] } else { vec![] };
            // Unless --inplace was explicit, changed files are published
            // through a sidecar + atomic rename. Small new files normally take
            // the batched small-file path instead of reaching this worker path.
            self.set_inplace(idx, inplace);

            if inplace {
                ok(
                    self.dst.call(Request::Prepare {
                        path: job.dst.clone(),
                        size,
                        inplace: true,
                        partial_id: self.partial_id(),
                        mode: self.create_mode(&job),
                    })?,
                    "prepare",
                )?;
                if final_is_file && size > 0 {
                    return Ok((self.diff_blocks(&job, Which::Final)?, true));
                }
                return Ok((full(), true));
            }
            if partial_size.is_some() {
                ok(
                    self.dst.call(Request::Prepare {
                        path: job.dst.clone(),
                        size,
                        inplace: false,
                        partial_id: self.partial_id(),
                        mode: self.create_mode(&job),
                    })?,
                    "prepare",
                )?;
                if size == 0 {
                    return Ok((vec![], true));
                }
                return Ok((self.diff_blocks(&job, Which::Partial)?, true));
            }
            if final_is_file {
                let (ranges, basis_len) = self.diff_final_and_hold(&job)?;
                if ranges.is_empty() && basis_len == size {
                    let mut meta = job.entry.meta();
                    meta.mode = self.create_mode(&job);
                    ok(
                        self.dst.call(Request::FinishBasis {
                            path: job.dst.clone(),
                            partial_id: self.partial_id(),
                            meta,
                            flags: self.opts.flags | flags::MODE,
                        })?,
                        "finish content-identical destination",
                    )?;
                    return Ok((vec![], false));
                }
                ok(
                    self.dst.call(Request::SeedBasis {
                        path: job.dst.clone(),
                        partial_id: self.partial_id(),
                        len: size,
                    })?,
                    "seed partial from destination basis",
                )?;
                return Ok((ranges, true));
            }
            ok(
                self.dst.call(Request::Prepare {
                    path: job.dst.clone(),
                    size,
                    inplace: false,
                    partial_id: self.partial_id(),
                    mode: self.create_mode(&job),
                })?,
                "prepare",
            )?;
            Ok((full(), true))
        })();

        let (ranges, needs_finalize) = match planned {
            Ok(result) => result,
            Err(e) => {
                self.sched.ranges_ready(idx, vec![]);
                if self.transport_dead() {
                    self.sched.requeue(idx);
                }
                return Err(e);
            }
        };
        let to_send: u64 = ranges.iter().map(|(o, e)| e - o).sum();
        job.done.store(size - to_send, Relaxed);
        self.progress
            .bytes_skipped
            .fetch_add(size - to_send, Relaxed);
        self.progress.bytes_total.fetch_sub(size - to_send, Relaxed);
        match self.sched.ranges_ready(idx, ranges) {
            Some(h) => {
                let start = h.lock().unwrap().pos;
                let mut credited = 0;
                let res = self.transfer_range(&h, &mut credited);
                if let Err(e) = res {
                    if self.transport_dead() {
                        self.undo_progress(idx, credited);
                        self.sched.retry_range(&h, start);
                        return Err(e);
                    }
                    self.sched.range_done(&h);
                    return Err(e);
                }
                if self.sched.range_done(&h) {
                    if let Err(e) = self.finish_file(idx) {
                        if self.transport_dead() {
                            self.sched.requeue_finish(idx, false);
                        }
                        return Err(e);
                    }
                }
            }
            None if needs_finalize => {
                if let Err(e) = self.finish_file(idx) {
                    if self.transport_dead() {
                        self.sched.requeue_finish(idx, false);
                    }
                    return Err(e);
                }
            }
            None => {
                if let Err(e) = self.finish_matched_file(idx) {
                    if self.transport_dead() {
                        self.sched.requeue_finish(idx, true);
                    }
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    /// Record the in-place decision on the job so every range worker and the
    /// finalize agree.
    fn set_inplace(&self, idx: usize, v: bool) {
        self.sched.jobs.lock().unwrap()[idx].inplace = v;
    }

    /// Attempt an in-kernel same-host copy. Ok(true) = done; Ok(false) =
    /// kernel can't offload, caller should stream; Err = real failure.
    /// The caller owns scheduler probing bookkeeping for every terminal result.
    fn try_copy_local(&mut self, idx: usize, job: &FileJob) -> Result<bool> {
        // Write to a partial and let finish_file rename it, so an interrupted
        // copy_file_range never leaves a final-named file the quick check could
        // mistake for complete. Only --inplace writes the final path directly.
        let inplace = self.opts.inplace;
        self.set_inplace(idx, inplace);
        let mode = self.create_mode(job);
        let resp = self.dst.call(Request::CopyLocal {
            src: job.src.clone(),
            dst: job.dst.clone(),
            inplace,
            partial_id: self.partial_id(),
            size: job.entry.size,
            mode,
        })?;
        match resp {
            Response::Ok => {
                self.progress.set_worker(
                    self.id,
                    Some(WorkerStatus {
                        path: job.rel.clone(),
                        done: job.done.clone(),
                        total: job.entry.size,
                    }),
                );
                self.progress.add_bytes(job.entry.size);
                job.done.store(job.entry.size, Relaxed);
                if let Err(e) = self.finish_file(idx) {
                    if self.transport_dead() {
                        self.sched.requeue_finish(idx, false);
                    }
                    return Err(e);
                }
                Ok(true)
            }
            Response::Err(e) if e.contains("EXDEV") => Ok(false),
            Response::Err(e) => bail!("{e}"),
            other => bail!("unexpected response {other:?}"),
        }
    }

    /// Mode a new destination file is created with (what finalize will want).
    /// The mode the finished file should have (rsync semantics):
    /// with -p the source mode; without -p an existing file keeps its own mode
    /// and a new file gets the source mode minus the umask.
    fn create_mode(&self, job: &FileJob) -> u32 {
        if self.opts.perms {
            job.entry.mode & 0o7777
        } else if let Some(d) = job.dst_entry.as_ref().filter(|d| d.kind == Kind::File) {
            d.mode & 0o7777
        } else {
            job.entry.mode & 0o777 & !self.opts.umask
        }
    }

    fn partial_id(&self) -> PartialId {
        *self
            .opts
            .partial_id
            .get()
            .expect("partial identity initialized before planning")
    }

    /// Metadata for the whole file just atomically published at the
    /// destination. A retry can use it as a block-diff basis without changing
    /// the no-`-p` mode chosen for the first attempt.
    fn published_entry(&self, job: &FileJob) -> Entry {
        let mut entry = job.entry.clone();
        entry.path = job.dst.clone();
        entry.mode = (entry.mode & !0o7777) | self.create_mode(job);
        entry
    }

    /// Hash blocks on both sides (in parallel) and return the ranges that differ.
    fn diff_blocks(&mut self, job: &FileJob, which: Which) -> Result<Vec<(u64, u64)>> {
        self.diff_with(
            job,
            Request::HashBlocks {
                path: job.dst.clone(),
                which,
                partial_id: self.partial_id(),
                block: self.opts.block,
                len: job.entry.size,
            },
            "hash destination",
        )
        .map(|diff| diff.ranges)
    }

    /// Compare the source with one opened final-file inode retained by the
    /// receiver for either metadata-only completion or sidecar seeding.
    fn diff_final_and_hold(&mut self, job: &FileJob) -> Result<(Vec<(u64, u64)>, u64)> {
        let diff = self.diff_with(
            job,
            Request::HashAndHold {
                path: job.dst.clone(),
                partial_id: self.partial_id(),
                block: self.opts.block,
                len: job.entry.size,
            },
            "hash and retain destination basis",
        )?;
        Ok((
            diff.ranges,
            diff.held_len
                .context("destination did not report its retained basis length")?,
        ))
    }

    fn diff_with(
        &mut self,
        job: &FileJob,
        destination_request: Request,
        destination_label: &str,
    ) -> Result<BlockDiff> {
        let block = self.opts.block;
        let size = job.entry.size;
        self.src.send(Request::HashBlocks {
            path: job.src.clone(),
            which: Which::Final,
            partial_id: self.partial_id(),
            block,
            len: size,
        })?;
        self.dst.send(destination_request)?;
        // Both requests are in flight. Always consume both responses before
        // interpreting either one so an ordinary endpoint error cannot leave
        // this reusable worker connection one response behind.
        let source_response = self.src.recv();
        let destination_response = self.dst.recv();
        let source = Self::hashes(ok(source_response?, "hash source")?)?;
        let (destination, held_len) =
            Self::destination_hashes(ok(destination_response?, destination_label)?)?;
        Ok(BlockDiff {
            ranges: Self::different_ranges(&source, &destination, block, size),
            held_len,
        })
    }

    fn hashes(response: Response) -> Result<Vec<u64>> {
        match response {
            Response::Hashes(hashes) => Ok(hashes),
            other => bail!("unexpected response {other:?}"),
        }
    }

    fn destination_hashes(response: Response) -> Result<(Vec<u64>, Option<u64>)> {
        match response {
            Response::Hashes(hashes) => Ok((hashes, None)),
            Response::HeldHashes { hashes, len } => Ok((hashes, Some(len))),
            other => bail!("unexpected response {other:?}"),
        }
    }

    fn different_ranges(
        source: &[u64],
        destination: &[u64],
        block: u64,
        size: u64,
    ) -> Vec<(u64, u64)> {
        let n = size.div_ceil(block) as usize;
        let mut ranges: Vec<(u64, u64)> = Vec::new();
        for i in 0..n {
            let same = source.get(i).is_some() && source.get(i) == destination.get(i);
            if same {
                continue;
            }
            let off = i as u64 * block;
            let end = (off + block).min(size);
            match ranges.last_mut() {
                Some(last) if last.1 == off => last.1 = end,
                _ => ranges.push((off, end)),
            }
        }
        ranges
    }

    fn transfer_range(&mut self, h: &RangeHandle, credited: &mut u64) -> Result<()> {
        let idx = {
            let g = h.lock().unwrap();
            g.idx
        };
        let job = self.job(idx);
        if self.sched.is_failed(idx) {
            return Ok(());
        }
        self.progress.set_worker(
            self.id,
            Some(WorkerStatus {
                path: job.rel.clone(),
                done: job.done.clone(),
                total: job.entry.size,
            }),
        );
        let block = self.transfer_block();
        let inplace = job.inplace;
        let mut reads_out = 0usize;
        let mut writes_out = 0usize;
        loop {
            if !self.gate.allowed(self.id) {
                // Being parked: give the rest of this range back so an active
                // worker picks it up; what's already requested still completes.
                self.sched.release_rest(h);
            }
            while reads_out < WINDOW {
                let (off, n) = {
                    let mut g = h.lock().unwrap();
                    if g.pos >= g.end {
                        break;
                    }
                    let n = (g.end - g.pos).min(block);
                    let off = g.pos;
                    g.pos += n;
                    (off, n)
                };
                self.limit(n);
                self.src.send(Request::ReadRange {
                    path: job.src.clone(),
                    attempt: job.attempts,
                    off,
                    len: n as u32,
                })?;
                reads_out += 1;
            }
            if reads_out == 0 {
                break;
            }
            let t0 = std::time::Instant::now();
            let (off, hash, data) = match ok(self.src.recv()?, "read")? {
                Response::Block { off, hash, data } => (off, hash, data),
                other => bail!("unexpected response {other:?}"),
            };
            self.t[0] += t0.elapsed().as_secs_f64();
            reads_out -= 1;
            if xxh3_64(&data) != hash {
                bail!("block hash mismatch on read @{off}");
            }
            let n = data.len() as u64;
            let t0 = std::time::Instant::now();
            self.dst.send(Request::WriteRange {
                path: job.dst.clone(),
                inplace,
                partial_id: self.partial_id(),
                attempt: job.attempts,
                off,
                hash,
                data,
            })?;
            self.t[1] += t0.elapsed().as_secs_f64();
            writes_out += 1;
            if writes_out >= WINDOW {
                let t0 = std::time::Instant::now();
                ok(self.dst.recv()?, "write")?;
                self.t[2] += t0.elapsed().as_secs_f64();
                writes_out -= 1;
            }
            self.progress.add_bytes(n);
            job.done.fetch_add(n, Relaxed);
            *credited += n;
        }
        while writes_out > 0 {
            ok(self.dst.recv()?, "write")?;
            writes_out -= 1;
        }
        Ok(())
    }

    fn undo_progress(&self, idx: usize, credited: u64) {
        if credited == 0 {
            return;
        }
        self.progress.bytes_done.fetch_sub(credited, Relaxed);
        self.sched.jobs.lock().unwrap()[idx]
            .done
            .fetch_sub(credited, Relaxed);
    }

    fn transfer_block(&self) -> u64 {
        self.bwlimit.as_ref().map_or(self.opts.block, |limit| {
            self.opts.block.min(limit.burst_bytes())
        })
    }

    fn limit(&self, bytes: u64) {
        if let Some(limit) = &self.bwlimit {
            limit.wait(bytes);
        }
    }

    /// Record a completed file in the explicit checkpoint, if active.
    fn record_done(&self, rel_bytes: &[u8], entry: &Entry) {
        if let Some(shared) = self.checkpoint.get() {
            if let Some(checkpoint) = &shared.checkpoint {
                checkpoint.record_complete(rel_bytes, entry, "transferred");
            }
        }
    }

    fn finish_file(&mut self, idx: usize) -> Result<()> {
        if self.sched.is_failed(idx) {
            return Ok(());
        }
        let job = self.job(idx);
        let mut meta = job.entry.meta();
        meta.mode = self.create_mode(&job);
        let flags = self.opts.flags | flags::MODE; // set the computed mode explicitly
        let finalized = ok(
            self.dst.call(Request::Finalize {
                path: job.dst.clone(),
                inplace: job.inplace,
                partial_id: self.partial_id(),
                meta,
                flags,
            })?,
            "finalize destination",
        );
        if let Err(error) = finalized {
            if self.transport_dead() || job.inplace {
                return Err(error);
            }
            // If the response to a previous Finalize was lost, its sidecar is
            // gone because publication already happened. Verify the final
            // bytes before treating the retry as successful; if a sidecar is
            // still present, preserve the real metadata/publication error.
            let partial_missing = match ok(
                self.dst.call(Request::ProbePartial {
                    path: job.dst.clone(),
                    partial_id: self.partial_id(),
                })?,
                "probe partial after finalize",
            )? {
                Response::PartialSize(size) => size.is_none(),
                other => bail!("unexpected response {other:?}"),
            };
            if !partial_missing || !self.contents_match(&job)? {
                return Err(error);
            }
        }
        #[cfg(debug_assertions)]
        if let Some(ms) = std::env::var_os("SYQ_TEST_HOLD_AFTER_FINALIZE_MS") {
            if let Ok(ms) = ms.to_string_lossy().parse::<u64>() {
                std::thread::sleep(std::time::Duration::from_millis(ms));
            }
        }
        self.complete_file(idx, job, false)
    }

    fn contents_match(&mut self, job: &FileJob) -> Result<bool> {
        self.src.send(Request::FileHash {
            path: job.src.clone(),
        })?;
        self.dst.send(Request::FileHash {
            path: job.dst.clone(),
        })?;
        let source = self.src.recv();
        let destination = self.dst.recv();
        let source = ok(source?, "hash source after finalize")?;
        let destination = ok(destination?, "hash destination after finalize")?;
        match (source, destination) {
            (
                Response::FileHash {
                    size: source_size,
                    hash: source_hash,
                },
                Response::FileHash {
                    size: destination_size,
                    hash: destination_hash,
                },
            ) => Ok(source_size == destination_size && source_hash == destination_hash),
            (source, destination) => {
                bail!("unexpected responses {source:?} {destination:?}")
            }
        }
    }

    fn finish_matched_file(&mut self, idx: usize) -> Result<()> {
        if self.sched.is_failed(idx) {
            return Ok(());
        }
        self.complete_file(idx, self.job(idx), true)
    }

    /// Recheck the source after either an atomic publication or a verified
    /// metadata-only completion, and retry from the completed destination when
    /// the source changed during that work.
    fn complete_file(&mut self, idx: usize, job: FileJob, matched: bool) -> Result<()> {
        // Did the source change under us?
        let now = stat_one(&mut *self.src, &job.src, false)?;
        let changed = match &now {
            Some(e) => {
                e.kind != Kind::File
                    || e.size != job.entry.size
                    || e.mtime != job.entry.mtime
                    || e.mtime_nsec != job.entry.mtime_nsec
            }
            None => true,
        };
        if changed {
            if job.attempts + 1 < MAX_ATTEMPTS {
                if let Some(e) = now {
                    if !self.opts.quiet {
                        self.progress.eprintln(&format!(
                            "syq: {}: changed during transfer, retrying",
                            job.rel
                        ));
                    }
                    let published = self.published_entry(&job);
                    let mut jobs = self.sched.jobs.lock().unwrap();
                    let j = &mut jobs[idx];
                    self.progress.bytes_total.fetch_add(e.size, Relaxed);
                    j.entry = Entry {
                        path: j.entry.path.clone(),
                        ..e
                    };
                    j.attempts += 1;
                    j.dst_entry = Some(published);
                    j.done.store(0, Relaxed);
                    drop(jobs);
                    self.sched.requeue(idx);
                    return Ok(());
                }
            }
            bail!("source changed during transfer (or vanished)");
        }
        if matched {
            self.progress.files_total.fetch_sub(1, Relaxed);
            self.progress.files_skipped.fetch_add(1, Relaxed);
        } else {
            self.progress.files_done.fetch_add(1, Relaxed);
        }
        self.record_done(&job.rel_bytes, &job.entry);
        if !matched && self.opts.verbose > 0 {
            self.progress.println(&job.rel);
        }
        Ok(())
    }

    fn verify_file(&mut self, idx: usize) -> Result<()> {
        let job = self.job(idx);
        self.progress.set_worker(
            self.id,
            Some(WorkerStatus {
                path: job.rel.clone(),
                done: job.done.clone(),
                total: job.entry.size,
            }),
        );
        let r = (|| -> Result<bool> {
            self.src.send(Request::FileHash {
                path: job.src.clone(),
            })?;
            self.dst.send(Request::FileHash {
                path: job.dst.clone(),
            })?;
            // Keep both reusable connections aligned even if one endpoint
            // reports an ordinary per-file error.
            let source_response = self.src.recv();
            let destination_response = self.dst.recv();
            let a = ok(source_response?, "hash source")?;
            let b = ok(destination_response?, "hash destination")?;
            match (a, b) {
                (
                    Response::FileHash { size: s1, hash: h1 },
                    Response::FileHash { size: s2, hash: h2 },
                ) => Ok(s1 == s2 && h1 == h2),
                (a, b) => bail!("unexpected responses {a:?} {b:?}"),
            }
        })();
        self.sched.ranges_ready(idx, vec![]);
        match r {
            Ok(true) => {
                self.progress.add_bytes(job.entry.size);
                job.done.store(job.entry.size, Relaxed);
                self.progress.files_done.fetch_add(1, Relaxed);
                if self.opts.verbose > 0 {
                    self.progress.println(&format!("ok      {}", job.rel));
                }
            }
            Ok(false) => {
                self.progress.add_bytes(job.entry.size);
                job.done.store(job.entry.size, Relaxed);
                self.progress.error(&format!("DIFFERS {}", job.rel));
                self.sched.fail_file(idx);
            }
            Err(e) => {
                if self.transport_dead() {
                    self.sched.requeue(idx);
                }
                return Err(e);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fast_batch_ceiling_only_grows_on_high_rtt_tcp() {
        assert_eq!(fast_batch_file_limit(None, None), FAST_BATCH_FILES);
        assert_eq!(fast_batch_file_limit(Some(99_999), None), FAST_BATCH_FILES);
        assert_eq!(
            fast_batch_file_limit(None, Some(HIGH_RTT_US)),
            HIGH_RTT_FAST_BATCH_FILES
        );
        assert_eq!(
            fast_batch_file_limit(Some(262_000), Some(1_000)),
            HIGH_RTT_FAST_BATCH_FILES
        );
    }

    #[test]
    fn clean_root_pins_the_edge_cases() {
        for (given, want) in [
            ("/", "/"),
            ("//", "/"),
            ("/.", "/"),
            (".", "."),
            ("./", "."),
            ("././//", "."),
            ("dst", "dst"),
            ("dst/", "dst"),
            ("dst/.", "dst"),
            ("dst//x", "dst/x"),
            ("./dst/./x/", "dst/x"),
            ("~/x//y/.", "~/x/y"),
            ("/a//b/./c", "/a/b/c"),
        ] {
            assert_eq!(
                clean_root(given.as_bytes()),
                want.as_bytes(),
                "clean_root({given:?})"
            );
        }
    }

    #[test]
    fn tcp_stats_distinguish_unavailable_fields_from_zero() {
        let output = format_tcp_stats(
            &[TcpPairStats {
                label: "host".into(),
                local: Some(TcpSocketStats {
                    bytes_sent: Some(100),
                    bytes_retransmitted: Some(0),
                    segments_sent: Some(10),
                    retransmissions: None,
                    rtt_us: Some(1_000),
                    min_rtt_us: None,
                    ecn_ce_delivered: None,
                    ..TcpSocketStats::default()
                }),
                peer: None,
            }],
            false,
        );
        assert!(output.contains("unavailable packets, 0 (0.000% of sent) bytes"));
        assert!(output.contains("current average 1.00 ms, minimum unavailable"));
        assert!(output.contains("receive unavailable, send-buffer unavailable"));
        assert!(output.contains("tcp ECN CE deliveries: unavailable"));
    }
}

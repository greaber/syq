//! The orchestrator: scan, diff, schedule, and the per-worker transfer loop.

use crate::bwlimit::BandwidthLimit;
use crate::cli::{parse_rsh, parse_size, Args, Location};
use crate::conn::{ok, Conn, Endpoint, RemoteSpec};
use crate::fsops::join;
use crate::progress::{commas, human, Progress, WorkerStatus};
use crate::proto::*;
use crate::sched::{FileJob, Item, RangeHandle, Sched};
use crate::tune::{self, Gate};
use anyhow::{bail, Result};
use std::os::unix::ffi::OsStrExt;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
use std::sync::Mutex;
use xxhash_rust::xxh3::xxh3_64;

const WINDOW: usize = 4;
const MAX_ATTEMPTS: u32 = 3;
pub const LOCAL_DEFAULT_CONNECTIONS: usize = 32;
const FAST_BATCH_FILES: usize = 64;
const FAST_BATCH_BYTES: u64 = 16 << 20;

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
    pub fsync: bool,
    pub same_host: bool,
    pub dry_run: bool,
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

/// The canonical form of a path (symlinks and `..` resolved the way the kernel
/// does), normalized by the endpoint that holds it. Used for the job identity —
/// so `host:dir`, `host:./dir` and `host:/home/u/dir` name one job — and for
/// the copy-into-itself check.
fn canonical_path(ctl: &mut dyn Conn, path: &str, remote: bool) -> Result<std::path::PathBuf> {
    if !remote {
        return Ok(crate::fsops::normalize(&crate::fsops::resolve(
            path.as_bytes(),
        )));
    }
    match ok(
        ctl.call(Request::Canonicalize {
            path: path.as_bytes().to_vec(),
        })?,
        "canonicalize",
    )? {
        Response::Path(p) => Ok(crate::fsops::resolve(&p)),
        other => bail!("unexpected response {other:?}"),
    }
}

/// Encode the content/metadata-affecting options into the job identity.
fn semantic_flags(opts: &Opts, args: &Args) -> String {
    serde_json::json!({
        "partial_format": 1,
        "recursive": opts.recursive,
        "links": opts.links,
        "perms": opts.flags & flags::MODE != 0,
        "times": opts.flags & flags::TIMES != 0,
        "group": opts.flags & flags::GROUP != 0,
        "owner": opts.flags & flags::OWNER != 0,
        "devices": opts.devices,
        "checksum": opts.checksum,
        "inplace": args.inplace,
        "block_size": opts.block,
        "ignore": opts.ignore,
    })
    .to_string()
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
    is_dir: bool,
}

fn copy_identity(
    args: &Args,
    srcs: &[Location],
    dst: &Location,
    src_ctl: &mut dyn Conn,
    dst_ctl: &mut dyn Conn,
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
    let dst_root = canonical_path(dst_ctl, &dst.path, dst.is_remote())?
        .to_string_lossy()
        .into_owned();
    Ok(crate::checkpoint::job_identity(
        &endpoint_identity(&srcs[0]),
        &src_roots,
        &endpoint_identity(dst),
        &dst_root,
        &semantic_flags(opts, args),
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
        let (checkpoint, loaded) = Checkpoint::open(path, identity, args.fsync)?;
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
        if dst.is_dir {
            for source in srcs.iter().filter(|source| !source.copies_contents()) {
                let basename = source.basename();
                if basename.is_empty() {
                    continue;
                }
                let prefix = basename.as_bytes();
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
    let locs: Vec<Location> = args
        .paths
        .iter()
        .map(|p| Location::parse(p))
        .collect::<Result<_>>()?;
    if locs.len() < 2 {
        bail!("need at least one source and a destination");
    }
    let (dst, srcs) = locs.split_last().unwrap();
    for s in srcs {
        if !s.same_host(&srcs[0]) {
            bail!("all sources must be on the same host");
        }
    }
    if let Some(checkpoint) = args.checkpoint.as_deref() {
        let checkpoint = crate::fsops::normalize(std::path::Path::new(checkpoint));
        for source in srcs.iter().filter(|source| !source.is_remote()) {
            let root = crate::fsops::normalize(&crate::fsops::resolve(source.path.as_bytes()));
            if checkpoint.starts_with(&root) {
                bail!(
                    "checkpoint {} must not be inside local source {}",
                    checkpoint.display(),
                    root.display()
                );
            }
        }
        if !dst.is_remote() {
            let root = crate::fsops::normalize(&crate::fsops::resolve(dst.path.as_bytes()));
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
                    bail!("two sources named {base:?} map to the same destination; rename one or copy them separately");
                }
            }
        }
    }
    let src_ep = endpoint(&srcs[0], &args)?;
    let dst_ep = endpoint(dst, &args)?;
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
            return crate::direct::run(&args, srcs, dst);
        }
        if !args.quiet {
            eprintln!("syq: remote-to-remote transfer: relaying data through this machine");
        }
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
        fsync: args.fsync,
        same_host: !src_ep.is_remote() && !dst_ep.is_remote(),
        dry_run: args.dry_run,
        verbose: args.verbose,
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
    if args.files_from.is_some() && srcs.len() > 1 {
        bail!("--files-from takes exactly one source directory");
    }

    let show_progress = !args.no_progress && !args.quiet && !args.dry_run;
    let progress = Progress::new(
        args.connections,
        show_progress,
        args.progress,
        args.width,
        args.progress_json,
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
    let spawn_worker: Arc<dyn Fn(usize) + Send + Sync> = {
        let (src_ep, dst_ep, sched, progress, opts, gate, workers, checkpoint_slot, bwlimit) = (
            src_ep.clone(),
            dst_ep.clone(),
            sched.clone(),
            progress.clone(),
            opts.clone(),
            gate.clone(),
            workers.clone(),
            checkpoint_slot.clone(),
            bwlimit.clone(),
        );
        let compress = args.compress;
        Arc::new(move |id: usize| {
            let (src_ep, dst_ep, sched, progress, opts, gate, checkpoint, bwlimit) = (
                src_ep.clone(),
                dst_ep.clone(),
                sched.clone(),
                progress.clone(),
                opts.clone(),
                gate.clone(),
                checkpoint_slot.clone(),
                bwlimit.clone(),
            );
            let h = std::thread::spawn(move || -> Result<()> {
                let t0 = std::time::Instant::now();
                let conns = src_ep
                    .connect(compress)
                    .and_then(|s| Ok((s, dst_ep.connect(compress)?)));
                // Counted whether or not it worked: the tuner waits for every
                // requested worker to arrive before judging, and a failed one
                // must not stall it.
                gate.connected.fetch_add(1, Relaxed);
                let (src, dst) = conns?;
                let mut w = Worker {
                    id,
                    src,
                    dst,
                    sched,
                    progress,
                    opts,
                    checkpoint,
                    bwlimit,
                    gate,
                    t: [0.0; 4],
                };
                if debug() {
                    eprintln!(
                        "syq: worker {id} connected in {:.2}s",
                        t0.elapsed().as_secs_f64()
                    );
                }
                w.run()
            });
            workers.lock().unwrap().push(h);
        })
    };
    let tuner: Mutex<Option<std::thread::JoinHandle<tune::Policy>>> = Mutex::new(None);
    let spawn_workers = |initial: usize| {
        for id in 0..initial {
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
                tune::run(policy, gate, sched, progress, |id| spawn_worker(id), n0)
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
                if let Err(e) = spec.setup_tcp(&mut **ctl, args.tcp_plain, ports) {
                    if !args.quiet || debug() {
                        eprintln!(
                            "syq: {}: data over ssh (TCP ports {}-{} not reachable: {e:#}); a Tailscale address or an open port is faster",
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
            Endpoint::Remote(spec) => spec.tcp.lock().unwrap().is_some(),
        });
    if autotune && all_remote_endpoints_use_tcp {
        args.connections = tune::START_TCP;
        gate.set_limit(args.connections);
    }
    if !opts.dry_run {
        spawn_workers(args.connections);
    }

    let dst_root = dst.path.as_bytes().to_vec();
    let dst_root_entry = stat_one(&mut *dst_ctl, &dst_root, false)?;
    // A destination that is a symlink to a directory is that directory (as
    // for rsync). Use the resolved target path for all planning and metadata,
    // so ordinary in-tree symlinks can still be replaced instead of followed.
    let (dst_root, dst_root_entry) = follow_dir_symlink(&mut *dst_ctl, &dst_root, dst_root_entry)?;
    let dst_existed = dst_root_entry.is_some();
    let dst_is_dir = match &dst_root_entry {
        Some(e) if e.kind == Kind::Dir => true,
        Some(_) if srcs.len() > 1 => {
            bail!("destination must be a directory when copying multiple sources")
        }
        Some(_) => false,
        None => srcs.len() > 1 || dst.copies_contents() || args.files_from.is_some(),
    };
    if args.files_from.is_some() {
        if let Some(e) = dst_root_entry.as_ref().filter(|e| e.kind != Kind::Dir) {
            bail!(
                "--files-from needs a directory destination; {} is a {:?}",
                display(&dst_root),
                e.kind
            );
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
            let src_is_dir = matches!(stat_one(&mut *src_ctl, s.path.as_bytes(), false)?, Some(ref e) if e.kind == Kind::Dir);
            if !src_is_dir {
                continue;
            }
            let sn = canonical_path(&mut *src_ctl, &s.path, remote)?;
            // Effective destination(s): the destination itself, plus
            // destination/basename only when the destination is really an
            // existing directory (so a bare source lands inside it).
            let mut effs = vec![canonical_path(&mut *src_ctl, &dst.path, remote)?];
            if dst_is_dir && !s.copies_contents() {
                let base = s.basename();
                if !base.is_empty() {
                    let joined = format!("{}/{}", dst.path.trim_end_matches('/'), base);
                    effs.push(canonical_path(&mut *src_ctl, &joined, remote)?);
                }
            }
            for eff in effs {
                if eff == sn {
                    bail!("source and destination are the same directory {:?}", s.path);
                } else if eff.starts_with(&sn) {
                    bail!(
                        "destination {:?} maps inside source {:?} — that would copy the directory into itself",
                        dst.path, s.path
                    );
                }
            }
        }
    }

    let identity = copy_identity(&args, srcs, dst, &mut *src_ctl, &mut *dst_ctl, &opts)?;
    opts.partial_id
        .set(crate::checkpoint::partial_id(&identity))
        .expect("partial identity set once");

    let checkpoint_state = checkpoint_setup(
        &args,
        srcs,
        DestinationRoot {
            path: &dst_root,
            existed: dst_existed,
            is_dir: dst_is_dir,
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
    if create_root && srcs.len() == 1 {
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
        dst_seen: std::collections::HashMap::new(),
        missing_dirs: std::collections::HashSet::new(),
        pruned: std::collections::HashSet::new(),
        collision: false,
        deferred: Vec::new(),
        dirs_created: 0,
        links_created: 0,
        specials_created: 0,
        scan_warned: false,
        max_delete_hit: false,
        buffer: if srcs.len() > 1 {
            Some(Vec::new())
        } else {
            None
        },
        create_root: if create_root && srcs.len() > 1 {
            Some(dst_root.clone())
        } else {
            None
        },
        keep_dirs: args.files_from.is_some(),
        delete_roots: Vec::new(),
        deletes: Deletes::default(),
    };

    let mut scan_err = None;
    if args.files_from.is_some() {
        let src = &srcs[0];
        if let Err(e) = st.scan_files_from(
            &mut *src_ctl,
            src.path.as_bytes(),
            &dst_root,
            &args.files_from_lines,
            args.recursive_explicit,
        ) {
            scan_err = Some(e);
        }
    }
    for src in srcs.iter().filter(|_| args.files_from.is_none()) {
        let src_root = src.path.as_bytes().to_vec();
        let follow = src.copies_contents();
        // A bare directory source goes to dest/basename even when dest doesn't
        // exist yet; a non-directory source only does so when dest is a directory
        // (decided once the root entry is seen).
        let sub = if follow {
            String::new()
        } else {
            src.basename()
        };
        if let Err(e) = st.scan_source(
            &mut *src_ctl,
            &src_root,
            follow,
            &sub,
            &dst_root,
            dst_is_dir,
        ) {
            scan_err = Some(e);
            break;
        }
    }
    if scan_err.is_none() && !st.collision {
        if let Err(e) = st.replay_buffered() {
            scan_err = Some(e);
        }
    }
    let collision = st.collision;
    progress.scan_done.store(true, Relaxed);
    sched.scan_done();
    if let Some(e) = &scan_err {
        progress.error(&format!("syq: {e:#}"));
        sched.abort();
    }
    if collision {
        sched.abort();
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
    let tuned = tuner.lock().unwrap().take().and_then(|t| t.join().ok());

    let aborted = sched.is_aborted();
    let mut deleted = 0u64;
    // --delete runs once the workers are done, so the destination walk sees a
    // quiescent tree (no partials being renamed, no entries being replaced),
    // and before apply_deferred, since unlinking bumps directory mtimes. Any
    // source-side scan problem disables deletion: a directory we couldn't
    // read would otherwise look like one whose contents vanished.
    if !aborted && opts.delete && scan_err.is_none() && !collision {
        if st.scan_warned {
            progress.eprintln("syq: source scan reported errors; skipping deletions");
        } else {
            match st.plan_deletes() {
                Ok(()) => deleted = st.run_deletes()?,
                Err(e) => progress.error(&format!("syq: delete: {e:#}")),
            }
        }
    }
    if !aborted && !opts.dry_run && !opts.verify_only {
        st.apply_deferred()?;
    }
    let max_delete_hit = st.max_delete_hit;
    drop(st);

    progress.stop();
    if let Some(t) = ticker {
        let _ = t.join();
    }
    progress.clear();

    let errors = progress.errors.load(Relaxed);

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
        if let Some(e) = failed {
            eprintln!(
                "syq: warning: checkpoint recording stopped ({e}); a retry will recheck files completed after that point"
            );
        }
    }
    let elapsed = progress.start.elapsed().as_secs_f64();
    let done = progress.bytes_done.load(Relaxed);
    if !args.quiet {
        if opts.verify_only {
            println!(
                "syq: verified {} files, {} differ/missing, {} in {}",
                commas(progress.files_done.load(Relaxed) + errors),
                errors,
                human(done),
                crate::progress::hms(elapsed)
            );
        } else {
            let verb = if opts.dry_run {
                "would transfer"
            } else {
                "transferred"
            };
            println!(
                "syq: {} {} files ({}), {} unchanged ({} files), {} dirs{}{}{}",
                verb,
                commas(progress.files_done.load(Relaxed)),
                human(if opts.dry_run {
                    progress.bytes_total.load(Relaxed)
                } else {
                    done
                }),
                human(progress.bytes_skipped.load(Relaxed)),
                commas(progress.files_skipped.load(Relaxed)),
                commas(st_dirs(&progress)),
                if opts.delete {
                    format!(
                        ", {} {}",
                        commas(deleted),
                        if opts.dry_run {
                            "would be deleted"
                        } else {
                            "deleted"
                        }
                    )
                } else {
                    String::new()
                },
                if opts.dry_run {
                    String::new()
                } else {
                    format!(
                        ", {} at {}/s",
                        crate::progress::hms(elapsed),
                        human((done as f64 / elapsed.max(0.001)) as u64)
                    )
                },
                if errors > 0 {
                    format!(", {errors} errors")
                } else {
                    String::new()
                }
            );
        }
        if args.stats {
            println!(
                "  scanned entries: {}\n  files to transfer: {}\n  files unchanged: {}\n  files excluded: {}\n  bytes transferred: {}\n  bytes unchanged: {}\n  elapsed: {:.2}s\n  connections: {}",
                commas(progress.scanned.load(Relaxed)),
                commas(progress.files_total.load(Relaxed)),
                commas(progress.files_skipped.load(Relaxed)),
                commas(progress.files_excluded.load(Relaxed)),
                commas(done),
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
                }
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

fn stat_one(conn: &mut dyn Conn, path: &[u8], follow: bool) -> Result<Option<Entry>> {
    Ok(stat_many(conn, vec![path.to_vec()], follow)?
        .pop()
        .flatten())
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
    let warned = std::cell::Cell::new(false);
    let res = src.scan(
        root,
        follow_root,
        ignore,
        false,
        &mut |batch| f(pl, batch),
        &mut |_| Ok(()),
        &mut |w| {
            // "skipping …" is a notice (nothing the copy owes is missing);
            // anything else from the scanner means an entry was lost.
            if w.starts_with("skipping ") {
                progress.eprintln(&format!("syq: {w}"));
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

/// What to checkpoint for a quick-check-identical file once metadata repair succeeds.
type QuickCheckRecord = (PathBytes, Entry);

struct Planner<'a> {
    dst: &'a mut dyn Conn,
    sched: &'a Sched,
    progress: &'a Progress,
    opts: &'a Opts,
    /// Destination paths claimed by source entries (see `Claim`).
    dst_seen: std::collections::HashMap<PathBytes, Claim>,
    /// --existing: destination directories that don't exist (or aren't
    /// directories); nothing under them is touched.
    missing_dirs: std::collections::HashSet<PathBytes>,
    /// Source directories that are never copied (sidecar-named); nothing
    /// under them is either.
    pruned: std::collections::HashSet<PathBytes>,
    completed:
        Option<std::sync::Arc<std::collections::HashMap<PathBytes, crate::checkpoint::Completed>>>,
    checkpoint: Option<std::sync::Arc<crate::checkpoint::Checkpoint>>,
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
    delete_roots: Vec<(PathBytes, String)>,
    deletes: Deletes,
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
    dirs: Vec<(PathBytes, Entry)>,
    others: Vec<Planned>,
}

/// What --delete found on the destination that the source doesn't have.
#[derive(Default)]
struct Deletes {
    /// (path, display name, destination-relative path) of files, symlinks and
    /// specials to unlink; the relative path is the journal's key.
    leaves: Vec<(PathBytes, String, PathBytes)>,
    /// Directories by depth, removed deepest-first once they are empty.
    dirs: std::collections::BTreeMap<usize, Vec<(PathBytes, String)>>,
}

impl Planner<'_> {
    fn scan_source(
        &mut self,
        src: &mut dyn Conn,
        src_root: &[u8],
        follow: bool,
        sub: &str,
        dst_root: &[u8],
        dst_is_dir: bool,
    ) -> Result<()> {
        let mut first = true;
        let mut sub = sub.to_string();
        let mut skip_all = false;
        let ignore = self.opts.ignore.clone();
        scan_into_planner(self, src, src_root, follow, &ignore, |pl, batch| {
            if skip_all {
                return Ok(());
            }
            if first {
                first = false;
                if let Some(root) = batch.first() {
                    if root.kind != Kind::Dir && !dst_is_dir {
                        sub = String::new();
                    }
                    if root.kind == Kind::Dir && !pl.opts.recursive {
                        pl.progress
                            .eprintln(&format!("skipping directory {}", display(src_root)));
                        skip_all = true;
                        return Ok(());
                    }
                    if root.kind == Kind::Dir {
                        pl.delete_roots
                            .push((join(dst_root, sub.as_bytes()), sub.clone()));
                    }
                }
            }
            pl.progress.scanned.fetch_add(batch.len() as u64, Relaxed);
            pl.handle_batch(batch, src_root, &sub, dst_root)
        })
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
        let root = match stat_one(src, src_root, true)? {
            Some(e) if e.kind == Kind::Dir => e,
            Some(_) => bail!(
                "--files-from: source {} is not a directory",
                display(src_root)
            ),
            None => bail!("--files-from: source {} does not exist", display(src_root)),
        };
        self.progress.scanned.fetch_add(1, Relaxed);
        self.handle_batch(vec![root], src_root, "", dst_root)?;

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
            for line in chunk {
                for anc in ancestors(line) {
                    if !parents.contains_key(&anc) && !want_parents.contains(&anc) {
                        want_parents.push(anc);
                    }
                }
                if !leaves.contains_key(line) && !want_leaves.contains(line) {
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
            self.handle_batch(batch, src_root, "", dst_root)?;
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
            pl.handle_batch(batch, src_root, "", dst_root)
        })
    }

    fn handle_batch(
        &mut self,
        batch: Vec<Entry>,
        src_root: &[u8],
        sub: &str,
        dst_root: &[u8],
    ) -> Result<()> {
        let mapped = self.map_batch(batch, src_root, sub, dst_root);
        match &mut self.buffer {
            Some(buf) => {
                buf.push(mapped);
                Ok(())
            }
            None => self.apply_mapped(mapped),
        }
    }

    /// The mapping loop: decide and claim everything about each entry.
    fn map_batch(
        &mut self,
        batch: Vec<Entry>,
        src_root: &[u8],
        sub: &str,
        dst_root: &[u8],
    ) -> Mapped {
        let opts = self.opts;
        let sub_b = sub.as_bytes();
        let mut dirs: Vec<(PathBytes, Entry)> = Vec::new();
        let mut others: Vec<Planned> = Vec::new();
        for e in batch {
            if e.kind == Kind::Dir && !opts.recursive && !self.keep_dirs {
                continue;
            }
            let dst_rel = join(sub_b, &e.path);
            let dst = join(dst_root, &dst_rel);
            let rel = self.rel_name(src_root, sub_b, &e.path);
            // Every source entry claims its destination here, before any
            // decision about it: that blocks two sources from mapping onto one
            // path, and it is what makes --delete safe — whatever happens
            // below (skip, filter, unsupported type, resumed from a journal),
            // a path the source has is never an extra.
            // Names reserved for sidecars are never payload, whatever kind of
            // entry carries them: a directory called `.x.syq-part.<id>` in the
            // destination would wedge every later transfer of `x` there.
            let partial_named = crate::fsops::is_partial_name(std::ffi::OsStr::from_bytes(
                e.path.rsplit(|&c| c == b'/').next().unwrap_or(&e.path),
            ));
            let claim = match e.kind {
                Kind::Dir if !partial_named => Claim::Dir,
                Kind::File if !partial_named => Claim::File {
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
                Claim::Dir => dirs.push((dst, e)),
                Claim::Weak if partial_named || e.kind == Kind::Other => {
                    // Never transferred: syq's own leftovers, unknown types.
                    if e.kind == Kind::Dir {
                        // ...and nothing below such a directory either.
                        self.pruned.insert(dst);
                    } else {
                        self.progress.files_excluded.fetch_add(1, Relaxed);
                    }
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
            let stats = self.stat_many(true, groups.keys().cloned().collect())?;
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
        } = mapped;
        let dst_root = &dst_root[..];

        // Directories: one stat pass decides everything about each one, and
        // the same filtered list drives creation, listing and deferred
        // metadata so they can't disagree.
        let need_stats = opts.verify_only || !opts.dry_run || opts.existing;
        if !dirs.is_empty() && (need_stats || opts.verbose > 0) {
            let stats: Vec<Option<Entry>> = if need_stats {
                self.stat_many(true, dirs.iter().map(|(p, _)| p.clone()).collect())?
            } else {
                vec![None; dirs.len()]
            };
            let mut planned: Vec<(PathBytes, Entry, Option<Entry>)> = Vec::new();
            for ((p, e), st) in dirs.into_iter().zip(stats) {
                if self.under_pruned(&p, dst_root) {
                    continue;
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
                if opts.existing && (!is_dir || self.under_missing_dir(&p, dst_root)) {
                    self.missing_dirs.insert(p);
                    continue;
                }
                planned.push((p, e, st));
            }
            if opts.dry_run {
                if opts.verbose > 0 {
                    for (p, _, _) in &planned {
                        self.progress.println(&format!("{}/", display(p)));
                    }
                }
            } else if !opts.verify_only {
                // Create new dirs; also "create" existing ones we can't yet
                // write into (0o700 not set) so apply() opens them up.
                let new_dirs: Vec<Op> = planned
                    .iter()
                    .filter(|(_, _, st)| {
                        !matches!(st, Some(d) if d.kind == Kind::Dir && d.mode & 0o700 == 0o700)
                    })
                    .map(|(p, e, _)| Op::Mkdir {
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
                    let errs = self.apply(true, new_dirs)?;
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
                for (p, e, s) in &planned {
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
                if p.e.kind == Kind::File {
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
        let stats = self.stat_many(true, others.iter().map(|p| p.dst.clone()).collect())?;
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
            if self.under_pruned(&dst_path, dst_root)
                || (opts.existing && self.under_missing_dir(&dst_path, dst_root))
            {
                // Below a directory we won't create: nothing to do, even if the
                // destination has something reachable there through a symlink.
                self.progress.files_excluded.fetch_add(1, Relaxed);
                continue;
            }
            match e.kind {
                Kind::File => {
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
                        self.progress.eprintln(&format!(
                            "skipping {rel}: source and destination are the same file"
                        ));
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
                                meta_fixes.push((
                                    Op::SetMeta {
                                        path: dst_path.clone(),
                                        meta: e.meta(),
                                        flags: ff,
                                    },
                                    self.checkpoint
                                        .as_ref()
                                        .map(|_| (dst_rel.clone(), e.clone())),
                                ));
                                self.progress.files_skipped.fetch_add(1, Relaxed);
                                self.progress.bytes_skipped.fetch_add(e.size, Relaxed);
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
                        if opts.verbose > 0 {
                            self.progress.println(&rel);
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
                        if opts.verbose > 0 {
                            self.progress
                                .println(&format!("{rel} -> {}", display(&target)));
                        }
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
                        if opts.dry_run && !same && opts.verbose > 0 {
                            self.progress.println(&rel);
                        }
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
            for (err, rec) in self.apply(true, ops)?.into_iter().zip(records) {
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
            let errs = self.apply(true, ops)?;
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

    fn under_pruned(&self, dst: &[u8], dst_root: &[u8]) -> bool {
        Self::under_any(&self.pruned, dst, dst_root)
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
            // this one (`syq --delete a b/ dst`: dst/a inside dst) is left to
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
            let our_pid: PartialId = self.opts.partial_id.get().copied().unwrap_or([0; 16]);
            let our_id = self
                .opts
                .partial_id
                .get()
                .map(crate::fsops::partial_id_string);
            // Destination directories that hold an ignored path, so must stay.
            let mut protected: std::collections::HashSet<PathBytes> =
                std::collections::HashSet::new();
            let seen = &self.dst_seen;
            // Destination directories whose path the source claims as a
            // non-directory (a file we chose not to send, a symlink skipped
            // without -l, ...). The source has that path, so syq doesn't touch
            // it — and gutting the directory underneath would be touching it.
            let mut shielded: Vec<PathBytes> = Vec::new();
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
                            || shielded.iter().any(|d| inside(&full, d))
                        {
                            continue;
                        }
                        match seen.get(&full) {
                            Some(Claim::Dir) => continue,
                            Some(_) => {
                                if e.kind == Kind::Dir {
                                    shielded.push(full);
                                }
                                continue;
                            }
                            None => {}
                        }
                        let dst_rel = join(sub.as_bytes(), &e.path);
                        let rel = display(&dst_rel);
                        let name = e.path.rsplit(|&c| c == b'/').next().unwrap_or(&e.path);
                        // Only a regular file can be a sidecar; a directory or
                        // symlink with that name is an ordinary extra. And only
                        // *this job's* sidecars are ours to judge: another
                        // job's is that command's live resume state, left alone.
                        // A truncated/compact name whose target can't be read
                        // back is left alone too.
                        if e.kind == Kind::File && crate::fsops::partial_job_id(name).is_some() {
                            // Ours: an extra only if its target is not in the
                            // source at all (orphan). A sidecar for a claimed
                            // target — whether that file failed, was filtered,
                            // or is already up to date — is resume state and
                            // stays until a transfer of that file consumes it.
                            if crate::fsops::partial_job_id(name)
                                == our_id.as_ref().map(|s| s.as_bytes())
                            {
                                if let Some(target) = crate::fsops::partial_target(&full, &our_pid)
                                {
                                    if !seen.contains_key(&target) {
                                        found.leaves.push((full, rel, Vec::new()));
                                    }
                                }
                            }
                        } else {
                            if e.kind == Kind::Dir {
                                let depth = full.iter().filter(|&&c| c == b'/').count();
                                found
                                    .dirs
                                    .entry(depth)
                                    .or_default()
                                    .push((full, format!("{rel}/")));
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
                &mut |w| self.progress.error(&format!("syq: delete: {w}")),
            );
            res?;
            self.deletes.leaves.append(&mut found.leaves);
            for (d, v) in found.dirs {
                for (path, rel) in v {
                    if protected.contains(&path) {
                        self.progress
                            .eprintln(&format!("syq: not deleting {rel}: it holds ignored paths"));
                    } else {
                        self.deletes.dirs.entry(d).or_default().push((path, rel));
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
        let mut run =
            |me: &mut Self, items: &[(PathBytes, String, PathBytes)], rmdir: bool| -> Result<()> {
                for chunk in items.chunks(1000) {
                    if opts.dry_run {
                        for (_, rel, _) in chunk {
                            n += 1;
                            if opts.verbose > 0 {
                                me.progress.println(&format!("deleting {rel}"));
                            }
                        }
                        continue;
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
                    for ((_, rel, dst_rel), err) in chunk.iter().zip(me.apply(true, ops)?) {
                        match err {
                            None => {
                                n += 1;
                                if opts.verbose > 0 {
                                    me.progress.println(&format!("deleting {rel}"));
                                }
                                // Forget any completion record: if the source ever
                                // brings this path back with the same fingerprint,
                                // it must be transferred, not assumed present.
                                if let (Some(c), false) = (&checkpoint, dst_rel.is_empty()) {
                                    c.record_deleted(dst_rel);
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
            let items: Vec<(PathBytes, String, PathBytes)> = items
                .iter()
                .map(|(p, r)| (p.clone(), r.clone(), Vec::new()))
                .collect();
            run(self, &items, true)?;
        }
        Ok(n)
    }

    fn stat_many(&mut self, _on_dst: bool, paths: Vec<PathBytes>) -> Result<Vec<Option<Entry>>> {
        stat_many(self.dst, paths, false)
    }

    fn apply(&mut self, _on_dst: bool, ops: Vec<Op>) -> Result<Vec<Option<String>>> {
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
            for err in self.apply(true, ops)?.into_iter().flatten() {
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
}

impl Worker {
    fn run(&mut self) -> Result<()> {
        let r = self.run_inner();
        if r.is_err() {
            // A dead connection here would otherwise leave peers blocked in
            // sched.next(); wake them so the whole transfer unwinds.
            self.sched.abort();
        }
        r
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
                            "syq: worker {} blocked: src recv {:.2}s, dst send {:.2}s, dst ack {:.2}s, idle {:.2}s",
                            self.id, self.t[0], self.t[1], self.t[2], self.t[3]
                        );
                    }
                    return Ok(());
                }
                Item::File(idx) => {
                    if self.fast_eligible(idx) {
                        let mut batch = vec![idx];
                        // The fast path reads a whole batch before sending it.
                        // Keep rate-limited batches to one file so a push can't
                        // accumulate locally and then hit the network in a burst.
                        if self.bwlimit.is_none() {
                            batch.extend(self.sched.take_small(
                                self.opts.block,
                                FAST_BATCH_FILES,
                                FAST_BATCH_BYTES,
                            ));
                        }
                        let (fast, slow): (Vec<usize>, Vec<usize>) =
                            batch.into_iter().partition(|&i| self.fast_eligible(i));
                        if let Err(e) = self.fast_batch(&fast) {
                            // Transport-level failure: every file in the batch is affected.
                            for &i in &fast {
                                self.sched.ranges_ready(i, vec![]);
                            }
                            self.file_error(fast[0], e)?;
                        }
                        for i in slow {
                            if let Err(e) = self.handle_file(i) {
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
                    let idx = h.lock().unwrap().idx;
                    let res = self.transfer_range(&h);
                    // Remove the handle from the scheduler's in-flight set FIRST,
                    // so a propagating error can't strand it and deadlock peers.
                    let done = self.sched.range_done(&h);
                    if let Err(e) = res {
                        self.file_error(idx, e)?;
                    }
                    if done {
                        if let Err(e) = self.finish_file(idx) {
                            self.file_error(idx, e)?;
                        }
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
        for j in &jobs {
            if j.entry.size > 0 {
                self.limit(j.entry.size);
                self.src.send(Request::ReadRange {
                    path: j.src.clone(),
                    attempt: j.attempts,
                    off: 0,
                    len: j.entry.size as u32,
                })?;
            }
        }
        let mut data: Vec<Result<Vec<u8>>> = Vec::with_capacity(jobs.len());
        for j in &jobs {
            if j.entry.size == 0 {
                data.push(Ok(Vec::new()));
                continue;
            }
            data.push(match ok(self.src.recv()?, "read") {
                Ok(Response::Block { hash, data, .. }) => {
                    if xxh3_64(&data) != hash {
                        Err(anyhow::anyhow!("block hash mismatch on read"))
                    } else {
                        Ok(data)
                    }
                }
                Ok(other) => Err(anyhow::anyhow!("unexpected response {other:?}")),
                Err(e) => Err(e),
            });
        }
        // One PutSmall per file (pipelined): the server writes each small file
        // through its sidecar and atomically renames it into place.
        let flags = self.opts.flags | flags::MODE; // set the computed mode explicitly
        let mut sent: Vec<bool> = Vec::with_capacity(jobs.len());
        for (j, d) in jobs.iter().zip(data.iter_mut()) {
            let Ok(bytes) = d else {
                sent.push(false);
                continue;
            };
            let bytes = std::mem::take(bytes);
            let hash = xxh3_64(&bytes);
            let mut meta = j.entry.meta();
            meta.mode = self.create_mode(j);
            self.dst.send(Request::PutSmall {
                path: j.dst.clone(),
                partial_id: self.partial_id(),
                data: bytes,
                hash,
                meta,
                flags,
                fsync: self.opts.fsync,
            })?;
            sent.push(true);
        }
        let mut results: Vec<Result<()>> = Vec::with_capacity(jobs.len());
        for (d, &was_sent) in data.iter_mut().zip(sent.iter()) {
            let res: Result<()> = if !was_sent {
                match d {
                    Ok(_) => Ok(()),
                    Err(e) => Err(anyhow::anyhow!("{e:#}")),
                }
            } else {
                ok(self.dst.recv()?, "put").map(|_| ())
            };
            results.push(res);
        }
        // Did any source change while we were at it?
        let paths: Vec<PathBytes> = jobs.iter().map(|j| j.src.clone()).collect();
        let now = match ok(
            self.src.call(Request::StatMany {
                paths,
                follow: false,
            })?,
            "stat",
        )? {
            Response::Stats(v) => v,
            other => bail!("unexpected response {other:?}"),
        };
        for ((idx, j), (res, now)) in batch
            .iter()
            .zip(jobs.iter())
            .zip(results.into_iter().zip(now.into_iter()))
        {
            self.sched.ranges_ready(*idx, vec![]);
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
                    self.progress.eprintln(&format!(
                        "syq: {}: changed during transfer, retrying",
                        j.rel
                    ));
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
            && job.attempts == 0
        {
            match self.try_copy_local(idx, &job) {
                Ok(true) => {
                    self.sched.ranges_ready(idx, vec![]);
                    return Ok(());
                }
                Ok(false) => {} // not offloadable — fall through to streaming
                Err(e) => {
                    self.sched.ranges_ready(idx, vec![]);
                    return Err(e);
                }
            }
        }
        let planned: Result<Vec<(u64, u64)>> = (|| {
            let final_entry = job.dst_entry.clone();
            if let Some(f) = &final_entry {
                if f.kind == Kind::Dir {
                    bail!("destination is a directory");
                }
            }
            let final_is_file = final_entry.as_ref().is_some_and(|f| f.kind == Kind::File);
            let full = || if size > 0 { vec![(0, size)] } else { vec![] };
            // Unless --inplace was explicit, every file is published through
            // a sidecar + atomic rename. Small new files normally take the
            // pipelined PutSmall path instead of reaching this worker path.
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
                    return self.diff_blocks(&job, Which::Final);
                }
                return Ok(full());
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
                    return Ok(vec![]);
                }
                return self.diff_blocks(&job, Which::Partial);
            }
            if final_is_file && (size > 0 && final_entry.as_ref().unwrap().size > 0 || size == 0) {
                if size == 0 {
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
                    return Ok(vec![]);
                }
                // SeedAndHash made a complete snapshot of the final file.
                // Publish it even when every block matched: applying metadata
                // to the live path could otherwise race with another job's
                // rename and produce one job's contents with the other's
                // metadata.
                return self.diff_final_and_seed(&job);
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
            Ok(full())
        })();

        let ranges = match planned {
            Ok(result) => result,
            Err(e) => {
                self.sched.ranges_ready(idx, vec![]);
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
                let res = self.transfer_range(&h);
                if let Err(e) = res {
                    self.file_error(idx, e)?;
                }
                if self.sched.range_done(&h) {
                    self.finish_file(idx)?;
                }
            }
            None => self.finish_file(idx)?,
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
                self.finish_file(idx)?;
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
        let block = self.opts.block;
        let size = job.entry.size;
        self.src.send(Request::HashBlocks {
            path: job.src.clone(),
            which: Which::Final,
            partial_id: self.partial_id(),
            block,
            len: size,
        })?;
        self.dst.send(Request::HashBlocks {
            path: job.dst.clone(),
            which,
            partial_id: self.partial_id(),
            block,
            len: size,
        })?;
        let sh = match ok(self.src.recv()?, "hash source")? {
            Response::Hashes(h) => h,
            other => bail!("unexpected response {other:?}"),
        };
        let dh = match ok(self.dst.recv()?, "hash destination")? {
            Response::Hashes(h) => h,
            other => bail!("unexpected response {other:?}"),
        };
        Ok(Self::different_ranges(&sh, &dh, block, size))
    }

    /// Compare the source with one opened final-file snapshot while the
    /// receiver seeds this job's sidecar from that exact same inode.
    fn diff_final_and_seed(&mut self, job: &FileJob) -> Result<Vec<(u64, u64)>> {
        let block = self.opts.block;
        let size = job.entry.size;
        self.src.send(Request::HashBlocks {
            path: job.src.clone(),
            which: Which::Final,
            partial_id: self.partial_id(),
            block,
            len: size,
        })?;
        self.dst.send(Request::SeedAndHash {
            path: job.dst.clone(),
            partial_id: self.partial_id(),
            block,
            len: size,
        })?;
        let source = match ok(self.src.recv()?, "hash source")? {
            Response::Hashes(hashes) => hashes,
            other => bail!("unexpected response {other:?}"),
        };
        let destination = match ok(self.dst.recv()?, "seed and hash destination")? {
            Response::Hashes(hashes) => hashes,
            other => bail!("unexpected response {other:?}"),
        };
        Ok(Self::different_ranges(&source, &destination, block, size))
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

    fn transfer_range(&mut self, h: &RangeHandle) -> Result<()> {
        let (idx, start, end0) = {
            let g = h.lock().unwrap();
            (g.idx, g.pos, g.end)
        };
        let job = self.job(idx);
        if self.sched.is_failed(idx) {
            return Ok(());
        }
        let _ = (start, end0);
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
        }
        while writes_out > 0 {
            ok(self.dst.recv()?, "write")?;
            writes_out -= 1;
        }
        Ok(())
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
        ok(
            self.dst.call(Request::Finalize {
                path: job.dst.clone(),
                inplace: job.inplace,
                partial_id: self.partial_id(),
                meta,
                flags,
                fsync: self.opts.fsync,
            })?,
            "finalize destination",
        )?;
        #[cfg(debug_assertions)]
        if let Some(ms) = std::env::var_os("SYQ_TEST_HOLD_AFTER_FINALIZE_MS") {
            if let Ok(ms) = ms.to_string_lossy().parse::<u64>() {
                std::thread::sleep(std::time::Duration::from_millis(ms));
            }
        }
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
                    self.progress.eprintln(&format!(
                        "syq: {}: changed during transfer, retrying",
                        job.rel
                    ));
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
        self.progress.files_done.fetch_add(1, Relaxed);
        self.record_done(&job.rel_bytes, &job.entry);
        if self.opts.verbose > 0 {
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
            let a = ok(self.src.recv()?, "hash source")?;
            let b = ok(self.dst.recv()?, "hash destination")?;
            match (a, b) {
                (
                    Response::FileHash { size: s1, hash: h1 },
                    Response::FileHash { size: s2, hash: h2 },
                ) => Ok(s1 == s2 && h1 == h2),
                (a, b) => bail!("unexpected responses {a:?} {b:?}"),
            }
        })();
        self.sched.ranges_ready(idx, vec![]);
        self.progress.add_bytes(job.entry.size);
        job.done.store(job.entry.size, Relaxed);
        match r {
            Ok(true) => {
                self.progress.files_done.fetch_add(1, Relaxed);
                if self.opts.verbose > 0 {
                    self.progress.println(&format!("ok      {}", job.rel));
                }
            }
            Ok(false) => {
                self.progress.error(&format!("DIFFERS {}", job.rel));
                self.sched.fail_file(idx);
            }
            Err(e) => return Err(e),
        }
        Ok(())
    }
}

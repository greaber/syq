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
                    if stat_one(dst_ctl, &target)?.is_none() {
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
    });

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
    let dst_root_entry = stat_one(&mut *dst_ctl, &dst_root)?;
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
        None => srcs.len() > 1 || dst.copies_contents(),
    };

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
            let src_is_dir = matches!(stat_one(&mut *src_ctl, s.path.as_bytes())?, Some(ref e) if e.kind == Kind::Dir);
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

    // Create a missing directory destination — never in the read-only modes.
    if dst_root_entry.is_none() && dst_is_dir && !args.dry_run && !args.verify_only {
        match ok(
            dst_ctl.call(Request::Apply(vec![Op::Mkdir {
                path: dst_root.clone(),
                mode: 0o755,
            }]))?,
            "mkdir",
        )? {
            Response::Applied(errs) => {
                if let Some(e) = errs.into_iter().flatten().next() {
                    bail!("{e}");
                }
            }
            other => bail!("unexpected response {other:?}"),
        }
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
        collision: false,
        deferred: Vec::new(),
        dirs_created: 0,
        links_created: 0,
        specials_created: 0,
    };

    let mut scan_err = None;
    for src in srcs {
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
    if !aborted && !opts.dry_run && !opts.verify_only {
        st.apply_deferred()?;
    }
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
                "syq: {} {} files ({}), {} unchanged ({} files), {} dirs{}{}",
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
                "  scanned entries: {}\n  files to transfer: {}\n  files unchanged: {}\n  bytes transferred: {}\n  bytes unchanged: {}\n  elapsed: {:.2}s\n  connections: {}",
                commas(progress.scanned.load(Relaxed)),
                commas(progress.files_total.load(Relaxed)),
                commas(progress.files_skipped.load(Relaxed)),
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
    } else {
        0
    })
}

fn st_dirs(p: &Progress) -> u64 {
    p.scanned
        .load(Relaxed)
        .saturating_sub(p.files_total.load(Relaxed) + p.files_skipped.load(Relaxed))
}

pub(crate) fn stat_one(conn: &mut dyn Conn, path: &[u8]) -> Result<Option<Entry>> {
    match ok(conn.call(Request::StatMany(vec![path.to_vec()]))?, "stat")? {
        Response::Stats(mut v) => Ok(v.pop().flatten()),
        other => bail!("unexpected response {other:?}"),
    }
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
        match stat_one(conn, &next_path)? {
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
    completed:
        Option<std::sync::Arc<std::collections::HashMap<PathBytes, crate::checkpoint::Completed>>>,
    checkpoint: Option<std::sync::Arc<crate::checkpoint::Checkpoint>>,
    /// Leaf destination paths already claimed, to reject two sources writing one file.
    /// dest path -> is_dir. Two dirs merge; a dir vs a leaf, or two leaves, conflict.
    dst_seen: std::collections::HashMap<PathBytes, bool>,
    collision: bool,
    /// (dst path, meta, flags, depth) for directories, applied deepest-first at the end.
    deferred: Vec<(PathBytes, Meta, u8, usize)>,
    dirs_created: u64,
    links_created: u64,
    specials_created: u64,
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
        let progress = self.progress;
        let recursive = self.opts.recursive;
        src.scan(
            src_root,
            follow,
            false,
            &self.opts.ignore,
            &mut |batch: Vec<Entry>| {
                if first {
                    first = false;
                    if let Some(root) = batch.first() {
                        if root.kind != Kind::Dir && !dst_is_dir {
                            sub = String::new();
                        }
                        if root.kind == Kind::Dir && !recursive {
                            progress.eprintln(&format!("skipping directory {}", display(src_root)));
                            return Ok(());
                        }
                    }
                }
                progress.scanned.fetch_add(batch.len() as u64, Relaxed);
                self.handle_batch(batch, src_root, &sub, dst_root)
            },
            &mut |w| {
                // "skipping …" is a notice (nothing the copy owes is missing);
                // anything else from the scanner means an entry was lost.
                if w.starts_with("skipping ") {
                    progress.eprintln(&format!("syq: {w}"));
                } else {
                    progress.error(&format!("syq: {w}"));
                }
            },
        )
    }

    fn handle_batch(
        &mut self,
        batch: Vec<Entry>,
        src_root: &[u8],
        sub: &str,
        dst_root: &[u8],
    ) -> Result<()> {
        let opts = self.opts;
        let sub_b = sub.as_bytes();
        let mut mkdirs: Vec<Op> = Vec::new();
        let mut dir_entries: Vec<(PathBytes, &Entry)> = Vec::new();
        let mut others: Vec<(PathBytes, PathBytes, PathBytes, &Entry)> = Vec::new();
        for e in &batch {
            if e.kind == Kind::Dir && !opts.recursive {
                continue;
            }
            let dst_rel = join(sub_b, &e.path);
            let dst_path = join(dst_root, &dst_rel);
            if e.kind == Kind::Dir {
                let rel = display(&dst_rel);
                if !self.claim_dst(&dst_path, &rel, true) {
                    continue;
                }
                mkdirs.push(Op::Mkdir {
                    path: dst_path.clone(),
                    mode: e.mode,
                });
                dir_entries.push((dst_path, e));
            } else {
                if e.kind == Kind::File {
                    // Claim before anything can skip the file (checkpoint, quick
                    // check), so a skipped file still blocks another source or
                    // a directory from mapping onto the same path.
                    let rel = self.rel_name(src_root, sub_b, &e.path);
                    if !self.claim_dst(&dst_path, &rel, false) {
                        continue;
                    }
                }
                others.push((join(src_root, &e.path), dst_path, dst_rel, e));
            }
        }

        if opts.verify_only && !dir_entries.is_empty() {
            let stats =
                self.stat_many(true, dir_entries.iter().map(|(p, _)| p.clone()).collect())?;
            for ((p, _), s) in dir_entries.iter().zip(stats) {
                if !matches!(s, Some(ref d) if d.kind == Kind::Dir) {
                    self.progress.error(&format!(
                        "{} {}/ (directory)",
                        if s.is_none() { "MISSING" } else { "DIFFERS" },
                        display(p)
                    ));
                }
            }
        } else if !dir_entries.is_empty() && !opts.dry_run && !opts.verify_only {
            let stats =
                self.stat_many(true, dir_entries.iter().map(|(p, _)| p.clone()).collect())?;
            let new_dirs: Vec<Op> = mkdirs
                .into_iter()
                .zip(stats.iter())
                // Keep the op for new dirs, and for existing dirs we can't yet
                // write into (0o700 not set) so apply() opens them up.
                .filter(|(_, s)| !matches!(s, Some(e) if e.kind == Kind::Dir && e.mode & 0o700 == 0o700))
                .map(|(op, _)| op)
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
            for ((p, e), s) in dir_entries.iter().zip(stats.iter()) {
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
        } else if opts.dry_run && opts.verbose > 0 {
            for (p, _) in &dir_entries {
                self.progress.println(&format!("{}/", display(p)));
            }
        }

        if others.is_empty() {
            return Ok(());
        }
        // An explicitly requested checkpoint may trust a matching source
        // fingerprint without a destination stat.
        if self.completed.is_some() && !opts.checksum {
            let completed = self.completed.clone().unwrap();
            let mut kept = Vec::with_capacity(others.len());
            for (src, dst, dst_rel, e) in others.into_iter() {
                if e.kind == Kind::File {
                    if let Some(c) = completed.get(&dst_rel) {
                        if c.matches(e, opts.flags) {
                            self.progress.files_skipped.fetch_add(1, Relaxed);
                            self.progress.bytes_skipped.fetch_add(e.size, Relaxed);
                            continue;
                        }
                    }
                }
                kept.push((src, dst, dst_rel, e));
            }
            others = kept;
        }
        let stats = self.stat_many(true, others.iter().map(|(_, d, _, _)| d.clone()).collect())?;
        let mut ops: Vec<Op> = Vec::new();
        let mut op_names: Vec<String> = Vec::new();
        // Metadata repairs for quick-check-identical files, each with the
        // checkpoint record once the repair has actually succeeded.
        let mut meta_fixes: Vec<(Op, Option<QuickCheckRecord>)> = Vec::new();
        for ((src_path, dst_path, dst_rel, e), dst_entry) in others.into_iter().zip(stats) {
            let rel = self.rel_name(src_root, sub_b, &e.path);
            match e.kind {
                Kind::File => {
                    // Never copy a file onto itself (same path, hardlink, or a
                    // symlinked alias) — with --inplace that would truncate the
                    // source. Only possible when both ends are the same machine.
                    if opts.same_host
                        && dst_entry
                            .as_ref()
                            .is_some_and(|d| d.dev == e.dev && d.ino == e.ino)
                    {
                        self.progress.eprintln(&format!(
                            "skipping {rel}: source and destination are the same file"
                        ));
                        continue;
                    }
                    let same = dst_entry.as_ref().is_some_and(|d| {
                        d.kind == Kind::File
                            && d.size == e.size
                            && (opts.flags & flags::TIMES != 0 && d.mtime == e.mtime)
                    });
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
                            checkpoint.record_complete(&dst_rel, e, "quick-check");
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
                    if !opts.links {
                        if opts.verbose > 0 {
                            self.progress
                                .eprintln(&format!("skipping non-regular file \"{rel}\""));
                        }
                        continue;
                    }
                    if !self.claim_dst(&dst_path, &rel, false) {
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
                    if !opts.devices {
                        if opts.verbose > 0 {
                            self.progress
                                .eprintln(&format!("skipping non-regular file \"{rel}\""));
                        }
                        continue;
                    }
                    if !self.claim_dst(&dst_path, &rel, false) {
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
                Kind::Dir | Kind::Other => {}
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
    fn claim_dst(&mut self, dst: &PathBytes, rel: &str, is_dir: bool) -> bool {
        match self.dst_seen.get(dst) {
            Some(&prev_dir) if prev_dir && is_dir => true,
            Some(_) => {
                self.progress.error(&format!(
                    "syq: {rel}: two sources map to the same destination {} with conflicting types — refusing to clobber it",
                    display(dst)
                ));
                self.collision = true;
                false
            }
            None => {
                self.dst_seen.insert(dst.clone(), is_dir);
                true
            }
        }
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

    fn stat_many(&mut self, _on_dst: bool, paths: Vec<PathBytes>) -> Result<Vec<Option<Entry>>> {
        match ok(self.dst.call(Request::StatMany(paths))?, "stat")? {
            Response::Stats(v) => Ok(v),
            other => bail!("unexpected response {other:?}"),
        }
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
        let now = match ok(self.src.call(Request::StatMany(paths))?, "stat")? {
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
            // the pipelined PutSmall path instead of reaching this worker path.
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
                let ranges = self.diff_final_and_hold(&job)?;
                if ranges.is_empty() && final_entry.as_ref().unwrap().size == size {
                    let mut meta = job.entry.meta();
                    meta.mode = self.create_mode(&job);
                    ok(
                        self.dst.call(Request::FinishBasis {
                            path: job.dst.clone(),
                            partial_id: self.partial_id(),
                            meta,
                            flags: self.opts.flags | flags::MODE,
                            fsync: self.opts.fsync,
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
            None if needs_finalize => self.finish_file(idx)?,
            None => self.finish_matched_file(idx)?,
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
    }

    /// Compare the source with one opened final-file inode retained by the
    /// receiver for either metadata-only completion or sidecar seeding.
    fn diff_final_and_hold(&mut self, job: &FileJob) -> Result<Vec<(u64, u64)>> {
        self.diff_with(
            job,
            Request::HashAndHold {
                path: job.dst.clone(),
                partial_id: self.partial_id(),
                block: self.opts.block,
                len: job.entry.size,
            },
            "hash and retain destination basis",
        )
    }

    fn diff_with(
        &mut self,
        job: &FileJob,
        destination_request: Request,
        destination_label: &str,
    ) -> Result<Vec<(u64, u64)>> {
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
        let source = Self::hashes(ok(self.src.recv()?, "hash source")?)?;
        let destination = Self::hashes(ok(self.dst.recv()?, destination_label)?)?;
        Ok(Self::different_ranges(&source, &destination, block, size))
    }

    fn hashes(response: Response) -> Result<Vec<u64>> {
        match response {
            Response::Hashes(hashes) => Ok(hashes),
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
        self.complete_file(idx, job, false)
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
        let now = stat_one(&mut *self.src, &job.src)?;
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

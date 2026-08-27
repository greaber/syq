//! The orchestrator: scan, diff, schedule, and the per-worker transfer loop.

use crate::bwlimit::BandwidthLimit;
use crate::cli::{parse_rsh, parse_size, Args, Location};
use crate::conn::{ok, Conn, Endpoint, RemoteSpec};
use crate::fsops::join;
use crate::progress::{commas, human, Progress, WorkerStatus};
use crate::proto::*;
use crate::sched::{FileJob, Item, RangeHandle, Sched};
use anyhow::{bail, Result};
use std::os::unix::ffi::OsStrExt;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
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
    pub atomic: bool,
    pub fsync: bool,
    pub same_host: bool,
    pub dry_run: bool,
    pub verbose: u8,
    pub umask: u32,
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
            pcp_path: args.pcp_path.clone(),
            auto_helper: args.pcp_path.is_none() && !args.no_bootstrap,
            helper_install: Default::default(),
            quiet: args.quiet,
            tcp: Default::default(),
        }),
    })
}

pub fn connect_ctl(ep: &Endpoint, args: &Args) -> Result<Box<dyn Conn>> {
    ep.connect(args.compress)
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

/// Absolute, normalized form of a path for containment checks. Locally we
/// canonicalize the longest existing prefix (resolving symlinks and `..`);
/// remotely we can only normalize lexically.
fn norm_path(p: &str, local: bool) -> std::path::PathBuf {
    use std::path::{Component, PathBuf};
    let raw = crate::fsops::resolve(p.as_bytes());
    let abs = if raw.is_absolute() {
        raw
    } else if local {
        std::env::current_dir().unwrap_or_default().join(raw)
    } else {
        // A remote relative path is relative to the remote home; keep it as-is
        // and rely on lexical comparison of like-formed paths.
        raw
    };
    // Lexical normalization (drop `.`, resolve `..`).
    let mut out = PathBuf::new();
    for c in abs.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            c => out.push(c.as_os_str()),
        }
    }
    if local {
        // Canonicalize the longest existing prefix so symlinked sources compare
        // by their real location; re-append the not-yet-existing tail.
        let mut existing = out.clone();
        let mut tail: Vec<std::ffi::OsString> = Vec::new();
        while !existing.as_os_str().is_empty() {
            if let Ok(mut real) = std::fs::canonicalize(&existing) {
                for name in tail.iter().rev() {
                    real.push(name);
                }
                return real;
            }
            match existing.file_name().map(|n| n.to_os_string()) {
                Some(name) => {
                    tail.push(name);
                    existing.pop();
                }
                None => break,
            }
        }
    }
    out
}

/// Encode the content/metadata-affecting options into the job identity.
fn semantic_flags(opts: &Opts, args: &Args) -> String {
    format!(
        "r={} l={} p={} t={} g={} o={} D={} inplace={} atomic={}",
        opts.recursive,
        opts.links,
        opts.flags & flags::MODE != 0,
        opts.flags & flags::TIMES != 0,
        opts.flags & flags::GROUP != 0,
        opts.flags & flags::OWNER != 0,
        opts.devices,
        args.inplace,
        args.atomic,
    )
}

fn root_meta_from(m: &Meta) -> crate::resume::RootMeta {
    crate::resume::RootMeta {
        mode: m.mode,
        uid: m.uid,
        gid: m.gid,
        mtime_sec: m.mtime,
        mtime_nsec: m.mtime_nsec,
    }
}
fn meta_from_root(r: &crate::resume::RootMeta) -> Meta {
    Meta {
        mode: r.mode,
        uid: r.uid,
        gid: r.gid,
        mtime: r.mtime_sec,
        mtime_nsec: r.mtime_nsec,
    }
}

/// Restore the destination-root metadata after the marker (a file inside it)
/// was created/removed and bumped its mtime.
fn restore_root_meta(ctl: &mut dyn Conn, dst_root: &[u8], meta: &Meta, flags: u8) -> Result<()> {
    if flags == 0 {
        return Ok(());
    }
    ok(
        ctl.call(Request::Apply(vec![Op::SetMeta {
            path: dst_root.to_vec(),
            meta: *meta,
            flags,
        }]))?,
        "restore root meta",
    )?;
    Ok(())
}

/// Decide fresh / resume / cleanup-then-fresh / abort, set up the journal and
/// marker, and return the resume state (None if resume is disabled for this run).
#[allow(clippy::too_many_arguments)]
fn resume_setup(
    args: &Args,
    srcs: &[Location],
    dst: &Location,
    src_ctl: &mut dyn Conn,
    dst_ctl: &mut dyn Conn,
    dst_root: &[u8],
    dst_is_dir: bool,
    opts: &Opts,
) -> Result<Option<ResumeState>> {
    use crate::resume::{
        job_key, journal_path, new_session_id, Journal, LastSession, Marker, FORMAT,
    };
    if args.no_resume || args.dry_run || args.verify_only {
        return Ok(None);
    }
    let local = |l: &Location| !l.is_remote();
    let src_ep = srcs[0].host.clone().unwrap_or_else(|| "local".into());
    let dst_ep = dst.host.clone().unwrap_or_else(|| "local".into());
    let src_roots: Vec<(String, bool)> = srcs
        .iter()
        .map(|l| {
            (
                norm_path(&l.path, local(l)).to_string_lossy().into_owned(),
                l.copies_contents(),
            )
        })
        .collect();
    let dst_norm = norm_path(&dst.path, local(dst))
        .to_string_lossy()
        .into_owned();
    let identity = crate::resume::job_identity(
        &src_ep,
        &src_roots,
        &dst_ep,
        &dst_norm,
        &semantic_flags(opts, args),
    );
    let key = job_key(&identity);

    let loaded = Journal::load(&key)?;
    if let Some(ex) = &loaded.existing_identity {
        if *ex != identity {
            bail!(
                "the resume journal for this destination describes a different copy; pass --no-resume or remove {}",
                journal_path(&key).display()
            );
        }
    }

    let marker_path = marker_path_for(dst_root, dst_is_dir);
    // Root metadata to restore after marker cleanup: only when a single source's
    // contents map onto the destination root and we preserve its mode/times.
    let meta_flags = opts.flags & (flags::MODE | flags::OWNER | flags::GROUP | flags::TIMES);
    let root_meta: Option<Meta> = if srcs.len() == 1 && srcs[0].copies_contents() && meta_flags != 0
    {
        stat_one(src_ctl, srcs[0].path.as_bytes())?.map(|e| {
            let mut m = e.meta();
            if opts.flags & flags::MODE == 0 {
                m.mode = e.mode & 0o777 & !opts.umask;
            }
            m
        })
    } else {
        None
    };

    let existing = marker_read(dst_ctl, &marker_path)?;

    // Cleanup helpers.
    let do_cleanup = |dst_ctl: &mut dyn Conn,
                      journal: &Journal,
                      sid: &str,
                      rm: Option<&crate::resume::RootMeta>,
                      marker_present: bool|
     -> Result<()> {
        if marker_present {
            marker_remove(dst_ctl, &marker_path)?;
        }
        if let Some(rm) = rm {
            restore_root_meta(dst_ctl, dst_root, &meta_from_root(rm), meta_flags)?;
        }
        journal.cleanup_complete(sid)?;
        Ok(())
    };

    let start_new = |dst_ctl: &mut dyn Conn,
                     completed: std::collections::HashMap<PathBytes, crate::resume::Completed>|
     -> Result<Option<ResumeState>> {
        let journal = Journal::open(&key, &identity, loaded.existing_identity.as_deref())?;
        let session_id = new_session_id();
        let marker = Marker {
            format: FORMAT,
            session_id: session_id.clone(),
            job_identity: identity.clone(),
            created_at: 0,
            coordinator_host: crate::resume::hostname(),
        };
        match marker_create(dst_ctl, &marker_path, &marker) {
            Ok(None) => {}
            Ok(Some(other)) => {
                bail!(
                    "destination was just claimed by another transfer (session {}, host {})",
                    other.session_id,
                    other.coordinator_host
                );
            }
            Err(e) => {
                // Can't claim the destination (e.g. read-only dir): fall back to
                // running without resume rather than failing the transfer.
                if debug() {
                    eprintln!("pcp: resume disabled (cannot create marker: {e:#})");
                }
                return Ok(None);
            }
        }
        journal.session_start(&session_id)?;
        Ok(Some(ResumeState {
            journal: std::sync::Arc::new(journal),
            completed: std::sync::Arc::new(completed),
            session_id,
            marker_path: marker_path.clone(),
            root_meta,
        }))
    };

    match (&existing, &loaded.last) {
        (Some(m), _) if m.job_identity != identity => bail!(
            "destination is claimed by a different transfer (session {}, host {}); if it is stale, remove {}",
            m.session_id, m.coordinator_host, display(&marker_path)
        ),
        (Some(m), LastSession::NeedsCleanup(sid, rm)) if sid == &m.session_id => {
            let journal = Journal::open(&key, &identity, loaded.existing_identity.as_deref())?;
            do_cleanup(dst_ctl, &journal, sid, rm.as_ref(), true)?;
            drop(journal);
            start_new(dst_ctl, loaded.completed)
        }
        (Some(m), LastSession::Incomplete(sid)) if sid == &m.session_id => {
            let journal = Journal::open(&key, &identity, loaded.existing_identity.as_deref())?;
            Ok(Some(ResumeState {
                journal: std::sync::Arc::new(journal),
                completed: std::sync::Arc::new(loaded.completed),
                session_id: sid.clone(),
                marker_path,
                root_meta,
            }))
        }
        (Some(m), other) => bail!(
            "destination is owned by session {} but the local journal does not match ({other:?}); resume needs the matching local journal, or remove {} to start over",
            m.session_id, display(&marker_path)
        ),
        (None, LastSession::NeedsCleanup(sid, rm)) => {
            let journal = Journal::open(&key, &identity, loaded.existing_identity.as_deref())?;
            do_cleanup(dst_ctl, &journal, sid, rm.as_ref(), false)?;
            drop(journal);
            start_new(dst_ctl, loaded.completed)
        }
        (None, LastSession::Incomplete(sid)) => bail!(
            "an interrupted transfer's journal exists (session {sid}) but its destination marker is gone; the destination may have changed — remove it and start over, or pass --no-resume"
        ),
        (None, _) => start_new(dst_ctl, loaded.completed),
    }
}

/// Read the destination marker (if any) as a parsed struct.
fn marker_read(ctl: &mut dyn Conn, path: &[u8]) -> Result<Option<crate::resume::Marker>> {
    match ok(
        ctl.call(Request::MarkerRead {
            path: path.to_vec(),
        })?,
        "marker read",
    )? {
        Response::Marker(Some(data)) => Ok(serde_json::from_slice(&data).ok()),
        Response::Marker(None) => Ok(None),
        other => bail!("unexpected response {other:?}"),
    }
}

/// Create the marker (exclusive). Ok(None) on success; Ok(Some(existing)) if it
/// already existed.
fn marker_create(
    ctl: &mut dyn Conn,
    path: &[u8],
    m: &crate::resume::Marker,
) -> Result<Option<crate::resume::Marker>> {
    let data = serde_json::to_vec(m)?;
    match ok(
        ctl.call(Request::MarkerCreate {
            path: path.to_vec(),
            data,
        })?,
        "marker create",
    )? {
        Response::Ok => Ok(None),
        Response::MarkerExists(existing) => Ok(Some(
            serde_json::from_slice(&existing).unwrap_or_else(|_| m.clone()),
        )),
        other => bail!("unexpected response {other:?}"),
    }
}

fn marker_remove(ctl: &mut dyn Conn, path: &[u8]) -> Result<()> {
    ok(
        ctl.call(Request::MarkerRemove {
            path: path.to_vec(),
        })?,
        "marker remove",
    )?;
    Ok(())
}

/// Resume state for one transfer: the completion journal, the set of files
/// already complete, the session id, and where the marker lives.
struct ResumeState {
    journal: std::sync::Arc<crate::resume::Journal>,
    completed: std::sync::Arc<std::collections::HashMap<PathBytes, crate::resume::Completed>>,
    session_id: String,
    marker_path: PathBytes,
    root_meta: Option<Meta>,
}

/// Shared with workers: the completion journal (if resume is active). Filled in
/// after resume_setup, before the planner enqueues any work.
#[derive(Default)]
struct ResumeShared {
    journal: Option<std::sync::Arc<crate::resume::Journal>>,
}
type ResumeSlot = std::sync::Arc<std::sync::OnceLock<ResumeShared>>;

/// Marker path for a destination: inside the directory for a dir scope, else a
/// sidecar next to the file.
fn marker_path_for(dst_root: &[u8], dst_is_dir: bool) -> PathBytes {
    use crate::resume::MARKER_NAME;
    if dst_is_dir {
        join(dst_root, MARKER_NAME.as_bytes())
    } else {
        let p = std::path::Path::new(std::ffi::OsStr::from_bytes(dst_root));
        let name = p
            .file_name()
            .map(|n| n.as_bytes().to_vec())
            .unwrap_or_else(|| b"root".to_vec());
        let mut sidecar = b".".to_vec();
        sidecar.extend_from_slice(&name);
        sidecar.extend_from_slice(MARKER_NAME.as_bytes());
        match p.parent() {
            Some(par) if !par.as_os_str().is_empty() => join(par.as_os_str().as_bytes(), &sidecar),
            _ => sidecar,
        }
    }
}

pub fn debug() -> bool {
    std::env::var_os("PCP_DEBUG").is_some()
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
    if args.connections_default && !src_ep.is_remote() && !dst_ep.is_remote() {
        // Local threads are cheap and network filesystems want the concurrency,
        // but don't oversubscribe a small machine (a laptop shouldn't spawn 32).
        let ncpu = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        args.connections = ncpu.clamp(4, LOCAL_DEFAULT_CONNECTIONS);
    }
    if src_ep.is_remote() && dst_ep.is_remote() {
        if !args.relay {
            return crate::direct::run(&args, srcs, dst);
        }
        if !args.quiet {
            eprintln!("pcp: remote-to-remote transfer: relaying data through this machine");
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
        atomic: args.atomic,
        fsync: args.fsync,
        same_host: !src_ep.is_remote() && !dst_ep.is_remote(),
        dry_run: args.dry_run,
        verbose: args.verbose,
        umask: read_umask(),
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

    // Workers connect on their own threads, in parallel with the control
    // connections below, so all ssh sessions come up at once.
    let mut workers: Vec<std::thread::JoinHandle<Result<()>>> = Vec::new();
    let resume_slot: ResumeSlot = std::sync::Arc::new(std::sync::OnceLock::new());
    let spawn_workers = |workers: &mut Vec<std::thread::JoinHandle<Result<()>>>| {
        for id in 0..args.connections {
            let (src_ep, dst_ep, sched, progress, opts, resume, bwlimit) = (
                src_ep.clone(),
                dst_ep.clone(),
                sched.clone(),
                progress.clone(),
                opts.clone(),
                resume_slot.clone(),
                bwlimit.clone(),
            );
            let compress = args.compress;
            workers.push(std::thread::spawn(move || -> Result<()> {
                let t0 = std::time::Instant::now();
                let mut w = Worker {
                    id,
                    src: src_ep.connect(compress)?,
                    dst: dst_ep.connect(compress)?,
                    sched,
                    progress,
                    opts,
                    resume,
                    bwlimit,
                    t: [0.0; 4],
                };
                if debug() {
                    eprintln!(
                        "pcp: worker {id} connected in {:.2}s",
                        t0.elapsed().as_secs_f64()
                    );
                }
                w.run()
            }));
        }
    };
    // TCP data connections are the default (auto-selecting the fastest reachable
    // NIC and falling back to ssh if unreachable); --no-tcp forces ssh data.
    // Local<->local needs no data plane at all.
    let use_tcp = !args.no_tcp && (src_ep.is_remote() || dst_ep.is_remote());
    // Whether the user said anything about TCP, which controls how loudly we
    // report a fallback (silent when it's just the default).
    let auto_helper =
        args.pcp_path.is_none() && !args.no_bootstrap && (src_ep.is_remote() || dst_ep.is_remote());
    if !opts.dry_run && !auto_helper && !use_tcp {
        spawn_workers(&mut workers);
    }

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
            "pcp: control connections up in {:.2}s",
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
                            "pcp: {}: data over ssh (TCP ports {}-{} not reachable: {e:#}); a Tailscale address or an open port is faster",
                            spec.label(),
                            ports.0,
                            ports.1
                        );
                    }
                    continue;
                }
                if debug() {
                    eprintln!(
                        "pcp: {}: tcp data port {:?}",
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
    if !opts.dry_run && (auto_helper || use_tcp) {
        spawn_workers(&mut workers);
    }

    let dst_root = dst.path.as_bytes().to_vec();
    let dst_root_entry = stat_one(&mut *dst_ctl, &dst_root)?;
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
        let local = !dst.is_remote();
        for s in srcs {
            // Only a directory source can trigger the recurse-into-itself trap.
            let src_is_dir = matches!(stat_one(&mut *src_ctl, s.path.as_bytes())?, Some(ref e) if e.kind == Kind::Dir);
            if !src_is_dir {
                continue;
            }
            let sn = norm_path(&s.path, local);
            // Effective destination(s): the destination itself, plus
            // destination/basename only when the destination is really an
            // existing directory (so a bare source lands inside it).
            let mut effs = vec![norm_path(&dst.path, local)];
            if dst_is_dir && !s.copies_contents() {
                let base = s.basename();
                if !base.is_empty() {
                    let joined = format!("{}/{}", dst.path.trim_end_matches('/'), base);
                    effs.push(norm_path(&joined, local));
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

    if dst_root_entry.is_none() && dst_is_dir && !args.dry_run {
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

    // Resume: read/create the destination marker and load the completion journal.
    let resume_state = resume_setup(
        &args,
        srcs,
        dst,
        &mut *src_ctl,
        &mut *dst_ctl,
        &dst_root,
        dst_is_dir,
        &opts,
    )?;
    let resume_completed = resume_state.as_ref().map(|r| r.completed.clone());
    let resume_journal = resume_state.as_ref().map(|r| r.journal.clone());
    if let Some(r) = &resume_state {
        let _ = resume_slot.set(ResumeShared {
            journal: Some(r.journal.clone()),
        });
    }

    let ticker = progress.spawn_ticker();

    let mut st = Planner {
        dst: &mut *dst_ctl,
        sched: &sched,
        progress: &progress,
        opts: &opts,
        completed: resume_completed.clone(),
        journal: resume_journal.clone(),
        reserved: resume_state.as_ref().map(|r| r.marker_path.clone()),
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
        progress.error(&format!("pcp: {e:#}"));
        sched.abort();
    }
    if collision {
        sched.abort();
    }

    for w in workers {
        match w.join() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                progress.error(&format!("pcp: worker: {e:#}"));
                sched.abort();
            }
            Err(_) => progress.error("pcp: worker thread panicked"),
        }
    }

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

    // Resume cleanup: on full success, release the marker and close the session;
    // otherwise leave marker + journal so the same command can resume.
    if let Some(r) = &resume_state {
        if !aborted && errors == 0 {
            let mf = opts.flags & (flags::MODE | flags::OWNER | flags::GROUP | flags::TIMES);
            let rm = r.root_meta.as_ref().map(root_meta_from);
            let res: Result<()> = (|| {
                r.journal.session_complete(&r.session_id, rm)?;
                marker_remove(&mut *dst_ctl, &r.marker_path)?;
                if let Some(m) = &r.root_meta {
                    restore_root_meta(&mut *dst_ctl, &dst_root, m, mf)?;
                }
                r.journal.cleanup_complete(&r.session_id)?;
                Ok(())
            })();
            if let Err(e) = res {
                eprintln!(
                    "pcp: resume cleanup: {e:#} (transfer completed; the next run will finish cleanup)"
                );
            }
        } else {
            let _ = r.journal.flush();
        }
    }
    let elapsed = progress.start.elapsed().as_secs_f64();
    let done = progress.bytes_done.load(Relaxed);
    if !args.quiet {
        if opts.verify_only {
            println!(
                "pcp: verified {} files, {} differ/missing, {} in {}",
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
                "pcp: {} {} files ({}), {} unchanged ({} files), {} dirs{}{}",
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
                "  scanned entries: {}\n  files to transfer: {}\n  files unchanged: {}\n  bytes transferred: {}\n  bytes unchanged: {}\n  elapsed: {:.2}s",
                commas(progress.scanned.load(Relaxed)),
                commas(progress.files_total.load(Relaxed)),
                commas(progress.files_skipped.load(Relaxed)),
                commas(done),
                commas(progress.bytes_skipped.load(Relaxed)),
                elapsed
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

fn stat_one(conn: &mut dyn Conn, path: &[u8]) -> Result<Option<Entry>> {
    match ok(conn.call(Request::StatMany(vec![path.to_vec()]))?, "stat")? {
        Response::Stats(mut v) => Ok(v.pop().flatten()),
        other => bail!("unexpected response {other:?}"),
    }
}

fn display(p: &[u8]) -> String {
    String::from_utf8_lossy(p).into_owned()
}

struct Planner<'a> {
    dst: &'a mut dyn Conn,
    sched: &'a Sched,
    progress: &'a Progress,
    opts: &'a Opts,
    completed:
        Option<std::sync::Arc<std::collections::HashMap<PathBytes, crate::resume::Completed>>>,
    journal: Option<std::sync::Arc<crate::resume::Journal>>,
    /// The resume marker's destination path, if resume is active. A source entry
    /// that maps onto it must be refused rather than clobbering the interlock.
    reserved: Option<PathBytes>,
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
            &mut |w| progress.error(&format!("pcp: {w}")),
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
                let rel = display(&join(sub_b, &e.path));
                if !self.claim_dst(&dst_path, &rel, true) {
                    continue;
                }
                mkdirs.push(Op::Mkdir {
                    path: dst_path.clone(),
                    mode: e.mode,
                });
                dir_entries.push((dst_path, e));
            } else {
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
                        self.progress.error(&format!("pcp: {err}"));
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
            for (p, e) in &dir_entries {
                let depth = p.iter().filter(|&&c| c == b'/').count();
                self.deferred.push((p.clone(), e.meta(), flags, depth));
            }
        } else if opts.dry_run && opts.verbose > 0 {
            for (p, _) in &dir_entries {
                self.progress.println(&format!("{}/", display(p)));
            }
        }

        if others.is_empty() {
            return Ok(());
        }
        // Journal skip: a file whose completion record still matches the source
        // fingerprint is complete without a destination stat. Bypassed under -c.
        if self.completed.is_some() && !opts.checksum {
            let completed = self.completed.clone().unwrap();
            let mut kept = Vec::with_capacity(others.len());
            for (src, dst, dst_rel, e) in others.into_iter() {
                if e.kind == Kind::File {
                    if let Some(c) = completed.get(&dst_rel) {
                        if c.size == e.size
                            && c.mtime_sec == e.mtime
                            && c.mtime_nsec == e.mtime_nsec
                        {
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
        let mut meta_fixes: Vec<Op> = Vec::new();
        for ((src_path, dst_path, dst_rel, e), dst_entry) in others.into_iter().zip(stats) {
            let rel = {
                let r = join(sub_b, &e.path);
                if r.is_empty() {
                    display(src_root.rsplit(|&c| c == b'/').next().unwrap_or(src_root))
                } else {
                    display(&r)
                }
            };
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
                    // Never let a source file land on the resume marker: that
                    // would destroy the cross-machine interlock for this run.
                    if self.reserved.as_deref() == Some(dst_path.as_slice()) {
                        self.progress.error(&format!(
                            "pcp: {rel}: destination path is reserved by pcp's resume marker — refusing to overwrite it"
                        ));
                        self.collision = true;
                        continue;
                    }
                    // Claim the destination BEFORE deciding skip-vs-transfer, so a
                    // quick-skipped file still blocks another source (or a dir)
                    // from mapping onto the same path.
                    if !self.claim_dst(&dst_path, &rel, false) {
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
                                meta_fixes.push(Op::SetMeta {
                                    path: dst_path.clone(),
                                    meta: e.meta(),
                                    flags: ff,
                                });
                            }
                        }
                        self.progress.files_skipped.fetch_add(1, Relaxed);
                        self.progress.bytes_skipped.fetch_add(e.size, Relaxed);
                        if let Some(j) = &self.journal {
                            j.record_complete(
                                &dst_rel,
                                e.size,
                                e.mtime,
                                e.mtime_nsec,
                                "quick-check",
                            );
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
            for err in self.apply(true, meta_fixes)?.into_iter().flatten() {
                self.progress.error(&format!("pcp: {err}"));
            }
        }
        if !ops.is_empty() {
            let errs = self.apply(true, ops)?;
            // Two ops per item: creation then metadata.
            for (i, name) in op_names.iter().enumerate() {
                let e1 = errs.get(2 * i).cloned().flatten();
                let e2 = errs.get(2 * i + 1).cloned().flatten();
                if let Some(e) = e1.or(e2) {
                    self.progress.error(&format!("pcp: {e}"));
                } else if opts.verbose > 0 {
                    self.progress.println(name);
                }
            }
        }
        Ok(())
    }

    /// Record a leaf (file/symlink/special) destination; return false if this
    /// exact destination was already claimed by another source (a collision).
    fn claim_dst(&mut self, dst: &PathBytes, rel: &str, is_dir: bool) -> bool {
        match self.dst_seen.get(dst) {
            Some(&prev_dir) if prev_dir && is_dir => true,
            Some(_) => {
                self.progress.error(&format!(
                    "pcp: {rel}: two sources map to the same destination {} with conflicting types — refusing to clobber it",
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
                self.progress.error(&format!("pcp: {err}"));
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
    resume: ResumeSlot,
    bwlimit: Option<Arc<BandwidthLimit>>,
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
            let t0 = std::time::Instant::now();
            let item = self.sched.next();
            self.t[3] += t0.elapsed().as_secs_f64();
            match item {
                Item::Exit => {
                    if debug() {
                        eprintln!(
                            "pcp: worker {} blocked: src recv {:.2}s, dst send {:.2}s, dst ack {:.2}s, idle {:.2}s",
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

    /// Small new files (no existing destination file) are sent without a
    /// per-file round trip: one pipelined burst of reads, one of
    /// prepare+write+finalize, one stat — a few RTTs for the whole batch.
    fn fast_eligible(&self, idx: usize) -> bool {
        let jobs = self.sched.jobs.lock().unwrap();
        let j = &jobs[idx];
        !self.opts.verify_only
            && !self.opts.inplace
            && !self.opts.atomic
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
        // One PutSmall per file (pipelined): the server writes each small new
        // file straight to its final path (no rename), which is the big NFS win.
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
                self.progress.error(&format!("pcp: {}: {e:#}", j.rel));
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
                        "pcp: {}: changed during transfer, retrying",
                        j.rel
                    ));
                    let mut all = self.sched.jobs.lock().unwrap();
                    let job = &mut all[*idx];
                    self.progress.bytes_total.fetch_add(e.size, Relaxed);
                    job.entry = Entry {
                        path: job.entry.path.clone(),
                        ..e
                    };
                    job.attempts += 1;
                    // Keep the original dst_entry so mode is preserved on retry
                    // without -p (don't adopt the source's mode).
                    drop(all);
                    self.sched.requeue(*idx);
                } else {
                    self.progress.error(&format!(
                        "pcp: {}: source changed during transfer (or vanished)",
                        j.rel
                    ));
                    self.sched.fail_file(*idx);
                }
                continue;
            }
            self.progress.add_bytes(j.entry.size);
            j.done.store(j.entry.size, Relaxed);
            self.progress.files_done.fetch_add(1, Relaxed);
            self.record_done(
                &j.rel_bytes,
                j.entry.size,
                j.entry.mtime,
                j.entry.mtime_nsec,
            );
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
            self.progress.error(&format!("pcp: {rel}: {e:#}"));
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
        // Same-machine copy: let the kernel move the bytes (reflink / NFS
        // server-side copy) instead of streaming them through userspace.
        // copy_file_range cannot be paced, so a limited same-machine transfer
        // uses the regular userspace path (also useful for mounted NFS paths).
        if self.opts.same_host
            && !self.opts.checksum
            && self.bwlimit.is_none()
            && job.entry.size > 0
        {
            match self.try_copy_local(idx, &job) {
                Ok(true) => return Ok(()),
                Ok(false) => {} // not offloadable — fall through to streaming
                Err(e) => {
                    self.sched.ranges_ready(idx, vec![]);
                    return Err(e);
                }
            }
        }
        let planned: Result<Vec<(u64, u64)>> = (|| {
            let (partial_size, final_entry) = match ok(
                self.dst.call(Request::Probe {
                    path: job.dst.clone(),
                })?,
                "probe",
            )? {
                Response::Probed {
                    partial_size,
                    final_entry,
                } => (partial_size, final_entry),
                other => bail!("unexpected response {other:?}"),
            };
            if let Some(f) = &final_entry {
                if f.kind == Kind::Dir {
                    bail!("destination is a directory");
                }
            }
            let final_is_file = final_entry.as_ref().is_some_and(|f| f.kind == Kind::File);
            let full = || if size > 0 { vec![(0, size)] } else { vec![] };
            // Larger files go through a partial file + atomic rename even when
            // new (unless --inplace): an interrupted in-place file sits under its
            // final name and could later be mistaken for complete by the quick
            // check. Small new files use the in-place fast-batch path instead
            // (written straight to their final path — fast on NFS, but not
            // atomically visible); this handle_file path is for the larger ones.
            self.set_inplace(idx, inplace);

            if inplace {
                ok(
                    self.dst.call(Request::Prepare {
                        path: job.dst.clone(),
                        size,
                        inplace: true,
                        from_final: false,
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
                        from_final: false,
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
                let ranges = if size > 0 {
                    self.diff_blocks(&job, Which::Final)?
                } else {
                    vec![]
                };
                if ranges.is_empty() && final_entry.as_ref().unwrap().size == size {
                    // Content identical: just fix up metadata (mode per rsync rules).
                    let mut meta = job.entry.meta();
                    meta.mode = self.create_mode(&job);
                    let flags = self.opts.flags | flags::MODE;
                    let errs = match ok(
                        self.dst.call(Request::Apply(vec![Op::SetMeta {
                            path: job.dst.clone(),
                            meta,
                            flags,
                        }]))?,
                        "setmeta",
                    )? {
                        Response::Applied(v) => v,
                        other => bail!("unexpected response {other:?}"),
                    };
                    if let Some(e) = errs.into_iter().flatten().next() {
                        bail!("{e}");
                    }
                    return Ok(vec![]);
                }
                ok(
                    self.dst.call(Request::Prepare {
                        path: job.dst.clone(),
                        size,
                        inplace: false,
                        from_final: true,
                        mode: self.create_mode(&job),
                    })?,
                    "prepare",
                )?;
                return Ok(ranges);
            }
            ok(
                self.dst.call(Request::Prepare {
                    path: job.dst.clone(),
                    size,
                    inplace: false,
                    from_final: false,
                    mode: self.create_mode(&job),
                })?,
                "prepare",
            )?;
            Ok(full())
        })();

        let ranges = match planned {
            Ok(r) => r,
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
        let metadata_only = ranges.is_empty()
            && to_send == 0
            && !inplace
            && matches!(
                self.sched.jobs.lock().unwrap()[idx].dst_entry,
                Some(Entry {
                    kind: Kind::File,
                    ..
                })
            )
            && !self.probe_left_partial(&job)?;

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
            None => {
                if metadata_only {
                    self.progress.files_total.fetch_sub(1, Relaxed);
                    self.progress.files_skipped.fetch_add(1, Relaxed);
                } else {
                    self.finish_file(idx)?;
                }
            }
        }
        Ok(())
    }

    /// Whether a partial file exists for this job on the destination.
    fn probe_left_partial(&mut self, job: &FileJob) -> Result<bool> {
        match ok(
            self.dst.call(Request::Probe {
                path: job.dst.clone(),
            })?,
            "probe",
        )? {
            Response::Probed { partial_size, .. } => Ok(partial_size.is_some()),
            other => bail!("unexpected response {other:?}"),
        }
    }

    /// Record the in-place decision on the job so every range worker and the
    /// finalize agree.
    fn set_inplace(&self, idx: usize, v: bool) {
        self.sched.jobs.lock().unwrap()[idx].inplace = v;
    }

    /// Attempt an in-kernel same-host copy. Ok(true) = done; Ok(false) =
    /// kernel can't offload, caller should stream; Err = real failure.
    fn try_copy_local(&mut self, idx: usize, job: &FileJob) -> Result<bool> {
        // If a partial exists, prefer the streaming path so its hash-based
        // resume reuses the bytes already on disk; copy_file_range would
        // discard them and recopy the whole file.
        let partial = match ok(
            self.dst.call(Request::Probe {
                path: job.dst.clone(),
            })?,
            "probe",
        )? {
            Response::Probed { partial_size, .. } => partial_size.is_some(),
            _ => false,
        };
        if partial {
            return Ok(false);
        }
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
                self.sched.ranges_ready(idx, vec![]);
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

    /// Hash blocks on both sides (in parallel) and return the ranges that differ.
    fn diff_blocks(&mut self, job: &FileJob, which: Which) -> Result<Vec<(u64, u64)>> {
        let block = self.opts.block;
        let size = job.entry.size;
        self.src.send(Request::HashBlocks {
            path: job.src.clone(),
            which: Which::Final,
            block,
            len: size,
        })?;
        self.dst.send(Request::HashBlocks {
            path: job.dst.clone(),
            which,
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
        let n = size.div_ceil(block) as usize;
        let mut ranges: Vec<(u64, u64)> = Vec::new();
        for i in 0..n {
            let same = sh.get(i).is_some() && sh.get(i) == dh.get(i);
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
        Ok(ranges)
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

    /// Record a completed file in the resume journal (if active).
    fn record_done(&self, rel_bytes: &[u8], size: u64, mtime: i64, mtime_nsec: u32) {
        if let Some(rs) = self.resume.get() {
            if let Some(j) = &rs.journal {
                j.record_complete(rel_bytes, size, mtime, mtime_nsec, "transferred");
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
                meta,
                flags,
                fsync: self.opts.fsync,
            })?,
            "finalize",
        )?;
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
                        "pcp: {}: changed during transfer, retrying",
                        job.rel
                    ));
                    let mut jobs = self.sched.jobs.lock().unwrap();
                    let j = &mut jobs[idx];
                    self.progress.bytes_total.fetch_add(e.size, Relaxed);
                    j.entry = Entry {
                        path: j.entry.path.clone(),
                        ..e
                    };
                    j.attempts += 1;
                    // Keep the original dst_entry: it drives mode preservation
                    // without -p, and re-reading the source must not change it.
                    j.done.store(0, Relaxed);
                    drop(jobs);
                    self.sched.requeue(idx);
                    return Ok(());
                }
            }
            bail!("source changed during transfer (or vanished)");
        }
        self.progress.files_done.fetch_add(1, Relaxed);
        self.record_done(
            &job.rel_bytes,
            job.entry.size,
            job.entry.mtime,
            job.entry.mtime_nsec,
        );
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

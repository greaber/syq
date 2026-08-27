//! The orchestrator: scan, diff, schedule, and the per-worker transfer loop.

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
    /// --delete: remove destination paths the source doesn't have (see Planner::plan_deletes).
    pub delete: bool,
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
            pcp_path: args.pcp_path.clone(),
            quiet: args.quiet,
            tcp: Default::default(),
        }),
    })
}

pub fn connect_ctl(ep: &Endpoint, args: &Args) -> Result<Box<dyn Conn>> {
    match ep.connect(args.compress) {
        Ok(c) => Ok(c),
        Err(e) => {
            if let (Endpoint::Remote(spec), true) = (ep, args.bootstrap) {
                eprintln!("pcp: {e:#}");
                spec.bootstrap()?;
                return ep.connect(args.compress);
            }
            Err(e)
        }
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
        delete: args.delete,
        update: args.update,
        ignore_existing: args.ignore_existing,
        existing: args.existing,
        max_size: args.max_size.as_deref().map(parse_size).transpose()?,
        min_size: args.min_size.as_deref().map(parse_size).transpose()?,
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

    // Workers connect on their own threads, in parallel with the control
    // connections below, so all ssh sessions come up at once.
    let mut workers: Vec<std::thread::JoinHandle<Result<()>>> = Vec::new();
    let spawn_workers = |workers: &mut Vec<std::thread::JoinHandle<Result<()>>>| {
        for id in 0..args.connections {
            let (src_ep, dst_ep, sched, progress, opts) = (
                src_ep.clone(),
                dst_ep.clone(),
                sched.clone(),
                progress.clone(),
                opts.clone(),
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
    if !opts.dry_run && !args.bootstrap && !use_tcp {
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
    if !opts.dry_run && (args.bootstrap || use_tcp) {
        spawn_workers(&mut workers);
    }

    let dst_root = dst.path.as_bytes().to_vec();
    let dst_root_entry = stat_one(&mut *dst_ctl, &dst_root, false)?;
    let dst_is_dir = match &dst_root_entry {
        Some(e) if e.kind == Kind::Dir => true,
        Some(_) if srcs.len() > 1 => {
            bail!("destination must be a directory when copying multiple sources")
        }
        Some(_) => false,
        None => srcs.len() > 1 || dst.copies_contents() || args.files_from.is_some(),
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
            let src_is_dir = matches!(stat_one(&mut *src_ctl, s.path.as_bytes(), false)?, Some(ref e) if e.kind == Kind::Dir);
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

    if dst_root_entry.is_none() && dst_is_dir && !args.dry_run && !args.existing {
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

    let ticker = progress.spawn_ticker();

    let mut st = Planner {
        dst: &mut *dst_ctl,
        sched: &sched,
        progress: &progress,
        opts: &opts,
        dst_seen: std::collections::HashMap::new(),
        missing_dirs: std::collections::HashSet::new(),
        excluded: std::collections::HashSet::new(),
        collision: false,
        deferred: Vec::new(),
        dirs_created: 0,
        links_created: 0,
        specials_created: 0,
        scan_warned: false,
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
    let mut deleted = 0u64;
    // --delete runs once the workers are done, so the destination walk sees a
    // quiescent tree (no partials being renamed, no entries being replaced),
    // and before apply_deferred, since unlinking bumps directory mtimes. Any
    // source-side scan problem disables deletion: a directory we couldn't
    // read would otherwise look like one whose contents vanished.
    if !aborted && opts.delete && scan_err.is_none() && !collision {
        if st.scan_warned {
            progress.eprintln("pcp: source scan reported errors; skipping deletions");
        } else {
            match st.plan_deletes() {
                Ok(()) => deleted = st.run_deletes(&sched.failed_dsts())?,
                Err(e) => progress.error(&format!("pcp: delete: {e:#}")),
            }
        }
    }
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
                "pcp: {} {} files ({}), {} unchanged ({} files), {} dirs{}{}{}",
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
                "  scanned entries: {}\n  files to transfer: {}\n  files unchanged: {}\n  files excluded: {}\n  bytes transferred: {}\n  bytes unchanged: {}\n  elapsed: {:.2}s",
                commas(progress.scanned.load(Relaxed)),
                commas(progress.files_total.load(Relaxed)),
                commas(progress.files_skipped.load(Relaxed)),
                commas(progress.files_excluded.load(Relaxed)),
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
    p.scanned.load(Relaxed).saturating_sub(
        p.files_total.load(Relaxed)
            + p.files_skipped.load(Relaxed)
            + p.files_excluded.load(Relaxed),
    )
}

fn stat_one(conn: &mut dyn Conn, path: &[u8], follow: bool) -> Result<Option<Entry>> {
    match ok(
        conn.call(Request::StatMany {
            paths: vec![path.to_vec()],
            follow,
        })?,
        "stat",
    )? {
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
    /// Destination paths claimed by source entries (see `Claim`).
    dst_seen: std::collections::HashMap<PathBytes, Claim>,
    /// --existing: destination directories that don't exist (or aren't
    /// directories); nothing under them is touched.
    missing_dirs: std::collections::HashSet<PathBytes>,
    /// Destination files the source has but this run chose not to send (-u,
    /// size limits, --existing, ...); their partials are resume state, not garbage.
    excluded: std::collections::HashSet<PathBytes>,
    collision: bool,
    /// (dst path, meta, flags, depth) for directories, applied deepest-first at the end.
    deferred: Vec<(PathBytes, Meta, u8, usize)>,
    dirs_created: u64,
    links_created: u64,
    specials_created: u64,
    /// A source scan reported a non-fatal problem (unreadable directory, ...).
    scan_warned: bool,
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
/// an entry pcp will not transfer (a symlink without -l, a special file
/// without -D, an unknown type): it still marks the path as the source's —
/// so --delete leaves it alone — but yields to any real claim, so two
/// sources overlapping on such an entry are not a conflict.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Claim {
    Dir,
    Leaf,
    Weak,
}

/// pcp's own destination-session marker (see RESUME-DESIGN.md; the resume
/// implementation defines it as `resume::MARKER_NAME`). It lives in the
/// destination root and is never an extra to delete.
const RESUME_MARKER: &[u8] = b".pcp-transfer-session.json";

/// What --delete found on the destination that the source doesn't have.
#[derive(Default)]
struct Deletes {
    /// (path, display name) of files, symlinks and specials to unlink.
    leaves: Vec<(PathBytes, String)>,
    /// Directories by depth, removed deepest-first once they are empty.
    dirs: std::collections::BTreeMap<usize, Vec<(PathBytes, String)>>,
    /// (partial path, final path, display name): stale unless the final path
    /// failed this run (then it is the resume state for the retry).
    partials: Vec<(PathBytes, PathBytes, String)>,
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
        let warned = std::cell::Cell::new(false);
        let mut skip_all = false;
        let res = src.scan(
            src_root,
            follow,
            &self.opts.ignore,
            false,
            &mut |batch: Vec<Entry>| {
                if skip_all {
                    return Ok(());
                }
                if first {
                    first = false;
                    if let Some(root) = batch.first() {
                        if root.kind != Kind::Dir && !dst_is_dir {
                            sub = String::new();
                        }
                        if root.kind == Kind::Dir && !recursive {
                            progress.eprintln(&format!("skipping directory {}", display(src_root)));
                            skip_all = true;
                            return Ok(());
                        }
                        if root.kind == Kind::Dir {
                            self.delete_roots
                                .push((join(dst_root, sub.as_bytes()), sub.clone()));
                        }
                    }
                }
                progress.scanned.fetch_add(batch.len() as u64, Relaxed);
                self.handle_batch(batch, src_root, &sub, dst_root)
            },
            &mut |_| Ok(()),
            &mut |w| {
                warned.set(true);
                progress.error(&format!("pcp: {w}"))
            },
        );
        if warned.get() {
            self.scan_warned = true;
        }
        res
    }

    /// --files-from: instead of walking the source, stat each listed path (and
    /// the directories leading to it) and feed them to the planner as if a scan
    /// had produced them. Every ancestor must be a real directory: a symlink in
    /// the middle of a listed path would let the copy read outside the source
    /// root (and, mirrored on the destination, write outside it). Listed
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
        // Through a symlink: `pcp --files-from L link dst` should work like `link/`.
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
        let stat = |src: &mut dyn Conn,
                    paths: Vec<PathBytes>,
                    follow: bool|
         -> Result<Vec<Option<Entry>>> {
            if paths.is_empty() {
                return Ok(Vec::new());
            }
            match ok(
                src.call(Request::StatMany {
                    paths: paths.iter().map(|r| join(src_root, r)).collect(),
                    follow,
                })?,
                "stat",
            )? {
                Response::Stats(v) => Ok(v),
                other => bail!("unexpected response {other:?}"),
            }
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
                for anc in ancestors(line) {
                    match parents.get(&anc).and_then(|e| e.as_ref()) {
                        Some(e) if e.kind == Kind::Dir => match emitted.get(&anc) {
                            Some(Kind::Dir) => {}
                            Some(_) => {
                                self.progress.error(&format!(
                                    "pcp: --files-from: {shown}: {} was listed as a non-directory",
                                    display(&anc)
                                ));
                                continue 'line;
                            }
                            None => {
                                emitted.insert(anc.clone(), Kind::Dir);
                                batch.push(e.clone());
                            }
                        },
                        Some(_) => {
                            self.progress.error(&format!(
                                "pcp: --files-from: {shown}: {} is not a directory",
                                display(&anc)
                            ));
                            continue 'line;
                        }
                        None => {
                            self.progress.error(&format!(
                                "pcp: --files-from: {shown}: no such file or directory"
                            ));
                            continue 'line;
                        }
                    }
                }
                match leaves.get(line).and_then(|e| e.as_ref()) {
                    Some(e) => {
                        if e.kind == Kind::Dir && recurse && recursed.insert(line.clone()) {
                            subtrees.push(line.clone());
                        }
                        if !emitted.contains_key(line) {
                            emitted.insert(line.clone(), e.kind);
                            batch.push(e.clone());
                        }
                    }
                    None => self.progress.error(&format!(
                        "pcp: --files-from: {shown}: no such file or directory"
                    )),
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
        let progress = self.progress;
        let warned = std::cell::Cell::new(false);
        let res = src.scan(
            &join(src_root, rel),
            false,
            &[],
            false,
            &mut |batch: Vec<Entry>| {
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
                progress.scanned.fetch_add(batch.len() as u64, Relaxed);
                self.handle_batch(batch, src_root, "", dst_root)
            },
            &mut |_| Ok(()),
            &mut |w| {
                warned.set(true);
                progress.error(&format!("pcp: {w}"))
            },
        );
        if warned.get() {
            self.scan_warned = true;
        }
        res
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
        let mut others: Vec<(PathBytes, PathBytes, String, &Entry)> = Vec::new();
        for e in &batch {
            if e.kind == Kind::Dir && !opts.recursive && !self.keep_dirs {
                continue;
            }
            let dst_rel = join(sub_b, &e.path);
            let dst_path = join(dst_root, &dst_rel);
            let rel = if dst_rel.is_empty() {
                display(src_root.rsplit(|&c| c == b'/').next().unwrap_or(src_root))
            } else {
                display(&dst_rel)
            };
            // Every source entry claims its destination here, before any
            // decision about it: that blocks two sources from mapping onto one
            // path, and it is what makes --delete safe — whatever the arms
            // below decide (skip, filter, unsupported type, resumed from a
            // journal), a path the source has is never an extra.
            let partial_named = e.kind != Kind::Dir
                && crate::fsops::is_partial_name(std::ffi::OsStr::from_bytes(
                    e.path.rsplit(|&c| c == b'/').next().unwrap_or(&e.path),
                ));
            let transferable = match e.kind {
                Kind::Dir | Kind::File => !partial_named,
                Kind::Symlink => opts.links,
                Kind::Fifo | Kind::Socket | Kind::CharDev | Kind::BlockDev => opts.devices,
                Kind::Other => false,
            };
            let claim = match (e.kind, transferable) {
                (Kind::Dir, _) => Claim::Dir,
                (_, true) => Claim::Leaf,
                (_, false) => Claim::Weak,
            };
            if !self.claim_dst(&dst_path, &rel, claim) {
                continue;
            }
            if e.kind == Kind::Dir {
                mkdirs.push(Op::Mkdir {
                    path: dst_path.clone(),
                    mode: e.mode,
                });
                dir_entries.push((dst_path, e));
            } else if partial_named {
                // pcp's own leftovers are never copied; claimed above, so a
                // same-named file on the destination is not an extra either.
                self.progress.files_excluded.fetch_add(1, Relaxed);
            } else {
                others.push((join(src_root, &e.path), dst_path, rel, e));
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
            if opts.existing {
                // Don't create missing directories; their contents are skipped
                // too, since every path under them is missing on the destination.
                // A non-directory there is "missing" too: creating the directory
                // would mean unlinking it.
                // Entries come parent-first, so a directory below one we just
                // marked missing is seen after it. (A destination symlink to a
                // directory counts as missing: we won't replace it, and we
                // won't write through it either.)
                let mut missing: Vec<bool> = Vec::with_capacity(stats.len());
                for ((p, _), s) in dir_entries.iter().zip(&stats) {
                    let m = !matches!(s, Some(e) if e.kind == Kind::Dir)
                        || self.under_missing_dir(p, dst_root);
                    if m {
                        self.missing_dirs.insert(p.clone());
                    }
                    missing.push(m);
                }
                let mut i = 0;
                dir_entries.retain(|_| {
                    i += 1;
                    !missing[i - 1]
                });
                i = 0;
                mkdirs.retain(|_| {
                    i += 1;
                    !missing[i - 1]
                });
            }
            let stats: Vec<&Option<Entry>> = stats
                .iter()
                .filter(|s| !opts.existing || matches!(s, Some(e) if e.kind == Kind::Dir))
                .collect();
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
        } else if opts.dry_run && (opts.verbose > 0 || opts.existing) && !dir_entries.is_empty() {
            // --existing creates nothing, so only list directories that exist
            // (and remember the others, so their contents are skipped too).
            let stats: Vec<Option<Entry>> = if opts.existing {
                self.stat_many(true, dir_entries.iter().map(|(p, _)| p.clone()).collect())?
            } else {
                Vec::new()
            };
            for (i, (p, _)) in dir_entries.iter().enumerate() {
                let ok = !opts.existing
                    || (matches!(stats[i], Some(ref e) if e.kind == Kind::Dir)
                        && !self.under_missing_dir(p, dst_root));
                if ok && opts.verbose > 0 {
                    self.progress.println(&format!("{}/", display(p)));
                } else if !ok {
                    self.missing_dirs.insert(p.clone());
                }
            }
        }

        if others.is_empty() {
            return Ok(());
        }
        let stats = self.stat_many(true, others.iter().map(|(_, d, _, _)| d.clone()).collect())?;
        let mut ops: Vec<Op> = Vec::new();
        let mut op_names: Vec<String> = Vec::new();
        let mut meta_fixes: Vec<Op> = Vec::new();
        for ((src_path, dst_path, rel, e), dst_entry) in others.into_iter().zip(stats) {
            if opts.existing && self.under_missing_dir(&dst_path, dst_root) {
                // Below a directory we won't create: nothing to do, even if the
                // destination has something reachable there through a symlink.
                self.excluded.insert(dst_path);
                self.progress.files_excluded.fetch_add(1, Relaxed);
                continue;
            }
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
                        self.progress.files_excluded.fetch_add(1, Relaxed);
                        // Nothing will be written here; let another source have it.
                        self.dst_seen.insert(dst_path, Claim::Weak);
                        continue;
                    }
                    if opts.max_size.is_some_and(|m| e.size > m)
                        || opts.min_size.is_some_and(|m| e.size < m)
                        || self.skip_existing(&dst_entry)
                    {
                        self.progress.files_excluded.fetch_add(1, Relaxed);
                        self.excluded.insert(dst_path);
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
                    if dst_newer && !opts.verify_only {
                        self.progress.files_excluded.fetch_add(1, Relaxed);
                        self.excluded.insert(dst_path);
                        continue;
                    }
                    if opts.verify_only {
                        if dst_entry.as_ref().is_some_and(|d| d.kind == Kind::File) {
                            self.enqueue(
                                src_path.clone(),
                                dst_path.clone(),
                                rel.clone(),
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
                    } else if opts.dry_run {
                        self.progress.files_total.fetch_add(1, Relaxed);
                        self.progress.bytes_total.fetch_add(e.size, Relaxed);
                        self.progress.files_done.fetch_add(1, Relaxed);
                        if opts.verbose > 0 {
                            self.progress.println(&rel);
                        }
                    } else {
                        self.enqueue(src_path, dst_path, rel, e.clone(), dst_entry);
                    }
                }
                Kind::Symlink => {
                    if !opts.links {
                        if opts.verbose > 0 {
                            self.progress
                                .eprintln(&format!("skipping non-regular file \"{rel}\""));
                        }
                        self.progress.files_excluded.fetch_add(1, Relaxed);
                        continue;
                    }
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
                    if !opts.devices {
                        if opts.verbose > 0 {
                            self.progress
                                .eprintln(&format!("skipping non-regular file \"{rel}\""));
                        }
                        self.progress.files_excluded.fetch_add(1, Relaxed);
                        continue;
                    }
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
                Kind::Other => {
                    // Unknown type: never transferred (claimed above).
                    self.progress.files_excluded.fetch_add(1, Relaxed);
                }
                Kind::Dir => {}
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
    fn claim_dst(&mut self, dst: &PathBytes, rel: &str, claim: Claim) -> bool {
        match (self.dst_seen.get(dst), claim) {
            (Some(Claim::Dir), Claim::Dir) | (Some(_), Claim::Weak) => true,
            (Some(Claim::Weak), c) => {
                self.dst_seen.insert(dst.clone(), c);
                true
            }
            (Some(_), _) => {
                self.progress.error(&format!(
                    "pcp: {rel}: two sources map to the same destination {} with conflicting types — refusing to clobber it",
                    display(dst)
                ));
                self.collision = true;
                false
            }
            (None, c) => {
                self.dst_seen.insert(dst.clone(), c);
                true
            }
        }
    }

    /// --existing: is some directory between the destination root and `dst`
    /// one we decided not to create?
    fn under_missing_dir(&self, dst: &[u8], dst_root: &[u8]) -> bool {
        if self.missing_dirs.is_empty() {
            return false;
        }
        // The root itself may be the missing one (e.g. a symlink to a
        // directory elsewhere, which we must neither replace nor write through).
        if self.missing_dirs.contains(dst_root) {
            return true;
        }
        let mut end = dst.len();
        while let Some(i) = dst[..end].iter().rposition(|&c| c == b'/') {
            if i <= dst_root.len() {
                break;
            }
            if self.missing_dirs.contains(&dst[..i]) {
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
        entry: Entry,
        dst_entry: Option<Entry>,
    ) {
        self.progress.files_total.fetch_add(1, Relaxed);
        self.progress.bytes_total.fetch_add(entry.size, Relaxed);
        self.sched.push_file(FileJob {
            src,
            dst,
            rel,
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
            // this one (`pcp --delete a b/ dst`: dst/a inside dst) is left to
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
            let ignore = self.opts.ignore.clone();
            let mut found = Deletes::default();
            // Destination directories that hold an ignored path, so must stay.
            let mut protected: std::collections::HashSet<PathBytes> =
                std::collections::HashSet::new();
            let seen = &self.dst_seen;
            // Destination directories whose path the source claims as a
            // non-directory (a file we chose not to send, a symlink skipped
            // without -l, ...). The source has that path, so pcp doesn't touch
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
                        if e.path == RESUME_MARKER
                            || nested.iter().any(|n| *n == full || inside(&full, n))
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
                        let rel = display(&join(sub.as_bytes(), &e.path));
                        let name = e.path.rsplit(|&c| c == b'/').next().unwrap_or(&e.path);
                        // Only a regular file can be pcp's leftover; a directory
                        // or symlink with that name is an ordinary extra.
                        if e.kind == Kind::File
                            && crate::fsops::is_partial_name(std::ffi::OsStr::from_bytes(name))
                        {
                            let target = crate::fsops::partial_target(&full);
                            found.partials.push((full, target, rel));
                        } else {
                            if e.kind == Kind::Dir {
                                let depth = full.iter().filter(|&&c| c == b'/').count();
                                found
                                    .dirs
                                    .entry(depth)
                                    .or_default()
                                    .push((full, format!("{rel}/")));
                            } else {
                                found.leaves.push((full, rel));
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
                &mut |w| self.progress.error(&format!("pcp: delete: {w}")),
            );
            res?;
            self.deletes.leaves.append(&mut found.leaves);
            self.deletes.partials.append(&mut found.partials);
            for (d, v) in found.dirs {
                for (path, rel) in v {
                    if protected.contains(&path) {
                        self.progress
                            .eprintln(&format!("pcp: not deleting {rel}: it holds ignored paths"));
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
    fn run_deletes(&mut self, failed: &[PathBytes]) -> Result<u64> {
        let opts = self.opts;
        let failed: std::collections::HashSet<&PathBytes> = failed.iter().collect();
        let mut leaves = std::mem::take(&mut self.deletes.leaves);
        // The walk ran after the transfer, so every partial still present is a
        // leftover — except those of files that failed this run or that a
        // filter kept us from sending: those are the resume state of a
        // transfer that hasn't happened yet.
        for (partial, target, rel) in std::mem::take(&mut self.deletes.partials) {
            if !failed.contains(&target) && !self.excluded.contains(&target) {
                leaves.push((partial, rel));
            }
        }
        let dirs = std::mem::take(&mut self.deletes.dirs);
        let mut n = 0u64;
        let mut run = |me: &mut Self, items: &[(PathBytes, String)], rmdir: bool| -> Result<()> {
            for chunk in items.chunks(1000) {
                if opts.dry_run {
                    for (_, rel) in chunk {
                        n += 1;
                        if opts.verbose > 0 {
                            me.progress.println(&format!("deleting {rel}"));
                        }
                    }
                    continue;
                }
                let ops: Vec<Op> = chunk
                    .iter()
                    .map(|(p, _)| {
                        if rmdir {
                            Op::Rmdir { path: p.clone() }
                        } else {
                            Op::Remove { path: p.clone() }
                        }
                    })
                    .collect();
                for ((_, rel), err) in chunk.iter().zip(me.apply(true, ops)?) {
                    match err {
                        None => {
                            n += 1;
                            if opts.verbose > 0 {
                                me.progress.println(&format!("deleting {rel}"));
                            }
                        }
                        Some(e) => me.progress.error(&format!("pcp: delete {rel}: {e}")),
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

    fn stat_many(&mut self, _on_dst: bool, paths: Vec<PathBytes>) -> Result<Vec<Option<Entry>>> {
        match ok(
            self.dst.call(Request::StatMany {
                paths,
                follow: false,
            })?,
            "stat",
        )? {
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
                        batch.extend(self.sched.take_small(
                            self.opts.block,
                            FAST_BATCH_FILES,
                            FAST_BATCH_BYTES,
                        ));
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
            && j.entry.size <= self.opts.block
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
        if self.opts.same_host && !self.opts.checksum && job.entry.size > 0 {
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
        let block = self.opts.block;
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

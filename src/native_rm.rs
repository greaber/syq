//! Descriptor-rooted implementation of native `syq rm`.
//!
//! All operator selectors are resolved before the first mutation. Resolution
//! is a component walk rooted at an already-open directory; it never produces
//! a canonical pathname that is reopened later. The selected object and its
//! parent directory remain pinned while an endpoint-local worker pool removes
//! descendants relative to directory descriptors. Without source following,
//! a selected symlink and symlinks encountered below a selected directory are
//! unlinked as entries; neither is followed.

use crate::proto::{
    Kind, NativeRemoveDisposition, NativeRemoveErrorClass, NativeRemoveFailure, NativeRemoveKind,
    NativeRemoveOutcome, NativeRemoveSelection, OperatorSymlinkPolicy, PathBytes,
};
use crate::rooted::{
    OperatorFinalComponent, OperatorResolver, OperatorSymlinkHop, PinnedLeaf as RootedPinnedLeaf,
    PinnedPath, RootMetadata,
};
use anyhow::{bail, Context, Result};
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

const EVENT_BATCH: usize = 200;
const EVENT_POLL: Duration = Duration::from_millis(100);
const EVENT_FLUSH: Duration = Duration::from_millis(100);
const ATTACHED_HEARTBEAT: Duration = Duration::from_secs(1);
const RMDIR_RETRIES: usize = 3;
const REMOVE_QUARANTINE_ATTEMPTS: usize = 32;
const REMOVE_QUARANTINE_PREFIX: &[u8] = b".syq-remove-";
const REMOVE_QUARANTINE_ENTRY: &[u8] = b"candidate";
const REMOVE_QUARANTINE_ANCESTORS: usize = 1024;

#[cfg(target_os = "linux")]
const MODE_TYPE_MASK: u32 = libc::S_IFMT;
#[cfg(not(target_os = "linux"))]
const MODE_TYPE_MASK: u32 = libc::S_IFMT as u32;
#[cfg(target_os = "linux")]
const MODE_DIRECTORY: u32 = libc::S_IFDIR;
#[cfg(not(target_os = "linux"))]
const MODE_DIRECTORY: u32 = libc::S_IFDIR as u32;
#[cfg(target_os = "linux")]
const MODE_SYMLINK: u32 = libc::S_IFLNK;
#[cfg(not(target_os = "linux"))]
const MODE_SYMLINK: u32 = libc::S_IFLNK as u32;
#[cfg(target_os = "linux")]
const MODE_REGULAR: u32 = libc::S_IFREG;
#[cfg(not(target_os = "linux"))]
const MODE_REGULAR: u32 = libc::S_IFREG as u32;
#[cfg(target_os = "linux")]
const MODE_STICKY: u32 = libc::S_ISVTX;
#[cfg(not(target_os = "linux"))]
const MODE_STICKY: u32 = libc::S_ISVTX as u32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Identity {
    dev: u64,
    ino: u64,
    file_type: u32,
}

impl Identity {
    fn is_dir(self) -> bool {
        self.file_type == MODE_DIRECTORY
    }

    fn is_symlink(self) -> bool {
        self.file_type == MODE_SYMLINK
    }

    fn kind(self) -> Kind {
        match self.file_type {
            MODE_DIRECTORY => Kind::Dir,
            MODE_REGULAR => Kind::File,
            MODE_SYMLINK => Kind::Symlink,
            _ => Kind::Other,
        }
    }
}

struct PinnedName {
    parent: PinnedParent,
    name: CString,
    identity: Identity,
}

enum PinnedParent {
    File(File),
    Directory(Arc<DirectoryJob>),
}

impl PinnedParent {
    fn as_raw_fd(&self) -> RawFd {
        match self {
            Self::File(file) => file.as_raw_fd(),
            Self::Directory(job) => job.directory.as_raw_fd(),
        }
    }

    fn try_clone(&self) -> io::Result<File> {
        match self {
            Self::File(file) => file.try_clone(),
            Self::Directory(job) => job.directory.try_clone(),
        }
    }
}

struct PinnedLeaf {
    selector: u64,
    name: PinnedName,
    _object: Option<File>,
    label: PathBytes,
}

struct PinnedDirectory {
    selector: u64,
    directory: File,
    name: Option<PinnedName>,
    label: PathBytes,
    remove_root: bool,
}

enum ResolvedSelection {
    Missing,
    Leaf(PinnedLeaf),
    Directory(PinnedDirectory),
}

struct Resolver {
    resolver: OperatorResolver,
    confined: bool,
    follow: bool,
    symlink_policy: OperatorSymlinkPolicy,
}

impl Resolver {
    fn new(base: &File, confined: bool, follow: bool) -> Result<Self> {
        let symlink_policy = if follow {
            OperatorSymlinkPolicy::FollowAll
        } else {
            OperatorSymlinkPolicy::Refuse
        };
        Ok(Self {
            resolver: OperatorResolver::beneath(base, confined, symlink_policy)?,
            confined,
            follow,
            symlink_policy,
        })
    }

    fn resolve(
        &self,
        selector: u64,
        selection: &NativeRemoveSelection,
        traces: &mut Vec<String>,
    ) -> Result<ResolvedSelection> {
        validate_selector(&selection.path, self.confined)?;
        let label = selection.path.clone();
        let path = crate::fsops::resolve(&selection.path);
        let mut hops = Vec::new();
        let final_component = OperatorFinalComponent::Entry {
            follow_symlink: self.follow,
        };
        let resolved = if path.is_absolute() {
            OperatorResolver::resolve_process(
                path.as_os_str().as_bytes(),
                self.symlink_policy,
                final_component,
                true,
                &mut hops,
            )
        } else {
            self.resolver.resolve(
                path.as_os_str().as_bytes(),
                final_component,
                true,
                &mut hops,
            )
        };
        append_selector_hops(&selection.path, &hops, traces);
        let resolved = resolved.with_context(|| {
            format!(
                "resolve selector {:?}",
                String::from_utf8_lossy(&selection.path)
            )
        })?;

        match resolved {
            PinnedPath::Missing(_) => {
                traces.push(format!(
                    "selector {:?} is absent",
                    String::from_utf8_lossy(&label)
                ));
                Ok(ResolvedSelection::Missing)
            }
            PinnedPath::Leaf(leaf) => {
                let identity = identity_from_root(leaf.metadata());
                require_kind(selection.kind, identity, &label)?;
                traces.push(format!(
                    "selector {:?} resolved to {} {}:{}",
                    String::from_utf8_lossy(&label),
                    if identity.is_symlink() {
                        "symlink"
                    } else {
                        "non-directory"
                    },
                    identity.dev,
                    identity.ino
                ));
                let (name, object) = pinned_name_from_root(leaf);
                Ok(ResolvedSelection::Leaf(PinnedLeaf {
                    selector,
                    name,
                    _object: object,
                    label,
                }))
            }
            PinnedPath::Directory(directory) => {
                let identity = identity_from_root(directory.metadata());
                require_kind(selection.kind, identity, &label)?;
                let remove_root = selection.kind != NativeRemoveKind::Contents;
                let (directory, name) = directory.into_parts();
                let name = name.map(|name| pinned_name_from_root(name).0);
                if remove_root && name.is_none() {
                    bail!(
                        "selector {:?} resolves to a directory without a removable name; select its contents explicitly instead",
                        String::from_utf8_lossy(&label)
                    );
                }
                traces.push(format!(
                    "selector {:?} resolved to directory {}:{}",
                    String::from_utf8_lossy(&label),
                    identity.dev,
                    identity.ino
                ));
                Ok(ResolvedSelection::Directory(PinnedDirectory {
                    selector,
                    directory,
                    name,
                    label,
                    remove_root,
                }))
            }
            PinnedPath::OpenFile(_) => {
                unreachable!("removal selection never opens a procfs input")
            }
        }
    }
}

fn append_selector_hops(path: &[u8], hops: &[OperatorSymlinkHop], traces: &mut Vec<String>) {
    for hop in hops {
        traces.push(format!(
            "selector {:?}: symlink {:?} -> {:?}",
            String::from_utf8_lossy(path),
            String::from_utf8_lossy(&hop.component),
            String::from_utf8_lossy(&hop.target)
        ));
    }
}

fn pinned_name_from_root(leaf: RootedPinnedLeaf) -> (PinnedName, Option<File>) {
    let (parent, name, metadata, object) = leaf.into_parts();
    (
        PinnedName {
            parent: PinnedParent::File(parent),
            name,
            identity: identity_from_root(metadata),
        },
        object,
    )
}

fn identity_from_root(metadata: RootMetadata) -> Identity {
    Identity {
        dev: metadata.dev,
        ino: metadata.ino,
        file_type: metadata.file_type(),
    }
}

fn validate_selector(path: &[u8], confined: bool) -> Result<()> {
    if path.is_empty() {
        bail!("source selectors may not be empty");
    }
    if confined && (path.starts_with(b"/") || path == b"~" || path.starts_with(b"~/")) {
        bail!(
            "source selector {:?} beneath --root must be relative",
            String::from_utf8_lossy(path)
        );
    }
    if path.contains(&0) {
        bail!("source selector contains NUL");
    }
    Ok(())
}

fn require_kind(kind: NativeRemoveKind, identity: Identity, label: &[u8]) -> Result<()> {
    match kind {
        NativeRemoveKind::Contents | NativeRemoveKind::Directory if !identity.is_dir() => bail!(
            "selector {:?} must resolve to a directory",
            String::from_utf8_lossy(label)
        ),
        NativeRemoveKind::File if identity.is_dir() => bail!(
            "selector {:?} must resolve to a non-directory",
            String::from_utf8_lossy(label)
        ),
        _ => Ok(()),
    }
}

fn open_base(
    cwd: Option<&[u8]>,
    root: Option<&[u8]>,
    selections: &[NativeRemoveSelection],
    follow: bool,
    traces: &mut Vec<String>,
) -> Result<(File, bool)> {
    if cwd.is_some() && root.is_some() {
        bail!("--cwd and --root are mutually exclusive");
    }
    for (option, path) in [("--cwd", cwd), ("--root", root)] {
        if let Some(path) = path {
            if path.is_empty() {
                bail!("{option} may not be empty");
            }
            if path.contains(&0) {
                bail!("{option} contains NUL");
            }
        }
    }
    if root.is_none()
        && selections
            .iter()
            .all(|selection| crate::fsops::resolve(&selection.path).is_absolute())
    {
        let directory = resolve_base_path(b".", false, "endpoint working directory", traces)?;
        let identity = identity_from_file(&directory)?;
        traces.push(format!(
            "endpoint working directory pinned as {}:{}",
            identity.dev, identity.ino
        ));
        return Ok((directory, false));
    }
    if let Some(path) = root {
        let directory = resolve_base_path(path, follow, "--root", traces)?;
        let identity = identity_from_file(&directory)?;
        traces.push(format!(
            "--root {:?} pinned as {}:{}",
            String::from_utf8_lossy(path),
            identity.dev,
            identity.ino
        ));
        return Ok((directory, true));
    }
    if let Some(path) = cwd {
        let directory = resolve_base_path(path, follow, "--cwd", traces)?;
        let identity = identity_from_file(&directory)?;
        traces.push(format!(
            "--cwd {:?} pinned as {}:{}",
            String::from_utf8_lossy(path),
            identity.dev,
            identity.ino
        ));
        return Ok((directory, false));
    }
    let directory = resolve_base_path(b".", false, "endpoint working directory", traces)?;
    let identity = identity_from_file(&directory)?;
    traces.push(format!(
        "endpoint working directory pinned as {}:{}",
        identity.dev, identity.ino
    ));
    Ok((directory, false))
}

fn resolve_base_path(
    path: &[u8],
    follow: bool,
    option: &str,
    traces: &mut Vec<String>,
) -> Result<File> {
    if path.is_empty() {
        bail!("{option} may not be empty");
    }
    if path.contains(&0) {
        bail!("{option} contains NUL");
    }
    let path = crate::fsops::resolve(path);
    let mut hops = Vec::new();
    let selected = OperatorResolver::resolve_process(
        path.as_os_str().as_bytes(),
        if follow {
            OperatorSymlinkPolicy::FollowAll
        } else {
            OperatorSymlinkPolicy::Refuse
        },
        OperatorFinalComponent::Directory,
        false,
        &mut hops,
    );
    for hop in &hops {
        traces.push(format!(
            "{option} {:?}: symlink {:?} -> {:?}",
            path.display(),
            String::from_utf8_lossy(&hop.component),
            String::from_utf8_lossy(&hop.target)
        ));
    }
    let selected = selected.with_context(|| format!("resolve {option} {}", path.display()))?;
    let PinnedPath::Directory(directory) = selected else {
        bail!("{option} {} is not a directory", path.display());
    };
    Ok(directory.into_parts().0)
}

struct DirectoryJob {
    selector: u64,
    directory: File,
    removal: Option<PinnedName>,
    label: PathBytes,
    parent: Option<Arc<DirectoryJob>>,
    remaining: AtomicUsize,
    retries: AtomicUsize,
    descendant_failed: AtomicBool,
}

enum Task {
    Scan(Arc<DirectoryJob>),
    Leaf {
        selector: u64,
        name: PinnedName,
        _object: Option<File>,
        label: PathBytes,
        parent: Option<Arc<DirectoryJob>>,
    },
    Finish(Arc<DirectoryJob>),
}

struct Pool {
    sender: Mutex<Option<mpsc::SyncSender<Task>>>,
    pending: Mutex<usize>,
    events: mpsc::Sender<NativeRemoveOutcome>,
    dry_run: bool,
    cancelled: AtomicBool,
}

impl Pool {
    fn submit(self: &Arc<Self>, task: Task) {
        *self.pending.lock().unwrap() += 1;
        let queued = self
            .sender
            .lock()
            .unwrap()
            .as_ref()
            .map(|sender| sender.try_send(task));
        match queued {
            Some(Ok(())) => return,
            Some(Err(mpsc::TrySendError::Full(task)))
            | Some(Err(mpsc::TrySendError::Disconnected(task))) => {
                process_task(self, task);
            }
            None => unreachable!("native removal submitted work after shutdown"),
        }
        self.task_done();
    }

    fn task_done(&self) {
        let mut pending = self.pending.lock().unwrap();
        *pending -= 1;
    }

    fn is_done(&self) -> bool {
        *self.pending.lock().unwrap() == 0
    }

    fn close(&self) {
        self.sender.lock().unwrap().take();
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    fn outcome(&self, outcome: NativeRemoveOutcome) {
        if !self.is_cancelled() {
            let _ = self.events.send(outcome);
        }
    }
}

fn removal_failure(error: anyhow::Error) -> NativeRemoveFailure {
    let wire = crate::fsops::wire_error(&error);
    let class = if wire.io_kind.is_some() {
        NativeRemoveErrorClass::Io
    } else {
        // The only settled removal failures without an underlying OS error
        // are pinned-identity and type conflicts caused by namespace races.
        NativeRemoveErrorClass::Conflict
    };
    NativeRemoveFailure { error: wire, class }
}

fn failed_outcome(
    selector: u64,
    path: PathBytes,
    kind: Option<Kind>,
    attempts: u64,
    error: anyhow::Error,
) -> NativeRemoveOutcome {
    NativeRemoveOutcome {
        selector,
        path,
        kind,
        disposition: NativeRemoveDisposition::Failed,
        attempts: Some(attempts),
        failure: Some(removal_failure(error)),
    }
}

fn endpoint_failure(error: anyhow::Error) -> anyhow::Error {
    anyhow::Error::new(crate::fsops::wire_error(&error))
}

fn removal_outcome(
    selector: u64,
    path: PathBytes,
    kind: Kind,
    disposition: NativeRemoveDisposition,
    attempts: Option<u64>,
) -> NativeRemoveOutcome {
    NativeRemoveOutcome {
        selector,
        path,
        kind: Some(kind),
        disposition,
        attempts,
        failure: None,
    }
}

fn emit_attached(
    pool: &Pool,
    batch: &mut Vec<NativeRemoveOutcome>,
    sink: &mut dyn FnMut(Vec<NativeRemoveOutcome>) -> Result<()>,
) -> Result<()> {
    let ready = std::mem::replace(batch, Vec::with_capacity(EVENT_BATCH));
    if let Err(error) = sink(ready) {
        pool.cancel();
        return Err(error);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn remove(
    cwd: Option<&[u8]>,
    root: Option<&[u8]>,
    selections: &[NativeRemoveSelection],
    follow_symlinks: bool,
    dry_run: bool,
    workers: usize,
    trace: &mut dyn FnMut(Vec<String>) -> Result<()>,
    sink: &mut dyn FnMut(Vec<NativeRemoveOutcome>) -> Result<()>,
) -> Result<()> {
    let mut traces = Vec::new();
    let (base, confined) =
        open_base(cwd, root, selections, follow_symlinks, &mut traces).map_err(endpoint_failure)?;
    let resolver = Resolver::new(&base, confined, follow_symlinks).map_err(endpoint_failure)?;

    // This phase is deliberately complete before the worker pool starts: a
    // later selector can never acquire a new meaning because an earlier one
    // has already changed the namespace.
    let mut resolved = Vec::with_capacity(selections.len());
    let mut selection_outcomes = Vec::with_capacity(selections.len());
    for (index, selection) in selections.iter().enumerate() {
        let selector = index as u64;
        let resolution = match resolver.resolve(selector, selection, &mut traces) {
            Ok(resolution) => resolution,
            Err(error) => {
                if !traces.is_empty() {
                    trace(std::mem::take(&mut traces))?;
                }
                if !selection_outcomes.is_empty() {
                    sink(std::mem::take(&mut selection_outcomes))?;
                }
                return Err(endpoint_failure(error));
            }
        };
        match resolution {
            ResolvedSelection::Missing => selection_outcomes.push(NativeRemoveOutcome {
                selector,
                path: selection.path.clone(),
                kind: None,
                disposition: NativeRemoveDisposition::Missing,
                attempts: None,
                failure: None,
            }),
            selected => {
                let kind = match &selected {
                    ResolvedSelection::Leaf(leaf) => leaf.name.identity.kind(),
                    ResolvedSelection::Directory(_) => Kind::Dir,
                    ResolvedSelection::Missing => unreachable!(),
                };
                selection_outcomes.push(NativeRemoveOutcome {
                    selector,
                    path: selection.path.clone(),
                    kind: Some(kind),
                    disposition: NativeRemoveDisposition::Resolved,
                    attempts: None,
                    failure: None,
                });
                resolved.push(selected);
            }
        }
    }
    if !traces.is_empty() {
        trace(traces)?;
    }
    sink(selection_outcomes)?;

    // Queue every resolved root before starting workers. Once workers run,
    // only they may take the bounded-queue inline fallback; the coordinator
    // remains available to flush results and detect connection failure.
    let queue_capacity = workers.max(1).saturating_mul(4).max(resolved.len()).max(1);
    let (task_tx, task_rx) = mpsc::sync_channel(queue_capacity);
    let (event_tx, event_rx) = mpsc::channel();
    let pool = Arc::new(Pool {
        sender: Mutex::new(Some(task_tx)),
        pending: Mutex::new(0),
        events: event_tx,
        dry_run,
        cancelled: AtomicBool::new(false),
    });
    for selected in resolved {
        match selected {
            ResolvedSelection::Missing => unreachable!(),
            ResolvedSelection::Leaf(leaf) => pool.submit(Task::Leaf {
                selector: leaf.selector,
                name: leaf.name,
                _object: leaf._object,
                label: leaf.label,
                parent: None,
            }),
            ResolvedSelection::Directory(directory) => {
                pool.submit(Task::Scan(Arc::new(DirectoryJob {
                    selector: directory.selector,
                    directory: directory.directory,
                    removal: directory.remove_root.then_some(directory.name).flatten(),
                    label: directory.label,
                    parent: None,
                    remaining: AtomicUsize::new(1),
                    retries: AtomicUsize::new(0),
                    descendant_failed: AtomicBool::new(false),
                })));
            }
        }
    }

    let task_rx = Arc::new(Mutex::new(task_rx));
    let mut threads = Vec::new();
    for _ in 0..workers.max(1) {
        let pool = pool.clone();
        let task_rx = task_rx.clone();
        threads.push(std::thread::spawn(move || worker_loop(pool, task_rx)));
    }

    let mut batch = Vec::with_capacity(EVENT_BATCH);
    let mut sink_error = None;
    let mut last_emit = Instant::now();
    while !pool.is_done() {
        match event_rx.recv_timeout(EVENT_POLL) {
            Ok(event) => {
                if sink_error.is_none() {
                    batch.push(event);
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
        if sink_error.is_none()
            && (batch.len() >= EVENT_BATCH
                || (!batch.is_empty() && last_emit.elapsed() >= EVENT_FLUSH)
                || last_emit.elapsed() >= ATTACHED_HEARTBEAT)
        {
            if let Err(error) = emit_attached(&pool, &mut batch, sink) {
                sink_error = Some(error);
            } else {
                last_emit = Instant::now();
            }
        }
    }
    while let Ok(event) = event_rx.try_recv() {
        if sink_error.is_none() {
            batch.push(event);
            if batch.len() >= EVENT_BATCH {
                if let Err(error) = emit_attached(&pool, &mut batch, sink) {
                    sink_error = Some(error);
                }
            }
        }
    }
    if !batch.is_empty() && sink_error.is_none() {
        if let Err(error) = emit_attached(&pool, &mut batch, sink) {
            sink_error = Some(error);
        }
    }
    pool.close();
    for thread in threads {
        if thread.join().is_err() && sink_error.is_none() {
            sink_error = Some(endpoint_failure(anyhow::anyhow!(
                "native removal worker panicked"
            )));
        }
    }
    if let Some(error) = sink_error {
        return Err(error);
    }
    Ok(())
}

fn worker_loop(pool: Arc<Pool>, receiver: Arc<Mutex<mpsc::Receiver<Task>>>) {
    loop {
        let task = match receiver.lock().unwrap().recv() {
            Ok(task) => task,
            Err(_) => return,
        };
        process_task(&pool, task);
        pool.task_done();
    }
}

fn process_task(pool: &Arc<Pool>, task: Task) {
    if pool.is_cancelled() {
        match task {
            Task::Scan(job) | Task::Finish(job) => abandon_directory(pool, &job),
            Task::Leaf { parent, .. } => {
                if let Some(parent) = parent {
                    directory_part_done(pool, parent);
                }
            }
        }
        return;
    }
    match task {
        Task::Scan(job) => scan_directory(pool, job),
        Task::Leaf {
            selector,
            name,
            _object,
            label,
            parent,
        } => {
            if pool.is_cancelled() {
                if let Some(parent) = parent {
                    directory_part_done(pool, parent);
                }
                return;
            }
            let kind = name.identity.kind();
            let outcome = if pool.dry_run {
                removal_outcome(
                    selector,
                    label,
                    kind,
                    NativeRemoveDisposition::WouldRemove,
                    None,
                )
            } else {
                match remove_pinned(&name, false) {
                    Ok(RemovePinnedOutcome::Removed) => removal_outcome(
                        selector,
                        label,
                        kind,
                        NativeRemoveDisposition::Removed,
                        Some(1),
                    ),
                    Ok(RemovePinnedOutcome::AlreadyAbsent) => removal_outcome(
                        selector,
                        label,
                        kind,
                        NativeRemoveDisposition::AlreadyAbsent,
                        Some(1),
                    ),
                    Err(error) => failed_outcome(selector, label, Some(kind), 1, error),
                }
            };
            let failed = outcome.disposition == NativeRemoveDisposition::Failed;
            pool.outcome(outcome);
            if let Some(parent) = parent {
                if failed {
                    directory_part_failed(pool, parent);
                } else {
                    directory_part_done(pool, parent);
                }
            }
        }
        Task::Finish(job) => finish_directory(pool, job),
    }
}

fn scan_directory(pool: &Arc<Pool>, job: Arc<DirectoryJob>) {
    let names = match read_directory(&job.directory) {
        Ok(names) => names,
        Err(error) => {
            pool.outcome(failed_outcome(
                job.selector,
                job.label.clone(),
                Some(Kind::Dir),
                job.retries.load(Ordering::SeqCst) as u64 + 1,
                error,
            ));
            finish_parent(pool, &job, true);
            return;
        }
    };
    for component in names {
        if pool.is_cancelled() {
            break;
        }
        let identity = match metadata_at(job.directory.as_raw_fd(), &component) {
            Ok(identity) => identity,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                job.descendant_failed.store(true, Ordering::SeqCst);
                pool.outcome(failed_outcome(
                    job.selector,
                    join_label(&job.label, &component),
                    None,
                    1,
                    error.into(),
                ));
                continue;
            }
        };
        let name = match component_cstring(&component) {
            Ok(name) => name,
            Err(error) => {
                job.descendant_failed.store(true, Ordering::SeqCst);
                pool.outcome(failed_outcome(
                    job.selector,
                    join_label(&job.label, &component),
                    Some(identity.kind()),
                    1,
                    error,
                ));
                continue;
            }
        };
        let pinned = PinnedName {
            parent: PinnedParent::Directory(job.clone()),
            name,
            identity,
        };
        let label = join_label(&job.label, &component);
        job.remaining.fetch_add(1, Ordering::SeqCst);
        if identity.is_dir() {
            let directory = match open_directory_at(&job.directory, &component) {
                Ok(directory) => directory,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    directory_part_done(pool, job.clone());
                    continue;
                }
                Err(error) => {
                    pool.outcome(failed_outcome(
                        job.selector,
                        label,
                        Some(Kind::Dir),
                        1,
                        error.into(),
                    ));
                    directory_part_failed(pool, job.clone());
                    continue;
                }
            };
            match identity_from_file(&directory)
                .and_then(|opened| require_same_identity(identity, opened, "directory"))
            {
                Ok(()) => pool.submit(Task::Scan(Arc::new(DirectoryJob {
                    selector: job.selector,
                    directory,
                    removal: Some(pinned),
                    label,
                    parent: Some(job.clone()),
                    remaining: AtomicUsize::new(1),
                    retries: AtomicUsize::new(0),
                    descendant_failed: AtomicBool::new(false),
                }))),
                Err(error) => {
                    pool.outcome(failed_outcome(
                        job.selector,
                        label,
                        Some(Kind::Dir),
                        1,
                        error,
                    ));
                    directory_part_failed(pool, job.clone());
                }
            }
        } else {
            pool.submit(Task::Leaf {
                selector: job.selector,
                name: pinned,
                _object: None,
                label,
                parent: Some(job.clone()),
            });
        }
    }
    directory_part_done(pool, job);
}

fn finish_directory(pool: &Arc<Pool>, job: Arc<DirectoryJob>) {
    if pool.is_cancelled() {
        abandon_directory(pool, &job);
        return;
    }
    let Some(removal) = &job.removal else {
        finish_parent(pool, &job, job.descendant_failed.load(Ordering::SeqCst));
        return;
    };
    let result = if pool.dry_run {
        Ok(RemovePinnedOutcome::Removed)
    } else {
        remove_pinned(removal, true)
    };
    match result {
        Ok(outcome) => {
            let disposition = if pool.dry_run {
                NativeRemoveDisposition::WouldRemove
            } else {
                match outcome {
                    RemovePinnedOutcome::Removed => NativeRemoveDisposition::Removed,
                    RemovePinnedOutcome::AlreadyAbsent => NativeRemoveDisposition::AlreadyAbsent,
                }
            };
            pool.outcome(removal_outcome(
                job.selector,
                job.label.clone(),
                Kind::Dir,
                disposition,
                (!pool.dry_run).then(|| job.retries.load(Ordering::SeqCst) as u64 + 1),
            ));
            finish_parent(pool, &job, job.descendant_failed.load(Ordering::SeqCst));
        }
        Err(error)
            if is_directory_not_empty(&error) && !job.descendant_failed.load(Ordering::SeqCst) =>
        {
            let previous_failures = job.retries.fetch_add(1, Ordering::SeqCst);
            if previous_failures < RMDIR_RETRIES {
                job.remaining.store(1, Ordering::SeqCst);
                pool.submit(Task::Scan(job));
            } else {
                pool.outcome(failed_outcome(
                    job.selector,
                    job.label.clone(),
                    Some(Kind::Dir),
                    previous_failures as u64 + 1,
                    error,
                ));
                finish_parent(pool, &job, true);
            }
        }
        Err(error) => {
            pool.outcome(failed_outcome(
                job.selector,
                job.label.clone(),
                Some(Kind::Dir),
                job.retries.load(Ordering::SeqCst) as u64 + 1,
                error,
            ));
            finish_parent(pool, &job, true);
        }
    }
}

fn abandon_directory(pool: &Arc<Pool>, job: &Arc<DirectoryJob>) {
    finish_parent(pool, job, false);
}

fn finish_parent(pool: &Arc<Pool>, job: &DirectoryJob, failed: bool) {
    if let Some(parent) = &job.parent {
        if failed {
            directory_part_failed(pool, parent.clone());
        } else {
            directory_part_done(pool, parent.clone());
        }
    }
}

fn directory_part_failed(pool: &Arc<Pool>, job: Arc<DirectoryJob>) {
    job.descendant_failed.store(true, Ordering::SeqCst);
    directory_part_done(pool, job);
}

fn directory_part_done(pool: &Arc<Pool>, job: Arc<DirectoryJob>) {
    if job.remaining.fetch_sub(1, Ordering::SeqCst) == 1 {
        pool.submit(Task::Finish(job));
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RemovePinnedOutcome {
    Removed,
    AlreadyAbsent,
}

fn remove_pinned(name: &PinnedName, directory: bool) -> Result<RemovePinnedOutcome> {
    remove_pinned_with_hook(name, directory, |_, _| Ok(()))
}

fn remove_pinned_with_hook(
    name: &PinnedName,
    directory: bool,
    after_quarantine: impl FnOnce(&RemovalQuarantine, &CString) -> Result<()>,
) -> Result<RemovePinnedOutcome> {
    // POSIX has no identity-conditioned unlink. Move the currently named
    // entry into an owner-only directory in a trusted ancestor on the same
    // filesystem, then authenticate and remove it there. An untrusted writer
    // cannot address the quarantined name, and a later object installed at the
    // operator-visible name is never addressed by the final unlink.
    let mut quarantine = RemovalQuarantine::create(&name.parent)?;
    let candidate = component_cstring(REMOVE_QUARANTINE_ENTRY)?;
    #[cfg(test)]
    tests::before_quarantine(name.parent.as_raw_fd(), &name.name);
    match rename_noreplace_at(
        name.parent.as_raw_fd(),
        &name.name,
        quarantine.directory.as_raw_fd(),
        &candidate,
    ) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            quarantine
                .cleanup()
                .context("remove empty removal quarantine")?;
            return Ok(RemovePinnedOutcome::AlreadyAbsent);
        }
        Err(error) => {
            let cause = anyhow::Error::new(error).context("quarantine pinned removal target");
            return Err(cleanup_quarantine_after_error(&mut quarantine, cause));
        }
    }
    if let Err(error) = after_quarantine(&quarantine, &candidate) {
        return Err(restore_or_preserve_quarantine(
            name,
            &mut quarantine,
            &candidate,
            error,
        ))
        .context("remove pinned object");
    }

    let current = match metadata_at_cstring(quarantine.directory.as_raw_fd(), &candidate) {
        Ok(current) => current,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let cause =
                anyhow::anyhow!("quarantined removal target disappeared before authentication");
            return Err(cleanup_quarantine_after_error(&mut quarantine, cause));
        }
        Err(error) => {
            return Err(restore_or_preserve_quarantine(
                name,
                &mut quarantine,
                &candidate,
                error.into(),
            ))
            .context("inspect quarantined removal target")
        }
    };
    if let Err(error) = require_same_identity(name.identity, current, "removal target") {
        return Err(restore_or_preserve_quarantine(
            name,
            &mut quarantine,
            &candidate,
            error,
        ))
        .context("remove pinned object");
    }

    let flags = if directory { libc::AT_REMOVEDIR } else { 0 };
    // SAFETY: `candidate` is a live CString and `quarantine.directory` is a
    // retained descriptor for an owner-only directory whose parent cannot be
    // renamed by an untrusted writer. The authenticated entry cannot be
    // replaced by the threat actor between this check and unlink.
    if let Err(error) = retry_zero(|| unsafe {
        libc::unlinkat(quarantine.directory.as_raw_fd(), candidate.as_ptr(), flags)
    }) {
        if error.kind() == io::ErrorKind::NotFound {
            let cause = anyhow::anyhow!("quarantined removal target disappeared before removal");
            return Err(cleanup_quarantine_after_error(&mut quarantine, cause));
        }
        return Err(restore_or_preserve_quarantine(
            name,
            &mut quarantine,
            &candidate,
            error.into(),
        ))
        .context("remove pinned object");
    }
    quarantine
        .cleanup()
        .context("remove empty removal quarantine")?;

    match metadata_at_cstring(name.parent.as_raw_fd(), &name.name) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(RemovePinnedOutcome::Removed),
        Ok(_) => bail!("removal target was replaced during removal"),
        Err(error) => Err(error).context("inspect removal name after quarantine"),
    }
}

struct RemovalQuarantine {
    parent: File,
    name: CString,
    directory: File,
    parent_hops: usize,
    cleanup_on_drop: bool,
}

impl RemovalQuarantine {
    fn create(source_parent: &PinnedParent) -> Result<Self> {
        let mut directory = source_parent
            .try_clone()
            .context("duplicate removal parent descriptor")?;
        let source_device = directory.metadata()?.dev();
        let effective_uid = effective_user_id();
        let mut last_create_error = None;

        for parent_hops in 0..REMOVE_QUARANTINE_ANCESTORS {
            let metadata = directory.metadata()?;
            if metadata.dev() != source_device {
                break;
            }
            if is_trusted_quarantine_parent(&metadata, effective_uid) {
                match Self::create_in(&directory, parent_hops, effective_uid) {
                    Ok(quarantine) => return Ok(quarantine),
                    Err(error)
                        if matches!(
                            error.raw_os_error(),
                            Some(errno)
                                if errno == libc::EACCES
                                    || errno == libc::EPERM
                                    || errno == libc::EROFS
                        ) =>
                    {
                        last_create_error = Some(error);
                    }
                    Err(error) => return Err(error).context("create removal quarantine"),
                }
            }

            let parent = open_directory_at(&directory, b"..")
                .context("walk to a trusted removal quarantine parent")?;
            let parent_metadata = parent.metadata()?;
            if parent_metadata.dev() != source_device
                || (parent_metadata.dev() == metadata.dev()
                    && parent_metadata.ino() == metadata.ino())
            {
                break;
            }
            directory = parent;
        }

        if let Some(error) = last_create_error {
            return Err(error).context(
                "no writable trusted ancestor can hold the removal quarantine on this filesystem",
            );
        }
        bail!("no trusted ancestor can hold the removal quarantine on this filesystem")
    }

    fn create_in(parent: &File, parent_hops: usize, effective_uid: u32) -> io::Result<Self> {
        for _ in 0..REMOVE_QUARANTINE_ATTEMPTS {
            let name = random_quarantine_name()?;
            // SAFETY: `name` is a live CString, `parent` is a retained
            // directory descriptor, and mode 0700 grants no group or other
            // access even before the process umask is applied.
            match retry_zero(|| unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) })
            {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }

            let setup = (|| -> io::Result<Self> {
                let opened = open_directory_at(parent, name.as_bytes())?;
                let named = metadata_at_cstring(parent.as_raw_fd(), &name)?;
                let opened_metadata = opened.metadata()?;
                let opened_identity = Identity {
                    dev: opened_metadata.dev(),
                    ino: opened_metadata.ino(),
                    file_type: opened_metadata.mode() & MODE_TYPE_MASK,
                };
                if named != opened_identity
                    || opened_metadata.uid() != effective_uid
                    || opened_metadata.mode() & 0o077 != 0
                {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "removal quarantine is not the new owner-only directory",
                    ));
                }
                Ok(Self {
                    parent: parent.try_clone()?,
                    name: name.clone(),
                    directory: opened,
                    parent_hops,
                    cleanup_on_drop: true,
                })
            })();
            match setup {
                Ok(quarantine) => return Ok(quarantine),
                Err(error) => {
                    if let Err(cleanup_error) = remove_directory_at(parent.as_raw_fd(), &name) {
                        return Err(io::Error::other(format!(
                            "{error}; could not remove invalid removal quarantine: {cleanup_error}"
                        )));
                    }
                    return Err(error);
                }
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a removal quarantine directory",
        ))
    }

    fn cleanup(&mut self) -> io::Result<()> {
        remove_directory_at(self.parent.as_raw_fd(), &self.name)?;
        self.cleanup_on_drop = false;
        Ok(())
    }

    fn preserve(&mut self) {
        self.cleanup_on_drop = false;
    }

    fn candidate_label(&self, candidate: &CString) -> String {
        let mut label = "../".repeat(self.parent_hops);
        label.push_str(&String::from_utf8_lossy(self.name.as_bytes()));
        label.push('/');
        label.push_str(&String::from_utf8_lossy(candidate.as_bytes()));
        label
    }
}

impl Drop for RemovalQuarantine {
    fn drop(&mut self) {
        if self.cleanup_on_drop {
            let _ = remove_directory_at(self.parent.as_raw_fd(), &self.name);
        }
    }
}

fn effective_user_id() -> u32 {
    // SAFETY: `geteuid` has no arguments and no safety preconditions.
    unsafe { libc::geteuid() }
}

fn is_trusted_quarantine_parent(metadata: &std::fs::Metadata, effective_uid: u32) -> bool {
    let owner_is_trusted = metadata.uid() == effective_uid || metadata.uid() == 0;
    let writable_by_others = metadata.mode() & 0o022 != 0;
    let sticky = metadata.mode() & MODE_STICKY != 0;
    owner_is_trusted && (!writable_by_others || sticky)
}

fn random_quarantine_name() -> io::Result<CString> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).map_err(io::Error::other)?;
    let mut name = Vec::with_capacity(REMOVE_QUARANTINE_PREFIX.len() + random.len() * 2);
    name.extend_from_slice(REMOVE_QUARANTINE_PREFIX);
    for byte in random {
        name.push(HEX[usize::from(byte >> 4)]);
        name.push(HEX[usize::from(byte & 0x0f)]);
    }
    CString::new(name).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "generated removal quarantine name contains NUL",
        )
    })
}

fn restore_or_preserve_quarantine(
    name: &PinnedName,
    quarantine: &mut RemovalQuarantine,
    candidate: &CString,
    cause: anyhow::Error,
) -> anyhow::Error {
    match rename_noreplace_at(
        quarantine.directory.as_raw_fd(),
        candidate,
        name.parent.as_raw_fd(),
        &name.name,
    ) {
        Ok(()) => cleanup_quarantine_after_error(quarantine, cause),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            cleanup_quarantine_after_error(quarantine, cause.context(error))
        }
        Err(error) => {
            let label = quarantine.candidate_label(candidate);
            quarantine.preserve();
            anyhow::Error::new(error).context(format!(
                "{cause:#}; preserved the entry at {label:?} because its original name could not be restored"
            ))
        }
    }
}

fn cleanup_quarantine_after_error(
    quarantine: &mut RemovalQuarantine,
    cause: anyhow::Error,
) -> anyhow::Error {
    match quarantine.cleanup() {
        Ok(()) => cause,
        Err(error) => anyhow::Error::new(error).context(format!(
            "{cause:#}; could not remove the empty removal quarantine"
        )),
    }
}

fn remove_directory_at(parent: RawFd, name: &CString) -> io::Result<()> {
    // SAFETY: `name` is a live CString and `parent` is a retained directory
    // descriptor supplied by the caller.
    retry_zero(|| unsafe { libc::unlinkat(parent, name.as_ptr(), libc::AT_REMOVEDIR) })
}

#[cfg(target_os = "linux")]
fn rename_noreplace_at(
    old_parent: RawFd,
    old_name: &CString,
    new_parent: RawFd,
    new_name: &CString,
) -> io::Result<()> {
    loop {
        // SAFETY: both names are live CStrings, both descriptors are retained
        // by their callers, and every variadic argument has the syscall ABI's
        // required integer or pointer representation.
        let result = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                old_parent,
                old_name.as_ptr(),
                new_parent,
                new_name.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if result == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(target_os = "macos")]
fn rename_noreplace_at(
    old_parent: RawFd,
    old_name: &CString,
    new_parent: RawFd,
    new_name: &CString,
) -> io::Result<()> {
    loop {
        // SAFETY: both names are live CStrings and both directory descriptors
        // remain valid for the duration of the call.
        let result = unsafe {
            libc::renameatx_np(
                old_parent,
                old_name.as_ptr(),
                new_parent,
                new_name.as_ptr(),
                libc::RENAME_EXCL,
            )
        };
        if result == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn rename_noreplace_at(
    _old_parent: RawFd,
    _old_name: &CString,
    _new_parent: RawFd,
    _new_name: &CString,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "atomic no-replace removal quarantine is unavailable on this platform",
    ))
}

fn join_label(parent: &[u8], child: &[u8]) -> PathBytes {
    let mut path = parent.to_vec();
    if !path.is_empty() && !path.ends_with(b"/") {
        path.push(b'/');
    }
    path.extend_from_slice(child);
    path
}

fn component_cstring(component: &[u8]) -> Result<CString> {
    CString::new(component).context("path component contains NUL")
}

fn open_directory_at(parent: &File, component: &[u8]) -> io::Result<File> {
    let component = CString::new(component)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path component contains NUL"))?;
    open_at(
        parent.as_raw_fd(),
        &component,
        libc::O_RDONLY
            | libc::O_DIRECTORY
            | libc::O_NOFOLLOW
            | libc::O_NONBLOCK
            | libc::O_NOCTTY
            | libc::O_CLOEXEC,
    )
}

fn open_at(parent: RawFd, name: &CString, flags: libc::c_int) -> io::Result<File> {
    loop {
        let descriptor = unsafe { libc::openat(parent, name.as_ptr(), flags) };
        if descriptor >= 0 {
            return Ok(unsafe { File::from_raw_fd(descriptor) });
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn metadata_at(parent: RawFd, component: &[u8]) -> io::Result<Identity> {
    let component = CString::new(component)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path component contains NUL"))?;
    metadata_at_cstring(parent, &component)
}

fn metadata_at_cstring(parent: RawFd, component: &CString) -> io::Result<Identity> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    retry_zero(|| unsafe {
        libc::fstatat(
            parent,
            component.as_ptr(),
            &mut stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    })?;
    Ok(identity_from_stat(&stat))
}

fn identity_from_file(file: &File) -> Result<Identity> {
    let metadata = file.metadata()?;
    Ok(Identity {
        dev: metadata.dev(),
        ino: metadata.ino(),
        file_type: metadata.mode() & MODE_TYPE_MASK,
    })
}

fn identity_from_stat(stat: &libc::stat) -> Identity {
    Identity {
        dev: stat_dev(stat),
        ino: stat.st_ino,
        file_type: stat_mode(stat) & MODE_TYPE_MASK,
    }
}

#[cfg(target_os = "linux")]
fn stat_dev(stat: &libc::stat) -> u64 {
    stat.st_dev
}

#[cfg(not(target_os = "linux"))]
fn stat_dev(stat: &libc::stat) -> u64 {
    stat.st_dev as u64
}

#[cfg(target_os = "linux")]
fn stat_mode(stat: &libc::stat) -> u32 {
    stat.st_mode
}

#[cfg(not(target_os = "linux"))]
fn stat_mode(stat: &libc::stat) -> u32 {
    stat.st_mode as u32
}

fn require_same_identity(expected: Identity, actual: Identity, what: &str) -> Result<()> {
    if expected != actual {
        bail!(
            "{what} changed identity (expected {}:{}, found {}:{})",
            expected.dev,
            expected.ino,
            actual.dev,
            actual.ino
        );
    }
    Ok(())
}

struct DirectoryStream(*mut libc::DIR);

impl Drop for DirectoryStream {
    fn drop(&mut self) {
        let _ = unsafe { libc::closedir(self.0) };
    }
}

fn open_directory_stream(directory: &File) -> Result<DirectoryStream> {
    // A duplicated directory descriptor shares its open-file-description
    // offset. Reopen `.` relative to the pinned descriptor so concurrent
    // scans and retries each have an independent offset.
    let reopened =
        open_directory_at(directory, b".").context("open independent removal directory stream")?;
    let descriptor = reopened.into_raw_fd();
    let stream = unsafe { libc::fdopendir(descriptor) };
    if stream.is_null() {
        let error = io::Error::last_os_error();
        let _ = unsafe { libc::close(descriptor) };
        return Err(error).context("open removal directory stream");
    }
    Ok(DirectoryStream(stream))
}

fn read_directory_stream(stream: &mut DirectoryStream) -> Result<Vec<Vec<u8>>> {
    let mut names = Vec::new();
    loop {
        set_errno(0);
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let errno = get_errno();
            if errno != 0 {
                return Err(io::Error::from_raw_os_error(errno)).context("read removal directory");
            }
            break;
        }
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." {
            names.push(name.to_vec());
        }
    }
    Ok(names)
}

fn read_directory(directory: &File) -> Result<Vec<Vec<u8>>> {
    let mut stream = open_directory_stream(directory)?;
    read_directory_stream(&mut stream)
}

fn retry_zero(mut operation: impl FnMut() -> libc::c_int) -> io::Result<()> {
    loop {
        if operation() == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn is_directory_not_empty(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .and_then(io::Error::raw_os_error)
            .is_some_and(|errno| errno == libc::ENOTEMPTY || errno == libc::EEXIST)
    })
}

#[cfg(target_os = "linux")]
fn set_errno(value: libc::c_int) {
    unsafe { *libc::__errno_location() = value };
}

#[cfg(target_os = "linux")]
fn get_errno() -> libc::c_int {
    unsafe { *libc::__errno_location() }
}

#[cfg(target_os = "macos")]
fn set_errno(value: libc::c_int) {
    unsafe { *libc::__error() = value };
}

#[cfg(target_os = "macos")]
fn get_errno() -> libc::c_int {
    unsafe { *libc::__error() }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn set_errno(_value: libc::c_int) {}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn get_errno() -> libc::c_int {
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;
    use std::fs::{self, OpenOptions};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt};
    use std::path::Path;
    use std::sync::OnceLock;

    type QuarantineHook = Box<dyn Fn(&CStr) + Send + Sync>;

    /// Hooks that run immediately before an entry is moved to quarantine,
    /// keyed by the identity of its parent directory. Tests register a hook
    /// for their own temporary directory so concurrent tests never observe it.
    fn quarantine_hooks() -> &'static Mutex<Vec<(Identity, QuarantineHook)>> {
        static HOOKS: OnceLock<Mutex<Vec<(Identity, QuarantineHook)>>> = OnceLock::new();
        HOOKS.get_or_init(|| Mutex::new(Vec::new()))
    }

    pub(super) fn before_quarantine(parent: RawFd, name: &CStr) {
        // SAFETY: an all-zero `libc::stat` is valid initialization before
        // `fstat` fills every field.
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: the removal code retains `parent`, and `stat` points to
        // writable storage of the size required by `fstat`.
        if unsafe { libc::fstat(parent, &mut stat) } != 0 {
            return;
        }
        let identity = identity_from_stat(&stat);
        let hooks = quarantine_hooks().lock().unwrap();
        for (target, hook) in hooks.iter() {
            if *target == identity {
                hook(name);
            }
        }
    }

    fn hook_quarantines_in(directory: &std::path::Path, hook: QuarantineHook) {
        let identity = identity_from_file(&File::open(directory).unwrap()).unwrap();
        quarantine_hooks().lock().unwrap().push((identity, hook));
    }

    fn remove_selectors(
        base: &std::path::Path,
        selections: &[NativeRemoveSelection],
    ) -> Vec<NativeRemoveOutcome> {
        let mut outcomes = Vec::new();
        remove(
            Some(base.as_os_str().as_bytes()),
            None,
            selections,
            false,
            false,
            2,
            &mut |_| Ok(()),
            &mut |batch| {
                outcomes.extend(batch);
                Ok(())
            },
        )
        .unwrap();
        outcomes
    }

    fn selector(path: &[u8], kind: NativeRemoveKind) -> NativeRemoveSelection {
        NativeRemoveSelection {
            path: path.to_vec(),
            kind,
        }
    }

    #[test]
    fn selector_grammar_distinguishes_unconfined_and_rooted_bases() {
        for path in [&b"."[..], b"..", b"a/../b", b"a/./b", b"a//b/"] {
            assert!(validate_selector(path, false).is_ok());
            assert!(validate_selector(path, true).is_ok());
        }
        for path in [&b"/absolute"[..], b"~", b"~/absolute"] {
            assert!(validate_selector(path, false).is_ok());
            assert!(validate_selector(path, true).is_err());
        }
        assert!(validate_selector(b"", false).is_err());
        assert!(validate_selector(b"nul\0name", false).is_err());
    }

    #[test]
    fn repeated_directory_scans_start_at_the_beginning() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("one"), b"1").unwrap();
        fs::write(temp.path().join("two"), b"2").unwrap();
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(temp.path())
            .unwrap();

        let mut first = read_directory(&directory).unwrap();
        let mut second = read_directory(&directory).unwrap();
        first.sort();
        second.sort();

        assert_eq!(first, vec![b"one".to_vec(), b"two".to_vec()]);
        assert_eq!(second, first);
    }

    #[test]
    fn simultaneous_directory_streams_have_independent_offsets() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("one"), b"1").unwrap();
        fs::write(temp.path().join("two"), b"2").unwrap();
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(temp.path())
            .unwrap();
        let mut first = open_directory_stream(&directory).unwrap();
        let mut second = open_directory_stream(&directory).unwrap();

        let mut first_names = read_directory_stream(&mut first).unwrap();
        let mut second_names = read_directory_stream(&mut second).unwrap();
        first_names.sort();
        second_names.sort();

        assert_eq!(first_names, vec![b"one".to_vec(), b"two".to_vec()]);
        assert_eq!(second_names, first_names);
    }

    fn pinned_test_name(directory: &File, name: &[u8]) -> PinnedName {
        PinnedName {
            parent: PinnedParent::File(directory.try_clone().unwrap()),
            name: component_cstring(name).unwrap(),
            identity: metadata_at(directory.as_raw_fd(), name).unwrap(),
        }
    }

    fn removal_quarantines(path: &std::path::Path) -> Vec<std::ffi::OsString> {
        fs::read_dir(path)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name.as_bytes().starts_with(REMOVE_QUARANTINE_PREFIX))
            .collect()
    }

    #[test]
    fn pinned_removal_never_unlinks_a_later_writer() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("selected"), b"selected").unwrap();
        let directory = File::open(temp.path()).unwrap();
        let selected = pinned_test_name(&directory, b"selected");

        let error = remove_pinned_with_hook(&selected, false, |_, _| {
            fs::write(temp.path().join("selected"), b"later")?;
            Ok(())
        })
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("removal target was replaced during removal"));
        assert_eq!(fs::read(temp.path().join("selected")).unwrap(), b"later");
        assert!(removal_quarantines(temp.path()).is_empty());
    }

    #[test]
    fn pinned_removal_preserves_a_candidate_when_restore_would_replace() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("selected"), b"selected").unwrap();
        let directory = File::open(temp.path()).unwrap();
        let selected = pinned_test_name(&directory, b"selected");
        let mut retained = None;

        let error = remove_pinned_with_hook(&selected, false, |quarantine, _| {
            retained = Some((
                quarantine.parent.try_clone()?,
                quarantine.name.clone(),
                quarantine.directory.try_clone()?,
            ));
            fs::write(temp.path().join("selected"), b"later")?;
            bail!("injected failure after quarantine")
        })
        .unwrap_err();

        let message = format!("{error:#}");
        assert!(message.contains("injected failure after quarantine"));
        assert!(message.contains("preserved the entry at"));
        assert_eq!(fs::read(temp.path().join("selected")).unwrap(), b"later");
        let (quarantine_parent, quarantine_name, quarantine_directory) = retained.unwrap();
        assert_eq!(
            metadata_at(quarantine_directory.as_raw_fd(), REMOVE_QUARANTINE_ENTRY).unwrap(),
            selected.identity
        );

        let candidate = component_cstring(REMOVE_QUARANTINE_ENTRY).unwrap();
        // SAFETY: the test retains the owner-only directory descriptor and
        // passes a live CString for the candidate it just authenticated.
        retry_zero(|| unsafe {
            libc::unlinkat(quarantine_directory.as_raw_fd(), candidate.as_ptr(), 0)
        })
        .unwrap();
        remove_directory_at(quarantine_parent.as_raw_fd(), &quarantine_name).unwrap();
    }

    #[test]
    fn pinned_removal_quarantines_outside_an_untrusted_parent() {
        let temp = tempfile::tempdir().unwrap();
        let hostile = temp.path().join("hostile");
        fs::create_dir(&hostile).unwrap();
        fs::set_permissions(&hostile, fs::Permissions::from_mode(0o777)).unwrap();
        fs::write(hostile.join("selected"), b"selected").unwrap();
        let directory = File::open(&hostile).unwrap();
        let selected = pinned_test_name(&directory, b"selected");

        let outcome = remove_pinned_with_hook(&selected, false, |quarantine, _| {
            assert!(removal_quarantines(&hostile).is_empty());
            let metadata = quarantine.directory.metadata()?;
            assert_eq!(metadata.mode() & 0o777, 0o700);
            Ok(())
        })
        .unwrap();

        assert_eq!(outcome, RemovePinnedOutcome::Removed);
        assert!(!hostile.join("selected").exists());
        assert!(removal_quarantines(temp.path()).is_empty());
    }

    #[test]
    fn pinned_removal_restores_a_candidate_that_changed_before_quarantine() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("selected"), b"selected").unwrap();
        fs::write(temp.path().join("replacement"), b"replacement").unwrap();
        let directory = File::open(temp.path()).unwrap();
        let selected = pinned_test_name(&directory, b"selected");
        fs::rename(
            temp.path().join("selected"),
            temp.path().join("original-selected"),
        )
        .unwrap();
        fs::rename(
            temp.path().join("replacement"),
            temp.path().join("selected"),
        )
        .unwrap();

        let error = remove_pinned(&selected, false).unwrap_err();

        assert!(format!("{error:#}").contains("removal target changed identity"));
        assert_eq!(
            fs::read(temp.path().join("original-selected")).unwrap(),
            b"selected"
        );
        assert_eq!(
            fs::read(temp.path().join("selected")).unwrap(),
            b"replacement"
        );
        assert!(removal_quarantines(temp.path()).is_empty());
    }

    #[test]
    fn pinned_removal_reports_a_quarantined_candidate_that_disappears() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("selected"), b"selected").unwrap();
        let directory = File::open(temp.path()).unwrap();
        let selected = pinned_test_name(&directory, b"selected");
        let moved = component_cstring(b"moved-elsewhere").unwrap();

        let error = remove_pinned_with_hook(&selected, false, |quarantine, candidate| {
            rename_noreplace_at(
                quarantine.directory.as_raw_fd(),
                candidate,
                directory.as_raw_fd(),
                &moved,
            )?;
            Ok(())
        })
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("quarantined removal target disappeared before authentication"));
        assert_eq!(
            fs::read(temp.path().join("moved-elsewhere")).unwrap(),
            b"selected"
        );
    }

    #[test]
    fn no_follow_aborts_before_any_mutation() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("real")).unwrap();
        fs::write(temp.path().join("real/file"), b"data").unwrap();
        fs::write(temp.path().join("victim"), b"data").unwrap();
        symlink("real", temp.path().join("link")).unwrap();
        let mut traces = Vec::new();
        let result = remove(
            Some(temp.path().as_os_str().as_bytes()),
            None,
            &[
                selector(b"victim", NativeRemoveKind::Any),
                selector(b"link/file", NativeRemoveKind::Any),
            ],
            false,
            false,
            2,
            &mut |messages| {
                traces.extend(messages);
                Ok(())
            },
            &mut |_| Ok(()),
        );
        assert!(result.is_err());
        assert!(temp.path().join("victim").exists());
        assert!(temp.path().join("real/file").exists());
    }

    #[test]
    fn no_follow_unlinks_selected_symlink_and_preserves_referent() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("real")).unwrap();
        fs::write(temp.path().join("real/file"), b"data").unwrap();
        symlink("real", temp.path().join("link")).unwrap();
        let mut outcomes = Vec::new();
        remove(
            Some(temp.path().as_os_str().as_bytes()),
            None,
            &[selector(b"link", NativeRemoveKind::File)],
            false,
            false,
            2,
            &mut |_| Ok(()),
            &mut |batch| {
                outcomes.extend(batch);
                Ok(())
            },
        )
        .unwrap();

        assert!(!temp.path().join("link").is_symlink());
        assert_eq!(fs::read(temp.path().join("real/file")).unwrap(), b"data");
        assert_eq!(outcomes.len(), 2);
        assert_eq!(outcomes[0].disposition, NativeRemoveDisposition::Resolved);
        assert_eq!(outcomes[1].disposition, NativeRemoveDisposition::Removed);
        assert!(outcomes[1].failure.is_none());
    }

    #[test]
    fn failed_attached_emit_cancels_pending_mutation() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("victim"), b"data").unwrap();
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(temp.path())
            .unwrap();
        let identity = metadata_at(directory.as_raw_fd(), b"victim").unwrap();
        let (task_tx, _task_rx) = mpsc::sync_channel(1);
        let (event_tx, _event_rx) = mpsc::channel();
        let pool = Arc::new(Pool {
            sender: Mutex::new(Some(task_tx)),
            pending: Mutex::new(0),
            events: event_tx,
            dry_run: false,
            cancelled: AtomicBool::new(false),
        });

        let mut heartbeat = Vec::new();
        let error = emit_attached(&pool, &mut heartbeat, &mut |_| bail!("client disconnected"))
            .unwrap_err();
        assert!(error.to_string().contains("client disconnected"));
        assert!(pool.is_cancelled());

        process_task(
            &pool,
            Task::Leaf {
                selector: 0,
                name: PinnedName {
                    parent: PinnedParent::File(directory),
                    name: component_cstring(b"victim").unwrap(),
                    identity,
                },
                _object: None,
                label: b"victim".to_vec(),
                parent: None,
            },
        );
        assert_eq!(fs::read(temp.path().join("victim")).unwrap(), b"data");
    }

    #[test]
    fn follow_removes_referent_and_leaves_link() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("real")).unwrap();
        fs::write(temp.path().join("real/file"), b"data").unwrap();
        symlink("real", temp.path().join("link")).unwrap();
        let mut outcomes = Vec::new();
        remove(
            Some(temp.path().as_os_str().as_bytes()),
            None,
            &[selector(b"link", NativeRemoveKind::Directory)],
            true,
            false,
            2,
            &mut |_| Ok(()),
            &mut |batch| {
                outcomes.extend(batch);
                Ok(())
            },
        )
        .unwrap();
        assert!(temp.path().join("link").is_symlink());
        assert!(!temp.path().join("real").exists());
        assert!(outcomes.iter().all(|outcome| outcome.failure.is_none()));
    }

    #[test]
    fn root_rejects_symlink_that_leaves_and_reenters() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("root/inside")).unwrap();
        symlink("../root/inside", temp.path().join("root/escape")).unwrap();
        let result = remove(
            None,
            Some(temp.path().join("root").as_os_str().as_bytes()),
            &[selector(b"escape", NativeRemoveKind::Contents)],
            true,
            true,
            1,
            &mut |_| Ok(()),
            &mut |_| Ok(()),
        );
        assert!(result.is_err());
    }

    #[test]
    fn selected_directory_rename_cannot_redirect_removal_to_its_replacement() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("tree")).unwrap();
        fs::write(temp.path().join("tree/old"), b"old").unwrap();
        let mut outcomes = Vec::new();
        remove(
            Some(temp.path().as_os_str().as_bytes()),
            None,
            &[selector(b"tree", NativeRemoveKind::Directory)],
            false,
            false,
            2,
            &mut |_| {
                fs::rename(temp.path().join("tree"), temp.path().join("moved"))?;
                fs::create_dir(temp.path().join("tree"))?;
                fs::write(temp.path().join("tree/replacement"), b"keep")?;
                Ok(())
            },
            &mut |batch| {
                outcomes.extend(batch);
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(
            fs::read(temp.path().join("tree/replacement")).unwrap(),
            b"keep"
        );
        assert!(temp.path().join("moved").is_dir());
        assert_eq!(fs::read_dir(temp.path().join("moved")).unwrap().count(), 0);
        assert!(outcomes.iter().any(|outcome| outcome.failure.is_some()));
    }

    #[test]
    fn directory_swapped_before_quarantine_is_preserved() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().to_path_buf();
        fs::create_dir(base.join("tree")).unwrap();
        fs::write(base.join("tree/old"), b"old").unwrap();
        let swap = base.clone();
        hook_quarantines_in(
            &base,
            Box::new(move |name| {
                if name.to_bytes() == b"tree" {
                    fs::rename(swap.join("tree"), swap.join("moved")).unwrap();
                    fs::create_dir(swap.join("tree")).unwrap();
                }
            }),
        );

        let outcomes = remove_selectors(&base, &[selector(b"tree", NativeRemoveKind::Directory)]);

        // The selected directory and the replacement both survive. The
        // replacement is moved into quarantine, rejected by the identity
        // check, and restored to the selected name.
        assert!(base.join("moved").is_dir());
        assert!(base.join("tree").is_dir());
        let failure = outcomes
            .iter()
            .find(|outcome| outcome.disposition == NativeRemoveDisposition::Failed)
            .and_then(|outcome| outcome.failure.as_ref())
            .expect("swapped directory removal is reported as a failure");
        assert!(
            failure.error.message.contains("changed identity")
                && failure.class == NativeRemoveErrorClass::Conflict,
            "{failure:?}"
        );
        assert!(!outcomes.iter().any(|outcome| {
            outcome.path == b"tree" && outcome.disposition == NativeRemoveDisposition::Removed
        }));
    }

    #[test]
    fn leaf_swapped_before_quarantine_preserves_replacement_entries() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().to_path_buf();
        fs::write(base.join("file"), b"old").unwrap();
        fs::write(base.join("dir-file"), b"old").unwrap();
        fs::create_dir(base.join("referent")).unwrap();
        fs::write(base.join("referent/keep"), b"keep").unwrap();
        fs::create_dir(base.join("full")).unwrap();
        fs::write(base.join("full/keep"), b"keep").unwrap();
        let swap = base.clone();
        hook_quarantines_in(
            &base,
            Box::new(move |name| match name.to_bytes() {
                b"file" => {
                    fs::rename(swap.join("file"), swap.join("file-moved")).unwrap();
                    symlink("referent", swap.join("file")).unwrap();
                }
                b"dir-file" => {
                    fs::rename(swap.join("dir-file"), swap.join("dir-file-moved")).unwrap();
                    fs::rename(swap.join("full"), swap.join("dir-file")).unwrap();
                }
                _ => {}
            }),
        );

        let outcomes = remove_selectors(
            &base,
            &[
                selector(b"file", NativeRemoveKind::File),
                selector(b"dir-file", NativeRemoveKind::File),
            ],
        );

        // A symlink swapped in is restored as an entry and never followed.
        assert!(base.join("file").is_symlink());
        assert_eq!(
            fs::read_link(base.join("file")).unwrap(),
            Path::new("referent")
        );
        assert_eq!(fs::read(base.join("file-moved")).unwrap(), b"old");
        assert_eq!(fs::read(base.join("referent/keep")).unwrap(), b"keep");
        // A directory swapped in is likewise restored without being entered.
        assert_eq!(fs::read(base.join("dir-file/keep")).unwrap(), b"keep");
        assert_eq!(fs::read(base.join("dir-file-moved")).unwrap(), b"old");
        for path in [b"file".as_slice(), b"dir-file".as_slice()] {
            assert!(outcomes.iter().any(|outcome| {
                outcome.path == path && outcome.disposition == NativeRemoveDisposition::Failed
            }));
        }
    }
}

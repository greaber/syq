//! Descriptor-rooted implementation of native `syq rm`.
//!
//! All operator selectors are resolved before the first mutation. Resolution
//! is a component walk rooted at an already-open directory; it never produces
//! a canonical pathname that is reopened later. The selected object and its
//! parent directory remain pinned while an endpoint-local worker pool removes
//! descendants relative to directory descriptors. Regardless of source following,
//! a selected symlink and symlinks encountered below a selected directory are
//! unlinked as entries; neither is followed. FIFOs on platforms without O_PATH
//! retain only their parent and observed identity, avoiding a stream reader.

use crate::proto::{
    Kind, NativeRemoveDisposition, NativeRemoveErrorClass, NativeRemoveFailure, NativeRemoveKind,
    NativeRemoveOutcome, NativeRemoveSelection, OperatorSymlinkPolicy, PathBytes,
};
use crate::rooted::{
    OperatorFinalComponent, OperatorResolver, OperatorSymlinkHop, PinnedLeaf as RootedPinnedLeaf,
    PinnedPath, RootMetadata,
};
use crate::sys::{
    directory_names, open_at, retry_zero, stat_dev, stat_mode, MODE_DIRECTORY, MODE_REGULAR,
    MODE_SYMLINK, MODE_TYPE_MASK,
};
use anyhow::{bail, Context, Result};
use std::ffi::{CString, OsStr};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, RawFd};
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
    remove_selected_directory: bool,
    partials_only: bool,
}

enum ResolvedSelection {
    Missing,
    Leaf(PinnedLeaf),
    Directory(PinnedDirectory),
}

struct Resolver {
    resolver: OperatorResolver,
    confined: bool,
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
            follow_symlink: false,
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
                let partials_only = selection.kind == NativeRemoveKind::Partials;
                let remove_selected_directory =
                    !partials_only && selection.kind != NativeRemoveKind::Contents;
                let (directory, name) = directory.into_parts();
                let name = name.map(|name| pinned_name_from_root(name).0);
                if remove_selected_directory && name.is_none() {
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
                    remove_selected_directory,
                    partials_only,
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
        NativeRemoveKind::Contents | NativeRemoveKind::Directory | NativeRemoveKind::Partials if identity.is_symlink() => bail!(
            "selector {:?} must resolve to a directory; final symlinks are never followed, even with --follow-src or --follow; name the target directory explicitly",
            String::from_utf8_lossy(label)
        ),
        NativeRemoveKind::Contents | NativeRemoveKind::Directory | NativeRemoveKind::Partials if !identity.is_dir() => bail!(
            "selector {:?} must resolve to a directory",
            String::from_utf8_lossy(label)
        ),
        NativeRemoveKind::File if identity.is_dir() => bail!(
            "selector {:?} must resolve to a non-directory; use --src-dir to remove a tree or --srcs-in to remove its contents",
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
    partials_only: bool,
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
    events: mpsc::Sender<Option<NativeRemoveOutcome>>,
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
        let finished = {
            let mut pending = self.pending.lock().unwrap();
            *pending -= 1;
            *pending == 0
        };
        if finished {
            // The coordinator can consume the last outcome before this task
            // finishes. Wake it again so completion cannot wait for EVENT_POLL.
            let _ = self.events.send(None);
        }
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
            let _ = self.events.send(Some(outcome));
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
                    partials_only: directory.partials_only,
                    directory: directory.directory,
                    removal: directory
                        .remove_selected_directory
                        .then_some(directory.name)
                        .flatten(),
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
            Ok(Some(event)) => {
                if sink_error.is_none() {
                    batch.push(event);
                }
            }
            Ok(None) => {}
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
    for event in event_rx.try_iter().flatten() {
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
                match remove_pinned(&name, None) {
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
        if job.partials_only
            && !identity.is_dir()
            && (identity.kind() != Kind::File
                || !crate::fsops::is_partial_name(OsStr::from_bytes(&component)))
        {
            continue;
        }
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
                    partials_only: job.partials_only,
                    directory,
                    removal: (!job.partials_only).then_some(pinned),
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
        remove_pinned(removal, Some(&job.directory))
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

/// Remove one pinned name from its retained parent.
///
/// The identity re-check and `unlinkat` are separate system calls; POSIX has
/// no identity-conditioned unlink, so an entry renamed over the name between
/// them is removed as a single entry (never followed or descended) while the
/// pinned object survives under its new name. For a directory the caller
/// passes the descriptor it holds on the pinned directory, and on Linux every
/// outcome that is not already a failure is checked against it: a pinned
/// directory that is still linked afterwards, whether its name was swapped
/// or renamed away, is reported as a failure instead of success. Leaves hold
/// no descriptor, so a swapped leaf cannot be detected afterwards.
fn remove_pinned(name: &PinnedName, held_directory: Option<&File>) -> Result<RemovePinnedOutcome> {
    let outcome = unlink_pinned(name, held_directory.is_some())?;
    if let Some(directory) = held_directory {
        require_unlinked_directory(directory)?;
    }
    Ok(outcome)
}

/// Two selectors that resolve to one entry race here. Linux orders their
/// unlinks so exactly one succeeds and the other is already absent; macOS can
/// report success to both, so the removed and already-absent counts may split
/// differently there. Either way the entry is removed once, and the same
/// outcomes already arise from an unrelated process removing the entry, so
/// the race is not serialized.
fn unlink_pinned(name: &PinnedName, directory: bool) -> Result<RemovePinnedOutcome> {
    let current = match metadata_at_cstring(name.parent.as_raw_fd(), &name.name) {
        Ok(identity) => identity,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(RemovePinnedOutcome::AlreadyAbsent)
        }
        Err(error) => return Err(error).context("inspect pinned removal name"),
    };
    require_same_identity(name.identity, current, "removal target")?;
    #[cfg(test)]
    tests::before_unlink(name.parent.as_raw_fd(), &name.name);
    let flags = if directory { libc::AT_REMOVEDIR } else { 0 };
    retry_zero(|| unsafe { libc::unlinkat(name.parent.as_raw_fd(), name.name.as_ptr(), flags) })
        .map(|()| RemovePinnedOutcome::Removed)
        .or_else(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                Ok(RemovePinnedOutcome::AlreadyAbsent)
            } else {
                Err(error)
            }
        })
        .context("remove pinned object")
}

/// Once the pinned name is gone, the held descriptor must refer to an
/// unlinked directory; otherwise the selected directory survives under
/// another name, either because a replacement was removed in its place or
/// because it was renamed away. Linux clears the link count of a removed
/// directory. macOS keeps reporting the old count, so this check is not
/// available there.
#[cfg(target_os = "linux")]
fn require_unlinked_directory(directory: &File) -> Result<()> {
    let metadata = directory.metadata().context("inspect removed directory")?;
    if metadata.nlink() != 0 {
        bail!(
            "removal target {}:{} is still linked after its name was removed; the selected directory remains under another name",
            metadata.dev(),
            metadata.ino()
        );
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn require_unlinked_directory(_directory: &File) -> Result<()> {
    Ok(())
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
        0,
    )
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

fn read_directory(directory: &File) -> Result<Vec<Vec<u8>>> {
    // A duplicated directory descriptor shares its open-file-description
    // offset. Reopen `.` relative to the pinned descriptor so concurrent
    // scans and retries each have an independent offset.
    let reopened =
        open_directory_at(directory, b".").context("open independent removal directory stream")?;
    directory_names(reopened).context("read removal directory")
}

fn is_directory_not_empty(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .and_then(io::Error::raw_os_error)
            .is_some_and(|errno| errno == libc::ENOTEMPTY || errno == libc::EEXIST)
    })
}

#[cfg(test)]
mod tests;

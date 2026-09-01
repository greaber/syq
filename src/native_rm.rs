//! Descriptor-rooted implementation of native `syq rm`.
//!
//! All operator selectors are resolved before the first mutation. Resolution
//! is a component walk rooted at an already-open directory; it never produces
//! a canonical pathname that is reopened later. The selected object and its
//! parent directory remain pinned while an endpoint-local worker pool removes
//! descendants relative to directory descriptors. Symlinks encountered below
//! a selected directory are payload entries and are unlinked, never followed.

use crate::proto::{NativeRemoveKind, NativeRemoveOutcome, NativeRemoveSelection, PathBytes};
use anyhow::{bail, Context, Result};
use std::collections::VecDeque;
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

const SYMLINK_LIMIT: usize = 40;
const EVENT_BATCH: usize = 200;
const RMDIR_RETRIES: usize = 3;

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
    name: PinnedName,
    _object: File,
    label: PathBytes,
}

struct PinnedDirectory {
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

struct Cursor {
    directory: File,
    anchor: Option<PinnedName>,
}

struct Resolver {
    base: File,
    confined: bool,
    follow: bool,
}

impl Resolver {
    fn resolve(
        &self,
        selection: &NativeRemoveSelection,
        traces: &mut Vec<String>,
    ) -> Result<ResolvedSelection> {
        validate_selector(&selection.path)?;
        let label = selection.path.clone();
        let mut components = path_components(&selection.path);
        let initial = Cursor {
            directory: self.base.try_clone().context("duplicate removal base")?,
            anchor: None,
        };
        let mut stack = vec![initial];
        let mut symlinks = 0usize;

        loop {
            let Some(component) = components.pop_front() else {
                let current = stack.last().expect("resolver stack is nonempty");
                let identity = identity_from_file(&current.directory)?;
                require_kind(selection.kind, identity, &label)?;
                let remove_root = selection.kind != NativeRemoveKind::Contents;
                if remove_root && current.anchor.is_none() {
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
                return Ok(ResolvedSelection::Directory(PinnedDirectory {
                    directory: current
                        .directory
                        .try_clone()
                        .context("pin selected directory")?,
                    name: current.anchor.as_ref().map(duplicate_name).transpose()?,
                    label,
                    remove_root,
                }));
            };

            if component == b"." {
                continue;
            }
            if component == b".." {
                if stack.len() > 1 {
                    stack.pop();
                } else if self.confined {
                    bail!(
                        "selector {:?} follows a symlink outside --root",
                        String::from_utf8_lossy(&selection.path)
                    );
                } else {
                    let parent = open_directory_at(&stack[0].directory, b"..")
                        .context("resolve symlink target parent")?;
                    stack[0] = Cursor {
                        directory: parent,
                        anchor: None,
                    };
                }
                continue;
            }

            let current = stack.last().expect("resolver stack is nonempty");
            let identity = match metadata_at(current.directory.as_raw_fd(), &component) {
                Ok(identity) => identity,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    traces.push(format!(
                        "selector {:?} is absent",
                        String::from_utf8_lossy(&label)
                    ));
                    return Ok(ResolvedSelection::Missing);
                }
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "resolve selector {:?}",
                            String::from_utf8_lossy(&selection.path)
                        )
                    });
                }
            };

            if identity.is_symlink() {
                if !self.follow {
                    bail!(
                        "selector {:?} encounters symlink component {:?}; pass --follow to resolve symlinks",
                        String::from_utf8_lossy(&selection.path),
                        String::from_utf8_lossy(&component)
                    );
                }
                symlinks += 1;
                if symlinks > SYMLINK_LIMIT {
                    bail!(
                        "too many symlinks while resolving selector {:?}",
                        String::from_utf8_lossy(&selection.path)
                    );
                }
                let target = read_link_at(current.directory.as_raw_fd(), &component)?;
                traces.push(format!(
                    "selector {:?}: symlink {:?} -> {:?}",
                    String::from_utf8_lossy(&selection.path),
                    String::from_utf8_lossy(&component),
                    String::from_utf8_lossy(&target)
                ));
                if target.starts_with(b"/") {
                    if self.confined {
                        bail!(
                            "selector {:?} has an absolute symlink target outside --root",
                            String::from_utf8_lossy(&selection.path)
                        );
                    }
                    stack = vec![Cursor {
                        directory: open_start(true)?,
                        anchor: None,
                    }];
                }
                let mut target_components = path_components(&target);
                target_components.append(&mut components);
                components = target_components;
                continue;
            }

            let terminal = components.is_empty();
            if identity.is_dir() {
                let directory = open_directory_at(&current.directory, &component)
                    .with_context(|| format!("open directory component {:?}", bytes(&component)))?;
                require_same_identity(identity, identity_from_file(&directory)?, "directory")?;
                let anchor = PinnedName {
                    parent: PinnedParent::File(
                        current
                            .directory
                            .try_clone()
                            .context("pin selected directory parent")?,
                    ),
                    name: component_cstring(&component)?,
                    identity,
                };
                if terminal {
                    require_kind(selection.kind, identity, &label)?;
                    traces.push(format!(
                        "selector {:?} resolved to directory {}:{}",
                        String::from_utf8_lossy(&label),
                        identity.dev,
                        identity.ino
                    ));
                    return Ok(ResolvedSelection::Directory(PinnedDirectory {
                        directory,
                        name: Some(anchor),
                        label,
                        remove_root: selection.kind != NativeRemoveKind::Contents,
                    }));
                }
                stack.push(Cursor {
                    directory,
                    anchor: Some(anchor),
                });
                continue;
            }

            if !terminal {
                bail!(
                    "non-directory component {:?} in selector {:?}",
                    String::from_utf8_lossy(&component),
                    String::from_utf8_lossy(&selection.path)
                );
            }
            require_kind(selection.kind, identity, &label)?;
            let object = open_metadata_at(current.directory.as_raw_fd(), &component)
                .with_context(|| format!("pin selector {:?}", bytes(&label)))?;
            require_same_identity(identity, identity_from_file(&object)?, "object")?;
            traces.push(format!(
                "selector {:?} resolved to non-directory {}:{}",
                String::from_utf8_lossy(&label),
                identity.dev,
                identity.ino
            ));
            return Ok(ResolvedSelection::Leaf(PinnedLeaf {
                name: PinnedName {
                    parent: PinnedParent::File(
                        current
                            .directory
                            .try_clone()
                            .context("pin selected object parent")?,
                    ),
                    name: component_cstring(&component)?,
                    identity,
                },
                _object: object,
                label,
            }));
        }
    }
}

fn validate_selector(path: &[u8]) -> Result<()> {
    if path.is_empty() {
        bail!("source selectors may not be empty");
    }
    if path.starts_with(b"/") {
        bail!(
            "source selector {:?} must be relative",
            String::from_utf8_lossy(path)
        );
    }
    if path.contains(&0) {
        bail!("source selector contains NUL");
    }
    if path
        .split(|byte| *byte == b'/')
        .any(|component| component == b"." || component == b"..")
    {
        bail!(
            "source selector {:?} contains forbidden `.` or `..` component",
            String::from_utf8_lossy(path)
        );
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
    follow: bool,
    traces: &mut Vec<String>,
) -> Result<(File, bool)> {
    if cwd.is_some() && root.is_some() {
        bail!("--cwd and --root are mutually exclusive");
    }
    if let Some(path) = root {
        let directory = resolve_base_path(path, false, "--root", traces)?;
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
    let directory = open_start(false)?;
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
    let mut components = path_components(path);
    let mut stack = vec![Cursor {
        directory: open_start(path.starts_with(b"/"))?,
        anchor: None,
    }];
    let mut symlinks = 0usize;
    while let Some(component) = components.pop_front() {
        if component == b"." {
            continue;
        }
        if component == b".." {
            if stack.len() > 1 {
                stack.pop();
            } else {
                let parent = open_directory_at(&stack[0].directory, b"..")
                    .with_context(|| format!("resolve {option} parent"))?;
                stack[0] = Cursor {
                    directory: parent,
                    anchor: None,
                };
            }
            continue;
        }
        let current = stack.last().expect("base resolver stack is nonempty");
        let identity = metadata_at(current.directory.as_raw_fd(), &component)
            .with_context(|| format!("resolve {option} {:?}", bytes(path)))?;
        if identity.is_symlink() {
            if !follow {
                bail!(
                    "{option} {:?} encounters symlink component {:?}",
                    String::from_utf8_lossy(path),
                    String::from_utf8_lossy(&component)
                );
            }
            symlinks += 1;
            if symlinks > SYMLINK_LIMIT {
                bail!(
                    "too many symlinks while resolving {option} {:?}",
                    bytes(path)
                );
            }
            let target = read_link_at(current.directory.as_raw_fd(), &component)?;
            traces.push(format!(
                "{option} {:?}: symlink {:?} -> {:?}",
                String::from_utf8_lossy(path),
                String::from_utf8_lossy(&component),
                String::from_utf8_lossy(&target)
            ));
            if target.starts_with(b"/") {
                stack = vec![Cursor {
                    directory: open_start(true)?,
                    anchor: None,
                }];
            }
            let mut target_components = path_components(&target);
            target_components.append(&mut components);
            components = target_components;
            continue;
        }
        if !identity.is_dir() {
            bail!("{option} {:?} is not a directory", bytes(path));
        }
        let directory = open_directory_at(&current.directory, &component)
            .with_context(|| format!("open {option} component {:?}", bytes(&component)))?;
        require_same_identity(identity, identity_from_file(&directory)?, "base directory")?;
        stack.push(Cursor {
            directory,
            anchor: None,
        });
    }
    stack
        .pop()
        .map(|cursor| cursor.directory)
        .context("base path did not resolve to a directory")
}

struct DirectoryJob {
    directory: File,
    removal: Option<PinnedName>,
    label: PathBytes,
    parent: Option<Arc<DirectoryJob>>,
    remaining: AtomicUsize,
    retries: AtomicUsize,
}

enum Task {
    Scan(Arc<DirectoryJob>),
    Leaf {
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

    fn outcome(&self, path: PathBytes, error: Option<String>) {
        let _ = self.events.send(NativeRemoveOutcome { path, error });
    }
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
    let (base, confined) = open_base(cwd, root, follow_symlinks, &mut traces)?;
    let resolver = Resolver {
        base,
        confined,
        follow: follow_symlinks,
    };

    // This phase is deliberately complete before the worker pool starts: a
    // later selector can never acquire a new meaning because an earlier one
    // has already changed the namespace.
    let mut resolved = Vec::with_capacity(selections.len());
    for selection in selections {
        let resolution = match resolver.resolve(selection, &mut traces) {
            Ok(resolution) => resolution,
            Err(error) => {
                if !traces.is_empty() {
                    trace(std::mem::take(&mut traces))?;
                }
                return Err(error);
            }
        };
        match resolution {
            ResolvedSelection::Missing => {}
            selected => resolved.push(selected),
        }
    }
    if !traces.is_empty() {
        trace(traces)?;
    }

    let (task_tx, task_rx) = mpsc::sync_channel(workers.max(1).saturating_mul(4));
    let (event_tx, event_rx) = mpsc::channel();
    let pool = Arc::new(Pool {
        sender: Mutex::new(Some(task_tx)),
        pending: Mutex::new(0),
        events: event_tx,
        dry_run,
    });
    let task_rx = Arc::new(Mutex::new(task_rx));
    let mut threads = Vec::new();
    for _ in 0..workers.max(1) {
        let pool = pool.clone();
        let task_rx = task_rx.clone();
        threads.push(std::thread::spawn(move || worker_loop(pool, task_rx)));
    }

    for selected in resolved {
        match selected {
            ResolvedSelection::Missing => unreachable!(),
            ResolvedSelection::Leaf(leaf) => pool.submit(Task::Leaf {
                name: leaf.name,
                _object: Some(leaf._object),
                label: leaf.label,
                parent: None,
            }),
            ResolvedSelection::Directory(directory) => {
                pool.submit(Task::Scan(Arc::new(DirectoryJob {
                    directory: directory.directory,
                    removal: directory.remove_root.then_some(directory.name).flatten(),
                    label: directory.label,
                    parent: None,
                    remaining: AtomicUsize::new(1),
                    retries: AtomicUsize::new(0),
                })));
            }
        }
    }

    let mut batch = Vec::with_capacity(EVENT_BATCH);
    let mut sink_error = None;
    while !pool.is_done() {
        match event_rx.recv_timeout(Duration::from_millis(100)) {
            Ok(event) => {
                batch.push(event);
                if batch.len() >= EVENT_BATCH {
                    let ready = std::mem::replace(&mut batch, Vec::with_capacity(EVENT_BATCH));
                    if sink_error.is_none() {
                        sink_error = sink(ready).err();
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    while let Ok(event) = event_rx.try_recv() {
        batch.push(event);
        if batch.len() >= EVENT_BATCH {
            let ready = std::mem::replace(&mut batch, Vec::with_capacity(EVENT_BATCH));
            if sink_error.is_none() {
                sink_error = sink(ready).err();
            }
        }
    }
    if !batch.is_empty() && sink_error.is_none() {
        sink_error = sink(batch).err();
    }
    pool.close();
    for thread in threads {
        if thread.join().is_err() && sink_error.is_none() {
            sink_error = Some(anyhow::anyhow!("native removal worker panicked"));
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
    match task {
        Task::Scan(job) => scan_directory(pool, job),
        Task::Leaf {
            name,
            _object,
            label,
            parent,
        } => {
            let error = if pool.dry_run {
                None
            } else {
                remove_pinned(&name, false)
                    .err()
                    .map(|error| format!("{error:#}"))
            };
            pool.outcome(label, error);
            if let Some(parent) = parent {
                directory_part_done(pool, parent);
            }
        }
        Task::Finish(job) => finish_directory(pool, job),
    }
}

fn scan_directory(pool: &Arc<Pool>, job: Arc<DirectoryJob>) {
    let names = match read_directory(&job.directory) {
        Ok(names) => names,
        Err(error) => {
            pool.outcome(job.label.clone(), Some(format!("{error:#}")));
            abandon_directory(pool, &job);
            return;
        }
    };
    for component in names {
        let identity = match metadata_at(job.directory.as_raw_fd(), &component) {
            Ok(identity) => identity,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                pool.outcome(join_label(&job.label, &component), Some(error.to_string()));
                continue;
            }
        };
        let name = match component_cstring(&component) {
            Ok(name) => name,
            Err(error) => {
                pool.outcome(
                    join_label(&job.label, &component),
                    Some(format!("{error:#}")),
                );
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
                    pool.outcome(label, Some(error.to_string()));
                    directory_part_done(pool, job.clone());
                    continue;
                }
            };
            match identity_from_file(&directory)
                .and_then(|opened| require_same_identity(identity, opened, "directory"))
            {
                Ok(()) => pool.submit(Task::Scan(Arc::new(DirectoryJob {
                    directory,
                    removal: Some(pinned),
                    label,
                    parent: Some(job.clone()),
                    remaining: AtomicUsize::new(1),
                    retries: AtomicUsize::new(0),
                }))),
                Err(error) => {
                    pool.outcome(label, Some(format!("{error:#}")));
                    directory_part_done(pool, job.clone());
                }
            }
        } else {
            pool.submit(Task::Leaf {
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
    let Some(removal) = &job.removal else {
        if let Some(parent) = &job.parent {
            directory_part_done(pool, parent.clone());
        }
        return;
    };
    let result = if pool.dry_run {
        Ok(())
    } else {
        remove_pinned(removal, true)
    };
    match result {
        Ok(()) => {
            pool.outcome(job.label.clone(), None);
            if let Some(parent) = &job.parent {
                directory_part_done(pool, parent.clone());
            }
        }
        Err(error)
            if is_directory_not_empty(&error)
                && job.retries.fetch_add(1, Ordering::SeqCst) < RMDIR_RETRIES =>
        {
            job.remaining.store(1, Ordering::SeqCst);
            pool.submit(Task::Scan(job));
        }
        Err(error) => {
            pool.outcome(job.label.clone(), Some(format!("{error:#}")));
            if let Some(parent) = &job.parent {
                directory_part_done(pool, parent.clone());
            }
        }
    }
}

fn abandon_directory(pool: &Arc<Pool>, job: &Arc<DirectoryJob>) {
    if let Some(parent) = &job.parent {
        directory_part_done(pool, parent.clone());
    }
}

fn directory_part_done(pool: &Arc<Pool>, job: Arc<DirectoryJob>) {
    if job.remaining.fetch_sub(1, Ordering::SeqCst) == 1 {
        pool.submit(Task::Finish(job));
    }
}

fn remove_pinned(name: &PinnedName, directory: bool) -> Result<()> {
    let current = match metadata_at_cstring(name.parent.as_raw_fd(), &name.name) {
        Ok(identity) => identity,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("inspect pinned removal name"),
    };
    require_same_identity(name.identity, current, "removal target")?;
    let flags = if directory { libc::AT_REMOVEDIR } else { 0 };
    retry_zero(|| unsafe { libc::unlinkat(name.parent.as_raw_fd(), name.name.as_ptr(), flags) })
        .or_else(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                Ok(())
            } else {
                Err(error)
            }
        })
        .context("remove pinned object")
}

fn duplicate_name(name: &PinnedName) -> Result<PinnedName> {
    Ok(PinnedName {
        parent: match &name.parent {
            PinnedParent::File(file) => {
                PinnedParent::File(file.try_clone().context("duplicate pinned parent")?)
            }
            PinnedParent::Directory(job) => PinnedParent::Directory(job.clone()),
        },
        name: name.name.clone(),
        identity: name.identity,
    })
}

fn path_components(path: &[u8]) -> VecDeque<Vec<u8>> {
    path.split(|byte| *byte == b'/')
        .filter(|component| !component.is_empty())
        .map(<[u8]>::to_vec)
        .collect()
}

fn join_label(parent: &[u8], child: &[u8]) -> PathBytes {
    let mut path = parent.to_vec();
    if !path.is_empty() && !path.ends_with(b"/") {
        path.push(b'/');
    }
    path.extend_from_slice(child);
    path
}

fn bytes(path: &[u8]) -> String {
    String::from_utf8_lossy(path).into_owned()
}

fn open_start(root: bool) -> Result<File> {
    let path = if root { Path::new("/") } else { Path::new(".") };
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOCTTY | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("open removal base {}", path.display()))
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

fn open_metadata_at(parent: RawFd, component: &[u8]) -> io::Result<File> {
    let component = CString::new(component)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path component contains NUL"))?;
    #[cfg(target_os = "linux")]
    let flags = libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    #[cfg(target_os = "macos")]
    let flags = libc::O_EVTONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let flags =
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC;
    open_at(parent, &component, flags)
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

fn read_link_at(parent: RawFd, component: &[u8]) -> Result<Vec<u8>> {
    let component = component_cstring(component)?;
    let mut buffer = vec![0u8; 256];
    loop {
        let read = loop {
            let result = unsafe {
                libc::readlinkat(
                    parent,
                    component.as_ptr(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                )
            };
            if result >= 0 {
                break result as usize;
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error).context("read selector symlink");
            }
        };
        if read < buffer.len() {
            buffer.truncate(read);
            return Ok(buffer);
        }
        if buffer.len() >= 1024 * 1024 {
            bail!("symlink target exceeds size limit");
        }
        buffer.resize(buffer.len() * 2, 0);
    }
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
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::symlink;

    fn selector(path: &[u8], kind: NativeRemoveKind) -> NativeRemoveSelection {
        NativeRemoveSelection {
            path: path.to_vec(),
            kind,
        }
    }

    #[test]
    fn selector_grammar_rejects_ambiguous_components() {
        for path in [&b"/absolute"[..], b".", b"..", b"a/../b", b"a/./b"] {
            assert!(validate_selector(path).is_err());
        }
        assert!(validate_selector(b"a//b/").is_ok());
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
                selector(b"link", NativeRemoveKind::Any),
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
    fn follow_removes_terminal_object_and_leaves_link() {
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
        assert!(outcomes.iter().all(|outcome| outcome.error.is_none()));
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
        assert!(outcomes.iter().any(|outcome| outcome.error.is_some()));
    }
}

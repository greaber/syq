//! Parallel directory walk producing `Entry` batches in parent-before-child order.

use crate::fsops::{lstat_entry, path_bytes};
use crate::proto::ContainerGuard;
use crate::proto::{Entry, PathBytes};
use crate::rooted::{RelativePath, Root, RootIdentity};
use anyhow::{Context, Result};
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use jwalk::WalkDirGeneric;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::time::{Duration, Instant};

pub const BATCH: usize = 4096;
const FIRST_BATCH: usize = 1000;
const FIRST_BATCH_MAX_DELAY: Duration = Duration::from_millis(50);

/// Per-entry result of the parallel read_dir hook.
#[derive(Clone, Default, Debug)]
enum State {
    /// lstat failed and will be warned about.
    #[default]
    Failed,
    /// Ignored path: silently dropped, subtree pruned.
    Skipped,
    /// Ignored path the caller wants to hear about (still pruned).
    Ignored,
    Keep(Entry),
}

/// Build a gitignore-style matcher from `lines` (the lines of a virtual .gitignore
/// anchored at the scan root). Returns None when there is nothing to match.
pub fn build_ignore(lines: &[String]) -> Result<Option<Gitignore>> {
    if lines.iter().all(|l| l.trim().is_empty()) {
        return Ok(None);
    }
    let mut b = GitignoreBuilder::new("");
    for l in lines {
        b.add_line(None, l)
            .map_err(|e| anyhow::anyhow!("bad ignore pattern {l:?}: {e}"))?;
    }
    Ok(Some(b.build()?))
}

enum ScanEvent {
    Entry(Entry),
    Ignored(PathBytes),
    Warning(String),
}

type ScanChunk = Vec<ScanEvent>;

fn send_scan_chunk(
    tx: &SyncSender<ScanChunk>,
    chunk: &mut ScanChunk,
    entries_sent: &mut usize,
    entries_in_chunk: &mut usize,
) -> bool {
    if chunk.is_empty() {
        return true;
    }
    *entries_sent += *entries_in_chunk;
    *entries_in_chunk = 0;
    tx.send(std::mem::replace(chunk, Vec::with_capacity(FIRST_BATCH)))
        .is_ok()
}

fn produce_scan(
    root: std::path::PathBuf,
    ignore: Option<Gitignore>,
    report_ignored: bool,
    tx: SyncSender<ScanChunk>,
) {
    let mut chunk = Vec::with_capacity(FIRST_BATCH);
    let mut entries_sent = 1; // The root entry is already waiting in the consumer.
    let mut entries_in_chunk = 0;
    let match_root = root.clone();
    let walk = WalkDirGeneric::<((), State)>::new(&root)
        .follow_links(false)
        .skip_hidden(false)
        .process_read_dir(move |_depth, _path, _state, children| {
            for child in children.iter_mut().flatten() {
                let full = child.path();
                let Ok(entry) = lstat_entry(Vec::new(), &full) else {
                    child.client_state = State::Failed;
                    continue;
                };
                if let Some(ig) = &ignore {
                    let rel = full.strip_prefix(&match_root).unwrap_or(&full);
                    let is_dir = entry.kind == crate::proto::Kind::Dir;
                    if ig.matched(rel, is_dir).is_ignore() {
                        // Pruned: neither listed nor descended into.
                        child.read_children = None;
                        child.client_state = if report_ignored {
                            State::Ignored
                        } else {
                            State::Skipped
                        };
                        continue;
                    }
                }
                child.client_state = State::Keep(entry);
            }
        });
    for item in walk {
        let mut de = match item {
            Ok(de) => de,
            Err(e) => {
                chunk.push(ScanEvent::Warning(format!("scan: {e}")));
                if chunk.len() >= FIRST_BATCH
                    && !send_scan_chunk(&tx, &mut chunk, &mut entries_sent, &mut entries_in_chunk)
                {
                    return;
                }
                continue;
            }
        };
        // Check this before skipping the root: an unreadable root is the
        // most important warning there is (--delete relies on it).
        if let Some(e) = de
            .read_children
            .as_ref()
            .and_then(|children| children.error())
        {
            let warning = format!("scan: {}: {e}", de.path().display());
            chunk.push(ScanEvent::Warning(warning));
        }
        if de.depth == 0 {
            if chunk.len() >= FIRST_BATCH
                && !send_scan_chunk(&tx, &mut chunk, &mut entries_sent, &mut entries_in_chunk)
            {
                return;
            }
            continue;
        }
        let event = match std::mem::take(&mut de.client_state) {
            State::Keep(mut entry) => {
                let full = de.path();
                let rel = full.strip_prefix(&root).unwrap_or(&full);
                entry.path = path_bytes(rel);
                entries_in_chunk += 1;
                ScanEvent::Entry(entry)
            }
            State::Skipped => continue,
            State::Ignored => {
                let full = de.path();
                ScanEvent::Ignored(path_bytes(full.strip_prefix(&root).unwrap_or(&full)))
            }
            State::Failed => {
                ScanEvent::Warning(format!("scan: cannot stat {}", de.path().display()))
            }
        };
        chunk.push(event);
        // Publish exactly when the consumer has its first 1,000 entries. Later
        // chunks are only an amortization detail and can use the same size cap.
        let first_batch_ready =
            entries_sent < FIRST_BATCH && entries_sent + entries_in_chunk >= FIRST_BATCH;
        if (first_batch_ready || chunk.len() >= FIRST_BATCH)
            && !send_scan_chunk(&tx, &mut chunk, &mut entries_sent, &mut entries_in_chunk)
        {
            return;
        }
    }
    let _ = send_scan_chunk(&tx, &mut chunk, &mut entries_sent, &mut entries_in_chunk);
}

#[allow(clippy::too_many_arguments)]
fn receive_scan(
    rx: &Receiver<ScanChunk>,
    scan_started: Instant,
    batch: &mut Vec<Entry>,
    ignored_batch: &mut Vec<PathBytes>,
    sink: &mut dyn FnMut(Vec<Entry>) -> Result<()>,
    ignored: &mut dyn FnMut(Vec<PathBytes>) -> Result<()>,
    warn: &mut dyn FnMut(String),
) -> Result<()> {
    let mut first_batch = true;
    loop {
        if batch.len() >= BATCH {
            sink(std::mem::replace(batch, Vec::with_capacity(BATCH)))?;
            first_batch = false;
            continue;
        }
        let chunk = if first_batch && batch.len() >= FIRST_BATCH {
            let remaining = FIRST_BATCH_MAX_DELAY.saturating_sub(scan_started.elapsed());
            match rx.recv_timeout(remaining) {
                Ok(chunk) => Some(chunk),
                Err(RecvTimeoutError::Timeout) => {
                    sink(std::mem::replace(batch, Vec::with_capacity(BATCH)))?;
                    first_batch = false;
                    continue;
                }
                Err(RecvTimeoutError::Disconnected) => None,
            }
        } else {
            rx.recv().ok()
        };
        let Some(chunk) = chunk else {
            break;
        };
        for event in chunk {
            match event {
                ScanEvent::Entry(entry) => batch.push(entry),
                ScanEvent::Ignored(path) => {
                    ignored_batch.push(path);
                    if ignored_batch.len() >= BATCH {
                        ignored(std::mem::take(ignored_batch))?;
                    }
                }
                ScanEvent::Warning(message) => warn(message),
            }
        }
    }
    Ok(())
}

/// Walk `root`, calling `sink` with batches of entries (root first, as path "").
/// Every entry is reported, syq's own `.name.syq-part.<job-id>` sidecars included (the
/// planner decides what they mean). `warn` receives non-fatal errors
/// (unreadable directories etc.). `ignore` holds gitignore-style patterns
/// relative to `root`; a matching directory is pruned with its whole subtree.
/// The root itself is never ignored. With `report_ignored`, the pruned paths
/// are handed to `ignored` (in batches).
#[allow(clippy::too_many_arguments)]
pub fn scan(
    root: &Path,
    follow_root: bool,
    ignore: &[String],
    report_ignored: bool,
    sink: &mut dyn FnMut(Vec<Entry>) -> Result<()>,
    ignored: &mut dyn FnMut(Vec<PathBytes>) -> Result<()>,
    warn: &mut dyn FnMut(String),
) -> Result<()> {
    let ignore = build_ignore(ignore)?;
    let md = if follow_root {
        fs::metadata(root)
    } else {
        fs::symlink_metadata(root)
    }
    .with_context(|| format!("stat {}", root.display()))?;
    let mut root_entry = crate::fsops::entry_from_meta(Vec::new(), root, &md);
    if follow_root && md.is_dir() {
        root_entry.kind = crate::proto::Kind::Dir;
        root_entry.link = None;
    }
    if !md.is_dir() {
        return sink(vec![root_entry]);
    }
    // Preserve bounded first-byte progress on slow/NFS walks without splitting
    // a small, fast scan into several serialized WAN planning round trips. The
    // producer is separate so a stalled metadata operation cannot hide a ready
    // first batch past its deadline; the bounded channel limits scan-ahead.
    let mut batch = Vec::with_capacity(FIRST_BATCH);
    let scan_started = Instant::now();
    batch.push(root_entry);
    let mut ignored_batch: Vec<PathBytes> = Vec::new();
    let root_buf = root.to_path_buf();
    let (tx, rx) = mpsc::sync_channel(BATCH / FIRST_BATCH);
    let producer = std::thread::Builder::new()
        .name("syq-scan-producer".into())
        .spawn(move || produce_scan(root_buf, ignore, report_ignored, tx))
        .context("start scan producer")?;
    let received = receive_scan(
        &rx,
        scan_started,
        &mut batch,
        &mut ignored_batch,
        sink,
        ignored,
        warn,
    );
    drop(rx);
    let producer_panicked = producer.join().is_err();
    received?;
    if producer_panicked {
        anyhow::bail!("scan producer panicked");
    }
    if !batch.is_empty() {
        sink(batch)?;
    }
    if !ignored_batch.is_empty() {
        ignored(ignored_batch)?;
    }
    Ok(())
}

/// Descriptor-relative receiver walk used for signed grants. The enrolled root
/// is reopened by identity and no descendant symlink is followed.
#[allow(clippy::too_many_arguments)]
pub fn scan_rooted(
    requested_root: &[u8],
    follow_root: bool,
    ignore: &[String],
    report_ignored: bool,
    guard: &ContainerGuard,
    sink: &mut dyn FnMut(Vec<Entry>) -> Result<()>,
    ignored: &mut dyn FnMut(Vec<PathBytes>) -> Result<()>,
    warn: &mut dyn FnMut(String),
) -> Result<()> {
    if follow_root {
        anyhow::bail!("a signed receiver never follows a destination root symlink");
    }
    let root_path = crate::fsops::resolve(&guard.root);
    let target = crate::fsops::resolve(requested_root);
    let target_relative = target.strip_prefix(&root_path).with_context(|| {
        format!(
            "scan target {} is outside enrolled root {}",
            target.display(),
            root_path.display()
        )
    })?;
    let target_relative = RelativePath::new(target_relative.as_os_str().as_bytes())?;
    let root = Root::open_verified(
        &root_path,
        RootIdentity {
            dev: guard.dev,
            ino: guard.ino,
        },
    )?;
    let metadata = root.metadata(&target_relative)?;
    let root_entry = crate::fsops::rooted_entry(&root, &target_relative, Vec::new(), metadata)?;
    if root_entry.kind != crate::proto::Kind::Dir {
        return sink(vec![root_entry]);
    }

    let matcher = build_ignore(ignore)?;
    let mut batch = vec![root_entry];
    let mut ignored_batch = Vec::new();
    let mut directories: Vec<PathBytes> = vec![Vec::new()];
    while let Some(relative_to_scan) = directories.pop() {
        let full_relative = crate::fsops::join(
            target_relative_path_bytes(&target, &root_path)?.as_slice(),
            &relative_to_scan,
        );
        let directory = RelativePath::new(&full_relative)?;
        let mut names = match root.read_directory(&directory) {
            Ok(names) => names,
            Err(error) => {
                warn(format!(
                    "scan: {}: {error:#}",
                    String::from_utf8_lossy(&relative_to_scan)
                ));
                continue;
            }
        };
        names.sort();
        let mut child_directories = Vec::new();
        for name in names {
            let relative = crate::fsops::join(&relative_to_scan, &name);
            let full_relative = crate::fsops::join(
                target_relative_path_bytes(&target, &root_path)?.as_slice(),
                &relative,
            );
            let child = RelativePath::new(&full_relative)?;
            let metadata = match root.metadata(&child) {
                Ok(metadata) => metadata,
                Err(error) => {
                    warn(format!(
                        "scan: {}: {error:#}",
                        String::from_utf8_lossy(&relative)
                    ));
                    continue;
                }
            };
            let entry = crate::fsops::rooted_entry(&root, &child, relative.clone(), metadata)?;
            let is_directory = entry.kind == crate::proto::Kind::Dir;
            if matcher.as_ref().is_some_and(|matcher| {
                matcher
                    .matched(
                        Path::new(std::ffi::OsStr::from_bytes(&relative)),
                        is_directory,
                    )
                    .is_ignore()
            }) {
                if report_ignored {
                    ignored_batch.push(relative);
                    if ignored_batch.len() >= BATCH {
                        ignored(std::mem::take(&mut ignored_batch))?;
                    }
                }
                continue;
            }
            if is_directory {
                child_directories.push(relative.clone());
            }
            batch.push(entry);
            if batch.len() >= BATCH {
                sink(std::mem::replace(&mut batch, Vec::with_capacity(BATCH)))?;
            }
        }
        // Reverse before pushing so byte-sorted directory order is retained.
        child_directories.reverse();
        directories.extend(child_directories);
    }
    if !batch.is_empty() {
        sink(batch)?;
    }
    if !ignored_batch.is_empty() {
        ignored(ignored_batch)?;
    }
    Ok(())
}

fn target_relative_path_bytes(target: &Path, root: &Path) -> Result<PathBytes> {
    Ok(target.strip_prefix(root)?.as_os_str().as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> Entry {
        Entry {
            path: Vec::new(),
            kind: crate::proto::Kind::File,
            size: 1,
            mtime: 0,
            mtime_nsec: 0,
            mode: 0o644,
            uid: 0,
            gid: 0,
            rdev: 0,
            dev: 0,
            ino: 0,
            ctime: 0,
            ctime_nsec: 0,
            link: None,
        }
    }

    #[test]
    fn first_batch_deadline_flushes_while_producer_is_stalled() {
        let (tx, rx) = mpsc::sync_channel(BATCH);
        let (release_tx, release_rx) = mpsc::channel();
        let producer = std::thread::spawn(move || {
            tx.send(
                (1..FIRST_BATCH)
                    .map(|_| ScanEvent::Entry(entry()))
                    .collect(),
            )
            .unwrap();
            release_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("ready first batch was not flushed while producer stalled");
        });
        let mut batch = vec![entry()];
        let mut ignored_batch = Vec::new();
        let mut sizes = Vec::new();
        receive_scan(
            &rx,
            Instant::now(),
            &mut batch,
            &mut ignored_batch,
            &mut |entries| {
                sizes.push(entries.len());
                release_tx.send(()).unwrap();
                Ok(())
            },
            &mut |_| Ok(()),
            &mut |_| {},
        )
        .unwrap();
        producer.join().unwrap();
        assert_eq!(sizes, [FIRST_BATCH]);
        assert!(batch.is_empty());
        assert!(ignored_batch.is_empty());
    }

    #[test]
    fn fast_small_scan_reaches_eof_as_one_planning_batch() {
        let (tx, rx) = mpsc::sync_channel(BATCH / FIRST_BATCH);
        tx.send(
            (1..FIRST_BATCH)
                .map(|_| ScanEvent::Entry(entry()))
                .collect(),
        )
        .unwrap();
        tx.send(
            (FIRST_BATCH..2000)
                .map(|_| ScanEvent::Entry(entry()))
                .collect(),
        )
        .unwrap();
        drop(tx);

        let mut batch = vec![entry()];
        let mut ignored_batch = Vec::new();
        let mut sizes = Vec::new();
        receive_scan(
            &rx,
            Instant::now(),
            &mut batch,
            &mut ignored_batch,
            &mut |entries| {
                sizes.push(entries.len());
                Ok(())
            },
            &mut |_| Ok(()),
            &mut |_| {},
        )
        .unwrap();

        assert!(sizes.is_empty(), "fast EOF should not flush at 1,000");
        assert_eq!(batch.len(), 2000);
    }
}

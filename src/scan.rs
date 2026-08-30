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

pub const BATCH: usize = 1000;

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
    let mut batch = Vec::with_capacity(BATCH);
    batch.push(root_entry);
    let mut ignored_batch: Vec<PathBytes> = Vec::new();

    let root_buf = root.to_path_buf();
    let walk = WalkDirGeneric::<((), State)>::new(root)
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
                    let rel = full.strip_prefix(&root_buf).unwrap_or(&full);
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
                warn(format!("scan: {e}"));
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
            warn(format!("scan: {}: {e}", de.path().display()));
        }
        if de.depth == 0 {
            continue;
        }
        let mut entry = match std::mem::take(&mut de.client_state) {
            State::Keep(e) => e,
            State::Skipped => continue,
            State::Ignored => {
                let full = de.path();
                ignored_batch.push(path_bytes(full.strip_prefix(root).unwrap_or(&full)));
                if ignored_batch.len() >= BATCH {
                    ignored(std::mem::take(&mut ignored_batch))?;
                }
                continue;
            }
            State::Failed => {
                warn(format!("scan: cannot stat {}", de.path().display()));
                continue;
            }
        };
        let full = de.path();
        let rel = full.strip_prefix(root).unwrap_or(&full);
        entry.path = path_bytes(rel);
        batch.push(entry);
        if batch.len() >= BATCH {
            sink(std::mem::replace(&mut batch, Vec::with_capacity(BATCH)))?;
        }
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

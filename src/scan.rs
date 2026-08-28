//! Parallel directory walk producing `Entry` batches in parent-before-child order.

use crate::fsops::{lstat_entry, path_bytes};
use crate::proto::Entry;
use anyhow::{Context, Result};
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use jwalk::WalkDirGeneric;
use std::fs;
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
/// `warn` receives non-fatal errors (unreadable directories etc.).
/// `ignore` holds gitignore-style patterns relative to `root`; a matching directory
/// is pruned with its whole subtree. The root itself is never ignored.
pub fn scan(
    root: &Path,
    follow_root: bool,
    ignore: &[String],
    sink: &mut dyn FnMut(Vec<Entry>) -> Result<()>,
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
                        child.client_state = State::Skipped;
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
        if de.depth == 0 {
            continue;
        }
        if let Some(e) = de
            .read_children
            .as_ref()
            .and_then(|children| children.error())
        {
            warn(format!("scan: {}: {e}", de.path().display()));
        }
        let mut entry = match std::mem::take(&mut de.client_state) {
            State::Keep(e) => e,
            State::Skipped => continue,
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
    Ok(())
}

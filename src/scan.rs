//! Parallel directory walk producing `Entry` batches in parent-before-child order.

use crate::fsops::{is_partial_name, lstat_entry, path_bytes};
use crate::proto::Entry;
use anyhow::{Context, Result};
use jwalk::WalkDirGeneric;
use std::fs;
use std::path::Path;

pub const BATCH: usize = 1000;

/// Walk `root`, calling `sink` with batches of entries (root first, as path "").
/// `warn` receives non-fatal errors (unreadable directories etc.).
pub fn scan(
    root: &Path,
    follow_root: bool,
    sink: &mut dyn FnMut(Vec<Entry>) -> Result<()>,
    warn: &mut dyn FnMut(String),
) -> Result<()> {
    let md = if follow_root { fs::metadata(root) } else { fs::symlink_metadata(root) }
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

    let walk = WalkDirGeneric::<((), Option<Entry>)>::new(root)
        .follow_links(false)
        .skip_hidden(false)
        .process_read_dir(|_depth, _path, _state, children| {
            for child in children.iter_mut().flatten() {
                if is_partial_name(&child.file_name) {
                    child.read_children_path = None;
                    child.client_state = None;
                    continue;
                }
                let full = child.path();
                child.client_state = lstat_entry(Vec::new(), &full).ok();
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
        if let Some(e) = de.read_children_error.take() {
            warn(format!("scan: {}: {e}", de.path().display()));
        }
        let Some(mut entry) = de.client_state.take() else {
            if !is_partial_name(&de.file_name) {
                warn(format!("scan: cannot stat {}", de.path().display()));
            }
            continue;
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

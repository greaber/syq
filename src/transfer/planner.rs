use super::*;

pub(super) struct Planner<'a> {
    /// Bounded parent cache, only for newly created rsync leaves without -p.
    pub(super) directory_expression_sources: std::collections::HashMap<PathBytes, PathBytes>,
    pub(super) unselected_dirs: std::collections::HashSet<PathBytes>,
    pub(super) dst: &'a mut dyn Conn,
    pub(super) sched: &'a Sched,
    pub(super) progress: &'a Progress,
    pub(super) opts: &'a Opts,
    /// Compile once, only when a scan selects a non-directory root.
    /// The outer None means uninitialized; Some(None) means no ignore rules.
    pub(super) selected_file_ignore: Option<Option<ignore::gitignore::Gitignore>>,
    /// Capability reported by the destination receiver's authenticated
    /// handshake. The coordinator may be running on a different platform.
    pub(super) destination_supports_confined_socket_nodes: bool,
    pub(super) destination_metadata_platform: String,
    /// Destination paths claimed by source entries (see `Claim`).
    pub(super) dst_seen: std::collections::HashMap<PathBytes, Claim>,
    /// Directories this run will not create — --existing: they don't exist
    /// (or aren't directories); --ignore-existing: an existing non-directory
    /// sits at their path. Nothing under them is touched.
    pub(super) missing_dirs: std::collections::HashSet<PathBytes>,
    /// Directory copies blocked by a destination file or symlink. The conflict
    /// is reported at the parent; its descendants must not be copied.
    pub(super) blocked_directory_paths: std::collections::HashSet<PathBytes>,
    /// The destination was missing or empty at preflight. Its root may
    /// still have metadata to preserve; only descendants are known absent.
    pub(super) destination_children_known_missing: bool,
    /// The destination root itself was missing at preflight. Until this copy
    /// creates it, planning treats it as absent without another lookup.
    pub(super) destination_root_known_missing: bool,
    /// Called after jobs are queued; starts streaming only when useful work exists.
    pub(super) start_streaming: &'a dyn Fn(),
    pub(super) source_partials: u64,
    pub(super) collision: bool,
    /// (dst path, meta, flags, depth, root condition) for directories,
    /// applied deepest-first at the end.
    pub(super) deferred: Vec<(PathBytes, Meta, u8, usize, TargetCondition)>,
    /// A source scan reported a non-fatal problem (unreadable directory, ...).
    pub(super) scan_warned: bool,
    /// --max-delete stopped the deletions (exit 25, as rsync).
    pub(super) max_delete_hit: bool,
    /// The destination walk reported errors: an unreadable directory there
    /// looks empty and would be rmdir'd over its unknown contents, so
    /// deletion is skipped entirely (the errors already count).
    pub(super) delete_walk_failed: bool,
    /// Several sources: mapped batches waiting for all scans to finish
    /// (see `Mapped`). None with a single source, where batches stream.
    pub(super) buffer: Option<Vec<Mapped>>,
    /// A missing or observed-empty target has no old payload to release and
    /// cannot contain descendant mounts. Its selected source population gives
    /// us one useful whole-copy capacity sanity check.
    pub(super) fresh_capacity: Option<FreshCapacityPlan>,
    /// --mapping: per-destination source override. A manifest entry's `path`
    /// carries the destination-relative path so claims, ordering, and job
    /// naming work unchanged; the read side looks the actual source up here.
    pub(super) src_overrides: std::collections::HashMap<PathBytes, PathBytes>,
    /// --mapping: full destination paths of implicit ancestor directories no
    /// entry names, created with default metadata (no deferred stamping).
    pub(super) implicit_dirs: std::collections::HashSet<PathBytes>,
    /// Manifest-relative parents with their own entry, even in a later batch.
    /// The signed mapping permits replacing these, unlike implicit parents.
    pub(super) mapping_explicit_parents: std::collections::HashSet<PathBytes>,
    /// Observed obstructions at implicit parents fail only mapped descendants.
    pub(super) blocked_mapping_parents: std::collections::HashSet<PathBytes>,
    /// One pending destination container, including a file-only copy's parent.
    pub(super) container_access: Option<(PathBytes, TargetCondition)>,
    /// Whether a destination container that lacks owner access is widened
    /// (`widens_destination_container`), decided once for every root.
    pub(super) widen_container: bool,
    /// Original receiver modes, only for directories actually widened.
    pub(super) directory_restorations:
        std::collections::HashMap<PathBytes, crate::proto::DirectoryMode>,
    /// The receiving account: None until asked, Some(None) for root, which
    /// needs no access changes.
    pub(super) receiver_uid: Option<Option<u32>>,
    /// The destination directory's own entry when its owner lacks write or
    /// search permission, checked with the first batch.
    pub(super) root_access_check: Option<Entry>,
    /// Directories already reported, as needing access or not inspected:
    /// later batches can meet them again.
    pub(super) access_reported: std::collections::HashSet<PathBytes>,
    /// apply_deferred has tried the saved modes once and reported failures;
    /// a retry when the planner is dropped does not report them again.
    pub(super) restorations_attempted: bool,
    /// Directories this copy created may receive metadata from later sources.
    pub(super) created_dirs: std::collections::HashSet<PathBytes>,
    /// A new destination root created private until a contents source's
    /// metadata reaches it: the mode it would otherwise have been created
    /// with, for when that metadata sets no mode.
    pub(super) private_root: Option<u32>,
    /// The mode `syq rsync` creates a new destination root with, from its
    /// contents source, when the planner creates it after scanning.
    pub(super) root_source_mode: Option<u32>,
    /// This run consumes a --mapping manifest (identity entries included).
    pub(super) mapping_mode: bool,
    /// Placement root and receiver-enforced conditions for native operations.
    pub(super) dst_root: PathBytes,
    pub(super) exact_condition: TargetCondition,
    pub(super) mutation_root_condition: TargetCondition,
    pub(super) container_guard: Option<ContainerGuard>,
    pub(super) guard_containers: bool,
    /// A missing retained operator directory: (request prefix, creation
    /// condition, whether it is the destination root). Create it only after
    /// final-destination conflict checks. Restricted transfers use the
    /// same slot only for their missing destination root.
    pub(super) create_root: Option<(PathBytes, TargetCondition, bool)>,
    pub(super) destination_anchor: &'a DestinationAnchorSlot,
    pub(super) use_operator_anchor: bool,
    /// --files-from: listed directories are created even without -r (which
    /// then only decides whether their contents are walked).
    pub(super) keep_dirs: bool,
    /// (destination directory, its path relative to the transfer root) for every
    /// directory source; --delete removes extras inside these.
    pub(super) delete_roots: Vec<(PathBytes, PathBytes)>,
    pub(super) deletes: Deletes,
    pub(super) dry_run_changes: DryRunChanges,
    /// Descriptor-session capability for the source currently feeding
    /// planner batches. Buffered jobs retain their own derived path.
    pub(super) active_source: Option<RegisteredPath>,
    pub(super) hardlinks: super::hardlinks::Hardlinks,
}

/// What a source entry asserts about its destination path. Two dirs merge;
/// a dir against a leaf, or two leaves, conflict. A `Weak` claim comes from
/// an entry syq will not transfer (a leaf excluded by --where, a symlink
/// without -l, a special file without -D, an unknown type): it still marks
/// the path as the source's — so --delete leaves it alone — but yields to any
/// real claim, so two sources overlapping on such an entry are not a conflict.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Claim {
    Dir,
    /// A regular file syq intends to write; its identity, so a second
    /// claimant can be checked against "is one of us the destination file?".
    File {
        dev: u64,
        ino: u64,
    },
    /// A symlink or special file syq intends to create.
    Leaf,
    Weak,
}

/// A failed entry's result identity, with a source path only in mapping mode.
pub(super) struct FailedEntry<'a> {
    pub(super) dst: &'a [u8],
    pub(super) src: Option<&'a [u8]>,
    pub(super) kind: Option<DeclaredKind>,
}

/// Keep destination-only candidates, borrowing source claim paths instead of
/// copying every destination spelling. Exact matches are discarded as scanned.
pub(super) struct PruneWalk<'a> {
    pub(super) seen: &'a std::collections::HashMap<PathBytes, Claim>,
    pub(super) unmatched: std::collections::HashSet<&'a PathBytes>,
    pub(super) entries: Vec<Entry>,
    pub(super) shielded: std::collections::HashSet<PathBytes>,
    pub(super) recovery_parents: std::collections::HashSet<PathBytes>,
}

impl<'a> PruneWalk<'a> {
    pub(super) fn new(
        seen: &'a std::collections::HashMap<PathBytes, Claim>,
        root: &[u8],
        sorted: Option<&[&'a PathBytes]>,
    ) -> Self {
        Self {
            seen,
            unmatched: match sorted {
                Some(paths) => {
                    let mut prefix = root.to_vec();
                    if !prefix.ends_with(b"/") {
                        prefix.push(b'/');
                    }
                    let start = paths.partition_point(|path| path.as_slice() < prefix.as_slice());
                    paths[start..]
                        .iter()
                        .copied()
                        .take_while(|path| path.starts_with(&prefix))
                        .collect()
                }
                None => seen
                    .keys()
                    .filter(|path| path_is_inside(path, root))
                    .collect(),
            },
            entries: Vec::new(),
            shielded: Default::default(),
            recovery_parents: Default::default(),
        }
    }

    pub(super) fn push(&mut self, mut entry: Entry, root: &[u8], nested: &[PathBytes]) {
        if entry.path.is_empty() {
            return;
        }
        let full = join(root, &entry.path);
        if entry
            .path
            .split(|byte| *byte == b'/')
            .any(|name| is_recovery_name(OsStr::from_bytes(name)))
        {
            self.recovery_parents
                .extend(ancestor_prefixes(&full).map(<[u8]>::to_vec));
            return;
        }
        self.unmatched.remove(&full);
        if nested
            .iter()
            .any(|n| *n == full || path_is_inside(&full, n))
        {
            return;
        }
        if let Some(claim) = self.seen.get(&full) {
            if *claim != Claim::Dir && entry.kind == Kind::Dir {
                self.shielded.insert(full);
            }
            return;
        }
        entry.path = full;
        self.entries.push(entry);
    }

    pub(super) fn finish_scan(&mut self, root: &[u8]) {
        // Apply exact directory shields after all batches, independently of
        // scan order. Alias directory shields are applied after lookup.
        self.entries
            .retain(|entry| !Planner::under_any(&self.shielded, &entry.path, root));
    }
}

pub(super) fn lookup_prune_aliases(
    conn: &mut dyn Conn,
    walk: &PruneWalk<'_>,
    guard: Option<&ContainerGuard>,
) -> Result<std::collections::HashMap<(u64, u64), Claim>> {
    let mut aliases = std::collections::HashMap::new();
    if walk.entries.is_empty() {
        return Ok(aliases);
    }
    let candidates: std::collections::HashSet<_> = walk
        .entries
        .iter()
        .map(|entry| (entry.dev, entry.ino))
        .collect();
    let mut unmatched = walk.unmatched.iter();
    // Remote response queues hold at least this many replies, even when the
    // file-data pipeline is configured smaller. Local calls execute in send.
    let depth = if conn.supports_request_pipelining() {
        crate::transfer_tuning::DEFAULT_PIPELINE_DEPTH
    } else {
        1
    };
    let mut pending = std::collections::VecDeque::new();
    let mut exhausted = false;
    loop {
        while !exhausted && pending.len() < depth {
            let paths: Vec<_> = unmatched
                .by_ref()
                .take(512)
                .map(|path| (**path).clone())
                .collect();
            if paths.is_empty() {
                exhausted = true;
                break;
            }
            if let Err(error) = conn.send(Request::PruneLookup {
                paths: paths.clone(),
                guard: guard.cloned(),
            }) {
                if !conn.is_dead() {
                    crate::conn::drain_range_replies(conn, pending.len(), "inspect prune aliases")?;
                }
                return Err(error);
            }
            pending.push_back(paths);
        }
        let Some(paths) = pending.pop_front() else {
            break;
        };
        let response = conn.recv()?;
        let stats = (|| -> Result<_> {
            match ok(response, "inspect prune aliases")? {
                Response::Stats(stats) if stats.len() == paths.len() => Ok(stats),
                Response::Stats(stats) => bail!(
                    "stat reply count {} does not match request count {}",
                    stats.len(),
                    paths.len()
                ),
                other => bail!("unexpected prune lookup response {other:?}"),
            }
        })();
        let stats = match stats {
            Ok(stats) => stats,
            Err(error) => {
                // Keep the shared control connection at a request boundary.
                crate::conn::drain_range_replies(conn, pending.len(), "inspect prune aliases")?;
                return Err(error);
            }
        };
        for (path, entry) in paths.iter().zip(stats) {
            if let Some(entry) = entry {
                let identity = (entry.dev, entry.ino);
                if candidates.contains(&identity) {
                    aliases.insert(identity, walk.seen[path]);
                }
            }
        }
    }
    Ok(aliases)
}

pub(super) fn path_is_inside(path: &[u8], root: &[u8]) -> bool {
    path.starts_with(root) && (root.ends_with(b"/") || path.get(root.len()) == Some(&b'/'))
}

/// Everything the planner decided about one source entry, made once in the
/// mapping loop so the directory pass and the per-kind arms can't disagree.
pub(super) struct Planned {
    pub(super) src: PathBytes,
    pub(super) source: RegisteredPath,
    pub(super) dst: PathBytes,
    pub(super) dst_rel: PathBytes,
    pub(super) rel: String,
    pub(super) e: Entry,
    /// Another source already claimed `dst` as a regular file. Resolved once
    /// the destination is stat'ed: fine if that file *is* this file (a copy
    /// onto itself), a collision otherwise.
    pub(super) contested: bool,
}

/// A directory that passed the filters, with what the destination held at
/// its path: destination path, path below the destination root, source
/// entry, destination stat.
type PlannedDir = (PathBytes, PathBytes, Entry, Option<Entry>);

/// Directory metadata applied before a batch's contents (see
/// `Planner::early_directory_metadata`).
#[derive(Default)]
struct EarlyMetadata {
    /// For directories that already exist, sent before any creation.
    existing: Vec<Op>,
    /// For new directories and a private root, sent with the creations.
    created: Vec<Op>,
    /// A private destination root to open, with owner access, to the mode
    /// creating it from this proposal would have given it.
    root_default: Option<u32>,
}

/// One scanned batch after the mapping loop: every destination claimed,
/// nothing touched yet. With several sources these are held until all of
/// them have been scanned, so a conflict between sources is reported before
/// the destination is changed at all.
pub(super) struct Mapped {
    directory_expression_sources: std::collections::HashMap<PathBytes, PathBytes>,
    pub(super) dst_root: PathBytes,
    pub(super) dirs: Vec<(PathBytes, PathBytes, Entry)>,
    pub(super) others: Vec<Planned>,
    pub(super) dir_stats: Option<Vec<Option<Entry>>>,
    pub(super) other_stats: Option<std::collections::HashMap<PathBytes, Option<Entry>>>,
}

/// What --delete found on the destination that the source doesn't have.
#[derive(Default)]
pub(super) struct Deletes {
    /// (path, display name, record kind) of files, symlinks and specials to
    /// unlink; the kind label keeps deletion records truthful.
    pub(super) leaves: Vec<(PathBytes, String, &'static str)>,
    /// Directories by depth, removed deepest-first once they are empty.
    pub(super) dirs: std::collections::BTreeMap<usize, Vec<(PathBytes, String, &'static str)>>,
    /// Owned destination-only directories without owner write or search
    /// permission that these removals need; widened only once they run.
    pub(super) access: Vec<(PathBytes, TargetCondition)>,
}

impl Deletes {
    pub(super) fn len(&self) -> u64 {
        self.leaves.len() as u64
            + self
                .dirs
                .values()
                .map(|items| items.len() as u64)
                .sum::<u64>()
    }
}

impl Drop for Planner<'_> {
    fn drop(&mut self) {
        // Early setup, planning or pruning errors must not bypass permission
        // restoration. Normal completion has already restored these; a mode
        // whose restoration failed, already reported, gets one quiet retry.
        if !self.directory_restorations.is_empty() {
            let reported = self.restorations_attempted;
            if let Err(error) = self.apply_deferred(true) {
                if !reported {
                    self.progress
                        .error(&format!("syq: restore directory permissions: {error:#}"));
                }
            }
        }
    }
}

impl Planner<'_> {
    pub(super) fn record_fresh_entry(
        &mut self,
        dst: &[u8],
        dst_rel: &[u8],
        src_root: &[u8],
        entry: &Entry,
        new_object: bool,
    ) -> Result<()> {
        if !new_object || self.fresh_capacity.is_none() {
            return Ok(());
        }
        let included = match entry.kind {
            Kind::Dir => true,
            Kind::File => {
                self.opts
                    .max_size
                    .is_none_or(|maximum| entry.size <= maximum)
                    && self
                        .opts
                        .min_size
                        .is_none_or(|minimum| entry.size >= minimum)
            }
            Kind::Symlink => self.opts.links,
            Kind::Fifo | Kind::Socket | Kind::CharDev | Kind::BlockDev => {
                self.opts.devices
                    && special_creation_supported(
                        self.destination_supports_confined_socket_nodes,
                        entry.kind,
                    )
            }
            Kind::Other => false,
        };
        if !included {
            return Ok(());
        }
        // A fresh target has no existing leaves. Directory containers are
        // still needed even when --copy-if excludes their source metadata.
        if entry.kind != Kind::Dir && self.opts.expressions.update.is_some() {
            let relative = self
                .src_overrides
                .get(&entry.path)
                .map(Vec::as_slice)
                .unwrap_or(&entry.path);
            if !self
                .opts
                .expressions
                .permits(
                    &crate::expression::File::from_entry(entry),
                    crate::expression::source_path(src_root, relative),
                    &crate::expression::File::default(),
                    crate::expression::source_path(dst, dst_rel),
                )
                .with_context(|| format!("capacity estimate for {}", display(dst)))?
            {
                return Ok(());
            }
        }
        let reuses_existing_root = dst == self.dst_root && entry.kind == Kind::Dir;
        let Some(plan) = &mut self.fresh_capacity else {
            return Ok(());
        };
        if self.opts.hardlinks
            && entry.kind == Kind::File
            && entry.nlink > 1
            && !plan.hardlink_inodes.insert((entry.dev, entry.ino))
        {
            return Ok(());
        }
        // When source contents map directly into an existing empty container,
        // the source's root directory reuses that one existing inode.
        if !(plan.root_existed && reuses_existing_root) {
            match plan.objects.checked_add(1) {
                Some(objects) => plan.objects = objects,
                None => plan.overflowed = true,
            }
        }
        if entry.kind == Kind::File {
            match plan.logical_bytes.checked_add(entry.size) {
                Some(bytes) => plan.logical_bytes = bytes,
                None => plan.overflowed = true,
            }
        }
        Ok(())
    }

    pub(super) fn assess_fresh_capacity(&mut self) -> Result<Option<FreshCapacityAssessment>> {
        let Some(plan) = self.fresh_capacity.as_mut() else {
            return Ok(None);
        };
        // The completed estimate no longer needs the scan's hardlink set.
        plan.hardlink_inodes = Default::default();
        if plan.overflowed {
            return Err(std::io::Error::from_raw_os_error(libc::ENOSPC)).context(
                "fresh destination logical size or object count exceeds supported limits",
            );
        }
        let response = self.dst.call(Request::DestinationFilesystemInfo {
            check_empty: false,
            target: plan.target.clone(),
        })?;
        let info = match response {
            Response::DestinationFilesystemInfo(info) if info.device == plan.device => info,
            Response::DestinationFilesystemInfo(_) => return Ok(None),
            // Capacity inspection is a best-effort optimization. Actual
            // allocations remain authoritative when a filesystem cannot
            // expose useful counters.
            Response::EndpointError(_) | Response::Err(_) => return Ok(None),
            other => bail!("unexpected response {other:?}"),
        };
        Ok(Some(FreshCapacityAssessment {
            logical_bytes: plan.logical_bytes,
            check_bytes: !self.opts.sparse,
            objects: plan.objects,
            available_bytes: info.available_bytes,
            available_inodes: info.available_inodes,
        }))
    }

    pub(super) fn exact_condition_for(&self, path: &[u8]) -> TargetCondition {
        if path == self.dst_root {
            self.exact_condition
        } else {
            TargetCondition::Any
        }
    }

    pub(super) fn metadata_condition_for(&self, path: &[u8]) -> TargetCondition {
        match self.exact_condition_for(path) {
            condition @ TargetCondition::Matches { .. } => condition,
            TargetCondition::MatchesFingerprint { dev, ino, .. } => {
                TargetCondition::Matches { dev, ino }
            }
            TargetCondition::Any | TargetCondition::Absent => TargetCondition::Any,
        }
    }

    pub(super) fn assert_mutation_root(&mut self) -> Result<Option<Entry>> {
        let (dev, ino) = match self.mutation_root_condition {
            TargetCondition::Matches { dev, ino }
            | TargetCondition::MatchesFingerprint { dev, ino, .. } => (dev, ino),
            TargetCondition::Any | TargetCondition::Absent => return Ok(None),
        };
        // Only identity matters here. A plain lookup avoids the rich-metadata
        // capture that preserving ACLs or xattrs adds to ordinary stats: its
        // change guard trips on entries this copy's workers are adding to the
        // root while later batches are still being planned.
        let current = match ok(
            self.dst.call(Request::PruneLookup {
                paths: vec![self.dst_root.clone()],
                guard: None,
            })?,
            "inspect destination root",
        )? {
            Response::Stats(mut entries) if entries.len() == 1 => entries.pop().flatten(),
            other => bail!("unexpected destination inspection response {other:?}"),
        };
        match current {
            Some(entry) if entry.dev == dev && entry.ino == ino => Ok(Some(entry)),
            _ => bail!(
                "target {} changed after the placement precondition was checked",
                display(&self.dst_root)
            ),
        }
    }

    fn selected_file_is_ignored(&mut self, path: &[u8]) -> Result<bool> {
        if self.selected_file_ignore.is_none() {
            self.selected_file_ignore = Some(crate::scan::build_ignore(&self.opts.ignore)?);
        }
        Ok(crate::scan::selected_file_is_ignored(
            self.selected_file_ignore.as_ref().unwrap().as_ref(),
            path,
        ))
    }

    pub(super) fn scan_source(
        &mut self,
        src: &mut dyn Conn,
        src_root: &[u8],
        source: SourceMapping<'_>,
        destination: DestinationRoot<'_>,
    ) -> Result<DryRunMapping> {
        let SourceMapping {
            follow_root,
            contents,
            selection,
            sub,
        } = source;
        let dst_root = destination.path;
        let dst_is_dir = destination.is_container;
        let dst_existed = destination.existed;
        let mut first = true;
        let mut sub = sub.to_vec();
        let mut skip_all = false;
        let mut mapping = None;
        let ignore = self.opts.ignore.clone();
        let source = self
            .active_source
            .clone()
            .context("registered source reference was not initialized")?;
        scan_into_planner(
            self,
            src,
            src_root,
            Some(&source),
            follow_root,
            &ignore,
            |pl, batch| {
                if skip_all {
                    return Ok(());
                }
                if first {
                    first = false;
                    if let Some(root) = batch.first() {
                        validate_native_source_type(src_root, selection, root.kind)?;
                        if destination.exact && destination.entry_is_dir && root.kind != Kind::Dir {
                            bail!(
                            "destination {} is an existing directory; cannot replace it with non-directory source {}",
                            display(dst_root),
                            display(src_root)
                        );
                        }
                        if pl.opts.dry_run
                            && root.kind == Kind::Dir
                            && !contents
                            && pl.opts.recursive
                            && dst_existed
                            && !destination.entry_is_dir
                            && !destination.exact
                            && !pl.opts.existing
                        {
                            bail!(
                            "destination {} is not a directory; cannot place directory {} inside it",
                            display(dst_root),
                            display(src_root)
                        );
                        }
                        if root.kind != Kind::Dir && !dst_is_dir {
                            sub.clear();
                        }
                        mapping = Some(DryRunMapping {
                            target: join(dst_root, &sub),
                            semantics: if destination.exact {
                                "exact destination path"
                            } else {
                                match (root.kind, contents, dst_is_dir) {
                                    (Kind::Dir, true, _) => "directory contents",
                                    (Kind::Dir, false, _) => "directory as child",
                                    (_, _, true) => "entry inside destination directory",
                                    _ => "exact destination path",
                                }
                            },
                        });
                        if root.kind != Kind::Dir && pl.selected_file_is_ignored(src_root)? {
                            pl.progress.paths_ignored.fetch_add(1, Relaxed);
                            if !pl.opts.delete_excluded {
                                pl.dst_seen
                                    .entry(join(dst_root, &sub))
                                    .or_insert(Claim::Weak);
                            }
                            skip_all = true;
                            return Ok(());
                        }
                        if root.kind == Kind::Dir && !pl.opts.recursive {
                            if !pl.opts.quiet {
                                pl.progress
                                    .eprintln(&format!("skipping directory {}", display(src_root)));
                            }
                            skip_all = true;
                            return Ok(());
                        }
                        if root.kind == Kind::Dir {
                            pl.delete_roots.push((join(dst_root, &sub), sub.clone()));
                        }
                    }
                }
                pl.progress.scanned.fetch_add(batch.len() as u64, Relaxed);
                pl.handle_batch(batch, src_root, &sub, dst_root)
            },
        )?;
        mapping.ok_or_else(|| anyhow::anyhow!("source scan returned no root entry"))
    }

    /// --files-from: instead of walking the source, stat each listed path (and
    /// the directories leading to it) and feed them to the planner as if a scan
    /// had produced them. Implied parents are descriptor-relative and never
    /// traversed through symlinks, including with `--insecure-links`. Listed directories —
    /// only those, not implied parents — are walked with an explicit -r.
    pub(super) fn scan_files_from(
        &mut self,
        src: &mut dyn Conn,
        src_root: &[u8],
        dst_root: &[u8],
        lines: &[PathBytes],
        recurse: bool,
    ) -> Result<()> {
        use std::collections::{HashMap, HashSet};
        let source_base = self
            .active_source
            .clone()
            .context("registered source reference was not initialized")?;
        // Validate the root but never plan it: it isn't in the list, so an
        // existing destination is not stamped with source-root metadata.
        let mut source_root_stat = stat_many_registered(
            src,
            vec![src_root.to_vec()],
            Some(vec![source_base.clone()]),
            true,
        )?;
        match source_root_stat.pop().flatten() {
            Some(e) if e.kind == Kind::Dir => {}
            Some(_) => bail!(
                "--files-from: source {} is not a directory",
                display(src_root)
            ),
            None => bail!("--files-from: source {} does not exist", display(src_root)),
        }
        self.progress.scanned.fetch_add(1, Relaxed);

        // Listed paths are lstat'ed (a listed symlink copies as a symlink).
        // Implied ancestors must be directories. Registered stats never follow
        // descendant symlinks. Results are kept for the whole list, since a later
        // line may repeat a path or name one first seen as a parent.
        let mut leaves: HashMap<PathBytes, Option<Entry>> = HashMap::new();
        let mut parents: HashMap<PathBytes, Option<Entry>> = HashMap::new();
        // What the planner has been given for each path (Dir or not).
        let mut emitted: HashMap<PathBytes, Kind> = HashMap::new();
        let mut recursed: HashSet<PathBytes> = HashSet::new();
        let mut completed_subtrees: HashSet<PathBytes> = HashSet::new();
        let ancestors = |line: &[u8]| -> Vec<PathBytes> {
            line.iter()
                .enumerate()
                .filter(|(_, &b)| b == b'/')
                .map(|(i, _)| line[..i].to_vec())
                .collect()
        };
        let stat = |src: &mut dyn Conn, paths: Vec<PathBytes>, follow: bool| -> Result<_> {
            let legacy_paths = paths.iter().map(|r| join(src_root, r)).collect();
            let registered = paths
                .iter()
                .map(|relative| source_base.join(relative))
                .collect::<Result<Vec<_>>>()?;
            stat_many_registered(src, legacy_paths, Some(registered), follow)
        };
        for chunk in lines.chunks(crate::scan::BATCH) {
            let mut want_parents: Vec<PathBytes> = Vec::new();
            let mut want_leaves: Vec<PathBytes> = Vec::new();
            // Per role: a path may be needed both as a followed ancestor and
            // as an lstat'ed leaf, with different answers.
            let mut wanted_parents: HashSet<PathBytes> = HashSet::new();
            let mut wanted_leaves: HashSet<PathBytes> = HashSet::new();
            for line in chunk {
                for anc in ancestors(line) {
                    if !parents.contains_key(&anc) && wanted_parents.insert(anc.clone()) {
                        want_parents.push(anc);
                    }
                }
                if !leaves.contains_key(line) && wanted_leaves.insert(line.clone()) {
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
                // Validate the whole chain before emitting any of it, so a bad
                // path leaves no half-created ancestors behind.
                let mut chain: Vec<Entry> = Vec::new();
                for anc in ancestors(line) {
                    match parents.get(&anc).and_then(|e| e.as_ref()) {
                        Some(e) if e.kind == Kind::Dir => match emitted.get(&anc) {
                            Some(Kind::Dir) => {}
                            Some(_) => {
                                self.progress.error(&format!(
                                    "syq: --files-from: {shown}: {} was listed as a non-directory",
                                    display(&anc)
                                ));
                                continue 'line;
                            }
                            None => {
                                if !chain.iter().any(|c| c.path == anc) {
                                    chain.push(e.clone());
                                }
                            }
                        },
                        Some(_) => {
                            self.progress.error(&format!(
                                "syq: --files-from: {shown}: {} is not a directory",
                                display(&anc)
                            ));
                            continue 'line;
                        }
                        None => {
                            self.progress.error(&format!(
                                "syq: --files-from: {shown}: no such file or directory"
                            ));
                            continue 'line;
                        }
                    }
                }
                let Some(e) = leaves.get(line).and_then(|e| e.as_ref()) else {
                    self.progress.error(&format!(
                        "syq: --files-from: {shown}: no such file or directory"
                    ));
                    continue;
                };
                for c in chain {
                    emitted.insert(c.path.clone(), Kind::Dir);
                    batch.push(c);
                }
                match emitted.get(line) {
                    None => {
                        emitted.insert(line.clone(), e.kind);
                        batch.push(e.clone());
                    }
                    Some(k) if *k == e.kind => {}
                    Some(_) => {
                        // Listed as a symlink (or file) after a path through it
                        // already made it a directory: the same conflict as the
                        // other order, refused the same way.
                        self.progress.error(&format!(
                            "syq: --files-from: {shown}: listed as a non-directory but already used as a directory"
                        ));
                        continue;
                    }
                }
                if e.kind == Kind::Dir && recurse && recursed.insert(line.clone()) {
                    subtrees.push(line.clone());
                }
            }
            self.progress.scanned.fetch_add(batch.len() as u64, Relaxed);
            self.handle_batch(batch, src_root, b"", dst_root)?;
            if subtrees.len() > 1 {
                let selected: HashSet<&[u8]> = subtrees.iter().map(Vec::as_slice).collect();
                let disjoint = subtrees.iter().all(|rel| {
                    ancestors(rel)
                        .iter()
                        .all(|ancestor| !selected.contains(ancestor.as_slice()))
                });
                if disjoint {
                    subtrees.retain(|rel| {
                        !ancestors(rel)
                            .iter()
                            .any(|a| completed_subtrees.contains(a))
                    });
                    let progress = self.progress;
                    let warned = std::cell::Cell::new(false);
                    let source = self
                        .active_source
                        .as_ref()
                        .context("registered source reference was not initialized")?
                        .clone();
                    let scanned = src.scan_selected(
                        &source,
                        &subtrees,
                        &mut |batch| {
                            let batch: Vec<_> = batch
                                .into_iter()
                                .filter(|e| {
                                    if emitted.contains_key(&e.path) {
                                        false
                                    } else {
                                        emitted.insert(e.path.clone(), e.kind);
                                        true
                                    }
                                })
                                .collect();
                            self.progress.scanned.fetch_add(batch.len() as u64, Relaxed);
                            self.handle_batch(batch, src_root, b"", dst_root)
                        },
                        &mut |w| {
                            warned.set(true);
                            progress.error(&format!("syq: {w}"));
                        },
                    );
                    self.scan_warned |= warned.get();
                    if scanned? {
                        if !self.scan_warned {
                            completed_subtrees.extend(subtrees);
                        }
                        continue;
                    }
                }
            }
            for rel in subtrees {
                if ancestors(&rel)
                    .iter()
                    .any(|ancestor| completed_subtrees.contains(ancestor))
                {
                    continue;
                }
                self.scan_subtree(src, src_root, &rel, dst_root, &mut emitted)?;
                // A partial walk may miss a readable, explicitly selected
                // child. After a scan warning, keep walking later selections.
                if !self.scan_warned {
                    completed_subtrees.insert(rel);
                }
            }
        }
        Ok(())
    }

    /// Consume an already-acquired NDJSON mapping manifest: each entry claims
    /// exactly one source object (relative to `src_root`) at an explicit
    /// destination (relative to `dst_root`). The caller buffers the complete
    /// input and validates it before opening the destination. Destination ancestors with
    /// no entries are synthesized as implicit directories with default
    /// metadata.
    pub(super) fn scan_mapping(
        &mut self,
        src: &mut dyn Conn,
        src_root: &[u8],
        dst_root: &[u8],
        entries: Vec<(u64, ManifestEntry)>,
        explicit_parents: std::collections::HashSet<PathBytes>,
    ) -> Result<()> {
        use std::collections::{HashMap, HashSet};
        self.mapping_mode = true;
        if self.opts.restricted_receiver {
            self.mapping_explicit_parents = explicit_parents;
        } else {
            drop(explicit_parents);
        }
        let source_base = self
            .active_source
            .clone()
            .context("registered source reference was not initialized")?;
        match stat_many_registered(
            src,
            vec![src_root.to_vec()],
            Some(vec![source_base.clone()]),
            true,
        )?
        .pop()
        .flatten()
        {
            Some(e) if e.kind == Kind::Dir => {}
            Some(_) => bail!(
                "--mapping: source base {} is not a directory",
                display(src_root)
            ),
            None => bail!(
                "--mapping: source base {} does not exist",
                display(src_root)
            ),
        }
        self.progress.scanned.fetch_add(1, Relaxed);

        // Stat sources and plan the already-validated entries in chunks.
        // Conflicts that depend on source or destination state fail individual
        // entries here. `synthesized` tracks ancestors a later entry can name.
        let mut emitted: HashMap<PathBytes, Kind> = HashMap::new();
        let mut synthesized: HashSet<PathBytes> = HashSet::new();
        let mut remaining = entries.into_iter().peekable();
        while remaining.peek().is_some() {
            let chunk: Vec<(u64, ManifestEntry)> =
                remaining.by_ref().take(crate::scan::BATCH).collect();
            let source_paths = chunk
                .iter()
                .map(|(_, manifest)| source_base.join(&manifest.src))
                .collect::<Result<Vec<_>>>()?;
            let stats = stat_many_registered(
                src,
                chunk.iter().map(|(_, m)| join(src_root, &m.src)).collect(),
                Some(source_paths),
                false,
            )?;
            let mut batch: Vec<Entry> = Vec::new();
            for ((line_number, m), st) in chunk.into_iter().zip(stats) {
                let Some(e) = st else {
                    let message = format!(
                        "--mapping line {line_number}: source {} does not exist",
                        display(&m.src)
                    );
                    self.progress.error_classified(
                        &format!("syq: {message}"),
                        Some("io"),
                        Some("not_found"),
                    );
                    self.emit_mapping_entry_failed(
                        &m,
                        "unknown",
                        "io",
                        Some("not_found"),
                        &message,
                    );
                    continue;
                };
                if let Some(declared) = m.kind {
                    if !declared.matches(e.kind) {
                        let message = format!(
                            "--mapping line {line_number}: source {} is {}, not the declared {}",
                            display(&m.src),
                            kind_label(e.kind),
                            declared.label(),
                        );
                        self.progress.error_classified(
                            &format!("syq: {message}"),
                            Some("conflict"),
                            None,
                        );
                        self.emit_mapping_entry_failed(&m, "no", "conflict", None, &message);
                        continue;
                    }
                }
                if let Some(metadata) = &m.metadata {
                    if let Err(error) = metadata.validate_kind(e.kind) {
                        let message = format!("--mapping line {line_number}: {error}");
                        self.progress
                            .error_classified(&message, Some("conflict"), None);
                        self.emit_mapping_entry_failed(&m, "no", "conflict", None, &message);
                        continue;
                    }
                }
                // Filter real mapping entries before synthesizing containers;
                // an excluded leaf must not create its otherwise unused parents.
                if self.opts.expressions.selection.is_some()
                    && !self
                        .opts
                        .expressions
                        .selects(&crate::expression::File::from_entry(&e), &m.src)
                        .with_context(|| {
                            format!("--mapping line {line_number}: source {}", display(&m.src))
                        })?
                {
                    if self.opts.delete {
                        self.dst_seen
                            .entry(join(dst_root, &m.dst))
                            .or_insert(Claim::Weak);
                    }
                    self.progress.files_excluded.fetch_add(1, Relaxed);
                    continue;
                }
                // Destination ancestors: consistent with what earlier entries
                // established, with missing ones synthesized parent-first.
                let mut conflict = false;
                let mut chain: Vec<PathBytes> = Vec::new();
                for (i, &byte) in m.dst.iter().enumerate() {
                    if byte != b'/' {
                        continue;
                    }
                    let anc = &m.dst[..i];
                    match emitted.get(anc) {
                        Some(Kind::Dir) => {}
                        Some(_) => {
                            let message = format!(
                                "--mapping line {line_number}: destination ancestor {} was mapped as a non-directory",
                                display(anc)
                            );
                            self.progress.error_classified(
                                &format!("syq: {message}"),
                                Some("conflict"),
                                None,
                            );
                            self.emit_mapping_entry_failed(&m, "no", "conflict", None, &message);
                            conflict = true;
                            break;
                        }
                        None => chain.push(anc.to_vec()),
                    }
                }
                if conflict {
                    continue;
                }
                match emitted.get(&m.dst) {
                    None => {}
                    Some(Kind::Dir) if e.kind == Kind::Dir && synthesized.remove(&m.dst) => {
                        // An explicit directory entry for a path an earlier
                        // entry implied: upgrade it from default metadata to
                        // this entry's metadata. If the synthetic entry is
                        // still queued in this chunk, replace it — otherwise
                        // a manifest listing x/a.txt before x would create,
                        // count, and stamp the directory twice.
                        self.implicit_dirs.remove(&join(dst_root, &m.dst));
                        if let Some(position) = batch
                            .iter()
                            .position(|queued| queued.path == m.dst && queued.kind == Kind::Dir)
                        {
                            batch.remove(position);
                        }
                    }
                    Some(_) => {
                        let message = format!(
                            "--mapping line {line_number}: destination {} was already used as a directory",
                            display(&m.dst)
                        );
                        self.progress.error_classified(
                            &format!("syq: {message}"),
                            Some("conflict"),
                            None,
                        );
                        self.emit_mapping_entry_failed(&m, "no", "conflict", None, &message);
                        continue;
                    }
                }
                for anc in chain {
                    self.implicit_dirs.insert(join(dst_root, &anc));
                    emitted.insert(anc.clone(), Kind::Dir);
                    synthesized.insert(anc.clone());
                    batch.push(implicit_dir_entry(anc));
                }
                emitted.insert(m.dst.clone(), e.kind);
                if m.src != m.dst {
                    self.src_overrides.insert(m.dst.clone(), m.src);
                }
                let mut e = e;
                e.path = m.dst;
                batch.push(e);
            }
            self.progress.scanned.fetch_add(batch.len() as u64, Relaxed);
            self.handle_batch(batch, src_root, b"", dst_root)?;
        }
        Ok(())
    }

    /// Walk `src_root/rel` and plan its entries under the same relative prefix.
    pub(super) fn scan_subtree(
        &mut self,
        src: &mut dyn Conn,
        src_root: &[u8],
        rel: &[u8],
        dst_root: &[u8],
        emitted: &mut std::collections::HashMap<PathBytes, Kind>,
    ) -> Result<()> {
        let source = self
            .active_source
            .as_ref()
            .context("registered source reference was not initialized")?
            .join(rel)?;
        scan_into_planner(
            self,
            src,
            &join(src_root, rel),
            Some(&source),
            false,
            &[],
            |pl, batch| {
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
                pl.progress.scanned.fetch_add(batch.len() as u64, Relaxed);
                pl.handle_batch(batch, src_root, b"", dst_root)
            },
        )
    }

    pub(super) fn handle_batch(
        &mut self,
        batch: Vec<Entry>,
        src_root: &[u8],
        sub: &[u8],
        dst_root: &[u8],
    ) -> Result<()> {
        let batch = if self.opts.expressions.selection.is_some() && !self.mapping_mode {
            let mut selected = Vec::with_capacity(batch.len());
            for entry in batch {
                // Directories bypass --where: they are created and receive
                // metadata as in an unfiltered copy.
                if entry.kind == Kind::Dir {
                    selected.push(entry);
                    continue;
                }
                let relative = self
                    .src_overrides
                    .get(&entry.path)
                    .map(Vec::as_slice)
                    .unwrap_or(&entry.path);
                let path = crate::expression::source_path(src_root, relative);
                let included = self
                    .opts
                    .expressions
                    .selects(&crate::expression::File::from_entry(&entry), path)
                    .with_context(|| format!("source {}", display(path)))?;
                if !included {
                    // Selection never makes a source counterpart extraneous.
                    if self.opts.delete {
                        let dst = join(dst_root, &join(sub, &entry.path));
                        self.dst_seen.entry(dst).or_insert(Claim::Weak);
                    }
                    self.progress.files_excluded.fetch_add(1, Relaxed);
                    continue;
                }
                selected.push(entry);
            }
            selected
        } else {
            batch
        };
        if self.opts.hardlinks
            && batch
                .iter()
                .any(|e| e.nlink > 1 && !matches!(e.kind, Kind::File | Kind::Dir))
        {
            bail!("hardlink preservation currently supports regular files only; the source contains a multiply linked non-regular file");
        }
        // Temporary names include a fresh invocation nonce. They are created
        // exclusively by the receiver, not reserved in a whole-copy index.
        for entry in &batch {
            if self.entry_is_payload(entry) {
                let name = if entry.path.is_empty() {
                    src_root
                } else {
                    &entry.path
                };
                if name
                    .rsplit(|&byte| byte == b'/')
                    .next()
                    .is_some_and(|name| is_partial_name(OsStr::from_bytes(name)))
                {
                    self.source_partials += 1;
                }
            }
        }
        // Every selected regular file is work for an empty destination. An
        // existing one may hold it unchanged; its first queued file is the
        // signal instead.
        if self.destination_children_known_missing
            && batch
                .iter()
                .any(|entry| entry.kind == Kind::File && self.entry_is_payload(entry))
        {
            self.sched.anticipate_file_work();
        }
        let mut mapped = self.map_batch(batch, src_root, sub, dst_root)?;
        if self.collision {
            return Ok(());
        }
        self.inspect_destination_batch(&mut mapped)?;
        match &mut self.buffer {
            Some(buf) => buf.push(mapped),
            None => self.apply_mapped(mapped)?,
        }
        (self.start_streaming)();
        #[cfg(debug_assertions)]
        if self.progress.files_total.load(Relaxed) >= STREAMING_START_FILES as u64 {
            crate::fsops::test_race_barrier(
                "SYQ_TEST_PLANNED_BATCH_READY_FILE",
                "SYQ_TEST_PLANNED_BATCH_CONTINUE_FILE",
                "streaming planning batch",
            )?;
        }
        Ok(())
    }

    pub(super) fn finish_planning(&mut self) -> Result<()> {
        if self.buffer.is_none() {
            self.retire_planning_state();
        }
        Ok(())
    }

    pub(super) fn retire_planning_state(&mut self) {
        // These sets exist only to validate and apply mapped scan entries.
        // Jobs already own the source spelling needed by workers. Deletion
        // alone still needs the destination claims.
        self.created_dirs = std::collections::HashSet::new();
        self.missing_dirs = std::collections::HashSet::new();
        self.mapping_explicit_parents = std::collections::HashSet::new();
        self.blocked_mapping_parents = std::collections::HashSet::new();
        self.blocked_directory_paths = std::collections::HashSet::new();
        // Dry-run traces need every directory identity. Live copies only need
        // identities for deferred metadata failures; retire the leaf mappings.
        if self.mapping_mode && !self.opts.dry_run {
            let deferred: std::collections::HashSet<_> =
                self.deferred.iter().map(|(path, ..)| path).collect();
            self.src_overrides
                .retain(|dst, _| deferred.contains(&join(&self.dst_root, dst)));
            self.implicit_dirs.retain(|path| deferred.contains(path));
            self.src_overrides.shrink_to_fit();
            self.implicit_dirs.shrink_to_fit();
        }
        if !self.opts.delete {
            self.dst_seen = std::collections::HashMap::new();
            self.delete_roots = Vec::new();
        }
    }

    /// The mapping loop: decide and claim everything about each entry.
    pub(super) fn map_batch(
        &mut self,
        batch: Vec<Entry>,
        src_root: &[u8],
        sub: &[u8],
        dst_root: &[u8],
    ) -> Result<Mapped> {
        let opts = self.opts;
        let mut dirs: Vec<(PathBytes, PathBytes, Entry)> = Vec::new();
        let mut others: Vec<Planned> = Vec::new();
        let mut directory_expression_sources = std::collections::HashMap::new();
        for e in batch {
            if e.kind == Kind::Dir && !opts.recursive && !self.keep_dirs {
                continue;
            }
            let dst_rel = join(sub, &e.path);
            if opts.expected_for(&dst_rel).is_some()
                && e.kind != Kind::File
                && !self.implicit_dirs.contains(&join(dst_root, &dst_rel))
            {
                let message = "expected digest requires a regular file";
                self.progress.error(message);
                let source = self.mapping_source_rel(&dst_rel);
                self.emit_entry_failed(
                    FailedEntry {
                        dst: &dst_rel,
                        src: source.as_deref(),
                        kind: Some(DeclaredKind::File),
                    },
                    "no",
                    "conflict",
                    None,
                    message,
                );
                continue;
            }
            let dst = join(dst_root, &dst_rel);
            let rel = self.rel_name(src_root, sub, &e.path);
            // Every source entry claims its destination here, before any
            // decision about it: that blocks two sources from mapping onto one
            // path, and it is what makes --delete safe — whatever happens
            // below (skip, filter, unsupported type), a path the source has is
            // never an extra.
            let claim = match e.kind {
                Kind::Dir => Claim::Dir,
                Kind::File => Claim::File {
                    dev: e.dev,
                    ino: e.ino,
                },
                Kind::Symlink if opts.links => Claim::Leaf,
                Kind::Fifo | Kind::Socket | Kind::CharDev | Kind::BlockDev
                    if opts.devices
                        && special_creation_supported(
                            self.destination_supports_confined_socket_nodes,
                            e.kind,
                        ) =>
                {
                    Claim::Leaf
                }
                _ => Claim::Weak,
            };
            // A later real claim can replace a weak claim from an entry that
            // is not copied. In that case it is the first capacity-relevant
            // object at this path even though the namespace was already seen.
            let new_capacity_object = match self.dst_seen.get(&dst) {
                None => true,
                Some(Claim::Weak) if claim != Claim::Weak => true,
                Some(_) => false,
            };
            let Some(contested) = self.claim_dst(&dst, &rel, claim) else {
                continue;
            };
            if claim != Claim::Weak && self.fail_blocked_mapping_entry(&dst, &dst_rel, e.kind) {
                continue;
            }
            self.record_fresh_entry(&dst, &dst_rel, src_root, &e, new_capacity_object)?;
            let src = match self.src_overrides.get(&e.path) {
                Some(actual) => join(src_root, actual),
                None => join(src_root, &e.path),
            };
            let source_relative = self
                .src_overrides
                .get(&e.path)
                .map(Vec::as_slice)
                .unwrap_or(&e.path);
            let source = self
                .active_source
                .as_ref()
                .expect("planner source reference initialized")
                .join(source_relative)
                .expect("scanner and manifest paths are strict relative paths");
            match claim {
                Claim::Dir => {
                    if opts.expressions.active() {
                        directory_expression_sources.insert(
                            dst.clone(),
                            crate::expression::source_path(src_root, source_relative).to_vec(),
                        );
                    }
                    dirs.push((dst, dst_rel, e));
                }
                Claim::Weak if e.kind == Kind::Other => {
                    // Unknown type: never transferred.
                    self.progress.files_excluded.fetch_add(1, Relaxed);
                }
                Claim::Weak
                    if e.kind == Kind::Socket
                        && opts.devices
                        && !special_creation_supported(
                            self.destination_supports_confined_socket_nodes,
                            e.kind,
                        ) =>
                {
                    self.progress.eprintln(&format!(
                        "syq: skipping socket \"{rel}\": macOS cannot create socket nodes through a confined destination"
                    ));
                    self.progress.files_excluded.fetch_add(1, Relaxed);
                }
                Claim::Weak => {
                    // Symlink without -l, special without -D.
                    if opts.verbose > 0 {
                        self.progress
                            .eprintln(&format!("skipping non-regular file \"{rel}\""));
                    }
                    self.progress.files_excluded.fetch_add(1, Relaxed);
                }
                Claim::File { .. } | Claim::Leaf => others.push(Planned {
                    src,
                    source,
                    dst,
                    dst_rel,
                    rel,
                    e,
                    contested,
                }),
            }
        }
        Ok(Mapped {
            directory_expression_sources,
            dst_root: dst_root.to_vec(),
            dirs,
            others,
            dir_stats: None,
            other_stats: None,
        })
    }

    pub(super) fn buffered_file_population(&self, fast_limit: u64) -> (usize, u64, bool) {
        let mut files = 0;
        let mut bytes = 0u64;
        let mut all_small = true;
        for planned in self
            .buffer
            .iter()
            .flatten()
            .flat_map(|mapped| &mapped.others)
        {
            let entry = &planned.e;
            if entry.kind == Kind::File
                && self.opts.max_size.is_none_or(|max| entry.size <= max)
                && self.opts.min_size.is_none_or(|min| entry.size >= min)
            {
                files += 1;
                bytes = bytes.saturating_add(entry.size);
                all_small &= entry.size <= fast_limit;
            }
        }
        (files, bytes, all_small)
    }

    /// Several sources: every batch has been mapped and claimed, nothing
    /// applied. Contested claims (two sources naming one regular file) are
    /// fine only when one of them *is* the destination file; settle those
    /// with one stat pass, then apply everything if there was no conflict.
    pub(super) fn replay_buffered(
        &mut self,
        prepare_for_pruning: bool,
        before_mutations: impl FnOnce(&mut Self) -> Result<()>,
        before_apply: impl FnOnce(),
    ) -> Result<()> {
        let Some(mut buffered) = self.buffer.take() else {
            return Ok(());
        };
        if self.opts.hardlinks && self.opts.inode_preservation.acls {
            super::hardlinks::validate_macos_acls(buffered.iter().flat_map(|m| &m.others).filter(
                |p| {
                    self.opts.max_size.is_none_or(|max| p.e.size <= max)
                        && self.opts.min_size.is_none_or(|min| p.e.size >= min)
                },
            ))?;
        }
        // Every claimant of each contested destination, as a group: the first
        // (from dst_seen) plus all the contested ones. The group is fine only
        // if at most one *distinct* file among them is not the destination
        // file itself — otherwise two different contents want one path.
        let mut groups: std::collections::BTreeMap<PathBytes, (String, Vec<(u64, u64)>)> =
            std::collections::BTreeMap::new();
        for p in buffered
            .iter()
            .flat_map(|m| m.others.iter().filter(|p| p.contested))
        {
            let g = groups.entry(p.dst.clone()).or_insert_with(|| {
                let first = match self.dst_seen.get(&p.dst) {
                    Some(Claim::File { dev, ino }) => vec![(*dev, *ino)],
                    _ => Vec::new(),
                };
                (p.rel.clone(), first)
            });
            g.1.push((p.e.dev, p.e.ino));
        }
        if !groups.is_empty() {
            let stats = self.stat_many(groups.keys().cloned().collect())?;
            for ((dst, (rel, ids)), st) in groups.into_iter().zip(stats) {
                let dst_id = st.filter(|_| self.opts.same_host).map(|d| (d.dev, d.ino));
                // Every claimant must be the destination file itself (a copy
                // onto itself, written by nobody). One claimant being that
                // file does not license another to overwrite it: the user
                // named it as a source, and it would be lost.
                let total = ids.len();
                let mut distinct: Vec<(u64, u64)> =
                    ids.into_iter().filter(|id| Some(*id) != dst_id).collect();
                distinct.sort_unstable();
                distinct.dedup();
                if !distinct.is_empty() {
                    self.progress.error(&format!(
                        "syq: {rel}: {total} sources map to the same destination {} — refusing to clobber it",
                        display(&dst)
                    ));
                    self.collision = true;
                }
            }
        }
        if self.collision {
            self.retire_planning_state();
            return Ok(());
        }
        // Early pruning needs access before walking the destination. Ordinary
        // buffered copies prepare each batch in apply_mapped, so directories
        // for later batches are not widened merely because they were planned.
        if prepare_for_pruning {
            self.prepare_container_access()?;
            self.prepare_existing_directories(
                buffered
                    .iter()
                    .flat_map(|mapped| mapped.dirs.iter().map(|(path, _, _)| path.clone()))
                    .collect(),
            )?;
        }
        before_mutations(self)?;
        if let Some((root, condition, is_destination_root)) = self.create_root.take() {
            if self.use_operator_anchor {
                let mode = match self.private_root {
                    Some(_) if is_destination_root => 0o700,
                    _ => self
                        .root_source_mode
                        .filter(|_| is_destination_root)
                        .unwrap_or_else(|| operator_directory_mode(self.opts)),
                };
                let (selection, created) = create_operator_directory(self.dst, condition, mode)?;
                if is_destination_root && !created {
                    self.adopt_existing_root(&root, &selection);
                }
                let anchor = activate_control_destination(self.dst, selection, root.clone())?;
                if is_destination_root && created {
                    self.mutation_root_condition = TargetCondition::Matches {
                        dev: anchor.dev,
                        ino: anchor.ino,
                    };
                    if self.guard_containers {
                        self.container_guard = Some(ContainerGuard {
                            root,
                            dev: anchor.dev,
                            ino: anchor.ino,
                        });
                    }
                }
                self.destination_anchor
                    .set(anchor)
                    .expect("destination anchor set once");
            } else {
                debug_assert!(is_destination_root);
                let mode = if self.private_root.is_some() {
                    0o700
                } else {
                    self.root_source_mode.unwrap_or(0o755)
                };
                let created = mkdir_root(self.dst, &root, condition, mode)?;
                self.mutation_root_condition = target_identity(&created);
                if self.guard_containers {
                    self.container_guard = Some(target_container(&root, &created));
                }
            }
        }
        // Validated: from here on they are ordinary entries (the one that is
        // the destination file skips itself; the other is written).
        for m in &mut buffered {
            for p in &mut m.others {
                p.contested = false;
            }
        }
        before_apply();
        for m in buffered {
            self.apply_mapped(m)?;
        }
        if !self.collision {
            self.finish_hardlink_planning()?;
        }
        self.retire_planning_state();
        Ok(())
    }

    /// Everything after the mapping loop: stat, create directories, filter,
    /// enqueue.
    pub(super) fn apply_mapped(&mut self, mapped: Mapped) -> Result<()> {
        if self.opts.inode_preservation.xattrs {
            for entry in mapped
                .dirs
                .iter()
                .map(|(_, _, e)| e)
                .chain(mapped.others.iter().map(|p| &p.e))
            {
                if let Some(attributes) = entry
                    .inode_metadata
                    .as_ref()
                    .and_then(|m| m.xattrs.as_ref())
                {
                    crate::inode_metadata::validate_xattr_destination(
                        attributes,
                        &self.destination_metadata_platform,
                    )?;
                }
            }
        }
        if self.collision {
            return Ok(());
        }
        let root_entry = self.assert_mutation_root()?;
        if !mapped.dirs.is_empty() || !mapped.others.is_empty() {
            self.prepare_container_access()?;
        }
        if let Some(entry) = self.root_access_check.take() {
            let root = self.dst_root.clone();
            if !self
                .check_directory_access(vec![(root.clone(), entry)])?
                .is_empty()
            {
                // Nothing beneath an uninspected root can be previewed.
                self.blocked_directory_paths.insert(root);
            }
        }
        let opts = self.opts;
        let Mapped {
            directory_expression_sources,
            dst_root,
            dirs,
            mut others,
            dir_stats,
            mut other_stats,
        } = mapped;
        let dst_root = &dst_root[..];
        self.directory_expression_sources = directory_expression_sources;
        self.unselected_dirs.clear();

        // Directories: one stat pass decides everything about each one, and
        // the same filtered list drives creation, listing and deferred
        // metadata so they can't disagree.
        if !dirs.is_empty() {
            let mut stats = if self.destination_children_known_missing {
                self.stat_fresh_descendants(
                    root_entry.as_ref(),
                    dirs.iter().map(|(path, _, _)| path),
                )?
            } else if let Some(stats) = dir_stats {
                stats
            } else {
                self.stat_directories_with_dry_run_overlay(&dirs, dst_root)?
            };
            if opts.may_widen_directory_permissions()
                && stats
                    .iter()
                    .flatten()
                    .any(|entry| entry.kind == Kind::Dir && entry.mode & 0o700 != 0o700)
            {
                self.prepare_existing_directories(
                    dirs.iter().map(|(path, _, _)| path.clone()).collect(),
                )?;
                stats = self.stat_directories_with_dry_run_overlay(&dirs, dst_root)?;
                // Previously unsearchable children may now be visible.
                other_stats = None;
            }
            if !opts.dry_run {
                let candidates = dirs
                    .iter()
                    .zip(&stats)
                    .filter_map(|((path, _, _), stat)| {
                        stat.as_ref()
                            .filter(|entry| entry.kind == Kind::Dir && entry.mode & 0o300 != 0o300)
                            .map(|entry| (path.clone(), entry.clone()))
                    })
                    .collect::<Vec<_>>();
                if !candidates.is_empty() {
                    self.check_directory_access(candidates)?;
                }
            }
            let planned = self.filter_dirs(dirs, stats, dst_root)?;
            if opts.dry_run {
                self.trace_dry_run_dirs(&planned, dst_root);
            } else {
                if !self.create_directories(&planned, dst_root)? {
                    return Ok(());
                }
                self.defer_directory_metadata(&planned)?;
            }
        }

        if !self.blocked_mapping_parents.is_empty() || !self.blocked_directory_paths.is_empty() {
            others.retain(|p| !self.fail_blocked_mapping_entry(&p.dst, &p.dst_rel, p.e.kind));
        }
        if others.is_empty() {
            return Ok(());
        }
        let stats = if self.destination_children_known_missing {
            self.stat_fresh_descendants(
                root_entry.as_ref(),
                others.iter().map(|planned| &planned.dst),
            )?
        } else if let Some(stats) = &mut other_stats {
            others
                .iter()
                .map(|planned| {
                    stats
                        .remove(&planned.dst)
                        .expect("batch plan covered every mapped leaf")
                })
                .collect()
        } else {
            self.stat_many_with_dry_run_overlay(
                others.iter().map(|p| p.dst.clone()).collect(),
                dst_root,
            )?
        };
        let mut leaf_ops = LeafOps::default();
        for (p, dst_entry) in others.into_iter().zip(stats) {
            // A preview reported this entry's directory as not inspected.
            if opts.dry_run && Self::under_any(&self.blocked_directory_paths, &p.dst, dst_root) {
                continue;
            }
            let target_condition = self.exact_condition_for(&p.dst);
            let target_condition_holds = match (target_condition, &dst_entry) {
                (TargetCondition::Any, _) | (TargetCondition::Absent, None) => true,
                (TargetCondition::Absent, Some(_)) => false,
                (TargetCondition::Matches { dev, ino }, Some(entry)) => {
                    entry.dev == dev && entry.ino == ino
                }
                (TargetCondition::Matches { .. }, None) => false,
                (
                    TargetCondition::MatchesFingerprint {
                        dev,
                        ino,
                        ctime,
                        ctime_nsec,
                    },
                    Some(entry),
                ) => {
                    entry.dev == dev
                        && entry.ino == ino
                        && entry.ctime == ctime
                        && entry.ctime_nsec == ctime_nsec
                }
                (TargetCondition::MatchesFingerprint { .. }, None) => false,
            };
            if !target_condition_holds {
                self.progress.error(&format!(
                    "syq: target {} changed after the placement precondition was checked",
                    display(&p.dst)
                ));
                self.collision = true;
                continue;
            }
            if (opts.existing || opts.ignore_existing) && self.under_missing_dir(&p.dst, dst_root) {
                // Below a directory we won't create: nothing to do, even if the
                // destination has something reachable there through a symlink.
                self.progress.files_excluded.fetch_add(1, Relaxed);
                continue;
            }
            if opts.expressions.update.is_some() {
                let source = crate::expression::File::from_entry(&p.e);
                let destination = dst_entry
                    .as_ref()
                    .map(crate::expression::File::from_entry)
                    .unwrap_or_default();
                let relative = self
                    .src_overrides
                    .get(&p.e.path)
                    .map(Vec::as_slice)
                    .unwrap_or(&p.e.path);
                if !opts
                    .expressions
                    .permits(
                        &source,
                        crate::expression::source_path(&p.src, relative),
                        &destination,
                        crate::expression::source_path(&p.dst, &p.dst_rel),
                    )
                    .with_context(|| format!("entry {}", p.rel))?
                {
                    self.progress.files_excluded.fetch_add(1, Relaxed);
                    continue;
                }
            }
            match p.e.kind {
                Kind::File => self.plan_file(p, dst_entry, target_condition, &mut leaf_ops),
                Kind::Symlink => self.plan_symlink(p, dst_entry, &mut leaf_ops),
                Kind::Fifo | Kind::Socket | Kind::CharDev | Kind::BlockDev => {
                    self.plan_special(p, dst_entry, &mut leaf_ops)
                }
                Kind::Dir | Kind::Other => unreachable!("handled in the mapping loop"),
            }
        }
        self.flush_meta_fixes(leaf_ops.meta_fixes)?;
        self.flush_leaf_ops(leaf_ops.ops, &leaf_ops.names)
    }

    /// Decide what a mapped regular file needs: a skip, a metadata fix, a
    /// dry-run trace or a transfer.
    fn plan_file(
        &mut self,
        leaf: Planned,
        dst_entry: Option<Entry>,
        target_condition: TargetCondition,
        leaf_ops: &mut LeafOps,
    ) {
        let opts = self.opts;
        let Planned {
            src: src_path,
            source,
            dst: dst_path,
            dst_rel,
            rel,
            e,
            contested,
        } = leaf;
        // Never copy a file onto itself (same path, hardlink, or a
        // symlinked alias) — with --inplace that would truncate the
        // source. Only possible when both ends are the same machine.
        // This is also what settles a contested claim: two sources
        // may map onto one destination file only if one of them
        // *is* that file (so nothing is actually written twice).
        let same_file = opts.same_host
            && dst_entry
                .as_ref()
                .is_some_and(|d| d.dev == e.dev && d.ino == e.ino);
        if same_file && opts.if_exists == Some(crate::cli::IfExists::Error) {
            self.existing_conflict(&dst_path, &dst_rel, "destination already exists");
            return;
        }
        if same_file {
            if !opts.quiet {
                self.progress.eprintln(&format!(
                    "skipping {rel}: source and destination are the same file"
                ));
            }
            self.progress.files_excluded.fetch_add(1, Relaxed);
            if !contested {
                // Nothing will be written here; let another source have it.
                self.dst_seen.insert(dst_path, Claim::Weak);
            }
            return;
        }
        if contested {
            self.progress.error(&format!(
                "syq: {rel}: two sources map to the same destination {} — refusing to clobber it",
                display(&dst_path)
            ));
            self.collision = true;
            return;
        }
        if opts.max_size.is_some_and(|m| e.size > m)
            || opts.min_size.is_some_and(|m| e.size < m)
            || self.skip_existing(&dst_entry)
        {
            self.progress.files_excluded.fetch_add(1, Relaxed);
            return;
        }
        if self.refuse_directory_target(&dst_path, &dst_rel, e.kind, dst_entry.as_ref()) {
            return;
        }
        if opts.if_exists == Some(crate::cli::IfExists::Error) && dst_entry.is_some() {
            self.existing_conflict(&dst_path, &dst_rel, "destination already exists");
            return;
        }
        if opts.if_exists == Some(crate::cli::IfExists::ErrorIfDifferent)
            && dst_entry
                .as_ref()
                .is_some_and(|d| d.kind != Kind::File || d.size != e.size)
        {
            if dst_entry.as_ref().is_some_and(|d| d.kind == Kind::File) {
                self.report_existing_conflict(
                    &dst_rel,
                    &opts.file_difference_message(&display(&dst_path)),
                );
            } else {
                self.existing_conflict(&dst_path, &dst_rel, "destination contents differ");
            }
            return;
        }
        let same = dst_entry
            .as_ref()
            .is_some_and(|d| opts.metadata_matches(&dst_rel, &e, d));
        let dst_newer = opts.update
            && dst_entry.as_ref().is_some_and(|d| {
                (d.kind == Kind::File || opts.if_exists.is_some())
                    && (d.mtime, d.mtime_nsec) > (e.mtime, e.mtime_nsec)
            });
        if dst_newer {
            self.progress.files_excluded.fetch_add(1, Relaxed);
            return;
        }
        if opts.hardlinks && e.nlink > 1 {
            self.plan_hardlinked_file(
                Planned {
                    src: src_path,
                    source,
                    dst: dst_path,
                    dst_rel,
                    rel,
                    e,
                    contested,
                },
                dst_entry,
            );
            return;
        }
        if same
            && opts.trusts_size_and_time()
            && (opts.dry_run || opts.expected_for(&dst_rel).is_none())
        {
            // Content is up to date, but still reconcile metadata
            // (mode/owner/group) the way rsync does — a skipped file
            // shouldn't keep stale permissions.
            if let Some(d) = &dst_entry {
                let ff = opts.metadata_fix_flags(&dst_rel, &e, d);
                if ff != 0 || opts.inode_metadata_differs(&dst_rel, &e, d) {
                    self.progress.files_unchanged.fetch_add(1, Relaxed);
                    self.progress.bytes_unchanged.fetch_add(e.size, Relaxed);
                    if opts.dry_run {
                        self.dry_run_changes.metadata_files += 1;
                        self.emit_trace(
                            "transfer_file",
                            &dst_rel,
                            "file",
                            None,
                            "metadata_differs",
                        );
                        if opts.verbose > 0 {
                            self.progress.println(&format!(
                                "update metadata {} (requested file metadata differs)",
                                display(&dst_path)
                            ));
                        }
                        return;
                    }
                    leaf_ops.meta_fixes.push((
                        Op::SetFileMetaIfSame {
                            path: dst_path.clone(),
                            condition: match target_condition {
                                TargetCondition::Any => target_identity(d),
                                condition => condition,
                            },
                            meta: opts.metadata_for(&dst_rel, &e),
                            flags: ff,
                        },
                        dst_rel,
                        DeclaredKind::File,
                    ));
                    return;
                }
            }
            self.progress.files_unchanged.fetch_add(1, Relaxed);
            self.progress.bytes_unchanged.fetch_add(e.size, Relaxed);
        } else if opts.dry_run
            && opts.previews_by_comparing(e.size, dst_entry.as_ref())
            && dst_entry
                .as_ref()
                .is_some_and(|d| d.kind == Kind::File && d.size == e.size)
        {
            // Equal-size files need a real comparison, as the copy would make
            // one. Hash them through the workers so large trees do not
            // serialize all reads in the planner.
            self.enqueue((src_path, source), dst_path, rel, dst_rel, e, dst_entry);
        } else if opts.dry_run {
            // Writing an existing file in place needs no directory write.
            self.note_directory_change(
                &dst_path,
                !(opts.inplace && dst_entry.as_ref().is_some_and(|d| d.kind == Kind::File)),
            );
            self.progress.files_total.fetch_add(1, Relaxed);
            self.progress.bytes_total.fetch_add(e.size, Relaxed);
            self.progress.add_files(1);
            // Dry aggregates mean planned work, bytes included —
            // files_done already moves here, so bytes_done must
            // too or the terminal record contradicts its traces.
            self.progress.bytes_done.fetch_add(e.size, Relaxed);
            self.dry_run_changes.regular_files += 1;
            if dst_entry.as_ref().is_some_and(|d| d.kind != Kind::File) {
                self.dry_run_changes.type_replacements += 1;
            }
            self.emit_trace(
                "transfer_file",
                &dst_rel,
                "file",
                Some(e.size),
                match &dst_entry {
                    None => "destination_missing",
                    Some(d) if d.kind != Kind::File => "type_differs",
                    Some(d) if d.size != e.size => "content_differs",
                    Some(_) => "metadata_differs",
                },
            );
            if opts.verbose > 0 {
                let shown = display(&dst_path);
                let action = match &dst_entry {
                    None => format!("create file {shown} (destination missing)"),
                    Some(d) if d.kind != Kind::File => format!(
                        "replace with file {shown} (destination is {})",
                        kind_label(d.kind)
                    ),
                    Some(d) if d.size != e.size => {
                        format!("update file {shown} (size differs)")
                    }
                    Some(_) if opts.checksum => {
                        format!("update file {shown} (content comparison requested)")
                    }
                    Some(d) if opts.hash_or_copy && opts.metadata_matches(&dst_rel, &e, d) => {
                        format!("update file {shown} (size and time not trusted)")
                    }
                    Some(d)
                        if opts.flags & flags::TIMES != 0
                            && (d.mtime, d.mtime_nsec) != (e.mtime, e.mtime_nsec) =>
                    {
                        format!("update file {shown} (modification time differs)")
                    }
                    Some(_) => {
                        format!("update file {shown} (content quick check unavailable)")
                    }
                };
                self.progress.println(&action);
            }
        } else {
            // Writing an existing file in place needs no directory write.
            let replaces_entry =
                !(opts.inplace && dst_entry.as_ref().is_some_and(|d| d.kind == Kind::File));
            self.note_directory_change(&dst_path, replaces_entry);
            self.enqueue(
                (src_path, source),
                dst_path,
                rel,
                dst_rel.clone(),
                e.clone(),
                dst_entry,
            );
        }
    }

    /// An existing link or special entry needs no content copy, but an explicit
    /// metadata request still applies. Ordinary preservation behavior is unchanged.
    fn plan_explicit_leaf_metadata(
        &mut self,
        path: &PathBytes,
        rel: &[u8],
        source: &Entry,
        destination: &Entry,
        ops: &mut LeafOps,
    ) {
        let requested = self.opts.mapping_metadata.get(rel);
        let flags = self.opts.matching_flags_for(rel);
        if flags == 0 && source.inode_metadata.is_none() {
            return;
        }
        let meta = self.opts.metadata_for(rel, source);
        // Explicit nanoseconds must be attempted even if preservation's quick
        // comparison would tolerate truncation by the destination filesystem.
        let time_differs = requested.is_some_and(|r| r.mtime.is_some())
            && (meta.mtime, meta.mtime_nsec) != (destination.mtime, destination.mtime_nsec);
        // Comparing a symlink target can change its access time after the
        // destination stat. Even matching captured times need restoration.
        let restore_link_atime = source.kind == Kind::Symlink
            && self.opts.inode_preservation.atimes
            && !self.opts.dry_run;
        if !time_differs
            && !restore_link_atime
            && !metadata_differs(&meta, &destination.meta(), flags)
        {
            return;
        }
        if self.opts.dry_run {
            self.dry_run_changes.metadata_files += 1;
            self.emit_trace(
                if source.kind == Kind::Symlink {
                    "create_symlink"
                } else {
                    "create_special"
                },
                rel,
                if source.kind == Kind::Symlink {
                    "symlink"
                } else {
                    "special"
                },
                None,
                "metadata_differs",
            );
        } else {
            ops.meta_fixes.push((
                Op::SetMeta {
                    path: path.clone(),
                    meta,
                    flags,
                    condition: target_identity(destination),
                },
                rel.to_vec(),
                if source.kind == Kind::Symlink {
                    DeclaredKind::Symlink
                } else {
                    DeclaredKind::Special
                },
            ));
        }
    }

    /// Queue the creation or replacement of a mapped symlink unless the
    /// destination already matches.
    fn plan_symlink(&mut self, leaf: Planned, dst_entry: Option<Entry>, leaf_ops: &mut LeafOps) {
        let opts = self.opts;
        let Planned {
            dst: dst_path,
            dst_rel,
            rel,
            e,
            ..
        } = leaf;
        if self.skip_existing(&dst_entry) {
            self.progress.files_excluded.fetch_add(1, Relaxed);
            return;
        }
        if self.refuse_directory_target(&dst_path, &dst_rel, e.kind, dst_entry.as_ref()) {
            return;
        }
        if opts.if_exists == Some(crate::cli::IfExists::UpdateIfOlder)
            && dst_entry
                .as_ref()
                .is_some_and(|d| (d.mtime, d.mtime_nsec) > (e.mtime, e.mtime_nsec))
        {
            self.progress.files_excluded.fetch_add(1, Relaxed);
            return;
        }
        let target = e.link.clone().unwrap_or_default();
        let same = dst_entry
            .as_ref()
            .is_some_and(|d| d.kind == Kind::Symlink && d.link.as_deref() == Some(&target[..]));

        if dst_entry.is_some()
            && (opts.if_exists == Some(crate::cli::IfExists::Error)
                || (!same && opts.if_exists == Some(crate::cli::IfExists::ErrorIfDifferent)))
        {
            self.existing_conflict(
                &dst_path,
                &dst_rel,
                if same {
                    "destination already exists"
                } else {
                    "destination contents differ"
                },
            );
            return;
        }
        if same {
            self.plan_explicit_leaf_metadata(
                &dst_path,
                &dst_rel,
                &e,
                dst_entry.as_ref().unwrap(),
                leaf_ops,
            );
            return;
        }
        self.note_directory_change(&dst_path, true);
        if opts.dry_run {
            self.dry_run_changes.symlinks += 1;
            if dst_entry.as_ref().is_some_and(|d| d.kind != Kind::Symlink) {
                self.dry_run_changes.type_replacements += 1;
            }
            self.emit_trace(
                "create_symlink",
                &dst_rel,
                "symlink",
                None,
                match &dst_entry {
                    None => "destination_missing",
                    Some(d) if d.kind != Kind::Symlink => "type_differs",
                    Some(_) => "content_differs",
                },
            );
            if opts.verbose > 0 {
                let shown = display(&dst_path);
                let action = match &dst_entry {
                    None => format!(
                        "create symlink {shown} -> {} (destination missing)",
                        display(&target)
                    ),
                    Some(d) if d.kind != Kind::Symlink => format!(
                        "replace with symlink {shown} -> {} (destination is {})",
                        display(&target),
                        kind_label(d.kind)
                    ),
                    Some(_) => format!(
                        "update symlink {shown} -> {} (target differs)",
                        display(&target)
                    ),
                };
                self.progress.println(&action);
            }
            return;
        }
        leaf_ops.names.push(QueuedLeafOp {
            dst_rel: dst_rel.clone(),
            action: "create_symlink",
            kind: "symlink",
            name: format!("{rel} -> {}", display(&target)),
        });
        leaf_ops.ops.push(Op::Symlink {
            path: dst_path.clone(),
            target,
            condition: self.leaf_condition_for(&dst_path, dst_entry.as_ref()),
        });
        leaf_ops.ops.push(Op::SetMeta {
            // Apply runs successful leaf creation/replacement
            // before metadata; a failed guarded replacement skips
            // this phase entirely.
            condition: TargetCondition::Any,
            path: dst_path,
            meta: opts.metadata_for(&dst_rel, &e),
            flags: opts.flags_for(&dst_rel) & !flags::MODE,
        });
    }

    /// Queue the creation or replacement of a mapped special file unless the
    /// destination already matches.
    fn plan_special(&mut self, leaf: Planned, dst_entry: Option<Entry>, leaf_ops: &mut LeafOps) {
        let opts = self.opts;
        let Planned {
            dst: dst_path,
            dst_rel,
            rel,
            e,
            ..
        } = leaf;
        if self.skip_existing(&dst_entry) {
            self.progress.files_excluded.fetch_add(1, Relaxed);
            return;
        }
        if self.refuse_directory_target(&dst_path, &dst_rel, e.kind, dst_entry.as_ref()) {
            return;
        }
        if opts.if_exists == Some(crate::cli::IfExists::UpdateIfOlder)
            && dst_entry
                .as_ref()
                .is_some_and(|d| (d.mtime, d.mtime_nsec) > (e.mtime, e.mtime_nsec))
        {
            self.progress.files_excluded.fetch_add(1, Relaxed);
            return;
        }
        let same = dst_entry
            .as_ref()
            .is_some_and(|d| d.kind == e.kind && d.rdev == e.rdev);
        if dst_entry.is_some()
            && (opts.if_exists == Some(crate::cli::IfExists::Error)
                || (!same && opts.if_exists == Some(crate::cli::IfExists::ErrorIfDifferent)))
        {
            self.existing_conflict(
                &dst_path,
                &dst_rel,
                if same {
                    "destination already exists"
                } else {
                    "destination contents differ"
                },
            );
            return;
        }
        if same {
            self.plan_explicit_leaf_metadata(
                &dst_path,
                &dst_rel,
                &e,
                dst_entry.as_ref().unwrap(),
                leaf_ops,
            );
            return;
        }
        self.note_directory_change(&dst_path, true);
        if opts.dry_run {
            self.dry_run_changes.specials += 1;
            if dst_entry.as_ref().is_some_and(|d| d.kind != e.kind) {
                self.dry_run_changes.type_replacements += 1;
            }
            self.emit_trace(
                "create_special",
                &dst_rel,
                "special",
                None,
                match &dst_entry {
                    None => "destination_missing",
                    Some(d) if d.kind != e.kind => "type_differs",
                    Some(_) => "content_differs",
                },
            );
            if opts.verbose > 0 {
                let shown = display(&dst_path);
                let action = match &dst_entry {
                    None => format!(
                        "create {} {shown} (destination missing)",
                        kind_label(e.kind)
                    ),
                    Some(d) if d.kind != e.kind => format!(
                        "replace with {} {shown} (destination is {})",
                        kind_label(e.kind),
                        kind_label(d.kind)
                    ),
                    Some(_) => format!(
                        "update {} {shown} (device identity differs)",
                        kind_label(e.kind)
                    ),
                };
                self.progress.println(&action);
            }
            return;
        }
        leaf_ops.names.push(QueuedLeafOp {
            dst_rel: dst_rel.clone(),
            action: "create_special",
            kind: "special",
            name: rel,
        });
        let meta = opts.metadata_for(&dst_rel, &e);
        let flags = opts.flags_for(&dst_rel);
        // Without a mode to apply, the node takes the source's permission
        // bits as creating it limits them, and none of its special bits.
        leaf_ops.ops.push(Op::Mknod {
            path: dst_path.clone(),
            mode: if flags & flags::MODE == 0 {
                e.mode & !0o7000
            } else {
                e.mode
            },
            rdev: e.rdev,
            condition: self.leaf_condition_for(&dst_path, dst_entry.as_ref()),
        });
        leaf_ops.ops.push(Op::SetMeta {
            condition: TargetCondition::Any,
            path: dst_path,
            meta,
            flags,
        });
    }

    /// Decide from its stat what happens to each mapped directory, and keep
    /// the ones to create or update.
    fn filter_dirs(
        &mut self,
        dirs: Vec<(PathBytes, PathBytes, Entry)>,
        stats: Vec<Option<Entry>>,
        dst_root: &[u8],
    ) -> Result<Vec<PlannedDir>> {
        let opts = self.opts;
        let mut planned: Vec<PlannedDir> = Vec::new();
        for ((p, dst_rel, e), st) in dirs.into_iter().zip(stats) {
            if self.fail_blocked_mapping_entry(&p, &dst_rel, e.kind) {
                continue;
            }
            let is_dir = matches!(st, Some(ref d) if d.kind == Kind::Dir);

            // --existing creates nothing. A non-directory at the path (a
            // file, a symlink even to a directory — in-tree symlinks are
            // never traversed) counts as missing: we won't
            // replace it and won't write through it, and since entries
            // come parent-first, everything below is skipped too.
            // --ignore-existing never touches what exists either: an
            // existing non-directory where a directory maps stays, and the
            // mapped directory with its whole subtree is skipped, visibly
            // (rsync would unlink the file; see docs/rsync-compat.md).
            let conflict = opts.ignore_existing && !is_dir && st.is_some();
            if conflict
                || (opts.existing && !is_dir)
                || ((opts.existing || opts.ignore_existing) && self.under_missing_dir(&p, dst_root))
            {
                if conflict && !opts.quiet {
                    self.progress.eprintln(&format!(
                        "syq: keeping existing {}; skipping the directory mapped onto it",
                        display(&p)
                    ));
                }
                self.missing_dirs.insert(p);
                continue;
            }
            if opts.restricted_receiver
                && st.is_some()
                && !is_dir
                && self.implicit_dirs.contains(&p)
                && !self.mapping_explicit_parents.contains(&dst_rel)
            {
                // Parent creation does not grant permission to replace a
                // file or symlink. Use the stat already in this batch to
                // fail affected entries before sending any mkdir request.
                self.blocked_mapping_parents.insert(p);
                continue;
            }
            if st.as_ref().is_some_and(|d| d.kind != Kind::Dir) {
                self.fail_directory_type_change(&p, &dst_rel, Kind::Dir);
                self.blocked_directory_paths.insert(p);
                continue;
            }
            if opts.expressions.update.is_some() && !self.implicit_dirs.contains(&p) {
                let source = crate::expression::File::from_entry(&e);
                let destination = st
                    .as_ref()
                    .map(crate::expression::File::from_entry)
                    .unwrap_or_default();
                let source_path = self
                    .directory_expression_sources
                    .get(&p)
                    .map(Vec::as_slice)
                    .unwrap_or(&e.path);
                if !opts
                    .expressions
                    .permits(
                        &source,
                        source_path,
                        &destination,
                        crate::expression::source_path(&p, &dst_rel),
                    )
                    .with_context(|| format!("directory {}", display(&p)))?
                {
                    self.unselected_dirs.insert(p.clone());
                }
            }
            planned.push((p, dst_rel, e, st));
        }
        Ok(planned)
    }

    /// The mode a directory's final metadata gives it, when that sets one.
    fn final_directory_mode(&self, dst_rel: &[u8], entry: &Entry) -> u32 {
        self.opts
            .mapping_metadata
            .get(dst_rel)
            .and_then(|metadata| metadata.mode)
            .unwrap_or(entry.mode)
            & 0o7777
    }

    /// The mode a new directory is created with. With its mode pending it
    /// gets its final bits, which grant no one more than the finished copy;
    /// its owner and group follow before anything is published into it (see
    /// `early_directory_metadata`). While an ACL is pending it is private
    /// instead, since entries inherited from a default ACL could reach its
    /// contents. Containers and implicit parents receive no later metadata,
    /// so their creation mode is final. Without a mode to apply, a directory
    /// takes the source's permission bits as creating it limits them, with
    /// owner access until it is filled (see `defer_directory_metadata`).
    fn new_directory_mode(&self, path: &[u8], dst_rel: &[u8], entry: &Entry) -> u32 {
        let flags = self.opts.flags_for(dst_rel);
        if self.unselected_dirs.contains(path) {
            0o777
        } else if self.implicit_dirs.contains(path) {
            entry.mode
        } else if crate::fsops::has_acl(entry.inode_metadata.as_deref()) {
            0o700
        } else if flags & flags::MODE != 0 {
            self.final_directory_mode(dst_rel, entry)
        } else {
            entry.mode & 0o777
        }
    }

    /// Metadata for this batch's directories as soon as they exist, before
    /// anything is created inside them, as rsync does.
    ///
    /// An existing directory that allows more than its final mode is
    /// narrowed to it, retaining its existing owner access, and takes
    /// its final group and owner; nothing is widened early. A new directory
    /// takes its final group and owner in the request that creates it. Its
    /// receiver creates it private when its starting group may differ, then
    /// gives it its creation mode; otherwise its creation mode is already no
    /// wider than final. A private destination root takes its final group,
    /// owner and mode, with owner access, unless its ACL is still pending.
    /// The rest of the final metadata follows at the end, which also reports
    /// any failure here.
    fn early_directory_metadata(&mut self, planned: &[PlannedDir]) -> Result<EarlyMetadata> {
        let opts = self.opts;
        let mut early = EarlyMetadata::default();
        for (path, dst_rel, entry, destination) in planned {
            // An unselected private root takes no source metadata, so it
            // has nothing to protect: give it its default mode right away.
            if self.unselected_dirs.contains(path)
                && path == &self.dst_root
                && self.private_root.is_some()
                && self.created_dirs.contains(path)
            {
                early.root_default = self
                    .private_root
                    .filter(|_| destination.as_ref().is_some_and(|d| d.kind == Kind::Dir));
                continue;
            }
            if self.implicit_dirs.contains(path) || self.unselected_dirs.contains(path) {
                continue;
            }
            let existing = match destination {
                Some(d) if d.kind == Kind::Dir => Some(d),
                Some(_) => continue,
                None => None,
            };
            let created = existing.is_none() || self.created_dirs.contains(path);
            if !created && opts.preserve_existing_directory_metadata {
                continue;
            }
            let flags = if created {
                opts.flags_for(dst_rel)
            } else {
                opts.matching_flags_for(dst_rel)
            };
            let meta = opts.metadata_for(dst_rel, entry);
            let mut early_flags = 0;
            // A new directory's starting group is unknown here; an existing
            // one needs a change only if its group differs.
            let group_changes =
                flags & flags::GROUP != 0 && existing.is_none_or(|d| d.gid != meta.gid);
            if group_changes {
                early_flags |= flags & (flags::GROUP | flags::REQUIRE_GROUP);
                // Ownership changes in one call, so move the owner along.
                if existing.is_none_or(|d| d.uid != meta.uid) {
                    early_flags |= flags & (flags::OWNER | flags::REQUIRE_OWNER);
                }
            }
            let private_root = created && path == &self.dst_root && self.private_root.is_some();
            let acl = crate::fsops::has_acl(entry.inode_metadata.as_deref());
            let mut mode = 0;
            if let Some(d) = existing {
                let current = d.mode & 0o7777;
                if private_root {
                    if acl {
                        // It waits privately for its ACL.
                    } else if flags & flags::MODE != 0 {
                        // Keep the setgid bit it inherited until its own
                        // subdirectories have inherited it too.
                        mode = (self.final_directory_mode(dst_rel, entry) & 0o777)
                            | 0o700
                            | (current & 0o2000);
                        early_flags |= flags::MODE;
                    } else if flags & flags::GROUP != 0 {
                        // After its group change it is open, with owner
                        // access, as creating it would have left it: from its
                        // source for `syq rsync`, which narrows it at the
                        // end, and with the default mode for native cp.
                        early.root_default = if opts.rsync_creation {
                            Some((entry.mode & 0o777) | 0o700)
                        } else {
                            self.private_root
                        };
                    }
                } else if flags & flags::MODE != 0 {
                    let wanted = if created && acl {
                        0o700
                    } else {
                        self.final_directory_mode(dst_rel, entry)
                    };
                    if current & 0o077 & !wanted != 0 {
                        // Existing owner access is widened only through the
                        // explicit preparation phase, which records restoration.
                        mode = (current & 0o7700) | (current & wanted & 0o077);
                        early_flags |= flags::MODE;
                    }
                }
            }
            if early_flags == 0 {
                continue;
            }
            let op = Op::SetMeta {
                path: path.clone(),
                meta: Meta {
                    mode,
                    uid: meta.uid,
                    gid: meta.gid,
                    mtime: 0,
                    mtime_nsec: 0,
                    inode_metadata: None,
                },
                flags: early_flags,
                condition: existing.map_or_else(
                    || self.metadata_condition_for(path),
                    |d| TargetCondition::Matches {
                        dev: d.dev,
                        ino: d.ino,
                    },
                ),
            };
            // A private root changes group only after this batch's
            // subdirectories have inherited its starting group, as they would
            // have from a root created with its default mode.
            if existing.is_some() && !private_root {
                early.existing.push(op);
            } else {
                early.created.push(op);
            }
        }
        Ok(early)
    }

    /// Treat the destination root as an existing directory after its
    /// creation found another process had created it since it was found
    /// missing: it gets no new root's metadata, what it holds is looked up
    /// before anything is written, and it is widened for its owner as any
    /// existing directory is.
    pub(super) fn adopt_existing_root(&mut self, root: &[u8], selection: &DirectoryAnchor) {
        self.created_dirs.remove(&self.dst_root);
        self.private_root = None;
        self.destination_root_known_missing = false;
        self.destination_children_known_missing = false;
        self.container_access = selected_container_access(self.widen_container, root, selection);
    }

    /// Give a private destination root whose final metadata sets no mode the
    /// mode creating it from `proposed` would have given it, after its group
    /// change. The receiver chooses it, as for a directory created that way,
    /// keeping the setgid bit only if that change left it, so its
    /// subdirectories inherit what they would have.
    fn open_private_root(&mut self, proposed: u32) -> Result<()> {
        let root = self.dst_root.clone();
        let condition = self.metadata_condition_for(&root);
        self.apply(vec![Op::SetMeta {
            path: root,
            meta: Meta {
                mode: proposed,
                uid: 0,
                gid: 0,
                mtime: 0,
                mtime_nsec: 0,
                inode_metadata: None,
            },
            flags: flags::RECEIVER_MODE,
            condition,
        }])?;
        Ok(())
    }

    /// Create missing directories. A failed placement-root condition prevents
    /// operations below it. Existing directory access is prepared separately.
    fn create_directories(&mut self, planned: &[PlannedDir], dst_root: &[u8]) -> Result<bool> {
        let opts = self.opts;
        if !self.opts.access_limited.lock().unwrap().is_empty() {
            for (path, _, _, st) in planned {
                if !matches!(st, Some(d) if d.kind == Kind::Dir) {
                    self.note_directory_change(path, true);
                }
            }
        }
        let mut early = self.early_directory_metadata(planned)?;
        // Narrow existing directories before publishing anything inside them.
        if !early.existing.is_empty() {
            self.apply(std::mem::take(&mut early.existing))?;
        }
        let mut new_dirs: Vec<Op> = planned
            .iter()
            .filter(|(path, _, _, st)| {
                let root_must_be_new =
                    self.exact_condition == TargetCondition::Absent && path == &self.dst_root;
                root_must_be_new || !matches!(st, Some(d) if d.kind == Kind::Dir)
            })
            .map(|(p, dst_rel, e, st)| Op::Mkdir {
                path: p.clone(),
                mode: self.new_directory_mode(p, dst_rel, e),
                condition: if opts.restricted_receiver
                    && st.is_none()
                    && self.implicit_dirs.contains(p)
                {
                    TargetCondition::Absent
                } else {
                    self.exact_condition_for(p)
                },
            })
            .collect();
        if let Some(root_index) = new_dirs.iter().position(|op| {
            matches!(
                op,
                Op::Mkdir {
                    path,
                    condition: TargetCondition::Absent,
                    ..
                } if path == &self.dst_root
            )
        }) {
            // Establish the new authority directory by itself. Every
            // descendant operation after this point carries the
            // identity returned by that atomic mkdir.
            let root_op = new_dirs.remove(root_index);
            // Its group comes with it, before anything is created inside it.
            let mut ops = vec![root_op];
            if let Some(index) = early
                .created
                .iter()
                .position(|op| matches!(op, Op::SetMeta { path, .. } if path == &self.dst_root))
            {
                ops.push(early.created.remove(index));
            }
            let error = self.apply(ops)?.into_iter().next().flatten();
            if let Some(error) = error {
                let os_kind = wire_os_kind(&error);
                self.progress.error_classified(
                    &format!(
                        "syq: {}",
                        self.opts.wire_error_message_at(&error, &self.dst_root)
                    ),
                    Some("io"),
                    os_kind,
                );
                if capacity_os_kind(os_kind) {
                    return Err(endpoint_error(error)).context("apply destination changes");
                }
                self.collision = true;
                return Ok(false);
            }
            self.created_dirs.insert(self.dst_root.clone());
            self.progress.directories_created.fetch_add(1, Relaxed);
            if opts.verbose > 0 {
                self.progress
                    .println(&format!("{}/", display(&self.dst_root)));
            }
            let created = stat_many(self.dst, vec![self.dst_root.clone()], false)?
                .pop()
                .flatten()
                .filter(|entry| entry.kind == Kind::Dir)
                .context("new exact target was not a directory after creation")?;
            self.exact_condition = target_identity(&created);
            self.mutation_root_condition = target_identity(&created);
            if self.guard_containers {
                self.container_guard = Some(target_container(&self.dst_root, &created));
            }
        }
        // A receiver applies a request's metadata after all of its
        // creations, so new directories take their group with the last ones.
        let mut batches = if new_dirs.is_empty() {
            Vec::new()
        } else {
            vec![new_dirs]
        };
        match batches.last_mut() {
            Some(last) => last.append(&mut early.created),
            None if !early.created.is_empty() => {
                self.apply(std::mem::take(&mut early.created))?;
            }
            None => {}
        }
        for mut new_dirs in batches {
            let n = new_dirs
                .iter()
                .position(|op| !matches!(op, Op::Mkdir { .. }))
                .unwrap_or(new_dirs.len());
            let op_info: Vec<(PathBytes, TargetCondition)> = new_dirs[..n]
                .iter()
                .map(|op| match op {
                    Op::Mkdir {
                        path, condition, ..
                    } => (path.clone(), *condition),
                    _ => unreachable!(),
                })
                .collect();
            let mut errs = self.apply(std::mem::take(&mut new_dirs))?;
            // Failed early metadata is retried, and reported, at the end.
            errs.truncate(n);
            let capacity_error = first_capacity_error(&errs);
            let mut failed = 0;
            for ((name, condition), err) in op_info.iter().zip(errs) {
                let succeeded = err.is_none();
                let created = succeeded;
                if created {
                    self.created_dirs.insert(name.clone());
                }
                let os_kind = err.as_ref().and_then(wire_os_kind);
                if let Some(err) = &err {
                    failed += 1;
                    self.progress.error_classified(
                        &format!("syq: {}", self.opts.wire_error_message_at(err, name)),
                        Some("io"),
                        os_kind,
                    );
                    if name == &self.dst_root && *condition != TargetCondition::Any {
                        self.collision = true;
                    }
                } else if opts.verbose > 0 {
                    self.progress.println(&format!("{}/", display(name)));
                }
                if let (Some(results), Some(dst_rel)) = (
                    self.progress.results_writer(),
                    strip_dst_root(name, dst_root),
                ) {
                    // An implicit --mapping ancestor has no source and
                    // is not independently retryable: the entries
                    // beneath it carry the actionable retry records.
                    let implicit = self.implicit_dirs.contains(name);
                    let src = if implicit {
                        None
                    } else {
                        self.mapping_source_rel(dst_rel)
                    };
                    results.emit_operation(&crate::results::OperationRecord {
                        action: "create_directory",
                        dst: dst_rel,
                        src: src.as_deref(),
                        kind: "dir",
                        disposition: if created { "succeeded" } else { "failed" },
                        bytes: None,
                        attempts: None,
                        retryable: (!created).then_some(if implicit { "no" } else { "unknown" }),
                        class: (!created).then_some("io"),
                        os_kind,
                        message: err.as_ref().map(WireError::as_str),
                    });
                }
            }
            self.progress
                .directories_created
                .fetch_add((n - failed) as u64, Relaxed);
            if let Some(error) = capacity_error {
                return Err(endpoint_error(error)).context("apply destination changes");
            }
        }
        if let Some(proposed) = early.root_default.take() {
            self.open_private_root(proposed)?;
        }
        Ok(true)
    }

    /// Record what a live run would do to this batch's directories.
    fn trace_dry_run_dirs(&mut self, planned: &[PlannedDir], dst_root: &[u8]) {
        let opts = self.opts;
        for (p, dst_rel, e, destination) in planned {
            let meta_flags = if destination.is_some() {
                opts.matching_flags_for(dst_rel)
            } else {
                opts.flags_for(dst_rel)
            };
            let meta = opts.metadata_for(dst_rel, e);
            match destination {
                None => {
                    // The insert doubles as a dedupe: an explicit
                    // directory entry that upgrades a synthesized
                    // ancestor from an earlier chunk plans the same
                    // path again, and a live run's stat would filter
                    // it while a dry run has nothing to stat. The
                    // trace itself is deferred (see
                    // directory_creates).
                    if self.dry_run_changes.directories.insert(p.clone()) {
                        self.note_directory_change(p, true);
                        self.dry_run_changes
                            .directory_creates
                            .push((p.clone(), "destination_missing"));
                        if opts.verbose > 0 {
                            self.progress.println(&format!(
                                "create directory {} (destination missing)",
                                display_directory(p)
                            ));
                        }
                    }
                }
                Some(d)
                    if !opts.preserve_existing_directory_metadata
                        && !self.unselected_dirs.contains(p)
                        && (metadata_differs(&meta, &d.meta(), meta_flags)
                            || opts.metadata_fix_flags(dst_rel, e, d) != 0)
                        && !self.implicit_dirs.contains(p) =>
                {
                    self.dry_run_changes.metadata_directories.insert(p.clone());
                    if let Some(dst_rel) = strip_dst_root(p, dst_root) {
                        self.emit_trace_with_src(
                            "create_directory",
                            dst_rel,
                            "dir",
                            None,
                            "metadata_differs",
                            !self.implicit_dirs.contains(p),
                        );
                    }
                    if opts.verbose > 0 {
                        self.progress.println(&format!(
                            "update metadata {} (requested directory metadata differs)",
                            display_directory(p)
                        ));
                    }
                }
                Some(_) => {}
            }
        }
    }

    /// Queue the final metadata of this batch's directories, applied once
    /// their contents are written.
    fn defer_directory_metadata(&mut self, planned: &[PlannedDir]) -> Result<()> {
        let opts = self.opts;
        for (p, dst_rel, e, s) in planned {
            if self.unselected_dirs.contains(p) {
                // Existing containers keep their metadata. A new private root
                // receives the mode it would normally have been created with.
                if let Some(proposed) = self.private_root.filter(|_| p == &self.dst_root) {
                    self.deferred.push((
                        p.clone(),
                        Meta {
                            // Its final mode keeps the setgid bit it inherited.
                            mode: proposed | 0o2000,
                            uid: 0,
                            gid: 0,
                            mtime: 0,
                            mtime_nsec: 0,
                            inode_metadata: None,
                        },
                        flags::RECEIVER_MODE,
                        p.iter().filter(|&&c| c == b'/').count(),
                        self.metadata_condition_for(p),
                    ));
                }
                continue;
            }
            if self.implicit_dirs.contains(p) {
                continue;
            }
            if opts.preserve_existing_directory_metadata && !self.created_dirs.contains(p) {
                continue;
            }
            let depth = p.iter().filter(|&&c| c == b'/').count();
            let mut meta = opts.metadata_for(dst_rel, e);
            let mut flags = if s.is_some() && !self.created_dirs.contains(p) {
                opts.matching_flags_for(dst_rel)
            } else {
                opts.flags_for(dst_rel)
            };
            // Existing directories need no mode operation unless metadata was
            // requested. Actual temporary changes are merged later. A new
            // private root receives the mode its creation would have given it.
            // Another new directory was created with owner access to fill it;
            // `syq rsync` gives a source without that access its own mode
            // back, limited as its creation limits it, as rsync does. Native
            // cp leaves it the owner access, so a later copy can update it.
            if flags & flags::MODE == 0 && self.created_dirs.contains(p) {
                match self.private_root.filter(|_| p == &self.dst_root) {
                    Some(default) => {
                        // Under `syq rsync` a private root takes its source's
                        // mode as a new directory does. Its final mode keeps
                        // the setgid bit it inherited.
                        let proposed = if opts.rsync_creation {
                            e.mode & 0o777
                        } else {
                            default
                        };
                        meta.mode = proposed | 0o2000;
                        flags |= flags::RECEIVER_MODE;
                    }
                    None if opts.rsync_creation && e.mode & 0o700 != 0o700 => {
                        meta.mode = e.mode & 0o777;
                        flags |= flags::RECEIVER_MODE;
                    }
                    None => {}
                }
            }
            self.deferred.push((
                p.clone(),
                meta,
                flags,
                depth,
                self.metadata_condition_for(p),
            ));
        }
        Ok(())
    }

    /// Apply metadata corrections for files whose content is already current.
    fn flush_meta_fixes(&mut self, meta_fixes: Vec<(Op, PathBytes, DeclaredKind)>) -> Result<()> {
        if meta_fixes.is_empty() {
            return Ok(());
        }
        let (ops, entries): (Vec<_>, Vec<_>) = meta_fixes
            .into_iter()
            .map(|(op, dst, kind)| (op, (dst, kind)))
            .unzip();
        let errors = self.apply(ops)?;
        let capacity_error = first_capacity_error(&errors);
        for ((dst, kind), error) in entries.iter().zip(errors) {
            if let Some(error) = error {
                self.report_metadata_failure(Some(dst), *kind, &error);
            }
        }
        if let Some(error) = capacity_error {
            return Err(endpoint_error(error)).context("apply destination changes");
        }
        Ok(())
    }

    fn report_metadata_failure(&self, dst: Option<&[u8]>, kind: DeclaredKind, error: &WireError) {
        let os_kind = wire_os_kind(error);
        self.progress.error_classified(
            &format!("syq: {}", self.opts.wire_error_message(error)),
            Some("io"),
            os_kind,
        );
        if let Some(dst) = dst {
            self.emit_entry_failed(
                FailedEntry {
                    dst,
                    src: self.mapping_source_rel(dst).as_deref(),
                    kind: Some(kind),
                },
                "unknown",
                "io",
                os_kind,
                error.as_str(),
            );
        }
    }

    /// Apply the queued symlink and special-file operations and report each
    /// item's outcome.
    fn flush_leaf_ops(&mut self, ops: Vec<Op>, op_names: &[QueuedLeafOp]) -> Result<()> {
        if ops.is_empty() {
            return Ok(());
        }
        let opts = self.opts;
        let errs = self.apply(ops)?;
        let capacity_error = first_capacity_error(&errs);
        // Two ops per item: creation then metadata.
        for (i, queued) in op_names.iter().enumerate() {
            let e1 = errs.get(2 * i).cloned().flatten();
            let e2 = errs.get(2 * i + 1).cloned().flatten();
            let error = e1.or(e2);
            let os_kind = error.as_ref().and_then(wire_os_kind);
            if let Some(e) = &error {
                let path = join(&self.dst_root, &queued.dst_rel);
                self.progress.error_classified(
                    &format!("syq: {}", self.opts.wire_error_message_at(e, &path)),
                    Some("io"),
                    os_kind,
                );
            } else {
                // Counted only once the operation settles: a fatal
                // unwind between queueing and applying must not leave
                // phantom creations in the terminal aggregates.
                match queued.action {
                    "create_symlink" => {
                        self.progress.symlinks_created.fetch_add(1, Relaxed);
                    }
                    _ => {
                        self.progress.specials_created.fetch_add(1, Relaxed);
                    }
                }
                if opts.verbose > 0 {
                    self.progress.println(&queued.name);
                }
            }
            if let Some(results) = self.progress.results_writer() {
                results.emit_operation(&crate::results::OperationRecord {
                    action: queued.action,
                    dst: &queued.dst_rel,
                    src: self.mapping_source_rel(&queued.dst_rel).as_deref(),
                    kind: queued.kind,
                    disposition: if error.is_none() {
                        "succeeded"
                    } else {
                        "failed"
                    },
                    bytes: None,
                    attempts: None,
                    retryable: error.is_some().then_some("unknown"),
                    class: error.is_some().then_some("io"),
                    os_kind,
                    message: error.as_ref().map(WireError::as_str),
                });
            }
        }
        if let Some(error) = capacity_error {
            return Err(endpoint_error(error)).context("apply destination changes");
        }
        Ok(())
    }

    fn inspect_destination_batch(&mut self, mapped: &mut Mapped) -> Result<()> {
        // Keep the remote receiver's combined metadata lookup, but wait for
        // container access first: an inaccessible child must not be cached as
        // absent before apply_mapped makes its container searchable.
        if self.opts.inode_preservation.any()
            || !self.opts.dst_remote
            || self.buffer.is_some()
            || self.opts.dry_run
            || self.container_access.is_some()
            || self.destination_children_known_missing
            || self.container_guard.is_some()
        {
            return Ok(());
        }
        let directories: Vec<_> = mapped
            .dirs
            .iter()
            .map(|(path, _, _)| path.clone())
            .collect();
        let others: Vec<_> = mapped
            .others
            .iter()
            .map(|planned| planned.dst.clone())
            .collect();
        if directories.is_empty() && others.is_empty() {
            return Ok(());
        }
        match ok(
            self.dst.call(Request::PlanBatch {
                partial_paths: Vec::new(),
                copy_id: self.opts.copy_id,
                directories: directories.clone(),
                others: others.clone(),
                guard: None,
                strict_metadata: self.opts.expressions.update.is_some(),
            })?,
            "plan destination batch",
        )? {
            Response::BatchPlan {
                partial_paths,
                directories: dir_stats,
                others: other_stats,
            } if partial_paths.is_empty()
                && dir_stats.len() == directories.len()
                && other_stats
                    .as_ref()
                    .is_none_or(|stats| stats.len() == others.len()) =>
            {
                self.progress.observe_destination_devices(
                    dir_stats
                        .iter()
                        .flatten()
                        .chain(other_stats.iter().flatten().flatten()),
                );
                mapped.dir_stats = Some(dir_stats);
                if let Some(stats) = other_stats {
                    mapped.other_stats = Some(others.into_iter().zip(stats).collect());
                }
                Ok(())
            }
            other => bail!("unexpected response {other:?}"),
        }
    }

    pub(super) fn entry_is_payload(&self, entry: &Entry) -> bool {
        match entry.kind {
            Kind::Dir => self.opts.recursive || self.keep_dirs,
            Kind::File => true,
            Kind::Symlink => self.opts.links,
            Kind::Fifo | Kind::Socket | Kind::CharDev | Kind::BlockDev => self.opts.devices,
            Kind::Other => false,
        }
    }

    /// Display name for a source entry: its destination-relative path, or the
    /// source's basename when a single file is copied to an exact destination.
    /// --mapping: the manifest source path (base-relative) for a destination,
    /// so `--results` records round-trip as retry mapping entries. None
    /// outside mapping mode, where no base-relative source spelling exists.
    pub(super) fn mapping_source_rel(&self, dst_rel: &[u8]) -> Option<PathBytes> {
        if !self.mapping_mode {
            return None;
        }
        Some(
            self.src_overrides
                .get(dst_rel)
                .cloned()
                .unwrap_or_else(|| dst_rel.to_vec()),
        )
    }

    pub(super) fn refuse_directory_target(
        &self,
        dst: &[u8],
        dst_rel: &[u8],
        kind: Kind,
        entry: Option<&Entry>,
    ) -> bool {
        if !entry.is_some_and(|entry| entry.kind == Kind::Dir) {
            return false;
        }
        self.fail_directory_type_change(dst, dst_rel, kind);
        true
    }

    pub(super) fn fail_directory_type_change(&self, dst: &[u8], dst_rel: &[u8], kind: Kind) {
        let message = if kind == Kind::Dir {
            format!(
                "syq: cannot replace non-directory {} with a directory",
                display(dst)
            )
        } else {
            format!(
                "syq: cannot replace directory {} with a non-directory",
                display(dst)
            )
        };
        self.progress
            .error_classified(&message, Some("conflict"), None);
        self.emit_entry_failed(
            FailedEntry {
                dst: dst_rel,
                src: self.mapping_source_rel(dst_rel).as_deref(),
                kind: Some(match kind {
                    Kind::Dir => DeclaredKind::Dir,
                    Kind::File => DeclaredKind::File,
                    Kind::Symlink => DeclaredKind::Symlink,
                    _ => DeclaredKind::Special,
                }),
            },
            "no",
            "conflict",
            None,
            &message,
        );
    }

    /// Report only real manifest entries beneath a protected obstruction;
    /// synthesized directories have no source object or retry record.
    pub(super) fn fail_blocked_mapping_entry(
        &self,
        dst: &[u8],
        dst_rel: &[u8],
        kind: Kind,
    ) -> bool {
        // The parent conflict has already been reported. Do not schedule its
        // descendants or report them as separate failed copies.
        if Self::under_any(&self.blocked_directory_paths, dst, &self.dst_root) {
            return true;
        }
        if !Self::under_any(&self.blocked_mapping_parents, dst, &self.dst_root) {
            return false;
        }
        if !self.implicit_dirs.contains(dst) {
            let message = format!(
                "syq: {}: a file or symlink blocks an implicit mapping parent",
                display(dst)
            );
            self.progress
                .error_classified(&message, Some("conflict"), None);
            self.emit_mapping_entry_failed(
                &ManifestEntry {
                    expected_hash: self.opts.expected_for(dst_rel).cloned(),
                    metadata: self.opts.mapping_metadata.get(dst_rel).copied(),
                    src: self
                        .mapping_source_rel(dst_rel)
                        .expect("mapping parent failure"),
                    dst: dst_rel.to_vec(),
                    kind: Some(match kind {
                        Kind::Dir => DeclaredKind::Dir,
                        Kind::File => DeclaredKind::File,
                        Kind::Symlink => DeclaredKind::Symlink,
                        _ => DeclaredKind::Special,
                    }),
                },
                "unknown",
                "conflict",
                None,
                &message,
            );
        }
        true
    }

    /// A mapping entry that failed before any job existed (missing source,
    /// declared-kind mismatch): the error was already counted; this emits the
    /// per-entry result record retry tooling filters on.
    pub(super) fn emit_mapping_entry_failed(
        &self,
        entry: &ManifestEntry,
        retryable: &'static str,
        class: &'static str,
        os_kind: Option<&'static str>,
        message: &str,
    ) {
        self.emit_entry_failed(
            FailedEntry {
                dst: &entry.dst,
                src: Some(&entry.src),
                kind: entry.kind,
            },
            retryable,
            class,
            os_kind,
            message,
        );
    }

    pub(super) fn emit_entry_failed(
        &self,
        entry: FailedEntry<'_>,
        retryable: &'static str,
        class: &'static str,
        os_kind: Option<&'static str>,
        message: &str,
    ) {
        // Dry runs are trace-only: the error record and terminal accounting
        // still reflect the failure.
        if self.opts.dry_run {
            return;
        }
        if let Some(results) = self.progress.results_writer() {
            let (action, kind) = match entry.kind {
                Some(DeclaredKind::Dir) => ("create_directory", "dir"),
                Some(DeclaredKind::Symlink) => ("create_symlink", "symlink"),
                Some(DeclaredKind::Special) => ("create_special", "special"),
                _ => ("transfer_file", "file"),
            };
            results.emit_operation_expected(
                &crate::results::OperationRecord {
                    action,
                    dst: entry.dst,
                    src: entry.src,
                    kind,
                    disposition: "failed",
                    bytes: None,
                    attempts: None,
                    retryable: Some(retryable),
                    class: Some(class),
                    os_kind,
                    message: Some(message),
                },
                self.opts.expected_for(entry.dst),
            );
        }
    }

    /// Dry run: one intended mutation, from the same decision point that
    /// prints the -v explanation, so human and machine reasons cannot
    /// diverge.
    pub(super) fn emit_trace(
        &self,
        action: &'static str,
        dst_rel: &[u8],
        kind: &'static str,
        bytes: Option<u64>,
        reason: &'static str,
    ) {
        self.emit_trace_with_src(action, dst_rel, kind, bytes, reason, true);
    }

    pub(super) fn emit_trace_with_src(
        &self,
        action: &'static str,
        dst_rel: &[u8],
        kind: &'static str,
        bytes: Option<u64>,
        reason: &'static str,
        with_src: bool,
    ) {
        if let Some(results) = self.progress.results_writer() {
            let src = with_src.then(|| self.mapping_source_rel(dst_rel)).flatten();
            results.emit_trace(&crate::results::TraceRecord {
                action,
                dst: dst_rel,
                src: src.as_deref(),
                kind,
                bytes,
                reason,
            });
        }
    }

    pub(super) fn rel_name(&self, src_root: &[u8], sub_b: &[u8], path: &[u8]) -> String {
        let r = join(sub_b, path);
        if r.is_empty() {
            display(src_root.rsplit(|&c| c == b'/').next().unwrap_or(src_root))
        } else {
            display(&r)
        }
    }

    /// Record a leaf (file/symlink/special) destination; return false if this
    /// exact destination was already claimed by another source (a collision).
    /// Some(contested) if the claim stands; None on a conflict (reported).
    pub(super) fn claim_dst(&mut self, dst: &PathBytes, rel: &str, claim: Claim) -> Option<bool> {
        match (self.dst_seen.get(dst), claim) {
            (Some(Claim::Dir), Claim::Dir) | (Some(_), Claim::Weak) => Some(false),
            (Some(Claim::Weak), c) => {
                self.dst_seen.insert(dst.clone(), c);
                Some(false)
            }
            (Some(Claim::File { .. }), Claim::File { .. }) => Some(true),
            (Some(_), _) => {
                self.progress.error_classified(
                    &format!(
                        "syq: {rel}: two sources map to the same destination {} with conflicting types — refusing to clobber it",
                        display(dst)
                    ),
                    Some("conflict"),
                    None,
                );
                self.collision = true;
                None
            }
            (None, c) => {
                self.dst_seen.insert(dst.clone(), c);
                Some(false)
            }
        }
    }

    /// --existing: is some directory between the destination root and `dst`
    /// one we decided not to create?
    pub(super) fn under_missing_dir(&self, dst: &[u8], dst_root: &[u8]) -> bool {
        Self::under_any(&self.missing_dirs, dst, dst_root)
    }

    /// Is `dst`, or a directory between the destination root and it, in `set`?
    pub(super) fn under_any(
        set: &std::collections::HashSet<PathBytes>,
        dst: &[u8],
        dst_root: &[u8],
    ) -> bool {
        if set.is_empty() {
            return false;
        }
        // The root itself may be the missing one (e.g. a symlink to a
        // directory elsewhere, which we must neither replace nor write through).
        if set.contains(dst_root) {
            return true;
        }
        let mut end = dst.len();
        while let Some(i) = dst[..end].iter().rposition(|&c| c == b'/') {
            if i <= dst_root.len() {
                break;
            }
            if set.contains(&dst[..i]) {
                return true;
            }
            end = i;
        }
        false
    }

    pub(super) fn enqueue(
        &mut self,
        source_path: (PathBytes, RegisteredPath),
        dst: PathBytes,
        rel: String,
        rel_bytes: PathBytes,
        entry: Entry,
        dst_entry: Option<Entry>,
    ) -> usize {
        let (src, source) = source_path;
        let target_condition = self.leaf_condition_for(&dst, dst_entry.as_ref());
        let src_rel = self.mapping_source_rel(&rel_bytes);
        let scanned = match &dst_entry {
            Some(d) if d.kind == Kind::File => {
                crate::proto::ScannedDestination::File(d.mode & 0o7777)
            }
            _ => crate::proto::ScannedDestination::Absent,
        };
        self.progress.files_total.fetch_add(1, Relaxed);
        self.progress.bytes_total.fetch_add(entry.size, Relaxed);
        self.sched.push_file(FileJob {
            dst_entry,
            data: FileJobData {
                compare_ranges: false,
                compare_final: false,
                compared: false,
                resume_partial: false,
                recompared: 0,
                src,
                source,
                dst,
                rel,
                rel_bytes,
                entry,
                target_condition,
                container_guard: self.container_guard.clone(),
                attempt: 0,
                done: Arc::new(AtomicU64::new(0)),
                inplace: self.opts.inplace
                    && target_condition == TargetCondition::Any
                    && self.container_guard.is_none(),
                src_rel,
                scanned,
            },
        })
    }

    fn leaf_condition_for(&self, path: &[u8], destination: Option<&Entry>) -> TargetCondition {
        let placement = self.exact_condition_for(path);
        if placement == TargetCondition::Any
            && destination.is_none()
            && self.opts.protects_existing_contents()
        {
            TargetCondition::Absent
        } else {
            placement
        }
    }

    fn existing_conflict(&self, path: &[u8], rel: &[u8], reason: &str) {
        let message = format!(
            "{reason}: {} (--if-exists={})",
            display(path),
            self.opts.if_exists.unwrap().as_str()
        );
        self.report_existing_conflict(rel, &message);
    }

    fn report_existing_conflict(&self, rel: &[u8], message: &str) {
        self.progress.error(&format!("syq: {message}"));
        if !self.opts.dry_run {
            self.emit_entry_failed(
                FailedEntry {
                    dst: rel,
                    src: self.mapping_source_rel(rel).as_deref(),
                    kind: None,
                },
                "no",
                "conflict",
                None,
                message,
            );
        }
    }

    /// --ignore-existing / --existing for a leaf, given what's on the destination.
    pub(super) fn skip_existing(&self, dst_entry: &Option<Entry>) -> bool {
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
    pub(super) fn plan_deletes(&mut self) -> Result<()> {
        let mut roots = std::mem::take(&mut self.delete_roots);
        roots.sort();
        roots.dedup();
        // Sorting costs more than a few linear scans. Larger root sets share
        // one index; focused timings cover this crossover.
        let sorted_claims = (roots.len() >= 32).then(|| {
            let mut paths: Vec<_> = self.dst_seen.keys().collect();
            paths.sort_unstable();
            paths
        });
        // Destination-only directories a removal may find without access.
        let mut access_candidates = Vec::new();
        for (root, sub) in roots.clone() {
            // Every root is walked with its own --ignore anchoring. A root nested in
            // this one (`syq rsync --delete a b/ dst`: dst/a inside dst) is left to
            // its own walk, so its patterns apply and nothing is deleted twice.
            let nested: Vec<PathBytes> = roots
                .iter()
                .filter(|(r, _)| *r != root && path_is_inside(r, &root))
                .map(|(r, _)| r.clone())
                .collect();
            // Not there yet (a dry run into a new destination): nothing to delete.
            if stat_one(self.dst, &root, false)?.is_none() {
                continue;
            }
            // --delete-excluded: walk without the patterns, so ignored paths
            // are ordinary unclaimed extras (and nothing is protected).
            let ignore = if self.opts.delete_excluded {
                Vec::new()
            } else {
                self.opts.ignore.clone()
            };
            let mut found = Deletes::default();
            let mut partial_parents = std::collections::HashMap::new();
            let mut alias_parents = std::collections::HashSet::new();
            // A native copy that may widen directories enters owned
            // destination-only directories it cannot list, then walks beneath
            // them; rsync leaves them unlisted, as rsync does. Anchored ignore
            // patterns apply from the root, so with those the whole root is
            // walked again instead.
            let enter = self.opts.may_widen_directory_permissions() && !self.opts.rsync_creation;
            let subtrees = ignore
                .iter()
                .all(|pattern| ignore_pattern_is_unanchored(pattern));
            let mut attempted = std::collections::HashSet::new();
            let mut walk = PruneWalk::new(&self.dst_seen, &root, sorted_claims.as_deref());
            // Destination directories that hold an ignored path, so must stay.
            let mut protected: std::collections::HashSet<PathBytes> =
                std::collections::HashSet::new();
            // Each walk warning with the directory its walk started from.
            let mut warnings: Vec<(PathBytes, crate::proto::ScanWarning)> = Vec::new();
            let mut bases = vec![root.clone()];
            loop {
                for base in std::mem::take(&mut bases) {
                    let prefix = base
                        .get(root.len()..)
                        .map(|rest| rest.strip_prefix(b"/").unwrap_or(rest).to_vec())
                        .unwrap_or_default();
                    self.dst.scan(
                        &base,
                        None,
                        false,
                        &ignore,
                        true,
                        &mut |batch: Vec<Entry>| {
                            for mut entry in batch {
                                if base != root {
                                    // Its own entry came from the walk above.
                                    if entry.path.is_empty() {
                                        continue;
                                    }
                                    entry.path = join(&prefix, &entry.path);
                                }
                                walk.push(entry, &root, &nested);
                            }
                            Ok(())
                        },
                        &mut |paths: Vec<PathBytes>| {
                            for p in paths {
                                // Every ancestor of an ignored path is protected.
                                let p = join(&prefix, &p);
                                protected.extend(
                                    ancestor_prefixes(&p).map(|prefix| join(&root, prefix)),
                                );
                            }
                            Ok(())
                        },
                        &mut |w| warnings.push((base.clone(), w)),
                    )?;
                }
                if !enter || warnings.is_empty() {
                    break;
                }
                // Shielded entries stay; nothing beneath them is entered.
                walk.finish_scan(&root);
                let unreadable: Vec<_> = walk
                    .entries
                    .iter()
                    .filter(|entry| {
                        entry.kind == Kind::Dir
                            && entry.mode & 0o500 != 0o500
                            && attempted.insert(entry.path.clone())
                    })
                    .map(|entry| (entry.path.clone(), directory_fingerprint(entry)))
                    .collect();
                let candidates: Vec<PathBytes> =
                    unreadable.iter().map(|(path, _)| path.clone()).collect();
                if unreadable.is_empty()
                    || widen_directory_batch(
                        self.dst,
                        self.opts,
                        self.progress,
                        self.container_guard.clone(),
                        &mut self.directory_restorations,
                        unreadable,
                    )? == 0
                {
                    break;
                }
                let widened: Vec<PathBytes> = candidates
                    .into_iter()
                    .filter(|path| self.directory_restorations.contains_key(path))
                    .collect();
                if subtrees {
                    // Walking beneath them again answers their warnings.
                    warnings.retain(|(base, warning)| {
                        !warning.path.as_ref().is_some_and(|path| {
                            let path = join(base, path);
                            widened.iter().any(|directory| {
                                path == *directory || path_is_inside(&path, directory)
                            })
                        })
                    });
                    bases = widened;
                } else {
                    walk = PruneWalk::new(&self.dst_seen, &root, sorted_claims.as_deref());
                    protected.clear();
                    warnings.clear();
                    bases = vec![root.clone()];
                }
            }
            for (base, warning) in warnings {
                self.delete_walk_failed = true;
                // A preview names the directory it could not inspect.
                match warning.path.as_ref().filter(|_| self.opts.dry_run) {
                    Some(path) => self.progress.error(&format!(
                        "syq: {}: not inspected: {}",
                        display(&join(&base, path)),
                        warning.error
                    )),
                    None => self.progress.error(&format!("syq: delete: {warning}")),
                }
            }
            if self.delete_walk_failed {
                return Ok(());
            }
            walk.finish_scan(&root);
            // There is nothing for an alias to protect when no candidates
            // remain, including dry runs whose claimed files do not exist yet.
            if walk.entries.is_empty() {
                continue;
            }
            if self.opts.may_suggest_directory_access() {
                access_candidates.extend(
                    walk.entries
                        .iter()
                        .filter(|entry| entry.kind == Kind::Dir && entry.mode & 0o300 != 0o300)
                        .map(|entry| (entry.path.clone(), entry.clone())),
                );
            }
            // Destination-only directories whose entries a removal needs to
            // change but whose owner lacks write or search permission.
            let unwritable: std::collections::HashMap<PathBytes, TargetCondition> =
                if self.opts.may_widen_directory_permissions() {
                    walk.entries
                        .iter()
                        .filter(|entry| {
                            entry.kind == Kind::Dir
                                && entry.mode & 0o300 != 0o300
                                && !self.directory_restorations.contains_key(&entry.path)
                        })
                        .map(|entry| (entry.path.clone(), directory_fingerprint(entry)))
                        .collect()
                } else {
                    std::collections::HashMap::new()
                };
            let aliases = lookup_prune_aliases(self.dst, &walk, self.container_guard.as_ref())?;
            let mut shielded = walk.shielded;
            let recovery_parents = walk.recovery_parents;
            for entry in walk.entries {
                let full = entry.path;
                let entry_path =
                    &full[root.len() + usize::from(!root.is_empty() && !root.ends_with(b"/"))..];
                let entry_kind = entry.kind;
                if Planner::under_any(&shielded, &full, &root) {
                    continue;
                }
                let claimed = aliases.get(&(entry.dev, entry.ino));
                if claimed.is_some() {
                    // An ambiguous hard link may live in an otherwise extra
                    // directory. Keep its ancestors as well as the link.
                    alias_parents.extend(ancestor_prefixes(&full).map(<[u8]>::to_vec));
                }
                match claimed {
                    Some(Claim::Dir) => continue,
                    Some(_) => {
                        if entry_kind == Kind::Dir {
                            shielded.insert(full);
                        }
                        continue;
                    }
                    None => {}
                }
                let dst_rel = join(&sub, entry_path);
                let rel = display(&dst_rel);
                let name = entry_path
                    .rsplit(|&c| c == b'/')
                    .next()
                    .unwrap_or(entry_path);
                if entry_kind == Kind::File && is_partial_name(OsStr::from_bytes(name)) {
                    if self.opts.verbose > 0 {
                        self.progress.eprintln(&format!(
                                    "syq: not deleting {rel}: its name matches syq's partial-file format; use syq clean-partials after copies stop"
                                ));
                    }
                    for prefix in ancestor_prefixes(&full) {
                        partial_parents
                            .entry(prefix.to_vec())
                            .or_insert_with(|| rel.clone());
                    }
                } else {
                    if entry_kind == Kind::Dir {
                        let depth = full.iter().filter(|&&c| c == b'/').count();
                        found
                            .dirs
                            .entry(depth)
                            .or_default()
                            .push((full, format!("{rel}/"), "dir"));
                    } else {
                        let kind = match entry_kind {
                            Kind::Symlink => "symlink",
                            Kind::Fifo | Kind::Socket | Kind::CharDev | Kind::BlockDev => "special",
                            _ => "file",
                        };
                        found.leaves.push((full, rel, kind));
                    }
                }
            }

            let mut access = std::collections::BTreeMap::new();
            let mut needs_access = |path: &[u8], parent: bool| {
                let path = if parent {
                    parent_path(path)
                } else {
                    path.to_vec()
                };
                if let Some(condition) = unwritable.get(&path) {
                    access.insert(path, *condition);
                }
            };
            for (path, ..) in &found.leaves {
                needs_access(path, true);
            }
            self.deletes.leaves.append(&mut found.leaves);
            for (d, v) in found.dirs {
                for (path, rel, kind) in v {
                    if let Some(partial) = partial_parents.get(&path) {
                        self.progress.eprintln(&format!(
                            "syq: not deleting {rel}: it holds partial {partial}; use syq clean-partials after copies stop"
                        ));
                    } else if recovery_parents.contains(&path) {
                        self.progress.eprintln(&format!(
                            "syq: not deleting {rel}: it holds replacement recovery data"
                        ));
                    } else if alias_parents.contains(&path) {
                        self.progress.eprintln(&format!(
                            "syq: not deleting {rel}: it holds a possible filename alias"
                        ));
                    } else if protected.contains(&path) {
                        self.progress
                            .eprintln(&format!("syq: not deleting {rel}: it holds ignored paths"));
                    } else {
                        needs_access(&path, false);
                        needs_access(&path, true);
                        self.deletes
                            .dirs
                            .entry(d)
                            .or_default()
                            .push((path, rel, kind));
                    }
                }
            }
            self.deletes.access.extend(access);
        }
        if !access_candidates.is_empty() {
            // Walked directories are listable, so none is reported here as
            // uninspected; the rest are noted before their first removal.
            self.check_directory_access(access_candidates)?;
        }
        Ok(())
    }

    /// Remove what plan_deletes found: leaves first, then directories deepest
    /// first. Returns the number of entries removed (or that would be, with -n).
    /// Emit the dry run's deferred create_directory traces, after the whole
    /// scan has settled which directories are implicit and which mapping
    /// entries claimed them — so a directory synthesized in one chunk and
    /// upgraded by an explicit entry in a later one still traces with that
    /// entry's `src`.
    pub(super) fn flush_dry_directory_traces(&mut self) {
        let creates = std::mem::take(&mut self.dry_run_changes.directory_creates);
        for (path, reason) in creates {
            if let Some(dst_rel) = strip_dst_root(&path, &self.dst_root) {
                self.emit_trace_with_src(
                    "create_directory",
                    dst_rel,
                    "dir",
                    None,
                    reason,
                    !self.implicit_dirs.contains(&path),
                );
            }
        }
    }

    /// Timing belongs to the copy planner. Both modes require a complete,
    /// valid selection; only the default can also wait for successful copies.
    pub(super) fn prune(
        &mut self,
        overlap_unsearchable: bool,
        before: bool,
    ) -> Result<(u64, DeletePlan)> {
        let reason = if self.scan_warned {
            Some(("source scan reported errors", "source scan errors"))
        } else if overlap_unsearchable {
            Some((
                "source ancestry could not be checked",
                "source ancestry could not be checked",
            ))
        } else if self.progress.errors.load(Relaxed) != 0 {
            Some(("copy reported errors", "copy errors"))
        } else {
            None
        };
        if let Some((message, reason)) = reason {
            self.progress
                .eprintln(&format!("syq: {message}; skipping deletions"));
            return Ok((0, DeletePlan::Skipped(reason)));
        }
        if before && self.destination_root_known_missing {
            return Ok((0, DeletePlan::Planned(0)));
        }
        match self
            .assert_mutation_root()
            .and_then(|_| self.plan_deletes())
        {
            Ok(()) if self.delete_walk_failed => {
                self.progress
                    .eprintln("syq: destination walk reported errors; skipping deletions");
                Ok((0, DeletePlan::Skipped("destination walk errors")))
            }
            Ok(()) => {
                let planned = DeletePlan::Planned(self.deletes.len());
                self.assert_mutation_root()?;
                Ok((self.run_deletes()?, planned))
            }
            Err(error) => {
                self.progress.error(&format!("syq: delete: {error:#}"));
                Ok((0, DeletePlan::Skipped("destination planning failed")))
            }
        }
    }

    pub(super) fn run_deletes(&mut self) -> Result<u64> {
        let opts = self.opts;
        let leaves = std::mem::take(&mut self.deletes.leaves);
        let dirs = std::mem::take(&mut self.deletes.dirs);
        let mut access = std::mem::take(&mut self.deletes.access);
        let planned = leaves.len() as u64 + dirs.values().map(|v| v.len() as u64).sum::<u64>();
        self.progress.deletions_planned.store(planned, Relaxed);
        if let Some(max) = opts.max_delete {
            if planned > max {
                self.progress.eprintln(&format!(
                    "syq: {planned} deletions planned, more than --max-delete {max}; deleting nothing"
                ));
                if let Some(results) = self.progress.results_writer().filter(|_| !opts.dry_run) {
                    let blocked = leaves
                        .iter()
                        .map(|(p, _, kind)| (p, *kind))
                        .chain(dirs.values().flatten().map(|(p, _, _)| (p, "dir")));
                    for (p, kind) in blocked {
                        let Some(dst_rel) = strip_dst_root(p, &self.dst_root) else {
                            continue;
                        };
                        results.emit_operation(&crate::results::OperationRecord {
                            action: "delete",
                            dst: dst_rel,
                            src: None,
                            kind,
                            disposition: "blocked",
                            bytes: None,
                            attempts: None,
                            retryable: None,
                            class: Some("safety_limit"),
                            os_kind: None,
                            message: None,
                        });
                    }
                }
                self.max_delete_hit = true;
                self.progress.deletions_blocked.store(planned, Relaxed);
                return Ok(0);
            }
        }
        if !opts.dry_run && !access.is_empty() {
            // Parents first; a removed directory's saved mode is dropped below.
            access.sort_by_key(|(path, _)| path.iter().filter(|&&c| c == b'/').count());
            access.dedup_by(|a, b| a.0 == b.0);
            self.widen_directories(access)?;
        }
        let mut n = 0u64;
        let mut run = |me: &mut Self,
                       items: &[(PathBytes, String, &'static str)],
                       rmdir: bool|
         -> Result<()> {
            for (path, ..) in items {
                me.note_directory_change(path, true);
            }
            for chunk in items.chunks(1000) {
                if opts.dry_run {
                    for (p, rel, kind) in chunk {
                        n += 1;
                        me.progress.deletions_completed.fetch_add(1, Relaxed);
                        if let Some(dst_rel) = strip_dst_root(p, &me.dst_root) {
                            me.emit_trace("delete", dst_rel, kind, None, "destination_only");
                        }
                        if opts.verbose > 0 {
                            me.progress
                                .println(&format!("delete {rel} (destination only)"));
                        }
                    }
                    continue;
                }
                let ops: Vec<Op> = chunk
                    .iter()
                    .map(|(p, _, _)| {
                        if rmdir {
                            Op::Rmdir { path: p.clone() }
                        } else {
                            // Never Remove: that recurses into a directory
                            // that appeared here since the walk.
                            Op::Unlink { path: p.clone() }
                        }
                    })
                    .collect();
                let errs = me.apply(ops)?;
                for ((p, rel, kind), err) in chunk.iter().zip(errs) {
                    let failed = err.is_some();
                    match err {
                        None => {
                            n += 1;
                            if rmdir {
                                me.directory_restorations.remove(p);
                            }
                            me.progress.deletions_completed.fetch_add(1, Relaxed);
                            if opts.verbose > 0 {
                                me.progress.println(&format!("deleting {rel}"));
                            }
                        }
                        Some(e) => me.progress.error_classified(
                            &format!("syq: delete {rel}: {e}"),
                            Some("io"),
                            None,
                        ),
                    }
                    if let Some(results) = me.progress.results_writer() {
                        let Some(dst_rel) = strip_dst_root(p, &me.dst_root) else {
                            continue;
                        };
                        results.emit_operation(&crate::results::OperationRecord {
                            action: "delete",
                            dst: dst_rel,
                            src: None,
                            kind,
                            disposition: if failed { "failed" } else { "succeeded" },
                            bytes: None,
                            attempts: None,
                            retryable: failed.then_some("unknown"),
                            class: failed.then_some("io"),
                            os_kind: None,
                            message: None,
                        });
                    }
                }
            }
            Ok(())
        };
        run(
            self,
            &crate::deletion::spread(leaves, |item| &item.0),
            false,
        )?;
        for (_, items) in dirs.into_iter().rev() {
            run(self, &crate::deletion::spread(items, |item| &item.0), true)?;
        }
        Ok(n)
    }

    /// Destination stats for a fresh tree: every descendant is absent. The
    /// root keeps its lookup so an existing empty root's metadata is
    /// preserved, unless it was missing at preflight: then it is absent until
    /// this copy creates it, after which the mutation-root identity check has
    /// already observed it this batch. Earlier batches may have created a
    /// shared directory; inspect it again so creation accounting and
    /// metadata decisions see that state.
    fn stat_fresh_descendants<'p>(
        &mut self,
        root_entry: Option<&Entry>,
        paths: impl Iterator<Item = &'p PathBytes> + Clone,
    ) -> Result<Vec<Option<Entry>>> {
        let mut stats = vec![None; paths.clone().count()];
        let mut positions = Vec::new();
        let mut inspect = Vec::new();
        for (index, path) in paths.enumerate() {
            if path == &self.dst_root {
                match root_entry {
                    Some(root) => stats[index] = Some(root.clone()),
                    None if self.destination_root_known_missing => {}
                    None => {
                        positions.push(index);
                        inspect.push(path.clone());
                    }
                }
            } else if self.created_dirs.contains(path) {
                positions.push(index);
                inspect.push(path.clone());
            }
        }
        if !inspect.is_empty() {
            for (index, entry) in positions.into_iter().zip(self.stat_many(inspect)?) {
                stats[index] = entry;
            }
        }
        Ok(stats)
    }

    pub(super) fn stat_many(&mut self, mut paths: Vec<PathBytes>) -> Result<Vec<Option<Entry>>> {
        let strict_preview =
            self.opts.dry_run && (self.opts.restricted_receiver || self.opts.rsync_creation);
        let preserve = self.opts.inode_preservation.any();
        let entries = if self.opts.expressions.update.is_some() {
            // This existing endpoint operation distinguishes absence from an
            // unreadable path, unlike ordinary planning stats. It has the same
            // destination-observation authority and needs no wire extension.
            let lookup = if preserve {
                paths.clone()
            } else {
                std::mem::take(&mut paths)
            };
            let inspected = if strict_preview {
                self.inspect_preview(lookup)?
            } else {
                inspect_destination_paths(
                    self.dst,
                    lookup,
                    self.container_guard.clone(),
                    "inspect destination for --copy-if",
                )?
            };
            if preserve && inspected.iter().any(Option::is_some) {
                // Strict lookup supplies expression fields. Rich preservation
                // still uses the existing metadata capture request.
                let captured = stat_many(self.dst, paths, false)?;
                anyhow::ensure!(
                    captured.len() == inspected.len(),
                    "destination stat count changed"
                );
                for (before, after) in inspected.iter().zip(&captured) {
                    if let Some(before) = before {
                        anyhow::ensure!(
                            after.as_ref().is_some_and(|after| (
                                before.dev,
                                before.ino,
                                before.ctime,
                                before.ctime_nsec
                            ) == (
                                after.dev,
                                after.ino,
                                after.ctime,
                                after.ctime_nsec
                            )),
                            "destination changed while reading metadata for --copy-if"
                        );
                    }
                }
                captured
            } else {
                inspected
            }
        } else if strict_preview && preserve {
            // One rich lookup, as an ordinary preview makes. Only the paths it
            // did not find need the strict one, to tell a denial from absence.
            let mut captured = stat_many(self.dst, paths.clone(), false)?;
            let missing: Vec<usize> = (0..captured.len())
                .filter(|&index| captured[index].is_none())
                .collect();
            if !missing.is_empty() {
                let inspected = self
                    .inspect_preview(missing.iter().map(|&index| paths[index].clone()).collect())?;
                for (&index, entry) in missing.iter().zip(inspected) {
                    captured[index] = entry;
                }
            }
            captured
        } else if strict_preview {
            // Previews never change permissions, so a denied lookup stays an
            // error rather than a missing file.
            self.inspect_preview(paths)?
        } else {
            stat_many(self.dst, paths, false)?
        };
        self.progress
            .observe_destination_devices(entries.iter().flatten());
        Ok(entries)
    }

    /// Strict lookups for a preview. A denied directory does not end it: it
    /// is reported once as not inspected and its contents are skipped, as
    /// rsync reports a path it cannot stat and goes on.
    fn inspect_preview(&mut self, paths: Vec<PathBytes>) -> Result<Vec<Option<Entry>>> {
        // Inside a directory this preview found missing nothing exists.
        let mut results = vec![None; paths.len()];
        let needed: Vec<usize> = (0..paths.len())
            .filter(|&index| {
                !self
                    .dry_run_changes
                    .directories
                    .contains(&parent_path(&paths[index]))
            })
            .collect();
        if needed.is_empty() {
            return Ok(results);
        }
        let lookups: Vec<PathBytes> = if needed.len() == paths.len() {
            paths
        } else {
            needed.iter().map(|&index| paths[index].clone()).collect()
        };
        let reported = &mut self.access_reported;
        let progress = self.progress;
        let entries = inspect_tolerating_denials(
            self.dst,
            &lookups,
            self.container_guard.clone(),
            &self.dst_root,
            &mut self.blocked_directory_paths,
            &mut |directory, error| {
                if reported.insert(directory.to_vec()) {
                    progress.error_classified(
                        &format!("syq: {}: not inspected: {error:#}", display(directory)),
                        Some("io"),
                        Some("permission_denied"),
                    );
                }
            },
        )?;
        for (index, entry) in needed.into_iter().zip(entries) {
            results[index] = entry;
        }
        Ok(results)
    }

    /// Avoid querying descendants of a directory conflict. The planner skips
    /// these entries; inspecting them could traverse an obstructing symlink.
    pub(super) fn stat_many_with_dry_run_overlay(
        &mut self,
        paths: Vec<PathBytes>,
        dst_root: &[u8],
    ) -> Result<Vec<Option<Entry>>> {
        if !self.opts.dry_run || self.blocked_directory_paths.is_empty() {
            return self.stat_many(paths);
        }
        let mut visible = Vec::new();
        let mut indexes = Vec::new();
        let mut results = vec![None; paths.len()];
        for (index, path) in paths.into_iter().enumerate() {
            if !Self::under_any(&self.blocked_directory_paths, &path, dst_root) {
                indexes.push(index);
                visible.push(path);
            }
        }
        for (index, entry) in indexes.into_iter().zip(self.stat_many(visible)?) {
            results[index] = entry;
        }
        Ok(results)
    }

    /// Stat dry-run directories parent-depth first, hiding descendants of
    /// obstructing leaves. The planner reports the parent conflict and skips
    /// its subtree without following an intermediate symlink.
    pub(super) fn stat_directories_with_dry_run_overlay(
        &mut self,
        dirs: &[(PathBytes, PathBytes, Entry)],
        dst_root: &[u8],
    ) -> Result<Vec<Option<Entry>>> {
        if !self.opts.dry_run {
            return self.stat_many(dirs.iter().map(|(path, _, _)| path.clone()).collect());
        }
        let existing = self.opts.existing;
        let ignore_existing = self.opts.ignore_existing;
        let mut blocked = self.blocked_directory_paths.clone();
        let mut missing = self.missing_dirs.clone();
        let mut by_depth: std::collections::BTreeMap<usize, Vec<usize>> =
            std::collections::BTreeMap::new();
        for (index, (_, dst_rel, _)) in dirs.iter().enumerate() {
            let depth = if dst_rel.is_empty() {
                0
            } else {
                1 + dst_rel.iter().filter(|&&byte| byte == b'/').count()
            };
            by_depth.entry(depth).or_default().push(index);
        }

        let mut results = vec![None; dirs.len()];
        for indexes in by_depth.into_values() {
            let mut visible = Vec::new();
            let mut visible_indexes = Vec::new();
            for &index in &indexes {
                let path = &dirs[index].0;
                let hidden_by_conflict = Self::under_any(&blocked, path, dst_root);
                let hidden_by_option =
                    (existing || ignore_existing) && Self::under_any(&missing, path, dst_root);
                if !hidden_by_conflict && !hidden_by_option {
                    visible_indexes.push(index);
                    visible.push(path.clone());
                }
            }
            for (index, entry) in visible_indexes.into_iter().zip(self.stat_many(visible)?) {
                results[index] = entry;
            }
            // Directories found uninspectable by those lookups hide theirs.
            blocked.extend(self.blocked_directory_paths.iter().cloned());
            // A directory this preview cannot search hides its contents.
            let candidates = indexes
                .iter()
                .filter_map(|&index| {
                    results[index]
                        .as_ref()
                        .filter(|entry| entry.kind == Kind::Dir && entry.mode & 0o300 != 0o300)
                        .map(|entry| (dirs[index].0.clone(), entry.clone()))
                })
                .collect::<Vec<_>>();
            if !candidates.is_empty() {
                for path in self.check_directory_access(candidates)? {
                    blocked.insert(path.clone());
                    self.blocked_directory_paths.insert(path);
                }
            }
            for index in indexes {
                let path = &dirs[index].0;
                let entry = &results[index];
                let is_dir = entry.as_ref().is_some_and(|item| item.kind == Kind::Dir);
                let conflict = ignore_existing && !is_dir && entry.is_some();
                if conflict
                    || (existing && !is_dir)
                    || ((existing || ignore_existing) && Self::under_any(&missing, path, dst_root))
                {
                    missing.insert(path.clone());
                } else if entry.as_ref().is_some_and(|item| item.kind != Kind::Dir) {
                    blocked.insert(path.clone());
                }
            }
        }
        Ok(results)
    }

    pub(super) fn apply(&mut self, mut ops: Vec<Op>) -> Result<Vec<Option<WireError>>> {
        if ops.len() > 1
            && ops.iter().map(Op::size_hint).sum::<usize>() > crate::proto::METADATA_BATCH_BYTES
        {
            let tail = ops.split_off(ops.len() / 2);
            let mut results = self.apply(ops)?;
            results.extend(self.apply(tail)?);
            return Ok(results);
        }
        match ok(
            self.dst.call(Request::Apply {
                ops,
                guard: self.container_guard.clone(),
            })?,
            "apply",
        )? {
            Response::Applied(v) => Ok(v),
            other => bail!("unexpected response {other:?}"),
        }
    }

    /// Whether the receiving account owns `entry`. The receiver is asked its
    /// account once, only after a directory needing access has been found.
    fn receiver_owns(&mut self, entry: &Entry) -> Result<bool> {
        if self.receiver_uid.is_none() {
            let uid = match ok(self.dst.call(Request::ReceiverUser)?, "receiving account")? {
                Response::ReceiverUser(uid) => uid,
                other => bail!("unexpected receiving account response {other:?}"),
            };
            self.receiver_uid = Some((uid != 0).then_some(uid));
        }
        Ok(self.receiver_uid.flatten() == Some(entry.uid))
    }

    /// Sort existing directories whose owner lacks write or search
    /// permission, using the modes and owners the destination scan already
    /// read. A dry run cannot look inside an owned one without search
    /// permission: it reports it as not inspected and returns it, so its
    /// contents are skipped. Without temporary access, the others are noted
    /// for the first change planned inside them.
    fn check_directory_access(
        &mut self,
        candidates: Vec<(PathBytes, Entry)>,
    ) -> Result<Vec<PathBytes>> {
        let mut uninspected = Vec::new();
        let hint = self.opts.may_suggest_directory_access();
        if !(hint || self.opts.dry_run) {
            return Ok(uninspected);
        }
        for (path, entry) in candidates {
            // Without the hint, only a preview's unsearchable directories matter.
            if entry.kind != Kind::Dir
                || entry.mode & 0o300 == 0o300
                || !hint && entry.mode & 0o100 != 0
                || self.opts.access_limited.lock().unwrap().contains_key(&path)
                || self.access_reported.contains(&path)
                || self.opts.access_noted.lock().unwrap().contains(&path)
                || !self.receiver_owns(&entry)?
            {
                continue;
            }
            if self.opts.dry_run && entry.mode & 0o100 == 0 {
                self.access_reported.insert(path.clone());
                self.progress.error_classified(
                    &format!(
                        "syq: {}: not inspected: you own this directory, but it lacks owner search permission{}",
                        display(&path),
                        if hint {
                            format!("; {DIRECTORY_ACCESS_HINT}")
                        } else {
                            String::new()
                        }
                    ),
                    Some("io"),
                    Some("permission_denied"),
                );
                uninspected.push(path);
            } else if hint {
                self.opts
                    .access_limited
                    .lock()
                    .unwrap()
                    .insert(path, entry.mode);
            }
        }
        Ok(uninspected)
    }

    /// Report, once and before the first change planned at `path`, that its
    /// directory is owned but lacks the owner permission the change needs.
    pub(super) fn note_directory_change(&mut self, path: &[u8], replaces_entry: bool) {
        self.opts
            .note_directory_change(self.progress, path, replaces_entry);
    }

    fn prepare_container_access(&mut self) -> Result<()> {
        if let Some(directory) = self.container_access.take() {
            self.widen_directories(vec![directory])?;
        }
        Ok(())
    }

    fn prepare_existing_directories(&mut self, mut paths: Vec<PathBytes>) -> Result<()> {
        if !self.opts.may_widen_directory_permissions() {
            return Ok(());
        }
        self.assert_mutation_root()?;
        paths.sort_by(|a, b| {
            a.iter()
                .filter(|&&c| c == b'/')
                .count()
                .cmp(&b.iter().filter(|&&c| c == b'/').count())
                .then(a.cmp(b))
        });
        paths.dedup();
        for depth in paths.chunk_by(|a, b| {
            a.iter().filter(|&&c| c == b'/').count() == b.iter().filter(|&&c| c == b'/').count()
        }) {
            for chunk in depth.chunks(1000) {
                let stats = self.stat_many(chunk.to_vec())?;
                let directories: Vec<_> = chunk
                    .iter()
                    .zip(stats)
                    .filter_map(|(path, entry)| {
                        let entry = entry.filter(|entry| {
                            entry.kind == Kind::Dir && entry.mode & 0o700 != 0o700
                        })?;
                        (!self.directory_restorations.contains_key(path)).then(|| {
                            (
                                path.clone(),
                                TargetCondition::MatchesFingerprint {
                                    dev: entry.dev,
                                    ino: entry.ino,
                                    ctime: entry.ctime,
                                    ctime_nsec: entry.ctime_nsec,
                                },
                            )
                        })
                    })
                    .collect();
                if directories.is_empty() {
                    continue;
                }
                self.widen_directories(directories)?;
            }
        }
        Ok(())
    }

    fn widen_directories(&mut self, directories: Vec<(PathBytes, TargetCondition)>) -> Result<()> {
        widen_directory_batch(
            self.dst,
            self.opts,
            self.progress,
            self.container_guard.clone(),
            &mut self.directory_restorations,
            directories,
        )
        .map(|_| ())
    }

    pub(super) fn apply_deferred(&mut self, aborted: bool) -> Result<()> {
        if self.directory_restorations.is_empty() && (aborted || self.deferred.is_empty()) {
            return Ok(());
        }
        let quiet = std::mem::replace(&mut self.restorations_attempted, true);
        self.assert_mutation_root()?;
        let mut d = if aborted {
            Vec::new()
        } else {
            std::mem::take(&mut self.deferred)
        };
        // Several sources can give one directory metadata, in source order.
        // The receiver applies a batch in parallel, so each directory gets one
        // change that leaves it as applying them in turn would.
        d.sort_by(|a, b| b.3.cmp(&a.3).then_with(|| a.0.cmp(&b.0)));
        d.dedup_by(|later, earlier| {
            later.0 == earlier.0 && {
                merge_directory_metadata(earlier, later);
                true
            }
        });
        // Without -p the receiver restores the modes of the directories it
        // widened itself.
        let restoration_flags = if self.opts.perms {
            flags::MODE
        } else {
            flags::RECEIVER_MODE
        };
        // Keep each saved mode until its restoration succeeds, so that an
        // early error still restores it when the planner is dropped.
        let mut remaining = self.directory_restorations.clone();
        for (path, meta, flags, _, condition) in &mut d {
            if let Some(saved) = remaining.remove(path) {
                if *flags & (flags::MODE | flags::RECEIVER_MODE) == 0 {
                    meta.mode = saved.mode;
                    *flags |= restoration_flags;
                }
                *condition = TargetCondition::Matches {
                    dev: saved.dev,
                    ino: saved.ino,
                };
            }
        }
        for (path, saved) in remaining {
            let depth = path.iter().filter(|&&c| c == b'/').count();
            d.push((
                path,
                Meta {
                    mode: saved.mode,
                    uid: 0,
                    gid: 0,
                    mtime: 0,
                    mtime_nsec: 0,
                    inode_metadata: None,
                },
                restoration_flags,
                depth,
                TargetCondition::Matches {
                    dev: saved.dev,
                    ino: saved.ino,
                },
            ));
        }
        d.retain(|(_, _, flags, _, _)| *flags != 0);
        d.sort_by(|a, b| b.3.cmp(&a.3));
        let mut pending = d.as_slice();
        while !pending.is_empty() {
            let (chunk, rest) = pending.split_at(directory_metadata_batch_len(pending));
            pending = rest;
            let ops: Vec<Op> = chunk
                .iter()
                .map(|(p, m, f, _, condition)| Op::SetMeta {
                    path: p.clone(),
                    meta: m.clone(),
                    flags: *f,
                    condition: *condition,
                })
                .collect();
            let errors = self.apply(ops)?;
            let capacity_error = first_capacity_error(&errors);
            for ((path, ..), error) in chunk.iter().zip(errors) {
                if let Some(error) = error {
                    if quiet {
                        continue;
                    }
                    let dst = (!self.implicit_dirs.contains(path))
                        .then(|| strip_dst_root(path, &self.dst_root))
                        .flatten();
                    self.report_metadata_failure(dst, DeclaredKind::Dir, &error);
                } else {
                    self.directory_restorations.remove(path);
                }
            }
            if let Some(error) = capacity_error {
                return Err(endpoint_error(error)).context("apply destination changes");
            }
        }
        Ok(())
    }
}

/// Whether an ignore pattern matches the same names from any directory, so a
/// subtree can be walked on its own: it names no path with a `/` other than a
/// trailing one.
fn ignore_pattern_is_unanchored(pattern: &str) -> bool {
    let pattern = pattern.trim();
    let pattern = pattern.strip_prefix('!').unwrap_or(pattern);
    !pattern.trim_end_matches('/').contains('/')
}

/// Strict destination lookups that survive denials. When a batch is denied,
/// its paths are looked up again in halves to find the denied ones; each
/// one's parent directory goes into `blocked` and to `report`, and paths
/// beneath a blocked directory are skipped, reading as absent.
pub(super) fn inspect_tolerating_denials(
    conn: &mut dyn Conn,
    paths: &[PathBytes],
    guard: Option<ContainerGuard>,
    dst_root: &[u8],
    blocked: &mut std::collections::HashSet<PathBytes>,
    report: &mut dyn FnMut(&[u8], &anyhow::Error),
) -> Result<Vec<Option<Entry>>> {
    let mut results = vec![None; paths.len()];
    let visible: Vec<usize> = (0..paths.len())
        .filter(|&index| !Planner::under_any(blocked, &paths[index], dst_root))
        .collect();
    if visible.is_empty() {
        return Ok(results);
    }
    let batch = visible.iter().map(|&index| paths[index].clone()).collect();
    match inspect_destination_paths(
        conn,
        batch,
        guard.clone(),
        "inspect destination for preview",
    ) {
        Ok(entries) => {
            for (&index, entry) in visible.iter().zip(entries) {
                results[index] = entry;
            }
        }
        Err(error) if os_kind_of(&error) == Some("permission_denied") => {
            if let [index] = visible[..] {
                let parent = parent_path(&paths[index]);
                report(&parent, &error);
                blocked.insert(parent);
            } else {
                let (first, second) = visible.split_at(visible.len() / 2);
                for half in [first, second] {
                    let subset: Vec<PathBytes> =
                        half.iter().map(|&index| paths[index].clone()).collect();
                    let entries = inspect_tolerating_denials(
                        conn,
                        &subset,
                        guard.clone(),
                        dst_root,
                        blocked,
                        report,
                    )?;
                    for (&index, entry) in half.iter().zip(entries) {
                        results[index] = entry;
                    }
                }
            }
        }
        Err(error) => return Err(error),
    }
    Ok(results)
}

/// Temporarily add owner access to `directories` and remember the original
/// modes of those actually changed; returns how many changed. The receiver
/// widens only owned directories, never as root.
fn widen_directory_batch(
    dst: &mut dyn Conn,
    opts: &Opts,
    progress: &Progress,
    guard: Option<ContainerGuard>,
    restorations: &mut std::collections::HashMap<PathBytes, crate::proto::DirectoryMode>,
    directories: Vec<(PathBytes, TargetCondition)>,
) -> Result<usize> {
    let mut widened = 0;
    let mut directories = directories.into_iter().peekable();
    while directories.peek().is_some() {
        let batch: Vec<_> = directories.by_ref().take(1000).collect();
        let names: Vec<_> = batch.iter().map(|(path, _)| path.clone()).collect();
        let response = ok(
            dst.call(Request::WidenDirectories {
                directories: batch,
                // Without -p the receiver restores the modes it saves.
                remember: !opts.perms,
                guard: guard.clone(),
            })?,
            "prepare directory permissions",
        )?;
        let Response::WidenedDirectories(results) = response else {
            bail!("unexpected directory access response {response:?}");
        };
        anyhow::ensure!(
            results.len() == names.len(),
            "directory access response count mismatch"
        );
        for (path, result) in names.into_iter().zip(results) {
            match result {
                Ok(Some(mode)) => {
                    restorations.insert(path, mode);
                    widened += 1;
                }
                Ok(None) => {}
                Err(error) => progress.error_classified(
                    &format!(
                        "syq: {}: {}",
                        display(&path),
                        opts.wire_error_message(&error)
                    ),
                    Some("io"),
                    wire_os_kind(&error),
                ),
            }
        }
    }
    Ok(widened)
}

fn directory_fingerprint(entry: &Entry) -> TargetCondition {
    TargetCondition::MatchesFingerprint {
        dev: entry.dev,
        ino: entry.ino,
        ctime: entry.ctime,
        ctime_nsec: entry.ctime_nsec,
    }
}

/// Merge a later directory metadata entry into an earlier one for the same
/// directory, as applying the earlier and then the later would leave it: each
/// field the later one sets replaces the earlier value, and the rest stay.
fn merge_directory_metadata(
    earlier: &mut (PathBytes, Meta, u8, usize, TargetCondition),
    later: &mut (PathBytes, Meta, u8, usize, TargetCondition),
) {
    let (_, meta, flags, _, _) = earlier;
    let (_, later_meta, later_flags, _, _) = later;
    let replaced = |field: u8, required: u8, flags: &mut u8| {
        *flags = *flags & !(field | required) | *later_flags & (field | required);
    };
    if *later_flags & flags::MODE_MASK != 0 {
        meta.mode = later_meta.mode;
        replaced(flags::MODE_MASK, 0, flags);
    }
    if *later_flags & flags::OWNER != 0 {
        meta.uid = later_meta.uid;
        replaced(flags::OWNER, flags::REQUIRE_OWNER, flags);
    }
    if *later_flags & flags::GROUP != 0 {
        meta.gid = later_meta.gid;
        replaced(flags::GROUP, flags::REQUIRE_GROUP, flags);
    }
    if *later_flags & flags::TIMES != 0 {
        meta.mtime = later_meta.mtime;
        meta.mtime_nsec = later_meta.mtime_nsec;
        *flags |= flags::TIMES;
    }
    if let Some(later_inode) = later_meta.inode_metadata.take() {
        match &mut meta.inode_metadata {
            Some(inode) => inode.overlay(*later_inode),
            None => meta.inode_metadata = Some(later_inode),
        }
    }
}

/// Keep ordinary metadata in full batches, even across directory depths. Only
/// a mode that removes search access needs to wait for deeper operations.
fn directory_metadata_batch_len(
    entries: &[(PathBytes, Meta, u8, usize, TargetCondition)],
) -> usize {
    let maximum = entries.len().min(1000);
    let deepest = entries[0].3;
    entries[..maximum]
        .iter()
        .position(|(_, meta, flags, depth, _)| {
            *depth < deepest
                && flags & (flags::MODE | flags::RECEIVER_MODE) != 0
                && meta.mode & 0o100 == 0
        })
        .unwrap_or(maximum)
}

/// A destination ancestor directory without selected source metadata: created
/// with receiver defaults (mode through the umask, natural mtime; see
/// `Planner::implicit_dirs`).
pub(super) fn implicit_dir_entry(path: PathBytes) -> Entry {
    Entry {
        path,
        kind: Kind::Dir,
        size: 0,
        mtime: 0,
        mtime_nsec: 0,
        mode: 0o777,
        uid: 0,
        gid: 0,
        rdev: 0,
        dev: 0,
        ino: 0,
        ctime: 0,
        atime: Default::default(),
        inode_metadata: None,
        nlink: 1,
        ctime_nsec: 0,
        link: None,
    }
}

/// Destination operations collected while classifying one batch of leaves.
/// Each entry of `names` owns two consecutive entries of `ops`: the creation
/// and then its metadata.
#[derive(Default)]
struct LeafOps {
    ops: Vec<Op>,
    names: Vec<QueuedLeafOp>,
    // Metadata-only operations retain the same retry identity as content copies.
    meta_fixes: Vec<(Op, PathBytes, DeclaredKind)>,
}

/// A queued symlink/special creation: the display string for -v plus the
/// machine-readable identity `--results` records need.
pub(super) struct QueuedLeafOp {
    pub(super) dst_rel: PathBytes,
    pub(super) action: &'static str,
    pub(super) kind: &'static str,
    pub(super) name: String,
}

/// The container-relative spelling of a full destination path; None for the
/// container itself.
pub(super) fn strip_dst_root<'p>(path: &'p [u8], dst_root: &[u8]) -> Option<&'p [u8]> {
    if path == dst_root {
        return None;
    }
    let rest = path.strip_prefix(dst_root)?;
    Some(rest.strip_prefix(b"/").unwrap_or(rest))
}

#[cfg(test)]
mod directory_metadata_tests {
    use super::*;

    #[test]
    fn final_metadata_batches_cross_depths_until_search_access_is_removed() {
        let mut entries: Vec<_> = (0..12)
            .rev()
            .map(|depth| {
                (
                    vec![b'd'; depth + 1],
                    Meta {
                        mode: 0o755,
                        uid: 0,
                        gid: 0,
                        mtime: 0,
                        mtime_nsec: 0,
                        inode_metadata: None,
                    },
                    flags::MODE | flags::TIMES,
                    depth,
                    TargetCondition::Any,
                )
            })
            .collect();
        assert_eq!(directory_metadata_batch_len(&entries), 12);
        entries[7].1.mode = 0o600;
        assert_eq!(directory_metadata_batch_len(&entries), 7);
        assert_eq!(directory_metadata_batch_len(&entries[7..]), 5);
        // A time-only update does not change access, regardless of its mode field.
        entries[7].2 = flags::TIMES;
        assert_eq!(directory_metadata_batch_len(&entries), 12);
        entries[7].2 = flags::RECEIVER_MODE;
        assert_eq!(directory_metadata_batch_len(&entries), 7);
    }

    #[test]
    fn a_later_source_replaces_only_the_directory_metadata_it_sets() {
        let meta = |mode, uid, gid, mtime, inode| Meta {
            mode,
            uid,
            gid,
            mtime,
            mtime_nsec: 0,
            inode_metadata: inode,
        };
        let inode = |xattrs: Option<&[u8]>, atime: Option<i64>| {
            Some(Box::new(crate::inode_metadata::InodeMetadata {
                xattrs: xattrs.map(|name| crate::inode_metadata::ExtendedAttributes {
                    privileged: false,
                    values: vec![(name.to_vec(), b"v".to_vec())],
                }),
                atime: atime.map(|seconds| crate::inode_metadata::Timestamp {
                    seconds,
                    nanoseconds: 0,
                }),
                ..Default::default()
            }))
        };
        let entry = |meta, flags| (b"d".to_vec(), meta, flags, 1, TargetCondition::Any);
        // The earlier source sets times, group (required), xattrs and atime;
        // the later one sets mode, group (best effort) and xattrs.
        let mut earlier = entry(
            meta(0o700, 1, 2, 100, inode(Some(b"user.a"), Some(5))),
            flags::TIMES | flags::GROUP | flags::REQUIRE_GROUP,
        );
        let mut later = entry(
            meta(0o751, 3, 4, 200, inode(Some(b"user.b"), None)),
            flags::MODE | flags::GROUP,
        );
        merge_directory_metadata(&mut earlier, &mut later);
        let (_, merged, merged_flags, _, _) = earlier;
        assert_eq!(
            merged_flags,
            flags::TIMES | flags::MODE | flags::GROUP,
            "the later group change keeps its own best-effort requirement"
        );
        assert_eq!(
            (merged.mode, merged.gid, merged.mtime),
            (0o751, 4, 100),
            "mode and group from the later source, times from the earlier"
        );
        let inode = merged.inode_metadata.unwrap();
        assert_eq!(inode.xattrs.unwrap().values[0].0, b"user.b");
        assert_eq!(inode.atime.unwrap().seconds, 5);
    }
}

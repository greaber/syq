use super::*;

pub(super) fn path_has_partial_component(path: &[u8]) -> bool {
    path.split(|&byte| byte == b'/')
        .any(|part| is_partial_name(OsStr::from_bytes(part)))
}

pub(super) struct Planner<'a> {
    pub(super) dst: &'a mut dyn Conn,
    pub(super) sched: &'a Sched,
    pub(super) progress: &'a Progress,
    pub(super) opts: &'a Opts,
    /// Capability reported by the destination receiver's authenticated
    /// handshake. The coordinator may be running on a different platform.
    pub(super) destination_supports_confined_socket_nodes: bool,
    /// Destination paths claimed by source entries (see `Claim`).
    pub(super) dst_seen: std::collections::HashMap<PathBytes, Claim>,
    /// Directories this run will not create — --existing: they don't exist
    /// (or aren't directories); --ignore-existing: an existing non-directory
    /// sits at their path. Nothing under them is touched.
    pub(super) missing_dirs: std::collections::HashSet<PathBytes>,
    /// Directory copies blocked by a destination file or symlink. The conflict
    /// is reported at the parent; its descendants must not be copied.
    pub(super) blocked_directory_paths: std::collections::HashSet<PathBytes>,
    /// A remote destination root was missing at preflight, so mapped paths
    /// cannot supply comparison bases. Local fresh trees retain the root
    /// lookup separately below so its existing metadata is preserved.
    pub(super) destination_tree_known_missing: bool,
    /// The local destination was missing or empty at preflight. Its root may
    /// still have metadata to preserve; only descendants are known absent.
    pub(super) destination_children_known_missing: bool,
    /// Mapped payload paths that look like current sidecars, and every
    /// sidecar path the current job may use. Their intersection is unsafe.
    /// Ordinary payload names cannot collide and do not need to stay in RAM.
    pub(super) payload_paths: std::collections::HashMap<PathBytes, String>,
    pub(super) sidecar_paths: std::collections::HashMap<PathBytes, String>,
    /// Files whose destination cannot accommodate a safe sidecar name. They
    /// fail individually while the rest of the scan and transfer continue.
    pub(super) unusable_files: std::collections::HashSet<PathBytes>,
    /// Payload paths inside the sidecar-looking namespace, mapped and claimed
    /// like everything else but applied only after the collision preflight
    /// over every source has passed (see finish_planning).
    pub(super) deferred_payloads: Vec<Mapped>,
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
    /// Only implicit parents actually reopened for writing need a final chmod.
    /// Keep these separate until the manifest is complete: a later explicit
    /// directory entry supplies its own deferred metadata instead.
    pub(super) implicit_restorations: Vec<(PathBytes, Meta, u8, usize, TargetCondition)>,
    /// Directories this copy created may receive metadata from later sources.
    pub(super) created_dirs: std::collections::HashSet<PathBytes>,
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
    /// namespace and fresh-capacity preflight. Restricted transfers use the
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
}

/// What a source entry asserts about its destination path. Two dirs merge;
/// a dir against a leaf, or two leaves, conflict. A `Weak` claim comes from
/// an entry syq will not transfer (a symlink without -l, a special file
/// without -D, an unknown type): it still marks the path as the source's —
/// so --delete leaves it alone — but yields to any real claim, so two
/// sources overlapping on such an entry are not a conflict.
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

/// One scanned batch after the mapping loop: every destination claimed,
/// nothing touched yet. With several sources these are held until all of
/// them have been scanned, so a conflict between sources is reported before
/// the destination is changed at all.
pub(super) struct Mapped {
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

impl Planner<'_> {
    pub(super) fn record_fresh_entry(&mut self, dst: &[u8], entry: &Entry, new_object: bool) {
        if !new_object {
            return;
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
            return;
        }
        let reuses_existing_root = dst == self.dst_root && entry.kind == Kind::Dir;
        let Some(plan) = &mut self.fresh_capacity else {
            return;
        };
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
    }

    pub(super) fn assess_fresh_capacity(&mut self) -> Result<Option<FreshCapacityAssessment>> {
        let Some(plan) = self.fresh_capacity.clone() else {
            return Ok(None);
        };
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

    pub(super) fn assert_mutation_root(&mut self) -> Result<()> {
        let (dev, ino) = match self.mutation_root_condition {
            TargetCondition::Matches { dev, ino }
            | TargetCondition::MatchesFingerprint { dev, ino, .. } => (dev, ino),
            TargetCondition::Any | TargetCondition::Absent => return Ok(()),
        };
        let current = stat_many(self.dst, vec![self.dst_root.clone()], false)?
            .pop()
            .flatten();
        match current {
            Some(entry) if entry.dev == dev && entry.ino == ino => Ok(()),
            _ => bail!(
                "target {} changed after the placement precondition was checked",
                display(&self.dst_root)
            ),
        }
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
            for rel in subtrees {
                self.scan_subtree(src, src_root, &rel, dst_root, &mut emitted)?;
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
        let namespace_files = self.collect_namespace_files(&batch, src_root, sub, dst_root);
        if !namespace_files.is_empty() {
            self.sched.anticipate_file_work();
        }
        if self.collision {
            return Ok(());
        }
        // Payloads inside the sidecar-looking namespace are mapped and claimed
        // now, like everything else, but applied only once the preflight over
        // every source has passed.
        let mut immediate = Vec::with_capacity(batch.len());
        let mut deferred = Vec::new();
        for entry in batch {
            let dst_rel = join(sub, &entry.path);
            let reserved_leaf = dst_rel.is_empty()
                && entry.kind != Kind::Dir
                && dst_root
                    .rsplit(|&byte| byte == b'/')
                    .next()
                    .is_some_and(|name| is_partial_name(OsStr::from_bytes(name)));
            if reserved_leaf || path_has_partial_component(&dst_rel) {
                deferred.push(entry);
            } else {
                immediate.push(entry);
            }
        }
        let mut mapped = self.map_batch(immediate, src_root, sub, dst_root);
        self.register_namespace(namespace_files, &mut mapped)?;
        if self.collision {
            return Ok(());
        }
        match &mut self.buffer {
            Some(buf) => buf.push(mapped),
            None => self.apply_mapped(mapped)?,
        }
        if !deferred.is_empty() {
            let mapped = self.map_batch(deferred, src_root, sub, dst_root);
            self.deferred_payloads.push(mapped);
        }
        Ok(())
    }

    /// All sources scanned and the sidecar namespace preflight passed: add
    /// deferred payloads to the buffer. The caller runs the fresh-target
    /// capacity check before replaying that buffer. The directory and mapping
    /// sets released by retire_planning_state remain live through replay,
    /// because applying buffered entries still consults them.
    pub(super) fn finish_planning(&mut self) -> Result<()> {
        // Every source has passed the sidecar collision preflight. Applying
        // buffered entries does not consult these indexes; release them before
        // the scheduler grows so their allocations can be reused for jobs.
        self.payload_paths = std::collections::HashMap::new();
        self.sidecar_paths = std::collections::HashMap::new();
        let deferred = std::mem::take(&mut self.deferred_payloads);
        if let Some(buf) = &mut self.buffer {
            buf.extend(deferred);
        } else {
            for m in deferred {
                self.apply_mapped(m)?;
            }
            self.retire_planning_state();
        }
        Ok(())
    }

    pub(super) fn retire_planning_state(&mut self) {
        // Resolve late explicit directory promotions before discarding the
        // implicit-parent index. Only the remaining implicit parents restore
        // receiver modes; explicit entries already have their own metadata.
        self.deferred.extend(
            std::mem::take(&mut self.implicit_restorations)
                .into_iter()
                .filter(|(path, ..)| self.implicit_dirs.contains(path)),
        );
        // These sets exist only to validate and apply mapped scan entries.
        // Jobs already own the source spelling needed by workers. Deletion
        // alone still needs the destination claims.
        self.created_dirs = std::collections::HashSet::new();
        self.missing_dirs = std::collections::HashSet::new();
        self.mapping_explicit_parents = std::collections::HashSet::new();
        self.blocked_mapping_parents = std::collections::HashSet::new();
        self.blocked_directory_paths = std::collections::HashSet::new();
        self.unusable_files = std::collections::HashSet::new();
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
    ) -> Mapped {
        let opts = self.opts;
        let mut dirs: Vec<(PathBytes, PathBytes, Entry)> = Vec::new();
        let mut others: Vec<Planned> = Vec::new();
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
            self.record_fresh_entry(&dst, &e, new_capacity_object);
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
                Claim::Dir => dirs.push((dst, dst_rel, e)),
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
        Mapped {
            dst_root: dst_root.to_vec(),
            dirs,
            others,
            dir_stats: None,
            other_stats: None,
        }
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
    pub(super) fn replay_buffered(&mut self, before_apply: impl FnOnce()) -> Result<()> {
        let Some(mut buffered) = self.buffer.take() else {
            return Ok(());
        };
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
        if let Some((root, condition, is_destination_root)) = self.create_root.take() {
            if self.use_operator_anchor {
                let selection = create_operator_directory(self.dst, condition)?;
                let anchor = activate_control_destination(self.dst, selection, root.clone())?;
                if is_destination_root {
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
                let created = mkdir_root(
                    self.dst,
                    &root,
                    condition,
                    self.opts.restricted_receiver,
                    self.opts.perms,
                )?;
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
            #[cfg(debug_assertions)]
            if !self.sched.jobs.lock().unwrap().is_empty() {
                crate::fsops::test_race_barrier(
                    "SYQ_TEST_PLANNED_BATCH_READY_FILE",
                    "SYQ_TEST_PLANNED_BATCH_CONTINUE_FILE",
                    "buffered planning batch",
                )?;
            }
        }
        self.retire_planning_state();
        Ok(())
    }

    /// Everything after the mapping loop: stat, create directories, filter,
    /// enqueue.
    pub(super) fn apply_mapped(&mut self, mapped: Mapped) -> Result<()> {
        if self.collision {
            return Ok(());
        }
        self.assert_mutation_root()?;
        let opts = self.opts;
        let Mapped {
            dst_root,
            dirs,
            mut others,
            dir_stats,
            mut other_stats,
        } = mapped;
        let dst_root = &dst_root[..];

        // Directories: one stat pass decides everything about each one, and
        // the same filtered list drives creation, listing and deferred
        // metadata so they can't disagree.
        if !dirs.is_empty() {
            let stats = if self.destination_tree_known_missing {
                vec![None; dirs.len()]
            } else if self.destination_children_known_missing {
                self.stat_fresh_descendants(dirs.iter().map(|(path, _, _)| path))?
            } else if let Some(stats) = dir_stats {
                stats
            } else {
                self.stat_directories_with_dry_run_overlay(&dirs, dst_root)?
            };
            let planned = self.filter_dirs(dirs, stats, dst_root);
            if opts.dry_run {
                self.trace_dry_run_dirs(&planned, dst_root);
            } else {
                let Some(reopened_dirs) = self.create_directories(&planned, dst_root)? else {
                    return Ok(());
                };
                self.defer_directory_metadata(&planned, &reopened_dirs);
            }
        }

        if !self.blocked_mapping_parents.is_empty() || !self.blocked_directory_paths.is_empty() {
            others.retain(|p| !self.fail_blocked_mapping_entry(&p.dst, &p.dst_rel, p.e.kind));
        }
        if others.is_empty() {
            return Ok(());
        }
        let stats = if self.destination_tree_known_missing {
            vec![None; others.len()]
        } else if self.destination_children_known_missing {
            self.stat_fresh_descendants(others.iter().map(|planned| &planned.dst))?
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
        if self.unusable_files.contains(&dst_path) {
            // register_namespace reported it; nothing can stage here.
            return;
        }
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
        let same = dst_entry
            .as_ref()
            .is_some_and(|d| opts.metadata_matches(&dst_rel, &e, d));
        let dst_newer = opts.update
            && dst_entry.as_ref().is_some_and(|d| {
                d.kind == Kind::File && (d.mtime, d.mtime_nsec) > (e.mtime, e.mtime_nsec)
            });
        if dst_newer {
            self.progress.files_excluded.fetch_add(1, Relaxed);
            return;
        }
        if same && !opts.checksum && (opts.dry_run || opts.expected_for(&dst_rel).is_none()) {
            // Content is up to date, but still reconcile metadata
            // (mode/owner/group) the way rsync does — a skipped file
            // shouldn't keep stale permissions.
            if let Some(d) = &dst_entry {
                let ff = opts.metadata_fix_flags(&dst_rel, &e, d);
                if ff != 0 {
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
            && opts.checksum
            && dst_entry
                .as_ref()
                .is_some_and(|d| d.kind == Kind::File && d.size == e.size)
        {
            // Equal-size files need a real comparison. Hash them through the
            // workers so large trees do not serialize all reads in the planner.
            self.enqueue((src_path, source), dst_path, rel, dst_rel, e, dst_entry);
        } else if opts.dry_run {
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
        let Some(requested) = self.opts.mapping_metadata.get(rel) else {
            return;
        };
        let meta = self.opts.metadata_for(rel, source);
        let flags = requested.apply_flags();
        // Explicit nanoseconds must be attempted even if preservation's quick
        // comparison would tolerate truncation by the destination filesystem.
        let time_differs = requested.mtime.is_some()
            && (meta.mtime, meta.mtime_nsec) != (destination.mtime, destination.mtime_nsec);
        if !time_differs && !metadata_differs(&meta, &destination.meta(), flags) {
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
        let target = e.link.clone().unwrap_or_default();
        let same = dst_entry
            .as_ref()
            .is_some_and(|d| d.kind == Kind::Symlink && d.link.as_deref() == Some(&target[..]));

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
            condition: self.exact_condition_for(&dst_path),
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
        let same = dst_entry
            .as_ref()
            .is_some_and(|d| d.kind == e.kind && d.rdev == e.rdev);
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
        leaf_ops.ops.push(Op::Mknod {
            path: dst_path.clone(),
            mode: e.mode,
            rdev: e.rdev,
            condition: self.exact_condition_for(&dst_path),
        });
        let mut meta = opts.metadata_for(&dst_rel, &e);
        let mut flags = opts.flags_for(&dst_rel);
        if flags & flags::MODE == 0 {
            meta.mode = e.mode & 0o777 & !opts.umask;
            flags |= flags::RECEIVER_MODE;
        }
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
    ) -> Vec<PlannedDir> {
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
            planned.push((p, dst_rel, e, st));
        }
        planned
    }

    /// Create this batch's missing directories and reopen existing ones that
    /// are not yet writable. Returns the implicit directories reopened that
    /// way, or `None` when a new destination root could not be created and
    /// nothing below it may proceed.
    fn create_directories(
        &mut self,
        planned: &[PlannedDir],
        dst_root: &[u8],
    ) -> Result<Option<std::collections::HashSet<PathBytes>>> {
        let opts = self.opts;
        // Create new dirs; also "create" existing ones we can't yet
        // write into (0o700 not set) so apply() opens them up. The
        // latter are not creations: no record, no count.
        let existing_dirs: std::collections::HashSet<&PathBytes> = planned
            .iter()
            .filter(|(_, _, _, st)| matches!(st, Some(d) if d.kind == Kind::Dir))
            .map(|(p, _, _, _)| p)
            .collect();
        let mut new_dirs: Vec<Op> = planned
            .iter()
            .filter(|(path, _, _, st)| {
                let root_must_be_new =
                    self.exact_condition == TargetCondition::Absent && path == &self.dst_root;
                if opts.preserve_existing_directory_metadata && existing_dirs.contains(path) {
                    return false;
                }
                root_must_be_new
                    || !matches!(st, Some(d) if d.kind == Kind::Dir && d.mode & 0o700 == 0o700)
            })
            .map(|(p, _, e, st)| Op::Mkdir {
                path: p.clone(),
                mode: e.mode,
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
            let error = self.apply(vec![root_op])?.into_iter().next().flatten();
            if let Some(error) = error {
                let os_kind = wire_os_kind(&error);
                self.progress
                    .error_classified(&format!("syq: {error}"), Some("io"), os_kind);
                if capacity_os_kind(os_kind) {
                    return Err(endpoint_error(error)).context("apply destination changes");
                }
                self.collision = true;
                return Ok(None);
            }
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
        let mut reopened_dirs = std::collections::HashSet::new();
        for new_dirs in directory_creation_batches(new_dirs, opts.restricted_receiver) {
            let n = new_dirs.len();
            let op_info: Vec<(PathBytes, TargetCondition)> = new_dirs
                .iter()
                .map(|op| match op {
                    Op::Mkdir {
                        path, condition, ..
                    } => (path.clone(), *condition),
                    _ => unreachable!(),
                })
                .collect();
            let errs = self.apply(new_dirs)?;
            let capacity_error = first_capacity_error(&errs);
            let mut failed = 0;
            let mut reopened = 0;
            for ((name, condition), err) in op_info.iter().zip(errs) {
                let preexisting = existing_dirs.contains(name);
                let succeeded = err.is_none();
                let created = succeeded && !preexisting;
                if created && opts.preserve_existing_directory_metadata {
                    self.created_dirs.insert(name.clone());
                }
                let os_kind = err.as_ref().and_then(wire_os_kind);
                if let Some(err) = &err {
                    failed += 1;
                    self.progress
                        .error_classified(&format!("syq: {err}"), Some("io"), os_kind);
                    if name == &self.dst_root && *condition != TargetCondition::Any {
                        self.collision = true;
                    }
                } else if opts.verbose > 0 && !preexisting {
                    self.progress.println(&format!("{}/", display(name)));
                }
                if preexisting && succeeded {
                    // Reopened for writability only; nothing was made.
                    reopened += 1;
                    if self.implicit_dirs.contains(name) {
                        reopened_dirs.insert(name.clone());
                    }
                    continue;
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
                .fetch_add((n - failed - reopened) as u64, Relaxed);
            if let Some(error) = capacity_error {
                return Err(endpoint_error(error)).context("apply destination changes");
            }
        }
        Ok(Some(reopened_dirs))
    }

    /// Record what a live run would do to this batch's directories.
    fn trace_dry_run_dirs(&mut self, planned: &[PlannedDir], dst_root: &[u8]) {
        let opts = self.opts;
        for (p, dst_rel, e, destination) in planned {
            let meta_flags = opts.flags_for(dst_rel);
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
    fn defer_directory_metadata(
        &mut self,
        planned: &[PlannedDir],
        reopened_dirs: &std::collections::HashSet<PathBytes>,
    ) {
        let opts = self.opts;
        for (p, dst_rel, e, s) in planned {
            // New implicit parents already have their final modes.
            // Restore only those temporarily reopened for writing.
            if self.implicit_dirs.contains(p) {
                if reopened_dirs.contains(p) {
                    let existing = s.as_ref().expect("reopened directory was observed");
                    self.implicit_restorations.push((
                        p.clone(),
                        existing.meta(),
                        if opts.restricted_receiver {
                            flags::RECEIVER_MODE
                        } else {
                            flags::MODE
                        },
                        p.iter().filter(|&&c| c == b'/').count(),
                        self.metadata_condition_for(p),
                    ));
                }
                continue;
            }
            if opts.preserve_existing_directory_metadata && !self.created_dirs.contains(p) {
                continue;
            }
            let depth = p.iter().filter(|&&c| c == b'/').count();
            let mut meta = opts.metadata_for(dst_rel, e);
            let mut flags = opts.flags_for(dst_rel);
            // Without -p, existing directories retain their mode and
            // new directories receive the source mode through the
            // receiving side's umask. Only a signed receiver needs to
            // replace the proposal: an ordinary receiver's Mkdir has
            // already applied its local umask and any kernel-inherited
            // setgid bit, which a follow-up chmod must not clear.
            if flags & flags::MODE == 0 {
                if opts.restricted_receiver {
                    meta.mode = s
                        .as_ref()
                        .filter(|d| d.kind == Kind::Dir)
                        .map_or(e.mode & 0o777 & !opts.umask, |d| d.mode & 0o7777);
                    flags |= flags::RECEIVER_MODE;
                } else if let Some(existing) = s.as_ref().filter(|d| d.kind == Kind::Dir) {
                    meta.mode = existing.mode & 0o7777;
                    flags |= flags::MODE;
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
        self.progress
            .error_classified(&format!("syq: {error}"), Some("io"), os_kind);
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
                self.progress
                    .error_classified(&format!("syq: {e}"), Some("io"), os_kind);
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

    pub(super) fn collect_namespace_files(
        &mut self,
        batch: &[Entry],
        src_root: &[u8],
        sub: &[u8],
        dst_root: &[u8],
    ) -> Vec<(PathBytes, String)> {
        let mut files = Vec::new();
        for entry in batch {
            if !self.entry_is_payload(entry) {
                continue;
            }
            let source_name = if entry.path.is_empty() {
                src_root
                    .rsplit(|&byte| byte == b'/')
                    .next()
                    .unwrap_or(src_root)
            } else {
                entry
                    .path
                    .rsplit(|&byte| byte == b'/')
                    .next()
                    .unwrap_or(&entry.path)
            };
            if is_partial_name(OsStr::from_bytes(source_name)) {
                self.source_partials += 1;
            }
            let dst_rel = join(sub, &entry.path);
            let dst_path = join(dst_root, &dst_rel);
            let rel = self.rel_name(src_root, sub, &entry.path);
            let reserved_payload = dst_path
                .rsplit(|&byte| byte == b'/')
                .next()
                .is_some_and(|name| is_partial_name(OsStr::from_bytes(name)));
            if reserved_payload {
                let reservation = crate::fsops::partial_reservation_key(&dst_path);
                if let Some(owner) = self.sidecar_paths.get(&reservation) {
                    self.progress.error(&format!(
                        "syq: source payload {rel} maps to {}, which is the reserved sidecar for {owner}",
                        display(&dst_path)
                    ));
                    self.collision = true;
                }
                self.payload_paths.entry(reservation).or_insert(rel.clone());
            }
            if entry.kind == Kind::File && !self.opts.inplace {
                files.push((dst_path, rel));
            }
        }
        files
    }

    pub(super) fn register_namespace(
        &mut self,
        files: Vec<(PathBytes, String)>,
        mapped: &mut Mapped,
    ) -> Result<()> {
        if files.is_empty() {
            return Ok(());
        }
        // Several sources are replayed only after every collision check, and
        // dry runs may need a depth-by-depth virtual overlay. Keep their stats
        // at the existing application point rather than caching stale or
        // unsafe observations. Sidecar resolution still uses this request.
        let pre_stat = self.opts.dst_remote
            && self.buffer.is_none()
            && !self.opts.dry_run
            && !self.destination_tree_known_missing
            && !self.destination_children_known_missing
            && self.container_guard.is_none();
        let directories: Vec<PathBytes> = if pre_stat {
            mapped
                .dirs
                .iter()
                .map(|(path, _, _)| path.clone())
                .collect()
        } else {
            Vec::new()
        };
        let other_paths: Vec<PathBytes> = if pre_stat {
            mapped
                .others
                .iter()
                .map(|planned| planned.dst.clone())
                .collect()
        } else {
            Vec::new()
        };
        // Sidecar resolution already costs a receiver turn for ordinary file
        // copies. Include the destination inspection in that same turn; the
        // receiver omits leaf stats when directory repair must happen first.
        let partial_paths = files.iter().map(|(path, _)| path.clone()).collect();
        let (sidecars, dir_stats, other_stats) = if pre_stat {
            let response = self.dst.call(Request::PlanBatch {
                partial_paths,
                copy_id: self.opts.copy_id,
                directories: directories.clone(),
                others: other_paths.clone(),
                guard: self.container_guard.clone(),
            })?;
            match ok(response, "plan destination batch")? {
                Response::BatchPlan {
                    partial_paths,
                    directories: dir_stats,
                    others: other_stats,
                } if partial_paths.len() == files.len()
                    && dir_stats.len() == directories.len()
                    && other_stats
                        .as_ref()
                        .is_none_or(|stats| stats.len() == other_paths.len()) =>
                {
                    (partial_paths, dir_stats, other_stats)
                }
                other => bail!("unexpected response {other:?}"),
            }
        } else {
            (self.partial_paths(partial_paths)?, Vec::new(), None)
        };
        if pre_stat {
            self.progress.observe_destination_devices(
                dir_stats
                    .iter()
                    .flatten()
                    .chain(other_stats.iter().flatten().flatten()),
            );
            mapped.dir_stats = Some(dir_stats);
            if let Some(stats) = other_stats {
                mapped.other_stats = Some(other_paths.into_iter().zip(stats).collect());
            }
        }
        for ((dst_path, file_rel), sidecar) in files.into_iter().zip(sidecars) {
            let sidecar = match sidecar {
                Ok(sidecar) => sidecar,
                Err(error) => {
                    self.progress.error(&format!(
                        "syq: {file_rel}: cannot create a safe sidecar beside {}: {error}",
                        display(&dst_path)
                    ));
                    self.unusable_files.insert(dst_path);
                    continue;
                }
            };
            let reservation = crate::fsops::partial_reservation_key(&sidecar);
            if let Some(payload_rel) = self.payload_paths.get(&reservation) {
                self.progress.error(&format!(
                    "syq: source payload {payload_rel} maps to {}, which is the reserved sidecar for {file_rel}",
                    display(&sidecar)
                ));
                self.collision = true;
            }
            if let Some(other) = self.sidecar_paths.insert(reservation, file_rel.clone()) {
                if other != file_rel {
                    self.progress.error(&format!(
                        "syq: {other} and {file_rel} require the same sidecar {}",
                        display(&sidecar)
                    ));
                    self.collision = true;
                }
            }
        }
        Ok(())
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
    ) {
        let (src, source) = source_path;
        let target_condition = self.exact_condition_for(&dst);
        let src_rel = self.mapping_source_rel(&rel_bytes);
        self.progress.files_total.fetch_add(1, Relaxed);
        self.progress.bytes_total.fetch_add(entry.size, Relaxed);
        self.sched.push_file(FileJob {
            dst_entry,
            data: FileJobData {
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
            },
        });
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
            // Destination directories that hold an ignored path, so must stay.
            let mut protected: std::collections::HashSet<PathBytes> =
                std::collections::HashSet::new();
            let mut partial_parents = std::collections::HashMap::new();
            let mut alias_parents = std::collections::HashSet::new();
            let mut walk = PruneWalk::new(&self.dst_seen, &root, sorted_claims.as_deref());
            let res = self.dst.scan(
                &root,
                None,
                false,
                &ignore,
                true,
                &mut |batch: Vec<Entry>| {
                    for entry in batch {
                        walk.push(entry, &root, &nested);
                    }
                    Ok(())
                },
                &mut |paths: Vec<PathBytes>| {
                    for p in paths {
                        // Every ancestor of an ignored path is protected.
                        protected.extend(ancestor_prefixes(&p).map(|prefix| join(&root, prefix)));
                    }
                    Ok(())
                },
                &mut |w| {
                    self.delete_walk_failed = true;
                    self.progress.error(&format!("syq: delete: {w}"))
                },
            );
            res?;
            if self.delete_walk_failed {
                return Ok(());
            }
            walk.finish_scan(&root);
            // There is nothing for an alias to protect when no candidates
            // remain, including dry runs whose claimed files do not exist yet.
            if walk.entries.is_empty() {
                continue;
            }
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
                        self.deletes
                            .dirs
                            .entry(d)
                            .or_default()
                            .push((path, rel, kind));
                    }
                }
            }
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

    pub(super) fn run_deletes(&mut self) -> Result<u64> {
        let opts = self.opts;
        let leaves = std::mem::take(&mut self.deletes.leaves);
        let dirs = std::mem::take(&mut self.deletes.dirs);
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
        let mut n = 0u64;
        let mut run = |me: &mut Self,
                       items: &[(PathBytes, String, &'static str)],
                       rmdir: bool|
         -> Result<()> {
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
        run(self, &leaves, false)?;
        for (_, items) in dirs.iter().rev() {
            run(self, items, true)?;
        }
        Ok(n)
    }

    fn stat_fresh_descendants<'p>(
        &mut self,
        paths: impl Iterator<Item = &'p PathBytes> + Clone,
    ) -> Result<Vec<Option<Entry>>> {
        let root = if paths.clone().any(|path| path == &self.dst_root) {
            self.stat_many(vec![self.dst_root.clone()])?.pop().flatten()
        } else {
            None
        };
        Ok(paths
            .map(|path| {
                if path == &self.dst_root {
                    root.clone()
                } else {
                    None
                }
            })
            .collect())
    }

    pub(super) fn stat_many(&mut self, paths: Vec<PathBytes>) -> Result<Vec<Option<Entry>>> {
        let entries = stat_many(self.dst, paths, false)?;
        self.progress
            .observe_destination_devices(entries.iter().flatten());
        Ok(entries)
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

    pub(super) fn partial_paths(
        &mut self,
        paths: Vec<PathBytes>,
    ) -> Result<Vec<std::result::Result<PathBytes, String>>> {
        match ok(
            self.dst.call(Request::PartialPaths {
                paths,
                copy_id: self.opts.copy_id,
                guard: None,
            })?,
            "compute sidecar paths",
        )? {
            Response::PathResults(paths) => Ok(paths),
            other => bail!("unexpected response {other:?}"),
        }
    }

    pub(super) fn apply(&mut self, ops: Vec<Op>) -> Result<Vec<Option<WireError>>> {
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

    pub(super) fn apply_deferred(&mut self) -> Result<()> {
        self.assert_mutation_root()?;
        let mut d = std::mem::take(&mut self.deferred);
        d.sort_by(|a, b| b.3.cmp(&a.3));
        for chunk in d.chunks(1000) {
            let ops: Vec<Op> = chunk
                .iter()
                .map(|(p, m, f, _, condition)| Op::SetMeta {
                    path: p.clone(),
                    meta: *m,
                    flags: *f,
                    condition: *condition,
                })
                .collect();
            let errors = self.apply(ops)?;
            let capacity_error = first_capacity_error(&errors);
            for ((path, ..), error) in chunk.iter().zip(errors) {
                if let Some(error) = error {
                    let dst = (!self.implicit_dirs.contains(path))
                        .then(|| strip_dst_root(path, &self.dst_root))
                        .flatten();
                    self.report_metadata_failure(dst, DeclaredKind::Dir, &error);
                }
            }
            if let Some(error) = capacity_error {
                return Err(endpoint_error(error)).context("apply destination changes");
            }
        }
        Ok(())
    }
}

/// A destination ancestor directory no manifest entry names: created with
/// default metadata (mode through the umask, natural mtime; see
/// `Planner::implicit_dirs`).
pub(super) fn implicit_dir_entry(path: PathBytes) -> Entry {
    Entry {
        path,
        kind: Kind::Dir,
        size: 0,
        mtime: 0,
        mtime_nsec: 0,
        mode: 0o755,
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

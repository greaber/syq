use super::*;

/// Only multiply linked source inodes consume group state. All selections in
/// one copy use the same source endpoint; device/inode are scoped to that host.
#[derive(Default)]
pub(super) struct Hardlinks {
    by_inode: std::collections::HashMap<(u64, u64), usize>,
    groups: Vec<Group>,
}

impl Hardlinks {
    /// The destination paths, below the root, of the representatives the
    /// planner kept.
    pub(super) fn kept_destinations(&self) -> std::collections::HashSet<&PathBytes> {
        self.groups
            .iter()
            .filter_map(|group| group.kept.as_ref().map(|kept| &kept.leaf.dst_rel))
            .collect()
    }

    /// The representative of `group` the planner kept.
    fn kept_leaf(&self, group: usize) -> &Planned {
        &self.groups[group].kept.as_ref().expect("a kept group").leaf
    }
}

struct Group {
    representative: usize,
    preview: Option<Box<(Planned, Option<Entry>)>>,
    /// A representative kept without a worker (`Planner::keeps_representative`).
    kept: Option<Box<Kept>>,
    followers: Vec<Follower>,
}

/// An existing representative whose size and time match its source, and
/// whose metadata needs no change: once planning ends, it is checked with
/// the others (`Planner::check_kept_representatives`), as a worker would
/// check it by itself. One the receiver will not keep is copied by a worker
/// instead.
struct Kept {
    leaf: Planned,
    /// What its check holds the existing file to.
    condition: TargetCondition,
    /// The existing file, as the lookup found it.
    destination: Entry,
    /// Its identity once the receiver has accepted it: what the group's
    /// other names are linked to.
    identity: Option<(u64, u64)>,
}

/// The name a group's other names are linked to: a worker's job, shared
/// with the scheduler, or a representative the planner kept.
enum Linked {
    Job(WorkerJob),
    Kept(Box<Kept>),
}

impl Linked {
    fn src(&self) -> &PathBytes {
        match self {
            Self::Job(job) => &job.src,
            Self::Kept(kept) => &kept.leaf.src,
        }
    }

    fn source(&self) -> &RegisteredPath {
        match self {
            Self::Job(job) => &job.source,
            Self::Kept(kept) => &kept.leaf.source,
        }
    }

    fn dst(&self) -> &PathBytes {
        match self {
            Self::Job(job) => &job.dst,
            Self::Kept(kept) => &kept.leaf.dst,
        }
    }

    /// Its path below the destination root.
    fn rel(&self) -> &PathBytes {
        match self {
            Self::Job(job) => &job.rel_bytes,
            Self::Kept(kept) => &kept.leaf.dst_rel,
        }
    }

    /// The source file as the scan found it.
    fn entry(&self) -> &Entry {
        match self {
            Self::Job(job) => &job.entry,
            Self::Kept(kept) => &kept.leaf.e,
        }
    }
}

struct Follower {
    src: PathBytes,
    source: RegisteredPath,
    dst: PathBytes,
    rel: PathBytes,
    destination: Option<(u64, u64)>,
    /// What the name must hold when the link is made, as for a file
    /// published there: nothing, for a new name the existing-file policy
    /// protects.
    condition: TargetCondition,
    compare_before_link: bool,
}

struct ReadyGroup {
    representative: Linked,
    published: Option<(u64, u64)>,
    followers: Vec<Follower>,
}

/// Hardlink copies already buffer the source scan before destination changes.
/// Check this structural ACL limitation across batches and source roots, while
/// allowing a single selected name even when it has links outside the copy.
pub(super) fn validate_macos_acls<'a>(entries: impl Iterator<Item = &'a Planned>) -> Result<()> {
    let mut protected = std::collections::HashMap::new();
    for entry in entries {
        if entry.e.kind != Kind::File
            || entry.e.nlink < 2
            || !entry
                .e
                .inode_metadata
                .as_ref()
                .and_then(|m| m.macos_acl.as_ref())
                .is_some_and(|acl| acl.has_deletion_denial())
        {
            continue;
        }
        if let Some(previous) = protected.insert((entry.e.dev, entry.e.ino), &entry.dst_rel) {
            bail!(
                "cannot preserve hardlinks with a macOS ACL that denies deletion: {} and {}; copy these names separately without hardlink preservation",
                display(previous), display(&entry.dst_rel)
            );
        }
    }
    Ok(())
}

impl Planner<'_> {
    pub(super) fn plan_hardlinked_file(
        &mut self,
        leaf: Planned,
        destination: Option<Entry>,
        target_condition: TargetCondition,
    ) {
        let identity = (leaf.e.dev, leaf.e.ino);
        let condition = self.leaf_condition_for(&leaf.dst, destination.as_ref());
        if let Some(&index) = self.hardlinks.by_inode.get(&identity) {
            let group = &mut self.hardlinks.groups[index];
            let jobs = self.sched.jobs.lock().unwrap();
            let (entry, rel) = if let Some(preview) = &group.preview {
                let (leaf, _) = &**preview;
                (&leaf.e, &leaf.dst_rel)
            } else if let Some(kept) = &group.kept {
                (&kept.leaf.e, &kept.leaf.dst_rel)
            } else {
                let representative = &jobs[group.representative];
                (&representative.entry, &representative.rel_bytes)
            };
            let flags = self.opts.flags_for(rel);
            let metadata = self.opts.metadata_for(rel, entry);
            if flags != self.opts.flags_for(&leaf.dst_rel)
                || metadata_differs(
                    &metadata,
                    &self.opts.metadata_for(&leaf.dst_rel, &leaf.e),
                    flags,
                    false,
                )
            {
                self.progress.error(&format!(
                    "syq: hardlinked source paths {} and {} request conflicting destination metadata",
                    display(rel), display(&leaf.dst_rel)
                ));
                self.collision = true;
                return;
            }
            let compare_before_link = self.opts.protects_existing_contents()
                && destination.as_ref().is_some_and(|d| {
                    !self.opts.trusts_size_and_time()
                        || !self.opts.metadata_matches(&leaf.dst_rel, &leaf.e, d)
                });
            group.followers.push(Follower {
                condition,
                compare_before_link,
                src: leaf.src,
                source: leaf.source,
                dst: leaf.dst,
                rel: leaf.dst_rel,
                destination: destination.map(|e| (e.dev, e.ino)),
            });
        } else if !self.opts.mapping_expected_hashes.is_empty() {
            // A later alias can add an assertion to this inode. Delay just
            // these representatives until all eligible aliases are known.
            self.hardlinks
                .by_inode
                .insert(identity, self.hardlinks.groups.len());
            self.hardlinks.groups.push(Group {
                representative: 0,
                preview: Some(Box::new((leaf, destination))),
                kept: None,
                followers: Vec::new(),
            });
        } else if self.opts.dry_run
            && (!self.opts.previews_by_comparing()
                || destination
                    .as_ref()
                    .is_none_or(|d| d.kind != Kind::File || d.size != leaf.e.size))
        {
            // A copy that would not compare the file rewrites it unless its
            // size and time are trusted, or replaces it when its metadata
            // cannot be changed in place (`must_replace`); either way, the
            // group's other names are linked to the new file.
            let mut matched = self.opts.trusts_size_and_time()
                && destination
                    .as_ref()
                    .is_some_and(|d| self.opts.metadata_matches(&leaf.dst_rel, &leaf.e, d));
            let replaced = matched
                && destination
                    .clone()
                    .is_some_and(|d| self.must_replace((&leaf.dst, &leaf.dst_rel), &leaf.e, &d));
            matched &= !replaced;
            if matched {
                self.progress.files_unchanged.fetch_add(1, Relaxed);
                self.progress
                    .bytes_unchanged
                    .fetch_add(leaf.e.size, Relaxed);
                self.progress.add_unchanged_file_bytes(leaf.e.size);
                if self.opts.metadata_fix_flags(
                    &leaf.dst_rel,
                    &leaf.e,
                    destination.as_ref().unwrap(),
                ) != 0
                    || self.opts.inode_metadata_differs(
                        &leaf.dst_rel,
                        &leaf.e,
                        destination.as_ref().unwrap(),
                    )
                {
                    self.dry_run_changes.metadata_files += 1;
                    self.emit_trace(
                        "transfer_file",
                        &leaf.dst_rel,
                        "file",
                        None,
                        "metadata_differs",
                    );
                }
            } else {
                self.preview_changed_file(
                    (&leaf.dst, &leaf.dst_rel),
                    &leaf.e,
                    destination.as_ref(),
                    replaced,
                );
            }
            self.hardlinks
                .by_inode
                .insert(identity, self.hardlinks.groups.len());
            self.hardlinks.groups.push(Group {
                representative: 0,
                preview: Some(Box::new((leaf, destination.filter(|_| matched)))),
                kept: None,
                followers: Vec::new(),
            });
        } else if destination
            .as_ref()
            .is_some_and(|d| self.keeps_representative(&leaf, d))
        {
            let destination = destination.expect("checked above");
            self.progress.files_unchanged.fetch_add(1, Relaxed);
            self.progress
                .bytes_unchanged
                .fetch_add(leaf.e.size, Relaxed);
            self.progress.add_unchanged_file_bytes(leaf.e.size);
            let group = self.hardlinks.groups.len();
            self.hardlinks.by_inode.insert(identity, group);
            self.hardlinks.groups.push(Group {
                representative: 0,
                preview: None,
                kept: Some(Box::new(Kept {
                    leaf,
                    condition: match target_condition {
                        TargetCondition::Any => target_identity(&destination),
                        condition => condition,
                    },
                    destination,
                    identity: None,
                })),
                followers: Vec::new(),
            });
        } else {
            // The workers compare a representative that may be unchanged.
            if self
                .opts
                .changes_directory_certainly(&leaf.e, destination.as_ref())
                && !(self.opts.trusts_size_and_time()
                    && destination
                        .as_ref()
                        .is_some_and(|d| self.opts.metadata_matches(&leaf.dst_rel, &leaf.e, d)))
            {
                self.note_directory_change(&leaf.dst, true);
            }
            let representative = self.enqueue(
                (leaf.src, leaf.source),
                leaf.dst,
                leaf.rel,
                leaf.dst_rel,
                leaf.e,
                destination,
            );
            self.hardlinks
                .by_inode
                .insert(identity, self.hardlinks.groups.len());
            self.hardlinks.groups.push(Group {
                representative,
                preview: None,
                kept: None,
                followers: Vec::new(),
            });
        }
    }

    /// Whether the planner keeps the existing representative `destination`
    /// of `leaf` without a worker: a worker would keep it on its size and
    /// time alone (`Worker::try_expected_match`), and the scan does not
    /// predict that the receiver will refuse it (`must_replace`), and its
    /// check would change nothing. A later alias may find the group's
    /// metadata in conflict (a mapping's, or the source's changing between
    /// the scans of its names), which refuses the copy before any name of
    /// the group is changed: a representative whose metadata needs changing
    /// is left to a worker, which runs only once the group is validated.
    fn keeps_representative(&mut self, leaf: &Planned, destination: &Entry) -> bool {
        // A preview changes nothing.
        !self.opts.dry_run
            && destination.kind == Kind::File
            && self.opts.keeps_matching_file(&leaf.dst_rel)
            && !self.opts.protects_existing_contents()
            && self
                .opts
                .metadata_matches(&leaf.dst_rel, &leaf.e, destination)
            && self
                .opts
                .metadata_fix_flags(&leaf.dst_rel, &leaf.e, destination)
                == 0
            && !self
                .opts
                .inode_metadata_differs(&leaf.dst_rel, &leaf.e, destination)
            && !self.must_replace((&leaf.dst, &leaf.dst_rel), &leaf.e, destination)
    }

    /// The receiver accepted the representative of `group` kept by the
    /// planner.
    pub(super) fn representative_kept(&mut self, group: usize) {
        if let Some(kept) = &mut self.hardlinks.groups[group].kept {
            kept.identity = Some((kept.destination.dev, kept.destination.ino));
        }
        #[cfg(debug_assertions)]
        let _ = crate::fsops::record_test_event("SYQ_TEST_HARDLINK_EVENTS", format_args!("kept"));
    }

    /// Give the representative of `group`, which the planner did not keep
    /// after all, to a worker: to be replaced, when the receiver refused to
    /// change it in place for `refused`, or else to be checked and copied
    /// as it would have been without the planner.
    pub(super) fn representative_to_worker(
        &mut self,
        group: usize,
        refused: Option<crate::proto::ReplaceReason>,
    ) {
        self.requeue_representative(group, refused, None);
    }

    /// `representative_to_worker`, or, with `changed`, what its source is
    /// now, to be copied from it as a worker copies a file whose source
    /// changed: as its second attempt, and whole when its size and time do
    /// not show the change, since they were already found to match.
    fn requeue_representative(
        &mut self,
        group: usize,
        refused: Option<crate::proto::ReplaceReason>,
        changed: Option<Entry>,
    ) {
        let Some(kept) = self.hardlinks.groups[group].kept.take() else {
            return;
        };
        let Kept {
            leaf, destination, ..
        } = *kept;
        // It was counted unchanged when it was planned.
        self.progress.files_unchanged.fetch_sub(1, Relaxed);
        self.progress
            .bytes_unchanged
            .fetch_sub(leaf.e.size, Relaxed);
        self.progress
            .bytes_in_unchanged_files
            .fetch_sub(leaf.e.size, Relaxed);
        let retry = changed.is_some();
        let (entry, copy_whole) = match changed {
            Some(now) => {
                if !self.opts.quiet {
                    self.progress.eprintln(&format!(
                        "syq: {}: changed during transfer, retrying",
                        leaf.rel
                    ));
                }
                let copy_whole = self
                    .opts
                    .metadata_matches(&leaf.dst_rel, &now, &destination);
                (
                    Entry {
                        path: leaf.e.path,
                        ..now
                    },
                    copy_whole,
                )
            }
            None => (leaf.e, false),
        };
        // The destination as the scan found it: the job is held to it, as
        // the existing-file policies require (`leaf_condition_for`).
        let job = self.enqueue_with(
            (leaf.src, leaf.source),
            leaf.dst,
            leaf.rel,
            leaf.dst_rel,
            entry,
            Some(destination),
            (refused, copy_whole, retry),
        );
        self.hardlinks.groups[group].representative = job;
        #[cfg(debug_assertions)]
        let _ = crate::fsops::record_test_event(
            "SYQ_TEST_HARDLINK_EVENTS",
            format_args!(
                "{}",
                match (refused, retry, copy_whole) {
                    (Some(_), ..) => "replaced",
                    (None, true, true) => "copied",
                    (None, true, false) => "retried",
                    (None, false, _) => "worker",
                }
            ),
        );
    }

    /// Whether `error`, from the receiver's check of the representative of
    /// `group` the planner kept, only shows a destination its existing-file
    /// policy keeps, as for a worker (`Worker::kept_by_policy`).
    fn representative_skipped_by_policy(&self, group: usize, error: &WireError) -> bool {
        let Some(kept) = &self.hardlinks.groups[group].kept else {
            return false;
        };
        let condition = self.leaf_condition_for(&kept.leaf.dst, Some(&kept.destination));
        crate::fsops::is_condition_not_met_wire(error)
            && self.policy_condition(&kept.leaf.dst, condition)
    }

    /// The representative of `group`, which the planner kept, failed or
    /// was skipped, and is reported: no name is linked to it.
    fn representative_failed(&mut self, group: usize) {
        let Some(kept) = &mut self.hardlinks.groups[group].kept else {
            return;
        };
        kept.identity = None;
        let size = kept.leaf.e.size;
        self.progress.files_unchanged.fetch_sub(1, Relaxed);
        self.progress.bytes_unchanged.fetch_sub(size, Relaxed);
        self.progress
            .bytes_in_unchanged_files
            .fetch_sub(size, Relaxed);
        #[cfg(debug_assertions)]
        let _ = crate::fsops::record_test_event("SYQ_TEST_HARDLINK_EVENTS", format_args!("failed"));
    }

    /// The receiver's check of the representative of `group` failed with
    /// `error`: settled as a worker settles it, skipped when its
    /// existing-file policy keeps the destination, and otherwise reported.
    fn representative_check_failed(&mut self, group: usize, error: &WireError) {
        let Some(kept) = &self.hardlinks.groups[group].kept else {
            return;
        };
        let rel = kept.leaf.dst_rel.clone();
        let skipped = self.representative_skipped_by_policy(group, error);
        self.representative_failed(group);
        if skipped {
            self.progress.files_excluded.fetch_add(1, Relaxed);
            if !self.opts.quiet {
                self.progress.eprintln(&format!(
                    "syq: {}: {}",
                    display(&rel),
                    self.opts.kept_note()
                ));
            }
        } else {
            self.report_metadata_failure(Some(&rel), DeclaredKind::File, error);
        }
    }

    /// The source of the representative of `group`, which the planner kept,
    /// changed, vanished or could not be read (`message`), and it is not
    /// copied again: it fails, as a file a worker cannot retry does, and no
    /// name is linked to it.
    fn representative_source_failed(
        &mut self,
        group: usize,
        message: &str,
        retryable: &'static str,
    ) {
        let Some(kept) = &self.hardlinks.groups[group].kept else {
            return;
        };
        let rel = kept.leaf.dst_rel.clone();
        self.representative_failed(group);
        self.progress.entry_error_classified(
            &format!("syq: {}: {message}", display(&rel)),
            Some("io"),
            None,
            Some((&rel, crate::results::ReceiverListing::Unlisted)),
        );
        self.emit_entry_failed(
            FailedEntry {
                dst: &rel,
                src: self.mapping_source_rel(&rel).as_deref(),
                kind: Some(DeclaredKind::File),
            },
            retryable,
            "io",
            None,
            message,
            crate::results::ReceiverListing::Unlisted,
        );
    }

    /// Once planning has ended, and before any worker starts, send the
    /// checks of the representatives the planner kept: the operation a
    /// worker sent for each (`Worker::try_expected_match`), with the same
    /// condition and an owner the receiver accepts for a file to get new
    /// names (`vouch`, `REPORT_IDENTITY`). Their metadata matches, so none
    /// of it is changed. They go in requests sized by their replies, sent
    /// ahead of their replies, rather than one per scan batch.
    ///
    /// A representative the receiver will not change in place goes to a
    /// worker to be replaced, and one a restricted receiver refused with
    /// its whole request goes to a worker to be asked about by itself.
    /// Any other failure is settled here (`representative_check_failed`).
    /// A full destination ends the copy, after each failure has been
    /// settled here.
    pub(super) fn check_kept_representatives(&mut self) -> Result<()> {
        let kept: Vec<usize> = (0..self.hardlinks.groups.len())
            .filter(|&group| self.hardlinks.groups[group].kept.is_some())
            .collect();
        if kept.is_empty() {
            return Ok(());
        }
        self.assert_mutation_root()?;
        // The files to replace are queued together.
        let _burst = self.sched.file_burst();
        for groups in kept.chunks(8192) {
            let ops = groups
                .iter()
                .map(|&group| {
                    let kept = self.hardlinks.groups[group].kept.as_ref().unwrap();
                    Op::SetFileMetaIfSame {
                        path: kept.leaf.dst.clone(),
                        condition: kept.condition,
                        meta: self.opts.metadata_for(&kept.leaf.dst_rel, &kept.leaf.e),
                        // Its metadata matches (`keeps_representative`): none
                        // of it needs fixing.
                        flags: self.opts.ownership_flags(&kept.leaf.dst_rel)
                            | flags::REPORT_IDENTITY,
                    }
                })
                .collect();
            #[cfg(debug_assertions)]
            let _ = crate::fsops::record_test_event(
                "SYQ_TEST_HARDLINK_EVENTS",
                format_args!("check {}", groups.len()),
            );
            let (errors, refused_whole) = self.apply_requests(metadata_requests(ops))?;
            let capacity_error = first_capacity_error(&errors);
            for ((&group, error), whole) in groups.iter().zip(errors).zip(refused_whole) {
                match error {
                    None => self.representative_kept(group),
                    Some(error)
                        if capacity_error.is_none()
                            && (whole || crate::fsops::vouch::is_replace_required_wire(&error)) =>
                    {
                        self.representative_to_worker(
                            group,
                            crate::fsops::vouch::replace_reason_wire(&error),
                        )
                    }
                    Some(error) => self.representative_check_failed(group, &error),
                }
            }
            if let Some(error) = capacity_error {
                return Err(endpoint_error(error)).context("apply destination changes");
            }
        }
        Ok(())
    }

    /// Before any worker starts, check the sources of the representatives
    /// the receiver kept as a worker checks a file's source before
    /// publishing it (`source_changed`). One that changed is retried by a
    /// worker from what its source is now (`requeue_representative`); one
    /// held to its scanned destination, or whose source vanished or cannot
    /// be read, fails here. A change this does not see, or one after it, is
    /// found before linking (`same_source`). The requests are bounded by
    /// the scanned entries they ask about, which hold any ACLs and extended
    /// attributes copied, as their replies do.
    pub(super) fn recheck_kept_representatives(&mut self, source: &mut dyn Conn) -> Result<()> {
        #[cfg(debug_assertions)]
        crate::fsops::test_race_barrier(
            "SYQ_TEST_HARDLINK_RECHECK_READY_FILE",
            "SYQ_TEST_HARDLINK_RECHECK_CONTINUE_FILE",
            "hard-link representative recheck",
        )?;
        let kept: Vec<usize> = (0..self.hardlinks.groups.len())
            .filter(|&group| {
                self.hardlinks.groups[group]
                    .kept
                    .as_ref()
                    .is_some_and(|kept| kept.identity.is_some())
            })
            .collect();
        // The files to copy again are queued together.
        let _burst = self.sched.file_burst();
        let mut rest = &kept[..];
        while !rest.is_empty() {
            let mut bytes = 0usize;
            let len = rest
                .iter()
                .take(4096)
                .position(|&group| {
                    let leaf = self.hardlinks.kept_leaf(group);
                    bytes = bytes
                        .saturating_add(source_request_bytes(&leaf.src, Some(&leaf.source)))
                        .saturating_add(leaf.e.size_hint());
                    bytes > SOURCE_BATCH_PATH_BYTES
                })
                .map_or(rest.len().min(4096), |index| index.max(1));
            let (groups, later) = rest.split_at(len);
            rest = later;
            self.recheck_representatives(source, groups)?;
        }
        Ok(())
    }

    /// `recheck_kept_representatives` for `groups`, in one request. If it
    /// fails for one of them, as for a named source that vanished, each
    /// half is asked again, so that only that one fails.
    fn recheck_representatives(&mut self, source: &mut dyn Conn, groups: &[usize]) -> Result<()> {
        let (paths, references): (Vec<_>, Vec<_>) = groups
            .iter()
            .map(|&group| {
                let leaf = self.hardlinks.kept_leaf(group);
                (leaf.src.clone(), leaf.source.clone())
            })
            .unzip();
        let current = match stat_many_registered(source, paths, Some(references), false) {
            Ok(current) if current.len() == groups.len() => current,
            Ok(_) => bail!("source returned an incomplete stat batch"),
            Err(error) if source.is_dead() => return Err(error),
            Err(_) if groups.len() > 1 => {
                let (first, second) = groups.split_at(groups.len() / 2);
                self.recheck_representatives(source, first)?;
                return self.recheck_representatives(source, second);
            }
            Err(error) => {
                self.representative_source_failed(groups[0], &format!("{error:#}"), "unknown");
                return Ok(());
            }
        };
        for (&group, now) in groups.iter().zip(current) {
            if !source_changed(&self.hardlinks.kept_leaf(group).e, now.as_ref()) {
                continue;
            }
            let kept = self.hardlinks.groups[group].kept.as_ref().unwrap();
            let held = self.leaf_condition_for(&kept.leaf.dst, Some(&kept.destination))
                != TargetCondition::Any;
            match now.filter(|now| now.kind == Kind::File) {
                // A copy is published over whatever its name holds by then
                // (`leaf_condition_for`), so one held to the file the scan
                // found, as under `--existing`, is not copied again once
                // that file has been kept, as a worker does not either.
                Some(now) if !held => self.requeue_representative(group, None, Some(now)),
                // One that vanished is not handed on as the scan found it:
                // a file that took its place with the same size and time
                // would be kept.
                _ => self.representative_source_failed(
                    group,
                    "source changed during transfer (or vanished)",
                    "yes",
                ),
            }
        }
        Ok(())
    }

    pub(super) fn finish_hardlink_planning(&mut self) -> Result<()> {
        if !self.opts.hardlinks || self.opts.mapping_expected_hashes.is_empty() {
            return Ok(());
        }
        let mut hashes = std::collections::HashMap::new();
        for group in &self.hardlinks.groups {
            let (leaf, _) = &**group
                .preview
                .as_ref()
                .expect("hashed groups wait for planning");
            let required = crate::hashing::ExpectedHashes::collect(
                std::iter::once(&leaf.dst_rel)
                    .chain(group.followers.iter().map(|f| &f.rel))
                    .filter_map(|path| self.opts.expected_for(path)),
            )
            .with_context(|| format!("hardlinked source {}", display(&leaf.dst_rel)))?;
            if let Some(required) = required {
                hashes.insert(leaf.dst_rel.clone(), required);
            }
        }
        self.opts
            .hardlink_expected_hashes
            .set(hashes)
            .expect("hardlink assertions set once");
        // Publish the complete assertion map before any worker can see a job.
        // The jobs are then queued together.
        let _burst = self.sched.file_burst();
        self.leaf_parents = self.group_question_parents(
            self.hardlinks
                .groups
                .iter()
                .filter_map(|group| group.preview.as_deref())
                .map(|(leaf, destination)| (leaf, destination.as_ref())),
        );
        for index in 0..self.hardlinks.groups.len() {
            let (leaf, destination) = *self.hardlinks.groups[index].preview.take().unwrap();
            let representative = self.enqueue(
                (leaf.src, leaf.source),
                leaf.dst,
                leaf.rel,
                leaf.dst_rel,
                leaf.e,
                destination,
            );
            self.hardlinks.groups[index].representative = representative;
        }
        self.leaf_parents = Vec::new();
        Ok(())
    }

    /// Workers have joined, but their per-file identities are still alive.
    /// Batch across groups, so a tree of two-name groups does not require a
    /// network round trip per inode. Settle links before deletion and final
    /// directory metadata; failed representatives never license a link.
    pub(super) fn complete_hardlinks(&mut self, source: &mut dyn Conn) -> Result<()> {
        let mut ready = Vec::new();
        for group in std::mem::take(&mut self.hardlinks).groups {
            if group.followers.is_empty() {
                continue;
            }
            if let Some(preview) = &group.preview {
                let (representative, published) = &**preview;
                for follower in &group.followers {
                    if !self.check_hardlink_contents(source, follower)? {
                        continue;
                    }
                    self.preview_hardlink(
                        follower,
                        &representative.dst,
                        published.as_ref().map(|p| (p.dev, p.ino)),
                    );
                }
                continue;
            }
            let completed = if let Some(kept) = group.kept {
                kept.identity
                    .map(|identity| (Linked::Kept(kept), Some(identity)))
            } else {
                let completed = self
                    .opts
                    .hardlink_completions
                    .lock()
                    .unwrap()
                    .remove(&group.representative);
                completed
                    .filter(|_| !self.sched.is_failed(group.representative))
                    .map(|published| {
                        let job = self
                            .sched
                            .jobs
                            .lock()
                            .unwrap()
                            .snapshot(group.representative);
                        (Linked::Job(job), published)
                    })
            };
            let Some((representative, published)) = completed else {
                for follower in group.followers {
                    self.hardlink_failure(
                        &follower,
                        "hardlink representative did not complete successfully".into(),
                        crate::results::ReceiverListing::Unlisted,
                    );
                }
                continue;
            };
            ready.push(ReadyGroup {
                representative,
                published,
                followers: group.followers,
            });
        }
        let mut links = ready
            .iter()
            .flat_map(|group| group.followers.iter().map(move |f| (group, f)))
            .peekable();
        // The receiver runs a connection's requests in the order sent, and
        // each link names a follower no other request names, so several link
        // requests can await their replies, as final directory metadata does
        // (`apply_deferred`). Checking a follower's contents first asks the
        // destination itself, so those copies wait for each reply.
        let unanswered = if self.opts.protects_existing_contents() {
            1
        } else {
            self.dst.reply_queue().map_or(1, |replies| {
                replies.min(super::directory_stream::REQUESTS_IN_FLIGHT)
            })
        };
        let mut prepared = std::collections::VecDeque::new();
        let mut in_flight = std::collections::VecDeque::new();
        let mut root_checked = false;
        // What ends the links early. Nothing more is sent, and the requests
        // already sent are still answered: they have changed the names they
        // link.
        let mut failure = None;
        loop {
            while failure.is_none() && in_flight.len() < unanswered {
                if prepared.is_empty() {
                    let mut batch = Vec::new();
                    let mut bytes = 0usize;
                    while let Some((group, follower)) = links.peek() {
                        let size = group
                            .representative
                            .dst()
                            .len()
                            .saturating_add(follower.dst.len())
                            .saturating_add(64);
                        if !batch.is_empty()
                            && (batch.len() >= 256
                                || bytes.saturating_add(size) > SOURCE_BATCH_PATH_BYTES)
                        {
                            break;
                        }
                        bytes = bytes.saturating_add(size);
                        batch.push(links.next().unwrap());
                    }
                    if batch.is_empty() {
                        break;
                    }
                    match self.prepare_link_batch(source, &batch) {
                        Ok(requests) => prepared.extend(requests),
                        Err(error) => failure = Some(error),
                    }
                    continue;
                }
                // The destination root is checked once, before the first
                // link, as before the final directory metadata.
                if !root_checked {
                    root_checked = true;
                    if let Err(error) = self.assert_mutation_root() {
                        failure = Some(error);
                        break;
                    }
                }
                let (ops, links): (Vec<Op>, Vec<_>) = prepared.pop_front().unwrap();
                // Tests count each request's links and the requests still
                // unanswered when it is sent.
                #[cfg(debug_assertions)]
                let _ = crate::fsops::record_test_event(
                    "SYQ_TEST_HARDLINK_EVENTS",
                    format_args!("link {} {}", ops.len(), in_flight.len()),
                );
                match self.dst.send_pending(Request::Apply { ops }) {
                    Ok(reply) => in_flight.push_back((reply, links)),
                    Err(error) => failure = Some(error),
                }
            }
            let Some((reply, links)) = in_flight.pop_front() else {
                break;
            };
            let response = match self.dst.take_reply(reply) {
                Ok(response) => response,
                // No usable reply came: the connection is lost or out of
                // step, so the replies after it are not waited for.
                Err(error) => return Err(failure.unwrap_or(error)),
            };
            if let Err(error) = self.settle_link_request(response, &links) {
                failure.get_or_insert(error);
            }
        }
        failure.map_or(Ok(()), Err)
    }

    fn check_hardlink_contents(
        &mut self,
        source: &mut dyn Conn,
        follower: &Follower,
    ) -> Result<bool> {
        if !follower.compare_before_link {
            return Ok(true);
        }
        let source_hash = ok(
            source.call(Request::FileHash {
                path: follower.src.clone(),
                source: Some(follower.source.clone()),
            })?,
            "hash hardlink source",
        )?;
        let destination_hash = ok(
            self.dst.call(Request::FileHash {
                path: follower.dst.clone(),
                source: None,
            })?,
            "hash hardlink destination",
        )?;
        let same = matches!((source_hash, destination_hash),
            (Response::FileHash { size: left_size, hash: left }, Response::FileHash { size: right_size, hash: right })
            if left_size == right_size && left == right);
        if !same {
            self.hardlink_failure(
                follower,
                self.opts
                    .file_difference_message(&display(&follower.rel))
                    .into(),
                crate::results::ReceiverListing::Unlisted,
            );
        }
        Ok(same)
    }

    /// The link requests for `links`, after checking each follower's
    /// source is still the representative's: each request with the links
    /// it makes. A preview reports them instead.
    #[allow(clippy::type_complexity)]
    fn prepare_link_batch<'a>(
        &mut self,
        source: &mut dyn Conn,
        links: &[(&'a ReadyGroup, &'a Follower)],
    ) -> Result<Vec<(Vec<Op>, Vec<(&'a ReadyGroup, &'a Follower)>)>> {
        let current = if self.opts.dry_run {
            Vec::new()
        } else {
            let paths = links
                .iter()
                .flat_map(|(g, f)| [g.representative.src().clone(), f.src.clone()])
                .collect();
            let references = links
                .iter()
                .flat_map(|(g, f)| [g.representative.source().clone(), f.source.clone()])
                .collect();
            stat_many_registered(source, paths, Some(references), false)?
        };
        let mut operations = Vec::new();
        let mut pending = Vec::new();
        for (index, &(group, follower)) in links.iter().enumerate() {
            if !self.check_hardlink_contents(source, follower)? {
                continue;
            }
            if self.opts.dry_run {
                self.preview_hardlink(follower, group.representative.dst(), group.published);
                continue;
            }
            if !same_source(current[2 * index].as_ref(), group.representative.entry())
                || !same_source(
                    current[2 * index + 1].as_ref(),
                    group.representative.entry(),
                )
            {
                self.hardlink_failure(
                    follower,
                    "source hardlink group changed during the copy".into(),
                    crate::results::ReceiverListing::Unlisted,
                );
                continue;
            }
            let (dev, ino) = group
                .published
                .expect("live completion has a destination identity");
            // A follower already linked to the representative is unchanged.
            if follower.destination != group.published {
                self.opts
                    .note_directory_change(self.progress, &follower.dst, true);
            }
            operations.push(Op::Hardlink {
                path: follower.dst.clone(),
                source: group.representative.dst().clone(),
                dev,
                ino,
                condition: follower.condition,
            });
            pending.push((group, follower));
        }
        if operations.is_empty() {
            return Ok(Vec::new());
        }
        let mut pending = pending.into_iter();
        Ok(metadata_requests(operations)
            .into_iter()
            .map(|ops| {
                let links = pending.by_ref().take(ops.len()).collect();
                (ops, links)
            })
            .collect())
    }

    /// Report the outcome of a link request from the receiver's `response`.
    fn settle_link_request(
        &mut self,
        response: Response,
        links: &[(&ReadyGroup, &Follower)],
    ) -> Result<()> {
        let errors = self.applied(response, links.len())?;
        anyhow::ensure!(
            errors.len() == links.len(),
            "hardlink receiver returned an incomplete result batch"
        );
        let paths: Vec<PathBytes> = links
            .iter()
            .map(|(_, follower)| follower.dst.clone())
            .collect();
        let conditions: Vec<TargetCondition> = links
            .iter()
            .map(|(_, follower)| follower.condition)
            .collect();
        let kept = self.kept_by_policy(&paths, &conditions, &errors);
        for ((&(group, follower), error), kept) in links.iter().zip(errors).zip(kept) {
            if kept {
                self.progress.files_excluded.fetch_add(1, Relaxed);
                if !self.opts.quiet {
                    self.progress.eprintln(&format!(
                        "syq: {}: {}",
                        display(&follower.rel),
                        self.opts.kept_note()
                    ));
                }
            } else if let Some(error) = error {
                self.hardlink_failure(follower, error, crate::results::ReceiverListing::Listed);
            } else if follower.destination == group.published {
                self.progress.files_unchanged.fetch_add(1, Relaxed);
            } else {
                self.progress.files_total.fetch_add(1, Relaxed);
                self.progress.add_files(1);
                if let Some(results) = self.progress.results_writer() {
                    results.emit_operation_expected(
                        &crate::results::OperationRecord {
                            action: "transfer_file",
                            dst: &follower.rel,
                            src: self.mapping_source_rel(&follower.rel).as_deref(),
                            kind: "file",
                            disposition: "succeeded",
                            bytes: Some(0),
                            attempts: Some(1),
                            retryable: None,
                            class: None,
                            os_kind: None,
                            message: None,
                        },
                        self.opts.expected_for(&follower.rel),
                    );
                }
                if self.opts.verbose > 0 {
                    self.progress.println(&format!(
                        "{} => {}",
                        display(&follower.rel),
                        display(group.representative.rel())
                    ));
                }
            }
        }
        Ok(())
    }

    fn preview_hardlink(
        &mut self,
        follower: &Follower,
        representative: &[u8],
        published: Option<(u64, u64)>,
    ) {
        if published.is_some() && follower.destination == published {
            self.progress.files_unchanged.fetch_add(1, Relaxed);
        } else {
            self.note_directory_change(&follower.dst, true);
            self.progress.files_total.fetch_add(1, Relaxed);
            self.progress.add_files(1);
            self.dry_run_changes.metadata_files += 1;
            self.dry_run_changes.linked_files += 1;
            self.emit_trace(
                "transfer_file",
                &follower.rel,
                "file",
                Some(0),
                "metadata_differs",
            );
            if self.opts.verbose > 0 {
                self.progress.println(&format!(
                    "link {} to {}",
                    display(&follower.dst),
                    display(representative)
                ));
            }
        }
    }

    /// A follower that was not linked: `listing` says whether the receiver
    /// refused or failed the link itself.
    fn hardlink_failure(
        &self,
        follower: &Follower,
        error: WireError,
        listing: crate::results::ReceiverListing,
    ) {
        self.progress.entry_error_classified(
            &format!(
                "syq: hardlink {}: {}",
                display(&follower.rel),
                self.opts.wire_error_message_at(&error, &follower.dst)
            ),
            None,
            None,
            Some((&follower.rel, listing)),
        );
        if !self.opts.dry_run {
            self.emit_entry_failed(
                FailedEntry {
                    dst: &follower.rel,
                    src: self.mapping_source_rel(&follower.rel).as_deref(),
                    kind: Some(DeclaredKind::File),
                },
                "unknown",
                "io",
                wire_os_kind(&error),
                error.as_str(),
                listing,
            );
        }
    }
}

fn same_source(current: Option<&Entry>, expected: &Entry) -> bool {
    current.is_some_and(|e| {
        e.kind == Kind::File
            && e.dev == expected.dev
            && e.ino == expected.ino
            && e.size == expected.size
            && e.mtime == expected.mtime
            && e.mtime_nsec == expected.mtime_nsec
            && e.ctime == expected.ctime
            && e.ctime_nsec == expected.ctime_nsec
    })
}

impl Worker {
    pub(super) fn publication_flags(&self, job: &WorkerJob) -> u8 {
        publication_metadata_flags(self.opts.flags_for(&job.rel_bytes))
            | if self.opts.hardlinks && job.entry.nlink > 1 {
                flags::REPORT_IDENTITY
            } else {
                0
            }
    }

    /// Metadata flags for a destination kept because its contents already
    /// match: publication's, with the times policy of a content match.
    pub(super) fn unchanged_flags(&self, job: &WorkerJob) -> u8 {
        (self.publication_flags(job) & !flags::TIMES)
            | (self.opts.matching_flags_for(&job.rel_bytes) & flags::TIMES)
    }

    pub(super) fn finish_matched_basis(&mut self, idx: usize, job: &WorkerJob) -> Result<()> {
        let mut meta = self.opts.metadata_for(&job.rel_bytes, &job.entry);
        meta.mode = self.create_mode(job);
        let response = change_ok(
            self.dst.call(Request::FinishBasis {
                expected_hash: self.opts.expected_hashes_for(job),
                path: job.dst.clone(),
                copy_id: self.copy_id(),
                meta,
                flags: self.unchanged_flags(job),
                condition: job.target_condition,
            })?,
            "finish content-identical destination",
        )?;
        self.accept_hardlink_reply(idx, job, response)
    }

    pub(super) fn accept_hardlink_reply(
        &self,
        idx: usize,
        job: &WorkerJob,
        response: Response,
    ) -> Result<()> {
        let identity = match response {
            Response::Published { dev, ino } => Some((dev, ino)),
            Response::Ok => None,
            Response::PublishedBesideEarlierPartials(identity) => identity,
            other => bail!("unexpected publication reply: {other:?}"),
        };
        self.record_hardlink_identity(idx, job, identity)
    }

    pub(super) fn record_hardlink_identity(
        &self,
        index: usize,
        job: &WorkerJob,
        identity: Option<(u64, u64)>,
    ) -> Result<()> {
        if self.opts.hardlinks && job.entry.nlink > 1 {
            let identity = identity
                .context("receiver omitted the completed hardlink representative's identity")?;
            self.opts
                .hardlink_completions
                .lock()
                .unwrap()
                .insert(index, Some(identity));
        }
        Ok(())
    }
}

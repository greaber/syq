use super::*;

/// Only multiply linked source inodes consume group state. All selections in
/// one copy use the same source endpoint; device/inode are scoped to that host.
#[derive(Default)]
pub(super) struct Hardlinks {
    by_inode: std::collections::HashMap<(u64, u64), usize>,
    groups: Vec<Group>,
}

struct Group {
    representative: usize,
    preview: Option<Box<(Planned, Option<Entry>)>>,
    followers: Vec<Follower>,
}

struct Follower {
    src: PathBytes,
    source: RegisteredPath,
    dst: PathBytes,
    rel: PathBytes,
    destination: Option<(u64, u64)>,
}

struct ReadyGroup {
    job: WorkerJob,
    published: Option<(u64, u64)>,
    followers: Vec<Follower>,
}

impl Planner<'_> {
    pub(super) fn plan_hardlinked_file(&mut self, leaf: Planned, destination: Option<Entry>) {
        let identity = (leaf.e.dev, leaf.e.ino);
        if let Some(&index) = self.hardlinks.by_inode.get(&identity) {
            let group = &mut self.hardlinks.groups[index];
            let jobs = self.sched.jobs.lock().unwrap();
            let (entry, rel) = if let Some(preview) = &group.preview {
                let (leaf, _) = &**preview;
                (&leaf.e, &leaf.dst_rel)
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
                )
            {
                self.progress.error(&format!(
                    "syq: hardlinked source paths {} and {} request conflicting destination metadata",
                    display(rel), display(&leaf.dst_rel)
                ));
                self.collision = true;
                return;
            }
            group.followers.push(Follower {
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
                followers: Vec::new(),
            });
        } else if self.opts.dry_run
            && (!self.opts.checksum
                || destination
                    .as_ref()
                    .is_none_or(|d| d.kind != Kind::File || d.size != leaf.e.size))
        {
            let matched = destination
                .as_ref()
                .is_some_and(|d| self.opts.metadata_matches(&leaf.dst_rel, &leaf.e, d));
            if matched {
                self.progress.files_unchanged.fetch_add(1, Relaxed);
                self.progress
                    .bytes_unchanged
                    .fetch_add(leaf.e.size, Relaxed);
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
                self.progress.files_total.fetch_add(1, Relaxed);
                self.progress.bytes_total.fetch_add(leaf.e.size, Relaxed);
                self.progress.bytes_done.fetch_add(leaf.e.size, Relaxed);
                self.progress.add_files(1);
                self.emit_trace(
                    "transfer_file",
                    &leaf.dst_rel,
                    "file",
                    Some(leaf.e.size),
                    if destination.is_none() {
                        "destination_missing"
                    } else {
                        "content_differs"
                    },
                );
            }
            self.hardlinks
                .by_inode
                .insert(identity, self.hardlinks.groups.len());
            self.hardlinks.groups.push(Group {
                representative: 0,
                preview: Some(Box::new((leaf, destination.filter(|_| matched)))),
                followers: Vec::new(),
            });
        } else {
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
                followers: Vec::new(),
            });
        }
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
                    self.preview_hardlink(
                        follower,
                        &representative.dst,
                        published.as_ref().map(|p| (p.dev, p.ino)),
                    );
                }
                continue;
            }
            let completed = self
                .opts
                .hardlink_completions
                .lock()
                .unwrap()
                .remove(&group.representative);
            let Some(published) = completed.filter(|_| !self.sched.is_failed(group.representative))
            else {
                for follower in group.followers {
                    self.hardlink_failure(
                        &follower,
                        "hardlink representative did not complete successfully".into(),
                    );
                }
                continue;
            };
            ready.push(ReadyGroup {
                job: self
                    .sched
                    .jobs
                    .lock()
                    .unwrap()
                    .snapshot(group.representative),
                published,
                followers: group.followers,
            });
        }
        let mut links = ready
            .iter()
            .flat_map(|group| group.followers.iter().map(move |f| (group, f)))
            .peekable();
        while links.peek().is_some() {
            let mut batch = Vec::new();
            let mut bytes = 0usize;
            while let Some((group, follower)) = links.peek() {
                let size = group
                    .job
                    .dst
                    .len()
                    .saturating_add(follower.dst.len())
                    .saturating_add(64);
                if !batch.is_empty()
                    && (batch.len() >= 256 || bytes.saturating_add(size) > SOURCE_BATCH_PATH_BYTES)
                {
                    break;
                }
                bytes = bytes.saturating_add(size);
                batch.push(links.next().unwrap());
            }
            self.complete_link_batch(source, &batch)?;
        }
        Ok(())
    }

    fn complete_link_batch(
        &mut self,
        source: &mut dyn Conn,
        links: &[(&ReadyGroup, &Follower)],
    ) -> Result<()> {
        let current = if self.opts.dry_run {
            Vec::new()
        } else {
            let paths = links
                .iter()
                .flat_map(|(g, f)| [g.job.src.clone(), f.src.clone()])
                .collect();
            let references = links
                .iter()
                .flat_map(|(g, f)| [g.job.source.clone(), f.source.clone()])
                .collect();
            stat_many_registered(source, paths, Some(references), false)?
        };
        let mut operations = Vec::new();
        let mut pending = Vec::new();
        for (index, &(group, follower)) in links.iter().enumerate() {
            if self.opts.dry_run {
                self.preview_hardlink(follower, &group.job.dst, group.published);
                continue;
            }
            if !same_source(current[2 * index].as_ref(), &group.job.entry)
                || !same_source(current[2 * index + 1].as_ref(), &group.job.entry)
            {
                self.hardlink_failure(
                    follower,
                    "source hardlink group changed during the copy".into(),
                );
                continue;
            }
            let (dev, ino) = group
                .published
                .expect("live completion has a destination identity");
            operations.push(Op::Hardlink {
                path: follower.dst.clone(),
                source: group.job.dst.clone(),
                dev,
                ino,
            });
            pending.push((group, follower));
        }
        if operations.is_empty() {
            return Ok(());
        }
        self.assert_mutation_root()?;
        let errors = self.apply(operations)?;
        anyhow::ensure!(
            errors.len() == pending.len(),
            "hardlink receiver returned an incomplete result batch"
        );
        for ((group, follower), error) in pending.into_iter().zip(errors) {
            if let Some(error) = error {
                self.hardlink_failure(follower, error);
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
                        display(&group.job.rel_bytes)
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
            self.progress.files_total.fetch_add(1, Relaxed);
            self.progress.add_files(1);
            self.dry_run_changes.metadata_files += 1;
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

    fn hardlink_failure(&self, follower: &Follower, error: WireError) {
        self.progress.error(&format!(
            "syq: hardlink {}: {error}",
            display(&follower.rel)
        ));
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

    pub(super) fn finish_matched_basis(&mut self, idx: usize, job: &WorkerJob) -> Result<()> {
        let mut meta = self.opts.metadata_for(&job.rel_bytes, &job.entry);
        meta.mode = self.create_mode(job);
        let response = ok(
            self.dst.call(Request::FinishBasis {
                expected_hash: self.opts.expected_hashes_for(job),
                path: job.dst.clone(),
                copy_id: self.copy_id(),
                meta,
                flags: self.publication_flags(job),
                condition: job.target_condition,
                guard: job.container_guard.clone(),
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

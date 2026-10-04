//! Replaced files up to `PATCH_MAX_FILE` bytes are compared before any
//! contents are sent, in groups that flow through three requests:
//!
//! 1. the destination hashes the blocks of the files they would replace
//!    (`HashExistingBatch`);
//! 2. the source reads each file once and returns only the blocks whose
//!    hashes differ (`ReadDifferingBatch`);
//! 3. the destination publishes each file from those blocks and the
//!    matching blocks of the file it replaces, hashing them again as it reads
//!    them, or keeps a file that matched whole and has not changed since it
//!    was hashed (`PatchSmallBatch`).
//!
//! Groups are pipelined through these stages, so a run of files costs about
//! one round trip of lead time rather than round trips per file.

use super::*;

/// Files and source bytes per group. The source reads each file of a group
/// into memory to compare it.
const COMPARE_GROUP_FILES: usize = 256;
const COMPARE_GROUP_BYTES: u64 = 16 << 20;
/// Files up to this size are compared and patched in groups. A larger file
/// takes the per-file path, whose ranges several workers can share.
pub(super) const PATCH_MAX_FILE: u64 = 64 << 20;
/// Comparison block of the grouped path unless one is configured. A small
/// edit then costs this much, not a whole default comparison block.
const PATCH_BLOCK: u64 = crate::proto::MIN_HASH_BLOCK_BYTES;

/// What comparing one file decided.
pub(super) enum Compared {
    /// The destination already held the source's contents and was kept, with
    /// the kept inode when the publication flags asked for it.
    Kept(Option<(u64, u64)>),
    /// Published from `sent` new bytes and `reused` bytes of the file it
    /// replaced.
    Published {
        identity: Option<(u64, u64)>,
        sent: u64,
        reused: u64,
    },
    /// The source changed after it was planned, to this or nothing.
    SourceChanged(Option<Entry>),
    /// Earlier runs left partial copies: resume from them per file.
    ResumePartial,
    /// The file could not be compared or patched: replace it whole.
    Differs,
}

#[derive(Clone, Copy)]
enum Stage {
    Hash,
    Read,
    Patch,
}

/// One group's files, as positions in the batch, and what each stage
/// learned about those still in flight.
#[derive(Default)]
struct Group {
    files: Vec<usize>,
    /// Files sent to be read: the destination's block hashes, the
    /// fingerprint of the file they came from, and whether the comparison
    /// only decides if the file is unchanged.
    reads: Vec<(usize, Vec<ContentDigest>, Option<FileFingerprint>, bool)>,
    /// Files sent to be published: the bytes sent and reused.
    published: Vec<(usize, u64, u64)>,
}

impl Worker {
    /// An explicit comparison block size applies here too.
    pub(super) fn patch_block(&self) -> u64 {
        if self.opts.block_explicit || self.opts.tuning.comparison_block_size.is_some() {
            self.opts.block
        } else {
            self.opts.block.min(PATCH_BLOCK)
        }
    }

    /// Claim files near `idx` whose destinations can be compared, and
    /// compare them. Kept and published files are complete; the others
    /// return to the queue, those that failed marked to be replaced whole.
    pub(super) fn compare_small_batch(&mut self, idx: usize) -> Result<()> {
        let first_bytes = self.job(idx).entry.size;
        let target = self
            .sched
            .begin_fast_batch(self.gate.active(), self.fast_batch_files);
        // Only differing blocks cross the network, so a batch holds enough
        // groups to keep the pipeline full: two windows of them.
        let batch_bytes =
            COMPARE_GROUP_BYTES * 2 * crate::transfer_tuning::DEFAULT_PIPELINE_DEPTH as u64;
        let mut batch = vec![idx];
        batch.extend(self.sched.take_small_near(
            idx,
            PATCH_MAX_FILE,
            target - 1,
            batch_bytes.saturating_sub(first_bytes),
        ));
        let (batch, others): (Vec<usize>, Vec<usize>) = batch
            .into_iter()
            .partition(|&i| i == idx || self.compare_candidate(i));
        for i in others {
            self.sched.return_unstarted(Item::File(i));
        }
        self.sched.mark_fast(batch.len() - 1);
        self.benchmark.compared_files += batch.len() as u64;
        let (outcomes, result) = self.compare_small_files(&batch);
        let mut finished = Vec::new();
        // Requeue before releasing the claim, so the queue is never empty
        // while these files are still unfinished.
        for (&i, outcome) in batch.iter().zip(outcomes) {
            match outcome {
                Some(Compared::Differs) => {
                    self.sched.jobs.lock().unwrap()[i].compared = true;
                    self.sched.requeue(i);
                }
                Some(Compared::ResumePartial) => {
                    self.sched.jobs.lock().unwrap()[i].resume_partial = true;
                    self.sched.requeue(i);
                }
                Some(Compared::SourceChanged(now)) => {
                    let job = self.job(i);
                    self.retry_changed_small(i, &job, now);
                }
                Some(outcome) => finished.push((i, outcome)),
                None => self.sched.requeue(i),
            }
        }
        let completed = finished
            .into_iter()
            .try_for_each(|(i, outcome)| self.complete_compared(i, outcome));
        self.sched.complete_fast_batch(batch.len());
        result.and(completed)
    }

    /// Compare `batch` with the destination in pipelined groups. Returns each
    /// file's outcome, None for a file left unfinished because comparison
    /// stopped early, and the first error that stopped it.
    fn compare_small_files(&mut self, batch: &[usize]) -> (Vec<Option<Compared>>, Result<()>) {
        let jobs: Vec<WorkerJob> = {
            let all = self.sched.jobs.lock().unwrap();
            batch.iter().map(|&i| all.snapshot(i)).collect()
        };
        let mut outcomes: Vec<Option<Compared>> = (0..jobs.len()).map(|_| None).collect();
        let mut unissued = std::collections::VecDeque::new();
        let (mut start, mut bytes) = (0, 0u64);
        for (i, job) in jobs.iter().enumerate() {
            if i > start
                && (i - start >= COMPARE_GROUP_FILES
                    || bytes.saturating_add(job.entry.size) > COMPARE_GROUP_BYTES)
            {
                unissued.push_back((start..i).collect::<Vec<_>>());
                (start, bytes) = (i, 0);
            }
            bytes += job.entry.size;
        }
        if start < jobs.len() {
            unissued.push_back((start..jobs.len()).collect());
        }
        let window = crate::transfer_tuning::DEFAULT_PIPELINE_DEPTH;
        let mut groups: Vec<Group> = Vec::new();
        let mut in_flight = 0;
        // Each group has at most one request outstanding, so neither
        // connection has more than `window` replies pending.
        let mut source = std::collections::VecDeque::new();
        let mut destination = std::collections::VecDeque::new();
        let result = (|| -> Result<()> {
            loop {
                while in_flight < window && self.gate.allowed(self.id) && !self.sched.is_aborted() {
                    let Some(files) = unissued.pop_front() else {
                        break;
                    };
                    let existing = files
                        .iter()
                        .map(|&i| {
                            let job = &jobs[i];
                            ExistingRead {
                                path: job.dst.clone(),
                                len: job.entry.size,
                                condition: job.target_condition,
                                guard: job.container_guard.clone(),
                            }
                        })
                        .collect();
                    self.dst.send(Request::HashExistingBatch {
                        block: self.patch_block(),
                        files: existing,
                    })?;
                    destination.push_back((groups.len(), Stage::Hash, std::time::Instant::now()));
                    groups.push(Group {
                        files,
                        ..Default::default()
                    });
                    in_flight += 1;
                }
                // Replies arrive in order on each connection. Take the one
                // whose request went out first.
                let from_source = match (source.front(), destination.front()) {
                    (Some((_, _, a)), Some((_, _, b))) => a <= b,
                    (Some(_), None) => true,
                    (None, Some(_)) => false,
                    (None, None) => return Ok(()),
                };
                let (group, stage, _) = if from_source {
                    source.pop_front()
                } else {
                    destination.pop_front()
                }
                .expect("pending reply");
                let response = if from_source {
                    self.src.recv()?
                } else {
                    self.dst.recv()?
                };
                let next =
                    self.compare_stage(&jobs, &mut groups[group], stage, response, &mut outcomes)?;
                match next {
                    Some((Stage::Read, request)) => {
                        self.src.send(request)?;
                        source.push_back((group, Stage::Read, std::time::Instant::now()));
                    }
                    Some((stage, request)) => {
                        self.dst.send(request)?;
                        destination.push_back((group, stage, std::time::Instant::now()));
                    }
                    None => in_flight -= 1,
                }
            }
        })();
        // An endpoint error consumes its own reply. Drain the requests still
        // outstanding in wire order, keeping what they decided; a transport
        // error ends the drain.
        let drain = |connection: &mut Box<dyn Conn>,
                     pending: std::collections::VecDeque<(usize, Stage, std::time::Instant)>,
                     groups: &mut Vec<Group>,
                     outcomes: &mut Vec<Option<Compared>>|
         -> Result<()> {
            for (group, stage, _) in pending {
                let response = connection.recv()?;
                Self::record_stage_outcomes(&mut groups[group], stage, response, outcomes);
            }
            Ok(())
        };
        let source_end = drain(&mut self.src, source, &mut groups, &mut outcomes);
        let destination_end = drain(&mut self.dst, destination, &mut groups, &mut outcomes);
        (outcomes, result.and(source_end).and(destination_end))
    }

    /// Act on one group's reply: record the outcomes it decides, and return
    /// the group's next request, if any of its files go on.
    fn compare_stage(
        &mut self,
        jobs: &[WorkerJob],
        group: &mut Group,
        stage: Stage,
        response: Response,
        outcomes: &mut [Option<Compared>],
    ) -> Result<Option<(Stage, Request)>> {
        let block = self.patch_block();
        match stage {
            Stage::Hash => {
                let existing = match ok(response, "hash existing batch") {
                    Ok(Response::ExistingHashes(existing))
                        if existing.len() == group.files.len() =>
                    {
                        existing
                    }
                    Ok(other) => bail!("unexpected response {other:?}"),
                    // The files are copied whole, where their errors are reported.
                    Err(_) => Vec::new(),
                };
                for &i in &group.files {
                    outcomes[i] = Some(Compared::Differs);
                }
                let mut reads = Vec::new();
                for (&i, existing) in group.files.iter().zip(existing) {
                    let job = &jobs[i];
                    let (expected, basis) = match existing {
                        Ok(ExistingHashes { partials: true, .. }) => {
                            outcomes[i] = Some(Compared::ResumePartial);
                            continue;
                        }
                        Ok(ExistingHashes {
                            fingerprint,
                            hashes,
                            ..
                        }) if hashes.len() as u64 <= job.entry.size.div_ceil(block) => {
                            (hashes, fingerprint)
                        }
                        _ => continue,
                    };
                    // Without block reuse (--hash alone), a comparison only
                    // decides whether the file is unchanged.
                    let compare_only = !self.reuses_blocks_for(job, job.dst_entry.as_deref());
                    reads.push(DifferingRead {
                        path: job.src.clone(),
                        source: self.source_reference(job),
                        attempt: job.attempt,
                        len: job.entry.size as u32,
                        expected: expected.clone(),
                        compare_only,
                    });
                    group.reads.push((i, expected, basis, compare_only));
                }
                Ok((!reads.is_empty())
                    .then(|| (Stage::Read, Request::ReadDifferingBatch { block, reads })))
            }
            Stage::Read => {
                let differing = match ok(response, "read differing batch") {
                    Ok(Response::DifferingBlocks(differing))
                        if differing.len() == group.reads.len() =>
                    {
                        differing
                    }
                    Ok(other) => bail!("unexpected response {other:?}"),
                    Err(_) => return Ok(None),
                };
                let mut patches = Vec::new();
                for ((i, expected, basis, compare_only), differing) in
                    std::mem::take(&mut group.reads).into_iter().zip(differing)
                {
                    let job = &jobs[i];
                    let Ok(DifferingBlocks {
                        source,
                        matching,
                        data,
                        hash,
                    }) = differing
                    else {
                        continue;
                    };
                    if source_changed(&job.entry, source.as_ref()) {
                        outcomes[i] = Some(Compared::SourceChanged(source));
                        continue;
                    }
                    if matching.len() as u64 != job.entry.size.div_ceil(block)
                        || (compare_only && matching.iter().any(|same| !same))
                    {
                        continue;
                    }
                    let Some(reuse) = matching
                        .iter()
                        .enumerate()
                        .map(|(index, &same)| {
                            if same {
                                expected.get(index).map(|hash| Some(*hash))
                            } else {
                                Some(None)
                            }
                        })
                        .collect::<Option<Vec<_>>>()
                    else {
                        continue;
                    };
                    let reused: u64 = matching
                        .iter()
                        .enumerate()
                        .filter(|(_, same)| **same)
                        .map(|(index, _)| block.min(job.entry.size - index as u64 * block))
                        .sum();
                    let sent = job.entry.size - reused;
                    if data.len() as u64 != sent {
                        continue;
                    }
                    self.limit(sent);
                    let mut meta = self.opts.metadata_for(&job.rel_bytes, &job.entry);
                    meta.mode = self.create_mode(job);
                    patches.push(SmallPatch {
                        path: job.dst.clone(),
                        copy_id: self.copy_id(),
                        len: job.entry.size,
                        block,
                        reuse,
                        data,
                        hash,
                        basis,
                        meta,
                        flags: self.publication_flags(job),
                        unchanged_flags: self.unchanged_flags(job),
                        condition: job.target_condition,
                        guard: job.container_guard.clone(),
                    });
                    group.published.push((i, sent, reused));
                }
                Ok(
                    (!patches.is_empty())
                        .then(|| (Stage::Patch, Request::PatchSmallBatch(patches))),
                )
            }
            Stage::Patch => {
                Self::record_stage_outcomes(group, stage, response, outcomes);
                Ok(None)
            }
        }
    }

    /// Record what a patch reply decided without sending anything further:
    /// the files kept and published.
    fn record_stage_outcomes(
        group: &mut Group,
        stage: Stage,
        response: Response,
        outcomes: &mut [Option<Compared>],
    ) {
        let Stage::Patch = stage else {
            return;
        };
        let Ok(Response::PatchedBatch(patched)) = ok(response, "patch small batch") else {
            return;
        };
        if patched.len() != group.published.len() {
            return;
        }
        for (&(i, sent, reused), patched) in group.published.iter().zip(patched) {
            outcomes[i] = Some(match patched {
                Ok(SmallPatched {
                    kept: true,
                    identity,
                }) => Compared::Kept(identity),
                Ok(SmallPatched { identity, .. }) => Compared::Published {
                    identity,
                    sent,
                    reused,
                },
                Err(_) => Compared::Differs,
            });
        }
    }

    fn complete_compared(&mut self, idx: usize, outcome: Compared) -> Result<()> {
        let job = self.job(idx);
        match outcome {
            Compared::Kept(identity) => {
                self.benchmark.kept_files += 1;
                self.complete_kept_small(idx, &job, identity)
            }
            Compared::Published {
                identity,
                sent,
                reused,
            } => {
                self.benchmark.patched_files += 1;
                if let Err(error) = self.record_hardlink_identity(idx, &job, identity) {
                    return self.file_error(idx, error);
                }
                job.done.store(job.entry.size, Relaxed);
                self.progress.add_bytes(sent);
                self.progress.bytes_unchanged.fetch_add(reused, Relaxed);
                self.progress.bytes_total.fetch_sub(reused, Relaxed);
                self.complete_file(job, false)
            }
            Compared::SourceChanged(_) | Compared::ResumePartial | Compared::Differs => {
                unreachable!("these files are requeued")
            }
        }
    }

    /// A small file whose destination already held its contents: as for a
    /// content-identical file on the per-file path, its bytes count as
    /// unchanged, and it is no transfer.
    pub(super) fn complete_kept_small(
        &mut self,
        idx: usize,
        job: &WorkerJob,
        identity: Option<(u64, u64)>,
    ) -> Result<()> {
        if let Err(error) = self.record_hardlink_identity(idx, job, identity) {
            return self.file_error(idx, error);
        }
        job.done.store(job.entry.size, Relaxed);
        self.progress
            .bytes_unchanged
            .fetch_add(job.entry.size, Relaxed);
        self.progress.bytes_total.fetch_sub(job.entry.size, Relaxed);
        self.progress.files_total.fetch_sub(1, Relaxed);
        self.progress.files_unchanged.fetch_add(1, Relaxed);
        Ok(())
    }
}

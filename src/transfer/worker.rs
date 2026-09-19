use super::*;

pub(super) struct RangeFlight {
    pub(super) handle: RangeHandle,
    pub(super) start: u64,
    pub(super) pending: usize,
    pub(super) credited: u64,
}

impl RangeFlight {
    pub(super) fn new(handle: RangeHandle) -> Self {
        let start = handle.lock().unwrap().pos;
        Self {
            handle,
            start,
            pending: 0,
            credited: 0,
        }
    }
}

pub(super) struct Worker {
    pub(super) id: usize,
    pub(super) src: Box<dyn Conn>,
    pub(super) dst: Box<dyn Conn>,
    pub(super) sched: Arc<Sched>,
    pub(super) progress: Arc<Progress>,
    pub(super) opts: Arc<Opts>,
    pub(super) bwlimit: Option<Arc<BandwidthLimit>>,
    pub(super) gate: Arc<Gate>,
    pub(super) observation: Option<Arc<crate::transfer_observations::Actor>>,
    pub(super) benchmark: crate::transfer_tuning::BenchmarkStats,
    pub(super) fast_batch_files: usize,
    pub(super) setup_elapsed: std::time::Duration,
}

pub(super) struct BlockDiff {
    pub(super) ranges: Vec<(u64, u64)>,
    pub(super) held_len: Option<u64>,
    pub(super) source_hashes: Vec<ContentDigest>,
}

impl Worker {
    /// Every content request carries the source capability, including when
    /// the operator allowed a foreign-owned symlink in the typed root path.
    pub(super) fn source_reference(&self, job: &WorkerJob) -> Option<RegisteredPath> {
        Some(job.source.clone())
    }

    pub(super) fn run(&mut self) -> Result<()> {
        let r = (|| {
            configure_hashing(&mut *self.src, self.opts.hash_policy)?;
            configure_hashing(&mut *self.dst, self.opts.hash_policy)?;
            if self.progress.observations.enabled.load(Relaxed) {
                let actor = self.progress.observations.workers.actor("worker");
                self.src
                    .observe(&self.progress.observations, &actor, true, self.id)?;
                self.dst
                    .observe(&self.progress.observations, &actor, false, self.id)?;
                self.observation = Some(actor);
            }
            let _working = self
                .observation
                .as_ref()
                .map(|a| a.span(crate::transfer_observations::Stage::Work));
            self.run_inner()
        })();
        if r.as_ref()
            .is_err_and(|error| error.is::<RangeReplyMismatch>() || !self.transport_dead())
        {
            // Fatal local/protocol failures cannot be healed by reopening a
            // transport. Wake peers so the whole transfer unwinds.
            self.sched.abort();
        }
        r
    }

    pub(super) fn transport_dead(&self) -> bool {
        self.src.is_dead() || self.dst.is_dead()
    }

    pub(super) fn collect_transport_stats(&mut self) -> Vec<TcpPairStats> {
        let mut stats = Vec::new();
        if let Some(value) = self.src.transport_stats() {
            stats.push(value);
        }
        if let Some(value) = self.dst.transport_stats() {
            stats.push(value);
        }
        stats
    }

    pub(super) fn run_inner(&mut self) -> Result<()> {
        loop {
            if !self.gate.allowed(self.id) {
                let _parked = self
                    .observation
                    .as_ref()
                    .map(|a| a.span(crate::transfer_observations::Stage::Parked));
                // Parked by the tuner: keep the connections, take no work.
                let sched = self.sched.clone();
                if !self
                    .gate
                    .park(self.id, || sched.is_aborted() || sched.finished())
                {
                    return Ok(());
                }
            }
            let item = {
                let _awaiting = self
                    .observation
                    .as_ref()
                    .map(|a| a.span(crate::transfer_observations::Stage::AwaitingWork));
                self.sched.next()
            };
            match item {
                Item::Exit => {
                    return Ok(());
                }
                Item::File(idx) => {
                    let progress = self.progress.clone();
                    let _copying = progress.copying_interval();
                    if self.fast_eligible(idx) {
                        let first_bytes = self.job(idx).entry.size;
                        let target = self
                            .sched
                            .begin_fast_batch(self.gate.active(), self.fast_batch_files);
                        let mut batch = vec![idx];
                        // Keep rate-limited batches to one file so a push can't
                        // accumulate locally and then hit the network in a burst.
                        if self.bwlimit.is_none() {
                            batch.extend(self.sched.take_small(
                                fast_file_size_limit(&self.opts, self.bwlimit.as_deref()),
                                target - batch.len(),
                                self.opts.tuning.batch_bytes().saturating_sub(first_bytes),
                            ));
                        }
                        let (mut fast, slow): (Vec<usize>, Vec<usize>) =
                            batch.into_iter().partition(|&i| self.fast_eligible(i));
                        self.sched.mark_fast(fast.len() - 1);
                        let fast_result = self.fast_batch(&mut fast);
                        self.sched.complete_fast_batch(fast.len());
                        if let Err(e) = fast_result {
                            if self.transport_dead() {
                                for &i in &slow {
                                    self.sched.ranges_ready(i, vec![]);
                                }
                                for &i in fast.iter().chain(&slow) {
                                    self.sched.requeue(i);
                                }
                                return Err(e);
                            }
                            let message = format!("{e:#}");
                            for &i in &fast {
                                self.file_error(i, anyhow::anyhow!(message.clone()))?;
                            }
                        }
                        for (position, &i) in slow.iter().enumerate() {
                            if let Err(e) = self.handle_file(i) {
                                if self.transport_dead() {
                                    for &pending in &slow[position + 1..] {
                                        self.sched.ranges_ready(pending, vec![]);
                                        self.sched.requeue(pending);
                                    }
                                }
                                self.file_error(i, e)?;
                            }
                        }
                    } else {
                        let res = if self.opts.dry_run {
                            self.preview_file(idx)
                        } else {
                            self.handle_file(idx)
                        };
                        if let Err(e) = res {
                            self.file_error(idx, e)?;
                        }
                    }
                }
                Item::Range(h) => {
                    let progress = self.progress.clone();
                    let _copying = progress.copying_interval();
                    let (idx, start) = {
                        let range = h.lock().unwrap();
                        (range.idx, range.pos)
                    };
                    let mut credited = 0;
                    let res = self.transfer_range(&h, &mut credited);
                    if let Err(e) = res {
                        if self.transport_dead() {
                            self.retry_credited_range(&h, start, credited);
                            return Err(e);
                        }
                        // Keep this range outstanding until failure is visible:
                        // another worker must not elect itself to publish it.
                        self.file_error(idx, e)?;
                        self.sched.range_done(&h);
                        continue;
                    }
                    let done = self.sched.range_done(&h);
                    if done {
                        if let Err(e) = self.finish_file(idx) {
                            if self.transport_dead() {
                                self.sched.requeue_finish(idx, false);
                            }
                            self.file_error(idx, e)?;
                        }
                    }
                }
                Item::Finish { idx, matched } => {
                    let progress = self.progress.clone();
                    let _copying = progress.copying_interval();
                    let result = if matched {
                        self.finish_matched_file(idx)
                    } else {
                        self.finish_file(idx)
                    };
                    if let Err(e) = result {
                        if self.transport_dead() {
                            self.sched.requeue_finish(idx, matched);
                        }
                        self.file_error(idx, e)?;
                    }
                }
            }
        }
    }

    /// Small new files are sent without a per-file protocol round trip. The
    /// default publishes sidecars atomically; explicit --inplace batches write
    /// final names directly when no placement guard requires staging.
    pub(super) fn fast_eligible(&self, idx: usize) -> bool {
        let jobs = self.sched.jobs.lock().unwrap();
        let j = &jobs[idx];
        !self.opts.dry_run
            && self.opts.expected_for(&j.rel_bytes).is_none()
            && !self.opts.tuning.force_ranges()
            && j.entry.size <= fast_file_size_limit(&self.opts, self.bwlimit.as_deref())
            && jobs.destination(idx).is_none()
            && (!self.opts.inplace || j.inplace)
    }

    pub(super) fn fail_small_batch(
        results: &mut [Option<Result<()>>],
        indices: impl IntoIterator<Item = usize>,
        error: &anyhow::Error,
    ) {
        let error = crate::fsops::wire_error(error);
        for idx in indices {
            results[idx] = Some(Err(endpoint_error(error.clone())));
        }
    }

    pub(super) fn record_small_batch_reply(
        sent: &[usize],
        response: Response,
        results: &mut [Option<Result<()>>],
    ) -> bool {
        let applied = ok(response, "put small batch").and_then(|response| match response {
            Response::Applied(applied) if applied.len() == sent.len() => Ok(applied),
            other => bail!("unexpected response {other:?}"),
        });
        let applied = match applied {
            Ok(applied) => applied,
            Err(error) => {
                Self::fail_small_batch(results, sent.iter().copied(), &error);
                return false;
            }
        };
        for (&idx, error) in sent.iter().zip(applied) {
            results[idx] =
                Some(error.map_or(Ok(()), |error| Err(endpoint_error(error)).context("put")));
        }
        true
    }

    pub(super) fn receive_small_batch(
        &mut self,
        sent: Vec<usize>,
        jobs: &[WorkerJob],
        results: &mut [Option<Result<()>>],
    ) -> Result<bool> {
        let response = self.dst.recv()?;
        let valid = Self::record_small_batch_reply(&sent, response, results);
        // Acknowledgments advance both byte and file activity for the tuner.
        // Confirmed file completion still belongs to the final source check.
        let (bytes, files) = sent
            .iter()
            .filter(|&&idx| matches!(results[idx], Some(Ok(()))))
            .fold((0, 0), |(bytes, files), &idx| {
                (bytes + jobs[idx].entry.size, files + 1)
            });
        if files > 0 {
            self.progress.add_bytes(bytes);
            self.progress.add_tuning_files(files);
        }
        Ok(valid)
    }

    pub(super) fn transfer_small_batches(
        &mut self,
        jobs: &[WorkerJob],
        mut groups: impl Iterator<Item = std::ops::Range<usize>>,
        results: &mut [Option<Result<()>>],
    ) -> Result<()> {
        let window = crate::transfer_tuning::DEFAULT_PIPELINE_DEPTH;
        let mut read_window = if self.src.supports_request_pipelining() {
            window
        } else {
            1
        };
        let write_window = if self.dst.supports_request_pipelining() {
            window
        } else {
            1
        };
        // Connection setup supplies a conservative latency allowance even
        // for SSH, which has no kernel RTT observation. Do not mistake an
        // ordinary WAN response for a stalled source read. Keep the conservative
        // sixteen-RTT allowance; the measured wait now ends when the reply starts,
        // before receiving its remaining payload.
        let source_rtt_us = self.src.tcp_rtt_us().unwrap_or(0);
        let read_stall_budget = self
            .setup_elapsed
            .max(std::time::Duration::from_millis(100))
            .max(std::time::Duration::from_micros(
                source_rtt_us.saturating_mul(16),
            ));
        let mut reads = std::collections::VecDeque::new();
        let mut writes = std::collections::VecDeque::new();
        let result = (|| -> Result<()> {
            'issuing: loop {
                while reads.len() < read_window {
                    let Some(group) = groups.next() else { break };
                    let mut requests = Vec::new();
                    for job in &jobs[group.clone()] {
                        // Empty files need no source access, including mode 000.
                        if job.entry.size > 0 {
                            self.limit(job.entry.size);
                            requests.push(SmallRead {
                                path: job.src.clone(),
                                source: self.source_reference(job),
                                attempt: job.attempt,
                                len: job.entry.size as u32,
                            });
                        }
                    }
                    let count = requests.len();
                    if count > 0 {
                        if let Err(error) = self.src.send(Request::ReadSmallBatch(requests)) {
                            Self::fail_small_batch(results, group.clone(), &error);
                            return Err(error);
                        }
                    }
                    reads.push_back((group.clone(), count));
                }
                let Some((group, count)) = reads.pop_front() else {
                    break;
                };
                let (blocks, waited) = if count == 0 {
                    (Vec::new(), std::time::Duration::ZERO)
                } else {
                    let (response, waited) = self.src.recv_with_wait()?;
                    let blocks =
                        ok(response, "read small batch").and_then(|response| match response {
                            Response::SmallBlocks(blocks) if blocks.len() == count => Ok(blocks),
                            other => bail!("unexpected response {other:?}"),
                        });
                    match blocks {
                        Ok(blocks) => (blocks, waited),
                        Err(error) => {
                            Self::fail_small_batch(results, group, &error);
                            break 'issuing;
                        }
                    }
                };
                if read_window > 1 && waited > read_stall_budget && self.gate.active() > 1 {
                    if debug() {
                        crate::output::diagnostic!(
                            "syq: worker {}: source reply wait {:.3}s exceeded {:.3}s allowance (RTT {}us, setup {:.3}s); draining read-ahead",
                            self.id, waited.as_secs_f64(), read_stall_budget.as_secs_f64(),
                            source_rtt_us, self.setup_elapsed.as_secs_f64()
                        );
                    }
                    // Drain existing read-ahead before claiming more. Unissued
                    // groups stay stealable, so one slow source file cannot
                    // keep a window of further work away from idle peers.
                    // The next logical batch starts with the full window again.
                    read_window = 1;
                }
                let mut blocks = blocks.into_iter();
                let mut puts = Vec::new();
                let mut sent = Vec::new();
                for idx in group {
                    let job = &jobs[idx];
                    let block = if job.entry.size == 0 {
                        Ok(SmallBlock {
                            data: Vec::new(),
                            hash: self.opts.hash_policy.payload_algorithm().hash(&[]),
                        })
                    } else {
                        match blocks.next() {
                            Some(Ok(block)) if block.data.len() as u64 == job.entry.size => {
                                Ok(block)
                            }
                            Some(Ok(_)) => Err(anyhow::anyhow!("block size mismatch on read")),
                            Some(Err(error)) => Err(anyhow::anyhow!("read: {error}")),
                            None => Err(anyhow::anyhow!("missing block in read small batch")),
                        }
                    };
                    let SmallBlock { data, hash } = match block {
                        Ok(block) => block,
                        Err(error) => {
                            results[idx] = Some(Err(error));
                            continue;
                        }
                    };
                    let mut meta = self.opts.metadata_for(&job.rel_bytes, &job.entry);
                    meta.mode = self.create_mode(job);
                    puts.push(SmallPut {
                        path: job.dst.clone(),
                        copy_id: self.copy_id(),
                        data,
                        hash,
                        meta,
                        flags: publication_metadata_flags(self.opts.flags_for(&job.rel_bytes)),
                        inplace: self.opts.inplace,
                        condition: job.target_condition,
                        guard: job.container_guard.clone(),
                    });
                    sent.push(idx);
                }
                if !puts.is_empty() {
                    if let Err(error) = self.dst.send(Request::PutSmallBatch(puts)) {
                        Self::fail_small_batch(results, sent, &error);
                        return Err(error);
                    }
                    writes.push_back(sent);
                }
                if writes.len() >= write_window
                    && !self.receive_small_batch(
                        writes.pop_front().expect("pending batch"),
                        jobs,
                        results,
                    )?
                {
                    break;
                }
            }
            Ok(())
        })();
        // A normal endpoint error consumes its reply. Drain only requests still
        // outstanding; a receive/transport error stops that drain immediately.
        let source_end = (|| {
            while let Some((group, count)) = reads.pop_front() {
                if count > 0 {
                    let response = self.src.recv()?;
                    if let Err(error) = ok(response, "read small batch") {
                        Self::fail_small_batch(results, group, &error);
                    }
                }
            }
            Ok(())
        })();
        let destination_end = (|| {
            while let Some(sent) = writes.pop_front() {
                // A receive error ends draining even if the connection cannot
                // report a dead flag. Endpoint errors consume their reply and
                // belong only to that group; keep later acknowledgments too.
                self.receive_small_batch(sent, jobs, results)?;
            }
            Ok(())
        })();
        result.and(source_end).and(destination_end)
    }

    pub(super) fn fast_batch(&mut self, batch: &mut Vec<usize>) -> Result<()> {
        #[cfg(debug_assertions)]
        crate::fsops::record_test_event(
            "SYQ_TEST_WORKER_EVENTS",
            format_args!("batch {} {}", self.id, batch.len()),
        )?;
        let mut jobs: Vec<WorkerJob> = {
            let all = self.sched.jobs.lock().unwrap();
            batch.iter().map(|&i| all.snapshot(i)).collect()
        };
        self.benchmark.small_batches += 1;
        self.benchmark.max_batch_files = self.benchmark.max_batch_files.max(jobs.len() as u64);
        self.benchmark.max_batch_bytes = self
            .benchmark
            .max_batch_bytes
            .max(jobs.iter().map(|j| j.entry.size).sum());
        // Each group keeps whole files, so publication and per-file hashes
        // are unchanged. Larger batches feed bounded read/write windows rather
        // than reading their entire payload before the first write.
        let group_bytes =
            if self.src.supports_request_pipelining() || self.dst.supports_request_pipelining() {
                // Return the first group before collecting a full read window.
                FAST_BATCH_READ_BYTES / crate::transfer_tuning::DEFAULT_PIPELINE_DEPTH as u64
            } else {
                // Both calls run synchronously: splitting cannot overlap work.
                u64::MAX
            };
        let mut groups = Vec::new();
        let mut start = 0;
        let mut bytes = 0u64;
        let mut path_bytes = 0usize;
        for (i, job) in jobs.iter().enumerate() {
            let source_bytes = source_request_bytes(&job.src, Some(&job.source));
            if i > start
                && (bytes.saturating_add(job.entry.size) > group_bytes
                    || path_bytes.saturating_add(source_bytes) > SOURCE_BATCH_PATH_BYTES)
            {
                groups.push(start..i);
                start = i;
                bytes = 0;
                path_bytes = 0;
            }
            bytes += job.entry.size;
            path_bytes = path_bytes.saturating_add(source_bytes);
        }
        if start < jobs.len() {
            groups.push(start..jobs.len());
        }
        let (first, shared) = self.sched.share_fast_groups(
            jobs.iter()
                .zip(batch.iter())
                .map(|(job, &idx)| (job.entry.size, idx))
                .collect(),
            groups.into(),
        );
        let groups =
            std::iter::once(first).chain(std::iter::from_fn(|| shared.lock().unwrap().claim()));
        // None means no destination result: an unissued group or a read
        // drained after another group's error is still safe to requeue.
        let mut results = (0..jobs.len()).map(|_| None).collect::<Vec<_>>();
        let result = self.transfer_small_batches(&jobs, groups, &mut results);
        let owned = self.sched.finish_fast_groups(&shared);
        // Fix the caller's ownership even on transport loss, before its retry
        // loop can requeue files that another worker has already taken.
        let mut keep = owned.iter();
        batch.retain(|_| *keep.next().unwrap());
        let mut keep = owned.iter();
        jobs.retain(|_| *keep.next().unwrap());
        let results: Vec<_> = results
            .into_iter()
            .zip(owned)
            .filter_map(|(result, own)| own.then_some(result))
            .collect();
        let (credited, credited_files) = jobs
            .iter()
            .zip(&results)
            .filter(|(_, result)| matches!(result, Some(Ok(()))))
            .fold((0, 0), |(bytes, files), (job, _)| {
                (bytes + job.entry.size, files + 1)
            });
        if let Err(error) = result {
            self.progress.bytes_done.fetch_sub(credited, Relaxed);
            self.progress.undo_tuning_files(credited_files);
            return Err(error);
        }
        // Recheck only acknowledged successes. Later errors must not discard
        // them or make us inspect groups this worker never published.
        let successful = jobs
            .iter()
            .zip(&results)
            .filter_map(|(job, result)| matches!(result, Some(Ok(()))).then_some(job));
        let paths = successful
            .clone()
            .map(|job| job.src.clone())
            .collect::<Vec<_>>();
        let registered = successful.map(|job| job.source.clone()).collect();
        let now = if paths.is_empty() {
            Vec::new()
        } else {
            match stat_many_registered(&mut *self.src, paths, Some(registered), false) {
                Ok(now) => now,
                Err(error) => {
                    self.progress.bytes_done.fetch_sub(credited, Relaxed);
                    self.progress.undo_tuning_files(credited_files);
                    return Err(error);
                }
            }
        };
        let mut now = now.into_iter();
        for ((idx, j), res) in batch.iter().zip(jobs.iter()).zip(results) {
            let Some(res) = res else {
                self.sched.requeue(*idx);
                continue;
            };
            if let Err(e) = res {
                let os_kind = os_kind_of(&e);
                let message = format!("{e:#}");
                self.progress.error_classified(
                    &format!("syq: {}: {message}", j.rel),
                    Some("io"),
                    os_kind,
                );
                self.emit_file_result_failed(j, "unknown", os_kind, &message);
                self.sched.fail_file(*idx);
                if capacity_os_kind(os_kind) {
                    self.sched.abort();
                }
                continue;
            }
            let now = now.next().expect("rechecked acknowledged file");
            let changed = match &now {
                Some(e) => {
                    e.kind != Kind::File
                        || e.size != j.entry.size
                        || e.mtime != j.entry.mtime
                        || e.mtime_nsec != j.entry.mtime_nsec
                }
                None => true,
            };
            if changed {
                self.progress.bytes_done.fetch_sub(j.entry.size, Relaxed);
                self.progress.undo_tuning_files(1);
                if let (Some(e), true, true) = (
                    now,
                    j.attempt + 1 < MAX_ATTEMPTS,
                    j.target_condition == TargetCondition::Any,
                ) {
                    if !self.opts.quiet {
                        self.progress.eprintln(&format!(
                            "syq: {}: changed during transfer, retrying",
                            j.rel
                        ));
                    }
                    let published = self.published_entry(j);
                    let mut all = self.sched.jobs.lock().unwrap();
                    let job = &mut all[*idx];
                    self.progress.bytes_total.fetch_add(e.size, Relaxed);
                    job.entry = Entry {
                        path: job.entry.path.clone(),
                        ..e
                    };
                    job.attempt += 1;
                    all.set_destination(*idx, published);
                    drop(all);
                    self.sched.requeue(*idx);
                } else {
                    self.progress.error(&format!(
                        "syq: {}: source changed during transfer (or vanished)",
                        j.rel
                    ));
                    self.emit_file_result_failed(
                        j,
                        "yes",
                        None,
                        "source changed during transfer (or vanished)",
                    );
                    self.sched.fail_file(*idx);
                }
                continue;
            }
            j.done.store(j.entry.size, Relaxed);
            // Already counted for tuning when the destination acknowledged it.
            self.progress.files_done.fetch_add(1, Relaxed);
            if let Some(results) = self.progress.results_writer() {
                results.emit_operation(&crate::results::OperationRecord {
                    action: "transfer_file",
                    dst: &j.rel_bytes,
                    src: j.src_rel.as_deref(),
                    kind: "file",
                    disposition: "succeeded",
                    bytes: Some(j.entry.size),
                    attempts: Some(u64::from(j.attempt) + 1),
                    retryable: None,
                    class: None,
                    os_kind: None,
                    message: None,
                });
            }
            if self.opts.verbose > 0 {
                self.progress.println(&j.rel);
            }
        }
        Ok(())
    }

    pub(super) fn file_error(&mut self, idx: usize, e: anyhow::Error) -> Result<()> {
        // Range validation can leave pipelined source replies and destination
        // acknowledgments unread. End this worker and abort the copy; neither
        // connection may serve another job or enter transport recovery.
        if e.is::<RangeReplyMismatch>() || self.transport_dead() {
            return Err(e);
        }
        if self.sched.fail_file(idx) {
            let job = self.job(idx);
            let os_kind = os_kind_of(&e);
            let message = format!("{e:#}");
            self.progress.error_classified(
                &format!("syq: {}: {message}", job.rel),
                Some("io"),
                os_kind,
            );
            self.emit_file_result_failed(&job, "unknown", os_kind, &message);
            if capacity_os_kind(os_kind) {
                self.sched.abort();
            }
        }
        Ok(())
    }

    /// One failed-transfer result record; the error itself was already
    /// counted and printed by the caller.
    pub(super) fn emit_file_result_failed(
        &self,
        job: &WorkerJob,
        retryable: &'static str,
        os_kind: Option<&'static str>,
        message: &str,
    ) {
        // Verification reports differences and inspection failures as errors,
        // never as a transfer operation that could be mistaken for a write.
        if self.opts.dry_run {
            return;
        }
        if let Some(results) = self.progress.results_writer() {
            results.emit_operation_expected(
                &crate::results::OperationRecord {
                    action: "transfer_file",
                    dst: &job.rel_bytes,
                    src: job.src_rel.as_deref(),
                    kind: "file",
                    disposition: "failed",
                    bytes: None,
                    attempts: Some(u64::from(job.attempt) + 1),
                    retryable: Some(retryable),
                    class: Some("io"),
                    os_kind,
                    message: Some(message),
                },
                self.opts.expected_for(&job.rel_bytes),
            );
        }
    }

    pub(super) fn job(&self, idx: usize) -> WorkerJob {
        self.sched.jobs.lock().unwrap().snapshot(idx)
    }

    pub(super) fn handle_file(&mut self, idx: usize) -> Result<()> {
        let job = self.job(idx);
        let size = job.entry.size;
        let opts = self.opts.clone();
        let _ = &opts;

        match self.try_expected_match(&job) {
            Ok(true) => {
                job.done.store(size, Relaxed);
                self.progress.bytes_unchanged.fetch_add(size, Relaxed);
                self.progress.bytes_total.fetch_sub(size, Relaxed);
                self.sched.ranges_ready(idx, vec![]);
                if let Err(error) = self.finish_matched_file(idx) {
                    if self.transport_dead() {
                        self.sched.requeue_finish(idx, true);
                    }
                    return Err(error);
                }
                return Ok(());
            }
            Ok(false) => {}
            Err(error) => {
                self.sched.ranges_ready(idx, vec![]);
                if self.transport_dead() {
                    self.sched.requeue(idx);
                }
                return Err(error);
            }
        }

        // Placement guards must be enforced by the final mutation. Stage even
        // an explicit --inplace transfer until that checked update; an
        // existing target is still updated through its held inode at finalize.
        let inplace = job.inplace;
        // Same-machine copy: let the receiver move the bytes directly (kernel
        // offload, or an eligible sequential userspace writer) instead of
        // framing, hashing and scheduling them through the transport.
        // copy_file_range cannot be paced, so a limited same-machine transfer
        // uses the regular userspace path (also useful for mounted NFS paths).
        if self
            .opts
            .copy_policy(self.bwlimit.is_some())
            .file_operation(job.entry.size, job.container_guard.is_some())
            == crate::copy_policy::FileOperation::ReceiverCopy
        {
            match self.try_copy_local(idx, &job) {
                Ok(true) => {
                    self.sched.ranges_ready(idx, vec![]);
                    return Ok(());
                }
                Ok(false) => {
                    // The one-worker automatic start was only a cheap direct
                    // copy probe. Restore the normal local worker count before
                    // exposing userspace ranges for an unsupported offload.
                    self.sched.request_direct_fallback();
                }
                Err(e) => {
                    self.sched.ranges_ready(idx, vec![]);
                    if self.transport_dead() {
                        // try_copy_local queues publication recovery after it
                        // has credited the completed kernel copy. Earlier
                        // connection failures still need the whole probe.
                        if job.done.load(Relaxed) < job.entry.size {
                            self.sched.requeue(idx);
                        }
                    }
                    return Err(e);
                }
            }
        }
        // bool = a staged or in-place file still needs Finalize. A verified
        // content match applies metadata through its retained basis fd instead.
        let planned: Result<(Vec<(u64, u64)>, bool)> = (|| {
            let final_entry = job.dst_entry.as_deref();
            if let Some(f) = &final_entry {
                if f.kind == Kind::Dir {
                    bail!("destination is a directory");
                }
            }
            let final_is_file = final_entry.as_ref().is_some_and(|f| f.kind == Kind::File);
            let full = || if size > 0 { vec![(0, size)] } else { vec![] };
            // Unless --inplace was explicit, changed files are published
            // through a sidecar + atomic rename. Small new files normally take
            // the batched small-file path instead of reaching this worker path.

            // One receiver turn now both observes resumable state and prepares
            // it. When a final-file basis exists, leave an absent sidecar
            // absent until the content comparison shows a difference.
            let prepared = match ok(
                self.dst.call(Request::Prepare {
                    path: job.dst.clone(),
                    size,
                    inplace,
                    copy_id: self.copy_id(),
                    mode: self.create_mode(&job),
                    attempt: job.attempt,
                    create_if_missing: inplace || !final_is_file,
                    guard: job.container_guard.clone(),
                })?,
                "prepare",
            )? {
                Response::Prepared(prepared) => prepared,
                other => bail!("unexpected response {other:?}"),
            };

            if prepared.partial_size.is_some() || prepared.has_candidates || final_is_file {
                self.sched.request_direct_fallback();
            }
            if inplace {
                if final_is_file && size > 0 {
                    return Ok((self.diff_blocks(&job, Which::Final)?, true));
                }
                return Ok((full(), true));
            }
            // A retry's own output must be finished (and thus consumed), even
            // if another copy has meanwhile published identical final bytes.
            if prepared.partial_size.is_some() {
                if size == 0 {
                    return Ok((vec![], true));
                }
                return Ok((self.diff_blocks(&job, Which::Partial)?, true));
            }
            if final_is_file {
                let diff = self.diff_final_and_hold(&job)?;
                if diff.ranges.is_empty() && diff.held_len == Some(size) {
                    let mut meta = self.opts.metadata_for(&job.rel_bytes, &job.entry);
                    meta.mode = self.create_mode(&job);
                    ok(
                        self.dst.call(Request::FinishBasis {
                            expected_hash: self.opts.expected_for(&job.rel_bytes).cloned(),
                            path: job.dst.clone(),
                            copy_id: self.copy_id(),
                            meta,
                            flags: publication_metadata_flags(self.opts.flags_for(&job.rel_bytes)),
                            condition: job.target_condition,
                            guard: job.container_guard.clone(),
                        })?,
                        "finish content-identical destination",
                    )?;
                    return Ok((vec![], false));
                }
                return Ok((
                    self.reuse_blocks(&job, diff.source_hashes, &diff.ranges)?,
                    true,
                ));
            }
            if prepared.has_candidates {
                return Ok((self.diff_blocks(&job, Which::Partial)?, true));
            }
            Ok((full(), true))
        })();

        let (ranges, needs_finalize) = match planned {
            Ok(result) => result,
            Err(e) => {
                self.sched.ranges_ready(idx, vec![]);
                if self.transport_dead() {
                    self.sched.requeue(idx);
                }
                return Err(e);
            }
        };
        let to_send: u64 = ranges.iter().map(|(o, e)| e - o).sum();
        job.done.store(size - to_send, Relaxed);
        self.progress
            .bytes_unchanged
            .fetch_add(size - to_send, Relaxed);
        self.progress.bytes_total.fetch_sub(size - to_send, Relaxed);
        match self.sched.ranges_ready(idx, ranges) {
            Some(h) => {
                let start = h.lock().unwrap().pos;
                let mut credited = 0;
                let res = self.transfer_range(&h, &mut credited);
                if let Err(e) = res {
                    if self.transport_dead() {
                        self.retry_credited_range(&h, start, credited);
                        return Err(e);
                    }
                    self.file_error(idx, e)?;
                    self.sched.range_done(&h);
                    return Ok(());
                }
                if self.sched.range_done(&h) {
                    if let Err(e) = self.finish_file(idx) {
                        if self.transport_dead() {
                            self.sched.requeue_finish(idx, false);
                        }
                        return Err(e);
                    }
                }
            }
            None if needs_finalize => {
                if let Err(e) = self.finish_file(idx) {
                    if self.transport_dead() {
                        self.sched.requeue_finish(idx, false);
                    }
                    return Err(e);
                }
            }
            None => {
                if let Err(e) = self.finish_matched_file(idx) {
                    if self.transport_dead() {
                        self.sched.requeue_finish(idx, true);
                    }
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    /// Attempt a receiver-side same-host copy. Ok(true) = done; Ok(false) =
    /// receiver cannot use its direct path, so the caller should stream;
    /// Err = real failure.
    /// The caller owns scheduler probing bookkeeping for every terminal result.
    pub(super) fn try_copy_local(&mut self, idx: usize, job: &WorkerJob) -> Result<bool> {
        // Write to a partial and let finish_file rename it, so an interrupted
        // A receiver-side copy never leaves a final-named file the quick check
        // could mistake for complete. Only --inplace writes the final path
        // directly.
        let inplace = job.inplace;
        let mode = self.create_mode(job);
        // Keep range parallelism for a single-file copy. Read the planned
        // file count before the RPC so no scheduler lock spans the copy.
        let allow_sequential_local_fallback = self.sched.jobs.lock().unwrap().len() > 1;
        let resp = self.dst.call(Request::CopyLocal {
            source: job.source.clone(),
            dst: job.dst.clone(),
            inplace,
            allow_sequential_nfs_fallback: self.opts.allow_sequential_nfs_fallback,
            allow_sequential_local_fallback,
            copy_id: self.copy_id(),
            size: job.entry.size,
            mode,
        })?;
        match resp {
            Response::Ok => {
                self.benchmark.local_whole_files += 1;
                self.progress.add_bytes(job.entry.size);
                job.done.store(job.entry.size, Relaxed);
                if let Err(e) = self.finish_file(idx) {
                    if self.transport_dead() {
                        self.sched.requeue_finish(idx, false);
                    }
                    return Err(e);
                }
                Ok(true)
            }
            Response::CopyLocalUnsupported => Ok(false),
            Response::EndpointError(error) => Err(endpoint_error(error)),
            Response::Err(e) => bail!("{e}"),
            other => bail!("unexpected response {other:?}"),
        }
    }

    /// Mode a new destination file is created with (what finalize will want).
    /// The mode the finished file should have (rsync semantics):
    /// with -p the source mode; without -p an existing file keeps its own mode
    /// and a new file gets the source mode minus the umask.
    pub(super) fn create_mode(&self, job: &WorkerJob) -> u32 {
        if let Some(mode) = self
            .opts
            .mapping_metadata
            .get(&job.rel_bytes)
            .and_then(|m| m.mode)
        {
            return mode;
        }
        match job.dst_entry.as_ref().filter(|d| d.kind == Kind::File) {
            Some(d) if !self.opts.perms => d.mode & 0o7777,
            _ => fresh_file_mode(&self.opts, &job.entry),
        }
    }

    pub(super) fn copy_id(&self) -> CopyId {
        self.opts.copy_id
    }

    /// Metadata for the whole file just atomically published at the
    /// destination. A retry can use it as a block-diff basis without changing
    /// the no-`-p` mode chosen for the first attempt.
    pub(super) fn published_entry(&self, job: &WorkerJob) -> Entry {
        let mut entry = job.entry.clone();
        entry.path = job.dst.clone();
        let meta = self.opts.metadata_for(&job.rel_bytes, &job.entry);
        entry.mode = (entry.mode & !0o7777) | self.create_mode(job);
        entry.uid = meta.uid;
        entry.gid = meta.gid;
        entry.mtime = meta.mtime;
        entry.mtime_nsec = meta.mtime_nsec;
        entry
    }

    /// Hash blocks on both sides (in parallel) and return the ranges that differ.
    pub(super) fn diff_blocks(&mut self, job: &WorkerJob, which: Which) -> Result<Vec<(u64, u64)>> {
        if which == Which::Partial {
            return self
                .diff_with(
                    job,
                    self.seed_request(job, None),
                    "seed and hash destination",
                )
                .map(|diff| diff.ranges);
        }
        self.diff_with(
            job,
            Request::HashBlocks {
                path: job.dst.clone(),
                source: None,
                which,
                copy_id: self.copy_id(),
                block: self.opts.block,
                len: job.entry.size,
                attempt: job.attempt,
                guard: None,
            },
            "hash destination",
        )
        .map(|diff| diff.ranges)
    }

    pub(super) fn reuse_blocks(
        &mut self,
        job: &WorkerJob,
        hashes: Vec<ContentDigest>,
        different: &[(u64, u64)],
    ) -> Result<Vec<(u64, u64)>> {
        let mut matching = Vec::new();
        let mut pos = 0;
        for &(start, end) in different {
            if pos < start {
                matching.push((pos, start));
            }
            pos = end;
        }
        if pos < job.entry.size {
            matching.push((pos, job.entry.size));
        }
        let response = self
            .dst
            .call(self.seed_request(job, Some(matching.clone())))?;
        let Response::SeededBasis(reused) = ok(response, "reuse destination blocks")? else {
            bail!("destination did not return seeded block hashes");
        };
        Self::different_seeded_ranges(&hashes, &reused, &matching, self.opts.block, job.entry.size)
    }

    pub(super) fn different_seeded_ranges(
        source: &[ContentDigest],
        reused: &SeededBasis,
        matching: &[(u64, u64)],
        block: u64,
        size: u64,
    ) -> Result<Vec<(u64, u64)>> {
        if !reused.selected_final {
            // Interrupted and retry copies remain independent donors, even
            // where the final file's blocks differed from the source.
            return Ok(Self::different_ranges(source, &reused.hashes, block, size));
        }
        let indices = || {
            matching.iter().flat_map(|&(start, end)| {
                (start / block..end.div_ceil(block)).map(|index| index as usize)
            })
        };
        ensure!(
            reused.hashes.len() as u64
                <= matching
                    .iter()
                    .map(|(start, end)| (end - start).div_ceil(block))
                    .sum::<u64>(),
            "too many seeded block hashes"
        );
        Ok(Self::different_ranges_at(
            source,
            indices().zip(&reused.hashes),
            block,
            size,
        ))
    }

    pub(super) fn seed_request(
        &self,
        job: &WorkerJob,
        final_ranges: Option<Vec<(u64, u64)>>,
    ) -> Request {
        Request::SeedBasis {
            path: job.dst.clone(),
            copy_id: self.copy_id(),
            len: job.entry.size,
            block: self.opts.block,
            final_ranges,
            attempt: job.attempt,
            guard: job.container_guard.clone(),
        }
    }

    /// Compare the source with one opened final-file inode retained by the
    /// receiver for either metadata-only completion or sidecar seeding.
    pub(super) fn diff_final_and_hold(&mut self, job: &WorkerJob) -> Result<BlockDiff> {
        let diff = self.diff_with(
            job,
            Request::HashAndHold {
                path: job.dst.clone(),
                copy_id: self.copy_id(),
                block: self.opts.block,
                len: job.entry.size,
                condition: job.target_condition,
                guard: job.container_guard.clone(),
            },
            "hash and retain destination basis",
        )?;
        diff.held_len
            .context("destination did not report its retained basis length")?;
        Ok(diff)
    }

    pub(super) fn diff_with(
        &mut self,
        job: &WorkerJob,
        destination_request: Request,
        destination_label: &str,
    ) -> Result<BlockDiff> {
        let block = self.opts.block;
        let size = job.entry.size;
        self.src.send(Request::HashBlocks {
            path: job.src.clone(),
            source: self.source_reference(job),
            which: Which::Final,
            copy_id: self.copy_id(),
            block,
            len: size,
            attempt: job.attempt,
            guard: None,
        })?;
        self.dst.send(destination_request)?;
        // Both requests are in flight. Always consume both responses before
        // interpreting either one so an ordinary endpoint error cannot leave
        // this reusable worker connection one response behind.
        let source_response = self.src.recv();
        let destination_response = self.dst.recv();
        let source = Self::hashes(ok(source_response?, "hash source")?)?;
        let (destination, held_len) =
            Self::destination_hashes(ok(destination_response?, destination_label)?)?;
        Ok(BlockDiff {
            ranges: Self::different_ranges(&source, &destination, block, size),
            source_hashes: source,
            held_len,
        })
    }

    pub(super) fn hashes(response: Response) -> Result<Vec<ContentDigest>> {
        match response {
            Response::Hashes(hashes) => Ok(hashes),
            other => bail!("unexpected response {other:?}"),
        }
    }

    pub(super) fn destination_hashes(
        response: Response,
    ) -> Result<(Vec<ContentDigest>, Option<u64>)> {
        match response {
            Response::Hashes(hashes) => Ok((hashes, None)),
            Response::HeldHashes { hashes, len } => Ok((hashes, Some(len))),
            Response::SeededBasis(SeededBasis {
                hashes,
                selected_final: false,
            }) => Ok((hashes, None)),
            other => bail!("unexpected response {other:?}"),
        }
    }

    pub(super) fn different_ranges(
        source: &[ContentDigest],
        destination: &[ContentDigest],
        block: u64,
        size: u64,
    ) -> Vec<(u64, u64)> {
        Self::different_ranges_at(source, destination.iter().enumerate(), block, size)
    }

    pub(super) fn different_ranges_at<'a>(
        source: &[ContentDigest],
        destination: impl Iterator<Item = (usize, &'a ContentDigest)>,
        block: u64,
        size: u64,
    ) -> Vec<(u64, u64)> {
        let mut destination = destination.peekable();
        let n = size.div_ceil(block) as usize;
        let mut ranges: Vec<(u64, u64)> = Vec::new();
        for i in 0..n {
            let same = destination
                .next_if(|(index, _)| *index == i)
                .is_some_and(|(_, hash)| source.get(i) == Some(hash));
            if same {
                continue;
            }
            let off = i as u64 * block;
            let end = (off + block).min(size);
            match ranges.last_mut() {
                Some(last) if last.1 == off => last.1 = end,
                _ => ranges.push((off, end)),
            }
        }
        ranges
    }

    pub(super) fn transfer_range(&mut self, h: &RangeHandle, credited: &mut u64) -> Result<()> {
        let bytes = {
            let range = h.lock().unwrap();
            range.end - range.pos
        };
        if self
            .opts
            .tuning
            .stream_range(self.opts.same_host, bytes, self.transfer_block())
        {
            return self.transfer_streaming_range(h, credited);
        }
        let idx = {
            let g = h.lock().unwrap();
            g.idx
        };
        let job = self.job(idx);
        if self.sched.is_failed(idx) {
            return Ok(());
        }

        let block = self.transfer_block();
        let read_window = if self.src.supports_request_pipelining() {
            self.opts.tuning.pipeline_depth()
        } else {
            1
        };
        let write_window = if self.dst.supports_request_pipelining() {
            self.opts.tuning.pipeline_depth()
        } else {
            1
        };
        self.transfer_range_pipeline(&job, h, credited, block, read_window, write_window)
    }

    pub(super) fn acknowledge_range_write(
        sched: &Sched,
        progress: &Progress,
        job: &WorkerJob,
        flights: &mut [Option<RangeFlight>],
        slot: usize,
        n: u64,
    ) {
        let flight = flights[slot].as_mut().expect("pending range write");
        flight.pending -= 1;
        flight.credited += n;
        progress.add_bytes(n);
        job.done.fetch_add(n, Relaxed);
        if slot != 0 && flight.pending == 0 && {
            let range = flight.handle.lock().unwrap();
            range.pos == range.end
        } {
            // The primary share remains owned by our caller until the whole
            // pipeline drains. Acknowledged extras can retire immediately.
            let done = sched.range_done(&flight.handle);
            debug_assert!(!done);
            flights[slot] = None;
        }
    }

    pub(super) fn transfer_range_pipeline(
        &mut self,
        job: &WorkerJob,
        primary: &RangeHandle,
        credited: &mut u64,
        block: u64,
        read_window: usize,
        write_window: usize,
    ) -> Result<()> {
        let (idx, mut current) = {
            let range = primary.lock().unwrap();
            (range.idx, (range.pos < range.end).then_some(0))
        };
        let mut flights = vec![Some(RangeFlight::new(primary.clone()))];
        let mut pending_reads = std::collections::VecDeque::new();
        let mut pending_writes = std::collections::VecDeque::new();
        let max_range = self
            .opts
            .tuning
            .ordinary_range_limit(self.opts.same_host, block);
        let mut released = false;
        let result = (|| -> Result<()> {
            loop {
                released |= !self.gate.allowed(self.id);
                // Check cancellation and optionally claim work with one scheduler
                // lock, including while the last read replies are draining.
                let claim = (!released && current.is_none() && pending_reads.len() < read_window)
                    .then_some(max_range);
                let mut next = match self.sched.range_work(idx, claim) {
                    RangeWork::Cancelled => break,
                    RangeWork::Ready(next) => next,
                };
                if released {
                    // Only the current range can have an unread suffix. Never
                    // reserve a batch of unread ranges from a synchronous source.
                    if let Some(slot) = current.take() {
                        let flight = flights[slot].as_ref().expect("readable range");
                        self.sched.release_rest(&flight.handle);
                    }
                }
                while !released && pending_reads.len() < read_window {
                    if current.is_none() {
                        // Claim only when there is room to issue a read now.
                        // Larger ranges retain their streaming selection, and
                        // a small backlog stays available to peer workers.
                        let Some(handle) = next.take() else {
                            break;
                        };
                        let slot = flights
                            .iter()
                            .position(Option::is_none)
                            .unwrap_or(flights.len());
                        let flight = Some(RangeFlight::new(handle));
                        if slot == flights.len() {
                            flights.push(flight);
                        } else {
                            flights[slot] = flight;
                        }
                        current = Some(slot);
                    }
                    let slot = current.expect("readable range");
                    let flight = flights[slot].as_mut().expect("readable range");
                    let (off, n) = {
                        let mut range = flight.handle.lock().unwrap();
                        let n = (range.end - range.pos).min(block);
                        let off = range.pos;
                        range.pos += n;
                        if range.pos == range.end {
                            current = None;
                        }
                        (off, n)
                    };
                    flight.pending += 1;
                    self.limit(n);
                    self.src.send(Request::ReadRange {
                        path: job.src.clone(),
                        source: self.source_reference(job),
                        attempt: job.attempt,
                        off,
                        len: n as u32,
                    })?;
                    self.benchmark.range_requests += 1;
                    self.benchmark.max_request_bytes = self.benchmark.max_request_bytes.max(n);
                    pending_reads.push_back((slot, off, n));
                    if current.is_none() && pending_reads.len() < read_window {
                        next = self.sched.take_short_range(idx, max_range);
                    }
                }
                let Some((slot, expected_off, expected_len)) = pending_reads.pop_front() else {
                    break;
                };

                let response = self.src.recv();
                let (off, hash, data) = match ok(response?, "read")? {
                    Response::Block { off, hash, data } => (off, hash, data),
                    other => bail!("unexpected response {other:?}"),
                };
                validate_range_reply(expected_off, expected_len, off, data.len())?;
                let n = data.len() as u64;
                self.dst.send(Request::WriteRange {
                    path: job.dst.clone(),
                    inplace: job.inplace,
                    copy_id: self.copy_id(),
                    attempt: job.attempt,
                    off,
                    hash,
                    data,
                    guard: job.container_guard.clone(),
                })?;
                pending_writes.push_back((slot, n));
                if pending_writes.len() >= write_window {
                    let (slot, n) = pending_writes.pop_front().expect("pending write");

                    let response = self.dst.recv();
                    ok(response?, "write")?;
                    Self::acknowledge_range_write(
                        &self.sched,
                        &self.progress,
                        job,
                        &mut flights,
                        slot,
                        n,
                    );
                }
            }
            Ok(())
        })();
        let malformed = result
            .as_ref()
            .is_err_and(|error| error.is::<RangeReplyMismatch>());
        let result = if malformed {
            // Fail closed: never drain or reuse a malformed source's connection.
            result
        } else {
            let source_end =
                crate::conn::drain_range_replies(&mut *self.src, pending_reads.len(), "read");

            let destination_end = crate::conn::drain_range_replies_with(
                &mut *self.dst,
                pending_writes,
                "write",
                |(slot, n)| {
                    Self::acknowledge_range_write(
                        &self.sched,
                        &self.progress,
                        job,
                        &mut flights,
                        slot,
                        n,
                    );
                },
            );
            result.and(source_end).and(destination_end)
        };
        *credited += flights[0].as_ref().expect("primary share").credited;
        for flight in flights.into_iter().skip(1).flatten() {
            if result.is_err() && self.transport_dead() {
                // Roll back before publishing retry work: another worker may
                // immediately transfer and credit these bytes again.
                self.retry_credited_range(&flight.handle, flight.start, flight.credited);
            } else {
                let done = self.sched.range_done(&flight.handle);
                debug_assert!(!done);
            }
        }
        result
    }

    pub(super) fn transfer_streaming_range(
        &mut self,
        h: &RangeHandle,
        credited: &mut u64,
    ) -> Result<()> {
        let (idx, start, end) = {
            let range = h.lock().unwrap();
            (range.idx, range.pos, range.end)
        };
        if start == end || self.sched.is_failed(idx) {
            return Ok(());
        }
        let job = self.job(idx);
        let block = self.opts.tuning.streaming_request_size(
            self.opts.block,
            self.bwlimit.as_deref(),
            self.opts.restricted_receiver,
        );
        // Do not advance the scheduler's claimed position when opening the
        // stream. Other workers may still steal the unread suffix. At a split
        // we notify the source at the next consumer block boundary, then
        // stop/drain after consuming our prefix. Queued frames can still arrive.
        let stream = ReadStreamRequest {
            path: job.src.clone(),
            source: self.source_reference(&job),
            attempt: job.attempt,
            off: start,
            end,
            block: block as u32,
        };
        stream.validate()?;
        match ok(
            self.src.call(Request::ReadStream(stream))?,
            "start read stream",
        )? {
            Response::Ok => {}
            _ => bail!("unexpected response starting read stream"),
        }
        self.benchmark.streaming_ranges += 1;
        let begin = self.dst.begin_streaming_writes();
        if let Err(error) = begin {
            let _ = self.src.stop_read_stream();
            return Err(error);
        }
        let mut sent = 0;
        let result = (|| -> Result<()> {
            let mut expected = start;
            let mut announced_end = end;
            loop {
                if !self.gate.allowed(self.id)
                    || self.sched.is_failed(idx)
                    || self.sched.is_aborted()
                {
                    self.sched.release_rest(h);
                }
                {
                    let range = h.lock().unwrap();
                    if range.pos == range.end {
                        break;
                    }
                }
                if crate::streaming::notify_shrunk_range(h, &mut announced_end, &mut *self.src)? {
                    self.benchmark.stream_shrink_requests += 1;
                }
                self.dst.check_streaming_writes()?;
                let (off, mut hash, mut data) = match ok(self.src.recv()?, "read stream")? {
                    Response::Block { off, hash, data } => (off, hash, data),
                    _ => bail!("unexpected response in read stream"),
                };
                let requested = (end - expected).min(block);
                validate_range_reply(expected, requested, off, data.len())?;
                expected += requested;
                let policy = self.opts.hash_policy;
                if !policy.transfer_integrity {
                    hash = [0; 32];
                }
                let claimed = crate::streaming::claim_block_with_digest(
                    h,
                    off,
                    &mut hash,
                    &mut data,
                    |data| {
                        if policy.transfer_integrity {
                            policy.payload_algorithm().hash(data)
                        } else {
                            [0; 32]
                        }
                    },
                )?;
                self.benchmark.stream_discarded_bytes += requested - claimed;
                if claimed == 0 {
                    break;
                }
                self.limit(claimed);
                self.dst.send(Request::WriteRange {
                    path: job.dst.clone(),
                    inplace: job.inplace,
                    copy_id: self.copy_id(),
                    attempt: job.attempt,
                    off,
                    hash,
                    data,
                    guard: job.container_guard.clone(),
                })?;
                sent += 1;
                self.benchmark.streamed_blocks += 1;
                self.benchmark.max_request_bytes = self.benchmark.max_request_bytes.max(claimed);
                self.progress.add_bytes(claimed);
                job.done.fetch_add(claimed, Relaxed);
                *credited += claimed;
            }
            Ok(())
        })();
        if result
            .as_ref()
            .is_err_and(|error| error.is::<RangeReplyMismatch>())
        {
            // As with ordinary ranges, do not wait for more messages from a
            // source that violated the protocol. Dropping the connections
            // cancels the collector; the caller aborts rather than reconnects.
            return result;
        }
        // Always restore both protocol boundaries, even after a local write
        // error. No following file can consume this one's data or late errors.
        let (source_end, destination_end, _destination_wait) =
            crate::streaming::finish_range(&mut *self.src, &mut *self.dst, sent);
        let source_end = source_end.map(|discarded| {
            self.benchmark.stream_discarded_bytes += discarded;
        });
        result.and(source_end).and(destination_end)
    }

    pub(super) fn retry_credited_range(&self, handle: &RangeHandle, start: u64, credited: u64) {
        // Remove uncertain credit before making work visible to another worker.
        let idx = handle.lock().unwrap().idx;
        self.undo_progress(idx, credited);
        self.sched.retry_range(handle, start);
    }

    pub(super) fn undo_progress(&self, idx: usize, credited: u64) {
        if credited == 0 {
            return;
        }
        self.progress.bytes_done.fetch_sub(credited, Relaxed);
        self.sched.jobs.lock().unwrap()[idx]
            .done
            .fetch_sub(credited, Relaxed);
    }

    pub(super) fn transfer_block(&self) -> u64 {
        self.opts.tuning.request_size(
            self.opts.block,
            self.bwlimit.as_deref(),
            self.opts.restricted_receiver,
        )
    }

    pub(super) fn limit(&self, bytes: u64) {
        if let Some(limit) = &self.bwlimit {
            let _pacing = self
                .observation
                .as_ref()
                .map(|a| a.span(crate::transfer_observations::Stage::Pacing));
            if self.opts.tuning.bw_pacing == Some(crate::transfer_tuning::BwPacing::Average) {
                limit.wait_prepaid(bytes);
            } else {
                limit.wait(bytes);
            }
        }
    }

    pub(super) fn finish_file(&mut self, idx: usize) -> Result<()> {
        if self.sched.is_failed(idx) || self.sched.is_aborted() {
            return Ok(());
        }
        let job = self.job(idx);
        if job.done.load(Relaxed) != job.entry.size {
            bail!("refusing to publish an incomplete file");
        }
        let mut meta = self.opts.metadata_for(&job.rel_bytes, &job.entry);
        meta.mode = self.create_mode(&job);
        let finalized = ok(
            self.dst.call(Request::Finalize {
                expected_hash: self.opts.expected_for(&job.rel_bytes).cloned(),
                path: job.dst.clone(),
                inplace: job.inplace,
                copy_id: self.copy_id(),
                meta,
                flags: publication_metadata_flags(self.opts.flags_for(&job.rel_bytes)),
                condition: job.target_condition,
                guard: job.container_guard.clone(),
            })?,
            "finalize destination",
        );
        if let Err(error) = finalized {
            if self.transport_dead() || job.inplace {
                return Err(error);
            }
            // If the response to a previous Finalize was lost, its sidecar is
            // gone because publication already happened. Verify the final
            // bytes before treating the retry as successful; if a sidecar is
            // still present, preserve the real metadata/publication error.
            let partial_missing = match ok(
                self.dst.call(Request::ProbePartial {
                    path: job.dst.clone(),
                    copy_id: self.copy_id(),
                    guard: None,
                })?,
                "probe partial after finalize",
            )? {
                Response::PartialSize(size) => size.is_none(),
                other => bail!("unexpected response {other:?}"),
            };
            if !partial_missing || !self.contents_match(&job)? {
                return Err(error);
            }
            self.validate_expected_destination(&job)?;
        }
        #[cfg(debug_assertions)]
        crate::fsops::test_race_barrier(
            "SYQ_TEST_FINALIZE_READY_FILE",
            "SYQ_TEST_FINALIZE_CONTINUE_FILE",
            "finalize-ready",
        )?;
        self.complete_file(idx, job, false)
    }

    pub(super) fn contents_match(&mut self, job: &WorkerJob) -> Result<bool> {
        self.src.send(Request::FileHash {
            path: job.src.clone(),
            source: self.source_reference(job),
            guard: None,
        })?;
        self.dst.send(Request::FileHash {
            path: job.dst.clone(),
            source: None,
            guard: None,
        })?;
        // Drain both replies even when one endpoint reports a per-file error.
        let source = self.src.recv();
        let destination = self.dst.recv();
        let source = ok(source?, "hash source")?;
        let destination = ok(destination?, "hash destination")?;
        match (source, destination) {
            (
                Response::FileHash {
                    size: source_size,
                    hash: source_hash,
                },
                Response::FileHash {
                    size: destination_size,
                    hash: destination_hash,
                },
            ) => Ok(source_size == destination_size && source_hash == destination_hash),
            (source, destination) => {
                bail!("unexpected responses {source:?} {destination:?}")
            }
        }
    }

    pub(super) fn finish_matched_file(&mut self, idx: usize) -> Result<()> {
        if self.sched.is_failed(idx) {
            return Ok(());
        }
        self.complete_file(idx, self.job(idx), true)
    }

    /// Recheck the source after either an atomic publication or a verified
    /// metadata-only completion, and retry from the completed destination when
    /// the source changed during that work.
    pub(super) fn complete_file(
        &mut self,
        idx: usize,
        job: WorkerJob,
        matched: bool,
    ) -> Result<()> {
        // Did the source change under us?
        let now = stat_one_registered(&mut *self.src, &job.src, &job.source, false)?;
        let changed = match &now {
            Some(e) => {
                e.kind != Kind::File
                    || e.size != job.entry.size
                    || e.mtime != job.entry.mtime
                    || e.mtime_nsec != job.entry.mtime_nsec
            }
            None => true,
        };
        if changed {
            if job.attempt + 1 < MAX_ATTEMPTS && job.target_condition == TargetCondition::Any {
                if let Some(e) = now {
                    if !self.opts.quiet {
                        self.progress.eprintln(&format!(
                            "syq: {}: changed during transfer, retrying",
                            job.rel
                        ));
                    }
                    let published = self.published_entry(&job);
                    let mut jobs = self.sched.jobs.lock().unwrap();
                    let j = &mut jobs[idx];
                    self.progress.bytes_total.fetch_add(e.size, Relaxed);
                    j.entry = Entry {
                        path: j.entry.path.clone(),
                        ..e
                    };
                    j.attempt += 1;
                    j.done.store(0, Relaxed);
                    jobs.set_destination(idx, published);
                    drop(jobs);
                    self.sched.requeue(idx);
                    return Ok(());
                }
            }
            bail!("source changed during transfer (or vanished)");
        }
        if matched {
            self.progress.files_total.fetch_sub(1, Relaxed);
            self.progress.files_unchanged.fetch_add(1, Relaxed);
        } else {
            self.progress.add_files(1);
            if let Some(results) = self.progress.results_writer() {
                results.emit_operation_expected(
                    &crate::results::OperationRecord {
                        action: "transfer_file",
                        dst: &job.rel_bytes,
                        src: job.src_rel.as_deref(),
                        kind: "file",
                        disposition: "succeeded",
                        bytes: Some(job.entry.size),
                        attempts: Some(u64::from(job.attempt) + 1),
                        retryable: None,
                        class: None,
                        os_kind: None,
                        message: None,
                    },
                    self.opts.expected_for(&job.rel_bytes),
                );
            }
        }
        if !matched && self.opts.verbose > 0 {
            self.progress.println(&job.rel);
        }
        Ok(())
    }

    // Keep digest reads in workers so one large file cannot stall directory
    // planning. A failed check takes the normal repair path; publication still
    // validates the expected digest. Explicit --hash continues to compare both
    // endpoints regardless of matching metadata or an expected digest.
    pub(super) fn try_expected_match(&mut self, job: &WorkerJob) -> Result<bool> {
        let Some(expected) = self.opts.expected_for(&job.rel_bytes).cloned() else {
            return Ok(false);
        };
        let Some(destination) = job.dst_entry.as_deref() else {
            return Ok(false);
        };
        if self.opts.checksum
            || !self
                .opts
                .metadata_matches(&job.rel_bytes, &job.entry, destination)
        {
            return Ok(false);
        }
        match self.dst.call(Request::ValidateDigest {
            path: job.dst.clone(),
            expected,
            guard: job.container_guard.clone(),
        })? {
            Response::Ok => {}
            Response::Err(_) | Response::EndpointError(_) => return Ok(false),
            other => bail!("unexpected response validating destination digest: {other:?}"),
        }
        // Preserve the ordinary quick check's metadata reconciliation and
        // require the same destination inode observed by the planner.
        let response = ok(
            self.dst.call(Request::Apply {
                ops: vec![Op::SetFileMetaIfSame {
                    path: job.dst.clone(),
                    condition: match job.target_condition {
                        TargetCondition::Any => target_identity(destination),
                        condition => condition,
                    },
                    meta: self.opts.metadata_for(&job.rel_bytes, &job.entry),
                    flags: self
                        .opts
                        .metadata_fix_flags(&job.rel_bytes, &job.entry, destination),
                }],
                guard: job.container_guard.clone(),
            })?,
            "update metadata after expected digest match",
        )?;
        match response {
            Response::Applied(results) if results.len() == 1 => {
                if let Some(error) = &results[0] {
                    bail!("update metadata after expected digest match: {error}");
                }
            }
            other => bail!("unexpected metadata response: {other:?}"),
        }
        Ok(true)
    }

    pub(super) fn validate_expected_destination(&mut self, job: &WorkerJob) -> Result<()> {
        if let Some(expected) = self.opts.expected_for(&job.rel_bytes).cloned() {
            ok(
                self.dst.call(Request::ValidateDigest {
                    path: job.dst.clone(),
                    expected,
                    guard: job.container_guard.clone(),
                })?,
                "validate expected digest",
            )?;
        }
        Ok(())
    }

    pub(super) fn preview_file(&mut self, idx: usize) -> Result<()> {
        let job = self.job(idx);
        let result = self.contents_match(&job);
        self.sched.ranges_ready(idx, vec![]);
        let matched = match result {
            Ok(matched) => matched,
            Err(error) => {
                if self.transport_dead() {
                    self.sched.requeue(idx);
                }
                return Err(error);
            }
        };
        let (bytes, reason) = if matched {
            self.progress.files_total.fetch_sub(1, Relaxed);
            self.progress.bytes_total.fetch_sub(job.entry.size, Relaxed);
            self.progress.files_unchanged.fetch_add(1, Relaxed);
            self.progress
                .bytes_unchanged
                .fetch_add(job.entry.size, Relaxed);
            let destination = job
                .dst_entry
                .as_ref()
                .expect("preview comparison has a destination");
            if self
                .opts
                .metadata_fix_flags(&job.rel_bytes, &job.entry, destination)
                == 0
            {
                return Ok(());
            }
            self.opts.dry_run_metadata_files.fetch_add(1, Relaxed);
            (None, "metadata_differs")
        } else {
            self.progress.add_files(1);
            self.progress.bytes_done.fetch_add(job.entry.size, Relaxed);
            (Some(job.entry.size), "content_differs")
        };
        if let Some(results) = self.progress.results_writer() {
            results.emit_trace(&crate::results::TraceRecord {
                action: "transfer_file",
                dst: &job.rel_bytes,
                src: job.src_rel.as_deref(),
                kind: "file",
                bytes,
                reason,
            });
        }
        if self.opts.verbose > 0 {
            self.progress.println(&if matched {
                format!(
                    "update metadata {} (requested file metadata differs)",
                    display(&job.dst)
                )
            } else {
                format!("update file {} (contents differ)", display(&job.dst))
            });
        }
        Ok(())
    }
}

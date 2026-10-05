//! Replaced files up to `PATCH_MAX_FILE` bytes are compared before any
//! contents are sent, in groups that flow through three requests:
//!
//! 1. the destination hashes the blocks of the files they would replace
//!    (`HashExistingBatch`);
//! 2. the source reads each file once and returns only the blocks whose
//!    hashes differ (`ReadDifferingBatch`);
//! 3. the destination publishes each file from those blocks and the
//!    matching blocks of the file it replaces, which must be unchanged since
//!    they were hashed, or keeps a file that matched whole and still does
//!    (`PatchSmallBatch`).
//!
//! Groups are pipelined through these stages, so a run of files costs about
//! one round trip of lead time rather than round trips per file. Groups are
//! small and many are in flight (`COMPARE_WINDOW`). An in-process source's
//! reply moves on before the next read, so a worker holds one group's data
//! at a time; a remote source's replies are bounded by its connection's
//! reply queue.
//!
//! The source returns no data for a file of which more differs than one
//! patch carries (`MAX_DIFFERING_FILE_BYTES`). Once a batch's groups are
//! done, each such file's patch is streamed instead: `PatchBegin` sends the
//! patch without data, its differing blocks follow as they are read from the
//! source in `PatchData` pieces, and `PatchEnd` publishes it, or abandons it
//! when the source changed while it was read. A destination connection
//! carries nothing else while a patch is open on it, so a worker streams
//! its patches one after another, each next one beginning as the last ends.
//! Pieces are pipelined: up to `STREAM_BUFFER_BYTES` of them are read ahead
//! from a remote source, and those sent await their acknowledgments within
//! the destination's reply queue.

use super::*;
use crate::proto::PATCH_PIECE_BYTES;
use crate::transfer_tuning::COMPARE_WINDOW;

/// Most piece data a worker reads ahead of sending it while streaming a
/// patch: as much as a group's patches hold.
const STREAM_BUFFER_BYTES: u64 = crate::proto::MAX_DIFFERING_FILE_BYTES;

/// Files and source bytes per group.
const COMPARE_GROUP_FILES: usize = 256;
const COMPARE_GROUP_BYTES: u64 = 4 << 20;
/// Files up to this size are compared and patched in groups. A larger file
/// takes the per-file path, whose ranges several workers can share.
const PATCH_MAX_FILE: u64 = crate::proto::MAX_PATCH_FILE_BYTES;
// Every group fits what a receiver patches in one batch
// (`proto::patch_batch_fits`): several files hold at most
// `COMPARE_GROUP_BYTES`, and a larger file, of at most `PATCH_MAX_FILE`,
// makes a group of its own.
const _: () = assert!(COMPARE_GROUP_BYTES <= crate::proto::MAX_READ_BYTES);
/// Comparison block of the grouped path unless one is configured. A small
/// edit then costs this much, not a whole default comparison block.
const PATCH_BLOCK: u64 = crate::proto::MIN_HASH_BLOCK_BYTES;

/// What comparing one file decided.
pub(super) enum Compared {
    /// The destination already held the source's contents and was kept, with
    /// the kept inode when the publication flags asked for it.
    Kept(Option<(u64, u64)>),
    /// Published from `sent` new bytes and `reused` bytes of the file it
    /// replaced, the new bytes `streamed` in pieces.
    Published {
        identity: Option<(u64, u64)>,
        sent: u64,
        reused: u64,
        streamed: bool,
    },
    /// The source changed after it was planned, to this or nothing.
    SourceChanged(Option<Entry>),
    /// Earlier runs left partial copies: resume from them per file.
    ResumePartial,
    /// The file could not be compared or patched: replace it whole.
    Differs,
    /// The destination no longer met the patch's target condition, as when
    /// keeping another name of the same file changed it: compare it again,
    /// under a fresh condition.
    StaleCondition,
    /// The destination already held the source's contents, but keeping it
    /// failed: a file error, as for a content-identical per-file finish.
    KeepFailed(WireError),
}

#[derive(Clone, Copy)]
enum Stage {
    Hash,
    Read,
    Patch,
}

/// A file of a group sent to be read.
struct PendingRead {
    /// Its position in the batch.
    file: usize,
    /// The destination's block hashes, and the fingerprint of the file they
    /// came from.
    expected: Vec<ContentDigest>,
    basis: Option<FileFingerprint>,
    /// The comparison only decides whether the file is unchanged.
    compare_only: bool,
}

/// A file of which more differs than one patch carries: its patch, without
/// data, until it is sent, and the new and reused bytes it publishes.
struct Streamed {
    file: usize,
    patch: Option<SmallPatch>,
    sent: u64,
    reused: u64,
}

/// The ranges of a patch's differing blocks, in file order, each of whole
/// blocks and at most `piece` bytes.
fn differing_ranges(patch: &SmallPatch, piece: u64) -> Vec<(u64, u32)> {
    let SmallPatch {
        len, block, reuse, ..
    } = patch;
    let mut ranges = Vec::new();
    let mut index = 0;
    while index < reuse.len() {
        if reuse[index].is_some() {
            index += 1;
            continue;
        }
        let mut start = index as u64 * block;
        while index < reuse.len() && reuse[index].is_none() {
            index += 1;
        }
        let end = (index as u64 * block).min(*len);
        while start < end {
            let range = piece.min(end - start);
            ranges.push((start, range as u32));
            start += range;
        }
    }
    ranges
}

/// Where a streamed patch's request stands on its connection.
enum StreamStep {
    /// A piece read from the source, at its offset and length.
    Piece(usize, u64, u32),
    /// The patch's begin, or a piece, sent to the destination.
    Begin(usize),
    Ack(usize),
    /// The source's metadata read after the patch's last piece.
    Recheck(usize),
    End(usize),
}

/// What streaming one patch has learned.
#[derive(Default)]
struct StreamState {
    /// Its ranges read from the source, and the next to read.
    ranges: Vec<(u64, u32)>,
    next: usize,
    begun: bool,
    /// It cannot be published: a piece failed, or the receiver reported
    /// that the patch did.
    failed: bool,
    /// The receiver refused its begin, so no patch is open there to end.
    refused: bool,
    /// The source changed while it was read, to this or nothing.
    changed: Option<Option<Entry>>,
}

/// One group's files, as positions in the batch, and what each stage
/// learned about those still in flight.
#[derive(Default)]
struct Group {
    files: Vec<usize>,
    /// Files sent to be read.
    reads: Vec<PendingRead>,
    /// Files sent to be published, and the bytes sent and reused.
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

    /// The largest file, and the most source bytes of one group, to compare
    /// in groups. A restricted receiver with a rate limit refuses a request
    /// carrying more file data than one burst, so a group's files, and with
    /// them the data its patches send, stay within that.
    pub(super) fn compare_group_limits(&self) -> (u64, u64) {
        match &self.bwlimit {
            Some(limit) if self.opts.restricted_receiver => {
                let burst = limit.burst_bytes();
                (PATCH_MAX_FILE.min(burst), COMPARE_GROUP_BYTES.min(burst))
            }
            _ => (PATCH_MAX_FILE, COMPARE_GROUP_BYTES),
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
        let (max_file, group_bytes) = self.compare_group_limits();
        // Only differing blocks cross the network, so a batch holds enough
        // groups to keep the pipeline full: two windows of them.
        let batch_bytes = group_bytes * 2 * COMPARE_WINDOW as u64;
        let mut batch = vec![idx];
        batch.extend(self.sched.take_small_near(
            idx,
            max_file,
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
                Some(Compared::StaleCondition) => {
                    // Keeping or replacing each other name of the
                    // destination in this copy changes the change time its
                    // condition holds, once. This batch's names of the file
                    // are authorized in turn (see `compare_small_files`),
                    // but another worker's can still leave this name's
                    // condition stale, once each. Comparing it again as many
                    // times as this copy has names of the file lets every
                    // name be kept, and leaves one comparison for a change
                    // from outside. A file that goes stale more often, as
                    // one that keeps changing does, is replaced whole. Names
                    // of it outside this copy do not count.
                    let mut jobs = self.sched.jobs.lock().unwrap();
                    let names = jobs.destination_names(i);
                    let job = &mut jobs[i];
                    job.recompared = job.recompared.saturating_add(1);
                    job.compared = job.recompared > names;
                    drop(jobs);
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
        let (_, group_bytes) = self.compare_group_limits();
        let (mut start, mut bytes) = (0, 0u64);
        // A restricted receiver binds each patch to the change time of the
        // file it replaces when it authorizes the patch's request, and
        // authorizes all of a request's patches before it carries out any.
        // Keeping one name of a hard-linked file with new metadata, or
        // replacing it, changes the change time the file's other names
        // share, so another of them in the same request would find its
        // condition stale: it would be compared again, or copied whole if
        // it was to be replaced. Each name of such a file goes in a group of
        // its own instead. This connection's requests are carried out in
        // turn, so a later group's patch is authorized against the file as
        // the earlier one left it.
        let mut linked = std::collections::HashSet::new();
        for (i, job) in jobs.iter().enumerate() {
            let identity = job
                .dst_entry
                .as_deref()
                .filter(|_| self.opts.restricted_receiver)
                .and_then(crate::sched::linked_identity);
            if i > start
                && (i - start >= COMPARE_GROUP_FILES
                    || bytes.saturating_add(job.entry.size) > group_bytes
                    || identity.is_some_and(|identity| linked.contains(&identity)))
            {
                unissued.push_back((start..i).collect::<Vec<_>>());
                (start, bytes) = (i, 0);
                linked.clear();
            }
            bytes += job.entry.size;
            linked.extend(identity);
        }
        if start < jobs.len() {
            unissued.push_back((start..jobs.len()).collect());
        }
        // Each group has at most one request outstanding, so the groups in
        // flight bound the replies the destination owes, and waiting reads
        // those the source owes, to what each connection queues.
        let window = self
            .dst
            .reply_queue()
            .map_or(COMPARE_WINDOW, |queue| queue.min(COMPARE_WINDOW));
        let source_queue = self.src.reply_queue().unwrap_or(usize::MAX);
        let mut groups: Vec<Group> = Vec::new();
        // Patches to stream once the groups are done.
        let mut streams = Vec::new();
        let mut in_flight = 0;
        // Reads waiting for the source to owe fewer replies.
        let mut waiting: std::collections::VecDeque<(usize, Request)> = Default::default();
        let mut source = std::collections::VecDeque::new();
        let mut destination = std::collections::VecDeque::new();
        let result = (|| -> Result<()> {
            loop {
                while source.len() < source_queue {
                    let Some((group, request)) = waiting.pop_front() else {
                        break;
                    };
                    self.src.send(request)?;
                    source.push_back((group, Stage::Read, std::time::Instant::now()));
                }
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
                // Replies arrive in order on each connection. Take one that
                // has arrived, as an in-process endpoint's has, so that the
                // data it holds moves on at once; otherwise wait for the one
                // whose request went out first.
                let from_source = match (source.front(), destination.front()) {
                    (Some(_), Some(_)) if self.src.reply_ready() => true,
                    (Some(_), Some(_)) if self.dst.reply_ready() => false,
                    (Some((_, _, a)), Some((_, _, b))) => a <= b,
                    (Some(_), None) => true,
                    (None, Some(_)) => false,
                    (None, None) => {
                        debug_assert!(waiting.is_empty());
                        return Ok(());
                    }
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
                let next = self.compare_stage(
                    &jobs,
                    &mut groups[group],
                    stage,
                    response,
                    &mut outcomes,
                    &mut streams,
                )?;
                match next {
                    Some((Stage::Read, request)) => waiting.push_back((group, request)),
                    Some((stage, request)) => {
                        self.dst.send(request)?;
                        destination.push_back((group, stage, std::time::Instant::now()));
                    }
                    None => in_flight -= 1,
                }
            }
        })();
        // Files whose reads were never sent were not compared.
        for (group, _) in waiting {
            for read in &groups[group].reads {
                outcomes[read.file] = None;
            }
        }
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
        let result = result.and(source_end).and(destination_end);
        // A patch that is not streamed to its end is compared again.
        for stream in &streams {
            outcomes[stream.file] = None;
        }
        let result = match result {
            Ok(()) if !streams.is_empty() => self.stream_patches(&jobs, streams, &mut outcomes),
            result => result,
        };
        (outcomes, result)
    }

    /// Bytes of new data each piece of a streamed patch carries: whole
    /// blocks, within one burst of a restricted receiver's rate limit.
    fn patch_piece(&self, block: u64) -> u64 {
        let piece = match &self.bwlimit {
            Some(limit) if self.opts.restricted_receiver => {
                PATCH_PIECE_BYTES.min(limit.burst_bytes())
            }
            _ => PATCH_PIECE_BYTES,
        };
        (piece / block).max(1) * block
    }

    /// Stream each of `streams`' patches, one after another, and record
    /// their outcomes. The next patch begins as soon as the last has ended,
    /// and its pieces are read ahead while the last's are still sent.
    fn stream_patches(
        &mut self,
        jobs: &[WorkerJob],
        mut streams: Vec<Streamed>,
        outcomes: &mut [Option<Compared>],
    ) -> Result<()> {
        use std::collections::VecDeque;
        let piece = self.patch_piece(self.patch_block());
        let mut states: Vec<StreamState> = streams
            .iter()
            .map(|stream| StreamState {
                ranges: stream
                    .patch
                    .as_ref()
                    .map_or_else(Vec::new, |patch| differing_ranges(patch, piece)),
                ..Default::default()
            })
            .collect();
        // An in-process source answers each read as it is sent, and its
        // piece moves on before the next is read. A remote one's reads queue
        // within its reply queue and the read-ahead buffer.
        let reads = self
            .src
            .reply_queue()
            .map_or(1, |queue| queue.min(COMPARE_WINDOW));
        let acknowledgments = self
            .dst
            .reply_queue()
            .map_or(COMPARE_WINDOW, |queue| queue.min(COMPARE_WINDOW));
        let mut source: VecDeque<(StreamStep, std::time::Instant)> = VecDeque::new();
        let mut destination: VecDeque<(StreamStep, std::time::Instant)> = VecDeque::new();
        // The patch whose reads are being sent, and the piece bytes read
        // and not yet sent on.
        let (mut reading, mut buffered) = (0, 0u64);
        #[cfg(debug_assertions)]
        crate::fsops::test_race_barrier(
            "SYQ_TEST_PATCH_STREAM_READY_FILE",
            "SYQ_TEST_PATCH_STREAM_CONTINUE_FILE",
            "streamed patches before their pieces are read",
        )?;
        self.begin_stream(&mut streams, &mut states, 0, &mut destination)?;
        loop {
            while source.len() < reads && reading < streams.len() {
                // The next patch's pieces are read ahead, before it begins.
                // Once the copy is aborted, no further patch begins, and
                // none is published with pieces left unread.
                let state = &mut states[reading];
                if self.sched.is_aborted() && (!state.begun || state.next < state.ranges.len()) {
                    state.failed = true;
                }
                if state.failed {
                    state.next = state.ranges.len();
                }
                let job = &jobs[streams[reading].file];
                if let Some(&(off, len)) = state.ranges.get(state.next) {
                    if buffered > 0 && buffered + u64::from(len) > STREAM_BUFFER_BYTES {
                        break;
                    }
                    self.src.send(Request::ReadRange {
                        path: job.src.clone(),
                        source: self.source_reference(job),
                        attempt: job.attempt,
                        off,
                        len,
                    })?;
                    state.next += 1;
                    buffered += u64::from(len);
                    source.push_back((
                        StreamStep::Piece(reading, off, len),
                        std::time::Instant::now(),
                    ));
                    continue;
                }
                // Whether the source changed while it was read.
                #[cfg(debug_assertions)]
                if !state.failed {
                    crate::fsops::test_race_barrier(
                        "SYQ_TEST_PATCH_STREAM_RECHECK_READY_FILE",
                        "SYQ_TEST_PATCH_STREAM_RECHECK_CONTINUE_FILE",
                        "streamed patch before its source is checked again",
                    )?;
                }
                self.src.send(Request::StatMany {
                    paths: vec![job.src.clone()],
                    sources: Some(vec![job.source.clone()]),
                    follow: false,
                    guard: None,
                })?;
                source.push_back((StreamStep::Recheck(reading), std::time::Instant::now()));
                reading += 1;
            }
            let from_source = match (source.front(), destination.front()) {
                (Some(_), Some(_)) if self.src.reply_ready() => true,
                (Some(_), Some(_)) if self.dst.reply_ready() => false,
                (Some((_, a)), Some((_, b))) => a <= b,
                (Some(_), None) => true,
                (None, Some(_)) => false,
                (None, None) => return Ok(()),
            };
            if !from_source {
                let (step, _) = destination.pop_front().expect("pending reply");
                let response = self.dst.recv()?;
                self.streamed_reply(&streams, &mut states, step, response, outcomes);
                continue;
            }
            let (step, _) = source.pop_front().expect("pending reply");
            let response = self.src.recv()?;
            // Before anything more goes to the destination, take the replies
            // that have arrived, so that a patch the receiver has failed
            // sends no more pieces, and owe no more acknowledgments than the
            // destination's connection queues.
            self.arrived_replies(&streams, &mut states, &mut destination, outcomes)?;
            while destination.len() >= acknowledgments {
                let (step, _) = destination.pop_front().expect("pending reply");
                let reply = self.dst.recv()?;
                self.streamed_reply(&streams, &mut states, step, reply, outcomes);
            }
            match step {
                StreamStep::Piece(index, off, len) => {
                    let state = &mut states[index];
                    buffered -= u64::from(len);
                    let piece = match ok(response, "read streamed patch piece") {
                        Ok(Response::Block {
                            off: at,
                            data,
                            hash,
                        }) if at == off && data.len() == len as usize => Some((data, hash)),
                        Ok(other) => bail!("unexpected response {other:?}"),
                        Err(_) => None,
                    };
                    match piece {
                        Some((data, hash)) if state.begun && !state.failed => {
                            self.limit(u64::from(len));
                            self.dst.send(Request::PatchData {
                                data: data.into(),
                                hash,
                            })?;
                            destination
                                .push_back((StreamStep::Ack(index), std::time::Instant::now()));
                        }
                        Some(_) => {}
                        // The source may have changed: its recheck tells.
                        None => state.failed = true,
                    }
                }
                StreamStep::Recheck(index) => {
                    let now = match ok(response, "check streamed patch source") {
                        Ok(Response::Stats(mut entries)) if entries.len() == 1 => {
                            Some(entries.pop().flatten())
                        }
                        Ok(other) => bail!("unexpected response {other:?}"),
                        Err(_) => None,
                    };
                    let state = &mut states[index];
                    if !state.begun {
                        continue;
                    }
                    // A piece that could not be read, as when the source
                    // shrank, fails the patch; the source's metadata then
                    // tells whether it changed, unless reading that failed
                    // too.
                    match now {
                        Some(now)
                            if source_changed(&jobs[streams[index].file].entry, now.as_ref()) =>
                        {
                            state.changed = Some(now);
                        }
                        Some(_) => {}
                        None => state.failed = true,
                    }
                    if state.refused {
                        // Nothing is open at the receiver: the patch ends
                        // here.
                        outcomes[streams[index].file] = Some(match state.changed.take() {
                            Some(now) => Compared::SourceChanged(now),
                            None => Compared::Differs,
                        });
                    } else {
                        let commit = !state.failed && state.changed.is_none();
                        self.dst.send(Request::PatchEnd { commit })?;
                        destination.push_back((StreamStep::End(index), std::time::Instant::now()));
                    }
                    if index + 1 < streams.len() {
                        while destination.len() >= acknowledgments {
                            let (step, _) = destination.pop_front().expect("pending reply");
                            let reply = self.dst.recv()?;
                            self.streamed_reply(&streams, &mut states, step, reply, outcomes);
                        }
                        self.begin_stream(&mut streams, &mut states, index + 1, &mut destination)?;
                    }
                }
                StreamStep::Begin(_) | StreamStep::Ack(_) | StreamStep::End(_) => {
                    unreachable!("destination steps")
                }
            }
        }
    }

    /// Act on the destination's replies that have already arrived, without
    /// waiting for more.
    fn arrived_replies(
        &mut self,
        streams: &[Streamed],
        states: &mut [StreamState],
        destination: &mut std::collections::VecDeque<(StreamStep, std::time::Instant)>,
        outcomes: &mut [Option<Compared>],
    ) -> Result<()> {
        while !destination.is_empty() {
            let response = if self.dst.reply_ready() {
                self.dst.recv()?
            } else {
                match self.dst.try_recv_with_arrival() {
                    Some(reply) => reply?.0,
                    None => return Ok(()),
                }
            };
            let (step, _) = destination.pop_front().expect("pending reply");
            self.streamed_reply(streams, states, step, response, outcomes);
        }
        Ok(())
    }

    /// Send the begin of stream `index`, unless the copy was aborted. A patch
    /// that does not reach its end, as when its connection fails, keeps no
    /// outcome and is compared again.
    fn begin_stream(
        &mut self,
        streams: &mut [Streamed],
        states: &mut [StreamState],
        index: usize,
        destination: &mut std::collections::VecDeque<(StreamStep, std::time::Instant)>,
    ) -> Result<()> {
        if self.sched.is_aborted() {
            return Ok(());
        }
        let stream = &mut streams[index];
        let patch = stream.patch.take().expect("a patch begins once");
        self.dst.send(Request::PatchBegin {
            patch: Box::new(patch),
            data_len: stream.sent,
        })?;
        destination.push_back((StreamStep::Begin(index), std::time::Instant::now()));
        states[index].begun = true;
        Ok(())
    }

    /// Act on the destination's reply to a streamed patch's begin, piece or
    /// end.
    fn streamed_reply(
        &mut self,
        streams: &[Streamed],
        states: &mut [StreamState],
        step: StreamStep,
        response: Response,
        outcomes: &mut [Option<Compared>],
    ) {
        match step {
            // A begin or piece replies Ok until the patch fails; its end
            // reports why. A refused begin opened nothing.
            StreamStep::Begin(index) | StreamStep::Ack(index) => {
                if !matches!(response, Response::Ok) {
                    states[index].failed = true;
                }
                if let (StreamStep::Begin(_), Response::Err(_) | Response::EndpointError(_)) =
                    (&step, &response)
                {
                    states[index].refused = true;
                }
            }
            StreamStep::End(index) => {
                let Streamed {
                    file, sent, reused, ..
                } = streams[index];
                let reply = match ok(response, "end streamed patch") {
                    Ok(Response::PatchedBatch(mut patched)) if patched.len() == 1 => patched.pop(),
                    _ => None,
                };
                outcomes[file] = Some(match (states[index].changed.take(), reply) {
                    (Some(now), _) => Compared::SourceChanged(now),
                    (
                        None,
                        Some(Ok(SmallPatched {
                            kept: false,
                            identity,
                        })),
                    ) if !states[index].failed => Compared::Published {
                        identity,
                        sent,
                        reused,
                        streamed: true,
                    },
                    (
                        None,
                        Some(Err(SmallPatchError {
                            stale_condition: true,
                            ..
                        })),
                    ) => Compared::StaleCondition,
                    _ => Compared::Differs,
                });
            }
            StreamStep::Piece(..) | StreamStep::Recheck(_) => unreachable!("source steps"),
        }
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
        streams: &mut Vec<Streamed>,
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
                    group.reads.push(PendingRead {
                        file: i,
                        expected,
                        basis,
                        compare_only,
                    });
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
                for (
                    PendingRead {
                        file: i,
                        expected,
                        basis,
                        compare_only,
                    },
                    differing,
                ) in std::mem::take(&mut group.reads).into_iter().zip(differing)
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
                    // The source sends none of a file of which more differs
                    // than one patch carries: its patch is streamed.
                    let streamed = !compare_only && data.is_empty() && matching.contains(&false);
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
                    if !streamed && data.len() as u64 != sent {
                        continue;
                    }
                    let mut meta = self.opts.metadata_for(&job.rel_bytes, &job.entry);
                    meta.mode = self.create_mode(job);
                    let patch = SmallPatch {
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
                    };
                    if streamed {
                        streams.push(Streamed {
                            file: i,
                            patch: Some(patch),
                            sent,
                            reused,
                        });
                        continue;
                    }
                    self.limit(sent);
                    patches.push(patch);
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
                    streamed: false,
                },
                Err(SmallPatchError {
                    error,
                    matched: true,
                    ..
                }) => Compared::KeepFailed(error),
                Err(SmallPatchError {
                    stale_condition: true,
                    ..
                }) => Compared::StaleCondition,
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
                streamed,
            } => {
                self.benchmark.patched_files += 1;
                self.benchmark.streamed_patches += u64::from(streamed);
                if let Err(error) = self.record_hardlink_identity(idx, &job, identity) {
                    return self.file_error(idx, error);
                }
                job.done.store(job.entry.size, Relaxed);
                self.progress.add_bytes(sent);
                self.progress.bytes_unchanged.fetch_add(reused, Relaxed);
                self.progress.bytes_total.fetch_sub(reused, Relaxed);
                self.complete_file(job, false)
            }
            Compared::KeepFailed(error) => self.file_error(
                idx,
                anyhow::Error::new(error).context("finish content-identical destination"),
            ),
            Compared::SourceChanged(_)
            | Compared::ResumePartial
            | Compared::Differs
            | Compared::StaleCondition => unreachable!("these files are requeued"),
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

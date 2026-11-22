//! Comparing a staged file's ranges with the destination, block by block.
//!
//! The destination hashes a window of the file (`HashWindow`), and for each
//! block the source either confirms that its own bytes hash the same
//! (`ReadComparedRange` answered by `RangeMatched`) or returns them. A
//! matching block is then reused from the file being replaced
//! (`ReuseComparedRange`, unless the stage already holds it as a clone) and a
//! differing one written (`WriteRange`). These requests flow continuously:
//! the destination hashes windows ahead while the source compares earlier
//! ones, and writes are acknowledged as they arrive, with no pause at window
//! boundaries.
//!
//! Unless the copy fixes comparison settings, each worker sizes its own
//! requests as it goes (`ComparisonSizing`):
//!
//! - How far ahead it has windows hashed: in a push, further after it waited
//!   for hashes with nothing else to do, up to the 32 MiB the receiver
//!   retained for one worker before comparisons adapted. A short link never
//!   needs that much. A pull or relay waits on a remote source in the
//!   ordinary course of its pipeline, which says nothing about whether more
//!   would help, so it hashes the 32 MiB ahead from the start.
//! - The comparison block of each window, from 64 KiB to the configured block.
//!   The worker measures the spacing of runs of changed blocks and sizes
//!   blocks to keep the extra bytes around their edges a small fraction of
//!   the bytes compared. Larger blocks take fewer requests per window.
//!   A pull keeps the 256 KiB ceiling so more comparisons can be queued
//!   under the remote source's byte allowance.

use super::*;
use std::collections::VecDeque;
use std::time::Instant;

/// Smallest comparison block: the protocol's hash granularity.
const MIN_BLOCK: u64 = crate::proto::MIN_HASH_BLOCK_BYTES;
/// Block a worker compares with before it has measured a run of changes.
const START_BLOCK: u64 = 256 << 10;
/// Most bytes a worker has hashed ahead and not yet used: what two 16 MiB
/// windows retained at the receiver before comparisons adapted.
const MAX_AHEAD: u64 = 32 << 20;
const START_AHEAD: u64 = 8 << 20;
/// Most bytes, and blocks, one hash window covers.
const MAX_WINDOW: u64 = 16 << 20;
const MAX_WINDOW_BLOCKS: u64 = 1024;
// The receiver holds at most `MAX_READ_BYTES` of hashed windows for one
// connection, and a window of the smallest blocks still fills `MAX_WINDOW`.
const _: () = assert!(MAX_AHEAD <= crate::proto::MAX_READ_BYTES);
const _: () = assert!(MAX_WINDOW_BLOCKS * MIN_BLOCK >= MAX_WINDOW);
/// File data the source's queued replies may carry (`conn::SOURCE_REPLY_BYTES`).
const SOURCE_DATA_IN_FLIGHT: u64 = 16 << 20;
/// Let recent compared bytes and change runs outweigh older ones.
const COMPARED_MEMORY: f64 = (1u64 << 30) as f64;
/// Each run can resend up to two block edges. Size their total at up to
/// 1/16 of the compared bytes at the observed run density, within the
/// supported bounds.
const BYTES_PER_RUN_BLOCK: f64 = 2.0 * 16.0;

/// One worker's comparison sizes and the measurements they come from. It
/// lasts for the worker's copy, across the files it compares.
#[derive(Clone, Debug)]
pub(super) struct ComparisonSizing {
    initial_block: u64,
    ahead: u64,
    /// Bytes compared, and runs of differing blocks among them.
    compared: f64,
    runs: f64,
}

impl Default for ComparisonSizing {
    fn default() -> Self {
        Self {
            initial_block: START_BLOCK,
            ahead: START_AHEAD,
            compared: 0.0,
            runs: 0.0,
        }
    }
}

impl ComparisonSizing {
    #[cfg(test)]
    pub(super) fn starting(block: u64, ahead: u64) -> Self {
        Self {
            initial_block: block,
            ahead,
            ..Self::default()
        }
    }

    /// Runs of differing blocks measured, as they now count.
    #[cfg(test)]
    pub(super) fn runs(&self) -> f64 {
        self.runs
    }

    /// The block of the next window, no larger than `ceiling`.
    pub(super) fn block(&self, ceiling: u64) -> u64 {
        if self.runs == 0.0 {
            return self.initial_block.clamp(MIN_BLOCK.min(ceiling), ceiling);
        }
        let best = (self.compared / (self.runs * BYTES_PER_RUN_BLOCK)) as u64;
        // Quantize down to preserve the bound across ordinary sample variation.
        let bounded = best.clamp(MIN_BLOCK.min(ceiling), ceiling);
        bounded
            .checked_ilog2()
            .map_or(0, |power| 1 << power)
            .max(MIN_BLOCK.min(ceiling))
    }

    /// Bytes of hashed windows not yet used that the worker may hold.
    pub(super) fn ahead(&self) -> u64 {
        self.ahead
    }

    /// The bytes of the next window for `block`: half the look-ahead, so one
    /// window is hashed while another is compared, in whole blocks.
    pub(super) fn window(&self, block: u64) -> u64 {
        let most = MAX_WINDOW.min(MAX_WINDOW_BLOCKS * block).max(block);
        ((self.ahead / 2).clamp(block, most) / block) * block
    }

    /// The worker waited for a window's hashes with nothing else to do.
    pub(super) fn starved(&mut self) {
        self.ahead = (self.ahead * 2).min(MAX_AHEAD);
    }

    /// The source answered for `bytes`, beginning `runs` runs of differing
    /// blocks.
    pub(super) fn compared(&mut self, bytes: u64, runs: u64) {
        self.compared += bytes as f64;
        self.runs += runs as f64;
        if self.compared > COMPARED_MEMORY {
            self.compared /= 2.0;
            self.runs /= 2.0;
        }
    }
}

/// The sizes one comparing range uses.
struct Sizes {
    adaptive: bool,
    /// Fixed block and window when not adaptive.
    block: u64,
    window: u64,
    /// Most bytes hashed ahead and not yet used.
    ahead: u64,
    /// Most requests awaiting replies on each connection.
    source_requests: usize,
    destination_requests: usize,
    /// Whether the destination is asked for hashes before it has answered
    /// everything sent to it.
    prefetch: bool,
    /// The source answers each request as it is sent, as one in this
    /// process does.
    source_answers_at_once: bool,
}

struct Window {
    start: u64,
    end: u64,
    block: u64,
    hashes: Option<Vec<ContentDigest>>,
    /// Next block to ask the source about.
    next: usize,
}

/// A destination reply still to come, in wire order, with when its request
/// was sent.
enum Awaited {
    Hashes(Instant),
    /// A block written or reused.
    Write {
        len: u64,
        reused: bool,
        sent: Instant,
    },
}

impl Awaited {
    fn sent(&self) -> Instant {
        match self {
            Self::Hashes(sent) | Self::Write { sent, .. } => *sent,
        }
    }
}

/// A source reply still to come: the block asked about, and when.
struct Read {
    off: u64,
    len: u64,
    sent: Instant,
}

/// What a comparing range has outstanding and has learned.
#[derive(Default)]
struct Flow {
    windows: VecDeque<Window>,
    awaited: VecDeque<Awaited>,
    reads: VecDeque<Read>,
    /// Bytes the destination hashed, or is hashing, that no sent request has
    /// used yet: what a final-basis comparison holds at the receiver.
    retained: u64,
    /// Bytes hashed, or being hashed, not yet asked of the source.
    ahead: u64,
    /// Bytes asked of the source and not yet answered.
    reading: u64,
    claimed_all: bool,
    matched: u64,
    /// Where the last block the source answered for ended, if it differed:
    /// a differing block there continues its run.
    differing_end: Option<u64>,
    /// A window has been asked about: waits for hashes after that mean the
    /// look-ahead is too short.
    started: bool,
}

/// Whether waiting for the destination's next reply, which has not arrived,
/// shows a push's look-ahead is too short: it waits for hashes with no block
/// left to ask about. A pull's look-ahead is already the most it may be.
fn hashes_ran_out(sizes: &Sizes, flow: &Flow) -> bool {
    sizes.adaptive
        && sizes.source_answers_at_once
        && sizes.prefetch
        && flow.started
        && flow.reads.is_empty()
        && matches!(flow.awaited.front(), Some(Awaited::Hashes(_)))
}

impl Worker {
    /// A pull can queue only `SOURCE_DATA_IN_FLIGHT` of potential payloads;
    /// keep its smaller ceiling so it can ask about more blocks at once.
    fn adaptive_ceiling(&self) -> u64 {
        let configured = self.opts.block.min(self.transfer_block());
        if self.opts.src_remote && !self.opts.dst_remote {
            configured.min(START_BLOCK)
        } else {
            configured
        }
    }

    fn comparison_sizes(&self) -> Sizes {
        let configured = self.opts.block.min(self.transfer_block());
        let src_pipelines = self.src.supports_request_pipelining();
        let dst_pipelines = self.dst.supports_request_pipelining();
        if !self.opts.adaptive_ranges() {
            // Fixed sizes, as configured: windows of `pipeline-depth` blocks,
            // one hashed ahead while the last is read, if the receiver can
            // hold both: a window over half its limit is hashed alone.
            let depth = self.opts.tuning.pipeline_depth();
            let window = configured
                .saturating_mul(depth as u64)
                .min(crate::proto::MAX_READ_BYTES / 2)
                .max(configured);
            return Sizes {
                adaptive: false,
                block: configured,
                window,
                ahead: (window * 2).min(crate::proto::MAX_READ_BYTES).max(window),
                source_requests: if src_pipelines { depth } else { 1 },
                destination_requests: if dst_pipelines { depth + 1 } else { 1 },
                prefetch: dst_pipelines,
                source_answers_at_once: !src_pipelines,
            };
        }
        let block = self.comparison.block(self.adaptive_ceiling());
        let queue = |conn: &dyn Conn| {
            conn.reply_queue()
                .unwrap_or(crate::transfer_tuning::DEFAULT_PIPELINE_DEPTH)
        };
        Sizes {
            adaptive: true,
            block,
            window: self.comparison.window(block),
            // A remote source's replies are waited on as a matter of course;
            // only a push learns how far ahead it needs to hash.
            ahead: if src_pipelines {
                MAX_AHEAD
            } else {
                self.comparison.ahead()
            },
            source_requests: if src_pipelines { queue(&*self.src) } else { 1 },
            destination_requests: if dst_pipelines { queue(&*self.dst) } else { 1 },
            prefetch: dst_pipelines,
            source_answers_at_once: !src_pipelines,
        }
    }

    /// Keep comparison memory bounded by the look-ahead, independent of file
    /// size. Each source reply either commits a matching block or carries the
    /// exact bytes just hashed; differing source bytes are never read twice.
    pub(super) fn transfer_comparing_range(
        &mut self,
        job: &WorkerJob,
        handle: &RangeHandle,
        credited: &mut u64,
    ) -> Result<()> {
        // Scheduler methods acquire its lock before inspecting range handles.
        let idx = handle.lock().unwrap().idx;
        let mut sizes = self.comparison_sizes();
        let mut flow = Flow::default();
        let result = self.compare_flow(job, handle, idx, &mut sizes, &mut flow, credited);
        if result.as_ref().is_err_and(|e| e.is::<RangeReplyMismatch>()) {
            return result;
        }
        // Drain in wire order, even after an ordinary endpoint error. Source
        // failures must not leave a hash reply mistaken for a write acknowledgment.
        let source_end =
            crate::conn::drain_range_replies(&mut *self.src, flow.reads.len(), "compare");
        let matched = &mut flow.matched;
        let destination_end = crate::conn::drain_range_replies_with(
            &mut *self.dst,
            flow.awaited,
            "write",
            |awaited| {
                if let Awaited::Write { len, reused, .. } = awaited {
                    Self::acknowledge_comparison(
                        &self.progress,
                        job,
                        len,
                        reused,
                        credited,
                        matched,
                    );
                }
            },
        );
        let result = result.and(source_end).and(destination_end);
        if result.is_err() && self.transport_dead() {
            job.done.fetch_sub(flow.matched, Relaxed);
            self.progress
                .bytes_unchanged
                .fetch_sub(flow.matched, Relaxed);
            self.progress.bytes_total.fetch_add(flow.matched, Relaxed);
        }
        #[cfg(debug_assertions)]
        if result.is_ok() {
            crate::fsops::record_test_event(
                "SYQ_TEST_WORKER_EVENTS",
                format_args!(
                    "compare-range {} {} {} {}",
                    self.id, idx, credited, flow.matched
                ),
            )?;
        }
        result
    }

    fn compare_flow(
        &mut self,
        job: &WorkerJob,
        handle: &RangeHandle,
        idx: usize,
        sizes: &mut Sizes,
        flow: &mut Flow,
        credited: &mut u64,
    ) -> Result<()> {
        loop {
            // Nothing further is written for a copy that ended or a file that
            // failed: the caller drains what is outstanding. One scheduler
            // visit answers both.
            if matches!(
                self.sched.range_work(idx, None),
                crate::sched::RangeWork::Cancelled
            ) {
                return Ok(());
            }
            self.issue_comparisons(job, handle, sizes, flow)?;
            let from_source = match (flow.reads.front(), flow.awaited.front()) {
                (None, None) => return Ok(()),
                (Some(_), None) => true,
                (None, Some(_)) => false,
                // A source reply leads to a destination request, which needs
                // room. Otherwise take an in-process source's reply, which is
                // there as soon as it is asked for, or one a connection says
                // has arrived (only an in-process one can), or else the reply
                // whose request went out first.
                (Some(read), Some(awaited)) => {
                    flow.awaited.len() < sizes.destination_requests
                        && (sizes.source_answers_at_once
                            || self.src.reply_ready()
                            || read.sent <= awaited.sent())
                }
            };
            if from_source {
                self.receive_compared_block(job, sizes, flow, credited)?;
                continue;
            }
            let reply = match self.dst.try_recv_with_arrival() {
                Some(arrived) => arrived?.0,
                None => {
                    if hashes_ran_out(sizes, flow) {
                        self.comparison.starved();
                        sizes.ahead = self.comparison.ahead();
                    }
                    self.dst.recv()?
                }
            };
            self.receive_compared_destination(job, flow, credited, reply)?;
        }
    }

    /// Ask for hashes of further windows within the look-ahead, and ask the
    /// source about the blocks of hashed windows.
    fn issue_comparisons(
        &mut self,
        job: &WorkerJob,
        handle: &RangeHandle,
        sizes: &Sizes,
        flow: &mut Flow,
    ) -> Result<()> {
        let ceiling = self.adaptive_ceiling();
        while !flow.claimed_all && flow.awaited.len() < sizes.destination_requests {
            // Without pipelining, the destination answers each request before
            // the next: hash a window only once the last has been used.
            if !sizes.prefetch
                && (!flow.windows.is_empty() || !flow.reads.is_empty() || !flow.awaited.is_empty())
            {
                break;
            }
            let (block, window) = if sizes.adaptive {
                let block = self.comparison.block(ceiling);
                (block, self.comparison.window(block))
            } else {
                (sizes.block, sizes.window)
            };
            // What the receiver holds of a final basis; else what is hashed
            // and not yet used.
            let held = if job.compare_final {
                flow.retained
            } else {
                flow.ahead
            };
            if held > 0 && held + window > sizes.ahead {
                break;
            }
            let Some((start, end)) = self.claim_comparison_window(handle, window) else {
                flow.claimed_all = true;
                break;
            };
            self.dst
                .send(self.hash_window_request(job, start, end, block))?;
            flow.awaited.push_back(Awaited::Hashes(Instant::now()));
            flow.windows.push_back(Window {
                start,
                end,
                block,
                hashes: None,
                next: 0,
            });
            flow.retained += end - start;
            flow.ahead += end - start;
        }
        while flow.reads.len() < sizes.source_requests {
            let Some(window) = flow.windows.front_mut() else {
                break;
            };
            let Some(hashes) = &window.hashes else {
                break;
            };
            let off = window.start + window.next as u64 * window.block;
            let len = (window.end - off).min(window.block);
            // Differing blocks come back as data: keep what may be on its way
            // within what the source connection queues.
            if sizes.adaptive
                && !flow.reads.is_empty()
                && flow.reading + len > SOURCE_DATA_IN_FLIGHT
            {
                break;
            }
            let expected = hashes[window.next];
            window.next += 1;
            if window.next == hashes.len() {
                flow.windows.pop_front();
            }
            flow.ahead -= len;
            flow.reading += len;
            flow.started = true;
            self.src.send(Request::ReadComparedRange {
                path: job.src.clone(),
                source: self.source_reference(job),
                attempt: job.attempt,
                off,
                len: len as u32,
                expected,
            })?;
            flow.reads.push_back(Read {
                off,
                len,
                sent: Instant::now(),
            });
            self.benchmark.max_request_bytes = self.benchmark.max_request_bytes.max(len);
        }
        Ok(())
    }

    /// Act on the source's answer for the oldest block asked about: reuse a
    /// matching block, write a differing one.
    fn receive_compared_block(
        &mut self,
        job: &WorkerJob,
        sizes: &Sizes,
        flow: &mut Flow,
        credited: &mut u64,
    ) -> Result<()> {
        let read = flow.reads.pop_front().expect("pending read");
        flow.reading -= read.len;
        let response = ok(self.src.recv()?, "compare source block")?;
        let differs = match response {
            Response::RangeMatched { off, len } => {
                validate_range_reply(read.off, read.len, off, len as usize)?;
                if job.compare_final {
                    self.dst.send(Request::ReuseComparedRange {
                        path: job.dst.clone(),
                        copy_id: self.copy_id(),
                        attempt: job.attempt,
                        off,
                        len,
                    })?;
                    flow.awaited.push_back(Awaited::Write {
                        len: read.len,
                        reused: true,
                        sent: Instant::now(),
                    });
                } else {
                    Self::acknowledge_comparison(
                        &self.progress,
                        job,
                        read.len,
                        true,
                        credited,
                        &mut flow.matched,
                    );
                }
                false
            }
            Response::Block { off, hash, data } => {
                validate_range_reply(read.off, read.len, off, data.len())?;
                self.benchmark.range_requests += 1;
                self.limit(read.len);
                self.dst.send(Request::WriteRange {
                    path: job.dst.clone(),
                    inplace: false,
                    copy_id: self.copy_id(),
                    attempt: job.attempt,
                    off,
                    hash,
                    data: data.into(),
                })?;
                flow.awaited.push_back(Awaited::Write {
                    len: read.len,
                    reused: false,
                    sent: Instant::now(),
                });
                true
            }
            _ => {
                return Err(
                    anyhow::Error::new(RangeReplyMismatch).context("invalid comparison reply")
                )
            }
        };
        // Either request ends the receiver's hold on the block's bytes.
        flow.retained = flow.retained.saturating_sub(read.len);
        if sizes.adaptive {
            // Windows of a range adjoin, so a run continues across them.
            let run = u64::from(differs && flow.differing_end != Some(read.off));
            self.comparison.compared(read.len, run);
        }
        flow.differing_end = differs.then_some(read.off + read.len);
        Ok(())
    }

    /// Take the destination's oldest reply: a window's hashes, or a block
    /// written or reused.
    fn receive_compared_destination(
        &mut self,
        job: &WorkerJob,
        flow: &mut Flow,
        credited: &mut u64,
        response: Response,
    ) -> Result<()> {
        let awaited = flow.awaited.pop_front().expect("awaited reply");
        match awaited {
            Awaited::Hashes(_) => {
                let window = flow
                    .windows
                    .iter_mut()
                    .find(|window| window.hashes.is_none())
                    .expect("a window awaits its hashes");
                window.hashes = Some(Self::window_hashes(
                    response,
                    window.start,
                    window.end,
                    window.block,
                )?);
            }
            Awaited::Write { len, reused, .. } => {
                match change_ok(response, "write compared block")? {
                    Response::Ok => {}
                    _ => {
                        return Err(anyhow::Error::new(RangeReplyMismatch)
                            .context("invalid comparison write acknowledgment"))
                    }
                }
                Self::acknowledge_comparison(
                    &self.progress,
                    job,
                    len,
                    reused,
                    credited,
                    &mut flow.matched,
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_size_tracks_observed_run_spacing_with_bounded_edge_bytes() {
        let ceiling = 4 << 20;
        for (spacing, limit, expected) in [
            (64 << 10, ceiling, MIN_BLOCK),
            (8 << 20, ceiling, 256 << 10),
            (64 << 20, ceiling, 2 << 20),
            (1 << 30, ceiling, ceiling),
            (1 << 30, 3 << 20, 2 << 20),
            (1 << 30, 32 << 10, 32 << 10),
        ] {
            let mut sizing = ComparisonSizing::default();
            sizing.compared(spacing, 1);
            assert_eq!(sizing.block(limit), expected);
            if expected > MIN_BLOCK {
                assert!(32 * expected <= spacing);
            }
        }
    }

    #[test]
    fn sizes_wait_for_change_runs_and_forget_old_ones() {
        let ceiling = 4 << 20;
        let mut sizing = ComparisonSizing::default();
        assert_eq!(sizing.block(ceiling), START_BLOCK);
        assert_eq!(sizing.block(128 << 10), 128 << 10);
        sizing.compared(64 << 20, 0);
        assert_eq!(sizing.block(ceiling), START_BLOCK);
        sizing.compared(1 << 30, 1 << 14);
        assert_eq!(sizing.block(ceiling), MIN_BLOCK);
        for _ in 0..16 {
            sizing.compared(1 << 30, 1);
        }
        assert_eq!(sizing.block(ceiling), ceiling);
    }

    #[test]
    fn only_a_push_that_waits_for_hashes_with_nothing_to_ask_has_run_out() {
        let sizes = |push: bool| Sizes {
            adaptive: true,
            block: 256 << 10,
            window: 4 << 20,
            ahead: if push { START_AHEAD } else { MAX_AHEAD },
            source_requests: if push { 1 } else { 256 },
            destination_requests: 256,
            prefetch: true,
            source_answers_at_once: push,
        };
        let waiting = || Flow {
            started: true,
            awaited: VecDeque::from([Awaited::Hashes(Instant::now())]),
            ..Flow::default()
        };
        assert!(hashes_ran_out(&sizes(true), &waiting()));
        assert!(!hashes_ran_out(&sizes(false), &waiting()), "a pull");
        let mut asking = waiting();
        asking.reads.push_back(Read {
            off: 0,
            len: 512,
            sent: Instant::now(),
        });
        assert!(!hashes_ran_out(&sizes(true), &asking), "blocks to ask");
        let mut first = waiting();
        first.started = false;
        assert!(!hashes_ran_out(&sizes(true), &first), "the first window");
        let mut acknowledging = waiting();
        acknowledging.awaited = VecDeque::from([Awaited::Write {
            len: 512,
            reused: true,
            sent: Instant::now(),
        }]);
        assert!(
            !hashes_ran_out(&sizes(true), &acknowledging),
            "an acknowledgment"
        );
        let mut fixed = sizes(true);
        fixed.adaptive = false;
        assert!(!hashes_ran_out(&fixed, &waiting()), "fixed sizes");
    }

    #[test]
    fn look_ahead_grows_when_starved_up_to_what_the_receiver_retained() {
        let mut sizing = ComparisonSizing::default();
        assert_eq!(sizing.ahead(), START_AHEAD);
        assert_eq!(sizing.window(4 << 20), 4 << 20);
        assert_eq!(sizing.window(256 << 10), 4 << 20);
        for _ in 0..8 {
            sizing.starved();
        }
        assert_eq!(sizing.ahead(), MAX_AHEAD);
        assert_eq!(sizing.window(4 << 20), MAX_WINDOW);
        // At most 1024 hashes per window, and at least one block.
        assert_eq!(sizing.window(MIN_BLOCK), MAX_WINDOW);
        assert_eq!(sizing.window(64 << 20), 64 << 20);
        assert_eq!(sizing.window(3 << 20), 15 << 20);
    }
}

//! Destination lookups sent before their batch's turn.
//!
//! A remote destination answers one combined lookup for each scan batch
//! (`Request::PlanBatch`). Sent one at a time, each waits a round trip while
//! the scan is usually several batches ahead. So the scan shows the planner
//! the batches it has complete (`Conn::scan_ahead`), and the planner sends
//! each one's lookup then, keeping several in flight.
//!
//! The receiver answers a lookup when it reads it, which may be before the
//! planner has applied an earlier batch: before it widened a directory, say,
//! that hid what the lookup asked about. Every such change goes through the
//! control connection the lookup used, so the planner counts what it sends
//! there. An early reply is used only if nothing but lookups was sent
//! between asking and using it; otherwise it is dropped and the batch asks
//! again in its turn, as it would have without this. What workers and other
//! programs do to the destination meanwhile races with a lookup sent in turn
//! just the same.

use super::*;
use crate::conn::PendingReply;

/// A batch the scan showed before its turn, with its lookup.
pub(super) struct EarlyLookup {
    /// What its lookup asks about, as `Planner::map_batch` is expected to
    /// map the batch.
    directories: Vec<PathBytes>,
    others: Vec<PathBytes>,
    /// The reply to come, and how many other requests the destination had
    /// been sent when the lookup was (`Planner::other_requests`).
    reply: Option<(PendingReply, u64)>,
}

#[derive(Default)]
pub(super) struct EarlyLookups {
    /// Batches shown and not yet planned, oldest first: at most
    /// `scan::AHEAD`.
    shown: std::collections::VecDeque<EarlyLookup>,
    /// Batch lookups the planner has sent, early or in turn.
    sent: u64,
    /// The batch planned last sent the destination nothing but its lookup.
    /// One that sent more is likely followed by others that do, each of
    /// which would waste the lookups sent ahead of it.
    quiet: bool,
}

impl Planner<'_> {
    /// Whether scans should show batches early: this copy looks each batch
    /// up in one request, plans it as it arrives, and its connection can
    /// leave replies for later.
    pub(super) fn looks_up_early(&self) -> bool {
        self.batch_lookups_configured()
            // `handle_batch` drops unselected entries before mapping.
            && self.opts.expressions.selection.is_none()
            && self.dst.requests_sent().is_some()
            && self
                .dst
                .reply_queue()
                .is_some_and(|replies| replies >= crate::scan::AHEAD)
    }

    /// Requests sent to the destination other than batch lookups: any of
    /// them may have changed what a lookup sent before it saw.
    pub(super) fn other_requests(&self) -> u64 {
        self.dst
            .requests_sent()
            .map_or(0, |sent| sent.wrapping_sub(self.early_lookups.sent))
    }

    pub(super) fn count_batch_lookup(&mut self) {
        self.early_lookups.sent += 1;
    }

    /// The scan has `entries` complete, to be planned after the batches
    /// shown before it: look its destinations up now if that is useful.
    pub(super) fn show_upcoming(&mut self, entries: &[Entry], sub: &[u8], dst_root: &[u8]) {
        let mut directories = Vec::new();
        let mut others = Vec::new();
        // `map_batch` joins the same three parts, the last two first.
        let base = join(dst_root, sub);
        for entry in entries {
            let list = match self.claim_for(entry) {
                Some(Claim::Dir) => &mut directories,
                Some(Claim::File { .. } | Claim::Leaf) => &mut others,
                Some(Claim::Weak) | None => continue,
            };
            list.push(join(&base, &entry.path));
        }
        self.early_lookups.shown.push_back(EarlyLookup {
            directories,
            others,
            reply: None,
        });
        self.send_early_lookups();
    }

    /// The next shown batch, whose turn has come.
    pub(super) fn next_early_lookup(&mut self) -> Option<EarlyLookup> {
        self.early_lookups.shown.pop_front()
    }

    /// Send the lookups of shown batches that have none in flight.
    fn send_early_lookups(&mut self) {
        if !self.early_lookups.quiet || !self.looks_up_batches() || self.collision {
            return;
        }
        let strict_metadata = self.opts.expressions.update.is_some();
        let after = self.other_requests();
        for early in self.early_lookups.shown.iter_mut().take(crate::scan::AHEAD) {
            if early.reply.is_some() || (early.directories.is_empty() && early.others.is_empty()) {
                continue;
            }
            // A failure to send is reported by the batch's lookup in turn.
            let Ok(reply) = self.dst.send_pending(Request::PlanBatch {
                directories: early.directories.clone(),
                others: early.others.clone(),
                strict_metadata,
            }) else {
                return;
            };
            self.early_lookups.sent += 1;
            early.reply = Some((reply, after));
            #[cfg(debug_assertions)]
            let _ = crate::fsops::record_test_event(
                "SYQ_TEST_EARLY_LOOKUPS",
                format_args!("sent {} {}", early.directories.len(), early.others.len()),
            );
        }
    }

    /// The reply to `early` with the paths it asked about, if those are
    /// exactly the batch's as mapped and nothing else was sent to the
    /// destination since. None leaves the batch to ask in its turn, which
    /// also reports a lookup that failed.
    pub(super) fn early_reply(
        &mut self,
        early: EarlyLookup,
        mapped: &Mapped,
    ) -> Option<(Vec<PathBytes>, Vec<PathBytes>, Response)> {
        let (reply, after) = early.reply?;
        // Taken whether or not it is used, so that it is not kept.
        let response = self.dst.take_reply(reply);
        let current = after == self.other_requests()
            && early
                .directories
                .iter()
                .eq(mapped.dirs.iter().map(|(path, _, _)| path))
            && early
                .others
                .iter()
                .eq(mapped.others.iter().map(|planned| &planned.dst));
        let response = response
            .ok()
            .filter(|response| current && matches!(response, Response::BatchPlan { .. }));
        #[cfg(debug_assertions)]
        let _ = crate::fsops::record_test_event(
            "SYQ_TEST_EARLY_LOOKUPS",
            format_args!(
                "{}",
                if response.is_some() {
                    "used"
                } else {
                    "repeated"
                }
            ),
        );
        Some((early.directories, early.others, response?))
    }

    /// Take and drop the reply to a lookup that will not be used.
    pub(super) fn discard_early_lookup(&mut self, early: EarlyLookup) {
        if let Some((reply, _)) = early.reply {
            let _ = self.dst.take_reply(reply);
            #[cfg(debug_assertions)]
            let _ = crate::fsops::record_test_event(
                "SYQ_TEST_EARLY_LOOKUPS",
                format_args!("discarded"),
            );
        }
    }

    /// Take and drop the replies to the lookups in flight: the destination
    /// is about to be, or has been, sent something they did not see. Their
    /// batches stay shown, to be looked up again.
    pub(super) fn withdraw_early_lookups(&mut self) {
        for early in &mut self.early_lookups.shown {
            if let Some((reply, _)) = early.reply.take() {
                let _ = self.dst.take_reply(reply);
                #[cfg(debug_assertions)]
                let _ = crate::fsops::record_test_event(
                    "SYQ_TEST_EARLY_LOOKUPS",
                    format_args!("withdrawn"),
                );
            }
        }
    }

    /// The scan that showed batches has ended: none is planned any more.
    pub(super) fn drop_early_lookups(&mut self) {
        self.withdraw_early_lookups();
        self.early_lookups.shown.clear();
    }

    /// A batch has been planned, having sent `before` other requests when
    /// it started. Lookups in flight are stale if it sent any; otherwise
    /// the shown batches without one are looked up.
    pub(super) fn batch_planned(&mut self, before: u64) {
        let quiet = self.other_requests() == before;
        if !quiet {
            self.withdraw_early_lookups();
        }
        self.early_lookups.quiet = quiet;
        self.send_early_lookups();
    }
}

//! Publishing a file without waiting for its round trips.
//!
//! A file written in ranges is published in two steps once its last write is
//! acknowledged: the source is checked again (a stat after its last read),
//! and only if it is unchanged does the destination publish it (`Finalize`).
//! Each step is a round trip. Rather than wait for them, a worker sends the
//! step's request and starts its next file; its next requests travel behind
//! it on the same connection, so their round trips overlap. The worker
//! settles each publication, in the order the publications began, once its
//! reply has arrived: after the next file's `Prepare` reply, which follows
//! it, between items, and before it waits for work, is parked, or leaves.
//!
//! Nothing a publication guarantees changes. Its source is still checked
//! after every read of the file has completed, and the destination publishes
//! it only after that check, which a change still sends back to be copied
//! again. Its success, failure and result record are reported as before,
//! once its reply arrives. The copy's later work (hard links, deletion,
//! directory metadata) waits for every worker to leave, so for every
//! publication. A worker whose connection drops finishes the publications
//! whose `Finalize` reply it has already read, and queues the rest again, as
//! a lost `Finalize` reply already is.

use super::*;
use crate::conn::PendingReply;

/// Publications a worker may have in flight while it starts further work.
/// Two let a publication that waits on both connections (a remote source's
/// check, then a remote destination's `Finalize`) overlap the next file's
/// work in each, and keep at most three files per worker unfinished at the
/// destination (`fsops::stages`).
const DEFERRED_PUBLICATIONS: usize = 2;

/// A file whose publication is in flight.
pub(super) struct Publication {
    idx: usize,
    job: WorkerJob,
    /// The destination already holds the file's contents and metadata: only
    /// the source check remains.
    matched: bool,
    earlier_partials: bool,
    stage: Stage,
}

enum Stage {
    /// Waiting for the source's attributes after its last read.
    Rechecking(PendingReply),
    /// Waiting for the destination's reply to `Finalize`.
    Finalizing(PendingReply),
}

/// The request that checks the source again before publication.
fn source_recheck_request(job: &WorkerJob) -> Request {
    Request::StatMany {
        paths: vec![job.src.clone()],
        sources: Some(vec![job.source.clone()]),
        follow: false,
    }
}

fn source_recheck_reply(response: Response) -> Result<Option<Entry>> {
    match ok(response, "stat")? {
        Response::Stats(mut entries) if entries.len() == 1 => Ok(entries.pop().flatten()),
        other => bail!("unexpected response {other:?}"),
    }
}

impl Worker {
    /// Publish the file at `idx`, whose contents are complete at the
    /// destination, without waiting for the round trips: as
    /// `finish_file` does, or, when `matched`, as `finish_matched_file`
    /// does. A failure of this file is reported here; an error returned
    /// means this worker's connection failed, and the file is queued to be
    /// published again.
    pub(super) fn publish(&mut self, idx: usize, matched: bool) -> Result<()> {
        let room = self.settle_publications(false).and_then(|()| {
            while self.publications.len() >= DEFERRED_PUBLICATIONS {
                self.settle_oldest_publication()?;
            }
            Ok(())
        });
        if let Err(error) = room {
            return self.publication_failed(idx, matched, error);
        }
        let begun = self.publication_checks(idx, matched).and_then(|checked| {
            let Some((job, earlier_partials)) = checked else {
                return Ok(None);
            };
            let stat = self.src.send_pending(source_recheck_request(&job))?;
            Ok(Some(Publication {
                idx,
                job,
                matched,
                earlier_partials,
                stage: Stage::Rechecking(stat),
            }))
        });
        match begun {
            Ok(Some(publication)) => self.publications.push_back(publication),
            Ok(None) => return Ok(()),
            Err(error) => return self.publication_failed(idx, matched, error),
        }
        // A local source has already answered: send Finalize now, so that
        // it shares its round trip with the next file's first request.
        self.settle_publications(false)
    }

    /// The file at `idx` and whether earlier copies left partials of it,
    /// when it is still to be published.
    pub(super) fn publication_checks(
        &self,
        idx: usize,
        matched: bool,
    ) -> Result<Option<(WorkerJob, bool)>> {
        if matched {
            if self.sched.is_failed(idx) {
                return Ok(None);
            }
            return Ok(Some((self.job(idx), false)));
        }
        if self.sched.is_failed(idx) || self.sched.is_aborted() {
            return Ok(None);
        }
        let (job, mut earlier_partials) = {
            let jobs = self.sched.jobs.lock().unwrap();
            (jobs.snapshot(idx), jobs.has_earlier_partials(idx))
        };
        // A source file this copy writes beside it, named as one of its
        // partials, is not an earlier copy's: the receiver then removes none.
        if earlier_partials && self.writes_partial_named_payload_for(&job.dst) {
            earlier_partials = false;
        }
        if job.done.load(Relaxed) != job.entry.size {
            bail!("refusing to publish an incomplete file");
        }
        #[cfg(debug_assertions)]
        crate::fsops::test_race_barrier(
            "SYQ_TEST_SOURCE_RECHECK_READY_FILE",
            "SYQ_TEST_SOURCE_RECHECK_CONTINUE_FILE",
            "source recheck before publication",
        )?;
        Ok(Some((job, earlier_partials)))
    }

    /// Settle publications in the order they began: each whose reply has
    /// arrived, or, when `wait`, every one. Settling happens only between
    /// operations, when neither connection has other requests outstanding.
    pub(super) fn settle_publications(&mut self, wait: bool) -> Result<()> {
        while let Some(oldest) = self.publications.front() {
            let arrived = match &oldest.stage {
                Stage::Rechecking(reply) => self.src.reply_arrived(reply),
                Stage::Finalizing(reply) => self.dst.reply_arrived(reply),
            };
            if !(arrived || wait) {
                break;
            }
            self.settle_oldest_publication()?;
        }
        Ok(())
    }

    /// Settle publications between items, as work that the tuner waits for:
    /// those whose replies have arrived, or, when `wait`, every one, as this
    /// worker does before it waits, parks or leaves.
    pub(super) fn settle_between_items(&mut self, wait: bool) -> Result<()> {
        if self.publications.is_empty() {
            return Ok(());
        }
        let _work = self.gate.work(self.id);
        let progress = self.progress.clone();
        let _copying = progress.copying_interval();
        self.settle_publications(wait)
    }

    /// Take the oldest publication one step, waiting for its reply.
    fn settle_oldest_publication(&mut self) -> Result<()> {
        let publication = self
            .publications
            .pop_front()
            .expect("a publication in flight");
        let (idx, matched) = (publication.idx, publication.matched);
        match self.advance_publication(publication) {
            Ok(Some(next)) => {
                self.publications.push_front(next);
                Ok(())
            }
            Ok(None) => Ok(()),
            Err(error) => self.publication_failed(idx, matched, error),
        }
    }

    fn advance_publication(&mut self, publication: Publication) -> Result<Option<Publication>> {
        let Publication {
            idx,
            job,
            matched,
            earlier_partials,
            stage,
        } = publication;
        match stage {
            Stage::Rechecking(reply) => {
                let response = self.src.take_reply(reply)?;
                // A copy that failed or was cancelled meanwhile publishes
                // nothing more, as one that ended before the check.
                if self.sched.is_failed(idx) || (!matched && self.sched.is_aborted()) {
                    return Ok(None);
                }
                let now = source_recheck_reply(response)?;
                if !self.source_unchanged(idx, &job, matched || job.inplace, now)? {
                    return Ok(None);
                }
                if matched {
                    self.complete_file(job, true)?;
                    return Ok(None);
                }
                let reply = self
                    .dst
                    .send_pending(self.finalize_request(&job, earlier_partials))?;
                Ok(Some(Publication {
                    idx,
                    job,
                    matched,
                    earlier_partials,
                    stage: Stage::Finalizing(reply),
                }))
            }
            Stage::Finalizing(reply) => {
                let response = self.dst.take_reply(reply)?;
                self.finalized(idx, job, earlier_partials, response)?;
                Ok(None)
            }
        }
    }

    /// Report a failure to publish the file at `idx`, queuing it to be
    /// published again when this worker's connection failed.
    fn publication_failed(
        &mut self,
        idx: usize,
        matched: bool,
        error: anyhow::Error,
    ) -> Result<()> {
        if self.transport_dead() {
            self.sched.requeue_finish(idx, matched);
        }
        self.file_error(idx, error)
    }

    /// This worker is leaving after `error`. When its connection failed,
    /// finish the publications whose Finalize reply has already arrived and
    /// queue the rest again; after another error, which cancels the copy,
    /// collect the replies of those already sent, unless a malformed reply
    /// makes its connections unusable.
    pub(super) fn abandon_publications(&mut self, error: &anyhow::Error) {
        if self.publications.is_empty() {
            return;
        }
        let malformed = error.is::<RangeReplyMismatch>();
        if malformed {
            // Nothing more is read from these connections.
        } else if self.transport_dead() {
            // A reply already read needs no connection. A publication still
            // checking its source is never ahead of one being finalized.
            while self.publications.front().is_some_and(|oldest| {
                matches!(&oldest.stage, Stage::Finalizing(reply) if self.dst.reply_arrived(reply))
            }) {
                // A failure queues the publication it concerns again.
                if self.settle_oldest_publication().is_err() {
                    break;
                }
            }
        } else {
            // A failure here queues the publication it concerns again.
            let _ = self.settle_publications(true);
        }
        for publication in std::mem::take(&mut self.publications) {
            if !malformed {
                self.sched
                    .requeue_finish(publication.idx, publication.matched);
            }
        }
    }
}

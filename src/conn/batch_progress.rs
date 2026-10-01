//! Credit batch acknowledgments when the existing connection reader receives
//! them, even while the worker is blocked sending later requests.
use crate::progress::Progress;
use crate::proto::{Request, Response};
use anyhow::Result;
use std::collections::VecDeque;
use std::sync::atomic::{
    AtomicBool,
    Ordering::{Acquire, Relaxed, Release},
};
use std::sync::{Arc, Mutex};

#[derive(Default)]
pub(super) struct BatchReceipts {
    enabled: AtomicBool,
    active: Mutex<Option<Active>>,
}
struct Active {
    progress: Arc<Progress>,
    pending: VecDeque<Vec<u64>>,
    received: VecDeque<(u64, u64)>,
}

/// The caller enters with no outstanding destination requests and issues only
/// PutSmallBatch until this scope ends. Dropping it retracts receipts the
/// worker never consumed; consumed receipts keep the usual file retry rules.
/// After a failed drain the connection must be discarded, as for other RPCs.
pub(crate) struct BatchProgress(Arc<BatchReceipts>);
impl BatchReceipts {
    pub(super) fn begin(self: &Arc<Self>, progress: Arc<Progress>) -> Result<BatchProgress> {
        let mut active = self.active.lock().unwrap();
        anyhow::ensure!(active.is_none(), "batch progress already active");
        *active = Some(Active {
            progress,
            pending: VecDeque::new(),
            received: VecDeque::new(),
        });
        self.enabled.store(true, Release);
        Ok(BatchProgress(self.clone()))
    }

    pub(super) fn request(&self, request: &Request) -> Result<()> {
        if !self.enabled.load(Acquire) {
            return Ok(());
        }
        let mut active = self.active.lock().unwrap();
        if let Some(active) = active.as_mut() {
            let Request::PutSmallBatch(puts) = request else {
                anyhow::bail!("only batch writes are valid while batch progress is active");
            };
            // Register before writing: a fast helper may reply before send returns.
            active
                .pending
                .push_back(puts.iter().map(|put| put.data.len() as u64).collect());
        }
        Ok(())
    }

    pub(super) fn response(&self, response: &Response) {
        if !self.enabled.load(Acquire) {
            return;
        }
        let mut active = self.active.lock().unwrap();
        let Some(active) = active.as_mut() else {
            return;
        };
        let Some(sizes) = active.pending.pop_front() else {
            return;
        };
        let credit = match response {
            Response::PublishedBatch(results) if results.len() == sizes.len() => {
                totals(&sizes, results.iter().map(Result::is_ok))
            }
            Response::Applied(errors) if errors.len() == sizes.len() => {
                totals(&sizes, errors.iter().map(Option::is_none))
            }
            // Invalid or rejected replies are still consumed by the worker,
            // which reports the error. They do not earn any progress credit.
            _ => (0, 0),
        };
        active.progress.add_bytes(credit.0);
        active.progress.add_tuning_files(credit.1);
        active.received.push_back(credit);
    }
}
fn totals(sizes: &[u64], success: impl Iterator<Item = bool>) -> (u64, u64) {
    sizes
        .iter()
        .zip(success)
        .filter(|(_, ok)| *ok)
        .fold((0, 0), |(bytes, files), (size, _)| {
            (bytes + size, files + 1)
        })
}
impl BatchProgress {
    pub(crate) fn consume(&self) -> Result<()> {
        let mut active = self.0.active.lock().unwrap();
        let active = active.as_mut().expect("batch progress scope active");
        anyhow::ensure!(
            active.received.pop_front().is_some(),
            "unregistered batch reply"
        );
        Ok(())
    }
}
impl Drop for BatchProgress {
    fn drop(&mut self) {
        self.0.enabled.store(false, Release);
        if let Some(active) = self.0.active.lock().unwrap().take() {
            let (bytes, files) = active
                .received
                .iter()
                .fold((0, 0), |(b, f), (db, df)| (b + db, f + df));
            active.progress.bytes_done.fetch_sub(bytes, Relaxed);
            active.progress.undo_tuning_files(files);
        }
    }
}

#[cfg(test)]
pub(super) fn test_request(sizes: &[usize]) -> Request {
    use crate::proto::{Meta, SmallPut, TargetCondition};
    Request::PutSmallBatch(
        sizes
            .iter()
            .map(|&size| SmallPut {
                path: b"file".to_vec(),
                copy_id: [0; 16],
                data: vec![42; size],
                hash: [0; 32],
                meta: Meta {
                    mode: 0o600,
                    uid: 0,
                    gid: 0,
                    mtime: 0,
                    mtime_nsec: 0,
                    inode_metadata: None,
                },
                flags: 0,
                inplace: false,
                condition: TargetCondition::Any,
                guard: None,
                replaces: false,
            })
            .collect(),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::tune::Meter;

    #[test]
    fn receipts_credit_only_valid_successes_including_empty_files() {
        for response in [
            Response::PublishedBatch(vec![Ok(None), Err("denied".into()), Ok(Some((1, 2)))]),
            Response::Applied(vec![None, Some("denied".into()), None]),
        ] {
            let receipts = Arc::new(BatchReceipts::default());
            let progress = Progress::new(false, false, None);
            let scope = receipts.begin(progress.clone()).unwrap();
            receipts.request(&test_request(&[16, 32, 0])).unwrap();
            assert_eq!(Meter::bytes(&*progress), 0, "sending is not progress");
            receipts.response(&response);
            assert_eq!(progress.bytes_done.load(Relaxed), 16);
            assert_eq!(Meter::files(&*progress), 2);
            assert_eq!(
                progress.files_done.load(Relaxed),
                0,
                "source validation is still pending"
            );
            scope.consume().unwrap();
            drop(scope);
            assert_eq!(
                progress.bytes_done.load(Relaxed),
                16,
                "no duplicate credit on consumption"
            );
        }
    }

    #[test]
    fn rejected_or_malformed_receipts_do_not_count_as_work() {
        for response in [
            Response::Err("denied".into()),
            Response::Ok,
            Response::Applied(vec![]),
            Response::PublishedBatch(vec![Ok(None), Ok(None)]),
            Response::PublishedBatch(vec![Err("denied".into())]),
        ] {
            let receipts = Arc::new(BatchReceipts::default());
            let progress = Progress::new(false, false, None);
            let scope = receipts.begin(progress.clone()).unwrap();
            receipts.request(&test_request(&[32])).unwrap();
            receipts.response(&response);
            scope.consume().unwrap();
            drop(scope);
            assert_eq!(Meter::bytes(&*progress), 0);
            assert_eq!(Meter::files(&*progress), 0);
        }
    }

    #[test]
    fn interrupted_scope_retracts_unconsumed_receipts_and_retry_does_not_double_count() {
        let receipts = Arc::new(BatchReceipts::default());
        let progress = Progress::new(false, false, None);
        let scope = receipts.begin(progress.clone()).unwrap();
        assert!(receipts.begin(progress.clone()).is_err());
        assert!(receipts.request(&Request::Shutdown).is_err());
        for size in [16, 32, 64] {
            receipts.request(&test_request(&[size])).unwrap();
        }
        let success = Response::PublishedBatch(vec![Ok(None)]);
        receipts.response(&success);
        scope.consume().unwrap();
        receipts.response(&success);
        drop(scope); // Third request was never acknowledged; second was not consumed.
        assert_eq!(progress.bytes_done.load(Relaxed), 16);
        receipts.response(&success); // A late reply cannot add credit after scope teardown.
        assert_eq!(progress.bytes_done.load(Relaxed), 16);
        assert_eq!(Meter::bytes(&*progress), 48);
        assert_eq!(Meter::files(&*progress), 2);
        let retry = receipts.begin(progress.clone()).unwrap();
        receipts.request(&test_request(&[32])).unwrap();
        receipts.response(&success);
        retry.consume().unwrap();
        assert_eq!(progress.bytes_done.load(Relaxed), 48);
        assert_eq!(
            Meter::bytes(&*progress),
            48,
            "retry catches up to the previous high water mark"
        );
        assert_eq!(Meter::files(&*progress), 2);
    }
}

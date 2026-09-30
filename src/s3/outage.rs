//! Stop a batch when S3 stops answering, instead of spending every object's
//! retries on a service that is down.
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering::Relaxed};

/// Requests that fail after their retries without an answer from the service,
/// with none answered in between, before a batch stops. A partial outage or
/// throttling that still lets some requests through never reaches this.
pub(crate) const LIMIT: u32 = 8;

#[derive(Debug, Default)]
pub(crate) struct Outage {
    failures: AtomicU32,
    stopped: AtomicBool,
    notify: tokio::sync::Notify,
}

impl Outage {
    /// The service answered, even with an error such as 404 or 403.
    pub(crate) fn responded(&self) {
        self.failures.store(0, Relaxed);
    }

    /// Report a failed request: `retryable` when its retry policy would have
    /// tried it again, so it ran out of retries rather than got an answer.
    pub(crate) fn failed(&self, retryable: bool) {
        if retryable {
            self.exhausted();
        } else {
            self.responded();
        }
    }

    /// A request failed on errors its retries are meant for, such as no
    /// connection, a timeout, a server error, or throttling, until it gave up.
    pub(crate) fn exhausted(&self) {
        if self.failures.fetch_add(1, Relaxed) + 1 >= LIMIT && !self.stopped.swap(true, Relaxed) {
            // The batch has one waiter; a stored permit covers a later wait.
            self.notify.notify_one();
        }
    }

    /// Completes once the batch should stop.
    pub(crate) async fn stopped(&self) {
        self.notify.notified().await;
    }

    pub(crate) fn message() -> String {
        format!(
            "{LIMIT} S3 requests in a row failed after all their retries, each with no connection, a timeout, or a server error or throttling response; stopping because the service appears unavailable. Rerun the command to continue"
        )
    }
}

/// HTTP statuses that mean "try again later" rather than an answer.
pub(crate) fn transient_status(status: u16) -> bool {
    matches!(status, 408 | 429 | 500 | 502 | 503 | 504)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stops_only_after_consecutive_exhausted_requests() {
        let outage = Outage::default();
        for _ in 0..LIMIT - 1 {
            outage.exhausted();
        }
        outage.responded();
        for _ in 0..LIMIT - 1 {
            outage.exhausted();
        }
        assert!(!outage.stopped.load(Relaxed));
        outage.exhausted();
        assert!(outage.stopped.load(Relaxed));
        // The permit is kept for a waiter that arrives later.
        tokio::time::timeout(std::time::Duration::from_secs(1), outage.stopped())
            .await
            .unwrap();
        // Later failures do not notify again.
        outage.exhausted();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), outage.stopped())
                .await
                .is_err()
        );
    }
}

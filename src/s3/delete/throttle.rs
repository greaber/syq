//! Per-run deletion feedback; request retries and their delays stay with the SDK.
use aws_smithy_runtime_api::{
    box_error::BoxError,
    client::{
        interceptors::{
            context::{BeforeTransmitInterceptorContextRef, FinalizerInterceptorContextRef},
            Intercept,
        },
        retries::{
            classifiers::{RetryAction, RetryReason},
            RequestAttempts,
        },
        runtime_components::RuntimeComponents,
    },
};
use aws_smithy_types::{
    config_bag::{ConfigBag, Storable, StoreReplace},
    retry::ErrorKind,
};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::time::Instant;

const SAMPLE: Duration = Duration::from_millis(250);
#[derive(Debug)]
struct Window {
    since: Instant,
    latency: Duration,
    succeeded: f64,
    fresh_keys: usize,
    fresh_throttled: usize,
    throttled_attempts: usize,
    suggested: Option<usize>,
}
#[derive(Debug)]
pub(super) struct Throttle {
    state: Mutex<Window>,
}
impl Throttle {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(Window {
                since: Instant::now(),
                latency: Duration::MAX,
                succeeded: 0.0,
                fresh_keys: 0,
                fresh_throttled: 0,
                throttled_attempts: 0,
                suggested: None,
            }),
        })
    }
    pub fn take_limit(&self, current: usize) -> Option<usize> {
        self.state
            .lock()
            .unwrap()
            .suggested
            .take()
            .filter(|limit| *limit < current)
    }
    pub fn observe(
        &self,
        keys: usize,
        fresh: bool,
        successful: usize,
        throttled: usize,
        elapsed: Duration,
    ) {
        let mut s = self.state.lock().unwrap();
        s.succeeded += successful as f64 / keys.max(1) as f64;
        if successful > 0 {
            s.latency = s.latency.min(elapsed);
        }
        if fresh {
            s.fresh_keys += keys;
            s.fresh_throttled += throttled;
        }
        // Require independent requests that made no progress. Partial bulk
        // successes and retries of previously busy keys do not establish a
        // limit on unrelated new work.
        if fresh && throttled == keys && throttled > 0 {
            s.throttled_attempts += 1;
        }
        // React to widespread rejection of new requests, not the repeated
        // failures of a few selected keys. Observe the initial wave before
        // retry sleeps can turn its throughput into an artificially low rate.
        let pressure =
            s.throttled_attempts >= 4 && s.fresh_throttled * 2 >= s.fresh_keys && s.succeeded > 0.0;
        if !pressure && s.since.elapsed() < SAMPLE {
            return;
        }
        if pressure {
            let capacity = (s.succeeded / s.since.elapsed().as_secs_f64() * s.latency.as_secs_f64())
                .ceil() as usize;
            s.suggested = Some(s.suggested.map_or(capacity, |cap| cap.min(capacity)).max(1));
            #[cfg(debug_assertions)]
            if std::env::var_os("SYQ_TEST_DELETE_TUNING").is_some() {
                eprintln!("S3 deletion throttling cap={}", s.suggested.unwrap());
            }
        }
        s.since = Instant::now();
        s.succeeded = 0.0;
        s.fresh_keys = 0;
        s.fresh_throttled = 0;
        s.throttled_attempts = 0;
    }
    pub fn observer(self: &Arc<Self>, keys: usize, fresh: bool) -> Observe {
        Observe {
            throttle: self.clone(),
            keys,
            fresh,
        }
    }
}
#[derive(Debug)]
struct Started(Instant);
impl Storable for Started {
    type Storer = StoreReplace<Self>;
}
#[derive(Debug)]
pub(super) struct Observe {
    throttle: Arc<Throttle>,
    keys: usize,
    fresh: bool,
}
impl Intercept for Observe {
    fn name(&self) -> &'static str {
        "S3DeletionThrottleFeedback"
    }
    fn read_before_transmit(
        &self,
        _: &BeforeTransmitInterceptorContextRef<'_>,
        _: &RuntimeComponents,
        cfg: &mut ConfigBag,
    ) -> Result<(), BoxError> {
        cfg.interceptor_state().store_put(Started(Instant::now()));
        Ok(())
    }
    fn read_after_attempt(
        &self,
        context: &FinalizerInterceptorContextRef<'_>,
        components: &RuntimeComponents,
        cfg: &mut ConfigBag,
    ) -> Result<(), BoxError> {
        let Some(started) = cfg.load::<Started>() else {
            return Ok(());
        };
        let (success, throttled) = match context.output_or_error() {
            Some(Ok(output)) => {
                if let Some(output) = output
                    .downcast_ref::<aws_sdk_s3::operation::delete_objects::DeleteObjectsOutput>(
                ) {
                    let throttled = output
                        .errors()
                        .iter()
                        .filter(|e| crate::s3::retry::throttled(e.code(), None))
                        .count()
                        .min(self.keys);
                    (output.deleted().len().min(self.keys), throttled)
                } else {
                    (self.keys, 0)
                }
            }
            _ => {
                let action =
                    aws_smithy_runtime::client::retries::classifiers::run_classifiers_on_ctx(
                        components.retry_classifiers(),
                        context.inner(),
                    );
                let throttled = context
                    .response()
                    .is_some_and(|r| r.status().as_u16() == 429)
                    || matches!(
                        action,
                        RetryAction::RetryIndicated(RetryReason::RetryableError {
                            kind: ErrorKind::ThrottlingError,
                            ..
                        })
                    );
                if !throttled {
                    return Ok(());
                }
                (0, self.keys)
            }
        };
        let fresh = self.fresh
            && cfg
                .load::<RequestAttempts>()
                .is_some_and(|n| n.attempts() == 1);
        self.throttle
            .observe(self.keys, fresh, success, throttled, started.0.elapsed());
        Ok(())
    }
}

#[cfg(test)]
mod tests;

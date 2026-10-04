//! Bounded retries for parallel S3 work. Keep admission slots while backing off.
use aws_sdk_s3::error::{ProvideErrorMetadata, SdkError};
use aws_smithy_runtime::client::retries::{RetryPartition, TokenBucket};
use aws_smithy_runtime_api::client::orchestrator::HttpResponse;
use std::time::Duration;

/// The SDK's shared retry quota can reject retries after just one attempt in a
/// large batch, or after repeated throttling even at low concurrency. Bound work
/// with the configured per-request attempts and existing admission/outage limits
/// instead. A retry continues holding its caller's request slot during backoff.
pub(super) fn partition() -> RetryPartition {
    RetryPartition::custom("syq-s3")
        .token_bucket(TokenBucket::unlimited())
        .build()
}

pub(super) fn throttled(code: Option<&str>, status: Option<u16>) -> bool {
    status == Some(429)
        || code.is_some_and(|code| {
            aws_runtime::retries::classifiers::THROTTLING_ERRORS.contains(&code)
        })
}

pub(super) fn delay(attempt: u32, throttled: bool) -> Duration {
    // Preserve a minimum delay for transport/body failures while spreading out
    // retries from concurrent requests. Throttling uses the SDK's 1-second base.
    let base = if throttled { 1000u64 } else { 100 };
    let minimum = base.saturating_mul(1 << attempt.min(8)).min(10_000);
    let maximum = (minimum * 2).min(20_000);
    let mut random = [0; 8];
    // Missing entropy must not prevent recovery; the minimum is still bounded.
    let _ = getrandom::fill(&mut random);
    Duration::from_millis(minimum + u64::from_ne_bytes(random) % (maximum - minimum + 1))
}

pub(super) fn error_delay<E: ProvideErrorMetadata>(
    attempt: u32,
    error: &SdkError<E, HttpResponse>,
) -> Duration {
    let code = error.as_service_error().and_then(|error| error.code());
    let response = error.raw_response();
    let delay = delay(
        attempt,
        throttled(code, response.map(|r| r.status().as_u16())),
    );
    let Some(response) = response else {
        return delay;
    };
    server_delay(response).map_or(delay, |hint| delay.max(hint))
}

pub(super) fn server_delay(response: &HttpResponse) -> Option<Duration> {
    let headers = response.headers();
    let hint = headers
        .get("x-amz-retry-after")
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_millis)
        .or_else(|| headers.get("retry-after").and_then(retry_after));
    // As with SDK retries, cap a server-suggested delay. Invalid hints are ignored.
    hint.map(|hint| hint.min(Duration::from_secs(20)))
}

fn retry_after(value: &str) -> Option<Duration> {
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    let date =
        time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc2822).ok()?;
    (date - time::OffsetDateTime::now_utc()).try_into().ok()
}

pub(super) async fn after_error<E: ProvideErrorMetadata>(
    attempt: u32,
    error: &SdkError<E, HttpResponse>,
) {
    tokio::time::sleep(error_delay(attempt, error)).await;
}

#[cfg(test)]
mod tests;

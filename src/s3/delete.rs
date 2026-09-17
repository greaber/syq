//! Shared bounded S3 deletion with one outcome per requested key/version.
use super::{client, tuning::Budget};
use anyhow::Result;
use aws_sdk_s3::{
    error::ProvideErrorMetadata,
    types::{Delete, ObjectIdentifier},
    Client,
};
use futures_util::{stream, StreamExt};
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub(super) struct Target {
    pub key: String,
    pub version: Option<String>,
}

#[derive(Clone, Debug)]
pub(super) struct Failure {
    pub message: String,
    pub class: &'static str,
    pub retryable: &'static str,
    pub os_kind: Option<&'static str>,
    // Counts bulk operations; SDK transport retries remain internal.
    pub attempts: u64,
}
impl Failure {
    fn new(message: String, code: Option<&str>, status: Option<u16>) -> Self {
        let (class, retryable, os_kind) = failure_classification(code, status);
        Self {
            message,
            class,
            retryable,
            os_kind,
            attempts: 1,
        }
    }
    pub fn preserved_marker() -> Self {
        Self {
            message:
                "delete marker preserved because selected data versions could not all be removed"
                    .into(),
            class: "conflict",
            // Retrying depends on resolving the preceding data-version failure.
            retryable: "unknown",
            os_kind: None,
            attempts: 0,
        }
    }
}
fn failure_classification(
    code: Option<&str>,
    status: Option<u16>,
) -> (&'static str, &'static str, Option<&'static str>) {
    match code {
        Some("AccessDenied" | "InvalidAccessKeyId" | "SignatureDoesNotMatch") => {
            ("io", "no", Some("permission_denied"))
        }
        Some("NoSuchBucket") => ("io", "no", Some("not_found")),
        Some("InvalidArgument" | "InvalidRequest" | "InvalidBucketName") => {
            ("usage", "no", Some("invalid_input"))
        }
        Some("SlowDown" | "Throttling" | "ThrottlingException" | "RequestTimeout") => {
            ("transport", "yes", None)
        }
        _ => match status {
            Some(403) => ("io", "no", Some("permission_denied")),
            Some(429 | 500 | 502 | 503 | 504) => ("transport", "yes", None),
            _ => ("transport", "unknown", None),
        },
    }
}

pub(super) struct Deleter<'a> {
    pub client: &'a Client,
    pub bucket: &'a str,
    pub budget: &'a std::sync::Arc<Budget>,
}
impl Deleter<'_> {
    pub async fn run<T>(
        &self,
        items: &[T],
        identify: impl Fn(&T) -> Target,
        check: impl Fn() -> Result<()>,
        mut finished: impl FnMut(&T, std::result::Result<(), Failure>),
    ) -> Result<()> {
        let mut batches = stream::iter(items.chunks(1000).map(|batch| {
            let identify = &identify;
            let check = &check;
            async move {
                let _slot = self.budget.acquire().await;
                check()?;
                let targets: Vec<_> = batch.iter().map(identify).collect();
                let outcomes = self.batch(&targets).await;
                Ok::<_, anyhow::Error>((batch, outcomes))
            }
        }))
        .buffer_unordered(10);
        let mut failure = None;
        // Stop starting requests when check fails, but drain all started ones.
        while let Some(result) = batches.next().await {
            match result {
                Ok((batch, outcomes)) => {
                    for (item, outcome) in batch.iter().zip(outcomes) {
                        finished(item, outcome);
                    }
                }
                Err(error) => {
                    failure.get_or_insert(error);
                }
            }
        }
        failure.map_or(Ok(()), Err)
    }

    async fn batch(&self, targets: &[Target]) -> Vec<std::result::Result<(), Failure>> {
        let objects = targets
            .iter()
            .map(|t| {
                ObjectIdentifier::builder()
                    .key(&t.key)
                    .set_version_id(t.version.clone())
                    .build()
                    .expect("key provided")
            })
            .collect();
        let result = self
            .client
            .delete_objects()
            .bucket(self.bucket)
            .delete(
                Delete::builder()
                    .set_objects(Some(objects))
                    .quiet(false)
                    .build()
                    .expect("objects provided"),
            )
            .send()
            .await;
        match result {
            Err(error) => {
                let message = format!("{}: {error}", client::failure("S3 removal", &error));
                let failure = Failure::new(
                    message,
                    error.as_service_error().and_then(|e| e.code()),
                    error.raw_response().map(|r| r.status().as_u16()),
                );
                targets.iter().map(|_| Err(failure.clone())).collect()
            }
            Ok(output) => {
                let errors: HashMap<_, _> = output
                    .errors()
                    .iter()
                    .filter_map(|e| e.key().map(|key| ((key, e.version_id()), e)))
                    .collect();
                let deleted: HashSet<_> = output
                    .deleted()
                    .iter()
                    .filter_map(|d| d.key().map(|key| (key, d.version_id())))
                    .collect();
                targets
                    .iter()
                    .map(|target| {
                        let mut id = (target.key.as_str(), target.version.as_deref());
                        // MinIO omits VersionId when acknowledging the literal null
                        // version. Do not relax identity matching for other versions.
                        if target.version.as_deref() == Some("null")
                            && !errors.contains_key(&id)
                            && !deleted.contains(&id)
                        {
                            id = (target.key.as_str(), None);
                        }
                        if let Some(error) = errors.get(&id) {
                            Err(Failure::new(
                                format!(
                                    "{}: {}",
                                    error.code().unwrap_or("S3 deletion error"),
                                    error.message().unwrap_or("")
                                ),
                                error.code(),
                                None,
                            ))
                        } else if deleted.contains(&id) {
                            Ok(())
                        } else {
                            Err(Failure::new(
                                format!(
                                    "S3 deletion response omitted key {:?} version {:?}",
                                    target.key, target.version
                                ),
                                None,
                                None,
                            ))
                        }
                    })
                    .collect()
            }
        }
    }
}

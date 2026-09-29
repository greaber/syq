//! Job identities use response metadata already obtained by the transfer.
use crate::cli::Args;

pub(super) fn key(bucket: &str, key: &str, version: Option<&str>) -> Vec<u8> {
    format!("s3\0{bucket}\0{key}\0{}", version.unwrap_or("")).into_bytes()
}
pub(super) fn identity(etag: &str, version: Option<&str>) -> String {
    serde_json::to_string(&(etag, version)).expect("strings serialize")
}
pub(super) fn observe(
    args: &Args,
    key_name: &str,
    current: Option<&super::client::Object>,
) -> bool {
    let Some(job) = &args.resume_job else {
        return false;
    };
    let path = key(&args.s3.as_ref().unwrap().bucket, key_name, None);
    let current = current.map(|o| identity(&o.etag, o.version.as_deref()));
    if !args.dry_run {
        job.observe_object(&path, current.clone());
    }
    job.owns_object(&path, current.as_deref())
}
pub(super) fn published(args: &Args, key_name: &str, etag: Option<&str>, version: Option<&str>) {
    if let Some(job) = &args.resume_job {
        if let Some(etag) = etag {
            job.published_object(
                &key(&args.s3.as_ref().unwrap().bucket, key_name, None),
                identity(etag, version),
            );
        } else {
            job.disable("S3 omitted the published object's ETag");
        }
    }
}
pub(super) fn removal_identity(size: u64, time: Option<(i64, u32)>, etag: Option<&str>) -> String {
    if time.is_none() || etag.is_none() {
        return "unavailable".into();
    }
    serde_json::to_string(&(size, time, etag)).expect("identity serializes")
}

pub(super) fn local_identity(meta: crate::rooted::RootMetadata) -> String {
    format!("{}:{}", meta.dev, meta.ino)
}

pub(super) fn bind(args: &Args, options: &super::Options) -> anyhow::Result<()> {
    if let Some(job) = &args.resume_job {
        if args.dry_run && job.object_original(b"s3-endpoint").is_none() {
            return Ok(());
        }
        job.bind_scope(
            b"s3-endpoint",
            serde_json::to_string(&(options.endpoint.as_deref(), &options.bucket))?,
        )?;
    }
    Ok(())
}

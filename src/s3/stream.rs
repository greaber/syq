//! One raw S3 object and one inherited local byte stream. No filesystem
//! metadata, helper protocol, or persistent upload identity is synthesized.
mod fd;
use super::{checksum::Algorithm, client, Options};
use anyhow::{bail, Context, Result};
use aws_sdk_s3::{
    primitives::ByteStream,
    types::{CompletedMultipartUpload, CompletedPart},
    Client,
};
use bytes::Bytes;
use clap::{CommandFactory, FromArgMatches, Parser};
use fd::Descriptor;
use futures_util::{stream, StreamExt, TryStreamExt};
use std::{
    ffi::OsString,
    sync::{
        atomic::{AtomicBool, Ordering::Relaxed},
        Arc,
    },
    time::Duration,
};

#[derive(Parser, Debug)]
#[command(
    name = "syq stream",
    bin_name = "syq stream",
    about = "Stream one S3 object's bytes to or from a local descriptor",
    long_about = "Stream one S3 object's bytes to or from a local descriptor. Downloads write stdout by default; uploads read stdin. Parallel parts use bounded memory. No local temporary file is created. EOF finishes an upload; syq cannot determine whether the upstream producer succeeded. Existing destination objects are replaced only when the upload completes. Output descriptors may contain partial data after failure.",
    before_help = "Examples:\n  gzip -c data | syq stream --to s3://bucket --as data.gz\n  syq stream --from s3://bucket data.gz | gzip -dc\n  syq stream --from s3://bucket data --write-fd 3 3>data"
)]
struct Command {
    /// Download from this S3 bucket
    #[arg(
        long,
        value_name = "s3://BUCKET",
        required_unless_present = "to",
        conflicts_with = "to"
    )]
    from: Option<String>,
    /// Upload to this S3 bucket
    #[arg(
        long,
        value_name = "s3://BUCKET",
        required_unless_present = "from",
        conflicts_with = "from"
    )]
    to: Option<String>,
    /// Exact source object key (no wildcard expansion)
    #[arg(value_name = "KEY", requires = "from", conflicts_with = "to")]
    source: Option<String>,
    /// Exact destination object key
    #[arg(
        long = "as",
        value_name = "KEY",
        requires = "to",
        conflicts_with = "from"
    )]
    destination: Option<String>,
    /// Read an inherited descriptor instead of stdin
    #[arg(long, value_name="FD", requires="to", conflicts_with="from", value_parser=clap::value_parser!(i32).range(0..))]
    read_fd: Option<i32>,
    /// Write an inherited descriptor instead of stdout (stderr is reserved)
    #[arg(long, value_name="FD", requires="from", conflicts_with="to", value_parser=clap::value_parser!(i32).range(0..))]
    write_fd: Option<i32>,
    #[command(flatten)]
    s3: super::Flags,
    /// S3 part controls: s3-part-size, s3-max-concurrent-parts-per-object, s3-retries
    #[arg(long, value_name="KEY=VALUE", action=clap::ArgAction::Append)]
    performance_tuning: Vec<String>,
}

pub(crate) fn command() -> clap::Command {
    Command::command()
}

struct Plan {
    options: Options,
    key: String,
    fd: i32,
}
fn parse(argv: &[OsString]) -> Result<Plan> {
    let matches = crate::help::configure(command()).try_get_matches_from(argv)?;
    let args = Command::from_arg_matches(&matches)?;
    for control in args.performance_tuning.iter().flat_map(|s| s.split(',')) {
        let key = control.split('=').next().unwrap_or("").trim();
        if !matches!(
            key,
            "s3-part-size" | "s3-max-concurrent-parts-per-object" | "s3-retries"
        ) {
            bail!("performance control {key:?} is not supported for streams");
        }
    }
    let upload = args.to.is_some();
    let endpoint = args.to.as_deref().or(args.from.as_deref()).unwrap();
    if !endpoint.starts_with("s3://") {
        bail!("stream currently requires an s3://BUCKET endpoint");
    }
    let key = if upload {
        args.destination.context("uploads require --as KEY")?
    } else {
        args.source.context("downloads require a source KEY")?
    };
    if key.is_empty() || key.as_bytes().contains(&0) {
        bail!("object key must be nonempty and contain no NUL bytes");
    }
    let mut options =
        Options::parse(args.s3, args.from.as_deref(), args.to.as_deref(), &matches)?.unwrap();
    // Four parts overlap network work without the much larger memory footprint
    // of the file engine's automatic worker ceiling.
    if options.automatic_concurrency {
        options.concurrency = 4;
    }
    let fd = if upload {
        args.read_fd.unwrap_or(0)
    } else {
        args.write_fd.unwrap_or(1)
    };
    if fd == 2 {
        bail!("descriptor 2 is reserved for diagnostics");
    }
    Ok(Plan { options, key, fd })
}

pub(crate) fn run(argv: &[OsString]) -> Result<i32> {
    let mut plan = parse(argv)?;
    let cancelled = Arc::new(AtomicBool::new(false));
    let descriptor = Descriptor::open(plan.fd, plan.options.upload, cancelled.clone())?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?;
    let result = runtime.block_on(async {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let interrupt = async { tokio::select! { result = tokio::signal::ctrl_c() => { result?; }, _ = term.recv() => {} }; Ok::<_, anyhow::Error>(()) };
        tokio::pin!(interrupt);
        let cancellation = Arc::new(super::upload_http::Cancellation::default());
        let (client, _) = tokio::select! {
            value = client::connect(&mut plan.options, Arc::default(), cancellation.clone()) => value?,
            value = &mut interrupt => { value?; bail!("stream cancelled"); }
        };
        let mut upload_id = None;
        let result = {
            let operation = async {
                if plan.options.upload { upload(&client, &plan, descriptor, &mut upload_id).await }
                else { download(&client, &plan, descriptor).await }
            };
            tokio::select! {
                result = operation => result,
                result = &mut interrupt => { result?; Err(anyhow::anyhow!("stream cancelled")) }
            }
        };
        cancelled.store(true, Relaxed);
        if result.is_err() {
            if let Some(id) = upload_id {
                let abort = client.abort_multipart_upload().bucket(&plan.options.bucket).key(&plan.key).upload_id(&id).send();
                match tokio::time::timeout(Duration::from_secs(5), abort).await {
                    Ok(Ok(_)) => {},
                    _ => crate::output::diagnostic!("syq stream: could not confirm multipart cleanup; inspect incomplete uploads for this object"),
                }
            }
        }
        cancellation.cancel();
        result
    });
    cancelled.store(true, Relaxed);
    // A quiet inherited pipe can keep a blocking worker alive indefinitely.
    // This entry point is CLI-only: main exits immediately after reporting the
    // result. Finish multipart cleanup above, then let process exit stop I/O.
    runtime.shutdown_background();
    result.map(|()| 0)
}

fn digest(algorithm: Algorithm, data: &[u8]) -> String {
    let mut hash = algorithm.hasher();
    hash.update(data);
    hash.finish()
}

async fn upload(
    client: &Client,
    plan: &Plan,
    input: Descriptor,
    upload_id: &mut Option<String>,
) -> Result<()> {
    let options = &plan.options;
    let size = usize::try_from(options.part_size)?;
    let algorithm = Algorithm::for_endpoint(options.endpoint.as_deref());
    let (mut input, first) = input.read_chunk(size).await?;
    if first.len() < size {
        let hash = digest(algorithm, &first);
        client
            .put_object()
            .bucket(&options.bucket)
            .key(&plan.key)
            .set_checksum_sha256(algorithm.is_sha256().then_some(hash.clone()))
            .set_content_md5((algorithm == Algorithm::Md5).then_some(hash))
            .body(ByteStream::from(first))
            .send()
            .await
            .map_err(|e| e.into_service_error())
            .context("upload object")?;
        return Ok(());
    }
    let created = client
        .create_multipart_upload()
        .bucket(&options.bucket)
        .key(&plan.key)
        .set_checksum_algorithm(
            algorithm
                .is_sha256()
                .then_some(aws_sdk_s3::types::ChecksumAlgorithm::Sha256),
        )
        .send()
        .await
        .map_err(|e| e.into_service_error())
        .context("create multipart upload")?;
    let id = created
        .upload_id()
        .context("S3 omitted upload ID")?
        .to_owned();
    *upload_id = Some(id.clone());
    let mut pending = futures_util::stream::FuturesUnordered::new();
    let mut completed = Vec::new();
    let mut number = 1;
    let mut data = first;
    loop {
        if number > 10_000 {
            bail!("stream exceeds 10,000 multipart parts; rerun with a larger --performance-tuning s3-part-size=SIZE");
        }
        let last = data.len() < size;
        pending.push(upload_part(client, plan, &id, number, data, algorithm));
        number += 1;
        if pending.len() >= options.concurrency {
            completed.push(pending.try_next().await?.unwrap());
        }
        if last {
            break;
        }
        // Poll network futures while reading a possibly slow producer.
        let read = input.read_chunk(size);
        tokio::pin!(read);
        let next = loop {
            tokio::select! {
                next = &mut read => break next?,
                part = pending.try_next(), if !pending.is_empty() => { completed.push(part?.unwrap()); }
            }
        };
        input = next.0;
        data = next.1;
        if data.is_empty() {
            break;
        }
    }
    while let Some(part) = pending.try_next().await? {
        completed.push(part);
    }
    completed.sort_by_key(|p| p.part_number());
    client
        .complete_multipart_upload()
        .bucket(&options.bucket)
        .key(&plan.key)
        .upload_id(&id)
        .multipart_upload(
            CompletedMultipartUpload::builder()
                .set_parts(Some(completed))
                .build(),
        )
        .send()
        .await
        .map_err(|e| e.into_service_error())
        .context(
            "complete multipart upload (destination may have completed if the response was lost)",
        )?;
    *upload_id = None;
    Ok(())
}

async fn upload_part(
    client: &Client,
    plan: &Plan,
    id: &str,
    number: i32,
    data: Bytes,
    algorithm: Algorithm,
) -> Result<CompletedPart> {
    let hash = digest(algorithm, &data);
    let output = client
        .upload_part()
        .bucket(&plan.options.bucket)
        .key(&plan.key)
        .upload_id(id)
        .part_number(number)
        .set_checksum_sha256(algorithm.is_sha256().then_some(hash.clone()))
        .set_content_md5((algorithm == Algorithm::Md5).then_some(hash.clone()))
        .body(ByteStream::from(data))
        .send()
        .await
        .map_err(|e| e.into_service_error())
        .context("upload stream part")?;
    Ok(CompletedPart::builder()
        .part_number(number)
        .e_tag(output.e_tag().context("S3 part omitted ETag")?)
        .set_checksum_sha256(algorithm.is_sha256().then_some(hash))
        .build())
}

async fn download(client: &Client, plan: &Plan, mut output: Descriptor) -> Result<()> {
    // Read raw objects, including objects carrying another tool's metadata.
    let head = client
        .head_object()
        .bucket(&plan.options.bucket)
        .key(&plan.key)
        .send()
        .await
        .map_err(|e| e.into_service_error())
        .context("inspect source object")?;
    let size = u64::try_from(
        head.content_length()
            .context("S3 HEAD omitted Content-Length")?,
    )?;
    let etag = head.e_tag().context("S3 HEAD omitted ETag")?;
    let version = head.version_id();
    let part_size = plan.options.part_size;
    let mut parts = stream::iter(0..size.div_ceil(part_size))
        .map(|index| {
            read_part(
                client,
                plan,
                etag,
                version,
                size,
                index * part_size,
                part_size.min(size - index * part_size),
            )
        })
        .buffered(plan.options.concurrency);
    while let Some(bytes) = parts.try_next().await? {
        output = output.write_chunk(bytes).await?;
    }
    Ok(())
}

async fn read_part(
    client: &Client,
    plan: &Plan,
    etag: &str,
    version: Option<&str>,
    size: u64,
    offset: u64,
    length: u64,
) -> Result<Bytes> {
    let range = format!("bytes={offset}-{}", offset + length - 1);
    let expected = format!("bytes {offset}-{}/{size}", offset + length - 1);
    for attempt in 0..=plan.options.retries {
        let result = client
            .get_object()
            .bucket(&plan.options.bucket)
            .key(&plan.key)
            .range(&range)
            .if_match(etag)
            .set_version_id(version.map(str::to_owned))
            .customize()
            .config_override(client::without_sdk_retries())
            .send()
            .await;
        let mut response = match result {
            Ok(response) => response,
            Err(e) if super::transfer::retryable(&e) && attempt < plan.options.retries => {
                super::backoff(attempt).await;
                continue;
            }
            Err(e) => return Err(e.into_service_error()).context("download stream part"),
        };
        if response.content_length() != Some(length as i64)
            || response.content_range() != Some(expected.as_str())
            || response.e_tag() != Some(etag)
            || (version.is_some() && response.version_id() != version)
        {
            bail!("S3 object changed or returned an unexpected range");
        }
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(usize::try_from(length)?)
            .context("allocate download part")?;
        let mut failed = false;
        while let Some(chunk) = response.body.next().await {
            match chunk {
                Ok(chunk) => {
                    if chunk.len() as u64 > length - buffer.len() as u64 {
                        bail!("S3 range returned too many bytes");
                    }
                    buffer.extend_from_slice(&chunk);
                }
                Err(_) => {
                    failed = true;
                    break;
                }
            }
        }
        if !failed && buffer.len() as u64 == length {
            return Ok(Bytes::from(buffer));
        }
        if attempt == plan.options.retries {
            bail!("S3 range was interrupted or truncated");
        }
        super::backoff(attempt).await;
    }
    unreachable!()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn plan(args: &[&str]) -> Result<Plan> {
        parse(&args.iter().map(OsString::from).collect::<Vec<_>>())
    }
    #[test]
    fn stream_cli_selects_one_exact_object_and_descriptor() {
        command().debug_assert();
        let download = plan(&[
            "stream",
            "--from",
            "s3://bucket",
            "a//../literal*",
            "--write-fd",
            "17",
        ])
        .unwrap();
        assert!(!download.options.upload);
        assert_eq!(download.key, "a//../literal*");
        assert_eq!(download.fd, 17);
        assert_eq!(download.options.concurrency, 4);
        let upload = plan(&["stream", "--to", "s3://bucket", "--as", "object"]).unwrap();
        assert!(upload.options.upload);
        assert_eq!(upload.fd, 0);
        for args in [
            vec!["stream"],
            vec!["stream", "--from", "s3://bucket"],
            vec!["stream", "--to", "s3://bucket"],
            vec!["stream", "--from", "server", "file"],
            vec!["stream", "--from", "s3://bucket", "file", "--read-fd", "3"],
            vec!["stream", "--from", "s3://bucket", "file", "--write-fd", "2"],
            vec![
                "stream",
                "--to",
                "s3://bucket",
                "--as",
                "file",
                "--performance-tuning",
                "s3-max-concurrent-objects=2",
            ],
        ] {
            assert!(plan(&args).is_err(), "{args:?}");
        }
    }
}

//! Native local/S3 and server-side S3 copies. The S3 client and its durable formats are independent
//! of the filesystem helper protocol: credentials never enter an SSH request.
mod admission;
mod checksum;
mod client;
mod delete;
mod diagnostics;
mod dns;
mod local;
mod remove;
pub(crate) use remove::RemoveFlags;
mod prune;
mod read_recovery;
mod state;
pub(crate) mod stream;
mod transfer;
mod tuning;
mod upload_http;
mod writer;

use anyhow::{bail, Context, Result};
use clap::parser::ValueSource;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::Duration;

use crate::cli::Args;
use crate::progress::{human, Progress};

#[derive(Clone)]
pub(crate) struct Header(pub String, pub String);
impl std::fmt::Debug for Header {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Header")
            .field(&self.0)
            .field(&"[redacted]")
            .finish()
    }
}
impl std::str::FromStr for Header {
    type Err = String;
    fn from_str(text: &str) -> std::result::Result<Self, Self::Err> {
        let (name, value) = text.split_once(':').ok_or("expected NAME: VALUE")?;
        let name = http::HeaderName::from_bytes(name.trim().as_bytes())
            .map_err(|_| "invalid header name")?;
        let value = value.trim();
        http::HeaderValue::from_str(value).map_err(|_| "invalid header value")?;
        let name = name.as_str();
        if matches!(
            name,
            "authorization"
                | "host"
                | "content-length"
                | "transfer-encoding"
                | "connection"
                | "range"
                | "if-match"
                | "if-none-match"
                | "content-md5"
                | "x-amz-content-sha256"
                | "x-amz-date"
                | "x-amz-security-token"
        ) || name.starts_with("x-amz-copy-source")
            || matches!(name, "x-amz-metadata-directive" | "x-amz-tagging-directive")
            || name.starts_with("x-amz-checksum-")
            || name.starts_with("x-amz-meta-syq-")
        {
            return Err(format!("header {name} is managed by syq"));
        }
        Ok(Self(name.to_owned(), value.to_owned()))
    }
}

#[derive(clap::Args, Debug, Default)]
pub(crate) struct Flags {
    /// S3 API endpoint URL (also AWS_ENDPOINT_URL_S3 or AWS_ENDPOINT_URL)
    #[arg(long, value_name = "URL", help_heading = "Object storage")]
    s3_endpoint: Option<String>,
    /// S3 signing region, used as given (otherwise syq asks AWS where the bucket is)
    #[arg(long, value_name = "REGION", help_heading = "Object storage")]
    s3_region: Option<String>,
    /// AWS shared configuration/credentials profile
    #[arg(long, value_name = "NAME", help_heading = "Object storage")]
    s3_profile: Option<String>,
    /// Add a header before signing every S3 request (repeatable; S3-to-S3 metadata/tag overrides are refused)
    #[arg(long, value_name = "NAME: VALUE", help_heading = "Object storage")]
    s3_header: Vec<Header>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Route {
    Upload,
    Download,
    ServerCopy { source_bucket: String },
}
impl Route {
    pub fn is_server_copy(&self) -> bool {
        matches!(self, Self::ServerCopy { .. })
    }

    pub fn source_bucket(&self) -> Option<&str> {
        match self {
            Self::ServerCopy { source_bucket } => Some(source_bucket),
            Self::Upload | Self::Download => None,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Options {
    pub bucket: String,
    pub route: Route,
    pub endpoint: Option<String>,
    pub region: Option<String>,
    pub profile: Option<String>,
    pub headers: Vec<Header>,
    pub concurrency: usize,
    pub part_size: u64,
    pub retries: u32,
    pub automatic_concurrency: bool,
    pub automatic_part_size: bool,
}
impl Options {
    pub fn parse(
        flags: Flags,
        from: Option<&str>,
        to: Option<&str>,
        matches: &clap::ArgMatches,
    ) -> Result<Option<Self>> {
        let tuning = matches
            .get_many::<String>("performance_tuning")
            .map(|v| v.cloned().collect::<Vec<_>>().join(","))
            .map(|v| {
                v.parse::<crate::transfer_tuning::TransferTuning>()
                    .context("invalid --performance-tuning")
            })
            .transpose()?
            .unwrap_or_default();
        let explicit = |id: &str| {
            matches.try_contains_id(id).unwrap_or(false)
                && matches.value_source(id) == Some(ValueSource::CommandLine)
        };
        let removal = matches.try_contains_id("s3_all_versions").unwrap_or(false);
        let endpoint_help = if removal {
            "--on s3://BUCKET"
        } else {
            "--from s3://BUCKET or --to s3://BUCKET"
        };
        let operation = if removal { "removal" } else { "copies" };
        if from.is_none() && to.is_none() {
            if tuning.has_s3_controls() {
                bail!("S3 performance tuning requires {endpoint_help}");
            }
            if ["s3_endpoint", "s3_region", "s3_profile", "s3_header"]
                .iter()
                .any(|id| explicit(id))
            {
                bail!("S3 options require {endpoint_help}");
            }
            return Ok(None);
        }
        for id in [
            "inplace",
            "recycle_staging",
            "auth_from",
            "via",
            "coordinate_at",
            "rsh",
            "syq_path",
            "no_bootstrap",
            "tcp_plain",
            "no_tcp",
            "tcp_ports",
            "tcp_congestion",
            "detach",
            "peer_auth",
            "pscope",
            "receiver_max_entries",
            "receiver_max_bytes",
            "receiver_receipt",
            "delegated_operands_b64",
            "suppress_summary",
        ] {
            if explicit(id) {
                bail!(
                    "--{} is not supported for S3 {operation}",
                    id.replace('_', "-")
                );
            }
        }
        if from.is_some() && to.is_some() {
            for Header(name, _) in &flags.s3_header {
                if name.starts_with("x-amz-meta-")
                    || matches!(
                        name.as_str(),
                        "content-type"
                            | "content-encoding"
                            | "content-language"
                            | "content-disposition"
                            | "cache-control"
                            | "expires"
                            | "x-amz-tagging"
                            | "x-amz-website-redirect-location"
                    )
                {
                    bail!("--s3-header {name} is not supported for S3-to-S3 copies: metadata and tag overrides behave differently for single-request and multipart copies");
                }
            }
        }
        let bucket = to.or(from).unwrap().strip_prefix("s3://").unwrap();
        for endpoint in [from, to].into_iter().flatten() {
            let name = endpoint.strip_prefix("s3://").unwrap();
            anyhow::ensure!(
                !name.is_empty()
                    && name
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b".-_".contains(&c)),
                "S3 endpoints must be s3://BUCKET; select keys with source and placement options"
            );
        }
        if tuning.comparison_block_size.is_some()
            || tuning.workers.is_some()
            || tuning.request_size.is_some()
            || tuning.pipeline_depth.is_some()
            || tuning.copy_path.is_some()
            || tuning.batch_files.is_some()
            || tuning.batch_bytes.is_some()
            || tuning.split_min_size.is_some()
            || tuning.bw_pacing.is_some()
        {
            bail!(
                "filesystem performance tuning is not supported for S3 {operation}; use the s3-* keys"
            );
        }
        let concurrency = tuning.s3_part_workers.unwrap_or(64);
        let part_size = tuning.s3_part_size.unwrap_or(16 << 20);
        if let Some(endpoint) = &flags.s3_endpoint {
            validate_endpoint(endpoint)?;
        }
        Ok(Some(Self {
            bucket: bucket.to_owned(),
            route: match (from, to) {
                (Some(source), Some(_)) => Route::ServerCopy {
                    source_bucket: source.strip_prefix("s3://").unwrap().to_owned(),
                },
                (None, Some(_)) => Route::Upload,
                (Some(_), None) => Route::Download,
                (None, None) => unreachable!("S3 route requires an S3 endpoint"),
            },
            endpoint: flags.s3_endpoint,
            region: flags.s3_region,
            profile: flags.s3_profile,
            headers: flags.s3_header,
            automatic_concurrency: tuning.s3_part_workers.is_none(),
            automatic_part_size: tuning.s3_part_size.is_none(),
            concurrency,
            part_size,
            retries: tuning.s3_retries.unwrap_or(10) as u32,
        }))
    }
}

fn validate_endpoint(endpoint: &str) -> Result<()> {
    let url = url::Url::parse(endpoint).context("invalid S3 endpoint URL")?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("S3 endpoint must be an HTTP(S) URL without credentials, query, or fragment");
    }
    Ok(())
}

pub(crate) fn run(mut args: Args) -> Result<i32> {
    if args.rm {
        return remove::run(args);
    }
    let writer = crate::results::start(
        &args,
        crate::results::RunMode::Cp {
            prune: args.delete,
            mapping: args.native_mapping.is_some(),
        },
    )?;
    let progress = Progress::new(!args.quiet && !args.no_progress, args.progress, None);
    if let Some(writer) = writer {
        progress.set_results(writer);
    }
    let ticker = progress.spawn_ticker();
    let result = (|| {
        args.read_copy_inputs()?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(
                std::thread::available_parallelism()
                    .map_or(4, |n| n.get())
                    .min(32),
            )
            .build()?;
        runtime.block_on(async {
            let engine = transfer::Engine::new(Arc::new(args.clone()), progress.clone()).await?;
            engine.run().await
        })
    })();
    diagnostics::finish();
    let limited = result
        .as_ref()
        .err()
        .is_some_and(|e| e.is::<prune::Limit>());
    let fatal = result.is_err();
    if let Err(error) = result {
        if limited {
            progress.eprintln(&format!("syq: {error:#}"));
        } else {
            progress.error(&format!("syq: {error:#}"));
        }
    }
    progress.scan_done.store(true, Relaxed);
    let errors = progress.errors.load(Relaxed);
    let code = if limited {
        25
    } else if fatal {
        1
    } else if errors != 0 {
        23
    } else {
        0
    };
    progress.finish(code == 0);
    if let Some(ticker) = ticker {
        ticker
            .join()
            .map_err(|_| anyhow::anyhow!("progress thread panicked"))?;
    }
    if let Some(writer) = progress.results_writer() {
        writer.emit_result(&crate::results::ResultRecord {
            status: match code {
                0 => "success",
                23 => "partial",
                25 => "refused",
                _ => "failed",
            },
            exit_code: code,
            dry_run: args.dry_run,
            files_transferred: progress.files_done.load(Relaxed),
            files_unchanged: progress.files_unchanged.load(Relaxed),
            files_excluded: progress.files_excluded.load(Relaxed),
            directories_created: progress.directories_created.load(Relaxed),
            symlinks_created: progress.symlinks_created.load(Relaxed),
            specials_created: 0,
            errors,
            bytes_transferred: progress.bytes_done.load(Relaxed),
            bytes_unchanged: progress.bytes_unchanged.load(Relaxed),
            copying_elapsed_ms: progress.copying_elapsed_ms(),
            elapsed_ms: progress.start.elapsed().as_millis() as u64,
            deletions_planned: args
                .delete
                .then(|| progress.deletions_planned.load(Relaxed)),
            deletions_completed: args
                .delete
                .then(|| progress.deletions_completed.load(Relaxed)),
            deletions_blocked: args
                .delete
                .then(|| progress.deletions_blocked.load(Relaxed)),
        });
        if writer.is_dead() {
            bail!("S3 result stream could not be completed");
        }
    }
    if !args.quiet {
        if args.delete {
            progress.println(&format!(
                "{} deletions planned, {} {}, {} blocked",
                progress.deletions_planned.load(Relaxed),
                progress.deletions_completed.load(Relaxed),
                if args.dry_run {
                    "would be removed"
                } else {
                    "removed"
                },
                progress.deletions_blocked.load(Relaxed),
            ));
        }
        let elapsed = progress.start.elapsed().as_secs_f64().max(0.001);
        progress.println(&format!(
            "{}{} files, {} transferred, {} unchanged, {} errors in {:.2}s ({}/s)",
            if args.dry_run {
                "Would copy "
            } else {
                "Copied "
            },
            progress.files_done.load(Relaxed),
            human(progress.bytes_done.load(Relaxed)),
            progress.files_unchanged.load(Relaxed),
            errors,
            elapsed,
            human((progress.bytes_done.load(Relaxed) as f64 / elapsed) as u64)
        ));
    }
    Ok(code)
}

pub(super) async fn backoff(attempt: u32) {
    tokio::time::sleep(Duration::from_millis(
        100u64.saturating_mul(1 << attempt.min(7)),
    ))
    .await;
}

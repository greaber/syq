//! Experimental S3 object listing, separate from copy selection and state.
pub(super) mod engine;
mod pattern;
#[cfg(test)]
mod tests;

use anyhow::{Context, Result};
use clap::{CommandFactory, FromArgMatches, Parser};
use engine::{Entry, Page, Store};
use pattern::Pattern;
use std::{ffi::OsString, io::Write, sync::Arc};

#[derive(Parser)]
#[command(
    name = "syq _ls",
    about = "List matching S3 objects as NDJSON (experimental; interface may change)",
    long_about = "List matching S3 objects as newline-delimited JSON. This command is experimental: its spelling, arguments, patterns, and output may change or be removed between releases.\n\nPatterns match the whole key. Quote them: ? matches one non-slash character, * matches zero or more non-slash characters, and ** matches zero or more characters including slashes. Every other character is literal, including backslashes and trailing slashes. Use ** explicitly for recursive listing. In a/**/b, both slashes are required: it does not match a/b.\n\nRecords arrive in unspecified order. Empty results succeed. A nonzero exit status means the listing is incomplete; stdout may already contain records. Objects are listed as stored, including directory markers; no virtual directories or filesystem metadata are inferred.",
    before_help = "Examples:\n  syq _ls 's3://bucket/logs/**'\n  syq _ls 's3://bucket/logs/2026-*/service-a/*.json'\n  syq _ls 's3://bucket/**'"
)]
struct Command {
    /// Literal S3 object key or quoted pattern
    #[arg(value_name = "S3_PATH")]
    path: String,
    #[command(flatten)]
    storage: super::Flags,
    /// Maximum concurrent listing tasks; 1 skips speculative prefix discovery
    #[arg(long, default_value_t = 32, value_parser = clap::value_parser!(u16).range(1..=256))]
    concurrency: u16,
}

pub(crate) fn command_for_help() -> clap::Command {
    crate::help::configure(Command::command()).mut_arg("s3_header", |arg| {
        arg.help("Add a header before signing every S3 request (repeatable)")
    })
}

pub(crate) fn run(args: &[OsString]) -> Result<i32> {
    let matches = match command_for_help().try_get_matches_from(
        std::iter::once(OsString::from("syq _ls")).chain(args.iter().cloned()),
    ) {
        Ok(matches) => matches,
        Err(error) => {
            let code = error.exit_code();
            error.print()?;
            return Ok(code);
        }
    };
    let command = Command::from_arg_matches(&matches)?;
    crate::fsops::reserve_startup_descriptors();
    let pattern = Pattern::parse(&command.path)?;
    let mut options = super::Options {
        bucket: pattern.bucket.clone(),
        route: super::Route::Download,
        endpoint: command.storage.s3_endpoint,
        region: command.storage.s3_region,
        profile: command.storage.s3_profile,
        headers: command.storage.s3_header,
        write_headers: vec![],
        concurrency: 1,
        part_size: 0,
        retries: command.storage.s3_retries.unwrap_or(super::DEFAULT_RETRIES),
        automatic_concurrency: false,
        automatic_part_size: false,
    };
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let (client, note) =
                super::client::connect(&mut options, Arc::default(), Arc::default()).await?;
            if let Some(note) = note {
                crate::output::diagnostic!("syq _ls: {note}");
            }
            let store = S3 {
                client,
                bucket: &pattern.bucket,
                divides: lists_in_byte_order(options.endpoint.as_deref(), &pattern.bucket),
            };
            let stdout = std::io::stdout();
            let mut out = stdout.lock();
            engine::enumerate(
                &store,
                &pattern,
                usize::from(command.concurrency),
                |entry| {
                    #[derive(serde::Serialize)]
                    struct Record<'a> {
                        bucket: &'a str,
                        #[serde(flatten)]
                        entry: Entry,
                    }
                    serde_json::to_writer(
                        &mut out,
                        &Record {
                            bucket: &pattern.bucket,
                            entry,
                        },
                    )?;
                    out.write_all(b"\n")?;
                    out.flush()?;
                    Ok(())
                },
            )
            .await
            .map_err(|error| {
                // A policy may allow listing only the prefix itself, and the
                // listings of narrower prefixes that divide it are refused.
                let denied = error
                    .downcast_ref::<super::client::RequestFailure>()
                    .is_some_and(super::client::RequestFailure::denied);
                if denied && command.concurrency > 1 {
                    error.context(
                        "if only the prefix itself may be listed, rerun with --concurrency 1",
                    )
                } else {
                    error
                }
            })
        })?;
    Ok(0)
}

/// ListObjectsV2 pages for every S3 listing: `_ls`, `map`, and copy,
/// download and removal planning.
pub(super) struct S3<'a> {
    pub(super) client: aws_sdk_s3::Client,
    pub(super) bucket: &'a str,
    /// Whether listings may be divided into parts: [`lists_in_byte_order`]
    /// for the endpoint the client uses and this bucket.
    pub(super) divides: bool,
}
/// Directory buckets do not promise lexicographic LIST order.
pub(super) fn lists_in_key_order(bucket: &str) -> bool {
    !bucket.ends_with("--x-s3")
}

/// Whether listings of `bucket` at `endpoint` may be divided into parts
/// (`engine::Store::divides`): the provider must document that ListObjectsV2
/// returns keys in UTF-8 byte order. `None` is the AWS endpoint the SDK
/// chooses.
///
/// Of the providers checked, only AWS documents it: "List results are always
/// returned in UTF-8 binary order" (https://docs.aws.amazon.com/AmazonS3/latest/userguide/ListingKeysUsingAPIs.html),
/// for general purpose buckets. Directory buckets are not in lexicographic
/// order (https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectsV2.html),
/// and Object Lambda access points can return a LIST response of their own
/// (https://docs.aws.amazon.com/AmazonS3/latest/userguide/olap-writing-lambda.html),
/// so only names of general purpose buckets divide.
///
/// Left out: Cloudflare R2, whose S3 API documentation states no order and
/// for which a different order was reported
/// (https://community.cloudflare.com/t/r2-listobjectsv2-returns-keys-in-non-standard-lexicographical-order/941399);
/// Google Cloud Storage, which says "lexicographically by name" without
/// saying by bytes (https://cloud.google.com/storage/docs/xml-api/get-bucket-list);
/// Backblaze B2, "sorted alphabetically by key"
/// (https://www.backblaze.com/apidocs/s3-list-objects-v2); Tigris, whose
/// S3 compatibility page states no order (https://www.tigrisdata.com/docs/api/s3/);
/// and every self-hosted or unrecognized endpoint.
pub(super) fn lists_in_byte_order(endpoint: Option<&str>, bucket: &str) -> bool {
    general_purpose_bucket(bucket)
        && endpoint
            .is_none_or(|endpoint| aws_endpoint(endpoint) || (test_divides() && loopback(endpoint)))
}

/// The test servers are not AWS. Debug builds let them divide listings: they
/// listen on a loopback address.
fn test_divides() -> bool {
    #[cfg(debug_assertions)]
    if std::env::var_os("SYQ_TEST_S3_DIVIDE_LISTINGS").is_some_and(|v| v == "1") {
        return true;
    }
    false
}

fn loopback(endpoint: &str) -> bool {
    url::Url::parse(endpoint).is_ok_and(|url| match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        _ => false,
    })
}

/// Whether `bucket` names a general purpose bucket rather than an ARN or an
/// alias with a suffix AWS reserves: directory buckets (`--x-s3`) and their
/// access points (`--xa-s3`), Object Lambda (`--ol-s3`), Outposts (`--op-s3`),
/// access point and multi-Region access point aliases (`-s3alias`, `.mrap`),
/// and table buckets (`--table-s3`)
/// (https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html).
fn general_purpose_bucket(bucket: &str) -> bool {
    !bucket.contains(':')
        && ![
            "--x-s3",
            "--xa-s3",
            "--ol-s3",
            "--op-s3",
            "-s3alias",
            ".mrap",
            "--table-s3",
        ]
        .iter()
        .any(|suffix| bucket.ends_with(suffix))
}

/// Whether `endpoint` is the base URL of an AWS S3 endpoint for general
/// purpose buckets, which the client addresses path-style: global, regional,
/// legacy dash-regional, dual-stack and FIPS endpoints in the AWS and China
/// partitions (https://docs.aws.amazon.com/general/latest/gr/s3.html), and
/// the bucket role of a VPC interface endpoint
/// (https://docs.aws.amazon.com/AmazonS3/latest/userguide/privatelink-interface-endpoints.html).
/// Hosts that already name a bucket, access points, Object Lambda, Outposts,
/// directory buckets (`s3express`) and multi-Region access points are not.
fn aws_endpoint(endpoint: &str) -> bool {
    let Ok(url) = url::Url::parse(endpoint) else {
        return false;
    };
    // A path would come before the bucket's: another bucket, and a key. The
    // SDK sends the path as given, so check it before any normalization.
    let path = endpoint.split_once("://").map_or("", |(_, rest)| {
        rest.find(['/', '\\']).map_or("", |at| &rest[at..])
    });
    if !matches!(path, "" | "/") {
        return false;
    }
    let Some(url::Host::Domain(host)) = url.host() else {
        return false;
    };
    let labels: Vec<&str> = host.split('.').collect();
    let rest = match labels.as_slice() {
        [rest @ .., "amazonaws", "com"] | [rest @ .., "amazonaws", "com", "cn"] => rest,
        _ => return false,
    };
    let region = |label: &str| {
        label
            .split('-')
            .next()
            .is_some_and(|area| area.len() == 2 && area.bytes().all(|b| b.is_ascii_lowercase()))
            && label.len() > 3
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && label.ends_with(|c: char| c.is_ascii_digit())
            && !label.contains("--")
    };
    match rest {
        ["s3"] | ["s3-external-1"] => true,
        ["s3" | "s3-fips", r] | ["s3" | "s3-fips", "dualstack", r] => region(r),
        ["bucket", endpoint, "s3", r, "vpce"] => endpoint.starts_with("vpce-") && region(r),
        [legacy] => legacy.strip_prefix("s3-").is_some_and(region),
        _ => false,
    }
}

impl Store for S3<'_> {
    fn ordered(&self) -> bool {
        lists_in_key_order(self.bucket)
    }

    fn divides(&self) -> bool {
        self.divides
    }

    async fn page(
        &self,
        prefix: &str,
        delimiter: bool,
        token: Option<&str>,
        start_after: Option<&str>,
    ) -> Result<Page> {
        let response = self
            .client
            .list_objects_v2()
            .bucket(self.bucket)
            .prefix(prefix)
            .max_keys(1000)
            .encoding_type(aws_sdk_s3::types::EncodingType::Url)
            .set_delimiter(delimiter.then(|| "/".into()))
            .set_continuation_token(token.map(str::to_owned))
            .set_start_after(start_after.map(str::to_owned))
            .send()
            .await
            .map_err(super::client::listing_failure)?;
        // URL encoding lets keys hold characters XML cannot carry. Decode only
        // when the response says it was applied: a provider that ignores the
        // request returns keys as stored, and those can contain '%' and '+'.
        let encoded = response.encoding_type() == Some(&aws_sdk_s3::types::EncodingType::Url);
        let decode = |value: &str| -> Result<String> {
            if !encoded {
                return Ok(value.to_owned());
            }
            Ok(
                percent_encoding::percent_decode_str(&value.replace('+', " "))
                    .decode_utf8()
                    .context("S3 listing returned a key that is not UTF-8")?
                    .into_owned(),
            )
        };
        let mut entries = Vec::new();
        for object in response.contents() {
            entries.push(Entry {
                key: decode(object.key().context("S3 listing omitted key")?)?,
                size: u64::try_from(object.size().context("S3 listing omitted size")?)
                    .context("S3 listing returned a negative size")?,
                last_modified: object
                    .last_modified()
                    .map(|time| (time.secs(), time.subsec_nanos())),
                etag: object.e_tag().map(str::to_owned),
            });
        }
        let prefixes = response
            .common_prefixes()
            .iter()
            .map(|p| decode(p.prefix().context("S3 listing omitted common prefix")?))
            .collect::<Result<_>>()?;
        let next = if response.is_truncated() == Some(true) {
            Some(
                response
                    .next_continuation_token()
                    .context("truncated S3 listing omitted continuation token")?
                    .to_owned(),
            )
        } else {
            None
        };
        Ok(Page {
            entries,
            prefixes,
            next,
        })
    }
}

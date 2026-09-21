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
    let pattern = Pattern::parse(&command.path)?;
    let mut options = super::Options {
        bucket: pattern.bucket.clone(),
        route: super::Route::Download,
        endpoint: command.storage.s3_endpoint,
        region: command.storage.s3_region,
        profile: command.storage.s3_profile,
        headers: command.storage.s3_header,
        concurrency: 1,
        part_size: 0,
        retries: 10,
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
        })?;
    Ok(0)
}

struct S3<'a> {
    client: aws_sdk_s3::Client,
    bucket: &'a str,
}
impl Store for S3<'_> {
    async fn page(&self, prefix: &str, delimiter: bool, token: Option<&str>) -> Result<Page> {
        let response = self
            .client
            .list_objects_v2()
            .bucket(self.bucket)
            .prefix(prefix)
            .max_keys(1000)
            .encoding_type(aws_sdk_s3::types::EncodingType::Url)
            .set_delimiter(delimiter.then(|| "/".into()))
            .set_continuation_token(token.map(str::to_owned))
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("{}", super::client::failure("listing S3 objects", &e)))?;
        let decode = |value: &str| -> Result<String> {
            Ok(percent_encoding::percent_decode_str(value)
                .decode_utf8()
                .context("S3 listing returned a key that is not UTF-8")?
                .into_owned())
        };
        let mut entries = Vec::new();
        for object in response.contents() {
            entries.push(Entry {
                key: decode(object.key().context("S3 listing omitted key")?)?,
                size: u64::try_from(object.size().context("S3 listing omitted size")?)
                    .context("S3 listing returned a negative size")?,
                last_modified: object
                    .last_modified()
                    .map(|date| date.fmt(aws_smithy_types::date_time::Format::DateTime))
                    .transpose()?,
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

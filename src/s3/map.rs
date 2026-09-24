//! Source-only S3 mapping generation. Objects are read one page at a time; HEAD
//! requests are needed only for selector disambiguation or requested metadata.
use super::{client, listing, local};
use crate::cli::{Args, SourceSelection};
use crate::native_map::{Emitter, Field, Options};
use anyhow::{bail, Context, Result};
use futures_util::{stream, StreamExt, TryStreamExt};
use listing::engine::Entry;
use std::{collections::HashSet, io::Write, sync::Arc};

pub(crate) fn run(args: &Args, options: &Options, out: &mut impl Write) -> Result<()> {
    let mut storage = args.s3.clone().expect("S3 map options");
    let destinations = options.destinations()?;
    let base = local::key_path(
        options
            .root
            .as_deref()
            .or(options.cwd.as_deref())
            .unwrap_or(b"."),
    )?;
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let (client, note) =
                client::connect(&mut storage, Arc::default(), Arc::default()).await?;
            if let Some(note) = note {
                crate::output::diagnostic!("syq map: {note}");
            }
            let store = listing::S3 {
                client: client.clone(),
                bucket: &storage.bucket,
            };
            let mut emitter = Emitter {
                out,
                fields: &options.include,
                policy: args.expressions.clone(),
            };
            let mut claims = HashSet::new();
            let details = options
                .include
                .iter()
                .any(|field| matches!(field, Field::Kind | Field::Mtime));
            let service_time = options.include.contains(&Field::S3LastModified)
                || args.expressions.uses_source_s3_time();
            for (source, destination) in options.sources.iter().zip(destinations) {
                let source_path = local::key_path(&source.path)?;
                let key = local::join(&base, &source_path);
                let contents = source.selection == SourceSelection::Contents;
                let directory = contents || source.selection == SourceSelection::Directory;
                let exact = if key.is_empty() {
                    None
                } else {
                    client::head_output(&client, &storage.bucket, &key, None).await?
                };
                if let Some(output) = exact {
                    if directory {
                        bail!("S3 selector requires a prefix but an object exists at {key:?}");
                    }
                    let size = u64::try_from(
                        output
                            .content_length()
                            .context("S3 HEAD omitted Content-Length")?,
                    )?;
                    let object_time = output.last_modified().map(|time| (time.secs(), time.subsec_nanos()));
                    let expression_path = crate::expression::source_path(&source.path, b"");
                    let selected = args.expressions.selects_known(
                        crate::expression::Facts::S3Listing { size, last_modified: object_time }, expression_path)?;
                    if selected == Some(false) { continue; }
                    let object = (details || selected.is_none())
                        .then(|| client::from_head(&key, &output)).transpose()?;
                    if selected.is_none() && !args.expressions.selects(
                        &object.as_ref().expect("expression metadata").expression_file(), expression_path)? {
                        continue;
                    }
                    emit(
                        &mut emitter,
                        &mut claims,
                        &source.path,
                        &destination,
                        size,
                        object.as_ref(),
                        output.last_modified().map(|time| time.secs()),
                        false,
                    )?;
                    continue;
                }
                if source.selection == SourceSelection::File {
                    bail!("S3 source object {key:?} is missing");
                }
                let prefix = if key.is_empty() {
                    String::new()
                } else {
                    format!("{key}/")
                };
                let mut token = None;
                let mut found = false;
                loop {
                    let page =
                        listing::engine::read(&store, &prefix, false, token.as_deref()).await?;
                    found |= !page.entries.is_empty();
                    for entry in &page.entries {
                        if entry.key.ends_with('/') && !client::is_directory_marker(&entry.key, entry.size) {
                            bail!("S3 object {:?} ends in '/' but is not a directory marker and cannot be represented as a mapping path", entry.key);
                        }
                    }
                    let mut objects = stream::iter(
                        page.entries.into_iter().filter(|entry| !(contents && entry.key == prefix)),
                    ).map(|entry| {
                        let client = &client;
                        let bucket = &storage.bucket;
                        let prefix = &prefix;
                        let source_path = &source_path;
                        let destination = &destination;
                        async move {
                            let suffix = entry.key.strip_prefix(prefix)
                                .context("S3 listing returned a key outside the requested prefix")?;
                            let marker = client::is_directory_marker(&entry.key, entry.size);
                            let suffix = if marker { suffix.strip_suffix('/').unwrap_or(suffix) } else { suffix };
                            let src = if contents { suffix.to_owned() } else { local::join(source_path, suffix) };
                            let dst = local::join(std::str::from_utf8(destination)?, suffix);
                            let object_time = if service_time { listed_time(&entry)? } else { None };
                            let expression_path = crate::expression::source_path(source_path.as_bytes(), suffix.as_bytes());
                            let selected = args.expressions.selects_known(
                                crate::expression::Facts::S3Listing { size: entry.size, last_modified: object_time },
                                expression_path)?;
                            if selected == Some(false) { return Ok(None); }
                            let object = if details || selected.is_none() {
                                Some(client::head(client, bucket, &entry.key).await?
                                    .context("S3 source disappeared during mapping generation")?)
                            } else { None };
                            if selected.is_none() && !args.expressions.selects(
                                &object.as_ref().expect("expression metadata").expression_file(), expression_path)? {
                                return Ok(None);
                            }
                            Ok::<_, anyhow::Error>(Some((src, dst, entry.size, object, object_time, marker)))
                        }
                    }).buffered(32);
                    while let Some(record) = objects.try_next().await? {
                        let Some((src, dst, size, object, object_time, marker)) = record else { continue; };
                        emit(&mut emitter, &mut claims, src.as_bytes(), dst.as_bytes(), size,
                            object.as_ref(), object_time.map(|(s, _)| s), marker)?;
                    }
                    token = page.next;
                    if token.is_none() {
                        break;
                    }
                }
                if !found {
                    bail!("S3 source prefix {key:?} contains no objects");
                }
            }
            Ok(())
        })
}

fn listed_time(entry: &Entry) -> Result<Option<(i64, u32)>> {
    entry
        .last_modified
        .as_deref()
        .map(|value| {
            aws_smithy_types::DateTime::from_str(
                value,
                aws_smithy_types::date_time::Format::DateTime,
            )
            .map(|time| (time.secs(), time.subsec_nanos()))
            .context("invalid S3 Last-Modified")
        })
        .transpose()
}

#[allow(clippy::too_many_arguments)]
fn emit(
    out: &mut Emitter<'_, impl Write>,
    claims: &mut HashSet<Vec<u8>>,
    src: &[u8],
    dst: &[u8],
    size: u64,
    object: Option<&client::Object>,
    object_time: Option<i64>,
    marker: bool,
) -> Result<()> {
    crate::mapping::validate_manifest_path(src, "src")?;
    crate::mapping::validate_manifest_path(dst, "dst")?;
    if !claims.insert(dst.to_vec()) {
        bail!(
            "S3 objects map to the same destination {:?}",
            String::from_utf8_lossy(dst)
        );
    }
    let kind = object
        .map(|object| object.kind().as_str())
        .or(marker.then_some("dir"));
    let mtime = object.and_then(|object| object.metadata.as_ref().map(|m| m.mtime));
    out.entry(
        src,
        dst,
        kind,
        (!marker).then_some(size),
        mtime,
        object_time,
    )
}

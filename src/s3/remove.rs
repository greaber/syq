//! Explicit S3 removal. Resolve every selector before issuing any DELETE.
use super::{client, delete, local};
use crate::{
    cli::{Args, Location, SourceSelection},
    progress::Progress,
    results::{RemovalRecord, RmResultRecord, RunMode, SelectionResultRecord},
};
use anyhow::{bail, Context, Result};
use aws_sdk_s3::Client;
use std::collections::HashSet;
use std::sync::atomic::Ordering::Relaxed;

#[derive(clap::Args, Clone, Debug, Default)]
pub(crate) struct RemoveFlags {
    /// Permanently remove all selected S3 object versions and delete markers
    #[arg(
        long,
        conflicts_with = "s3_version_id",
        help_heading = "Object storage"
    )]
    pub s3_all_versions: bool,
    /// Permanently remove one version or delete marker of one exact S3 key
    #[arg(long, value_name = "ID", help_heading = "Object storage")]
    pub s3_version_id: Option<String>,
}
impl RemoveFlags {
    pub fn validate(&self, s3: bool, count: usize, kinds: &[SourceSelection]) -> Result<()> {
        if !s3 && (self.s3_all_versions || self.s3_version_id.is_some()) {
            bail!("--s3-all-versions and --s3-version-id require --on s3://BUCKET");
        }
        if let Some(id) = &self.s3_version_id {
            if id.is_empty()
                || count != 1
                || kinds
                    .iter()
                    .any(|k| matches!(k, SourceSelection::Directory | SourceSelection::Contents))
            {
                bail!("--s3-version-id requires a nonempty ID and one exact key (not a directory or contents selector)");
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct Entry {
    key: String,
    version: Option<String>,
    marker: bool,
    selector: u64,
}
impl Entry {
    fn kind(&self) -> &'static str {
        if self.key.ends_with('/') {
            "dir"
        } else {
            "file"
        }
    }
}

async fn versions(client: &Client, bucket: &str, prefix: &str, exact: bool) -> Result<Vec<Entry>> {
    let mut entries = Vec::new();
    let mut key_marker = None;
    let mut version_marker = None;
    let mut seen = HashSet::new();
    loop {
        let output = client
            .list_object_versions()
            .bucket(bucket)
            .prefix(prefix)
            .set_delimiter(exact.then(|| "/".to_owned()))
            .set_key_marker(key_marker)
            .set_version_id_marker(version_marker)
            .send()
            .await
            .map_err(|e| {
                let message = client::failure("list S3 versions", &e);
                anyhow::Error::new(e.into_service_error()).context(message)
            })?;
        let mut past_exact = false;
        for (key, version, marker) in output
            .versions()
            .iter()
            .map(|v| (v.key(), v.version_id(), false))
            .chain(
                output
                    .delete_markers()
                    .iter()
                    .map(|v| (v.key(), v.version_id(), true)),
            )
        {
            let key = key.context("S3 version listing omitted key")?;
            anyhow::ensure!(
                key.starts_with(prefix),
                "S3 version listing returned a key outside the requested prefix"
            );
            let version = version
                .filter(|v| !v.is_empty())
                .context("S3 version listing omitted version ID")?;
            if exact && key != prefix {
                past_exact = true;
                continue;
            }
            entries.push(Entry {
                key: key.into(),
                version: Some(version.into()),
                marker,
                selector: 0,
            });
        }
        if output.is_truncated() != Some(true) {
            break;
        }
        key_marker = Some(
            output
                .next_key_marker()
                .filter(|s| !s.is_empty())
                .context("truncated S3 version listing omitted key marker")?
                .to_owned(),
        );
        // Later keys or rolled-up prefixes mean this page passed the exact
        // key. Do not interpret continuation markers: providers may encode
        // additional state in them (including MinIO's listing cache identity).
        if exact
            && (past_exact
                || output.common_prefixes().iter().any(|p| {
                    p.prefix()
                        .is_some_and(|p| p.starts_with(prefix) && p != prefix)
                }))
        {
            break;
        }
        version_marker = output.next_version_id_marker().map(str::to_owned);
        anyhow::ensure!(
            seen.insert((key_marker.clone(), version_marker.clone())),
            "S3 version listing repeated pagination markers"
        );
    }
    Ok(entries)
}

async fn present(client: &Client, bucket: &str, key: &str) -> Result<bool> {
    match client.head_object().bucket(bucket).key(key).send().await {
        Ok(_) => Ok(true),
        Err(error)
            if error
                .raw_response()
                .is_some_and(|r| r.status().as_u16() == 404) =>
        {
            Ok(false)
        }
        Err(error) => {
            let message = client::failure("resolve S3 removal key", &error);
            Err(error.into_service_error()).context(message)
        }
    }
}

// Share selector interpretation with authorization so approved keys match the
// removal plan, including the slash on an exact directory-marker version.
pub(super) fn selector_key(base: &str, location: &Location, exact_version: bool) -> Result<String> {
    let raw = std::str::from_utf8(&location.path).context("S3 keys require UTF-8")?;
    let mut path = local::key_path(raw.strip_suffix('/').unwrap_or(raw).as_bytes())?;
    if exact_version && raw.ends_with('/') && !path.is_empty() {
        path.push('/');
    }
    let key = local::join(base, &path);
    let directory = matches!(
        location.selection,
        SourceSelection::Directory | SourceSelection::Contents
    );
    anyhow::ensure!(
        !key.is_empty() || location.selection == SourceSelection::Contents,
        "select bucket contents explicitly with --srcs-in .; S3 removal does not remove buckets"
    );
    anyhow::ensure!(
        directory || exact_version || !raw.ends_with('/'),
        "S3 tree removal requires --src-dir or --srcs-in: {raw:?}"
    );
    Ok(key)
}

async fn plan(
    args: &Args,
    client: &Client,
    progress: &Progress,
    summary: &mut RmResultRecord,
) -> Result<Vec<Entry>> {
    let bucket = &args.s3.as_ref().unwrap().bucket;
    let base = local::key_path(
        args.native_rm_root
            .as_deref()
            .or(args.native_rm_cwd.as_deref())
            .unwrap_or(b"."),
    )?;
    let mut entries = Vec::new();
    let mut seen = HashSet::new();
    for (index, location) in args.locations.iter().enumerate() {
        let exact_version = args.s3_remove.s3_version_id.as_deref();
        let key = selector_key(&base, location, exact_version.is_some())?;
        let directory = matches!(
            location.selection,
            SourceSelection::Directory | SourceSelection::Contents
        );
        let use_versions = args.s3_remove.s3_all_versions || exact_version.is_some();
        let mut listed = if use_versions && !key.is_empty() && !directory {
            versions(client, bucket, &key, true).await?
        } else {
            Vec::new()
        };
        let prefix = if key.is_empty() {
            String::new()
        } else {
            format!("{key}/")
        };
        let exact = !directory
            && if use_versions {
                listed.iter().any(|e| {
                    e.key == key && exact_version.is_none_or(|id| e.version.as_deref() == Some(id))
                })
            } else {
                present(client, bucket, &key).await?
            };
        if use_versions && exact_version.is_none() && !exact {
            listed.extend(versions(client, bucket, &prefix, false).await?);
        }
        let is_tree = directory;
        if !directory && !exact && exact_version.is_none() {
            let has_children = if use_versions {
                listed.iter().any(|e| e.key.starts_with(&prefix))
            } else {
                client::prefix_exists(client, bucket, &prefix).await?
            };
            anyhow::ensure!(
                !has_children,
                "S3 non-directory selector names a prefix: {key:?}; use --src-dir to remove a tree or --srcs-in to remove its contents"
            );
        }
        let exists;
        if is_tree {
            if !use_versions {
                listed = client::list(
                    client,
                    bucket,
                    &prefix,
                    None,
                    &mut HashSet::new(),
                    args.s3.as_ref().unwrap().concurrency,
                )
                .await?
                .objects
                .into_iter()
                .map(|(key, _)| Entry {
                    key,
                    version: None,
                    marker: false,
                    selector: 0,
                })
                .collect();
                anyhow::ensure!(
                    listed.iter().all(|e| e.key.starts_with(&prefix)),
                    "S3 listing returned a key outside the requested prefix"
                );
            }
            listed.retain(|e| e.key.starts_with(&prefix));
            exists = !listed.is_empty() || key.is_empty();
            if location.selection == SourceSelection::Contents {
                listed.retain(|e| e.key != prefix);
            }
        } else {
            exists = exact;
            if use_versions {
                listed.retain(|e| {
                    e.key == key && exact_version.is_none_or(|id| e.version.as_deref() == Some(id))
                });
            } else if exact {
                listed.push(Entry {
                    key: key.clone(),
                    version: None,
                    marker: false,
                    selector: 0,
                });
            }
        }
        if exists {
            summary.selectors_resolved += 1;
        } else {
            summary.selectors_missing += 1;
        }
        if let Some(writer) = progress.results_writer() {
            writer.emit_selection_result(&SelectionResultRecord {
                selector: index as u64,
                path: &location.path,
                status: if exists { "resolved" } else { "missing" },
                kind: exists.then_some(if is_tree || key.ends_with('/') {
                    "dir"
                } else {
                    "file"
                }),
            });
        }
        for mut entry in listed {
            if seen.insert((entry.key.clone(), entry.version.clone())) {
                entry.selector = index as u64;
                entries.push(entry);
            }
        }
    }
    // Retain delete markers until all selected data versions have been removed.
    entries.sort_by_key(|e| e.marker);
    Ok(entries)
}

fn finished(
    args: &Args,
    progress: &Progress,
    summary: &mut RmResultRecord,
    entry: &Entry,
    result: std::result::Result<(), delete::Failure>,
) {
    let failure = result.as_ref().err();
    let message = result
        .as_ref()
        .err()
        .map(|e| format!("S3 remove {:?}: {}", entry.key, e.message));
    if let Some(message) = &message {
        // Unattempted markers share one explanation printed by the caller.
        if !entry.marker || failure.is_none_or(|f| f.attempts != 0) {
            progress.error(message);
        }
        summary.entries_failed += 1;
        summary.errors += 1;
    } else if args.dry_run {
        summary.entries_planned += 1;
    } else {
        summary.entries_removed += 1;
    }
    if result.is_ok() {
        progress.files_done.fetch_add(1, Relaxed);
    }
    if !args.quiet && args.verbose > 0 {
        progress.println(&format!(
            "{} {:?}{}{}",
            if args.dry_run {
                "would remove"
            } else if result.is_ok() {
                "removed"
            } else {
                "failed"
            },
            entry.key,
            entry
                .version
                .as_ref()
                .map_or(String::new(), |v| format!(" version {v:?}")),
            if entry.marker { " (delete marker)" } else { "" }
        ));
    }
    if let Some(writer) = progress.results_writer() {
        let record = RemovalRecord {
            selector: entry.selector,
            path: entry.key.as_bytes(),
            kind: Some(entry.kind()),
            disposition: if result.is_ok() { "removed" } else { "failed" },
            attempts: Some(failure.map_or(1, |f| f.attempts)),
            retryable: failure.map(|f| f.retryable),
            class: failure.map(|f| f.class),
            os_kind: failure.and_then(|f| f.os_kind),
            message: message.as_deref(),
        };
        let version = entry.version.as_deref().map(|v| (v, entry.marker));
        if args.dry_run {
            writer.emit_removal_trace_s3(&record, version);
        } else {
            writer.emit_removal_result_s3(&record, version);
        }
    }
}

pub(super) fn run(args: Args) -> Result<i32> {
    let writer = crate::results::start(&args, RunMode::Rm)?;
    let mut progress = Progress::new(
        !args.quiet && !args.no_progress && !args.dry_run,
        args.progress,
        args.width,
    );
    std::sync::Arc::get_mut(&mut progress).unwrap().rm = true;
    if let Some(writer) = writer {
        progress.set_results(writer);
    }
    let mut summary = RmResultRecord {
        status: "success",
        exit_code: 0,
        dry_run: args.dry_run,
        selectors_total: args.locations.len() as u64,
        selectors_resolved: 0,
        selectors_missing: 0,
        entries_planned: 0,
        entries_removed: 0,
        entries_already_absent: 0,
        entries_failed: 0,
        errors: 0,
        elapsed_ms: 0,
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let ticker = progress.spawn_ticker();
    let result = runtime.block_on(async {
        let cancelled = std::sync::atomic::AtomicBool::new(false);
        let deleting = std::cell::Cell::new(false);
        let work = async {
            let mut options = args.s3.clone().unwrap();
            let control = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX));
            let uploads = std::sync::Arc::new(super::upload_http::Cancellation::default());
            let authorization = super::authorization::connect(&args, &options).await?;
            let (client, note) = client::connect_authorized(&mut options, control.clone(), uploads, authorization.clone()).await?;
            if let Some(note) = note.filter(|_| args.verbose > 0 && !args.quiet) {
                progress.println(&note);
            }
            let entries = plan(&args, &client, &progress, &mut summary).await?;
            if let Some(authorization) = &authorization {
                if !args.dry_run {
                    let mut requests = Vec::with_capacity(entries.len());
                    for entry in &entries {
                        let mut request = super::authorization::Unsigned::new("DELETE", &entry.key);
                        if let Some(version) = &entry.version { request = request.query("versionId", version); }
                        for super::Header(name, value) in &options.headers {
                            if super::authorization::signed_header(name, "DELETE") { request.headers.insert(name.clone(), value.clone()); }
                        }
                        requests.push(request);
                    }
                    let authorization = authorization.clone();
                    tokio::task::spawn_blocking(move || authorization.authorize(requests)).await??;
                }
                authorization.finish().await?;
            }
            progress.files_total.store(entries.len() as u64, Relaxed);
            progress.scan_done.store(true, Relaxed);
            let check = || {
                anyhow::ensure!(!cancelled.load(Relaxed), "S3 removal interrupted");
                anyhow::ensure!(
                    !progress.results_writer().is_some_and(|w| w.is_dead()),
                    "S3 removal result stream became unavailable"
                );
                Ok(())
            };
            let tuning = super::tuning::Tuning::new(&options, &args, control);
            if tuning.tigris() && authorization.is_none()
                && (args.s3_remove.s3_all_versions || args.s3_remove.s3_version_id.is_some())
            {
                progress.warning(
                    "Tigris versioned bulk deletion has been observed to ignore version IDs, leaving versions intact and creating delete markers. Continuing with standard S3 requests; verify the resulting version history. Provider behavior may have changed.",
                );
            }
            let deleter = delete::Deleter {
                client: &client,
                bucket: &options.bucket,
                budget: &tuning.requests,
                individual: authorization.is_some(),
            };
            let identify = |entry: &Entry| delete::Target {
                key: entry.key.clone(),
                version: entry.version.clone(),
            };
            if args.dry_run {
                for entry in &entries {
                    check()?;
                    finished(&args, &progress, &mut summary, entry, Ok(()));
                }
            } else {
                // Planning is read-only and can be dropped on cancellation.
                // Once deletion starts, drain requests already sent so their
                // outcomes are recorded before exiting.
                deleting.set(true);
                let split = entries.partition_point(|e| !e.marker);
                let (data, markers) = entries.split_at(split);
                deleter
                    .run(data, identify, &check, |entry, result| {
                        finished(&args, &progress, &mut summary, entry, result);
                    })
                    .await?;
                if summary.entries_failed == 0 {
                    deleter
                        .run(markers, identify, &check, |entry, result| {
                            finished(&args, &progress, &mut summary, entry, result);
                        })
                        .await?;
                } else {
                    if !markers.is_empty() {
                        progress.error(&format!(
                            "S3 removal preserved {} delete markers because selected data versions could not all be removed; resolve those failures before retrying the purge",
                            markers.len()
                        ));
                    }
                    for entry in markers {
                        finished(
                            &args,
                            &progress,
                            &mut summary,
                            entry,
                            Err(delete::Failure::preserved_marker()),
                        );
                    }
                }
            }
            Ok::<_, anyhow::Error>(())
        };
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::pin!(work);
        tokio::select! {
            result = &mut work => result,
            _ = tokio::signal::ctrl_c() => {
                cancelled.store(true, Relaxed);
                if deleting.get() {
                    let _ = work.await;
                }
                bail!("S3 removal interrupted");
            },
            _ = terminate.recv() => {
                cancelled.store(true, Relaxed);
                if deleting.get() {
                    let _ = work.await;
                }
                bail!("S3 removal terminated");
            },
        }
    });
    if let Err(error) = result {
        progress.error(&format!("syq: {error:#}"));
        summary.errors += 1;
        summary.exit_code = 1;
        summary.status = "failed";
    } else if summary.entries_failed != 0 {
        summary.exit_code = 23;
        summary.status = "partial";
    }
    summary.elapsed_ms = progress.start.elapsed().as_millis() as u64;
    progress.scan_done.store(true, Relaxed);
    progress.finish(summary.exit_code == 0);
    if let Some(ticker) = ticker {
        ticker
            .join()
            .map_err(|_| anyhow::anyhow!("S3 removal progress thread panicked"))?;
    }
    if let Some(writer) = progress.results_writer() {
        writer.emit_rm_result(&summary);
        anyhow::ensure!(
            !writer.is_dead(),
            "S3 removal result stream could not be completed"
        );
    }
    if !args.quiet {
        progress.println(&format!(
            "{} {} entries, {} missing selectors, {} errors",
            if args.dry_run {
                "Would remove"
            } else {
                "Removed"
            },
            if args.dry_run {
                summary.entries_planned
            } else {
                summary.entries_removed
            },
            summary.selectors_missing,
            summary.errors
        ));
    }
    Ok(summary.exit_code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use SourceSelection::{Contents, Directory, File};

    #[test]
    fn selector_keys_distinguish_trees_from_exact_marker_versions() {
        for (raw, selection, version, key) in [
            ("tree/", Directory, false, "tree"),
            ("tree/", Contents, false, "tree"),
            ("tree/", File, true, "tree/"),
            ("tree", File, true, "tree"),
            (".", Contents, false, ""),
            ("./", Contents, false, ""),
        ] {
            let mut location = Location::parse(raw).unwrap();
            location.selection = selection;
            for base in ["", "parent"] {
                assert_eq!(
                    selector_key(base, &location, version).unwrap(),
                    local::join(base, key),
                    "{raw:?}, {selection:?}, version={version}, base={base:?}"
                );
            }
        }
        for (raw, selection, version) in [
            ("tree/", File, false),
            ("tree//", Directory, false),
            ("../tree/", Directory, false),
            (".", File, true),
        ] {
            let mut location = Location::parse(raw).unwrap();
            location.selection = selection;
            assert!(selector_key("", &location, version).is_err(), "{raw:?}");
        }
    }
}

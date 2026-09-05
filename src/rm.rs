//! Native removal command orchestration.
//!
//! `syq rm` delegates one descriptor-rooted operation to the endpoint, whose
//! in-process worker pool owns all pinned handles. Its optional result stream
//! is written on the invoking machine for local and ordinary SSH endpoints;
//! command-restricted receivers deliberately reject native remove.

use crate::cli::{Args, SourceSelection};
use crate::progress::{commas, Progress};
use crate::proto::{
    Kind, NativeRemoveDisposition, NativeRemoveErrorClass, NativeRemoveKind, NativeRemoveOutcome,
    NativeRemoveSelection, WireError, WireIoKind,
};
use crate::results::{
    RemovalRecord, ResultsWriter, RmResultRecord, RunMode, SelectionResultRecord,
};
use crate::transfer::{connect_ctl, endpoint};
use anyhow::{bail, Result};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;

#[derive(Default)]
struct RemovalSummary {
    selectors_resolved: u64,
    selectors_missing: u64,
    entries_planned: u64,
    entries_removed: u64,
    entries_already_absent: u64,
    entries_failed: u64,
    errors: u64,
}

pub fn run(mut args: Args) -> Result<i32> {
    let selectors_total = args.locations.len() as u64;
    let remote = args
        .locations
        .first()
        .is_some_and(|location| location.is_remote());
    let show_progress = !args.no_progress && !args.quiet && !args.dry_run;
    let progress = Progress::new(
        show_progress,
        args.progress,
        args.width,
        !args.quiet && args.progress_json,
    );
    let progress = {
        let mut value = Arc::try_unwrap(progress).ok().expect("fresh progress");
        value.rm = true;
        Arc::new(value)
    };
    progress.scan_done.store(true, Relaxed);
    let results = crate::results::start(&args, RunMode::Rm)?;
    if let Some(writer) = &results {
        progress.set_results(Arc::clone(writer));
    }
    let ticker = progress.spawn_ticker();
    let mut summary = RemovalSummary::default();

    let outcome = run_remove(&mut args, &progress, results.as_deref(), &mut summary);
    progress.stop();
    if let Some(ticker) = ticker {
        let _ = ticker.join();
    }
    progress.clear();

    match outcome {
        Ok(()) => {
            let exit_code = if summary.entries_failed > 0 { 23 } else { 0 };
            let status = if exit_code == 0 { "success" } else { "partial" };
            progress.finish(exit_code == 0);
            emit_terminal(
                results.as_deref(),
                &progress,
                &summary,
                selectors_total,
                args.dry_run,
                status,
                exit_code,
            );
            if !args.quiet {
                print_summary(&args, &progress, &summary);
            }
            Ok(exit_code)
        }
        Err(error) => {
            progress.finish(false);
            summary.errors += 1;
            if let Some(writer) = results.as_deref().filter(|writer| !writer.is_dead()) {
                let (class, os_kind) = fatal_classification(&error, remote);
                writer.emit_error_classified(&format!("{error:#}"), Some(class), os_kind);
            }
            emit_terminal(
                results.as_deref(),
                &progress,
                &summary,
                selectors_total,
                args.dry_run,
                "failed",
                1,
            );
            Err(error)
        }
    }
}

fn print_summary(args: &Args, progress: &Progress, summary: &RemovalSummary) {
    let count = if args.dry_run {
        summary.entries_planned
    } else {
        summary.entries_removed
    };
    let mut details = Vec::new();
    if summary.entries_already_absent > 0 {
        details.push(format!(
            "{} already absent",
            commas(summary.entries_already_absent)
        ));
    }
    if summary.selectors_missing > 0 {
        details.push(format!(
            "{} missing selectors",
            commas(summary.selectors_missing)
        ));
    }
    if summary.entries_failed > 0 {
        details.push(format!("{} errors", commas(summary.entries_failed)));
    }
    crate::output::human_stdout!(
        "syq: {} {} entries in {}{}",
        if args.dry_run {
            "would remove"
        } else {
            "removed"
        },
        commas(count),
        crate::progress::hms(progress.start.elapsed().as_secs_f64()),
        if details.is_empty() {
            String::new()
        } else {
            format!(", {}", details.join(", "))
        }
    );
}

fn run_remove(
    args: &mut Args,
    progress: &Arc<Progress>,
    results: Option<&ResultsWriter>,
    summary: &mut RemovalSummary,
) -> Result<()> {
    let locs = &args.locations;
    for location in locs {
        if !location.same_host(&locs[0]) {
            bail!("all paths must be on the same host");
        }
    }
    let endpoint = endpoint(&locs[0], args)?;
    if args.connections_default && !endpoint.is_remote() {
        args.connections = crate::transfer::LOCAL_DEFAULT_CONNECTIONS;
    }
    let selections = locs
        .iter()
        .map(|location| NativeRemoveSelection {
            path: location.path.clone(),
            kind: match location.selection {
                SourceSelection::Contents => NativeRemoveKind::Contents,
                SourceSelection::File => NativeRemoveKind::File,
                SourceSelection::Directory => NativeRemoveKind::Directory,
                SourceSelection::Named | SourceSelection::NamedNoFollow => NativeRemoveKind::Any,
                SourceSelection::Rsync => unreachable!("native selector uses rsync semantics"),
            },
        })
        .collect::<Vec<_>>();
    let mut connection = connect_ctl(&endpoint, args)?;
    let verbose = !args.quiet && args.verbose > 0;
    let trace_resolution = !args.quiet && args.verbose > 1;

    connection.native_remove(
        args.native_rm_cwd.as_deref(),
        args.native_rm_root.as_deref(),
        &selections,
        args.follows_native_source_paths(),
        args.dry_run,
        args.connections,
        &mut |messages| {
            if trace_resolution {
                for message in messages {
                    progress.println(&format!("syq: resolve: {message}"));
                }
            }
            Ok(())
        },
        &mut |outcomes| {
            for outcome in outcomes {
                record_outcome(outcome, verbose, progress, results, summary);
            }
            if results.is_some_and(ResultsWriter::is_dead) {
                bail!("--results stream became unavailable; stopping native removal");
            }
            Ok(())
        },
    )
}

fn record_outcome(
    outcome: NativeRemoveOutcome,
    verbose: bool,
    progress: &Progress,
    results: Option<&ResultsWriter>,
    summary: &mut RemovalSummary,
) {
    let kind = outcome.kind.map(kind_name);
    match outcome.disposition {
        NativeRemoveDisposition::Resolved | NativeRemoveDisposition::Missing => {
            let status = if outcome.disposition == NativeRemoveDisposition::Resolved {
                summary.selectors_resolved += 1;
                "resolved"
            } else {
                summary.selectors_missing += 1;
                "missing"
            };
            if let Some(writer) = results {
                writer.emit_selection_result(&SelectionResultRecord {
                    selector: outcome.selector,
                    path: &outcome.path,
                    status,
                    kind,
                });
            }
        }
        NativeRemoveDisposition::WouldRemove => {
            summary.entries_planned += 1;
            progress.files_total.fetch_add(1, Relaxed);
            progress.files_done.fetch_add(1, Relaxed);
            if verbose {
                progress.println(&String::from_utf8_lossy(&outcome.path));
            }
            if let Some(writer) = results {
                writer.emit_removal_trace(&RemovalRecord {
                    selector: outcome.selector,
                    path: &outcome.path,
                    kind,
                    disposition: "would_remove",
                    attempts: None,
                    retryable: None,
                    class: None,
                    os_kind: None,
                    message: None,
                });
            }
        }
        NativeRemoveDisposition::Removed | NativeRemoveDisposition::AlreadyAbsent => {
            if outcome.disposition == NativeRemoveDisposition::Removed {
                summary.entries_removed += 1;
            } else {
                summary.entries_already_absent += 1;
            }
            progress.files_total.fetch_add(1, Relaxed);
            progress.files_done.fetch_add(1, Relaxed);
            if verbose {
                progress.println(&String::from_utf8_lossy(&outcome.path));
            }
            if let Some(writer) = results {
                writer.emit_removal_result(&RemovalRecord {
                    selector: outcome.selector,
                    path: &outcome.path,
                    kind,
                    disposition: if outcome.disposition == NativeRemoveDisposition::Removed {
                        "removed"
                    } else {
                        "already_absent"
                    },
                    attempts: outcome.attempts,
                    retryable: None,
                    class: None,
                    os_kind: None,
                    message: None,
                });
            }
        }
        NativeRemoveDisposition::Failed => {
            summary.entries_failed += 1;
            summary.errors += 1;
            progress.files_total.fetch_add(1, Relaxed);
            let failure = outcome
                .failure
                .as_ref()
                .expect("failed native removal carries a structured failure");
            let class = match failure.class {
                NativeRemoveErrorClass::Io => "io",
                NativeRemoveErrorClass::Conflict => "conflict",
            };
            let retryable = match failure.class {
                NativeRemoveErrorClass::Io => "unknown",
                NativeRemoveErrorClass::Conflict => "no",
            };
            let os_kind = failure.error.io_kind.map(wire_os_kind);
            if let Some(writer) = results {
                writer.emit_removal_result(&RemovalRecord {
                    selector: outcome.selector,
                    path: &outcome.path,
                    kind,
                    disposition: "failed",
                    attempts: outcome.attempts,
                    retryable: Some(retryable),
                    class: Some(class),
                    os_kind,
                    message: Some(&failure.error.message),
                });
            }
            progress.error_classified(
                &format!(
                    "syq: remove {:?}: {}",
                    String::from_utf8_lossy(&outcome.path),
                    failure.error.message
                ),
                Some(class),
                os_kind,
            );
        }
    }
}

fn emit_terminal(
    writer: Option<&ResultsWriter>,
    progress: &Progress,
    summary: &RemovalSummary,
    selectors_total: u64,
    dry_run: bool,
    status: &'static str,
    exit_code: i32,
) {
    if let Some(writer) = writer.filter(|writer| !writer.is_dead()) {
        writer.emit_rm_result(&RmResultRecord {
            status,
            exit_code,
            dry_run,
            selectors_total,
            selectors_resolved: summary.selectors_resolved,
            selectors_missing: summary.selectors_missing,
            entries_planned: summary.entries_planned,
            entries_removed: summary.entries_removed,
            entries_already_absent: summary.entries_already_absent,
            entries_failed: summary.entries_failed,
            errors: summary.errors,
            elapsed_ms: progress.start.elapsed().as_millis() as u64,
        });
    }
}

fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Dir => "dir",
        Kind::File => "file",
        Kind::Symlink => "symlink",
        Kind::Fifo | Kind::Socket | Kind::CharDev | Kind::BlockDev | Kind::Other => "special",
    }
}

fn wire_os_kind(kind: WireIoKind) -> &'static str {
    match kind {
        WireIoKind::NotFound => "not_found",
        WireIoKind::PermissionDenied => "permission_denied",
        WireIoKind::AlreadyExists => "already_exists",
        WireIoKind::InvalidInput => "invalid_input",
        WireIoKind::NoSpace => "no_space",
        WireIoKind::QuotaExceeded => "quota_exceeded",
        WireIoKind::ReadOnly => "read_only",
        WireIoKind::Other => "other",
    }
}

fn io_os_kind(error: &std::io::Error) -> &'static str {
    match error.raw_os_error() {
        Some(libc::ENOSPC) => "no_space",
        Some(libc::EDQUOT) => "quota_exceeded",
        Some(libc::EROFS) => "read_only",
        _ => match error.kind() {
            std::io::ErrorKind::NotFound => "not_found",
            std::io::ErrorKind::PermissionDenied => "permission_denied",
            std::io::ErrorKind::AlreadyExists => "already_exists",
            std::io::ErrorKind::InvalidInput => "invalid_input",
            _ => "other",
        },
    }
}

fn fatal_classification(
    error: &anyhow::Error,
    remote: bool,
) -> (&'static str, Option<&'static str>) {
    if let Some(wire) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<WireError>())
    {
        return (
            if wire.io_kind.is_some() {
                "io"
            } else {
                "conflict"
            },
            wire.io_kind.map(wire_os_kind),
        );
    }
    if let Some(io) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<std::io::Error>())
    {
        return (
            if remote { "transport" } else { "io" },
            Some(io_os_kind(io)),
        );
    }
    ("internal", None)
}

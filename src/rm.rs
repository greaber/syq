//! Native removal command orchestration.
//!
//! `syq rm` delegates one descriptor-rooted operation to the endpoint, whose
//! in-process worker pool owns all pinned handles.

use crate::cli::{Args, SourceSelection};
use crate::progress::{commas, Progress};
use crate::proto::{NativeRemoveKind, NativeRemoveSelection};
use crate::transfer::{connect_ctl, endpoint};
use anyhow::{bail, Result};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;

pub fn run(mut args: Args) -> Result<i32> {
    let locs = &args.locations;
    for location in locs {
        if !location.same_host(&locs[0]) {
            bail!("all paths must be on the same host");
        }
    }
    let endpoint = endpoint(&locs[0], &args)?;
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
    let mut connection = connect_ctl(&endpoint, &args)?;
    let show_progress = !args.no_progress && !args.quiet && !args.dry_run;
    let verbose = !args.quiet && args.verbose > 0;
    let trace_resolution = !args.quiet && args.verbose > 1;
    let progress = Progress::new(
        args.connections,
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
    let ticker = progress.spawn_ticker();

    let result = connection.native_remove(
        args.native_rm_cwd.as_deref(),
        args.native_rm_root.as_deref(),
        &selections,
        args.native_follow,
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
                progress.files_total.fetch_add(1, Relaxed);
                if let Some(error) = outcome.error {
                    progress.error(&format!(
                        "syq: remove {:?}: {error}",
                        String::from_utf8_lossy(&outcome.path)
                    ));
                } else {
                    progress.files_done.fetch_add(1, Relaxed);
                    if verbose {
                        progress.println(&String::from_utf8_lossy(&outcome.path));
                    }
                }
            }
            Ok(())
        },
    );
    progress.stop();
    if let Some(ticker) = ticker {
        let _ = ticker.join();
    }
    progress.clear();
    result?;
    let errors = progress.errors.load(Relaxed);
    if !args.quiet {
        println!(
            "syq: {} {} entries in {}{}",
            if args.dry_run {
                "would remove"
            } else {
                "removed"
            },
            commas(progress.files_done.load(Relaxed)),
            crate::progress::hms(progress.start.elapsed().as_secs_f64()),
            if errors > 0 {
                format!(", {errors} errors")
            } else {
                String::new()
            }
        );
    }
    Ok(if errors > 0 { 23 } else { 0 })
}

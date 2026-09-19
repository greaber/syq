//! Byte-stream outcomes have descriptor identities, not invented pathnames.
use super::{controls::Controls, fd::Source};
use crate::{
    cli::Args,
    results::{self, ResultsWriter},
};
use anyhow::Result;
use serde_json::{json, Value};
use std::{
    os::unix::ffi::OsStrExt,
    sync::{
        atomic::{AtomicBool, Ordering::Relaxed},
        Arc,
    },
};

pub(crate) struct Report {
    pub dry_run: bool,
    pub only_new: bool,
    pub only_existing: bool,
    skipped: AtomicBool,
    ready_sent: AtomicBool,
    quiet: bool,
    writer: Option<Arc<ResultsWriter>>,
    source: Value,
    destination: Value,
}
impl Report {
    pub fn start(args: &Args) -> Result<Self> {
        let plan = args.descriptor_copy.as_ref().unwrap();
        let named = || {
            let mut path = plan
                .key
                .as_ref()
                .map(|key| key.as_bytes().to_vec())
                .unwrap_or_else(|| plan.location.as_ref().unwrap().path.clone());
            if let Some(name) = &plan.placement.name {
                if !path.is_empty() && !path.ends_with(b"/") {
                    path.push(b'/');
                }
                path.extend_from_slice(name);
            }
            json!({ "path": results::tagged(&path) })
        };
        let source = match &plan.source {
            Some(Source::Descriptor(fd)) => json!({ "fd": fd }),
            Some(Source::Pipe { path, .. }) => {
                json!({ "path": results::tagged(path.as_os_str().as_bytes()) })
            }
            None => named(),
        };
        let destination = plan.as_fd.map_or_else(named, |fd| json!({ "fd": fd }));
        let report = Self {
            dry_run: args.dry_run,
            only_new: args.ignore_existing,
            only_existing: args.existing,
            skipped: AtomicBool::new(false),
            ready_sent: AtomicBool::new(false),
            quiet: args.quiet,
            writer: results::start(
                args,
                results::RunMode::Cp {
                    prune: false,
                    mapping: false,
                },
            )?,
            source,
            destination,
        };
        // Without a skip policy, input can queue while the destination connects.
        // Decide this after CLI/environment parsing so the SDK need not duplicate it.
        if plan.source.is_some()
            && !report.dry_run
            && !report.only_new
            && !report.only_existing
            && !plan.size_filter.active()
        {
            report.ready();
        }
        Ok(report)
    }
    pub fn skip(&self) {
        self.skipped.store(true, Relaxed);
    }
    pub fn skipped(&self) -> bool {
        self.skipped.load(Relaxed)
    }
    pub fn ready(&self) {
        if self.ready_sent.swap(true, Relaxed) {
            return;
        }
        if let Some(writer) = &self.writer {
            writer.emit_value(json!({ "type": "stream_ready" }));
        }
    }
    pub fn writer(&self) -> Option<&Arc<ResultsWriter>> {
        self.writer.as_ref()
    }
    pub fn finish(&self, controls: &Controls, error: Option<&anyhow::Error>) {
        let progress = &controls.progress;
        let success = error.is_none();
        let known = progress.scan_done.load(Relaxed);
        let bytes = if self.dry_run && success {
            progress.bytes_total.load(Relaxed)
        } else {
            progress.bytes_done.load(Relaxed)
        };
        let skipped = self.skipped();
        if skipped && !self.quiet {
            crate::output::diagnostic!(
                "Skipped stream destination {}",
                describe(&self.destination)
            );
        }
        if self.dry_run && success && !skipped && !self.quiet {
            crate::output::diagnostic!(
                "Would copy stream {} to {}{}",
                describe(&self.source),
                describe(&self.destination),
                if known {
                    format!(" ({bytes} bytes)")
                } else {
                    " (length unknown)".into()
                }
            );
        }
        let Some(writer) = &self.writer else {
            return;
        };
        let mut record = json!({ "type": "stream_result", "source": self.source,
            "destination": self.destination, "dry_run": self.dry_run,
            "disposition": if !success { "failed" } else if skipped { "skipped" } else if self.dry_run { "planned" } else { "succeeded" } });
        if skipped {
            record["bytes"] = 0.into();
        } else if !self.dry_run || known {
            record["bytes"] = bytes.into();
        }
        writer.emit_value(record);
        if let Some(error) = error {
            writer.emit_error_classified(&format!("{error:#}"), None, None);
        }
        writer.emit_result_size_known(
            &results::ResultRecord {
                status: if success { "success" } else { "failed" },
                exit_code: if success { 0 } else { 1 },
                dry_run: self.dry_run,
                files_transferred: u64::from(success && !skipped),
                files_unchanged: 0,
                files_excluded: u64::from(skipped),
                directories_created: 0,
                symlinks_created: 0,
                specials_created: 0,
                errors: u64::from(!success),
                bytes_transferred: if skipped { 0 } else { bytes },
                bytes_unchanged: 0,
                copying_elapsed_ms: None,
                elapsed_ms: progress.start.elapsed().as_millis() as u64,
                deletions_planned: None,
                deletions_completed: None,
                deletions_blocked: None,
            },
            Some(known),
        );
    }
}

fn describe(endpoint: &Value) -> String {
    if let Some(fd) = endpoint.get("fd") {
        return format!("descriptor {fd}");
    }
    let path = &endpoint["path"];
    if path["encoding"] == "utf-8" {
        format!("{:?}", path["value"].as_str().unwrap())
    } else {
        format!("path (base64: {})", path["value"])
    }
}

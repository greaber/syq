//! Controls shared by filesystem and S3 byte streams.
use super::Settings;
use crate::{cli::Args, progress::Progress};
use anyhow::{bail, Result};
use std::{
    sync::{atomic::Ordering::Relaxed, Arc},
    time::Instant,
};

pub(crate) fn validate_controls(args: &mut Args) -> Result<()> {
    let tuning = args.tuning_options.unwrap_or_default();
    tuning.validate(args.bwlimit_bytes)?;
    let s3 = args.s3.is_some();
    for control in args.performance_tuning.iter().flat_map(|s| s.split(',')) {
        let key = control.split('=').next().unwrap_or("").trim();
        let supported = if s3 {
            key.starts_with("s3-")
        } else {
            matches!(
                key,
                "workers" | "request-size" | "pipeline-depth" | "bw-pacing"
            )
        };
        if !supported {
            bail!("performance control {key:?} is not supported with this descriptor copy: streams transfer one object without file comparison or small-file batching; S3 uses its part controls");
        }
    }
    if let Some(checks) = args.integrity_checking {
        if checks.compare.is_some() {
            bail!("descriptor copies always transfer the selected bytes; content comparison is not supported");
        }
        if s3 && checks.transfer.flatten().is_some() {
            bail!("extra S3 stream verification is not supported: raw objects have no syq hash metadata (provider checksums remain enabled)");
        }
    }
    if let Some(options) = &mut args.s3 {
        let limits = args.resource_limits.clone().unwrap_or_default();
        options.concurrency = options
            .concurrency
            .min(tuning.s3_requests.unwrap_or(usize::MAX))
            .min(limits.s3_requests.unwrap_or(usize::MAX))
            .min(limits.s3_part_workers.unwrap_or(usize::MAX));
        // There is exactly one object, so every valid object-worker ceiling
        // is already satisfied.
    }
    Ok(())
}

pub(crate) struct Controls {
    pub report: super::report::Report,
    pub metadata: super::metadata::Policy,
    pub expected: super::check::Expected,
    pub settings: Settings,
    pub pipeline: usize,
    pub s3_requests: Option<usize>,
    pub s3_objects: usize,
    pub progress: Arc<Progress>,
    pub parent_progress: Option<Arc<Progress>>,
    limit: Option<Arc<crate::bwlimit::BandwidthLimit>>,
    stats: bool,
    quiet: bool,
}
impl Controls {
    pub fn new(args: &Args, report: super::report::Report) -> Self {
        let tuning = args.tuning_options.unwrap_or_default();
        let limit = (args.bwlimit_bytes != 0)
            .then(|| Arc::new(crate::bwlimit::BandwidthLimit::new(args.bwlimit_bytes)));
        let settings = Settings {
            request_size: tuning.streaming_request_size(
                super::CHUNK as u64,
                limit.as_deref(),
                false,
            ) as usize,
            algorithm: args.transfer_hash_type.unwrap_or_default(),
            verify: args.transfer_integrity,
        };
        let mut progress = Progress::new(!args.quiet && !args.no_progress, args.progress, None);
        Arc::get_mut(&mut progress).unwrap().stream = true;
        if let Some(writer) = report.writer().filter(|_| !report.is_entry()) {
            progress.set_results(writer.clone());
        }
        progress.files_total.store(1, Relaxed);
        if args.s3.is_none() && !args.dry_run {
            if let Some(history) = crate::tune::history::Recorder::start(
                progress.start,
                serde_json::json!({
                    "policy_version":1,"driver":"descriptor","automatic":args.connections_default,
                    "configured_workers":(!args.connections_default).then_some(args.connections),"worker_limit":(args.automatic_worker_limit() != usize::MAX).then(|| args.automatic_worker_limit()),
                    "bandwidth_limit":args.bwlimit_bytes,"request_size":settings.request_size
                }),
            ) {
                let _ = progress.tuning_history.set(history);
            }
        }
        if args.verbose > 0 && !args.quiet {
            if let Some(options) = &args.s3 {
                crate::output::diagnostic!(
                    "stream: one object, up to {} concurrent parts, {} bytes per part",
                    options.concurrency,
                    options.part_size
                );
            } else {
                crate::output::diagnostic!(
                    "stream: up to {} bytes per request, {} payload checks",
                    settings.request_size,
                    if settings.verify {
                        settings.algorithm.to_string()
                    } else {
                        "no extra".into()
                    }
                );
            }
            if args.bwlimit_bytes > 0 {
                crate::output::diagnostic!(
                    "stream bandwidth limit: {} bytes/s",
                    args.bwlimit_bytes
                );
            }
        }
        Self {
            report,
            metadata: super::metadata::Policy::new(args),
            expected: Default::default(),
            settings,
            pipeline: tuning.pipeline_depth(),
            s3_requests: tuning
                .s3_requests
                .into_iter()
                .chain(args.resource_limits.as_ref().and_then(|l| l.s3_requests))
                .min(),
            s3_objects: tuning.s3_object_workers.unwrap_or(32).min(
                args.resource_limits
                    .as_ref()
                    .and_then(|l| l.s3_object_workers)
                    .unwrap_or(usize::MAX),
            ),
            progress,
            parent_progress: None,
            limit,
            stats: args.stats,
            quiet: args.quiet,
        }
    }
    pub(crate) fn share_bandwidth(&mut self, limit: Option<Arc<crate::bwlimit::BandwidthLimit>>) {
        self.limit = limit;
    }
    pub fn add_bytes(&self, bytes: u64) {
        self.progress.add_bytes(bytes);
        if let Some(parent) = &self.parent_progress {
            parent.add_bytes(bytes);
        }
    }
    pub fn set_size(&self, size: u64) {
        let previous = self.progress.bytes_total.swap(size, Relaxed);
        if let Some(parent) = &self.parent_progress {
            if size >= previous {
                parent.bytes_total.fetch_add(size - previous, Relaxed);
            } else {
                parent.bytes_total.fetch_sub(previous - size, Relaxed);
            }
        }
        self.progress.scan_done.store(true, Relaxed);
    }
    pub(crate) fn bandwidth(&self) -> Option<Arc<crate::bwlimit::BandwidthLimit>> {
        self.limit.clone()
    }
    pub async fn pace(&self, bytes: u64) {
        if let Some(limit) = &self.limit {
            if bytes != 0 {
                tokio::time::sleep_until(limit.reserve_prepaid_at(Instant::now(), bytes).into())
                    .await;
            }
        }
    }
    pub fn finish(&self, error: Option<&anyhow::Error>) {
        let success = error.is_none();
        let bytes = self.progress.bytes_done.load(Relaxed);
        if success && !self.report.dry_run && !self.report.skipped() {
            self.set_size(bytes);
            self.progress.files_done.store(1, Relaxed);
        }
        if success && self.report.dry_run && !self.report.skipped() {
            self.progress.files_done.store(1, Relaxed);
            self.progress
                .bytes_done
                .store(self.progress.bytes_total.load(Relaxed), Relaxed);
        }
        if success && self.report.skipped() {
            self.progress.files_excluded.store(1, Relaxed);
        }
        self.progress.errors.store(u64::from(!success), Relaxed);
        self.progress.finish(success);
        self.report.finish(self, error);
        if let Some(history) = self.progress.tuning_history.get() {
            history.complete(success,serde_json::json!({"elapsed_ms":self.progress.start.elapsed().as_millis(),
                "bytes":bytes,"files":self.progress.files_done.load(Relaxed),"errors":u64::from(!success)}));
        }
        if self.stats && !self.quiet && !self.report.dry_run && !self.report.skipped() {
            let seconds = self.progress.start.elapsed().as_secs_f64();
            crate::output::diagnostic!(
                "stream {}: {} bytes in {:.3}s ({:.0} bytes/s)",
                if success { "complete" } else { "incomplete" },
                bytes,
                seconds,
                bytes as f64 / seconds.max(f64::EPSILON)
            );
        }
    }
}

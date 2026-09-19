//! Controls shared by filesystem and S3 byte streams.
use super::Settings;
use crate::{
    cli::Args,
    hashing::{Digest, Hasher},
    progress::Progress,
};
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
            bail!("extra S3 stream verification is not supported: raw objects have no syq digest metadata; use --expected-hash with a known digest (provider checksums remain enabled)");
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
    pub settings: Settings,
    pub pipeline: usize,
    pub progress: Arc<Progress>,
    limit: Option<crate::bwlimit::BandwidthLimit>,
    expected: Option<Digest>,
    stats: bool,
    quiet: bool,
}
impl Controls {
    pub fn new(args: &Args, report: super::report::Report) -> Self {
        let tuning = args.tuning_options.unwrap_or_default();
        let limit = (args.bwlimit_bytes != 0)
            .then(|| crate::bwlimit::BandwidthLimit::new(args.bwlimit_bytes));
        let settings = Settings {
            request_size: tuning.streaming_request_size(super::CHUNK as u64, limit.as_ref(), false)
                as usize,
            algorithm: args.transfer_hash_type.unwrap_or_default(),
            verify: args.transfer_integrity,
        };
        let mut progress = Progress::new(
            !args.quiet && !args.no_progress,
            args.progress,
            None,
            args.progress_json && !args.quiet,
        );
        Arc::get_mut(&mut progress).unwrap().stream = true;
        if let Some(writer) = report.writer() {
            progress.set_results(writer.clone());
        }
        progress.files_total.store(1, Relaxed);
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
            settings,
            pipeline: tuning.pipeline_depth(),
            progress,
            limit,
            expected: args.expected_digest.clone(),
            stats: args.stats,
            quiet: args.quiet,
        }
    }
    pub fn set_size(&self, size: u64) {
        self.progress.bytes_total.store(size, Relaxed);
        self.progress.scan_done.store(true, Relaxed);
    }
    pub fn pace_blocking(&self, bytes: u64) {
        if let Some(limit) = &self.limit {
            limit.wait_prepaid(bytes);
        }
    }
    pub async fn pace(&self, bytes: u64) {
        if let Some(limit) = &self.limit {
            if bytes != 0 {
                tokio::time::sleep_until(limit.reserve_prepaid_at(Instant::now(), bytes).into())
                    .await;
            }
        }
    }
    pub fn expected_hasher(&self) -> Option<Hasher> {
        self.expected
            .as_ref()
            .map(|digest| digest.algorithm.hasher())
    }
    pub fn verify(&self, hash: Option<Hasher>) -> Result<()> {
        if let Some(expected) = &self.expected {
            expected.verify(&hash.expect("expected hash state").finalize())?;
        }
        Ok(())
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
        if self.report.skipped() {
            self.progress.files_excluded.store(1, Relaxed);
        }
        self.progress.errors.store(u64::from(!success), Relaxed);
        self.progress.finish(success);
        self.report.finish(self, error);
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

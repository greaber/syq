//! Per-command transfer overrides. Comparison granularity also sets the existing
//! signed receiver hash-block limit. Overrides are not saved in the tuning cache.

use anyhow::{bail, Context, Result};
use std::str::FromStr;

pub(crate) const DEFAULT_PIPELINE_DEPTH: usize = 4;
/// Groups a worker keeps in flight while comparing replaced files in groups
/// (`transfer::small_compare`), each with one request outstanding.
pub(crate) const COMPARE_WINDOW: usize = 16;
/// Block requests a comparison keeps awaiting replies on each connection,
/// enough for small blocks to fill a long link (`transfer::comparing`).
pub(crate) const COMPARE_REQUESTS: usize = 256;
const MAX_PIPELINE_DEPTH: usize = 64;
const MAX_REQUEST_BYTES: u64 = 64 << 20;
pub(crate) const DEFAULT_BATCH_BYTES: u64 = 16 << 20;
pub(crate) const DEFAULT_SPLIT_BYTES: u64 = 32 << 20;

pub(crate) const HELP: &str = "Fix settings syq normally chooses itself, as comma-separated KEY=VALUE pairs, for troubleshooting and benchmarks. Keys: workers, s3-requests, s3-objects, s3-parts-per-object, s3-part-size, comparison-block-size, request-size, pipeline-depth, copy-path, batch-files, batch-bytes, split-min-size. See the performance tuning reference.";
/// rsync copies never use S3, so they accept only the filesystem keys.
pub(crate) const RSYNC_HELP: &str = "Fix settings syq normally chooses itself, as comma-separated KEY=VALUE pairs, for troubleshooting and benchmarks. Keys: workers, comparison-block-size, request-size, pipeline-depth, copy-path, batch-files, batch-bytes, split-min-size. See the performance tuning reference.";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum CopyPath {
    #[default]
    Auto,
    Ranges,
    Streaming,
    AutoStreaming,
}

impl std::fmt::Display for CopyPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Auto => "auto",
            Self::Ranges => "ranges",
            Self::Streaming => "streaming",
            Self::AutoStreaming => "auto-streaming",
        })
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct TransferTuning {
    pub workers: Option<usize>,
    pub s3_requests: Option<usize>,
    pub s3_object_workers: Option<usize>,
    pub s3_part_workers: Option<usize>,
    pub s3_part_size: Option<u64>,
    pub comparison_block_size: Option<u64>,
    pub request_size: Option<u64>,
    pub pipeline_depth: Option<usize>,
    pub copy_path: Option<CopyPath>,
    pub batch_files: Option<usize>,
    pub batch_bytes: Option<u64>,
    pub split_min_size: Option<u64>,
}

impl TransferTuning {
    pub fn has_s3_controls(self) -> bool {
        self.s3_requests.is_some()
            || self.s3_object_workers.is_some()
            || self.s3_part_workers.is_some()
            || self.s3_part_size.is_some()
    }
    pub fn pipeline_depth(self) -> usize {
        self.pipeline_depth.unwrap_or(DEFAULT_PIPELINE_DEPTH)
    }
    pub fn force_ranges(self) -> bool {
        matches!(self.copy_path, Some(CopyPath::Ranges | CopyPath::Streaming))
    }
    pub fn streaming(self) -> bool {
        matches!(
            self.copy_path,
            Some(CopyPath::Streaming | CopyPath::AutoStreaming)
        )
    }
    /// Select the range engine without asking users to size a credit window.
    /// Local copies have no network credit latency to hide. A short remote
    /// range fits in one ordinary window, so streaming would only add fences.
    /// Explicit depth/range controls retain the old engine for experiments.
    pub fn ordinary_range_limit(self, same_host: bool, block: u64) -> u64 {
        if self.streaming() {
            0
        } else if same_host
            || self.copy_path == Some(CopyPath::Ranges)
            || self.pipeline_depth.is_some()
        {
            u64::MAX
        } else {
            block.saturating_mul(DEFAULT_PIPELINE_DEPTH as u64)
        }
    }

    pub fn stream_range(self, same_host: bool, bytes: u64, block: u64) -> bool {
        self.streaming() || bytes > self.ordinary_range_limit(same_host, block)
    }
    /// This line describes selection policy before ranges have been planned,
    /// not an observed engine. Use the actual range predicate at its bounds
    /// so mixed automatic selection cannot be mislabeled as a fixed window.
    pub fn pipeline_label(self, same_host: bool, block: u64) -> String {
        if self.stream_range(same_host, 0, block) {
            "unused(streaming)".into()
        } else if self.stream_range(same_host, u64::MAX, block) {
            format!(
                "{}(ordinary ranges only; streaming above {} bytes)",
                self.pipeline_depth(),
                self.ordinary_range_limit(same_host, block)
            )
        } else {
            format!("{}(ordinary ranges only)", self.pipeline_depth())
        }
    }
    pub fn batch_bytes(self) -> u64 {
        self.batch_bytes.unwrap_or(DEFAULT_BATCH_BYTES)
    }
    pub fn batch_override(self) -> bool {
        self.batch_files.is_some() || self.batch_bytes.is_some()
    }
    pub fn split_min_size(self, hash_block: u64) -> u64 {
        self.split_min_size
            .unwrap_or(DEFAULT_SPLIT_BYTES)
            .max(2 * hash_block)
    }
    pub fn validate(self) -> Result<()> {
        if self.streaming() && self.pipeline_depth.is_some() {
            bail!(
                "--performance-tuning streaming copy paths cannot be combined with pipeline-depth"
            );
        }
        if self.force_ranges() && self.batch_override() {
            bail!("--performance-tuning range copy paths cannot be combined with batch controls");
        }
        Ok(())
    }
    /// Stream frames have no ordinary request-credit window. Bound their
    /// default payload separately without changing range selection or hashes.
    pub fn streaming_request_size(
        self,
        hash_block: u64,
        limit: Option<&crate::bwlimit::BandwidthLimit>,
    ) -> u64 {
        let size = self.request_size(hash_block, limit);
        if self.request_size.is_some() {
            size
        } else {
            size.min(2 << 20)
        }
    }

    pub fn request_size(
        self,
        hash_block: u64,
        limit: Option<&crate::bwlimit::BandwidthLimit>,
    ) -> u64 {
        let size = self.request_size.unwrap_or(hash_block);
        limit.map_or(size, |limit| size.min(limit.request_bytes()))
    }
}

fn set_once<T>(slot: &mut Option<T>, value: T, key: &str) -> Result<()> {
    if slot.replace(value).is_some() {
        bail!("duplicate tuning option {key}");
    }
    Ok(())
}

pub(crate) fn parse_comparison_block_size(value: &str, key: Option<&str>) -> Result<u64> {
    size(
        value,
        key,
        crate::proto::MIN_HASH_BLOCK_BYTES,
        crate::proto::MAX_HASH_BLOCK_BYTES,
    )
}

fn size(value: &str, key: Option<&str>, min: u64, max: u64) -> Result<u64> {
    let bytes = crate::cli::parse_size(value).map_err(|error| match key {
        Some(key) => error.context(key.to_owned()),
        None => error,
    })?;
    if !(min..=max).contains(&bytes) {
        let prefix = key.map(|key| format!("{key} ")).unwrap_or_default();
        bail!("{prefix}must be between {min} and {max} bytes");
    }
    Ok(bytes)
}

fn count(value: &str, key: &str, max: usize) -> Result<usize> {
    let n: usize = value
        .parse()
        .with_context(|| format!("{key} must be an integer"))?;
    if !(1..=max).contains(&n) {
        bail!("{key} must be between 1 and {max}");
    }
    Ok(n)
}

impl FromStr for TransferTuning {
    type Err = anyhow::Error;
    fn from_str(value: &str) -> Result<Self> {
        let mut tuning = Self::default();
        for pair in value.split(',') {
            let Some((key, value)) = pair.split_once('=') else {
                bail!("expected a tuning KEY=VALUE pair, got {pair:?}; see --help-all");
            };
            match key {
                "workers" => set_once(&mut tuning.workers, count(value, key, 65536)?, key)?,
                "s3-requests" => set_once(&mut tuning.s3_requests, count(value, key, 65536)?, key)?,
                "s3-objects" => set_once(
                    &mut tuning.s3_object_workers,
                    count(value, key, 65536)?,
                    key,
                )?,
                "s3-parts-per-object" => {
                    set_once(&mut tuning.s3_part_workers, count(value, key, 1024)?, key)?
                }
                "s3-part-size" => set_once(
                    &mut tuning.s3_part_size,
                    size(value, Some(key), 5 << 20, 5 << 30)?,
                    key,
                )?,
                "comparison-block-size" => set_once(
                    &mut tuning.comparison_block_size,
                    parse_comparison_block_size(value, Some(key))?,
                    key,
                )?,
                "request-size" => set_once(
                    &mut tuning.request_size,
                    size(value, Some(key), 512, MAX_REQUEST_BYTES)?,
                    key,
                )?,
                "pipeline-depth" => set_once(
                    &mut tuning.pipeline_depth,
                    count(value, key, MAX_PIPELINE_DEPTH)?,
                    key,
                )?,
                "copy-path" => set_once(
                    &mut tuning.copy_path,
                    match value {
                        "auto" => CopyPath::Auto,
                        "ranges" => CopyPath::Ranges,
                        "streaming" => CopyPath::Streaming,
                        "auto-streaming" => CopyPath::AutoStreaming,
                        _ => bail!("copy-path must be auto, ranges, streaming or auto-streaming"),
                    },
                    key,
                )?,
                "batch-files" => set_once(&mut tuning.batch_files, count(value, key, 4096)?, key)?,
                "batch-bytes" => set_once(
                    &mut tuning.batch_bytes,
                    size(value, Some(key), 512, 64 << 20)?,
                    key,
                )?,
                "split-min-size" => set_once(
                    &mut tuning.split_min_size,
                    size(value, Some(key), 1, 1 << 30)?,
                    key,
                )?,
                "bw-pacing" => bail!(
                    "bw-pacing is no longer a --performance-tuning key; a bandwidth cap always sends requests of up to 125 ms of its rate"
                ),
                // An S3 option since it left this group.
                "s3-retries" => {
                    bail!("s3-retries is no longer a --performance-tuning key; use --s3-retries N")
                }
                _ => bail!("unknown tuning option {key:?}; see --help-all"),
            }
        }
        Ok(tuning)
    }
}

impl std::fmt::Display for TransferTuning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut pairs = Vec::new();
        macro_rules! pair {
            ($key:literal, $value:expr) => {
                if let Some(value) = $value {
                    pairs.push(format!("{}={value}", $key));
                }
            };
        }
        pair!("workers", self.workers);
        pair!("s3-requests", self.s3_requests);
        pair!("s3-objects", self.s3_object_workers);
        pair!("s3-parts-per-object", self.s3_part_workers);
        pair!("s3-part-size", self.s3_part_size);
        pair!("comparison-block-size", self.comparison_block_size);
        pair!("request-size", self.request_size);
        pair!("pipeline-depth", self.pipeline_depth);
        pair!("copy-path", self.copy_path);
        pair!("batch-files", self.batch_files);
        pair!("batch-bytes", self.batch_bytes);
        pair!("split-min-size", self.split_min_size);
        f.write_str(&pairs.join(","))
    }
}

/// Diagnostic counters for attempted work, independent of completion records.
#[derive(Clone, Copy, Debug, Default, serde::Serialize)]
pub(crate) struct BenchmarkStats {
    pub native_small_copies: u64,
    pub local_whole_files: u64,
    pub range_requests: u64,
    pub streaming_ranges: u64,
    pub streamed_blocks: u64,
    pub stream_discarded_bytes: u64,
    pub stream_shrink_requests: u64,
    pub max_request_bytes: u64,
    pub small_batches: u64,
    pub max_batch_files: u64,
    pub max_batch_bytes: u64,
    /// Files compared in groups before sending, and of those, the files
    /// kept and the files published from reused and new blocks.
    pub compared_files: u64,
    pub kept_files: u64,
    pub patched_files: u64,
    /// Of the patched files, those whose new data was streamed in pieces.
    pub streamed_patches: u64,
}

impl BenchmarkStats {
    pub fn add(&mut self, other: Self) {
        self.native_small_copies += other.native_small_copies;
        self.local_whole_files += other.local_whole_files;
        self.range_requests += other.range_requests;
        self.streaming_ranges += other.streaming_ranges;
        self.streamed_blocks += other.streamed_blocks;
        self.stream_discarded_bytes += other.stream_discarded_bytes;
        self.stream_shrink_requests += other.stream_shrink_requests;
        self.small_batches += other.small_batches;
        self.compared_files += other.compared_files;
        self.kept_files += other.kept_files;
        self.patched_files += other.patched_files;
        self.streamed_patches += other.streamed_patches;
        self.max_request_bytes = self.max_request_bytes.max(other.max_request_bytes);
        self.max_batch_files = self.max_batch_files.max(other.max_batch_files);
        self.max_batch_bytes = self.max_batch_bytes.max(other.max_batch_bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// v0.7.1 took S3 retries as a tuning key; the error names the option
    /// that replaced it.
    #[test]
    fn the_removed_s3_retries_key_names_its_replacement() {
        let error = "s3-retries=3".parse::<TransferTuning>().unwrap_err();
        assert!(
            format!("{error:#}").contains("use --s3-retries N"),
            "{error:#}"
        );
    }

    #[test]
    fn the_removed_bw_pacing_key_is_named_as_removed() {
        for value in ["bw-pacing=average", "request-size=1M,bw-pacing=125ms"] {
            let error = value.parse::<TransferTuning>().unwrap_err();
            assert!(
                format!("{error:#}").contains("bw-pacing is no longer a --performance-tuning key"),
                "{error:#}"
            );
        }
    }

    #[test]
    fn comparison_granularity_validates_and_survives_forwarding() {
        for (value, bytes) in [("64K", 64 << 10), ("64M", 64 << 20)] {
            let tuning: TransferTuning = format!("comparison-block-size={value},request-size=4M")
                .parse()
                .unwrap();
            assert_eq!(tuning.comparison_block_size, Some(bytes));
            assert_eq!(
                tuning.to_string().parse::<TransferTuning>().unwrap(),
                tuning
            );
        }
        for value in [
            "comparison-block-size=32K",
            "comparison-block-size=65M",
            "comparison-block-size=64K,comparison-block-size=128K",
        ] {
            assert!(value.parse::<TransferTuning>().is_err(), "{value}");
        }
    }

    #[test]
    fn tuning_preserves_defaults_and_bandwidth_burst_bound() {
        let hash_block = 4 << 20;
        let default = TransferTuning::default();
        assert_eq!(default.request_size(hash_block, None), hash_block);
        assert_eq!(default.pipeline_depth(), 4);
        assert!(!default.streaming());
        let override_: TransferTuning = "request-size=8M,pipeline-depth=16".parse().unwrap();
        assert_eq!(override_.request_size(hash_block, None), 8 << 20);
        let limit = crate::bwlimit::BandwidthLimit::new(1 << 20);
        assert_eq!(override_.request_size(hash_block, Some(&limit)), 128 << 10);
        let small: TransferTuning = "request-size=512".parse().unwrap();
        assert_eq!(small.request_size(hash_block, Some(&limit)), 512);
        assert_eq!(
            override_.to_string().parse::<TransferTuning>().unwrap(),
            override_
        );
    }

    #[test]
    fn streaming_block_default_preserves_ordinary_selection_and_hash_sizes() {
        let tuning = TransferTuning::default();
        for hash in [
            512,
            64 << 10,
            1 << 20,
            (2 << 20) - 1,
            2 << 20,
            (2 << 20) + 1,
            4 << 20,
            64 << 20,
        ] {
            assert_eq!(tuning.request_size(hash, None), hash);
            assert_eq!(tuning.streaming_request_size(hash, None), hash.min(2 << 20));
            let ordinary = tuning.request_size(hash, None);
            assert!(!tuning.stream_range(false, 4 * ordinary, ordinary));
            assert!(tuning.stream_range(false, 4 * ordinary + 1, ordinary));
            assert!(!tuning.stream_range(true, 64 * ordinary, ordinary));
        }
        let override_: TransferTuning = "request-size=3M".parse().unwrap();
        assert_eq!(override_.streaming_request_size(4 << 20, None), 3 << 20);
        let small: TransferTuning = "request-size=512".parse().unwrap();
        assert_eq!(small.streaming_request_size(4 << 20, None), 512);
    }

    #[test]
    fn streaming_block_size_obeys_pacing_limits() {
        let limit = crate::bwlimit::BandwidthLimit::new(1 << 20);
        for options in ["copy-path=auto", "request-size=3M"] {
            let tuning: TransferTuning = options.parse().unwrap();
            assert_eq!(
                tuning.streaming_request_size(4 << 20, Some(&limit)),
                128 << 10
            );
        }
    }

    #[test]
    fn tuning_round_trips_every_key_for_remote_coordinators() {
        for value in [
            "copy-path=streaming,request-size=1M,split-min-size=1M",
            "copy-path=auto-streaming,request-size=1M,batch-files=32,batch-bytes=2M",
            "request-size=8M,pipeline-depth=16,copy-path=ranges,split-min-size=1M",
            "copy-path=auto,batch-files=4096,batch-bytes=64M,split-min-size=1G",
        ] {
            let tuning: TransferTuning = value.parse().unwrap();
            tuning.validate().unwrap();
            assert_eq!(
                tuning.to_string().parse::<TransferTuning>().unwrap(),
                tuning
            );
        }
        let split: TransferTuning = "request-size=8M,split-min-size=1M".parse().unwrap();
        assert_eq!(split.split_min_size(4 << 20), 8 << 20);
        assert!("copy-path=ranges,batch-files=1"
            .parse::<TransferTuning>()
            .unwrap()
            .validate()
            .is_err());
    }

    #[test]
    fn tuning_rejects_mistyped_or_unbounded_experiments() {
        for value in [
            "",
            "request-size",
            "block-size=1M",
            "request-size=0",
            "request-size=511",
            "request-size=65M",
            "request-size=NaN",
            "request-size=18446744073709551615G",
            "pipeline-depth=0",
            "pipeline-depth=65",
            "pipeline-depth=-1",
            "pipeline-depth=1.5",
            "request-size=1M,",
            "request-size=1M,request-size=2M",
            "pipeline-depth=1,pipeline-depth=2",
            "copy-path=magic",
            "copy-path=auto,copy-path=ranges",
            "batch-files=0",
            "batch-files=4097",
            "batch-bytes=511",
            "batch-bytes=65M",
            "split-min-size=0",
            "split-min-size=2G",
        ] {
            assert!(
                value.parse::<TransferTuning>().is_err(),
                "accepted {value:?}"
            );
        }
    }

    #[test]
    fn forced_streaming_rejects_irrelevant_controls() {
        let streaming: TransferTuning = "copy-path=streaming".parse().unwrap();
        streaming.validate().unwrap();
        assert!(streaming.streaming() && streaming.force_ranges());
        let automatic: TransferTuning = "copy-path=auto-streaming".parse().unwrap();
        automatic.validate().unwrap();
        assert!(automatic.streaming() && !automatic.force_ranges());
        "copy-path=auto-streaming,batch-files=8"
            .parse::<TransferTuning>()
            .unwrap()
            .validate()
            .unwrap();
        for value in [
            "copy-path=streaming,pipeline-depth=4",
            "copy-path=auto-streaming,pipeline-depth=4",
            "copy-path=streaming,batch-files=1",
            "copy-path=streaming,batch-bytes=1M",
        ] {
            assert!(value.parse::<TransferTuning>().unwrap().validate().is_err());
        }
    }

    #[test]
    fn automatic_streaming_skips_local_and_single_window_ranges() {
        let automatic = TransferTuning::default();
        let block = 4 << 20;
        for size in [0, 1, block, 4 * block] {
            assert!(!automatic.stream_range(false, size, block));
        }
        for size in [4 * block + 1, 8 * block, u64::MAX] {
            assert!(automatic.stream_range(false, size, block));
            assert!(!automatic.stream_range(true, size, block));
        }
        assert!(!automatic.stream_range(false, u64::MAX, u64::MAX));
        for control in [
            "copy-path=ranges",
            "pipeline-depth=4",
            "copy-path=auto,pipeline-depth=16",
        ] {
            let tuning: TransferTuning = control.parse().unwrap();
            assert!(!tuning.stream_range(false, 64 * block, block));
        }
        for control in ["copy-path=streaming", "copy-path=auto-streaming"] {
            let tuning: TransferTuning = control.parse().unwrap();
            assert!(tuning.stream_range(true, block, block));
        }
    }

    #[test]
    fn pipeline_labels_distinguish_policy_from_observed_paths() {
        let automatic = TransferTuning::default();
        assert_eq!(
            automatic.pipeline_label(false, 4 << 20),
            "4(ordinary ranges only; streaming above 16777216 bytes)"
        );
        assert_eq!(
            automatic.pipeline_label(false, 64 << 10),
            "4(ordinary ranges only; streaming above 262144 bytes)"
        );
        assert_eq!(
            automatic.pipeline_label(true, 4 << 20),
            "4(ordinary ranges only)"
        );
        assert_eq!(
            automatic.pipeline_label(false, u64::MAX),
            "4(ordinary ranges only)"
        );
        for mode in ["copy-path=streaming", "copy-path=auto-streaming"] {
            let tuning: TransferTuning = mode.parse().unwrap();
            for same_host in [false, true] {
                assert_eq!(
                    tuning.pipeline_label(same_host, 4 << 20),
                    "unused(streaming)"
                );
            }
        }
        let ordinary: TransferTuning = "pipeline-depth=16".parse().unwrap();
        assert_eq!(
            ordinary.pipeline_label(false, 4 << 20),
            "16(ordinary ranges only)"
        );
    }
}

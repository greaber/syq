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

/// Split comma-separated `KEY=VALUE` pairs, as `--performance-tuning`,
/// `--resource-limits` and `--integrity-checking` take them.
pub(crate) fn pairs(s: &str) -> Result<Vec<(&str, &str)>> {
    s.split(',')
        .map(|pair| {
            pair.split_once('=')
                .filter(|(key, value)| !key.is_empty() && !value.is_empty())
                .ok_or_else(|| anyhow::anyhow!("expected KEY=VALUE, got {pair:?}; see --help-all"))
        })
        .collect()
}

pub(crate) fn set_once<T>(slot: &mut Option<T>, value: T, key: &str) -> Result<()> {
    if slot.replace(value).is_some() {
        bail!("duplicate option {key:?}");
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

pub(crate) fn count(value: &str, key: &str, max: usize) -> Result<usize> {
    let n: usize = value
        .parse()
        .with_context(|| format!("{key} must be an integer"))?;
    if !(1..=max).contains(&n) {
        bail!("{key} must be between 1 and {max}");
    }
    Ok(n)
}

/// The kind of operation a command's tuning applies to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TuningRoute {
    /// A filesystem copy, local, over SSH or over TCP, by `cp` or `rsync`.
    Copy,
    /// A filesystem copy of one byte stream: a descriptor copy or a
    /// callback mapping's entries.
    Stream,
    /// An S3 copy, of files or of a stream.
    S3Copy,
    /// A filesystem removal.
    Removal,
    /// An S3 removal.
    S3Removal,
}

impl TuningRoute {
    const fn bit(self) -> u8 {
        match self {
            Self::Copy => COPY,
            Self::Stream => STREAM,
            Self::S3Copy => S3_COPY,
            Self::Removal => REMOVAL,
            Self::S3Removal => S3_REMOVAL,
        }
    }

    fn refusal(self, key: &str) -> String {
        let s3_key = key.starts_with("s3-");
        match self {
            Self::Copy | Self::Stream | Self::Removal if s3_key => {
                "S3 performance tuning requires an S3 endpoint".into()
            }
            Self::S3Copy | Self::S3Removal if !s3_key => format!(
                "filesystem performance tuning is not supported for S3 {}; use the s3-* keys",
                if self == Self::S3Removal { "removal" } else { "copies" }
            ),
            Self::Stream => format!("performance control {key:?} is not supported with this descriptor copy: streams transfer one object without file comparison or small-file batching; S3 uses its part controls"),
            _ => "removal supports only performance-tuning workers for filesystems or s3-requests for S3".into(),
        }
    }
}

const COPY: u8 = 1;
const STREAM: u8 = 2;
const S3_COPY: u8 = 4;
const REMOVAL: u8 = 8;
const S3_REMOVAL: u8 = 16;

/// One `--performance-tuning` key: its name, the routes that use it, how
/// to set it from a value, and how to show it when set.
struct Key {
    name: &'static str,
    routes: u8,
    set: fn(&mut TransferTuning, &str, &str) -> Result<()>,
    show: fn(&TransferTuning) -> Option<String>,
}

/// A key that stores the value `parse(value, key)` returns in `field`.
macro_rules! key {
    ($name:literal, $routes:expr, $field:ident, $parse:expr) => {
        Key {
            name: $name,
            routes: $routes,
            set: |t, key, value| set_once(&mut t.$field, $parse(value, key)?, key),
            show: |t| t.$field.map(|v| v.to_string()),
        }
    };
}

fn copy_path(value: &str, _key: &str) -> Result<CopyPath> {
    Ok(match value {
        "auto" => CopyPath::Auto,
        "ranges" => CopyPath::Ranges,
        "streaming" => CopyPath::Streaming,
        "auto-streaming" => CopyPath::AutoStreaming,
        _ => bail!("copy-path must be auto, ranges, streaming or auto-streaming"),
    })
}

/// Every key, in the order help lists them and forwarding writes them.
#[rustfmt::skip]
const KEYS: &[Key] = &[
    key!("workers", COPY | STREAM | REMOVAL, workers, |v, k| count(v, k, 65536)),
    key!("s3-requests", S3_COPY | S3_REMOVAL, s3_requests, |v, k| count(v, k, 65536)),
    key!("s3-objects", S3_COPY, s3_object_workers, |v, k| count(v, k, 65536)),
    key!("s3-parts-per-object", S3_COPY, s3_part_workers, |v, k| count(v, k, 1024)),
    key!("s3-part-size", S3_COPY, s3_part_size, |v, k| size(v, Some(k), 5 << 20, 5 << 30)),
    key!("comparison-block-size", COPY, comparison_block_size, |v, k| parse_comparison_block_size(v, Some(k))),
    key!("request-size", COPY | STREAM, request_size, |v, k| size(v, Some(k), 512, MAX_REQUEST_BYTES)),
    key!("pipeline-depth", COPY | STREAM, pipeline_depth, |v, k| count(v, k, MAX_PIPELINE_DEPTH)),
    key!("copy-path", COPY, copy_path, copy_path),
    key!("batch-files", COPY, batch_files, |v, k| count(v, k, 4096)),
    key!("batch-bytes", COPY, batch_bytes, |v, k| size(v, Some(k), 512, 64 << 20)),
    key!("split-min-size", COPY, split_min_size, |v, k| size(v, Some(k), 1, 1 << 30)),
];

/// `--performance-tuning` help listing the keys a copy can use: every
/// key for `cp`, and the filesystem keys for `rsync`, which never uses S3.
pub(crate) fn help(rsync: bool) -> String {
    let routes = if rsync { COPY } else { COPY | S3_COPY };
    let keys: Vec<_> = KEYS
        .iter()
        .filter(|key| key.routes & routes != 0)
        .map(|key| key.name)
        .collect();
    format!(
        "Fix settings syq normally chooses itself, as comma-separated KEY=VALUE pairs, for troubleshooting and benchmarks. Keys: {}. See the performance tuning reference.",
        keys.join(", ")
    )
}

impl TransferTuning {
    /// Refuse a key that `route` does not use.
    pub(crate) fn check_route(&self, route: TuningRoute) -> Result<()> {
        match KEYS
            .iter()
            .find(|key| key.routes & route.bit() == 0 && (key.show)(self).is_some())
        {
            Some(key) => bail!("{}", route.refusal(key.name)),
            None => Ok(()),
        }
    }
}

impl FromStr for TransferTuning {
    type Err = anyhow::Error;
    fn from_str(value: &str) -> Result<Self> {
        let mut tuning = Self::default();
        for (name, value) in pairs(value)? {
            let Some(key) = KEYS.iter().find(|key| key.name == name) else {
                match name {
                    // An S3 option since it left this group.
                    "s3-retries" => bail!(
                        "s3-retries is no longer a --performance-tuning key; use --s3-retries N"
                    ),
                    "bw-pacing" => bail!(
                        "bw-pacing is no longer a --performance-tuning key; a bandwidth cap always sends requests of up to 125 ms of its rate"
                    ),
                    _ => bail!("unknown tuning option {name:?}; see --help-all"),
                }
            };
            (key.set)(&mut tuning, name, value)?;
        }
        Ok(tuning)
    }
}

impl std::fmt::Display for TransferTuning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let pairs: Vec<_> = KEYS
            .iter()
            .filter_map(|key| (key.show)(self).map(|value| format!("{}={value}", key.name)))
            .collect();
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

    /// Each route accepts the keys it accepted before the key table; help
    /// lists the keys a copy accepts.
    #[test]
    fn routes_accept_the_keys_they_use_and_help_lists_them() {
        let values = [
            ("workers", "2"),
            ("s3-requests", "2"),
            ("s3-objects", "2"),
            ("s3-parts-per-object", "2"),
            ("s3-part-size", "8M"),
            ("comparison-block-size", "1M"),
            ("request-size", "1M"),
            ("pipeline-depth", "2"),
            ("copy-path", "ranges"),
            ("batch-files", "2"),
            ("batch-bytes", "1M"),
            ("split-min-size", "1M"),
        ];
        assert_eq!(values.len(), KEYS.len());
        for (key, value) in values {
            let tuning: TransferTuning = format!("{key}={value}").parse().unwrap();
            let s3 = key.starts_with("s3-");
            for (route, accepted) in [
                (TuningRoute::Copy, !s3),
                (
                    TuningRoute::Stream,
                    matches!(key, "workers" | "request-size" | "pipeline-depth"),
                ),
                (TuningRoute::S3Copy, s3),
                (TuningRoute::Removal, key == "workers"),
                (TuningRoute::S3Removal, key == "s3-requests"),
            ] {
                assert_eq!(
                    tuning.check_route(route).is_ok(),
                    accepted,
                    "{key} on {route:?}"
                );
            }
        }
        assert_eq!(
            help(false),
            "Fix settings syq normally chooses itself, as comma-separated KEY=VALUE pairs, for troubleshooting and benchmarks. Keys: workers, s3-requests, s3-objects, s3-parts-per-object, s3-part-size, comparison-block-size, request-size, pipeline-depth, copy-path, batch-files, batch-bytes, split-min-size. See the performance tuning reference."
        );
        assert_eq!(
            help(true),
            "Fix settings syq normally chooses itself, as comma-separated KEY=VALUE pairs, for troubleshooting and benchmarks. Keys: workers, comparison-block-size, request-size, pipeline-depth, copy-path, batch-files, batch-bytes, split-min-size. See the performance tuning reference."
        );
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

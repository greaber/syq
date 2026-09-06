//! Per-command transfer experiments. Settings never enter resume identities,
//! signed grants, or the remembered connection-count cache.

use anyhow::{bail, Context, Result};
use std::str::FromStr;

pub(crate) const DEFAULT_PIPELINE_DEPTH: usize = 4;
const MAX_PIPELINE_DEPTH: usize = 64;
const MAX_REQUEST_BYTES: u64 = 64 << 20;
pub(crate) const DEFAULT_BATCH_BYTES: u64 = 16 << 20;
pub(crate) const DEFAULT_SPLIT_BYTES: u64 = 32 << 20;

pub(crate) const HELP: &str = "Override copy internals for benchmarks with comma-separated KEY=VALUE pairs. Keys:\n\nrequest-size=SIZE: 512 bytes..64M; default is the hash block size, normally 4M.\npipeline-depth=N: 1..64 outstanding range requests per endpoint per worker; default 4. In-process endpoints remain synchronous.\ncopy-path=auto|ranges|streaming|auto-streaming: default auto; ranges bypasses whole-file and small-file copy shortcuts. Experimental streaming also bypasses those shortcuts, streams source blocks and drains checked write replies without a block-credit window. auto-streaming keeps normal whole-file and small-file shortcuts, streaming only range transfers. Auto streams remote ranges larger than one default request window, keeping ordinary requests for local or shorter ranges. An explicit pipeline-depth selects ordinary requests. The forced streaming modes are incompatible with pipeline-depth; forced streaming also rejects batch controls.\nbatch-files=N: 1..4096 files per worker batch; default 128 or 512 depending on transport/latency.\nbatch-bytes=SIZE: 512 bytes..64M per worker batch; default 16M, including the first file. Explicit batch controls bypass the native small-copy shortcut.\nsplit-min-size=SIZE: 1..1G bytes; default 32M, raised to at least two hash blocks.\nbw-pacing=average|INTERVAL: requires --bwlimit. Default 125ms. Intervals accept integer ms or s, from 1ms through 10s. Timed pacing caps request size at max(rate * interval, 512 bytes). Average pacing preserves request size and waits for each block's full byte budget before issuing its request (or its destination write in streaming mode). Neither mode guarantees a network burst ceiling. Restricted receivers retain their signed 125ms request-size ceiling in both modes.\n\nK/M/G sizes use powers of 1024. Hash/resume blocks stay unchanged. Overrides are not saved and bypass the remembered connection count. Use -v to report effective settings and observed paths; fix the connection count for comparisons. See the Speed guide for benchmark examples.";

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BwPacing {
    Average,
    IntervalMs(u64),
}

impl Default for BwPacing {
    fn default() -> Self {
        Self::IntervalMs(125)
    }
}

impl std::fmt::Display for BwPacing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Average => f.write_str("average"),
            Self::IntervalMs(ms) => write!(f, "{ms}ms"),
        }
    }
}

impl FromStr for BwPacing {
    type Err = anyhow::Error;
    fn from_str(value: &str) -> Result<Self> {
        if value == "average" {
            return Ok(Self::Average);
        }
        let (n, scale) = if let Some(n) = value.strip_suffix("ms") {
            (n, 1)
        } else if let Some(n) = value.strip_suffix('s') {
            (n, 1000)
        } else {
            bail!("bw-pacing needs average or an integer interval with ms or s units");
        };
        let ms = n
            .parse::<u64>()
            .ok()
            .and_then(|n| n.checked_mul(scale))
            .filter(|ms| (1..=10_000).contains(ms))
            .ok_or_else(|| anyhow::anyhow!("bw-pacing interval must be between 1ms and 10s"))?;
        Ok(Self::IntervalMs(ms))
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct TransferTuning {
    pub request_size: Option<u64>,
    pub pipeline_depth: Option<usize>,
    pub copy_path: Option<CopyPath>,
    pub batch_files: Option<usize>,
    pub batch_bytes: Option<u64>,
    pub split_min_size: Option<u64>,
    pub bw_pacing: Option<BwPacing>,
}

impl TransferTuning {
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
    pub fn stream_range(self, same_host: bool, bytes: u64, block: u64) -> bool {
        if self.streaming() {
            return true;
        }
        if same_host || self.copy_path == Some(CopyPath::Ranges) || self.pipeline_depth.is_some() {
            return false;
        }
        bytes > block.saturating_mul(DEFAULT_PIPELINE_DEPTH as u64)
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
                block.saturating_mul(DEFAULT_PIPELINE_DEPTH as u64)
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
    pub fn validate(self, rate: u64) -> Result<()> {
        if self.streaming() && self.pipeline_depth.is_some() {
            bail!("--tuning-options streaming copy paths cannot be combined with pipeline-depth");
        }
        if self.bw_pacing.is_some() && rate == 0 {
            bail!("--tuning-options bw-pacing requires a nonzero --bwlimit");
        }
        if self.force_ranges() && self.batch_override() {
            bail!("--tuning-options range copy paths cannot be combined with batch controls");
        }
        Ok(())
    }
    pub fn request_size(
        self,
        hash_block: u64,
        limit: Option<&crate::bwlimit::BandwidthLimit>,
        restricted_receiver: bool,
    ) -> u64 {
        let size = self.request_size.unwrap_or(hash_block);
        let size = match (limit, self.bw_pacing.unwrap_or_default()) {
            (Some(limit), BwPacing::IntervalMs(ms)) => size.min(limit.bytes_for_interval(ms)),
            _ => size,
        };
        // The signed receiver independently refuses larger writes. Tuning
        // cannot enlarge that authority; retain its released request ceiling.
        match limit {
            Some(limit) if restricted_receiver => size.min(limit.burst_bytes()),
            _ => size,
        }
    }
}

fn set_once<T>(slot: &mut Option<T>, value: T, key: &str) -> Result<()> {
    if slot.replace(value).is_some() {
        bail!("duplicate tuning option {key}");
    }
    Ok(())
}

fn size(value: &str, key: &str, min: u64, max: u64) -> Result<u64> {
    let bytes = crate::cli::parse_size(value).with_context(|| key.to_string())?;
    if !(min..=max).contains(&bytes) {
        bail!("{key} must be between {min} and {max} bytes");
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
                "request-size" => set_once(
                    &mut tuning.request_size,
                    size(value, key, 512, MAX_REQUEST_BYTES)?,
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
                    size(value, key, 512, 64 << 20)?,
                    key,
                )?,
                "split-min-size" => set_once(
                    &mut tuning.split_min_size,
                    size(value, key, 1, 1 << 30)?,
                    key,
                )?,
                "bw-pacing" => set_once(&mut tuning.bw_pacing, value.parse()?, key)?,
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
        pair!("request-size", self.request_size);
        pair!("pipeline-depth", self.pipeline_depth);
        pair!("copy-path", self.copy_path);
        pair!("batch-files", self.batch_files);
        pair!("batch-bytes", self.batch_bytes);
        pair!("split-min-size", self.split_min_size);
        pair!("bw-pacing", self.bw_pacing);
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
        self.max_request_bytes = self.max_request_bytes.max(other.max_request_bytes);
        self.max_batch_files = self.max_batch_files.max(other.max_batch_files);
        self.max_batch_bytes = self.max_batch_bytes.max(other.max_batch_bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tuning_preserves_defaults_and_bandwidth_burst_bound() {
        let hash_block = 4 << 20;
        let default = TransferTuning::default();
        assert_eq!(default.request_size(hash_block, None, false), hash_block);
        assert_eq!(default.pipeline_depth(), 4);
        assert!(!default.streaming());
        let override_: TransferTuning = "request-size=8M,pipeline-depth=16".parse().unwrap();
        assert_eq!(override_.request_size(hash_block, None, false), 8 << 20);
        let limit = crate::bwlimit::BandwidthLimit::new(1 << 20);
        assert_eq!(
            override_.request_size(hash_block, Some(&limit), false),
            128 << 10
        );
        let small: TransferTuning = "request-size=512".parse().unwrap();
        assert_eq!(small.request_size(hash_block, Some(&limit), false), 512);
        assert_eq!(
            override_.to_string().parse::<TransferTuning>().unwrap(),
            override_
        );
    }

    #[test]
    fn tuning_round_trips_every_key_for_remote_coordinators() {
        for value in [
            "copy-path=streaming,request-size=1M,split-min-size=1M,bw-pacing=average",
            "copy-path=auto-streaming,request-size=1M,batch-files=32,batch-bytes=2M",
            "request-size=8M,pipeline-depth=16,copy-path=ranges,split-min-size=1M,bw-pacing=average",
            "copy-path=auto,batch-files=4096,batch-bytes=64M,split-min-size=1G,bw-pacing=2s",
        ] {
            let tuning: TransferTuning = value.parse().unwrap();
            tuning.validate(1 << 20).unwrap();
            assert_eq!(tuning.to_string().parse::<TransferTuning>().unwrap(), tuning);
        }
        let limit = crate::bwlimit::BandwidthLimit::new(1 << 20);
        let average: TransferTuning = "request-size=8M,bw-pacing=average,split-min-size=1M"
            .parse()
            .unwrap();
        assert_eq!(average.request_size(4 << 20, Some(&limit), false), 8 << 20);
        assert_eq!(average.split_min_size(4 << 20), 8 << 20);
        let interval: TransferTuning = "bw-pacing=250ms".parse().unwrap();
        assert_eq!(
            interval.request_size(4 << 20, Some(&limit), false),
            256 << 10
        );
        assert!(average.validate(0).is_err());
        assert!("copy-path=ranges,batch-files=1"
            .parse::<TransferTuning>()
            .unwrap()
            .validate(0)
            .is_err());
    }

    #[test]
    fn tuning_preserves_the_signed_receiver_request_ceiling() {
        let limit = crate::bwlimit::BandwidthLimit::new(1 << 20);
        for pacing in ["average", "1s"] {
            let tuning: TransferTuning = format!("request-size=8M,bw-pacing={pacing}")
                .parse()
                .unwrap();
            assert_eq!(tuning.request_size(4 << 20, Some(&limit), true), 128 << 10);
        }
        let tighter: TransferTuning = "bw-pacing=25ms".parse().unwrap();
        assert_eq!(tighter.request_size(4 << 20, Some(&limit), true), 26_214);
        let uncapped: TransferTuning = "request-size=8M".parse().unwrap();
        assert_eq!(uncapped.request_size(4 << 20, None, true), 8 << 20);
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
            "bw-pacing=0ms",
            "bw-pacing=11s",
            "bw-pacing=125",
            "bw-pacing=0.1s",
            "bw-pacing=18446744073709551615s",
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
        streaming.validate(0).unwrap();
        assert!(streaming.streaming() && streaming.force_ranges());
        let automatic: TransferTuning = "copy-path=auto-streaming".parse().unwrap();
        automatic.validate(0).unwrap();
        assert!(automatic.streaming() && !automatic.force_ranges());
        "copy-path=auto-streaming,batch-files=8"
            .parse::<TransferTuning>()
            .unwrap()
            .validate(0)
            .unwrap();
        for value in [
            "copy-path=streaming,pipeline-depth=4",
            "copy-path=auto-streaming,pipeline-depth=4",
            "copy-path=streaming,batch-files=1",
            "copy-path=streaming,batch-bytes=1M",
        ] {
            assert!(value
                .parse::<TransferTuning>()
                .unwrap()
                .validate(0)
                .is_err());
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

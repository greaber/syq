//! Explicit, per-command transfer experiments. These settings are never part
//! of hash grids, resume identities, signed grants, or remembered tuning.

use anyhow::{bail, Context, Result};
use std::str::FromStr;

pub(crate) const DEFAULT_PIPELINE_DEPTH: usize = 4;
const MAX_PIPELINE_DEPTH: usize = 64;
const MAX_REQUEST_BYTES: u64 = 64 << 20;

pub(crate) const HELP: &str = "Override transfer internals for benchmarking: request-size=SIZE,pipeline-depth=N. Use one or both keys, separated by a comma. request-size accepts 512 bytes through 64M (K/M/G are binary units); its default is the hash block size, normally 4M. --bwlimit may reduce it further. pipeline-depth accepts 1 through 64 outstanding requests per endpoint per worker (default: 4); in-process endpoints remain synchronous. These options affect range transfers; whole-file optimizations can bypass them. Hash/resume blocks are unchanged. Overrides are not saved, and runs with overrides do not read or update the remembered connection count. Use a fixed connection count for comparisons.";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct TransferTuning {
    pub request_size: Option<u64>,
    pub pipeline_depth: Option<usize>,
}

impl TransferTuning {
    pub fn pipeline_depth(self) -> usize {
        self.pipeline_depth.unwrap_or(DEFAULT_PIPELINE_DEPTH)
    }

    pub fn request_size(
        self,
        hash_block: u64,
        limit: Option<&crate::bwlimit::BandwidthLimit>,
    ) -> u64 {
        let size = self.request_size.unwrap_or(hash_block);
        limit.map_or(size, |limit| size.min(limit.burst_bytes()))
    }
}

impl FromStr for TransferTuning {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        let mut tuning = Self::default();
        for pair in value.split(',') {
            let Some((key, value)) = pair.split_once('=') else {
                bail!("expected request-size=SIZE or pipeline-depth=N, got {pair:?}");
            };
            match key {
                "request-size" => {
                    if tuning.request_size.is_some() {
                        bail!("duplicate tuning option request-size");
                    }
                    let size = crate::cli::parse_size(value).context("request-size")?;
                    if !(512..=MAX_REQUEST_BYTES).contains(&size) {
                        bail!("request-size must be between 512 bytes and 64M");
                    }
                    tuning.request_size = Some(size);
                }
                "pipeline-depth" => {
                    if tuning.pipeline_depth.is_some() {
                        bail!("duplicate tuning option pipeline-depth");
                    }
                    let depth: usize =
                        value.parse().context("pipeline-depth must be an integer")?;
                    if !(1..=MAX_PIPELINE_DEPTH).contains(&depth) {
                        bail!("pipeline-depth must be between 1 and 64");
                    }
                    tuning.pipeline_depth = Some(depth);
                }
                _ => {
                    bail!("unknown tuning option {key:?}; expected request-size or pipeline-depth")
                }
            }
        }
        Ok(tuning)
    }
}

impl std::fmt::Display for TransferTuning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(size) = self.request_size {
            write!(f, "request-size={size}")?;
        }
        if let Some(depth) = self.pipeline_depth {
            if self.request_size.is_some() {
                write!(f, ",")?;
            }
            write!(f, "pipeline-depth={depth}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tuning_preserves_defaults_and_bandwidth_burst_bound() {
        let hash_block = 4 << 20;
        let default = TransferTuning::default();
        assert_eq!(default.request_size(hash_block, None), hash_block);
        assert_eq!(default.pipeline_depth(), 4);
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
        ] {
            assert!(
                value.parse::<TransferTuning>().is_err(),
                "accepted {value:?}"
            );
        }
    }
}

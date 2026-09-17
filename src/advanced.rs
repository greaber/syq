//! Public advanced controls. Limits constrain tuning; integrity is independent.
use crate::hashing::HashAlgorithm;
use anyhow::{bail, Result};
use std::str::FromStr;

pub(crate) const RESOURCE_HELP: &str = "Set resource ceilings with comma-separated KEY=VALUE pairs. bandwidth=RATE caps aggregate logical file-data bytes per second; plain numbers use KiB/s, K/M/G use powers of 1024, and 0 disables the rate cap. Limits are not saved. Worker and request counts are performance-tuning controls.";
pub(crate) const INTEGRITY_HELP: &str = "Choose content comparison and extra payload checks independently with comma-separated KEY=VALUE pairs. compare=size-mtime is the default; use compare=blake3 to detect edits that preserve size and time (--hash is a shorthand). transfer=off is the default; transfer=blake3 adds payload checks. Both roles also accept sha256, md5, and xxh3-128. Transport authentication, S3 provider checksums and recovery checks remain enabled. Same-host copies keep kernel-copy shortcuts; use --expected-hash to validate a complete result.";

#[derive(Clone, Debug, Default)]
pub(crate) struct ResourceLimits {
    pub bandwidth: Option<String>,
}
impl FromStr for ResourceLimits {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        let mut result = Self::default();
        for (key, value) in pairs(s)? {
            match key {
                "bandwidth" => {
                    crate::bwlimit::parse_rate(value)?;
                    once(&mut result.bandwidth, value.to_owned(), key)?;
                }
                _ => bail!("unknown resource limit {key:?}"),
            }
        }
        Ok(result)
    }
}
impl std::fmt::Display for ResourceLimits {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut fields = Vec::new();
        if let Some(n) = &self.bandwidth {
            fields.push(format!("bandwidth={n}"));
        }
        write!(f, "{}", fields.join(","))
    }
}
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct IntegrityChecking {
    pub compare: Option<Option<HashAlgorithm>>,
    pub transfer: Option<Option<HashAlgorithm>>,
}
impl FromStr for IntegrityChecking {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        let mut result = Self::default();
        for (key, value) in pairs(s)? {
            match key {
                "compare" => once(
                    &mut result.compare,
                    if value == "size-mtime" {
                        None
                    } else {
                        Some(value.parse()?)
                    },
                    key,
                )?,
                "transfer" => once(
                    &mut result.transfer,
                    if value == "off" {
                        None
                    } else {
                        Some(value.parse()?)
                    },
                    key,
                )?,
                _ => bail!("unknown integrity checking option {key:?}"),
            }
        }
        Ok(result)
    }
}
fn pairs(s: &str) -> Result<Vec<(&str, &str)>> {
    s.split(',')
        .map(|p| {
            p.split_once('=')
                .filter(|(k, v)| !k.is_empty() && !v.is_empty())
                .ok_or_else(|| anyhow::anyhow!("expected KEY=VALUE, got {p:?}"))
        })
        .collect()
}
fn once<T>(slot: &mut Option<T>, value: T, key: &str) -> Result<()> {
    if slot.is_some() {
        bail!("duplicate option {key:?}");
    }
    *slot = Some(value);
    Ok(())
}

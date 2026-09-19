//! Public advanced controls. Limits constrain tuning; integrity is independent.
use crate::hashing::HashAlgorithm;
use anyhow::{bail, Result};
use std::str::FromStr;

pub(crate) const RESOURCE_HELP: &str = "Set resource ceilings with comma-separated KEY=VALUE pairs. bandwidth=RATE caps aggregate logical file-data bytes per second; plain numbers use KiB/s, K/M/G use powers of 1024, and 0 disables the rate cap. Limits are not saved. workers=N caps automatically chosen filesystem copy-worker slots, 1..65536. s3-max-concurrent-requests=N caps automatic S3 data-request concurrency, 1..65536. s3-max-concurrent-objects=N caps automatic S3 object concurrency, 1..65536. s3-max-concurrent-parts-per-object=N caps automatically chosen parts or ranges per S3 object, 1..1024. A ceiling does not raise automatic defaults. Each count conflicts with the same key in --performance-tuning, which fixes that count. Counts do not bound total threads, sockets, CPU or memory.";
pub(crate) const INTEGRITY_HELP: &str = "Add extra payload checks with transfer=blake3, sha256, md5, or xxh3-128; transfer=off is the default. Transport authentication, S3 provider checksums and recovery checks remain enabled. Same-host copies keep kernel-copy shortcuts; use expected_hash in a mapping to validate a complete result.";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ResourceLimits {
    pub bandwidth: Option<String>,
    pub workers: Option<usize>,
    pub s3_requests: Option<usize>,
    pub s3_object_workers: Option<usize>,
    pub s3_part_workers: Option<usize>,
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
                "workers" => once(&mut result.workers, count(value, key, 65536)?, key)?,
                "s3-max-concurrent-requests" => {
                    once(&mut result.s3_requests, count(value, key, 65536)?, key)?
                }
                "s3-max-concurrent-objects" => once(
                    &mut result.s3_object_workers,
                    count(value, key, 65536)?,
                    key,
                )?,
                "s3-max-concurrent-parts-per-object" => {
                    once(&mut result.s3_part_workers, count(value, key, 1024)?, key)?
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
        for (key, value) in [
            ("workers", self.workers),
            ("s3-max-concurrent-requests", self.s3_requests),
            ("s3-max-concurrent-objects", self.s3_object_workers),
            ("s3-max-concurrent-parts-per-object", self.s3_part_workers),
        ] {
            if let Some(value) = value {
                fields.push(format!("{key}={value}"));
            }
        }
        write!(f, "{}", fields.join(","))
    }
}
impl ResourceLimits {
    pub fn validate(
        &self,
        tuning: crate::transfer_tuning::TransferTuning,
        s3: bool,
        removal: bool,
    ) -> Result<()> {
        if self.workers.is_some() && (s3 || removal) {
            bail!("resource-limits workers requires a filesystem copy");
        }
        if !s3
            && (self.s3_requests.is_some()
                || self.s3_object_workers.is_some()
                || self.s3_part_workers.is_some())
        {
            bail!("S3 resource limits require an S3 endpoint");
        }
        for (key, limit, fixed) in [
            ("workers", self.workers, tuning.workers),
            (
                "s3-max-concurrent-requests",
                self.s3_requests,
                tuning.s3_requests,
            ),
            (
                "s3-max-concurrent-objects",
                self.s3_object_workers,
                tuning.s3_object_workers,
            ),
            (
                "s3-max-concurrent-parts-per-object",
                self.s3_part_workers,
                tuning.s3_part_workers,
            ),
        ] {
            if limit.is_some() && fixed.is_some() {
                bail!("--resource-limits {key} conflicts with --performance-tuning {key}");
            }
        }
        Ok(())
    }
}

fn count(value: &str, key: &str, max: usize) -> Result<usize> {
    let n = value
        .parse::<usize>()
        .ok()
        .filter(|n| (1..=max).contains(n));
    n.ok_or_else(|| anyhow::anyhow!("{key} must be between 1 and {max}"))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_counts_validate_and_round_trip() {
        let limits: ResourceLimits = "bandwidth=10M,workers=4,s3-max-concurrent-requests=8,s3-max-concurrent-objects=3,s3-max-concurrent-parts-per-object=2".parse().unwrap();
        assert_eq!(
            limits.to_string().parse::<ResourceLimits>().unwrap(),
            limits
        );
        for (key, max) in [
            ("workers", 65536),
            ("s3-max-concurrent-requests", 65536),
            ("s3-max-concurrent-objects", 65536),
            ("s3-max-concurrent-parts-per-object", 1024),
        ] {
            for bad in [
                "0".to_string(),
                "-1".to_string(),
                "1.5".to_string(),
                (max + 1).to_string(),
            ] {
                assert!(format!("{key}={bad}").parse::<ResourceLimits>().is_err());
            }
            assert!(format!("{key}={max}").parse::<ResourceLimits>().is_ok());
            assert!(format!("{key}=1,{key}=2")
                .parse::<ResourceLimits>()
                .is_err());
            let limits: ResourceLimits = format!("{key}=4").parse().unwrap();
            for fixed in [2, 4, 8] {
                let tuning = format!("{key}={fixed}").parse().unwrap();
                let error = limits
                    .validate(tuning, key.starts_with("s3-"), false)
                    .unwrap_err();
                assert!(error.to_string().contains("conflicts"), "{error}");
            }
        }
        assert!("workers=4"
            .parse::<ResourceLimits>()
            .unwrap()
            .validate("request-size=1M".parse().unwrap(), false, false)
            .is_ok());
    }
}

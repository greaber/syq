//! Aggregate transfer-rate limiting shared by all copy workers.

use anyhow::{bail, Result};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Parse an rsync-style `--bwlimit` rate into bytes per second.
///
/// A bare value is in KiB/s. Single-letter and IEC suffixes use powers of
/// 1024 (`M`, `MiB`); SI `KB`/`MB`/etc. suffixes use powers of 1000. A final
/// `+1` or `-1` adjusts the scaled value by one byte. Rsync then rounds the
/// result to the nearest KiB/s and treats zero as unlimited.
pub fn parse_rate(value: &str) -> Result<u64> {
    let value = value.trim();
    if value.is_empty() {
        bail!("empty --bwlimit rate");
    }

    let (scaled, adjustment) = if let Some(s) = value.strip_suffix("+1") {
        (s, 1.0)
    } else if let Some(s) = value.strip_suffix("-1") {
        (s, -1.0)
    } else {
        (value, 0.0)
    };

    let suffix_at = scaled
        .char_indices()
        .find_map(|(i, c)| c.is_ascii_alphabetic().then_some(i))
        .unwrap_or(scaled.len());
    let (number, suffix) = scaled.split_at(suffix_at);
    let number: f64 = number
        .parse()
        .map_err(|_| anyhow::anyhow!("bad --bwlimit rate {value:?}"))?;
    if !number.is_finite() || number < 0.0 {
        bail!("bad --bwlimit rate {value:?}");
    }

    let multiplier = match suffix.to_ascii_lowercase().as_str() {
        // No suffix follows rsync's historical KiB/s default.
        "" | "k" | "kib" => 1u64 << 10,
        "b" => 1,
        "kb" => 1_000,
        "m" | "mib" => 1u64 << 20,
        "mb" => 1_000_000,
        "g" | "gib" => 1u64 << 30,
        "gb" => 1_000_000_000,
        "t" | "tib" => 1u64 << 40,
        "tb" => 1_000_000_000_000,
        "p" | "pib" => 1u64 << 50,
        "pb" => 1_000_000_000_000_000,
        _ => bail!("bad --bwlimit suffix in {value:?}"),
    };
    let bytes = number * multiplier as f64 + adjustment;
    if !bytes.is_finite() || bytes < 0.0 {
        bail!("bad --bwlimit rate {value:?}");
    }
    if bytes > u64::MAX as f64 {
        bail!("--bwlimit rate is too large: {value:?}");
    }
    if bytes == 0.0 {
        return Ok(0);
    }
    if bytes < 512.0 {
        bail!("--bwlimit rate must be 0 or at least 512 bytes/s");
    }

    // Match rsync's nearest-KiB compatibility rounding.
    let whole_bytes = bytes.round() as u128;
    let kib = (whole_bytes + 512) / 1024;
    let rate = kib
        .checked_mul(1024)
        .filter(|n| *n <= u64::MAX as u128)
        .ok_or_else(|| anyhow::anyhow!("--bwlimit rate is too large: {value:?}"))?;
    Ok(rate as u64)
}

/// A virtual-clock pacer. Each caller reserves the next interval under one
/// mutex, then sleeps without holding the lock. Sharing one instance makes the
/// cap aggregate across all worker threads.
pub struct BandwidthLimit {
    bytes_per_sec: u64,
    next: Mutex<Option<Instant>>,
}

impl BandwidthLimit {
    pub fn new(bytes_per_sec: u64) -> Self {
        assert!(bytes_per_sec > 0);
        Self {
            bytes_per_sec,
            next: Mutex::new(None),
        }
    }

    /// Keep each transfer request to roughly one eighth of a second of data,
    /// matching rsync's write-size pacing and avoiding multi-megabyte bursts at
    /// low limits. The floor permits the minimum 1 KiB/s rate without tiny
    /// protocol frames.
    pub fn burst_bytes(&self) -> u64 {
        self.bytes_for_interval(125)
    }

    /// Request-sizing budget only, not a bound on bytes on the network.
    pub fn bytes_for_interval(&self, milliseconds: u64) -> u64 {
        ((self.bytes_per_sec as u128 * milliseconds as u128 / 1000).min(u64::MAX as u128) as u64)
            .max(512)
    }

    /// Pay the entire reservation before admitting the request. With no
    /// request-size cap, this avoids a free, arbitrarily large first chunk.
    pub fn wait_prepaid(&self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        let now = Instant::now();
        let at = self.reserve_prepaid_at(now, bytes);
        if at > now {
            std::thread::sleep(at - now);
        }
    }

    fn reserve_prepaid_at(&self, now: Instant, bytes: u64) -> Instant {
        self.reserve_at(now, bytes)
            + Duration::from_secs_f64(bytes as f64 / self.bytes_per_sec as f64)
    }

    pub fn wait(&self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        let now = Instant::now();
        let at = self.reserve_at(now, bytes);
        if at > now {
            std::thread::sleep(at - now);
        }
    }

    fn reserve_at(&self, now: Instant, bytes: u64) -> Instant {
        let duration = Duration::from_secs_f64(bytes as f64 / self.bytes_per_sec as f64);
        let mut next = self.next.lock().unwrap();
        let at = next.map_or(now, |n| n.max(now));
        *next = Some(at + duration);
        at
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rsync_rates() {
        assert_eq!(parse_rate("0").unwrap(), 0);
        assert_eq!(parse_rate("1").unwrap(), 1 << 10);
        assert_eq!(parse_rate("1.5M").unwrap(), 3 << 19);
        assert_eq!(parse_rate("2MiB").unwrap(), 2 << 20);
        assert_eq!(parse_rate("1MB").unwrap(), 977 * 1024);
        assert_eq!(parse_rate("512B").unwrap(), 1024);
        assert_eq!(parse_rate("1m+1").unwrap(), 1 << 20);
        assert_eq!(parse_rate("1g-1").unwrap(), 1 << 30);
        assert_eq!(parse_rate("511B+1").unwrap(), 1024);
        assert_eq!(parse_rate("1B-1").unwrap(), 0);
    }

    #[test]
    fn rejects_bad_rates() {
        for value in ["", "-1", "1XB", "511B", "nan", "1M/s", "1M+2", "0-1"] {
            assert!(parse_rate(value).is_err(), "accepted {value:?}");
        }
    }

    #[test]
    fn prepaid_reservations_cover_the_first_request_and_share_one_budget() {
        let limit = BandwidthLimit::new(1 << 20);
        let now = Instant::now();
        assert_eq!(
            limit.reserve_prepaid_at(now, 4 << 20),
            now + Duration::from_secs(4)
        );
        assert_eq!(
            limit.reserve_prepaid_at(now, 1 << 19),
            now + Duration::from_millis(4500)
        );
        let later = now + Duration::from_secs(10);
        assert_eq!(
            limit.reserve_prepaid_at(later, 1 << 20),
            later + Duration::from_secs(1)
        );
    }

    #[test]
    fn interval_budget_handles_rounding_and_large_rates() {
        assert_eq!(BandwidthLimit::new(1024).bytes_for_interval(1), 512);
        assert_eq!(BandwidthLimit::new(2 << 20).bytes_for_interval(25), 52_428);
        assert_eq!(
            BandwidthLimit::new(u64::MAX).bytes_for_interval(10_000),
            u64::MAX
        );
    }

    #[test]
    fn reservations_are_aggregate_and_recover_after_idle_time() {
        let limit = BandwidthLimit::new(1024);
        let now = Instant::now();
        assert_eq!(limit.burst_bytes(), 512);
        assert_eq!(limit.reserve_at(now, 512), now);
        assert_eq!(limit.reserve_at(now, 512), now + Duration::from_millis(500));

        let later = now + Duration::from_secs(2);
        assert_eq!(limit.reserve_at(later, 512), later);
    }
}

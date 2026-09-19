//! Per-channel transport compression. Selection uses time spent writing wire
//! bytes, not the content's compression ratio or time spent compressing it.

use std::io;
use std::time::Duration;

pub(crate) const ZSTD: u8 = 1;
pub(crate) const LZ4: u8 = 2;
const REUSE_LIMIT: usize = 8 << 20;
const MIN_SAMPLE_BYTES: usize = 64 << 10;
const SAMPLE_BYTES: usize = 4 << 20;
const SAMPLE_TIME: Duration = Duration::from_millis(100);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Lz4,
    Zstd1,
    Zstd3,
}

struct Policy {
    mode: Mode,
    legacy: bool,
    bytes: usize,
    elapsed: Duration,
}

impl Policy {
    fn new(legacy: bool) -> Self {
        Self {
            mode: if legacy { Mode::Zstd1 } else { Mode::Lz4 },
            legacy,
            bytes: 0,
            elapsed: Duration::ZERO,
        }
    }

    fn observe(&mut self, bytes: usize, elapsed: Duration) -> bool {
        if self.legacy || elapsed.is_zero() {
            return false;
        }
        self.bytes = self.bytes.saturating_add(bytes);
        self.elapsed = self.elapsed.saturating_add(elapsed);
        if self.bytes < MIN_SAMPLE_BYTES
            || (self.bytes < SAMPLE_BYTES && self.elapsed < SAMPLE_TIME)
        {
            return false;
        }
        let rate = self.bytes as f64 / self.elapsed.as_secs_f64() / (1 << 20) as f64;
        self.bytes = 0;
        self.elapsed = Duration::ZERO;
        // Per-channel MiB/s thresholds with hysteresis. Favor Zstd on
        // intermediate-speed paths. Writes include encryption and receiver pressure;
        // this is an effective drain rate, not the physical interface speed.
        let next = match self.mode {
            _ if rate < 6.0 => Mode::Zstd3,
            _ if rate > 200.0 => Mode::Lz4,
            Mode::Lz4 if rate < 150.0 => Mode::Zstd1,
            Mode::Zstd3 if rate > 10.0 => Mode::Zstd1,
            current => current,
        };
        let changed = next != self.mode;
        self.mode = next;
        changed
    }
}

pub(crate) struct Compressor {
    policy: Policy,
    output: Vec<u8>,
    zstd: Option<(i32, zstd::bulk::Compressor<'static>)>,
}

impl Compressor {
    pub(crate) fn new(legacy: bool) -> Self {
        Self {
            policy: Policy::new(legacy),
            output: Vec::new(),
            zstd: None,
        }
    }

    /// Every eligible frame is attempted, including after incompressible data.
    /// A compressed representation must save at least 1%, including its prefix.
    pub(crate) fn encode(&mut self, input: &[u8]) -> io::Result<Option<(u8, usize)>> {
        let bound = match self.policy.mode {
            Mode::Lz4 => lz4::block::compress_bound(input.len())? + 4,
            _ => zstd::zstd_safe::compress_bound(input.len()),
        };
        if self.output.len() < bound {
            self.output
                .try_reserve_exact(bound - self.output.len())
                .map_err(io::Error::other)?;
            self.output.resize(bound, 0);
        }
        let (flag, len) = match self.policy.mode {
            Mode::Lz4 => (
                LZ4,
                lz4::block::compress_to_buffer(
                    input,
                    Some(lz4::block::CompressionMode::FAST(4)),
                    true,
                    &mut self.output[..bound],
                )?,
            ),
            mode => {
                let level = if mode == Mode::Zstd3 { 3 } else { 1 };
                if self.zstd.is_none() {
                    self.zstd = Some((level, zstd::bulk::Compressor::new(level)?));
                }
                let (previous, compressor) = self.zstd.as_mut().expect("initialized above");
                if *previous != level {
                    compressor.set_compression_level(level)?;
                    *previous = level;
                }
                (
                    ZSTD,
                    compressor.compress_to_buffer(input, &mut self.output[..bound])?,
                )
            }
        };
        Ok((len <= input.len().saturating_sub(input.len().div_ceil(100))).then_some((flag, len)))
    }

    pub(crate) fn output(&self, len: usize) -> &[u8] {
        &self.output[..len]
    }

    pub(crate) fn finish_frame(&mut self) {
        // A one-off large request must not keep tens of MiB on every channel.
        if self.output.capacity() > REUSE_LIMIT {
            self.output = Vec::new();
        }
    }

    pub(crate) fn observe_write(&mut self, bytes: usize, elapsed: Duration) -> bool {
        self.policy.observe(bytes, elapsed)
    }

    pub(crate) fn name(&self) -> &'static str {
        match self.policy.mode {
            Mode::Lz4 => "lz4",
            Mode::Zstd1 => "zstd level 1",
            Mode::Zstd3 => "zstd level 3",
        }
    }
}

pub(crate) fn decode_lz4(body: &[u8], limit: usize) -> io::Result<Vec<u8>> {
    let prefix = body
        .get(..4)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing lz4 size prefix"))?;
    let size = u32::from_le_bytes(prefix.try_into().expect("four bytes")) as usize;
    // Check before allocating or asking the C decoder to interpret the block.
    if size >= limit || size > i32::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "decompressed frame exceeds limit",
        ));
    }
    let mut output = Vec::new();
    output.try_reserve_exact(size).map_err(io::Error::other)?;
    output.resize(size, 0);
    let decoded = lz4::block::decompress_to_buffer(body, None, &mut output)?;
    if decoded != size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "lz4 decoded size does not match its prefix",
        ));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observe(policy: &mut Policy, mib_per_second: u64) {
        let bytes = (mib_per_second as usize) << 20;
        policy.observe(bytes, Duration::from_secs(1));
    }

    #[test]
    fn transport_rate_selects_codecs_in_both_directions_with_hysteresis() {
        let mut policy = Policy::new(false);
        assert_eq!(policy.mode, Mode::Lz4);
        for rate in [256, 200, 175, 150] {
            observe(&mut policy, rate);
            assert_eq!(policy.mode, Mode::Lz4);
        }
        observe(&mut policy, 149);
        assert_eq!(policy.mode, Mode::Zstd1);
        for rate in [150, 175, 199, 200] {
            observe(&mut policy, rate);
            assert_eq!(policy.mode, Mode::Zstd1);
        }
        observe(&mut policy, 201);
        assert_eq!(policy.mode, Mode::Lz4);
        for rate in [64, 100, 112] {
            let mut intermediate = Policy::new(false);
            assert_eq!(intermediate.mode, Mode::Lz4);
            observe(&mut intermediate, rate);
            assert_eq!(intermediate.mode, Mode::Zstd1);
        }
        observe(&mut policy, 4);
        assert_eq!(policy.mode, Mode::Zstd3);
        for rate in [6, 9, 10] {
            observe(&mut policy, rate);
            assert_eq!(policy.mode, Mode::Zstd3);
        }
        observe(&mut policy, 11);
        assert_eq!(policy.mode, Mode::Zstd1);
        observe(&mut policy, 6);
        assert_eq!(policy.mode, Mode::Zstd1);
        observe(&mut policy, 256);
        assert_eq!(policy.mode, Mode::Lz4);
    }

    #[test]
    fn small_writes_accumulate_without_treating_a_tiny_reply_as_a_rate_probe() {
        let mut policy = Policy::new(false);
        policy.observe(100, Duration::from_secs(1));
        assert_eq!(policy.mode, Mode::Lz4);
        policy.observe(64 << 10, Duration::from_millis(100));
        assert_eq!(policy.mode, Mode::Zstd3);
    }

    #[test]
    fn release_helper_compatibility_always_emits_zstd() {
        let mut compressor = Compressor::new(true);
        for rate in [4, 32, 1024] {
            observe(&mut compressor.policy, rate);
            assert_eq!(compressor.policy.mode, Mode::Zstd1);
            let (flag, len) = compressor.encode(&vec![b'x'; 65536]).unwrap().unwrap();
            assert_eq!(flag, ZSTD);
            assert_eq!(
                zstd::bulk::decompress(compressor.output(len), 65536).unwrap(),
                vec![b'x'; 65536]
            );
        }
    }

    #[test]
    fn all_modes_recover_immediately_after_random_data_and_bound_buffer_reuse() {
        let mut random = vec![0; 128 << 10];
        let mut state = 0x123456789abcdefu64;
        for b in &mut random {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *b = state as u8;
        }
        let text = b"the next block is compressible\n".repeat(8192);
        let mut compressor = Compressor::new(false);
        for mode in [Mode::Lz4, Mode::Zstd1, Mode::Zstd3, Mode::Lz4] {
            compressor.policy.mode = mode;
            assert!(compressor.encode(&random).unwrap().is_none());
            let (flag, len) = compressor.encode(&text).unwrap().unwrap();
            let decoded = if flag == LZ4 {
                decode_lz4(compressor.output(len), text.len() + 1).unwrap()
            } else {
                zstd::bulk::decompress(compressor.output(len), text.len()).unwrap()
            };
            assert_eq!(decoded, text);
        }
        compressor.encode(&vec![0; REUSE_LIMIT + 1]).unwrap();
        compressor.finish_frame();
        assert_eq!(compressor.output.capacity(), 0);
    }

    #[test]
    fn lz4_rejects_large_claims_truncation_and_false_lengths() {
        for body in [&[][..], &[0, 1, 2][..], &u32::MAX.to_le_bytes()[..]] {
            assert!(decode_lz4(body, 1024).is_err());
        }
        let data = vec![b'x'; 1024];
        let body = lz4::block::compress(&data, None, true).unwrap();
        assert!(decode_lz4(&body, 1024).is_err());
        assert_eq!(decode_lz4(&body, 1025).unwrap(), data);
        assert!(decode_lz4(&body[..body.len() - 1], 1025).is_err());
        let mut false_size = body;
        false_size[..4].copy_from_slice(&1025u32.to_le_bytes());
        assert!(decode_lz4(&false_size, 1026).is_err());
    }
}

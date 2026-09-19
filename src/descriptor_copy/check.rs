//! Checks requested for generated mapping bytes, without extra work by default.
use anyhow::{ensure, Context, Result};

#[derive(Clone, Debug, Default)]
pub(crate) struct Expected {
    pub size: Option<u64>,
    pub hash: Option<crate::hashing::Digest>,
}
pub(crate) struct Check {
    expected: Expected,
    bytes: u64,
    hash: Option<crate::hashing::Hasher>,
}
impl Expected {
    pub fn start(&self) -> Check {
        Check {
            expected: self.clone(),
            bytes: 0,
            hash: self.hash.as_ref().map(|h| h.algorithm.hasher()),
        }
    }
}
impl Check {
    pub fn add(&mut self, data: &[u8]) -> Result<()> {
        self.bytes = self
            .bytes
            .checked_add(data.len() as u64)
            .context("stream length overflow")?;
        ensure!(
            self.expected.size.is_none_or(|size| self.bytes <= size),
            "stream exceeds its promised size"
        );
        if let Some(hash) = &mut self.hash {
            hash.update(data);
        }
        Ok(())
    }
    pub fn finish(self) -> Result<u64> {
        if let Some(size) = self.expected.size {
            ensure!(
                self.bytes == size,
                "stream promised {size} bytes but produced {}",
                self.bytes
            );
        }
        if let Some(hash) = self.hash {
            self.expected
                .hash
                .as_ref()
                .unwrap()
                .verify(&hash.finalize())?;
        }
        Ok(self.bytes)
    }
}

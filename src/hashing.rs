//! File checksums. Authority and receipt commitments use their fixed algorithms.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use std::io::Read;
use std::str::FromStr;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
pub(crate) enum HashAlgorithm {
    #[default]
    #[serde(rename = "blake3")]
    Blake3,
    #[serde(rename = "sha256")]
    Sha256,
    #[serde(rename = "md5")]
    Md5,
    #[serde(rename = "xxh3-128")]
    #[value(name = "xxh3-128")]
    Xxh3,
}

impl HashAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Blake3 => "blake3",
            Self::Sha256 => "sha256",
            Self::Md5 => "md5",
            Self::Xxh3 => "xxh3-128",
        }
    }

    pub fn output_len(self) -> usize {
        match self {
            Self::Blake3 | Self::Sha256 => 32,
            Self::Md5 | Self::Xxh3 => 16,
        }
    }

    pub fn hasher(self) -> Hasher {
        match self {
            Self::Blake3 => Hasher::Blake3(Box::new(blake3::Hasher::new())),
            Self::Sha256 => Hasher::Sha256(sha2::Sha256::new()),
            Self::Md5 => Hasher::Md5(md5::Md5::new()),
            Self::Xxh3 => Hasher::Xxh3(Box::new(xxhash_rust::xxh3::Xxh3::new())),
        }
    }

    // The helper protocol retains its fixed-width representation. Short hashes
    // have zero padding; public values use only the algorithm's actual width.
    pub fn hash(self, bytes: &[u8]) -> [u8; 32] {
        let mut result = [0; 32];
        match self {
            Self::Blake3 => result.copy_from_slice(blake3::hash(bytes).as_bytes()),
            Self::Sha256 => result.copy_from_slice(&sha2::Sha256::digest(bytes)),
            Self::Md5 => result[..16].copy_from_slice(&md5::Md5::digest(bytes)),
            Self::Xxh3 => {
                result[..16].copy_from_slice(&xxhash_rust::xxh3::xxh3_128(bytes).to_be_bytes())
            }
        }
        result
    }
}

impl std::fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for HashAlgorithm {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "blake3" => Ok(Self::Blake3),
            "sha256" => Ok(Self::Sha256),
            "md5" => Ok(Self::Md5),
            "xxh3-128" => Ok(Self::Xxh3),
            _ => {
                bail!("unknown hash algorithm {value:?}; expected blake3, sha256, md5, or xxh3-128")
            }
        }
    }
}

pub(crate) enum Hasher {
    Blake3(Box<blake3::Hasher>),
    Sha256(sha2::Sha256),
    Md5(md5::Md5),
    Xxh3(Box<xxhash_rust::xxh3::Xxh3>),
}

impl Hasher {
    pub fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Blake3(h) => {
                h.update(bytes);
            }
            Self::Sha256(h) => h.update(bytes),
            Self::Md5(h) => h.update(bytes),
            Self::Xxh3(h) => h.update(bytes),
        }
    }

    pub fn finalize(self) -> [u8; 32] {
        let mut result = [0; 32];
        match self {
            Self::Blake3(h) => result.copy_from_slice(h.finalize().as_bytes()),
            Self::Sha256(h) => result.copy_from_slice(&h.finalize()),
            Self::Md5(h) => result[..16].copy_from_slice(&h.finalize()),
            Self::Xxh3(h) => result[..16].copy_from_slice(&h.digest128().to_be_bytes()),
        }
        result
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct HashPolicy {
    pub algorithm: HashAlgorithm,
    pub transfer_integrity: bool,
    #[serde(default)]
    pub transfer_hash_type: Option<HashAlgorithm>,
}

impl HashPolicy {
    pub fn payload_algorithm(self) -> HashAlgorithm {
        self.transfer_hash_type.unwrap_or(self.algorithm)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CopyHashing {
    pub policy: HashPolicy,
    // Preserve the spelling inside signed grants; public mappings use expected_hash.
    #[serde(rename = "expected_digest")]
    pub expected_hash: Option<Digest>,
}

impl CopyHashing {
    pub fn from_args(args: &crate::cli::Args) -> Self {
        Self {
            policy: HashPolicy {
                algorithm: args.hash_algorithm,
                transfer_integrity: args.transfer_integrity,
                transfer_hash_type: args.transfer_hash_type,
            },
            expected_hash: args.expected_hash.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "DigestInput")]
pub(crate) struct Digest {
    pub algorithm: HashAlgorithm,
    pub value: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DigestInput {
    algorithm: HashAlgorithm,
    value: String,
}

impl TryFrom<DigestInput> for Digest {
    type Error = anyhow::Error;

    fn try_from(input: DigestInput) -> Result<Self> {
        Self::new(input.algorithm, input.value)
    }
}

impl Digest {
    pub fn validate(&self) -> Result<()> {
        Self::new(self.algorithm, self.value.clone()).map(|_| ())
    }

    pub fn new(algorithm: HashAlgorithm, value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.len() != algorithm.output_len() * 2
            || !value.bytes().all(|b| b.is_ascii_hexdigit())
        {
            bail!(
                "{algorithm} hash must contain exactly {} hexadecimal characters",
                algorithm.output_len() * 2
            );
        }
        Ok(Self {
            algorithm,
            value: value.to_ascii_lowercase(),
        })
    }

    pub fn from_hash(algorithm: HashAlgorithm, hash: &[u8; 32]) -> Self {
        let value = hash[..algorithm.output_len()]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        Self { algorithm, value }
    }

    pub fn hash_bytes(algorithm: HashAlgorithm, bytes: &[u8]) -> Self {
        Self::from_hash(algorithm, &algorithm.hash(bytes))
    }

    pub fn verify(&self, actual: &[u8; 32]) -> Result<()> {
        let actual = Self::from_hash(self.algorithm, actual);
        if actual != *self {
            bail!(
                "expected {} hash {}, got {}",
                self.algorithm,
                self.value,
                actual.value
            );
        }
        Ok(())
    }

    pub fn verify_reader(&self, reader: &mut impl Read) -> Result<()> {
        let mut hasher = self.algorithm.hasher();
        let mut buffer = vec![0; 1024 * 1024];
        loop {
            let count = reader
                .read(&mut buffer)
                .context("read file for expected hash")?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        self.verify(&hasher.finalize())
    }
}

impl FromStr for Digest {
    type Err = anyhow::Error;

    fn from_str(text: &str) -> Result<Self> {
        let (algorithm, value) = text
            .split_once(':')
            .context("expected hash must be ALGORITHM:HEX")?;
        Self::new(algorithm.parse()?, value)
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.algorithm, self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_vectors_and_streaming_agree() {
        for (algorithm, expected) in [
            (
                HashAlgorithm::Blake3,
                "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85",
            ),
            (
                HashAlgorithm::Sha256,
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (HashAlgorithm::Md5, "900150983cd24fb0d6963f7d28e17f72"),
            (HashAlgorithm::Xxh3, "06b05ab6733a618578af5f94892f3950"),
        ] {
            let digest = Digest::new(algorithm, expected).unwrap();
            digest.verify(&algorithm.hash(b"abc")).unwrap();
            let mut h = algorithm.hasher();
            h.update(b"a");
            h.update(b"bc");
            digest.verify(&h.finalize()).unwrap();
            assert!(digest.verify(&algorithm.hash(b"abd")).is_err());
            let encoded = postcard::to_allocvec(&digest).unwrap();
            assert_eq!(postcard::from_bytes::<Digest>(&encoded).unwrap(), digest);
        }
    }

    #[test]
    fn malformed_expectations_fail_during_parsing() {
        for text in [
            "md5:00",
            "unknown:00",
            "md5",
            "md5:gggggggggggggggggggggggggggggggg",
        ] {
            assert!(text.parse::<Digest>().is_err());
        }
        assert!(serde_json::from_str::<Digest>(r#"{"algorithm":"md5","value":"00"}"#).is_err());
        let parsed: Digest = "md5:900150983CD24FB0D6963F7D28E17F72".parse().unwrap();
        assert_eq!(parsed.value, "900150983cd24fb0d6963f7d28e17f72");
    }
}

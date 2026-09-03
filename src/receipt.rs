//! Signed receipts: hostB's own account of what a command-restricted
//! transfer did to its disk.
//!
//! Nothing from the receiver reaches the invoking machine except through the
//! source-side coordinator, so the receiver signs a summary bound to the
//! grant's request ID with a key only it holds. The coordinator relays the
//! envelope opaquely; the invoking machine verifies it against the public key
//! recorded at enrollment. The receipt attests hostB's view; it says nothing
//! about the source's completeness or authenticity.

use crate::delegation::RequestId;
use crate::enrollment::EnrollmentId;
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use ssh_key::{HashAlg, LineEnding, PrivateKey, PublicKey, SshSig};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const RECEIPT_NAMESPACE: &str = "syq-receipt-v1@greaber.github";
/// The coordinator prints the base64 envelope after this prefix as one
/// stdout line; the invoking machine filters that line out and verifies it.
pub(crate) const RECEIPT_LINE_PREFIX: &str = "syq-receipt-v1:";
const WIRE_MAGIC: &[u8; 8] = b"SYQRCPT\0";
const WIRE_VERSION: u16 = 1;
const WIRE_HEADER_LEN: usize = WIRE_MAGIC.len() + 2 + 4 + 4;
/// Lists longer than this travel as their digest only, so a receipt for a
/// very large transfer stays a bounded single line on the relay path.
pub(crate) const LIST_LIMIT: usize = 65_536;
const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;
/// Lists whose encodings together exceed this travel as their digest only,
/// whatever their entry count, so a receipt of long paths still fits.
pub(crate) const MAX_LIST_BYTES: usize = 16 * 1024 * 1024;
const MAX_SIGNATURE_BYTES: usize = 16 * 1024;
pub(crate) const MAX_REFUSAL_SAMPLES: usize = 8;

/// One file the receiver published under a final name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PublishedV1 {
    pub path: Vec<u8>,
    pub size: u64,
    /// BLAKE3 of the published contents, present only for hashed receipts
    /// and only once the file is complete.
    pub digest: Option<[u8; 32]>,
    /// False for an in-place file whose bytes changed but whose final step
    /// never ran; staged files appear only once complete.
    pub complete: bool,
}

/// One file the receiver hashed for the coordinator (`--verify-only`,
/// `--hash`); this is hostB's view of that object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ObservedV1 {
    pub path: Vec<u8>,
    pub size: u64,
    pub digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ReceiptV1 {
    pub enrollment_id: EnrollmentId,
    pub request_id: RequestId,
    pub issued_at: i64,
    pub published_count: u64,
    pub published_bytes: u64,
    /// Published entries that were left incomplete.
    pub incomplete_count: u64,
    pub deleted_count: u64,
    pub observed_count: u64,
    /// Requests the grant refused, with the first few messages.
    pub refused: u64,
    pub refusal_samples: Vec<String>,
    /// Distinct destination entries the grant observed or mutated, and file
    /// bytes it accepted.
    pub entries: u64,
    pub transferred_bytes: u64,
    /// BLAKE3 over the canonical encoding of the complete sorted lists, so
    /// the lists can be checked or omitted independently of the signature.
    pub list_digest: [u8; 32],
    /// True when a list exceeded `LIST_LIMIT` and was omitted below.
    pub lists_truncated: bool,
    pub published: Vec<PublishedV1>,
    pub deleted: Vec<Vec<u8>>,
    pub observed: Vec<ObservedV1>,
}

/// One published path as the receiver tracks it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Published {
    pub size: u64,
    pub digest: Option<[u8; 32]>,
    pub complete: bool,
}

/// What the receiver accumulates while a grant runs.
#[derive(Debug, Default)]
pub(crate) struct Ledger {
    pub published: BTreeMap<Vec<u8>, Published>,
    pub deleted: BTreeSet<Vec<u8>>,
    pub observed: BTreeMap<Vec<u8>, (u64, [u8; 32])>,
    pub refused: u64,
    pub refusal_samples: Vec<String>,
    /// Files a hashed receipt could not read back; any entry here means no
    /// receipt can be issued.
    pub hash_failures: Vec<String>,
}

impl Ledger {
    pub(crate) fn record_refusal(&mut self, message: &str) {
        self.refused += 1;
        if self.refusal_samples.len() < MAX_REFUSAL_SAMPLES {
            self.refusal_samples.push(message.to_owned());
        }
    }

    /// Build the receipt body. `entries` and `transferred_bytes` come from the
    /// authority's own counters.
    pub(crate) fn receipt(
        &self,
        enrollment_id: EnrollmentId,
        request_id: RequestId,
        issued_at: i64,
        entries: u64,
        transferred_bytes: u64,
    ) -> Result<ReceiptV1> {
        let published: Vec<PublishedV1> = self
            .published
            .iter()
            .map(|(path, state)| PublishedV1 {
                path: path.clone(),
                size: state.size,
                digest: state.digest,
                complete: state.complete,
            })
            .collect();
        let incomplete_count = published.iter().filter(|item| !item.complete).count() as u64;
        let deleted: Vec<Vec<u8>> = self.deleted.iter().cloned().collect();
        let observed: Vec<ObservedV1> = self
            .observed
            .iter()
            .map(|(path, (size, digest))| ObservedV1 {
                path: path.clone(),
                size: *size,
                digest: *digest,
            })
            .collect();
        let list_digest = list_digest(&published, &deleted, &observed)?;
        let encoded_lists = postcard::to_stdvec(&published)?.len()
            + postcard::to_stdvec(&deleted)?.len()
            + postcard::to_stdvec(&observed)?.len();
        let lists_truncated = published.len() > LIST_LIMIT
            || deleted.len() > LIST_LIMIT
            || observed.len() > LIST_LIMIT
            || encoded_lists > MAX_LIST_BYTES;
        let published_bytes = published
            .iter()
            .try_fold(0u64, |total, item| total.checked_add(item.size))
            .context("published byte total overflow")?;
        Ok(ReceiptV1 {
            enrollment_id,
            request_id,
            issued_at,
            published_count: published.len() as u64,
            published_bytes,
            incomplete_count,
            deleted_count: deleted.len() as u64,
            observed_count: observed.len() as u64,
            refused: self.refused,
            refusal_samples: self.refusal_samples.clone(),
            entries,
            transferred_bytes,
            list_digest,
            lists_truncated,
            published: if lists_truncated {
                Vec::new()
            } else {
                published
            },
            deleted: if lists_truncated { Vec::new() } else { deleted },
            observed: if lists_truncated {
                Vec::new()
            } else {
                observed
            },
        })
    }
}

pub(crate) fn list_digest(
    published: &[PublishedV1],
    deleted: &[Vec<u8>],
    observed: &[ObservedV1],
) -> Result<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    for (label, bytes) in [
        ("published", postcard::to_stdvec(published)?),
        ("deleted", postcard::to_stdvec(deleted)?),
        ("observed", postcard::to_stdvec(observed)?),
    ] {
        hasher.update(&(label.len() as u32).to_be_bytes());
        hasher.update(label.as_bytes());
        hasher.update(&(bytes.len() as u64).to_be_bytes());
        hasher.update(&bytes);
    }
    Ok(*hasher.finalize().as_bytes())
}

fn signing_payload(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(WIRE_MAGIC.len() + 2 + 4 + body.len());
    out.extend_from_slice(WIRE_MAGIC);
    out.extend_from_slice(&WIRE_VERSION.to_be_bytes());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// Sign a receipt with the receiver's key into a self-describing envelope.
pub(crate) fn sign(receipt: &ReceiptV1, private_key: &PrivateKey) -> Result<Vec<u8>> {
    if private_key.is_encrypted() {
        bail!("cannot sign a receipt with an encrypted key");
    }
    let body = postcard::to_stdvec(receipt).context("encode receipt")?;
    if body.len() > MAX_BODY_BYTES {
        bail!("receipt exceeds {MAX_BODY_BYTES} bytes");
    }
    let signature = private_key
        .sign(RECEIPT_NAMESPACE, HashAlg::Sha256, &signing_payload(&body))
        .context("sign receipt")?
        .to_pem(LineEnding::LF)
        .context("encode receipt signature")?
        .into_bytes();
    if signature.len() > MAX_SIGNATURE_BYTES {
        bail!("receipt signature exceeds {MAX_SIGNATURE_BYTES} bytes");
    }
    let mut out = Vec::with_capacity(WIRE_HEADER_LEN + body.len() + signature.len());
    out.extend_from_slice(WIRE_MAGIC);
    out.extend_from_slice(&WIRE_VERSION.to_be_bytes());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&(signature.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    out.extend_from_slice(&signature);
    Ok(out)
}

/// Verify an envelope against the enrollment's receipt public key and return
/// the receipt. The caller still checks that the IDs are the ones it signed.
#[cfg_attr(not(test), allow(dead_code))] // used by the local verifier
pub(crate) fn verify(envelope: &[u8], public_key: &str) -> Result<ReceiptV1> {
    let public_key =
        PublicKey::from_openssh(public_key).context("parse enrollment receipt public key")?;
    if envelope.len() < WIRE_HEADER_LEN || &envelope[..WIRE_MAGIC.len()] != WIRE_MAGIC {
        bail!("not a syq receipt envelope");
    }
    let version = u16::from_be_bytes(envelope[8..10].try_into().expect("fixed header"));
    if version != WIRE_VERSION {
        bail!("unsupported receipt envelope version {version}");
    }
    let body_len = u32::from_be_bytes(envelope[10..14].try_into().expect("fixed header")) as usize;
    let signature_len =
        u32::from_be_bytes(envelope[14..18].try_into().expect("fixed header")) as usize;
    if body_len == 0 || body_len > MAX_BODY_BYTES {
        bail!("receipt length is outside the supported range");
    }
    if signature_len == 0 || signature_len > MAX_SIGNATURE_BYTES {
        bail!("receipt signature length is outside the supported range");
    }
    let expected = WIRE_HEADER_LEN
        .checked_add(body_len)
        .and_then(|length| length.checked_add(signature_len))
        .ok_or_else(|| anyhow!("receipt envelope length overflow"))?;
    if envelope.len() != expected {
        bail!("receipt envelope length is noncanonical");
    }
    let body = &envelope[WIRE_HEADER_LEN..WIRE_HEADER_LEN + body_len];
    let signature = std::str::from_utf8(&envelope[WIRE_HEADER_LEN + body_len..])
        .context("receipt signature is not text")?;
    let signature = SshSig::from_pem(signature).context("parse receipt signature")?;
    public_key
        .verify(RECEIPT_NAMESPACE, &signing_payload(body), &signature)
        .context("receipt signature does not verify against the enrollment's receipt key")?;
    let receipt: ReceiptV1 = postcard::from_bytes(body).context("decode receipt")?;
    if postcard::to_stdvec(&receipt)? != body {
        bail!("receipt uses a noncanonical encoding");
    }
    if !receipt.lists_truncated
        && list_digest(&receipt.published, &receipt.deleted, &receipt.observed)?
            != receipt.list_digest
    {
        bail!("receipt lists do not match their digest");
    }
    if receipt.refusal_samples.len() > MAX_REFUSAL_SAMPLES
        || receipt.refusal_samples.len() as u64 > receipt.refused
    {
        bail!("receipt refusal samples are inconsistent");
    }
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> PrivateKey {
        let keypair = ssh_key::private::Ed25519Keypair::from_seed(&[seed; 32]);
        PrivateKey::new(keypair.into(), "syq-receipt-test").unwrap()
    }

    fn ledger() -> Ledger {
        let mut ledger = Ledger::default();
        ledger.published.insert(
            b"/srv/dst/b".to_vec(),
            Published {
                size: 4,
                digest: Some([7; 32]),
                complete: true,
            },
        );
        ledger.published.insert(
            b"/srv/dst/a".to_vec(),
            Published {
                size: 10,
                digest: None,
                complete: false,
            },
        );
        ledger.deleted.insert(b"/srv/dst/gone".to_vec());
        ledger
            .observed
            .insert(b"/srv/dst/kept".to_vec(), (3, [9; 32]));
        ledger.record_refusal("out of scope");
        ledger
    }

    #[test]
    fn receipts_round_trip_and_bind_to_the_signing_key() {
        let enrollment_id = EnrollmentId::random();
        let request_id = RequestId::fresh(1_900_000_000).unwrap();
        let receipt = ledger()
            .receipt(enrollment_id, request_id, 1_900_000_000, 5, 14)
            .unwrap();
        assert_eq!(receipt.published_count, 2);
        assert_eq!(receipt.published_bytes, 14);
        assert_eq!(receipt.incomplete_count, 1);
        assert_eq!(receipt.deleted_count, 1);
        assert_eq!(receipt.observed_count, 1);
        assert_eq!(receipt.refused, 1);
        assert_eq!(receipt.published[0].path, b"/srv/dst/a");
        assert!(!receipt.lists_truncated);

        let signer = key(1);
        let envelope = sign(&receipt, &signer).unwrap();
        let public = signer.public_key().to_openssh().unwrap();
        assert_eq!(verify(&envelope, &public).unwrap(), receipt);

        let other = key(2).public_key().to_openssh().unwrap();
        assert!(verify(&envelope, &other).is_err());
        let mut tampered = envelope.clone();
        let body_start = WIRE_HEADER_LEN + 40;
        tampered[body_start] ^= 1;
        assert!(verify(&tampered, &public).is_err());
        let mut truncated = envelope.clone();
        truncated.pop();
        assert!(verify(&truncated, &public).is_err());
    }

    #[test]
    fn long_paths_truncate_by_encoded_size() {
        let mut ledger = Ledger::default();
        let long = vec![b'p'; 4096];
        for index in 0..(MAX_LIST_BYTES / 4096 + 2) {
            let mut path = format!("/{index:08}/").into_bytes();
            path.extend_from_slice(&long);
            ledger.published.insert(
                path,
                Published {
                    size: 1,
                    digest: None,
                    complete: true,
                },
            );
        }
        let receipt = ledger
            .receipt(
                EnrollmentId::random(),
                RequestId::fresh(1_900_000_000).unwrap(),
                1_900_000_000,
                0,
                0,
            )
            .unwrap();
        assert!(receipt.lists_truncated);
        assert!(receipt.published.is_empty());
        let signer = key(4);
        let envelope = sign(&receipt, &signer).unwrap();
        assert!(envelope.len() < MAX_LIST_BYTES);
        verify(&envelope, &signer.public_key().to_openssh().unwrap()).unwrap();
    }

    #[test]
    fn oversized_lists_travel_as_their_digest() {
        let mut ledger = Ledger::default();
        for index in 0..=LIST_LIMIT {
            ledger.published.insert(
                format!("/srv/dst/{index:08}").into_bytes(),
                Published {
                    size: 1,
                    digest: None,
                    complete: true,
                },
            );
        }
        let receipt = ledger
            .receipt(
                EnrollmentId::random(),
                RequestId::fresh(1_900_000_000).unwrap(),
                1_900_000_000,
                0,
                0,
            )
            .unwrap();
        assert!(receipt.lists_truncated);
        assert!(receipt.published.is_empty());
        assert_eq!(receipt.published_count, LIST_LIMIT as u64 + 1);
        let signer = key(3);
        let envelope = sign(&receipt, &signer).unwrap();
        let public = signer.public_key().to_openssh().unwrap();
        assert_eq!(
            verify(&envelope, &public).unwrap().published_count,
            receipt.published_count
        );
    }
}

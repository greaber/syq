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
use serde::ser::SerializeSeq;
use serde::{Deserialize, Serialize};
use ssh_key::{HashAlg, LineEnding, PrivateKey, PublicKey, SshSig};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufWriter, Write};

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

#[derive(Serialize)]
struct PublishedRef<'a> {
    path: &'a [u8],
    size: u64,
    digest: Option<[u8; 32]>,
    complete: bool,
}

struct PublishedList<'a>(&'a BTreeMap<Vec<u8>, Published>);

impl Serialize for PublishedList<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for (path, state) in self.0 {
            sequence.serialize_element(&PublishedRef {
                path,
                size: state.size,
                digest: state.digest,
                complete: state.complete,
            })?;
        }
        sequence.end()
    }
}

struct DeletedList<'a>(&'a BTreeSet<Vec<u8>>);

impl Serialize for DeletedList<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for path in self.0 {
            sequence.serialize_element(path.as_slice())?;
        }
        sequence.end()
    }
}

#[derive(Serialize)]
struct ObservedRef<'a> {
    path: &'a [u8],
    size: u64,
    digest: [u8; 32],
}

struct ObservedList<'a>(&'a BTreeMap<Vec<u8>, (u64, [u8; 32])>);

impl Serialize for ObservedList<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for (path, (size, digest)) in self.0 {
            sequence.serialize_element(&ObservedRef {
                path,
                size: *size,
                digest: *digest,
            })?;
        }
        sequence.end()
    }
}

struct DigestWriter<'a>(&'a mut blake3::Hasher);

impl Write for DigestWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
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
        let (published_bytes, incomplete_count) = self.published.values().try_fold(
            (0u64, 0u64),
            |(bytes, incomplete), state| -> Result<_> {
                Ok((
                    bytes
                        .checked_add(state.size)
                        .context("published byte total overflow")?,
                    incomplete + u64::from(!state.complete),
                ))
            },
        )?;
        let published_list = PublishedList(&self.published);
        let deleted_list = DeletedList(&self.deleted);
        let observed_list = ObservedList(&self.observed);
        let (list_digest, encoded_lists) =
            serialized_list_digest(&published_list, &deleted_list, &observed_list)?;
        let lists_truncated = self.published.len() > LIST_LIMIT
            || self.deleted.len() > LIST_LIMIT
            || self.observed.len() > LIST_LIMIT
            || encoded_lists > MAX_LIST_BYTES;
        let published = if lists_truncated {
            Vec::new()
        } else {
            self.published
                .iter()
                .map(|(path, state)| PublishedV1 {
                    path: path.clone(),
                    size: state.size,
                    digest: state.digest,
                    complete: state.complete,
                })
                .collect()
        };
        let deleted = if lists_truncated {
            Vec::new()
        } else {
            self.deleted.iter().cloned().collect()
        };
        let observed = if lists_truncated {
            Vec::new()
        } else {
            self.observed
                .iter()
                .map(|(path, (size, digest))| ObservedV1 {
                    path: path.clone(),
                    size: *size,
                    digest: *digest,
                })
                .collect()
        };
        Ok(ReceiptV1 {
            enrollment_id,
            request_id,
            issued_at,
            published_count: self.published.len() as u64,
            published_bytes,
            incomplete_count,
            deleted_count: self.deleted.len() as u64,
            observed_count: self.observed.len() as u64,
            refused: self.refused,
            refusal_samples: self.refusal_samples.clone(),
            entries,
            transferred_bytes,
            list_digest,
            lists_truncated,
            published,
            deleted,
            observed,
        })
    }
}

fn serialized_len(value: &(impl Serialize + ?Sized)) -> Result<usize> {
    Ok(postcard::experimental::serialized_size(value)?)
}

fn digest_serialized(
    hasher: &mut blake3::Hasher,
    label: &str,
    value: &(impl Serialize + ?Sized),
    encoded_len: usize,
) -> Result<()> {
    hasher.update(&(label.len() as u32).to_be_bytes());
    hasher.update(label.as_bytes());
    hasher.update(&(encoded_len as u64).to_be_bytes());
    // Postcard emits many single-byte writes. Buffer those calls so hashing a
    // large list stays CPU-efficient without materializing its whole encoding.
    let mut writer = BufWriter::with_capacity(64 * 1024, DigestWriter(hasher));
    postcard::to_io(value, &mut writer)?;
    writer.flush()?;
    Ok(())
}

fn serialized_list_digest(
    published: &(impl Serialize + ?Sized),
    deleted: &(impl Serialize + ?Sized),
    observed: &(impl Serialize + ?Sized),
) -> Result<([u8; 32], usize)> {
    let published_len = serialized_len(published)?;
    let deleted_len = serialized_len(deleted)?;
    let observed_len = serialized_len(observed)?;
    let encoded_len = published_len
        .checked_add(deleted_len)
        .and_then(|length| length.checked_add(observed_len))
        .context("serialized receipt list length overflow")?;
    let mut hasher = blake3::Hasher::new();
    digest_serialized(&mut hasher, "published", published, published_len)?;
    digest_serialized(&mut hasher, "deleted", deleted, deleted_len)?;
    digest_serialized(&mut hasher, "observed", observed, observed_len)?;
    Ok((*hasher.finalize().as_bytes(), encoded_len))
}

pub(crate) fn list_digest(
    published: &[PublishedV1],
    deleted: &[Vec<u8>],
    observed: &[ObservedV1],
) -> Result<[u8; 32]> {
    Ok(serialized_list_digest(published, deleted, observed)?.0)
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
    let body_len = serialized_len(receipt).context("size receipt encoding")?;
    if body_len > MAX_BODY_BYTES {
        bail!("receipt exceeds {MAX_BODY_BYTES} bytes");
    }
    // Build the signed payload in the envelope's final allocation. Once it is
    // signed, make room for the signature-length field in place. This avoids
    // copying a potentially 16 MiB body into both a signing buffer and then a
    // second envelope buffer.
    let signed_header_len = WIRE_MAGIC.len() + 2 + 4;
    let mut out = Vec::with_capacity(WIRE_HEADER_LEN + body_len + MAX_SIGNATURE_BYTES);
    out.extend_from_slice(WIRE_MAGIC);
    out.extend_from_slice(&WIRE_VERSION.to_be_bytes());
    out.extend_from_slice(&(body_len as u32).to_be_bytes());
    out = postcard::to_extend(receipt, out).context("encode receipt")?;
    debug_assert_eq!(out.len(), signed_header_len + body_len);
    let signature = private_key
        .sign(RECEIPT_NAMESPACE, HashAlg::Sha256, &out)
        .context("sign receipt")?
        .to_pem(LineEnding::LF)
        .context("encode receipt signature")?
        .into_bytes();
    if signature.len() > MAX_SIGNATURE_BYTES {
        bail!("receipt signature exceeds {MAX_SIGNATURE_BYTES} bytes");
    }
    let payload_len = out.len();
    out.resize(payload_len + 4, 0);
    out.copy_within(signed_header_len..payload_len, WIRE_HEADER_LEN);
    out[signed_header_len..WIRE_HEADER_LEN]
        .copy_from_slice(&(signature.len() as u32).to_be_bytes());
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
    fn streaming_ledger_encoding_preserves_the_v1_digest() {
        let ledger = ledger();
        let published: Vec<PublishedV1> = ledger
            .published
            .iter()
            .map(|(path, state)| PublishedV1 {
                path: path.clone(),
                size: state.size,
                digest: state.digest,
                complete: state.complete,
            })
            .collect();
        let deleted: Vec<Vec<u8>> = ledger.deleted.iter().cloned().collect();
        let observed: Vec<ObservedV1> = ledger
            .observed
            .iter()
            .map(|(path, (size, digest))| ObservedV1 {
                path: path.clone(),
                size: *size,
                digest: *digest,
            })
            .collect();

        assert_eq!(
            postcard::to_stdvec(&PublishedList(&ledger.published)).unwrap(),
            postcard::to_stdvec(&published).unwrap()
        );
        assert_eq!(
            postcard::to_stdvec(&DeletedList(&ledger.deleted)).unwrap(),
            postcard::to_stdvec(&deleted).unwrap()
        );
        assert_eq!(
            postcard::to_stdvec(&ObservedList(&ledger.observed)).unwrap(),
            postcard::to_stdvec(&observed).unwrap()
        );

        let mut legacy = blake3::Hasher::new();
        for (label, bytes) in [
            ("published", postcard::to_stdvec(&published).unwrap()),
            ("deleted", postcard::to_stdvec(&deleted).unwrap()),
            ("observed", postcard::to_stdvec(&observed).unwrap()),
        ] {
            legacy.update(&(label.len() as u32).to_be_bytes());
            legacy.update(label.as_bytes());
            legacy.update(&(bytes.len() as u64).to_be_bytes());
            legacy.update(&bytes);
        }
        assert_eq!(
            serialized_list_digest(
                &PublishedList(&ledger.published),
                &DeletedList(&ledger.deleted),
                &ObservedList(&ledger.observed)
            )
            .unwrap()
            .0,
            *legacy.finalize().as_bytes()
        );
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

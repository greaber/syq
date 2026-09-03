//! Receipt v2: a complete receiver-authored record stream, a small signed
//! terminal commitment, and optional HPKE delivery to the invoking machine.
//!
//! The stream records logical pathname operations and closure-time state. It
//! deliberately does not attest source completeness, block writes, syscalls,
//! or hostB-local writers. An authenticated expected manifest is a separate
//! future layer.

use crate::delegation::RequestId;
use crate::enrollment::EnrollmentId;
use crate::proto::Kind;
use anyhow::{anyhow, bail, Context, Result};
use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, setup_receiver, setup_sender,
    Deserializable, Kem as _, OpModeR, OpModeS, Serializable,
};
use serde::{Deserialize, Serialize};
use ssh_key::{HashAlg, LineEnding, PrivateKey, PublicKey, SshSig};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use zeroize::Zeroize;

type Kem = X25519HkdfSha256;
type Kdf = HkdfSha256;
type Aead = ChaCha20Poly1305;

pub(crate) const RECEIPT_NAMESPACE: &str = "syq-receipt-v2@greaber.github";
pub(crate) const RECEIPT_LINE_PREFIX: &str = "syq-receipt-v2:";
const TERMINAL_MAGIC: &[u8; 8] = b"SYQRCV2\0";
const TERMINAL_VERSION: u16 = 2;
const FRAME_MAGIC: &[u8; 8] = b"SYQRFV2\0";
const FRAME_VERSION: u16 = 2;
const HEADER_LEN: usize = 8 + 2 + 4;
const TERMINAL_HEADER_LEN: usize = 8 + 2 + 4 + 4;
const MAX_TERMINAL_BYTES: usize = 64 * 1024;
const MAX_SIGNATURE_BYTES: usize = 16 * 1024;
const MAX_FRAME_BODY_BYTES: usize = 96 * 1024;
pub(crate) const PLAINTEXT_CHUNK_BYTES: usize = 64 * 1024;
pub(crate) const MAX_DIAGNOSTIC_BYTES: usize = 1024;
pub(crate) const DEFAULT_MAX_RECORDS: u64 = 4_000_000;
pub(crate) const DEFAULT_MAX_PLAINTEXT_BYTES: u64 = 512 * 1024 * 1024;
const STREAM_RECORD_HEADER_BYTES: usize = 4;
const HPKE_TAG_BYTES: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum HpkeSuiteV1 {
    X25519HkdfSha256HkdfSha256ChaCha20Poly1305,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum ReceiptDeliveryV2 {
    AttachedEncrypted {
        suite: HpkeSuiteV1,
        recipient_public_key: [u8; 32],
    },
    DetachedSignedPlaintext,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ReceiptPolicyV2 {
    pub required: bool,
    pub hashed: bool,
    pub max_records: u64,
    pub max_plaintext_bytes: u64,
    pub delivery: ReceiptDeliveryV2,
}

impl ReceiptPolicyV2 {
    pub(crate) fn validate(&self) -> Result<()> {
        if !self.required {
            bail!("receipt v2 policy must require a receipt");
        }
        if self.max_records == 0 || self.max_records > DEFAULT_MAX_RECORDS {
            bail!("receipt record limit is outside the supported range");
        }
        if self.max_plaintext_bytes == 0 || self.max_plaintext_bytes > DEFAULT_MAX_PLAINTEXT_BYTES {
            bail!("receipt byte limit is outside the supported range");
        }
        match &self.delivery {
            ReceiptDeliveryV2::AttachedEncrypted {
                recipient_public_key,
                ..
            } if recipient_public_key.iter().all(|byte| *byte == 0) => {
                bail!("receipt recipient public key must be nonzero")
            }
            ReceiptDeliveryV2::AttachedEncrypted { .. }
            | ReceiptDeliveryV2::DetachedSignedPlaintext => Ok(()),
        }
    }
}

pub(crate) struct RecipientSecret([u8; 32]);

impl std::fmt::Debug for RecipientSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RecipientSecret([REDACTED])")
    }
}

impl Drop for RecipientSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub(crate) fn generate_recipient() -> Result<(RecipientSecret, [u8; 32])> {
    let (private, public) = Kem::gen_keypair();
    let private: [u8; 32] = private
        .to_bytes()
        .as_slice()
        .try_into()
        .context("HPKE generated an unexpected private-key length")?;
    let public: [u8; 32] = public
        .to_bytes()
        .as_slice()
        .try_into()
        .context("HPKE generated an unexpected public-key length")?;
    Ok((RecipientSecret(private), public))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum OperationActionV2 {
    PublishFile { size: u64, inplace: bool },
    EnsureDirectory,
    CreateSymlink,
    CreateSpecial { kind: Kind },
    SetMetadata { flags: u8 },
    DeleteFile,
    DeleteDirectory,
    ObserveFileHash,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum OperationDispositionV2 {
    Applied,
    Failed,
    Incomplete,
    Observed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum OutcomeCodeV2 {
    None,
    ExecutionFailed,
    AuthorizationRefused,
    FileLifecycleIncomplete,
    ObservationFailed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct OperationRecordV2 {
    pub sequence: u64,
    pub scope: u32,
    pub path: Vec<u8>,
    pub action: OperationActionV2,
    pub disposition: OperationDispositionV2,
    pub code: OutcomeCodeV2,
    pub diagnostic: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RefusalRecordV2 {
    pub sequence: u64,
    pub code: OutcomeCodeV2,
    pub diagnostic: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ObjectMetadataV2 {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: i64,
    pub mtime_nsec: u32,
    pub rdev: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum FinalObjectV2 {
    Absent,
    Present {
        kind: Kind,
        size: u64,
        digest: Option<[u8; 32]>,
        symlink_target: Option<Vec<u8>>,
        metadata: ObjectMetadataV2,
        observation_error: Option<String>,
    },
    ObservationFailed {
        code: OutcomeCodeV2,
        diagnostic: Option<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct FinalStateRecordV2 {
    pub sequence: u64,
    pub scope: u32,
    pub path: Vec<u8>,
    pub object: FinalObjectV2,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum RecordV2 {
    Operation(OperationRecordV2),
    Refusal(RefusalRecordV2),
    FinalState(FinalStateRecordV2),
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ReceiptSummaryV2 {
    pub operations: u64,
    pub applied: u64,
    pub failed: u64,
    pub incomplete: u64,
    pub refusals: u64,
    pub final_states: u64,
    pub observation_failures: u64,
    pub published_files: u64,
    pub published_bytes: u64,
    pub deletions: u64,
    pub observed_hashes: u64,
    pub entries_touched: u64,
    pub transferred_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum ReceiptStatusV2 {
    Clean,
    Failed,
    Incomplete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum RecordingFailureV2 {
    LimitExceeded,
    StorageFailed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum ManifestStatusV2 {
    NotProvided,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum ReceiptSchemaV2 {
    LogicalMutationsAndFinalStateV2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum DigestAlgorithmV2 {
    Blake3,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TerminalReceiptV2 {
    pub schema: ReceiptSchemaV2,
    pub enrollment_id: EnrollmentId,
    pub request_id: RequestId,
    pub grant_digest: [u8; 32],
    pub issued_at: i64,
    pub status: ReceiptStatusV2,
    pub authority_closed: bool,
    pub in_flight: u64,
    pub stream_digest: [u8; 32],
    pub stream_digest_algorithm: DigestAlgorithmV2,
    pub content_digest_algorithm: Option<DigestAlgorithmV2>,
    pub record_count: u64,
    pub plaintext_bytes: u64,
    pub summary: ReceiptSummaryV2,
    pub policy: ReceiptPolicyV2,
    pub recording_failure: Option<RecordingFailureV2>,
    pub expected_manifest_digest: Option<[u8; 32]>,
    pub manifest_status: ManifestStatusV2,
}

/// Append-only canonical receipt stream. The anonymous temporary file keeps
/// receipt size off the heap; its signed policy bounds both records and bytes.
pub(crate) struct StreamWriterV2 {
    file: File,
    hasher: blake3::Hasher,
    record_buffer: Vec<u8>,
    record_count: u64,
    plaintext_bytes: u64,
    summary: ReceiptSummaryV2,
    max_records: u64,
    max_plaintext_bytes: u64,
    recording_failure: Option<RecordingFailureV2>,
}

pub(crate) struct ReceiptClosureV2<'a> {
    pub enrollment_id: EnrollmentId,
    pub request_id: RequestId,
    pub grant_digest: [u8; 32],
    pub issued_at: i64,
    pub policy: ReceiptPolicyV2,
    pub entries_touched: u64,
    pub transferred_bytes: u64,
    pub signing_key: &'a PrivateKey,
}

impl std::fmt::Debug for StreamWriterV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StreamWriterV2")
            .field("record_count", &self.record_count)
            .field("plaintext_bytes", &self.plaintext_bytes)
            .field("summary", &self.summary)
            .field("recording_failure", &self.recording_failure)
            .finish()
    }
}

impl StreamWriterV2 {
    pub(crate) fn new(policy: &ReceiptPolicyV2) -> Result<Self> {
        policy.validate()?;
        Ok(Self {
            file: tempfile::tempfile().context("create receiver receipt spool")?,
            hasher: blake3::Hasher::new(),
            record_buffer: Vec::new(),
            record_count: 0,
            plaintext_bytes: 0,
            summary: ReceiptSummaryV2::default(),
            max_records: policy.max_records,
            max_plaintext_bytes: policy.max_plaintext_bytes,
            recording_failure: None,
        })
    }

    pub(crate) fn is_failed(&self) -> bool {
        self.recording_failure.is_some()
    }

    pub(crate) fn next_sequence(&self) -> u64 {
        self.record_count
    }

    pub(crate) fn mark_recording_failure(&mut self) {
        self.recording_failure
            .get_or_insert(RecordingFailureV2::StorageFailed);
    }

    pub(crate) fn append(&mut self, record: &RecordV2) {
        if self.recording_failure.is_some() {
            return;
        }
        if record_sequence(record) != self.record_count {
            self.recording_failure = Some(RecordingFailureV2::StorageFailed);
            return;
        }
        let mut body = std::mem::take(&mut self.record_buffer);
        body.clear();
        let body = match postcard::to_extend(record, body) {
            Ok(body) => body,
            Err(_) => {
                self.recording_failure = Some(RecordingFailureV2::StorageFailed);
                return;
            }
        };
        let framed_len = match STREAM_RECORD_HEADER_BYTES.checked_add(body.len()) {
            Some(length) => length,
            None => {
                self.record_buffer = body;
                self.recording_failure = Some(RecordingFailureV2::LimitExceeded);
                return;
            }
        };
        let new_bytes = match self.plaintext_bytes.checked_add(framed_len as u64) {
            Some(bytes) => bytes,
            None => {
                self.record_buffer = body;
                self.recording_failure = Some(RecordingFailureV2::LimitExceeded);
                return;
            }
        };
        if self.record_count >= self.max_records || new_bytes > self.max_plaintext_bytes {
            self.record_buffer = body;
            self.recording_failure = Some(RecordingFailureV2::LimitExceeded);
            return;
        }
        let length = match u32::try_from(body.len()) {
            Ok(length) => length.to_be_bytes(),
            Err(_) => {
                self.record_buffer = body;
                self.recording_failure = Some(RecordingFailureV2::LimitExceeded);
                return;
            }
        };
        if self
            .file
            .write_all(&length)
            .and_then(|()| self.file.write_all(&body))
            .is_err()
        {
            self.record_buffer = body;
            self.recording_failure = Some(RecordingFailureV2::StorageFailed);
            return;
        }
        self.hasher.update(&length);
        self.hasher.update(&body);
        self.record_count += 1;
        self.plaintext_bytes = new_bytes;
        summarize(record, &mut self.summary);
        self.record_buffer = body;
    }

    pub(crate) fn finish(mut self, closure: ReceiptClosureV2<'_>) -> Result<IssuedReceiptV2> {
        let ReceiptClosureV2 {
            enrollment_id,
            request_id,
            grant_digest,
            issued_at,
            policy,
            entries_touched,
            transferred_bytes,
            signing_key,
        } = closure;
        self.file.flush().context("flush receiver receipt spool")?;
        self.file
            .seek(SeekFrom::Start(0))
            .context("rewind receiver receipt spool")?;
        self.summary.entries_touched = entries_touched;
        self.summary.transferred_bytes = transferred_bytes;
        let status = if self.recording_failure.is_some() || self.summary.observation_failures > 0 {
            ReceiptStatusV2::Incomplete
        } else if self.summary.failed > 0
            || self.summary.incomplete > 0
            || self.summary.refusals > 0
        {
            ReceiptStatusV2::Failed
        } else {
            ReceiptStatusV2::Clean
        };
        let terminal = TerminalReceiptV2 {
            schema: ReceiptSchemaV2::LogicalMutationsAndFinalStateV2,
            enrollment_id,
            request_id,
            grant_digest,
            issued_at,
            status,
            authority_closed: true,
            in_flight: 0,
            stream_digest: *self.hasher.finalize().as_bytes(),
            stream_digest_algorithm: DigestAlgorithmV2::Blake3,
            content_digest_algorithm: policy.hashed.then_some(DigestAlgorithmV2::Blake3),
            record_count: self.record_count,
            plaintext_bytes: self.plaintext_bytes,
            summary: self.summary,
            policy: policy.clone(),
            recording_failure: self.recording_failure,
            expected_manifest_digest: None,
            manifest_status: ManifestStatusV2::NotProvided,
        };
        Ok(IssuedReceiptV2 {
            stream: self.file,
            stream_len: self.plaintext_bytes,
            signed_terminal: sign_terminal(&terminal, signing_key)?,
            enrollment_id,
            request_id,
            grant_digest,
            delivery: policy.delivery,
        })
    }
}

fn record_sequence(record: &RecordV2) -> u64 {
    match record {
        RecordV2::Operation(record) => record.sequence,
        RecordV2::Refusal(record) => record.sequence,
        RecordV2::FinalState(record) => record.sequence,
    }
}

fn summarize(record: &RecordV2, summary: &mut ReceiptSummaryV2) {
    match record {
        RecordV2::Operation(record) => {
            summary.operations += 1;
            match record.disposition {
                OperationDispositionV2::Applied | OperationDispositionV2::Observed => {
                    summary.applied += 1
                }
                OperationDispositionV2::Failed => summary.failed += 1,
                OperationDispositionV2::Incomplete => summary.incomplete += 1,
            }
            match record.action {
                OperationActionV2::PublishFile { size, .. }
                    if record.disposition == OperationDispositionV2::Applied =>
                {
                    summary.published_files += 1;
                    summary.published_bytes = summary.published_bytes.saturating_add(size);
                }
                OperationActionV2::DeleteFile | OperationActionV2::DeleteDirectory
                    if record.disposition == OperationDispositionV2::Applied =>
                {
                    summary.deletions += 1;
                }
                OperationActionV2::ObserveFileHash
                    if record.disposition == OperationDispositionV2::Observed =>
                {
                    summary.observed_hashes += 1;
                }
                _ => {}
            }
        }
        RecordV2::Refusal(_) => summary.refusals += 1,
        RecordV2::FinalState(record) => {
            summary.final_states += 1;
            if matches!(
                record.object,
                FinalObjectV2::ObservationFailed { .. }
                    | FinalObjectV2::Present {
                        observation_error: Some(_),
                        ..
                    }
            ) {
                summary.observation_failures += 1;
            }
        }
    }
}

pub(crate) struct IssuedReceiptV2 {
    stream: File,
    stream_len: u64,
    signed_terminal: Vec<u8>,
    enrollment_id: EnrollmentId,
    request_id: RequestId,
    grant_digest: [u8; 32],
    delivery: ReceiptDeliveryV2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum TransportModeV2 {
    AttachedEncrypted,
    DetachedSignedPlaintext,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum TransportFrameV2 {
    Start {
        mode: TransportModeV2,
        encapsulated_key: Vec<u8>,
    },
    Chunk {
        sequence: u64,
        payload: Vec<u8>,
    },
    End {
        sequence: u64,
        payload: Vec<u8>,
    },
}

#[derive(Serialize)]
enum BorrowedTransportFrameV2<'a> {
    Start {
        mode: TransportModeV2,
        encapsulated_key: &'a [u8],
    },
    Chunk {
        sequence: u64,
        payload: &'a [u8],
    },
    End {
        sequence: u64,
        payload: &'a [u8],
    },
}

#[cfg(test)]
impl TransportFrameV2 {
    fn as_borrowed(&self) -> BorrowedTransportFrameV2<'_> {
        match self {
            Self::Start {
                mode,
                encapsulated_key,
            } => BorrowedTransportFrameV2::Start {
                mode: *mode,
                encapsulated_key,
            },
            Self::Chunk { sequence, payload } => BorrowedTransportFrameV2::Chunk {
                sequence: *sequence,
                payload,
            },
            Self::End { sequence, payload } => BorrowedTransportFrameV2::End {
                sequence: *sequence,
                payload,
            },
        }
    }
}

pub(crate) fn emit_transport_frames(
    mut issued: IssuedReceiptV2,
    mut emit: impl FnMut(Vec<u8>) -> Result<()>,
) -> Result<()> {
    let info = hpke_info(issued.enrollment_id, issued.request_id, issued.grant_digest)?;
    match issued.delivery {
        ReceiptDeliveryV2::AttachedEncrypted {
            suite: HpkeSuiteV1::X25519HkdfSha256HkdfSha256ChaCha20Poly1305,
            recipient_public_key,
        } => {
            let public = <Kem as hpke::Kem>::PublicKey::from_bytes(&recipient_public_key)
                .map_err(|_| anyhow!("invalid HPKE recipient public key in signed grant"))?;
            let (encapsulated, mut sender) =
                setup_sender::<Aead, Kdf, Kem>(&OpModeS::Base, &public, &info)
                    .map_err(|_| anyhow!("set up HPKE receipt sender"))?;
            let encapsulated = encapsulated.to_bytes();
            emit(encode_borrowed_transport_frame(
                &BorrowedTransportFrameV2::Start {
                    mode: TransportModeV2::AttachedEncrypted,
                    encapsulated_key: encapsulated.as_slice(),
                },
            )?)?;
            let mut sequence = 0u64;
            let mut buffer = vec![0u8; PLAINTEXT_CHUNK_BYTES];
            let mut remaining = issued.stream_len;
            while remaining > 0 {
                let wanted = usize::try_from(remaining.min(PLAINTEXT_CHUNK_BYTES as u64))
                    .expect("bounded receipt chunk");
                issued
                    .stream
                    .read_exact(&mut buffer[..wanted])
                    .context("read receiver receipt spool")?;
                let payload = sender
                    .seal(&buffer[..wanted], &frame_aad(sequence, false))
                    .map_err(|_| anyhow!("encrypt receipt stream frame"))?;
                emit(encode_borrowed_transport_frame(
                    &BorrowedTransportFrameV2::Chunk {
                        sequence,
                        payload: &payload,
                    },
                )?)?;
                sequence += 1;
                remaining -= wanted as u64;
            }
            let payload = sender
                .seal(&issued.signed_terminal, &frame_aad(sequence, true))
                .map_err(|_| anyhow!("encrypt receipt terminal frame"))?;
            emit(encode_borrowed_transport_frame(
                &BorrowedTransportFrameV2::End {
                    sequence,
                    payload: &payload,
                },
            )?)?;
        }
        ReceiptDeliveryV2::DetachedSignedPlaintext => {
            emit(encode_borrowed_transport_frame(
                &BorrowedTransportFrameV2::Start {
                    mode: TransportModeV2::DetachedSignedPlaintext,
                    encapsulated_key: &[],
                },
            )?)?;
            let mut sequence = 0u64;
            let mut buffer = vec![0u8; PLAINTEXT_CHUNK_BYTES];
            let mut remaining = issued.stream_len;
            while remaining > 0 {
                let wanted = usize::try_from(remaining.min(PLAINTEXT_CHUNK_BYTES as u64))
                    .expect("bounded receipt chunk");
                issued
                    .stream
                    .read_exact(&mut buffer[..wanted])
                    .context("read receiver receipt spool")?;
                emit(encode_borrowed_transport_frame(
                    &BorrowedTransportFrameV2::Chunk {
                        sequence,
                        payload: &buffer[..wanted],
                    },
                )?)?;
                sequence += 1;
                remaining -= wanted as u64;
            }
            emit(encode_borrowed_transport_frame(
                &BorrowedTransportFrameV2::End {
                    sequence,
                    payload: &issued.signed_terminal,
                },
            )?)?;
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn encode_transport_frame(frame: &TransportFrameV2) -> Result<Vec<u8>> {
    encode_borrowed_transport_frame(&frame.as_borrowed())
}

fn encode_borrowed_transport_frame(frame: &BorrowedTransportFrameV2<'_>) -> Result<Vec<u8>> {
    let payload_len = match frame {
        BorrowedTransportFrameV2::Start {
            encapsulated_key, ..
        } => encapsulated_key.len(),
        BorrowedTransportFrameV2::Chunk { payload, .. }
        | BorrowedTransportFrameV2::End { payload, .. } => payload.len(),
    };
    // Postcard adds only enum tags and variable-length integer fields around
    // the byte payload. Leave modest headroom so normal frames need one
    // allocation without walking the payload once just to measure it.
    let capacity = HEADER_LEN
        .checked_add(payload_len)
        .and_then(|length| length.checked_add(32))
        .context("receipt transport frame length overflow")?;
    let mut encoded = Vec::with_capacity(capacity);
    encoded.resize(HEADER_LEN, 0);
    encoded = postcard::to_extend(frame, encoded).context("encode receipt transport frame")?;
    let body_len = encoded.len() - HEADER_LEN;
    if body_len == 0 || body_len > MAX_FRAME_BODY_BYTES {
        bail!("receipt transport frame exceeds size limit");
    }
    encoded[..8].copy_from_slice(FRAME_MAGIC);
    encoded[8..10].copy_from_slice(&FRAME_VERSION.to_be_bytes());
    encoded[10..HEADER_LEN].copy_from_slice(&(body_len as u32).to_be_bytes());
    Ok(encoded)
}

pub(crate) fn decode_transport_frame(encoded: &[u8]) -> Result<TransportFrameV2> {
    if encoded.len() < HEADER_LEN || &encoded[..8] != FRAME_MAGIC {
        bail!("not a receipt v2 transport frame");
    }
    let version = u16::from_be_bytes(encoded[8..10].try_into().expect("fixed header"));
    if version != FRAME_VERSION {
        bail!("unsupported receipt transport version {version}");
    }
    let body_len = u32::from_be_bytes(encoded[10..14].try_into().expect("fixed header")) as usize;
    if body_len == 0 || body_len > MAX_FRAME_BODY_BYTES || encoded.len() != HEADER_LEN + body_len {
        bail!("receipt transport frame length is noncanonical");
    }
    let body = &encoded[HEADER_LEN..];
    let frame: TransportFrameV2 =
        postcard::from_bytes(body).context("decode receipt transport frame")?;
    if postcard::to_stdvec(&frame)? != body {
        bail!("receipt transport frame uses a noncanonical encoding");
    }
    match &frame {
        TransportFrameV2::Start {
            mode: TransportModeV2::AttachedEncrypted,
            encapsulated_key,
        } if encapsulated_key.len() != 32 => bail!("invalid HPKE encapsulated-key length"),
        TransportFrameV2::Start {
            mode: TransportModeV2::DetachedSignedPlaintext,
            encapsulated_key,
        } if !encapsulated_key.is_empty() => {
            bail!("plaintext receipt start frame carries an encapsulated key")
        }
        TransportFrameV2::Chunk { payload, .. }
            if payload.len() > PLAINTEXT_CHUNK_BYTES + HPKE_TAG_BYTES =>
        {
            bail!("receipt chunk payload exceeds size limit")
        }
        TransportFrameV2::End { payload, .. }
            if payload.len()
                > MAX_TERMINAL_BYTES
                    + MAX_SIGNATURE_BYTES
                    + TERMINAL_HEADER_LEN
                    + HPKE_TAG_BYTES =>
        {
            bail!("receipt terminal payload exceeds size limit")
        }
        _ => {}
    }
    Ok(frame)
}

pub(crate) fn transport_frame_is_end(encoded: &[u8]) -> Result<bool> {
    Ok(matches!(
        decode_transport_frame(encoded)?,
        TransportFrameV2::End { .. }
    ))
}

pub(crate) struct VerifiedReceiptV2 {
    pub terminal: TerminalReceiptV2,
    stream: File,
}

impl VerifiedReceiptV2 {
    pub(crate) fn for_each_record(
        &mut self,
        mut visit: impl FnMut(RecordV2) -> Result<()>,
    ) -> Result<()> {
        self.stream.seek(SeekFrom::Start(0))?;
        for _ in 0..self.terminal.record_count {
            let record = read_record(&mut self.stream)?;
            visit(record)?;
        }
        Ok(())
    }
}

/// Publish the already-verified receiver account as the version-0 automation
/// stream. These records deliberately identify their provenance: unlike the
/// coordinator's ordinary `--results`, every fact here came from the signed
/// receipt. Scope-relative paths are not expanded into ambient hostB paths.
/// Emit the receiver-attested automation records into the run's results
/// stream: one v1-vocabulary `operation_result` per receipt operation, an
/// `error` record per refusal, a `final_state` record per closure-time
/// observation, and the sealed terminal `result`. Every attested record
/// carries `provenance: "receiver_attested"`.
/// What the emission produced, for the human summary that renders from the
/// same data.
pub(crate) struct EmittedAutomationRecords {
    pub errors: u64,
}

pub(crate) fn emit_automation_records(
    receipt: &mut VerifiedReceiptV2,
    writer: &crate::results::ResultsWriter,
    results_status: &'static str,
    exit_code: i32,
    elapsed_ms: u64,
) -> Result<EmittedAutomationRecords> {
    let mut directories_created = 0u64;
    let mut symlinks_created = 0u64;
    let mut specials_created = 0u64;
    let mut errors_emitted = 0u64;
    receipt.for_each_record(|record| {
        let value = match record {
            RecordV2::Operation(record) => {
                let (action, kind, bytes) = match record.action {
                    OperationActionV2::PublishFile { size, .. } => {
                        ("transfer_file", Some("file"), Some(size))
                    }
                    OperationActionV2::EnsureDirectory => {
                        if record.disposition == OperationDispositionV2::Applied {
                            directories_created += 1;
                        }
                        ("create_directory", Some("dir"), None)
                    }
                    OperationActionV2::CreateSymlink => {
                        if record.disposition == OperationDispositionV2::Applied {
                            symlinks_created += 1;
                        }
                        ("create_symlink", Some("symlink"), None)
                    }
                    OperationActionV2::CreateSpecial { .. } => {
                        if record.disposition == OperationDispositionV2::Applied {
                            specials_created += 1;
                        }
                        ("create_special", Some("special"), None)
                    }
                    OperationActionV2::SetMetadata { .. } => ("set_metadata", None, None),
                    OperationActionV2::DeleteFile => ("delete", Some("file"), None),
                    OperationActionV2::DeleteDirectory => ("delete", Some("dir"), None),
                    OperationActionV2::ObserveFileHash => ("observe_hash", Some("file"), None),
                };
                let mut value = serde_json::json!({
                    "type": "operation_result",
                    "provenance": "receiver_attested",
                    "action": action,
                    "scope": record.scope,
                    "dst": tagged_path(&record.path),
                    "disposition": disposition_name(record.disposition),
                });
                let object = value
                    .as_object_mut()
                    .expect("operation record is an object");
                if let Some(kind) = kind {
                    object.insert("kind".into(), kind.into());
                }
                if record.code != OutcomeCodeV2::None {
                    object.insert("code".into(), outcome_name(record.code).into());
                }
                if let Some(bytes) = bytes {
                    object.insert("bytes".into(), bytes.into());
                }
                if let Some(message) = &record.diagnostic {
                    object.insert("message".into(), message.as_str().into());
                }
                if matches!(
                    record.disposition,
                    OperationDispositionV2::Failed | OperationDispositionV2::Incomplete
                ) {
                    writer.emit_value(value);
                    errors_emitted += 1;
                    serde_json::json!({
                        "type": "error",
                        "provenance": "receiver_attested",
                        "class": error_class_for(record.code),
                        "code": outcome_name(record.code),
                        "message": record.diagnostic.unwrap_or_else(|| {
                            format!(
                                "receiver operation on {} did not complete",
                                String::from_utf8_lossy(&record.path)
                            )
                        }),
                    })
                } else {
                    value
                }
            }
            RecordV2::Refusal(record) => {
                errors_emitted += 1;
                serde_json::json!({
                    "type": "error",
                    "provenance": "receiver_attested",
                    // The receiver's guard deliberately refused the request.
                    "class": "safety_limit",
                    "code": outcome_name(record.code),
                    "message": record
                        .diagnostic
                        .unwrap_or_else(|| "receiver refused the request".to_string()),
                })
            }
            RecordV2::FinalState(record) => {
                let object = match record.object {
                    FinalObjectV2::Absent => serde_json::json!({"state": "absent"}),
                    FinalObjectV2::ObservationFailed { code, diagnostic } => {
                        writer.emit_value(serde_json::json!({
                            "type": "error",
                            "provenance": "receiver_attested",
                            "class": "io",
                            "code": outcome_name(code),
                            "message": diagnostic.clone().unwrap_or_else(|| {
                                format!(
                                    "final state of {} could not be observed",
                                    String::from_utf8_lossy(&record.path)
                                )
                            }),
                        }));
                        errors_emitted += 1;
                        let mut object = serde_json::json!({
                            "state": "observation_failed",
                            "code": outcome_name(code),
                        });
                        if let Some(message) = diagnostic {
                            object
                                .as_object_mut()
                                .expect("final object is an object")
                                .insert("message".into(), message.into());
                        }
                        object
                    }
                    FinalObjectV2::Present {
                        kind,
                        size,
                        digest,
                        symlink_target,
                        metadata,
                        observation_error,
                    } => {
                        let mut object = serde_json::json!({
                            "state": "present",
                            "kind": kind_name(kind),
                            "size": size,
                            "metadata": {
                                "mode": metadata.mode,
                                "uid": metadata.uid,
                                "gid": metadata.gid,
                                "mtime": metadata.mtime,
                                "mtime_nsec": metadata.mtime_nsec,
                                "rdev": metadata.rdev,
                            },
                        });
                        let fields = object.as_object_mut().expect("final object is an object");
                        if let Some(digest) = digest {
                            fields.insert(
                                "digest".into(),
                                serde_json::json!({
                                    "algorithm": "blake3",
                                    "value": encode_hex(&digest),
                                }),
                            );
                        }
                        if let Some(target) = symlink_target {
                            fields.insert("symlink_target".into(), tagged_path(&target));
                        }
                        if let Some(error) = &observation_error {
                            // The object landed but part of its final state
                            // (hash or link target) could not be attested;
                            // that failure counts like any other.
                            writer.emit_value(serde_json::json!({
                                "type": "error",
                                "provenance": "receiver_attested",
                                "class": "io",
                                "message": format!(
                                    "final state of {} was only partly observed: {error}",
                                    String::from_utf8_lossy(&record.path)
                                ),
                            }));
                            errors_emitted += 1;
                        }
                        if let Some(error) = observation_error {
                            fields.insert("observation_error".into(), error.into());
                        }
                        object
                    }
                };
                serde_json::json!({
                    "type": "final_state",
                    "provenance": "receiver_attested",
                    "scope": record.scope,
                    "dst": tagged_path(&record.path),
                    "object": object,
                })
            }
        };
        writer.emit_value(value);
        Ok(())
    })?;

    let terminal = &receipt.terminal;
    // errors matches the error records actually emitted above — one per
    // counted error, by construction.
    let errors = errors_emitted;
    // Aggregates describe receiver-visible work only: unchanged and
    // excluded entries are orchestrator concepts a receipt cannot attest.
    writer.emit_terminal_value(serde_json::json!({
        "type": "result",
        "provenance": "receiver_attested",
        "status": results_status,
        "receipt_status": receipt_status_name(terminal.status),
        "exit_code": exit_code,
        "dry_run": false,
        "files_transferred": terminal.summary.published_files,
        "files_unchanged": 0,
        "files_excluded": 0,
        "directories_created": directories_created,
        "symlinks_created": symlinks_created,
        "specials_created": specials_created,
        "errors": errors,
        "bytes_transferred": terminal.summary.transferred_bytes,
        "bytes_unchanged": 0,
        "elapsed_ms": elapsed_ms,
        // The one deletion fact a receipt can attest: settled deletions.
        // Planning and --max-delete blocking are coordinator concepts, so
        // deletions_planned and deletions_blocked never appear here.
        "deletions_completed": terminal.summary.deletions,
        "operations": terminal.summary.operations,
        "final_states": terminal.summary.final_states,
        "receipt_records": terminal.record_count,
    }));
    Ok(EmittedAutomationRecords {
        errors: errors_emitted,
    })
}

fn tagged_path(path: &[u8]) -> serde_json::Value {
    use base64::Engine as _;
    match std::str::from_utf8(path) {
        Ok(value) => serde_json::json!({"encoding": "utf-8", "value": value}),
        Err(_) => serde_json::json!({
            "encoding": "base64",
            "value": base64::engine::general_purpose::STANDARD.encode(path),
        }),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}").expect("write to String");
    }
    encoded
}

fn disposition_name(disposition: OperationDispositionV2) -> &'static str {
    match disposition {
        OperationDispositionV2::Applied => "succeeded",
        OperationDispositionV2::Failed => "failed",
        OperationDispositionV2::Incomplete => "incomplete",
        OperationDispositionV2::Observed => "observed",
    }
}

fn outcome_name(code: OutcomeCodeV2) -> &'static str {
    match code {
        OutcomeCodeV2::None => "none",
        OutcomeCodeV2::ExecutionFailed => "execution_failed",
        OutcomeCodeV2::AuthorizationRefused => "authorization_refused",
        OutcomeCodeV2::FileLifecycleIncomplete => "file_lifecycle_incomplete",
        OutcomeCodeV2::ObservationFailed => "observation_failed",
    }
}

pub(crate) fn receipt_status_label(status: ReceiptStatusV2) -> &'static str {
    receipt_status_name(status)
}

fn error_class_for(code: OutcomeCodeV2) -> &'static str {
    match code {
        OutcomeCodeV2::AuthorizationRefused => "safety_limit",
        OutcomeCodeV2::FileLifecycleIncomplete => "integrity",
        OutcomeCodeV2::ExecutionFailed | OutcomeCodeV2::ObservationFailed | OutcomeCodeV2::None => {
            "io"
        }
    }
}

fn receipt_status_name(status: ReceiptStatusV2) -> &'static str {
    match status {
        ReceiptStatusV2::Clean => "clean",
        ReceiptStatusV2::Failed => "failed",
        ReceiptStatusV2::Incomplete => "incomplete",
    }
}

fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Dir => "dir",
        Kind::File => "file",
        Kind::Symlink => "symlink",
        Kind::Fifo => "fifo",
        Kind::Socket => "socket",
        Kind::CharDev => "character_device",
        Kind::BlockDev => "block_device",
        Kind::Other => "other",
    }
}

/// Decrypt and verify an attached receipt whose encoded transport frames have
/// been captured in order. Decrypted bytes remain in an anonymous temporary
/// file until the terminal signature and stream commitment have verified.
pub(crate) fn open_attached_frames<I>(
    frames: I,
    recipient_secret: &RecipientSecret,
    receipt_public_key: &str,
    expected_enrollment_id: EnrollmentId,
    expected_request_id: RequestId,
    expected_grant_digest: [u8; 32],
    expected_policy: &ReceiptPolicyV2,
) -> Result<VerifiedReceiptV2>
where
    I: IntoIterator<Item = Result<Vec<u8>>>,
{
    let mut frames = frames.into_iter();
    let first = frames
        .next()
        .context("receipt stream has no start frame")??;
    let encapsulated_key = match decode_transport_frame(&first)? {
        TransportFrameV2::Start {
            mode: TransportModeV2::AttachedEncrypted,
            encapsulated_key,
        } => encapsulated_key,
        TransportFrameV2::Start {
            mode: TransportModeV2::DetachedSignedPlaintext,
            ..
        } => bail!("attached transfer received a detached plaintext receipt"),
        _ => bail!("receipt stream does not begin with a start frame"),
    };
    let private = <Kem as hpke::Kem>::PrivateKey::from_bytes(&recipient_secret.0)
        .map_err(|_| anyhow!("invalid local HPKE receipt private key"))?;
    let encapsulated = <Kem as hpke::Kem>::EncappedKey::from_bytes(&encapsulated_key)
        .map_err(|_| anyhow!("invalid HPKE receipt encapsulated key"))?;
    let info = hpke_info(
        expected_enrollment_id,
        expected_request_id,
        expected_grant_digest,
    )?;
    let mut receiver =
        setup_receiver::<Aead, Kdf, Kem>(&OpModeR::Base, &private, &encapsulated, &info)
            .map_err(|_| anyhow!("set up HPKE receipt receiver"))?;
    let mut stream = tempfile::tempfile().context("create local decrypted receipt spool")?;
    let mut sequence = 0u64;
    let signed_terminal = loop {
        let encoded = frames
            .next()
            .context("receipt stream has no terminal frame")??;
        match decode_transport_frame(&encoded)? {
            TransportFrameV2::Chunk {
                sequence: observed,
                payload,
            } => {
                if observed != sequence {
                    bail!("receipt frame sequence is not contiguous");
                }
                let plaintext = receiver
                    .open(&payload, &frame_aad(sequence, false))
                    .map_err(|_| anyhow!("receipt stream frame failed authentication"))?;
                stream
                    .write_all(&plaintext)
                    .context("write local decrypted receipt spool")?;
                sequence += 1;
            }
            TransportFrameV2::End {
                sequence: observed,
                payload,
            } => {
                if observed != sequence {
                    bail!("receipt terminal sequence is not contiguous");
                }
                let terminal = receiver
                    .open(&payload, &frame_aad(sequence, true))
                    .map_err(|_| anyhow!("receipt terminal frame failed authentication"))?;
                break terminal;
            }
            TransportFrameV2::Start { .. } => bail!("receipt stream contains a second start frame"),
        }
    };
    if frames.next().is_some() {
        bail!("receipt stream contains data after its terminal frame");
    }
    stream
        .flush()
        .context("flush local decrypted receipt spool")?;
    let terminal = verify_terminal(&signed_terminal, receipt_public_key)?;
    if terminal.enrollment_id != expected_enrollment_id
        || terminal.request_id != expected_request_id
        || terminal.grant_digest != expected_grant_digest
    {
        bail!("receipt names a different signed grant");
    }
    if &terminal.policy != expected_policy {
        bail!("receipt policy does not match the signed grant");
    }
    verify_stream(&mut stream, &terminal)?;
    Ok(VerifiedReceiptV2 { terminal, stream })
}

fn verify_stream(stream: &mut File, terminal: &TerminalReceiptV2) -> Result<()> {
    if terminal.schema != ReceiptSchemaV2::LogicalMutationsAndFinalStateV2
        || terminal.stream_digest_algorithm != DigestAlgorithmV2::Blake3
        || terminal.content_digest_algorithm
            != terminal.policy.hashed.then_some(DigestAlgorithmV2::Blake3)
    {
        bail!("receipt schema or digest algorithms are inconsistent with its policy");
    }
    if terminal.record_count > terminal.policy.max_records
        || terminal.plaintext_bytes > terminal.policy.max_plaintext_bytes
    {
        bail!("receipt stream exceeds its signed policy limit");
    }
    if terminal.expected_manifest_digest.is_some()
        || terminal.manifest_status != ManifestStatusV2::NotProvided
    {
        bail!("receipt uses an expected-manifest result not supported by this version");
    }
    let length = stream
        .metadata()
        .context("inspect decrypted receipt spool")?
        .len();
    if length != terminal.plaintext_bytes {
        bail!("receipt plaintext byte count does not match its stream");
    }
    stream.seek(SeekFrom::Start(0))?;
    let mut hasher = blake3::Hasher::new();
    let mut summary = ReceiptSummaryV2::default();
    let mut final_locations = BTreeSet::new();
    for expected_sequence in 0..terminal.record_count {
        let mut length = [0u8; STREAM_RECORD_HEADER_BYTES];
        stream
            .read_exact(&mut length)
            .context("receipt stream ended before its signed record count")?;
        let body_len = u32::from_be_bytes(length) as usize;
        if body_len == 0 || body_len > MAX_FRAME_BODY_BYTES {
            bail!("receipt record length is outside the supported range");
        }
        let mut body = vec![0u8; body_len];
        stream
            .read_exact(&mut body)
            .context("receipt record is truncated")?;
        let record: RecordV2 = postcard::from_bytes(&body).context("decode receipt record")?;
        if postcard::to_stdvec(&record)? != body {
            bail!("receipt record uses a noncanonical encoding");
        }
        if record_sequence(&record) != expected_sequence {
            bail!("receipt record sequence is not contiguous");
        }
        validate_record(&record, &terminal.policy)?;
        if let RecordV2::FinalState(record) = &record {
            if !final_locations.insert((record.scope, record.path.clone())) {
                bail!("receipt repeats a final-state location");
            }
        }
        hasher.update(&length);
        hasher.update(&body);
        summarize(&record, &mut summary);
    }
    let mut trailing = [0u8; 1];
    if stream.read(&mut trailing)? != 0 {
        bail!("receipt stream has data after its signed record count");
    }
    summary.entries_touched = terminal.summary.entries_touched;
    summary.transferred_bytes = terminal.summary.transferred_bytes;
    if terminal.recording_failure.is_none()
        && final_locations.len() as u64 != terminal.summary.entries_touched
    {
        bail!("receipt final-state coverage does not match its touched-path count");
    }
    if *hasher.finalize().as_bytes() != terminal.stream_digest {
        bail!("receipt stream does not match its signed digest");
    }
    if summary != terminal.summary {
        bail!("receipt summary does not match its record stream");
    }
    if !terminal.authority_closed || terminal.in_flight != 0 {
        bail!("receipt was issued before receiver authority closed");
    }
    let expected_status =
        if terminal.recording_failure.is_some() || summary.observation_failures > 0 {
            ReceiptStatusV2::Incomplete
        } else if summary.failed > 0 || summary.incomplete > 0 || summary.refusals > 0 {
            ReceiptStatusV2::Failed
        } else {
            ReceiptStatusV2::Clean
        };
    if terminal.status != expected_status {
        bail!("receipt status is inconsistent with its records");
    }
    stream.seek(SeekFrom::Start(0))?;
    Ok(())
}

fn validate_record(record: &RecordV2, policy: &ReceiptPolicyV2) -> Result<()> {
    let valid_relative_path = |path: &[u8]| {
        !path.starts_with(b"/")
            && !path.contains(&0)
            && (path.is_empty()
                || path
                    .split(|byte| *byte == b'/')
                    .all(|part| !part.is_empty() && part != b"." && part != b".."))
    };
    let valid_diagnostic = |diagnostic: &Option<String>| {
        diagnostic
            .as_ref()
            .is_none_or(|message| message.len() <= MAX_DIAGNOSTIC_BYTES + '…'.len_utf8())
    };
    match record {
        RecordV2::Operation(record) => {
            if !valid_relative_path(&record.path) || !valid_diagnostic(&record.diagnostic) {
                bail!("receipt operation has an invalid path or diagnostic");
            }
            let expected_code = match record.disposition {
                OperationDispositionV2::Applied | OperationDispositionV2::Observed => {
                    OutcomeCodeV2::None
                }
                OperationDispositionV2::Failed => OutcomeCodeV2::ExecutionFailed,
                OperationDispositionV2::Incomplete => OutcomeCodeV2::FileLifecycleIncomplete,
            };
            if record.code != expected_code
                || (record.disposition == OperationDispositionV2::Observed
                    && record.action != OperationActionV2::ObserveFileHash)
                || (record.action == OperationActionV2::ObserveFileHash
                    && matches!(record.disposition, OperationDispositionV2::Applied))
                || (matches!(
                    record.disposition,
                    OperationDispositionV2::Applied | OperationDispositionV2::Observed
                ) && record.diagnostic.is_some())
            {
                bail!("receipt operation code, disposition, and diagnostic are inconsistent");
            }
        }
        RecordV2::Refusal(record) => {
            if record.code != OutcomeCodeV2::AuthorizationRefused
                || !valid_diagnostic(&record.diagnostic)
            {
                bail!("receipt refusal is inconsistent");
            }
        }
        RecordV2::FinalState(record) => {
            if !valid_relative_path(&record.path) {
                bail!("receipt final state has an invalid relative path");
            }
            match &record.object {
                FinalObjectV2::Absent => {}
                FinalObjectV2::ObservationFailed { code, diagnostic } => {
                    if *code != OutcomeCodeV2::ObservationFailed || !valid_diagnostic(diagnostic) {
                        bail!("receipt final-state failure is inconsistent");
                    }
                }
                FinalObjectV2::Present {
                    kind,
                    digest,
                    symlink_target,
                    observation_error,
                    ..
                } => {
                    if !valid_diagnostic(observation_error)
                        || (*kind != Kind::File && digest.is_some())
                        || (*kind == Kind::File
                            && policy.hashed
                            && observation_error.is_none()
                            && digest.is_none())
                        || (!policy.hashed && digest.is_some())
                        || (*kind != Kind::Symlink && symlink_target.is_some())
                        || (*kind == Kind::Symlink
                            && observation_error.is_none()
                            && symlink_target.is_none())
                    {
                        bail!("receipt final object is inconsistent with its kind or policy");
                    }
                }
            }
        }
    }
    Ok(())
}

fn read_record(stream: &mut File) -> Result<RecordV2> {
    let mut length = [0u8; STREAM_RECORD_HEADER_BYTES];
    stream.read_exact(&mut length)?;
    let body_len = u32::from_be_bytes(length) as usize;
    if body_len == 0 || body_len > MAX_FRAME_BODY_BYTES {
        bail!("receipt record length is outside the supported range");
    }
    let mut body = vec![0u8; body_len];
    stream.read_exact(&mut body)?;
    let record: RecordV2 = postcard::from_bytes(&body)?;
    if postcard::to_stdvec(&record)? != body {
        bail!("receipt record uses a noncanonical encoding");
    }
    Ok(record)
}

fn sign_terminal(receipt: &TerminalReceiptV2, private_key: &PrivateKey) -> Result<Vec<u8>> {
    if private_key.is_encrypted() {
        bail!("cannot sign a receipt with an encrypted key");
    }
    let measured_body_len =
        postcard::experimental::serialized_size(receipt).context("measure receipt terminal")?;
    if measured_body_len > MAX_TERMINAL_BYTES {
        bail!("receipt terminal exceeds size limit");
    }
    let signed_header_len = TERMINAL_HEADER_LEN - std::mem::size_of::<u32>();
    let mut encoded =
        Vec::with_capacity(TERMINAL_HEADER_LEN + measured_body_len + MAX_SIGNATURE_BYTES);
    encoded.extend_from_slice(TERMINAL_MAGIC);
    encoded.extend_from_slice(&TERMINAL_VERSION.to_be_bytes());
    encoded.extend_from_slice(&[0; std::mem::size_of::<u32>()]);
    encoded = postcard::to_extend(receipt, encoded).context("encode receipt terminal")?;
    let body_len = encoded.len() - signed_header_len;
    debug_assert_eq!(body_len, measured_body_len);
    if body_len > MAX_TERMINAL_BYTES {
        bail!("receipt terminal exceeds size limit");
    }
    encoded[10..signed_header_len].copy_from_slice(&(body_len as u32).to_be_bytes());
    let payload_len = encoded.len();
    let signature = private_key
        .sign(RECEIPT_NAMESPACE, HashAlg::Sha256, &encoded)
        .context("sign receipt terminal")?
        .to_pem(LineEnding::LF)
        .context("encode receipt terminal signature")?
        .into_bytes();
    if signature.len() > MAX_SIGNATURE_BYTES {
        bail!("receipt terminal signature exceeds size limit");
    }
    encoded.resize(TERMINAL_HEADER_LEN + body_len + signature.len(), 0);
    encoded.copy_within(signed_header_len..payload_len, TERMINAL_HEADER_LEN);
    encoded[signed_header_len..TERMINAL_HEADER_LEN]
        .copy_from_slice(&(signature.len() as u32).to_be_bytes());
    encoded[TERMINAL_HEADER_LEN + body_len..].copy_from_slice(&signature);
    Ok(encoded)
}

fn verify_terminal(encoded: &[u8], public_key: &str) -> Result<TerminalReceiptV2> {
    if encoded.len() < TERMINAL_HEADER_LEN || &encoded[..8] != TERMINAL_MAGIC {
        bail!("not a receipt v2 terminal envelope");
    }
    let version = u16::from_be_bytes(encoded[8..10].try_into().expect("fixed header"));
    if version != TERMINAL_VERSION {
        bail!("unsupported receipt terminal version {version}");
    }
    let body_len = u32::from_be_bytes(encoded[10..14].try_into().expect("fixed header")) as usize;
    let signature_len =
        u32::from_be_bytes(encoded[14..18].try_into().expect("fixed header")) as usize;
    if body_len == 0 || body_len > MAX_TERMINAL_BYTES {
        bail!("receipt terminal length is outside the supported range");
    }
    if signature_len == 0 || signature_len > MAX_SIGNATURE_BYTES {
        bail!("receipt terminal signature length is outside the supported range");
    }
    let expected = TERMINAL_HEADER_LEN
        .checked_add(body_len)
        .and_then(|length| length.checked_add(signature_len))
        .context("receipt terminal length overflow")?;
    if encoded.len() != expected {
        bail!("receipt terminal envelope length is noncanonical");
    }
    let body = &encoded[TERMINAL_HEADER_LEN..TERMINAL_HEADER_LEN + body_len];
    let signature = std::str::from_utf8(&encoded[TERMINAL_HEADER_LEN + body_len..])
        .context("receipt terminal signature is not text")?;
    let signature = SshSig::from_pem(signature).context("parse receipt terminal signature")?;
    let public_key =
        PublicKey::from_openssh(public_key).context("parse enrollment receipt public key")?;
    public_key
        .verify(
            RECEIPT_NAMESPACE,
            &terminal_signing_payload(body),
            &signature,
        )
        .context("receipt terminal signature does not verify")?;
    let receipt: TerminalReceiptV2 =
        postcard::from_bytes(body).context("decode receipt terminal")?;
    if postcard::to_stdvec(&receipt)? != body {
        bail!("receipt terminal uses a noncanonical encoding");
    }
    receipt.policy.validate()?;
    Ok(receipt)
}

fn terminal_signing_payload(body: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(8 + 2 + 4 + body.len());
    payload.extend_from_slice(TERMINAL_MAGIC);
    payload.extend_from_slice(&TERMINAL_VERSION.to_be_bytes());
    payload.extend_from_slice(&(body.len() as u32).to_be_bytes());
    payload.extend_from_slice(body);
    payload
}

fn hpke_info(
    enrollment_id: EnrollmentId,
    request_id: RequestId,
    grant_digest: [u8; 32],
) -> Result<Vec<u8>> {
    postcard::to_stdvec(&(
        "syq-receipt-v2-hpke@greaber.github",
        enrollment_id,
        request_id,
        grant_digest,
    ))
    .context("encode receipt HPKE context")
}

fn frame_aad(sequence: u64, terminal: bool) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32);
    aad.extend_from_slice(b"syq-receipt-v2-frame\0");
    aad.extend_from_slice(&sequence.to_be_bytes());
    aad.push(u8::from(terminal));
    aad
}

pub(crate) fn bounded_diagnostic(error: &str) -> Option<String> {
    bounded_format(format_args!("{error}"))
}

pub(crate) fn bounded_format(arguments: std::fmt::Arguments<'_>) -> Option<String> {
    struct BoundedWriter {
        text: String,
        truncated: bool,
    }

    impl std::fmt::Write for BoundedWriter {
        fn write_str(&mut self, value: &str) -> std::fmt::Result {
            let remaining = MAX_DIAGNOSTIC_BYTES.saturating_sub(self.text.len());
            if value.len() <= remaining {
                self.text.push_str(value);
            } else {
                let mut end = remaining.min(value.len());
                while !value.is_char_boundary(end) {
                    end -= 1;
                }
                self.text.push_str(&value[..end]);
                self.truncated = true;
            }
            Ok(())
        }
    }

    let mut writer = BoundedWriter {
        text: String::new(),
        truncated: false,
    };
    std::fmt::write(&mut writer, arguments).expect("bounded String formatting cannot fail");
    if writer.text.is_empty() {
        return None;
    }
    if writer.truncated {
        writer.text.push('…');
    }
    Some(writer.text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> PrivateKey {
        let keypair = ssh_key::private::Ed25519Keypair::from_seed(&[seed; 32]);
        PrivateKey::new(keypair.into(), "syq-receipt-v2-test").unwrap()
    }

    fn policy(public: [u8; 32]) -> ReceiptPolicyV2 {
        ReceiptPolicyV2 {
            required: true,
            hashed: true,
            max_records: 32,
            max_plaintext_bytes: 64 * 1024,
            delivery: ReceiptDeliveryV2::AttachedEncrypted {
                suite: HpkeSuiteV1::X25519HkdfSha256HkdfSha256ChaCha20Poly1305,
                recipient_public_key: public,
            },
        }
    }

    #[test]
    fn attested_failures_emit_matching_error_records() {
        let (secret, public) = generate_recipient().unwrap();
        let policy = policy(public);
        let enrollment_id = EnrollmentId::random();
        let request_id = RequestId::fresh(1_900_000_000).unwrap();
        let grant_digest = [7; 32];
        let signing_key = key(3);
        let mut stream = StreamWriterV2::new(&policy).unwrap();
        stream.append(&RecordV2::Operation(OperationRecordV2 {
            sequence: stream.next_sequence(),
            scope: 0,
            path: b"artifact".to_vec(),
            action: OperationActionV2::PublishFile {
                size: 3,
                inplace: false,
            },
            disposition: OperationDispositionV2::Failed,
            code: OutcomeCodeV2::ExecutionFailed,
            diagnostic: Some("short write".to_string()),
        }));
        stream.append(&RecordV2::Refusal(RefusalRecordV2 {
            sequence: stream.next_sequence(),
            code: OutcomeCodeV2::AuthorizationRefused,
            diagnostic: None,
        }));
        stream.append(&RecordV2::FinalState(FinalStateRecordV2 {
            sequence: stream.next_sequence(),
            scope: 0,
            path: b"artifact".to_vec(),
            object: FinalObjectV2::ObservationFailed {
                code: OutcomeCodeV2::ObservationFailed,
                diagnostic: None,
            },
        }));
        // A present object whose closure hash could not be taken: the object
        // is attested, but the partial observation still counts as an error.
        stream.append(&RecordV2::FinalState(FinalStateRecordV2 {
            sequence: stream.next_sequence(),
            scope: 0,
            path: b"partial".to_vec(),
            object: FinalObjectV2::Present {
                kind: Kind::File,
                size: 4,
                digest: None,
                symlink_target: None,
                metadata: ObjectMetadataV2 {
                    mode: 0o100644,
                    uid: 1000,
                    gid: 1000,
                    mtime: 5,
                    mtime_nsec: 6,
                    rdev: 0,
                },
                observation_error: Some("hash final file: boom".to_string()),
            },
        }));
        let issued = stream
            .finish(ReceiptClosureV2 {
                enrollment_id,
                request_id,
                grant_digest,
                issued_at: 1_900_000_001,
                policy: policy.clone(),
                entries_touched: 2,
                transferred_bytes: 0,
                signing_key: &signing_key,
            })
            .unwrap();
        let mut frames = Vec::new();
        emit_transport_frames(issued, |frame| {
            frames.push(frame);
            Ok(())
        })
        .unwrap();
        let mut verified = open_attached_frames(
            frames.into_iter().map(Ok),
            &secret,
            &signing_key.public_key().to_openssh().unwrap(),
            enrollment_id,
            request_id,
            grant_digest,
            &policy,
        )
        .unwrap();
        assert_eq!(verified.terminal.status, ReceiptStatusV2::Incomplete);

        #[derive(Clone, Default)]
        struct Sink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Sink {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let sink = Sink::default();
        let writer = crate::results::ResultsWriter::new(Box::new(sink.clone()));
        let emitted = emit_automation_records(&mut verified, &writer, "aborted", 1, 3).unwrap();
        assert_eq!(emitted.errors, 4);
        let automation = sink.0.lock().unwrap().clone();
        let records: Vec<serde_json::Value> = String::from_utf8(automation)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let schema: serde_json::Value =
            serde_json::from_str(include_str!("../schemas/automation-v1.schema.json")).unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();
        for (index, record) in records.iter().enumerate() {
            assert_eq!(record["seq"], index as u64);
            if let Err(error) = validator.validate(record) {
                panic!("line {}: {error}: {record}", index + 1);
            }
        }
        // Each counted failure produces an error record: the failed
        // operation, the refusal, and the failed observation, in stream
        // order, with the failed operation's record preceding its error.
        let types: Vec<&str> = records
            .iter()
            .map(|record| record["type"].as_str().unwrap())
            .collect();
        assert_eq!(
            types,
            [
                "operation_result",
                "error",
                "error",
                "error",
                "final_state",
                "error",
                "final_state",
                "result"
            ]
        );
        assert_eq!(records[0]["disposition"], "failed");
        assert_eq!(records[1]["class"], "io");
        assert_eq!(records[1]["code"], "execution_failed");
        assert_eq!(records[1]["message"], "short write");
        assert_eq!(records[2]["class"], "safety_limit");
        assert_eq!(records[2]["code"], "authorization_refused");
        assert_eq!(records[3]["class"], "io");
        assert_eq!(records[3]["code"], "observation_failed");
        assert_eq!(records[4]["object"]["state"], "observation_failed");
        assert_eq!(records[5]["class"], "io");
        assert!(records[5]["message"]
            .as_str()
            .unwrap()
            .contains("hash final file: boom"));
        assert_eq!(records[6]["object"]["state"], "present");
        assert_eq!(
            records[6]["object"]["observation_error"],
            "hash final file: boom"
        );
        let result = records.last().unwrap();
        assert_eq!(result["status"], "aborted");
        assert_eq!(result["receipt_status"], "incomplete");
        assert_eq!(result["exit_code"], 1);
        assert_eq!(result["errors"], 4);
    }

    #[test]
    fn borrowed_transport_frames_preserve_wire_encoding() {
        let frames = [
            TransportFrameV2::Start {
                mode: TransportModeV2::AttachedEncrypted,
                encapsulated_key: vec![3; 32],
            },
            TransportFrameV2::Chunk {
                sequence: u64::MAX,
                payload: vec![5; PLAINTEXT_CHUNK_BYTES],
            },
            TransportFrameV2::End {
                sequence: 17,
                payload: vec![7; 257],
            },
        ];
        for frame in frames {
            let owned = postcard::to_stdvec(&frame).unwrap();
            let borrowed = postcard::to_stdvec(&frame.as_borrowed()).unwrap();
            assert_eq!(borrowed, owned);

            let encoded = encode_transport_frame(&frame).unwrap();
            assert_eq!(&encoded[HEADER_LEN..], owned);
            assert_eq!(decode_transport_frame(&encoded).unwrap(), frame);
        }
    }

    #[test]
    fn encrypted_stream_round_trips_and_binds_all_frames() {
        let (secret, public) = generate_recipient().unwrap();
        let policy = policy(public);
        let enrollment_id = EnrollmentId::random();
        let request_id = RequestId::fresh(1_900_000_000).unwrap();
        let grant_digest = [7; 32];
        let signing_key = key(3);
        let mut stream = StreamWriterV2::new(&policy).unwrap();
        stream.append(&RecordV2::Operation(OperationRecordV2 {
            sequence: stream.next_sequence(),
            scope: 0,
            path: b"artifact".to_vec(),
            action: OperationActionV2::PublishFile {
                size: 3,
                inplace: false,
            },
            disposition: OperationDispositionV2::Applied,
            code: OutcomeCodeV2::None,
            diagnostic: None,
        }));
        stream.append(&RecordV2::FinalState(FinalStateRecordV2 {
            sequence: stream.next_sequence(),
            scope: 0,
            path: b"artifact".to_vec(),
            object: FinalObjectV2::Present {
                kind: Kind::File,
                size: 3,
                digest: Some([9; 32]),
                symlink_target: None,
                metadata: ObjectMetadataV2 {
                    mode: 0o100644,
                    uid: 1000,
                    gid: 1000,
                    mtime: 5,
                    mtime_nsec: 6,
                    rdev: 0,
                },
                observation_error: None,
            },
        }));
        let issued = stream
            .finish(ReceiptClosureV2 {
                enrollment_id,
                request_id,
                grant_digest,
                issued_at: 1_900_000_001,
                policy: policy.clone(),
                entries_touched: 1,
                transferred_bytes: 3,
                signing_key: &signing_key,
            })
            .unwrap();
        let mut frames = Vec::new();
        emit_transport_frames(issued, |frame| {
            frames.push(frame);
            Ok(())
        })
        .unwrap();
        let mut verified = open_attached_frames(
            frames.clone().into_iter().map(Ok),
            &secret,
            &signing_key.public_key().to_openssh().unwrap(),
            enrollment_id,
            request_id,
            grant_digest,
            &policy,
        )
        .unwrap();
        assert_eq!(verified.terminal.status, ReceiptStatusV2::Clean);
        let mut records = Vec::new();
        verified
            .for_each_record(|record| {
                records.push(record);
                Ok(())
            })
            .unwrap();
        assert_eq!(records.len(), 2);

        #[derive(Clone, Default)]
        struct Sink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Sink {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let sink = Sink::default();
        let writer = crate::results::ResultsWriter::new(Box::new(sink.clone()));
        emit_automation_records(&mut verified, &writer, "refused", 25, 7).unwrap();
        let automation = sink.0.lock().unwrap().clone();
        let records: Vec<serde_json::Value> = String::from_utf8(automation)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        // The records ride the shared envelope with contiguous sequencing
        // and validate against the committed automation schema.
        let schema: serde_json::Value =
            serde_json::from_str(include_str!("../schemas/automation-v1.schema.json")).unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();
        for (index, record) in records.iter().enumerate() {
            assert_eq!(record["seq"], index as u64);
            assert_eq!(record["schema"], "syq.automation");
            if let Err(error) = validator.validate(record) {
                panic!("line {}: {error}: {record}", index + 1);
            }
        }
        assert_eq!(records[0]["type"], "operation_result");
        assert_eq!(records[0]["provenance"], "receiver_attested");
        assert_eq!(records[1]["type"], "final_state");
        assert_eq!(
            records[1]["object"]["digest"]["value"],
            "0909090909090909090909090909090909090909090909090909090909090909"
        );
        assert_eq!(records[1]["object"]["metadata"]["mode"], 0o100644);
        let result = records.last().unwrap();
        assert_eq!(result["type"], "result");
        assert_eq!(result["status"], "refused");
        assert_eq!(result["receipt_status"], "clean");
        assert_eq!(result["exit_code"], 25);
        assert_eq!(result["elapsed_ms"], 7);
        assert_eq!(result["errors"], 0);
        assert_eq!(result["deletions_completed"], 0);
        assert_eq!(result["operations"], 1);
        assert_eq!(result["final_states"], 1);
        assert!(result.get("deletions_planned").is_none());
        assert!(result.get("deletions_blocked").is_none());

        let mut missing = frames;
        missing.remove(1);
        assert!(open_attached_frames(
            missing.into_iter().map(Ok),
            &secret,
            &signing_key.public_key().to_openssh().unwrap(),
            enrollment_id,
            request_id,
            grant_digest,
            &policy,
        )
        .is_err());

        let issued = {
            let mut stream = StreamWriterV2::new(&policy).unwrap();
            stream.append(&RecordV2::Operation(OperationRecordV2 {
                sequence: 0,
                scope: 0,
                path: b"artifact".to_vec(),
                action: OperationActionV2::EnsureDirectory,
                disposition: OperationDispositionV2::Applied,
                code: OutcomeCodeV2::None,
                diagnostic: None,
            }));
            stream
                .finish(ReceiptClosureV2 {
                    enrollment_id,
                    request_id,
                    grant_digest,
                    issued_at: 1_900_000_001,
                    policy: policy.clone(),
                    entries_touched: 1,
                    transferred_bytes: 0,
                    signing_key: &signing_key,
                })
                .unwrap()
        };
        let mut tampered = Vec::new();
        emit_transport_frames(issued, |frame| {
            tampered.push(frame);
            Ok(())
        })
        .unwrap();
        let mut chunk = decode_transport_frame(&tampered[1]).unwrap();
        let TransportFrameV2::Chunk { payload, .. } = &mut chunk else {
            panic!("expected encrypted stream chunk");
        };
        payload[0] ^= 1;
        tampered[1] = encode_transport_frame(&chunk).unwrap();
        assert!(open_attached_frames(
            tampered.into_iter().map(Ok),
            &secret,
            &signing_key.public_key().to_openssh().unwrap(),
            enrollment_id,
            request_id,
            grant_digest,
            &policy,
        )
        .is_err());
    }

    #[test]
    fn detached_delivery_is_a_signed_plaintext_stream() {
        let policy = ReceiptPolicyV2 {
            required: true,
            hashed: false,
            max_records: 8,
            max_plaintext_bytes: 4096,
            delivery: ReceiptDeliveryV2::DetachedSignedPlaintext,
        };
        let enrollment_id = EnrollmentId::random();
        let request_id = RequestId::fresh(1_900_000_000).unwrap();
        let signing_key = key(8);
        let mut stream = StreamWriterV2::new(&policy).unwrap();
        stream.append(&RecordV2::Operation(OperationRecordV2 {
            sequence: 0,
            scope: 1,
            path: b"plain".to_vec(),
            action: OperationActionV2::EnsureDirectory,
            disposition: OperationDispositionV2::Applied,
            code: OutcomeCodeV2::None,
            diagnostic: None,
        }));
        stream.append(&RecordV2::FinalState(FinalStateRecordV2 {
            sequence: 1,
            scope: 1,
            path: b"plain".to_vec(),
            object: FinalObjectV2::Absent,
        }));
        let issued = stream
            .finish(ReceiptClosureV2 {
                enrollment_id,
                request_id,
                grant_digest: [8; 32],
                issued_at: 1_900_000_001,
                policy,
                entries_touched: 1,
                transferred_bytes: 0,
                signing_key: &signing_key,
            })
            .unwrap();
        let mut frames = Vec::new();
        emit_transport_frames(issued, |frame| {
            frames.push(decode_transport_frame(&frame)?);
            Ok(())
        })
        .unwrap();
        assert!(matches!(
            frames[0],
            TransportFrameV2::Start {
                mode: TransportModeV2::DetachedSignedPlaintext,
                ref encapsulated_key,
            } if encapsulated_key.is_empty()
        ));
        let TransportFrameV2::Chunk { payload, .. } = &frames[1] else {
            panic!("expected plaintext receipt chunk");
        };
        let mut spool = tempfile::tempfile().unwrap();
        spool.write_all(payload).unwrap();
        let TransportFrameV2::End { payload, .. } = &frames[2] else {
            panic!("expected signed terminal frame");
        };
        let terminal =
            verify_terminal(payload, &signing_key.public_key().to_openssh().unwrap()).unwrap();
        verify_stream(&mut spool, &terminal).unwrap();
    }

    #[test]
    fn limits_fail_closed_without_truncating_into_success() {
        let (_, public) = generate_recipient().unwrap();
        let mut policy = policy(public);
        policy.max_records = 1;
        let mut stream = StreamWriterV2::new(&policy).unwrap();
        for path in [b"a".as_slice(), b"b".as_slice()] {
            stream.append(&RecordV2::Operation(OperationRecordV2 {
                sequence: stream.next_sequence(),
                scope: 0,
                path: path.to_vec(),
                action: OperationActionV2::EnsureDirectory,
                disposition: OperationDispositionV2::Applied,
                code: OutcomeCodeV2::None,
                diagnostic: None,
            }));
        }
        assert!(stream.is_failed());
        let signing_key = key(4);
        let terminal = stream
            .finish(ReceiptClosureV2 {
                enrollment_id: EnrollmentId::random(),
                request_id: RequestId::fresh(1_900_000_000).unwrap(),
                grant_digest: [1; 32],
                issued_at: 1_900_000_001,
                policy,
                entries_touched: 2,
                transferred_bytes: 0,
                signing_key: &signing_key,
            })
            .unwrap();
        assert_eq!(terminal.stream_len, 13);
    }

    #[test]
    fn diagnostics_are_bounded_on_utf8_boundaries() {
        let text = "é".repeat(MAX_DIAGNOSTIC_BYTES);
        let bounded = bounded_diagnostic(&text).unwrap();
        assert!(bounded.len() <= MAX_DIAGNOSTIC_BYTES + '…'.len_utf8());
        assert!(bounded.ends_with('…'));
    }
}

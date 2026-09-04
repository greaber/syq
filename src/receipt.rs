//! Receipts: a complete receiver-authored record stream, a small signed
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

pub(crate) const RECEIPT_NAMESPACE: &str = "syq-receipt@greaber.github";
pub(crate) const RECEIPT_LINE_PREFIX: &str = "syq-receipt:";
const TERMINAL_MAGIC: &[u8; 8] = b"SYQRCPT\0";
const FRAME_MAGIC: &[u8; 8] = b"SYQRFRM\0";
const HEADER_LEN: usize = 8 + 4;
const TERMINAL_HEADER_LEN: usize = 8 + 4 + 4;
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
pub(crate) enum HpkeSuite {
    X25519HkdfSha256HkdfSha256ChaCha20Poly1305,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum ReceiptDelivery {
    AttachedEncrypted {
        suite: HpkeSuite,
        recipient_public_key: [u8; 32],
    },
    DetachedSignedPlaintext,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ReceiptPolicy {
    pub required: bool,
    pub hashed: bool,
    pub max_records: u64,
    pub max_plaintext_bytes: u64,
    pub delivery: ReceiptDelivery,
}

impl ReceiptPolicy {
    pub(crate) fn validate(&self) -> Result<()> {
        if !self.required {
            bail!("receipt policy must require a receipt");
        }
        if self.max_records == 0 || self.max_records > DEFAULT_MAX_RECORDS {
            bail!("receipt record limit is outside the supported range");
        }
        if self.max_plaintext_bytes == 0 || self.max_plaintext_bytes > DEFAULT_MAX_PLAINTEXT_BYTES {
            bail!("receipt byte limit is outside the supported range");
        }
        match &self.delivery {
            ReceiptDelivery::AttachedEncrypted {
                recipient_public_key,
                ..
            } if recipient_public_key.iter().all(|byte| *byte == 0) => {
                bail!("receipt recipient public key must be nonzero")
            }
            ReceiptDelivery::AttachedEncrypted { .. }
            | ReceiptDelivery::DetachedSignedPlaintext => Ok(()),
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
pub(crate) enum OperationAction {
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
pub(crate) enum OperationDisposition {
    Succeeded,
    Failed,
    Incomplete,
    Observed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum OutcomeCode {
    None,
    ExecutionFailed,
    AuthorizationRefused,
    FileLifecycleIncomplete,
    ObservationFailed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ReceiptOperationRecord {
    pub sequence: u64,
    pub scope: u32,
    pub path: Vec<u8>,
    pub action: OperationAction,
    pub disposition: OperationDisposition,
    pub code: OutcomeCode,
    pub diagnostic: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RefusalReceiptRecord {
    pub sequence: u64,
    pub code: OutcomeCode,
    pub diagnostic: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ObjectMetadata {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: i64,
    pub mtime_nsec: u32,
    pub rdev: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum FinalObject {
    Absent,
    Present {
        kind: Kind,
        size: u64,
        digest: Option<[u8; 32]>,
        symlink_target: Option<Vec<u8>>,
        metadata: ObjectMetadata,
        observation_error: Option<String>,
    },
    ObservationFailed {
        code: OutcomeCode,
        diagnostic: Option<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct FinalStateReceiptRecord {
    pub sequence: u64,
    pub scope: u32,
    pub path: Vec<u8>,
    pub object: FinalObject,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum ReceiptRecord {
    Operation(ReceiptOperationRecord),
    Refusal(RefusalReceiptRecord),
    FinalState(FinalStateReceiptRecord),
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ReceiptSummary {
    pub operations: u64,
    pub succeeded: u64,
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
pub(crate) enum ReceiptStatus {
    Clean,
    Failed,
    Incomplete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum RecordingFailure {
    LimitExceeded,
    StorageFailed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum ManifestStatus {
    NotProvided,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum ReceiptSchema {
    LogicalMutationsAndFinalState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum DigestAlgorithm {
    Blake3,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TerminalReceipt {
    pub schema: ReceiptSchema,
    pub enrollment_id: EnrollmentId,
    pub request_id: RequestId,
    pub grant_digest: [u8; 32],
    pub issued_at: i64,
    pub status: ReceiptStatus,
    pub authority_closed: bool,
    pub in_flight: u64,
    pub stream_digest: [u8; 32],
    pub stream_digest_algorithm: DigestAlgorithm,
    pub content_digest_algorithm: Option<DigestAlgorithm>,
    pub record_count: u64,
    pub plaintext_bytes: u64,
    pub summary: ReceiptSummary,
    pub policy: ReceiptPolicy,
    pub recording_failure: Option<RecordingFailure>,
    pub expected_manifest_digest: Option<[u8; 32]>,
    pub manifest_status: ManifestStatus,
}

/// Append-only canonical receipt stream. The anonymous temporary file keeps
/// receipt size off the heap; its signed policy bounds both records and bytes.
pub(crate) struct ReceiptStreamWriter {
    file: File,
    hasher: blake3::Hasher,
    record_buffer: Vec<u8>,
    record_count: u64,
    plaintext_bytes: u64,
    summary: ReceiptSummary,
    max_records: u64,
    max_plaintext_bytes: u64,
    recording_failure: Option<RecordingFailure>,
}

pub(crate) struct ReceiptClosure<'a> {
    pub enrollment_id: EnrollmentId,
    pub request_id: RequestId,
    pub grant_digest: [u8; 32],
    pub issued_at: i64,
    pub policy: ReceiptPolicy,
    pub entries_touched: u64,
    pub transferred_bytes: u64,
    pub signing_key: &'a PrivateKey,
}

impl std::fmt::Debug for ReceiptStreamWriter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReceiptStreamWriter")
            .field("record_count", &self.record_count)
            .field("plaintext_bytes", &self.plaintext_bytes)
            .field("summary", &self.summary)
            .field("recording_failure", &self.recording_failure)
            .finish()
    }
}

impl ReceiptStreamWriter {
    pub(crate) fn new(policy: &ReceiptPolicy) -> Result<Self> {
        policy.validate()?;
        Ok(Self {
            file: tempfile::tempfile().context("create receiver receipt spool")?,
            hasher: blake3::Hasher::new(),
            record_buffer: Vec::new(),
            record_count: 0,
            plaintext_bytes: 0,
            summary: ReceiptSummary::default(),
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
            .get_or_insert(RecordingFailure::StorageFailed);
    }

    pub(crate) fn append(&mut self, record: &ReceiptRecord) {
        if self.recording_failure.is_some() {
            return;
        }
        if record_sequence(record) != self.record_count {
            self.recording_failure = Some(RecordingFailure::StorageFailed);
            return;
        }
        let mut body = std::mem::take(&mut self.record_buffer);
        body.clear();
        let body = match postcard::to_extend(record, body) {
            Ok(body) => body,
            Err(_) => {
                self.recording_failure = Some(RecordingFailure::StorageFailed);
                return;
            }
        };
        let framed_len = match STREAM_RECORD_HEADER_BYTES.checked_add(body.len()) {
            Some(length) => length,
            None => {
                self.record_buffer = body;
                self.recording_failure = Some(RecordingFailure::LimitExceeded);
                return;
            }
        };
        let new_bytes = match self.plaintext_bytes.checked_add(framed_len as u64) {
            Some(bytes) => bytes,
            None => {
                self.record_buffer = body;
                self.recording_failure = Some(RecordingFailure::LimitExceeded);
                return;
            }
        };
        if self.record_count >= self.max_records || new_bytes > self.max_plaintext_bytes {
            self.record_buffer = body;
            self.recording_failure = Some(RecordingFailure::LimitExceeded);
            return;
        }
        let length = match u32::try_from(body.len()) {
            Ok(length) => length.to_be_bytes(),
            Err(_) => {
                self.record_buffer = body;
                self.recording_failure = Some(RecordingFailure::LimitExceeded);
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
            self.recording_failure = Some(RecordingFailure::StorageFailed);
            return;
        }
        self.hasher.update(&length);
        self.hasher.update(&body);
        self.record_count += 1;
        self.plaintext_bytes = new_bytes;
        summarize(record, &mut self.summary);
        self.record_buffer = body;
    }

    pub(crate) fn finish(mut self, closure: ReceiptClosure<'_>) -> Result<IssuedReceipt> {
        let ReceiptClosure {
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
            ReceiptStatus::Incomplete
        } else if self.summary.failed > 0
            || self.summary.incomplete > 0
            || self.summary.refusals > 0
        {
            ReceiptStatus::Failed
        } else {
            ReceiptStatus::Clean
        };
        let terminal = TerminalReceipt {
            schema: ReceiptSchema::LogicalMutationsAndFinalState,
            enrollment_id,
            request_id,
            grant_digest,
            issued_at,
            status,
            authority_closed: true,
            in_flight: 0,
            stream_digest: *self.hasher.finalize().as_bytes(),
            stream_digest_algorithm: DigestAlgorithm::Blake3,
            content_digest_algorithm: policy.hashed.then_some(DigestAlgorithm::Blake3),
            record_count: self.record_count,
            plaintext_bytes: self.plaintext_bytes,
            summary: self.summary,
            policy: policy.clone(),
            recording_failure: self.recording_failure,
            expected_manifest_digest: None,
            manifest_status: ManifestStatus::NotProvided,
        };
        Ok(IssuedReceipt {
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

fn record_sequence(record: &ReceiptRecord) -> u64 {
    match record {
        ReceiptRecord::Operation(record) => record.sequence,
        ReceiptRecord::Refusal(record) => record.sequence,
        ReceiptRecord::FinalState(record) => record.sequence,
    }
}

fn summarize(record: &ReceiptRecord, summary: &mut ReceiptSummary) {
    match record {
        ReceiptRecord::Operation(record) => {
            summary.operations += 1;
            match record.disposition {
                OperationDisposition::Succeeded | OperationDisposition::Observed => {
                    summary.succeeded += 1
                }
                OperationDisposition::Failed => summary.failed += 1,
                OperationDisposition::Incomplete => summary.incomplete += 1,
            }
            match record.action {
                OperationAction::PublishFile { size, .. }
                    if record.disposition == OperationDisposition::Succeeded =>
                {
                    summary.published_files += 1;
                    summary.published_bytes = summary.published_bytes.saturating_add(size);
                }
                OperationAction::DeleteFile | OperationAction::DeleteDirectory
                    if record.disposition == OperationDisposition::Succeeded =>
                {
                    summary.deletions += 1;
                }
                OperationAction::ObserveFileHash
                    if record.disposition == OperationDisposition::Observed =>
                {
                    summary.observed_hashes += 1;
                }
                _ => {}
            }
        }
        ReceiptRecord::Refusal(_) => summary.refusals += 1,
        ReceiptRecord::FinalState(record) => {
            summary.final_states += 1;
            if matches!(
                record.object,
                FinalObject::ObservationFailed { .. }
                    | FinalObject::Present {
                        observation_error: Some(_),
                        ..
                    }
            ) {
                summary.observation_failures += 1;
            }
        }
    }
}

pub(crate) struct IssuedReceipt {
    stream: File,
    stream_len: u64,
    signed_terminal: Vec<u8>,
    enrollment_id: EnrollmentId,
    request_id: RequestId,
    grant_digest: [u8; 32],
    delivery: ReceiptDelivery,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum ReceiptDeliveryKind {
    AttachedEncrypted,
    DetachedSignedPlaintext,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum ReceiptFrame {
    Start {
        mode: ReceiptDeliveryKind,
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
enum BorrowedReceiptFrame<'a> {
    Start {
        mode: ReceiptDeliveryKind,
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
impl ReceiptFrame {
    fn as_borrowed(&self) -> BorrowedReceiptFrame<'_> {
        match self {
            Self::Start {
                mode,
                encapsulated_key,
            } => BorrowedReceiptFrame::Start {
                mode: *mode,
                encapsulated_key,
            },
            Self::Chunk { sequence, payload } => BorrowedReceiptFrame::Chunk {
                sequence: *sequence,
                payload,
            },
            Self::End { sequence, payload } => BorrowedReceiptFrame::End {
                sequence: *sequence,
                payload,
            },
        }
    }
}

pub(crate) fn emit_receipt_frames(
    mut issued: IssuedReceipt,
    mut emit: impl FnMut(Vec<u8>) -> Result<()>,
) -> Result<()> {
    let info = hpke_info(issued.enrollment_id, issued.request_id, issued.grant_digest)?;
    match issued.delivery {
        ReceiptDelivery::AttachedEncrypted {
            suite: HpkeSuite::X25519HkdfSha256HkdfSha256ChaCha20Poly1305,
            recipient_public_key,
        } => {
            let public = <Kem as hpke::Kem>::PublicKey::from_bytes(&recipient_public_key)
                .map_err(|_| anyhow!("invalid HPKE recipient public key in signed grant"))?;
            let (encapsulated, mut sender) =
                setup_sender::<Aead, Kdf, Kem>(&OpModeS::Base, &public, &info)
                    .map_err(|_| anyhow!("set up HPKE receipt sender"))?;
            let encapsulated = encapsulated.to_bytes();
            emit(encode_borrowed_receipt_frame(
                &BorrowedReceiptFrame::Start {
                    mode: ReceiptDeliveryKind::AttachedEncrypted,
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
                emit(encode_borrowed_receipt_frame(
                    &BorrowedReceiptFrame::Chunk {
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
            emit(encode_borrowed_receipt_frame(&BorrowedReceiptFrame::End {
                sequence,
                payload: &payload,
            })?)?;
        }
        ReceiptDelivery::DetachedSignedPlaintext => {
            emit(encode_borrowed_receipt_frame(
                &BorrowedReceiptFrame::Start {
                    mode: ReceiptDeliveryKind::DetachedSignedPlaintext,
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
                emit(encode_borrowed_receipt_frame(
                    &BorrowedReceiptFrame::Chunk {
                        sequence,
                        payload: &buffer[..wanted],
                    },
                )?)?;
                sequence += 1;
                remaining -= wanted as u64;
            }
            emit(encode_borrowed_receipt_frame(&BorrowedReceiptFrame::End {
                sequence,
                payload: &issued.signed_terminal,
            })?)?;
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn encode_receipt_frame(frame: &ReceiptFrame) -> Result<Vec<u8>> {
    encode_borrowed_receipt_frame(&frame.as_borrowed())
}

fn encode_borrowed_receipt_frame(frame: &BorrowedReceiptFrame<'_>) -> Result<Vec<u8>> {
    let payload_len = match frame {
        BorrowedReceiptFrame::Start {
            encapsulated_key, ..
        } => encapsulated_key.len(),
        BorrowedReceiptFrame::Chunk { payload, .. } | BorrowedReceiptFrame::End { payload, .. } => {
            payload.len()
        }
    };
    // Postcard adds only enum tags and variable-length integer fields around
    // the byte payload. Leave modest headroom so normal frames need one
    // allocation without walking the payload once just to measure it.
    let capacity = HEADER_LEN
        .checked_add(payload_len)
        .and_then(|length| length.checked_add(32))
        .context("receipt frame length overflow")?;
    let mut encoded = Vec::with_capacity(capacity);
    encoded.resize(HEADER_LEN, 0);
    encoded = postcard::to_extend(frame, encoded).context("encode receipt frame")?;
    let body_len = encoded.len() - HEADER_LEN;
    if body_len == 0 || body_len > MAX_FRAME_BODY_BYTES {
        bail!("receipt frame exceeds size limit");
    }
    encoded[..8].copy_from_slice(FRAME_MAGIC);
    encoded[8..HEADER_LEN].copy_from_slice(&(body_len as u32).to_be_bytes());
    Ok(encoded)
}

pub(crate) fn decode_receipt_frame(encoded: &[u8]) -> Result<ReceiptFrame> {
    if encoded.len() < HEADER_LEN || &encoded[..8] != FRAME_MAGIC {
        bail!("not a receipt frame");
    }
    let body_len = u32::from_be_bytes(encoded[8..12].try_into().expect("fixed header")) as usize;
    if body_len == 0 || body_len > MAX_FRAME_BODY_BYTES || encoded.len() != HEADER_LEN + body_len {
        bail!("receipt frame length is noncanonical");
    }
    let body = &encoded[HEADER_LEN..];
    let frame: ReceiptFrame = postcard::from_bytes(body).context("decode receipt frame")?;
    if postcard::to_stdvec(&frame)? != body {
        bail!("receipt frame uses a noncanonical encoding");
    }
    match &frame {
        ReceiptFrame::Start {
            mode: ReceiptDeliveryKind::AttachedEncrypted,
            encapsulated_key,
        } if encapsulated_key.len() != 32 => bail!("invalid HPKE encapsulated-key length"),
        ReceiptFrame::Start {
            mode: ReceiptDeliveryKind::DetachedSignedPlaintext,
            encapsulated_key,
        } if !encapsulated_key.is_empty() => {
            bail!("plaintext receipt start frame carries an encapsulated key")
        }
        ReceiptFrame::Chunk { payload, .. }
            if payload.len() > PLAINTEXT_CHUNK_BYTES + HPKE_TAG_BYTES =>
        {
            bail!("receipt chunk payload exceeds size limit")
        }
        ReceiptFrame::End { payload, .. }
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

pub(crate) fn receipt_frame_is_end(encoded: &[u8]) -> Result<bool> {
    Ok(matches!(
        decode_receipt_frame(encoded)?,
        ReceiptFrame::End { .. }
    ))
}

pub(crate) struct VerifiedReceipt {
    pub terminal: TerminalReceipt,
    stream: File,
}

impl VerifiedReceipt {
    pub(crate) fn for_each_record(
        &mut self,
        mut visit: impl FnMut(ReceiptRecord) -> Result<()>,
    ) -> Result<()> {
        self.stream.seek(SeekFrom::Start(0))?;
        for _ in 0..self.terminal.record_count {
            let record = read_record(&mut self.stream)?;
            visit(record)?;
        }
        Ok(())
    }
}

/// What the emission produced, for the human summary that renders from the
/// same data.
pub(crate) struct EmittedAutomationRecords {
    pub errors: u64,
}

/// Publish the already-verified receiver account as automation records in the
/// run's results stream: one `operation_result` per receipt operation, an
/// `error` record per refusal, a `final_state` record per closure-time
/// observation, and the sealed terminal `result`. These records identify their
/// provenance: unlike the coordinator's ordinary `--results`, every fact here
/// came from the signed receipt, and every attested record carries
/// `provenance: "receiver_attested"`. Scope-relative paths are not expanded
/// into ambient hostB paths.
pub(crate) fn emit_automation_records(
    receipt: &mut VerifiedReceipt,
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
            ReceiptRecord::Operation(record) => {
                let (action, kind, bytes) = match record.action {
                    OperationAction::PublishFile { size, .. } => {
                        ("transfer_file", Some("file"), Some(size))
                    }
                    OperationAction::EnsureDirectory => {
                        if record.disposition == OperationDisposition::Succeeded {
                            directories_created += 1;
                        }
                        ("create_directory", Some("dir"), None)
                    }
                    OperationAction::CreateSymlink => {
                        if record.disposition == OperationDisposition::Succeeded {
                            symlinks_created += 1;
                        }
                        ("create_symlink", Some("symlink"), None)
                    }
                    OperationAction::CreateSpecial { .. } => {
                        if record.disposition == OperationDisposition::Succeeded {
                            specials_created += 1;
                        }
                        ("create_special", Some("special"), None)
                    }
                    OperationAction::SetMetadata { .. } => ("set_metadata", None, None),
                    OperationAction::DeleteFile => ("delete", Some("file"), None),
                    OperationAction::DeleteDirectory => ("delete", Some("dir"), None),
                    OperationAction::ObserveFileHash => ("observe_hash", Some("file"), None),
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
                if record.code != OutcomeCode::None {
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
                    OperationDisposition::Failed | OperationDisposition::Incomplete
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
            ReceiptRecord::Refusal(record) => {
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
            ReceiptRecord::FinalState(record) => {
                let object = match record.object {
                    FinalObject::Absent => serde_json::json!({"state": "absent"}),
                    FinalObject::ObservationFailed { code, diagnostic } => {
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
                    FinalObject::Present {
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
    // excluded entries are coordinator concepts a receipt cannot attest.
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

fn disposition_name(disposition: OperationDisposition) -> &'static str {
    match disposition {
        OperationDisposition::Succeeded => "succeeded",
        OperationDisposition::Failed => "failed",
        OperationDisposition::Incomplete => "incomplete",
        OperationDisposition::Observed => "observed",
    }
}

fn outcome_name(code: OutcomeCode) -> &'static str {
    match code {
        OutcomeCode::None => "none",
        OutcomeCode::ExecutionFailed => "execution_failed",
        OutcomeCode::AuthorizationRefused => "authorization_refused",
        OutcomeCode::FileLifecycleIncomplete => "file_lifecycle_incomplete",
        OutcomeCode::ObservationFailed => "observation_failed",
    }
}

pub(crate) fn receipt_status_label(status: ReceiptStatus) -> &'static str {
    receipt_status_name(status)
}

fn error_class_for(code: OutcomeCode) -> &'static str {
    match code {
        OutcomeCode::AuthorizationRefused => "safety_limit",
        OutcomeCode::FileLifecycleIncomplete => "integrity",
        OutcomeCode::ExecutionFailed | OutcomeCode::ObservationFailed | OutcomeCode::None => "io",
    }
}

fn receipt_status_name(status: ReceiptStatus) -> &'static str {
    match status {
        ReceiptStatus::Clean => "clean",
        ReceiptStatus::Failed => "failed",
        ReceiptStatus::Incomplete => "incomplete",
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

/// Decrypt and verify an attached receipt whose encoded frames have
/// been captured in order. Decrypted bytes remain in an anonymous temporary
/// file until the terminal signature and stream commitment have verified.
pub(crate) fn open_attached_frames<I>(
    frames: I,
    recipient_secret: &RecipientSecret,
    receipt_public_key: &str,
    expected_enrollment_id: EnrollmentId,
    expected_request_id: RequestId,
    expected_grant_digest: [u8; 32],
    expected_policy: &ReceiptPolicy,
) -> Result<VerifiedReceipt>
where
    I: IntoIterator<Item = Result<Vec<u8>>>,
{
    let mut frames = frames.into_iter();
    let first = frames
        .next()
        .context("receipt stream has no start frame")??;
    let encapsulated_key = match decode_receipt_frame(&first)? {
        ReceiptFrame::Start {
            mode: ReceiptDeliveryKind::AttachedEncrypted,
            encapsulated_key,
        } => encapsulated_key,
        ReceiptFrame::Start {
            mode: ReceiptDeliveryKind::DetachedSignedPlaintext,
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
        match decode_receipt_frame(&encoded)? {
            ReceiptFrame::Chunk {
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
            ReceiptFrame::End {
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
            ReceiptFrame::Start { .. } => bail!("receipt stream contains a second start frame"),
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
    Ok(VerifiedReceipt { terminal, stream })
}

fn verify_stream(stream: &mut File, terminal: &TerminalReceipt) -> Result<()> {
    if terminal.schema != ReceiptSchema::LogicalMutationsAndFinalState
        || terminal.stream_digest_algorithm != DigestAlgorithm::Blake3
        || terminal.content_digest_algorithm
            != terminal.policy.hashed.then_some(DigestAlgorithm::Blake3)
    {
        bail!("receipt schema or digest algorithms are inconsistent with its policy");
    }
    if terminal.record_count > terminal.policy.max_records
        || terminal.plaintext_bytes > terminal.policy.max_plaintext_bytes
    {
        bail!("receipt stream exceeds its signed policy limit");
    }
    if terminal.expected_manifest_digest.is_some()
        || terminal.manifest_status != ManifestStatus::NotProvided
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
    let mut summary = ReceiptSummary::default();
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
        let record: ReceiptRecord = postcard::from_bytes(&body).context("decode receipt record")?;
        if postcard::to_stdvec(&record)? != body {
            bail!("receipt record uses a noncanonical encoding");
        }
        if record_sequence(&record) != expected_sequence {
            bail!("receipt record sequence is not contiguous");
        }
        validate_record(&record, &terminal.policy)?;
        if let ReceiptRecord::FinalState(record) = &record {
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
            ReceiptStatus::Incomplete
        } else if summary.failed > 0 || summary.incomplete > 0 || summary.refusals > 0 {
            ReceiptStatus::Failed
        } else {
            ReceiptStatus::Clean
        };
    if terminal.status != expected_status {
        bail!("receipt status is inconsistent with its records");
    }
    stream.seek(SeekFrom::Start(0))?;
    Ok(())
}

fn validate_record(record: &ReceiptRecord, policy: &ReceiptPolicy) -> Result<()> {
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
        ReceiptRecord::Operation(record) => {
            if !valid_relative_path(&record.path) || !valid_diagnostic(&record.diagnostic) {
                bail!("receipt operation has an invalid path or diagnostic");
            }
            let expected_code = match record.disposition {
                OperationDisposition::Succeeded | OperationDisposition::Observed => {
                    OutcomeCode::None
                }
                OperationDisposition::Failed => OutcomeCode::ExecutionFailed,
                OperationDisposition::Incomplete => OutcomeCode::FileLifecycleIncomplete,
            };
            if record.code != expected_code
                || (record.disposition == OperationDisposition::Observed
                    && record.action != OperationAction::ObserveFileHash)
                || (record.action == OperationAction::ObserveFileHash
                    && matches!(record.disposition, OperationDisposition::Succeeded))
                || (matches!(
                    record.disposition,
                    OperationDisposition::Succeeded | OperationDisposition::Observed
                ) && record.diagnostic.is_some())
            {
                bail!("receipt operation code, disposition, and diagnostic are inconsistent");
            }
        }
        ReceiptRecord::Refusal(record) => {
            if record.code != OutcomeCode::AuthorizationRefused
                || !valid_diagnostic(&record.diagnostic)
            {
                bail!("receipt refusal is inconsistent");
            }
        }
        ReceiptRecord::FinalState(record) => {
            if !valid_relative_path(&record.path) {
                bail!("receipt final state has an invalid relative path");
            }
            match &record.object {
                FinalObject::Absent => {}
                FinalObject::ObservationFailed { code, diagnostic } => {
                    if *code != OutcomeCode::ObservationFailed || !valid_diagnostic(diagnostic) {
                        bail!("receipt final-state failure is inconsistent");
                    }
                }
                FinalObject::Present {
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

fn read_record(stream: &mut File) -> Result<ReceiptRecord> {
    let mut length = [0u8; STREAM_RECORD_HEADER_BYTES];
    stream.read_exact(&mut length)?;
    let body_len = u32::from_be_bytes(length) as usize;
    if body_len == 0 || body_len > MAX_FRAME_BODY_BYTES {
        bail!("receipt record length is outside the supported range");
    }
    let mut body = vec![0u8; body_len];
    stream.read_exact(&mut body)?;
    let record: ReceiptRecord = postcard::from_bytes(&body)?;
    if postcard::to_stdvec(&record)? != body {
        bail!("receipt record uses a noncanonical encoding");
    }
    Ok(record)
}

fn sign_terminal(receipt: &TerminalReceipt, private_key: &PrivateKey) -> Result<Vec<u8>> {
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
    encoded.extend_from_slice(&[0; std::mem::size_of::<u32>()]);
    encoded = postcard::to_extend(receipt, encoded).context("encode receipt terminal")?;
    let body_len = encoded.len() - signed_header_len;
    debug_assert_eq!(body_len, measured_body_len);
    if body_len > MAX_TERMINAL_BYTES {
        bail!("receipt terminal exceeds size limit");
    }
    encoded[8..signed_header_len].copy_from_slice(&(body_len as u32).to_be_bytes());
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

fn verify_terminal(encoded: &[u8], public_key: &str) -> Result<TerminalReceipt> {
    if encoded.len() < TERMINAL_HEADER_LEN || &encoded[..8] != TERMINAL_MAGIC {
        bail!("not a receipt terminal envelope");
    }
    let body_len = u32::from_be_bytes(encoded[8..12].try_into().expect("fixed header")) as usize;
    let signature_len =
        u32::from_be_bytes(encoded[12..16].try_into().expect("fixed header")) as usize;
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
    let receipt: TerminalReceipt = postcard::from_bytes(body).context("decode receipt terminal")?;
    if postcard::to_stdvec(&receipt)? != body {
        bail!("receipt terminal uses a noncanonical encoding");
    }
    receipt.policy.validate()?;
    Ok(receipt)
}

fn terminal_signing_payload(body: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(8 + 2 + 4 + body.len());
    payload.extend_from_slice(TERMINAL_MAGIC);
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
        "syq-receipt-hpke@greaber.github",
        enrollment_id,
        request_id,
        grant_digest,
    ))
    .context("encode receipt HPKE context")
}

fn frame_aad(sequence: u64, terminal: bool) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32);
    aad.extend_from_slice(b"syq-receipt-frame\0");
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
        PrivateKey::new(keypair.into(), "syq-receipt-test").unwrap()
    }

    fn policy(public: [u8; 32]) -> ReceiptPolicy {
        ReceiptPolicy {
            required: true,
            hashed: true,
            max_records: 32,
            max_plaintext_bytes: 64 * 1024,
            delivery: ReceiptDelivery::AttachedEncrypted {
                suite: HpkeSuite::X25519HkdfSha256HkdfSha256ChaCha20Poly1305,
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
        let mut stream = ReceiptStreamWriter::new(&policy).unwrap();
        stream.append(&ReceiptRecord::Operation(ReceiptOperationRecord {
            sequence: stream.next_sequence(),
            scope: 0,
            path: b"artifact".to_vec(),
            action: OperationAction::PublishFile {
                size: 3,
                inplace: false,
            },
            disposition: OperationDisposition::Failed,
            code: OutcomeCode::ExecutionFailed,
            diagnostic: Some("short write".to_string()),
        }));
        stream.append(&ReceiptRecord::Refusal(RefusalReceiptRecord {
            sequence: stream.next_sequence(),
            code: OutcomeCode::AuthorizationRefused,
            diagnostic: None,
        }));
        stream.append(&ReceiptRecord::FinalState(FinalStateReceiptRecord {
            sequence: stream.next_sequence(),
            scope: 0,
            path: b"artifact".to_vec(),
            object: FinalObject::ObservationFailed {
                code: OutcomeCode::ObservationFailed,
                diagnostic: None,
            },
        }));
        // A present object whose closure hash could not be taken: the object
        // is attested, but the partial observation still counts as an error.
        stream.append(&ReceiptRecord::FinalState(FinalStateReceiptRecord {
            sequence: stream.next_sequence(),
            scope: 0,
            path: b"partial".to_vec(),
            object: FinalObject::Present {
                kind: Kind::File,
                size: 4,
                digest: None,
                symlink_target: None,
                metadata: ObjectMetadata {
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
            .finish(ReceiptClosure {
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
        emit_receipt_frames(issued, |frame| {
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
        assert_eq!(verified.terminal.status, ReceiptStatus::Incomplete);

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
            serde_json::from_str(include_str!("../schemas/automation.schema.json")).unwrap();
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
    fn borrowed_receipt_frames_preserve_wire_encoding() {
        let frames = [
            ReceiptFrame::Start {
                mode: ReceiptDeliveryKind::AttachedEncrypted,
                encapsulated_key: vec![3; 32],
            },
            ReceiptFrame::Chunk {
                sequence: u64::MAX,
                payload: vec![5; PLAINTEXT_CHUNK_BYTES],
            },
            ReceiptFrame::End {
                sequence: 17,
                payload: vec![7; 257],
            },
        ];
        for frame in frames {
            let owned = postcard::to_stdvec(&frame).unwrap();
            let borrowed = postcard::to_stdvec(&frame.as_borrowed()).unwrap();
            assert_eq!(borrowed, owned);

            let encoded = encode_receipt_frame(&frame).unwrap();
            assert_eq!(&encoded[HEADER_LEN..], owned);
            assert_eq!(decode_receipt_frame(&encoded).unwrap(), frame);
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
        let mut stream = ReceiptStreamWriter::new(&policy).unwrap();
        stream.append(&ReceiptRecord::Operation(ReceiptOperationRecord {
            sequence: stream.next_sequence(),
            scope: 0,
            path: b"artifact".to_vec(),
            action: OperationAction::PublishFile {
                size: 3,
                inplace: false,
            },
            disposition: OperationDisposition::Succeeded,
            code: OutcomeCode::None,
            diagnostic: None,
        }));
        stream.append(&ReceiptRecord::FinalState(FinalStateReceiptRecord {
            sequence: stream.next_sequence(),
            scope: 0,
            path: b"artifact".to_vec(),
            object: FinalObject::Present {
                kind: Kind::File,
                size: 3,
                digest: Some([9; 32]),
                symlink_target: None,
                metadata: ObjectMetadata {
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
            .finish(ReceiptClosure {
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
        emit_receipt_frames(issued, |frame| {
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
        assert_eq!(verified.terminal.status, ReceiptStatus::Clean);
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
            serde_json::from_str(include_str!("../schemas/automation.schema.json")).unwrap();
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
            let mut stream = ReceiptStreamWriter::new(&policy).unwrap();
            stream.append(&ReceiptRecord::Operation(ReceiptOperationRecord {
                sequence: 0,
                scope: 0,
                path: b"artifact".to_vec(),
                action: OperationAction::EnsureDirectory,
                disposition: OperationDisposition::Succeeded,
                code: OutcomeCode::None,
                diagnostic: None,
            }));
            stream
                .finish(ReceiptClosure {
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
        emit_receipt_frames(issued, |frame| {
            tampered.push(frame);
            Ok(())
        })
        .unwrap();
        let mut chunk = decode_receipt_frame(&tampered[1]).unwrap();
        let ReceiptFrame::Chunk { payload, .. } = &mut chunk else {
            panic!("expected encrypted stream chunk");
        };
        payload[0] ^= 1;
        tampered[1] = encode_receipt_frame(&chunk).unwrap();
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
        let policy = ReceiptPolicy {
            required: true,
            hashed: false,
            max_records: 8,
            max_plaintext_bytes: 4096,
            delivery: ReceiptDelivery::DetachedSignedPlaintext,
        };
        let enrollment_id = EnrollmentId::random();
        let request_id = RequestId::fresh(1_900_000_000).unwrap();
        let signing_key = key(8);
        let mut stream = ReceiptStreamWriter::new(&policy).unwrap();
        stream.append(&ReceiptRecord::Operation(ReceiptOperationRecord {
            sequence: 0,
            scope: 1,
            path: b"plain".to_vec(),
            action: OperationAction::EnsureDirectory,
            disposition: OperationDisposition::Succeeded,
            code: OutcomeCode::None,
            diagnostic: None,
        }));
        stream.append(&ReceiptRecord::FinalState(FinalStateReceiptRecord {
            sequence: 1,
            scope: 1,
            path: b"plain".to_vec(),
            object: FinalObject::Absent,
        }));
        let issued = stream
            .finish(ReceiptClosure {
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
        emit_receipt_frames(issued, |frame| {
            frames.push(decode_receipt_frame(&frame)?);
            Ok(())
        })
        .unwrap();
        assert!(matches!(
            frames[0],
            ReceiptFrame::Start {
                mode: ReceiptDeliveryKind::DetachedSignedPlaintext,
                ref encapsulated_key,
            } if encapsulated_key.is_empty()
        ));
        let ReceiptFrame::Chunk { payload, .. } = &frames[1] else {
            panic!("expected plaintext receipt chunk");
        };
        let mut spool = tempfile::tempfile().unwrap();
        spool.write_all(payload).unwrap();
        let ReceiptFrame::End { payload, .. } = &frames[2] else {
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
        let mut stream = ReceiptStreamWriter::new(&policy).unwrap();
        for path in [b"a".as_slice(), b"b".as_slice()] {
            stream.append(&ReceiptRecord::Operation(ReceiptOperationRecord {
                sequence: stream.next_sequence(),
                scope: 0,
                path: path.to_vec(),
                action: OperationAction::EnsureDirectory,
                disposition: OperationDisposition::Succeeded,
                code: OutcomeCode::None,
                diagnostic: None,
            }));
        }
        assert!(stream.is_failed());
        let signing_key = key(4);
        let terminal = stream
            .finish(ReceiptClosure {
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

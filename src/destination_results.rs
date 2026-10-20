//! The destination's own results, streamed to the invoking machine.
//!
//! A command-restricted destination reports each change it makes, in the
//! ordinary `--results` record format, while the copy runs. The records reach
//! the invoking machine through the coordinating server, which the
//! destination's approval does not trust, so the destination authenticates
//! them for the invoking machine with keys the copy already has:
//!
//! - A header signed with the destination's key (set up at enrollment, or
//!   returned with a receiving machine's approval) binds this copy's signed
//!   grant to an HPKE exchange with the invoking machine's per-copy recipient
//!   key, which the grant carries. Both ends export a frame key and a
//!   completeness key from that exchange; the coordinator learns neither.
//! - Every later frame carries a sequence number and a tag under the frame
//!   key. Frames travel on whichever destination connection answers next, so
//!   they may arrive in any order.
//! - The end frame carries the number of frames and the destination's
//!   totals. The invoking machine adds up a keyed hash of every sequence
//!   number it received; the count and the sum must equal those of 0..N.
//!   Dropping, repeating, adding, or cutting off frames is detected with
//!   constant memory on both sides.
//!
//! Frames are authenticated, not encrypted: the coordinator already sees
//! every path it sends and every error the destination returns.

use crate::delegation::RequestId;
use crate::enrollment::EnrollmentId;
use anyhow::{anyhow, bail, Context, Result};
use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, setup_receiver, setup_sender,
    Deserializable, Kem as _, OpModeR, OpModeS, Serializable,
};
use serde::{Deserialize, Serialize};
use ssh_key::{HashAlg, LineEnding, PrivateKey, PublicKey, SshSig};
use std::time::{Duration, Instant};
use zeroize::Zeroize;

type Kem = X25519HkdfSha256;
type Kdf = HkdfSha256;
type Aead = ChaCha20Poly1305;

/// SSHSIG namespace of the destination's signed header.
const RESULTS_NAMESPACE: &str = "syq-results@greaber.github";
const HPKE_INFO_LABEL: &str = "syq-results-hpke@greaber.github";
const FRAME_KEY_LABEL: &[u8] = b"syq-results frame key";
const COMPLETENESS_KEY_LABEL: &[u8] = b"syq-results completeness key";
/// The largest encoded frame either side accepts.
pub(crate) const MAX_FRAME_BYTES: usize = 160 * 1024;
const MAX_SIGNATURE_BYTES: usize = 16 * 1024;
const MAX_HEADER_BYTES: usize = 1024;
/// Pending records are sealed into a frame once they reach this size, or
/// once the oldest has waited `SEAL_AFTER`, at the next response the
/// destination writes on any connection.
const SEAL_BYTES: usize = 32 * 1024;
const SEAL_AFTER: Duration = Duration::from_millis(200);
pub(crate) const MAX_DIAGNOSTIC_BYTES: usize = 1024;
/// Signed values new grants keep writing in their unchanged policy field.
pub(crate) const DEFAULT_MAX_RECORDS: u64 = 4_000_000;
pub(crate) const DEFAULT_MAX_PLAINTEXT_BYTES: u64 = 512 * 1024 * 1024;

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

/// A signed grant's results policy. Grants keep its released encoding byte
/// for byte (it was the receipt policy); the destination now reads only the
/// invoking machine's recipient key from it. Its record and byte limits no
/// longer cap anything.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ReceiptPolicy {
    pub required: bool,
    pub hashed: bool,
    pub max_records: u64,
    pub max_plaintext_bytes: u64,
    pub delivery: ReceiptDelivery,
}

impl ReceiptPolicy {
    /// The policy a new grant or request carries for this recipient key.
    pub(crate) fn for_recipient(recipient_public_key: [u8; 32]) -> Self {
        Self {
            required: true,
            hashed: false,
            max_records: DEFAULT_MAX_RECORDS,
            max_plaintext_bytes: DEFAULT_MAX_PLAINTEXT_BYTES,
            delivery: ReceiptDelivery::AttachedEncrypted {
                suite: HpkeSuite::X25519HkdfSha256HkdfSha256ChaCha20Poly1305,
                recipient_public_key,
            },
        }
    }

    /// For a copy whose coordinator reads the destination's replies itself
    /// and asks for no results: a valid policy whose key nobody keeps.
    pub(crate) fn unused() -> Result<Self> {
        Ok(Self::for_recipient(generate_recipient()?.1))
    }

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

    fn recipient(&self) -> Result<[u8; 32]> {
        match &self.delivery {
            ReceiptDelivery::AttachedEncrypted {
                suite: HpkeSuite::X25519HkdfSha256HkdfSha256ChaCha20Poly1305,
                recipient_public_key,
            } => Ok(*recipient_public_key),
            ReceiptDelivery::DetachedSignedPlaintext => {
                bail!("the signed grant names no recipient for the destination's results")
            }
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

/// A fresh per-copy recipient key pair for the invoking machine.
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

/// The copy a stream belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Binding {
    pub enrollment_id: EnrollmentId,
    pub request_id: RequestId,
    pub grant_digest: [u8; 32],
}

/// The destination's totals, sent in its end frame.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Totals {
    pub files_transferred: u64,
    pub bytes_transferred: u64,
    pub directories_created: u64,
    pub symlinks_created: u64,
    pub specials_created: u64,
    pub deletions_completed: u64,
    /// Changes that failed or were left unfinished, metadata-only ones
    /// included.
    pub failed: u64,
    /// Requests the destination refused; it lists each change they asked for.
    pub refused: u64,
}

/// One change the destination settled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Change {
    PublishFile {
        size: u64,
    },
    /// A new name for a file already in the destination.
    LinkFile,
    EnsureDirectory,
    CreateSymlink,
    CreateSpecial,
    /// Ordinary results list a metadata-only change only when it fails, as
    /// a failure of the object it belongs to.
    SetMetadata {
        kind: crate::proto::Kind,
    },
    /// The removal of a name that is not a directory, of a kind the
    /// receiver does not look up.
    DeleteNonDirectory,
    DeleteDirectory,
}

impl Change {
    /// Whether this is a change to a file: its contents, a name for it, or
    /// its metadata.
    fn is_file(self) -> bool {
        matches!(
            self,
            Change::PublishFile { .. }
                | Change::LinkFile
                | Change::SetMetadata {
                    kind: crate::proto::Kind::File
                }
        )
    }

    /// The ordinary record's action and kind, where known.
    fn action(self) -> (&'static str, Option<&'static str>) {
        let (action, kind) = match self {
            Change::PublishFile { .. } | Change::LinkFile => ("transfer_file", "file"),
            Change::EnsureDirectory => ("create_directory", "dir"),
            Change::CreateSymlink => ("create_symlink", "symlink"),
            Change::CreateSpecial => ("create_special", "special"),
            Change::SetMetadata { kind } => match kind {
                crate::proto::Kind::Dir => ("create_directory", "dir"),
                crate::proto::Kind::File => ("transfer_file", "file"),
                crate::proto::Kind::Symlink => ("create_symlink", "symlink"),
                _ => ("create_special", "special"),
            },
            Change::DeleteNonDirectory => return ("delete", None),
            Change::DeleteDirectory => ("delete", "dir"),
        };
        (action, Some(kind))
    }
}

#[derive(Serialize, Deserialize)]
struct HeaderBody {
    binding: Binding,
    encapsulated_key: [u8; 32],
    records: bool,
}

#[derive(Serialize, Deserialize)]
enum Frame {
    Header {
        body: Vec<u8>,
        signature: Vec<u8>,
    },
    Records {
        seq: u64,
        payload: Vec<u8>,
        tag: [u8; 16],
    },
    End {
        frames: u64,
        totals: Totals,
        tag: [u8; 16],
    },
}

struct Keys {
    frame: [u8; 32],
    completeness: [u8; 32],
}

impl Drop for Keys {
    fn drop(&mut self) {
        self.frame.zeroize();
        self.completeness.zeroize();
    }
}

impl Keys {
    fn export(export: impl Fn(&[u8], &mut [u8]) -> Result<(), hpke::HpkeError>) -> Result<Self> {
        let mut keys = Self {
            frame: [0; 32],
            completeness: [0; 32],
        };
        export(FRAME_KEY_LABEL, &mut keys.frame)
            .map_err(|_| anyhow!("derive the results frame key"))?;
        export(COMPLETENESS_KEY_LABEL, &mut keys.completeness)
            .map_err(|_| anyhow!("derive the results completeness key"))?;
        Ok(keys)
    }

    fn records_tag(&self, seq: u64, payload: &[u8]) -> [u8; 16] {
        let mut hasher = blake3::Hasher::new_keyed(&self.frame);
        hasher.update(b"records\0");
        hasher.update(&seq.to_be_bytes());
        hasher.update(&(payload.len() as u64).to_be_bytes());
        hasher.update(payload);
        truncated(hasher)
    }

    fn end_tag(&self, frames: u64, totals: &Totals) -> Result<[u8; 16]> {
        let mut hasher = blake3::Hasher::new_keyed(&self.frame);
        hasher.update(b"end\0");
        hasher.update(&frames.to_be_bytes());
        hasher.update(&postcard::to_stdvec(totals).context("encode results totals")?);
        Ok(truncated(hasher))
    }

    /// The secret summand of one sequence number.
    fn summand(&self, seq: u64) -> u128 {
        let hash = blake3::keyed_hash(&self.completeness, &seq.to_be_bytes());
        u128::from_be_bytes(hash.as_bytes()[..16].try_into().expect("16 bytes"))
    }
}

fn truncated(hasher: blake3::Hasher) -> [u8; 16] {
    hasher.finalize().as_bytes()[..16]
        .try_into()
        .expect("16 bytes")
}

fn hpke_info(binding: &Binding) -> Result<Vec<u8>> {
    postcard::to_stdvec(&(HPKE_INFO_LABEL, binding)).context("encode results HPKE context")
}

fn encode_frame<T: Serialize>(frame: &T) -> Result<Vec<u8>> {
    let encoded = postcard::to_stdvec(frame).context("encode results frame")?;
    anyhow::ensure!(
        encoded.len() <= MAX_FRAME_BYTES,
        "results frame exceeds its size limit"
    );
    Ok(encoded)
}

/// The destination's side of one copy's stream. It holds the records that
/// have not reached a connection yet, and the failures of files the sender
/// is expected to try again until a later record settles each.
pub(crate) struct Stream {
    keys: Keys,
    records: bool,
    next_seq: u64,
    pending: Vec<u8>,
    pending_since: Option<Instant>,
    ready: Vec<Vec<u8>>,
    /// Failed changes to files the sender tries again, by destination path:
    /// each is listed when the results end unless a later record for that
    /// file settles it (`record_retried`).
    retried: std::collections::BTreeMap<Vec<u8>, RetriedFailure>,
    totals: Totals,
    ended: bool,
}

/// A failure `Stream::record_retried` holds until a retry settles it.
#[derive(Debug)]
struct RetriedFailure {
    change: Change,
    message: String,
    class: &'static str,
}

impl std::fmt::Debug for Stream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Stream")
            .field("records", &self.records)
            .field("next_seq", &self.next_seq)
            .field("totals", &self.totals)
            .field("ended", &self.ended)
            .finish_non_exhaustive()
    }
}

impl Stream {
    /// Start a stream for the recipient the grant names. The signed header
    /// is the first frame `take_frames` returns.
    pub(crate) fn start(
        policy: &ReceiptPolicy,
        binding: Binding,
        signing_key: &PrivateKey,
        records: bool,
    ) -> Result<Self> {
        let public = <Kem as hpke::Kem>::PublicKey::from_bytes(&policy.recipient()?)
            .map_err(|_| anyhow!("invalid HPKE recipient public key in the signed grant"))?;
        let (encapsulated, context) =
            setup_sender::<Aead, Kdf, Kem>(&OpModeS::Base, &public, &hpke_info(&binding)?)
                .map_err(|_| anyhow!("set up the results key exchange"))?;
        let keys = Keys::export(|label, out| context.export(label, out))?;
        let body = postcard::to_stdvec(&HeaderBody {
            binding,
            encapsulated_key: encapsulated
                .to_bytes()
                .as_slice()
                .try_into()
                .context("HPKE produced an unexpected encapsulated-key length")?,
            records,
        })
        .context("encode results header")?;
        if signing_key.is_encrypted() {
            bail!("cannot sign results with an encrypted key");
        }
        let signature = signing_key
            .sign(RESULTS_NAMESPACE, HashAlg::Sha256, &body)
            .context("sign the results header")?
            .to_pem(LineEnding::LF)
            .context("encode the results header signature")?
            .into_bytes();
        Ok(Self {
            keys,
            records,
            next_seq: 0,
            pending: Vec::new(),
            pending_since: None,
            ready: vec![encode_frame(&Frame::Header { body, signature })?],
            retried: Default::default(),
            totals: Totals::default(),
            ended: false,
        })
    }

    /// Record one settled change. `dst` is the record's destination path, or
    /// `None` when ordinary results would not list it; a failure is listed
    /// whatever its path.
    pub(crate) fn record(
        &mut self,
        change: Change,
        dst: Option<&[u8]>,
        error: Option<Failure<'_>>,
    ) {
        if self.ended {
            return;
        }
        // A later outcome for a file settles a failure held for its retry:
        // the retry is listed instead, succeeded or failed.
        if let Some(dst) = dst.filter(|_| change.is_file()) {
            self.retried.remove(dst);
        }
        let totals = &mut self.totals;
        match (change, error) {
            (_, Some(error)) => {
                totals.failed += 1;
                self.list_failure(change, dst, error.class, error.message);
                return;
            }
            (Change::PublishFile { .. } | Change::LinkFile, None) => totals.files_transferred += 1,
            (Change::EnsureDirectory, None) => totals.directories_created += 1,
            (Change::CreateSymlink, None) => totals.symlinks_created += 1,
            (Change::CreateSpecial, None) => totals.specials_created += 1,
            (Change::DeleteNonDirectory | Change::DeleteDirectory, None) => {
                totals.deletions_completed += 1
            }
            (Change::SetMetadata { .. }, None) => return,
        }
        let (Some(dst), true) = (dst, self.records) else {
            return;
        };
        let (action, kind) = change.action();
        let mut record = serde_json::json!({
            "type": "operation_result",
            "action": action,
            "dst": crate::results::tagged(dst),
            "disposition": "succeeded",
        });
        if let Some(kind) = kind {
            record["kind"] = kind.into();
        }
        let bytes = match change {
            Change::PublishFile { size } => Some(size),
            Change::LinkFile => Some(0),
            _ => None,
        };
        if let Some(bytes) = bytes {
            record["bytes"] = bytes.into();
        }
        self.push(&record);
    }

    /// Hold the failure of a change to a file that the sender tries again,
    /// such as a small-file patch it then copies whole. A later record for
    /// that file settles it; otherwise it is listed, and counted, when the
    /// results end, so a sender that never retries cannot hide it. A
    /// failure with no destination path is recorded at once.
    pub(crate) fn record_retried(
        &mut self,
        change: Change,
        dst: Option<&[u8]>,
        error: Failure<'_>,
    ) {
        if self.ended {
            return;
        }
        match dst.filter(|_| change.is_file()) {
            Some(dst) => {
                self.retried.insert(
                    dst.to_vec(),
                    RetriedFailure {
                        change,
                        message: bounded_diagnostic(error.message)
                            .unwrap_or_else(|| "failed".into()),
                        class: error.class,
                    },
                );
            }
            None => self.record(change, dst, Some(error)),
        }
    }

    /// Count a request the destination refused, and list each change it
    /// asked for: the changes with a destination path, or the request as a
    /// whole.
    pub(crate) fn refused(&mut self, message: &str, changes: &[(Option<Vec<u8>>, Change)]) {
        if self.ended {
            return;
        }
        self.totals.refused += 1;
        let mut listed = false;
        for (dst, change) in changes {
            if let Some(dst) = dst {
                // The refusal is the outcome of a retry it refuses.
                if change.is_file() {
                    self.retried.remove(dst);
                }
                self.list_failure(*change, Some(dst), "safety_limit", message);
                listed = true;
            }
        }
        if !listed {
            self.list_failure(Change::EnsureDirectory, None, "safety_limit", message);
        }
    }

    /// A failed or refused change as an ordinary copy reports one: an
    /// `operation_result` for its path, and the `error` record it counts.
    fn list_failure(&mut self, change: Change, dst: Option<&[u8]>, class: &str, error: &str) {
        if !self.records {
            return;
        }
        let message = bounded_diagnostic(error).unwrap_or_else(|| "failed".into());
        let line = match dst {
            Some(dst) => format!(
                "syq: {}: {message}",
                if dst.is_empty() {
                    ".".into()
                } else {
                    String::from_utf8_lossy(dst)
                }
            ),
            None => format!("syq: the receiver: {message}"),
        };
        self.push(&serde_json::json!({
            "type": "error",
            "class": class,
            "message": line,
        }));
        if let Some(dst) = dst {
            let (action, kind) = change.action();
            let mut record = serde_json::json!({
                "type": "operation_result",
                "action": action,
                "dst": crate::results::tagged(dst),
                "disposition": "failed",
                "class": class,
                "message": message,
            });
            if let Some(kind) = kind {
                record["kind"] = kind.into();
            }
            self.push(&record);
        }
    }

    fn push(&mut self, record: &serde_json::Value) {
        if serde_json::to_writer(&mut self.pending, record).is_ok() {
            self.pending.push(b'\n');
            self.pending_since.get_or_insert_with(Instant::now);
        }
    }

    #[cfg(test)]
    pub(crate) fn totals(&self) -> Totals {
        self.totals
    }

    /// Whether `take_frames` has anything to return now.
    pub(crate) fn due(&self, now: Instant) -> bool {
        !self.ready.is_empty()
            || self.pending.len() >= SEAL_BYTES
            || self
                .pending_since
                .is_some_and(|since| now.duration_since(since) >= SEAL_AFTER)
    }

    /// Frames ready to write, sealing pending records first when they are due.
    pub(crate) fn take_frames(&mut self, now: Instant) -> Result<Vec<Vec<u8>>> {
        if self.due(now) {
            self.seal()?;
        }
        Ok(std::mem::take(&mut self.ready))
    }

    fn seal(&mut self) -> Result<()> {
        let pending = std::mem::take(&mut self.pending);
        self.pending_since = None;
        let mut rest = pending.as_slice();
        while !rest.is_empty() {
            // Split between records once a frame holds a full batch. One
            // record is far smaller than a batch: its message is bounded.
            let mut end = rest.len().min(SEAL_BYTES * 2);
            if end < rest.len() {
                end = match rest[..end].iter().rposition(|byte| *byte == b'\n') {
                    Some(index) => index + 1,
                    None => rest
                        .iter()
                        .position(|byte| *byte == b'\n')
                        .map_or(rest.len(), |index| index + 1),
                };
            }
            let (payload, remaining) = rest.split_at(end);
            let seq = self.next_seq;
            self.next_seq += 1;
            self.ready.push(encode_frame(&Frame::Records {
                seq,
                payload: payload.to_vec(),
                tag: self.keys.records_tag(seq, payload),
            })?);
            rest = remaining;
        }
        Ok(())
    }

    /// Seal the rest and the end frame. Nothing is recorded afterwards.
    pub(crate) fn finish(&mut self, bytes_transferred: u64) -> Result<Totals> {
        if self.ended {
            bail!("the destination's results have already ended");
        }
        // Failures no retry settled are failures of the copy.
        for (dst, failure) in std::mem::take(&mut self.retried) {
            self.record(
                failure.change,
                Some(&dst),
                Some(Failure {
                    message: &failure.message,
                    class: failure.class,
                }),
            );
        }
        self.seal()?;
        self.ended = true;
        self.totals.bytes_transferred = bytes_transferred;
        let frames = self.next_seq;
        let tag = self.keys.end_tag(frames, &self.totals)?;
        self.ready.push(encode_frame(&Frame::End {
            frames,
            totals: self.totals,
            tag,
        })?);
        Ok(self.totals)
    }
}

/// What the invoking machine expects of a destination's stream.
#[derive(Debug)]
pub(crate) struct Expectation {
    /// OpenSSH public key of the destination's results signing key.
    pub public_key: String,
    pub binding: Binding,
    pub secret: RecipientSecret,
    /// Whether the destination was asked to list its changes.
    pub records: bool,
}

/// The invoking machine's side: verifies frames as they arrive, in any
/// order, and passes the records on.
pub(crate) struct Reader {
    expectation: Expectation,
    keys: Option<Keys>,
    frames: u64,
    sum: u128,
    /// The sum over 0..`expected_upto`, extended as frames arrive.
    expected_sum: u128,
    expected_upto: u64,
    end: Option<(u64, Totals)>,
}

impl std::fmt::Debug for Reader {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Reader")
            .field("frames", &self.frames)
            .field("end", &self.end)
            .finish_non_exhaustive()
    }
}

impl Reader {
    pub(crate) fn new(expectation: Expectation) -> Self {
        Self {
            expectation,
            keys: None,
            frames: 0,
            sum: 0,
            expected_sum: 0,
            expected_upto: 0,
            end: None,
        }
    }

    /// Verify one encoded frame and pass each record it carries to `emit`.
    pub(crate) fn accept(
        &mut self,
        encoded: &[u8],
        mut emit: impl FnMut(serde_json::Value) -> Result<()>,
    ) -> Result<()> {
        anyhow::ensure!(
            encoded.len() <= MAX_FRAME_BYTES,
            "a destination results frame exceeds its size limit"
        );
        let frame: Frame = postcard::from_bytes(encoded).context("decode a results frame")?;
        match frame {
            Frame::Header { body, signature } => {
                anyhow::ensure!(
                    self.keys.is_none(),
                    "the destination's results repeat their header"
                );
                self.keys = Some(self.verify_header(&body, &signature)?);
                Ok(())
            }
            Frame::Records { seq, payload, tag } => {
                let keys = self
                    .keys
                    .as_ref()
                    .context("destination results arrived before their signed header")?;
                anyhow::ensure!(
                    bool::from(subtle::ConstantTimeEq::ct_eq(
                        &keys.records_tag(seq, &payload)[..],
                        &tag[..]
                    )),
                    "a destination results frame failed authentication"
                );
                if let Some((frames, _)) = self.end {
                    anyhow::ensure!(seq < frames, "a destination results frame follows its end");
                }
                self.frames = self
                    .frames
                    .checked_add(1)
                    .context("too many results frames")?;
                self.sum = self.sum.wrapping_add(keys.summand(seq));
                while self.expected_upto <= seq {
                    self.expected_sum = self
                        .expected_sum
                        .wrapping_add(keys.summand(self.expected_upto));
                    self.expected_upto += 1;
                }
                if !self.expectation.records {
                    anyhow::ensure!(
                        payload.is_empty(),
                        "the destination listed changes that were not requested"
                    );
                }
                for line in payload.split(|byte| *byte == b'\n') {
                    if line.is_empty() {
                        continue;
                    }
                    let record: serde_json::Value = serde_json::from_slice(line)
                        .context("decode a destination result record")?;
                    anyhow::ensure!(
                        matches!(
                            record.get("type").and_then(serde_json::Value::as_str),
                            Some("operation_result" | "error")
                        ),
                        "a destination result record has an unexpected type"
                    );
                    emit(record)?;
                }
                Ok(())
            }
            Frame::End {
                frames,
                totals,
                tag,
            } => {
                let keys = self
                    .keys
                    .as_ref()
                    .context("destination results ended before their signed header")?;
                anyhow::ensure!(
                    bool::from(subtle::ConstantTimeEq::ct_eq(
                        &keys.end_tag(frames, &totals)?[..],
                        &tag[..]
                    )),
                    "the destination's results end failed authentication"
                );
                anyhow::ensure!(self.end.is_none(), "the destination's results end twice");
                self.end = Some((frames, totals));
                Ok(())
            }
        }
    }

    fn verify_header(&self, body: &[u8], signature: &[u8]) -> Result<Keys> {
        anyhow::ensure!(
            body.len() <= MAX_HEADER_BYTES && signature.len() <= MAX_SIGNATURE_BYTES,
            "the destination's results header exceeds its size limit"
        );
        let signature = SshSig::from_pem(
            std::str::from_utf8(signature).context("results header signature is not text")?,
        )
        .context("parse the results header signature")?;
        PublicKey::from_openssh(&self.expectation.public_key)
            .context("parse the destination's results key")?
            .verify(RESULTS_NAMESPACE, body, &signature)
            .context("the destination's results header signature does not verify")?;
        let header: HeaderBody = postcard::from_bytes(body).context("decode results header")?;
        anyhow::ensure!(
            postcard::to_stdvec(&header)? == body,
            "the results header uses a noncanonical encoding"
        );
        anyhow::ensure!(
            header.binding == self.expectation.binding,
            "the destination's results name a different signed grant"
        );
        anyhow::ensure!(
            header.records == self.expectation.records,
            "the destination was not asked for the results it is sending"
        );
        let private = <Kem as hpke::Kem>::PrivateKey::from_bytes(&self.expectation.secret.0)
            .map_err(|_| anyhow!("invalid local results recipient key"))?;
        let encapsulated = <Kem as hpke::Kem>::EncappedKey::from_bytes(&header.encapsulated_key)
            .map_err(|_| anyhow!("invalid results encapsulated key"))?;
        let context = setup_receiver::<Aead, Kdf, Kem>(
            &OpModeR::Base,
            &private,
            &encapsulated,
            &hpke_info(&header.binding)?,
        )
        .map_err(|_| anyhow!("set up the results key exchange"))?;
        Keys::export(|label, out| context.export(label, out))
    }

    /// The destination's totals, once every frame through its end arrived
    /// exactly once.
    pub(crate) fn finish(&mut self) -> Result<Totals> {
        let keys = self
            .keys
            .as_ref()
            .context("the destination sent no results")?;
        let (frames, totals) = self
            .end
            .context("the destination's results ended without their final frame")?;
        while self.expected_upto < frames {
            self.expected_sum = self
                .expected_sum
                .wrapping_add(keys.summand(self.expected_upto));
            self.expected_upto += 1;
        }
        anyhow::ensure!(
            self.frames == frames && self.expected_upto == frames && self.sum == self.expected_sum,
            "the destination's results arrived incomplete or altered ({} of {frames} frames)",
            self.frames
        );
        Ok(totals)
    }
}

/// Test hook: a coordinator that drops the destination's end frame, as a
/// relay that cuts the stream would.
#[cfg(debug_assertions)]
const DROP_END_ENV: &str = "SYQ_TEST_DROP_DESTINATION_RESULTS_END";
#[cfg(debug_assertions)]
fn drop_end_requested() -> bool {
    std::env::var_os(DROP_END_ENV).is_some()
}

/// The test hooks a syq passes on to the remote coordinator it starts.
#[cfg(debug_assertions)]
pub(crate) fn test_environment() -> Vec<(&'static str, String)> {
    [DROP_END_ENV, crate::results::ALTER_FAILURES_ENV]
        .into_iter()
        .filter_map(|name| Some((name, std::env::var(name).ok()?)))
        .collect()
}

/// Lines carrying results from a remote coordinator to the syq that started
/// it. The per-run token keeps file names printed on the same output from
/// passing as either kind of line.
pub(crate) mod relay {
    use base64::Engine as _;
    use std::sync::OnceLock;

    /// Environment variable carrying the token to a remote coordinator.
    pub(crate) const TOKEN_ENV: &str = "SYQ_INTERNAL_RESULTS_TOKEN";

    pub(crate) fn coordinator_prefix(token: &str) -> String {
        format!("syq-results-{token}:")
    }

    pub(crate) fn destination_prefix(token: &str) -> String {
        format!("syq-destination-{token}:")
    }

    pub(crate) fn new_token() -> anyhow::Result<String> {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes)
            .map_err(|error| anyhow::anyhow!("generate a results token: {error}"))?;
        Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
    }

    pub(crate) fn valid_token(token: &str) -> bool {
        token.len() == 32 && token.bytes().all(|byte| byte.is_ascii_hexdigit())
    }

    static DESTINATION: OnceLock<String> = OnceLock::new();

    /// Print the destination's frames for the syq that started this
    /// coordinator, from whichever connection reader receives them.
    pub(crate) fn install(token: &str) {
        let _ = DESTINATION.set(destination_prefix(token));
    }

    /// Relay one destination frame. Without an installed relay the frame is
    /// dropped, and the invoking machine finds its stream incomplete.
    pub(crate) fn forward(frame: &[u8]) {
        #[cfg(debug_assertions)]
        if super::drop_end_requested()
            && matches!(
                postcard::from_bytes::<super::Frame>(frame),
                Ok(super::Frame::End { .. })
            )
        {
            return;
        }
        let Some(prefix) = DESTINATION.get() else {
            if crate::output::debug() {
                crate::output::diagnostic!("syq: dropped a destination results frame");
            }
            return;
        };
        let line = format!(
            "{prefix}{}",
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(frame)
        );
        if let Err(error) = crate::output::write_stdout(format_args!("{line}")) {
            crate::output::warn_stdout(&error);
        }
    }

    /// A results writer's output on a remote coordinator: each record
    /// becomes one marked line on standard output.
    pub(crate) struct CoordinatorLines {
        prefix: String,
    }

    impl CoordinatorLines {
        pub(crate) fn new(token: &str) -> Self {
            Self {
                prefix: coordinator_prefix(token),
            }
        }
    }

    impl std::io::Write for CoordinatorLines {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            // The results writer hands over one whole record per write.
            let record = buf.strip_suffix(b"\n").unwrap_or(buf);
            let record = std::str::from_utf8(record)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
            crate::output::write_stdout(format_args!("{}{record}", self.prefix))?;
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
}

/// Why a change failed, as the results list it: its message and its error
/// class, the same class an ordinary copy reports for that failure.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Failure<'a> {
    pub(crate) message: &'a str,
    pub(crate) class: &'static str,
}

impl<'a> Failure<'a> {
    /// A failure the receiver knows only by its message.
    pub(crate) fn io(message: &'a str) -> Self {
        Self {
            message,
            class: "io",
        }
    }

    /// A failure the receiver's executor reported as `error`.
    pub(crate) fn of(error: &'a crate::proto::WireError) -> Self {
        Self {
            message: error.as_str(),
            class: crate::fsops::failure_class(error),
        }
    }
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
mod tests;

//! Signed receiver authorization core.
//!
//! The forced receiver verifies and claims a grant here, then converts the
//! resulting `VerifiedGrant` into `restricted::RestrictedAuthority`. That
//! separate type binds every protocol request to the enrolled filesystem root;
//! verification by itself remains deliberately incapable of filesystem access.
//!
//! The wire representation deliberately signs a typed, canonical binary grant
//! rather than a command line. The signature is an OpenSSH SSHSIG in the fixed
//! [`SSHSIG_NAMESPACE`], verified by OpenSSH against an explicit allowed-signers
//! policy. A fresh random [`RequestId`] is a replay nonce; durable claiming gives
//! at-most-once redemption, not exactly-once execution across a receiver crash.
//! The ID is a separate type and size from the stable copy IDs in
//! `proto`.
//! Redeemed IDs are rejected from the pinned claim store before invoking the
//! verifier. Each verifier runs in an isolated process group with a 30-second
//! deadline; a timeout kills the group before request handling returns.
//!
//! "Durable" here means that claim contents and directory-entry changes are
//! flushed with ordinary `fsync` through [`File::sync_all`] on a local filesystem
//! that honors those operations. It is not a promise against filesystems or
//! storage hardware that discard acknowledged writes. In particular, this core
//! does not issue macOS `F_FULLFSYNC`, which Apple documents as the stronger
//! power-loss barrier.
//!
//! Enrollment provisioning, not request handling, creates the replay namespace
//! once. It remains a real, target-owned mode-0700 directory; replay records and
//! other private state remain target-owned mode-0600 regular files. Opening and
//! reading state uses no-follow descriptors and fixed size bounds. Ownership,
//! mode, and ACL walks over ancestor directories are deliberately not part of
//! sender confinement: the receiver account and its local filesystem are in
//! the trusted boundary. The restricted receiver instead prevents signed copy
//! scopes from overlapping its executable, SSH configuration, verifier, or
//! enrollment state.

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ssh_key::{HashAlg, LineEnding, PrivateKey};
use std::ffi::{CString, OsStr};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

pub(crate) const SSHSIG_NAMESPACE: &str = "syq-grant@greaber.github";
const WIRE_MAGIC: &[u8; 8] = b"SYQGRNT\0";
const WIRE_VERSION: u16 = 3;
const WIRE_HEADER_LEN: usize = WIRE_MAGIC.len() + 2 + 4 + 4;
const MAX_GRANT_BYTES: usize = 32 * 1024;
const MAX_SIGNATURE_BYTES: usize = 16 * 1024;
const MAX_ENVELOPE_BYTES: usize = WIRE_HEADER_LEN + MAX_GRANT_BYTES + MAX_SIGNATURE_BYTES;
const MAX_POLICY_BYTES: usize = 1024 * 1024;
const MAX_REVOCATION_BYTES: usize = 4 * 1024 * 1024;
const MAX_VERIFIER_OUTPUT_BYTES: usize = 4096;
const VERIFIER_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_PATH_BYTES: usize = 4096;
const MAX_LOGIN_BYTES: usize = 256;
const MAX_SIGNER_BYTES: usize = 512;
const MAX_GRANT_VALIDITY_SECS: i64 = 24 * 60 * 60;
/// Upper bound on how far past issuance a grant may let a transfer run.
const MAX_FINISH_WINDOW_SECS: i64 = 30 * 24 * 60 * 60;
const MAX_CLOCK_SKEW_SECS: i64 = 5 * 60;
const MAX_UNIX_TIMESTAMP: i64 = 253_402_300_799; // 9999-12-31T23:59:59Z
pub(crate) const MAX_ENTRIES: u64 = 1_000_000_000_000;
// Keep later accounting representable in both signed and unsigned counters.
pub(crate) const MAX_COPY_BYTES: u64 = i64::MAX as u64;
const MAX_CONNECTIONS: u16 = 64;
const MAX_FILTER_RULES: usize = 4096;
const MAX_FILTER_RULE_BYTES: usize = 4096;
const MAX_FILTER_ROOTS: usize = 1024;
const CLAIM_MAGIC: &[u8; 8] = b"SYQCLM\0\0";
const CLAIM_VERSION: u16 = 1;
const CLAIM_RECORD_LEN: usize = CLAIM_MAGIC.len() + 2 + 8 + 32 + 32;

use crate::enrollment::EnrollmentId;

/// A one-redemption nonce generated independently for every signed request.
/// It is intentionally not constructible from `proto::PartialId`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) struct RequestId([u8; 32]);

impl RequestId {
    /// A fresh nonce whose first 8 bytes are the big-endian issue time, so
    /// hex claim filenames sort chronologically for inspection. The
    /// remaining 24 random bytes carry uniqueness; the timestamp is
    /// organizational only — verifiers rely on the envelope signature and
    /// the claim store, never on this prefix. IMPORTANT: Any future expiry
    /// or pruning decision MUST read `claimed_at` from the
    /// claim record (see `validate_claim_record`), never infer it from the
    /// filename.
    pub(crate) fn fresh(issued_at: i64) -> Result<Self> {
        let mut bytes = [0u8; 32];
        let seconds = u64::try_from(issued_at).context("request ID issue time before epoch")?;
        bytes[..8].copy_from_slice(&seconds.to_be_bytes());
        getrandom::fill(&mut bytes[8..]).context("generate signed-request ID")?;
        Ok(Self(bytes))
    }

    fn validate(self) -> Result<()> {
        if self.0.iter().all(|byte| *byte == 0) {
            bail!("request ID must be random and nonzero");
        }
        Ok(())
    }

    fn file_component(self) -> String {
        hex(&self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum GrantOperation {
    Copy(CopyOperation),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CopyOperation {
    /// Canonically spelled absolute target path. This is only a signed name;
    /// receiver authorization resolves it beneath the enrolled root handle.
    pub destination: Vec<u8>,
    /// Exact receiver-side mutation roots derived locally from the source
    /// spellings. A scope may authorize the named object alone or its subtree.
    pub mutation_scopes: Vec<MutationScope>,
    pub policy: CopyPolicy,
    pub options: CopyOptions,
    pub limits: CopyLimits,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MutationScope {
    pub path: Vec<u8>,
    pub descendants: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CopyPolicy {
    pub placement: DestinationPlacement,
    pub existing: ExistingDestinationPolicy,
    pub deletion: DeletionPolicy,
    pub publication: PublicationPolicy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum DestinationPlacement {
    ExactPath,
    DirectoryContents,
    DirectoryAsChild,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum ExistingDestinationPolicy {
    Replace,
    Skip,
    UpdateIfOlder,
    MustExist,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum DeletionPolicy {
    Forbid,
    DeleteDestinationOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum PublicationPolicy {
    AtomicStaged,
    InPlace,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CopyOptions {
    pub recursive: bool,
    pub preserve_symlinks: bool,
    pub preserve_permissions: bool,
    pub receiver_managed_modes: bool,
    pub preserve_times: bool,
    pub preserve_owner: bool,
    pub preserve_group: bool,
    pub preserve_devices: bool,
    pub compare_existing_by_content: bool,
    pub dry_run: bool,
    pub verify_only: bool,
    pub compressed_transport: bool,
    pub tcp_port_lo: u16,
    pub tcp_port_hi: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CopyLimits {
    pub max_entries: u64,
    pub max_total_bytes: u64,
    pub max_file_bytes: u64,
    pub hash_block_bytes: u64,
    pub max_connections: u16,
    pub max_deletions: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Grant {
    pub enrollment_id: EnrollmentId,
    pub target_login: String,
    pub signer: String,
    pub request_id: RequestId,
    pub issued_at: i64,
    pub not_before: i64,
    /// The receiver must redeem the grant by this wall-clock time.
    pub start_by: i64,
    /// The transfer must finish by this wall-clock time.
    pub finish_by: i64,
    pub operation: GrantOperation,
}

impl Grant {
    fn validate_static(&self) -> Result<()> {
        self.enrollment_id.validate()?;
        self.request_id.validate()?;
        validate_identity("target login", &self.target_login, MAX_LOGIN_BYTES, false)?;
        validate_identity("signer", &self.signer, MAX_SIGNER_BYTES, true)?;

        for (name, value) in [
            ("issued-at", self.issued_at),
            ("not-before", self.not_before),
            ("start-by", self.start_by),
            ("finish-by", self.finish_by),
        ] {
            if !(0..=MAX_UNIX_TIMESTAMP).contains(&value) {
                bail!("grant {name} timestamp is out of range");
            }
        }
        if self.not_before > self.issued_at
            || self.issued_at > self.start_by
            || self.start_by > self.finish_by
        {
            bail!("grant times must satisfy not-before <= issued-at <= start-by <= finish-by");
        }
        let validity = self
            .start_by
            .checked_sub(self.not_before)
            .ok_or_else(|| anyhow!("grant validity interval overflow"))?;
        if validity == 0 || validity > MAX_GRANT_VALIDITY_SECS {
            bail!("grant start-by time must be between 1 second and 24 hours after not-before");
        }
        let finish_window = self
            .finish_by
            .checked_sub(self.issued_at)
            .ok_or_else(|| anyhow!("grant finish window overflow"))?;
        if finish_window > MAX_FINISH_WINDOW_SECS {
            bail!("grant finish-by time is more than 30 days after issue");
        }

        match &self.operation {
            GrantOperation::Copy(copy) => copy.validate(),
        }
    }
}

impl CopyOperation {
    fn validate(&self) -> Result<()> {
        validate_absolute_path(&self.destination)?;
        if self.mutation_scopes.is_empty() || self.mutation_scopes.len() > 1024 {
            bail!("copy mutation-scope count is outside the supported range");
        }
        for scope in &self.mutation_scopes {
            validate_absolute_path(&scope.path)?;
            if scope.descendants && !self.options.recursive {
                bail!("nonrecursive copy cannot authorize descendant mutations");
            }
            if scope.path != self.destination
                && !(scope.path.starts_with(&self.destination)
                    && scope.path.get(self.destination.len()) == Some(&b'/'))
            {
                bail!("copy mutation scope is outside the requested destination");
            }
        }
        let limits = &self.limits;
        if limits.max_entries == 0 || limits.max_entries > MAX_ENTRIES {
            bail!("copy max-entries is outside the supported range");
        }
        if limits.max_total_bytes == 0
            || limits.max_file_bytes == 0
            || limits.max_total_bytes > MAX_COPY_BYTES
        {
            bail!("copy byte limits are outside the supported range");
        }
        if limits.max_file_bytes > limits.max_total_bytes {
            bail!("copy max-file-bytes exceeds max-total-bytes");
        }
        if self.options.preserve_permissions == self.options.receiver_managed_modes {
            bail!(
                "copy must authorize exactly one of source-mode preservation or receiver-managed modes"
            );
        }
        if !crate::proto::hash_response_fits(limits.hash_block_bytes, 0) {
            bail!("copy hash block size is outside protocol limits");
        }
        if limits.max_connections == 0 || limits.max_connections > MAX_CONNECTIONS {
            bail!("copy max-connections is outside the supported range");
        }
        if self.options.tcp_port_hi < self.options.tcp_port_lo {
            bail!("copy TCP port range is reversed");
        }
        match self.policy.deletion {
            DeletionPolicy::Forbid if limits.max_deletions != 0 => {
                bail!("copy forbids deletion but has a nonzero deletion limit")
            }
            DeletionPolicy::DeleteDestinationOnly
                if limits.max_deletions == 0 || limits.max_deletions > limits.max_entries =>
            {
                bail!("copy deletion limit is outside the supported range")
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct FilterPolicy {
    /// Ordered gitignore-style rules, anchored independently at every source
    /// root mapped into the signed destination scopes.
    pub ignore: Vec<String>,
    /// Canonical receiver-side roots produced by those source mappings.
    pub destination_roots: Vec<Vec<u8>>,
    /// Permit ignored destination paths to be removed by a prune operation.
    pub delete_excluded: bool,
}

impl FilterPolicy {
    fn validate(&self, grant: &Grant) -> Result<()> {
        if self.ignore.len() > MAX_FILTER_RULES {
            bail!("signed filter-rule count exceeds the supported range");
        }
        for rule in &self.ignore {
            if rule.len() > MAX_FILTER_RULE_BYTES || rule.contains('\0') {
                bail!("signed filter rule is outside the supported range");
            }
        }
        crate::scan::build_ignore(&self.ignore).context("validate signed filter policy")?;
        if self.ignore.is_empty() {
            if !self.destination_roots.is_empty() {
                bail!("signed filter roots require filter rules");
            }
        } else {
            if self.destination_roots.is_empty() || self.destination_roots.len() > MAX_FILTER_ROOTS
            {
                bail!("signed filter-root count is outside the supported range");
            }
            let GrantOperation::Copy(copy) = &grant.operation;
            for root in &self.destination_roots {
                validate_absolute_path(root)?;
                if !copy.mutation_scopes.iter().any(|scope| {
                    root == &scope.path
                        || (scope.descendants
                            && root.starts_with(&scope.path)
                            && root.get(scope.path.len()) == Some(&b'/'))
                }) {
                    bail!("signed filter root is outside the destination mutation scopes");
                }
            }
            if self
                .destination_roots
                .windows(2)
                .any(|roots| roots[0] >= roots[1])
            {
                bail!("signed filter roots must be sorted and unique");
            }
        }
        // `delete_excluded` is also a scan policy: with it, the coordinator
        // inspects the destination unfiltered, and the receiver requires
        // exactly that. It therefore stays meaningful when deletion is
        // forbidden (a dry run, or a zero deletion budget); the receiver's
        // deletion policy still refuses every actual removal.
        let _ = grant;
        Ok(())
    }
}

/// Signed precondition on the placement root itself. The receiver checks it
/// once against the enrolled root when the grant is claimed, and `New`
/// additionally forces no-replace creation of that root, so a remote source
/// coordinator cannot turn `--into-new` into an update of an existing tree.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum RootExistence {
    #[default]
    Any,
    /// The signed destination must not exist when the grant is claimed.
    New,
    /// The signed destination must already exist when the grant is claimed;
    /// a directory placement additionally requires a directory.
    Existing,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct GrantBody {
    grant: Grant,
    max_file_data_bytes_per_second: u64,
    filters: FilterPolicy,
    root_existence: RootExistence,
    receipt_v2: crate::receipt_v2::ReceiptPolicyV2,
}

#[cfg(test)]
fn test_receipt_policy() -> crate::receipt_v2::ReceiptPolicyV2 {
    crate::receipt_v2::ReceiptPolicyV2 {
        required: true,
        hashed: false,
        max_records: crate::receipt_v2::DEFAULT_MAX_RECORDS,
        max_plaintext_bytes: crate::receipt_v2::DEFAULT_MAX_PLAINTEXT_BYTES,
        delivery: crate::receipt_v2::ReceiptDeliveryV2::DetachedSignedPlaintext,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SignedGrantEnvelope {
    pub grant: Grant,
    pub max_file_data_bytes_per_second: u64,
    pub filters: FilterPolicy,
    pub root_existence: RootExistence,
    pub receipt_v2: crate::receipt_v2::ReceiptPolicyV2,
    /// Canonical OpenSSH armored SSHSIG bytes.
    pub signature: Vec<u8>,
}

impl SignedGrantEnvelope {
    #[cfg(test)]
    fn new(grant: Grant, max_file_data_bytes_per_second: u64, signature: Vec<u8>) -> Self {
        Self {
            grant,
            max_file_data_bytes_per_second,
            filters: FilterPolicy::default(),
            root_existence: RootExistence::Any,
            receipt_v2: test_receipt_policy(),
            signature,
        }
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        self.grant.validate_static()?;
        validate_canonical_sshsig(&self.signature)?;
        let body = canonical_body_bytes(
            &self.grant,
            self.max_file_data_bytes_per_second,
            &self.filters,
            self.root_existence,
            &self.receipt_v2,
        )?;
        if body.len() > MAX_GRANT_BYTES {
            bail!("canonical grant exceeds {MAX_GRANT_BYTES} bytes");
        }
        if self.signature.len() > MAX_SIGNATURE_BYTES {
            bail!("SSHSIG exceeds {MAX_SIGNATURE_BYTES} bytes");
        }
        let mut out = Vec::with_capacity(WIRE_HEADER_LEN + body.len() + self.signature.len());
        out.extend_from_slice(WIRE_MAGIC);
        out.extend_from_slice(&WIRE_VERSION.to_be_bytes());
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(&(self.signature.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_ENVELOPE_BYTES {
            bail!("signed grant envelope exceeds size limit");
        }
        if bytes.len() < WIRE_HEADER_LEN || &bytes[..WIRE_MAGIC.len()] != WIRE_MAGIC {
            bail!("not a SYQ signed grant envelope");
        }
        let version = u16::from_be_bytes(bytes[8..10].try_into().expect("fixed header"));
        if version != WIRE_VERSION {
            bail!("unsupported signed grant envelope version {version}");
        }
        let grant_len =
            u32::from_be_bytes(bytes[10..14].try_into().expect("fixed header")) as usize;
        let signature_len =
            u32::from_be_bytes(bytes[14..18].try_into().expect("fixed header")) as usize;
        if grant_len == 0 || grant_len > MAX_GRANT_BYTES {
            bail!("signed grant length is outside the supported range");
        }
        if signature_len == 0 || signature_len > MAX_SIGNATURE_BYTES {
            bail!("SSHSIG length is outside the supported range");
        }
        let expected = WIRE_HEADER_LEN
            .checked_add(grant_len)
            .and_then(|length| length.checked_add(signature_len))
            .ok_or_else(|| anyhow!("signed grant envelope length overflow"))?;
        if bytes.len() != expected {
            bail!("signed grant envelope length is noncanonical");
        }
        let body_bytes = &bytes[WIRE_HEADER_LEN..WIRE_HEADER_LEN + grant_len];
        let body: GrantBody = postcard::from_bytes(body_bytes).context("decode signed grant")?;
        let GrantBody {
            grant,
            max_file_data_bytes_per_second,
            filters,
            root_existence,
            receipt_v2,
        } = body;
        if canonical_body_bytes(
            &grant,
            max_file_data_bytes_per_second,
            &filters,
            root_existence,
            &receipt_v2,
        )? != body_bytes
        {
            bail!("signed grant uses a noncanonical encoding");
        }
        grant.validate_static()?;
        filters.validate(&grant)?;
        receipt_v2.validate()?;
        let signature = bytes[WIRE_HEADER_LEN + grant_len..].to_vec();
        validate_canonical_sshsig(&signature)?;
        Ok(Self {
            grant,
            max_file_data_bytes_per_second,
            filters,
            root_existence,
            receipt_v2,
            signature,
        })
    }

    fn signing_payload(&self) -> Result<Vec<u8>> {
        signing_payload(
            &self.grant,
            self.max_file_data_bytes_per_second,
            &self.filters,
            self.root_existence,
            &self.receipt_v2,
        )
    }
}

pub(crate) fn sign_grant(
    grant: Grant,
    constraints: GrantConstraints,
    private_key: &PrivateKey,
) -> Result<Vec<u8>> {
    let GrantConstraints {
        max_file_data_bytes_per_second,
        mut filters,
        root_existence,
        receipt_v2,
    } = constraints;
    if private_key.is_encrypted() {
        bail!("cannot sign a grant with an encrypted transport key");
    }
    // With no filters, --delete-excluded has no observable effect.
    if filters.ignore.is_empty() {
        filters.delete_excluded = false;
        filters.destination_roots.clear();
    } else {
        filters.destination_roots.sort();
        filters.destination_roots.dedup();
    }
    filters.validate(&grant)?;
    let payload = signing_payload(
        &grant,
        max_file_data_bytes_per_second,
        &filters,
        root_existence,
        &receipt_v2,
    )?;
    let signature = private_key
        .sign(SSHSIG_NAMESPACE, HashAlg::Sha256, &payload)
        .context("sign restricted transfer grant")?
        .to_pem(LineEnding::LF)
        .context("encode restricted transfer SSHSIG")?
        .into_bytes();
    SignedGrantEnvelope {
        grant,
        max_file_data_bytes_per_second,
        filters,
        root_existence,
        receipt_v2,
        signature,
    }
    .encode()
}

#[cfg(test)]
fn signing_payload_default(grant: &Grant, max_file_data_bytes_per_second: u64) -> Result<Vec<u8>> {
    signing_payload(
        grant,
        max_file_data_bytes_per_second,
        &FilterPolicy::default(),
        RootExistence::Any,
        &test_receipt_policy(),
    )
}

fn signing_payload(
    grant: &Grant,
    max_file_data_bytes_per_second: u64,
    filters: &FilterPolicy,
    root_existence: RootExistence,
    receipt_v2: &crate::receipt_v2::ReceiptPolicyV2,
) -> Result<Vec<u8>> {
    grant.validate_static()?;
    filters.validate(grant)?;
    let body = canonical_body_bytes(
        grant,
        max_file_data_bytes_per_second,
        filters,
        root_existence,
        receipt_v2,
    )?;
    if body.len() > MAX_GRANT_BYTES {
        bail!("canonical grant exceeds {MAX_GRANT_BYTES} bytes");
    }
    let mut out = Vec::with_capacity(WIRE_MAGIC.len() + 2 + 4 + body.len());
    out.extend_from_slice(WIRE_MAGIC);
    out.extend_from_slice(&WIRE_VERSION.to_be_bytes());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

fn canonical_body_bytes(
    grant: &Grant,
    max_file_data_bytes_per_second: u64,
    filters: &FilterPolicy,
    root_existence: RootExistence,
    receipt_v2: &crate::receipt_v2::ReceiptPolicyV2,
) -> Result<Vec<u8>> {
    receipt_v2.validate()?;
    postcard::to_stdvec(&GrantBody {
        grant: grant.clone(),
        max_file_data_bytes_per_second,
        filters: filters.clone(),
        root_existence,
        receipt_v2: receipt_v2.clone(),
    })
    .context("encode canonical signed grant")
}

fn validate_identity(name: &str, value: &str, maximum: usize, slash_allowed: bool) -> Result<()> {
    if value.is_empty() || value.len() > maximum {
        bail!("grant {name} length is outside the supported range");
    }
    if value
        .chars()
        .any(|character| character.is_control() || (!slash_allowed && character == '/'))
    {
        bail!("grant {name} contains a forbidden character");
    }
    Ok(())
}

fn validate_absolute_path(path: &[u8]) -> Result<()> {
    if path.is_empty() || path.len() > MAX_PATH_BYTES || path[0] != b'/' {
        bail!("grant destination must be a bounded absolute path");
    }
    if path.contains(&0) {
        bail!("grant destination contains NUL");
    }
    if path == b"/" {
        return Ok(());
    }
    if path.ends_with(b"/") {
        bail!("grant destination has a noncanonical trailing slash");
    }
    for component in path[1..].split(|byte| *byte == b'/') {
        if component.is_empty() || component == b"." || component == b".." {
            bail!("grant destination has a noncanonical path component");
        }
    }
    Ok(())
}

fn validate_canonical_sshsig(signature: &[u8]) -> Result<()> {
    if signature.is_empty() || signature.len() > MAX_SIGNATURE_BYTES {
        bail!("SSHSIG length is outside the supported range");
    }
    let text = std::str::from_utf8(signature).context("SSHSIG armor is not UTF-8")?;
    if text.contains('\r') || !text.ends_with('\n') {
        bail!("SSHSIG armor is noncanonical");
    }
    let lines: Vec<&str> = text.lines().collect();
    if lines.len() < 3
        || lines[0] != "-----BEGIN SSH SIGNATURE-----"
        || lines[lines.len() - 1] != "-----END SSH SIGNATURE-----"
    {
        bail!("malformed SSHSIG armor");
    }
    let encoded_lines = &lines[1..lines.len() - 1];
    if encoded_lines.iter().any(|line| line.is_empty()) {
        bail!("SSHSIG armor contains an empty data line");
    }
    for (index, line) in encoded_lines.iter().enumerate() {
        let is_last = index + 1 == encoded_lines.len();
        if (!is_last && line.len() != 70) || (is_last && line.len() > 70) {
            bail!("SSHSIG armor has noncanonical line wrapping");
        }
    }
    let encoded = encoded_lines.concat();
    let raw = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .context("malformed SSHSIG base64")?;
    if raw.len() < 10 || &raw[..6] != b"SSHSIG" || u32::from_be_bytes(raw[6..10].try_into()?) != 1 {
        bail!("malformed or unsupported SSHSIG payload");
    }
    if canonical_sshsig_armor(&raw) != signature {
        bail!("SSHSIG armor is noncanonical");
    }
    Ok(())
}

fn canonical_sshsig_armor(raw: &[u8]) -> Vec<u8> {
    let encoded = base64::engine::general_purpose::STANDARD.encode(raw);
    let mut out = b"-----BEGIN SSH SIGNATURE-----\n".to_vec();
    for chunk in encoded.as_bytes().chunks(70) {
        out.extend_from_slice(chunk);
        out.push(b'\n');
    }
    out.extend_from_slice(b"-----END SSH SIGNATURE-----\n");
    out
}

pub(crate) struct ClockObservation {
    pub unix_seconds: i64,
    pub monotonic: Instant,
}

pub(crate) struct ReceiverContext<'a> {
    pub enrollment_id: EnrollmentId,
    pub target_login: &'a str,
    pub expected_signer: &'a str,
    pub clock: ClockObservation,
    pub clock_skew_seconds: i64,
}

impl ReceiverContext<'_> {
    fn wall_time_bounds_at(&self, observed_at: Instant) -> Result<(i64, i64)> {
        let elapsed = observed_at
            .checked_duration_since(self.clock.monotonic)
            .ok_or_else(|| anyhow!("receiver monotonic clock moved backwards"))?;
        let elapsed_floor = i64::try_from(elapsed.as_secs())
            .map_err(|_| anyhow!("receiver observation duration is out of range"))?;
        // The paired wall observation has whole-second precision. Use the
        // lower bound for not-before/future checks and the upper bound for
        // expiry, claims, and deadlines. That accepts neither end of the
        // interval based on a favorable fractional-second assumption.
        let elapsed_ceil = elapsed
            .as_secs()
            .checked_add(u64::from(elapsed.subsec_nanos() != 0))
            .ok_or_else(|| anyhow!("receiver observation duration overflow"))?;
        let elapsed_ceil = i64::try_from(elapsed_ceil)
            .map_err(|_| anyhow!("receiver observation duration is out of range"))?;
        let earliest = self
            .clock
            .unix_seconds
            .checked_add(elapsed_floor)
            .ok_or_else(|| anyhow!("receiver time overflow"))?;
        let latest = self
            .clock
            .unix_seconds
            .checked_add(elapsed_ceil)
            .ok_or_else(|| anyhow!("receiver time overflow"))?;
        Ok((earliest, latest))
    }

    #[cfg(test)]
    fn wall_time_at(&self, observed_at: Instant) -> Result<i64> {
        Ok(self.wall_time_bounds_at(observed_at)?.1)
    }

    fn validate_at(&self, grant: &Grant, observed_at: Instant) -> Result<i64> {
        let (earliest_now, latest_now) = self.wall_time_bounds_at(observed_at)?;
        self.enrollment_id.validate()?;
        validate_identity(
            "expected target login",
            self.target_login,
            MAX_LOGIN_BYTES,
            false,
        )?;
        validate_identity(
            "expected signer",
            self.expected_signer,
            MAX_SIGNER_BYTES,
            true,
        )?;
        if !(0..=MAX_UNIX_TIMESTAMP).contains(&earliest_now)
            || !(0..=MAX_UNIX_TIMESTAMP).contains(&latest_now)
        {
            bail!("receiver clock is outside the supported range");
        }
        if !(0..=MAX_CLOCK_SKEW_SECS).contains(&self.clock_skew_seconds) {
            bail!("receiver clock skew allowance is outside the supported range");
        }
        if grant.enrollment_id != self.enrollment_id {
            bail!("grant is for a different receiver enrollment");
        }
        if grant.target_login != self.target_login {
            bail!("grant is for a different target login");
        }
        if grant.signer != self.expected_signer {
            bail!("grant names an unexpected signer");
        }
        let latest_acceptable_issue = earliest_now
            .checked_add(self.clock_skew_seconds)
            .ok_or_else(|| anyhow!("receiver time overflow"))?;
        if grant.issued_at > latest_acceptable_issue {
            bail!("grant was issued too far in the future");
        }
        let latest_for_start = earliest_now
            .checked_add(self.clock_skew_seconds)
            .ok_or_else(|| anyhow!("receiver time overflow"))?;
        if latest_for_start < grant.not_before {
            bail!("grant is not yet valid");
        }
        let earliest_for_expiry = latest_now
            .checked_sub(self.clock_skew_seconds)
            .ok_or_else(|| anyhow!("receiver time overflow"))?;
        if earliest_for_expiry > grant.start_by {
            bail!("grant start-by time has passed");
        }
        Ok(latest_now)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SshsigPolicy {
    pub ssh_keygen: PathBuf,
    pub allowed_signers: PathBuf,
    pub revocation_file: Option<PathBuf>,
}

impl SshsigPolicy {
    fn verify(
        &self,
        store: &ReplayStore,
        signer: &str,
        signature: &[u8],
        payload: &[u8],
    ) -> Result<()> {
        validate_regular_executable(&self.ssh_keygen, "SSHSIG verifier")?;
        let allowed = read_private_regular(
            &self.allowed_signers,
            "allowed-signers policy",
            MAX_POLICY_BYTES,
        )?;
        let revocation = self
            .revocation_file
            .as_ref()
            .map(|path| {
                read_private_regular(path, "SSHSIG revocation policy", MAX_REVOCATION_BYTES)
            })
            .transpose()?;
        let signature_file = store.temporary_file("signature", signature)?;
        let allowed_file = store.temporary_file("allowed-signers", &allowed)?;
        let revocation_file = revocation
            .as_deref()
            .map(|contents| store.temporary_file("revocations", contents))
            .transpose()?;

        // Reserve CLOEXEC descriptor numbers in the parent, then map the
        // read-only snapshots onto those numbers in the forked child only.
        // This avoids a process-wide inheritance window while still making
        // ssh-keygen consume the exact pinned inodes through /dev/fd.
        let signature_child = VerifierSnapshotFd::reserve(&signature_file, 64)
            .context("reserve signature descriptor for verifier")?;
        let allowed_child = VerifierSnapshotFd::reserve(&allowed_file, 64)
            .context("reserve allowed-signers descriptor for verifier")?;
        let revocation_child = revocation_file
            .as_ref()
            .map(|file| VerifierSnapshotFd::reserve(file, 64))
            .transpose()
            .context("reserve revocation descriptor for verifier")?;

        let mut command = Command::new(&self.ssh_keygen);
        command
            .env_clear()
            .args(["-Y", "verify", "-f"])
            .arg(allowed_child.path())
            .args(["-I", signer, "-n", SSHSIG_NAMESPACE, "-s"])
            .arg(signature_child.path());
        if let Some(revocation) = &revocation_child {
            // ssh-keygen opens a plain-text revocation list twice: once to
            // probe for KRL magic and again to scan keys. On Darwin an open of
            // /dev/fd/N duplicates the descriptor and shares its offset, so the
            // second pass would start at EOF and a revoked key would verify.
            // macOS therefore names the snapshot relative to the store's
            // retained directory descriptor, which the child enters with
            // fchdir below, so a replaced path cannot substitute the list.
            let argument = if cfg!(target_os = "macos") {
                PathBuf::from(
                    &revocation_file
                        .as_ref()
                        .expect("revocation snapshot exists when its descriptor does")
                        .name,
                )
            } else {
                revocation.path()
            };
            command.arg("-r").arg(argument);
        }
        let mut mappings = vec![signature_child.mapping(), allowed_child.mapping()];
        if let Some(revocation) = &revocation_child {
            mappings.push(revocation.mapping());
        }
        let store_directory = if cfg!(target_os = "macos") && revocation_child.is_some() {
            Some(store.directory.as_raw_fd())
        } else {
            None
        };
        unsafe {
            command.pre_exec(move || {
                if libc::setpgid(0, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
                if let Some(directory) = store_directory {
                    if libc::fchdir(directory) == -1 {
                        return Err(io::Error::last_os_error());
                    }
                }
                for (source, target) in &mappings {
                    dup2_retry(*source, *target)?;
                }
                Ok(())
            });
        }
        let child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("start trusted ssh-keygen SSHSIG verifier")?;
        let output = wait_for_verifier(child, payload, VERIFIER_TIMEOUT)?;
        if !output.status.success() {
            let diagnostic = String::from_utf8_lossy(&output.stderr);
            let diagnostic: String = diagnostic
                .trim()
                .chars()
                .take(MAX_VERIFIER_OUTPUT_BYTES)
                .collect();
            if diagnostic.is_empty() {
                bail!("SSHSIG verification failed");
            }
            bail!("SSHSIG verification failed: {diagnostic}");
        }
        Ok(())
    }
}

#[derive(Debug)]
struct VerifierOutput {
    status: ExitStatus,
    stderr: Vec<u8>,
}

fn wait_for_verifier(
    mut child: Child,
    payload: &[u8],
    timeout: Duration,
) -> Result<VerifierOutput> {
    let process_group =
        libc::pid_t::try_from(child.id()).context("SSHSIG verifier process ID is out of range")?;
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| anyhow!("SSHSIG verifier timeout overflow"))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("SSHSIG verifier stdin unavailable"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("SSHSIG verifier stdout unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("SSHSIG verifier stderr unavailable"))?;
    let payload = payload.to_vec();
    let writer = match thread::Builder::new()
        .name("syq-sshsig-input".into())
        .spawn(move || stdin.write_all(&payload))
    {
        Ok(worker) => worker,
        Err(error) => {
            terminate_verifier(&mut child, process_group);
            return Err(error).context("start SSHSIG verifier input worker");
        }
    };
    let stdout_reader = match thread::Builder::new()
        .name("syq-sshsig-output".into())
        .spawn(move || read_verifier_output(stdout))
    {
        Ok(worker) => worker,
        Err(error) => {
            terminate_verifier(&mut child, process_group);
            let _ = writer.join();
            return Err(error).context("start SSHSIG verifier output worker");
        }
    };
    let stderr_reader = match thread::Builder::new()
        .name("syq-sshsig-diagnostic".into())
        .spawn(move || read_verifier_output(stderr))
    {
        Ok(worker) => worker,
        Err(error) => {
            terminate_verifier(&mut child, process_group);
            let _ = writer.join();
            let _ = stdout_reader.join();
            return Err(error).context("start SSHSIG verifier diagnostic worker");
        }
    };

    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(error) => {
                terminate_verifier(&mut child, process_group);
                let _ = writer.join();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(error).context("poll SSHSIG verifier");
            }
        }
        let now = Instant::now();
        if now >= deadline {
            // pre_exec creates a dedicated process group, so descendants cannot
            // keep the verifier pipes or receiver resources alive after timeout.
            terminate_verifier(&mut child, process_group);
            let _ = writer.join();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            bail!("SSHSIG verifier exceeded its configured timeout");
        }
        thread::sleep((deadline - now).min(Duration::from_millis(10)));
    };

    writer
        .join()
        .map_err(|_| anyhow!("SSHSIG verifier input worker panicked"))?
        .context("write SSHSIG verification payload")?;
    stdout_reader
        .join()
        .map_err(|_| anyhow!("SSHSIG verifier output worker panicked"))??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| anyhow!("SSHSIG verifier diagnostic worker panicked"))??;
    Ok(VerifierOutput { status, stderr })
}

fn terminate_verifier(child: &mut Child, process_group: libc::pid_t) {
    let _ = unsafe { libc::kill(-process_group, libc::SIGKILL) };
    let _ = child.kill();
    let _ = child.wait();
}

fn read_verifier_output(mut output: impl Read) -> io::Result<Vec<u8>> {
    let mut contents = Vec::new();
    output
        .by_ref()
        .take(MAX_VERIFIER_OUTPUT_BYTES as u64 + 1)
        .read_to_end(&mut contents)?;
    if contents.len() > MAX_VERIFIER_OUTPUT_BYTES {
        contents.truncate(MAX_VERIFIER_OUTPUT_BYTES);
    }
    Ok(contents)
}

/// Evidence that the signature, target binding, time bounds, and one-time
/// replay claim all succeeded. The restricted receiver consumes this into its
/// independently enforced request authority and monotonic execution deadline.
#[derive(Debug)]
pub(crate) struct VerifiedGrant {
    #[allow(dead_code)]
    grant: Grant,
    max_file_data_bytes_per_second: u64,
    filters: FilterPolicy,
    root_existence: RootExistence,
    receipt_v2: crate::receipt_v2::ReceiptPolicyV2,
    grant_digest: [u8; 32],
    execution_deadline: Instant,
}

/// Signed receiver policy carried alongside the copy grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GrantConstraints {
    pub max_file_data_bytes_per_second: u64,
    pub filters: FilterPolicy,
    pub root_existence: RootExistence,
    pub receipt_v2: crate::receipt_v2::ReceiptPolicyV2,
}

#[cfg(test)]
impl Default for GrantConstraints {
    fn default() -> Self {
        Self {
            max_file_data_bytes_per_second: 0,
            filters: FilterPolicy::default(),
            root_existence: RootExistence::Any,
            receipt_v2: test_receipt_policy(),
        }
    }
}

impl VerifiedGrant {
    #[cfg(test)]
    pub(crate) fn execution_deadline(&self) -> Instant {
        self.execution_deadline
    }

    pub(crate) fn into_parts(self) -> (Grant, GrantConstraints, [u8; 32], Instant) {
        (
            self.grant,
            GrantConstraints {
                max_file_data_bytes_per_second: self.max_file_data_bytes_per_second,
                filters: self.filters,
                root_existence: self.root_existence,
                receipt_v2: self.receipt_v2,
            },
            self.grant_digest,
            self.execution_deadline,
        )
    }
}

pub(crate) fn verify_and_claim(
    encoded: &[u8],
    context: &ReceiverContext<'_>,
    policy: &SshsigPolicy,
    replay: &ReplayStore,
) -> Result<VerifiedGrant> {
    let envelope = SignedGrantEnvelope::decode(encoded)?;
    context.validate_at(&envelope.grant, Instant::now())?;
    let payload = envelope.signing_payload()?;
    let replay_digest: [u8; 32] = Sha256::digest(&payload).into();
    let grant_digest = grant_transcript_digest(&payload);
    replay.reject_if_claimed(envelope.grant.request_id, replay_digest)?;
    policy.verify(
        replay,
        context.expected_signer,
        &envelope.signature,
        &payload,
    )?;
    replay.claim_after_lock(envelope.grant.request_id, replay_digest, || {
        context.validate_at(&envelope.grant, Instant::now())
    })?;
    let verified_at = Instant::now();
    let verified_wall_time = context.validate_at(&envelope.grant, verified_at)?;
    let execution_deadline = execution_deadline(
        &envelope.grant,
        context.clock_skew_seconds,
        verified_wall_time,
        verified_at,
    )?;
    Ok(VerifiedGrant {
        grant: envelope.grant,
        max_file_data_bytes_per_second: envelope.max_file_data_bytes_per_second,
        filters: envelope.filters,
        root_existence: envelope.root_existence,
        receipt_v2: envelope.receipt_v2,
        grant_digest,
        execution_deadline,
    })
}

pub(crate) fn signed_grant_digest(encoded: &[u8]) -> Result<[u8; 32]> {
    let envelope = SignedGrantEnvelope::decode(encoded)?;
    Ok(grant_transcript_digest(&envelope.signing_payload()?))
}

fn grant_transcript_digest(payload: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"syq-grant-transcript-v1@greaber.github\0");
    hasher.update(&(payload.len() as u64).to_be_bytes());
    hasher.update(payload);
    *hasher.finalize().as_bytes()
}

fn execution_deadline(
    grant: &Grant,
    clock_skew_seconds: i64,
    current_wall_time: i64,
    verified_at: Instant,
) -> Result<Instant> {
    let finish_by = grant
        .finish_by
        .checked_add(clock_skew_seconds)
        .ok_or_else(|| anyhow!("grant finish-by overflow"))?;
    let remaining = finish_by
        .checked_sub(current_wall_time)
        .ok_or_else(|| anyhow!("grant remaining finish window overflow"))?;
    if remaining <= 0 {
        bail!("grant finish-by time passed while it was being verified and claimed");
    }
    verified_at
        .checked_add(Duration::from_secs(remaining as u64))
        .ok_or_else(|| anyhow!("monotonic execution deadline overflow"))
}

#[derive(Clone)]
pub(crate) struct ReplayStore {
    path: PathBuf,
    directory: Arc<File>,
}

impl ReplayStore {
    pub(crate) fn open(path: &Path) -> Result<Self> {
        let directory = open_existing_replay_directory(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            directory: Arc::new(directory),
        })
    }

    #[cfg(test)]
    fn claim(&self, request: RequestId, digest: [u8; 32], claimed_at: i64) -> Result<()> {
        self.claim_after_lock(request, digest, || Ok(claimed_at))
    }

    fn reject_if_claimed(&self, request: RequestId, digest: [u8; 32]) -> Result<()> {
        request.validate()?;
        let final_name = format!("claim-{}", request.file_component());
        if let Some(existing) = readat_optional(
            self.directory.as_raw_fd(),
            &final_name,
            CLAIM_RECORD_LEN + 1,
        )? {
            validate_claim_record(&existing, request, digest)?;
            bail!("signed request has already been redeemed");
        }
        Ok(())
    }

    /// Open the shared lock file, creating it on first use. macOS can answer
    /// a concurrent `O_CREAT` open of one name with a spurious `ENOENT` while
    /// another thread is creating it, so retry that case a few times.
    fn open_lock(&self) -> io::Result<File> {
        let mut attempt = 0;
        loop {
            match openat_file(
                self.directory.as_raw_fd(),
                ".claim-lock",
                libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            ) {
                Err(error) if error.kind() == io::ErrorKind::NotFound && attempt < 16 => {
                    attempt += 1;
                    thread::sleep(Duration::from_millis(1));
                }
                result => return result,
            }
        }
    }

    fn claim_after_lock(
        &self,
        request: RequestId,
        digest: [u8; 32],
        claimed_at: impl FnOnce() -> Result<i64>,
    ) -> Result<()> {
        request.validate()?;
        let lock = self
            .open_lock()
            .with_context(|| format!("open replay lock in {}", self.path.display()))?;
        validate_private_file(&lock, "replay lock")?;
        flock_exclusive(lock.as_raw_fd()).context("lock replay claim store")?;
        // Timestamp and revalidate only after a potentially queued lock wait.
        // No stale ReceiverContext observation may authorize a later claim.
        let claimed_at = claimed_at()?;

        let final_name = format!("claim-{}", request.file_component());
        if let Some(existing) = readat_optional(
            self.directory.as_raw_fd(),
            &final_name,
            CLAIM_RECORD_LEN + 1,
        )? {
            validate_claim_record(&existing, request, digest)?;
            bail!("signed request has already been redeemed");
        }

        let temporary_name = format!(
            ".claim-{}-{}.tmp",
            request.file_component(),
            hex(&random_array::<16>()?)
        );
        let mut temporary = openat_file(
            self.directory.as_raw_fd(),
            &temporary_name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
        .with_context(|| format!("create replay claim in {}", self.path.display()))?;
        if let Err(error) = validate_private_file(&temporary, "temporary replay claim") {
            let _ = unlinkat(self.directory.as_raw_fd(), &temporary_name);
            return Err(error);
        }
        let record = claim_record(request, digest, claimed_at)?;
        if let Err(error) = (|| -> io::Result<()> {
            temporary.write_all(&record)?;
            temporary.sync_all()?;
            linkat(
                self.directory.as_raw_fd(),
                &temporary_name,
                self.directory.as_raw_fd(),
                &final_name,
            )?;
            // Persist the no-replace publication before removing the temporary
            // name. A crash after this point can only leave an already-claimed
            // request, never a successful-but-forgotten claim.
            self.directory.sync_all()?;
            unlinkat(self.directory.as_raw_fd(), &temporary_name)?;
            self.directory.sync_all()?;
            Ok(())
        })() {
            let _ = unlinkat(self.directory.as_raw_fd(), &temporary_name);
            if error.kind() == io::ErrorKind::AlreadyExists {
                if let Some(existing) = readat_optional(
                    self.directory.as_raw_fd(),
                    &final_name,
                    CLAIM_RECORD_LEN + 1,
                )? {
                    validate_claim_record(&existing, request, digest)?;
                    bail!("signed request has already been redeemed");
                }
            }
            return Err(error).context("durably publish replay claim");
        }
        Ok(())
    }

    fn temporary_file(&self, label: &str, contents: &[u8]) -> Result<TemporaryStateFile> {
        let name = format!(".{label}-{}.tmp", hex(&random_array::<16>()?));
        let cleanup_name = name.clone();
        let mut writable = openat_file(
            self.directory.as_raw_fd(),
            &name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
        .with_context(|| format!("create private {label} file"))?;
        let result = (|| -> Result<TemporaryStateFile> {
            validate_private_file(&writable, label)?;
            writable
                .write_all(contents)
                .with_context(|| format!("write private {label} file"))?;
            writable
                .flush()
                .with_context(|| format!("flush private {label} file"))?;
            let file = openat_file(
                self.directory.as_raw_fd(),
                &name,
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0,
            )
            .with_context(|| format!("reopen private {label} file read-only"))?;
            validate_private_file(&file, label)?;
            let written_metadata = writable.metadata()?;
            let read_metadata = file.metadata()?;
            if written_metadata.dev() != read_metadata.dev()
                || written_metadata.ino() != read_metadata.ino()
            {
                bail!("private {label} file changed while making a verifier snapshot");
            }
            drop(writable);
            Ok(TemporaryStateFile {
                directory: Arc::clone(&self.directory),
                name,
                file,
            })
        })();
        if result.is_err() {
            let _ = unlinkat(self.directory.as_raw_fd(), &cleanup_name);
        }
        result
    }
}

struct TemporaryStateFile {
    directory: Arc<File>,
    name: String,
    file: File,
}

impl TemporaryStateFile {
    fn is_read_only(&self) -> io::Result<bool> {
        descriptor_is_read_only(self.file.as_raw_fd())
    }

    fn is_close_on_exec(&self) -> io::Result<bool> {
        descriptor_is_close_on_exec(self.file.as_raw_fd())
    }
}

struct VerifierSnapshotFd {
    source: RawFd,
    child: File,
}

impl VerifierSnapshotFd {
    fn reserve(snapshot: &TemporaryStateFile, minimum: libc::c_int) -> io::Result<Self> {
        if !snapshot.is_read_only()? || !snapshot.is_close_on_exec()? {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "verifier snapshot must be read-only and close-on-exec",
            ));
        }
        let fd = unsafe { libc::fcntl(snapshot.file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, minimum) };
        if fd == -1 {
            return Err(io::Error::last_os_error());
        }
        let reserved = Self {
            source: snapshot.file.as_raw_fd(),
            child: unsafe { File::from_raw_fd(fd) },
        };
        if !reserved.is_close_on_exec()? || !descriptor_is_read_only(reserved.child.as_raw_fd())? {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "reserved verifier descriptor must be read-only and close-on-exec",
            ));
        }
        Ok(reserved)
    }

    fn path(&self) -> PathBuf {
        PathBuf::from(format!("/dev/fd/{}", self.child.as_raw_fd()))
    }

    fn mapping(&self) -> (RawFd, RawFd) {
        (self.source, self.child.as_raw_fd())
    }

    fn is_close_on_exec(&self) -> io::Result<bool> {
        descriptor_is_close_on_exec(self.child.as_raw_fd())
    }
}

impl Drop for TemporaryStateFile {
    fn drop(&mut self) {
        let _ = unlinkat(self.directory.as_raw_fd(), &self.name);
    }
}

fn validate_private_directory(directory: &File, path: &Path) -> Result<()> {
    let metadata = directory
        .metadata()
        .with_context(|| format!("inspect replay state directory {}", path.display()))?;
    if !metadata.is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
        bail!(
            "private directory {} must be target-owned and not a symlink",
            path.display()
        );
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode != 0o700 {
        bail!(
            "private directory {} must have mode 0700 (found {:04o})",
            path.display(),
            mode
        );
    }
    Ok(())
}

pub(crate) fn validate_private_directory_path(path: &Path) -> Result<()> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("open private directory {}", path.display()))?;
    validate_private_directory(&directory, path)
}

fn open_existing_replay_directory(path: &Path) -> Result<File> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("open replay state directory {}", path.display()))?;
    validate_private_directory(&directory, path)?;
    Ok(directory)
}

fn validate_private_file(file: &File, label: &str) -> Result<()> {
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect {label}"))?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o7777 != 0o600
    {
        bail!("{label} must be a target-owned mode-0600 regular file");
    }
    Ok(())
}

pub(crate) fn validate_regular_executable(path: &Path, label: &str) -> Result<()> {
    let metadata =
        fs::metadata(path).with_context(|| format!("inspect {label} {}", path.display()))?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        bail!(
            "{label} {} must be a regular executable file",
            path.display()
        );
    }
    Ok(())
}

pub(crate) fn read_private_regular(path: &Path, label: &str, maximum: usize) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("open {label} {}", path.display()))?;
    validate_private_file(&file, &format!("{label} {}", path.display()))?;
    let mut contents = Vec::new();
    Read::by_ref(&mut file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut contents)?;
    if contents.is_empty() || contents.len() > maximum {
        bail!("{label} size is outside the supported range");
    }
    Ok(contents)
}

fn claim_record(request: RequestId, digest: [u8; 32], claimed_at: i64) -> Result<Vec<u8>> {
    if !(0..=MAX_UNIX_TIMESTAMP).contains(&claimed_at) {
        bail!("replay claim timestamp is outside the supported range");
    }
    let mut record = Vec::with_capacity(CLAIM_RECORD_LEN);
    record.extend_from_slice(CLAIM_MAGIC);
    record.extend_from_slice(&CLAIM_VERSION.to_be_bytes());
    record.extend_from_slice(&claimed_at.to_be_bytes());
    record.extend_from_slice(&request.0);
    record.extend_from_slice(&digest);
    Ok(record)
}

fn validate_claim_record(record: &[u8], request: RequestId, digest: [u8; 32]) -> Result<()> {
    if record.len() != CLAIM_RECORD_LEN
        || &record[..8] != CLAIM_MAGIC
        || u16::from_be_bytes(record[8..10].try_into().expect("claim header")) != CLAIM_VERSION
    {
        bail!("replay state is malformed; refusing signed request");
    }
    let claimed_at = i64::from_be_bytes(record[10..18].try_into().expect("claim timestamp"));
    if !(0..=MAX_UNIX_TIMESTAMP).contains(&claimed_at) {
        bail!("replay state has an invalid timestamp; refusing signed request");
    }
    if record[18..50] != request.0 {
        bail!("replay state request ID does not match its filename");
    }
    if record[50..82] != digest {
        bail!("request ID was already claimed by a different signed grant");
    }
    Ok(())
}

fn openat_file(directory: RawFd, name: &str, flags: i32, mode: libc::c_int) -> io::Result<File> {
    openat_os_file(directory, OsStr::new(name), flags, mode)
}

fn openat_os_file(
    directory: RawFd,
    name: &OsStr,
    flags: i32,
    mode: libc::c_int,
) -> io::Result<File> {
    let name = CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in state filename"))?;
    loop {
        let fd = unsafe { libc::openat(directory, name.as_ptr(), flags, mode) };
        if fd >= 0 {
            return Ok(unsafe { File::from_raw_fd(fd) });
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn descriptor_is_read_only(fd: RawFd) -> io::Result<bool> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(flags & libc::O_ACCMODE == libc::O_RDONLY)
}

fn descriptor_is_close_on_exec(fd: RawFd) -> io::Result<bool> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(flags & libc::FD_CLOEXEC != 0)
}

// Called from CommandExt::pre_exec. Keep this to async-signal-safe dup2(2),
// errno inspection, and bounded stack-only control flow.
fn dup2_retry(source: RawFd, target: RawFd) -> io::Result<()> {
    loop {
        if unsafe { libc::dup2(source, target) } >= 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn readat_optional(directory: RawFd, name: &str, maximum: usize) -> Result<Option<Vec<u8>>> {
    let mut file = match openat_file(
        directory,
        name,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        0,
    ) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("open replay record {name}")),
    };
    validate_private_file(&file, "replay claim")?;
    let mut contents = Vec::new();
    Read::by_ref(&mut file)
        .take(maximum as u64)
        .read_to_end(&mut contents)?;
    if contents.len() >= maximum {
        bail!("replay claim exceeds its fixed format; refusing request");
    }
    Ok(Some(contents))
}

fn flock_exclusive(fd: RawFd) -> io::Result<()> {
    loop {
        if unsafe { libc::flock(fd, libc::LOCK_EX) } == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn linkat(old_directory: RawFd, old: &str, new_directory: RawFd, new: &str) -> io::Result<()> {
    let old = CString::new(old)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in old state filename"))?;
    let new = CString::new(new)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in new state filename"))?;
    if unsafe { libc::linkat(old_directory, old.as_ptr(), new_directory, new.as_ptr(), 0) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn unlinkat(directory: RawFd, name: &str) -> io::Result<()> {
    let name = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in state filename"))?;
    if unsafe { libc::unlinkat(directory, name.as_ptr(), 0) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).context("generate private state filename")?;
    Ok(bytes)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{DirBuilderExt, FileTypeExt};
    use std::process::Child;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::Duration;

    const NOW: i64 = 1_900_000_000;
    const SIGNER: &str = "alice@example.test";
    const MALLORY: &str = "mallory@example.test";
    const TARGET: &str = "backup";

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(label: &str) -> Self {
            #[cfg(target_os = "macos")]
            let parent = std::env::var_os("TMPDIR")
                .or_else(|| std::env::var_os("XDG_RUNTIME_DIR"))
                .or_else(|| std::env::var_os("HOME"));
            #[cfg(not(target_os = "macos"))]
            let parent = std::env::var_os("XDG_RUNTIME_DIR").or_else(|| std::env::var_os("HOME"));
            let parent = parent
                .map(PathBuf::from)
                .filter(|path| path.is_absolute())
                .expect("tests require an absolute private runtime or home directory");
            // Resolve symlinks (macOS `/var`) and keep the name short: an
            // ssh-agent socket beneath this directory must fit `sun_path`,
            // which is 104 bytes on macOS beneath an already long `TMPDIR`.
            let parent = fs::canonicalize(&parent).unwrap_or(parent);
            let label: String = label
                .chars()
                .filter(|c| c.is_ascii_alphanumeric())
                .take(6)
                .collect();
            for _ in 0..100 {
                let path = parent.join(format!(
                    "syq-{label}-{}-{}",
                    std::process::id(),
                    hex(&random_array::<4>().expect("test randomness"))
                ));
                let result = fs::DirBuilder::new().mode(0o700).create(&path);
                match result {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("create test directory: {error}"),
                }
            }
            panic!("could not allocate a unique test directory");
        }

        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct AgentGuard {
        child: Child,
        socket: PathBuf,
    }

    impl Drop for AgentGuard {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    struct Fixture {
        directory: TestDir,
        key: PathBuf,
        allowed_signers: PathBuf,
    }

    impl Fixture {
        fn ordinary() -> Self {
            let directory = TestDir::new("ordinary");
            let key = directory.join("signer");
            generate_key(&key);
            let allowed_signers = directory.join("allowed-signers");
            write_allowed_signers(&allowed_signers, SIGNER, &key.with_extension("pub"), false);
            Self {
                directory,
                key,
                allowed_signers,
            }
        }

        fn replay(&self, name: &str) -> ReplayStore {
            let path = self.directory.join(name);
            provision_test_replay_directory(&path);
            ReplayStore::open(&path).expect("open replay store")
        }

        fn policy(&self) -> SshsigPolicy {
            SshsigPolicy {
                ssh_keygen: ssh_tool("ssh-keygen"),
                allowed_signers: self.allowed_signers.clone(),
                revocation_file: None,
            }
        }

        fn signed(&self, grant: Grant) -> Vec<u8> {
            signed_envelope(grant, &self.key, SSHSIG_NAMESPACE, None)
        }
    }

    fn ssh_tool(name: &str) -> PathBuf {
        for directory in ["/usr/bin", "/bin", "/usr/local/bin"] {
            let candidate = Path::new(directory).join(name);
            if candidate.is_file() {
                return candidate;
            }
        }
        panic!("required test tool {name} is not installed");
    }

    fn command_output(mut command: Command, action: &str) -> std::process::Output {
        let output = command
            .output()
            .unwrap_or_else(|error| panic!("{action}: {error}"));
        assert!(
            output.status.success(),
            "{action} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    fn generate_key(path: &Path) {
        let mut command = Command::new(ssh_tool("ssh-keygen"));
        command
            .env_clear()
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(path)
            .stdin(Stdio::null());
        command_output(command, "generate test signing key");
    }

    fn certify_key(ca: &Path, public_key: &Path, principals: &str) {
        let mut command = Command::new(ssh_tool("ssh-keygen"));
        command
            .env_clear()
            .args(["-q", "-s"])
            .arg(ca)
            .args(["-I", "syq-test", "-n", principals])
            .arg(public_key)
            .stdin(Stdio::null());
        command_output(command, "create test signing certificate");
    }

    fn write_private(path: &Path, contents: &[u8]) {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .expect("create private test file");
        file.write_all(contents).expect("write private test file");
        file.sync_all().expect("sync private test file");
    }

    fn provision_test_replay_directory(path: &Path) {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path)
            .expect("provision test replay directory");
    }

    fn write_allowed_signers(path: &Path, signer: &str, public_key: &Path, certificate: bool) {
        let public_key = fs::read_to_string(public_key).expect("read test public key");
        let authority = if certificate { "cert-authority," } else { "" };
        let line = format!(
            "{signer} {authority}namespaces=\"{SSHSIG_NAMESPACE}\" {}\n",
            public_key.trim()
        );
        write_private(path, line.as_bytes());
    }

    fn start_agent(directory: &TestDir) -> AgentGuard {
        let socket = directory.join("agent.sock");
        let mut child = Command::new(ssh_tool("ssh-agent"))
            .env_clear()
            .args(["-D", "-a"])
            .arg(&socket)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start test ssh-agent");
        for _ in 0..200 {
            if fs::symlink_metadata(&socket)
                .map(|metadata| metadata.file_type().is_socket())
                .unwrap_or(false)
            {
                return AgentGuard { child, socket };
            }
            thread::sleep(Duration::from_millis(10));
        }
        let _ = child.kill();
        let _ = child.wait();
        panic!("test ssh-agent did not create its socket");
    }

    fn add_to_agent(agent: &AgentGuard, key: &Path) {
        let mut command = Command::new(ssh_tool("ssh-add"));
        command
            .env_clear()
            .env("SSH_AUTH_SOCK", &agent.socket)
            .arg(key)
            .stdin(Stdio::null());
        command_output(command, "load test agent key");
    }

    fn sign(payload: &[u8], key: &Path, namespace: &str, agent: Option<&AgentGuard>) -> Vec<u8> {
        let mut command = Command::new(ssh_tool("ssh-keygen"));
        command
            .env_clear()
            .args(["-Y", "sign", "-f"])
            .arg(key)
            .args(["-n", namespace])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(agent) = agent {
            command.env("SSH_AUTH_SOCK", &agent.socket);
        }
        let mut child = command.spawn().expect("start test signer");
        child
            .stdin
            .take()
            .expect("signer stdin")
            .write_all(payload)
            .expect("write signing payload");
        let output = child.wait_with_output().expect("wait for test signer");
        assert!(
            output.status.success(),
            "sign test payload: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }

    fn fixture_grant(request_byte: u8) -> Grant {
        Grant {
            enrollment_id: EnrollmentId::test_v4(7),
            target_login: TARGET.to_owned(),
            signer: SIGNER.to_owned(),
            request_id: RequestId([request_byte; 32]),
            issued_at: NOW,
            not_before: NOW - 30,
            start_by: NOW + 600,
            finish_by: NOW + 900,
            operation: GrantOperation::Copy(CopyOperation {
                destination: b"/srv/archive/project".to_vec(),
                mutation_scopes: vec![MutationScope {
                    path: b"/srv/archive/project".to_vec(),
                    descendants: true,
                }],
                policy: CopyPolicy {
                    placement: DestinationPlacement::ExactPath,
                    existing: ExistingDestinationPolicy::Replace,
                    deletion: DeletionPolicy::Forbid,
                    publication: PublicationPolicy::AtomicStaged,
                },
                options: CopyOptions {
                    recursive: true,
                    preserve_symlinks: true,
                    preserve_permissions: true,
                    receiver_managed_modes: false,
                    preserve_times: true,
                    preserve_owner: false,
                    preserve_group: false,
                    preserve_devices: false,
                    compare_existing_by_content: true,
                    dry_run: false,
                    verify_only: true,
                    compressed_transport: false,
                    tcp_port_lo: 47_600,
                    tcp_port_hi: 47_699,
                },
                limits: CopyLimits {
                    max_entries: 10_000,
                    max_total_bytes: 1 << 30,
                    max_file_bytes: 1 << 29,
                    hash_block_bytes: 4 << 20,
                    max_connections: 8,
                    max_deletions: 0,
                },
            }),
        }
    }

    fn context<'a>(signer: &'a str, target: &'a str, now: i64, skew: i64) -> ReceiverContext<'a> {
        context_at(signer, target, now, skew, Instant::now())
    }

    fn context_at<'a>(
        signer: &'a str,
        target: &'a str,
        now: i64,
        skew: i64,
        observed_at: Instant,
    ) -> ReceiverContext<'a> {
        ReceiverContext {
            enrollment_id: EnrollmentId::test_v4(7),
            target_login: target,
            expected_signer: signer,
            clock: ClockObservation {
                unix_seconds: now,
                monotonic: observed_at,
            },
            clock_skew_seconds: skew,
        }
    }

    fn signed_envelope(
        grant: Grant,
        key: &Path,
        namespace: &str,
        agent: Option<&AgentGuard>,
    ) -> Vec<u8> {
        signed_envelope_with_rate(grant, 0, key, namespace, agent)
    }

    fn signed_envelope_with_rate(
        grant: Grant,
        max_file_data_bytes_per_second: u64,
        key: &Path,
        namespace: &str,
        agent: Option<&AgentGuard>,
    ) -> Vec<u8> {
        let payload = signing_payload_default(&grant, max_file_data_bytes_per_second)
            .expect("make signing payload");
        let signature = sign(&payload, key, namespace, agent);
        SignedGrantEnvelope::new(grant, max_file_data_bytes_per_second, signature)
            .encode()
            .expect("encode signed grant")
    }

    fn raw_envelope(grant: &Grant, signature: &[u8]) -> Vec<u8> {
        raw_envelope_with_rate(grant, 0, signature)
    }

    fn raw_envelope_with_rate(
        grant: &Grant,
        max_file_data_bytes_per_second: u64,
        signature: &[u8],
    ) -> Vec<u8> {
        let grant = canonical_body_bytes(
            grant,
            max_file_data_bytes_per_second,
            &FilterPolicy::default(),
            RootExistence::Any,
            &test_receipt_policy(),
        )
        .expect("encode test grant");
        let mut out = Vec::new();
        out.extend_from_slice(WIRE_MAGIC);
        out.extend_from_slice(&WIRE_VERSION.to_be_bytes());
        out.extend_from_slice(&(grant.len() as u32).to_be_bytes());
        out.extend_from_slice(&(signature.len() as u32).to_be_bytes());
        out.extend_from_slice(&grant);
        out.extend_from_slice(signature);
        out
    }

    #[test]
    fn canonical_typed_grant_round_trips_and_has_strict_bounds() {
        let fixture = Fixture::ordinary();
        let encoded = fixture.signed(fixture_grant(1));
        let decoded = SignedGrantEnvelope::decode(&encoded).expect("decode canonical grant");
        assert_eq!(decoded.grant, fixture_grant(1));
        assert_eq!(decoded.max_file_data_bytes_per_second, 0);
        let mut unsupported = encoded.clone();
        unsupported[8..10].copy_from_slice(&(WIRE_VERSION + 1).to_be_bytes());
        assert!(SignedGrantEnvelope::decode(&unsupported).is_err());
        let mut legacy = encoded.clone();
        legacy[8..10].copy_from_slice(&1u16.to_be_bytes());
        assert!(SignedGrantEnvelope::decode(&legacy).is_err());
        legacy[8..10].copy_from_slice(&2u16.to_be_bytes());
        assert!(SignedGrantEnvelope::decode(&legacy).is_err());

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(SignedGrantEnvelope::decode(&trailing).is_err());

        let mut relative = fixture_grant(2);
        let GrantOperation::Copy(copy) = &mut relative.operation;
        copy.destination = b"relative/path".to_vec();
        assert!(signing_payload_default(&relative, 0).is_err());

        let mut unbounded = fixture_grant(3);
        unbounded.start_by = unbounded.not_before + MAX_GRANT_VALIDITY_SECS + 1;
        unbounded.finish_by = unbounded.start_by;
        assert!(signing_payload_default(&unbounded, 0).is_err());

        let mut endless = fixture_grant(3);
        endless.finish_by = endless.issued_at + MAX_FINISH_WINDOW_SECS + 1;
        assert!(signing_payload_default(&endless, 0).is_err());

        let mut reversed = fixture_grant(3);
        reversed.finish_by = reversed.start_by - 1;
        assert!(signing_payload_default(&reversed, 0).is_err());

        let mut excessive = fixture_grant(4);
        let GrantOperation::Copy(copy) = &mut excessive.operation;
        copy.limits.max_connections = MAX_CONNECTIONS + 1;
        assert!(signing_payload_default(&excessive, 0).is_err());

        let mut excessive = fixture_grant(4);
        let GrantOperation::Copy(copy) = &mut excessive.operation;
        copy.limits.max_total_bytes = u64::MAX;
        assert!(signing_payload_default(&excessive, 0).is_err());
    }

    #[test]
    fn in_process_transport_key_signature_is_accepted_by_openssh() {
        let fixture = Fixture::ordinary();
        let keypair = ssh_key::private::Ed25519Keypair::from_seed(&[42; 32]);
        let private = PrivateKey::new(keypair.into(), "syq-test").unwrap();
        let public = private.public_key().to_openssh().unwrap();
        fs::write(&fixture.allowed_signers, format!("{SIGNER} {public}\n")).unwrap();
        let replay = fixture.replay("in-process-signature-replay");
        let encoded = sign_grant(fixture_grant(44), GrantConstraints::default(), &private).unwrap();
        SignedGrantEnvelope::decode(&encoded).unwrap();
        verify_and_claim(
            &encoded,
            &context(SIGNER, TARGET, NOW, 0),
            &fixture.policy(),
            &replay,
        )
        .expect("OpenSSH must accept the in-process SSHSIG");

        let rate_limited = sign_grant(
            fixture_grant(45),
            GrantConstraints {
                max_file_data_bytes_per_second: 4096,
                ..GrantConstraints::default()
            },
            &private,
        )
        .unwrap();
        let decoded = SignedGrantEnvelope::decode(&rate_limited).unwrap();
        assert_eq!(decoded.max_file_data_bytes_per_second, 4096);
        verify_and_claim(
            &rate_limited,
            &context(SIGNER, TARGET, NOW, 0),
            &fixture.policy(),
            &fixture.replay("in-process-rate-signature-replay"),
        )
        .expect("OpenSSH must accept the signed rate extension");

        let filters = FilterPolicy {
            ignore: vec!["*.tmp".into(), "!keep.tmp".into()],
            destination_roots: vec![b"/srv/archive/project".to_vec()],
            delete_excluded: false,
        };
        let filtered = sign_grant(
            fixture_grant(46),
            GrantConstraints {
                filters: filters.clone(),
                ..GrantConstraints::default()
            },
            &private,
        )
        .unwrap();
        let decoded = SignedGrantEnvelope::decode(&filtered).unwrap();
        assert_eq!(decoded.filters, filters);
        assert_eq!(decoded.root_existence, RootExistence::Any);
        let verified = verify_and_claim(
            &filtered,
            &context(SIGNER, TARGET, NOW, 0),
            &fixture.policy(),
            &fixture.replay("in-process-filter-signature-replay"),
        )
        .expect("OpenSSH must accept the signed filter extension");
        assert_eq!(verified.into_parts().1.filters, filters);

        let outside = FilterPolicy {
            ignore: vec!["*.tmp".into()],
            destination_roots: vec![b"/srv/outside".to_vec()],
            delete_excluded: false,
        };
        assert!(sign_grant(
            fixture_grant(47),
            GrantConstraints {
                filters: outside,
                ..GrantConstraints::default()
            },
            &private
        )
        .is_err());

        // A root-existence precondition survives verification unchanged.
        let rooted = sign_grant(
            fixture_grant(48),
            GrantConstraints {
                root_existence: RootExistence::New,
                ..GrantConstraints::default()
            },
            &private,
        )
        .unwrap();
        let decoded = SignedGrantEnvelope::decode(&rooted).unwrap();
        assert_eq!(decoded.root_existence, RootExistence::New);
        let verified = verify_and_claim(
            &rooted,
            &context(SIGNER, TARGET, NOW, 0),
            &fixture.policy(),
            &fixture.replay("in-process-root-existence-signature-replay"),
        )
        .expect("OpenSSH must accept the signed root-existence extension");
        assert_eq!(verified.into_parts().1.root_existence, RootExistence::New);

        // The grant binds the complete receipt delivery policy, including the
        // per-transfer HPKE recipient key, into the signed grant transcript.
        let policy_v2 = crate::receipt_v2::ReceiptPolicyV2 {
            required: true,
            hashed: true,
            max_records: 32,
            max_plaintext_bytes: 64 * 1024,
            delivery: crate::receipt_v2::ReceiptDeliveryV2::AttachedEncrypted {
                suite: crate::receipt_v2::HpkeSuiteV1::X25519HkdfSha256HkdfSha256ChaCha20Poly1305,
                recipient_public_key: [4; 32],
            },
        };
        let receipted_v2 = sign_grant(
            fixture_grant(53),
            GrantConstraints {
                receipt_v2: policy_v2.clone(),
                ..GrantConstraints::default()
            },
            &private,
        )
        .unwrap();
        let decoded = SignedGrantEnvelope::decode(&receipted_v2).unwrap();
        assert_eq!(
            u16::from_be_bytes(receipted_v2[8..10].try_into().unwrap()),
            WIRE_VERSION
        );
        assert_eq!(decoded.receipt_v2, policy_v2.clone());
        let expected_digest = signed_grant_digest(&receipted_v2).unwrap();
        let verified = verify_and_claim(
            &receipted_v2,
            &context(SIGNER, TARGET, NOW, 0),
            &fixture.policy(),
            &fixture.replay("in-process-receipt-v2-signature-replay"),
        )
        .expect("OpenSSH must accept the signed receipt v2 policy");
        let (_, extensions, digest, _) = verified.into_parts();
        assert_eq!(extensions.receipt_v2, policy_v2);
        assert_eq!(digest, expected_digest);
    }

    #[test]
    fn delete_excluded_filters_remain_valid_when_deletion_is_forbidden() {
        let grant = fixture_grant(50);
        let GrantOperation::Copy(copy) = &grant.operation;
        assert_eq!(copy.policy.deletion, DeletionPolicy::Forbid);
        let filters = FilterPolicy {
            ignore: vec!["*.tmp".into()],
            destination_roots: vec![b"/srv/archive/project".to_vec()],
            delete_excluded: true,
        };
        // The unfiltered-scan policy still matters for a dry run or a zero
        // deletion budget; the receiver's deletion policy refuses removals.
        filters.validate(&grant).unwrap();
    }

    #[test]
    fn malformed_and_noncanonical_sshsig_are_rejected() {
        let fixture = Fixture::ordinary();
        let grant = fixture_grant(5);
        let payload = signing_payload_default(&grant, 0).expect("payload");
        let signature = sign(&payload, &fixture.key, SSHSIG_NAMESPACE, None);

        let mut malformed = signature.clone();
        let body_start = malformed
            .iter()
            .position(|byte| *byte == b'\n')
            .expect("armor header newline")
            + 1;
        let position = malformed[body_start..]
            .iter()
            .position(|byte| byte.is_ascii_alphanumeric())
            .expect("base64 character")
            + body_start;
        malformed[position] = b'!';
        assert!(SignedGrantEnvelope::decode(&raw_envelope(&grant, &malformed)).is_err());

        let lines: Vec<&[u8]> = signature.split(|byte| *byte == b'\n').collect();
        let mut encoded = Vec::new();
        for line in &lines[1..lines.len() - 2] {
            encoded.extend_from_slice(line);
        }
        let mut rewrapped = b"-----BEGIN SSH SIGNATURE-----\n".to_vec();
        for chunk in encoded.chunks(64) {
            rewrapped.extend_from_slice(chunk);
            rewrapped.push(b'\n');
        }
        rewrapped.extend_from_slice(b"-----END SSH SIGNATURE-----\n");
        assert!(SignedGrantEnvelope::decode(&raw_envelope(&grant, &rewrapped)).is_err());
    }

    #[test]
    fn verifies_ordinary_key_and_binds_every_typed_field() {
        let fixture = Fixture::ordinary();
        let replay = fixture.replay("replay");
        let encoded = fixture.signed(fixture_grant(6));
        verify_and_claim(
            &encoded,
            &context(SIGNER, TARGET, NOW, 0),
            &fixture.policy(),
            &replay,
        )
        .expect("verify signed request");

        let original = SignedGrantEnvelope::decode(&fixture.signed(fixture_grant(7)))
            .expect("decode signed request");
        let mut altered = original.grant;
        let GrantOperation::Copy(copy) = &mut altered.operation;
        copy.options.verify_only = false;
        let tampered = raw_envelope(&altered, &original.signature);
        assert!(verify_and_claim(
            &tampered,
            &context(SIGNER, TARGET, NOW, 0),
            &fixture.policy(),
            &fixture.replay("tamper-replay"),
        )
        .is_err());

        let rate_grant = fixture_grant(29);
        let rate_limited = signed_envelope_with_rate(
            rate_grant.clone(),
            4096,
            &fixture.key,
            SSHSIG_NAMESPACE,
            None,
        );
        let decoded =
            SignedGrantEnvelope::decode(&rate_limited).expect("decode rate-limited grant");
        assert_eq!(decoded.max_file_data_bytes_per_second, 4096);
        let tampered_rate = raw_envelope_with_rate(&rate_grant, 8192, &decoded.signature);
        assert!(verify_and_claim(
            &tampered_rate,
            &context(SIGNER, TARGET, NOW, 0),
            &fixture.policy(),
            &fixture.replay("rate-tamper-replay"),
        )
        .is_err());
    }

    #[test]
    fn rejects_wrong_namespace_signer_target_and_enrollment_without_claiming() {
        let fixture = Fixture::ordinary();
        let grant = fixture_grant(8);
        let wrong_namespace = signed_envelope(
            grant.clone(),
            &fixture.key,
            "other-protocol@example.test",
            None,
        );
        let replay = fixture.replay("binding-replay");
        assert!(verify_and_claim(
            &wrong_namespace,
            &context(SIGNER, TARGET, NOW, 0),
            &fixture.policy(),
            &replay,
        )
        .is_err());

        let encoded = fixture.signed(grant.clone());
        assert!(verify_and_claim(
            &encoded,
            &context("mallory@example.test", TARGET, NOW, 0),
            &fixture.policy(),
            &replay,
        )
        .is_err());
        let mut unlisted_signer = grant.clone();
        unlisted_signer.signer = "mallory@example.test".to_owned();
        let unlisted_signer = fixture.signed(unlisted_signer);
        assert!(verify_and_claim(
            &unlisted_signer,
            &context("mallory@example.test", TARGET, NOW, 0),
            &fixture.policy(),
            &replay,
        )
        .is_err());
        assert!(verify_and_claim(
            &encoded,
            &context(SIGNER, "root", NOW, 0),
            &fixture.policy(),
            &replay,
        )
        .is_err());
        let mut wrong_enrollment = context(SIGNER, TARGET, NOW, 0);
        wrong_enrollment.enrollment_id = EnrollmentId::test_v4(9);
        assert!(verify_and_claim(&encoded, &wrong_enrollment, &fixture.policy(), &replay).is_err());
        verify_and_claim(
            &encoded,
            &context(SIGNER, TARGET, NOW, 0),
            &fixture.policy(),
            &replay,
        )
        .expect("failed binding checks must not consume request");
    }

    #[test]
    fn expiry_and_not_before_honor_only_bounded_clock_skew() {
        let fixture = Fixture::ordinary();
        let encoded = fixture.signed(fixture_grant(9));
        let replay = fixture.replay("expired-replay");
        assert!(verify_and_claim(
            &encoded,
            &context(SIGNER, TARGET, NOW + 620, 10),
            &fixture.policy(),
            &replay,
        )
        .is_err());
        verify_and_claim(
            &encoded,
            &context(SIGNER, TARGET, NOW + 590, 10),
            &fixture.policy(),
            &replay,
        )
        .expect("expiry inside clock-skew allowance");

        let mut future = fixture_grant(10);
        future.issued_at = NOW + 100;
        future.not_before = NOW + 100;
        future.start_by = NOW + 400;
        let encoded = fixture.signed(future);
        let replay = fixture.replay("future-replay");
        assert!(verify_and_claim(
            &encoded,
            &context(SIGNER, TARGET, NOW, 90),
            &fixture.policy(),
            &replay,
        )
        .is_err());
        verify_and_claim(
            &encoded,
            &context(SIGNER, TARGET, NOW + 50, 60),
            &fixture.policy(),
            &replay,
        )
        .expect("not-before inside clock-skew allowance");
        let invalid_skew = context(SIGNER, TARGET, NOW, MAX_CLOCK_SKEW_SECS + 1);
        assert!(invalid_skew
            .validate_at(&fixture_grant(11), invalid_skew.clock.monotonic)
            .is_err());
    }

    #[test]
    fn execution_deadline_is_monotonic_and_bounded_by_finish_by() {
        let started = Instant::now();
        let verified = started + Duration::from_secs(3);

        let mut bounded = fixture_grant(17);
        bounded.finish_by = NOW + 20;
        assert_eq!(
            execution_deadline(&bounded, 5, NOW + 3, verified).expect("finish-by deadline"),
            verified + Duration::from_secs(22)
        );

        let partially_elapsed = started + Duration::from_millis(1100);
        let mut rounded = fixture_grant(19);
        rounded.finish_by = NOW + 5;
        assert_eq!(
            execution_deadline(&rounded, 0, NOW + 2, partially_elapsed)
                .expect("subsecond verification is rounded conservatively"),
            partially_elapsed + Duration::from_secs(3)
        );

        let mut finished = fixture_grant(20);
        finished.finish_by = NOW + 1;
        assert!(
            execution_deadline(&finished, 0, NOW + 2, started + Duration::from_secs(2),).is_err()
        );
    }

    #[test]
    fn queued_clock_observation_advances_validation_claim_and_deadline() {
        let fixture = Fixture::ordinary();
        let replay = fixture.replay("paired-clock-replay");
        let observed_at = Instant::now()
            .checked_sub(Duration::from_secs(3))
            .expect("monotonic observation in the recent past");
        let context = context_at(SIGNER, TARGET, NOW, 0, observed_at);
        assert!(
            context
                .wall_time_at(Instant::now())
                .expect("adjust wall time")
                >= NOW + 3
        );

        let encoded = fixture.signed(fixture_grant(22));
        let verified = verify_and_claim(&encoded, &context, &fixture.policy(), &replay)
            .expect("verify with a queued but still-valid clock observation");
        assert!(verified.execution_deadline() <= Instant::now() + Duration::from_secs(900));
        let claim = fs::read(
            replay
                .path
                .join(format!("claim-{}", RequestId([22; 32]).file_component())),
        )
        .expect("read adjusted replay claim");
        let claimed_at = i64::from_be_bytes(claim[10..18].try_into().expect("claim timestamp"));
        assert!(claimed_at >= NOW + 3);

        let mut expired = fixture_grant(23);
        expired.start_by = NOW + 2;
        expired.finish_by = NOW + 2;
        let encoded = fixture.signed(expired);
        let expired_replay = fixture.replay("queued-expired-replay");
        assert!(verify_and_claim(&encoded, &context, &fixture.policy(), &expired_replay).is_err());
        assert!(!expired_replay
            .path
            .join(format!("claim-{}", RequestId([23; 32]).file_component()))
            .exists());
    }

    #[test]
    fn duplicate_and_concurrent_redemption_allow_exactly_one_claim() {
        let fixture = Fixture::ordinary();
        let encoded = Arc::new(fixture.signed(fixture_grant(12)));
        let replay = fixture.replay("concurrent-replay");
        let policy = fixture.policy();
        let barrier = Arc::new(Barrier::new(8));
        let mut threads = Vec::new();
        for _ in 0..8 {
            let encoded = Arc::clone(&encoded);
            let replay = replay.clone();
            let policy = policy.clone();
            let barrier = Arc::clone(&barrier);
            threads.push(thread::spawn(move || {
                barrier.wait();
                verify_and_claim(&encoded, &context(SIGNER, TARGET, NOW, 0), &policy, &replay)
            }));
        }
        let results: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().expect("redemption thread"))
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        let failures: Vec<_> = results.into_iter().filter_map(Result::err).collect();
        assert_eq!(failures.len(), 7);
        assert!(
            failures.iter().all(|error| error
                .to_string()
                .contains("signed request has already been redeemed")),
            "{failures:?}"
        );
        let mut no_verifier = fixture.policy();
        no_verifier.ssh_keygen = PathBuf::from("/missing/verifier-must-not-run");
        let error = verify_and_claim(
            &encoded,
            &context(SIGNER, TARGET, NOW, 0),
            &no_verifier,
            &replay,
        )
        .expect_err("duplicate request must fail");
        assert!(error
            .to_string()
            .contains("signed request has already been redeemed"));
    }

    #[test]
    fn replay_claim_survives_reopen_ignores_stale_temp_and_fails_closed_on_corruption() {
        let directory = TestDir::new("replay-disk");
        let state = directory.join("state");
        let first = RequestId([13; 32]);
        let first_digest = [0x31; 32];
        provision_test_replay_directory(&state);
        let store = ReplayStore::open(&state).expect("open replay store");
        store.claim(first, first_digest, NOW).expect("first claim");
        drop(store);

        let record_path = state.join(format!("claim-{}", first.file_component()));
        let metadata = fs::metadata(&record_path).expect("claim record metadata");
        assert_eq!(metadata.len() as usize, CLAIM_RECORD_LEN);
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

        write_private(&state.join(".claim-crash-residue.tmp"), b"partial");
        let reopened = ReplayStore::open(&state).expect("reopen replay store");
        assert!(reopened.claim(first, first_digest, NOW + 1).is_err());
        assert!(reopened.claim(first, [0xff; 32], NOW + 1).is_err());
        reopened
            .claim(RequestId([14; 32]), [0x32; 32], NOW + 1)
            .expect("stale unpublished temp cannot block another claim");

        let corrupt = RequestId([15; 32]);
        write_private(
            &state.join(format!("claim-{}", corrupt.file_component())),
            b"partial",
        );
        assert!(reopened.claim(corrupt, [0x33; 32], NOW + 2).is_err());
    }

    #[test]
    fn verifier_snapshots_remain_pinned_when_the_state_path_is_replaced() {
        let directory = TestDir::new("pinned-snapshot");
        let state = directory.join("state");
        let relocated = directory.join("relocated-state");
        provision_test_replay_directory(&state);
        let store = ReplayStore::open(&state).expect("open replay store");
        fs::rename(&state, &relocated).expect("relocate open replay directory");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&state)
            .expect("replace replay pathname");

        let temporary = store
            .temporary_file("policy", b"pinned policy contents")
            .expect("create pinned verifier snapshot");
        let name = temporary.name.clone();
        assert!(relocated.join(&name).is_file());
        assert!(!state.join(&name).exists());
        assert!(temporary
            .is_read_only()
            .expect("inspect snapshot access mode"));
        assert!(temporary
            .is_close_on_exec()
            .expect("inspect snapshot descriptor flags"));
        let byte = [0u8];
        assert_eq!(
            unsafe { libc::write(temporary.file.as_raw_fd(), byte.as_ptr().cast(), byte.len(),) },
            -1,
            "the verifier snapshot itself must not be writable"
        );
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
        let reserved = VerifierSnapshotFd::reserve(&temporary, 64)
            .expect("reserve child-only verifier descriptor");
        assert!(reserved
            .is_close_on_exec()
            .expect("inspect reserved descriptor flags"));
        assert!(descriptor_is_read_only(reserved.child.as_raw_fd())
            .expect("inspect reserved access mode"));
        assert_eq!(
            fs::read(format!("/dev/fd/{}", temporary.file.as_raw_fd()))
                .expect("read snapshot descriptor"),
            b"pinned policy contents"
        );

        drop(temporary);
        assert!(!relocated.join(name).exists());
    }

    #[test]
    fn replay_store_checks_the_final_private_directory_not_its_ancestors() {
        let directory = TestDir::new("replay-security");
        let missing = directory.join("missing-state");
        assert!(ReplayStore::open(&missing).is_err());
        assert!(
            !missing.exists(),
            "request handling must not provision state"
        );

        let public = directory.join("public-state");
        fs::DirBuilder::new()
            .mode(0o755)
            .create(&public)
            .expect("create public state directory");
        assert!(ReplayStore::open(&public).is_err());

        let private = directory.join("private-state");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&private)
            .expect("create private state directory");
        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o777))
            .expect("make the non-secret ancestor broadly writable");
        let dotted = PathBuf::from(format!("{}/./private-state", directory.0.display()));
        ReplayStore::open(&dotted).expect("ancestor permissions do not reject private state");
        let link = directory.join("state-link");
        std::os::unix::fs::symlink(&private, &link).expect("create state symlink");
        assert!(ReplayStore::open(&link).is_err());
    }

    #[test]
    fn replay_store_accepts_a_setgid_private_directory() {
        let directory = TestDir::new("setgid-private");
        let state = directory.join("state");
        provision_test_replay_directory(&state);
        fs::set_permissions(&state, fs::Permissions::from_mode(0o2700))
            .expect("set setgid on private state directory");
        assert_eq!(fs::metadata(&state).unwrap().mode() & 0o2000, 0o2000);

        ReplayStore::open(&state).expect("setgid does not grant another principal access");
    }

    #[test]
    fn verifier_and_policy_checks_are_structural_not_ownership_walks() {
        let directory = TestDir::new("structural-policy");
        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o777)).unwrap();

        let verifier = directory.join("ssh-keygen");
        fs::write(&verifier, b"test executable").unwrap();
        fs::set_permissions(&verifier, fs::Permissions::from_mode(0o777)).unwrap();
        validate_regular_executable(&verifier, "test verifier")
            .expect("writable permissions do not reject a trusted receiver executable");
        fs::set_permissions(&verifier, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(validate_regular_executable(&verifier, "test verifier").is_err());

        let policy = directory.join("allowed-signers");
        fs::write(&policy, b"signer ssh-ed25519 test\n").unwrap();
        fs::set_permissions(&policy, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            read_private_regular(&policy, "test policy", 1024).unwrap(),
            b"signer ssh-ed25519 test\n"
        );
        fs::set_permissions(&policy, fs::Permissions::from_mode(0o660)).unwrap();
        assert!(read_private_regular(&policy, "test policy", 1024).is_err());
        assert!(read_private_regular(&directory.0, "test policy", 1024).is_err());
    }

    #[test]
    fn request_ids_are_fresh_and_distinct_from_stable_copy_ids() {
        let first = RequestId::fresh(NOW).expect("fresh request ID");
        let second = RequestId::fresh(NOW).expect("fresh request ID");
        assert_ne!(first, second);
        assert_eq!(std::mem::size_of::<RequestId>(), 32);
        assert_eq!(std::mem::size_of::<crate::proto::PartialId>(), 16);
    }

    #[test]
    fn timestamped_request_ids_sort_chronologically_and_stay_unique() {
        let earlier = RequestId::fresh(NOW).expect("fresh request ID");
        let later = RequestId::fresh(NOW + 1).expect("fresh request ID");
        assert_eq!(earlier.0[..8], u64::try_from(NOW).unwrap().to_be_bytes());
        // Hex filenames of big-endian timestamps sort lexicographically in
        // time order, so claim listings are naturally chronological.
        assert!(earlier.file_component() < later.file_component());
        // Same second, distinct nonces: the 24 random bytes carry uniqueness.
        let sibling = RequestId::fresh(NOW).expect("fresh request ID");
        assert_ne!(earlier, sibling);
        assert_eq!(earlier.0[..8], sibling.0[..8]);
        earlier.validate().expect("timestamped IDs validate");
        // Pre-epoch issue times are refused rather than wrapped.
        assert!(RequestId::fresh(-1).is_err());
    }

    #[test]
    fn verifier_timeout_kills_its_process_group() {
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "sleep 30"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn().expect("start stalled verifier fixture");
        let started = Instant::now();
        let error = wait_for_verifier(child, b"test", Duration::from_millis(50))
            .expect_err("stalled verifier must time out");
        assert!(error.to_string().contains("timeout"));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn rejects_a_key_authorized_only_for_another_principal() {
        let directory = TestDir::new("wrong-principal-key");
        let key = directory.join("mallory");
        generate_key(&key);
        let allowed_signers = directory.join("allowed-signers");
        write_allowed_signers(&allowed_signers, MALLORY, &key.with_extension("pub"), false);
        let encoded = signed_envelope(fixture_grant(24), &key, SSHSIG_NAMESPACE, None);
        let replay_path = directory.join("replay");
        provision_test_replay_directory(&replay_path);
        let replay = ReplayStore::open(&replay_path).expect("open replay store");
        let policy = SshsigPolicy {
            ssh_keygen: ssh_tool("ssh-keygen"),
            allowed_signers,
            revocation_file: None,
        };

        let error = verify_and_claim(&encoded, &context(SIGNER, TARGET, NOW, 0), &policy, &replay)
            .expect_err("a key listed only for another principal must fail");
        assert!(error.to_string().starts_with("SSHSIG verification failed"));
    }

    #[test]
    fn revocation_survives_replay_path_replacement() {
        let fixture = Fixture::ordinary();
        let revocations = fixture.directory.join("revocations");
        let public_key =
            fs::read(fixture.key.with_extension("pub")).expect("read revoked test public key");
        write_private(&revocations, &public_key);
        let mut policy = fixture.policy();
        policy.revocation_file = Some(revocations);
        let replay = fixture.replay("replaced-replay");
        // Move the opened store aside and put a fresh, empty store at its
        // old path. The verifier must keep using the retained directory.
        let moved = fixture.directory.join("replaced-replay-moved");
        fs::rename(&replay.path, &moved).expect("move replay directory");
        provision_test_replay_directory(&replay.path);
        let error = verify_and_claim(
            &fixture.signed(fixture_grant(26)),
            &context(SIGNER, TARGET, NOW, 0),
            &policy,
            &replay,
        )
        .expect_err("a revoked signer must fail after its store path is replaced");
        assert!(
            error.to_string().starts_with("SSHSIG verification failed"),
            "{error:#}"
        );
        assert!(fs::read_dir(&replay.path).unwrap().next().is_none());
    }

    #[test]
    fn rejects_a_revoked_signing_key() {
        let fixture = Fixture::ordinary();
        let revocations = fixture.directory.join("revocations");
        let public_key =
            fs::read(fixture.key.with_extension("pub")).expect("read revoked test public key");
        write_private(&revocations, &public_key);
        let mut policy = fixture.policy();
        policy.revocation_file = Some(revocations);
        let replay = fixture.replay("revoked-replay");

        let error = verify_and_claim(
            &fixture.signed(fixture_grant(25)),
            &context(SIGNER, TARGET, NOW, 0),
            &policy,
            &replay,
        )
        .expect_err("a revoked signer must fail");
        assert!(error.to_string().starts_with("SSHSIG verification failed"));
    }

    #[test]
    fn verifies_certificate_signature_against_allowed_ca() {
        let directory = TestDir::new("certificate");
        let ca = directory.join("ca");
        let user = directory.join("user");
        generate_key(&ca);
        generate_key(&user);
        certify_key(&ca, &user.with_extension("pub"), SIGNER);

        let agent = start_agent(&directory);
        add_to_agent(&agent, &user);
        let allowed_signers = directory.join("allowed-signers");
        write_allowed_signers(&allowed_signers, SIGNER, &ca.with_extension("pub"), true);
        let grant = fixture_grant(16);
        let encoded = signed_envelope(
            grant,
            &directory.join("user-cert.pub"),
            SSHSIG_NAMESPACE,
            Some(&agent),
        );
        let replay_path = directory.join("replay");
        provision_test_replay_directory(&replay_path);
        let replay = ReplayStore::open(&replay_path).expect("open replay store");
        let policy = SshsigPolicy {
            ssh_keygen: ssh_tool("ssh-keygen"),
            allowed_signers,
            revocation_file: None,
        };
        verify_and_claim(&encoded, &context(SIGNER, TARGET, NOW, 0), &policy, &replay)
            .expect("verify SSH certificate signature through allowed CA");
    }

    #[test]
    fn rejects_certificate_without_the_expected_principal() {
        let directory = TestDir::new("certificate-principal");
        let ca = directory.join("ca");
        let user = directory.join("user");
        generate_key(&ca);
        generate_key(&user);
        certify_key(&ca, &user.with_extension("pub"), MALLORY);

        let agent = start_agent(&directory);
        add_to_agent(&agent, &user);
        let allowed_signers = directory.join("allowed-signers");
        write_allowed_signers(&allowed_signers, SIGNER, &ca.with_extension("pub"), true);
        let encoded = signed_envelope(
            fixture_grant(26),
            &directory.join("user-cert.pub"),
            SSHSIG_NAMESPACE,
            Some(&agent),
        );
        let replay_path = directory.join("replay");
        provision_test_replay_directory(&replay_path);
        let replay = ReplayStore::open(&replay_path).expect("open replay store");
        let policy = SshsigPolicy {
            ssh_keygen: ssh_tool("ssh-keygen"),
            allowed_signers,
            revocation_file: None,
        };

        let error = verify_and_claim(&encoded, &context(SIGNER, TARGET, NOW, 0), &policy, &replay)
            .expect_err("a certificate without the expected principal must fail");
        assert!(error.to_string().starts_with("SSHSIG verification failed"));
    }

    #[test]
    fn rejects_certificate_when_ca_is_not_marked_as_an_authority() {
        let directory = TestDir::new("certificate-not-ca");
        let ca = directory.join("ca");
        let user = directory.join("user");
        generate_key(&ca);
        generate_key(&user);
        certify_key(&ca, &user.with_extension("pub"), SIGNER);

        let agent = start_agent(&directory);
        add_to_agent(&agent, &user);
        let allowed_signers = directory.join("allowed-signers");
        write_allowed_signers(&allowed_signers, SIGNER, &ca.with_extension("pub"), false);
        let encoded = signed_envelope(
            fixture_grant(27),
            &directory.join("user-cert.pub"),
            SSHSIG_NAMESPACE,
            Some(&agent),
        );
        let replay_path = directory.join("replay");
        provision_test_replay_directory(&replay_path);
        let replay = ReplayStore::open(&replay_path).expect("open replay store");
        let policy = SshsigPolicy {
            ssh_keygen: ssh_tool("ssh-keygen"),
            allowed_signers,
            revocation_file: None,
        };

        let error = verify_and_claim(&encoded, &context(SIGNER, TARGET, NOW, 0), &policy, &replay)
            .expect_err("a certificate signed by a non-authority entry must fail");
        assert!(error.to_string().starts_with("SSHSIG verification failed"));
    }
}

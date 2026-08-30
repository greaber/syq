//! Experimental signed receiver authorization core.
//!
//! Nothing in this module is reachable from the CLI or `--server`. In
//! particular, successfully verifying and claiming a grant does not authorize
//! a filesystem request. The future receiver entrypoint must integrate
//! root-anchored path confinement before it may consume `VerifiedGrant`.
//!
//! The wire representation deliberately signs a typed, canonical binary grant
//! rather than a command line. The signature is an OpenSSH SSHSIG in the fixed
//! [`SSHSIG_NAMESPACE`], verified by OpenSSH against an explicit allowed-signers
//! policy. A fresh random [`RequestId`] is a replay nonce; it is a separate type
//! and size from the stable copy/checkpoint IDs in `proto`.

// This module is intentionally unreachable until path confinement is ready.
// Keep the complete core compiled in normal builds without pretending its
// currently-private entry points are production dead code.
#![allow(dead_code)]

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

pub(crate) const SSHSIG_NAMESPACE: &str = "syq-grant-v1@greaber.github";
const WIRE_MAGIC: &[u8; 8] = b"SYQGRNT\0";
const WIRE_VERSION: u16 = 1;
const WIRE_HEADER_LEN: usize = WIRE_MAGIC.len() + 2 + 4 + 4;
const MAX_GRANT_BYTES: usize = 32 * 1024;
const MAX_SIGNATURE_BYTES: usize = 16 * 1024;
const MAX_ENVELOPE_BYTES: usize = WIRE_HEADER_LEN + MAX_GRANT_BYTES + MAX_SIGNATURE_BYTES;
const MAX_POLICY_BYTES: usize = 1024 * 1024;
const MAX_REVOCATION_BYTES: usize = 4 * 1024 * 1024;
const MAX_PATH_BYTES: usize = 4096;
const MAX_LOGIN_BYTES: usize = 256;
const MAX_SIGNER_BYTES: usize = 512;
const MAX_GRANT_VALIDITY_SECS: i64 = 24 * 60 * 60;
const MAX_CLOCK_SKEW_SECS: i64 = 5 * 60;
const MAX_UNIX_TIMESTAMP: i64 = 253_402_300_799; // 9999-12-31T23:59:59Z
const MAX_ENTRIES: u64 = 1_000_000_000_000;
// Keep later accounting representable in both signed and unsigned counters.
const MAX_COPY_BYTES: u64 = i64::MAX as u64;
const MAX_CONNECTIONS: u16 = 64;
const CLAIM_MAGIC: &[u8; 8] = b"SYQCLM\0\0";
const CLAIM_VERSION: u16 = 1;
const CLAIM_RECORD_LEN: usize = CLAIM_MAGIC.len() + 2 + 8 + 32 + 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EnrollmentId([u8; 16]);

impl EnrollmentId {
    #[cfg(test)]
    fn test_v4(last: u8) -> Self {
        let mut bytes = [0u8; 16];
        bytes[6] = 0x40;
        bytes[8] = 0x80;
        bytes[15] = last;
        Self(bytes)
    }

    fn validate(self) -> Result<()> {
        let version = self.0[6] >> 4;
        if self.0[8] & 0xc0 != 0x80 || !(1..=8).contains(&version) {
            bail!("enrollment ID is not an RFC 4122 UUID");
        }
        Ok(())
    }
}

/// A one-redemption nonce generated independently for every signed request.
/// It is intentionally not constructible from `proto::PartialId`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) struct RequestId([u8; 32]);

impl RequestId {
    pub(crate) fn random() -> Result<Self> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).context("generate signed-request ID")?;
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
pub(crate) enum GrantOperationV1 {
    Copy(CopyOperationV1),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CopyOperationV1 {
    /// Canonically spelled absolute target path. This is only a signed name;
    /// future authorization must resolve it beneath the enrolled root handle.
    pub destination: Vec<u8>,
    pub policy: CopyPolicyV1,
    pub options: CopyOptionsV1,
    pub limits: CopyLimitsV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CopyPolicyV1 {
    pub placement: DestinationPlacementV1,
    pub existing: ExistingDestinationPolicyV1,
    pub deletion: DeletionPolicyV1,
    pub publication: PublicationPolicyV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum DestinationPlacementV1 {
    ExactPath,
    DirectoryContents,
    DirectoryAsChild,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum ExistingDestinationPolicyV1 {
    Replace,
    Skip,
    UpdateIfOlder,
    MustExist,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum DeletionPolicyV1 {
    Forbid,
    DeleteDestinationOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum PublicationPolicyV1 {
    AtomicStaged,
    InPlace,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CopyOptionsV1 {
    pub recursive: bool,
    pub preserve_symlinks: bool,
    pub preserve_permissions: bool,
    pub preserve_times: bool,
    pub preserve_owner: bool,
    pub preserve_group: bool,
    pub preserve_devices: bool,
    pub compare_existing_by_content: bool,
    pub verify_after_copy: bool,
    pub compressed_transport: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CopyLimitsV1 {
    pub max_entries: u64,
    pub max_total_bytes: u64,
    pub max_file_bytes: u64,
    pub max_connections: u16,
    pub max_deletions: u64,
    pub max_runtime_seconds: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct GrantV1 {
    pub enrollment_id: EnrollmentId,
    pub target_login: String,
    pub signer: String,
    pub request_id: RequestId,
    pub issued_at: i64,
    pub not_before: i64,
    pub not_after: i64,
    pub operation: GrantOperationV1,
}

impl GrantV1 {
    fn validate_static(&self) -> Result<()> {
        self.enrollment_id.validate()?;
        self.request_id.validate()?;
        validate_identity("target login", &self.target_login, MAX_LOGIN_BYTES, false)?;
        validate_identity("signer", &self.signer, MAX_SIGNER_BYTES, true)?;

        for (name, value) in [
            ("issued-at", self.issued_at),
            ("not-before", self.not_before),
            ("not-after", self.not_after),
        ] {
            if !(0..=MAX_UNIX_TIMESTAMP).contains(&value) {
                bail!("grant {name} timestamp is out of range");
            }
        }
        if self.not_before > self.issued_at || self.issued_at > self.not_after {
            bail!("grant times must satisfy not-before <= issued-at <= not-after");
        }
        let validity = self
            .not_after
            .checked_sub(self.not_before)
            .ok_or_else(|| anyhow!("grant validity interval overflow"))?;
        if validity == 0 || validity > MAX_GRANT_VALIDITY_SECS {
            bail!("grant validity must be between 1 second and 24 hours");
        }

        match &self.operation {
            GrantOperationV1::Copy(copy) => copy.validate(validity),
        }
    }
}

impl CopyOperationV1 {
    fn validate(&self, validity: i64) -> Result<()> {
        validate_absolute_path(&self.destination)?;
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
        if limits.max_connections == 0 || limits.max_connections > MAX_CONNECTIONS {
            bail!("copy max-connections is outside the supported range");
        }
        if limits.max_runtime_seconds == 0 || i64::from(limits.max_runtime_seconds) > validity {
            bail!("copy max-runtime exceeds the signed validity interval");
        }
        match self.policy.deletion {
            DeletionPolicyV1::Forbid if limits.max_deletions != 0 => {
                bail!("copy forbids deletion but has a nonzero deletion limit")
            }
            DeletionPolicyV1::DeleteDestinationOnly
                if limits.max_deletions == 0 || limits.max_deletions > limits.max_entries =>
            {
                bail!("copy deletion limit is outside the supported range")
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SignedGrantEnvelopeV1 {
    pub grant: GrantV1,
    /// Canonical OpenSSH armored SSHSIG bytes.
    pub signature: Vec<u8>,
}

impl SignedGrantEnvelopeV1 {
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        self.grant.validate_static()?;
        validate_canonical_sshsig(&self.signature)?;
        let grant = canonical_grant_bytes(&self.grant)?;
        if grant.len() > MAX_GRANT_BYTES {
            bail!("canonical grant exceeds {MAX_GRANT_BYTES} bytes");
        }
        if self.signature.len() > MAX_SIGNATURE_BYTES {
            bail!("SSHSIG exceeds {MAX_SIGNATURE_BYTES} bytes");
        }
        let mut out = Vec::with_capacity(WIRE_HEADER_LEN + grant.len() + self.signature.len());
        out.extend_from_slice(WIRE_MAGIC);
        out.extend_from_slice(&WIRE_VERSION.to_be_bytes());
        out.extend_from_slice(&(grant.len() as u32).to_be_bytes());
        out.extend_from_slice(&(self.signature.len() as u32).to_be_bytes());
        out.extend_from_slice(&grant);
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
        let grant_bytes = &bytes[WIRE_HEADER_LEN..WIRE_HEADER_LEN + grant_len];
        let grant: GrantV1 = postcard::from_bytes(grant_bytes).context("decode signed grant")?;
        if canonical_grant_bytes(&grant)? != grant_bytes {
            bail!("signed grant uses a noncanonical encoding");
        }
        grant.validate_static()?;
        let signature = bytes[WIRE_HEADER_LEN + grant_len..].to_vec();
        validate_canonical_sshsig(&signature)?;
        Ok(Self { grant, signature })
    }

    fn signing_payload(&self) -> Result<Vec<u8>> {
        signing_payload(&self.grant)
    }
}

fn signing_payload(grant: &GrantV1) -> Result<Vec<u8>> {
    grant.validate_static()?;
    let grant = canonical_grant_bytes(grant)?;
    if grant.len() > MAX_GRANT_BYTES {
        bail!("canonical grant exceeds {MAX_GRANT_BYTES} bytes");
    }
    let mut out = Vec::with_capacity(WIRE_MAGIC.len() + 2 + 4 + grant.len());
    out.extend_from_slice(WIRE_MAGIC);
    out.extend_from_slice(&WIRE_VERSION.to_be_bytes());
    out.extend_from_slice(&(grant.len() as u32).to_be_bytes());
    out.extend_from_slice(&grant);
    Ok(out)
}

fn canonical_grant_bytes(grant: &GrantV1) -> Result<Vec<u8>> {
    postcard::to_stdvec(grant).context("encode canonical signed grant")
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

pub(crate) struct ReceiverContext<'a> {
    pub enrollment_id: EnrollmentId,
    pub target_login: &'a str,
    pub expected_signer: &'a str,
    pub now: i64,
    pub clock_skew_seconds: i64,
}

impl ReceiverContext<'_> {
    fn validate(&self, grant: &GrantV1) -> Result<()> {
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
        if !(0..=MAX_UNIX_TIMESTAMP).contains(&self.now) {
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
        let latest_acceptable_issue = self
            .now
            .checked_add(self.clock_skew_seconds)
            .ok_or_else(|| anyhow!("receiver time overflow"))?;
        if grant.issued_at > latest_acceptable_issue {
            bail!("grant was issued too far in the future");
        }
        let latest_for_start = self
            .now
            .checked_add(self.clock_skew_seconds)
            .ok_or_else(|| anyhow!("receiver time overflow"))?;
        if latest_for_start < grant.not_before {
            bail!("grant is not yet valid");
        }
        let earliest_for_expiry = self
            .now
            .checked_sub(self.clock_skew_seconds)
            .ok_or_else(|| anyhow!("receiver time overflow"))?;
        if earliest_for_expiry > grant.not_after {
            bail!("grant has expired");
        }
        Ok(())
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
        validate_secure_executable(&self.ssh_keygen)?;
        let allowed = read_secure_regular(
            &self.allowed_signers,
            "allowed-signers policy",
            MAX_POLICY_BYTES,
        )?;
        let revocation = self
            .revocation_file
            .as_ref()
            .map(|path| read_secure_regular(path, "SSHSIG revocation policy", MAX_REVOCATION_BYTES))
            .transpose()?;
        let signature_file = store.temporary_file("signature", signature)?;
        let allowed_file = store.temporary_file("allowed-signers", &allowed)?;
        let revocation_file = revocation
            .as_deref()
            .map(|contents| store.temporary_file("revocations", contents))
            .transpose()?;

        let mut command = Command::new(&self.ssh_keygen);
        command
            .env_clear()
            .args(["-Y", "verify", "-f"])
            .arg(allowed_file.path())
            .args(["-I", signer, "-n", SSHSIG_NAMESPACE, "-s"])
            .arg(signature_file.path());
        if let Some(revocation) = &revocation_file {
            command.arg("-r").arg(revocation.path());
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("start trusted ssh-keygen SSHSIG verifier")?;
        let write_result = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("SSHSIG verifier stdin unavailable"))?
            .write_all(payload)
            .context("write SSHSIG verification payload");
        let output = child
            .wait_with_output()
            .context("wait for SSHSIG verifier")?;
        write_result?;
        if !output.status.success() {
            let diagnostic = String::from_utf8_lossy(&output.stderr);
            let diagnostic: String = diagnostic.trim().chars().take(4096).collect();
            if diagnostic.is_empty() {
                bail!("SSHSIG verification failed");
            }
            bail!("SSHSIG verification failed: {diagnostic}");
        }
        Ok(())
    }
}

/// Evidence that the signature, target binding, time bounds, and one-time
/// replay claim all succeeded. This type intentionally has no conversion into
/// existing `server::Request` authorization.
#[derive(Debug)]
pub(crate) struct VerifiedGrant {
    #[allow(dead_code)]
    grant: GrantV1,
}

pub(crate) fn verify_and_claim(
    encoded: &[u8],
    context: &ReceiverContext<'_>,
    policy: &SshsigPolicy,
    replay: &ReplayStore,
) -> Result<VerifiedGrant> {
    let envelope = SignedGrantEnvelopeV1::decode(encoded)?;
    context.validate(&envelope.grant)?;
    let payload = envelope.signing_payload()?;
    policy.verify(
        replay,
        context.expected_signer,
        &envelope.signature,
        &payload,
    )?;
    let digest: [u8; 32] = Sha256::digest(&payload).into();
    replay.claim(envelope.grant.request_id, digest, context.now)?;
    Ok(VerifiedGrant {
        grant: envelope.grant,
    })
}

#[derive(Clone)]
pub(crate) struct ReplayStore {
    path: PathBuf,
    directory: Arc<File>,
}

impl ReplayStore {
    pub(crate) fn open(path: &Path) -> Result<Self> {
        if !path.is_absolute() {
            bail!("replay state directory must be absolute");
        }
        match fs::DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("create replay state directory {}", path.display()))
            }
        }
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .with_context(|| format!("open replay state directory {}", path.display()))?;
        validate_private_directory(&directory, path)?;
        // Persist the state directory entry itself. Without syncing its
        // parent, a first claim could survive inside a directory whose name is
        // lost by a crash, allowing the request to be redeemed again.
        directory
            .sync_all()
            .with_context(|| format!("sync replay state directory {}", path.display()))?;
        sync_parent_directory(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            directory: Arc::new(directory),
        })
    }

    fn claim(&self, request: RequestId, digest: [u8; 32], claimed_at: i64) -> Result<()> {
        request.validate()?;
        let lock = openat_file(
            self.directory.as_raw_fd(),
            ".claim-lock",
            libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
        .with_context(|| format!("open replay lock in {}", self.path.display()))?;
        validate_private_file(&lock, "replay lock")?;
        flock_exclusive(lock.as_raw_fd()).context("lock replay claim store")?;

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
        validate_private_file(&temporary, "temporary replay claim")?;
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
        let path = self.path.join(&name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .with_context(|| format!("create private {label} file"))?;
        validate_private_file(&file, label)?;
        file.write_all(contents)
            .with_context(|| format!("write private {label} file"))?;
        file.flush()
            .with_context(|| format!("flush private {label} file"))?;
        Ok(TemporaryStateFile { path })
    }
}

struct TemporaryStateFile {
    path: PathBuf,
}

impl TemporaryStateFile {
    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TemporaryStateFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn validate_private_directory(directory: &File, path: &Path) -> Result<()> {
    let metadata = directory
        .metadata()
        .with_context(|| format!("inspect replay state directory {}", path.display()))?;
    if !metadata.is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
        bail!("replay state directory must be target-owned and not a symlink");
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 || mode & 0o700 != 0o700 {
        bail!("replay state directory must have private mode 0700");
    }
    Ok(())
}

fn sync_parent_directory(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("replay state directory has no parent"))?;
    let parent_directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent)
        .with_context(|| format!("open replay state parent {}", parent.display()))?;
    parent_directory
        .sync_all()
        .with_context(|| format!("sync replay state parent {}", parent.display()))
}

fn validate_private_file(file: &File, label: &str) -> Result<()> {
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect {label}"))?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        bail!("{label} must be a target-owned private regular file");
    }
    Ok(())
}

fn validate_secure_executable(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!("ssh-keygen verifier path must be absolute");
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("open trusted SSHSIG verifier {}", path.display()))?;
    let metadata = file.metadata()?;
    let effective_uid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || (metadata.uid() != 0 && metadata.uid() != effective_uid)
        || metadata.permissions().mode() & 0o022 != 0
        || metadata.permissions().mode() & 0o111 == 0
    {
        bail!("SSHSIG verifier must be a trusted non-writable executable");
    }
    Ok(())
}

fn read_secure_regular(path: &Path, label: &str, maximum: usize) -> Result<Vec<u8>> {
    if !path.is_absolute() {
        bail!("{label} path must be absolute");
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("open {label} {}", path.display()))?;
    let metadata = file.metadata()?;
    let effective_uid = unsafe { libc::geteuid() };
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.file_type().is_socket()
        || (metadata.uid() != 0 && metadata.uid() != effective_uid)
        || metadata.permissions().mode() & 0o022 != 0
    {
        bail!("{label} must be a trusted non-writable regular file");
    }
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
    let name = CString::new(name)
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
    use std::process::Child;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::Duration;

    const NOW: i64 = 1_900_000_000;
    const SIGNER: &str = "alice@example.test";
    const TARGET: &str = "backup";

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(label: &str) -> Self {
            for _ in 0..100 {
                let path = std::env::temp_dir().join(format!(
                    "syq-delegation-{label}-{}-{}",
                    std::process::id(),
                    hex(&random_array::<12>().expect("test randomness"))
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
            ReplayStore::open(&self.directory.join(name)).expect("open replay store")
        }

        fn policy(&self) -> SshsigPolicy {
            SshsigPolicy {
                ssh_keygen: ssh_tool("ssh-keygen"),
                allowed_signers: self.allowed_signers.clone(),
                revocation_file: None,
            }
        }

        fn signed(&self, grant: GrantV1) -> Vec<u8> {
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

    fn fixture_grant(request_byte: u8) -> GrantV1 {
        GrantV1 {
            enrollment_id: EnrollmentId::test_v4(7),
            target_login: TARGET.to_owned(),
            signer: SIGNER.to_owned(),
            request_id: RequestId([request_byte; 32]),
            issued_at: NOW,
            not_before: NOW - 30,
            not_after: NOW + 600,
            operation: GrantOperationV1::Copy(CopyOperationV1 {
                destination: b"/srv/archive/project".to_vec(),
                policy: CopyPolicyV1 {
                    placement: DestinationPlacementV1::ExactPath,
                    existing: ExistingDestinationPolicyV1::Replace,
                    deletion: DeletionPolicyV1::Forbid,
                    publication: PublicationPolicyV1::AtomicStaged,
                },
                options: CopyOptionsV1 {
                    recursive: true,
                    preserve_symlinks: true,
                    preserve_permissions: true,
                    preserve_times: true,
                    preserve_owner: false,
                    preserve_group: false,
                    preserve_devices: false,
                    compare_existing_by_content: true,
                    verify_after_copy: true,
                    compressed_transport: false,
                },
                limits: CopyLimitsV1 {
                    max_entries: 10_000,
                    max_total_bytes: 1 << 30,
                    max_file_bytes: 1 << 29,
                    max_connections: 8,
                    max_deletions: 0,
                    max_runtime_seconds: 300,
                },
            }),
        }
    }

    fn context<'a>(signer: &'a str, target: &'a str, now: i64, skew: i64) -> ReceiverContext<'a> {
        ReceiverContext {
            enrollment_id: EnrollmentId::test_v4(7),
            target_login: target,
            expected_signer: signer,
            now,
            clock_skew_seconds: skew,
        }
    }

    fn signed_envelope(
        grant: GrantV1,
        key: &Path,
        namespace: &str,
        agent: Option<&AgentGuard>,
    ) -> Vec<u8> {
        let payload = signing_payload(&grant).expect("make signing payload");
        let signature = sign(&payload, key, namespace, agent);
        SignedGrantEnvelopeV1 { grant, signature }
            .encode()
            .expect("encode signed grant")
    }

    fn raw_envelope(grant: &GrantV1, signature: &[u8]) -> Vec<u8> {
        let grant = canonical_grant_bytes(grant).expect("encode test grant");
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
        let decoded = SignedGrantEnvelopeV1::decode(&encoded).expect("decode canonical grant");
        assert_eq!(decoded.grant, fixture_grant(1));

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(SignedGrantEnvelopeV1::decode(&trailing).is_err());

        let mut relative = fixture_grant(2);
        let GrantOperationV1::Copy(copy) = &mut relative.operation;
        copy.destination = b"relative/path".to_vec();
        assert!(signing_payload(&relative).is_err());

        let mut unbounded = fixture_grant(3);
        unbounded.not_after = unbounded.not_before + MAX_GRANT_VALIDITY_SECS + 1;
        assert!(signing_payload(&unbounded).is_err());

        let mut excessive = fixture_grant(4);
        let GrantOperationV1::Copy(copy) = &mut excessive.operation;
        copy.limits.max_connections = MAX_CONNECTIONS + 1;
        assert!(signing_payload(&excessive).is_err());

        let mut excessive = fixture_grant(4);
        let GrantOperationV1::Copy(copy) = &mut excessive.operation;
        copy.limits.max_total_bytes = u64::MAX;
        assert!(signing_payload(&excessive).is_err());
    }

    #[test]
    fn version_one_grant_encoding_is_frozen() {
        let bytes = canonical_grant_bytes(&fixture_grant(1)).expect("encode version-one grant");
        assert_eq!(
            hex(&Sha256::digest(&bytes)),
            "14e187e3648784c1878d887e8b70bead312874ae6296e492907232481b9af1b6",
            "changing these bytes requires a new wire version"
        );
    }

    #[test]
    fn malformed_and_noncanonical_sshsig_are_rejected() {
        let fixture = Fixture::ordinary();
        let grant = fixture_grant(5);
        let payload = signing_payload(&grant).expect("payload");
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
        assert!(SignedGrantEnvelopeV1::decode(&raw_envelope(&grant, &malformed)).is_err());

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
        assert!(SignedGrantEnvelopeV1::decode(&raw_envelope(&grant, &rewrapped)).is_err());
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

        let original = SignedGrantEnvelopeV1::decode(&fixture.signed(fixture_grant(7)))
            .expect("decode signed request");
        let mut altered = original.grant;
        let GrantOperationV1::Copy(copy) = &mut altered.operation;
        copy.options.verify_after_copy = false;
        let tampered = raw_envelope(&altered, &original.signature);
        assert!(verify_and_claim(
            &tampered,
            &context(SIGNER, TARGET, NOW, 0),
            &fixture.policy(),
            &fixture.replay("tamper-replay"),
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
            &context(SIGNER, TARGET, NOW + 611, 10),
            &fixture.policy(),
            &replay,
        )
        .is_err());
        verify_and_claim(
            &encoded,
            &context(SIGNER, TARGET, NOW + 605, 10),
            &fixture.policy(),
            &replay,
        )
        .expect("expiry inside clock-skew allowance");

        let mut future = fixture_grant(10);
        future.issued_at = NOW + 100;
        future.not_before = NOW + 100;
        future.not_after = NOW + 400;
        let encoded = fixture.signed(future);
        let replay = fixture.replay("future-replay");
        assert!(verify_and_claim(
            &encoded,
            &context(SIGNER, TARGET, NOW, 99),
            &fixture.policy(),
            &replay,
        )
        .is_err());
        verify_and_claim(
            &encoded,
            &context(SIGNER, TARGET, NOW, 100),
            &fixture.policy(),
            &replay,
        )
        .expect("not-before inside clock-skew allowance");
        assert!(context(SIGNER, TARGET, NOW, MAX_CLOCK_SKEW_SECS + 1)
            .validate(&fixture_grant(11))
            .is_err());
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
                    .is_ok()
            }));
        }
        let successes = threads
            .into_iter()
            .map(|thread| thread.join().expect("redemption thread"))
            .filter(|succeeded| *succeeded)
            .count();
        assert_eq!(successes, 1);
        assert!(verify_and_claim(
            &encoded,
            &context(SIGNER, TARGET, NOW, 0),
            &fixture.policy(),
            &replay,
        )
        .is_err());
    }

    #[test]
    fn replay_claim_survives_reopen_ignores_stale_temp_and_fails_closed_on_corruption() {
        let directory = TestDir::new("replay-disk");
        let state = directory.join("state");
        let first = RequestId([13; 32]);
        let first_digest = [0x31; 32];
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
    fn replay_store_rejects_nonprivate_or_symlinked_state() {
        let directory = TestDir::new("replay-security");
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
        let link = directory.join("state-link");
        std::os::unix::fs::symlink(&private, &link).expect("create state symlink");
        assert!(ReplayStore::open(&link).is_err());
    }

    #[test]
    fn request_ids_are_fresh_and_distinct_from_stable_copy_ids() {
        let first = RequestId::random().expect("random request ID");
        let second = RequestId::random().expect("random request ID");
        assert_ne!(first, second);
        assert_eq!(std::mem::size_of::<RequestId>(), 32);
        assert_eq!(std::mem::size_of::<crate::proto::PartialId>(), 16);
    }

    #[test]
    fn verifies_certificate_signature_against_allowed_ca() {
        let directory = TestDir::new("certificate");
        let ca = directory.join("ca");
        let user = directory.join("user");
        generate_key(&ca);
        generate_key(&user);
        let mut certify = Command::new(ssh_tool("ssh-keygen"));
        certify
            .env_clear()
            .args(["-q", "-s"])
            .arg(&ca)
            .args(["-I", "syq-test", "-n", SIGNER])
            .arg(user.with_extension("pub"))
            .stdin(Stdio::null());
        command_output(certify, "create test signing certificate");

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
        let replay = ReplayStore::open(&directory.join("replay")).expect("open replay store");
        let policy = SshsigPolicy {
            ssh_keygen: ssh_tool("ssh-keygen"),
            allowed_signers,
            revocation_file: None,
        };
        verify_and_claim(&encoded, &context(SIGNER, TARGET, NOW, 0), &policy, &replay)
            .expect("verify SSH certificate signature through allowed CA");
    }
}

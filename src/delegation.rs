//! Signed receiver authorization core.
//!
//! The forced receiver verifies and redeems a grant here, then converts the
//! resulting `VerifiedGrant` into `restricted::RestrictedAuthority`. That
//! separate type binds every protocol request to the destination it resolves
//! in the session; verification by itself remains deliberately incapable of
//! filesystem access.
//!
//! The wire representation deliberately signs a typed, canonical binary grant
//! rather than a command line. The signature is an OpenSSH SSHSIG in the fixed
//! [`SSHSIG_NAMESPACE`], made by the user's login key and verified here in
//! Rust against the [`TrustedSigner`] the enrollment recorded, including a FIDO
//! key's touch and PIN flags and a certificate's expiry. A fresh random
//! [`RequestId`] is a replay nonce; durable redeeming gives at-most-once
//! redemption, not exactly-once execution across a receiver crash.
//! The ID is a separate type and size from the stable copy IDs in
//! `proto`.
//! Redeemed IDs are rejected from the pinned redeem store before the signature
//! is checked.
//!
//! "Durable" here means that redeem contents and directory-entry changes are
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
//! scopes from overlapping its executables, SSH configuration, or enrollment
//! state.

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
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

pub(crate) const SSHSIG_NAMESPACE: &str = "syq-grant@greaber.github";
const WIRE_MAGIC: &[u8; 8] = b"SYQGRNT\0";
const WIRE_HEADER_LEN: usize = WIRE_MAGIC.len() + 4 + 4;
const MAX_GRANT_BYTES: usize = 32 * 1024;
const MAX_SIGNATURE_BYTES: usize = 16 * 1024;
const MAX_ENVELOPE_BYTES: usize = WIRE_HEADER_LEN + MAX_GRANT_BYTES + MAX_SIGNATURE_BYTES;
pub(crate) const MAX_PATH_BYTES: usize = 4096;
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
pub(crate) const MAX_CONNECTIONS: u16 = 128;
const MAX_FILTER_RULES: usize = 4096;
const MAX_FILTER_RULE_BYTES: usize = 4096;
const MAX_FILTER_ROOTS: usize = 1024;
const REDEMPTION_MAGIC: &[u8; 8] = b"SYQCLM\0\0";
const REDEMPTION_RECORD_LEN: usize = REDEMPTION_MAGIC.len() + 8 + 32 + 32;

use crate::enrollment::EnrollmentId;

/// A one-redemption nonce generated independently for every signed request.
/// It is intentionally not constructible from `proto::CopyId`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) struct RequestId([u8; 32]);

impl RequestId {
    /// A fresh nonce whose first 8 bytes are the big-endian issue time, so
    /// hex redeem filenames sort chronologically for inspection. The
    /// remaining 24 random bytes carry uniqueness; the timestamp is
    /// organizational only — verifiers rely on the envelope signature and
    /// the redeem store, never on this prefix. IMPORTANT: Any future expiry
    /// or pruning decision MUST read `redeemed_at` from the
    /// redeem record (see `validate_redeem_record`), never infer it from the
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
    /// Create missing entries without modifying pre-existing entries.
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
    /// The in-place policy of earlier releases, under which a receiver
    /// wrote existing files in place. A receiver now treats it as
    /// `InPlaceNew`, which allows less. A named destination never receives
    /// it: its requests come only from a matching build.
    InPlace,
    /// `--in-place=new`: new files may be written directly at their final
    /// names, and existing files are replaced as under `AtomicStaged`. A
    /// variant of its own, so that a receiver from before it, which would
    /// read `InPlace` as permission to write existing files in place,
    /// refuses the grant instead.
    InPlaceNew,
    /// `--in-place=update`: as `InPlaceNew`, and an existing file the
    /// receiver can vouch for (`fsops::vouch::update_refusal`) is updated in
    /// place too. A receiver from before it refuses the grant, rather than
    /// writing existing files in place without those checks.
    InPlaceUpdate,
}

impl PublicationPolicy {
    /// Whether new files may be written directly at their final names.
    pub(crate) fn writes_new_files_in_place(self) -> bool {
        !matches!(self, Self::AtomicStaged)
    }

    /// Whether existing files may be updated in place.
    pub(crate) fn updates_existing_files_in_place(self) -> bool {
        self == Self::InPlaceUpdate
    }
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
    // Legacy signed grants use this bit to forbid writes; preserve its encoding.
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
        // A per-file limit of zero admits only empty files (`--max-size 0`).
        if limits.max_total_bytes == 0 || limits.max_total_bytes > MAX_COPY_BYTES {
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
    fn normalize(&mut self) {
        // With no filters, --delete-excluded has no observable effect.
        if self.ignore.is_empty() {
            self.delete_excluded = false;
            self.destination_roots.clear();
        } else {
            self.destination_roots.sort();
            self.destination_roots.dedup();
        }
    }
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
/// once against the enrolled root when the grant is redeemed, and `New`
/// additionally forces no-replace creation of that root, so a remote source
/// coordinator cannot turn `--into-new` into an update of an existing tree.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum RootExistence {
    #[default]
    Any,
    /// The signed destination must not exist when the grant is redeemed.
    New,
    /// The signed destination must already exist when the grant is redeemed;
    /// a directory placement additionally requires a directory.
    Existing,
}

const EXTRA_OPTIONS_EXTENSION: &str = "copy-options-v1";

/// Copy options released after the signed `CopyOptions`. They are signed in
/// a grant extension, so a receiver that predates them refuses the grant
/// instead of silently dropping them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ExtraCopyOptions {
    pub hardlinks: bool,
    pub acls: bool,
    pub xattrs: bool,
    pub atimes: bool,
    pub crtimes: bool,
    pub sparse: bool,
    pub open_noatime: bool,
    pub widen_dirs: DirectoryWidening,
    /// `syq rsync --ignore-existing`: new files, links and special files are
    /// created without replacing anything, as under the `Skip` policy, while
    /// existing directories still take the copy's metadata.
    pub keep_files: bool,
    /// `--follow-dst` with `--into`: when the destination is a symlink, the
    /// copy goes into the directory it resolves to inside the enrolled root.
    pub follow_dst: bool,
}

/// Which existing destination directories the receiver may briefly give the
/// owner permission the copy needs, as `--widen-dirs` names them: none, the
/// ones the copy includes, or also the directory the copy goes into. Never
/// one above the enrolled root.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) enum DirectoryWidening {
    #[default]
    None,
    Rsync,
    All,
}

impl From<crate::cli::WidenDirs> for DirectoryWidening {
    fn from(mode: crate::cli::WidenDirs) -> Self {
        match mode {
            crate::cli::WidenDirs::None => Self::None,
            crate::cli::WidenDirs::Rsync => Self::Rsync,
            crate::cli::WidenDirs::All => Self::All,
        }
    }
}

impl ExtraCopyOptions {
    pub(crate) fn is_default(&self) -> bool {
        *self == Self::default()
    }
    /// The inode metadata these options let a request apply or select.
    pub(crate) fn allows(&self, selection: crate::inode_metadata::Selection) -> bool {
        (!selection.acls || self.acls)
            && (!selection.xattrs || self.xattrs)
            && (!selection.atimes || self.atimes)
            && (!selection.crtimes || self.crtimes)
            && (!selection.open_noatime || self.open_noatime)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct GrantBody {
    grant: Grant,
    max_file_data_bytes_per_second: u64,
    filters: FilterPolicy,
    root_existence: RootExistence,
    receipt_policy: crate::destination_results::ReceiptPolicy,
}

#[cfg(test)]
fn test_receipt_policy() -> crate::destination_results::ReceiptPolicy {
    crate::destination_results::ReceiptPolicy {
        required: true,
        hashed: false,
        max_records: crate::destination_results::DEFAULT_MAX_RECORDS,
        max_plaintext_bytes: crate::destination_results::DEFAULT_MAX_PLAINTEXT_BYTES,
        delivery: crate::destination_results::ReceiptDelivery::DetachedSignedPlaintext,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SignedGrantEnvelope {
    pub grant: Grant,
    pub max_file_data_bytes_per_second: u64,
    pub filters: FilterPolicy,
    pub root_existence: RootExistence,
    pub receipt_policy: crate::destination_results::ReceiptPolicy,
    /// Canonical OpenSSH armored SSHSIG bytes.
    pub signature: Vec<u8>,
    pub tcp_congestion: Option<String>,
    pub mapping: Option<crate::mapping::Authorization>,
    pub hashing: Option<crate::hashing::CopyHashing>,
    pub extra_options: ExtraCopyOptions,
}

impl SignedGrantEnvelope {
    #[cfg(test)]
    fn new(grant: Grant, max_file_data_bytes_per_second: u64, signature: Vec<u8>) -> Self {
        Self {
            grant,
            max_file_data_bytes_per_second,
            filters: FilterPolicy::default(),
            root_existence: RootExistence::Any,
            receipt_policy: test_receipt_policy(),
            tcp_congestion: None,
            mapping: None,
            hashing: None,
            extra_options: ExtraCopyOptions::default(),
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
            &self.receipt_policy,
            self.tcp_congestion.as_deref(),
            self.mapping.as_ref(),
            self.hashing.as_ref(),
            &self.extra_options,
        )?;
        if body.len() > MAX_GRANT_BYTES {
            bail!("canonical grant exceeds {MAX_GRANT_BYTES} bytes");
        }
        if self.signature.len() > MAX_SIGNATURE_BYTES {
            bail!("SSHSIG exceeds {MAX_SIGNATURE_BYTES} bytes");
        }
        let mut out = Vec::with_capacity(WIRE_HEADER_LEN + body.len() + self.signature.len());
        out.extend_from_slice(WIRE_MAGIC);
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
        let grant_len = u32::from_be_bytes(bytes[8..12].try_into().expect("fixed header")) as usize;
        let signature_len =
            u32::from_be_bytes(bytes[12..16].try_into().expect("fixed header")) as usize;
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
        let (body, extension): (GrantBody, &[u8]) =
            postcard::take_from_bytes(body_bytes).context("decode signed grant")?;
        let (tcp_congestion, mapping, hashing, extra_options) = if extension.is_empty() {
            (None, None, None, ExtraCopyOptions::default())
        } else {
            let (kind, rest): (String, &[u8]) =
                postcard::take_from_bytes(extension).context("decode signed grant extension")?;
            match kind.as_str() {
                "tcp-congestion-v1" => (
                    Some(postcard::from_bytes(rest)?),
                    None,
                    None,
                    ExtraCopyOptions::default(),
                ),
                "mapping-v1" => {
                    let (tcp, mapping): (Option<String>, crate::mapping::Authorization) =
                        postcard::from_bytes(rest)?;
                    (tcp, Some(mapping), None, ExtraCopyOptions::default())
                }
                "copy-hashing-v2" => {
                    let (tcp, mapping, hashing): (
                        Option<String>,
                        Option<crate::mapping::Authorization>,
                        crate::hashing::CopyHashing,
                    ) = postcard::from_bytes(rest)?;
                    (tcp, mapping, Some(hashing), ExtraCopyOptions::default())
                }
                EXTRA_OPTIONS_EXTENSION => postcard::from_bytes(rest)?,
                _ => bail!("unknown signed grant extension"),
            }
        };
        let GrantBody {
            grant,
            max_file_data_bytes_per_second,
            filters,
            root_existence,
            receipt_policy,
        } = body;
        if canonical_body_bytes(
            &grant,
            max_file_data_bytes_per_second,
            &filters,
            root_existence,
            &receipt_policy,
            tcp_congestion.as_deref(),
            mapping.as_ref(),
            hashing.as_ref(),
            &extra_options,
        )? != body_bytes
        {
            bail!("signed grant uses a noncanonical encoding");
        }
        grant.validate_static()?;
        filters.validate(&grant)?;
        receipt_policy.validate()?;
        let signature = bytes[WIRE_HEADER_LEN + grant_len..].to_vec();
        validate_canonical_sshsig(&signature)?;
        Ok(Self {
            grant,
            max_file_data_bytes_per_second,
            filters,
            root_existence,
            receipt_policy,
            signature,
            tcp_congestion,
            mapping,
            hashing,
            extra_options,
        })
    }

    fn signing_payload(&self) -> Result<Vec<u8>> {
        signing_payload(
            &self.grant,
            self.max_file_data_bytes_per_second,
            &self.filters,
            self.root_existence,
            &self.receipt_policy,
            self.tcp_congestion.as_deref(),
            self.mapping.as_ref(),
            self.hashing.as_ref(),
            &self.extra_options,
        )
    }
}

/// Validate an ephemeral request before an approval can authorize outbound SSH.
/// This does not sign, redeem, or touch any durable authority state.
pub(crate) fn validate_return_request(request: &crate::destination::CopyRequest) -> Result<()> {
    let grant = Grant {
        enrollment_id: EnrollmentId::random(),
        target_login: "return".into(),
        signer: "return".into(),
        request_id: RequestId::fresh(0)?,
        issued_at: 0,
        not_before: 0,
        start_by: 60,
        finish_by: 3600,
        operation: GrantOperation::Copy(request.copy.clone()),
    };
    let mut policy = request.constraints.clone();
    policy.filters.normalize();
    signing_payload(
        &grant,
        policy.max_file_data_bytes_per_second,
        &policy.filters,
        policy.root_existence,
        &policy.receipt_policy,
        policy.tcp_congestion.as_deref(),
        policy.mapping.as_ref(),
        policy.hashing.as_ref(),
        &policy.extra_options,
    )?;
    Ok(())
}

pub(crate) fn sign_grant(
    grant: Grant,
    constraints: GrantConstraints,
    private_key: &PrivateKey,
) -> Result<Vec<u8>> {
    sign_grant_with(grant, constraints, |payload| {
        if private_key.is_encrypted() {
            bail!("cannot sign a grant with an encrypted enrollment key");
        }
        Ok(private_key
            .sign(SSHSIG_NAMESPACE, HashAlg::Sha256, payload)
            .context("sign restricted transfer grant")?
            .to_pem(LineEnding::LF)
            .context("encode restricted transfer SSHSIG")?
            .into_bytes())
    })
}

pub(crate) fn sign_grant_with(
    grant: Grant,
    constraints: GrantConstraints,
    sign: impl FnOnce(&[u8]) -> Result<Vec<u8>>,
) -> Result<Vec<u8>> {
    let GrantConstraints {
        max_file_data_bytes_per_second,
        mut filters,
        root_existence,
        receipt_policy,
        tcp_congestion,
        mapping,
        hashing,
        extra_options,
    } = constraints;
    filters.normalize();
    filters.validate(&grant)?;
    let payload = signing_payload(
        &grant,
        max_file_data_bytes_per_second,
        &filters,
        root_existence,
        &receipt_policy,
        tcp_congestion.as_deref(),
        mapping.as_ref(),
        hashing.as_ref(),
        &extra_options,
    )?;
    let signature = sign(&payload)?;
    SignedGrantEnvelope {
        grant,
        max_file_data_bytes_per_second,
        filters,
        root_existence,
        receipt_policy,
        signature,
        tcp_congestion,
        mapping,
        hashing,
        extra_options,
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
        None,
        None,
        None,
        &ExtraCopyOptions::default(),
    )
}

#[allow(clippy::too_many_arguments)]
fn signing_payload(
    grant: &Grant,
    max_file_data_bytes_per_second: u64,
    filters: &FilterPolicy,
    root_existence: RootExistence,
    receipt_policy: &crate::destination_results::ReceiptPolicy,
    tcp_congestion: Option<&str>,
    mapping: Option<&crate::mapping::Authorization>,
    hashing: Option<&crate::hashing::CopyHashing>,
    extra_options: &ExtraCopyOptions,
) -> Result<Vec<u8>> {
    grant.validate_static()?;
    filters.validate(grant)?;
    let body = canonical_body_bytes(
        grant,
        max_file_data_bytes_per_second,
        filters,
        root_existence,
        receipt_policy,
        tcp_congestion,
        mapping,
        hashing,
        extra_options,
    )?;
    if body.len() > MAX_GRANT_BYTES {
        bail!("canonical grant exceeds {MAX_GRANT_BYTES} bytes");
    }
    let mut out = Vec::with_capacity(WIRE_MAGIC.len() + 4 + body.len());
    out.extend_from_slice(WIRE_MAGIC);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn canonical_body_bytes(
    grant: &Grant,
    max_file_data_bytes_per_second: u64,
    filters: &FilterPolicy,
    root_existence: RootExistence,
    receipt_policy: &crate::destination_results::ReceiptPolicy,
    tcp_congestion: Option<&str>,
    mapping: Option<&crate::mapping::Authorization>,
    hashing: Option<&crate::hashing::CopyHashing>,
    extra_options: &ExtraCopyOptions,
) -> Result<Vec<u8>> {
    receipt_policy.validate()?;
    // Preserve the released v0.4.1 body byte for byte when no override is
    // requested. Its reader checks canonical re-encoding and rejects trailing
    // extensions, so it cannot silently discard this signed constraint.
    let mut bytes = postcard::to_stdvec(&GrantBody {
        grant: grant.clone(),
        max_file_data_bytes_per_second,
        filters: filters.clone(),
        root_existence,
        receipt_policy: receipt_policy.clone(),
    })
    .context("encode canonical signed grant")?;
    if let Some(algorithm) = tcp_congestion {
        crate::cli::parse_tcp_congestion(algorithm).map_err(anyhow::Error::msg)?;
    }
    if let Some(expected) = hashing.and_then(|hashing| hashing.expected_hash.as_ref()) {
        expected.validate()?;
    }
    if mapping.is_some() {
        let GrantOperation::Copy(copy) = &grant.operation;
        if copy.policy.deletion != DeletionPolicy::Forbid {
            bail!("mapping authorization does not permit pruning");
        }
    }
    if !extra_options.is_default() {
        let GrantOperation::Copy(copy) = &grant.operation;
        if extra_options.acls && !copy.options.preserve_permissions {
            bail!("ACL preservation requires permission preservation");
        }
        // Released receivers reject this unknown extension, so a grant
        // carrying these options never reaches a receiver that ignores them.
        bytes.extend(postcard::to_stdvec(&(
            EXTRA_OPTIONS_EXTENSION,
            (tcp_congestion, mapping, hashing, extra_options),
        ))?);
    } else if let Some(hashing) = hashing {
        bytes.extend(postcard::to_stdvec(&(
            "copy-hashing-v2",
            tcp_congestion,
            mapping,
            hashing,
        ))?);
    } else if let Some(mapping) = mapping {
        bytes.extend(postcard::to_stdvec(&(
            "mapping-v1",
            tcp_congestion,
            mapping,
        ))?);
    } else if let Some(algorithm) = tcp_congestion {
        bytes.extend(postcard::to_stdvec(&("tcp-congestion-v1", algorithm))?);
    }
    Ok(bytes)
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
        // expiry, redeems, and deadlines. That accepts neither end of the
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

/// The login key a receiver trusts to sign its grants, with what each
/// signature must also show: a FIDO key's touch (user presence) and PIN (user
/// verification) flags, and a certificate login's expiry. Verification is
/// done here in Rust; no other program takes part.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TrustedSigner {
    /// The login key, as an OpenSSH public key without a comment. For a
    /// certificate login it is the certificate's own key.
    pub public_key: String,
    /// For a FIDO key, the flags every signature must carry: 1 for touch and
    /// 4 for PIN.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_key_flags: Option<u8>,
    /// For a certificate login, when the certificate stops being valid, in
    /// seconds since the Unix epoch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_before: Option<u64>,
}

/// FIDO signature flags: user presence (touch) and user verification (PIN).
pub(crate) const SK_USER_PRESENCE: u8 = 0x01;
pub(crate) const SK_USER_VERIFICATION: u8 = 0x04;

impl TrustedSigner {
    pub(crate) fn new(
        key: &ssh_key::PublicKey,
        security_key_flags: Option<u8>,
        valid_before: Option<u64>,
    ) -> Result<Self> {
        let mut plain = ssh_key::PublicKey::new(key.key_data().clone(), "");
        plain.set_comment("");
        let signer = Self {
            public_key: plain.to_openssh().context("encode the trusted login key")?,
            security_key_flags,
            valid_before,
        };
        signer.validate()?;
        Ok(signer)
    }

    pub(crate) fn key(&self) -> Result<ssh_key::PublicKey> {
        ssh_key::PublicKey::from_openssh(&self.public_key).context("parse the trusted login key")
    }

    /// Whether the key is one whose signatures can be checked and carry
    /// FIDO flags exactly when it is a FIDO key.
    pub(crate) fn validate(&self) -> Result<()> {
        use ssh_key::Algorithm;
        let key = self.key()?;
        let security_key = matches!(
            key.algorithm(),
            Algorithm::SkEd25519 | Algorithm::SkEcdsaSha2NistP256
        );
        match key.algorithm() {
            Algorithm::Ed25519
            | Algorithm::Ecdsa { .. }
            | Algorithm::Rsa { .. }
            | Algorithm::SkEd25519
            | Algorithm::SkEcdsaSha2NistP256 => {}
            algorithm => bail!("syq cannot check signatures made with a {algorithm} login key"),
        }
        match (security_key, self.security_key_flags) {
            (true, Some(flags)) if flags & !(SK_USER_PRESENCE | SK_USER_VERIFICATION) == 0 => {}
            (true, Some(_)) => bail!("unsupported FIDO touch and PIN policy"),
            (true, None) => bail!("a FIDO login key needs a touch and PIN policy"),
            (false, Some(_)) => bail!("a touch and PIN policy applies only to a FIDO login key"),
            (false, None) => {}
        }
        Ok(())
    }

    /// The SHA-256 fingerprint of the trusted key, as `ssh-keygen -l` shows it.
    pub(crate) fn fingerprint(&self) -> Result<String> {
        Ok(self.key()?.fingerprint(HashAlg::Sha256).to_string())
    }

    /// Check one armored SSHSIG over `payload` in `namespace`: made by this
    /// key, with the flags a FIDO key must show, while a certificate is
    /// still valid at `now`.
    pub(crate) fn verify(
        &self,
        namespace: &str,
        payload: &[u8],
        armored: &[u8],
        now: i64,
    ) -> Result<()> {
        self.validate()?;
        if let Some(valid_before) = self.valid_before {
            if u64::try_from(now).map_or(true, |now| now >= valid_before) {
                bail!("the login certificate this receiver trusts has expired; the next copy from your machine renews it");
            }
        }
        let key = self.key()?;
        let signature = ssh_key::SshSig::from_pem(armored).context("parse the SSH signature")?;
        if signature.namespace() != namespace {
            bail!("the signature was made for another purpose");
        }
        if !signature.reserved().is_empty() {
            bail!("the signature carries reserved data");
        }
        if signature.public_key() != key.key_data() {
            bail!("the signature was made by a key this receiver does not trust");
        }
        key.verify(namespace, payload, &signature)
            .map_err(|_| anyhow!("the signature does not verify with the trusted login key"))?;
        if let Some(required) = self.security_key_flags {
            let flags = security_key_flags(&signature)?;
            if flags & required != required {
                bail!(
                    "the signature lacks the FIDO {} this receiver requires",
                    match (
                        required & !flags & SK_USER_PRESENCE != 0,
                        required & !flags & SK_USER_VERIFICATION != 0,
                    ) {
                        (true, true) => "touch and PIN",
                        (true, false) => "touch",
                        _ => "PIN",
                    }
                );
            }
        }
        Ok(())
    }
}

/// The flags of a FIDO signature: user presence and user verification.
pub(crate) fn security_key_flags(signature: &ssh_key::SshSig) -> Result<u8> {
    if !matches!(
        signature.algorithm(),
        ssh_key::Algorithm::SkEd25519 | ssh_key::Algorithm::SkEcdsaSha2NistP256
    ) {
        bail!("the signature was not made by a FIDO key");
    }
    // A FIDO signature ends with its flags byte and a 4-byte counter.
    let bytes = signature.signature_bytes();
    let index = bytes
        .len()
        .checked_sub(5)
        .context("truncated FIDO signature")?;
    Ok(bytes[index])
}

/// Evidence that the signature, target binding, time bounds, and one-time
/// replay redeem all succeeded. The restricted receiver consumes this into its
/// independently enforced request authority and monotonic execution deadline.
#[derive(Debug)]
pub(crate) struct VerifiedGrant {
    #[allow(dead_code)]
    grant: Grant,
    max_file_data_bytes_per_second: u64,
    filters: FilterPolicy,
    root_existence: RootExistence,
    receipt_policy: crate::destination_results::ReceiptPolicy,
    grant_digest: [u8; 32],
    execution_deadline: Instant,
    pub tcp_congestion: Option<String>,
    pub mapping: Option<crate::mapping::Authorization>,
    pub hashing: Option<crate::hashing::CopyHashing>,
    extra_options: ExtraCopyOptions,
}

/// Signed receiver policy carried alongside the copy grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct GrantConstraints {
    pub max_file_data_bytes_per_second: u64,
    pub filters: FilterPolicy,
    pub root_existence: RootExistence,
    pub receipt_policy: crate::destination_results::ReceiptPolicy,
    pub tcp_congestion: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mapping: Option<crate::mapping::Authorization>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hashing: Option<crate::hashing::CopyHashing>,
    #[serde(default, skip_serializing_if = "ExtraCopyOptions::is_default")]
    pub extra_options: ExtraCopyOptions,
}

#[cfg(test)]
impl Default for GrantConstraints {
    fn default() -> Self {
        Self {
            max_file_data_bytes_per_second: 0,
            filters: FilterPolicy::default(),
            root_existence: RootExistence::Any,
            receipt_policy: test_receipt_policy(),
            tcp_congestion: None,
            mapping: None,
            hashing: None,
            extra_options: ExtraCopyOptions::default(),
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
                receipt_policy: self.receipt_policy,
                tcp_congestion: self.tcp_congestion,
                mapping: self.mapping,
                hashing: self.hashing,
                extra_options: self.extra_options,
            },
            self.grant_digest,
            self.execution_deadline,
        )
    }
}

pub(crate) fn verify_and_redeem(
    encoded: &[u8],
    context: &ReceiverContext<'_>,
    signer: &TrustedSigner,
    replay: &ReplayStore,
) -> Result<VerifiedGrant> {
    let envelope = SignedGrantEnvelope::decode(encoded)?;
    let observed_at = Instant::now();
    context.validate_at(&envelope.grant, observed_at)?;
    let payload = envelope.signing_payload()?;
    let replay_digest: [u8; 32] = Sha256::digest(&payload).into();
    let grant_digest = grant_transcript_digest(&payload);
    replay.reject_if_redeemed(envelope.grant.request_id, replay_digest)?;
    // A certificate's expiry is judged with the clock skew in the signer's
    // favour, like the grant's own start-by time.
    let (_, latest_now) = context.wall_time_bounds_at(observed_at)?;
    signer.verify(
        SSHSIG_NAMESPACE,
        &payload,
        &envelope.signature,
        latest_now.saturating_sub(context.clock_skew_seconds),
    )?;
    replay.redeem_after_lock(envelope.grant.request_id, replay_digest, || {
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
        receipt_policy: envelope.receipt_policy,
        tcp_congestion: envelope.tcp_congestion,
        mapping: envelope.mapping,
        hashing: envelope.hashing,
        extra_options: envelope.extra_options,
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
    hasher.update(b"syq-grant-transcript@greaber.github\0");
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
        bail!("grant finish-by time passed while it was being verified and redeemed");
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
    fn redeem(&self, request: RequestId, digest: [u8; 32], redeemed_at: i64) -> Result<()> {
        self.redeem_after_lock(request, digest, || Ok(redeemed_at))
    }

    fn reject_if_redeemed(&self, request: RequestId, digest: [u8; 32]) -> Result<()> {
        request.validate()?;
        let final_name = format!("redeemed-{}", request.file_component());
        if let Some(existing) = readat_optional(
            self.directory.as_raw_fd(),
            &final_name,
            REDEMPTION_RECORD_LEN + 1,
        )? {
            validate_redeem_record(&existing, request, digest)?;
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
                ".redeem-lock",
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

    fn redeem_after_lock(
        &self,
        request: RequestId,
        digest: [u8; 32],
        redeemed_at: impl FnOnce() -> Result<i64>,
    ) -> Result<()> {
        request.validate()?;
        let lock = self
            .open_lock()
            .with_context(|| format!("open replay lock in {}", self.path.display()))?;
        validate_private_file(&lock, "replay lock")?;
        flock_exclusive(lock.as_raw_fd()).context("lock replay redeem store")?;
        // Timestamp and revalidate only after a potentially queued lock wait.
        // No stale ReceiverContext observation may authorize a later redeem.
        let redeemed_at = redeemed_at()?;

        let final_name = format!("redeemed-{}", request.file_component());
        if let Some(existing) = readat_optional(
            self.directory.as_raw_fd(),
            &final_name,
            REDEMPTION_RECORD_LEN + 1,
        )? {
            validate_redeem_record(&existing, request, digest)?;
            bail!("signed request has already been redeemed");
        }

        let temporary_name = format!(
            ".redeemed-{}-{}.tmp",
            request.file_component(),
            hex(&random_array::<16>()?)
        );
        let mut temporary = openat_file(
            self.directory.as_raw_fd(),
            &temporary_name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
        .with_context(|| format!("create replay redeem in {}", self.path.display()))?;
        if let Err(error) = validate_private_file(&temporary, "temporary replay redeem") {
            let _ = unlinkat(self.directory.as_raw_fd(), &temporary_name);
            return Err(error);
        }
        let record = redeem_record(request, digest, redeemed_at)?;
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
            // name. A crash after this point can only leave an already-redeemed
            // request, never a successful-but-forgotten redeem.
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
                    REDEMPTION_RECORD_LEN + 1,
                )? {
                    validate_redeem_record(&existing, request, digest)?;
                    bail!("signed request has already been redeemed");
                }
            }
            return Err(error).context("durably publish replay redeem");
        }
        Ok(())
    }
}

pub(crate) fn validate_private_directory(directory: &File, path: &Path) -> Result<()> {
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

fn redeem_record(request: RequestId, digest: [u8; 32], redeemed_at: i64) -> Result<Vec<u8>> {
    if !(0..=MAX_UNIX_TIMESTAMP).contains(&redeemed_at) {
        bail!("replay redeem timestamp is outside the supported range");
    }
    let mut record = Vec::with_capacity(REDEMPTION_RECORD_LEN);
    record.extend_from_slice(REDEMPTION_MAGIC);
    record.extend_from_slice(&redeemed_at.to_be_bytes());
    record.extend_from_slice(&request.0);
    record.extend_from_slice(&digest);
    Ok(record)
}

fn validate_redeem_record(record: &[u8], request: RequestId, digest: [u8; 32]) -> Result<()> {
    if record.len() != REDEMPTION_RECORD_LEN || &record[..8] != REDEMPTION_MAGIC {
        bail!("replay state is malformed; refusing signed request");
    }
    let redeemed_at = i64::from_be_bytes(record[8..16].try_into().expect("redeem timestamp"));
    if !(0..=MAX_UNIX_TIMESTAMP).contains(&redeemed_at) {
        bail!("replay state has an invalid timestamp; refusing signed request");
    }
    if record[16..48] != request.0 {
        bail!("replay state request ID does not match its filename");
    }
    if record[48..80] != digest {
        bail!("request ID was already redeemed by a different signed grant");
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
    validate_private_file(&file, "replay redeem")?;
    let mut contents = Vec::new();
    Read::by_ref(&mut file)
        .take(maximum as u64)
        .read_to_end(&mut contents)?;
    if contents.len() >= maximum {
        bail!("replay redeem exceeds its fixed format; refusing request");
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
mod tests;

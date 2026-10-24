//! Receiver authorization core: what a copy may do at its destination, the
//! login key that signs its directive, and the record of directives used.
//!
//! The forced receiver verifies and redeems a directive (`crate::directive`)
//! here, and turns the rules derived from its command into
//! `restricted::RestrictedAuthority`. That separate type binds every protocol
//! request to the destination it resolves in the session; verification by
//! itself has no filesystem access beyond the record of used directives.
//!
//! The signature is an OpenSSH SSHSIG in the directive namespace, made by
//! the user's login key and verified here in Rust against the
//! [`TrustedSigner`] the enrollment recorded, including a FIDO key's touch and
//! PIN flags and a certificate's expiry. A fresh random [`RequestId`] is a
//! replay nonce; durable redeeming gives at-most-once redemption, not
//! exactly-once execution across a receiver crash. The ID is a separate type
//! and size from the stable copy IDs in `proto`. Redeemed IDs are refused from
//! the pinned redeem store before the signature is checked.
//!
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
use ssh_key::HashAlg;
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

pub(crate) const MAX_SIGNATURE_BYTES: usize = 16 * 1024;
pub(crate) const MAX_PATH_BYTES: usize = 4096;
const MAX_LOGIN_BYTES: usize = 256;
const MAX_CLOCK_SKEW_SECS: i64 = 5 * 60;
pub(crate) const MAX_UNIX_TIMESTAMP: i64 = 253_402_300_799; // 9999-12-31T23:59:59Z
pub(crate) const MAX_ENTRIES: u64 = 1_000_000_000_000;
// Keep later accounting representable in both signed and unsigned counters.
pub(crate) const MAX_COPY_BYTES: u64 = i64::MAX as u64;
pub(crate) const MAX_CONNECTIONS: u16 = 128;
const MAX_FILTER_RULES: usize = 4096;
const MAX_FILTER_RULE_BYTES: usize = 4096;
const MAX_FILTER_ROOTS: usize = 1024;
const REDEMPTION_MAGIC: &[u8; 8] = b"SYQCLM\0\0";
const REDEMPTION_RECORD_LEN: usize = REDEMPTION_MAGIC.len() + 8 + 32 + 32;

use crate::directive::Directive;
use crate::enrollment::EnrollmentId;

/// A one-redemption nonce generated independently for every signed request.
/// It is intentionally not constructible from `proto::CopyId`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) struct RequestId([u8; 32]);

impl RequestId {
    /// A fresh nonce whose first 8 bytes are the big-endian issue time, so
    /// hex redeem filenames sort chronologically for inspection. The
    /// remaining 24 random bytes carry uniqueness; the timestamp is
    /// organizational only — verifiers rely on the directive's signature
    /// and the redeem store, never on this prefix. IMPORTANT: Any future expiry
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

    /// A fixed ID for tests that compare derivations.
    #[cfg(test)]
    pub(crate) fn test(byte: u8) -> Self {
        Self([byte; 32])
    }

    pub(crate) fn validate(self) -> Result<()> {
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
pub(crate) struct CopyOperation {
    /// Canonically spelled absolute target path. This is only a name;
    /// receiver authorization resolves it beneath the confinement root handle.
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
    /// `--in-place=new`: new files may be written directly at their final
    /// names, and existing files are replaced as under `AtomicStaged`.
    InPlaceNew,
    /// `--in-place=update`: as `InPlaceNew`, and an existing file the
    /// receiver can vouch for (`fsops::vouch::update_refusal`) is updated in
    /// place too.
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

/// What one approved copy may do at its destination: the rules derived from
/// its command, and the approval they came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Grant {
    pub enrollment_id: EnrollmentId,
    pub request_id: RequestId,
    pub copy: CopyOperation,
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
    fn validate(&self, copy: &CopyOperation) -> Result<()> {
        if self.ignore.len() > MAX_FILTER_RULES {
            bail!("filter-rule count exceeds the supported range");
        }
        for rule in &self.ignore {
            if rule.len() > MAX_FILTER_RULE_BYTES || rule.contains('\0') {
                bail!("filter rule is outside the supported range");
            }
        }
        crate::scan::build_ignore(&self.ignore).context("validate filter policy")?;
        if self.ignore.is_empty() {
            if !self.destination_roots.is_empty() {
                bail!("filter roots require filter rules");
            }
        } else {
            if self.destination_roots.is_empty() || self.destination_roots.len() > MAX_FILTER_ROOTS
            {
                bail!("filter-root count is outside the supported range");
            }
            for root in &self.destination_roots {
                validate_absolute_path(root)?;
                if !copy.mutation_scopes.iter().any(|scope| {
                    root == &scope.path
                        || (scope.descendants
                            && root.starts_with(&scope.path)
                            && root.get(scope.path.len()) == Some(&b'/'))
                }) {
                    bail!("filter root is outside the destination mutation scopes");
                }
            }
            if self
                .destination_roots
                .windows(2)
                .any(|roots| roots[0] >= roots[1])
            {
                bail!("filter roots must be sorted and unique");
            }
        }
        // `delete_excluded` is also a scan policy: with it, the coordinator
        // inspects the destination unfiltered, and the receiver requires
        // exactly that. It therefore stays meaningful when deletion is
        // forbidden (a dry run, or a zero deletion budget); the receiver's
        // deletion policy still refuses every actual removal.
        Ok(())
    }
}

/// Precondition on the placement root itself. The receiver checks it once
/// against the confinement root when the copy starts, and `New`
/// additionally forces no-replace creation of that root, so a remote source
/// coordinator cannot turn `--into-new` into an update of an existing tree.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum RootExistence {
    #[default]
    Any,
    /// The destination must not exist when the copy starts.
    New,
    /// The destination must already exist when the copy starts; a
    /// directory placement additionally requires a directory.
    Existing,
}

/// Copy options beyond `CopyOptions`.
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
    /// copy goes into the directory it resolves to inside the confinement root.
    pub follow_dst: bool,
}

/// Which existing destination directories the receiver may briefly give the
/// owner permission the copy needs, as `--widen-dirs` names them: none, the
/// ones the copy includes, or also the directory the copy goes into. Never
/// one above the confinement root.
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

/// Check the rules derived for a destination before a receiver uses them:
/// bounded, consistent, and with filter roots sorted as the receiver matches
/// them.
pub(crate) fn validate_rules(
    copy: &CopyOperation,
    constraints: &mut GrantConstraints,
) -> Result<()> {
    copy.validate()?;
    constraints.filters.normalize();
    constraints.filters.validate(copy)?;
    constraints.receipt_policy.validate()?;
    if let Some(algorithm) = &constraints.tcp_congestion {
        crate::cli::parse_tcp_congestion(algorithm).map_err(anyhow::Error::msg)?;
    }
    if let Some(expected) = constraints
        .hashing
        .as_ref()
        .and_then(|hashing| hashing.expected_hash.as_ref())
    {
        expected.validate()?;
    }
    if constraints.mapping.is_some() && copy.policy.deletion != DeletionPolicy::Forbid {
        bail!("mapping authorization does not permit pruning");
    }
    if constraints.extra_options.acls && !copy.options.preserve_permissions {
        bail!("ACL preservation requires permission preservation");
    }
    Ok(())
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

/// Check an account name: bounded, without control characters or `/`.
pub(crate) fn validate_identity(name: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_LOGIN_BYTES {
        bail!("the {name} name's length is outside the supported range");
    }
    if value
        .chars()
        .any(|character| character.is_control() || character == '/')
    {
        bail!("the {name} name contains a forbidden character");
    }
    Ok(())
}

fn validate_absolute_path(path: &[u8]) -> Result<()> {
    if path.is_empty() || path.len() > MAX_PATH_BYTES || path[0] != b'/' {
        bail!("destination must be a bounded absolute path");
    }
    if path.contains(&0) {
        bail!("destination contains NUL");
    }
    if path == b"/" {
        return Ok(());
    }
    if path.ends_with(b"/") {
        bail!("destination has a noncanonical trailing slash");
    }
    for component in path[1..].split(|byte| *byte == b'/') {
        if component.is_empty() || component == b"." || component == b".." {
            bail!("destination has a noncanonical path component");
        }
    }
    Ok(())
}

pub(crate) fn validate_canonical_sshsig(signature: &[u8]) -> Result<()> {
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

/// What a receiver expects of a directive: its own enrollment, generation,
/// account and build, and the time it observed.
pub(crate) struct ReceiverContext<'a> {
    pub enrollment_id: EnrollmentId,
    pub generation: u64,
    pub target_login: &'a str,
    pub build: &'a str,
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

    /// Check the directive's binding and times, and return the latest the
    /// time can be now.
    fn validate_at(&self, directive: &Directive, observed_at: Instant) -> Result<i64> {
        let (earliest_now, latest_now) = self.wall_time_bounds_at(observed_at)?;
        self.enrollment_id.validate()?;
        validate_identity("expected account", self.target_login)?;
        if !(0..=MAX_UNIX_TIMESTAMP).contains(&earliest_now)
            || !(0..=MAX_UNIX_TIMESTAMP).contains(&latest_now)
        {
            bail!("receiver clock is outside the supported range");
        }
        if !(0..=MAX_CLOCK_SKEW_SECS).contains(&self.clock_skew_seconds) {
            bail!("receiver clock skew allowance is outside the supported range");
        }
        let binding = &directive.binding;
        if directive.build != self.build {
            bail!(
                "the copy was approved for a receiver of syq {}, and this receiver runs {}",
                directive.build,
                self.build
            );
        }
        if binding.enrollment != self.enrollment_id {
            bail!("the directive is for a different enrollment");
        }
        if binding.generation != self.generation {
            bail!(
                "the directive is for generation {} of enrollment {}, which is now at generation {}",
                binding.generation,
                self.enrollment_id,
                self.generation
            );
        }
        if binding.account != self.target_login {
            bail!("the directive is for a different account");
        }
        let latest_acceptable_issue = earliest_now
            .checked_add(self.clock_skew_seconds)
            .ok_or_else(|| anyhow!("receiver time overflow"))?;
        if directive.issued_at > latest_acceptable_issue {
            bail!("the directive was issued too far in the future");
        }
        let latest_for_start = earliest_now
            .checked_add(self.clock_skew_seconds)
            .ok_or_else(|| anyhow!("receiver time overflow"))?;
        if latest_for_start < directive.not_before {
            bail!("the directive is not yet valid");
        }
        let earliest_for_expiry = latest_now
            .checked_sub(self.clock_skew_seconds)
            .ok_or_else(|| anyhow!("receiver time overflow"))?;
        if earliest_for_expiry > directive.start_by {
            bail!("the directive's start-by time has passed");
        }
        Ok(latest_now)
    }
}

/// The login key a receiver trusts to sign its directives, with what each
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
        if let Some(bits) = rsa_bits(key.key_data()) {
            if bits < MIN_RSA_BITS {
                bail!("RSA login keys need at least {MIN_RSA_BITS} bits; this one has {bits}");
            }
            if bits > MAX_RSA_BITS {
                bail!(
                    "syq checks RSA login keys of up to {MAX_RSA_BITS} bits; this one has {bits}"
                );
            }
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
        let signed = ssh_key::SshSig::signed_data(namespace, signature.hash_alg(), payload)?;
        verify_signature(key.key_data(), &signed, signature.signature())
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

/// The largest RSA login key syq checks signatures from.
pub(crate) const MAX_RSA_BITS: usize = 16384;
/// The smallest RSA login key a receiver trusts.
pub(crate) const MIN_RSA_BITS: usize = 2048;

/// The size of an RSA key's modulus in bits.
pub(crate) fn rsa_bits(key: &ssh_key::public::KeyData) -> Option<usize> {
    let modulus = key.rsa()?.n.as_positive_bytes()?;
    Some(modulus.first().map_or(0, |first| {
        modulus.len() * 8 - first.leading_zeros() as usize
    }))
}

/// Check `signature` over `data` with `key`. RSA goes through the rsa crate
/// directly: ssh-key 0.6.7 builds RSA public keys with
/// `rsa::RsaPublicKey::new`, which refuses moduli over 4,096 bits, so
/// signatures from larger login keys would never verify.
pub(crate) fn verify_signature(
    key: &ssh_key::public::KeyData,
    data: &[u8],
    signature: &ssh_key::Signature,
) -> Result<()> {
    use signature::Verifier as _;
    let Some(rsa_key) = key.rsa() else {
        return key
            .verify(data, signature)
            .map_err(|_| anyhow!("the signature does not verify"));
    };
    let public = rsa::RsaPublicKey::new_with_max_size(
        rsa::BigUint::from_bytes_be(rsa_key.n.as_positive_bytes().context("RSA modulus")?),
        rsa::BigUint::from_bytes_be(rsa_key.e.as_positive_bytes().context("RSA exponent")?),
        MAX_RSA_BITS,
    )
    .context("unsupported RSA key")?;
    let rsa_signature = rsa::pkcs1v15::Signature::try_from(signature.as_bytes())
        .map_err(|_| anyhow!("malformed RSA signature"))?;
    let verified = match signature.algorithm() {
        ssh_key::Algorithm::Rsa {
            hash: Some(HashAlg::Sha256),
        } => rsa::pkcs1v15::VerifyingKey::<sha2_compat::Sha256>::new(public)
            .verify(data, &rsa_signature),
        ssh_key::Algorithm::Rsa {
            hash: Some(HashAlg::Sha512),
        } => rsa::pkcs1v15::VerifyingKey::<sha2_compat::Sha512>::new(public)
            .verify(data, &rsa_signature),
        algorithm => bail!("an RSA key cannot have made a {algorithm} signature"),
    };
    verified.map_err(|_| anyhow!("the signature does not verify"))
}

/// The armored SSHSIG of `signature`, made by `key` over a message hashed
/// with `hash` in `namespace`.
///
/// Syq writes the blob itself instead of using `ssh_key::SshSig::to_pem`.
/// In ssh-key 0.6.7, `Signature`'s `Encode` splits off the flags byte and
/// counter of a FIDO signature only for `sk-ssh-ed25519@openssh.com`; for
/// `sk-ecdsa-sha2-nistp256@openssh.com` it writes them inside the signature
/// string. `SshSig::from_pem` then fails on the result with "length
/// invalid", and OpenSSH cannot read it either, so every directive signed
/// with a FIDO ECDSA login key would be refused. Decoding is correct.
pub(crate) fn armored_sshsig(
    key: &ssh_key::public::KeyData,
    namespace: &str,
    hash: HashAlg,
    signature: &ssh_key::Signature,
) -> Result<Vec<u8>> {
    use ssh_agent_lib::ssh_encoding::Encode as _;
    let mut encoded = Vec::new();
    signature.algorithm().as_str().encode(&mut encoded)?;
    let bytes = signature.as_bytes();
    match signature.algorithm() {
        ssh_key::Algorithm::SkEd25519 | ssh_key::Algorithm::SkEcdsaSha2NistP256 => {
            // The flags byte and the 4-byte counter follow the signature.
            let split = bytes
                .len()
                .checked_sub(5)
                .context("truncated FIDO signature")?;
            bytes[..split].encode(&mut encoded)?;
            encoded.extend_from_slice(&bytes[split..]);
        }
        _ => bytes.encode(&mut encoded)?,
    }
    let mut blob = b"SSHSIG".to_vec();
    1u32.encode(&mut blob)?;
    key.encode_prefixed(&mut blob)?;
    namespace.encode(&mut blob)?;
    b"".as_slice().encode(&mut blob)?;
    hash.as_str().encode(&mut blob)?;
    encoded.encode(&mut blob)?;
    Ok(canonical_sshsig_armor(&blob))
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

/// The destination's rules beyond the copy operation.
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

/// Evidence that the signature, binding, time bounds, and one-time replay
/// redeem of a directive all succeeded.
#[derive(Debug)]
pub(crate) struct VerifiedDirective {
    /// Binds the destination's results to this directive.
    pub digest: [u8; 32],
    pub execution_deadline: Instant,
}

/// Verify `encoded` against `context` and `signer`, derive what it allows
/// with `derive`, and only then record it as used. Nothing is recorded for
/// a directive that any check, or the derivation, refuses.
pub(crate) fn verify_and_redeem<T>(
    encoded: &[u8],
    context: &ReceiverContext<'_>,
    signer: &TrustedSigner,
    replay: &ReplayStore,
    derive: impl FnOnce(&Directive) -> Result<T>,
) -> Result<(T, VerifiedDirective)> {
    let signed = crate::directive::Signed::decode(encoded)?;
    let directive = &signed.directive;
    let observed_at = Instant::now();
    context.validate_at(directive, observed_at)?;
    let replay_digest: [u8; 32] = Sha256::digest(&signed.payload).into();
    replay.reject_if_redeemed(directive.request_id, replay_digest)?;
    // A certificate's expiry is judged with the clock skew in the signer's
    // favour, like the directive's own start-by time.
    let (_, latest_now) = context.wall_time_bounds_at(observed_at)?;
    signer.verify(
        crate::directive::NAMESPACE,
        &signed.payload,
        &signed.signature,
        latest_now.saturating_sub(context.clock_skew_seconds),
    )?;
    // Only a signed command reaches the parser, and a directive whose rules
    // cannot be derived stays unused.
    let derived = derive(directive)?;
    replay.redeem_after_lock(directive.request_id, replay_digest, || {
        context.validate_at(directive, Instant::now())
    })?;
    let verified_at = Instant::now();
    let verified_wall_time = context.validate_at(directive, verified_at)?;
    let execution_deadline = execution_deadline(
        directive.finish_by,
        context.clock_skew_seconds,
        verified_wall_time,
        verified_at,
    )?;
    Ok((
        derived,
        VerifiedDirective {
            digest: signed.digest(),
            execution_deadline,
        },
    ))
}

fn execution_deadline(
    finish_by: i64,
    clock_skew_seconds: i64,
    current_wall_time: i64,
    verified_at: Instant,
) -> Result<Instant> {
    let finish_by = finish_by
        .checked_add(clock_skew_seconds)
        .ok_or_else(|| anyhow!("directive finish-by overflow"))?;
    let remaining = finish_by
        .checked_sub(current_wall_time)
        .ok_or_else(|| anyhow!("directive remaining finish window overflow"))?;
    if remaining <= 0 {
        bail!("the directive's finish-by time passed while it was being verified");
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
        bail!("request ID was already redeemed by a different directive");
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

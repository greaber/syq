//! End-to-end enrollment and signed restricted-transfer integration.

mod active;
mod ssh;
pub(crate) use ssh::start as start_ssh_workers;

use crate::cli::{Args, Existence, Location, Placement};
use crate::delegation::{
    self, CopyLimits, CopyOperation, CopyOptions, CopyPolicy, DeletionPolicy, DestinationPlacement,
    ExistingDestinationPolicy, FilterPolicy, Grant, GrantConstraints, GrantOperation,
    MutationScope, PublicationPolicy, RequestId, RootExistence,
};
use crate::enrollment::{
    self, AuthorizedKeyEntry, AuthorizedKeysChange, EnrollmentId, EnrollmentPublicKey,
    EnrollmentRoute, SshEndpoint,
};
use crate::proto::{self, ContainerGuard, Op, Request};
use crate::rooted::{RelativePath, Root, RootIdentity, RootMetadata};
use anyhow::{bail, Context, Result};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use ssh_key::private::Ed25519Keypair;
use ssh_key::{LineEnding, PrivateKey};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Instant;
use std::time::{SystemTime, UNIX_EPOCH};

// Advance this generation whenever an installed receiver or its signed grant
// protocol becomes incompatible. Local metadata from another generation is
// ignored, so the next eligible copy installs a fresh receiver enrollment.
const CONFIG_VERSION: u16 = 4;
const MAX_STATE_FILE: usize = 256 * 1024;
const MAX_AUTHORIZED_KEYS: usize = 16 * 1024 * 1024;
const DEFAULT_MAX_ENTRIES: u64 = 100_000_000;
const DEFAULT_MAX_BYTES: u64 = 8 * 1024 * 1024 * 1024 * 1024;
/// A grant must be redeemed within this long of being issued.
const GRANT_VALIDITY_SECONDS: i64 = 24 * 60 * 60;
/// A transfer must finish within this long of its grant being issued.
const FINISH_WINDOW_SECONDS: i64 = 7 * 24 * 60 * 60;
const CLOCK_SKEW_SECONDS: i64 = 60;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ReceiverEnrollment {
    version: u16,
    pub(crate) id: EnrollmentId,
    pub(crate) target_login: String,
    pub(crate) signer: String,
    pub(crate) root: String,
    pub(crate) root_dev: u64,
    pub(crate) root_ino: u64,
    pub(crate) ssh_keygen: String,
    pub(crate) receiver_path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct InstallRequest {
    version: u16,
    id: EnrollmentId,
    target_login: String,
    requested_destination: String,
    public_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct InstallResponse {
    version: u16,
    id: EnrollmentId,
    target_login: String,
    remote_home: String,
    requested_parent: String,
    canonical_root: String,
    canonical_destination: String,
    receiver_path: String,
    /// OpenSSH public key of the receipt signing key hostB generated for
    /// this enrollment; the local side verifies receipts against it.
    receipt_public_key: String,
    change: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RevokeRequest {
    version: u16,
    id: EnrollmentId,
    target_login: String,
    public_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LocalEnrollment {
    version: u16,
    id: EnrollmentId,
    host: String,
    #[serde(default)]
    port: Option<u16>,
    target_login: String,
    remote_home: String,
    requested_parent: String,
    canonical_root: String,
    receiver_path: String,
    receipt_public_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PendingEnrollment {
    version: u16,
    id: EnrollmentId,
    host: String,
    #[serde(default)]
    port: Option<u16>,
    target_login: String,
    requested_destination: String,
}

pub(crate) struct PreparedTransfer {
    pub(crate) private_key: PrivateKey,
    pub(crate) canonical_destination: Vec<u8>,
    pub(crate) grant: String,
    pub(crate) enrollment_id: EnrollmentId,
    /// The nonce the grant was signed with; the receipt must name it.
    pub(crate) request_id: RequestId,
    /// Verifier for the receipt hostB will issue.
    pub(crate) receipt_public_key: String,
    /// Attached transfers keep this ephemeral HPKE key only until settlement.
    pub(crate) receipt_recipient_secret: Option<crate::receipt::RecipientSecret>,
    pub(crate) receipt_policy: crate::receipt::ReceiptPolicy,
    pub(crate) grant_digest: [u8; 32],
}

struct AuthorityState {
    paths: HashSet<Vec<u8>>,
    receiver_modes: HashMap<Vec<u8>, ReceiverModeState>,
    /// Objects this grant created and the executor confirmed. The
    /// existing-object policy is about what existed before the transfer, so
    /// later operations on these are the transfer's own business.
    created: HashSet<Vec<u8>>,
    /// Creations authorized but not yet confirmed or rolled back. They never
    /// grant the shortcut above: a second creation of the same path races at
    /// the kernel instead of trusting an outcome that has not happened yet.
    provisional: HashSet<Vec<u8>>,
    /// Bytes each staged or in-place file may occupy on disk, keyed by the
    /// destination path and the partial this grant declared for it:
    /// preallocation and basis seeding are charged against the aggregate
    /// ceiling here, once per file at its largest declared size, and every
    /// write or publication must name a declared partial. Observation-only
    /// preparations own separate provisional holds so an older absent
    /// observation cannot roll back a newer preparation for the same key.
    reserved: HashMap<(Vec<u8>, proto::CopyId), ByteReservation>,
    reserved_bytes: u64,
    next_reservation_hold: u64,
    transferred_bytes: u64,
    deletions: u64,
    live_connections: u16,
    tcp_listener_started: bool,
    /// What hostB will attest to in its receipt.
    /// Receipt records live in an anonymous spool; only mutation-relevant paths
    /// enter `touched`, never paths merely returned by a destination scan.
    receipt_stream: Option<crate::receipt::ReceiptStreamWriter>,
    touched: BTreeSet<Vec<u8>>,
    file_lifecycles: HashMap<(Vec<u8>, proto::CopyId), FileLifecycle>,
    /// Requests authorized for execution whose outcome has not been settled
    /// yet, across every connection. The receipt waits for zero.
    in_flight: u64,
    /// Set when the receipt is being issued: no new mutation is authorized
    /// from then on, so the receipt describes a final state.
    receipt_closing: bool,
    receipt_issued: bool,
}

#[derive(Clone, Copy, Debug)]
enum ReceiverModeState {
    /// Keep the permissions HostB had before syq temporarily opened an
    /// existing object or prepared to replace its contents.
    Existing {
        mode: u32,
        kind: ReceiverModeKind,
        dev: u64,
        ino: u64,
        ctime: i64,
        ctime_nsec: u32,
    },
    /// The object will be created by this transfer. Its proposed source mode
    /// has not yet been constrained by HostB's umask.
    New(ReceiverModeKind),
    /// A new object's already-constrained mode. Pin it for the remainder of
    /// the grant so repeated requests cannot act as repeated chmod calls.
    Selected { mode: u32, kind: ReceiverModeKind },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct ReservationHoldId(u64);

#[derive(Debug, Default)]
struct ByteReservation {
    /// Capacity retained by a preparation that may have created, resized, or
    /// reused the write target.
    retained: Option<u64>,
    /// Capacity provisionally held by observation-only preparations until
    /// their individual outcomes are settled.
    observations: HashMap<ReservationHoldId, u64>,
}

impl ByteReservation {
    fn effective_size(&self) -> Option<u64> {
        self.retained
            .into_iter()
            .chain(self.observations.values().copied())
            .max()
    }
}

impl ReceiverModeState {
    fn carry_forward(self, observed: Self) -> Option<Self> {
        match (self, observed) {
            (
                Self::Existing {
                    mode,
                    kind,
                    dev,
                    ino,
                    ..
                },
                Self::Existing {
                    mode: observed_mode,
                    kind: observed_kind,
                    dev: observed_dev,
                    ino: observed_ino,
                    ctime: observed_ctime,
                    ctime_nsec: observed_ctime_nsec,
                },
            ) if kind == observed_kind && (dev, ino) == (observed_dev, observed_ino) => {
                let mode = if kind == ReceiverModeKind::Directory && observed_mode == (mode | 0o700)
                {
                    mode
                } else {
                    observed_mode
                };
                Some(Self::Existing {
                    mode,
                    kind,
                    dev,
                    ino,
                    ctime: observed_ctime,
                    ctime_nsec: observed_ctime_nsec,
                })
            }
            (Self::New(kind), Self::New(observed_kind))
            | (Self::Selected { kind, .. }, Self::New(observed_kind))
            | (
                Self::New(kind),
                Self::Existing {
                    kind: observed_kind,
                    ..
                },
            )
            | (
                Self::Selected { kind, .. },
                Self::Existing {
                    kind: observed_kind,
                    ..
                },
            ) if kind == observed_kind => Some(self),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReceiverModeKind {
    Directory,
    RegularFile,
    Other,
}

#[derive(Clone, Copy)]
enum ReceiverModeTarget {
    AnyExisting,
    RegularFile,
}

#[derive(Clone, Copy)]
struct ReceiverModeDecision {
    mode: u32,
    identity: Option<(u64, u64, i64, u32)>,
}

#[derive(Clone, Debug)]
struct ReceiverControlPath {
    path: Vec<u8>,
    label: &'static str,
}

fn path_is_at_or_below(path: &[u8], prefix: &[u8]) -> bool {
    path == prefix
        || (path.starts_with(prefix) && (prefix == b"/" || path.get(prefix.len()) == Some(&b'/')))
}

fn paths_overlap(left: &[u8], right: &[u8]) -> bool {
    path_is_at_or_below(left, right) || path_is_at_or_below(right, left)
}

fn reject_control_plane_path(path: &[u8], protected: &[ReceiverControlPath]) -> Result<()> {
    if let Some(control) = protected
        .iter()
        .find(|control| paths_overlap(path, &control.path))
    {
        bail!(
            "command-restricted destination {} overlaps the receiver's protected {} {}; choose a destination outside the receiver control plane",
            Path::new(OsStr::from_bytes(path)).display(),
            control.label,
            Path::new(OsStr::from_bytes(&control.path)).display()
        );
    }
    Ok(())
}

fn reject_control_plane_scopes(
    copy: &CopyOperation,
    protected: &[ReceiverControlPath],
) -> Result<()> {
    for scope in &copy.mutation_scopes {
        reject_control_plane_path(&scope.path, protected)?;
    }
    Ok(())
}

#[cfg(not(test))]
fn read_process_umask() -> u32 {
    // main captured the mask before any thread existed.
    crate::fsops::process_umask()
}

#[cfg(test)]
fn read_process_umask() -> u32 {
    // Avoid changing the process-global umask while unit tests run in
    // parallel. Individual policy tests can override the stored value.
    0o022
}

/// Shared capability inherited by the authorized SSH control process and all
/// of its token-authenticated TCP workers. HostA may choose protocol messages,
/// but it cannot remove or replace this receiver-side authority.
pub(crate) struct RestrictedAuthority {
    guard: ContainerGuard,
    destination: Vec<u8>,
    copy: CopyOperation,
    filters: FilterPolicy,
    filter_matcher: Option<ignore::gitignore::Gitignore>,
    filter_roots: Vec<Vec<u8>>,
    root_existence: RootExistence,
    enrollment_id: EnrollmentId,
    request_id: RequestId,
    receipt_policy: crate::receipt::ReceiptPolicy,
    grant_digest: [u8; 32],
    receipt_key: PrivateKey,
    file_data_limit: Option<crate::bwlimit::BandwidthLimit>,
    receiver_umask: u32,
    deadline: Instant,
    control_open: AtomicBool,
    state: Mutex<AuthorityState>,
    /// Signalled whenever an in-flight request settles.
    settled: std::sync::Condvar,
    tcp_congestion: Option<String>,
    mapping: Option<Mutex<crate::mapping::Admission>>,
    hashing: Option<crate::hashing::CopyHashing>,
}

impl RestrictedAuthority {
    pub(crate) fn hash_policy(&self) -> crate::hashing::HashPolicy {
        self.hashing.as_ref().map_or(
            crate::hashing::HashPolicy {
                algorithm: crate::hashing::HashAlgorithm::Blake3,
                transfer_integrity: true,
                transfer_hash_type: None,
            },
            |hashing| hashing.policy,
        )
    }

    fn expected_digest(&self, path: &[u8]) -> Result<Option<crate::hashing::Digest>> {
        if let Some(mapping) = &self.mapping {
            return Ok(mapping
                .lock()
                .unwrap()
                .expected_digest(self.mapping_relative(path)?)?
                .cloned());
        }
        let selected = match self.copy.policy.placement {
            DestinationPlacement::ExactPath => path == self.destination,
            _ => {
                path != self.destination
                    && self
                        .copy
                        .mutation_scopes
                        .iter()
                        .any(|scope| scope.path == path)
            }
        };
        Ok(selected
            .then(|| {
                self.hashing
                    .as_ref()
                    .and_then(|hashing| hashing.expected_digest.clone())
            })
            .flatten())
    }

    fn new(
        config: &ReceiverEnrollment,
        grant: Grant,
        extensions: GrantConstraints,
        grant_digest: [u8; 32],
        receipt_key: PrivateKey,
        deadline: Instant,
        protected: &[ReceiverControlPath],
    ) -> Result<Self> {
        let GrantConstraints {
            max_file_data_bytes_per_second,
            filters,
            root_existence,
            receipt_policy,
            tcp_congestion,
            mapping,
            hashing,
        } = extensions;
        let enrollment_id = grant.enrollment_id;
        let request_id = grant.request_id;
        let GrantOperation::Copy(copy) = grant.operation;
        reject_control_plane_scopes(&copy, protected)?;
        if copy.policy.existing == ExistingDestinationPolicy::UpdateIfOlder {
            // The comparison depends on a source mtime only the remote
            // coordinator reports, so the receiver cannot enforce it.
            bail!("update-if-older existing-object policy is not enforceable by the receiver");
        }
        if copy.policy.publication == PublicationPolicy::InPlace
            && (copy.policy.existing != ExistingDestinationPolicy::Replace
                || (root_existence == RootExistence::New
                    && copy.policy.placement == DestinationPlacement::ExactPath))
        {
            // In-place preparation opens, creates, or replaces the final
            // pathname with no condition to attach, so it can neither retain
            // a pre-existing object nor be pinned to one.
            bail!("in-place publication cannot honor a signed existing-object policy");
        }
        let filter_matcher = crate::scan::build_ignore(&filters.ignore)?;
        let filter_roots = filters.destination_roots.clone();
        let root_path = Path::new(&config.root);
        let destination = Path::new(std::ffi::OsStr::from_bytes(&copy.destination));
        let relative = destination.strip_prefix(root_path).with_context(|| {
            format!(
                "signed destination {} is outside enrolled root {}",
                destination.display(),
                root_path.display()
            )
        })?;
        if relative.as_os_str().is_empty() {
            bail!("signed destination must be a child of the enrolled root");
        }
        crate::rooted::RelativePath::new(relative.as_os_str().as_bytes())?;
        Root::open_verified(
            root_path,
            RootIdentity {
                dev: config.root_dev,
                ino: config.root_ino,
            },
        )?;
        let receiver_umask = read_process_umask();
        let file_data_limit = (max_file_data_bytes_per_second > 0)
            .then(|| crate::bwlimit::BandwidthLimit::new(max_file_data_bytes_per_second));
        let receipt_stream = Some(crate::receipt::ReceiptStreamWriter::new(&receipt_policy)?);
        let authority = Self {
            hashing,
            tcp_congestion,
            mapping: mapping.map(|authorization| {
                Mutex::new(crate::mapping::Admission::new(
                    authorization,
                    copy.limits.max_entries,
                ))
            }),
            guard: ContainerGuard {
                root: config.root.as_bytes().to_vec(),
                dev: config.root_dev,
                ino: config.root_ino,
            },
            destination: copy.destination.clone(),
            copy,
            filters,
            filter_matcher,
            filter_roots,
            root_existence,
            enrollment_id,
            request_id,
            receipt_policy,
            grant_digest,
            receipt_key,
            file_data_limit,
            receiver_umask,
            deadline,
            control_open: AtomicBool::new(true),
            settled: std::sync::Condvar::new(),
            state: Mutex::new(AuthorityState {
                paths: HashSet::new(),
                receiver_modes: HashMap::new(),
                created: HashSet::new(),
                provisional: HashSet::new(),
                reserved: HashMap::new(),
                reserved_bytes: 0,
                next_reservation_hold: 0,
                transferred_bytes: 0,
                deletions: 0,
                live_connections: 0,
                tcp_listener_started: false,
                receipt_stream,
                touched: BTreeSet::new(),
                file_lifecycles: HashMap::new(),
                in_flight: 0,
                receipt_closing: false,
                receipt_issued: false,
            }),
        };
        authority.check_root_existence()?;
        Ok(authority)
    }

    /// Sign hostB's account of this grant and close it to further mutation.
    pub(crate) fn issue_receipt(&self) -> Result<crate::receipt::IssuedReceipt> {
        let key = &self.receipt_key;
        let policy = self.receipt_policy.clone();
        // Close the grant first, then wait for every request already
        // authorized on any connection to execute and settle, so the receipt
        // describes a final state rather than a snapshot with work in flight.
        let mut state = self.state.lock().unwrap();
        if state.receipt_issued || state.receipt_closing {
            bail!("the receipt for this grant has already been issued");
        }
        state.receipt_closing = true;
        while state.in_flight > 0 {
            let remaining = self
                .deadline
                .checked_duration_since(Instant::now())
                .unwrap_or_default();
            if remaining.is_zero() {
                bail!(
                    "{} request(s) were still in flight at the grant deadline; no receipt can be issued",
                    state.in_flight
                );
            }
            state = self.settled.wait_timeout(state, remaining).unwrap().0;
        }
        state.receipt_issued = true;
        let mut stream = state
            .receipt_stream
            .take()
            .context("receiver receipt spool is unavailable")?;
        let lifecycles = std::mem::take(&mut state.file_lifecycles);
        let touched = std::mem::take(&mut state.touched);
        let entries_touched = touched.len() as u64;
        let transferred_bytes = state.transferred_bytes;
        drop(state);

        for ((path, _), lifecycle) in lifecycles {
            if lifecycle.recorded {
                continue;
            }
            self.append_operation_to_stream(
                &mut stream,
                &path,
                crate::receipt::OperationAction::PublishFile {
                    size: lifecycle.size,
                    inplace: lifecycle.inplace,
                },
                if lifecycle.last_error.is_some() {
                    crate::receipt::OperationDisposition::Failed
                } else {
                    crate::receipt::OperationDisposition::Incomplete
                },
                lifecycle.last_error.as_deref().or(Some(
                    "file lifecycle ended without a successful finalization",
                )),
            );
        }

        for path in touched {
            let object = match self.observe_final(&path) {
                Ok(None) => crate::receipt::FinalObject::Absent,
                Ok(Some(metadata)) => {
                    let kind = kind_from_mode(metadata.mode);
                    let mut observation_error = None;
                    let digest = if kind == proto::Kind::File && policy.hashed {
                        match self.digest_published(&path) {
                            Ok(digest) => Some(digest),
                            Err(error) => {
                                observation_error = crate::receipt::bounded_format(format_args!(
                                    "hash final file: {error:#}"
                                ));
                                None
                            }
                        }
                    } else {
                        None
                    };
                    let symlink_target = if kind == proto::Kind::Symlink {
                        match self.read_published_link(&path) {
                            Ok(target) => Some(target),
                            Err(error) => {
                                observation_error = crate::receipt::bounded_format(format_args!(
                                    "read final symlink: {error:#}"
                                ));
                                None
                            }
                        }
                    } else {
                        None
                    };
                    crate::receipt::FinalObject::Present {
                        kind,
                        size: metadata.len,
                        digest,
                        symlink_target,
                        metadata: crate::receipt::ObjectMetadata {
                            mode: metadata.mode,
                            uid: metadata.uid,
                            gid: metadata.gid,
                            mtime: metadata.mtime,
                            mtime_nsec: metadata.mtime_nsec,
                            rdev: metadata.rdev,
                        },
                        observation_error,
                    }
                }
                Err(error) => crate::receipt::FinalObject::ObservationFailed {
                    code: crate::receipt::OutcomeCode::ObservationFailed,
                    diagnostic: crate::receipt::bounded_format(format_args!("{error:#}")),
                },
            };
            let Some((scope, relative)) = self.receipt_location(&path) else {
                stream.mark_recording_failure();
                continue;
            };
            let sequence = stream.next_sequence();
            stream.append(&crate::receipt::ReceiptRecord::FinalState(
                crate::receipt::FinalStateReceiptRecord {
                    sequence,
                    scope,
                    path: relative,
                    object,
                },
            ));
        }
        stream.finish(crate::receipt::ReceiptClosure {
            enrollment_id: self.enrollment_id,
            request_id: self.request_id,
            grant_digest: self.grant_digest,
            issued_at: now()?,
            policy,
            entries_touched,
            transferred_bytes,
            signing_key: key,
        })
    }

    /// Metadata of a touched path in the final tree, with a missing path or
    /// a missing ancestor reported as absent rather than as an error.
    fn observe_final(&self, path: &[u8]) -> Result<Option<RootMetadata>> {
        match self.rooted_metadata(path) {
            Ok(observed) => Ok(observed),
            Err(error)
                if error.chain().any(|cause| {
                    cause
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound)
                }) =>
            {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    /// BLAKE3 of a file this grant published, read back through the root.
    fn digest_published(&self, path: &[u8]) -> Result<[u8; 32]> {
        let root_path = Path::new(OsStr::from_bytes(&self.guard.root));
        let relative = Path::new(OsStr::from_bytes(path))
            .strip_prefix(root_path)
            .context("published path is outside the enrolled root")?;
        let relative = RelativePath::new(relative.as_os_str().as_bytes())?;
        let root = Root::open_verified(
            root_path,
            RootIdentity {
                dev: self.guard.dev,
                ino: self.guard.ino,
            },
        )?;
        let mut file = root.open_regular_read(&relative)?;
        let mut hasher = blake3::Hasher::new();
        std::io::copy(&mut file, &mut hasher)?;
        Ok(*hasher.finalize().as_bytes())
    }

    fn read_published_link(&self, path: &[u8]) -> Result<Vec<u8>> {
        let root_path = Path::new(OsStr::from_bytes(&self.guard.root));
        let relative = Path::new(OsStr::from_bytes(path))
            .strip_prefix(root_path)
            .context("published path is outside the enrolled root")?;
        let relative = RelativePath::new(relative.as_os_str().as_bytes())?;
        let root = Root::open_verified(
            root_path,
            RootIdentity {
                dev: self.guard.dev,
                ino: self.guard.ino,
            },
        )?;
        root.read_link(&relative)
    }

    /// Check the signed placement-root precondition once, against the
    /// enrolled root, before any request is served. `New` is then kept true
    /// by `constrain_creation`, which forces no-replace creation of the root.
    fn check_root_existence(&self) -> Result<()> {
        let observed = self.rooted_metadata(&self.destination)?;
        let destination = String::from_utf8_lossy(&self.destination);
        match (self.root_existence, observed) {
            (RootExistence::Any, _) => Ok(()),
            (RootExistence::New, Some(_)) => bail!(
                "signed destination {destination} already exists, but the grant requires a new path"
            ),
            (RootExistence::New, None) => Ok(()),
            (RootExistence::Existing, None) => bail!(
                "signed destination {destination} does not exist, but the grant requires an existing path"
            ),
            (RootExistence::Existing, Some(metadata))
                if self.copy.policy.placement != DestinationPlacement::ExactPath
                    && !metadata.is_dir() =>
            {
                bail!(
                    "signed destination {destination} is not a directory, but the grant places names inside it"
                )
            }
            (RootExistence::Existing, Some(_)) => Ok(()),
        }
    }

    pub(crate) fn validate_hello(&self, compressed: bool) -> Result<()> {
        if !self.control_is_open() {
            bail!("transfer control is closed or expired");
        }
        self.check_deadline()?;
        if compressed != self.copy.options.compressed_transport {
            bail!("transport compression does not match the signed grant");
        }
        Ok(())
    }

    pub(crate) fn control_is_open(&self) -> bool {
        self.control_open.load(Ordering::Acquire) && Instant::now() <= self.deadline
    }

    pub(crate) fn close_control(&self) {
        // Serialize revocation with admission: already-admitted work may
        // settle, but no new request can enter after this returns.
        let _state = self.state.lock().unwrap();
        self.control_open.store(false, Ordering::Release);
    }

    pub(crate) fn acquire_connection(&self) -> Result<()> {
        self.check_deadline()?;
        let mut state = self.state.lock().unwrap();
        if !self.control_is_open() {
            bail!("transfer control is closed or expired");
        }
        if state.live_connections >= self.copy.limits.max_connections {
            bail!("signed grant connection limit exceeded");
        }
        state.live_connections += 1;
        Ok(())
    }

    pub(crate) fn release_connection(&self) {
        let mut state = self.state.lock().unwrap();
        state.live_connections = state.live_connections.saturating_sub(1);
    }

    fn check_deadline(&self) -> Result<()> {
        if Instant::now() > self.deadline {
            bail!("signed transfer execution deadline has expired");
        }
        Ok(())
    }

    fn validate_request_path(path: &[u8]) -> Result<()> {
        if path.contains(&0)
            || !path.starts_with(b"/")
            || path
                .split(|byte| *byte == b'/')
                .skip(1)
                .any(|component| component.is_empty() || component == b"." || component == b"..")
        {
            bail!("signed receiver request contains a noncanonical path");
        }
        Ok(())
    }

    fn scope_allows(scope: &MutationScope, path: &[u8]) -> bool {
        path == scope.path
            || (scope.descendants
                && path.starts_with(&scope.path)
                && path.get(scope.path.len()) == Some(&b'/'))
    }

    fn filter_applies(&self, path: &[u8]) -> bool {
        self.filter_roots.iter().any(|root| {
            path == root || (path.starts_with(root) && path.get(root.len()) == Some(&b'/'))
        })
    }

    /// A mapped source root itself is never ignored. A destination path that
    /// can be supplied by several overlapping roots remains allowed when any
    /// one of those source-relative spellings is included.
    fn path_is_ignored(&self, path: &[u8], is_dir: bool) -> bool {
        let Some(matcher) = &self.filter_matcher else {
            return false;
        };
        let mut under_root = false;
        for root in &self.filter_roots {
            if path == root {
                return false;
            }
            if !path.starts_with(root) || path.get(root.len()) != Some(&b'/') {
                continue;
            }
            under_root = true;
            let relative = &path[root.len() + 1..];
            let relative = Path::new(OsStr::from_bytes(relative));
            let pruned_by_ancestor = relative.ancestors().skip(1).any(|ancestor| {
                !ancestor.as_os_str().is_empty() && matcher.matched(ancestor, true).is_ignore()
            });
            if !pruned_by_ancestor && !matcher.matched(relative, is_dir).is_ignore() {
                return false;
            }
        }
        under_root
    }

    /// Charge the on-disk size a prepared or seeded file will occupy against
    /// the signed aggregate byte ceiling. A path is charged once, at the
    /// largest size declared for it, so retries and resumes do not double
    /// count while many distinct preparations cannot exceed the ceiling.
    fn reserve_bytes(
        &self,
        path: &[u8],
        copy_id: proto::CopyId,
        size: u64,
        observation_only: bool,
    ) -> Result<Option<ReservationHoldId>> {
        let mut state = self.state.lock().unwrap();
        let key = (path.to_vec(), copy_id);
        let previous = state
            .reserved
            .get(&key)
            .and_then(ByteReservation::effective_size);
        // An existing declaration only grows; a new one is registered even at
        // zero length, so an empty file can still be published.
        let effective = previous.map_or(size, |previous| previous.max(size));
        let total = state
            .reserved_bytes
            .checked_add(effective - previous.unwrap_or(0))
            .context("signed reservation byte counter overflow")?;
        if total > self.copy.limits.max_total_bytes {
            bail!("signed grant total-byte limit exceeded by file preparation");
        }
        let hold = if observation_only {
            let hold = ReservationHoldId(state.next_reservation_hold);
            state.next_reservation_hold = state
                .next_reservation_hold
                .checked_add(1)
                .context("reservation hold counter overflow")?;
            Some(hold)
        } else {
            None
        };
        let reservation = state.reserved.entry(key).or_default();
        if let Some(hold) = hold {
            reservation.observations.insert(hold, size);
        } else {
            reservation.retained = Some(
                reservation
                    .retained
                    .map_or(size, |retained| retained.max(size)),
            );
        }
        state.reserved_bytes = total;
        Ok(hold)
    }

    /// Settle one observation's provisional reservation without disturbing
    /// holds installed by requests that ran before or after it.
    fn settle_observation_reservation(
        state: &mut AuthorityState,
        key: &(Vec<u8>, proto::CopyId),
        hold: ReservationHoldId,
        retain: bool,
    ) {
        let Some(reservation) = state.reserved.get_mut(key) else {
            return;
        };
        let before = reservation
            .effective_size()
            .expect("a stored reservation has at least one hold");
        let Some(size) = reservation.observations.remove(&hold) else {
            return;
        };
        if retain {
            reservation.retained = Some(
                reservation
                    .retained
                    .map_or(size, |retained| retained.max(size)),
            );
        }
        let after = reservation.effective_size();
        let released = before - after.unwrap_or(0);
        state.reserved_bytes = state
            .reserved_bytes
            .checked_sub(released)
            .expect("reservation settlement cannot underflow");
        if after.is_none() {
            state.reserved.remove(key);
        }
    }

    /// The size this grant declared for a partial, which bounds what may be
    /// written into it and what may be published from it. A partial left by
    /// an earlier grant has no declaration here and cannot be used.
    fn declared_size(&self, path: &[u8], copy_id: proto::CopyId) -> Result<u64> {
        self.state
            .lock()
            .unwrap()
            .reserved
            .get(&(path.to_vec(), copy_id))
            .and_then(ByteReservation::effective_size)
            .with_context(|| {
                format!(
                    "staged file {} was not declared under this grant",
                    String::from_utf8_lossy(path)
                )
            })
    }

    /// Refuse to publish a staged or in-place file that is larger than the
    /// size this grant declared for it.
    fn check_published_length(
        &self,
        path: &[u8],
        copy_id: proto::CopyId,
        inplace: bool,
    ) -> Result<()> {
        let declared = self.declared_size(path, copy_id)?;
        let staged = if inplace {
            path.to_vec()
        } else {
            crate::fsops::partial_path(Path::new(OsStr::from_bytes(path)), &copy_id)?
                .into_os_string()
                .into_vec()
        };
        if let Some(metadata) = self.rooted_metadata(&staged)? {
            if metadata.len > declared {
                bail!(
                    "staged file {} exceeds its declared size",
                    String::from_utf8_lossy(path)
                );
            }
        }
        Ok(())
    }

    /// Charge every entry a destination scan returns against the signed entry
    /// ceiling, so enumeration is bounded like every other observation.
    pub(crate) fn record_scanned<'a>(
        &self,
        root: &[u8],
        entries: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<()> {
        for relative in entries {
            if relative.is_empty() {
                continue;
            }
            self.record_path(&crate::fsops::join(root, relative))?;
        }
        Ok(())
    }

    fn record_path(&self, path: &[u8]) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        if state.paths.contains(path) {
            return Ok(());
        }
        // Check before inserting: a path rejected at the ceiling must not be
        // remembered, or resubmitting it would pass as already counted.
        if state.paths.len() as u64 >= self.copy.limits.max_entries {
            bail!("signed grant entry limit exceeded");
        }
        state.paths.insert(path.to_vec());
        Ok(())
    }

    fn mapping_relative<'a>(&self, path: &'a [u8]) -> Result<&'a [u8]> {
        if path == self.destination {
            return Ok(b"");
        }
        path.strip_prefix(self.destination.as_slice())
            .and_then(|relative| relative.strip_prefix(b"/"))
            .context("mapping path is outside the destination")
    }

    fn check_mapping_path(&self, path: &[u8], directory: Option<bool>) -> Result<()> {
        if let Some(mapping) = &self.mapping {
            let mapping = mapping.lock().unwrap();
            if !mapping
                .permissions()?
                .allows(self.mapping_relative(path)?, directory)
            {
                bail!("path is not authorized by the signed mapping");
            }
        }
        Ok(())
    }

    fn mapping_parent(&self, path: &[u8]) -> Result<bool> {
        match &self.mapping {
            Some(mapping) => Ok(mapping
                .lock()
                .unwrap()
                .permissions()?
                .implicit_directory(self.mapping_relative(path)?)),
            None => Ok(false),
        }
    }

    fn check_observation_path(&self, path: &[u8]) -> Result<()> {
        Self::validate_request_path(path)?;
        if path != self.destination
            && !self
                .copy
                .mutation_scopes
                .iter()
                .any(|scope| Self::scope_allows(scope, path))
        {
            bail!("receiver observation is outside the signed destination scopes");
        }
        self.check_mapping_path(path, None)?;
        self.record_path(path)
    }

    fn check_mutation_authority(&self, path: &[u8]) -> Result<()> {
        if self.copy.options.dry_run || self.copy.options.verify_only {
            bail!("signed read-only transfer forbids destination mutations");
        }
        let state = self.state.lock().unwrap();
        if state.receipt_issued || state.receipt_closing {
            bail!("the signed grant is closed: its receipt has been issued");
        }
        if state
            .receipt_stream
            .as_ref()
            .is_some_and(crate::receipt::ReceiptStreamWriter::is_failed)
        {
            bail!("the signed grant is closed because receipt recording failed");
        }
        drop(state);
        Self::validate_request_path(path)?;
        if !self
            .copy
            .mutation_scopes
            .iter()
            .any(|scope| Self::scope_allows(scope, path))
        {
            bail!("receiver mutation is outside the signed destination scopes");
        }
        Ok(())
    }

    fn check_mutation_path(&self, path: &[u8], is_dir: bool) -> Result<()> {
        self.check_mutation_authority(path)?;
        self.check_mapping_path(path, Some(is_dir))?;
        if self.path_is_ignored(path, is_dir) {
            bail!("receiver mutation targets a path excluded by the signed filter policy");
        }
        self.record_path(path)
    }

    fn created_by_this_grant(&self, path: &[u8]) -> bool {
        self.state.lock().unwrap().created.contains(path)
    }

    fn receipt_location(&self, path: &[u8]) -> Option<(u32, Vec<u8>)> {
        self.copy
            .mutation_scopes
            .iter()
            .enumerate()
            .filter(|(_, scope)| Self::scope_allows(scope, path))
            .max_by_key(|(index, scope)| (scope.path.len(), std::cmp::Reverse(*index)))
            .and_then(|(index, scope)| {
                let relative = if path == scope.path {
                    Vec::new()
                } else {
                    path.get(scope.path.len() + 1..)?.to_vec()
                };
                Some((u32::try_from(index).ok()?, relative))
            })
    }

    fn append_operation(
        &self,
        state: &mut AuthorityState,
        path: &[u8],
        action: crate::receipt::OperationAction,
        disposition: crate::receipt::OperationDisposition,
        error: Option<&str>,
    ) {
        let Some(stream) = state.receipt_stream.as_mut() else {
            return;
        };
        self.append_operation_to_stream(stream, path, action, disposition, error);
    }

    fn append_operation_to_stream(
        &self,
        stream: &mut crate::receipt::ReceiptStreamWriter,
        path: &[u8],
        action: crate::receipt::OperationAction,
        disposition: crate::receipt::OperationDisposition,
        error: Option<&str>,
    ) {
        let Some((scope, relative)) = self.receipt_location(path) else {
            stream.mark_recording_failure();
            return;
        };
        let sequence = stream.next_sequence();
        let code = match disposition {
            crate::receipt::OperationDisposition::Failed => {
                crate::receipt::OutcomeCode::ExecutionFailed
            }
            crate::receipt::OperationDisposition::Incomplete => {
                crate::receipt::OutcomeCode::FileLifecycleIncomplete
            }
            crate::receipt::OperationDisposition::Succeeded
            | crate::receipt::OperationDisposition::Observed => crate::receipt::OutcomeCode::None,
        };
        stream.append(&crate::receipt::ReceiptRecord::Operation(
            crate::receipt::ReceiptOperationRecord {
                sequence,
                scope,
                path: relative,
                action,
                disposition,
                code,
                diagnostic: error.and_then(crate::receipt::bounded_diagnostic),
            },
        ));
    }

    /// Confirm or forget the provisional creations of an executed request.
    /// Only a confirmed creation becomes this grant's own; a failed one is
    /// dropped so the path cannot later be replaced as if it were.
    /// `response` is the executor's answer to the authorized request.
    pub(crate) fn settle(&self, settlement: Settlement, response: &proto::Response) {
        let Settlement {
            creations,
            outcomes,
            touched,
            tracked,
        } = settlement;
        if creations.is_empty() && outcomes.is_empty() && touched.is_empty() && !tracked {
            return;
        }
        let outcome_error = |index: usize| -> Option<&str> {
            match response {
                proto::Response::Err(error) => Some(error.as_str()),
                proto::Response::EndpointError(error) => Some(error.as_str()),
                proto::Response::Applied(results) => results
                    .get(index)
                    .and_then(|error| error.as_ref().map(proto::WireError::as_str)),
                _ => None,
            }
        };
        let failed = |index: usize| outcome_error(index).is_some();
        let mut state = self.state.lock().unwrap();
        if tracked {
            state.in_flight = state.in_flight.saturating_sub(1);
            self.settled.notify_all();
        }
        for creation in creations {
            state.provisional.remove(&creation.path);
            if creation.persist && !failed(creation.index) {
                state.created.insert(creation.path);
            }
        }
        state.touched.extend(touched);
        for outcome in outcomes {
            match outcome {
                PendingOutcome::Observe { path } => {
                    if let proto::Response::FileHash { .. } = response {
                        self.append_operation(
                            &mut state,
                            &path,
                            crate::receipt::OperationAction::ObserveFileHash,
                            crate::receipt::OperationDisposition::Observed,
                            None,
                        );
                    } else {
                        self.append_operation(
                            &mut state,
                            &path,
                            crate::receipt::OperationAction::ObserveFileHash,
                            crate::receipt::OperationDisposition::Failed,
                            outcome_error(0).or(Some("receiver returned no file hash")),
                        );
                    }
                }
                PendingOutcome::Logical {
                    index,
                    path,
                    action,
                } => {
                    let error = outcome_error(index);
                    self.append_operation(
                        &mut state,
                        &path,
                        action,
                        if error.is_some() {
                            crate::receipt::OperationDisposition::Failed
                        } else {
                            crate::receipt::OperationDisposition::Succeeded
                        },
                        error,
                    );
                }
                PendingOutcome::FileStage {
                    index,
                    path,
                    copy_id,
                    size,
                    inplace,
                    stage,
                    skip_if_absent,
                    observation_hold,
                } => {
                    // Observation-only Prepare replaces the old partial probe.
                    // Settle only this request's provisional hold: concurrent
                    // preparations for the same partial retain their own
                    // capacity regardless of response ordering.
                    let absent = matches!(response,
                        proto::Response::Prepared(prepared)
                            if prepared.has_candidates || (skip_if_absent && prepared.partial_size.is_none())
                    );
                    if let Some(hold) = observation_hold {
                        let key = (path.clone(), copy_id);
                        Self::settle_observation_reservation(&mut state, &key, hold, !absent);
                    }
                    // If no sidecar existed, the observation performed no
                    // file-lifecycle mutation and must not create an
                    // incomplete receipt entry.
                    if absent {
                        continue;
                    }
                    if state.receipt_stream.is_none() {
                        continue;
                    }
                    let error = outcome_error(index);
                    let mut inconsistent = false;
                    let emit_complete = {
                        let lifecycle = state
                            .file_lifecycles
                            .entry((path.clone(), copy_id))
                            .or_insert(FileLifecycle {
                                size,
                                inplace,
                                recorded: false,
                                last_error: None,
                            });
                        if lifecycle.size != size || lifecycle.inplace != inplace {
                            inconsistent = true;
                        }
                        if matches!(stage, FileStage::Prepare | FileStage::Write)
                            && lifecycle.recorded
                        {
                            lifecycle.recorded = false;
                            lifecycle.last_error = None;
                        }
                        if let Some(error) = error {
                            lifecycle.last_error = crate::receipt::bounded_diagnostic(error);
                            if stage == FileStage::Finalize {
                                lifecycle.recorded = false;
                            }
                            false
                        } else if stage == FileStage::Finalize && !lifecycle.recorded {
                            lifecycle.recorded = true;
                            lifecycle.last_error = None;
                            true
                        } else {
                            false
                        }
                    };
                    if inconsistent {
                        if let Some(stream) = state.receipt_stream.as_mut() {
                            stream.mark_recording_failure();
                        }
                    }
                    if emit_complete {
                        self.append_operation(
                            &mut state,
                            &path,
                            crate::receipt::OperationAction::PublishFile { size, inplace },
                            crate::receipt::OperationDisposition::Succeeded,
                            None,
                        );
                    }
                }
            }
        }
    }

    fn forget_provisional(&self, pending: &[PendingCreation]) {
        let mut state = self.state.lock().unwrap();
        for creation in pending {
            state.provisional.remove(&creation.path);
        }
    }

    /// Bind an operation that creates or replaces the object at `path` to the
    /// signed existing-object policy. `Skip` retains whatever existed before
    /// the transfer, so creation is forced to be no-replace; `MustExist`
    /// creates nothing, so something must already be there and the mutation
    /// is pinned to that object's identity. `directory` marks a directory
    /// creation. Under `Skip`, a raced-in directory fails its individual
    /// no-replace operation without refusing unrelated batch entries. A root the grant
    /// requires to be new is forced to no-replace creation under every
    /// policy, as a directory whenever the placement puts names inside it.
    /// A creation this call records is provisional until `settle` sees the
    /// executor succeed; `index` and `pending` carry that bookkeeping.
    fn constrain_creation(
        &self,
        path: &[u8],
        condition: &mut proto::TargetCondition,
        directory: bool,
        index: usize,
        pending: &mut Vec<PendingCreation>,
    ) -> Result<()> {
        let policy = self.copy.policy.existing;
        let root_must_be_new =
            self.root_existence == RootExistence::New && path == self.destination;
        let label = String::from_utf8_lossy(path);
        if root_must_be_new
            && !directory
            && self.copy.policy.placement != DestinationPlacement::ExactPath
        {
            bail!(
                "signed placement puts names inside {label}, so it must be created as a directory"
            );
        }
        if self.created_by_this_grant(path)
            || (policy == ExistingDestinationPolicy::Replace && !root_must_be_new)
        {
            return Ok(());
        }
        let observed = self.rooted_metadata(path)?;
        self.constrain_observed_creation(
            path,
            condition,
            directory,
            index,
            pending,
            (policy, observed),
        )
    }

    fn constrain_observed_creation(
        &self,
        path: &[u8],
        condition: &mut proto::TargetCondition,
        directory: bool,
        index: usize,
        pending: &mut Vec<PendingCreation>,
        (policy, observed): (ExistingDestinationPolicy, Option<RootMetadata>),
    ) -> Result<()> {
        use proto::TargetCondition::{Absent, Any, Matches, MatchesFingerprint};
        let label = String::from_utf8_lossy(path);
        match policy {
            ExistingDestinationPolicy::MustExist => {
                let metadata = match observed {
                    Some(metadata) if !directory || metadata.is_dir() => metadata,
                    Some(_) => {
                        bail!("signed grant creates nothing: {label} exists but is not a directory")
                    }
                    None => bail!("signed grant creates nothing: {label} does not exist"),
                };
                // Pin the mutation to what was observed: a signed deletion on
                // another connection could otherwise empty the path between
                // this check and execution, turning an update into a creation.
                // A caller-supplied identity is accepted only when it names
                // the observed object, never on its own authority.
                match *condition {
                    Any => {
                        *condition = Matches {
                            dev: metadata.dev,
                            ino: metadata.ino,
                        }
                    }
                    Absent => bail!(
                        "no-replace creation of {label} contradicts the signed existing-object policy"
                    ),
                    Matches { dev, ino } if (dev, ino) == (metadata.dev, metadata.ino) => {}
                    MatchesFingerprint {
                        dev,
                        ino,
                        ctime,
                        ctime_nsec,
                    } if (dev, ino, ctime, ctime_nsec)
                        == (
                            metadata.dev,
                            metadata.ino,
                            metadata.ctime,
                            metadata.ctime_nsec,
                        ) => {}
                    Matches { .. } | MatchesFingerprint { .. } => bail!(
                        "requested identity for {label} does not match the object the receiver observed"
                    ),
                }
                if !directory {
                    // Metadata later in this same batch lands on the new
                    // inode, not the one it replaces, so it must not be
                    // pinned to the old identity. The replacement is never
                    // remembered beyond this request: a later request must
                    // again observe and pin whatever is there, or a chain of
                    // replacements could change the object's type.
                    pending.push(PendingCreation {
                        index,
                        path: path.to_vec(),
                        persist: false,
                    });
                }
                Ok(())
            }
            ExistingDestinationPolicy::Skip | ExistingDestinationPolicy::Replace => {
                // An existing directory under Skip may disappear before execution.
                // Keep the common no-replace condition and creation bookkeeping
                // so a successful mkdir can receive its later metadata updates.
                if observed.is_some_and(|metadata| {
                    !(directory && metadata.is_dir() && policy == ExistingDestinationPolicy::Skip)
                }) {
                    bail!("signed grant retains existing objects: {label} already exists")
                }
                match *condition {
                    Any | Absent => *condition = Absent,
                    Matches { .. } | MatchesFingerprint { .. } => bail!(
                        "replacement of {label} contradicts the signed existing-object policy"
                    ),
                }
                self.state.lock().unwrap().provisional.insert(path.to_vec());
                pending.push(PendingCreation {
                    index,
                    path: path.to_vec(),
                    persist: true,
                });
                Ok(())
            }
            ExistingDestinationPolicy::UpdateIfOlder => {
                bail!("update-if-older existing-object policy is not enforceable by the receiver")
            }
        }
    }

    /// Bind mutations at `path` to the signed existing-object policy.
    /// `Skip` protects all pre-existing objects, including directories,
    /// while permitting updates to objects created by this grant.
    fn constrain_update(
        &self,
        path: &[u8],
        condition: Option<&mut proto::TargetCondition>,
        pending: &[PendingCreation],
    ) -> Result<()> {
        use proto::TargetCondition::{Absent, Any, Matches, MatchesFingerprint};
        let label = String::from_utf8_lossy(path);
        // A creation earlier in this same request (a symlink followed by its
        // metadata, say) counts: the batch executes in order, so the
        // metadata only ever lands on this request's own creation.
        let own = self.created_by_this_grant(path)
            || pending.iter().any(|creation| creation.path == path);
        match self.copy.policy.existing {
            ExistingDestinationPolicy::Skip if own => Ok(()),
            ExistingDestinationPolicy::Skip => {
                bail!("signed grant retains existing objects: {label} may not be modified")
            }
            ExistingDestinationPolicy::MustExist if own => Ok(()),
            ExistingDestinationPolicy::MustExist => {
                // Updates are pinned to the observed object, like
                // publications: nothing hostA supplies names an inode on its
                // own authority.
                let Some(metadata) = self.rooted_metadata(path)? else {
                    bail!("signed grant creates nothing: {label} does not exist")
                };
                let Some(condition) = condition else {
                    return Ok(());
                };
                match *condition {
                    Any => {
                        *condition = Matches {
                            dev: metadata.dev,
                            ino: metadata.ino,
                        }
                    }
                    Absent => bail!(
                        "no-replace update of {label} contradicts the signed existing-object policy"
                    ),
                    Matches { dev, ino } if (dev, ino) == (metadata.dev, metadata.ino) => {}
                    MatchesFingerprint {
                        dev,
                        ino,
                        ctime,
                        ctime_nsec,
                    } if (dev, ino, ctime, ctime_nsec)
                        == (
                            metadata.dev,
                            metadata.ino,
                            metadata.ctime,
                            metadata.ctime_nsec,
                        ) => {}
                    Matches { .. } | MatchesFingerprint { .. } => bail!(
                        "requested identity for {label} does not match the object the receiver observed"
                    ),
                }
                Ok(())
            }
            ExistingDestinationPolicy::Replace => Ok(()),
            ExistingDestinationPolicy::UpdateIfOlder => {
                bail!("update-if-older existing-object policy is not enforceable by the receiver")
            }
        }
    }

    /// Refuse staging work whose eventual publication the existing-object
    /// policy would reject, so the transfer fails before moving bytes.
    fn constrain_prepare(&self, path: &[u8]) -> Result<()> {
        if self.created_by_this_grant(path) {
            return Ok(());
        }
        let label = String::from_utf8_lossy(path);
        match self.copy.policy.existing {
            ExistingDestinationPolicy::Skip if self.rooted_metadata(path)?.is_some() => {
                bail!("signed grant retains existing objects: {label} already exists")
            }
            ExistingDestinationPolicy::MustExist if self.rooted_metadata(path)?.is_none() => {
                bail!("signed grant creates nothing: {label} does not exist")
            }
            _ => Ok(()),
        }
    }

    fn check_flags(&self, flags: u8) -> Result<()> {
        let known = proto::flags::MODE_MASK
            | proto::flags::OWNER
            | proto::flags::GROUP
            | proto::flags::TIMES;
        if flags & !known != 0 {
            bail!("request contains unknown metadata flags");
        }
        if flags & proto::flags::MODE_MASK == proto::flags::MODE_MASK {
            bail!("request cannot mix source and receiver-managed mode flags");
        }
        if flags & proto::flags::MODE != 0 && !self.copy.options.preserve_permissions {
            bail!("request tries to preserve permissions not authorized by the grant");
        }
        if flags & proto::flags::RECEIVER_MODE != 0 && !self.copy.options.receiver_managed_modes {
            bail!("request tries to apply receiver-managed modes not authorized by the grant");
        }
        if flags & proto::flags::OWNER != 0 && !self.copy.options.preserve_owner {
            bail!("request tries to preserve ownership not authorized by the grant");
        }
        if flags & proto::flags::GROUP != 0 && !self.copy.options.preserve_group {
            bail!("request tries to preserve group not authorized by the grant");
        }
        if flags & proto::flags::TIMES != 0 && !self.copy.options.preserve_times {
            bail!("request tries to preserve timestamps not authorized by the grant");
        }
        Ok(())
    }

    fn rooted_metadata(&self, path: &[u8]) -> Result<Option<RootMetadata>> {
        let root_path = Path::new(OsStr::from_bytes(&self.guard.root));
        let target = Path::new(OsStr::from_bytes(path));
        let relative = target.strip_prefix(root_path).with_context(|| {
            format!(
                "receiver metadata target {} is outside enrolled root {}",
                target.display(),
                root_path.display()
            )
        })?;
        let relative = RelativePath::new(relative.as_os_str().as_bytes())?;
        let root = Root::open_verified(
            root_path,
            RootIdentity {
                dev: self.guard.dev,
                ino: self.guard.ino,
            },
        )?;
        root.metadata_optional(&relative)
    }

    fn remember_receiver_creation(&self, path: &[u8], existing_directory_kept: bool) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        let metadata = self.rooted_metadata(path)?;
        Self::remember_receiver_creation_observed(
            &mut state.receiver_modes,
            path,
            existing_directory_kept,
            metadata,
        );
        Ok(())
    }

    fn remember_receiver_creation_observed(
        modes: &mut HashMap<Vec<u8>, ReceiverModeState>,
        path: &[u8],
        existing_directory_kept: bool,
        metadata: Option<RootMetadata>,
    ) {
        let kind = if existing_directory_kept {
            ReceiverModeKind::Directory
        } else {
            ReceiverModeKind::Other
        };
        let initial =
            if existing_directory_kept && metadata.is_some_and(|metadata| metadata.is_dir()) {
                ReceiverModeState::Existing {
                    mode: metadata.unwrap().mode & 0o7777,
                    kind,
                    dev: metadata.unwrap().dev,
                    ino: metadata.unwrap().ino,
                    ctime: metadata.unwrap().ctime,
                    ctime_nsec: metadata.unwrap().ctime_nsec,
                }
            } else {
                ReceiverModeState::New(kind)
            };
        let mode = modes
            .get(path)
            .copied()
            .and_then(|existing| existing.carry_forward(initial))
            .unwrap_or(initial);
        modes.insert(path.to_vec(), mode);
    }

    fn receiver_mode(
        &self,
        path: &[u8],
        proposed: u32,
        target: ReceiverModeTarget,
    ) -> Result<ReceiverModeDecision> {
        let mut state = self.state.lock().unwrap();
        if matches!(target, ReceiverModeTarget::AnyExisting) {
            match state.receiver_modes.get(path).copied() {
                Some(existing @ ReceiverModeState::Selected { .. })
                | Some(existing @ ReceiverModeState::New(ReceiverModeKind::Other))
                | Some(existing @ ReceiverModeState::New(ReceiverModeKind::RegularFile)) => {
                    return Ok(Self::select_receiver_mode(
                        &mut state.receiver_modes,
                        path,
                        proposed,
                        self.receiver_umask,
                        existing,
                    ));
                }
                Some(ReceiverModeState::New(ReceiverModeKind::Directory)) => {
                    let Some(metadata) = self.rooted_metadata(path)? else {
                        return Ok(Self::select_receiver_mode(
                            &mut state.receiver_modes,
                            path,
                            proposed,
                            self.receiver_umask,
                            ReceiverModeState::New(ReceiverModeKind::Directory),
                        ));
                    };
                    if !metadata.is_dir() {
                        bail!("receiver-managed directory target changed before authorization");
                    }

                    // Mkdir itself was constrained to 0700, so a setgid bit
                    // observed now came from HostB's destination-parent
                    // inheritance rather than HostA's proposed source mode.
                    // Retain just that receiver-derived special bit and bind
                    // the metadata operation to the observed directory.
                    let selected =
                        (proposed & 0o777 & !self.receiver_umask) | (metadata.mode & 0o2000);
                    state.receiver_modes.insert(
                        path.to_vec(),
                        ReceiverModeState::Selected {
                            mode: selected,
                            kind: ReceiverModeKind::Directory,
                        },
                    );
                    return Ok(ReceiverModeDecision {
                        mode: selected,
                        identity: Some((
                            metadata.dev,
                            metadata.ino,
                            metadata.ctime,
                            metadata.ctime_nsec,
                        )),
                    });
                }
                Some(ReceiverModeState::Existing { .. }) | None => {}
            }
        }
        let observed = self.rooted_metadata(path)?;
        let initial = match (target, observed) {
            (ReceiverModeTarget::AnyExisting, Some(metadata)) => {
                let kind = if metadata.is_dir() {
                    ReceiverModeKind::Directory
                } else if metadata.is_file() {
                    ReceiverModeKind::RegularFile
                } else {
                    ReceiverModeKind::Other
                };
                ReceiverModeState::Existing {
                    mode: metadata.mode & 0o7777,
                    kind,
                    dev: metadata.dev,
                    ino: metadata.ino,
                    ctime: metadata.ctime,
                    ctime_nsec: metadata.ctime_nsec,
                }
            }
            (ReceiverModeTarget::RegularFile, Some(metadata)) if metadata.is_file() => {
                ReceiverModeState::Existing {
                    mode: metadata.mode & 0o7777,
                    kind: ReceiverModeKind::RegularFile,
                    dev: metadata.dev,
                    ino: metadata.ino,
                    ctime: metadata.ctime,
                    ctime_nsec: metadata.ctime_nsec,
                }
            }
            (ReceiverModeTarget::RegularFile, _) => {
                ReceiverModeState::New(ReceiverModeKind::RegularFile)
            }
            (ReceiverModeTarget::AnyExisting, None) => {
                ReceiverModeState::New(ReceiverModeKind::Other)
            }
        };
        let mode = state
            .receiver_modes
            .get(path)
            .copied()
            .and_then(|existing| existing.carry_forward(initial))
            .unwrap_or(initial);
        state.receiver_modes.insert(path.to_vec(), mode);
        Ok(Self::select_receiver_mode(
            &mut state.receiver_modes,
            path,
            proposed,
            self.receiver_umask,
            mode,
        ))
    }

    fn select_receiver_mode(
        modes: &mut HashMap<Vec<u8>, ReceiverModeState>,
        path: &[u8],
        proposed: u32,
        receiver_umask: u32,
        mode: ReceiverModeState,
    ) -> ReceiverModeDecision {
        match mode {
            ReceiverModeState::Existing {
                mode,
                dev,
                ino,
                ctime,
                ctime_nsec,
                ..
            } => ReceiverModeDecision {
                mode,
                identity: Some((dev, ino, ctime, ctime_nsec)),
            },
            ReceiverModeState::Selected { mode, .. } => ReceiverModeDecision {
                mode,
                identity: None,
            },
            ReceiverModeState::New(kind) => {
                // New objects may inherit ordinary source permission bits, but
                // never source-proposed special bits, and HostB's own umask is
                // authoritative. Directory setgid inheritance is added only
                // from receiver-observed state in receiver_mode().
                let selected = proposed & 0o777 & !receiver_umask;
                modes.insert(
                    path.to_vec(),
                    ReceiverModeState::Selected {
                        mode: selected,
                        kind,
                    },
                );
                ReceiverModeDecision {
                    mode: selected,
                    identity: None,
                }
            }
        }
    }

    fn constrain_receiver_mode(
        &self,
        path: &[u8],
        meta: &mut proto::Meta,
        flags: &mut u8,
        condition: &mut proto::TargetCondition,
        target: ReceiverModeTarget,
    ) -> Result<()> {
        self.check_flags(*flags)?;
        self.apply_receiver_mode(path, meta, flags, condition, target)
    }

    fn apply_receiver_mode(
        &self,
        path: &[u8],
        meta: &mut proto::Meta,
        flags: &mut u8,
        condition: &mut proto::TargetCondition,
        target: ReceiverModeTarget,
    ) -> Result<()> {
        if *flags & proto::flags::RECEIVER_MODE != 0 {
            let decision = self.receiver_mode(path, meta.mode, target)?;
            meta.mode = decision.mode;
            if let Some((dev, ino, ctime, ctime_nsec)) = decision.identity {
                match *condition {
                    proto::TargetCondition::Any => {
                        *condition = proto::TargetCondition::MatchesFingerprint {
                            dev,
                            ino,
                            ctime,
                            ctime_nsec,
                        };
                    }
                    proto::TargetCondition::Matches {
                        dev: expected_dev,
                        ino: expected_ino,
                    } if (expected_dev, expected_ino) == (dev, ino) => {
                        *condition = proto::TargetCondition::MatchesFingerprint {
                            dev,
                            ino,
                            ctime,
                            ctime_nsec,
                        };
                    }
                    proto::TargetCondition::MatchesFingerprint {
                        dev: expected_dev,
                        ino: expected_ino,
                        ctime: expected_ctime,
                        ctime_nsec: expected_ctime_nsec,
                    } if (
                        expected_dev,
                        expected_ino,
                        expected_ctime,
                        expected_ctime_nsec,
                    ) == (dev, ino, ctime, ctime_nsec) => {}
                    _ => bail!("receiver-managed mode target changed before authorization"),
                }
            }
            // From this point on MODE contains receiver-authored data. FsOps
            // never interprets the untrusted RECEIVER_MODE proposal directly.
            *flags = (*flags & !proto::flags::RECEIVER_MODE) | proto::flags::MODE;
        }
        Ok(())
    }

    fn check_hash_request(&self, block: u64, len: u64) -> Result<()> {
        if block != self.copy.limits.hash_block_bytes {
            bail!("hash block size does not match the signed grant");
        }
        if len > self.copy.limits.max_file_bytes {
            bail!("signed grant per-file byte limit exceeded");
        }
        if !proto::hash_response_fits(block, len) {
            bail!("hash response would exceed protocol limits");
        }
        Ok(())
    }

    fn charge_bytes(&self, path: &[u8], offset: u64, bytes: usize) -> Result<()> {
        self.check_mutation_path(path, false)?;
        let bytes = u64::try_from(bytes).context("request byte count overflow")?;
        if self
            .file_data_limit
            .as_ref()
            .is_some_and(|limit| bytes > limit.burst_bytes())
        {
            bail!("request exceeds the signed file-data rate-limit burst");
        }
        let end = offset.checked_add(bytes).context("file offset overflow")?;
        if end > self.copy.limits.max_file_bytes {
            bail!("signed grant per-file byte limit exceeded");
        }
        let mut state = self.state.lock().unwrap();
        state.transferred_bytes = state
            .transferred_bytes
            .checked_add(bytes)
            .context("signed transfer byte counter overflow")?;
        if state.transferred_bytes > self.copy.limits.max_total_bytes {
            bail!("signed grant total-byte limit exceeded");
        }
        drop(state);
        if let Some(limit) = &self.file_data_limit {
            limit.wait(bytes);
            self.check_deadline()?;
        }
        Ok(())
    }

    fn charge_deletion(&self, path: &[u8], is_dir: bool) -> Result<()> {
        if path == self.destination {
            bail!("the signed destination root itself may not be deleted");
        }
        if self.filters.delete_excluded {
            self.check_mutation_authority(path)?;
            self.record_path(path)?;
        } else {
            self.check_mutation_path(path, is_dir)?;
        }
        if self.copy.policy.deletion == DeletionPolicy::Forbid {
            bail!("deletion is not authorized by the signed grant");
        }
        let mut state = self.state.lock().unwrap();
        state.deletions += 1;
        if state.deletions > self.copy.limits.max_deletions {
            bail!("signed grant deletion limit exceeded");
        }
        Ok(())
    }

    fn authorize_op(
        &self,
        operation: &mut Op,
        index: usize,
        pending: &mut Vec<PendingCreation>,
        outcomes: &mut Vec<PendingOutcome>,
        touched: &mut Vec<Vec<u8>>,
    ) -> Result<()> {
        let path = match &*operation {
            Op::Mkdir { path, .. }
            | Op::SetMeta { path, .. }
            | Op::SetFileMetaIfSame { path, .. } => path,
            Op::Symlink { path, .. } => {
                if !self.copy.options.preserve_symlinks {
                    bail!("symlink creation is not authorized by the signed grant");
                }
                path
            }
            Op::Mknod { path, .. } => {
                if !self.copy.options.preserve_devices {
                    bail!("special-file creation is not authorized by the signed grant");
                }
                path
            }
            Op::Remove { .. } => {
                bail!("recursive remove is not supported by the root-confined receiver")
            }
            Op::Rmdir { path } => {
                self.charge_deletion(path, true)?;
                self.state.lock().unwrap().receiver_modes.remove(path);
                outcomes.push(PendingOutcome::Logical {
                    index,
                    path: path.clone(),
                    action: crate::receipt::OperationAction::DeleteDirectory,
                });
                touched.push(path.clone());
                return Ok(());
            }
            Op::Unlink { path } => {
                self.charge_deletion(path, false)?;
                self.state.lock().unwrap().receiver_modes.remove(path);
                outcomes.push(PendingOutcome::Logical {
                    index,
                    path: path.clone(),
                    action: crate::receipt::OperationAction::DeleteFile,
                });
                touched.push(path.clone());
                return Ok(());
            }
        };
        let is_dir = match operation {
            Op::Mkdir { .. } => true,
            Op::SetMeta { .. } => self
                .rooted_metadata(path)?
                .is_some_and(|metadata| metadata.is_dir()),
            _ => false,
        };
        self.check_mutation_path(path, is_dir)?;
        if self.expected_digest(path)?.is_some()
            && matches!(
                operation,
                Op::Mkdir { .. } | Op::Symlink { .. } | Op::Mknod { .. }
            )
        {
            bail!("expected hash requires a regular file");
        }
        match operation {
            Op::Mkdir {
                path,
                mode,
                condition,
            } => {
                if self.mapping_parent(path)? {
                    // Observe once for both the existing-object constraint and
                    // receiver-owned mode restoration. An existing implicit
                    // parent may be reopened, but never replaced or recreated.
                    // An explicit no-replace mkdir needs no preflight stat:
                    // the filesystem checks absence atomically. This is the
                    // planner's usual request for a missing implicit parent.
                    let observed = if *condition == proto::TargetCondition::Absent {
                        None
                    } else {
                        self.rooted_metadata(path)?
                    };
                    let policy = match self.copy.policy.existing {
                        ExistingDestinationPolicy::Replace => {
                            if observed.is_some()
                                && !(self.root_existence == RootExistence::New
                                    && *path == self.destination)
                            {
                                ExistingDestinationPolicy::MustExist
                            } else {
                                ExistingDestinationPolicy::Skip
                            }
                        }
                        policy => policy,
                    };
                    self.constrain_observed_creation(
                        path,
                        condition,
                        true,
                        index,
                        pending,
                        (policy, observed),
                    )?;
                    Self::remember_receiver_creation_observed(
                        &mut self.state.lock().unwrap().receiver_modes,
                        path,
                        true,
                        observed,
                    );
                    // Implicit parents have no source mode. Let mkdir apply
                    // HostB's umask and setgid inheritance directly, avoiding
                    // a later stat/chmod for newly created parents.
                    *mode = 0o755;
                } else {
                    self.constrain_creation(path, condition, true, index, pending)?;
                    if !self.copy.options.preserve_permissions {
                        self.remember_receiver_creation(path, true)?;
                        *mode = 0o700;
                    }
                }
                outcomes.push(PendingOutcome::Logical {
                    index,
                    path: path.clone(),
                    action: crate::receipt::OperationAction::EnsureDirectory,
                });
                touched.push(path.clone());
                Ok(())
            }
            Op::Symlink {
                path, condition, ..
            } => {
                self.constrain_creation(path, condition, false, index, pending)?;
                outcomes.push(PendingOutcome::Logical {
                    index,
                    path: path.clone(),
                    action: crate::receipt::OperationAction::CreateSymlink,
                });
                touched.push(path.clone());
                Ok(())
            }
            Op::Mknod {
                path,
                mode,
                condition,
                ..
            } => {
                let kind = kind_from_mode(*mode);
                if !matches!(
                    kind,
                    proto::Kind::Fifo
                        | proto::Kind::Socket
                        | proto::Kind::CharDev
                        | proto::Kind::BlockDev
                ) {
                    bail!("special-file creation requires a FIFO, socket, or device mode");
                }
                #[cfg(target_os = "linux")]
                let file_type = *mode & libc::S_IFMT;
                #[cfg(not(target_os = "linux"))]
                let file_type = *mode & libc::S_IFMT as u32;
                *mode = file_type | (*mode & 0o7777);
                self.constrain_creation(path, condition, false, index, pending)?;
                if !self.copy.options.preserve_permissions {
                    self.remember_receiver_creation(path, false)?;
                    *mode = file_type | 0o600;
                }
                outcomes.push(PendingOutcome::Logical {
                    index,
                    path: path.clone(),
                    action: crate::receipt::OperationAction::CreateSpecial { kind },
                });
                touched.push(path.clone());
                Ok(())
            }
            Op::SetMeta {
                path,
                meta,
                flags,
                condition,
            } => {
                let implicit = self.mapping_parent(path)?;
                if implicit {
                    // A parent has no source metadata. Only receiver-derived
                    // permissions may be finalized, including restoration after
                    // reopening a read-only parent. Permission preservation on
                    // explicit entries grants no chmod authority over parents.
                    let remembered = self.state.lock().unwrap().receiver_modes.get(path).copied();
                    if *flags & !(proto::flags::MODE | proto::flags::RECEIVER_MODE) != 0
                        || remembered.is_none()
                        || (!matches!(remembered, Some(ReceiverModeState::Existing { .. }))
                            && !self.created_by_this_grant(path))
                    {
                        bail!("mapping cannot change metadata of an existing implicit parent");
                    }
                    meta.mode = 0o755;
                    if *flags != 0 {
                        *flags = proto::flags::RECEIVER_MODE;
                    }
                }
                self.constrain_update(path, Some(&mut *condition), pending)?;
                if !implicit {
                    self.check_flags(*flags)?;
                }
                self.apply_receiver_mode(
                    path,
                    meta,
                    flags,
                    condition,
                    ReceiverModeTarget::AnyExisting,
                )?;
                outcomes.push(PendingOutcome::Logical {
                    index,
                    path: path.clone(),
                    action: crate::receipt::OperationAction::SetMetadata { flags: *flags },
                });
                touched.push(path.clone());
                Ok(())
            }
            Op::SetFileMetaIfSame {
                path,
                meta,
                flags,
                condition,
            } => {
                self.constrain_update(path, Some(&mut *condition), pending)?;
                self.constrain_receiver_mode(
                    path,
                    meta,
                    flags,
                    condition,
                    ReceiverModeTarget::RegularFile,
                )?;
                outcomes.push(PendingOutcome::Logical {
                    index,
                    path: path.clone(),
                    action: crate::receipt::OperationAction::SetMetadata { flags: *flags },
                });
                touched.push(path.clone());
                Ok(())
            }
            Op::Remove { .. } | Op::Rmdir { .. } | Op::Unlink { .. } => Ok(()),
        }
    }

    /// Check and rewrite one request against the signed grant. The returned
    /// settlement must be handed back to `settle` with the executor's
    /// response so provisional creations are forgotten when execution fails.
    pub(crate) fn authorize(&self, request: &mut Request, over_ssh: bool) -> Result<Settlement> {
        let mut pending = Vec::new();
        let mut outcomes = Vec::new();
        let mut touched = Vec::new();
        // Requests the server executes and then settles; the receipt waits
        // for all of them. The others are answered inline without settling.
        let tracked = !matches!(
            request,
            Request::Hello { .. }
                | Request::Scan { .. }
                | Request::TcpListen { .. }
                | Request::TransportStats
                | Request::WriteStreamFence
                | Request::Receipt
                | Request::Shutdown
        );
        // Admission and closure are decided under one lock: a request either
        // counts as in flight before the receipt can observe the count, or
        // it is refused because the receipt has started. Authorization may
        // block afterwards (the file-data limiter, say) without letting the
        // receipt slip past it.
        {
            let mut state = self.state.lock().unwrap();
            if !self.control_is_open() {
                bail!("transfer control is closed or expired");
            }
            if tracked && (state.receipt_issued || state.receipt_closing) {
                bail!("the signed grant is closed: its receipt has been issued");
            }
            if tracked
                && state
                    .receipt_stream
                    .as_ref()
                    .is_some_and(crate::receipt::ReceiptStreamWriter::is_failed)
            {
                bail!("the signed grant is closed because receipt recording failed");
            }
            if tracked {
                state.in_flight += 1;
            }
        }
        match self.authorize_inner(request, over_ssh, &mut pending, &mut outcomes, &mut touched) {
            Ok(()) => Ok(Settlement {
                creations: pending,
                outcomes,
                touched,
                tracked,
            }),
            Err(error) => {
                // Nothing of a refused request executes, including the
                // entries authorized before the refusing one.
                self.forget_provisional(&pending);
                let mut state = self.state.lock().unwrap();
                if tracked {
                    state.in_flight = state.in_flight.saturating_sub(1);
                    self.settled.notify_all();
                }
                if let Some(stream) = state.receipt_stream.as_mut() {
                    let sequence = stream.next_sequence();
                    stream.append(&crate::receipt::ReceiptRecord::Refusal(
                        crate::receipt::RefusalReceiptRecord {
                            sequence,
                            code: crate::receipt::OutcomeCode::AuthorizationRefused,
                            diagnostic: crate::receipt::bounded_format(format_args!("{error:#}")),
                        },
                    ));
                }
                Err(error)
            }
        }
    }

    fn authorize_inner(
        &self,
        request: &mut Request,
        over_ssh: bool,
        pending: &mut Vec<PendingCreation>,
        outcomes: &mut Vec<PendingOutcome>,
        touched: &mut Vec<Vec<u8>>,
    ) -> Result<()> {
        self.check_deadline()?;
        match request {
            Request::ConfigureHashing(policy) => {
                if *policy != self.hash_policy() {
                    bail!("hash policy differs from the authorized copy");
                }
            }
            Request::ValidateDigest {
                path,
                expected,
                guard,
            } => {
                self.check_observation_path(path)?;
                if let Some(authorized) = self.expected_digest(path)? {
                    if *expected != authorized {
                        bail!("expected hash differs from the authorized copy");
                    }
                }
                *guard = Some(self.guard.clone());
            }

            Request::MappingChunk {
                offset,
                data,
                finish,
            } => {
                if !over_ssh {
                    bail!("mapping admission requires the signed control connection");
                }
                self.mapping
                    .as_ref()
                    .context("this grant does not authorize a mapping")?
                    .lock()
                    .unwrap()
                    .append(*offset, data, *finish)?;
            }

            Request::TcpListen {
                key,
                token,
                port_lo,
                port_hi,
                congestion_control,
            } => {
                if !over_ssh {
                    bail!("TCP listener request is allowed only on the signed control connection");
                }
                if key
                    .as_ref()
                    .is_none_or(|key| key.len() != crate::tcp_records::KEY_LEN)
                    || token.len() != 16
                {
                    bail!("signed transfers require encrypted TCP data connections");
                }
                if (*port_lo, *port_hi)
                    != (self.copy.options.tcp_port_lo, self.copy.options.tcp_port_hi)
                {
                    bail!("TCP listener range does not match the signed grant");
                }
                if congestion_control.as_ref() != self.tcp_congestion.as_ref() {
                    bail!("TCP congestion override is not authorized by the signed grant");
                }
                let mut state = self.state.lock().unwrap();
                if state.tcp_listener_started {
                    bail!("signed grant permits only one TCP listener");
                }
                state.tcp_listener_started = true;
            }
            Request::Scan {
                root,
                source,
                follow_root,
                ignore,
                guard,
                ..
            } => {
                if source.is_some() {
                    bail!("source references are not valid on a command-restricted destination");
                }
                if self.mapping.is_some() {
                    bail!("mapping grants do not authorize recursive destination scans");
                }
                if *follow_root {
                    bail!("signed destination scans cannot follow a root symlink");
                }
                self.check_observation_path(root)?;
                if self.filter_applies(root) {
                    let expected = if self.filters.delete_excluded {
                        &[][..]
                    } else {
                        self.filters.ignore.as_slice()
                    };
                    if ignore.as_slice() != expected {
                        bail!("destination scan filters do not match the signed filter policy");
                    }
                }
                *guard = Some(self.guard.clone());
            }
            Request::StatMany {
                paths,
                sources,
                follow,
                guard,
                ..
            } => {
                if sources.is_some() {
                    bail!("source references are not valid on a command-restricted destination");
                }
                if *follow {
                    bail!("signed destination stat cannot follow symlinks");
                }
                for path in paths {
                    self.check_observation_path(path)?;
                }
                *guard = Some(self.guard.clone());
            }
            Request::DestinationFilesystemInfo { .. } => {
                bail!("destination filesystem inspection is not authorized by the signed grant")
            }
            Request::PartialPaths { paths, guard, .. } | Request::PruneLookup { paths, guard } => {
                for path in paths {
                    self.check_observation_path(path)?;
                }
                *guard = Some(self.guard.clone());
            }
            Request::PlanBatch {
                partial_paths,
                directories,
                others,
                guard,
                ..
            } => {
                for path in partial_paths
                    .iter()
                    .chain(directories.iter())
                    .chain(others.iter())
                {
                    self.check_observation_path(path)?;
                }
                *guard = Some(self.guard.clone());
            }
            Request::Apply { ops, guard } => {
                for (index, operation) in ops.iter_mut().enumerate() {
                    self.authorize_op(operation, index, pending, outcomes, touched)?;
                }
                *guard = Some(self.guard.clone());
            }
            Request::ProbePartial { path, guard, .. } | Request::Canonicalize { path, guard } => {
                self.check_observation_path(path)?;
                *guard = Some(self.guard.clone());
            }
            Request::FileHash {
                path,
                source,
                guard,
            } => {
                if source.is_some() {
                    bail!("source references are not valid on a command-restricted destination");
                }
                self.check_observation_path(path)?;
                outcomes.push(PendingOutcome::Observe { path: path.clone() });
                *guard = Some(self.guard.clone());
            }
            Request::HashBlocks {
                path,
                source,
                block,
                len,
                guard,
                ..
            } => {
                if source.is_some() {
                    bail!("source references are not valid on a command-restricted destination");
                }
                self.check_hash_request(*block, *len)?;
                self.check_observation_path(path)?;
                *guard = Some(self.guard.clone());
            }
            Request::HashAndHold {
                path,
                block,
                len,
                guard,
                ..
            } => {
                self.check_hash_request(*block, *len)?;
                self.check_observation_path(path)?;
                *guard = Some(self.guard.clone());
            }
            Request::SeedBasis {
                path,
                copy_id,
                len,
                block,
                guard,
                ..
            } => {
                self.check_hash_request(*block, *len)?;
                if self.copy.policy.publication != PublicationPolicy::AtomicStaged {
                    bail!("in-place signed receiver forbids staged basis creation");
                }
                if *len > self.copy.limits.max_file_bytes {
                    bail!("signed grant per-file byte limit exceeded");
                }
                self.check_mutation_path(path, false)?;
                self.constrain_prepare(path)?;
                self.reserve_bytes(path, *copy_id, *len, false)?;
                outcomes.push(PendingOutcome::FileStage {
                    index: 0,
                    path: path.clone(),
                    copy_id: *copy_id,
                    size: *len,
                    inplace: false,
                    stage: FileStage::Prepare,
                    skip_if_absent: false,
                    observation_hold: None,
                });
                *guard = Some(self.guard.clone());
            }
            Request::FinishBasis {
                expected_digest,
                path,
                meta,
                flags,
                condition,
                guard,
                ..
            } => {
                *expected_digest = self.expected_digest(path)?;
                self.check_mutation_path(path, false)?;
                self.constrain_update(path, Some(&mut *condition), pending)?;
                self.constrain_receiver_mode(
                    path,
                    meta,
                    flags,
                    condition,
                    ReceiverModeTarget::RegularFile,
                )?;
                outcomes.push(PendingOutcome::Logical {
                    index: 0,
                    path: path.clone(),
                    action: crate::receipt::OperationAction::SetMetadata { flags: *flags },
                });
                touched.push(path.clone());
                *guard = Some(self.guard.clone());
            }
            Request::Prepare {
                path,
                size,
                inplace,
                copy_id,
                create_if_missing,
                guard,
                ..
            } => {
                if *inplace != (self.copy.policy.publication == PublicationPolicy::InPlace) {
                    bail!("file preparation does not match the signed publication policy");
                }
                if *size > self.copy.limits.max_file_bytes {
                    bail!("signed grant per-file byte limit exceeded");
                }
                self.check_mutation_path(path, false)?;
                self.constrain_prepare(path)?;
                let observation_hold =
                    self.reserve_bytes(path, *copy_id, *size, !*create_if_missing)?;
                outcomes.push(PendingOutcome::FileStage {
                    index: 0,
                    path: path.clone(),
                    copy_id: *copy_id,
                    size: *size,
                    inplace: *inplace,
                    stage: FileStage::Prepare,
                    skip_if_absent: !*create_if_missing,
                    observation_hold,
                });
                if *inplace {
                    // In-place preparation resizes the final file itself:
                    // the receipt must know even if no final step follows.
                    touched.push(path.clone());
                }
                *guard = Some(self.guard.clone());
            }
            Request::WriteRange {
                path,
                inplace,
                copy_id,
                off,
                data,
                guard,
                ..
            } => {
                if *inplace != (self.copy.policy.publication == PublicationPolicy::InPlace) {
                    bail!("file write does not match the signed publication policy");
                }
                let declared = self.declared_size(path, *copy_id)?;
                if off
                    .checked_add(data.len() as u64)
                    .is_none_or(|end| end > declared)
                {
                    bail!("file write extends past the size declared for it");
                }
                if *inplace {
                    touched.push(path.clone());
                }
                outcomes.push(PendingOutcome::FileStage {
                    index: 0,
                    path: path.clone(),
                    copy_id: *copy_id,
                    size: declared,
                    inplace: *inplace,
                    stage: FileStage::Write,
                    skip_if_absent: false,
                    observation_hold: None,
                });
                self.charge_bytes(path, *off, data.len())?;
                *guard = Some(self.guard.clone());
            }
            Request::Finalize {
                expected_digest,
                path,
                inplace,
                copy_id,
                meta,
                flags,
                condition,
                guard,
                ..
            } => {
                *expected_digest = self.expected_digest(path)?;
                if *inplace != (self.copy.policy.publication == PublicationPolicy::InPlace) {
                    bail!("file finalization does not match the signed publication policy");
                }
                self.check_mutation_path(path, false)?;
                self.check_published_length(path, *copy_id, *inplace)?;
                self.constrain_creation(path, condition, false, 0, pending)?;
                outcomes.push(PendingOutcome::FileStage {
                    index: 0,
                    path: path.clone(),
                    copy_id: *copy_id,
                    size: self.declared_size(path, *copy_id)?,
                    inplace: *inplace,
                    stage: FileStage::Finalize,
                    skip_if_absent: false,
                    observation_hold: None,
                });
                touched.push(path.clone());
                self.constrain_receiver_mode(
                    path,
                    meta,
                    flags,
                    condition,
                    ReceiverModeTarget::RegularFile,
                )?;
                *guard = Some(self.guard.clone());
            }
            Request::PutSmallBatch(puts) => {
                if self.copy.policy.publication != PublicationPolicy::AtomicStaged
                    || puts.iter().any(|put| put.inplace)
                {
                    bail!("small-file publication does not match the signed publication policy");
                }
                if let Some(limit) = &self.file_data_limit {
                    let bytes = puts.iter().try_fold(0u64, |total, put| {
                        total
                            .checked_add(put.data.len() as u64)
                            .context("small-file batch byte count overflow")
                    })?;
                    if bytes > limit.burst_bytes() {
                        bail!("small-file batch exceeds the signed file-data rate-limit burst");
                    }
                }
                for (index, put) in puts.iter_mut().enumerate() {
                    if self.expected_digest(&put.path)?.is_some() {
                        bail!("expected-hash files require checked finalization");
                    }
                    self.charge_bytes(&put.path, 0, put.data.len())?;
                    self.constrain_creation(&put.path, &mut put.condition, false, index, pending)?;
                    outcomes.push(PendingOutcome::Logical {
                        index,
                        path: put.path.clone(),
                        action: crate::receipt::OperationAction::PublishFile {
                            size: put.data.len() as u64,
                            inplace: false,
                        },
                    });
                    touched.push(put.path.clone());
                    self.constrain_receiver_mode(
                        &put.path,
                        &mut put.meta,
                        &mut put.flags,
                        &mut put.condition,
                        ReceiverModeTarget::RegularFile,
                    )?;
                    put.guard = Some(self.guard.clone());
                }
            }
            Request::CopyLocal { .. }
            | Request::ReadRange { .. }
            | Request::ReadStream(_)
            | Request::ShrinkReadStream { .. }
            | Request::StopReadStream
            | Request::ReadSmallBatch(_)
            | Request::CopySmallFiles(_) => {
                bail!("request is not valid on a command-restricted destination")
            }
            Request::ListDir { .. }
            | Request::ListDirDetails { .. }
            | Request::ListDirNoFollowFinal { .. } => {
                bail!("directory completion is not valid on a command-restricted destination")
            }
            Request::CheckOperatorDirectory { .. }
            | Request::CheckOperatorDirectoryAncestry { .. }
            | Request::RegisterSourceRoots { .. }
            | Request::CreateOperatorDirectory { .. }
            | Request::AnchorDestination { .. } => {
                bail!("destination-anchor management is not valid on a root-confined receiver")
            }
            Request::NativeRemove { .. } => {
                bail!("native removal is not valid on a command-restricted destination")
            }
            Request::DescriptorCopy(_) => {
                bail!("descriptor copies are not valid on a command-restricted receiver")
            }
            Request::Hello { .. } => bail!("unexpected second receiver handshake"),
            Request::Receipt => {
                if !over_ssh {
                    bail!("the receipt is issued only on the signed control connection");
                }
            }
            Request::TransportStats | Request::Shutdown | Request::WriteStreamFence => {}
        }
        Ok(())
    }
}

/// What an authorized request recorded provisionally: creations, keyed by
/// the operation or small-put index the executor reports on, and the
/// outcomes the receipt will attest to once the executor confirms them.
#[derive(Debug, Default)]
pub(crate) struct Settlement {
    creations: Vec<PendingCreation>,
    outcomes: Vec<PendingOutcome>,
    /// Final destination paths this admitted request could have changed.
    touched: Vec<Vec<u8>>,
    /// The request counts as in flight until settled.
    tracked: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FileStage {
    Prepare,
    Write,
    Finalize,
}

fn kind_from_mode(mode: u32) -> proto::Kind {
    #[cfg(target_os = "linux")]
    let kind = mode & libc::S_IFMT;
    #[cfg(not(target_os = "linux"))]
    let kind = mode & libc::S_IFMT as u32;
    #[cfg(target_os = "linux")]
    let value = |value: libc::mode_t| value;
    #[cfg(not(target_os = "linux"))]
    let value = |value: libc::mode_t| value as u32;
    match kind {
        kind if kind == value(libc::S_IFDIR) => proto::Kind::Dir,
        kind if kind == value(libc::S_IFREG) => proto::Kind::File,
        kind if kind == value(libc::S_IFLNK) => proto::Kind::Symlink,
        kind if kind == value(libc::S_IFIFO) => proto::Kind::Fifo,
        kind if kind == value(libc::S_IFSOCK) => proto::Kind::Socket,
        kind if kind == value(libc::S_IFCHR) => proto::Kind::CharDev,
        kind if kind == value(libc::S_IFBLK) => proto::Kind::BlockDev,
        _ => proto::Kind::Other,
    }
}

#[derive(Debug)]
struct FileLifecycle {
    size: u64,
    inplace: bool,
    recorded: bool,
    last_error: Option<String>,
}

/// One receipt-relevant effect of a request, confirmed by `settle`.
#[derive(Debug)]
enum PendingOutcome {
    Observe {
        path: Vec<u8>,
    },
    Logical {
        index: usize,
        path: Vec<u8>,
        action: crate::receipt::OperationAction,
    },
    FileStage {
        index: usize,
        path: Vec<u8>,
        copy_id: proto::CopyId,
        size: u64,
        inplace: bool,
        stage: FileStage,
        /// Ignore a successful observation-only Prepare when it found no
        /// resumable sidecar and therefore performed no lifecycle mutation.
        skip_if_absent: bool,
        /// This observation-only Prepare's provisional reservation. Settlement
        /// releases or retains precisely this hold without affecting a
        /// concurrent preparation for the same partial.
        observation_hold: Option<ReservationHoldId>,
    },
}

/// One object a request creates or replaces. Only creations that `persist`
/// become the grant's own once confirmed; a `MustExist` replacement counts
/// only for the rest of its own request.
#[derive(Debug)]
pub(crate) struct PendingCreation {
    index: usize,
    path: Vec<u8>,
    persist: bool,
}

fn current_account() -> Result<(String, PathBuf)> {
    let uid = unsafe { libc::geteuid() };
    let suggested = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let capacity = if suggested > 0 {
        usize::try_from(suggested).unwrap_or(16 * 1024)
    } else {
        16 * 1024
    }
    .clamp(1024, 1024 * 1024);
    let mut buffer = vec![0u8; capacity];
    let mut record: libc::passwd = unsafe { std::mem::zeroed() };
    let mut found = std::ptr::null_mut();
    let result = unsafe {
        libc::getpwuid_r(
            uid,
            &mut record,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut found,
        )
    };
    if result != 0 {
        return Err(std::io::Error::from_raw_os_error(result)).context("resolve current account");
    }
    if found.is_null() || record.pw_name.is_null() || record.pw_dir.is_null() {
        bail!("current effective uid has no passwd entry");
    }
    let name = unsafe { CStr::from_ptr(record.pw_name) }
        .to_str()
        .context("current account name is not UTF-8")?
        .to_owned();
    let home = OsString::from_vec(unsafe { CStr::from_ptr(record.pw_dir) }.to_bytes().to_vec());
    Ok((name, PathBuf::from(home)))
}

fn ensure_directory(path: &Path, mode: u32) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                bail!("{} is not a real directory", path.display());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::DirBuilder::new()
                .mode(mode)
                .create(path)
                .with_context(|| format!("create private directory {}", path.display()))?;
        }
        Err(error) => {
            return Err(error).with_context(|| format!("inspect directory {}", path.display()))
        }
    }
    Ok(())
}

fn ensure_directory_chain(home: &Path, components: &[&str]) -> Result<PathBuf> {
    let mut path = home.to_path_buf();
    for component in components {
        path.push(component);
        ensure_directory(&path, 0o700)?;
    }
    Ok(path)
}

fn ensure_private_chain(home: &Path, components: &[&str]) -> Result<PathBuf> {
    let path = ensure_directory_chain(home, components)?;
    delegation::validate_private_directory_path(&path)?;
    Ok(path)
}

fn open_directory(path: &Path) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NOCTTY | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("open private directory {}", path.display()))
}

fn lock_directory(directory: &File) -> Result<()> {
    loop {
        if unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX) } == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error).context("lock private directory");
        }
    }
}

fn leaf_name(name: &str) -> Result<CString> {
    if name.is_empty() || name.contains('/') || name == "." || name == ".." {
        bail!("invalid private state filename");
    }
    CString::new(name).context("private state filename contains NUL")
}

fn read_leaf(
    directory: &File,
    name: &str,
    maximum: usize,
    private: bool,
) -> Result<Option<Vec<u8>>> {
    let name = leaf_name(name)?;
    let fd = loop {
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY
                    | libc::O_NOFOLLOW
                    | libc::O_NONBLOCK
                    | libc::O_NOCTTY
                    | libc::O_CLOEXEC,
            )
        };
        if fd >= 0 {
            break fd;
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error).with_context(|| format!("open private state {name:?}"));
        }
    };
    let mut file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        bail!("state file must be a regular file");
    }
    if private
        && (metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o7777 != 0o600)
    {
        bail!("private state file must be target-owned with mode 0600");
    }
    let mut contents = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut contents)?;
    if contents.len() > maximum {
        bail!("private state file exceeds {maximum} bytes");
    }
    Ok(Some(contents))
}

fn atomic_write(directory_path: &Path, name: &str, contents: &[u8], mode: u32) -> Result<()> {
    delegation::validate_private_directory_path(directory_path)?;
    let directory = open_directory(directory_path)?;
    lock_directory(&directory)?;
    atomic_write_locked(&directory, name, contents, mode, true)
}

fn atomic_write_locked(
    directory: &File,
    name: &str,
    contents: &[u8],
    mode: u32,
    existing_private: bool,
) -> Result<()> {
    let destination = leaf_name(name)?;
    if let Some(existing) = read_leaf(directory, name, MAX_AUTHORIZED_KEYS, existing_private)? {
        let _ = existing;
    }
    let mut random = [0u8; 8];
    getrandom::fill(&mut random).context("generate atomic state filename")?;
    let temporary_name = format!(
        ".syq-write-{}-{}",
        std::process::id(),
        u64::from_le_bytes(random)
    );
    let temporary = leaf_name(&temporary_name)?;
    let fd = loop {
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                temporary.as_ptr(),
                libc::O_WRONLY
                    | libc::O_CREAT
                    | libc::O_EXCL
                    | libc::O_NOFOLLOW
                    | libc::O_NOCTTY
                    | libc::O_CLOEXEC,
                (mode & 0o600) as libc::c_int,
            )
        };
        if fd >= 0 {
            break fd;
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error).context("create atomic private state file");
        }
    };
    let mut file = unsafe { File::from_raw_fd(fd) };
    let write_result = (|| -> Result<()> {
        file.write_all(contents)?;
        file.sync_all()?;
        loop {
            let result = unsafe {
                libc::renameat(
                    directory.as_raw_fd(),
                    temporary.as_ptr(),
                    directory.as_raw_fd(),
                    destination.as_ptr(),
                )
            };
            if result == 0 {
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error).context("publish atomic private state file");
            }
        }
        directory.sync_all()?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = unsafe { libc::unlinkat(directory.as_raw_fd(), temporary.as_ptr(), 0) };
    }
    write_result
}

fn atomic_replace_executable_locked(directory: &File, name: &str, contents: &[u8]) -> Result<()> {
    let destination = leaf_name(name)?;
    let mut random = [0u8; 8];
    getrandom::fill(&mut random).context("generate atomic receiver filename")?;
    let temporary_name = format!(
        ".syq-receiver-write-{}-{}",
        std::process::id(),
        u64::from_le_bytes(random)
    );
    let temporary = leaf_name(&temporary_name)?;
    let fd = loop {
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                temporary.as_ptr(),
                libc::O_WRONLY
                    | libc::O_CREAT
                    | libc::O_EXCL
                    | libc::O_NOFOLLOW
                    | libc::O_NOCTTY
                    | libc::O_CLOEXEC,
                0o700,
            )
        };
        if fd >= 0 {
            break fd;
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error).context("create atomic restricted receiver");
        }
    };
    let mut file = unsafe { File::from_raw_fd(fd) };
    let write_result = (|| -> Result<()> {
        file.set_permissions(fs::Permissions::from_mode(0o700))?;
        file.write_all(contents)?;
        file.sync_all()?;
        loop {
            let result = unsafe {
                libc::renameat(
                    directory.as_raw_fd(),
                    temporary.as_ptr(),
                    directory.as_raw_fd(),
                    destination.as_ptr(),
                )
            };
            if result == 0 {
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error).context("publish restricted receiver");
            }
        }
        directory.sync_all()?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = unsafe { libc::unlinkat(directory.as_raw_fd(), temporary.as_ptr(), 0) };
    }
    write_result
}

fn remove_leaf_locked(directory: &File, name: &str) -> Result<()> {
    let name = leaf_name(name)?;
    loop {
        let result = unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) };
        if result == 0 {
            directory.sync_all()?;
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(());
        }
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error).context("remove private state file");
        }
    }
}

fn generate_enrollment_key(id: EnrollmentId) -> Result<PrivateKey> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).context("generate enrollment key")?;
    let keypair = Ed25519Keypair::from_seed(&seed);
    seed.fill(0);
    PrivateKey::new(keypair.into(), format!("syq-enrollment:{id}"))
        .context("construct enrollment key")
}

/// The receiver's own signing key for receipts. It lives only on hostB, in
/// the enrollment's state directory, and is generated once per enrollment.
fn generate_receipt_key(id: EnrollmentId) -> Result<PrivateKey> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).context("generate receipt signing key")?;
    let keypair = Ed25519Keypair::from_seed(&seed);
    seed.fill(0);
    PrivateKey::new(keypair.into(), format!("syq-receipt:{id}"))
        .context("construct receipt signing key")
}

const RECEIPT_KEY_FILE: &str = "receipt-key";

/// The enrollment's receipt key: generated on first install and kept by
/// every later install, so a refresh after a syq upgrade, or a retry after
/// a lost reply, always reports the key the local side already holds.
/// Rotation is explicit: revoke, then enroll again.
fn ensure_receipt_key(state: &Path, id: EnrollmentId) -> Result<PrivateKey> {
    let path = state.join(RECEIPT_KEY_FILE);
    match fs::symlink_metadata(&path) {
        Ok(_) => return load_receipt_key(state),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("inspect {}", path.display()));
        }
    }
    let key = generate_receipt_key(id)?;
    atomic_write(
        state,
        RECEIPT_KEY_FILE,
        key.to_openssh(LineEnding::LF)
            .context("encode receipt signing key")?
            .as_bytes(),
        0o600,
    )?;
    Ok(key)
}

/// The receipt signing key installed for this enrollment.
fn load_receipt_key(state: &Path) -> Result<PrivateKey> {
    let path = state.join(RECEIPT_KEY_FILE);
    let encoded = delegation::read_private_regular(&path, "receipt signing key", 128 * 1024)?;
    PrivateKey::from_openssh(&encoded).context("parse receipt signing key")
}

fn signer_name(id: EnrollmentId) -> String {
    format!("syq-enrollment-{id}")
}

fn normalize_absolute(path: &std::ffi::OsStr, home: &Path) -> Result<PathBuf> {
    use std::os::unix::ffi::OsStrExt as _;
    let bytes = path.as_bytes();
    let raw = if bytes == b"~" {
        home.to_path_buf()
    } else if let Some(rest) = bytes.strip_prefix(b"~/") {
        home.join(std::ffi::OsStr::from_bytes(rest))
    } else if bytes.starts_with(b"/") {
        PathBuf::from(path)
    } else {
        home.join(path)
    };
    let mut normalized = PathBuf::from("/");
    for component in raw.components() {
        match component {
            std::path::Component::RootDir => {}
            std::path::Component::Normal(component) => normalized.push(component),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                bail!("restricted destination must not contain .. components")
            }
            std::path::Component::Prefix(_) => bail!("unsupported destination prefix"),
        }
    }
    Ok(normalized)
}

fn requested_parent(destination: &Path) -> &Path {
    destination.parent().unwrap_or_else(|| Path::new("/"))
}

fn install_state_paths(home: &Path, id: EnrollmentId) -> Result<(PathBuf, PathBuf, PathBuf)> {
    let base = ensure_private_chain(home, &[".local", "share", "syq", "restricted"])?;
    let enrollment = base.join(id.to_string());
    ensure_directory(&enrollment, 0o700)?;
    let replay = enrollment.join("replay");
    ensure_directory(&replay, 0o700)?;
    Ok((
        enrollment.clone(),
        enrollment.join("allowed-signers"),
        replay,
    ))
}

fn receiver_install_path(home: &Path) -> PathBuf {
    home.join(".local/libexec/syq-receiver")
}

fn receiver_control_paths(
    home: &Path,
    receiver: &Path,
    ssh_keygen: Option<&Path>,
) -> Result<Vec<ReceiverControlPath>> {
    let receiver_directory = receiver
        .parent()
        .context("restricted receiver path has no parent directory")?;
    let mut protected = vec![
        ReceiverControlPath {
            path: home.join(".ssh").as_os_str().as_bytes().to_vec(),
            label: "SSH configuration directory",
        },
        ReceiverControlPath {
            path: receiver_directory.as_os_str().as_bytes().to_vec(),
            label: "receiver executable directory",
        },
        ReceiverControlPath {
            path: home
                .join(".local/share/syq/restricted")
                .as_os_str()
                .as_bytes()
                .to_vec(),
            label: "enrollment state directory",
        },
    ];
    if let Some(ssh_keygen) = ssh_keygen {
        protected.push(ReceiverControlPath {
            path: ssh_keygen.as_os_str().as_bytes().to_vec(),
            label: "signature verifier executable",
        });
    }
    Ok(protected)
}

fn materialize_receiver(home: &Path, contents: &[u8]) -> Result<PathBuf> {
    let directory_path = ensure_directory_chain(home, &[".local", "libexec"])?;
    let directory = open_directory(&directory_path)?;
    atomic_replace_executable_locked(&directory, "syq-receiver", contents)?;
    let receiver = receiver_install_path(home);
    delegation::validate_regular_executable(&receiver, "restricted receiver")?;
    Ok(receiver)
}

fn directory_is_empty(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => delegation::validate_private_directory_path(path)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(error) => return Err(error).with_context(|| format!("inspect {}", path.display())),
    }
    Ok(fs::read_dir(path)
        .with_context(|| format!("list {}", path.display()))?
        .next()
        .transpose()?
        .is_none())
}

fn remove_empty_directory(path: &Path) -> Result<()> {
    match fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::DirectoryNotEmpty
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(error).with_context(|| format!("remove empty {}", path.display())),
    }
}

fn remove_final_enrollment_state_directories(home: &Path) -> Result<()> {
    remove_empty_directory(&home.join(".local/share/syq/restricted"))?;
    remove_empty_directory(&home.join(".local/share/syq"))
}

fn contains_managed_enrollment(contents: &[u8]) -> bool {
    const MARKER: &[u8] = b"syq-enrollment:";
    contents.split(|byte| *byte == b'\n').any(|line| {
        let trimmed = line
            .iter()
            .copied()
            .skip_while(u8::is_ascii_whitespace)
            .collect::<Vec<_>>();
        !trimmed.starts_with(b"#")
            && line
                .rsplit(|byte| byte.is_ascii_whitespace())
                .find(|word| !word.is_empty())
                .is_some_and(|word| word.starts_with(MARKER))
    })
}

fn resolve_ssh_keygen() -> Result<PathBuf> {
    let candidates = std::iter::once(PathBuf::from("/usr/bin/ssh-keygen")).chain(
        std::env::var_os("PATH")
            .into_iter()
            .flat_map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>())
            .map(|directory| directory.join("ssh-keygen")),
    );
    for candidate in candidates {
        if candidate.is_absolute()
            && candidate
                .metadata()
                .is_ok_and(|metadata| metadata.is_file() && metadata.mode() & 0o111 != 0)
        {
            return fs::canonicalize(&candidate)
                .with_context(|| format!("canonicalize {}", candidate.display()));
        }
    }
    bail!("restricted receiver requires ssh-keygen for SSHSIG verification")
}

pub(crate) fn remote_install() -> Result<()> {
    let mut encoded = Vec::new();
    std::io::stdin()
        .take(MAX_STATE_FILE as u64 + 1)
        .read_to_end(&mut encoded)?;
    if encoded.len() > MAX_STATE_FILE {
        bail!("restricted enrollment request is too large");
    }
    let request: InstallRequest =
        serde_json::from_slice(&encoded).context("decode restricted enrollment request")?;
    if request.version != CONFIG_VERSION {
        bail!("unsupported restricted enrollment request version");
    }
    request.id.validate()?;
    let (account, home) = current_account()?;
    if account != request.target_login {
        bail!("enrollment target login does not match the remote account");
    }
    let destination =
        normalize_absolute(std::ffi::OsStr::new(&request.requested_destination), &home)?;
    let parent = requested_parent(&destination);
    let canonical_root = fs::canonicalize(parent)
        .with_context(|| format!("resolve restricted destination parent {}", parent.display()))?;
    if !fs::metadata(&canonical_root)?.is_dir() {
        bail!("restricted destination parent is not a directory");
    }
    let leaf = destination
        .file_name()
        .context("restricted destination / is not supported")?;
    let canonical_destination = canonical_root.join(leaf);
    if fs::symlink_metadata(&canonical_destination).is_ok_and(|metadata| metadata.is_symlink()) {
        bail!(
            "command-restricted enrollment does not follow a destination-root symlink; enroll its explicit referent instead"
        );
    }
    let canonical_home = fs::canonicalize(&home)
        .with_context(|| format!("resolve receiver home {}", home.display()))?;
    let ssh_keygen = resolve_ssh_keygen()?;
    let bootstrap_receiver = receiver_install_path(&canonical_home);
    let protected =
        receiver_control_paths(&canonical_home, &bootstrap_receiver, Some(&ssh_keygen))?;
    reject_control_plane_path(canonical_destination.as_os_str().as_bytes(), &protected)?;
    let root = crate::rooted::Root::open(&canonical_root)?;
    let root_identity = root.identity();
    let enrollment_key = EnrollmentPublicKey::parse(&request.public_key)?;
    let signer = signer_name(request.id);
    let public_words: Vec<&str> = request.public_key.split_ascii_whitespace().collect();
    if public_words.len() < 2 {
        bail!("enrollment public key is malformed");
    }
    let running_receiver = std::env::current_exe().context("resolve restricted receiver path")?;
    delegation::validate_regular_executable(&running_receiver, "restricted receiver")?;
    let receiver_contents = fs::read(&running_receiver)
        .with_context(|| format!("read restricted receiver {}", running_receiver.display()))?;
    let ssh = ensure_directory_chain(&home, &[".ssh"])?;
    let directory = open_directory(&ssh)?;
    lock_directory(&directory)?;
    // The authorized-keys directory lock is the receiver lifecycle lock too.
    // A concurrent final revoke may unlink the shared executable, but an
    // installer that already started has its bytes and recreates it before
    // publishing the new forced authorization.
    let receiver_path = materialize_receiver(&home, &receiver_contents)?;
    let entry = AuthorizedKeyEntry::new(request.id, &receiver_path, &enrollment_key)?;
    let original =
        read_leaf(&directory, "authorized_keys", MAX_AUTHORIZED_KEYS, false)?.unwrap_or_default();
    let normalized = normalize_managed_authorized_keys(&original, &entry.marker());
    let (updated, change) = enrollment::install_authorized_key(&normalized, &entry)?;

    // Publish the forced authorization last. A failed preflight therefore
    // cannot leave a usable key, and a later state-write failure leaves only
    // inert private state that an idempotent retry can complete.
    let (state, _allowed_signers, _replay) = install_state_paths(&home, request.id)?;
    active::require_not_revoked(&state)?;
    atomic_write(
        &state,
        "allowed-signers",
        format!("{signer} {} {}\n", public_words[0], public_words[1]).as_bytes(),
        0o600,
    )?;
    let config = ReceiverEnrollment {
        version: CONFIG_VERSION,
        id: request.id,
        target_login: request.target_login.clone(),
        signer,
        root: canonical_root
            .to_str()
            .context("canonical restricted root is not UTF-8")?
            .to_owned(),
        root_dev: root_identity.dev,
        root_ino: root_identity.ino,
        ssh_keygen: ssh_keygen
            .to_str()
            .context("ssh-keygen path is not UTF-8")?
            .to_owned(),
        receiver_path: receiver_path
            .to_str()
            .context("restricted receiver path is not UTF-8")?
            .to_owned(),
    };
    let receipt_key = ensure_receipt_key(&state, request.id)?;
    let receipt_public_key = receipt_key
        .public_key()
        .to_openssh()
        .context("encode receipt public key")?;
    atomic_write(&state, "config.json", &serde_json::to_vec(&config)?, 0o600)?;
    atomic_write_locked(&directory, "authorized_keys", &updated, 0o600, false)?;

    let response = InstallResponse {
        version: CONFIG_VERSION,
        id: request.id,
        target_login: request.target_login,
        remote_home: home
            .to_str()
            .context("remote account home is not UTF-8")?
            .to_owned(),
        requested_parent: parent
            .to_str()
            .context("requested destination parent is not UTF-8")?
            .to_owned(),
        canonical_root: config.root,
        canonical_destination: canonical_destination
            .to_str()
            .context("canonical destination is not UTF-8")?
            .to_owned(),
        receiver_path: receiver_path
            .to_str()
            .context("restricted receiver path is not UTF-8")?
            .to_owned(),
        receipt_public_key,
        change: match change {
            AuthorizedKeysChange::Installed => "installed",
            AuthorizedKeysChange::Unchanged => "unchanged",
            AuthorizedKeysChange::Revoked => unreachable!("install cannot revoke"),
        }
        .to_owned(),
    };
    serde_json::to_writer(std::io::stdout().lock(), &response)?;
    Ok(())
}

pub(crate) fn remote_revoke() -> Result<()> {
    let mut encoded = Vec::new();
    std::io::stdin()
        .take(MAX_STATE_FILE as u64 + 1)
        .read_to_end(&mut encoded)?;
    if encoded.len() > MAX_STATE_FILE {
        bail!("restricted revocation request is too large");
    }
    let request: RevokeRequest = serde_json::from_slice(&encoded)?;
    if request.version != CONFIG_VERSION {
        bail!("unsupported restricted revocation request version");
    }
    request.id.validate()?;
    let (account, home) = current_account()?;
    revoke_for_account(&request, &account, &home)
}

fn revoke_for_account(request: &RevokeRequest, account: &str, home: &Path) -> Result<()> {
    if account != request.target_login {
        bail!("revocation target login does not match the remote account");
    }
    // Serialize revocation with both enrollment updates and receiver admission.
    let ssh = ensure_directory_chain(home, &[".ssh"])?;
    let directory = open_directory(&ssh)?;
    lock_directory(&directory)?;
    let state_base = home.join(".local/share/syq/restricted");
    let state = state_base.join(request.id.to_string());
    let (receiver_path, remove_state) = match fs::symlink_metadata(&state) {
        Ok(_) => {
            delegation::validate_private_directory_path(&state)?;
            let (config, allowed_signers, _) = receiver_config(request.id)?;
            if config.target_login != request.target_login {
                bail!("revocation target login does not match receiver state");
            }
            let state = allowed_signers
                .parent()
                .context("restricted receiver state has no enrollment directory")?;
            (
                PathBuf::from(config.receiver_path),
                Some(state.to_path_buf()),
            )
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            (receiver_install_path(home), None)
        }
        Err(error) => return Err(error).context("inspect restricted receiver state"),
    };
    let enrollment_key = EnrollmentPublicKey::parse(&request.public_key)?;
    let entry = AuthorizedKeyEntry::new(request.id, &receiver_path, &enrollment_key)?;
    // Validate the shared state chain before removing the credential. The
    // second check below determines whether the now-updated state is empty.
    let _ = directory_is_empty(&state_base)?;
    let leases = remove_state
        .as_deref()
        .map(active::open_leases)
        .transpose()?;
    let original =
        read_leaf(&directory, "authorized_keys", MAX_AUTHORIZED_KEYS, false)?.unwrap_or_default();
    let normalized = normalize_managed_authorized_keys(&original, &entry.marker());
    let (updated, _) = enrollment::revoke_authorized_key(&normalized, &entry)?;
    atomic_write_locked(&directory, "authorized_keys", &updated, 0o600, false)?;
    if let Some(state) = remove_state {
        active::revoke(&state, leases.as_ref().expect("enrollment lease file"))?;
        fs::remove_dir_all(&state)
            .with_context(|| format!("remove revoked receiver state {}", state.display()))?;
    }
    let last_enrollment =
        !contains_managed_enrollment(&updated) && directory_is_empty(&state_base)?;
    if last_enrollment {
        let installed_receiver = receiver_install_path(home);
        if receiver_path != installed_receiver {
            bail!(
                "refusing to remove unexpected restricted receiver path {}",
                receiver_path.display()
            );
        }
        remove_final_enrollment_state_directories(home)?;
        match fs::symlink_metadata(&installed_receiver) {
            Ok(_) => {
                delegation::validate_regular_executable(
                    &installed_receiver,
                    "restricted receiver",
                )?;
                fs::remove_file(&installed_receiver).with_context(|| {
                    format!(
                        "remove final restricted receiver {}",
                        installed_receiver.display()
                    )
                })?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspect {}", installed_receiver.display()))
            }
        }
        // `.local`, `share`, and `libexec` are general account directories.
        // Without a durable record proving syq created them, preserve them
        // even when the final enrollment leaves them empty.
    }
    drop(directory);
    println!("revoked {}", request.id);
    Ok(())
}

fn normalize_managed_authorized_keys(original: &[u8], marker: &str) -> Vec<u8> {
    let mut normalized = Vec::with_capacity(original.len());
    for raw in original.split_inclusive(|byte| *byte == b'\n') {
        let line = raw.strip_suffix(b"\n").unwrap_or(raw);
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let trimmed = line
            .iter()
            .copied()
            .skip_while(u8::is_ascii_whitespace)
            .collect::<Vec<_>>();
        let commented_managed = trimmed.starts_with(b"#")
            && line
                .rsplit(|byte| byte.is_ascii_whitespace())
                .find(|word| !word.is_empty())
                == Some(marker.as_bytes());
        if !commented_managed {
            normalized.extend_from_slice(line);
            normalized.push(b'\n');
        }
    }
    normalized
}

fn local_state_base() -> Result<PathBuf> {
    let (_, home) = current_account()?;
    ensure_private_chain(&home, &[".local", "state", "syq", "restricted"])
        .context("validate restricted enrollment state on the invoking machine")
}

fn store_pending_enrollment(
    pending: &PendingEnrollment,
    private_key: &PrivateKey,
) -> Result<PathBuf> {
    let base = local_state_base()?;
    let directory = base.join(pending.id.to_string());
    ensure_directory(&directory, 0o700)?;
    store_pending_files(&directory, pending, private_key)?;
    Ok(directory)
}

fn store_pending_files(
    directory: &Path,
    pending: &PendingEnrollment,
    private_key: &PrivateKey,
) -> Result<()> {
    let private = private_key
        .to_openssh(LineEnding::LF)
        .context("encode enrollment private key")?;
    atomic_write(directory, "enrollment-key", private.as_bytes(), 0o600)?;
    atomic_write(
        directory,
        "pending.json",
        &serde_json::to_vec(pending)?,
        0o600,
    )
}

fn complete_local_enrollment(directory: &Path, metadata: &LocalEnrollment) -> Result<()> {
    atomic_write(
        directory,
        "metadata.json",
        &serde_json::to_vec(metadata)?,
        0o600,
    )?;
    let directory = open_directory(directory)?;
    lock_directory(&directory)?;
    remove_leaf_locked(&directory, "pending.json")
}

fn load_local_enrollments() -> Result<Vec<(LocalEnrollment, PathBuf)>> {
    let base = local_state_base()?;
    let mut enrollments = Vec::new();
    for entry in fs::read_dir(&base).with_context(|| format!("list {}", base.display()))? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let directory = entry.path();
        if delegation::validate_private_directory_path(&directory).is_err() {
            continue;
        }
        let metadata_path = directory.join("metadata.json");
        let Ok(encoded) = delegation::read_private_regular(
            &metadata_path,
            "local enrollment metadata",
            MAX_STATE_FILE,
        ) else {
            continue;
        };
        let Ok(metadata) = serde_json::from_slice::<LocalEnrollment>(&encoded) else {
            continue;
        };
        if metadata.version == CONFIG_VERSION
            && metadata.id.to_string() == entry.file_name().to_string_lossy()
        {
            enrollments.push((metadata, directory));
        }
    }
    Ok(enrollments)
}

fn load_pending_enrollments() -> Result<Vec<(PendingEnrollment, PathBuf)>> {
    let base = local_state_base()?;
    let mut enrollments = Vec::new();
    for entry in fs::read_dir(&base).with_context(|| format!("list {}", base.display()))? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let directory = entry.path();
        if delegation::validate_private_directory_path(&directory).is_err() {
            continue;
        }
        let metadata_path = directory.join("pending.json");
        let Ok(encoded) = delegation::read_private_regular(
            &metadata_path,
            "pending local enrollment metadata",
            MAX_STATE_FILE,
        ) else {
            continue;
        };
        let Ok(metadata) = serde_json::from_slice::<PendingEnrollment>(&encoded) else {
            continue;
        };
        if metadata.version == CONFIG_VERSION
            && metadata.id.to_string() == entry.file_name().to_string_lossy()
        {
            enrollments.push((metadata, directory));
        }
    }
    enrollments.sort_by_key(|(metadata, _)| metadata.id.to_string());
    Ok(enrollments)
}

fn load_private_key(directory: &Path) -> Result<PrivateKey> {
    let encoded = delegation::read_private_regular(
        &directory.join("enrollment-key"),
        "enrollment private key",
        128 * 1024,
    )?;
    PrivateKey::from_openssh(&encoded).context("parse enrollment private key")
}

#[derive(Debug)]
struct EnrollmentSshError {
    message: String,
    transport: bool,
}

impl fmt::Display for EnrollmentSshError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for EnrollmentSshError {}

fn enrollment_ssh_error(
    target: &SshEndpoint,
    transport: bool,
    message: impl fmt::Display,
) -> anyhow::Error {
    anyhow::Error::new(EnrollmentSshError {
        message: format!(
            "restricted enrollment SSH to {} failed: {message}",
            target.label()
        ),
        transport,
    })
}

fn is_enrollment_transport_failure(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<EnrollmentSshError>()
            .is_some_and(|failure| failure.transport)
    })
}

fn run_ssh(
    target: &SshEndpoint,
    route: EnrollmentRoute<'_>,
    remote_command: &str,
    input: &[u8],
) -> Result<Vec<u8>> {
    let args = enrollment::enrollment_ssh_args_raw(target, route, remote_command);
    let mut command = Command::new("ssh");
    command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| enrollment_ssh_error(target, true, error))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| enrollment_ssh_error(target, true, "stdin unavailable"))?;
    let write_error = stdin.write_all(input).err();
    drop(stdin);
    let output = child
        .wait_with_output()
        .map_err(|error| enrollment_ssh_error(target, true, error))?;
    if !output.status.success() {
        let diagnostic = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(enrollment_ssh_error(
            target,
            output.status.code() == Some(255),
            format_args!(
                "{}: {}",
                output.status,
                if diagnostic.is_empty() {
                    "no diagnostic"
                } else {
                    &diagnostic
                }
            ),
        ));
    }
    if let Some(error) = write_error {
        return Err(enrollment_ssh_error(target, true, error));
    }
    Ok(output.stdout)
}

#[derive(Clone, Copy)]
enum ManagementAction {
    Install,
    Revoke,
}

impl ManagementAction {
    fn argument(self) -> &'static str {
        match self {
            Self::Install => "--restricted-install",
            Self::Revoke => "--restricted-revoke",
        }
    }
}

fn management_remote_command(
    stage: &str,
    action: ManagementAction,
    request: &[u8],
) -> Result<String> {
    let request = std::str::from_utf8(request).context("management request is not UTF-8")?;
    Ok(format!(
        "set -eu; d=\"$HOME/.local/libexec\"; p=\"$d/{stage}\"; umask 077; mkdir -p -- \"$d\"; trap 'rm -f -- \"$p\"' EXIT; trap 'exit 129' HUP; trap 'exit 130' INT; trap 'exit 143' TERM; cat >\"$p\"; chmod 700 \"$p\"; printf '%s' {} | \"$p\" {}",
        shell_words::quote(request),
        action.argument()
    ))
}

fn run_management_over_route(
    target: &SshEndpoint,
    route: EnrollmentRoute<'_>,
    id: EnrollmentId,
    action: ManagementAction,
    input: &[u8],
) -> Result<Vec<u8>> {
    let platform = run_ssh(target, route.clone(), "set -eu; uname -s; uname -m", &[])?;
    let platform = std::str::from_utf8(&platform).context("receiver platform is not UTF-8")?;
    let mut lines = platform.lines();
    let os = lines
        .next()
        .context("receiver platform probe returned no operating system")?;
    let arch = lines
        .next()
        .context("receiver platform probe returned no architecture")?;
    let platform = crate::remote_helper::Target::for_bootstrap(os, arch)
        .with_context(|| format!("restricted enrollment does not support {os} {arch}"))?;
    let bytes = management_executable(platform)?;
    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce).context("generate receiver staging filename")?;
    let stage = format!(".syq-receiver-{}-{:016x}", id, u64::from_le_bytes(nonce));
    let command = management_remote_command(&stage, action, input)?;
    // Upload and invocation share one SSH session. The remote shell installs
    // its cleanup trap before reading the binary and retains it until the
    // management helper exits, so there is no inter-session orphan window or
    // cleanup request that depends on a route which has already failed.
    run_ssh(target, route, &command, &bytes)
}

fn management_executable(target: crate::remote_helper::Target) -> Result<Vec<u8>> {
    // A source build opting into release helpers must use the verified upstream
    // helper even on its own platform. Official releases keep their offline path.
    if (crate::identity::uses_release_helpers() && !crate::identity::is_release_build())
        || !target.can_upload_self()
    {
        if crate::identity::uses_release_helpers() {
            let helper = crate::update::trusted_current_helper(target)?;
            return crate::update::verified_current_helper(&helper);
        }
        bail!("cannot install a source-built restricted receiver for {} from {}; use an official release or enroll from a compatible host", target.key, crate::identity::platform());
    }
    // Same-platform enrollment and revocation retain their existing offline
    // upload path, including official releases.
    #[cfg(target_os = "linux")]
    let executable = PathBuf::from("/proc/self/exe");
    #[cfg(not(target_os = "linux"))]
    let executable = std::env::current_exe().context("resolve local syq executable")?;
    read_local_management_executable(&executable)
}

fn read_local_management_executable(path: &Path) -> Result<Vec<u8>> {
    let executable = fs::canonicalize(path)
        .with_context(|| format!("canonicalize local syq executable {}", path.display()))?;
    let mut binary = File::open(&executable)
        .with_context(|| format!("open local syq executable {}", executable.display()))?;
    let metadata = binary
        .metadata()
        .with_context(|| format!("inspect local syq executable {}", executable.display()))?;
    if !metadata.is_file() {
        bail!(
            "local syq executable {} must be a regular file",
            executable.display()
        );
    }
    let mut bytes = Vec::new();
    binary
        .read_to_end(&mut bytes)
        .with_context(|| format!("read local syq executable {}", executable.display()))?;
    Ok(bytes)
}

fn install_over_route(
    target: &SshEndpoint,
    route: EnrollmentRoute<'_>,
    request: &InstallRequest,
) -> Result<InstallResponse> {
    let expected_id = request.id;
    let expected_login = request.target_login.clone();
    let request = serde_json::to_vec(request)?;
    let output = run_management_over_route(
        target,
        route,
        expected_id,
        ManagementAction::Install,
        &request,
    )?;
    let response: InstallResponse =
        serde_json::from_slice(&output).context("decode restricted enrollment response")?;
    if response.version != CONFIG_VERSION
        || response.id != expected_id
        || response.target_login != expected_login
    {
        bail!("restricted enrollment response did not match the request");
    }
    Ok(response)
}

fn endpoint(login: &str, host: &str, port: Option<u16>) -> Result<SshEndpoint> {
    SshEndpoint::from_parts(login, host, port)
}

fn enroll(
    host: &str,
    port: Option<u16>,
    login: &str,
    requested_destination: &str,
    jump: Option<&SshEndpoint>,
    refresh_existing: bool,
) -> Result<(LocalEnrollment, PathBuf, Vec<u8>)> {
    let base = local_state_base()?;
    let base_lock = open_directory(&base)?;
    lock_directory(&base_lock)?;

    let mut active = None;
    for (metadata, directory) in load_local_enrollments()? {
        if metadata.host == host && metadata.port == port && metadata.target_login == login {
            if let Some(canonical_destination) =
                destination_for(&metadata, requested_destination.as_bytes())?
            {
                active = Some((metadata, directory, canonical_destination));
                break;
            }
        }
    }
    if !refresh_existing {
        if let Some(existing) = active.take() {
            return Ok(existing);
        }
    }
    let retry_state = if active.is_some() {
        "remains active with its previous metadata; the receiver refresh can be retried"
    } else {
        "remains pending for a safe retry"
    };

    let pending = if active.is_none() {
        load_pending_enrollments()?
            .into_iter()
            .find(|(pending, _)| {
                pending.host == host
                    && pending.port == port
                    && pending.target_login == login
                    && pending.requested_destination == requested_destination
            })
    } else {
        None
    };
    let (pending, directory, private_key) = match (active, pending) {
        (Some((metadata, directory, _)), _) => {
            let private_key = load_private_key(&directory)?;
            let pending = PendingEnrollment {
                version: CONFIG_VERSION,
                id: metadata.id,
                host: metadata.host,
                port: metadata.port,
                target_login: metadata.target_login,
                requested_destination: requested_destination.to_owned(),
            };
            (pending, directory, private_key)
        }
        (None, Some((pending, directory))) => {
            let private_key = load_private_key(&directory)?;
            (pending, directory, private_key)
        }
        (None, None) => {
            let id = EnrollmentId::random();
            let private_key = generate_enrollment_key(id)?;
            let pending = PendingEnrollment {
                version: CONFIG_VERSION,
                id,
                host: host.to_owned(),
                port,
                target_login: login.to_owned(),
                requested_destination: requested_destination.to_owned(),
            };
            let directory = store_pending_enrollment(&pending, &private_key)?;
            (pending, directory, private_key)
        }
    };
    let public_key = private_key.public_key().to_openssh()?;
    let request = InstallRequest {
        version: CONFIG_VERSION,
        id: pending.id,
        target_login: login.to_owned(),
        requested_destination: requested_destination.to_owned(),
        public_key,
    };
    let target = endpoint(login, host, port)?;
    let direct = install_over_route(&target, EnrollmentRoute::Direct, &request);
    let response = match (direct, jump) {
        (Ok(response), _) => response,
        (Err(direct_error), Some(jump)) if is_enrollment_transport_failure(&direct_error) => {
            install_over_route(&target, EnrollmentRoute::ProxyJump { jump }, &request)
                .with_context(|| {
                    format!(
                "enrollment {} {retry_state}; direct enrollment also failed: {direct_error:#}",
                pending.id,
            )
                })?
        }
        (Err(error), _) => {
            return Err(error).with_context(|| format!("enrollment {} {retry_state}", pending.id,))
        }
    };
    let metadata = LocalEnrollment {
        version: CONFIG_VERSION,
        id: pending.id,
        host: host.to_owned(),
        port,
        target_login: login.to_owned(),
        remote_home: response.remote_home,
        requested_parent: response.requested_parent,
        canonical_root: response.canonical_root,
        receiver_path: response.receiver_path,
        receipt_public_key: response.receipt_public_key,
    };
    complete_local_enrollment(&directory, &metadata)?;
    Ok((
        metadata,
        directory,
        response.canonical_destination.into_bytes(),
    ))
}

fn destination_for(metadata: &LocalEnrollment, requested: &[u8]) -> Result<Option<Vec<u8>>> {
    use std::os::unix::ffi::OsStrExt as _;
    let normalized = normalize_absolute(
        std::ffi::OsStr::from_bytes(requested),
        Path::new(&metadata.remote_home),
    )?;
    if requested_parent(&normalized) != Path::new(&metadata.requested_parent) {
        return Ok(None);
    }
    let leaf = normalized
        .file_name()
        .context("restricted destination / is not supported")?;
    // The enrollment's canonical root is UTF-8 (it is administrative,
    // declared at enrollment time); the leaf may be any bytes.
    Ok(Some(
        Path::new(&metadata.canonical_root)
            .join(leaf)
            .as_os_str()
            .as_bytes()
            .to_vec(),
    ))
}

fn now() -> Result<i64> {
    i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
        .context("current time exceeds signed grant range")
}

fn root_existence_for(existence: Existence) -> RootExistence {
    match existence {
        Existence::Any => RootExistence::Any,
        Existence::New => RootExistence::New,
        Existence::Existing => RootExistence::Existing,
    }
}

pub(crate) fn validate_restricted_args(args: &Args) -> Result<()> {
    if let Some(input) = &args.mapping_contents {
        input.validate_restricted_bounds()?;
    }
    if args.tcp_plain {
        bail!("command-restricted transfers require encrypted data connections");
    }
    if args.inplace
        && (args.only_new_native_entries()
            || args.existing
            || (args.target_existence == Existence::New && args.placement == Placement::As))
    {
        bail!(
            "--inplace cannot be combined with --only-new, --only-existing, or --as-new on the command-restricted path: in-place writes open the final pathname directly, so the receiver can neither make them no-replace nor pin them to an observed object"
        );
    }
    if !args.dry_run && !args.verify_only && args.delete && args.max_delete.is_none() {
        // The signed deletion count is the only bound on what a compromised
        // hostA can remove inside the scope, so make it an explicit choice
        // instead of a silent hundred-million default.
        bail!(
            "deletion through the command-restricted receiver needs an explicit --max-delete ceiling"
        );
    }
    // Range-check every ceiling here, before automatic enrollment can touch
    // hostB, rather than leaving it to grant validation after the fact.
    if args
        .receiver_max_entries
        .is_some_and(|entries| entries == 0 || entries > delegation::MAX_ENTRIES)
    {
        bail!(
            "--receiver-max-entries must be between 1 and {}",
            delegation::MAX_ENTRIES
        );
    }
    if args
        .receiver_max_bytes
        .is_some_and(|bytes| bytes == 0 || bytes > delegation::MAX_COPY_BYTES)
    {
        bail!("--receiver-max-bytes must be at least 1 byte");
    }
    if let Some(maximum) = args.max_size.as_deref() {
        if crate::cli::parse_size(maximum)? == 0 {
            bail!("--max-size must be at least 1 byte on the command-restricted path");
        }
    }
    if !args.files_from_lines.is_empty() || args.files_from.is_some() || args.min_size.is_some() {
        bail!(
            "--files-from and --min-size are not yet independently enforceable by the command-restricted receiver"
        );
    }
    if args.pscope_explicit {
        bail!(
            "--pscope is not available with the command-restricted receiver: its host-bound authentication is verified per fresh connection"
        );
    }
    if !args.dry_run && !args.verify_only && args.delete && args.max_size.is_some() {
        bail!(
            "--max-size with deletion is not yet independently enforceable by the command-restricted receiver"
        );
    }
    if args.connections_opt.is_some() && args.connections > usize::from(delegation::MAX_CONNECTIONS)
    {
        bail!(
            "command-restricted transfers support at most {} connections",
            usize::from(delegation::MAX_CONNECTIONS)
        );
    }
    crate::conn::parse_ports(&args.tcp_ports)?;
    if let Some(maximum) = args.max_size.as_deref() {
        crate::cli::parse_size(maximum)?;
    }
    Ok(())
}

fn grant_for(
    args: &Args,
    sources: &[Location],
    id: EnrollmentId,
    login: &str,
    destination: &[u8],
) -> Result<Grant> {
    validate_restricted_args(args)?;
    let issued_at = now()?;
    let read_only = args.dry_run || args.verify_only;
    // `--max-delete 0` means nothing may be deleted, which the grant states
    // directly as a forbidding policy rather than a zero budget.
    let deletion = if !read_only && args.delete && args.max_delete != Some(0) {
        DeletionPolicy::DeleteDestinationOnly
    } else {
        DeletionPolicy::Forbid
    };
    let max_entries = args.receiver_max_entries.unwrap_or(DEFAULT_MAX_ENTRIES);
    let max_total_bytes = args.receiver_max_bytes.unwrap_or(DEFAULT_MAX_BYTES);
    let max_file_bytes = args
        .max_size
        .as_deref()
        .map(crate::cli::parse_size)
        .transpose()?
        .unwrap_or(DEFAULT_MAX_BYTES)
        .min(max_total_bytes);
    let max_deletions = match deletion {
        DeletionPolicy::Forbid => 0,
        DeletionPolicy::DeleteDestinationOnly => args
            .max_delete
            .context("deletion through the command-restricted receiver needs --max-delete")?
            .min(max_entries),
    };
    let start_by = issued_at
        .checked_add(GRANT_VALIDITY_SECONDS - CLOCK_SKEW_SECONDS)
        .context("signed grant start-by overflow")?;
    let finish_by = issued_at
        .checked_add(FINISH_WINDOW_SECONDS)
        .context("signed grant finish-by overflow")?;
    let copies_contents = sources.iter().any(Location::copies_contents);
    let placement = match args.placement {
        Placement::As => DestinationPlacement::ExactPath,
        Placement::Into | Placement::Rsync if copies_contents => {
            DestinationPlacement::DirectoryContents
        }
        Placement::Into | Placement::Rsync => DestinationPlacement::DirectoryAsChild,
    };
    let destination_bytes = destination.to_vec();
    let mut mutation_scopes = match placement {
        DestinationPlacement::ExactPath | DestinationPlacement::DirectoryContents => {
            vec![MutationScope {
                path: destination_bytes.clone(),
                descendants: args.recursive && args.expected_digest.is_none(),
            }]
        }
        DestinationPlacement::DirectoryAsChild => {
            let mut scopes = vec![MutationScope {
                path: destination_bytes.clone(),
                descendants: false,
            }];
            for source in sources {
                let basename = source.basename();
                if basename.is_empty() {
                    bail!("named source has no destination basename for signed scope");
                }
                scopes.push(MutationScope {
                    path: crate::fsops::join(&destination_bytes, &basename),
                    descendants: args.recursive && args.expected_digest.is_none(),
                });
            }
            scopes
        }
    };
    mutation_scopes.sort_by(|left, right| left.path.cmp(&right.path));
    mutation_scopes.dedup_by(|left, right| left.path == right.path);
    // Per-object policy only. The placement root's own precondition
    // (`--into-existing` and friends) is the separate signed root-existence
    // field; folding it in here would forbid creating files inside an
    // existing directory.
    // Timestamp selection is a coordinator policy based on source metadata.
    // The receiver enforces only the independently observable write authority.
    let existing = if args.only_new_native_entries() {
        ExistingDestinationPolicy::Skip
    } else if args.existing {
        ExistingDestinationPolicy::MustExist
    } else {
        ExistingDestinationPolicy::Replace
    };
    let (tcp_port_lo, tcp_port_hi) = crate::conn::parse_ports(&args.tcp_ports)?;
    let grant = Grant {
        enrollment_id: id,
        target_login: login.to_owned(),
        signer: signer_name(id),
        request_id: RequestId::fresh(issued_at)?,
        issued_at,
        not_before: issued_at.saturating_sub(CLOCK_SKEW_SECONDS),
        start_by,
        finish_by,
        operation: GrantOperation::Copy(CopyOperation {
            destination: destination_bytes,
            mutation_scopes,
            policy: CopyPolicy {
                placement,
                existing,
                deletion,
                publication: if args.inplace {
                    PublicationPolicy::InPlace
                } else {
                    PublicationPolicy::AtomicStaged
                },
            },
            options: CopyOptions {
                recursive: args.recursive,
                preserve_symlinks: args.links,
                preserve_permissions: args.perms,
                receiver_managed_modes: !args.perms,
                preserve_times: args.times,
                preserve_owner: args.owner,
                preserve_group: args.group,
                preserve_devices: args.devices,
                compare_existing_by_content: args.checksum,
                dry_run: args.dry_run,
                verify_only: args.verify_only,
                compressed_transport: args.compress,
                tcp_port_lo,
                tcp_port_hi,
            },
            limits: CopyLimits {
                max_entries,
                max_total_bytes,
                max_file_bytes,
                hash_block_bytes: args.block_size,
                max_connections: u16::try_from(if args.connections_opt.is_some() {
                    args.connections
                } else {
                    args.resource_limits
                        .as_ref()
                        .and_then(|limits| limits.workers)
                        .unwrap_or(usize::from(delegation::MAX_CONNECTIONS))
                        .min(usize::from(delegation::MAX_CONNECTIONS))
                })
                .context("connection maximum exceeds grant representation")?,
                max_deletions,
            },
        }),
    };
    Ok(grant)
}

fn filter_destination_roots(
    args: &Args,
    sources: &[Location],
    destination: &[u8],
) -> Result<Vec<Vec<u8>>> {
    let mut roots = Vec::with_capacity(sources.len());
    for source in sources {
        if args.placement == Placement::As || source.copies_contents() {
            roots.push(destination.to_vec());
        } else {
            let basename = source.basename();
            if basename.is_empty() {
                bail!("named source has no destination basename for signed filters");
            }
            roots.push(crate::fsops::join(destination, &basename));
        }
    }
    roots.sort();
    roots.dedup();
    Ok(roots)
}

fn mapping_authorization(args: &Args) -> Result<Option<crate::mapping::Authorization>> {
    args.mapping_contents
        .as_ref()
        .map(|input| input.authorization())
        .transpose()
}

pub(crate) fn prepare_transfer(
    args: &Args,
    sources: &[Location],
    destination: &Location,
    source_login: &str,
    destination_login: &str,
    allow_enrollment: bool,
) -> Result<PreparedTransfer> {
    validate_restricted_args(args)?;
    let host = destination
        .host
        .as_deref()
        .context("destination host missing")?;
    let requested = destination.path.as_slice();
    let mut selected = None;
    for (metadata, directory) in load_local_enrollments()? {
        if metadata.host == host
            && metadata.port == destination.port
            && metadata.target_login == destination_login
        {
            if let Some(canonical_destination) = destination_for(&metadata, requested)? {
                selected = Some((metadata, directory, canonical_destination));
                break;
            }
        }
    }
    let (metadata, directory, canonical_destination) = match selected {
        Some(selected) => selected,
        None => {
            if !allow_enrollment {
                bail!(
                    "read-only operations will not install a receiver enrollment; pre-enroll this destination with `syq receiver enroll` or explicitly use --peer-auth broker"
                );
            }
            let jump = endpoint(
                source_login,
                sources[0].host.as_deref().context("source host missing")?,
                sources[0].port,
            )?;
            enroll(
                host,
                destination.port,
                destination_login,
                // Automatic enrollment declares a new administrative scope,
                // which stays UTF-8; transfers against an existing
                // enrollment accept any destination bytes above.
                std::str::from_utf8(requested).context(
                    "automatic enrollment requires a UTF-8 destination; pre-enroll a scope with `syq receiver enroll` to copy to this path",
                )?,
                Some(&jump),
                false,
            )?
        }
    };
    let private_key = load_private_key(&directory)?;
    let receipt_public_key = metadata.receipt_public_key.clone();
    let grant = grant_for(
        args,
        sources,
        metadata.id,
        destination_login,
        &canonical_destination,
    )?;
    let protected = receiver_control_paths(
        Path::new(&metadata.remote_home),
        Path::new(&metadata.receiver_path),
        None,
    )?;
    let GrantOperation::Copy(copy) = &grant.operation;
    reject_control_plane_scopes(copy, &protected)?;
    let request_id = grant.request_id;
    let (receipt_recipient_secret, receipt_delivery) = if args.detach {
        (
            None,
            crate::receipt::ReceiptDelivery::DetachedSignedPlaintext,
        )
    } else {
        let (secret, public) = crate::receipt::generate_recipient()?;
        (
            Some(secret),
            crate::receipt::ReceiptDelivery::AttachedEncrypted {
                suite: crate::receipt::HpkeSuite::X25519HkdfSha256HkdfSha256ChaCha20Poly1305,
                recipient_public_key: public,
            },
        )
    };
    let receipt_policy = crate::receipt::ReceiptPolicy {
        required: true,
        hashed: args.receiver_receipt == Some(crate::cli::ReceiptDetail::Digests),
        max_records: crate::receipt::DEFAULT_MAX_RECORDS,
        max_plaintext_bytes: crate::receipt::DEFAULT_MAX_PLAINTEXT_BYTES,
        delivery: receipt_delivery,
    };
    let grant = delegation::sign_grant(
        grant,
        GrantConstraints {
            tcp_congestion: args.tcp_congestion.clone(),
            mapping: mapping_authorization(args)?,
            hashing: Some(crate::hashing::CopyHashing::from_args(args)),
            max_file_data_bytes_per_second: args.bwlimit_bytes,
            filters: FilterPolicy {
                ignore: args.ignore_lines.clone(),
                destination_roots: filter_destination_roots(args, sources, &canonical_destination)?,
                delete_excluded: args.delete_excluded,
            },
            root_existence: root_existence_for(args.target_existence),
            receipt_policy: receipt_policy.clone(),
        },
        &private_key,
    )?;
    let grant_digest = delegation::signed_grant_digest(&grant)?;
    Ok(PreparedTransfer {
        private_key,
        request_id,
        receipt_public_key,
        receipt_recipient_secret,
        receipt_policy,
        grant_digest,
        canonical_destination,
        grant: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(grant),
        enrollment_id: metadata.id,
    })
}

/// Build a request without trusting the source's eventual filesystem claims.
/// The receiving laptop separately confines and approves every mutation scope.
pub(crate) fn named_request(
    args: &Args,
    receipt_policy: crate::receipt::ReceiptPolicy,
) -> Result<crate::destination::CopyRequest> {
    let (destination, sources) = args
        .locations
        .split_last()
        .context("copy endpoints missing")?;
    let mut checked = args.clone();
    // These channels are encrypted by the laptop-initiated SSH connection.
    checked.no_tcp = false;
    let path = crate::destination::request_path(b".")?;
    let grant = grant_for(
        &checked,
        sources,
        EnrollmentId::random(),
        "named-destination",
        &path,
    )?;
    let GrantOperation::Copy(copy) = grant.operation;
    Ok(crate::destination::CopyRequest {
        destination: destination.path.clone(),
        copy,
        constraints: GrantConstraints {
            tcp_congestion: args.tcp_congestion.clone(),
            mapping: mapping_authorization(args)?,
            hashing: Some(crate::hashing::CopyHashing::from_args(args)),
            max_file_data_bytes_per_second: args.bwlimit_bytes,
            filters: FilterPolicy {
                ignore: args.ignore_lines.clone(),
                destination_roots: filter_destination_roots(args, sources, &path)?,
                delete_excluded: args.delete_excluded,
            },
            root_existence: root_existence_for(args.target_existence),
            receipt_policy,
        },
    })
}

/// A fresh, in-memory authorization minted on the receiving machine after
/// approval. It shares the restricted executor, but never reads or changes an
/// SSH enrollment, a signed grant's replay store, or persistence preferences.
pub(crate) fn named_authority(
    root: &Path,
    request: crate::destination::CopyRequest,
) -> Result<(
    std::sync::Arc<RestrictedAuthority>,
    crate::destination::Approved,
)> {
    let (login, home) = current_account()?;
    let parent = root;
    let metadata = fs::metadata(parent)?;
    let id = EnrollmentId::random();
    let issued_at = now()?;
    let request_id = RequestId::fresh(issued_at)?;
    let grant = Grant {
        enrollment_id: id,
        target_login: login.clone(),
        signer: signer_name(id),
        request_id,
        issued_at,
        not_before: issued_at,
        start_by: issued_at + 60,
        finish_by: issued_at + FINISH_WINDOW_SECONDS,
        operation: GrantOperation::Copy(request.copy.clone()),
    };
    let key = generate_receipt_key(id)?;
    // Reuse the complete canonical grant validator. This ephemeral signature
    // is not sent to the requester as a redeemable enrollment credential.
    let signed = delegation::sign_grant(grant.clone(), request.constraints.clone(), &key)?;
    let digest = delegation::signed_grant_digest(&signed)?;
    let executable = fs::canonicalize(std::env::current_exe()?)?;
    let home = fs::canonicalize(home)?;
    let mut protected = receiver_control_paths(&home, &executable, None)?;
    for directory in [
        ".syq-receive-v1",
        ".syq-destinations-v1",
        ".syq-destinations-v2",
        ".syq-destinations-v3",
    ] {
        protected.push(ReceiverControlPath {
            path: home.join(directory).as_os_str().as_bytes().to_vec(),
            label: "named destination authority state",
        });
    }
    for path in [
        crate::destination::receiver_identity_directory()?,
        crate::receive_service::config_path()?
            .parent()
            .unwrap()
            .to_path_buf(),
        crate::persistence::runtime_parent_path(),
    ] {
        protected.push(ReceiverControlPath {
            path: path.as_os_str().as_bytes().to_vec(),
            label: "background receiving control state",
        });
    }
    let config = ReceiverEnrollment {
        version: CONFIG_VERSION,
        id,
        target_login: login,
        signer: signer_name(id),
        root: parent
            .to_str()
            .context("receiving directory must be UTF-8")?
            .into(),
        root_dev: metadata.dev(),
        root_ino: metadata.ino(),
        ssh_keygen: String::new(),
        receiver_path: executable.to_string_lossy().into_owned(),
    };
    let approved = crate::destination::Approved {
        token: String::new(),
        destination: request.copy.destination.clone(),
        enrollment: id,
        request: request_id,
        digest,
        receipt_key: key.public_key().to_openssh()?,
    };
    let authority = RestrictedAuthority::new(
        &config,
        grant,
        request.constraints,
        digest,
        key,
        Instant::now() + std::time::Duration::from_secs(FINISH_WINDOW_SECONDS as u64),
        &protected,
    )?;
    Ok((std::sync::Arc::new(authority), approved))
}

pub(crate) fn receiver_config(id: EnrollmentId) -> Result<(ReceiverEnrollment, PathBuf, PathBuf)> {
    let (_, home) = current_account()?;
    let state = home
        .join(".local/share/syq/restricted")
        .join(id.to_string());
    let encoded = delegation::read_private_regular(
        &state.join("config.json"),
        "restricted receiver configuration",
        MAX_STATE_FILE,
    )?;
    let config: ReceiverEnrollment = serde_json::from_slice(&encoded)?;
    if config.version != CONFIG_VERSION || config.id != id {
        bail!("restricted receiver configuration does not match enrollment");
    }
    Ok((config, state.join("allowed-signers"), state.join("replay")))
}

pub(crate) fn run_receiver(enrollment: &str) -> Result<()> {
    let enrollment = EnrollmentId::parse(enrollment)?;
    let original = std::env::var("SSH_ORIGINAL_COMMAND")
        .context("restricted receiver requires SSH_ORIGINAL_COMMAND from sshd")?;
    if let Some(ticket) = ssh::worker_command(&original)? {
        let (_, _, replay) = receiver_config(enrollment)?;
        ssh::enter_state_directory(replay.parent().context("receiver state directory")?)?;
        return ssh::connect(&ticket);
    }
    let envelope = decode_receiver_command(&original)?;
    let (config, allowed_signers, replay_path) = receiver_config(enrollment)?;
    let state = replay_path.parent().context("receiver state directory")?;
    let observed_state = fs::symlink_metadata(state).context("inspect receiver enrollment")?;
    let (_, home) = current_account()?;
    let canonical_home = fs::canonicalize(&home)
        .with_context(|| format!("resolve receiver home {}", home.display()))?;
    let canonical_receiver = fs::canonicalize(&config.receiver_path).with_context(|| {
        format!(
            "resolve restricted receiver {}",
            Path::new(&config.receiver_path).display()
        )
    })?;
    let canonical_ssh_keygen = fs::canonicalize(&config.ssh_keygen).with_context(|| {
        format!(
            "resolve signature verifier {}",
            Path::new(&config.ssh_keygen).display()
        )
    })?;
    let protected = receiver_control_paths(
        &canonical_home,
        &canonical_receiver,
        Some(&canonical_ssh_keygen),
    )?;
    let replay = delegation::ReplayStore::open(&replay_path)?;
    let observed_at = Instant::now();
    let context = delegation::ReceiverContext {
        enrollment_id: enrollment,
        target_login: &config.target_login,
        expected_signer: &config.signer,
        clock: delegation::ClockObservation {
            unix_seconds: now()?,
            monotonic: observed_at,
        },
        clock_skew_seconds: CLOCK_SKEW_SECONDS,
    };
    let policy = delegation::SshsigPolicy {
        ssh_keygen: PathBuf::from(&config.ssh_keygen),
        allowed_signers,
        revocation_file: None,
    };
    let verified = delegation::verify_and_redeem(&envelope, &context, &policy, &replay)?;
    let (grant, extensions, grant_digest, deadline) = verified.into_parts();
    let receipt_key = load_receipt_key(replay_path.parent().context("receiver state directory")?)?;
    let authority = std::sync::Arc::new(RestrictedAuthority::new(
        &config,
        grant,
        extensions,
        grant_digest,
        receipt_key,
        deadline,
        &protected,
    )?);
    ssh::enter_state_directory(state)?;
    // Verification does not hold the lifecycle lock or permit mutations. A
    // revoke during verification is caught when this receiver tries to enter.
    active::watch(
        &home,
        state,
        (observed_state.dev(), observed_state.ino()),
        deadline,
    )?;
    crate::server::run_restricted(authority)
}

fn decode_receiver_command(original: &str) -> Result<Vec<u8>> {
    if original.len() > 128 * 1024 {
        bail!("restricted receiver command exceeds size limit");
    }
    let words = shell_words::split(original).context("parse restricted receiver command")?;
    if words.len() != 3 || words[0] != "syq" || words[1] != "--server" {
        bail!("the enrollment key accepts only a syq server request with one signed grant");
    }
    let encoded = words[2]
        .strip_prefix("--restricted-grant=")
        .context("restricted receiver command is missing its signed grant")?;
    let envelope = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .context("decode restricted receiver grant")?;
    Ok(envelope)
}

/// `syq receiver enroll|list|revoke`: the receiver enrollment system is one
/// subcommand with its verbs beneath it.
pub(crate) fn dispatch_receiver_command(argv: &[OsString]) -> Option<Result<i32>> {
    if argv.get(1)?.to_str()? != "receiver" {
        return None;
    }
    let matches = crate::help::receiver()
        .try_get_matches_from(
            std::iter::once(OsString::from("syq receiver")).chain(argv[2..].iter().cloned()),
        )
        .unwrap_or_else(|error| error.exit());
    let (command, options) = matches.subcommand().expect("subcommand required");
    let via = || -> Result<Option<SshEndpoint>> {
        options
            .get_one::<String>("via")
            .map(|value| SshEndpoint::parse(value))
            .transpose()
    };
    match command {
        "list" => Some((|| {
            let active = load_local_enrollments()?;
            let active_ids = active
                .iter()
                .map(|(metadata, _)| metadata.id)
                .collect::<HashSet<_>>();
            for (metadata, _) in active {
                let target = endpoint(&metadata.target_login, &metadata.host, metadata.port)?;
                println!(
                    "{}\tactive\t{}\t{}",
                    metadata.id,
                    target.label(),
                    metadata.canonical_root
                );
            }
            for (pending, _) in load_pending_enrollments()? {
                if !active_ids.contains(&pending.id) {
                    let target = endpoint(&pending.target_login, &pending.host, pending.port)?;
                    println!(
                        "{}\tpending\t{}\t{}",
                        pending.id,
                        target.label(),
                        pending.requested_destination
                    );
                }
            }
            Ok(0)
        })()),
        "enroll" => Some((|| {
            let target = options
                .get_one::<String>("target")
                .expect("target required");
            let location = Location::parse(target)?;
            let host = location
                .host
                .as_deref()
                .context("enrollment target must be remote")?;
            let requested = std::str::from_utf8(&location.path)
                .context("enrollment destination is not UTF-8")?;
            let via = via()?;
            let policy =
                crate::agent_broker::resolve_host_policy("ssh", location.user.as_deref(), host)?;
            let (metadata, _, destination) = enroll(
                host,
                None,
                &policy.login_user,
                requested,
                via.as_ref(),
                true,
            )?;
            println!(
                "enrolled {} for {}:{}",
                metadata.id,
                endpoint(&metadata.target_login, &metadata.host, metadata.port)?.label(),
                String::from_utf8_lossy(&destination)
            );
            Ok(0)
        })()),
        "revoke" => Some((|| {
            let id = EnrollmentId::parse(options.get_one::<String>("id").expect("ID required"))?;
            let via = via()?;
            let active = load_local_enrollments()?
                .into_iter()
                .find(|(metadata, _)| metadata.id == id);
            let (target_login, host, port, directory) = match active {
                Some((metadata, directory)) => (
                    metadata.target_login,
                    metadata.host,
                    metadata.port,
                    directory,
                ),
                None => {
                    let (pending, directory) = load_pending_enrollments()?
                        .into_iter()
                        .find(|(pending, _)| pending.id == id)
                        .context("no local enrollment has that ID")?;
                    (pending.target_login, pending.host, pending.port, directory)
                }
            };
            let private_key = load_private_key(&directory)?;
            let request = RevokeRequest {
                version: CONFIG_VERSION,
                id,
                target_login: target_login.clone(),
                public_key: private_key.public_key().to_openssh()?,
            };
            let target = endpoint(&target_login, &host, port)?;
            let encoded = serde_json::to_vec(&request)?;
            let direct = run_management_over_route(
                &target,
                EnrollmentRoute::Direct,
                id,
                ManagementAction::Revoke,
                &encoded,
            );
            match (direct, via.as_ref()) {
                (Ok(_), _) => {}
                (Err(direct_error), Some(via))
                    if is_enrollment_transport_failure(&direct_error) =>
                {
                    run_management_over_route(
                        &target,
                        EnrollmentRoute::ProxyJump { jump: via },
                        id,
                        ManagementAction::Revoke,
                        &encoded,
                    )
                    .with_context(|| format!("direct revocation also failed: {direct_error:#}"))?;
                }
                (Err(error), _) => return Err(error),
            }
            delegation::validate_private_directory_path(&directory)?;
            fs::remove_dir_all(&directory)
                .with_context(|| format!("remove local enrollment {}", directory.display()))?;
            println!("revoked {id} from {}", target.label());
            Ok(0)
        })()),
        _ => unreachable!("receiver subcommand validated by clap"),
    }
}

#[cfg(test)]
pub(crate) mod tests;

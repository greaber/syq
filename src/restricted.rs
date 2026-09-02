//! End-to-end enrollment and signed restricted-transfer integration.

use crate::cli::{Args, Existence, Location, Placement};
use crate::delegation::{
    self, CopyLimitsV1, CopyOperationV1, CopyOptionsV1, CopyPolicyV1, DeletionPolicyV1,
    DestinationPlacementV1, ExistingDestinationPolicyV1, FilterPolicyV3, GrantExtensions,
    GrantOperationV1, GrantV1, MutationScopeV1, PublicationPolicyV1, RequestId, RootExistenceV4,
};
use crate::enrollment::{
    self, AuthorizedKeyEntry, AuthorizedKeysChange, EnrollmentId, EnrollmentRoute, SshEndpoint,
    TransportPublicKey,
};
use crate::proto::{self, ContainerGuard, Op, Request};
use crate::rooted::{RelativePath, Root, RootIdentity, RootMetadata};
use anyhow::{bail, Context, Result};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use ssh_key::private::Ed25519Keypair;
use ssh_key::{LineEnding, PrivateKey};
use std::collections::{HashMap, HashSet};
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Instant;
use std::time::{SystemTime, UNIX_EPOCH};

const CONFIG_VERSION: u16 = 1;
const MAX_STATE_FILE: usize = 256 * 1024;
const MAX_AUTHORIZED_KEYS: usize = 16 * 1024 * 1024;
const DEFAULT_MAX_ENTRIES: u64 = 100_000_000;
const DEFAULT_MAX_BYTES: u64 = 8 * 1024 * 1024 * 1024 * 1024;
const DEFAULT_RUNTIME_SECONDS: u32 = 23 * 60 * 60;
const GRANT_VALIDITY_SECONDS: i64 = 24 * 60 * 60;
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
    /// Absent for enrollments installed before receivers had receipt keys;
    /// rerunning `syq enroll` refreshes them.
    #[serde(default)]
    receipt_public_key: Option<String>,
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
    pub(crate) canonical_destination: String,
    pub(crate) grant: String,
    pub(crate) enrollment_id: EnrollmentId,
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
    /// write or publication must name a declared partial.
    reserved: HashMap<(Vec<u8>, proto::PartialId), u64>,
    reserved_bytes: u64,
    transferred_bytes: u64,
    deletions: u64,
    live_connections: u16,
    tcp_listener_started: bool,
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

#[cfg(not(test))]
fn read_process_umask() -> u32 {
    // RestrictedAuthority is constructed by the forced receiver before it
    // starts any protocol worker threads.
    unsafe {
        let mask = libc::umask(0o022);
        libc::umask(mask);
        mask as u32
    }
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
    copy: CopyOperationV1,
    filters: FilterPolicyV3,
    filter_matcher: Option<ignore::gitignore::Gitignore>,
    filter_roots: Vec<Vec<u8>>,
    root_existence: RootExistenceV4,
    file_data_limit: Option<crate::bwlimit::BandwidthLimit>,
    receiver_umask: u32,
    deadline: Instant,
    control_open: AtomicBool,
    state: Mutex<AuthorityState>,
}

impl RestrictedAuthority {
    fn new(
        config: &ReceiverEnrollment,
        grant: GrantV1,
        extensions: GrantExtensions,
        deadline: Instant,
    ) -> Result<Self> {
        let GrantExtensions {
            max_file_data_bytes_per_second,
            filters,
            root_existence,
        } = extensions;
        let GrantOperationV1::Copy(copy) = grant.operation;
        if copy.policy.existing == ExistingDestinationPolicyV1::UpdateIfOlder {
            // The comparison depends on a source mtime only the remote
            // coordinator reports, so the receiver cannot enforce it.
            bail!("update-if-older existing-object policy is not enforceable by the receiver");
        }
        if copy.policy.publication == PublicationPolicyV1::InPlace
            && (copy.policy.existing != ExistingDestinationPolicyV1::Replace
                || (root_existence == RootExistenceV4::New
                    && copy.policy.placement == DestinationPlacementV1::ExactPath))
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
        let authority = Self {
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
            file_data_limit,
            receiver_umask,
            deadline,
            control_open: AtomicBool::new(true),
            state: Mutex::new(AuthorityState {
                paths: HashSet::new(),
                receiver_modes: HashMap::new(),
                created: HashSet::new(),
                provisional: HashSet::new(),
                reserved: HashMap::new(),
                reserved_bytes: 0,
                transferred_bytes: 0,
                deletions: 0,
                live_connections: 0,
                tcp_listener_started: false,
            }),
        };
        authority.check_root_existence()?;
        Ok(authority)
    }

    /// Check the signed placement-root precondition once, against the
    /// enrolled root, before any request is served. `New` is then kept true
    /// by `constrain_creation`, which forces no-replace creation of the root.
    fn check_root_existence(&self) -> Result<()> {
        let observed = self.rooted_metadata(&self.destination)?;
        let destination = String::from_utf8_lossy(&self.destination);
        match (self.root_existence, observed) {
            (RootExistenceV4::Any, _) => Ok(()),
            (RootExistenceV4::New, Some(_)) => bail!(
                "signed destination {destination} already exists, but the grant requires a new path"
            ),
            (RootExistenceV4::New, None) => Ok(()),
            (RootExistenceV4::Existing, None) => bail!(
                "signed destination {destination} does not exist, but the grant requires an existing path"
            ),
            (RootExistenceV4::Existing, Some(metadata))
                if self.copy.policy.placement != DestinationPlacementV1::ExactPath
                    && !metadata.is_dir() =>
            {
                bail!(
                    "signed destination {destination} is not a directory, but the grant places names inside it"
                )
            }
            (RootExistenceV4::Existing, Some(_)) => Ok(()),
        }
    }

    pub(crate) fn validate_hello(&self, compressed: bool) -> Result<()> {
        self.check_deadline()?;
        if compressed != self.copy.options.compressed_transport {
            bail!("transport compression does not match the signed grant");
        }
        Ok(())
    }

    pub(crate) fn maximum_connections(&self) -> u16 {
        self.copy.limits.max_connections
    }

    pub(crate) fn control_is_open(&self) -> bool {
        self.control_open.load(Ordering::Acquire) && Instant::now() <= self.deadline
    }

    pub(crate) fn close_control(&self) {
        self.control_open.store(false, Ordering::Release);
    }

    pub(crate) fn acquire_connection(&self) -> Result<()> {
        self.check_deadline()?;
        let mut state = self.state.lock().unwrap();
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

    fn scope_allows(scope: &MutationScopeV1, path: &[u8]) -> bool {
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
    fn reserve_bytes(&self, path: &[u8], partial_id: proto::PartialId, size: u64) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        let key = (path.to_vec(), partial_id);
        // An existing declaration only grows; a new one is registered even
        // at zero length, so an empty file can still be published.
        let previous = state.reserved.get(&key).copied();
        if previous.is_some_and(|previous| size <= previous) {
            return Ok(());
        }
        let total = state
            .reserved_bytes
            .checked_add(size - previous.unwrap_or(0))
            .context("signed reservation byte counter overflow")?;
        if total > self.copy.limits.max_total_bytes {
            bail!("signed grant total-byte limit exceeded by file preparation");
        }
        state.reserved_bytes = total;
        state.reserved.insert(key, size);
        Ok(())
    }

    /// The size this grant declared for a partial, which bounds what may be
    /// written into it and what may be published from it. A partial left by
    /// an earlier grant has no declaration here and cannot be used.
    fn declared_size(&self, path: &[u8], partial_id: proto::PartialId) -> Result<u64> {
        self.state
            .lock()
            .unwrap()
            .reserved
            .get(&(path.to_vec(), partial_id))
            .copied()
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
        partial_id: proto::PartialId,
        inplace: bool,
    ) -> Result<()> {
        let declared = self.declared_size(path, partial_id)?;
        let staged = if inplace {
            path.to_vec()
        } else {
            crate::fsops::partial_path(Path::new(OsStr::from_bytes(path)), &partial_id)?
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
        self.record_path(path)
    }

    fn check_mutation_authority(&self, path: &[u8]) -> Result<()> {
        if self.copy.options.dry_run || self.copy.options.verify_only {
            bail!("signed read-only transfer forbids destination mutations");
        }
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
        if self.path_is_ignored(path, is_dir) {
            bail!("receiver mutation targets a path excluded by the signed filter policy");
        }
        self.record_path(path)
    }

    fn created_by_this_grant(&self, path: &[u8]) -> bool {
        self.state.lock().unwrap().created.contains(path)
    }

    /// Confirm or forget the provisional creations of an executed request.
    /// Only a confirmed creation becomes this grant's own; a failed one is
    /// dropped so the path cannot later be replaced as if it were.
    /// `response` is the executor's answer to the authorized request.
    pub(crate) fn settle(&self, settlement: Settlement, response: &proto::Response) {
        if settlement.0.is_empty() {
            return;
        }
        let failed = |index: usize| match response {
            proto::Response::Err(_) => true,
            proto::Response::Applied(results) => results.get(index).is_some_and(Option::is_some),
            _ => false,
        };
        let mut state = self.state.lock().unwrap();
        for creation in settlement.0 {
            state.provisional.remove(&creation.path);
            if creation.persist && !failed(creation.index) {
                state.created.insert(creation.path);
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
    /// creation, which may reuse an existing directory under `Skip` exactly
    /// as the ordinary engine keeps recursing into it. A root the grant
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
        use proto::TargetCondition::{Absent, Any, Matches, MatchesFingerprint};
        let policy = self.copy.policy.existing;
        let root_must_be_new =
            self.root_existence == RootExistenceV4::New && path == self.destination;
        let label = String::from_utf8_lossy(path);
        if root_must_be_new
            && !directory
            && self.copy.policy.placement != DestinationPlacementV1::ExactPath
        {
            bail!(
                "signed placement puts names inside {label}, so it must be created as a directory"
            );
        }
        if self.created_by_this_grant(path)
            || (policy == ExistingDestinationPolicyV1::Replace && !root_must_be_new)
        {
            return Ok(());
        }
        let observed = self.rooted_metadata(path)?;
        match policy {
            ExistingDestinationPolicyV1::MustExist => {
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
            ExistingDestinationPolicyV1::Skip | ExistingDestinationPolicyV1::Replace => {
                match observed {
                    Some(metadata)
                        if directory
                            && metadata.is_dir()
                            && policy == ExistingDestinationPolicyV1::Skip =>
                    {
                        return Ok(());
                    }
                    Some(_) => {
                        bail!("signed grant retains existing objects: {label} already exists")
                    }
                    None => {}
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
            ExistingDestinationPolicyV1::UpdateIfOlder => {
                bail!("update-if-older existing-object policy is not enforceable by the receiver")
            }
        }
    }

    /// Bind an operation that modifies an existing non-directory object at
    /// `path` (metadata, replacement bases, in-place content) to the signed
    /// existing-object policy. Only `Skip` forbids these, and only for objects
    /// that predate the transfer; directories are kept and may still receive
    /// metadata, as in the ordinary engine.
    fn constrain_update(
        &self,
        path: &[u8],
        is_dir: bool,
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
            ExistingDestinationPolicyV1::Skip if is_dir || own => Ok(()),
            ExistingDestinationPolicyV1::Skip => {
                bail!("signed grant retains existing objects: {label} may not be modified")
            }
            ExistingDestinationPolicyV1::MustExist if own => Ok(()),
            ExistingDestinationPolicyV1::MustExist => {
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
            ExistingDestinationPolicyV1::Replace => Ok(()),
            ExistingDestinationPolicyV1::UpdateIfOlder => {
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
            ExistingDestinationPolicyV1::Skip if self.rooted_metadata(path)?.is_some() => {
                bail!("signed grant retains existing objects: {label} already exists")
            }
            ExistingDestinationPolicyV1::MustExist if self.rooted_metadata(path)?.is_none() => {
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
        let mode = state
            .receiver_modes
            .get(path)
            .copied()
            .and_then(|existing| existing.carry_forward(initial))
            .unwrap_or(initial);
        state.receiver_modes.insert(path.to_vec(), mode);
        Ok(())
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
        if self.copy.policy.deletion == DeletionPolicyV1::Forbid {
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
                return Ok(());
            }
            Op::Unlink { path } => {
                self.charge_deletion(path, false)?;
                self.state.lock().unwrap().receiver_modes.remove(path);
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
        match operation {
            Op::Mkdir {
                path,
                mode,
                condition,
            } => {
                self.constrain_creation(path, condition, true, index, pending)?;
                if !self.copy.options.preserve_permissions {
                    self.remember_receiver_creation(path, true)?;
                    *mode = 0o700;
                }
                Ok(())
            }
            Op::Symlink {
                path, condition, ..
            } => self.constrain_creation(path, condition, false, index, pending),
            Op::Mknod {
                path,
                mode,
                condition,
                ..
            } => {
                self.constrain_creation(path, condition, false, index, pending)?;
                if !self.copy.options.preserve_permissions {
                    self.remember_receiver_creation(path, false)?;
                    #[cfg(target_os = "linux")]
                    let file_type = *mode & libc::S_IFMT;
                    #[cfg(not(target_os = "linux"))]
                    let file_type = *mode & libc::S_IFMT as u32;
                    *mode = file_type | 0o600;
                }
                Ok(())
            }
            Op::SetMeta {
                path,
                meta,
                flags,
                condition,
            } => {
                self.constrain_update(path, is_dir, Some(&mut *condition), pending)?;
                self.constrain_receiver_mode(
                    path,
                    meta,
                    flags,
                    condition,
                    ReceiverModeTarget::AnyExisting,
                )
            }
            Op::SetFileMetaIfSame {
                path,
                meta,
                flags,
                condition,
            } => {
                self.constrain_update(path, false, Some(&mut *condition), pending)?;
                self.constrain_receiver_mode(
                    path,
                    meta,
                    flags,
                    condition,
                    ReceiverModeTarget::RegularFile,
                )
            }
            Op::Remove { .. } | Op::Rmdir { .. } | Op::Unlink { .. } => Ok(()),
        }
    }

    /// Check and rewrite one request against the signed grant. The returned
    /// settlement must be handed back to `settle` with the executor's
    /// response so provisional creations are forgotten when execution fails.
    pub(crate) fn authorize(&self, request: &mut Request, over_ssh: bool) -> Result<Settlement> {
        let mut pending = Vec::new();
        match self.authorize_inner(request, over_ssh, &mut pending) {
            Ok(()) => Ok(Settlement(pending)),
            Err(error) => {
                // Nothing of a refused request executes, including the
                // entries authorized before the refusing one.
                self.forget_provisional(&pending);
                Err(error)
            }
        }
    }

    fn authorize_inner(
        &self,
        request: &mut Request,
        over_ssh: bool,
        pending: &mut Vec<PendingCreation>,
    ) -> Result<()> {
        self.check_deadline()?;
        match request {
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
                    .is_none_or(|key| key.len() != crate::crypto::KEY_LEN)
                    || token.len() != 16
                {
                    bail!("signed transfers require encrypted TCP data connections");
                }
                if (*port_lo, *port_hi)
                    != (self.copy.options.tcp_port_lo, self.copy.options.tcp_port_hi)
                {
                    bail!("TCP listener range does not match the signed grant");
                }
                if congestion_control.is_some() {
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
                follow_root,
                ignore,
                guard,
                ..
            } => {
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
                follow,
                guard,
            } => {
                if *follow {
                    bail!("signed destination stat cannot follow symlinks");
                }
                for path in paths {
                    self.check_observation_path(path)?;
                }
                *guard = Some(self.guard.clone());
            }
            Request::PartialPaths { paths, guard, .. } => {
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
                    self.authorize_op(operation, index, pending)?;
                }
                *guard = Some(self.guard.clone());
            }
            Request::ProbePartial { path, guard, .. }
            | Request::FileHash { path, guard }
            | Request::Canonicalize { path, guard } => {
                self.check_observation_path(path)?;
                *guard = Some(self.guard.clone());
            }
            Request::HashBlocks {
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
                partial_id,
                len,
                guard,
                ..
            } => {
                if self.copy.policy.publication != PublicationPolicyV1::AtomicStaged {
                    bail!("in-place signed receiver forbids staged basis creation");
                }
                if *len > self.copy.limits.max_file_bytes {
                    bail!("signed grant per-file byte limit exceeded");
                }
                self.check_mutation_path(path, false)?;
                self.constrain_update(path, false, None, pending)?;
                self.reserve_bytes(path, *partial_id, *len)?;
                *guard = Some(self.guard.clone());
            }
            Request::FinishBasis {
                path,
                meta,
                flags,
                condition,
                guard,
                ..
            } => {
                self.check_mutation_path(path, false)?;
                self.constrain_update(path, false, Some(&mut *condition), pending)?;
                self.constrain_receiver_mode(
                    path,
                    meta,
                    flags,
                    condition,
                    ReceiverModeTarget::RegularFile,
                )?;
                *guard = Some(self.guard.clone());
            }
            Request::Prepare {
                path,
                size,
                inplace,
                partial_id,
                guard,
                ..
            } => {
                if *inplace != (self.copy.policy.publication == PublicationPolicyV1::InPlace) {
                    bail!("file preparation does not match the signed publication policy");
                }
                if *size > self.copy.limits.max_file_bytes {
                    bail!("signed grant per-file byte limit exceeded");
                }
                self.check_mutation_path(path, false)?;
                self.constrain_prepare(path)?;
                self.reserve_bytes(path, *partial_id, *size)?;
                *guard = Some(self.guard.clone());
            }
            Request::WriteRange {
                path,
                inplace,
                partial_id,
                off,
                data,
                guard,
                ..
            } => {
                if *inplace != (self.copy.policy.publication == PublicationPolicyV1::InPlace) {
                    bail!("file write does not match the signed publication policy");
                }
                let declared = self.declared_size(path, *partial_id)?;
                if off
                    .checked_add(data.len() as u64)
                    .is_none_or(|end| end > declared)
                {
                    bail!("file write extends past the size declared for it");
                }
                self.charge_bytes(path, *off, data.len())?;
                *guard = Some(self.guard.clone());
            }
            Request::Finalize {
                path,
                inplace,
                partial_id,
                meta,
                flags,
                condition,
                guard,
                ..
            } => {
                if *inplace != (self.copy.policy.publication == PublicationPolicyV1::InPlace) {
                    bail!("file finalization does not match the signed publication policy");
                }
                self.check_mutation_path(path, false)?;
                self.check_published_length(path, *partial_id, *inplace)?;
                self.constrain_creation(path, condition, false, 0, pending)?;
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
                if self.copy.policy.publication != PublicationPolicyV1::AtomicStaged {
                    bail!("in-place signed receiver forbids staged small-file publication");
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
                    self.charge_bytes(&put.path, 0, put.data.len())?;
                    self.constrain_creation(&put.path, &mut put.condition, false, index, pending)?;
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
            Request::CopyLocal { .. } | Request::ReadRange { .. } | Request::ReadSmallBatch(_) => {
                bail!("request is not valid on a command-restricted destination")
            }
            Request::CheckOperatorDirectory { .. }
            | Request::CreateOperatorDirectory { .. }
            | Request::AnchorDestination { .. } => {
                bail!("destination-anchor management is not valid on a root-confined receiver")
            }
            Request::NativeRemove { .. } => {
                bail!("native removal is not valid on a command-restricted destination")
            }
            Request::Hello { .. } => bail!("unexpected second receiver handshake"),
            Request::TransportStats | Request::Shutdown => {}
        }
        Ok(())
    }
}

/// Creations an authorized request recorded provisionally, keyed by the
/// operation or small-put index the executor reports on.
#[derive(Debug, Default)]
pub(crate) struct Settlement(Vec<PendingCreation>);

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
            if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
                bail!(
                    "{} is not a private owner-controlled directory",
                    path.display()
                );
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
    delegation::validate_trusted_directory_path(path)
}

fn ensure_private_chain(home: &Path, components: &[&str]) -> Result<PathBuf> {
    delegation::validate_trusted_directory_path(home)
        .with_context(|| format!("validate account home {}", home.display()))?;
    let mut path = home.to_path_buf();
    for component in components {
        path.push(component);
        ensure_directory(&path, 0o700)?;
    }
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
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & if private { 0o077 } else { 0o022 } != 0
    {
        bail!("private state file has unsafe type, owner, or permissions");
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

fn generate_transport_key(id: EnrollmentId) -> Result<PrivateKey> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).context("generate restricted transport key")?;
    let keypair = Ed25519Keypair::from_seed(&seed);
    seed.fill(0);
    PrivateKey::new(keypair.into(), format!("syq-enrollment:{id}"))
        .context("construct restricted transport key")
}

/// The receiver's own signing key for receipts. It lives only on hostB, in
/// the enrollment's state directory, and is rotated by every install.
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
    if let Some(existing) = load_receipt_key(state)? {
        return Ok(existing);
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

/// The receipt signing key an install left in the state directory, if any.
fn load_receipt_key(state: &Path) -> Result<Option<PrivateKey>> {
    let path = state.join(RECEIPT_KEY_FILE);
    if !path.exists() {
        return Ok(None);
    }
    let encoded = delegation::read_secure_regular(&path, "receipt signing key", 128 * 1024)?;
    PrivateKey::from_openssh(&encoded)
        .context("parse receipt signing key")
        .map(Some)
}

fn signer_name(id: EnrollmentId) -> String {
    format!("syq-enrollment-{id}")
}

fn normalize_absolute(path: &str, home: &Path) -> Result<PathBuf> {
    let raw = if path == "~" {
        home.to_path_buf()
    } else if let Some(rest) = path.strip_prefix("~/") {
        home.join(rest)
    } else if path.starts_with('/') {
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
    let destination = normalize_absolute(&request.requested_destination, &home)?;
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
    let root = crate::rooted::Root::open(&canonical_root)?;
    let root_identity = root.identity();
    let transport = TransportPublicKey::parse(&request.public_key)?;
    let signer = signer_name(request.id);
    let public_words: Vec<&str> = request.public_key.split_ascii_whitespace().collect();
    if public_words.len() < 2 {
        bail!("transport public key is malformed");
    }
    let receiver_path = std::env::current_exe().context("resolve restricted receiver path")?;
    delegation::validate_secure_executable(&receiver_path, "restricted receiver")?;
    let entry = AuthorizedKeyEntry::new(request.id, &receiver_path, &transport)?;
    let ssh = ensure_private_chain(&home, &[".ssh"])?;
    let directory = open_directory(&ssh)?;
    lock_directory(&directory)?;
    let original =
        read_leaf(&directory, "authorized_keys", MAX_AUTHORIZED_KEYS, false)?.unwrap_or_default();
    let normalized = normalize_managed_authorized_keys(&original, &entry.marker());
    let (updated, change) = enrollment::install_authorized_key(&normalized, &entry)?;

    // Publish the forced authorization last. A failed preflight therefore
    // cannot leave a usable key, and a later state-write failure leaves only
    // inert private state that an idempotent retry can complete.
    let (state, _allowed_signers, _replay) = install_state_paths(&home, request.id)?;
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
        ssh_keygen: resolve_ssh_keygen()?
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
    if account != request.target_login {
        bail!("revocation target login does not match the remote account");
    }
    let state = home
        .join(".local/share/syq/restricted")
        .join(request.id.to_string());
    let (receiver_path, remove_state) = match fs::symlink_metadata(&state) {
        Ok(_) => {
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
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (
            std::env::current_exe().context("resolve restricted receiver path")?,
            None,
        ),
        Err(error) => return Err(error).context("inspect restricted receiver state"),
    };
    let transport = TransportPublicKey::parse(&request.public_key)?;
    let entry = AuthorizedKeyEntry::new(request.id, &receiver_path, &transport)?;
    let ssh = ensure_private_chain(&home, &[".ssh"])?;
    let directory = open_directory(&ssh)?;
    lock_directory(&directory)?;
    let original =
        read_leaf(&directory, "authorized_keys", MAX_AUTHORIZED_KEYS, false)?.unwrap_or_default();
    let normalized = normalize_managed_authorized_keys(&original, &entry.marker());
    let (updated, _) = enrollment::revoke_authorized_key(&normalized, &entry)?;
    atomic_write_locked(&directory, "authorized_keys", &updated, 0o600, false)?;
    drop(directory);
    if let Some(state) = remove_state {
        delegation::validate_private_directory_path(&state)?;
        fs::remove_dir_all(&state)
            .with_context(|| format!("remove revoked receiver state {}", state.display()))?;
    }
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
        .context("encode restricted transport private key")?;
    atomic_write(directory, "transport", private.as_bytes(), 0o600)?;
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
        let Ok(encoded) = delegation::read_secure_regular(
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
        let Ok(encoded) = delegation::read_secure_regular(
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
    let encoded = delegation::read_secure_regular(
        &directory.join("transport"),
        "restricted transport private key",
        128 * 1024,
    )?;
    PrivateKey::from_openssh(&encoded).context("parse restricted transport private key")
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
    let mut child = command.spawn().context("start restricted enrollment SSH")?;
    let mut stdin = child
        .stdin
        .take()
        .context("enrollment SSH stdin unavailable")?;
    stdin.write_all(input)?;
    drop(stdin);
    let output = child.wait_with_output()?;
    if !output.status.success() {
        let diagnostic = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        bail!(
            "restricted enrollment SSH failed ({}): {}",
            output.status,
            if diagnostic.is_empty() {
                "no diagnostic"
            } else {
                &diagnostic
            }
        );
    }
    Ok(output.stdout)
}

fn install_over_route(
    target: &SshEndpoint,
    route: EnrollmentRoute<'_>,
    request: &InstallRequest,
) -> Result<InstallResponse> {
    let executable = std::env::current_exe().context("resolve local syq executable")?;
    let mut binary = File::open(&executable)
        .with_context(|| format!("open local syq executable {}", executable.display()))?;
    let metadata = binary.metadata()?;
    if !metadata.is_file() || metadata.mode() & 0o022 != 0 {
        bail!("local syq executable is not a trusted regular file");
    }
    let mut bytes = Vec::new();
    binary.read_to_end(&mut bytes)?;
    let upload = "set -eu; d=\"$HOME/.local/libexec\"; umask 077; mkdir -p -- \"$d\"; t=\"$d/.syq-receiver.$$\"; trap 'rm -f -- \"$t\"' EXIT HUP INT TERM; cat >\"$t\"; chmod 700 \"$t\"; mv -f -- \"$t\" \"$d/syq-receiver\"; trap - EXIT HUP INT TERM";
    run_ssh(target, route.clone(), upload, &bytes)?;
    let expected_id = request.id;
    let expected_login = request.target_login.clone();
    let request = serde_json::to_vec(request)?;
    let output = run_ssh(
        target,
        route,
        "exec \"$HOME/.local/libexec/syq-receiver\" --restricted-install",
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
) -> Result<(LocalEnrollment, PathBuf, String)> {
    let base = local_state_base()?;
    let base_lock = open_directory(&base)?;
    lock_directory(&base_lock)?;

    let mut active = None;
    for (metadata, directory) in load_local_enrollments()? {
        if metadata.host == host && metadata.port == port && metadata.target_login == login {
            if let Some(canonical_destination) = destination_for(&metadata, requested_destination)?
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
            let private_key = generate_transport_key(id)?;
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
        (Err(direct_error), Some(jump)) => {
            install_over_route(&target, EnrollmentRoute::ProxyJump { jump }, &request)
                .with_context(|| {
                    format!(
                "enrollment {} {retry_state}; direct enrollment also failed: {direct_error:#}",
                pending.id,
            )
                })?
        }
        (Err(error), None) => {
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
        receipt_public_key: Some(response.receipt_public_key),
    };
    complete_local_enrollment(&directory, &metadata)?;
    Ok((metadata, directory, response.canonical_destination))
}

fn destination_for(metadata: &LocalEnrollment, requested: &str) -> Result<Option<String>> {
    let normalized = normalize_absolute(requested, Path::new(&metadata.remote_home))?;
    if requested_parent(&normalized) != Path::new(&metadata.requested_parent) {
        return Ok(None);
    }
    let leaf = normalized
        .file_name()
        .context("restricted destination / is not supported")?;
    Ok(Some(
        Path::new(&metadata.canonical_root)
            .join(leaf)
            .to_str()
            .context("canonical restricted destination is not UTF-8")?
            .to_owned(),
    ))
}

fn now() -> Result<i64> {
    i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
        .context("current time exceeds signed grant range")
}

fn root_existence_for(existence: Existence) -> RootExistenceV4 {
    match existence {
        Existence::Any => RootExistenceV4::Any,
        Existence::New => RootExistenceV4::New,
        Existence::Existing => RootExistenceV4::Existing,
    }
}

fn validate_restricted_args(args: &Args) -> Result<()> {
    if args.no_tcp || args.tcp_plain {
        bail!("command-restricted transfers require encrypted TCP data connections");
    }
    if args.tcp_congestion.is_some() {
        bail!("--tcp-congestion is not yet represented in the signed receiver grant");
    }
    if args.update {
        bail!(
            "--update compares against source modification times that only hostA reports, so the command-restricted receiver cannot enforce it"
        );
    }
    if args.inplace
        && (args.ignore_existing
            || args.existing
            || (args.target_existence == Existence::New && args.placement == Placement::As))
    {
        bail!(
            "--inplace cannot be combined with --ignore-existing, --existing, or --as-new on the command-restricted path: in-place writes open the final pathname directly, so the receiver can neither make them no-replace nor pin them to an observed object"
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
    if let Some(runtime) = args.max_runtime_secs {
        if runtime > DEFAULT_RUNTIME_SECONDS {
            bail!(
                "--max-runtime exceeds the {}-hour signed grant ceiling",
                DEFAULT_RUNTIME_SECONDS / 3600
            );
        }
    }
    if args
        .max_entries
        .is_some_and(|entries| entries == 0 || entries > delegation::MAX_ENTRIES)
    {
        bail!(
            "--max-entries must be between 1 and {}",
            delegation::MAX_ENTRIES
        );
    }
    if args
        .max_total_bytes
        .is_some_and(|bytes| bytes == 0 || bytes > delegation::MAX_COPY_BYTES)
    {
        bail!("--max-total-bytes must be at least 1 byte");
    }
    if let Some(maximum) = args.max_size.as_deref() {
        if crate::cli::parse_size(maximum)? == 0 {
            bail!("--max-size must be at least 1 byte on the command-restricted path");
        }
    }
    if !args.files_from_lines.is_empty()
        || args.files_from.is_some()
        || args.native_mapping.is_some()
        || args.min_size.is_some()
    {
        bail!(
            "--files-from, --mapping, and --min-size are not yet independently enforceable by the command-restricted receiver"
        );
    }
    if args.syq_path.is_some() || args.no_bootstrap {
        bail!(
            "--syq-path and --no-bootstrap cannot select the pre-enrolled command-restricted receiver"
        );
    }
    if args.reuse_connection {
        bail!(
            "--reuse-connection is not available with the command-restricted receiver: its host-bound authentication is verified per fresh connection"
        );
    }
    if !args.dry_run && !args.verify_only && args.delete && args.max_size.is_some() {
        bail!(
            "--max-size with deletion is not yet independently enforceable by the command-restricted receiver"
        );
    }
    if args.connections_opt.is_some() && args.connections > crate::tune::MAX {
        bail!(
            "command-restricted transfers support at most {} connections",
            crate::tune::MAX
        );
    }
    crate::transfer::parse_ports(&args.tcp_ports)?;
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
    destination: &str,
) -> Result<GrantV1> {
    validate_restricted_args(args)?;
    let issued_at = now()?;
    let read_only = args.dry_run || args.verify_only;
    // `--max-delete 0` means nothing may be deleted, which the grant states
    // directly as a forbidding policy rather than a zero budget.
    let deletion = if !read_only && args.delete && args.max_delete != Some(0) {
        DeletionPolicyV1::DeleteDestinationOnly
    } else {
        DeletionPolicyV1::Forbid
    };
    let max_entries = args.max_entries.unwrap_or(DEFAULT_MAX_ENTRIES);
    let max_total_bytes = args.max_total_bytes.unwrap_or(DEFAULT_MAX_BYTES);
    let max_file_bytes = args
        .max_size
        .as_deref()
        .map(crate::cli::parse_size)
        .transpose()?
        .unwrap_or(DEFAULT_MAX_BYTES)
        .min(max_total_bytes);
    let max_deletions = match deletion {
        DeletionPolicyV1::Forbid => 0,
        DeletionPolicyV1::DeleteDestinationOnly => args
            .max_delete
            .context("deletion through the command-restricted receiver needs --max-delete")?
            .min(max_entries),
    };
    let (not_after, max_runtime_seconds) = match args.max_runtime_secs {
        None => (
            issued_at
                .checked_add(GRANT_VALIDITY_SECONDS - CLOCK_SKEW_SECONDS)
                .context("signed grant expiration overflow")?,
            DEFAULT_RUNTIME_SECONDS,
        ),
        Some(runtime) => (
            issued_at
                .checked_add(i64::from(runtime))
                .context("signed grant expiration overflow")?,
            runtime,
        ),
    };
    let copies_contents = sources.iter().any(Location::copies_contents);
    let placement = match args.placement {
        Placement::As => DestinationPlacementV1::ExactPath,
        Placement::Into | Placement::Rsync if copies_contents => {
            DestinationPlacementV1::DirectoryContents
        }
        Placement::Into | Placement::Rsync => DestinationPlacementV1::DirectoryAsChild,
    };
    let destination_bytes = destination.as_bytes().to_vec();
    let mut mutation_scopes = match placement {
        DestinationPlacementV1::ExactPath | DestinationPlacementV1::DirectoryContents => {
            vec![MutationScopeV1 {
                path: destination_bytes.clone(),
                descendants: args.recursive,
            }]
        }
        DestinationPlacementV1::DirectoryAsChild => {
            let mut scopes = vec![MutationScopeV1 {
                path: destination_bytes.clone(),
                descendants: false,
            }];
            for source in sources {
                let basename = source.basename();
                if basename.is_empty() {
                    bail!("named source has no destination basename for signed scope");
                }
                scopes.push(MutationScopeV1 {
                    path: crate::fsops::join(&destination_bytes, &basename),
                    descendants: args.recursive,
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
    let existing = if args.ignore_existing {
        ExistingDestinationPolicyV1::Skip
    } else if args.update {
        ExistingDestinationPolicyV1::UpdateIfOlder
    } else if args.existing {
        ExistingDestinationPolicyV1::MustExist
    } else {
        ExistingDestinationPolicyV1::Replace
    };
    let (tcp_port_lo, tcp_port_hi) = crate::transfer::parse_ports(&args.tcp_ports)?;
    let grant = GrantV1 {
        enrollment_id: id,
        target_login: login.to_owned(),
        signer: signer_name(id),
        request_id: RequestId::fresh(issued_at)?,
        issued_at,
        not_before: issued_at.saturating_sub(CLOCK_SKEW_SECONDS),
        not_after,
        operation: GrantOperationV1::Copy(CopyOperationV1 {
            destination: destination_bytes,
            mutation_scopes,
            policy: CopyPolicyV1 {
                placement,
                existing,
                deletion,
                publication: if args.inplace {
                    PublicationPolicyV1::InPlace
                } else {
                    PublicationPolicyV1::AtomicStaged
                },
            },
            options: CopyOptionsV1 {
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
            limits: CopyLimitsV1 {
                max_entries,
                max_total_bytes,
                max_file_bytes,
                hash_block_bytes: crate::cli::parse_size(&args.block_size)?
                    .clamp(proto::MIN_HASH_BLOCK_BYTES, proto::MAX_HASH_BLOCK_BYTES),
                max_connections: u16::try_from(if args.connections_opt.is_some() {
                    args.connections
                } else {
                    crate::tune::MAX
                })
                .context("connection maximum exceeds grant representation")?,
                max_deletions,
                max_runtime_seconds,
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
    let requested = std::str::from_utf8(&destination.path)
        .context("restricted destination path is not UTF-8")?;
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
                    "read-only operations will not install a receiver enrollment; pre-enroll this destination with `syq enroll` or explicitly use --agent-broker-only"
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
                requested,
                Some(&jump),
                false,
            )?
        }
    };
    let private_key = load_private_key(&directory)?;
    let grant = delegation::sign_grant(
        grant_for(
            args,
            sources,
            metadata.id,
            destination_login,
            &canonical_destination,
        )?,
        args.bwlimit_bytes,
        FilterPolicyV3 {
            ignore: args.ignore_lines.clone(),
            destination_roots: filter_destination_roots(
                args,
                sources,
                canonical_destination.as_bytes(),
            )?,
            delete_excluded: args.delete_excluded,
        },
        root_existence_for(args.target_existence),
        &private_key,
    )?;
    Ok(PreparedTransfer {
        private_key,
        canonical_destination,
        grant: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(grant),
        enrollment_id: metadata.id,
    })
}

pub(crate) fn receiver_config(id: EnrollmentId) -> Result<(ReceiverEnrollment, PathBuf, PathBuf)> {
    let (_, home) = current_account()?;
    let state = home
        .join(".local/share/syq/restricted")
        .join(id.to_string());
    let encoded = delegation::read_secure_regular(
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
    let envelope = decode_receiver_command(&original)?;
    let (config, allowed_signers, replay_path) = receiver_config(enrollment)?;
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
    let verified = delegation::verify_and_claim(&envelope, &context, &policy, &replay)?;
    let (grant, extensions, deadline) = verified.into_parts();
    let authority = std::sync::Arc::new(RestrictedAuthority::new(
        &config, grant, extensions, deadline,
    )?);
    crate::server::run_restricted(authority)
}

fn decode_receiver_command(original: &str) -> Result<Vec<u8>> {
    if original.len() > 128 * 1024 {
        bail!("restricted receiver command exceeds size limit");
    }
    let words = shell_words::split(original).context("parse restricted receiver command")?;
    if words.len() != 3 || words[0] != "syq" || words[1] != "--server" {
        bail!("restricted credential accepts only a syq server request with one signed grant");
    }
    let encoded = words[2]
        .strip_prefix("--restricted-grant=")
        .context("restricted receiver command is missing its signed grant")?;
    let envelope = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .context("decode restricted receiver grant")?;
    Ok(envelope)
}

fn management_via(arguments: &[OsString]) -> Result<Option<SshEndpoint>> {
    if arguments.is_empty() {
        return Ok(None);
    }
    if arguments.len() != 2 || arguments[0] != "--via" {
        bail!("expected optional --via [USER@]HOST");
    }
    Ok(Some(SshEndpoint::parse(
        arguments[1]
            .to_str()
            .context("--via endpoint is not UTF-8")?,
    )?))
}

pub(crate) fn dispatch_management(argv: &[OsString]) -> Option<Result<i32>> {
    let command = argv.get(1)?.to_str()?;
    match command {
        "enrollments" => {
            Some((|| {
                if argv.get(2).is_some_and(|argument| argument == "--help") {
                    println!("Usage: syq enrollments\n\nList local command-restricted receiver enrollments.");
                    return Ok(0);
                }
                if argv.len() != 2 {
                    bail!("usage: syq enrollments");
                }
                let active = load_local_enrollments()?;
                let active_ids = active
                    .iter()
                    .map(|(metadata, _)| metadata.id)
                    .collect::<HashSet<_>>();
                for (metadata, _) in active {
                    let target = endpoint(&metadata.target_login, &metadata.host, metadata.port)?;
                    println!(
                        "{}\tactive\t{}\t{}\t{}",
                        metadata.id,
                        target.label(),
                        metadata.canonical_root,
                        if metadata.receipt_public_key.is_some() {
                            "receipt-key"
                        } else {
                            "no-receipt-key"
                        }
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
            })())
        }
        "enroll" => Some((|| {
            if argv.get(2).is_some_and(|argument| argument == "--help") {
                println!(
                    "Usage: syq enroll [USER@]HOST:DESTINATION [--via [USER@]HOST]\n\nPre-enroll a command-restricted receiver for DESTINATION's existing parent."
                );
                return Ok(0);
            }
            if argv.len() < 3 {
                bail!("usage: syq enroll [USER@]HOST:DESTINATION [--via [USER@]HOST]");
            }
            let target = argv[2].to_str().context("enrollment target is not UTF-8")?;
            let location = Location::parse(target)?;
            let host = location
                .host
                .as_deref()
                .context("enrollment target must be remote")?;
            let requested = std::str::from_utf8(&location.path)
                .context("enrollment destination is not UTF-8")?;
            let via = management_via(&argv[3..])?;
            let policy = crate::agent_broker::resolve_host_policy(
                "ssh",
                location.user.as_deref(),
                host,
                true,
            )?;
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
                destination
            );
            Ok(0)
        })()),
        "revoke" => Some((|| {
            if argv.get(2).is_some_and(|argument| argument == "--help") {
                println!(
                    "Usage: syq revoke ENROLLMENT-ID [--via [USER@]HOST]\n\nRemove the forced key and per-enrollment state from both machines."
                );
                return Ok(0);
            }
            if argv.len() < 3 {
                bail!("usage: syq revoke ENROLLMENT-ID [--via [USER@]HOST]");
            }
            let id = EnrollmentId::parse(argv[2].to_str().context("enrollment ID is not UTF-8")?)?;
            let via = management_via(&argv[3..])?;
            let active = load_local_enrollments()?
                .into_iter()
                .find(|(metadata, _)| metadata.id == id);
            let (target_login, host, port, remote_command, directory) = match active {
                Some((metadata, directory)) => {
                    let command = enrollment::EnrollmentRemoteCommand::new(
                        Path::new(&metadata.receiver_path),
                        &["--restricted-revoke".into()],
                    )?;
                    (
                        metadata.target_login,
                        metadata.host,
                        metadata.port,
                        command.as_str().to_owned(),
                        directory,
                    )
                }
                None => {
                    let (pending, directory) = load_pending_enrollments()?
                        .into_iter()
                        .find(|(pending, _)| pending.id == id)
                        .context("no local enrollment has that ID")?;
                    (
                        pending.target_login,
                        pending.host,
                        pending.port,
                        "exec \"$HOME/.local/libexec/syq-receiver\" --restricted-revoke".to_owned(),
                        directory,
                    )
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
            let direct = run_ssh(&target, EnrollmentRoute::Direct, &remote_command, &encoded);
            match (direct, via.as_ref()) {
                (Ok(_), _) => {}
                (Err(direct_error), Some(via)) => {
                    run_ssh(
                        &target,
                        EnrollmentRoute::ProxyJump { jump: via },
                        &remote_command,
                        &encoded,
                    )
                    .with_context(|| format!("direct revocation also failed: {direct_error:#}"))?;
                }
                (Err(error), None) => return Err(error),
            }
            delegation::validate_private_directory_path(&directory)?;
            fs::remove_dir_all(&directory)
                .with_context(|| format!("remove local enrollment {}", directory.display()))?;
            println!("revoked {id} from {}", target.label());
            Ok(0)
        })()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn test_authority(
        root: &Path,
        deletion: DeletionPolicyV1,
        maximum_bytes: u64,
    ) -> RestrictedAuthority {
        test_authority_with_rate(root, deletion, maximum_bytes, 0)
    }

    fn test_authority_with_rate(
        root: &Path,
        deletion: DeletionPolicyV1,
        maximum_bytes: u64,
        max_file_data_bytes_per_second: u64,
    ) -> RestrictedAuthority {
        test_authority_with_policy(
            root,
            deletion,
            maximum_bytes,
            max_file_data_bytes_per_second,
            FilterPolicyV3::default(),
            PublicationPolicyV1::AtomicStaged,
        )
    }

    fn test_authority_with_policy(
        root: &Path,
        deletion: DeletionPolicyV1,
        maximum_bytes: u64,
        max_file_data_bytes_per_second: u64,
        filters: FilterPolicyV3,
        publication: PublicationPolicyV1,
    ) -> RestrictedAuthority {
        test_authority_with_existence(
            root,
            deletion,
            maximum_bytes,
            max_file_data_bytes_per_second,
            filters,
            publication,
            ExistingDestinationPolicyV1::Replace,
            DestinationPlacementV1::ExactPath,
            RootExistenceV4::Any,
        )
        .unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn test_authority_with_existence(
        root: &Path,
        deletion: DeletionPolicyV1,
        maximum_bytes: u64,
        max_file_data_bytes_per_second: u64,
        mut filters: FilterPolicyV3,
        publication: PublicationPolicyV1,
        existing: ExistingDestinationPolicyV1,
        placement: DestinationPlacementV1,
        root_existence: RootExistenceV4,
    ) -> Result<RestrictedAuthority> {
        let opened = Root::open(root).unwrap();
        let identity = opened.identity();
        let id = EnrollmentId::random();
        let config = ReceiverEnrollment {
            version: CONFIG_VERSION,
            id,
            target_login: "receiver".into(),
            signer: signer_name(id),
            root: root.to_str().unwrap().into(),
            root_dev: identity.dev,
            root_ino: identity.ino,
            ssh_keygen: "/usr/bin/ssh-keygen".into(),
            receiver_path: "/usr/bin/syq".into(),
        };
        let destination = root.join("target");
        if !filters.ignore.is_empty() && filters.destination_roots.is_empty() {
            filters.destination_roots = vec![destination.as_os_str().as_bytes().to_vec()];
        }
        let grant = GrantV1 {
            enrollment_id: id,
            target_login: "receiver".into(),
            signer: signer_name(id),
            request_id: RequestId::fresh(1_900_000_000).unwrap(),
            issued_at: 1,
            not_before: 1,
            not_after: 100,
            operation: GrantOperationV1::Copy(CopyOperationV1 {
                destination: destination.as_os_str().as_bytes().to_vec(),
                mutation_scopes: vec![MutationScopeV1 {
                    path: destination.as_os_str().as_bytes().to_vec(),
                    descendants: true,
                }],
                policy: CopyPolicyV1 {
                    placement,
                    existing,
                    deletion,
                    publication,
                },
                options: CopyOptionsV1 {
                    recursive: true,
                    preserve_symlinks: true,
                    preserve_permissions: false,
                    receiver_managed_modes: true,
                    preserve_times: false,
                    preserve_owner: false,
                    preserve_group: false,
                    preserve_devices: false,
                    compare_existing_by_content: false,
                    dry_run: false,
                    verify_only: false,
                    compressed_transport: true,
                    tcp_port_lo: 47_600,
                    tcp_port_hi: 47_699,
                },
                limits: CopyLimitsV1 {
                    max_entries: 8,
                    max_total_bytes: maximum_bytes,
                    max_file_bytes: maximum_bytes,
                    hash_block_bytes: 4 << 20,
                    max_connections: 2,
                    max_deletions: u64::from(deletion != DeletionPolicyV1::Forbid) * 2,
                    max_runtime_seconds: 60,
                },
            }),
        };
        RestrictedAuthority::new(
            &config,
            grant,
            GrantExtensions {
                max_file_data_bytes_per_second,
                filters,
                root_existence,
            },
            Instant::now() + std::time::Duration::from_secs(60),
        )
    }

    #[test]
    fn managed_crlf_and_commented_tombstones_normalize_without_touching_other_content() {
        let marker = "syq-enrollment:00112233445566778899aabbccddeeff";
        let original = format!(
            "# unrelated\r\n# restrict ssh-ed25519 AAAA {marker}\r\nssh-ed25519 BBBB user\r\n"
        );
        assert_eq!(
            normalize_managed_authorized_keys(original.as_bytes(), marker),
            b"# unrelated\nssh-ed25519 BBBB user\n"
        );
    }

    #[test]
    fn relative_destination_resolution_rejects_parent_components() {
        assert_eq!(
            normalize_absolute("archive/file", Path::new("/home/backup")).unwrap(),
            Path::new("/home/backup/archive/file")
        );
        assert!(normalize_absolute("archive/../escape", Path::new("/home/backup")).is_err());
    }

    #[test]
    fn receiver_command_accepts_only_one_encoded_signed_grant() {
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"signed grant");
        assert_eq!(
            decode_receiver_command(&format!("syq --server --restricted-grant={encoded}")).unwrap(),
            b"signed grant"
        );
        assert!(decode_receiver_command(&format!(
            "syq --server --restricted-grant={encoded} extra"
        ))
        .is_err());
        assert!(decode_receiver_command(&format!(
            "env X=1 syq --server --restricted-grant={encoded}"
        ))
        .is_err());
    }

    #[test]
    fn receipt_keys_are_distinct_per_enrollment_and_older_metadata_still_loads() {
        let id = EnrollmentId::random();
        let key = generate_receipt_key(id).unwrap();
        let public = key.public_key().to_openssh().unwrap();
        assert!(public.starts_with("ssh-ed25519 "));
        assert!(public.ends_with(&format!("syq-receipt:{id}")));
        let again = generate_receipt_key(id).unwrap();
        assert_ne!(again.public_key().to_openssh().unwrap(), public);
        ssh_key::PublicKey::from_openssh(&public).unwrap();

        // An install keeps the key it finds, so a refresh or a retried
        // install reports the same public key the local side already has.
        let (_, home) = current_account().unwrap();
        let temporary = tempfile::tempdir_in(home).unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let state = temporary.path().join("state");
        ensure_directory(&state, 0o700).unwrap();
        let first = ensure_receipt_key(&state, id).unwrap();
        let second = ensure_receipt_key(&state, id).unwrap();
        assert_eq!(
            first.public_key().to_openssh().unwrap(),
            second.public_key().to_openssh().unwrap()
        );
        assert!(state.join(RECEIPT_KEY_FILE).is_file());

        // Metadata written before receipt keys existed has no key and is
        // listed as needing a refresh rather than failing to load.
        let current = LocalEnrollment {
            version: CONFIG_VERSION,
            id,
            host: "vault".into(),
            port: None,
            target_login: "backup".into(),
            remote_home: "/home/backup".into(),
            requested_parent: "/archive".into(),
            canonical_root: "/archive".into(),
            receiver_path: "/home/backup/.local/libexec/syq-receiver".into(),
            receipt_public_key: Some(public),
        };
        let mut older = serde_json::to_value(&current).unwrap();
        older.as_object_mut().unwrap().remove("receipt_public_key");
        let metadata: LocalEnrollment = serde_json::from_value(older).unwrap();
        assert!(metadata.receipt_public_key.is_none());
    }

    #[test]
    fn pending_enrollment_keeps_its_key_until_active_metadata_is_durable() {
        let (_, home) = current_account().unwrap();
        let temporary = tempfile::tempdir_in(home).unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let id = EnrollmentId::random();
        let directory = temporary.path().join(id.to_string());
        ensure_directory(&directory, 0o700).unwrap();
        let pending = PendingEnrollment {
            version: CONFIG_VERSION,
            id,
            host: "host-b".into(),
            port: None,
            target_login: "backup".into(),
            requested_destination: "/archive/item".into(),
        };
        let private_key = generate_transport_key(id).unwrap();
        store_pending_files(&directory, &pending, &private_key).unwrap();
        assert!(directory.join("pending.json").is_file());
        assert_eq!(
            fs::metadata(directory.join("transport")).unwrap().mode() & 0o777,
            0o600
        );
        assert_eq!(
            load_private_key(&directory)
                .unwrap()
                .public_key()
                .to_openssh()
                .unwrap(),
            private_key.public_key().to_openssh().unwrap()
        );

        let metadata = LocalEnrollment {
            version: CONFIG_VERSION,
            id,
            host: pending.host,
            port: pending.port,
            target_login: pending.target_login,
            remote_home: "/home/backup".into(),
            requested_parent: "/archive".into(),
            canonical_root: "/archive".into(),
            receiver_path: "/home/backup/.local/libexec/syq-receiver".into(),
            receipt_public_key: None,
        };
        complete_local_enrollment(&directory, &metadata).unwrap();
        assert!(!directory.join("pending.json").exists());
        assert!(directory.join("metadata.json").is_file());
        assert!(directory.join("transport").is_file());
    }

    #[test]
    fn authority_overwrites_client_guards_and_rejects_scope_and_option_escalation() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("root");
        fs::create_dir(&root).unwrap();
        let authority = test_authority(&root, DeletionPolicyV1::Forbid, 4);
        let target = root.join("target").as_os_str().as_bytes().to_vec();
        let outside = temporary
            .path()
            .join("outside")
            .as_os_str()
            .as_bytes()
            .to_vec();

        let mut stat = Request::StatMany {
            paths: vec![target.clone()],
            follow: false,
            guard: Some(ContainerGuard {
                root: outside.clone(),
                dev: 1,
                ino: 2,
            }),
        };
        authority.authorize(&mut stat, false).unwrap();
        let Request::StatMany {
            guard: Some(guard), ..
        } = stat
        else {
            panic!("authority did not install a guard")
        };
        assert_eq!(guard.root, root.as_os_str().as_bytes());

        let mut plan = Request::PlanBatch {
            partial_paths: vec![target.clone()],
            partial_id: [3; 16],
            directories: vec![target.clone()],
            others: vec![target.clone()],
            guard: None,
        };
        authority.authorize(&mut plan, false).unwrap();
        let Request::PlanBatch {
            guard: Some(guard), ..
        } = plan
        else {
            panic!("authority did not guard the combined planning request")
        };
        assert_eq!(guard.root, root.as_os_str().as_bytes());

        let mut outside_stat = Request::StatMany {
            paths: vec![outside.clone()],
            follow: false,
            guard: None,
        };
        assert!(authority.authorize(&mut outside_stat, false).is_err());

        let mut mkdir = Request::Apply {
            ops: vec![Op::Mkdir {
                path: target.clone(),
                mode: 0o777,
                condition: proto::TargetCondition::Absent,
            }],
            guard: None,
        };
        authority.authorize(&mut mkdir, false).unwrap();
        let Request::Apply { ops, .. } = mkdir else {
            unreachable!()
        };
        assert!(matches!(ops[0], Op::Mkdir { mode: 0o700, .. }));

        let mut small = Request::PutSmallBatch(vec![proto::SmallPut {
            path: target.clone(),
            partial_id: [1; 16],
            data: vec![0; 4],
            hash: [0; 32],
            meta: proto::Meta {
                mode: 0o644,
                uid: 0,
                gid: 0,
                mtime: 0,
                mtime_nsec: 0,
            },
            flags: proto::flags::RECEIVER_MODE,
            condition: proto::TargetCondition::Any,
            guard: Some(ContainerGuard {
                root: outside,
                dev: 1,
                ino: 2,
            }),
        }]);
        authority.authorize(&mut small, false).unwrap();
        let Request::PutSmallBatch(puts) = small else {
            unreachable!()
        };
        assert_eq!(
            puts[0].guard.as_ref().unwrap().root,
            root.as_os_str().as_bytes()
        );

        let mut write = Request::WriteRange {
            path: target,
            inplace: false,
            partial_id: [0; 16],
            attempt: 0,
            off: 0,
            hash: [0; 32],
            data: vec![0; 5],
            guard: None,
        };
        assert!(authority.authorize(&mut write, false).is_err());
    }

    #[test]
    fn exact_destination_observation_scope_excludes_its_parent() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("root");
        fs::create_dir(&root).unwrap();
        let authority = test_authority(&root, DeletionPolicyV1::Forbid, 4);
        let destination = root.join("target").as_os_str().as_bytes().to_vec();
        let parent = root.as_os_str().as_bytes().to_vec();

        let mut exact = Request::StatMany {
            paths: vec![destination],
            follow: false,
            guard: None,
        };
        authority.authorize(&mut exact, false).unwrap();

        let mut parent = Request::Canonicalize {
            path: parent,
            guard: None,
        };
        let error = authority.authorize(&mut parent, false).unwrap_err();
        assert!(error
            .to_string()
            .contains("observation is outside the signed destination scopes"));
    }

    #[test]
    fn signed_filters_bind_scans_mutations_and_prune_protection() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("root");
        fs::create_dir(&root).unwrap();
        let policy = FilterPolicyV3 {
            ignore: vec!["ignored/".into(), "!ignored/file".into()],
            destination_roots: Vec::new(),
            delete_excluded: false,
        };
        let authority = test_authority_with_policy(
            &root,
            DeletionPolicyV1::DeleteDestinationOnly,
            16,
            0,
            policy.clone(),
            PublicationPolicyV1::AtomicStaged,
        );
        let target = root.join("target").as_os_str().as_bytes().to_vec();
        let ignored = root
            .join("target/ignored/file")
            .as_os_str()
            .as_bytes()
            .to_vec();
        let included = root.join("target/included").as_os_str().as_bytes().to_vec();

        let scan = |ignore: Vec<String>| Request::Scan {
            root: target.clone(),
            follow_root: false,
            ignore,
            report_ignored: true,
            guard: None,
        };
        let mut matching_scan = scan(policy.ignore.clone());
        authority.authorize(&mut matching_scan, false).unwrap();
        let mut altered_scan = scan(Vec::new());
        assert!(authority.authorize(&mut altered_scan, false).is_err());

        let prepare = |path| Request::Prepare {
            path,
            size: 4,
            inplace: false,
            partial_id: [1; 16],
            mode: 0o600,
            guard: None,
        };
        let mut included_prepare = prepare(included);
        authority.authorize(&mut included_prepare, false).unwrap();
        let mut ignored_prepare = prepare(ignored.clone());
        assert!(authority.authorize(&mut ignored_prepare, false).is_err());
        let mut protected_delete = Request::Apply {
            ops: vec![Op::Unlink {
                path: ignored.clone(),
            }],
            guard: None,
        };
        assert!(authority.authorize(&mut protected_delete, false).is_err());

        let delete_excluded = test_authority_with_policy(
            &root,
            DeletionPolicyV1::DeleteDestinationOnly,
            16,
            0,
            FilterPolicyV3 {
                ignore: policy.ignore,
                destination_roots: Vec::new(),
                delete_excluded: true,
            },
            PublicationPolicyV1::AtomicStaged,
        );
        let mut permitted_delete = Request::Apply {
            ops: vec![Op::Unlink { path: ignored }],
            guard: None,
        };
        delete_excluded
            .authorize(&mut permitted_delete, false)
            .unwrap();
    }

    #[test]
    fn mixed_filter_mappings_keep_an_explicit_named_source_root() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("root");
        fs::create_dir(&root).unwrap();
        let destination = root.join("target").as_os_str().as_bytes().to_vec();
        let mut args = Args::try_parse_from([
            "syq rsync",
            "-r",
            "host-a:tree/",
            "host-a:cache",
            "host-b:/target",
        ])
        .unwrap();
        args.normalize();
        args.placement = Placement::Into;
        let sources = [
            Location::parse("host-a:tree/").unwrap(),
            Location::parse("host-a:cache").unwrap(),
        ];
        let destination_roots = filter_destination_roots(&args, &sources, &destination).unwrap();
        let cache = root.join("target/cache").as_os_str().as_bytes().to_vec();
        assert_eq!(destination_roots, vec![destination, cache.clone()]);

        let authority = test_authority_with_policy(
            &root,
            DeletionPolicyV1::Forbid,
            16,
            0,
            FilterPolicyV3 {
                ignore: vec!["cache/".into()],
                destination_roots,
                delete_excluded: false,
            },
            PublicationPolicyV1::AtomicStaged,
        );
        let prepare = |path| Request::Prepare {
            path,
            size: 4,
            inplace: false,
            partial_id: [2; 16],
            mode: 0o600,
            guard: None,
        };
        let mut cache_root = prepare(cache.clone());
        authority.authorize(&mut cache_root, false).unwrap();
        let mut cache_child = prepare(crate::fsops::join(&cache, b"file"));
        authority.authorize(&mut cache_child, false).unwrap();
    }

    #[test]
    fn signed_inplace_policy_requires_inplace_file_mutations() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("root");
        fs::create_dir(&root).unwrap();
        let authority = test_authority_with_policy(
            &root,
            DeletionPolicyV1::Forbid,
            16,
            0,
            FilterPolicyV3::default(),
            PublicationPolicyV1::InPlace,
        );
        let target = root.join("target/file").as_os_str().as_bytes().to_vec();
        let prepare = |inplace| Request::Prepare {
            path: target.clone(),
            size: 4,
            inplace,
            partial_id: [1; 16],
            mode: 0o600,
            guard: None,
        };
        let mut inplace = prepare(true);
        authority.authorize(&mut inplace, false).unwrap();
        let mut staged = prepare(false);
        assert!(authority.authorize(&mut staged, false).is_err());
    }

    fn existence_authority(
        root: &Path,
        existing: ExistingDestinationPolicyV1,
        placement: DestinationPlacementV1,
        root_existence: RootExistenceV4,
    ) -> Result<RestrictedAuthority> {
        test_authority_with_existence(
            root,
            DeletionPolicyV1::DeleteDestinationOnly,
            1024,
            0,
            FilterPolicyV3::default(),
            PublicationPolicyV1::AtomicStaged,
            existing,
            placement,
            root_existence,
        )
    }

    fn path_bytes(path: &Path) -> Vec<u8> {
        path.as_os_str().as_bytes().to_vec()
    }

    fn plain_meta() -> proto::Meta {
        proto::Meta {
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
            mtime_nsec: 0,
        }
    }

    fn prepare_request(path: &Path) -> Request {
        Request::Prepare {
            path: path_bytes(path),
            size: 4,
            inplace: false,
            partial_id: [1; 16],
            mode: 0o600,
            guard: None,
        }
    }

    fn finalize_request(path: &Path, condition: proto::TargetCondition) -> Request {
        Request::Finalize {
            path: path_bytes(path),
            inplace: false,
            partial_id: [1; 16],
            meta: plain_meta(),
            flags: 0,
            condition,
            guard: None,
        }
    }

    fn finalize_condition(request: &Request) -> proto::TargetCondition {
        let Request::Finalize { condition, .. } = request else {
            unreachable!()
        };
        *condition
    }

    fn small_put(path: &Path) -> Request {
        Request::PutSmallBatch(vec![proto::SmallPut {
            path: path_bytes(path),
            partial_id: [1; 16],
            data: b"new".to_vec(),
            hash: crate::fsops::content_digest(b"new"),
            meta: plain_meta(),
            flags: 0,
            condition: proto::TargetCondition::Any,
            guard: None,
        }])
    }

    fn small_put_condition(request: &Request) -> proto::TargetCondition {
        let Request::PutSmallBatch(puts) = request else {
            unreachable!()
        };
        puts[0].condition
    }

    fn apply(op: Op) -> Request {
        Request::Apply {
            ops: vec![op],
            guard: None,
        }
    }

    fn op_condition(request: &Request) -> proto::TargetCondition {
        let Request::Apply { ops, .. } = request else {
            unreachable!()
        };
        match &ops[0] {
            Op::Mkdir { condition, .. }
            | Op::Symlink { condition, .. }
            | Op::Mknod { condition, .. }
            | Op::SetMeta { condition, .. }
            | Op::SetFileMetaIfSame { condition, .. } => *condition,
            Op::Remove { .. } | Op::Rmdir { .. } | Op::Unlink { .. } => unreachable!(),
        }
    }

    fn mkdir(path: &Path) -> Op {
        Op::Mkdir {
            path: path_bytes(path),
            mode: 0o755,
            condition: proto::TargetCondition::Any,
        }
    }

    fn symlink_op(path: &Path) -> Op {
        Op::Symlink {
            path: path_bytes(path),
            target: b"elsewhere".to_vec(),
            condition: proto::TargetCondition::Any,
        }
    }

    fn set_meta(path: &Path) -> Op {
        Op::SetMeta {
            path: path_bytes(path),
            meta: plain_meta(),
            flags: 0,
            condition: proto::TargetCondition::Any,
        }
    }

    #[test]
    fn signed_skip_policy_retains_preexisting_objects() {
        use proto::TargetCondition::{Absent, Any, Matches};
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("root");
        let target = root.join("target");
        let dir = target.join("dir");
        let kept = target.join("kept");
        let fresh = target.join("fresh");
        let small = target.join("small");
        let new_dir = target.join("new-dir");
        let link = target.join("link");
        fs::create_dir_all(&dir).unwrap();
        fs::write(&kept, b"old").unwrap();
        let authority = existence_authority(
            &root,
            ExistingDestinationPolicyV1::Skip,
            DestinationPlacementV1::ExactPath,
            RootExistenceV4::Any,
        )
        .unwrap();

        // New files are staged and published without replacing anything;
        // staging for a pre-existing object fails before bytes move.
        let mut prepare_fresh = prepare_request(&fresh);
        authority.authorize(&mut prepare_fresh, false).unwrap();
        let mut prepare_kept = prepare_request(&kept);
        assert!(authority.authorize(&mut prepare_kept, false).is_err());
        let mut publish_fresh = finalize_request(&fresh, Any);
        let settlement = authority.authorize(&mut publish_fresh, false).unwrap();
        assert_eq!(finalize_condition(&publish_fresh), Absent);
        authority.settle(settlement, &proto::Response::Ok);
        let mut publish_kept = finalize_request(&kept, Any);
        assert!(authority.authorize(&mut publish_kept, false).is_err());
        // What this grant created, and the executor confirmed, is its own to
        // republish.
        let mut republish_fresh = finalize_request(&fresh, Matches { dev: 1, ino: 1 });
        authority.authorize(&mut republish_fresh, false).unwrap();
        assert_eq!(
            finalize_condition(&republish_fresh),
            Matches { dev: 1, ino: 1 }
        );
        let mut small_kept = small_put(&kept);
        assert!(authority.authorize(&mut small_kept, false).is_err());
        let mut small_new = small_put(&small);
        authority.authorize(&mut small_new, false).unwrap();
        assert_eq!(small_put_condition(&small_new), Absent);

        // Existing directories are kept and reused; nothing existing becomes
        // a directory, and new directories are created without replacement.
        let mut reuse_dir = apply(mkdir(&dir));
        authority.authorize(&mut reuse_dir, false).unwrap();
        assert_eq!(op_condition(&reuse_dir), Any);
        let mut dir_over_file = apply(mkdir(&kept));
        assert!(authority.authorize(&mut dir_over_file, false).is_err());
        let mut create_dir = apply(mkdir(&new_dir));
        authority.authorize(&mut create_dir, false).unwrap();
        assert_eq!(op_condition(&create_dir), Absent);

        // Symlinks follow the same rule, and metadata may follow only this
        // grant's own creations or directories.
        let mut link_over_file = apply(symlink_op(&kept));
        assert!(authority.authorize(&mut link_over_file, false).is_err());
        let mut create_link = apply(symlink_op(&link));
        let settlement = authority.authorize(&mut create_link, false).unwrap();
        assert_eq!(op_condition(&create_link), Absent);
        authority.settle(settlement, &proto::Response::Applied(vec![None]));
        let mut meta_link = apply(set_meta(&link));
        authority.authorize(&mut meta_link, false).unwrap();
        let mut meta_dir = apply(set_meta(&dir));
        authority.authorize(&mut meta_dir, false).unwrap();
        let mut meta_kept = apply(set_meta(&kept));
        assert!(authority.authorize(&mut meta_kept, false).is_err());
        let mut same_kept = apply(Op::SetFileMetaIfSame {
            path: path_bytes(&kept),
            condition: Any,
            meta: plain_meta(),
            flags: 0,
        });
        assert!(authority.authorize(&mut same_kept, false).is_err());

        // Content repair of a pre-existing file is refused; deletion remains
        // governed by the separately signed deletion policy.
        let mut finish = Request::FinishBasis {
            path: path_bytes(&kept),
            partial_id: [1; 16],
            meta: plain_meta(),
            flags: 0,
            condition: Any,
            guard: None,
        };
        assert!(authority.authorize(&mut finish, false).is_err());
        let mut seed = Request::SeedBasis {
            path: path_bytes(&kept),
            partial_id: [1; 16],
            len: 3,
            guard: None,
        };
        assert!(authority.authorize(&mut seed, false).is_err());
        let mut delete = apply(Op::Unlink {
            path: path_bytes(&kept),
        });
        authority.authorize(&mut delete, false).unwrap();
    }

    #[test]
    fn signed_must_exist_policy_creates_nothing() {
        use proto::TargetCondition::{Absent, Any, Matches};
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("root");
        let target = root.join("target");
        let dir = target.join("dir");
        let present = target.join("present");
        let link = target.join("link");
        let missing = target.join("missing");
        fs::create_dir_all(&dir).unwrap();
        fs::write(&present, b"old").unwrap();
        std::os::unix::fs::symlink("present", &link).unwrap();
        let authority = existence_authority(
            &root,
            ExistingDestinationPolicyV1::MustExist,
            DestinationPlacementV1::ExactPath,
            RootExistenceV4::Any,
        )
        .unwrap();

        let mut prepare_present = prepare_request(&present);
        authority.authorize(&mut prepare_present, false).unwrap();
        let mut prepare_missing = prepare_request(&missing);
        assert!(authority.authorize(&mut prepare_missing, false).is_err());
        let mut update_present = finalize_request(&present, Any);
        authority.authorize(&mut update_present, false).unwrap();
        let present_identity = fs::symlink_metadata(&present).unwrap();
        assert_eq!(
            finalize_condition(&update_present),
            Matches {
                dev: present_identity.dev(),
                ino: present_identity.ino(),
            }
        );
        let mut create_present = finalize_request(&present, Absent);
        assert!(authority.authorize(&mut create_present, false).is_err());
        let mut publish_missing = finalize_request(&missing, Any);
        assert!(authority.authorize(&mut publish_missing, false).is_err());
        let mut small_missing = small_put(&missing);
        assert!(authority.authorize(&mut small_missing, false).is_err());
        let mut small_present = small_put(&present);
        authority.authorize(&mut small_present, false).unwrap();

        let mut reuse_dir = apply(mkdir(&dir));
        authority.authorize(&mut reuse_dir, false).unwrap();
        let mut create_dir = apply(mkdir(&missing));
        assert!(authority.authorize(&mut create_dir, false).is_err());
        let mut dir_over_file = apply(mkdir(&present));
        assert!(authority.authorize(&mut dir_over_file, false).is_err());
        let mut replace_link = apply(symlink_op(&link));
        authority.authorize(&mut replace_link, false).unwrap();
        let link_identity = fs::symlink_metadata(&link).unwrap();
        assert_eq!(
            op_condition(&replace_link),
            Matches {
                dev: link_identity.dev(),
                ino: link_identity.ino(),
            }
        );
        let mut create_link = apply(symlink_op(&missing));
        assert!(authority.authorize(&mut create_link, false).is_err());

        let mut finish = Request::FinishBasis {
            path: path_bytes(&present),
            partial_id: [1; 16],
            meta: plain_meta(),
            flags: 0,
            condition: Any,
            guard: None,
        };
        authority.authorize(&mut finish, false).unwrap();
        let mut meta_present = apply(set_meta(&present));
        authority.authorize(&mut meta_present, false).unwrap();
    }

    #[test]
    fn provisional_creations_are_forgotten_when_execution_fails() {
        use proto::TargetCondition::{Absent, Any, Matches};
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("root");
        let target = root.join("target");
        fs::create_dir_all(&target).unwrap();
        let authority = existence_authority(
            &root,
            ExistingDestinationPolicyV1::Skip,
            DestinationPlacementV1::ExactPath,
            RootExistenceV4::Any,
        )
        .unwrap();
        let fresh = target.join("fresh");
        let kept = target.join("kept");
        let dir_a = target.join("dir-a");
        let dir_b = target.join("dir-b");

        // A failed no-replace publication leaves nothing behind, so a foreign
        // object that appears afterwards is retained like any other.
        authority
            .authorize(&mut prepare_request(&fresh), false)
            .unwrap();
        let mut publish = finalize_request(&fresh, Any);
        let settlement = authority.authorize(&mut publish, false).unwrap();
        authority.settle(settlement, &proto::Response::Err("raced".into()));
        fs::write(&fresh, b"foreign").unwrap();
        let mut republish = finalize_request(&fresh, Any);
        assert!(authority.authorize(&mut republish, false).is_err());

        // A successful one stays this grant's own.
        let mut publish = small_put(&kept);
        let settlement = authority.authorize(&mut publish, false).unwrap();
        authority.settle(settlement, &proto::Response::Applied(vec![None]));
        authority
            .authorize(&mut prepare_request(&kept), false)
            .unwrap();
        let mut republish = finalize_request(&kept, Matches { dev: 1, ino: 1 });
        authority.authorize(&mut republish, false).unwrap();

        // Per-operation results settle a batch operation by operation.
        let mut batch = Request::Apply {
            ops: vec![mkdir(&dir_a), mkdir(&dir_b)],
            guard: None,
        };
        let settlement = authority.authorize(&mut batch, false).unwrap();
        authority.settle(
            settlement,
            &proto::Response::Applied(vec![None, Some("raced".into())]),
        );
        let mut again_a = apply(mkdir(&dir_a));
        authority.authorize(&mut again_a, false).unwrap();
        assert_eq!(op_condition(&again_a), Any);
        let mut again_b = apply(mkdir(&dir_b));
        authority.authorize(&mut again_b, false).unwrap();
        assert_eq!(op_condition(&again_b), Absent);
    }

    #[test]
    fn a_refused_request_leaves_no_provisional_creations_behind() {
        use proto::TargetCondition::{Absent, Any};
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("root");
        let target = root.join("target");
        let kept = target.join("kept");
        let fresh = target.join("fresh");
        let link = target.join("link");
        fs::create_dir_all(&target).unwrap();
        fs::write(&kept, b"old").unwrap();
        let authority = existence_authority(
            &root,
            ExistingDestinationPolicyV1::Skip,
            DestinationPlacementV1::ExactPath,
            RootExistenceV4::Any,
        )
        .unwrap();

        // The first entry is authorized before the second is refused; nothing
        // of the batch runs, so the first must not count as created.
        let mut batch = Request::Apply {
            ops: vec![mkdir(&fresh), symlink_op(&kept)],
            guard: None,
        };
        assert!(authority.authorize(&mut batch, false).is_err());
        let mut again = apply(mkdir(&fresh));
        authority.authorize(&mut again, false).unwrap();
        assert_eq!(op_condition(&again), Absent);

        // Until the executor confirms a creation, a second creation of the
        // same path is not this grant's own either: it races at the kernel.
        let mut concurrent = apply(mkdir(&fresh));
        authority.authorize(&mut concurrent, false).unwrap();
        assert_eq!(op_condition(&concurrent), Absent);

        // Metadata may follow a creation within the same request.
        let mut create_and_touch = Request::Apply {
            ops: vec![symlink_op(&link), set_meta(&link)],
            guard: None,
        };
        authority.authorize(&mut create_and_touch, false).unwrap();
        let Request::Apply { ops, .. } = &create_and_touch else {
            unreachable!()
        };
        assert!(matches!(ops[1], Op::SetMeta { condition: Any, .. }));
    }

    #[test]
    fn must_exist_accepts_only_the_observed_identity() {
        use proto::TargetCondition::{Matches, MatchesFingerprint};
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("root");
        let target = root.join("target");
        let present = target.join("present");
        fs::create_dir_all(&target).unwrap();
        fs::write(&present, b"old").unwrap();
        let authority = existence_authority(
            &root,
            ExistingDestinationPolicyV1::MustExist,
            DestinationPlacementV1::ExactPath,
            RootExistenceV4::Any,
        )
        .unwrap();
        let identity = fs::symlink_metadata(&present).unwrap();
        let mut bogus = finalize_request(&present, Matches { dev: 1, ino: 1 });
        assert!(authority.authorize(&mut bogus, false).is_err());
        let mut stale = finalize_request(
            &present,
            MatchesFingerprint {
                dev: identity.dev(),
                ino: identity.ino(),
                ctime: identity.ctime() + 1,
                ctime_nsec: identity.ctime_nsec() as u32,
            },
        );
        assert!(authority.authorize(&mut stale, false).is_err());
        authority
            .authorize(&mut prepare_request(&present), false)
            .unwrap();
        let mut exact = finalize_request(
            &present,
            Matches {
                dev: identity.dev(),
                ino: identity.ino(),
            },
        );
        authority.authorize(&mut exact, false).unwrap();
    }

    #[test]
    fn must_exist_pins_update_only_operations() {
        use proto::TargetCondition::{Any, Matches};
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("root");
        let target = root.join("target");
        let present = target.join("present");
        let missing = target.join("missing");
        fs::create_dir_all(&target).unwrap();
        fs::write(&present, b"old").unwrap();
        let authority = existence_authority(
            &root,
            ExistingDestinationPolicyV1::MustExist,
            DestinationPlacementV1::ExactPath,
            RootExistenceV4::Any,
        )
        .unwrap();
        let identity = fs::symlink_metadata(&present).unwrap();
        let expected = Matches {
            dev: identity.dev(),
            ino: identity.ino(),
        };

        let mut meta = apply(set_meta(&present));
        authority.authorize(&mut meta, false).unwrap();
        assert_eq!(op_condition(&meta), expected);
        let mut same = apply(Op::SetFileMetaIfSame {
            path: path_bytes(&present),
            condition: Any,
            meta: plain_meta(),
            flags: 0,
        });
        authority.authorize(&mut same, false).unwrap();
        assert_eq!(op_condition(&same), expected);
        let mut finish = Request::FinishBasis {
            path: path_bytes(&present),
            partial_id: [1; 16],
            meta: plain_meta(),
            flags: 0,
            condition: Any,
            guard: None,
        };
        authority.authorize(&mut finish, false).unwrap();
        let Request::FinishBasis { condition, .. } = &finish else {
            unreachable!()
        };
        assert_eq!(*condition, expected);

        let mut bogus = apply(Op::SetMeta {
            path: path_bytes(&present),
            meta: plain_meta(),
            flags: 0,
            condition: Matches { dev: 1, ino: 1 },
        });
        assert!(authority.authorize(&mut bogus, false).is_err());
        let mut absent = apply(set_meta(&missing));
        assert!(authority.authorize(&mut absent, false).is_err());
    }

    #[test]
    fn must_exist_replacement_and_metadata_execute_as_one_batch() {
        use proto::TargetCondition::{Any, Matches};
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("root");
        let target = root.join("target");
        let link = target.join("link");
        fs::create_dir_all(&target).unwrap();
        std::os::unix::fs::symlink("old-target", &link).unwrap();
        let authority = existence_authority(
            &root,
            ExistingDestinationPolicyV1::MustExist,
            DestinationPlacementV1::ExactPath,
            RootExistenceV4::Any,
        )
        .unwrap();
        let before = fs::symlink_metadata(&link).unwrap();

        // A changed symlink is replaced and then given its metadata in one
        // ordinary batch. The replacement is pinned to the old inode; the
        // metadata must land on the new one.
        let mut batch = Request::Apply {
            ops: vec![symlink_op(&link), set_meta(&link)],
            guard: None,
        };
        let settlement = authority.authorize(&mut batch, false).unwrap();
        let Request::Apply {
            ops,
            guard: Some(guard),
        } = &batch
        else {
            unreachable!()
        };
        assert!(matches!(
            ops[0],
            Op::Symlink { condition: Matches { dev, ino }, .. }
                if (dev, ino) == (before.dev(), before.ino())
        ));
        assert!(matches!(ops[1], Op::SetMeta { condition: Any, .. }));
        let results = crate::fsops::FsOps::new().apply(ops, Some(guard));
        assert!(results.iter().all(Option::is_none), "{results:?}");
        authority.settle(settlement, &proto::Response::Applied(results));
        assert_eq!(
            fs::read_link(&link).unwrap().as_os_str().as_bytes(),
            b"elsewhere"
        );
        let after = fs::symlink_metadata(&link).unwrap();
        assert_ne!(after.ino(), before.ino());

        // A later request must observe and pin the replacement afresh; it
        // is not a creation the grant may now treat as its own, so neither a
        // type change nor an unpinned publication is possible.
        let mut touch = apply(set_meta(&link));
        authority.authorize(&mut touch, false).unwrap();
        assert_eq!(
            op_condition(&touch),
            Matches {
                dev: after.dev(),
                ino: after.ino(),
            }
        );
        let mut as_directory = apply(mkdir(&link));
        assert!(authority.authorize(&mut as_directory, false).is_err());
        authority
            .authorize(&mut prepare_request(&link), false)
            .unwrap();
        let mut publish = finalize_request(&link, Any);
        authority.authorize(&mut publish, false).unwrap();
        assert_eq!(
            finalize_condition(&publish),
            Matches {
                dev: after.dev(),
                ino: after.ino(),
            }
        );
    }

    #[test]
    fn guarded_executor_honors_creation_conditions() {
        use proto::TargetCondition::{Absent, Any, Matches};
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("root");
        let target = root.join("target");
        let file = target.join("file");
        let dir = target.join("dir");
        let link = target.join("link");
        let fresh = target.join("fresh");
        fs::create_dir_all(&dir).unwrap();
        fs::write(&file, b"keep").unwrap();
        std::os::unix::fs::symlink("file", &link).unwrap();
        let root_identity = fs::metadata(&root).unwrap();
        let guard = ContainerGuard {
            root: path_bytes(&root),
            dev: root_identity.dev(),
            ino: root_identity.ino(),
        };
        let identity = |path: &Path| {
            let metadata = fs::symlink_metadata(path).unwrap();
            Matches {
                dev: metadata.dev(),
                ino: metadata.ino(),
            }
        };
        let run = |op: Op| crate::fsops::FsOps::new().apply(&[op], Some(&guard))[0].clone();
        let with = |op: Op, condition| match op {
            Op::Mkdir { path, mode, .. } => Op::Mkdir {
                path,
                mode,
                condition,
            },
            Op::Symlink { path, target, .. } => Op::Symlink {
                path,
                target,
                condition,
            },
            other => other,
        };

        // No-replace creation never removes what is there.
        assert!(run(with(mkdir(&file), Absent)).is_some());
        assert!(run(with(symlink_op(&file), Absent)).is_some());
        assert!(run(with(mkdir(&dir), Absent)).is_some());
        assert_eq!(fs::read(&file).unwrap(), b"keep");
        assert!(run(with(mkdir(&fresh), Absent)).is_none());
        assert!(fresh.is_dir());

        // Matched replacement requires the observed object and its type.
        assert!(run(with(symlink_op(&link), Matches { dev: 1, ino: 1 })).is_some());
        assert!(run(with(symlink_op(&file), identity(&file))).is_some());
        assert_eq!(fs::read(&file).unwrap(), b"keep");
        assert!(run(with(symlink_op(&link), identity(&link))).is_none());
        assert!(run(with(mkdir(&file), identity(&file))).is_some());
        assert!(run(with(mkdir(&dir), identity(&dir))).is_none());

        // The unconditioned form keeps the ordinary replace behavior.
        assert!(run(with(symlink_op(&file), Any)).is_none());
        assert!(file.is_symlink());
    }

    #[test]
    fn new_directory_placement_root_must_be_created_as_a_directory() {
        use proto::TargetCondition::{Absent, Any};
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("root");
        fs::create_dir(&root).unwrap();
        let target = root.join("target");
        let authority = existence_authority(
            &root,
            ExistingDestinationPolicyV1::Replace,
            DestinationPlacementV1::DirectoryAsChild,
            RootExistenceV4::New,
        )
        .unwrap();
        let mut as_file = finalize_request(&target, Any);
        assert!(authority.authorize(&mut as_file, false).is_err());
        let mut as_small_file = small_put(&target);
        assert!(authority.authorize(&mut as_small_file, false).is_err());
        let mut as_link = apply(symlink_op(&target));
        assert!(authority.authorize(&mut as_link, false).is_err());
        let mut as_directory = apply(mkdir(&target));
        authority.authorize(&mut as_directory, false).unwrap();
        assert_eq!(op_condition(&as_directory), Absent);
    }

    #[test]
    fn inplace_publication_cannot_honor_no_replace_policies() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("root");
        fs::create_dir(&root).unwrap();
        let inplace = |existing, placement, root_existence| {
            test_authority_with_existence(
                &root,
                DeletionPolicyV1::Forbid,
                1024,
                0,
                FilterPolicyV3::default(),
                PublicationPolicyV1::InPlace,
                existing,
                placement,
                root_existence,
            )
        };
        assert!(inplace(
            ExistingDestinationPolicyV1::Skip,
            DestinationPlacementV1::ExactPath,
            RootExistenceV4::Any,
        )
        .is_err());
        assert!(inplace(
            ExistingDestinationPolicyV1::Replace,
            DestinationPlacementV1::ExactPath,
            RootExistenceV4::New,
        )
        .is_err());
        // In-place preparation cannot be pinned to an observed object either,
        // so MustExist is refused as well; only Replace remains, and a new
        // directory root is fine because mkdir creates it.
        assert!(inplace(
            ExistingDestinationPolicyV1::MustExist,
            DestinationPlacementV1::ExactPath,
            RootExistenceV4::Any,
        )
        .is_err());
        inplace(
            ExistingDestinationPolicyV1::Replace,
            DestinationPlacementV1::DirectoryContents,
            RootExistenceV4::New,
        )
        .unwrap();

        // The orchestrator refuses the same combination before signing. The
        // rsync-shaped parser already makes --inplace and --ignore-existing
        // conflict, so the reachable case is the native --as-new placement.
        let mut args = Args::try_parse_from([
            "syq rsync",
            "-r",
            "--inplace",
            "host-a:source",
            "host-b:/backup",
        ])
        .unwrap();
        args.normalize();
        validate_restricted_args(&args).unwrap();
        args.placement = Placement::As;
        args.target_existence = Existence::New;
        assert!(validate_restricted_args(&args).is_err());
        args.placement = Placement::Into;
        validate_restricted_args(&args).unwrap();
    }

    #[test]
    fn signed_root_existence_is_checked_at_claim_and_forced_on_creation() {
        use proto::TargetCondition::{Absent, Any};
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("root");
        fs::create_dir(&root).unwrap();
        let target = root.join("target");
        let replace = ExistingDestinationPolicyV1::Replace;

        // A root that must be new is refused when present, and otherwise may
        // only be created without replacement; afterwards it is this grant's.
        fs::create_dir(&target).unwrap();
        assert!(existence_authority(
            &root,
            replace,
            DestinationPlacementV1::DirectoryContents,
            RootExistenceV4::New,
        )
        .is_err());
        fs::remove_dir(&target).unwrap();
        let authority = existence_authority(
            &root,
            replace,
            DestinationPlacementV1::DirectoryContents,
            RootExistenceV4::New,
        )
        .unwrap();
        let mut create_root = apply(mkdir(&target));
        let settlement = authority.authorize(&mut create_root, false).unwrap();
        assert_eq!(op_condition(&create_root), Absent);
        fs::create_dir(&target).unwrap();
        authority.settle(settlement, &proto::Response::Applied(vec![None]));
        let mut revisit_root = apply(mkdir(&target));
        authority.authorize(&mut revisit_root, false).unwrap();
        assert_eq!(op_condition(&revisit_root), Any);
        authority
            .authorize(&mut prepare_request(&target.join("child")), false)
            .unwrap();
        let mut child = finalize_request(&target.join("child"), Any);
        authority.authorize(&mut child, false).unwrap();
        assert_eq!(finalize_condition(&child), Any);

        // A root that must exist needs the object, and a directory whenever
        // the placement puts names inside it.
        fs::remove_dir(&target).unwrap();
        assert!(existence_authority(
            &root,
            replace,
            DestinationPlacementV1::DirectoryContents,
            RootExistenceV4::Existing,
        )
        .is_err());
        fs::write(&target, b"file").unwrap();
        assert!(existence_authority(
            &root,
            replace,
            DestinationPlacementV1::DirectoryContents,
            RootExistenceV4::Existing,
        )
        .is_err());
        existence_authority(
            &root,
            replace,
            DestinationPlacementV1::ExactPath,
            RootExistenceV4::Existing,
        )
        .unwrap();
        fs::remove_file(&target).unwrap();
        fs::create_dir(&target).unwrap();
        existence_authority(
            &root,
            replace,
            DestinationPlacementV1::DirectoryAsChild,
            RootExistenceV4::Existing,
        )
        .unwrap();

        // The one existing-object policy the receiver cannot enforce is
        // refused when the grant is claimed rather than trusted.
        assert!(existence_authority(
            &root,
            ExistingDestinationPolicyV1::UpdateIfOlder,
            DestinationPlacementV1::ExactPath,
            RootExistenceV4::Any,
        )
        .is_err());
    }

    #[test]
    fn grant_distinguishes_receiver_modes_from_source_permission_preservation() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("root");
        fs::create_dir(&root).unwrap();
        let target = root.join("target").as_os_str().as_bytes().to_vec();
        let metadata = |flags| Request::Apply {
            ops: vec![Op::SetMeta {
                path: target.clone(),
                meta: proto::Meta {
                    mode: 0o640,
                    uid: 0,
                    gid: 0,
                    mtime: 0,
                    mtime_nsec: 0,
                },
                flags,
                condition: proto::TargetCondition::Any,
            }],
            guard: None,
        };

        let receiver_modes = test_authority(&root, DeletionPolicyV1::Forbid, 1024);
        let mut receiver_mode = metadata(proto::flags::RECEIVER_MODE);
        receiver_modes.authorize(&mut receiver_mode, false).unwrap();
        let mut source_mode = metadata(proto::flags::MODE);
        assert!(receiver_modes.authorize(&mut source_mode, false).is_err());
        let mut mixed = metadata(proto::flags::MODE_MASK);
        assert!(receiver_modes.authorize(&mut mixed, false).is_err());

        let mut source_modes = test_authority(&root, DeletionPolicyV1::Forbid, 1024);
        source_modes.copy.options.preserve_permissions = true;
        source_modes.copy.options.receiver_managed_modes = false;
        let mut source_mode = metadata(proto::flags::MODE);
        source_modes.authorize(&mut source_mode, false).unwrap();
        let mut receiver_mode = metadata(proto::flags::RECEIVER_MODE);
        assert!(source_modes.authorize(&mut receiver_mode, false).is_err());
    }

    #[test]
    fn receiver_managed_modes_preserve_existing_objects_and_mask_new_ones() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("root");
        let target = root.join("target");
        let existing_directory = target.join("existing-dir");
        let new_directory = target.join("new-dir");
        fs::create_dir_all(&existing_directory).unwrap();
        fs::set_permissions(&existing_directory, fs::Permissions::from_mode(0o500)).unwrap();
        let mut authority = test_authority(&root, DeletionPolicyV1::Forbid, 1024);
        authority.receiver_umask = 0o022;
        let path = |path: &Path| path.as_os_str().as_bytes().to_vec();

        let mut mkdir = Request::Apply {
            ops: vec![
                Op::Mkdir {
                    path: path(&existing_directory),
                    mode: 0o7777,
                    condition: proto::TargetCondition::Any,
                },
                Op::Mkdir {
                    path: path(&new_directory),
                    mode: 0o7777,
                    condition: proto::TargetCondition::Any,
                },
            ],
            guard: None,
        };
        authority.authorize(&mut mkdir, false).unwrap();
        let Request::Apply {
            ops,
            guard: Some(guard),
        } = &mkdir
        else {
            panic!("authority did not guard directory creation")
        };
        assert!(ops
            .iter()
            .all(|operation| matches!(operation, Op::Mkdir { mode: 0o700, .. })));
        assert!(crate::fsops::FsOps::new()
            .apply(ops, Some(guard))
            .into_iter()
            .all(|error| error.is_none()));
        assert_eq!(
            fs::metadata(&existing_directory).unwrap().mode() & 0o7777,
            0o700
        );
        assert_eq!(fs::metadata(&new_directory).unwrap().mode() & 0o7777, 0o700);

        let receiver_meta = |path: &Path| Op::SetMeta {
            path: path.as_os_str().as_bytes().to_vec(),
            meta: proto::Meta {
                mode: 0o7777,
                uid: 0,
                gid: 0,
                mtime: 0,
                mtime_nsec: 0,
            },
            flags: proto::flags::RECEIVER_MODE,
            condition: proto::TargetCondition::Any,
        };
        let mut metadata = Request::Apply {
            ops: vec![
                receiver_meta(&existing_directory),
                receiver_meta(&new_directory),
            ],
            guard: None,
        };
        authority.authorize(&mut metadata, false).unwrap();
        let Request::Apply {
            ops,
            guard: Some(guard),
        } = &metadata
        else {
            panic!("authority did not guard directory metadata")
        };
        assert!(matches!(
            &ops[0],
            Op::SetMeta {
                meta: proto::Meta { mode: 0o500, .. },
                flags: proto::flags::MODE,
                ..
            }
        ));
        assert!(matches!(
            &ops[1],
            Op::SetMeta {
                meta: proto::Meta { mode: 0o755, .. },
                flags: proto::flags::MODE,
                ..
            }
        ));
        assert!(crate::fsops::FsOps::new()
            .apply(ops, Some(guard))
            .into_iter()
            .all(|error| error.is_none()));
        assert_eq!(
            fs::metadata(&existing_directory).unwrap().mode() & 0o7777,
            0o500
        );
        assert_eq!(fs::metadata(&new_directory).unwrap().mode() & 0o7777, 0o755);

        let raced_directory = target.join("raced-dir");
        fs::create_dir(&raced_directory).unwrap();
        fs::set_permissions(&raced_directory, fs::Permissions::from_mode(0o500)).unwrap();
        let mut raced_mkdir = Request::Apply {
            ops: vec![Op::Mkdir {
                path: path(&raced_directory),
                mode: 0o7777,
                condition: proto::TargetCondition::Any,
            }],
            guard: None,
        };
        authority.authorize(&mut raced_mkdir, false).unwrap();
        let Request::Apply {
            ops,
            guard: Some(guard),
        } = &raced_mkdir
        else {
            unreachable!()
        };
        assert!(crate::fsops::FsOps::new()
            .apply(ops, Some(guard))
            .into_iter()
            .all(|error| error.is_none()));
        let mut raced_metadata = Request::Apply {
            ops: vec![receiver_meta(&raced_directory)],
            guard: None,
        };
        authority.authorize(&mut raced_metadata, false).unwrap();
        let displaced_directory = File::open(&raced_directory).unwrap();
        fs::remove_dir(&raced_directory).unwrap();
        fs::create_dir(&raced_directory).unwrap();
        fs::set_permissions(&raced_directory, fs::Permissions::from_mode(0o700)).unwrap();
        let Request::Apply {
            ops,
            guard: Some(guard),
        } = &raced_metadata
        else {
            unreachable!()
        };
        assert!(crate::fsops::FsOps::new()
            .apply(ops, Some(guard))
            .into_iter()
            .all(|error| error.is_some()));
        drop(displaced_directory);
        assert_eq!(
            fs::metadata(&raced_directory).unwrap().mode() & 0o7777,
            0o700
        );

        let existing_file = target.join("existing-file");
        let new_file = target.join("new-file");
        fs::write(&existing_file, b"old").unwrap();
        fs::set_permissions(&existing_file, fs::Permissions::from_mode(0o600)).unwrap();
        let put = |path: &Path, mode| proto::SmallPut {
            path: path.as_os_str().as_bytes().to_vec(),
            partial_id: [1; 16],
            data: b"new".to_vec(),
            hash: crate::fsops::content_digest(b"new"),
            meta: proto::Meta {
                mode,
                uid: 0,
                gid: 0,
                mtime: 0,
                mtime_nsec: 0,
            },
            flags: proto::flags::RECEIVER_MODE,
            condition: proto::TargetCondition::Any,
            guard: None,
        };
        let mut files =
            Request::PutSmallBatch(vec![put(&existing_file, 0o7777), put(&new_file, 0o7777)]);
        authority.authorize(&mut files, false).unwrap();
        let Request::PutSmallBatch(puts) = &files else {
            unreachable!()
        };
        assert_eq!(
            (puts[0].meta.mode, puts[0].flags),
            (0o600, proto::flags::MODE)
        );
        assert_eq!(
            (puts[1].meta.mode, puts[1].flags),
            (0o755, proto::flags::MODE)
        );
        assert!(matches!(
            puts[0].condition,
            proto::TargetCondition::MatchesFingerprint { .. }
        ));
        assert_eq!(puts[1].condition, proto::TargetCondition::Any);
        let response = crate::fsops::FsOps::new().handle(&files);
        let proto::Response::Applied(errors) = response else {
            panic!("unexpected small-publication response")
        };
        assert!(errors.iter().all(Option::is_none), "{errors:?}");
        assert_eq!(fs::read(&existing_file).unwrap(), b"new");
        assert_eq!(fs::metadata(&existing_file).unwrap().mode() & 0o7777, 0o600);
        assert_eq!(fs::read(&new_file).unwrap(), b"new");
        assert_eq!(fs::metadata(&new_file).unwrap().mode() & 0o7777, 0o755);

        let mut repeated = Request::PutSmallBatch(vec![put(&new_file, 0o600)]);
        authority.authorize(&mut repeated, false).unwrap();
        let Request::PutSmallBatch(puts) = repeated else {
            unreachable!()
        };
        assert_eq!(
            (puts[0].meta.mode, puts[0].flags),
            (0o755, proto::flags::MODE)
        );

        // A later type replacement cannot reuse an existing directory's
        // receiver-owned mode (including any directory-only special bits) for
        // a newly published regular file.
        let mut replacement = Request::PutSmallBatch(vec![put(&existing_directory, 0o7777)]);
        authority.authorize(&mut replacement, false).unwrap();
        let Request::PutSmallBatch(puts) = replacement else {
            unreachable!()
        };
        assert_eq!(
            (puts[0].meta.mode, puts[0].flags),
            (0o755, proto::flags::MODE)
        );

        let raced_file = target.join("raced-file");
        fs::write(&raced_file, b"old").unwrap();
        fs::set_permissions(&raced_file, fs::Permissions::from_mode(0o6777)).unwrap();
        let mut raced = Request::PutSmallBatch(vec![put(&raced_file, 0o600)]);
        authority.authorize(&mut raced, false).unwrap();
        fs::remove_file(&raced_file).unwrap();
        let response = crate::fsops::FsOps::new().handle(&raced);
        assert!(matches!(
            response,
            proto::Response::Applied(errors) if errors.iter().all(Option::is_some)
        ));
        assert!(!raced_file.exists());
    }

    #[test]
    fn receiver_managed_new_directory_preserves_receiver_inherited_setgid() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("root");
        let parent = root.join("target/inheriting-parent");
        let child = parent.join("child");
        fs::create_dir_all(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o2755)).unwrap();
        let mut authority = test_authority(&root, DeletionPolicyV1::Forbid, 1024);
        authority.receiver_umask = 0o022;

        let mut mkdir = Request::Apply {
            ops: vec![Op::Mkdir {
                path: child.as_os_str().as_bytes().to_vec(),
                mode: 0o7777,
                condition: proto::TargetCondition::Any,
            }],
            guard: None,
        };
        authority.authorize(&mut mkdir, false).unwrap();
        let Request::Apply {
            ops,
            guard: Some(guard),
        } = &mkdir
        else {
            unreachable!()
        };
        assert!(matches!(ops[0], Op::Mkdir { mode: 0o700, .. }));
        assert!(crate::fsops::FsOps::new()
            .apply(ops, Some(guard))
            .into_iter()
            .all(|error| error.is_none()));
        assert_eq!(fs::metadata(&child).unwrap().mode() & 0o7777, 0o2700);

        let mut metadata = Request::Apply {
            ops: vec![Op::SetMeta {
                path: child.as_os_str().as_bytes().to_vec(),
                meta: proto::Meta {
                    // None of these source-proposed special bits are trusted.
                    mode: 0o7777,
                    uid: 0,
                    gid: 0,
                    mtime: 0,
                    mtime_nsec: 0,
                },
                flags: proto::flags::RECEIVER_MODE,
                condition: proto::TargetCondition::Any,
            }],
            guard: None,
        };
        authority.authorize(&mut metadata, false).unwrap();
        let Request::Apply {
            ops,
            guard: Some(guard),
        } = &metadata
        else {
            unreachable!()
        };
        assert!(matches!(
            ops[0],
            Op::SetMeta {
                meta: proto::Meta { mode: 0o2755, .. },
                flags: proto::flags::MODE,
                condition: proto::TargetCondition::MatchesFingerprint { .. },
                ..
            }
        ));
        assert!(crate::fsops::FsOps::new()
            .apply(ops, Some(guard))
            .into_iter()
            .all(|error| error.is_none()));
        assert_eq!(fs::metadata(&child).unwrap().mode() & 0o7777, 0o2755);
    }

    #[test]
    fn signed_hash_block_and_response_bounds_are_enforced() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("root");
        fs::create_dir(&root).unwrap();
        let mut authority = test_authority(&root, DeletionPolicyV1::Forbid, DEFAULT_MAX_BYTES);
        let target = root.join("target").as_os_str().as_bytes().to_vec();
        let request = |block, len| Request::HashBlocks {
            path: target.clone(),
            which: proto::Which::Final,
            partial_id: [0; 16],
            block,
            len,
            guard: None,
        };

        let mut valid = request(4 << 20, 8 << 20);
        authority.authorize(&mut valid, false).unwrap();
        for block in [0, 1, 8 << 20] {
            let mut altered = request(block, 8 << 20);
            assert!(authority.authorize(&mut altered, false).is_err());
        }

        authority.copy.limits.hash_block_bytes = proto::MIN_HASH_BLOCK_BYTES;
        let excessive_entries = proto::MAX_FRAME as u64 / 32 + 1;
        let mut excessive = request(
            proto::MIN_HASH_BLOCK_BYTES,
            excessive_entries * proto::MIN_HASH_BLOCK_BYTES,
        );
        assert_eq!(
            authority
                .authorize(&mut excessive, false)
                .unwrap_err()
                .to_string(),
            "hash response would exceed protocol limits"
        );
    }

    #[test]
    fn signed_file_data_rate_is_enforced_across_requests() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("root");
        fs::create_dir(&root).unwrap();
        let authority = test_authority_with_rate(&root, DeletionPolicyV1::Forbid, 1024, 1024);
        let target = root.join("target").as_os_str().as_bytes().to_vec();
        let request = |off| Request::WriteRange {
            path: target.clone(),
            inplace: false,
            partial_id: [0; 16],
            attempt: 0,
            off,
            hash: [0; 32],
            data: vec![0; 256],
            guard: None,
        };

        // Writes must land in a partial this grant declared.
        assert!(authority.authorize(&mut request(0), false).is_err());
        let mut prepare = Request::Prepare {
            path: target.clone(),
            size: 1024,
            inplace: false,
            partial_id: [0; 16],
            mode: 0o600,
            guard: None,
        };
        authority.authorize(&mut prepare, false).unwrap();

        let started = Instant::now();
        authority.authorize(&mut request(0), false).unwrap();
        authority.authorize(&mut request(256), false).unwrap();
        assert!(
            started.elapsed() >= std::time::Duration::from_millis(200),
            "signed aggregate rate limit did not pace consecutive writes"
        );

        let mut oversized = request(0);
        if let Request::WriteRange { data, .. } = &mut oversized {
            data.resize(513, 0);
        }
        assert_eq!(
            authority
                .authorize(&mut oversized, false)
                .unwrap_err()
                .to_string(),
            "request exceeds the signed file-data rate-limit burst"
        );
    }

    #[test]
    fn command_restricted_validation_accepts_a_signed_rate_limit() {
        let mut args = Args::try_parse_from(["syq", "source", "destination"]).unwrap();
        args.normalize();
        args.bwlimit_bytes = 1024;
        validate_restricted_args(&args).unwrap();
    }

    #[test]
    fn authority_binds_one_encrypted_listener_and_known_metadata_flags() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("root");
        fs::create_dir(&root).unwrap();
        let authority = test_authority(&root, DeletionPolicyV1::Forbid, 1024);
        let mut listener = Request::TcpListen {
            key: Some(vec![7; crate::crypto::KEY_LEN]),
            token: vec![8; 16],
            port_lo: 47_600,
            port_hi: 47_699,
            congestion_control: None,
        };
        authority.authorize(&mut listener, true).unwrap();
        assert!(authority.authorize(&mut listener, true).is_err());
        assert!(authority.control_is_open());
        authority.close_control();
        assert!(!authority.control_is_open());

        let wrong_range = test_authority(&root, DeletionPolicyV1::Forbid, 1024);
        let mut listener = Request::TcpListen {
            key: Some(vec![7; crate::crypto::KEY_LEN]),
            token: vec![8; 16],
            port_lo: 1,
            port_hi: 2,
            congestion_control: None,
        };
        assert!(wrong_range.authorize(&mut listener, true).is_err());

        let congestion_override = test_authority(&root, DeletionPolicyV1::Forbid, 1024);
        let mut listener = Request::TcpListen {
            key: Some(vec![7; crate::crypto::KEY_LEN]),
            token: vec![8; 16],
            port_lo: 47_600,
            port_hi: 47_699,
            congestion_control: Some("reno".into()),
        };
        assert!(congestion_override.authorize(&mut listener, true).is_err());

        let target = root.join("target").as_os_str().as_bytes().to_vec();
        let mut metadata = Request::Apply {
            ops: vec![Op::SetMeta {
                path: target,
                meta: proto::Meta {
                    mode: 0,
                    uid: 0,
                    gid: 0,
                    mtime: 0,
                    mtime_nsec: 0,
                },
                flags: 0x80,
                condition: proto::TargetCondition::Any,
            }],
            guard: None,
        };
        assert!(wrong_range.authorize(&mut metadata, false).is_err());
    }

    #[test]
    fn signed_read_only_modes_reject_every_destination_mutation() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("root");
        fs::create_dir(&root).unwrap();
        let mut authority = test_authority(&root, DeletionPolicyV1::Forbid, 1024);
        authority.copy.options.dry_run = true;
        let target = root.join("target").as_os_str().as_bytes().to_vec();
        let mut mutation = Request::Apply {
            ops: vec![Op::Mkdir {
                path: target.clone(),
                mode: 0o700,
                condition: proto::TargetCondition::Absent,
            }],
            guard: None,
        };
        assert!(authority.authorize(&mut mutation, false).is_err());

        let mut small = Request::PutSmallBatch(vec![proto::SmallPut {
            path: target.clone(),
            partial_id: [1; 16],
            data: vec![0],
            hash: [0; 32],
            meta: proto::Meta {
                mode: 0o600,
                uid: 0,
                gid: 0,
                mtime: 0,
                mtime_nsec: 0,
            },
            flags: 0,
            condition: proto::TargetCondition::Any,
            guard: None,
        }]);
        assert!(authority.authorize(&mut small, false).is_err());

        let mut observation = Request::StatMany {
            paths: vec![target],
            follow: false,
            guard: None,
        };
        authority.authorize(&mut observation, false).unwrap();
    }

    #[test]
    fn directory_as_child_scope_does_not_authorize_unrelated_siblings() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("root");
        fs::create_dir(&root).unwrap();
        let mut authority = test_authority(&root, DeletionPolicyV1::Forbid, 1024);
        let target = root.join("target").as_os_str().as_bytes().to_vec();
        let allowed = root.join("target/source").as_os_str().as_bytes().to_vec();
        authority.copy.mutation_scopes = vec![
            MutationScopeV1 {
                path: target.clone(),
                descendants: false,
            },
            MutationScopeV1 {
                path: allowed,
                descendants: true,
            },
        ];
        let mut request = Request::Apply {
            ops: vec![Op::Mkdir {
                path: root
                    .join("target/unrelated")
                    .as_os_str()
                    .as_bytes()
                    .to_vec(),
                mode: 0o700,
                condition: proto::TargetCondition::Absent,
            }],
            guard: None,
        };
        assert!(authority.authorize(&mut request, false).is_err());

        let mut observe_container = Request::StatMany {
            paths: vec![target],
            follow: false,
            guard: None,
        };
        authority.authorize(&mut observe_container, false).unwrap();
    }

    #[test]
    fn entry_ceiling_survives_resubmission_of_a_rejected_path() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("root");
        fs::create_dir(&root).unwrap();
        // The helper grant allows eight entries.
        let authority = test_authority(&root, DeletionPolicyV1::Forbid, 1024);
        let stat = |name: String| Request::StatMany {
            paths: vec![root
                .join("target")
                .join(name)
                .as_os_str()
                .as_bytes()
                .to_vec()],
            follow: false,
            guard: None,
        };
        for index in 0..8 {
            authority
                .authorize(&mut stat(format!("entry-{index}")), false)
                .unwrap();
        }
        assert!(authority
            .authorize(&mut stat("entry-8".into()), false)
            .is_err());
        // Resubmitting the rejected path must not slip through as counted.
        assert!(authority
            .authorize(&mut stat("entry-8".into()), false)
            .is_err());
        // Paths already inside the ceiling remain usable.
        authority
            .authorize(&mut stat("entry-0".into()), false)
            .unwrap();
    }

    #[test]
    fn forbidden_deletion_keeps_the_unfiltered_scan_but_refuses_removals() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("root");
        fs::create_dir(&root).unwrap();
        let authority = test_authority_with_policy(
            &root,
            DeletionPolicyV1::Forbid,
            16,
            0,
            FilterPolicyV3 {
                ignore: vec!["ignored/".into()],
                destination_roots: Vec::new(),
                delete_excluded: true,
            },
            PublicationPolicyV1::AtomicStaged,
        );
        let target = root.join("target").as_os_str().as_bytes().to_vec();
        let mut unfiltered_scan = Request::Scan {
            root: target,
            follow_root: false,
            ignore: Vec::new(),
            report_ignored: true,
            guard: None,
        };
        authority.authorize(&mut unfiltered_scan, false).unwrap();
        let ignored = root
            .join("target/ignored/file")
            .as_os_str()
            .as_bytes()
            .to_vec();
        let mut delete = Request::Apply {
            ops: vec![Op::Unlink { path: ignored }],
            guard: None,
        };
        assert!(authority.authorize(&mut delete, false).is_err());
    }

    #[test]
    fn preparation_and_seeding_are_charged_against_the_byte_ceiling() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("root");
        fs::create_dir_all(root.join("target")).unwrap();
        // The helper grant allows 16 bytes in total and per file.
        let authority = test_authority(&root, DeletionPolicyV1::Forbid, 16);
        let prepare = |name: &str, size| Request::Prepare {
            path: root
                .join("target")
                .join(name)
                .as_os_str()
                .as_bytes()
                .to_vec(),
            size,
            inplace: false,
            partial_id: [1; 16],
            mode: 0o600,
            guard: None,
        };
        authority.authorize(&mut prepare("a", 10), false).unwrap();
        // A second file would take the aggregate past the ceiling.
        assert!(authority.authorize(&mut prepare("b", 10), false).is_err());
        // Re-preparing the same file at the same or a larger size charges only
        // the difference; a retry never double counts.
        authority.authorize(&mut prepare("a", 10), false).unwrap();
        authority.authorize(&mut prepare("a", 14), false).unwrap();
        assert!(authority.authorize(&mut prepare("b", 3), false).is_err());
        authority.authorize(&mut prepare("b", 2), false).unwrap();
        let mut seed = Request::SeedBasis {
            path: root.join("target/b").as_os_str().as_bytes().to_vec(),
            partial_id: [1; 16],
            len: 3,
            guard: None,
        };
        assert!(authority.authorize(&mut seed, false).is_err());

        // An empty file is declared at zero length and can be published.
        authority
            .authorize(&mut prepare("empty", 0), false)
            .unwrap();
        let mut publish_empty = Request::Finalize {
            path: root.join("target/empty").as_os_str().as_bytes().to_vec(),
            inplace: false,
            partial_id: [1; 16],
            meta: proto::Meta {
                mode: 0o644,
                uid: 0,
                gid: 0,
                mtime: 0,
                mtime_nsec: 0,
            },
            flags: 0,
            condition: proto::TargetCondition::Any,
            guard: None,
        };
        authority.authorize(&mut publish_empty, false).unwrap();
        // A file never declared under this grant cannot be published.
        let mut publish_foreign = Request::Finalize {
            path: root.join("target/foreign").as_os_str().as_bytes().to_vec(),
            inplace: false,
            partial_id: [9; 16],
            meta: proto::Meta {
                mode: 0o644,
                uid: 0,
                gid: 0,
                mtime: 0,
                mtime_nsec: 0,
            },
            flags: 0,
            condition: proto::TargetCondition::Any,
            guard: None,
        };
        assert!(authority.authorize(&mut publish_foreign, false).is_err());
    }

    #[test]
    fn scanned_entries_count_against_the_entry_ceiling() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("root");
        fs::create_dir(&root).unwrap();
        // The helper grant allows eight entries.
        let authority = test_authority(&root, DeletionPolicyV1::Forbid, 1024);
        let target = root.join("target").as_os_str().as_bytes().to_vec();
        let mut scan = Request::Scan {
            root: target.clone(),
            follow_root: false,
            ignore: Vec::new(),
            report_ignored: false,
            guard: None,
        };
        authority.authorize(&mut scan, false).unwrap();
        let names: Vec<Vec<u8>> = (0..7)
            .map(|index| format!("entry-{index}").into_bytes())
            .collect();
        let mut batch: Vec<&[u8]> = vec![b""];
        batch.extend(names.iter().map(Vec::as_slice));
        // Root plus seven descendants fills the ceiling exactly.
        authority.record_scanned(&target, batch).unwrap();
        assert!(authority
            .record_scanned(&target, [b"entry-7".as_slice()])
            .is_err());
        // Already counted entries may be listed again.
        authority
            .record_scanned(&target, [b"entry-0".as_slice()])
            .unwrap();
    }

    #[test]
    fn ceiling_ranges_are_checked_before_any_enrollment_side_effect() {
        let parse = |options: &[&str]| {
            let mut argv = vec!["syq rsync", "-r"];
            argv.extend_from_slice(options);
            argv.extend_from_slice(&["host-a:source", "host-b:/backup"]);
            let mut args = Args::try_parse_from(argv).unwrap();
            args.normalize();
            args
        };
        // validate_restricted_args runs first in prepare_transfer, before
        // the enrollment lookup or installation.
        let mut args = parse(&[]);
        validate_restricted_args(&args).unwrap();
        args.max_runtime_secs = Some(DEFAULT_RUNTIME_SECONDS + 1);
        assert!(validate_restricted_args(&args).is_err());
        let mut args = parse(&[]);
        args.max_entries = Some(0);
        assert!(validate_restricted_args(&args).is_err());
        args.max_entries = Some(delegation::MAX_ENTRIES + 1);
        assert!(validate_restricted_args(&args).is_err());
        let mut args = parse(&[]);
        args.max_total_bytes = Some(0);
        assert!(validate_restricted_args(&args).is_err());
        assert!(validate_restricted_args(&parse(&["--max-size", "0"])).is_err());
        assert!(validate_restricted_args(&parse(&["--delete"])).is_err());
        validate_restricted_args(&parse(&["--delete", "--max-delete", "0"])).unwrap();

        // A zero deletion budget signs a grant that forbids deletion outright.
        let id = EnrollmentId::random();
        let source = Location::parse("host-a:source").unwrap();
        let grant = grant_for(
            &parse(&["--delete", "--max-delete", "0"]),
            std::slice::from_ref(&source),
            id,
            "backup",
            "/backup",
        )
        .unwrap();
        let GrantOperationV1::Copy(copy) = &grant.operation;
        assert_eq!(copy.policy.deletion, DeletionPolicyV1::Forbid);
        assert_eq!(copy.limits.max_deletions, 0);
    }

    #[test]
    fn explicit_ceilings_are_signed_and_deletion_needs_a_stated_budget() {
        let id = EnrollmentId::random();
        let source = Location::parse("host-a:source").unwrap();
        let parse = |options: &[&str]| {
            let mut argv = vec!["syq rsync", "-r"];
            argv.extend_from_slice(options);
            argv.extend_from_slice(&["host-a:source", "host-b:/backup"]);
            let mut args = Args::try_parse_from(argv).unwrap();
            args.normalize();
            args
        };

        // Defaults are the wide built-in ceilings and the 24-hour validity.
        let default_args = parse(&[]);
        let default_grant = grant_for(
            &default_args,
            std::slice::from_ref(&source),
            id,
            "backup",
            "/backup",
        )
        .unwrap();
        let GrantOperationV1::Copy(default_copy) = &default_grant.operation;
        assert_eq!(default_copy.limits.max_entries, DEFAULT_MAX_ENTRIES);
        assert_eq!(default_copy.limits.max_total_bytes, DEFAULT_MAX_BYTES);
        assert_eq!(default_copy.limits.max_file_bytes, DEFAULT_MAX_BYTES);
        assert_eq!(
            default_copy.limits.max_runtime_seconds,
            DEFAULT_RUNTIME_SECONDS
        );
        assert_eq!(
            default_grant.not_after - default_grant.not_before,
            GRANT_VALIDITY_SECONDS
        );

        // Explicit ceilings land in the signed limits; the per-file bound
        // never exceeds the total, and the validity shrinks to the runtime.
        let mut ceilings = parse(&["--max-size", "3M"]);
        ceilings.max_entries = Some(12);
        ceilings.max_total_bytes = Some(2 << 20);
        ceilings.max_runtime_secs = Some(1800);
        let grant = grant_for(
            &ceilings,
            std::slice::from_ref(&source),
            id,
            "backup",
            "/backup",
        )
        .unwrap();
        let GrantOperationV1::Copy(copy) = &grant.operation;
        assert_eq!(copy.limits.max_entries, 12);
        assert_eq!(copy.limits.max_total_bytes, 2 << 20);
        assert_eq!(copy.limits.max_file_bytes, 2 << 20);
        assert_eq!(copy.limits.max_runtime_seconds, 1800);
        assert_eq!(grant.not_after - grant.issued_at, 1800);
        assert_eq!(grant.issued_at - grant.not_before, CLOCK_SKEW_SECONDS);

        let mut too_long = parse(&[]);
        too_long.max_runtime_secs = Some(DEFAULT_RUNTIME_SECONDS + 1);
        assert!(grant_for(
            &too_long,
            std::slice::from_ref(&source),
            id,
            "backup",
            "/backup"
        )
        .is_err());

        // Deletion authority must be stated; it is then capped by the entry
        // ceiling so the grant stays self-consistent.
        let unbounded = parse(&["--delete"]);
        assert!(grant_for(
            &unbounded,
            std::slice::from_ref(&source),
            id,
            "backup",
            "/backup"
        )
        .is_err());
        let mut bounded = parse(&["--delete", "--max-delete", "40"]);
        bounded.max_entries = Some(30);
        let grant = grant_for(
            &bounded,
            std::slice::from_ref(&source),
            id,
            "backup",
            "/backup",
        )
        .unwrap();
        let GrantOperationV1::Copy(copy) = &grant.operation;
        assert_eq!(
            copy.policy.deletion,
            DeletionPolicyV1::DeleteDestinationOnly
        );
        assert_eq!(copy.limits.max_deletions, 30);
        // A read-only run plans no deletion, so it needs no budget.
        let preview = parse(&["--delete", "--dry-run"]);
        let grant = grant_for(&preview, &[source], id, "backup", "/backup").unwrap();
        let GrantOperationV1::Copy(copy) = &grant.operation;
        assert_eq!(copy.policy.deletion, DeletionPolicyV1::Forbid);
    }

    #[test]
    fn signed_scopes_distinguish_named_children_from_directory_contents() {
        let id = EnrollmentId::random();
        let mut named_args =
            Args::try_parse_from(["syq rsync", "-r", "host-a:source", "host-b:/backup"]).unwrap();
        named_args.normalize();
        let named_source = Location::parse("host-a:source").unwrap();
        let named = grant_for(&named_args, &[named_source], id, "backup", "/backup").unwrap();
        let GrantOperationV1::Copy(named) = named.operation;
        assert_eq!(
            named.mutation_scopes,
            vec![
                MutationScopeV1 {
                    path: b"/backup".to_vec(),
                    descendants: false,
                },
                MutationScopeV1 {
                    path: b"/backup/source".to_vec(),
                    descendants: true,
                },
            ]
        );

        let mut contents_args =
            Args::try_parse_from(["syq rsync", "-r", "host-a:source/", "host-b:/backup"]).unwrap();
        contents_args.normalize();
        let contents_source = Location::parse("host-a:source/").unwrap();
        let contents =
            grant_for(&contents_args, &[contents_source], id, "backup", "/backup").unwrap();
        let GrantOperationV1::Copy(contents) = contents.operation;
        assert_eq!(
            contents.mutation_scopes,
            vec![MutationScopeV1 {
                path: b"/backup".to_vec(),
                descendants: true,
            }]
        );

        let mut nonrecursive_args =
            Args::try_parse_from(["syq rsync", "host-a:file", "host-b:/backup"]).unwrap();
        nonrecursive_args.normalize();
        let file = Location::parse("host-a:file").unwrap();
        let nonrecursive = grant_for(&nonrecursive_args, &[file], id, "backup", "/backup").unwrap();
        let GrantOperationV1::Copy(nonrecursive) = nonrecursive.operation;
        assert!(nonrecursive
            .mutation_scopes
            .iter()
            .all(|scope| !scope.descendants));

        let mut unsupported = nonrecursive_args;
        unsupported.min_size = Some("1".into());
        let file = Location::parse("host-a:file").unwrap();
        assert!(grant_for(&unsupported, &[file], id, "backup", "/backup").is_err());
    }

    #[test]
    fn rooted_scan_and_hash_never_follow_a_payload_symlink() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("root");
        let target = root.join("target");
        let outside = temporary.path().join("outside");
        fs::create_dir_all(&target).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(target.join("inside"), b"inside").unwrap();
        fs::write(outside.join("secret"), b"secret").unwrap();
        symlink(&outside, target.join("escape")).unwrap();
        let authority = test_authority(&root, DeletionPolicyV1::Forbid, 1024);

        let mut scan = Request::Scan {
            root: target.as_os_str().as_bytes().to_vec(),
            follow_root: false,
            ignore: Vec::new(),
            report_ignored: false,
            guard: None,
        };
        authority.authorize(&mut scan, true).unwrap();
        let Request::Scan {
            guard: Some(guard), ..
        } = scan
        else {
            panic!("authority did not install a scan guard")
        };
        let mut entries = Vec::new();
        crate::scan::scan_rooted(
            target.as_os_str().as_bytes(),
            false,
            &[],
            false,
            &guard,
            &mut |batch| {
                entries.extend(batch);
                Ok(())
            },
            &mut |_| Ok(()),
            &mut |_| {},
        )
        .unwrap();
        assert!(entries.iter().any(|entry| entry.path == b"inside"));
        assert!(entries
            .iter()
            .any(|entry| { entry.path == b"escape" && entry.kind == proto::Kind::Symlink }));
        assert!(!entries.iter().any(|entry| entry.path == b"escape/secret"));

        let response = crate::fsops::FsOps::new().handle(&Request::HashBlocks {
            path: target.join("escape").as_os_str().as_bytes().to_vec(),
            which: proto::Which::Final,
            partial_id: [0; 16],
            block: 4096,
            len: 1,
            guard: Some(guard),
        });
        assert!(matches!(response, proto::Response::Err(_)));
        assert_eq!(fs::metadata(outside.join("secret")).unwrap().len(), 6);
    }
}

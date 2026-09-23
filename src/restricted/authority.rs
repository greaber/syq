use super::*;

pub(super) struct AuthorityState {
    pub(super) paths: HashSet<Vec<u8>>,
    pub(super) receiver_modes: HashMap<Vec<u8>, ReceiverModeState>,
    /// Objects this grant created and the executor confirmed. The
    /// existing-object policy is about what existed before the transfer, so
    /// later operations on these are the transfer's own business.
    pub(super) created: HashSet<Vec<u8>>,
    /// Creations authorized but not yet confirmed or rolled back. They never
    /// grant the shortcut above: a second creation of the same path races at
    /// the kernel instead of trusting an outcome that has not happened yet.
    pub(super) provisional: HashSet<Vec<u8>>,
    /// Bytes each staged or in-place file may occupy on disk, keyed by the
    /// destination path and the partial this grant declared for it:
    /// preallocation and basis seeding are charged against the aggregate
    /// ceiling here, once per file at its largest declared size, and every
    /// write or publication must name a declared partial. Observation-only
    /// preparations own separate provisional holds so an older absent
    /// observation cannot roll back a newer preparation for the same key.
    pub(super) reserved: HashMap<(Vec<u8>, proto::CopyId), ByteReservation>,
    pub(super) reserved_bytes: u64,
    pub(super) next_reservation_hold: u64,
    pub(super) transferred_bytes: u64,
    pub(super) deletions: u64,
    pub(super) live_connections: u16,
    pub(super) tcp_listener_started: bool,
    /// What hostB will attest to in its receipt.
    /// Receipt records live in an anonymous spool; only mutation-relevant paths
    /// enter `touched`, never paths merely returned by a destination scan.
    pub(super) receipt_stream: Option<crate::receipt::ReceiptStreamWriter>,
    pub(super) touched: BTreeSet<Vec<u8>>,
    pub(super) file_lifecycles: HashMap<(Vec<u8>, proto::CopyId), FileLifecycle>,
    /// Requests authorized for execution whose outcome has not been settled
    /// yet, across every connection. The receipt waits for zero.
    pub(super) in_flight: u64,
    /// Set when the receipt is being issued: no new mutation is authorized
    /// from then on, so the receipt describes a final state.
    pub(super) receipt_closing: bool,
    pub(super) receipt_issued: bool,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum ReceiverModeState {
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
pub(super) struct ReservationHoldId(u64);

#[derive(Debug, Default)]
pub(super) struct ByteReservation {
    /// Capacity retained by a preparation that may have created, resized, or
    /// reused the write target.
    pub(super) retained: Option<u64>,
    /// Capacity provisionally held by observation-only preparations until
    /// their individual outcomes are settled.
    pub(super) observations: HashMap<ReservationHoldId, u64>,
}

impl ByteReservation {
    pub(super) fn effective_size(&self) -> Option<u64> {
        self.retained
            .into_iter()
            .chain(self.observations.values().copied())
            .max()
    }
}

impl ReceiverModeState {
    pub(super) fn carry_forward(self, observed: Self) -> Option<Self> {
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
pub(super) enum ReceiverModeKind {
    Directory,
    RegularFile,
    Other,
}

#[derive(Clone, Copy)]
pub(super) enum ReceiverModeTarget {
    AnyExisting,
    RegularFile,
}

#[derive(Clone, Copy)]
pub(super) struct ReceiverModeDecision {
    pub(super) mode: u32,
    pub(super) identity: Option<(u64, u64, i64, u32)>,
}

#[derive(Clone, Debug)]
pub(super) struct ReceiverControlPath {
    pub(super) path: Vec<u8>,
    pub(super) label: &'static str,
}

pub(super) fn path_is_at_or_below(path: &[u8], prefix: &[u8]) -> bool {
    path == prefix
        || (path.starts_with(prefix) && (prefix == b"/" || path.get(prefix.len()) == Some(&b'/')))
}

pub(super) fn paths_overlap(left: &[u8], right: &[u8]) -> bool {
    path_is_at_or_below(left, right) || path_is_at_or_below(right, left)
}

pub(super) fn reject_control_plane_path(
    path: &[u8],
    protected: &[ReceiverControlPath],
) -> Result<()> {
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

pub(super) fn reject_control_plane_scopes(
    copy: &CopyOperation,
    protected: &[ReceiverControlPath],
) -> Result<()> {
    for scope in &copy.mutation_scopes {
        reject_control_plane_path(&scope.path, protected)?;
    }
    Ok(())
}

#[cfg(not(test))]
pub(super) fn read_process_umask() -> u32 {
    // main captured the mask before any thread existed.
    crate::fsops::process_umask()
}

#[cfg(test)]
pub(super) fn read_process_umask() -> u32 {
    // Avoid changing the process-global umask while unit tests run in
    // parallel. Individual policy tests can override the stored value.
    0o022
}

/// Shared capability inherited by the authorized SSH control process and all
/// of its token-authenticated TCP workers. HostA may choose protocol messages,
/// but it cannot remove or replace this receiver-side authority.
pub(crate) struct RestrictedAuthority {
    pub(super) guard: ContainerGuard,
    pub(super) destination: Vec<u8>,
    pub(super) copy: CopyOperation,
    pub(super) filters: FilterPolicy,
    pub(super) filter_matcher: Option<ignore::gitignore::Gitignore>,
    pub(super) filter_roots: Vec<Vec<u8>>,
    pub(super) root_existence: RootExistence,
    pub(super) enrollment_id: EnrollmentId,
    pub(super) request_id: RequestId,
    pub(super) receipt_policy: crate::receipt::ReceiptPolicy,
    pub(super) grant_digest: [u8; 32],
    pub(super) receipt_key: PrivateKey,
    pub(super) file_data_limit: Option<crate::bwlimit::BandwidthLimit>,
    pub(super) receiver_umask: u32,
    pub(super) deadline: Instant,
    pub(super) control_open: AtomicBool,
    pub(super) state: Mutex<AuthorityState>,
    /// Signalled whenever an in-flight request settles.
    pub(super) settled: std::sync::Condvar,
    pub(super) tcp_congestion: Option<String>,
    pub(super) mapping: Option<Mutex<crate::mapping::Admission>>,
    pub(super) hashing: Option<crate::hashing::CopyHashing>,
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

    pub(super) fn expected_hash(&self, path: &[u8]) -> Result<Option<crate::hashing::Digest>> {
        if let Some(mapping) = &self.mapping {
            return Ok(mapping
                .lock()
                .unwrap()
                .expected_hash(self.mapping_relative(path)?)?
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
                    .and_then(|hashing| hashing.expected_hash.clone())
            })
            .flatten())
    }

    pub(super) fn new(
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
    pub(super) fn observe_final(&self, path: &[u8]) -> Result<Option<RootMetadata>> {
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
    pub(super) fn digest_published(&self, path: &[u8]) -> Result<[u8; 32]> {
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

    pub(super) fn read_published_link(&self, path: &[u8]) -> Result<Vec<u8>> {
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
    pub(super) fn check_root_existence(&self) -> Result<()> {
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

    pub(super) fn check_deadline(&self) -> Result<()> {
        if Instant::now() > self.deadline {
            bail!("signed transfer execution deadline has expired");
        }
        Ok(())
    }

    pub(super) fn validate_request_path(path: &[u8]) -> Result<()> {
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

    pub(super) fn scope_allows(scope: &MutationScope, path: &[u8]) -> bool {
        path == scope.path
            || (scope.descendants
                && path.starts_with(&scope.path)
                && path.get(scope.path.len()) == Some(&b'/'))
    }

    pub(super) fn filter_applies(&self, path: &[u8]) -> bool {
        self.filter_roots.iter().any(|root| {
            path == root || (path.starts_with(root) && path.get(root.len()) == Some(&b'/'))
        })
    }

    /// A mapped source root itself is never ignored. A destination path that
    /// can be supplied by several overlapping roots remains allowed when any
    /// one of those source-relative spellings is included.
    pub(super) fn path_is_ignored(&self, path: &[u8], is_dir: bool) -> bool {
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
    pub(super) fn reserve_bytes(
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
    pub(super) fn settle_observation_reservation(
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
    pub(super) fn declared_size(&self, path: &[u8], copy_id: proto::CopyId) -> Result<u64> {
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
    pub(super) fn check_published_length(
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

    pub(super) fn record_path(&self, path: &[u8]) -> Result<()> {
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

    pub(super) fn mapping_relative<'a>(&self, path: &'a [u8]) -> Result<&'a [u8]> {
        if path == self.destination {
            return Ok(b"");
        }
        path.strip_prefix(self.destination.as_slice())
            .and_then(|relative| relative.strip_prefix(b"/"))
            .context("mapping path is outside the destination")
    }

    pub(super) fn check_mapping_path(&self, path: &[u8], directory: Option<bool>) -> Result<()> {
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

    pub(super) fn mapping_parent(&self, path: &[u8]) -> Result<bool> {
        match &self.mapping {
            Some(mapping) => Ok(mapping
                .lock()
                .unwrap()
                .permissions()?
                .implicit_directory(self.mapping_relative(path)?)),
            None => Ok(false),
        }
    }

    pub(super) fn check_observation_path(&self, path: &[u8]) -> Result<()> {
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

    pub(super) fn check_mutation_authority(&self, path: &[u8]) -> Result<()> {
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

    pub(super) fn check_mutation_path(&self, path: &[u8], is_dir: bool) -> Result<()> {
        self.check_mutation_authority(path)?;
        self.check_mapping_path(path, Some(is_dir))?;
        if self.path_is_ignored(path, is_dir) {
            bail!("receiver mutation targets a path excluded by the signed filter policy");
        }
        self.record_path(path)
    }

    pub(super) fn created_by_this_grant(&self, path: &[u8]) -> bool {
        self.state.lock().unwrap().created.contains(path)
    }

    pub(super) fn receipt_location(&self, path: &[u8]) -> Option<(u32, Vec<u8>)> {
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

    pub(super) fn append_operation(
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

    pub(super) fn append_operation_to_stream(
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

    pub(super) fn forget_provisional(&self, pending: &[PendingCreation]) {
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
    pub(super) fn constrain_creation(
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

    pub(super) fn constrain_observed_creation(
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
    pub(super) fn constrain_update(
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
    pub(super) fn constrain_prepare(&self, path: &[u8]) -> Result<()> {
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

    pub(super) fn check_flags(&self, flags: u8) -> Result<()> {
        let known = proto::flags::MODE_MASK
            | proto::flags::OWNER
            | proto::flags::GROUP
            | proto::flags::TIMES
            | proto::flags::REQUIRE_OWNER
            | proto::flags::REQUIRE_GROUP;
        if flags & !known != 0 {
            bail!("request contains unknown metadata flags");
        }
        if (flags & proto::flags::REQUIRE_OWNER != 0 && flags & proto::flags::OWNER == 0)
            || (flags & proto::flags::REQUIRE_GROUP != 0 && flags & proto::flags::GROUP == 0)
        {
            bail!("required ownership flags need the corresponding ownership request");
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

    pub(super) fn rooted_metadata(&self, path: &[u8]) -> Result<Option<RootMetadata>> {
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

    pub(super) fn remember_receiver_creation(
        &self,
        path: &[u8],
        existing_directory_kept: bool,
    ) -> Result<()> {
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

    pub(super) fn remember_receiver_creation_observed(
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

    pub(super) fn receiver_mode(
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

    pub(super) fn select_receiver_mode(
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

    pub(super) fn constrain_receiver_mode(
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

    pub(super) fn apply_receiver_mode(
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

    pub(super) fn check_hash_request(&self, block: u64, len: u64) -> Result<()> {
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

    pub(super) fn charge_bytes(&self, path: &[u8], offset: u64, bytes: usize) -> Result<()> {
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

    pub(super) fn charge_deletion(&self, path: &[u8], is_dir: bool) -> Result<()> {
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

    pub(super) fn authorize_op(
        &self,
        operation: &mut Op,
        index: usize,
        pending: &mut Vec<PendingCreation>,
        outcomes: &mut Vec<PendingOutcome>,
        touched: &mut Vec<Vec<u8>>,
    ) -> Result<()> {
        if matches!(operation, Op::Hardlink { .. }) {
            bail!("hardlink creation is not authorized by the signed grant");
        }
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
            Op::Hardlink { .. } => unreachable!("hardlinks rejected above"),
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
        if self.expected_hash(path)?.is_some()
            && matches!(
                operation,
                Op::Mkdir { .. } | Op::Symlink { .. } | Op::Mknod { .. }
            )
        {
            bail!("expected hash requires a regular file");
        }
        match operation {
            Op::Hardlink { .. } => bail!("hardlink creation is not authorized by the signed grant"),
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

    pub(super) fn authorize_inner(
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
                if let Some(authorized) = self.expected_hash(path)? {
                    if *expected != crate::hashing::ExpectedHashes::Single(authorized) {
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
                expected_hash,
                path,
                meta,
                flags,
                condition,
                guard,
                ..
            } => {
                *expected_hash = self.expected_hash(path)?.map(Into::into);
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
                expected_hash,
                path,
                inplace,
                copy_id,
                meta,
                flags,
                condition,
                guard,
                ..
            } => {
                *expected_hash = self.expected_hash(path)?.map(Into::into);
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
                    if self.expected_hash(&put.path)?.is_some() {
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
            Request::DescriptorCopy(_) | Request::BindStream(_) => {
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
    pub(super) creations: Vec<PendingCreation>,
    pub(super) outcomes: Vec<PendingOutcome>,
    /// Final destination paths this admitted request could have changed.
    pub(super) touched: Vec<Vec<u8>>,
    /// The request counts as in flight until settled.
    pub(super) tracked: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FileStage {
    Prepare,
    Write,
    Finalize,
}

pub(super) fn kind_from_mode(mode: u32) -> proto::Kind {
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
pub(super) struct FileLifecycle {
    pub(super) size: u64,
    pub(super) inplace: bool,
    pub(super) recorded: bool,
    pub(super) last_error: Option<String>,
}

/// One receipt-relevant effect of a request, confirmed by `settle`.
#[derive(Debug)]
pub(super) enum PendingOutcome {
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
    pub(super) index: usize,
    pub(super) path: Vec<u8>,
    pub(super) persist: bool,
}

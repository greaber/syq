use super::*;
use crate::destination_results::{Change, Failure};

pub(super) struct AuthorityState {
    /// Objects this grant created and the executor confirmed. The
    /// existing-object policy is about what existed before the transfer, so
    /// later operations on these are the transfer's own business.
    pub(super) created: HashSet<Vec<u8>>,
    /// Creations authorized but not yet confirmed or rolled back. They never
    /// grant the shortcut above: a second creation of the same path races at
    /// the kernel instead of trusting an outcome that has not happened yet.
    pub(super) provisional: HashSet<Vec<u8>>,
    /// Bytes each staged, in-place or patched file this copy is writing
    /// may occupy on disk, keyed by the destination path and the partial
    /// this grant declared for it: preallocation and basis seeding are
    /// charged against the aggregate ceiling here, once per file at its
    /// largest declared size, while the file is in flight. A published file
    /// leaves the map and its bytes stay counted. Observation-only
    /// preparations own separate provisional holds so an older absent
    /// observation cannot roll back a newer preparation for the same key.
    pub(super) reserved: HashMap<(Vec<u8>, proto::CopyId), ByteReservation>,
    pub(super) reserved_bytes: u64,
    pub(super) next_reservation_hold: u64,
    pub(super) next_reservation_instance: u64,
    pub(super) live_connections: u16,
    pub(super) tcp_listener_started: bool,
    /// Files this grant's results stream is writing that have not been
    /// published yet: reported as unfinished if the copy ends without them.
    pub(super) file_lifecycles: HashMap<(Vec<u8>, proto::CopyId), FileLifecycle>,
    /// Requests authorized for execution whose outcome has not been settled
    /// yet, across every connection. The results' end waits for zero.
    pub(super) in_flight: u64,
    /// Set when the results end: no new change is authorized from then on,
    /// so they describe every change the grant made.
    pub(super) results_closing: bool,
    /// A change was attempted or a request refused. Results must start
    /// before either, so that they leave nothing out.
    pub(super) recorded_any: bool,
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
    /// The file counts against the entry limit (`charge_request`), and
    /// how many requests still to settle share that count.
    pub(super) entry: Option<EntryCharge>,
    /// Which reservation of its key this is: one settled away and made
    /// again for the same file and partial is another, which a request
    /// that held a share of the first must not touch.
    pub(super) instance: u64,
}

/// One file's count against the entry limit, which every request that may
/// create or open it for writing shares: it is given back only once all of
/// them have settled and none changed anything.
#[derive(Debug, Default)]
pub(super) struct EntryCharge {
    /// Requests that rely on the count and have not settled.
    holders: usize,
    /// One of them reported a change.
    made: bool,
}

impl ByteReservation {
    pub(super) fn effective_size(&self) -> Option<u64> {
        self.retained
            .into_iter()
            .chain(self.observations.values().copied())
            .max()
    }
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

pub(super) fn reject_control_plane_path(
    path: &[u8],
    protected: &[ReceiverControlPath],
) -> Result<()> {
    for control in protected {
        if path_is_at_or_below(path, &control.path) {
            return Err(inside_protected(Some(path), control));
        }
        if path_is_at_or_below(&control.path, path) {
            return Err(holds_protected(Some(path), control));
        }
    }
    Ok(())
}

/// A destination that is one of the receiver's protected paths, or lies
/// inside one.
pub(super) fn inside_protected(
    destination: Option<&[u8]>,
    control: &ReceiverControlPath,
) -> anyhow::Error {
    anyhow!(
        "command-restricted destination {}is the receiver's protected {} {} or lies inside it; choose another destination",
        destination.map_or(String::new(), |path| format!(
            "{} ",
            Path::new(OsStr::from_bytes(path)).display()
        )),
        control.label,
        Path::new(OsStr::from_bytes(&control.path)).display()
    )
}

/// A destination whose contents the copy may change, holding one of the
/// receiver's protected paths: the copy could write into it or delete it.
/// A subdirectory of the destination holds none.
pub(super) fn holds_protected(
    destination: Option<&[u8]>,
    control: &ReceiverControlPath,
) -> anyhow::Error {
    let destination = destination.map_or_else(
        || "the destination".to_owned(),
        |path| Path::new(OsStr::from_bytes(path)).display().to_string(),
    );
    anyhow!(
        "command-restricted destination {destination} holds the receiver's protected {} {}, which this copy could change; copy into a subdirectory of {destination} instead",
        control.label,
        Path::new(OsStr::from_bytes(&control.path)).display()
    )
}

/// Most symlinks `resolve_destination_links` follows, as the kernel bounds
/// a path lookup.
const MAX_DESTINATION_LINKS: usize = 40;

/// Where `resolve_destination_links` found a destination reached through
/// symlinks.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct ResolvedDestination {
    /// The deepest existing directory on the resolved path, relative to the
    /// confinement root, as components.
    pub(super) existing: Vec<Vec<u8>>,
    /// How many of the signed destination's components lead to `existing`:
    /// the rest do not exist yet, and the copy creates them inside it.
    pub(super) signed_components: usize,
}

/// Resolve the symlinks on the way to `destination`, a path relative to
/// `root` (named `root_path`), inside the root: `None` when no component is
/// a symlink. Components of the destination itself that do not exist yet
/// are left for the copy to create; a symlink that leads outside the root,
/// or to a name that does not exist, is refused.
pub(super) fn resolve_destination_links(
    root: &Root,
    root_path: &[u8],
    destination: &[u8],
) -> Result<Option<ResolvedDestination>> {
    let components = |path: &[u8]| -> Vec<Vec<u8>> {
        path.split(|byte| *byte == b'/')
            .filter(|component| !component.is_empty())
            .map(<[u8]>::to_vec)
            .collect()
    };
    let label = |path: &[Vec<u8>]| String::from_utf8_lossy(&path.join(&b'/')).into_owned();
    // Each pending component, with the index of the destination component
    // it is, or the link whose target it comes from.
    enum Origin {
        Destination(usize),
        Link(String, Vec<u8>),
    }
    let mut pending: std::collections::VecDeque<(Vec<u8>, Origin)> = components(destination)
        .into_iter()
        .enumerate()
        .map(|(index, component)| (component, Origin::Destination(index)))
        .collect();
    let signed_total = pending.len();
    let mut resolved: Vec<Vec<u8>> = Vec::new();
    let mut links = 0;
    while let Some((component, origin)) = pending.pop_front() {
        match component.as_slice() {
            b"." => continue,
            b".." => {
                if resolved.pop().is_none() {
                    bail!(
                        "a destination symlink leads outside the directory the destination is in"
                    );
                }
                continue;
            }
            _ => {}
        }
        resolved.push(component);
        let path = crate::rooted::RelativePath::new(&resolved.join(&b'/'))?;
        let Some(metadata) = root.metadata_optional(&path)? else {
            resolved.pop();
            return match origin {
                // The rest of the destination is missing too: the copy
                // creates it inside the directory found so far.
                Origin::Destination(index) => Ok((links > 0).then_some(ResolvedDestination {
                    existing: resolved,
                    signed_components: index,
                })),
                Origin::Link(link, target) => bail!(
                    "the destination symlink {link} leads to {}, which does not exist",
                    String::from_utf8_lossy(&target)
                ),
            };
        };
        if !metadata.is_symlink() {
            continue;
        }
        links += 1;
        if links > MAX_DESTINATION_LINKS {
            bail!("too many symlinks on the way to the destination");
        }
        let target = root.read_link(&path)?;
        let link = label(&resolved);
        resolved.pop();
        let rest = if target.starts_with(b"/") {
            let inside =
                crate::fsops::destination_relative_to(root_path, &target).with_context(|| {
                    format!(
                        "the destination symlink {link} leads outside the directory the destination is in"
                    )
                })?;
            resolved.clear();
            inside
        } else {
            target.clone()
        };
        for component in components(&rest).into_iter().rev() {
            pending.push_front((component, Origin::Link(link.clone(), target.clone())));
        }
    }
    Ok((links > 0).then_some(ResolvedDestination {
        existing: resolved,
        signed_components: signed_total,
    }))
}

/// Refuse a destination whose directory is, contains or lies inside one of
/// the receiver's protected control paths, judged by identity: `existing`
/// is the deepest existing directory of the destination, relative to
/// `root`, and `whole` says whether it is the destination itself rather
/// than one the copy creates the destination inside. Names a path is
/// spelled with, through symlinks or a root of `/`, do not matter, and a
/// control path that is a symlink is judged where it really is. A control
/// path that does not exist yet is protected by its ancestors: a
/// destination that contains where it would be is refused.
pub(super) fn reject_control_plane_directory(
    root: &Root,
    existing: &[Vec<u8>],
    whole: bool,
    protected: &[ReceiverControlPath],
) -> Result<()> {
    // The identities from the root down to the directory.
    let mut chain = Vec::with_capacity(existing.len() + 1);
    for depth in 0..=existing.len() {
        let relative = crate::rooted::RelativePath::new(&existing[..depth].join(&b'/'))?;
        let directory = root.open_directory(&relative)?;
        let metadata = directory.metadata()?;
        chain.push((metadata.dev(), metadata.ino()));
    }
    let destination = *chain.last().expect("the root is always in the chain");
    for control in protected {
        let control_path = Path::new(OsStr::from_bytes(&control.path));
        // The destination is the control path or lies beneath it.
        let inside = fs::metadata(control_path)
            .is_ok_and(|metadata| chain.contains(&(metadata.dev(), metadata.ino())));
        // The destination is the control path or one of its ancestors,
        // spelled as configured or where the path really is.
        let real = real_location(control_path);
        let contains = whole
            && control_path
                .ancestors()
                .chain(real.iter().flat_map(|real| real.ancestors()))
                .any(|ancestor| {
                    fs::metadata(ancestor)
                        .is_ok_and(|metadata| (metadata.dev(), metadata.ino()) == destination)
                });
        if inside {
            return Err(inside_protected(None, control));
        }
        if contains {
            return Err(holds_protected(None, control));
        }
    }
    Ok(())
}

/// Where `path` really is: its deepest existing ancestor with every symlink
/// resolved, and the rest of it as spelled.
fn real_location(path: &Path) -> Option<std::path::PathBuf> {
    let mut missing = Vec::new();
    let mut existing = path;
    loop {
        if let Ok(real) = fs::canonicalize(existing) {
            return Some(
                missing
                    .iter()
                    .rev()
                    .fold(real, |path, name| path.join(name)),
            );
        }
        missing.push(existing.file_name()?);
        existing = existing.parent()?;
    }
}

/// The deepest existing directory of `destination` beneath `root`,
/// following no symlink, and whether it is the destination itself.
fn existing_directory_components(root: &Root, destination: &[u8]) -> Result<(Vec<Vec<u8>>, bool)> {
    let mut existing = Vec::new();
    for component in destination
        .split(|byte| *byte == b'/')
        .filter(|c| !c.is_empty())
    {
        existing.push(component.to_vec());
        let relative = crate::rooted::RelativePath::new(&existing.join(&b'/'))?;
        match root.metadata_optional(&relative)? {
            Some(metadata) if metadata.is_dir() => {}
            Some(_) => bail!("not a directory"),
            None => {
                existing.pop();
                return Ok((existing, false));
            }
        }
    }
    Ok((existing, true))
}

/// Refuse a path the copy may change when it is a protected path or lies
/// beneath one, or, when the copy may also change what is beneath it
/// (`descendants`), when a protected path lies beneath it.
pub(super) fn reject_control_plane_scope(
    path: &[u8],
    descendants: bool,
    protected: &[ReceiverControlPath],
) -> Result<()> {
    if descendants {
        return reject_control_plane_path(path, protected);
    }
    if let Some(control) = protected
        .iter()
        .find(|control| path_is_at_or_below(path, &control.path))
    {
        return Err(inside_protected(Some(path), control));
    }
    Ok(())
}

pub(super) fn reject_control_plane_scopes(
    copy: &CopyOperation,
    protected: &[ReceiverControlPath],
) -> Result<()> {
    for scope in &copy.mutation_scopes {
        reject_control_plane_scope(&scope.path, scope.descendants, protected)?;
    }
    Ok(())
}

/// Whether the copy may change what lies beneath its destination, rather
/// than only the destination directory itself.
fn destination_has_descendants(copy: &CopyOperation) -> bool {
    copy.mutation_scopes
        .iter()
        .any(|scope| scope.path == copy.destination && scope.descendants)
}

/// The directory a copy's destination is in, resolved and opened when the
/// copy starts and held for the whole copy. No device or inode outlives the
/// session: a remount between copies changes nothing.
pub(crate) struct ConfinedRoot {
    root: Root,
    /// The path requests name the directory by: the signed destination's
    /// parent.
    named: Vec<u8>,
    /// Where the directory really is.
    real: Vec<u8>,
}

impl ConfinedRoot {
    /// The signed destination's directory as the account itself resolves it
    /// now, refused when it is, or is inside, a protected path, by name or
    /// by identity.
    pub(super) fn resolve(destination: &[u8], protected: &[ReceiverControlPath]) -> Result<Self> {
        let destination = Path::new(OsStr::from_bytes(destination));
        let parent = requested_parent(destination);
        let real = fs::canonicalize(parent).with_context(|| {
            format!(
                "resolve the directory {} the destination goes in",
                parent.display()
            )
        })?;
        // Only being a protected path or inside one matters here: the copy
        // writes beneath its destination, whose own check is in `new`.
        if let Some(control) = protected
            .iter()
            .find(|control| path_is_at_or_below(real.as_os_str().as_bytes(), &control.path))
        {
            return Err(inside_protected(None, control));
        }
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOCTTY | libc::O_CLOEXEC)
            .open(&real)
            .with_context(|| format!("open the destination's directory {}", real.display()))?;
        reject_protected_ancestry(&directory, &real, protected)?;
        Ok(Self {
            root: Root::from_directory(directory)?,
            named: parent.as_os_str().as_bytes().to_vec(),
            real: real.as_os_str().as_bytes().to_vec(),
        })
    }

    #[cfg(test)]
    pub(super) fn identity(&self) -> RootIdentity {
        self.root.identity()
    }

    /// A directory this session already chose and checked, such as a
    /// receiving machine's container.
    pub(super) fn opened(path: &Path, expected: RootIdentity) -> Result<Self> {
        Ok(Self {
            root: Root::open_verified(path, expected)?,
            named: path.as_os_str().as_bytes().to_vec(),
            real: path.as_os_str().as_bytes().to_vec(),
        })
    }
}

/// Refuse a directory that is a protected path or lies anywhere beneath
/// one, by the identities of the directory, as opened, and of each directory
/// above its real path, as the session finds them. Looking at the
/// directories above needs no search permission on the directory itself.
fn reject_protected_ancestry(
    directory: &File,
    real: &Path,
    protected: &[ReceiverControlPath],
) -> Result<()> {
    let identities: Vec<_> = protected
        .iter()
        .filter_map(|control| {
            fs::metadata(Path::new(OsStr::from_bytes(&control.path)))
                .ok()
                .map(|metadata| ((metadata.dev(), metadata.ino()), control))
        })
        .collect();
    let opened = directory.metadata()?;
    let opened = (opened.dev(), opened.ino());
    let named = fs::metadata(real)
        .with_context(|| format!("inspect the destination's directory {}", real.display()))?;
    if (named.dev(), named.ino()) != opened {
        bail!(
            "the destination's directory {} changed while it was opened",
            real.display()
        );
    }
    let mut ancestors = vec![opened];
    for ancestor in real.ancestors().skip(1) {
        let metadata =
            fs::metadata(ancestor).with_context(|| format!("inspect {}", ancestor.display()))?;
        ancestors.push((metadata.dev(), metadata.ino()));
    }
    if let Some((_, control)) = identities
        .iter()
        .find(|(identity, _)| ancestors.contains(identity))
    {
        return Err(inside_protected(None, control));
    }
    Ok(())
}

/// Shared capability inherited by the authorized SSH control process and all
/// of its token-authenticated TCP workers. HostA may choose protocol messages,
/// but it cannot remove or replace this receiver-side authority.
pub(crate) struct RestrictedAuthority {
    /// The confinement root (or a receiving machine's container), opened once
    /// and verified by identity when the grant is redeemed. Every
    /// connection of the copy uses it as its destination root, and every
    /// lookup here resolves beneath it.
    pub(super) root: std::sync::Arc<Root>,
    /// The path requests name `root` by.
    pub(super) root_path: Vec<u8>,
    pub(super) destination: Vec<u8>,
    pub(super) copy: CopyOperation,
    pub(super) filters: FilterPolicy,
    pub(super) filter_matcher: Option<ignore::gitignore::Gitignore>,
    pub(super) filter_roots: Vec<Vec<u8>>,
    pub(super) root_existence: RootExistence,
    pub(super) enrollment_id: EnrollmentId,
    pub(super) request_id: RequestId,
    pub(super) receipt_policy: crate::destination_results::ReceiptPolicy,
    pub(super) grant_digest: [u8; 32],
    /// Signs the header of this grant's results for the invoking machine.
    pub(super) results_key: PrivateKey,
    /// The results for the invoking machine, once the coordinator starts
    /// them. Locked after `state` when both are held.
    pub(super) results: Mutex<Option<crate::destination_results::Stream>>,
    pub(super) results_started: AtomicBool,
    pub(super) file_data_limit: Option<crate::bwlimit::BandwidthLimit>,
    pub(super) deadline: Instant,
    pub(super) control_open: AtomicBool,
    /// Changes authorized so far, against the signed entry limit: each
    /// creation, publication, link, metadata change and deletion counts
    /// each time it is made. Lookups count nothing.
    pub(super) changes: std::sync::atomic::AtomicU64,
    /// File bytes received so far, against the signed byte limit.
    pub(super) transferred_bytes: std::sync::atomic::AtomicU64,
    /// Deletions authorized so far, against the signed deletion limit.
    pub(super) deletions: std::sync::atomic::AtomicU64,
    pub(super) state: Mutex<AuthorityState>,
    /// Signalled whenever an in-flight request settles.
    pub(super) settled: std::sync::Condvar,
    pub(super) tcp_congestion: Option<String>,
    pub(super) mapping: Option<Mutex<crate::mapping::Admission>>,
    pub(super) hashing: Option<crate::hashing::CopyHashing>,
    pub(super) extra_options: crate::delegation::ExtraCopyOptions,
    /// The files this receiver created for the grant, shared with every
    /// connection's operations.
    pub(super) owned: std::sync::Arc<crate::fsops::owned::OwnedObjects>,
    /// The scope of the files this copy is writing, which the receiver holds
    /// open until the copy's control connection ends.
    pub(super) stage_scope: u64,
    /// What this receiver's own lookups for the planner found, where
    /// they let a file's publication be held to the grant without looking
    /// again (`constrain_publication`): keeping existing files, or
    /// replacing only existing ones.
    pub(super) lookups: Option<std::sync::Arc<crate::fsops::lookups::PlanningLookups>>,
}

impl RestrictedAuthority {
    /// The files that may take new names by hard link, when the grant keeps
    /// existing objects and copies hard links: those this receiver created
    /// for the grant. Without hard links nothing is recorded.
    pub(crate) fn owned_objects(
        &self,
    ) -> Option<std::sync::Arc<crate::fsops::owned::OwnedObjects>> {
        (self.creation_policy(false) == ExistingDestinationPolicy::Skip
            && self.extra_options.hardlinks)
            .then(|| self.owned.clone())
    }

    /// The scope of the files this copy is writing (`FsOps::set_stage_scope`).
    pub(crate) fn stage_scope(&self) -> u64 {
        self.stage_scope
    }

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
        confined: ConfinedRoot,
        grant: Grant,
        extensions: GrantConstraints,
        grant_digest: [u8; 32],
        results_key: PrivateKey,
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
            extra_options,
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
        let filter_matcher = crate::scan::build_ignore(&filters.ignore)?;
        let filter_roots = filters.destination_roots.clone();
        let root_path = Path::new(std::ffi::OsStr::from_bytes(&confined.named));
        let destination = Path::new(std::ffi::OsStr::from_bytes(&copy.destination));
        let relative = destination.strip_prefix(root_path).with_context(|| {
            format!(
                "signed destination {} is outside the directory {} it was resolved in",
                destination.display(),
                root_path.display()
            )
        })?;
        if relative.as_os_str().is_empty() {
            bail!("signed destination must be a child of its directory");
        }
        crate::rooted::RelativePath::new(relative.as_os_str().as_bytes())?;
        let relative = relative.as_os_str().as_bytes();
        // Where the destination really is, by name, beside the checks of the
        // names the grant uses and of identities below.
        let descendants = destination_has_descendants(&copy);
        reject_control_plane_scope(
            &crate::fsops::join(&confined.real, relative),
            descendants,
            protected,
        )?;
        let real_root = confined.real.clone();
        let mut held_path = confined.named.clone();
        let mut root = std::sync::Arc::new(confined.root);
        // `--follow-dst`: a destination reached through symlinks is the
        // directory they resolve to inside the confinement root. That
        // directory, or the deepest existing one the copy creates the rest
        // of the destination inside, is the root every connection works
        // beneath, named in requests by the matching part of the signed
        // destination, so nothing reaches past it.
        let followed = if extra_options.follow_dst
            && copy.policy.placement != DestinationPlacement::ExactPath
        {
            // An absolute link target names where the directory really
            // is, whatever name the grant uses for it.
            resolve_destination_links(&root, &real_root, relative)?
        } else {
            None
        };
        if let Some(found) = followed {
            let signed: Vec<&[u8]> = relative
                .split(|byte| *byte == b'/')
                .filter(|component| !component.is_empty())
                .collect();
            let whole = found.signed_components == signed.len();
            if whole && found.existing.is_empty() {
                bail!("signed destination resolves to the directory it is in");
            }
            // The path the links resolve to, with the directories the copy
            // creates, by its names as well as by identity: a control
            // directory that does not exist yet has no identity.
            let resolved = signed[found.signed_components..].iter().fold(
                crate::fsops::join(&real_root, &found.existing.join(&b'/')),
                |path, component| crate::fsops::join(&path, component),
            );
            reject_control_plane_scope(&resolved, descendants, protected)?;
            reject_control_plane_directory(
                &root,
                &found.existing,
                whole && descendants,
                protected,
            )?;
            let directory = root
                .open_directory(&crate::rooted::RelativePath::new(
                    &found.existing.join(&b'/'),
                )?)
                .with_context(|| {
                    format!(
                        "signed destination {} resolves to {}, which is not a directory",
                        destination.display(),
                        String::from_utf8_lossy(&found.existing.join(&b'/'))
                    )
                })?;
            root = std::sync::Arc::new(Root::from_directory(directory)?);
            held_path =
                crate::fsops::join(&held_path, &signed[..found.signed_components].join(&b'/'));
        } else if let Ok(found) = existing_directory_components(&root, relative) {
            // The destination's directory as it stands, judged by identity
            // too: a name the strings above miss cannot reach the control
            // plane either.
            reject_control_plane_directory(&root, &found.0, found.1 && descendants, protected)?;
        }
        let file_data_limit = (max_file_data_bytes_per_second > 0)
            .then(|| crate::bwlimit::BandwidthLimit::new(max_file_data_bytes_per_second));
        receipt_policy.validate()?;
        let mut authority = Self {
            hashing,
            extra_options,
            owned: Default::default(),
            stage_scope: crate::fsops::new_stage_scope(),
            tcp_congestion,
            mapping: mapping.map(|authorization| {
                Mutex::new(crate::mapping::Admission::new(
                    authorization,
                    copy.limits.max_entries,
                ))
            }),
            root,
            root_path: held_path,
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
            results_key,
            results: Mutex::new(None),
            results_started: AtomicBool::new(false),
            file_data_limit,
            deadline,
            control_open: AtomicBool::new(true),
            settled: std::sync::Condvar::new(),
            changes: Default::default(),
            transferred_bytes: Default::default(),
            deletions: Default::default(),
            state: Mutex::new(AuthorityState {
                created: HashSet::new(),
                provisional: HashSet::new(),
                reserved: HashMap::new(),
                reserved_bytes: 0,
                next_reservation_hold: 0,
                next_reservation_instance: 0,
                live_connections: 0,
                tcp_listener_started: false,
                file_lifecycles: HashMap::new(),
                in_flight: 0,
                results_closing: false,
                recorded_any: false,
            }),
            lookups: None,
        };
        authority.lookups = match authority.creation_policy(false) {
            ExistingDestinationPolicy::Skip => Some(crate::fsops::lookups::Recording::Keep),
            ExistingDestinationPolicy::MustExist => {
                Some(crate::fsops::lookups::Recording::Existing)
            }
            _ => None,
        }
        .map(|recording| {
            std::sync::Arc::new(crate::fsops::lookups::PlanningLookups::new(recording))
        });
        authority.check_root_existence()?;
        Ok(authority)
    }

    /// Start this grant's results for the invoking machine. Nothing may have
    /// changed yet: results that start late could leave changes out.
    pub(crate) fn start_results(&self, records: bool) -> Result<()> {
        let state = self.state.lock().unwrap();
        anyhow::ensure!(
            !state.recorded_any && !state.results_closing,
            "destination results must start before any change"
        );
        let mut results = self.results.lock().unwrap();
        anyhow::ensure!(
            results.is_none(),
            "destination results have already started"
        );
        *results = Some(crate::destination_results::Stream::start(
            &self.receipt_policy,
            crate::destination_results::Binding {
                enrollment_id: self.enrollment_id,
                request_id: self.request_id,
                grant_digest: self.grant_digest,
            },
            &self.results_key,
            records,
        )?);
        self.results_started.store(true, Ordering::Release);
        Ok(())
    }

    /// End this grant's results and its authority to change anything: once
    /// every request already authorized on any connection has settled,
    /// report the files left unfinished and the end frame.
    pub(crate) fn finish_results(&self) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        anyhow::ensure!(
            self.results_started.load(Ordering::Acquire),
            "destination results were not started"
        );
        anyhow::ensure!(
            !state.results_closing,
            "destination results have already ended"
        );
        state.results_closing = true;
        while state.in_flight > 0 {
            let remaining = self
                .deadline
                .checked_duration_since(Instant::now())
                .unwrap_or_default();
            if remaining.is_zero() {
                bail!(
                    "{} request(s) were still in flight at the grant deadline; the destination's results cannot end",
                    state.in_flight
                );
            }
            state = self.settled.wait_timeout(state, remaining).unwrap().0;
        }
        let unfinished = std::mem::take(&mut state.file_lifecycles);
        let transferred_bytes = self.transferred_bytes.load(Ordering::Acquire);
        let mut results = self.results.lock().unwrap();
        let stream = results
            .as_mut()
            .context("destination results are unavailable")?;
        for ((path, _), lifecycle) in unfinished {
            if lifecycle.listed {
                continue;
            }
            stream.record(
                crate::destination_results::Change::PublishFile {
                    size: lifecycle.size,
                },
                self.result_path(&path, false).as_deref(),
                Some(Failure {
                    message: lifecycle
                        .last_error
                        .as_deref()
                        .unwrap_or("the file was not finished"),
                    class: lifecycle.last_class,
                }),
            );
        }
        stream.finish(transferred_bytes)?;
        Ok(())
    }

    /// Results frames ready to go out on the connection about to respond.
    pub(crate) fn take_results_frames(&self) -> Vec<Vec<u8>> {
        if !self.results_started.load(Ordering::Acquire) {
            return Vec::new();
        }
        let mut results = self.results.lock().unwrap();
        let Some(stream) = results.as_mut() else {
            return Vec::new();
        };
        if !stream.due(Instant::now()) {
            return Vec::new();
        }
        // A frame that cannot be encoded leaves a gap the invoking machine
        // reports; the copy itself goes on.
        stream.take_frames(Instant::now()).unwrap_or_default()
    }

    /// Check the signed placement-root precondition once, against the
    /// confinement root, before any request is served. `New` is then kept true
    /// by `constrain_creation`, which forces no-replace creation of the root.
    pub(super) fn check_root_existence(&self) -> Result<()> {
        // Either answer will do, so nothing is looked up: the destination
        // may lie in a root only an approved `all` lets the copy search.
        if self.root_existence == RootExistence::Any {
            return Ok(());
        }
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

    /// Requests authorized and not yet settled, for other modules' tests.
    #[cfg(test)]
    pub(crate) fn in_flight(&self) -> u64 {
        self.state.lock().unwrap().in_flight
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
        let AuthorityState {
            reserved,
            next_reservation_instance,
            ..
        } = &mut *state;
        let reservation = reserved.entry(key).or_insert_with(|| {
            *next_reservation_instance += 1;
            ByteReservation {
                instance: *next_reservation_instance,
                ..Default::default()
            }
        });
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
        self.check_mapping_path(path, None)
    }

    /// The directory the copy goes into without filling it, which only an
    /// approved `all` widens: the destination of named sources, or the
    /// directory an exact target is in. The signed destination lies beneath
    /// the confinement root, so this is the root or a directory inside it, never
    /// one above it.
    fn outer_directory(&self) -> Option<Vec<u8>> {
        match self.copy.policy.placement {
            DestinationPlacement::DirectoryAsChild => Some(self.destination.clone()),
            DestinationPlacement::ExactPath => {
                let end = self.destination.iter().rposition(|&byte| byte == b'/')?;
                Some(if end == 0 {
                    b"/".to_vec()
                } else {
                    self.destination[..end].to_vec()
                })
            }
            DestinationPlacement::DirectoryContents => None,
        }
    }

    /// Pin the directory the copy goes into as this authority finds it now,
    /// beneath the confinement root; the sender cannot observe it.
    fn outer_directory_condition(
        &self,
        path: &[u8],
        condition: proto::TargetCondition,
    ) -> Result<proto::TargetCondition> {
        let metadata = self
            .rooted_metadata(path)?
            .context("the directory the copy goes into does not exist")?;
        anyhow::ensure!(
            metadata.is_dir(),
            "the directory the copy goes into is not a directory"
        );
        match condition {
            proto::TargetCondition::Any => {}
            proto::TargetCondition::Matches { dev, ino }
            | proto::TargetCondition::MatchesFingerprint { dev, ino, .. } => anyhow::ensure!(
                (dev, ino) == (metadata.dev, metadata.ino),
                "the directory the copy goes into changed"
            ),
            proto::TargetCondition::Absent => {
                bail!("temporary directory access requires an existing directory")
            }
        }
        Ok(proto::TargetCondition::Matches {
            dev: metadata.dev,
            ino: metadata.ino,
        })
    }

    /// Whether the grant allows changes at all now: not a read-only one, and
    /// not after its results ended.
    fn check_mutation_allowed(&self) -> Result<()> {
        if self.copy.options.dry_run || self.copy.options.verify_only {
            bail!("signed read-only transfer forbids destination mutations");
        }
        if self.state.lock().unwrap().results_closing {
            bail!("the signed grant is closed: its results have ended");
        }
        Ok(())
    }

    pub(super) fn check_mutation_authority(&self, path: &[u8]) -> Result<()> {
        self.check_mutation_allowed()?;
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
        Ok(())
    }

    pub(super) fn created_by_this_grant(&self, path: &[u8]) -> bool {
        self.state.lock().unwrap().created.contains(path)
    }

    /// A changed path as ordinary results name it: relative to the signed
    /// destination. Paths above it, and the directory a copy goes into, are
    /// counted but not listed, as an ordinary copy lists them.
    pub(super) fn result_path(&self, path: &[u8], directory: bool) -> Option<Vec<u8>> {
        if path == self.destination {
            return (!directory).then(Vec::new);
        }
        path.strip_prefix(self.destination.as_slice())
            .and_then(|rest| rest.strip_prefix(b"/"))
            .map(<[u8]>::to_vec)
    }

    /// Add one settled change to the results, if they have started.
    pub(super) fn record_change(&self, path: &[u8], change: Change, error: Option<Failure<'_>>) {
        if !self.results_started.load(Ordering::Acquire) {
            return;
        }
        // As an ordinary copy counts them, the directory a copy goes into is
        // not one of the directories it created.
        if change == Change::EnsureDirectory
            && error.is_none()
            && path == self.destination
            && self.copy.policy.placement != DestinationPlacement::ExactPath
        {
            return;
        }
        // A failure is listed even at the destination itself.
        let directory =
            error.is_none() && matches!(change, Change::EnsureDirectory | Change::DeleteDirectory);
        let dst = self.result_path(path, directory);
        if let Some(stream) = self.results.lock().unwrap().as_mut() {
            stream.record(change, dst.as_deref(), error);
        }
    }

    /// Hold the failure of a change the sender tries again until a later
    /// change to the same file settles it (`destination_results::Stream::
    /// record_retried`).
    fn record_retried(&self, path: &[u8], change: Change, error: Failure<'_>) {
        if !self.results_started.load(Ordering::Acquire) {
            return;
        }
        let dst = self.result_path(path, false);
        if let Some(stream) = self.results.lock().unwrap().as_mut() {
            stream.record_retried(change, dst.as_deref(), error);
        }
    }

    /// A refused request for a file being written lists that file as
    /// failed; it is not listed again as unfinished when the results end.
    /// A later publication still reports it. A file not being written has
    /// nothing to mark, and a refusal adds nothing that lasts.
    fn end_refused_lifecycles(&self, state: &mut AuthorityState, request: &Request) {
        let Some(key) = file_key(request) else {
            return;
        };
        if let Some(lifecycle) = state.file_lifecycles.get_mut(&key) {
            lifecycle.listed = true;
        }
    }

    /// The changes a request asked for, by destination path where a record
    /// could name one, for the results to list when it is refused.
    fn requested_changes(&self, request: &Request) -> Vec<(Option<Vec<u8>>, Change)> {
        let file =
            |path: &[u8], size: u64| (self.result_path(path, false), Change::PublishFile { size });
        match request {
            Request::Apply { ops, .. } => ops
                .iter()
                .map(|op| {
                    let (path, change) = match op {
                        Op::Mkdir { path, .. } => (path, Change::EnsureDirectory),
                        Op::Symlink { path, .. } => (path, Change::CreateSymlink),
                        Op::Mknod { path, .. } => (path, Change::CreateSpecial),
                        Op::Hardlink { path, .. } => (path, Change::LinkFile),
                        Op::Rmdir { path } => (path, Change::DeleteDirectory),
                        Op::Unlink { path } | Op::Remove { path } => {
                            (path, Change::DeleteNonDirectory)
                        }
                        Op::SetMeta { path, .. } => (
                            path,
                            Change::SetMetadata {
                                kind: self
                                    .rooted_metadata(path)
                                    .ok()
                                    .flatten()
                                    .map_or(proto::Kind::File, |metadata| {
                                        kind_from_mode(metadata.mode)
                                    }),
                            },
                        ),
                        Op::SetFileMetaIfSame { path, .. } => (
                            path,
                            Change::SetMetadata {
                                kind: proto::Kind::File,
                            },
                        ),
                    };
                    (self.result_path(path, false), change)
                })
                .collect(),
            Request::PutSmallBatch(puts) => puts
                .iter()
                .map(|put| file(&put.path, put.data.len() as u64))
                .collect(),
            Request::PrepareSmallFiles(request) => request
                .files
                .iter()
                .map(|small| file(&small.path, small.size))
                .collect(),
            Request::PatchSmallBatch(patches) => patches
                .iter()
                .map(|patch| file(&patch.path, patch.len))
                .collect(),
            Request::PatchBegin { patch, .. } => vec![file(&patch.path, patch.len)],
            Request::Prepare { path, size, .. } => vec![file(path, *size)],
            Request::StageBasis { path, len, .. } | Request::SeedBasis { path, len, .. } => {
                vec![file(path, *len)]
            }
            Request::WriteRange { path, .. }
            | Request::ReuseComparedRange { path, .. }
            | Request::Finalize { path, .. } => vec![file(path, 0)],
            Request::FinishBasis { path, .. } => {
                vec![(self.result_path(path, false), Change::KeepFile)]
            }
            _ => Vec::new(),
        }
    }

    /// Confirm or forget the provisional creations of an executed request.
    /// Only a confirmed creation becomes this grant's own; a failed one is
    /// dropped so the path cannot later be replaced as if it were.
    /// `response` is the executor's answer to the authorized request.
    pub(crate) fn settle(&self, settlement: Settlement, response: &proto::Response) {
        let Settlement {
            creations,
            outcomes,
            charged,
            tracked,
            stream: _,
        } = settlement;
        self.refund_unmade(&charged, response);
        if creations.is_empty() && outcomes.is_empty() && !tracked {
            return;
        }
        let outcome_error = |index: usize| -> Option<Failure<'_>> {
            let missing = || Failure::io("receiver returned no outcome for this file");
            match response {
                proto::Response::Err(error) => Some(Failure::io(error.as_str())),
                proto::Response::EndpointError(error) => Some(Failure::of(error)),
                proto::Response::WidenedDirectories(results) => results
                    .get(index)
                    .and_then(|result| result.as_ref().err().map(Failure::of)),
                proto::Response::Applied(results) => results
                    .get(index)
                    .and_then(|error| error.as_ref().map(Failure::of)),
                proto::Response::PatchedBatch(results) => match results.get(index) {
                    Some(Ok(_)) => None,
                    Some(Err(error)) => Some(Failure::of(&error.error)),
                    None => Some(missing()),
                },
                // Small files published with their identities, for links.
                proto::Response::PublishedBatch(results) => match results.get(index) {
                    Some(Ok(_)) => None,
                    Some(Err(error)) => Some(Failure::of(error)),
                    None => Some(missing()),
                },
                _ => None,
            }
        };
        // The executor's typed error for an operation, where it gave one.
        let outcome_wire = |index: usize| -> Option<&proto::WireError> {
            match response {
                proto::Response::EndpointError(error) => Some(error),
                proto::Response::Applied(results) => results.get(index).and_then(Option::as_ref),
                proto::Response::PatchedBatch(results) => match results.get(index) {
                    Some(Err(error)) => Some(&error.error),
                    _ => None,
                },
                proto::Response::PublishedBatch(results) => match results.get(index) {
                    Some(Err(error)) => Some(error),
                    _ => None,
                },
                _ => None,
            }
        };
        let failed = |index: usize| outcome_error(index).is_some();
        // A change the receiver declined to make in place, because only a
        // replacement may change that file's metadata (`fsops::vouch`), is
        // not a failure: the copy replaces the file, and the results report
        // that replacement.
        let declined = |index: usize| {
            let error = match response {
                proto::Response::EndpointError(error) => Some(error),
                proto::Response::Applied(results) => results.get(index).and_then(Option::as_ref),
                proto::Response::PatchedBatch(results) => match results.get(index) {
                    Some(Err(error)) => Some(&error.error),
                    _ => None,
                },
                _ => None,
            };
            error.is_some_and(crate::fsops::vouch::is_replace_required_wire)
        };
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
        if !outcomes.is_empty() {
            state.recorded_any = true;
        }
        let streaming = self.results_started.load(Ordering::Acquire);
        for outcome in outcomes {
            match outcome {
                PendingOutcome::Patch {
                    index,
                    path,
                    copy_id,
                    size,
                    hold,
                } => {
                    let reply = match response {
                        proto::Response::PatchedBatch(results) => results.get(index),
                        _ => None,
                    };
                    // A file that already matched was kept, or failed only
                    // to be kept.
                    let kept = matches!(
                        reply,
                        Some(Ok(proto::SmallPatched { kept: true, .. }))
                            | Some(Err(proto::SmallPatchError { matched: true, .. }))
                    );
                    // A file that no longer met its condition was neither
                    // kept nor written, and the sender compares it again.
                    let stale = matches!(
                        reply,
                        Some(Err(proto::SmallPatchError {
                            stale_condition: true,
                            ..
                        }))
                    );
                    // A kept or stale file occupies nothing new. A
                    // publication, or another failed attempt, keeps the size
                    // it declared, as staging keeps its declaration.
                    if let Some(hold) = hold {
                        let key = (path.clone(), copy_id);
                        let published = !kept && !stale && outcome_error(index).is_none();
                        Self::settle_observation_reservation(
                            &mut state,
                            &key,
                            hold,
                            !kept && !stale,
                        );
                        // A published file is no longer in flight; what it
                        // occupies stays counted.
                        if published {
                            state.reserved.remove(&key);
                        }
                    }
                    let change = if kept {
                        Change::KeepFile
                    } else {
                        Change::PublishFile { size }
                    };
                    // The sender tries a file again when its patch failed
                    // with nothing kept or written: it compares again one
                    // that no longer met its condition and copies the rest
                    // whole, as it does each file of a batch that failed
                    // whole or returned no outcome for it, and one the
                    // receiver would only replace. The failure is held until
                    // that retry settles it, and listed if none does.
                    let retried = match reply {
                        Some(Err(error)) => error.retried(),
                        Some(Ok(_)) => false,
                        None => true,
                    } || declined(index);
                    match outcome_error(index) {
                        Some(error) if retried => self.record_retried(&path, change, error),
                        error => self.record_change(&path, change, error),
                    }
                }
                PendingOutcome::LogicalIfFailed { index, .. }
                | PendingOutcome::Logical { index, .. }
                | PendingOutcome::Metadata { index, .. }
                    if declined(index) => {}
                PendingOutcome::Metadata { index, path, kind } => {
                    if let Some(error) = outcome_error(index) {
                        let kind = kind.unwrap_or_else(|| {
                            self.rooted_metadata(&path)
                                .ok()
                                .flatten()
                                .map_or(proto::Kind::File, |metadata| kind_from_mode(metadata.mode))
                        });
                        self.record_change(&path, Change::SetMetadata { kind }, Some(error));
                    }
                }
                PendingOutcome::LogicalIfFailed {
                    index,
                    path,
                    change,
                } => {
                    if let Some(error) = outcome_error(index) {
                        self.record_change(&path, change, Some(error));
                    }
                }
                PendingOutcome::SmallCopy { index, path, size } => {
                    let proto::Response::SmallFilesCopied(proto::SmallCopyResponse {
                        outcome: proto::SmallCopyOutcome::Published(results),
                        ..
                    }) = response
                    else {
                        continue;
                    };
                    let Some(result) = results.get(index) else {
                        continue;
                    };
                    let error = result.error.as_ref().map(Failure::of);
                    let change = match result.disposition {
                        proto::SmallCopyDisposition::Copied => Change::PublishFile { size },
                        proto::SmallCopyDisposition::QuickChecked
                        | proto::SmallCopyDisposition::ContentMatched
                            if result.repaired =>
                        {
                            Change::SetMetadata {
                                kind: proto::Kind::File,
                            }
                        }
                        _ => continue,
                    };
                    self.record_change(&path, change, error);
                }
                PendingOutcome::Logical {
                    index,
                    path,
                    change,
                } => {
                    let creation = matches!(
                        change,
                        Change::PublishFile { .. }
                            | Change::CreateSymlink
                            | Change::CreateSpecial
                            | Change::LinkFile
                    );
                    let error = outcome_error(index);
                    if creation && self.kept_by_policy(&state, &path, false, outcome_wire(index)) {
                        continue;
                    }
                    self.record_change(&path, change, error);
                }
                PendingOutcome::FileStage {
                    index,
                    path,
                    copy_id,
                    size,
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
                    // file-lifecycle mutation and must not report an
                    // unfinished file. Nor did a preparation
                    // `--in-place=update` refused: the sender replaces the
                    // file instead, through a stage.
                    let refused = stage == FileStage::Prepare
                        && matches!(response, proto::Response::EndpointError(error)
                            if crate::fsops::vouch::is_replace_required_wire(error));
                    // A published file is no longer in flight; what it
                    // occupies stays counted. Nor is one whose name the
                    // existing-object policy keeps.
                    if stage == FileStage::Finalize
                        && (outcome_error(index).is_none()
                            || self.kept_by_policy(&state, &path, false, outcome_wire(index)))
                    {
                        state.reserved.remove(&(path.clone(), copy_id));
                        if outcome_error(index).is_some() {
                            state.file_lifecycles.remove(&(path.clone(), copy_id));
                            continue;
                        }
                    }
                    if absent || refused || !streaming {
                        continue;
                    }
                    let key = (path.clone(), copy_id);
                    let declared = size.or_else(|| {
                        state
                            .reserved
                            .get(&key)
                            .and_then(ByteReservation::effective_size)
                    });
                    match (stage, outcome_error(index)) {
                        // Published: reported now and no longer tracked. A
                        // repeated finalization reports nothing new.
                        (FileStage::Finalize, None) => {
                            if let Some(lifecycle) = state.file_lifecycles.remove(&key) {
                                self.record_change(
                                    &path,
                                    Change::PublishFile {
                                        size: lifecycle.size,
                                    },
                                    None,
                                );
                            }
                        }
                        (_, error) => {
                            let lifecycle =
                                state.file_lifecycles.entry(key).or_insert(FileLifecycle {
                                    size: declared.unwrap_or(0),
                                    last_error: None,
                                    last_class: "io",
                                    listed: false,
                                });
                            if let Some(declared) = declared {
                                lifecycle.size = declared;
                            }
                            if let Some(error) = error {
                                lifecycle.last_error =
                                    crate::destination_results::bounded_diagnostic(error.message);
                                lifecycle.last_class = error.class;
                            }
                        }
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
    ///
    /// `refuses_existing` says the executor's operation refuses a name that
    /// exists, atomically, when held to `Absent`: a file's publication, a
    /// symlink, special file or hard link. Under `Skip` such a creation
    /// needs no look here.
    pub(super) fn constrain_creation(
        &self,
        path: &[u8],
        condition: &mut proto::TargetCondition,
        (directory, refuses_existing): (bool, bool),
        index: usize,
        pending: &mut Vec<PendingCreation>,
    ) -> Result<()> {
        let policy = self.creation_policy(directory);
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
        // A new file under `Skip` is published without replacing anything,
        // which the receiver refuses atomically if the name exists: it
        // needs no look first either.
        let observed =
            if policy == ExistingDestinationPolicy::Skip && refuses_existing && !directory {
                None
            } else {
                self.rooted_metadata(path)?
            };
        self.constrain_observed_creation(
            path,
            condition,
            directory,
            index,
            pending,
            (policy, observed),
        )
    }

    /// Bind a staged file's publication at `path`, a put or a
    /// finalization, to the signed existing-object policy, as
    /// `constrain_creation` does, and say what it replaces as the receiver
    /// knows it without a look.
    ///
    /// Where this receiver recorded what it found itself (`fsops::lookups`),
    /// the publication needs neither a look nor a link. Keeping existing
    /// files, a name found absent, by the receiver's own lookup for the
    /// planner or because a directory above it was found missing or empty
    /// or was created by this receiver, is renamed into place unchecked, by
    /// one publication only, and a name found present is kept. Replacing
    /// only existing files, a file found present is renamed over. A name
    /// not recorded, or found absent and already given to a publication, is
    /// held as `constrain_creation` holds it, and so is a publication
    /// `in_place`. Another program creating or removing the name after the
    /// receiver looked is the race every copy accepts.
    pub(super) fn constrain_publication(
        &self,
        path: &[u8],
        condition: &mut proto::TargetCondition,
        in_place: bool,
        index: usize,
        pending: &mut Vec<PendingCreation>,
    ) -> Result<proto::ScannedDestination> {
        use crate::fsops::lookups::{Claim, Looked};
        use proto::TargetCondition::{Absent, Any, Matches, MatchesFingerprint};
        let label = String::from_utf8_lossy(path);
        let root_must_be_new =
            self.root_existence == RootExistence::New && path == self.destination;
        let recorded = match &self.lookups {
            Some(lookups)
                if !(in_place || root_must_be_new || self.created_by_this_grant(path)) =>
            {
                crate::fsops::destination_relative_to(&self.root_path, path)
                    .ok()
                    .map(|relative| (lookups, relative))
            }
            _ => None,
        };
        if let Some((lookups, relative)) = recorded {
            match self.creation_policy(false) {
                ExistingDestinationPolicy::Skip => match lookups.claim(&relative) {
                    Claim::Absent => {
                        match *condition {
                            Any | Absent => *condition = Any,
                            Matches { .. } | MatchesFingerprint { .. } => bail!(
                                "replacement of {label} contradicts the signed existing-object policy"
                            ),
                        }
                        self.state.lock().unwrap().provisional.insert(path.to_vec());
                        pending.push(PendingCreation {
                            index,
                            path: path.to_vec(),
                            persist: true,
                            link: false,
                        });
                        return Ok(proto::ScannedDestination::Absent);
                    }
                    Claim::Present => {
                        return Err(kept(format!(
                            "signed grant retains existing objects: {label} already exists"
                        )))
                    }
                    Claim::Unknown => {}
                },
                ExistingDestinationPolicy::MustExist => {
                    if let Some(Looked::Present { file_mode }) = lookups.get(&relative) {
                        if *condition == Absent {
                            bail!(
                                "no-replace creation of {label} contradicts the signed existing-object policy"
                            );
                        }
                        pending.push(PendingCreation {
                            index,
                            path: path.to_vec(),
                            persist: false,
                            link: false,
                        });
                        return Ok(file_mode.map_or(
                            proto::ScannedDestination::Unknown,
                            proto::ScannedDestination::File,
                        ));
                    }
                }
                _ => {}
            }
        }
        self.constrain_creation(path, condition, (false, true), index, pending)?;
        Ok(if *condition == Absent {
            proto::ScannedDestination::Absent
        } else {
            proto::ScannedDestination::Unknown
        })
    }

    /// Whether this receiver's own lookup for the planner found `path`.
    fn looked_up_present(&self, path: &[u8]) -> bool {
        self.lookups.as_ref().is_some_and(|lookups| {
            crate::fsops::destination_relative_to(&self.root_path, path).is_ok_and(|relative| {
                matches!(
                    lookups.get(&relative),
                    Some(crate::fsops::lookups::Looked::Present { .. })
                )
            })
        })
    }

    /// Forget what the receiver's lookups found at `path`, once the grant
    /// deletes it.
    fn forget_lookup(&self, path: &[u8]) {
        if let (Some(lookups), Ok(relative)) = (
            &self.lookups,
            crate::fsops::destination_relative_to(&self.root_path, path),
        ) {
            lookups.forget(&relative);
        }
    }

    /// The existing-object policy a creation is held to: the grant's, or,
    /// for anything but a directory under `keep_files` (`syq rsync
    /// --ignore-existing`), `Skip`.
    fn creation_policy(&self, directory: bool) -> ExistingDestinationPolicy {
        match self.copy.policy.existing {
            ExistingDestinationPolicy::Replace if self.extra_options.keep_files && !directory => {
                ExistingDestinationPolicy::Skip
            }
            policy => policy,
        }
    }

    /// Whether the failure of a change at `path` only shows an object its
    /// existing-object policy keeps: the executor found, before changing
    /// anything, that the destination did not meet the change's condition
    /// (`fsops::condition_not_met`), under `Skip` (or `keep_files` for
    /// anything but a directory) or `MustExist`. Such a change is no
    /// failure: nothing changed, as the policy asks. A root that must be
    /// new, and a name this grant created, are never kept.
    fn kept_by_policy(
        &self,
        state: &AuthorityState,
        path: &[u8],
        directory: bool,
        error: Option<&proto::WireError>,
    ) -> bool {
        error.is_some_and(crate::fsops::is_condition_not_met_wire)
            && matches!(
                self.creation_policy(directory),
                ExistingDestinationPolicy::Skip | ExistingDestinationPolicy::MustExist
            )
            && !(self.root_existence == RootExistence::New && path == self.destination)
            && !state.created.contains(path)
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
                        return Err(kept(format!(
                            "signed grant creates nothing: {label} exists but is not a directory"
                        )))
                    }
                    None => {
                        return Err(kept(format!(
                            "signed grant creates nothing: {label} does not exist"
                        )))
                    }
                };
                // Pin the mutation to what was observed: a signed deletion on
                // another connection could otherwise empty the path between
                // this check and execution, turning an update into a creation.
                // A caller-supplied identity is accepted only when it names
                // the observed object, never on its own authority, and only
                // where numbers can show that.
                self.existence_only_where_numbers_mislead(&metadata, condition);
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
                    Matches { .. } | MatchesFingerprint { .. } => {
                        return Err(kept(format!(
                            "requested identity for {label} does not match the object the receiver observed"
                        )))
                    }
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
                        link: false,
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
                    let refusal =
                        format!("signed grant retains existing objects: {label} already exists");
                    // A root that must be new fails; anything else is kept.
                    if policy == ExistingDestinationPolicy::Skip {
                        return Err(kept(refusal));
                    }
                    bail!(refusal)
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
                    link: false,
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
    /// `directory` marks a directory's metadata: under `keep_files` only
    /// those of existing objects may change.
    pub(super) fn constrain_update(
        &self,
        path: &[u8],
        condition: Option<&mut proto::TargetCondition>,
        pending: &[PendingCreation],
        directory: bool,
    ) -> Result<()> {
        let label = String::from_utf8_lossy(path);
        // A creation earlier in this same request (a symlink followed by its
        // metadata, say) counts: the request's metadata runs only once its
        // no-replace creations have all succeeded.
        let created_before = self.created_by_this_grant(path);
        let created_here = pending
            .iter()
            .any(|creation| creation.path == path && !creation.link);
        match self.creation_policy(directory) {
            // A name this grant created leads only to an object it created,
            // whatever runs on other connections meanwhile: the one step
            // that could give it an existing file is a hard link, which
            // this policy allows only to the grant's own files
            // (`OwnedObjects`).
            ExistingDestinationPolicy::Skip if created_before || created_here => Ok(()),
            ExistingDestinationPolicy::Skip => Err(kept(format!(
                "signed grant retains existing objects: {label} may not be modified"
            ))),
            ExistingDestinationPolicy::MustExist if created_before || created_here => Ok(()),
            // Updates are pinned to the observed object, like publications:
            // nothing hostA supplies names an inode on its own authority.
            ExistingDestinationPolicy::MustExist => self.pin_update(path, &label, condition),
            ExistingDestinationPolicy::Replace => Ok(()),
            ExistingDestinationPolicy::UpdateIfOlder => {
                bail!("update-if-older existing-object policy is not enforceable by the receiver")
            }
        }
    }

    /// Where inode numbers cannot show which file a name leads to
    /// (`fsops::Profile::link_counts_trusted`), a sender's identity for the
    /// object observed as `observed` is set aside: the change is pinned to
    /// what is there, as on any receiver there (`FsOps`'s
    /// `existence_only_where_numbers_mislead`).
    fn existence_only_where_numbers_mislead(
        &self,
        observed: &RootMetadata,
        condition: &mut proto::TargetCondition,
    ) {
        let trusted = self.root.known_profile(observed.dev).map_or_else(
            || self.root.link_counts_trusted(),
            |profile| profile.link_counts_trusted,
        );
        if !trusted && matches!(*condition, proto::TargetCondition::Matches { .. }) {
            *condition = proto::TargetCondition::Any;
        }
    }

    /// Hold an update of `path` to the object the receiver observes there
    /// now: its device and inode, or the identity the sender named if it is
    /// that object's. Execution then refuses a name that has come to lead
    /// to another object. A change time would also tell an inode number
    /// reused by a new file, but this copy's own links and publications
    /// change it too, so it would refuse legitimate updates.
    fn pin_update(
        &self,
        path: &[u8],
        label: &str,
        condition: Option<&mut proto::TargetCondition>,
    ) -> Result<()> {
        use proto::TargetCondition::{Absent, Any, Matches, MatchesFingerprint};
        let Some(metadata) = self.rooted_metadata(path)? else {
            return Err(kept(format!(
                "signed grant creates nothing: {label} does not exist"
            )));
        };
        let Some(condition) = condition else {
            return Ok(());
        };
        self.existence_only_where_numbers_mislead(&metadata, condition);
        match *condition {
            Any => {
                *condition = Matches {
                    dev: metadata.dev,
                    ino: metadata.ino,
                }
            }
            Absent => {
                bail!("no-replace update of {label} contradicts the signed existing-object policy")
            }
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
            Matches { .. } | MatchesFingerprint { .. } => {
                return Err(kept(format!(
                    "requested identity for {label} does not match the object the receiver observed"
                )))
            }
        }
        Ok(())
    }

    /// Refuse to write in place a root the grant requires to be new: it is
    /// staged and published without replacing anything, so that no one
    /// sees it partly written, unless this grant created it.
    /// `creates` says the in-place write creates the file where its name is
    /// free; one that only updates an existing file creates nothing.
    pub(super) fn constrain_inplace(&self, path: &[u8], creates: bool) -> Result<()> {
        // In place, the receiver creates the file when its name is free,
        // and the name can become free after any check here: only a grant
        // that lets the copy replace and create alike allows that. A grant
        // that creates nothing lets an existing file be updated in place,
        // as one it replaces would be: the receiver writes into the file
        // it opens at the name, and stages the file where there is none,
        // held to the grant as any staged file is.
        let policy = self.creation_policy(false);
        let updates_only = !creates && policy == ExistingDestinationPolicy::MustExist;
        if policy != ExistingDestinationPolicy::Replace && !updates_only {
            bail!(
                "signed grant does not let {} be created or replaced freely: it is not written in place",
                String::from_utf8_lossy(path)
            );
        }
        let root_must_be_new =
            self.root_existence == RootExistence::New && path == self.destination;
        if root_must_be_new && !self.created_by_this_grant(path) {
            bail!(
                "signed grant only creates {}: it is staged and published without replacing anything, not written in place",
                String::from_utf8_lossy(path)
            );
        }
        Ok(())
    }

    /// Refuse a write or publication of `path` in place unless the signed
    /// policy lets new files be written in place. Under it the receiver
    /// writes in place only a file it creates; whatever else the name holds
    /// is replaced through a stage, published under the existing-object
    /// policy as any staged file is. Staged requests are always allowed.
    fn require_publication_mode(&self, inplace: bool, what: &str) -> Result<()> {
        if inplace && !self.copy.policy.publication.writes_new_files_in_place() {
            bail!("{what} does not match the signed publication policy");
        }
        Ok(())
    }

    /// Refuse staging work whose eventual publication the existing-object
    /// policy would reject, so the transfer fails before moving bytes.
    pub(super) fn constrain_prepare(&self, path: &[u8]) -> Result<()> {
        if self.created_by_this_grant(path) {
            return Ok(());
        }
        let label = String::from_utf8_lossy(path);
        // Under `Skip` the publication refuses a name that exists, so
        // nothing is looked at here; under `MustExist`, a name this
        // receiver's lookups found needs no look either.
        match self.creation_policy(false) {
            ExistingDestinationPolicy::MustExist
                if !self.looked_up_present(path) && self.rooted_metadata(path)?.is_none() =>
            {
                Err(kept(format!(
                    "signed grant creates nothing: {label} does not exist"
                )))
            }
            _ => Ok(()),
        }
    }

    /// Check a request's metadata flags against the grant's options, also
    /// allowing those in `mapped`, which a signed mapping entry sets for the
    /// path the request changes (`mapped_grants`).
    pub(super) fn check_flags(&self, flags: u8, mapped: u8) -> Result<()> {
        let granted = |flag: u8| mapped & flag != 0;
        let known = proto::flags::MODE_MASK
            | proto::flags::OWNER
            | proto::flags::GROUP
            | proto::flags::TIMES
            | proto::flags::REQUIRE_OWNER
            | proto::flags::REQUIRE_GROUP;
        // A hard-link representative reports the identity its followers
        // link to; that changes only the reply.
        let known = if self.extra_options.hardlinks {
            known | proto::flags::REPORT_IDENTITY
        } else {
            known
        };
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
        if flags & proto::flags::MODE != 0
            && !self.copy.options.preserve_permissions
            && !granted(proto::flags::MODE)
        {
            bail!("request tries to preserve permissions not authorized by the grant");
        }
        if flags & proto::flags::RECEIVER_MODE != 0 && !self.copy.options.receiver_managed_modes {
            bail!("request tries to apply receiver-managed modes not authorized by the grant");
        }
        if flags & proto::flags::OWNER != 0
            && !self.copy.options.preserve_owner
            && !granted(proto::flags::OWNER)
        {
            bail!("request tries to preserve ownership not authorized by the grant");
        }
        if flags & proto::flags::GROUP != 0
            && !self.copy.options.preserve_group
            && !granted(proto::flags::GROUP)
        {
            bail!("request tries to preserve group not authorized by the grant");
        }
        if flags & proto::flags::TIMES != 0
            && !self.copy.options.preserve_times
            && !granted(proto::flags::TIMES)
        {
            bail!("request tries to preserve timestamps not authorized by the grant");
        }
        Ok(())
    }

    /// What is at `path` now, looked up beneath the root this copy holds.
    pub(super) fn rooted_metadata(&self, path: &[u8]) -> Result<Option<RootMetadata>> {
        self.root.metadata_optional(&self.root_relative(path)?)
    }

    /// `path` relative to the root this copy holds.
    pub(super) fn root_relative(&self, path: &[u8]) -> Result<RelativePath> {
        let relative =
            crate::fsops::destination_relative_to(&self.root_path, path).with_context(|| {
                format!(
                    "receiver metadata target {} is outside {}, the directory the destination is in",
                    String::from_utf8_lossy(path),
                    String::from_utf8_lossy(&self.root_path)
                )
            })?;
        RelativePath::new(&relative)
    }

    /// Set up one connection's executor to serve this copy: its hashing,
    /// the files it gives new names to, the scope of the files it writes,
    /// and the root it works beneath, which every connection shares, as an
    /// ordinary receiver works beneath the directory its sender anchored.
    pub(crate) fn configure_session(&self, ops: &mut crate::fsops::FsOps) {
        ops.set_hash_policy(self.hash_policy());
        ops.set_owned_objects(self.owned_objects());
        ops.set_stage_scope(self.stage_scope());
        ops.install_restricted_destination(self.root.clone(), &self.root_path);
        ops.set_planning_lookups(self.lookups.clone());
    }

    /// An executor set up as one of this copy's connections, for tests.
    #[cfg(test)]
    pub(crate) fn test_ops(&self) -> crate::fsops::FsOps {
        let mut ops = crate::fsops::FsOps::new();
        self.configure_session(&mut ops);
        ops
    }

    /// Check metadata a request applies: the grant's flags, and only the
    /// inode metadata the grant selects. A receiver-chosen mode is the
    /// receiver's own to decide, as on every receiver
    /// (`fsops::receiver_mode`).
    pub(super) fn check_metadata(&self, path: &[u8], meta: &proto::Meta, flags: u8) -> Result<()> {
        let mapped = self.mapped_grants(path, |metadata| {
            let mut granted = 0;
            if metadata.mode == Some(meta.mode & 0o7777) {
                granted |= proto::flags::MODE;
            }
            if metadata.uid == Some(meta.uid) {
                granted |= proto::flags::OWNER;
            }
            if metadata.gid == Some(meta.gid) {
                granted |= proto::flags::GROUP;
            }
            if metadata.mtime == Some(meta.mtime)
                && metadata.mtime_nsec.unwrap_or(0) == meta.mtime_nsec
            {
                granted |= proto::flags::TIMES;
            }
            granted
        })?;
        self.check_flags(flags, mapped)?;
        if let Some(metadata) = &meta.inode_metadata {
            let requested = crate::inode_metadata::Selection {
                acls: metadata.acls.is_some() || metadata.macos_acl.is_some(),
                xattrs: metadata.xattrs.is_some(),
                atimes: metadata.atime.is_some(),
                crtimes: metadata.crtime.is_some(),
                open_noatime: false,
            };
            anyhow::ensure!(
                self.extra_options.allows(requested),
                "request applies inode metadata not authorized by the signed grant"
            );
        }
        Ok(())
    }

    /// The metadata flags the signed mapping entry for `path` grants, as
    /// `grants` finds them in that entry's metadata: what the mapping sets
    /// explicitly may be applied without the matching copy option, and only
    /// with exactly its values.
    fn mapped_grants(
        &self,
        path: &[u8],
        grants: impl FnOnce(&crate::mapping::Metadata) -> u8,
    ) -> Result<u8> {
        let Some(mapping) = &self.mapping else {
            return Ok(0);
        };
        let mapping = mapping.lock().unwrap();
        Ok(mapping
            .permissions()?
            .metadata(self.mapping_relative(path)?)
            .map_or(0, grants))
    }

    /// The flags a preparation of `path` names for the publication to come,
    /// in `mode`: a mapping entry's explicit mode must be `mode`, and the
    /// other values it sets are checked when the file is published.
    pub(super) fn check_preparation_flags(&self, path: &[u8], mode: u32, flags: u8) -> Result<()> {
        let mapped = self.mapped_grants(path, |metadata| {
            let mut granted = metadata.flags() & !proto::flags::MODE;
            if metadata.mode == Some(mode & 0o7777) {
                granted |= proto::flags::MODE;
            }
            granted
        })?;
        self.check_flags(flags, mapped)
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

    /// A grouped comparison may use any block the protocol allows. The
    /// grant's block applies to the per-file comparison; `HashWindow` already
    /// returns hashes in blocks of any size, so these reveal nothing more.
    pub(super) fn check_comparison_request(&self, block: u64, len: u64) -> Result<()> {
        if !(proto::MIN_HASH_BLOCK_BYTES..=proto::MAX_HASH_BLOCK_BYTES).contains(&block) {
            bail!("comparison block size is outside protocol limits");
        }
        if len > self.copy.limits.max_file_bytes {
            bail!("signed grant per-file byte limit exceeded");
        }
        if !proto::hash_response_fits(block, len) {
            bail!("hash response would exceed protocol limits");
        }
        Ok(())
    }

    /// Check file data a request carries for `path` at `offset`: within the
    /// per-file limit and one rate-limit burst, paced to the signed rate.
    /// Its bytes count against the total once the request is authorized
    /// (`charge_request`).
    pub(super) fn check_file_bytes(&self, path: &[u8], offset: u64, bytes: usize) -> Result<()> {
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
        if let Some(limit) = &self.file_data_limit {
            limit.wait(bytes);
            self.check_deadline()?;
        }
        Ok(())
    }

    /// Check a deletion the grant may make. It counts against the deletion
    /// limit once its request is authorized (`charge_request`).
    pub(super) fn check_deletion(&self, path: &[u8], is_dir: bool) -> Result<()> {
        if path == self.destination {
            bail!("the signed destination root itself may not be deleted");
        }
        if self.filters.delete_excluded {
            self.check_mutation_authority(path)?;
        } else {
            self.check_mutation_path(path, is_dir)?;
        }
        if self.copy.policy.deletion == DeletionPolicy::Forbid {
            bail!("deletion is not authorized by the signed grant");
        }
        Ok(())
    }

    /// Count an authorized request against the signed limits: each change
    /// it makes against the entry limit, each deletion against the deletion
    /// limit, and the file bytes it carries against the byte limit. Nothing
    /// is counted when any limit would be exceeded.
    pub(super) fn charge_request(&self, request: &Request) -> Result<Charged> {
        let mut deleting = Vec::new();
        // A file the copy writes counts once, before its first change: the
        // request that creates or opens it for writing (a stage, a
        // sidecar, an in-place file, even an empty one) or, for one prepared
        // only to look, the publication.
        let file = match request {
            Request::Prepare {
                path,
                copy_id,
                create_if_missing,
                update,
                ..
            } if *create_if_missing || update.is_some() => Some((path.clone(), *copy_id)),
            Request::StageBasis { path, copy_id, .. }
            | Request::SeedBasis { path, copy_id, .. }
            | Request::Finalize { path, copy_id, .. } => Some((path.clone(), *copy_id)),
            _ => None,
        };
        // The file's count is shared through its reservation; without one,
        // the request counts the file as an ordinary change of its own.
        // The state stays locked until the request holds its share, so two
        // requests never both count the file.
        let mut state = self.state.lock().unwrap();
        let (file, file_charge, own_file_change) = match file {
            Some(key) => match state.reserved.get(&key) {
                Some(reservation) => {
                    let charge = reservation.entry.is_none();
                    let instance = reservation.instance;
                    (Some((key, instance)), charge, false)
                }
                None => (None, false, true),
            },
            None => (None, false, false),
        };
        let (changes, bytes) = match request {
            Request::Apply { ops } => {
                deleting = ops
                    .iter()
                    .enumerate()
                    .filter(|(_, op)| matches!(op, Op::Rmdir { .. } | Op::Unlink { .. }))
                    .map(|(index, _)| index)
                    .collect();
                (ops.len() as u64, 0)
            }
            Request::PutSmallBatch(puts) => (
                puts.len() as u64,
                puts.iter().map(|put| put.data.len() as u64).sum(),
            ),
            Request::PatchSmallBatch(patches) => (
                patches.len() as u64,
                patches.iter().map(|patch| patch.data.len() as u64).sum(),
            ),
            Request::PatchBegin { .. } | Request::FinishBasis { .. } => (1, 0),
            Request::Prepare { .. }
            | Request::StageBasis { .. }
            | Request::SeedBasis { .. }
            | Request::Finalize { .. } => (u64::from(own_file_change), 0),
            Request::PrepareSmallFiles(request) => (request.files.len() as u64, 0),
            Request::CopySmallFiles(payloads) => (
                0,
                payloads
                    .iter()
                    .map(|payload| payload.data.len() as u64)
                    .sum(),
            ),
            Request::WriteRange { data, .. } | Request::PatchData { data, .. } => {
                (0, data.len() as u64)
            }
            _ => (0, 0),
        };
        let charge = |counter: &std::sync::atomic::AtomicU64, amount: u64, limit: u64| {
            amount == 0
                || counter
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |total| {
                        total.checked_add(amount).filter(|total| *total <= limit)
                    })
                    .is_ok()
        };
        let refund = |counter: &std::sync::atomic::AtomicU64, amount: u64| {
            counter.fetch_sub(amount, Ordering::AcqRel);
        };
        let deletions = deleting.len() as u64;
        let limits = &self.copy.limits;
        let counted = changes + u64::from(file_charge);
        if !charge(&self.changes, counted, limits.max_entries) {
            bail!("signed grant entry limit exceeded");
        }
        if !charge(&self.deletions, deletions, limits.max_deletions) {
            refund(&self.changes, counted);
            bail!("signed grant deletion limit exceeded");
        }
        if !charge(&self.transferred_bytes, bytes, limits.max_total_bytes) {
            refund(&self.changes, counted);
            refund(&self.deletions, deletions);
            bail!("signed grant total-byte limit exceeded");
        }
        if let Some((key, _)) = &file {
            let reservation = state
                .reserved
                .get_mut(key)
                .expect("the reservation was found under the same lock");
            reservation
                .entry
                .get_or_insert_with(Default::default)
                .holders += 1;
        }
        Ok(Charged {
            changes,
            deleting,
            file,
        })
    }

    /// Settle a request whose execution never started, as a small copy
    /// that ended without its payloads: nothing it was charged for
    /// changed, and it fails with `reason`.
    pub(super) fn settle_unexecuted(&self, mut settlement: Settlement, reason: &str) {
        let charged = std::mem::take(&mut settlement.charged);
        self.changes.fetch_sub(charged.changes, Ordering::AcqRel);
        self.deletions
            .fetch_sub(charged.deleting.len() as u64, Ordering::AcqRel);
        self.release_file(charged.file.as_ref(), false);
        self.settle(settlement, &proto::Response::Err(reason.into()));
    }

    /// Release a settled request's share of `file`'s count against the
    /// entry limit, noting whether it `made` a change. The count is given
    /// back when the last share goes and no request changed the file.
    fn release_file(&self, file: Option<&FileShare>, made: bool) {
        let Some((key, instance)) = file else {
            return;
        };
        let mut state = self.state.lock().unwrap();
        // A reservation settled away meanwhile was published or failed
        // after a change: the count stays, and a newer reservation of the
        // same key is another file's.
        let Some(reservation) = state
            .reserved
            .get_mut(key)
            .filter(|reservation| reservation.instance == *instance)
        else {
            return;
        };
        let Some(entry) = &mut reservation.entry else {
            return;
        };
        entry.holders = entry.holders.saturating_sub(1);
        entry.made |= made;
        if entry.holders == 0 && !entry.made {
            reservation.entry = None;
            self.changes.fetch_sub(1, Ordering::AcqRel);
        }
    }

    /// Give back the changes and deletions of an authorized request that
    /// the executor reports it did not make, and nothing else: a change
    /// whose condition the executor found unmet before changing anything
    /// (`fsops::condition_not_met`), a patch that found its file changed
    /// since it was compared, a small-copy file that needed no change, and
    /// a small copy that wrote nothing. A change that failed after it may
    /// have changed something stays counted, as do the files of a small
    /// copy whose staging failed: their sidecars stay for the fallback
    /// engine to resume.
    fn refund_unmade(&self, charged: &Charged, response: &proto::Response) {
        use crate::fsops::is_unchanged_wire as unmet;
        let all = || (0..charged.changes as usize).collect::<Vec<usize>>();
        let unmade: Vec<usize> = match response {
            proto::Response::EndpointError(error) if unmet(error) => all(),
            proto::Response::Applied(results) => results
                .iter()
                .enumerate()
                .filter(|(_, error)| error.as_ref().is_some_and(unmet))
                .map(|(index, _)| index)
                .collect(),
            proto::Response::PatchedBatch(results) => results
                .iter()
                .enumerate()
                .filter(|(_, result)| {
                    result
                        .as_ref()
                        .err()
                        .is_some_and(|error| error.stale_condition || unmet(&error.error))
                })
                .map(|(index, _)| index)
                .collect(),
            proto::Response::PublishedBatch(results) => results
                .iter()
                .enumerate()
                .filter(|(_, result)| result.as_ref().err().is_some_and(unmet))
                .map(|(index, _)| index)
                .collect(),
            // A small copy changes the files it publishes and those whose
            // metadata it changes; a preparation waiting for its payloads
            // is settled with their reply, and one that published nothing
            // changed nothing.
            proto::Response::SmallFilesCopied(proto::SmallCopyResponse {
                outcome: proto::SmallCopyOutcome::Published(results),
                ..
            }) => results
                .iter()
                .enumerate()
                .filter(|(_, result)| match &result.error {
                    Some(error) => unmet(error),
                    None => match result.disposition {
                        proto::SmallCopyDisposition::Copied => false,
                        proto::SmallCopyDisposition::QuickChecked
                        | proto::SmallCopyDisposition::ContentMatched => !result.repaired,
                        proto::SmallCopyDisposition::Excluded => true,
                    },
                })
                .map(|(index, _)| index)
                .collect(),
            proto::Response::SmallFilesCopied(proto::SmallCopyResponse {
                outcome: proto::SmallCopyOutcome::StagingFailed(error),
                ..
            }) => {
                if unmet(error) {
                    all()
                } else {
                    Vec::new()
                }
            }
            // A target it does not handle, a capacity shortfall, or one
            // that needs block reuse: nothing was written.
            proto::Response::SmallFilesCopied(_) => all(),
            _ => Vec::new(),
        };
        let refunded = (unmade.len() as u64).min(charged.changes);
        if refunded > 0 {
            self.changes.fetch_sub(refunded, Ordering::AcqRel);
        }
        // A file request changes nothing only when its condition was unmet
        // before it started.
        let file_unmade = matches!(response, proto::Response::EndpointError(error) if unmet(error));
        self.release_file(charged.file.as_ref(), !file_unmade);
        // Both lists are in operation order.
        let mut unmade = unmade.iter().peekable();
        let undeleted = charged
            .deleting
            .iter()
            .filter(|&&index| {
                while unmade.next_if(|&&unmade| unmade < index).is_some() {}
                unmade.peek().is_some_and(|&&unmade| unmade == index)
            })
            .count() as u64;
        if undeleted > 0 {
            self.deletions.fetch_sub(undeleted, Ordering::AcqRel);
        }
    }

    /// Release the sizes held by the patches of a refused request.
    fn release_patch_holds(&self, outcomes: impl Iterator<Item = PendingOutcome>) {
        let mut state = self.state.lock().unwrap();
        for outcome in outcomes {
            if let PendingOutcome::Patch {
                path,
                copy_id,
                hold: Some(hold),
                ..
            } = outcome
            {
                Self::settle_observation_reservation(&mut state, &(path, copy_id), hold, false);
            }
        }
    }

    /// Hold an authorized request to the streamed patch open on its
    /// connection. A begin needs none to be open. Each piece must belong to
    /// the open patch and stay within the new data its begin declared, and is
    /// charged as a written range is, within one rate-limit burst. An end
    /// needs the patch open.
    fn authorize_stream(
        &self,
        request: &Request,
        stream: &mut Option<OpenPatchStream>,
        small_copy: &mut Option<PreparedSmallCopy>,
        step: &mut StreamStep,
    ) -> Result<()> {
        match request {
            Request::PrepareSmallFiles(request) => {
                *step = StreamStep::PrepareSmallCopy {
                    sizes: request.files.iter().map(|file| file.size).collect(),
                };
            }
            // Payloads only for the files the preparation asked for, each
            // of the size it offered.
            Request::CopySmallFiles(payloads) => {
                let prepared = small_copy
                    .take()
                    .context("no small copy is prepared on this connection")?;
                let mut sent = vec![false; prepared.needed.len()];
                let mismatched = payloads.iter().any(|payload| {
                    let index = payload.index as usize;
                    !prepared.needed.get(index).is_some_and(|needed| *needed)
                        || std::mem::replace(&mut sent[index], true)
                        || prepared.sizes[index] != payload.data.len() as u64
                });
                *step = StreamStep::CopySmallCopy(Box::new(prepared.settlement));
                if mismatched {
                    bail!("small copy payloads differ from what its preparation asked for");
                }
            }
            Request::PatchBegin { patch, data_len } => {
                if stream.is_some() {
                    bail!("a streamed patch is already open on this connection");
                }
                *step = StreamStep::Begin {
                    path: patch.path.clone(),
                    declared: *data_len,
                };
            }
            Request::PatchData { data, .. } => {
                let open = stream
                    .as_mut()
                    .context("no streamed patch is open on this connection")?;
                let received = open
                    .received
                    .checked_add(data.len() as u64)
                    .filter(|received| *received <= open.declared)
                    .context("streamed patch data runs past the length its begin declared")?;
                self.check_file_bytes(&open.path, open.received, data.len())?;
                open.received = received;
            }
            Request::PatchEnd { .. } => {
                if stream.is_none() {
                    bail!("no streamed patch is open on this connection");
                }
                *step = StreamStep::End;
            }
            _ => {}
        }
        Ok(())
    }

    /// The small-copy shortcut (`Request::PrepareSmallFiles`) publishes
    /// staged files at names directly inside one directory, replacing what
    /// it finds there, or changes a kept file's metadata in place. Each file
    /// passes the rules a `PutSmallBatch` entry does; the payloads that
    /// follow are held to them (`authorize_stream`), and `settle` records
    /// what the reply reports.
    fn authorize_small_copy(
        &self,
        request: &proto::SmallCopyRequest,
        outcomes: &mut Vec<PendingOutcome>,
    ) -> Result<()> {
        if self.creation_policy(false) != ExistingDestinationPolicy::Replace
            || self.root_existence != RootExistence::Any
        {
            bail!("the small-copy shortcut replaces existing files, which this grant does not");
        }
        self.require_publication_mode(false, "small-copy publication")?;
        if request.hash_policy != self.hash_policy() {
            bail!("hash policy differs from the authorized copy");
        }
        let parent = |path: &[u8]| {
            path.iter()
                .rposition(|byte| *byte == b'/')
                .map(|slash| path[..slash.max(1)].to_vec())
        };
        let in_destination = request.directory == self.destination
            && self.copy.policy.placement != DestinationPlacement::ExactPath;
        let at_destination = self.copy.policy.placement == DestinationPlacement::ExactPath
            && parent(&self.destination).as_deref() == Some(request.directory.as_slice());
        if !in_destination && !at_destination {
            bail!("small copy writes into a directory other than the signed destination");
        }
        if let Some(limit) = &self.file_data_limit {
            let bytes = request.files.iter().try_fold(0u64, |total, file| {
                total
                    .checked_add(file.size)
                    .context("small copy byte count overflow")
            })?;
            if bytes > limit.burst_bytes() {
                bail!("small copy exceeds the signed file-data rate-limit burst");
            }
        }
        // A content match also sets times the copy compares by.
        let flags = request.flags | (request.matching_flags & proto::flags::TIMES);
        for (index, file) in request.files.iter().enumerate() {
            if parent(&file.path).as_deref() != Some(request.directory.as_slice()) {
                bail!("small copy names a file outside the directory it writes into");
            }
            if self.expected_hash(&file.path)?.is_some() {
                bail!("expected-hash files require checked finalization");
            }
            let size = usize::try_from(file.size).context("small copy file size overflow")?;
            self.check_file_bytes(&file.path, 0, size)?;
            self.check_metadata(&file.path, &file.meta, flags)?;
            outcomes.push(PendingOutcome::SmallCopy {
                index,
                path: file.path.clone(),
                size: file.size,
            });
        }
        Ok(())
    }

    /// A patch either keeps the existing file, as FinishBasis does, or
    /// publishes a new file from its data and the existing file's blocks, as
    /// a staged copy that reuses compared blocks does. Only the executor's
    /// reply says which, so each patch passes the rules of both: its new data
    /// is charged as written ranges are, the size its publication would
    /// occupy is held as staging would declare it, and `settle` records the
    /// outcome the reply reports.
    pub(super) fn authorize_patches(
        &self,
        patches: &mut [proto::SmallPatch],
        pending: &mut Vec<PendingCreation>,
        outcomes: &mut Vec<PendingOutcome>,
    ) -> Result<()> {
        // The receiver builds every file of the batch in memory, reused
        // blocks included, which a repeated path and copy ID would not
        // otherwise hold back.
        if !proto::patch_batch_fits(patches.iter().map(|patch| patch.len)) {
            bail!("small-file patch batch describes more file bytes than the protocol allows");
        }
        if let Some(limit) = &self.file_data_limit {
            let bytes = patches.iter().try_fold(0u64, |total, patch| {
                total
                    .checked_add(patch.data.len() as u64)
                    .context("small-file batch byte count overflow")
            })?;
            if bytes > limit.burst_bytes() {
                bail!("small-file batch exceeds the signed file-data rate-limit burst");
            }
        }
        for (index, patch) in patches.iter_mut().enumerate() {
            if self.expected_hash(&patch.path)?.is_some() {
                bail!("expected-hash files require checked finalization");
            }
            self.check_comparison_request(patch.block, patch.len)?;
            // Keeping the file may apply other times than publishing it,
            // but nothing else.
            if (patch.flags ^ patch.unchanged_flags) & !proto::flags::TIMES != 0 {
                bail!("kept and published metadata flags differ beyond times");
            }
            self.check_metadata(&patch.path, &patch.meta, patch.unchanged_flags)?;
            // A patch that updates its file in place passes the rules of an
            // in-place preparation too (`Request::Prepare` with `update`):
            // under a grant for it, and with metadata the grant allows,
            // which the receiver checks again as it finishes the file.
            if patch.update_in_place {
                if !self
                    .copy
                    .policy
                    .publication
                    .updates_existing_files_in_place()
                {
                    bail!("small-file patch does not match the signed publication policy");
                }
                self.constrain_inplace(&patch.path, false)?;
            }
            self.check_file_bytes(&patch.path, 0, patch.data.len())?;
            // A patch is for a file that exists: it is looked at.
            self.constrain_creation(
                &patch.path,
                &mut patch.condition,
                (false, false),
                index,
                pending,
            )?;
            self.constrain_update(&patch.path, Some(&mut patch.condition), pending, false)?;
            self.check_metadata(&patch.path, &patch.meta, patch.flags)?;
            let hold = self.reserve_bytes(&patch.path, patch.copy_id, patch.len, true)?;
            outcomes.push(PendingOutcome::Patch {
                index,
                path: patch.path.clone(),
                copy_id: patch.copy_id,
                size: patch.len,
                hold,
            });
        }
        Ok(())
    }

    /// A new name for a file already in the signed scopes: a representative
    /// this copy published or kept, as for an ordinary copy. The new name
    /// follows the existing-object policy like any creation, and does not
    /// make the file the grant's own. Keeping existing objects, the receiver
    /// links only to files it created for the grant, which it checks as it
    /// links (`OwnedObjects`); an honest copy then gives a group's new names
    /// a new file of their own, as rsync does.
    fn authorize_hardlink(
        &self,
        (path, source, identity, condition): (
            &[u8],
            &[u8],
            (u64, u64),
            &mut proto::TargetCondition,
        ),
        index: usize,
        pending: &mut Vec<PendingCreation>,
        outcomes: &mut Vec<PendingOutcome>,
    ) -> Result<()> {
        if !self.extra_options.hardlinks {
            bail!("hardlink creation is not authorized by the signed grant");
        }
        if self.expected_hash(path)?.is_some() || self.expected_hash(source)?.is_some() {
            bail!("expected hashes require their own file publications, not hard links");
        }
        self.check_mutation_path(source, false)?;
        self.check_mutation_path(path, false)?;
        if matches!(condition, proto::TargetCondition::MatchesFingerprint { .. }) {
            bail!("hardlink publication accepts no fingerprint condition");
        }
        self.constrain_creation(path, condition, (false, true), index, pending)?;
        // Keeping existing files, a link replaces nothing, not even a name
        // this grant created, as an honest copy links only new names there.
        // The receiver links to the final name, which the kernel refuses
        // when it exists.
        let keep = self.creation_policy(false) == ExistingDestinationPolicy::Skip;
        if keep {
            *condition = proto::TargetCondition::Absent;
        }
        // The link replaces whatever this grant made at that name, in this
        // request or before, so that name no longer makes a file its own.
        for creation in pending.iter_mut().filter(|creation| creation.path == path) {
            creation.persist = false;
            creation.link = true;
        }
        self.state.lock().unwrap().created.remove(path);
        // A name already linked to the file changes nothing; the copy
        // reports it unchanged, as an ordinary copy does. The link is then
        // held to that file, so that it succeeds only by finding the name
        // still linked, and fails rather than link it again if the name
        // changes first; a failure is recorded.
        let linked = self
            .rooted_metadata(path)?
            .is_some_and(|metadata| (metadata.dev, metadata.ino) == identity);
        if linked && !keep {
            *condition = proto::TargetCondition::Matches {
                dev: identity.0,
                ino: identity.1,
            };
        }
        let path = path.to_vec();
        let change = Change::LinkFile;
        outcomes.push(if linked {
            PendingOutcome::LogicalIfFailed {
                index,
                path,
                change,
            }
        } else {
            PendingOutcome::Logical {
                index,
                path,
                change,
            }
        });
        Ok(())
    }

    pub(super) fn authorize_op(
        &self,
        operation: &mut Op,
        index: usize,
        pending: &mut Vec<PendingCreation>,
        outcomes: &mut Vec<PendingOutcome>,
    ) -> Result<()> {
        if let Op::Hardlink {
            path,
            source,
            dev,
            ino,
            condition,
        } = operation
        {
            return self.authorize_hardlink(
                (&*path, &*source, (*dev, *ino), condition),
                index,
                pending,
                outcomes,
            );
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
            Op::Hardlink { .. } => unreachable!("hardlinks are authorized above"),
            Op::Remove { .. } => {
                bail!("recursive remove is not supported by the root-confined receiver")
            }
            Op::Rmdir { path } => {
                self.check_deletion(path, true)?;
                self.forget_lookup(path);
                outcomes.push(PendingOutcome::Logical {
                    index,
                    path: path.clone(),
                    change: Change::DeleteDirectory,
                });
                return Ok(());
            }
            Op::Unlink { path } => {
                self.check_deletion(path, false)?;
                self.forget_lookup(path);
                outcomes.push(PendingOutcome::Logical {
                    index,
                    path: path.clone(),
                    change: Change::DeleteNonDirectory,
                });
                return Ok(());
            }
        };
        // What a metadata change applies to: a directory's is for nothing
        // else (`Op::SetMeta::directory`). Otherwise it is looked up only
        // where filters or a mapping decide by it; a failure's record looks
        // it up when it is settled.
        let metadata_kind = match operation {
            Op::SetMeta {
                directory: true, ..
            } => Some(proto::Kind::Dir),
            Op::SetMeta { .. } if self.filter_matcher.is_some() || self.mapping.is_some() => Some(
                self.rooted_metadata(path)?
                    .map_or(proto::Kind::File, |metadata| kind_from_mode(metadata.mode)),
            ),
            _ => None,
        };
        let is_dir = match operation {
            Op::Mkdir { .. } => true,
            Op::SetMeta { .. } => metadata_kind == Some(proto::Kind::Dir),
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
            Op::Hardlink { .. } => unreachable!("hardlinks are authorized above"),
            Op::Mkdir {
                path,
                mode,
                condition,
            } => {
                if self.mapping_parent(path)? {
                    // An existing implicit parent may be reopened, but never
                    // replaced or recreated.
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
                } else {
                    self.constrain_creation(path, condition, (true, false), index, pending)?;
                }
                // Creation limits the permission bits; without -p the
                // sender chooses no special bits.
                if !self.copy.options.preserve_permissions {
                    *mode &= 0o777;
                }
                outcomes.push(PendingOutcome::Logical {
                    index,
                    path: path.clone(),
                    change: Change::EnsureDirectory,
                });
                Ok(())
            }
            Op::Symlink {
                path,
                condition,
                meta,
                flags,
                ..
            } => {
                self.constrain_creation(path, condition, (false, true), index, pending)?;
                self.check_metadata(path, meta, *flags)?;
                outcomes.push(PendingOutcome::Logical {
                    index,
                    path: path.clone(),
                    change: Change::CreateSymlink,
                });
                Ok(())
            }
            Op::Mknod {
                path,
                mode,
                condition,
                meta,
                flags,
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
                let permitted = if self.copy.options.preserve_permissions {
                    0o7777
                } else {
                    0o777
                };
                *mode = file_type | (*mode & permitted);
                self.constrain_creation(path, condition, (false, true), index, pending)?;
                self.check_metadata(path, meta, *flags)?;
                outcomes.push(PendingOutcome::Logical {
                    index,
                    path: path.clone(),
                    change: Change::CreateSpecial,
                });
                Ok(())
            }
            Op::SetMeta {
                path,
                meta,
                flags,
                condition,
                directory,
            } => {
                let implicit = self.mapping_parent(path)?;
                if implicit {
                    // A parent has no source metadata. Only a mode the
                    // receiver chooses may be finalized, as when it restores
                    // a parent it widened. Permission preservation on
                    // explicit entries grants no chmod authority over parents.
                    if *flags & !(proto::flags::MODE | proto::flags::RECEIVER_MODE) != 0 {
                        bail!("mapping cannot change metadata of an existing implicit parent");
                    }
                    if *flags != 0 {
                        *flags = proto::flags::RECEIVER_MODE;
                    }
                }
                self.constrain_update(path, Some(&mut *condition), pending, *directory)?;
                if implicit {
                    anyhow::ensure!(
                        meta.inode_metadata.is_none(),
                        "signed grants do not authorize additional inode metadata"
                    );
                } else {
                    self.check_metadata(path, meta, *flags)?;
                }
                outcomes.push(PendingOutcome::Metadata {
                    index,
                    path: path.clone(),
                    kind: metadata_kind,
                });
                Ok(())
            }
            Op::SetFileMetaIfSame {
                path,
                meta,
                flags,
                condition,
            } => {
                self.constrain_update(path, Some(&mut *condition), pending, false)?;
                self.check_metadata(path, meta, *flags)?;
                outcomes.push(PendingOutcome::Logical {
                    index,
                    path: path.clone(),
                    change: Change::SetMetadata {
                        kind: proto::Kind::File,
                    },
                });
                Ok(())
            }
            Op::Remove { .. } | Op::Rmdir { .. } | Op::Unlink { .. } => Ok(()),
        }
    }

    /// Check and rewrite one request against the signed grant. The returned
    /// settlement must be handed back to `settle` with the executor's
    /// response so provisional creations are forgotten when execution fails.
    /// A streamed patch needs its connection's `PatchStreamGate`.
    pub(crate) fn authorize(&self, request: &mut Request, over_ssh: bool) -> Result<Settlement> {
        self.authorize_streaming(request, over_ssh, &mut None, &mut None)
    }

    /// `authorize`, with the streamed patch open on the request's
    /// connection and the small copy prepared there, if any.
    fn authorize_streaming(
        &self,
        request: &mut Request,
        over_ssh: bool,
        stream: &mut Option<OpenPatchStream>,
        small_copy: &mut Option<PreparedSmallCopy>,
    ) -> Result<Settlement> {
        // A prepared small copy ends with its payloads or with the
        // connection's next request but a telemetry sample: then it made
        // no change.
        if !matches!(
            request,
            Request::CopySmallFiles(_) | Request::TransportStats
        ) {
            if let Some(prepared) = small_copy.take() {
                self.settle_unexecuted(
                    prepared.settlement,
                    "the small copy ended without its payloads",
                );
            }
        }
        let mut pending = Vec::new();
        let mut outcomes = Vec::new();
        // Requests the server executes and then settles; the results' end
        // waits for all of them. The others are answered inline without
        // settling. Restoring the destination's ancestors only undoes what
        // this connection widened, and changes nothing the results list.
        let tracked = !matches!(
            request,
            Request::Hello { .. }
                | Request::Scan { .. }
                | Request::TcpListen { .. }
                | Request::TransportStats
                | Request::WriteStreamFence
                | Request::DestinationResults { .. }
                | Request::FinishDestinationResults
                | Request::Shutdown
                | Request::RestoreDestinationPath
        );
        // Admission and closure are decided under one lock: a request either
        // counts as in flight before the results' end can observe the count,
        // or it is refused because the results have ended. Authorization may
        // block afterwards (the file-data limiter, say) without letting the
        // end slip past it.
        {
            let mut state = self.state.lock().unwrap();
            if !self.control_is_open() {
                bail!("transfer control is closed or expired");
            }
            if tracked && state.results_closing {
                bail!("the signed grant is closed: its results have ended");
            }
            if tracked {
                state.in_flight += 1;
            }
        }
        let mut step = StreamStep::None;
        let authorized = self.authorize_inner(request, over_ssh, &mut pending, &mut outcomes);
        let authorized = authorized
            .and_then(|()| self.authorize_stream(request, stream, small_copy, &mut step))
            .and_then(|()| self.charge_request(request));
        match authorized {
            Ok(charged) => Ok(Settlement {
                creations: pending,
                outcomes,
                charged,
                tracked,
                stream: step,
            }),
            Err(error) => {
                // Nothing of a refused request executes, including the
                // entries authorized before the refusing one, or the small
                // copy whose payloads it carries.
                if let StreamStep::CopySmallCopy(prepared) = step {
                    self.settle_unexecuted(*prepared, &format!("{error:#}"));
                }
                self.forget_provisional(&pending);
                self.release_patch_holds(outcomes.into_iter());
                // What it asked for, classified before taking the state lock:
                // classifying may look at the destination.
                // The existing-object policy keeping what the destination
                // holds is no refusal: nothing changed, as the policy asks,
                // and the file this request was for is no longer in flight.
                let kept = KeptExisting::is(&error);
                let changes = if self.results_started.load(Ordering::Acquire) && !kept {
                    self.requested_changes(request)
                } else {
                    Vec::new()
                };
                // Every refusal counts, and lists the changes it refused, as
                // the coordinator could have hidden it. It is recorded before
                // the request stops counting as in flight, so the results
                // cannot end between the two. The state lock is taken before
                // the results lock, as everywhere.
                let mut state = self.state.lock().unwrap();
                if kept {
                    if let Some(key) = file_key(request) {
                        state.file_lifecycles.remove(&key);
                    }
                } else {
                    state.recorded_any = true;
                    if self.results_started.load(Ordering::Acquire) {
                        if let Some(stream) = self.results.lock().unwrap().as_mut() {
                            stream.refused(&format!("refused: {error:#}"), &changes);
                        }
                        self.end_refused_lifecycles(&mut state, request);
                    }
                }
                if tracked {
                    state.in_flight = state.in_flight.saturating_sub(1);
                    self.settled.notify_all();
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
    ) -> Result<()> {
        self.check_deadline()?;
        let bounded_basis = matches!(request, Request::StageBasis { .. });
        match request {
            Request::CreateSendBudget { .. } => {
                bail!("signed copies retain their authorized bandwidth policy");
            }
            Request::ConfigureHashing(policy) => {
                if *policy != self.hash_policy() {
                    bail!("hash policy differs from the authorized copy");
                }
            }
            Request::ValidateDigest { path, expected } => {
                self.check_observation_path(path)?;
                if let Some(authorized) = self.expected_hash(path)? {
                    if *expected != crate::hashing::ExpectedHashes::Single(authorized) {
                        bail!("expected hash differs from the authorized copy");
                    }
                }
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
                send_rate,
            } => {
                anyhow::ensure!(
                    send_rate.is_none(),
                    "signed copies retain their authorized bandwidth policy"
                );
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
            }
            Request::StatMany {
                paths,
                sources,
                follow,
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
            }
            Request::DestinationFilesystemInfo {
                check_empty,
                target,
            } => {
                // What the copy learns of the destination's filesystem is
                // about the directory it writes into, found here: the signed
                // destination when it is a directory, or else the directory
                // it goes into. Only the destination is checked for
                // emptiness.
                let (path, metadata) = match self.rooted_metadata(&self.destination)? {
                    Some(metadata) if metadata.is_dir() => (self.destination.clone(), metadata),
                    _ => {
                        *check_empty = false;
                        let end = self.destination.iter().rposition(|&byte| byte == b'/');
                        let parent = end
                            .map(|end| self.destination[..end].to_vec())
                            .filter(|parent| parent.len() > self.root_path.len())
                            .unwrap_or_else(|| self.root_path.clone());
                        match self.rooted_metadata(&parent)? {
                            Some(metadata) if metadata.is_dir() => (parent, metadata),
                            _ => (
                                self.root_path.clone(),
                                self.rooted_metadata(&self.root_path)?
                                    .context("the directory the destination is in is missing")?,
                            ),
                        }
                    }
                };
                *target = (path != self.root_path).then(|| proto::DestinationFilesystemTarget {
                    relative_path: self
                        .root_relative(&path)
                        .map(|relative| relative.to_bytes())
                        .unwrap_or_default(),
                    dev: metadata.dev,
                    ino: metadata.ino,
                });
            }
            Request::PartialPaths { paths, .. } | Request::PruneLookup { paths } => {
                for path in paths {
                    self.check_observation_path(path)?;
                }
            }
            Request::PlanBatch {
                partial_paths,
                directories,
                others,
                ..
            } => {
                for path in partial_paths
                    .iter()
                    .chain(directories.iter())
                    .chain(others.iter())
                {
                    self.check_observation_path(path)?;
                }
            }
            Request::WidenDirectories {
                directories,
                remember,
                access,
            } => {
                // The approved mode bounds what is widened, and how: `rsync`
                // only the directories the copy includes, for write and
                // search, and read too when the copy prunes and so lists
                // them, never to enter a directory it could not read; `all`
                // also the directory the copy goes into.
                let approved = self.extra_options.widen_dirs;
                match approved {
                    DirectoryWidening::None => {
                        bail!("the approved copy does not widen read-only directories")
                    }
                    DirectoryWidening::Rsync => anyhow::ensure!(
                        *access & !0o300 == 0
                            || *access == 0o700
                                && self.copy.policy.deletion
                                    == DeletionPolicy::DeleteDestinationOnly,
                        "the approved copy widens only directories it includes, as rsync does"
                    ),
                    DirectoryWidening::All => {}
                }
                let outer = (approved == DirectoryWidening::All)
                    .then(|| self.outer_directory())
                    .flatten();
                // The receiver restores what it widened when asked to choose
                // a mode, as it always is for a mapping parent, whose
                // restoration this authority turns into a receiver-chosen mode.
                *remember = true;
                for (index, (path, condition)) in directories.iter_mut().enumerate() {
                    if outer.as_deref() == Some(path.as_slice()) {
                        *condition = self.outer_directory_condition(path, *condition)?;
                        continue;
                    }
                    // Widening is the existing-directory part of EnsureDirectory.
                    // Apply exactly the same signed path/policy/quota checks,
                    // but require an observed directory: this request cannot create.
                    anyhow::ensure!(
                        matches!(
                            condition,
                            proto::TargetCondition::Matches { .. }
                                | proto::TargetCondition::MatchesFingerprint { .. }
                        ),
                        "temporary directory access requires an existing identity"
                    );
                    let mut op = Op::Mkdir {
                        path: path.clone(),
                        mode: 0o700,
                        condition: *condition,
                    };
                    self.authorize_op(&mut op, index, pending, outcomes)?;
                    let Op::Mkdir {
                        condition: authorized,
                        ..
                    } = op
                    else {
                        unreachable!()
                    };
                    *condition = authorized;
                }
            }
            Request::PrepareDestinationPath {
                path,
                symlink_policy,
                ..
            } => {
                // Only an approved `all` widens the directories on the way to
                // the destination, and only from the confinement root down: the
                // walk goes to the signed destination, beneath that root, and
                // follows no symlink.
                anyhow::ensure!(
                    self.extra_options.widen_dirs == DirectoryWidening::All,
                    "the approved copy does not widen the directories on the way to its destination"
                );
                self.check_mutation_allowed()?;
                if path.starts_with(b"/") {
                    let root = &self.root_path;
                    anyhow::ensure!(
                        path != root && path_is_at_or_below(path, root),
                        "nothing above the directory the destination is in is widened"
                    );
                }
                *path = self.destination.clone();
                *symlink_policy = proto::OperatorSymlinkPolicy::Refuse;
            }
            // It restores only what the request above changed.
            Request::RestoreDestinationPath => {}
            Request::Apply { ops } => {
                let outer = (self.extra_options.widen_dirs == DirectoryWidening::All)
                    .then(|| self.outer_directory())
                    .flatten();
                for (index, operation) in ops.iter_mut().enumerate() {
                    // The directory the copy goes into lies outside the signed
                    // scopes. Under an approved `all` its metadata can only be
                    // the receiver's choice: the mode it had before this
                    // connection widened it, or else its own.
                    if let Op::SetMeta { path, flags, .. } = operation {
                        if outer.as_deref() == Some(path.as_slice()) {
                            *flags = proto::flags::RECEIVER_MODE;
                            continue;
                        }
                    }
                    self.authorize_op(operation, index, pending, outcomes)?;
                }
            }
            Request::ProbePartial { path, .. } | Request::Canonicalize { path } => {
                self.check_observation_path(path)?;
            }
            Request::FileHash { path, source } => {
                if source.is_some() {
                    bail!("source references are not valid on a command-restricted destination");
                }
                self.check_observation_path(path)?;
            }
            Request::HashBlocks {
                path,
                source,
                block,
                len,
                ..
            } => {
                if source.is_some() {
                    bail!("source references are not valid on a command-restricted destination");
                }
                self.check_hash_request(*block, *len)?;
                self.check_observation_path(path)?;
            }
            Request::HashWindow {
                path,
                off,
                len,
                block,
                ..
            } => {
                anyhow::ensure!(
                    crate::proto::hash_window_fits(*off, *len, *block),
                    "invalid hash window"
                );
                self.check_observation_path(path)?;
            }
            Request::HashAndHold {
                path, block, len, ..
            } => {
                self.check_hash_request(*block, *len)?;
                self.check_observation_path(path)?;
            }
            // Each file is observed as HashAndHold observes one, and the
            // hashes of the whole batch share one response.
            Request::HashExistingBatch { block, files } => {
                for file in files.iter() {
                    self.check_comparison_request(*block, file.len)?;
                }
                if !proto::existing_hashes_fit(*block, files.iter().map(|file| file.len)) {
                    bail!("hash response would exceed protocol limits");
                }
                for file in files.iter_mut() {
                    self.check_observation_path(&file.path)?;
                }
            }
            Request::StageBasis {
                path,
                copy_id,
                len,
                block,
                ..
            }
            | Request::SeedBasis {
                path,
                copy_id,
                len,
                block,
                ..
            } => {
                self.check_hash_request(*block, if bounded_basis { 0 } else { *len })?;
                self.require_publication_mode(false, "staged basis creation")?;
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
                    size: Some(*len),
                    stage: FileStage::Prepare,
                    skip_if_absent: false,
                    observation_hold: None,
                });
            }
            Request::FinishBasis {
                expected_hash,
                path,
                meta,
                flags,
                condition,
                ..
            } => {
                *expected_hash = self.expected_hash(path)?.map(Into::into);
                self.check_mutation_path(path, false)?;
                self.constrain_update(path, Some(&mut *condition), pending, false)?;
                self.check_metadata(path, meta, *flags)?;
                outcomes.push(PendingOutcome::Logical {
                    index: 0,
                    path: path.clone(),
                    change: Change::KeepFile,
                });
            }
            Request::Prepare {
                path,
                size,
                inplace,
                copy_id,
                mode,
                flags,
                scanned,
                create_if_missing,
                update,
                ..
            } => {
                // The receiver looks for itself at what a file replaces: a
                // sender's word could give an existing file a new mode.
                *scanned = proto::ScannedDestination::Unknown;
                self.require_publication_mode(*inplace, "file preparation")?;
                // An existing file is updated in place only under a grant
                // for it, and only with metadata the grant allows, which
                // finalization checks again.
                if let Some(update) = update {
                    if !*inplace
                        || !self
                            .copy
                            .policy
                            .publication
                            .updates_existing_files_in_place()
                    {
                        bail!("file preparation does not match the signed publication policy");
                    }
                    self.check_metadata(path, &update.meta, update.flags)?;
                }
                self.check_preparation_flags(path, *mode, *flags)?;
                if *size > self.copy.limits.max_file_bytes {
                    bail!("signed grant per-file byte limit exceeded");
                }
                self.check_mutation_path(path, false)?;
                if *inplace {
                    self.constrain_inplace(path, *create_if_missing)?;
                }
                self.constrain_prepare(path)?;
                let observation_hold =
                    self.reserve_bytes(path, *copy_id, *size, !*create_if_missing)?;
                outcomes.push(PendingOutcome::FileStage {
                    index: 0,
                    path: path.clone(),
                    copy_id: *copy_id,
                    size: Some(*size),
                    stage: FileStage::Prepare,
                    skip_if_absent: !*create_if_missing,
                    observation_hold,
                });
            }
            Request::ReuseComparedRange {
                path,
                copy_id,
                off,
                len,
                ..
            } => {
                self.require_publication_mode(false, "staged block reuse")?;
                self.check_mutation_path(path, false)?;
                // The receiver writes only within the size declared for the
                // file it holds (`fsops::stages`).
                anyhow::ensure!(
                    *len > 0 && off.checked_add(u64::from(*len)).is_some(),
                    "invalid reused block"
                );
                outcomes.push(PendingOutcome::FileStage {
                    index: 0,
                    path: path.clone(),
                    copy_id: *copy_id,
                    size: None,
                    stage: FileStage::Write,
                    skip_if_absent: false,
                    observation_hold: None,
                });
                // No payload crossed the transport. Logical file capacity was
                // reserved by StageBasis, just as for a native cloned basis.
            }
            Request::WriteRange {
                path,
                inplace,
                copy_id,
                off,
                data,
                ..
            } => {
                // The receiver writes only within the size declared for the
                // file it holds (`fsops::stages`).
                self.require_publication_mode(*inplace, "file write")?;
                outcomes.push(PendingOutcome::FileStage {
                    index: 0,
                    path: path.clone(),
                    copy_id: *copy_id,
                    size: None,
                    stage: FileStage::Write,
                    skip_if_absent: false,
                    observation_hold: None,
                });
                self.check_file_bytes(path, *off, data.len())?;
            }
            Request::Finalize {
                expected_hash,
                path,
                inplace,
                copy_id,
                meta,
                flags,
                scanned,
                condition,
                ..
            } => {
                // The receiver looks for itself, and knows the in-place
                // files it opened: all of the copy's connections are in its
                // process.
                *scanned = proto::ScannedDestination::Unknown;
                *expected_hash = self.expected_hash(path)?.map(Into::into);
                self.require_publication_mode(*inplace, "file finalization")?;
                self.check_mutation_path(path, false)?;
                *scanned = self.constrain_publication(path, condition, *inplace, 0, pending)?;
                outcomes.push(PendingOutcome::FileStage {
                    index: 0,
                    path: path.clone(),
                    copy_id: *copy_id,
                    size: None,
                    stage: FileStage::Finalize,
                    skip_if_absent: false,
                    observation_hold: None,
                });
                self.check_metadata(path, meta, *flags)?;
            }
            Request::PutSmallBatch(puts) => {
                if puts.iter().any(|put| put.inplace) {
                    self.require_publication_mode(true, "small-file publication")?;
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
                    // As for `Prepare`, the receiver looks for itself
                    // unless it knows (`constrain_publication`).
                    put.scanned = proto::ScannedDestination::Unknown;
                    if self.expected_hash(&put.path)?.is_some() {
                        bail!("expected-hash files require checked finalization");
                    }
                    self.check_file_bytes(&put.path, 0, put.data.len())?;
                    if put.inplace {
                        self.constrain_inplace(&put.path, true)?;
                    }
                    put.scanned = self.constrain_publication(
                        &put.path,
                        &mut put.condition,
                        put.inplace,
                        index,
                        pending,
                    )?;
                    outcomes.push(PendingOutcome::Logical {
                        index,
                        path: put.path.clone(),
                        change: Change::PublishFile {
                            size: put.data.len() as u64,
                        },
                    });
                    self.check_metadata(&put.path, &put.meta, put.flags)?;
                }
            }
            Request::PatchSmallBatch(patches) => {
                let first = outcomes.len();
                if let Err(error) = self.authorize_patches(patches, pending, outcomes) {
                    // A refused batch executes nothing: release the sizes
                    // its patches already hold.
                    self.release_patch_holds(outcomes.drain(first..));
                    return Err(error);
                }
            }
            // A streamed patch passes every rule a patch of a batch does. Its
            // pieces and end are checked against it in `authorize_stream`.
            Request::PatchBegin { patch, data_len } => {
                if !patch.data.is_empty() {
                    bail!("a streamed patch carries its data in pieces");
                }
                if patch.update_in_place {
                    bail!("a streamed patch is staged, not written in place");
                }
                self.check_comparison_request(patch.block, patch.len)?;
                let blocks = patch.len.div_ceil(patch.block);
                if patch.reuse.len() as u64 != blocks {
                    bail!(
                        "streamed patch lists {} blocks, not {blocks}",
                        patch.reuse.len()
                    );
                }
                let new = patch.new_bytes();
                if *data_len == 0 || *data_len != new {
                    bail!("streamed patch declares {data_len} new bytes for blocks of {new} bytes");
                }
                let first = outcomes.len();
                let patches = std::slice::from_mut(&mut **patch);
                if let Err(error) = self.authorize_patches(patches, pending, outcomes) {
                    self.release_patch_holds(outcomes.drain(first..));
                    return Err(error);
                }
            }
            Request::PatchData { .. } | Request::PatchEnd { .. } => {}
            Request::CopyLocal { .. }
            | Request::ReadRange { .. }
            | Request::ReadComparedRange { .. }
            | Request::ReadStream(_)
            | Request::ShrinkReadStream { .. }
            | Request::StopReadStream
            | Request::ReadSmallBatch(_)
            | Request::ReadDifferingBatch { .. } => {
                bail!("request is not valid on a command-restricted destination")
            }
            Request::PrepareSmallFiles(request) => self.authorize_small_copy(request, outcomes)?,
            // Held to its preparation in `authorize_stream`.
            Request::CopySmallFiles(_) => {}
            Request::ListDir { .. }
            | Request::ListDirDetails { .. }
            | Request::ListDirNoFollowFinal { .. } => {
                bail!("directory completion is not valid on a command-restricted destination")
            }
            Request::CheckOperatorDirectory { .. }
            | Request::CheckOperatorDirectoryAncestry { .. }
            | Request::CheckOperatorDirectoryAncestryWithAccess { .. }
            | Request::CheckSearchableOperatorDirectory { .. }
            | Request::RegisterSourceRoots { .. }
            | Request::CreateOperatorDirectory { .. }
            | Request::AnchorDestination { .. } => {
                bail!("destination-anchor management is not valid on a root-confined receiver")
            }
            Request::NativeMap(_) => {
                bail!("mapping generation is not valid on a command-restricted destination")
            }
            Request::NativeRemove { .. } => {
                bail!("native removal is not valid on a command-restricted destination")
            }
            Request::ConfigurePreservation {
                selection,
                sparse,
                narrow_new_directories,
                unchecked_keep,
                ..
            } => {
                // Every no-replace publication a grant sets is held.
                if *unchecked_keep {
                    bail!("a command-restricted receiver keeps existing files atomically");
                }
                if *narrow_new_directories
                    || (*sparse && !self.extra_options.sparse)
                    || !self.extra_options.allows(*selection)
                {
                    bail!("inode metadata or read policy is not authorized by the signed grant");
                }
            }
            Request::DescriptorCopy(_) | Request::BindStream(_) => {
                bail!("descriptor copies are not valid on a command-restricted receiver")
            }
            Request::Hello { .. } => bail!("unexpected second receiver handshake"),
            Request::DestinationResults { .. } | Request::FinishDestinationResults => {
                if !over_ssh {
                    bail!("destination results run only on the signed control connection");
                }
            }
            Request::NewFileOwner { path, probe } => {
                // A probe the receiver creates to learn whom its files show
                // stays inside the destination and is removed at once, and
                // is made only while the grant allows changes.
                self.check_observation_path(path)?;
                if self.check_mutation_allowed().is_err() {
                    *probe = false;
                }
            }
            Request::TransportStats
            | Request::ReceiverUser
            | Request::Shutdown
            | Request::WriteStreamFence => {}
        }
        Ok(())
    }
}

/// What an authorized request recorded provisionally: creations, keyed by
/// the operation or small-put index the executor reports on, and the
/// changes the results report once the executor confirms them.
#[derive(Debug, Default)]
pub(crate) struct Settlement {
    pub(super) creations: Vec<PendingCreation>,
    pub(super) outcomes: Vec<PendingOutcome>,
    /// What the request counted against the signed limits.
    pub(super) charged: Charged,
    /// The request counts as in flight until settled.
    pub(super) tracked: bool,
    /// Where the request leaves its connection's streamed patch.
    pub(super) stream: StreamStep,
}

/// The changes a request counted against the entry limit, and which of its
/// operations, by index, counted as deletions (`charge_request`).
#[derive(Debug, Default)]
pub(super) struct Charged {
    changes: u64,
    deleting: Vec<usize>,
    /// The file whose shared count against the entry limit this request
    /// holds until it settles (`EntryCharge`).
    file: Option<FileShare>,
}

/// A file's reservation key and which reservation of it a request shares
/// (`ByteReservation::instance`).
type FileShare = ((Vec<u8>, proto::CopyId), u64);

/// What a request does to its connection's streamed patch.
#[derive(Debug, Default)]
pub(super) enum StreamStep {
    #[default]
    None,
    /// Begin a patch whose pieces carry `declared` new bytes.
    Begin {
        path: Vec<u8>,
        declared: u64,
    },
    End,
    /// Prepare a small copy of files of these sizes.
    PrepareSmallCopy {
        sizes: Vec<u64>,
    },
    /// Send the prepared small copy's payloads; its preparation settles
    /// with their reply.
    CopySmallCopy(Box<Settlement>),
}

/// A small copy prepared on one connection, waiting for its payloads: the
/// files its preparation asked for, and that preparation's settlement,
/// which the payloads' reply settles. Until then it counts as in flight.
#[derive(Debug)]
pub(crate) struct PreparedSmallCopy {
    sizes: Vec<u64>,
    needed: Vec<bool>,
    settlement: Settlement,
}

/// A streamed patch open on one connection: the new data its pieces may
/// still carry, and its begin's settlement, which its end settles with the
/// patch's outcome. Until then the patch counts as in flight, as a batch
/// patch does until its reply.
#[derive(Debug)]
pub(crate) struct OpenPatchStream {
    path: Vec<u8>,
    declared: u64,
    received: u64,
    settlement: Settlement,
}

/// The streamed patch open on one receiver connection, if any. A connection
/// that closes with one open settles it as a failed publication.
pub(crate) struct PatchStreamGate {
    authority: std::sync::Arc<RestrictedAuthority>,
    open: Option<OpenPatchStream>,
    small_copy: Option<PreparedSmallCopy>,
}

impl PatchStreamGate {
    pub(crate) fn new(authority: std::sync::Arc<RestrictedAuthority>) -> Self {
        Self {
            authority,
            open: None,
            small_copy: None,
        }
    }

    pub(crate) fn is_open(&self) -> bool {
        self.open.is_some()
    }

    /// `RestrictedAuthority::authorize`, for a request on this connection.
    pub(crate) fn authorize(
        &mut self,
        request: &mut Request,
        over_ssh: bool,
    ) -> Result<Settlement> {
        self.authority
            .authorize_streaming(request, over_ssh, &mut self.open, &mut self.small_copy)
    }

    /// Settle an executed request. A begin whose patch the executor left
    /// `opened` is held until its end, and the end settles both.
    pub(crate) fn settle(
        &mut self,
        mut settlement: Settlement,
        response: &proto::Response,
        opened: bool,
    ) {
        match std::mem::take(&mut settlement.stream) {
            StreamStep::Begin { path, declared } if opened => {
                self.open = Some(OpenPatchStream {
                    path,
                    declared,
                    received: 0,
                    settlement,
                });
            }
            StreamStep::End => {
                self.authority.settle(settlement, response);
                if let Some(open) = self.open.take() {
                    self.authority.settle(open.settlement, response);
                }
            }
            StreamStep::PrepareSmallCopy { sizes } => match response {
                proto::Response::SmallFilesPrepared(needed) if needed.len() == sizes.len() => {
                    self.small_copy = Some(PreparedSmallCopy {
                        sizes,
                        needed: needed.clone(),
                        settlement,
                    });
                }
                _ => self.authority.settle(settlement, response),
            },
            StreamStep::CopySmallCopy(prepared) => {
                self.authority.settle(settlement, response);
                self.authority.settle(*prepared, response);
            }
            _ => self.authority.settle(settlement, response),
        }
    }

    /// Settle the open streamed patch as failed with `error`, as when its
    /// end was refused or its connection closed first.
    pub(crate) fn abandon(&mut self, error: &str) {
        if let Some(open) = self.open.take() {
            self.authority.settle(
                open.settlement,
                &proto::Response::PatchedBatch(vec![Err(proto::SmallPatchError {
                    error: error.to_string().into(),
                    matched: false,
                    stale_condition: false,
                    written: false,
                })]),
            );
        }
    }
}

impl Drop for PatchStreamGate {
    fn drop(&mut self) {
        self.abandon("the connection closed before its streamed patch ended");
        if let Some(prepared) = self.small_copy.take() {
            self.authority.settle_unexecuted(
                prepared.settlement,
                "the connection closed before the small copy's payloads",
            );
        }
    }
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

/// A file whose writing has begun under the results stream and which has not
/// been published.
#[derive(Debug)]
pub(super) struct FileLifecycle {
    pub(super) size: u64,
    pub(super) last_error: Option<String>,
    /// The error class of `last_error`, as `destination_results::Failure`
    /// carries it.
    pub(super) last_class: &'static str,
    /// A refusal already listed it as failed: the end does not list it again.
    pub(super) listed: bool,
}

/// One change a request makes, reported by `settle` once the executor
/// confirms it.
#[derive(Debug)]
pub(super) enum PendingOutcome {
    Logical {
        index: usize,
        path: Vec<u8>,
        change: Change,
    },
    /// A metadata change, whose kind is looked up if it fails and was not
    /// known when it was authorized.
    Metadata {
        index: usize,
        path: Vec<u8>,
        kind: Option<proto::Kind>,
    },
    /// An operation expected to change nothing, recorded only if it fails.
    LogicalIfFailed {
        index: usize,
        path: Vec<u8>,
        change: Change,
    },
    FileStage {
        index: usize,
        path: Vec<u8>,
        copy_id: proto::CopyId,
        /// The size a preparation declares; writes and finalization leave
        /// the declared size as it is.
        size: Option<u64>,
        stage: FileStage,
        /// Ignore a successful observation-only Prepare when it found no
        /// resumable sidecar and therefore performed no lifecycle mutation.
        skip_if_absent: bool,
        /// This observation-only Prepare's provisional reservation. Settlement
        /// releases or retains precisely this hold without affecting a
        /// concurrent preparation for the same partial.
        observation_hold: Option<ReservationHoldId>,
    },
    /// A file of the small-copy shortcut, which the executor reports as
    /// published, kept with its metadata changed or not, or excluded.
    SmallCopy {
        index: usize,
        path: Vec<u8>,
        size: u64,
    },
    /// A small-file patch, which the executor reports as kept or published.
    Patch {
        index: usize,
        path: Vec<u8>,
        copy_id: proto::CopyId,
        size: u64,
        /// The size a publication occupies, held until the reply.
        hold: Option<ReservationHoldId>,
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
    /// The name a hard link made, for a file that may already have been
    /// there: never the grant's own, even later in its own request.
    pub(super) link: bool,
}

/// The file a request writes, by destination path and partial.
fn file_key(request: &Request) -> Option<(Vec<u8>, proto::CopyId)> {
    match request {
        Request::Prepare { path, copy_id, .. }
        | Request::StageBasis { path, copy_id, .. }
        | Request::SeedBasis { path, copy_id, .. }
        | Request::WriteRange { path, copy_id, .. }
        | Request::ReuseComparedRange { path, copy_id, .. }
        | Request::Finalize { path, copy_id, .. } => Some((path.clone(), *copy_id)),
        _ => None,
    }
}

/// A request the grant's existing-object policy declines because of what
/// the destination holds now: a name that is taken where only new objects
/// are made, or an object gone or replaced where only existing ones are
/// changed. Nothing is changed, and the existing object is kept, as the
/// policy asks; it is not reported as a refusal.
#[derive(Debug)]
pub(crate) struct KeptExisting(String);

impl std::fmt::Display for KeptExisting {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for KeptExisting {}

fn kept(message: String) -> anyhow::Error {
    KeptExisting(message).into()
}

impl KeptExisting {
    /// Whether `error` is one.
    pub(crate) fn is(error: &anyhow::Error) -> bool {
        error
            .chain()
            .any(|cause| cause.downcast_ref::<KeptExisting>().is_some())
    }
}

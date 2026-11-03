use super::*;

/// Owner search permission added only while checking a selected destination,
/// to directories the copy itself would widen. Restore through the same
/// handles before replying, including when ancestry rejects the copy.
#[derive(Default)]
pub(crate) struct TemporaryDirectorySearchAccess {
    enabled: bool,
    /// A directory outside the copy, such as the parent of an exact
    /// placement, whose mode must not change.
    protected: Option<(u64, u64)>,
    changed: Vec<(File, u32)>,
}

impl TemporaryDirectorySearchAccess {
    pub(crate) fn new(enabled: bool, protected: Option<(u64, u64)>) -> Self {
        Self {
            enabled,
            protected,
            changed: Vec::new(),
        }
    }

    pub(super) fn prepare(&mut self, directory: &File) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        self.widen(directory, 0o100).map(|_| ())
    }

    /// Add the owner permission `bits` to `directory` when the receiving
    /// user owns it and it lacks them, and report whether its mode changed.
    fn widen(&mut self, directory: &File, bits: u32) -> Result<bool> {
        let metadata = directory.metadata()?;
        if is_superuser()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & bits == bits
            || self.protected == Some((metadata.dev(), metadata.ino()))
        {
            return Ok(false);
        }
        anyhow::ensure!(
            metadata.is_dir(),
            "temporary search access requires a directory"
        );
        // Clone and reserve before chmod so a descriptor-limit or allocation
        // failure cannot leave an unrecorded permission change behind.
        let retained = directory.try_clone()?;
        self.changed.try_reserve(1)?;
        set_mode_handle(&retained, metadata.mode() | bits)?;
        self.changed.push((retained, metadata.mode() & 0o7777));
        Ok(true)
    }

    /// Open `name` beneath `directory`, adding search permission to
    /// `directory` once if the kernel denies the lookup.
    fn open(&mut self, directory: &File, name: &[u8]) -> Result<File> {
        match open_operator_directory_at(directory, name) {
            Err(error)
                if self.enabled && error_is_kind(&error, io::ErrorKind::PermissionDenied) =>
            {
                self.prepare(directory)?;
                open_operator_directory_at(directory, name)
            }
            result => result,
        }
    }

    pub(crate) fn restore(&mut self) -> Result<()> {
        let mut failure = None;
        while let Some((directory, mode)) = self.changed.pop() {
            if let Err(error) = set_mode_handle(&directory, mode) {
                failure.get_or_insert_with(|| {
                    error.context("restore directory permissions after destination inspection")
                });
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

/// For `--widen-dirs=all`: give each owned directory on the way to `path`
/// the owner search permission looking it up needs and, when
/// `create_missing` and part of the path is missing, the nearest existing
/// one owner write and search permission to create the rest. `access` keeps
/// every change until it restores them. A path that does not resolve is
/// left for the copy itself to report.
pub(crate) fn prepare_destination_path(
    path: &[u8],
    symlink_policy: OperatorSymlinkPolicy,
    create_missing: bool,
    access: &mut TemporaryDirectorySearchAccess,
) -> Result<()> {
    let path = resolve(path);
    let path = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()?.join(path)
    };
    prepare_resolved_path(create_missing, access, |search| {
        OperatorResolver::resolve_process_with_search(
            path.as_os_str().as_bytes(),
            symlink_policy,
            OperatorFinalComponent::Entry {
                follow_symlink: false,
            },
            true,
            &mut Vec::new(),
            search,
        )
    })
}

/// The same for `relative` beneath `root`, the confinement root of a restricted
/// receiver: nothing above `root` is looked up or widened, and no symlink is
/// followed. `root` itself may gain search permission.
pub(crate) fn prepare_destination_path_beneath(
    root: &File,
    relative: &[u8],
    create_missing: bool,
    access: &mut TemporaryDirectorySearchAccess,
) -> Result<()> {
    let resolver = OperatorResolver::beneath(root, true, OperatorSymlinkPolicy::Refuse)?;
    prepare_resolved_path(create_missing, access, |search| {
        resolver.resolve_with_search(
            relative,
            OperatorFinalComponent::Entry {
                follow_symlink: false,
            },
            true,
            &mut Vec::new(),
            search,
        )
    })
}

fn prepare_resolved_path(
    create_missing: bool,
    access: &mut TemporaryDirectorySearchAccess,
    resolve: impl FnOnce(&mut dyn FnMut(&File) -> Result<bool>) -> Result<PinnedPath>,
) -> Result<()> {
    let mut failure = None;
    let resolved = resolve(&mut |directory| match access.widen(directory, 0o100) {
        Ok(changed) => Ok(changed),
        Err(error) => {
            failure = Some(error);
            Ok(false)
        }
    });
    if let Some(error) = failure {
        return Err(error.context("give a destination ancestor search permission"));
    }
    if let (Ok(PinnedPath::Missing(missing)), true) = (resolved, create_missing) {
        let (directory, _) = missing.into_parts();
        access
            .widen(&directory, 0o300)
            .context("give a destination ancestor write permission")?;
    }
    Ok(())
}

impl Drop for TemporaryDirectorySearchAccess {
    fn drop(&mut self) {
        if let Err(error) = self.restore() {
            crate::output::diagnostic!("syq: {error:#}");
        }
    }
}

/// Completion follows the same operator-path symlink policy as the command.
/// Keep the explicit root check even when following symlinks is requested.
pub(crate) fn check_completion_directory(
    directory: &[u8],
    confined_root: Option<&[u8]>,
    symlink_policy: OperatorSymlinkPolicy,
) -> Result<()> {
    let path = resolve(directory);
    OperatorResolver::resolve_process(
        path.as_os_str().as_bytes(),
        symlink_policy,
        OperatorFinalComponent::Directory,
        false,
        &mut Vec::new(),
    )?;
    if let Some(root) = confined_root {
        let root = std::fs::canonicalize(resolve(root))?;
        let directory = std::fs::canonicalize(path)?;
        if !directory.starts_with(root) {
            bail!("completion directory is outside the requested root");
        }
    }
    Ok(())
}

/// A receiver-side selection retained from the ownership walk until it is
/// either created or made the connection's working directory. Keeping the fd,
/// rather than just its identity, closes the post-check pathname race.
pub(super) struct OperatorDirectorySelection {
    pub(super) path: PathBytes,
    pub(super) directory: File,
    pub(super) missing: VecDeque<Vec<u8>>,
}

impl OperatorDirectorySelection {
    pub(super) fn anchor(&self) -> Result<DirectoryAnchor> {
        let metadata = self.directory.metadata()?;
        Ok(DirectoryAnchor {
            path: self.path.clone(),
            dev: metadata.dev(),
            ino: metadata.ino(),
            needs_owner_access: !is_superuser()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o700 != 0o700,
        })
    }

    /// Create the missing components, the last with `mode`. Also returns
    /// whether this call created the last component, rather than finding a
    /// directory there.
    pub(super) fn create_missing(
        &mut self,
        mode: u32,
        require_absent: bool,
    ) -> Result<(DirectoryAnchor, bool)> {
        let mut created = false;
        while let Some(component) = self.missing.pop_front() {
            if component == b"." {
                continue;
            }
            if component == b".." {
                self.directory = open_operator_directory_at(&self.directory, b"..")?;
                continue;
            }
            let final_component = self.missing.is_empty();
            match operator_lstat_at(&self.directory, &component) {
                Ok(metadata)
                    if metadata.st_mode & libc::S_IFMT == libc::S_IFDIR
                        && !(final_component && require_absent) => {}
                Ok(metadata) if metadata.st_mode & libc::S_IFMT == libc::S_IFDIR => {
                    return Err(appeared_after_precondition())
                }
                Ok(_) => bail!(
                    "destination path component {:?} appeared with an unsafe type while creating the destination",
                    OsStr::from_bytes(&component)
                ),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    // Match create_dir_all's historical behavior: intermediate
                    // components start at 0777 (subject to umask), while the
                    // requested mode applies to the selected destination root.
                    let component_mode = if self.missing.is_empty() { mode } else { 0o777 };
                    match mkdir_operator_directory_at(
                        &self.directory,
                        &component,
                        component_mode,
                    ) {
                        Ok(()) if final_component => {
                            created = true;
                            apply::hold_after_directory_creation_for_test(Path::new(
                                OsStr::from_bytes(&self.path),
                            ))?;
                        }
                        Ok(()) => {}
                        Err(error)
                            if error.kind() == io::ErrorKind::AlreadyExists
                                && final_component
                                && require_absent =>
                        {
                            return Err(appeared_after_precondition())
                        }
                        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                            match operator_lstat_at(&self.directory, &component) {
                                Ok(metadata)
                                    if metadata.st_mode & libc::S_IFMT == libc::S_IFDIR => {}
                                Ok(_) => bail!(
                                    "destination path component {:?} appeared with an unsafe type while creating the destination",
                                    OsStr::from_bytes(&component)
                                ),
                                Err(error) => return Err(error.into()),
                            }
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
                Err(error) => return Err(error.into()),
            }
            self.directory = open_operator_directory_at(&self.directory, &component)?;
        }
        Ok((self.anchor()?, created))
    }

    /// Compare an effective directory beneath this retained operator
    /// selection with an exact opened source directory.
    #[cfg(test)]
    pub(super) fn relation_to_source(
        &self,
        source: &File,
        suffix: &[u8],
    ) -> Result<DirectoryRelation> {
        let mut access = TemporaryDirectorySearchAccess::default();
        let mut ancestry = DirectoryAncestry::new(self, &mut access);
        let mut source = AncestrySource::new(source.try_clone()?, true)?;
        let destination = ancestry.resolve(suffix)?;
        ancestry.relation(&mut source, destination)
    }

    /// Whether the copy may widen the selected directory itself: not when it
    /// is the nearest existing ancestor of a missing destination.
    pub(super) fn protected_identity(&self, selection_in_copy: bool) -> Result<Option<(u64, u64)>> {
        if selection_in_copy && self.missing.is_empty() {
            return Ok(None);
        }
        let metadata = self.directory.metadata()?;
        Ok(Some((metadata.dev(), metadata.ino())))
    }
}

/// Device and inode of an open directory.
type Identity = (u64, u64);

fn identity(metadata: &fs::Metadata) -> Identity {
    (metadata.dev(), metadata.ino())
}

/// Compares exact source directories with effective destination directories
/// beneath one retained operator selection. Each destination spelling is
/// walked once, and each source's ancestors at most once, however many pairs
/// are compared; the identities those walks gather decide every relation. The
/// source descriptors stay open for the whole query, so device/inode reuse
/// cannot turn a comparison into pathname authority.
pub(super) struct DirectoryAncestry<'a> {
    selection: &'a OperatorDirectorySelection,
    access: &'a mut TemporaryDirectorySearchAccess,
    destinations: Vec<EffectiveDirectory>,
    by_suffix: HashMap<PathBytes, usize>,
}

/// The walk from the selection through one suffix, then up to the root.
struct EffectiveDirectory {
    /// Every component exists as a directory. Otherwise the copy would create
    /// the rest beneath the directory the walk reached.
    exists: bool,
    /// The directory the walk reached, then each parent up to the root, as
    /// far as the walk got.
    chain: Vec<Identity>,
    /// The walk up reached the root. Otherwise it failed with `error`.
    finished: bool,
    error: Option<anyhow::Error>,
}

impl EffectiveDirectory {
    /// The relation of a source on this chain: an existing destination is the
    /// source itself, and anything else lies beneath it.
    fn relation_to(&self, source: Identity) -> Option<DirectoryRelation> {
        let position = self.chain.iter().position(|&found| found == source)?;
        Some(if position == 0 && self.exists {
            DirectoryRelation::Same
        } else {
            DirectoryRelation::Descendant
        })
    }

    fn failure(&mut self) -> anyhow::Error {
        self.error
            .take()
            .unwrap_or_else(|| anyhow!("walk effective destination ancestry failed"))
    }
}

/// An exact source directory; an exact file or symlink is represented by its
/// parent.
struct AncestrySource {
    directory: File,
    identity: Identity,
    is_directory: bool,
    ancestors: Option<SourceAncestors>,
}

/// A source's ancestors, from its parent up, as far as the walk got.
struct SourceAncestors {
    identities: Vec<Identity>,
    end: AncestorsEnd,
}

enum AncestorsEnd {
    Root,
    Unsearchable,
    Failed(Option<anyhow::Error>),
}

impl AncestrySource {
    fn new(directory: File, is_directory: bool) -> Result<Self> {
        let metadata = directory
            .metadata()
            .context("inspect source directory capability")?;
        if !metadata.is_dir() {
            bail!("destination ancestry source capability is not a directory");
        }
        Ok(Self {
            directory,
            identity: identity(&metadata),
            is_directory,
            ancestors: None,
        })
    }

    /// Walked once, on first need. Source permissions are never changed.
    fn ancestors(&mut self) -> &mut SourceAncestors {
        let (directory, identity) = (&self.directory, self.identity);
        self.ancestors.get_or_insert_with(|| {
            let (identities, error) =
                ancestors_from(open_operator_directory_at(directory, b".."), identity);
            let end = match error {
                None => AncestorsEnd::Root,
                Some(error) if error_is_kind(&error, io::ErrorKind::PermissionDenied) => {
                    AncestorsEnd::Unsearchable
                }
                Some(error) => AncestorsEnd::Failed(Some(error)),
            };
            SourceAncestors { identities, end }
        })
    }

    /// How a destination not on the source's ancestry relates to it once the
    /// walk up from the source has passed every ancestor it could reach.
    fn beyond_ancestors(&mut self) -> Result<DirectoryRelation> {
        match &mut self.ancestors().end {
            AncestorsEnd::Root => Ok(DirectoryRelation::Separate),
            AncestorsEnd::Unsearchable => Ok(DirectoryRelation::SourceUnsearchable),
            AncestorsEnd::Failed(error) => Err(error
                .take()
                .unwrap_or_else(|| anyhow!("walk source directory ancestry failed"))),
        }
    }

    /// An exact file's parent that is the destination puts the file in it,
    /// and a destination beneath that parent cannot contain the file.
    fn as_seen(&self, relation: DirectoryRelation) -> DirectoryRelation {
        match relation {
            _ if self.is_directory => relation,
            DirectoryRelation::Same => DirectoryRelation::Ancestor,
            DirectoryRelation::Descendant => DirectoryRelation::Separate,
            other => other,
        }
    }
}

/// Identities from `parent`, the opened parent of the directory `child`, up to
/// the root, and the error that stopped the walk below the root.
fn ancestors_from(
    mut parent: Result<File>,
    mut child: Identity,
) -> (Vec<Identity>, Option<anyhow::Error>) {
    let mut identities = Vec::new();
    loop {
        let step = parent
            .context("walk effective destination ancestry")
            .and_then(|parent| {
                let metadata = parent
                    .metadata()
                    .context("inspect effective destination parent")?;
                Ok((parent, identity(&metadata)))
            });
        match step {
            Err(error) => return (identities, Some(error)),
            Ok((_, found)) if found == child => return (identities, None),
            Ok((directory, found)) => {
                identities.push(found);
                child = found;
                parent = open_operator_directory_at(&directory, b"..");
            }
        }
    }
}

impl<'a> DirectoryAncestry<'a> {
    pub(super) fn new(
        selection: &'a OperatorDirectorySelection,
        access: &'a mut TemporaryDirectorySearchAccess,
    ) -> Self {
        Self {
            selection,
            access,
            destinations: Vec::new(),
            by_suffix: HashMap::new(),
        }
    }

    /// One check's relations: to each of its own suffixes, then to the shared
    /// suffixes together, which is that of the first shared suffix it is
    /// `Same`, `Descendant` or `Ancestor` to; otherwise `SourceUnsearchable`
    /// if it is to any, else `Separate`. Each suffix is walked once for all
    /// checks, and each source's ancestors at most once.
    pub(super) fn check(
        &mut self,
        source: File,
        is_directory: bool,
        suffixes: &[PathBytes],
        shared: &[PathBytes],
    ) -> Result<SourceDirectoryRelations> {
        if suffixes.is_empty() && shared.is_empty() {
            return Ok(SourceDirectoryRelations {
                relations: Vec::new(),
                shared: DirectoryRelation::Separate,
            });
        }
        let mut source = AncestrySource::new(source, is_directory)?;
        let relations = suffixes
            .iter()
            .map(|suffix| {
                let destination = self.resolve(suffix)?;
                self.relation(&mut source, destination)
            })
            .collect::<Result<_>>()?;
        let mut combined = DirectoryRelation::Separate;
        for suffix in shared {
            let destination = self.resolve(suffix)?;
            match self.relation(&mut source, destination)? {
                DirectoryRelation::Separate => {}
                DirectoryRelation::SourceUnsearchable => {
                    combined = DirectoryRelation::SourceUnsearchable;
                }
                refusing => {
                    combined = refusing;
                    break;
                }
            }
        }
        Ok(SourceDirectoryRelations {
            relations,
            shared: combined,
        })
    }

    /// The destination `suffix` names, walked on first use. Existing
    /// components are opened without following symlinks. Once a missing or
    /// non-directory component is reached, the remaining virtual suffix is
    /// interpreted component by component so `.` and `..` retain kernel path
    /// semantics.
    fn resolve(&mut self, suffix: &[u8]) -> Result<usize> {
        if let Some(&destination) = self.by_suffix.get(suffix) {
            return Ok(destination);
        }
        if suffix.starts_with(b"/") {
            bail!("destination ancestry suffix must be relative");
        }
        if suffix.contains(&0) {
            bail!("destination ancestry suffix contains NUL");
        }

        let mut directory = self
            .selection
            .directory
            .try_clone()
            .context("duplicate retained destination directory")?;
        let mut components = self.selection.missing.clone();
        components.extend(
            suffix
                .split(|byte| *byte == b'/')
                .filter(|component| !component.is_empty())
                .map(<[u8]>::to_vec),
        );
        let mut virtual_components: Vec<Vec<u8>> = Vec::new();
        // Search access applies only while walking down from the selection;
        // a `..` component can leave the copy, so later lookups never widen.
        let mut left_selection = false;

        while let Some(component) = components.pop_front() {
            if component == b"." {
                continue;
            }
            if component == b".." {
                if virtual_components.pop().is_none() {
                    directory = open_operator_directory_at(&directory, b"..")
                        .context("open retained destination parent")?;
                    left_selection = true;
                }
                continue;
            }
            if !virtual_components.is_empty() {
                virtual_components.push(component);
                continue;
            }
            let opened = if left_selection {
                open_operator_directory_at(&directory, &component)
            } else {
                self.access.open(&directory, &component)
            };
            match opened {
                Ok(child) => directory = child,
                Err(error) if absent_or_nondirectory(&error) => {
                    // A missing entry can become a directory; an existing leaf
                    // makes the copy fail. Neither is followed for this decision.
                    virtual_components.push(component);
                }
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "inspect effective destination component {:?}",
                            OsStr::from_bytes(&component)
                        )
                    })
                }
            }
        }

        let reached = identity(&directory.metadata()?);
        // The reached directory may need search access. Its ancestors lie
        // above the copy and are never widened by this check.
        let parent = if left_selection {
            open_operator_directory_at(&directory, b"..")
        } else {
            self.access.open(&directory, b"..")
        };
        let (ancestors, error) = ancestors_from(parent, reached);
        let mut chain = Vec::with_capacity(ancestors.len() + 1);
        chain.push(reached);
        chain.extend(ancestors);
        self.destinations.push(EffectiveDirectory {
            exists: virtual_components.is_empty(),
            chain,
            finished: error.is_none(),
            error,
        });
        let destination = self.destinations.len() - 1;
        self.by_suffix.insert(suffix.to_vec(), destination);
        Ok(destination)
    }

    /// The relation of `source` to one destination, as walking up from the
    /// destination, and then from the source when it exists, finds it.
    fn relation(
        &mut self,
        source: &mut AncestrySource,
        destination: usize,
    ) -> Result<DirectoryRelation> {
        let directory = &mut self.destinations[destination];
        let relation = if let Some(relation) = directory.relation_to(source.identity) {
            relation
        } else if !directory.finished {
            return Err(directory.failure());
        } else if !directory.exists {
            DirectoryRelation::Separate
        } else if source.ancestors().identities.contains(&directory.chain[0]) {
            DirectoryRelation::Ancestor
        } else {
            source.beyond_ancestors()?
        };
        Ok(source.as_seen(relation))
    }
}

/// Resolve an operator-selected directory under the requested symlink policy.
/// The descriptor remains in the returned selection.
pub(super) fn select_operator_directory(
    path: &[u8],
    allow_missing: bool,
    symlink_policy: OperatorSymlinkPolicy,
) -> Result<(OperatorDirectorySelection, Option<DirectoryAnchor>)> {
    let path = resolve(path);
    let path = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()?.join(path)
    };
    let raw = path.as_os_str().as_bytes();
    if raw.contains(&0) {
        bail!("destination path contains NUL");
    }
    let mut hops = Vec::new();
    match OperatorResolver::resolve_process(
        raw,
        symlink_policy,
        OperatorFinalComponent::Directory,
        allow_missing,
        &mut hops,
    )? {
        PinnedPath::Directory(directory) => {
            let (directory, _) = directory.into_parts();
            let selection = OperatorDirectorySelection {
                path: path_bytes(&path),
                directory,
                missing: VecDeque::new(),
            };
            let anchor = selection.anchor()?;
            Ok((selection, Some(anchor)))
        }
        PinnedPath::Missing(missing) => {
            let (directory, missing) = missing.into_parts();
            Ok((
                OperatorDirectorySelection {
                    path: path_bytes(&path),
                    directory,
                    missing,
                },
                None,
            ))
        }
        PinnedPath::Leaf(_) => bail!("destination path is not a directory"),
        PinnedPath::OpenFile(_) => {
            unreachable!("directory selection never opens a procfs input")
        }
    }
}

pub(super) fn resolve_operator_entry(
    path: &[u8],
    symlink_policy: OperatorSymlinkPolicy,
    allow_missing_final: bool,
    follow_final_symlink: bool,
    readable_final: bool,
) -> Result<(PathBuf, PinnedPath)> {
    let path = resolve(path);
    let path = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()?.join(path)
    };
    let raw = path.as_os_str().as_bytes();
    if raw.contains(&0) {
        bail!("operator path contains NUL");
    }
    let mut hops = Vec::new();
    let selected = OperatorResolver::resolve_process(
        raw,
        symlink_policy,
        if readable_final {
            OperatorFinalComponent::ReadableEntry {
                follow_symlink: follow_final_symlink,
            }
        } else {
            OperatorFinalComponent::Entry {
                follow_symlink: follow_final_symlink,
            }
        },
        allow_missing_final,
        &mut hops,
    )?;
    Ok((path, selected))
}

#[cfg(debug_assertions)]
pub(super) fn hold_operator_control_path_for_test(path: &Path) -> Result<()> {
    let Some(expected) = std::env::var_os("SYQ_TEST_CONTROL_PATH") else {
        return Ok(());
    };
    if expected.as_bytes() != path.as_os_str().as_bytes() {
        return Ok(());
    }
    test_race_barrier(
        "SYQ_TEST_CONTROL_PATH_READY_FILE",
        "SYQ_TEST_CONTROL_PATH_CONTINUE_FILE",
        "control-path selection",
    )
}

#[cfg(not(debug_assertions))]
pub(super) fn hold_operator_control_path_for_test(_path: &Path) -> Result<()> {
    Ok(())
}

/// Open an existing operator-supplied input and retain the identity
/// selected by the component walk. A namespace replacement after resolution
/// is reported rather than followed.
pub(crate) fn open_operator_file_read(
    path: &[u8],
    symlink_policy: OperatorSymlinkPolicy,
) -> Result<File> {
    if path.ends_with(b"/") {
        bail!("operator file path has a trailing slash");
    }
    let (path, selected) = resolve_operator_entry(path, symlink_policy, false, true, true)?;
    hold_operator_control_path_for_test(&path)?;
    match selected {
        PinnedPath::Leaf(leaf) => leaf.open_read(),
        PinnedPath::OpenFile(file) => Ok(file),
        PinnedPath::Directory(_) => bail!("operator path selects a directory, not a regular file"),
        PinnedPath::Missing(_) => Err(io::Error::from_raw_os_error(libc::ENOENT).into()),
    }
}

/// Select an operator-supplied ordinary output and create it through retained
/// descriptors. An existing final entry is always refused; a missing entry is
/// created exclusively beneath its pinned parent.
pub(crate) fn create_operator_file(
    path: &[u8],
    symlink_policy: OperatorSymlinkPolicy,
) -> Result<File> {
    if path.ends_with(b"/") {
        bail!("operator file path has a trailing slash");
    }
    let (path, selected) = resolve_operator_entry(path, symlink_policy, true, true, false)?;
    hold_operator_control_path_for_test(&path)?;
    match selected {
        PinnedPath::Leaf(_) | PinnedPath::Directory(_) => {
            Err(io::Error::from(io::ErrorKind::AlreadyExists).into())
        }
        PinnedPath::Missing(missing) => missing.create_regular(0o666),
        PinnedPath::OpenFile(_) => unreachable!("output resolution never opens a procfs input"),
    }
}

pub(super) fn mkdir_operator_directory_at(
    parent: &File,
    component: &[u8],
    mode: u32,
) -> io::Result<()> {
    let component = CString::new(component).expect("path component was checked for NUL");
    loop {
        let result = unsafe {
            libc::mkdirat(
                parent.as_raw_fd(),
                component.as_ptr(),
                (mode & 0o7777) as libc::mode_t,
            )
        };
        if result == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

pub(super) fn operator_lstat_at(parent: &File, component: &[u8]) -> io::Result<libc::stat> {
    let component = CString::new(component).expect("path component was checked for NUL");
    loop {
        let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
        let result = unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                component.as_ptr(),
                metadata.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result == 0 {
            return Ok(unsafe { metadata.assume_init() });
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// A destination directory that must be new appeared at its name after it
/// was found missing: the receiver creates nothing there. Its kind tells the
/// coordinator the destination exists.
fn appeared_after_precondition() -> anyhow::Error {
    io::Error::new(
        io::ErrorKind::AlreadyExists,
        "destination directory appeared after the new-path precondition",
    )
    .into()
}

/// Master's per-pair ancestry check before the shared walk replaced it
/// (b77f661a, `relation_to_source_with_access` and
/// `opened_directory_relation`), without temporary search access. Tests
/// compare the shared walk with it: it walks the destination down and up and
/// the source up for each pair on its own.
#[cfg(test)]
pub(super) fn pairwise_relation_for_test(
    selection: &OperatorDirectorySelection,
    source: &File,
    source_is_directory: bool,
    suffix: &[u8],
) -> Result<DirectoryRelation> {
    if suffix.starts_with(b"/") {
        bail!("destination ancestry suffix must be relative");
    }
    if suffix.contains(&0) {
        bail!("destination ancestry suffix contains NUL");
    }
    let source_metadata = source
        .metadata()
        .context("inspect source directory capability")?;
    if !source_metadata.is_dir() {
        bail!("destination ancestry source capability is not a directory");
    }
    let mut directory = selection
        .directory
        .try_clone()
        .context("duplicate retained destination directory")?;
    let mut components = selection.missing.clone();
    components.extend(
        suffix
            .split(|byte| *byte == b'/')
            .filter(|component| !component.is_empty())
            .map(<[u8]>::to_vec),
    );
    let mut virtual_components: Vec<Vec<u8>> = Vec::new();
    while let Some(component) = components.pop_front() {
        if component == b"." {
            continue;
        }
        if component == b".." {
            if virtual_components.pop().is_none() {
                directory = open_operator_directory_at(&directory, b"..")
                    .context("open retained destination parent")?;
            }
            continue;
        }
        if !virtual_components.is_empty() {
            virtual_components.push(component);
            continue;
        }
        match open_operator_directory_at(&directory, &component) {
            Ok(child) => directory = child,
            Err(error) if absent_or_nondirectory(&error) => virtual_components.push(component),
            Err(error) => return Err(error),
        }
    }
    let destination_metadata = directory.metadata()?;
    let mut relation = pairwise_opened_relation(
        directory,
        source_metadata.dev(),
        source_metadata.ino(),
        !virtual_components.is_empty(),
    )?;
    if relation == DirectoryRelation::Separate && virtual_components.is_empty() {
        match pairwise_opened_relation(
            source.try_clone()?,
            destination_metadata.dev(),
            destination_metadata.ino(),
            false,
        ) {
            Ok(DirectoryRelation::Descendant) => relation = DirectoryRelation::Ancestor,
            Ok(_) => {}
            Err(error) if error_is_kind(&error, io::ErrorKind::PermissionDenied) => {
                relation = DirectoryRelation::SourceUnsearchable;
            }
            Err(error) => return Err(error),
        }
    }
    // An exact file is represented by its parent, as master's
    // `check_operator_directory_ancestry` mapped it.
    Ok(if source_is_directory {
        relation
    } else {
        match relation {
            DirectoryRelation::Same => DirectoryRelation::Ancestor,
            DirectoryRelation::Descendant => DirectoryRelation::Separate,
            other => other,
        }
    })
}

#[cfg(test)]
fn pairwise_opened_relation(
    mut directory: File,
    source_dev: u64,
    source_ino: u64,
    virtual_descendant: bool,
) -> Result<DirectoryRelation> {
    let mut below_candidate = virtual_descendant;
    loop {
        let metadata = directory
            .metadata()
            .context("inspect effective destination directory")?;
        if (metadata.dev(), metadata.ino()) == (source_dev, source_ino) {
            return Ok(if below_candidate {
                DirectoryRelation::Descendant
            } else {
                DirectoryRelation::Same
            });
        }
        let parent = open_operator_directory_at(&directory, b"..")
            .context("walk effective destination ancestry")?;
        let parent_metadata = parent
            .metadata()
            .context("inspect effective destination parent")?;
        if (parent_metadata.dev(), parent_metadata.ino()) == (metadata.dev(), metadata.ino()) {
            return Ok(DirectoryRelation::Separate);
        }
        directory = parent;
        below_candidate = true;
    }
}

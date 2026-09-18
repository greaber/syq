use super::*;

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
        })
    }

    pub(super) fn create_missing(
        &mut self,
        mode: u32,
        require_absent: bool,
    ) -> Result<DirectoryAnchor> {
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
                    bail!("destination directory appeared after the new-path precondition")
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
                        Ok(()) => {}
                        Err(error)
                            if error.kind() == io::ErrorKind::AlreadyExists
                                && final_component
                                && require_absent =>
                        {
                            bail!("destination directory appeared after the new-path precondition")
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
        self.anchor()
    }

    /// Compare an effective directory beneath this retained operator
    /// selection with an exact opened source directory. Existing components
    /// are opened without following symlinks. Once a missing or non-directory
    /// component is reached, the remaining virtual suffix is interpreted
    /// component by component so `.` and `..` retain kernel path semantics.
    pub(super) fn relation_to_source(
        &self,
        source: &File,
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

        let mut directory = self
            .directory
            .try_clone()
            .context("duplicate retained destination directory")?;
        let mut components = self.missing.clone();
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

        let destination_metadata = directory.metadata()?;
        let relation = opened_directory_relation(
            directory,
            source_metadata.dev(),
            source_metadata.ino(),
            !virtual_components.is_empty(),
        )?;
        if relation == DirectoryRelation::Separate && virtual_components.is_empty() {
            match opened_directory_relation(
                source.try_clone()?,
                destination_metadata.dev(),
                destination_metadata.ino(),
                false,
            ) {
                Ok(DirectoryRelation::Descendant) => return Ok(DirectoryRelation::Ancestor),
                Ok(_) => {}
                Err(error) if error_is_kind(&error, io::ErrorKind::PermissionDenied) => {
                    return Ok(DirectoryRelation::SourceUnsearchable);
                }
                Err(error) => return Err(error),
            }
        }
        Ok(relation)
    }
}

/// Walk parents from an already-open destination directory. The source
/// descriptor stays open for the whole query, so device/inode reuse cannot
/// turn the comparison into pathname authority.
pub(super) fn opened_directory_relation(
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

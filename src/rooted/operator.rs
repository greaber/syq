use super::*;

/// Whether resolution needs to traverse the last component as a directory or
/// select it as a named entry. Selecting an entry may independently request
/// that a last-component symlink be followed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OperatorFinalComponent {
    Directory,
    Entry {
        follow_symlink: bool,
    },
    /// A byte-stream source. Like other selections, FIFO classification does
    /// not open a reader; the caller opens it when ready to consume bytes.
    StreamSource {
        follow_symlink: bool,
    },
    /// An input file whose final procfs magic link may be opened relative to
    /// its retained procfs parent instead of interpreting its synthetic target
    /// bytes as an ordinary symlink path.
    ReadableEntry {
        follow_symlink: bool,
    },
}

/// One symlink hop taken while resolving an operator path. Callers use this
/// only for diagnostics; authority is carried by the returned descriptors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OperatorSymlinkHop {
    pub(crate) component: Vec<u8>,
    pub(crate) target: Vec<u8>,
}

/// An existing named entry selected relative to its retained parent. `object`
/// pins a non-directory object where the platform can open it without
/// following or connecting a FIFO. FIFOs outside Linux and some symlinks have
/// only their parent, name, and observed identity. Directories are pinned
/// separately by `PinnedDirectory`.
pub(crate) struct PinnedLeaf {
    pub(super) parent: File,
    pub(super) name: CString,
    pub(super) metadata: RootMetadata,
    pub(super) object: Option<File>,
    pub(super) resolved_relative: Option<Vec<u8>>,
}

impl PinnedLeaf {
    pub(crate) fn metadata(&self) -> RootMetadata {
        self.metadata
    }

    pub(crate) fn into_parts(self) -> (File, CString, RootMetadata, Option<File>) {
        (self.parent, self.name, self.metadata, self.object)
    }

    /// Canonical components from the resolver's initial directory to this
    /// selection, or `None` while an unconfined walk is outside that base.
    pub(crate) fn resolved_relative(&self) -> Option<&[u8]> {
        self.resolved_relative.as_deref()
    }

    /// Open the selected identity for input without resolving its
    /// pathname again. The metadata handle retained by the resolver prevents
    /// inode reuse until the newly opened descriptor has been checked.
    pub(crate) fn open_read(self) -> Result<File> {
        if self.metadata.is_dir() || self.metadata.is_symlink() {
            bail!("operator path does not select a readable file");
        }
        if self.metadata.is_fifo() {
            #[cfg(target_os = "linux")]
            if let Some(object) = &self.object {
                if let Some(file) = reopen_pinned_object_for_read(object)? {
                    let actual = root_metadata_from_std(&file.metadata()?)?;
                    require_operator_identity(self.metadata, actual, "operator FIFO")?;
                    return Ok(file);
                }
            }
            bail!(
                "selected FIFO control input cannot be reopened through an exact descriptor on this platform; use --files-from - or --mapping -, or materialize ignore rules in a regular file"
            );
        }
        // Reject an already-visible replacement before opening it: even a
        // nonblocking open of a replacement FIFO would connect its producer.
        // The descriptor check below still covers changes after this stat.
        require_operator_identity(
            self.metadata,
            metadata_at(self.parent.as_raw_fd(), &self.name)?,
            "operator file",
        )?;
        // A pathname replacement must not make the candidate open block before
        // its identity is checked. The selected object is not a FIFO here, but
        // its replacement may be one. Restore ordinary blocking I/O only after
        // the opened object has been validated.
        let flags =
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NOCTTY | libc::O_CLOEXEC | libc::O_NONBLOCK;
        let file = open_at(self.parent.as_raw_fd(), &self.name, flags, 0)
            .context("open selected operator file")?;
        let actual = root_metadata_from_std(&file.metadata()?)?;
        require_operator_identity(self.metadata, actual, "operator file")?;
        clear_nonblocking(&file).context("normalize selected operator file flags")?;
        Ok(file)
    }
}

/// An existing selected directory. `entry` retains the parent/name used to
/// select it when the directory itself may later need to be renamed or
/// removed; it is absent when resolution ends at the resolver's base.
pub(crate) struct PinnedDirectory {
    pub(super) directory: File,
    pub(super) entry: Option<PinnedLeaf>,
    pub(super) metadata: RootMetadata,
    pub(super) resolved_relative: Option<Vec<u8>>,
}

impl PinnedDirectory {
    pub(crate) fn metadata(&self) -> RootMetadata {
        self.metadata
    }

    pub(crate) fn into_parts(self) -> (File, Option<PinnedLeaf>) {
        (self.directory, self.entry)
    }

    /// Canonical components from the resolver's initial directory to this
    /// selection. See `PinnedLeaf::resolved_relative` for unconfined walks.
    pub(crate) fn resolved_relative(&self) -> Option<&[u8]> {
        self.resolved_relative.as_deref()
    }
}

/// The nearest retained existing directory and the unresolved suffix beneath
/// it. Creation remains a caller policy; this type supplies only authority.
pub(crate) struct PinnedMissing {
    pub(super) directory: File,
    pub(super) components: VecDeque<Vec<u8>>,
}

impl PinnedMissing {
    pub(crate) fn into_parts(self) -> (File, VecDeque<Vec<u8>>) {
        (self.directory, self.components)
    }

    /// Create a single missing regular-file leaf relative to the retained
    /// parent. Missing parents are deliberately not created for control paths.
    pub(crate) fn create_regular(self, mode: u32) -> Result<File> {
        let mut components = self.components;
        if components.len() != 1 {
            return Err(io::Error::from_raw_os_error(libc::ENOENT).into());
        }
        let name = operator_component_cstring(
            &components
                .pop_front()
                .expect("one missing operator component was checked"),
        )?;
        let file = open_at(
            self.directory.as_raw_fd(),
            &name,
            libc::O_WRONLY
                | libc::O_CREAT
                | libc::O_EXCL
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | libc::O_NOCTTY
                | libc::O_CLOEXEC,
            mode & 0o777,
        )
        .context("create selected operator file")?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            bail!("created operator path is not a regular file");
        }
        clear_nonblocking(&file).context("normalize selected operator file flags")?;
        Ok(file)
    }
}

pub(crate) enum PinnedPath {
    Missing(PinnedMissing),
    Leaf(PinnedLeaf),
    Directory(PinnedDirectory),
    /// A readable object opened directly through a retained procfs magic-link
    /// parent. This is used only for final control-file inputs.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    OpenFile(File),
}

pub(super) struct OperatorCursor {
    pub(super) directory: File,
    pub(super) entry: Option<OperatorEntry>,
    /// Canonical components beneath the resolver's original base. `None`
    /// means an unconfined walk is currently outside that base.
    pub(super) resolved_relative: Option<Vec<u8>>,
}

/// How the cursor's directory was selected. Intermediate cursors deliberately
/// omit a parent descriptor; only the final capability retains one.
pub(super) struct OperatorEntry {
    pub(super) name: CString,
    pub(super) metadata: RootMetadata,
}

/// Descriptor-retaining component resolver for paths supplied directly by an
/// operator. Descendant transfer paths use `RelativePath` and `Root` instead.
pub(crate) struct OperatorResolver {
    pub(super) base: File,
    pub(super) base_identity: OperatorDirectoryIdentity,
    pub(super) base_is_process_root: bool,
    pub(super) confined: bool,
    pub(super) relative_input: bool,
    pub(super) symlink_policy: OperatorSymlinkPolicy,
}

impl OperatorResolver {
    /// Begin at the process root or cwd. Absolute symlink targets may restart
    /// at `/` because this form is not confined beneath a caller-provided base.
    pub(crate) fn resolve_process(
        path: &[u8],
        symlink_policy: OperatorSymlinkPolicy,
        final_component: OperatorFinalComponent,
        allow_missing: bool,
        hops: &mut Vec<OperatorSymlinkHop>,
    ) -> Result<PinnedPath> {
        let base = open_operator_start(path.starts_with(b"/"))?;
        let base_identity = operator_directory_identity(&base)?;
        let base_is_process_root = operator_base_is_process_root(base_identity)?;
        Self {
            base,
            base_identity,
            base_is_process_root,
            confined: false,
            relative_input: false,
            symlink_policy,
        }
        .resolve(path, final_component, allow_missing, hops)
    }

    /// Begin at an already-open directory. The supplied path must be relative;
    /// a confined resolver also refuses `..` and symlink targets that would
    /// escape that directory.
    pub(crate) fn beneath(
        base: &File,
        confined: bool,
        symlink_policy: OperatorSymlinkPolicy,
    ) -> Result<Self> {
        let base = base.try_clone().context("duplicate operator path base")?;
        let base_identity = operator_directory_identity(&base)?;
        let base_is_process_root = operator_base_is_process_root(base_identity)?;
        Ok(Self {
            base,
            base_identity,
            base_is_process_root,
            confined,
            relative_input: true,
            symlink_policy,
        })
    }

    pub(crate) fn resolve(
        &self,
        path: &[u8],
        final_component: OperatorFinalComponent,
        allow_missing: bool,
        hops: &mut Vec<OperatorSymlinkHop>,
    ) -> Result<PinnedPath> {
        if path.contains(&0) {
            bail!("operator path contains NUL");
        }
        if self.relative_input && path.starts_with(b"/") {
            bail!("path beneath an opened operator base must be relative");
        }
        let mut components = operator_components(path);
        let mut stack = vec![OperatorCursor {
            directory: self
                .base
                .try_clone()
                .context("duplicate operator path base")?,
            entry: None,
            resolved_relative: Some(Vec::new()),
        }];
        let mut symlink_count = 0usize;

        loop {
            let Some(component) = components.pop_front() else {
                let current = stack.last().expect("operator resolver stack is nonempty");
                let metadata = root_metadata_from_std(&current.directory.metadata()?)?;
                let resolved_relative = current.resolved_relative.clone();
                let entry = if let Some(entry) = &current.entry {
                    let parent = &stack
                        .iter()
                        .rev()
                        .nth(1)
                        .expect("a selected entry has a parent cursor")
                        .directory;
                    Some(PinnedLeaf {
                        parent: parent
                            .try_clone()
                            .context("pin selected directory parent")?,
                        name: entry.name.clone(),
                        metadata: entry.metadata,
                        object: None,
                        resolved_relative: resolved_relative.clone(),
                    })
                } else {
                    None
                };
                return Ok(PinnedPath::Directory(PinnedDirectory {
                    directory: current
                        .directory
                        .try_clone()
                        .context("pin selected directory")?,
                    entry,
                    metadata,
                    resolved_relative,
                }));
            };

            if component == b"." {
                continue;
            }
            if component == b".." {
                if stack.len() > 1 {
                    stack.pop();
                } else if self.confined {
                    if !self.base_is_process_root {
                        bail!("operator path resolves outside its confined root");
                    }
                } else {
                    let directory = open_operator_directory_at(&stack[0].directory, b"..")
                        .context("resolve operator path parent")?;
                    stack[0] = OperatorCursor {
                        resolved_relative: self.relative_if_base(&directory)?,
                        directory,
                        entry: None,
                    };
                }
                continue;
            }

            let current = stack.last().expect("operator resolver stack is nonempty");
            let name = operator_component_cstring(&component)?;
            let metadata = match metadata_at(current.directory.as_raw_fd(), &name) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound && allow_missing => {
                    components.push_front(component);
                    return Ok(PinnedPath::Missing(PinnedMissing {
                        directory: current
                            .directory
                            .try_clone()
                            .context("pin nearest existing directory")?,
                        components,
                    }));
                }
                Err(error) => return Err(error).context("inspect operator path component"),
            };
            let final_name = components.is_empty();
            let follow_symlink = !final_name
                || matches!(final_component, OperatorFinalComponent::Directory)
                || matches!(
                    final_component,
                    OperatorFinalComponent::Entry {
                        follow_symlink: true
                    } | OperatorFinalComponent::ReadableEntry {
                        follow_symlink: true
                    } | OperatorFinalComponent::StreamSource {
                        follow_symlink: true
                    }
                );

            if metadata.is_symlink() {
                if !follow_symlink {
                    let resolved_relative =
                        append_operator_component(current.resolved_relative.as_deref(), &component);
                    let object = open_operator_symlink_at(current.directory.as_raw_fd(), &name)?;
                    if let Some(object) = &object {
                        require_operator_identity(
                            metadata,
                            root_metadata_from_std(&object.metadata()?)?,
                            "operator symlink",
                        )?;
                    }
                    return Ok(PinnedPath::Leaf(PinnedLeaf {
                        parent: current
                            .directory
                            .try_clone()
                            .context("pin selected symlink parent")?,
                        name,
                        metadata,
                        object,
                        resolved_relative,
                    }));
                }
                // Refusal needs no second observation. Policies that follow
                // the link pin it first so ownership and target bytes come
                // from the same symlink object.
                if self.symlink_policy == OperatorSymlinkPolicy::Refuse {
                    self.authorize_symlink(metadata, &component)?;
                    unreachable!("the refusing policy always returns an error for a symlink");
                }
                symlink_count += 1;
                if symlink_count > 40 {
                    bail!("too many symlink levels in operator path");
                }
                let object = open_operator_symlink_at(current.directory.as_raw_fd(), &name)?;
                let target = if let Some(object) = object {
                    let opened_metadata = root_metadata_from_std(&object.metadata()?)?;
                    require_operator_identity(metadata, opened_metadata, "operator symlink")?;
                    self.authorize_symlink(opened_metadata, &component)?;
                    hold_open_operator_symlink_for_test(&component)?;
                    match operator_read_open_link(&object)? {
                        Some(target) => {
                            #[cfg(target_os = "linux")]
                            if final_name
                                && matches!(
                                    final_component,
                                    OperatorFinalComponent::ReadableEntry { .. }
                                )
                                && operator_descriptor_is_procfs(&object)?
                            {
                                let file = open_at(
                                    current.directory.as_raw_fd(),
                                    &name,
                                    libc::O_RDONLY | libc::O_NOCTTY | libc::O_CLOEXEC,
                                    0,
                                )
                                .context("open selected procfs magic-link input")?;
                                let after = operator_read_open_link(&object)?
                                    .context("procfs magic link lost descriptor-bound access")?;
                                if after != target {
                                    bail!("procfs magic-link target changed during selection");
                                }
                                let metadata = root_metadata_from_std(&file.metadata()?)?;
                                if metadata.is_dir() || metadata.is_symlink() {
                                    bail!("operator path does not select a readable file");
                                }
                                hops.push(OperatorSymlinkHop { component, target });
                                return Ok(PinnedPath::OpenFile(file));
                            }
                            target
                        }
                        None => {
                            require_operator_link_fallback_allowed(self.symlink_policy)?;
                            operator_read_link_at(current.directory.as_raw_fd(), &name)?
                        }
                    }
                } else {
                    self.authorize_symlink(metadata, &component)?;
                    require_operator_link_fallback_allowed(self.symlink_policy)?;
                    operator_read_link_at(current.directory.as_raw_fd(), &name)?
                };
                hops.push(OperatorSymlinkHop {
                    component,
                    target: target.clone(),
                });
                if target.starts_with(b"/") {
                    if self.confined {
                        bail!("operator path has an absolute symlink target outside its root");
                    }
                    let directory = open_operator_start(true)?;
                    stack = vec![OperatorCursor {
                        resolved_relative: self.relative_if_base(&directory)?,
                        directory,
                        entry: None,
                    }];
                }
                let mut target_components = operator_components(&target);
                target_components.append(&mut components);
                components = target_components;
                continue;
            }

            if metadata.is_dir() {
                let directory = open_operator_directory_at(&current.directory, &component)
                    .context("open operator directory component")?;
                require_operator_identity(
                    metadata,
                    root_metadata_from_std(&directory.metadata()?)?,
                    "operator directory",
                )?;
                let resolved_relative = if let Some(path) = current.resolved_relative.as_deref() {
                    Some(join_operator_component(path, &component))
                } else if self.directory_is_base(&directory)? {
                    Some(Vec::new())
                } else {
                    None
                };
                if final_name {
                    return Ok(PinnedPath::Directory(PinnedDirectory {
                        directory,
                        entry: Some(PinnedLeaf {
                            parent: current
                                .directory
                                .try_clone()
                                .context("pin selected directory parent")?,
                            name,
                            metadata,
                            object: None,
                            resolved_relative: resolved_relative.clone(),
                        }),
                        metadata,
                        resolved_relative,
                    }));
                }
                stack.push(OperatorCursor {
                    directory,
                    entry: Some(OperatorEntry { name, metadata }),
                    resolved_relative,
                });
                continue;
            }

            if !final_name || matches!(final_component, OperatorFinalComponent::Directory) {
                return Err(io::Error::from_raw_os_error(libc::ENOTDIR).into());
            }
            // Only Linux O_PATH pins a FIFO without joining it as a reader.
            // macOS O_EVTONLY can release a producer and discard its bytes even
            // when the caller only inspects a name. Elsewhere retain the parent
            // and observed identity. Callers recheck it but cannot prevent FIFO
            // inode reuse.
            let object = if metadata.is_fifo() && !cfg!(target_os = "linux") {
                None
            } else {
                let object = open_operator_metadata_at(current.directory.as_raw_fd(), &name)
                    .context("pin operator path leaf")?;
                require_operator_identity(
                    metadata,
                    root_metadata_from_std(&object.metadata()?)?,
                    "operator leaf",
                )?;
                Some(object)
            };
            return Ok(PinnedPath::Leaf(PinnedLeaf {
                parent: current
                    .directory
                    .try_clone()
                    .context("pin selected object parent")?,
                name,
                metadata,
                object,
                resolved_relative: append_operator_component(
                    current.resolved_relative.as_deref(),
                    &component,
                ),
            }));
        }
    }

    pub(super) fn relative_if_base(&self, directory: &File) -> Result<Option<Vec<u8>>> {
        Ok(self.directory_is_base(directory)?.then(Vec::new))
    }

    pub(super) fn directory_is_base(&self, directory: &File) -> Result<bool> {
        let identity = operator_directory_identity(directory)?;
        Ok(operator_directory_identities_match(
            identity,
            self.base_identity,
        ))
    }

    pub(super) fn authorize_symlink(&self, metadata: RootMetadata, component: &[u8]) -> Result<()> {
        let euid = unsafe { libc::geteuid() };
        match self.symlink_policy {
            OperatorSymlinkPolicy::Refuse => bail!(
                "refusing symlink component {:?} in operator path; {OPERATOR_SYMLINK_FOLLOW_ADVICE}",
                String::from_utf8_lossy(component),
            ),
            OperatorSymlinkPolicy::TrustedOwner
                if !operator_symlink_owner_is_trusted(metadata.uid, euid) =>
            {
                bail!(
                    "refusing symlink component {:?} owned by uid {}; expected uid 0 or receiver uid {}",
                    String::from_utf8_lossy(component),
                    metadata.uid,
                    euid
                )
            }
            OperatorSymlinkPolicy::TrustedOwner | OperatorSymlinkPolicy::FollowAll => Ok(()),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct OperatorDirectoryIdentity {
    pub(super) dev: u64,
    pub(super) ino: u64,
    #[cfg(target_os = "linux")]
    pub(super) mount_id: Option<u64>,
}

pub(super) fn operator_directory_identity(directory: &File) -> Result<OperatorDirectoryIdentity> {
    let metadata = root_metadata_from_std(&directory.metadata()?)?;
    Ok(OperatorDirectoryIdentity {
        dev: metadata.dev,
        ino: metadata.ino,
        #[cfg(target_os = "linux")]
        mount_id: operator_mount_id(directory)?,
    })
}

pub(super) fn operator_directory_identities_match(
    left: OperatorDirectoryIdentity,
    right: OperatorDirectoryIdentity,
) -> bool {
    if left.dev != right.dev || left.ino != right.ino {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        matches!((left.mount_id, right.mount_id), (Some(left), Some(right)) if left == right)
    }
    #[cfg(not(target_os = "linux"))]
    {
        true
    }
}

#[cfg(target_os = "linux")]
pub(super) fn operator_mount_id(directory: &File) -> Result<Option<u64>> {
    let mut status = std::mem::MaybeUninit::<libc::statx>::zeroed();
    let result = unsafe {
        libc::statx(
            directory.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
            libc::STATX_MNT_ID,
            status.as_mut_ptr(),
        )
    };
    if result == 0 {
        let status = unsafe { status.assume_init() };
        return Ok(((status.stx_mask & libc::STATX_MNT_ID) != 0).then_some(status.stx_mnt_id));
    }
    let error = io::Error::last_os_error();
    if matches!(
        error.raw_os_error(),
        Some(libc::ENOSYS | libc::EINVAL | libc::EOPNOTSUPP | libc::EPERM)
    ) {
        return Ok(None);
    }
    Err(error).context("identify operator directory mount")
}

pub(super) fn operator_base_is_process_root(identity: OperatorDirectoryIdentity) -> Result<bool> {
    let root = open_operator_start(true)?;
    Ok(operator_directory_identities_match(
        operator_directory_identity(&root)?,
        identity,
    ))
}

pub(super) fn append_operator_component(path: Option<&[u8]>, component: &[u8]) -> Option<Vec<u8>> {
    path.map(|path| join_operator_component(path, component))
}

pub(super) fn join_operator_component(path: &[u8], component: &[u8]) -> Vec<u8> {
    let mut joined = path.to_vec();
    if !joined.is_empty() {
        joined.push(b'/');
    }
    joined.extend_from_slice(component);
    joined
}

pub(super) fn operator_components(path: &[u8]) -> VecDeque<Vec<u8>> {
    path.split(|byte| *byte == b'/')
        .filter(|component| !component.is_empty())
        .map(<[u8]>::to_vec)
        .collect()
}

pub(super) fn operator_component_cstring(component: &[u8]) -> Result<CString> {
    CString::new(component).context("operator path component contains NUL")
}

pub(super) fn operator_directory_flags() -> libc::c_int {
    #[cfg(target_os = "linux")]
    {
        libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC
    }
    #[cfg(target_os = "macos")]
    {
        libc::O_SEARCH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC
    }
}

pub(super) fn open_operator_start(absolute: bool) -> Result<File> {
    let name = CString::new(if absolute { "/" } else { "." })
        .expect("fixed operator start contains no NUL");
    open_operator_directory_fd(libc::AT_FDCWD, &name)
}

pub(crate) fn open_operator_directory_at(parent: &File, component: &[u8]) -> Result<File> {
    let component = operator_component_cstring(component)?;
    open_operator_directory_fd(parent.as_raw_fd(), &component)
}

pub(super) fn open_operator_directory_fd(parent: RawFd, component: &CString) -> Result<File> {
    // O_DIRECTORY is the kernel-enforced type check. Repeating it with
    // fstat costs another metadata operation on network filesystems.
    Ok(open_at(parent, component, operator_directory_flags(), 0)?)
}

pub(super) fn open_operator_metadata_at(parent: RawFd, name: &CString) -> io::Result<File> {
    #[cfg(target_os = "linux")]
    let flags =
        libc::O_PATH | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC;
    #[cfg(target_os = "macos")]
    let flags =
        libc::O_EVTONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let flags =
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC;
    open_at(parent, name, flags, 0)
}

pub(super) fn open_operator_symlink_at(parent: RawFd, name: &CString) -> Result<Option<File>> {
    #[cfg(target_os = "linux")]
    {
        open_at(
            parent,
            name,
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_NOCTTY | libc::O_CLOEXEC,
            0,
        )
        .map(Some)
        .context("pin operator symlink")
    }
    #[cfg(target_os = "macos")]
    {
        open_at(
            parent,
            name,
            libc::O_SYMLINK | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC,
            0,
        )
        .map(Some)
        .context("pin operator symlink")
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (parent, name);
        Ok(None)
    }
}

#[cfg(debug_assertions)]
pub(super) fn hold_open_operator_symlink_for_test(component: &[u8]) -> Result<()> {
    let Some(expected) = std::env::var_os("SYQ_TEST_OPERATOR_SYMLINK_COMPONENT") else {
        return Ok(());
    };
    if expected.as_encoded_bytes() != component {
        return Ok(());
    }
    if let Some(ready) = std::env::var_os("SYQ_TEST_OPERATOR_SYMLINK_READY_FILE") {
        std::fs::write(&ready, b"ready").with_context(|| {
            format!(
                "write operator-symlink-ready signal {}",
                Path::new(&ready).display()
            )
        })?;
    }
    let Some(release) = std::env::var_os("SYQ_TEST_OPERATOR_SYMLINK_RELEASE_FILE") else {
        return Ok(());
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !Path::new(&release).exists() {
        if std::time::Instant::now() >= deadline {
            bail!(
                "timed out waiting for operator-symlink release signal {}",
                Path::new(&release).display()
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    Ok(())
}

#[cfg(not(debug_assertions))]
pub(super) fn hold_open_operator_symlink_for_test(_component: &[u8]) -> Result<()> {
    Ok(())
}

/// Read target bytes through an already-open symlink when the platform has a
/// descriptor-bound API. `None` means that only the insecure pathname API is
/// available; callers enforcing trusted-owner traversal must fail closed.
pub(super) fn operator_read_open_link(object: &File) -> Result<Option<Vec<u8>>> {
    read_open_symlink(object)
}

pub(super) fn operator_read_link_at(parent: RawFd, name: &CString) -> Result<Vec<u8>> {
    read_link_bytes(|target, capacity| unsafe {
        libc::readlinkat(parent, name.as_ptr(), target, capacity)
    })
}

/// Read raw target bytes through an already-open symlink object. `None` means
/// the running platform lacks a descriptor-bound API; security-sensitive
/// callers must fail closed instead of reopening the symlink by name.
pub(crate) fn read_open_symlink(object: &File) -> Result<Option<Vec<u8>>> {
    #[cfg(target_os = "linux")]
    {
        let empty = c"";
        read_link_bytes(|target, capacity| unsafe {
            libc::readlinkat(object.as_raw_fd(), empty.as_ptr(), target, capacity)
        })
        .map(Some)
    }
    #[cfg(target_os = "macos")]
    {
        // `freadlink` was added in macOS 13. Resolve it dynamically so a binary
        // that otherwise runs on an older release does not gain a hard loader
        // dependency. Callers reject `None` rather than re-address by name.
        type Freadlink =
            unsafe extern "C" fn(libc::c_int, *mut libc::c_char, libc::size_t) -> libc::ssize_t;
        let symbol = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"freadlink".as_ptr()) };
        if symbol.is_null() {
            return Ok(None);
        }
        let freadlink: Freadlink = unsafe { std::mem::transmute(symbol) };
        read_link_bytes(|target, capacity| unsafe {
            freadlink(object.as_raw_fd(), target, capacity)
        })
        .map(Some)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = object;
        Ok(None)
    }
}

pub(super) fn read_link_bytes(
    mut read: impl FnMut(*mut libc::c_char, usize) -> isize,
) -> Result<Vec<u8>> {
    let mut capacity = 256usize;
    loop {
        let mut target = Vec::<u8>::with_capacity(capacity);
        let length = read(target.as_mut_ptr().cast(), capacity);
        if length < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error).context("read operator symlink");
        }
        let length = length as usize;
        if length < capacity {
            unsafe { target.set_len(length) };
            return Ok(target);
        }
        capacity = capacity
            .checked_mul(2)
            .filter(|next| *next <= libc::PATH_MAX as usize * 2)
            .context("operator symlink target is too long")?;
    }
}

pub(super) fn require_operator_identity(
    expected: RootMetadata,
    actual: RootMetadata,
    label: &str,
) -> Result<()> {
    if (actual.dev, actual.ino, actual.file_type())
        != (expected.dev, expected.ino, expected.file_type())
    {
        bail!("{label} changed identity during resolution");
    }
    Ok(())
}

pub(super) fn require_metadata_identity(
    expected: RootMetadata,
    actual: RootMetadata,
    label: &str,
) -> Result<()> {
    if (actual.dev, actual.ino, actual.file_type())
        != (expected.dev, expected.ino, expected.file_type())
    {
        bail!("{label} changed identity");
    }
    Ok(())
}

pub(super) fn operator_symlink_owner_is_trusted(owner: u32, euid: u32) -> bool {
    owner == 0 || owner == euid
}

pub(super) fn require_operator_link_fallback_allowed(policy: OperatorSymlinkPolicy) -> Result<()> {
    if policy == OperatorSymlinkPolicy::TrustedOwner {
        bail!(
            "trusted-owner symlink traversal requires descriptor-bound link reads on this platform"
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn operator_descriptor_is_procfs(file: &File) -> Result<bool> {
    let mut stats = std::mem::MaybeUninit::<libc::statfs>::uninit();
    loop {
        if unsafe { libc::fstatfs(file.as_raw_fd(), stats.as_mut_ptr()) } == 0 {
            let stats = unsafe { stats.assume_init() };
            return Ok(stats.f_type as u32 == libc::PROC_SUPER_MAGIC as u32);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error).context("identify operator descriptor filesystem");
        }
    }
}

/// Upgrade a retained Linux `O_PATH` object to a readable descriptor without
/// consulting its former pathname. A verified procfs directory makes the
/// decimal entry an exact reference to `object`, even after namespace rename.
#[cfg(target_os = "linux")]
pub(super) fn reopen_pinned_object_for_read(object: &File) -> Result<Option<File>> {
    let proc_path = CString::new("/proc/self/fd").expect("fixed procfs path contains no NUL");
    let proc_fd = match open_at(
        libc::AT_FDCWD,
        &proc_path,
        libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        0,
    ) {
        Ok(proc_fd) => proc_fd,
        Err(_) => return Ok(None),
    };
    if !operator_descriptor_is_procfs(&proc_fd)? {
        return Ok(None);
    }
    let name = CString::new(object.as_raw_fd().to_string())
        .expect("decimal file descriptor contains no NUL");
    open_at(
        proc_fd.as_raw_fd(),
        &name,
        libc::O_RDONLY | libc::O_NOCTTY | libc::O_CLOEXEC,
        0,
    )
    .map(Some)
    .context("reopen selected FIFO through its retained descriptor")
}

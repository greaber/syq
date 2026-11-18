//! Pin operator source selections. The copy engine's source registration and
//! `syq map` resolve selectors through this one path, so a source symlink or
//! identity rule cannot apply to one of them only.

use super::*;

/// The pinned source base, when relative selectors or `--root` need one.
pub(crate) struct SourceSelector {
    resolver: Option<OperatorResolver>,
    confined: bool,
    symlink_policy: OperatorSymlinkPolicy,
}

impl SourceSelector {
    /// Pin the source base once. `outer_root`, when set, confines the base
    /// itself beneath that directory. Without `needs_base` (every selector is
    /// absolute and the base is not confined) nothing is resolved. `label`
    /// names the base in errors.
    pub(crate) fn new(
        label: &str,
        base: &SourceRootBase,
        outer_root: Option<&[u8]>,
        symlink_policy: OperatorSymlinkPolicy,
        needs_base: bool,
    ) -> Result<Self> {
        let resolver = if needs_base || base.confined {
            let base_path = resolve(base.path.as_deref().unwrap_or(b"."));
            let mut base_hops = Vec::new();
            let directory = |pinned: Result<PinnedPath>| -> Result<_> {
                match pinned.with_context(|| format!("resolve {label} {}", base_path.display()))? {
                    PinnedPath::Directory(directory) => Ok(directory.into_parts().0),
                    PinnedPath::Leaf(_) | PinnedPath::OpenFile(_) => {
                        bail!("{label} {} is not a directory", base_path.display())
                    }
                    PinnedPath::Missing(_) => {
                        unreachable!("source base resolution requires an existing directory")
                    }
                }
            };
            let base_directory = match outer_root {
                None => directory(OperatorResolver::resolve_process(
                    base_path.as_os_str().as_bytes(),
                    symlink_policy,
                    OperatorFinalComponent::Directory,
                    false,
                    &mut base_hops,
                ))?,
                Some(outer) => {
                    let outer = Path::new(OsStr::from_bytes(outer));
                    let inside = base_path.strip_prefix(outer).with_context(|| {
                        format!("{label} {} is outside its root", base_path.display())
                    })?;
                    let outer_directory = directory(OperatorResolver::resolve_process(
                        outer.as_os_str().as_bytes(),
                        OperatorSymlinkPolicy::Refuse,
                        OperatorFinalComponent::Directory,
                        false,
                        &mut Vec::new(),
                    ))?;
                    if inside.as_os_str().is_empty() {
                        outer_directory
                    } else {
                        directory(
                            OperatorResolver::beneath(&outer_directory, true, symlink_policy)?
                                .resolve(
                                    inside.as_os_str().as_bytes(),
                                    OperatorFinalComponent::Directory,
                                    false,
                                    &mut base_hops,
                                ),
                        )?
                    }
                }
            };
            Some(OperatorResolver::beneath(
                &base_directory,
                base.confined,
                symlink_policy,
            )?)
        } else {
            None
        };
        Ok(Self {
            resolver,
            confined: base.confined,
            symlink_policy,
        })
    }

    /// Resolve one selector, already passed through `resolve`, to an existing
    /// object. `context` labels resolution failures.
    pub(crate) fn resolve(
        &self,
        path: &Path,
        follow_root: bool,
        context: impl FnOnce() -> String,
    ) -> Result<PinnedPath> {
        let mut hops = Vec::new();
        let final_component = OperatorFinalComponent::Entry {
            follow_symlink: follow_root,
        };
        let pinned = if path.is_absolute() {
            if self.confined {
                bail!(
                    "source selector {} beneath --root must be relative",
                    path.display()
                );
            }
            OperatorResolver::resolve_process(
                path.as_os_str().as_bytes(),
                self.symlink_policy,
                final_component,
                false,
                &mut hops,
            )
        } else {
            self.resolver
                .as_ref()
                .expect("relative source selection requires a pinned base")
                .resolve(
                    path.as_os_str().as_bytes(),
                    final_component,
                    false,
                    &mut hops,
                )
        };
        pinned.with_context(context)
    }
}

/// One pinned selection, represented by the smallest directory that preserves
/// it: the selected directory itself, or a selected leaf's opened parent plus
/// its literal name, identity and retained object.
pub(crate) struct PinnedSource {
    pub(crate) directory: File,
    pub(crate) relative: Vec<u8>,
    pub(crate) expected_leaf: Option<SourceLeafIdentity>,
    pub(crate) object: Option<File>,
    /// Canonical components from the source base, or `None` when the
    /// selection resolved outside it.
    pub(crate) resolved_relative: Option<Vec<u8>>,
}

impl PinnedSource {
    /// `record_symlink_atime` keeps a selected symlink's access time from
    /// before its target was snapshotted, for callers that report or restore it.
    pub(crate) fn new(pinned: PinnedPath, record_symlink_atime: bool) -> Result<Self> {
        match pinned {
            PinnedPath::Directory(directory) => {
                let resolved_relative = directory.resolved_relative().map(<[u8]>::to_vec);
                let (directory, _) = directory.into_parts();
                Ok(Self {
                    directory,
                    relative: Vec::new(),
                    expected_leaf: None,
                    object: None,
                    resolved_relative,
                })
            }
            PinnedPath::Leaf(leaf) => {
                let resolved_relative = leaf.resolved_relative().map(<[u8]>::to_vec);
                let (parent, name, metadata, object) = leaf.into_parts();
                if object.is_none() && !metadata.is_fifo() {
                    bail!("this platform cannot retain the selected source leaf safely");
                }
                let symlink_target = if metadata.is_symlink() {
                    Some(
                        read_open_symlink(object.as_ref().expect("symlink object was checked"))?
                            .context("this platform cannot snapshot a selected source symlink through its pinned object (macOS 13 or newer is required on Darwin)")?,
                    )
                } else {
                    None
                };
                Ok(Self {
                    directory: parent,
                    relative: name.as_bytes().to_vec(),
                    expected_leaf: Some(SourceLeafIdentity {
                        dev: metadata.dev,
                        ino: metadata.ino,
                        file_type: metadata.file_type(),
                        symlink_atime: (metadata.is_symlink() && record_symlink_atime)
                            .then_some(metadata.atime),
                        symlink_target,
                    }),
                    object,
                    resolved_relative,
                })
            }
            PinnedPath::Missing(_) => {
                unreachable!("source resolution did not allow a missing suffix")
            }
            PinnedPath::OpenFile(_) => {
                unreachable!("source resolution never opens a procfs control input")
            }
        }
    }
}

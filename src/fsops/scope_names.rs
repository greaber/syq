//! A confined receiver changes no file in place that has names outside the
//! directories it promises to stay within: a file's contents and metadata
//! belong to every name it has. The receiver counts the names it knows a
//! file has inside: those its own destination scans and lookups returned,
//! and the links this copy made. A file with more names than that has some
//! elsewhere, including names inside that the receiver never saw.

use super::*;
use std::collections::BTreeSet;

pub(crate) struct ScopeNames {
    /// The receiver's root, beneath which every name here lies.
    root: Vec<u8>,
    /// The approved directories, each with whether it covers descendants.
    scopes: Vec<(Vec<u8>, bool)>,
    names: Mutex<NamesByFile>,
}

/// The names known inside, by file identity.
type NamesByFile = HashMap<(u64, u64), BTreeSet<Vec<u8>>>;

impl ScopeNames {
    pub(crate) fn new(root: Vec<u8>, scopes: impl IntoIterator<Item = (Vec<u8>, bool)>) -> Self {
        Self {
            root,
            scopes: scopes.into_iter().collect(),
            names: Mutex::default(),
        }
    }

    /// The approved directory holding `path`, if any.
    fn scope_of(&self, path: &[u8]) -> Option<&[u8]> {
        self.scopes
            .iter()
            .filter(|(scope, descendants)| {
                path == scope.as_slice()
                    || (*descendants
                        && path.starts_with(scope)
                        && path.get(scope.len()) == Some(&b'/'))
            })
            .map(|(scope, _)| scope.as_slice())
            .max_by_key(|scope| scope.len())
    }

    /// Remember `path` as a name of the file `(dev, ino)` when it lies in an
    /// approved directory.
    pub(crate) fn record(&self, path: &[u8], dev: u64, ino: u64) {
        if self.scope_of(path).is_some() {
            self.names
                .lock()
                .unwrap()
                .entry((dev, ino))
                .or_default()
                .insert(path.to_vec());
        }
    }

    /// Remember the names a destination listing or lookup under `root`
    /// returned, for the files with more than one.
    pub(crate) fn record_entries<'a>(
        &self,
        root: &[u8],
        entries: impl IntoIterator<Item = &'a Entry>,
    ) {
        for entry in entries {
            if entry.nlink > 1 && entry.kind != Kind::Dir {
                self.record(&join(root, &entry.path), entry.dev, entry.ino);
            }
        }
    }

    /// Refuse to change the file at `path` in place, the file `(dev, ino)`
    /// with `nlink` names held beneath `root`, when some of its names lie
    /// outside the approved directories. A remembered name counts only while
    /// it still names that file.
    pub(crate) fn require_inside(
        &self,
        root: &Root,
        path: &[u8],
        (dev, ino, nlink): (u64, u64, u64),
    ) -> Result<()> {
        if nlink <= 1 {
            return Ok(());
        }
        let known: Vec<Vec<u8>> = self
            .names
            .lock()
            .unwrap()
            .get(&(dev, ino))
            .map(|names| names.iter().filter(|name| *name != path).cloned().collect())
            .unwrap_or_default();
        let mut inside = 1;
        for name in known {
            if inside >= nlink {
                break;
            }
            let Some(relative) = name
                .strip_prefix(self.root.as_slice())
                .and_then(|relative| relative.strip_prefix(b"/"))
            else {
                continue;
            };
            let Ok(relative) = RelativePath::new(relative) else {
                continue;
            };
            if let Ok(Some(metadata)) = root.metadata_optional(&relative) {
                if (metadata.dev, metadata.ino) == (dev, ino) {
                    inside += 1;
                }
            }
        }
        if nlink > inside {
            let shown = |bytes: &[u8]| Path::new(OsStr::from_bytes(bytes)).display().to_string();
            bail!(
                "{} has other names outside {}; not changed in place",
                shown(path),
                shown(self.scope_of(path).unwrap_or(path)),
            );
        }
        Ok(())
    }
}

impl FsOps {
    /// Confine in-place changes to files whose names are all inside the
    /// approved directories (`ScopeNames`). Only a confined receiver has
    /// them; every other receiver writes through a file's names as before.
    pub(crate) fn set_scope_names(&mut self, names: Arc<ScopeNames>) {
        self.scope_names = Some(names);
    }

    /// Remember the names a destination scan under `root` returned.
    pub(crate) fn record_scope_names(&self, root: &[u8], entries: &[Entry]) {
        if let Some(names) = &self.scope_names {
            names.record_entries(root, entries);
        }
    }

    /// Remember the names a guarded destination lookup of `paths` found,
    /// whichever request asked: a stat, a planning batch or a pruning lookup.
    pub(crate) fn record_looked_up_names(
        &self,
        paths: &[PathBytes],
        entries: &[Option<Entry>],
        guard: Option<&ContainerGuard>,
    ) {
        let Some(names) = self.scope_names.as_ref().filter(|_| guard.is_some()) else {
            return;
        };
        for (path, entry) in paths.iter().zip(entries) {
            if let Some(entry) = entry
                .as_ref()
                .filter(|entry| entry.nlink > 1 && entry.kind != Kind::Dir)
            {
                names.record(path, entry.dev, entry.ino);
            }
        }
    }

    /// Refuse to change `target`'s file in place, described by `metadata`,
    /// when it has names outside the approved directories.
    pub(super) fn require_names_inside(
        &self,
        target: &RootedTarget,
        metadata: &fs::Metadata,
    ) -> Result<()> {
        require_names_inside(self.scope_names.as_deref(), target, metadata)
    }
}

/// As `FsOps::require_names_inside`, for code without the operations.
pub(super) fn require_names_inside(
    names: Option<&ScopeNames>,
    target: &RootedTarget,
    metadata: &fs::Metadata,
) -> Result<()> {
    match names {
        Some(names) if !metadata.is_dir() && metadata.nlink() > 1 => names.require_inside(
            &target.root,
            target.label.as_os_str().as_bytes(),
            (metadata.dev(), metadata.ino(), metadata.nlink()),
        ),
        _ => Ok(()),
    }
}

/// Whether applying `meta` under `flags` would change the file `current`
/// describes, as the metadata step changes only what differs. An owner
/// change by a receiver that is not root is skipped unless required.
pub(super) fn changes_metadata(current: &fs::Metadata, meta: &Meta, flags: u8) -> bool {
    meta.inode_metadata.is_some()
        || (flags & flags::MODE != 0
            && !current.file_type().is_symlink()
            && current.mode() & 0o7777 != meta.mode & 0o7777)
        || (flags & flags::OWNER != 0
            && (is_superuser() || flags & flags::REQUIRE_OWNER != 0)
            && current.uid() != meta.uid)
        || (flags & flags::GROUP != 0 && current.gid() != meta.gid)
        || (flags & flags::TIMES != 0
            && (current.mtime() != meta.mtime || current.mtime_nsec() as u32 != meta.mtime_nsec))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A name counts while it still names the file: a name the receiver saw
    /// that now holds another file proves nothing about the others.
    #[test]
    fn names_count_inside_only_while_they_name_the_file() {
        let temporary = crate::test_support::tempdir().unwrap();
        let base = temporary.path();
        for directory in ["scope", "outside"] {
            fs::create_dir(base.join(directory)).unwrap();
        }
        fs::write(base.join("scope/a"), b"shared").unwrap();
        fs::hard_link(base.join("scope/a"), base.join("scope/b")).unwrap();
        let root = Root::open(base).unwrap();
        let bytes = |path: &Path| path.as_os_str().as_bytes().to_vec();
        let names = ScopeNames::new(bytes(base), [(bytes(&base.join("scope")), true)]);
        let identity = |name: &str| {
            let metadata = fs::metadata(base.join(name)).unwrap();
            (metadata.dev(), metadata.ino(), metadata.nlink())
        };
        let a = bytes(&base.join("scope/a"));
        let b = bytes(&base.join("scope/b"));

        // An unseen second name counts as outside.
        let error = names
            .require_inside(&root, &a, identity("scope/a"))
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            format!(
                "{} has other names outside {}; not changed in place",
                base.join("scope/a").display(),
                base.join("scope").display()
            )
        );
        // Both names seen inside: the file may change.
        let (dev, ino, _) = identity("scope/a");
        names.record(&b, dev, ino);
        names
            .require_inside(&root, &a, identity("scope/a"))
            .unwrap();
        // A name outside the scope is never remembered as inside.
        fs::hard_link(base.join("scope/a"), base.join("outside/a")).unwrap();
        names.record(&bytes(&base.join("outside/a")), dev, ino);
        assert!(names
            .require_inside(&root, &a, identity("scope/a"))
            .is_err());
        // Replacing a remembered name takes it out of the count.
        fs::remove_file(base.join("outside/a")).unwrap();
        fs::remove_file(base.join("scope/b")).unwrap();
        fs::write(base.join("scope/b"), b"other").unwrap();
        fs::hard_link(base.join("scope/a"), base.join("outside/a")).unwrap();
        assert!(names
            .require_inside(&root, &a, identity("scope/a"))
            .is_err());
        // A file with one name is never refused.
        let lone = bytes(&base.join("scope/b"));
        names
            .require_inside(&root, &lone, identity("scope/b"))
            .unwrap();
    }
}

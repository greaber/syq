//! Existing directory access is prepared at download admission, except when
//! early pruning needs a complete destination walk before downloads begin.

use super::{Destination, Download, ObjectKind};
use crate::proto::{DirectoryMode, TargetCondition};
use crate::rooted::RelativePath;
use anyhow::Result;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// Paths are bytes beneath the destination root: pruning can meet local
/// names that are not UTF-8.
pub(super) struct TemporaryAccess {
    enabled: bool,
    prepared: HashSet<Vec<u8>>,
    widened: BTreeMap<Vec<u8>, DirectoryMode>,
}

impl TemporaryAccess {
    pub(super) fn new(enabled: bool) -> Self {
        Self {
            enabled,
            prepared: HashSet::new(),
            widened: BTreeMap::new(),
        }
    }

    pub(super) fn prepare(&mut self, destination: &Destination, jobs: &[Download]) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let mut paths = BTreeSet::new();
        if destination.prefix.is_empty() {
            paths.insert(Vec::new());
        }
        for job in jobs {
            for (index, _) in job.path.match_indices('/') {
                let parent = &job.path[..index];
                if super::super::prune::beneath(parent.as_bytes(), destination.prefix.as_bytes())
                    .is_some()
                {
                    paths.insert(parent.as_bytes().to_vec());
                }
            }
            if job.kind == ObjectKind::Dir {
                paths.insert(job.path.as_bytes().to_vec());
            }
        }
        // Parents precede descendants. Remember successful inspections as well
        // as changes: siblings do not need another stat/chmod of their parent.
        for path in paths {
            if self.prepared.contains(&path) {
                continue;
            }
            let relative = RelativePath::new(&path)?;
            if let Some(metadata) = destination.root.metadata_optional(&relative)? {
                if metadata.is_dir() {
                    let condition = TargetCondition::MatchesFingerprint {
                        dev: metadata.dev,
                        ino: metadata.ino,
                        ctime: metadata.ctime,
                        ctime_nsec: metadata.ctime_nsec,
                    };
                    if let Some(saved) = crate::fsops::widen_directory(
                        &destination.root,
                        &relative,
                        condition,
                        Path::new(OsStr::from_bytes(&path)),
                    )? {
                        self.widened.insert(path.clone(), saved);
                    }
                }
            }
            self.prepared.insert(path);
        }
        Ok(())
    }

    /// Widen one existing directory that pruning must enter or empty, if
    /// the option is on. Returns whether its mode changed.
    pub(super) fn prepare_for_pruning(
        &mut self,
        root: &crate::rooted::Root,
        path: &[u8],
        metadata: &crate::rooted::RootMetadata,
    ) -> Result<bool> {
        if !self.enabled || self.widened.contains_key(path) {
            return Ok(false);
        }
        let condition = TargetCondition::MatchesFingerprint {
            dev: metadata.dev,
            ino: metadata.ino,
            ctime: metadata.ctime,
            ctime_nsec: metadata.ctime_nsec,
        };
        let saved = crate::fsops::widen_directory(
            root,
            &RelativePath::new(path)?,
            condition,
            Path::new(OsStr::from_bytes(path)),
        )?;
        Ok(saved.is_some_and(|saved| self.widened.insert(path.to_vec(), saved).is_none()))
    }

    /// A directory pruning removed has no mode to restore.
    pub(super) fn forget(&mut self, path: &[u8]) {
        self.widened.remove(path);
    }

    pub(super) fn into_restorations(self) -> BTreeMap<Vec<u8>, DirectoryMode> {
        self.widened
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rooted::Root;
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::sync::Arc;

    fn job(path: &str) -> Download {
        Download {
            expression_path: path.into(),
            expression_destination_path: path.into(),
            kind: ObjectKind::File,
            key: path.into(),
            path: path.into(),
            size: 1,
            mapping: None,
            copy_source: None,
            source_object: None,
        }
    }

    #[test]
    fn queued_downloads_keep_original_directory_permissions() {
        let temporary = crate::test_support::tempdir().unwrap();
        for name in ["first", "later"] {
            fs::create_dir(temporary.path().join(name)).unwrap();
            fs::set_permissions(
                temporary.path().join(name),
                fs::Permissions::from_mode(0o500),
            )
            .unwrap();
        }
        let destination = Destination {
            root: Arc::new(Root::open(temporary.path()).unwrap()),
            prefix: String::new(),
        };
        let mut access = TemporaryAccess::new(true);
        access.prepare(&destination, &[job("first/one")]).unwrap();
        assert_eq!(
            fs::metadata(temporary.path().join("later")).unwrap().mode() & 0o777,
            0o500
        );
        assert!(!access.prepared.contains(b"later".as_slice()));
        access.prepare(&destination, &[job("first/two")]).unwrap();
        assert_eq!(
            access
                .widened
                .get(b"first".as_slice())
                .map(|saved| saved.mode),
            (unsafe { libc::geteuid() } != 0).then_some(0o500)
        );
        access.prepare(&destination, &[job("later/one")]).unwrap();
        for (path, saved) in access.into_restorations() {
            crate::fsops::restore_directory_mode(
                &destination.root,
                &RelativePath::new(&path).unwrap(),
                saved,
                Path::new(OsStr::from_bytes(&path)),
            )
            .unwrap();
        }
        for name in ["first", "later"] {
            assert_eq!(
                fs::metadata(temporary.path().join(name)).unwrap().mode() & 0o777,
                0o500
            );
            fs::set_permissions(
                temporary.path().join(name),
                fs::Permissions::from_mode(0o700),
            )
            .unwrap();
        }
    }

    #[test]
    fn conservative_downloads_do_not_prepare_directory_access() {
        let temporary = crate::test_support::tempdir().unwrap();
        let destination = Destination {
            root: Arc::new(Root::open(temporary.path()).unwrap()),
            prefix: String::new(),
        };
        let mut access = TemporaryAccess::new(false);
        access
            .prepare(&destination, &[job("missing/file")])
            .unwrap();
        assert!(access.prepared.is_empty());
        assert!(access.widened.is_empty());
        assert!(!temporary.path().join("missing").exists());
    }
}

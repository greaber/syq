//! Existing directory access is prepared at download admission, except when
//! early pruning needs a complete destination walk before downloads begin.

use super::{Destination, Download, ObjectKind};
use crate::proto::{DirectoryMode, TargetCondition};
use crate::rooted::RelativePath;
use anyhow::Result;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::Path;

pub(super) struct TemporaryAccess {
    enabled: bool,
    prepared: HashSet<String>,
    widened: BTreeMap<String, DirectoryMode>,
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
            paths.insert(String::new());
        }
        for job in jobs {
            for (index, _) in job.path.match_indices('/') {
                let parent = &job.path[..index];
                if super::super::prune::beneath(parent.as_bytes(), destination.prefix.as_bytes())
                    .is_some()
                {
                    paths.insert(parent.to_owned());
                }
            }
            if job.kind == ObjectKind::Dir {
                paths.insert(job.path.clone());
            }
        }
        // Parents precede descendants. Remember successful inspections as well
        // as changes: siblings do not need another stat/chmod of their parent.
        for path in paths {
            if self.prepared.contains(&path) {
                continue;
            }
            let relative = RelativePath::new(path.as_bytes())?;
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
                        Path::new(&path),
                    )? {
                        self.widened.insert(path.clone(), saved);
                    }
                }
            }
            self.prepared.insert(path);
        }
        Ok(())
    }

    pub(super) fn into_restorations(self) -> BTreeMap<String, DirectoryMode> {
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
        assert!(!access.prepared.contains("later"));
        access.prepare(&destination, &[job("first/two")]).unwrap();
        assert_eq!(
            access.widened.get("first").map(|saved| saved.mode),
            (unsafe { libc::geteuid() } != 0).then_some(0o500)
        );
        access.prepare(&destination, &[job("later/one")]).unwrap();
        for (path, saved) in access.into_restorations() {
            crate::fsops::restore_directory_mode(
                &destination.root,
                &RelativePath::new(path.as_bytes()).unwrap(),
                saved,
                Path::new(&path),
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

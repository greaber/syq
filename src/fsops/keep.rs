//! Keeping an existing file that already holds the contents a copy would
//! give it: the receiver changes its metadata in place through the handle
//! it holds, when it can vouch for the file (`vouch`), and the copy keeps
//! the file only while its name still leads to it.

use super::*;

/// What kind of handle a kept file's metadata changes through.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Handle {
    /// A descriptor the file was opened for reading or writing with.
    Open,
    /// A handle for the file's metadata only (`Root::open_metadata`):
    /// `O_PATH` on Linux, for a file whose contents nothing read. It cannot
    /// set times there.
    Path,
}

/// How a caller keeps a file: the handle it holds, whether the name is
/// checked again after the change when the condition is `Any`, and what
/// a failure to set the metadata says it was doing, if anything.
#[derive(Clone, Copy)]
pub(crate) struct Keeping {
    pub(crate) handle: Handle,
    /// Under `TargetCondition::Any`, still require that the name lead to
    /// the file once its metadata is set.
    pub(crate) recheck_any: bool,
    /// Wrapped around an error setting the metadata, before the file's
    /// label.
    pub(crate) setting: Option<&'static str>,
}

/// What keeping an existing file came to.
pub(crate) enum Keep {
    /// Kept, with its identity when `flags::REPORT_IDENTITY` asks for it.
    Kept(Option<(u64, u64)>),
    /// The receiver cannot vouch for changing its metadata in place: the
    /// `vouch::replace_required` error, which a caller returns or turns
    /// into a stage that replaces the file.
    Replace(anyhow::Error),
}

impl Keep {
    /// The identity of a file that had to be kept, or the error saying it
    /// must be replaced.
    pub(crate) fn required(self) -> Result<Option<(u64, u64)>> {
        match self {
            Keep::Kept(identity) => Ok(identity),
            Keep::Replace(error) => Err(error),
        }
    }
}

/// Keep `file`, the existing file at `place` whose metadata `current` was
/// read through it, with `meta` under `flags`: vouch for the change
/// (`vouch::require`), make it through `file`, then require that the name
/// still lead to the file `condition` names (under `Any`, the file itself,
/// when `keeping.recheck_any`). Every check reads `file` or `current`,
/// never the name, except the final lookup of the name itself.
pub(crate) fn keep_existing(
    place: vouch::Place<'_>,
    file: &File,
    current: &fs::Metadata,
    (meta, flags): (&Meta, u8),
    condition: TargetCondition,
    keeping: Keeping,
) -> Result<Keep> {
    if let Err(error) = vouch::require(place, file, current, meta, flags) {
        if vouch::is_replace_required(&error) {
            return Ok(Keep::Replace(error));
        }
        return Err(error);
    }
    #[cfg(debug_assertions)]
    fail_set_meta_for_test(place.label)?;
    let set = set_meta_file_inner(file, keeping.handle, meta, flags, current, false, true);
    match keeping.setting {
        Some(doing) => set.with_context(|| format!("{doing} {}", place.label.display()))?,
        None => set?,
    }
    if condition != TargetCondition::Any || keeping.recheck_any {
        require_rooted_named_identity_known(
            place.root,
            place.relative,
            place.label,
            current,
            condition,
        )?;
    }
    Ok(Keep::Kept(known_identity(current, flags)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::tempdir;

    fn keeping(recheck_any: bool) -> Keeping {
        Keeping {
            handle: Handle::Open,
            recheck_any,
            setting: None,
        }
    }

    /// A file kept under `Any` has its metadata set through its handle; only
    /// a caller that asks checks that its name still leads to it.
    #[test]
    fn a_kept_file_whose_name_moved_on_fails_only_where_the_caller_rechecks() {
        for recheck_any in [false, true] {
            let dir = tempdir().unwrap();
            let root = Root::open(dir.path()).unwrap();
            let path = dir.path().join("kept");
            fs::write(&path, b"same").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            let file = File::open(&path).unwrap();
            let current = file.metadata().unwrap();
            // Someone moves it away and puts another file at its name.
            fs::rename(&path, dir.path().join("moved")).unwrap();
            fs::write(&path, b"other").unwrap();
            let relative = RelativePath::new(b"kept").unwrap();
            let place = vouch::Place {
                root: &root,
                relative: &relative,
                label: &path,
                preview: false,
            };
            let meta = Meta {
                inode_metadata: None,
                mode: 0o640,
                uid: current.uid(),
                gid: current.gid(),
                mtime: 0,
                mtime_nsec: 0,
            };
            let kept = keep_existing(
                place,
                &file,
                &current,
                (&meta, flags::MODE),
                TargetCondition::Any,
                keeping(recheck_any),
            );
            match kept {
                Ok(Keep::Kept(_)) => assert!(!recheck_any),
                Err(error) => {
                    assert!(recheck_any, "{error:#}");
                    assert!(
                        format!("{error:#}").contains("changed during update"),
                        "{error:#}"
                    );
                }
                Ok(Keep::Replace(error)) => panic!("refused: {error:#}"),
            }
            // The change went to the file the handle holds either way.
            assert_eq!(file.metadata().unwrap().mode() & 0o7777, 0o640);
        }
    }

    /// A change the receiver cannot vouch for changes nothing and comes back
    /// as the error that asks for a replacement.
    #[test]
    fn a_file_with_other_names_is_left_alone_for_replacement() {
        let dir = tempdir().unwrap();
        let root = Root::open(dir.path()).unwrap();
        let path = dir.path().join("kept");
        fs::write(&path, b"same").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&path, dir.path().join("alias")).unwrap();
        let file = File::open(&path).unwrap();
        let current = file.metadata().unwrap();
        let relative = RelativePath::new(b"kept").unwrap();
        let place = vouch::Place {
            root: &root,
            relative: &relative,
            label: &path,
            preview: false,
        };
        let meta = Meta {
            inode_metadata: None,
            mode: 0o640,
            uid: current.uid(),
            gid: current.gid(),
            mtime: 0,
            mtime_nsec: 0,
        };
        let kept = keep_existing(
            place,
            &file,
            &current,
            (&meta, flags::MODE),
            TargetCondition::Matches {
                dev: current.dev(),
                ino: current.ino(),
            },
            keeping(true),
        )
        .unwrap();
        let Keep::Replace(error) = kept else {
            panic!("a file with other names was kept");
        };
        assert_eq!(
            vouch::replace_reason(&error),
            Some(ReplaceReason::OtherNames)
        );
        assert_eq!(file.metadata().unwrap().mode() & 0o7777, 0o600);
    }
}

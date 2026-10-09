//! Under a grant that keeps existing objects, a restricted receiver changes
//! the metadata only of objects it created for that grant. It records each
//! object it creates by device and inode, read from the object it just
//! created, and checks a later change against the identity of the very
//! descriptor the change goes through. Names never confer ownership: a name
//! this grant created may since lead to an existing file, linked there, and
//! no check of a name before the change can rule that out.
//!
//! An existing object's inode is in use for as long as the object exists,
//! so its number cannot be given to another object while the copy runs.
//! Only objects this grant created can leave numbers to reuse, so a number
//! in this record names, at worst, a newer object, never one the grant
//! keeps.

use super::*;
use std::collections::HashSet;

#[derive(Default)]
pub(crate) struct OwnedObjects(Mutex<HashSet<(u64, u64)>>);

impl OwnedObjects {
    /// Remember the object `created` describes, which this receiver created.
    pub(crate) fn record(&self, created: &fs::Metadata) {
        self.record_identity(created.dev(), created.ino());
    }

    /// Remember the object `(dev, ino)`, which this receiver created.
    pub(crate) fn record_identity(&self, dev: u64, ino: u64) {
        self.0.lock().unwrap().insert((dev, ino));
    }

    /// Refuse a metadata change to the object open as `opened` (`label`
    /// names it) unless this receiver created it for this grant.
    pub(crate) fn require(&self, opened: &fs::Metadata, label: &Path) -> Result<()> {
        if self
            .0
            .lock()
            .unwrap()
            .contains(&(opened.dev(), opened.ino()))
        {
            return Ok(());
        }
        bail!(
            "{} existed before this copy, which keeps existing objects: its metadata is not changed",
            label.display()
        )
    }
}

impl FsOps {
    /// Change the metadata only of objects this receiver created, as a grant
    /// that keeps existing objects requires.
    pub(crate) fn set_owned_objects(&mut self, owned: Option<Arc<OwnedObjects>>) {
        self.owned = owned;
    }

    /// Refuse to change the metadata of the object open as `opened` (`label`
    /// names it) to `meta` under `flags` unless this receiver created it, or
    /// the change would change nothing.
    pub(super) fn require_owned(
        &self,
        opened: &fs::Metadata,
        meta: &Meta,
        flags: u8,
        label: &Path,
    ) -> Result<()> {
        match &self.owned {
            Some(owned) if changes_metadata(opened, meta, flags) => owned.require(opened, label),
            _ => Ok(()),
        }
    }
}

/// Whether applying `meta` under `flags` would change the object `current`
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

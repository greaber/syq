use super::*;

pub fn entry_from_meta(rel: PathBytes, full: &Path, md: &fs::Metadata) -> Entry {
    let ft = md.file_type();
    let kind = if ft.is_dir() {
        Kind::Dir
    } else if ft.is_file() {
        Kind::File
    } else if ft.is_symlink() {
        Kind::Symlink
    } else {
        use std::os::unix::fs::FileTypeExt;
        if ft.is_fifo() {
            Kind::Fifo
        } else if ft.is_socket() {
            Kind::Socket
        } else if ft.is_char_device() {
            Kind::CharDev
        } else if ft.is_block_device() {
            Kind::BlockDev
        } else {
            Kind::Other
        }
    };
    let link = if kind == Kind::Symlink {
        fs::read_link(full)
            .ok()
            .map(|t| t.into_os_string().into_vec())
    } else {
        None
    };
    Entry {
        path: rel,
        kind,
        size: if kind == Kind::File { md.len() } else { 0 },
        mtime: md.mtime(),
        mtime_nsec: md.mtime_nsec() as u32,
        mode: md.mode(),
        uid: md.uid(),
        gid: md.gid(),
        rdev: md.rdev(),
        dev: md.dev(),
        ino: md.ino(),
        ctime: md.ctime(),
        inode_metadata: None,
        nlink: md.nlink(),
        ctime_nsec: md.ctime_nsec() as u32,
        link,
    }
}

pub(crate) fn rooted_entry(
    root: &Root,
    relative: &RelativePath,
    path: PathBytes,
    metadata: RootMetadata,
) -> Result<Entry> {
    let kind = match metadata.file_type() {
        MODE_DIRECTORY => Kind::Dir,
        MODE_REGULAR => Kind::File,
        MODE_SYMLINK => Kind::Symlink,
        MODE_FIFO => Kind::Fifo,
        MODE_SOCKET => Kind::Socket,
        MODE_CHAR => Kind::CharDev,
        MODE_BLOCK => Kind::BlockDev,
        _ => Kind::Other,
    };
    let link = if kind == Kind::Symlink {
        let target = root.read_link(relative)?;
        let after = root.metadata(relative)?;
        if (after.dev, after.ino, after.file_type())
            != (metadata.dev, metadata.ino, metadata.file_type())
        {
            bail!("symlink changed while reading its target");
        }
        Some(target)
    } else {
        None
    };
    Ok(entry_from_root_metadata(path, metadata, kind, link))
}

/// Build an entry for a registered source. An exact symlink's target is the
/// descriptor-bound registration snapshot: reading it through `relative`
/// would let a same-inode A -> B -> A name race return B's target.
pub(crate) fn rooted_source_entry(
    root: &Root,
    relative: &RelativePath,
    path: PathBytes,
    metadata: RootMetadata,
    expected: Option<&SourceLeafIdentity>,
) -> Result<Entry> {
    let Some(expected) = expected else {
        return rooted_entry(root, relative, path, metadata);
    };
    require_source_leaf_identity(expected, metadata)?;
    if metadata.is_symlink() {
        let target = expected
            .symlink_target
            .clone()
            .context("registered source symlink is missing its pinned target")?;
        return Ok(entry_from_root_metadata(
            path,
            metadata,
            Kind::Symlink,
            Some(target),
        ));
    }
    if expected.symlink_target.is_some() {
        bail!("registered non-symlink source carries a symlink target");
    }
    rooted_entry(root, relative, path, metadata)
}

/// Build an entry relative to a directory already opened by a descriptor
/// scanner. Symlink target reads and the confirming stat use that same parent
/// descriptor, so neither operation has to rewalk a possibly renamed path.
pub(crate) fn rooted_entry_in_directory(
    root: &Root,
    directory: &File,
    name: &[u8],
    path: PathBytes,
    metadata: RootMetadata,
) -> Result<Entry> {
    let kind = match metadata.file_type() {
        MODE_DIRECTORY => Kind::Dir,
        MODE_REGULAR => Kind::File,
        MODE_SYMLINK => Kind::Symlink,
        MODE_FIFO => Kind::Fifo,
        MODE_SOCKET => Kind::Socket,
        MODE_CHAR => Kind::CharDev,
        MODE_BLOCK => Kind::BlockDev,
        _ => Kind::Other,
    };
    let link = if kind == Kind::Symlink {
        let target = root.read_link_in_directory(directory, name)?;
        let after = root.metadata_in_directory(directory, name)?;
        if (after.dev, after.ino, after.file_type())
            != (metadata.dev, metadata.ino, metadata.file_type())
        {
            bail!("symlink changed while reading its target");
        }
        Some(target)
    } else {
        None
    };
    Ok(entry_from_root_metadata(path, metadata, kind, link))
}

pub(super) fn entry_from_root_metadata(
    path: PathBytes,
    metadata: RootMetadata,
    kind: Kind,
    link: Option<PathBytes>,
) -> Entry {
    Entry {
        path,
        kind,
        size: if kind == Kind::File { metadata.len } else { 0 },
        mtime: metadata.mtime,
        mtime_nsec: metadata.mtime_nsec,
        mode: metadata.mode,
        uid: metadata.uid,
        gid: metadata.gid,
        rdev: metadata.rdev,
        dev: metadata.dev,
        ino: metadata.ino,
        ctime: metadata.ctime,
        inode_metadata: None,
        nlink: metadata.nlink,
        ctime_nsec: metadata.ctime_nsec,
        link,
    }
}

pub fn lstat_entry(rel: PathBytes, full: &Path) -> io::Result<Entry> {
    let md = fs::symlink_metadata(full)?;
    Ok(entry_from_meta(rel, full, &md))
}

impl FsOps {
    pub(crate) fn preserving_inode_metadata(&self) -> bool {
        self.inode_preservation.any()
    }
    pub(crate) fn capture_scan_metadata(
        &self,
        root: &[u8],
        source: Option<&RegisteredPath>,
        follow_root: bool,
        entries: &mut [Entry],
    ) -> Result<()> {
        if !self.inode_preservation.any() {
            return Ok(());
        }
        for entry in entries {
            let path = join(root, &entry.path);
            let reference = source.map(|s| s.join(&entry.path)).transpose()?;
            self.capture_entry_metadata(
                &path,
                reference.as_ref(),
                follow_root && entry.path.is_empty(),
                entry,
            )?;
        }
        Ok(())
    }

    fn capture_entry_metadata(
        &self,
        path: &[u8],
        source: Option<&RegisteredPath>,
        follow: bool,
        entry: &mut Entry,
    ) -> Result<()> {
        if !self.inode_preservation.any() {
            return Ok(());
        }
        let file = if let Some(source) = source {
            let target = self.registered_source_target(source)?;
            target.root.open_metadata(&target.relative)?
        } else if let Some(target) = self.rooted_destination_target(path, None)? {
            target.root.open_metadata(&target.relative)?
        } else {
            #[cfg(target_os = "linux")]
            {
                OpenOptions::new()
                    .read(true)
                    .custom_flags(
                        libc::O_PATH | libc::O_CLOEXEC | if follow { 0 } else { libc::O_NOFOLLOW },
                    )
                    .open(resolve(path))?
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = follow;
                bail!("inode metadata capture is unavailable on this platform");
            }
        };
        let opened = file.metadata()?;
        anyhow::ensure!(
            (
                opened.dev(),
                opened.ino(),
                opened.ctime(),
                opened.ctime_nsec() as u32
            ) == (entry.dev, entry.ino, entry.ctime, entry.ctime_nsec),
            "{} changed before reading inode metadata",
            resolve(path).display()
        );
        entry.inode_metadata = crate::inode_metadata::capture(&file, self.inode_preservation)
            .with_context(|| format!("read inode metadata: {}", resolve(path).display()))?;
        Ok(())
    }

    pub(super) fn stat_many_request(
        &mut self,
        paths: &[PathBytes],
        sources: Option<&[RegisteredPath]>,
        follow: bool,
        guard: Option<&ContainerGuard>,
    ) -> Result<Vec<Option<Entry>>> {
        let mut entries = self.stat_many_unadorned_request(paths, sources, follow, guard)?;
        if self.inode_preservation.any() {
            anyhow::ensure!(
                guard.is_none(),
                "signed receivers do not support ACL or xattr preservation"
            );
            for (index, entry) in entries.iter_mut().enumerate() {
                if let Some(entry) = entry {
                    self.capture_entry_metadata(
                        &paths[index],
                        sources.map(|s| &s[index]),
                        follow,
                        entry,
                    )?;
                }
            }
        }
        Ok(entries)
    }
}

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
        atime: crate::inode_metadata::Timestamp {
            seconds: md.atime(),
            nanoseconds: md.atime_nsec() as u32,
        },
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
        let mut metadata = metadata;
        if let Some(atime) = expected.symlink_atime {
            metadata.atime = atime;
        }
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
/// Name-only mappings can omit the target and its consistency check; callers
/// that copy links or evaluate their targets must request it.
pub(crate) fn rooted_entry_in_directory(
    root: &Root,
    directory: &File,
    name: &[u8],
    path: PathBytes,
    metadata: RootMetadata,
    read_symlink_target: bool,
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
    let link = if read_symlink_target && kind == Kind::Symlink {
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
        atime: metadata.atime,
        inode_metadata: None,
        nlink: metadata.nlink,
        ctime_nsec: metadata.ctime_nsec,
        link,
    }
}

#[cfg(test)]
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
        if !self.inode_preservation.acls
            && !self.inode_preservation.xattrs
            && !self.inode_preservation.crtimes
        {
            // Access time was observed before scanning a directory or reading
            // a symlink. Do not replace it with a post-read stat value.
            entry.inode_metadata = Some(Box::new(crate::inode_metadata::InodeMetadata {
                atime: self.inode_preservation.atimes.then_some(entry.atime),
                ..Default::default()
            }));
            return Ok(());
        }
        let file = if let Some(source) = source {
            let target = self.registered_source_target(source)?;
            target.root.open_metadata(&target.relative)?
        } else if let Some(target) = self.rooted_destination_target(path)? {
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
                OpenOptions::new()
                    .read(true)
                    .custom_flags(
                        libc::O_EVTONLY
                            | libc::O_CLOEXEC
                            | if follow { 0 } else { libc::O_SYMLINK },
                    )
                    .open(resolve(path))?
            }
        };
        entry.inode_metadata = inode_metadata_of(&file, path, entry, self.inode_preservation)?;
        Ok(())
    }

    /// `capture_entry_metadata` for each of `entries`, the registered
    /// sources `sources`, on the metadata pool: reading ACLs and extended
    /// attributes waits on the filesystem for each file, as the stats before
    /// it do (`stat_many_unadorned_request`).
    fn capture_source_metadata_in_parallel(
        &self,
        paths: &[PathBytes],
        sources: &[RegisteredPath],
        entries: &mut [Option<Entry>],
    ) -> Result<()> {
        let targets = entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.is_some())
            .map(|(index, _)| Ok((index, self.registered_source_target(&sources[index])?)))
            .collect::<Result<Vec<_>>>()?;
        let preservation = self.inode_preservation;
        let captured = {
            let entries = &*entries;
            parallel_map(&targets, |(index, target)| {
                let entry = entries[*index].as_ref().expect("selected above");
                let file = target.root.open_metadata(&target.relative)?;
                inode_metadata_of(&file, &paths[*index], entry, preservation)
            })
        };
        for ((index, _), metadata) in targets.iter().zip(captured) {
            entries[*index]
                .as_mut()
                .expect("selected above")
                .inode_metadata = metadata?;
        }
        Ok(())
    }

    pub(super) fn stat_many_request(
        &mut self,
        paths: &[PathBytes],
        sources: Option<&[RegisteredPath]>,
        follow: bool,
    ) -> Result<Vec<Option<Entry>>> {
        self.stat_sources_request(paths, sources, follow, false)
    }

    /// `stat_many_request`, where `read_here` says that this thread has just
    /// read every registered source named: those are statted on it as well.
    pub(super) fn stat_sources_request(
        &mut self,
        paths: &[PathBytes],
        sources: Option<&[RegisteredPath]>,
        follow: bool,
        read_here: bool,
    ) -> Result<Vec<Option<Entry>>> {
        #[cfg(debug_assertions)]
        if sources.is_none() {
            crate::fsops::record_test_event(
                "SYQ_TEST_DESTINATION_LOOKUPS",
                format_args!("stat {}", paths.len()),
            )?;
        }
        let mut entries = self.stat_many_unadorned_request(paths, sources, follow, read_here)?;
        // As for the stats, sources this thread has just read are captured
        // on it too.
        let reads_files = self.inode_preservation.acls
            || self.inode_preservation.xattrs
            || self.inode_preservation.crtimes;
        if let Some(sources) = sources.filter(|_| reads_files && !read_here) {
            self.capture_source_metadata_in_parallel(paths, sources, &mut entries)?;
        } else if self.inode_preservation.any() {
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

/// The inode metadata `preservation` selects of `file`, opened at `path`,
/// which must still be the object `entry` describes.
fn inode_metadata_of(
    file: &File,
    path: &[u8],
    entry: &Entry,
    preservation: crate::inode_metadata::Selection,
) -> Result<Option<Box<crate::inode_metadata::InodeMetadata>>> {
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
    crate::inode_metadata::capture(file, preservation, entry.atime)
        .with_context(|| format!("read inode metadata: {}", resolve(path).display()))
}

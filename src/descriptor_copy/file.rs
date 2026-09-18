//! One pinned regular file per connection, with private staging for writes.
use super::{Operation, Settings, StreamPlacement};
use crate::{
    proto::{OperatorSymlinkPolicy, Response},
    rooted::{OperatorFinalComponent, OperatorResolver, PinnedPath, RelativePath, Root},
};
use anyhow::{bail, Context, Result};
use std::{
    fs::{File, Metadata, Permissions},
    io::{Read, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, PermissionsExt},
    },
};

pub(crate) struct Session {
    file: File,
    original: Metadata,
    remaining: u64,
    offset: u64,
    hash: Option<crate::hashing::Hasher>,
    settings: Settings,
    destination: Option<Destination>,
}
struct Destination {
    root: Root,
    target: RelativePath,
    temporary: RelativePath,
    mode: u32,
}
impl Drop for Destination {
    fn drop(&mut self) {
        let _ = self.root.unlink(&self.temporary);
    }
}
pub(crate) fn resolve_source(path: &[u8], root: Option<&[u8]>, follow: bool) -> Result<PinnedPath> {
    let policy = if follow {
        OperatorSymlinkPolicy::FollowAll
    } else {
        OperatorSymlinkPolicy::Refuse
    };
    let final_component = OperatorFinalComponent::Entry {
        follow_symlink: follow,
    };
    let path = crate::fsops::resolve(path);
    if let Some(root) = root {
        let root = crate::fsops::resolve(root);
        let PinnedPath::Directory(directory) = OperatorResolver::resolve_process(
            root.as_os_str().as_bytes(),
            policy,
            OperatorFinalComponent::Directory,
            false,
            &mut Vec::new(),
        )?
        else {
            bail!("source root must be a directory");
        };
        OperatorResolver::beneath(&directory.into_parts().0, true, policy)?.resolve(
            path.as_os_str().as_bytes(),
            final_component,
            false,
            &mut Vec::new(),
        )
    } else {
        OperatorResolver::resolve_process(
            path.as_os_str().as_bytes(),
            policy,
            final_component,
            false,
            &mut Vec::new(),
        )
    }
}

fn resolve_destination(
    path: &[u8],
    follow: bool,
    placement: &StreamPlacement,
) -> Result<PinnedPath> {
    let path = crate::fsops::resolve(path);
    let policy = if follow {
        OperatorSymlinkPolicy::FollowAll
    } else {
        OperatorSymlinkPolicy::Refuse
    };
    let selected = OperatorResolver::resolve_process(
        path.as_os_str().as_bytes(),
        policy,
        if placement.name.is_some() {
            OperatorFinalComponent::Directory
        } else {
            OperatorFinalComponent::Entry {
                follow_symlink: false,
            }
        },
        true,
        &mut Vec::new(),
    )?;
    let exists = !matches!(&selected, PinnedPath::Missing(_));
    use crate::cli::Existence;
    if (placement.existence == Existence::New && exists)
        || (placement.existence == Existence::Existing && !exists)
    {
        bail!(
            "destination existence condition failed for {}",
            path.display()
        );
    }
    let Some(name) = &placement.name else {
        return Ok(selected);
    };
    // The name is one source basename, not another operator path.
    anyhow::ensure!(
        !name.is_empty() && !name.contains(&b'/') && name != b"." && name != b"..",
        "invalid stream source basename"
    );
    let directory = match selected {
        PinnedPath::Directory(directory) => directory.into_parts().0,
        PinnedPath::Missing(missing) => {
            let (parent, components) = missing.into_parts();
            let root = Root::from_directory(parent)?;
            let path = RelativePath::new(&components.into_iter().collect::<Vec<_>>().join(&b'/'))?;
            root.create_missing_parents(&path, 0o777)?;
            root.create_directory(&path, 0o777)?;
            root.open_directory(&path)?
        }
        _ => bail!("--into destination must be a directory"),
    };
    OperatorResolver::beneath(&directory, true, policy)?.resolve(
        name,
        OperatorFinalComponent::Entry {
            follow_symlink: false,
        },
        true,
        &mut Vec::new(),
    )
}

impl Session {
    fn open(
        path: &[u8],
        write: bool,
        follow: bool,
        root: Option<&[u8]>,
        placement: &StreamPlacement,
        settings: Settings,
    ) -> Result<Self> {
        anyhow::ensure!(
            (512..=64 << 20).contains(&settings.request_size),
            "invalid stream request size"
        );
        let selected = if write {
            anyhow::ensure!(
                root.is_none(),
                "source root does not apply to a destination"
            );
            resolve_destination(path, follow, placement)?
        } else {
            resolve_source(path, root, follow)?
        };
        let (file, destination) = if write {
            let (root, target, mode) = match selected {
                PinnedPath::Leaf(leaf) => {
                    if !leaf.metadata().is_file() && !leaf.metadata().is_symlink() {
                        bail!("stream destination must be a regular file or an absent path");
                    }
                    let (parent, name, meta, _) = leaf.into_parts();
                    (
                        Root::from_directory(parent)?,
                        RelativePath::new(name.to_bytes())?,
                        if meta.is_file() {
                            meta.mode & 0o777
                        } else {
                            0o666 & !crate::fsops::process_umask()
                        },
                    )
                }
                PinnedPath::Missing(missing) => {
                    let (parent, components) = missing.into_parts();
                    let path = components.into_iter().collect::<Vec<_>>().join(&b'/');
                    (
                        Root::from_directory(parent)?,
                        RelativePath::new(&path)?,
                        0o666 & !crate::fsops::process_umask(),
                    )
                }
                _ => bail!("stream destination must be a regular file or an absent path"),
            };
            root.create_missing_parents(&target, 0o777)?;
            // Keep the temporary in the target's own directory, including when
            // that directory is a mount point beneath the selected root.
            let mut bytes = target
                .to_path_buf()
                .parent()
                .unwrap()
                .as_os_str()
                .as_bytes()
                .to_vec();
            if !bytes.is_empty() {
                bytes.push(b'/');
            }
            let mut random = [0u8; 16];
            getrandom::fill(&mut random).context("generate stream temporary name")?;
            bytes.extend_from_slice(
                format!(
                    ".syq-stream-{}",
                    random
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>()
                )
                .as_bytes(),
            );
            let temporary = RelativePath::new(&bytes)?;
            let file = root.create_file(&temporary, 0o600)?;
            (
                file,
                Some(Destination {
                    root,
                    target,
                    temporary,
                    mode,
                }),
            )
        } else {
            let PinnedPath::Leaf(leaf) = selected else {
                bail!("stream source must be one regular file");
            };
            if !leaf.metadata().is_file() {
                bail!("stream source must be one regular file");
            }
            (leaf.open_read()?, None)
        };
        let original = file.metadata()?;
        Ok(Self {
            remaining: original.len(),
            original,
            file,
            offset: 0,
            hash: Some(settings.algorithm.hasher()),
            settings,
            destination,
        })
    }
    fn unchanged(&self) -> Result<()> {
        let now = self.file.metadata()?;
        anyhow::ensure!(
            now.len() == self.original.len()
                && now.mtime() == self.original.mtime()
                && now.mtime_nsec() == self.original.mtime_nsec()
                && now.ctime() == self.original.ctime()
                && now.ctime_nsec() == self.original.ctime_nsec(),
            "source file changed during descriptor copy"
        );
        Ok(())
    }
    pub(crate) fn handle(slot: &mut Option<Self>, operation: &Operation) -> Result<Response> {
        let result = Self::handle_inner(slot, operation);
        if result.is_err() {
            slot.take();
        }
        result
    }
    fn handle_inner(slot: &mut Option<Self>, operation: &Operation) -> Result<Response> {
        if let Operation::Open {
            path,
            write,
            follow,
            root,
            placement,
            settings,
        } = operation
        {
            anyhow::ensure!(slot.is_none(), "descriptor stream already open");
            *slot = Some(Self::open(
                path,
                *write,
                *follow,
                root.as_deref(),
                placement,
                *settings,
            )?);
            return Ok(Response::DescriptorOpened(
                (!*write).then(|| slot.as_ref().unwrap().remaining),
            ));
        }
        let stream = slot.as_mut().context("no descriptor stream is open")?;
        match operation {
            Operation::Read => {
                anyhow::ensure!(stream.destination.is_none(), "stream is not readable");
                let mut data =
                    vec![0; stream.remaining.min(stream.settings.request_size as u64) as usize];
                stream
                    .file
                    .read_exact(&mut data)
                    .context("read complete source stream block")?;
                stream.unchanged()?;
                let off = stream.offset;
                stream.offset += data.len() as u64;
                stream.remaining -= data.len() as u64;
                stream.hash.as_mut().unwrap().update(&data);
                Ok(Response::Block {
                    off,
                    hash: stream.settings.algorithm.hash(&data),
                    data,
                })
            }
            Operation::Write { off, hash, data } => {
                anyhow::ensure!(stream.destination.is_some(), "stream is not writable");
                anyhow::ensure!(
                    *off == stream.offset
                        && !data.is_empty()
                        && data.len() <= stream.settings.request_size
                        && *hash == stream.settings.algorithm.hash(data),
                    "invalid stream write block"
                );
                stream.file.write_all(data)?;
                stream.hash.as_mut().unwrap().update(data);
                stream.offset = stream
                    .offset
                    .checked_add(data.len() as u64)
                    .context("stream length overflow")?;
                Ok(Response::Ok)
            }
            Operation::Finish { size, hash } => {
                anyhow::ensure!(
                    *size == stream.offset && *hash == stream.hash.take().unwrap().finalize(),
                    "stream completion length or digest mismatch"
                );
                if let Some(destination) = &stream.destination {
                    stream
                        .file
                        .set_permissions(Permissions::from_mode(destination.mode))?;
                    stream.file.sync_all()?;
                    destination.root.rename_regular_if_same(
                        &destination.temporary,
                        &destination.target,
                        (stream.original.dev(), stream.original.ino()),
                    )?;
                } else {
                    anyhow::ensure!(stream.remaining == 0, "source stream is incomplete");
                    stream.unchanged()?;
                }
                slot.take();
                Ok(Response::Ok)
            }
            Operation::Open { .. } => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_or_abandoned_streams_do_not_publish() {
        let temporary = crate::test_support::tempdir().unwrap();
        let target = temporary.path().join("target");
        std::fs::write(&target, b"old").unwrap();
        for corrupt_block in [false, true] {
            let mut slot = None;
            Session::handle(
                &mut slot,
                &Operation::Open {
                    path: target.as_os_str().as_bytes().to_vec(),
                    write: true,
                    follow: false,
                    root: None,
                    placement: StreamPlacement::default(),
                    settings: Settings::default(),
                },
            )
            .unwrap();
            let hash = if corrupt_block {
                [0; 32]
            } else {
                *blake3::hash(b"new").as_bytes()
            };
            let result = Session::handle(
                &mut slot,
                &Operation::Write {
                    off: 0,
                    hash,
                    data: b"new".to_vec(),
                },
            );
            assert_eq!(result.is_err(), corrupt_block);
            if !corrupt_block {
                assert!(Session::handle(&mut slot, &Operation::Finish { size: 4, hash }).is_err());
            }
            assert!(slot.is_none());
            assert_eq!(std::fs::read(&target).unwrap(), b"old");
            assert_eq!(std::fs::read_dir(temporary.path()).unwrap().count(), 1);
        }
        let mut slot = None;
        Session::handle(
            &mut slot,
            &Operation::Open {
                path: target.as_os_str().as_bytes().to_vec(),
                write: true,
                follow: false,
                root: None,
                placement: StreamPlacement::default(),
                settings: Settings::default(),
            },
        )
        .unwrap();
        drop(slot);
        assert_eq!(std::fs::read_dir(temporary.path()).unwrap().count(), 1);
    }

    #[test]
    fn truncated_source_stream_is_an_error() {
        let temporary = crate::test_support::tempdir().unwrap();
        let source = temporary.path().join("source");
        std::fs::write(&source, b"original").unwrap();
        let mut slot = None;
        Session::handle(
            &mut slot,
            &Operation::Open {
                path: source.as_os_str().as_bytes().to_vec(),
                write: false,
                follow: false,
                root: None,
                placement: StreamPlacement::default(),
                settings: Settings::default(),
            },
        )
        .unwrap();
        std::fs::write(&source, b"short").unwrap();
        assert!(Session::handle(&mut slot, &Operation::Read).is_err());
        assert!(slot.is_none());
    }
}

//! Entry-scoped pinned files and private staging, owned by a control session.
use super::{Operation, Settings, StreamPlacement};
use crate::{
    proto::{OperatorSymlinkPolicy, Response},
    rooted::{OperatorFinalComponent, OperatorResolver, PinnedPath, RelativePath, Root},
};
use anyhow::{bail, Context, Result};
use std::{
    fs::{File, Metadata, Permissions},
    os::unix::{
        ffi::OsStrExt,
        fs::{FileExt, MetadataExt, PermissionsExt},
    },
};

#[derive(Default)]
pub(crate) struct Session {
    entries: std::collections::HashMap<u64, FileSession>,
}
impl Session {
    pub(crate) fn handle(
        slot: &mut Self,
        operation: &Operation,
        descriptors: &crate::descriptor_broker::DescriptorSessionSlot,
    ) -> Result<Response> {
        let entry = match operation {
            Operation::Open { entry, .. } => {
                anyhow::ensure!(
                    !slot.entries.contains_key(entry),
                    "descriptor entry already open"
                );
                *entry
            }
            Operation::Finish { entry, .. } | Operation::Abort { entry } => *entry,
        };
        let mut file = slot.entries.remove(&entry);
        let result = FileSession::handle(&mut file, operation, descriptors);
        if let Some(file) = file {
            slot.entries.insert(entry, file);
        }
        result
    }
}

struct Registration {
    slot: crate::descriptor_broker::DescriptorSessionSlot,
    ticket: crate::descriptor_broker::DescriptorTicket,
}
impl Drop for Registration {
    fn drop(&mut self) {
        self.slot.release_stream(&self.ticket);
    }
}

struct FileSession {
    file: File,
    original: Metadata,
    destination: Option<Destination>,
    registration: Option<Registration>,
}
struct Destination {
    root: Root,
    target: RelativePath,
    temporary: RelativePath,
    mode: u32,
    source_meta: Option<crate::proto::Meta>,
    metadata: super::metadata::Policy,
    existed: bool,
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
    let final_component = OperatorFinalComponent::StreamSource {
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
    create_container: bool,
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
            if !create_container {
                return Ok(PinnedPath::Missing(missing));
            }
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

impl FileSession {
    fn open(
        selected: PinnedPath,
        write: bool,
        metadata: super::metadata::Policy,
        source_meta: Option<crate::proto::Meta>,
    ) -> Result<Self> {
        let existed = !matches!(&selected, PinnedPath::Missing(_));
        let new_mode =
            source_meta.as_ref().map_or(0o666, |m| m.mode & 0o777) & !crate::fsops::process_umask();
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
                            meta.mode & 0o7777
                        } else {
                            new_mode
                        },
                    )
                }
                PinnedPath::Missing(missing) => {
                    let (parent, components) = missing.into_parts();
                    let path = components.into_iter().collect::<Vec<_>>().join(&b'/');
                    (
                        Root::from_directory(parent)?,
                        RelativePath::new(&path)?,
                        new_mode,
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
                    mode: if metadata.preserve & crate::proto::flags::MODE != 0 {
                        source_meta
                            .as_ref()
                            .context("missing source permissions")?
                            .mode
                    } else {
                        mode
                    },
                    source_meta,
                    metadata,
                    existed,
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
            original,
            file,
            destination,
            registration: None,
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
    pub(crate) fn handle(
        slot: &mut Option<Self>,
        operation: &Operation,
        descriptors: &crate::descriptor_broker::DescriptorSessionSlot,
    ) -> Result<Response> {
        let result = (|| match operation {
            Operation::Open {
                entry: _,
                dry_run,
                only_new,
                only_existing,
                path,
                write,
                follow,
                root,
                placement,
                settings,
                metadata,
                source_meta,
            } => {
                anyhow::ensure!(slot.is_none(), "descriptor stream already open");
                anyhow::ensure!(
                    (512..=64 << 20).contains(&settings.request_size),
                    "invalid stream request size"
                );
                if *write {
                    metadata.source(source_meta.clone())?;
                }
                let check_only = *dry_run || *only_new || *only_existing || metadata.skip_newer;
                let mut selected = if *write {
                    anyhow::ensure!(
                        root.is_none(),
                        "source root does not apply to a destination"
                    );
                    resolve_destination(path, *follow, placement, !check_only)?
                } else {
                    resolve_source(path, root.as_deref(), *follow)?
                };
                let exists = !matches!(selected, PinnedPath::Missing(_));
                if *write && ((*only_new && exists) || (*only_existing && !exists)) {
                    return Ok(Response::DescriptorInspected {
                        skipped: true,
                        size: None,
                        metadata: None,
                    });
                }
                if *write && exists && metadata.if_exists == Some(crate::cli::IfExists::Error) {
                    bail!("destination already exists (--if-exists=error)");
                }
                let size = match &selected {
                    PinnedPath::Leaf(leaf) if leaf.metadata().is_file() => {
                        (!*write).then_some(leaf.metadata().len)
                    }
                    PinnedPath::Leaf(leaf) if *write && leaf.metadata().is_symlink() => None,
                    PinnedPath::Missing(_) if *write => None,
                    _ => bail!(
                        "stream {} must be a regular file{}",
                        if *write { "destination" } else { "source" },
                        if *write { " or an absent path" } else { "" }
                    ),
                };
                let file_meta = match &selected {
                    PinnedPath::Leaf(leaf) if leaf.metadata().is_file() => {
                        let m = leaf.metadata();
                        Some(crate::proto::Meta {
                            inode_metadata: None,
                            mode: m.mode & 0o7777,
                            uid: m.uid,
                            gid: m.gid,
                            mtime: m.mtime,
                            mtime_nsec: m.mtime_nsec,
                        })
                    }
                    _ => None,
                };
                let skipped = if *write {
                    metadata.newer(source_meta.clone(), file_meta.clone())
                } else {
                    *only_new
                };
                if *dry_run || skipped {
                    return Ok(Response::DescriptorInspected {
                        skipped,
                        size,
                        metadata: (!*write).then_some(file_meta).flatten(),
                    });
                }
                // A policy check must not create directories for a skipped copy.
                // An eligible --into copy can create its missing container now.
                if *write
                    && check_only
                    && placement.name.is_some()
                    && matches!(selected, PinnedPath::Missing(_))
                {
                    selected = resolve_destination(path, *follow, placement, true)?;
                }
                let mut stream = Self::open(selected, *write, *metadata, source_meta.clone())?;
                let size = (!*write).then_some(stream.original.len());
                let ticket = descriptors.register_stream(stream.file.try_clone()?, *write)?;
                stream.registration = Some(Registration {
                    slot: descriptors.clone(),
                    ticket: ticket.clone(),
                });
                let metadata = (!*write).then(|| super::metadata::from_file(&stream.original));
                *slot = Some(stream);
                Ok(Response::DescriptorOpened {
                    size,
                    ticket,
                    metadata,
                })
            }
            Operation::Finish { size, .. } => {
                let stream = slot.as_ref().context("no descriptor stream is open")?;
                anyhow::ensure!(
                    stream.file.metadata()?.len() == *size,
                    "stream completion length mismatch"
                );
                if let Some(destination) = &stream.destination {
                    let protected = matches!(
                        destination.metadata.if_exists,
                        Some(crate::cli::IfExists::ErrorIfDifferent | crate::cli::IfExists::Error)
                    );
                    if protected && destination.existed {
                        let existing = destination.root.open_regular_read(&destination.target)?;
                        anyhow::ensure!(
                            same_contents(&stream.file, &existing)?,
                            "destination contents differ (--if-exists=error-if-different)"
                        );
                        let base = destination
                            .source_meta
                            .clone()
                            .map(|meta| (meta, destination.metadata.preserve));
                        if let Some((meta, flags)) =
                            with_overrides(&existing, base, destination.metadata.overrides)?
                        {
                            crate::fsops::set_meta_file(&existing, &meta, flags)?;
                        }
                        slot.take();
                        return Ok(Response::Ok);
                    }
                    let base = match destination.source_meta.clone() {
                        Some(mut meta) => {
                            meta.mode = destination.mode;
                            let times = if destination.metadata.restore_named_mtime {
                                crate::proto::flags::TIMES
                            } else {
                                0
                            };
                            Some((
                                meta,
                                crate::proto::flags::MODE | times | destination.metadata.preserve,
                            ))
                        }
                        None if destination.metadata.overrides.is_some() => {
                            let mut meta = super::metadata::from_file(&stream.file.metadata()?);
                            meta.mode = destination.mode;
                            Some((meta, crate::proto::flags::MODE))
                        }
                        None => None,
                    };
                    match with_overrides(&stream.file, base, destination.metadata.overrides)? {
                        Some((meta, flags)) => {
                            crate::fsops::set_meta_file(&stream.file, &meta, flags)?
                        }
                        None => {
                            stream
                                .file
                                .set_permissions(Permissions::from_mode(destination.mode))?;
                            crate::fsops::access_changed(&stream.file);
                        }
                    }
                    stream.file.sync_all()?;
                    if protected {
                        destination.root.publish_new_regular(
                            &destination.temporary,
                            &destination.target,
                            (stream.original.dev(), stream.original.ino()),
                        )?;
                    } else {
                        destination.root.rename_regular_if_same(
                            &destination.temporary,
                            &destination.target,
                            (stream.original.dev(), stream.original.ino()),
                        )?;
                    }
                } else {
                    stream.unchanged()?;
                }
                slot.take();
                Ok(Response::Ok)
            }
            Operation::Abort { .. } => {
                slot.take();
                Ok(Response::Ok)
            }
        })();
        if result.is_err() {
            slot.take();
        }
        result
    }
}

/// A destination's final metadata and the flags selecting it: `base`, with
/// what a mapping entry's metadata overrides replaced. Applying it in one
/// step means no other mode comes first, which would let anyone it admits
/// open the finished file and keep reading it once the override narrows it.
fn with_overrides(
    file: &File,
    base: Option<(crate::proto::Meta, u8)>,
    overrides: Option<crate::mapping::Metadata>,
) -> Result<Option<(crate::proto::Meta, u8)>> {
    let Some(attributes) = overrides else {
        return Ok(base);
    };
    let (mut meta, flags) = match base {
        Some(base) => base,
        None => (super::metadata::from_file(&file.metadata()?), 0),
    };
    attributes.apply(&mut meta);
    Ok(Some((meta, flags | attributes.apply_flags())))
}

fn same_contents(left: &File, right: &File) -> Result<bool> {
    let size = left.metadata()?.len();
    if right.metadata()?.len() != size {
        return Ok(false);
    }
    let mut left_bytes = vec![0u8; 64 * 1024];
    let mut right_bytes = vec![0u8; 64 * 1024];
    let mut offset = 0;
    while offset < size {
        let n = (size - offset).min(left_bytes.len() as u64) as usize;
        left.read_exact_at(&mut left_bytes[..n], offset)?;
        right.read_exact_at(&mut right_bytes[..n], offset)?;
        if left_bytes[..n] != right_bytes[..n] {
            return Ok(false);
        }
        offset += n as u64;
    }
    Ok(true)
}

/// Uses the ordinary range frames and direct payload encoding, confined to
/// the already-open file. No worker can choose a different pathname or publish.
pub(crate) struct FileWorker {
    file: File,
    write: bool,
    settings: Settings,
}
impl FileWorker {
    pub(crate) fn new(file: File, write: bool, settings: Settings) -> Result<Self> {
        anyhow::ensure!(
            file.metadata()?.is_file(),
            "stream worker needs a regular file"
        );
        anyhow::ensure!(
            (512..=64 << 20).contains(&settings.request_size),
            "invalid stream request size"
        );
        Ok(Self {
            file,
            write,
            settings,
        })
    }
    pub(crate) fn handle(&self, request: &crate::proto::Request) -> Result<Response> {
        use crate::proto::Request;
        match request {
            Request::ReadRange {
                path,
                source: None,
                off,
                len,
                ..
            } if !self.write && path.is_empty() && *len as usize <= self.settings.request_size => {
                let mut data = vec![0; *len as usize];
                self.file
                    .read_exact_at(&mut data, *off)
                    .context("read complete stream range")?;
                Ok(Response::Block {
                    off: *off,
                    hash: self.settings.hash(&data),
                    data,
                })
            }
            Request::WriteRange {
                path,
                off,
                data,
                hash,
                ..
            } if self.write
                && path.is_empty()
                && !data.is_empty()
                && data.len() <= self.settings.request_size =>
            {
                anyhow::ensure!(
                    self.settings.matches(data, *hash),
                    "stream range digest mismatch"
                );
                self.file.write_all_at(data, *off)?;
                Ok(Response::Ok)
            }
            Request::Shutdown => Ok(Response::Ok),
            _ => bail!("request is not valid for this stream file capability"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{descriptor_broker::DescriptorSessionSlot, proto::Request};

    #[test]
    fn parallel_workers_are_confined_and_publication_waits_for_finish() {
        let temporary = crate::test_support::tempdir().unwrap();
        let target = temporary.path().join("target");
        std::fs::write(&target, b"old").unwrap();
        let descriptors = DescriptorSessionSlot::default();
        let mut slot = Session::default();
        let open = Operation::Open {
            entry: 1,
            dry_run: false,
            only_new: false,
            only_existing: false,
            path: target.as_os_str().as_bytes().to_vec(),
            write: true,
            follow: false,
            root: None,
            placement: StreamPlacement::default(),
            metadata: Default::default(),
            source_meta: None,
            settings: Settings {
                verify: true,
                ..Settings::default()
            },
        };
        let Response::DescriptorOpened { ticket, .. } =
            Session::handle(&mut slot, &open, &descriptors).unwrap()
        else {
            panic!()
        };
        let first = FileWorker::new(
            descriptors.acquire(&ticket).unwrap(),
            ticket.stream_write().unwrap(),
            Settings {
                verify: true,
                ..Settings::default()
            },
        )
        .unwrap();
        let second = FileWorker::new(
            descriptors.acquire(&ticket).unwrap(),
            true,
            Settings {
                verify: true,
                ..Settings::default()
            },
        )
        .unwrap();
        let write = |off, data: &[u8]| Request::WriteRange {
            path: Vec::new(),
            inplace: true,
            copy_id: [0; 16],
            attempt: 0,
            off,
            hash: Settings::default().algorithm.hash(data),
            data: data.to_vec().into(),
            guard: None,
        };
        second.handle(&write(3, b"two")).unwrap();
        first.handle(&write(0, b"one")).unwrap();
        let mut wrong_path = write(0, b"bad");
        if let Request::WriteRange { path, .. } = &mut wrong_path {
            *path = b"another-file".to_vec();
        }
        assert!(first.handle(&wrong_path).is_err());
        let mut corrupt = write(0, b"bad");
        if let Request::WriteRange { hash, .. } = &mut corrupt {
            *hash = [0; 32];
        }
        assert!(first.handle(&corrupt).is_err());
        assert!(first
            .handle(&Request::DescriptorCopy(Operation::Finish {
                entry: 1,
                size: 6
            }))
            .is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"old");
        Session::handle(
            &mut slot,
            &Operation::Finish { entry: 1, size: 6 },
            &descriptors,
        )
        .unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"onetwo");
        assert!(descriptors.acquire(&ticket).is_err());
        assert!(slot.entries.is_empty());
        // Bad lengths and abandoned sessions preserve the already-published file.
        Session::handle(&mut slot, &open, &descriptors).unwrap();
        assert!(Session::handle(
            &mut slot,
            &Operation::Finish { entry: 1, size: 1 },
            &descriptors
        )
        .is_err());
        Session::handle(&mut slot, &open, &descriptors).unwrap();
        drop(slot);
        assert_eq!(std::fs::read_dir(temporary.path()).unwrap().count(), 1);
        assert_eq!(std::fs::read(&target).unwrap(), b"onetwo");
    }

    #[test]
    fn a_metadata_override_is_the_first_mode_the_finished_file_gets() {
        // A mapping entry's metadata replaces the mode the destination would
        // otherwise get. The finished file must take it at once: a default
        // or source mode on the way lets anyone it admits open the file and
        // keep reading it after the override narrows it.
        let mut exposed = Vec::new();
        for case in ["callback source", "file source", "existing destination"] {
            let temporary = crate::test_support::tempdir().unwrap();
            let target = temporary.path().join("target");
            let existing = case == "existing destination";
            if existing {
                std::fs::write(&target, b"private").unwrap();
                std::fs::set_permissions(&target, Permissions::from_mode(0o600)).unwrap();
            }
            let source_meta = (case != "callback source").then_some(crate::proto::Meta {
                inode_metadata: None,
                mode: 0o644,
                uid: 0,
                gid: 0,
                mtime: 0,
                mtime_nsec: 0,
            });
            let metadata = super::super::metadata::Policy {
                preserve: if existing {
                    crate::proto::flags::MODE
                } else {
                    0
                },
                if_exists: existing.then_some(crate::cli::IfExists::ErrorIfDifferent),
                overrides: Some(crate::mapping::Metadata {
                    mode: Some(0o640),
                    ..Default::default()
                }),
                ..Default::default()
            };
            let descriptors = DescriptorSessionSlot::default();
            let mut slot = Session::default();
            let Response::DescriptorOpened { ticket, .. } = Session::handle(
                &mut slot,
                &Operation::Open {
                    entry: 1,
                    dry_run: false,
                    only_new: false,
                    only_existing: false,
                    path: target.as_os_str().as_bytes().to_vec(),
                    write: true,
                    follow: false,
                    root: None,
                    placement: StreamPlacement::default(),
                    settings: Settings::default(),
                    metadata,
                    source_meta,
                },
                &descriptors,
            )
            .unwrap() else {
                panic!()
            };
            let worker = FileWorker::new(
                descriptors.acquire(&ticket).unwrap(),
                ticket.stream_write().unwrap(),
                Settings::default(),
            )
            .unwrap();
            worker
                .handle(&Request::WriteRange {
                    path: Vec::new(),
                    inplace: true,
                    copy_id: [0; 16],
                    attempt: 0,
                    off: 0,
                    hash: [0; 32],
                    data: b"private".to_vec().into(),
                    guard: None,
                })
                .unwrap();
            let modes = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
            let observed = modes.clone();
            crate::fsops::ACCESS_CHANGED.set(Some(Box::new(move |file: &File| {
                observed
                    .borrow_mut()
                    .push(file.metadata().unwrap().mode() & 0o7777);
            })));
            let finished = Session::handle(
                &mut slot,
                &Operation::Finish { entry: 1, size: 7 },
                &descriptors,
            );
            crate::fsops::ACCESS_CHANGED.set(None);
            finished.unwrap();
            assert_eq!(std::fs::read(&target).unwrap(), b"private", "{case}");
            assert_eq!(
                std::fs::metadata(&target).unwrap().mode() & 0o7777,
                0o640,
                "{case}"
            );
            let modes = modes.borrow();
            assert!(!modes.is_empty(), "{case}");
            if modes.iter().any(|&mode| mode != 0o640) {
                let modes = modes.iter().map(|mode| format!("{mode:o}"));
                exposed.push(format!("{case}: {:?}", modes.collect::<Vec<_>>()));
            }
        }
        assert!(
            exposed.is_empty(),
            "the file took other modes on the way: {exposed:?}"
        );
    }

    #[test]
    fn source_ticket_cannot_write_and_changed_source_fails_finish() {
        let temporary = crate::test_support::tempdir().unwrap();
        let target = temporary.path().join("source");
        std::fs::write(&target, b"old").unwrap();
        let descriptors = DescriptorSessionSlot::default();
        let mut slot = Session::default();
        let Response::DescriptorOpened { size, ticket, .. } = Session::handle(
            &mut slot,
            &Operation::Open {
                entry: 1,
                dry_run: false,
                only_new: false,
                only_existing: false,
                path: target.as_os_str().as_bytes().to_vec(),
                write: false,
                follow: false,
                root: None,
                placement: StreamPlacement::default(),
                settings: Settings::default(),
                metadata: Default::default(),
                source_meta: None,
            },
            &descriptors,
        )
        .unwrap() else {
            panic!()
        };
        assert_eq!(size, Some(3));
        let worker = FileWorker::new(
            descriptors.acquire(&ticket).unwrap(),
            ticket.stream_write().unwrap(),
            Settings::default(),
        )
        .unwrap();
        assert!(worker
            .handle(&Request::WriteRange {
                path: Vec::new(),
                inplace: true,
                copy_id: [0; 16],
                attempt: 0,
                off: 0,
                hash: [0; 32],
                data: b"bad".to_vec().into(),
                guard: None
            })
            .is_err());
        std::fs::write(target, b"changed").unwrap();
        assert!(Session::handle(
            &mut slot,
            &Operation::Finish { entry: 1, size: 3 },
            &descriptors
        )
        .is_err());
    }
}

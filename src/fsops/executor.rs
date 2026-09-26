//! One data executor owns its roots, partials, cache and live file handles.
//! The server retains sockets and authority/receipt state in their original
//! descriptor domain. Requests and buffers move, without serialization or
//! cloning, over a bounded channel; no descriptor-bearing value crosses it.
use super::*;
use std::sync::mpsc;

#[derive(Clone, Copy)]
pub(super) struct Settings {
    pub(super) preservation: crate::inode_metadata::Selection,
    pub(super) sparse: bool,
    pub(super) hashing: crate::hashing::HashPolicy,
}

struct Work {
    request: Request,
    settings: Settings,
}

enum Command {
    Execute(Box<Work>),
    BeginRead(std::ops::Range<u64>),
    ShrinkRead(u64),
    EndRead,
}

enum Event {
    Finished(Box<(Request, Response)>),
    Progress(u64, mpsc::SyncSender<std::result::Result<(), String>>),
}

pub(super) struct Executor {
    commands: Option<mpsc::SyncSender<Command>>,
    events: Option<Mutex<mpsc::Receiver<Event>>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Executor {
    fn drop(&mut self) {
        // Wake a blocked result/progress sender before joining. Cancellation
        // cannot strand a worker waiting for a reply from a vanished caller.
        self.events.take();
        self.commands.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Executor {
    pub(super) fn start(owner: &FsOps) -> Result<Option<Self>> {
        let mut handles = Vec::new();
        let mut sources = Vec::new();
        for (&id, source) in &owner.source_roots {
            handles.push(source.root.directory_descriptor());
            if let Some(leaf) = &source._leaf_object {
                handles.push(leaf.as_ref());
            }
            sources.push((
                id,
                source.selection.clone(),
                source.expected_leaf.clone(),
                source._leaf_object.is_some(),
            ));
        }
        let has_destination = owner.destination_root.is_some();
        if let Some(root) = &owner.destination_root {
            handles.push(root.directory_descriptor());
        }
        let stream = owner.stream_worker.as_ref().map(|stream| {
            let (file, write, settings) = stream.bootstrap();
            handles.push(file);
            (write, settings)
        });
        let prefix = owner.destination_prefix.clone();
        let stream_ticket = owner.stream_ticket.clone();
        let unconfined = owner.allow_unconfined_source_paths;
        let observations = owner.observations.clone();
        let (commands, rx) = mpsc::sync_channel(1);
        let (tx, events) = mpsc::sync_channel(1);
        // SAFETY: captured source records, settings, observations and channels
        // contain no descriptors. All owning Files arrive through SCM_RIGHTS;
        // original roots, sockets and authority/receipt state stay with owner.
        let thread = unsafe {
            crate::fs_executor::spawn(
                "syq-file-executor".into(),
                true,
                &handles,
                move |handles| {
                    let mut handles = handles.into_iter();
                    let mut ops =
                        FsOps::with_observations(DescriptorSessionSlot::default(), observations);
                    for (id, selection, expected_leaf, has_leaf) in sources {
                        let root = Arc::new(Root::from_directory(
                            handles.next().context("missing source root handoff")?,
                        )?);
                        let leaf = if has_leaf {
                            Some(Arc::new(
                                handles.next().context("missing source leaf handoff")?,
                            ))
                        } else {
                            None
                        };
                        ops.source_roots.insert(
                            id,
                            SourceRootHandle {
                                root,
                                selection,
                                expected_leaf,
                                _leaf_object: leaf,
                            },
                        );
                    }
                    if has_destination {
                        ops.destination_root = Some(Arc::new(Root::from_directory(
                            handles.next().context("missing destination root handoff")?,
                        )?));
                        ops.destination_prefix = prefix;
                    }
                    if let Some((write, settings)) = stream {
                        ops.stream_worker = Some(crate::descriptor_copy::FileWorker::new(
                            handles.next().context("missing stream handoff")?,
                            write,
                            settings,
                        )?);
                        ops.stream_ticket = stream_ticket;
                    }
                    ops.allow_unconfined_source_paths = unconfined;
                    anyhow::ensure!(
                        handles.next().is_none(),
                        "unexpected executor handoff descriptor"
                    );
                    Ok(ops)
                },
                move |mut ops| {
                    while let Ok(command) = rx.recv() {
                        match command {
                            Command::BeginRead(range) => ops.begin_source_range(range),
                            Command::ShrinkRead(end) => ops.shrink_source_range(end),
                            Command::EndRead => ops.end_source_range(),
                            Command::Execute(work) => {
                                let Work {
                                    mut request,
                                    settings,
                                } = *work;
                                ops.inode_preservation = settings.preservation;
                                ops.sparse = settings.sparse;
                                ops.hash_policy = settings.hashing;
                                let result =
                                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                        ops.handle_with_copy_progress(&mut request, &mut |bytes| {
                                            let (reply, received) = mpsc::sync_channel(1);
                                            tx.send(Event::Progress(bytes, reply)).map_err(
                                                |_| anyhow!("filesystem executor caller stopped"),
                                            )?;
                                            received
                                                .recv()
                                                .context("filesystem progress caller stopped")?
                                                .map_err(anyhow::Error::msg)
                                        })
                                    }));
                                let (response, failed) = match result {
                                    Ok(response) => (response, false),
                                    Err(_) => {
                                        (Response::Err("filesystem executor panicked".into()), true)
                                    }
                                };
                                if tx
                                    .send(Event::Finished(Box::new((request, response))))
                                    .is_err()
                                    || failed
                                {
                                    break;
                                }
                            }
                        }
                    }
                },
            )?
        };
        Ok(thread.map(|thread| Self {
            commands: Some(commands),
            events: Some(Mutex::new(events)),
            thread: Some(thread),
        }))
    }

    // Only file-data operations cross this boundary. Directory scans and
    // metadata pools may borrow handles and remain with their original owner.
    // A new request must be audited here before it can enter the private table.
    pub(super) fn handles(request: &Request) -> bool {
        matches!(
            request,
            Request::ProbePartial { .. }
                | Request::Prepare { .. }
                | Request::HashAndHold { .. }
                | Request::FinishBasis { .. }
                | Request::SeedBasis { .. }
                | Request::CopyLocal { .. }
                | Request::HashBlocks { .. }
                | Request::ReadRange { .. }
                | Request::ReadSmallBatch(_)
                | Request::WriteRange { .. }
                | Request::Finalize { .. }
                | Request::PutSmallBatch(_)
                | Request::FileHash { .. }
                | Request::ValidateDigest { .. }
                | Request::BindStream(_)
        )
    }

    pub(super) fn execute(
        &mut self,
        request: &mut Request,
        settings: Settings,
        progress: &mut dyn FnMut(u64) -> Result<()>,
    ) -> Response {
        let work = Work {
            request: std::mem::replace(request, Request::TransportStats),
            settings,
        };
        if let Err(error) = self
            .commands
            .as_ref()
            .unwrap()
            .send(Command::Execute(Box::new(work)))
        {
            if let Command::Execute(work) = error.0 {
                *request = work.request;
            }
            return Response::Err("filesystem executor stopped".into());
        }
        loop {
            match self.events.as_mut().unwrap().get_mut().unwrap().recv() {
                Ok(Event::Finished(result)) => {
                    let (completed, response) = *result;
                    *request = completed;
                    return response;
                }
                Ok(Event::Progress(bytes, reply)) => {
                    let _ = reply.send(progress(bytes).map_err(|error| format!("{error:#}")));
                }
                Err(_) => {
                    return Response::Err(
                        "filesystem executor stopped before returning a result".into(),
                    )
                }
            }
        }
    }

    pub(super) fn begin_read(&self, range: std::ops::Range<u64>) {
        let _ = self
            .commands
            .as_ref()
            .unwrap()
            .send(Command::BeginRead(range));
    }
    pub(super) fn shrink_read(&self, end: u64) {
        let _ = self
            .commands
            .as_ref()
            .unwrap()
            .send(Command::ShrinkRead(end));
    }
    pub(super) fn end_read(&self) {
        let _ = self.commands.as_ref().unwrap().send(Command::EndRead);
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::io::Read;

    fn setup(directory: &Path) -> (FsOps, DescriptorSessionSlot) {
        let session = DescriptorSessionSlot::default();
        let destination = DestinationRoot {
            ticket: session.register(File::open(directory).unwrap()).unwrap(),
            request_prefix: b"logical".to_vec(),
        };
        let role = ConnectionRole::DestinationWorker {
            destination: Some(destination.clone()),
            copy_sources: Vec::new(),
        };
        let mut ops = FsOps::with_descriptor_session(session.clone());
        ops.initialize_destination(&destination).unwrap();
        ops.start_data_executor(&role).unwrap();
        (ops, session)
    }

    fn put(name: &[u8], bytes: &[u8]) -> SmallPut {
        SmallPut {
            path: name.to_vec(),
            copy_id: [7; 16],
            data: bytes.to_vec(),
            hash: content_digest(bytes),
            meta: Meta {
                mode: 0o600,
                uid: 0,
                gid: 0,
                mtime: 0,
                mtime_nsec: 0,
                inode_metadata: None,
            },
            flags: 0,
            inplace: false,
            condition: TargetCondition::Absent,
            guard: None,
        }
    }

    #[test]
    fn private_data_executor_keeps_selected_root_and_moves_payload_without_copying() {
        let temporary = crate::test_support::tempdir().unwrap();
        let path = temporary.path().join("root");
        let moved = temporary.path().join("moved");
        fs::create_dir(&path).unwrap();
        let (mut ops, _session) = setup(&path);
        fs::rename(&path, &moved).unwrap();
        fs::create_dir(&path).unwrap();
        let put = put(b"logical/file", b"hello executor");
        let pointer = put.data.as_ptr();
        let mut request = Request::PutSmallBatch(vec![put]);
        assert!(
            matches!(ops.handle_in_place(&mut request), Response::Applied(errors) if errors == vec![None])
        );
        let Request::PutSmallBatch(puts) = request else {
            panic!("request was not returned");
        };
        assert_eq!(puts[0].data.as_ptr(), pointer);
        assert_eq!(fs::read(moved.join("file")).unwrap(), b"hello executor");
        assert!(!path.join("file").exists());
    }

    #[test]
    fn executor_does_not_keep_unrelated_connections_alive() {
        let temporary = crate::test_support::tempdir().unwrap();
        let (mut reader, writer) = std::os::unix::net::UnixStream::pair().unwrap();
        reader
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let (_ops, _session) = setup(temporary.path());
        drop(writer);
        // A private table that merely unshared, without closing inherited
        // sockets, would still own writer and this read would time out.
        assert_eq!(reader.read(&mut [0]).unwrap(), 0);
    }

    #[test]
    fn executor_errors_do_not_poison_later_files() {
        let temporary = crate::test_support::tempdir().unwrap();
        let (mut ops, _session) = setup(temporary.path());
        let mut invalid = put(b"logical/bad", b"original bytes");
        invalid.data[0] ^= 1;
        let response = ops.handle_in_place(&mut Request::PutSmallBatch(vec![
            invalid,
            put(b"logical/good", b"good"),
        ]));
        let Response::Applied(errors) = response else {
            panic!("expected per-file result");
        };
        assert!(errors[0].is_some());
        assert!(errors[1].is_none());
        assert!(!temporary.path().join("bad").exists());
        assert_eq!(fs::read(temporary.path().join("good")).unwrap(), b"good");
        let mut request = Request::PutSmallBatch(vec![put(b"logical/next", b"next")]);
        assert!(
            matches!(ops.handle_in_place(&mut request), Response::Applied(errors) if errors == vec![None])
        );
    }
}

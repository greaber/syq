//! Directory iterators stay with their executor. Only unopened descriptions and
//! entry batches move through the dispatcher. A lone wide directory can lend
//! its exact opened handle to idle stat helpers with SCM_RIGHTS.
use super::*;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::thread::JoinHandle;

#[derive(Clone)]
pub(super) struct Options {
    pub(super) scan_root: PathBytes,
    pub(super) hold_destination_for_test: bool,
    pub(super) ignore: Option<Gitignore>,
    pub(super) report_ignored: bool,
}

impl Options {
    fn scan<'a>(&'a self, root: &'a Root) -> DescriptorScan<'a> {
        DescriptorScan {
            root,
            scan_root: &self.scan_root,
            hold_destination_for_test: self.hold_destination_for_test,
            ignore: self.ignore.as_ref(),
            report_ignored: self.report_ignored,
        }
    }
}

pub(super) fn start(
    root: &Root,
    options: Options,
    directories: Vec<UnopenedDirectory>,
    output: SyncSender<ScanChunk>,
) -> Result<JoinHandle<()>> {
    // SAFETY: options, unopened descriptions and the output channel contain no
    // descriptors. The producer receives its own root before it starts work.
    unsafe {
        crate::fs_executor::spawn(
            "syq-descriptor-scan".into(),
            false,
            &[root.directory_descriptor()],
            |mut handles| Root::from_directory(handles.pop().context("missing scanner root")?),
            move |root| {
                if let Err(error) = produce(&root, options, directories, &output) {
                    let _ = output.send(vec![ScanEvent::Warning(format!("scan: {error:#}"))]);
                }
            },
        )?
    }
    .context("start descriptor scan producer")
}

enum Job {
    Open(UnopenedDirectory),
    Continue,
}

enum Command {
    Step {
        job: Job,
        retain: usize,
        parallel_stats: bool,
    },
    Stat {
        parent: PathBytes,
        names: Vec<PathBytes>,
    },
}

struct StepResult {
    events: ScanChunk,
    unopened: Vec<UnopenedDirectory>,
    retained: usize,
}

enum Event {
    Done(usize, StepResult),
    Inspect(
        usize,
        PathBytes,
        Vec<PathBytes>,
        SyncSender<Result<Inspected>>,
    ),
    Stats(usize, Result<Inspected>),
    Failed(usize),
}

fn send_directory(socket: &UnixStream, directory: &File) -> Result<()> {
    crate::descriptor_broker::send_message(socket.as_raw_fd(), &[2], &[directory.as_raw_fd()])
        .context("send scan directory")
}

fn receive_directory(socket: &UnixStream) -> Result<File> {
    let (payload, mut files) = crate::descriptor_broker::receive_message(socket, 1)?;
    anyhow::ensure!(
        payload == [2] && files.len() == 1,
        "invalid scan directory handoff"
    );
    Ok(files.pop().unwrap())
}

fn next_job(pending: &mut Vec<UnopenedDirectory>, retained: usize) -> Option<Job> {
    if retained != 0 {
        Some(Job::Continue)
    } else {
        pending.pop().map(Job::Open)
    }
}

fn step(
    scan: &DescriptorScan<'_>,
    local: &mut Vec<DescriptorDirectory>,
    job: Job,
    retain: usize,
    inspect: &mut impl FnMut(&Root, &File, &[u8], &[PathBytes]) -> Result<Inspected>,
) -> StepResult {
    let directory = match job {
        Job::Continue => local
            .pop()
            .expect("retained directory belongs to this executor"),
        Job::Open(directory) => DescriptorDirectory {
            relative: directory.relative,
            expected: directory.expected,
            opened: None,
            names: None,
        },
    };
    let label = directory.relative.clone();
    let mut unopened = Vec::new();
    let events = match scan.step(directory, retain, inspect) {
        Ok(step) => {
            let mut held = Vec::new();
            for child in step.children {
                if child.opened.is_some() {
                    held.push(child);
                } else {
                    unopened.push(UnopenedDirectory {
                        relative: child.relative,
                        expected: child.expected,
                    });
                }
            }
            held.reverse();
            local.extend(held);
            // Finish an opened name list before admitting another one.
            local.extend(step.remainder);
            step.events
        }
        Err(error) => vec![ScanEvent::Warning(format!(
            "scan: {}: {error:#}",
            String::from_utf8_lossy(&label)
        ))],
    };
    StepResult {
        events,
        unopened,
        retained: local.len(),
    }
}

struct Worker {
    commands: Option<SyncSender<Command>>,
    socket: Option<UnixStream>,
    thread: Option<JoinHandle<()>>,
    retained: usize,
}

struct Pool {
    workers: Vec<Worker>,
    events: Option<Receiver<Event>>,
    output: mpsc::Sender<Event>,
    limit: usize,
    cannot_grow: bool,
}

impl Default for Pool {
    fn default() -> Self {
        let (output, events) = mpsc::channel();
        Self {
            workers: Vec::new(),
            events: Some(events),
            output,
            // This is the previous scanner's concurrency ceiling. Workers are
            // now created only for independent directories or a wide stat batch.
            limit: std::thread::available_parallelism()
                .map_or(1, usize::from)
                .min(DESCRIPTOR_STAT_THREADS)
                .saturating_sub(1),
            cannot_grow: false,
        }
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        // Dropping queued reply senders unblocks a directory worker asking for
        // stat help. Close handoff sockets before joining any receiver.
        self.events.take();
        for worker in &mut self.workers {
            worker.commands.take();
            worker.socket.take();
        }
        for worker in &mut self.workers {
            if let Some(thread) = worker.thread.take() {
                let _ = thread.join();
            }
        }
    }
}

impl Pool {
    fn grow(&mut self, root: &Root, options: &Options, wanted: usize) {
        while !self.cannot_grow && self.workers.len() < wanted.min(self.limit) {
            if self.add_worker(root, options).is_err() {
                // Additional workers are optional; the selected root and
                // existing workers remain usable under resource pressure.
                self.cannot_grow = true;
            }
        }
    }

    fn add_worker(&mut self, root: &Root, options: &Options) -> Result<()> {
        let index = self.workers.len();
        let (commands, incoming) = mpsc::sync_channel::<Command>(1);
        let events = self.output.clone();
        let options = options.clone();
        // SAFETY: callbacks capture only options/channels. Root and handoff
        // socket are imported/created on this executor, and never leave it.
        let (thread, socket) = unsafe {
            crate::fs_executor::spawn_connected(
                format!("syq-scan-{index}"),
                false,
                &[root.directory_descriptor()],
                |mut handles, socket| {
                    Ok((
                        Root::from_directory(handles.pop().context("missing scanner root")?)?,
                        socket,
                    ))
                },
                move |(root, socket)| {
                    let scan = options.scan(&root);
                    let mut local = Vec::new();
                    while let Ok(command) = incoming.recv() {
                        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                            || match command {
                                Command::Step {
                                    job,
                                    retain,
                                    parallel_stats,
                                } => {
                                    let result = step(
                                        &scan,
                                        &mut local,
                                        job,
                                        retain,
                                        &mut |root, directory, parent, names| {
                                            if !parallel_stats
                                                || names.len() < DESCRIPTOR_STAT_PAR_MIN
                                            {
                                                return Ok(inspect_descriptor_children(
                                                    root, directory, parent, names,
                                                ));
                                            }
                                            send_directory(&socket, directory)?;
                                            let (reply, received) = mpsc::sync_channel(1);
                                            events
                                                .send(Event::Inspect(
                                                    index,
                                                    parent.to_vec(),
                                                    names.to_vec(),
                                                    reply,
                                                ))
                                                .context("scan dispatcher stopped")?;
                                            received
                                                .recv()
                                                .context("scan stat dispatcher stopped")?
                                        },
                                    );
                                    Event::Done(index, result)
                                }
                                Command::Stat { parent, names } => {
                                    let result = receive_directory(&socket).map(|directory| {
                                        inspect_descriptor_children(
                                            &root, &directory, &parent, &names,
                                        )
                                    });
                                    Event::Stats(index, result)
                                }
                            },
                        ));
                        let failed = outcome.is_err();
                        if events
                            .send(outcome.unwrap_or(Event::Failed(index)))
                            .is_err()
                            || failed
                        {
                            return;
                        }
                    }
                },
            )?
        }
        .context("start scan executor")?;
        self.workers.push(Worker {
            commands: Some(commands),
            socket: Some(socket),
            thread: Some(thread),
            retained: 0,
        });
        Ok(())
    }

    fn event(&self) -> Result<Event> {
        self.events
            .as_ref()
            .unwrap()
            .recv()
            .context("scan workers stopped")
    }

    fn command(&self, index: usize, command: Command) -> Result<()> {
        self.workers[index]
            .commands
            .as_ref()
            .unwrap()
            .send(command)
            .context("scan executor stopped")
    }

    // Called only when a single directory is active. Other executors may own
    // parked iterators, but have no in-flight work and can inspect this exact
    // directory through a temporary imported descriptor.
    #[allow(clippy::too_many_arguments)]
    fn inspect(
        &mut self,
        root: &Root,
        options: &Options,
        directory: &File,
        parent: &[u8],
        names: &[PathBytes],
        requester: Option<usize>,
    ) -> Result<Inspected> {
        if names.len() < DESCRIPTOR_STAT_PAR_MIN {
            return Ok(inspect_descriptor_children(root, directory, parent, names));
        }
        let wanted = names
            .len()
            .div_ceil(DESCRIPTOR_STAT_PAR_MIN)
            .saturating_sub(1);
        self.grow(root, options, wanted);
        let helpers: Vec<_> = (0..self.workers.len())
            .filter(|index| Some(*index) != requester)
            .collect();
        let size = names.len().div_ceil(helpers.len() + 1);
        let mut batches = names.chunks(size);
        let own = batches.next().unwrap();
        let mut assigned = Vec::new();
        for (index, names) in helpers.into_iter().zip(batches) {
            send_directory(self.workers[index].socket.as_ref().unwrap(), directory)?;
            self.command(
                index,
                Command::Stat {
                    parent: parent.to_vec(),
                    names: names.to_vec(),
                },
            )?;
            assigned.push(index);
        }
        let mut result = inspect_descriptor_children(root, directory, parent, own);
        let mut replies: Vec<Option<Result<Inspected>>> =
            (0..assigned.len()).map(|_| None).collect();
        for _ in &assigned {
            match self.event()? {
                Event::Stats(index, entries) => {
                    let position = assigned
                        .iter()
                        .position(|worker| *worker == index)
                        .context("unexpected stat executor")?;
                    anyhow::ensure!(replies[position].is_none(), "duplicate stat reply");
                    // Drain every assigned reply before returning a helper's
                    // error, so the next dispatch cannot consume stale results.
                    replies[position] = Some(entries);
                }
                Event::Failed(index) => anyhow::bail!("scan executor {index} panicked"),
                _ => anyhow::bail!("unexpected scan event during stat dispatch"),
            }
        }
        for entries in replies {
            result.extend(entries.unwrap()?);
        }
        Ok(result)
    }
}

fn produce(
    root: &Root,
    options: Options,
    mut pending: Vec<UnopenedDirectory>,
    output: &SyncSender<ScanChunk>,
) -> Result<()> {
    let scan = options.scan(root);
    let mut pool = Pool::default();
    let mut local = Vec::new();
    let mut chunk = Vec::with_capacity(FIRST_BATCH);
    let mut entries_sent = 1;
    let mut entries_in_chunk = 0;
    loop {
        let retained = local.len()
            + pool
                .workers
                .iter()
                .map(|worker| worker.retained)
                .sum::<usize>();
        let ready = pending.len() + retained;
        if ready == 0 {
            break;
        }
        pool.grow(root, &options, ready.saturating_sub(1));
        let own = next_job(&mut pending, local.len());
        let mut assigned = Vec::new();
        for (index, worker) in pool.workers.iter().enumerate() {
            if let Some(job) = next_job(&mut pending, worker.retained) {
                assigned.push((index, job));
            }
        }
        let count = assigned.len() + usize::from(own.is_some());
        let resumed = assigned
            .iter()
            .filter(|(_, job)| matches!(job, Job::Continue))
            .count()
            + usize::from(matches!(own, Some(Job::Continue)));
        let available = DESCRIPTOR_DIRECTORY_FDS.saturating_sub(retained - resumed + count);
        let mut results: Vec<Option<StepResult>> = (0..count).map(|_| None).collect();
        let indexes: Vec<_> = assigned.iter().map(|(index, _)| *index).collect();
        for (position, (index, job)) in assigned.into_iter().enumerate() {
            pool.command(
                index,
                Command::Step {
                    job,
                    retain: available / count + usize::from(position < available % count),
                    parallel_stats: count == 1,
                },
            )?;
        }
        if let Some(job) = own {
            let position = indexes.len();
            results[position] = Some(step(
                &scan,
                &mut local,
                job,
                available / count + usize::from(position < available % count),
                &mut |root, directory, parent, names| {
                    if count == 1 {
                        pool.inspect(root, &options, directory, parent, names, None)
                    } else {
                        Ok(inspect_descriptor_children(root, directory, parent, names))
                    }
                },
            ));
        }
        let mut outstanding = indexes.len();
        while outstanding != 0 {
            match pool.event()? {
                Event::Done(index, step) => {
                    let position = indexes
                        .iter()
                        .position(|worker| *worker == index)
                        .context("unexpected directory executor")?;
                    anyhow::ensure!(results[position].is_none(), "duplicate directory result");
                    pool.workers[index].retained = step.retained;
                    results[position] = Some(step);
                    outstanding -= 1;
                }
                Event::Inspect(index, parent, names, reply) => {
                    anyhow::ensure!(
                        count == 1 && indexes == [index],
                        "stat help requires one active directory"
                    );
                    let directory =
                        receive_directory(pool.workers[index].socket.as_ref().unwrap())?;
                    let result =
                        pool.inspect(root, &options, &directory, &parent, &names, Some(index));
                    let _ = reply.send(result);
                }
                Event::Failed(index) => anyhow::bail!("scan executor {index} panicked"),
                Event::Stats(..) => {
                    anyhow::bail!("unexpected stat result during directory dispatch")
                }
            }
        }
        let mut children = Vec::new();
        // Publish every parent event before making its unopened children ready.
        // No worker is in flight while the consumer applies backpressure.
        for step in results.into_iter().flatten() {
            children.extend(step.unopened);
            for event in step.events {
                entries_in_chunk += usize::from(matches!(event, ScanEvent::Entry(_)));
                chunk.push(event);
                if chunk.len() >= FIRST_BATCH
                    && !send_scan_chunk(
                        output,
                        &mut chunk,
                        &mut entries_sent,
                        &mut entries_in_chunk,
                    )
                {
                    return Ok(());
                }
            }
        }
        children.reverse();
        pending.extend(children);
    }
    let _ = send_scan_chunk(output, &mut chunk, &mut entries_sent, &mut entries_in_chunk);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options() -> Options {
        Options {
            scan_root: Vec::new(),
            hold_destination_for_test: false,
            ignore: None,
            report_ignored: false,
        }
    }

    #[test]
    fn small_stat_batch_stays_inline_and_wide_batch_uses_the_held_directory() {
        let temporary = crate::test_support::tempdir().unwrap();
        let selected = temporary.path().join("selected");
        fs::create_dir(&selected).unwrap();
        let names: Vec<_> = (0..96)
            .map(|index| format!("f{index:03}").into_bytes())
            .collect();
        for name in &names {
            fs::write(
                selected.join(std::ffi::OsStr::from_bytes(name)),
                b"original",
            )
            .unwrap();
        }
        let root = Root::from_directory(File::open(temporary.path()).unwrap()).unwrap();
        let held = File::open(&selected).unwrap();
        fs::rename(&selected, temporary.path().join("moved")).unwrap();
        fs::create_dir(&selected).unwrap();
        for name in &names {
            fs::write(
                selected.join(std::ffi::OsStr::from_bytes(name)),
                b"replacement bytes",
            )
            .unwrap();
        }
        let mut pool = Pool::default();
        let small = pool
            .inspect(&root, &options(), &held, b"selected", &names[..4], None)
            .unwrap();
        assert_eq!(small.len(), 4);
        assert!(pool.workers.is_empty());
        let wide = pool
            .inspect(&root, &options(), &held, b"selected", &names, None)
            .unwrap();
        assert_eq!(wide.len(), names.len());
        for (index, (relative, result)) in wide.into_iter().enumerate() {
            assert_eq!(relative, join(b"selected", &names[index]));
            assert_eq!(result.unwrap().0.size, 8);
        }
    }

    #[test]
    fn stat_error_drains_other_helpers_before_next_inspection() {
        let temporary = crate::test_support::tempdir().unwrap();
        let names: Vec<_> = (0..96)
            .map(|index| format!("f{index:03}").into_bytes())
            .collect();
        for name in &names {
            fs::write(
                temporary.path().join(std::ffi::OsStr::from_bytes(name)),
                b"file",
            )
            .unwrap();
        }
        let root = Arc::new(Root::from_directory(File::open(temporary.path()).unwrap()).unwrap());
        let held = File::open(temporary.path()).unwrap();
        let mut pool = Pool::default();
        pool.cannot_grow = true;
        let (sent, received) = mpsc::channel();
        let mut signal = Some(sent);
        let mut wait = Some(received);
        for index in 0..2 {
            let root = root.clone();
            let (commands, incoming) = mpsc::sync_channel(1);
            let (sender, receiver) = UnixStream::pair().unwrap();
            let events = pool.output.clone();
            let mut signal = if index == 0 { signal.take() } else { None };
            let mut wait = if index == 1 { wait.take() } else { None };
            // Scripted helpers inject one handoff error before the other
            // helper replies, then serve the next inspection normally.
            let thread = std::thread::spawn(move || {
                while let Ok(Command::Stat { parent, names }) = incoming.recv() {
                    let directory = receive_directory(&receiver).unwrap();
                    if let Some(signal) = signal.take() {
                        events
                            .send(Event::Stats(
                                index,
                                Err(anyhow::anyhow!("injected stat handoff error")),
                            ))
                            .unwrap();
                        signal.send(()).unwrap();
                    } else {
                        if let Some(wait) = wait.take() {
                            wait.recv().unwrap();
                        }
                        let entries =
                            inspect_descriptor_children(&root, &directory, &parent, &names);
                        if events.send(Event::Stats(index, Ok(entries))).is_err() {
                            return;
                        }
                    }
                }
            });
            pool.workers.push(Worker {
                commands: Some(commands),
                socket: Some(sender),
                thread: Some(thread),
                retained: 0,
            });
        }
        let error = match pool.inspect(&root, &options(), &held, b"failed", &names, None) {
            Err(error) => error,
            Ok(_) => panic!("injected failure was not reported"),
        };
        assert!(error.to_string().contains("injected stat handoff error"));
        let next = pool
            .inspect(&root, &options(), &held, b"next", &names, None)
            .unwrap();
        assert_eq!(next.len(), names.len());
        for (index, (path, entry)) in next.into_iter().enumerate() {
            assert_eq!(
                path,
                join(b"next", &names[index]),
                "stale reply crossed the inspection boundary"
            );
            assert_eq!(entry.unwrap().0.size, 4);
        }
        assert!(matches!(
            pool.events.as_ref().unwrap().try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
    }

    #[test]
    fn worker_keeps_its_iterator_while_idle_helpers_inspect_its_exact_directory() {
        let temporary = crate::test_support::tempdir().unwrap();
        for index in 0..(FIRST_BATCH + 40) {
            fs::write(temporary.path().join(format!("f{index:04}")), b"file").unwrap();
        }
        let root = Root::from_directory(File::open(temporary.path()).unwrap()).unwrap();
        let metadata = root.metadata(&RelativePath::new(b"").unwrap()).unwrap();
        let options = options();
        let mut pool = Pool::default();
        pool.limit = 2;
        pool.grow(&root, &options, 1);
        assert_eq!(pool.workers.len(), 1);
        let mut job = Job::Open(UnopenedDirectory {
            relative: Vec::new(),
            expected: metadata,
        });
        let mut paths = Vec::new();
        let mut requests = 0;
        loop {
            pool.command(
                0,
                Command::Step {
                    job,
                    retain: 0,
                    parallel_stats: true,
                },
            )
            .unwrap();
            let result = loop {
                match pool.event().unwrap() {
                    Event::Inspect(index, parent, names, reply) => {
                        assert_eq!(index, 0);
                        requests += 1;
                        let held = receive_directory(pool.workers[index].socket.as_ref().unwrap())
                            .unwrap();
                        let result =
                            pool.inspect(&root, &options, &held, &parent, &names, Some(index));
                        reply.send(result).unwrap();
                    }
                    Event::Done(index, result) => {
                        assert_eq!(index, 0);
                        break result;
                    }
                    _ => panic!("unexpected scan response"),
                }
            };
            for event in result.events {
                match event {
                    ScanEvent::Entry(entry) => paths.push(entry.path),
                    _ => panic!("unexpected scan event"),
                }
            }
            if result.retained == 0 {
                break;
            }
            job = Job::Continue;
        }
        assert_eq!(requests, 2);
        assert_eq!(paths.len(), FIRST_BATCH + 40);
        assert!(paths.windows(2).all(|pair| pair[0] < pair[1]));
        drop(pool); // Both the iterator owner and its idle helpers must join.
    }
}

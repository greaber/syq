//! Bounded pipe adapters over the normal data transports and range frames.
use super::{
    controls::Controls,
    fd,
    session::{Entry, Session},
    Operation, Plan, GRANULE,
};
use crate::{
    cli::Args,
    conn::{self, Conn, Endpoint},
    descriptor_broker::DescriptorTicket,
    proto::{Request, Response},
    tune,
};
use anyhow::{bail, Context, Result};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{
        atomic::{AtomicBool, Ordering::Relaxed},
        Arc,
    },
    time::Instant,
};
use tokio::sync::{mpsc, Mutex, OwnedSemaphorePermit, Semaphore};

// Bound queued input and out-of-order output independently of tuning products.
// Allocation is lazy; a short stream never allocates the entire window.
struct Job {
    off: u64,
    len: usize,
    data: Vec<u8>,
    _credit: OwnedSemaphorePermit,
}
struct Prepared {
    entry: Entry,
    ticket: DescriptorTicket,
    size: Option<u64>,
    source_meta: Option<crate::proto::Meta>,
    workers: usize,
    worker_limit: usize,
}
fn prepare(
    session: Arc<Session>,
    plan: &Plan,
    controls: &Controls,
    input_meta: Option<crate::proto::Meta>,
) -> Result<Option<Prepared>> {
    let args = &session.args;
    let endpoint = &session.endpoint;
    let mut entry = session.entry()?;
    // Excluded uploads still check explicit placement conditions, but must not
    // create a container or a staged destination. Reuse the inspection path.
    let inspect_only = args.dry_run || controls.report.skipped();
    let (size, ticket, source_meta) = match conn::ok(
        session.call(Request::DescriptorCopy(Operation::Open {
            entry: entry.id,
            dry_run: inspect_only,
            only_new: args.ignore_existing,
            only_existing: args.existing,
            path: plan.location.as_ref().unwrap().path.clone(),
            write: plan.source.is_some(),
            follow: plan.follow,
            root: plan.root.clone(),
            placement: plan.placement.clone(),
            settings: controls.settings,
            metadata: controls.metadata,
            source_meta: input_meta,
        }))?,
        "open stream",
    )? {
        Response::DescriptorOpened {
            size,
            ticket,
            metadata,
        } => (size, ticket, metadata),
        Response::DescriptorInspected {
            size,
            skipped,
            metadata,
        } => {
            anyhow::ensure!(inspect_only || skipped, "stream was not opened");
            if plan.source.is_none() {
                if let Some(size) = size {
                    controls.set_size(size);
                }
                controls.metadata.source(metadata)?;
            }
            if skipped {
                controls.report.skip();
            }
            return Ok(None);
        }
        _ => bail!("unexpected stream open response"),
    };
    entry.opened();
    anyhow::ensure!(
        plan.source.is_some() || size.is_some(),
        "stream source did not report its length"
    );
    if plan.source.is_none() {
        controls.metadata.source(source_meta)?;
        if let Some(size) = size {
            controls.set_size(size);
        }
    }
    session.start_data()?;
    let start = match endpoint {
        Endpoint::Remote(spec) if spec.data_transport() != conn::DataTransport::Ssh => {
            tune::START_TCP
        }
        Endpoint::Remote(_) => tune::START_SSH,
        _ => tune::start_local(),
    };
    let worker_limit = if args.connections_default {
        // A download's complete range count is known. More workers cannot
        // take useful work, even if a slow consumer keeps the tuner running.
        let ranges = size.map_or(usize::MAX, |size| {
            usize::try_from(size.div_ceil(controls.settings.request_size as u64))
                .unwrap_or(usize::MAX)
                .max(1)
        });
        args.automatic_worker_limit().min(ranges)
    } else {
        args.connections
    };
    let workers = if args.connections_default {
        start.min(worker_limit)
    } else {
        worker_limit
    };
    if !args.connections_default {
        crate::fsops::require_source_descriptor_capacity(1, workers, 0)?;
    }
    if args.tcp_congestion.is_some() && !endpoint.is_remote() {
        bail!("--tcp-congestion applies only to copies with a remote endpoint");
    }
    if args.verbose > 0 && !args.quiet {
        crate::output::diagnostic!(
            "stream: {workers} data worker{}{}",
            if workers == 1 { "" } else { "s" },
            if args.connections_default {
                " (automatic)"
            } else {
                ""
            }
        );
    }
    Ok(Some(Prepared {
        entry,
        ticket,
        size,
        source_meta,
        workers,
        worker_limit,
    }))
}

#[derive(Clone)]
struct Workers {
    session: Arc<Session>,
    ticket: DescriptorTicket,
    args: Arc<Args>,
    controls: Arc<Controls>,
    jobs: Arc<Mutex<mpsc::Receiver<Job>>>,
    results: mpsc::Sender<Job>,
    gate: Arc<tune::Gate>,
    cancelled: Arc<AtomicBool>,
    draining: Arc<AtomicBool>,
    ready: Arc<tokio::sync::Notify>,
    upload: bool,
    runtime: tokio::runtime::Handle,
}
impl Workers {
    fn run(&self, id: usize) -> Result<()> {
        let mut worker = self.session.worker(
            self.ticket.clone(),
            self.controls.settings,
            self.args.connections_default && id < 2,
            &self.cancelled,
            &self.runtime,
        )?;
        self.gate.mark_ready(id);
        self.ready.notify_one();
        if self.args.verbose > 1 && !self.args.quiet {
            let transport = match &self.session.endpoint {
                Endpoint::Remote(spec) => format!("{:?}", spec.data_transport()),
                Endpoint::Local { .. } => "local".into(),
            };
            crate::output::diagnostic!("stream data worker {id} ready ({transport})");
        }
        let result = if self.upload {
            self.write(worker.connection(), id)
        } else {
            self.read(worker.connection(), id)
        };
        if result.is_ok() {
            worker.completed()?;
        }
        result
    }
    fn next(&self, id: usize) -> Result<Option<Job>> {
        anyhow::ensure!(!self.cancelled.load(Relaxed), "stream cancelled");
        if !self.gate.park(id, || {
            self.draining.load(Relaxed) || self.cancelled.load(Relaxed)
        }) {
            return Ok(None);
        }
        self.runtime.block_on(async {
            let mut jobs = self.jobs.lock().await;
            loop {
                anyhow::ensure!(!self.cancelled.load(Relaxed), "stream cancelled");
                tokio::select! {
                    job = jobs.recv() => return Ok(job),
                    _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {},
                }
            }
        })
    }
    fn write(&self, connection: &mut dyn Conn, id: usize) -> Result<()> {
        let streaming = self
            .args
            .tuning_options
            .unwrap_or_default()
            .pipeline_depth
            .is_none();
        if streaming {
            connection.begin_streaming_writes()?;
        }
        let mut sent = 0;
        let mut bytes = 0;
        let mut pending = 0;
        let result = (|| {
            while let Some(job) = self.next(id)? {
                self.session.pace(job.len as u64);
                if streaming {
                    connection.check_streaming_writes()?;
                }
                let hash = self.controls.settings.hash(&job.data);
                let buffer = connection.send_recycling(Request::WriteRange {
                    path: Vec::new(),
                    inplace: true,
                    copy_id: [0; 16],
                    attempt: 0,
                    off: job.off,
                    hash,
                    data: job.data.into(),
                    guard: None,
                })?;
                if let Some(buffer) = buffer {
                    self.session.recycle(buffer);
                }
                sent += 1;
                bytes += job.len as u64;
                if !streaming {
                    pending += 1;
                    if pending >= self.controls.pipeline {
                        conn::ok(connection.recv()?, "write stream range")?;
                        pending -= 1;
                    }
                }
                self.controls.add_bytes(job.len as u64);
            }
            Ok(())
        })();
        if self.args.verbose > 1 && !self.args.quiet {
            crate::output::diagnostic!("stream worker {id}: sent {bytes} bytes in {sent} requests");
        }
        if streaming {
            let fence = connection.fence_streaming_writes();
            let finish = connection.finish_streaming_writes(sent, fence);
            result.and(finish)
        } else {
            let finish = conn::drain_range_replies(connection, pending, "write stream range");
            result.and(finish)
        }
    }
    fn read(&self, connection: &mut dyn Conn, id: usize) -> Result<()> {
        let mut pending = VecDeque::new();
        let mut bytes = 0u64;
        let window = if connection.supports_request_pipelining() {
            self.controls.pipeline
        } else {
            1
        };
        let mut ended = false;
        loop {
            while !ended && pending.len() < window {
                let job = if pending.is_empty() {
                    self.next(id)?
                } else {
                    // Another idle worker may be waiting for the next job.
                    // Do not wait behind it while holding unread responses:
                    // those responses can own all available reorder credits.
                    let Ok(mut jobs) = self.jobs.try_lock() else {
                        break;
                    };
                    match jobs.try_recv() {
                        Ok(job) => Some(job),
                        Err(mpsc::error::TryRecvError::Empty) => break,
                        Err(mpsc::error::TryRecvError::Disconnected) => None,
                    }
                };
                let Some(job) = job else {
                    ended = true;
                    break;
                };
                self.session.pace(job.len as u64);
                connection.send(Request::ReadRange {
                    path: Vec::new(),
                    source: None,
                    attempt: 0,
                    off: job.off,
                    len: job.len as u32,
                })?;
                pending.push_back(job);
            }
            let Some(mut job) = pending.pop_front() else {
                break;
            };
            match conn::ok(connection.recv()?, "read stream range")? {
                Response::Block { off, hash, data }
                    if off == job.off
                        && data.len() == job.len
                        && self.controls.settings.matches(&data, hash) =>
                {
                    job.data = data
                }
                _ => bail!("invalid stream range response"),
            }
            bytes += job.len as u64;
            self.results
                .blocking_send(job)
                .map_err(|_| anyhow::anyhow!("stream output closed"))?;
        }
        if self.args.verbose > 1 && !self.args.quiet {
            crate::output::diagnostic!("stream worker {id}: read {bytes} bytes");
        }
        Ok(())
    }
}
async fn credit(
    budget: &Arc<Semaphore>,
    bytes: usize,
    cancelled: &AtomicBool,
) -> Result<OwnedSemaphorePermit> {
    let acquire = budget
        .clone()
        .acquire_many_owned(bytes.div_ceil(GRANULE) as u32);
    tokio::pin!(acquire);
    loop {
        anyhow::ensure!(!cancelled.load(Relaxed), "stream cancelled");
        tokio::select! {
            permit = &mut acquire => return Ok(permit?),
            _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {},
        }
    }
}

pub(super) async fn run(
    args: Args,
    plan: Plan,
    controls: Arc<Controls>,
    cancelled: Arc<AtomicBool>,
) -> Result<()> {
    // Duplicate inherited descriptors before launching helpers; check placement
    // before opening a named FIFO, which can wait indefinitely for its writer.
    let commit = plan
        .commit_fd
        .map(|fd| fd::Descriptor::open(fd, true, cancelled.clone()))
        .transpose()?;
    let mut input = match &plan.source {
        Some(fd::Source::Descriptor(fd)) => {
            Some(fd::Descriptor::open(*fd, true, cancelled.clone())?)
        }
        _ => None,
    };
    let output = plan
        .as_fd
        .map(|fd| fd::Descriptor::open(fd, false, cancelled.clone()))
        .transpose()?;
    let input_meta = input.as_ref().and_then(fd::Descriptor::metadata);
    if let Some(output) = &output {
        controls.metadata.output(output.metadata().is_some())?;
    }
    if plan.source.is_some() {
        controls.metadata.source(input_meta)?;
        if let Some(size) = input
            .as_ref()
            .map(fd::Descriptor::remaining_len)
            .transpose()?
            .flatten()
        {
            controls.set_size(size);
        }
    }
    if plan.location.is_none() {
        if args.ignore_existing || controls.report.skipped() {
            controls.report.skip();
            return Ok(());
        }
        if args.dry_run {
            return Ok(());
        }
        controls.report.ready();
        if input.is_none() {
            input = Some(
                plan.source
                    .context("missing stream source")?
                    .open(cancelled.clone())
                    .await?,
            );
        }
        return direct(
            input.context("missing stream input")?,
            output.context("missing stream output")?,
            commit,
            controls,
            None,
        )
        .await;
    }
    let session = if plan.location.as_ref().unwrap().host.is_none() {
        Session::connect(&args, plan.location.as_ref().unwrap())?
    } else {
        let (args, location) = (args.clone(), plan.location.clone().unwrap());
        tokio::task::spawn_blocking(move || Session::connect(&args, &location)).await??
    };
    execute(
        session, plan, controls, cancelled, input, output, commit, input_meta, None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn execute(
    session: Arc<Session>,
    plan: Plan,
    controls: Arc<Controls>,
    cancelled: Arc<AtomicBool>,
    mut input: Option<fd::Descriptor>,
    mut output: Option<fd::Descriptor>,
    mut commit: Option<fd::Descriptor>,
    input_meta: Option<crate::proto::Meta>,
    callback: Option<Arc<crate::stream_mapping::Payload>>,
) -> Result<()> {
    let _cancel = fd::CancelOnDrop(cancelled.clone());
    let args = &session.args;
    let prepared = if !session.endpoint.is_remote() {
        prepare(session.clone(), &plan, &controls, input_meta)?
    } else {
        let (s, p, c) = (session.clone(), plan.clone(), controls.clone());
        tokio::task::spawn_blocking(move || prepare(s, &p, &c, input_meta)).await??
    };
    let Some(mut prepared) = prepared else {
        return Ok(());
    };
    controls.report.ready();
    if let Some(payload) = &callback {
        let upload = plan.source.is_some();
        let (descriptor, acknowledge) = payload.open(upload, cancelled.clone())?;
        if upload {
            input = Some(descriptor);
        } else {
            output = Some(descriptor);
        }
        commit = Some(acknowledge);
    }
    if let Some(source @ fd::Source::Pipe { .. }) = plan.source.clone() {
        input = Some(source.open(cancelled.clone()).await?);
    }
    let retirements: Vec<_> = input
        .iter()
        .chain(output.iter())
        .chain(commit.iter())
        .filter_map(fd::Descriptor::retirement)
        .collect();
    let metadata_output = output
        .as_ref()
        .filter(|_| controls.metadata.preserve != 0)
        .map(fd::Descriptor::metadata_file)
        .transpose()?
        .flatten();
    let budget = session.budget.clone();
    let (jobs_tx, jobs_rx) = mpsc::channel(64);
    let (results_tx, mut results_rx) = mpsc::channel(64);
    let gate = tune::Gate::new(prepared.workers);
    let draining = Arc::new(AtomicBool::new(false));
    let ready = Arc::new(tokio::sync::Notify::new());
    let workers = Workers {
        session: session.clone(),
        ticket: prepared.ticket,
        args: Arc::new(args.clone()),
        controls: controls.clone(),
        jobs: Arc::new(Mutex::new(jobs_rx)),
        results: results_tx,
        gate: gate.clone(),
        cancelled: cancelled.clone(),
        draining: draining.clone(),
        ready: ready.clone(),
        upload: input.is_some(),
        runtime: tokio::runtime::Handle::current(),
    };
    let mut tasks = tokio::task::JoinSet::new();
    let spawn = |tasks: &mut tokio::task::JoinSet<Result<()>>, id| -> Result<()> {
        let worker = workers.clone();
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        // Workers must not exhaust Tokio's blocking pool: the pipe reader and
        // ordered writer also need that pool to make forward progress.
        let thread = std::thread::Builder::new()
            .name(format!("stream-{id}"))
            .spawn(move || {
                let result = worker.run(id);
                worker.gate.mark_absent(id);
                let _ = result_tx.send(result);
            })
            .context("start stream data worker")?;
        tasks.spawn(async move {
            let result = result_rx.await;
            thread
                .join()
                .map_err(|_| anyhow::anyhow!("stream worker panicked"))?;
            result.context("stream worker stopped")?
        });
        Ok(())
    };
    for id in gate.begin_warming(prepared.workers) {
        spawn(&mut tasks, id)?;
    }
    let mut policy = tune::Policy::new(prepared.workers, 1, prepared.worker_limit);
    let mut sampler = tune::Sampler::default();
    let mut interval = tokio::time::interval(tune::SAMPLE);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last = (Instant::now(), controls.progress.bytes_done.load(Relaxed));
    let transfer = async {
        // An entry must have a worker before reserving shared payload memory:
        // queued entries must not starve the entries holding the connections.
        ready.notified().await;
        let size = if let Some(mut input) = input {
            let (controls, budget, session, cancelled) = (
                controls.clone(),
                budget.clone(),
                session.clone(),
                cancelled.clone(),
            );
            let runtime = tokio::runtime::Handle::current();
            tokio::task::spawn_blocking(move || -> Result<u64> {
                let mut off = 0u64;
                let mut check = controls.expected.start();
                loop {
                    // Reserve one request, not request-size times depth. Only
                    // bytes actually read become initialized buffer contents.
                    let permit = runtime.block_on(credit(
                        &budget,
                        controls.settings.request_size,
                        &cancelled,
                    ))?;
                    let data = input.read_reusing(
                        controls.settings.request_size,
                        false,
                        session.buffer(),
                    )?;
                    if data.is_empty() {
                        break;
                    }
                    let len = data.len();
                    check.add(&data)?;
                    jobs_tx
                        .blocking_send(Job {
                            off,
                            len,
                            data,
                            _credit: permit,
                        })
                        .map_err(|_| anyhow::anyhow!("stream workers stopped"))?;
                    off = off
                        .checked_add(len as u64)
                        .context("stream length overflow")?;
                }
                check.finish()
            })
            .await??
        } else {
            let size = prepared
                .size
                .context("stream source did not report its length")?;
            let feeder = async {
                let mut off = 0;
                while off < size {
                    let len = (size - off).min(controls.settings.request_size as u64) as usize;
                    let permit = credit(&budget, len, &cancelled).await?;
                    jobs_tx
                        .send(Job {
                            off,
                            len,
                            data: Vec::new(),
                            _credit: permit,
                        })
                        .await
                        .map_err(|_| anyhow::anyhow!("stream workers stopped"))?;
                    off += len as u64;
                }
                drop(jobs_tx);
                Ok::<_, anyhow::Error>(())
            };
            let writer = async {
                let mut output = output.context("missing stream output")?;
                let mut next = 0u64;
                let mut check = controls.expected.start();
                let mut ready = BTreeMap::new();
                while next < size {
                    let job = results_rx
                        .recv()
                        .await
                        .context("stream workers stopped before EOF")?;
                    anyhow::ensure!(
                        job.off >= next && !ready.contains_key(&job.off),
                        "duplicate stream range"
                    );
                    ready.insert(job.off, job);
                    while let Some(job) = ready.remove(&next) {
                        check.add(&job.data)?;
                        output = output.write_chunk(job.data.into()).await?;
                        controls.add_bytes(job.len as u64);
                        next += job.len as u64;
                    }
                }
                check.finish()?;
                Ok::<_, anyhow::Error>(())
            };
            tokio::try_join!(feeder, writer)?;
            size
        };
        Ok::<_, anyhow::Error>(size)
    };
    let mut transfer = Box::pin(transfer);
    let result = async {
        let size = loop {
            tokio::select! {
                value = &mut transfer => break value?,
                value = tasks.join_next(), if !tasks.is_empty() => { value.unwrap()??; }
                _ = interval.tick(), if args.connections_default => {
                    if !gate.ready_through(policy.n) { continue; }
                    if gate.active() != policy.n { gate.set_active(policy.n); policy.activated(); sampler.reset(); last = (Instant::now(), controls.progress.bytes_done.load(Relaxed)); continue; }
                    let now = (Instant::now(), controls.progress.bytes_done.load(Relaxed));
                    let elapsed = now.0.duration_since(last.0).as_secs_f64();
                    if elapsed < tune::SAMPLE.as_secs_f64() / 2.0 { continue; }
                    let rate = (now.1.saturating_sub(last.1)) as f64 / elapsed;
                    last = now;
                    if let Some(score) = sampler.push(rate) {
                        let target = policy.observe(score);
                        if target != gate.active() {
                            if target < gate.active() { gate.set_active(target); gate.set_retain(target.max(2)); policy.activated(); }
                            for id in gate.begin_warming(target) { spawn(&mut tasks, id)?; }
                            sampler.reset();
                        }
                    }
                }
            }
        };
        draining.store(true, Relaxed);
        while let Some(result) = tasks.join_next().await { result??; }
        let mut commit = commit;
        if workers.upload {
            fd::await_commit(commit.take()).await?;
        }
        let mut finish = move || prepared.entry.finish(size);
        if session.endpoint.is_remote() {
            tokio::task::spawn_blocking(finish).await??;
        } else {
            finish()?;
        }
        if !workers.upload {
            if let Some(payload) = &callback { payload.transferred(None)?; }
            fd::await_commit(commit).await?;
        }
        if let Some(output) = metadata_output {
            controls.metadata.apply(&output, prepared.source_meta)?;
        }
        Ok(())
    }.await;
    draining.store(true, Relaxed);
    if result.is_err() {
        cancelled.store(true, Relaxed);
        // The shared session budget remains available to other entries.
    }
    drop(transfer);
    while let Some(joined) = tasks.join_next().await {
        // Preserve the first copy error; these joins only retire its workers.
        let _ = joined;
    }
    // No worker can consume queued jobs now. Release the remaining receiver
    // so a producer blocked in blocking_send wakes and drops its descriptor.
    drop(workers);
    for retired in retirements {
        retired.wait().await;
    }
    if let Some(payload) = callback {
        payload.transferred(result.as_ref().err())?;
    }
    result
}
pub(crate) async fn direct(
    mut input: fd::Descriptor,
    mut output: fd::Descriptor,
    commit: Option<fd::Descriptor>,
    controls: Arc<Controls>,
    budget: Option<Arc<Semaphore>>,
) -> Result<()> {
    let source_meta = input.metadata();
    let mut check = controls.expected.start();
    loop {
        let _credit = if let Some(budget) = &budget {
            Some(
                budget
                    .clone()
                    .acquire_many_owned(controls.settings.request_size.div_ceil(GRANULE) as u32)
                    .await?,
            )
        } else {
            None
        };
        let (next, data) = input.read_available(controls.settings.request_size).await?;
        input = next;
        if data.is_empty() {
            break;
        }
        controls.pace(data.len() as u64).await;
        let len = data.len();
        check.add(&data)?;
        output = output.write_chunk(data).await?;
        controls.add_bytes(len as u64);
    }
    check.finish()?;
    fd::await_commit(commit).await?;
    output.apply_metadata(controls.metadata, source_meta)
}

#[cfg(test)]
mod tests;

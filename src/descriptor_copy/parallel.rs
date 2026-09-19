//! Bounded pipe adapters over the normal data transports and range frames.
use super::{controls::Controls, fd, Operation, Plan};
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
        Arc, Mutex,
    },
    time::Instant,
};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};

// Bound queued input and out-of-order output independently of tuning products.
// Allocation is lazy; a short stream never allocates the entire window.
const BUFFER_BYTES: usize = 128 << 20;
const GRANULE: usize = 1024;
struct Job {
    off: u64,
    len: usize,
    data: Vec<u8>,
    _credit: OwnedSemaphorePermit,
}
struct Prepared {
    endpoint: Endpoint,
    control: Box<dyn Conn>,
    ticket: DescriptorTicket,
    size: Option<u64>,
    workers: usize,
    worker_limit: usize,
    _local_session: Option<LocalSession>,
}
struct LocalSession(crate::descriptor_broker::DescriptorSessionSlot);
impl Drop for LocalSession {
    fn drop(&mut self) {
        self.0.close();
    }
}
fn prepare(args: &Args, plan: &Plan, controls: &Controls) -> Result<Option<Prepared>> {
    let location = plan.location.as_ref().unwrap();
    let local_session = location
        .host
        .is_none()
        .then(crate::descriptor_broker::DescriptorSessionSlot::managed)
        .transpose()?
        .map(LocalSession);
    let endpoint = if let Some(session) = &local_session {
        Endpoint::Local {
            descriptor_session: session.0.clone(),
        }
    } else {
        crate::transfer::endpoint(location, args)?
    };
    let mut control = endpoint.connect_control(args.compress)?;
    if args.dry_run || args.ignore_existing || args.existing {
        let response = conn::ok(
            control.call(Request::DescriptorCopy(Operation::Inspect {
                only_new: args.ignore_existing,
                only_existing: args.existing,
                path: location.path.clone(),
                write: plan.source.is_some(),
                follow: plan.follow,
                root: plan.root.clone(),
                placement: plan.placement.clone(),
            }))?,
            "inspect stream",
        )?;
        let Response::DescriptorInspected { size, skipped } = response else {
            bail!("unexpected stream inspection response");
        };
        if let Some(size) = size {
            controls.set_size(size);
        }
        if skipped || (plan.as_fd.is_some() && args.ignore_existing) {
            controls.report.skip();
            return Ok(None);
        }
        if args.dry_run {
            return Ok(None);
        }
    }
    let (size, ticket) = match conn::ok(
        control.call(Request::DescriptorCopy(Operation::Open {
            path: plan.location.as_ref().unwrap().path.clone(),
            write: plan.source.is_some(),
            follow: plan.follow,
            root: plan.root.clone(),
            placement: plan.placement.clone(),
            settings: controls.settings,
        }))?,
        "open stream",
    )? {
        Response::DescriptorOpened { size, ticket } => (size, ticket),
        _ => bail!("unexpected stream open response"),
    };
    anyhow::ensure!(
        plan.source.is_some() || size.is_some(),
        "stream source did not report its length"
    );
    if let Some(size) = size {
        controls.set_size(size);
    }
    if let Endpoint::Remote(spec) = &endpoint {
        if !args.no_tcp {
            let result = spec
                .begin_tcp_setup(
                    &mut *control,
                    args.tcp_plain,
                    conn::parse_ports(&args.tcp_ports)?,
                    args.tcp_congestion.as_deref(),
                )
                .and_then(|pending| spec.finish_tcp_setup(pending));
            if let Err(error) = result {
                if conn::is_tcp_congestion_error(&error) {
                    return Err(error);
                }
                if !args.quiet {
                    crate::output::diagnostic!(
                        "syq: stream data over SSH (TCP setup failed: {error:#})"
                    );
                }
            }
        }
    }
    let start = match &endpoint {
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
        endpoint,
        control,
        ticket,
        size,
        workers,
        worker_limit,
        _local_session: local_session,
    }))
}

#[derive(Clone)]
struct Workers {
    endpoint: Endpoint,
    ticket: DescriptorTicket,
    args: Arc<Args>,
    controls: Arc<Controls>,
    jobs: Arc<Mutex<mpsc::Receiver<Job>>>,
    results: mpsc::Sender<Job>,
    buffers: std::sync::mpsc::SyncSender<Vec<u8>>,
    gate: Arc<tune::Gate>,
    cancelled: Arc<AtomicBool>,
    draining: Arc<AtomicBool>,
    upload: bool,
}
impl Workers {
    fn run(&self, id: usize) -> Result<()> {
        let mut connection = self.endpoint.connect_stream(
            self.args.compress,
            self.ticket.clone(),
            self.controls.settings,
            self.args.connections_default && id < 2,
        )?;
        self.gate.mark_ready(id);
        if self.args.verbose > 1 && !self.args.quiet {
            let transport = match &self.endpoint {
                Endpoint::Remote(spec) => format!("{:?}", spec.data_transport()),
                Endpoint::Local { .. } => "local".into(),
            };
            crate::output::diagnostic!("stream data worker {id} ready ({transport})");
        }
        if self.upload {
            self.write(&mut *connection, id)
        } else {
            self.read(&mut *connection, id)
        }
    }
    fn next(&self, id: usize) -> Result<Option<Job>> {
        anyhow::ensure!(!self.cancelled.load(Relaxed), "stream cancelled");
        if !self.gate.park(id, || {
            self.draining.load(Relaxed) || self.cancelled.load(Relaxed)
        }) {
            return Ok(None);
        }
        Ok(self.jobs.lock().unwrap().blocking_recv())
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
                self.controls.pace_blocking(job.len as u64);
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
                    data: job.data,
                    guard: None,
                })?;
                if let Some(buffer) = buffer {
                    let _ = self.buffers.try_send(buffer);
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
                self.controls.progress.add_bytes(job.len as u64);
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
                self.controls.pace_blocking(job.len as u64);
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
async fn credit(budget: &Arc<Semaphore>, bytes: usize) -> Result<OwnedSemaphorePermit> {
    Ok(budget
        .clone()
        .acquire_many_owned(bytes.div_ceil(GRANULE) as u32)
        .await?)
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
    if let Some(input) = &input {
        if let Some(size) = input.remaining_len()? {
            controls.set_size(size);
        }
    }
    if plan.location.is_none() {
        if args.ignore_existing {
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
        )
        .await;
    }
    let prepared = if plan.location.as_ref().unwrap().host.is_none() {
        // Keep local staging owned by this future from the instant it exists.
        // A detached blocking task could create it just as cancellation drops
        // the receiver, then lose its cleanup when the CLI exits.
        prepare(&args, &plan, &controls)?
    } else {
        let (a, p, c) = (args.clone(), plan.clone(), controls.clone());
        tokio::task::spawn_blocking(move || prepare(&a, &p, &c)).await??
    };
    let Some(prepared) = prepared else {
        return Ok(());
    };
    controls.report.ready();
    if let Some(source @ fd::Source::Pipe { .. }) = plan.source.clone() {
        input = Some(source.open(cancelled.clone()).await?);
    }
    let budget = Arc::new(Semaphore::new(BUFFER_BYTES / GRANULE));
    let (jobs_tx, jobs_rx) = mpsc::channel(64);
    let (results_tx, mut results_rx) = mpsc::channel(64);
    // Return buffers before releasing their memory credits. The reader can
    // reuse them without another allocation or zeroing newly mapped pages.
    let (buffers_tx, buffers_rx) =
        std::sync::mpsc::sync_channel(BUFFER_BYTES / controls.settings.request_size);
    let gate = tune::Gate::new(prepared.workers);
    let draining = Arc::new(AtomicBool::new(false));
    let workers = Workers {
        endpoint: prepared.endpoint.clone(),
        ticket: prepared.ticket,
        args: Arc::new(args.clone()),
        controls: controls.clone(),
        jobs: Arc::new(Mutex::new(jobs_rx)),
        results: results_tx,
        buffers: buffers_tx,
        gate: gate.clone(),
        cancelled: cancelled.clone(),
        draining: draining.clone(),
        upload: input.is_some(),
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
        let size = if let Some(mut input) = input {
            let (controls, budget) = (controls.clone(), budget.clone());
            let runtime = tokio::runtime::Handle::current();
            tokio::task::spawn_blocking(move || -> Result<u64> {
                let mut off = 0u64;
                let mut expected = controls.expected_hasher();
                loop {
                    // Reserve one request, not request-size times depth. Only
                    // bytes actually read become initialized buffer contents.
                    let permit =
                        runtime.block_on(credit(&budget, controls.settings.request_size))?;
                    let data = input.read_reusing(
                        controls.settings.request_size,
                        false,
                        buffers_rx.try_recv().unwrap_or_default(),
                    )?;
                    if data.is_empty() {
                        break;
                    }
                    if let Some(hash) = &mut expected {
                        hash.update(&data);
                    }
                    let len = data.len();
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
                controls.verify(expected)?;
                Ok(off)
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
                    let permit = credit(&budget, len).await?;
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
                let mut ready = BTreeMap::new();
                let mut expected = controls.expected_hasher();
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
                        if let Some(hash) = &mut expected {
                            hash.update(&job.data);
                        }
                        output = output.write_chunk(job.data.into()).await?;
                        controls.progress.add_bytes(job.len as u64);
                        next += job.len as u64;
                    }
                }
                controls.verify(expected)?;
                Ok::<_, anyhow::Error>(())
            };
            tokio::try_join!(feeder, writer)?;
            size
        };
        Ok::<_, anyhow::Error>(size)
    };
    tokio::pin!(transfer);
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
        fd::await_commit(commit).await?;
        let mut control = prepared.control;
        let mut finish = move || {
            conn::ok(control.call(Request::DescriptorCopy(Operation::Finish { size }))?, "finish stream")?;
            Ok::<_, anyhow::Error>(())
        };
        if prepared.endpoint.is_remote() {
            tokio::task::spawn_blocking(finish).await??;
        } else {
            // As with opening, local publication and cleanup stay owned here.
            finish()?;
        }
        Ok(())
    }.await;
    draining.store(true, Relaxed);
    if result.is_err() {
        cancelled.store(true, Relaxed);
        budget.close();
    }
    result
}
async fn direct(
    mut input: fd::Descriptor,
    mut output: fd::Descriptor,
    commit: Option<fd::Descriptor>,
    controls: Arc<Controls>,
) -> Result<()> {
    let mut hash = controls.expected_hasher();
    loop {
        let (next, data) = input.read_available(controls.settings.request_size).await?;
        input = next;
        if data.is_empty() {
            break;
        }
        if let Some(hash) = &mut hash {
            hash.update(&data);
        }
        controls.pace(data.len() as u64).await;
        let len = data.len();
        output = output.write_chunk(data).await?;
        controls.progress.add_bytes(len as u64);
    }
    controls.verify(hash)?;
    fd::await_commit(commit).await
}

//! Endpoint lifetime and transport resources shared by stream entries.
use super::{Settings, BUFFER_BYTES, GRANULE};
use crate::{
    cli::{Args, Location},
    conn::{self, Conn, Endpoint},
    descriptor_broker::{DescriptorSessionSlot, DescriptorTicket},
    proto::{Request, Response},
};
use anyhow::Result;
use std::collections::VecDeque;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering::Relaxed},
    Arc, Condvar, Mutex,
};
use std::time::Duration;
use tokio::sync::Semaphore;

struct Control {
    connection: Box<dyn Conn>,
    pending_aborts: usize,
}
impl Control {
    fn send_aborts(&mut self, entries: Vec<u64>) -> Result<()> {
        for entry in entries {
            self.connection
                .send(Request::DescriptorCopy(super::Operation::Abort { entry }))?;
            self.pending_aborts += 1;
        }
        Ok(())
    }
    fn drain(&mut self) -> Result<()> {
        while self.pending_aborts != 0 {
            let reply = self.connection.recv()?;
            self.pending_aborts -= 1;
            conn::ok(reply, "abort stream entry")?;
        }
        Ok(())
    }
}

struct Connections {
    idle: Vec<Box<dyn Conn>>,
    leased: usize,
}
struct LocalSession(DescriptorSessionSlot);
impl Drop for LocalSession {
    fn drop(&mut self) {
        self.0.close();
    }
}
pub(crate) struct Resources {
    workers: Arc<Semaphore>,
    pub budget: Arc<Semaphore>,
    buffers: Mutex<VecDeque<Vec<u8>>>,
    bandwidth: Option<Arc<crate::bwlimit::BandwidthLimit>>,
}
impl Resources {
    pub fn new(args: &Args) -> Arc<Self> {
        Arc::new(Self {
            workers: Arc::new(Semaphore::new(
                (if args.connections_default {
                    args.automatic_worker_limit()
                } else {
                    args.connections
                })
                .min(Semaphore::MAX_PERMITS),
            )),
            budget: Arc::new(Semaphore::new(BUFFER_BYTES / GRANULE)),
            buffers: Mutex::new(VecDeque::new()),
            bandwidth: (args.bwlimit_bytes != 0)
                .then(|| Arc::new(crate::bwlimit::BandwidthLimit::new(args.bwlimit_bytes))),
        })
    }
    pub fn bandwidth(&self) -> Option<Arc<crate::bwlimit::BandwidthLimit>> {
        self.bandwidth.clone()
    }
}
pub(crate) struct Session {
    pub endpoint: Endpoint,
    pub args: Args,
    control: Mutex<Control>,
    abandoned: Mutex<Vec<u64>>,
    next_entry: AtomicU64,
    connections: Mutex<Connections>,
    available: Condvar,
    data_started: Mutex<bool>,
    limit: usize,
    pub budget: Arc<Semaphore>,
    // Keep the previous FIFO reuse order as entries share the buffer cache.
    resources: Arc<Resources>,
    // Drop connections before closing the broker.
    _local: Option<LocalSession>,
    #[cfg(test)]
    pub connections_created: AtomicU64,
}
impl Session {
    pub fn connect(args: &Args, location: &Location) -> Result<Arc<Self>> {
        Self::connect_shared(args, location, Resources::new(args))
    }
    pub fn connect_shared(
        args: &Args,
        location: &Location,
        resources: Arc<Resources>,
    ) -> Result<Arc<Self>> {
        let local = location
            .host
            .is_none()
            .then(DescriptorSessionSlot::managed)
            .transpose()?
            .map(LocalSession);
        let endpoint = match &local {
            Some(local) => Endpoint::Local {
                descriptor_session: local.0.clone(),
            },
            None => crate::transfer::endpoint(location, args)?,
        };
        anyhow::ensure!(
            args.tcp_congestion.is_none() || endpoint.is_remote(),
            "--tcp-congestion applies only to copies with a remote endpoint"
        );
        let control = endpoint.connect_control(args.compress)?;
        Ok(Arc::new(Self {
            endpoint,
            args: args.clone(),
            control: Mutex::new(Control {
                connection: control,
                pending_aborts: 0,
            }),
            abandoned: Mutex::new(Vec::new()),
            next_entry: AtomicU64::new(1),
            connections: Mutex::new(Connections {
                idle: Vec::new(),
                leased: 0,
            }),
            available: Condvar::new(),
            data_started: Mutex::new(false),
            limit: if args.connections_default {
                args.automatic_worker_limit()
            } else {
                args.connections
            },
            budget: resources.budget.clone(),
            resources,
            _local: local,
            #[cfg(test)]
            connections_created: AtomicU64::new(0),
        }))
    }
    pub(super) fn entry(self: &Arc<Self>) -> Result<Entry> {
        let id = self
            .next_entry
            .fetch_update(Relaxed, Relaxed, |id| id.checked_add(1))
            .map_err(|_| anyhow::anyhow!("stream entry identifiers exhausted"))?;
        Ok(Entry {
            session: self.clone(),
            id,
            complete: true,
        })
    }
    fn abandoned(&self) -> Vec<u64> {
        std::mem::take(&mut *self.abandoned.lock().unwrap())
    }
    pub fn call(&self, request: Request) -> Result<Response> {
        let mut control = self.control.lock().unwrap();
        control.send_aborts(self.abandoned())?;
        control.drain()?;
        control.connection.call(request)
    }
    fn abandon(&self, entry: u64) {
        self.abandoned.lock().unwrap().push(entry);
        // Dropping an entry must not wait behind another entry's control call,
        // or wait for an abort reply from an unresponsive helper. Flush now if
        // idle; otherwise the next control call flushes and checks the replies.
        // Closing the session itself also discards all unpublished entries.
        if let Ok(mut control) = self.control.try_lock() {
            let _ = control.send_aborts(self.abandoned());
        }
    }
    pub fn start_data(&self) -> Result<()> {
        let mut started = self.data_started.lock().unwrap();
        if *started {
            return Ok(());
        }
        if let Endpoint::Remote(spec) = &self.endpoint {
            if !self.args.no_tcp && spec.tcp.lock().unwrap().is_none() {
                let mut control = self.control.lock().unwrap();
                control.send_aborts(self.abandoned())?;
                control.drain()?;
                // Serialize both the check and listener setup across entry opens.
                if spec.tcp.lock().unwrap().is_some() {
                    return Ok(());
                }
                let result = spec
                    .begin_tcp_setup(
                        &mut *control.connection,
                        self.args.tcp_plain,
                        conn::parse_ports(&self.args.tcp_ports)?,
                        self.args.tcp_congestion.as_deref(),
                    )
                    .and_then(|pending| spec.finish_tcp_setup(pending));
                if let Err(error) = result {
                    if conn::is_tcp_congestion_error(&error) {
                        return Err(error);
                    }
                    if !self.args.quiet {
                        crate::output::diagnostic!(
                            "syq: stream data over SSH (TCP setup failed: {error:#})"
                        );
                    }
                }
            }
        }
        *started = true;
        Ok(())
    }
    pub(super) async fn worker_permit(
        &self,
        cancelled: &AtomicBool,
        draining: &AtomicBool,
    ) -> Result<Option<tokio::sync::OwnedSemaphorePermit>> {
        // Queue once, before creating an OS thread. Entries waiting for shared
        // capacity must neither consume threads nor jump ahead of one another.
        let acquire = self.resources.workers.clone().acquire_owned();
        tokio::pin!(acquire);
        loop {
            anyhow::ensure!(!cancelled.load(Relaxed), "stream cancelled");
            if draining.load(Relaxed) {
                return Ok(None);
            }
            tokio::select! {
                permit = &mut acquire => {
                    let permit = permit?;
                    anyhow::ensure!(!cancelled.load(Relaxed), "stream cancelled");
                    return Ok((!draining.load(Relaxed)).then_some(permit));
                },
                _ = tokio::time::sleep(Duration::from_millis(100)) => {},
            }
        }
    }
    pub(super) fn worker(
        self: &Arc<Self>,
        ticket: DescriptorTicket,
        settings: Settings,
        first: bool,
        cancelled: &AtomicBool,
        permit: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<Worker> {
        let mut connections = self.connections.lock().unwrap();
        while connections.leased >= self.limit {
            anyhow::ensure!(!cancelled.load(Relaxed), "stream cancelled");
            connections = self
                .available
                .wait_timeout(connections, Duration::from_millis(100))
                .unwrap()
                .0;
        }
        anyhow::ensure!(!cancelled.load(Relaxed), "stream cancelled");
        connections.leased += 1;
        let cached = connections.idle.pop();
        drop(connections);
        let mut worker = Worker {
            session: self.clone(),
            connection: None,
            reusable: false,
            _permit: permit,
        };
        worker.connection = Some(if let Some(mut connection) = cached {
            // Release was sent after the previous entry's checked fence. Send
            // the new bind before draining both replies, costing just one RTT.
            connection.send(Request::BindStream(Some((ticket, settings))))?;
            conn::ok(connection.recv()?, "release stream entry")?;
            conn::ok(connection.recv()?, "bind stream entry")?;
            connection
        } else {
            let connection =
                self.endpoint
                    .connect_stream(self.args.compress, ticket, settings, first)?;
            #[cfg(test)]
            self.connections_created.fetch_add(1, Relaxed);
            connection
        });
        Ok(worker)
    }
    pub fn buffer(&self) -> Vec<u8> {
        self.resources
            .buffers
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_default()
    }
    pub fn recycle(&self, mut buffer: Vec<u8>) {
        let mut buffers = self.resources.buffers.lock().unwrap();
        let held = buffers.iter().map(Vec::capacity).sum::<usize>();
        if held.saturating_add(buffer.capacity()) <= BUFFER_BYTES {
            buffer.clear();
            buffers.push_back(buffer);
        }
    }
    pub fn pace(&self, bytes: u64) {
        if let Some(limit) = &self.resources.bandwidth {
            limit.wait_prepaid(bytes);
        }
    }
}

pub(super) struct Entry {
    pub session: Arc<Session>,
    pub id: u64,
    complete: bool,
}
impl Entry {
    pub fn opened(&mut self) {
        self.complete = false;
    }
    pub fn finish(&mut self, size: u64) -> Result<()> {
        conn::ok(
            self.session
                .call(Request::DescriptorCopy(super::Operation::Finish {
                    entry: self.id,
                    size,
                }))?,
            "finish stream",
        )?;
        self.complete = true;
        Ok(())
    }
}
impl Drop for Entry {
    fn drop(&mut self) {
        if !self.complete {
            self.session.abandon(self.id);
        }
    }
}
pub(super) struct Worker {
    session: Arc<Session>,
    connection: Option<Box<dyn Conn>>,
    reusable: bool,
    _permit: tokio::sync::OwnedSemaphorePermit,
}
impl Worker {
    pub fn connection(&mut self) -> &mut dyn Conn {
        &mut **self.connection.as_mut().unwrap()
    }
    pub fn completed(&mut self) -> Result<()> {
        // Do not keep old files (or aborted staging disk space) pinned while
        // idle. Its reply is drained before this connection serves a new job.
        self.connection().send(Request::BindStream(None))?;
        self.reusable = true;
        Ok(())
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        let mut connections = self.session.connections.lock().unwrap();
        connections.leased -= 1;
        if self.reusable {
            connections
                .idle
                .push(self.connection.take().expect("completed worker connection"));
        }
        self.session.available.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Unresponsive {
        reads: Arc<AtomicU64>,
    }
    impl Conn for Unresponsive {
        fn send(&mut self, _: Request) -> Result<()> {
            Ok(())
        }
        fn recv(&mut self) -> Result<Response> {
            self.reads.fetch_add(1, Relaxed);
            anyhow::bail!("unresponsive helper")
        }
        fn scan(
            &mut self,
            _: &[u8],
            _: Option<&crate::proto::RegisteredPath>,
            _: bool,
            _: &[String],
            _: bool,
            _: &mut dyn FnMut(Vec<crate::proto::Entry>) -> Result<()>,
            _: &mut dyn FnMut(Vec<crate::proto::PathBytes>) -> Result<()>,
            _: &mut dyn FnMut(String),
        ) -> Result<()> {
            unreachable!("stream control does not scan")
        }
        fn native_remove(
            &mut self,
            _: Option<&[u8]>,
            _: Option<&[u8]>,
            _: &[crate::proto::NativeRemoveSelection],
            _: bool,
            _: bool,
            _: usize,
            _: &mut dyn FnMut(Vec<String>) -> Result<()>,
            _: &mut dyn FnMut(Vec<crate::proto::NativeRemoveOutcome>) -> Result<()>,
        ) -> Result<()> {
            unreachable!("stream control does not remove paths")
        }
    }
    #[test]
    fn abandoned_entry_does_not_wait_for_a_control_reply() {
        let dir = crate::test_support::tempdir().unwrap();
        let args = Args::parse_args(&[
            "cp".into(),
            "--src-fd".into(),
            "0".into(),
            "--as".into(),
            dir.path().join("file").into_os_string(),
        ])
        .unwrap();
        let session = Session::connect(
            &args,
            args.descriptor_copy
                .as_ref()
                .unwrap()
                .location
                .as_ref()
                .unwrap(),
        )
        .unwrap();
        let reads = Arc::new(AtomicU64::new(0));
        session.control.lock().unwrap().connection = Box::new(Unresponsive {
            reads: reads.clone(),
        });
        let mut entry = session.entry().unwrap();
        entry.opened();
        drop(entry);
        assert_eq!(reads.load(Relaxed), 0);
        // A later control operation must check the pending abort reply, so a
        // transport failure cannot be mistaken for the next entry's response.
        assert!(session
            .call(Request::DescriptorCopy(super::super::Operation::Abort {
                entry: 999
            }))
            .unwrap_err()
            .to_string()
            .contains("unresponsive"));
        assert_eq!(reads.load(Relaxed), 1);
    }
}

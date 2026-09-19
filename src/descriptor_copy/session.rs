//! Endpoint lifetime and transport resources shared by stream entries.
use super::{Settings, BUFFER_BYTES, GRANULE};
use crate::{
    cli::{Args, Location},
    conn::{self, Conn, Endpoint},
    descriptor_broker::{DescriptorSessionSlot, DescriptorTicket},
    proto::{Request, Response},
};
use anyhow::Result;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering::Relaxed},
    Arc, Condvar, Mutex,
};
use std::time::Duration;
use tokio::sync::Semaphore;

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
pub(super) struct Session {
    pub endpoint: Endpoint,
    pub args: Args,
    control: Mutex<Box<dyn Conn>>,
    next_entry: AtomicU64,
    connections: Mutex<Connections>,
    available: Condvar,
    data_started: Mutex<bool>,
    limit: usize,
    pub budget: Arc<Semaphore>,
    buffers: Mutex<Vec<Vec<u8>>>,
    bandwidth: Option<crate::bwlimit::BandwidthLimit>,
    // Drop connections before closing the broker.
    _local: Option<LocalSession>,
    #[cfg(test)]
    pub connections_created: AtomicU64,
}
impl Session {
    pub fn connect(args: &Args, location: &Location) -> Result<Arc<Self>> {
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
            control: Mutex::new(control),
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
            budget: Arc::new(Semaphore::new(BUFFER_BYTES / GRANULE)),
            buffers: Mutex::new(Vec::new()),
            bandwidth: (args.bwlimit_bytes != 0)
                .then(|| crate::bwlimit::BandwidthLimit::new(args.bwlimit_bytes)),
            _local: local,
            #[cfg(test)]
            connections_created: AtomicU64::new(0),
        }))
    }
    pub fn entry(self: &Arc<Self>) -> Result<Entry> {
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
    pub fn call(&self, request: Request) -> Result<Response> {
        self.control.lock().unwrap().call(request)
    }
    pub fn start_data(&self) -> Result<()> {
        let mut started = self.data_started.lock().unwrap();
        if *started {
            return Ok(());
        }
        if let Endpoint::Remote(spec) = &self.endpoint {
            if !self.args.no_tcp && spec.tcp.lock().unwrap().is_none() {
                let mut control = self.control.lock().unwrap();
                // Serialize both the check and listener setup across entry opens.
                if spec.tcp.lock().unwrap().is_some() {
                    return Ok(());
                }
                let result = spec
                    .begin_tcp_setup(
                        &mut **control,
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
    pub fn worker(
        self: &Arc<Self>,
        ticket: DescriptorTicket,
        settings: Settings,
        first: bool,
        cancelled: &AtomicBool,
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
        self.buffers.lock().unwrap().pop().unwrap_or_default()
    }
    pub fn recycle(&self, mut buffer: Vec<u8>) {
        let mut buffers = self.buffers.lock().unwrap();
        let held = buffers.iter().map(Vec::capacity).sum::<usize>();
        if held.saturating_add(buffer.capacity()) <= BUFFER_BYTES {
            buffer.clear();
            buffers.push(buffer);
        }
    }
    pub fn pace(&self, bytes: u64) {
        if let Some(limit) = &self.bandwidth {
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
            // A failed/disconnected control leaves every unpublished entry owned
            // by helper cleanup. Never substitute a new endpoint connection.
            let _ = self
                .session
                .call(Request::DescriptorCopy(super::Operation::Abort {
                    entry: self.id,
                }));
        }
    }
}
pub(super) struct Worker {
    session: Arc<Session>,
    connection: Option<Box<dyn Conn>>,
    reusable: bool,
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

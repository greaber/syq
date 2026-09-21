//! Reverse establishment for named copies. Concurrent callers accept sockets
//! and hand each one to the worker that requested its one-use proof.
use super::*;
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub(crate) struct ReverseTcp {
    listeners: Vec<TcpListener>,
    pending: Mutex<std::collections::HashMap<[u8; 32], std::sync::mpsc::SyncSender<TcpStream>>>,
    authenticating: Mutex<std::collections::VecDeque<PendingProof>>,
    grant: String,
}

impl RemoteSpec {
    pub(super) fn begin_reverse_tcp_setup(
        &self,
        ports: (u16, u16),
        congestion_control: Option<&str>,
    ) -> Result<PendingTcpSetup> {
        let (port, listeners) = crate::server::bind_data_listeners(ports.0, ports.1)?;
        let mut effective = None;
        for listener in &listeners {
            effective = effective.or(configure_tcp_congestion(listener, congestion_control)?);
            listener.set_nonblocking(true)?;
        }
        let advertised = crate::server::return_tcp_addresses(&listeners);
        let grant = self
            .restricted_grant
            .clone()
            .context("missing named route")?;
        let reverse = Arc::new(ReverseTcp {
            listeners,
            pending: Mutex::new(std::collections::HashMap::new()),
            authenticating: Mutex::new(std::collections::VecDeque::new()),
            grant: grant.clone(),
        });
        let congestion_control = congestion_control.map(str::to_owned);
        let requested = congestion_control.clone();
        let probe = std::thread::spawn(move || {
            crate::destination::tcp::probe(&grant, port, ports, advertised, requested)
        });
        Ok(PendingTcpSetup {
            reverse: Some(reverse),
            port,
            // Every worker gets a fresh key over SSH.
            key: None,
            token: Vec::new(),
            congestion_control,
            remote_congestion_control: effective,
            probe,
        })
    }

    pub(super) fn connect_reverse_tcp(
        &self,
        reverse: &ReverseTcp,
        compress: bool,
        role: ConnectionRole,
    ) -> Result<RemoteConn> {
        let (stream, channel, key) = reverse.accept()?;
        stream.set_nodelay(true)?;
        let observation = Arc::new(crate::transfer_observations::RemoteSample::default());
        let (rx, reader) = spawn_observed_reader(
            Box::new(RecordReader::new(
                stream.try_clone()?,
                Some(Cipher::new(&key, 0, 2)),
            )),
            self.read_ahead,
            observation.clone(),
        );
        let conn = RemoteConn {
            observation,
            child: None,
            w: FrameWriter::new(
                Box::new(RecordWriter::new(
                    stream.try_clone()?,
                    Some(Cipher::new(&key, 0, 1)),
                )),
                compress,
            ),
            rx: Some(rx),
            reader: Some(reader),
            label: format!("{} (reverse tcp {})", self.label(), stream.peer_addr()?),
            dead: false,
            rpc_observation: None,
            write_stream: None,
            peer: None,
            tcp_socket: Some(Arc::new(stream)),
            named_socket: Some(channel),
            multiplexed_ssh: false,
            detached: false,
        };
        let conn = hello(conn, compress, Vec::new(), role)?;
        conn.tcp_socket.as_ref().unwrap().set_read_timeout(None)?;
        conn.tcp_socket.as_ref().unwrap().set_write_timeout(None)?;
        self.record_peer(&conn);
        Ok(conn)
    }
}

impl ReverseTcp {
    fn accept(&self) -> Result<(TcpStream, std::os::unix::net::UnixStream, Vec<u8>)> {
        let key = crate::tcp_records::random_bytes(crate::tcp_records::KEY_LEN);
        let mut proof = vec![0; 16];
        Cipher::new(&key, 0, 0).seal_in_place(&mut proof);
        let proof: [u8; 32] = proof.try_into().expect("fixed-size encrypted proof");
        let (send, receive) = std::sync::mpsc::sync_channel(1);
        self.pending.lock().unwrap().insert(proof, send);
        let _pending = PendingWorker { owner: self, proof };
        let channel = crate::destination::tcp::open(&self.grant, key.clone())?;
        let deadline = Instant::now() + Duration::from_secs(10);
        // Probes and unauthenticated arrivals cannot become workers. The proof
        // uses its own nonce direction (0); file protocol directions remain 1/2.
        // A new key per open also makes late arrivals and captured proofs useless.
        loop {
            if let Ok(stream) = receive.try_recv() {
                let remaining = deadline
                    .checked_duration_since(Instant::now())
                    .context("reverse TCP authentication deadline expired")?;
                stream.set_nonblocking(false)?;
                stream.set_read_timeout(Some(remaining))?;
                stream.set_write_timeout(Some(remaining))?;
                return Ok((stream, channel, key));
            }
            anyhow::ensure!(
                Instant::now() < deadline,
                "timed out accepting the receiving machine's TCP worker"
            );
            self.poll_authentication()?;
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn poll_authentication(&self) -> Result<()> {
        // Shared by all accepting workers, so one worker finishing cannot drop
        // another worker's partially received proof. No read holds up acceptance.
        let mut arrivals = self.authenticating.lock().unwrap();
        for listener in &self.listeners {
            match listener.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(true)?;
                    // Evict the oldest arrival rather than letting idle sockets
                    // reserve every authentication slot until their deadlines.
                    if arrivals.len() == MAX_PENDING_PROOFS {
                        arrivals.pop_front();
                    }
                    arrivals.push_back(PendingProof {
                        stream,
                        proof: [0; 32],
                        offset: 0,
                        deadline: Instant::now() + Duration::from_secs(10),
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e.into()),
            }
        }
        for _ in 0..arrivals.len() {
            let mut arrival = arrivals.pop_front().unwrap();
            if Instant::now() >= arrival.deadline {
                continue;
            }
            match arrival.stream.read(&mut arrival.proof[arrival.offset..]) {
                Ok(0) => continue,
                Ok(n) => arrival.offset += n,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => continue,
            }
            if arrival.offset == arrival.proof.len() {
                // Taking the pending slot consumes this proof once. A caller
                // can deliver another caller's socket without knowing its key.
                if let Some(send) = self.pending.lock().unwrap().remove(&arrival.proof) {
                    let _ = send.send(arrival.stream);
                }
            } else {
                arrivals.push_back(arrival);
            }
        }
        Ok(())
    }
}

struct PendingWorker<'a> {
    owner: &'a ReverseTcp,
    proof: [u8; 32],
}

impl Drop for PendingWorker<'_> {
    fn drop(&mut self) {
        self.owner.pending.lock().unwrap().remove(&self.proof);
    }
}

// This bound applies to the whole listener, independently of worker count.
const MAX_PENDING_PROOFS: usize = 64;

struct PendingProof {
    stream: TcpStream,
    proof: [u8; 32],
    offset: usize,
    deadline: Instant,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_proofs_are_bounded_and_fragmented_proofs_complete() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let reverse = ReverseTcp {
            listeners: vec![listener],
            pending: Mutex::new(Default::default()),
            authenticating: Mutex::new(Default::default()),
            grant: String::new(),
        };
        let mut idle = Vec::new();
        for _ in 0..MAX_PENDING_PROOFS + 1 {
            idle.push(TcpStream::connect(addr).unwrap());
            reverse.poll_authentication().unwrap();
            assert!(reverse.authenticating.lock().unwrap().len() <= MAX_PENDING_PROOFS);
        }
        assert_eq!(
            reverse.authenticating.lock().unwrap().len(),
            MAX_PENDING_PROOFS
        );

        let proof = [7; 32];
        let (send, receive) = std::sync::mpsc::sync_channel(1);
        reverse.pending.lock().unwrap().insert(proof, send);
        let mut worker = TcpStream::connect(addr).unwrap();
        worker.set_nodelay(true).unwrap();
        worker.write_all(&proof[..16]).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            reverse.poll_authentication().unwrap();
            if reverse
                .authenticating
                .lock()
                .unwrap()
                .iter()
                .any(|p| p.offset == 16)
            {
                break;
            }
            assert!(Instant::now() < deadline, "partial proof was not read");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(receive.try_recv().is_err());
        worker.write_all(&proof[16..]).unwrap();
        loop {
            reverse.poll_authentication().unwrap();
            if let Ok(stream) = receive.try_recv() {
                assert_eq!(stream.peer_addr().unwrap(), worker.local_addr().unwrap());
                break;
            }
            assert!(
                Instant::now() < deadline,
                "fragmented proof was not authenticated"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(reverse.pending.lock().unwrap().is_empty());
        // Expired idle sockets are removed even when no new connection arrives.
        for arrival in reverse.authenticating.lock().unwrap().iter_mut() {
            arrival.deadline = Instant::now();
        }
        reverse.poll_authentication().unwrap();
        assert!(reverse.authenticating.lock().unwrap().is_empty());
    }
}

//! TCP workers dialed by the receiving laptop. SSH carries setup and retains
//! each worker's cancellation channel, but carries no worker file data.
use super::*;
use crate::conn::{TcpCandidate, TcpInfo};
use std::net::Shutdown;

#[derive(Serialize, Deserialize)]
pub(super) struct ProbeRequest {
    token: String,
    port: u16,
    ports: (u16, u16),
    advertised: Vec<(String, u32)>,
    congestion_control: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub(super) struct OpenRequest {
    token: String,
    key: Vec<u8>,
}

pub(crate) fn probe(
    grant: &str,
    port: u16,
    ports: (u16, u16),
    advertised: Vec<(String, u32)>,
    congestion_control: Option<String>,
) -> Result<Vec<TcpCandidate>> {
    let route = decode_route(grant)?;
    let (_, reply) = exchange(
        &route.registration,
        Message::TcpProbe(ProbeRequest {
            token: route.token,
            port,
            ports,
            advertised,
            congestion_control,
        }),
        START_TIMEOUT,
    )?;
    match reply {
        Reply::TcpProbed(candidates) => Ok(candidates),
        Reply::TcpCongestionRejected(error) => Err(crate::conn::TcpCongestionError(error).into()),
        _ => bail!("unexpected reverse TCP probe response"),
    }
}

pub(crate) fn open(grant: &str, key: Vec<u8>) -> Result<UnixStream> {
    let route = decode_route(grant)?;
    let (stream, reply) = exchange(
        &route.registration,
        Message::TcpOpen(OpenRequest {
            token: route.token,
            key,
        }),
        START_TIMEOUT,
    )?;
    match reply {
        Reply::Ready => {
            stream.set_read_timeout(None)?;
            stream.set_write_timeout(None)?;
            Ok(stream)
        }
        Reply::TcpCongestionRejected(error) => Err(crate::conn::TcpCongestionError(error).into()),
        _ => bail!("unexpected reverse TCP worker response"),
    }
}

impl Receiver {
    pub(super) fn probe_tcp(&self, request: ProbeRequest, mut stream: TrackedStream) -> Result<()> {
        let authority = {
            let sessions = self.sessions.lock().unwrap();
            let session = sessions
                .get(&request.token)
                .context("unknown transfer authorization")?;
            if !session.opened {
                bail!("transfer control channel has not opened");
            }
            Arc::clone(&session.authority)
        };
        if request.port == 0
            || (request.ports != (0, 0)
                && !(request.ports.0..=request.ports.1).contains(&request.port))
        {
            bail!("reverse TCP port is outside the approved range");
        }
        // Reuse the approved transport constraints and one-listener allowance.
        authority.authorize(
            &mut crate::proto::Request::TcpListen {
                key: Some(vec![0; crate::tcp_records::KEY_LEN]),
                token: vec![0; 16],
                port_lo: request.ports.0,
                port_hi: request.ports.1,
                congestion_control: request.congestion_control.clone(),
            },
            true,
        )?;
        let candidates = self
            .tcp_peer
            .probe_tcp_addresses(request.advertised, request.port)?;
        // Use the ordinary speed selection on both peers. This temporary spec
        // has no helper or control connection and performs no filesystem work.
        let selected = crate::conn::select_tcp_candidates(candidates);
        let addrs = selected
            .iter()
            .filter(|c| c.selected)
            .map(|c| c.address.clone())
            .collect::<Vec<_>>();
        if addrs.is_empty() {
            bail!("no advertised data address is reachable");
        }
        let info = TcpInfo {
            reverse: None,
            addrs,
            port: request.port,
            key: None,
            token: Vec::new(),
            congestion_control: request.congestion_control,
            failed: false,
            failure: None,
            next: Default::default(),
        };
        let mut sessions = self.sessions.lock().unwrap();
        let session = sessions
            .get_mut(&request.token)
            .context("transfer ended during TCP setup")?;
        if !authority.control_is_open() {
            bail!("transfer control channel closed");
        }
        session.tcp = Some(info);
        drop(sessions);
        write_message(&mut stream, &Reply::TcpProbed(selected))
    }

    pub(super) fn open_tcp(&self, request: OpenRequest, mut channel: TrackedStream) -> Result<()> {
        if request.key.len() != crate::tcp_records::KEY_LEN {
            bail!("invalid reverse TCP key");
        }
        let (authority, info, _permit, _tracked) = {
            let sessions = self.sessions.lock().unwrap();
            let session = sessions
                .get(&request.token)
                .context("unknown transfer authorization")?;
            if !session.opened {
                bail!("transfer control channel has not opened");
            }
            let info = session
                .tcp
                .as_ref()
                .context("reverse TCP was not set up")?
                .clone();
            let permit = crate::server::ConnectionPermit::acquire(Arc::clone(&session.authority))?;
            let tracked = session.channels.track(channel.try_clone()?)?;
            (Arc::clone(&session.authority), info, permit, tracked)
        };
        let mut socket = match info.connect_socket() {
            Ok(socket) => socket,
            Err(error) if crate::conn::is_tcp_congestion_error(&error) => {
                return write_message(
                    &mut channel,
                    &Reply::TcpCongestionRejected(format!("{error:#}")),
                );
            }
            Err(error) => return Err(error),
        };
        socket.set_nodelay(true)?;
        socket.set_read_timeout(Some(Duration::from_secs(10)))?;
        socket.set_write_timeout(Some(Duration::from_secs(10)))?;
        let mut proof = vec![0; 16];
        crate::tcp_records::Cipher::new(&request.key, 0, 0).seal_in_place(&mut proof);
        socket.write_all(&proof)?;
        write_message(&mut channel, &Reply::Ready)?;
        let lifetime = channel.try_clone()?;
        lifetime.set_read_timeout(None)?;
        lifetime.set_write_timeout(None)?;
        let mut watch_channel = channel.try_clone()?;
        let watch_socket = socket.try_clone()?;
        let serve_channel = lifetime.try_clone()?;
        let watcher = std::thread::spawn(move || {
            let _ = watch_channel.read(&mut [0]);
            let _ = watch_socket.shutdown(Shutdown::Both);
        });
        let result = crate::server::run_named_tcp(socket, serve_channel, &request.key, authority);
        let _ = lifetime.shutdown(Shutdown::Both);
        let _ = watcher.join();
        result
    }
}

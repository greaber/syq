use super::*;

#[cfg(target_os = "linux")]
pub(super) fn tcp_congestion_control<S: AsRawFd>(socket: &S) -> std::io::Result<String> {
    // Linux currently caps names at TCP_CA_NAME_MAX (16 including NUL). Leave
    // extra room so this remains safe if the kernel raises that limit.
    let mut name = [0u8; 64];
    let mut len = name.len() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_CONGESTION,
            name.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let len = (len as usize).min(name.len());
    let end = name[..len]
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(len);
    std::str::from_utf8(&name[..end])
        .map(str::to_owned)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

/// Apply an explicit Linux TCP_CONGESTION override and read it back. With no
/// override this is observational only: an unavailable getter returns None
/// and never changes normal socket behavior.
#[cfg(not(target_os = "linux"))]
pub(crate) fn configure_tcp_congestion<S: AsRawFd>(
    _socket: &S,
    requested: Option<&str>,
) -> Result<Option<String>> {
    match requested {
        None => Ok(None),
        Some(requested) => Err(TcpCongestionError(format!(
            "TCP congestion control {requested:?} was requested, but per-socket selection is supported only on Linux"
        ))
        .into()),
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn configure_tcp_congestion<S: AsRawFd>(
    socket: &S,
    requested: Option<&str>,
) -> Result<Option<String>> {
    let Some(requested) = requested else {
        return Ok(tcp_congestion_control(socket).ok());
    };

    {
        let result = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_CONGESTION,
                requested.as_ptr().cast(),
                requested.len() as libc::socklen_t,
            )
        };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            return Err(TcpCongestionError(format!(
                "kernel rejected TCP congestion control {requested:?}: {error}; check net.ipv4.tcp_available_congestion_control and net.ipv4.tcp_allowed_congestion_control on this host"
            ))
            .into());
        }
        let actual = tcp_congestion_control(socket).map_err(|error| {
            TcpCongestionError(format!(
                "could not verify TCP congestion control {requested:?}: {error}"
            ))
        })?;
        if actual != requested {
            return Err(TcpCongestionError(format!(
                "requested TCP congestion control {requested:?}, but the socket reports {actual:?}"
            ))
            .into());
        }
        Ok(Some(actual))
    }
}

#[cfg(not(target_os = "linux"))]
pub(super) fn connect_tcp_stream(
    address: &SocketAddr,
    timeout: std::time::Duration,
    congestion_control: Option<&str>,
) -> Result<TcpStream> {
    match congestion_control {
        None => TcpStream::connect_timeout(address, timeout).map_err(Into::into),
        Some(congestion_control) => Err(TcpCongestionError(format!(
            "TCP congestion control {congestion_control:?} was requested, but per-socket selection is supported only on Linux"
        ))
        .into()),
    }
}

#[cfg(target_os = "linux")]
pub(super) fn connect_tcp_stream(
    address: &SocketAddr,
    timeout: std::time::Duration,
    congestion_control: Option<&str>,
) -> Result<TcpStream> {
    let Some(congestion_control) = congestion_control else {
        return TcpStream::connect_timeout(address, timeout).map_err(Into::into);
    };

    {
        use socket2::{Domain, Protocol, SockAddr, Socket, Type};

        let domain = if address.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        configure_tcp_congestion(&socket, Some(congestion_control))?;
        socket.connect_timeout(&SockAddr::from(*address), timeout)?;
        Ok(socket.into())
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn tcp_socket_stats(stream: &TcpStream) -> Option<TcpSocketStats> {
    let mut info: libc::tcp_info = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            &mut info as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if result != 0 {
        return None;
    }
    macro_rules! field {
        ($name:ident, $value:expr) => {
            ((len as usize)
                >= std::mem::offset_of!(libc::tcp_info, $name) + std::mem::size_of_val(&info.$name))
            .then(|| $value)
        };
    }
    Some(TcpSocketStats {
        congestion_control: tcp_congestion_control(stream).ok(),
        bytes_sent: field!(tcpi_bytes_sent, info.tcpi_bytes_sent),
        bytes_retransmitted: field!(tcpi_bytes_retrans, info.tcpi_bytes_retrans),
        segments_sent: field!(tcpi_segs_out, info.tcpi_segs_out.into()),
        segments_received: field!(tcpi_segs_in, info.tcpi_segs_in.into()),
        retransmissions: field!(tcpi_total_retrans, info.tcpi_total_retrans.into()),
        rtt_us: field!(tcpi_rtt, info.tcpi_rtt.into()),
        rtt_variance_us: field!(tcpi_rttvar, info.tcpi_rttvar.into()),
        min_rtt_us: field!(tcpi_min_rtt, info.tcpi_min_rtt.into()),
        send_cwnd_bytes: field!(
            tcpi_snd_cwnd,
            u64::from(info.tcpi_snd_cwnd) * u64::from(info.tcpi_snd_mss)
        ),
        delivery_rate: field!(tcpi_delivery_rate, info.tcpi_delivery_rate),
        busy_time_us: field!(tcpi_busy_time, info.tcpi_busy_time),
        receive_window_limited_us: field!(tcpi_rwnd_limited, info.tcpi_rwnd_limited),
        send_buffer_limited_us: field!(tcpi_sndbuf_limited, info.tcpi_sndbuf_limited),
        ecn_ce_delivered: field!(tcpi_delivered_ce, info.tcpi_delivered_ce.into()),
    })
}

/// `struct tcp_connection_info` as the XNU kernel lays it out. The `libc`
/// crate expands the kernel's single 32-bit TFO bit-field word into
/// eighteen separate fields, which shifts every 64-bit counter and makes the
/// kernel's returned length fall short of them.
#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct DarwinTcpConnectionInfo {
    pub(super) tcpi_state: u8,
    pub(super) tcpi_snd_wscale: u8,
    pub(super) tcpi_rcv_wscale: u8,
    pub(super) __pad1: u8,
    pub(super) tcpi_options: u32,
    pub(super) tcpi_flags: u32,
    pub(super) tcpi_rto: u32,
    pub(super) tcpi_maxseg: u32,
    pub(super) tcpi_snd_ssthresh: u32,
    pub(super) tcpi_snd_cwnd: u32,
    pub(super) tcpi_snd_wnd: u32,
    pub(super) tcpi_snd_sbbytes: u32,
    pub(super) tcpi_rcv_wnd: u32,
    pub(super) tcpi_rttcur: u32,
    pub(super) tcpi_srtt: u32,
    pub(super) tcpi_rttvar: u32,
    pub(super) tcpi_tfo: u32,
    pub(super) tcpi_txpackets: u64,
    pub(super) tcpi_txbytes: u64,
    pub(super) tcpi_txretransmitbytes: u64,
    pub(super) tcpi_rxpackets: u64,
    pub(super) tcpi_rxbytes: u64,
    pub(super) tcpi_rxoutoforderbytes: u64,
    pub(super) tcpi_txretransmitpackets: u64,
}

#[cfg(target_os = "macos")]
pub(crate) fn tcp_socket_stats(stream: &TcpStream) -> Option<TcpSocketStats> {
    let mut info: DarwinTcpConnectionInfo = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<DarwinTcpConnectionInfo>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_CONNECTION_INFO,
            &mut info as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if result != 0 {
        return None;
    }
    macro_rules! field {
        ($name:ident, $value:expr) => {
            ((len as usize)
                >= std::mem::offset_of!(DarwinTcpConnectionInfo, $name)
                    + std::mem::size_of_val(&info.$name))
            .then(|| $value)
        };
    }
    Some(TcpSocketStats {
        congestion_control: None,
        bytes_sent: field!(tcpi_txbytes, info.tcpi_txbytes),
        bytes_retransmitted: field!(tcpi_txretransmitbytes, info.tcpi_txretransmitbytes),
        segments_sent: field!(tcpi_txpackets, info.tcpi_txpackets),
        segments_received: field!(tcpi_rxpackets, info.tcpi_rxpackets),
        retransmissions: None,
        // Darwin reports these fields in milliseconds.
        rtt_us: field!(tcpi_srtt, u64::from(info.tcpi_srtt) * 1000),
        rtt_variance_us: field!(tcpi_rttvar, u64::from(info.tcpi_rttvar) * 1000),
        min_rtt_us: None,
        send_cwnd_bytes: field!(tcpi_snd_cwnd, info.tcpi_snd_cwnd.into()),
        delivery_rate: None,
        busy_time_us: None,
        receive_window_limited_us: None,
        send_buffer_limited_us: None,
        ecn_ce_delivered: None,
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn tcp_socket_stats(_stream: &TcpStream) -> Option<TcpSocketStats> {
    None
}

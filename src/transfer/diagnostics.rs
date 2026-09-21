use super::*;

pub(super) fn link_speed(speed_mbps: u32) -> String {
    if speed_mbps == 0 {
        "link speed unknown".to_string()
    } else if speed_mbps.is_multiple_of(1000) {
        format!("{} Gbit/s advertised", speed_mbps / 1000)
    } else {
        format!("{speed_mbps} Mbit/s advertised")
    }
}

pub(super) fn candidate_status(candidate: &TcpCandidate, fastest: u32) -> String {
    match candidate.reachable {
        None => return "untested (probe unfinished at route selection)".to_string(),
        Some(false) => return "not reachable".to_string(),
        Some(true) => {}
    }
    let speed = link_speed(candidate.speed_mbps);
    if candidate.selected {
        return format!("reachable, {speed}, selected by preflight");
    }
    let reason = if fastest == 0 {
        "link speeds unknown; first reachable path preferred"
    } else if candidate.speed_mbps == 0 {
        "a faster advertised path was available"
    } else {
        "less than half the fastest advertised link speed"
    };
    format!("reachable, {speed}, not selected ({reason})")
}

pub(super) fn one_line(message: &str) -> String {
    message
        .lines()
        .map(str::trim)
        .collect::<Vec<_>>()
        .join("; ")
}

pub(super) fn interface_option<'a>(args: &Args, native: &'a str, rsync: &'a str) -> &'a str {
    if args.interface == Interface::Rsync {
        rsync
    } else {
        native
    }
}

pub(super) fn remote_helper_mode(spec: &RemoteSpec, interface: Interface) -> &'static str {
    if spec.forwarded.is_some() {
        "approved return connection"
    } else if spec.bootstrap_helper {
        if *spec.helper_install.lock().unwrap() {
            "managed; installed now"
        } else {
            "managed helper cache"
        }
    } else if spec.restricted_grant.is_some() {
        "restricted grant"
    } else if spec.syq_path.is_some() {
        match interface {
            Interface::Rsync => "--rsync-path",
            _ => "--syq-path",
        }
    } else {
        match interface {
            Interface::Rsync => "remote PATH (--syq-no-bootstrap)",
            _ => "remote PATH (--no-bootstrap)",
        }
    }
}

/// The control-connection and helper lines of a remote endpoint's -vv report.
pub(super) fn print_remote_control_diagnostics(spec: &RemoteSpec, args: &Args) {
    let diagnostics = spec.diagnostics();
    crate::output::diagnostic!("syq: {}:", spec.label());
    if let Some(peer) = &diagnostics.peer {
        crate::output::diagnostic!(
            "  control: connected via {}; remote {}",
            spec.remote_shell_name(),
            peer.platform
        );
        if let Some(version) = crate::conn::openssh_version(&spec.rsh[0]) {
            crate::output::diagnostic!("  ssh client: {version}");
        }
        let helper_mode = remote_helper_mode(spec, args.interface);
        crate::output::diagnostic!("  helper: {} ({helper_mode})", peer.identity);
    }
}

/// What -vv explains for a copy whose files travelled on the control
/// connection: the same helper lines, and a route that involved no data
/// connection at all.
pub(super) fn print_small_copy_diagnostics(args: &Args, dst_ep: &Endpoint) {
    if args.quiet || args.verbose < 2 {
        return;
    }
    if let Endpoint::Remote(spec) = dst_ep {
        print_remote_control_diagnostics(spec, args);
        crate::output::diagnostic!(
            "  transport: control connection (small files sent in one request)"
        );
    }
    crate::output::diagnostic!(
        "syq: concurrency: no data connections (small files sent on the control connection)"
    );
}

pub(super) fn print_remote_diagnostics(spec: &RemoteSpec, args: &Args) {
    print_remote_control_diagnostics(spec, args);
    let diagnostics = spec.diagnostics();
    if let Some(probe) = &diagnostics.tcp_probe {
        let fastest = probe
            .candidates
            .iter()
            .filter(|candidate| candidate.reachable == Some(true))
            .map(|candidate| candidate.speed_mbps)
            .max()
            .unwrap_or(0);
        for candidate in &probe.candidates {
            let source = if candidate.source == DataAddressSource::SshTarget {
                " (SSH target)"
            } else {
                ""
            };
            crate::output::diagnostic!(
                "  TCP {}{source}: {}",
                data_address(&candidate.address, probe.port),
                candidate_status(candidate, fastest)
            );
        }
        let remote = probe.congestion_control.as_deref().unwrap_or("unavailable");
        match &args.tcp_congestion {
            Some(requested) => crate::output::diagnostic!(
                "  congestion control: remote listener {remote}; local data sockets request {requested}"
            ),
            None => crate::output::diagnostic!("  congestion control: remote listener {remote} (host default)"),
        }
    }

    let route_state = if args.dry_run {
        "planned for a real transfer"
    } else {
        "planned"
    };
    let transport = spec.data_transport();
    match transport {
        DataTransport::EncryptedTcp | DataTransport::PlaintextTcp => {
            let name = if transport == DataTransport::EncryptedTcp {
                "encrypted TCP"
            } else {
                "plaintext TCP"
            };
            crate::output::diagnostic!(
                "  transport: {name} {route_state} (reachability preflight passed)"
            );
        }
        DataTransport::Ssh => {
            let tcp_failure = spec
                .tcp
                .lock()
                .unwrap()
                .as_ref()
                .and_then(|info| info.failure.clone())
                .or(diagnostics.tcp_setup_error.clone());
            if args.no_tcp {
                crate::output::diagnostic!(
                    "  transport: SSH {route_state} ({})",
                    interface_option(args, "--no-tcp", "--syq-no-tcp")
                );
            } else if let Some(error) = tcp_failure {
                crate::output::diagnostic!(
                    "  transport: SSH {route_state} (TCP unavailable: {})",
                    one_line(&error)
                );
            } else {
                crate::output::diagnostic!("  transport: SSH {route_state}");
            }
        }
    }
}

pub(super) fn print_transport_diagnostics(args: &Args, src: &Endpoint, dst: &Endpoint) {
    if args.quiet || args.verbose < 2 {
        return;
    }
    for endpoint in [src, dst] {
        if let Endpoint::Remote(spec) = endpoint {
            if !spec.local_process {
                print_remote_diagnostics(spec, args);
            }
        }
    }
    let remote = src.is_remote() || dst.is_remote();
    let unit = match (remote, args.connections) {
        (true, 1) => "connection",
        (true, _) => "connections",
        (false, 1) => "worker",
        (false, _) => "workers",
    };
    let policy = if args.connections_default {
        "auto-tuned"
    } else {
        "fixed"
    };
    if !remote {
        crate::output::diagnostic!("syq: transport: local filesystem");
    }
    let automatic_ssh = args.connections_default
        && [src, dst]
            .into_iter()
            .filter_map(real_remote_spec)
            .any(|spec| spec.data_transport() == DataTransport::Ssh);
    if automatic_ssh {
        let dry = if args.dry_run {
            "; dry-run starts no workers"
        } else {
            ""
        };
        crate::output::diagnostic!(
            "syq: concurrency: target {} {unit} ({policy}){dry}",
            args.connections
        );
    } else if args.dry_run {
        crate::output::diagnostic!(
            "syq: concurrency: a real transfer would start with {} {unit} ({policy}); dry-run starts no workers",
            args.connections
        );
    } else {
        crate::output::diagnostic!(
            "syq: concurrency: starting with {} {unit} ({policy})",
            args.connections
        );
    }
}

pub(super) fn format_tcp_stats(pairs: &[TcpPairStats], has_ssh_data: bool) -> String {
    let sockets: Vec<&TcpSocketStats> = pairs
        .iter()
        .flat_map(|pair| {
            [pair.local.as_ref(), pair.peer.as_ref()]
                .into_iter()
                .flatten()
        })
        .collect();
    if sockets.is_empty() {
        return if has_ssh_data {
            "\n  tcp statistics: unavailable (data used SSH)".into()
        } else {
            "\n  tcp statistics: unavailable on this platform/kernel".into()
        };
    }
    // Aggregates are meaningful only when every sampled socket exposes the
    // field. Do not turn an unsupported end into a genuine zero.
    let sum = |field: fn(&TcpSocketStats) -> Option<u64>| {
        sockets
            .iter()
            .map(|stats| field(stats))
            .sum::<Option<u64>>()
    };
    let values = |field: fn(&TcpSocketStats) -> Option<u64>| {
        sockets
            .iter()
            .map(|stats| field(stats))
            .collect::<Option<Vec<u64>>>()
    };
    let bytes_sent = sum(|stats| stats.bytes_sent);
    let bytes_retransmitted = sum(|stats| stats.bytes_retransmitted);
    let segments_sent = sum(|stats| stats.segments_sent);
    let retransmissions = sum(|stats| stats.retransmissions);
    let average_rtt =
        values(|stats| stats.rtt_us).map(|rtts| rtts.iter().sum::<u64>() / rtts.len() as u64);
    let min_rtt = values(|stats| stats.min_rtt_us).and_then(|rtts| rtts.into_iter().min());
    let loss = |amount: Option<u64>, sent: Option<u64>| match amount {
        None => "unavailable".into(),
        Some(amount) => match sent {
            Some(sent) if sent > 0 => format!(
                "{} ({:.3}% of sent)",
                commas(amount),
                amount as f64 * 100.0 / sent as f64
            ),
            _ => format!("{} (percentage unavailable)", commas(amount)),
        },
    };
    let average_congestion_window = values(|stats| stats.send_cwnd_bytes)
        .map(|windows| windows.iter().sum::<u64>() / windows.len() as u64);
    let delivery_rate = sum(|stats| stats.delivery_rate);
    let busy = sum(|stats| stats.busy_time_us);
    let receive_limited = sum(|stats| stats.receive_window_limited_us);
    let send_limited = sum(|stats| stats.send_buffer_limited_us);
    let limited_percent = |limited: Option<u64>| match (limited, busy) {
        (Some(limited), Some(busy)) if busy > 0 => {
            format!("{:.1}%", limited as f64 * 100.0 / busy as f64)
        }
        _ => "unavailable".into(),
    };
    let paths = pairs
        .iter()
        .map(|pair| pair.label.as_str())
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    let mut congestion_controls = std::collections::BTreeMap::<&str, usize>::new();
    let mut unavailable_congestion_controls = 0usize;
    for socket in &sockets {
        match socket.congestion_control.as_deref() {
            Some(algorithm) => *congestion_controls.entry(algorithm).or_default() += 1,
            None => unavailable_congestion_controls += 1,
        }
    }
    let mut congestion_control = congestion_controls
        .into_iter()
        .map(|(algorithm, count)| format!("{algorithm} ({count} socket ends)"))
        .collect::<Vec<_>>();
    if unavailable_congestion_controls > 0 {
        congestion_control.push(format!(
            "unavailable ({unavailable_congestion_controls} socket ends)"
        ));
    }
    let congestion_control = congestion_control.join(", ");
    let mut output = format!(
        "\n  tcp connection lifetimes sampled: {} across {} path(s) ({} socket ends)\n  tcp congestion control: {}\n  tcp retransmissions (loss signal): {} packets, {} bytes\n  tcp RTT: current average {}, minimum {}\n  tcp congestion: average send window {}, aggregate delivery rate {}\n  tcp window-limited time: receive {}, send-buffer {}\n  tcp ECN CE deliveries: {}",
        pairs.len(),
        paths,
        sockets.len(),
        congestion_control,
        loss(retransmissions, segments_sent),
        loss(bytes_retransmitted, bytes_sent),
        average_rtt.map_or_else(|| "unavailable".into(), |value| format!("{:.2} ms", value as f64 / 1000.0)),
        min_rtt.map_or_else(|| "unavailable".into(), |value| format!("{:.2} ms", value as f64 / 1000.0)),
        average_congestion_window.map_or_else(|| "unavailable".into(), human),
        delivery_rate.map_or_else(|| "unavailable".into(), |value| format!("{}/s", human(value))),
        limited_percent(receive_limited),
        limited_percent(send_limited),
        sum(|stats| stats.ecn_ce_delivered)
            .map_or_else(|| "unavailable".into(), commas),
    );
    if has_ssh_data {
        output.push_str("\n  ssh data connections: kernel TCP loss statistics unavailable");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unfinished_probe_is_not_reported_as_unreachable() {
        let mut candidate = TcpCandidate {
            address: "192.0.2.1".into(),
            speed_mbps: 0,
            source: DataAddressSource::RemoteInterface,
            reachable: None,
            selected: false,
        };
        assert_eq!(
            candidate_status(&candidate, 0),
            "untested (probe unfinished at route selection)"
        );
        candidate.reachable = Some(false);
        assert_eq!(candidate_status(&candidate, 0), "not reachable");
    }
}

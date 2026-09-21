//! Platform enumeration feeding shared data-address selection.
use std::net::IpAddr;

fn is_virtual_iface(name: &str) -> bool {
    matches!(name, "lo" | "lo0")
        || [
            "docker", "veth", "br-", "virbr", "vmnet", "cni", "flannel", "cali", "kube",
        ]
        .iter()
        .any(|p| name.starts_with(p))
        || platform_virtual_iface(name)
}

#[cfg(target_os = "linux")]
fn iface_speed(name: &str) -> u32 {
    std::fs::read_to_string(format!("/sys/class/net/{name}/speed"))
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .filter(|&v| v > 0)
        .map(|v| v as u32)
        .unwrap_or(0)
}

/// Which address families the data listener bound, and so which advertised
/// addresses a client could possibly connect to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct BoundFamilies {
    pub(super) v4: bool,
    pub(super) v6: bool,
}

impl BoundFamilies {
    fn accepts(self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(_) => self.v4,
            IpAddr::V6(_) => self.v6,
        }
    }
}

#[cfg(target_os = "linux")]
fn platform_virtual_iface(name: &str) -> bool {
    std::path::Path::new(&format!("/sys/class/net/{name}/bridge")).exists()
}

#[cfg(not(target_os = "linux"))]
fn platform_virtual_iface(name: &str) -> bool {
    // Darwin bridge interfaces are the counterpart of Linux bridge devices.
    name.starts_with("bridge")
}

struct InterfaceAddress {
    name: String,
    ip: IpAddr,
    speed_mbps: u32,
}

/// Advertise reachable candidates on this endpoint; SSH's arrival IP remains
/// available even when enumeration fails or filters its interface out.
pub(super) fn local_addrs(families: BoundFamilies) -> Vec<(String, u32)> {
    let ssh_ip = std::env::var("SSH_CONNECTION")
        .ok()
        .and_then(|c| c.split_whitespace().nth(2).and_then(|ip| ip.parse().ok()));
    let interfaces = interface_addresses();
    // Fallback fixtures must not depend on the host's reachable interfaces.
    #[cfg(debug_assertions)]
    let interfaces = if std::env::var_os("SYQ_TEST_NO_INTERFACE_ADDRESSES").is_some() {
        Vec::new()
    } else {
        interfaces
    };
    advertised_addrs(interfaces, ssh_ip, families)
}

#[cfg(target_os = "linux")]
fn interface_addresses() -> Vec<InterfaceAddress> {
    let text = std::process::Command::new("ip")
        .args(["-o", "addr", "show"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    parse_ip_addrs(&text, iface_speed)
}

#[cfg(target_os = "macos")]
#[path = "interfaces/macos.rs"]
mod macos;
#[cfg(target_os = "macos")]
use macos::interface_addresses;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn interface_addresses() -> Vec<InterfaceAddress> {
    Vec::new()
}

/// Priority bucket for an advertised address: lower sorts first. The address
/// ssh arrived on is bucket 0 (handled by the caller); this classifies the
/// rest so that LAN addresses are tried before public ones and overlay
/// (CGNAT / Tailscale) addresses last.
fn addr_bucket(ip: IpAddr) -> u8 {
    if crate::conn::is_overlay_address(&ip.to_string()) {
        return 3; // CGNAT / Tailscale
    }
    match ip {
        IpAddr::V4(v4) if v4.is_private() => 1,
        // Unique local (fc00::/7), e.g. a private cloud network.
        IpAddr::V6(v6) if (v6.segments()[0] & 0xfe00) == 0xfc00 => 1,
        _ => 2, // public
    }
}

/// The platform adapter supplies usable addresses and optional link speeds.
/// Keep address filtering and priority common to both platforms.
fn advertised_addrs(
    interfaces: impl IntoIterator<Item = InterfaceAddress>,
    ssh_ip: Option<IpAddr>,
    families: BoundFamilies,
) -> Vec<(String, u32)> {
    let mut addrs: Vec<(IpAddr, u32, u8)> = Vec::new();
    for interface in interfaces {
        let ip = interface.ip;
        if !families.accepts(ip) || !usable_ip(ip) || is_virtual_iface(&interface.name) {
            continue;
        }
        let bucket = if ssh_ip == Some(ip) {
            0
        } else {
            addr_bucket(ip)
        };
        addrs.push((ip, interface.speed_mbps, bucket));
    }
    // The address ssh arrived on is reachable by construction (loopback
    // included: the client is then on this host). Advertise it even when the
    // listing did not name it (no `ip` tool, or an address on an interface
    // the listing filtered out).
    if let Some(ip) = ssh_ip {
        if families.accepts(ip) && !addrs.iter().any(|a| a.0 == ip) {
            addrs.push((ip, 0, 0));
        }
    }
    // ssh-arrival ip first, then by bucket, then by speed (fastest first).
    addrs.sort_by(|a, b| a.2.cmp(&b.2).then(b.1.cmp(&a.1)));
    let mut seen = std::collections::HashSet::new();
    addrs.retain(|a| seen.insert(a.0));
    addrs
        .into_iter()
        .map(|(ip, sp, _)| (ip.to_string(), sp))
        .collect()
}

fn usable_ip(ip: IpAddr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    match ip {
        IpAddr::V4(ip) => !ip.is_link_local() && !ip.is_broadcast(),
        IpAddr::V6(ip) => !ip.is_unicast_link_local(),
    }
}

#[cfg(any(target_os = "linux", test))]
fn parse_ip_addrs(text: &str, iface_speed: impl Fn(&str) -> u32) -> Vec<InterfaceAddress> {
    let mut addrs = Vec::new();
    for line in text.lines() {
        // "3: bond0    inet 10.2.201.45/24 brd ... scope global bond0\ ..."
        // "3: bond0    inet6 fdaa:0:1::2/112 scope global \ ..."
        let f: Vec<&str> = line.split_whitespace().collect();
        let Some(iface) = f.get(1) else {
            continue;
        };
        let Some(family_at) = f.iter().position(|w| *w == "inet" || *w == "inet6") else {
            continue;
        };
        let Some(ipcidr) = f.get(family_at + 1) else {
            continue;
        };
        let scope = f
            .iter()
            .position(|w| *w == "scope")
            .and_then(|at| f.get(at + 1))
            .copied();
        if scope != Some("global") {
            continue;
        }
        // An address the kernel is still checking, or is retiring, is not a
        // reliable route to advertise.
        if f.iter().any(|w| *w == "tentative" || *w == "deprecated") {
            continue;
        }
        let Some(ip) = ipcidr
            .split('/')
            .next()
            .and_then(|ip| ip.parse::<IpAddr>().ok())
        else {
            continue;
        };
        addrs.push(InterfaceAddress {
            name: (*iface).to_owned(),
            ip,
            speed_mbps: iface_speed(iface),
        });
    }
    addrs
}

#[cfg(test)]
mod tests {
    use super::*;
    const IP_ADDR_SHOW: &str = "\
1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever
1: lo    inet6 ::1/128 scope host noprefixroute \\       valid_lft forever preferred_lft forever
2: eth0    inet 172.19.3.10/29 brd 172.19.3.15 scope global eth0\\       valid_lft forever preferred_lft forever
2: eth0    inet6 fdaa:0:1:a7b::2/112 scope global \\       valid_lft forever preferred_lft forever
2: eth0    inet6 2001:db8::2/64 scope global \\       valid_lft forever preferred_lft forever
2: eth0    inet6 2001:db8::3/64 scope global tentative \\       valid_lft forever preferred_lft forever
2: eth0    inet6 fe80::9e6b:ff:fe4e:89ad/64 scope link \\       valid_lft forever preferred_lft forever
3: bond0    inet 10.2.201.45/24 brd 10.2.201.255 scope global bond0\\       valid_lft forever preferred_lft forever
4: tailscale0    inet 100.101.102.103/32 scope global tailscale0\\       valid_lft forever preferred_lft forever
4: tailscale0    inet6 fd7a:115c:a1e0::1234/128 scope global \\       valid_lft forever preferred_lft forever
5: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0\\       valid_lft forever preferred_lft forever
";

    fn speeds(name: &str) -> u32 {
        match name {
            "bond0" => 25000,
            "eth0" => 1000,
            _ => 0,
        }
    }

    #[test]
    fn advertised_addrs_lists_both_families_with_ssh_arrival_first() {
        let ssh = "fdaa:0:1:a7b::2".parse().ok();
        let both = BoundFamilies { v4: true, v6: true };
        let got = advertised_addrs(parse_ip_addrs(IP_ADDR_SHOW, speeds), ssh, both);
        assert_eq!(
            got,
            vec![
                ("fdaa:0:1:a7b::2".to_string(), 1000),
                ("10.2.201.45".to_string(), 25000),
                ("172.19.3.10".to_string(), 1000),
                ("2001:db8::2".to_string(), 1000),
                ("100.101.102.103".to_string(), 0),
                ("fd7a:115c:a1e0::1234".to_string(), 0),
            ]
        );
    }

    #[test]
    fn advertised_addrs_only_names_families_the_listener_bound() {
        let v4 = BoundFamilies {
            v4: true,
            v6: false,
        };
        let got = advertised_addrs(parse_ip_addrs(IP_ADDR_SHOW, speeds), None, v4);
        assert!(got
            .iter()
            .all(|(ip, _)| ip.parse::<IpAddr>().unwrap().is_ipv4()));
        assert_eq!(got[0].0, "10.2.201.45");
        // The ssh arrival address is still advertised first, but only when a
        // listener of its family exists.
        let ssh = "fdaa:0:1:a7b::2".parse().ok();
        let got = advertised_addrs(parse_ip_addrs(IP_ADDR_SHOW, speeds), ssh, v4);
        assert!(!got.iter().any(|(ip, _)| ip.starts_with("fdaa")));
    }

    #[test]
    fn advertised_addrs_includes_ipoib_addresses_with_known_or_unknown_speed() {
        let listing = "\
    2: eth0    inet 192.0.2.2/24 scope global eth0
    3: ib0    inet 192.0.2.3/24 scope global ib0
    4: ib0.8001    inet6 2001:db8::4/64 scope global
    4: ib0.8001    inet6 fe80::4/64 scope link
    5: docker0    inet 172.17.0.1/16 scope global docker0
    ";
        let both = BoundFamilies { v4: true, v6: true };
        let got = advertised_addrs(
            parse_ip_addrs(listing, |name| match name {
                "ib0" => 100_000,
                "eth0" => 10_000,
                _ => 0,
            }),
            None,
            both,
        );
        assert_eq!(
            got,
            vec![
                ("192.0.2.3".into(), 100_000),
                ("192.0.2.2".into(), 10_000),
                ("2001:db8::4".into(), 0),
            ]
        );
    }

    #[test]
    fn advertised_addrs_includes_ssh_arrival_address_without_a_listing() {
        let ssh = "203.0.113.7".parse().ok();
        let both = BoundFamilies { v4: true, v6: true };
        assert_eq!(
            advertised_addrs([], ssh, both),
            vec![("203.0.113.7".to_string(), 0)]
        );
    }

    #[test]
    fn selection_filters_unusable_addresses_and_keeps_unknown_speed_candidates() {
        let entries = [
            ("en0", "192.168.1.8", 0),
            ("en1", "2001:db8::8", 0),
            ("utun0", "100.100.1.2", 0),
            ("docker0", "172.17.0.1", 1000),
            ("lo0", "127.0.0.1", 0),
            ("lo0", "::1", 0),
            ("en0", "169.254.1.1", 0),
            ("en0", "fe80::1", 0),
            ("en0", "0.0.0.0", 0),
            ("en0", "::", 0),
            ("en0", "224.0.0.1", 0),
            ("en0", "ff02::1", 0),
        ];
        let addresses = entries.map(|(name, ip, speed_mbps)| InterfaceAddress {
            name: name.into(),
            ip: ip.parse().unwrap(),
            speed_mbps,
        });
        assert_eq!(
            advertised_addrs(
                addresses,
                Some("127.0.0.1".parse().unwrap()),
                BoundFamilies { v4: true, v6: true }
            ),
            vec![
                ("127.0.0.1".into(), 0),
                ("192.168.1.8".into(), 0),
                ("2001:db8::8".into(), 0),
                ("100.100.1.2".into(), 0),
            ]
        );
    }

    #[test]
    fn loopback_aliases_are_excluded_unless_used_by_ssh() {
        let entries = || {
            [
                ("lo", "10.0.0.1"),
                ("lo0", "10.0.0.2"),
                ("lo0", "fd00::2"),
                ("en0", "10.0.0.3"),
            ]
            .map(|(name, ip)| InterfaceAddress {
                name: name.into(),
                ip: ip.parse().unwrap(),
                speed_mbps: 0,
            })
        };
        let families = BoundFamilies { v4: true, v6: true };
        assert_eq!(
            advertised_addrs(entries(), None, families),
            vec![("10.0.0.3".into(), 0)],
        );
        for ssh in ["10.0.0.2", "fd00::2"] {
            assert_eq!(
                advertised_addrs(entries(), Some(ssh.parse().unwrap()), families),
                vec![(ssh.into(), 0), ("10.0.0.3".into(), 0)],
            );
        }
    }

    #[test]
    fn selection_deduplicates_addresses_with_different_interface_speeds() {
        let addresses =
            [("10.0.0.1", 1000), ("10.0.0.2", 500), ("10.0.0.1", 100)].map(|(ip, speed_mbps)| {
                InterfaceAddress {
                    name: "eth0".into(),
                    ip: ip.parse().unwrap(),
                    speed_mbps,
                }
            });
        assert_eq!(
            advertised_addrs(addresses, None, BoundFamilies { v4: true, v6: true }),
            vec![("10.0.0.1".into(), 1000), ("10.0.0.2".into(), 500)]
        );
    }
}

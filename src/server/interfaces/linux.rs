//! Linux enumeration without running an external program: IPv4 addresses come
//! from getifaddrs(3), and IPv6 addresses from /proc/net/if_inet6, which also
//! carries each address's scope and the flags marking addresses the kernel is
//! still checking or retiring.
use super::InterfaceAddress;
use std::collections::{HashMap, HashSet};
use std::ffi::CStr;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

struct InterfaceList(*mut libc::ifaddrs);

impl InterfaceList {
    fn new() -> io::Result<Self> {
        let mut head = std::ptr::null_mut();
        // SAFETY: getifaddrs initializes head on success; this owner frees it.
        if unsafe { libc::getifaddrs(&mut head) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(head))
    }
}

impl Drop for InterfaceList {
    fn drop(&mut self) {
        // SAFETY: this is the unchanged list returned by getifaddrs, freed once.
        unsafe { libc::freeifaddrs(self.0) };
    }
}

pub(super) fn interface_addresses() -> Vec<InterfaceAddress> {
    let ipv6 = std::fs::read_to_string("/proc/net/if_inet6").unwrap_or_default();
    enumerate(&ipv6, super::iface_speed).unwrap_or_default()
}

fn enumerate(ipv6: &str, iface_speed: impl Fn(&str) -> u32) -> io::Result<Vec<InterfaceAddress>> {
    let list = InterfaceList::new()?;
    let mut up = HashSet::new();
    let mut found = Vec::new();
    let mut next = list.0;
    while !next.is_null() {
        // SAFETY: list owns every node, name and sockaddr for this traversal.
        let entry = unsafe { &*next };
        next = entry.ifa_next;
        if entry.ifa_name.is_null() || entry.ifa_flags & libc::IFF_UP as u32 == 0 {
            continue;
        }
        // SAFETY: getifaddrs supplies a NUL-terminated interface name.
        let name = unsafe { CStr::from_ptr(entry.ifa_name) }
            .to_string_lossy()
            .into_owned();
        // SAFETY: a non-null address's family identifies its concrete layout.
        if !entry.ifa_addr.is_null()
            && unsafe { (*entry.ifa_addr).sa_family } as i32 == libc::AF_INET
        {
            let address = unsafe { &*entry.ifa_addr.cast::<libc::sockaddr_in>() };
            let ip = Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes());
            found.push((name.clone(), IpAddr::V4(ip)));
        }
        up.insert(name);
    }
    found.extend(
        parse_if_inet6(ipv6)
            .into_iter()
            .filter(|(name, _)| up.contains(name))
            .map(|(name, ip)| (name, IpAddr::V6(ip))),
    );
    let mut speeds = HashMap::new();
    Ok(found
        .into_iter()
        .map(|(name, ip)| {
            let speed_mbps = *speeds
                .entry(name.clone())
                .or_insert_with(|| iface_speed(&name));
            InterfaceAddress {
                name,
                ip,
                speed_mbps,
            }
        })
        .collect())
}

/// Global IPv6 addresses that are ready for use. Each line reads
/// `address ifindex prefix scope flags name`, in hexadecimal except the name.
fn parse_if_inet6(text: &str) -> Vec<(String, Ipv6Addr)> {
    // <linux/if_addr.h>: IFA_F_DADFAILED, IFA_F_DEPRECATED, IFA_F_TENTATIVE.
    const UNREADY: u8 = 0x08 | 0x20 | 0x40;
    text.lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let [address, _, _, scope, flags, name] = fields[..] else {
                return None;
            };
            let scope = u8::from_str_radix(scope, 16).ok()?;
            let flags = u8::from_str_radix(flags, 16).ok()?;
            if scope != 0 || flags & UNREADY != 0 {
                return None;
            }
            let address = u128::from_str_radix(address, 16).ok()?;
            Some((name.to_owned(), Ipv6Addr::from(address)))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enumeration_reads_live_ipv4_loopback_without_running_ip() {
        let addresses = enumerate("", |_| 0).unwrap();
        assert!(addresses
            .iter()
            .any(|a| a.ip == IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }

    #[test]
    fn ipv6_listing_keeps_ready_global_addresses_only() {
        let listing = "\
00000000000000000000000000000001 01 80 10 80       lo
fdaa000000010a7b0000000000000002 02 70 00 80     eth0
20010db8000000000000000000000002 02 40 00 00     eth0
20010db8000000000000000000000003 02 40 00 40     eth0
20010db8000000000000000000000005 02 40 00 20     eth0
20010db8000000000000000000000006 02 40 00 08     eth0
fe800000000000009e6b00fffe4e89ad 02 40 20 80     eth0
not a line
";
        assert_eq!(
            parse_if_inet6(listing),
            vec![
                ("eth0".into(), "fdaa:0:1:a7b::2".parse().unwrap()),
                ("eth0".into(), "2001:db8::2".parse().unwrap()),
            ]
        );
    }
}

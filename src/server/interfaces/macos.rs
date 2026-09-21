//! Darwin enumeration must stay in-process: spawning while the receiver is
//! accepting SCM_RIGHTS can leak a descriptor before it becomes close-on-exec.
use super::InterfaceAddress;
use std::collections::HashMap;
use std::ffi::CStr;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;

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
    enumerate().unwrap_or_default()
}

fn enumerate() -> io::Result<Vec<InterfaceAddress>> {
    let list = InterfaceList::new()?;
    // This socket only queries address flags; it never sends network traffic.
    // Failure leaves IPv4 and the independently preserved SSH address usable.
    let ipv6 = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, None).ok();
    let mut addresses = Vec::new();
    let mut speeds = HashMap::new();
    let mut next = list.0;
    while !next.is_null() {
        // SAFETY: list owns every node, name and sockaddr for this traversal.
        let entry = unsafe { &*next };
        next = entry.ifa_next;
        if entry.ifa_name.is_null()
            || entry.ifa_addr.is_null()
            || entry.ifa_flags & libc::IFF_UP as u32 == 0
        {
            continue;
        }
        // SAFETY: getifaddrs supplies a NUL-terminated name and a sockaddr
        // whose family identifies its concrete layout.
        let name = unsafe { CStr::from_ptr(entry.ifa_name) };
        let family = unsafe { (*entry.ifa_addr).sa_family } as i32;
        let ip = match family {
            libc::AF_INET => {
                let address = unsafe { &*entry.ifa_addr.cast::<libc::sockaddr_in>() };
                IpAddr::V4(Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()))
            }
            libc::AF_INET6 => {
                let address = unsafe { &*entry.ifa_addr.cast::<libc::sockaddr_in6>() };
                if !ipv6.as_ref().is_some_and(|socket| {
                    ipv6_address_flags(socket, name, address).is_ok_and(ipv6_flags_usable)
                }) {
                    continue;
                }
                IpAddr::V6(Ipv6Addr::from(address.sin6_addr.s6_addr))
            }
            _ => continue,
        };
        let speed_mbps = *speeds
            .entry(name.to_owned())
            .or_insert_with(|| interface_speed(name));
        addresses.push(InterfaceAddress {
            name: name.to_string_lossy().into_owned(),
            ip,
            speed_mbps,
        });
    }
    Ok(addresses)
}

unsafe extern "C" {
    fn syq_macos_link_speed(name: *const libc::c_char) -> f64;
}

fn interface_speed(name: &CStr) -> u32 {
    // SAFETY: name is NUL-terminated and lives throughout the native call.
    // The bridge returns Mbps, with zero for unavailable/inactive interfaces.
    speed_mbps(unsafe { syq_macos_link_speed(name.as_ptr()) })
}

fn speed_mbps(rate: f64) -> u32 {
    if rate.is_finite() && rate > 0.0 && rate <= u32::MAX as f64 {
        rate as u32
    } else {
        0
    }
}

fn ipv6_address_flags(
    socket: &socket2::Socket,
    name: &CStr,
    address: &libc::sockaddr_in6,
) -> io::Result<i32> {
    // <netinet6/in6_var.h>: _IOWR('i', 73, struct in6_ifreq).
    // libc supplies the ABI layout but does not expose this ioctl constant.
    const REQUEST: libc::c_ulong = 0xc000_0000
        | ((std::mem::size_of::<libc::in6_ifreq>() as libc::c_ulong) << 16)
        | ((b'i' as libc::c_ulong) << 8)
        | 73;
    let bytes = name.to_bytes();
    if bytes.len() >= libc::IFNAMSIZ {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface name too long",
        ));
    }
    // SAFETY: zero initializes the C request, including name termination.
    let mut request: libc::in6_ifreq = unsafe { std::mem::zeroed() };
    for (dst, src) in request.ifr_name.iter_mut().zip(bytes) {
        *dst = *src as libc::c_char;
    }
    request.ifr_ifru.ifru_addr = *address;
    // SAFETY: request has the kernel's in6_ifreq layout; this read-only ioctl
    // replaces the address union member with the flags for that address.
    if unsafe { libc::ioctl(socket.as_raw_fd(), REQUEST, &mut request) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { request.ifr_ifru.ifru_flags6 })
}

fn ipv6_flags_usable(flags: i32) -> bool {
    // <netinet6/in6_var.h>: tentative, duplicate, detached, deprecated.
    flags & (0x0002 | 0x0004 | 0x0008 | 0x0010) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enumeration_reads_live_ipv4_loopback() {
        let addresses = enumerate().unwrap();
        assert!(addresses
            .iter()
            .any(|a| a.ip == IpAddr::V4(Ipv4Addr::LOCALHOST)));
        // IPv6 discovery intentionally degrades to an empty result if its
        // socket or address-flag query is unavailable on this host.
    }

    #[test]
    fn link_speeds_keep_fast_and_fractional_rates_without_wrapping() {
        for (rate, expected) in [
            (5.5, 5),
            (1000.0, 1000),
            (2500.0, 2500),
            (10000.0, 10000),
            (100000.0, 100000),
            (400000.0, 400000),
        ] {
            assert_eq!(speed_mbps(rate), expected);
        }
        for rate in [0.0, -1.0, f64::NAN, f64::INFINITY, u32::MAX as f64 + 1.0] {
            assert_eq!(speed_mbps(rate), 0);
        }
    }

    #[test]
    fn link_speed_is_unknown_for_loopback_and_absent_interfaces() {
        assert_eq!(interface_speed(c"lo0"), 0);
        assert_eq!(interface_speed(c"syq-no-iface"), 0);
    }

    #[test]
    fn ipv6_rejects_unready_and_retiring_addresses() {
        assert!(ipv6_flags_usable(0));
        // A temporary privacy address remains eligible once ready.
        assert!(ipv6_flags_usable(0x0080));
        for flag in [0x0002, 0x0004, 0x0008, 0x0010] {
            assert!(!ipv6_flags_usable(flag));
            assert!(!ipv6_flags_usable(flag | 0x0080));
        }
    }
}

//! Linux enumeration without running an external program. One netlink
//! RTM_GETADDR dump, the request `ip addr show` also makes, reports every
//! address with the index of the interface it belongs to, its scope, and the
//! flags that mark addresses the kernel is still checking or retiring.
use super::InterfaceAddress;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

// <linux/rtnetlink.h> and <linux/if_addr.h>.
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_FLAGS: u16 = 8;
const IFA_F_DADFAILED: u32 = 0x08;
const IFA_F_DEPRECATED: u32 = 0x20;
const IFA_F_TENTATIVE: u32 = 0x40;
const RT_SCOPE_UNIVERSE: u8 = 0;
const HEADER: usize = 16; // struct nlmsghdr
const ADDRESS_MESSAGE: usize = 8; // struct ifaddrmsg

pub(super) fn interface_addresses() -> Vec<InterfaceAddress> {
    let Ok(addresses) = dump_addresses() else {
        return Vec::new();
    };
    let mut names = HashMap::new();
    let mut speeds = HashMap::new();
    addresses
        .into_iter()
        .filter_map(|(index, ip)| {
            // An alias label such as eth0:1 is not an interface; the index
            // names the device whose speed and kind apply to the address.
            let name = names
                .entry(index)
                .or_insert_with(|| interface_name(index))
                .clone()?;
            let speed_mbps = *speeds
                .entry(index)
                .or_insert_with(|| super::iface_speed(&name));
            Some(InterfaceAddress {
                name,
                ip,
                speed_mbps,
            })
        })
        .collect()
}

fn interface_name(index: u32) -> Option<String> {
    let mut name = [0 as libc::c_char; libc::IF_NAMESIZE];
    // SAFETY: the buffer has the IF_NAMESIZE bytes if_indextoname requires,
    // and a non-null result is NUL-terminated within it.
    if unsafe { libc::if_indextoname(index, name.as_mut_ptr()) }.is_null() {
        return None;
    }
    let name = unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) };
    Some(name.to_string_lossy().into_owned())
}

/// Global, ready addresses with their interface indexes.
fn dump_addresses() -> io::Result<Vec<(u32, IpAddr)>> {
    // SAFETY: plain socket creation; the descriptor is owned immediately.
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    // The kernel answers a dump at once; the timeout only guards a stuck read.
    let timeout = libc::timeval {
        tv_sec: 1,
        tv_usec: 0,
    };
    // SAFETY: timeval is the option's documented type and size.
    unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&timeout as *const libc::timeval).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    let mut request = [0u8; HEADER + ADDRESS_MESSAGE];
    request[0..4].copy_from_slice(&((HEADER + ADDRESS_MESSAGE) as u32).to_ne_bytes());
    request[4..6].copy_from_slice(&libc::RTM_GETADDR.to_ne_bytes());
    let flags = (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16;
    request[6..8].copy_from_slice(&flags.to_ne_bytes());
    request[8..12].copy_from_slice(&1u32.to_ne_bytes());
    request[HEADER] = libc::AF_UNSPEC as u8;
    // SAFETY: request is a complete netlink message; the kernel is the peer.
    if unsafe {
        libc::send(
            socket.as_raw_fd(),
            request.as_ptr().cast(),
            request.len(),
            0,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut addresses = Vec::new();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        // SAFETY: buffer is writable for its full length.
        let received = unsafe {
            libc::recv(
                socket.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                0,
            )
        };
        if received < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if parse_messages(&buffer[..received as usize], &mut addresses)? {
            return Ok(addresses);
        }
    }
}

/// Parse one datagram of the dump. Returns true once the dump is complete.
fn parse_messages(mut data: &[u8], addresses: &mut Vec<(u32, IpAddr)>) -> io::Result<bool> {
    let malformed = || io::Error::new(io::ErrorKind::InvalidData, "malformed netlink reply");
    while data.len() >= HEADER {
        let length = u32::from_ne_bytes(data[0..4].try_into().unwrap()) as usize;
        let kind = u16::from_ne_bytes(data[4..6].try_into().unwrap());
        if length < HEADER || length > data.len() {
            return Err(malformed());
        }
        match kind {
            k if k == libc::NLMSG_DONE as u16 => return Ok(true),
            k if k == libc::NLMSG_ERROR as u16 => {
                let code = data
                    .get(HEADER..HEADER + 4)
                    .map(|b| i32::from_ne_bytes(b.try_into().unwrap()))
                    .ok_or_else(malformed)?;
                return Err(io::Error::from_raw_os_error(-code));
            }
            k if k == libc::RTM_NEWADDR => {
                if let Some(address) = parse_address(&data[HEADER..length]) {
                    addresses.push(address);
                }
            }
            _ => {}
        }
        data = &data[align(length).min(data.len())..];
    }
    Ok(false)
}

fn parse_address(message: &[u8]) -> Option<(u32, IpAddr)> {
    let header = message.get(..ADDRESS_MESSAGE)?;
    let family = i32::from(header[0]);
    let mut flags = u32::from(header[2]);
    let scope = header[3];
    let index = u32::from_ne_bytes(header[4..8].try_into().unwrap());
    let (mut local, mut address) = (None, None);
    let mut attributes = &message[ADDRESS_MESSAGE..];
    while attributes.len() >= 4 {
        let length = usize::from(u16::from_ne_bytes(attributes[0..2].try_into().unwrap()));
        let kind = u16::from_ne_bytes(attributes[2..4].try_into().unwrap());
        if length < 4 || length > attributes.len() {
            break;
        }
        let value = &attributes[4..length];
        match kind {
            IFA_LOCAL => local = Some(value),
            IFA_ADDRESS => address = Some(value),
            // The 32-bit field supersedes the 8-bit header flags when present.
            IFA_FLAGS if value.len() == 4 => flags = u32::from_ne_bytes(value.try_into().unwrap()),
            _ => {}
        }
        attributes = &attributes[align(length).min(attributes.len())..];
    }
    if scope != RT_SCOPE_UNIVERSE
        || flags & (IFA_F_DADFAILED | IFA_F_DEPRECATED | IFA_F_TENTATIVE) != 0
    {
        return None;
    }
    // On point-to-point links IFA_ADDRESS is the peer; IFA_LOCAL is ours.
    let bytes = local.or(address)?;
    let ip = match family {
        libc::AF_INET => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(bytes).ok()?)),
        libc::AF_INET6 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(bytes).ok()?)),
        _ => return None,
    };
    Some((index, ip))
}

fn align(length: usize) -> usize {
    (length + 3) & !3
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attribute(kind: u16, value: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&((4 + value.len()) as u16).to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(value);
        bytes.resize(align(bytes.len()), 0);
        bytes
    }

    fn message(kind: u16, body: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&((HEADER + body.len()) as u32).to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(&[0; 10]);
        bytes.extend_from_slice(body);
        bytes.resize(align(bytes.len()), 0);
        bytes
    }

    fn address(family: i32, flags: u8, scope: u8, index: u32, attributes: &[Vec<u8>]) -> Vec<u8> {
        let mut body = vec![family as u8, 24, flags, scope];
        body.extend_from_slice(&index.to_ne_bytes());
        for attribute in attributes {
            body.extend_from_slice(attribute);
        }
        message(libc::RTM_NEWADDR, &body)
    }

    #[test]
    fn dump_keeps_ready_global_addresses_with_their_interface_index() {
        let v4 = |octets: [u8; 4]| attribute(IFA_LOCAL, &octets);
        let v6 = |ip: &str| attribute(IFA_ADDRESS, &ip.parse::<Ipv6Addr>().unwrap().octets());
        let mut reply = Vec::new();
        // An eth0:1 alias still reports eth0's index; its label is ignored.
        reply.extend(address(
            libc::AF_INET,
            0,
            0,
            2,
            &[v4([10, 0, 0, 1]), attribute(3, b"eth0:1\0")],
        ));
        reply.extend(address(libc::AF_INET, 0, 254, 1, &[v4([127, 0, 0, 1])])); // host scope
        reply.extend(address(
            libc::AF_INET,
            0,
            0,
            2,
            &[
                v4([10, 0, 0, 2]),
                attribute(IFA_FLAGS, &IFA_F_DEPRECATED.to_ne_bytes()),
            ],
        ));
        reply.extend(address(libc::AF_INET, 0x40, 0, 2, &[v4([10, 0, 0, 3])])); // tentative
                                                                                // Point-to-point: IFA_ADDRESS is the peer, IFA_LOCAL our address.
        reply.extend(address(
            libc::AF_INET,
            0,
            0,
            4,
            &[attribute(IFA_ADDRESS, &[192, 0, 2, 9]), v4([192, 0, 2, 1])],
        ));
        reply.extend(address(libc::AF_INET6, 0, 0, 2, &[v6("2001:db8::2")]));
        reply.extend(address(libc::AF_INET6, 0, 253, 2, &[v6("fe80::1")])); // link scope
        reply.extend(address(libc::AF_INET6, 0x08, 0, 2, &[v6("2001:db8::6")])); // DAD failed
        reply.extend(message(libc::NLMSG_DONE as u16, &[0; 4]));
        let mut addresses = Vec::new();
        assert!(parse_messages(&reply, &mut addresses).unwrap());
        assert_eq!(
            addresses,
            vec![
                (2, "10.0.0.1".parse().unwrap()),
                (4, "192.0.2.1".parse().unwrap()),
                (2, "2001:db8::2".parse().unwrap()),
            ]
        );
    }

    #[test]
    fn dump_errors_and_truncation_are_reported() {
        let mut reply = message(libc::NLMSG_ERROR as u16, &(-libc::EPERM).to_ne_bytes());
        assert_eq!(
            parse_messages(&reply, &mut Vec::new())
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EPERM)
        );
        reply = message(libc::RTM_NEWADDR, &[0; 8]);
        reply.truncate(HEADER + 2);
        reply[0..4].copy_from_slice(&64u32.to_ne_bytes());
        assert!(parse_messages(&reply, &mut Vec::new()).is_err());
    }

    #[test]
    fn interface_indexes_resolve_to_names_and_live_dump_succeeds() {
        // Loopback has host scope, so the dump skips it; check name
        // resolution through its fixed index instead.
        assert_eq!(interface_name(1).as_deref(), Some("lo"));
        dump_addresses().unwrap();
    }
}

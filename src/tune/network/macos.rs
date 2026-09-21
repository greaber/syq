use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// Use the same read-only route sysctl as Apple's arp/ndp tools. Darwin route
// sockaddrs have four-byte alignment, including on 64-bit hosts.
pub(super) fn routers() -> Option<Vec<[u8; 6]>> {
    let mut mib = [
        libc::CTL_NET,
        libc::PF_ROUTE,
        0,
        libc::AF_UNSPEC,
        libc::NET_RT_DUMP,
        0,
    ];
    for _ in 0..2 {
        let mut size = 0;
        // SAFETY: mib and size are valid for this read-only size query.
        if unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                6,
                std::ptr::null_mut(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        } != 0
        {
            return None;
        }
        if size > 4 * 1024 * 1024 {
            return None;
        }
        let mut bytes = vec![0u8; size];
        // SAFETY: the buffer has size writable bytes; no new value is supplied.
        if unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                6,
                bytes.as_mut_ptr().cast(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        } == 0
        {
            bytes.truncate(size);
            return parse(&bytes);
        }
        // A changing table may outgrow the first allocation. Retry once.
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOMEM) {
            return None;
        }
    }
    None
}

fn ip(address: &[u8]) -> Option<IpAddr> {
    match i32::from(*address.get(1)?) {
        libc::AF_INET => Some(Ipv4Addr::from(<[u8; 4]>::try_from(address.get(4..8)?).ok()?).into()),
        libc::AF_INET6 => {
            let mut bytes: [u8; 16] = address.get(8..24)?.try_into().ok()?;
            // Darwin can embed the interface scope in a link-local address.
            // The route's interface index already supplies that scope below.
            if bytes[0] == 0xfe && bytes[1] & 0xc0 == 0x80 {
                bytes[2] = 0;
                bytes[3] = 0;
            }
            Some(Ipv6Addr::from(bytes).into())
        }
        _ => None,
    }
}

fn parse(mut bytes: &[u8]) -> Option<Vec<[u8; 6]>> {
    let mut gateways = Vec::new();
    let mut neighbors = BTreeMap::new();
    let header_size = std::mem::size_of::<libc::rt_msghdr>();
    while !bytes.is_empty() {
        if bytes.len() < header_size {
            return None;
        }
        // SAFETY: length checked; rt_msghdr contains integers only. Kernel
        // messages are not assumed to have Rust allocation alignment.
        let header = unsafe { bytes.as_ptr().cast::<libc::rt_msghdr>().read_unaligned() };
        let len = usize::from(header.rtm_msglen);
        if len < header_size || len > bytes.len() {
            return None;
        }
        let (message, rest) = bytes.split_at(len);
        bytes = rest;
        let mut addresses = &message[header_size..];
        let mut slots = [None; libc::RTAX_MAX as usize];
        for (index, slot) in slots.iter_mut().enumerate() {
            if header.rtm_addrs & (1 << index) == 0 {
                continue;
            }
            let len = usize::from(*addresses.first()?);
            let padded = len.max(1).div_ceil(4) * 4;
            *slot = Some(addresses.get(..len)?);
            addresses = addresses.get(padded..)?;
        }
        if header.rtm_flags & libc::RTF_UP == 0 {
            continue;
        }
        let Some(destination) = slots[libc::RTAX_DST as usize].and_then(ip) else {
            continue;
        };
        let Some(gateway) = slots[libc::RTAX_GATEWAY as usize] else {
            continue;
        };
        let mask_is_zero = slots[libc::RTAX_NETMASK as usize]
            .is_none_or(|mask| mask.iter().skip(2).all(|&b| b == 0));
        if destination.is_unspecified() && mask_is_zero && header.rtm_flags & libc::RTF_GATEWAY != 0
        {
            if let Some(gateway) = ip(gateway) {
                gateways.push((header.rtm_index, gateway));
            }
        }
        if header.rtm_flags & libc::RTF_LLINFO != 0
            && gateway.get(1) == Some(&(libc::AF_LINK as u8))
        {
            let Some((&name_len, &addr_len)) = gateway.get(5).zip(gateway.get(6)) else {
                continue;
            };
            if addr_len == 6 {
                let start = 8 + usize::from(name_len);
                if let Some(mac) = gateway
                    .get(start..start + 6)
                    .and_then(|b| <[u8; 6]>::try_from(b).ok())
                {
                    neighbors.insert((header.rtm_index, destination), mac);
                }
            }
        }
    }
    Some(
        gateways
            .into_iter()
            .filter_map(|key| neighbors.get(&key).copied())
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires a live Mac with a resolved default router"]
    fn native_router_fingerprint() {
        ipv4_ipv6_and_interface_scoped_neighbors();
        malformed_route_messages_are_rejected();
        let routers = routers().expect("read Darwin route table");
        assert!(
            super::super::fingerprint_routers(routers).is_some(),
            "no resolved default-router hardware address"
        );
    }

    fn route(index: u16, flags: i32, destination: &[u8], gateway: &[u8]) -> Vec<u8> {
        let mut message = vec![0; std::mem::size_of::<libc::rt_msghdr>()];
        for address in [destination, gateway] {
            message.extend_from_slice(address);
            message.resize(message.len().div_ceil(4) * 4, 0);
        }
        let length = message.len() as u16;
        let offset = std::mem::offset_of!(libc::rt_msghdr, rtm_msglen);
        message[offset..offset + 2].copy_from_slice(&length.to_ne_bytes());
        let offset = std::mem::offset_of!(libc::rt_msghdr, rtm_index);
        message[offset..offset + 2].copy_from_slice(&index.to_ne_bytes());
        let offset = std::mem::offset_of!(libc::rt_msghdr, rtm_flags);
        message[offset..offset + 4].copy_from_slice(&flags.to_ne_bytes());
        let offset = std::mem::offset_of!(libc::rt_msghdr, rtm_addrs);
        message[offset..offset + 4]
            .copy_from_slice(&(libc::RTA_DST | libc::RTA_GATEWAY).to_ne_bytes());
        message
    }

    #[test]
    fn ipv4_ipv6_and_interface_scoped_neighbors() {
        let mut zero4 = [0u8; 16];
        zero4[0] = 16;
        zero4[1] = libc::AF_INET as u8;
        let mut gw4 = zero4;
        gw4[4..8].copy_from_slice(&[192, 0, 2, 1]);
        let mut zero6 = [0u8; 28];
        zero6[0] = 28;
        zero6[1] = libc::AF_INET6 as u8;
        let mut gw6 = zero6;
        gw6[8..12].copy_from_slice(&[0xfe, 0x80, 0, 7]);
        gw6[23] = 1;
        let link = [
            17,
            libc::AF_LINK as u8,
            0,
            0,
            6,
            3,
            6,
            0,
            b'e',
            b'n',
            b'0',
            2,
            0,
            0,
            0,
            0,
            1,
        ];
        let up = libc::RTF_UP;
        let mut dump = route(7, up | libc::RTF_GATEWAY, &zero4, &gw4);
        dump.extend(route(7, up | libc::RTF_GATEWAY, &zero6, &gw6));
        dump.extend(route(8, up | libc::RTF_LLINFO, &gw4, &link));
        assert_eq!(parse(&dump), Some(vec![])); // wrong interface
        dump.extend(route(7, up | libc::RTF_LLINFO, &gw4, &link));
        gw6[10..12].fill(0); // equivalent IPv6 scope representation
        dump.extend(route(7, up | libc::RTF_LLINFO, &gw6, &link));
        assert_eq!(parse(&dump), Some(vec![[2, 0, 0, 0, 0, 1]; 2]));
        for length in 1..std::mem::size_of::<libc::rt_msghdr>() {
            assert!(parse(&dump[..length]).is_none());
        }
    }

    #[test]
    fn malformed_route_messages_are_rejected() {
        assert!(parse(&[0; 3]).is_none());
        assert!(parse(&vec![0; std::mem::size_of::<libc::rt_msghdr>()]).is_none());
        assert_eq!(parse(&[]), Some(vec![]));
    }
}

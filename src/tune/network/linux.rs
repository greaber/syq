// IPv4 router and neighbor tables are readable without opening sockets or
// starting subprocesses. IPv6-only hosts currently have unknown context here.
pub(super) fn routers() -> Option<Vec<[u8; 6]>> {
    let routes = std::fs::read_to_string("/proc/net/route").ok()?;
    let neighbors = std::fs::read_to_string("/proc/net/arp").ok()?;
    Some(parse(&routes, &neighbors))
}

fn parse(routes: &str, neighbors: &str) -> Vec<[u8; 6]> {
    let mut result = Vec::new();
    for route in routes.lines().skip(1) {
        let fields: Vec<_> = route.split_whitespace().collect();
        if fields.len() < 8 || fields[1] != "00000000" || fields[7] != "00000000" {
            continue;
        }
        let Some(flags) = u32::from_str_radix(fields[3], 16).ok() else {
            continue;
        };
        if flags & 3 != 3 {
            continue;
        } // RTF_UP | RTF_GATEWAY
        let Some(gateway) = u32::from_str_radix(fields[2], 16).ok() else {
            continue;
        };
        let gateway = std::net::Ipv4Addr::from(gateway.to_ne_bytes()).to_string();
        for neighbor in neighbors.lines().skip(1) {
            let entry: Vec<_> = neighbor.split_whitespace().collect();
            if entry.len() < 6 || entry[0] != gateway || entry[5] != fields[0] {
                continue;
            }
            let flags = u32::from_str_radix(entry[2].trim_start_matches("0x"), 16).unwrap_or(0);
            if flags & 2 == 0 {
                continue;
            } // ATF_COM: resolved hardware address
            let bytes: Option<Vec<u8>> = entry[3]
                .split(':')
                .map(|s| u8::from_str_radix(s, 16).ok())
                .collect();
            if let Some(mac) = bytes.and_then(|v| v.try_into().ok()) {
                result.push(mac);
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_resolved_default_router_on_matching_interface_is_used() {
        // /proc/net/route prints native-endian IPv4 addresses as hex.
        let gateway = u32::from_ne_bytes([192, 0, 2, 1]);
        let routes = format!("Iface Destination Gateway Flags RefCnt Use Metric Mask\nwlan0 00000000 {gateway:08X} 0003 0 0 100 00000000\nwlan1 00000000 {gateway:08X} 0002 0 0 100 00000000\n");
        let arp = "IP address HW type Flags HW address Mask Device\n192.0.2.1 0x1 0x2 02:00:00:00:00:01 * wlan0\n192.0.2.1 0x1 0x2 02:00:00:00:00:02 * wlan1\n192.0.2.2 0x1 0x2 02:00:00:00:00:03 * wlan0\n";
        assert_eq!(parse(&routes, arp), vec![[2, 0, 0, 0, 0, 1]]);
        assert!(parse(&routes, &arp.replace("0x2", "0x0")).is_empty());
    }
}

//! Best-effort local network context for remote-copy starting hints.
//!
//! Default-router hardware addresses distinguish familiar networks without
//! querying SSIDs, requesting location access, or probing an external service.
//! This is host network context, not an assertion about the route to a peer:
//! VPNs, multiple interfaces, and changes upstream of a hotspot remain possible.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

pub(super) fn fingerprint() -> Option<String> {
    // Integration tests simulate reconnecting on another network without
    // modifying the host's routing table. Release builds always read the OS.
    #[cfg(debug_assertions)]
    if let Some(value) = std::env::var_os("SYQ_TEST_TUNING_NETWORK") {
        return value.into_string().ok().filter(|v| !v.is_empty());
    }
    #[cfg(target_os = "linux")]
    let routers = linux::routers()?;
    #[cfg(target_os = "macos")]
    let routers = macos::routers()?;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let routers = Vec::new();
    fingerprint_routers(routers)
}

fn fingerprint_routers(mut routers: Vec<[u8; 6]>) -> Option<String> {
    routers.retain(|mac| mac[0] & 1 == 0 && *mac != [0; 6]);
    routers.sort_unstable();
    routers.dedup();
    if routers.is_empty() {
        return None;
    }
    let mut hash = blake3::Hasher::new_derive_key("syq tuning network context v1");
    for router in routers {
        hash.update(&router);
    }
    Some(hash.finalize().to_hex().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn router_identity_is_stable_and_distinguishes_networks() {
        let home = [2, 0, 0, 0, 0, 1];
        let office = [2, 0, 0, 0, 0, 2];
        assert_ne!(
            fingerprint_routers(vec![home]),
            fingerprint_routers(vec![office])
        );
        assert_eq!(
            fingerprint_routers(vec![home, office]),
            fingerprint_routers(vec![office, home, home])
        );
        assert_eq!(fingerprint_routers(vec![]), None);
        assert_eq!(fingerprint_routers(vec![[0; 6], [255; 6]]), None);
    }
}

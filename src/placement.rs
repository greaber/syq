//! Compact metadata work and socket-local bulk data, within inherited CPU limits.

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::Path;

    const COMPACT_CORES: usize = 16;

    pub struct Mask(libc::cpu_set_t);

    impl Mask {
        fn current() -> Option<Self> {
            // SAFETY: cpu_set_t is a plain bit set; the kernel receives its
            // exact size and a writable pointer. Zero means this thread only.
            let mut mask = unsafe { std::mem::zeroed::<libc::cpu_set_t>() };
            (unsafe { libc::sched_getaffinity(0, std::mem::size_of_val(&mask), &mut mask) } == 0)
                .then_some(Self(mask))
        }

        fn contains(&self, cpu: usize) -> bool {
            cpu < libc::CPU_SETSIZE as usize && unsafe { libc::CPU_ISSET(cpu, &self.0) }
        }

        fn from_cpus(cpus: impl IntoIterator<Item = usize>) -> Option<Self> {
            // SAFETY: zero initializes an empty cpu_set_t; every index is
            // checked before using libc's CPU_SET accessor.
            let mut mask = unsafe { std::mem::zeroed::<libc::cpu_set_t>() };
            let mut any = false;
            for cpu in cpus {
                if cpu >= libc::CPU_SETSIZE as usize {
                    return None;
                }
                unsafe { libc::CPU_SET(cpu, &mut mask) };
                any = true;
            }
            any.then_some(Self(mask))
        }

        /// Only dedicated pool threads call this. Intersect again at thread
        /// entry so placement never expands an inherited CPU allocation.
        /// A denied or unsupported affinity operation leaves scheduling alone.
        pub fn apply(&self) -> bool {
            let Some(current) = Self::current() else {
                return false;
            };
            let Some(mask) = Self::from_cpus(
                (0..libc::CPU_SETSIZE as usize)
                    .filter(|&cpu| self.contains(cpu) && current.contains(cpu)),
            ) else {
                return false;
            };
            // SAFETY: mask is a valid nonempty cpu_set_t with the exact size.
            unsafe { libc::sched_setaffinity(0, std::mem::size_of_val(&mask.0), &mask.0) == 0 }
        }
    }

    impl Mask {
        fn intersect(&self, other: &Self) -> Option<Self> {
            Self::from_cpus(
                (0..libc::CPU_SETSIZE as usize)
                    .filter(|&cpu| self.contains(cpu) && other.contains(cpu)),
            )
        }
        fn set(&self) -> bool {
            // SAFETY: this is an initialized cpu_set_t and only addresses the
            // calling thread; the kernel enforces current cpuset restrictions.
            unsafe { libc::sched_setaffinity(0, std::mem::size_of_val(&self.0), &self.0) == 0 }
        }
    }

    /// Lazily resolve interface locality only when a connection carries bulk
    /// data. Small-file batches keep the scheduler's original CPU allocation.
    pub struct BulkPlacement {
        addresses: Vec<std::net::IpAddr>,
        initialized: bool,
        original: Option<Mask>,
        target: Option<Mask>,
        active: bool,
        _thread: std::marker::PhantomData<std::rc::Rc<()>>,
    }

    impl BulkPlacement {
        pub fn new(addresses: Vec<std::net::IpAddr>) -> Self {
            Self {
                addresses,
                initialized: false,
                original: None,
                target: None,
                active: false,
                _thread: std::marker::PhantomData,
            }
        }
        fn initialize(&mut self) {
            self.initialized = true;
            let addresses = std::mem::take(&mut self.addresses);
            if addresses.is_empty() {
                return;
            }
            let Some(original) = Mask::current() else {
                return;
            };
            let mut masks = addresses.iter().filter_map(|address| for_address(*address));
            let Some(mut target) = masks.next() else {
                return;
            };
            for other in masks {
                let Some(shared) = target.intersect(&other) else {
                    return;
                };
                target = shared;
            }
            self.target = target.intersect(&original);
            self.original = Some(original);
        }
        pub fn set_bulk(&mut self, bulk: bool) {
            if bulk && !self.initialized {
                self.initialize();
            }
            if bulk == self.active {
                return;
            }
            let mask = if bulk { &self.target } else { &self.original };
            if let Some(mask) = mask {
                if mask.set() {
                    self.active = bulk;
                } else if bulk {
                    // Affinity can be denied in containers. Do not retry a
                    // failed optimization for every block of a large file.
                    self.target = None;
                }
            }
        }
    }
    impl Drop for BulkPlacement {
        fn drop(&mut self) {
            if self.active {
                if let Some(mask) = &self.original {
                    mask.set();
                }
            }
        }
    }

    fn for_address(address: std::net::IpAddr) -> Option<Mask> {
        if address.is_loopback() {
            return None;
        }
        let mut first = std::ptr::null_mut();
        // SAFETY: getifaddrs initializes an owned linked list, held until the
        // Interfaces guard drops. Its family tags govern the address casts.
        if unsafe { libc::getifaddrs(&mut first) } != 0 {
            return None;
        }
        struct Interfaces(*mut libc::ifaddrs);
        impl Drop for Interfaces {
            fn drop(&mut self) {
                unsafe { libc::freeifaddrs(self.0) };
            }
        }
        let _interfaces = Interfaces(first);
        let mut entry = first;
        while !entry.is_null() {
            let item = unsafe { &*entry };
            entry = item.ifa_next;
            if item.ifa_addr.is_null() || item.ifa_name.is_null() {
                continue;
            }
            let ip = match unsafe { (*item.ifa_addr).sa_family as i32 } {
                libc::AF_INET => {
                    let a = unsafe { &*item.ifa_addr.cast::<libc::sockaddr_in>() };
                    std::net::IpAddr::V4(std::net::Ipv4Addr::from(a.sin_addr.s_addr.to_ne_bytes()))
                }
                libc::AF_INET6 => {
                    let a = unsafe { &*item.ifa_addr.cast::<libc::sockaddr_in6>() };
                    std::net::IpAddr::V6(std::net::Ipv6Addr::from(a.sin6_addr.s6_addr))
                }
                _ => continue,
            };
            if ip != address {
                continue;
            }
            let name = unsafe { std::ffi::CStr::from_ptr(item.ifa_name) }
                .to_str()
                .ok()?;
            let node = std::fs::read_to_string(format!("/sys/class/net/{name}/device/numa_node"))
                .ok()?
                .trim()
                .parse::<u32>()
                .ok()?;
            let cpus =
                std::fs::read_to_string(format!("/sys/devices/system/node/node{node}/cpulist"))
                    .ok()?;
            return parse_cpulist(&cpus)?.intersect(&Mask::current()?);
        }
        None
    }

    fn parse_cpulist(list: &str) -> Option<Mask> {
        let mut cpus = Vec::new();
        for part in list.trim().split(',') {
            let (start, end) = part.split_once('-').unwrap_or((part, part));
            let start = start.parse::<usize>().ok()?;
            let end = end.parse::<usize>().ok()?;
            if end >= libc::CPU_SETSIZE as usize || start > end {
                return None;
            }
            cpus.extend(start..=end);
        }
        Mask::from_cpus(cpus)
    }

    struct Core {
        cpu: usize,
        package: i32,
        core: i32,
        node: Option<usize>,
    }

    fn select(cores: &[Core], seed: usize, preferred: Option<usize>) -> Option<Mask> {
        let mut groups: BTreeMap<_, BTreeMap<_, usize>> = BTreeMap::new();
        for core in cores {
            if core.package < 0 || core.core < 0 {
                return None;
            }
            groups
                .entry((core.package, core.node))
                .or_default()
                .entry(core.core)
                .and_modify(|cpu| *cpu = (*cpu).min(core.cpu))
                .or_insert(core.cpu);
        }
        let largest = groups.values().map(|cores| cores.len()).max()?;
        // Keep the scheduler's freedom on small CPU allocations. On larger
        // hosts retain metadata I/O concurrency while limiting migration and
        // avoiding contention between sibling hardware threads.
        if largest < COMPACT_CORES {
            return None;
        }
        let candidates: Vec<_> = groups
            .values()
            .filter(|cores| cores.len() == largest)
            .collect();
        let nearby = preferred
            .and_then(|cpu| cores.iter().find(|core| core.cpu == cpu))
            .and_then(|core| groups.get(&(core.package, core.node)))
            .filter(|cores| cores.len() >= COMPACT_CORES);
        let cores = nearby.unwrap_or(candidates[seed % candidates.len()]);
        let cpus: BTreeSet<_> = cores.values().copied().collect();
        // Spread independent processes instead of always choosing node/core 0.
        Mask::from_cpus(
            cpus.iter()
                .copied()
                .cycle()
                .skip(seed % cpus.len())
                .take(COMPACT_CORES),
        )
    }

    pub fn compact() -> Option<(usize, Mask)> {
        let allowed = Mask::current()?;
        let mut cores = Vec::new();
        for cpu in 0..libc::CPU_SETSIZE as usize {
            if !allowed.contains(cpu) {
                continue;
            }
            let path = Path::new("/sys/devices/system/cpu").join(format!("cpu{cpu}"));
            let number = |name| {
                std::fs::read_to_string(path.join("topology").join(name))
                    .ok()?
                    .trim()
                    .parse::<i32>()
                    .ok()
            };
            let package = number("physical_package_id")?;
            let core = number("core_id")?;
            let node = std::fs::read_dir(&path)
                .ok()?
                .filter_map(Result::ok)
                .find_map(|entry| {
                    entry
                        .file_name()
                        .to_str()?
                        .strip_prefix("node")?
                        .parse()
                        .ok()
                });
            cores.push(Core {
                cpu,
                package,
                core,
                node,
            });
        }
        // The initiating thread has already allocated request and metadata
        // state. Prefer its node instead of moving that work across sockets.
        let current = unsafe { libc::sched_getcpu() };
        select(
            &cores,
            std::process::id() as usize,
            usize::try_from(current).ok(),
        )
        .map(|mask| (COMPACT_CORES, mask))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn cpus(mask: &Mask) -> Vec<usize> {
            (0..libc::CPU_SETSIZE as usize)
                .filter(|&cpu| mask.contains(cpu))
                .collect()
        }

        fn topology() -> Vec<Core> {
            (0..128)
                .map(|cpu| Core {
                    cpu,
                    package: (cpu % 64 / 32) as i32,
                    core: (cpu % 32) as i32,
                    node: Some(cpu % 64 / 32),
                })
                .collect()
        }

        #[test]
        fn node_cpu_lists_validate_ranges_before_building_a_mask() {
            assert_eq!(
                cpus(&parse_cpulist("1-3,7,9-10\n").unwrap()),
                vec![1, 2, 3, 7, 9, 10]
            );
            for bad in ["", "-1", "2-1", "0-1024", "x", "1,", "1-2-3"] {
                assert!(parse_cpulist(bad).is_none(), "{bad}");
            }
        }

        #[test]
        fn bulk_placement_restores_affinity_for_small_work_and_on_drop() {
            std::thread::spawn(|| {
                let original = Mask::current().unwrap();
                let before = cpus(&original);
                let first = before[0];
                let mut placement = BulkPlacement::new(Vec::new());
                placement.initialized = true;
                placement.original = Some(original);
                placement.target = Mask::from_cpus([first]);
                placement.set_bulk(true);
                assert_eq!(cpus(&Mask::current().unwrap()), vec![first]);
                // Non-payload acknowledgements do not churn the affinity mask.
                placement.response(&crate::proto::Response::Ok);
                assert!(placement.active);
                placement.request(&crate::proto::Request::ReadSmallBatch(Vec::new()));
                assert_eq!(cpus(&Mask::current().unwrap()), before);
                placement.set_bulk(true);
                placement.response(&crate::proto::Response::SmallBlocks(Vec::new()));
                assert_eq!(cpus(&Mask::current().unwrap()), before);
                placement.set_bulk(true);
                drop(placement);
                assert_eq!(cpus(&Mask::current().unwrap()), before);
            })
            .join()
            .unwrap();
        }

        #[test]
        fn small_work_does_not_resolve_interface_locality() {
            let mut placement = BulkPlacement::new(vec![std::net::Ipv4Addr::LOCALHOST.into()]);
            placement.request(&crate::proto::Request::ReadSmallBatch(Vec::new()));
            placement.response(&crate::proto::Response::SmallBlocks(Vec::new()));
            assert!(!placement.initialized);
            placement.set_bulk(true);
            assert!(placement.initialized);
            assert!(!placement.active);
        }

        #[test]
        fn incompatible_endpoint_nodes_do_not_share_a_cpu_mask() {
            assert!(Mask::from_cpus([0, 2])
                .unwrap()
                .intersect(&Mask::from_cpus([1, 3]).unwrap())
                .is_none());
            assert_eq!(
                cpus(
                    &Mask::from_cpus([0, 2])
                        .unwrap()
                        .intersect(&Mask::from_cpus([2, 3]).unwrap())
                        .unwrap()
                ),
                vec![2]
            );
        }

        #[test]
        fn compact_uses_distinct_cores_in_one_locality() {
            let topology = topology();
            for seed in 0..128 {
                let chosen = cpus(&select(&topology, seed, None).unwrap());
                assert_eq!(chosen.len(), COMPACT_CORES);
                assert!(chosen.iter().all(|&cpu| cpu < 64));
                assert!(chosen.iter().all(|&cpu| cpu / 32 == chosen[0] / 32));
            }
            assert_ne!(
                cpus(&select(&topology, 0, None).unwrap()),
                cpus(&select(&topology, 1, None).unwrap())
            );
        }

        #[test]
        fn compact_prefers_the_initiating_threads_node() {
            let cores = topology();
            for cpu in 0..128 {
                let chosen = cpus(&select(&cores, 0, Some(cpu)).unwrap());
                assert!(chosen.iter().all(|chosen| chosen / 32 == cpu % 64 / 32));
            }
        }

        #[test]
        fn compact_respects_sparse_allocations_and_smt_only_allocations() {
            let cores: Vec<_> = topology()
                .into_iter()
                .filter(|core| core.cpu >= 64 && core.cpu % 2 == 0)
                .collect();
            for seed in 0..64 {
                let chosen = cpus(&select(&cores, seed, None).unwrap());
                assert_eq!(chosen.len(), COMPACT_CORES);
                assert!(chosen
                    .iter()
                    .all(|cpu| cores.iter().any(|core| core.cpu == *cpu)));
            }
            assert!(select(&cores[..15], 0, None).is_none());
            assert!(select(&[], 0, None).is_none());
        }

        #[test]
        fn compact_supports_single_socket_and_missing_numa_topology() {
            let mut cores = topology();
            cores.retain(|core| core.package == 0);
            for core in &mut cores {
                core.node = None;
            }
            assert_eq!(cpus(&select(&cores, 4, None).unwrap()).len(), COMPACT_CORES);
            cores[0].core = -1;
            assert!(select(&cores, 0, None).is_none());
        }

        #[test]
        fn placement_does_not_change_caller_or_widen_worker_affinity() {
            let before = cpus(&Mask::current().unwrap());
            let first = before[0];
            let worker = std::thread::spawn(move || {
                assert!(Mask::from_cpus([first]).unwrap().apply());
                assert_eq!(cpus(&Mask::current().unwrap()), vec![first]);
                assert!(compact().is_none());
                // A later broader preference must not expand that allocation.
                assert!(Mask::from_cpus(0..libc::CPU_SETSIZE as usize)
                    .unwrap()
                    .apply());
                assert_eq!(cpus(&Mask::current().unwrap()), vec![first]);
                assert!(!Mask::from_cpus(
                    (0..libc::CPU_SETSIZE as usize).filter(|&cpu| cpu != first)
                )
                .unwrap()
                .apply());
                assert_eq!(cpus(&Mask::current().unwrap()), vec![first]);
            });
            worker.join().unwrap();
            assert_eq!(cpus(&Mask::current().unwrap()), before);
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::{compact, BulkPlacement};

#[cfg(not(target_os = "linux"))]
pub struct Mask;
#[cfg(not(target_os = "linux"))]
impl Mask {
    pub fn apply(&self) -> bool {
        false
    }
}
#[cfg(not(target_os = "linux"))]
pub fn compact() -> Option<(usize, Mask)> {
    None
}

#[cfg(not(target_os = "linux"))]
pub struct BulkPlacement;
#[cfg(not(target_os = "linux"))]
impl BulkPlacement {
    pub fn new(_: Vec<std::net::IpAddr>) -> Self {
        Self
    }
    pub fn set_bulk(&mut self, _: bool) {}
}
// Leave control and metadata exchanges alone. A short final block or an ACK
// does not end a bulk run; a small-file batch explicitly restores the mask.
impl BulkPlacement {
    pub fn request(&mut self, request: &crate::proto::Request) {
        use crate::proto::Request;
        match request {
            Request::ReadRange { len, .. } if *len >= 64 << 10 => self.set_bulk(true),
            Request::WriteRange { data, .. } if data.len() >= 64 << 10 => self.set_bulk(true),
            Request::ReadStream(stream) if stream.end.saturating_sub(stream.off) >= 64 << 10 => {
                self.set_bulk(true)
            }
            Request::ReadSmallBatch(_) | Request::PutSmallBatch(_) | Request::CopySmallFiles(_) => {
                self.set_bulk(false)
            }
            _ => {}
        }
    }
    pub fn response(&mut self, response: &crate::proto::Response) {
        match response {
            crate::proto::Response::Block { data, .. } if data.len() >= 64 << 10 => {
                self.set_bulk(true)
            }
            crate::proto::Response::SmallBlocks(_) => self.set_bulk(false),
            _ => {}
        }
    }
}

//! Keep shared metadata work compact without restricting transfer workers.

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
pub use linux::compact;

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

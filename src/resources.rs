//! Estimates for automatic admission and fallible optional parallelism.
use serde::{Deserialize, Serialize};

/// A control connection's process snapshot. This travels only over the
/// exact-build helper protocol; it is neither saved nor a reservation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Descriptors {
    pub limit: u64,
    pub open: u64,
}

impl Descriptors {
    pub fn current() -> Option<Self> {
        let limits = crate::fsops::nofile_limits().ok()?;
        if limits.rlim_cur == libc::RLIM_INFINITY {
            return None;
        }
        Some(Self {
            limit: limits.rlim_cur,
            open: crate::fsops::current_open_descriptor_count(limits.rlim_cur).ok()? as u64,
        })
    }

    pub fn source_workers(self, roots: usize) -> usize {
        self.workers(roots, false)
    }

    pub fn receiver_workers(self, roots: usize) -> usize {
        self.workers(roots, true)
    }

    fn workers(self, roots: usize, receiver: bool) -> usize {
        // Source registrations retain parent/object pairs in both registry and
        // control. Only receivers stage files: source/coordinator processes
        // should not reserve the receiver's separate quarter-limit allowance.
        // Keep control/scanning headroom in either process.
        let available = self
            .limit
            .saturating_sub(self.open)
            .saturating_sub(if receiver { self.limit / 4 } else { 0 })
            .saturating_sub(32)
            .saturating_sub((roots as u64).saturating_mul(4));
        // Keep the entire file cache, up to eight transport descriptors (two
        // coordinator connections, or a helper's socket clones), and four for
        // the destination root, held comparison basis and transient opens.
        // Source parent/object claims are charged separately. These are still
        // estimates, not reservations or a promise against every EMFILE.
        let per_worker = (crate::fsops::FD_CACHE_MAX as u64 + 8 + 4)
            .saturating_add((roots as u64).saturating_mul(2));
        usize::try_from(available / per_worker)
            .unwrap_or(usize::MAX)
            .max(1)
    }
}

/// EAGAIN means resource exhaustion at a thread/process spawn, but may mean
/// a timeout on socket I/O. Preserve that distinction at the allocation site.
#[derive(Debug)]
struct AllocationRefused;
impl std::fmt::Display for AllocationRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("resource allocation refused")
    }
}
impl std::error::Error for AllocationRefused {}

pub(crate) fn allocation_error(error: std::io::Error) -> anyhow::Error {
    let temporary = error.raw_os_error() == Some(libc::EAGAIN);
    let error = anyhow::Error::from(error);
    if temporary {
        error.context(AllocationRefused)
    } else {
        error
    }
}

/// Classify on the endpoint that owns errno; remote errno numbers are not portable.
pub(crate) fn exhausted(error: &anyhow::Error) -> bool {
    error.is::<AllocationRefused>()
        || error
            .chain()
            .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
            .any(|error| {
                matches!(
                    error.raw_os_error(),
                    Some(libc::EMFILE | libc::ENFILE | libc::ENOMEM)
                )
            })
}

/// Pools are an optimization. A failed build must leave the caller able to
/// perform the same operations sequentially without starting Rayon's global pool.
pub(crate) fn optional_pool(name: &'static str, threads: usize) -> Option<rayon::ThreadPool> {
    #[cfg(debug_assertions)]
    if std::env::var_os("SYQ_TEST_NO_OPTIONAL_POOLS").is_some() {
        return None;
    }
    match rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .thread_name(move |index| format!("{name}-{index}"))
        .build()
    {
        Ok(pool) => Some(pool),
        Err(error) => {
            if crate::output::debug() {
                crate::output::diagnostic!("syq: {name}: using sequential operations ({error})");
            }
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocation_pressure_is_distinct_from_socket_timeout() {
        let errno = || std::io::Error::from_raw_os_error(libc::EAGAIN);
        assert!(!exhausted(
            &anyhow::Error::from(errno()).context("read handshake")
        ));
        assert!(exhausted(
            &allocation_error(errno()).context("start reader")
        ));
        for code in [libc::EMFILE, libc::ENFILE, libc::ENOMEM] {
            assert!(exhausted(
                &anyhow::Error::from(std::io::Error::from_raw_os_error(code)).context("open file")
            ));
        }
        assert!(!exhausted(&allocation_error(
            std::io::Error::from_raw_os_error(libc::EACCES)
        )));
    }

    #[test]
    fn receivers_with_low_limits_admit_more_than_one_worker() {
        let budget = Descriptors {
            limit: 128,
            open: 6,
        };
        assert_eq!(budget.receiver_workers(0), 2);
        assert!(Descriptors { open: 70, ..budget }.receiver_workers(0) < 2);
    }

    #[test]
    fn sources_do_not_reserve_receiver_staging_handles() {
        let budget = Descriptors {
            limit: 512,
            open: 12,
        };
        assert!(budget.source_workers(1) > budget.receiver_workers(1));
        assert_eq!(
            Descriptors {
                limit: 128,
                ..budget
            }
            .source_workers(1),
            2
        );
    }

    #[test]
    fn descriptor_admission_leaves_room_for_staging_and_control() {
        assert_eq!(
            Descriptors {
                limit: 128,
                open: 12
            }
            .receiver_workers(1),
            1
        );
        assert_eq!(
            Descriptors {
                limit: 512,
                open: 12
            }
            .receiver_workers(1),
            11
        );
        assert!(
            Descriptors {
                limit: 1 << 20,
                open: 12
            }
            .receiver_workers(1)
                > 10_000
        );
        assert!(
            Descriptors {
                limit: 1024,
                open: 400
            }
            .receiver_workers(20)
                < Descriptors {
                    limit: 1024,
                    open: 12
                }
                .receiver_workers(1)
        );
        assert_eq!(
            Descriptors {
                limit: 32,
                open: 32
            }
            .receiver_workers(256),
            1
        );
    }
}

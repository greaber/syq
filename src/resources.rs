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
            limit: limits.rlim_cur as u64,
            open: crate::fsops::current_open_descriptor_count(limits.rlim_cur).ok()? as u64,
        })
    }

    pub fn workers(self, roots: usize) -> usize {
        // Source registrations retain parent/object pairs in both registry and
        // control. Leave a quarter for small-file staging (its existing shared
        // allowance), plus control/scanning headroom. A worker may retain file
        // caches, transport clones, source claims and transient opens. This is
        // admission for the main consumers, not a promise against all EMFILE.
        let available = self
            .limit
            .saturating_sub(self.open)
            .saturating_sub(self.limit / 4)
            .saturating_sub(32)
            .saturating_sub((roots as u64).saturating_mul(4));
        let per_worker = 32u64.saturating_add((roots as u64).saturating_mul(2));
        usize::try_from(available / per_worker)
            .unwrap_or(usize::MAX)
            .max(1)
    }
}

/// Classify on the endpoint that owns errno; remote errno numbers are not portable.
pub(crate) fn exhausted(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
        .any(|error| {
            matches!(
                error.raw_os_error(),
                Some(libc::EMFILE | libc::ENFILE | libc::EAGAIN | libc::ENOMEM)
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
    fn descriptor_admission_leaves_room_for_staging_and_control() {
        assert_eq!(
            Descriptors {
                limit: 128,
                open: 12
            }
            .workers(1),
            1
        );
        assert_eq!(
            Descriptors {
                limit: 512,
                open: 12
            }
            .workers(1),
            9
        );
        assert!(
            Descriptors {
                limit: 1 << 20,
                open: 12
            }
            .workers(1)
                > 10_000
        );
        assert!(
            Descriptors {
                limit: 1024,
                open: 400
            }
            .workers(20)
                < Descriptors {
                    limit: 1024,
                    open: 12
                }
                .workers(1)
        );
        assert_eq!(
            Descriptors {
                limit: 32,
                open: 32
            }
            .workers(256),
            1
        );
    }
}

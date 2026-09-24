//! Share concurrent system lookups, without retaining addresses or failures
//! after the callers finish. A connection burst must not become a DNS burst.
use aws_smithy_runtime_api::client::dns::{
    DnsFuture, ResolveDns, ResolveDnsError, SharedDnsResolver,
};
use std::{
    collections::HashMap,
    net::{IpAddr, ToSocketAddrs},
    sync::{Arc, Mutex, Weak},
};
use tokio::sync::OnceCell;

type Lookup = OnceCell<Result<Vec<IpAddr>, Arc<ResolveDnsError>>>;

const MAX_CONCURRENT_LOOKUPS: usize = 8;

#[derive(Clone, Debug)]
pub(super) struct CoalescingDns {
    resolver: SharedDnsResolver,
    lookups: Arc<Mutex<HashMap<String, Weak<Lookup>>>>,
}

impl Default for CoalescingDns {
    fn default() -> Self {
        Self::new(SharedDnsResolver::new(SystemDns::default()))
    }
}

impl CoalescingDns {
    fn new(resolver: SharedDnsResolver) -> Self {
        Self {
            resolver,
            lookups: Default::default(),
        }
    }
}

impl ResolveDns for CoalescingDns {
    fn resolve_dns<'a>(&'a self, name: &'a str) -> DnsFuture<'a> {
        DnsFuture::new(async move {
            let lookup = {
                let mut lookups = self.lookups.lock().expect("DNS lookup lock poisoned");
                lookups.retain(|_, value| value.strong_count() > 0);
                if let Some(lookup) = lookups.get(name).and_then(Weak::upgrade) {
                    lookup
                } else {
                    let lookup = Arc::new(OnceCell::new());
                    lookups.insert(name.into(), Arc::downgrade(&lookup));
                    lookup
                }
            };
            lookup
                .get_or_init(|| async { self.resolver.resolve_dns(name).await.map_err(Arc::new) })
                .await
                .clone()
                .map_err(ResolveDnsError::new)
        })
    }
}

#[derive(Debug)]
struct SystemDns {
    slots: Arc<tokio::sync::Semaphore>,
}
impl Default for SystemDns {
    fn default() -> Self {
        Self {
            slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_LOOKUPS)),
        }
    }
}
impl ResolveDns for SystemDns {
    fn resolve_dns<'a>(&'a self, name: &'a str) -> DnsFuture<'a> {
        let name = name.to_owned();
        DnsFuture::new(async move {
            system_lookup(self.slots.clone(), move || {
                (name.as_str(), 0)
                    .to_socket_addrs()
                    .map(|addresses| addresses.map(|a| a.ip()).collect())
            })
            .await
        })
    }
}

// A pooled HTTP connection can satisfy a request while a speculative connection
// is still resolving DNS. System lookups cannot be cancelled, so Tokio's blocking
// pool would make runtime shutdown wait for an unused lookup. Isolate only DNS
// on detached threads; file I/O continues to use the runtime's normal drain.
async fn system_lookup(
    slots: Arc<tokio::sync::Semaphore>,
    lookup: impl FnOnce() -> std::io::Result<Vec<IpAddr>> + Send + 'static,
) -> Result<Vec<IpAddr>, ResolveDnsError> {
    let permit = slots.acquire_owned().await.map_err(ResolveDnsError::new)?;
    let (send, receive) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("syq-s3-dns".into())
        .spawn(move || {
            // Cancellation does not release capacity while libc is still running.
            // This bounds outstanding threads even across cancelled lookups.
            if !send.is_closed() {
                let result = lookup();
                drop(permit);
                let _ = send.send(result);
            }
        })
        .map_err(ResolveDnsError::new)?;
    receive
        .await
        .map_err(ResolveDnsError::new)?
        .map_err(ResolveDnsError::new)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn cancelled_lookup_does_not_delay_runtime_shutdown() {
        use std::sync::mpsc;
        use std::time::Duration;
        let (entered, started) = mpsc::channel();
        let (release, blocked) = mpsc::channel();
        let (stopped, shutdown) = mpsc::channel();
        let (cancel, cancellation) = tokio::sync::oneshot::channel::<()>();
        let owner = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let request = tokio::spawn(system_lookup(
                    Arc::new(tokio::sync::Semaphore::new(1)),
                    move || {
                        entered.send(()).unwrap();
                        blocked.recv_timeout(Duration::from_secs(10)).unwrap();
                        Ok(vec!["127.0.0.1".parse().unwrap()])
                    },
                ));
                cancellation.await.unwrap();
                request.abort();
                assert!(request.await.unwrap_err().is_cancelled());
            });
            drop(runtime);
            stopped.send(()).unwrap();
        });
        started.recv_timeout(Duration::from_secs(5)).unwrap();
        cancel.send(()).unwrap();
        let finished = shutdown.recv_timeout(Duration::from_secs(1));
        // Always release the worker and join the owner, including the regression case.
        release.send(()).unwrap();
        owner.join().unwrap();
        assert!(finished.is_ok(), "cancelled DNS blocked runtime shutdown");
    }

    #[tokio::test]
    async fn cancelled_lookup_holds_capacity_until_system_call_finishes() {
        use std::sync::mpsc;
        use std::time::Duration;
        let slots = Arc::new(tokio::sync::Semaphore::new(1));
        let (entered, started) = tokio::sync::oneshot::channel();
        let (release, blocked) = mpsc::channel();
        let first = tokio::spawn(system_lookup(slots.clone(), move || {
            entered.send(()).unwrap();
            blocked.recv_timeout(Duration::from_secs(5)).unwrap();
            Ok(Vec::new())
        }));
        started.await.unwrap();
        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());
        assert_eq!(slots.available_permits(), 0);
        release.send(()).unwrap();
        let next = tokio::time::timeout(
            Duration::from_secs(5),
            system_lookup(slots.clone(), || Ok(vec!["127.0.0.1".parse().unwrap()])),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(next, vec!["127.0.0.1".parse::<IpAddr>().unwrap()]);
        assert_eq!(slots.available_permits(), 1);
    }

    #[tokio::test]
    async fn system_lookup_preserves_failure_and_releases_capacity() {
        let slots = Arc::new(tokio::sync::Semaphore::new(1));
        let error = system_lookup(slots.clone(), || {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "test DNS failure",
            ))
        })
        .await
        .unwrap_err();
        assert!(format!("{error:?}").contains("test DNS failure"));
        assert_eq!(slots.available_permits(), 1);
    }

    #[derive(Debug)]
    struct Resolver(Arc<AtomicUsize>);
    impl ResolveDns for Resolver {
        fn resolve_dns<'a>(&'a self, name: &'a str) -> DnsFuture<'a> {
            self.0.fetch_add(1, Ordering::SeqCst);
            DnsFuture::new(async move {
                tokio::task::yield_now().await;
                if name == "missing" {
                    Err(ResolveDnsError::new(std::io::Error::other("missing")))
                } else {
                    Ok(vec!["127.0.0.1".parse().unwrap()])
                }
            })
        }
    }

    #[tokio::test]
    async fn shares_inflight_lookups_but_does_not_cache_results_or_errors() {
        let calls = Arc::new(AtomicUsize::new(0));
        let resolver = CoalescingDns::new(SharedDnsResolver::new(Resolver(calls.clone())));
        for name in ["example", "missing"] {
            let before = calls.load(Ordering::SeqCst);
            let results =
                futures_util::future::join_all((0..256).map(|_| resolver.resolve_dns(name))).await;
            assert!(results.iter().all(|r| r.is_ok() == (name == "example")));
            assert_eq!(calls.load(Ordering::SeqCst), before + 1);
            let _ = resolver.resolve_dns(name).await;
            assert_eq!(calls.load(Ordering::SeqCst), before + 2);
        }
    }

    #[tokio::test]
    async fn distinct_names_are_resolved_independently() {
        let calls = Arc::new(AtomicUsize::new(0));
        let resolver = CoalescingDns::new(SharedDnsResolver::new(Resolver(calls.clone())));
        let (a, b) = tokio::join!(
            resolver.resolve_dns("example"),
            resolver.resolve_dns("missing")
        );
        assert!(a.is_ok());
        assert!(b.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}

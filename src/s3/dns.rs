//! Share concurrent system lookups and briefly reuse successful answers.
use aws_smithy_runtime_api::client::dns::{
    DnsFuture, ResolveDns, ResolveDnsError, SharedDnsResolver,
};
use std::{
    collections::HashMap,
    net::{IpAddr, ToSocketAddrs},
    sync::{Arc, Mutex, OnceLock, Weak},
    time::Duration,
};
use tokio::{sync::OnceCell, time::Instant};

type Lookup = OnceCell<Result<Vec<IpAddr>, Arc<ResolveDnsError>>>;

const MAX_CONCURRENT_LOOKUPS: usize = 8;
const CACHE_CAPACITY: usize = 64;
// The system resolver does not expose record TTLs.
const CACHE_TTL: Duration = Duration::from_secs(5);

#[derive(Debug, Default)]
struct Lookups {
    inflight: HashMap<String, Weak<Lookup>>,
    cached: HashMap<String, (Instant, Vec<IpAddr>)>,
}

#[derive(Clone, Debug)]
pub(super) struct CoalescingDns {
    resolver: SharedDnsResolver,
    lookups: Arc<Mutex<Lookups>>,
}

impl Default for CoalescingDns {
    fn default() -> Self {
        Self::new(SharedDnsResolver::new(SystemDns))
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
                let now = Instant::now();
                if let Some((expires, addresses)) = lookups.cached.get(name) {
                    if now < *expires {
                        return Ok(addresses.clone());
                    }
                    lookups.cached.remove(name);
                }
                lookups.inflight.retain(|_, value| value.strong_count() > 0);
                if let Some(lookup) = lookups.inflight.get(name).and_then(Weak::upgrade) {
                    lookup
                } else {
                    let lookup = Arc::new(OnceCell::new());
                    lookups
                        .inflight
                        .insert(name.into(), Arc::downgrade(&lookup));
                    lookup
                }
            };
            lookup
                .get_or_init(|| async {
                    let addresses = self.resolver.resolve_dns(name).await.map_err(Arc::new)?;
                    if !addresses.is_empty() {
                        let mut lookups = self.lookups.lock().expect("DNS lookup lock poisoned");
                        if lookups.cached.len() == CACHE_CAPACITY {
                            let oldest = lookups
                                .cached
                                .iter()
                                .min_by_key(|(_, (expires, _))| expires)
                                .map(|(name, _)| name.clone())
                                .unwrap();
                            lookups.cached.remove(&oldest);
                        }
                        lookups
                            .cached
                            .insert(name.into(), (Instant::now() + CACHE_TTL, addresses.clone()));
                        lookups.inflight.remove(name);
                    }
                    Ok(addresses)
                })
                .await
                .clone()
                .map_err(ResolveDnsError::new)
        })
    }
}

#[derive(Debug)]
struct SystemDns;

impl ResolveDns for SystemDns {
    fn resolve_dns<'a>(&'a self, name: &'a str) -> DnsFuture<'a> {
        static SLOTS: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
        DnsFuture::new(async move {
            let slots =
                SLOTS.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_LOOKUPS)));
            let name = name.to_owned();
            system_lookup(slots.clone(), move || {
                (name.as_str(), 0)
                    .to_socket_addrs()
                    .map(|addresses| addresses.map(|a| a.ip()).collect())
            })
            .await
        })
    }
}

// A pooled HTTP connection can satisfy a request while a speculative connection
// is resolving DNS. libc lookups cannot be cancelled. This process-wide pool
// runs only DNS, so it does not delay shutdown of the transfer's runtime.
async fn system_lookup(
    slots: Arc<tokio::sync::Semaphore>,
    lookup: impl FnOnce() -> std::io::Result<Vec<IpAddr>> + Send + 'static,
) -> Result<Vec<IpAddr>, ResolveDnsError> {
    static POOL: OnceLock<std::io::Result<tokio::runtime::Runtime>> = OnceLock::new();
    let permit = slots.acquire_owned().await.map_err(ResolveDnsError::new)?;
    let pool = POOL.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .thread_name("syq-s3-dns")
            .max_blocking_threads(MAX_CONCURRENT_LOOKUPS)
            .build()
    });
    let pool = pool
        .as_ref()
        .map_err(|error| ResolveDnsError::new(std::io::Error::other(error.to_string())))?;
    let (send, receive) = tokio::sync::oneshot::channel();
    pool.spawn_blocking(move || {
        if !send.is_closed() {
            let result = lookup();
            drop(permit);
            let _ = send.send(result);
        }
    });
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

    #[tokio::test(start_paused = true)]
    async fn shares_inflight_lookups_and_caches_only_successes_until_expiry() {
        let calls = Arc::new(AtomicUsize::new(0));
        let resolver = CoalescingDns::new(SharedDnsResolver::new(Resolver(calls.clone())));
        for name in ["example", "missing"] {
            let before = calls.load(Ordering::SeqCst);
            let results =
                futures_util::future::join_all((0..256).map(|_| resolver.resolve_dns(name))).await;
            assert!(results.iter().all(|r| r.is_ok() == (name == "example")));
            assert_eq!(calls.load(Ordering::SeqCst), before + 1);
            let _ = resolver.resolve_dns(name).await;
            if name == "example" {
                assert_eq!(calls.load(Ordering::SeqCst), before + 1);
                tokio::time::advance(CACHE_TTL).await;
                resolver.resolve_dns(name).await.unwrap();
            }
            assert_eq!(calls.load(Ordering::SeqCst), before + 2);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn cache_evicts_the_oldest_answer_at_capacity() {
        let calls = Arc::new(AtomicUsize::new(0));
        let resolver = CoalescingDns::new(SharedDnsResolver::new(Resolver(calls.clone())));
        for index in 0..=CACHE_CAPACITY {
            resolver.resolve_dns(&index.to_string()).await.unwrap();
            tokio::time::advance(Duration::from_millis(1)).await;
        }
        resolver.resolve_dns("1").await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), CACHE_CAPACITY + 1);
        resolver.resolve_dns("0").await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), CACHE_CAPACITY + 2);
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

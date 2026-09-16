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

#[derive(Clone, Debug)]
pub(super) struct CoalescingDns {
    resolver: SharedDnsResolver,
    lookups: Arc<Mutex<HashMap<String, Weak<Lookup>>>>,
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
struct SystemDns;
impl ResolveDns for SystemDns {
    fn resolve_dns<'a>(&'a self, name: &'a str) -> DnsFuture<'a> {
        let name = name.to_owned();
        DnsFuture::new(async move {
            tokio::task::spawn_blocking(move || {
                (name.as_str(), 0)
                    .to_socket_addrs()
                    .map(|addresses| addresses.map(|a| a.ip()).collect())
            })
            .await
            .map_err(ResolveDnsError::new)?
            .map_err(ResolveDnsError::new)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

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

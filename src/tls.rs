//! HTTPS trust shared by the synchronous clients. The AWS SDK uses the same
//! system certificate loader for its asynchronous clients.

use std::sync::{Arc, LazyLock};
use ureq::tls::{Certificate, RootCerts, TlsConfig};

// Loading a system store can be expensive, especially on macOS. Do it only
// when an HTTP client is needed and share the resulting certificates between
// update downloads and file uploads for the lifetime of this process.
static CONFIG: LazyLock<TlsConfig> = LazyLock::new(|| {
    let certificates = rustls_native_certs::load_native_certs()
        .certs
        .iter()
        .map(|cert| Certificate::from_der(cert.as_ref()).to_owned())
        .collect();
    TlsConfig::builder()
        .root_certs(RootCerts::Specific(Arc::new(certificates)))
        .unversioned_rustls_crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .build()
});

pub(crate) fn config() -> TlsConfig {
    CONFIG.clone()
}

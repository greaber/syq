//! HTTPS trust shared by the synchronous clients. The AWS SDK uses the same
//! system certificate loader for its asynchronous clients.

use std::sync::{Arc, LazyLock};
use ureq::tls::{Certificate, RootCerts, TlsConfig};

struct Trust {
    config: TlsConfig,
    empty_store: Option<String>,
}

// Load roots for the first release download or synchronous file upload, then
// reuse them for the lifetime of this process. Other S3 requests use the SDK.
static TRUST: LazyLock<Trust> = LazyLock::new(|| {
    let loaded = rustls_native_certs::load_native_certs();
    let empty_store = loaded.certs.is_empty().then(|| {
        let mut message = "no trusted CA certificates were loaded".to_owned();
        if let Some(error) = loaded.errors.first() {
            message.push_str(&format!(" ({error})"));
        }
        message.push_str(
            "; check SSL_CERT_FILE and SSL_CERT_DIR, or install the system CA certificates",
        );
        message
    });
    let certificates = loaded
        .certs
        .iter()
        .map(|cert| Certificate::from_der(cert.as_ref()).to_owned())
        .collect();
    Trust {
        config: TlsConfig::builder()
            .root_certs(RootCerts::Specific(Arc::new(certificates)))
            .unversioned_rustls_crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .build(),
        empty_store,
    }
});

pub(crate) fn config_builder() -> ureq::config::ConfigBuilder<ureq::typestate::AgentScope> {
    ureq::Agent::config_builder().tls_config(TRUST.config.clone())
}

pub(crate) fn download_error(error: anyhow::Error) -> anyhow::Error {
    match &TRUST.empty_store {
        Some(context) => error.context(context.clone()),
        None => error,
    }
}

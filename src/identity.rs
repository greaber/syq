//! Build identities shared by the wire handshake and managed helpers.

use anyhow::{bail, Result};

/// Peer compatibility identity. Official builds and source builds explicitly
/// choosing release helpers use the release tag. Other source builds include
/// their revision. This is a compatibility claim, not proof of artifact origin.
pub const fn build() -> &'static str {
    env!("SYQ_BUILD_IDENTITY")
}

/// The version `--version` and the results stream report: a release's
/// package version, and otherwise the build identity without its `v`, so
/// that a development build, say `0.7.1+dev.0123456789ab`, is not mistaken
/// for the release it was built from.
pub fn version() -> &'static str {
    if is_release_build() {
        env!("CARGO_PKG_VERSION")
    } else {
        build().strip_prefix('v').unwrap_or(build())
    }
}

/// The platform this executable was built for, reported by remote helpers in
/// the wire handshake. This avoids a separate `uname` ssh round trip on a
/// managed helper that is already installed.
pub fn platform() -> String {
    #[cfg(debug_assertions)]
    if let Some(platform) = std::env::var_os("SYQ_TEST_PLATFORM") {
        return platform.to_string_lossy().into_owned();
    }
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

/// Whether this receiver can create an unbound socket node while keeping all
/// destination traversal descriptor-relative.
pub fn supports_confined_socket_nodes() -> bool {
    #[cfg(debug_assertions)]
    if let Some(value) = std::env::var_os("SYQ_TEST_CONFINED_SOCKET_NODES") {
        return value == "1";
    }
    !cfg!(target_os = "macos")
}

pub fn require_release_helpers() -> Result<()> {
    if uses_release_helpers() {
        return Ok(());
    }
    bail!(
        "official helper downloads require a release-compatible build (this build is {}); rebuild with SYQ_HELPER_RELEASE=v{}",
        build(), env!("CARGO_PKG_VERSION")
    )
}

/// Helper origin is independent of whether this executable is a published build.
pub(crate) fn uses_release_helpers() -> bool {
    if env!("SYQ_RELEASE_HELPERS") == "1" || is_release_build() {
        return true;
    }
    #[cfg(any(test, debug_assertions))]
    if std::env::var_os("SYQ_TEST_RELEASE_HELPERS").is_some_and(|value| value == "1") {
        return true;
    }
    false
}

pub(crate) fn is_release_build() -> bool {
    if env!("SYQ_IS_RELEASE_BUILD") == "1" {
        return true;
    }
    #[cfg(any(test, debug_assertions))]
    if std::env::var_os("SYQ_TEST_RELEASE_BUILD").is_some_and(|value| value == "1") {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn development_builds_do_not_claim_the_release_identity() {
        if env!("SYQ_RELEASE_HELPERS") == "0" {
            let release = format!("v{}", env!("CARGO_PKG_VERSION"));
            assert!(build().starts_with(&format!("{release}+dev.")));
            assert_ne!(build(), release);
            if !is_release_build() {
                assert_eq!(format!("v{}", version()), build());
            }
        } else {
            assert_eq!(version(), env!("CARGO_PKG_VERSION"));
        }
    }
}

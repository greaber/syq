//! Build identities shared by the wire handshake and managed helpers.

use anyhow::{bail, Result};

/// Official builds use the immutable release tag. Development builds include
/// their Git revision so two source builds do not claim release compatibility.
pub const fn build() -> &'static str {
    env!("SYQ_BUILD_IDENTITY")
}

/// The platform this executable was built for, reported by remote helpers in
/// the wire handshake. This avoids a separate `uname` ssh round trip on a
/// managed-helper cache hit.
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

pub fn require_release_build() -> Result<()> {
    if is_release_build() {
        return Ok(());
    }
    bail!(
        "managed remote bootstrap is only available from an official syq release build (this build is {}); use an official release",
        build()
    )
}

pub(crate) fn is_release_build() -> bool {
    if env!("SYQ_IS_RELEASE_BUILD") == "1" {
        return true;
    }
    #[cfg(debug_assertions)]
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
        if env!("SYQ_IS_RELEASE_BUILD") == "0" {
            let release = format!("v{}", env!("CARGO_PKG_VERSION"));
            assert!(build().starts_with(&format!("{release}+dev.")));
            assert_ne!(build(), release);
        }
    }
}

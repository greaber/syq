//! Build identities shared by the wire handshake and managed helpers.

use anyhow::{bail, Result};

/// Official builds use the immutable release tag. Development builds include
/// their Git revision so two source builds do not claim release compatibility.
pub const fn build() -> &'static str {
    env!("SYQ_BUILD_IDENTITY")
}

pub fn release() -> String {
    format!("v{}", env!("CARGO_PKG_VERSION"))
}

/// Kept so the 0.1.0 updater can validate newer binaries. It is no longer a
/// protocol identity and deliberately has a fixed numeric suffix.
pub fn legacy_helper_id() -> String {
    format!("{}-p0", release())
}

pub fn require_release_build() -> Result<()> {
    if is_release_build() {
        return Ok(());
    }
    bail!(
        "managed remote bootstrap is only available from an official syq release build (this build is {}); install this build on the remote and pass --syq-path, or use an official release",
        build()
    )
}

fn is_release_build() -> bool {
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
            assert!(build().starts_with(&format!("{}+dev.", release())));
            assert_ne!(build(), release());
        }
    }

    #[test]
    fn legacy_identity_is_not_a_protocol_version() {
        assert_eq!(legacy_helper_id(), format!("{}-p0", release()));
    }
}

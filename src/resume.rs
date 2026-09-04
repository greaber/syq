//! Stable identity for destination-side partial files.

use sha2::{Digest, Sha256};

const IDENTITY_FORMAT: u32 = 1;

/// Canonical description used to keep partial files scoped to one logical
/// copy. Keep this serialization stable: changing it would orphan resumable
/// sidecars created by earlier syq versions.
pub fn copy_identity(
    src_endpoint: &str,
    src_roots: &[(String, bool)],
    dst_endpoint: &str,
    dst_root: &str,
    semantic_flags: &str,
) -> String {
    serde_json::json!({
        "format": IDENTITY_FORMAT,
        "source_endpoint": src_endpoint,
        "source_roots": src_roots,
        "destination_endpoint": dst_endpoint,
        "destination_root": dst_root,
        "semantics": semantic_flags,
    })
    .to_string()
}

/// Compact collision-resistant ID used in destination partial names.
pub fn copy_id(copy_identity: &str) -> crate::proto::CopyId {
    let digest = Sha256::digest(copy_identity.as_bytes());
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[..16]);
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn established_copy_identity_stays_stable() {
        let identity = copy_identity("local", &[("/src".to_string(), true)], "host", "/dst", "{}");
        assert_eq!(
            identity,
            r#"{"destination_endpoint":"host","destination_root":"/dst","format":1,"semantics":"{}","source_endpoint":"local","source_roots":[["/src",true]]}"#
        );
        assert_eq!(
            copy_id(&identity),
            [
                0xed, 0x14, 0xa1, 0xb7, 0x64, 0x57, 0x16, 0x81, 0x0f, 0xaf, 0xc5, 0x23, 0xd1, 0x34,
                0xc8, 0x69,
            ]
        );
    }
}

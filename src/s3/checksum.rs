use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::Digest;

/// Reuse the native single-PUT checksum in SigV4's payload field. Some services
/// store the additional SHA256 checksum without validating it on PutObject, but
/// validate the signed payload hash. This only converts the existing digest;
/// it never reads or hashes a request body.
pub(super) fn single_put_payload(
    method: &str,
    multipart: bool,
    checksum: Option<&str>,
) -> anyhow::Result<Option<String>> {
    if method != "PUT" || multipart {
        return Ok(None);
    }
    let Some(checksum) = checksum else {
        return Ok(None);
    };
    let bytes = base64::engine::general_purpose::STANDARD.decode(checksum)?;
    anyhow::ensure!(bytes.len() == 32, "invalid SHA256 upload checksum length");
    Ok(Some(bytes.iter().map(|b| format!("{b:02x}")).collect()))
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum Algorithm {
    #[default]
    Sha256,
    Md5,
}
impl Algorithm {
    pub fn for_endpoint(endpoint: Option<&str>) -> Self {
        // R2 accepts Content-MD5 on UploadPart but rejects the additional
        // SHA-256 checksum header. Keep other providers' recovery protocol.
        if endpoint
            .and_then(|s| url::Url::parse(s).ok())
            .and_then(|url| url.host_str().map(str::to_owned))
            .is_some_and(|host| host.ends_with(".r2.cloudflarestorage.com"))
        {
            Self::Md5
        } else {
            Self::Sha256
        }
    }
    pub fn is_sha256(&self) -> bool {
        *self == Self::Sha256
    }
    pub fn schema(self) -> u32 {
        match self {
            Self::Sha256 => 1,
            Self::Md5 => 2,
        }
    }
    pub fn hasher(self) -> Hasher {
        match self {
            Self::Sha256 => Hasher::Sha256(sha2::Sha256::new()),
            Self::Md5 => Hasher::Md5(md5::Md5::new()),
        }
    }
    pub fn digest(self, bytes: &[u8]) -> String {
        let mut hash = self.hasher();
        hash.update(bytes);
        hash.finish()
    }
}
pub(super) enum Hasher {
    Sha256(sha2::Sha256),
    Md5(md5::Md5),
}
impl Hasher {
    pub fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Sha256(h) => h.update(bytes),
            Self::Md5(h) => h.update(bytes),
        }
    }
    pub fn finish(self) -> String {
        match self {
            Self::Sha256(h) => base64::engine::general_purpose::STANDARD.encode(h.finalize()),
            Self::Md5(h) => base64::engine::general_purpose::STANDARD.encode(h.finalize()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn payload_hash_reuses_only_single_put_sha256() {
        let checksum = Algorithm::Sha256.digest(b"abc");
        assert_eq!(
            single_put_payload("PUT", false, Some(&checksum))
                .unwrap()
                .as_deref(),
            Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        for (method, multipart, checksum) in [
            ("GET", false, Some("unused")),
            ("PUT", true, Some("unused")),
            ("PUT", false, None),
        ] {
            assert_eq!(
                single_put_payload(method, multipart, checksum).unwrap(),
                None
            );
        }
        for checksum in ["invalid base64!", "YWJj"] {
            assert!(single_put_payload("PUT", false, Some(checksum)).is_err());
        }
    }
    #[test]
    fn r2_uses_content_md5_including_jurisdiction_endpoints() {
        for endpoint in [
            "https://account.r2.cloudflarestorage.com",
            "https://account.eu.r2.cloudflarestorage.com",
        ] {
            assert_eq!(Algorithm::for_endpoint(Some(endpoint)), Algorithm::Md5);
        }
        for endpoint in [
            None,
            Some("https://t3.storage.dev"),
            Some("https://account.r2.cloudflarestorage.com.example.org"),
        ] {
            assert_eq!(Algorithm::for_endpoint(endpoint), Algorithm::Sha256);
        }
        assert_eq!(Algorithm::Md5.digest(b"abc"), "kAFQmDzST7DWlj99KOF/cg==");
    }
}

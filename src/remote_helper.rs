//! Versioned remote helper discovery and installation commands.
//!
//! The local client always names the exact release/protocol helper it expects.
//! A cache hit adds no extra ssh round trip: the normal remote command computes
//! the target name and execs the cached binary directly.  On a miss, `conn`
//! probes the target and downloads the matching authorized release asset.

use crate::proto::VERSION;

pub const RELEASE_BASE_URL: &str = "https://github.com/greaber/syq/releases/download";
pub const HELPER_MISSING_EXIT: i32 = 125;
pub const HELPER_NOT_EXECUTABLE_EXIT: i32 = 126;
const DOWNLOAD_CACHE_GENERATION: &str = "download-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Target {
    pub key: &'static str,
    pub asset: &'static str,
}

impl Target {
    pub fn from_uname(os: &str, arch: &str) -> Option<Self> {
        match (os.trim(), arch.trim()) {
            ("Linux", "x86_64") => Some(Self {
                key: "linux-x86_64",
                asset: "syq-linux-x86_64",
            }),
            ("Linux", "aarch64" | "arm64") => Some(Self {
                key: "linux-aarch64",
                asset: "syq-linux-aarch64",
            }),
            ("Darwin", "x86_64") => Some(Self {
                key: "macos-x86_64",
                asset: "syq-macos-x86_64",
            }),
            ("Darwin", "arm64" | "aarch64") => Some(Self {
                key: "macos-arm64",
                asset: "syq-macos-arm64",
            }),
            _ => None,
        }
    }

    pub fn local() -> Option<Self> {
        Self::from_uname(
            match std::env::consts::OS {
                "linux" => "Linux",
                "macos" => "Darwin",
                other => other,
            },
            std::env::consts::ARCH,
        )
    }
}

pub fn release_key() -> String {
    format!("v{}-p{VERSION}", env!("CARGO_PKG_VERSION"))
}

/// Keep cache provenance separate from the helper identity recorded in signed
/// release manifests. The generation suffix invalidates upload-capable caches
/// without requiring otherwise-identical release assets to be republished.
fn cache_key() -> String {
    format!("{}-{DOWNLOAD_CACHE_GENERATION}", release_key())
}

pub fn probe_command() -> &'static str {
    "sh -c 'printf \"syq-helper-target:%s:%s\\n\" \"$(uname -s)\" \"$(uname -m)\"'"
}

/// Run this release's helper from its deterministic cache path.  The target
/// selection deliberately lives in this command so a cache hit needs no probe
/// connection before the real server connection.
pub fn launcher(args: &[String]) -> String {
    let script = format!(
        r#"case "$(uname -s):$(uname -m)" in
Linux:x86_64) target=linux-x86_64 ;;
Linux:aarch64|Linux:arm64) target=linux-aarch64 ;;
Darwin:x86_64) target=macos-x86_64 ;;
Darwin:arm64|Darwin:aarch64) target=macos-arm64 ;;
*) exit {HELPER_MISSING_EXIT} ;;
esac
program="$HOME/.cache/syq/helpers/{release}/$target/syq"
[ -x "$program" ] || exit {HELPER_MISSING_EXIT}
exec "$program" "$@""#,
        release = cache_key(),
    );
    format!(
        "sh -c {} syq {}",
        shell_words::quote(&script),
        shell_words::join(args)
    )
}

pub fn download_script(target: Target, expected_sha256: &str) -> String {
    assert!(
        expected_sha256.len() == 64
            && expected_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "trusted release hash must be lowercase SHA-256"
    );
    let release = cache_key();
    let legacy_release = release_key();
    let tag = format!("v{}", env!("CARGO_PKG_VERSION"));
    let url = format!("{RELEASE_BASE_URL}/{tag}/{}.gz", target.asset);
    let expected_version = format!("syq {}", env!("CARGO_PKG_VERSION"));
    let expected_helper_id = release_key();
    format!(
        r#"set -eu
legacy_dir="$HOME/.cache/syq/helpers/{legacy_release}/{target_key}"
legacy_pcp_dir="$HOME/.cache/pcp/helpers/{legacy_release}/{target_key}"
rm -f "$legacy_dir/syq" "$legacy_pcp_dir/pcp"
rmdir "$legacy_dir" "$HOME/.cache/syq/helpers/{legacy_release}" 2>/dev/null || :
rmdir "$legacy_pcp_dir" "$HOME/.cache/pcp/helpers/{legacy_release}" 2>/dev/null || :
dir="$HOME/.cache/syq/helpers/{release}/{target_key}"
program="$dir/syq"
tmp="$dir/.syq.$$.tmp"
archive="$tmp.gz"
mkdir -p "$dir"
cleanup() {{ rm -f "$tmp" "$archive"; }}
trap cleanup EXIT HUP INT TERM
fetch() {{
    if command -v curl >/dev/null 2>&1; then
        curl --fail --silent --show-error --location --retry 2 --connect-timeout 10 --proto '=https' --proto-redir '=https' --output "$2" "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$2" "$1"
    else
        echo "syq: remote helper download needs curl or wget" >&2
        return 1
    fi
}}
fetch {url} "$archive"
expected={expected_sha256}
if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$archive" | sed 's/[[:space:]].*$//')
elif command -v shasum >/dev/null 2>&1; then
    actual=$(shasum -a 256 "$archive" | sed 's/[[:space:]].*$//')
elif command -v openssl >/dev/null 2>&1; then
    actual=$(openssl dgst -sha256 "$archive" | sed 's/^.*= //')
else
    echo "syq: remote helper verification needs sha256sum, shasum, or openssl" >&2
    exit 1
fi
[ -n "$expected" ] && [ "$actual" = "$expected" ] || {{
    echo "syq: remote helper checksum mismatch" >&2
    exit 1
}}
gzip -dc "$archive" > "$tmp"
chmod 700 "$tmp"
got=$("$tmp" --version 2>/dev/null) || {{
    echo "syq: downloaded helper cannot run on this host" >&2
    exit 1
}}
[ "$got" = {expected_version} ] || {{
    echo "syq: downloaded helper has unexpected version: $got" >&2
    exit 1
}}
got_id=$("$tmp" --remote-helper-id 2>/dev/null) || {{
    echo "syq: downloaded helper does not report a helper identity" >&2
    exit 1
}}
[ "$got_id" = {expected_helper_id} ] || {{
    echo "syq: downloaded helper has unexpected identity: $got_id" >&2
    exit 1
}}
mv "$tmp" "$program"
cleanup
trap - EXIT HUP INT TERM"#,
        target_key = target.key,
        legacy_release = legacy_release,
        url = shell_words::quote(&url),
        expected_sha256 = shell_words::quote(expected_sha256),
        expected_version = shell_words::quote(&expected_version),
        expected_helper_id = shell_words::quote(&expected_helper_id),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_supported_uname_pairs() {
        assert_eq!(
            Target::from_uname("Linux", "x86_64").unwrap().asset,
            "syq-linux-x86_64"
        );
        assert_eq!(
            Target::from_uname("Linux", "arm64").unwrap().key,
            "linux-aarch64"
        );
        assert_eq!(
            Target::from_uname("Darwin", "arm64").unwrap().asset,
            "syq-macos-arm64"
        );
        assert!(Target::from_uname("FreeBSD", "x86_64").is_none());
    }

    #[test]
    fn launcher_uses_versioned_path_and_quotes_arguments() {
        let command = launcher(&["--server".into(), "argument with spaces".into()]);
        assert!(command.contains(&cache_key()));
        assert!(command.contains(DOWNLOAD_CACHE_GENERATION));
        assert!(command.contains("linux-x86_64"));
        assert!(command.contains("'argument with spaces'"));
    }

    #[test]
    fn release_download_is_pinned_and_verified() {
        let target = Target::from_uname("Linux", "x86_64").unwrap();
        let script = download_script(target, &"a".repeat(64));
        assert!(script.contains(&format!(
            "/v{}/syq-linux-x86_64.gz",
            env!("CARGO_PKG_VERSION")
        )));
        assert!(script.contains("sha256sum"));
        assert!(script.contains("checksum mismatch"));
        assert!(!script.contains(".sha256"));
        assert!(script.contains(&release_key()));
        assert!(script.contains("rm -f \"$legacy_dir/syq\" \"$legacy_pcp_dir/pcp\""));
    }
}

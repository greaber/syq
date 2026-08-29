//! Release/build-identified remote helper discovery and installation commands.
//!
//! Official clients name their exact release; development clients carry a Git
//! identity but may not populate the managed cache. A cache hit adds no extra
//! ssh round trip: the normal remote command computes the target name and execs
//! the cached binary directly. On a miss, `conn` probes the target and either
//! authorizes a direct download or uploads a locally verified matching asset.

pub const RELEASE_BASE_URL: &str = "https://github.com/greaber/syq/releases/download";
pub const HELPER_MISSING_EXIT: i32 = 125;
pub const HELPER_NOT_EXECUTABLE_EXIT: i32 = 126;
/// Direct download could not be used, but installing an uploaded helper may work.
pub const DIRECT_FALLBACK_EXIT: i32 = 75;
/// Direct download completed, but its digest did not match the signed manifest.
pub const DIRECT_INTEGRITY_EXIT: i32 = 76;
/// The remote cache itself could not be written or finalized; upload cannot fix it.
pub const INSTALL_FAILED_EXIT: i32 = 77;
const DOWNLOAD_CACHE_GENERATION: &str = "release-v1";

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

pub fn helper_identity() -> &'static str {
    crate::identity::build()
}

/// Keep cache layout separate from peer identity. Changing the generation
/// prevents older cache formats from being executed without changing which
/// builds are wire-compatible.
fn cache_key() -> String {
    format!("{}-{DOWNLOAD_CACHE_GENERATION}", helper_identity())
}

pub fn probe_command() -> &'static str {
    r#"sh -c 'downloader=
if command -v curl >/dev/null 2>&1; then downloader=curl
elif command -v wget >/dev/null 2>&1; then downloader=wget
fi
hasher=
if command -v sha256sum >/dev/null 2>&1; then hasher=sha256sum
elif command -v shasum >/dev/null 2>&1; then hasher=shasum
elif command -v openssl >/dev/null 2>&1; then hasher=openssl
fi
decompressor=
if command -v gzip >/dev/null 2>&1; then decompressor=gzip; fi
printf "syq-helper-target:%s:%s\n" "$(uname -s)" "$(uname -m)"
printf "syq-helper-tools:%s:%s:%s\n" "$downloader" "$hasher" "$decompressor"'"#
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

pub fn download_script(target: Target) -> String {
    let release = cache_key();
    let tag = format!("v{}", env!("CARGO_PKG_VERSION"));
    let archive_url = format!("{RELEASE_BASE_URL}/{tag}/{}.gz", target.asset);
    let manifest_url = format!("{RELEASE_BASE_URL}/{tag}/syq-release-manifest.json");
    let expected_version = format!("syq {}", env!("CARGO_PKG_VERSION"));
    let expected_identity = helper_identity();
    format!(
        r#"set -u
dir="$HOME/.cache/syq/helpers/{release}/{target_key}"
program="$dir/syq"
tmp="$dir/.syq.$$.tmp"
archive="$tmp.gz"
manifest="$tmp.json"
if ! mkdir -p "$dir"; then
    echo "syq: cannot create the remote helper cache" >&2
    exit {install_failed_exit}
fi
cleanup() {{ rm -f "$tmp" "$archive" "$manifest"; }}
trap cleanup EXIT HUP INT TERM
download() {{
    source=$1
    destination=$2
    if ! : > "$destination"; then
        echo "syq: cannot write the remote helper cache" >&2
        exit {install_failed_exit}
    fi
    if command -v curl >/dev/null 2>&1; then
        curl --fail --silent --show-error --location --connect-timeout 5 --max-time 30 --speed-limit 1024 --speed-time 10 --proto '=https' --proto-redir '=https' --output "$destination" "$source"
        status=$?
        if [ "$status" -ne 0 ]; then
            if [ "$status" -eq 23 ]; then
                echo "syq: remote helper download could not write its temporary file" >&2
                exit {install_failed_exit}
            fi
            echo "syq: remote helper download with curl failed" >&2
            exit {direct_fallback_exit}
        fi
    elif command -v wget >/dev/null 2>&1; then
        wget -q --timeout=10 --tries=1 -O "$destination" "$source"
        status=$?
        if [ "$status" -ne 0 ]; then
            if [ "$status" -eq 3 ]; then
                echo "syq: remote helper download could not write its temporary file" >&2
                exit {install_failed_exit}
            fi
            echo "syq: remote helper download with wget failed" >&2
            exit {direct_fallback_exit}
        fi
    else
        echo "syq: remote helper download needs curl or wget" >&2
        exit {direct_fallback_exit}
    fi
}}
download {manifest_url} "$manifest"
download {archive_url} "$archive"
if command -v sha256sum >/dev/null 2>&1; then
    if output=$(sha256sum "$archive" 2>/dev/null); then
        actual=${{output%%[[:space:]]*}}
    else
        echo "syq: remote helper hashing with sha256sum failed" >&2
        exit {direct_fallback_exit}
    fi
elif command -v shasum >/dev/null 2>&1; then
    if output=$(shasum -a 256 "$archive" 2>/dev/null); then
        actual=${{output%%[[:space:]]*}}
    else
        echo "syq: remote helper hashing with shasum failed" >&2
        exit {direct_fallback_exit}
    fi
elif command -v openssl >/dev/null 2>&1; then
    if output=$(openssl dgst -sha256 "$archive" 2>/dev/null); then
        actual=${{output##* }}
    else
        echo "syq: remote helper hashing with openssl failed" >&2
        exit {direct_fallback_exit}
    fi
else
    echo "syq: remote helper verification needs sha256sum, shasum, or openssl" >&2
    exit {direct_fallback_exit}
fi
case "$actual" in
    ''|*[!0-9a-f]*)
        echo "syq: remote helper hasher returned an invalid SHA-256 digest" >&2
        exit {direct_fallback_exit}
        ;;
esac
if [ "${{#actual}}" -ne 64 ]; then
    echo "syq: remote helper hasher returned an invalid SHA-256 digest" >&2
    exit {direct_fallback_exit}
fi
printf 'syq-helper-manifest-begin\n'
while IFS= read -r line || [ -n "$line" ]; do
    printf '%s\n' "$line"
done < "$manifest"
printf 'syq-helper-manifest-end\n'
printf 'syq-helper-sha256:%s\n' "$actual"
if ! IFS= read -r decision; then
    echo "syq: local client did not authorize the remote helper download" >&2
    exit {direct_fallback_exit}
fi
if [ "$decision" != install ]; then
    echo "syq: remote helper download was discarded after local integrity verification" >&2
    exit {direct_integrity_exit}
fi
if ! gzip -dc "$archive" > "$tmp"; then
    echo "syq: remote helper decompression failed" >&2
    exit {direct_fallback_exit}
fi
if ! chmod 700 "$tmp"; then
    echo "syq: cannot make the remote helper executable" >&2
    exit {install_failed_exit}
fi
got=$("$tmp" --version 2>/dev/null) || {{
    echo "syq: downloaded helper cannot run on this host" >&2
    exit {install_failed_exit}
}}
[ "$got" = {expected_version} ] || {{
    echo "syq: downloaded helper has unexpected version: $got" >&2
    exit {install_failed_exit}
}}
got_id=$("$tmp" --build-identity 2>/dev/null) || {{
    echo "syq: downloaded helper does not report a build identity" >&2
    exit {install_failed_exit}
}}
[ "$got_id" = {expected_identity} ] || {{
    echo "syq: downloaded helper has unexpected identity: $got_id" >&2
    exit {install_failed_exit}
}}
if ! mv "$tmp" "$program"; then
    echo "syq: cannot install the remote helper" >&2
    exit {install_failed_exit}
fi
cleanup
trap - EXIT HUP INT TERM"#,
        target_key = target.key,
        archive_url = shell_words::quote(&archive_url),
        manifest_url = shell_words::quote(&manifest_url),
        expected_version = shell_words::quote(&expected_version),
        expected_identity = shell_words::quote(expected_identity),
        direct_fallback_exit = DIRECT_FALLBACK_EXIT,
        direct_integrity_exit = DIRECT_INTEGRITY_EXIT,
        install_failed_exit = INSTALL_FAILED_EXIT,
    )
}

/// Install a locally verified, uncompressed helper received on standard input.
/// This path deliberately needs no remote downloader, hasher, or decompressor.
pub fn upload_script(target: Target) -> String {
    let release = cache_key();
    let expected_version = format!("syq {}", env!("CARGO_PKG_VERSION"));
    let expected_identity = helper_identity();
    format!(
        r#"set -u
umask 077
dir="$HOME/.cache/syq/helpers/{release}/{target_key}"
program="$dir/syq"
tmp="$dir/.syq.$$.upload"
if ! mkdir -p "$dir"; then
    echo "syq: cannot create the remote helper cache" >&2
    exit {install_failed_exit}
fi
cleanup() {{ rm -f "$tmp"; }}
trap cleanup EXIT HUP INT TERM
if ! cat > "$tmp"; then
    echo "syq: could not upload the remote helper" >&2
    exit {install_failed_exit}
fi
if ! chmod 700 "$tmp"; then
    echo "syq: cannot make the uploaded remote helper executable" >&2
    exit {install_failed_exit}
fi
got=$("$tmp" --version 2>/dev/null) || {{
    echo "syq: uploaded helper cannot run on this host" >&2
    exit {install_failed_exit}
}}
[ "$got" = {expected_version} ] || {{
    echo "syq: uploaded helper has unexpected version: $got" >&2
    exit {install_failed_exit}
}}
got_id=$("$tmp" --build-identity 2>/dev/null) || {{
    echo "syq: uploaded helper does not report a build identity" >&2
    exit {install_failed_exit}
}}
[ "$got_id" = {expected_identity} ] || {{
    echo "syq: uploaded helper has unexpected identity: $got_id" >&2
    exit {install_failed_exit}
}}
if ! mv "$tmp" "$program"; then
    echo "syq: cannot install the uploaded remote helper" >&2
    exit {install_failed_exit}
fi
cleanup
trap - EXIT HUP INT TERM"#,
        target_key = target.key,
        expected_version = shell_words::quote(&expected_version),
        expected_identity = shell_words::quote(expected_identity),
        install_failed_exit = INSTALL_FAILED_EXIT,
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
        let script = download_script(target);
        assert!(script.contains(&format!(
            "/v{}/syq-linux-x86_64.gz",
            env!("CARGO_PKG_VERSION")
        )));
        assert!(script.contains(&format!(
            "/v{}/syq-release-manifest.json",
            env!("CARGO_PKG_VERSION")
        )));
        assert!(script.contains("sha256sum"));
        assert!(script.contains("local integrity verification"));
        assert!(script.contains("syq-helper-manifest-begin"));
        assert!(script.contains("syq-helper-sha256:"));
        assert!(script.contains("read -r decision"));
        assert!(!script.contains(".sha256"));
        assert!(script.contains(helper_identity()));
        assert!(script.contains("--build-identity"));
        assert!(!script.contains("--remote-helper-id"));
    }

    #[test]
    fn probe_reports_the_complete_direct_download_toolchain() {
        let command = probe_command();
        assert!(command.contains("curl"));
        assert!(command.contains("wget"));
        assert!(command.contains("sha256sum"));
        assert!(command.contains("shasum"));
        assert!(command.contains("openssl"));
        assert!(command.contains("gzip"));
        assert!(command.contains("syq-helper-tools:"));
    }

    #[test]
    fn upload_needs_no_download_verification_or_decompression_tools() {
        let target = Target::from_uname("Linux", "x86_64").unwrap();
        let script = upload_script(target);
        assert!(script.contains("cat > \"$tmp\""));
        assert!(script.contains("--build-identity"));
        assert!(!script.contains("curl"));
        assert!(!script.contains("wget"));
        assert!(!script.contains("sha256"));
        assert!(!script.contains("gzip"));
    }
}

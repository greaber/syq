//! Integration tests: local -> local copies through the built binary.

use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

struct Tmp(PathBuf);

impl Tmp {
    fn new() -> Tmp {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("syq-test-{}-{}", std::process::id(), n));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        Tmp(p)
    }
    fn path(&self, rel: &str) -> PathBuf {
        self.0.join(rel)
    }
    fn s(&self, rel: &str) -> String {
        self.path(rel).to_string_lossy().into_owned()
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        // Make everything removable again (tests chmod 000 some files).
        fn fix(p: &Path) {
            if let Ok(md) = fs::symlink_metadata(p) {
                if md.is_dir() {
                    let _ = fs::set_permissions(p, fs::Permissions::from_mode(0o755));
                    if let Ok(rd) = fs::read_dir(p) {
                        for e in rd.flatten() {
                            fix(&e.path());
                        }
                    }
                } else if md.is_file() {
                    let _ = fs::set_permissions(p, fs::Permissions::from_mode(0o644));
                }
            }
        }
        fix(&self.0);
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn syq(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(args)
        .arg("--no-progress")
        .output()
        .expect("run syq")
}

fn run_ok(args: &[&str]) -> String {
    let out = syq(args);
    assert!(
        out.status.success(),
        "syq {:?} failed: status {:?}\nstdout:\n{}\nstderr:\n{}",
        args,
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Parse "syq: transferred N files" from the summary line.
fn transferred(stdout: &str) -> u64 {
    let line = stdout
        .lines()
        .find(|l| l.starts_with("syq: transferred") || l.starts_with("syq: would transfer"))
        .unwrap_or_else(|| panic!("no summary line in {stdout:?}"));
    let after = line.split("transfer").nth(1).unwrap();
    let after = after.trim_start_matches("red").trim_start();
    let n: String = after
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == ',')
        .collect();
    n.replace(',', "").parse().unwrap()
}

fn write(p: &Path, data: &[u8]) {
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    File::create(p).unwrap().write_all(data).unwrap();
}

fn read(p: &Path) -> Vec<u8> {
    let mut v = Vec::new();
    File::open(p).unwrap().read_to_end(&mut v).unwrap();
    v
}

fn partial_files(dir: &Path) -> Vec<PathBuf> {
    fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().contains(".syq-part."))
        })
        .collect()
}

#[cfg(debug_assertions)]
fn interrupted_partial(args: &[&str], dir: &Path) -> PathBuf {
    let mut child = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(args)
        .arg("--no-progress")
        .env("SYQ_TEST_HOLD_PARTIAL_MS", "10000")
        .spawn()
        .unwrap();
    let partial = (0..300).find_map(|_| {
        let mut partials = partial_files(dir);
        if partials.len() == 1 {
            partials.pop()
        } else {
            std::thread::sleep(std::time::Duration::from_millis(10));
            None
        }
    });
    let _ = child.kill();
    let _ = child.wait();
    partial.expect("copy never created its job-scoped partial")
}

fn executable(p: &Path, body: &[u8]) {
    write(p, body);
    fs::set_permissions(p, fs::Permissions::from_mode(0o755)).unwrap();
}

/// A remote shell that executes the supplied command locally with an isolated
/// HOME.  This exercises syq's real remote launcher/server protocol without
/// touching ssh or a real remote machine.
fn fake_rsh(t: &Tmp) -> PathBuf {
    let path = t.path("fake-rsh");
    executable(
        &path,
        br#"#!/bin/sh
shift
HOME="$FAKE_REMOTE_HOME"
if [ -n "${FAKE_REMOTE_PATH:-}" ]; then
    PATH="$FAKE_REMOTE_PATH"
else
    PATH="$FAKE_REMOTE_BIN:/usr/bin:/bin"
fi
export HOME PATH
printf '%s\n' "$1" >> "$FAKE_RSH_LOG"
exec /bin/sh -c "$1"
"#,
    );
    path
}

fn remote_syq_command(t: &Tmp, rsh: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_syq"));
    cmd.args(["-e", rsh.to_str().unwrap(), "--no-tcp", "-j", "1"])
        .args(args)
        .arg("--no-progress")
        .env("FAKE_REMOTE_HOME", t.path("remote-home"))
        .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
        .env("FAKE_REMOTE_RELEASE_ARCHIVE", t.path("release.gz"))
        .env("FAKE_CURL_LOG", t.path("curl.log"))
        .env(
            "FAKE_REMOTE_RELEASE_MANIFEST",
            t.path("release-manifest.json"),
        )
        .env("FAKE_RSH_LOG", t.path("rsh.log"))
        .env("FAKE_LEGACY_LOG", t.path("legacy.log"))
        .env("XDG_CONFIG_HOME", t.path("config"))
        .env("XDG_CACHE_HOME", t.path("cache"));
    if let Ok(key) = fs::read_to_string(t.path("release-public-key")) {
        cmd.env("SYQ_TEST_RELEASE_PUBLIC_KEY", key.trim())
            .env("SYQ_TEST_RELEASE_BUILD", "1")
            .env(
                "SYQ_TEST_RELEASE_DOWNLOADS",
                "https://release.invalid/download",
            )
            .env("SYQ_TEST_FIXTURES", &t.0);
    }
    cmd
}

fn remote_syq(t: &Tmp, rsh: &Path, args: &[&str]) -> Output {
    remote_syq_command(t, rsh, args)
        .output()
        .expect("run syq through fake remote shell")
}

fn assert_output_ok(out: &Output) {
    assert!(
        out.status.success(),
        "syq failed: status {:?}\nstdout:\n{}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn cached_remote_helper(t: &Tmp) -> PathBuf {
    let identity = binary_identity("--build-identity");
    let target = match std::env::consts::ARCH {
        "x86_64" => "linux-x86_64",
        "aarch64" => "linux-aarch64",
        arch => panic!("unsupported test architecture {arch}"),
    };
    t.path(&format!(
        "remote-home/.cache/syq/helpers/{identity}-release-v1/{target}/syq"
    ))
}

fn cached_local_helper(t: &Tmp) -> PathBuf {
    let target = match std::env::consts::ARCH {
        "x86_64" => "linux-x86_64",
        "aarch64" => "linux-aarch64",
        arch => panic!("unsupported test architecture {arch}"),
    };
    t.path(&format!(
        "cache/syq/helpers/v{}/{target}/syq",
        env!("CARGO_PKG_VERSION")
    ))
}

fn binary_identity(argument: &str) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .arg(argument)
        .output()
        .unwrap();
    assert!(out.status.success());
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

#[cfg(target_os = "linux")]
fn legacy_cached_remote_helpers(t: &Tmp) -> [PathBuf; 2] {
    let target = match std::env::consts::ARCH {
        "x86_64" => "linux-x86_64",
        "aarch64" => "linux-aarch64",
        arch => panic!("unsupported test architecture {arch}"),
    };
    [
        t.path(&format!(
            "remote-home/.cache/syq/helpers/v{}-p5-download-v1/{target}/syq",
            env!("CARGO_PKG_VERSION")
        )),
        t.path(&format!(
            "remote-home/.cache/syq/helpers/v{}-p5/{target}/syq",
            env!("CARGO_PKG_VERSION")
        )),
    ]
}

#[cfg(target_os = "linux")]
fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(target_os = "linux")]
fn setup_release_bootstrap(t: &Tmp) {
    let binary_bytes = fs::read(env!("CARGO_BIN_EXE_syq")).unwrap();
    let mut encoder = GzEncoder::new(
        File::create(t.path("release.gz")).unwrap(),
        Compression::best(),
    );
    encoder.write_all(&binary_bytes).unwrap();
    encoder.finish().unwrap();
    let archive_bytes = fs::read(t.path("release.gz")).unwrap();
    let (target, asset) = match std::env::consts::ARCH {
        "x86_64" => ("linux-x86_64", "syq-linux-x86_64"),
        "aarch64" => ("linux-aarch64", "syq-linux-aarch64"),
        arch => panic!("unsupported test architecture {arch}"),
    };
    let manifest = serde_json::json!({
        "schema": 1,
        "repository": "https://github.com/greaber/syq",
        "version": env!("CARGO_PKG_VERSION"),
        "tag": format!("v{}", env!("CARGO_PKG_VERSION")),
        "helper_id": format!("v{}-p0", env!("CARGO_PKG_VERSION")),
        "artifacts": {
            (target): {
                "binary": {
                    "name": asset,
                    "sha256": sha256_hex(&binary_bytes),
                    "size": binary_bytes.len()
                },
                "archive": {
                    "name": format!("{asset}.gz"),
                    "sha256": sha256_hex(&archive_bytes),
                    "size": archive_bytes.len()
                }
            }
        },
        "installer": {"name": "install.sh", "sha256": "1".repeat(64), "size": 1},
        "homebrew_formula": {"name": "syq.rb", "sha256": "2".repeat(64), "size": 1},
        "signature_scheme": "ed25519-jcs-v1"
    });
    let signing = SigningKey::from_bytes(&[19; 32]);
    let canonical = serde_json_canonicalizer::to_vec(&manifest).unwrap();
    let signature =
        base64::engine::general_purpose::STANDARD.encode(signing.sign(&canonical).to_bytes());
    let mut manifest = manifest;
    manifest["signature"] = signature.into();
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).unwrap();
    write(&t.path("syq-release-manifest.json"), &manifest_bytes);
    write(&t.path("release-manifest.json"), &manifest_bytes);
    write(
        &t.path("release-public-key"),
        base64::engine::general_purpose::STANDARD
            .encode(signing.verifying_key().to_bytes())
            .as_bytes(),
    );
    fs::copy(t.path("release.gz"), t.path(&format!("{asset}.gz"))).unwrap();

    executable(
        &t.path("remote-bin/curl"),
        br#"#!/bin/sh
printf 'fetch\n' >> "$FAKE_CURL_LOG"
out=
url=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --output) out=$2; shift 2 ;;
        *) url=$1; shift ;;
    esac
done
case "$url" in
    *.json) cp "$FAKE_REMOTE_RELEASE_MANIFEST" "$out" ;;
    *.gz) cp "$FAKE_REMOTE_RELEASE_ARCHIVE" "$out" ;;
    *) exit 22 ;;
esac
"#,
    );
}

#[cfg(target_os = "linux")]
fn add_remote_tool(t: &Tmp, name: &str) {
    let destination = t.path(&format!("remote-bin/{name}"));
    if destination.exists() {
        return;
    }
    let source = [
        Path::new("/usr/bin").join(name),
        Path::new("/bin").join(name),
    ]
    .into_iter()
    .find(|path| path.exists())
    .unwrap_or_else(|| panic!("test host has no {name}"));
    std::os::unix::fs::symlink(source, destination).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn release_keyed_remote_helper_ignores_legacy_protocol_caches() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    let legacy_helpers = legacy_cached_remote_helpers(&t);
    for legacy_helper in &legacy_helpers {
        executable(
            legacy_helper,
            br#"#!/bin/sh
printf 'legacy helper ran\n' >> "$FAKE_LEGACY_LOG"
exit 99
"#,
        );
    }
    setup_release_bootstrap(&t);

    write(&t.path("src"), b"first");
    let remote = format!("fake:{}", t.s("dst"));
    let out = remote_syq(&t, &rsh, &["-avv", &t.s("src"), &remote]);
    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), b"first");
    assert!(cached_remote_helper(&t).is_file());
    assert!(legacy_helpers.iter().all(|helper| helper.exists()));
    assert!(!t.path("legacy.log").exists(), "legacy helper was executed");
    assert_eq!(read(&t.path("curl.log")), b"fetch\nfetch\n");
    assert!(!String::from_utf8_lossy(&out.stderr).contains("uploading this executable"));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains(&format!(
            "helper: {} (managed; installed now)",
            binary_identity("--build-identity")
        )),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let probes = fs::read_to_string(t.path("rsh.log"))
        .unwrap()
        .matches("syq-helper-target:")
        .count();
    assert_eq!(probes, 1);

    // A cache hit goes straight to the helper: no platform probe or download.
    write(&t.path("src"), b"second");
    let out = remote_syq(&t, &rsh, &["-avv", &t.s("src"), &remote]);
    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), b"second");
    assert_eq!(read(&t.path("curl.log")), b"fetch\nfetch\n");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains(&format!(
            "helper: {} (managed helper cache)",
            binary_identity("--build-identity")
        )),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let probes = fs::read_to_string(t.path("rsh.log"))
        .unwrap()
        .matches("syq-helper-target:")
        .count();
    assert_eq!(probes, 1, "cache hit should not probe the platform again");
}

#[cfg(target_os = "linux")]
#[test]
fn remote_helper_integrity_mismatch_warns_and_uploads_verified_binary() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    setup_release_bootstrap(&t);
    let mut corrupt = read(&t.path("release.gz"));
    let middle = corrupt.len() / 2;
    corrupt[middle] ^= 1;
    write(&t.path("corrupt-release.gz"), &corrupt);
    let corrupt_digest = sha256_hex(&corrupt);

    write(&t.path("src"), b"integrity fallback");
    let remote = format!("fake:{}", t.s("dst"));
    let mut cmd = remote_syq_command(&t, &rsh, &["-a", "-q", &t.s("src"), &remote]);
    let out = cmd
        .env("FAKE_REMOTE_RELEASE_ARCHIVE", t.path("corrupt-release.gz"))
        .output()
        .unwrap();

    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), b"integrity fallback");
    assert_eq!(
        read(&cached_remote_helper(&t)),
        read(Path::new(env!("CARGO_BIN_EXE_syq")))
    );
    assert_eq!(
        read(&cached_local_helper(&t)),
        read(Path::new(env!("CARGO_BIN_EXE_syq")))
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("remote helper download failed integrity verification"),
        "{stderr}"
    );
    assert!(stderr.contains("expected SHA-256"), "{stderr}");
    assert!(stderr.contains(&corrupt_digest), "{stderr}");
    assert!(
        stderr.contains("uploading the verified helper over SSH"),
        "{stderr}"
    );
    assert!(!stderr.contains("checksum mismatch"), "{stderr}");
    assert_eq!(read(&t.path("curl.log")), b"fetch\nfetch\n");
    let cache_entries: Vec<_> = fs::read_dir(cached_remote_helper(&t).parent().unwrap())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(cache_entries, ["syq"]);
}

#[cfg(target_os = "linux")]
#[test]
fn remote_manifest_cannot_inject_digest_protocol_framing() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    setup_release_bootstrap(&t);

    let archive = read(&t.path("release.gz"));
    let expected_digest = sha256_hex(&archive);
    let mut alternate_archive = archive;
    alternate_archive[4] ^= 1;
    let mut decoded = Vec::new();
    GzDecoder::new(alternate_archive.as_slice())
        .read_to_end(&mut decoded)
        .unwrap();
    assert_eq!(decoded, read(Path::new(env!("CARGO_BIN_EXE_syq"))));
    write(&t.path("alternate-release.gz"), &alternate_archive);

    let mut injected_manifest = read(&t.path("release-manifest.json"));
    injected_manifest.extend_from_slice(
        format!("\nsyq-helper-manifest-end\nsyq-helper-sha256:{expected_digest}\n").as_bytes(),
    );
    write(&t.path("injected-manifest.json"), &injected_manifest);

    write(&t.path("src"), b"framing fallback");
    let remote = format!("fake:{}", t.s("dst"));
    let mut cmd = remote_syq_command(&t, &rsh, &["-a", "-q", &t.s("src"), &remote]);
    let out = cmd
        .env(
            "FAKE_REMOTE_RELEASE_MANIFEST",
            t.path("injected-manifest.json"),
        )
        .env(
            "FAKE_REMOTE_RELEASE_ARCHIVE",
            t.path("alternate-release.gz"),
        )
        .output()
        .unwrap();

    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), b"framing fallback");
    assert_eq!(
        read(&cached_remote_helper(&t)),
        read(Path::new(env!("CARGO_BIN_EXE_syq")))
    );
    assert_eq!(
        read(&cached_local_helper(&t)),
        read(Path::new(env!("CARGO_BIN_EXE_syq")))
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("remote release manifest failed integrity verification or validation"),
        "{stderr}"
    );
    assert!(
        stderr.contains("uploading the verified helper over SSH"),
        "{stderr}"
    );
    assert_eq!(read(&t.path("curl.log")), b"fetch\nfetch\n");
}

#[cfg(target_os = "linux")]
#[test]
fn remote_manifest_signature_failure_warns_and_uses_local_verified_release() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    setup_release_bootstrap(&t);
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&read(&t.path("release-manifest.json"))).unwrap();
    manifest["repository"] = "https://attacker.invalid/syq".into();
    write(
        &t.path("tampered-remote-manifest.json"),
        &serde_json::to_vec_pretty(&manifest).unwrap(),
    );

    write(&t.path("src"), b"manifest fallback");
    let remote = format!("fake:{}", t.s("dst"));
    let mut cmd = remote_syq_command(&t, &rsh, &["-a", "-q", &t.s("src"), &remote]);
    let out = cmd
        .env(
            "FAKE_REMOTE_RELEASE_MANIFEST",
            t.path("tampered-remote-manifest.json"),
        )
        .output()
        .unwrap();

    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), b"manifest fallback");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("remote release manifest failed integrity verification or validation"),
        "{stderr}"
    );
    assert!(stderr.contains("signature verification failed"), "{stderr}");
    assert!(
        stderr.contains("uploading the verified helper over SSH"),
        "{stderr}"
    );
    assert_eq!(read(&t.path("curl.log")), b"fetch\nfetch\n");
}

#[cfg(target_os = "linux")]
#[test]
fn failed_remote_download_falls_back_to_verified_upload() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    setup_release_bootstrap(&t);
    executable(
        &t.path("remote-bin/curl"),
        br#"#!/bin/sh
printf 'fetch\n' >> "$FAKE_CURL_LOG"
exit 22
"#,
    );

    write(&t.path("src"), b"download fallback");
    let remote = format!("fake:{}", t.s("dst"));
    let out = remote_syq(&t, &rsh, &["-a", &t.s("src"), &remote]);

    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), b"download fallback");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("remote download unavailable"), "{stderr}");
    assert!(
        stderr.contains("uploading the verified helper over SSH"),
        "{stderr}"
    );
    assert!(!stderr.contains("warning:"), "{stderr}");
    assert_eq!(read(&t.path("curl.log")), b"fetch\n");
}

#[cfg(target_os = "linux")]
#[test]
fn missing_remote_hasher_skips_download_and_uploads_verified_binary() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    setup_release_bootstrap(&t);
    for tool in ["sh", "uname", "mkdir", "rm", "cat", "chmod", "mv", "gzip"] {
        add_remote_tool(&t, tool);
    }

    write(&t.path("src"), b"capability fallback");
    let remote = format!("fake:{}", t.s("dst"));
    let mut cmd = remote_syq_command(&t, &rsh, &["-a", &t.s("src"), &remote]);
    let out = cmd
        .env("FAKE_REMOTE_PATH", t.path("remote-bin"))
        .output()
        .unwrap();

    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), b"capability fallback");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("remote download prerequisites unavailable"),
        "{stderr}"
    );
    assert!(
        stderr.contains("uploading the verified helper over SSH"),
        "{stderr}"
    );
    assert!(!t.path("curl.log").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn broken_remote_hasher_falls_back_to_verified_upload() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    setup_release_bootstrap(&t);
    executable(
        &t.path("remote-bin/sha256sum"),
        br#"#!/bin/sh
exit 1
"#,
    );

    write(&t.path("src"), b"hasher fallback");
    let remote = format!("fake:{}", t.s("dst"));
    let out = remote_syq(&t, &rsh, &["-a", &t.s("src"), &remote]);

    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), b"hasher fallback");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("remote helper hashing with sha256sum failed"),
        "{stderr}"
    );
    assert!(
        stderr.contains("uploading the verified helper over SSH"),
        "{stderr}"
    );
    assert_eq!(read(&t.path("curl.log")), b"fetch\nfetch\n");
}

#[cfg(target_os = "linux")]
#[test]
fn corrupted_local_helper_cache_is_discarded_and_refetched() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    setup_release_bootstrap(&t);
    executable(
        &t.path("remote-bin/curl"),
        br#"#!/bin/sh
exit 22
"#,
    );
    let mut corrupt = read(Path::new(env!("CARGO_BIN_EXE_syq")));
    let middle = corrupt.len() / 2;
    corrupt[middle] ^= 1;
    fs::create_dir_all(cached_local_helper(&t).parent().unwrap()).unwrap();
    write(&cached_local_helper(&t), &corrupt);

    write(&t.path("src"), b"local cache repair");
    let remote = format!("fake:{}", t.s("dst"));
    let out = remote_syq(&t, &rsh, &["-a", "-q", &t.s("src"), &remote]);

    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), b"local cache repair");
    assert_eq!(
        read(&cached_local_helper(&t)),
        read(Path::new(env!("CARGO_BIN_EXE_syq")))
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("cached remote helper failed integrity verification"),
        "{stderr}"
    );
    assert!(stderr.contains("discarding it"), "{stderr}");
}

#[cfg(target_os = "linux")]
#[test]
fn remote_download_write_failure_does_not_retry_with_upload() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    setup_release_bootstrap(&t);
    executable(
        &t.path("remote-bin/curl"),
        br#"#!/bin/sh
printf 'fetch\n' >> "$FAKE_CURL_LOG"
exit 23
"#,
    );

    write(&t.path("src"), b"must fail");
    let remote = format!("fake:{}", t.s("dst"));
    let out = remote_syq(&t, &rsh, &["-a", &t.s("src"), &remote]);

    assert!(
        !out.status.success(),
        "remote write failure unexpectedly succeeded"
    );
    assert!(!t.path("dst").exists());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("remote helper download could not write its temporary file"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("uploading the verified helper"),
        "{stderr}"
    );
    assert_eq!(read(&t.path("curl.log")), b"fetch\n");
    assert!(!cached_local_helper(&t).exists());
}

#[test]
fn development_build_refuses_managed_remote_bootstrap() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);

    write(&t.path("src"), b"offline");
    let remote = format!("fake:{}", t.s("dst"));
    let out = remote_syq(&t, &rsh, &["-a", &t.s("src"), &remote]);
    assert!(!out.status.success(), "bootstrap unexpectedly succeeded");
    assert!(!t.path("dst").exists());
    assert!(!t.path("remote-home/.cache/syq/helpers").exists());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(
            "managed remote bootstrap is only available from an official syq release build"
        ),
        "{stderr}"
    );
    assert!(!stderr.contains("uploading"), "{stderr}");
}

#[test]
fn no_bootstrap_uses_remote_path_without_managed_cache() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    fs::create_dir_all(t.path("remote-bin")).unwrap();
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_syq"), t.path("remote-bin/syq")).unwrap();

    write(&t.path("src"), b"preinstalled");
    let remote = format!("fake:{}", t.s("dst"));
    let out = remote_syq(&t, &rsh, &["-a", "--no-bootstrap", &t.s("src"), &remote]);
    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), b"preinstalled");
    assert!(!t.path("remote-home/.cache/syq/helpers").exists());
}

#[test]
fn remote_retained_basis_handles_matching_and_changed_files() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    fs::create_dir_all(t.path("remote-bin")).unwrap();
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_syq"), t.path("remote-bin/syq")).unwrap();
    let original = vec![b'a'; 5 * 1024 * 1024];
    let mut changed = original.clone();
    changed[2 * 1024 * 1024] = b'b';
    write(&t.path("src"), &original);
    write(&t.path("dst"), &original);
    set_mtime(&t.path("src"), 1_600_000_001);
    set_mtime(&t.path("dst"), 1_600_000_000);
    let inode = fs::metadata(t.path("dst")).unwrap().ino();
    let remote = format!("fake:{}", t.s("dst"));

    let matching = remote_syq(&t, &rsh, &["-ac", "--no-bootstrap", &t.s("src"), &remote]);
    assert_output_ok(&matching);
    assert_eq!(fs::metadata(t.path("dst")).unwrap().ino(), inode);

    write(&t.path("src"), &changed);
    set_mtime(&t.path("src"), 1_600_000_002);
    let repair = remote_syq(&t, &rsh, &["-a", "--no-bootstrap", &t.s("src"), &remote]);
    assert_output_ok(&repair);
    assert_eq!(read(&t.path("dst")), changed);
    assert!(partial_files(&t.0).is_empty());
}

#[test]
fn double_verbose_dry_run_reports_tcp_without_extra_connection() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    write(&t.path("src"), b"diagnose");
    let remote = format!("127.0.0.1:{}", t.s("dst"));

    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .arg("-e")
        .arg(&rsh)
        .arg("--syq-path")
        .arg(env!("CARGO_BIN_EXE_syq"))
        .args(["--dry-run", "-vv", "-a"])
        .arg(t.s("src"))
        .arg(&remote)
        .arg("--no-progress")
        .env("FAKE_REMOTE_HOME", t.path("remote-home"))
        .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
        .env("FAKE_RSH_LOG", t.path("rsh.log"))
        .env("XDG_CONFIG_HOME", t.path("config"))
        .output()
        .expect("run double-verbose dry-run over TCP");

    assert_output_ok(&out);
    assert!(!t.path("dst").exists());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("control: connected via fake-rsh; remote linux-"),
        "{stderr}"
    );
    assert!(
        stderr.contains(&format!(
            "helper: {} (--syq-path)",
            binary_identity("--build-identity")
        )),
        "{stderr}"
    );
    assert!(
        stderr.contains("TCP ") && stderr.contains(": reachable"),
        "{stderr}"
    );
    assert!(
        stderr.contains(
            "transport: encrypted TCP planned for a real transfer (reachability preflight passed)"
        ),
        "{stderr}"
    );
    assert!(
        stderr.contains(
            "a real transfer would start with 16 connections (auto-tuned); dry-run starts no workers"
        ),
        "{stderr}"
    );
    assert_eq!(
        fs::read_to_string(t.path("rsh.log"))
            .unwrap()
            .lines()
            .count(),
        1,
        "-vv must not add a remote-shell connection during dry-run"
    );
}

#[test]
fn double_verbose_dry_run_reports_ssh_fallback_without_extra_connection() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    executable(
        &t.path("remote-bin/ip"),
        b"#!/bin/sh\nprintf '2: eth9 inet 192.0.2.1/24 scope global eth9\\n'\n",
    );
    write(&t.path("src"), b"fallback");
    let remote = format!("diagnostic.invalid:{}", t.s("dst"));

    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .arg("-e")
        .arg(&rsh)
        .arg("--syq-path")
        .arg(env!("CARGO_BIN_EXE_syq"))
        .args(["--dry-run", "-vv", "-a"])
        .arg(t.s("src"))
        .arg(&remote)
        .arg("--no-progress")
        .env("FAKE_REMOTE_HOME", t.path("remote-home"))
        .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
        .env("FAKE_RSH_LOG", t.path("rsh.log"))
        .env("XDG_CONFIG_HOME", t.path("config"))
        .output()
        .expect("run double-verbose dry-run with TCP fallback");

    assert_output_ok(&out);
    assert!(!t.path("dst").exists());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("TCP 192.0.2.1:") && stderr.contains("not reachable"),
        "{stderr}"
    );
    assert!(
        stderr.contains("transport: SSH planned for a real transfer (TCP unavailable:"),
        "{stderr}"
    );
    assert!(
        stderr.contains(
            "a real transfer would start with 8 connections (auto-tuned); dry-run starts no workers"
        ),
        "{stderr}"
    );
    assert_eq!(
        fs::read_to_string(t.path("rsh.log"))
            .unwrap()
            .lines()
            .count(),
        1,
        "-vv must not verify fallback with an extra connection"
    );
}

#[test]
fn single_verbose_keeps_file_listing_semantics() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    write(&t.path("src"), b"listed");
    let remote = format!("fake:{}", t.s("dst"));

    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .arg("-e")
        .arg(&rsh)
        .arg("--syq-path")
        .arg(env!("CARGO_BIN_EXE_syq"))
        .args(["--no-tcp", "-v", "-a", "-j", "1"])
        .arg(t.s("src"))
        .arg(&remote)
        .arg("--no-progress")
        .env("FAKE_REMOTE_HOME", t.path("remote-home"))
        .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
        .env("FAKE_RSH_LOG", t.path("rsh.log"))
        .env("XDG_CONFIG_HOME", t.path("config"))
        .output()
        .expect("run single-verbose remote copy");

    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), b"listed");
    assert!(String::from_utf8_lossy(&out.stdout).contains("src"));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("  control:"), "{stderr}");
    assert!(!stderr.contains("syq: concurrency:"), "{stderr}");
}

#[test]
fn tcp_copy_auto_tuning_starts_with_sixteen_connections() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    write(&t.path("src"), b"tcp default");
    let remote = format!("127.0.0.1:{}", t.s("dst"));

    let dry = Command::new(env!("CARGO_BIN_EXE_syq"))
        .arg("-e")
        .arg(&rsh)
        .arg("--syq-path")
        .arg(env!("CARGO_BIN_EXE_syq"))
        .args(["--dry-run", "-a"])
        .arg(t.s("src"))
        .arg(&remote)
        .arg("--no-progress")
        .env("FAKE_REMOTE_HOME", t.path("remote-home"))
        .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
        .env("FAKE_RSH_LOG", t.path("rsh.log"))
        .env("XDG_CONFIG_HOME", t.path("config"))
        .output()
        .expect("dry-run syq over encrypted TCP through fake remote shell");
    assert_output_ok(&dry);
    assert!(!t.path("dst").exists());
    let stdout = String::from_utf8_lossy(&dry.stdout);
    assert!(
        stdout.contains("route: encrypted TCP to 127.0.0.1; 16 initial connections (auto-tuned)"),
        "{stdout}"
    );

    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .arg("-e")
        .arg(&rsh)
        .arg("--syq-path")
        .arg(env!("CARGO_BIN_EXE_syq"))
        .args(["--tcp-plain", "--stats", "-avv"])
        .arg(t.s("src"))
        .arg(&remote)
        .arg("--no-progress")
        .env("FAKE_REMOTE_HOME", t.path("remote-home"))
        .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
        .env("FAKE_RSH_LOG", t.path("rsh.log"))
        .env("XDG_CONFIG_HOME", t.path("config"))
        .output()
        .expect("run syq over TCP through fake remote shell");

    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), b"tcp default");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("connections: auto: settled at 16 (path 16, peak 16)"),
        "{stdout}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("transport: plaintext TCP planned (reachability preflight passed)"),
        "{stderr}"
    );
    assert!(
        stderr.contains("concurrency: starting with 16 connections (auto-tuned)"),
        "{stderr}"
    );
}

fn set_mtime(p: &Path, secs: i64) {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let c = CString::new(p.as_os_str().as_bytes()).unwrap();
    let ts = [
        libc::timespec {
            tv_sec: secs,
            tv_nsec: 0,
        },
        libc::timespec {
            tv_sec: secs,
            tv_nsec: 0,
        },
    ];
    let r = unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            c.as_ptr(),
            ts.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    assert_eq!(r, 0, "utimensat {}", p.display());
}

fn mkfifo(p: &Path) {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let c = CString::new(p.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
}

/// Cheap deterministic pseudo-random bytes.
fn prng(len: usize, seed: u64) -> Vec<u8> {
    let mut v = vec![0u8; len];
    let mut x = seed
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407)
        | 1;
    for chunk in v.chunks_mut(8) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let b = x.to_le_bytes();
        chunk.copy_from_slice(&b[..chunk.len()]);
    }
    v
}

/// Assert two trees are identical in kind, size, content, mode, mtime (seconds) and link targets.
fn assert_same_tree(a: &Path, b: &Path) {
    let ma = fs::symlink_metadata(a).unwrap_or_else(|e| panic!("{}: {e}", a.display()));
    let mb = fs::symlink_metadata(b).unwrap_or_else(|e| panic!("{}: {e}", b.display()));
    assert_eq!(
        ma.file_type(),
        mb.file_type(),
        "kind differs: {} vs {}",
        a.display(),
        b.display()
    );
    if ma.file_type().is_symlink() {
        assert_eq!(
            fs::read_link(a).unwrap(),
            fs::read_link(b).unwrap(),
            "link target {}",
            a.display()
        );
        return;
    }
    assert_eq!(
        ma.mode() & 0o7777,
        mb.mode() & 0o7777,
        "mode differs: {}",
        a.display()
    );
    assert_eq!(ma.mtime(), mb.mtime(), "mtime differs: {}", a.display());
    if ma.is_file() {
        assert_eq!(ma.len(), mb.len(), "size differs: {}", a.display());
        assert!(read(a) == read(b), "content differs: {}", a.display());
    } else if ma.is_dir() {
        let mut ea: Vec<_> = fs::read_dir(a)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        let mut eb: Vec<_> = fs::read_dir(b)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        ea.sort();
        eb.sort();
        assert_eq!(
            ea,
            eb,
            "directory listing differs: {} vs {}",
            a.display(),
            b.display()
        );
        for name in ea {
            assert_same_tree(&a.join(&name), &b.join(&name));
        }
    }
}

/// A representative source tree with all the entry kinds we care about.
fn make_tree(root: &Path) {
    write(&root.join("hello.txt"), b"hello\n");
    write(&root.join("a/med.bin"), &prng(3 * 1024 * 1024 + 17, 1));
    for i in 0..30 {
        write(
            &root.join(format!("a/b/f{i}")),
            &prng((i * 977) % 5000, i as u64),
        );
    }
    write(&root.join("a/b/c/zero"), b"");
    fs::create_dir_all(root.join("empty")).unwrap();
    std::os::unix::fs::symlink("hello.txt", root.join("link")).unwrap();
    std::os::unix::fs::symlink("/nonexistent/target", root.join("badlink")).unwrap();
    mkfifo(&root.join("fifo"));
    fs::set_permissions(root.join("hello.txt"), fs::Permissions::from_mode(0o640)).unwrap();
    fs::set_permissions(root.join("a"), fs::Permissions::from_mode(0o750)).unwrap();
    fs::set_permissions(root.join("a/med.bin"), fs::Permissions::from_mode(0o600)).unwrap();
    let t = 1_577_934_245; // 2020-01-02 03:04:05 UTC
    set_mtime(&root.join("hello.txt"), t);
    set_mtime(&root.join("a/b/c/zero"), t + 1);
    set_mtime(&root.join("link"), t + 2);
    set_mtime(&root.join("a/b/c"), t + 3);
    set_mtime(&root.join("a/b"), t + 4);
    set_mtime(&root.join("a"), t + 5);
    set_mtime(&root.join("empty"), t + 6);
    set_mtime(root, t + 7);
}

#[test]
fn dir_into_missing_dest_creates_basename() {
    let t = Tmp::new();
    make_tree(&t.path("src"));
    run_ok(&["-a", &t.s("src"), &t.s("dst")]);
    assert!(t.path("dst/src").is_dir(), "expected dst/src to be created");
    assert_same_tree(&t.path("src"), &t.path("dst/src"));
}

#[test]
fn trailing_slash_copies_contents() {
    let t = Tmp::new();
    make_tree(&t.path("src"));
    run_ok(&["-a", &t.s("src/"), &t.s("dst")]);
    assert!(t.path("dst/hello.txt").is_file());
    assert!(!t.path("dst/src").exists());
    assert_same_tree(&t.path("src"), &t.path("dst"));
}

#[test]
fn dir_into_existing_dir() {
    let t = Tmp::new();
    make_tree(&t.path("src"));
    fs::create_dir(t.path("dst")).unwrap();
    run_ok(&["-a", &t.s("src"), &t.s("dst")]);
    assert_same_tree(&t.path("src"), &t.path("dst/src"));
}

#[test]
fn single_file_to_new_name() {
    let t = Tmp::new();
    write(&t.path("src/f.txt"), b"data");
    set_mtime(&t.path("src/f.txt"), 1_600_000_000);
    run_ok(&["-a", &t.s("src/f.txt"), &t.s("out.txt")]);
    assert_eq!(read(&t.path("out.txt")), b"data");
    assert_same_tree(&t.path("src/f.txt"), &t.path("out.txt"));
}

#[test]
fn single_file_into_existing_dir() {
    let t = Tmp::new();
    write(&t.path("src/f.txt"), b"data");
    fs::create_dir(t.path("dst")).unwrap();
    run_ok(&["-a", &t.s("src/f.txt"), &t.s("dst")]);
    assert_eq!(read(&t.path("dst/f.txt")), b"data");
    run_ok(&["-a", &t.s("src/f.txt"), &t.s("dst2/")]);
    assert_eq!(read(&t.path("dst2/f.txt")), b"data");
}

#[test]
fn multiple_sources_into_new_dest() {
    let t = Tmp::new();
    write(&t.path("src/f.txt"), b"data");
    write(&t.path("src/d/x"), b"x");
    write(&t.path("src/d/y/z"), b"z");
    run_ok(&["-a", &t.s("src/f.txt"), &t.s("src/d"), &t.s("dst")]);
    assert!(t.path("dst").is_dir());
    assert_eq!(read(&t.path("dst/f.txt")), b"data");
    assert_same_tree(&t.path("src/d"), &t.path("dst/d"));
}

#[test]
fn multiple_sources_require_dir_dest() {
    let t = Tmp::new();
    write(&t.path("src/f.txt"), b"data");
    write(&t.path("src/g.txt"), b"data");
    write(&t.path("dst"), b"a file");
    let out = syq(&["-a", &t.s("src/f.txt"), &t.s("src/g.txt"), &t.s("dst")]);
    assert!(!out.status.success());
    assert_eq!(read(&t.path("dst")), b"a file");
}

#[test]
fn metadata_preserved_with_archive() {
    let t = Tmp::new();
    make_tree(&t.path("src"));
    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    let d = t.path("dst");
    // Explicit spot checks in addition to the tree comparison.
    let md = fs::metadata(d.join("hello.txt")).unwrap();
    assert_eq!(md.mode() & 0o777, 0o640);
    assert_eq!(md.mtime(), 1_577_934_245);
    assert_eq!(fs::metadata(d.join("a")).unwrap().mode() & 0o777, 0o750);
    assert_eq!(
        fs::read_link(d.join("badlink")).unwrap(),
        PathBuf::from("/nonexistent/target")
    );
    assert_eq!(
        fs::read_link(d.join("link")).unwrap(),
        PathBuf::from("hello.txt")
    );
    assert!(std::os::unix::fs::FileTypeExt::is_fifo(
        &fs::symlink_metadata(d.join("fifo")).unwrap().file_type()
    ));
    assert_eq!(fs::metadata(d.join("a/b/c/zero")).unwrap().len(), 0);
    assert!(d.join("empty").is_dir());
    assert_eq!(fs::read_dir(d.join("empty")).unwrap().count(), 0);
    // Directory mtimes survive their children being written.
    assert_eq!(
        fs::metadata(d.join("a")).unwrap().mtime(),
        1_577_934_245 + 5
    );
    assert_eq!(
        fs::metadata(d.join("a/b")).unwrap().mtime(),
        1_577_934_245 + 4
    );
    assert_eq!(
        fs::metadata(d.join("a/b/c")).unwrap().mtime(),
        1_577_934_245 + 3
    );
    assert_eq!(
        fs::metadata(d.join("empty")).unwrap().mtime(),
        1_577_934_245 + 6
    );
    assert_eq!(fs::metadata(&d).unwrap().mtime(), 1_577_934_245 + 7);
    assert_same_tree(&t.path("src"), &d);
}

#[test]
fn rerun_transfers_nothing() {
    let t = Tmp::new();
    make_tree(&t.path("src"));
    let out = run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    assert!(transferred(&out) > 0);
    let out = run_ok(&["-av", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(
        transferred(&out),
        0,
        "second run should transfer nothing: {out}"
    );
    assert_same_tree(&t.path("src"), &t.path("dst"));
}

#[cfg(debug_assertions)]
#[test]
fn resume_from_partial() {
    let t = Tmp::new();
    let data = prng(6 * 1024 * 1024 + 123, 42);
    write(&t.path("src/big.bin"), &data);
    set_mtime(&t.path("src/big.bin"), 1_600_000_000);
    fs::create_dir_all(t.path("dst")).unwrap();
    let src = t.s("src/big.bin");
    let dst = t.s("dst/");
    let args = ["-a", "--block-size", "1M", "--bwlimit", "1G", &src, &dst];
    // Fake an interrupted transfer: first half present, rest preallocated.
    let partial = interrupted_partial(&args, &t.path("dst"));
    {
        let f = File::create(&partial).unwrap();
        (&f).write_all(&data[..data.len() / 2]).unwrap();
        f.set_len(data.len() as u64).unwrap();
    }
    let out = run_ok(&args);
    assert!(read(&t.path("dst/big.bin")) == data);
    assert!(!partial.exists(), "partial should be gone after finalize");
    assert_same_tree(&t.path("src/big.bin"), &t.path("dst/big.bin"));
    // Roughly half should have been reused.
    assert!(out.contains("unchanged"), "{out}");
}

#[cfg(debug_assertions)]
#[test]
fn checksum_toggle_reuses_the_same_partial() {
    let t = Tmp::new();
    let data = prng(6 * 1024 * 1024, 43);
    write(&t.path("src"), &data);
    set_mtime(&t.path("src"), 1_600_000_000);
    let src = t.s("src");
    let dst = t.s("dst");
    let initial = ["-a", "--block-size", "1M", "--bwlimit", "1G", &src, &dst];
    let partial = interrupted_partial(&initial, &t.0);

    run_ok(&["-ac", "--block-size", "1M", "--bwlimit", "1G", &src, &dst]);

    assert_eq!(read(&t.path("dst")), data);
    assert!(
        !partial.exists(),
        "changing only -c must not strand the resumable partial"
    );
    assert!(partial_files(&t.0).is_empty());
}

#[test]
fn checksum_repairs_silent_corruption() {
    let t = Tmp::new();
    let data = prng(5 * 1024 * 1024, 7);
    write(&t.path("src/f.bin"), &data);
    set_mtime(&t.path("src/f.bin"), 1_600_000_000);
    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    // Corrupt one byte in the middle, keeping size and mtime.
    let mut bad = data.clone();
    bad[2_500_000] ^= 0xff;
    write(&t.path("dst/f.bin"), &bad);
    set_mtime(&t.path("dst/f.bin"), 1_600_000_000);

    let out = run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(transferred(&out), 0, "quick check should skip: {out}");
    assert!(
        read(&t.path("dst/f.bin")) == bad,
        "without -c the file must be left alone"
    );

    let out = run_ok(&["-ac", "--block-size", "1M", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(transferred(&out), 1, "{out}");
    assert!(read(&t.path("dst/f.bin")) == data, "-c should repair");
    assert!(
        out.contains("(1.00 MiB)"),
        "only one block should be resent: {out}"
    );
    assert_same_tree(&t.path("src"), &t.path("dst"));
}

#[test]
fn verify_only_detects_differences() {
    let t = Tmp::new();
    make_tree(&t.path("src"));
    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    let out = syq(&["-a", "--verify-only", &t.s("src/"), &t.s("dst/")]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let mut bad = read(&t.path("dst/a/med.bin"));
    bad[1000] ^= 1;
    write(&t.path("dst/a/med.bin"), &bad);
    set_mtime(
        &t.path("dst/a/med.bin"),
        fs::metadata(t.path("src/a/med.bin")).unwrap().mtime(),
    );
    fs::remove_file(t.path("dst/hello.txt")).unwrap();

    let out = syq(&["-a", "--verify-only", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(out.status.code(), Some(23));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("DIFFERS a/med.bin"), "{err}");
    assert!(err.contains("MISSING hello.txt"), "{err}");
    // verify-only must not modify anything
    assert!(read(&t.path("dst/a/med.bin")) == bad);
    assert!(!t.path("dst/hello.txt").exists());
}

#[test]
fn hash_errors_do_not_desynchronize_worker_connections() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }

    let t = Tmp::new();
    write(&t.path("src/bad"), &vec![b'b'; 8192]);
    write(&t.path("src/good"), &vec![b'g'; 4096]);
    write(&t.path("dst/bad"), &vec![b'x'; 8192]);
    write(&t.path("dst/good"), &vec![b'x'; 4096]);
    fs::set_permissions(t.path("src/bad"), fs::Permissions::from_mode(0o000)).unwrap();

    // Largest-first scheduling makes the unreadable file fail first. The
    // receiver still answers its already-issued hash request; that response
    // must be drained before this worker proceeds to `good`.
    let copy = syq(&["-a", "-c", "-j", "1", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(copy.status.code(), Some(23));
    let copy_stderr = String::from_utf8_lossy(&copy.stderr);
    assert!(
        !copy_stderr.contains("unexpected response"),
        "{copy_stderr}"
    );
    assert_eq!(read(&t.path("dst/good")), vec![b'g'; 4096]);

    // Verification has the same paired-request shape and must likewise keep
    // processing the connection after the source-side error.
    let verify = syq(&[
        "-a",
        "--verify-only",
        "-v",
        "-j",
        "1",
        &t.s("src/"),
        &t.s("dst/"),
    ]);
    assert_eq!(verify.status.code(), Some(23));
    let verify_stderr = String::from_utf8_lossy(&verify.stderr);
    assert!(
        !verify_stderr.contains("unexpected response"),
        "{verify_stderr}"
    );
    assert!(
        String::from_utf8_lossy(&verify.stdout).contains("ok      good"),
        "{}",
        String::from_utf8_lossy(&verify.stdout)
    );
}

#[cfg(debug_assertions)]
#[test]
fn large_file_parallel_chunks() {
    let t = Tmp::new();
    let data = prng(200 * 1024 * 1024 + 4321, 99);
    write(&t.path("src/huge.bin"), &data);
    set_mtime(&t.path("src/huge.bin"), 1_600_000_000);
    run_ok(&[
        "-a",
        "-j",
        "8",
        "--block-size",
        "1M",
        "--min-split",
        "2M",
        &t.s("src/"),
        &t.s("dst/"),
    ]);
    assert!(read(&t.path("dst/huge.bin")) == data);
    assert_same_tree(&t.path("src/huge.bin"), &t.path("dst/huge.bin"));
    assert!(partial_files(&t.path("dst")).is_empty());
    // And partial resume of the same big file with parallel chunks.
    let src = t.s("src/");
    let dst = t.s("dst/");
    let args = [
        "-a",
        "-j",
        "8",
        "--block-size",
        "1M",
        "--min-split",
        "2M",
        "--bwlimit",
        "1G",
        &src,
        &dst,
    ];
    fs::remove_file(t.path("dst/huge.bin")).unwrap();
    let partial = interrupted_partial(&args, &t.path("dst"));
    {
        let f = File::create(&partial).unwrap();
        (&f).write_all(&data[..50 * 1024 * 1024]).unwrap();
        f.set_len(data.len() as u64).unwrap();
    }
    run_ok(&args);
    assert!(read(&t.path("dst/huge.bin")) == data);
}

#[test]
fn bwlimit_is_aggregate_across_workers() {
    let t = Tmp::new();
    for i in 0..4 {
        write(
            &t.path(&format!("src/{i}.bin")),
            &prng(512 * 1024, i as u64 + 100),
        );
    }

    // Four independent files keep four workers active. At 1 MiB/s, their
    // aggregate 2 MiB must take about two seconds (minus the initial burst). A
    // mistakenly per-worker limiter would finish in well under one second.
    let start = std::time::Instant::now();
    run_ok(&[
        "-a",
        "-j",
        "4",
        "--bwlimit",
        "1M",
        &t.s("src/"),
        &t.s("dst/"),
    ]);
    let elapsed = start.elapsed();
    assert!(
        elapsed >= std::time::Duration::from_millis(1600),
        "aggregate 2 MiB copy completed too quickly: {elapsed:?}"
    );
    assert_same_tree(&t.path("src"), &t.path("dst"));
}

#[test]
fn bwlimit_rejects_invalid_rates() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"x");
    let out = syq(&["-a", "--bwlimit", "fast", &t.s("src/"), &t.s("dst/")]);
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("bad --bwlimit"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn dry_run_creates_nothing() {
    let t = Tmp::new();
    make_tree(&t.path("src"));
    let out = run_ok(&["-an", &t.s("src"), &t.s("dst")]);
    assert!(
        !t.path("dst").exists(),
        "dry run must not create the destination"
    );
    assert!(out.contains("syq: dry-run summary"), "{out}");
    assert!(out.contains("regular files"), "{out}");
    assert!(out.contains("directories"), "{out}");
    assert!(out.contains("symlinks"), "{out}");
    assert!(out.contains("special file"), "{out}");
    assert!(out.contains("logical data:"), "{out}");
}

#[test]
fn dry_run_reports_typed_preflight_summary() {
    let t = Tmp::new();
    write(&t.path("src/send"), b"new");
    write(&t.path("src/same"), b"same");
    write(&t.path("src/too-big"), b"123456");
    write(&t.path("src/skip.log"), b"ignored");
    write(&t.path("dst/same"), b"same");
    write(&t.path("dst/extra"), b"delete me");
    set_mtime(&t.path("src/same"), 1_600_000_000);
    set_mtime(&t.path("dst/same"), 1_600_000_000);
    set_mtime(&t.path("src"), 1_600_000_100);
    set_mtime(&t.path("dst"), 1_600_000_100);

    let out = run_ok(&[
        "-an",
        "--delete",
        "--max-size",
        "5",
        "-i",
        "*.log",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert!(out.contains("syq: dry-run summary"), "{out}");
    assert!(
        out.contains(&format!(
            "mapping: {} -> {} (directory contents)",
            t.s("src/"),
            t.s("dst")
        )),
        "{out}"
    );
    assert!(out.contains("changes: 1 regular file"), "{out}");
    assert!(
        out.contains(
            "logical data: 3 B in 1 file needing content work (upper bound); 4 B in 1 file with unchanged content"
        ),
        "{out}"
    );
    assert!(
        out.contains("exclusions: 1 path/subtree pruned by ignore rules; 1 other entry"),
        "{out}"
    );
    assert!(
        out.contains("deletions: 1 entry planned after a successful copy"),
        "{out}"
    );
    assert!(
        out.contains("route: local filesystem; 32 initial workers (auto-tuned)"),
        "{out}"
    );
    assert!(t.path("dst/extra").exists());
}

#[test]
fn dry_run_summary_resolves_path_semantics() {
    let t = Tmp::new();
    write(&t.path("src/file"), b"data");

    let child = run_ok(&["-an", &t.s("src"), &t.s("child-target")]);
    assert!(
        child.contains(&format!(
            "mapping: {} -> {} (directory as child)",
            t.s("src"),
            t.s("child-target/src")
        )),
        "{child}"
    );

    let contents = run_ok(&["-an", &t.s("src/"), &t.s("contents-target/")]);
    assert!(
        contents.contains(&format!(
            "mapping: {} -> {} (directory contents)",
            t.s("src/"),
            t.s("contents-target")
        )),
        "{contents}"
    );

    let exact = run_ok(&["-an", &t.s("src/file"), &t.s("exact-target")]);
    assert!(
        exact.contains(&format!(
            "mapping: {} -> {} (exact destination path)",
            t.s("src/file"),
            t.s("exact-target")
        )),
        "{exact}"
    );
}

#[test]
fn dry_run_does_not_apply_metadata_repairs() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"same");
    write(&t.path("dst/f"), b"same");
    fs::set_permissions(t.path("src/f"), fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(t.path("dst/f"), fs::Permissions::from_mode(0o644)).unwrap();
    set_mtime(&t.path("src/f"), 1_600_000_000);
    set_mtime(&t.path("dst/f"), 1_600_000_000);
    set_mtime(&t.path("src"), 1_600_000_100);
    set_mtime(&t.path("dst"), 1_600_000_100);

    let out = run_ok(&["-anv", &t.s("src/"), &t.s("dst")]);
    assert_eq!(
        fs::symlink_metadata(t.path("dst/f")).unwrap().mode() & 0o777,
        0o644,
        "dry run changed destination permissions\n{out}"
    );
    assert!(out.contains("changes: 1 metadata-only entry"), "{out}");
    assert!(
        out.contains(&format!(
            "update metadata {} (requested file metadata differs)",
            t.s("dst/f")
        )),
        "{out}"
    );
    assert!(
        out.contains("4 B in 1 file with unchanged content"),
        "{out}"
    );

    run_ok(&["-a", &t.s("src/"), &t.s("dst")]);
    assert_eq!(
        fs::symlink_metadata(t.path("dst/f")).unwrap().mode() & 0o777,
        0o600,
        "the corresponding real run must still repair metadata"
    );
}

#[test]
fn dry_run_accounts_for_changed_symlinks_and_type_replacements() {
    let t = Tmp::new();
    fs::create_dir_all(t.path("src")).unwrap();
    fs::create_dir_all(t.path("dst")).unwrap();
    std::os::unix::fs::symlink("new-target", t.path("src/link")).unwrap();
    std::os::unix::fs::symlink("old-target", t.path("dst/link")).unwrap();
    write(&t.path("src/replaced"), b"file");
    std::os::unix::fs::symlink("old-target", t.path("dst/replaced")).unwrap();
    set_mtime(&t.path("src"), 1_600_000_100);
    set_mtime(&t.path("dst"), 1_600_000_100);

    let out = run_ok(&["-anv", &t.s("src/"), &t.s("dst")]);
    assert!(
        out.contains("changes: 1 regular file; 1 symlink; 1 type replacement among them"),
        "{out}"
    );
    assert!(
        out.contains(&format!(
            "update symlink {} -> new-target (target differs)",
            t.s("dst/link")
        )),
        "{out}"
    );
    assert!(
        out.contains(&format!(
            "replace with file {} (destination is symlink)",
            t.s("dst/replaced")
        )),
        "{out}"
    );
    assert!(
        out.contains("4 B in 1 file needing content work (upper bound)"),
        "{out}"
    );
    assert_eq!(
        fs::read_link(t.path("dst/link")).unwrap(),
        PathBuf::from("old-target")
    );
    assert!(t
        .path("dst/replaced")
        .symlink_metadata()
        .unwrap()
        .is_symlink());
}

#[test]
fn dry_run_directory_replacement_makes_descendants_virtually_missing() {
    let t = Tmp::new();
    write(&t.path("src/d/f"), b"same");
    write(&t.path("outside/f"), b"same");
    fs::create_dir_all(t.path("dst")).unwrap();
    std::os::unix::fs::symlink(t.path("outside"), t.path("dst/d")).unwrap();
    set_mtime(&t.path("src/d/f"), 1_600_000_000);
    set_mtime(&t.path("outside/f"), 1_600_000_000);
    set_mtime(&t.path("src"), 1_600_000_100);
    set_mtime(&t.path("dst"), 1_600_000_100);

    let out = run_ok(&["-anv", &t.s("src/"), &t.s("dst")]);
    let changes = out
        .lines()
        .find(|line| line.starts_with("  changes:"))
        .unwrap_or_else(|| panic!("missing changes line in {out}"));
    assert!(changes.contains("1 regular file"), "{out}");
    assert!(changes.contains("1 directory"), "{out}");
    assert!(changes.contains("1 type replacement among them"), "{out}");
    assert!(
        out.contains("4 B in 1 file needing content work (upper bound)"),
        "{out}"
    );
    assert!(
        out.contains("0 B in 0 files with unchanged content"),
        "{out}"
    );
    assert!(
        out.contains(&format!(
            "replace with directory {}/ (destination is symlink)",
            t.s("dst/d")
        )),
        "{out}"
    );
    assert!(
        out.contains(&format!(
            "create file {} (destination missing)",
            t.s("dst/d/f")
        )),
        "{out}"
    );
    assert!(t.path("dst/d").symlink_metadata().unwrap().is_symlink());
    assert_eq!(read(&t.path("outside/f")), b"same");

    let actual = run_ok(&["-a", &t.s("src/"), &t.s("dst")]);
    assert_eq!(transferred(&actual), 1, "{actual}");
    assert!(t.path("dst/d").is_dir());
    assert_eq!(read(&t.path("dst/d/f")), b"same");
    assert_eq!(read(&t.path("outside/f")), b"same");
}

#[test]
fn dry_run_rejects_bare_directory_into_existing_file() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"source");
    write(&t.path("destination"), b"keep me");

    let skipped = syq(&["-n", &t.s("src"), &t.s("destination")]);
    assert!(skipped.status.success(), "{}", stderr_of(&skipped));
    assert!(stderr_of(&skipped).contains("skipping directory"));

    let dry = syq(&["-an", &t.s("src"), &t.s("destination")]);
    assert!(!dry.status.success());
    assert!(
        stderr_of(&dry).contains(&format!(
            "destination {} is not a directory; cannot place directory {} inside it",
            t.s("destination"),
            t.s("src")
        )),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&dry.stdout),
        stderr_of(&dry)
    );
    assert!(
        !String::from_utf8_lossy(&dry.stdout).contains("syq: dry-run summary"),
        "a rejected mapping must not print a successful summary"
    );
    assert_eq!(read(&t.path("destination")), b"keep me");

    let actual = syq(&["-a", &t.s("src"), &t.s("destination")]);
    assert_eq!(actual.status.code(), Some(23), "{}", stderr_of(&actual));
    assert_eq!(read(&t.path("destination")), b"keep me");
}

#[test]
fn inplace_leaves_no_partial() {
    let t = Tmp::new();
    let data = prng(3 * 1024 * 1024, 5);
    write(&t.path("src/f.bin"), &data);
    set_mtime(&t.path("src/f.bin"), 1_600_000_000);
    run_ok(&["-a", "--inplace", &t.s("src/"), &t.s("dst/")]);
    assert!(read(&t.path("dst/f.bin")) == data);
    assert!(partial_files(&t.path("dst")).is_empty());
    // Update in place when the destination differs.
    let data2 = prng(3 * 1024 * 1024 + 10, 6);
    write(&t.path("src/f.bin"), &data2);
    set_mtime(&t.path("src/f.bin"), 1_600_000_001);
    run_ok(&["-a", "--inplace", &t.s("src/"), &t.s("dst/")]);
    assert!(read(&t.path("dst/f.bin")) == data2);
    assert!(partial_files(&t.path("dst")).is_empty());
    assert_same_tree(&t.path("src"), &t.path("dst"));
}

#[test]
fn unreadable_source_reports_error_but_continues() {
    if unsafe { libc::geteuid() } == 0 {
        return; // root can read anything
    }
    let t = Tmp::new();
    write(&t.path("src/ok.txt"), b"fine");
    write(&t.path("src/secret.txt"), b"nope");
    write(&t.path("src/also_ok.txt"), b"fine too");
    fs::set_permissions(t.path("src/secret.txt"), fs::Permissions::from_mode(0o000)).unwrap();
    let out = syq(&["-a", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(
        out.status.code(),
        Some(23),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("secret.txt"), "{err}");
    assert_eq!(read(&t.path("dst/ok.txt")), b"fine");
    assert_eq!(read(&t.path("dst/also_ok.txt")), b"fine too");
    assert!(!t.path("dst/secret.txt").exists());
}

#[test]
fn updates_changed_file_and_skips_symlink_only_when_same() {
    let t = Tmp::new();
    write(&t.path("src/f.txt"), b"v1");
    std::os::unix::fs::symlink("f.txt", t.path("src/l")).unwrap();
    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(read(&t.path("dst/f.txt")), b"v1");
    write(&t.path("src/f.txt"), b"v2 longer");
    set_mtime(&t.path("src/f.txt"), 1_700_000_000);
    fs::remove_file(t.path("src/l")).unwrap();
    std::os::unix::fs::symlink("other", t.path("src/l")).unwrap();
    let out = run_ok(&["-av", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(transferred(&out), 1);
    assert_eq!(read(&t.path("dst/f.txt")), b"v2 longer");
    assert_eq!(
        fs::read_link(t.path("dst/l")).unwrap(),
        PathBuf::from("other")
    );
    assert_same_tree(&t.path("src"), &t.path("dst"));
}

// ---- Regression tests for the security review ----

#[test]
fn inplace_self_copy_preserves_source() {
    let t = Tmp::new();
    write(&t.path("f"), b"hello world data");
    // Copying a file onto itself must never truncate it.
    let out = syq(&["-a", "--inplace", &t.s("f"), &t.s("f")]);
    assert!(out.status.success());
    assert_eq!(read(&t.path("f")), b"hello world data");
}

#[test]
fn inplace_hardlink_alias_preserves_source() {
    let t = Tmp::new();
    write(&t.path("a"), b"aaaa");
    fs::hard_link(t.path("a"), t.path("b")).unwrap();
    let out = syq(&["-a", "--inplace", &t.s("a"), &t.s("b")]);
    assert!(out.status.success());
    assert_eq!(read(&t.path("a")), b"aaaa");
    assert_eq!(read(&t.path("b")), b"aaaa");
}

#[test]
fn inplace_replaces_symlink_dest_not_its_target() {
    let t = Tmp::new();
    write(&t.path("src"), b"SRCDATA");
    write(&t.path("external"), b"EXTERNAL");
    std::os::unix::fs::symlink("external", t.path("link")).unwrap();
    run_ok(&["-a", "--inplace", &t.s("src"), &t.s("link")]);
    // The symlink target must be untouched; the dest is now a regular file.
    assert_eq!(read(&t.path("external")), b"EXTERNAL");
    assert!(fs::symlink_metadata(t.path("link"))
        .unwrap()
        .file_type()
        .is_file());
    assert_eq!(read(&t.path("link")), b"SRCDATA");
}

#[test]
fn rm_rejects_parent_traversal() {
    let t = Tmp::new();
    fs::create_dir_all(t.path("parent/child")).unwrap();
    write(&t.path("parent/sibling"), b"x");
    write(&t.path("parent/child/y"), b"y");
    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["--rm", ".."])
        .arg("--no-progress")
        .current_dir(t.path("parent/child"))
        .output()
        .unwrap();
    assert!(!out.status.success());
    // The sibling outside child must survive.
    assert!(t.path("parent/sibling").exists());
}

#[test]
fn rm_rejects_dangerous_roots() {
    for target in ["/", ".", "~", "/tmp/.."] {
        let out = syq(&["--rm", target]);
        assert!(!out.status.success(), "should reject --rm {target}");
    }
}

#[test]
fn rm_normal_target_works() {
    let t = Tmp::new();
    fs::create_dir_all(t.path("killme/sub")).unwrap();
    write(&t.path("killme/sub/f"), b"f");
    run_ok(&["--rm", &t.s("killme")]);
    assert!(!t.path("killme").exists());
}

#[test]
fn quiet_overrides_verbose_and_json_progress_for_rm() {
    let t = Tmp::new();
    write(&t.path("killme/sub/f"), b"f");

    let dry = syq(&[
        "--rm",
        "--dry-run",
        "-q",
        "-v",
        "--progress-json",
        &t.s("killme"),
    ]);
    assert_output_ok(&dry);
    assert!(
        dry.stdout.is_empty(),
        "{}",
        String::from_utf8_lossy(&dry.stdout)
    );
    assert!(
        dry.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&dry.stderr)
    );
    assert!(t.path("killme/sub/f").exists());

    let actual = syq(&["--rm", "-q", "-v", "--progress-json", &t.s("killme")]);
    assert_output_ok(&actual);
    assert!(
        actual.stdout.is_empty(),
        "{}",
        String::from_utf8_lossy(&actual.stdout)
    );
    assert!(
        actual.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&actual.stderr)
    );
    assert!(!t.path("killme").exists());
}

#[test]
fn duplicate_destination_rejected() {
    let t = Tmp::new();
    write(&t.path("a/same"), b"A");
    write(&t.path("b/same"), b"B");
    fs::create_dir_all(t.path("dest")).unwrap();
    let out = syq(&["-a", &t.s("a/same"), &t.s("b/same"), &t.s("dest/")]);
    assert!(
        !out.status.success(),
        "two sources named 'same' must be rejected"
    );
    assert!(!t.path("dest/same").exists());
}

#[test]
fn checksum_repair_shrinks_longer_destination() {
    let t = Tmp::new();
    write(&t.path("src"), b"abc");
    write(&t.path("dst"), b"ABCDEFG");
    set_mtime(&t.path("dst"), 1_000_000_000);
    set_mtime(&t.path("src"), 1_000_000_000);
    run_ok(&["-ac", &t.s("src"), &t.s("dst")]);
    assert_eq!(read(&t.path("dst")), b"abc");
}

#[test]
fn skip_reconciles_mode() {
    let t = Tmp::new();
    write(&t.path("src"), b"data");
    fs::set_permissions(t.path("src"), fs::Permissions::from_mode(0o600)).unwrap();
    fs::copy(t.path("src"), t.path("dst")).unwrap();
    fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o644)).unwrap();
    set_mtime(&t.path("src"), 1_000_000_000);
    set_mtime(&t.path("dst"), 1_000_000_000);
    // content is skipped, but -a must still fix the mode
    run_ok(&["-a", &t.s("src"), &t.s("dst")]);
    let m = fs::symlink_metadata(t.path("dst")).unwrap().mode() & 0o777;
    assert_eq!(m, 0o600, "mode should be reconciled on skip");
}

#[test]
fn no_perms_preserves_existing_dest_mode() {
    let t = Tmp::new();
    write(&t.path("src"), b"x");
    fs::copy(t.path("src"), t.path("dst")).unwrap();
    fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o666)).unwrap();
    write(&t.path("src"), b"y"); // change content so it transfers
    set_mtime(&t.path("dst"), 1_000_000_000);
    set_mtime(&t.path("src"), 1_000_000_500); // newer -> not skipped
    run_ok(&["-t", &t.s("src"), &t.s("dst")]); // no -p
    let m = fs::symlink_metadata(t.path("dst")).unwrap().mode() & 0o777;
    assert_eq!(m, 0o666, "existing dest mode must be preserved without -p");
    assert_eq!(read(&t.path("dst")), b"y");
}

#[test]
fn many_symlinks_no_setmeta_race() {
    let t = Tmp::new();
    fs::create_dir_all(t.path("ln")).unwrap();
    for i in 0..100 {
        std::os::unix::fs::symlink(format!("/target{i}"), t.path(&format!("ln/l{i}"))).unwrap();
    }
    run_ok(&["-a", &t.s("ln"), &t.s("dst")]);
    let n = fs::read_dir(t.path("dst/ln")).unwrap().count();
    assert_eq!(n, 100);
}

#[test]
fn archive_into_readonly_dest_dir() {
    let t = Tmp::new();
    write(&t.path("src/sub/f"), b"hi");
    run_ok(&["-a", &t.s("src"), &t.s("d")]);
    fs::set_permissions(t.path("d/src"), fs::Permissions::from_mode(0o555)).unwrap();
    write(&t.path("src/sub/g"), b"more");
    run_ok(&["-a", &t.s("src/"), &t.s("d/src/")]);
    assert_eq!(read(&t.path("d/src/sub/g")), b"more");
}

// ---- Review round 3 ----

#[cfg(debug_assertions)]
#[test]
fn partial_symlink_is_not_followed() {
    let t = Tmp::new();
    write(&t.path("src"), &vec![7u8; 5 * 1024 * 1024]);
    write(&t.path("external"), b"EXTERNAL-DO-NOT-TOUCH");
    let src = t.s("src");
    let dst = t.s("out");
    let args = ["-a", "--bwlimit", "1G", &src, &dst];
    let partial = interrupted_partial(&args, &t.0);
    fs::remove_file(&partial).unwrap();
    // A malicious/stale partial symlink pointing outside must not be followed.
    std::os::unix::fs::symlink("external", &partial).unwrap();
    run_ok(&args);
    assert_eq!(read(&t.path("external")), b"EXTERNAL-DO-NOT-TOUCH");
    assert!(fs::symlink_metadata(t.path("out"))
        .unwrap()
        .file_type()
        .is_file());
    assert_eq!(read(&t.path("out")).len(), 5 * 1024 * 1024);
}

#[test]
fn rm_rejects_dot_final_component() {
    let t = Tmp::new();
    write(&t.path("p/f"), b"x");
    let out = syq(&["--rm", &format!("{}/.", t.s("p"))]);
    assert!(!out.status.success());
    assert!(t.path("p/f").exists(), "contents must survive rm p/.");
}

#[test]
fn dir_vs_file_destination_collision_rejected() {
    let t = Tmp::new();
    write(&t.path("A/x"), b"aaa"); // A/x is a file
    write(&t.path("B/x/y"), b"yyy"); // B/x is a directory
    fs::create_dir_all(t.path("dest")).unwrap();
    let out = syq(&[
        "-a",
        &format!("{}/", t.s("A")),
        &format!("{}/", t.s("B")),
        &format!("{}/", t.s("dest")),
    ]);
    assert!(
        !out.status.success(),
        "conflicting file-vs-dir destination must be rejected"
    );
}

#[test]
fn file_over_nonempty_destination_directory_reports_error_without_panicking() {
    let t = Tmp::new();
    write(&t.path("src/foo"), b"source");
    write(&t.path("dest/foo/keep"), b"keep");

    let out = syq(&["-j", "1", &t.s("src/foo"), &t.s("dest")]);

    assert_eq!(out.status.code(), Some(23));
    let err = String::from_utf8_lossy(&out.stderr);
    let err_lower = err.to_ascii_lowercase();
    assert!(
        err_lower.contains("destination") && err_lower.contains("is a directory"),
        "{err}"
    );
    assert!(!err.contains("panicked"), "{err}");
    assert_eq!(read(&t.path("dest/foo/keep")), b"keep");
}

#[test]
fn verify_only_detects_symlink_difference() {
    let t = Tmp::new();
    fs::create_dir_all(t.path("s")).unwrap();
    fs::create_dir_all(t.path("d")).unwrap();
    std::os::unix::fs::symlink("target-a", t.path("s/l")).unwrap();
    std::os::unix::fs::symlink("target-b", t.path("d/l")).unwrap();
    let out = syq(&[
        "-a",
        "--verify-only",
        &format!("{}/", t.s("s")),
        &format!("{}/", t.s("d")),
    ]);
    assert_eq!(out.status.code(), Some(23));
    assert!(String::from_utf8_lossy(&out.stderr).contains("DIFFERS"));
}

#[test]
fn small_files_atomic_no_partials() {
    let t = Tmp::new();
    for i in 0..200 {
        write(&t.path(&format!("sm/f{i}")), format!("data-{i}").as_bytes());
    }
    run_ok(&[
        "-a",
        &format!("{}/", t.s("sm")),
        &format!("{}/", t.s("smd")),
    ]);
    assert!(partial_files(&t.path("smd")).is_empty());
    assert_eq!(read(&t.path("smd/f7")), b"data-7");
}

#[cfg(debug_assertions)]
#[test]
fn small_file_failure_never_publishes_partial_contents() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"complete contents");
    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["-a", "--no-progress", &t.s("src/"), &t.s("dst/")])
        .env("SYQ_TEST_FAIL_PUT_SMALL_BEFORE_RENAME", "/f")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(23));
    assert!(
        !t.path("dst/f").exists(),
        "the final name must not appear before the atomic rename"
    );
    let partials = partial_files(&t.path("dst"));
    assert_eq!(partials.len(), 1);
    let partial = &partials[0];
    assert_eq!(read(partial), b"complete contents");

    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(read(&t.path("dst/f")), b"complete contents");
    assert!(!partial.exists());
}

// ---- Review round 4 (integrity) ----

#[test]
fn quick_skipped_file_still_claims_destination() {
    let t = Tmp::new();
    write(&t.path("A/x"), b"aaa"); // A/x is a file
    write(&t.path("B/x/y"), b"yyy"); // B/x is a directory
                                     // Pre-populate dest/x identical to A/x so A/x is quick-skipped.
    write(&t.path("dest/x"), b"aaa");
    set_mtime(&t.path("A/x"), 1_000_000_000);
    set_mtime(&t.path("dest/x"), 1_000_000_000);
    let out = syq(&[
        "-a",
        &format!("{}/", t.s("A")),
        &format!("{}/", t.s("B")),
        &format!("{}/", t.s("dest")),
    ]);
    // The skipped file must still claim dest/x, so B's directory is rejected.
    assert!(
        !out.status.success(),
        "quick-skipped file must still block a colliding directory"
    );
}

#[test]
fn verify_only_flags_missing_directory() {
    let t = Tmp::new();
    write(&t.path("s/sub/f"), b"f");
    fs::create_dir_all(t.path("d")).unwrap(); // d exists but d/sub does not
    let out = syq(&[
        "-a",
        "--verify-only",
        &format!("{}/", t.s("s")),
        &format!("{}/", t.s("d")),
    ]);
    assert_eq!(out.status.code(), Some(23));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("MISSING")
            && String::from_utf8_lossy(&out.stderr)
                .to_lowercase()
                .contains("director")
    );
}

#[test]
fn verify_only_flags_missing_special() {
    let t = Tmp::new();
    fs::create_dir_all(t.path("s")).unwrap();
    fs::create_dir_all(t.path("d")).unwrap();
    // create a fifo in the source
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(t.path("s/pipe").as_os_str().as_bytes()).unwrap();
    unsafe {
        assert_eq!(libc::mkfifo(c.as_ptr(), 0o644), 0);
    }
    let out = syq(&[
        "-a",
        "--verify-only",
        &format!("{}/", t.s("s")),
        &format!("{}/", t.s("d")),
    ]);
    assert_eq!(out.status.code(), Some(23));
    assert!(String::from_utf8_lossy(&out.stderr).contains("special"));
}

// ---- Review round 5 ----

#[test]
fn rejects_copying_directory_into_itself() {
    let t = Tmp::new();
    write(&t.path("src/file"), b"hi");
    let out = syq(&[
        "-a",
        &format!("{}/", t.s("src")),
        &format!("{}/", t.s("src/dst")),
    ]);
    assert!(!out.status.success(), "dest inside source must be rejected");
    // src must be untouched (no dst subtree created)
    assert!(!t.path("src/dst").exists());
}

#[cfg(debug_assertions)]
#[test]
fn hardlinked_partial_does_not_corrupt_external_file() {
    let t = Tmp::new();
    write(&t.path("src"), &vec![9u8; 5 * 1024 * 1024]);
    write(&t.path("external"), b"EXTERNAL-DO-NOT-TOUCH");
    let src = t.s("src");
    let dst = t.s("out");
    let args = ["-a", "--bwlimit", "1G", &src, &dst];
    let partial = interrupted_partial(&args, &t.0);
    fs::remove_file(&partial).unwrap();
    // A partial hardlinked to an external file (as a dedup/backup tool might make).
    fs::hard_link(t.path("external"), partial).unwrap();
    run_ok(&args);
    assert_eq!(read(&t.path("external")), b"EXTERNAL-DO-NOT-TOUCH");
    assert_eq!(read(&t.path("out")).len(), 5 * 1024 * 1024);
    // out and external must be different inodes
    let mo = fs::metadata(t.path("out")).unwrap();
    let me = fs::metadata(t.path("external")).unwrap();
    assert!(!(mo.dev() == me.dev() && mo.ino() == me.ino()));
}

#[test]
fn rejects_bare_dir_into_parent_mapping_onto_itself() {
    let t = Tmp::new();
    write(&t.path("sub/f"), b"x");
    // Copying t/sub into t (existing dir) maps to t/sub — the source itself.
    let out = syq(&["-a", &t.s("sub"), &t.s(".")]);
    // t.s(".") is the tmp dir itself (existing), so effective dest = <tmp>/sub.
    assert!(
        !out.status.success(),
        "bare dir whose effective destination is itself must be rejected"
    );
    assert!(t.path("sub/f").exists());
}

#[test]
fn file_onto_itself_is_allowed_noop() {
    let t = Tmp::new();
    write(&t.path("f"), b"hello");
    run_ok(&["-a", "--inplace", &t.s("f"), &t.s("f")]);
    assert_eq!(read(&t.path("f")), b"hello");
}

/// Tree for the --ignore tests.
fn make_ignore_tree(root: &Path) {
    for f in [
        "hello.txt",
        "x.o",
        "a/y.o",
        "a/b/z.jpg",
        "a/pic.jpg",
        "node_modules/x/m.js",
        "a/node_modules/n.js",
        "build/out",
        "a/build/out2",
        "logs/l1",
        "logs/keep/k",
    ] {
        write(&root.join(f), f.as_bytes());
    }
    fs::create_dir_all(root.join("empty")).unwrap();
}

fn listing(root: &Path) -> Vec<String> {
    fn walk(root: &Path, p: &Path, out: &mut Vec<String>) {
        let mut names: Vec<_> = fs::read_dir(p)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        names.sort();
        for n in names {
            out.push(n.strip_prefix(root).unwrap().to_string_lossy().into_owned());
            if n.symlink_metadata().unwrap().is_dir() {
                walk(root, &n, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out
}

#[test]
fn ignore_patterns_prune_dirs_and_files() {
    let t = Tmp::new();
    make_ignore_tree(&t.path("src"));
    // `node_modules` at any depth, `*.o` anywhere, `/build` only at the root.
    run_ok(&[
        "-a",
        "-i",
        "node_modules",
        "-i",
        "*.o",
        "-i",
        "/build",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert_eq!(
        listing(&t.path("dst")),
        [
            "a",
            "a/b",
            "a/b/z.jpg",
            "a/build",
            "a/build/out2",
            "a/pic.jpg",
            "empty",
            "hello.txt",
            "logs",
            "logs/keep",
            "logs/keep/k",
            "logs/l1",
        ]
    );
}

#[test]
fn ignore_only_idiom_and_empty_dirs() {
    let t = Tmp::new();
    make_ignore_tree(&t.path("src"));
    // The gitignore "only *.jpg" idiom: directories are still all created.
    run_ok(&[
        "-a",
        "-i",
        "*",
        "-i",
        "!*/",
        "-i",
        "!*.jpg",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    let l = listing(&t.path("dst"));
    assert!(l.contains(&"a/b/z.jpg".to_string()));
    assert!(l.contains(&"a/pic.jpg".to_string()));
    assert!(l.contains(&"empty".to_string()));
    assert!(l.contains(&"node_modules/x".to_string()));
    assert!(!l
        .iter()
        .any(|p| p.ends_with(".o") || p.ends_with(".txt") || p.ends_with(".js")));
    // Without any pattern, empty dirs are copied too.
    run_ok(&["-a", &t.s("src/"), &t.s("dst2")]);
    assert!(t.path("dst2/empty").is_dir());
}

#[test]
fn ignore_from_file_and_later_negation_wins() {
    let t = Tmp::new();
    make_ignore_tree(&t.path("src"));
    write(&t.path("pats"), b"# comment\nnode_modules\n\n*.o\r\n");
    run_ok(&[
        "-a",
        "--ignore-from",
        &t.s("pats"),
        "-i",
        "!x.o",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    let l = listing(&t.path("dst"));
    assert!(
        l.contains(&"x.o".to_string()),
        "later -i '!x.o' must override file"
    );
    assert!(!l.contains(&"a/y.o".to_string()));
    assert!(!l.iter().any(|p| p.contains("node_modules")));
    // And the other order: the file's `*.o` comes last, so x.o stays ignored.
    run_ok(&[
        "-a",
        "-i",
        "!x.o",
        "--ignore-from",
        &t.s("pats"),
        &t.s("src/"),
        &t.s("dst2"),
    ]);
    assert!(!t.path("dst2/x.o").exists());
    // Missing file is an error.
    let out = syq(&[
        "-a",
        "--ignore-from",
        &t.s("nope"),
        &t.s("src/"),
        &t.s("dst3"),
    ]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--ignore-from"));
}

#[test]
fn ignore_applies_per_source_root_and_dry_run() {
    let t = Tmp::new();
    make_ignore_tree(&t.path("s1"));
    make_ignore_tree(&t.path("s2"));
    fs::create_dir(t.path("dst")).unwrap();
    // `/build` is anchored at each source's root, not the destination.
    run_ok(&["-a", "-i", "/build", &t.s("s1"), &t.s("s2"), &t.s("dst")]);
    assert!(!t.path("dst/s1/build").exists());
    assert!(!t.path("dst/s2/build").exists());
    assert!(t.path("dst/s1/a/build/out2").is_file());
    // Dry run with the root itself matching a pattern: the root is never ignored.
    let out = run_ok(&["-an", "-i", "s1", "-i", "*.o", &t.s("s1"), &t.s("dst2")]);
    assert!(!t.path("dst2").exists());
    assert!(out.contains("in 9 files needing content work"), "{out}");
}

#[test]
fn ignore_reinclude_subdir_idiom() {
    let t = Tmp::new();
    make_ignore_tree(&t.path("src"));
    // Everything directly under logs/ except the keep/ directory (git idiom).
    run_ok(&[
        "-a",
        "-i",
        "logs/*",
        "-i",
        "!logs/keep/",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert!(t.path("dst/logs/keep/k").is_file());
    assert!(!t.path("dst/logs/l1").exists());
}

#[test]
fn ignore_from_strips_bom_and_hyphen_patterns_work() {
    let t = Tmp::new();
    make_ignore_tree(&t.path("src"));
    write(&t.path("-dash"), b"d");
    write(&t.path("src/-secret"), b"s");
    write(&t.path("pats"), "\u{feff}*.o\n".as_bytes());
    run_ok(&[
        "-a",
        "--ignore-from",
        &t.s("pats"),
        "-i",
        "-secret",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert!(
        !t.path("dst/x.o").exists(),
        "BOM must not hide the first rule"
    );
    assert!(!t.path("dst/-secret").exists());
    assert!(t.path("dst/hello.txt").is_file());
}

#[test]
fn ignore_conflicts_with_rm() {
    let t = Tmp::new();
    make_ignore_tree(&t.path("tree"));
    let out = syq(&["--rm", "-i", "keep", &t.s("tree")]);
    assert!(!out.status.success(), "--rm with -i must be rejected");
    assert!(
        t.path("tree/logs/keep/k").is_file(),
        "nothing may be removed"
    );
    let out = syq(&[
        "--rm",
        "--ignore-from",
        &t.s("tree/hello.txt"),
        &t.s("tree"),
    ]);
    assert!(!out.status.success());
    assert!(t.path("tree/hello.txt").is_file());
}

// ---------------------------------------------------------------- --delete

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn delete_removes_extras_and_protects_ignored() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"a");
    write(&t.path("src/d/b"), b"b");
    write(&t.path("dst/a"), b"old");
    write(&t.path("dst/d/b"), b"b");
    write(&t.path("dst/c"), b"extra");
    write(&t.path("dst/extra/x/y"), b"extra");
    write(&t.path("dst/keep/k.log"), b"protected");
    write(&t.path("dst/keep/gone"), b"not protected");
    std::os::unix::fs::symlink("nowhere", t.path("dst/dangling")).unwrap();

    // Dry run: everything listed, nothing removed.
    let out = syq(&[
        "-a",
        "-n",
        "-v",
        "--delete",
        "-i",
        "*.log",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert!(out.status.success());
    let so = String::from_utf8_lossy(&out.stdout);
    for l in [
        "delete c (destination only)",
        "delete extra/x/y (destination only)",
        "delete extra/x/ (destination only)",
        "delete extra/ (destination only)",
        "delete keep/gone (destination only)",
        "delete dangling (destination only)",
    ] {
        assert!(so.contains(l), "missing {l:?} in {so}");
    }
    assert!(!so.contains("k.log"), "{so}");
    assert!(!so.contains("delete keep/ (destination only)"), "{so}");
    assert!(
        so.contains("deletions: 6 entries planned after a successful copy"),
        "{so}"
    );
    assert!(
        stderr_of(&out).contains("not deleting keep/"),
        "{}",
        stderr_of(&out)
    );
    assert!(t.path("dst/c").exists() && t.path("dst/extra/x/y").exists());

    let out = syq(&[
        "-a",
        "-v",
        "--delete",
        "-i",
        "*.log",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert!(out.status.success(), "{}", stderr_of(&out));
    assert_eq!(
        listing(&t.path("dst")),
        ["a", "d", "d/b", "keep", "keep/k.log"]
    );
    assert_eq!(read(&t.path("dst/a")), b"a");
    let so = String::from_utf8_lossy(&out.stdout);
    assert!(so.contains("6 deleted"), "{so}");
    // keep/ stays because it holds a protected file: reported, not an error.
    let se = stderr_of(&out);
    assert!(se.contains("not deleting keep/"), "{se}");
}

#[cfg(debug_assertions)]
#[test]
fn delete_removes_only_this_jobs_orphaned_sidecars() {
    // Each scenario needs its own job (same source/destination/flags) so the
    // interrupted run and the --delete run share a partial id.
    // 1. The file is still in the source (here even up to date): the sidecar
    //    is resume state and stays.
    let t = Tmp::new();
    write(&t.path("src/ok"), &vec![7u8; 8 << 20]);
    fs::create_dir_all(t.path("dst")).unwrap();
    let partial = interrupted_partial(
        &["-a", "--bwlimit", "1G", &t.s("src/"), &t.s("dst")],
        &t.path("dst"),
    );
    assert!(partial.exists());
    fs::copy(t.path("src/ok"), t.path("dst/ok")).unwrap();
    set_mtime(&t.path("src/ok"), 1_600_000_000);
    set_mtime(&t.path("dst/ok"), 1_600_000_000);
    let so = run_ok(&["-a", "--delete", &t.s("src/"), &t.s("dst")]);
    assert!(partial.exists(), "{so}");
    assert!(so.contains("0 deleted"), "{so}");

    // 2. Orphan: the source file is gone, so its sidecar is an extra.
    let t = Tmp::new();
    write(&t.path("src/gone"), &vec![7u8; 8 << 20]);
    fs::create_dir_all(t.path("dst")).unwrap();
    let partial = interrupted_partial(
        &["-a", "--bwlimit", "1G", &t.s("src/"), &t.s("dst")],
        &t.path("dst"),
    );
    fs::remove_file(t.path("src/gone")).unwrap();
    let so = run_ok(&["-a", "--delete", &t.s("src/"), &t.s("dst")]);
    assert!(!partial.exists());
    assert!(so.contains("1 deleted"), "{so}");

    // 3. Failed this run: still in the source, kept.
    let t = Tmp::new();
    write(&t.path("src/bad"), &vec![7u8; 8 << 20]);
    fs::create_dir_all(t.path("dst")).unwrap();
    let partial = interrupted_partial(
        &["-a", "--bwlimit", "1G", &t.s("src/"), &t.s("dst")],
        &t.path("dst"),
    );
    fs::set_permissions(t.path("src/bad"), fs::Permissions::from_mode(0o000)).unwrap();
    let out = syq(&["-a", "--delete", &t.s("src/"), &t.s("dst")]);
    assert_eq!(out.status.code(), Some(23), "{}", stderr_of(&out));
    assert!(partial.exists());

    // 4. Any other id is an ordinary extra (syq copies such names as
    //    payload, so the name alone proves nothing).
    let t = Tmp::new();
    write(&t.path("src/a"), b"a");
    let other = format!("dst/.gone.syq-part.{}", "a".repeat(26));
    write(&t.path(&other), b"unclaimed, whoever wrote it");
    run_ok(&["-a", "--delete", &t.s("src/"), &t.s("dst")]);
    assert!(!t.path(&other).exists());
}

#[test]
fn delete_is_skipped_when_the_source_scan_has_errors() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"a");
    write(&t.path("src/locked/inner"), b"x");
    write(&t.path("dst/extra"), b"extra");
    fs::set_permissions(t.path("src/locked"), fs::Permissions::from_mode(0o000)).unwrap();
    let out = syq(&["-a", "--delete", &t.s("src/"), &t.s("dst")]);
    assert_eq!(out.status.code(), Some(23));
    assert!(t.path("dst/extra").exists(), "nothing may be deleted");
    assert!(
        stderr_of(&out).contains("skipping deletions"),
        "{}",
        stderr_of(&out)
    );
}

#[test]
fn delete_only_inside_directories_the_sources_map_onto() {
    let t = Tmp::new();
    write(&t.path("s1/a"), b"a");
    write(&t.path("s2/b"), b"b");
    write(&t.path("dst/s1/extra"), b"x");
    write(&t.path("dst/s2/extra"), b"x");
    write(&t.path("dst/other"), b"untouched");
    run_ok(&["-a", "--delete", &t.s("s1"), &t.s("s2"), &t.s("dst")]);
    assert_eq!(
        listing(&t.path("dst")),
        ["other", "s1", "s1/a", "s2", "s2/b"]
    );
    // A dry run into a destination that doesn't exist yet has nothing to delete.
    let so = run_ok(&["-a", "-n", "--delete", &t.s("s1/"), &t.s("nowhere")]);
    assert!(
        so.contains("deletions: 0 entries planned after a successful copy"),
        "{so}"
    );
    assert!(!t.path("nowhere").exists());
    // A single-file source deletes nothing.
    write(&t.path("dst2/junk"), b"j");
    run_ok(&["-a", "--delete", &t.s("s1/a"), &t.s("dst2/")]);
    assert!(t.path("dst2/junk").exists());
}

// --------------------------------------------- -u, --existing, --ignore-existing

#[test]
fn update_skips_files_newer_on_the_destination() {
    let t = Tmp::new();
    write(&t.path("src/newer"), b"src-new");
    write(&t.path("src/older"), b"src-old");
    write(&t.path("dst/newer"), b"dst-old");
    write(&t.path("dst/older"), b"dst-new");
    set_mtime(&t.path("src/newer"), 2000);
    set_mtime(&t.path("dst/newer"), 1000);
    set_mtime(&t.path("src/older"), 1000);
    set_mtime(&t.path("dst/older"), 2000);
    let so = run_ok(&["-a", "-u", &t.s("src/"), &t.s("dst")]);
    assert_eq!(transferred(&so), 1);
    assert_eq!(read(&t.path("dst/newer")), b"src-new");
    assert_eq!(read(&t.path("dst/older")), b"dst-new");
    // Without -u the older destination file is replaced too.
    run_ok(&["-a", &t.s("src/"), &t.s("dst")]);
    assert_eq!(read(&t.path("dst/older")), b"src-old");
}

#[test]
fn ignore_existing_and_existing() {
    let t = Tmp::new();
    write(&t.path("src/have"), b"new content");
    write(&t.path("src/new"), b"n");
    write(&t.path("src/sub/deep"), b"d");
    write(&t.path("dst/have"), b"old content");
    set_mtime(&t.path("src/have"), 2000);
    set_mtime(&t.path("dst/have"), 1000);

    let so = run_ok(&["-a", "--ignore-existing", &t.s("src/"), &t.s("dst")]);
    assert_eq!(transferred(&so), 2);
    assert_eq!(read(&t.path("dst/have")), b"old content");
    assert!(t.path("dst/new").is_file() && t.path("dst/sub/deep").is_file());

    let t = Tmp::new();
    write(&t.path("src/have"), b"new content");
    write(&t.path("src/new"), b"n");
    write(&t.path("src/sub/deep"), b"d");
    write(&t.path("dst/have"), b"old content");
    set_mtime(&t.path("src/have"), 2000);
    set_mtime(&t.path("dst/have"), 1000);
    let so = run_ok(&["-a", "--existing", &t.s("src/"), &t.s("dst")]);
    assert_eq!(transferred(&so), 1);
    assert_eq!(read(&t.path("dst/have")), b"new content");
    assert_eq!(listing(&t.path("dst")), ["have"]);
    // --existing --delete still removes extras.
    write(&t.path("dst/extra"), b"e");
    run_ok(&["-a", "--existing", "--delete", &t.s("src/"), &t.s("dst")]);
    assert_eq!(listing(&t.path("dst")), ["have"]);
}

// ------------------------------------------------------- --max-size / --min-size

#[test]
fn size_limits_filter_files_and_protect_them_from_delete() {
    let t = Tmp::new();
    write(&t.path("src/small"), &[0u8; 10]);
    write(&t.path("src/mid"), &[0u8; 2048]);
    write(&t.path("src/big"), &[0u8; 8192]);
    write(&t.path("dst/big"), b"stays");
    let so = run_ok(&[
        "-a",
        "--delete",
        "--max-size",
        "4K",
        "--min-size",
        "1K",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert_eq!(transferred(&so), 1);
    assert_eq!(listing(&t.path("dst")), ["big", "mid"]);
    assert_eq!(read(&t.path("dst/big")), b"stays");
}

// --------------------------------------------------------------- --files-from

#[test]
fn files_from_copies_listed_paths_with_their_parents() {
    let t = Tmp::new();
    for f in ["a/1", "a/2", "b/c/3", "b/c/4", "d/5", "top"] {
        write(&t.path("src").join(f), f.as_bytes());
    }
    write(&t.path("list"), b"a/1\n\n./b/c/3\n/top\nb/c/\nmissing/x\n");
    let out = syq(&["-a", "--files-from", &t.s("list"), &t.s("src"), &t.s("dst")]);
    // The missing entry is an error but the rest is copied.
    assert_eq!(out.status.code(), Some(23), "{}", stderr_of(&out));
    assert!(stderr_of(&out).contains("missing/x"));
    // b/c is listed as a directory but -r wasn't given explicitly: no contents
    // beyond what the list names.
    assert_eq!(
        listing(&t.path("dst")),
        ["a", "a/1", "b", "b/c", "b/c/3", "top"]
    );
    assert_eq!(read(&t.path("dst/b/c/3")), b"b/c/3");

    // Explicit -r walks listed directories; --from0 takes NUL separators.
    write(&t.path("list0"), b"b/c\0d\0");
    run_ok(&[
        "-a",
        "-r",
        "--files-from",
        &t.s("list0"),
        "--from0",
        &t.s("src/"),
        &t.s("dst2"),
    ]);
    assert_eq!(
        listing(&t.path("dst2")),
        ["b", "b/c", "b/c/3", "b/c/4", "d", "d/5"]
    );

    // Alternate spellings of one path are one path: no double scheduling.
    write(&t.path("list-dup"), b"a/1\na//1\n./a/./1/\n");
    let so = run_ok(&[
        "-a",
        "--files-from",
        &t.s("list-dup"),
        &t.s("src"),
        &t.s("dst4"),
    ]);
    assert_eq!(transferred(&so), 1);
    assert_eq!(listing(&t.path("dst4")), ["a", "a/1"]);

    // A `..` component is rejected before anything happens.
    write(&t.path("bad"), b"../etc\n");
    let out = syq(&["-a", "--files-from", &t.s("bad"), &t.s("src"), &t.s("dst3")]);
    assert!(!out.status.success());
    assert!(!t.path("dst3").exists());
}

// ------------------------------------------------------------ review fixes

#[test]
fn delete_never_removes_paths_the_source_has_but_skips() {
    let t = Tmp::new();
    write(&t.path("src/plain"), b"p");
    write(&t.path("src/hard"), b"h");
    fs::create_dir_all(t.path("dst")).unwrap();
    fs::hard_link(t.path("src/hard"), t.path("dst/hard")).unwrap();
    std::os::unix::fs::symlink("plain", t.path("src/link")).unwrap();
    std::os::unix::fs::symlink("plain", t.path("dst/link")).unwrap();
    write(&t.path("dst/extra"), b"x");
    // No -l: the symlink is skipped, but it is the source's, so it stays.
    // The hardlinked file is "the same file" and skipped, and stays.
    let so = run_ok(&["-rt", "--delete", &t.s("src/"), &t.s("dst")]);
    assert_eq!(listing(&t.path("dst")), ["hard", "link", "plain"]);
    // Skipped files are not reported as directories.
    assert!(so.contains(", 1 dirs"), "{so}");
    write(&t.path("src2/big"), b"bb");
    let so = run_ok(&["-a", "--max-size", "1", &t.s("src2/"), &t.s("dst2")]);
    assert!(
        so.contains("transferred 0 files") && so.contains(", 1 dirs"),
        "{so}"
    );
}

#[test]
fn files_from_rejects_symlinked_ancestors_and_recurses_only_listed_dirs() {
    let t = Tmp::new();
    write(&t.path("outside/secret"), b"secret");
    fs::create_dir_all(t.path("src/a")).unwrap();
    std::os::unix::fs::symlink("../outside", t.path("src/link")).unwrap();
    write(&t.path("src/a/listed"), b"l");
    write(&t.path("src/a/unlisted"), b"u");
    write(&t.path("list"), b"link/secret\na/listed\n");
    let out = syq(&[
        "-a",
        "-r",
        "--files-from",
        &t.s("list"),
        &t.s("src"),
        &t.s("dst"),
    ]);
    // `link` resolves to a directory, so the listed path is followed: the
    // implied parent becomes a real directory on the destination (never a
    // symlink a later write could go through). `a` was not recursed into
    // despite -r: only listed directories are walked.
    assert!(out.status.success(), "{}", stderr_of(&out));
    assert_eq!(
        listing(&t.path("dst")),
        ["a", "a/listed", "link", "link/secret"]
    );
    assert!(t.path("dst/link").symlink_metadata().unwrap().is_dir());
    assert_eq!(read(&t.path("dst/link/secret")), b"secret");

    // An ancestor that resolves to a file, or dangles, is an error.
    std::os::unix::fs::symlink("a/listed", t.path("src/tofile")).unwrap();
    std::os::unix::fs::symlink("nowhere", t.path("src/dangling")).unwrap();
    write(&t.path("list2"), b"tofile/x\ndangling/y\n");
    let out = syq(&[
        "-a",
        "--files-from",
        &t.s("list2"),
        &t.s("src"),
        &t.s("dst2"),
    ]);
    assert_eq!(out.status.code(), Some(23));
    let se = stderr_of(&out);
    assert!(
        se.contains("tofile is not a directory") && se.contains("dangling/y: no such file"),
        "{se}"
    );
    assert_eq!(listing(&t.path("dst2")), Vec::<String>::new());

    // Listing a symlink itself and a path through it conflicts; the path is
    // refused rather than written through the destination symlink.
    write(&t.path("list3"), b"link\nlink/secret\n");
    let out = syq(&[
        "-a",
        "--files-from",
        &t.s("list3"),
        &t.s("src"),
        &t.s("dst3"),
    ]);
    assert_eq!(out.status.code(), Some(23));
    assert!(stderr_of(&out).contains("listed as a non-directory"));
    assert!(t.path("dst3/link").symlink_metadata().unwrap().is_symlink());
    assert!(!t.path("outside/secret2").exists());
}

#[test]
fn existing_never_creates_the_destination_root() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"f");
    let so = run_ok(&["-a", "--existing", &t.s("src/"), &t.s("dst/")]);
    assert!(!t.path("dst").exists(), "{so}");
    write(&t.path("src2/g"), b"g");
    let so = run_ok(&["-a", "--existing", &t.s("src"), &t.s("src2"), &t.s("dst2")]);
    assert!(!t.path("dst2").exists(), "{so}");
}

#[test]
fn files_from_repeats_and_late_listed_dirs_across_chunks() {
    let t = Tmp::new();
    write(&t.path("src/d/inner"), b"i");
    write(&t.path("src/d/sub/deep"), b"x");
    let mut list = String::from("d/inner\n");
    for i in 0..1200 {
        write(&t.path(&format!("src/many/f{i}")), b"f");
        list.push_str(&format!("many/f{i}\n"));
    }
    // After the 1000-entry boundary: repeat a path, and list `d` (so far only
    // an implied parent) explicitly so -r walks it.
    list.push_str("d/inner\nd\n");
    write(&t.path("list"), list.as_bytes());
    let so = run_ok(&[
        "-a",
        "-r",
        "--files-from",
        &t.s("list"),
        &t.s("src"),
        &t.s("dst"),
    ]);
    assert_eq!(transferred(&so), 1202);
    assert!(t.path("dst/d/sub/deep").is_file());
    assert!(t.path("dst/many/f1199").is_file());
}

#[test]
fn existing_dry_run_reports_no_missing_directory_changes() {
    let t = Tmp::new();
    write(&t.path("src/there/f"), b"f");
    write(&t.path("src/missing/g"), b"g");
    fs::create_dir_all(t.path("dst/there")).unwrap();
    let so = run_ok(&["-a", "-n", "-v", "--existing", &t.s("src/"), &t.s("dst")]);
    assert!(!so.contains("create directory"), "{so}");
    assert!(!so.contains(&t.s("dst/missing")), "{so}");
    assert!(!so.contains("there/f"), "--existing creates no files: {so}");
}

// ------------------------------------------------------------ review round 3

#[test]
fn existing_leaves_a_file_where_a_source_directory_would_go() {
    let t = Tmp::new();
    write(&t.path("src/d/inner"), b"i");
    write(&t.path("dst/d"), b"a file, not a directory");
    let so = run_ok(&["-a", "--existing", &t.s("src/"), &t.s("dst")]);
    assert_eq!(read(&t.path("dst/d")), b"a file, not a directory");
    assert_eq!(listing(&t.path("dst")), ["d"]);
    let so2 = run_ok(&["-a", "-n", "-v", "--existing", &t.s("src/"), &t.s("dst")]);
    assert!(!so2.contains("dst/d/"), "{so2}\n{so}");
}

#[test]
fn delete_treats_sidecar_patterned_files_as_ordinary_extras() {
    let t = Tmp::new();
    write(
        &t.path("src/.notes.syq-part.aaaaaaaaaaaaaaaaaaaaaaaaaa"),
        b"mine",
    );
    write(&t.path("src/real"), b"r");
    write(
        &t.path("dst/.notes.syq-part.aaaaaaaaaaaaaaaaaaaaaaaaaa"),
        b"mine",
    );
    write(&t.path("dst/.syq-part.notes"), b"odd name, not a sidecar");
    write(
        &t.path("dst/.gone.syq-part.aaaaaaaaaaaaaaaaaaaaaaaaaa"),
        b"leftover",
    );
    let so = run_ok(&["-a", "--delete", &t.s("src/"), &t.s("dst")]);
    // The source's sidecar-named file is ordinary payload (copied, and here
    // already up to date), so the destination copy stays. Everything else
    // matching the pattern is an ordinary extra, whatever id it carries.
    assert_eq!(
        listing(&t.path("dst")),
        [".notes.syq-part.aaaaaaaaaaaaaaaaaaaaaaaaaa", "real"]
    );
    assert!(so.contains("2 deleted"), "{so}");
}

#[test]
fn files_from_creates_listed_and_implied_dirs_without_r() {
    let t = Tmp::new();
    write(&t.path("src/a/1"), b"1");
    fs::create_dir_all(t.path("src/b/inner")).unwrap();
    fs::set_permissions(t.path("src/a"), fs::Permissions::from_mode(0o750)).unwrap();
    fs::set_permissions(t.path("src/b"), fs::Permissions::from_mode(0o710)).unwrap();
    write(&t.path("list"), b"a/1\nb\n");
    // -t only: no -r, no -a. Directories must still be created, with metadata.
    run_ok(&[
        "-pt",
        "--files-from",
        &t.s("list"),
        &t.s("src"),
        &t.s("dst"),
    ]);
    assert_eq!(listing(&t.path("dst")), ["a", "a/1", "b"]);
    assert_eq!(fs::metadata(t.path("dst/a")).unwrap().mode() & 0o777, 0o750);
    assert_eq!(fs::metadata(t.path("dst/b")).unwrap().mode() & 0o777, 0o710);
}

#[test]
fn delete_with_nested_roots_deletes_once() {
    let t = Tmp::new();
    write(&t.path("a/x"), b"x");
    write(&t.path("b/y"), b"y");
    write(&t.path("dst/a/extra/deep"), b"e");
    write(&t.path("dst/stray"), b"s");
    let so = run_ok(&["-a", "-v", "--delete", &t.s("a"), &t.s("b/"), &t.s("dst")]);
    assert_eq!(listing(&t.path("dst")), ["a", "a/x", "y"]);
    assert!(so.contains("3 deleted"), "{so}");
    assert!(!so.contains("errors"), "{so}");
}

#[test]
fn delete_with_inplace_replacing_many_symlinks() {
    let t = Tmp::new();
    fs::create_dir_all(t.path("dst")).unwrap();
    for i in 0..3000 {
        write(&t.path(&format!("src/f{i}")), b"file now");
        std::os::unix::fs::symlink("nowhere", t.path(&format!("dst/f{i}"))).unwrap();
    }
    let so = run_ok(&[
        "-a",
        "--inplace",
        "--delete",
        "-j",
        "16",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert!(!so.contains("errors"), "{so}");
    assert_eq!(read(&t.path("dst/f2999")), b"file now");
}

// ------------------------------------------------------------ review round 5

#[test]
fn unreadable_source_root_disables_delete() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"a");
    write(&t.path("dst/precious"), b"p");
    fs::set_permissions(t.path("src"), fs::Permissions::from_mode(0o000)).unwrap();
    // -rt rather than -a, so dst doesn't faithfully inherit the 000 mode.
    let out = syq(&["-rt", "--delete", &t.s("src/"), &t.s("dst")]);
    fs::set_permissions(t.path("src"), fs::Permissions::from_mode(0o755)).unwrap();
    assert_ne!(out.status.code(), Some(0));
    assert!(t.path("dst/precious").exists(), "{}", stderr_of(&out));
    assert!(
        stderr_of(&out).contains("skipping deletions"),
        "{}",
        stderr_of(&out)
    );
}

#[test]
fn delete_nested_roots_keep_their_own_anchored_ignores() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"a");
    write(&t.path("src2/foo/g"), b"g");
    write(&t.path("src2/b"), b"b");
    write(&t.path("dst/src2/foo/g"), b"g");
    write(&t.path("dst/src2/junk"), b"j");
    write(&t.path("dst/foo/h"), b"h");
    let so = run_ok(&[
        "-a",
        "-v",
        "--delete",
        "-i",
        "/foo",
        &t.s("src/"),
        &t.s("src2"),
        &t.s("dst"),
    ]);
    // /foo is anchored at each root: dst/src2/foo is protected (ignored on
    // both sides of the src2 mapping), dst/foo likewise for src/; junk goes.
    assert_eq!(
        listing(&t.path("dst")),
        [
            "a",
            "foo",
            "foo/h",
            "src2",
            "src2/b",
            "src2/foo",
            "src2/foo/g"
        ]
    );
    assert!(so.contains("1 deleted"), "{so}");
}

#[test]
fn delete_treats_partial_named_directory_as_ordinary_extra() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"a");
    write(
        &t.path("dst/.d.syq-part.aaaaaaaaaaaaaaaaaaaaaaaaaa/x"),
        b"x",
    );
    write(
        &t.path("dst/.d.syq-part.aaaaaaaaaaaaaaaaaaaaaaaaaa/keep.log"),
        b"k",
    );
    let so = run_ok(&[
        "-a",
        "-v",
        "--delete",
        "-i",
        "*.log",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert_eq!(
        listing(&t.path("dst")),
        [
            ".d.syq-part.aaaaaaaaaaaaaaaaaaaaaaaaaa",
            ".d.syq-part.aaaaaaaaaaaaaaaaaaaaaaaaaa/keep.log",
            "a"
        ]
    );
    assert!(so.contains("1 deleted") && !so.contains("errors"), "{so}");
}

#[test]
fn untransferred_entries_yield_to_another_source() {
    let t = Tmp::new();
    std::os::unix::fs::symlink(
        "nowhere",
        t.path("a/x")
            .parent()
            .map(|p| {
                fs::create_dir_all(p).unwrap();
                t.path("a/x")
            })
            .unwrap(),
    )
    .unwrap();
    write(&t.path("b/x"), b"hi");
    // No -l: a/x is skipped and must not block b/x (either order).
    run_ok(&["-r", &t.s("a/"), &t.s("b/"), &t.s("dst")]);
    assert_eq!(read(&t.path("dst/x")), b"hi");
    run_ok(&["-r", &t.s("b/"), &t.s("a/"), &t.s("dst2")]);
    assert_eq!(read(&t.path("dst2/x")), b"hi");
    // But a real conflict is still one.
    write(&t.path("c/x"), b"other");
    let out = syq(&["-r", &t.s("b/"), &t.s("c/"), &t.s("dst3")]);
    assert_eq!(out.status.code(), Some(1));
}

#[cfg(debug_assertions)]
#[test]
fn delete_keeps_partials_of_filtered_files() {
    // A file this run chose not to send (--max-size here) keeps its partial:
    // it is the resume state of a transfer that hasn't happened yet.
    let t = Tmp::new();
    write(&t.path("src/big"), &vec![7u8; 8 << 20]);
    fs::create_dir_all(t.path("dst")).unwrap();
    let partial = interrupted_partial(
        &["-a", "--bwlimit", "1G", &t.s("src/"), &t.s("dst")],
        &t.path("dst"),
    );
    run_ok(&[
        "-a",
        "--delete",
        "--max-size",
        "10",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert!(partial.exists());
    assert!(!t.path("dst/big").exists());
    // Same for -u.
    let t = Tmp::new();
    write(&t.path("src/f"), &vec![7u8; 8 << 20]);
    fs::create_dir_all(t.path("dst")).unwrap();
    let partial = interrupted_partial(
        &["-a", "--bwlimit", "1G", &t.s("src/"), &t.s("dst")],
        &t.path("dst"),
    );
    write(&t.path("dst/f"), b"newer on dst");
    set_mtime(&t.path("src/f"), 1000);
    set_mtime(&t.path("dst/f"), 2000);
    run_ok(&["-a", "--delete", "-u", &t.s("src/"), &t.s("dst")]);
    assert!(partial.exists());
    assert_eq!(read(&t.path("dst/f")), b"newer on dst");
}

#[test]
fn existing_does_not_write_through_a_destination_symlink_dir() {
    // An in-tree destination symlink is a payload conflict (replaced in a
    // normal run, never traversed); --existing replaces nothing, so it and
    // everything below it are left alone.
    let t = Tmp::new();
    write(&t.path("src/d/f"), b"new");
    write(&t.path("src/d/sub/g"), b"new");
    write(&t.path("elsewhere/f"), b"old");
    write(&t.path("elsewhere/sub/g"), b"old");
    fs::create_dir_all(t.path("dst")).unwrap();
    std::os::unix::fs::symlink(t.path("elsewhere"), t.path("dst/d")).unwrap();
    set_mtime(&t.path("src/d/f"), 2000);
    set_mtime(&t.path("elsewhere/f"), 1000);
    let so = run_ok(&["-a", "--existing", &t.s("src/"), &t.s("dst")]);
    assert_eq!(read(&t.path("elsewhere/f")), b"old", "{so}");
    assert_eq!(read(&t.path("elsewhere/sub/g")), b"old", "{so}");
    assert!(t.path("dst/d").symlink_metadata().unwrap().is_symlink());
    let so = run_ok(&["-a", "-n", "--existing", &t.s("src/"), &t.s("dst")]);
    assert!(so.contains("0 files needing content work"), "{so}");
}

#[test]
fn no_recursive_skips_every_batch_of_a_directory_source() {
    let t = Tmp::new();
    for i in 0..1500 {
        write(&t.path(&format!("src/f{i}")), b"f");
    }
    let so = run_ok(&["-t", &t.s("src/"), &t.s("dst")]);
    assert_eq!(transferred(&so), 0);
    assert!(!t.path("dst/f1400").exists());
}

#[test]
fn files_from_root_may_be_a_symlink_and_root_lines_are_rejected() {
    let t = Tmp::new();
    write(&t.path("real/f"), b"f");
    std::os::unix::fs::symlink(t.path("real"), t.path("link")).unwrap();
    write(&t.path("list"), b"f\n");
    run_ok(&[
        "-a",
        "--files-from",
        &t.s("list"),
        &t.s("link"),
        &t.s("dst"),
    ]);
    assert_eq!(read(&t.path("dst/f")), b"f");
    write(&t.path("bad"), b"././//\n");
    let out = syq(&[
        "-a",
        "--files-from",
        &t.s("bad"),
        &t.s("real"),
        &t.s("dst2"),
    ]);
    assert!(!out.status.success());
    assert!(
        stderr_of(&out).contains("names the source root"),
        "{}",
        stderr_of(&out)
    );
}

#[test]
fn delete_leaves_directory_contents_under_a_skipped_source_path() {
    let t = Tmp::new();
    write(&t.path("src/big"), &[0u8; 100]);
    std::os::unix::fs::symlink("nowhere", t.path("src/lnk")).unwrap();
    write(&t.path("src/real"), b"r");
    write(&t.path("dst/big/inside"), b"i");
    write(&t.path("dst/lnk/deep/inside"), b"i");
    write(&t.path("dst/extra"), b"e");
    let so = run_ok(&[
        "-rt",
        "--delete",
        "--max-size",
        "10",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert_eq!(
        listing(&t.path("dst")),
        [
            "big",
            "big/inside",
            "lnk",
            "lnk/deep",
            "lnk/deep/inside",
            "real"
        ]
    );
    assert!(so.contains("1 deleted"), "{so}");
}

#[test]
fn existing_updates_through_a_destination_root_symlink_to_a_dir() {
    // A destination that is a symlink to a directory *is* that directory (as
    // for rsync), so --existing updates the file there and leaves the link.
    let t = Tmp::new();
    write(&t.path("src/f"), b"new");
    write(&t.path("src/missing"), b"m");
    write(&t.path("elsewhere/f"), b"old");
    set_mtime(&t.path("src/f"), 2000);
    set_mtime(&t.path("elsewhere/f"), 1000);
    std::os::unix::fs::symlink(t.path("elsewhere"), t.path("dst")).unwrap();
    let so = run_ok(&["-a", "--existing", &t.s("src/"), &t.s("dst")]);
    assert_eq!(read(&t.path("elsewhere/f")), b"new", "{so}");
    assert!(!t.path("elsewhere/missing").exists());
    assert!(t.path("dst").symlink_metadata().unwrap().is_symlink());
}

// Resume: a successful transfer leaves no marker behind, and the retained
// journal is authoritative — a completed file is skipped on a plain rerun even
// if the destination was externally deleted, while -c bypasses the journal.
#[test]
fn checkpoint_conflicts_are_rejected() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"data");
    for conflicting in ["-c", "--verify-only"] {
        let out = syq(&[
            "-a",
            conflicting,
            "--checkpoint",
            &t.s("state"),
            &t.s("src/"),
            &t.s("dst/"),
        ]);
        assert!(!out.status.success(), "{conflicting}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("cannot be used with"), "{conflicting}: {err}");
    }
    let out = syq(&["--rm", "--checkpoint", &t.s("state"), &t.s("src")]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("cannot be used with"), "{err}");
    assert!(t.path("src/f").is_file());
    assert!(!t.path("state").exists());
}

#[test]
fn no_forward_agent_conflicts_with_explicit_rsh() {
    let t = Tmp::new();
    write(&t.path("src"), b"data");
    let out = syq(&[
        "--no-forward-agent",
        "-e",
        "ssh -a",
        &t.s("src"),
        &t.s("dst"),
    ]);
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("cannot be used with"), "{err}");
    assert!(!t.path("dst").exists());
}

// Ordinary copies keep no historical completion state: the current destination
// determines what a later invocation repairs.
#[test]
fn ordinary_rerun_reconciles_destination() {
    let t = Tmp::new();
    write(&t.path("src/f.bin"), b"hello world");
    set_mtime(&t.path("src/f.bin"), 1_600_000_000);
    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    fs::remove_file(t.path("dst/f.bin")).unwrap();
    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(read(&t.path("dst/f.bin")), b"hello world");
}

#[test]
fn ordinary_copy_needs_no_writable_history_directory() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"data");
    // A regular file cannot contain an application state directory. Ordinary
    // copies must ignore both locations because history is opt-in.
    write(&t.path("not-a-directory"), b"occupied");
    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["-a", "--no-progress", &t.s("src/"), &t.s("dst/")])
        .env("XDG_STATE_HOME", t.s("not-a-directory"))
        .env("HOME", t.s("not-a-directory"))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(read(&t.path("dst/f")), b"data");
}

// An explicitly requested checkpoint is retained after a copy error and is
// authoritative on retry. A source metadata change invalidates its record.
#[cfg(debug_assertions)]
#[test]
fn checkpoint_is_explicit_retained_and_source_sensitive() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"data");
    write(&t.path("src/fail/other"), b"other");
    set_mtime(&t.path("src/f"), 1_600_000_000);
    let checkpoint = t.s("copy.checkpoint");
    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "-a",
            "--no-progress",
            "--checkpoint",
            &checkpoint,
            &t.s("src/"),
            &t.s("dest/"),
        ])
        .env("SYQ_TEST_FAIL_SETMETA", "fail")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(23));
    assert!(t.path("copy.checkpoint").is_file());

    // Changing mode under -a makes the source fingerprint differ, so this file
    // is checked and restored rather than checkpoint-skipped.
    fs::set_permissions(t.path("src/f"), fs::Permissions::from_mode(0o600)).unwrap();
    set_mtime(&t.path("src/f"), 1_600_000_000);
    fs::remove_file(t.path("dest/f")).unwrap();
    run_ok(&[
        "-a",
        "--checkpoint",
        &checkpoint,
        &t.s("src/"),
        &t.s("dest/"),
    ]);
    assert_eq!(read(&t.path("dest/f")), b"data");
    assert_eq!(
        fs::metadata(t.path("dest/f")).unwrap().mode() & 0o777,
        0o600
    );
    assert!(
        t.path("copy.checkpoint").is_file(),
        "an explicit checkpoint persists after a clean retry"
    );
}

// A completed checkpoint deliberately trusts destination history, but an
// ordinary source fingerprint change invalidates the corresponding record.
#[test]
fn completed_checkpoint_trusts_destination_and_tracks_source() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"original");
    set_mtime(&t.path("src/f"), 1_600_000_000);
    let checkpoint = t.s("copy.checkpoint");
    run_ok(&[
        "-a",
        "--checkpoint",
        &checkpoint,
        &t.s("src/"),
        &t.s("dst/"),
    ]);
    assert!(t.path("copy.checkpoint").is_file());

    write(&t.path("dst/f"), b"damaged independently");
    let stdout = run_ok(&[
        "-a",
        "--checkpoint",
        &checkpoint,
        &t.s("src/"),
        &t.s("dst/"),
    ]);
    assert_eq!(transferred(&stdout), 0);
    assert_eq!(
        read(&t.path("dst/f")),
        b"damaged independently",
        "a matching record intentionally bypasses destination inspection"
    );

    write(&t.path("src/f"), b"updated source");
    set_mtime(&t.path("src/f"), 1_600_000_001);
    run_ok(&[
        "-a",
        "--checkpoint",
        &checkpoint,
        &t.s("src/"),
        &t.s("dst/"),
    ]);
    assert_eq!(read(&t.path("dst/f")), b"updated source");
    assert!(t.path("copy.checkpoint").is_file());
}

#[cfg(debug_assertions)]
#[test]
fn checkpoint_tombstone_precedes_destination_deletion() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"same source fingerprint");
    set_mtime(&t.path("src/f"), 1_600_000_000);
    let checkpoint = t.s("copy.checkpoint");
    run_ok(&[
        "-a",
        "--checkpoint",
        &checkpoint,
        &t.s("src/"),
        &t.s("dst/"),
    ]);

    fs::remove_file(t.path("src/f")).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "-a",
            "--delete",
            "--no-progress",
            "--checkpoint",
            &checkpoint,
            &t.s("src/"),
            &t.s("dst/"),
        ])
        .env("SYQ_TEST_HOLD_AFTER_DELETE_MS", "10000")
        .spawn()
        .unwrap();
    for _ in 0..300 {
        if !t.path("dst/f").exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let deletion_observed = !t.path("dst/f").exists();
    let kill_result = child.kill();
    let wait_result = child.wait();
    assert!(
        deletion_observed,
        "delete attempt did not reach the interruption window"
    );
    kill_result.unwrap();
    wait_result.unwrap();

    // Recreate precisely the fingerprint stored by the first run. Without a
    // durable pre-delete tombstone, the checkpoint would skip this file while
    // leaving its destination missing.
    write(&t.path("src/f"), b"same source fingerprint");
    set_mtime(&t.path("src/f"), 1_600_000_000);
    let stdout = run_ok(&[
        "-a",
        "--checkpoint",
        &checkpoint,
        &t.s("src/"),
        &t.s("dst/"),
    ]);
    assert_eq!(transferred(&stdout), 1, "{stdout}");
    assert_eq!(read(&t.path("dst/f")), b"same source fingerprint");
}

#[test]
fn checkpoint_inside_local_source_is_rejected() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"data");
    let out = syq(&[
        "-a",
        "--checkpoint",
        &t.s("src/state"),
        &t.s("src/"),
        &t.s("dst/"),
    ]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("must not be inside local source"), "{err}");
    assert!(!t.path("src/state").exists());
    assert!(!t.path("dst").exists());
}

#[test]
fn checkpoint_inside_local_destination_is_rejected() {
    let t = Tmp::new();
    write(&t.path("src/state"), b"payload");
    let out = syq(&[
        "-a",
        "--checkpoint",
        &t.s("dst/state"),
        &t.s("src/"),
        &t.s("dst/"),
    ]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("must not be inside local destination"),
        "{err}"
    );
    assert!(!t.path("dst").exists());
}

// A checkpoint-complete file is still a claimed destination: a second source that
// later maps onto the same path is a collision, not a silent overwrite.
#[cfg(debug_assertions)]
#[test]
fn checkpoint_skip_still_detects_collision() {
    let t = Tmp::new();
    write(&t.path("A/x"), b"from A");
    write(&t.path("A/fail/y"), b"failure trigger");
    fs::create_dir_all(t.path("B")).unwrap();
    let checkpoint = t.s("copy.checkpoint");
    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "-a",
            "--no-progress",
            "--checkpoint",
            &checkpoint,
            &t.s("A/"),
            &t.s("B/"),
            &t.s("dest/"),
        ])
        .env("SYQ_TEST_FAIL_SETMETA", "fail")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(23));
    assert_eq!(read(&t.path("dest/x")), b"from A");
    write(&t.path("B/x"), b"from B");
    let out = syq(&[
        "-a",
        "--checkpoint",
        &checkpoint,
        &t.s("A/"),
        &t.s("B/"),
        &t.s("dest/"),
    ]);
    assert!(!out.status.success(), "ambiguous mapping must be reported");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("same destination"), "stderr: {err}");
    assert_eq!(read(&t.path("dest/x")), b"from A", "must not be clobbered");
}

// A read-only source root: the copy succeeds, the root ends up 0555, and a
// rerun into the now read-only destination works too.
#[test]
fn readonly_root_copies_and_reruns() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"data");
    fs::set_permissions(t.path("src"), fs::Permissions::from_mode(0o555)).unwrap();
    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(fs::metadata(t.path("dst")).unwrap().mode() & 0o777, 0o555);
    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(fs::metadata(t.path("dst")).unwrap().mode() & 0o777, 0o555);
    // No implicit history: deleting a destination file makes the next run
    // restore it from the read-only source.
    fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o755)).unwrap();
    fs::remove_file(t.path("dst/f")).unwrap();
    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(read(&t.path("dst/f")), b"data");
}

// The old implicit-marker subsystem is gone. Its former filename is ordinary
// payload and must not make an otherwise identical second run look interrupted.
#[test]
fn legacy_marker_name_is_ordinary_payload() {
    const LEGACY_TRANSFER_MARKER: &str = ".syq-transfer-session.json";

    let t = Tmp::new();
    let src_marker = t.path("src").join(LEGACY_TRANSFER_MARKER);
    let dst_marker = t.path("dst").join(LEGACY_TRANSFER_MARKER);
    write(&src_marker, b"ordinary user data");
    write(&t.path("src/file"), b"payload");

    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(read(&dst_marker), b"ordinary user data");
    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(read(&t.path("dst/file")), b"payload");
}

#[test]
fn source_partials_are_copied_and_warned_about() {
    let t = Tmp::new();
    let id = "a".repeat(26);
    let file = format!(".payload.syq-part.{id}");
    let dir = format!(".directory.syq-part.{id}");
    write(&t.path(&format!("src/{file}")), b"partial payload");
    write(&t.path(&format!("src/{dir}/child")), b"nested payload");
    write(
        &t.path("src/.legacy.syq-partial"),
        b"legacy-looking payload",
    );

    let output = syq(&["-a", &t.s("src/"), &t.s("dst/")]);
    assert_output_ok(&output);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("warning: source contains 2 recognizable SYQ partial paths"),
        "{stderr}"
    );
    assert!(
        stderr.contains("they are treated as ordinary payload"),
        "{stderr}"
    );
    assert!(
        !stderr.to_ascii_lowercase().contains("copying"),
        "warning must not promise that a dry run, verification, or failed run will copy: {stderr}"
    );
    assert_eq!(read(&t.path(&format!("dst/{file}"))), b"partial payload");
    assert_eq!(
        read(&t.path(&format!("dst/{dir}/child"))),
        b"nested payload"
    );
    assert_eq!(
        read(&t.path("dst/.legacy.syq-partial")),
        b"legacy-looking payload"
    );

    let output = syq(&["-a", "--progress-json", &t.s("src/"), &t.s("json-dst/")]);
    assert_output_ok(&output);
    let warning = String::from_utf8_lossy(&output.stderr)
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find(|value| value["code"] == "source_partials")
        .expect("missing structured source-partial warning");
    assert_eq!(warning["type"], "warning");
    assert_eq!(warning["count"], 2);

    let quiet = syq(&[
        "-q",
        "-v",
        "-a",
        "--progress-json",
        &t.s("src/"),
        &t.s("quiet-dst/"),
    ]);
    assert_output_ok(&quiet);
    assert!(
        quiet.stdout.is_empty(),
        "{}",
        String::from_utf8_lossy(&quiet.stdout)
    );
    assert!(
        quiet.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&quiet.stderr)
    );
    assert_eq!(
        read(&t.path(&format!("quiet-dst/{file}"))),
        b"partial payload"
    );

    let dry = syq(&["-n", "-a", &t.s("src/"), &t.s("dry-dst/")]);
    assert_output_ok(&dry);
    let dry_stderr = String::from_utf8_lossy(&dry.stderr);
    assert!(
        dry_stderr.contains("treated as ordinary payload"),
        "{dry_stderr}"
    );
    assert!(!dry_stderr.to_ascii_lowercase().contains("copying"));
    assert!(!t.path("dry-dst").exists());
}

#[test]
fn quiet_suppresses_notices_but_not_errors() {
    let t = Tmp::new();
    fs::create_dir(t.path("src")).unwrap();

    let notice = syq(&["-q", &t.s("src"), &t.s("dst")]);
    assert_output_ok(&notice);
    assert!(
        notice.stdout.is_empty(),
        "{}",
        String::from_utf8_lossy(&notice.stdout)
    );
    assert!(
        notice.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&notice.stderr)
    );

    let error = syq(&["-q", &t.s("missing"), &t.s("dst")]);
    assert!(!error.status.success());
    assert!(
        error.stdout.is_empty(),
        "{}",
        String::from_utf8_lossy(&error.stdout)
    );
    assert!(
        !error.stderr.is_empty(),
        "quiet mode must still report errors"
    );
}

#[cfg(debug_assertions)]
#[test]
fn exact_payload_sidecar_collision_fails_before_publication() {
    let t = Tmp::new();
    write(&t.path("src/file"), &vec![b'x'; 5 * 1024 * 1024]);
    let src = t.s("src/");
    let dst = t.s("dst/");
    let args = ["-a", "--block-size", "1M", "--bwlimit", "1G", &src, &dst];
    let partial = interrupted_partial(&args, &t.path("dst"));
    let collision_name = partial.file_name().unwrap().to_owned();
    fs::remove_file(&partial).unwrap();
    write(
        &t.path("src").join(&collision_name),
        b"deliberate collision",
    );

    let output = syq(&args);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("reserved sidecar"), "{stderr}");
    assert!(!t.path("dst/file").exists());
    assert!(!t.path("dst").join(collision_name).exists());
}

// Several content sources map onto the destination root; the last one's
// metadata wins, as for any other directory.
#[test]
fn multiple_content_sources_root_meta() {
    let t = Tmp::new();
    write(&t.path("A/a"), b"a");
    write(&t.path("B/b"), b"b");
    fs::set_permissions(t.path("A"), fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(t.path("B"), fs::Permissions::from_mode(0o555)).unwrap();
    run_ok(&["-a", &t.s("A/"), &t.s("B/"), &t.s("dest/")]);
    assert_eq!(fs::metadata(t.path("dest")).unwrap().mode() & 0o777, 0o555);
    assert_eq!(read(&t.path("dest/a")), b"a");
    assert_eq!(read(&t.path("dest/b")), b"b");
}

// Directories syq had to open up (no owner write bit) get their own mode back
// at the end when nothing else sets it (no -p); with -p the source mode wins.
#[test]
fn opened_up_directories_get_their_mode_back() {
    let t = Tmp::new();
    write(&t.path("src/sub/f"), b"data");
    fs::set_permissions(t.path("src/sub"), fs::Permissions::from_mode(0o755)).unwrap();
    fs::create_dir_all(t.path("dst/sub")).unwrap();
    fs::set_permissions(t.path("dst/sub"), fs::Permissions::from_mode(0o555)).unwrap();
    fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o555)).unwrap();
    run_ok(&["-r", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(read(&t.path("dst/sub/f")), b"data");
    assert_eq!(
        fs::metadata(t.path("dst/sub")).unwrap().mode() & 0o777,
        0o555
    );
    assert_eq!(fs::metadata(t.path("dst")).unwrap().mode() & 0o777, 0o555);
    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(
        fs::metadata(t.path("dst/sub")).unwrap().mode() & 0o777,
        0o755
    );
}

// A directory metadata failure is a copy error (exit 23), not a footnote.
#[cfg(debug_assertions)]
#[test]
fn root_meta_failure_is_visible() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"data");
    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["-a", "--no-progress", &t.s("src/"), &t.s("dst")])
        .env("SYQ_TEST_FAIL_SETMETA", "dst")
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(23), "stderr: {err}");
    assert!(err.contains("injected"), "stderr: {err}");
    assert_eq!(read(&t.path("dst/f")), b"data");
}

// A quick-check-identical file whose metadata repair fails is not checkpointed
// as complete, so the next run repairs it instead of skipping it.
#[cfg(debug_assertions)]
#[test]
fn checkpoint_records_quick_check_only_after_meta_repair() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"data");
    set_mtime(&t.path("src/f"), 1_600_000_000);
    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    let before = fs::metadata(t.path("dst/f")).unwrap().mode() & 0o777;
    assert_ne!(before, 0o600);
    fs::set_permissions(t.path("src/f"), fs::Permissions::from_mode(0o600)).unwrap();
    set_mtime(&t.path("src/f"), 1_600_000_000);
    let checkpoint = t.s("copy.checkpoint");
    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "-a",
            "--no-progress",
            "--checkpoint",
            &checkpoint,
            &t.s("src/"),
            &t.s("dst/"),
        ])
        .env("SYQ_TEST_FAIL_SETMETA", "f")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(23));
    assert_eq!(
        fs::metadata(t.path("dst/f")).unwrap().mode() & 0o777,
        before
    );
    assert!(t.path("copy.checkpoint").is_file());
    run_ok(&[
        "-a",
        "--checkpoint",
        &checkpoint,
        &t.s("src/"),
        &t.s("dst/"),
    ]);
    assert_eq!(
        fs::metadata(t.path("dst/f")).unwrap().mode() & 0o777,
        0o600,
        "the failed repair must not have been checkpointed as complete"
    );
    assert!(t.path("copy.checkpoint").is_file());
}

// The read-only modes create nothing, not even the destination directory.
#[test]
fn readonly_modes_create_nothing() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"data");
    let checkpoint = t.s("dry-run.checkpoint");
    let out = syq(&["-a", "--verify-only", &t.s("src/"), &t.s("dst/")]);
    assert!(
        !t.path("dst").exists(),
        "--verify-only must not create the destination"
    );
    assert!(!out.status.success(), "everything is missing");
    let out = syq(&[
        "-a",
        "-n",
        "--checkpoint",
        &checkpoint,
        &t.s("src/"),
        &t.s("dst/"),
    ]);
    assert!(out.status.success());
    assert!(
        !t.path("dst").exists(),
        "--dry-run must not create the destination"
    );
    assert!(
        !t.path("dry-run.checkpoint").exists(),
        "--dry-run must not create a checkpoint"
    );
}

#[test]
fn dry_run_validates_checkpoint_identity_with_missing_destination() {
    let t = Tmp::new();
    write(&t.path("first/f"), b"first");
    write(&t.path("second/f"), b"second");
    let checkpoint = t.s("copy.checkpoint");
    run_ok(&[
        "-a",
        "--checkpoint",
        &checkpoint,
        &t.s("first/"),
        &t.s("first-dst/"),
    ]);
    let out = syq(&[
        "-an",
        "--checkpoint",
        &checkpoint,
        &t.s("second/"),
        &t.s("missing/"),
    ]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("describes a different copy"), "{err}");
    assert!(!t.path("missing").exists());
}

// Different spellings of the same local path are one job.
#[cfg(debug_assertions)]
#[test]
fn checkpoint_identity_is_spelling_independent() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"data");
    write(&t.path("src/fail/y"), b"trigger");
    set_mtime(&t.path("src/f"), 1_600_000_000);
    let dotted = format!("{}/./src/", t.s(""));
    let checkpoint = t.s("copy.checkpoint");
    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "-a",
            "--no-progress",
            "--checkpoint",
            &checkpoint,
            &dotted,
            &t.s("dst/"),
        ])
        .env("SYQ_TEST_FAIL_SETMETA", "fail")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(23));
    fs::remove_file(t.path("dst/f")).unwrap();
    run_ok(&[
        "-a",
        "--checkpoint",
        &checkpoint,
        &t.s("src/"),
        &t.s("dst/"),
    ]);
    assert!(
        !t.path("dst/f").exists(),
        "same checkpoint identity, so the explicitly trusted file is skipped"
    );
}

// Existing completion records are never reset automatically. A missing
// destination is suspicious and requires the user to remove the checkpoint.
#[cfg(debug_assertions)]
#[test]
fn existing_checkpoint_with_missing_destination_fails() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"aaaa");
    write(&t.path("src/fail/secret"), b"secret");
    let checkpoint = t.s("copy.checkpoint");
    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "-a",
            "--no-progress",
            "--checkpoint",
            &checkpoint,
            &t.s("src/"),
            &t.s("dest/"),
        ])
        .env("SYQ_TEST_FAIL_SETMETA", "fail")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(23));
    assert!(t.path("copy.checkpoint").is_file());
    fs::remove_dir_all(t.path("dest")).unwrap();
    assert!(!t.path("dest").exists());
    let out = syq(&[
        "-a",
        "--checkpoint",
        &checkpoint,
        &t.s("src/"),
        &t.s("dest/"),
    ]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("destination") && err.contains("missing"),
        "{err}"
    );
    assert!(!t.path("dest").exists());
    assert!(t.path("copy.checkpoint").is_file());
}

#[test]
fn existing_checkpoint_with_missing_mapped_source_target_fails() {
    let t = Tmp::new();
    write(&t.path("bigdir/f"), b"data");
    let checkpoint = t.s("copy.checkpoint");
    run_ok(&[
        "-a",
        "--checkpoint",
        &checkpoint,
        &t.s("bigdir"),
        &t.s("backups"),
    ]);
    fs::remove_dir_all(t.path("backups/bigdir")).unwrap();
    let out = syq(&[
        "-a",
        "--checkpoint",
        &checkpoint,
        &t.s("bigdir"),
        &t.s("backups"),
    ]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("destination target") && err.contains("missing"),
        "{err}"
    );
    assert!(!t.path("backups/bigdir").exists());
}

#[test]
fn missing_destination_does_not_replace_an_unrelated_checkpoint_path() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"data");
    write(&t.path("important"), b"not a checkpoint");
    let out = syq(&[
        "-a",
        "--checkpoint",
        &t.s("important"),
        &t.s("src/"),
        &t.s("dest/"),
    ]);
    assert!(!out.status.success());
    assert_eq!(read(&t.path("important")), b"not a checkpoint");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("not a SYQ checkpoint"), "stderr: {err}");
}

// Two ordinary copies into one tree behave like rsync: the union lands, and a
// later invocation checks current destination state rather than hidden history.
#[test]
fn concurrent_copies_union() {
    let t = Tmp::new();
    for i in 0..200 {
        write(&t.path(&format!("A/a{i}")), b"a");
        write(&t.path(&format!("B/b{i}")), b"b");
    }
    let spawn = |src: &str| {
        Command::new(env!("CARGO_BIN_EXE_syq"))
            .args(["-a", "--no-progress", &t.s(src), &t.s("dest/")])
            .spawn()
            .unwrap()
    };
    let (mut a, mut b) = (spawn("A/"), spawn("B/"));
    assert!(a.wait().unwrap().success());
    assert!(b.wait().unwrap().success());
    for i in 0..200 {
        assert_eq!(read(&t.path(&format!("dest/a{i}"))), b"a");
        assert_eq!(read(&t.path(&format!("dest/b{i}"))), b"b");
    }
    fs::remove_file(t.path("dest/a7")).unwrap();
    run_ok(&["-a", &t.s("A/"), &t.s("dest/")]);
    assert_eq!(read(&t.path("dest/a7")), b"a");
}

#[cfg(debug_assertions)]
#[test]
fn different_jobs_use_distinct_partial_inodes() {
    let t = Tmp::new();
    let first_contents = vec![b'a'; 8 * 1024 * 1024];
    let second_contents = vec![b'b'; 8 * 1024 * 1024];
    write(&t.path("first"), &first_contents);
    write(&t.path("second"), &second_contents);

    let mut first = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "-a",
            "-j",
            "1",
            "--bwlimit",
            "1G",
            "--no-progress",
            &t.s("first"),
            &t.s("out"),
        ])
        .env("SYQ_TEST_HOLD_PARTIAL_MS", "2000")
        .spawn()
        .unwrap();
    let first_partial = (0..300).find_map(|_| {
        let mut partials = partial_files(&t.0);
        if partials.len() == 1 {
            partials.pop()
        } else {
            std::thread::sleep(std::time::Duration::from_millis(10));
            None
        }
    });
    let first_partial = first_partial.expect("first copy never created its sidecar");

    let second = syq(&[
        "-a",
        "-j",
        "1",
        "--bwlimit",
        "1G",
        &t.s("second"),
        &t.s("out"),
    ]);
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert_eq!(read(&t.path("out")), second_contents);
    assert!(
        first_partial.exists(),
        "the second job must not rename the first job's partial"
    );
    assert!(first.wait().unwrap().success());
    assert_eq!(read(&t.path("out")), first_contents);
    assert!(partial_files(&t.0).is_empty());
}

#[cfg(debug_assertions)]
#[test]
fn final_hash_and_partial_seed_use_one_inode_snapshot() {
    let t = Tmp::new();
    let mut first_contents = vec![0u8; 8 * 1024 * 1024];
    first_contents[4 * 1024 * 1024..].fill(b'a');
    let second_contents = vec![b'b'; 8 * 1024 * 1024];
    write(&t.path("basis"), &vec![0u8; 8 * 1024 * 1024]);
    write(&t.path("first"), &first_contents);
    write(&t.path("second"), &second_contents);
    set_mtime(&t.path("basis"), 1_600_000_000);
    set_mtime(&t.path("first"), 1_600_000_001);
    set_mtime(&t.path("second"), 1_600_000_002);
    let ready = t.path("basis-ready");

    let mut first = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "-a",
            "-j",
            "1",
            "--bwlimit",
            "1G",
            "--no-progress",
            &t.s("first"),
            &t.s("basis"),
        ])
        .env("SYQ_TEST_BASIS_READY_FILE", &ready)
        .env("SYQ_TEST_HOLD_BASIS_MS", "2000")
        .spawn()
        .unwrap();
    let held = (0..300).any(|_| {
        if ready.exists() {
            true
        } else {
            std::thread::sleep(std::time::Duration::from_millis(10));
            false
        }
    });
    assert!(held, "first copy never retained its destination basis");
    assert!(
        partial_files(&t.0).is_empty(),
        "hashing alone must not create a sidecar"
    );

    let second = syq(&[
        "-a",
        "-j",
        "1",
        "--bwlimit",
        "1G",
        &t.s("second"),
        &t.s("basis"),
    ]);
    assert_output_ok(&second);
    assert_eq!(read(&t.path("basis")), second_contents);
    assert!(first.wait().unwrap().success());
    assert_eq!(read(&t.path("basis")), first_contents);
    assert!(partial_files(&t.0).is_empty());
}

#[cfg(debug_assertions)]
#[test]
fn retained_basis_growth_is_not_treated_as_an_exact_match() {
    let t = Tmp::new();
    let contents = vec![b'a'; 2 * 1024 * 1024];
    write(&t.path("src"), &contents);
    write(&t.path("basis"), &contents);
    set_mtime(&t.path("src"), 1_600_000_001);
    set_mtime(&t.path("basis"), 1_600_000_000);
    let ready = t.path("basis-ready");

    let mut child = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "-a",
            "-j",
            "1",
            "--bwlimit",
            "1G",
            "--no-progress",
            &t.s("src"),
            &t.s("basis"),
        ])
        .env("SYQ_TEST_BASIS_READY_FILE", &ready)
        .env("SYQ_TEST_HOLD_BASIS_MS", "2000")
        .spawn()
        .unwrap();
    let held = (0..300).any(|_| {
        if ready.exists() {
            true
        } else {
            std::thread::sleep(std::time::Duration::from_millis(10));
            false
        }
    });
    assert!(held, "copy never retained its destination basis");

    OpenOptions::new()
        .append(true)
        .open(t.path("basis"))
        .unwrap()
        .write_all(b"trailing data")
        .unwrap();

    assert!(child.wait().unwrap().success());
    assert_eq!(read(&t.path("basis")), contents);
    assert!(partial_files(&t.0).is_empty());
}

#[cfg(debug_assertions)]
#[test]
fn content_identical_basis_never_mixes_contents_and_metadata() {
    let t = Tmp::new();
    let first_contents = vec![b'a'; 8 * 1024 * 1024];
    let second_contents = vec![b'b'; 8 * 1024 * 1024];
    write(&t.path("basis"), &first_contents);
    write(&t.path("first"), &first_contents);
    write(&t.path("second"), &second_contents);
    fs::set_permissions(t.path("first"), fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(t.path("second"), fs::Permissions::from_mode(0o640)).unwrap();
    set_mtime(&t.path("basis"), 1_600_000_000);
    set_mtime(&t.path("first"), 1_600_000_001);
    set_mtime(&t.path("second"), 1_600_000_002);
    let ready = t.path("basis-ready");

    let mut first = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "-a",
            "-j",
            "1",
            "--bwlimit",
            "1G",
            "--no-progress",
            &t.s("first"),
            &t.s("basis"),
        ])
        .env("SYQ_TEST_BASIS_READY_FILE", &ready)
        .env("SYQ_TEST_HOLD_BASIS_MS", "2000")
        .spawn()
        .unwrap();
    let held = (0..300).any(|_| {
        if ready.exists() {
            true
        } else {
            std::thread::sleep(std::time::Duration::from_millis(10));
            false
        }
    });
    assert!(held, "first copy never retained its destination basis");
    assert!(
        partial_files(&t.0).is_empty(),
        "content comparison must not allocate a full sidecar"
    );

    let second = syq(&[
        "-a",
        "-j",
        "1",
        "--bwlimit",
        "1G",
        &t.s("second"),
        &t.s("basis"),
    ]);
    assert_output_ok(&second);
    assert_eq!(read(&t.path("basis")), second_contents);
    let published = fs::metadata(t.path("basis")).unwrap();
    assert_eq!(published.mode() & 0o777, 0o640);
    assert_eq!(published.mtime(), 1_600_000_002);

    assert!(first.wait().unwrap().success());
    // The second job renamed a complete file over the descriptor retained by
    // the first. Metadata applied through the old descriptor cannot leak onto
    // the second job's contents, so the second whole-file publication wins.
    assert_eq!(read(&t.path("basis")), second_contents);
    let published = fs::metadata(t.path("basis")).unwrap();
    assert_eq!(published.mode() & 0o777, 0o640);
    assert_eq!(published.mtime(), 1_600_000_002);
    assert!(partial_files(&t.0).is_empty());
}

#[cfg(debug_assertions)]
#[test]
fn quick_check_metadata_repair_does_not_touch_a_concurrent_publication() {
    let t = Tmp::new();
    write(&t.path("basis"), b"aaaa");
    write(&t.path("first"), b"aaaa");
    write(&t.path("second"), b"bbbb");
    fs::set_permissions(t.path("basis"), fs::Permissions::from_mode(0o644)).unwrap();
    fs::set_permissions(t.path("first"), fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(t.path("second"), fs::Permissions::from_mode(0o640)).unwrap();
    set_mtime(&t.path("basis"), 1_600_000_000);
    set_mtime(&t.path("first"), 1_600_000_000);
    set_mtime(&t.path("second"), 1_600_000_001);
    let ready = t.path("quick-meta-ready");

    let mut first = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["-a", "--no-progress", &t.s("first"), &t.s("basis")])
        .env("SYQ_TEST_QUICK_META_READY_FILE", &ready)
        .env("SYQ_TEST_HOLD_QUICK_META_MS", "2000")
        .spawn()
        .unwrap();
    let held = (0..300).any(|_| {
        if ready.exists() {
            true
        } else {
            std::thread::sleep(std::time::Duration::from_millis(10));
            false
        }
    });
    assert!(held, "first copy never reached quick-check metadata repair");

    let second = syq(&["-a", &t.s("second"), &t.s("basis")]);
    assert_output_ok(&second);
    assert_eq!(read(&t.path("basis")), b"bbbb");
    let published = fs::metadata(t.path("basis")).unwrap();
    assert_eq!(published.mode() & 0o777, 0o640);
    assert_eq!(published.mtime(), 1_600_000_001);

    assert_eq!(first.wait().unwrap().code(), Some(23));
    assert_eq!(read(&t.path("basis")), b"bbbb");
    let published = fs::metadata(t.path("basis")).unwrap();
    assert_eq!(published.mode() & 0o777, 0o640);
    assert_eq!(published.mtime(), 1_600_000_001);
}

#[test]
fn quick_check_repairs_mode_without_destination_read_permission() {
    let t = Tmp::new();
    write(&t.path("src"), b"same contents");
    write(&t.path("dst"), b"same contents");
    fs::set_permissions(t.path("src"), fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o000)).unwrap();
    set_mtime(&t.path("src"), 1_600_000_000);
    set_mtime(&t.path("dst"), 1_600_000_000);

    let output = run_ok(&["-a", &t.s("src"), &t.s("dst")]);

    assert_eq!(transferred(&output), 0, "{output}");
    assert_eq!(fs::metadata(t.path("dst")).unwrap().mode() & 0o777, 0o600);
    assert_eq!(read(&t.path("dst")), b"same contents");
}

#[cfg(debug_assertions)]
#[test]
fn quick_check_metadata_open_reports_concurrent_fifo_without_blocking() {
    use std::os::unix::fs::FileTypeExt;

    let t = Tmp::new();
    write(&t.path("basis"), b"same");
    write(&t.path("first"), b"same");
    mkfifo(&t.path("second"));
    fs::set_permissions(t.path("basis"), fs::Permissions::from_mode(0o644)).unwrap();
    fs::set_permissions(t.path("first"), fs::Permissions::from_mode(0o600)).unwrap();
    set_mtime(&t.path("basis"), 1_600_000_000);
    set_mtime(&t.path("first"), 1_600_000_000);
    let ready = t.path("quick-meta-ready");

    let mut first = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["-a", "--no-progress", &t.s("first"), &t.s("basis")])
        .env("SYQ_TEST_QUICK_META_READY_FILE", &ready)
        .env("SYQ_TEST_HOLD_QUICK_META_MS", "1000")
        .spawn()
        .unwrap();
    let held = (0..300).any(|_| {
        if ready.exists() {
            true
        } else {
            std::thread::sleep(std::time::Duration::from_millis(10));
            false
        }
    });
    assert!(held, "first copy never reached quick-check metadata repair");

    assert_output_ok(&syq(&["-a", &t.s("second"), &t.s("basis")]));
    let status = (0..300).find_map(|_| {
        let status = first.try_wait().unwrap();
        if status.is_none() {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        status
    });
    if status.is_none() {
        let _ = first.kill();
        let _ = first.wait();
        panic!("quick-check repair blocked while opening a concurrently published FIFO");
    }
    assert_eq!(status.unwrap().code(), Some(23));
    assert!(fs::symlink_metadata(t.path("basis"))
        .unwrap()
        .file_type()
        .is_fifo());
}

#[test]
fn checksum_identical_file_preserves_destination_inode() {
    let t = Tmp::new();
    let contents = vec![b'a'; 8 * 1024 * 1024];
    write(&t.path("src"), &contents);
    write(&t.path("dst"), &contents);
    fs::hard_link(t.path("dst"), t.path("alias")).unwrap();
    fs::set_permissions(t.path("src"), fs::Permissions::from_mode(0o600)).unwrap();
    set_mtime(&t.path("src"), 1_600_000_001);
    set_mtime(&t.path("dst"), 1_600_000_000);
    let before = fs::metadata(t.path("dst")).unwrap();

    let output = run_ok(&["-ac", "--bwlimit", "1G", &t.s("src"), &t.s("dst")]);

    assert_eq!(transferred(&output), 0, "{output}");
    let after = fs::metadata(t.path("dst")).unwrap();
    assert_eq!(after.dev(), before.dev());
    assert_eq!(after.ino(), before.ino());
    assert_eq!(fs::metadata(t.path("alias")).unwrap().ino(), before.ino());
    assert_eq!(after.mode() & 0o777, 0o600);
    assert_eq!(after.mtime(), 1_600_000_001);
    assert!(partial_files(&t.0).is_empty());
}

#[cfg(debug_assertions)]
#[test]
fn unreadable_interrupted_partials_are_reused() {
    let t = Tmp::new();
    let contents = vec![b'a'; 8 * 1024 * 1024];
    write(&t.path("src"), &contents);
    for (i, mode) in [0o444, 0o000].into_iter().enumerate() {
        let src = t.s("src");
        let dst = t.s(&format!("out-{i}"));
        let args = ["-a", "--bwlimit", "1G", &src, &dst];
        let partial = interrupted_partial(&args, &t.0);
        fs::set_permissions(&partial, fs::Permissions::from_mode(mode)).unwrap();

        run_ok(&args);
        assert_eq!(read(&t.path(&format!("out-{i}"))), contents);
        assert!(!partial.exists());
    }
}

#[cfg(debug_assertions)]
#[test]
fn unchmodable_interrupted_partial_is_replaced() {
    let t = Tmp::new();
    let contents = vec![b'a'; 8 * 1024 * 1024];
    write(&t.path("src"), &contents);
    let src = t.s("src");
    let dst = t.s("dst");
    let args = ["-a", "--bwlimit", "1G", &src, &dst];
    let partial = interrupted_partial(&args, &t.0);
    fs::set_permissions(&partial, fs::Permissions::from_mode(0o000)).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(args)
        .arg("--no-progress")
        .env("SYQ_TEST_FAIL_PARTIAL_CHMOD", "1")
        .output()
        .unwrap();

    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), contents);
    assert!(!partial.exists());
}

#[cfg(debug_assertions)]
#[test]
fn writable_interrupted_partial_is_made_private_before_reuse() {
    let t = Tmp::new();
    let contents = vec![b'a'; 8 * 1024 * 1024];
    write(&t.path("src"), &contents);
    let src = t.s("src");
    let dst = t.s("dst");
    let args = ["-a", "--bwlimit", "1M", &src, &dst];
    let partial = interrupted_partial(&args, &t.0);
    fs::set_permissions(&partial, fs::Permissions::from_mode(0o644)).unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(args)
        .arg("--no-progress")
        .env("SYQ_TEST_HOLD_PARTIAL_MS", "10000")
        .spawn()
        .unwrap();
    for _ in 0..300 {
        if fs::metadata(&partial).unwrap().mode() & 0o7777 == 0o600 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert_eq!(fs::metadata(&partial).unwrap().mode() & 0o7777, 0o600);
    child.kill().unwrap();
    child.wait().unwrap();
}

#[cfg(all(debug_assertions, target_os = "linux"))]
#[test]
fn copy_local_exdev_fallback_leaves_no_partial() {
    let t = Tmp::new();
    let contents = vec![b'x'; 8 * 1024 * 1024];
    write(&t.path("src"), &contents);
    write(&t.path("dst"), &contents);
    set_mtime(&t.path("src"), 1_600_000_001);
    set_mtime(&t.path("dst"), 1_600_000_000);

    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["-a", "-j", "1", "--no-progress", &t.s("src"), &t.s("dst")])
        .env("SYQ_TEST_COPY_LOCAL_EXDEV", "1")
        .output()
        .unwrap();
    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), contents);
    assert!(partial_files(&t.0).is_empty());
}

#[cfg(debug_assertions)]
#[test]
fn long_basename_partial_is_truncated_and_resumed() {
    let t = Tmp::new();
    let basename = "n".repeat(240);
    let contents = vec![b'z'; 5 * 1024 * 1024];
    write(&t.path(&format!("src/{basename}")), &contents);
    fs::create_dir_all(t.path("dst")).unwrap();
    let src = t.s(&format!("src/{basename}"));
    let dst = t.s("dst/");
    let args = ["-a", "--bwlimit", "1G", &src, &dst];
    let partial = interrupted_partial(&args, &t.path("dst"));
    assert!(partial.file_name().unwrap().as_encoded_bytes().len() <= 255);
    assert!(partial
        .file_name()
        .unwrap()
        .to_string_lossy()
        .contains(".syq-part."));

    run_ok(&args);
    assert_eq!(read(&t.path(&format!("dst/{basename}"))), contents);
    assert!(!partial.exists());
}

#[test]
fn impossible_sidecar_name_fails_one_file_and_continues() {
    let t = Tmp::new();
    let mut deep = PathBuf::new();
    let target_parent_len = libc::PATH_MAX as usize - 20;
    loop {
        let current = t
            .path("dst")
            .join(&deep)
            .as_os_str()
            .as_encoded_bytes()
            .len();
        if current >= target_parent_len {
            break;
        }
        let component_len = (target_parent_len - current - 1).min(200);
        assert!(component_len > 0);
        deep.push("d".repeat(component_len));
    }
    assert!(
        t.path("dst")
            .join(&deep)
            .as_os_str()
            .as_encoded_bytes()
            .len()
            >= target_parent_len
    );

    write(&t.path("src/good"), b"copied");
    write(
        &t.path("src").join(&deep).join("x"),
        b"cannot fit a sidecar",
    );

    let output = syq(&["-a", &t.s("src/"), &t.s("dst/")]);

    assert_eq!(output.status.code(), Some(23));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cannot create a safe sidecar"), "{stderr}");
    assert_eq!(read(&t.path("dst/good")), b"copied");
    assert!(!t.path("dst").join(deep).join("x").exists());
}

#[cfg(debug_assertions)]
#[test]
fn changed_source_retry_uses_published_file_as_block_basis() {
    let t = Tmp::new();
    let original = vec![b'a'; 8 * 1024 * 1024];
    let mut changed = original.clone();
    changed[0] = b'b';
    write(&t.path("src"), &original);
    set_mtime(&t.path("src"), 1_600_000_000);

    let child = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "-a",
            "--stats",
            "--bwlimit",
            "1G",
            "--no-progress",
            &t.s("src"),
            &t.s("dst"),
        ])
        .env("SYQ_TEST_HOLD_AFTER_FINALIZE_MS", "1000")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    for _ in 0..200 {
        if t.path("dst").exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(t.path("dst").exists(), "first attempt never finalized");
    write(&t.path("replacement"), &changed);
    set_mtime(&t.path("replacement"), 1_600_000_001);
    fs::rename(t.path("replacement"), t.path("src")).unwrap();

    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(read(&t.path("dst")), changed);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("bytes transferred: 12,582,912"),
        "retry should send one changed 4 MiB block, not the full file: {stdout}"
    );
}

#[cfg(all(debug_assertions, target_os = "linux"))]
#[test]
fn changed_source_retry_still_uses_copy_file_range() {
    let t = Tmp::new();
    let original = vec![b'a'; 8 * 1024 * 1024];
    let changed = vec![b'b'; 8 * 1024 * 1024];
    write(&t.path("src"), &original);
    set_mtime(&t.path("src"), 1_600_000_000);

    let child = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["-a", "--no-progress", &t.s("src"), &t.s("dst")])
        .env("SYQ_TEST_HOLD_AFTER_FINALIZE_MS", "1000")
        .env("SYQ_TEST_FAIL_HASH_BASIS", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    for _ in 0..200 {
        if t.path("dst").exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(t.path("dst").exists(), "first attempt never finalized");
    write(&t.path("replacement"), &changed);
    set_mtime(&t.path("replacement"), 1_600_000_001);
    fs::rename(t.path("replacement"), t.path("src")).unwrap();

    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(read(&t.path("dst")), changed);
}

// A destination given as a symlink to a directory is that directory, whether
// or not it's spelled with a trailing slash: the link survives, the payload
// lands in its target.
#[test]
fn symlink_destination_is_followed() {
    for spelling in ["link", "link/"] {
        let t = Tmp::new();
        write(&t.path("src/f"), b"hi");
        fs::create_dir_all(t.path("real")).unwrap();
        std::os::unix::fs::symlink("real", t.path("link")).unwrap();
        run_ok(&["-a", &t.s("src/"), &t.s(spelling)]);
        assert!(
            fs::symlink_metadata(t.path("link"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "{spelling}: the symlink must survive"
        );
        assert_eq!(read(&t.path("real/f")), b"hi", "{spelling}");
    }
    let t = Tmp::new();
    write(&t.path("src/f"), b"hi");
    fs::create_dir_all(t.path("real")).unwrap();
    std::os::unix::fs::symlink("real", t.path("link")).unwrap();
    run_ok(&["-a", &t.s("src"), &t.s("link")]);
    assert!(fs::symlink_metadata(t.path("link"))
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(read(&t.path("real/src/f")), b"hi");
}

#[test]
fn in_tree_destination_symlink_is_replaced_not_followed() {
    let t = Tmp::new();
    write(&t.path("src/sub/f"), b"payload");
    fs::create_dir_all(t.path("dst")).unwrap();
    fs::create_dir_all(t.path("elsewhere")).unwrap();
    std::os::unix::fs::symlink("../elsewhere", t.path("dst/sub")).unwrap();

    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);

    assert!(fs::symlink_metadata(t.path("dst/sub")).unwrap().is_dir());
    assert_eq!(read(&t.path("dst/sub/f")), b"payload");
    assert!(!t.path("elsewhere/f").exists());
}

#[test]
fn destination_root_symlink_preserves_target_metadata_for_both_spellings() {
    for spelling in ["link", "link/"] {
        let t = Tmp::new();
        write(&t.path("src/f"), b"payload");
        fs::set_permissions(t.path("src"), fs::Permissions::from_mode(0o555)).unwrap();
        set_mtime(&t.path("src"), 1_600_000_000);
        fs::create_dir_all(t.path("real")).unwrap();
        std::os::unix::fs::symlink("real", t.path("link")).unwrap();

        run_ok(&["-a", &t.s("src/"), &t.s(spelling)]);

        let metadata = fs::metadata(t.path("real")).unwrap();
        assert_eq!(metadata.mode() & 0o777, 0o555, "{spelling}");
        assert_eq!(metadata.mtime(), 1_600_000_000, "{spelling}");
        assert_eq!(read(&t.path("real/f")), b"payload", "{spelling}");
        assert!(fs::symlink_metadata(t.path("link"))
            .unwrap()
            .file_type()
            .is_symlink());
    }
}

// The copy-into-itself guard resolves paths the way the kernel does: `..`
// after a symlink pops the link's target, so a destination that physically
// lands inside the source is refused even when it lexically looks elsewhere.
#[test]
fn self_copy_guard_sees_through_symlinks() {
    let t = Tmp::new();
    write(&t.path("src/inner/f"), b"x");
    std::os::unix::fs::symlink(t.path("src/inner"), t.path("link")).unwrap();
    // link/../out == src/out: inside the source.
    let out = syq(&["-a", &t.s("src/"), &t.s("link/../out/")]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("into itself"), "stderr: {err}");
    assert!(!t.path("src/out").exists());
}

// Metadata-only reconciliation is a valid checkpoint completion. The explicit
// checkpoint then trusts it on retry, just like a transferred completion.
#[cfg(debug_assertions)]
#[test]
fn checkpoint_records_metadata_only_reconcile() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"");
    write(&t.path("src/fail/y"), b"trigger");
    set_mtime(&t.path("src/f"), 1_600_000_000);
    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    set_mtime(&t.path("src/f"), 1_600_000_001);
    let checkpoint = t.s("copy.checkpoint");
    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "-a",
            "--no-progress",
            "--checkpoint",
            &checkpoint,
            &t.s("src/"),
            &t.s("dst/"),
        ])
        .env("SYQ_TEST_FAIL_SETMETA", "fail")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(23));
    assert_eq!(
        fs::metadata(t.path("dst/f")).unwrap().mtime(),
        1_600_000_001
    );
    fs::remove_file(t.path("dst/f")).unwrap();
    run_ok(&[
        "-a",
        "--checkpoint",
        &checkpoint,
        &t.s("src/"),
        &t.s("dst/"),
    ]);
    assert!(
        !t.path("dst/f").exists(),
        "the metadata-only reconcile must have been checkpointed"
    );
}

// Unsupported rsync flags get a helpful, specific error (not clap's generic
// "unexpected argument"), and the filter family points at -i.
#[test]
fn unsupported_rsync_flags_explain_themselves() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"x");

    let out = syq(&[
        "-a",
        "--exclude",
        "node_modules",
        &t.s("src/"),
        &t.s("dst/"),
    ]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("-i/--ignore"), "should point to -i: {err}");
    assert!(err.contains("gitignore"), "should mention gitignore: {err}");

    let out = syq(&["-a", "--delete-during", &t.s("src/"), &t.s("dst/")]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("after the transfer"));

    // Bundled short flags from a pasted `rsync -aHz` are caught too (the
    // unsupported letter is found inside the cluster).
    let out = syq(&["-aHz", &t.s("src/"), &t.s("dst/")]);
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("hard links"),
        "bundled -H should be explained: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn removed_fsync_option_is_rejected() {
    let t = Tmp::new();
    write(&t.path("src"), b"data");
    let output = syq(&["--fsync", &t.s("src"), &t.s("dst")]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unexpected argument '--fsync'"), "{stderr}");
    assert!(!t.path("dst").exists());
}

// Compatibility no-ops are accepted and change nothing.
#[test]
fn rsync_compat_noops_are_accepted() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"hello");
    // --numeric-ids, --partial, -P, -h are all no-ops here.
    run_ok(&[
        "-a",
        "--numeric-ids",
        "--partial",
        "-P",
        "-h",
        &t.s("src/"),
        &t.s("dst/"),
    ]);
    assert_eq!(read(&t.path("dst/f")), b"hello");
}

// A value that happens to look like an unsupported flag is not misread.
#[test]
fn flag_like_ignore_pattern_is_not_rejected() {
    let t = Tmp::new();
    write(&t.path("src/keep"), b"k");
    // `-i --exclude` means "ignore a pattern literally named --exclude"; it must
    // not trip the --exclude rejection.
    run_ok(&["-a", "-i", "--exclude", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(read(&t.path("dst/keep")), b"k");
}

// ------------------------------------------------------------ review round 6

#[test]
fn existing_opens_up_readonly_dirs_even_after_a_symlinked_dir() {
    let t = Tmp::new();
    write(&t.path("src/s/x"), b"x");
    write(&t.path("src/r/y"), b"new");
    write(&t.path("elsewhere/x"), b"x");
    write(&t.path("dst/r/y"), b"old");
    set_mtime(&t.path("src/r/y"), 2000);
    set_mtime(&t.path("dst/r/y"), 1000);
    // `s` sorts before `r`? No — make the symlinked dir sort first explicitly.
    fs::rename(t.path("src/s"), t.path("src/a")).unwrap();
    std::os::unix::fs::symlink(t.path("elsewhere"), t.path("dst/a")).unwrap();
    fs::set_permissions(t.path("dst/r"), fs::Permissions::from_mode(0o500)).unwrap();
    let so = run_ok(&["-rt", "--existing", &t.s("src/"), &t.s("dst")]);
    assert_eq!(read(&t.path("dst/r/y")), b"new", "{so}");
    assert_eq!(read(&t.path("elsewhere/x")), b"x");
}

#[test]
fn partial_named_symlink_is_a_symlink_not_a_leftover() {
    let t = Tmp::new();
    write(&t.path("a/target"), b"t");
    std::os::unix::fs::symlink("target", t.path("a/.x.syq-part.aaaaaaaaaaaaaaaaaaaaaaaaaa"))
        .unwrap();
    write(&t.path("b/other"), b"o");
    std::os::unix::fs::symlink("target", t.path("b/.x.syq-part.aaaaaaaaaaaaaaaaaaaaaaaaaa"))
        .unwrap();
    run_ok(&["-a", &t.s("a/"), &t.s("dst")]);
    assert!(t
        .path("dst/.x.syq-part.aaaaaaaaaaaaaaaaaaaaaaaaaa")
        .symlink_metadata()
        .unwrap()
        .is_symlink());
    // Without -l the symlinks are skipped, and two sources skipping the same
    // path is not a collision.
    run_ok(&["-r", &t.s("a/"), &t.s("b/"), &t.s("dst2")]);
    assert!(!t
        .path("dst2/.x.syq-part.aaaaaaaaaaaaaaaaaaaaaaaaaa")
        .exists());
    assert!(t.path("dst2/target").is_file() && t.path("dst2/other").is_file());
}

#[test]
fn copy_onto_itself_among_sources_is_order_independent() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"a");
    write(&t.path("dst/a"), b"a");
    // Naming the destination file as a source, together with a different file
    // for the same path, is a conflict in either order: dst/a would be lost.
    write(&t.path("src/a"), b"changed");
    for args in [
        [&t.s("src/"), &t.s("dst/a"), &t.s("dst/")],
        [&t.s("dst/a"), &t.s("src/"), &t.s("dst/")],
    ] {
        let out = syq(&["-r", args[0], args[1], args[2]]);
        assert_eq!(out.status.code(), Some(1), "{}", stderr_of(&out));
        assert_eq!(read(&t.path("dst/a")), b"a", "untouched");
    }
    // The destination file alone, given twice over two sources, is a no-op.
    fs::create_dir_all(t.path("h")).unwrap();
    fs::hard_link(t.path("dst/a"), t.path("h/a")).unwrap();
    run_ok(&["-r", &t.s("dst/a"), &t.s("h/"), &t.s("dst/")]);
    assert_eq!(read(&t.path("dst/a")), b"a");
    // Two different files onto one destination is still a collision.
    write(&t.path("src2/a"), b"different");
    let out = syq(&["-r", &t.s("src/"), &t.s("src2/"), &t.s("dst3/")]);
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn bad_size_limits_fail_before_anything_connects() {
    for value in ["12Q", "-1", "18446744073709551616", "1e999"] {
        let t0 = std::time::Instant::now();
        let max_size = format!("--max-size={value}");
        let out = syq(&["-a", &max_size, "nohost-a.invalid:x", "nohost-b.invalid:y"]);
        assert!(!out.status.success(), "accepted {value:?}");
        assert!(
            stderr_of(&out).contains("bad size"),
            "{value:?}: {}",
            stderr_of(&out)
        );
        assert!(t0.elapsed() < std::time::Duration::from_secs(2));
    }
}

#[test]
fn verify_only_checks_the_filtered_scope() {
    let t = Tmp::new();
    write(&t.path("src/big"), b"abc");
    write(&t.path("dst/big"), b"xyz");
    let out = syq(&["-a", "--verify-only", &t.s("src/"), &t.s("dst")]);
    assert_eq!(out.status.code(), Some(23));
    let so = run_ok(&[
        "-a",
        "--verify-only",
        "--max-size",
        "1",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert!(so.contains("verified 0 files"), "{so}");
    set_mtime(&t.path("src/big"), 1000);
    set_mtime(&t.path("dst/big"), 2000);
    let so = run_ok(&["-a", "--verify-only", "-u", &t.s("src/"), &t.s("dst")]);
    assert!(so.contains("verified 0 files"), "{so}");
}

#[test]
fn files_from_leaves_no_ancestors_behind_on_a_bad_chain() {
    let t = Tmp::new();
    write(&t.path("src/a/b"), b"b is a file");
    write(&t.path("list"), b"a/b/c\n");
    let out = syq(&["-a", "--files-from", &t.s("list"), &t.s("src"), &t.s("dst")]);
    assert_eq!(out.status.code(), Some(23));
    assert_eq!(listing(&t.path("dst")), Vec::<String>::new());
}

#[test]
fn stats_report_connection_tuning_mode() {
    let t = Tmp::new();
    std::fs::create_dir_all(t.path("src")).unwrap();
    for i in 0..20 {
        std::fs::write(t.path(&format!("src/f{i}")), vec![b'x'; 1000]).unwrap();
    }
    // Without -j the count is auto-tuned; a short local copy never leaves the
    // local starting count of 32.
    let out = run_ok(&["-a", "--stats", &t.s("src/"), &t.s("auto/")]);
    assert!(
        out.contains("connections: auto: settled at 32 (path 32, peak 32)"),
        "{out}"
    );
    // An explicit -j is used as given, with no tuning.
    let out = run_ok(&["-a", "--stats", "-j", "3", &t.s("src/"), &t.s("fixed/")]);
    assert!(out.contains("connections: 3\n"), "{out}");
}

// --------------------------------------- --delete-after/-delay, --delete-excluded, --max-delete

#[test]
fn delete_after_and_delay_are_synonyms() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"a");
    for flag in ["--delete-after", "--delete-delay"] {
        write(&t.path("dst/extra"), b"x");
        run_ok(&["-a", flag, &t.s("src/"), &t.s("dst")]);
        assert!(!t.path("dst/extra").exists(), "{flag}");
    }
    let out = syq(&["-a", "--delete-before", &t.s("src/"), &t.s("dst")]);
    assert!(!out.status.success());
    assert!(stderr_of(&out).contains("after the transfer"));
}

#[test]
fn delete_excluded_removes_ignored_destination_paths() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"a");
    write(&t.path("src/junk.log"), b"src log, never copied");
    write(&t.path("dst/keep/k.log"), b"k");
    write(&t.path("dst/junk.log"), b"old");
    // Protected without the flag...
    run_ok(&["-a", "--delete", "-i", "*.log", &t.s("src/"), &t.s("dst")]);
    assert_eq!(
        listing(&t.path("dst")),
        ["a", "junk.log", "keep", "keep/k.log"]
    );
    // ...extras with it, including the directory that only held them.
    let so = run_ok(&[
        "-a",
        "--delete",
        "--delete-excluded",
        "-i",
        "*.log",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert_eq!(listing(&t.path("dst")), ["a"]);
    assert!(so.contains("3 deleted"), "{so}");
    assert!(
        !t.path("dst/junk.log").exists(),
        "source's ignored file is not copied either"
    );
}

#[test]
fn max_delete_refuses_everything_past_the_limit() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"a");
    for i in 0..5 {
        write(&t.path(&format!("dst/extra{i}")), b"x");
    }
    let dry = syq(&[
        "-an",
        "--delete",
        "--max-delete",
        "3",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert_eq!(dry.status.code(), Some(25), "{}", stderr_of(&dry));
    let dry_stdout = String::from_utf8_lossy(&dry.stdout);
    assert!(
        dry_stdout.contains("deletions: 5 entries planned; blocked by --max-delete 3"),
        "{dry_stdout}"
    );
    assert_eq!(listing(&t.path("dst")).len(), 5, "dry run changed files");

    let out = syq(&[
        "-a",
        "--delete",
        "--max-delete",
        "3",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert_eq!(out.status.code(), Some(25), "{}", stderr_of(&out));
    assert!(
        stderr_of(&out).contains("5 deletions planned"),
        "{}",
        stderr_of(&out)
    );
    assert_eq!(listing(&t.path("dst")).len(), 6, "nothing deleted");
    assert_eq!(
        read(&t.path("dst/a")),
        b"a",
        "the copy itself still happened"
    );
    run_ok(&[
        "-a",
        "--delete",
        "--max-delete",
        "5",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert_eq!(listing(&t.path("dst")), ["a"]);
    // --max-delete without --delete is a usage error.
    let out = syq(&["-a", "--max-delete", "5", &t.s("src/"), &t.s("dst")]);
    assert!(!out.status.success());
}

// ------------------------------------------------------------ review round 7

#[test]
fn cross_source_collision_is_detected_before_any_change() {
    let t = Tmp::new();
    fs::create_dir_all(t.path("a")).unwrap();
    std::os::unix::fs::symlink("nowhere", t.path("a/x")).unwrap();
    write(&t.path("a/other"), b"o");
    write(&t.path("b/x/inside"), b"i");
    write(&t.path("dst/x"), b"precious file");
    let out = syq(&["-a", &t.s("a/"), &t.s("b/"), &t.s("dst")]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr_of(&out));
    assert!(stderr_of(&out).contains("refusing to clobber"));
    assert_eq!(
        read(&t.path("dst/x")),
        b"precious file",
        "nothing was written"
    );
    assert!(
        !t.path("dst/other").exists(),
        "nothing from either source was applied"
    );
}

#[test]
fn files_from_symlink_conflict_is_order_independent() {
    let t = Tmp::new();
    write(&t.path("outside/secret"), b"s");
    fs::create_dir_all(t.path("src")).unwrap();
    std::os::unix::fs::symlink("../outside", t.path("src/link")).unwrap();
    for (n, list) in [("1", "link\nlink/secret\n"), ("2", "link/secret\nlink\n")] {
        write(&t.path(&format!("list{n}")), list.as_bytes());
        let out = syq(&[
            "-a",
            "--files-from",
            &t.s(&format!("list{n}")),
            &t.s("src"),
            &t.s(&format!("dst{n}")),
        ]);
        assert_eq!(
            out.status.code(),
            Some(23),
            "order {n}: {}",
            stderr_of(&out)
        );
        let md = t.path(&format!("dst{n}/link")).symlink_metadata().unwrap();
        // Either the symlink alone (order 1) or a real directory (order 2) —
        // never a write through a destination symlink.
        assert!(md.is_symlink() || md.is_dir());
        assert!(!t.path("outside/secret2").exists());
    }
    assert_eq!(read(&t.path("dst2/link/secret")), b"s");
    assert!(t.path("dst2/link").symlink_metadata().unwrap().is_dir());
}

#[test]
fn three_claimants_are_validated_as_a_group() {
    let t = Tmp::new();
    write(&t.path("dst/x"), b"dest content");
    fs::create_dir_all(t.path("a")).unwrap();
    fs::hard_link(t.path("dst/x"), t.path("a/x")).unwrap();
    write(&t.path("b/x"), b"from b");
    write(&t.path("c/x"), b"from c");
    // a/x is the destination file; b/x and c/x are two different contents.
    let out = syq(&["-r", &t.s("a/"), &t.s("b/"), &t.s("c/"), &t.s("dst")]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr_of(&out));
    assert!(stderr_of(&out).contains("3 sources map to the same destination"));
    assert_eq!(read(&t.path("dst/x")), b"dest content");
    // Even one other content is a conflict: dst/x was named as a source.
    let out = syq(&["-r", &t.s("b/"), &t.s("a/"), &t.s("dst")]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(read(&t.path("dst/x")), b"dest content");
}

#[test]
fn conflicting_sources_leave_no_destination_behind() {
    let t = Tmp::new();
    write(&t.path("a/x"), b"1");
    write(&t.path("b/x"), b"2");
    let out = syq(&["-r", &t.s("a/"), &t.s("b/"), &t.s("dst/")]);
    assert_eq!(out.status.code(), Some(1));
    assert!(!t.path("dst").exists(), "destination must not be created");
    // And a clean multi-source copy into a missing destination still works.
    write(&t.path("c/y"), b"3");
    run_ok(&["-r", &t.s("a/"), &t.s("c/"), &t.s("dst2/")]);
    assert_eq!(listing(&t.path("dst2")), ["x", "y"]);
}

// ------------------------------------------------------------ review round 8

#[test]
fn files_from_onto_a_file_destination_is_refused() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"a");
    write(&t.path("list"), b"a\n");
    write(&t.path("dst"), b"a precious file");
    let out = syq(&["-a", "--files-from", &t.s("list"), &t.s("src"), &t.s("dst")]);
    assert!(!out.status.success());
    assert!(
        stderr_of(&out).contains("needs a directory destination"),
        "{}",
        stderr_of(&out)
    );
    assert_eq!(read(&t.path("dst")), b"a precious file");
}

#[test]
fn sidecar_named_source_directory_is_payload() {
    // A sidecar-looking name in the source is ordinary payload (with one
    // warning); it uses another job's id, so it can't collide with this job's
    // own sidecar for `name`, and later updates of `name` still stage fine.
    let t = Tmp::new();
    let sidecar_dir = format!("src/.name.syq-part.{}", "a".repeat(26));
    write(&t.path(&format!("{sidecar_dir}/inside")), b"i");
    write(&t.path("src/name"), b"v1");
    let out = syq(&["-a", &t.s("src/"), &t.s("dst")]);
    assert!(out.status.success(), "{}", stderr_of(&out));
    assert!(
        stderr_of(&out).contains("recognizable SYQ partial path"),
        "{}",
        stderr_of(&out)
    );
    let sidecar_rel = &sidecar_dir["src/".len()..];
    assert_eq!(
        listing(&t.path("dst")),
        [sidecar_rel, &format!("{sidecar_rel}/inside"), "name"]
    );
    write(&t.path("src/name"), &vec![7u8; 8 << 20]);
    run_ok(&["-a", &t.s("src/"), &t.s("dst")]);
    assert_eq!(read(&t.path("dst/name")), vec![7u8; 8 << 20]);
    assert_eq!(listing(&t.path("dst")).len(), 3);
}

#[test]
fn files_from_rejections_and_stdin() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"a");
    write(&t.path("src/b"), b"b");
    write(&t.path("list"), b"a\n");
    // `-` reads the list from stdin.
    let mut child = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "-a",
            "--files-from",
            "-",
            "--no-progress",
            &t.s("src"),
            &t.s("dst"),
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"b\n").unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    assert_eq!(listing(&t.path("dst")), ["b"]);
    // Cannot combine with -i / --ignore-from / --delete (clap-level errors).
    for extra in [["-i", "x"], ["--ignore-from", "list"], ["--delete", "-v"]] {
        let out = syq(&[
            "-a",
            "--files-from",
            &t.s("list"),
            extra[0],
            extra[1],
            &t.s("src"),
            &t.s("dst2"),
        ]);
        assert!(!out.status.success(), "{extra:?}");
        assert!(
            stderr_of(&out).contains("cannot be used with"),
            "{extra:?}: {}",
            stderr_of(&out)
        );
    }
    assert!(!t.path("dst2").exists());
    // Direct remote-to-remote needs --relay; refused before anything connects.
    let t0 = std::time::Instant::now();
    let out = syq(&[
        "-a",
        "--files-from",
        &t.s("list"),
        "nohost-a.invalid:x",
        "nohost-b.invalid:y",
    ]);
    assert!(!out.status.success());
    assert!(
        stderr_of(&out).contains("needs --relay"),
        "{}",
        stderr_of(&out)
    );
    assert!(t0.elapsed() < std::time::Duration::from_secs(2));
}

// ------------------------------------------------------------ review round 9

#[cfg(debug_assertions)]
#[test]
fn truncated_sidecar_of_a_filtered_file_survives_delete() {
    // A 240-character basename forces the truncated sidecar form, whose name
    // cannot be read back to its target; liveness must come from the
    // preflight's sidecar set, not from parsing.
    let t = Tmp::new();
    let long = "n".repeat(240);
    write(&t.path(&format!("src/{long}")), &vec![7u8; 8 << 20]);
    fs::create_dir_all(t.path("dst")).unwrap();
    let partial = interrupted_partial(
        &["-a", "--bwlimit", "1G", &t.s("src/"), &t.s("dst")],
        &t.path("dst"),
    );
    let so = run_ok(&[
        "-a",
        "--bwlimit",
        "1G",
        "--delete",
        "--max-size",
        "1K",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert!(partial.exists(), "{so}");
    assert!(so.contains("0 deleted"), "{so}");
    // Once the file leaves the source, the same sidecar is an orphan.
    fs::remove_file(t.path(&format!("src/{long}"))).unwrap();
    run_ok(&[
        "-a",
        "--bwlimit",
        "1G",
        "--delete",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert!(!partial.exists());
}

#[cfg(debug_assertions)]
#[test]
fn sidecar_whose_target_became_a_directory_is_an_orphan() {
    let t = Tmp::new();
    write(&t.path("src/x"), &vec![7u8; 8 << 20]);
    fs::create_dir_all(t.path("dst")).unwrap();
    let partial = interrupted_partial(
        &["-a", "--bwlimit", "1G", &t.s("src/"), &t.s("dst")],
        &t.path("dst"),
    );
    fs::remove_file(t.path("src/x")).unwrap();
    write(&t.path("src/x/inside"), b"now a directory");
    run_ok(&[
        "-a",
        "--bwlimit",
        "1G",
        "--delete",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert!(!partial.exists(), "no file transfer will ever consume it");
    assert_eq!(read(&t.path("dst/x/inside")), b"now a directory");
}

#[test]
fn sidecar_patterned_extras_do_not_block_directory_deletion() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"a");
    let foreign = format!("dst/extra/deep/.f.syq-part.{}", "a".repeat(26));
    write(&t.path(&foreign), b"unclaimed");
    write(&t.path("dst/extra/gone"), b"an ordinary extra");
    let so = run_ok(&["-a", "-n", "-v", "--delete", &t.s("src/"), &t.s("dst")]);
    assert!(so.contains("delete extra/ (destination only)"), "{so}");
    let out = syq(&["-a", "-v", "--delete", &t.s("src/"), &t.s("dst")]);
    assert!(out.status.success(), "{}", stderr_of(&out));
    assert_eq!(listing(&t.path("dst")), ["a"]);
}

// ----------------------------------------------------------- review round 10

#[test]
fn size_arguments_reject_negative_nan_and_overflow() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"data");
    for (flag, bad) in [
        ("--max-size", "-1"),
        ("--max-size", "-1K"),
        ("--min-size", "nan"),
        ("--max-size", "inf"),
        ("--max-size", "1e30"),
        ("--block-size", "-4M"),
    ] {
        let arg = format!("{flag}={bad}");
        let out = syq(&["-a", &arg, &t.s("src/"), &t.s("dst")]);
        assert!(!out.status.success(), "{arg}");
        assert!(
            stderr_of(&out).to_lowercase().contains("size"),
            "{arg}: {}",
            stderr_of(&out)
        );
        assert!(!t.path("dst/f").exists(), "{arg}: nothing may be copied");
    }
    // Fractional sizes keep working.
    let so = run_ok(&["-a", "--max-size", "1.5K", &t.s("src/"), &t.s("dst")]);
    assert_eq!(transferred(&so), 1);
}

#[test]
fn delete_records_checkpoint_intent_before_unlinking() {
    // A file the checkpoint recorded as complete leaves the source; --delete
    // tries to remove it but the unlink fails (read-only extra directory —
    // claimed directories get opened up, extras don't). The Deleted intent
    // must already be durable in the checkpoint — written before the unlink —
    // so a later restore with the same fingerprint is rechecked, not assumed.
    let t = Tmp::new();
    write(&t.path("src/sub/f"), b"data");
    set_mtime(&t.path("src/sub/f"), 1_600_000_000);
    run_ok(&[
        "-a",
        "--checkpoint",
        &t.s("state"),
        &t.s("src/"),
        &t.s("dst"),
    ]);
    fs::remove_dir_all(t.path("src/sub")).unwrap();
    fs::set_permissions(t.path("dst/sub"), fs::Permissions::from_mode(0o555)).unwrap();
    let out = syq(&[
        "-a",
        "--checkpoint",
        &t.s("state"),
        "--delete",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    fs::set_permissions(t.path("dst/sub"), fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(out.status.code(), Some(23), "{}", stderr_of(&out));
    assert!(t.path("dst/sub/f").exists(), "unlink really failed");
    let state = String::from_utf8_lossy(&read(&t.path("state"))).into_owned();
    assert!(
        state.contains("\"deleted\""),
        "intent must precede the unlink: {state}"
    );
}

#[test]
fn delete_halts_when_checkpoint_intents_cannot_be_persisted() {
    // RLIMIT_FSIZE pins the checkpoint at its current size, so the Deleted
    // intent cannot be appended. Deletion must then not happen at all:
    // unlinking would leave a durable Complete record for a missing file.
    use std::os::unix::process::CommandExt;
    let t = Tmp::new();
    write(&t.path("src/f"), b"data");
    set_mtime(&t.path("src/f"), 1_600_000_000);
    run_ok(&[
        "-a",
        "--checkpoint",
        &t.s("state"),
        &t.s("src/"),
        &t.s("dst"),
    ]);
    fs::remove_file(t.path("src/f")).unwrap();
    let limit = fs::metadata(t.path("state")).unwrap().len();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_syq"));
    cmd.args([
        "-a",
        "--checkpoint",
        &t.s("state"),
        "--delete",
        &t.s("src/"),
        &t.s("dst"),
        "--no-progress",
    ]);
    unsafe {
        cmd.pre_exec(move || {
            libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
            let rl = libc::rlimit {
                rlim_cur: limit,
                rlim_max: limit,
            };
            if libc::setrlimit(libc::RLIMIT_FSIZE, &rl) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let out = cmd.output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(23),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("could not persist deletion intents"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        t.path("dst/f").exists(),
        "nothing may be deleted without a durable intent"
    );
}

// ----------------------------------------------------------- review round 11

#[test]
fn inplace_conflicts_with_receiver_state_filters() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"data");
    for filter in ["-u", "--ignore-existing"] {
        let out = syq(&["-a", "--inplace", filter, &t.s("src/"), &t.s("dst")]);
        assert!(!out.status.success(), "{filter}");
        assert!(
            stderr_of(&out).contains("cannot be used with"),
            "{filter}: {}",
            stderr_of(&out)
        );
    }
    assert!(!t.path("dst").exists());
}

#[test]
fn checkpoint_invalidated_on_type_change_and_directory_removal() {
    // f completes as a file; the source turns f into a directory (type-change
    // invalidation), then drops it (--delete rmdir), then restores the
    // original file with an identical fingerprint. The checkpointed run must
    // transfer it — a stale Complete record would report "unchanged" while
    // the destination has nothing.
    let t = Tmp::new();
    write(&t.path("src/f"), b"data");
    set_mtime(&t.path("src/f"), 1_600_000_000);
    run_ok(&[
        "-a",
        "--checkpoint",
        &t.s("state"),
        &t.s("src/"),
        &t.s("dst"),
    ]);
    fs::remove_file(t.path("src/f")).unwrap();
    write(&t.path("src/f/child"), b"c");
    run_ok(&[
        "-a",
        "--checkpoint",
        &t.s("state"),
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert!(t.path("dst/f").is_dir());
    fs::remove_dir_all(t.path("src/f")).unwrap();
    run_ok(&[
        "-a",
        "--checkpoint",
        &t.s("state"),
        "--delete",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert!(!t.path("dst/f").exists());
    write(&t.path("src/f"), b"data");
    set_mtime(&t.path("src/f"), 1_600_000_000);
    let so = run_ok(&[
        "-a",
        "--checkpoint",
        &t.s("state"),
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert_eq!(read(&t.path("dst/f")), b"data", "{so}");
    assert_eq!(transferred(&so), 1, "{so}");
}

#[test]
fn files_from_self_copy_through_symlinked_root_is_rejected() {
    let t = Tmp::new();
    write(&t.path("real/a"), b"a");
    fs::create_dir_all(t.path("real/dstdir")).unwrap();
    std::os::unix::fs::symlink(t.path("real"), t.path("link")).unwrap();
    write(&t.path("list"), b"a\n");
    let out = syq(&[
        "-a",
        "-r",
        "--files-from",
        &t.s("list"),
        &t.s("link"),
        &t.s("real/dstdir"),
    ]);
    assert!(!out.status.success(), "{}", stderr_of(&out));
    assert!(
        stderr_of(&out).contains("maps inside source")
            || stderr_of(&out).contains("same directory"),
        "{}",
        stderr_of(&out)
    );
    assert_eq!(listing(&t.path("real")), ["a", "dstdir"], "nothing copied");
}

#[test]
fn destination_walk_errors_disable_deletion() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"a");
    write(&t.path("dst/gone"), b"an ordinary extra");
    write(&t.path("dst/dark/inside"), b"unknown contents");
    fs::set_permissions(t.path("dst/dark"), fs::Permissions::from_mode(0o000)).unwrap();
    let src_arg = t.s("src/");
    let dst_arg = t.s("dst");
    for flags in [vec!["-rt", "-n"], vec!["-rt"]] {
        let mut args = flags.clone();
        args.extend(["--delete", &src_arg, &dst_arg]);
        let out = syq(&args);
        assert_eq!(
            out.status.code(),
            Some(23),
            "{flags:?}: {}",
            stderr_of(&out)
        );
        assert!(
            stderr_of(&out).contains("destination walk reported errors; skipping deletions"),
            "{flags:?}: {}",
            stderr_of(&out)
        );
    }
    fs::set_permissions(t.path("dst/dark"), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(t.path("dst/gone").exists(), "nothing may be deleted");
    assert!(t.path("dst/dark/inside").exists());
}

#[test]
fn checkpoint_invalidation_survives_trailing_slash_destination() {
    // Same type-change sequence as above, but the destination is spelled
    // `dst/` and the file has a one-character name: join() adds no extra
    // separator for a trailing slash, so slicing the full path used to drop
    // the first byte of the key (or produce an empty one).
    let t = Tmp::new();
    write(&t.path("src/f"), b"data");
    set_mtime(&t.path("src/f"), 1_600_000_000);
    let dst = format!("{}/", t.s("dst"));
    run_ok(&["-a", "--checkpoint", &t.s("state"), &t.s("src/"), &dst]);
    fs::remove_file(t.path("src/f")).unwrap();
    write(&t.path("src/f/child"), b"c");
    run_ok(&["-a", "--checkpoint", &t.s("state"), &t.s("src/"), &dst]);
    assert!(t.path("dst/f").is_dir());
    fs::remove_dir_all(t.path("src/f")).unwrap();
    run_ok(&[
        "-a",
        "--checkpoint",
        &t.s("state"),
        "--delete",
        &t.s("src/"),
        &dst,
    ]);
    assert!(!t.path("dst/f").exists());
    write(&t.path("src/f"), b"data");
    set_mtime(&t.path("src/f"), 1_600_000_000);
    let so = run_ok(&["-a", "--checkpoint", &t.s("state"), &t.s("src/"), &dst]);
    assert!(t.path("dst/f").is_file(), "{so}");
    assert_eq!(read(&t.path("dst/f")), b"data");
    assert_eq!(transferred(&so), 1, "{so}");
}

#[cfg(debug_assertions)]
#[test]
fn live_sidecar_survives_delete_with_dotted_destination_spelling() {
    // `dst/.` and `dst//` must produce the same keys as `dst`: the receiver
    // rebuilds sidecar paths through Path (which normalizes), the delete walk
    // joins bytes (which doesn't), and a spelling mismatch classified the
    // job's own live sidecar as an orphan.
    for spelling in ["/.", "//"] {
        let t = Tmp::new();
        write(&t.path("src/f"), &vec![7u8; 8 << 20]);
        fs::create_dir_all(t.path("dst")).unwrap();
        let dst = format!("{}{spelling}", t.s("dst"));
        let partial = interrupted_partial(
            &["-a", "--bwlimit", "1G", &t.s("src/"), &dst],
            &t.path("dst"),
        );
        // Filtered target: the sidecar is resume state and must survive, in
        // this spelling and cross-spelling alike.
        let so = run_ok(&[
            "-a",
            "--bwlimit",
            "1G",
            "--delete",
            "--max-size",
            "10",
            &t.s("src/"),
            &dst,
        ]);
        assert!(partial.exists(), "{spelling}: {so}");
        let so = run_ok(&[
            "-a",
            "--bwlimit",
            "1G",
            "--delete",
            "--max-size",
            "10",
            &t.s("src/"),
            &t.s("dst"),
        ]);
        assert!(partial.exists(), "cross-spelling {spelling}: {so}");
    }
}

// ----------------------------------------------------------- review round 12

#[test]
fn files_from_leaves_unlisted_destination_root_metadata_alone() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"a");
    fs::set_permissions(t.path("src"), fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir_all(t.path("dst")).unwrap();
    fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o755)).unwrap();
    write(&t.path("list"), b"a\n");
    run_ok(&["-a", "--files-from", &t.s("list"), &t.s("src"), &t.s("dst")]);
    fs::set_permissions(t.path("src"), fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(read(&t.path("dst/a")), b"a");
    assert_eq!(
        fs::metadata(t.path("dst")).unwrap().mode() & 0o777,
        0o755,
        "the unlisted root keeps its own mode"
    );
    // An empty list still creates a missing destination (syq's choice:
    // rsync 3.2.7 creates it only when spelled with a trailing slash).
    write(&t.path("empty"), b"");
    run_ok(&[
        "-a",
        "--files-from",
        &t.s("empty"),
        &t.s("src"),
        &t.s("dst2"),
    ]);
    assert!(t.path("dst2").is_dir());
}

#[test]
fn direct_remote_to_remote_verbose_diagnostics_are_orchestrator_relative() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    fs::create_dir_all(t.path("remote-bin")).unwrap();
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_syq"), t.path("remote-bin/syq")).unwrap();
    write(&t.path("src/a"), b"a");

    let src = format!("hostA:{}", t.s("src/"));
    let dst = format!("hostB:{}", t.s("dst"));
    let out = remote_syq(
        &t,
        &rsh,
        &["-avv", "--dry-run", "--no-bootstrap", &src, &dst],
    );
    assert_output_ok(&out);
    assert!(!t.path("dst").exists());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("remote-to-remote: running on hostA"),
        "{stderr}"
    );
    assert!(stderr.contains("syq: hostB:\n"), "{stderr}");
    assert!(!stderr.contains("syq: hostA:\n"), "{stderr}");
    assert!(
        stderr.contains("transport: SSH planned for a real transfer (--no-tcp)"),
        "{stderr}"
    );

    let same_host_dst = format!("hostA:{}", t.s("same-host-dst"));
    let out = remote_syq(
        &t,
        &rsh,
        &["-avv", "--dry-run", "--no-bootstrap", &src, &same_host_dst],
    );
    assert_output_ok(&out);
    assert!(!t.path("same-host-dst").exists());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("remote-to-remote: running on hostA"),
        "{stderr}"
    );
    assert!(
        stderr.contains("syq: transport: local filesystem"),
        "{stderr}"
    );
    assert!(!stderr.contains("syq: hostA:\n"), "{stderr}");
}

#[test]
fn direct_remote_to_remote_passes_through_defined_exit_codes() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    fs::create_dir_all(t.path("remote-bin")).unwrap();
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_syq"), t.path("remote-bin/syq")).unwrap();
    write(&t.path("src/a"), b"a");
    write(&t.path("dst/extra1"), b"x");
    write(&t.path("dst/extra2"), b"y");
    let src = format!("fake:{}", t.s("src/"));
    let dst = format!("fake:{}", t.s("dst"));
    let dry = remote_syq(&t, &rsh, &["-an", "--no-bootstrap", &src, &dst]);
    assert_output_ok(&dry);
    let dry_stdout = String::from_utf8_lossy(&dry.stdout);
    assert!(
        dry_stdout.contains(&format!(
            "mapping: fake:{} -> fake:{} (directory contents)",
            t.s("src/"),
            t.s("dst")
        )),
        "{dry_stdout}"
    );
    assert!(
        dry_stdout.contains("route: local filesystem on fake; 1 worker (fixed)"),
        "{dry_stdout}"
    );
    // --max-delete refusal on the remote orchestrator must surface as 25.
    let out = remote_syq(
        &t,
        &rsh,
        &[
            "-a",
            "--no-bootstrap",
            "--delete",
            "--max-delete",
            "1",
            &src,
            &dst,
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(25),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(t.path("dst/extra1").exists() && t.path("dst/extra2").exists());
    // Partial failure (unreadable source file) must surface as 23.
    write(&t.path("src/bad"), b"unreadable");
    fs::set_permissions(t.path("src/bad"), fs::Permissions::from_mode(0o000)).unwrap();
    let out = remote_syq(&t, &rsh, &["-a", "--no-bootstrap", &src, &dst]);
    fs::set_permissions(t.path("src/bad"), fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        out.status.code(),
        Some(23),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn direct_remote_to_remote_forwards_compression_opt_out() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    fs::create_dir_all(t.path("remote-bin")).unwrap();
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_syq"), t.path("remote-bin/syq")).unwrap();
    write(&t.path("src"), b"payload");
    let src = format!("fake:{}", t.s("src"));
    let dst = format!("fake:{}", t.s("dst"));

    let out = remote_syq(
        &t,
        &rsh,
        &["-a", "--no-bootstrap", "--no-compress", &src, &dst],
    );
    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), b"payload");
    assert!(
        fs::read_to_string(t.path("rsh.log"))
            .unwrap()
            .contains("--no-compress"),
        "the source-side orchestrator silently reverted to default compression"
    );
}

// ----------------------------------------------------------- review round 13

#[test]
fn ignore_existing_keeps_a_file_where_a_source_directory_maps() {
    let t = Tmp::new();
    write(&t.path("src/d/inner"), b"i");
    write(&t.path("src/plain"), b"p");
    fs::create_dir_all(t.path("dst")).unwrap();
    write(&t.path("dst/d"), b"precious");
    // Dry run and real run agree; the existing file survives; the rest copies.
    let so = run_ok(&["-r", "-n", "--ignore-existing", &t.s("src/"), &t.s("dst")]);
    assert!(so.contains("1 B in 1 file needing content work"), "{so}");
    let out = syq(&["-r", "--ignore-existing", &t.s("src/"), &t.s("dst")]);
    assert!(out.status.success(), "{}", stderr_of(&out));
    assert!(
        stderr_of(&out).contains("keeping existing"),
        "{}",
        stderr_of(&out)
    );
    assert_eq!(read(&t.path("dst/d")), b"precious");
    assert_eq!(read(&t.path("dst/plain")), b"p");
    // An existing *directory* is still descended into — the flag stays useful.
    fs::create_dir_all(t.path("dst2/d")).unwrap();
    run_ok(&["-r", "--ignore-existing", &t.s("src/"), &t.s("dst2")]);
    assert_eq!(read(&t.path("dst2/d/inner")), b"i");
}

#[test]
fn files_from_empty_list_leaves_an_existing_destination_untouched() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"a");
    fs::create_dir_all(t.path("dst")).unwrap();
    fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o711)).unwrap();
    set_mtime(&t.path("dst"), 1_000);
    set_mtime(&t.path("src"), 2_000);
    write(&t.path("empty"), b"");
    run_ok(&[
        "-a",
        "--files-from",
        &t.s("empty"),
        &t.s("src"),
        &t.s("dst"),
    ]);
    let md = fs::metadata(t.path("dst")).unwrap();
    assert_eq!(md.mode() & 0o777, 0o711);
    assert_eq!(md.mtime(), 1_000, "nothing created, nothing stamped");
}

#[test]
fn files_from_unwritable_destination_root_fails_and_is_left_alone() {
    // Ordinary copies open up and restore an unwritable root; --files-from
    // deliberately doesn't (the root isn't listed), so it fails per file.
    let t = Tmp::new();
    write(&t.path("src/a"), b"a");
    fs::create_dir_all(t.path("dst")).unwrap();
    fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o500)).unwrap();
    write(&t.path("list"), b"a\n");
    let out = syq(&["-a", "--files-from", &t.s("list"), &t.s("src"), &t.s("dst")]);
    let mode = fs::metadata(t.path("dst")).unwrap().mode() & 0o777;
    fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(out.status.code(), Some(23), "{}", stderr_of(&out));
    assert_eq!(mode, 0o500, "the unlisted root keeps its mode");
    assert!(!t.path("dst/a").exists());
}

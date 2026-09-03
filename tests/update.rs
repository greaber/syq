//! End-to-end standalone updater tests using a copied executable and signed,
//! local fixtures. No test ever replaces the Cargo-built binary.

use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use flate2::{write::GzEncoder, Compression};
use semver::Version;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("syq-update-test-{}-{sequence}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self, value: &str) -> PathBuf {
        self.0.join(value)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(target_os = "linux")]
struct UpdateFixture {
    temp: TempDir,
    installed: PathBuf,
    config: PathBuf,
    public_key: String,
    original: Vec<u8>,
}

#[cfg(target_os = "linux")]
impl UpdateFixture {
    fn new(release_version: &str, executable_identity: &str) -> Self {
        let temp = TempDir::new();
        let installed = temp.path("bin/syq");
        fs::create_dir_all(installed.parent().unwrap()).unwrap();
        fs::copy(env!("CARGO_BIN_EXE_syq"), &installed).unwrap();
        fs::set_permissions(&installed, fs::Permissions::from_mode(0o755)).unwrap();
        let original = fs::read(&installed).unwrap();

        let target = if cfg!(target_arch = "x86_64") {
            "linux-x86_64"
        } else {
            "linux-aarch64"
        };
        let asset = format!("syq-{target}");
        let replacement = format!(
            "#!/bin/sh\ncase \"$1\" in\n  --version) echo 'syq {release_version}' ;;\n  --build-identity) echo '{executable_identity}' ;;\n  *) exit 2 ;;\nesac\n"
        );
        let replacement = replacement.as_bytes();
        let archive_path = temp.path(&format!("fixtures/{asset}.gz"));
        fs::create_dir_all(archive_path.parent().unwrap()).unwrap();
        let mut encoder = GzEncoder::new(File::create(&archive_path).unwrap(), Compression::best());
        encoder.write_all(replacement).unwrap();
        encoder.finish().unwrap();
        let archive = fs::read(&archive_path).unwrap();

        let manifest = serde_json::json!({
            "schema": 1,
            "repository": "https://github.com/greaber/syq",
            "version": release_version,
            "tag": format!("v{release_version}"),
            "artifacts": {
                (target): {
                    "binary": {
                        "name": asset,
                        "sha256": Sha256::digest(replacement)
                            .iter()
                            .map(|byte| format!("{byte:02x}"))
                            .collect::<String>(),
                        "size": replacement.len()
                    },
                    "archive": {
                        "name": format!("{asset}.gz"),
                        "sha256": Sha256::digest(&archive)
                            .iter()
                            .map(|byte| format!("{byte:02x}"))
                            .collect::<String>(),
                        "size": archive.len()
                    }
                }
            },
            "installer": {"name": "install.sh", "sha256": "1".repeat(64), "size": 1},
            "homebrew_formula": {"name": "syq.rb", "sha256": "2".repeat(64), "size": 1},
            "signature_scheme": "ed25519-jcs-v1"
        });
        let signing = SigningKey::from_bytes(&[31; 32]);
        let canonical = serde_json_canonicalizer::to_vec(&manifest).unwrap();
        let signature =
            base64::engine::general_purpose::STANDARD.encode(signing.sign(&canonical).to_bytes());
        let mut manifest = manifest;
        manifest["signature"] = signature.into();
        fs::write(
            temp.path("fixtures/syq-release-manifest.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        let public_key =
            base64::engine::general_purpose::STANDARD.encode(signing.verifying_key().to_bytes());

        Self {
            config: temp.path("config"),
            temp,
            installed,
            public_key,
            original,
        }
    }

    fn command_at_args(&self, executable: &Path, arguments: &[&str]) -> Output {
        Command::new(executable)
            .args(arguments)
            .env("XDG_CONFIG_HOME", &self.config)
            .env("SYQ_TEST_RELEASE_PUBLIC_KEY", &self.public_key)
            .env(
                "SYQ_TEST_LATEST_DOWNLOADS",
                "https://release.invalid/latest",
            )
            .env(
                "SYQ_TEST_RELEASE_DOWNLOADS",
                "https://release.invalid/download",
            )
            .env("SYQ_TEST_FIXTURES", self.temp.path("fixtures"))
            .output()
            .unwrap()
    }

    fn command_at(&self, executable: &Path, argument: &str) -> Output {
        self.command_at_args(executable, &[argument])
    }

    fn command(&self, argument: &str) -> Output {
        self.command_at(&self.installed, argument)
    }

    fn register(&self) {
        let output = self.command("--register-standalone-install");
        assert_success(&output);
    }

    fn receipt(&self) -> serde_json::Value {
        serde_json::from_slice(
            &fs::read(self.config.join("syq/install.json")).expect("install receipt should exist"),
        )
        .unwrap()
    }

    fn assert_original_unchanged(&self) {
        assert_eq!(fs::read(&self.installed).unwrap(), self.original);
        assert_eq!(
            self.receipt()["version"],
            env!("CARGO_PKG_VERSION"),
            "a failed update must not advance the receipt"
        );
    }
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_failure_contains(output: &Output, expected: &str) {
    assert!(!output.status.success(), "command unexpectedly succeeded");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(expected),
        "stderr did not contain {expected:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn signed_self_update_replaces_only_the_receipted_copy() {
    let fixture = UpdateFixture::new("0.2.0", "v0.2.0");
    fixture.register();

    let update = fixture.command("--self-update");
    assert_success(&update);
    assert!(String::from_utf8_lossy(&update.stdout).contains("updated syq to 0.2.0"));

    let version = Command::new(&fixture.installed)
        .arg("--version")
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&version.stdout).trim(), "syq 0.2.0");
    assert_eq!(fixture.receipt()["version"], "0.2.0");
}

#[cfg(target_os = "linux")]
#[test]
fn self_update_rejects_a_tampered_signed_manifest_without_changing_install() {
    let fixture = UpdateFixture::new("0.2.0", "v0.2.0");
    fixture.register();
    let path = fixture.temp.path("fixtures/syq-release-manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    manifest["version"] = "9.9.9".into();
    fs::write(path, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();

    let update = fixture.command("--self-update");
    assert_failure_contains(&update, "signature verification failed");
    fixture.assert_original_unchanged();
}

#[cfg(target_os = "linux")]
#[test]
fn self_update_rejects_a_tampered_archive_without_changing_install() {
    let fixture = UpdateFixture::new("0.2.0", "v0.2.0");
    fixture.register();
    let target = if cfg!(target_arch = "x86_64") {
        "linux-x86_64"
    } else {
        "linux-aarch64"
    };
    let archive = fixture.temp.path(&format!("fixtures/syq-{target}.gz"));
    File::options()
        .append(true)
        .open(archive)
        .unwrap()
        .write_all(b"tamper")
        .unwrap();

    let update = fixture.command("--self-update");
    assert_failure_contains(&update, "downloaded release archive has size");
    fixture.assert_original_unchanged();
}

#[cfg(target_os = "linux")]
#[test]
fn self_update_rejects_an_executable_with_the_wrong_build_identity() {
    let fixture = UpdateFixture::new("0.2.0", "v0.2.0+dev.wrong");
    fixture.register();

    let update = fixture.command("--self-update");
    assert_failure_contains(&update, "unexpected build identity");
    fixture.assert_original_unchanged();
}

#[cfg(target_os = "linux")]
#[test]
fn self_update_refuses_a_signed_downgrade() {
    let current = Version::parse(env!("CARGO_PKG_VERSION")).unwrap();
    let older = if current.patch > 0 {
        Version::new(current.major, current.minor, current.patch - 1)
    } else {
        assert!(
            current.minor > 0,
            "test needs a package version above 0.0.0"
        );
        Version::new(current.major, current.minor - 1, 0)
    };
    let identity = format!("v{older}");
    let fixture = UpdateFixture::new(&older.to_string(), &identity);
    fixture.register();

    let update = fixture.command("--self-update");
    assert_failure_contains(&update, "refusing to downgrade");
    fixture.assert_original_unchanged();
}

#[cfg(target_os = "linux")]
#[test]
fn receipt_is_bound_to_the_exact_installed_executable() {
    let fixture = UpdateFixture::new("0.2.0", "v0.2.0");
    fixture.register();
    let other = fixture.temp.path("other/syq");
    fs::create_dir_all(other.parent().unwrap()).unwrap();
    fs::copy(&fixture.installed, &other).unwrap();
    fs::set_permissions(&other, fs::Permissions::from_mode(0o755)).unwrap();

    let update = fixture.command_at(&other, "--self-update");
    assert_failure_contains(&update, "standalone install receipt belongs to");
    fixture.assert_original_unchanged();
    assert_eq!(fs::read(other).unwrap(), fixture.original);
}

#[cfg(target_os = "linux")]
#[test]
fn source_install_cannot_create_or_use_a_standalone_receipt_implicitly() {
    let fixture = UpdateFixture::new("0.2.0", "v0.2.0");

    let update = fixture.command("--self-update");
    assert_failure_contains(&update, "self-update is only available");
    assert!(String::from_utf8_lossy(&update.stderr).contains("`brew upgrade syq`"));
    assert!(!fixture.config.join("syq/install.json").exists());
    assert_eq!(fs::read(&fixture.installed).unwrap(), fixture.original);
}

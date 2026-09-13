//! End-to-end standalone updater tests using a copied executable and signed,
//! local fixtures. No test ever replaces the Cargo-built binary.
//!
//! The fixtures select the release artifact for the current Linux or macOS
//! host so the same update contract is exercised on every release platform.
#![cfg(any(target_os = "linux", target_os = "macos"))]

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

fn release_target() -> &'static str {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "linux-x86_64",
        ("linux", "aarch64") => "linux-aarch64",
        ("macos", "x86_64") => "macos-x86_64",
        ("macos", "aarch64") => "macos-arm64",
        other => panic!("unsupported update-test platform {other:?}"),
    }
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let parent = std::env::temp_dir();
        let parent = fs::canonicalize(&parent).unwrap_or(parent);
        let path = parent.join(format!("syq-update-test-{}-{sequence}", std::process::id()));
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

struct UpdateFixture {
    temp: TempDir,
    installed: PathBuf,
    config: PathBuf,
    public_key: String,
    original: Vec<u8>,
}

impl UpdateFixture {
    fn new(release_version: &str, executable_identity: &str) -> Self {
        let temp = TempDir::new();
        let installed = temp.path("bin/syq");
        fs::create_dir_all(installed.parent().unwrap()).unwrap();
        fs::copy(env!("CARGO_BIN_EXE_syq"), &installed).unwrap();
        fs::set_permissions(&installed, fs::Permissions::from_mode(0o755)).unwrap();
        let original = fs::read(&installed).unwrap();

        let target = release_target();
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
            &fs::read(self.installed.with_file_name(".syq-install.json"))
                .expect("install receipt should exist"),
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

fn next_release_version() -> String {
    let mut version = Version::parse(env!("CARGO_PKG_VERSION")).unwrap();
    version.patch = version.patch.checked_add(1).unwrap();
    version.to_string()
}

#[test]
fn malformed_adjacent_receipt_names_its_path_and_shadows_legacy_receipt() {
    let version = next_release_version();
    let fixture = UpdateFixture::new(&version, &format!("v{version}"));
    fixture.register();
    let adjacent = fixture.installed.with_file_name(".syq-install.json");
    let receipt = fs::read(&adjacent).unwrap();
    let legacy = fixture.config.join("syq/install.json");
    fs::create_dir_all(legacy.parent().unwrap()).unwrap();
    fs::write(&legacy, &receipt).unwrap();
    fs::write(&adjacent, b"invalid JSON").unwrap();

    let output = fixture.command("--self-update");
    assert_failure_contains(&output, adjacent.to_str().unwrap());
    assert_failure_contains(&output, "parse standalone install receipt");
    assert_eq!(fs::read(&fixture.installed).unwrap(), fixture.original);
    assert_eq!(fs::read(&legacy).unwrap(), receipt);
    assert_eq!(fs::read(&adjacent).unwrap(), b"invalid JSON");
}

#[test]
fn signed_self_update_replaces_only_the_receipted_copy() {
    let release_version = next_release_version();
    let fixture = UpdateFixture::new(&release_version, &format!("v{release_version}"));
    fixture.register();

    let update = fixture.command("--self-update");
    assert_success(&update);
    assert!(String::from_utf8_lossy(&update.stdout)
        .contains(&format!("updated syq to {release_version}")));

    let version = Command::new(&fixture.installed)
        .arg("--version")
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&version.stdout).trim(),
        format!("syq {release_version}")
    );
    assert_eq!(fixture.receipt()["version"], release_version);
}

#[test]
fn self_update_rejects_a_tampered_signed_manifest_without_changing_install() {
    let release_version = next_release_version();
    let fixture = UpdateFixture::new(&release_version, &format!("v{release_version}"));
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

#[test]
fn self_update_rejects_a_tampered_archive_without_changing_install() {
    let release_version = next_release_version();
    let fixture = UpdateFixture::new(&release_version, &format!("v{release_version}"));
    fixture.register();
    let target = release_target();
    let archive = fixture.temp.path(&format!("fixtures/syq-{target}.gz"));
    File::options()
        .append(true)
        .open(archive)
        .unwrap()
        .write_all(b"tamper")
        .unwrap();

    let update = fixture.command("--self-update");
    assert_failure_contains(&update, "response exceeds the expected");
    fixture.assert_original_unchanged();
}

#[test]
fn self_update_rejects_an_executable_with_the_wrong_build_identity() {
    let release_version = next_release_version();
    let fixture = UpdateFixture::new(&release_version, &format!("v{release_version}+dev.wrong"));
    fixture.register();

    let update = fixture.command("--self-update");
    assert_failure_contains(&update, "unexpected build identity");
    fixture.assert_original_unchanged();
}

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

#[test]
fn receipt_is_bound_to_the_exact_installed_executable() {
    let release_version = next_release_version();
    let fixture = UpdateFixture::new(&release_version, &format!("v{release_version}"));
    fixture.register();
    let other = fixture.temp.path("other/syq");
    fs::create_dir_all(other.parent().unwrap()).unwrap();
    fs::copy(&fixture.installed, &other).unwrap();
    fs::set_permissions(&other, fs::Permissions::from_mode(0o755)).unwrap();
    fs::copy(
        fixture.installed.with_file_name(".syq-install.json"),
        other.with_file_name(".syq-install.json"),
    )
    .unwrap();

    let update = fixture.command_at(&other, "--self-update");
    assert_failure_contains(&update, "standalone install receipt belongs to");
    fixture.assert_original_unchanged();
    assert_eq!(fs::read(other).unwrap(), fixture.original);
}

#[test]
fn source_install_cannot_create_or_use_a_standalone_receipt_implicitly() {
    let release_version = next_release_version();
    let fixture = UpdateFixture::new(&release_version, &format!("v{release_version}"));

    let update = fixture.command("--self-update");
    assert_failure_contains(&update, "self-update is only available");
    assert!(String::from_utf8_lossy(&update.stderr).contains("`brew upgrade syq`"));
    assert!(!fixture
        .installed
        .with_file_name(".syq-install.json")
        .exists());
    assert_eq!(fs::read(&fixture.installed).unwrap(), fixture.original);
}

#[test]
fn remote_command_registration_enables_signed_update_without_changing_helper() {
    let release_version = next_release_version();
    let fixture = UpdateFixture::new(&release_version, &format!("v{release_version}"));
    let home = fixture.temp.path("remote-home");
    fs::create_dir(&home).unwrap();
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
    let installed = home.join(".local/bin/syq");
    let install = Command::new(&fixture.installed)
        .arg("--install-remote-command")
        .env("HOME", &home)
        .env("PATH", fixture.temp.path("no-tools"))
        .env_remove("XDG_CONFIG_HOME")
        .env("SYQ_TEST_RELEASE_BUILD", "1")
        .env("SYQ_TEST_RELEASE_PUBLIC_KEY", &fixture.public_key)
        .output()
        .unwrap();
    assert_success(&install);
    let receipt = || -> serde_json::Value {
        serde_json::from_slice(&fs::read(installed.with_file_name(".syq-install.json")).unwrap())
            .unwrap()
    };
    assert_eq!(receipt()["binary"], installed.to_str().unwrap());
    assert_eq!(receipt()["provider"], "standalone");
    let update = fixture.command_at(&installed, "--self-update");
    assert_success(&update);
    assert_eq!(receipt()["version"], release_version);
    assert_eq!(fs::read(&fixture.installed).unwrap(), fixture.original);
}

#[test]
fn remote_install_is_independent_of_other_standalone_installations() {
    let release_version = next_release_version();
    let fixture = UpdateFixture::new(&release_version, &format!("v{release_version}"));
    fixture.register();
    let receipt = fs::read(fixture.installed.with_file_name(".syq-install.json")).unwrap();
    let home = fixture.temp.path("remote-home");
    fs::create_dir(&home).unwrap();
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
    let install = Command::new(&fixture.installed)
        .arg("--install-remote-command")
        .env("HOME", &home)
        .env("PATH", fixture.temp.path("no-tools"))
        .env("XDG_CONFIG_HOME", &fixture.config)
        .env("SYQ_TEST_RELEASE_BUILD", "1")
        .env("SYQ_TEST_RELEASE_PUBLIC_KEY", &fixture.public_key)
        .output()
        .unwrap();
    assert_success(&install);
    assert!(home.join(".local/bin/syq").is_file());
    assert_eq!(
        fs::read(fixture.installed.with_file_name(".syq-install.json")).unwrap(),
        receipt
    );
}

#[test]
fn remote_install_reports_receipt_failure_without_removing_the_command() {
    let release_version = next_release_version();
    let fixture = UpdateFixture::new(&release_version, &format!("v{release_version}"));
    let home = fixture.temp.path("remote-home");
    fs::create_dir(&home).unwrap();
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
    let blocked_receipt = home.join(".local/bin/.syq-install.json");
    fs::create_dir_all(&blocked_receipt).unwrap();
    for path in [home.join(".local"), home.join(".local/bin")] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let install = Command::new(&fixture.installed)
        .arg("--install-remote-command")
        .env("HOME", &home)
        .env("PATH", fixture.temp.path("no-tools"))
        .env("XDG_CONFIG_HOME", &fixture.config)
        .env("SYQ_TEST_RELEASE_BUILD", "1")
        .env("SYQ_TEST_RELEASE_PUBLIC_KEY", &fixture.public_key)
        .output()
        .unwrap();
    assert_success(&install);
    assert_eq!(
        fs::read(home.join(".local/bin/syq")).unwrap(),
        fixture.original
    );
    assert!(blocked_receipt.is_dir());
    let stderr = String::from_utf8_lossy(&install.stderr);
    assert!(stderr.contains("could not enable self-update"));
    assert!(stderr.contains("rerun the standalone installer"));
    assert!(!stderr.contains("for use on this server"));
    assert!(!stderr.contains("on your shell PATH"));
    assert_eq!(stderr.lines().filter(|line| !line.is_empty()).count(), 1);
    assert!(stderr.starts_with('\n'));
    assert!(stderr
        .lines()
        .all(|line| line.is_empty() || line.starts_with("syq-remote-install-notice:")));
}

// Produced by the published, checksum-verified v0.5.2 Linux x86-64 executable.
// Preserve the old bytes on disk; only rebind its binary path to this disposable
// installation. This must not use the current receipt writer.
#[test]
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn self_update_accepts_the_released_v052_receipt() {
    let version = next_release_version();
    let fixture = UpdateFixture::new(&version, &format!("v{version}"));
    let mut receipt: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/standalone-install-v0.5.2.json")).unwrap();
    receipt["binary"] = fixture.installed.to_str().unwrap().into();
    let legacy = fixture.config.join("syq/install.json");
    fs::create_dir_all(legacy.parent().unwrap()).unwrap();
    fs::write(&legacy, serde_json::to_vec(&receipt).unwrap()).unwrap();
    assert_success(&fixture.command("--self-update"));
    let updated: serde_json::Value = serde_json::from_slice(&fs::read(&legacy).unwrap()).unwrap();
    assert_eq!(updated["version"], version);
    assert!(!fixture
        .installed
        .with_file_name(".syq-install.json")
        .exists());
}

#[test]
fn registration_needs_no_config_and_does_not_change_bin_permissions() {
    let version = next_release_version();
    let fixture = UpdateFixture::new(&version, &format!("v{version}"));
    let bin = fixture.installed.parent().unwrap();
    fs::set_permissions(bin, fs::Permissions::from_mode(0o750)).unwrap();
    let output = Command::new(&fixture.installed)
        .arg("--register-standalone-install")
        .env_remove("HOME")
        .env_remove("XDG_CONFIG_HOME")
        .env("SYQ_TEST_RELEASE_PUBLIC_KEY", &fixture.public_key)
        .output()
        .unwrap();
    assert_success(&output);
    assert_eq!(
        fs::metadata(bin).unwrap().permissions().mode() & 0o777,
        0o750
    );
    assert_eq!(fixture.receipt()["provider"], "standalone");
}

#[test]
fn remote_install_preserves_deleted_command_until_its_receipt_is_removed() {
    let version = next_release_version();
    let fixture = UpdateFixture::new(&version, &format!("v{version}"));
    let home = fixture.temp.path("remote-home");
    fs::create_dir(&home).unwrap();
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
    let other_bin = fixture.temp.path("other-bin");
    fs::create_dir_all(other_bin.join("syq")).unwrap();
    let install = || {
        Command::new(&fixture.installed)
            .arg("--install-remote-command")
            .env("HOME", &home)
            .env("PATH", &other_bin)
            .env("SYQ_TEST_RELEASE_BUILD", "1")
            .env("SYQ_TEST_RELEASE_PUBLIC_KEY", &fixture.public_key)
            .output()
            .unwrap()
    };
    assert_success(&install());
    let binary = home.join(".local/bin/syq");
    fs::remove_file(&binary).unwrap();
    let receipt = binary.with_file_name(".syq-install.json");
    let saved_receipt = fs::read(&receipt).unwrap();
    let skipped = install();
    assert_success(&skipped);
    assert!(skipped.stderr.is_empty());
    assert!(!binary.exists());
    assert_eq!(fs::read(&receipt).unwrap(), saved_receipt);
    fs::remove_file(&receipt).unwrap();
    assert_success(&install());
    assert_eq!(fs::read(binary).unwrap(), fixture.original);
    let registered: serde_json::Value =
        serde_json::from_slice(&fs::read(receipt).unwrap()).unwrap();
    assert_eq!(registered["provider"], "standalone");
    assert!(other_bin.join("syq").is_dir());
}

#[test]
fn legacy_receipt_preserves_deleted_command_and_is_bound_to_its_path() {
    for custom_config in [false, true] {
        let version = next_release_version();
        let fixture = UpdateFixture::new(&version, &format!("v{version}"));
        let home = fixture.temp.path("remote-home");
        let binary = home.join(".local/bin/syq");
        let adjacent = binary.with_file_name(".syq-install.json");
        fs::create_dir_all(binary.parent().unwrap()).unwrap();
        let config = if custom_config {
            fixture.config.clone()
        } else {
            home.join(".config")
        };
        let legacy = config.join("syq/install.json");
        fs::create_dir_all(legacy.parent().unwrap()).unwrap();
        // Preserve the released v0.5.2 fields; only bind the old fixture to this
        // disposable installation, without invoking the current receipt writer.
        let mut receipt: serde_json::Value =
            serde_json::from_str(include_str!("fixtures/standalone-install-v0.5.2.json")).unwrap();
        receipt["binary"] = binary.to_str().unwrap().into();
        let saved = serde_json::to_vec(&receipt).unwrap();
        fs::write(&legacy, &saved).unwrap();
        let install = || {
            let mut command = Command::new(&fixture.installed);
            command
                .arg("--install-remote-command")
                .env("HOME", &home)
                .env("SYQ_TEST_RELEASE_BUILD", "1")
                .env("SYQ_TEST_RELEASE_PUBLIC_KEY", &fixture.public_key);
            if custom_config {
                command.env("XDG_CONFIG_HOME", &config);
            } else {
                command.env_remove("XDG_CONFIG_HOME");
            }
            command.output().unwrap()
        };
        let skipped = install();
        assert_success(&skipped);
        assert!(skipped.stderr.is_empty(), "{skipped:?}");
        assert!(!binary.exists());
        assert!(!adjacent.exists());
        assert_eq!(fs::read(&legacy).unwrap(), saved);

        fs::remove_file(&legacy).unwrap();
        assert_success(&install());
        assert_eq!(fs::read(&binary).unwrap(), fixture.original);
        assert!(adjacent.is_file());
        assert!(!legacy.exists());

        fs::remove_file(&binary).unwrap();
        fs::remove_file(&adjacent).unwrap();
        receipt["binary"] = fixture.installed.to_str().unwrap().into();
        let foreign = serde_json::to_vec(&receipt).unwrap();
        fs::write(&legacy, &foreign).unwrap();
        assert_success(&install());
        assert_eq!(fs::read(&binary).unwrap(), fixture.original);
        assert!(adjacent.is_file());
        assert_eq!(fs::read(&legacy).unwrap(), foreign);
    }
}

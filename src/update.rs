//! Signed standalone release updates.
//!
//! Package-manager and source installs deliberately have no install receipt,
//! so this module will never replace them. Official release builds embed the
//! Ed25519 public key supplied by the release workflow at compile time.

use crate::remote_helper::Target;
use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use flate2::read::GzDecoder;
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

const REPOSITORY: &str = "https://github.com/greaber/syq";
const RELEASE_DOWNLOADS: &str = "https://github.com/greaber/syq/releases/download";
const LATEST_DOWNLOADS: &str = "https://github.com/greaber/syq/releases/latest/download";
const MANIFEST_NAME: &str = "syq-release-manifest.json";
const SIGNATURE_NAME: &str = "syq-release-manifest.json.sig";
const RECEIPT_SCHEMA: u32 = 1;
const MANIFEST_SCHEMA: u32 = 1;
const CHECK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
const RELEASE_PUBLIC_KEY: Option<&str> = option_env!("SYQ_RELEASE_PUBLIC_KEY");

#[derive(Clone, Debug, Deserialize, Serialize)]
struct InstallReceipt {
    schema: u32,
    provider: String,
    version: String,
    target: String,
    binary: PathBuf,
    #[serde(default)]
    auto_update: bool,
}

#[derive(Clone, Debug, Deserialize)]
struct ReleaseManifest {
    schema: u32,
    repository: String,
    version: String,
    tag: String,
    helper_id: String,
    artifacts: BTreeMap<String, ReleaseArtifact>,
    installer: ReleaseFile,
    homebrew_formula: ReleaseFile,
}

#[derive(Clone, Debug, Deserialize)]
struct ReleaseArtifact {
    binary: ReleaseFile,
    archive: ReleaseFile,
}

#[derive(Clone, Debug, Deserialize)]
struct ReleaseFile {
    name: String,
    sha256: String,
    size: u64,
}

struct VerifiedRelease {
    manifest: ReleaseManifest,
    version: Version,
}

#[derive(Clone, Copy)]
enum FetchMode {
    Interactive,
    BackgroundCheck,
}

/// Install the latest release when this executable came from the standalone
/// installer. A package-manager binary cannot accidentally overwrite itself.
pub fn self_update() -> Result<()> {
    let (_, mut receipt) = managed_receipt().context(
        "self-update is only available for installs made by the standalone installer; use your package manager or reinstall with the curl installer",
    )?;
    let release = fetch_latest(FetchMode::Interactive)?;
    match release.version.cmp(&current_version()?) {
        std::cmp::Ordering::Less => bail!(
            "refusing to downgrade from {} to {}",
            env!("CARGO_PKG_VERSION"),
            release.version
        ),
        std::cmp::Ordering::Equal => {
            println!("syq {} is already the newest release", release.version);
            return Ok(());
        }
        std::cmp::Ordering::Greater => {}
    }
    install_release(&release, &mut receipt)?;
    println!("updated syq to {}", release.version);
    Ok(())
}

/// Change the opt-in automatic update setting in the standalone receipt.
pub fn set_auto_update(enabled: bool) -> Result<()> {
    let (path, mut receipt) = managed_receipt().context(
        "automatic updates are only available for installs made by the standalone installer; package-manager installs should be updated by their package manager",
    )?;
    receipt.auto_update = enabled;
    write_receipt(&path, &receipt)?;
    if enabled {
        println!("automatic signed updates enabled");
    } else {
        println!("automatic updates disabled; interactive update notices remain enabled");
    }
    Ok(())
}

/// Called by the generated installer after the verified binary has reached its
/// final path. Keeping receipt creation inside syq avoids shell JSON escaping.
pub fn register_standalone_install() -> Result<()> {
    embedded_public_key()?;
    let target = Target::local().ok_or_else(|| {
        anyhow!(
            "standalone releases do not support {} {}",
            std::env::consts::OS,
            std::env::consts::ARCH
        )
    })?;
    let binary = canonical_current_exe()?;
    let path = receipt_path()?;
    let auto_update = read_receipt(&path)
        .ok()
        .filter(|old| canonical_or_original(&old.binary) == binary)
        .is_some_and(|old| old.auto_update);
    let receipt = InstallReceipt {
        schema: RECEIPT_SCHEMA,
        provider: "standalone".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        target: target.key.into(),
        binary,
        auto_update,
    };
    write_receipt(&path, &receipt)
}

/// Check at most once per day after a successful interactive command. Errors
/// never change the command's exit status. Automatic replacement is opt-in.
pub fn after_success(quiet: bool) {
    if quiet || !std::io::stderr().is_terminal() {
        return;
    }
    let Ok((_, mut receipt)) = managed_receipt() else {
        return;
    };
    let Ok(stamp) = check_stamp_path() else {
        return;
    };
    if !check_is_due(&stamp) {
        return;
    }
    // Mark before networking so an outage does not delay every invocation.
    if touch_check_stamp(&stamp).is_err() {
        return;
    }
    let mode = if receipt.auto_update {
        FetchMode::Interactive
    } else {
        FetchMode::BackgroundCheck
    };
    let release = match fetch_latest(mode) {
        Ok(release) => release,
        Err(e) => {
            if receipt.auto_update {
                eprintln!("syq: automatic update check failed: {e:#}");
            }
            return;
        }
    };
    let Ok(current) = current_version() else {
        return;
    };
    if release.version <= current {
        return;
    }
    if receipt.auto_update {
        match install_release(&release, &mut receipt) {
            Ok(()) => eprintln!(
                "syq: installed signed update {} (used on the next command)",
                release.version
            ),
            Err(e) => eprintln!(
                "syq: automatic update to {} failed: {e:#}; run `syq --self-update` to retry",
                release.version
            ),
        }
    } else {
        eprintln!(
            "syq: update {} is available; run `syq --self-update`",
            release.version
        );
    }
}

/// Return the archive hash for this exact release after verifying its signed
/// manifest. Remote bootstrap passes this trusted value to the remote shell;
/// it never trusts a checksum downloaded beside the executable.
pub fn trusted_current_archive_hash(target: Target) -> Result<String> {
    let tag = format!("v{}", env!("CARGO_PKG_VERSION"));
    let release = fetch_verified(
        &format!("{}/{tag}", release_downloads()),
        FetchMode::Interactive,
    )?;
    if release.version != current_version()?
        || release.manifest.helper_id != crate::remote_helper::release_key()
    {
        bail!("signed release manifest does not describe this syq build");
    }
    let artifact = release
        .manifest
        .artifacts
        .get(target.key)
        .ok_or_else(|| anyhow!("release has no artifact for {}", target.key))?;
    if artifact.binary.name != target.asset {
        bail!("release artifact name does not match target {}", target.key);
    }
    Ok(artifact.archive.sha256.clone())
}

fn current_version() -> Result<Version> {
    Version::parse(env!("CARGO_PKG_VERSION")).context("parse the current syq version")
}

fn fetch_latest(mode: FetchMode) -> Result<VerifiedRelease> {
    fetch_verified(&latest_downloads(), mode)
}

fn fetch_verified(base_url: &str, mode: FetchMode) -> Result<VerifiedRelease> {
    let key = embedded_public_key()?;
    let temp_dir = config_dir()?;
    create_private_dir(&temp_dir)?;
    let manifest_temp = TempFile::new(&temp_dir, ".json")?;
    let signature_temp = TempFile::new(&temp_dir, ".sig")?;
    fetch(
        &format!("{base_url}/{MANIFEST_NAME}"),
        manifest_temp.path(),
        mode,
    )?;
    fetch(
        &format!("{base_url}/{SIGNATURE_NAME}"),
        signature_temp.path(),
        mode,
    )?;
    let manifest_bytes = fs::read(manifest_temp.path()).context("read release manifest")?;
    let signature =
        fs::read_to_string(signature_temp.path()).context("read release manifest signature")?;
    verify_manifest(&manifest_bytes, &signature, key.as_ref())?;
    let manifest: ReleaseManifest =
        serde_json::from_slice(&manifest_bytes).context("parse signed release manifest")?;
    let version = validate_manifest(&manifest)?;
    Ok(VerifiedRelease { manifest, version })
}

fn embedded_public_key() -> Result<Cow<'static, str>> {
    #[cfg(debug_assertions)]
    if let Some(key) = std::env::var_os("SYQ_TEST_RELEASE_PUBLIC_KEY").filter(|v| !v.is_empty()) {
        return Ok(Cow::Owned(key.to_string_lossy().into_owned()));
    }
    RELEASE_PUBLIC_KEY
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .map(Cow::Borrowed)
        .ok_or_else(|| {
            anyhow!(
                "this syq build has no official release verification key; update it with its package manager"
            )
        })
}

fn verify_manifest(manifest: &[u8], signature_b64: &str, public_key_b64: &str) -> Result<()> {
    let public = base64::engine::general_purpose::STANDARD
        .decode(public_key_b64.trim())
        .context("decode the embedded release public key")?;
    let public: [u8; 32] = public
        .try_into()
        .map_err(|_| anyhow!("the embedded release public key is not 32 bytes"))?;
    let key = VerifyingKey::from_bytes(&public).context("parse the release public key")?;
    let signature = base64::engine::general_purpose::STANDARD
        .decode(signature_b64.trim())
        .context("decode the release manifest signature")?;
    let signature =
        Signature::from_slice(&signature).context("parse the release manifest signature")?;
    key.verify_strict(manifest, &signature)
        .context("release manifest signature verification failed")
}

fn validate_manifest(manifest: &ReleaseManifest) -> Result<Version> {
    if manifest.schema != MANIFEST_SCHEMA {
        bail!("unsupported release manifest schema {}", manifest.schema);
    }
    if manifest.repository != REPOSITORY {
        bail!("release manifest names an unexpected repository");
    }
    let version = Version::parse(&manifest.version).context("invalid release version")?;
    if manifest.tag != format!("v{version}") {
        bail!("release tag does not match its version");
    }
    let helper_prefix = format!("{}-p", manifest.tag);
    let protocol = manifest
        .helper_id
        .strip_prefix(&helper_prefix)
        .filter(|value| !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()));
    if protocol.is_none() {
        bail!("release helper identity is malformed");
    }
    for (target, artifact) in &manifest.artifacts {
        validate_release_file(target, &artifact.binary)?;
        validate_release_file(target, &artifact.archive)?;
        if artifact.archive.name != format!("{}.gz", artifact.binary.name) {
            bail!("archive name does not match binary name for {target}");
        }
    }
    validate_release_file("installer", &manifest.installer)?;
    validate_release_file("Homebrew formula", &manifest.homebrew_formula)?;
    if manifest.installer.name != "install.sh" || manifest.homebrew_formula.name != "syq.rb" {
        bail!("release distribution metadata has unexpected file names");
    }
    Ok(version)
}

fn validate_release_file(target: &str, file: &ReleaseFile) -> Result<()> {
    if file.name.is_empty()
        || file.name == "."
        || file.name == ".."
        || file.name.contains('/')
        || file.name.contains('\\')
    {
        bail!("release has an unsafe file name for {target}");
    }
    if file.size == 0 {
        bail!("release has an empty file for {target}");
    }
    if file.sha256.len() != 64
        || !file
            .sha256
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        bail!("release has an invalid SHA-256 for {target}");
    }
    Ok(())
}

fn install_release(release: &VerifiedRelease, receipt: &mut InstallReceipt) -> Result<()> {
    let target = Target::local().ok_or_else(|| {
        anyhow!(
            "standalone releases do not support {} {}",
            std::env::consts::OS,
            std::env::consts::ARCH
        )
    })?;
    if receipt.target != target.key {
        bail!(
            "standalone install receipt is for {}, but this host is {}",
            receipt.target,
            target.key
        );
    }
    let artifact = release
        .manifest
        .artifacts
        .get(target.key)
        .ok_or_else(|| anyhow!("release has no artifact for {}", target.key))?;
    if artifact.binary.name != target.asset {
        bail!("release artifact name does not match target {}", target.key);
    }

    let executable = canonical_current_exe()?;
    let parent = executable
        .parent()
        .ok_or_else(|| anyhow!("the syq executable has no parent directory"))?;
    let archive = TempFile::new(parent, ".gz")?;
    let binary = TempFile::new(parent, ".bin")?;
    let url = format!(
        "{}/{}/{}",
        release_downloads(),
        release.manifest.tag,
        artifact.archive.name
    );
    fetch(&url, archive.path(), FetchMode::Interactive)?;
    verify_file(archive.path(), &artifact.archive)?;

    let input = File::open(archive.path()).context("open downloaded release archive")?;
    let mut decoder = GzDecoder::new(BufReader::new(input));
    let output = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(binary.path())
        .context("open temporary update executable")?;
    let mut output = BufWriter::new(output);
    std::io::copy(&mut decoder, &mut output).context("decompress the syq update")?;
    output.flush().context("flush the syq update")?;
    output.get_ref().sync_all().context("sync the syq update")?;
    drop(output);
    set_executable(binary.path())?;
    verify_executable(binary.path(), release)?;

    fs::rename(binary.path(), &executable).with_context(|| {
        format!(
            "replace {} (is its directory writable?)",
            executable.display()
        )
    })?;
    sync_parent(parent)?;
    receipt.version = release.version.to_string();
    write_receipt(&receipt_path()?, receipt)?;
    Ok(())
}

fn release_downloads() -> Cow<'static, str> {
    #[cfg(debug_assertions)]
    if let Some(url) = std::env::var_os("SYQ_TEST_RELEASE_DOWNLOADS").filter(|v| !v.is_empty()) {
        return Cow::Owned(url.to_string_lossy().into_owned());
    }
    Cow::Borrowed(RELEASE_DOWNLOADS)
}

fn latest_downloads() -> Cow<'static, str> {
    #[cfg(debug_assertions)]
    if let Some(url) = std::env::var_os("SYQ_TEST_LATEST_DOWNLOADS").filter(|v| !v.is_empty()) {
        return Cow::Owned(url.to_string_lossy().into_owned());
    }
    Cow::Borrowed(LATEST_DOWNLOADS)
}

fn verify_file(path: &Path, expected: &ReleaseFile) -> Result<()> {
    let metadata = fs::metadata(path).context("stat downloaded release archive")?;
    if metadata.len() != expected.size {
        bail!(
            "downloaded release archive has size {}, expected {}",
            metadata.len(),
            expected.size
        );
    }
    let mut input = BufReader::new(File::open(path).context("open release archive for hashing")?);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 128 * 1024];
    loop {
        let count = input.read(&mut buffer).context("hash release archive")?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    let actual: String = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if actual != expected.sha256 {
        bail!("downloaded release archive failed SHA-256 verification");
    }
    Ok(())
}

fn verify_executable(path: &Path, release: &VerifiedRelease) -> Result<()> {
    let version = Command::new(path)
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .context("run the downloaded syq update")?;
    if !version.status.success()
        || String::from_utf8_lossy(&version.stdout).trim() != format!("syq {}", release.version)
    {
        bail!("downloaded executable reports an unexpected version");
    }
    let identity = Command::new(path)
        .arg("--remote-helper-id")
        .stdin(Stdio::null())
        .output()
        .context("read the downloaded syq helper identity")?;
    if !identity.status.success()
        || String::from_utf8_lossy(&identity.stdout).trim() != release.manifest.helper_id
    {
        bail!("downloaded executable reports an unexpected helper identity");
    }
    Ok(())
}

fn fetch(url: &str, destination: &Path, mode: FetchMode) -> Result<()> {
    let mut curl = Command::new("curl");
    curl.args([
        "--fail",
        "--silent",
        "--show-error",
        "--location",
        "--proto",
        "=https",
        "--proto-redir",
        "=https",
        "--connect-timeout",
    ]);
    match mode {
        FetchMode::Interactive => {
            curl.args(["10", "--retry", "2"]);
        }
        FetchMode::BackgroundCheck => {
            curl.args(["2", "--max-time", "5"]);
        }
    }
    curl.arg("--output").arg(destination).arg(url);
    match curl.stdin(Stdio::null()).status() {
        Ok(status) if status.success() => return Ok(()),
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).context("run curl"),
    }

    let mut wget = Command::new("wget");
    wget.args(["--quiet", "--https-only"]);
    match mode {
        FetchMode::Interactive => {
            wget.args(["--timeout=10", "--tries=3"]);
        }
        FetchMode::BackgroundCheck => {
            wget.args(["--timeout=5", "--tries=1"]);
        }
    }
    wget.arg("-O").arg(destination).arg(url);
    match wget.stdin(Stdio::null()).status() {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => bail!("download {url} failed ({status})"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            bail!("downloading updates requires curl or wget")
        }
        Err(e) => Err(e).context("run wget"),
    }
}

fn managed_receipt() -> Result<(PathBuf, InstallReceipt)> {
    let path = receipt_path()?;
    let receipt = read_receipt(&path)?;
    if receipt.schema != RECEIPT_SCHEMA || receipt.provider != "standalone" {
        bail!("unrecognized standalone install receipt");
    }
    let current = canonical_current_exe()?;
    if canonical_or_original(&receipt.binary) != current {
        bail!(
            "standalone install receipt belongs to {}, not {}",
            receipt.binary.display(),
            current.display()
        );
    }
    Ok((path, receipt))
}

fn read_receipt(path: &Path) -> Result<InstallReceipt> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).context("parse standalone install receipt")
}

fn write_receipt(path: &Path, receipt: &InstallReceipt) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("install receipt has no parent directory"))?;
    create_private_dir(parent)?;
    let temporary = TempFile::new(parent, ".receipt")?;
    let file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(temporary.path())
        .context("open temporary install receipt")?;
    let mut file = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut file, receipt).context("serialize install receipt")?;
    file.write_all(b"\n").context("write install receipt")?;
    file.flush().context("flush install receipt")?;
    file.get_ref().sync_all().context("sync install receipt")?;
    set_private_file(temporary.path())?;
    fs::rename(temporary.path(), path).context("replace install receipt")?;
    sync_parent(parent)
}

fn receipt_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("install.json"))
}

fn check_stamp_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("last-update-check"))
}

fn config_dir() -> Result<PathBuf> {
    if let Some(base) = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(base).join("syq"));
    }
    let home = std::env::var_os("HOME")
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            anyhow!("HOME is not set, so the standalone install receipt cannot be located")
        })?;
    Ok(PathBuf::from(home).join(".config/syq"))
}

fn canonical_current_exe() -> Result<PathBuf> {
    let path = std::env::current_exe().context("locate the current syq executable")?;
    fs::canonicalize(&path)
        .with_context(|| format!("resolve the current executable {}", path.display()))
}

fn canonical_or_original(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn check_is_due(path: &Path) -> bool {
    fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .and_then(|modified| modified.elapsed().map_err(std::io::Error::other))
        .map_or(true, |elapsed| elapsed >= CHECK_INTERVAL)
}

fn touch_check_stamp(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("update check stamp has no parent directory"))?;
    create_private_dir(parent)?;
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .context("write update check stamp")?;
    set_private_file(path)
}

fn create_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("create {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("set permissions on {}", path.display()))?;
    }
    Ok(())
}

fn set_private_file(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("set permissions on {}", path.display()))?;
    }
    Ok(())
}

fn set_executable(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))
            .with_context(|| format!("make {} executable", path.display()))?;
    }
    Ok(())
}

fn sync_parent(parent: &Path) -> Result<()> {
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("sync directory {}", parent.display()))
}

struct TempFile {
    path: PathBuf,
}

impl TempFile {
    fn new(parent: &Path, suffix: &str) -> Result<Self> {
        for _ in 0..16 {
            let mut random = [0u8; 12];
            getrandom::fill(&mut random)
                .map_err(|e| anyhow!("generate a temporary file name: {e}"))?;
            let token: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
            let path = parent.join(format!(".syq-{}-{token}{suffix}", std::process::id()));
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(_) => {
                    set_private_file(&path)?;
                    return Ok(Self { path });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => {
                    return Err(e)
                        .with_context(|| format!("create temporary file in {}", parent.display()))
                }
            }
        }
        bail!(
            "could not create a unique temporary file in {}",
            parent.display()
        )
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn manifest() -> ReleaseManifest {
        ReleaseManifest {
            schema: 1,
            repository: REPOSITORY.into(),
            version: "1.2.3".into(),
            tag: "v1.2.3".into(),
            helper_id: "v1.2.3-p4".into(),
            artifacts: BTreeMap::from([(
                "linux-x86_64".into(),
                ReleaseArtifact {
                    binary: ReleaseFile {
                        name: "syq-linux-x86_64".into(),
                        sha256: "a".repeat(64),
                        size: 10,
                    },
                    archive: ReleaseFile {
                        name: "syq-linux-x86_64.gz".into(),
                        sha256: "b".repeat(64),
                        size: 8,
                    },
                },
            )]),
            installer: ReleaseFile {
                name: "install.sh".into(),
                sha256: "c".repeat(64),
                size: 12,
            },
            homebrew_formula: ReleaseFile {
                name: "syq.rb".into(),
                sha256: "d".repeat(64),
                size: 13,
            },
        }
    }

    #[test]
    fn verifies_a_signed_manifest_and_rejects_tampering() {
        let signing = SigningKey::from_bytes(&[7; 32]);
        let bytes = br#"{"schema":1}"#;
        let signature = signing.sign(bytes);
        let signature = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());
        let public =
            base64::engine::general_purpose::STANDARD.encode(signing.verifying_key().to_bytes());
        verify_manifest(bytes, &signature, &public).unwrap();
        assert!(verify_manifest(br#"{"schema":2}"#, &signature, &public).is_err());
    }

    #[test]
    fn validates_release_identity_and_safe_file_names() {
        let mut value = manifest();
        assert_eq!(validate_manifest(&value).unwrap(), Version::new(1, 2, 3));
        value
            .artifacts
            .get_mut("linux-x86_64")
            .unwrap()
            .archive
            .name = "../syq.gz".into();
        assert!(validate_manifest(&value).is_err());
    }

    #[test]
    fn rejects_a_tag_or_helper_id_from_another_release() {
        let mut value = manifest();
        value.tag = "v1.2.4".into();
        assert!(validate_manifest(&value).is_err());
        value.tag = "v1.2.3".into();
        value.helper_id = "v1.2.2-p4".into();
        assert!(validate_manifest(&value).is_err());
    }
}

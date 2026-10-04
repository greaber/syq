//! Provider-selected connection metadata, independent of approved SSH sockets.
use super::{persistent, SessionRequest, Tty};
use crate::auth_from::Provider;
use crate::cli::NativeEndpoint;
use crate::destination::ssh_auth::{self, ResolvedPolicy};
use crate::persistence::Domain;
use crate::process::CommandExt as _;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const DIRECTORY: &str = "resolution-v1";
const INTERNAL: &str = "--refresh-ssh-resolution";
const FRESH: u64 = 30;
const MAX_FILE: u64 = 256 * 1024;
const MAX_STARTUP: usize = 16 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Selection {
    pub(super) provider: String,
    pub(super) policy: ResolvedPolicy,
}
pub(super) struct Plan {
    pub(super) selected: Selection,
    pub(super) generation: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    version: u16,
    authorizer: Provider,
    requested: NativeEndpoint,
    selected: Selection,
    checked: u64,
    attempted: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Refresh {
    authorizer: Provider,
    requested: NativeEndpoint,
    provider: String,
    generation: String,
    scope: Option<PathBuf>,
    scope_identity: Option<(u64, u64)>,
}

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn key(authorizer: &Provider, requested: &NativeEndpoint, provider: &str) -> Result<String> {
    Ok(
        blake3::hash(&serde_json::to_vec(&(authorizer, requested, provider))?)
            .to_hex()
            .to_string(),
    )
}
fn path(
    domain: &Domain,
    authorizer: &Provider,
    requested: &NativeEndpoint,
    provider: &str,
) -> Result<PathBuf> {
    Ok(domain
        .approved_index_path()
        .join(DIRECTORY)
        .join(format!("{}.json", key(authorizer, requested, provider)?)))
}
fn private_file(path: &Path, write: bool, limit: u64) -> Result<Option<File>> {
    let file = match OpenOptions::new()
        .read(true)
        .write(write)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0
            && metadata.len() <= limit,
        "SSH resolution metadata must be a bounded owner-only file"
    );
    Ok(Some(file))
}
fn existing_directory(domain: &Domain) -> Result<Option<PathBuf>> {
    if persistent::existing_directory(domain)?.is_none() {
        return Ok(None);
    }
    let path = domain.approved_index_path().join(DIRECTORY);
    let metadata = match path.symlink_metadata() {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(
        metadata.is_dir()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0,
        "SSH resolution cache must be an owner-only directory"
    );
    Ok(Some(path))
}
fn directory(domain: &Domain) -> Result<PathBuf> {
    let path = persistent::directory(domain)?.join(DIRECTORY);
    match fs::DirBuilder::new().mode(0o700).create(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    existing_directory(domain)?.context("SSH resolution directory disappeared")
}
fn read_at(
    path: &Path,
    authorizer: &Provider,
    requested: &NativeEndpoint,
    provider: &str,
) -> Result<Option<Entry>> {
    let Some(file) = private_file(path, false, MAX_FILE)? else {
        return Ok(None);
    };
    let entry: Entry =
        serde_json::from_reader(file.take(MAX_FILE + 1)).context("read SSH resolution metadata")?;
    anyhow::ensure!(
        entry.version == persistent::provider_state_version(authorizer)
            && entry.authorizer == *authorizer
            && entry.requested == *requested
            && entry.selected.provider == provider,
        "SSH resolution metadata does not match the selected provider and endpoint"
    );
    entry.authorizer.validate()?;
    entry.selected.policy.validate()?;
    Ok(Some(entry))
}
fn store_at(path: &Path, entry: &Entry) -> Result<()> {
    let bytes = serde_json::to_vec(entry)?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_FILE,
        "SSH resolution metadata is too large"
    );
    // Never recreate a cache directory after scope shutdown removed it.
    let mut temporary = tempfile::NamedTempFile::new_in(path.parent().unwrap())?;
    temporary.write_all(&bytes)?;
    temporary.persist(path)?;
    Ok(())
}

/// Read-only selection for completion/export: no provider exchange or refresh.
pub(super) fn cached(domain: &Domain, request: &SessionRequest) -> Result<Option<Selection>> {
    // Cache damage is an optional-state miss. Completion must neither create
    // files nor contact the provider, and stays quiet on these misses.
    Ok((|| -> Result<Option<Selection>> {
        if existing_directory(domain)?.is_none() {
            return Ok(None);
        }
        let Some(provider) = ssh_auth::local_binding(domain, &request.provider)? else {
            return Ok(None);
        };
        Ok(read_at(
            &path(domain, &request.provider, &request.destination, &provider)?,
            &request.provider,
            &request.destination,
            &provider,
        )?
        .map(|entry| entry.selected))
    })()
    .unwrap_or(None))
}

/// Freeze one plan before any master lookup. Stale metadata remains usable;
/// only a later invocation can observe a completed background refresh.
pub(super) fn select(domain: &Domain, request: &SessionRequest) -> Result<Plan> {
    let generation = persistent::ensure_generation(domain)?;
    let entry = (|| -> Result<Option<Entry>> {
        let Some(binding) = ssh_auth::local_binding(domain, &request.provider)? else { return Ok(None); };
        if existing_directory(domain)?.is_none() { return Ok(None); }
        read_at(&path(domain, &request.provider, &request.destination, &binding)?,
            &request.provider, &request.destination, &binding)
    })().unwrap_or_else(|error| {
        crate::output::diagnostic!("syq: warning: cannot read SSH resolution cache ({error:#}); resolving the selected provider again");
        None
    });
    if let Some(entry) = entry {
        let selected = entry.selected.clone();
        if now()?
            .checked_sub(entry.attempted)
            .is_none_or(|age| age >= FRESH)
        {
            let cache_path = path(
                domain,
                &request.provider,
                &request.destination,
                &selected.provider,
            )?;
            if let Err(error) = refresh(domain, &cache_path, entry, &generation) {
                crate::output::diagnostic!("syq: warning: cannot refresh SSH resolution ({error:#}); using the selected cached endpoint");
            }
        }
        return Ok(Plan {
            selected,
            generation,
        });
    }
    let resolved = ssh_auth::resolve(domain, request)?;
    anyhow::ensure!(
        ssh_auth::local_binding(domain, &request.provider)?.as_deref()
            == Some(resolved.binding.as_str()),
        "SSH provider connection changed during resolution; retry the command"
    );
    let selected = Selection {
        provider: resolved.binding,
        policy: resolved.policy,
    };
    anyhow::ensure!(
        persistent::generation_open(domain, &generation)?,
        "SSH resolution was cancelled while inspecting the provider"
    );
    let saved = (|| -> Result<()> {
        directory(domain)?;
        let cache_path = path(
            domain,
            &request.provider,
            &request.destination,
            &selected.provider,
        )?;
        let Some(_lock) = try_lock(&cache_path)? else {
            return Ok(());
        };
        anyhow::ensure!(
            persistent::generation_open(domain, &generation)?,
            "SSH resolution was cancelled before saving"
        );
        let timestamp = now()?;
        store_at(
            &cache_path,
            &Entry {
                version: persistent::provider_state_version(&request.provider),
                authorizer: request.provider.clone(),
                requested: request.destination.clone(),
                selected: selected.clone(),
                checked: timestamp,
                attempted: timestamp,
            },
        )
    })();
    if let Err(error) = saved {
        crate::output::diagnostic!("syq: warning: cannot save SSH resolution cache ({error:#}); continuing with the resolved endpoint");
    }
    Ok(Plan {
        selected,
        generation,
    })
}

/// A failed new login must not force repeated retries of the same stale plan.
/// Preserve a refresh which already selected a different policy.
pub(super) fn invalidate(
    domain: &Domain,
    request: &SessionRequest,
    selected: &Selection,
) -> Result<()> {
    let path = path(
        domain,
        &request.provider,
        &request.destination,
        &selected.provider,
    )?;
    if read_at(
        &path,
        &request.provider,
        &request.destination,
        &selected.provider,
    )?
    .is_some_and(|entry| entry.selected == *selected)
    {
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn try_lock(cache_path: &Path) -> Result<Option<File>> {
    let lock_path = cache_path.with_extension("lock");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&lock_path)?;
    let metadata = lock.metadata()?;
    anyhow::ensure!(
        metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0
            && metadata.len() == 0,
        "SSH resolution refresh lock must be an owner-only empty file"
    );
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::WouldBlock {
            return Ok(None);
        }
        return Err(error.into());
    }
    Ok(Some(lock))
}

fn refresh(domain: &Domain, cache_path: &Path, mut entry: Entry, generation: &str) -> Result<()> {
    anyhow::ensure!(
        persistent::generation_open(domain, generation)?,
        "SSH resolution refresh was cancelled"
    );
    let Some(lock) = try_lock(cache_path)? else {
        return Ok(());
    };
    anyhow::ensure!(
        persistent::generation_open(domain, generation)?,
        "SSH resolution refresh was cancelled"
    );
    // Another command may have refreshed between our initial read and lock.
    if let Some(current) = read_at(
        cache_path,
        &entry.authorizer,
        &entry.requested,
        &entry.selected.provider,
    )? {
        if now()?
            .checked_sub(current.attempted)
            .is_some_and(|age| age < FRESH)
        {
            return Ok(());
        }
        entry = current;
    }
    let startup = Refresh {
        authorizer: entry.authorizer.clone(),
        requested: entry.requested.clone(),
        provider: entry.selected.provider.clone(),
        generation: generation.to_owned(),
        scope: domain.explicit_path().map(Path::to_path_buf),
        scope_identity: if domain.is_default() {
            None
        } else {
            Some(domain.identity()?)
        },
    };
    let encoded = serde_json::to_string(&startup)?;
    anyhow::ensure!(
        encoded.len() <= MAX_STARTUP,
        "SSH resolution refresh startup is too large"
    );
    entry.attempted = now()?;
    store_at(cache_path, &entry)?;
    let mut command = Command::new(std::env::current_exe()?);
    use std::os::unix::process::CommandExt as _;
    command
        .args([INTERNAL, &encoded])
        .process_group(0)
        .stdin(Stdio::from(lock))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    persistent::protect_keeper_inheritance(&mut command)?;
    let mut child = command.spawn_guarded()?;
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}
fn refresh_open(domain: &Domain, startup: &Refresh) -> bool {
    startup
        .scope_identity
        .is_none_or(|identity| domain.is_current(identity))
        && persistent::generation_open(domain, &startup.generation).unwrap_or(false)
}
fn run_refresh(startup: Refresh) -> Result<()> {
    let domain = Domain::select(startup.scope.as_deref())?;
    anyhow::ensure!(
        domain.is_default() == startup.scope_identity.is_none(),
        "SSH resolution refresh is missing its scope identity"
    );
    let request = SessionRequest {
        provider: startup.authorizer.clone(),
        destination: startup.requested.clone(),
        tty: Tty::Disabled,
        command: Vec::new(),
    };
    super::validate_endpoint(&request.destination)?;
    anyhow::ensure!(
        refresh_open(&domain, &startup),
        "SSH resolution refresh was cancelled"
    );
    anyhow::ensure!(
        ssh_auth::local_binding(&domain, &request.provider)?.as_deref()
            == Some(startup.provider.as_str()),
        "SSH provider connection changed before refresh"
    );
    // The parent acquired this lock before spawning; fd 0 keeps it held until
    // this bounded process exits, including when its resolver thread is busy.
    let lock_path = path(
        &domain,
        &startup.authorizer,
        &startup.requested,
        &startup.provider,
    )?
    .with_extension("lock");
    let lock =
        private_file(&lock_path, true, 0)?.context("SSH resolution refresh lock disappeared")?;
    let inherited = File::from(std::io::stdin().as_fd().try_clone_to_owned()?);
    let expected = lock.metadata()?;
    let actual = inherited.metadata()?;
    anyhow::ensure!(
        expected.dev() == actual.dev() && expected.ino() == actual.ino(),
        "SSH resolution refresh did not inherit its lock"
    );
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let resolve_domain = domain.clone();
    std::thread::spawn(move || {
        let _ = sender.send(ssh_auth::resolve(&resolve_domain, &request));
    });
    let Some(resolved) = await_resolution(
        &domain,
        &startup,
        &receiver,
        Instant::now() + Duration::from_secs(30),
    )?
    else {
        return Ok(());
    };
    if !refresh_open(&domain, &startup)
        || ssh_auth::local_binding(&domain, &startup.authorizer)?.as_deref()
            != Some(resolved.binding.as_str())
    {
        return Ok(());
    }
    let timestamp = now()?;
    store_at(
        &path(
            &domain,
            &startup.authorizer,
            &startup.requested,
            &resolved.binding,
        )?,
        &Entry {
            version: persistent::provider_state_version(&startup.authorizer),
            authorizer: startup.authorizer,
            requested: startup.requested,
            selected: Selection {
                provider: resolved.binding,
                policy: resolved.policy,
            },
            checked: timestamp,
            attempted: timestamp,
        },
    )
}

fn await_resolution(
    domain: &Domain,
    startup: &Refresh,
    receiver: &std::sync::mpsc::Receiver<Result<ssh_auth::Resolved>>,
    deadline: Instant,
) -> Result<Option<ssh_auth::Resolved>> {
    loop {
        if !refresh_open(domain, startup) || Instant::now() >= deadline {
            return Ok(None);
        }
        let timeout =
            Duration::from_millis(100).min(deadline.saturating_duration_since(Instant::now()));
        match receiver.recv_timeout(timeout) {
            Ok(result) => return result.map(Some),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return Ok(None),
        }
    }
}

pub(super) fn dispatch(argv: &[OsString]) -> Option<Result<i32>> {
    if argv.get(1).is_none_or(|arg| arg != INTERNAL) {
        return None;
    }
    Some((|| {
        anyhow::ensure!(argv.len() == 3, "invalid SSH resolution refresh startup");
        let encoded = argv[2]
            .to_str()
            .context("SSH resolution refresh startup is not UTF-8")?;
        anyhow::ensure!(
            encoded.len() <= MAX_STARTUP,
            "SSH resolution refresh startup is too large"
        );
        run_refresh(serde_json::from_str(encoded)?)?;
        Ok(0)
    })())
}

fn state_paths(domain: &Domain, locks_only: bool) -> Result<Vec<PathBuf>> {
    let Some(directory) = existing_directory(domain)? else {
        return Ok(Vec::new());
    };
    let mut paths = Vec::new();
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if locks_only && path.extension().is_none_or(|ext| ext != "lock") {
            continue;
        }
        anyhow::ensure!(
            path.extension()
                .is_some_and(|ext| ext == "json" || ext == "lock")
                && path
                    .file_stem()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.len() == 64
                        && name.bytes().all(|byte| byte.is_ascii_hexdigit())),
            "unexpected SSH resolution state file {}",
            path.display()
        );
        paths.push(path);
    }
    Ok(paths)
}
/// Generation cancellation precedes this wait. Refresh helpers exit even if
/// the provider is unavailable; no metadata writer can recreate a closed scope.
pub(super) fn wait(domain: &Domain) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut report = Instant::now();
    loop {
        let mut running = 0;
        for path in state_paths(domain, true)? {
            if path.extension().is_none_or(|ext| ext != "lock") {
                continue;
            }
            let Some(lock) = private_file(&path, true, 0)? else {
                continue;
            };
            if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::WouldBlock {
                    return Err(error.into());
                }
                running += 1;
            }
        }
        if running == 0 {
            return Ok(());
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "SSH resolution refresh did not stop within 10 seconds"
        );
        if report.elapsed() >= Duration::from_secs(1) {
            crate::output::diagnostic!("syq: waiting for SSH resolution refresh to stop");
            report = Instant::now();
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
pub(super) fn cleanup(domain: &Domain) -> Result<()> {
    wait(domain)?;
    for path in state_paths(domain, false)? {
        private_file(&path, false, MAX_FILE)?.context("SSH resolution state disappeared")?;
        fs::remove_file(path)?;
    }
    if let Some(directory) = existing_directory(domain)? {
        fs::remove_dir(directory)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn fixture() -> (tempfile::TempDir, Domain, Entry) {
        let root = tempfile::tempdir_in(fs::canonicalize("/tmp").unwrap()).unwrap();
        let scope = root.path().join("scope");
        crate::persistence::initialize_scope(&scope).unwrap();
        let domain = Domain::select(Some(&scope)).unwrap();
        persistent::ensure_generation(&domain).unwrap();
        directory(&domain).unwrap();
        let key = ssh_key::PrivateKey::new(
            ssh_key::private::Ed25519Keypair::from_seed(&[9; 32]).into(),
            "",
        )
        .unwrap();
        let policy = ResolvedPolicy::new(
            NativeEndpoint {
                user: Some("user".into()),
                host: "resolved.invalid".into(),
                port: Some(22),
            },
            &format!(
                "syq-approved-peer {}\n",
                key.public_key().to_openssh().unwrap()
            ),
            "ssh-ed25519",
        )
        .unwrap();
        let entry = Entry {
            version: 1,
            authorizer: Provider::Return("laptop".into()),
            requested: NativeEndpoint {
                user: None,
                host: "alias".into(),
                port: None,
            },
            selected: Selection {
                provider: "a".repeat(64),
                policy,
            },
            checked: 1,
            attempted: 1,
        };
        (root, domain, entry)
    }
    fn entry_path(domain: &Domain, entry: &Entry) -> PathBuf {
        path(
            domain,
            &entry.authorizer,
            &entry.requested,
            &entry.selected.provider,
        )
        .unwrap()
    }
    fn startup(domain: &Domain, entry: &Entry) -> Refresh {
        Refresh {
            authorizer: entry.authorizer.clone(),
            requested: entry.requested.clone(),
            provider: entry.selected.provider.clone(),
            generation: persistent::ensure_generation(domain).unwrap(),
            scope: domain.explicit_path().map(Path::to_owned),
            scope_identity: Some(domain.identity().unwrap()),
        }
    }

    #[test]
    fn metadata_survives_master_absence_but_is_bound_to_provider_and_endpoint() {
        let (_root, domain, entry) = fixture();
        let path = entry_path(&domain, &entry);
        store_at(&path, &entry).unwrap();
        let frozen = read_at(
            &path,
            &entry.authorizer,
            &entry.requested,
            &entry.selected.provider,
        )
        .unwrap()
        .unwrap();
        assert_eq!(frozen.selected, entry.selected);
        assert!(read_at(
            &path,
            &Provider::Return("other".into()),
            &entry.requested,
            &entry.selected.provider
        )
        .is_err());
        assert!(read_at(&path, &entry.authorizer, &entry.requested, &"b".repeat(64)).is_err());
        let mut other = entry.requested.clone();
        other.port = Some(2222);
        assert!(read_at(&path, &entry.authorizer, &other, &entry.selected.provider).is_err());
        // A completed refresh changes only subsequent reads, not an invocation
        // which already froze its plan. No master socket exists in this fixture.
        let mut changed = entry.clone();
        changed.selected.policy.endpoint.host = "changed.invalid".into();
        store_at(&path, &changed).unwrap();
        assert_eq!(frozen.selected, entry.selected);
        assert_eq!(
            read_at(
                &path,
                &entry.authorizer,
                &entry.requested,
                &entry.selected.provider
            )
            .unwrap()
            .unwrap()
            .selected,
            changed.selected
        );
    }

    #[test]
    fn native_provider_metadata_has_distinct_keys_and_version() {
        let (_root, domain, mut entry) = fixture();
        let old_path = entry_path(&domain, &entry);
        store_at(&old_path, &entry).unwrap();
        // Keep the existing Return encoding and cache key, including the
        // original bare authorizer string used before typed providers.
        assert_eq!(
            key(
                &entry.authorizer,
                &entry.requested,
                &entry.selected.provider
            )
            .unwrap(),
            blake3::hash(
                &serde_json::to_vec(&("laptop", &entry.requested, &entry.selected.provider))
                    .unwrap()
            )
            .to_hex()
            .to_string()
        );
        let old_json = serde_json::to_value(&entry).unwrap();
        assert_eq!(old_json["authorizer"], "laptop");
        entry.authorizer = Provider::parse("laptop").unwrap();
        let new_path = entry_path(&domain, &entry);
        assert_ne!(new_path, old_path);
        entry.version = persistent::provider_state_version(&entry.authorizer);
        assert_eq!(entry.version, 2);
        store_at(&new_path, &entry).unwrap();
        assert_eq!(
            read_at(
                &new_path,
                &entry.authorizer,
                &entry.requested,
                &entry.selected.provider
            )
            .unwrap()
            .unwrap()
            .authorizer,
            entry.authorizer
        );
        assert!(read_at(
            &new_path,
            &Provider::Return("laptop".into()),
            &entry.requested,
            &entry.selected.provider
        )
        .is_err());
        entry.version = 1;
        store_at(&new_path, &entry).unwrap();
        assert!(read_at(
            &new_path,
            &entry.authorizer,
            &entry.requested,
            &entry.selected.provider
        )
        .is_err());
        assert!(old_path.exists());
    }

    #[test]
    fn metadata_rejects_unknown_versions_symlinks_and_public_files() {
        let (root, domain, mut entry) = fixture();
        let path = entry_path(&domain, &entry);
        entry.version = 2;
        store_at(&path, &entry).unwrap();
        assert!(read_at(
            &path,
            &entry.authorizer,
            &entry.requested,
            &entry.selected.provider
        )
        .is_err());
        entry.version = 1;
        store_at(&path, &entry).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_at(
            &path,
            &entry.authorizer,
            &entry.requested,
            &entry.selected.provider
        )
        .is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let saved = root.path().join("saved");
        fs::rename(&path, &saved).unwrap();
        std::os::unix::fs::symlink(saved, &path).unwrap();
        assert!(read_at(
            &path,
            &entry.authorizer,
            &entry.requested,
            &entry.selected.provider
        )
        .is_err());
    }

    #[test]
    fn failed_login_invalidation_preserves_a_newer_selected_policy() {
        let (_root, domain, entry) = fixture();
        let path = entry_path(&domain, &entry);
        let request = SessionRequest {
            provider: entry.authorizer.clone(),
            destination: entry.requested.clone(),
            tty: Tty::Disabled,
            command: Vec::new(),
        };
        store_at(&path, &entry).unwrap();
        invalidate(&domain, &request, &entry.selected).unwrap();
        assert!(!path.exists());
        let mut changed = entry.clone();
        changed.selected.policy.endpoint.host = "changed.invalid".into();
        store_at(&path, &changed).unwrap();
        invalidate(&domain, &request, &entry.selected).unwrap();
        assert_eq!(
            read_at(
                &path,
                &entry.authorizer,
                &entry.requested,
                &entry.selected.provider
            )
            .unwrap()
            .unwrap()
            .selected,
            changed.selected
        );
    }

    #[test]
    fn refresh_wait_is_bounded_and_cancelled_while_provider_is_busy() {
        let (_root, domain, entry) = fixture();
        let startup = startup(&domain, &entry);
        let (_sender, receiver) = std::sync::mpsc::sync_channel(1);
        let started = Instant::now();
        assert!(await_resolution(
            &domain,
            &startup,
            &receiver,
            started + Duration::from_millis(25)
        )
        .unwrap()
        .is_none());
        assert!(started.elapsed() < Duration::from_secs(1));
        let generation = domain.approved_index_path().join("account-generation");
        let cancel = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(25));
            fs::remove_file(generation).unwrap();
        });
        let started = Instant::now();
        let result = await_resolution(
            &domain,
            &startup,
            &receiver,
            started + Duration::from_secs(5),
        );
        cancel.join().unwrap();
        assert!(result.unwrap().is_none());
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn refresh_lock_deduplicates_and_cleanup_waits_for_writer() {
        let (_root, domain, entry) = fixture();
        let path = entry_path(&domain, &entry);
        store_at(&path, &entry).unwrap();
        let lock = try_lock(&path).unwrap().unwrap();
        assert!(try_lock(&path).unwrap().is_none());
        // Atomic-write temporary files can coexist with the lock. Shutdown
        // waits for the owner before validating/removing completed cache files.
        let temporary = tempfile::NamedTempFile::new_in(path.parent().unwrap()).unwrap();
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            drop(temporary);
            drop(lock);
        });
        let result = cleanup(&domain);
        writer.join().unwrap();
        result.unwrap();
        assert!(!path.parent().unwrap().exists());
        assert!(domain.runtime_path().exists());
        assert!(store_at(&path, &entry).is_err());
        assert!(!path.parent().unwrap().exists());
    }
}

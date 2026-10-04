//! Requester-selected SSH policy. Matching warm commands need no provider RPC.
use super::{local_config::LocalPlan, persistent, SessionRequest};
use crate::auth_from::Provider;
use crate::cli::NativeEndpoint;
use crate::destination::ssh_auth::{self, ResolvedPolicy};
use crate::persistence::Domain;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const DIRECTORY: &str = "resolution-v1";
const MAX_FILE: u64 = 256 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Selection {
    pub(super) provider: String,
    pub(super) policy: ResolvedPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) local: Option<LocalPlan>,
}
pub(super) struct Plan {
    pub(super) selected: Selection,
    pub(super) generation: String,
    pub(super) proxy: Option<String>,
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
    if let Some(local) = &entry.selected.local {
        local.validate()?;
    }
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

/// Completion/export validates local configuration within a short budget. It
/// never contacts a provider, requests approval, or refreshes provider metadata.
pub(super) fn cached(domain: &Domain, request: &SessionRequest) -> Result<Option<Selection>> {
    Ok((|| -> Result<Option<Selection>> {
        if existing_directory(domain)?.is_none() {
            return Ok(None);
        }
        let Some(provider) = ssh_auth::local_binding(domain, &request.provider)? else {
            return Ok(None);
        };
        let Some(entry) = read_at(
            &path(domain, &request.provider, &request.destination, &provider)?,
            &request.provider,
            &request.destination,
            &provider,
        )?
        else {
            return Ok(None);
        };
        if entry.selected.local.as_ref().is_none_or(|local| {
            LocalPlan::resolve_bounded(&request.destination, Duration::from_millis(200)).map_or(
                true,
                |current| {
                    current.config_digest != local.config_digest
                        || current.endpoint != local.endpoint
                },
            )
        }) {
            return Ok(None);
        }
        Ok(Some(entry.selected))
    })()
    .unwrap_or(None))
}

/// Local configuration is resolved before this function and before looking at
/// any live master. Provider metadata can never choose the destination route.
pub(super) fn select(
    domain: &Domain,
    request: &SessionRequest,
    local: LocalPlan,
    proxy: Option<String>,
) -> Result<Plan> {
    local.validate()?;
    let generation = persistent::ensure_generation(domain)?;
    let entry = (|| -> Result<Option<Entry>> {
        let Some(binding) = ssh_auth::local_binding(domain, &request.provider)? else { return Ok(None); };
        if existing_directory(domain)?.is_none() { return Ok(None); }
        read_at(&path(domain, &request.provider, &request.destination, &binding)?,
            &request.provider, &request.destination, &binding)
    })().unwrap_or_else(|error| {
        crate::output::diagnostic!("syq: warning: cannot read SSH policy cache ({error:#}); consulting the selected provider again");
        None
    });
    if let Some(mut entry) = entry {
        if entry.selected.local.as_ref().is_some_and(|previous| {
            previous.config_digest == local.config_digest
                && previous.endpoint == local.endpoint
                && previous.requested == local.requested
                && previous.host_key_alias == local.host_key_alias
        }) && entry.selected.policy.endpoint == local.endpoint
        {
            // Preserve the exact local plan selected before looking for a master.
            if entry.selected.local.as_ref() != Some(&local) {
                entry.selected.local = Some(local);
                save(domain, &entry);
            }
            return Ok(Plan {
                selected: entry.selected,
                generation,
                proxy,
            });
        }
    }
    let resolved = ssh_auth::resolve(domain, request, &local)?;
    anyhow::ensure!(
        resolved.policy.endpoint == local.endpoint,
        "SSH provider changed the requester-selected endpoint"
    );
    anyhow::ensure!(
        ssh_auth::local_binding(domain, &request.provider)?.as_deref()
            == Some(resolved.binding.as_str()),
        "SSH provider connection changed during resolution; retry the command"
    );
    let selected = Selection {
        provider: resolved.binding,
        policy: resolved.policy,
        local: Some(local),
    };
    anyhow::ensure!(
        persistent::generation_open(domain, &generation)?,
        "SSH policy setup was cancelled while inspecting the provider"
    );
    let timestamp = now()?;
    save(
        domain,
        &Entry {
            version: persistent::provider_state_version(&request.provider),
            authorizer: request.provider.clone(),
            requested: request.destination.clone(),
            selected: selected.clone(),
            checked: timestamp,
            attempted: timestamp,
        },
    );
    Ok(Plan {
        selected,
        generation,
        proxy,
    })
}

fn save(domain: &Domain, entry: &Entry) {
    let result = (|| -> Result<()> {
        directory(domain)?;
        store_at(
            &path(
                domain,
                &entry.authorizer,
                &entry.requested,
                &entry.selected.provider,
            )?,
            entry,
        )
    })();
    if let Err(error) = result {
        crate::output::diagnostic!("syq: warning: cannot save SSH policy cache ({error:#}); continuing with the selected endpoint");
    }
}

/// Keep a later command from repeatedly using metadata whose new login failed.
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
                local: None,
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
            tty: super::super::Tty::Disabled,
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
}

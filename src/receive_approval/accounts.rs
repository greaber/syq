//! Remembered account permissions are local policy, separate from receiving
//! settings and account connection indexes used by older syq versions.
use crate::persistence::Domain;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const VERSION: u16 = 1;
const MAX_STATE: usize = 512 * 1024;

/// Construct only from the laptop's resolved SSH policy. A requesting server
/// cannot choose the endpoint or trusted host keys used for this identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AccountIdentity {
    pub endpoint: crate::cli::NativeEndpoint,
    pub host_keys: Vec<String>,
}
impl AccountIdentity {
    pub(crate) fn new(
        endpoint: crate::cli::NativeEndpoint,
        mut host_keys: Vec<String>,
    ) -> Result<Self> {
        host_keys.sort();
        host_keys.dedup();
        let identity = Self {
            endpoint,
            host_keys,
        };
        identity.validate()?;
        Ok(identity)
    }
    pub(super) fn validate(&self) -> Result<()> {
        crate::destination::ssh::validate_endpoint(&self.endpoint)?;
        anyhow::ensure!(
            self.endpoint
                .user
                .as_ref()
                .is_some_and(|user| !user.is_empty())
                && self.endpoint.port.is_some(),
            "account permission requires a resolved SSH login and port"
        );
        anyhow::ensure!(
            !self.host_keys.is_empty() && self.host_keys.len() <= 128,
            "account permission requires bounded trusted host-key identities"
        );
        for key in &self.host_keys {
            anyhow::ensure!(
                key.len() <= 128 && key.starts_with("SHA256:"),
                "invalid trusted host-key fingerprint"
            );
            key.parse::<ssh_key::Fingerprint>()
                .context("invalid trusted host-key fingerprint")?;
        }
        anyhow::ensure!(
            self.host_keys.windows(2).all(|keys| keys[0] < keys[1]),
            "account permission host-key identities are not canonical"
        );
        Ok(())
    }
    pub(crate) fn label(&self) -> String {
        let host = if self.endpoint.host.contains(':') {
            format!("[{}]", self.endpoint.host)
        } else {
            self.endpoint.host.clone()
        };
        format!(
            "{}@{host}:{}",
            self.endpoint.user.as_deref().unwrap_or(""),
            self.endpoint.port.unwrap_or(22)
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AccountPermission {
    pub profile: String,
    pub source: AccountIdentity,
    pub destination: AccountIdentity,
}
impl AccountPermission {
    pub(crate) fn new(
        profile: String,
        source: AccountIdentity,
        destination: AccountIdentity,
    ) -> Result<Self> {
        let permission = Self {
            profile,
            source,
            destination,
        };
        permission.validate()?;
        Ok(permission)
    }
    fn validate(&self) -> Result<()> {
        crate::destination::validate_name(&self.profile)?;
        self.source.validate()?;
        self.destination.validate()
    }
    pub(crate) fn id(&self) -> String {
        // The canonical v1 identity includes every authority-bearing field.
        blake3::hash(&serde_json::to_vec(self).expect("account identity serializes"))
            .to_hex()
            .to_string()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RememberedPermission<P = AccountPermission> {
    pub id: String,
    pub permission: P,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct State<P = AccountPermission> {
    version: u16,
    pub(super) permissions: Vec<RememberedPermission<P>>,
}
impl<P> Default for State<P> {
    fn default() -> Self {
        Self {
            version: VERSION,
            permissions: Vec::new(),
        }
    }
}
fn path(domain: &Domain) -> Result<PathBuf> {
    domain.config_file("account-permissions-v1.json")
}
pub(super) trait StoredPermission:
    Clone + PartialEq + Serialize + serde::de::DeserializeOwned
{
    fn validate(&self) -> Result<()>;
    fn id(&self) -> String;
}
impl StoredPermission for AccountPermission {
    fn validate(&self) -> Result<()> {
        AccountPermission::validate(self)
    }
    fn id(&self) -> String {
        AccountPermission::id(self)
    }
}

fn read(path: &Path) -> Result<State> {
    read_permissions(path)
}
pub(super) fn read_permissions<P: StoredPermission>(path: &Path) -> Result<State<P>> {
    let bytes = match crate::delegation::read_private_regular(path, "remembered account permissions", MAX_STATE) {
        Ok(bytes) => bytes,
        Err(error) if error.chain().any(|cause| cause.downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)) => return Ok(State::default()),
        Err(error) => return Err(error).with_context(|| format!("read remembered account permissions {}; repair the file before authorizing accounts", path.display())),
    };
    let state: State<P> = serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "parse remembered account permissions {}; repair the file before authorizing accounts",
            path.display()
        )
    })?;
    anyhow::ensure!(
        state.version == VERSION,
        "unsupported remembered account permissions version {} in {}; use a matching syq version",
        state.version,
        path.display()
    );
    let mut ids = std::collections::BTreeSet::new();
    for item in &state.permissions {
        item.permission.validate().with_context(|| {
            format!("invalid remembered account permission in {}; repair the file before authorizing accounts", path.display())
        })?;
        anyhow::ensure!(
            item.id == item.permission.id() && ids.insert(&item.id),
            "invalid or duplicate remembered account permission in {}",
            path.display()
        );
    }
    Ok(state)
}

pub(crate) fn remembered(domain: &Domain, permission: &AccountPermission) -> Result<bool> {
    permission.validate()?;
    Ok(read(&path(domain)?)?
        .permissions
        .iter()
        .any(|item| item.permission == *permission))
}
pub(crate) fn list(domain: &Domain) -> Result<Vec<RememberedPermission>> {
    Ok(read(&path(domain)?)?.permissions)
}
pub(crate) fn remember(domain: &Domain, permission: &AccountPermission) -> Result<()> {
    update_domain(domain, Some(permission), None)
}
pub(crate) fn remove(domain: &Domain, id: &str) -> Result<()> {
    validate_id(id)?;
    update_domain(domain, None, Some(id))
}
pub(super) fn validate_id(id: &str) -> Result<()> {
    anyhow::ensure!(
        id.len() == 64 && id.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "use the complete permission ID from syq persist receive permissions list"
    );
    Ok(())
}
fn update_domain(
    domain: &Domain,
    add: Option<&AccountPermission>,
    remove: Option<&str>,
) -> Result<()> {
    let path = prepare_store(domain, "account-permissions-v1.json")?;
    update(&path, add, remove)
}
pub(super) fn prepare_store(domain: &Domain, filename: &str) -> Result<PathBuf> {
    let path = domain.config_file(filename)?;
    if domain.is_default() {
        fs::create_dir_all(
            path.parent()
                .context("account permission directory missing")?,
        )?;
    }
    Ok(path)
}

struct PermissionLock(std::fs::File);
impl Drop for PermissionLock {
    fn drop(&mut self) {
        // A concurrently forked child can temporarily retain this open file
        // description before exec closes it. End writer ownership explicitly.
        unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}
fn update(path: &Path, add: Option<&AccountPermission>, remove: Option<&str>) -> Result<()> {
    update_permissions(path, add, remove)
}
pub(super) fn update_permissions<P: StoredPermission>(
    path: &Path,
    add: Option<&P>,
    remove: Option<&str>,
) -> Result<()> {
    if let Some(permission) = add {
        permission.validate()?;
    }
    let parent = path
        .parent()
        .context("account permission directory missing")?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path.with_extension("lock"))?;
    let metadata = lock.metadata()?;
    anyhow::ensure!(
        metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0,
        "account permission lock must be owned and private"
    );
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        bail!("account permissions are being changed; retry shortly");
    }
    let _lock = PermissionLock(lock);
    let mut state: State<P> = read_permissions(path)?;
    if let Some(id) = remove {
        let count = state.permissions.len();
        state.permissions.retain(|item| item.id != id);
        anyhow::ensure!(
            state.permissions.len() != count,
            "remembered account permission not found"
        );
    }
    if let Some(permission) = add {
        if !state
            .permissions
            .iter()
            .any(|item| item.permission == *permission)
        {
            state.permissions.push(RememberedPermission {
                id: permission.id(),
                permission: permission.clone(),
            });
            state.permissions.sort_by(|a, b| a.id.cmp(&b.id));
        }
    }
    let bytes = serde_json::to_vec_pretty(&state)?;
    anyhow::ensure!(
        bytes.len() < MAX_STATE,
        "remembered account permissions exceed the state-file size limit"
    );
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(&bytes)?;
    temporary.write_all(b"\n")?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn permission() -> AccountPermission {
        let identity = |host: &str, key: u8| {
            AccountIdentity::new(
                crate::cli::NativeEndpoint {
                    user: Some("alice".into()),
                    host: host.into(),
                    port: Some(22),
                },
                vec![ssh_key::Fingerprint::Sha256([key; 32]).to_string()],
            )
            .unwrap()
        };
        AccountPermission::new(
            "laptop".into(),
            identity("source", 1),
            identity("destination", 2),
        )
        .unwrap()
    }
    fn write(path: &Path, data: &[u8]) {
        fs::write(path, data).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn return_permission_v1_serialization_and_identity_remain_unchanged() {
        let original = r#"{"profile":"laptop","source":{"endpoint":{"user":"alice","host":"source","port":22},"host_keys":["SHA256:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"]},"destination":{"endpoint":{"user":"alice","host":"destination","port":22},"host_keys":["SHA256:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"]}}"#;
        let permission: AccountPermission = serde_json::from_str(original).unwrap();
        permission.validate().unwrap();
        assert_eq!(serde_json::to_string(&permission).unwrap(), original);
        // v1 used the unprefixed hash of these exact serialized bytes.
        let id = blake3::hash(original.as_bytes()).to_hex().to_string();
        assert_eq!(permission.id(), id);
        let original_state =
            format!(r#"{{"version":1,"permissions":[{{"id":"{id}","permission":{original}}}]}}"#);
        let temp = crate::test_support::tempdir().unwrap();
        let path = temp.path().join("account-permissions-v1.json");
        write(&path, original_state.as_bytes());
        let state = read(&path).unwrap();
        assert_eq!(serde_json::to_string(&state).unwrap(), original_state);
        update(&path, Some(&permission), None).unwrap();
        assert_eq!(
            serde_json::to_string(&read(&path).unwrap()).unwrap(),
            original_state
        );
    }

    #[test]
    fn remembered_permission_matches_the_complete_trusted_pair_and_profile() {
        let temp = crate::test_support::tempdir().unwrap();
        let path = temp.path().join("account-permissions-v1.json");
        let permission = permission();
        assert!(read(&path).unwrap().permissions.is_empty());
        update(&path, Some(&permission), None).unwrap();
        update(&path, Some(&permission), None).unwrap();
        let saved = read(&path).unwrap();
        assert_eq!(saved.permissions.len(), 1);
        assert_eq!(saved.permissions[0].permission, permission);
        assert_eq!(saved.permissions[0].id, permission.id());
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        for field in 0..7 {
            let mut changed = permission.clone();
            match field {
                0 => changed.profile = "other".into(),
                1 => changed.source.endpoint.user = Some("bob".into()),
                2 => changed.source.endpoint.host = "other-source".into(),
                3 => changed.source.endpoint.port = Some(2222),
                4 => {
                    changed.source.host_keys =
                        vec![ssh_key::Fingerprint::Sha256([3; 32]).to_string()]
                }
                5 => changed.destination.endpoint.user = Some("bob".into()),
                _ => {
                    changed.destination.host_keys =
                        vec![ssh_key::Fingerprint::Sha256([4; 32]).to_string()]
                }
            }
            assert_ne!(changed.id(), permission.id());
            assert!(!saved
                .permissions
                .iter()
                .any(|item| item.permission == changed));
        }
        update(&path, None, Some(&permission.id())).unwrap();
        assert!(read(&path).unwrap().permissions.is_empty());
    }

    #[test]
    fn remembered_permissions_belong_only_to_the_authorizing_domain() {
        // Socket paths must fit even when the platform's ambient TMPDIR is long.
        let root = std::fs::canonicalize("/tmp").unwrap();
        let temporary = tempfile::tempdir_in(root).unwrap();
        let first_path = temporary.path().join("first");
        let second_path = temporary.path().join("second");
        for path in [&first_path, &second_path] {
            crate::persistence::initialize_scope(path).unwrap();
        }
        let first = Domain::select(Some(&first_path)).unwrap();
        let second = Domain::select(Some(&second_path)).unwrap();
        let permission = permission();
        remember(&first, &permission).unwrap();
        let first_queue = super::super::Queue::new(first.clone());
        let second_queue = super::super::Queue::new(second.clone());
        assert!(first_queue.account_remembered(&permission).unwrap());
        assert!(!second_queue.account_remembered(&permission).unwrap());
        assert!(list(&second).unwrap().is_empty());
        remember(&second, &permission).unwrap();
        assert_eq!(
            fs::read(path(&first).unwrap()).unwrap(),
            fs::read(path(&second).unwrap()).unwrap()
        );
        remove(&first, &permission.id()).unwrap();
        assert!(!first_queue.account_remembered(&permission).unwrap());
        assert!(second_queue.account_remembered(&permission).unwrap());
    }

    #[test]
    fn invalid_or_newer_remembered_state_is_preserved_and_blocks_authorization() {
        let temp = crate::test_support::tempdir().unwrap();
        let path = temp.path().join("account-permissions-v1.json");
        let permission = permission();
        let item = RememberedPermission {
            id: permission.id(),
            permission: permission.clone(),
        };
        let mut wrong_id = item.clone();
        wrong_id.id = "0".repeat(64);
        let invalid = [
            b"broken".to_vec(),
            br#"{"version":2,"permissions":[]}"#.to_vec(),
            br#"{"version":1,"permissions":[],"new_authority":true}"#.to_vec(),
            serde_json::to_vec(&State {
                version: VERSION,
                permissions: vec![item.clone(), item],
            })
            .unwrap(),
            serde_json::to_vec(&State {
                version: VERSION,
                permissions: vec![wrong_id],
            })
            .unwrap(),
        ];
        for bytes in invalid {
            write(&path, &bytes);
            assert!(read(&path).is_err());
            assert!(update(&path, Some(&permission), None).is_err());
            assert!(update(&path, None, Some(&permission.id())).is_err());
            assert_eq!(fs::read(&path).unwrap(), bytes);
        }
    }

    #[test]
    fn remembered_state_rejects_public_files_and_symlinks() {
        let temp = crate::test_support::tempdir().unwrap();
        let path = temp.path().join("account-permissions-v1.json");
        let target = temp.path().join("other");
        let bytes = serde_json::to_vec(&State::<AccountPermission>::default()).unwrap();
        write(&target, &bytes);
        symlink(&target, &path).unwrap();
        assert!(read(&path).is_err());
        assert!(update(&path, Some(&permission()), None).is_err());
        assert!(fs::symlink_metadata(&path).unwrap().is_symlink());
        fs::remove_file(&path).unwrap();
        write(&path, &bytes);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read(&path).is_err());
    }

    #[test]
    fn writer_unlocks_even_while_a_forked_description_remains_open() {
        let temp = crate::test_support::tempdir().unwrap();
        let path = temp.path().join("account-permissions-v1.lock");
        write(&path, b"");
        let first = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        assert_eq!(
            unsafe { libc::flock(first.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        // dup and fork both retain the same open file description. Keep one
        // alive to model the child before it reaches close-on-exec.
        let inherited = first.try_clone().unwrap();
        let lock = PermissionLock(first);
        let second = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        assert_ne!(
            unsafe { libc::flock(second.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        drop(lock);
        assert_eq!(
            unsafe { libc::flock(second.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        drop(PermissionLock(second));
        drop(inherited);
    }

    #[test]
    fn identities_require_explicit_accounts_and_trusted_sha256_keys() {
        let identity = permission().source;
        let mut alias = identity.endpoint.clone();
        alias.user = None;
        assert!(AccountIdentity::new(alias, identity.host_keys.clone()).is_err());
        assert!(AccountIdentity::new(identity.endpoint.clone(), vec![]).is_err());
        assert!(
            AccountIdentity::new(identity.endpoint.clone(), vec!["SHA256:invalid".into()]).is_err()
        );
        let second = ssh_key::Fingerprint::Sha256([2; 32]).to_string();
        let canonical = AccountIdentity::new(
            identity.endpoint,
            vec![second.clone(), identity.host_keys[0].clone(), second],
        )
        .unwrap();
        assert_eq!(canonical.host_keys.len(), 2);
        assert!(canonical.host_keys[0] < canonical.host_keys[1]);
    }
}

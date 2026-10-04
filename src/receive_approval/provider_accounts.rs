//! Permissions for SSH logins to the provider's own account. These are not
//! return-channel grants: an inbound login does not verify a source host.
use super::accounts::{self, AccountIdentity, StoredPermission};
use crate::persistence::Domain;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

pub(crate) const STATE_FILE: &str = "provider-account-permissions-v1.json";
pub(crate) const LOCK_FILE: &str = "provider-account-permissions-v1.lock";
const ID_CONTEXT: &str = "syq provider-login permission v1";

/// Construct from the provider's effective-UID account lookup and its local
/// receiving identity key. Neither USER/LOGNAME nor incoming request fields
/// establish this identity. The fingerprint names the receiving identity,
/// not an SSH host key or a claimed source machine.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProviderIdentity {
    pub user: String,
    pub receiver_identity: String,
}
impl ProviderIdentity {
    pub(crate) fn new(user: String, receiver_identity: String) -> Result<Self> {
        let identity = Self {
            user,
            receiver_identity,
        };
        identity.validate()?;
        Ok(identity)
    }
    fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            !self.user.is_empty()
                && self.user.len() <= 512
                && !self.user.starts_with('-')
                && self
                    .user
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte)),
            "provider permission requires a plain local account name"
        );
        anyhow::ensure!(
            self.receiver_identity.len() <= 128 && self.receiver_identity.starts_with("SHA256:"),
            "provider permission requires a receiving-identity SHA256 fingerprint"
        );
        self.receiver_identity
            .parse::<ssh_key::Fingerprint>()
            .context("invalid provider receiving-identity fingerprint")?;
        Ok(())
    }
    pub(crate) fn label(&self) -> String {
        format!("SSH logins to this provider account: {}", self.user)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProviderLoginPermission {
    pub profile: String,
    pub provider: ProviderIdentity,
    pub destination: AccountIdentity,
}
impl ProviderLoginPermission {
    pub(crate) fn new(
        profile: String,
        provider: ProviderIdentity,
        destination: AccountIdentity,
    ) -> Result<Self> {
        let permission = Self {
            profile,
            provider,
            destination,
        };
        permission.validate()?;
        Ok(permission)
    }
    pub(crate) fn validate(&self) -> Result<()> {
        crate::destination::validate_name(&self.profile)?;
        self.provider.validate()?;
        self.destination.validate()
    }
    pub(crate) fn id(&self) -> String {
        let mut hash = blake3::Hasher::new_derive_key(ID_CONTEXT);
        hash.update(&serde_json::to_vec(self).expect("provider permission serializes"));
        hash.finalize().to_hex().to_string()
    }
}
impl StoredPermission for ProviderLoginPermission {
    fn validate(&self) -> Result<()> {
        ProviderLoginPermission::validate(self)
    }
    fn id(&self) -> String {
        ProviderLoginPermission::id(self)
    }
}

pub(crate) type RememberedPermission = accounts::RememberedPermission<ProviderLoginPermission>;

pub(crate) fn remembered(domain: &Domain, permission: &ProviderLoginPermission) -> Result<bool> {
    permission.validate()?;
    Ok(list(domain)?
        .iter()
        .any(|item| item.permission == *permission))
}
pub(crate) fn list(domain: &Domain) -> Result<Vec<RememberedPermission>> {
    Ok(accounts::read_permissions(&domain.config_file(STATE_FILE)?)?.permissions)
}
pub(crate) fn remember(domain: &Domain, permission: &ProviderLoginPermission) -> Result<()> {
    let path = accounts::prepare_store(domain, STATE_FILE)?;
    accounts::update_permissions(&path, Some(permission), None)
}
pub(crate) fn remove(domain: &Domain, id: &str) -> Result<()> {
    accounts::validate_id(id)?;
    let path = accounts::prepare_store(domain, STATE_FILE)?;
    accounts::update_permissions::<ProviderLoginPermission>(&path, None, Some(id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    pub(super) fn permission() -> ProviderLoginPermission {
        ProviderLoginPermission::new(
            "provider".into(),
            ProviderIdentity::new(
                "alice".into(),
                ssh_key::Fingerprint::Sha256([1; 32]).to_string(),
            )
            .unwrap(),
            AccountIdentity::new(
                crate::cli::NativeEndpoint {
                    user: Some("bob".into()),
                    host: "destination".into(),
                    port: Some(22),
                },
                vec![ssh_key::Fingerprint::Sha256([2; 32]).to_string()],
            )
            .unwrap(),
        )
        .unwrap()
    }
    fn domain(path: &Path) -> Domain {
        crate::persistence::initialize_scope(path).unwrap();
        Domain::select(Some(path)).unwrap()
    }
    fn write(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn permission_binds_provider_identity_profile_and_destination() {
        let permission = permission();
        let unprefixed = blake3::hash(&serde_json::to_vec(&permission).unwrap())
            .to_hex()
            .to_string();
        assert_ne!(permission.id(), unprefixed);
        for field in 0..7 {
            let mut changed = permission.clone();
            match field {
                0 => changed.profile = "other".into(),
                1 => changed.provider.user = "other".into(),
                2 => {
                    changed.provider.receiver_identity =
                        ssh_key::Fingerprint::Sha256([3; 32]).to_string()
                }
                3 => changed.destination.endpoint.user = Some("other".into()),
                4 => changed.destination.endpoint.host = "other".into(),
                5 => changed.destination.endpoint.port = Some(2222),
                _ => {
                    changed.destination.host_keys =
                        vec![ssh_key::Fingerprint::Sha256([4; 32]).to_string()]
                }
            }
            changed.validate().unwrap();
            assert_ne!(permission.id(), changed.id());
            assert_ne!(permission, changed);
        }
        assert!(ProviderIdentity::new(
            "claimed@source".into(),
            permission.provider.receiver_identity.clone()
        )
        .is_err());
        assert!(ProviderIdentity::new("alice".into(), "SHA256:invalid".into()).is_err());
    }

    #[test]
    fn provider_permissions_are_separate_from_return_grants_and_other_domains() {
        let root = std::fs::canonicalize("/tmp").unwrap();
        let temporary = tempfile::tempdir_in(root).unwrap();
        let first = domain(&temporary.path().join("first"));
        let second = domain(&temporary.path().join("second"));
        let permission = permission();
        let return_permission = accounts::AccountPermission::new(
            permission.profile.clone(),
            permission.destination.clone(),
            permission.destination.clone(),
        )
        .unwrap();
        accounts::remember(&first, &return_permission).unwrap();
        let return_path = first.config_file("account-permissions-v1.json").unwrap();
        let original_return = fs::read(&return_path).unwrap();
        assert!(!remembered(&first, &permission).unwrap());
        remember(&first, &permission).unwrap();
        remember(&first, &permission).unwrap();
        assert_eq!(list(&first).unwrap().len(), 1);
        assert!(remembered(&first, &permission).unwrap());
        assert!(!remembered(&second, &permission).unwrap());
        assert_eq!(fs::read(&return_path).unwrap(), original_return);
        assert!(accounts::remembered(&first, &return_permission).unwrap());
        let path = first.config_file(STATE_FILE).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert_eq!(
            path.with_extension("lock"),
            first.config_file(LOCK_FILE).unwrap()
        );
        // Each store rejects the other origin instead of translating authority.
        let return_bytes = fs::read(&return_path).unwrap();
        let provider_bytes = fs::read(&path).unwrap();
        write(&path, &return_bytes);
        assert!(remembered(&first, &permission).is_err());
        write(&path, &provider_bytes);
        write(&return_path, &provider_bytes);
        assert!(accounts::remembered(&first, &return_permission).is_err());
        write(&return_path, &return_bytes);
        remember(&second, &permission).unwrap();
        remove(&first, &permission.id()).unwrap();
        assert!(!remembered(&first, &permission).unwrap());
        assert!(remembered(&second, &permission).unwrap());
        assert_eq!(fs::read(&return_path).unwrap(), original_return);
    }

    #[test]
    fn malformed_or_incompatible_provider_state_is_never_replaced() {
        let root = std::fs::canonicalize("/tmp").unwrap();
        let temporary = tempfile::tempdir_in(root).unwrap();
        let domain = domain(&temporary.path().join("provider"));
        let path = domain.config_file(STATE_FILE).unwrap();
        let permission = permission();
        let invalid = [
            b"broken".to_vec(),
            br#"{"version":2,"permissions":[]}"#.to_vec(),
            br#"{"version":1,"permissions":[],"new_authority":true}"#.to_vec(),
            serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "permissions": [{"id": "0".repeat(64), "permission": permission}],
            }))
            .unwrap(),
        ];
        for bytes in invalid {
            write(&path, &bytes);
            assert!(remembered(&domain, &permission).is_err());
            assert!(remember(&domain, &permission).is_err());
            assert!(remove(&domain, &permission.id()).is_err());
            assert_eq!(fs::read(&path).unwrap(), bytes);
        }
    }
}

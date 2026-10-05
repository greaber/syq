//! User-selected authorization defaults. This file is independent of SSH
//! persistence state so older binaries can keep using their existing settings.
use crate::cli::AuthFrom;
use crate::persistence::Domain;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const MAX_CONFIG_BYTES: u64 = 128 * 1024;

/// The selected authority, independent of any reusable connection. Existing
/// return records keep their bare name strings; native SSH providers have a
/// distinct representation which older readers cannot mistake for a name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub(crate) enum Provider {
    Return(String),
    Ssh {
        #[serde(rename = "ssh")]
        endpoint: crate::cli::NativeEndpoint,
    },
}
impl Provider {
    pub(crate) fn parse(value: &str) -> Result<Self> {
        let provider = if let Some(name) = value.strip_prefix('@') {
            Self::Return(name.into())
        } else {
            Self::Ssh {
                endpoint: crate::cli::parse_native_endpoint(Some(value))?
                    .context("SSH authorization provider is missing")?,
            }
        };
        provider.validate()?;
        Ok(provider)
    }
    pub(crate) fn validate(&self) -> Result<()> {
        match self {
            Self::Return(name) => crate::destination::validate_name(name),
            Self::Ssh { endpoint } => crate::destination::ssh::validate_endpoint(endpoint),
        }
    }
    pub(crate) fn receiving_name(&self) -> Option<&str> {
        match self {
            Self::Return(name) => Some(name),
            Self::Ssh { .. } => None,
        }
    }
    pub(crate) fn label(&self) -> String {
        match self {
            Self::Return(name) => format!("@{name}"),
            Self::Ssh { endpoint } => {
                let mut label = if endpoint.host.contains(':') {
                    format!("[{}]", endpoint.host)
                } else {
                    endpoint.host.clone()
                };
                if let Some(user) = &endpoint.user {
                    label = format!("{user}@{label}");
                }
                if let Some(port) = endpoint.port {
                    label.push_str(&format!(":{port}"));
                }
                label
            }
        }
    }
}
impl std::fmt::Display for Provider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.label())
    }
}

#[derive(clap::Args, Debug)]
pub(crate) struct PreferenceCommand {
    /// Authorization for later commands; omit to show saved defaults
    #[arg(value_name = "auto|ssh|@NAME|HOST", value_parser = crate::cli::parse_auth_from)]
    value: Option<AuthFrom>,
    /// Apply to this exact destination hostname or SSH alias, for any login/port
    #[arg(long = "for", value_name = "HOST", value_parser = host_key)]
    host: Option<String>,
    /// Remove the selected override so it inherits the default
    #[arg(long, conflicts_with = "value")]
    reset: bool,
}

#[derive(Default, Serialize, Deserialize)]
struct Config {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_version"
    )]
    version: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    default: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    hosts: BTreeMap<String, String>,
    // Additive fields must survive edits by a binary that does not use them.
    #[serde(flatten)]
    extensions: BTreeMap<String, serde_json::Value>,
}

fn deserialize_version<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<u32>, D::Error> {
    u32::deserialize(deserializer).map(Some)
}

impl Config {
    fn validate(&self) -> Result<()> {
        if let Some(version) = self.version {
            anyhow::ensure!(
                version == 1,
                "unsupported authorization preferences version {version}"
            );
        }
        if let Some(value) = &self.default {
            crate::cli::parse_auth_from(value)?;
        }
        for (host, value) in &self.hosts {
            anyhow::ensure!(
                host_key(host)? == *host,
                "noncanonical authorization preference host"
            );
            crate::cli::parse_auth_from(value)?;
        }
        Ok(())
    }
    fn selected(&self, host: &str) -> Result<AuthFrom> {
        crate::cli::parse_auth_from(
            self.hosts
                .get(host)
                .or(self.default.as_ref())
                .map(String::as_str)
                .unwrap_or("auto"),
        )
    }
}

fn spelling(value: &AuthFrom) -> String {
    match value {
        AuthFrom::Auto => "auto".into(),
        AuthFrom::Ssh => "ssh".into(),
        AuthFrom::Provider(provider) => provider.label(),
    }
}

fn host_key(value: &str) -> Result<String> {
    // Endpoint parsing removes IPv6 brackets; accept the stored host spelling too.
    if value.parse::<std::net::Ipv6Addr>().is_ok() {
        return Ok(value.to_owned());
    }
    let endpoint =
        crate::cli::parse_native_endpoint(Some(value))?.context("authorization host is empty")?;
    if endpoint.user.is_some()
        || endpoint.port.is_some()
        || endpoint.host.starts_with('-')
        || !endpoint
            .host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-:".contains(&byte))
    {
        bail!("--for needs a hostname or SSH alias without a login or port");
    }
    Ok(endpoint.host)
}

fn path(domain: &Domain) -> Result<PathBuf> {
    domain.config_file("auth-from.json")
}

fn read(path: &Path) -> Result<Config> {
    read_inner(path).with_context(|| {
        format!(
            "read saved authorization choice from {}; repair this file or pass --auth-from explicitly (--syq-auth-from for rsync)",
            path.display(),
        )
    })
}

fn linked_target(path: &Path) -> Result<PathBuf> {
    std::fs::canonicalize(path).with_context(|| {
        format!(
            "resolve symlinked authorization preferences {}; the target must exist",
            path.display()
        )
    })
}

fn read_inner(path: &Path) -> Result<Config> {
    let open = |path: &Path| {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)
    };
    let mut file = match open(path) {
        Ok(file) => file,
        // Keep the ordinary read to one open. A final symlink resolves once;
        // a dangling target is an error, never a missing/default preference.
        Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
            open(&linked_target(path)?).context("open linked authorization preferences")?
        }
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                || error.raw_os_error() == Some(libc::ENOTDIR) =>
        {
            return Ok(Config::default());
        }
        Err(error) => return Err(error).context("open authorization preferences"),
    };
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o022 == 0,
        "authorization preferences must be a regular file owned by this user and not writable by others"
    );
    let mut contents = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut contents)?;
    anyhow::ensure!(
        contents.len() as u64 <= MAX_CONFIG_BYTES,
        "authorization preferences are too large"
    );
    let config: Config =
        serde_json::from_slice(&contents).context("parse authorization preferences")?;
    config.validate()?;
    Ok(config)
}
fn load(domain: &Domain) -> Result<Config> {
    if domain.is_default() && crate::persistence::config_path().is_none() {
        return Ok(Config::default());
    }
    read(&path(domain)?)
}

/// Explicit flags bypass disk reads, including `auto`. Preference lookup uses
/// the typed hostname/alias, without an SSH connection or config expansion.
pub(crate) fn resolve(domain: &Domain, host: &str, explicit: Option<AuthFrom>) -> Result<AuthFrom> {
    if let Some(choice) = explicit {
        return Ok(choice);
    }
    load(domain)?.selected(host)
}

pub(crate) fn selected_context<T>(result: Result<T>, mode: &AuthFrom, explicit: bool) -> Result<T> {
    match mode {
        AuthFrom::Provider(provider) if !explicit => result.with_context(|| {
            format!("authorization provider {provider} comes from the saved auth-from choice")
        }),
        _ => result,
    }
}

pub(crate) fn apply_copy(args: &mut crate::cli::Args) -> Result<()> {
    if args.auth_from_explicit || args.s3.is_some() {
        return Ok(());
    }
    let location = if let Some((location, _)) = crate::destination::account_copy::remote(args) {
        Some(location)
    } else if crate::destination::forward_target(args).is_ok() {
        args.locations.last()
    } else if crate::destination::pull::eligible_target(args).is_ok() {
        args.locations.first()
    } else {
        return Ok(());
    };
    let host = location
        .and_then(|location| location.host.as_deref())
        .context("authorization endpoint missing")?;
    let domain = Domain::select(args.pscope.as_deref())?;
    args.auth_from = resolve(&domain, host, None)?;
    Ok(())
}

fn update(
    path: &Path,
    host: Option<&str>,
    value: Option<&AuthFrom>,
    create_parent: bool,
) -> Result<Config> {
    update_inner(path, host, value, create_parent)
        .with_context(|| format!("update saved authorization choice in {}", path.display()))
}

fn update_inner(
    path: &Path,
    host: Option<&str>,
    value: Option<&AuthFrom>,
    create_parent: bool,
) -> Result<Config> {
    let parent = path
        .parent()
        .context("authorization configuration parent missing")?;
    if create_parent {
        std::fs::create_dir_all(parent).context("create authorization configuration directory")?;
    }
    let linked_file = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata.file_type().is_symlink(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error).context("inspect authorization preferences"),
    };
    let target = if linked_file {
        linked_target(path)?
    } else {
        path.to_owned()
    };
    let parent = target
        .parent()
        .context("authorization target parent missing")?;
    let linked = linked_file || std::fs::symlink_metadata(parent)?.file_type().is_symlink();
    // Resolve once, then lock, read and atomically replace in the target's
    // directory. Different links to the same file share this lock, and the
    // user's symlink is never replaced when preferences are saved.
    let parent = std::fs::canonicalize(parent).with_context(|| {
        format!(
            "resolve authorization configuration directory {}",
            parent.display()
        )
    })?;
    let path = parent.join(
        target
            .file_name()
            .context("authorization configuration filename missing")?,
    );
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&parent)
        .with_context(|| {
            format!(
                "open authorization configuration directory {}",
                parent.display()
            )
        })?;
    if linked {
        anyhow::ensure!(
            directory.metadata()?.uid() == unsafe { libc::geteuid() },
            "symlinked authorization configuration directory must be owned by this user: {}",
            parent.display()
        );
    }
    // A read-modify-write changes one override while preserving concurrent
    // changes made by another `persist auth-from` command.
    loop {
        if unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX) } == 0 {
            break;
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error).context("lock authorization configuration");
        }
    }
    let mut config = read(&path)?;
    match (host, value) {
        (None, value) => config.default = value.map(spelling),
        (Some(host), Some(value)) => {
            config.hosts.insert(host.into(), spelling(value));
        }
        (Some(host), None) => {
            config.hosts.remove(host);
        }
    }
    let mut temporary = tempfile::NamedTempFile::new_in(&parent)?;
    serde_json::to_writer_pretty(&mut temporary, &config)?;
    temporary.write_all(b"\n")?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(&path)
        .map_err(|error| error.error)
        .context("write authorization preferences")?;
    Ok(config)
}

pub(crate) fn run(domain: &Domain, command: PreferenceCommand) -> Result<i32> {
    let config = if command.reset || command.value.is_some() {
        update(
            &path(domain)?,
            command.host.as_deref(),
            command.value.as_ref(),
            domain.is_default(),
        )?
    } else {
        load(domain)?
    };
    if let Some(host) = &command.host {
        crate::output::human_stdout!(
            "{host}: {}{}",
            spelling(&config.selected(host)?),
            if config.hosts.contains_key(host) {
                ""
            } else {
                " (default)"
            }
        );
    } else {
        crate::output::human_stdout!("default: {}", config.default.as_deref().unwrap_or("auto"));
        for (host, value) in &config.hosts {
            crate::output::human_stdout!("{host}: {value}");
        }
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn provider_values_preserve_return_state_and_distinguish_native_hosts() {
        let returning = Provider::parse("@laptop").unwrap();
        assert_eq!(serde_json::to_string(&returning).unwrap(), r#""laptop""#);
        assert_eq!(
            serde_json::from_str::<Provider>(r#""laptop""#).unwrap(),
            returning
        );
        for value in [
            "provider",
            "alice@provider:2222",
            "alice@[2001:db8::1]:2222",
        ] {
            let provider = Provider::parse(value).unwrap();
            assert_eq!(provider.label(), value);
            let encoded = serde_json::to_string(&provider).unwrap();
            assert!(encoded.starts_with(r#"{"ssh":{"#), "{encoded}");
            assert_eq!(
                serde_json::from_str::<Provider>(&encoded).unwrap(),
                provider
            );
            assert!(serde_json::from_str::<String>(&encoded).is_err());
        }
        for value in ["", "@", "bad/name", "-oProxyCommand=x", "alice@host:0"] {
            assert!(Provider::parse(value).is_err(), "{value}");
        }
    }

    #[test]
    fn ordinary_provider_preferences_round_trip_without_changing_return_defaults() {
        let root = crate::test_support::tempdir().unwrap();
        let path = root.path().join("auth-from.json");
        std::fs::write(&path, br#"{"default":"@laptop","hosts":{"other":"ssh"}}"#).unwrap();
        let provider = crate::cli::parse_auth_from("alice@provider:2222").unwrap();
        update(&path, Some("backup"), Some(&provider), true).unwrap();
        let config = read(&path).unwrap();
        assert_eq!(config.selected("backup").unwrap(), provider);
        assert_eq!(config.selected("other").unwrap(), AuthFrom::Ssh);
        assert_eq!(
            config.selected("unchanged").unwrap(),
            AuthFrom::Provider(Provider::Return("laptop".into()))
        );
    }

    #[test]
    fn host_override_and_reset_preserve_other_preferences() {
        let root = crate::test_support::tempdir().unwrap();
        let path = root.path().join("auth-from.json");
        assert_eq!(
            read(&path).unwrap().selected("backup").unwrap(),
            AuthFrom::Auto
        );
        update(
            &path,
            None,
            Some(&AuthFrom::Provider(Provider::Return("laptop".into()))),
            true,
        )
        .unwrap();
        let config = update(&path, Some("backup"), Some(&AuthFrom::Ssh), true).unwrap();
        assert_eq!(config.selected("backup").unwrap(), AuthFrom::Ssh);
        assert_eq!(
            config.selected("Backup").unwrap(),
            AuthFrom::Provider(Provider::Return("laptop".into()))
        );
        let config = update(&path, Some("backup"), Some(&AuthFrom::Auto), true).unwrap();
        assert_eq!(config.selected("backup").unwrap(), AuthFrom::Auto);
        let config = update(&path, Some("backup"), None, true).unwrap();
        assert_eq!(
            config.selected("backup").unwrap(),
            AuthFrom::Provider(Provider::Return("laptop".into()))
        );
        let config = update(&path, None, None, true).unwrap();
        assert_eq!(config.selected("backup").unwrap(), AuthFrom::Auto);
    }
    #[test]
    fn host_keys_reject_logins_and_ports_and_keep_ipv6_spelling() {
        for host in ["backup", "BACKUP", "192.0.2.1", "2001:db8::1"] {
            assert_eq!(host_key(host).unwrap(), host);
        }
        assert_eq!(host_key("[2001:db8::1]").unwrap(), "2001:db8::1");
        for host in [
            "",
            "user@backup",
            "backup:22",
            "[::1]:22",
            "@laptop",
            "-oProxyCommand=x",
        ] {
            assert!(host_key(host).is_err(), "{host}");
        }
    }

    #[test]
    fn malformed_preferences_are_not_reinterpreted_or_overwritten() {
        let root = crate::test_support::tempdir().unwrap();
        let path = root.path().join("auth-from.json");
        for data in [
            "{",
            r#"{"default":"bad/name"}"#,
            r#"{"hosts":{"user@host":"ssh"}}"#,
            r#"{"version":2,"default":"@laptop","hosts":{"backup":"ssh"}}"#,
            r#"{"version":0}"#,
            r#"{"version":null}"#,
            r#"{"version":"1"}"#,
        ] {
            std::fs::write(&path, data).unwrap();
            let errors = [
                read(&path).err().unwrap(),
                update(&path, None, Some(&AuthFrom::Auto), true)
                    .err()
                    .unwrap(),
                update(&path, None, None, true).err().unwrap(),
                update(&path, Some("backup"), None, true).err().unwrap(),
            ];
            for error in errors {
                let detail = format!("{error:#}");
                assert!(detail.contains(path.to_str().unwrap()), "{detail}");
                assert!(detail.contains("repair this file"), "{detail}");
                assert!(detail.contains("pass --auth-from explicitly"), "{detail}");
            }
            assert_eq!(std::fs::read_to_string(&path).unwrap(), data);
        }
    }

    #[test]
    fn unversioned_preferences_remain_unversioned_after_edits() {
        let root = crate::test_support::tempdir().unwrap();
        let path = root.path().join("auth-from.json");
        // The original unversioned format, unchanged by schema serialization.
        let original = r#"{"default":"@laptop","hosts":{"backup":"ssh"}}"#;
        std::fs::write(&path, original).unwrap();
        let config = read(&path).unwrap();
        assert_eq!(config.selected("backup").unwrap(), AuthFrom::Ssh);
        assert_eq!(
            config.selected("other").unwrap(),
            AuthFrom::Provider(Provider::Return("laptop".into()))
        );
        update(&path, None, None, true).unwrap();
        let saved: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(saved, serde_json::json!({"hosts": {"backup": "ssh"}}));
    }

    #[test]
    fn additive_fields_survive_setting_and_resetting_preferences() {
        let root = crate::test_support::tempdir().unwrap();
        let path = root.path().join("auth-from.json");
        for original in [
            r#"{"future":true}"#,
            r#"{"version":1,"future":{"values":[null,true,42,"text"],"nested":{"key":"value"}}}"#,
        ] {
            std::fs::write(&path, original).unwrap();
            let original: serde_json::Value = serde_json::from_str(original).unwrap();
            for (host, value) in [
                (
                    None,
                    Some(AuthFrom::Provider(Provider::Return("laptop".into()))),
                ),
                (Some("backup"), Some(AuthFrom::Ssh)),
                (None, None),
                (Some("backup"), None),
            ] {
                update(&path, host, value.as_ref(), true).unwrap();
                let saved: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                assert_eq!(saved.get("version"), original.get("version"));
                assert_eq!(saved["future"], original["future"]);
            }
            let saved: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            assert_eq!(saved, original);
        }
    }

    #[test]
    fn linked_config_directory_and_file_update_target_without_replacing_links() {
        let root = crate::test_support::tempdir().unwrap();
        let target = root.path().join("owned-config");
        std::fs::create_dir(&target).unwrap();
        let linked = root.path().join("config");
        std::os::unix::fs::symlink(&target, &linked).unwrap();
        let path = linked.join("auth-from.json");
        update(&path, Some("backup"), Some(&AuthFrom::Ssh), true).unwrap();
        update(
            &path,
            None,
            Some(&AuthFrom::Provider(Provider::Return("laptop".into()))),
            true,
        )
        .unwrap();
        assert!(linked.symlink_metadata().unwrap().file_type().is_symlink());
        assert_eq!(
            read(&target.join("auth-from.json"))
                .unwrap()
                .selected("backup")
                .unwrap(),
            AuthFrom::Ssh
        );
        assert_eq!(
            read(&path).unwrap().selected("other").unwrap(),
            AuthFrom::Provider(Provider::Return("laptop".into()))
        );

        let actual = target.join("saved.json");
        std::fs::rename(&path, &actual).unwrap();
        let original = std::fs::read(&actual).unwrap();
        let mut old_reader = std::fs::File::open(&actual).unwrap();
        std::os::unix::fs::symlink("saved.json", &path).unwrap();
        assert_eq!(
            read(&path).unwrap().selected("backup").unwrap(),
            AuthFrom::Ssh
        );
        update(&path, None, Some(&AuthFrom::Auto), true).unwrap();
        update(&path, Some("backup"), None, true).unwrap();
        assert_eq!(std::fs::read_link(&path).unwrap(), Path::new("saved.json"));
        assert_eq!(
            read(&actual).unwrap().selected("backup").unwrap(),
            AuthFrom::Auto
        );
        // Replacement is atomic: a reader of the old inode still sees the
        // complete old configuration, while the link now reads the new one.
        let mut old_contents = Vec::new();
        old_reader.read_to_end(&mut old_contents).unwrap();
        assert_eq!(old_contents, original);
    }

    #[test]
    fn linked_preferences_reject_missing_and_unsafe_targets_without_changing_them() {
        use std::os::unix::fs::PermissionsExt;
        let root = crate::test_support::tempdir().unwrap();
        let path = root.path().join("auth-from.json");
        let target = root.path().join("saved.json");
        std::os::unix::fs::symlink(&target, &path).unwrap();
        for error in [
            read(&path).err().unwrap(),
            update(&path, None, None, true).err().unwrap(),
        ] {
            assert!(format!("{error:#}").contains("the target must exist"));
        }
        assert!(!target.exists());
        std::fs::write(&target, b"{}").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(read(&path).is_err());
        assert!(update(&path, None, Some(&AuthFrom::Ssh), true).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"{}");
        assert_eq!(std::fs::read_link(&path).unwrap(), target);
    }

    #[test]
    fn concurrent_updates_through_different_links_preserve_all_overrides() {
        let root = crate::test_support::tempdir().unwrap();
        let target = root.path().join("saved.json");
        std::fs::write(&target, br#"{"version":1,"future":true}"#).unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let threads: Vec<_> = (0..8)
            .map(|index| {
                let directory = root.path().join(format!("config-{index}"));
                std::fs::create_dir(&directory).unwrap();
                let link = directory.join("auth-from.json");
                std::os::unix::fs::symlink(&target, &link).unwrap();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    update(
                        &link,
                        Some(&format!("host-{index}")),
                        Some(&AuthFrom::Ssh),
                        true,
                    )
                    .unwrap();
                    assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        let config = read(&target).unwrap();
        assert_eq!(config.hosts.len(), 8);
        assert!(config.hosts.values().all(|value| value == "ssh"));
        assert_eq!(config.extensions["future"], true);
        assert_eq!(config.version, Some(1));
    }

    #[test]
    fn saved_provider_error_context_preserves_typed_failure() {
        let mode = AuthFrom::Provider(Provider::Return("laptop".into()));
        let error = selected_context::<()>(
            Err(std::io::Error::from(std::io::ErrorKind::ConnectionRefused).into()),
            &mode,
            false,
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("provider @laptop comes from the saved"));
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::ConnectionRefused
        );
        let explicit =
            selected_context::<()>(Err(anyhow::anyhow!("original")), &mode, true).unwrap_err();
        assert_eq!(explicit.to_string(), "original");
    }

    #[test]
    fn update_directory_errors_name_the_preferences_file() {
        let root = crate::test_support::tempdir().unwrap();
        let parent = root.path().join("config");
        std::fs::write(&parent, "not a directory").unwrap();
        let path = parent.join("auth-from.json");
        let error = update(&path, None, Some(&AuthFrom::Ssh), true)
            .err()
            .unwrap();
        let detail = format!("{error:#}");
        assert!(detail.contains(path.to_str().unwrap()), "{detail}");
        assert_eq!(std::fs::read_to_string(parent).unwrap(), "not a directory");
    }
}

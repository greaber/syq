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

#[derive(clap::Args, Debug)]
pub(crate) struct PreferenceCommand {
    /// Authorization for later commands; omit to show saved defaults
    #[arg(value_name = "auto|ssh|@NAME", value_parser = crate::cli::parse_auth_from)]
    value: Option<AuthFrom>,
    /// Apply to this exact destination hostname or SSH alias, for any login/port
    #[arg(long = "for", value_name = "HOST", value_parser = host_key)]
    host: Option<String>,
    /// Remove the selected override so it inherits the default
    #[arg(long, conflicts_with = "value")]
    reset: bool,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    default: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    hosts: BTreeMap<String, String>,
}
impl Config {
    fn validate(&self) -> Result<()> {
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
        AuthFrom::Return(name) => format!("@{name}"),
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
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
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
    let path = path(domain)?;
    read(&path).with_context(|| {
        format!(
        "read saved authorization choice from {}; repair this file or pass --auth-from explicitly",
        path.display(),
    )
    })
}

/// Explicit flags bypass disk reads, including `auto`. Preference lookup uses
/// the typed hostname/alias, without an SSH connection or config expansion.
pub(crate) fn resolve(domain: &Domain, host: &str, explicit: Option<AuthFrom>) -> Result<AuthFrom> {
    if let Some(choice) = explicit {
        return Ok(choice);
    }
    load(domain)?.selected(host)
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
    let parent = path
        .parent()
        .context("authorization configuration parent missing")?;
    if create_parent {
        std::fs::create_dir_all(parent).context("create authorization configuration directory")?;
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent).with_context(|| format!("open authorization configuration directory {}; use a real directory, not a symlink", parent.display()))?;
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
    let mut config = read(path)?;
    match (host, value) {
        (None, value) => config.default = value.map(spelling),
        (Some(host), Some(value)) => {
            config.hosts.insert(host.into(), spelling(value));
        }
        (Some(host), None) => {
            config.hosts.remove(host);
        }
    }
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer_pretty(&mut temporary, &config)?;
    temporary.write_all(b"\n")?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(path)
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
    fn host_override_and_reset_preserve_other_preferences() {
        let root = crate::test_support::tempdir().unwrap();
        let path = root.path().join("auth-from.json");
        assert_eq!(
            read(&path).unwrap().selected("backup").unwrap(),
            AuthFrom::Auto
        );
        update(&path, None, Some(&AuthFrom::Return("laptop".into())), true).unwrap();
        let config = update(&path, Some("backup"), Some(&AuthFrom::Ssh), true).unwrap();
        assert_eq!(config.selected("backup").unwrap(), AuthFrom::Ssh);
        assert_eq!(
            config.selected("Backup").unwrap(),
            AuthFrom::Return("laptop".into())
        );
        let config = update(&path, Some("backup"), Some(&AuthFrom::Auto), true).unwrap();
        assert_eq!(config.selected("backup").unwrap(), AuthFrom::Auto);
        let config = update(&path, Some("backup"), None, true).unwrap();
        assert_eq!(
            config.selected("backup").unwrap(),
            AuthFrom::Return("laptop".into())
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
            r#"{"default":"laptop"}"#,
            r#"{"hosts":{"user@host":"ssh"}}"#,
            r#"{"future":true}"#,
        ] {
            std::fs::write(&path, data).unwrap();
            assert!(update(&path, None, Some(&AuthFrom::Auto), true).is_err());
            assert_eq!(std::fs::read_to_string(&path).unwrap(), data);
        }
    }
}

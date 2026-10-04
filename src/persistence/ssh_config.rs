//! A snapshot for native SSH tools, bound to one approved account's live socket.
use crate::cli::{AuthFrom, NativeEndpoint};
use crate::process::CommandExt as _;
use anyhow::{bail, ensure, Context, Result};
use clap::Args;
use std::fs;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Args, Debug)]
pub(crate) struct ExportCommand {
    /// Approved SSH endpoint: [USER@]HOST[:PORT]
    host: String,
    /// Select existing approval; omitted uses the saved preference, then auto
    #[arg(long, value_name = "auto|ssh|@NAME|HOST", value_parser = crate::cli::parse_auth_from)]
    auth_from: Option<AuthFrom>,
}

pub(crate) fn run(domain: &super::Domain, command: ExportCommand) -> Result<i32> {
    let requested = crate::cli::parse_native_endpoint(Some(&command.host))?
        .context("SSH destination is missing")?;
    crate::destination::ssh::validate_endpoint(&requested)?;
    let mode = crate::auth_from::resolve(domain, &requested.host, command.auth_from)?;
    ensure!(mode != AuthFrom::Ssh,
        "ssh-config exports approved account connections; select an authorization provider instead of native SSH authorization");
    let cached = crate::destination::ssh::persistent::select_export(domain, &requested, &mode)?
        .context("no approved account connection matches; first run syq ssh HOST --auth-from PROVIDER (ssh-config never opens a connection)")?;
    let config = export(&requested, cached.endpoint(), cached.control())?;
    std::io::stdout().lock().write_all(config.as_bytes())?;
    Ok(0)
}

fn export(requested: &NativeEndpoint, endpoint: &NativeEndpoint, control: &Path) -> Result<String> {
    crate::destination::ssh::validate_endpoint(requested)?;
    crate::destination::ssh::validate_endpoint(endpoint)?;
    let scope = control
        .parent()
        .context("approved SSH socket has no scope")?;
    super::validate_scope(scope)?;
    // %C includes the remote host, account and port. A literal ControlPath would
    // silently reuse the approved account even after a caller changed -l or -p.
    // Ask the installed OpenSSH to expand its own token instead of copying its
    // hash algorithm. Use just its full hash to leave room under Unix socket
    // path limits. The alias is removed with its master's ephemeral scope.
    let pattern = alias_pattern(scope)?;
    let config = render(requested, endpoint, &pattern)?;
    let alias = expanded_control(&pattern, endpoint)?;
    ensure!(
        alias.parent() == Some(scope)
            && alias.file_name().is_some_and(|name| {
                name.as_bytes().len() == 40 && name.as_bytes().iter().all(u8::is_ascii_hexdigit)
            }),
        "OpenSSH expanded its control path outside the approved scope"
    );
    super::validate_openssh_control_path(&alias)?;
    let address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    ensure!(
        alias.as_os_str().len() < address.sun_path.len(),
        "exported SSH socket path is too long; use a shorter XDG_RUNTIME_DIR"
    );
    let target = control
        .file_name()
        .context("approved SSH socket has no filename")?;
    match std::os::unix::fs::symlink(target, &alias) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            ensure!(
                fs::read_link(&alias)? == Path::new(target),
                "exported SSH socket alias does not match the approved connection"
            );
        }
        Err(error) => return Err(error).context("create exported SSH socket alias"),
    }
    Ok(config)
}

fn alias_pattern(scope: &Path) -> Result<String> {
    Ok(format!(
        "{}/%C",
        super::openssh_control_path(scope)
            .to_str()
            .context("SSH config export requires a UTF-8 persistence path")?
    ))
}

fn expanded_control(pattern: &str, endpoint: &NativeEndpoint) -> Result<PathBuf> {
    let mut command = Command::new("ssh");
    command
        .args(["-G", "-T", "-F", "/dev/null", "-o", "ProxyJump=none"])
        .args(["-S", pattern]);
    if let Some(user) = &endpoint.user {
        command.args(["-l", user]);
    }
    command.args([
        "-p",
        &endpoint.port.unwrap_or(22).to_string(),
        "--",
        &endpoint.host,
    ]);
    let output = command
        .capture_output()
        .context("inspect native OpenSSH control path")?;
    ensure!(
        output.status.success(),
        "native OpenSSH could not expand the exported control path: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let text = std::str::from_utf8(&output.stdout).context("OpenSSH configuration is not UTF-8")?;
    let value = text
        .lines()
        .find_map(|line| line.strip_prefix("controlpath "))
        .context("native OpenSSH did not return a control path")?;
    Ok(PathBuf::from(value))
}

fn quote(value: &str) -> Result<String> {
    if value.bytes().any(|b| matches!(b, 0 | b'\n' | b'\r')) {
        bail!("SSH configuration values must fit on one line");
    }
    Ok(format!(
        "\"{}\"",
        value.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

fn render(requested: &NativeEndpoint, endpoint: &NativeEndpoint, pattern: &str) -> Result<String> {
    let user = endpoint
        .user
        .as_deref()
        .context("approved SSH account has no resolved login")?;
    Ok(format!(
        "# Snapshot of one approved account login. Export again after reconnecting.\n\
         # Use with ssh/scp/sftp -F FILE, or Git/rsync's SSH command option.\n\
         Host *\n\
             ControlMaster no\n\
             ProxyCommand false\n\
             ProxyJump none\n\
             PubkeyAuthentication no\n\
             PasswordAuthentication no\n\
             KbdInteractiveAuthentication no\n\
             GSSAPIAuthentication no\n\
             HostbasedAuthentication no\n\
             ForwardAgent no\n\
             ForwardX11 no\n\
             ClearAllForwardings yes\n\
             PermitLocalCommand no\n\
         Host {}\n\
             HostName {}\n\
             User {}\n\
             Port {}\n\
             ControlPath {}\n",
        quote(&requested.host)?,
        quote(&endpoint.host)?,
        quote(user)?,
        endpoint.port.unwrap_or(22),
        quote(pattern)?
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint() -> NativeEndpoint {
        NativeEndpoint {
            user: Some("approved-user".into()),
            host: "example.invalid".into(),
            port: Some(2222),
        }
    }

    #[test]
    fn scoped_export_alias_fits_default_darwin_and_large_linux_uid_paths() {
        for (scope, capacity) in [
            (
                "/private/tmp/syq-persist-501/domain-ABCDEF/approved-ABCDEF",
                104,
            ),
            (
                "/run/user/10000/syq-persist-10000/domain-ABCDEF/approved-ABCDEF",
                108,
            ),
        ] {
            let scope = Path::new(scope);
            let pattern = alias_pattern(scope).unwrap();
            let alias = expanded_control(&pattern, &endpoint()).unwrap();
            assert_eq!(alias.parent(), Some(scope));
            assert_eq!(alias.file_name().unwrap().as_bytes().len(), 40);
            assert!(alias.as_os_str().len() < capacity, "{}", alias.display());
            let mut other = endpoint();
            other.user = Some("other-account".into());
            assert_ne!(expanded_control(&pattern, &other).unwrap(), alias);
        }
    }

    #[test]
    fn native_control_hash_binds_the_host_account_and_port() {
        let pattern = "/tmp/syq-export-test/tool-%C";
        let endpoint = endpoint();
        let original = expanded_control(pattern, &endpoint).unwrap();
        assert!(!original.to_string_lossy().contains('%'));
        for changed in [
            NativeEndpoint {
                host: "other.invalid".into(),
                ..endpoint.clone()
            },
            NativeEndpoint {
                user: Some("other-user".into()),
                ..endpoint.clone()
            },
            NativeEndpoint {
                port: Some(2223),
                ..endpoint.clone()
            },
        ] {
            assert_ne!(original, expanded_control(pattern, &changed).unwrap());
        }
    }

    #[test]
    fn native_config_keeps_overridden_endpoints_away_from_the_socket() {
        let temporary = crate::test_support::tempdir().unwrap();
        let config = temporary.path().join("config");
        let endpoint = endpoint();
        let requested = NativeEndpoint {
            user: None,
            host: "alias".into(),
            port: None,
        };
        let pattern = "/tmp/syq-export-test/tool-%C";
        fs::write(&config, render(&requested, &endpoint, pattern).unwrap()).unwrap();
        let expected = expanded_control(pattern, &endpoint).unwrap();
        for (options, matches) in [
            (vec![], true),
            (vec!["-l", "other-user"], false),
            (vec!["-p", "2223"], false),
            (vec!["-o", "HostName=other.invalid"], false),
        ] {
            let output = Command::new("ssh")
                .args(["-G", "-T", "-F"])
                .arg(&config)
                .args(options)
                .arg("alias")
                .capture_output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let text = String::from_utf8(output.stdout).unwrap();
            let actual = text
                .lines()
                .find_map(|line| line.strip_prefix("controlpath "))
                .unwrap();
            assert_eq!(Path::new(actual) == expected, matches, "{text}");
            assert!(text.lines().any(|line| line == "proxycommand false"));
        }
        let output = Command::new("ssh")
            .args(["-G", "-T", "-F"])
            .arg(&config)
            .arg("other.invalid")
            .capture_output()
            .unwrap();
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(!text.lines().any(|line| line.starts_with("controlpath ")));
        assert!(text.lines().any(|line| line == "proxycommand false"));
    }

    #[test]
    fn exported_values_reject_newlines_and_preserve_quoted_path_characters() {
        assert!(quote("bad\nHost *").is_err());
        assert!(quote("bad\rHost *").is_err());
        let pattern = "/tmp/path with space/quote\"back\\slash/%%value-%C";
        let endpoint = endpoint();
        let temporary = crate::test_support::tempdir().unwrap();
        let config = temporary.path().join("config");
        fs::write(&config, render(&endpoint, &endpoint, pattern).unwrap()).unwrap();
        let output = Command::new("ssh")
            .args(["-G", "-T", "-F"])
            .arg(&config)
            .arg(&endpoint.host)
            .capture_output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = String::from_utf8(output.stdout).unwrap();
        let value = text
            .lines()
            .find_map(|line| line.strip_prefix("controlpath "))
            .unwrap();
        assert!(
            value.starts_with("/tmp/path with space/quote\"back\\slash/%value-"),
            "{value}"
        );
    }
}

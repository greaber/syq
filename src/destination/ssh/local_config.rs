//! The requester owns SSH configuration and routes. Approval owns only the
//! destination account and trusted host keys.
use super::{foreground, validate_endpoint};
use crate::cli::NativeEndpoint;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::process::Command;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

const LIMIT: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LocalPlan {
    pub(crate) requested: NativeEndpoint,
    pub(crate) endpoint: NativeEndpoint,
    pub(crate) host_key_alias: Option<String>,
    pub(crate) config_digest: String,
    pub(crate) route: Route,
    #[serde(default)]
    pub(crate) host_key_algorithms: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) hop: Option<Box<LocalPlan>>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Route {
    Direct,
    Command(String),
    Jump(Vec<NativeEndpoint>),
}

impl LocalPlan {
    pub(crate) fn resolve(requested: &NativeEndpoint) -> Result<Self> {
        Self::resolve_bounded(requested, Duration::from_secs(30))
    }
    pub(super) fn resolve_bounded(requested: &NativeEndpoint, timeout: Duration) -> Result<Self> {
        let signals = foreground::Signals::new()?;
        Self::resolve_inner(
            requested,
            &[],
            &mut Vec::new(),
            Instant::now() + timeout,
            &|| signals.received.load(Ordering::Acquire) != 0,
        )
    }
    fn resolve_inner(
        requested: &NativeEndpoint,
        forced: &[NativeEndpoint],
        visited: &mut Vec<NativeEndpoint>,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Self> {
        validate_endpoint(requested)?;
        anyhow::ensure!(
            visited.len() < 16 && !visited.contains(requested),
            "ProxyJump configuration contains a cycle or exceeds 16 hops"
        );
        visited.push(requested.clone());
        let mut command = Command::new("ssh");
        command.arg("-G").env("LC_ALL", "C");
        if let Some(user) = &requested.user {
            command.args(["-l", user]);
        }
        if let Some(port) = requested.port {
            command.args(["-p", &port.to_string()]);
        }
        if !forced.is_empty() {
            command.args([
                "-J",
                &forced.iter().map(jump_label).collect::<Vec<_>>().join(","),
            ]);
        }
        command.args(["--", &requested.host]);
        let output =
            crate::process::capture_output_bounded(&mut command, deadline, cancelled, LIMIT)
                .context("resolve SSH configuration on the requesting machine")?;
        anyhow::ensure!(
            output.status.success(),
            "could not resolve local SSH configuration: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut plan = Self::parse(requested, &output.stdout)?;
        if let Route::Jump(chain) = &plan.route {
            let (last, previous) = chain.split_last().context("empty ProxyJump chain")?;
            let hop = Self::resolve_inner(last, previous, visited, deadline, cancelled)?;
            plan.config_digest = blake3::hash(&serde_json::to_vec(&(
                &plan.config_digest,
                &hop.config_digest,
            ))?)
            .to_hex()
            .to_string();
            plan.hop = Some(Box::new(hop));
        }
        visited.pop();
        Ok(plan)
    }

    fn parse(requested: &NativeEndpoint, output: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(output).context("local ssh -G output is not UTF-8")?;
        let value = |name: &str| -> Option<&str> {
            text.lines().find_map(|line| {
                line.strip_prefix(name)
                    .and_then(|rest| rest.strip_prefix(' '))
            })
        };
        let endpoint = NativeEndpoint {
            user: Some(value("user").context("local ssh -G omitted User")?.into()),
            host: value("hostname")
                .context("local ssh -G omitted HostName")?
                .into(),
            port: Some(
                value("port")
                    .context("local ssh -G omitted Port")?
                    .parse()?,
            ),
        };
        validate_endpoint(&endpoint)?;
        let host_key_alias = value("hostkeyalias")
            .filter(|value| *value != "none")
            .map(str::to_owned);
        let route = if let Some(jumps) = value("proxyjump").filter(|value| *value != "none") {
            let jumps = jumps
                .split(',')
                .map(|jump| {
                    let jump = jump.strip_prefix("ssh://").unwrap_or(jump);
                    let endpoint = crate::cli::parse_native_endpoint(Some(jump))?
                        .context("empty ProxyJump endpoint")?;
                    validate_endpoint(&endpoint)?;
                    Ok(endpoint)
                })
                .collect::<Result<Vec<_>>>()?;
            anyhow::ensure!(jumps.len() <= 16, "ProxyJump has too many hops");
            Route::Jump(jumps)
        } else if let Some(command) = value("proxycommand").filter(|value| *value != "none") {
            Route::Command(command.into())
        } else {
            Route::Direct
        };
        let plan = Self {
            requested: requested.clone(),
            endpoint,
            host_key_alias,
            config_digest: blake3::hash(output).to_hex().to_string(),
            route,
            host_key_algorithms: value("hostkeyalgorithms").unwrap_or_default().into(),
            hop: None,
        };
        plan.validate()?;
        Ok(plan)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.validate_at(0)
    }
    fn validate_at(&self, depth: usize) -> Result<()> {
        anyhow::ensure!(depth < 16, "ProxyJump chain is too deep");
        validate_endpoint(&self.requested)?;
        validate_endpoint(&self.endpoint)?;
        anyhow::ensure!(
            self.endpoint.user.is_some() && self.endpoint.port.is_some(),
            "local SSH plan lacks its resolved account or port"
        );
        if let Some(alias) = &self.host_key_alias {
            super::validate_host_key_alias(alias)?;
        }
        anyhow::ensure!(
            self.config_digest.len() == 64
                && self
                    .config_digest
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit()),
            "invalid local SSH configuration identity"
        );
        match &self.route {
            Route::Jump(jumps) => {
                anyhow::ensure!(
                    !jumps.is_empty() && jumps.len() <= 16,
                    "invalid ProxyJump chain"
                );
                for jump in jumps {
                    validate_endpoint(jump)?;
                }
            }
            Route::Command(command) => anyhow::ensure!(
                command.len() <= LIMIT && !command.contains('\0'),
                "invalid ProxyCommand"
            ),
            Route::Direct => {}
        }
        if let Some(hop) = &self.hop {
            hop.validate_at(depth + 1)?;
        }
        Ok(())
    }

    pub(crate) fn intersect_host_algorithms(&self, approved: &str) -> Result<String> {
        let allowed = approved.split(',').collect::<Vec<_>>();
        let algorithms = self
            .host_key_algorithms
            .split(',')
            .filter(|algorithm| allowed.contains(algorithm))
            .collect::<Vec<_>>()
            .join(",");
        anyhow::ensure!(
            !algorithms.is_empty(),
            "requester and authorization provider allow no common trusted host-key algorithm"
        );
        Ok(algorithms)
    }

    /// Pin selected account/address while retaining original Host matching and
    /// all ordinary local IdentityFile/CertificateFile/IdentitiesOnly settings.
    pub(super) fn options(&self) -> Vec<OsString> {
        vec![
            "-o".into(),
            format!("HostName={}", self.endpoint.host).into(),
            "-l".into(),
            self.endpoint.user.as_ref().unwrap().into(),
            "-p".into(),
            self.endpoint.port.unwrap().to_string().into(),
        ]
    }
    pub(super) fn route_options(&self, jump_proxy: Option<&str>) -> Result<Vec<OsString>> {
        let proxy = match &self.route {
            Route::Direct => "none",
            Route::Command(command) => command,
            Route::Jump(_) => jump_proxy.context("ProxyJump account connection is missing")?,
        };
        Ok(vec![
            "-o".into(),
            "ProxyJump=none".into(),
            "-o".into(),
            format!("ProxyCommand={proxy}").into(),
        ])
    }
}

fn jump_label(endpoint: &NativeEndpoint) -> String {
    let mut value = endpoint
        .user
        .as_ref()
        .map(|user| format!("{user}@"))
        .unwrap_or_default();
    if endpoint.host.contains(':') {
        value.push_str(&format!("[{}]", endpoint.host));
    } else {
        value.push_str(&endpoint.host);
    }
    if let Some(port) = endpoint.port {
        value.push_str(&format!(":{port}"));
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::CommandExt as _;

    fn requested() -> NativeEndpoint {
        NativeEndpoint {
            user: None,
            host: "alias".into(),
            port: None,
        }
    }

    #[test]
    fn effective_account_route_and_identity_changes_invalidate_local_selection() {
        let config = "user alice\nhostname private.invalid\nport 2200\nhostkeyalias trusted\nhostkeyalgorithms ssh-ed25519,rsa-sha2-512\nidentityfile /tmp/public-key.pub\nidentitiesonly yes\nproxycommand nc %h %p\n";
        let plan = LocalPlan::parse(&requested(), config.as_bytes()).unwrap();
        assert_eq!(plan.requested, requested());
        assert_eq!(plan.endpoint.user.as_deref(), Some("alice"));
        assert_eq!(plan.endpoint.host, "private.invalid");
        assert_eq!(plan.endpoint.port, Some(2200));
        assert_eq!(plan.host_key_alias.as_deref(), Some("trusted"));
        assert_eq!(plan.route, Route::Command("nc %h %p".into()));
        for (from, to) in [
            ("alice", "bob"),
            ("private.invalid", "other.invalid"),
            ("2200", "2201"),
            ("public-key.pub", "other-key.pub"),
            ("identitiesonly yes", "identitiesonly no"),
            ("nc %h %p", "other-proxy %h %p"),
        ] {
            let changed =
                LocalPlan::parse(&requested(), config.replace(from, to).as_bytes()).unwrap();
            assert_ne!(plan.config_digest, changed.config_digest, "{from}");
        }
        assert_eq!(
            plan.intersect_host_algorithms("rsa-sha2-256,rsa-sha2-512,ssh-ed25519")
                .unwrap(),
            "ssh-ed25519,rsa-sha2-512"
        );
        assert!(plan
            .intersect_host_algorithms("ecdsa-sha2-nistp256")
            .is_err());
        let route = plan.route_options(None).unwrap();
        assert!(route.contains(&OsString::from("ProxyCommand=nc %h %p")));
        assert!(!route
            .iter()
            .any(|option| option.to_string_lossy().contains("IdentityAgent")));
    }

    #[test]
    fn native_config_keeps_public_identity_selection_and_original_host_matching() {
        let root = crate::test_support::tempdir().unwrap();
        let config = root.path().join("config");
        std::fs::write(&config, "Host alias\n HostName private.invalid\n HostKeyAlias [stable-server]:2200\n User alice\n Port 2200\n IdentityFile /tmp/selected-public-key.pub\n CertificateFile /tmp/selected-cert.pub\n IdentitiesOnly yes\n RemoteCommand printf configured\n RequestTTY force\n ProxyJump jump1,second@jump2:2202\n").unwrap();
        let mut query = Command::new("ssh");
        query.args(["-G", "-F"]).arg(&config).arg("alias");
        let output = query.capture_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let plan = LocalPlan::parse(&requested(), &output.stdout).unwrap();
        assert_eq!(plan.host_key_alias.as_deref(), Some("[stable-server]:2200"));
        let Route::Jump(hops) = &plan.route else {
            panic!("ProxyJump was lost");
        };
        assert_eq!(hops.len(), 2);
        assert_eq!(hops[1].user.as_deref(), Some("second"));
        assert_eq!(hops[1].port, Some(2202));
        let mut query = Command::new("ssh");
        query
            .args(["-G", "-F"])
            .arg(&config)
            .args(plan.options())
            .arg("alias");
        let output = query.capture_output().unwrap();
        assert!(output.status.success());
        let effective = String::from_utf8(output.stdout).unwrap();
        for expected in [
            "hostname private.invalid",
            "hostkeyalias [stable-server]:2200",
            "user alice",
            "port 2200",
            "identityfile /tmp/selected-public-key.pub",
            "certificatefile /tmp/selected-cert.pub",
            "identitiesonly yes",
            "remotecommand printf configured",
            "requesttty force",
        ] {
            assert!(
                effective.lines().any(|line| line == expected),
                "missing {expected}: {effective}"
            );
        }
    }
}

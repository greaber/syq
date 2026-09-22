//! A fail-closed SSH-agent proxy for native remote-to-remote transfers.
//!
//! The default mode exposes only the transfer's enrollment key. Native
//! `--peer-auth broker` instead advertises supported ambient-agent identities,
//! while applying the same signature restrictions. OpenSSH's session-bind
//! messages prove the coordinator and peer sessions, and the host-bound
//! userauth request binds each signature to the peer host key and login
//! user.

use crate::private_broker::{
    ConnectionRegistry, PrivateBroker, PrivateBrokerConfig, TrackedStream,
};
use crate::process::CommandExt as _;
use anyhow::{anyhow, bail, Context, Result};
use signature::{Signer, Verifier};
use ssh_agent_lib::proto::extension::{MessageExtension, SessionBind};
use ssh_agent_lib::proto::{Extension, Identity, PublicCredential, Request, Response, SignRequest};
use ssh_agent_lib::ssh_encoding::{Decode, Encode};
use ssh_agent_lib::ssh_key::{public::KeyData, Algorithm, PrivateKey, PublicKey};
use std::ffi::{CStr, OsString};
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::FileTypeExt;
#[cfg(test)]
use std::os::unix::fs::PermissionsExt;
#[cfg(test)]
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
#[cfg(test)]
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// Agent messages are normally only a few KiB. This accommodates large
/// identity lists without allowing a peer to force an unbounded allocation.
const MAX_AGENT_FRAME: usize = 256 * 1024;
/// Bound stalled forwarded clients while leaving enough time for SSH setup.
const BROKER_IO_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_SSH_CONFIG_FILES: usize = 256;
const MAX_SSH_CONFIG_BYTES: usize = 1024 * 1024;
const SSH_AGENT_FAILURE: &[u8] = &[5];
const SSH_AGENT_SUCCESS: &[u8] = &[6];
const SSH_AGENT_EXTENSION_FAILURE: &[u8] = &[28];

#[derive(Clone, Debug)]
pub struct HostPolicy {
    pub login_user: String,
    connection_host: String,
    port: u16,
    host_keys: Vec<KeyData>,
    known_hosts_name: String,
    host_key_algorithms: Vec<String>,
    required_rsa_size: usize,
}

impl HostPolicy {
    pub(crate) fn connection_host(&self) -> &str {
        &self.connection_host
    }

    pub(crate) fn port(&self) -> u16 {
        self.port
    }

    pub(crate) fn host_key_algorithms(&self) -> String {
        self.host_key_algorithms.join(",")
    }

    fn authorizes_binding(&self, binding: &SessionBind) -> bool {
        key_is_cryptographically_verifiable(&binding.host_key)
            && signature_algorithm_is_cryptographically_verifiable(&binding.signature.algorithm())
            && self.host_keys.contains(&binding.host_key)
            && self
                .host_key_algorithms
                .iter()
                .any(|allowed| allowed == binding.signature.algorithm().as_str())
            && binding.host_key.rsa().is_none_or(|rsa| {
                rsa.n.as_positive_bytes().is_some_and(|modulus| {
                    let bits = modulus
                        .first()
                        .map(|first| modulus.len() * 8 - first.leading_zeros() as usize)
                        .unwrap_or(0);
                    bits >= self.required_rsa_size
                })
            })
    }
}

#[derive(Clone, Debug)]
pub struct BrokerPolicy {
    coordinator: HostPolicy,
    peer: HostPolicy,
}

impl BrokerPolicy {
    pub fn new(coordinator: HostPolicy, peer: HostPolicy) -> Self {
        Self { coordinator, peer }
    }
}

/// Resolve the effective user and exact, already trusted plain host keys using
/// the caller's OpenSSH configuration and known_hosts files. Host certificates
/// are deliberately rejected for now: treating a CA key as the presented host
/// key would silently weaken the name/principal checks OpenSSH performs.
pub fn resolve_host_policy(
    ssh_program: &str,
    explicit_user: Option<&str>,
    host: &str,
) -> Result<HostPolicy> {
    resolve_host_policy_at(ssh_program, explicit_user, host, None)
}

/// Resolve host policy after applying an explicit endpoint port. Keeping the
/// port in the OpenSSH query makes the actual connection, known-host lookup,
/// broker binding, and enrollment route describe the same endpoint.
pub fn resolve_host_policy_at(
    ssh_program: &str,
    explicit_user: Option<&str>,
    host: &str,
    explicit_port: Option<u16>,
) -> Result<HostPolicy> {
    let inspection =
        inspect_ssh_configuration_at(ssh_program, explicit_user, host, explicit_port, false)?;
    let defaults =
        inspect_ssh_configuration_at(ssh_program, explicit_user, host, explicit_port, true)?;
    let defaults = KnownHostsDefaults::from_openssh(&defaults.output)?;
    let config = parse_ssh_config_with_defaults(
        &inspection.output,
        Some(&defaults),
        &inspection.known_hosts_configured,
    )
    .with_context(|| format!("parse `ssh -G` output for {host}"))?;
    let keygen = ssh_keygen_for(ssh_program);
    let (mut host_keys, saw_ca) = read_known_host_keys(&keygen, &config.lookup, &config.files)?;
    host_keys.retain(|key| configured_host_key_allowed(&config, key));
    if host_keys.is_empty() {
        if saw_ca {
            bail!(
                "{host} is trusted only through an SSH host certificate; constrained agent forwarding currently requires an exact plain host key in known_hosts"
            );
        }
        bail!(
            "no exact trusted host key for {host} ({}) allowed by HostKeyAlgorithms and RequiredRSASize and supported by syq's cryptographic verifier was found in the configured known_hosts files; connect once with ssh to record it before retrying the direct transfer",
            config.lookup
        );
    }
    Ok(HostPolicy {
        login_user: config.user,
        connection_host: config.hostname,
        port: config.port,
        host_keys,
        known_hosts_name: config.lookup,
        host_key_algorithms: config.host_key_algorithms,
        required_rsa_size: config.required_rsa_size,
    })
}

struct SshConfigurationInspection {
    output: Vec<u8>,
    known_hosts_configured: KnownHostsConfigured,
}

#[cfg(test)]
fn inspect_ssh_configuration(
    ssh_program: &str,
    explicit_user: Option<&str>,
    host: &str,
    compiled_defaults_only: bool,
) -> Result<SshConfigurationInspection> {
    inspect_ssh_configuration_at(
        ssh_program,
        explicit_user,
        host,
        None,
        compiled_defaults_only,
    )
}

fn inspect_ssh_configuration_at(
    ssh_program: &str,
    explicit_user: Option<&str>,
    host: &str,
    explicit_port: Option<u16>,
    compiled_defaults_only: bool,
) -> Result<SshConfigurationInspection> {
    let mut command = Command::new(ssh_program);
    command.args(["-G", "-vvv"]);
    if compiled_defaults_only {
        command.args(["-F", "/dev/null"]);
    }
    if let Some(user) = explicit_user {
        command.args(["-l", user]);
    }
    if let Some(port) = explicit_port {
        command.args(["-p", &port.to_string()]);
    }
    command.args(["--", host]).env("LC_ALL", "C");
    let output = command
        .capture_output()
        .with_context(|| format!("inspect SSH configuration for {host}"))?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
        bail!(
            "could not inspect SSH configuration for {host}{}",
            if detail.is_empty() {
                String::new()
            } else {
                format!(": {detail}")
            }
        );
    }
    // OpenSSH does not retain filename quoting in `ssh -G` output. Its debug
    // stream identifies the configuration files that contributed to this
    // query, which lets us distinguish compiled defaults from an explicitly
    // configured value that happens to render identically. Requiring the
    // controlled query to name /dev/null also validates that this OpenSSH's
    // debug format is one we can use as provenance.
    let configuration_paths = ssh_configuration_paths(&output.stderr)?;
    let known_hosts_configured = if compiled_defaults_only {
        if configuration_paths != [PathBuf::from("/dev/null")] {
            bail!(
                "OpenSSH did not report /dev/null as the sole configuration source for the compiled-default query"
            );
        }
        KnownHostsConfigured::default()
    } else {
        configured_known_hosts_directives(&configuration_paths)?
    };
    Ok(SshConfigurationInspection {
        output: output.stdout,
        known_hosts_configured,
    })
}

#[derive(Clone, Copy, Debug, Default)]
struct KnownHostsConfigured {
    user: bool,
    global: bool,
}

fn ssh_configuration_paths(debug: &[u8]) -> Result<Vec<PathBuf>> {
    const PREFIX: &str = "debug1: Reading configuration data ";
    let debug = std::str::from_utf8(debug).context("OpenSSH debug output was not UTF-8")?;
    let mut paths = Vec::new();
    for line in debug.lines() {
        let Some(path) = line.strip_prefix(PREFIX) else {
            continue;
        };
        let path = PathBuf::from(path);
        if !path.is_absolute() {
            bail!(
                "OpenSSH reported a non-absolute configuration path while resolving known_hosts provenance"
            );
        }
        if !paths.contains(&path) {
            if paths.len() == MAX_SSH_CONFIG_FILES {
                bail!(
                    "OpenSSH read too many configuration files to establish known_hosts provenance"
                );
            }
            paths.push(path);
        }
    }
    Ok(paths)
}

fn configured_known_hosts_directives(paths: &[PathBuf]) -> Result<KnownHostsConfigured> {
    let mut configured = KnownHostsConfigured::default();
    for path in paths {
        let mut file = fs::File::open(path)
            .with_context(|| format!("open SSH configuration file {}", path.display()))?;
        let metadata = file
            .metadata()
            .with_context(|| format!("inspect SSH configuration file {}", path.display()))?;
        if !metadata.is_file() || metadata.len() > MAX_SSH_CONFIG_BYTES as u64 {
            bail!(
                "SSH configuration file {} is not a bounded regular file; constrained agent forwarding cannot establish known_hosts provenance",
                path.display()
            );
        }
        let mut contents = Vec::new();
        Read::by_ref(&mut file)
            .take(MAX_SSH_CONFIG_BYTES as u64 + 1)
            .read_to_end(&mut contents)
            .with_context(|| format!("read SSH configuration file {}", path.display()))?;
        if contents.len() > MAX_SSH_CONFIG_BYTES {
            bail!(
                "SSH configuration file {} grew beyond the provenance size limit",
                path.display()
            );
        }
        configured.user |= contains_ssh_config_directive(&contents, b"userknownhostsfile");
        configured.global |= contains_ssh_config_directive(&contents, b"globalknownhostsfile");
    }
    Ok(configured)
}

fn contains_ssh_config_directive(contents: &[u8], keyword: &[u8]) -> bool {
    contents.split(|byte| *byte == b'\n').any(|line| {
        let line = line.trim_ascii_start();
        if line.is_empty() || line[0] == b'#' {
            return false;
        }
        let end = line
            .iter()
            .position(|byte| byte.is_ascii_whitespace() || *byte == b'=')
            .unwrap_or(line.len());
        line[..end].eq_ignore_ascii_case(keyword)
    })
}

#[derive(Debug)]
struct EffectiveSshConfig {
    user: String,
    hostname: String,
    port: u16,
    lookup: String,
    files: Vec<PathBuf>,
    host_key_algorithms: Vec<String>,
    required_rsa_size: usize,
}

#[derive(Debug)]
struct KnownHostsDefault {
    rendered: String,
    files: Vec<PathBuf>,
}

#[derive(Debug)]
struct KnownHostsDefaults {
    user: KnownHostsDefault,
    global: KnownHostsDefault,
}

impl KnownHostsDefaults {
    fn from_openssh(output: &[u8]) -> Result<Self> {
        let (user, global) = known_hosts_values(output)?;
        let account = local_account()?;
        let user_files = [
            PathBuf::from(&account.home).join(".ssh/known_hosts"),
            PathBuf::from(&account.home).join(".ssh/known_hosts2"),
        ];
        let expected_user = user_files
            .iter()
            .map(|path| path.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ");
        if user != expected_user {
            bail!(
                "OpenSSH reported unfamiliar compiled UserKnownHostsFile defaults; constrained agent forwarding cannot recover their filename boundaries"
            );
        }
        let global_files = parse_compiled_global_known_hosts(&global)?;
        Ok(Self {
            user: KnownHostsDefault {
                rendered: user,
                files: user_files.into_iter().collect(),
            },
            global: KnownHostsDefault {
                rendered: global,
                files: global_files,
            },
        })
    }
}

#[cfg(test)]
fn parse_ssh_config(output: &[u8]) -> Result<EffectiveSshConfig> {
    parse_ssh_config_with_defaults(output, None, &KnownHostsConfigured::default())
}

fn parse_ssh_config_with_defaults(
    output: &[u8],
    defaults: Option<&KnownHostsDefaults>,
    configured: &KnownHostsConfigured,
) -> Result<EffectiveSshConfig> {
    let output = std::str::from_utf8(output).context("SSH configuration was not UTF-8")?;
    let mut user = None;
    let mut hostname = None;
    let mut port = None;
    let mut hostkey_alias = None;
    let mut files = Vec::new();
    let mut host_key_algorithms = None;
    let mut required_rsa_size = None;
    for line in output.lines() {
        let Some((name, value)) = line.split_once(' ') else {
            continue;
        };
        let value = value.trim();
        match name {
            "user" => user = Some(value.to_string()),
            "hostname" => hostname = Some(value.to_string()),
            "port" => port = Some(value.parse::<u16>().context("invalid SSH port")?),
            "hostkeyalias" if value != "none" => hostkey_alias = Some(value.to_string()),
            "hostkeyalgorithms" => {
                let algorithms: Vec<_> = value
                    .split(',')
                    .filter(|algorithm| !algorithm.is_empty())
                    .map(str::to_string)
                    .collect();
                if algorithms.is_empty() {
                    bail!("empty HostKeyAlgorithms in `ssh -G` output");
                }
                host_key_algorithms = Some(algorithms);
            }
            "requiredrsasize" => {
                required_rsa_size =
                    Some(value.parse::<usize>().context("invalid RequiredRSASize")?);
            }
            "knownhostscommand" if value != "none" => {
                bail!(
                    "KnownHostsCommand is configured as {value:?}; constrained agent forwarding cannot safely reproduce dynamic OpenSSH host-key policy"
                );
            }
            "revokedhostkeys" if value != "none" => {
                bail!(
                    "RevokedHostKeys is configured as {value:?}; constrained agent forwarding does not yet query OpenSSH KRL revocations"
                );
            }
            "userknownhostsfile" => {
                append_known_hosts_files(
                    &mut files,
                    value,
                    defaults.map(|item| &item.user),
                    configured.user,
                )?;
            }
            "globalknownhostsfile" => {
                append_known_hosts_files(
                    &mut files,
                    value,
                    defaults.map(|item| &item.global),
                    configured.global,
                )?;
            }
            _ => {}
        }
    }
    let user = user
        .filter(|value| !value.is_empty())
        .context("missing SSH user")?;
    let hostname = hostname
        .filter(|value| !value.is_empty())
        .context("missing SSH hostname")?;
    let port = port.context("missing SSH port")?;
    let lookup = match &hostkey_alias {
        Some(alias) => alias.clone(),
        None if port == 22 => hostname.clone(),
        None => format!("[{hostname}]:{port}"),
    };
    files.sort();
    files.dedup();
    Ok(EffectiveSshConfig {
        user,
        hostname,
        port,
        lookup,
        files,
        host_key_algorithms: host_key_algorithms.context("missing SSH HostKeyAlgorithms")?,
        // RequiredRSASize was added after the OpenSSH 8.9 functional floor.
        // Before the directive existed, OpenSSH's minimum was 1024 bits.
        required_rsa_size: required_rsa_size.unwrap_or(1024),
    })
}

fn known_hosts_values(output: &[u8]) -> Result<(String, String)> {
    let output = std::str::from_utf8(output).context("SSH configuration was not UTF-8")?;
    let mut user = None;
    let mut global = None;
    for line in output.lines() {
        let Some((name, value)) = line.split_once(' ') else {
            continue;
        };
        match name {
            "userknownhostsfile" => user = Some(value.trim().to_owned()),
            "globalknownhostsfile" => global = Some(value.trim().to_owned()),
            _ => {}
        }
    }
    Ok((
        user.context("missing SSH UserKnownHostsFile")?,
        global.context("missing SSH GlobalKnownHostsFile")?,
    ))
}

fn parse_compiled_global_known_hosts(value: &str) -> Result<Vec<PathBuf>> {
    if value == "none" {
        return Ok(Vec::new());
    }
    let mut files = Vec::new();
    for path in value.split_ascii_whitespace() {
        let path = PathBuf::from(path);
        if !path.is_absolute() {
            bail!("OpenSSH reported a relative compiled GlobalKnownHostsFile default");
        }
        files.push(path);
    }
    if files.is_empty() {
        bail!("OpenSSH reported empty compiled GlobalKnownHostsFile defaults");
    }
    Ok(files)
}

fn append_known_hosts_files(
    files: &mut Vec<PathBuf>,
    value: &str,
    compiled_default: Option<&KnownHostsDefault>,
    configured: bool,
) -> Result<()> {
    if value == "none" {
        return Ok(());
    }
    if let Some(compiled_default) =
        compiled_default.filter(|default| !configured && default.rendered == value)
    {
        files.extend(compiled_default.files.iter().cloned());
        return Ok(());
    }
    if value.bytes().any(|byte| byte.is_ascii_whitespace()) {
        bail!(
            "ambiguous known_hosts filenames in `ssh -G` output {value:?}; OpenSSH removes quoting, so constrained agent forwarding accepts only one whitespace-free configured file per directive"
        );
    }
    if value.contains('%') || value.starts_with('~') {
        bail!("unexpanded known_hosts path {value:?} in `ssh -G` output");
    }
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        bail!("relative known_hosts path {value:?} in `ssh -G` output");
    }
    files.push(path);
    Ok(())
}

fn configured_host_key_allowed(config: &EffectiveSshConfig, key: &KeyData) -> bool {
    if !key_is_cryptographically_verifiable(key) {
        return false;
    }
    if let Some(rsa) = key.rsa() {
        let Some(modulus) = rsa.n.as_positive_bytes() else {
            return false;
        };
        let bits = modulus
            .first()
            .map(|first| modulus.len() * 8 - first.leading_zeros() as usize)
            .unwrap_or(0);
        if bits < config.required_rsa_size {
            return false;
        }
        return config
            .host_key_algorithms
            .iter()
            .any(|algorithm| matches!(algorithm.as_str(), "rsa-sha2-256" | "rsa-sha2-512"));
    }
    let algorithm = key.algorithm();
    config
        .host_key_algorithms
        .iter()
        .any(|allowed| allowed == algorithm.as_str())
}

fn key_is_cryptographically_verifiable(key: &KeyData) -> bool {
    matches!(
        key,
        KeyData::Ecdsa(_)
            | KeyData::Ed25519(_)
            | KeyData::Rsa(_)
            | KeyData::SkEcdsaSha2NistP256(_)
            | KeyData::SkEd25519(_)
    )
}

fn credential_is_cryptographically_verifiable(credential: &PublicCredential) -> bool {
    key_is_cryptographically_verifiable(credential.key_data())
        && match credential {
            PublicCredential::Key(_) => true,
            PublicCredential::Cert(certificate) => certificate.verify_signature().is_ok(),
        }
}

fn signature_algorithm_is_cryptographically_verifiable(algorithm: &Algorithm) -> bool {
    matches!(
        algorithm,
        Algorithm::Ecdsa { .. }
            | Algorithm::Ed25519
            | Algorithm::Rsa { hash: Some(_) }
            | Algorithm::SkEcdsaSha2NistP256
            | Algorithm::SkEd25519
    )
}

#[derive(Default)]
struct LocalAccount {
    home: String,
}

fn local_account() -> Result<LocalAccount> {
    const MAX_ACCOUNT_BUFFER: usize = 1024 * 1024;

    let uid = unsafe { libc::getuid() };
    let configured_size = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let mut size = if configured_size > 0 {
        configured_size as usize
    } else {
        16 * 1024
    }
    .clamp(1024, MAX_ACCOUNT_BUFFER);
    loop {
        let mut entry = unsafe { std::mem::zeroed::<libc::passwd>() };
        let mut result = std::ptr::null_mut();
        let mut buffer = vec![0u8; size];
        let status = unsafe {
            libc::getpwuid_r(
                uid,
                &mut entry,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if status == libc::ERANGE && size < MAX_ACCOUNT_BUFFER {
            size = size.saturating_mul(2).min(MAX_ACCOUNT_BUFFER);
            continue;
        }
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status)).context("look up local SSH user");
        }
        if result.is_null() {
            bail!("local SSH user for uid {uid} was not found");
        }
        if entry.pw_dir.is_null() {
            bail!("local SSH account record for uid {uid} was incomplete");
        }
        let home = unsafe { CStr::from_ptr(entry.pw_dir) }
            .to_str()
            .context("local SSH home directory was not UTF-8")?
            .to_string();
        return Ok(LocalAccount { home });
    }
}

fn ssh_keygen_for(ssh_program: &str) -> OsString {
    let path = Path::new(ssh_program);
    if path.components().count() > 1 {
        let mut sibling = path.to_path_buf();
        sibling.set_file_name("ssh-keygen");
        sibling.into_os_string()
    } else {
        OsString::from("ssh-keygen")
    }
}

fn read_known_host_keys(
    keygen: &OsString,
    lookup: &str,
    files: &[PathBuf],
) -> Result<(Vec<KeyData>, bool)> {
    let mut trusted = Vec::new();
    let mut revoked = Vec::new();
    let mut saw_ca = false;
    for file in files {
        if !file.exists() {
            continue;
        }
        let output = Command::new(keygen)
            .args(["-F", lookup, "-f"])
            .arg(file)
            .env("LC_ALL", "C")
            .capture_output()
            .with_context(|| format!("search {} for {lookup}", file.display()))?;
        if !output.status.success() {
            if output.status.code() == Some(1)
                && output.stdout.is_empty()
                && output.stderr.is_empty()
            {
                continue;
            }
            let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
            bail!(
                "could not search {} for {lookup}{}",
                file.display(),
                if detail.is_empty() {
                    String::new()
                } else {
                    format!(": {detail}")
                }
            );
        }
        let text = std::str::from_utf8(&output.stdout)
            .with_context(|| format!("{} contained non-UTF-8 key text", file.display()))?;
        parse_known_host_output(text, file, &mut trusted, &mut revoked, &mut saw_ca)?;
    }
    trusted.retain(|key| !revoked.contains(key));
    Ok((trusted, saw_ca))
}

fn parse_known_host_output(
    text: &str,
    file: &Path,
    trusted: &mut Vec<KeyData>,
    revoked: &mut Vec<KeyData>,
    saw_ca: &mut bool,
) -> Result<()> {
    for line in text.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        if fields.is_empty() {
            continue;
        }
        let (marker, offset) = if fields[0].starts_with('@') {
            (Some(fields[0]), 1)
        } else {
            (None, 0)
        };
        if fields.len() < offset + 3 {
            bail!("malformed known_hosts result from {}", file.display());
        }
        if marker == Some("@cert-authority") {
            *saw_ca = true;
            continue;
        }
        let public =
            PublicKey::from_openssh(&format!("{} {}", fields[offset + 1], fields[offset + 2]))
                .with_context(|| format!("parse host key from {}", file.display()))?;
        let key = public.key_data().clone();
        if marker == Some("@revoked") {
            revoked.push(key);
        } else if marker.is_none() && !trusted.contains(&key) {
            trusted.push(key);
        } else if marker.is_some() {
            bail!(
                "unsupported known_hosts marker {} in {}",
                marker.unwrap_or_default(),
                file.display()
            );
        }
    }
    Ok(())
}

/// A running broker. Dropping it closes every active client socket, joins the
/// listener and workers, and removes the private socket directory.
pub struct ConstrainedAgentBroker {
    ambient_socket: PathBuf,
    broker: PrivateBroker,
}

impl std::fmt::Debug for ConstrainedAgentBroker {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConstrainedAgentBroker")
            .field("socket_path", &self.broker.socket_path())
            .finish_non_exhaustive()
    }
}

impl ConstrainedAgentBroker {
    /// Start a peer-bound broker backed by the current SSH agent. This
    /// is the native `--peer-auth broker` mode: signatures remain limited to
    /// the validated coordinator-to-peer session and login user.
    pub fn start(policy: BrokerPolicy, max_connections: usize) -> Result<Self> {
        let ambient = std::env::var_os("SSH_AUTH_SOCK")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .context(
                "SSH_AUTH_SOCK is not set; constrained direct remote-to-remote authentication needs a local SSH agent",
            )?;
        Self::start_with_backend(
            ambient.clone(),
            SigningBackend::Ambient(ambient),
            policy,
            max_connections,
        )
    }

    #[cfg(test)]
    fn start_with_ambient_socket(
        ambient_socket: PathBuf,
        policy: BrokerPolicy,
        max_connections: usize,
    ) -> Result<Self> {
        Self::start_with_backend(
            ambient_socket.clone(),
            SigningBackend::Ambient(ambient_socket),
            policy,
            max_connections,
        )
    }

    /// Start a peer-bound broker which advertises and signs only with
    /// one local private key. The ambient agent remains available solely for
    /// authenticating the outer local-to-coordinator SSH connection.
    pub fn start_with_private_key(
        policy: BrokerPolicy,
        max_connections: usize,
        private_key: PrivateKey,
    ) -> Result<Self> {
        if private_key.is_encrypted() || private_key.algorithm() != Algorithm::Ed25519 {
            bail!("enrollment key must be an unencrypted Ed25519 key");
        }
        let ambient = std::env::var_os("SSH_AUTH_SOCK")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .context(
                "SSH_AUTH_SOCK is not set; authenticating to the source host still needs the local SSH agent",
            )?;
        Self::start_with_backend(
            ambient,
            SigningBackend::Private(Arc::new(private_key)),
            policy,
            max_connections,
        )
    }

    #[cfg(test)]
    fn start_with_private_key_and_socket(
        ambient_socket: PathBuf,
        policy: BrokerPolicy,
        max_connections: usize,
        private_key: PrivateKey,
    ) -> Result<Self> {
        Self::start_with_backend(
            ambient_socket,
            SigningBackend::Private(Arc::new(private_key)),
            policy,
            max_connections,
        )
    }

    fn start_with_backend(
        ambient_socket: PathBuf,
        backend: SigningBackend,
        policy: BrokerPolicy,
        max_connections: usize,
    ) -> Result<Self> {
        if max_connections == 0 {
            bail!("constrained agent broker needs at least one connection slot");
        }
        if !ambient_socket.is_absolute() {
            bail!("SSH_AUTH_SOCK must be an absolute Unix socket path");
        }
        validate_openssh_option_path(&ambient_socket, "SSH_AUTH_SOCK")?;
        let ambient_metadata = std::fs::metadata(&ambient_socket).with_context(|| {
            format!("inspect ambient SSH agent at {}", ambient_socket.display())
        })?;
        if !ambient_metadata.file_type().is_socket() {
            bail!(
                "SSH_AUTH_SOCK {} is not a Unix socket",
                ambient_socket.display()
            );
        }
        let backend = Arc::new(backend);
        let policy = Arc::new(policy);
        let broker = PrivateBroker::start(
            PrivateBrokerConfig {
                directory_prefix: "syq-agent-",
                socket_name: "agent.sock",
                listener_thread: "syq-agent-listener",
                client_thread: "syq-agent-client",
                max_connections,
                io_timeout: BROKER_IO_TIMEOUT,
            },
            move |stream, connections| {
                let _ = serve_client(stream, &backend, &policy, connections);
            },
        )?;
        validate_openssh_option_path(broker.socket_path(), "temporary constrained-agent path")?;

        Ok(Self {
            ambient_socket,
            broker,
        })
    }

    pub fn socket_path(&self) -> &Path {
        self.broker.socket_path()
    }

    pub fn ambient_socket(&self) -> &Path {
        &self.ambient_socket
    }
}

fn validate_openssh_option_path(path: &Path, label: &str) -> Result<()> {
    let text = path
        .to_str()
        .with_context(|| format!("{label} is not valid UTF-8"))?;
    if !text.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'/' | b'.' | b'_' | b'-' | b'+' | b':' | b'@' | b',' | b'='
            )
    }) {
        bail!("{label} contains characters that are unsafe in an OpenSSH command-line option");
    }
    Ok(())
}

#[derive(Default)]
struct BindState {
    bindings: Vec<SessionBind>,
}

impl BindState {
    fn add(&mut self, policy: &BrokerPolicy, binding: SessionBind) -> Result<()> {
        if binding.session_id.is_empty() || binding.session_id.len() > 64 {
            bail!("invalid SSH session identifier length");
        }
        if !key_is_cryptographically_verifiable(&binding.host_key)
            || !signature_algorithm_is_cryptographically_verifiable(&binding.signature.algorithm())
        {
            bail!("session-bind used an unsupported host-key or signature algorithm");
        }
        binding
            .verify_signature()
            .context("invalid session-bind host-key signature")?;
        match self.bindings.len() {
            0 if binding.is_forwarding && policy.coordinator.authorizes_binding(&binding) => {}
            1 if !binding.is_forwarding && policy.peer.authorizes_binding(&binding) => {}
            0 => bail!(
                "first session-bind did not identify trusted coordinator {}",
                policy.coordinator.known_hosts_name
            ),
            1 => bail!(
                "final session-bind did not identify trusted peer {}",
                policy.peer.known_hosts_name
            ),
            _ => bail!("unexpected extra SSH forwarding hop"),
        }
        if self
            .bindings
            .iter()
            .any(|previous| previous.session_id == binding.session_id)
        {
            bail!("reused SSH session identifier");
        }
        self.bindings.push(binding);
        Ok(())
    }

    fn authorize(&self, policy: &BrokerPolicy, request: &SignRequest) -> Result<()> {
        let [_, peer] = self.bindings.as_slice() else {
            bail!("signature requested before the exact two-hop path was bound");
        };
        let parsed = HostboundUserauth::parse(&request.data)?;
        if parsed.session_id != peer.session_id {
            bail!("userauth session did not match session-bind");
        }
        if parsed.user != policy.peer.login_user.as_bytes() {
            bail!("userauth login user was not authorized");
        }
        if parsed.service != b"ssh-connection" {
            bail!("userauth service was not ssh-connection");
        }
        if parsed.method != b"publickey-hostbound-v00@openssh.com" {
            bail!("unsupported or non-host-bound userauth request");
        }
        let mut credential = Vec::new();
        request
            .credential
            .encode(&mut credential)
            .context("encode requested credential")?;
        if parsed.credential != credential {
            bail!("embedded userauth credential did not match sign request");
        }
        let mut host_key = Vec::new();
        peer.host_key
            .encode(&mut host_key)
            .context("encode bound host key")?;
        if parsed.host_key != host_key {
            bail!("embedded userauth host key did not match session-bind");
        }
        validate_signature_algorithm(parsed.algorithm, parsed.credential, request.flags)?;
        Ok(())
    }
}

fn serve_client(
    mut downstream: TrackedStream,
    backend: &SigningBackend,
    policy: &BrokerPolicy,
    connections: Arc<ConnectionRegistry>,
) -> Result<()> {
    let mut state = BindState::default();
    let mut upstream: Option<TrackedStream> = None;
    let mut advertised_identities: Option<Vec<Identity>> = None;
    while let Some(frame) = read_frame(&mut downstream)? {
        let Some(message_id) = frame.first().copied() else {
            break;
        };
        match message_id {
            11 if frame.len() == 1 && !state.bindings.is_empty() => {
                let mut identities =
                    backend.identities(&mut upstream, &connections, &state.bindings, &frame)?;
                identities.retain(|identity| {
                    credential_is_cryptographically_verifiable(&identity.credential)
                });
                for identity in &mut identities {
                    identity.comment.clear();
                }
                let response = encode_identities_response(&identities)?;
                advertised_identities = Some(identities);
                write_frame(&mut downstream, &response)?;
            }
            13 => {
                let request = parse_sign_request(&frame);
                let Ok(request) = request else {
                    write_frame(&mut downstream, SSH_AGENT_FAILURE)?;
                    break;
                };
                let Some(identities) = advertised_identities.as_ref() else {
                    write_frame(&mut downstream, SSH_AGENT_FAILURE)?;
                    break;
                };
                if !identities.iter().any(|identity| {
                    credentials_equal_on_wire(&identity.credential, &request.credential)
                }) || state.authorize(policy, &request).is_err()
                {
                    write_frame(&mut downstream, SSH_AGENT_FAILURE)?;
                    break;
                }
                let response = backend.sign(
                    &mut upstream,
                    &connections,
                    &state.bindings,
                    &request,
                    &frame,
                )?;
                if verify_agent_sign_response(
                    &response,
                    request.credential.key_data(),
                    &request.data,
                )
                .is_err()
                {
                    write_frame(&mut downstream, SSH_AGENT_FAILURE)?;
                    break;
                }
                write_frame(&mut downstream, &response)?;
            }
            27 => {
                let binding = parse_session_bind(&frame);
                match binding.and_then(|binding| {
                    state.add(policy, binding)?;
                    if matches!(backend, SigningBackend::Ambient(_)) {
                        if let Some(stream) = upstream.as_mut() {
                            replay_session_bind(
                                stream,
                                state
                                    .bindings
                                    .last()
                                    .context("missing validated session-bind")?,
                            )?;
                        }
                    }
                    Ok(())
                }) {
                    Ok(()) => write_frame(&mut downstream, SSH_AGENT_SUCCESS)?,
                    Err(_) => {
                        write_frame(&mut downstream, SSH_AGENT_EXTENSION_FAILURE)?;
                        break;
                    }
                }
            }
            _ => {
                // Mutations, query/unknown extensions, unsupported protocol
                // operations and malformed identity requests all fail closed.
                write_frame(&mut downstream, SSH_AGENT_FAILURE)?;
                break;
            }
        }
    }
    Ok(())
}

fn parse_sign_request(frame: &[u8]) -> Result<SignRequest> {
    // ssh-agent-lib's nested Vec decoder allocates from the encoded u32 before
    // it notices that the bytes are absent. Walk every attacker-controlled
    // length as a borrowed slice before invoking its typed decoders.
    let mut input = SshCursor::new(frame);
    if input.byte()? != 13 {
        bail!("not a sign request");
    }
    let encoded_credential = input.string()?;
    validate_public_credential_wire(encoded_credential)?;
    let mut credential_input = encoded_credential;
    let credential = PublicCredential::decode(&mut credential_input)
        .context("decode bounded sign-request credential")?;
    if !credential_input.is_empty() {
        bail!("trailing bytes in sign-request credential");
    }
    let data = input.string()?.to_vec();
    let flags = u32::from_be_bytes(
        input
            .fixed(4)?
            .try_into()
            .map_err(|_| anyhow!("invalid sign-request flags"))?,
    );
    if !input.is_empty() {
        bail!("trailing bytes in sign request");
    }
    Ok(SignRequest {
        credential,
        data,
        flags,
    })
}

fn parse_session_bind(frame: &[u8]) -> Result<SessionBind> {
    let mut input = SshCursor::new(frame);
    if input.byte()? != 27 {
        bail!("not an agent extension");
    }
    if input.string()? != SessionBind::NAME.as_bytes() {
        bail!("unsupported agent extension");
    }

    let encoded_host_key = input.string()?;
    validate_key_wire(encoded_host_key)?;
    let mut host_key_input = encoded_host_key;
    let host_key =
        KeyData::decode(&mut host_key_input).context("decode bounded session host key")?;
    if !host_key_input.is_empty() {
        bail!("trailing bytes in session host key");
    }
    let session_id = input.string()?.to_vec();
    let encoded_signature = input.string()?;
    validate_signature_wire(encoded_signature)?;
    let mut signature_input = encoded_signature;
    let signature = ssh_agent_lib::ssh_key::Signature::decode(&mut signature_input)
        .context("decode bounded session signature")?;
    if !signature_input.is_empty() {
        bail!("trailing bytes in session signature");
    }
    let is_forwarding = input.byte()? != 0;
    if !input.is_empty() {
        bail!("trailing bytes in session-bind");
    }
    Ok(SessionBind {
        host_key,
        session_id,
        signature,
        is_forwarding,
    })
}

#[derive(Clone, Copy)]
enum WireKeyKind {
    Dsa,
    Ecdsa,
    Ed25519,
    Rsa,
    SkEcdsa,
    SkEd25519,
}

fn plain_wire_key_kind(algorithm: &[u8]) -> Result<WireKeyKind> {
    match algorithm {
        b"ssh-dss" => Ok(WireKeyKind::Dsa),
        b"ecdsa-sha2-nistp256" | b"ecdsa-sha2-nistp384" | b"ecdsa-sha2-nistp521" => {
            Ok(WireKeyKind::Ecdsa)
        }
        b"ssh-ed25519" => Ok(WireKeyKind::Ed25519),
        b"ssh-rsa" | b"rsa-sha2-256" | b"rsa-sha2-512" => Ok(WireKeyKind::Rsa),
        b"sk-ecdsa-sha2-nistp256@openssh.com" => Ok(WireKeyKind::SkEcdsa),
        b"sk-ssh-ed25519@openssh.com" => Ok(WireKeyKind::SkEd25519),
        _ => bail!("unsupported SSH key algorithm"),
    }
}

fn certificate_wire_key_kind(algorithm: &[u8]) -> Result<WireKeyKind> {
    match algorithm {
        b"ssh-dss-cert-v01@openssh.com" => Ok(WireKeyKind::Dsa),
        b"ecdsa-sha2-nistp256-cert-v01@openssh.com"
        | b"ecdsa-sha2-nistp384-cert-v01@openssh.com"
        | b"ecdsa-sha2-nistp521-cert-v01@openssh.com" => Ok(WireKeyKind::Ecdsa),
        b"ssh-ed25519-cert-v01@openssh.com" => Ok(WireKeyKind::Ed25519),
        b"ssh-rsa-cert-v01@openssh.com" => Ok(WireKeyKind::Rsa),
        b"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com" => Ok(WireKeyKind::SkEcdsa),
        b"sk-ssh-ed25519-cert-v01@openssh.com" => Ok(WireKeyKind::SkEd25519),
        _ => bail!("unsupported SSH certificate algorithm"),
    }
}

fn validate_key_fields(input: &mut SshCursor<'_>, kind: WireKeyKind) -> Result<()> {
    let field_count = match kind {
        WireKeyKind::Dsa => 4,
        WireKeyKind::Ecdsa | WireKeyKind::Rsa | WireKeyKind::SkEd25519 => 2,
        WireKeyKind::Ed25519 => 1,
        WireKeyKind::SkEcdsa => 3,
    };
    for _ in 0..field_count {
        input.string()?;
    }
    Ok(())
}

fn validate_key_wire(encoded: &[u8]) -> Result<()> {
    let mut input = SshCursor::new(encoded);
    let kind = plain_wire_key_kind(input.string()?)?;
    validate_key_fields(&mut input, kind)?;
    if !input.is_empty() {
        bail!("trailing bytes in SSH key");
    }
    Ok(())
}

fn validate_string_sequence(encoded: &[u8]) -> Result<()> {
    let mut input = SshCursor::new(encoded);
    while !input.is_empty() {
        input.string()?;
    }
    Ok(())
}

fn validate_certificate_options(encoded: &[u8]) -> Result<()> {
    let mut input = SshCursor::new(encoded);
    while !input.is_empty() {
        input.string()?;
        let data = input.string()?;
        if !data.is_empty() {
            let mut nested = SshCursor::new(data);
            nested.string()?;
            if !nested.is_empty() {
                bail!("trailing bytes in SSH certificate option");
            }
        }
    }
    Ok(())
}

fn validate_signature_wire(encoded: &[u8]) -> Result<()> {
    let mut input = SshCursor::new(encoded);
    let algorithm = input.string()?;
    let signature = input.string()?;
    if matches!(
        algorithm,
        b"ecdsa-sha2-nistp256"
            | b"ecdsa-sha2-nistp384"
            | b"ecdsa-sha2-nistp521"
            | b"sk-ecdsa-sha2-nistp256@openssh.com"
    ) {
        let mut components = SshCursor::new(signature);
        components.string()?;
        components.string()?;
        if !components.is_empty() {
            bail!("trailing bytes in ECDSA signature");
        }
    }
    if matches!(
        algorithm,
        b"sk-ecdsa-sha2-nistp256@openssh.com" | b"sk-ssh-ed25519@openssh.com"
    ) {
        input.fixed(5)?;
    }
    if !input.is_empty() {
        bail!("trailing bytes in SSH signature");
    }
    Ok(())
}

fn validate_public_credential_wire(encoded: &[u8]) -> Result<()> {
    let mut input = SshCursor::new(encoded);
    let algorithm = input.string()?;
    if algorithm.ends_with(b"-cert-v01@openssh.com") {
        let kind = certificate_wire_key_kind(algorithm)?;
        input.string()?; // nonce
        validate_key_fields(&mut input, kind)?;
        input.fixed(8)?; // serial
        input.fixed(4)?; // certificate type
        input.string()?; // key ID
        validate_string_sequence(input.string()?)?; // principals
        input.fixed(8)?; // valid after
        input.fixed(8)?; // valid before
        validate_certificate_options(input.string()?)?;
        validate_certificate_options(input.string()?)?;
        input.string()?; // reserved
        validate_key_wire(input.string()?)?; // signing key
        validate_signature_wire(input.string()?)?;
    } else {
        let kind = plain_wire_key_kind(algorithm)?;
        validate_key_fields(&mut input, kind)?;
    }
    if !input.is_empty() {
        bail!("trailing bytes in SSH credential");
    }
    Ok(())
}

enum SigningBackend {
    Ambient(PathBuf),
    Private(Arc<PrivateKey>),
}

impl SigningBackend {
    fn identities(
        &self,
        upstream: &mut Option<TrackedStream>,
        connections: &Arc<ConnectionRegistry>,
        bindings: &[SessionBind],
        request: &[u8],
    ) -> Result<Vec<Identity>> {
        match self {
            Self::Ambient(socket) => {
                let response = upstream_request(upstream, socket, connections, bindings, request)?;
                decode_identities_response(&response)
            }
            Self::Private(private) => Ok(vec![Identity {
                credential: private.public_key().key_data().clone().into(),
                comment: String::new(),
            }]),
        }
    }

    fn sign(
        &self,
        upstream: &mut Option<TrackedStream>,
        connections: &Arc<ConnectionRegistry>,
        bindings: &[SessionBind],
        request: &SignRequest,
        frame: &[u8],
    ) -> Result<Vec<u8>> {
        match self {
            Self::Ambient(socket) => {
                upstream_request(upstream, socket, connections, bindings, frame)
            }
            Self::Private(private) => {
                let expected = PublicCredential::Key(private.public_key().key_data().clone());
                if request.flags != 0 || !credentials_equal_on_wire(&request.credential, &expected)
                {
                    bail!("sign request did not select the enrollment key");
                }
                let signature = private
                    .try_sign(&request.data)
                    .context("sign destination authentication with the enrollment key")?;
                let mut response = Vec::new();
                Response::SignResponse(signature).encode(&mut response)?;
                Ok(response)
            }
        }
    }
}

fn upstream_request(
    upstream: &mut Option<TrackedStream>,
    ambient_socket: &Path,
    connections: &Arc<ConnectionRegistry>,
    bindings: &[SessionBind],
    request: &[u8],
) -> Result<Vec<u8>> {
    if upstream.is_none() {
        let stream = UnixStream::connect(ambient_socket).with_context(|| {
            format!(
                "connect to ambient SSH agent at {}",
                ambient_socket.display()
            )
        })?;
        let mut stream = connections.track(stream)?;
        for binding in bindings {
            replay_session_bind(&mut stream, binding)?;
        }
        *upstream = Some(stream);
    }
    let stream = upstream.as_mut().context("ambient SSH agent unavailable")?;
    write_frame(stream, request)?;
    read_frame(stream)?.context("ambient SSH agent closed without a response")
}

fn replay_session_bind(stream: &mut TrackedStream, binding: &SessionBind) -> Result<()> {
    let request = Request::Extension(Extension::new_message(binding.clone())?);
    let mut frame = Vec::new();
    request.encode(&mut frame)?;
    write_frame(stream, &frame)?;
    let response = read_frame(stream)?.context("ambient SSH agent closed during session-bind")?;
    let mut input = response.as_slice();
    let response = Response::decode(&mut input).context("decode ambient session-bind response")?;
    if !input.is_empty() {
        bail!("trailing bytes in ambient session-bind response");
    }
    match response {
        // OpenSSH enforces the binding when supported. The broker's own exact
        // path checks remain mandatory if an agent rejects the extension.
        Response::Success | Response::Failure | Response::ExtensionFailure => Ok(()),
        _ => bail!("ambient agent returned an unexpected session-bind response"),
    }
}

fn decode_identities_response(frame: &[u8]) -> Result<Vec<Identity>> {
    let mut input = frame;
    let response = Response::decode(&mut input).context("decode ambient identities response")?;
    if !input.is_empty() {
        bail!("trailing bytes in ambient identities response");
    }
    match response {
        Response::IdentitiesAnswer(identities) => Ok(identities),
        Response::Failure => Ok(Vec::new()),
        _ => bail!("ambient agent returned an unexpected identities response"),
    }
}

fn verify_agent_sign_response(frame: &[u8], key: &KeyData, data: &[u8]) -> Result<()> {
    let mut input = frame;
    let response = Response::decode(&mut input).context("decode ambient signature response")?;
    if !input.is_empty() {
        bail!("trailing bytes in ambient signature response");
    }
    match response {
        Response::SignResponse(signature) => key
            .verify(data, &signature)
            .context("ambient agent returned an invalid signature"),
        Response::Failure => Ok(()),
        _ => bail!("ambient agent returned an unexpected signature response"),
    }
}

fn credentials_equal_on_wire(left: &PublicCredential, right: &PublicCredential) -> bool {
    let mut left_encoded = Vec::new();
    let mut right_encoded = Vec::new();
    left.encode(&mut left_encoded).is_ok()
        && right.encode(&mut right_encoded).is_ok()
        && left_encoded == right_encoded
}

fn encode_identities_response(identities: &[Identity]) -> Result<Vec<u8>> {
    let mut frame = Vec::new();
    Response::IdentitiesAnswer(identities.to_vec()).encode(&mut frame)?;
    Ok(frame)
}

fn read_frame(stream: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut length = [0u8; 4];
    let first = stream.read(&mut length[..1])?;
    if first == 0 {
        return Ok(None);
    }
    stream.read_exact(&mut length[1..])?;
    let length = u32::from_be_bytes(length) as usize;
    if !(1..=MAX_AGENT_FRAME).contains(&length) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SSH agent frame length is outside the allowed range",
        ));
    }
    let mut frame = vec![0u8; length];
    stream.read_exact(&mut frame)?;
    Ok(Some(frame))
}

fn write_frame(stream: &mut impl Write, frame: &[u8]) -> io::Result<()> {
    let length = u32::try_from(frame.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "SSH agent frame too large"))?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(frame)?;
    stream.flush()
}

struct HostboundUserauth<'a> {
    session_id: &'a [u8],
    user: &'a [u8],
    service: &'a [u8],
    method: &'a [u8],
    algorithm: &'a [u8],
    credential: &'a [u8],
    host_key: &'a [u8],
}

impl<'a> HostboundUserauth<'a> {
    fn parse(data: &'a [u8]) -> Result<Self> {
        let mut input = SshCursor::new(data);
        let session_id = input.string()?;
        if input.byte()? != 50 {
            bail!("signing data was not SSH2_MSG_USERAUTH_REQUEST");
        }
        let user = input.string()?;
        let service = input.string()?;
        let method = input.string()?;
        if input.byte()? != 1 {
            bail!("public-key request did not contain a signature");
        }
        let algorithm = input.string()?;
        let credential = input.string()?;
        let host_key = input.string()?;
        if !input.is_empty() {
            bail!("trailing bytes in host-bound userauth request");
        }
        Ok(Self {
            session_id,
            user,
            service,
            method,
            algorithm,
            credential,
            host_key,
        })
    }
}

fn validate_signature_algorithm(algorithm: &[u8], credential: &[u8], flags: u32) -> Result<()> {
    let mut credential = SshCursor::new(credential);
    let key_type = credential.string()?;
    if matches!(
        (key_type, algorithm),
        (b"ssh-rsa", b"ssh-rsa")
            | (
                b"ssh-rsa-cert-v01@openssh.com",
                b"ssh-rsa-cert-v01@openssh.com"
            )
    ) {
        bail!("RSA/SHA-1 userauth signatures cannot be verified safely");
    }
    let expected_flags = match (key_type, algorithm) {
        (b"ssh-rsa", b"rsa-sha2-256")
        | (b"ssh-rsa-cert-v01@openssh.com", b"rsa-sha2-256-cert-v01@openssh.com") => 2,
        (b"ssh-rsa", b"rsa-sha2-512")
        | (b"ssh-rsa-cert-v01@openssh.com", b"rsa-sha2-512-cert-v01@openssh.com") => 4,
        (key_type, algorithm) if key_type == algorithm => 0,
        _ => bail!("userauth signature algorithm did not match credential"),
    };
    if flags != expected_flags {
        bail!("agent signature flags did not match userauth algorithm");
    }
    Ok(())
}

struct SshCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> SshCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn byte(&mut self) -> Result<u8> {
        let value = *self
            .bytes
            .get(self.offset)
            .context("truncated SSH signing data")?;
        self.offset += 1;
        Ok(value)
    }

    fn fixed(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .context("SSH field offset overflow")?;
        let value = self
            .bytes
            .get(self.offset..end)
            .context("truncated SSH field")?;
        self.offset = end;
        Ok(value)
    }

    fn string(&mut self) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(4)
            .context("SSH string offset overflow")?;
        let length: [u8; 4] = self
            .bytes
            .get(self.offset..end)
            .context("truncated SSH string length")?
            .try_into()
            .map_err(|_| anyhow!("invalid SSH string length"))?;
        self.offset = end;
        let end = self
            .offset
            .checked_add(u32::from_be_bytes(length) as usize)
            .context("SSH string length overflow")?;
        let value = self
            .bytes
            .get(self.offset..end)
            .context("truncated SSH string")?;
        self.offset = end;
        Ok(value)
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests;

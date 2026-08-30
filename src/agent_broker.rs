//! A fail-closed SSH-agent proxy for live direct remote-to-remote transfers.
//!
//! The source host sees public identities from the caller's ambient agent, but
//! signatures are released only for one hostA -> user@hostB SSH authentication
//! path. OpenSSH's session-bind messages prove the two SSH sessions and the
//! host-bound userauth request binds the signature to B's host key and login
//! user. The broker never accepts key-management or opaque signing requests.

use anyhow::{anyhow, bail, Context, Result};
use signature::Verifier;
use ssh_agent_lib::proto::extension::{MessageExtension, SessionBind};
use ssh_agent_lib::proto::{Extension, Identity, PublicCredential, Request, Response, SignRequest};
use ssh_agent_lib::ssh_encoding::{Decode, Encode};
use ssh_agent_lib::ssh_key::{
    certificate::{CertType, Certificate},
    public::KeyData,
    Algorithm, PublicKey,
};
use std::collections::HashMap;
use std::ffi::{CStr, OsString};
use std::fs;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// Agent messages are normally only a few KiB. This accommodates large
/// identity lists without allowing a peer to force an unbounded allocation.
const MAX_AGENT_FRAME: usize = 256 * 1024;
/// Bound stalled forwarded clients and ambient-agent operations while leaving
/// enough time for hardware-token touch/PIN/confirmation prompts.
const BROKER_IO_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_SSH_CONFIG_FILES: usize = 256;
const MAX_SSH_CONFIG_BYTES: usize = 1024 * 1024;
const SSH_AGENT_FAILURE: &[u8] = &[5];
const SSH_AGENT_SUCCESS: &[u8] = &[6];
const SSH_AGENT_EXTENSION_FAILURE: &[u8] = &[28];

#[derive(Clone, Debug)]
pub struct HostPolicy {
    pub login_user: String,
    host_keys: Vec<KeyData>,
    known_hosts_name: String,
    host_key_algorithms: Vec<String>,
    required_rsa_size: usize,
    user_certificates: Vec<Certificate>,
}

impl HostPolicy {
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
    delegate: HostPolicy,
    destination: HostPolicy,
}

impl BrokerPolicy {
    pub fn new(delegate: HostPolicy, destination: HostPolicy) -> Self {
        Self {
            delegate,
            destination,
        }
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
    load_user_certificates: bool,
) -> Result<HostPolicy> {
    let inspection = inspect_ssh_configuration(ssh_program, explicit_user, host, false)?;
    let defaults = inspect_ssh_configuration(ssh_program, explicit_user, host, true)?;
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
            "no exact trusted host key for {host} ({}) allowed by HostKeyAlgorithms and RequiredRSASize and supported by syq's cryptographic verifier was found in the configured known_hosts files; connect once with ssh to record it, use --relay, or use --no-forward-agent with credentials on the source host",
            config.lookup
        );
    }
    let user_certificates = if load_user_certificates {
        let certificate_paths = certificate_paths(&config, host)?;
        read_user_certificates(&certificate_paths)?
    } else {
        Vec::new()
    };
    Ok(HostPolicy {
        login_user: config.user,
        host_keys,
        known_hosts_name: config.lookup,
        host_key_algorithms: config.host_key_algorithms,
        required_rsa_size: config.required_rsa_size,
        user_certificates,
    })
}

struct SshConfigurationInspection {
    output: Vec<u8>,
    known_hosts_configured: KnownHostsConfigured,
}

fn inspect_ssh_configuration(
    ssh_program: &str,
    explicit_user: Option<&str>,
    host: &str,
    compiled_defaults_only: bool,
) -> Result<SshConfigurationInspection> {
    let mut command = Command::new(ssh_program);
    command.arg("-G");
    if compiled_defaults_only {
        command.args(["-F", "/dev/null"]);
    } else {
        // OpenSSH does not retain filename quoting in `ssh -G` output. Its
        // debug stream identifies the configuration files that contributed to
        // this query, which lets us distinguish compiled defaults from an
        // explicitly configured value that happens to render identically.
        command.arg("-vvv");
    }
    if let Some(user) = explicit_user {
        command.args(["-l", user]);
    }
    command.args(["--", host]).env("LC_ALL", "C");
    let output = command
        .output()
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
    let known_hosts_configured = if compiled_defaults_only {
        KnownHostsConfigured::default()
    } else {
        configured_known_hosts_directives(&output.stderr)?
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

fn configured_known_hosts_directives(debug: &[u8]) -> Result<KnownHostsConfigured> {
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

    let mut configured = KnownHostsConfigured::default();
    for path in paths {
        let mut file = fs::File::open(&path)
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
    host_key_alias: Option<String>,
    proxy_jump: Option<String>,
    lookup: String,
    files: Vec<PathBuf>,
    host_key_algorithms: Vec<String>,
    required_rsa_size: usize,
    certificate_files: Vec<String>,
    certificate_files_configured: bool,
    identity_files: Vec<String>,
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
    let mut proxy_jump = None;
    let mut files = Vec::new();
    let mut host_key_algorithms = None;
    let mut required_rsa_size = None;
    let mut certificate_files = Vec::new();
    let mut certificate_files_configured = false;
    let mut identity_files = Vec::new();
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
            "proxyjump" if value != "none" => proxy_jump = Some(value.to_string()),
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
            "certificatefile" => {
                certificate_files_configured = true;
                if value != "none" {
                    certificate_files.push(value.to_string());
                }
            }
            "identityfile" if value != "none" => identity_files.push(value.to_string()),
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
        host_key_alias: hostkey_alias,
        proxy_jump,
        lookup,
        files,
        host_key_algorithms: host_key_algorithms.context("missing SSH HostKeyAlgorithms")?,
        // RequiredRSASize was added after the OpenSSH 8.9 functional floor.
        // Before the directive existed, OpenSSH's minimum was 1024 bits.
        required_rsa_size: required_rsa_size.unwrap_or(1024),
        certificate_files,
        certificate_files_configured,
        identity_files,
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

fn credential_is_cryptographically_verifiable(credential: &PublicCredential) -> bool {
    key_is_cryptographically_verifiable(credential.key_data())
        && match credential {
            PublicCredential::Key(_) => true,
            PublicCredential::Cert(certificate) => certificate.verify_signature().is_ok(),
        }
}

fn certificate_paths(config: &EffectiveSshConfig, original_host: &str) -> Result<Vec<PathBuf>> {
    let candidates: Vec<(String, &str)> = if config.certificate_files_configured {
        config
            .certificate_files
            .iter()
            .cloned()
            .map(|path| (path, "CertificateFile"))
            .collect()
    } else {
        config
            .identity_files
            .iter()
            .map(|path| {
                (
                    format!("{path}-cert.pub"),
                    "implicit IdentityFile certificate",
                )
            })
            .collect()
    };
    let mut paths = Vec::new();
    for (configured, source) in candidates {
        let expanded = expand_credential_path(&configured, config, original_host)
            .with_context(|| format!("expand {source} {configured:?}"))?;
        if !paths.contains(&expanded) {
            paths.push(expanded);
        }
    }
    Ok(paths)
}

fn expand_credential_path(
    configured: &str,
    config: &EffectiveSshConfig,
    original_host: &str,
) -> Result<PathBuf> {
    expand_credential_path_with_env(configured, config, original_host, |name| {
        std::env::var(name)
            .with_context(|| format!("SSH credential path environment variable {name} is unset"))
    })
}

fn expand_credential_path_with_env(
    configured: &str,
    config: &EffectiveSshConfig,
    original_host: &str,
    environment: impl Fn(&str) -> Result<String>,
) -> Result<PathBuf> {
    let needs_account = configured == "~"
        || configured.starts_with("~/")
        || configured.contains("%d")
        || configured.contains("%u");
    let account = needs_account
        .then(local_account)
        .transpose()?
        .unwrap_or_default();
    let home = account.home;
    let configured = if configured == "~" {
        home.clone()
    } else if let Some(rest) = configured.strip_prefix("~/") {
        format!("{home}/{rest}")
    } else if configured.starts_with('~') {
        bail!("SSH credential path uses an unsupported named-user tilde");
    } else {
        configured.to_owned()
    };

    let host_key_name = config.host_key_alias.as_deref().unwrap_or(original_host);
    let mut expanded = String::with_capacity(configured.len());
    let mut chars = configured.chars().peekable();
    while let Some(character) = chars.next() {
        match character {
            '%' => {
                let token = chars
                    .next()
                    .context("trailing '%' in SSH credential path")?;
                match token {
                    '%' => expanded.push('%'),
                    'd' => expanded.push_str(&home),
                    'h' => expanded.push_str(&config.hostname),
                    'i' => expanded.push_str(&unsafe { libc::getuid() }.to_string()),
                    'j' => expanded.push_str(config.proxy_jump.as_deref().unwrap_or("")),
                    'k' => expanded.push_str(host_key_name),
                    'L' => {
                        let hostname = local_hostname()?;
                        expanded.push_str(
                            hostname
                                .split_once('.')
                                .map_or(hostname.as_str(), |(short, _)| short),
                        );
                    }
                    'l' => expanded.push_str(&local_hostname()?),
                    'n' => expanded.push_str(original_host),
                    'p' => expanded.push_str(&config.port.to_string()),
                    'r' => expanded.push_str(&config.user),
                    'u' => expanded.push_str(&account.username),
                    'C' => bail!(
                        "SSH credential path uses OpenSSH's %C connection hash, which syq cannot reproduce safely"
                    ),
                    other => bail!("unsupported SSH credential path token %{other}"),
                }
            }
            '$' if chars.peek() == Some(&'{') => {
                chars.next();
                let mut name = String::new();
                loop {
                    match chars.next() {
                        Some('}') => break,
                        Some(character) => name.push(character),
                        None => {
                            bail!("unterminated environment variable in SSH credential path")
                        }
                    }
                }
                if name.is_empty()
                    || !name
                        .bytes()
                        .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
                {
                    bail!("invalid environment variable in SSH credential path");
                }
                // OpenSSH expands percent tokens and environment variables in
                // one pass. Do not reinterpret '%' or '${...}' in this value.
                expanded.push_str(&environment(&name)?);
            }
            _ => expanded.push(character),
        }
    }
    Ok(PathBuf::from(expanded))
}

#[derive(Default)]
struct LocalAccount {
    username: String,
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
        if entry.pw_name.is_null() || entry.pw_dir.is_null() {
            bail!("local SSH account record for uid {uid} was incomplete");
        }
        let username = unsafe { CStr::from_ptr(entry.pw_name) }
            .to_str()
            .context("local SSH username was not UTF-8")?
            .to_string();
        let home = unsafe { CStr::from_ptr(entry.pw_dir) }
            .to_str()
            .context("local SSH home directory was not UTF-8")?
            .to_string();
        return Ok(LocalAccount { username, home });
    }
}

fn local_hostname() -> Result<String> {
    let mut bytes = [0u8; 256];
    if unsafe { libc::gethostname(bytes.as_mut_ptr().cast(), bytes.len()) } != 0 {
        return Err(io::Error::last_os_error()).context("read local hostname");
    }
    let length = bytes
        .iter()
        .position(|byte| *byte == 0)
        .context("local hostname exceeded 255 bytes")?;
    String::from_utf8(bytes[..length].to_vec()).context("local hostname was not UTF-8")
}

fn read_user_certificates(paths: &[PathBuf]) -> Result<Vec<Certificate>> {
    let mut certificates = Vec::new();
    for path in paths {
        if !path.exists() {
            continue;
        }
        let certificate = Certificate::read_file(path)
            .with_context(|| format!("read user CertificateFile {}", path.display()))?;
        if certificate.cert_type() != CertType::User {
            bail!(
                "CertificateFile {} is not a user certificate",
                path.display()
            );
        }
        if !key_is_cryptographically_verifiable(certificate.public_key()) {
            bail!(
                "user certificate {} uses unsupported authentication algorithm {}",
                path.display(),
                certificate.public_key().algorithm()
            );
        }
        certificate
            .verify_signature()
            .with_context(|| format!("verify CertificateFile {}", path.display()))?;
        if !certificates
            .iter()
            .any(|existing| certificates_equal_on_wire(existing, &certificate))
        {
            certificates.push(certificate);
        }
    }
    Ok(certificates)
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
            .output()
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

/// A running broker. Dropping it closes every active client/upstream socket,
/// joins the listener and workers, and removes the private socket directory.
pub struct ConstrainedAgentBroker {
    ambient_socket: PathBuf,
    socket_path: PathBuf,
    shutdown: Arc<AtomicBool>,
    connections: Arc<ConnectionRegistry>,
    listener_thread: Option<JoinHandle<()>>,
    _socket_dir: tempfile::TempDir,
}

impl std::fmt::Debug for ConstrainedAgentBroker {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConstrainedAgentBroker")
            .field("socket_path", &self.socket_path)
            .finish_non_exhaustive()
    }
}

impl ConstrainedAgentBroker {
    pub fn start(policy: BrokerPolicy, max_connections: usize) -> Result<Self> {
        let ambient = std::env::var_os("SSH_AUTH_SOCK")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .context(
                "SSH_AUTH_SOCK is not set; constrained direct remote-to-remote authentication needs a local SSH agent (or use --relay/--no-forward-agent)",
            )?;
        Self::start_with_socket(ambient, policy, max_connections)
    }

    fn start_with_socket(
        ambient_socket: PathBuf,
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
        let socket_dir = tempfile::Builder::new()
            .prefix("syq-agent-")
            .tempdir()
            .context("create private constrained-agent directory")?;
        let socket_path = socket_dir.path().join("agent.sock");
        validate_openssh_option_path(&socket_path, "temporary constrained-agent path")?;
        let listener = UnixListener::bind(&socket_path)
            .with_context(|| format!("bind constrained agent at {}", socket_path.display()))?;
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;

        let shutdown = Arc::new(AtomicBool::new(false));
        let connections = Arc::new(ConnectionRegistry::default());
        let thread_shutdown = Arc::clone(&shutdown);
        let thread_connections = Arc::clone(&connections);
        let thread_ambient = ambient_socket.clone();
        let policy = Arc::new(policy);
        let listener_thread = thread::Builder::new()
            .name("syq-agent-listener".into())
            .spawn(move || {
                accept_connections(
                    listener,
                    thread_ambient,
                    policy,
                    max_connections,
                    thread_shutdown,
                    thread_connections,
                )
            })
            .context("start constrained-agent listener")?;

        Ok(Self {
            ambient_socket,
            socket_path,
            shutdown,
            connections,
            listener_thread: Some(listener_thread),
            _socket_dir: socket_dir,
        })
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
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

impl Drop for ConstrainedAgentBroker {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        self.connections.shutdown_all();
        // Wake accept immediately instead of waiting for the nonblocking poll.
        let _ = UnixStream::connect(&self.socket_path);
        if let Some(listener) = self.listener_thread.take() {
            let _ = listener.join();
        }
    }
}

fn accept_connections(
    listener: UnixListener,
    ambient_socket: PathBuf,
    policy: Arc<BrokerPolicy>,
    max_connections: usize,
    shutdown: Arc<AtomicBool>,
    connections: Arc<ConnectionRegistry>,
) {
    let mut workers: Vec<JoinHandle<()>> = Vec::new();
    while !shutdown.load(Ordering::Acquire) {
        reap_workers(&mut workers);
        match listener.accept() {
            Ok((stream, _)) => {
                if workers.len() >= max_connections {
                    let _ = stream.shutdown(Shutdown::Both);
                    continue;
                }
                let Ok(stream) = connections.track(stream) else {
                    continue;
                };
                let worker_ambient = ambient_socket.clone();
                let worker_policy = Arc::clone(&policy);
                let worker_connections = Arc::clone(&connections);
                match thread::Builder::new()
                    .name("syq-agent-client".into())
                    .spawn(move || {
                        let _ = serve_client(
                            stream,
                            &worker_ambient,
                            &worker_policy,
                            worker_connections,
                        );
                    }) {
                    Ok(worker) => workers.push(worker),
                    Err(_) => continue,
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(_) => break,
        }
    }
    connections.shutdown_all();
    for worker in workers {
        let _ = worker.join();
    }
}

fn reap_workers(workers: &mut Vec<JoinHandle<()>>) {
    let mut index = 0;
    while index < workers.len() {
        if workers[index].is_finished() {
            let worker = workers.swap_remove(index);
            let _ = worker.join();
        } else {
            index += 1;
        }
    }
}

#[derive(Default)]
struct ConnectionRegistry {
    next_id: AtomicU64,
    streams: Mutex<HashMap<u64, UnixStream>>,
}

impl ConnectionRegistry {
    fn track(self: &Arc<Self>, stream: UnixStream) -> io::Result<TrackedStream> {
        stream.set_read_timeout(Some(BROKER_IO_TIMEOUT))?;
        stream.set_write_timeout(Some(BROKER_IO_TIMEOUT))?;
        let registered = stream.try_clone()?;
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.streams
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(id, registered);
        Ok(TrackedStream {
            stream,
            id,
            registry: Arc::clone(self),
        })
    }

    fn shutdown_all(&self) {
        let streams = self
            .streams
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for stream in streams.values() {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
}

struct TrackedStream {
    stream: UnixStream,
    id: u64,
    registry: Arc<ConnectionRegistry>,
}

impl Drop for TrackedStream {
    fn drop(&mut self) {
        self.registry
            .streams
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.id);
    }
}

impl Read for TrackedStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buffer)
    }
}

impl Write for TrackedStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.stream.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
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
            0 if binding.is_forwarding && policy.delegate.authorizes_binding(&binding) => {}
            1 if !binding.is_forwarding && policy.destination.authorizes_binding(&binding) => {}
            0 => bail!(
                "first session-bind did not identify trusted delegate {}",
                policy.delegate.known_hosts_name
            ),
            1 => bail!(
                "final session-bind did not identify trusted destination {}",
                policy.destination.known_hosts_name
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
        let [_, destination] = self.bindings.as_slice() else {
            bail!("signature requested before the exact two-hop path was bound");
        };
        let parsed = HostboundUserauth::parse(&request.data)?;
        if parsed.session_id != destination.session_id {
            bail!("userauth session did not match session-bind");
        }
        if parsed.user != policy.destination.login_user.as_bytes() {
            bail!("userauth login user was not authorized");
        }
        if parsed.service != b"ssh-connection" {
            bail!("userauth service was not ssh-connection");
        }
        if parsed.method != b"publickey-hostbound-v00@openssh.com" {
            bail!("legacy or non-host-bound userauth request");
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
        destination
            .host_key
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
    ambient_socket: &Path,
    policy: &BrokerPolicy,
    connections: Arc<ConnectionRegistry>,
) -> Result<()> {
    let mut state = BindState::default();
    let mut upstream: Option<TrackedStream> = None;
    let mut sanitized_identities: Option<SanitizedIdentities> = None;
    while let Some(frame) = read_frame(&mut downstream)? {
        let Some(message_id) = frame.first().copied() else {
            break;
        };
        match message_id {
            11 if frame.len() == 1 && !state.bindings.is_empty() => {
                let response = upstream_request(
                    &mut upstream,
                    ambient_socket,
                    &connections,
                    &state.bindings,
                    &frame,
                    UpstreamResponse::Identities,
                )?;
                let identities = decode_identities_response(&response)?;
                let identities =
                    sanitize_identities(identities, &policy.destination.user_certificates);
                let response = encode_identities_response(&identities.advertised)?;
                sanitized_identities = Some(identities);
                write_frame(&mut downstream, &response)?;
            }
            13 => {
                let request = parse_sign_request(&frame);
                let Ok(request) = request else {
                    write_frame(&mut downstream, SSH_AGENT_FAILURE)?;
                    break;
                };
                let Some(identities) = sanitized_identities.as_ref() else {
                    write_frame(&mut downstream, SSH_AGENT_FAILURE)?;
                    break;
                };
                if !identities.advertises(&request.credential)
                    || state.authorize(policy, &request).is_err()
                {
                    write_frame(&mut downstream, SSH_AGENT_FAILURE)?;
                    break;
                }
                let upstream_frame = translated_sign_request(
                    &request,
                    &identities.ambient,
                    &policy.destination.user_certificates,
                )?;
                let response = upstream_request(
                    &mut upstream,
                    ambient_socket,
                    &connections,
                    &state.bindings,
                    &upstream_frame,
                    UpstreamResponse::Signature,
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
                    if let Some(stream) = upstream.as_mut() {
                        replay_session_bind(
                            stream,
                            state
                                .bindings
                                .last()
                                .context("missing validated session-bind")?,
                        )?;
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
                // Mutations, query/unknown extensions, legacy protocol
                // operations and malformed identity requests all fail closed.
                write_frame(&mut downstream, SSH_AGENT_FAILURE)?;
                break;
            }
        }
    }
    Ok(())
}

fn parse_sign_request(frame: &[u8]) -> Result<SignRequest> {
    let mut input = frame;
    let request = Request::decode(&mut input).context("decode sign request")?;
    if !input.is_empty() {
        bail!("trailing bytes in sign request");
    }
    match request {
        Request::SignRequest(request) => Ok(request),
        _ => bail!("not a sign request"),
    }
}

fn parse_session_bind(frame: &[u8]) -> Result<SessionBind> {
    let mut input = frame;
    let request = Request::decode(&mut input).context("decode agent extension")?;
    if !input.is_empty() {
        bail!("trailing bytes in agent extension");
    }
    let Request::Extension(extension) = request else {
        bail!("not an agent extension");
    };
    if extension.name != SessionBind::NAME {
        bail!("unsupported agent extension");
    }
    let mut details = extension.details.as_ref();
    let binding = SessionBind::decode(&mut details).context("decode session-bind")?;
    if !details.is_empty() {
        bail!("trailing bytes in session-bind");
    }
    Ok(binding)
}

enum UpstreamResponse {
    Identities,
    Signature,
}

fn upstream_request(
    upstream: &mut Option<TrackedStream>,
    ambient_socket: &Path,
    connections: &Arc<ConnectionRegistry>,
    bindings: &[SessionBind],
    request: &[u8],
    expected: UpstreamResponse,
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
    let response = read_frame(stream)?.context("ambient SSH agent closed without a response")?;
    validate_upstream_response(&response, expected)?;
    Ok(response)
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
        // OpenSSH accepts and enforces the binding. Agents that do not
        // implement session-bind commonly reject it but remain usable; syq's
        // own broker policy is still mandatory for every downstream request.
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

struct SanitizedIdentities {
    ambient: Vec<Identity>,
    advertised: Vec<Identity>,
}

impl SanitizedIdentities {
    fn advertises(&self, credential: &PublicCredential) -> bool {
        self.advertised
            .iter()
            .any(|identity| credentials_equal_on_wire(&identity.credential, credential))
    }
}

fn credentials_equal_on_wire(left: &PublicCredential, right: &PublicCredential) -> bool {
    let mut left_encoded = Vec::new();
    let mut right_encoded = Vec::new();
    left.encode(&mut left_encoded).is_ok()
        && right.encode(&mut right_encoded).is_ok()
        && left_encoded == right_encoded
}

fn certificates_equal_on_wire(left: &Certificate, right: &Certificate) -> bool {
    credentials_equal_on_wire(
        &PublicCredential::Cert(Box::new(left.clone())),
        &PublicCredential::Cert(Box::new(right.clone())),
    )
}

fn sanitize_identities(
    identities: Vec<Identity>,
    certificates: &[Certificate],
) -> SanitizedIdentities {
    let ambient: Vec<_> = identities
        .into_iter()
        .filter(|identity| credential_is_cryptographically_verifiable(&identity.credential))
        .collect();
    let ambient_raw_keys: Vec<_> = ambient
        .iter()
        .filter_map(|identity| match &identity.credential {
            PublicCredential::Key(key) => Some(key.clone()),
            PublicCredential::Cert(_) => None,
        })
        .collect();
    let mut advertised: Vec<_> = ambient
        .iter()
        .filter(|identity| {
            let covered = certificates
                .iter()
                .any(|certificate| certificate.public_key() == identity.credential.key_data());
            !covered
                || certificates.iter().any(|certificate| {
                    matches!(
                        &identity.credential,
                        PublicCredential::Cert(advertised)
                            if certificates_equal_on_wire(advertised, certificate)
                    )
                })
        })
        .cloned()
        .map(|mut identity| {
            identity.comment.clear();
            identity
        })
        .collect();
    for certificate in certificates {
        let credential = PublicCredential::Cert(Box::new(certificate.clone()));
        if !credential_is_cryptographically_verifiable(&credential) {
            continue;
        }
        if advertised
            .iter()
            .any(|identity| credentials_equal_on_wire(&identity.credential, &credential))
        {
            continue;
        }
        if ambient_raw_keys.contains(certificate.public_key()) {
            advertised.push(Identity {
                credential,
                comment: String::new(),
            });
        }
    }
    SanitizedIdentities {
        ambient,
        advertised,
    }
}

fn encode_identities_response(identities: &[Identity]) -> Result<Vec<u8>> {
    let mut frame = Vec::new();
    Response::IdentitiesAnswer(identities.to_vec()).encode(&mut frame)?;
    Ok(frame)
}

fn translated_sign_request(
    request: &SignRequest,
    ambient_identities: &[Identity],
    certificates: &[Certificate],
) -> Result<Vec<u8>> {
    let mut translated = request.clone();
    if let PublicCredential::Cert(certificate) = &request.credential {
        let ambient_has_exact_certificate = ambient_identities
            .iter()
            .any(|identity| credentials_equal_on_wire(&identity.credential, &request.credential));
        let configured_locally = certificates
            .iter()
            .any(|configured| certificates_equal_on_wire(configured, certificate));
        let ambient_has_raw_key = ambient_identities.iter().any(|identity| {
            matches!(
                &identity.credential,
                PublicCredential::Key(key) if key == certificate.public_key()
            )
        });
        if !ambient_has_exact_certificate && configured_locally && ambient_has_raw_key {
            translated.credential = PublicCredential::Key(certificate.public_key().clone());
        }
    }
    let mut frame = Vec::new();
    Request::SignRequest(translated).encode(&mut frame)?;
    Ok(frame)
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

fn validate_upstream_response(frame: &[u8], expected: UpstreamResponse) -> Result<()> {
    let mut input = frame;
    let response = Response::decode(&mut input).context("decode ambient agent response")?;
    if !input.is_empty() {
        bail!("trailing bytes in ambient agent response");
    }
    match (expected, response) {
        (_, Response::Failure)
        | (UpstreamResponse::Identities, Response::IdentitiesAnswer(_))
        | (UpstreamResponse::Signature, Response::SignResponse(_)) => Ok(()),
        _ => bail!("ambient agent returned an unexpected response"),
    }
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
mod tests {
    use super::*;
    use signature::Signer;
    use ssh_agent_lib::proto::{Extension, Identity};
    use ssh_agent_lib::ssh_key::private::Ed25519Keypair;
    use std::sync::mpsc;
    use std::time::Instant;

    const TEST_BROKER_CONNECTIONS: usize = 4;

    fn key(seed: u8) -> (Ed25519Keypair, KeyData) {
        let keypair = Ed25519Keypair::from_seed(&[seed; 32]);
        let public = KeyData::Ed25519(keypair.public);
        (keypair, public)
    }

    fn host_policy(user: &str, name: &str, key: KeyData) -> HostPolicy {
        let algorithm = key.algorithm().as_str().to_string();
        HostPolicy {
            login_user: user.into(),
            host_keys: vec![key],
            known_hosts_name: name.into(),
            host_key_algorithms: vec![algorithm],
            required_rsa_size: 1024,
            user_certificates: Vec::new(),
        }
    }

    fn policy(delegate: KeyData, destination: KeyData) -> BrokerPolicy {
        BrokerPolicy::new(
            host_policy("source-user", "source", delegate),
            host_policy("backup", "destination", destination),
        )
    }

    fn binding(keypair: &Ed25519Keypair, key: KeyData, id: &[u8], forwarding: bool) -> SessionBind {
        SessionBind {
            host_key: key,
            session_id: id.to_vec(),
            signature: keypair.try_sign(id).unwrap(),
            is_forwarding: forwarding,
        }
    }

    fn encode_request(request: Request) -> Vec<u8> {
        let mut encoded = Vec::new();
        request.encode(&mut encoded).unwrap();
        encoded
    }

    fn bind_request(binding: SessionBind) -> Vec<u8> {
        encode_request(Request::Extension(Extension::new_message(binding).unwrap()))
    }

    fn hostbound_data(
        session_id: &[u8],
        user: &[u8],
        method: &[u8],
        credential: &ssh_agent_lib::proto::PublicCredential,
        host_key: &KeyData,
    ) -> Vec<u8> {
        let mut credential_blob = Vec::new();
        credential.encode(&mut credential_blob).unwrap();
        let mut host_key_blob = Vec::new();
        host_key.encode(&mut host_key_blob).unwrap();
        let mut data = Vec::new();
        session_id.encode(&mut data).unwrap();
        data.push(50);
        for value in [user, b"ssh-connection", method] {
            value.encode(&mut data).unwrap();
        }
        data.push(1);
        let algorithm = match credential {
            PublicCredential::Key(key) => key.algorithm().as_str().to_string(),
            PublicCredential::Cert(certificate) => certificate.algorithm().to_certificate_type(),
        };
        algorithm.as_bytes().encode(&mut data).unwrap();
        credential_blob.as_slice().encode(&mut data).unwrap();
        host_key_blob.as_slice().encode(&mut data).unwrap();
        data
    }

    fn sign_request(
        session_id: &[u8],
        user: &[u8],
        method: &[u8],
        identity: KeyData,
        host_key: &KeyData,
    ) -> SignRequest {
        sign_request_for_credential(session_id, user, method, identity.into(), host_key)
    }

    fn sign_request_for_credential(
        session_id: &[u8],
        user: &[u8],
        method: &[u8],
        credential: PublicCredential,
        host_key: &KeyData,
    ) -> SignRequest {
        let data = hostbound_data(session_id, user, method, &credential, host_key);
        SignRequest {
            credential,
            data,
            flags: 0,
        }
    }

    fn user_certificate(subject: &KeyData, ca_seed: u8, key_id: &str) -> Certificate {
        let ca =
            ssh_agent_lib::ssh_key::PrivateKey::from(Ed25519Keypair::from_seed(&[ca_seed; 32]));
        let mut builder = ssh_agent_lib::ssh_key::certificate::Builder::new(
            vec![ca_seed; 16],
            subject.clone(),
            0,
            4_000_000_000,
        )
        .unwrap();
        builder.key_id(key_id).unwrap();
        builder.valid_principal("backup").unwrap();
        builder.sign(&ca).unwrap()
    }

    fn read_response(stream: &mut UnixStream) -> Response {
        let frame = read_frame(stream).unwrap().unwrap();
        let mut input = frame.as_slice();
        let response = Response::decode(&mut input).unwrap();
        assert!(input.is_empty());
        response
    }

    fn assert_closed(stream: &mut UnixStream) {
        let mut byte = [0];
        match stream.read(&mut byte) {
            Ok(0) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
                ) => {}
            other => panic!("agent connection was not closed: {other:?}"),
        }
    }

    fn fake_ambient(
        socket: &Path,
        identity: Ed25519Keypair,
    ) -> (JoinHandle<()>, mpsc::Receiver<Vec<u8>>) {
        let listener = UnixListener::bind(socket).unwrap();
        let (sent, received) = mpsc::channel();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            while let Some(frame) = read_frame(&mut stream).unwrap() {
                sent.send(frame.clone()).unwrap();
                let response = match frame.first() {
                    Some(27) => Response::ExtensionFailure,
                    Some(11) => Response::IdentitiesAnswer(vec![Identity {
                        credential: KeyData::Ed25519(identity.public).into(),
                        comment: "hardware-backed test key".into(),
                    }]),
                    Some(13) => {
                        let request = parse_sign_request(&frame).unwrap();
                        Response::SignResponse(identity.try_sign(&request.data).unwrap())
                    }
                    other => panic!("unexpected upstream request {other:?}"),
                };
                let mut response_frame = Vec::new();
                response.encode(&mut response_frame).unwrap();
                write_frame(&mut stream, &response_frame).unwrap();
            }
        });
        (worker, received)
    }

    #[test]
    fn parses_effective_host_lookup_and_files() {
        let output = b"host alias\nuser backup\nhostname vault.internal\nport 2222\nuserknownhostsfile /tmp/default-one /tmp/default-two\nglobalknownhostsfile none\nhostkeyalgorithms ssh-ed25519,rsa-sha2-512\nrequiredrsasize 3072\n";
        let defaults = KnownHostsDefaults {
            user: KnownHostsDefault {
                rendered: "/tmp/default-one /tmp/default-two".into(),
                files: vec!["/tmp/default-one".into(), "/tmp/default-two".into()],
            },
            global: KnownHostsDefault {
                rendered: "none".into(),
                files: Vec::new(),
            },
        };
        let config = parse_ssh_config_with_defaults(
            output,
            Some(&defaults),
            &KnownHostsConfigured::default(),
        )
        .unwrap();
        assert_eq!(config.user, "backup");
        assert_eq!(config.lookup, "[vault.internal]:2222");
        assert_eq!(config.required_rsa_size, 3072);
        assert_eq!(
            config.files,
            [
                PathBuf::from("/tmp/default-one"),
                PathBuf::from("/tmp/default-two")
            ]
        );
    }

    #[test]
    fn ambiguous_or_relative_known_hosts_filenames_fail_closed() {
        for value in ["/tmp/known hosts", "/tmp/one /tmp/two", "relative-hosts"] {
            let output = format!(
                "user backup\nhostname vault.internal\nport 22\nuserknownhostsfile {value}\nglobalknownhostsfile none\nhostkeyalgorithms ssh-ed25519\n"
            );
            let error = parse_ssh_config(output.as_bytes()).unwrap_err();
            assert!(
                error.to_string().contains("known_hosts"),
                "unexpected error for {value:?}: {error:#}"
            );
        }
    }

    #[test]
    fn configured_value_identical_to_flattened_defaults_fails_closed() {
        let rendered = "/home/grant/.ssh/known_hosts /home/grant/.ssh/known_hosts2";
        let output = format!(
            "user backup\nhostname vault.internal\nport 22\nuserknownhostsfile {rendered}\nglobalknownhostsfile none\nhostkeyalgorithms ssh-ed25519\n"
        );
        let defaults = KnownHostsDefaults {
            user: KnownHostsDefault {
                rendered: rendered.into(),
                files: vec![
                    "/home/grant/.ssh/known_hosts".into(),
                    "/home/grant/.ssh/known_hosts2".into(),
                ],
            },
            global: KnownHostsDefault {
                rendered: "none".into(),
                files: Vec::new(),
            },
        };
        let error = parse_ssh_config_with_defaults(
            output.as_bytes(),
            Some(&defaults),
            &KnownHostsConfigured {
                user: true,
                global: false,
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("ambiguous known_hosts"));
    }

    #[test]
    fn configured_known_hosts_provenance_uses_files_openssh_read() {
        let temp = tempfile::tempdir().unwrap();
        let config = temp.path().join("ssh_config");
        std::fs::write(
            &config,
            b"# GlobalKnownHostsFile /ignored/comment\nHost *\n  UserKnownHostsFile=\"/tmp/known hosts\"\n",
        )
        .unwrap();
        let debug = format!(
            "OpenSSH test\ndebug1: Reading configuration data {}\n",
            config.display()
        );
        let configured = configured_known_hosts_directives(debug.as_bytes()).unwrap();
        assert!(configured.user);
        assert!(!configured.global);
    }

    #[test]
    fn pre_required_rsa_size_config_uses_historical_default() {
        let config = parse_ssh_config(
            b"user backup\nhostname vault.internal\nport 22\nuserknownhostsfile /tmp/known\nhostkeyalgorithms ssh-ed25519\n",
        )
        .unwrap();
        assert_eq!(config.required_rsa_size, 1024);
    }

    #[test]
    fn host_key_alias_is_used_verbatim() {
        let config = parse_ssh_config(
            b"user backup\nhostname vault.internal\nport 2222\nhostkeyalias stable-vault\nuserknownhostsfile /tmp/known\nhostkeyalgorithms ssh-ed25519\nrequiredrsasize 1024\n",
        )
        .unwrap();
        assert_eq!(config.lookup, "stable-vault");
    }

    #[test]
    fn dynamic_and_external_revocation_host_policies_fail_closed() {
        for policy in [
            "knownhostscommand /usr/local/bin/known-host %h",
            "revokedhostkeys /etc/ssh/revoked.krl",
        ] {
            let config = format!(
                "user backup\nhostname vault.internal\nport 22\nuserknownhostsfile /tmp/known\nhostkeyalgorithms ssh-ed25519\nrequiredrsasize 1024\n{policy}\n"
            );
            let error = parse_ssh_config(config.as_bytes()).unwrap_err();
            assert!(error.to_string().contains("constrained agent forwarding"));
        }
    }

    #[test]
    fn host_key_algorithms_and_required_rsa_size_are_enforced() {
        use ssh_agent_lib::ssh_key::{public::RsaPublicKey, Mpint};

        let config = parse_ssh_config(
            b"user backup\nhostname vault.internal\nport 22\nuserknownhostsfile /tmp/known\nhostkeyalgorithms rsa-sha2-512\nrequiredrsasize 3072\n",
        )
        .unwrap();
        let rsa = KeyData::Rsa(RsaPublicKey {
            e: Mpint::from_positive_bytes(&[1, 0, 1]).unwrap(),
            n: Mpint::from_positive_bytes(&[0x80; 256]).unwrap(),
        });
        assert!(!configured_host_key_allowed(&config, &rsa));
        let mut config = config;
        config.required_rsa_size = 2048;
        assert!(configured_host_key_allowed(&config, &rsa));
        let (_, ed25519) = key(50);
        assert!(!configured_host_key_allowed(&config, &ed25519));
    }

    #[test]
    fn certificate_paths_expand_effective_remote_tokens() {
        let config = parse_ssh_config(
            b"user backup\nhostname vault.internal\nport 2222\nhostkeyalias stable-vault\nuserknownhostsfile /tmp/known\nhostkeyalgorithms ssh-ed25519\nrequiredrsasize 1024\nidentityfile /tmp/ignored-identity\ncertificatefile /tmp/%r@%h:%p-%k-%n-cert.pub\n",
        )
        .unwrap();
        assert_eq!(
            certificate_paths(&config, "vault-alias").unwrap(),
            [PathBuf::from(
                "/tmp/backup@vault.internal:2222-stable-vault-vault-alias-cert.pub"
            )]
        );
    }

    #[test]
    fn credential_path_environment_values_are_not_recursively_expanded() {
        let config = parse_ssh_config(
            b"user backup\nhostname vault.internal\nport 2222\nuserknownhostsfile /tmp/known\nhostkeyalgorithms ssh-ed25519\nrequiredrsasize 1024\n",
        )
        .unwrap();
        let expanded = expand_credential_path_with_env(
            "${CERT_ROOT}/%r-cert.pub",
            &config,
            "vault-alias",
            |name| {
                assert_eq!(name, "CERT_ROOT");
                Ok("/tmp/%n-${OTHER}".to_owned())
            },
        )
        .unwrap();
        assert_eq!(expanded, PathBuf::from("/tmp/%n-${OTHER}/backup-cert.pub"));
    }

    #[test]
    fn identity_file_implicitly_loads_certificate_only_without_certificate_file() {
        let temp = tempfile::tempdir().unwrap();
        let configured_identity_path = temp.path().join("%r-id_ed25519");
        let expanded_identity_path = temp.path().join("backup-id_ed25519");
        let implicit_path = PathBuf::from(format!("{}-cert.pub", expanded_identity_path.display()));
        let (_, raw_key) = key(58);
        let certificate = user_certificate(&raw_key, 59, "implicit-central-cert");
        certificate.write_file(&implicit_path).unwrap();
        let base = format!(
            "user backup\nhostname vault.internal\nport 22\nuserknownhostsfile /tmp/known\nhostkeyalgorithms ssh-ed25519\nidentityfile {}\n",
            configured_identity_path.display()
        );
        let config = parse_ssh_config(base.as_bytes()).unwrap();
        assert_eq!(
            certificate_paths(&config, "vault").unwrap(),
            [implicit_path]
        );
        let certificates =
            read_user_certificates(&certificate_paths(&config, "vault").unwrap()).unwrap();
        assert_eq!(certificates.as_slice(), std::slice::from_ref(&certificate));

        let identities = sanitize_identities(
            vec![Identity {
                credential: PublicCredential::Key(raw_key.clone()),
                comment: "YubiKey raw key".into(),
            }],
            &certificates,
        );
        assert!(!identities.advertises(&PublicCredential::Key(raw_key)));
        assert!(identities.advertises(&PublicCredential::Cert(Box::new(certificate))));

        let explicit_none =
            parse_ssh_config(format!("{base}certificatefile none\n").as_bytes()).unwrap();
        assert!(certificate_paths(&explicit_none, "vault")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn openssh_certificate_comments_do_not_break_translation() {
        let temp = tempfile::tempdir().unwrap();
        let ca = temp.path().join("ca");
        let subject = temp.path().join("subject");
        for (path, comment) in [
            (&ca, "test certificate authority"),
            (&subject, "raw key comment"),
        ] {
            let status = Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", "", "-C", comment, "-f"])
                .arg(path)
                .status()
                .expect("run ssh-keygen key generation");
            assert!(status.success(), "ssh-keygen key generation failed");
        }
        let status = Command::new("ssh-keygen")
            .args(["-q", "-s"])
            .arg(&ca)
            .args(["-I", "central-cert", "-n", "backup", "-V", "+1h"])
            .arg(subject.with_extension("pub"))
            .status()
            .expect("run ssh-keygen certificate signing");
        assert!(status.success(), "ssh-keygen certificate signing failed");

        let certificate_path = temp.path().join("subject-cert.pub");
        let configured = read_user_certificates(std::slice::from_ref(&certificate_path)).unwrap();
        assert_eq!(configured.len(), 1);
        assert!(!configured[0].comment().is_empty());
        let raw_key = PublicKey::read_openssh_file(&subject.with_extension("pub"))
            .unwrap()
            .key_data()
            .clone();
        let ambient = vec![Identity {
            credential: PublicCredential::Key(raw_key.clone()),
            comment: "ambient comment must stay private".into(),
        }];
        let identities = sanitize_identities(ambient.clone(), &configured);
        assert_eq!(identities.advertised.len(), 1);
        assert!(identities.advertised[0].comment.is_empty());

        let mut encoded = Vec::new();
        identities.advertised[0]
            .credential
            .encode(&mut encoded)
            .unwrap();
        let mut input = encoded.as_slice();
        let echoed = PublicCredential::decode(&mut input).unwrap();
        assert!(input.is_empty());
        let PublicCredential::Cert(echoed_certificate) = &echoed else {
            panic!("expected echoed user certificate")
        };
        assert!(echoed_certificate.comment().is_empty());
        assert!(identities.advertises(&echoed));

        let request = SignRequest {
            credential: echoed,
            data: b"host-bound certificate request".to_vec(),
            flags: 0,
        };
        let translated = translated_sign_request(&request, &ambient, &configured).unwrap();
        assert_eq!(
            parse_sign_request(&translated).unwrap().credential,
            PublicCredential::Key(raw_key)
        );
    }

    #[test]
    fn unsupported_opaque_algorithms_are_not_trusted_or_advertised() {
        use ssh_agent_lib::ssh_key::public::{OpaquePublicKey, SkEd25519};

        let unsupported = KeyData::Other(OpaquePublicKey::new(
            vec![1, 2, 3],
            Algorithm::new("ssh-mldsa44-ed25519@openssh.com").unwrap(),
        ));
        assert!(!key_is_cryptographically_verifiable(&unsupported));
        let config = parse_ssh_config(
            b"user backup\nhostname vault.internal\nport 22\nuserknownhostsfile /tmp/known\nhostkeyalgorithms ssh-mldsa44-ed25519@openssh.com\n",
        )
        .unwrap();
        assert!(!configured_host_key_allowed(&config, &unsupported));
        let identities = sanitize_identities(
            vec![Identity {
                credential: PublicCredential::Key(unsupported),
                comment: "unsupported experimental key".into(),
            }],
            &[],
        );
        assert!(identities.ambient.is_empty());
        assert!(identities.advertised.is_empty());
        let (supported_private, supported) = key(60);
        assert!(key_is_cryptographically_verifiable(&supported));
        assert!(signature_algorithm_is_cryptographically_verifiable(
            &Algorithm::Ed25519
        ));
        assert!(!signature_algorithm_is_cryptographically_verifiable(
            &Algorithm::Rsa { hash: None }
        ));
        let fido = KeyData::SkEd25519(SkEd25519::new(supported_private.public, "ssh:".to_string()));
        assert!(key_is_cryptographically_verifiable(&fido));
    }

    #[test]
    fn configured_certificate_is_advertised_and_translated_only_for_its_raw_key() {
        let (raw_private, raw_key) = key(61);
        let certificate = user_certificate(&raw_key, 62, "central-cert");
        let ambient = vec![Identity {
            credential: PublicCredential::Key(raw_key.clone()),
            comment: "YubiKey raw key".into(),
        }];
        let identities = sanitize_identities(ambient.clone(), std::slice::from_ref(&certificate));
        let advertised = &identities.advertised;
        assert_eq!(advertised.len(), 1);
        assert_eq!(
            advertised[0].credential,
            PublicCredential::Cert(Box::new(certificate.clone()))
        );
        assert!(!identities.advertises(&PublicCredential::Key(raw_key.clone())));

        let request = SignRequest {
            credential: PublicCredential::Cert(Box::new(certificate.clone())),
            data: b"host-bound request containing the exact certificate".to_vec(),
            flags: 0,
        };
        let translated =
            translated_sign_request(&request, &ambient, std::slice::from_ref(&certificate))
                .unwrap();
        let translated = parse_sign_request(&translated).unwrap();
        assert_eq!(
            translated.credential,
            PublicCredential::Key(raw_key.clone())
        );
        assert_eq!(translated.data, request.data);
        assert!(identities.advertises(&request.credential));
        let mut valid_response = Vec::new();
        Response::SignResponse(raw_private.try_sign(&request.data).unwrap())
            .encode(&mut valid_response)
            .unwrap();
        verify_agent_sign_response(&valid_response, &raw_key, &request.data).unwrap();
        let (wrong_private, _) = key(64);
        let mut invalid_response = Vec::new();
        Response::SignResponse(wrong_private.try_sign(&request.data).unwrap())
            .encode(&mut invalid_response)
            .unwrap();
        assert!(verify_agent_sign_response(&invalid_response, &raw_key, &request.data).is_err());

        let (source_private, source) = key(65);
        let (destination_private, destination) = key(66);
        let mut broker_policy = policy(source.clone(), destination.clone());
        broker_policy.destination.user_certificates = vec![certificate.clone()];
        let mut state = BindState::default();
        state
            .add(
                &broker_policy,
                binding(&source_private, source, b"source-cert-session", true),
            )
            .unwrap();
        state
            .add(
                &broker_policy,
                binding(
                    &destination_private,
                    destination.clone(),
                    b"destination-cert-session",
                    false,
                ),
            )
            .unwrap();
        let certificate_request = sign_request_for_credential(
            b"destination-cert-session",
            b"backup",
            b"publickey-hostbound-v00@openssh.com",
            PublicCredential::Cert(Box::new(certificate.clone())),
            &destination,
        );
        state
            .authorize(&broker_policy, &certificate_request)
            .unwrap();
        let mut mismatched_outer = certificate_request.clone();
        mismatched_outer.credential = PublicCredential::Key(raw_key.clone());
        assert!(state.authorize(&broker_policy, &mismatched_outer).is_err());

        let unrelated = user_certificate(&raw_key, 63, "not-configured");
        let request = SignRequest {
            credential: PublicCredential::Cert(Box::new(unrelated.clone())),
            data: Vec::new(),
            flags: 0,
        };
        assert!(!identities.advertises(&request.credential));
        let untranslated = translated_sign_request(&request, &ambient, &[]).unwrap();
        assert_eq!(
            parse_sign_request(&untranslated).unwrap().credential,
            request.credential
        );
    }

    #[test]
    fn failure_or_empty_identity_list_advertises_no_signing_credential() {
        let mut failure = Vec::new();
        Response::Failure.encode(&mut failure).unwrap();
        let identities = sanitize_identities(decode_identities_response(&failure).unwrap(), &[]);
        assert!(identities.advertised.is_empty());
        let (_, key) = key(67);
        assert!(!identities.advertises(&PublicCredential::Key(key)));

        let identities = sanitize_identities(Vec::new(), &[]);
        assert!(identities.advertised.is_empty());
    }

    #[test]
    fn known_hosts_parser_keeps_plain_keys_and_tracks_ca_and_revocation() {
        let (_, plain) = key(51);
        let (_, revoked_key) = key(52);
        let plain_text = PublicKey::new(plain.clone(), "").to_openssh().unwrap();
        let revoked_text = PublicKey::new(revoked_key.clone(), "")
            .to_openssh()
            .unwrap();
        let text = format!(
            "host {plain_text}\n@cert-authority host {plain_text}\n@revoked host {revoked_text}\n"
        );
        let mut trusted = Vec::new();
        let mut revoked = Vec::new();
        let mut saw_ca = false;
        parse_known_host_output(
            &text,
            Path::new("known_hosts"),
            &mut trusted,
            &mut revoked,
            &mut saw_ca,
        )
        .unwrap();
        assert_eq!(trusted, [plain]);
        assert_eq!(revoked, [revoked_key]);
        assert!(saw_ca);
        assert!(parse_known_host_output(
            &format!("@unknown host {plain_text}\n"),
            Path::new("known_hosts"),
            &mut trusted,
            &mut revoked,
            &mut saw_ca,
        )
        .is_err());
    }

    #[test]
    fn openssh_defaults_and_hashed_known_hosts_lookup_are_exercised() {
        let output = inspect_ssh_configuration("ssh", None, "unused.example", true).unwrap();
        let defaults = KnownHostsDefaults::from_openssh(&output.output).unwrap();
        assert_eq!(defaults.user.files.len(), 2);
        assert!(defaults.user.files.iter().all(|path| path.is_absolute()));
        assert!(defaults.global.files.iter().all(|path| path.is_absolute()));

        let temp = tempfile::tempdir().unwrap();
        let known_hosts = temp.path().join("known_hosts");
        let lookup = "[vault.internal]:2222";
        let (_, host_key) = key(53);
        let public = PublicKey::new(host_key.clone(), "").to_openssh().unwrap();
        std::fs::write(&known_hosts, format!("{lookup} {public}\n")).unwrap();
        let status = Command::new("ssh-keygen")
            .args(["-q", "-H", "-f"])
            .arg(&known_hosts)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("hash test known_hosts entry");
        assert!(status.success(), "ssh-keygen known_hosts hashing failed");

        let (trusted, saw_ca) = read_known_host_keys(
            &ssh_keygen_for("ssh"),
            lookup,
            std::slice::from_ref(&known_hosts),
        )
        .unwrap();
        assert_eq!(trusted, [host_key]);
        assert!(!saw_ca);
    }

    #[test]
    fn signature_algorithm_and_flags_must_match_key_blob() {
        let mut rsa = Vec::new();
        b"ssh-rsa".as_slice().encode(&mut rsa).unwrap();
        rsa.extend_from_slice(b"key fields are irrelevant here");
        validate_signature_algorithm(b"rsa-sha2-512", &rsa, 4).unwrap();
        assert!(validate_signature_algorithm(b"rsa-sha2-256", &rsa, 4).is_err());
        assert!(validate_signature_algorithm(b"ssh-rsa", &rsa, 0).is_err());
        assert!(validate_signature_algorithm(b"ssh-ed25519", &rsa, 0).is_err());
    }

    #[test]
    fn hostbound_parser_rejects_trailing_or_legacy_data() {
        let mut data = Vec::new();
        b"session".as_slice().encode(&mut data).unwrap();
        data.push(50);
        for value in [
            b"user".as_slice(),
            b"ssh-connection".as_slice(),
            b"publickey".as_slice(),
        ] {
            value.encode(&mut data).unwrap();
        }
        data.push(1);
        for value in [
            b"ssh-ed25519".as_slice(),
            b"key".as_slice(),
            b"host".as_slice(),
        ] {
            value.encode(&mut data).unwrap();
        }
        let parsed = HostboundUserauth::parse(&data).unwrap();
        assert_eq!(parsed.method, b"publickey");
        data.push(0);
        assert!(HostboundUserauth::parse(&data).is_err());
    }

    #[test]
    fn bind_state_rejects_bad_signatures_wrong_hosts_and_extra_hops() {
        let (source_private, source) = key(1);
        let (destination_private, destination) = key(2);
        let (other_private, other) = key(3);
        let policy = policy(source.clone(), destination.clone());

        let mut disallowed_algorithm = policy.clone();
        disallowed_algorithm.delegate.host_key_algorithms = vec!["rsa-sha2-512".into()];
        assert!(BindState::default()
            .add(
                &disallowed_algorithm,
                binding(
                    &source_private,
                    source.clone(),
                    b"disallowed-algorithm",
                    true,
                ),
            )
            .is_err());

        let mut state = BindState::default();
        assert!(state
            .add(
                &policy,
                binding(&other_private, source.clone(), b"bad-signature", true)
            )
            .is_err());
        assert!(state
            .add(
                &policy,
                binding(&other_private, other.clone(), b"wrong-source", true)
            )
            .is_err());
        state
            .add(
                &policy,
                binding(&source_private, source, b"source-session", true),
            )
            .unwrap();
        assert!(state
            .add(
                &policy,
                binding(&other_private, other.clone(), b"wrong-destination", false)
            )
            .is_err());
        state
            .add(
                &policy,
                binding(
                    &destination_private,
                    destination,
                    b"destination-session",
                    false,
                ),
            )
            .unwrap();
        assert!(state
            .add(&policy, binding(&other_private, other, b"third-hop", true))
            .is_err());
    }

    #[test]
    fn authorization_is_exact_for_user_session_host_and_method() {
        let (source_private, source) = key(11);
        let (destination_private, destination) = key(12);
        let (_, identity) = key(13);
        let (_, other_host) = key(14);
        let policy = policy(source.clone(), destination.clone());
        let mut state = BindState::default();
        state
            .add(
                &policy,
                binding(&source_private, source, b"source-session", true),
            )
            .unwrap();
        state
            .add(
                &policy,
                binding(
                    &destination_private,
                    destination.clone(),
                    b"destination-session",
                    false,
                ),
            )
            .unwrap();

        let allowed = sign_request(
            b"destination-session",
            b"backup",
            b"publickey-hostbound-v00@openssh.com",
            identity.clone(),
            &destination,
        );
        state.authorize(&policy, &allowed).unwrap();
        for denied in [
            sign_request(
                b"other-session",
                b"backup",
                b"publickey-hostbound-v00@openssh.com",
                identity.clone(),
                &destination,
            ),
            sign_request(
                b"destination-session",
                b"root",
                b"publickey-hostbound-v00@openssh.com",
                identity.clone(),
                &destination,
            ),
            sign_request(
                b"destination-session",
                b"backup",
                b"publickey",
                identity.clone(),
                &destination,
            ),
            sign_request(
                b"destination-session",
                b"backup",
                b"publickey-hostbound-v00@openssh.com",
                identity,
                &other_host,
            ),
        ] {
            assert!(state.authorize(&policy, &denied).is_err());
        }
    }

    #[test]
    fn broker_forwards_only_list_and_fully_bound_sign_requests() {
        let temp = tempfile::tempdir().unwrap();
        let ambient_socket = temp.path().join("ambient.sock");
        let (identity_private, identity) = key(23);
        let (ambient, requests) = fake_ambient(&ambient_socket, identity_private.clone());
        let (source_private, source) = key(21);
        let (destination_private, destination) = key(22);
        let broker = ConstrainedAgentBroker::start_with_socket(
            ambient_socket,
            policy(source.clone(), destination.clone()),
            TEST_BROKER_CONNECTIONS,
        )
        .unwrap();
        let broker_path = broker.socket_path().to_path_buf();
        assert_eq!(
            std::fs::metadata(&broker_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let mut client = UnixStream::connect(&broker_path).unwrap();

        let source_bind = bind_request(binding(&source_private, source, b"source-session", true));
        write_frame(&mut client, &source_bind).unwrap();
        assert!(matches!(read_response(&mut client), Response::Success));

        write_frame(&mut client, &[11]).unwrap();
        let Response::IdentitiesAnswer(identities) = read_response(&mut client) else {
            panic!("expected identities response")
        };
        assert_eq!(identities.len(), 1);
        assert!(identities[0].comment.is_empty());
        assert_eq!(requests.recv().unwrap(), source_bind);
        assert_eq!(requests.recv().unwrap(), vec![11]);

        let destination_bind = bind_request(binding(
            &destination_private,
            destination.clone(),
            b"destination-session",
            false,
        ));
        write_frame(&mut client, &destination_bind).unwrap();
        assert!(matches!(read_response(&mut client), Response::Success));
        assert_eq!(requests.recv().unwrap(), destination_bind);
        let request = sign_request(
            b"destination-session",
            b"backup",
            b"publickey-hostbound-v00@openssh.com",
            identity,
            &destination,
        );
        let encoded = encode_request(Request::SignRequest(request.clone()));
        write_frame(&mut client, &encoded).unwrap();
        let Response::SignResponse(signature) = read_response(&mut client) else {
            panic!("expected signature response")
        };
        assert_eq!(signature, identity_private.try_sign(&request.data).unwrap());
        assert_eq!(requests.recv().unwrap(), encoded);

        let (_, unadvertised) = key(24);
        let request = sign_request(
            b"destination-session",
            b"backup",
            b"publickey-hostbound-v00@openssh.com",
            unadvertised,
            &destination,
        );
        write_frame(&mut client, &encode_request(Request::SignRequest(request))).unwrap();
        assert!(matches!(read_response(&mut client), Response::Failure));
        assert_closed(&mut client);
        assert!(requests.try_recv().is_err());

        drop(client);
        drop(broker);
        ambient.join().unwrap();
        assert!(!broker_path.exists());
    }

    #[test]
    fn failed_identity_list_cannot_be_followed_by_signing() {
        let temp = tempfile::tempdir().unwrap();
        let ambient_socket = temp.path().join("ambient.sock");
        let listener = UnixListener::bind(&ambient_socket).unwrap();
        let (sent, requests) = mpsc::channel();
        let ambient = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            while let Some(frame) = read_frame(&mut stream).unwrap() {
                sent.send(frame.clone()).unwrap();
                let response = match frame.first() {
                    Some(27) => Response::ExtensionFailure,
                    Some(11) => Response::Failure,
                    other => panic!("unexpected upstream request {other:?}"),
                };
                let mut response_frame = Vec::new();
                response.encode(&mut response_frame).unwrap();
                write_frame(&mut stream, &response_frame).unwrap();
            }
        });
        let (source_private, source) = key(25);
        let (destination_private, destination) = key(26);
        let (_, identity) = key(27);
        let broker = ConstrainedAgentBroker::start_with_socket(
            ambient_socket,
            policy(source.clone(), destination.clone()),
            TEST_BROKER_CONNECTIONS,
        )
        .unwrap();
        let mut client = UnixStream::connect(broker.socket_path()).unwrap();

        let source_bind = bind_request(binding(
            &source_private,
            source,
            b"source-failed-list",
            true,
        ));
        write_frame(&mut client, &source_bind).unwrap();
        assert!(matches!(read_response(&mut client), Response::Success));
        write_frame(&mut client, &[11]).unwrap();
        let Response::IdentitiesAnswer(identities) = read_response(&mut client) else {
            panic!("expected sanitized empty identities response")
        };
        assert!(identities.is_empty());
        assert_eq!(requests.recv().unwrap(), source_bind);
        assert_eq!(requests.recv().unwrap(), vec![11]);

        let destination_bind = bind_request(binding(
            &destination_private,
            destination.clone(),
            b"destination-failed-list",
            false,
        ));
        write_frame(&mut client, &destination_bind).unwrap();
        assert!(matches!(read_response(&mut client), Response::Success));
        assert_eq!(requests.recv().unwrap(), destination_bind);
        let request = sign_request(
            b"destination-failed-list",
            b"backup",
            b"publickey-hostbound-v00@openssh.com",
            identity,
            &destination,
        );
        write_frame(&mut client, &encode_request(Request::SignRequest(request))).unwrap();
        assert!(matches!(read_response(&mut client), Response::Failure));
        assert_closed(&mut client);
        assert!(requests.try_recv().is_err());

        drop(client);
        drop(broker);
        ambient.join().unwrap();
    }

    #[test]
    fn unbound_sign_mutation_unknown_extension_and_oversize_never_reach_ambient() {
        let temp = tempfile::tempdir().unwrap();
        let ambient_socket = temp.path().join("ambient.sock");
        let _ambient = UnixListener::bind(&ambient_socket).unwrap();
        let (_, source) = key(31);
        let (_, destination) = key(32);
        let (_, identity) = key(33);
        let broker = ConstrainedAgentBroker::start_with_socket(
            ambient_socket,
            policy(source, destination.clone()),
            TEST_BROKER_CONNECTIONS,
        )
        .unwrap();

        let request = sign_request(
            b"unbound-session",
            b"backup",
            b"publickey-hostbound-v00@openssh.com",
            identity,
            &destination,
        );
        let cases = [
            (encode_request(Request::SignRequest(request)), false),
            (vec![11], false),
            (vec![17], false),
            (
                encode_request(Request::Extension(Extension {
                    name: "query".into(),
                    details: Vec::new().into(),
                })),
                true,
            ),
        ];
        for (request, extension_failure) in cases {
            let mut client = UnixStream::connect(broker.socket_path()).unwrap();
            write_frame(&mut client, &request).unwrap();
            let response = read_response(&mut client);
            assert!(
                matches!(response, Response::ExtensionFailure) == extension_failure,
                "unexpected response: {response:?}"
            );
            assert!(read_frame(&mut client).unwrap().is_none());
        }

        let mut oversized = UnixStream::connect(broker.socket_path()).unwrap();
        oversized
            .write_all(&((MAX_AGENT_FRAME as u32) + 1).to_be_bytes())
            .unwrap();
        assert!(read_frame(&mut oversized).unwrap().is_none());
    }

    #[test]
    fn broker_bounds_idle_clients_and_drop_closes_them() {
        let temp = tempfile::tempdir().unwrap();
        let ambient_socket = temp.path().join("ambient.sock");
        let _ambient = UnixListener::bind(&ambient_socket).unwrap();
        let (_, source) = key(41);
        let (_, destination) = key(42);
        let broker = ConstrainedAgentBroker::start_with_socket(
            ambient_socket,
            policy(source, destination),
            TEST_BROKER_CONNECTIONS,
        )
        .unwrap();
        let path = broker.socket_path().to_path_buf();
        let mut clients = Vec::new();
        for _ in 0..TEST_BROKER_CONNECTIONS {
            let mut client = UnixStream::connect(&path).unwrap();
            client.write_all(&[0]).unwrap(); // keep each worker waiting on its header
            clients.push(client);
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while broker
            .connections
            .streams
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
            < TEST_BROKER_CONNECTIONS
            && Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            broker
                .connections
                .streams
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .len(),
            TEST_BROKER_CONNECTIONS
        );
        let mut excess = UnixStream::connect(&path).unwrap();
        excess
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        excess.write_all(&[0]).unwrap();
        assert_closed(&mut excess);

        drop(broker);
        assert!(!path.exists());
        for mut client in clients {
            client
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            assert_closed(&mut client);
        }
    }

    #[test]
    fn tracked_broker_connections_have_bounded_io() {
        let (stream, _peer) = UnixStream::pair().unwrap();
        let registry = Arc::new(ConnectionRegistry::default());
        let tracked = registry.track(stream).unwrap();
        assert_eq!(
            tracked.stream.read_timeout().unwrap(),
            Some(BROKER_IO_TIMEOUT)
        );
        assert_eq!(
            tracked.stream.write_timeout().unwrap(),
            Some(BROKER_IO_TIMEOUT)
        );
    }
}

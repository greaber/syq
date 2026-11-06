//! Restricted-receiver enrollment primitives.
//!
//! This module keeps the security-sensitive authorized-keys representation
//! and safe end-to-end SSH route independent from the user-facing lifecycle in
//! `restricted`. The separation lets enrollment reuse these narrow primitives
//! without making free-form shell commands part of the authorization model.
//!
//! The caller owns the filesystem and private-key boundary: it must generate a
//! dedicated private key with a CSPRNG, store it in a trusted private
//! directory with mode 0600, and replace `authorized_keys` atomically without
//! following symlinks while preserving the target account's ownership and
//! StrictModes-compatible permissions. `restricted` implements that contract.

use anyhow::{bail, Context, Result};
#[cfg(test)]
use base64::Engine as _;
use std::path::{Component, Path};

const ENROLLMENT_ID_BYTES: usize = 16;
const COMMENT_PREFIX: &str = "syq-enrollment:";

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EnrollmentId(pub(crate) [u8; ENROLLMENT_ID_BYTES]);

impl EnrollmentId {
    #[cfg(test)]
    pub(crate) fn test_v4(last: u8) -> Self {
        let mut bytes = [0u8; ENROLLMENT_ID_BYTES];
        bytes[6] = 0x40;
        bytes[8] = 0x80;
        bytes[15] = last;
        Self(bytes)
    }

    pub fn parse(value: &str) -> Result<Self> {
        if value.len() != ENROLLMENT_ID_BYTES * 2
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            bail!(
                "enrollment ID must be {} lowercase hexadecimal characters",
                ENROLLMENT_ID_BYTES * 2
            );
        }
        let mut bytes = [0u8; ENROLLMENT_ID_BYTES];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
                .expect("lowercase hexadecimal enrollment ID");
        }
        let version = bytes[6] >> 4;
        if bytes[8] & 0xc0 != 0x80 || !(1..=8).contains(&version) {
            bail!("enrollment ID must be an RFC 4122 UUID");
        }
        Ok(Self(bytes))
    }

    pub fn random() -> Self {
        let mut bytes = crate::tcp_records::random_bytes(ENROLLMENT_ID_BYTES);
        // RFC 4122 variant, randomly generated (version 4).  The on-wire and
        // authorized_keys spelling stays compact lowercase hexadecimal.
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        Self(bytes.try_into().expect("fixed enrollment ID length"))
    }

    pub(crate) fn validate(self) -> Result<()> {
        let version = self.0[6] >> 4;
        if self.0[8] & 0xc0 != 0x80 || !(1..=8).contains(&version) {
            bail!("enrollment ID must be an RFC 4122 UUID");
        }
        Ok(())
    }

    fn marker(&self) -> String {
        format!("{COMMENT_PREFIX}{self}")
    }
}

impl std::fmt::Display for EnrollmentId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrollmentPublicKey {
    algorithm: String,
    blob: String,
}

impl EnrollmentPublicKey {
    /// Parse a dedicated enrollment key. Certificates and obsolete algorithms
    /// are not enrollment credentials.
    pub fn parse(line: &str) -> Result<Self> {
        let key =
            ssh_key::PublicKey::from_openssh(line).context("invalid enrollment public key")?;
        use ssh_key::Algorithm;
        match key.algorithm() {
            Algorithm::Ed25519
            | Algorithm::Ecdsa { .. }
            | Algorithm::SkEd25519
            | Algorithm::SkEcdsaSha2NistP256 => {}
            Algorithm::Rsa { .. } => {
                let n = key
                    .key_data()
                    .rsa()
                    .context("RSA key")?
                    .n
                    .as_positive_bytes()
                    .context("invalid RSA modulus")?;
                let bits = n
                    .first()
                    .map_or(0, |first| n.len() * 8 - first.leading_zeros() as usize);
                if bits < 3072 {
                    bail!("enrollment RSA key must be at least 3072 bits");
                }
            }
            _ => bail!("unsupported enrollment key algorithm"),
        }
        let encoded = key.to_openssh()?;
        let mut words = encoded.split_ascii_whitespace();
        Ok(Self {
            algorithm: words.next().context("key algorithm")?.to_owned(),
            blob: words.next().context("key blob")?.to_owned(),
        })
    }
}

impl EnrollmentPublicKey {
    /// The login key an enrollment trusts, as syq's line names it in its
    /// comment. Any key that can sign a grant qualifies.
    pub(crate) fn login(line: &str) -> Result<Self> {
        let key = ssh_key::PublicKey::from_openssh(line).context("invalid login public key")?;
        use ssh_key::Algorithm;
        if !matches!(
            key.algorithm(),
            Algorithm::Ed25519
                | Algorithm::Ecdsa { .. }
                | Algorithm::Rsa { .. }
                | Algorithm::SkEd25519
                | Algorithm::SkEcdsaSha2NistP256
        ) {
            bail!("unsupported login key algorithm");
        }
        let encoded = ssh_key::PublicKey::new(key.key_data().clone(), "").to_openssh()?;
        let mut words = encoded.split_ascii_whitespace();
        Ok(Self {
            algorithm: words.next().context("key algorithm")?.to_owned(),
            blob: words.next().context("key blob")?.to_owned(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedKeyEntry {
    marker: String,
    key: EnrollmentPublicKey,
    line: String,
}

impl AuthorizedKeyEntry {
    /// Syq's line for an enrollment. The entry key can only start the
    /// receiver release at `receiver_path`, at `generation`; the comment
    /// names the login key the enrollment trusts, so removing every line that
    /// contains that key removes this one too.
    pub(crate) fn enrollment(
        id: EnrollmentId,
        receiver_path: &Path,
        generation: u64,
        entry_key: &EnrollmentPublicKey,
        signer: &EnrollmentPublicKey,
    ) -> Result<Self> {
        let receiver = safe_receiver_path(receiver_path)?;
        if generation == 0 {
            bail!("enrollment generations start at 1");
        }
        let command =
            format!("{receiver} --restricted-receiver --enrollment={id} --generation={generation}");
        let line = format!(
            "restrict,command=\"{command}\" {} {} {} signer {} {}",
            entry_key.algorithm,
            entry_key.blob,
            id.marker(),
            signer.algorithm,
            signer.blob,
        );
        Ok(Self {
            marker: id.marker(),
            key: entry_key.clone(),
            line,
        })
    }

    pub fn line(&self) -> &str {
        &self.line
    }

    pub fn marker(&self) -> String {
        self.marker.clone()
    }
}

fn safe_receiver_path(path: &Path) -> Result<String> {
    if !path.is_absolute() {
        bail!("restricted receiver path must be absolute");
    }
    for component in path.components() {
        match component {
            Component::RootDir | Component::Normal(_) => {}
            _ => bail!("restricted receiver path must not contain . or .. components"),
        }
    }
    let value = path
        .to_str()
        .context("restricted receiver path is not valid UTF-8")?;
    if value.is_empty()
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-' | b'+')
        })
    {
        bail!("restricted receiver path contains shell-sensitive characters");
    }
    Ok(value.to_owned())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorizedKeysChange {
    Unchanged,
    Installed,
    Revoked,
}

/// Whether `line` names `token` as one of its words.
fn has_word(line: &[u8], token: &[u8]) -> bool {
    line.split(|byte| byte.is_ascii_whitespace())
        .any(|word| word == token)
}

fn comment_line(line: &[u8]) -> bool {
    line.iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
        .is_none_or(|byte| byte == b'#')
}

/// Make `entry` the enrollment's one line, replacing the line it had before
/// (which must hold the same entry key) without touching other lines.
/// Comment lines are not authorizations and are left alone.
pub(crate) fn set_enrollment_line(
    original: &[u8],
    entry: &AuthorizedKeyEntry,
) -> Result<(Vec<u8>, AuthorizedKeysChange)> {
    let marker = entry.marker();
    let mut updated = Vec::with_capacity(original.len() + entry.line().len() + 1);
    let mut found = 0usize;
    let mut exact = false;
    for raw in original.split_inclusive(|byte| *byte == b'\n') {
        let line = raw.strip_suffix(b"\n").unwrap_or(raw);
        if comment_line(line) {
            updated.extend_from_slice(raw);
            continue;
        }
        if has_word(line, marker.as_bytes()) {
            if !line_contains_enrollment_key(line, &entry.key) {
                bail!("authorized_keys has a different line for {marker}; remove it, then retry");
            }
            found += 1;
            exact |= line == entry.line().as_bytes();
            continue;
        }
        if line_contains_enrollment_key(line, &entry.key) {
            bail!("the enrollment's entry key is also authorized by another authorized_keys line");
        }
        updated.extend_from_slice(raw);
    }
    if found > 1 {
        bail!("authorized_keys has several lines for {marker}; remove them, then retry");
    }
    if exact {
        return Ok((original.to_vec(), AuthorizedKeysChange::Unchanged));
    }
    if !updated.is_empty() && !updated.ends_with(b"\n") {
        updated.push(b'\n');
    }
    updated.extend_from_slice(entry.line().as_bytes());
    updated.push(b'\n');
    Ok((updated, AuthorizedKeysChange::Installed))
}

/// Remove the enrollment's line, found by its marker and entry key. A
/// missing line is an idempotent no-op; a marker on a line with another key,
/// or the entry key on another line, fails instead of guessing.
pub(crate) fn remove_enrollment_line(
    original: &[u8],
    id: EnrollmentId,
    entry_key: &EnrollmentPublicKey,
) -> Result<(Vec<u8>, AuthorizedKeysChange)> {
    let marker = id.marker();
    let mut updated = Vec::with_capacity(original.len());
    let mut found = 0usize;
    for raw in original.split_inclusive(|byte| *byte == b'\n') {
        let line = raw.strip_suffix(b"\n").unwrap_or(raw);
        if comment_line(line) {
            updated.extend_from_slice(raw);
            continue;
        }
        let ours = has_word(line, marker.as_bytes());
        let keyed = line_contains_enrollment_key(line, entry_key);
        match (ours, keyed) {
            (true, true) => found += 1,
            (true, false) => {
                bail!("authorized_keys has a different line for {marker}; refusing to remove it")
            }
            (false, true) => bail!(
                "the enrollment's entry key is also authorized by another authorized_keys line; refusing to remove it"
            ),
            (false, false) => updated.extend_from_slice(raw),
        }
    }
    if found > 1 {
        bail!("authorized_keys has several lines for {marker}; remove them by hand");
    }
    Ok(if found == 0 {
        (original.to_vec(), AuthorizedKeysChange::Unchanged)
    } else {
        (updated, AuthorizedKeysChange::Revoked)
    })
}

fn line_contains_enrollment_key(line: &[u8], key: &EnrollmentPublicKey) -> bool {
    let mut words = line
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|word| !word.is_empty());
    let algorithm = key.algorithm.as_bytes();
    let blob = key.blob.as_bytes();
    while let Some(word) = words.next() {
        if word == algorithm && words.next() == Some(blob) {
            return true;
        }
    }
    false
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshEndpoint {
    target: String,
    port: Option<u16>,
}

impl SshEndpoint {
    /// Parse the deliberately narrow endpoint syntax accepted by automatic
    /// enrollment. Ports and unusual SSH routing belong in trusted ssh_config;
    /// accepting free-form destination text here would make OpenSSH's
    /// ProxyCommand expansion a shell-injection boundary.
    pub fn parse(value: &str) -> Result<Self> {
        let (user, host) = match value.split_once('@') {
            Some((user, host)) if !host.contains('@') => (Some(user), host),
            Some(_) => bail!("enrollment endpoint contains more than one @"),
            None => (None, value),
        };
        if user.is_some_and(|user| !safe_ssh_name(user)) || !safe_ssh_name(host) {
            bail!(
                "enrollment endpoint must be [user@]host using only letters, digits, dot, underscore, and hyphen"
            );
        }
        if host == "none" {
            bail!("none is not an enrollment host");
        }
        Ok(Self {
            target: value.to_owned(),
            port: None,
        })
    }

    /// Construct an endpoint already split by the native endpoint parser.
    /// Arguments are still passed to OpenSSH as distinct words; `target` is
    /// quoted separately if it must appear inside a ProxyCommand.
    pub(crate) fn from_parts(user: &str, host: &str, port: Option<u16>) -> Result<Self> {
        if user.is_empty()
            || host.is_empty()
            || user
                .bytes()
                .any(|byte| byte == 0 || byte.is_ascii_whitespace())
            || host
                .bytes()
                .any(|byte| byte == 0 || byte.is_ascii_whitespace())
        {
            bail!("invalid native enrollment endpoint");
        }
        Ok(Self {
            // OpenSSH takes a literal IPv6 address without URI-style
            // brackets. Brackets belong only in syq's endpoint grammar and
            // human-facing labels; -p carries the port separately.
            target: format!("{user}@{host}"),
            port,
        })
    }

    /// An endpoint whose login the SSH configuration may choose.
    pub(crate) fn from_host(user: Option<&str>, host: &str, port: Option<u16>) -> Result<Self> {
        match user {
            Some(user) => Self::from_parts(user, host, port),
            None => {
                if host.is_empty()
                    || host.starts_with('-')
                    || host
                        .bytes()
                        .any(|byte| byte == 0 || byte == b'@' || byte.is_ascii_whitespace())
                {
                    bail!("invalid native enrollment endpoint");
                }
                Ok(Self {
                    target: host.to_owned(),
                    port,
                })
            }
        }
    }

    pub fn as_str(&self) -> &str {
        &self.target
    }

    /// What `ssh -G` needs after its options to resolve this endpoint.
    pub(crate) fn query_arguments(&self) -> Vec<String> {
        let mut args = Vec::new();
        self.append_connection_args(&mut args);
        args
    }

    pub(crate) fn label(&self) -> String {
        let target = match self.target.rsplit_once('@') {
            Some((user, host)) if host.contains(':') => format!("{user}@[{host}]"),
            _ => self.target.clone(),
        };
        match self.port {
            Some(port) => format!("{target}:{port}"),
            None => target,
        }
    }

    fn append_connection_args(&self, args: &mut Vec<String>) {
        if let Some(port) = self.port {
            args.extend(["-p".to_owned(), port.to_string()]);
        }
        args.extend(["--".to_owned(), self.target.clone()]);
    }

    fn proxy_target(&self) -> String {
        let mut words = Vec::new();
        if let Some(port) = self.port {
            words.extend(["-p".to_owned(), port.to_string()]);
        }
        words.extend(["--".to_owned(), self.target.clone()]);
        // OpenSSH expands percent tokens even inside shell quotes. Escape
        // literal endpoint bytes before inserting them in ProxyCommand.
        shell_words::join(words).replace('%', "%%")
    }
}

fn safe_ssh_name(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrollmentRemoteCommand(String);

impl EnrollmentRemoteCommand {
    /// Construct shell source only from a validated absolute program and
    /// individually quoted arguments. sshd always invokes remote commands via
    /// the account's shell, even when the local process supplied one argv.
    pub fn new(program: &Path, args: &[String]) -> Result<Self> {
        let program = safe_receiver_path(program)?;
        if args.iter().any(|arg| arg.bytes().any(|byte| byte == 0)) {
            bail!("enrollment command argument contains NUL");
        }
        let mut words = Vec::with_capacity(args.len() + 1);
        words.push(program);
        words.extend(args.iter().cloned());
        Ok(Self(shell_words::join(words)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnrollmentRoute<'a> {
    /// The way the user's SSH configuration routes `ssh` to the account,
    /// its jump hosts and proxy commands included: the user's own login,
    /// as plain `ssh` makes it.
    Configured,
    /// Through `jump`, which receives only an opaque TCP stream, in place of
    /// any route the configuration gives.
    ProxyJump { jump: &'a SshEndpoint },
}

/// A login nobody is watching, such as the receiving service's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Unattended {
    /// The SSH configuration would ask about a host key it does not know,
    /// which nobody can answer: accept a new one the first time, as
    /// `accept-new` does.
    pub login_accepts_new: bool,
    /// The same, for the jump syq makes.
    pub jump_accepts_new: bool,
}

/// What an unattended login adds ahead of the user's configuration, for
/// itself and for a jump syq makes: never prompt, and give up on a server
/// that stops answering. Host keys are checked as the configuration says.
const BACKGROUND_LOGIN: [&str; 4] = [
    "BatchMode=yes",
    "ConnectTimeout=10",
    "ServerAliveInterval=15",
    "ServerAliveCountMax=3",
];

/// Whether `ssh -G` output says `StrictHostKeyChecking ask`, the default:
/// someone would have to answer about a host key nobody knows.
pub(crate) fn asks_about_new_host_keys(config: &[u8]) -> bool {
    String::from_utf8_lossy(config)
        .lines()
        .any(|line| line.trim() == "stricthostkeychecking ask")
}

/// Arguments for the trusted local OpenSSH client that enrolls HostB.  A jump
/// host receives only an opaque TCP stream; it never receives an agent socket
/// or an authenticated HostB session.
pub fn enrollment_ssh_args(
    target: &SshEndpoint,
    route: EnrollmentRoute<'_>,
    remote_command: &EnrollmentRemoteCommand,
) -> Vec<String> {
    enrollment_ssh_args_raw(target, route, remote_command.as_str(), None)
}

/// `unattended`: nobody is watching this login.
pub(crate) fn enrollment_ssh_args_raw(
    target: &SshEndpoint,
    route: EnrollmentRoute<'_>,
    remote_command: &str,
    unattended: Option<Unattended>,
) -> Vec<String> {
    // SSH takes the first value of each option, and the command line's
    // before its configuration's.
    let policy = |accepts_new: bool| -> Vec<&str> {
        match unattended {
            None => Vec::new(),
            Some(_) => BACKGROUND_LOGIN
                .into_iter()
                .chain(accepts_new.then_some("StrictHostKeyChecking=accept-new"))
                .collect(),
        }
    };
    let mut args: Vec<String> = policy(unattended.is_some_and(|login| login.login_accepts_new))
        .into_iter()
        .flat_map(|option| ["-o".to_owned(), option.to_owned()])
        .collect();
    args.extend([
        "-a".to_owned(),
        "-x".to_owned(),
        "-k".to_owned(),
        "-T".to_owned(),
        "-o".to_owned(),
        "ClearAllForwardings=yes".to_owned(),
        "-o".to_owned(),
        "ControlMaster=no".to_owned(),
        "-o".to_owned(),
        "ControlPath=none".to_owned(),
        "-o".to_owned(),
        "ForwardX11=no".to_owned(),
        "-o".to_owned(),
        "PermitLocalCommand=no".to_owned(),
    ]);
    match route {
        // A jump or proxy the configuration names carries only the TCP
        // stream; this login stays end to end with hostB, which it checks
        // against the host keys the user trusts.
        EnrollmentRoute::Configured => {}
        EnrollmentRoute::ProxyJump { jump } => {
            // -J does not apply destination command-line safety options to its
            // implicit jump process. A fixed ProxyCommand lets us constrain that
            // process explicitly while the inner SSH connection remains local and
            // end-to-end with HostB.
            // A login nobody is watching passes its policy on: OpenSSH gives
            // its proxy command none of its own options.
            let policy: String = policy(unattended.is_some_and(|login| login.jump_accepts_new))
                .into_iter()
                .map(|option| format!(" -o {option}"))
                .collect();
            args.push("-o".to_owned());
            args.push(format!(
                "ProxyCommand=ssh -a -x -k -T{policy} -o ClearAllForwardings=yes -o ControlMaster=no -o ControlPath=none -o ForwardX11=no -o PermitLocalCommand=no -W '[%h]:%p' {}",
                jump.proxy_target()
            ));
        }
    }
    target.append_connection_args(&mut args);
    args.push(remote_command.to_owned());
    args
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> EnrollmentPublicKey {
        const ED25519_ALGORITHM: &str = "ssh-ed25519";
        const ED25519_KEY_BYTES: usize = 32;
        let mut blob = Vec::new();
        for value in [ED25519_ALGORITHM.as_bytes(), &[7u8; ED25519_KEY_BYTES]] {
            blob.extend_from_slice(&(value.len() as u32).to_be_bytes());
            blob.extend_from_slice(value);
        }
        EnrollmentPublicKey::parse(&format!(
            "{ED25519_ALGORITHM} {} ignored-comment",
            base64::engine::general_purpose::STANDARD.encode(blob)
        ))
        .unwrap()
    }

    fn id() -> EnrollmentId {
        EnrollmentId::parse("00112233445566778899aabbccddeeff").unwrap()
    }

    fn login() -> EnrollmentPublicKey {
        let mut blob = Vec::new();
        for value in [b"ssh-ed25519".as_slice(), &[9u8; 32]] {
            blob.extend_from_slice(&(value.len() as u32).to_be_bytes());
            blob.extend_from_slice(value);
        }
        EnrollmentPublicKey::login(&format!(
            "ssh-ed25519 {} user@laptop",
            base64::engine::general_purpose::STANDARD.encode(blob)
        ))
        .unwrap()
    }

    fn enrollment_entry(generation: u64) -> AuthorizedKeyEntry {
        AuthorizedKeyEntry::enrollment(
            id(),
            Path::new("/opt/syq/receiver"),
            generation,
            &key(),
            &login(),
        )
        .unwrap()
    }

    #[test]
    fn enrollment_ids_are_rfc_4122_uuids() {
        let generated = EnrollmentId::random();
        let generated = generated.to_string();
        assert_eq!(generated.as_bytes()[12], b'4');
        assert!(matches!(generated.as_bytes()[16], b'8'..=b'9' | b'a'..=b'b'));
        assert!(EnrollmentId::parse("00112233445566770899aabbccddeeff").is_err());
        assert!(EnrollmentId::parse("00112233445566774899aabbccddeeff").is_err());
    }

    #[test]
    fn enrollment_line_starts_only_the_receiver_and_names_its_signer() {
        let entry = AuthorizedKeyEntry::enrollment(
            id(),
            Path::new("/home/backup/.local/lib/syq/v0.8.0/linux-x86_64/syq"),
            3,
            &key(),
            &login(),
        )
        .unwrap();
        assert!(entry.line().starts_with(
            "restrict,command=\"/home/backup/.local/lib/syq/v0.8.0/linux-x86_64/syq --restricted-receiver --enrollment=00112233445566778899aabbccddeeff --generation=3\" ssh-ed25519 "
        ));
        assert!(entry.line().ends_with(&format!(
            " syq-enrollment:00112233445566778899aabbccddeeff signer {} {}",
            login().algorithm,
            login().blob
        )));
        // Removing every line that contains the login key removes this one.
        assert!(line_contains_enrollment_key(
            entry.line().as_bytes(),
            &login()
        ));
        assert!(
            AuthorizedKeyEntry::enrollment(id(), Path::new("/opt/syq"), 0, &key(), &login())
                .is_err()
        );
    }

    #[test]
    fn entry_rejects_shell_sensitive_receiver_paths() {
        let error = AuthorizedKeyEntry::enrollment(
            id(),
            Path::new("/home/backup/bad path/syq"),
            1,
            &key(),
            &login(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("shell-sensitive"));
    }

    #[test]
    fn enrollment_key_parser_checks_the_wire_blob() {
        let mut bad = Vec::new();
        bad.extend_from_slice(&11u32.to_be_bytes());
        bad.extend_from_slice(b"ssh-ed25519");
        bad.extend_from_slice(&31u32.to_be_bytes());
        bad.extend_from_slice(&[0u8; 31]);
        let error = EnrollmentPublicKey::parse(&format!(
            "ssh-ed25519 {}",
            base64::engine::general_purpose::STANDARD.encode(bad)
        ))
        .unwrap_err();
        assert!(error.to_string().contains("invalid enrollment public key"));
    }

    #[test]
    fn enrollment_line_replaces_its_own_previous_line_only() {
        let first = enrollment_entry(1);
        let original = b"# administrator \xff comment\nssh-ed25519 AAAA existing\n";
        let (installed, change) = set_enrollment_line(original, &first).unwrap();
        assert_eq!(change, AuthorizedKeysChange::Installed);
        assert!(installed.starts_with(original));
        assert_eq!(
            set_enrollment_line(&installed, &first).unwrap(),
            (installed.clone(), AuthorizedKeysChange::Unchanged)
        );
        // A refresh replaces the line in place of the old one.
        let second = enrollment_entry(2);
        let (refreshed, change) = set_enrollment_line(&installed, &second).unwrap();
        assert_eq!(change, AuthorizedKeysChange::Installed);
        assert_eq!(
            refreshed,
            [original.as_slice(), second.line().as_bytes(), b"\n"].concat()
        );
        // A comment that mentions the enrollment is not an authorization.
        let commented = [b"# ".as_slice(), first.line().as_bytes(), b"\n", &refreshed].concat();
        let (kept, _) = set_enrollment_line(&commented, &second).unwrap();
        assert_eq!(kept, commented);
    }

    #[test]
    fn enrollment_line_refuses_conflicts_and_removal_is_exact() {
        let entry = enrollment_entry(1);
        // Another line with the marker but another key, or two lines.
        let foreign = format!(
            "restrict,command=\"evil\" ssh-ed25519 AAAA {}\n",
            id().marker()
        );
        assert!(set_enrollment_line(foreign.as_bytes(), &entry)
            .unwrap_err()
            .to_string()
            .contains("different line"));
        let twice = format!("{0}\n{0}\n", entry.line());
        assert!(set_enrollment_line(twice.as_bytes(), &entry).is_err());
        assert!(remove_enrollment_line(twice.as_bytes(), id(), &key()).is_err());
        // The entry key authorized without restriction elsewhere.
        let unrestricted = format!("{} {} administrator\n", key().algorithm, key().blob);
        assert!(set_enrollment_line(unrestricted.as_bytes(), &entry).is_err());
        let both = format!("{}\n{unrestricted}", entry.line());
        assert!(remove_enrollment_line(both.as_bytes(), id(), &key())
            .unwrap_err()
            .to_string()
            .contains("also authorized"));
        assert!(remove_enrollment_line(foreign.as_bytes(), id(), &key()).is_err());

        let original = format!("before\n{}\nafter\n", entry.line());
        let (updated, change) = remove_enrollment_line(original.as_bytes(), id(), &key()).unwrap();
        assert_eq!(change, AuthorizedKeysChange::Revoked);
        assert_eq!(updated, b"before\nafter\n");
        assert_eq!(
            remove_enrollment_line(&updated, id(), &key()).unwrap(),
            (updated.clone(), AuthorizedKeysChange::Unchanged)
        );
    }

    #[test]
    fn endpoint_rejects_proxy_shell_syntax_and_multi_hop_forms() {
        for unsafe_endpoint in [
            "none",
            "user;touch@host",
            "user@host,other",
            "user@$(command)",
            "-option",
            "user name@host",
            "user@@host",
        ] {
            assert!(
                SshEndpoint::parse(unsafe_endpoint).is_err(),
                "accepted {unsafe_endpoint}"
            );
        }
        assert_eq!(
            SshEndpoint::parse("backup_user@host-b.example")
                .unwrap()
                .as_str(),
            "backup_user@host-b.example"
        );
    }

    #[test]
    fn native_proxy_target_preserves_literal_percent_tokens() {
        let endpoint = SshEndpoint::from_parts("user%h", "fe80::1%eth0", Some(2222)).unwrap();
        assert_eq!(
            endpoint.proxy_target(),
            "-p 2222 -- 'user%%h@fe80::1%%eth0'"
        );
        assert_eq!(endpoint.as_str(), "user%h@fe80::1%eth0");
    }

    #[test]
    fn remote_command_quotes_every_argument_for_the_remote_shell() {
        let command = EnrollmentRemoteCommand::new(
            Path::new("/opt/syq/receiver"),
            &["enroll".into(), "argument with spaces;$(bad)".into()],
        )
        .unwrap();
        assert_eq!(
            command.as_str(),
            "/opt/syq/receiver enroll 'argument with spaces;$(bad)'"
        );
    }

    #[test]
    fn proxyjump_route_keeps_authentication_local() {
        let target = SshEndpoint::parse("backup@hostB").unwrap();
        let jump = SshEndpoint::parse("user@hostA").unwrap();
        let command = EnrollmentRemoteCommand::new(Path::new("/opt/syq/enroll"), &[]).unwrap();
        assert_eq!(
            enrollment_ssh_args(&target, EnrollmentRoute::ProxyJump { jump: &jump }, &command),
            [
                "-a",
                "-x",
                "-k",
                "-T",
                "-o",
                "ClearAllForwardings=yes",
                "-o",
                "ControlMaster=no",
                "-o",
                "ControlPath=none",
                "-o",
                "ForwardX11=no",
                "-o",
                "PermitLocalCommand=no",
                "-o",
                "ProxyCommand=ssh -a -x -k -T -o ClearAllForwardings=yes -o ControlMaster=no -o ControlPath=none -o ForwardX11=no -o PermitLocalCommand=no -W '[%h]:%p' -- user@hostA",
                "--",
                "backup@hostB",
                "/opt/syq/enroll",
            ]
        );
    }

    #[test]
    fn native_endpoint_port_reaches_direct_and_proxy_routes() {
        let target = SshEndpoint::from_parts("backup", "2001:db8::1", Some(2222)).unwrap();
        let jump = SshEndpoint::from_parts("alice", "jump.example", Some(2200)).unwrap();
        let command = EnrollmentRemoteCommand::new(Path::new("/opt/syq/enroll"), &[]).unwrap();
        let args = enrollment_ssh_args(
            &target,
            EnrollmentRoute::ProxyJump { jump: &jump },
            &command,
        );
        assert!(args.windows(2).any(|args| args == ["-p", "2222"]));
        assert!(args.iter().any(|arg| {
            arg.contains("ProxyCommand=")
                && arg.contains("-p 2200")
                && arg.contains("alice@jump.example")
        }));
        assert_eq!(target.as_str(), "backup@2001:db8::1");
        assert_eq!(target.label(), "backup@[2001:db8::1]:2222");
        assert!(args.iter().any(|arg| arg == "backup@2001:db8::1"));
        assert!(!args.iter().any(|arg| arg.contains("[2001:db8::1]")));
    }

    #[test]
    fn a_background_login_gives_its_policy_to_the_jump_syq_makes() {
        let target = SshEndpoint::parse("backup@hostB").unwrap();
        let jump = SshEndpoint::parse("user@hostA").unwrap();
        let proxy = |unattended| {
            let args = enrollment_ssh_args_raw(
                &target,
                EnrollmentRoute::ProxyJump { jump: &jump },
                "/opt/syq/enroll",
                unattended,
            );
            let proxy = args
                .iter()
                .find_map(|arg| arg.strip_prefix("ProxyCommand="))
                .unwrap()
                .to_owned();
            (args, proxy)
        };
        let (args, command) = proxy(Some(Unattended::default()));
        for option in BACKGROUND_LOGIN {
            assert!(
                args.windows(2).any(|pair| pair == ["-o", option]),
                "{option}"
            );
            assert!(command.contains(&format!(" -o {option} ")), "{command}");
        }
        // Host keys are checked as the configuration says...
        assert!(!args
            .iter()
            .any(|arg| arg.starts_with("StrictHostKeyChecking")));
        assert!(!command.contains("StrictHostKeyChecking"), "{command}");
        // ...except that where it would ask, nobody can answer, so a new
        // key is accepted the first time, for the login or for the jump.
        let (args, command) = proxy(Some(Unattended {
            login_accepts_new: true,
            jump_accepts_new: false,
        }));
        assert!(args
            .windows(2)
            .any(|pair| pair == ["-o", "StrictHostKeyChecking=accept-new"]));
        assert!(!command.contains("StrictHostKeyChecking"), "{command}");
        let (args, command) = proxy(Some(Unattended {
            login_accepts_new: false,
            jump_accepts_new: true,
        }));
        assert!(!args
            .iter()
            .any(|arg| arg.starts_with("StrictHostKeyChecking")));
        assert!(
            command.contains(" -o StrictHostKeyChecking=accept-new "),
            "{command}"
        );
        // A foreground login, as `--via` makes, may still ask.
        let (args, command) = proxy(None);
        assert!(!args.iter().any(|arg| arg.starts_with("BatchMode")));
        assert!(!command.contains("BatchMode"), "{command}");

        // The jump's own options win over a configuration that would ask for
        // a passphrase or wait long, and its host-key setting is the
        // configuration's.
        let effective = |config_text: &str, unattended| {
            let (_, command) = proxy(Some(unattended));
            let temporary = crate::test_support::tempdir().unwrap();
            let config = temporary.path().join("config");
            std::fs::write(&config, config_text).unwrap();
            let words = shell_words::split(&command).unwrap();
            let (program, options) = words.split_first().unwrap();
            assert_eq!(program, "ssh");
            let output = std::process::Command::new("ssh")
                .arg("-G")
                .arg("-F")
                .arg(&config)
                .args(
                    options
                        .iter()
                        .map(|word| word.replace("%h", "hostB").replace("%p", "22")),
                )
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
            String::from_utf8(output.stdout).unwrap()
        };
        let strict = effective(
            "Host *\n  StrictHostKeyChecking yes\n  BatchMode no\n  ConnectTimeout 300\n",
            Unattended::default(),
        );
        for setting in [
            "batchmode yes",
            "stricthostkeychecking true",
            "connecttimeout 10",
            "serveraliveinterval 15",
            "serveralivecountmax 3",
        ] {
            assert!(
                strict.lines().any(|line| line == setting),
                "{setting}\n{strict}"
            );
        }
        let accepting = effective(
            "Host *\n  StrictHostKeyChecking accept-new\n",
            Unattended::default(),
        );
        assert!(accepting
            .lines()
            .any(|line| line == "stricthostkeychecking accept-new"));
        let asking = effective(
            "Host *\n  StrictHostKeyChecking ask\n",
            Unattended {
                login_accepts_new: false,
                jump_accepts_new: true,
            },
        );
        assert!(asking
            .lines()
            .any(|line| line == "stricthostkeychecking accept-new"));
        assert!(asks_about_new_host_keys(
            b"user x\nstricthostkeychecking ask\n"
        ));
        assert!(!asks_about_new_host_keys(b"stricthostkeychecking true\n"));
    }

    #[test]
    fn the_configured_route_keeps_the_ssh_configurations_jumps_and_proxies() {
        let target = SshEndpoint::parse("backup@hostB").unwrap();
        let command = EnrollmentRemoteCommand::new(Path::new("/opt/syq/enroll"), &[]).unwrap();
        let args = enrollment_ssh_args(&target, EnrollmentRoute::Configured, &command);
        // Nothing overrides the configuration's route...
        assert!(!args
            .iter()
            .any(|arg| arg.starts_with("ProxyJump") || arg.starts_with("ProxyCommand")));
        assert!(!args.iter().any(|arg| arg == "-J"));
        // ...and the login itself still forwards nothing and shares nothing.
        for option in [
            "ClearAllForwardings=yes",
            "ControlMaster=no",
            "ControlPath=none",
            "ForwardX11=no",
            "PermitLocalCommand=no",
        ] {
            assert!(
                args.windows(2).any(|pair| pair == ["-o", option]),
                "{option}"
            );
        }
        assert_eq!(&args[..4], ["-a", "-x", "-k", "-T"]);
        assert_eq!(
            &args[args.len() - 3..],
            ["--", "backup@hostB", "/opt/syq/enroll"]
        );
    }
}

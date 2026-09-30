use super::*;

#[derive(Debug)]
pub(crate) struct SshMultiplexer {
    /// Owns the per-run private socket directory; None in persistent mode,
    /// where the socket lives in the shared per-user runtime directory and
    /// deliberately outlives this process.
    pub(super) _directory: Option<tempfile::TempDir>,
    pub(super) path: PathBuf,
    /// A managed persistence scope keeps its control master alive, so later
    /// syq runs in that scope skip the SSH handshake.
    pub(super) persistent: bool,
    pub(super) idle_timeout: &'static str,
    pub(super) automatic_receiving: bool,
    /// Pool spares open sessions with syq's own fixed options, so the pool
    /// serves only connections made without an `--rsh` command's options.
    pub(super) session_pool: bool,
    pub(super) reuse_for_workers: AtomicBool,
    pub(super) workers_rejected: AtomicBool,
}

// Keepalives detect dead transports so a later command can reconnect. Durable
// logins have no idle expiry; abandoned script scopes retain a bounded lifetime.
pub(super) const PERSISTENT_SSH_OPTIONS: &[&str] = &[
    "-o",
    "ServerAliveInterval=15",
    "-o",
    "ServerAliveCountMax=3",
];

/// How syq may share an `--rsh` ssh command's connections.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SshSharing<'a> {
    /// The command's own ssh options, passed through on every session.
    pub(crate) options: &'a [String],
    /// Whether a connection may outlive this run. A debug log level would keep
    /// writing to the first command's terminal from the background, so such
    /// commands share connections only within the run.
    pub(crate) persist: bool,
}

/// The options of an `--rsh` command that syq can treat as its default `ssh`
/// plus those options: shared and persistent connections work as usual, with
/// persistent ones kept separately for each set of options. None when the
/// program is not OpenSSH, or when the options set up connection sharing
/// themselves (`-M`, `-S`, `-O`, or `ControlMaster`/`ControlPath`/
/// `ControlPersist`), so that the command keeps full control of it.
pub(crate) fn shareable_ssh_options(rsh: &[String]) -> Option<SshSharing<'_>> {
    let (program, options) = rsh.split_first()?;
    if !program.ends_with("ssh") {
        return None;
    }
    // The option letters that take a value in OpenSSH's ssh(1).
    const VALUED: &[u8] = b"bceilmopBDEFIJLOPQRSwW";
    let mut persist = true;
    let mut index = 0;
    while index < options.len() {
        let argument = options[index].as_str();
        index += 1;
        // An operand or `--` means this is not a plain list of options.
        let letters = argument
            .strip_prefix('-')
            .filter(|letters| !letters.is_empty() && !letters.starts_with('-'))?;
        for (at, letter) in letters.bytes().enumerate() {
            match letter {
                b'M' => return None,
                b'v' => persist = false,
                _ => {}
            }
            if VALUED.contains(&letter) {
                let value = if at + 1 < letters.len() {
                    &letters[at + 1..]
                } else {
                    index += 1;
                    options.get(index - 1)?.as_str()
                };
                if matches!(letter, b'S' | b'O') {
                    return None;
                }
                if letter == b'o' {
                    let (name, setting) = option_name(value);
                    if ["ControlMaster", "ControlPath", "ControlPersist"]
                        .iter()
                        .any(|sharing| name.eq_ignore_ascii_case(sharing))
                    {
                        return None;
                    }
                    let setting = setting.to_ascii_lowercase();
                    if name.eq_ignore_ascii_case("LogLevel")
                        && (setting.starts_with("debug") || setting == "verbose")
                    {
                        persist = false;
                    }
                }
                break;
            }
        }
    }
    Some(SshSharing { options, persist })
}

/// Whether syq can keep a persistent connection for an `--rsh` command
/// string (see [`shareable_ssh_options`]).
pub(crate) fn rsh_persists_connections(rsh: &str) -> bool {
    shell_words::split(rsh)
        .is_ok_and(|words| shareable_ssh_options(&words).is_some_and(|sharing| sharing.persist))
}

/// The options that identify a persistent connection. Relative paths to local
/// files, as in `-F ssh.conf` or `-i key`, resolve against the working
/// directory, so they are made absolute: the same options given in another
/// directory can name different files, and must not reuse this connection.
/// Options that run a local command, such as `ProxyCommand=./proxy`, can refer
/// to the directory in ways that cannot be resolved, so they tie the connection
/// to the directory itself. A configuration file named with `-F` is treated
/// like the default `~/.ssh/config`: its own settings are not examined. None
/// when a path or that directory cannot be recorded.
pub(crate) fn persistent_ssh_options(
    options: &[String],
    directory: Option<&std::path::Path>,
) -> Option<crate::persistence::SshOptions> {
    // `-o` names whose value is a command run on this machine.
    const COMMAND_OPTIONS: &[&str] = &["KnownHostsCommand", "LocalCommand", "ProxyCommand"];
    let mut uses_directory = false;
    // Option letters whose value is a local file, and `-o` names likewise.
    const FILE_LETTERS: &[u8] = b"EFIi";
    const FILE_OPTIONS: &[&str] = &[
        "CertificateFile",
        "GlobalKnownHostsFile",
        "IdentityAgent",
        "IdentityFile",
        "PKCS11Provider",
        "RevokedHostKeys",
        "SecurityKeyProvider",
        "UserKnownHostsFile",
        "XAuthLocation",
    ];
    const VALUED: &[u8] = b"bceilmopBDEFIJLOPQRSwW";
    let absolute = |path: &str| -> Option<String> {
        if path.starts_with(['/', '~', '%', '$']) || path.eq_ignore_ascii_case("none") {
            return Some(path.to_owned());
        }
        directory?.join(path).to_str().map(str::to_owned)
    };
    let mut resolved = Vec::with_capacity(options.len());
    let mut index = 0;
    while index < options.len() {
        let argument = &options[index];
        index += 1;
        let letters = argument.strip_prefix('-').unwrap_or_default();
        let Some(at) = letters.bytes().position(|letter| VALUED.contains(&letter)) else {
            resolved.push(argument.clone());
            continue;
        };
        let letter = letters.as_bytes()[at];
        let (value, inline) = if at + 1 < letters.len() {
            (letters[at + 1..].to_owned(), true)
        } else {
            index += 1;
            (options.get(index - 1)?.clone(), false)
        };
        let value = if FILE_LETTERS.contains(&letter) {
            absolute(&value)?
        } else if letter == b'o' {
            let (name, setting) = option_name(&value);
            uses_directory |= COMMAND_OPTIONS
                .iter()
                .any(|command| name.eq_ignore_ascii_case(command));
            if FILE_OPTIONS
                .iter()
                .any(|file| name.eq_ignore_ascii_case(file))
            {
                let paths = setting
                    .split_whitespace()
                    .map(absolute)
                    .collect::<Option<Vec<_>>>()?;
                format!("{name}={}", paths.join(" "))
            } else {
                value
            }
        } else {
            value
        };
        if inline {
            resolved.push(format!("-{}{value}", &letters[..=at]));
        } else {
            resolved.push(argument.clone());
            resolved.push(value);
        }
    }
    let directory = if uses_directory {
        Some(directory?.to_str()?.to_owned())
    } else {
        None
    };
    Some(crate::persistence::SshOptions {
        options: resolved,
        directory,
    })
}

/// An `-o` option's name and value. OpenSSH accepts leading whitespace and
/// either `=` or whitespace between them.
fn option_name(option: &str) -> (&str, &str) {
    let option = option.trim_start();
    let end = option
        .find(|c: char| c == '=' || c.is_whitespace())
        .unwrap_or(option.len());
    let value = option[end..].trim_start_matches(|c: char| c == '=' || c.is_whitespace());
    (&option[..end], value.trim())
}

/// The oldest OpenSSH release whose client speaks the agent session-bind
/// extension and host-bound public-key authentication. Constrained agent
/// forwarding relies on both, on the local machine and on the coordinator
/// host, and the peer's `sshd` must be at least this new as well.
pub(crate) const CONSTRAINED_OPENSSH_MINIMUM: OpenSshVersion =
    OpenSshVersion { major: 8, minor: 9 };

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct OpenSshVersion {
    pub major: u32,
    pub minor: u32,
}

impl std::fmt::Display for OpenSshVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OpenSSH {}.{}", self.major, self.minor)
    }
}

/// Read the release number out of an `ssh -V` banner such as
/// `OpenSSH_9.6p1 Ubuntu-3ubuntu13.19, OpenSSL 3.0.13 30 Jan 2024`. Other
/// clients report nothing recognizable and yield `None`.
pub(crate) fn parse_openssh_version(banner: &[u8]) -> Option<OpenSshVersion> {
    let text = String::from_utf8_lossy(banner);
    let rest = text.split("OpenSSH_").nth(1)?;
    let mut numbers = rest
        .split(|c: char| !c.is_ascii_digit())
        .take(2)
        .map(|digits| digits.parse::<u32>().ok());
    let major = numbers.next()??;
    let minor = numbers.next()??;
    Some(OpenSshVersion { major, minor })
}

/// Ask `program -V` for its version once per program name. Only programs
/// whose name ends in `ssh` are probed: an arbitrary `--rsh` command is a
/// complete user policy and might do anything with a `-V` argument.
pub(crate) fn openssh_version(program: &str) -> Option<OpenSshVersion> {
    use std::collections::HashMap;
    use std::sync::Mutex;
    static CACHE: Mutex<Option<HashMap<String, Option<OpenSshVersion>>>> = Mutex::new(None);
    if !program.ends_with("ssh") {
        return None;
    }
    let mut cache = CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let cache = cache.get_or_insert_with(HashMap::new);
    if let Some(version) = cache.get(program) {
        return *version;
    }
    let version = Command::new(program)
        .arg("-V")
        .stdin(Stdio::null())
        .capture_output()
        .ok()
        .and_then(|output| {
            parse_openssh_version(&output.stderr).or_else(|| parse_openssh_version(&output.stdout))
        });
    cache.insert(program.to_owned(), version);
    version
}

/// An installed OpenSSH client is too old for constrained agent forwarding.
/// Nothing about a retry changes that, so the connection loop gives up on it
/// immediately.
#[derive(Debug)]
pub(crate) struct OpenSshVersionError(pub(super) String);

impl std::fmt::Display for OpenSshVersionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for OpenSshVersionError {}

/// Refuse constrained agent forwarding through an OpenSSH client that
/// predates session binding. A client whose version cannot be read is left to
/// fail on its own, so this only turns a confusing authentication failure
/// into a direct explanation.
pub(crate) fn require_constrained_openssh(program: &str, location: &str) -> Result<()> {
    match openssh_version(program) {
        Some(version) if version < CONSTRAINED_OPENSSH_MINIMUM => {
            Err(OpenSshVersionError(format!(
                "constrained agent forwarding needs {CONSTRAINED_OPENSSH_MINIMUM} or newer {location}, but {program} is {version}; use --peer-auth own-credentials with credentials on the coordinator host, --peer-auth full-agent, or an explicit --rsh policy"
            ))
            .into())
        }
        _ => Ok(()),
    }
}

impl SshMultiplexer {
    pub(crate) fn new() -> Result<Self> {
        let directory = crate::private_broker::private_temp_dir("syq-ssh-")
            .context("create private SSH control directory")?;
        let path = directory.path().join("socket");
        crate::persistence::validate_openssh_socket_path(&path)?;
        Ok(Self {
            _directory: Some(directory),
            path,
            persistent: false,
            idle_timeout: "no",
            automatic_receiving: false,
            session_pool: false,
            reuse_for_workers: AtomicBool::new(false),
            workers_rejected: AtomicBool::new(false),
        })
    }

    /// `ssh` holds an `--rsh` command's own ssh options, which select a
    /// separate persistent connection. Receiving and the session pool open
    /// sessions with plain `ssh` and syq's own options, so they serve only
    /// connections without them.
    pub(crate) fn persistent(
        scope: &std::path::Path,
        user: Option<&str>,
        host: &str,
        port: Option<u16>,
        ssh: Option<&crate::persistence::SshOptions>,
    ) -> Result<Self> {
        let path = crate::persistence::prepare_endpoint(scope, user, host, port, ssh)?;
        let global = crate::persistence::is_global_scope(scope)?;
        Ok(Self {
            _directory: None,
            path,
            persistent: true,
            idle_timeout: if global { "yes" } else { "300" },
            automatic_receiving: global && ssh.is_none(),
            session_pool: ssh.is_none(),
            reuse_for_workers: AtomicBool::new(false),
            workers_rejected: AtomicBool::new(false),
        })
    }

    /// The explicit connect command starts receiving once and propagates setup errors.
    pub(crate) fn defer_receiving(&mut self) {
        self.automatic_receiving = false;
    }

    pub(crate) fn control_path(&self) -> &std::path::Path {
        &self.path
    }

    pub(super) fn set_reuse_for_workers(&self, reuse: bool) {
        // A persistent master is shared across runs; worker data channels
        // must never ride it (MaxSessions contention, shared cipher stream).
        if self.persistent {
            return;
        }
        self.reuse_for_workers.store(reuse, Ordering::Relaxed);
    }

    pub(super) fn reuse_for_workers(&self) -> bool {
        self.reuse_for_workers.load(Ordering::Relaxed)
    }
}

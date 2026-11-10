use super::*;

#[derive(Debug)]
pub(crate) struct SshMultiplexer {
    /// Owns the per-run private socket directory, removed also when a
    /// signal ends the run; None in persistent mode, where the socket lives
    /// in the shared per-user runtime directory and deliberately outlives
    /// this process.
    pub(super) _directory: Option<crate::private_broker::SignalCleanedDir>,
    pub(super) path: PathBuf,
    pub(super) domain: Option<crate::persistence::Domain>,
    /// A managed persistence scope keeps its control master alive, so later
    /// syq runs in that scope skip the SSH handshake.
    pub(super) persistent: bool,
    /// An approved account owns this master. Only attach to it; never create,
    /// replace, or authenticate a master through the ordinary SSH path.
    pub(super) existing_only: bool,
    pub(super) approved_workers:
        Option<std::sync::Arc<crate::destination::ssh::workers::Authorization>>,
    pub(super) idle_timeout: &'static str,
    pub(super) automatic_receiving: bool,
    /// Pool spares open sessions with syq's own fixed options, so the pool
    /// serves only connections made without an `--rsh` command's options.
    pub(super) session_pool: bool,
    pub(super) reuse_for_workers: AtomicBool,
    pub(super) workers_rejected: AtomicBool,
    /// A control session ran when no persistent master was live, so it became
    /// the master, which keeps running after this command.
    pub(super) starting_master: AtomicBool,
}

// Keepalives detect dead transports so a later command can reconnect. Durable
// logins have no idle expiry; abandoned script scopes retain a bounded lifetime.
pub(super) const PERSISTENT_SSH_OPTIONS: &[&str] = &[
    "-o",
    "ServerAliveInterval=15",
    "-o",
    "ServerAliveCountMax=3",
];

/// Every ssh command that may start or join a connection kept open after the
/// command forwards nothing. sshd keeps a forwarded agent usable on the server
/// for as long as the connection lasts, not just for the session that asked
/// for it, and a configured port forward stays bound with it, so either would
/// stay available there until `syq persist off`. A mux client's configured
/// port forwards would also be added to the master and stay with it. syq's own
/// forwards on such a master use `ssh -O forward`, which these leave alone.
pub(crate) const PERSISTENT_NO_FORWARDING: &[&str] =
    &["-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes"];

/// How syq may share an `--rsh` ssh command's connections.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SshSharing<'a> {
    /// The command's own ssh options, passed through on every session.
    pub(crate) options: &'a [String],
    /// Whether a connection may outlive this run. A debug log level would keep
    /// writing to the first command's terminal from the background, and a
    /// connection kept open never forwards (`PERSISTENT_NO_FORWARDING`), so
    /// commands that ask for either share connections only within the run.
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
                // Debug output, or agent, port or tunnel forwarding.
                b'v' | b'A' | b'L' | b'R' | b'D' | b'w' => persist = false,
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
                    // OpenSSH reads a quoted keyword, as in `"ForwardAgent"
                    // yes`, and quoted values. Rather than repeat its rules,
                    // a value counts as `no` or `yes` only as that word, alone
                    // or in one pair of matching quotes, and an option with a
                    // quoted keyword counts as one that may forward.
                    let quoted = name.contains('"');
                    let setting = setting.to_ascii_lowercase();
                    let setting = ['"', '\'']
                        .iter()
                        .find_map(|quote| setting.strip_prefix(*quote)?.strip_suffix(*quote))
                        .unwrap_or(&setting);
                    let named = |option: &str| name.eq_ignore_ascii_case(option);
                    if quoted
                        || (named("LogLevel")
                            && (setting.starts_with("debug") || setting == "verbose"))
                        || (["ForwardAgent", "Tunnel"]
                            .iter()
                            .any(|option| named(option))
                            && setting != "no")
                        || (named("ClearAllForwardings") && setting != "yes")
                        || ["LocalForward", "RemoteForward", "DynamicForward"]
                            .iter()
                            .any(|forward| named(forward))
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

/// What a command left running in the background for `label`, and the
/// command that stops it.
pub(super) fn background_notice(
    label: &str,
    master: bool,
    pool: bool,
    receiving: bool,
    stop: &str,
) -> String {
    let mut running = Vec::new();
    if master {
        running.push(format!("the SSH connection to {label}"));
    }
    if pool && master {
        running.push("a ready syq session there".to_owned());
    }
    if receiving {
        running.push(if master {
            "receiving through it".to_owned()
        } else {
            format!("receiving through {label}")
        });
    }
    let list = match running.as_slice() {
        [only] => only.clone(),
        [first, second] => format!("{first} and {second}"),
        [rest @ .., last] => format!("{}, and {last}", rest.join(", ")),
        [] => String::new(),
    };
    let (these, them) = if running.len() == 1 {
        ("this", "it")
    } else {
        ("these", "them")
    };
    format!("persistence keeps {these} running in the background: {list}. `{stop}` stops {them}.")
}

impl SshMultiplexer {
    pub(crate) fn new() -> Result<Self> {
        let directory = crate::private_broker::SignalCleanedDir::new("syq-ssh-")
            .context("create private SSH control directory")?;
        let path = directory.path().join("socket");
        crate::persistence::validate_openssh_socket_path(&path)?;
        Ok(Self {
            _directory: Some(directory),
            path,
            domain: None,
            persistent: false,
            existing_only: false,
            approved_workers: None,
            idle_timeout: "no",
            automatic_receiving: false,
            session_pool: false,
            reuse_for_workers: AtomicBool::new(false),
            workers_rejected: AtomicBool::new(false),
            starting_master: AtomicBool::new(false),
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
        let domain = crate::persistence::Domain::select(Some(scope))?;
        let global = domain.is_default();
        Ok(Self {
            _directory: None,
            path,
            domain: Some(domain),
            persistent: true,
            existing_only: false,
            approved_workers: None,
            idle_timeout: if global { "yes" } else { "300" },
            automatic_receiving: ssh.is_none(),
            session_pool: ssh.is_none(),
            reuse_for_workers: AtomicBool::new(false),
            workers_rejected: AtomicBool::new(false),
            starting_master: AtomicBool::new(false),
        })
    }

    /// Share ready helpers on an already validated account connection. The
    /// caller retains the approved connection's strict SSH options in `rsh`.
    pub(crate) fn approved(
        control: &std::path::Path,
        workers: Option<std::sync::Arc<crate::destination::ssh::workers::Authorization>>,
    ) -> Self {
        Self {
            _directory: None,
            path: control.into(),
            domain: None,
            persistent: true,
            existing_only: true,
            approved_workers: workers,
            idle_timeout: "no",
            automatic_receiving: false,
            session_pool: true,
            reuse_for_workers: AtomicBool::new(false),
            workers_rejected: AtomicBool::new(false),
            starting_master: AtomicBool::new(false),
        }
    }

    /// The explicit connect command starts receiving once and propagates setup errors.
    pub(crate) fn defer_receiving(&mut self) {
        self.automatic_receiving = false;
    }

    pub(crate) fn control_path(&self) -> &std::path::Path {
        &self.path
    }

    /// Before a control session that becomes this endpoint's persistent
    /// master when none is live: note that it will start one.
    pub(super) fn note_master_start(&self) {
        if self.persistent
            && !self.existing_only
            && !crate::persistence::socket_is_ready(&self.path).unwrap_or(true)
        {
            self.starting_master.store(true, Ordering::Relaxed);
        }
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

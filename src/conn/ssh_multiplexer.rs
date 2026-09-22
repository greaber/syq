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
        let directory = tempfile::Builder::new()
            .prefix("syq-ssh-")
            .tempdir()
            .context("create private SSH control directory")?;
        let path = directory.path().join("socket");
        crate::persistence::validate_openssh_socket_path(&path)?;
        Ok(Self {
            _directory: Some(directory),
            path,
            persistent: false,
            idle_timeout: "no",
            automatic_receiving: false,
            reuse_for_workers: AtomicBool::new(false),
            workers_rejected: AtomicBool::new(false),
        })
    }

    pub(crate) fn persistent(
        scope: &std::path::Path,
        user: Option<&str>,
        host: &str,
        port: Option<u16>,
    ) -> Result<Self> {
        let path = crate::persistence::prepare_endpoint(scope, user, host, port)?;
        let global = crate::persistence::is_global_scope(scope)?;
        Ok(Self {
            _directory: None,
            path,
            persistent: true,
            idle_timeout: if global { "yes" } else { "300" },
            automatic_receiving: global,
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

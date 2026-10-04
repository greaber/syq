//! Stable local discovery and exec handoff; transfer protocols remain build-pinned.
use super::*;
use std::sync::OnceLock;

const HANDOFF: &str = "--return-handoff-v1";
static ACCEPTED: OnceLock<Guard> = OnceLock::new();
static ACCOUNT_PREFLIGHT_DONE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

pub(crate) fn finish_account_preflight() {
    ACCOUNT_PREFLIGHT_DONE.store(true, std::sync::atomic::Ordering::Release);
}
// Process-local timing only: keep the released argv guard and registration
// formats unchanged. CLOCK_MONOTONIC has the same origin across a local exec.
const COPY_START_ENV: &str = "SYQ_RETURN_COPY_START_NS";
static COPY_START: OnceLock<u64> = OnceLock::new();

fn monotonic_ns() -> Option<u64> {
    let mut time = std::mem::MaybeUninit::<libc::timespec>::uninit();
    // SAFETY: clock_gettime initializes the timespec on success.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, time.as_mut_ptr()) } != 0 {
        return None;
    }
    let time = unsafe { time.assume_init() };
    u64::try_from(time.tv_sec)
        .ok()?
        .checked_mul(1_000_000_000)?
        .checked_add(u64::try_from(time.tv_nsec).ok()?)
}

pub(crate) fn copy_start() -> std::time::Instant {
    let now = std::time::Instant::now();
    let Some(ticks) = monotonic_ns() else {
        return now;
    };
    let start = *COPY_START.get_or_init(|| ticks);
    ticks
        .checked_sub(start)
        .and_then(|elapsed| now.checked_sub(Duration::from_nanos(elapsed)))
        .unwrap_or(now)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum Kind {
    Copy,
    Forward,
    Pull,
    Command,
    Ssh,
    SshPersistent,
    Account,
}

#[derive(Clone)]
pub(crate) struct Selection {
    pub(super) name: String,
    pub(super) registration: Registration,
    pub(super) kind: Kind,
    pub(super) target: Option<String>,
}

impl std::fmt::Debug for Selection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Registration includes the private return credential.
        f.debug_struct("Selection")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

impl Selection {
    pub(super) fn new(
        name: String,
        registration: Registration,
        kind: Kind,
        target: Option<String>,
    ) -> Self {
        Self {
            name,
            registration,
            kind,
            target,
        }
    }

    fn guard(&self) -> Result<Guard> {
        Ok(Guard {
            name: self.name.clone(),
            identity: self.registration.identity.clone(),
            kind: self.kind,
            registration: digest(&self.registration)?,
        })
    }
}

// This small argv contract and registration v3 are shared across builds. No
// serialized transfer arguments, signed authority, or credentials enter argv.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Guard {
    name: String,
    identity: String,
    kind: Kind,
    registration: String,
}

fn digest(registration: &Registration) -> Result<String> {
    Ok(blake3::hash(&serde_json::to_vec(registration)?)
        .to_hex()
        .to_string())
}

impl Guard {
    fn validate(&self) -> Result<()> {
        if self.identity != crate::identity::build() {
            bail!("registered return helper has a different build; reconnect from the receiving machine to refresh it");
        }
        let registration = load_registration(&self.name)?;
        if self.registration != digest(&registration)? {
            bail!("return registration changed during handoff; retry the command");
        }
        Ok(())
    }
}

/// Strip the private prefix before public CLI parsing. Validate the guard in
/// preflight so copy failures can settle the requested automation stream.
pub(crate) fn enter(mut argv: Vec<OsString>) -> Result<Vec<OsString>> {
    let inherited_start = std::env::var(COPY_START_ENV).ok();
    // SAFETY: main calls enter before starting any threads. Do not let this
    // private value reach remote helpers or unrelated child commands.
    unsafe { std::env::remove_var(COPY_START_ENV) };
    if argv.get(1).is_none_or(|arg| arg != HANDOFF) {
        return Ok(argv);
    }
    let encoded = argv.get(2).context("return handoff guard missing")?;
    if encoded.len() > MAX_MESSAGE {
        bail!("return handoff guard too large");
    }
    let guard: Guard = serde_json::from_slice(encoded.as_bytes())?;
    let command = argv.get(3).and_then(|arg| arg.to_str());
    if !accepts_command(
        guard.kind,
        command,
        argv.get(4).and_then(|arg| arg.to_str()),
    ) {
        bail!("invalid return handoff command");
    }
    if matches!(
        guard.kind,
        Kind::Copy | Kind::Forward | Kind::Pull | Kind::Account
    ) {
        if let Some(start) = inherited_start.and_then(|value| value.parse().ok()) {
            let _ = COPY_START.set(start);
        }
    }
    ACCEPTED
        .set(guard)
        .map_err(|_| anyhow::anyhow!("return handoff already accepted"))?;
    argv.drain(1..3);
    Ok(argv)
}

fn accepts_command(kind: Kind, command: Option<&str>, subcommand: Option<&str>) -> bool {
    match (kind, command) {
        (Kind::Copy | Kind::Forward | Kind::Pull, Some("cp"))
        | (Kind::Command, Some("exec"))
        | (Kind::Ssh, Some("ssh"))
        | (Kind::Account, Some("ssh" | "cp" | "rm" | "rsync" | "map" | "clean-partials")) => true,
        (Kind::SshPersistent | Kind::Account, Some("persist")) => subcommand == Some("connect"),
        _ => false,
    }
}

pub(crate) fn validate_account_selection(mode: &crate::cli::AuthFrom) -> Result<()> {
    let Some(guard) = ACCEPTED.get().filter(|guard| guard.kind == Kind::Account) else {
        return Ok(());
    };
    guard.validate()?;
    anyhow::ensure!(
        matches!(mode, crate::cli::AuthFrom::Provider(crate::auth_from::Provider::Return(name)) if *name == guard.name),
        "account authorizer changed during handoff; retry the command"
    );
    Ok(())
}

pub(super) fn selected_name(kind: Kind) -> Option<&'static str> {
    ACCEPTED
        .get()
        .filter(|guard| guard.kind == kind)
        .map(|guard| guard.name.as_str())
}

pub(super) fn check_selection(selection: &Selection) -> Result<()> {
    if let Some(guard) = ACCEPTED.get() {
        guard.validate()?;
        if *guard != selection.guard()? {
            bail!("return route changed during handoff; retry the command");
        }
    }
    Ok(())
}

/// The public command line after `enter` and environment options, recorded
/// by main. A re-executed helper receives exactly this, so arguments taken
/// from the environment reach it even when it predates that feature, and the
/// variables themselves, already removed from the environment, are not
/// applied a second time.
static COMMAND_LINE: OnceLock<Vec<OsString>> = OnceLock::new();

pub(crate) fn record_command_line(argv: &[OsString]) {
    COMMAND_LINE
        .set(argv.to_vec())
        .expect("command line recorded once");
}

pub(crate) fn command_line() -> Result<&'static [OsString]> {
    Ok(COMMAND_LINE.get().context("command line not recorded")?)
}

pub(super) fn maybe_exec(selection: &Selection) -> Result<()> {
    check_selection(selection)?;
    if selection.registration.identity == crate::identity::build() {
        return Ok(());
    }
    let program = std::ffi::OsStr::from_bytes(&selection.registration.program);
    if selection.kind == Kind::Pull {
        let supported = Command::new(program)
            .arg("--return-source-probe")
            .env("SYQ_NO_UPDATE_CHECK", "1")
            .capture_output()
            .is_ok_and(|output| output.status.success());
        if !supported {
            bail!("the registered helper for @{} does not support source authorization; update syq on the receiving machine and reconnect with syq persist connect SERVER", selection.name);
        }
    }
    if selection.kind == Kind::Account {
        anyhow::ensure!(!ACCOUNT_PREFLIGHT_DONE.load(std::sync::atomic::Ordering::Acquire),
            "receiving connection changed after account preflight; retry the command to use its matching helper");
        let supported = Command::new(program)
            .arg("--account-ssh-probe")
            .env("SYQ_NO_UPDATE_CHECK", "1")
            .capture_output()
            .is_ok_and(|output| output.status.success());
        if !supported {
            bail!("the registered helper for @{} does not support account authorization; update syq on the receiving machine and reconnect with syq persist connect SERVER", selection.name);
        }
    }
    if matches!(selection.kind, Kind::Ssh | Kind::SshPersistent) {
        // Help is a read-only capability probe. Older helpers do not know the
        // new guard kind; give a recovery step before handing them this argv.
        let supported = Command::new(program)
            .args(["help", "ssh"])
            .env("SYQ_NO_UPDATE_CHECK", "1")
            .capture_output()
            .is_ok_and(|output| output.status.success());
        if !supported {
            bail!("the registered helper for @{} does not support syq ssh; update syq on the receiving machine and reconnect with syq persist connect SERVER", selection.name);
        }
    }
    let guard = serde_json::to_string(&selection.guard()?)?;
    let argv = command_line()?;
    let mut command = Command::new(program);
    if let Some(start) = COPY_START.get() {
        command.env(COPY_START_ENV, start.to_string());
    }
    let error = command
        .arg(HANDOFF)
        .arg(guard)
        .args(argv.iter().skip(1))
        .exec();
    Err(error).with_context(|| format!(
        "start matching return helper {} for @{}; reconnect from the receiving machine to refresh it",
        Path::new(program).display(), selection.name
    ))
}

pub(crate) fn copy(
    args: &mut crate::cli::Args,
    progress: &crate::progress::Progress,
) -> Result<()> {
    if args.interface != crate::cli::Interface::NativeCp {
        return Ok(());
    }
    if let Some(guard) = ACCEPTED.get() {
        guard.validate()?;
    }
    let selection = select_copy(args, Some(progress))?;
    if let Some(selection) = &selection {
        if selection.kind != Kind::Pull
            && (args.hardlinks
                || args.acls
                || args.xattrs
                || args.atimes > 0
                || args.crtimes
                || args.open_noatime
                || args.sparse)
        {
            bail!("hardlink, ACL, xattr, access-time and birth-time preservation, no-atime reads and sparse allocation are not supported by named or receiving destinations");
        }
        maybe_exec(selection)?;
    } else if ACCEPTED
        .get()
        .is_some_and(|guard| guard.kind != Kind::Account)
    {
        bail!("return route disappeared during handoff; retry the command");
    }
    // Some(None) records ordinary SSH/local copying; prepare must not discover
    // a different authorizer after output files or stdin have been consumed.
    args.return_selection = Some(selection);
    finish_account_preflight();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_handoff_accepts_operations_but_never_other_persistence_actions() {
        for command in ["ssh", "cp", "rm", "rsync", "map", "clean-partials"] {
            assert!(accepts_command(Kind::Account, Some(command), None));
        }
        assert!(accepts_command(
            Kind::Account,
            Some("persist"),
            Some("connect")
        ));
        for command in ["exec", "completion", "--self-update", "unknown"] {
            assert!(!accepts_command(Kind::Account, Some(command), None));
        }
        for action in [
            None,
            Some("off"),
            Some("receive"),
            Some("auth-from"),
            Some("ssh-config"),
        ] {
            assert!(!accepts_command(Kind::Account, Some("persist"), action));
        }
        assert!(!accepts_command(Kind::Copy, Some("rm"), None));
        assert!(!accepts_command(Kind::Command, Some("ssh"), None));
    }

    #[test]
    fn existing_handoff_guard_json_remains_readable_and_unchanged() {
        // Fixed JSON from the e4c130af guard format: do not regenerate these
        // fixtures from the serializer whose compatibility they check.
        for encoded in [
            r#"{"name":"laptop","identity":"old-build","kind":"Copy","registration":"old-registration-digest"}"#,
            r#"{"name":"laptop","identity":"old-build","kind":"Forward","registration":"old-registration-digest"}"#,
            r#"{"name":"laptop","identity":"old-build","kind":"Command","registration":"old-registration-digest"}"#,
        ] {
            let guard: Guard = serde_json::from_str(encoded).unwrap();
            assert_eq!(serde_json::to_string(&guard).unwrap(), encoded);
            assert_ne!(guard.kind, Kind::Ssh);
        }
    }
}

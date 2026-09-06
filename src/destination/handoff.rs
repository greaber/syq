//! Stable local discovery and exec handoff; transfer protocols remain build-pinned.
use super::*;
use std::sync::OnceLock;

const HANDOFF: &str = "--return-handoff-v1";
static ACCEPTED: OnceLock<Guard> = OnceLock::new();

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum Kind {
    Copy,
    Forward,
    Command,
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
    if argv.get(1).is_none_or(|arg| arg != HANDOFF) {
        return Ok(argv);
    }
    let encoded = argv.get(2).context("return handoff guard missing")?;
    if encoded.len() > MAX_MESSAGE {
        bail!("return handoff guard too large");
    }
    let guard: Guard = serde_json::from_slice(encoded.as_bytes())?;
    let command = argv.get(3).and_then(|arg| arg.to_str());
    if !matches!(
        (guard.kind, command),
        (Kind::Copy | Kind::Forward, Some("cp")) | (Kind::Command, Some("exec"))
    ) {
        bail!("invalid return handoff command");
    }
    ACCEPTED
        .set(guard)
        .map_err(|_| anyhow::anyhow!("return handoff already accepted"))?;
    argv.drain(1..3);
    Ok(argv)
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

pub(super) fn maybe_exec(selection: &Selection) -> Result<()> {
    check_selection(selection)?;
    if selection.registration.identity == crate::identity::build() {
        return Ok(());
    }
    let program = std::ffi::OsStr::from_bytes(&selection.registration.program);
    let guard = serde_json::to_string(&selection.guard()?)?;
    let error = Command::new(program)
        .arg(HANDOFF)
        .arg(guard)
        .args(std::env::args_os().skip(1))
        .exec();
    Err(error).with_context(|| format!(
        "start matching return helper {} for @{}; reconnect from the receiving machine to refresh it",
        Path::new(program).display(), selection.name
    ))
}

pub(crate) fn copy(args: &mut crate::cli::Args) -> Result<()> {
    if args.interface != crate::cli::Interface::NativeCp {
        return Ok(());
    }
    if let Some(guard) = ACCEPTED.get() {
        guard.validate()?;
    }
    let selection = select_copy(args)?;
    if let Some(selection) = &selection {
        maybe_exec(selection)?;
    } else if ACCEPTED.get().is_some() {
        bail!("return route disappeared during handoff; retry the command");
    }
    // Some(None) records ordinary SSH/local copying; prepare must not discover
    // a different authorizer after output files or stdin have been consumed.
    args.return_selection = Some(selection);
    Ok(())
}

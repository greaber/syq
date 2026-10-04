//! Local approval decisions. Remote requests cannot submit decisions;
//! only the receiving user's private control socket and owned desktop UI can.
use anyhow::{bail, Context, Result};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::process::{Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub(crate) mod accounts;
pub(crate) mod provider_accounts;
pub(crate) use accounts::{AccountIdentity, AccountPermission};
pub(crate) use provider_accounts::ProviderLoginPermission;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AccountDecision {
    Session,
    Remember,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Answer {
    Deny,
    Allow,
    Remember,
}

pub(crate) const TIMEOUT: Duration = Duration::from_secs(300);
/// Desktop prompts show about this much of a requesting command;
/// `persist receive pending` shows all of it.
const DESKTOP_COMMAND_CHARS: usize = 400;
/// Longer titles are truncated by the macOS dialog; the directory then moves
/// into the body.
const TITLE_CHARS: usize = 40;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Mode {
    #[default]
    Ask,
    Always,
}
impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Ask => "approval required",
            Self::Always => "automatic approval",
        })
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Notifications {
    #[default]
    Desktop,
    Off,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Kind {
    #[default]
    Copy,
    Command,
    Ssh,
    ProviderSsh,
    Storage,
    Source,
}
impl Kind {
    pub(crate) fn is_copy(&self) -> bool {
        *self == Self::Copy
    }
}

/// Who is asking: the server as this machine names it, and the receiving
/// profile the request arrived on. Both come from local configuration.
#[derive(Clone, Debug)]
pub(crate) struct Requester {
    pub server: String,
    pub profile: String,
}
impl std::fmt::Display for Requester {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (receiving profile @{})", self.server, self.profile)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Summary {
    pub id: String,
    pub from: String,
    pub expires_at: u64,
    pub notification: String,
    /// The requesting command, one displayed argument per element. Commands
    /// run on this machine keep their literal arguments in `argv`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub command: Vec<String>,
    // Local desktop presentation only: preserve the released pending JSON shape.
    #[serde(skip)]
    server: String,
    /// The requesting process's working directory, as the server showed it.
    #[serde(skip)]
    server_cwd: String,
    /// The prompt's request: "wants to download", what, "to" where. Copy
    /// sources stay as the command named them; the destination is resolved.
    #[serde(skip)]
    verb: &'static str,
    #[serde(skip)]
    sources: Vec<String>,
    #[serde(skip)]
    preposition: &'static str,
    #[serde(skip)]
    target: String,
    /// Facts the command does not show, such as how long storage requests
    /// stay valid.
    #[serde(skip)]
    notes: Vec<String>,
    #[serde(flatten)]
    pub details: Details,
}
// Preserve the released copy JSON fields. Commands have their own explicit
// kind and no fabricated copy fields: old copy-only readers reject them.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub(crate) enum Details {
    Source {
        kind: SourceKind,
        source: String,
        scopes: Vec<String>,
        permission: String,
        max_bytes: u64,
        max_entries: u64,
    },
    ProviderSsh {
        kind: ProviderSshKind,
        destination: String,
        permission: String,
        provider_account: ProviderLoginPermission,
    },
    Ssh {
        kind: SshKind,
        reusable: bool,
        destination: String,
        permission: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        account: Option<AccountPermission>,
    },
    Storage {
        kind: StorageKind,
        description: String,
    },
    Command {
        kind: CommandKind,
        argv: Vec<String>,
        cwd: String,
        permission: String,
    },
    Copy {
        destination: String,
        permission: String,
        max_bytes: u64,
        max_entries: u64,
        max_delete: u64,
        preserve_permissions: bool,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CommandKind {
    Command,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SshKind {
    Ssh,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProviderSshKind {
    ProviderSsh,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StorageKind {
    Storage,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SourceKind {
    Source,
}
impl Summary {
    fn new(
        from: &Requester,
        command: &[Vec<u8>],
        cwd: &str,
        request: &crate::destination::CopyRequest,
        lifetime: Duration,
        remote: Option<&str>,
    ) -> Result<Self> {
        let mut id = [0; 16];
        getrandom::fill(&mut id).map_err(|e| anyhow::anyhow!("approval ID: {e}"))?;
        let permission = if request.copy.options.dry_run {
            "Preview only; no filesystem changes"
        } else if request.copy.options.verify_only {
            "Compare contents only; no filesystem changes"
        } else {
            use crate::delegation::ExistingDestinationPolicy::*;
            match request.copy.policy.existing {
                Replace => "May create and overwrite matching entries",
                Skip => "May create new entries; keep existing entries",
                MustExist => "May change existing entries only",
                UpdateIfOlder => bail!("unsupported receiving overwrite policy"),
            }
        };
        // Debug formatting preserves unusual bytes and escapes terminal
        // control characters. Do not interpret remote text as UI markup.
        // A copy to another server keeps its requested path; the operation's
        // own destination is a placeholder until that server resolves it.
        let (destination, permission) = match remote {
            None => (
                format!("{:?}", std::ffi::OsStr::from_bytes(&request.copy.destination)),
                permission.to_owned(),
            ),
            // Automatic approval of writes to this machine does not authorize
            // use of its SSH credentials on another host; say what that use is.
            Some(target) => (
                format!(
                    "{:?} on {target:?} using your SSH access",
                    std::ffi::OsStr::from_bytes(&request.destination)
                ),
                format!("{permission}. Uses this machine's SSH access to {target:?} and installs the syq helper there if needed"),
            ),
        };
        // Sources stay as the command wrote them, relative to `cwd` on the
        // server; only the destination is resolved, by this machine.
        let parsed = crate::approval_command::parse(command).ok();
        let sources = parsed
            .as_ref()
            .map(|args| {
                let count = args.locations.len().saturating_sub(1);
                args.locations
                    .iter()
                    .take(count)
                    .map(|location| crate::approval_command::display_arg(&location.path))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let prunes = parsed.as_ref().is_some_and(|args| args.delete);
        let target = match remote {
            None => local_path(&request.copy.destination),
            Some(target) => crate::approval_command::display_arg(
                &[target.as_bytes(), b":", request.destination.as_slice()].concat(),
            ),
        };
        Ok(Self {
            id: id.iter().map(|b| format!("{b:02x}")).collect(),
            from: format!("{:?}", from.to_string()),
            server: from.server.clone(),
            server_cwd: shown_directory(cwd),
            verb: if prunes {
                "wants to sync"
            } else if remote.is_some() {
                "wants to copy"
            } else {
                "wants to download"
            },
            sources,
            preposition: "to",
            target,
            notes: copy_notes(request, remote.is_some()),
            details: Details::Copy {
                destination,
                permission,
                max_bytes: request.copy.limits.max_total_bytes,
                max_entries: request.copy.limits.max_entries,
                max_delete: request.copy.limits.max_deletions,
                preserve_permissions: request.copy.options.preserve_permissions,
            },
            expires_at: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()
                + lifetime.as_secs(),
            notification: "starting".into(),
            command: crate::approval_command::display(command),
        })
    }
    /// The server and, when it fits the title bar, its working directory;
    /// otherwise the directory becomes the first line of the body. A
    /// directory that needed quoting stays in the body, where it is escaped.
    fn title_and_directory(&self) -> (String, Option<&str>) {
        let short = format!("syq on {}", self.server);
        if self.server_cwd.is_empty() {
            return (short, None);
        }
        let long = format!("{short} in {}", self.server_cwd);
        if long.chars().count() <= TITLE_CHARS && !self.server_cwd.starts_with('"') {
            (long, None)
        } else {
            (short, Some(&self.server_cwd))
        }
    }
    fn title(&self) -> String {
        self.title_and_directory().0
    }
    pub(crate) fn kind(&self) -> Kind {
        match self.details {
            Details::Source { .. } => Kind::Source,
            Details::Copy { .. } => Kind::Copy,
            Details::Command { .. } => Kind::Command,
            Details::Ssh { .. } => Kind::Ssh,
            Details::ProviderSsh { .. } => Kind::ProviderSsh,
            Details::Storage { .. } => Kind::Storage,
        }
    }
    pub(crate) fn account(&self) -> Option<&AccountPermission> {
        match &self.details {
            Details::Ssh { account, .. } => account.as_ref(),
            _ => None,
        }
    }
    pub(crate) fn provider_account(&self) -> Option<&ProviderLoginPermission> {
        match &self.details {
            Details::ProviderSsh {
                provider_account, ..
            } => Some(provider_account),
            _ => None,
        }
    }
    pub(crate) fn can_remember(&self) -> bool {
        self.account_permission().is_some()
    }
    fn account_permission(&self) -> Option<AccountPermissionRef<'_>> {
        self.account()
            .map(AccountPermissionRef::Return)
            .or_else(|| self.provider_account().map(AccountPermissionRef::Provider))
    }
    /// The requesting command. `server_input` styles arguments naming files that
    /// the server reads and this machine cannot check.
    fn command_text(
        &self,
        limit: Option<usize>,
        plain: impl Fn(&str) -> String,
        server_input: impl Fn(&str) -> String,
    ) -> String {
        crate::approval_command::render(&self.command, limit, plain, server_input)
    }
    /// Keep the decision visible; the full description remains available in
    /// `persist receive pending` on both platforms. With `markup`, the text is
    /// escaped for notify-send and server inputs are italic.
    ///
    /// The title is the subject, "syq on hetz ... wants to download", unless
    /// a directory line comes between. What moves and where sit indented on
    /// their own lines; the server's command comes last.
    fn desktop_description(&self, markup: bool) -> String {
        let text = |text: &str| {
            if markup {
                escape_markup(text)
            } else {
                text.to_owned()
            }
        };
        let (_, directory) = self.title_and_directory();
        let mut request = if directory.is_some() {
            format!("syq {}", self.verb)
        } else {
            self.verb.to_owned()
        };
        for source in &self.sources {
            request.push_str(&format!("\n\n    {source}"));
        }
        if !self.target.is_empty() {
            request.push_str(&format!("\n\n{}\n\n    {}", self.preposition, self.target));
        }
        for note in &self.notes {
            request.push_str(&format!("\n\n{note}"));
        }
        let command = self.desktop_command(markup);
        directory
            .map(|directory| text(&format!("in {directory}")))
            .into_iter()
            .chain([text(&request)])
            .chain((!command.is_empty()).then_some(command))
            .collect::<Vec<_>>()
            .join("\n\n")
    }
    fn desktop_command(&self, markup: bool) -> String {
        let text = |text: &str| {
            if markup {
                escape_markup(text)
            } else {
                text.to_owned()
            }
        };
        self.command_text(Some(DESKTOP_COMMAND_CHARS), text, |word| {
            if markup {
                format!("<i>{}</i>", escape_markup(word))
            } else {
                word.to_owned()
            }
        })
    }
    fn details_description(&self, server_input: impl Fn(&str) -> String) -> String {
        let command = if self.command.is_empty() {
            String::new()
        } else {
            format!(
                "\n{} command: {}",
                if self.kind() == Kind::ProviderSsh {
                    "Requester"
                } else {
                    "Server"
                },
                self.command_text(None, str::to_owned, server_input)
            )
        };
        let body = match &self.details {
            Details::Source { source, scopes, permission, max_bytes, max_entries, .. } => format!("{source}\n{}\n{permission}\nAt most {max_bytes} bytes and {max_entries} entries", scopes.join("\n")),
            Details::Storage { description, .. } => description.clone(),
            Details::Ssh { destination, permission, .. }
            | Details::ProviderSsh { destination, permission, .. } => format!("{destination}\n{permission}"),
            Details::Copy { destination, permission, max_bytes, max_entries, max_delete, preserve_permissions } =>
                format!("Destination: {destination}\n{permission}\nLimits: {max_bytes} bytes, {max_entries} entries; at most {max_delete} deletions.\nPreserve permissions: {preserve_permissions}.\nSource contents have not been inspected by this machine."),
            Details::Command { argv, cwd, permission, .. } =>
                format!("Command (literal arguments): {}\nWorking directory: {cwd}\n{permission}\nScripts and build files used by this command have not been inspected by syq.", argv.join(" ")),
        };
        format!("From: {}{command}\n{body}", self.from)
    }
    /// `server_input` styles arguments naming files that the server reads.
    pub(crate) fn description(
        &self,
        domain: &crate::persistence::Domain,
        server_input: impl Fn(&str) -> String,
    ) -> String {
        let question = match self.kind() {
            Kind::Source => "Allow these source reads once?",
            Kind::Copy => "Allow this copy once?",
            Kind::Command => "Run this command once?",
            Kind::Ssh | Kind::ProviderSsh => "Allow access to this SSH account?",
            Kind::Storage => "Authorize this storage access?",
        };
        let command = self.approval_command(domain);
        let approval = match &command {
            Some(command) => format!("Local command: {command}"),
            None => format!(
                "Approve request {} using `syq persist receive approve`, with the same --pscope argument used to list it.",
                crate::approval_command::display_arg(self.id.as_bytes())
            ),
        };
        let remember = if self.can_remember() {
            match command {
                Some(command) => {
                    format!("\nRemember this account permission: {command} --remember")
                }
                None => "\nTo remember this account permission, also pass --remember.".into(),
            }
        } else {
            String::new()
        };
        format!(
            "{}\n\n{question}\n{approval}{remember}",
            self.details_description(server_input),
        )
    }

    fn approval_command(&self, domain: &crate::persistence::Domain) -> Option<String> {
        let mut command = "syq persist".to_owned();
        if let Some(scope) = domain.explicit_path() {
            // A lossy path could point at another domain. Non-UTF-8 scopes
            // instead get instructions to repeat the caller's original flag.
            command.push_str(&format!(
                " --pscope {}",
                shell_words::quote(scope.to_str()?)
            ));
        }
        command.push_str(&format!(
            " receive approve {}",
            shell_words::quote(&self.id)
        ));
        Some(command)
    }
}
/// A server's working directory as sent, escaped here like any other remote
/// text: quoted with control characters escaped when it is not plain.
fn shown_directory(cwd: &str) -> String {
    if cwd.is_empty() {
        String::new()
    } else {
        crate::approval_command::display_arg(cwd.as_bytes())
    }
}
/// A path on this machine, with its home shortened to `~`.
fn local_path(path: &[u8]) -> String {
    crate::approval_command::display_arg(&crate::approval_command::abbreviate_home(
        path,
        std::env::var_os("HOME").as_deref(),
    ))
}

/// What this copy does beyond moving files: only facts that differ between
/// requests, such as a preview, a non-default overwrite policy, deletions, or
/// an existing destination. For a local destination, the named mutation
/// roots are inspected (never their children or contents). This is a local
/// hint, not a restriction on the approved policy or a promise that names
/// cannot change before execution. Another server is not contacted using the
/// receiving machine's credentials before approval.
fn copy_notes(request: &crate::destination::CopyRequest, remote: bool) -> Vec<String> {
    use crate::delegation::{ExistingDestinationPolicy, RootExistence};
    let options = &request.copy.options;
    let mut notes = Vec::new();
    if options.dry_run {
        notes.push("preview only".to_owned());
    } else if options.verify_only {
        notes.push("compares only, writes nothing".to_owned());
    } else {
        match request.copy.policy.existing {
            ExistingDestinationPolicy::Skip => notes.push("keeps existing files".to_owned()),
            ExistingDestinationPolicy::MustExist => {
                notes.push("changes existing files only".to_owned())
            }
            _ if remote || request.constraints.root_existence == RootExistence::New => {}
            _ => match destination_exists(request) {
                Some(true) => notes.push("replaces existing files".to_owned()),
                Some(false) => {}
                None => notes.push("may replace existing files".to_owned()),
            },
        }
    }
    let deletions = request.copy.limits.max_deletions;
    if deletions > 0 && !options.dry_run && !options.verify_only {
        notes.push(format!("deletes up to {deletions} files or folders"));
    }
    notes
}
/// Whether any named mutation root exists on this machine, or `None` when
/// that cannot be told cheaply. Existing directory scopes need no recursive
/// inspection: merging into them can overwrite children whose names are not
/// yet known.
fn destination_exists(request: &crate::destination::CopyRequest) -> Option<bool> {
    let scopes = &request.copy.mutation_scopes;
    if scopes.is_empty() || scopes.len() > 32 {
        return None;
    }
    let root = crate::rooted::Root::open(std::path::Path::new("/")).ok()?;
    for scope in scopes {
        let relative = scope.path.strip_prefix(b"/")?;
        if relative.split(|byte| *byte == b'/').count() > 32 {
            return None;
        }
        let relative = crate::rooted::RelativePath::new(relative).ok()?;
        match root.metadata(&relative) {
            Ok(_) => return Some(true),
            Err(error)
                if error.chain().any(|cause| {
                    cause
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
                }) => {}
            Err(_) => return None,
        }
    }
    Some(false)
}

/// What a storage authorization lets the server do, in the prompt's shape:
/// the verb, what, where, and the facts that differ between requests.
fn storage_request(
    command: &[Vec<u8>],
    request: &crate::s3::authorization::Request,
) -> (&'static str, Vec<String>, &'static str, String, Vec<String>) {
    use crate::s3::authorization::{Removal, Scope};
    fn locations(bucket: &str, scopes: &[Scope]) -> Vec<String> {
        let mut shown: Vec<_> = scopes
            .iter()
            .take(3)
            .map(|scope| {
                crate::approval_command::display_arg(
                    format!("s3://{bucket}/{}", scope.key).as_bytes(),
                )
            })
            .collect();
        if scopes.len() > 3 {
            shown.push(format!("and {} more", scopes.len() - 3));
        }
        shown
    }
    // The command names the operation and its local operands; a dry run
    // clears the request's write flags, so they cannot say the direction.
    let parsed = crate::approval_command::parse(command).ok();
    let local = parsed
        .as_ref()
        .map(|args| {
            args.locations
                .iter()
                .filter(|location| location.host.is_none())
                .map(|location| crate::approval_command::display_arg(&location.path))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let (removes, uploads, prunes, dry_run) = match &parsed {
        Some(args) => (
            args.rm,
            matches!(
                args.s3.as_ref().map(|options| &options.route),
                Some(crate::s3::Route::Upload | crate::s3::Route::ServerCopy { .. })
            ),
            args.delete,
            args.dry_run,
        ),
        None => (
            request.delete && !request.upload,
            request.upload,
            false,
            false,
        ),
    };
    let storage = locations(&request.bucket, &request.scopes);
    let (verb, sources, preposition, target) = if removes {
        ("wants to delete", storage, "", String::new())
    } else if let Some(source) = &request.source {
        (
            if prunes {
                "wants to sync"
            } else {
                "wants to copy"
            },
            locations(&source.bucket, &source.scopes),
            "to",
            storage.join("\n    "),
        )
    } else if uploads {
        (
            if prunes {
                "wants to sync"
            } else {
                "wants to upload"
            },
            local,
            "to",
            storage.join("\n    "),
        )
    } else {
        let destination = local.last().cloned().unwrap_or_default();
        ("wants to download", storage, "to", destination)
    };
    let mut notes = Vec::new();
    if dry_run {
        notes.push("preview only".to_owned());
    }
    if request.delete
        && matches!(
            request.removal,
            Some(Removal::Version(_) | Removal::AllVersions)
        )
    {
        notes.push("deleting versions is permanent".to_owned());
    }
    // An endpoint from the server's environment is invisible in the command.
    if let Some(endpoint) = &request.endpoint {
        if !command.iter().any(|arg| arg.starts_with(b"--s3-endpoint")) {
            notes.push(format!(
                "endpoint {}",
                crate::approval_command::display_arg(endpoint.as_bytes())
            ));
        }
    }
    (verb, sources, preposition, target, notes)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AccountPermissionRef<'a> {
    Return(&'a AccountPermission),
    Provider(&'a ProviderLoginPermission),
}

struct Pending {
    summary: Summary,
    deadline: Instant,
    decision: Option<Answer>,
}
#[derive(Default)]
pub(crate) struct Queue {
    domain: crate::persistence::Domain,
    pending: Mutex<BTreeMap<String, Pending>>,
}
impl Queue {
    pub(crate) fn new(domain: crate::persistence::Domain) -> Self {
        Self {
            domain,
            pending: Mutex::default(),
        }
    }
    pub(crate) fn account_remembered(&self, permission: &AccountPermission) -> Result<bool> {
        accounts::remembered(&self.domain, permission)
    }
    pub(crate) fn provider_account_remembered(
        &self,
        permission: &ProviderLoginPermission,
    ) -> Result<bool> {
        provider_accounts::remembered(&self.domain, permission)
    }
    pub(crate) fn snapshots(&self) -> Vec<Summary> {
        self.pending
            .lock()
            .unwrap()
            .values()
            .filter(|p| p.decision.is_none() && Instant::now() < p.deadline)
            .map(|p| p.summary.clone())
            .collect()
    }
    #[cfg(test)]
    pub(crate) fn decide(&self, id: &str, allow: bool, kind: Kind) -> Result<()> {
        self.decide_with_remember(id, allow, kind, false)
    }
    pub(crate) fn decide_with_remember(
        &self,
        id: &str,
        allow: bool,
        kind: Kind,
        remember: bool,
    ) -> Result<()> {
        self.decide_using(id, allow, kind, remember, |permission| match permission {
            AccountPermissionRef::Return(permission) => {
                accounts::remember(&self.domain, permission)
            }
            AccountPermissionRef::Provider(permission) => {
                provider_accounts::remember(&self.domain, permission)
            }
        })
    }
    fn decide_using(
        &self,
        id: &str,
        allow: bool,
        kind: Kind,
        remember: bool,
        save: impl FnOnce(AccountPermissionRef<'_>) -> Result<()>,
    ) -> Result<()> {
        let mut pending = self.pending.lock().unwrap();
        let entry = pending
            .get_mut(id)
            .context("approval is unknown, expired, or already answered")?;
        if entry.decision.is_some() || Instant::now() >= entry.deadline {
            bail!("approval is expired or already answered");
        }
        if entry.summary.kind() != kind {
            bail!(
                "approval request kind differs; use a matching syq client to inspect and decide it"
            );
        }
        if remember {
            anyhow::ensure!(
                allow && matches!(kind, Kind::Ssh | Kind::ProviderSsh),
                "--remember applies only to SSH account approval"
            );
            let account = entry.summary.account_permission().context("this SSH request does not support remembered permissions; update syq and reconnect receiving")?;
            save(account)
                .context("remember account permission; the request is still awaiting approval")?;
        }
        entry.decision = Some(if !allow {
            Answer::Deny
        } else if remember {
            Answer::Remember
        } else {
            Answer::Allow
        });
        Ok(())
    }
    fn notification_status(&self, id: &str, status: String) {
        if let Some(pending) = self.pending.lock().unwrap().get_mut(id) {
            pending.summary.notification = status;
        }
    }
    pub(crate) fn request(
        &self,
        from: &Requester,
        command: &[Vec<u8>],
        cwd: &str,
        request: &crate::destination::CopyRequest,
        notifications: Notifications,
        cancelled: impl Fn() -> bool,
    ) -> Result<()> {
        self.wait(
            Summary::new(from, command, cwd, request, TIMEOUT, None)?,
            notifications,
            TIMEOUT,
            cancelled,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn request_remote(
        &self,
        from: &Requester,
        command: &[Vec<u8>],
        cwd: &str,
        target: &str,
        request: &crate::destination::CopyRequest,
        notifications: Notifications,
        cancelled: impl Fn() -> bool,
    ) -> Result<()> {
        self.wait(
            Summary::new(from, command, cwd, request, TIMEOUT, Some(target))?,
            notifications,
            TIMEOUT,
            cancelled,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn request_command(
        &self,
        from: &Requester,
        argv: &[Vec<u8>],
        cwd: &std::path::Path,
        command: &[Vec<u8>],
        server_cwd: &str,
        notifications: Notifications,
        cancelled: impl Fn() -> bool,
    ) -> Result<()> {
        let mut id = [0; 16];
        getrandom::fill(&mut id).map_err(|e| anyhow::anyhow!("approval ID: {e}"))?;
        self.wait(Summary {
            id: id.iter().map(|b| format!("{b:02x}")).collect(),
            from: format!("{:?}", from.to_string()),
            server: from.server.clone(),
            expires_at: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + TIMEOUT.as_secs(),
            notification: "starting".into(),
            command: crate::approval_command::display(command),
            server_cwd: shown_directory(server_cwd),
            verb: "wants to run",
            sources: vec![argv
                .iter()
                .map(|arg| crate::approval_command::display_arg(arg))
                .collect::<Vec<_>>()
                .join(" ")],
            preposition: "in",
            target: local_path(cwd.as_os_str().as_bytes()),
            notes: Vec::new(),
            details: Details::Command {
                kind: CommandKind::Command,
                argv: argv.iter().map(|arg| format!("{:?}", std::ffi::OsStr::from_bytes(arg))).collect(),
                cwd: format!("{cwd:?}"),
                permission: "Runs as your local user with access to your files, programs and credentials. Copy root and copy limits do not contain this command. Stdin is closed.".into(),
            },
        }, notifications, TIMEOUT, cancelled)
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn request_ssh(
        &self,
        from: &Requester,
        command: &[Vec<u8>],
        cwd: &str,
        endpoint: &crate::cli::NativeEndpoint,
        persistent: bool,
        notifications: Notifications,
        cancelled: impl Fn() -> bool,
    ) -> Result<()> {
        let mut id = [0; 16];
        getrandom::fill(&mut id).map_err(|e| anyhow::anyhow!("approval ID: {e}"))?;
        let target = format!(
            "{}@{}:{}",
            endpoint.user.as_deref().unwrap_or(""),
            endpoint.host,
            endpoint.port.unwrap_or(22)
        );
        self.wait(Summary {
            id: id.iter().map(|b| format!("{b:02x}")).collect(),
            from: format!("{:?}", from.to_string()),
            server: from.server.clone(),
            expires_at: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + TIMEOUT.as_secs(),
            notification: "starting".into(),
            command: crate::approval_command::display(command),
            server_cwd: shown_directory(cwd),
            verb: "wants SSH account access",
            sources: Vec::new(),
            preposition: "to",
            target: target.clone(),
            notes: vec![if persistent {
                "This permits repeated commands and copies through a reusable SSH login while the laptop stays connected. Close it with syq persist off.".into()
            } else {
                "This grants account access, not permission for only the displayed command.".into()
            }],
            details: Details::Ssh {
                kind: SshKind::Ssh,
                reusable: persistent,
                account: None,
                destination: target,
                permission: if persistent {
                    "May reuse this account's full authority for repeated SSH commands and copies while the laptop stays connected. Copy roots and limits do not apply. Close this login with syq persist off.".into()
                } else {
                    "May use this account's full authority for this SSH login. Copy roots and limits do not apply. Session traffic travels directly between the servers.".into()
                },
            },
        }, notifications, TIMEOUT, cancelled)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn request_account(
        &self,
        from: &Requester,
        command: &[Vec<u8>],
        cwd: &str,
        account: &AccountPermission,
        notifications: Notifications,
        cancelled: impl Fn() -> bool,
    ) -> Result<AccountDecision> {
        anyhow::ensure!(
            account.profile == from.profile,
            "account permission differs from the receiving profile"
        );
        let mut id = [0; 16];
        getrandom::fill(&mut id).map_err(|e| anyhow::anyhow!("approval ID: {e}"))?;
        let target = account.destination.label();
        self.wait_decision(Summary {
            id: id.iter().map(|b| format!("{b:02x}")).collect(),
            from: format!("{:?}", from.to_string()), server: from.server.clone(),
            expires_at: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + TIMEOUT.as_secs(),
            notification: "starting".into(), command: crate::approval_command::display(command),
            server_cwd: shown_directory(cwd), verb: "wants SSH account access", sources: vec![account.source.label()],
            preposition: "to", target: target.clone(),
            notes: vec![
                "Allow grants account access until this laptop's receiving connection to the source ends. It is not limited to the displayed command.".into(),
                "Remember also permits future authentications for these accounts through this receiving profile while the laptop is available. Remove it with syq persist receive permissions remove ID; already authenticated sessions may continue.".into(),
            ],
            details: Details::Ssh { kind: SshKind::Ssh, reusable: true, destination: target,
                permission: format!("{} may use this destination account's full authority for commands and copies. Allow lasts until this laptop's receiving connection to the source ends. Remember also permits future authentications for these accounts through profile @{} while the laptop is available. Removing a remembered permission stops future authentications; already authenticated sessions may continue. Copy roots and limits do not apply. Session traffic travels directly between the servers.", account.source.label(), account.profile),
                account: Some(account.clone()),
            },
        }, notifications, TIMEOUT, cancelled)
    }

    /// The provider supplies its verified local identity and destination policy.
    /// Command/cwd are requester context, never proof of an originating host.
    pub(crate) fn request_provider_account(
        &self,
        command: &[Vec<u8>],
        cwd: &str,
        account: &ProviderLoginPermission,
        notifications: Notifications,
        cancelled: impl Fn() -> bool,
    ) -> Result<AccountDecision> {
        account.validate()?;
        let mut id = [0; 16];
        getrandom::fill(&mut id).map_err(|e| anyhow::anyhow!("approval ID: {e}"))?;
        let target = account.destination.label();
        let origin = account.provider.label();
        let authority = "May use this destination account's full authority for commands and copies. Copy roots and limits do not apply; the displayed command is context, not a restriction.";
        let allow = "Allow lasts for this provider-issued authorization session.";
        let remember = format!("Remember also permits future SSH logins to this provider account through profile @{} to request the same destination account. It does not identify a requesting source machine. Removing a remembered permission requires new approval for future authentications; already authenticated sessions may continue.", account.profile);
        let identity = format!(
            "Provider receiving identity: {} (not an SSH host key).",
            account.provider.receiver_identity
        );
        let mut notes = vec![
            authority.into(),
            allow.into(),
            remember.clone(),
            identity.clone(),
        ];
        if !cwd.is_empty() {
            notes.push(format!(
                "Requester's reported directory: {}",
                shown_directory(cwd)
            ));
        }
        self.wait_decision(
            Summary {
                id: id.iter().map(|byte| format!("{byte:02x}")).collect(),
                from: format!("{origin} (provider profile @{})", account.profile),
                server: format!("provider account {}", account.provider.user),
                expires_at: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()
                    + TIMEOUT.as_secs(),
                notification: "starting".into(),
                command: crate::approval_command::display(command),
                server_cwd: String::new(),
                verb: "requests SSH account access",
                sources: vec![origin.clone()],
                preposition: "to",
                target: target.clone(),
                notes,
                details: Details::ProviderSsh {
                    kind: ProviderSshKind::ProviderSsh,
                    destination: target,
                    permission: format!("{origin}. {authority} {allow} {remember} {identity}"),
                    provider_account: account.clone(),
                },
            },
            notifications,
            TIMEOUT,
            cancelled,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn request_source(
        &self,
        from: &Requester,
        command: &[Vec<u8>],
        cwd: &str,
        target: &str,
        request: &crate::destination::pull::PullRequest,
        notifications: Notifications,
        cancelled: impl Fn() -> bool,
    ) -> Result<()> {
        let mut id = [0; 16];
        getrandom::fill(&mut id).map_err(|e| anyhow::anyhow!("approval ID: {e}"))?;
        let scopes = request.scopes();
        let base = request
            .base
            .path
            .as_deref()
            .map(crate::approval_command::display_arg)
            .unwrap_or_else(|| "source login directory".into());
        let permission = format!("May list and read the selected directory trees or exact non-directory entries. Filters narrow the copy, not this read permission. {}: {base}. Uses this machine's SSH access and installs the syq helper if needed. File data travels directly between the servers; no source mutations are allowed.", if request.base.confined { "Hard source root" } else { "Source working directory" });
        self.wait(
            Summary {
                id: id.iter().map(|b| format!("{b:02x}")).collect(),
                from: format!("{:?}", from.to_string()),
                server: from.server.clone(),
                expires_at: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()
                    + TIMEOUT.as_secs(),
                notification: "starting".into(),
                command: crate::approval_command::display(command),
                server_cwd: shown_directory(cwd),
                verb: "wants to read",
                sources: scopes.clone(),
                preposition: "from",
                target: target.into(),
                notes: vec![
                    permission.clone(),
                    "Read authority ends when this copy closes, or after seven days.".into(),
                ],
                details: Details::Source {
                    kind: SourceKind::Source,
                    source: target.into(),
                    scopes,
                    permission,
                    max_bytes: request.limits.max_total_bytes,
                    max_entries: request.limits.max_entries,
                },
            },
            notifications,
            TIMEOUT,
            cancelled,
        )
    }

    pub(crate) fn request_storage(
        &self,
        from: &Requester,
        command: &[Vec<u8>],
        cwd: &str,
        request: &crate::s3::authorization::Request,
        notifications: Notifications,
        cancelled: impl Fn() -> bool,
    ) -> Result<()> {
        let mut id = [0; 16];
        getrandom::fill(&mut id).map_err(|e| anyhow::anyhow!("approval ID: {e}"))?;
        let scopes = request
            .scopes
            .iter()
            .map(|scope| {
                format!(
                    "{:?}{}",
                    scope.key,
                    if scope.descendants {
                        " and descendants"
                    } else {
                        ""
                    }
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        let source = request
            .source
            .as_ref()
            .map(|source| {
                format!(
                    "\nCopy source bucket: {:?}\nRead source objects and tags:\n{}",
                    source.bucket,
                    source
                        .scopes
                        .iter()
                        .map(|scope| format!(
                            "{:?}{}",
                            scope.key,
                            if scope.descendants {
                                " and descendants"
                            } else {
                                ""
                            }
                        ))
                        .collect::<Vec<_>>()
                        .join("\n")
                )
            })
            .unwrap_or_default();
        let removal = match &request.removal {
            Some(crate::s3::authorization::Removal::AllVersions) => "\nSelection: all versions and delete markers. Version discovery may list names sharing the selected key prefix.".to_owned(),
            Some(crate::s3::authorization::Removal::Version(id)) => format!("\nSelected version or delete marker: {id:?}. Version discovery may list names sharing the selected key prefix."),
            _ => String::new(),
        };
        let permanence = if request.delete
            && matches!(
                request.removal,
                Some(
                    crate::s3::authorization::Removal::Version(_)
                        | crate::s3::authorization::Removal::AllVersions
                )
            ) {
            "\nDeleting selected versions or delete markers is permanent."
        } else {
            ""
        };
        let acl = if request.acl.is_empty() {
            String::new()
        } else {
            format!("\nApproved object ACL headers: {:?}", request.acl)
        };
        let description = format!("Bucket: {:?}\nEndpoint: {:?}\nCredential profile on this machine: {:?}\nPaths:\n{scopes}{source}{removal}{permanence}{acl}\nPermission: {}{}{}.\nRequested lifetime: {} seconds (credentials or provider policies may shorten it).\nIssued requests can be reused until expiry, even after this machine disconnects or receiving stops. Copy roots, aggregate limits and receiver receipts do not apply. Source contents are not inspected.",
            request.bucket, request.endpoint.as_deref().unwrap_or("configured AWS/S3 endpoint"), request.profile.as_deref().unwrap_or("default"),
            if request.upload { "read and upload" } else { "read" },
            if request.create_only { ", create-only writes" } else if request.upload { ", may overwrite" } else { "" },
            if request.delete { ", may delete" } else { ", no object deletion" }, request.lifetime);
        let (verb, sources, preposition, target, notes) = storage_request(command, request);
        self.wait(
            Summary {
                id: id.iter().map(|b| format!("{b:02x}")).collect(),
                from: format!("{:?}", from.to_string()),
                server: from.server.clone(),
                expires_at: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()
                    + TIMEOUT.as_secs(),
                notification: "starting".into(),
                command: crate::approval_command::display(command),
                server_cwd: shown_directory(cwd),
                verb,
                sources,
                preposition,
                target,
                notes,
                details: Details::Storage {
                    kind: StorageKind::Storage,
                    description,
                },
            },
            notifications,
            TIMEOUT,
            cancelled,
        )
    }
    fn wait(
        &self,
        summary: Summary,
        notifications: Notifications,
        lifetime: Duration,
        cancelled: impl Fn() -> bool,
    ) -> Result<()> {
        self.wait_decision(summary, notifications, lifetime, cancelled)
            .map(|_| ())
    }
    fn wait_decision(
        &self,
        summary: Summary,
        notifications: Notifications,
        lifetime: Duration,
        cancelled: impl Fn() -> bool,
    ) -> Result<AccountDecision> {
        if cancelled() {
            bail!("request disconnected before approval");
        }
        let id = summary.id.clone();
        let deadline = Instant::now() + lifetime;
        {
            let mut pending = self.pending.lock().unwrap();
            if pending.len() >= 8 {
                bail!("too many requests awaiting approval");
            }
            pending.insert(
                id.clone(),
                Pending {
                    summary: summary.clone(),
                    deadline,
                    decision: None,
                },
            );
        }
        struct Remove<'a> {
            queue: &'a Queue,
            id: String,
        }
        impl Drop for Remove<'_> {
            fn drop(&mut self) {
                self.queue.pending.lock().unwrap().remove(&self.id);
            }
        }
        let _remove = Remove {
            queue: self,
            id: id.clone(),
        };
        let mut notification = if notifications == Notifications::Desktop {
            match Notification::spawn(&summary, lifetime) {
                Ok(notification) => {
                    self.notification_status(&id, "desktop prompt requested; use local syq persist receive approve/deny if it is not visible".into());
                    Some(notification)
                }
                Err(error) => {
                    self.notification_status(
                        &id,
                        format!(
                            "unavailable: {error:#}; use local syq persist receive approve/deny"
                        ),
                    );
                    None
                }
            }
        } else {
            self.notification_status(
                &id,
                "disabled; use local syq persist receive approve/deny".into(),
            );
            None
        };
        loop {
            if cancelled() {
                bail!("request disconnected or receiving stopped while awaiting approval");
            }
            if Instant::now() >= deadline {
                bail!(
                    "request approval expired after {} seconds",
                    lifetime.as_secs()
                );
            }
            if let Some(answer) = self
                .pending
                .lock()
                .unwrap()
                .get(&id)
                .and_then(|p| p.decision)
            {
                if answer == Answer::Deny {
                    bail!("request denied on the receiving machine");
                }
                // An answer that races disconnect/expiry cannot survive it.
                if cancelled() || Instant::now() >= deadline {
                    bail!("request approval expired or was cancelled");
                }
                return Ok(if answer == Answer::Remember {
                    AccountDecision::Remember
                } else {
                    AccountDecision::Session
                });
            }
            if let Some(process) = notification.as_mut() {
                // Some notify-send versions keep waiting after reporting a
                // desktop error. Surface it without granting permission or
                // waiting for that process to exit.
                if process.error_seen.load(Ordering::Acquire) {
                    self.notification_status(
                        &id,
                        "desktop reported an error; use local syq persist receive approve/deny"
                            .into(),
                    );
                }
                if let Some(result) = process.poll() {
                    notification.take();
                    match result {
                        Ok(Some(answer)) => {
                            if let Err(error) = self.decide_with_remember(&id, answer != Answer::Deny,
                                summary.kind(), answer == Answer::Remember) {
                                self.notification_status(&id, format!("decision failed: {error:#}; use local syq persist receive approve/deny"));
                            }
                        }
                        Ok(None) => self.notification_status(
                            &id,
                            "dismissed; use local syq persist receive approve/deny".into(),
                        ),
                        Err(error) => self.notification_status(
                            &id,
                            format!("unavailable: {error:#}; use local syq persist receive approve/deny"),
                        ),
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }
}

fn escape_markup(text: &str) -> String {
    // notify-send applies g_strcompress to its body argument before passing
    // it to D-Bus. Preserve escaped filename bytes through that extra parser.
    text.replace('\\', "\\\\")
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
#[cfg(target_os = "macos")]
const APPLESCRIPT: &str = r#"on run argv
    try
        set remainingSeconds to item 2 of argv as integer
        if (item 4 of argv) is "account" then
            set answer to display dialog (item 1 of argv) with title (item 3 of argv) buttons {"Remember", "Allow", "Deny"} default button "Deny" cancel button "Deny" giving up after remainingSeconds
        else
            set answer to display dialog (item 1 of argv) with title (item 3 of argv) buttons {"Allow once", "Deny"} default button "Deny" cancel button "Deny" giving up after remainingSeconds
        end if
        if gave up of answer then return "expired"
        if button returned of answer is "Remember" then return "remember"
        if button returned of answer is "Allow" then return "allow"
        if button returned of answer is "Allow once" then return "allow"
        return "deny"
    on error number -128
        return "deny"
    end try
end run"#;
fn notification_command(summary: &Summary, lifetime: Duration) -> Command {
    let description = summary.desktop_description(cfg!(not(target_os = "macos")));
    let title = summary.title();
    #[cfg(target_os = "macos")]
    {
        let mut cmd = Command::new("/usr/bin/osascript");
        cmd.args([
            "-e",
            APPLESCRIPT,
            "--",
            &description,
            &lifetime.as_secs().max(1).to_string(),
            &title,
            if summary.can_remember() {
                "account"
            } else {
                "once"
            },
        ]);
        cmd
    }
    #[cfg(not(target_os = "macos"))]
    {
        let mut cmd = Command::new("/usr/bin/notify-send");
        cmd.args(["--app-name=syq", "--wait"]);
        if summary.can_remember() {
            cmd.args(["--action=allow=Allow", "--action=remember=Remember"]);
        } else {
            cmd.arg("--action=allow=Allow once");
        }
        cmd.arg("--action=deny=Deny")
            .arg(format!("--expire-time={}", lifetime.as_millis()))
            .arg("--")
            .arg(&title)
            .arg(description);
        cmd
    }
}
fn capture(
    mut input: impl Read + Send + 'static,
    seen: Option<Arc<AtomicBool>>,
) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut output = Vec::new();
        let mut buffer = [0; 1024];
        while let Ok(count) = input.read(&mut buffer) {
            if count == 0 {
                break;
            }
            if let Some(seen) = &seen {
                seen.store(true, Ordering::Release);
            }
            let keep = count.min(4096_usize.saturating_sub(output.len()));
            output.extend_from_slice(&buffer[..keep]);
        }
        output
    })
}
struct Notification {
    child: crate::process_group::ProcessGroup,
    error_seen: Arc<AtomicBool>,
    output: Option<std::thread::JoinHandle<Vec<u8>>>,
    errors: Option<std::thread::JoinHandle<Vec<u8>>>,
}
impl Notification {
    fn spawn(summary: &Summary, lifetime: Duration) -> Result<Self> {
        Self::spawn_command(notification_command(summary, lifetime))
    }
    fn spawn_command(mut command: std::process::Command) -> Result<Self> {
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = crate::process_group::ProcessGroup::spawn(&mut command)
            .context("start desktop approval prompt")?;
        let error_seen = Arc::new(AtomicBool::new(false));
        let output = Some(capture(child.child.stdout.take().unwrap(), None));
        let errors = Some(capture(
            child.child.stderr.take().unwrap(),
            Some(error_seen.clone()),
        ));
        Ok(Self {
            child,
            error_seen,
            output,
            errors,
        })
    }
    fn close(&mut self) -> std::io::Result<std::process::ExitStatus> {
        self.child.close()
    }
    fn poll(&mut self) -> Option<Result<Option<Answer>>> {
        let status = match self.child.poll() {
            Ok(None) => return None,
            Ok(Some(status)) => status,
            Err(error) => return Some(Err(error.into())),
        };
        let output = self.output.take().unwrap().join().unwrap_or_default();
        let errors = self.errors.take().unwrap().join().unwrap_or_default();
        Some(if !status.success() {
            Err(anyhow::anyhow!(
                "desktop prompt exited {status}: {:?}",
                String::from_utf8_lossy(&errors)
            ))
        } else {
            match output.as_slice() {
                b"allow\n" => Ok(Some(Answer::Allow)),
                b"deny\n" => Ok(Some(Answer::Deny)),
                b"remember\n" => Ok(Some(Answer::Remember)),
                _ => Ok(None),
            }
        })
    }
}
impl Drop for Notification {
    fn drop(&mut self) {
        let _ = self.close();
        if let Some(reader) = self.output.take() {
            let _ = reader.join();
        }
        if let Some(reader) = self.errors.take() {
            let _ = reader.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn summary() -> Summary {
        Summary {
            id: "request".into(),
            from: "\"server (receiving profile @laptop)\"".into(),
            server: "server".into(),
            details: Details::Copy {
                destination: "/tmp/receiving".into(),
                permission: "May create and overwrite".into(),
                max_bytes: 100,
                max_entries: 3,
                max_delete: 0,
                preserve_permissions: false,
            },
            expires_at: 0,
            notification: String::new(),
            command: Vec::new(),
            server_cwd: "~/rt-bench".into(),
            verb: "wants to download",
            sources: vec!["dbg".into()],
            preposition: "to",
            target: "~/Downloads/server/dbg".into(),
            notes: Vec::new(),
        }
    }
    fn requester() -> Requester {
        Requester {
            server: "server".into(),
            profile: "laptop".into(),
        }
    }
    fn copy_request(path: &std::path::Path) -> crate::destination::CopyRequest {
        use crate::delegation::*;
        let path = path.as_os_str().as_bytes().to_vec();
        crate::destination::CopyRequest {
            destination: path.clone(),
            copy: CopyOperation {
                destination: path.clone(),
                mutation_scopes: vec![MutationScope {
                    path,
                    descendants: true,
                }],
                policy: CopyPolicy {
                    placement: DestinationPlacement::ExactPath,
                    existing: ExistingDestinationPolicy::Replace,
                    deletion: DeletionPolicy::Forbid,
                    publication: PublicationPolicy::AtomicStaged,
                },
                options: CopyOptions {
                    recursive: true,
                    preserve_symlinks: true,
                    preserve_permissions: false,
                    receiver_managed_modes: true,
                    preserve_times: true,
                    preserve_owner: false,
                    preserve_group: false,
                    preserve_devices: false,
                    compare_existing_by_content: false,
                    dry_run: false,
                    verify_only: false,
                    compressed_transport: true,
                    tcp_port_lo: 47600,
                    tcp_port_hi: 47699,
                },
                limits: CopyLimits {
                    max_entries: 100,
                    max_total_bytes: 1000,
                    max_file_bytes: 1000,
                    hash_block_bytes: 4096,
                    max_connections: 1,
                    max_deletions: 0,
                },
            },
            constraints: GrantConstraints::default(),
        }
    }

    #[test]
    fn approval_instructions_select_the_listed_domain_and_quote_its_path() {
        use crate::persistence::Domain;
        let mut summary = summary();
        summary.details = Details::Ssh {
            kind: SshKind::Ssh,
            reusable: true,
            destination: "alice@destination:22".into(),
            permission: "account access".into(),
            account: Some(account_permission()),
        };
        for domain in [
            Domain::default(),
            Domain::Explicit("/tmp/scope 'quoted' $(untrusted)".into()),
        ] {
            let description = summary.description(&domain, str::to_owned);
            let mut expected = vec!["syq", "persist"];
            if let Some(scope) = domain.explicit_path() {
                expected.extend(["--pscope", scope.to_str().unwrap()]);
            }
            expected.extend(["receive", "approve", "request"]);
            let approve = description
                .lines()
                .find_map(|line| line.strip_prefix("Local command: "))
                .unwrap();
            assert_eq!(shell_words::split(approve).unwrap(), expected);
            if domain.is_default() {
                assert_eq!(approve, "syq persist receive approve request");
            }
            let remember = description
                .lines()
                .find_map(|line| line.strip_prefix("Remember this account permission: "))
                .unwrap();
            expected.push("--remember");
            assert_eq!(shell_words::split(remember).unwrap(), expected);
        }
    }

    #[test]
    fn approval_instructions_do_not_render_a_lossy_scope_as_a_command() {
        use std::os::unix::ffi::OsStringExt;
        let path = std::ffi::OsString::from_vec(b"/tmp/non-utf8-\xff".to_vec());
        let domain = crate::persistence::Domain::Explicit(path.into());
        let description = summary().description(&domain, str::to_owned);
        assert!(description.contains("Approve request request"));
        assert!(description.contains("same --pscope argument"));
        assert!(!description.contains("Local command:"));
        assert!(!description.contains("syq persist receive approve request"));
        assert!(!description.contains('\u{fffd}'));
    }

    #[test]
    fn v0_6_0_pending_json_remains_compatible() {
        // Unchanged released copy/command envelopes; storage does not reuse
        // their kind or add fields to their serialized form.
        for (raw, kind) in [
            (
                r#"{"id":"fixture","from":"server","expires_at":123,"notification":"off","destination":"backup","permission":"copy","max_bytes":100,"max_entries":10,"max_delete":0,"preserve_permissions":false}"#,
                Kind::Copy,
            ),
            (
                r#"{"id":"fixture","from":"server","expires_at":123,"notification":"off","kind":"command","argv":["true"],"cwd":"/tmp","permission":"run"}"#,
                Kind::Command,
            ),
        ] {
            let expected: serde_json::Value = serde_json::from_str(raw).unwrap();
            let summary: Summary = serde_json::from_str(raw).unwrap();
            assert_eq!(summary.kind(), kind);
            assert_eq!(serde_json::to_value(summary).unwrap(), expected);
        }
        let storage: Summary = serde_json::from_str(r#"{"id":"fixture","from":"server","expires_at":123,"notification":"off","kind":"storage","description":"read bucket/path"}"#).unwrap();
        assert_eq!(storage.kind(), Kind::Storage);
    }

    #[test]
    fn prompts_show_command_sources_and_the_resolved_destination() {
        let temp = crate::test_support::tempdir().unwrap();
        let path = temp.path().canonicalize().unwrap().join("dbg");
        let request = copy_request(&path);
        let command: Vec<Vec<u8>> = ["cp", "rt-bench/dbg", "--to", "@laptop", "--as", "dbg"]
            .iter()
            .map(|arg| arg.as_bytes().to_vec())
            .collect();
        let summary = Summary::new(
            &requester(),
            &command,
            "~/rt-bench",
            &request,
            TIMEOUT,
            None,
        )
        .unwrap();
        assert_eq!(summary.title(), "syq on server in ~/rt-bench");
        assert_eq!(
            summary.desktop_description(false),
            format!(
                "wants to download\n\n    rt-bench/dbg\n\nto\n\n    {}\n\nsyq cp rt-bench/dbg --to @laptop --as dbg",
                path.display()
            )
        );
        // No presentation-only field enters the released pending JSON contract:
        // the released copy fields plus the command.
        let json = serde_json::to_value(&summary).unwrap();
        assert_eq!(json.as_object().unwrap().len(), 11);
        assert_eq!(json["from"], "\"server (receiving profile @laptop)\"");
        assert_eq!(
            json["permission"],
            "May create and overwrite matching entries"
        );
        let old_shape: Summary = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(serde_json::to_value(old_shape).unwrap(), json);

        // Another host is never inspected; the destination keeps its host and
        // the requested path, not the placeholder that host later resolves.
        let mut forwarded = request.clone();
        forwarded.copy.destination = b"/SYQ-RECEIVE".to_vec();
        let remote = Summary::new(
            &requester(),
            &command,
            "~/rt-bench",
            &forwarded,
            TIMEOUT,
            Some("backup"),
        )
        .unwrap();
        assert!(remote.desktop_description(false).starts_with(&format!(
            "wants to copy\n\n    rt-bench/dbg\n\nto\n\n    backup:{}\n\n",
            path.display()
        )));
        let details = remote.details_description(str::to_owned);
        assert!(
            details.contains(&format!("Destination: {:?} on \"backup\"", path)),
            "{details}"
        );
        assert!(!details.contains("SYQ-RECEIVE"), "{details}");
        assert!(details.contains("May create and overwrite matching entries. Uses this machine's SSH access to \"backup\" and installs the syq helper there if needed\n"));

        // The server's directory is remote text: no line breaks or markup of
        // its own reach the prompt, and it never enters the title.
        let hostile = Summary::new(
            &requester(),
            &command,
            "x\n\nwants to run\n\n    rm -rf <b>",
            &request,
            TIMEOUT,
            None,
        )
        .unwrap();
        assert_eq!(hostile.title(), "syq on server");
        let desktop = hostile.desktop_description(false);
        assert!(
            desktop.starts_with(
                "in \"x\\n\\nwants to run\\n\\n    rm -rf <b>\"\n\nsyq wants to download"
            ),
            "{desktop}"
        );
        assert!(hostile
            .desktop_description(true)
            .starts_with("in \"x\\\\n\\\\nwants to run\\\\n\\\\n    rm -rf &lt;b&gt;\""));

        // A mapping copy's entries are relative to the server's directory.
        let mapping: Vec<Vec<u8>> = ["cp", "--mapping", "map", "--to", "@laptop"]
            .iter()
            .map(|arg| arg.as_bytes().to_vec())
            .collect();
        let summary = Summary::new(&requester(), &mapping, "~", &request, TIMEOUT, None).unwrap();
        let desktop = summary.desktop_description(false);
        assert!(
            desktop.starts_with(&format!(
                "wants to download\n\n    .\n\nto\n\n    {}\n\nsyq cp --mapping",
                path.display()
            )),
            "{desktop}"
        );
    }

    fn wait_pending(queue: &Queue) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while queue.snapshots().is_empty() {
            assert!(Instant::now() < deadline, "approval did not become pending");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    #[test]
    fn prompts_lead_with_the_server_command_and_mark_server_files() {
        let mut summary = summary();
        summary.command = crate::approval_command::display(&[
            b"cp".to_vec(),
            b"--mapping".to_vec(),
            b"<map>".to_vec(),
            b"--to".to_vec(),
            b"@laptop".to_vec(),
        ]);
        let plain = summary.desktop_description(false);
        assert_eq!(
            plain,
            "wants to download\n\n    dbg\n\nto\n\n    ~/Downloads/server/dbg\n\nsyq cp --mapping \"<map>\" --to @laptop"
        );
        assert_eq!(summary.title(), "syq on server in ~/rt-bench");
        let markup = summary.desktop_description(true);
        assert_eq!(
            markup,
            "wants to download\n\n    dbg\n\nto\n\n    ~/Downloads/server/dbg\n\nsyq cp --mapping <i>\"&lt;map&gt;\"</i> --to @laptop"
        );
        assert!(!markup.contains("<map>"));
        let details = summary.details_description(|word| format!("[{word}]"));
        assert!(details.contains("Server command: syq cp --mapping [\"<map>\"] --to @laptop"));
        // The command enters the pending JSON for local clients.
        let json = serde_json::to_value(&summary).unwrap();
        assert_eq!(json["command"][0], "syq");
    }
    #[test]
    fn storage_prompts_name_the_operation_and_its_validity() {
        use crate::s3::authorization::{Removal, Request, Scope};
        let scope = |key: &str| Scope {
            key: key.into(),
            descendants: true,
        };
        let mut request = Request {
            bucket: "bucket".into(),
            endpoint: Some("https://storage.example".into()),
            region: None,
            profile: None,
            scopes: vec![scope("runs")],
            source: None,
            removal: None,
            acl: Default::default(),
            upload: true,
            delete: false,
            create_only: false,
            lifetime: crate::s3::authorization::DEFAULT_LIFETIME,
            headers: Default::default(),
        };
        let command = |parts: &[&str]| -> Vec<Vec<u8>> {
            parts.iter().map(|part| part.as_bytes().to_vec()).collect()
        };
        let upload = command(&["cp", "results", "--to", "s3://bucket", "--into", "runs"]);
        let (verb, sources, preposition, target, notes) = storage_request(&upload, &request);
        assert_eq!(verb, "wants to upload");
        assert_eq!(sources, ["results"]);
        assert_eq!((preposition, target.as_str()), ("to", "s3://bucket/runs"));
        assert_eq!(notes, ["endpoint https://storage.example"]);
        let named = command(&[
            "cp",
            "results",
            "--to",
            "s3://bucket",
            "--into",
            "runs",
            "--s3-endpoint=https://storage.example",
        ]);
        assert!(storage_request(&named, &request).4.is_empty());
        let pruning = command(&[
            "cp",
            "results",
            "--to",
            "s3://bucket",
            "--into",
            "runs",
            "--prune",
        ]);
        let (verb, _, _, _, notes) = storage_request(&pruning, &request);
        assert_eq!(verb, "wants to sync");
        assert_eq!(notes, ["endpoint https://storage.example"]);
        // A copy between buckets prunes too.
        let mut between = request.clone();
        between.source = Some(crate::s3::authorization::ReadAccess {
            bucket: "source".into(),
            scopes: vec![scope("tree")],
        });
        let mirror = command(&[
            "cp",
            "--srcs-in",
            "tree",
            "--from",
            "s3://source",
            "--to",
            "s3://bucket",
            "--into",
            "runs",
            "--prune",
        ]);
        let (verb, sources, _, target, _) = storage_request(&mirror, &between);
        assert_eq!(verb, "wants to sync");
        assert_eq!(sources, ["s3://source/tree"]);
        assert_eq!(target, "s3://bucket/runs");
        let plain = command(&[
            "cp",
            "--srcs-in",
            "tree",
            "--from",
            "s3://source",
            "--to",
            "s3://bucket",
            "--into",
            "runs",
        ]);
        assert_eq!(storage_request(&plain, &between).0, "wants to copy");
        request.endpoint = None;

        // A dry run clears the request's write flags; the command still says
        // which way the data goes.
        request.upload = false;
        let preview = command(&[
            "cp",
            "results",
            "--to",
            "s3://bucket",
            "--into",
            "runs",
            "--dry-run",
        ]);
        let (verb, sources, _, target, notes) = storage_request(&preview, &request);
        assert_eq!(verb, "wants to upload");
        assert_eq!(sources, ["results"]);
        assert_eq!(target, "s3://bucket/runs");
        assert_eq!(notes, ["preview only"]);

        let download = command(&["cp", "runs", "--from", "s3://bucket", "--into", "archive"]);
        let (verb, sources, _, target, notes) = storage_request(&download, &request);
        assert_eq!(verb, "wants to download");
        assert_eq!(sources, ["s3://bucket/runs"]);
        assert_eq!(target, "archive");
        assert!(notes.is_empty());

        request.delete = true;
        request.removal = Some(Removal::AllVersions);
        request.scopes = ["a", "b", "c", "d", "e"].map(scope).to_vec();
        request.lifetime = 60;
        let (verb, sources, _, target, notes) =
            storage_request(&command(&["rm", "--on", "s3://bucket"]), &request);
        assert_eq!(verb, "wants to delete");
        assert_eq!(
            sources,
            [
                "s3://bucket/a",
                "s3://bucket/b",
                "s3://bucket/c",
                "and 2 more"
            ]
        );
        assert!(target.is_empty());
        assert_eq!(notes, ["deleting versions is permanent"]);

        let mut summary = summary();
        summary.command = crate::approval_command::display(&upload);
        summary.verb = "wants to delete";
        summary.sources = vec!["s3://bucket/a".into(), "s3://bucket/b".into()];
        summary.target = String::new();
        summary.notes = vec!["deleting versions is permanent".into()];
        assert_eq!(
            summary.desktop_description(false),
            "wants to delete\n\n    s3://bucket/a\n\n    s3://bucket/b\n\ndeleting versions is permanent\n\nsyq cp results --to s3://bucket --into runs"
        );
    }
    #[test]
    fn copy_notes_say_only_what_differs_between_requests() {
        use crate::delegation::{ExistingDestinationPolicy, RootExistence};
        use std::os::unix::fs::symlink;
        let temp = crate::test_support::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let missing = root.join("missing");
        let none: [&str; 0] = [];
        assert_eq!(copy_notes(&copy_request(&missing), false), none);
        assert_eq!(
            copy_notes(&copy_request(&missing.join("child")), false),
            none
        );

        let file = root.join("file");
        std::fs::write(&file, b"keep").unwrap();
        let directory = root.join("directory");
        std::fs::create_dir(&directory).unwrap();
        let link = root.join("link");
        symlink(&missing, &link).unwrap();
        for path in [&file, &directory, &link] {
            assert_eq!(
                copy_notes(&copy_request(path), false),
                ["replaces existing files"]
            );
        }
        // A parent symlink is not followed, even when its target is missing;
        // unknown existence is said as such.
        assert_eq!(
            copy_notes(&copy_request(&link.join("child")), false),
            ["may replace existing files"]
        );
        assert_eq!(
            copy_notes(&copy_request(&file.join("child")), false),
            ["may replace existing files"]
        );
        assert_eq!(std::fs::read(&file).unwrap(), b"keep");
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 0);
        let mut many = copy_request(&missing);
        many.copy.mutation_scopes = vec![many.copy.mutation_scopes[0].clone(); 33];
        assert_eq!(copy_notes(&many, false), ["may replace existing files"]);
        // Another server is never inspected, so nothing is claimed about it.
        assert_eq!(copy_notes(&copy_request(&file), true), none);

        let mut request = copy_request(&file);
        request.copy.options.dry_run = true;
        assert_eq!(copy_notes(&request, false), ["preview only"]);
        request.copy.options.dry_run = false;
        request.copy.options.verify_only = true;
        assert_eq!(
            copy_notes(&request, false),
            ["compares only, writes nothing"]
        );
        request.copy.options.verify_only = false;
        request.copy.policy.existing = ExistingDestinationPolicy::Skip;
        assert_eq!(copy_notes(&request, false), ["keeps existing files"]);
        assert_eq!(copy_notes(&request, true), ["keeps existing files"]);
        request.copy.policy.existing = ExistingDestinationPolicy::MustExist;
        assert_eq!(copy_notes(&request, false), ["changes existing files only"]);
        request.copy.policy.existing = ExistingDestinationPolicy::Replace;
        request.constraints.root_existence = RootExistence::New;
        assert_eq!(copy_notes(&request, false), none);
        request.constraints.root_existence = RootExistence::Any;
        request.copy.limits.max_deletions = 3;
        assert_eq!(
            copy_notes(&request, false),
            [
                "replaces existing files",
                "deletes up to 3 files or folders"
            ]
        );
        assert_eq!(
            copy_notes(&request, true),
            ["deletes up to 3 files or folders"]
        );

        let summary = Summary::new(
            &requester(),
            &[b"cp".to_vec(), b"file".to_vec()],
            "~",
            &request,
            TIMEOUT,
            None,
        )
        .unwrap();
        assert!(summary.desktop_description(false).ends_with(&format!(
            "to\n\n    {}\n\nreplaces existing files\n\ndeletes up to 3 files or folders\n\nsyq cp file",
            file.display()
        )));
        // Pruning is a sync, whichever way it goes.
        let pruning: Vec<Vec<u8>> = ["cp", "file", "--to", "@laptop", "--as", "file", "--prune"]
            .iter()
            .map(|arg| arg.as_bytes().to_vec())
            .collect();
        let sync = Summary::new(&requester(), &pruning, "~", &request, TIMEOUT, None).unwrap();
        assert!(sync
            .desktop_description(false)
            .starts_with("wants to sync\n\n    file\n\n"));
        let sync = Summary::new(
            &requester(),
            &pruning,
            "~",
            &request,
            TIMEOUT,
            Some("backup"),
        )
        .unwrap();
        assert!(sync
            .desktop_description(false)
            .starts_with("wants to sync\n\n"));
    }
    #[test]
    fn long_directories_move_from_the_title_to_the_body() {
        let mut summary = summary();
        summary.command = crate::approval_command::display(&[b"cp".to_vec(), b"dbg".to_vec()]);
        assert_eq!(summary.title(), "syq on server in ~/rt-bench");
        let body = "wants to download\n\n    dbg\n\nto\n\n    ~/Downloads/server/dbg\n\nsyq cp dbg";
        assert_eq!(summary.desktop_description(false), body);
        summary.server_cwd = "~/projects/very-long-directory-name".into();
        assert_eq!(summary.title(), "syq on server");
        assert_eq!(
            summary.desktop_description(false),
            format!("in ~/projects/very-long-directory-name\n\nsyq {body}")
        );
        summary.server_cwd = String::new();
        assert_eq!(summary.title(), "syq on server");
        assert_eq!(summary.desktop_description(false), body);
        // Limits stay in the full description only.
        if let Details::Copy { max_delete, .. } = &mut summary.details {
            *max_delete = 2;
        }
        assert!(!summary.desktop_description(false).contains("deletions"));
        let details = summary.description(&crate::persistence::Domain::default(), str::to_owned);
        assert!(details.contains("100 bytes, 3 entries; at most 2 deletions"));
        assert!(details.contains("not been inspected"));
    }
    #[test]
    fn ssh_access_requires_its_own_explicit_approval_kind() {
        let queue = Arc::new(Queue::default());
        let waiter = queue.clone();
        let task = std::thread::spawn(move || {
            waiter.request_ssh(
                &requester(),
                &[b"ssh".to_vec(), b"hostB".to_vec()],
                "/tmp/project",
                &crate::cli::NativeEndpoint {
                    user: Some("alice".into()),
                    host: "hostB".into(),
                    port: Some(2222),
                },
                false,
                Notifications::Off,
                || false,
            )
        });
        wait_pending(&queue);
        let pending = queue.snapshots().pop().unwrap();
        assert_eq!(pending.kind(), Kind::Ssh);
        assert!(pending
            .desktop_description(false)
            .contains("account access"));
        assert!(pending
            .desktop_description(false)
            .contains("not permission for only"));
        let details = pending.description(&crate::persistence::Domain::default(), str::to_owned);
        assert!(details.contains("alice@hostB:2222"));
        assert!(details.contains("full authority"));
        assert!(details.contains("directly between the servers"));
        let json = serde_json::to_value(&pending).unwrap();
        assert_eq!(json["kind"], "ssh");
        assert!(json.get("max_bytes").is_none());
        for other in [Kind::Copy, Kind::Command, Kind::Storage] {
            assert!(queue.decide(&pending.id, true, other).is_err());
        }
        queue.decide(&pending.id, false, Kind::Ssh).unwrap();
        assert!(task.join().unwrap().is_err());
    }

    fn account_permission() -> AccountPermission {
        let identity = |host: &str| {
            AccountIdentity::new(
                crate::cli::NativeEndpoint {
                    user: Some("alice".into()),
                    host: host.into(),
                    port: Some(22),
                },
                vec![ssh_key::Fingerprint::Sha256([1; 32]).to_string()],
            )
            .unwrap()
        };
        AccountPermission::new("laptop".into(), identity("source"), identity("destination"))
            .unwrap()
    }

    #[test]
    fn account_approval_distinguishes_session_and_remembered_authority() {
        for remember in [false, true] {
            let queue = Arc::new(Queue::default());
            let waiter = queue.clone();
            let task = std::thread::spawn(move || {
                waiter.request_account(
                    &requester(),
                    &[b"ssh".to_vec(), b"destination".to_vec()],
                    "/tmp/project",
                    &account_permission(),
                    Notifications::Off,
                    || false,
                )
            });
            wait_pending(&queue);
            let pending = queue.snapshots().pop().unwrap();
            assert_eq!(pending.kind(), Kind::Ssh);
            assert_eq!(pending.account(), Some(&account_permission()));
            let desktop = pending.desktop_description(false);
            assert!(desktop.contains("alice@source:22"));
            assert!(desktop.contains("alice@destination:22"));
            assert!(desktop.contains("receiving connection to the source ends"));
            assert!(desktop.contains("Remember also permits future authentications"));
            let decoded: Summary =
                serde_json::from_value(serde_json::to_value(&pending).unwrap()).unwrap();
            let details =
                decoded.description(&crate::persistence::Domain::default(), str::to_owned);
            assert!(details.contains("commands and copies"));
            assert!(details.contains("Remember also permits future authentications"));
            assert!(details.contains("already authenticated sessions may continue"));
            assert!(details.contains("--remember"));
            let notification = notification_command(&pending, TIMEOUT);
            let args: Vec<_> = notification
                .get_args()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect();
            #[cfg(not(target_os = "macos"))]
            assert!(args.iter().any(|arg| arg == "--action=remember=Remember"));
            #[cfg(target_os = "macos")]
            assert_eq!(args.last().unwrap(), "account");
            let mut saved = false;
            queue
                .decide_using(&pending.id, true, Kind::Ssh, remember, |permission| {
                    assert_eq!(
                        permission,
                        AccountPermissionRef::Return(&account_permission())
                    );
                    saved = true;
                    Ok(())
                })
                .unwrap();
            assert_eq!(saved, remember);
            assert_eq!(
                task.join().unwrap().unwrap(),
                if remember {
                    AccountDecision::Remember
                } else {
                    AccountDecision::Session
                }
            );
            assert!(queue
                .decide_with_remember(&pending.id, true, Kind::Ssh, true)
                .is_err());
        }
    }

    fn provider_permission() -> ProviderLoginPermission {
        ProviderLoginPermission::new(
            "provider".into(),
            provider_accounts::ProviderIdentity::new(
                "alice".into(),
                ssh_key::Fingerprint::Sha256([7; 32]).to_string(),
            )
            .unwrap(),
            account_permission().destination,
        )
        .unwrap()
    }

    #[test]
    fn provider_approval_has_distinct_origin_and_session_or_remember_decisions() {
        let root = std::fs::canonicalize("/tmp").unwrap();
        let temporary = tempfile::tempdir_in(root).unwrap();
        for remember in [false, true] {
            let scope = temporary
                .path()
                .join(if remember { "remember" } else { "session" });
            crate::persistence::initialize_scope(&scope).unwrap();
            let domain = crate::persistence::Domain::select(Some(&scope)).unwrap();
            let queue = Arc::new(Queue::new(domain.clone()));
            let waiter = queue.clone();
            let task = std::thread::spawn(move || {
                waiter.request_provider_account(
                    &[b"ssh".to_vec(), b"destination".to_vec()],
                    "/claimed/source-directory",
                    &provider_permission(),
                    Notifications::Off,
                    || false,
                )
            });
            wait_pending(&queue);
            let pending = queue.snapshots().pop().unwrap();
            assert_eq!(pending.kind(), Kind::ProviderSsh);
            assert_eq!(pending.account(), None);
            assert_eq!(pending.provider_account(), Some(&provider_permission()));
            assert!(pending.can_remember());
            assert!(!pending.title().contains("claimed"));
            let desktop = pending.desktop_description(false);
            assert!(desktop.contains("SSH logins to this provider account"));
            assert!(desktop.contains("Requester's reported directory"));
            assert!(desktop.contains("provider-issued authorization session"));
            assert!(desktop.contains("not an SSH host key"));
            let json = serde_json::to_value(&pending).unwrap();
            assert_eq!(json["kind"], "provider_ssh");
            assert!(json.get("account").is_none());
            assert!(json["provider_account"].get("source").is_none());
            let decoded: Summary = serde_json::from_value(json).unwrap();
            let details =
                decoded.description(&crate::persistence::Domain::default(), str::to_owned);
            assert!(details.contains("commands and copies"));
            assert!(details.contains("future SSH logins to this provider account"));
            assert!(details.contains("already authenticated sessions may continue"));
            assert!(details.contains("--remember"));
            let notification = notification_command(&pending, TIMEOUT);
            let args: Vec<_> = notification
                .get_args()
                .map(|arg| arg.to_string_lossy())
                .collect();
            #[cfg(not(target_os = "macos"))]
            assert!(args.iter().any(|arg| arg == "--action=remember=Remember"));
            #[cfg(target_os = "macos")]
            assert_eq!(args.last().unwrap(), "account");
            for wrong_kind in [
                Kind::Ssh,
                Kind::Copy,
                Kind::Command,
                Kind::Source,
                Kind::Storage,
            ] {
                assert!(queue.decide(&pending.id, true, wrong_kind).is_err());
            }
            assert!(!queue
                .provider_account_remembered(&provider_permission())
                .unwrap());
            queue
                .decide_with_remember(&pending.id, true, Kind::ProviderSsh, remember)
                .unwrap();
            assert_eq!(
                task.join().unwrap().unwrap(),
                if remember {
                    AccountDecision::Remember
                } else {
                    AccountDecision::Session
                }
            );
            assert_eq!(
                queue
                    .provider_account_remembered(&provider_permission())
                    .unwrap(),
                remember
            );
            assert!(accounts::list(&domain).unwrap().is_empty());
            assert!(!domain
                .config_file("account-permissions-v1.json")
                .unwrap()
                .exists());
            if remember {
                provider_accounts::remove(&domain, &provider_permission().id()).unwrap();
                assert!(!queue
                    .provider_account_remembered(&provider_permission())
                    .unwrap());
            }
            assert!(queue.decide(&pending.id, true, Kind::ProviderSsh).is_err());
        }
    }

    #[test]
    fn provider_remember_failure_and_session_disconnect_never_approve() {
        let queue = Arc::new(Queue::default());
        let waiter = queue.clone();
        let stopped = Arc::new(AtomicBool::new(false));
        let cancelled = stopped.clone();
        let task = std::thread::spawn(move || {
            waiter.request_provider_account(
                &[],
                "",
                &provider_permission(),
                Notifications::Off,
                || cancelled.load(Ordering::Acquire),
            )
        });
        wait_pending(&queue);
        let pending = queue.snapshots().pop().unwrap();
        let error = queue
            .decide_using(&pending.id, true, Kind::ProviderSsh, true, |permission| {
                assert_eq!(
                    permission,
                    AccountPermissionRef::Provider(&provider_permission())
                );
                bail!("provider permissions are unreadable")
            })
            .unwrap_err();
        assert!(format!("{error:#}").contains("still awaiting approval"));
        assert_eq!(queue.snapshots().len(), 1);
        stopped.store(true, Ordering::Release);
        assert!(task.join().unwrap().is_err());
        assert!(queue.snapshots().is_empty());
        assert!(queue.decide(&pending.id, true, Kind::ProviderSsh).is_err());
    }

    #[test]
    fn failed_remember_does_not_answer_the_pending_account_request() {
        let queue = Arc::new(Queue::default());
        let waiter = queue.clone();
        let task = std::thread::spawn(move || {
            waiter.request_account(
                &requester(),
                &[],
                "~",
                &account_permission(),
                Notifications::Off,
                || false,
            )
        });
        wait_pending(&queue);
        let pending = queue.snapshots().pop().unwrap();
        let error = queue
            .decide_using(&pending.id, true, Kind::Ssh, true, |_| {
                bail!("unsupported saved permission version")
            })
            .unwrap_err();
        assert!(format!("{error:#}").contains("still awaiting approval"));
        assert_eq!(queue.snapshots().len(), 1);
        queue.decide(&pending.id, false, Kind::Ssh).unwrap();
        assert!(task.join().unwrap().is_err());
    }

    #[test]
    fn remember_is_unavailable_for_old_ssh_and_non_account_approvals() {
        // Unchanged PR #711 one-login SSH pending envelope. Its ordinary local
        // decision keeps the old one-use meaning and does not gain Remember.
        let old = r#"{"id":"fixture","from":"server","expires_at":123,"notification":"off","kind":"ssh","reusable":false,"destination":"alice@destination:22","permission":"May use this account's full authority for this SSH login."}"#;
        let legacy: Summary = serde_json::from_str(old).unwrap();
        assert_eq!(
            serde_json::to_value(&legacy).unwrap(),
            serde_json::from_str::<serde_json::Value>(old).unwrap()
        );
        for pending in [legacy, summary()] {
            let id = pending.id.clone();
            let kind = pending.kind();
            let command = notification_command(&pending, TIMEOUT);
            assert!(!command
                .get_args()
                .any(|arg| arg.to_string_lossy().contains("--action=remember")));
            let queue = Queue::default();
            queue.pending.lock().unwrap().insert(
                id.clone(),
                Pending {
                    summary: pending,
                    deadline: Instant::now() + TIMEOUT,
                    decision: None,
                },
            );
            assert!(queue
                .decide_using(&id, true, kind, true, |_| panic!(
                    "must not save non-account approval"
                ))
                .is_err());
            assert_eq!(queue.snapshots().len(), 1);
            queue.decide(&id, true, kind).unwrap();
            assert_eq!(
                queue.pending.lock().unwrap().get(&id).unwrap().decision,
                Some(Answer::Allow)
            );
        }
    }

    #[test]
    fn command_prompts_show_the_program_and_its_directory() {
        let mut summary = summary();
        summary.command = crate::approval_command::display(&[
            b"exec".to_vec(),
            b"--on".to_vec(),
            b"@laptop".to_vec(),
            b"--".to_vec(),
            b"make".to_vec(),
            b"-j8".to_vec(),
        ]);
        summary.verb = "wants to run";
        summary.sources = vec!["make -j8".into()];
        summary.preposition = "in";
        summary.target = "~/project".into();
        summary.details = Details::Command {
            kind: CommandKind::Command,
            argv: vec!["\"make\"".into(), "\"-j8\"".into()],
            cwd: "\"/home/me/project\"".into(),
            permission: String::new(),
        };
        assert_eq!(summary.title(), "syq on server in ~/rt-bench");
        assert_eq!(
            summary.desktop_description(false),
            "wants to run\n\n    make -j8\n\nin\n\n    ~/project\n\nsyq exec --on @laptop -- make -j8"
        );
        summary.server_cwd = "~/projects/very-long-directory-name".into();
        assert!(summary
            .desktop_description(false)
            .starts_with("in ~/projects/very-long-directory-name\n\nsyq wants to run\n\n"));
    }
    #[test]
    fn exited_prompt_closes_descendant_output_before_reaping() {
        let mut command = std::process::Command::new("sh");
        command.args(["-c", "sleep 30 & printf 'allow\\n'"]);
        let mut prompt = Notification::spawn_command(command).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(result) = prompt.poll() {
                assert_eq!(result.unwrap(), Some(Answer::Allow));
                break;
            }
            assert!(Instant::now() < deadline, "prompt did not exit");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(prompt.child.poll().unwrap().is_some());
    }
    #[test]
    fn decisions_are_local_one_use_and_expire() {
        for allow in [true, false] {
            let queue = Arc::new(Queue::default());
            let waiter = queue.clone();
            let task = std::thread::spawn(move || {
                waiter.wait(
                    summary(),
                    Notifications::Off,
                    Duration::from_secs(2),
                    || false,
                )
            });
            wait_pending(&queue);
            assert!(queue.decide("unknown", true, Kind::Copy).is_err());
            queue.decide("request", allow, Kind::Copy).unwrap();
            assert!(queue.decide("request", !allow, Kind::Copy).is_err());
            assert_eq!(task.join().unwrap().is_ok(), allow);
            assert!(queue.snapshots().is_empty());
        }
        let queue = Queue::default();
        assert!(queue
            .wait(
                summary(),
                Notifications::Off,
                Duration::from_millis(30),
                || false
            )
            .is_err());
        assert!(queue.decide("request", true, Kind::Copy).is_err());
        assert!(queue.snapshots().is_empty());
    }
    #[test]
    fn disconnect_cancels_unanswered_and_racing_decisions() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let queue = Arc::new(Queue::default());
        let waiter = queue.clone();
        let stopped = Arc::new(AtomicBool::new(false));
        let cancellation = stopped.clone();
        let task = std::thread::spawn(move || {
            waiter.wait(
                summary(),
                Notifications::Off,
                Duration::from_secs(2),
                || cancellation.load(Ordering::Acquire),
            )
        });
        wait_pending(&queue);
        stopped.store(true, Ordering::Release);
        let _ = queue.decide("request", true, Kind::Copy);
        assert!(task.join().unwrap().is_err());
        assert!(queue.snapshots().is_empty());
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_dialog_script_compiles_without_opening_a_prompt() {
        let temp = crate::test_support::tempdir().unwrap();
        use crate::process::CommandExt as _;
        let output = Command::new("/usr/bin/osacompile")
            .arg("-o")
            .arg(temp.path().join("approval.scpt"))
            .args(["-e", APPLESCRIPT])
            .capture_output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    #[test]
    fn remote_text_is_data_in_desktop_commands() {
        let text = "<a>&\"; do shell script \"touch /tmp/not-code\"";
        let mut summary = summary();
        summary.from = text.into();
        summary.server = text.into();
        summary.command = crate::approval_command::display(&[b"cp".to_vec()]);
        let command = notification_command(&summary, TIMEOUT);
        let args: Vec<_> = command
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        #[cfg(not(target_os = "macos"))]
        {
            assert_eq!(args[args.len() - 2], summary.title());
            assert!(args[args.len() - 2].contains(text));
            assert_eq!(*args.last().unwrap(), summary.desktop_description(true));
        }
        #[cfg(target_os = "macos")]
        {
            assert_eq!(args[0], "-e");
            assert_eq!(args[1], APPLESCRIPT);
            assert_eq!(args[3], summary.desktop_description(false));
            assert_eq!(args[5], summary.title());
            assert!(args[5].contains(text));
            assert!(!APPLESCRIPT.contains(text));
        }
    }
}

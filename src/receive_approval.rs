//! Local, one-use approval decisions. Remote requests cannot submit decisions;
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
    Storage,
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
pub(crate) enum StorageKind {
    Storage,
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
        let path = std::ffi::OsStr::from_bytes(&request.copy.destination);
        let (destination, permission) = match remote {
            None => (format!("{path:?}"), permission.to_owned()),
            // Automatic approval of writes to this machine does not authorize
            // use of its SSH credentials on another host; say what that use is.
            Some(target) => (
                format!("{path:?} on {target:?} using your SSH access"),
                format!("{permission}. Uses this machine's SSH access to {target:?} and installs the syq helper there if needed"),
            ),
        };
        // Sources stay as the command wrote them, relative to `cwd` on the
        // server; only the destination is resolved, by this machine.
        let sources = crate::approval_command::parse(command)
            .map(|args| {
                let count = args.locations.len().saturating_sub(1);
                args.locations
                    .iter()
                    .take(count)
                    .map(|location| crate::approval_command::display_arg(&location.path))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let target = match remote {
            None => crate::approval_command::abbreviate_home(
                &request.copy.destination,
                std::env::var_os("HOME").as_deref(),
            ),
            Some(target) => crate::approval_command::display_arg(
                &[target.as_bytes(), b":", request.destination.as_slice()].concat(),
            ),
        };
        Ok(Self {
            id: id.iter().map(|b| format!("{b:02x}")).collect(),
            from: format!("{:?}", from.to_string()),
            server: from.server.clone(),
            server_cwd: cwd.to_owned(),
            verb: if remote.is_some() {
                "wants to copy"
            } else {
                "wants to download"
            },
            sources,
            preposition: "to",
            target,
            notes: Vec::new(),
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
    /// otherwise the directory becomes the first line of the body.
    fn title_and_directory(&self) -> (String, Option<&str>) {
        let short = format!("syq on {}", self.server);
        if self.server_cwd.is_empty() {
            return (short, None);
        }
        let long = format!("{short} in {}", self.server_cwd);
        if long.chars().count() <= TITLE_CHARS {
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
            Details::Copy { .. } => Kind::Copy,
            Details::Command { .. } => Kind::Command,
            Details::Storage { .. } => Kind::Storage,
        }
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
                "\nServer command: {}",
                self.command_text(None, str::to_owned, server_input)
            )
        };
        let body = match &self.details {
            Details::Storage { description, .. } => description.clone(),
            Details::Copy { destination, permission, max_bytes, max_entries, max_delete, preserve_permissions } =>
                format!("Destination: {destination}\n{permission}\nLimits: {max_bytes} bytes, {max_entries} entries; at most {max_delete} deletions.\nPreserve permissions: {preserve_permissions}.\nSource contents have not been inspected by this machine."),
            Details::Command { argv, cwd, permission, .. } =>
                format!("Command (literal arguments): {}\nWorking directory: {cwd}\n{permission}\nScripts and build files used by this command have not been inspected by syq.", argv.join(" ")),
        };
        format!("From: {}{command}\n{body}", self.from)
    }
    /// `server_input` styles arguments naming files that the server reads.
    pub(crate) fn description(&self, server_input: impl Fn(&str) -> String) -> String {
        let question = match self.kind() {
            Kind::Copy => "Allow this copy once?",
            Kind::Command => "Run this command once?",
            Kind::Storage => "Authorize this storage access?",
        };
        format!(
            "{}\n\n{question}\nLocal command: syq persist receive approve {}",
            self.details_description(server_input),
            self.id
        )
    }
}
/// What a storage authorization lets the server do, in the prompt's shape:
/// the verb, what, where, and the facts the command does not show.
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
    // The command's local operands, as it wrote them, for the non-storage side.
    let local = crate::approval_command::parse(command)
        .map(|args| {
            args.locations
                .iter()
                .filter(|location| location.host.is_none())
                .map(|location| crate::approval_command::display_arg(&location.path))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let storage = locations(&request.bucket, &request.scopes);
    let (verb, sources, preposition, target) = if let Some(source) = &request.source {
        (
            "wants to copy",
            locations(&source.bucket, &source.scopes),
            "to",
            storage.join("\n    "),
        )
    } else if request.upload {
        ("wants to upload", local, "to", storage.join("\n    "))
    } else if request.delete {
        ("wants to delete", storage, "", String::new())
    } else {
        let destination = local.last().cloned().unwrap_or_default();
        ("wants to download", storage, "to", destination)
    };
    let mut notes = Vec::new();
    if request.delete
        && matches!(
            request.removal,
            Some(Removal::Version(_) | Removal::AllVersions)
        )
    {
        notes.push("deleting versions is permanent".to_owned());
    }
    let days = request.lifetime.div_ceil(24 * 60 * 60);
    notes.push(if days == 1 {
        "valid for 1 day".to_owned()
    } else {
        format!("valid for {days} days")
    });
    (verb, sources, preposition, target, notes)
}

struct Pending {
    summary: Summary,
    deadline: Instant,
    decision: Option<bool>,
}
#[derive(Default)]
pub(crate) struct Queue {
    pending: Mutex<BTreeMap<String, Pending>>,
}
impl Queue {
    pub(crate) fn snapshots(&self) -> Vec<Summary> {
        self.pending
            .lock()
            .unwrap()
            .values()
            .filter(|p| p.decision.is_none() && Instant::now() < p.deadline)
            .map(|p| p.summary.clone())
            .collect()
    }
    pub(crate) fn decide(&self, id: &str, allow: bool, kind: Kind) -> Result<()> {
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
        entry.decision = Some(allow);
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
            server_cwd: server_cwd.to_owned(),
            verb: "wants to run",
            sources: vec![argv
                .iter()
                .map(|arg| crate::approval_command::display_arg(arg))
                .collect::<Vec<_>>()
                .join(" ")],
            preposition: "in",
            target: crate::approval_command::abbreviate_home(
                cwd.as_os_str().as_bytes(),
                std::env::var_os("HOME").as_deref(),
            ),
            notes: Vec::new(),
            details: Details::Command {
                kind: CommandKind::Command,
                argv: argv.iter().map(|arg| format!("{:?}", std::ffi::OsStr::from_bytes(arg))).collect(),
                cwd: format!("{cwd:?}"),
                permission: "Runs as your local user with access to your files, programs and credentials. Copy root and copy limits do not contain this command. Stdin is closed.".into(),
            },
        }, notifications, TIMEOUT, cancelled)
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
                server_cwd: cwd.to_owned(),
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
            if let Some(allow) = self
                .pending
                .lock()
                .unwrap()
                .get(&id)
                .and_then(|p| p.decision)
            {
                if !allow {
                    bail!("request denied on the receiving machine");
                }
                // An answer that races disconnect/expiry cannot survive it.
                if cancelled() || Instant::now() >= deadline {
                    bail!("request approval expired or was cancelled");
                }
                return Ok(());
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
                        Ok(Some(allow)) => {
                            let _ = self.decide(&id, allow, summary.kind());
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
        set answer to display dialog (item 1 of argv) with title (item 3 of argv) buttons {"Allow once", "Deny"} default button "Deny" cancel button "Deny" giving up after remainingSeconds
        if gave up of answer then return "expired"
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
        ]);
        cmd
    }
    #[cfg(not(target_os = "macos"))]
    {
        let mut cmd = Command::new("/usr/bin/notify-send");
        cmd.args([
            "--app-name=syq",
            "--wait",
            "--action=allow=Allow once",
            "--action=deny=Deny",
        ])
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
    fn poll(&mut self) -> Option<Result<Option<bool>>> {
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
                b"allow\n" => Ok(Some(true)),
                b"deny\n" => Ok(Some(false)),
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

        // Another host is never inspected; the destination keeps its host.
        let remote = Summary::new(
            &requester(),
            &command,
            "~/rt-bench",
            &request,
            TIMEOUT,
            Some("backup"),
        )
        .unwrap();
        assert!(remote.desktop_description(false).starts_with(&format!(
            "wants to copy\n\n    rt-bench/dbg\n\nto\n\n    backup:{}\n\n",
            path.display()
        )));
        assert!(remote
            .details_description(str::to_owned)
            .contains("May create and overwrite matching entries. Uses this machine's SSH access to \"backup\" and installs the syq helper there if needed\n"));

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
        assert_eq!(notes, ["valid for 7 days"]);

        request.upload = false;
        let download = command(&["cp", "runs", "--from", "s3://bucket", "--into", "archive"]);
        let (verb, sources, _, target, _) = storage_request(&download, &request);
        assert_eq!(verb, "wants to download");
        assert_eq!(sources, ["s3://bucket/runs"]);
        assert_eq!(target, "archive");

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
        assert_eq!(notes, ["deleting versions is permanent", "valid for 1 day"]);

        let mut summary = summary();
        summary.command = crate::approval_command::display(&upload);
        summary.verb = "wants to delete";
        summary.sources = vec!["s3://bucket/a".into(), "s3://bucket/b".into()];
        summary.target = String::new();
        summary.notes = vec!["valid for 1 day".into()];
        assert_eq!(
            summary.desktop_description(false),
            "wants to delete\n\n    s3://bucket/a\n\n    s3://bucket/b\n\nvalid for 1 day\n\nsyq cp results --to s3://bucket --into runs"
        );
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
        let details = summary.description(str::to_owned);
        assert!(details.contains("100 bytes, 3 entries; at most 2 deletions"));
        assert!(details.contains("not been inspected"));
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
                assert_eq!(result.unwrap(), Some(true));
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

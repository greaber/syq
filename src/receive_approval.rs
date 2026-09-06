//! Local, one-use approval decisions. Remote requests cannot submit decisions;
//! only the receiving user's private control socket and owned desktop UI can.
use anyhow::{bail, Context, Result};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub(crate) const TIMEOUT: Duration = Duration::from_secs(300);

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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Summary {
    pub id: String,
    pub from: String,
    pub destination: String,
    pub permission: String,
    pub max_bytes: u64,
    pub max_entries: u64,
    pub max_delete: u64,
    pub preserve_permissions: bool,
    pub expires_at: u64,
    pub notification: String,
}
impl Summary {
    fn new(
        from: &str,
        request: &crate::destination::CopyRequest,
        lifetime: Duration,
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
        Ok(Self {
            id: id.iter().map(|b| format!("{b:02x}")).collect(),
            // Debug formatting preserves unusual bytes and escapes terminal
            // control characters. Do not interpret remote text as UI markup.
            from: format!("{from:?}"),
            destination: format!(
                "{:?}",
                std::ffi::OsStr::from_bytes(&request.copy.destination)
            ),
            permission: permission.into(),
            max_bytes: request.copy.limits.max_total_bytes,
            max_entries: request.copy.limits.max_entries,
            max_delete: request.copy.limits.max_deletions,
            preserve_permissions: request.copy.options.preserve_permissions,
            expires_at: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()
                + lifetime.as_secs(),
            notification: "starting".into(),
        })
    }
    pub(crate) fn description(&self) -> String {
        format!("From: {}\nDestination: {}\n{}\nLimits: {} bytes, {} entries; at most {} deletions.\nPreserve permissions: {}.\nSource contents have not been inspected by this laptop.\n\nAllow this copy once?\nLocal command: syq recv approve {}", self.from, self.destination, self.permission,
            self.max_bytes, self.max_entries, self.max_delete, self.preserve_permissions, self.id)
    }
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
    pub(crate) fn decide(&self, id: &str, allow: bool) -> Result<()> {
        let mut pending = self.pending.lock().unwrap();
        let entry = pending
            .get_mut(id)
            .context("approval is unknown, expired, or already answered")?;
        if entry.decision.is_some() || Instant::now() >= entry.deadline {
            bail!("approval is expired or already answered");
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
        from: &str,
        request: &crate::destination::CopyRequest,
        notifications: Notifications,
        cancelled: impl Fn() -> bool,
    ) -> Result<()> {
        self.wait(
            Summary::new(from, request, TIMEOUT)?,
            notifications,
            TIMEOUT,
            cancelled,
        )
    }
    pub(crate) fn request_remote(
        &self,
        from: &str,
        target: &str,
        request: &crate::destination::CopyRequest,
        notifications: Notifications,
        cancelled: impl Fn() -> bool,
    ) -> Result<()> {
        let mut summary = Summary::new(from, request, TIMEOUT)?;
        summary.destination = format!(
            "SSH {target:?}, path {:?} (relative paths start in the destination login home)",
            std::ffi::OsStr::from_bytes(&request.destination)
        );
        summary.permission.push_str(". Connect using this machine's SSH access and install the matching syq helper if needed");
        self.wait(summary, notifications, TIMEOUT, cancelled)
    }
    fn wait(
        &self,
        summary: Summary,
        notifications: Notifications,
        lifetime: Duration,
        cancelled: impl Fn() -> bool,
    ) -> Result<()> {
        if cancelled() {
            bail!("copy disconnected before approval");
        }
        let id = summary.id.clone();
        let deadline = Instant::now() + lifetime;
        {
            let mut pending = self.pending.lock().unwrap();
            if pending.len() >= 8 {
                bail!("too many copies awaiting approval");
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
            match Notification::spawn(&summary.description(), lifetime) {
                Ok(notification) => {
                    self.notification_status(&id, "desktop prompt requested; use local recv approve/deny if it is not visible".into());
                    Some(notification)
                }
                Err(error) => {
                    self.notification_status(
                        &id,
                        format!("unavailable: {error:#}; use local recv approve/deny"),
                    );
                    None
                }
            }
        } else {
            self.notification_status(&id, "disabled; use local recv approve/deny".into());
            None
        };
        loop {
            if cancelled() {
                bail!("copy disconnected or receiving stopped while awaiting approval");
            }
            if Instant::now() >= deadline {
                bail!("copy approval expired after {} seconds", lifetime.as_secs());
            }
            if let Some(allow) = self
                .pending
                .lock()
                .unwrap()
                .get(&id)
                .and_then(|p| p.decision)
            {
                if !allow {
                    bail!("copy denied on the receiving machine");
                }
                // An answer that races disconnect/expiry cannot survive it.
                if cancelled() || Instant::now() >= deadline {
                    bail!("copy approval expired or was cancelled");
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
                        "desktop reported an error; use local recv approve/deny".into(),
                    );
                }
                if let Some(result) = process.poll() {
                    notification.take();
                    match result {
                        Ok(Some(allow)) => {
                            let _ = self.decide(&id, allow);
                        }
                        Ok(None) => self.notification_status(
                            &id,
                            "dismissed; use local recv approve/deny".into(),
                        ),
                        Err(error) => self.notification_status(
                            &id,
                            format!("unavailable: {error:#}; use local recv approve/deny"),
                        ),
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }
}

#[cfg(not(target_os = "macos"))]
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
        set answer to display dialog (item 1 of argv) with title "syq: incoming copy" buttons {"Deny", "Allow once"} default button "Deny" cancel button "Deny" giving up after (item 2 of argv as integer)
        if gave up of answer then return "expired"
        if button returned of answer is "Allow once" then return "allow"
        return "deny"
    on error number -128
        return "deny"
    end try
end run"#;
fn notification_command(description: &str, lifetime: Duration) -> Command {
    #[cfg(target_os = "macos")]
    {
        let mut cmd = Command::new("/usr/bin/osascript");
        cmd.args([
            "-e",
            APPLESCRIPT,
            "--",
            description,
            &lifetime.as_secs().max(1).to_string(),
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
        .arg("syq: incoming copy")
        .arg(escape_markup(description));
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
    child: Child,
    closed: bool,
    error_seen: Arc<AtomicBool>,
    output: Option<std::thread::JoinHandle<Vec<u8>>>,
    errors: Option<std::thread::JoinHandle<Vec<u8>>>,
}
impl Notification {
    fn spawn(description: &str, lifetime: Duration) -> Result<Self> {
        let mut command = notification_command(description, lifetime);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        let mut child = command.spawn().context("start desktop approval prompt")?;
        let error_seen = Arc::new(AtomicBool::new(false));
        let output = Some(capture(child.stdout.take().unwrap(), None));
        let errors = Some(capture(
            child.stderr.take().unwrap(),
            Some(error_seen.clone()),
        ));
        Ok(Self {
            child,
            closed: false,
            error_seen,
            output,
            errors,
        })
    }
    fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        unsafe {
            libc::kill(-(self.child.id() as i32), libc::SIGKILL);
        }
        let _ = self.child.wait();
    }
    fn poll(&mut self) -> Option<Result<Option<bool>>> {
        let status = match self.child.try_wait() {
            Ok(Some(status)) => status,
            Ok(None) => return None,
            Err(e) => return Some(Err(e.into())),
        };
        self.close();
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
        self.close();
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
            from: "server".into(),
            destination: "/tmp/receiving".into(),
            permission: "May create and overwrite".into(),
            max_bytes: 100,
            max_entries: 3,
            max_delete: 0,
            preserve_permissions: false,
            expires_at: 0,
            notification: String::new(),
        }
    }
    fn wait_pending(queue: &Queue) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while queue.snapshots().is_empty() {
            assert!(Instant::now() < deadline, "approval did not become pending");
            std::thread::sleep(Duration::from_millis(5));
        }
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
            assert!(queue.decide("unknown", true).is_err());
            queue.decide("request", allow).unwrap();
            assert!(queue.decide("request", !allow).is_err());
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
        assert!(queue.decide("request", true).is_err());
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
        let _ = queue.decide("request", true);
        assert!(task.join().unwrap().is_err());
        assert!(queue.snapshots().is_empty());
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_dialog_script_compiles_without_opening_a_prompt() {
        let temp = tempfile::tempdir().unwrap();
        let output = Command::new("/usr/bin/osacompile")
            .arg("-o")
            .arg(temp.path().join("approval.scpt"))
            .args(["-e", APPLESCRIPT])
            .output()
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
        let command = notification_command(text, TIMEOUT);
        let args: Vec<_> = command
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        #[cfg(not(target_os = "macos"))]
        assert_eq!(args.last().unwrap(), &escape_markup(text));
        #[cfg(target_os = "macos")]
        {
            assert!(args.iter().any(|arg| arg == text));
            assert!(!APPLESCRIPT.contains(text));
        }
    }
}

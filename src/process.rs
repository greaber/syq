//! Coordinate process creation, not process lifetime.
use std::process::{Child, Command, ExitStatus, Output, Stdio};

pub(crate) trait CommandExt {
    fn spawn_guarded(&mut self) -> std::io::Result<Child>;
    fn status_guarded(&mut self) -> std::io::Result<ExitStatus>;
    /// Capture both outputs with null stdin. For custom stdio, configure it
    /// explicitly and use spawn_guarded followed by wait_with_output instead.
    fn capture_output(&mut self) -> std::io::Result<Output>;
}

impl CommandExt for Command {
    fn spawn_guarded(&mut self) -> std::io::Result<Child> {
        // Darwin's pipe creation and FD_CLOEXEC setup are separate operations.
        // Every launch must participate, even one that does not create pipes:
        // otherwise it can inherit another launch's not-yet-protected pipe.
        #[cfg(target_os = "macos")]
        let _guard = {
            static SPAWN: std::sync::Mutex<()> = std::sync::Mutex::new(());
            SPAWN.lock().unwrap_or_else(|error| error.into_inner())
        };
        self.spawn()
    }

    fn status_guarded(&mut self) -> std::io::Result<ExitStatus> {
        self.spawn_guarded()?.wait()
    }

    fn capture_output(&mut self) -> std::io::Result<Output> {
        self.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn_guarded()?
            .wait_with_output()
    }
}

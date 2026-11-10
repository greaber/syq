//! Start child processes under the descriptor-inheritance guard.
//!
//! The integration test targets include this file as their own `process`
//! module, and `local` includes `process_group.rs` beside it. Neither file
//! holds tests, so the process modules' tests compile into the `syq`
//! binary's unit tests alone, rather than once more for each target.
use std::process::{Child, Command, ExitStatus, Output, Stdio};

/// Serialize non-atomic close-on-exec setup with child launches on Darwin.
/// The operation must only create/protect descriptors or launch a process;
/// do not hold this guard while waiting for peer I/O or child completion.
pub(crate) fn with_inheritance_guard<T>(operation: impl FnOnce() -> T) -> T {
    #[cfg(target_os = "macos")]
    let _guard = {
        static SPAWN: std::sync::Mutex<()> = std::sync::Mutex::new(());
        SPAWN.lock().unwrap_or_else(|error| error.into_inner())
    };
    operation()
}

pub(crate) trait CommandExt {
    fn spawn_guarded(&mut self) -> std::io::Result<Child>;
    fn status_guarded(&mut self) -> std::io::Result<ExitStatus>;
    /// Capture both outputs with null stdin. For custom stdio, configure it
    /// explicitly and use spawn_guarded followed by wait_with_output instead.
    fn capture_output(&mut self) -> std::io::Result<Output>;
}

impl CommandExt for Command {
    fn spawn_guarded(&mut self) -> std::io::Result<Child> {
        with_inheritance_guard(|| self.spawn())
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

//! Executable fixtures that the test process never opens for writing.
//!
//! Tests run in parallel threads of one process. A child that another test
//! forks inherits every open descriptor until it execs, so if this process
//! writes a script itself, a child forked during the write keeps a writable
//! descriptor for it after the write finishes. Until that child execs,
//! running the script fails with ETXTBSY ("Text file busy"). A short-lived
//! child process writes the file instead, so the test process never holds a
//! writable descriptor that a fork could inherit. Use these helpers for every
//! file a test, or product code under test, will execute.

use crate::process::CommandExt as _;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

/// Create or overwrite the executable `path` with `contents` and `mode`,
/// creating its parent directories.
// Not every target writes executable fixtures.
#[allow(dead_code)]
pub(crate) fn write_executable(path: &Path, contents: impl AsRef<[u8]>, mode: u32) {
    let mut tee = Command::new("tee");
    tee.arg(path);
    create(path, mode, &mut tee, Some(contents.as_ref()));
}

/// Copy `source` to the executable `path` with `mode`, creating its parent
/// directories.
// Not every target copies executables.
#[allow(dead_code)]
pub(crate) fn copy_executable(source: &Path, path: &Path, mode: u32) {
    let mut cp = Command::new("cp");
    cp.arg(source).arg(path);
    create(path, mode, &mut cp, None);
}

fn create(path: &Path, mode: u32, writer: &mut Command, input: Option<&[u8]>) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .unwrap_or_else(|error| panic!("create {}: {error}", parent.display()));
    }
    let mut child = writer
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn_guarded()
        .unwrap_or_else(|error| panic!("start writing {}: {error}", path.display()));
    let written = match input {
        Some(input) => child.stdin.take().unwrap().write_all(input),
        None => Ok(()),
    };
    let output = child
        .wait_with_output()
        .unwrap_or_else(|error| panic!("write {}: {error}", path.display()));
    assert!(
        written.is_ok() && output.status.success(),
        "write {}: {written:?}, {}: {}",
        path.display(),
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    // chmod by path does not open the file.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .unwrap_or_else(|error| panic!("chmod {}: {error}", path.display()));
}

//! Shared helpers for unit tests.

use std::path::PathBuf;

/// Run a unit test in a separate process whose stderr reader has gone away.
/// Keep stdout available for the test harness and assertion diagnostics.
pub(crate) fn with_broken_stderr(name: &str) -> bool {
    if std::env::var("SYQ_TEST_BROKEN_STDERR").as_deref() == Ok(name) {
        return true;
    }
    let (reader, writer) = std::os::unix::net::UnixStream::pair().unwrap();
    drop(reader);
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture"])
        .env("SYQ_TEST_BROKEN_STDERR", name)
        .stderr(std::process::Stdio::from(std::os::fd::OwnedFd::from(
            writer,
        )))
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
    false
}

/// The process temporary directory with symlinks resolved.
///
/// macOS places `TMPDIR` under `/var`, a symlink to `/private/var`. Native
/// operator paths refuse symlink components by default, so tests that hand a
/// temporary path to the product must start from its resolved form.
pub(crate) fn temp_dir() -> PathBuf {
    let path = std::env::temp_dir();
    std::fs::canonicalize(&path).unwrap_or(path)
}

/// A fresh temporary directory beneath the resolved [`temp_dir`].
pub(crate) fn tempdir() -> std::io::Result<tempfile::TempDir> {
    tempfile::tempdir_in(temp_dir())
}

/// Whether the temporary filesystem accepts file names that are not valid
/// UTF-8. APFS on macOS rejects them with `EILSEQ`, so tests that exercise raw
/// byte names have nothing to test there.
pub(crate) fn filesystem_accepts_non_utf8_names() -> bool {
    use std::os::unix::ffi::OsStringExt;
    let name =
        std::ffi::OsString::from_vec(format!("syq-probe-{}-", std::process::id()).into_bytes());
    let mut name = name;
    name.push(std::ffi::OsString::from_vec(vec![0xff]));
    let path = temp_dir().join(name);
    match std::fs::File::create(&path) {
        Ok(_) => {
            let _ = std::fs::remove_file(&path);
            true
        }
        Err(_) => false,
    }
}

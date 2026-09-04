//! Shared helpers for unit tests.

use std::path::PathBuf;

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

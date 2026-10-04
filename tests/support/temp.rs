//! Temporary fixture roots shared by unit and integration tests.
//!
//! Resolve temporary roots before creating fixtures.
//! Symlinks created inside a fixture keep their meaning for product tests.

use std::path::PathBuf;

pub(crate) fn temp_dir() -> PathBuf {
    let path = std::env::temp_dir();
    std::fs::canonicalize(&path).unwrap_or_else(|error| {
        panic!("resolve temporary fixture root {}: {error}", path.display())
    })
}

// Some integration targets only need temp_dir() for their named fixtures.
#[allow(dead_code)]
pub(crate) fn tempdir() -> std::io::Result<tempfile::TempDir> {
    tempfile::tempdir_in(temp_dir())
}

/// A canonical short root for fixtures whose Unix socket paths or persistence
/// scopes must fit the platform's path limit, even with a long ambient TMPDIR.
/// Keep ordinary filesystem fixtures on tempdir() so they use the ambient root.
#[allow(dead_code)]
pub(crate) fn short_tempdir() -> std::io::Result<tempfile::TempDir> {
    tempfile::tempdir_in(std::fs::canonicalize("/tmp")?)
}

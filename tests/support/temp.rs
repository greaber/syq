//! Temporary fixture roots shared by unit and integration tests.
//!
//! Resolve only the ambient temporary directory, before creating fixtures.
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

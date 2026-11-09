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

/// A symlink to a target, made directly in a sticky directory anyone can
/// write to that another account owns, such as /tmp, where Linux's
/// protected-symlinks rule applies. Removed when dropped.
#[allow(dead_code)]
pub(crate) struct SharedDirectoryLink(pub(crate) PathBuf);

#[allow(dead_code)]
impl SharedDirectoryLink {
    /// `None` when there is no such directory, as when this process runs as
    /// root, which owns /tmp.
    pub(crate) fn new(target: &std::path::Path) -> Option<Self> {
        use std::os::unix::fs::MetadataExt as _;
        let own = unsafe { libc::geteuid() };
        let directory = ["/tmp", "/var/tmp"]
            .into_iter()
            .filter_map(|path| std::fs::canonicalize(path).ok())
            .find(|path| {
                std::fs::metadata(path).is_ok_and(|metadata| {
                    metadata.is_dir() && metadata.mode() & 0o1002 == 0o1002 && metadata.uid() != own
                })
            })?;
        for attempt in 0.. {
            let unique = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let link = directory.join(format!(
                "syq-test-link-{}-{unique}-{attempt}",
                std::process::id()
            ));
            match std::os::unix::fs::symlink(target, &link) {
                Ok(()) => return Some(Self(link)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("make a symlink in {}: {error}", directory.display()),
            }
        }
        unreachable!()
    }
}

impl Drop for SharedDirectoryLink {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

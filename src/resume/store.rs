//! Private job directories. Existing S3 checkpoints and adjacent partial files
//! keep their existing formats and namespaces.
use super::journal::Journal;
use crate::rooted::{RelativePath, Root};
use anyhow::{bail, Context, Result};
use serde::{de::DeserializeOwned, Serialize};
use std::fs::{File, OpenOptions};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub(super) struct Store {
    root: Root,
    name: RelativePath,
    pub journal: Journal,
}

pub(super) fn cache_directory() -> Result<PathBuf> {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
        .filter(|path| path.is_absolute())
        .context("job recording needs an absolute HOME or XDG_CACHE_HOME")?;
    Ok(base.join("syq/jobs"))
}

pub(super) fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn private_directory(path: &Path, create: bool) -> Result<File> {
    if create {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)?;
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("open job directory {}", path.display()))?;
    let metadata = file.metadata()?;
    if metadata.uid() != unsafe { libc::geteuid() } {
        bail!("job directory is not owned by this user");
    }
    if metadata.mode() & 0o077 != 0 {
        bail!("job directory is not private (expected mode 0700)");
    }
    Ok(file)
}

impl Store {
    /// Each role has a separate journal: the invoking machine owns the saved
    /// command; endpoints own the mutation records they can authenticate.
    pub fn open<T: DeserializeOwned>(
        base: &Path,
        id: &str,
        role: &str,
        create: bool,
        visit: impl FnMut(T) -> Result<()>,
    ) -> Result<Self> {
        if !valid_id(id) {
            bail!("invalid job ID {id:?}");
        }
        if !matches!(role, "command" | "copy" | "remove") {
            bail!("invalid job journal role");
        }
        let root = Root::from_directory(private_directory(base, create)?)?;
        let name = RelativePath::new(format!("{id}.{role}").as_bytes())?;
        let file = if create {
            root.create_file(&name, 0o600)?
        } else {
            root.open_regular_read_write(&name)
                .with_context(|| format!("job {id} is unavailable on this machine"))?
        };
        let journal = Journal::open(file, visit)?;
        Ok(Self {
            root,
            name,
            journal,
        })
    }

    pub fn append<T: Serialize>(&mut self, records: &[T]) -> Result<()> {
        self.journal.append(records)
    }

    pub fn remove(&self) -> Result<()> {
        self.root.unlink(&self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const ID: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn reopens_records_and_does_not_follow_symlinks() {
        let temp = crate::test_support::tempdir().unwrap();
        let base = temp.path().join("jobs");
        let mut store = Store::open::<String>(&base, ID, "command", true, |_| Ok(())).unwrap();
        store.append(&["saved command"]).unwrap();
        drop(store);
        let mut records = Vec::<String>::new();
        let store = Store::open(&base, ID, "command", false, |record| {
            records.push(record);
            Ok(())
        })
        .unwrap();
        assert_eq!(records, ["saved command"]);
        store.remove().unwrap();
        drop(store);
        let outside = temp.path().join("outside");
        std::fs::write(&outside, b"untouched").unwrap();
        std::os::unix::fs::symlink(&outside, base.join(format!("{ID}.command"))).unwrap();
        assert!(Store::open::<String>(&base, ID, "command", false, |_| Ok(())).is_err());
        assert_eq!(std::fs::read(outside).unwrap(), b"untouched");
    }

    #[test]
    fn explicit_resume_does_not_create_missing_directories() {
        let temp = crate::test_support::tempdir().unwrap();
        let base = temp.path().join("missing");
        assert!(Store::open::<String>(&base, ID, "command", false, |_| Ok(())).is_err());
        assert!(!base.exists());
        assert!(!valid_id("../other"));
    }
}

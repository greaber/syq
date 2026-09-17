//! Private recovery records. Their identity includes the endpoint and request
//! policy; values of custom headers and credentials are never written here.
use crate::rooted::{RelativePath, Root};
use anyhow::{bail, Context, Result};
use serde::{de::DeserializeOwned, Serialize};
use std::{
    fs::File,
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, PermissionsExt},
    },
    sync::Arc,
};

pub(super) struct State {
    directory: std::path::PathBuf,
    root: Arc<Root>,
    name: String,
    _lock: File,
}
impl State {
    pub fn open(identity: &[u8]) -> Result<Self> {
        let base = std::env::var_os("XDG_CACHE_HOME")
            .map(std::path::PathBuf::from)
            .filter(|p| p.is_absolute())
            .or_else(|| {
                std::env::var_os("HOME").map(|p| std::path::PathBuf::from(p).join(".cache"))
            })
            .context("S3 recovery requires HOME or absolute XDG_CACHE_HOME")?;
        let path = base.join("syq/s3");
        std::fs::create_dir_all(&path).context("create S3 recovery directory")?;
        let m = std::fs::symlink_metadata(&path)?;
        if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } {
            bail!("S3 recovery directory must be owned by this user and not be a symlink");
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
        let root = Arc::new(Root::open(&path)?);
        let name = blake3::hash(identity).to_hex().to_string();
        let lock_path = RelativePath::new(format!("{name}.lock").as_bytes())?;
        let lock = match root.create_file(&lock_path, 0o600) {
            Ok(f) => f,
            Err(e) if is_exists(&e) => root.open_regular_read_write(&lock_path)?,
            Err(e) => return Err(e),
        };
        let m = lock.metadata()?;
        if m.nlink() != 1 || m.uid() != unsafe { libc::geteuid() } {
            bail!("unsafe S3 recovery lock");
        }
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            bail!("another S3 copy is using this recovery record; retry after it finishes");
        }
        let state = Self {
            directory: path,
            root,
            name,
            _lock: lock,
        };
        // Only the lock holder writes this file, so one found now was left by
        // an interrupted save.
        let temporary = state.temporary()?;
        if state.root.metadata_optional(&temporary)?.is_some() {
            state.root.unlink(&temporary)?;
        }
        Ok(state)
    }
    fn temporary(&self) -> Result<RelativePath> {
        RelativePath::new(format!("{}.tmp", self.name).as_bytes())
    }
    fn path(&self) -> Result<RelativePath> {
        RelativePath::new(format!("{}.json", self.name).as_bytes())
    }
    pub fn load<T: DeserializeOwned>(&self) -> Result<Option<T>> {
        let path = self.path()?;
        if self.root.metadata_optional(&path)?.is_none() {
            return Ok(None);
        }
        let file = self.root.open_regular_read(&path)?;
        let m = file.metadata()?;
        if m.nlink() != 1 || m.uid() != unsafe { libc::geteuid() } || m.len() > 16 * 1024 * 1024 {
            bail!("unsafe S3 recovery record");
        }
        let mut text = Vec::new();
        file.take(16 * 1024 * 1024 + 1).read_to_end(&mut text)?;
        Ok(Some(serde_json::from_slice(&text).with_context(|| {
            format!(
                "invalid S3 recovery record {}; preserve it for recovery or remove it to restart",
                self.directory.join(format!("{}.json", self.name)).display()
            )
        })?))
    }
    pub fn save<T: Serialize>(&self, value: &T) -> Result<()> {
        let tmp = self.temporary()?;
        let mut file = self.root.create_file(&tmp, 0o600)?;
        // One write: serializing straight to the file costs a syscall per token.
        file.write_all(&serde_json::to_vec(value)?)?;
        // Recovery handles interrupted processes, not machine-crash durability.
        self.root.rename_regular_if_same(
            &tmp,
            &self.path()?,
            (file.metadata()?.dev(), file.metadata()?.ino()),
        )?;
        Ok(())
    }
    pub fn clear(&self) -> Result<()> {
        let p = self.path()?;
        if self.root.metadata_optional(&p)?.is_some() {
            self.root.unlink(&p)?;
        }
        Ok(())
    }
}
fn is_exists(error: &anyhow::Error) -> bool {
    error.chain().any(|e| {
        e.downcast_ref::<std::io::Error>()
            .is_some_and(|e| e.kind() == std::io::ErrorKind::AlreadyExists)
    })
}

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
    sync::{
        atomic::{AtomicBool, Ordering::Relaxed},
        Arc,
    },
};

// Keep the lock even after a checkpoint fails: another process must not reuse
// an older checkpoint while this transfer is still writing the same partial.
pub(super) struct State {
    persistent: Option<PersistentState>,
    writable: AtomicBool,
    recorded: AtomicBool,
}
impl State {
    pub fn without_cache() -> Self {
        Self::new(None)
    }
    pub fn open(identity: &[u8]) -> Result<Self> {
        let base = std::env::var_os("XDG_CACHE_HOME")
            .map(std::path::PathBuf::from)
            .filter(|p| p.is_absolute())
            .or_else(|| {
                std::env::var_os("HOME").map(|p| std::path::PathBuf::from(p).join(".cache"))
            });
        match base {
            Some(base) => Self::open_at(base.join("syq/s3"), identity),
            None => {
                warn("HOME and absolute XDG_CACHE_HOME are unset");
                Ok(Self::new(None))
            }
        }
    }
    fn open_at(path: std::path::PathBuf, identity: &[u8]) -> Result<Self> {
        match PersistentState::open(path, identity) {
            Ok(state) => Ok(Self::new(Some(state))),
            Err(error) if cache_io_error(&error) => {
                warn(&format!("{error:#}"));
                Ok(Self::new(None))
            }
            Err(error) => Err(error),
        }
    }
    fn new(persistent: Option<PersistentState>) -> Self {
        Self {
            writable: AtomicBool::new(persistent.is_some()),
            persistent,
            recorded: AtomicBool::new(false),
        }
    }
    // Only filesystem failures make the cache optional. Invalid records,
    // unsafe identities and a busy recovery lock still stop the transfer.
    fn optional_io<T>(&self, result: Result<T>) -> Result<Option<T>> {
        match result {
            Ok(value) => Ok(Some(value)),
            Err(error) if cache_io_error(&error) => {
                if self.writable.swap(false, Relaxed) {
                    warn(&format!("{error:#}"));
                }
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }
    pub fn load<T: DeserializeOwned>(&self) -> Result<Option<T>> {
        let Some(state) = self
            .persistent
            .as_ref()
            .filter(|_| self.writable.load(Relaxed))
        else {
            return Ok(None);
        };
        let value = self.optional_io(state.load())?.flatten();
        self.recorded.store(value.is_some(), Relaxed);
        Ok(value)
    }
    pub fn save<T: Serialize>(&self, value: &T) -> Result<()> {
        if let Some(state) = self
            .persistent
            .as_ref()
            .filter(|_| self.writable.load(Relaxed))
        {
            if self.optional_io(state.save(value))?.is_some() {
                self.recorded.store(true, Relaxed);
            }
        }
        Ok(())
    }
    pub fn clear(&self) -> Result<()> {
        self.recorded.store(false, Relaxed);
        if let Some(state) = &self.persistent {
            // Try cleanup even after a checkpoint failure, but do not turn a
            // completed copy into an error because its cache is unwritable.
            self.optional_io(state.clear())?;
        }
        Ok(())
    }
    pub fn has_record(&self) -> bool {
        self.recorded.load(Relaxed)
    }
}
fn cache_io_error(error: &anyhow::Error) -> bool {
    error.chain().any(|e| {
        e.downcast_ref::<std::io::Error>()
            // O_NOFOLLOW rejects substituted cache files with ELOOP. Keep
            // that identity check fatal instead of treating it as capacity
            // or permission failure.
            .is_some_and(|e| e.raw_os_error() != Some(libc::ELOOP))
    })
}
fn warn(reason: &str) {
    crate::output::diagnostic!(
        "syq: warning: cannot use S3 recovery cache ({reason}); continuing without saving recovery progress"
    );
}

struct PersistentState {
    directory: std::path::PathBuf,
    root: Arc<Root>,
    name: String,
    _lock: File,
}
impl PersistentState {
    fn open(path: std::path::PathBuf, identity: &[u8]) -> Result<Self> {
        std::fs::create_dir_all(&path).context("create S3 recovery directory")?;
        let m = std::fs::symlink_metadata(&path)?;
        if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } {
            bail!("S3 recovery directory must be owned by this user and not be a symlink");
        }
        // A private, searchable cache can already be used read-only. Avoid
        // chmod on every open: even an unchanged mode fails on a read-only FS.
        if m.mode() & 0o777 != 0o700 && m.mode() & 0o777 != 0o500 {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
        }
        let root = Arc::new(Root::open(&path)?);
        let name = blake3::hash(identity).to_hex().to_string();
        let lock_path = RelativePath::new(format!("{name}.lock").as_bytes())?;
        let lock = match root.open_regular_read_write(&lock_path) {
            Ok(file) => file,
            Err(error) if is_kind(&error, std::io::ErrorKind::NotFound) => {
                match root.create_file(&lock_path, 0o600) {
                    Ok(file) => file,
                    Err(error) if is_kind(&error, std::io::ErrorKind::AlreadyExists) => {
                        root.open_regular_read(&lock_path)?
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(error) if cache_io_error(&error) => root.open_regular_read(&lock_path)?,
            Err(error) => return Err(error),
        };
        let m = lock.metadata()?;
        if m.nlink() != 1 || m.uid() != unsafe { libc::geteuid() } {
            bail!("unsafe S3 recovery lock");
        }
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::WouldBlock {
                bail!("another S3 copy is using this recovery record; retry after it finishes");
            }
            return Err(error).context("lock S3 recovery record");
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
fn is_kind(error: &anyhow::Error, kind: std::io::ErrorKind) -> bool {
    error.chain().any(|e| {
        e.downcast_ref::<std::io::Error>()
            .is_some_and(|e| e.kind() == kind)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_cache_does_not_require_persistence() {
        let temp = crate::test_support::tempdir().unwrap();
        let blocked = temp.path().join("cache");
        std::fs::write(&blocked, b"not a directory").unwrap();
        let state = State::open_at(blocked.join("syq/s3"), b"upload").unwrap();
        assert!(state.load::<serde_json::Value>().unwrap().is_none());
        state
            .save(&serde_json::json!({"upload_id": "in-memory"}))
            .unwrap();
        assert!(!state.has_record());
        state.clear().unwrap();
        assert_eq!(std::fs::read(blocked).unwrap(), b"not a directory");
    }

    #[test]
    fn read_only_cache_does_not_fail_creation_checkpoints_or_cleanup() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let temp = crate::test_support::tempdir().unwrap();
        let parent = temp.path().join("home");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o555)).unwrap();
        let opened = State::open_at(parent.join(".cache/syq/s3"), b"upload");
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        let unavailable = opened.unwrap();
        unavailable.save(&serde_json::json!({"parts": {}})).unwrap();
        assert!(!unavailable.has_record());
        assert!(!parent.join(".cache").exists());

        let directory = parent.join("cache");
        let state = State::open_at(directory.clone(), b"download").unwrap();
        let original = serde_json::json!({"parts": {"0": "hash"}});
        state.save(&original).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o555)).unwrap();
        let checkpoint = state.save(&serde_json::json!({"parts": {"1": "new"}}));
        let retained = state.has_record();
        let cleanup = state.clear();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        checkpoint.unwrap();
        assert!(retained);
        cleanup.unwrap();
        let path = directory.join(format!("{}.json", state.persistent.as_ref().unwrap().name));
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&std::fs::read(path).unwrap()).unwrap(),
            original
        );
    }

    #[test]
    fn existing_record_and_lock_can_be_reopened_read_only() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let temp = crate::test_support::tempdir().unwrap();
        let directory = temp.path().join("cache");
        let original = serde_json::json!({"upload_id": "prepared"});
        let state = State::open_at(directory.clone(), b"upload").unwrap();
        state.save(&original).unwrap();
        let name = state.persistent.as_ref().unwrap().name.clone();
        drop(state);
        for extension in ["json", "lock"] {
            std::fs::set_permissions(
                directory.join(format!("{name}.{extension}")),
                std::fs::Permissions::from_mode(0o400),
            )
            .unwrap();
        }
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o500)).unwrap();
        let reopened = State::open_at(directory.clone(), b"upload");
        let mode = std::fs::metadata(&directory).unwrap().mode() & 0o777;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let reopened = reopened.unwrap();
        assert_eq!(
            mode, 0o500,
            "opening a private cache must not require chmod"
        );
        assert_eq!(
            reopened.load::<serde_json::Value>().unwrap(),
            Some(original)
        );
        assert!(reopened.has_record());
    }

    #[test]
    fn checkpoint_failure_keeps_previous_record_and_lock() {
        let temp = crate::test_support::tempdir().unwrap();
        let directory = temp.path().join("cache");
        let state = State::open_at(directory.clone(), b"download").unwrap();
        let previous = serde_json::json!({"parts": {"0": "old-hash"}});
        state.save(&previous).unwrap();
        let persistent = state.persistent.as_ref().unwrap();
        let path = directory.join(format!("{}.json", persistent.name));
        // Deterministic filesystem write failure, including when run as root.
        let temporary = directory.join(format!("{}.tmp", persistent.name));
        std::fs::create_dir(&temporary).unwrap();
        state
            .save(&serde_json::json!({"parts": {"1": "new-hash"}}))
            .unwrap();
        assert!(!state.writable.load(Relaxed));
        assert!(state.has_record());
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&std::fs::read(path).unwrap()).unwrap(),
            previous
        );
        assert!(State::open_at(directory.clone(), b"download")
            .err()
            .unwrap()
            .to_string()
            .contains("another S3 copy"));
        std::fs::remove_dir(temporary).unwrap();
        // Clearing remains best-effort even after checkpointing was disabled.
        state.clear().unwrap();
        assert!(!state.has_record());
        drop(state);
        let next = State::open_at(directory, b"download").unwrap();
        assert!(next.load::<serde_json::Value>().unwrap().is_none());
    }

    #[test]
    fn initial_checkpoint_and_cleanup_io_failures_are_optional() {
        let temp = crate::test_support::tempdir().unwrap();
        let directory = temp.path().join("cache");
        let state = State::open_at(directory.clone(), b"upload").unwrap();
        let name = state.persistent.as_ref().unwrap().name.clone();
        let temporary = directory.join(format!("{name}.tmp"));
        std::fs::create_dir(&temporary).unwrap();
        state
            .save(&serde_json::json!({"upload_id": "not-recorded"}))
            .unwrap();
        assert!(!state.has_record());
        std::fs::create_dir(directory.join(format!("{name}.json"))).unwrap();
        state.clear().unwrap();
        assert!(!state.has_record());
    }

    #[test]
    fn invalid_records_and_unsafe_cache_paths_are_still_errors() {
        let temp = crate::test_support::tempdir().unwrap();
        let directory = temp.path().join("cache");
        let state = State::open_at(directory.clone(), b"download").unwrap();
        let name = &state.persistent.as_ref().unwrap().name;
        let path = directory.join(format!("{name}.json"));
        std::fs::write(&path, b"{").unwrap();
        let error = state.load::<serde_json::Value>().unwrap_err();
        assert!(format!("{error:#}").contains(path.to_str().unwrap()));
        std::fs::remove_file(&path).unwrap();
        let other = temp.path().join("other.json");
        std::fs::write(&other, b"{}").unwrap();
        std::os::unix::fs::symlink(other, &path).unwrap();
        assert!(state.load::<serde_json::Value>().is_err());
        let alias = temp.path().join("alias");
        std::os::unix::fs::symlink(directory, &alias).unwrap();
        assert!(State::open_at(alias, b"other").is_err());
    }
}

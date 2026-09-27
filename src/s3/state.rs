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
    // A record this process could not read is left alone, even on success.
    readable: AtomicBool,
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
            Err(error) if blocked(&error) => Err(error),
            Err(error) => {
                warn(&format!("{error:#}"));
                Ok(Self::new(None))
            }
        }
    }
    fn new(persistent: Option<PersistentState>) -> Self {
        Self {
            writable: AtomicBool::new(persistent.is_some()),
            readable: AtomicBool::new(true),
            persistent,
            recorded: AtomicBool::new(false),
        }
    }
    // The cache is optional: a copy continues without it when it cannot be
    // read, written, or trusted. Only an invalid record and a busy recovery
    // lock stop the transfer, because they need the user's attention.
    fn optional<T>(&self, result: Result<T>) -> Result<Option<T>> {
        match result {
            Ok(value) => Ok(Some(value)),
            Err(error) if blocked(&error) => Err(error),
            Err(error) => {
                if self.writable.swap(false, Relaxed) {
                    warn(&format!("{error:#}"));
                }
                Ok(None)
            }
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
        let loaded = self.optional(state.load())?;
        if loaded.is_none() {
            self.readable.store(false, Relaxed);
        }
        let value = loaded.flatten();
        self.recorded.store(value.is_some(), Relaxed);
        Ok(value)
    }
    pub fn save<T: Serialize>(&self, value: &T) -> Result<()> {
        if let Some(state) = self
            .persistent
            .as_ref()
            .filter(|_| self.writable.load(Relaxed))
        {
            if self.optional(state.save(value))?.is_some() {
                self.recorded.store(true, Relaxed);
            }
        }
        Ok(())
    }
    pub fn clear(&self) -> Result<()> {
        self.recorded.store(false, Relaxed);
        if let Some(state) = self
            .persistent
            .as_ref()
            .filter(|_| self.readable.load(Relaxed))
        {
            // Try cleanup even after a checkpoint failure, but do not turn a
            // completed copy into an error because its cache is unwritable.
            self.optional(state.clear())?;
        }
        Ok(())
    }
    pub fn can_checkpoint(&self) -> bool {
        self.writable.load(Relaxed)
    }
    pub fn has_record(&self) -> bool {
        self.recorded.load(Relaxed)
    }
}
// A recovery problem the user should resolve rather than have syq bypass.
#[derive(Debug)]
struct Blocked(String);
impl std::fmt::Display for Blocked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Blocked {}
fn blocked(error: &anyhow::Error) -> bool {
    // Also finds Blocked when it was attached as context.
    error.downcast_ref::<Blocked>().is_some()
}
fn warn(reason: &str) {
    // Every multipart object opens its own record; say this once per process.
    static WARNED: AtomicBool = AtomicBool::new(false);
    if !WARNED.swap(true, Relaxed) {
        crate::output::diagnostic!(
            "syq: warning: cannot use S3 recovery cache ({reason}); continuing without saving recovery progress"
        );
    }
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
            bail!(
                "{} is a symlink or is not a directory owned by this user",
                path.display()
            );
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
            // flock needs only a readable descriptor.
            Err(_) => root.open_regular_read(&lock_path)?,
        };
        let m = lock.metadata()?;
        if m.nlink() != 1 || m.uid() != unsafe { libc::geteuid() } {
            bail!("S3 recovery lock is not a private file owned by this user");
        }
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::WouldBlock {
                return Err(Blocked(
                    "another S3 copy is using this recovery record; retry after it finishes".into(),
                )
                .into());
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
        if m.nlink() != 1 || m.uid() != unsafe { libc::geteuid() } {
            bail!("S3 recovery record is not a private file owned by this user");
        }
        let invalid = || {
            Blocked(format!(
                "invalid S3 recovery record {}; preserve it for recovery or remove it to restart",
                self.directory.join(format!("{}.json", self.name)).display()
            ))
        };
        if m.len() > 16 * 1024 * 1024 {
            return Err(invalid().into());
        }
        let mut text = Vec::new();
        file.take(16 * 1024 * 1024 + 1).read_to_end(&mut text)?;
        match serde_json::from_slice(&text) {
            Ok(value) => Ok(Some(value)),
            Err(error) => Err(anyhow::Error::new(error).context(invalid())),
        }
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
    fn invalid_records_are_still_errors() {
        let temp = crate::test_support::tempdir().unwrap();
        let directory = temp.path().join("cache");
        let state = State::open_at(directory.clone(), b"download").unwrap();
        let name = &state.persistent.as_ref().unwrap().name;
        let path = directory.join(format!("{name}.json"));
        std::fs::write(&path, b"{").unwrap();
        let error = state.load::<serde_json::Value>().unwrap_err();
        assert!(format!("{error:#}").contains(path.to_str().unwrap()));
        std::fs::File::create(&path)
            .unwrap()
            .set_len(16 * 1024 * 1024 + 1)
            .unwrap();
        let error = state.load::<serde_json::Value>().unwrap_err();
        assert!(format!("{error:#}").contains(path.to_str().unwrap()));
    }

    #[test]
    fn untrusted_cache_entries_are_skipped_and_kept() {
        let temp = crate::test_support::tempdir().unwrap();
        let directory = temp.path().join("cache");
        let state = State::open_at(directory.clone(), b"download").unwrap();
        let name = state.persistent.as_ref().unwrap().name.clone();
        drop(state);
        let path = directory.join(format!("{name}.json"));
        let other = temp.path().join("other.json");
        std::fs::write(&other, br#"{"parts": {}}"#).unwrap();
        for link in [
            std::os::unix::fs::symlink::<&std::path::Path, &std::path::Path>,
            std::fs::hard_link,
        ] {
            link(&other, &path).unwrap();
            let state = State::open_at(directory.clone(), b"download").unwrap();
            assert!(state.load::<serde_json::Value>().unwrap().is_none());
            state
                .save(&serde_json::json!({"parts": {"0": "new"}}))
                .unwrap();
            assert!(!state.has_record());
            state.clear().unwrap();
            drop(state);
            // A record this process could not read is neither replaced nor removed.
            assert!(std::fs::symlink_metadata(&path).is_ok());
            assert_eq!(std::fs::read(&other).unwrap(), br#"{"parts": {}}"#);
            std::fs::remove_file(&path).unwrap();
        }

        let lock = directory.join(format!("{name}.lock"));
        std::fs::hard_link(&lock, temp.path().join("lock-alias")).unwrap();
        let state = State::open_at(directory.clone(), b"download").unwrap();
        assert!(state.persistent.is_none());
        std::fs::remove_file(temp.path().join("lock-alias")).unwrap();

        // The same check covers a cache directory owned by another user.
        let alias = temp.path().join("alias");
        std::os::unix::fs::symlink(&directory, &alias).unwrap();
        let state = State::open_at(alias, b"download").unwrap();
        assert!(state.persistent.is_none());
        assert!(State::open_at(directory, b"download")
            .unwrap()
            .persistent
            .is_some());
    }
}

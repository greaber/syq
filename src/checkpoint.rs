//! Explicit cross-run checkpointing for unusually large or failure-prone jobs.
//!
//! No checkpoint is created unless the user supplies `--checkpoint FILE`.
//! The file is append-only JSONL and records regular files that were confirmed
//! complete. It persists until the user removes it. Destination partial files
//! remain the authoritative state for an unfinished individual file.

use crate::proto::{flags, Entry, PathBytes};
use anyhow::{bail, Context, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// 3: Deleted invalidation records. An older syq would skip the unparseable
// lines and trust the Complete records they void; the format check makes it
// refuse the file instead (restarting a checkpoint is always safe).
pub const FORMAT: u32 = 3;
const IDENTITY_FORMAT: u32 = 1;

fn checkpoint_lock_error(path: &Path, error: io::Error) -> anyhow::Error {
    if error.kind() == io::ErrorKind::WouldBlock {
        anyhow::anyhow!("checkpoint {} is already in use: {error}", path.display())
    } else if matches!(
        error.raw_os_error(),
        Some(libc::ENOLCK | libc::EOPNOTSUPP | libc::ENOSYS)
    ) {
        anyhow::anyhow!(
            "checkpoint locking is unavailable on the filesystem for {}: {error}",
            path.display()
        )
    } else {
        anyhow::anyhow!("lock checkpoint {}: {error}", path.display())
    }
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn unb64(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Record {
    Header {
        format: u32,
        job_identity: String,
    },
    Complete {
        path_b64: String,
        size: u64,
        mtime_sec: i64,
        mtime_nsec: u32,
        mode: u32,
        uid: u32,
        gid: u32,
        basis: String,
    },
    /// --delete removed this path; an earlier completion record is void.
    Deleted {
        path_b64: String,
    },
}

/// Source fingerprint stored when a destination file became complete.
#[derive(Clone, Copy, Debug)]
pub struct Completed {
    pub size: u64,
    pub mtime_sec: i64,
    pub mtime_nsec: u32,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

impl Completed {
    pub fn matches(&self, entry: &Entry, metadata_flags: u8) -> bool {
        self.size == entry.size
            && self.mtime_sec == entry.mtime
            && self.mtime_nsec == entry.mtime_nsec
            && (metadata_flags & flags::MODE == 0 || self.mode & 0o7777 == entry.mode & 0o7777)
            && (metadata_flags & flags::OWNER == 0 || self.uid == entry.uid)
            && (metadata_flags & flags::GROUP == 0 || self.gid == entry.gid)
    }
}

impl From<&Entry> for Completed {
    fn from(entry: &Entry) -> Self {
        Self {
            size: entry.size,
            mtime_sec: entry.mtime,
            mtime_nsec: entry.mtime_nsec,
            mode: entry.mode,
            uid: entry.uid,
            gid: entry.gid,
        }
    }
}

/// Canonical description used to reject accidental reuse for a different job.
pub fn job_identity(
    src_endpoint: &str,
    src_roots: &[(String, bool)],
    dst_endpoint: &str,
    dst_root: &str,
    semantic_flags: &str,
) -> String {
    serde_json::json!({
        "format": IDENTITY_FORMAT,
        "source_endpoint": src_endpoint,
        "source_roots": src_roots,
        "destination_endpoint": dst_endpoint,
        "destination_root": dst_root,
        "semantics": semantic_flags,
    })
    .to_string()
}

/// Compact collision-resistant ID used in destination partial names. The full
/// JSON identity remains in checkpoints where it can be inspected by a user.
pub fn partial_id(job_identity: &str) -> crate::proto::PartialId {
    let digest = Sha256::digest(job_identity.as_bytes());
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[..16]);
    id
}

const FLUSH_EVERY: usize = 256;
const FLUSH_AFTER: Duration = Duration::from_secs(1);

pub struct Loaded {
    pub completed: HashMap<PathBytes, Completed>,
    pub existing_identity: Option<String>,
}

impl Loaded {
    pub fn empty() -> Self {
        Self {
            completed: HashMap::new(),
            existing_identity: None,
        }
    }
}

/// Writable half of an enabled checkpoint.
pub struct Checkpoint {
    writer: Mutex<Writer>,
    failed: Mutex<Option<String>>,
    stop: AtomicBool,
    flusher: Mutex<Option<std::thread::JoinHandle<()>>>,
}

struct Writer {
    file: File,
    buf: Vec<u8>,
    unflushed: usize,
    oldest_unflushed: Option<Instant>,
}

impl Checkpoint {
    pub fn load(path: &Path) -> Result<Loaded> {
        let mut file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Loaded::empty()),
            Err(e) => return Err(e).with_context(|| format!("open checkpoint {}", path.display())),
        };
        Self::load_file(&mut file, path)
    }

    fn load_file(file: &mut File, path: &Path) -> Result<Loaded> {
        let mut out = Loaded::empty();
        let has_data = file
            .metadata()
            .with_context(|| format!("stat checkpoint {}", path.display()))?
            .len()
            != 0;
        file.seek(std::io::SeekFrom::Start(0))?;
        let mut reader = BufReader::with_capacity(1 << 20, &mut *file);
        let mut raw = String::new();
        loop {
            raw.clear();
            if reader
                .read_line(&mut raw)
                .with_context(|| format!("read checkpoint {}", path.display()))?
                == 0
            {
                break;
            }
            let Ok(record) = serde_json::from_str::<Record>(raw.trim()) else {
                continue;
            };
            match record {
                Record::Header {
                    format,
                    job_identity,
                } => {
                    if format != FORMAT {
                        bail!(
                            "checkpoint {} has format {format}, but this syq reads format {FORMAT}; remove it to restart (destination partials remain resumable)",
                            path.display()
                        );
                    }
                    if out
                        .existing_identity
                        .as_ref()
                        .is_some_and(|existing| existing != &job_identity)
                    {
                        bail!(
                            "checkpoint {} contains conflicting job headers",
                            path.display()
                        );
                    }
                    out.existing_identity = Some(job_identity);
                }
                Record::Complete {
                    path_b64,
                    size,
                    mtime_sec,
                    mtime_nsec,
                    mode,
                    uid,
                    gid,
                    ..
                } => {
                    // A real checkpoint starts with a flushed header. Never
                    // trust orphan records from a malformed or hand-made file.
                    if let (Some(_), Some(path)) = (&out.existing_identity, unb64(&path_b64)) {
                        out.completed.insert(
                            path,
                            Completed {
                                size,
                                mtime_sec,
                                mtime_nsec,
                                mode,
                                uid,
                                gid,
                            },
                        );
                    }
                }
                Record::Deleted { path_b64 } => {
                    if let Some(path) = unb64(&path_b64) {
                        out.completed.remove(&path);
                    }
                }
            }
        }
        if has_data && out.existing_identity.is_none() {
            bail!(
                "{} is not a SYQ checkpoint (no valid header); choose another path",
                path.display()
            );
        }
        Ok(out)
    }

    pub fn open(path: &Path, job_identity: &str) -> Result<(Self, Loaded)> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("open checkpoint {}", path.display()))?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(checkpoint_lock_error(path, io::Error::last_os_error()));
        }
        validate_writable_checkpoint(&file, path)?;
        // Validate and load only after locking the same file we will append to.
        let loaded = Self::load_file(&mut file, path)?;
        if let Some(existing) = &loaded.existing_identity {
            if existing != job_identity {
                bail!(
                    "checkpoint {} describes a different copy; choose another path or remove it",
                    path.display()
                );
            }
        }
        // Loading an existing checkpoint may take time. Recheck immediately
        // before the first mutation so a link/path swap during parsing is not
        // trusted merely because the initial post-lock check succeeded.
        validate_writable_checkpoint(&file, path)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        let len = file.metadata()?.len();
        if len > 0 {
            let mut last = [0u8; 1];
            file.seek(std::io::SeekFrom::Start(len - 1))?;
            file.read_exact(&mut last)?;
            if last[0] != b'\n' {
                file.write_all(b"\n")?;
            }
        }
        let checkpoint = Self {
            writer: Mutex::new(Writer {
                file,
                buf: Vec::with_capacity(64 << 10),
                unflushed: 0,
                oldest_unflushed: None,
            }),
            failed: Mutex::new(None),
            stop: AtomicBool::new(false),
            flusher: Mutex::new(None),
        };
        if loaded.existing_identity.is_none() {
            checkpoint.append(&Record::Header {
                format: FORMAT,
                job_identity: job_identity.to_string(),
            })?;
            checkpoint.flush()?;
        }
        Ok((checkpoint, loaded))
    }

    pub fn spawn_flusher(self: &Arc<Self>) {
        let checkpoint = self.clone();
        let handle = std::thread::spawn(move || {
            while !checkpoint.stop.load(Relaxed) {
                std::thread::sleep(Duration::from_millis(200));
                let due = checkpoint
                    .writer
                    .lock()
                    .unwrap()
                    .oldest_unflushed
                    .is_some_and(|t| t.elapsed() >= FLUSH_AFTER);
                if due {
                    if let Err(e) = checkpoint.flush() {
                        checkpoint.note_error(e);
                    }
                }
            }
        });
        *self.flusher.lock().unwrap() = Some(handle);
    }

    pub fn close(&self) -> Result<()> {
        self.stop.store(true, Relaxed);
        if let Some(handle) = self.flusher.lock().unwrap().take() {
            let _ = handle.join();
        }
        self.flush()
    }

    pub fn record_complete(&self, path: &[u8], entry: &Entry, basis: &str) {
        if self.failed.lock().unwrap().is_some() {
            return;
        }
        let fingerprint = Completed::from(entry);
        let result = self
            .append(&Record::Complete {
                path_b64: b64(path),
                size: fingerprint.size,
                mtime_sec: fingerprint.mtime_sec,
                mtime_nsec: fingerprint.mtime_nsec,
                mode: fingerprint.mode,
                uid: fingerprint.uid,
                gid: fingerprint.gid,
                basis: basis.to_string(),
            })
            .and_then(|_| {
                let mut writer = self.writer.lock().unwrap();
                if writer.unflushed >= FLUSH_EVERY {
                    self.flush_locked(&mut writer)
                } else {
                    Ok(())
                }
            });
        if let Err(e) = result {
            self.note_error(e);
        }
    }

    /// A mutation is about to make these checkpoint-complete paths missing or
    /// non-regular: persist the invalidation intents *first* — written and
    /// flushed, though not fsynced; the checkpoint never promises power-loss
    /// durability (see README) — so a crash can't leave a stale Complete
    /// record for a file that is gone. A stale intent (recorded, then the
    /// mutation failed or never ran) only costs a recheck on retry. An Err
    /// means the intents did not persist — the caller must not mutate.
    pub fn record_deleted_batch<'a>(&self, paths: impl Iterator<Item = &'a [u8]>) -> Result<()> {
        if let Some(error) = self.failed.lock().unwrap().as_ref() {
            bail!("checkpoint recording already stopped: {error}");
        }
        let result = (|| {
            for path in paths {
                self.append(&Record::Deleted {
                    path_b64: b64(path),
                })?;
            }
            let mut writer = self.writer.lock().unwrap();
            self.flush_locked(&mut writer)
        })();
        if let Err(error) = result {
            let message = format!("{error:#}");
            self.note_error(error);
            bail!("{message}");
        }
        Ok(())
    }

    pub fn take_error(&self) -> Option<String> {
        self.failed.lock().unwrap().take()
    }

    fn append(&self, record: &Record) -> Result<()> {
        let mut writer = self.writer.lock().unwrap();
        serde_json::to_writer(&mut writer.buf, record)?;
        writer.buf.push(b'\n');
        writer.unflushed += 1;
        writer.oldest_unflushed.get_or_insert_with(Instant::now);
        Ok(())
    }

    fn flush(&self) -> Result<()> {
        let mut writer = self.writer.lock().unwrap();
        self.flush_locked(&mut writer)
    }

    fn flush_locked(&self, writer: &mut Writer) -> Result<()> {
        if !writer.buf.is_empty() {
            writer.file.write_all(&writer.buf)?;
            writer.buf.clear();
        }
        writer.unflushed = 0;
        writer.oldest_unflushed = None;
        Ok(())
    }

    fn note_error(&self, error: anyhow::Error) {
        let mut failed = self.failed.lock().unwrap();
        if failed.is_none() {
            *failed = Some(format!("{error:#}"));
        }
    }
}

fn validate_writable_checkpoint(file: &File, path: &Path) -> Result<()> {
    let opened = file
        .metadata()
        .with_context(|| format!("stat open checkpoint {}", path.display()))?;
    if !opened.file_type().is_file() {
        bail!("checkpoint {} is not a regular file", path.display());
    }
    if opened.nlink() != 1 {
        bail!(
            "checkpoint {} must have exactly one hard link (found {})",
            path.display(),
            opened.nlink()
        );
    }
    let named = fs::symlink_metadata(path)
        .with_context(|| format!("stat checkpoint path {}", path.display()))?;
    if !named.file_type().is_file() || named.dev() != opened.dev() || named.ino() != opened.ino() {
        bail!(
            "checkpoint {} changed while it was being opened",
            path.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::Kind;
    use std::os::unix::fs::PermissionsExt;

    fn entry(size: u64, mtime: i64, mode: u32) -> Entry {
        Entry {
            path: Vec::new(),
            kind: Kind::File,
            size,
            mtime,
            mtime_nsec: 7,
            mode,
            uid: 11,
            gid: 12,
            rdev: 0,
            dev: 0,
            ino: 0,
            link: None,
        }
    }

    #[test]
    fn checkpoint_lock_errors_distinguish_contention_and_unsupported_filesystems() {
        let path = Path::new("state.jsonl");
        let contention =
            checkpoint_lock_error(path, io::Error::from_raw_os_error(libc::EWOULDBLOCK))
                .to_string();
        assert!(contention.contains("already in use"), "{contention}");

        let unavailable =
            checkpoint_lock_error(path, io::Error::from_raw_os_error(libc::ENOLCK)).to_string();
        assert!(
            unavailable.contains("locking is unavailable"),
            "{unavailable}"
        );

        let other =
            checkpoint_lock_error(path, io::Error::from_raw_os_error(libc::EACCES)).to_string();
        assert!(other.starts_with("lock checkpoint "), "{other}");
        assert!(!other.contains("already in use"), "{other}");
    }

    #[test]
    fn round_trip_and_metadata_matching() {
        let dir = std::env::temp_dir().join(format!(
            "syq-checkpoint-unit-{}-round-trip",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.jsonl");
        let _ = fs::remove_file(&path);
        let (checkpoint, _) = Checkpoint::open(&path, "identity").unwrap();
        checkpoint.record_complete(b"a/b", &entry(10, 20, 0o644), "transferred");
        checkpoint.close().unwrap();
        let loaded = Checkpoint::load(&path).unwrap();
        let complete = loaded.completed.get(b"a/b".as_slice()).unwrap();
        assert!(complete.matches(&entry(10, 20, 0o644), flags::MODE));
        assert!(!complete.matches(&entry(10, 20, 0o600), flags::MODE));
        assert!(complete.matches(&entry(10, 20, 0o600), 0));
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        drop(checkpoint);
        fs::remove_file(&path).unwrap();
        fs::remove_dir(&dir).unwrap();
    }

    #[test]
    fn deletion_tombstones_are_flushed_immediately() {
        let dir = std::env::temp_dir().join(format!(
            "syq-checkpoint-unit-{}-deleted",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.jsonl");
        let _ = fs::remove_file(&path);

        let (checkpoint, _) = Checkpoint::open(&path, "identity").unwrap();
        checkpoint.record_complete(b"a/b", &entry(10, 20, 0o644), "transferred");
        checkpoint.close().unwrap();
        drop(checkpoint);

        let (checkpoint, loaded) = Checkpoint::open(&path, "identity").unwrap();
        assert!(loaded.completed.contains_key(b"a/b".as_slice()));
        checkpoint
            .record_deleted_batch([b"a/b".as_slice()].into_iter())
            .unwrap();
        assert!(
            !Checkpoint::load(&path)
                .unwrap()
                .completed
                .contains_key(b"a/b".as_slice()),
            "the tombstone must be visible before close"
        );
        checkpoint.close().unwrap();
        drop(checkpoint);
        fs::remove_file(&path).unwrap();
        fs::remove_dir(&dir).unwrap();
    }

    #[test]
    fn identity_mismatch_is_rejected() {
        let dir = std::env::temp_dir().join(format!(
            "syq-checkpoint-unit-{}-identity",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.jsonl");
        let _ = fs::remove_file(&path);
        Checkpoint::open(&path, "A").unwrap().0.close().unwrap();
        assert!(Checkpoint::open(&path, "B").is_err());
        let cleanup = Checkpoint::open(&path, "A").unwrap().0;
        cleanup.close().unwrap();
        drop(cleanup);
        fs::remove_file(&path).unwrap();
        fs::remove_dir(&dir).unwrap();
    }

    #[test]
    fn old_format_error_explains_safe_restart() {
        let dir = std::env::temp_dir().join(format!(
            "syq-checkpoint-unit-{}-old-format",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.jsonl");
        fs::write(
            &path,
            b"{\"type\":\"header\",\"format\":1,\"job_identity\":\"old\"}\n",
        )
        .unwrap();

        let error = Checkpoint::load(&path).err().unwrap().to_string();
        assert!(error.contains("remove it to restart"), "{error}");
        assert!(error.contains("partials remain resumable"), "{error}");

        fs::remove_file(&path).unwrap();
        fs::remove_dir(&dir).unwrap();
    }

    #[test]
    fn concurrent_writer_is_rejected() {
        let dir =
            std::env::temp_dir().join(format!("syq-checkpoint-unit-{}-locked", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.jsonl");
        let _ = fs::remove_file(&path);
        let (first, _) = Checkpoint::open(&path, "A").unwrap();
        assert!(Checkpoint::open(&path, "A").is_err());
        first.close().unwrap();
        drop(first);
        fs::remove_file(&path).unwrap();
        fs::remove_dir(&dir).unwrap();
    }

    #[test]
    fn hardlinked_checkpoint_is_rejected_before_chmod_or_write() {
        let dir = std::env::temp_dir().join(format!(
            "syq-checkpoint-unit-{}-hardlink",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.jsonl");
        let alias = dir.join("important");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&alias);
        fs::write(&alias, b"important").unwrap();
        fs::set_permissions(&alias, fs::Permissions::from_mode(0o644)).unwrap();
        fs::hard_link(&alias, &path).unwrap();

        let error = Checkpoint::open(&path, "A").err().unwrap().to_string();
        assert!(error.contains("exactly one hard link"), "{error}");
        assert_eq!(fs::read(&alias).unwrap(), b"important");
        assert_eq!(fs::metadata(&alias).unwrap().mode() & 0o777, 0o644);

        fs::remove_file(&path).unwrap();
        fs::remove_file(&alias).unwrap();
        fs::remove_dir(&dir).unwrap();
    }

    #[test]
    fn orphaned_or_replaced_checkpoint_handle_is_rejected() {
        let dir = std::env::temp_dir().join(format!(
            "syq-checkpoint-unit-{}-handle-identity",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.jsonl");
        let moved = dir.join("moved");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&moved);

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&path)
            .unwrap();
        fs::rename(&path, &moved).unwrap();
        fs::write(&path, b"replacement").unwrap();
        let error = validate_writable_checkpoint(&file, &path)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("changed while"), "{error}");
        fs::remove_file(&path).unwrap();
        fs::remove_file(&moved).unwrap();

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&path)
            .unwrap();
        fs::remove_file(&path).unwrap();
        let error = validate_writable_checkpoint(&file, &path)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("exactly one hard link"), "{error}");
        drop(file);
        fs::remove_dir(&dir).unwrap();
    }
}

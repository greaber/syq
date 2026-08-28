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
use std::io::{BufRead, BufReader, Read, Seek, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const FORMAT: u32 = 2;
const IDENTITY_FORMAT: u32 = 1;

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
    path: PathBuf,
    writer: Mutex<Writer>,
    fsync: bool,
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
                            "checkpoint {} has format {format}, but this syq reads format {FORMAT}",
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

    pub fn open(path: &Path, job_identity: &str, fsync: bool) -> Result<(Self, Loaded)> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("open checkpoint {}", path.display()))?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            bail!(
                "checkpoint {} is already in use: {}",
                path.display(),
                std::io::Error::last_os_error()
            );
        }
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
            path: path.to_path_buf(),
            writer: Mutex::new(Writer {
                file,
                buf: Vec::with_capacity(64 << 10),
                unflushed: 0,
                oldest_unflushed: None,
            }),
            fsync,
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
            if fsync {
                checkpoint.sync_parent()?;
            }
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
            if self.fsync {
                writer.file.sync_data()?;
            }
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

    fn sync_parent(&self) -> Result<()> {
        crate::fsops::fsync_parent(&self.path)
    }
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
    fn round_trip_and_metadata_matching() {
        let dir = std::env::temp_dir().join(format!(
            "syq-checkpoint-unit-{}-round-trip",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.jsonl");
        let _ = fs::remove_file(&path);
        let (checkpoint, _) = Checkpoint::open(&path, "identity", false).unwrap();
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
    fn identity_mismatch_is_rejected() {
        let dir = std::env::temp_dir().join(format!(
            "syq-checkpoint-unit-{}-identity",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.jsonl");
        let _ = fs::remove_file(&path);
        Checkpoint::open(&path, "A", false)
            .unwrap()
            .0
            .close()
            .unwrap();
        assert!(Checkpoint::open(&path, "B", false).is_err());
        let cleanup = Checkpoint::open(&path, "A", false).unwrap().0;
        cleanup.close().unwrap();
        drop(cleanup);
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
        let (first, _) = Checkpoint::open(&path, "A", false).unwrap();
        assert!(Checkpoint::open(&path, "A", false).is_err());
        first.close().unwrap();
        drop(first);
        fs::remove_file(&path).unwrap();
        fs::remove_dir(&dir).unwrap();
    }
}

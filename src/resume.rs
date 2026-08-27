//! Interrupted-transfer resume: a destination-side session marker (the
//! cross-machine interlock) plus a local, job-keyed completion journal (which
//! lets a resume or rerun skip destination metadata for files already done).
//!
//! See RESUME-DESIGN.md. v1 journals regular files only; directories, symlinks
//! and special files continue through the ordinary planner.

use crate::proto::PathBytes;
use anyhow::{bail, Context, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::Mutex;

pub const FORMAT: u32 = 1;
pub const MARKER_NAME: &str = ".pcp-transfer-session.json";

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}
fn unb64(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

/// Root-directory metadata captured at session_complete so post-marker cleanup
/// can restore it even after a crash.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
pub struct RootMeta {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime_sec: i64,
    pub mtime_nsec: u32,
}

/// The marker written on the destination filesystem.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Marker {
    pub format: u32,
    pub session_id: String,
    pub job_identity: String,
    pub created_at: i64,
    pub coordinator_host: String,
}

/// JSONL journal records.
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Record {
    Header {
        format: u32,
        job_identity: String,
    },
    SessionStart {
        session_id: String,
        started_at: i64,
    },
    Complete {
        path_b64: String,
        kind: String,
        size: u64,
        mtime_sec: i64,
        mtime_nsec: u32,
        basis: String,
    },
    SessionComplete {
        session_id: String,
        completed_at: i64,
        root_meta: Option<RootMeta>,
    },
    CleanupComplete {
        session_id: String,
        completed_at: i64,
    },
}

/// A previously-recorded completion (source fingerprint at the time it finished).
#[derive(Clone, Copy)]
pub struct Completed {
    pub size: u64,
    pub mtime_sec: i64,
    pub mtime_nsec: u32,
}

/// State of the latest session found in an existing journal.
#[derive(Clone, Debug, PartialEq)]
pub enum LastSession {
    None,
    /// session_start seen, no session_complete: payload interrupted.
    Incomplete(String),
    /// session_complete but not cleanup_complete: cleanup pending/crashed.
    NeedsCleanup(String, Option<RootMeta>),
    /// cleanup_complete: fully done.
    CleanedUp(String),
}

/// Normalized, hashable description of a repeatable copy job.
pub fn job_key(job_identity: &str) -> String {
    format!(
        "{:032x}",
        xxhash_rust::xxh3::xxh3_128(job_identity.as_bytes())
    )
}

/// Build the canonical job-identity string. Only content/metadata-affecting
/// inputs are included; operational options (workers, tcp, compression, …) are
/// not, so they don't fragment the journal.
pub fn job_identity(
    src_endpoint: &str,
    src_roots: &[(String, bool)], // (normalized path, copies_contents)
    dst_endpoint: &str,
    dst_root: &str,
    semantic_flags: &str,
) -> String {
    let mut s = format!("format={FORMAT}\nsrc_ep={src_endpoint}\n");
    for (p, cc) in src_roots {
        s.push_str(&format!("src={p}\tcontents={cc}\n"));
    }
    s.push_str(&format!(
        "dst_ep={dst_endpoint}\ndst={dst_root}\nopts={semantic_flags}\n"
    ));
    s
}

fn state_dir() -> PathBuf {
    if let Some(x) = std::env::var_os("PCP_STATE_DIR") {
        return PathBuf::from(x);
    }
    if let Some(x) = std::env::var_os("XDG_STATE_HOME") {
        return PathBuf::from(x).join("pcp");
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".local/state/pcp")
}

pub fn journal_path(job_key: &str) -> PathBuf {
    state_dir()
        .join("transfers")
        .join(format!("{job_key}.jsonl"))
}

/// The completion journal for one job. Appends are serialized and flushed on a
/// cadence; per-file fsync is not required (loss only causes repeated work).
pub struct Journal {
    w: Mutex<BufWriter<File>>,
}

/// Result of opening a journal: the completed-file map and the latest session.
pub struct Loaded {
    pub completed: HashMap<PathBytes, Completed>,
    pub last: LastSession,
    pub existing_identity: Option<String>,
}

impl Journal {
    /// Parse an existing journal (if any) without opening for append.
    pub fn load(job_key: &str) -> Result<Loaded> {
        let p = journal_path(job_key);
        let mut completed = HashMap::new();
        let mut last = LastSession::None;
        let mut existing_identity = None;
        let data = match fs::read_to_string(&p) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Loaded {
                    completed,
                    last,
                    existing_identity,
                })
            }
            Err(e) => return Err(e).with_context(|| format!("read journal {}", p.display())),
        };
        let lines: Vec<&str> = data.lines().collect();
        let n = lines.len();
        for (i, line) in lines.iter().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let rec: Record = match serde_json::from_str(line) {
                Ok(r) => r,
                Err(e) => {
                    // A malformed *final* line is a crash-truncated tail: ignore.
                    if i + 1 == n {
                        break;
                    }
                    bail!("journal {} corrupt at line {}: {e}", p.display(), i + 1);
                }
            };
            match rec {
                Record::Header { job_identity, .. } => existing_identity = Some(job_identity),
                Record::SessionStart { session_id, .. } => {
                    last = LastSession::Incomplete(session_id)
                }
                Record::Complete {
                    path_b64,
                    size,
                    mtime_sec,
                    mtime_nsec,
                    ..
                } => {
                    if let Some(path) = unb64(&path_b64) {
                        completed.insert(
                            path,
                            Completed {
                                size,
                                mtime_sec,
                                mtime_nsec,
                            },
                        );
                    }
                }
                Record::SessionComplete {
                    session_id,
                    root_meta,
                    ..
                } => {
                    last = LastSession::NeedsCleanup(session_id, root_meta);
                }
                Record::CleanupComplete { session_id, .. } => {
                    last = LastSession::CleanedUp(session_id);
                }
            }
        }
        Ok(Loaded {
            completed,
            last,
            existing_identity,
        })
    }

    /// Open (creating parents) for append, writing the header if new.
    pub fn open(
        job_key: &str,
        job_identity: &str,
        existing_identity: Option<&str>,
    ) -> Result<Journal> {
        let p = journal_path(job_key);
        if let Some(dir) = p.parent() {
            fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
            let _ = fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o700));
        }
        let is_new = existing_identity.is_none() && !p.exists();
        use std::os::unix::fs::OpenOptionsExt;
        let f = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&p)
            .with_context(|| format!("open journal {}", p.display()))?;
        let j = Journal {
            w: Mutex::new(BufWriter::new(f)),
        };
        if is_new {
            j.append(&Record::Header {
                format: FORMAT,
                job_identity: job_identity.to_string(),
            })?;
        } else if let Some(existing) = existing_identity {
            if existing != job_identity {
                bail!("journal identity mismatch (different mapping for the same key)");
            }
        }
        Ok(j)
    }

    fn append(&self, rec: &Record) -> Result<()> {
        let mut w = self.w.lock().unwrap();
        let line = serde_json::to_string(rec)?;
        w.write_all(line.as_bytes())?;
        w.write_all(b"\n")?;
        Ok(())
    }

    pub fn session_start(&self, session_id: &str) -> Result<()> {
        self.append(&Record::SessionStart {
            session_id: session_id.to_string(),
            started_at: now_secs(),
        })?;
        self.flush()
    }

    pub fn record_complete(
        &self,
        path: &[u8],
        size: u64,
        mtime_sec: i64,
        mtime_nsec: u32,
        basis: &str,
    ) {
        let _ = self.append(&Record::Complete {
            path_b64: b64(path),
            kind: "file".into(),
            size,
            mtime_sec,
            mtime_nsec,
            basis: basis.to_string(),
        });
    }

    pub fn session_complete(&self, session_id: &str, root_meta: Option<RootMeta>) -> Result<()> {
        self.append(&Record::SessionComplete {
            session_id: session_id.to_string(),
            completed_at: now_secs(),
            root_meta,
        })?;
        self.flush()
    }

    pub fn cleanup_complete(&self, session_id: &str) -> Result<()> {
        self.append(&Record::CleanupComplete {
            session_id: session_id.to_string(),
            completed_at: now_secs(),
        })?;
        self.flush()
    }

    pub fn flush(&self) -> Result<()> {
        self.w.lock().unwrap().flush()?;
        Ok(())
    }
}

pub fn new_session_id() -> String {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).expect("getrandom");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn hostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup(name: &str) -> String {
        let dir = std::env::temp_dir().join("pcp-unit-state");
        std::env::set_var("PCP_STATE_DIR", &dir);
        let key = job_key(&format!("test-identity-{name}"));
        let _ = std::fs::remove_file(journal_path(&key));
        key
    }

    #[test]
    fn job_key_deterministic_and_sensitive() {
        let a = job_identity("h", &[("/x".into(), true)], "h2", "/y", "aOgt");
        let b = job_identity("h", &[("/x".into(), true)], "h2", "/y", "aOgt");
        let c = job_identity("h", &[("/x".into(), true)], "h2", "/z", "aOgt");
        assert_eq!(job_key(&a), job_key(&b), "same inputs -> same key");
        assert_ne!(job_key(&a), job_key(&c), "different dst -> different key");
    }

    #[test]
    fn journal_state_machine() {
        let key = setup("lifecycle");
        let ident = "test-identity-lifecycle";

        // Fresh: nothing recorded.
        let loaded = Journal::load(&key).unwrap();
        assert_eq!(loaded.last, LastSession::None);
        assert!(loaded.completed.is_empty());

        // A session that records one file but never completes -> Incomplete,
        // and the completion is visible for a resume skip.
        let j = Journal::open(&key, ident, None).unwrap();
        j.session_start("sess-1").unwrap();
        j.record_complete(b"a/b.txt", 100, 1_600_000_000, 42, "transferred");
        j.flush().unwrap();
        drop(j);

        let loaded = Journal::load(&key).unwrap();
        assert_eq!(loaded.last, LastSession::Incomplete("sess-1".into()));
        assert_eq!(loaded.existing_identity.as_deref(), Some(ident));
        let c = loaded
            .completed
            .get(b"a/b.txt".as_slice())
            .expect("recorded");
        assert_eq!(
            (c.size, c.mtime_sec, c.mtime_nsec),
            (100, 1_600_000_000, 42)
        );

        // session_complete -> NeedsCleanup, completion still retained.
        let rm = RootMeta {
            mode: 0o755,
            uid: 7,
            gid: 8,
            mtime_sec: 5,
            mtime_nsec: 9,
        };
        let j = Journal::open(&key, ident, loaded.existing_identity.as_deref()).unwrap();
        j.session_complete("sess-1", Some(rm)).unwrap();
        drop(j);
        let loaded = Journal::load(&key).unwrap();
        assert_eq!(
            loaded.last,
            LastSession::NeedsCleanup("sess-1".into(), Some(rm))
        );
        assert!(loaded.completed.contains_key(b"a/b.txt".as_slice()));

        // cleanup_complete -> CleanedUp, completion STILL retained for fast reruns.
        let j = Journal::open(&key, ident, loaded.existing_identity.as_deref()).unwrap();
        j.cleanup_complete("sess-1").unwrap();
        drop(j);
        let loaded = Journal::load(&key).unwrap();
        assert_eq!(loaded.last, LastSession::CleanedUp("sess-1".into()));
        assert!(loaded.completed.contains_key(b"a/b.txt".as_slice()));
    }

    #[test]
    fn identity_mismatch_is_rejected() {
        let key = setup("mismatch");
        let j = Journal::open(&key, "identity-A", None).unwrap();
        j.session_start("s").unwrap();
        drop(j);
        let loaded = Journal::load(&key).unwrap();
        assert!(
            Journal::open(&key, "identity-B", loaded.existing_identity.as_deref()).is_err(),
            "a different mapping for the same key must be refused"
        );
    }
}

//! Independently compressed JSON batches. A complete batch is visible before
//! its associated mutations begin; a torn final batch is discarded on reopen.
//! This is process-interruption recovery, not a power-loss durability promise.
use anyhow::{bail, Context, Result};
use serde::{de::DeserializeOwned, Serialize};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;

const MAGIC: &[u8; 8] = b"SYQJOB\0\x01";
const HEADER: usize = 40;
const MAX_BATCH: usize = 16 * 1024 * 1024;

pub(super) struct Journal {
    file: File,
    end: u64,
    failed: bool,
    compressor: zstd::bulk::Compressor<'static>,
}

impl Journal {
    /// The caller opens a private, non-symlink regular file. Lock the inode for
    /// the entire attempt, including after a write failure.
    pub fn open<T: DeserializeOwned>(
        mut file: File,
        mut visit: impl FnMut(T) -> Result<()>,
    ) -> Result<Self> {
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            bail!("job journal must be a private regular file owned by this user");
        }
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(std::io::Error::last_os_error())
                .context("lock job journal (another attempt may still be running)");
        }
        if metadata.len() == 0 {
            file.write_all(MAGIC)?;
        }
        file.seek(SeekFrom::Start(0))?;
        let mut magic = [0; 8];
        file.read_exact(&mut magic)
            .context("read job journal version")?;
        if &magic != MAGIC {
            bail!("unsupported job journal format; use the syq version that created this job");
        }
        let mut end = 8;
        loop {
            let mut header = [0; HEADER];
            if !read_complete(&mut file, &mut header)? {
                break;
            }
            let compressed = u32::from_le_bytes(header[..4].try_into().unwrap()) as usize;
            let uncompressed = u32::from_le_bytes(header[4..8].try_into().unwrap()) as usize;
            if compressed > MAX_BATCH || uncompressed > MAX_BATCH || compressed == 0 {
                bail!("invalid job journal batch length");
            }
            let mut payload = vec![0; compressed];
            if !read_complete(&mut file, &mut payload)? {
                break;
            }
            if blake3::hash(&payload).as_bytes() != &header[8..] {
                bail!("job journal batch checksum does not match");
            }
            let decoded = zstd::bulk::decompress(&payload, uncompressed)
                .context("decompress job journal batch")?;
            if decoded.len() != uncompressed {
                bail!("job journal batch length does not match");
            }
            let records: Vec<T> =
                serde_json::from_slice(&decoded).context("read job journal records")?;
            for record in records {
                visit(record)?;
            }
            end += (HEADER + compressed) as u64;
        }
        // Only an incomplete tail is removed. Corrupt complete records and
        // unknown versions fail above without rewriting the file.
        file.set_len(end)?;
        file.seek(SeekFrom::Start(end))?;
        Ok(Self {
            file,
            end,
            failed: false,
            compressor: zstd::bulk::Compressor::new(3)?,
        })
    }

    pub fn append<T: Serialize>(&mut self, records: &[T]) -> Result<()> {
        if self.failed {
            bail!("job journal is unavailable after a previous write failure");
        }
        if records.is_empty() {
            return Ok(());
        }
        let decoded = serde_json::to_vec(records)?;
        if decoded.len() > MAX_BATCH {
            bail!("job journal batch exceeds 16 MiB");
        }
        let compressed = self.compressor.compress(&decoded)?;
        if compressed.len() > MAX_BATCH {
            bail!("compressed job journal batch exceeds 16 MiB");
        }
        let mut frame = Vec::with_capacity(HEADER + compressed.len());
        frame.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        frame.extend_from_slice(&(decoded.len() as u32).to_le_bytes());
        frame.extend_from_slice(blake3::hash(&compressed).as_bytes());
        frame.extend_from_slice(&compressed);
        if let Err(error) = self.file.write_all(&frame) {
            self.failed = true;
            return Err(error).context("append job journal batch");
        }
        self.end += frame.len() as u64;
        Ok(())
    }
}

impl Drop for Journal {
    fn drop(&mut self) {
        // A concurrent fork may briefly inherit this open file description.
        // Release our lock explicitly instead of waiting for its exec/exit.
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

fn read_complete(file: &mut File, bytes: &mut [u8]) -> Result<bool> {
    match file.read_exact(bytes) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;

    fn open(path: &std::path::Path) -> File {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)
            .unwrap()
    }

    #[test]
    fn resumes_at_last_complete_batch_after_every_possible_tail_cut() {
        let dir = crate::test_support::tempdir().unwrap();
        let path = dir.path().join("journal");
        let mut journal = Journal::open::<String>(open(&path), |_| Ok(())).unwrap();
        journal.append(&["first", "second"]).unwrap();
        let first_end = journal.end as usize;
        journal.append(&["third"]).unwrap();
        drop(journal);
        let original = std::fs::read(&path).unwrap();
        for cut in first_end..original.len() {
            std::fs::write(&path, &original[..cut]).unwrap();
            let mut found = Vec::<String>::new();
            let mut resumed = Journal::open(open(&path), |value| {
                found.push(value);
                Ok(())
            })
            .unwrap();
            assert_eq!(found, ["first", "second"]);
            resumed.append(&["replacement"]).unwrap();
            drop(resumed);
            let mut found = Vec::<String>::new();
            let _reopened = Journal::open(open(&path), |value| {
                found.push(value);
                Ok(())
            })
            .unwrap();
            assert_eq!(found, ["first", "second", "replacement"]);
        }
    }

    #[test]
    fn rejects_concurrent_attempts_and_corrupt_complete_batches() {
        let dir = crate::test_support::tempdir().unwrap();
        let path = dir.path().join("journal");
        let mut journal = Journal::open::<u64>(open(&path), |_| Ok(())).unwrap();
        journal.append(&[1, 2, 3]).unwrap();
        assert!(Journal::open::<u64>(open(&path), |_| Ok(())).is_err());
        drop(journal);
        let mut bytes = std::fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        std::fs::write(&path, &bytes).unwrap();
        assert!(Journal::open::<u64>(open(&path), |_| Ok(())).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }

    #[test]
    fn rejects_unknown_version_without_modifying_it() {
        let dir = crate::test_support::tempdir().unwrap();
        let path = dir.path().join("journal");
        let _file = open(&path);
        let unknown = b"SYQJOB\0\x02";
        std::fs::write(&path, unknown).unwrap();
        assert!(Journal::open::<u64>(open(&path), |_| Ok(())).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), unknown);
    }
}

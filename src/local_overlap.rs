//! Opt-in diagnostic for overlap inside a same-host whole-file copy.
//! This module is experimental and is not intended for a production merge.
use anyhow::{bail, Context, Result};
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

pub(crate) const BLOCK: u64 = 1 << 20;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Experiment {
    pipeline: bool,
    workers: usize,
}

impl Experiment {
    pub(crate) fn from_env() -> Result<Option<Self>> {
        match std::env::var("SYQ_EXPERIMENT_LOCAL_OVERLAP") {
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(error) => Err(error.into()),
            Ok(value) => Self::parse(&value).map(Some),
        }
    }

    fn parse(value: &str) -> Result<Self> {
        let Some((mode, workers)) = value.split_once(':') else {
            bail!("overlap experiment expects cfr:N or pipeline:N (1..8)");
        };
        let workers = workers.parse::<usize>()?;
        if !matches!(mode, "cfr" | "pipeline") || !(1..=8).contains(&workers) {
            bail!("overlap experiment expects cfr:N or pipeline:N (1..8)");
        }
        Ok(Self {
            pipeline: mode == "pipeline",
            workers,
        })
    }

    /// Descriptors are already authorized and remain borrowed until all workers
    /// join. Errors stop new work and all issued writes finish before returning.
    pub(crate) fn copy(
        self,
        source: &File,
        destination: &File,
        start: u64,
        size: u64,
    ) -> Result<()> {
        let next = AtomicU64::new(start);
        let cancelled = AtomicBool::new(false);
        let writer = Mutex::new(());
        std::thread::scope(|scope| -> Result<()> {
            let mut handles = Vec::with_capacity(self.workers);
            let mut failure = None;
            for _ in 0..self.workers {
                let (next, cancelled, writer) = (&next, &cancelled, &writer);
                let spawned = std::thread::Builder::new()
                    .name("syq-copy-overlap".into())
                    .spawn_scoped(scope, move || -> io::Result<()> {
                        let result = (|| {
                            let mut buffer = if self.pipeline {
                                vec![0; BLOCK as usize]
                            } else {
                                Vec::new()
                            };
                            while !cancelled.load(Ordering::Relaxed) {
                                let offset = next.fetch_add(BLOCK, Ordering::Relaxed);
                                if offset >= size {
                                    break;
                                }
                                let len = (size - offset).min(BLOCK) as usize;
                                if self.pipeline {
                                    source.read_exact_at(&mut buffer[..len], offset)?;
                                    let _guard = writer
                                        .lock()
                                        .map_err(|_| io::Error::other("copy writer panicked"))?;
                                    if cancelled.load(Ordering::Relaxed) {
                                        break;
                                    }
                                    destination.write_all_at(&buffer[..len], offset)?;
                                } else {
                                    let (mut src, mut dst) =
                                        (offset as libc::off64_t, offset as libc::off64_t);
                                    let mut remaining = len;
                                    while remaining > 0 {
                                        let n = unsafe {
                                            libc::copy_file_range(
                                                source.as_raw_fd(),
                                                &mut src,
                                                destination.as_raw_fd(),
                                                &mut dst,
                                                remaining,
                                                0,
                                            )
                                        };
                                        if n < 0 {
                                            let error = io::Error::last_os_error();
                                            if error.kind() == io::ErrorKind::Interrupted {
                                                continue;
                                            }
                                            return Err(error);
                                        }
                                        if n == 0 {
                                            return Err(io::Error::new(
                                                io::ErrorKind::UnexpectedEof,
                                                "source shortened during overlap copy",
                                            ));
                                        }
                                        remaining -= n as usize;
                                    }
                                }
                            }
                            Ok(())
                        })();
                        if result.is_err() {
                            cancelled.store(true, Ordering::Relaxed);
                        }
                        result
                    });
                match spawned {
                    Ok(handle) => handles.push(handle),
                    Err(error) => {
                        cancelled.store(true, Ordering::Relaxed);
                        failure = Some(anyhow::Error::new(error));
                        break;
                    }
                }
            }
            for handle in handles {
                let result = handle
                    .join()
                    .map_err(|_| anyhow::anyhow!("overlap worker panicked"))
                    .and_then(|r| r.map_err(Into::into));
                if let Err(error) = result {
                    cancelled.store(true, Ordering::Relaxed);
                    if failure.is_none() {
                        failure = Some(error);
                    }
                }
            }
            if let Some(error) = failure {
                return Err(error);
            }
            Ok(())
        })
        .context("experimental local copy overlap")?;
        if std::env::var_os("SYQ_DEBUG").is_some() {
            eprintln!(
                "syq: overlap observed: {}",
                serde_json::json!({"mode":if self.pipeline {"pipeline"} else {"cfr"},"workers":self.workers,"bytes":size-start})
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn overlap_preserves_prefix_and_copies_tail() {
        let temp = crate::test_support::tempdir().unwrap();
        let source_path = temp.path().join("source");
        let data: Vec<u8> = (0..(3 * BLOCK as usize + 73))
            .map(|n| (n.wrapping_mul(137) ^ (n >> 12)) as u8)
            .collect();
        std::fs::write(&source_path, &data).unwrap();
        let source = File::open(source_path).unwrap();
        for mode in ["cfr:1", "cfr:8", "pipeline:1", "pipeline:8"] {
            let dest_path = temp.path().join(mode);
            let mut destination = File::create(&dest_path).unwrap();
            destination.write_all(&data[..BLOCK as usize]).unwrap();
            Experiment::parse(mode)
                .unwrap()
                .copy(&source, &destination, BLOCK, data.len() as u64)
                .unwrap();
            assert_eq!(std::fs::read(dest_path).unwrap(), data);
        }
    }

    #[test]
    fn overlap_rejects_short_sources_and_write_errors() {
        let temp = crate::test_support::tempdir().unwrap();
        let path = temp.path().join("source");
        std::fs::write(&path, vec![7; 2 * BLOCK as usize]).unwrap();
        let source = File::open(&path).unwrap();
        for mode in ["cfr:8", "pipeline:8"] {
            let destination = File::create(temp.path().join(mode)).unwrap();
            let experiment = Experiment::parse(mode).unwrap();
            assert!(experiment
                .copy(&source, &destination, 0, 4 * BLOCK)
                .is_err());
            assert!(experiment.copy(&source, &source, 0, BLOCK).is_err());
        }
        for invalid in ["cfr", "cfr:0", "cfr:9", "pipeline:1000", "other:8"] {
            assert!(Experiment::parse(invalid).is_err());
        }
    }
}

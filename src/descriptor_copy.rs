//! Raw byte copies through caller-owned descriptors. The named counterpart is
//! one regular file or one exact S3 key; no file-tree or recovery state is made.
pub(crate) mod controls;
pub(crate) mod fd;
mod file;
mod parallel;
mod report;
pub(crate) use controls::validate_controls;
use controls::Controls;

use crate::cli::{Args, Location};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::{
    atomic::{AtomicBool, Ordering::Relaxed},
    Arc,
};

const CHUNK: usize = 4 * 1024 * 1024;
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub(crate) struct Settings {
    request_size: usize,
    algorithm: crate::hashing::HashAlgorithm,
    verify: bool,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            request_size: CHUNK,
            algorithm: Default::default(),
            verify: false,
        }
    }
}

impl Settings {
    fn hash(self, data: &[u8]) -> [u8; 32] {
        if self.verify {
            self.algorithm.hash(data)
        } else {
            [0; 32]
        }
    }
    fn matches(self, data: &[u8], hash: [u8; 32]) -> bool {
        !self.verify || self.algorithm.hash(data) == hash
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Plan {
    pub source: Option<fd::Source>,
    pub as_fd: Option<i32>,
    pub commit_fd: Option<i32>,
    pub location: Option<Location>,
    pub key: Option<String>,
    pub follow: bool,
    pub root: Option<Vec<u8>>,
    pub placement: StreamPlacement,
}

/// The destination operand remains separate from the source basename so that
/// existence conditions apply to the container for --into-* placement.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct StreamPlacement {
    pub name: Option<Vec<u8>>,
    pub existence: crate::cli::Existence,
}

// Carried by the trailing DescriptorCopy request, behind the exact-build
// handshake. Only unrestricted control sessions may use this protocol;
// it never interprets grants or existing recovery records.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) enum Operation {
    Open {
        path: Vec<u8>,
        write: bool,
        follow: bool,
        root: Option<Vec<u8>>,
        placement: StreamPlacement,
        settings: Settings,
    },
    Finish {
        size: u64,
    },
    /// Validate a dry run without opening payload files or creating directories.
    Inspect {
        only_new: bool,
        only_existing: bool,
        path: Vec<u8>,
        write: bool,
        follow: bool,
        root: Option<Vec<u8>>,
        placement: StreamPlacement,
    },
}
pub(crate) use file::{resolve_source, FileWorker, Session};

pub(crate) fn run(mut args: Args) -> Result<i32> {
    let report = report::Report::start(&args)?;
    let plan = args.descriptor_copy.take().unwrap();
    let controls = Arc::new(Controls::new(&args, report));
    if let Some(options) = args.s3.take() {
        let ticker = controls.progress.spawn_ticker();
        let result = crate::s3::stream::run(
            options,
            plan.key.unwrap(),
            plan.source,
            plan.as_fd,
            plan.commit_fd,
            plan.placement,
            &controls,
        );
        controls.progress.stop();
        if let Some(ticker) = ticker {
            let _ = ticker.join();
        }
        controls.finish(result.as_ref().err());
        return result;
    }
    let ticker = controls.progress.spawn_ticker();
    let cancelled = Arc::new(AtomicBool::new(false));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let result = runtime.block_on(async {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = parallel::run(args, plan, controls.clone(), cancelled.clone()) => result,
            result = tokio::signal::ctrl_c() => { result?; Err(anyhow::anyhow!("descriptor copy cancelled")) },
            _ = term.recv() => Err(anyhow::anyhow!("descriptor copy cancelled")),
        }
    });
    cancelled.store(true, Relaxed);
    controls.progress.stop();
    if let Some(ticker) = ticker {
        let _ = ticker.join();
    }
    controls.finish(result.as_ref().err());
    // A caller-owned quiet pipe cannot be interrupted by changing its shared
    // flags. This CLI entry point exits after endpoint cleanup.
    runtime.shutdown_background();
    result.map(|()| 0)
}

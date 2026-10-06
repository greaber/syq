//! Raw byte copies through caller-owned descriptors. The named counterpart is
//! one regular file or one exact S3 key; no file-tree or recovery state is made.
pub(crate) mod check;
pub(crate) mod controls;
pub(crate) mod fd;
mod file;
pub(crate) mod metadata;
pub(crate) mod parallel;
pub(crate) mod report;
pub(crate) mod session;
pub(crate) use controls::validate_controls;
use controls::Controls;

use crate::cli::{Args, Location};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::{
    atomic::{AtomicBool, Ordering::Relaxed},
    Arc,
};

// Active payloads and idle reusable buffers each have a session-wide bound.
const BUFFER_BYTES: usize = 128 << 20;
const GRANULE: usize = 1024;
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
        entry: u64,
        dry_run: bool,
        only_new: bool,
        only_existing: bool,
        path: Vec<u8>,
        write: bool,
        follow: bool,
        root: Option<Vec<u8>>,
        placement: StreamPlacement,
        settings: Settings,
        metadata: metadata::Policy,
        source_meta: Option<crate::proto::Meta>,
    },
    Finish {
        entry: u64,
        size: u64,
    },
    Abort {
        entry: u64,
    },
    // Append: keep the existing Open encoding unchanged.
    OpenWithDirectoryAccess {
        entry: u64,
        dry_run: bool,
        only_new: bool,
        only_existing: bool,
        path: Vec<u8>,
        write: bool,
        follow: bool,
        root: Option<Vec<u8>>,
        placement: StreamPlacement,
        settings: Settings,
        metadata: metadata::Policy,
        source_meta: Option<crate::proto::Meta>,
    },
}
impl Operation {
    fn with_directory_access(self, enabled: bool) -> Self {
        if !enabled {
            return self;
        }
        match self {
            Self::Open {
                entry,
                dry_run,
                only_new,
                only_existing,
                path,
                write,
                follow,
                root,
                placement,
                settings,
                metadata,
                source_meta,
            } => Self::OpenWithDirectoryAccess {
                entry,
                dry_run,
                only_new,
                only_existing,
                path,
                write,
                follow,
                root,
                placement,
                settings,
                metadata,
                source_meta,
            },
            other => other,
        }
    }
}
pub(crate) use file::{resolve_source, FileWorker, Session};

pub(crate) fn run(mut args: Args) -> Result<i32> {
    let report = report::Report::start(&args)?;
    let plan = args.descriptor_copy.take().unwrap();
    let controls = Arc::new(Controls::new(&args, report));
    if args.s3.is_some() {
        let ticker = controls.progress.spawn_ticker();
        let result = crate::s3::stream::run(
            &args,
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
        let mut signals = crate::process::signals::interrupt_and_terminate()?;
        let (sigint, term) = &mut *signals;
        tokio::select! {
            result = parallel::run(args, plan, controls.clone(), cancelled.clone()) => result,
            _ = sigint.recv() => { Err(anyhow::anyhow!("descriptor copy cancelled")) },
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

#[cfg(test)]
mod wire_tests {
    use super::*;

    #[test]
    fn existing_descriptor_open_wire_bytes_remain_unchanged() {
        // Captured with the unchanged Open, Settings, StreamPlacement and
        // Policy definitions at 75fdc4c8, before OpenWithDirectoryAccess.
        const BEFORE: &[u8] = &[
            0, 130, 1, 1, 0, 1, 8, 100, 115, 116, 47, 102, 105, 108, 101, 1, 1, 1, 4, 114, 111,
            111, 116, 1, 4, 102, 105, 108, 101, 2, 128, 128, 4, 1, 1, 3, 1, 1, 1, 0, 0, 0, 0,
        ];
        let operation: Operation = postcard::from_bytes(BEFORE).unwrap();
        assert!(matches!(&operation, Operation::Open {
            entry: 130, dry_run: true, only_new: false, only_existing: true,
            path, write: true, follow: true, root: Some(root),
            placement: StreamPlacement { name: Some(name), existence: crate::cli::Existence::Existing },
            settings: Settings { request_size: 65536, algorithm: crate::hashing::HashAlgorithm::Sha256, verify: true },
            metadata: metadata::Policy { preserve: 3, if_exists: Some(crate::cli::IfExists::Error), restore_named_mtime: true, skip_newer: false, specials: false, overrides: None },
            source_meta: None,
        } if path == b"dst/file" && root == b"root" && name == b"file"));
        assert_eq!(postcard::to_allocvec(&operation).unwrap(), BEFORE);
    }
}

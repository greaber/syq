use super::Route;
mod authorization;
mod directory_permissions;
mod fast;
mod pruning;
mod server_copy;
mod upload_hashes;

use super::{
    admission::parallel,
    checksum::Algorithm,
    client::{self, Metadata, Object, ObjectKind},
    local::{self, Destination, Source},
    state::State,
    Options,
};
use crate::{
    cli::{Args, Existence, Location, Placement, SourceSelection, WidenDirs},
    hashing::{Digest, HashAlgorithm},
    progress::Progress,
    rooted::{RelativePath, Root},
};
use anyhow::{bail, Context, Result};
use aws_sdk_s3::{
    primitives::ByteStream,
    types::{CompletedMultipartUpload, CompletedPart},
    Client,
};
use aws_smithy_types::byte_stream::Length;
use futures_util::{stream, StreamExt};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs::File,
    io::Read,
    os::unix::fs::{FileExt, MetadataExt},
    sync::{atomic::Ordering::Relaxed, Arc},
    time::Duration,
};
use tokio::{io::AsyncReadExt, sync::Mutex};

type DirectoryMetadata = Arc<Directories>;
/// A marker's path, metadata, the mode of a directory it found, and its
/// mapping overrides.
type MarkerMetadata = (String, Metadata, Option<u32>, crate::mapping::Metadata);

/// The directories of one download.
struct Directories {
    /// Marker metadata, applied once the descendants are written.
    metadata: Mutex<Vec<MarkerMetadata>>,
    /// Planned directory markers. A marker's metadata reaches its directory
    /// only at the end, so whichever job creates that directory creates it
    /// private until then.
    markers: HashSet<Vec<u8>>,
    /// Marker directories this download created, recorded before creating
    /// them so a marker job never mistakes one for an existing directory.
    created: std::sync::Mutex<HashSet<Vec<u8>>>,
}

impl Directories {
    fn new(plan: &[Download]) -> Result<Self> {
        let mut markers = HashSet::new();
        for job in plan.iter().filter(|job| job.kind == ObjectKind::Dir) {
            if !job.path.is_empty() {
                markers.insert(directory_key(&RelativePath::new(job.path.as_bytes())?));
            }
        }
        Ok(Self {
            metadata: Mutex::new(Vec::new()),
            markers,
            created: Default::default(),
        })
    }

    /// The creation mode for a missing directory at `path`.
    fn creation_mode(&self, path: &[u8]) -> u32 {
        if !self.markers.contains(path) {
            return 0o777;
        }
        self.created.lock().unwrap().insert(path.to_vec());
        0o700
    }

    fn created(&self, path: &[u8]) -> bool {
        self.created.lock().unwrap().contains(path)
    }

    fn create_missing_parents(&self, root: &Root, path: &RelativePath) -> Result<()> {
        root.create_missing_parents_with(path, &mut |parent| self.creation_mode(parent))
    }
}

/// A directory's path beneath the destination root, in the form parent
/// creation reports it.
fn directory_key(path: &RelativePath) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    path.to_path_buf().as_os_str().as_bytes().to_vec()
}

pub(super) struct Engine {
    args: Arc<Args>,
    options: Options,
    client: Client,
    progress: Arc<Progress>,
    pace: Mutex<tokio::time::Instant>,
    upload_keys: OnceLock<HashMap<String, u64>>,
    copy_checksum_unsupported: std::sync::atomic::AtomicBool,
    copy_tagging_unsupported: std::sync::atomic::AtomicBool,
    tuning: super::tuning::Tuning,
    cancelled: Arc<std::sync::atomic::AtomicBool>,
    cancel_wake: tokio::sync::Notify,
    uploads: Arc<super::upload_http::Cancellation>,
    authorization: Option<Arc<super::authorization::Authorization>>,
    /// The destination rejected an upload without a checksum; send Content-MD5.
    content_md5: std::sync::atomic::AtomicBool,
    /// What new downloaded files' directories let them have.
    file_permissions: std::sync::Mutex<local::CreationPermissions>,
    outage: Arc<super::outage::Outage>,
}
impl Drop for Engine {
    fn drop(&mut self) {
        // Fatal errors can drop the scheduler before its usual drain finishes.
        self.uploads.cancel();
    }
}
#[derive(Clone)]
struct Download {
    expression_path: String,
    expression_destination_path: String,
    kind: ObjectKind,
    key: String,
    path: String,
    size: u64,
    mapping: Option<Box<DownloadMapping>>,
    copy_source: Option<Box<(Object, aws_sdk_s3::operation::head_object::HeadObjectOutput)>>,
    source_object: Option<Box<Object>>,
}
// Most mappings carry paths only. Allocate overrides only when requested,
// rather than reserving their full size in every planned download.
#[derive(Clone)]
struct DownloadMapping {
    expected_hash: Option<Digest>,
    metadata: Option<crate::mapping::Metadata>,
}
impl Download {
    fn expected_hash(&self) -> Option<&Digest> {
        self.mapping.as_ref().and_then(|m| m.expected_hash.as_ref())
    }
    fn metadata(&self) -> Option<crate::mapping::Metadata> {
        self.mapping.as_ref().and_then(|m| m.metadata)
    }
}
struct DownloadPlan {
    jobs: Vec<Download>,
    prune: super::prune::Plan,
    // Aligned with jobs when requested; empty otherwise, so ordinary copies
    // do not retain an extra timestamp per object.
    service_times: Vec<Option<(i64, u32)>>,
}
#[derive(Clone, Serialize, Deserialize)]
struct UploadState {
    schema: u32,
    digest: String,
    part_size: u64,
    upload_id: String,
    metadata: Metadata,
    #[serde(default, skip_serializing_if = "Algorithm::is_sha256")]
    algorithm: Algorithm,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    completed: BTreeMap<i32, UploadedPart>,
}
#[derive(Clone, Serialize, Deserialize)]
struct UploadedPart {
    etag: String,
    // Uploads without request checksums identify parts by ETag alone.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    checksum: String,
    length: u64,
}
struct Acknowledged {
    parts: BTreeMap<i32, UploadedPart>,
    saved: tokio::time::Instant,
    dirty: bool,
}
impl UploadState {
    fn acknowledged_part(&self, number: i32, etag: &str, checksum: &str, length: u64) -> bool {
        self.completed
            .get(&number)
            .is_some_and(|p| p.etag == etag && p.checksum == checksum && p.length == length)
    }
}
enum UploadPreparation {
    Skipped,
    Preview(u64),
    Ready(Box<PreparedUpload>),
}
struct PreparedUpload {
    source: Source,
    size: u64,
    part_size: u64,
    algorithm: Algorithm,
    checksums: Vec<String>,
    small: Option<bytes::Bytes>,
    metadata: Metadata,
    must_be_new: bool,
    multipart: Option<PreparedMultipart>,
    metadata_update: Option<super::metadata_copy::Prepared>,
}
struct PreparedMultipart {
    recorded: bool,
    upload: UploadState,
    uploaded: HashMap<i32, (String, Option<String>, Option<u64>)>,
}
#[derive(Serialize, Deserialize)]
struct DownloadState {
    schema: u32,
    etag: String,
    version: Option<String>,
    size: u64,
    part_size: u64,
    partial: String,
    dev: u64,
    ino: u64,
    parts: BTreeMap<u64, String>,
    #[serde(default)]
    hash_algorithm: HashAlgorithm,
}

impl Engine {
    fn expression_destination_path<'a>(&self, path: &'a str) -> &'a [u8] {
        let path = path.trim_end_matches('/');
        let root = self
            .args
            .locations
            .last()
            .map(|l| l.path.as_slice())
            .unwrap_or(b"");
        let root = std::str::from_utf8(root).unwrap_or("").trim_matches('/');
        let relative = path.strip_prefix(root).and_then(|s| s.strip_prefix('/'));
        crate::expression::source_path(
            path.as_bytes(),
            relative
                .unwrap_or_else(|| if path == root { "" } else { path })
                .as_bytes(),
        )
    }
    pub async fn new(args: Arc<Args>, progress: Arc<Progress>) -> Result<Arc<Self>> {
        let setup = super::diagnostics::start();
        let mut options = args.s3.clone().unwrap();
        options.endpoint = options
            .endpoint
            .or_else(|| std::env::var("AWS_ENDPOINT_URL_S3").ok())
            .or_else(|| std::env::var("AWS_ENDPOINT_URL").ok());
        let control = Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX));
        let uploads = Arc::new(super::upload_http::Cancellation::default());
        let authorization = super::authorization::connect(&args, &options).await?;
        let outage = Arc::new(super::outage::Outage::default());
        let (client, note) = client::connect_authorized(
            &mut options,
            control.clone(),
            uploads.clone(),
            authorization.clone(),
            Some(outage.clone()),
        )
        .await?;
        if let Some(note) = note.filter(|_| args.verbose > 0) {
            progress.println(&note);
        }
        super::diagnostics::elapsed(setup, "client_setup", 0);
        let content_md5 = super::checksum::plain_http(options.endpoint.as_deref());
        Ok(Arc::new(Self {
            tuning: super::tuning::Tuning::new(&options, &args, control),
            cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            cancel_wake: tokio::sync::Notify::new(),
            uploads,
            authorization,
            args,
            options,
            client,
            progress,
            pace: Mutex::new(tokio::time::Instant::now()),
            upload_keys: OnceLock::new(),
            copy_checksum_unsupported: Default::default(),
            content_md5: content_md5.into(),
            file_permissions: Default::default(),
            copy_tagging_unsupported: Default::default(),
            outage,
        }))
    }
    pub async fn run(self: Arc<Self>) -> Result<()> {
        let work = self.clone().copy();
        let mut signals = crate::process::signals::interrupt_and_terminate()?;
        let (sigint, terminate) = &mut *signals;
        tokio::pin!(work);
        let outage = self.outage.clone();
        let interrupted = tokio::select! {
            result = &mut work => return result.and_then(|()| {
                if self.progress.deletions_blocked.load(Relaxed) > 0 {
                    Err(super::prune::Limit.into())
                } else { Ok(()) }
            }),
            _ = sigint.recv() => Some("interrupted"),
            _ = terminate.recv() => Some("terminated"),
            _ = outage.stopped() => None,
        };
        self.cancelled.store(true, Relaxed);
        self.cancel_wake.notify_waiters();
        self.uploads.cancel();
        // Drain started requests, including synchronous file bodies, before exit.
        let _ = work.await;
        match interrupted {
            Some(interrupted) => bail!("S3 copy {interrupted}; rerun the command to continue"),
            None => bail!("{}", super::outage::Outage::message()),
        }
    }
    /// Report a request that syq retried itself and has now given up on.
    fn report_final<E: aws_sdk_s3::error::ProvideErrorMetadata>(
        &self,
        error: &aws_sdk_s3::error::SdkError<
            E,
            aws_smithy_runtime_api::client::orchestrator::HttpResponse,
        >,
    ) {
        self.outage.failed(retryable(error));
    }
    fn check_cancelled(&self) -> Result<()> {
        anyhow::ensure!(!self.cancelled.load(Relaxed), "S3 copy cancelled");
        Ok(())
    }

    async fn copy(self: Arc<Self>) -> Result<()> {
        if self.options.route.is_server_copy() {
            return self.server_copy().await;
        }
        if self.options.route == Route::Upload {
            let scanning = super::diagnostics::start();
            let args = self.args.clone();
            let local::UploadPlan {
                sources: plan,
                mut prune,
                ignored,
                excluded,
            } = tokio::task::spawn_blocking(move || local::upload_plan(&args)).await??;
            self.progress.paths_ignored.fetch_add(ignored, Relaxed);
            self.progress.files_excluded.fetch_add(excluded, Relaxed);
            super::diagnostics::elapsed(scanning, "source_plan", plan.len() as u64);
            if let Some(results) = self.progress.results_writer() {
                results.mapping_metadata(
                    plan.iter()
                        .filter_map(|s| s.metadata.map(|m| (s.key.as_bytes().to_vec(), m))),
                );
            }
            self.check_upload_placement(plan.first().map(|s| s.kind() != ObjectKind::Dir))
                .await?;
            self.discover_destination(plan.iter().map(|s| s.key.as_str()).collect())
                .await?;
            let workers = self.object_workers(plan.iter().map(|s| s.meta.len))?;
            self.progress.files_total.store(plan.len() as u64, Relaxed);
            self.progress.bytes_total.store(
                plan.iter()
                    .filter(|s| s.kind() == ObjectKind::File)
                    .map(|s| s.meta.len)
                    .sum(),
                Relaxed,
            );
            self.progress.scan_done.store(true, Relaxed);
            if self.authorization.is_some() {
                let prepared = Arc::new(Mutex::new(Vec::with_capacity(plan.len())));
                parallel(plan, workers, |source| {
                    let engine = self.clone();
                    let prepared = prepared.clone();
                    async move {
                        let key = source.key.clone();
                        let label = source.label.clone();
                        let kind = source.kind();
                        let expected = source.expected_hash.clone();
                        match engine.prepare_upload(source).await {
                            Ok(work) => prepared
                                .lock()
                                .await
                                .push((key, label, kind, expected, work)),
                            Err(error) => {
                                engine.settle(&label, &key, kind, &Err(error), expected.as_ref())
                            }
                        }
                        Ok(None)
                    }
                })
                .await?;
                let authorized = async {
                    self.prepare_pruning(&prune).await?;
                    self.finish_authorization().await?;
                    if self.args.prune_before {
                        self.prune(std::mem::take(&mut prune), None).await?;
                    }
                    Ok::<_, anyhow::Error>(())
                }
                .await;
                let prepared = std::mem::take(&mut *prepared.lock().await);
                if let Err(error) = authorized {
                    for (_, _, _, _, work) in &prepared {
                        if let UploadPreparation::Ready(work) = work {
                            self.abort_unrecorded_preparation(work).await;
                        }
                    }
                    return Err(error);
                }
                let workers =
                    self.object_workers(prepared.iter().map(|(_, _, _, _, work)| match work {
                        UploadPreparation::Ready(work) => work.size,
                        UploadPreparation::Preview(n) => *n,
                        UploadPreparation::Skipped => 0,
                    }))?;
                parallel(prepared, workers, |(key, label, kind, expected, work)| {
                    let engine = self.clone();
                    async move {
                        // Keep admitting jobs after cancellation so each one can
                        // abort its unrecorded upload, but report nothing new.
                        if engine.check_cancelled().is_err() {
                            if let UploadPreparation::Ready(work) = &work {
                                engine.abort_unrecorded_preparation(work).await;
                            }
                            return Ok(None);
                        }
                        let result = engine.execute_upload(work).await;
                        engine.settle(&label, &key, kind, &result, expected.as_ref());
                        Ok(result.ok().flatten())
                    }
                })
                .await?;
            } else {
                if self.args.prune_before {
                    self.prune(std::mem::take(&mut prune), None).await?;
                }
                parallel(plan, workers, |source| {
                    let engine = self.clone();
                    async move {
                        let key = source.key.clone();
                        let label = source.label.clone();
                        let kind = source.kind();
                        engine.check_cancelled()?;
                        let expected = source.expected_hash.as_ref().cloned();
                        let result = engine.upload(source).await;
                        engine.settle(&label, &key, kind, &result, expected.as_ref());
                        Ok(result.ok().flatten())
                    }
                })
                .await?;
            }
            self.progress.finish_transfer();
            if !self.args.prune_before {
                self.prune(prune, None).await?;
            }
        } else {
            // Dry runs never change permissions.
            let widen = if self.args.dry_run {
                WidenDirs::None
            } else {
                self.args.widen_dirs
            };
            // Under `all`, the owned directories on the way to the
            // destination first get the owner access reaching it and creating
            // its missing parents needs, until the copy ends.
            let mut path_access = crate::fsops::TemporaryDirectorySearchAccess::default();
            if widen == WidenDirs::All {
                crate::fsops::prepare_destination_path(
                    &self.args.locations.last().unwrap().path,
                    Destination::symlink_policy(&self.args),
                    !self.args.existing,
                    &mut path_access,
                )?;
            }
            let destination = Arc::new(Destination::open(&self.args)?);
            let DownloadPlan {
                jobs: mut plan,
                mut prune,
                service_times,
            } = self.download_plan(&destination.prefix).await?;
            self.authorize_downloads(&mut plan).await?;
            self.finish_authorization().await?;
            let workers = self.object_workers(plan.iter().map(|s| s.size))?;
            self.progress.files_total.store(plan.len() as u64, Relaxed);
            self.progress
                .bytes_total
                .store(plan.iter().map(|s| s.size).sum(), Relaxed);
            self.progress.scan_done.store(true, Relaxed);
            let directories = Arc::new(Directories::new(&plan)?);
            // --if-exists=keep widens like any other policy; it only leaves
            // existing directory metadata alone. `rsync` widens the
            // destination itself only when a contents source fills it.
            let mut directory_access = directory_permissions::TemporaryAccess::new(
                widen,
                self.args.native_mapping.is_none()
                    && self.args.locations[..self.args.locations.len() - 1]
                        .iter()
                        .any(Location::copies_contents),
            );
            let mut copies_finished = false;
            let transferred = async {
                if self.args.prune_before {
                    directory_access.prepare(&destination, &plan)?;
                    self.prune(
                        std::mem::take(&mut prune),
                        Some((&destination, &mut directory_access)),
                    )
                    .await?;
                }
                let mut service_times = service_times.into_iter();
                parallel(plan, workers, |mut job| {
                    let service_time = service_times.next().flatten();
                    let engine = self.clone();
                    let dst = destination.clone();
                    let dirs = directories.clone();
                    // Admission invokes this closure in plan order. Preparing
                    // here keeps queued downloads' directories untouched and
                    // needs no lock shared by the running file transfers.
                    let prepared = directory_access.prepare(&dst, std::slice::from_ref(&job));
                    async move {
                        engine.check_cancelled()?;
                        let result = match prepared {
                            Ok(()) => engine.download(&mut job, &dst, dirs, service_time).await,
                            Err(error) => Err(error),
                        }
                        .map_err(|error| {
                            if engine.args.widen_dirs == WidenDirs::None
                                && error.chain().any(|cause| {
                                    cause.downcast_ref::<std::io::Error>().is_some_and(|e| {
                                        e.kind() == std::io::ErrorKind::PermissionDenied
                                    })
                                })
                            {
                                if let Ok(path) = RelativePath::new(job.path.as_bytes()) {
                                    if let Some(hint) = crate::fsops::directory_permission_hint(
                                        &dst.root, &path, 0o300,
                                    ) {
                                        return error.context(format!(
                                            "{hint}; {}",
                                            crate::transfer::DIRECTORY_ACCESS_HINT
                                        ));
                                    }
                                }
                            }
                            error
                        });
                        engine.settle(
                            job.key.as_bytes(),
                            &job.path,
                            job.kind,
                            &result,
                            job.expected_hash(),
                        );
                        Ok(result.ok().flatten())
                    }
                })
                .await?;
                copies_finished = true;
                self.progress.finish_transfer();
                #[cfg(debug_assertions)]
                crate::fsops::test_race_barrier(
                    "SYQ_TEST_FINALIZATION_READY_FILE",
                    "SYQ_TEST_FINALIZATION_CONTINUE_FILE",
                    "copy finalization",
                )?;
                if !self.args.prune_before {
                    self.prune(prune, Some((&destination, &mut directory_access)))
                        .await?;
                }
                Ok::<_, anyhow::Error>(())
            }
            .await;
            let finished = self
                .finish_directories(
                    &destination,
                    &directories,
                    directory_access.into_restorations(),
                    !copies_finished,
                )
                .await;
            // The destination's ancestors are restored last.
            let restored = path_access.restore();
            finished?;
            transferred?;
            restored?;
        }
        Ok(())
    }

    async fn finish_directories(
        &self,
        destination: &Destination,
        directories: &DirectoryMetadata,
        mut widened: BTreeMap<Vec<u8>, crate::proto::DirectoryMode>,
        aborted: bool,
    ) -> Result<()> {
        if self.args.dry_run {
            return Ok(());
        }
        let mut entries: BTreeMap<_, _> = if aborted {
            BTreeMap::new()
        } else {
            directories
                .metadata
                .lock()
                .await
                .iter()
                .map(|(path, meta, mode, explicit)| {
                    let path = directory_key(&RelativePath::new(path.as_bytes())?);
                    Ok((path, Some((meta.clone(), *mode, *explicit))))
                })
                .collect::<Result<_>>()?
        };
        if !aborted {
            for path in directories.created.lock().unwrap().iter() {
                entries.entry(path.clone()).or_insert(None);
            }
        }
        for path in widened.keys() {
            entries.entry(path.clone()).or_insert(None);
        }
        let mut entries: Vec<_> = entries.into_iter().collect();
        entries.sort_by_key(|(path, _)| {
            std::cmp::Reverse(
                path.iter().filter(|&&c| c == b'/').count() + usize::from(!path.is_empty()),
            )
        });
        let mut first_error = None;
        let mut creation = local::CreationPermissions::default();
        for (path, metadata) in entries {
            let relative = RelativePath::new(&path)?;
            let label = String::from_utf8_lossy(&path).into_owned();
            let saved = widened.remove(&path);
            // Require the inode we widened before applying any final metadata.
            let result = (|| {
                if let Some(saved) = saved {
                    let now = destination.root.metadata(&relative)?;
                    anyhow::ensure!(
                        (now.dev, now.ino) == (saved.dev, saved.ino),
                        "directory {label} changed before restoring permissions"
                    );
                }
                if let Some((meta, mode, explicit)) = &metadata {
                    local::apply_metadata(
                        &destination.root,
                        &relative,
                        meta,
                        &self.args,
                        *mode,
                        *explicit,
                        mode.is_none(),
                        &mut creation,
                    )?;
                } else if saved.is_none() {
                    let directory = destination.root.open_directory(&relative)?;
                    let current = directory.metadata()?.mode();
                    crate::fsops::set_mode_handle(
                        &directory,
                        crate::fsops::created_directory_mode(&directory, 0o777, current)?,
                    )?;
                }
                Ok::<_, anyhow::Error>(())
            })();
            let explicit_mode_applied = result.is_ok()
                && metadata
                    .as_ref()
                    .is_some_and(|(_, _, explicit)| self.args.perms || explicit.mode.is_some());
            if !explicit_mode_applied {
                if let Some(saved) = saved {
                    if let Err(error) = crate::fsops::restore_directory_mode(
                        &destination.root,
                        &relative,
                        saved,
                        std::path::Path::new(
                            <std::ffi::OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(&path),
                        ),
                    ) {
                        first_error.get_or_insert(error);
                    }
                }
            }
            if let Err(error) = result {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }
    fn settle(
        &self,
        src: &[u8],
        dst: &str,
        kind: ObjectKind,
        result: &Result<Option<u64>>,
        expected: Option<&Digest>,
    ) {
        let action = match kind {
            ObjectKind::Dir => "create_directory",
            ObjectKind::Symlink => "create_symlink",
            ObjectKind::File => "transfer_file",
        };
        match result {
            Ok(Some(bytes)) => {
                if kind == ObjectKind::File {
                    self.progress.files_done.fetch_add(1, Relaxed);
                } else if self.options.route != Route::Download {
                    if kind == ObjectKind::Dir {
                        self.progress.directories_created.fetch_add(1, Relaxed);
                    } else {
                        self.progress.symlinks_created.fetch_add(1, Relaxed);
                    }
                }
                if self.args.verbose > 0 {
                    self.progress.println(&format!(
                        "{} {dst}",
                        if self.args.dry_run {
                            "would copy"
                        } else {
                            "copied"
                        }
                    ));
                }
                if let Some(writer) = self.progress.results_writer() {
                    if self.args.dry_run {
                        writer.emit_trace(&crate::results::TraceRecord {
                            action,
                            src: Some(src),
                            dst: dst.as_bytes(),
                            kind: kind.as_str(),
                            bytes: Some(*bytes),
                            reason: "content_differs",
                        });
                    } else {
                        writer.emit_operation_expected(
                            &crate::results::OperationRecord {
                                action,
                                src: Some(src),
                                dst: dst.as_bytes(),
                                kind: kind.as_str(),
                                disposition: "succeeded",
                                bytes: Some(*bytes),
                                attempts: None,
                                retryable: None,
                                class: None,
                                os_kind: None,
                                message: None,
                            },
                            expected,
                        );
                    }
                }
            }
            Ok(None) => {
                if kind == ObjectKind::File {
                    self.progress.files_unchanged.fetch_add(1, Relaxed);
                }
            }
            // Objects cut short by cancellation share the run's one message
            // and are copied again by the rerun it asks for.
            Err(_) if self.cancelled.load(Relaxed) => {}
            Err(error) => {
                let message = format!("S3 {dst}: {error:#}");
                self.progress.error(&message);
                if let Some(writer) = self.progress.results_writer() {
                    writer.emit_operation_expected(
                        &crate::results::OperationRecord {
                            action,
                            src: Some(src),
                            dst: dst.as_bytes(),
                            kind: kind.as_str(),
                            disposition: "failed",
                            bytes: None,
                            attempts: None,
                            retryable: None,
                            class: Some("transport"),
                            os_kind: None,
                            message: Some(&message),
                        },
                        expected,
                    );
                }
            }
        }
    }
    async fn pace(&self, n: u64) -> Result<()> {
        self.check_cancelled()?;
        if self.args.bwlimit_bytes == 0 {
            return Ok(());
        }
        let mut next = self.pace.lock().await;
        let now = tokio::time::Instant::now();
        let start = (*next).max(now);
        *next = start + Duration::from_secs_f64(n as f64 / self.args.bwlimit_bytes as f64);
        drop(next);
        let cancelled = self.cancel_wake.notified();
        tokio::pin!(cancelled);
        // Register before checking the flag so a concurrent signal cannot be lost.
        cancelled.as_mut().enable();
        self.check_cancelled()?;
        tokio::select! {
            _ = &mut cancelled => {},
            _ = tokio::time::sleep_until(start) => {},
        }
        self.check_cancelled()
    }
    fn identity(&self, key: &str, extra: &str) -> Vec<u8> {
        let mut hash = blake3::Hasher::new();
        for header in &self.options.headers {
            hash.update(header.0.as_bytes());
            hash.update(&[0]);
            hash.update(header.1.as_bytes());
            hash.update(&[0]);
        }
        // Object-writing headers change the uploaded object's settings. Without
        // them, keep earlier identities so existing recovery records still match.
        // Header names and values cannot contain a newline, so the marker cannot
        // be confused with an every-request header.
        if !self.options.write_headers.is_empty() {
            hash.update(b"\nwrite\n");
            for header in &self.options.write_headers {
                hash.update(header.0.as_bytes());
                hash.update(&[0]);
                hash.update(header.1.as_bytes());
                hash.update(&[0]);
            }
        }
        format!(
            "syq.s3.v1\n{}\n{}\n{}\n{}\n{}\n{extra}",
            self.options.endpoint.as_deref().unwrap_or("AWS"),
            self.client.config().region().map_or("", |r| r.as_ref()),
            self.options.bucket,
            key,
            hash.finalize()
        )
        .into_bytes()
    }
    async fn discover_destination(&self, keys: HashSet<&str>) -> Result<()> {
        if keys.len() > 1 && !self.args.existing && !self.args.ignore_existing {
            let target = local::key_path(&self.args.locations.last().unwrap().path)?;
            let prefix = if target.is_empty() {
                String::new()
            } else {
                format!("{target}/")
            };
            let listing = if self.args.delete {
                // Pruning needs every destination key, including keys absent
                // from the upload plan. Only this complete cache is reusable
                // by the deletion planner.
                client::list(
                    &self.client,
                    &self.options.bucket,
                    &prefix,
                    None,
                    &mut HashSet::new(),
                    self.options.concurrency,
                )
                .await
                .map(|listing| Some(listing.into_objects().into_iter().collect()))
            } else {
                client::upload_listing(&self.client, &self.options.bucket, &prefix, &keys).await
            };
            match listing {
                Ok(Some(keys)) => {
                    let _ = self.upload_keys.set(keys);
                }
                Ok(None) => {}
                Err(error)
                    if error
                        .downcast_ref::<client::RequestFailure>()
                        .is_some_and(|failure| failure.region_mismatch()) =>
                {
                    return Err(error);
                }
                Err(error) if self.args.delete => {
                    self.progress
                        .error(&format!("list S3 destination: {error:#}"));
                }
                Err(error) => return Err(error),
            }
        }

        Ok(())
    }
    async fn check_upload_placement(&self, single_object: Option<bool>) -> Result<()> {
        if self.args.target_existence == Existence::Any {
            return Ok(());
        }
        let target = local::key_path(&self.args.locations.last().unwrap().path)?;
        let exact = if target.is_empty() {
            false
        } else {
            client::head(&self.client, &self.options.bucket, &target)
                .await?
                .is_some()
        };
        let prefix = if target.is_empty() {
            String::new()
        } else {
            format!("{target}/")
        };
        let needs_prefix = self.args.target_existence == Existence::Existing
            && (self.args.placement != Placement::As || single_object == Some(false));
        let present = (!needs_prefix && exact)
            || client::prefix_exists(&self.client, &self.options.bucket, &prefix).await?;
        if (self.args.target_existence == Existence::New && present)
            || (self.args.target_existence == Existence::Existing && !present)
        {
            bail!("S3 destination existence condition failed");
        }
        if self.args.placement == Placement::As && single_object == Some(true) && present && !exact
        {
            bail!("S3 destination is a prefix, not an object");
        }
        Ok(())
    }
    fn upload_contents_match(&self, source: &Source, size: u64, object: &Object) -> bool {
        object.kind() == source.kind()
            && object.size == size
            && (source.kind() == ObjectKind::Dir
                || object.metadata.as_ref().is_some_and(|m| {
                    (m.mtime, m.nsec) == (source.meta.mtime, source.meta.mtime_nsec)
                }))
    }

    fn upload_requested_metadata_matches(&self, source: &Source, object: &Object) -> bool {
        let explicit = source.metadata.unwrap_or_default();
        let desired = source.metadata(None);
        let flags = self.args.matching_meta_flags() | explicit.apply_flags();
        if flags == 0 {
            return true;
        }
        object.metadata.as_ref().is_some_and(|m| {
            (flags & crate::proto::flags::TIMES == 0
                || (m.mtime, m.nsec) == (desired.mtime, desired.nsec))
                && (flags & crate::proto::flags::MODE == 0 || m.mode == desired.mode)
                && (flags & crate::proto::flags::OWNER == 0 || m.uid == desired.uid)
                && (flags & crate::proto::flags::GROUP == 0 || m.gid == desired.gid)
        })
    }

    async fn prepare_accepted_upload(
        self: &Arc<Self>,
        source: Source,
        object: &Object,
    ) -> Result<UploadPreparation> {
        let size = object.size;
        if self.upload_requested_metadata_matches(&source, object) {
            self.progress.bytes_unchanged.fetch_add(size, Relaxed);
            return Ok(UploadPreparation::Skipped);
        }
        if self.args.dry_run {
            self.progress.add_bytes(size);
            return Ok(UploadPreparation::Preview(size));
        }
        let desired = source.metadata(None);
        let flags =
            self.args.matching_meta_flags() | source.metadata.map_or(0, |m| m.apply_flags());
        let _slot = self.tuning.requests.acquire().await;
        let head = client::head_output(&self.client, &self.options.bucket, &source.key, None)
            .await?
            .context("S3 destination disappeared before metadata update")?;
        anyhow::ensure!(
            head.e_tag() == Some(&object.etag),
            "S3 destination changed before metadata update"
        );
        let mut metadata = object.metadata.clone().unwrap_or(Metadata {
            kind: object.kind(),
            mode: if object.kind() == ObjectKind::Dir {
                0o777
            } else {
                0o666
            },
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
            mtime: object.mtime,
            nsec: 0,
            hash: None,
            hash_algorithm: HashAlgorithm::Blake3,
        });
        if flags & crate::proto::flags::TIMES != 0 {
            metadata.mtime = desired.mtime;
            metadata.nsec = desired.nsec;
        }
        if flags & crate::proto::flags::MODE != 0 {
            metadata.mode = desired.mode;
        }
        if flags & crate::proto::flags::OWNER != 0 {
            metadata.uid = desired.uid;
        }
        if flags & crate::proto::flags::GROUP != 0 {
            metadata.gid = desired.gid;
        }
        let mut fields = head.metadata().cloned().unwrap_or_default();
        fields.extend(metadata.encode());
        let update = super::metadata_copy::Prepared::prepare(
            &self.client,
            &self.options,
            &source.key,
            &head,
            fields,
            self.part_size(size),
            self.copy_request_limit(size),
        )
        .await?;
        drop(_slot);
        if let Err(error) = self.authorize_requests(update.requests()).await {
            update.abort(&self.client, &self.options.bucket).await;
            return Err(error);
        }
        Ok(UploadPreparation::Ready(Box::new(PreparedUpload {
            source,
            size,
            part_size: self.part_size(size),
            algorithm: Algorithm::for_upload(
                self.options.endpoint.as_deref(),
                self.authorization.is_some(),
            ),
            checksums: Vec::new(),
            small: None,
            metadata,
            must_be_new: false,
            multipart: None,
            metadata_update: Some(update),
        })))
    }

    async fn prepare_upload(self: &Arc<Self>, source: Source) -> Result<UploadPreparation> {
        let expected_hash = source.expected_hash.as_ref().filter(|_| !self.args.dry_run);
        let existing = if self
            .upload_keys
            .get()
            .is_some_and(|keys| !keys.contains_key(&source.key))
        {
            None
        } else {
            let object = client::head(&self.client, &self.options.bucket, &source.key).await?;
            object
        };
        if (self.args.ignore_existing && existing.is_some())
            || (self.args.existing && existing.is_none())
        {
            return Ok(UploadPreparation::Skipped);
        }
        if self.args.expressions.update.is_some()
            && !self.args.expressions.permits(
                &source.expression_file()?,
                source.expression_path(),
                &existing
                    .as_ref()
                    .map(Object::expression_file)
                    .unwrap_or_default(),
                self.expression_destination_path(&source.key),
            )?
        {
            return Ok(UploadPreparation::Skipped);
        }

        anyhow::ensure!(
            source.kind() == ObjectKind::Dir
                || existing.is_none()
                || self.args.if_exists != Some(crate::cli::IfExists::Error),
            "destination already exists: {} (--if-exists=error)",
            source.key
        );
        if self.args.update
            && source.kind() != ObjectKind::Dir
            && existing.as_ref().is_some_and(|o| {
                let time = o
                    .metadata
                    .as_ref()
                    .map_or((o.mtime, 0), |m| (m.mtime, m.nsec));
                time > (source.meta.mtime, source.meta.mtime_nsec)
            })
        {
            return Ok(UploadPreparation::Skipped);
        }
        let size = if source.kind() == ObjectKind::Dir {
            0
        } else {
            source.meta.len
        };
        let protected_existing = self.args.protects_existing_contents()
            && existing.is_some()
            && source.kind() != ObjectKind::Dir;
        anyhow::ensure!(
            !protected_existing
                || existing
                    .as_ref()
                    .is_some_and(|o| o.kind() == source.kind() && o.size == size),
            "destination contents differ: {} (--if-exists=error-if-different)",
            source.key
        );
        let requested_algorithm = expected_hash.map(|d| d.algorithm).or_else(|| {
            if self.args.transfer_integrity {
                Some(self.args.transfer_hash_type.unwrap_or_default())
            } else if self.args.checksum {
                Some(self.args.hash_algorithm)
            } else {
                None
            }
        });
        let can_compare_time = source.metadata.is_none_or(|m| m.mtime.is_none());
        if requested_algorithm.is_none()
            && can_compare_time
            && existing
                .as_ref()
                .is_some_and(|o| self.upload_contents_match(&source, size, o))
        {
            if source.kind() == ObjectKind::File {
                // Opening validates the pinned scan identity without reading the
                // body. Explicit content checks still take the hashing path.
                source.open()?;
            } else {
                source.bytes()?;
            }
            return self
                .prepare_accepted_upload(source, existing.as_ref().unwrap())
                .await;
        }
        let comparable = existing
            .as_ref()
            .filter(|o| o.kind() == source.kind() && o.size == size);
        let stored_hash = comparable.and_then(|o| self.stored_comparison_hash(o));
        let comparison_algorithm = (source.kind() != ObjectKind::Dir
            && comparable.is_some()
            && (self.args.checksum || protected_existing || stored_hash.is_some()))
        .then(|| stored_hash.map_or(self.args.hash_algorithm, |(algorithm, _)| algorithm));
        let part_size = self.part_size(size);
        if part_size > 5 * 1024 * 1024 * 1024 {
            bail!("file exceeds the S3 multipart size limit");
        }
        let algorithm = Algorithm::for_upload(
            self.options.endpoint.as_deref(),
            self.authorization.is_some(),
        );
        // Once the destination has required Content-MD5, compute it in the
        // hashing read rather than reading each file again to send it.
        let part_checksums = if algorithm == Algorithm::None && self.content_md5.load(Relaxed) {
            Algorithm::Md5
        } else {
            algorithm
        };
        let whole_algorithm = requested_algorithm.unwrap_or(HashAlgorithm::Blake3);
        let buffer_limit = if self.tuning.tigris() {
            8 << 20
        } else {
            1 << 20
        };
        let reservation = if self.authorization.is_none()
            && source.kind() == ObjectKind::File
            && size <= part_size
            && size <= buffer_limit
        {
            Some(
                self.tuning
                    .upload_buffers
                    .clone()
                    .acquire_many_owned(size.max(1) as u32)
                    .await?,
            )
        } else {
            None
        };
        self.check_cancelled()?;
        let source_clone = source.clone();
        let (hashes, small) = tokio::task::spawn_blocking(move || -> Result<_> {
            if source_clone.kind() != ObjectKind::File {
                let bytes = source_clone.bytes()?;
                return Ok((
                    upload_hashes::bytes(
                        &bytes,
                        part_checksums,
                        whole_algorithm,
                        comparison_algorithm,
                    ),
                    Some(bytes::Bytes::from(bytes)),
                ));
            }
            if let Some(reservation) = reservation {
                let mut file = source_clone.open()?;
                let buffer_trace = super::diagnostics::upload_buffer(size);
                let mut bytes = vec![0; size as usize];
                file.read_exact(&mut bytes)?;
                source_clone.check(&file)?;
                return Ok((
                    upload_hashes::bytes(
                        &bytes,
                        part_checksums,
                        whole_algorithm,
                        comparison_algorithm,
                    ),
                    Some(bytes::Bytes::from_owner(fast::UploadBuffer {
                        bytes,
                        _reservation: reservation,
                        _trace: buffer_trace,
                    })),
                ));
            }
            let hashes = upload_hashes::ranges(
                size,
                part_size,
                part_checksums,
                whole_algorithm,
                comparison_algorithm,
                |end| {
                    let file = source_clone.open()?;
                    let source = &source_clone;
                    Ok(move |buffer: &mut [u8], offset| {
                        file.read_exact_at(buffer, offset)?;
                        if offset + buffer.len() as u64 == end {
                            source.check(&file)?;
                        }
                        Ok(())
                    })
                },
            )?;
            if hashes.concurrent {
                // Parallel readers can finish at different times. Recheck the
                // selected pathname after all parts complete, as before.
                source_clone.check(&source_clone.open()?)?;
            }
            Ok((hashes, None))
        })
        .await??;
        let upload_hashes::Hashes {
            whole: whole_digest,
            comparison: comparison_digest,
            checksums,
            concurrent: _,
        } = hashes;
        if let Some(expected) = expected_hash {
            if !whole_digest.eq_ignore_ascii_case(&expected.value) {
                bail!("source does not match expected hash");
            }
        }
        let store_hash = source.kind() != ObjectKind::Dir || requested_algorithm.is_some();
        let mut metadata = source.metadata(store_hash.then_some(whole_digest));
        if store_hash {
            metadata.hash_algorithm = whole_algorithm;
        }
        let digest = upload_identity(algorithm, size, part_size, &checksums, &metadata);
        let mut same_contents = existing.as_ref().is_some_and(|o| {
            o.kind() == source.kind()
                && o.size == size
                && (source.kind() == ObjectKind::Dir
                    || (can_compare_time
                        && o.metadata.as_ref().is_some_and(|m| {
                            (m.mtime, m.nsec) == (source.meta.mtime, source.meta.mtime_nsec)
                        })))
        });
        if self.args.checksum || !same_contents {
            if let (Some(object), Some(algorithm), Some(source_hash)) =
                (comparable, comparison_algorithm, comparison_digest)
            {
                let destination_hash = match stored_hash {
                    Some((_, hash)) => hash.to_owned(),
                    None => self.remote_hash_as(object, algorithm).await?,
                };
                same_contents = source_hash.eq_ignore_ascii_case(&destination_hash);
            }
        }
        if same_contents && expected_hash.is_some() {
            same_contents = self
                .verify_expected_remote(existing.as_ref().unwrap(), expected_hash)
                .await
                .is_ok();
        }
        anyhow::ensure!(
            !protected_existing || same_contents,
            "destination contents differ: {} (--if-exists=error-if-different)",
            source.key
        );
        if same_contents {
            return self
                .prepare_accepted_upload(source, existing.as_ref().unwrap())
                .await;
        }
        if self.args.dry_run {
            self.progress.add_bytes(size);
            return Ok(UploadPreparation::Preview(size));
        }
        let must_be_new = self.args.ignore_existing
            || self.args.target_existence == Existence::New
            || (self.args.protects_existing_contents() && existing.is_none());
        let multipart = if size > part_size && small.is_none() {
            Some(
                self.prepare_multipart(&source, digest, part_size, &metadata, algorithm)
                    .await?,
            )
        } else {
            None
        };
        let prepared = PreparedUpload {
            source,
            size,
            part_size,
            algorithm,
            checksums,
            small,
            metadata,
            must_be_new,
            multipart,
            metadata_update: None,
        };
        if let Err(error) = self.authorize_upload(&prepared).await {
            self.abort_unrecorded_preparation(&prepared).await;
            return Err(error);
        }
        Ok(UploadPreparation::Ready(Box::new(prepared)))
    }

    async fn upload(self: &Arc<Self>, source: Source) -> Result<Option<u64>> {
        self.execute_upload(self.prepare_upload(source).await?)
            .await
    }

    async fn execute_upload(self: &Arc<Self>, prepared: UploadPreparation) -> Result<Option<u64>> {
        let prepared = match prepared {
            UploadPreparation::Skipped => return Ok(None),
            UploadPreparation::Preview(size) => return Ok(Some(size)),
            UploadPreparation::Ready(prepared) => *prepared,
        };
        if let Some(update) = &prepared.metadata_update {
            update
                .execute(
                    &self.client,
                    &self.options.bucket,
                    self.part_workers(),
                    || async {
                        let slot = self.tuning.requests.acquire().await;
                        self.check_cancelled()?;
                        Ok(slot)
                    },
                )
                .await?;
            self.progress
                .bytes_unchanged
                .fetch_add(prepared.size, Relaxed);
            return Ok(Some(0));
        }
        let PreparedUpload {
            source,
            size,
            part_size,
            algorithm,
            checksums,
            small,
            metadata,
            must_be_new,
            multipart,
            metadata_update: _,
        } = prepared;
        let _interval = self.progress.copying_interval();
        if size <= part_size || small.is_some() {
            let checksum = checksums.first().map(String::as_str);
            let _slot = self.tuning.requests.acquire().await;
            let synchronous =
                source.kind() == ObjectKind::File && small.is_none() && self.tuning.local_latency();
            let sync_file =
                synchronous.then(|| crate::s3::upload_http::FileBody::new(source.clone(), 0, size));
            let mut fallback = None;
            let mut retry_with_md5 = false;
            let mut attempt = 0;
            loop {
                self.check_cancelled()?;
                if algorithm == Algorithm::None
                    && fallback.is_none()
                    && (retry_with_md5 || self.content_md5.load(Relaxed))
                {
                    fallback = Some(match checksum {
                        Some(md5) => md5.to_owned(),
                        None => content_md5(&source, small.as_ref(), 0, size).await?,
                    });
                }
                let body = if let Some(bytes) = &small {
                    ByteStream::from(bytes.clone())
                } else if synchronous {
                    crate::s3::upload_http::body(size)
                } else {
                    file_body(&source, 0, size).await?
                };
                self.pace(size).await?;
                let request = self
                    .client
                    .put_object()
                    .bucket(&self.options.bucket)
                    .key(&source.key)
                    .body(body)
                    .content_length(size as i64)
                    .set_checksum_sha256(algorithm.header(Algorithm::Sha256, checksum))
                    .set_content_md5(
                        algorithm
                            .header(Algorithm::Md5, checksum)
                            .or_else(|| fallback.clone()),
                    )
                    .set_metadata(Some(metadata.encode()))
                    .set_if_none_match(must_be_new.then(|| "*".into()))
                    .customize()
                    .config_override(super::client::without_sdk_retries())
                    .disable_payload_signing();
                let request = if let Some(file) = &sync_file {
                    request.interceptor(file.clone())
                } else {
                    request
                };
                let result = request.send().await;
                if let Some(file) = &sync_file {
                    file.drain().await;
                }
                match result {
                    Ok(_) => {
                        self.outage.responded();
                        // Content-MD5 fixed the rejection, so send it from now on.
                        if fallback.is_some() {
                            self.content_md5.store(true, Relaxed);
                        }
                        break;
                    }
                    Err(e)
                        if algorithm == Algorithm::None
                            && fallback.is_none()
                            && super::checksum::requires_checksum(&e) =>
                    {
                        retry_with_md5 = true;
                    }
                    Err(e)
                        if attempt < self.options.retries
                            && super::checksum::corrupted(&e).is_some() =>
                    {
                        self.progress.warning(&format!(
                            "{}: the destination received corrupted data ({}); retrying",
                            source.key,
                            super::checksum::corrupted(&e).unwrap_or_default()
                        ));
                        super::backoff(attempt).await;
                        attempt += 1;
                    }
                    Err(e) if retryable(&e) && attempt < self.options.retries => {
                        super::retry::after_error(attempt, &e).await;
                        attempt += 1;
                    }
                    Err(e) => {
                        self.report_final(&e);
                        return Err(e.into_service_error()).context("S3 PUT failed");
                    }
                }
            }
            self.tuning.requests.completed(size);
            self.progress.add_bytes(size);
        } else {
            let PreparedMultipart {
                recorded,
                upload,
                uploaded,
            } = multipart.context("multipart preparation missing")?;
            let state = if recorded {
                let state = State::open(&self.identity(&source.key, "upload"))?;
                let saved: Option<UploadState> = state.load()?;
                anyhow::ensure!(
                    saved
                        .as_ref()
                        .is_some_and(|saved| saved.upload_id == upload.upload_id
                            && saved.digest == upload.digest),
                    "upload recovery changed during preparation; rerun the copy"
                );
                state
            } else {
                // This upload has never been published in the recovery cache.
                // Its in-memory ID suffices; no process can resume it from disk.
                State::without_cache()
            };
            let result: Result<()> = async {
                let acknowledged = Mutex::new(Acknowledged {
                    parts: upload.completed.clone(),
                    saved: tokio::time::Instant::now(),
                    dirty: false,
                });
                let save = |parts: &BTreeMap<i32, UploadedPart>| {
                    let mut record = upload.clone();
                    record.completed = parts.clone();
                    state.save(&record)
                };
                // Stop admitting parts on failure, but drain requests already in flight.
                let failed = std::sync::atomic::AtomicBool::new(false);
                let results = stream::iter(0..size.div_ceil(part_size))
                    .take_while(|_| std::future::ready(!failed.load(Relaxed)))
                    .map(|index| {
                        let source = &source;
                        let upload = &upload;
                        let uploaded = &uploaded;
                        let acknowledged = &acknowledged;
                        let save = &save;
                        // Without request checksums any precomputed value is a
                        // Content-MD5 fallback, not part of the recovery identity.
                        let checksum = checksums.get(index as usize).map(String::as_str);
                        let recorded = match algorithm {
                            Algorithm::None => "",
                            _ => checksum.unwrap_or_default(),
                        };
                        async move {
                            let number = index as i32 + 1;
                            let offset = index * part_size;
                            let length = part_size.min(size - offset);
                            if let Some((etag, old_checksum, old_length)) = uploaded.get(&number) {
                                let matches = match algorithm {
                                    Algorithm::Sha256 => {
                                        checksum.is_some() && old_checksum.as_deref() == checksum
                                    }
                                    // An ETag is opaque. Reuse only an acknowledged
                                    // part from this exact source/recovery record.
                                    Algorithm::Md5 | Algorithm::None => {
                                        upload.acknowledged_part(number, etag, recorded, length)
                                    }
                                };
                                if matches && *old_length == Some(length) {
                                    self.progress.bytes_unchanged.fetch_add(length, Relaxed);
                                    return Ok(CompletedPart::builder()
                                        .part_number(number)
                                        .e_tag(etag)
                                        .set_checksum_sha256(
                                            algorithm.header(Algorithm::Sha256, checksum),
                                        )
                                        .build());
                                }
                            }
                            let _slot = self.tuning.requests.acquire().await;
                            let sync_file = self.tuning.local_latency().then(|| {
                                crate::s3::upload_http::FileBody::new(
                                    source.clone(),
                                    offset,
                                    length,
                                )
                            });
                            let mut fallback = None;
                            let mut retry_with_md5 = false;
                            let mut attempt = 0;
                            loop {
                                self.check_cancelled()?;
                                if algorithm == Algorithm::None
                                    && fallback.is_none()
                                    && (retry_with_md5 || self.content_md5.load(Relaxed))
                                {
                                    fallback = Some(match checksum {
                                        Some(md5) => md5.to_owned(),
                                        None => content_md5(source, None, offset, length).await?,
                                    });
                                }
                                let body = if sync_file.is_some() {
                                    crate::s3::upload_http::body(length)
                                } else {
                                    file_body(source, offset, length).await?
                                };
                                self.pace(length).await?;
                                let request = self
                                    .client
                                    .upload_part()
                                    .bucket(&self.options.bucket)
                                    .key(&source.key)
                                    .upload_id(&upload.upload_id)
                                    .part_number(number)
                                    .body(body)
                                    .content_length(length as i64)
                                    .set_checksum_sha256(
                                        algorithm.header(Algorithm::Sha256, checksum),
                                    )
                                    .set_content_md5(
                                        algorithm
                                            .header(Algorithm::Md5, checksum)
                                            .or_else(|| fallback.clone()),
                                    )
                                    .customize()
                                    .config_override(super::client::without_sdk_retries())
                                    .disable_payload_signing();
                                let request = if let Some(file) = &sync_file {
                                    request.interceptor(file.clone())
                                } else {
                                    request
                                };
                                let result = request.send().await;
                                if let Some(file) = &sync_file {
                                    file.drain().await;
                                }
                                match result {
                                    Ok(output) => {
                                        self.outage.responded();
                                        let etag =
                                            output.e_tag().context("S3 part omitted ETag")?;
                                        if fallback.is_some() {
                                            self.content_md5.store(true, Relaxed);
                                        }
                                        if !algorithm.is_sha256() {
                                            let mut acknowledged = acknowledged.lock().await;
                                            acknowledged.parts.insert(
                                                number,
                                                UploadedPart {
                                                    etag: etag.into(),
                                                    checksum: recorded.to_owned(),
                                                    length,
                                                },
                                            );
                                            acknowledged.dirty = true;
                                            // The record grows with each part. Saving at most
                                            // once a second bounds its rewrites; an unsaved
                                            // acknowledgment only uploads that part again.
                                            if acknowledged.saved.elapsed()
                                                >= Duration::from_secs(1)
                                            {
                                                save(&acknowledged.parts)?;
                                                acknowledged.saved = tokio::time::Instant::now();
                                                acknowledged.dirty = false;
                                            }
                                        }
                                        self.tuning.requests.completed(length);
                                        self.progress.add_bytes(length);
                                        return Ok(CompletedPart::builder()
                                            .part_number(number)
                                            .e_tag(etag)
                                            .set_checksum_sha256(
                                                algorithm.header(Algorithm::Sha256, checksum),
                                            )
                                            .build());
                                    }
                                    Err(e)
                                        if algorithm == Algorithm::None
                                            && fallback.is_none()
                                            && super::checksum::requires_checksum(&e) =>
                                    {
                                        retry_with_md5 = true;
                                    }
                                    Err(e)
                                        if attempt < self.options.retries
                                            && super::checksum::corrupted(&e).is_some() =>
                                    {
                                        self.progress.warning(&format!(
                                            "{}: the destination received corrupted data in part {number} ({}); retrying",
                                            source.key,
                                            super::checksum::corrupted(&e).unwrap_or_default()
                                        ));
                                        super::backoff(attempt).await;
                                        attempt += 1;
                                    }
                                    Err(e) if retryable(&e) && attempt < self.options.retries => {
                                        super::retry::after_error(attempt, &e).await;
                                        attempt += 1;
                                    }
                                    Err(e) => {
                                        self.report_final(&e);
                                        return Err(e.into_service_error())
                                            .context("upload part; rerun the command to resume");
                                    }
                                }
                            }
                        }
                    })
                    .buffer_unordered(self.part_workers())
                    .inspect(|result| {
                        if result.is_err() {
                            failed.store(true, Relaxed);
                        }
                    })
                    .collect::<Vec<Result<_>>>()
                    .await;
                if results.iter().any(Result::is_err) {
                    let acknowledged = acknowledged.lock().await;
                    if acknowledged.dirty {
                        // Keep the part failure as the reported error.
                        let _ = save(&acknowledged.parts);
                    }
                }
                let completed = results.into_iter().collect::<Result<Vec<_>>>()?;
                self.check_cancelled()?;
                source.check(&source.open()?)?;
                let mut completed = completed;
                completed.sort_by_key(|p| p.part_number());
                self.client
                    .complete_multipart_upload()
                    .bucket(&self.options.bucket)
                    .key(&source.key)
                    .upload_id(&upload.upload_id)
                    .multipart_upload(
                        CompletedMultipartUpload::builder()
                            .set_parts(Some(completed))
                            .build(),
                    )
                    .set_if_none_match(must_be_new.then(|| "*".into()))
                    .send()
                    .await
                    .map_err(|e| e.into_service_error())
                    .context("complete multipart upload; rerun the command to recover")?;
                Ok(())
            }
            .await;
            if result.is_err() && !state.has_record() {
                self.abort_unrecorded_upload(&source.key, &upload.upload_id)
                    .await;
            }
            result?;
            state.clear()?;
        }
        if source.kind() == ObjectKind::File {
            source.check(&source.open()?)?;
        }
        Ok(Some(size))
    }
    async fn abort_unrecorded_preparation(&self, prepared: &PreparedUpload) {
        if let Some(update) = &prepared.metadata_update {
            update.abort(&self.client, &self.options.bucket).await;
        }
        if let Some(multipart) = &prepared.multipart {
            if !multipart.recorded {
                self.abort_unrecorded_upload(&prepared.source.key, &multipart.upload.upload_id)
                    .await;
            }
        }
    }
    async fn abort_unrecorded_upload(&self, key: &str, upload_id: &str) {
        if let Err(error) = self
            .client
            .abort_multipart_upload()
            .bucket(&self.options.bucket)
            .key(key)
            .upload_id(upload_id)
            .send()
            .await
        {
            if error
                .raw_response()
                .is_none_or(|r| r.status().as_u16() != 404)
            {
                crate::output::diagnostic!(
                    "syq: warning: failed to abort unfinished upload {key:?} without a recovery record: {}",
                    error.into_service_error()
                );
            }
        }
    }
    async fn prepare_multipart(
        &self,
        source: &Source,
        digest: String,
        part_size: u64,
        metadata: &Metadata,
        algorithm: Algorithm,
    ) -> Result<PreparedMultipart> {
        let state = State::open(&self.identity(&source.key, "upload"))?;
        let mut previous: Option<UploadState> = state.load()?;
        if let Some(old) = &previous {
            if old.schema != old.algorithm.schema() {
                bail!("unsupported S3 upload recovery schema");
            }
            if old.digest != digest
                || old.part_size != part_size
                || old.metadata != *metadata
                || old.algorithm != algorithm
            {
                match self
                    .client
                    .abort_multipart_upload()
                    .bucket(&self.options.bucket)
                    .key(&source.key)
                    .upload_id(&old.upload_id)
                    .send()
                    .await
                {
                    Ok(_) => {}
                    Err(error)
                        if error
                            .raw_response()
                            .is_some_and(|r| r.status().as_u16() == 404) => {}
                    Err(error) => {
                        return Err(error.into_service_error())
                            .context("abort obsolete multipart upload")
                    }
                }
                state.clear()?;
                previous = None;
            }
        }
        let mut uploaded = HashMap::new();
        if let Some(old) = &previous {
            let mut marker = None;
            loop {
                let result = self
                    .client
                    .list_parts()
                    .bucket(&self.options.bucket)
                    .key(&source.key)
                    .upload_id(&old.upload_id)
                    .set_part_number_marker(marker.clone())
                    .send()
                    .await;
                match result {
                    Ok(output) => {
                        for p in output.parts() {
                            if let (Some(number), Some(etag)) = (p.part_number(), p.e_tag()) {
                                uploaded.insert(
                                    number,
                                    (
                                        etag.to_owned(),
                                        p.checksum_sha256().map(str::to_owned),
                                        p.size().and_then(|n| u64::try_from(n).ok()),
                                    ),
                                );
                            }
                        }
                        if output.is_truncated() != Some(true) {
                            break;
                        }
                        let next = output
                            .next_part_number_marker()
                            .context("S3 parts listing omitted continuation")?
                            .to_owned();
                        if marker.as_ref() == Some(&next) {
                            bail!("S3 parts listing repeated its continuation marker");
                        }
                        marker = Some(next);
                    }
                    Err(e) if e.raw_response().is_some_and(|r| r.status().as_u16() == 404) => {
                        previous = None;
                        state.clear()?;
                        break;
                    }
                    Err(e) => return Err(e.into_service_error()).context("list uploaded parts"),
                }
            }
        }
        let upload = if let Some(old) = previous {
            old
        } else {
            let output = self
                .client
                .create_multipart_upload()
                .bucket(&self.options.bucket)
                .key(&source.key)
                .set_metadata(Some(metadata.encode()))
                .set_checksum_algorithm(
                    algorithm
                        .is_sha256()
                        .then_some(aws_sdk_s3::types::ChecksumAlgorithm::Sha256),
                )
                .send()
                .await
                .map_err(|e| e.into_service_error())
                .context("create multipart upload")?;
            let record = UploadState {
                schema: algorithm.schema(),
                digest,
                part_size,
                metadata: metadata.clone(),
                upload_id: output.upload_id().context("S3 omitted upload ID")?.into(),
                algorithm,
                completed: BTreeMap::new(),
            };
            if let Err(error) = state.save(&record) {
                self.client
                    .abort_multipart_upload()
                    .bucket(&self.options.bucket)
                    .key(&source.key)
                    .upload_id(&record.upload_id)
                    .send()
                    .await
                    .map_err(|e| e.into_service_error())
                    .context("recovery record could not be saved and aborting the upload failed")?;
                return Err(error);
            }
            record
        };
        Ok(PreparedMultipart {
            recorded: state.has_record(),
            upload,
            uploaded,
        })
    }

    async fn download_plan(&self, destination_prefix: &str) -> Result<DownloadPlan> {
        let mut prune = super::prune::Plan::default();
        let count = self.args.locations.len() - 1;
        let base = local::key_path(
            self.args
                .native_source_root
                .as_deref()
                .or(self.args.native_source_cwd.as_deref())
                .unwrap_or(b"."),
        )?;
        let manifest = if self.args.native_mapping.is_some() {
            Some(match self.args.parsed_mapping.clone() {
                Some(parsed) => parsed,
                None => {
                    let args = self.args.clone();
                    tokio::task::spawn_blocking(move || crate::mapping::load(&args)).await??
                }
            })
        } else {
            None
        };
        if self.options.route.is_server_copy()
            && manifest.as_ref().is_some_and(|manifest| {
                manifest
                    .entries
                    .iter()
                    .any(|(_, entry)| entry.expected_hash.is_some())
            })
        {
            bail!("S3-to-S3 copies stay server-side; mapping expected hashes require reading object contents and are not supported");
        }
        // Consume entries as they enter the metadata window, releasing the raw
        // input immediately when this planner owns it. An in-process mapping
        // can remain shared; clone only its admitted entries in that case.
        let (owned_entries, shared_manifest) = match manifest {
            Some(manifest) => match Arc::try_unwrap(manifest) {
                Ok(manifest) => (manifest.entries, None),
                Err(manifest) => (Vec::new(), Some(manifest)),
            },
            None => (Vec::new(), None),
        };
        let mapping_selectors = owned_entries
            .into_iter()
            .chain(shared_manifest.iter().flat_map(|m| &m.entries).cloned())
            .map(|(_, entry)| -> Result<_> {
                Ok((
                    local::join(&base, &local::key_path(&entry.src)?),
                    local::join(destination_prefix, &local::key_path(&entry.dst)?),
                    match entry.kind.map(|k| k.label()) {
                        Some("dir") => SourceSelection::Directory,
                        Some("file" | "symlink") => SourceSelection::File,
                        _ => SourceSelection::Named,
                    },
                    entry.kind.map(|kind| kind.label()),
                    entry.expected_hash,
                    entry.metadata,
                ))
            });
        let locations = &self.args.locations[..if self.args.native_mapping.is_some() {
            0
        } else {
            count
        }];
        let path_selectors = locations.iter().map(|location| {
            let key = local::join(&base, &local::key_path(&location.path)?);
            let path = if self.args.placement == Placement::As || location.copies_contents() {
                destination_prefix.to_owned()
            } else {
                local::join(
                    destination_prefix,
                    &local::key_path(
                        crate::cli::native_basename(&location.path)
                            .context("source has no basename")?,
                    )?,
                )
            };
            Ok((key, path, location.selection, None, None, None))
        });
        let selectors = mapping_selectors.chain(path_selectors);
        let matcher = crate::scan::build_ignore(&self.args.ignore_lines)?;
        let min = self
            .args
            .min_size
            .as_deref()
            .map(crate::cli::parse_size)
            .transpose()?
            .unwrap_or(0);
        let max = self
            .args
            .max_size
            .as_deref()
            .map(crate::cli::parse_size)
            .transpose()?
            .unwrap_or(u64::MAX);
        let source_bucket = self
            .options
            .route
            .source_bucket()
            .unwrap_or(&self.options.bucket);
        let mut out = Vec::new();
        let mut service_times = Vec::new();
        let retain_times =
            !self.options.route.is_server_copy() && self.args.expressions.uses_source_s3_time();
        let mut claims = BTreeMap::new();
        let same_bucket = self.options.route.source_bucket() == Some(self.options.bucket.as_str());
        let mut copy_sources = Vec::new();
        let mut copy_targets = Vec::new();
        // Keep selector order for claims, but overlap bounded source metadata reads.
        let mut selectors = stream::iter(selectors)
            .map(|selector| async move {
                self.check_cancelled()?;
                let selector = selector?;
                let prefix = self.args.native_mapping.is_none()
                    && matches!(
                        selector.2,
                        SourceSelection::Contents | SourceSelection::Directory
                    );
                let mut copy_source = None;
                let mut exact = None;
                if !selector.0.is_empty() && !prefix {
                    if self.options.route.is_server_copy() {
                        copy_source = self.copy_head(source_bucket, &selector.0).await?;
                        exact = copy_source.as_ref().map(|(object, _)| object.clone());
                    } else {
                        let _slot = self.tuning.requests.acquire().await;
                        exact = client::head(&self.client, source_bucket, &selector.0).await?;
                    }
                    if exact.is_none() && self.args.native_mapping.is_some() {
                        let marker = format!("{}/", selector.0);
                        if self.options.route.is_server_copy() {
                            copy_source = self.copy_head(source_bucket, &marker).await?;
                            exact = copy_source.as_ref().map(|(object, _)| object.clone());
                        } else {
                            let _slot = self.tuning.requests.acquire().await;
                            exact = client::head(&self.client, source_bucket, &marker).await?;
                        }
                    }
                }
                Ok::<_, anyhow::Error>((selector, exact, copy_source))
            })
            .buffered(32);
        while let Some(selector) = selectors.next().await {
            let (
                (key, path, selection, declared_kind, expected_hash, metadata),
                exact,
                mut copy_source,
            ) = selector?;
            let expression_root = if self.args.expressions.active() {
                key.clone()
            } else {
                String::new()
            };
            // An exclusion under one root says nothing about the same object
            // selected through another root with different anchoring.
            let mut excluded_subtrees = HashSet::new();
            let contents = selection == SourceSelection::Contents;
            let directory = matches!(
                selection,
                SourceSelection::Contents | SourceSelection::Directory
            );
            let prefix = if key.is_empty() {
                String::new()
            } else {
                format!("{key}/")
            };
            let exact = async {
                let exact = if !key.is_empty() && directory && self.args.native_mapping.is_none() {
                    client::head(&self.client, source_bucket, &key).await?
                } else {
                    exact
                };
                if exact.is_some() && directory && self.args.native_mapping.is_none() {
                    bail!("S3 selector requires a prefix but an object exists at {key:?}");
                }
                Ok::<_, anyhow::Error>(exact)
            };
            // Explicit prefix selectors need both reads. Start the listing
            // while checking for a conflicting object, but validate both
            // results before any file transfer or publication can begin.
            let (exact, listed) = if directory && self.args.native_mapping.is_none() {
                let (exact, listed) = tokio::try_join!(
                    exact,
                    client::list_with_times(
                        &self.client,
                        source_bucket,
                        &prefix,
                        matcher.as_ref(),
                        &mut excluded_subtrees,
                        self.options.concurrency,
                        self.args.expressions.uses_source_s3_time(),
                    )
                )?;
                (exact, Some(listed))
            } else {
                (exact.await?, None)
            };
            let from_listing = self.args.native_mapping.is_none() && exact.is_none();
            if self.args.native_mapping.is_some() {
                // Mapping entries name individual objects. A directory entry
                // copies its marker, while explicit child entries copy children.
                let object = exact
                    .as_ref()
                    .context("S3 mapping source object or directory marker is missing")?;
                if declared_kind
                    .map(str::parse::<ObjectKind>)
                    .transpose()?
                    .is_some_and(|kind| kind != object.kind())
                {
                    bail!("S3 source type does not match mapping");
                }
                if expected_hash.is_some() && object.kind() != ObjectKind::File {
                    bail!("an expected hash requires a regular file");
                }
            }
            let objects: Box<dyn Iterator<Item = Result<_>> + Send + '_> =
                if let Some(exact) = exact {
                    let kind = exact.kind();
                    let directory = client::is_directory_marker(&exact.key, exact.size);
                    Box::new(std::iter::once(Ok((
                        exact.key.clone(),
                        exact.size,
                        path.clone(),
                        kind,
                        directory,
                        None,
                        Some(exact),
                    ))))
                } else {
                    if selection == SourceSelection::File {
                        bail!("S3 source object {key:?} is missing");
                    }
                    let listed = match listed {
                        Some(listed) => listed,
                        None => {
                            client::list_with_times(
                                &self.client,
                                source_bucket,
                                &prefix,
                                matcher.as_ref(),
                                &mut excluded_subtrees,
                                self.options.concurrency,
                                self.args.expressions.uses_source_s3_time(),
                            )
                            .await?
                        }
                    };
                    if !listed.found {
                        bail!("S3 source prefix {key:?} contains no objects");
                    }
                    self.progress
                        .paths_ignored
                        .fetch_add(listed.excluded, Relaxed);
                    if same_bucket {
                        copy_sources.push((prefix.clone(), true));
                        copy_targets.push((
                            if path.is_empty() {
                                String::new()
                            } else {
                                format!("{path}/")
                            },
                            true,
                        ));
                    }
                    if self.args.delete {
                        prune.scope(path.as_bytes());
                    }
                    Box::new(listed.into_entries().filter_map(
                        move |(object, size, service_time)| {
                            (|| {
                                let suffix = object.strip_prefix(&prefix).context(
                                    "S3 listing returned a key outside the requested prefix",
                                )?;
                                let directory = client::is_directory_marker(&object, size);
                                if suffix.is_empty()
                                    && (contents
                                        || (directory
                                            && self.options.route.is_server_copy()
                                            && path.is_empty()))
                                {
                                    return Ok(None);
                                }
                                let suffix = if directory {
                                    suffix.trim_end_matches('/')
                                } else {
                                    suffix
                                };
                                let suffix = local::key_path(suffix.as_bytes())
                                    .with_context(|| format!("S3 source key {object:?}"))?;
                                let kind = if directory {
                                    ObjectKind::Dir
                                } else {
                                    ObjectKind::File
                                };
                                Ok(Some((
                                    object,
                                    size,
                                    local::join(&path, &suffix),
                                    kind,
                                    directory,
                                    service_time,
                                    None,
                                )))
                            })()
                            .transpose()
                        },
                    ))
                };
            for object in objects {
                let (key, size, path, kind, directory, service_time, source_object) = object?;
                if !directory
                    && !from_listing
                    && crate::scan::selected_file_is_ignored(matcher.as_ref(), key.as_bytes())
                {
                    self.progress.paths_ignored.fetch_add(1, Relaxed);
                    prune.protect(path.as_bytes());
                    continue;
                }
                if !directory && (size < min || size > max) {
                    self.progress.files_excluded.fetch_add(1, Relaxed);
                    prune.protect(path.as_bytes());
                    continue;
                }
                if path.is_empty() && !directory {
                    bail!("cannot replace the destination directory with an object");
                }
                if same_bucket && !from_listing {
                    copy_sources.push((key.clone(), false));
                    copy_targets.push((
                        if directory {
                            format!("{path}/")
                        } else {
                            path.clone()
                        },
                        false,
                    ));
                }
                local::claim(&mut claims, &path, directory)?;
                if self.args.delete {
                    if directory {
                        prune.claim(path.as_bytes());
                    } else if self.options.route.is_server_copy()
                        && !self.args.ignore_existing
                        && !self.args.existing
                        && !self.args.expressions.active()
                    {
                        prune.claim_file(path.as_bytes());
                    } else {
                        prune.protect(path.as_bytes());
                    }
                }
                let expression_destination_path = if !self.args.expressions.active() {
                    String::new()
                } else {
                    path.strip_prefix(destination_prefix)
                        .and_then(|s| s.strip_prefix('/'))
                        .filter(|s| !s.is_empty())
                        .unwrap_or(if destination_prefix.is_empty() {
                            &path
                        } else {
                            path.rsplit('/').next().unwrap_or(&path)
                        })
                        .to_owned()
                };
                // Directory markers use the same path spelling as filesystem
                // directories. A mapping keeps its complete source-relative path.
                let expression_key = if directory {
                    key.trim_end_matches('/')
                } else {
                    &key
                };
                let expression_path = if !self.args.expressions.active() {
                    String::new()
                } else if self.args.native_mapping.is_some() {
                    if base.is_empty() {
                        expression_key
                    } else {
                        expression_key
                            .strip_prefix(&base)
                            .and_then(|s| s.strip_prefix('/'))
                            .context("mapped S3 source is outside its base")?
                    }
                    .to_owned()
                } else {
                    let relative = if expression_root.is_empty() {
                        expression_key
                    } else {
                        expression_key
                            .strip_prefix(&expression_root)
                            .and_then(|s| s.strip_prefix('/'))
                            .unwrap_or("")
                    };
                    String::from_utf8(
                        crate::expression::source_path(
                            expression_root.as_bytes(),
                            relative.as_bytes(),
                        )
                        .to_vec(),
                    )?
                };
                let known_source = source_object.as_ref().map(Object::expression_file);
                let facts = known_source.as_ref().map_or(
                    crate::expression::Facts::S3Listing {
                        size,
                        directory_marker: directory,
                        last_modified: service_time,
                    },
                    crate::expression::Facts::Complete,
                );
                let selected = self
                    .args
                    .expressions
                    .selects_known(facts, expression_path.as_bytes())?;
                if selected == Some(false)
                    || (selected == Some(true)
                        && self.args.expressions.permits_known(
                            facts,
                            expression_path.as_bytes(),
                            crate::expression::Facts::Unread,
                            expression_destination_path.as_bytes(),
                        )? == Some(false))
                {
                    self.progress.files_excluded.fetch_add(1, Relaxed);
                    continue;
                }
                if retain_times {
                    service_times.push(service_time);
                }
                out.push(Download {
                    expression_path,
                    expression_destination_path,
                    kind,
                    key,
                    path,
                    size,
                    mapping: (expected_hash.is_some() || metadata.is_some()).then(|| {
                        Box::new(DownloadMapping {
                            expected_hash: expected_hash.clone(),
                            metadata,
                        })
                    }),
                    copy_source: copy_source.take().map(Box::new),
                    source_object: if self.options.route.is_server_copy() {
                        None
                    } else {
                        source_object.map(Box::new)
                    },
                });
            }
        }
        if same_bucket {
            server_copy::check_overlap(&copy_sources, &copy_targets)?;
        }
        if let Some(results) = self.progress.results_writer() {
            results.mapping_metadata(
                out.iter()
                    .filter_map(|j| j.metadata().map(|m| (j.path.as_bytes().to_vec(), m))),
            );
        }
        Ok(DownloadPlan {
            jobs: out,
            prune,
            service_times,
        })
    }
    async fn download(
        self: &Arc<Self>,
        job: &mut Download,
        destination: &Destination,
        directories: DirectoryMetadata,
        service_time: Option<(i64, u32)>,
    ) -> Result<Option<u64>> {
        let known_source = job.source_object.as_deref().map(Object::expression_file);
        let source_facts = known_source.as_ref().map_or(
            crate::expression::Facts::S3Listing {
                size: job.size,
                directory_marker: client::is_directory_marker(&job.key, job.size),
                last_modified: service_time,
            },
            crate::expression::Facts::Complete,
        );
        let selected = self
            .args
            .expressions
            .selects_known(source_facts, job.expression_path.as_bytes())?;
        if selected == Some(false) {
            return Ok(None);
        }
        let part_size = self.part_size(job.size);
        let expected_hash = job.mapping.as_ref().and_then(|m| m.expected_hash.as_ref());
        let requires_regular_file = expected_hash.is_some();
        let expected_hash = expected_hash.filter(|_| !self.args.dry_run);
        let root = &destination.root;
        let path = RelativePath::new(job.path.as_bytes())?;
        let existing = match root.metadata_optional(&path) {
            Ok(m) => m,
            Err(e)
                if e.chain().any(|c| {
                    c.downcast_ref::<std::io::Error>()
                        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
                }) =>
            {
                None
            }
            Err(e) => return Err(e),
        };
        // A marker directory another job of this download created is still
        // new to its marker. Its creator recorded it before creating it, so
        // checking after the lookup cannot miss it.
        let existing = if job.kind == ObjectKind::Dir {
            existing.filter(|_| !directories.created(&directory_key(&path)))
        } else {
            existing
        };
        if (self.args.ignore_existing && existing.is_some())
            || (self.args.existing && existing.is_none())
        {
            return Ok(None);
        }
        let destination_file = || -> Result<crate::expression::File> {
            let mut file = existing
                .map(crate::expression::File::from_root)
                .unwrap_or_default();
            if file.kind == Some(crate::proto::Kind::Symlink) {
                file.link_target = Some(root.read_link(&path)?);
            }
            Ok(file)
        };
        let mut observed_destination = None;
        let permitted = if self.args.expressions.update.is_none() {
            Some(true)
        } else if selected == Some(true) {
            let file = destination_file()?;
            let result = self.args.expressions.permits_known(
                source_facts,
                job.expression_path.as_bytes(),
                crate::expression::Facts::Complete(&file),
                job.expression_destination_path.as_bytes(),
            )?;
            observed_destination = Some(file);
            result
        } else {
            None
        };
        if permitted == Some(false) {
            return Ok(None);
        }
        // A fresh file, or an ordinary update with a different listed size,
        // needs the body anyway. Obtain metadata with its first data request.
        // Keep HEAD when metadata could still reject the copy or prove equality.
        // For multipart downloads these headers let the other ranges start
        // while the first body is consumed alongside them.
        let needs_body = existing.is_none()
            || (job.source_object.is_none()
                && existing.is_some_and(|m| m.is_file() && m.len != job.size)
                && !self.args.update
                && !self.args.protects_existing_contents());
        let mut get_first = needs_body
            && !self.args.dry_run
            && !job.key.ends_with('/')
            && selected == Some(true)
            && permitted == Some(true);
        // A saved first range can exist before the destination is published.
        // Check recovery before fetching it, and keep this state for the normal
        // identity and range checks below so the record is opened only once.
        let recovery = if get_first && job.size > part_size {
            let recovery = self.open_download_state(root, &job.key, &job.path)?;
            get_first = recovery.1.is_none();
            Some(recovery)
        } else {
            None
        };
        let mut initial_slot = None;
        let initial = if get_first {
            initial_slot = Some(self.tuning.requests.acquire().await);
            Some(
                self.client
                    .get_object()
                    .bucket(&self.options.bucket)
                    .key(&job.key)
                    .set_if_match(job.source_object.as_ref().map(|object| object.etag.clone()))
                    .set_version_id(
                        job.source_object
                            .as_ref()
                            .and_then(|object| object.version.clone()),
                    )
                    .set_range((job.size > part_size).then(|| format!("bytes=0-{}", part_size - 1)))
                    .send()
                    .await
                    .map_err(|e| e.into_service_error())
                    .context("S3 GET failed")?,
            )
        } else {
            None
        };
        let object = if let Some(output) = &initial {
            client::from_get(&job.key, job.size, part_size, output)?
        } else if let Some(object) = job.source_object.as_deref() {
            object.clone()
        } else {
            client::head(&self.client, &self.options.bucket, &job.key)
                .await?
                .context("S3 source disappeared after listing")?
        };
        job.kind = object.kind();
        if self.args.expressions.active() {
            let source = object.expression_file();
            if !self
                .args
                .expressions
                .selects(&source, job.expression_path.as_bytes())?
            {
                return Ok(None);
            }
            let dest = match observed_destination {
                Some(file) => file,
                None if self.args.expressions.update.is_some() => destination_file()?,
                None => crate::expression::File::default(),
            };
            if !self.args.expressions.permits(
                &source,
                job.expression_path.as_bytes(),
                &dest,
                job.expression_destination_path.as_bytes(),
            )? {
                return Ok(None);
            }
        }
        let mut initial = initial.map(|output| output.body);
        let mut metadata = object.metadata.clone().unwrap_or(Metadata {
            kind: object.kind(),
            mode: if object.kind() == ObjectKind::Dir {
                0o777
            } else {
                0o666
            },
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
            mtime: object.mtime,
            nsec: 0,
            hash: None,
            hash_algorithm: HashAlgorithm::Blake3,
        });
        let source_time = (metadata.mtime, metadata.nsec);
        let explicit = job.metadata().unwrap_or_default();
        explicit.validate_kind(match object.kind() {
            ObjectKind::File => crate::proto::Kind::File,
            ObjectKind::Dir => crate::proto::Kind::Dir,
            ObjectKind::Symlink => crate::proto::Kind::Symlink,
        })?;
        metadata.override_with(&explicit);
        anyhow::ensure!(
            object.kind() == ObjectKind::Dir
                || existing.is_none()
                || self.args.if_exists != Some(crate::cli::IfExists::Error),
            "destination already exists: {} (--if-exists=error)",
            job.path
        );
        if self.args.update
            && object.kind() != ObjectKind::Dir
            && existing.is_some_and(|m| !m.is_dir() && (m.mtime, m.mtime_nsec) > source_time)
        {
            return Ok(None);
        }
        if let Some(m) = existing {
            if m.is_dir() != (object.kind() == ObjectKind::Dir) {
                bail!("refusing to replace a directory with a non-directory or the reverse");
            }
        }
        if requires_regular_file && object.kind() != ObjectKind::File {
            bail!("an expected hash requires a regular file");
        }
        if object.kind() == ObjectKind::Dir {
            if !self.args.dry_run {
                if existing.is_none() {
                    // Private until finish_directories applies the marker's
                    // metadata, which it always does for a new directory.
                    directories.create_missing_parents(root, &path)?;
                    let mode = directories.creation_mode(&directory_key(&path));
                    match root.create_directory(&path, mode) {
                        Ok(()) => {
                            self.progress.directories_created.fetch_add(1, Relaxed);
                        }
                        Err(e) if root.metadata(&path).is_ok_and(|m| m.is_dir()) => {
                            let _ = e;
                        }
                        Err(e) => return Err(e),
                    }
                }
                directories.metadata.lock().await.push((
                    job.path.clone(),
                    metadata,
                    existing.map(|m| m.mode & 0o7777),
                    explicit,
                ));
            }
            return Ok(Some(0));
        }
        if object.kind() == ObjectKind::Symlink {
            if object.size > 1024 * 1024 {
                bail!("S3 symlink target is too large");
            }
            let bytes = self.get_small(&object, initial, initial_slot).await?;
            if let Some(hash) = metadata
                .hash
                .as_ref()
                .filter(|_| self.args.transfer_integrity)
            {
                if Digest::hash_bytes(metadata.hash_algorithm, &bytes).value != *hash {
                    bail!("symlink checksum mismatch");
                }
            }
            let same = existing.is_some_and(|m| m.is_symlink()) && root.read_link(&path)? == bytes;

            anyhow::ensure!(
                same || existing.is_none() || !self.args.protects_existing_contents(),
                "destination contents differ: {} (--if-exists=error-if-different)",
                job.path
            );
            if !self.args.dry_run {
                directories.create_missing_parents(root, &path)?;
                if !same {
                    if existing.is_some() {
                        root.replace_symlink(&path, &bytes)?;
                    } else {
                        root.create_symlink(&path, &bytes)?;
                    }
                    self.progress.symlinks_created.fetch_add(1, Relaxed);
                }
                local::apply_metadata(
                    root,
                    &path,
                    &metadata,
                    &self.args,
                    None,
                    explicit,
                    !same,
                    &mut Default::default(),
                )?;
            }
            if same {
                return Ok(None);
            }
            self.progress.add_bytes(bytes.len() as u64);
            return Ok(Some(bytes.len() as u64));
        }
        let mut unchanged = false;
        if let Some(m) = existing.filter(|m| m.is_file() && m.len == object.size) {
            unchanged = !self.args.checksum
                && explicit.mtime.is_none()
                && (m.mtime, m.mtime_nsec) == source_time;
            if !unchanged
                && (self.args.checksum
                    || self.args.protects_existing_contents()
                    || self.stored_comparison_hash(&object).is_some())
            {
                unchanged = self.verify_download(root, &path, &object).await?;
            }
        }
        anyhow::ensure!(
            unchanged || existing.is_none() || !self.args.protects_existing_contents(),
            "destination contents differ: {} (--if-exists=error-if-different)",
            job.path
        );
        if unchanged && expected_hash.is_some() {
            unchanged = self
                .verify_expected_local(root, &path, expected_hash)
                .await
                .is_ok();
        }
        if unchanged {
            if self.args.dry_run {
                let current = existing.expect("unchanged file exists");
                let differs = ((self.args.perms || explicit.mode.is_some())
                    && metadata.mode & 0o7777 != current.mode & 0o7777)
                    || ((self.args.owner || explicit.uid.is_some()) && metadata.uid != current.uid)
                    || ((self.args.group || explicit.gid.is_some()) && metadata.gid != current.gid)
                    || ((self.args.copy_mtime_metadata || explicit.mtime.is_some())
                        && (metadata.mtime, metadata.nsec) != (current.mtime, current.mtime_nsec));
                if differs {
                    if self.args.verbose > 0 {
                        self.progress.println(&format!(
                            "update metadata {} (requested file metadata differs)",
                            job.path
                        ));
                    }
                    if let Some(writer) = self.progress.results_writer() {
                        writer.emit_trace(&crate::results::TraceRecord {
                            action: "transfer_file",
                            src: Some(job.key.as_bytes()),
                            dst: job.path.as_bytes(),
                            kind: "file",
                            bytes: None,
                            reason: "metadata_differs",
                        });
                    }
                }
            } else {
                local::apply_metadata(
                    root,
                    &path,
                    &metadata,
                    &self.args,
                    existing.map(|m| m.mode & 0o7777),
                    explicit,
                    false,
                    &mut Default::default(),
                )?;
            }
            self.progress
                .bytes_unchanged
                .fetch_add(object.size, Relaxed);
            return Ok(None);
        }
        if self.args.dry_run {
            self.progress.add_bytes(object.size);
            return Ok(Some(object.size));
        }
        directories.create_missing_parents(root, &path)?;
        if object.size <= part_size {
            return self
                .download_single(
                    &object,
                    root,
                    &path,
                    (&metadata, expected_hash, explicit),
                    existing.filter(|m| m.is_file()).map(|m| m.mode & 0o7777),
                    initial,
                    initial_slot,
                )
                .await;
        }
        let (state, mut saved) = match recovery {
            Some(recovery) => recovery,
            None => self.open_download_state(root, &object.key, &job.path)?,
        };
        if let Some(old) = &saved {
            if old.schema != 1 && old.schema != 2 {
                bail!("unsupported S3 download recovery schema");
            }
            if old.etag != object.etag
                || old.version != object.version
                || old.size != object.size
                || old.part_size != part_size
            {
                remove_partial(root, old)?;
                state.clear()?;
                saved = None;
            }
        }
        let (record, file) = if let Some(old) = saved {
            let partial = RelativePath::new(old.partial.as_bytes())?;
            match root.metadata_optional(&partial)? {
                Some(m) if m.dev == old.dev && m.ino == old.ino && m.is_file() && m.nlink == 1 => {
                    (old, root.open_regular_read_write(&partial)?)
                }
                None => {
                    state.clear()?;
                    self.new_download_state(root, &job.path, &object, &state)?
                }
                _ => bail!("partial download changed identity; refusing to overwrite it"),
            }
        } else {
            self.new_download_state(root, &job.path, &object, &state)?
        };
        let _cleanup = if state.has_record() {
            None
        } else {
            Some(PartialCleanup {
                root,
                path: RelativePath::new(record.partial.as_bytes())?,
                identity: (record.dev, record.ino),
            })
        };
        let range_algorithm = record.hash_algorithm;
        let record = Arc::new(Mutex::new(record));
        let file = Arc::new(file);
        let allocation = file.clone();
        let size = object.size;
        tokio::task::spawn_blocking(move || super::writer::allocate(&allocation, size)).await??;
        let output = super::writer::Writer::with_readback(
            file.clone(),
            object.size,
            !part_size.is_multiple_of(4096)
                || !self.download_digests(&metadata, expected_hash).is_empty(),
        )?;
        let parts = object.size.div_ceil(part_size);
        let _interval = self.progress.copying_interval();
        let failed = std::sync::atomic::AtomicBool::new(false);
        let copied = stream::iter(0..parts)
            .take_while(|_| std::future::ready(!failed.load(Relaxed)))
            .map(|index| {
                let output = output.clone();
                let file = file.clone();
                let record = record.clone();
                let object = &object;
                let state = &state;
                let initial = if index == 0 { initial.take() } else { None };
                let slot = if index == 0 {
                    initial_slot.take()
                } else {
                    None
                };
                async move {
                    let offset = index * part_size;
                    let length = part_size.min(object.size - offset);
                    let previous = record.lock().await.parts.get(&index).cloned();
                    if let Some(hash) = previous {
                        let f = file.clone();
                        let actual = tokio::task::spawn_blocking(move || {
                            hash_range(&f, offset, length, range_algorithm)
                        })
                        .await??;
                        if actual == hash {
                            self.progress.bytes_unchanged.fetch_add(length, Relaxed);
                            return Ok::<_, anyhow::Error>(());
                        }
                    }
                    let hash = self
                        .download_fast_range(
                            object,
                            &output,
                            offset,
                            length,
                            initial,
                            slot,
                            Some(range_algorithm),
                        )
                        .await?;
                    output.finish().await?;
                    let mut record = record.lock().await;
                    record.parts.insert(index, hash);
                    state.save(&*record)?;
                    Ok(())
                }
            })
            .buffer_unordered(self.part_workers())
            .inspect(|result| {
                if result.is_err() {
                    failed.store(true, Relaxed);
                }
            })
            .collect::<Vec<Result<_>>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>>>();
        let flushed = output.finish().await;
        copied?;
        flushed?;
        let partial = record.lock().await.partial.clone();
        let partial_path = RelativePath::new(partial.as_bytes())?;
        // A network filesystem may flush here; keep that off the async workers.
        let writer = file.clone();
        let label = path.to_path_buf();
        tokio::task::spawn_blocking(move || {
            crate::fsops::check_destination_writes(&writer, &label)
        })
        .await??;
        for expected in self.download_digests(&metadata, expected_hash) {
            let f = root.open_regular_read(&partial_path)?;
            tokio::task::spawn_blocking(move || expected.verify_reader(&mut &f)).await??;
        }
        // A version ID pins immutable content; otherwise confirm the source
        // still has the identity used on every range request.
        if object.version.is_none() {
            let final_object = client::head(&self.client, &self.options.bucket, &object.key)
                .await?
                .context("source disappeared during download")?;
            if final_object.etag != object.etag || final_object.size != object.size {
                bail!("source object changed during download");
            }
        }
        self.check_cancelled()?;
        local::apply_file_metadata(
            &file,
            &metadata,
            &self.args,
            existing.filter(|m| m.is_file()).map(|m| m.mode & 0o7777),
            explicit,
            || local::CreationPermissions::shared_for_file(&self.file_permissions, root, &path),
        )?;
        let m = file.metadata()?;
        if self.args.ignore_existing
            || self.args.target_existence == Existence::New
            || self.args.protects_existing_contents()
        {
            root.publish_new_regular(&partial_path, &path, (m.dev(), m.ino()))?;
        } else {
            root.rename_regular_if_same(&partial_path, &path, (m.dev(), m.ino()))?;
        }
        state.clear()?;
        Ok(Some(object.size))
    }
    fn download_digests(&self, metadata: &Metadata, expected: Option<&Digest>) -> Vec<Digest> {
        let mut digests = expected.cloned().into_iter().collect::<Vec<_>>();
        if self.args.transfer_integrity {
            if let Some(value) = &metadata.hash {
                let digest = Digest {
                    algorithm: metadata.hash_algorithm,
                    value: value.clone(),
                };
                if !digests.contains(&digest) {
                    digests.push(digest);
                }
            }
        }
        digests
    }
    async fn verify_expected_local(
        &self,
        root: &Root,
        path: &RelativePath,
        expected: Option<&Digest>,
    ) -> Result<()> {
        if let Some(expected) = expected.cloned() {
            let mut file = root.open_regular_read(path)?;
            tokio::task::spawn_blocking(move || expected.verify_reader(&mut file)).await??;
        }
        Ok(())
    }
    async fn verify_expected_remote(
        &self,
        object: &Object,
        expected: Option<&Digest>,
    ) -> Result<()> {
        if let Some(expected) = expected {
            if object.kind() != ObjectKind::File {
                bail!("an expected hash requires a regular file");
            }
            let actual = self.remote_hash_as(object, expected.algorithm).await?;
            if actual != expected.value {
                bail!("remote object does not match expected hash");
            }
        }
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    async fn download_single(
        &self,
        object: &Object,
        root: &Root,
        path: &RelativePath,
        validation: (&Metadata, Option<&Digest>, crate::mapping::Metadata),
        mode: Option<u32>,
        initial: Option<ByteStream>,
        initial_slot: Option<super::tuning::Permit>,
    ) -> Result<Option<u64>> {
        let (metadata, expected_hash, explicit) = validation;
        let path_buf = path.to_path_buf();
        let label = path_buf
            .to_str()
            .context("S3 download placement requires UTF-8")?;
        let parent = label.rsplit_once('/').map_or("", |(p, _)| p);
        let mut random = [0u8; 16];
        getrandom::fill(&mut random)?;
        let partial = RelativePath::new(
            local::join(parent, &super::prune::partial_name(&random)).as_bytes(),
        )?;
        let file = Arc::new(root.create_file(&partial, 0o600)?);
        let _cleanup = PartialCleanup {
            root,
            path: partial.clone(),
            identity: (file.metadata()?.dev(), file.metadata()?.ino()),
        };
        let result = async {
            let digests = self.download_digests(metadata, expected_hash);
            let algorithm = digests.first().map(|d| d.algorithm);
            let output =
                super::writer::Writer::with_readback(file.clone(), object.size, digests.len() > 1)?;
            let hash = if object.size == 0 && initial.is_none() {
                algorithm
                    .map(|a| Digest::hash_bytes(a, &[]).value)
                    .unwrap_or_default()
            } else {
                let copied = self
                    .download_fast_range(
                        object,
                        &output,
                        0,
                        object.size,
                        initial,
                        initial_slot,
                        algorithm,
                    )
                    .await;
                let flushed = output.finish().await;
                let hash = copied?;
                flushed?;
                hash
            };
            if digests
                .first()
                .is_some_and(|expected| expected.value != hash)
            {
                bail!("download checksum mismatch");
            }
            // If the caller requires a second algorithm, reread only for that
            // distinct requirement, never rehash the same digest twice.
            for expected in digests.into_iter().skip(1) {
                let f = file.clone();
                tokio::task::spawn_blocking(move || expected.verify_reader(&mut &*f)).await??;
            }
            self.check_cancelled()?;
            let writer = file.clone();
            let label = path_buf.clone();
            tokio::task::spawn_blocking(move || {
                crate::fsops::check_destination_writes(&writer, &label)
            })
            .await??;
            local::apply_file_metadata(&file, metadata, &self.args, mode, explicit, || {
                local::CreationPermissions::shared_for_file(&self.file_permissions, root, path)
            })?;
            let m = file.metadata()?;
            if self.args.ignore_existing
                || self.args.target_existence == Existence::New
                || self.args.protects_existing_contents()
            {
                root.publish_new_regular(&partial, path, (m.dev(), m.ino()))?;
            } else {
                root.rename_regular_if_same(&partial, path, (m.dev(), m.ino()))?;
            }
            Ok(Some(object.size))
        }
        .await;
        result
    }
    fn open_download_state(
        &self,
        root: &Root,
        key: &str,
        path: &str,
    ) -> Result<(State, Option<DownloadState>)> {
        let extra = format!(
            "download:{}:{}:{path}",
            root.identity().dev,
            root.identity().ino,
        );
        let state = State::open(&self.identity(key, &extra))?;
        let saved = state.load()?;
        Ok((state, saved))
    }
    fn new_download_state(
        &self,
        root: &Root,
        path: &str,
        object: &Object,
        state: &State,
    ) -> Result<(DownloadState, File)> {
        let parent = path.rsplit_once('/').map_or("", |(p, _)| p);
        let mut random = [0u8; 16];
        getrandom::fill(&mut random)?;
        let partial = local::join(parent, &super::prune::partial_name(&random));
        let file = root.create_file(&RelativePath::new(partial.as_bytes())?, 0o600)?;
        file.set_len(object.size)?;
        let m = file.metadata()?;
        let record = DownloadState {
            schema: 2,
            etag: object.etag.clone(),
            version: object.version.clone(),
            size: object.size,
            part_size: self.part_size(object.size),
            partial,
            dev: m.dev(),
            ino: m.ino(),
            parts: BTreeMap::new(),
            hash_algorithm: self.args.hash_algorithm,
        };
        state.save(&record)?;
        Ok((record, file))
    }
    async fn get_small(
        &self,
        object: &Object,
        initial: Option<ByteStream>,
        initial_slot: Option<super::tuning::Permit>,
    ) -> Result<Vec<u8>> {
        let _slot = match initial_slot {
            Some(slot) => slot,
            None => self.tuning.requests.acquire().await,
        };
        let body = match initial {
            Some(body) => body,
            None => {
                self.client
                    .get_object()
                    .bucket(&self.options.bucket)
                    .key(&object.key)
                    .if_match(&object.etag)
                    .set_version_id(object.version.clone())
                    .send()
                    .await
                    .map_err(|e| e.into_service_error())?
                    .body
            }
        };
        let mut bytes = Vec::new();
        body.into_async_read()
            .take(object.size + 1)
            .read_to_end(&mut bytes)
            .await?;
        if bytes.len() as u64 != object.size {
            bail!("S3 response length differs");
        }
        Ok(bytes)
    }
    async fn verify_download(
        &self,
        root: &Root,
        path: &RelativePath,
        object: &Object,
    ) -> Result<bool> {
        let file = root.open_regular_read(path)?;
        let stored = self.stored_comparison_hash(object);
        let algorithm = stored.map_or(self.args.hash_algorithm, |(algorithm, _)| algorithm);
        let expected =
            tokio::task::spawn_blocking(move || local::hash_file_as(file, algorithm)).await??;
        let actual = match stored {
            Some((_, hash)) => hash.to_owned(),
            None => self.remote_hash_as(object, algorithm).await?,
        };
        Ok(actual.eq_ignore_ascii_case(&expected))
    }

    fn stored_comparison_hash<'a>(&self, object: &'a Object) -> Option<(HashAlgorithm, &'a str)> {
        let metadata = object.metadata.as_ref()?;
        // Explicit --hash selects the comparison algorithm. Automatic comparisons
        // can reuse any supported stored whole-file hash.
        if self.args.checksum && metadata.hash_algorithm != self.args.hash_algorithm {
            return None;
        }
        Some((metadata.hash_algorithm, metadata.hash.as_deref()?))
    }
    async fn remote_hash_as(&self, object: &Object, algorithm: HashAlgorithm) -> Result<String> {
        let _slot = self.tuning.requests.acquire().await;
        let output = self
            .client
            .get_object()
            .bucket(&self.options.bucket)
            .key(&object.key)
            .if_match(&object.etag)
            .set_version_id(object.version.clone())
            .send()
            .await
            .map_err(|e| e.into_service_error())?;
        let mut body = output.body.into_async_read();
        let mut buffer = vec![0; 1024 * 1024];
        let mut hash = algorithm.hasher();
        let mut n = 0;
        loop {
            let got = body.read(&mut buffer).await?;
            if got == 0 {
                break;
            }
            hash.update(&buffer[..got]);
            n += got as u64;
        }
        if n != object.size {
            bail!("S3 response was truncated or exceeded its advertised size");
        }
        Ok(Digest::from_hash(algorithm, &hash.finalize()).value)
    }
}
#[derive(Debug)]
struct Permanent(String);
impl std::fmt::Display for Permanent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Permanent {}
/// The upload loops replace SDK retries, so they must recognize the same
/// throttling and transient conditions: dispatch failures without a response,
/// retryable statuses, and the error codes S3 can send with other statuses,
/// such as `RequestTimeout` with HTTP 400.
pub(super) fn retryable<E: aws_sdk_s3::error::ProvideErrorMetadata>(
    error: &aws_sdk_s3::error::SdkError<
        E,
        aws_smithy_runtime_api::client::orchestrator::HttpResponse,
    >,
) -> bool {
    use aws_runtime::retries::classifiers::{THROTTLING_ERRORS, TRANSIENT_ERRORS};
    error
        .raw_response()
        .map(|r| r.status().as_u16())
        .is_none_or(super::outage::transient_status)
        || error
            .as_service_error()
            .and_then(|e| e.code())
            .is_some_and(|code| {
                THROTTLING_ERRORS.contains(&code) || TRANSIENT_ERRORS.contains(&code)
            })
}
async fn file_body(source: &Source, offset: u64, length: u64) -> Result<ByteStream> {
    let source = source.clone();
    let file = tokio::task::spawn_blocking(move || source.open()).await??;
    Ok(ByteStream::read_from()
        .file(tokio::fs::File::from_std(file))
        .offset(offset)
        .length(Length::Exact(length))
        .buffer_size(length.clamp(1, 1024 * 1024) as usize)
        .build()
        .await?)
}
fn upload_identity(
    algorithm: Algorithm,
    size: u64,
    part_size: u64,
    checksums: &[String],
    metadata: &Metadata,
) -> String {
    let mut hash = blake3::Hasher::new();
    if algorithm == Algorithm::None {
        // Parts carry no request checksums; the stored whole-file hash
        // identifies the contents that the recorded parts were cut from.
        hash.update(b"syq-s3-whole-v1\0");
        hash.update(metadata.hash_algorithm.as_str().as_bytes());
        hash.update(&[0]);
        hash.update(metadata.hash.as_deref().unwrap_or_default().as_bytes());
        hash.update(&[0]);
        hash.update(&size.to_le_bytes());
        hash.update(&part_size.to_le_bytes());
        return format!("whole:{}", hash.finalize().to_hex());
    }
    hash.update(b"syq-s3-native-parts-v1\0");
    hash.update(&[match algorithm {
        Algorithm::Sha256 => 1,
        Algorithm::Md5 => 2,
        Algorithm::None => unreachable!(),
    }]);
    hash.update(&size.to_le_bytes());
    hash.update(&part_size.to_le_bytes());
    for checksum in checksums {
        hash.update(checksum.as_bytes());
        hash.update(&[0]);
    }
    format!("parts:{}", hash.finalize().to_hex())
}

/// Content-MD5 for a destination that requires upload checksums. Only such
/// destinations pay for this separate read.
async fn content_md5(
    source: &Source,
    small: Option<&bytes::Bytes>,
    offset: u64,
    length: u64,
) -> Result<String> {
    if let Some(bytes) = small {
        let range = &bytes[offset as usize..(offset + length) as usize];
        return Ok(Algorithm::Md5.digest(range).unwrap());
    }
    let source = source.clone();
    tokio::task::spawn_blocking(move || {
        let file = source.open()?;
        let mut hash = Algorithm::Md5.hasher().unwrap();
        let mut buffer = vec![0; length.clamp(1, 1024 * 1024) as usize];
        let mut done = 0;
        while done < length {
            let n = buffer.len().min((length - done) as usize);
            file.read_exact_at(&mut buffer[..n], offset + done)?;
            hash.update(&buffer[..n]);
            done += n as u64;
        }
        source.check(&file)?;
        Ok(hash.finish())
    })
    .await?
}

fn hash_range(file: &File, offset: u64, length: u64, algorithm: HashAlgorithm) -> Result<String> {
    let mut buffer = vec![0; 1024 * 1024];
    let mut done = 0;
    let mut hash = algorithm.hasher();
    while done < length {
        let n = buffer.len().min((length - done) as usize);
        file.read_exact_at(&mut buffer[..n], offset + done)?;
        hash.update(&buffer[..n]);
        done += n as u64;
    }
    Ok(Digest::from_hash(algorithm, &hash.finalize()).value)
}
fn remove_partial(root: &Root, record: &DownloadState) -> Result<()> {
    let path = RelativePath::new(record.partial.as_bytes())?;
    if let Some(m) = root.metadata_optional(&path)? {
        if m.dev != record.dev || m.ino != record.ino || !m.is_file() || m.nlink != 1 {
            bail!("obsolete partial changed identity; refusing to remove it");
        }
        root.unlink(&path)?;
    }
    Ok(())
}

// Downloads without a recovery record have no reusable saved progress. Remove
// their temporary file on failure or cancellation, including a dropped future.
struct PartialCleanup<'a> {
    root: &'a Root,
    path: RelativePath,
    identity: (u64, u64),
}
impl Drop for PartialCleanup<'_> {
    fn drop(&mut self) {
        if self
            .root
            .metadata_optional(&self.path)
            .ok()
            .flatten()
            .is_some_and(|m| (m.dev, m.ino) == self.identity)
        {
            let _ = self.root.unlink(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_upload_identity_binds_parts_algorithm_and_boundaries() {
        let metadata: UploadState =
            serde_json::from_str(include_str!("../../tests/fixtures/s3-upload-v1.json")).unwrap();
        let metadata = metadata.metadata;
        let checksums = vec!["first".to_string(), "second".to_string()];
        let identity = |algorithm, size, part_size, checksums: &[String]| {
            upload_identity(algorithm, size, part_size, checksums, &metadata)
        };
        let native = identity(Algorithm::Sha256, 10, 5, &checksums);
        assert_ne!(native, identity(Algorithm::Md5, 10, 5, &checksums));
        assert_ne!(native, identity(Algorithm::Sha256, 11, 5, &checksums));
        assert_ne!(native, identity(Algorithm::Sha256, 10, 6, &checksums));
        assert_ne!(
            native,
            identity(Algorithm::Sha256, 10, 5, &["second".into(), "first".into()])
        );
        // Without request checksums the stored whole-file hash identifies the
        // contents, together with the part boundaries.
        let whole = identity(Algorithm::None, 10, 5, &[]);
        assert!(whole.starts_with("whole:"), "{whole}");
        assert_eq!(whole, identity(Algorithm::None, 10, 5, &checksums));
        assert_ne!(whole, identity(Algorithm::None, 11, 5, &[]));
        assert_ne!(whole, identity(Algorithm::None, 10, 6, &[]));
        let mut changed = metadata.clone();
        changed.hash = Some("0".repeat(64));
        assert_ne!(
            whole,
            upload_identity(Algorithm::None, 10, 5, &[], &changed)
        );
    }

    #[test]
    fn reads_unchanged_upload_record_from_4be9e58() {
        let fixture = include_str!("../../tests/fixtures/s3-upload-v1.json");
        let record: UploadState = serde_json::from_str(fixture).unwrap();
        assert_eq!(record.schema, 1);
        assert_eq!(record.algorithm, Algorithm::Sha256);
        assert!(record.completed.is_empty());
        assert_eq!(
            serde_json::to_value(&record).unwrap(),
            serde_json::from_str::<serde_json::Value>(fixture).unwrap()
        );
    }

    #[test]
    fn unlisted_checksum_recovery_requires_acknowledged_etag_checksum_and_length() {
        // ETags are opaque. Uploads whose part checksums are not listed (R2's
        // MD5, or none at all) reuse only parts recorded by this source's upload.
        for (algorithm, schema, name, checksum) in [
            (Algorithm::Md5, 2, "md5", "checksum"),
            (Algorithm::None, 3, "none", ""),
        ] {
            let mut record: UploadState =
                serde_json::from_str(include_str!("../../tests/fixtures/s3-upload-v1.json"))
                    .unwrap();
            record.algorithm = algorithm;
            record.schema = record.algorithm.schema();
            record.completed.insert(
                1,
                UploadedPart {
                    etag: "opaque-etag".into(),
                    checksum: checksum.into(),
                    length: 42,
                },
            );
            let value = serde_json::to_value(record).unwrap();
            // Earlier binaries reject this schema or algorithm name.
            assert_eq!(value["schema"], schema);
            assert_eq!(value["algorithm"], name);
            assert_eq!(
                value["completed"]["1"].get("checksum").is_some(),
                !checksum.is_empty()
            );
            let record: UploadState = serde_json::from_value(value).unwrap();
            assert!(record.acknowledged_part(1, "opaque-etag", checksum, 42));
            assert!(!record.acknowledged_part(2, "opaque-etag", checksum, 42));
            assert!(!record.acknowledged_part(1, "replaced-etag", checksum, 42));
            assert!(!record.acknowledged_part(1, "opaque-etag", "changed", 42));
            assert!(!record.acknowledged_part(1, "opaque-etag", checksum, 41));
        }
    }
}

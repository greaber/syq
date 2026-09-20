//! Whole-manifest programmatic streams over shared native stream sessions.
mod channel;
mod manifest;
mod payload;
pub(crate) use payload::Payload;

use crate::{
    cli::{Args, CoordinateAt, Existence, Location},
    descriptor_copy::{self as copy, controls::Controls},
    results::{self, ResultsWriter},
};
use anyhow::{bail, ensure, Context, Result};
use futures_util::{stream, StreamExt};
use manifest::{Endpoint, Entry};
use serde_json::{json, Value};
use std::{
    io::Read,
    sync::{
        atomic::{AtomicBool, Ordering::Relaxed},
        Arc,
    },
};

struct Totals(Value);
impl Totals {
    fn new(dry_run: bool) -> Self {
        Self(
            json!({"type":"result", "status":"success", "exit_code":0, "dry_run":dry_run,
            "files_transferred":0,"files_unchanged":0,"files_excluded":0,"directories_created":0,
            "symlinks_created":0,"specials_created":0,"errors":0,"bytes_transferred":0,
            "bytes_unchanged":0,"elapsed_ms":0}),
        )
    }
    fn add(&mut self, name: &str, value: u64) {
        self.0[name] = (self.0[name].as_u64().unwrap_or(0) + value).into();
    }
    fn phase(&mut self, value: &Value) {
        for name in [
            "files_transferred",
            "files_unchanged",
            "files_excluded",
            "directories_created",
            "symlinks_created",
            "specials_created",
            "errors",
            "bytes_transferred",
            "bytes_unchanged",
        ] {
            self.add(name, value[name].as_u64().unwrap_or(0));
        }
    }
}

pub(crate) fn run(args: Args) -> Result<i32> {
    let started = std::time::Instant::now();
    let writer = results::start(
        &args,
        results::RunMode::Cp {
            prune: false,
            mapping: true,
        },
    )?
    .context("stream mapping requires an automation results descriptor")?;
    let mut totals = Totals::new(args.dry_run);
    let outcome = run_inner(&args, writer.clone(), &mut totals);
    let code = if let Err(error) = &outcome {
        writer.emit_error_classified(&format!("{error:#}"), None, None);
        crate::output::diagnostic!("syq: {error:#}");
        totals.add("errors", 1);
        1
    } else if totals.0["errors"].as_u64().unwrap_or(0) != 0 {
        23
    } else {
        0
    };
    totals.0["status"] = (if code == 0 {
        "success"
    } else if code == 23 {
        "partial"
    } else {
        "failed"
    })
    .into();
    totals.0["exit_code"] = code.into();
    totals.0["elapsed_ms"] = (started.elapsed().as_millis() as u64).into();
    writer.emit_terminal_value(totals.0);
    Ok(if writer.is_dead() { 1 } else { code })
}

fn run_inner(args: &Args, writer: Arc<ResultsWriter>, totals: &mut Totals) -> Result<()> {
    let channel = Arc::new(channel::Channel::connect(args.stream_mapping_fd.unwrap())?);
    let outcome = (|| {
        let mut contents = Vec::new();
        let path = args
            .native_mapping
            .as_deref()
            .context("missing stream mapping manifest")?;
        if path == b"-" {
            std::io::stdin().read_to_end(&mut contents)?;
        } else {
            crate::fsops::open_operator_file_read(
                path,
                if args.native_follow {
                    crate::proto::OperatorSymlinkPolicy::FollowAll
                } else {
                    crate::proto::OperatorSymlinkPolicy::Refuse
                },
            )?
            .read_to_end(&mut contents)?;
        }
        let manifest = manifest::parse(&contents)?;
        validate(args, &manifest)?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()?;
        let mut shared = args.clone();
        if let Some(options) = &args.s3 {
            shared.storage_authorization =
                runtime.block_on(crate::s3::authorization::connect(args, options))?;
        }
        let args = &shared;
        let resources = copy::session::Resources::new(args);
        let mut sessions = Sessions::default();
        let result = (|| {
            // Containers are checked before either phase. Per-entry placement then
            // addresses its final path, without repeating a container's -new test.
            runtime.block_on(sessions.prepare(args, &manifest, resources.clone()))?;
            runtime.block_on(sessions.prepare_storage(args, &manifest.callbacks))?;
            if manifest.paths.entries.is_empty() {
                if let Some(authorization) = &args.storage_authorization {
                    runtime.block_on(authorization.finish())?;
                }
            }
            if !manifest.paths.entries.is_empty() {
                let mut ordinary = args.clone();
                ordinary.stream_mapping_fd = None;
                if manifest.callbacks.iter().any(|e| e.dst.path().is_some()) {
                    ordinary.target_existence = Existence::Any;
                }
                ordinary.parsed_mapping = Some(Arc::new(manifest.paths));
                let phase = ResultsWriter::phase(writer.clone());
                ordinary.results_override = Some(phase.clone());
                ordinary.suppress_summary = true;
                let result = if ordinary.s3.is_some() {
                    crate::s3::run(ordinary)
                } else {
                    crate::transfer::run(ordinary)
                };
                if let Some(record) = phase.take_phase_result() {
                    totals.phase(&record);
                }
                let code = result?;
                ensure!(
                    code == 0 || code == 23,
                    "pathname phase failed with exit status {code}"
                );
            }
            let mut progress = crate::progress::Progress::new(
                !args.quiet && !args.no_progress,
                args.progress,
                None,
            );
            Arc::get_mut(&mut progress).unwrap().stream = true;
            progress.set_results(writer.clone());
            progress
                .bytes_done
                .store(totals.0["bytes_transferred"].as_u64().unwrap(), Relaxed);
            progress
                .files_total
                .store(manifest.callbacks.len() as u64, Relaxed);
            let ordinary_done = totals.0["files_transferred"].as_u64().unwrap();
            let ordinary_unchanged = totals.0["files_unchanged"].as_u64().unwrap();
            let ordinary_excluded = totals.0["files_excluded"].as_u64().unwrap();
            progress.files_total.fetch_add(
                ordinary_done + ordinary_unchanged + ordinary_excluded,
                Relaxed,
            );
            progress.files_done.store(ordinary_done, Relaxed);
            progress.files_unchanged.store(ordinary_unchanged, Relaxed);
            progress.files_excluded.store(ordinary_excluded, Relaxed);
            progress
                .bytes_total
                .store(totals.0["bytes_transferred"].as_u64().unwrap(), Relaxed);
            progress
                .bytes_unchanged
                .store(totals.0["bytes_unchanged"].as_u64().unwrap(), Relaxed);
            let ticker = progress.spawn_ticker();
            let result = runtime.block_on(async {
            let cancelled = Arc::new(AtomicBool::new(false));
            let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
            let entries = stream::iter(manifest.callbacks).map(|entry| {
                let cancelled = cancelled.clone();
                let channel = channel.clone();
                let progress = progress.clone();
                let writer = writer.clone();
                let resources = resources.clone();
                let sessions = &sessions;
                async move {
                    let mut controls = entry_controls(args, &entry, Some(writer));
                    controls.parent_progress = Some(progress);
                    controls.share_bandwidth(resources.bandwidth());
                    let controls = Arc::new(controls);
                    let payload = Arc::new(Payload::new(channel, entry.id));
                    let local_cancel = Arc::new(AtomicBool::new(false));
                    let result = if cancelled.load(Relaxed) { Err(anyhow::anyhow!("stream mapping cancelled before callback admission")) } else {
                        let operation = sessions.execute(args, entry, controls.clone(), payload.clone(), local_cancel.clone(), resources.budget.clone());
                        tokio::pin!(operation);
                        tokio::select! {
                            result = &mut operation => result,
                            _ = async { while !cancelled.load(Relaxed) { tokio::time::sleep(std::time::Duration::from_millis(50)).await; } } => {
                                local_cancel.store(true, Relaxed);
                                operation.await
                            }
                        }
                    };
                    let result = result.and_then(|()| payload.transferred(None));
                    if let Err(error) = &result { let _ = payload.transferred(Some(error)); }
                    controls.finish(result.as_ref().err());
                    (controls, result.is_ok())
                }
            }).buffer_unordered(args.stream_concurrency);
            tokio::pin!(entries);
            let signal = async { tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} } };
            tokio::pin!(signal);
            loop {
                let next = tokio::select! {
                    next = entries.next() => next,
                    _ = &mut signal, if !cancelled.load(Relaxed) => { cancelled.store(true, Relaxed); continue; }
                };
                let Some((controls, success)) = next else { break; };
                let skipped = success && controls.report.skipped();
                totals.add("files_transferred", u64::from(success && !skipped));
                totals.add("files_excluded", u64::from(skipped));
                totals.add("errors", u64::from(!success));
                totals.add("bytes_transferred", controls.progress.bytes_done.load(Relaxed));
                progress.files_done.fetch_add(u64::from(success && !skipped), Relaxed);
                progress.files_excluded.fetch_add(u64::from(skipped), Relaxed);
                progress.errors.fetch_add(u64::from(!success), Relaxed);
            }
            Ok::<_, anyhow::Error>(())
        });
            progress.stop();
            if let Some(ticker) = ticker {
                let _ = ticker.join();
            }
            if args.stats && !args.quiet {
                crate::output::diagnostic!("mapping complete: {} bytes transferred, {} unchanged files, {} excluded files, {} errors", totals.0["bytes_transferred"], totals.0["files_unchanged"], totals.0["files_excluded"], totals.0["errors"]);
            }
            result
        })();
        runtime.block_on(sessions.cleanup_storage(args));
        result
    })();
    let ended = channel.send(channel::Message::End, &[]);
    outcome.and(ended)
}

fn entry_controls(args: &Args, entry: &Entry, writer: Option<Arc<ResultsWriter>>) -> Controls {
    let mut per_entry = entry_args(args);
    per_entry.stats = false;
    let report = copy::report::Report::entry(
        &per_entry,
        entry.id,
        writer,
        entry.src.json(entry.id),
        entry.dst.json(entry.id),
    );
    let mut controls = Controls::new(&per_entry, report);
    controls.metadata.overrides = entry.metadata;
    controls.expected = copy::check::Expected {
        size: match entry.src {
            Endpoint::Callback { size } => size,
            _ => None,
        },
        hash: entry.expected_hash.clone(),
    };
    if let Some(size) = controls.expected.size {
        controls.set_size(size);
    }
    controls
}

fn entry_args(args: &Args) -> Args {
    let mut args = args.clone();
    args.times = args.stream_preserve_times;
    args.no_progress = true;
    args
}
fn validate(args: &Args, manifest: &manifest::Manifest) -> Result<()> {
    ensure!(
        !args.detach && matches!(args.coordinate_at, CoordinateAt::Auto | CoordinateAt::Local),
        "Stream callbacks run on the invoking machine; use --coordinate-at local"
    );
    ensure!(!args.locations.iter().any(|l| l.host.as_deref().is_some_and(|h| h.starts_with('@'))), "callback mappings require unrestricted endpoints; named receiver grants authorize pathname entries");
    ensure!(
        !args.delete,
        "callback mappings cannot prune a tree: byte streams do not describe its complete contents"
    );
    ensure!(!args.inplace, "callback mappings publish only after the producer succeeds; --inplace cannot provide that behavior");
    ensure!(!args.checksum, "callback mappings cannot compare content before invoking producers; use expected_hash to check produced bytes");
    ensure!(
        args.ignore.is_empty() && args.ignore_from.is_empty() && args.ignore_lines.is_empty(),
        "callback mappings have no source tree to filter; filter the mapping entries in the script"
    );
    ensure!(
        args.min_size.is_none() && args.max_size.is_none(),
        "callback mappings require explicit entry selection; filter promised sizes in the script"
    );
    if !manifest.paths.entries.is_empty()
        && args.locations.iter().all(|l| l.host.is_some())
        && args.s3.as_ref().is_none_or(|o| !o.route.is_server_copy())
    {
        ensure!(args.coordinate_at == CoordinateAt::Local, "mixed remote pathname copies require --coordinate-at local; callbacks must not silently change the data route");
    }
    let mut controls_args = entry_args(args);
    copy::validate_controls(&mut controls_args)?;
    let metadata = copy::metadata::Policy::new(&controls_args);
    for entry in &manifest.callbacks {
        for (endpoint, location, base) in [
            (
                &entry.src,
                &args.locations[0],
                args.native_source_root
                    .as_deref()
                    .or(args.native_source_cwd.as_deref()),
            ),
            (
                &entry.dst,
                args.locations.last().unwrap(),
                Some(args.locations.last().unwrap().path.as_slice()),
            ),
        ] {
            if location
                .host
                .as_deref()
                .is_some_and(|host| host.starts_with("s3://"))
            {
                if let Some(path) = endpoint.path() {
                    crate::s3::stream::source_key(path, base)?;
                }
            }
        }
        if entry.src.callback() {
            metadata.source(None)?;
        }
        if entry.dst.callback() {
            metadata.output(false)?;
            ensure!(!args.update, "--skip-newer requires a named destination; a callback consumer has no destination timestamp");
        }
    }
    Ok(())
}

#[derive(Default)]
struct Sessions {
    prepared: std::sync::Mutex<
        std::collections::HashMap<u64, Result<crate::s3::stream::Prepared, String>>,
    >,
    files: std::collections::HashMap<String, Arc<copy::session::Session>>,
    objects: std::collections::HashMap<String, Arc<crate::s3::stream::Session>>,
}
fn identity(location: &Location) -> String {
    format!(
        "{:?}:{:?}:{:?}",
        location.user, location.host, location.port
    )
}
impl Sessions {
    async fn prepare(
        &mut self,
        args: &Args,
        manifest: &manifest::Manifest,
        resources: Arc<copy::session::Resources>,
    ) -> Result<()> {
        let source = &args.locations[0];
        let destination = args.locations.last().unwrap();
        for location in [source, destination] {
            let needed = if std::ptr::eq(location, source) {
                manifest.callbacks.iter().any(|e| e.src.path().is_some())
            } else {
                manifest.callbacks.iter().any(|e| e.dst.path().is_some())
            };
            if !needed {
                continue;
            }
            let id = identity(location);
            if location
                .host
                .as_deref()
                .is_some_and(|h| h.starts_with("s3://"))
            {
                if self.objects.contains_key(&id) {
                    continue;
                }
                let mut entry_args = entry_args(args);
                let mut options = args.s3.clone().context("missing S3 options")?;
                options.bucket = location
                    .host
                    .as_deref()
                    .unwrap()
                    .trim_start_matches("s3://")
                    .into();
                entry_args.s3 = Some(options.clone());
                copy::validate_controls(&mut entry_args)?;
                options = entry_args.s3.clone().unwrap();
                let report =
                    copy::report::Report::entry(&entry_args, 0, None, Value::Null, Value::Null);
                let mut controls = Controls::new(&entry_args, report);
                controls.share_bandwidth(resources.bandwidth());
                let mut session = crate::s3::stream::Session::connect(
                    options,
                    &controls,
                    args.storage_authorization.clone(),
                )
                .await?;
                if let Some(other) = self.objects.values().next() {
                    session.share_admission(other);
                }
                self.objects.insert(id, Arc::new(session));
            } else if let std::collections::hash_map::Entry::Vacant(slot) = self.files.entry(id) {
                let (args, location, resources) =
                    (entry_args(args), location.clone(), resources.clone());
                let session = tokio::task::spawn_blocking(move || {
                    copy::session::Session::connect_shared(&args, &location, resources)
                })
                .await??;
                slot.insert(session);
            }
        }
        if manifest.callbacks.iter().any(|e| e.dst.path().is_some()) {
            if let Some(session) = self.objects.get(&identity(destination)) {
                session
                    .check_container(&destination.path, args.target_existence)
                    .await?;
            } else {
                let session = self.files[&identity(destination)].clone();
                let path = destination.path.clone();
                let existence = args.target_existence;
                let follow = args.follows_native_destination_paths();
                tokio::task::spawn_blocking(move || -> Result<()> {
                    let response = crate::conn::ok(
                        session.call(crate::proto::Request::CheckOperatorDirectory {
                            path,
                            allow_missing: existence != Existence::Existing,
                            symlink_policy: if follow {
                                crate::proto::OperatorSymlinkPolicy::FollowAll
                            } else {
                                crate::proto::OperatorSymlinkPolicy::Refuse
                            },
                        })?,
                        "mapping destination container",
                    )?;
                    let crate::proto::Response::DirectorySelection(anchor) = response else {
                        bail!("unexpected destination container response");
                    };
                    ensure!(
                        existence != Existence::New || anchor.is_none(),
                        "destination container already exists"
                    );
                    Ok(())
                })
                .await??;
            }
        }
        Ok(())
    }
    async fn prepare_storage(&self, args: &Args, entries: &[Entry]) -> Result<()> {
        if args.storage_authorization.is_none() {
            return Ok(());
        }
        for entry in entries {
            if entry.src.callback() && entry.dst.callback() {
                continue;
            }
            let upload = entry.src.callback();
            let location = if upload {
                args.locations.last().unwrap()
            } else {
                &args.locations[0]
            };
            let Some(session) = self.objects.get(&identity(location)) else {
                continue;
            };
            let path = if upload {
                entry.dst.path().unwrap()
            } else {
                entry.src.path().unwrap()
            };
            let base = if upload {
                Some(location.path.as_slice())
            } else {
                args.native_source_root
                    .as_deref()
                    .or(args.native_source_cwd.as_deref())
            };
            let key = crate::s3::stream::source_key(path, base)?;
            let controls = entry_controls(args, entry, None);
            let prepared = session
                .prepare_callback(key, upload, &controls)
                .await
                .and_then(|p| p.context("missing stream authorization preparation"))
                .map_err(|e| format!("{e:#}"));
            self.prepared.lock().unwrap().insert(entry.id, prepared);
        }
        Ok(())
    }

    async fn cleanup_storage(&self, args: &Args) {
        let prepared = std::mem::take(&mut *self.prepared.lock().unwrap());
        let Some(session) = self.objects.get(&identity(args.locations.last().unwrap())) else {
            return;
        };
        for (_, prepared) in prepared {
            if let Ok(crate::s3::stream::Prepared::Upload {
                key, id: Some(id), ..
            }) = prepared
            {
                if let Err(error) = session.abort(&key, &id).await {
                    crate::output::diagnostic!(
                        "syq: unused stream upload cleanup failed for {key:?}: {error}"
                    );
                }
            }
        }
    }

    async fn execute(
        &self,
        args: &Args,
        entry: Entry,
        controls: Arc<Controls>,
        payload: Arc<Payload>,
        cancelled: Arc<AtomicBool>,
        budget: Arc<tokio::sync::Semaphore>,
    ) -> Result<()> {
        if entry.src.callback() && entry.dst.callback() {
            if controls.report.only_new {
                controls.report.skip();
                return Ok(());
            }
            if args.dry_run {
                return Ok(());
            }
            let (input, producer) = payload.open(true, cancelled.clone())?;
            let (output, consumer) = payload.open(false, cancelled)?;
            copy::parallel::direct(input, output, Some(producer), controls, Some(budget)).await?;
            payload.transferred(None)?;
            return copy::fd::await_commit(Some(consumer)).await;
        }
        let upload = entry.src.callback();
        let location = if upload {
            args.locations.last().unwrap()
        } else {
            &args.locations[0]
        };
        let path = if upload {
            entry.dst.path().unwrap()
        } else {
            entry.src.path().unwrap()
        };
        let base = if upload {
            Some(location.path.as_slice())
        } else {
            args.native_source_root
                .as_deref()
                .or(args.native_source_cwd.as_deref())
        };
        let mut location = location.clone();
        location.path = if !upload && args.native_source_root.is_some() {
            path.to_vec()
        } else {
            join(base.unwrap_or(b"."), path)
        };
        if let Some(session) = self.objects.get(&identity(&location)) {
            let key = crate::s3::stream::source_key(path, base)?;
            let prepared = self
                .prepared
                .lock()
                .unwrap()
                .remove(&entry.id)
                .transpose()
                .map_err(anyhow::Error::msg)?;
            return session
                .callback(key, upload, controls, payload, cancelled, prepared)
                .await;
        }
        let session = self.files[&identity(&location)].clone();
        let plan = copy::Plan {
            source: upload.then_some(copy::fd::Source::Descriptor(-1)),
            as_fd: None,
            commit_fd: None,
            location: Some(location),
            key: None,
            follow: if upload {
                args.follows_native_destination_paths()
            } else {
                args.follows_native_source_paths()
            },
            root: (!upload).then(|| args.native_source_root.clone()).flatten(),
            placement: Default::default(),
        };
        copy::parallel::execute(
            session,
            plan,
            controls,
            cancelled,
            None,
            None,
            None,
            None,
            Some(payload),
        )
        .await
    }
}
fn join(base: &[u8], path: &[u8]) -> Vec<u8> {
    if base.is_empty() || base == b"." {
        return path.to_vec();
    }
    let mut result = base.to_vec();
    if !result.ends_with(b"/") {
        result.push(b'/');
    }
    result.extend_from_slice(path);
    result
}

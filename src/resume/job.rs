use super::{
    command::{Bytes, Command},
    store::{cache_directory, Store},
};
use crate::proto::{Entry, Kind, Meta, PathBytes};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, ffi::OsString, path::Path, sync::Mutex};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub(super) enum Record {
    Command {
        command: Command,
    },
    Observed {
        path: Bytes,
        original: Option<Entry>,
    },
    Published {
        path: Bytes,
        dev: u64,
        ino: u64,
    },
    DirectoryMetadata {
        path: Bytes,
        meta: Meta,
        flags: u8,
    },
    RemoveIntent {
        path: Bytes,
        dev: u64,
        ino: u64,
        kind: Kind,
        ctime: Option<(i64, u32)>,
    },
    Removed {
        path: Bytes,
    },
    DeleteReserved {
        path: Bytes,
    },
    Inputs {
        ignore: Vec<String>,
        mapping: Option<Bytes>,
    },
    ObjectObserved {
        path: Bytes,
        identity: Option<String>,
    },
    ObjectPublished {
        path: Bytes,
        identity: String,
    },
    ObjectRemoveIntent {
        path: Bytes,
        identity: String,
    },
    DirectoryMode {
        path: Bytes,
        mode: Option<u32>,
    },
    Invalid,
}

type RemovalIdentity = (u64, u64, Kind, Option<(i64, u32)>);

#[derive(Clone, Debug, Default)]
pub(super) struct EntryState {
    pub observed: bool,
    pub original: Option<Entry>,
    pub published: Option<(u64, u64)>,
    pub directory_metadata: Option<(Meta, u8)>,
    pub removal: Option<RemovalIdentity>,
    pub removed: bool,
    // Set only after replay, never by removals in the current attempt.
    pub removed_before_attempt: bool,
    pub object_original: Option<Option<String>>,
    pub object_published: Option<String>,
    pub object_removal: Option<String>,
    pub directory_mode: Option<Option<u32>>,
}

#[derive(Default)]
struct Replay {
    command: Option<Command>,
    entries: HashMap<PathBytes, EntryState>,
    invalid: bool,
    deletes: std::collections::HashSet<PathBytes>,
    inputs: Option<(Vec<String>, Option<Bytes>)>,
}
impl Replay {
    fn start_attempt(&mut self) {
        for entry in self.entries.values_mut() {
            entry.removed_before_attempt = entry.removed;
        }
    }
    fn apply(&mut self, record: Record) -> Result<()> {
        match record {
            Record::Command { command } => {
                if self.command.is_some() || !self.entries.is_empty() {
                    bail!("job has more than one saved command");
                }
                self.command = Some(command);
            }
            Record::Invalid => self.invalid = true,
            Record::DeleteReserved { path } => {
                self.deletes.insert(path.decode()?);
            }
            Record::Inputs { ignore, mapping } => self.inputs = Some((ignore, mapping)),
            record => {
                if self.command.is_none() {
                    bail!("job entries precede the saved command");
                }
                match record {
                    Record::ObjectObserved { path, identity } => {
                        self.entries
                            .entry(path.decode()?)
                            .or_default()
                            .object_original
                            .get_or_insert(identity);
                    }
                    Record::ObjectPublished { path, identity } => {
                        self.entries
                            .entry(path.decode()?)
                            .or_default()
                            .object_published = Some(identity);
                    }
                    Record::ObjectRemoveIntent { path, identity } => {
                        self.entries
                            .entry(path.decode()?)
                            .or_default()
                            .object_removal
                            .get_or_insert(identity);
                    }
                    Record::DirectoryMode { path, mode } => {
                        self.entries
                            .entry(path.decode()?)
                            .or_default()
                            .directory_mode
                            .get_or_insert(mode);
                    }
                    Record::Observed { path, original } => {
                        let entry = self.entries.entry(path.decode()?).or_default();
                        if !entry.observed {
                            entry.original = original;
                            entry.observed = true;
                        }
                    }
                    Record::Published { path, dev, ino } => {
                        self.entries.entry(path.decode()?).or_default().published = Some((dev, ino))
                    }
                    Record::DirectoryMetadata { path, meta, flags } => {
                        let entry = self.entries.entry(path.decode()?).or_default();
                        // Preserve the original final metadata, including a mode
                        // temporarily changed to make a directory writable.
                        entry.directory_metadata.get_or_insert((meta, flags));
                    }
                    Record::RemoveIntent {
                        path,
                        dev,
                        ino,
                        kind,
                        ctime,
                    } => {
                        self.entries
                            .entry(path.decode()?)
                            .or_default()
                            .removal
                            .get_or_insert((dev, ino, kind, ctime));
                    }
                    Record::Removed { path } => {
                        self.entries.entry(path.decode()?).or_default().removed = true
                    }
                    Record::Command { .. }
                    | Record::DeleteReserved { .. }
                    | Record::Inputs { .. }
                    | Record::Invalid => unreachable!(),
                }
            }
        }
        Ok(())
    }
}

struct State {
    store: Store,
    replay: Replay,
    available: bool,
    pending: Vec<Record>,
}

pub(crate) struct Job {
    pub id: String,
    pub resumed: bool,
    pub copy_id: crate::proto::CopyId,
    state: Mutex<State>,
}
impl std::fmt::Debug for Job {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("Job")
            .field("id", &self.id)
            .field("resumed", &self.resumed)
            .finish_non_exhaustive()
    }
}
impl Job {
    pub fn create(argv: &[OsString]) -> Result<Self> {
        Self::create_at(&cache_directory()?, argv)
    }
    fn create_at(base: &Path, argv: &[OsString]) -> Result<Self> {
        let command = Command::new(argv)?;
        let id = id_string(command.copy_id);
        let mut store = Store::open::<Record>(base, &id, "command", true, |_| Ok(()))?;
        let copy_id = command.copy_id;
        let record = Record::Command { command };
        if let Err(error) = store.append(std::slice::from_ref(&record)) {
            let _ = store.remove();
            return Err(error);
        }
        let mut replay = Replay::default();
        replay.apply(record)?;
        Ok(Self {
            id,
            resumed: false,
            copy_id,
            state: Mutex::new(State {
                store,
                replay,
                available: true,
                pending: Vec::new(),
            }),
        })
    }
    pub fn open(id: &str) -> Result<Self> {
        Self::open_at(&cache_directory()?, id)
    }
    fn open_at(base: &Path, id: &str) -> Result<Self> {
        let mut replay = Replay::default();
        let store = Store::open(base, id, "command", false, |record| replay.apply(record))?;
        replay.start_attempt();
        let command = replay
            .command
            .as_ref()
            .context("job has no saved command")?;
        if replay.invalid {
            bail!("job {id} cannot be resumed because recording failed during an earlier attempt");
        }
        let copy_id = command.copy_id;
        if id_string(copy_id) != id {
            bail!("saved job ID does not match its record");
        }
        Ok(Self {
            id: id.to_owned(),
            resumed: true,
            copy_id,
            state: Mutex::new(State {
                store,
                replay,
                available: true,
                pending: Vec::new(),
            }),
        })
    }
    pub fn endpoint(id: &str, role: &str, resumed: bool) -> Result<Self> {
        let base = cache_directory()?;
        Self::endpoint_at(&base, id, role, resumed)
    }
    pub(crate) fn endpoint_at(base: &Path, id: &str, role: &str, resumed: bool) -> Result<Self> {
        let mut replay = Replay::default();
        let mut store = Store::open(base, id, role, !resumed, |record| replay.apply(record))?;
        replay.start_attempt();
        if !resumed {
            let mut command = Command::new(&["rm".into()])?;
            command.copy_id = parse_id(id)?;
            let record = Record::Command { command };
            store.append(std::slice::from_ref(&record))?;
            replay.apply(record)?;
        }
        let copy_id = replay
            .command
            .as_ref()
            .context("endpoint job has no header")?
            .copy_id;
        if id_string(copy_id) != id || replay.invalid {
            bail!("endpoint job is not resumable");
        }
        Ok(Self {
            id: id.to_owned(),
            resumed,
            copy_id,
            state: Mutex::new(State {
                store,
                replay,
                available: true,
                pending: Vec::new(),
            }),
        })
    }
    pub fn save_inputs(&self, args: &mut crate::cli::Args) -> Result<()> {
        if self.state.lock().unwrap().replay.inputs.is_some() {
            return Ok(());
        }
        args.read_copy_inputs()?;
        let mapping = if args.native_mapping.is_some() {
            let parsed = crate::mapping::load(args)?;
            let bytes = Bytes::new(&parsed.input.contents);
            args.parsed_mapping = Some(parsed);
            Some(bytes)
        } else {
            None
        };
        self.record(vec![Record::Inputs {
            ignore: args.ignore_lines.clone(),
            mapping,
        }]);
        Ok(())
    }
    pub fn restore_inputs(&self, args: &mut crate::cli::Args) -> Result<()> {
        if let Some((ignore, mapping)) = &self.state.lock().unwrap().replay.inputs {
            args.restore_resume_ignore(ignore.clone());
            if let Some(mapping) = mapping {
                args.parsed_mapping = Some(std::sync::Arc::new(
                    crate::mapping::read_mapping_manifest(mapping.decode()?)?,
                ));
            }
        }
        Ok(())
    }
    pub fn deletion_total(&self, paths: &[PathBytes]) -> u64 {
        let state = self.state.lock().unwrap();
        state.replay.deletes.len() as u64
            + paths
                .iter()
                .filter(|path| !state.replay.deletes.contains(*path))
                .count() as u64
    }
    pub fn reserve_deletions(&self, paths: &[PathBytes]) {
        self.record(
            paths
                .iter()
                .map(|path| Record::DeleteReserved {
                    path: Bytes::new(path),
                })
                .collect(),
        );
    }
    pub fn observe(&self, entries: impl IntoIterator<Item = (PathBytes, Option<Entry>)>) {
        let records = {
            let state = self.state.lock().unwrap();
            if !state.available {
                return;
            }
            entries
                .into_iter()
                .filter(|(path, _)| {
                    !state
                        .replay
                        .entries
                        .get(path)
                        .is_some_and(|entry| entry.observed)
                })
                .map(|(path, original)| Record::Observed {
                    path: Bytes::new(&path),
                    original,
                })
                .collect()
        };
        self.record(records);
    }
    pub fn published(&self, entries: impl IntoIterator<Item = (PathBytes, (u64, u64))>) {
        self.record(
            entries
                .into_iter()
                .map(|(path, (dev, ino))| Record::Published {
                    path: Bytes::new(&path),
                    dev,
                    ino,
                })
                .collect(),
        );
    }
    pub fn owns_created(&self, path: &[u8], current: Option<&Entry>) -> bool {
        if !self.resumed || !self.available() {
            return false;
        }
        self.entry(path).is_some_and(|previous| {
            previous.observed
                && previous.original.is_none()
                && current
                    .is_some_and(|current| previous.published == Some((current.dev, current.ino)))
        })
    }
    pub fn original(&self, path: &[u8]) -> Option<Option<Entry>> {
        self.entry(path)
            .filter(|entry| entry.observed)
            .map(|entry| entry.original)
    }
    pub fn directory_metadata(&self, path: &[u8]) -> Option<(Meta, u8)> {
        self.entry(path)?.directory_metadata
    }
    pub fn save_directory_metadata(&self, values: impl IntoIterator<Item = (PathBytes, Meta, u8)>) {
        let records = {
            let state = self.state.lock().unwrap();
            values
                .into_iter()
                .filter(|(path, _, _)| {
                    state
                        .replay
                        .entries
                        .get(path)
                        .is_none_or(|entry| entry.directory_metadata.is_none())
                })
                .map(|(path, meta, flags)| Record::DirectoryMetadata {
                    path: Bytes::new(&path),
                    meta,
                    flags,
                })
                .collect()
        };
        self.record(records);
    }
    pub fn before_remove(
        &self,
        path: &[u8],
        dev: u64,
        ino: u64,
        kind: Kind,
        ctime: Option<(i64, u32)>,
        dry_run: bool,
    ) -> Result<bool> {
        if let Some(previous) = self.entry(path) {
            if previous.removed {
                // A directory rescan in this attempt keeps ordinary rm
                // semantics. Only prior attempts protect recreated paths.
                return Ok(!previous.removed_before_attempt);
            }
            if previous
                .removal
                .is_some_and(|identity| identity != (dev, ino, kind, ctime))
            {
                bail!(
                    "entry changed since the earlier removal attempt: {}",
                    crate::completion_details::display_bytes(path)
                );
            }
            if previous.removal.is_some() {
                return Ok(true);
            }
        }
        if !dry_run {
            self.record(vec![Record::RemoveIntent {
                path: Bytes::new(path),
                dev,
                ino,
                kind,
                ctime,
            }]);
        }
        Ok(true)
    }
    pub fn removed(&self, path: &[u8]) {
        let flush = {
            let mut state = self.state.lock().unwrap();
            if !state.available {
                return;
            }
            let record = Record::Removed {
                path: Bytes::new(path),
            };
            // Intent was persisted before unlinking. Outcomes can be batched:
            // a retry checks the recorded identity if the final batch is lost.
            state
                .replay
                .apply(record.clone())
                .expect("locally constructed record");
            state.pending.push(record);
            state.pending.len() >= 256
        };
        if flush {
            self.flush();
        }
    }
    pub fn flush(&self) {
        let pending = std::mem::take(&mut self.state.lock().unwrap().pending);
        if !pending.is_empty() {
            self.record(pending);
        }
    }
    pub fn observe_removals(
        &self,
        entries: impl IntoIterator<Item = (PathBytes, u64, u64, Kind, Option<(i64, u32)>)>,
    ) {
        let records = {
            let state = self.state.lock().unwrap();
            entries
                .into_iter()
                .filter(|(path, ..)| {
                    state
                        .replay
                        .entries
                        .get(path)
                        .is_none_or(|entry| entry.removal.is_none())
                })
                .map(|(path, dev, ino, kind, ctime)| Record::RemoveIntent {
                    path: Bytes::new(&path),
                    dev,
                    ino,
                    kind,
                    ctime,
                })
                .collect()
        };
        self.record(records);
    }
    pub fn object_original(&self, path: &[u8]) -> Option<Option<String>> {
        self.entry(path)?.object_original
    }
    pub fn bind_scope(&self, path: &[u8], identity: String) -> Result<()> {
        if let Some(previous) = self.object_original(path) {
            anyhow::ensure!(
                previous.as_ref() == Some(&identity),
                "endpoint settings changed since the job began"
            );
        } else {
            self.observe_object(path, Some(identity));
        }
        Ok(())
    }
    pub fn observe_object(&self, path: &[u8], identity: Option<String>) {
        if self
            .entry(path)
            .is_none_or(|entry| entry.object_original.is_none())
        {
            self.record(vec![Record::ObjectObserved {
                path: Bytes::new(path),
                identity,
            }]);
        }
    }
    pub fn published_object(&self, path: &[u8], identity: String) {
        self.record(vec![Record::ObjectPublished {
            path: Bytes::new(path),
            identity,
        }]);
    }
    pub fn owns_object(&self, path: &[u8], identity: Option<&str>) -> bool {
        self.resumed
            && self.available()
            && self.entry(path).is_some_and(|entry| {
                entry.object_original == Some(None)
                    && identity.is_some()
                    && entry.object_published.as_deref() == identity
            })
    }
    pub fn has_created_objects_beneath(&self, prefix: &[u8]) -> bool {
        let state = self.state.lock().unwrap();
        self.resumed
            && state.available
            && state.replay.entries.iter().any(|(path, entry)| {
                path.starts_with(prefix)
                    && entry.object_original == Some(None)
                    && entry.object_published.is_some()
            })
    }
    pub fn was_removed(&self, path: &[u8]) -> bool {
        self.entry(path)
            .is_some_and(|entry| entry.removed_before_attempt)
    }
    #[cfg(test)]
    pub fn before_remove_object(&self, path: &[u8], identity: &str, dry_run: bool) -> Result<bool> {
        Ok(self.prepare_object_removals(&[(path.to_vec(), identity.to_owned())], dry_run)?[0])
    }
    pub fn prepare_object_removals(
        &self,
        entries: &[(Vec<u8>, String)],
        dry_run: bool,
    ) -> Result<Vec<bool>> {
        let mut records = Vec::new();
        let mut selected = Vec::with_capacity(entries.len());
        {
            let state = self.state.lock().unwrap();
            for (path, identity) in entries {
                let entry = state.replay.entries.get(path);
                if let Some(entry) = entry.filter(|entry| entry.removed) {
                    selected.push(!entry.removed_before_attempt);
                    continue;
                }
                if let Some(previous) = entry.and_then(|entry| entry.object_removal.as_ref()) {
                    anyhow::ensure!(
                        previous == identity,
                        "object changed since the earlier removal attempt: {}",
                        crate::completion_details::display_bytes(path)
                    );
                } else if !dry_run {
                    records.push(Record::ObjectRemoveIntent {
                        path: Bytes::new(path),
                        identity: identity.clone(),
                    });
                }
                selected.push(true);
            }
        }
        if !records.is_empty() {
            self.record(records);
        }
        Ok(selected)
    }
    pub fn original_directory_mode(
        &self,
        path: &[u8],
        mode: Option<u32>,
        dry_run: bool,
    ) -> Option<u32> {
        if let Some(previous) = self.entry(path).and_then(|entry| entry.directory_mode) {
            return previous;
        }
        if !dry_run {
            self.record(vec![Record::DirectoryMode {
                path: Bytes::new(path),
                mode,
            }]);
        }
        mode
    }
    pub fn arguments(&self, overrides: &[OsString]) -> Result<(Vec<OsString>, std::path::PathBuf)> {
        self.state
            .lock()
            .unwrap()
            .replay
            .command
            .as_ref()
            .unwrap()
            .arguments(overrides)
    }
    pub fn available(&self) -> bool {
        self.state.lock().unwrap().available
    }
    pub fn disable(&self, reason: &str) {
        let mut state = self.state.lock().unwrap();
        if state.available {
            state.available = false;
            let _ = state.store.append(&[Record::Invalid]);
            let _ = state.store.remove();
            crate::output::diagnostic!("syq: job {} is not resumable: {reason}", self.id);
        }
    }
    pub fn complete(&self) {
        self.flush();
        let state = self.state.lock().unwrap();
        if let Err(error) = state.store.remove() {
            crate::output::diagnostic!(
                "syq: could not remove completed job {}: {error:#}",
                self.id
            );
        }
    }
    pub(super) fn entry(&self, path: &[u8]) -> Option<EntryState> {
        self.state.lock().unwrap().replay.entries.get(path).cloned()
    }
    /// Journal failure disables this optional aid, not the ordinary operation.
    /// Removing the token file prevents later use of incomplete observations.
    pub(super) fn record(&self, records: Vec<Record>) -> bool {
        let mut state = self.state.lock().unwrap();
        if !state.available {
            return false;
        }
        let result = (|| -> Result<()> {
            let mut records = records.into_iter();
            loop {
                let batch: Vec<_> = records.by_ref().take(256).collect();
                if batch.is_empty() {
                    break;
                }
                state.store.append(&batch)?;
                for record in batch {
                    state.replay.apply(record)?;
                }
            }
            Ok(())
        })();
        if let Err(error) = result {
            state.available = false;
            let invalidated = state
                .store
                .remove()
                .or_else(|_| state.store.append(&[Record::Invalid]));
            crate::output::diagnostic!("syq: job {} is no longer resumable: {error:#}", self.id);
            if let Err(error) = invalidated {
                crate::output::diagnostic!(
                    "syq: could not invalidate stale job {}: {error:#}; do not resume this job",
                    self.id
                );
            }
            return false;
        }
        true
    }
}

fn id_string(id: crate::proto::CopyId) -> String {
    id.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn parse_id(id: &str) -> Result<crate::proto::CopyId> {
    if !super::store::valid_id(id) {
        bail!("invalid job ID");
    }
    let mut result = [0; 16];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&id[index * 2..index * 2 + 2], 16)?;
    }
    Ok(result)
}

impl Drop for Job {
    fn drop(&mut self) {
        self.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn object_publications_and_removals_survive_reopening() {
        let temp = crate::test_support::tempdir().unwrap();
        let base = temp.path().join("jobs");
        let job = Job::create_at(&base, &["cp".into(), "file".into()]).unwrap();
        let id = job.id.clone();
        job.observe_object(b"created", None);
        job.published_object(b"created", "etag/version".into());
        job.observe_object(b"preexisting", Some("original".into()));
        job.published_object(b"preexisting", "etag/version".into());
        assert!(job.before_remove_object(b"removed", "old", false).unwrap());
        job.removed(b"removed");
        assert!(!job.was_removed(b"removed"));
        assert!(job
            .before_remove_object(b"removed", "replacement", false)
            .unwrap());
        assert!(job
            .before_remove_object(b"uncertain", "old", false)
            .unwrap());
        drop(job);
        let job = Job::open_at(&base, &id).unwrap();
        assert!(job.was_removed(b"removed"));
        assert!(job.owns_object(b"created", Some("etag/version")));
        assert!(!job.owns_object(b"created", Some("replacement")));
        assert!(!job.owns_object(b"preexisting", Some("etag/version")));
        assert!(!job
            .before_remove_object(b"removed", "replacement", false)
            .unwrap());
        assert!(job
            .before_remove_object(b"uncertain", "old", false)
            .unwrap());
        assert!(job
            .before_remove_object(b"uncertain", "replacement", false)
            .is_err());
    }
    #[test]
    fn reopens_command_and_entry_history_then_removes_completed_job() {
        let temp = crate::test_support::tempdir().unwrap();
        let base = temp.path().join("jobs");
        let job = Job::create_at(&base, &["rm".into(), "files".into()]).unwrap();
        let id = job.id.clone();
        assert!(job.record(vec![
            Record::RemoveIntent {
                path: Bytes::new(b"files/a"),
                dev: 1,
                ino: 20,
                kind: Kind::File,
                ctime: None
            },
            Record::Removed {
                path: Bytes::new(b"files/a")
            }
        ]));
        drop(job);
        let job = Job::open_at(&base, &id).unwrap();
        assert!(job.resumed && job.available());
        let entry = job.entry(b"files/a").unwrap();
        assert!(entry.removed);
        assert_eq!(entry.removal, Some((1, 20, Kind::File, None)));
        assert_eq!(
            job.arguments(&[]).unwrap().0,
            [OsString::from("rm"), OsString::from("files")]
        );
        job.complete();
        drop(job);
        assert!(Job::open_at(&base, &id).is_err());
    }
}

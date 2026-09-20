use super::*;
use crate::s3::prune::{self, Plan};
use std::collections::BTreeSet;

struct Candidate {
    path: Vec<u8>,
    // An S3 marker retains its trailing slash; local directories do not.
    key: Option<String>,
    kind: &'static str,
    identity: Option<(u64, u64)>,
}

impl Engine {
    pub(super) async fn prune(
        &self,
        mut plan: Plan,
        destination: Option<&Destination>,
    ) -> Result<()> {
        self.check_cancelled()?;
        if !self.args.delete {
            return Ok(());
        }
        if self.progress.errors.load(Relaxed) != 0 {
            self.progress
                .eprintln("syq: copy or scan reported errors; skipping deletions");
            return Ok(());
        }
        if plan.scopes.is_empty() {
            return Ok(());
        }
        let found = match self.deletion_candidates(&mut plan, destination).await {
            Ok(found) => found,
            Err(error) => {
                self.check_cancelled()?;
                self.progress.error(&format!("plan deletions: {error:#}"));
                self.progress
                    .eprintln("syq: destination walk reported errors; skipping deletions");
                return Ok(());
            }
        };
        let count = found.len() as u64;
        self.progress.deletions_planned.store(count, Relaxed);
        if self.args.max_delete.is_some_and(|max| count > max) {
            self.progress.deletions_blocked.store(count, Relaxed);
            for c in &found {
                self.deletion_record(c, "blocked", Some("safety_limit"), None);
            }
            return Err(prune::Limit.into());
        }
        if destination.is_none() && !self.args.dry_run {
            self.delete_objects(&found).await?;
        } else {
            for candidate in found {
                self.check_cancelled()?;
                let result = if self.args.dry_run {
                    Ok(())
                } else {
                    let root = &destination.unwrap().root;
                    let path = RelativePath::new(&candidate.path)?;
                    if candidate.kind == "dir" {
                        root.remove_directory(&path)
                    } else {
                        root.unlink(&path)
                    }
                };
                self.deletion_finished(&candidate, result, "io");
            }
        }
        Ok(())
    }

    async fn deletion_candidates(
        &self,
        plan: &mut Plan,
        destination: Option<&Destination>,
    ) -> Result<Vec<Candidate>> {
        let matcher = crate::scan::build_ignore(&self.args.ignore_lines)?;
        let mut identities = BTreeSet::new();
        // Claims outside the walked scopes can still have aliases inside them.
        if let Some(dst) = destination {
            for path in plan.claimed_paths().filter(|path| {
                !plan
                    .scopes
                    .iter()
                    .any(|(scope, _)| prune::beneath(path, scope).is_some())
            }) {
                if let Some(meta) = metadata_optional(&dst.root, &RelativePath::new(path)?)? {
                    identities.insert((meta.dev, meta.ino));
                }
            }
        }
        let mut found = Vec::new();
        let mut seen = BTreeSet::new();
        for (scope, _) in plan.scopes.clone() {
            if let Some(dst) = destination {
                let mut stack = vec![scope];
                while let Some(path) = stack.pop() {
                    self.check_cancelled()?;
                    if !seen.insert(path.clone()) {
                        continue;
                    }
                    let rel = RelativePath::new(&path)?;
                    let Some(meta) = metadata_optional(&dst.root, &rel)? else {
                        continue;
                    };
                    if plan.keeps(&path) {
                        identities.insert((meta.dev, meta.ino));
                    }
                    if plan.shields(&path) {
                        continue;
                    }
                    let directory = meta.is_dir();
                    if prune::recovery(&path) || plan.ignores(&path, directory, matcher.as_ref()) {
                        self.kept_recovery(&path);
                        plan.protect(&path);
                        continue;
                    }
                    if directory {
                        for name in dst.root.read_directory(&rel)? {
                            let mut child = path.clone();
                            if !child.is_empty() {
                                child.push(b'/');
                            }
                            child.extend_from_slice(&name);
                            stack.push(child);
                        }
                    }
                    found.push(Candidate {
                        path,
                        key: None,
                        identity: Some((meta.dev, meta.ino)),
                        kind: if directory {
                            "dir"
                        } else if meta.is_symlink() {
                            "symlink"
                        } else {
                            "file"
                        },
                    });
                }
            } else {
                let mut prefix = String::from_utf8(scope)?;
                if !prefix.is_empty() {
                    prefix.push('/');
                }
                let listed = match self.upload_keys.get() {
                    Some(keys) => keys
                        .iter()
                        .filter(|(key, _)| key.starts_with(&prefix))
                        .map(|(key, size)| (key.clone(), *size))
                        .collect(),
                    None => {
                        client::list(
                            &self.client,
                            &self.options.bucket,
                            &prefix,
                            None,
                            &mut HashSet::new(),
                        )
                        .await?
                        .objects
                    }
                };
                for (key, size) in listed {
                    self.check_cancelled()?;
                    anyhow::ensure!(
                        key.starts_with(&prefix),
                        "S3 listing returned a key outside the requested prefix"
                    );
                    if !seen.insert(key.as_bytes().to_vec()) {
                        continue;
                    }
                    let directory = client::is_directory_marker(&key, size);
                    let path = if directory {
                        key.strip_suffix('/').unwrap()
                    } else {
                        &key
                    };
                    let path = path.as_bytes().to_vec();
                    if prune::recovery(&path) || plan.ignores(&path, directory, matcher.as_ref()) {
                        self.kept_recovery(&path);
                        plan.protect(&path);
                        continue;
                    }
                    // Ignored keys need not be representable as local paths.
                    local::key_path(&path)?;
                    found.push(Candidate {
                        path,
                        key: Some(key),
                        identity: None,
                        kind: if directory { "dir" } else { "file" },
                    });
                }
            }
        }
        for c in &found {
            if !plan.keeps(&c.path) && c.identity.is_some_and(|id| identities.contains(&id)) {
                plan.protect(&c.path);
            }
        }
        found.retain(|c| {
            if c.key.is_some() {
                !plan.keeps_object(&c.path, c.kind == "dir")
            } else {
                !plan.keeps(&c.path)
            }
        });
        // Children first; never recursively remove a local directory.
        found.sort_by(|a, b| b.path.cmp(&a.path));
        Ok(found)
    }

    fn kept_recovery(&self, path: &[u8]) {
        if self.args.verbose > 0 && prune::recovery(path) {
            self.progress.println(&format!(
                "keeping recovery entry {}",
                String::from_utf8_lossy(path)
            ));
        }
    }

    pub(super) async fn prepare_pruning(&self, plan: &Plan) -> Result<()> {
        if self.authorization.is_none() || !self.args.delete {
            return Ok(());
        }
        // Cache complete listings before disconnect. The pruning pass reuses the
        // snapshot and still skips deletions if any copy failed.
        if self.upload_keys.get().is_none() {
            let mut keys = HashMap::new();
            for (scope, _) in &plan.scopes {
                let key = std::str::from_utf8(scope)?;
                let prefix = if key.is_empty() {
                    String::new()
                } else {
                    format!("{key}/")
                };
                keys.extend(
                    client::list(
                        &self.client,
                        &self.options.bucket,
                        &prefix,
                        None,
                        &mut HashSet::new(),
                    )
                    .await?
                    .objects,
                );
            }
            let _ = self.upload_keys.set(keys);
        }
        if self.args.dry_run {
            return Ok(());
        }
        let requests = self
            .deletion_candidates(&mut plan.clone(), None)
            .await?
            .iter()
            .map(|candidate| {
                crate::s3::authorization::Unsigned::new("DELETE", candidate.key.as_ref().unwrap())
            })
            .collect();
        self.authorize_requests(requests).await
    }

    async fn delete_objects(&self, candidates: &[Candidate]) -> Result<()> {
        crate::s3::delete::Deleter {
            client: &self.client,
            bucket: &self.options.bucket,
            budget: &self.tuning.requests,
            individual: self.authorization.is_some(),
        }
        .run(
            candidates,
            |c| crate::s3::delete::Target {
                key: c.key.clone().unwrap(),
                version: None,
            },
            || self.check_cancelled(),
            |candidate, result| {
                let class = result.as_ref().err().map_or("transport", |e| e.class);
                self.deletion_finished(
                    candidate,
                    result.map_err(|e| anyhow::anyhow!(e.message)),
                    class,
                );
            },
        )
        .await
    }

    fn deletion_finished(&self, candidate: &Candidate, result: Result<()>, class: &'static str) {
        match result {
            Ok(()) => {
                self.progress.deletions_completed.fetch_add(1, Relaxed);
                if self.args.verbose > 0 {
                    self.progress.println(&format!(
                        "{} {}",
                        if self.args.dry_run {
                            "would delete"
                        } else {
                            "deleted"
                        },
                        String::from_utf8_lossy(&candidate.path)
                    ));
                }
                self.deletion_record(candidate, "succeeded", None, None);
            }
            Err(error) => {
                let message = format!(
                    "delete {}: {error:#}",
                    String::from_utf8_lossy(&candidate.path)
                );
                self.progress.error(&message);
                self.deletion_record(candidate, "failed", Some(class), Some(&message));
            }
        }
    }

    fn deletion_record(
        &self,
        candidate: &Candidate,
        disposition: &'static str,
        class: Option<&'static str>,
        message: Option<&str>,
    ) {
        let Some(writer) = self.progress.results_writer() else {
            return;
        };
        let path = candidate
            .key
            .as_ref()
            .map_or(candidate.path.as_slice(), |k| k.as_bytes());
        if self.args.dry_run {
            if disposition == "succeeded" {
                writer.emit_trace(&crate::results::TraceRecord {
                    action: "delete",
                    src: None,
                    dst: path,
                    kind: candidate.kind,
                    bytes: None,
                    reason: "destination_only",
                });
            }
        } else {
            writer.emit_operation(&crate::results::OperationRecord {
                action: "delete",
                src: None,
                dst: path,
                kind: candidate.kind,
                disposition,
                bytes: None,
                attempts: None,
                retryable: None,
                class,
                os_kind: None,
                message,
            });
        }
    }
}

// Missing ancestors are expected for dry runs and --only-existing copies.
fn metadata_optional(
    root: &Root,
    path: &RelativePath,
) -> Result<Option<crate::rooted::RootMetadata>> {
    match root.metadata_optional(path) {
        Err(error)
            if error.chain().any(|cause| {
                cause
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
            }) =>
        {
            Ok(None)
        }
        result => result,
    }
}

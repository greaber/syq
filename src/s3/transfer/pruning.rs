use super::*;
use crate::s3::prune::{self, Plan};
use std::collections::BTreeSet;

struct Candidate {
    path: Vec<u8>,
    // An S3 marker retains its trailing slash; local directories do not.
    key: Option<String>,
    kind: &'static str,
}

impl Engine {
    pub(super) async fn prune(
        &self,
        mut plan: Plan,
        destination: Option<&Destination>,
    ) -> Result<()> {
        self.check_cancelled()?;
        if plan.scopes.is_empty() {
            return Ok(());
        }
        let matcher = crate::scan::build_ignore(&self.args.ignore_lines)?;
        // Preserve alternate spellings and hard-link aliases of claimed local paths.
        let mut identities = BTreeSet::new();
        if let Some(dst) = destination {
            for path in &plan.claims {
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
                    if plan.shields(&path) {
                        continue;
                    }
                    let rel = RelativePath::new(&path)?;
                    let Some(meta) = metadata_optional(&dst.root, &rel)? else {
                        continue;
                    };
                    let directory = meta.is_dir();
                    if prune::recovery(&path) || plan.ignores(&path, directory, matcher.as_ref()) {
                        plan.protect(&path);
                        continue;
                    }
                    if !plan.keeps(&path) && identities.contains(&(meta.dev, meta.ino)) {
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
                for (key, size) in client::list(&self.client, &self.options.bucket, &prefix).await?
                {
                    self.check_cancelled()?;
                    anyhow::ensure!(
                        key.starts_with(&prefix),
                        "S3 listing returned a key outside the requested prefix"
                    );
                    if !seen.insert(key.as_bytes().to_vec()) {
                        continue;
                    }
                    let directory = key.ends_with('/') && size == 0;
                    let path = if directory {
                        key.strip_suffix('/').unwrap()
                    } else {
                        &key
                    };
                    // Reject keys that cannot be interpreted under the same path rules as copying.
                    local::key_path(path.as_bytes())?;
                    let path = path.as_bytes().to_vec();
                    if prune::recovery(&path) || plan.ignores(&path, directory, matcher.as_ref()) {
                        plan.protect(&path);
                    }
                    found.push(Candidate {
                        path,
                        key: Some(key),
                        kind: if directory { "dir" } else { "file" },
                    });
                }
            }
        }
        found.retain(|c| !plan.keeps(&c.path));
        // Children first. Never recursively remove a directory: a new child must cause failure.
        found.sort_by(|a, b| b.path.cmp(&a.path));
        let count = found.len() as u64;
        self.progress.deletions_planned.store(count, Relaxed);
        if self.args.max_delete.is_some_and(|max| count > max) {
            self.progress.deletions_blocked.store(count, Relaxed);
            for c in &found {
                self.deletion_record(c, "blocked", Some("safety_limit"), None);
            }
            return Err(prune::Limit.into());
        }
        for candidate in found {
            self.check_cancelled()?;
            let result = if self.args.dry_run {
                Ok(())
            } else if let Some(key) = &candidate.key {
                self.client
                    .delete_object()
                    .bucket(&self.options.bucket)
                    .key(key)
                    .send()
                    .await
                    .map(|_| ())
                    .map_err(|e| anyhow::anyhow!(e.into_service_error()))
            } else {
                let root = &destination.unwrap().root;
                let path = RelativePath::new(&candidate.path)?;
                if candidate.kind == "dir" {
                    root.remove_directory(&path)
                } else {
                    root.unlink(&path)
                }
            };
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
                    self.deletion_record(&candidate, "succeeded", None, None);
                }
                Err(error) => {
                    let message = format!(
                        "delete {}: {error:#}",
                        String::from_utf8_lossy(&candidate.path)
                    );
                    self.progress.error(&message);
                    self.deletion_record(
                        &candidate,
                        "failed",
                        Some(if destination.is_some() {
                            "io"
                        } else {
                            "transport"
                        }),
                        Some(&message),
                    );
                    break;
                }
            }
        }
        Ok(())
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

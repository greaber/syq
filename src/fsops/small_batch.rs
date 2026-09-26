use super::*;
use std::collections::HashSet;
use std::rc::Rc;

type Outcome = std::result::Result<Option<(u64, u64)>, WireError>;

struct Group {
    domain: Rc<namespace::Domain>,
    waiting: Option<namespace::Ticket>,
    unopened: Vec<(usize, RootedTarget)>,
    staged: Vec<(usize, SmallStage)>,
    publishing: bool,
    done: bool,
}

fn staged(put: &SmallPut) -> bool {
    if put.inplace {
        return false;
    }
    put.guard.is_some()
        || matches!(
            put.condition,
            TargetCondition::Any | TargetCondition::Absent
        )
}

fn window_capacity() -> usize {
    // Each admitted file can need a stage, its parent, and a guard root. Reserve transient
    // opens for publication and error recovery before admitting more starts.
    // 64 is a fairness/memory ceiling, independent of directory or file count.
    nofile_limits()
        .ok()
        .and_then(|limits| {
            if limits.rlim_cur == libc::RLIM_INFINITY {
                return Some(64);
            }
            let open = current_open_descriptor_count(limits.rlim_cur).ok()?;
            let available = usize::try_from(limits.rlim_cur)
                .unwrap_or(usize::MAX)
                .saturating_sub(open);
            Some((available.saturating_sub(16) / 3).clamp(1, 64))
        })
        .unwrap_or(1)
}

impl FsOps {
    pub(super) fn put_small_batch(&mut self, puts: &[SmallPut]) -> Vec<Outcome> {
        let mut results = vec![Ok(None); puts.len()];
        let capacity = window_capacity();
        let mut next = 0;
        while next < puts.len() {
            if !staged(&puts[next]) {
                // Existing inode and explicit in-place updates retain their
                // ordering and write semantics. Drain prior publications before
                // crossing this boundary; no namespace turn spans this write.
                results[next] = self
                    .put_small(&puts[next])
                    .map_err(|error| wire_error(&error));
                next += 1;
                continue;
            }
            let mut groups = Vec::<Group>::new();
            let mut parents = HashMap::<(RootIdentity, PathBytes), Rc<namespace::Domain>>::new();
            let mut by_identity = HashMap::<RootIdentity, usize>::new();
            let mut names = HashSet::<(RootIdentity, Vec<u8>)>::new();
            let stop = (next + capacity).min(puts.len());
            while next < stop && staged(&puts[next]) {
                let put = &puts[next];
                let prepared = (|| -> Result<_> {
                    if self.hash_policy.transfer_integrity
                        && self.observed_payload_hash(&put.data) != put.hash
                    {
                        bail!("block hash mismatch on receive");
                    }
                    let target = self.destination_mutation_target(&put.path, put.guard.as_ref())?;
                    let path = target.relative.to_path_buf();
                    let parent = path
                        .parent()
                        .context("small-file destination requires a leaf")?;
                    let name = path
                        .file_name()
                        .context("small-file destination requires a leaf")?
                        .as_bytes()
                        .to_vec();
                    let key = (target.root.identity(), path_bytes(parent));
                    let domain = if let Some(domain) = parents.get(&key) {
                        domain.clone()
                    } else {
                        let directory = target.root.open_directory(&RelativePath::new(&key.1)?)?;
                        let domain = namespace::Domain::new(directory)?;
                        parents.insert(key, domain.clone());
                        domain
                    };
                    Ok((target, domain, name))
                })();
                match prepared {
                    Ok((target, domain, name)) => {
                        if !names.insert((domain.identity, name)) {
                            // The same target can appear more than once in a
                            // request, including through directory aliases.
                            // Complete the earlier occurrence before staging it
                            // again, so shared sidecar names never overlap.
                            break;
                        }
                        let group = *by_identity.entry(domain.identity).or_insert_with(|| {
                            let index = groups.len();
                            groups.push(Group {
                                domain,
                                waiting: None,
                                unopened: Vec::new(),
                                staged: Vec::new(),
                                publishing: false,
                                done: false,
                            });
                            index
                        });
                        groups[group].unopened.push((next, target));
                    }
                    Err(error) => results[next] = Err(wire_error(&error)),
                }
                next += 1;
            }
            let wake = Arc::new(namespace::Wake::default());
            for group in &mut groups {
                group.waiting = Some(group.domain.request(&wake));
            }
            while groups.iter().any(|group| !group.done) {
                let version = wake.version();
                // Completing a publication releases live-file capacity before
                // admitting another creation burst. Try independent directories
                // before sleeping on an unavailable turn.
                let ready = [true, false].into_iter().find_map(|publishing| {
                    groups.iter_mut().enumerate().find_map(|(index, group)| {
                        if group.done || group.publishing != publishing {
                            return None;
                        }
                        group
                            .waiting
                            .as_mut()
                            .unwrap()
                            .try_enter()
                            .map(|turn| (index, turn))
                    })
                });
                let Some((index, turn)) = ready else {
                    wake.wait(version);
                    continue;
                };
                let group = &mut groups[index];
                group.waiting.take();
                if group.publishing {
                    let mut published = Vec::new();
                    for (file, stage) in group.staged.drain(..) {
                        match self.publish_small_stage_name(&puts[file], &stage) {
                            Ok(()) => published.push((file, stage)),
                            Err(error) => results[file] = Err(wire_error(&error)),
                        }
                    }
                    drop(turn);
                    for (file, stage) in published {
                        results[file] = self
                            .finish_small_stage(&puts[file], stage)
                            .map_err(|error| wire_error(&error));
                    }
                    group.done = true;
                } else {
                    for (file, target) in group.unopened.drain(..) {
                        match self.create_small_stage(&puts[file], target) {
                            Ok(stage) => group.staged.push((file, stage)),
                            Err(error) => results[file] = Err(wire_error(&error)),
                        }
                    }
                    drop(turn);
                    group.staged.retain(|(file, stage)| {
                        match self.write_small_stage(&puts[*file], stage) {
                            Ok(()) => true,
                            Err(error) => {
                                results[*file] = Err(wire_error(&error));
                                false
                            }
                        }
                    });
                    if group.staged.is_empty() {
                        group.done = true;
                    } else {
                        group.publishing = true;
                        group.waiting = Some(group.domain.request(&wake));
                    }
                }
            }
        }
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put(path: &str, data: &[u8]) -> SmallPut {
        SmallPut {
            path: path.as_bytes().to_vec(),
            copy_id: [2; 16],
            data: data.to_vec(),
            hash: content_digest(data),
            meta: Meta {
                mode: 0o600,
                uid: 0,
                gid: 0,
                mtime: 0,
                mtime_nsec: 0,
                inode_metadata: None,
            },
            flags: 0,
            inplace: false,
            condition: TargetCondition::Any,
            guard: None,
        }
    }
    fn ops(directory: &Path) -> FsOps {
        let mut ops = FsOps::new();
        ops.install_destination(File::open(directory).unwrap(), b"logical")
            .unwrap();
        ops
    }

    #[test]
    fn repeated_targets_complete_in_order_without_sharing_live_sidecars() {
        let temporary = crate::test_support::tempdir().unwrap();
        let mut ops = ops(temporary.path());
        let puts = vec![
            put("file", b"long first version"),
            put("other", b"independent"),
            put("file", b"last"),
        ];
        assert_eq!(ops.put_small_batch(&puts), vec![Ok(None); 3]);
        assert_eq!(fs::read(temporary.path().join("file")).unwrap(), b"last");
        assert_eq!(fs::read_dir(temporary.path()).unwrap().count(), 2);
    }

    #[test]
    fn bounded_windows_keep_every_outcome_in_request_order() {
        let temporary = crate::test_support::tempdir().unwrap();
        for name in ["a", "b", "c"] {
            fs::create_dir(temporary.path().join(name)).unwrap();
        }
        let mut ops = ops(temporary.path());
        let mut puts: Vec<_> = (0..137)
            .map(|i| {
                put(
                    &format!("{}/f{i}", ["a", "b", "c"][i % 3]),
                    format!("data{i}").as_bytes(),
                )
            })
            .collect();
        puts[61].data[0] ^= 1;
        let results = ops.put_small_batch(&puts);
        assert_eq!(results.len(), puts.len());
        for (i, (put, result)) in puts.iter().zip(results).enumerate() {
            let path = temporary.path().join(OsStr::from_bytes(&put.path));
            if i == 61 {
                assert!(result.is_err());
                assert!(!path.exists());
            } else {
                assert!(result.is_ok());
                assert_eq!(fs::read(path).unwrap(), put.data);
            }
        }
    }

    #[test]
    fn a_busy_parent_does_not_prevent_another_parents_publication() {
        let temporary = crate::test_support::tempdir().unwrap();
        let a = temporary.path().join("a");
        let b = temporary.path().join("b");
        fs::create_dir(&a).unwrap();
        fs::create_dir(&b).unwrap();
        let domain = namespace::Domain::new(File::open(&a).unwrap()).unwrap();
        let wake = Arc::new(namespace::Wake::default());
        let turn = domain.request(&wake).try_enter().unwrap();
        let root = temporary.path().to_path_buf();
        let worker = std::thread::spawn(move || {
            ops(&root).put_small_batch(&[put("a/file", b"a"), put("b/file", b"b")])
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !b.join("file").exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let independent_published = b.join("file").exists();
        let busy_absent = !a.join("file").exists();
        drop(turn);
        let results = worker.join().unwrap();
        assert!(independent_published && busy_absent);
        assert_eq!(results, vec![Ok(None); 2]);
    }
}

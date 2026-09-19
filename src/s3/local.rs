use super::client::{Metadata, ObjectKind};
use crate::{
    cli::{Args, Existence, Placement, SourceSelection},
    proto::OperatorSymlinkPolicy,
    rooted::{
        OperatorFinalComponent, OperatorResolver, PinnedPath, RelativePath, Root, RootMetadata,
    },
};
use anyhow::{bail, Context, Result};
use std::{
    collections::BTreeMap,
    fs::File,
    io::Read,
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    sync::Arc,
};

#[derive(Clone)]
pub(super) struct Source {
    pub root: Arc<Root>,
    pub path: Vec<u8>,
    pub meta: RootMetadata,
    pub key: String,
    pub label: Vec<u8>,
    pub metadata: Option<crate::mapping::Metadata>,
    pub expected_hash: Option<crate::hashing::Digest>,
    // Keep a selected leaf alive so an unlink cannot recycle its inode.
    _pin: Option<Arc<File>>,
}
impl Source {
    pub fn kind(&self) -> ObjectKind {
        if self.meta.is_dir() {
            ObjectKind::Dir
        } else if self.meta.is_symlink() {
            ObjectKind::Symlink
        } else {
            ObjectKind::File
        }
    }
    pub fn open(&self) -> Result<File> {
        let file = self
            .root
            .open_regular_read(&RelativePath::new(&self.path)?)?;
        self.check(&file)?;
        Ok(file)
    }
    pub fn check(&self, file: &File) -> Result<()> {
        let m = file.metadata()?;
        if (
            m.dev(),
            m.ino(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        ) != (
            self.meta.dev,
            self.meta.ino,
            self.meta.len,
            self.meta.mtime,
            self.meta.mtime_nsec as i64,
            self.meta.ctime,
            self.meta.ctime_nsec as i64,
        ) {
            bail!(
                "source changed during S3 copy: {}",
                String::from_utf8_lossy(&self.label)
            );
        }
        Ok(())
    }
    pub fn metadata(&self, hash: Option<String>) -> Metadata {
        let mut metadata = Metadata {
            kind: self.kind(),
            mode: self.meta.mode & 0o7777,
            uid: self.meta.uid,
            gid: self.meta.gid,
            mtime: self.meta.mtime,
            nsec: self.meta.mtime_nsec,
            hash,
            hash_algorithm: crate::hashing::HashAlgorithm::Blake3,
        };
        if let Some(attributes) = self.metadata {
            metadata.override_with(&attributes);
        }
        metadata
    }
    pub fn bytes(&self) -> Result<Vec<u8>> {
        if self.kind() == ObjectKind::Dir {
            return Ok(Vec::new());
        }
        let path = RelativePath::new(&self.path)?;
        if self.root.metadata(&path)? != self.meta {
            bail!("symlink changed during S3 copy");
        }
        let target = self.root.read_link(&path)?;
        if self.root.metadata(&path)? != self.meta {
            bail!("symlink changed during S3 copy");
        }
        Ok(target)
    }
}

pub(super) fn hash_file_as(
    mut file: File,
    algorithm: crate::hashing::HashAlgorithm,
) -> Result<String> {
    let mut hasher = algorithm.hasher();
    let mut buffer = vec![0; 1024 * 1024];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(crate::hashing::Digest::from_hash(algorithm, &hasher.finalize()).value)
}

pub(super) fn key_path(bytes: &[u8]) -> Result<String> {
    let path = std::str::from_utf8(bytes).context("S3 keys require UTF-8 filenames")?;
    let path = if path == "." { "" } else { path };
    if !path.is_empty() {
        RelativePath::new(path.as_bytes()).context(
            "S3 keys used as paths must have relative, nonempty components without . or ..",
        )?;
    }
    if path.len() > 1024 {
        bail!("S3 key exceeds 1024 bytes");
    }
    Ok(path.to_owned())
}
pub(super) fn join(a: &str, b: &str) -> String {
    if a.is_empty() {
        b.to_owned()
    } else if b.is_empty() {
        a.to_owned()
    } else {
        format!("{a}/{b}")
    }
}

pub(super) fn upload_plan(args: &Args) -> Result<(Vec<Source>, super::prune::Plan)> {
    let mut prune = super::prune::Plan::default();
    let count = args.locations.len() - 1;
    let target = key_path(&args.locations[count].path)?;
    let base_path = crate::fsops::resolve(
        args.native_source_root
            .as_deref()
            .or(args.native_source_cwd.as_deref())
            .unwrap_or(b"."),
    );
    let policy = if args.follows_native_source_paths() {
        OperatorSymlinkPolicy::FollowAll
    } else {
        OperatorSymlinkPolicy::Refuse
    };
    let base = match OperatorResolver::resolve_process(
        base_path.as_os_str().as_bytes(),
        policy,
        OperatorFinalComponent::Directory,
        false,
        &mut Vec::new(),
    )? {
        PinnedPath::Directory(d) => d.into_parts().0,
        _ => bail!("source base is not a directory"),
    };
    let matcher = crate::scan::build_ignore(&args.ignore_lines)?;
    let min = args
        .min_size
        .as_deref()
        .map(crate::cli::parse_size)
        .transpose()?
        .unwrap_or(0);
    let max = args
        .max_size
        .as_deref()
        .map(crate::cli::parse_size)
        .transpose()?
        .unwrap_or(u64::MAX);
    let mut selectors = Vec::new();
    if args.native_mapping.is_some() {
        let manifest = crate::mapping::load(args)?;
        for (_, entry) in &manifest.entries {
            selectors.push((
                entry.src.clone(),
                join(&target, &key_path(&entry.dst)?),
                SourceSelection::Named,
                entry.kind,
                entry.expected_hash.clone(),
                entry.metadata,
            ));
        }
    } else {
        for location in &args.locations[..count] {
            let destination = if args.placement == Placement::As || location.copies_contents() {
                target.clone()
            } else {
                join(
                    &target,
                    &key_path(
                        crate::cli::native_basename(&location.path)
                            .context("source has no basename")?,
                    )?,
                )
            };
            selectors.push((
                location.path.clone(),
                destination,
                location.selection,
                None,
                None,
                None,
            ));
        }
    }
    let mut out = Vec::new();
    let mut claims = BTreeMap::new();
    for (path, destination, selection, declared_kind, expected_hash, metadata) in selectors {
        let resolved = crate::fsops::resolve(&path);
        let pinned = if resolved.is_absolute() {
            if args.native_source_root.is_some() {
                bail!("absolute source beneath --root");
            }
            OperatorResolver::resolve_process(
                resolved.as_os_str().as_bytes(),
                policy,
                OperatorFinalComponent::Entry {
                    follow_symlink: args.follows_native_source_paths(),
                },
                false,
                &mut Vec::new(),
            )?
        } else {
            OperatorResolver::beneath(&base, args.native_source_root.is_some(), policy)?.resolve(
                resolved.as_os_str().as_bytes(),
                OperatorFinalComponent::Entry {
                    follow_symlink: args.follows_native_source_paths(),
                },
                false,
                &mut Vec::new(),
            )?
        };
        let source = match pinned {
            PinnedPath::Directory(d) => {
                let meta = d.metadata();
                let root = Root::from_directory(d.into_parts().0)?;
                Source {
                    root: Arc::new(root),
                    path: Vec::new(),
                    meta,
                    key: destination,
                    label: path,
                    expected_hash,
                    metadata,
                    _pin: None,
                }
            }
            PinnedPath::Leaf(l) => {
                let (parent, name, meta, pin) = l.into_parts();
                Source {
                    root: Arc::new(Root::from_directory(parent)?),
                    path: name.as_bytes().to_vec(),
                    meta,
                    key: destination,
                    label: path,
                    expected_hash,
                    metadata,
                    _pin: pin.map(Arc::new),
                }
            }
            _ => bail!("source cannot be selected for S3 upload"),
        };
        if (selection == SourceSelection::File && source.kind() == ObjectKind::Dir)
            || (matches!(
                selection,
                SourceSelection::Directory | SourceSelection::Contents
            ) && source.kind() != ObjectKind::Dir)
        {
            bail!("source type does not match selector");
        }
        if let Some(kind) = declared_kind {
            if kind.label().parse::<ObjectKind>()? != source.kind() {
                bail!("source type does not match mapping");
            }
        }
        if let Some(metadata) = metadata {
            metadata.validate_kind(match source.kind() {
                ObjectKind::File => crate::proto::Kind::File,
                ObjectKind::Dir => crate::proto::Kind::Dir,
                ObjectKind::Symlink => crate::proto::Kind::Symlink,
            })?;
        }
        if source.expected_hash.is_some() && source.kind() != ObjectKind::File {
            bail!("an expected digest requires a regular file");
        }
        if args.delete
            && source.kind() == ObjectKind::Dir
            && !matcher
                .as_ref()
                .is_some_and(|m| crate::scan::path_is_ignored(m, &source.label, true))
        {
            prune.scope(source.key.as_bytes(), &source.label);
        }
        let mut stack = vec![(source, selection == SourceSelection::Contents)];
        while let Some((mut source, contents)) = stack.pop() {
            if matcher.as_ref().is_some_and(|m| {
                crate::scan::path_is_ignored(m, &source.label, source.kind() == ObjectKind::Dir)
            }) {
                prune.protect(source.key.as_bytes());
                continue;
            }
            if source.kind() == ObjectKind::File
                && (!source.meta.is_file() || source.meta.len < min || source.meta.len > max)
            {
                if !source.meta.is_file() {
                    bail!("special files cannot be uploaded to S3");
                }
                prune.protect(source.key.as_bytes());
                continue;
            }
            if args.delete {
                if source.kind() == ObjectKind::Dir {
                    prune.claim(source.key.as_bytes());
                } else if args.existing || args.ignore_existing {
                    prune.protect(source.key.as_bytes());
                } else {
                    prune.claim_file(source.key.as_bytes());
                }
            }
            if source.kind() == ObjectKind::Dir {
                let rel = RelativePath::new(&source.path)?;
                for name in if args.native_mapping.is_none() {
                    source.root.read_directory(&rel)?
                } else {
                    Vec::new()
                } {
                    let mut child = source.clone();
                    if !child.path.is_empty() {
                        child.path.push(b'/');
                    }
                    child.path.extend_from_slice(&name);
                    child.meta = child.root.metadata(&RelativePath::new(&child.path)?)?;
                    child.key = join(&source.key, &key_path(&name)?);
                    if !child.label.is_empty() {
                        child.label.push(b'/');
                    }
                    child.label.extend_from_slice(&name);
                    stack.push((child, false));
                }
                if contents {
                    continue;
                }
                if source.key.is_empty() {
                    continue;
                }
                source.key.push('/');
            }
            claim(
                &mut claims,
                source.key.trim_end_matches('/'),
                source.kind() == ObjectKind::Dir,
            )?;
            if source.key.len() > 1024 {
                bail!("S3 key exceeds 1024 bytes");
            }
            out.push(source);
        }
    }
    Ok((out, prune))
}

pub(super) fn claim(
    claims: &mut BTreeMap<String, bool>,
    path: &str,
    directory: bool,
) -> Result<()> {
    if claims.insert(path.to_owned(), directory).is_some() {
        bail!("multiple sources map to {path:?}");
    }
    let mut parent = path;
    while let Some((next, _)) = parent.rsplit_once('/') {
        if claims.get(next) == Some(&false) {
            bail!("file/directory collision at {next:?}");
        }
        parent = next;
    }
    if !directory {
        let prefix = format!("{path}/");
        if claims
            .range(prefix.clone()..)
            .next()
            .is_some_and(|(key, _)| key.starts_with(&prefix))
        {
            bail!("file/directory collision at {path:?}");
        }
    }
    Ok(())
}

pub(super) struct Destination {
    pub root: Arc<Root>,
    pub prefix: String,
}
impl Destination {
    pub fn open(args: &Args) -> Result<Self> {
        let path = crate::fsops::resolve(&args.locations.last().unwrap().path);
        let policy = if args.follows_native_destination_paths() {
            OperatorSymlinkPolicy::FollowAll
        } else {
            OperatorSymlinkPolicy::Refuse
        };
        let final_component = if args.placement == Placement::Into {
            OperatorFinalComponent::Directory
        } else {
            OperatorFinalComponent::Entry {
                follow_symlink: false,
            }
        };
        let pinned = OperatorResolver::resolve_process(
            path.as_os_str().as_bytes(),
            policy,
            final_component,
            true,
            &mut Vec::new(),
        )?;
        let exists = !matches!(&pinned, PinnedPath::Missing(_));
        if (args.target_existence == Existence::New && exists)
            || (args.target_existence == Existence::Existing && !exists)
        {
            bail!("destination existence condition failed");
        }
        match pinned {
            PinnedPath::Directory(d) => Ok(Self {
                root: Arc::new(Root::from_directory(d.into_parts().0)?),
                prefix: String::new(),
            }),
            PinnedPath::Leaf(l) => {
                let (p, n, m, _) = l.into_parts();
                if m.is_dir() {
                    bail!("unexpected directory destination");
                }
                Ok(Self {
                    root: Arc::new(Root::from_directory(p)?),
                    prefix: std::str::from_utf8(n.as_bytes())
                        .context("S3 download placement requires UTF-8")?
                        .into(),
                })
            }
            PinnedPath::Missing(m) => {
                let (p, parts) = m.into_parts();
                let path = parts
                    .into_iter()
                    .map(|p| String::from_utf8(p).context("S3 download placement requires UTF-8"))
                    .collect::<Result<Vec<_>>>()?
                    .join("/");
                Ok(Self {
                    root: Arc::new(Root::from_directory(p)?),
                    prefix: path,
                })
            }
            _ => bail!("unsupported S3 download destination"),
        }
    }
}

pub(super) fn apply_metadata(
    root: &Root,
    path: &RelativePath,
    metadata: &Metadata,
    args: &Args,
    existing_mode: Option<u32>,
    explicit: crate::mapping::Metadata,
) -> Result<()> {
    if metadata.kind == super::client::ObjectKind::File {
        return apply_file_metadata(
            &root.open_regular_read(path)?,
            metadata,
            args,
            existing_mode,
            explicit,
        );
    }
    if args.owner || args.group || explicit.uid.is_some() || explicit.gid.is_some() {
        root.chown(
            path,
            (args.owner || explicit.uid.is_some()).then_some(metadata.uid),
            (args.group || explicit.gid.is_some()).then_some(metadata.gid),
        )?;
    }
    if metadata.kind != super::client::ObjectKind::Symlink {
        let file = if metadata.kind == super::client::ObjectKind::Dir {
            root.open_directory(path)?
        } else {
            root.open_regular_read(path)?
        };
        let mode = if args.perms || explicit.mode.is_some() {
            metadata.mode
        } else {
            existing_mode.unwrap_or(metadata.mode & 0o777 & !crate::fsops::process_umask())
        };
        crate::fsops::set_mode_handle(&file, mode)?;
    }
    root.set_times(
        path,
        &[
            libc::timespec {
                tv_sec: 0,
                tv_nsec: libc::UTIME_OMIT,
            },
            libc::timespec {
                tv_sec: metadata.mtime as _,
                tv_nsec: metadata.nsec as _,
            },
        ],
    )?;
    Ok(())
}

// Use the file we wrote, so replacement of a temporary pathname cannot redirect
// chmod, chown or timestamp restoration to a different inode.
pub(super) fn apply_file_metadata(
    file: &File,
    metadata: &Metadata,
    args: &Args,
    existing_mode: Option<u32>,
    explicit: crate::mapping::Metadata,
) -> Result<()> {
    use crate::proto::{flags, Meta};
    let mode = if args.perms || explicit.mode.is_some() {
        metadata.mode
    } else {
        existing_mode.unwrap_or(metadata.mode & 0o777 & !crate::fsops::process_umask())
    };
    crate::fsops::set_meta_file(
        file,
        &Meta {
            mode,
            uid: metadata.uid,
            gid: metadata.gid,
            mtime: metadata.mtime,
            mtime_nsec: metadata.nsec,
        },
        flags::MODE
            | flags::TIMES
            | explicit.apply_flags()
            | if args.owner || explicit.uid.is_some() {
                flags::OWNER
            } else {
                0
            }
            | if args.group || explicit.gid.is_some() {
                flags::GROUP
            } else {
                0
            },
    )
}

//! Bounded, invocation-local reuse of retired destination files (explicit opt-in only).
//! The owner closes the pool explicitly before reporting command completion.
use super::*;
use std::os::unix::fs::{FileExt, PermissionsExt};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

mod ideal;

const SLOTS: usize = 32;
const STATE: &CStr = c"state";

pub(crate) struct Pool {
    directory: File,
    state: File,
    max_bytes: u64,
    local: std::sync::Mutex<()>,
    ideal: Option<ideal::Ideal>,
}

pub(crate) struct Owner {
    root: Arc<Root>,
    name: RelativePath,
    identity: RootIdentity,
    pub(crate) pool: Pool,
    cleaned: bool,
    drainers: Vec<std::thread::JoinHandle<Result<()>>>,
}

impl Pool {
    pub(crate) fn open(directory: File) -> Result<Self> {
        // This experiment requires exclusive destination access. Reading a
        // global hard-link sysctl does not establish that condition, and some
        // hosts hide it from unprivileged processes. Check the actual objects
        // below; these checks do not make concurrent hostile access supported.
        let metadata = directory.metadata()?;
        anyhow::ensure!(
            metadata.is_dir()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o777 == 0o700,
            "staging pool is not an owned private directory"
        );
        // An independent open description gives every worker its own flock owner.
        let state = open_at(
            directory.as_raw_fd(),
            STATE,
            libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        )?;
        let metadata = state.metadata()?;
        anyhow::ensure!(
            metadata.is_file()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o7777 == 0o600
                && metadata.nlink() == 1,
            "staging pool state is not a private regular file"
        );
        let mut bytes = [0; 8];
        state.read_exact_at(&mut bytes, 1)?;
        let max_bytes = u64::from_le_bytes(bytes);
        anyhow::ensure!(max_bytes != 0, "staging pool budget is zero");
        let ideal = ideal::Ideal::open(&directory)?;
        Ok(Self {
            ideal,
            directory,
            state,
            max_bytes,
            local: std::sync::Mutex::new(()),
        })
    }

    pub(crate) fn stats(&self) -> Result<crate::proto::RecyclingStats> {
        if let Some(ideal) = &self.ideal {
            return Ok(ideal.stats());
        }
        let _lock = lock(self)?;
        let mut bytes = [0; 16];
        self.state.read_exact_at(&mut bytes, 9)?;
        Ok(crate::proto::RecyclingStats {
            files: u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            bytes: u64::from_le_bytes(bytes[8..].try_into().unwrap()),
        })
    }

    pub(crate) fn directory(&self) -> Result<File> {
        Ok(self.directory.try_clone()?)
    }

    fn closed(&self) -> Result<bool> {
        let mut byte = [0];
        self.state.read_exact_at(&mut byte, 0)?;
        Ok(byte[0] != 0)
    }
}

impl Owner {
    pub(crate) fn create(root: Arc<Root>, max_bytes: u64) -> Result<Self> {
        Self::create_mode(
            root,
            max_bytes,
            std::env::var_os("SYQ_EXPERIMENT_IDEAL_RECYCLE").is_some(),
        )
    }

    fn create_mode(root: Arc<Root>, max_bytes: u64, ideal: bool) -> Result<Self> {
        anyhow::ensure!(max_bytes != 0, "staging pool budget is zero");
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce)?;
        let suffix: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
        let name = RelativePath::new(format!(".syq-recycle-{suffix}").as_bytes())?;
        root.create_directory(&name, 0o700)?;
        let directory = match root.open_directory(&name) {
            Ok(directory) => directory,
            Err(error) => {
                let _ = root.remove_directory(&name);
                return Err(error);
            }
        };
        let metadata = directory.metadata()?;
        anyhow::ensure!(
            metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o777 == 0o700,
            "staging pool directory is not private"
        );
        let identity = RootIdentity {
            dev: metadata.dev(),
            ino: metadata.ino(),
        };
        let state = open_at(
            directory.as_raw_fd(),
            STATE,
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )?;
        let result = (|| {
            state.write_all_at(&[0], 0)?;
            state.write_all_at(&max_bytes.to_le_bytes(), 1)?;
            state.write_all_at(&[0; 16], 9)?;
            if ideal {
                ideal::Ideal::create(&directory)?;
            }
            Pool::open(directory.try_clone()?)
        })();
        match result {
            Ok(pool) => {
                let mut owner = Self {
                    root,
                    name,
                    identity,
                    pool,
                    cleaned: false,
                    drainers: Vec::new(),
                };
                if owner
                    .pool
                    .ideal
                    .as_ref()
                    .is_some_and(|i| i.draining_enabled())
                {
                    let workers = std::env::var("SYQ_EXPERIMENT_DRAIN_WORKERS")
                        .unwrap_or_else(|_| "1".into())
                        .parse::<usize>()?;
                    anyhow::ensure!(
                        (1..=8).contains(&workers),
                        "drain experiment requires 1..8 workers"
                    );
                    for _ in 0..workers {
                        let directory = owner.pool.directory.try_clone()?;
                        let mapping = ideal::Ideal::open(&directory)?.unwrap();
                        owner
                            .drainers
                            .push(std::thread::spawn(move || mapping.drain(directory)));
                    }
                }
                Ok(owner)
            }
            Err(error) => {
                // Use the retained directory, never reopen a raced pathname
                // before removing the state file this attempt created.
                let _ = unlink_at(directory.as_raw_fd(), STATE, 0);
                if root
                    .metadata(&name)
                    .is_ok_and(|m| m.dev == identity.dev && m.ino == identity.ino)
                {
                    let _ = root.remove_directory(&name);
                }
                Err(error)
            }
        }
    }

    pub(crate) fn close(&mut self) -> Result<()> {
        if self.cleaned {
            return Ok(());
        }
        let _lock = lock(&self.pool)?;
        // Workers keep this descriptor: closure survives unlinking its name.
        self.pool.state.write_all_at(&[1], 0)?;
        if let Some(ideal) = &self.pool.ideal {
            ideal.close(&self.pool.directory)?;
        }
        let mut drain_error = None;
        for thread in self.drainers.drain(..) {
            let result = thread
                .join()
                .unwrap_or_else(|_| Err(anyhow::anyhow!("experimental drain worker panicked")));
            if let Err(error) = result {
                drain_error = Some(error);
            }
        }
        if let Some(error) = drain_error {
            return Err(error);
        }
        if let Some(ideal) = &self.pool.ideal {
            if ideal.draining_enabled() {
                ideal.report_drain();
            }
        }
        for i in 0..SLOTS {
            let name = CString::new(i.to_string())?;
            match unlink_at(self.pool.directory.as_raw_fd(), &name, 0) {
                Ok(()) => (),
                Err(error) if error.kind() == io::ErrorKind::NotFound => (),
                Err(error) => return Err(error.into()),
            }
        }
        match unlink_at(self.pool.directory.as_raw_fd(), STATE, 0) {
            Ok(()) => (),
            Err(error) if error.kind() == io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
        let named = self.root.metadata(&self.name)?;
        anyhow::ensure!(
            named.dev == self.identity.dev && named.ino == self.identity.ino,
            "staging pool directory changed before cleanup"
        );
        self.root.remove_directory(&self.name)?;
        self.cleaned = true;
        Ok(())
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

/// A lease is an extra reader check, not a substitute for ownership and modes.
fn unopened(file: &File) -> bool {
    static BREAK: std::sync::OnceLock<Option<Arc<AtomicBool>>> = std::sync::OnceLock::new();
    let Some(broken) = BREAK.get_or_init(|| {
        let flag = Arc::new(AtomicBool::new(false));
        signal_hook::flag::register(libc::SIGIO, flag.clone())
            .ok()
            .map(|_| flag)
    }) else {
        return false;
    };
    if broken.load(Ordering::Relaxed) {
        return false;
    }
    let fd = file.as_raw_fd();
    if unsafe { libc::fcntl(fd, libc::F_SETLEASE, libc::F_WRLCK) } != 0 {
        return false;
    }
    let intact = unsafe { libc::fcntl(fd, libc::F_GETLEASE) } == libc::F_WRLCK;
    let released = unsafe { libc::fcntl(fd, libc::F_SETLEASE, libc::F_UNLCK) } == 0;
    intact && released && !broken.load(Ordering::Relaxed)
}

struct Lock<'a> {
    file: &'a File,
    _local: std::sync::MutexGuard<'a, ()>,
}
impl Drop for Lock<'_> {
    fn drop(&mut self) {
        unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}
fn lock(pool: &Pool) -> Result<Lock<'_>> {
    let local = pool.local.lock().unwrap_or_else(|p| p.into_inner());
    retry_zero(|| unsafe { libc::flock(pool.state.as_raw_fd(), libc::LOCK_EX) })?;
    Ok(Lock {
        file: &pool.state,
        _local: local,
    })
}
// Do not inherit behavior such as append-only, no-dump, no-COW, or project
// inheritance from a retired inode. Extent layout and directory indexing are
// filesystem implementation details rather than user-selected file behavior.
fn ordinary_flags(file: &File) -> bool {
    let mut flags: libc::c_long = 0;
    if unsafe { libc::ioctl(file.as_raw_fd(), libc::FS_IOC_GETFLAGS, &mut flags) } == 0 {
        flags & !(0x0008_0000 | 0x0000_1000) == 0
    } else {
        matches!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ENOTTY | libc::EOPNOTSUPP)
        )
    }
}

fn eligible(file: &File) -> Result<bool> {
    let m = file.metadata()?;
    Ok(m.is_file()
        && ordinary_flags(file)
        && m.uid() == unsafe { libc::geteuid() }
        && m.nlink() == 1
        && m.mode() & 0o6000 == 0
        && unsafe { libc::flistxattr(file.as_raw_fd(), std::ptr::null_mut(), 0) } == 0)
}
fn slots(pool: &Pool) -> Result<Vec<(CString, u64)>> {
    let mut slots = Vec::new();
    for i in 0..SLOTS {
        let name = CString::new(i.to_string())?;
        match metadata_at(pool.directory.as_raw_fd(), &name) {
            Ok(m) if m.is_file() && m.nlink == 1 => slots.push((name, m.len)),
            Ok(_) => bail!("invalid recycled staging pool entry"),
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
    }
    Ok(slots)
}

pub(super) fn take(pool: &Pool, parent: &ResolvedParent<'_>, size: u64) -> Result<Option<File>> {
    if let Some(ideal) = &pool.ideal {
        return ideal.take(pool, parent, size);
    }
    let _process = lock(pool)?;
    if pool.closed()? {
        return Ok(None);
    }
    match metadata_at(parent.directory.as_raw_fd(), &parent.leaf) {
        Ok(_) => return Ok(None), // Resume its actual contents using the ordinary path.
        Err(e) if e.kind() == io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    }
    let mut candidates = slots(pool)?;
    // Prefer the smallest sufficient file; otherwise extend the largest spare.
    candidates.sort_by_key(|(_, len)| {
        (
            u8::from(*len < size),
            if *len < size { u64::MAX - *len } else { *len },
        )
    });
    let Some((name, _old_size)) = candidates.first() else {
        return Ok(None);
    };
    let file = open_at(
        pool.directory.as_raw_fd(),
        name,
        libc::O_RDWR | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        0,
    )?;
    if !eligible(&file)? || !unopened(&file) {
        unlink_at(pool.directory.as_raw_fd(), name, 0)?;
        return Ok(None);
    }
    let before = file.metadata()?;
    let parent_metadata = parent.directory.metadata()?;
    // A fresh inode would inherit the target directory's default ACL and
    // filesystem policy. Reuse only ordinary parents without such metadata.
    // Operator roots may be O_PATH handles. Attribute ioctls need a readable
    // directory descriptor, opened relative to the already retained object.
    let Ok(inspection) = open_at(
        parent.directory.as_raw_fd(),
        c".",
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        0,
    ) else {
        return Ok(None);
    };
    if !ordinary_flags(&inspection)
        || unsafe { libc::flistxattr(inspection.as_raw_fd(), std::ptr::null_mut(), 0) } != 0
    {
        return Ok(None);
    }
    let creation_gid = if parent_metadata.mode() & 0o2000 != 0 {
        parent_metadata.gid()
    } else {
        unsafe { libc::getegid() }
    };
    // Match a fresh file's default ownership even when the caller does not
    // request group preservation. Final metadata is applied by the caller.
    if before.gid() != creation_gid {
        unlink_at(pool.directory.as_raw_fd(), name, 0)?;
        return Ok(None);
    }
    let moved = retry_zero(|| unsafe {
        libc::renameat2(
            pool.directory.as_raw_fd(),
            name.as_ptr(),
            parent.directory.as_raw_fd(),
            parent.leaf.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    });
    if let Err(error) = moved {
        if matches!(error.raw_os_error(), Some(libc::EXDEV | libc::EEXIST)) {
            return Ok(None);
        }
        return Err(error.into());
    }
    let named = metadata_at(parent.directory.as_raw_fd(), &parent.leaf)?;
    if named.dev != before.dev() || named.ino != before.ino() {
        bail!("recycled staging inode changed");
    }
    if before.mode() & 0o7777 != 0o600 {
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    // This is storage reuse, not a resume hint. Callers must treat every byte
    // as unverified and run their ordinary copy/hash decisions.
    file.set_len(size)?;
    let mut counters = [0; 16];
    pool.state.read_exact_at(&mut counters, 9)?;
    let files = u64::from_le_bytes(counters[..8].try_into().unwrap()).saturating_add(1);
    let bytes = u64::from_le_bytes(counters[8..].try_into().unwrap()).saturating_add(size);
    counters[..8].copy_from_slice(&files.to_le_bytes());
    counters[8..].copy_from_slice(&bytes.to_le_bytes());
    pool.state.write_all_at(&counters, 9)?;
    Ok(Some(file))
}

pub(super) fn publish(
    pool: &Pool,
    source: &ResolvedParent<'_>,
    target: &ResolvedParent<'_>,
    staged_identity: (u64, u64),
) -> Result<bool> {
    if let Some(ideal) = &pool.ideal {
        return ideal.publish(pool, source, target);
    }
    let old = match open_at(
        target.directory.as_raw_fd(),
        &target.leaf,
        libc::O_RDWR | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        0,
    ) {
        Ok(file) => file,
        // Retaining the old destination is optional. Ordinary publication
        // does not need to open it (e.g. a read-only file or a raced symlink).
        Err(_) => return Ok(false),
    };
    if !eligible(&old)? {
        return Ok(false);
    }
    let metadata = old.metadata()?;
    let _process = lock(pool)?;
    if pool.closed()? {
        return Ok(false);
    }
    let entries = slots(pool)?;
    if entries.len() == SLOTS
        || entries
            .iter()
            .fold(0u64, |total, (_, size)| total.saturating_add(*size))
            .saturating_add(metadata.len())
            > pool.max_bytes
    {
        return Ok(false);
    }
    let name = (0..SLOTS)
        .map(|i| CString::new(i.to_string()).unwrap())
        .find(|n| !entries.iter().any(|(used, _)| used == n))
        .unwrap();
    let linked = retry_zero(|| unsafe {
        libc::linkat(
            target.directory.as_raw_fd(),
            target.leaf.as_ptr(),
            pool.directory.as_raw_fd(),
            name.as_ptr(),
            0,
        )
    });
    if let Err(error) = linked {
        if matches!(
            error.raw_os_error(),
            Some(libc::EXDEV | libc::EMLINK | libc::EOPNOTSUPP)
        ) {
            return Ok(false);
        }
        return Err(error.into());
    }
    let retained = metadata_at(pool.directory.as_raw_fd(), &name)?;
    if retained.dev != metadata.dev() || retained.ino != metadata.ino() || retained.nlink != 2 {
        unlink_at(pool.directory.as_raw_fd(), &name, 0)?;
        return Ok(false);
    }
    let publication = (|| -> Result<()> {
        // Pool admission can wait on other workers; repeat the ordinary
        // staged-name check immediately before publishing.
        let staged = metadata_at(source.directory.as_raw_fd(), &source.leaf)?;
        anyhow::ensure!(
            is_safe_staged_identity(staged, staged_identity.0, staged_identity.1),
            "staged file changed before recycled publication"
        );
        retry_zero(|| unsafe {
            libc::renameat(
                source.directory.as_raw_fd(),
                source.leaf.as_ptr(),
                target.directory.as_raw_fd(),
                target.leaf.as_ptr(),
            )
        })?;
        Ok(())
    })();
    if let Err(error) = publication {
        unlink_at(pool.directory.as_raw_fd(), &name, 0)?;
        return Err(error);
    }
    let retained = metadata_at(pool.directory.as_raw_fd(), &name)?;
    if retained.dev != metadata.dev() || retained.ino != metadata.ino() || retained.nlink != 1 {
        unlink_at(pool.directory.as_raw_fd(), &name, 0)?;
    }
    // Hide retired content while it waits in the pool. This does not revoke
    // previously opened descriptors, which is why recycling is opt-in.
    if old.metadata()?.nlink() == 1 {
        old.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    drop(old);
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};

    struct Fixture {
        directory: tempfile::TempDir,
        root: Arc<Root>,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir_in(crate::test_support::temp_dir()).unwrap();
            let root = Arc::new(Root::open(directory.path()).unwrap());
            Self { directory, root }
        }

        fn path(name: &str) -> RelativePath {
            RelativePath::new(name.as_bytes()).unwrap()
        }

        fn file(&self, name: &str, content: &[u8]) -> u64 {
            let file = self.root.create_file(&Self::path(name), 0o600).unwrap();
            file.write_all_at(content, 0).unwrap();
            file.metadata().unwrap().ino()
        }

        fn publish(&self, pool: &Pool, source: &str, target: &str) -> Result<bool> {
            publish(
                pool,
                &self.root.resolve_parent(&Self::path(source))?,
                &self.root.resolve_parent(&Self::path(target))?,
                self.root
                    .metadata(&Self::path(source))
                    .map_or((0, 0), |m| (m.dev, m.ino)),
            )
        }

        fn take(&self, pool: &Pool, name: &str, size: u64) -> Result<Option<File>> {
            take(pool, &self.root.resolve_parent(&Self::path(name))?, size)
        }

        fn read(&self, name: &str) -> Vec<u8> {
            fs::read(self.directory.path().join(name)).unwrap()
        }
    }

    #[test]
    fn ideal_pool_shares_atomic_inventory_between_worker_mappings() {
        let fixture = Fixture::new();
        let mut owner = Owner::create_mode(fixture.root.clone(), 128, true).unwrap();
        let worker = Pool::open(owner.pool.directory().unwrap()).unwrap();
        assert!(fixture.take(&worker, "first-part", 4).unwrap().is_none());
        let old = fixture.file("target", b"old!");
        fixture.file("part", b"new!");
        assert!(fixture.publish(&owner.pool, "part", "target").unwrap());
        let reused = fixture.take(&worker, "next-part", 4).unwrap().unwrap();
        assert_eq!(reused.metadata().unwrap().ino(), old);
        assert_eq!(fixture.read("target"), b"new!");
        reused.write_all_at(b"next", 0).unwrap();
        fixture.file("next-target", b"last");
        assert!(fixture
            .publish(&worker, "next-part", "next-target")
            .unwrap());
        assert_eq!(fixture.read("next-target"), b"next");
        assert_eq!(owner.pool.stats().unwrap().files, 1);
        owner.close().unwrap();
        assert!(fixture.take(&worker, "after-close", 4).unwrap().is_none());
    }

    #[test]
    fn ideal_pool_declines_retirement_when_equal_file_exceeds_budget() {
        let fixture = Fixture::new();
        let owner = Owner::create_mode(fixture.root.clone(), 3, true).unwrap();
        assert!(fixture
            .take(&owner.pool, "first-part", 4)
            .unwrap()
            .is_none());
        fixture.file("target", b"old!");
        fixture.file("part", b"new!");
        assert!(!fixture.publish(&owner.pool, "part", "target").unwrap());
        assert_eq!(fixture.read("target"), b"old!");
    }

    #[test]
    fn retires_old_inode_and_reuses_it_without_changing_published_file() {
        let fixture = Fixture::new();
        let mut owner = Owner::create(fixture.root.clone(), 4096).unwrap();
        assert!(fixture.take(&owner.pool, "empty", 8).unwrap().is_none());
        let old_inode = fixture.file("final", b"old bytes");
        let new_inode = fixture.file("part", b"new bytes");
        assert!(fixture.publish(&owner.pool, "part", "final").unwrap());
        assert_eq!(fixture.read("final"), b"new bytes");
        assert_eq!(
            fixture.root.metadata(&Fixture::path("final")).unwrap().ino,
            new_inode
        );
        let reused = fixture.take(&owner.pool, "next", 4).unwrap().unwrap();
        assert_eq!(reused.metadata().unwrap().ino(), old_inode);
        assert_eq!(reused.metadata().unwrap().len(), 4);
        // Reused storage is not a resume hint: it still contains old bytes.
        assert_eq!(fixture.read("next"), b"old ");
        reused.write_all_at(b"next", 0).unwrap();
        assert_eq!(fixture.read("final"), b"new bytes");
        owner.close().unwrap();
        assert!(!fixture.directory.path().join(owner.name.label()).exists());
    }

    #[test]
    fn grows_spare_but_never_replaces_existing_partial() {
        let fixture = Fixture::new();
        let mut owner = Owner::create(fixture.root.clone(), 4096).unwrap();
        let old_inode = fixture.file("final", b"old");
        fixture.file("part", b"new");
        assert!(fixture.publish(&owner.pool, "part", "final").unwrap());
        fixture.file("resume", b"verified by caller");
        assert!(fixture.take(&owner.pool, "resume", 1).unwrap().is_none());
        assert_eq!(fixture.read("resume"), b"verified by caller");
        let reused = fixture.take(&owner.pool, "next", 8).unwrap().unwrap();
        assert_eq!(reused.metadata().unwrap().ino(), old_inode);
        assert_eq!(fixture.read("next"), b"old\0\0\0\0\0");
        owner.close().unwrap();
    }

    #[test]
    fn bounded_pool_does_not_publish_when_budget_is_exhausted() {
        let fixture = Fixture::new();
        let mut owner = Owner::create(fixture.root.clone(), 3).unwrap();
        fixture.file("final", b"old");
        fixture.file("part", b"new");
        assert!(fixture.publish(&owner.pool, "part", "final").unwrap());
        fixture.file("second", b"old second");
        fixture.file("second-part", b"new second");
        assert!(!fixture
            .publish(&owner.pool, "second-part", "second")
            .unwrap());
        assert_eq!(fixture.read("second"), b"old second");
        assert_eq!(fixture.read("second-part"), b"new second");
        assert_eq!(slots(&owner.pool).unwrap().len(), 1);
        owner.close().unwrap();
    }

    #[test]
    fn existing_reader_keeps_old_contents_and_prevents_reuse() {
        let fixture = Fixture::new();
        let mut owner = Owner::create(fixture.root.clone(), 4096).unwrap();
        fixture.file("final", b"old");
        fixture.file("part", b"new");
        let reader = fixture
            .root
            .open_regular_read(&Fixture::path("final"))
            .unwrap();
        assert!(fixture.publish(&owner.pool, "part", "final").unwrap());
        assert!(fixture.take(&owner.pool, "next", 3).unwrap().is_none());
        let mut old = [0; 3];
        reader.read_exact_at(&mut old, 0).unwrap();
        assert_eq!(&old, b"old");
        assert_eq!(fixture.read("final"), b"new");
        owner.close().unwrap();
    }

    #[test]
    fn skips_hardlinks_and_symlinks() {
        let fixture = Fixture::new();
        let mut owner = Owner::create(fixture.root.clone(), 4096).unwrap();
        fixture.file("public", b"public data");
        fs::set_permissions(
            fixture.directory.path().join("public"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        fixture.file("part", b"new");

        fixture.file("linked", b"linked data");
        fs::hard_link(
            fixture.directory.path().join("linked"),
            fixture.directory.path().join("alias"),
        )
        .unwrap();
        assert!(!fixture.publish(&owner.pool, "part", "linked").unwrap());
        symlink("public", fixture.directory.path().join("symlink")).unwrap();
        assert!(!fixture.publish(&owner.pool, "part", "symlink").unwrap());
        assert!(slots(&owner.pool).unwrap().is_empty());
        assert_eq!(fixture.read("part"), b"new");
        assert_eq!(fixture.read("alias"), b"linked data");
        owner.close().unwrap();
    }

    #[test]
    fn publication_failure_removes_only_the_retirement_link() {
        let fixture = Fixture::new();
        let mut owner = Owner::create(fixture.root.clone(), 4096).unwrap();
        fixture.file("final", b"old");
        assert!(fixture
            .publish(&owner.pool, "missing-part", "final")
            .is_err());
        assert_eq!(fixture.read("final"), b"old");
        assert_eq!(
            fixture
                .root
                .metadata(&Fixture::path("final"))
                .unwrap()
                .nlink,
            1
        );
        assert!(slots(&owner.pool).unwrap().is_empty());
        owner.close().unwrap();
    }

    #[test]
    fn explicit_close_disposes_pool_and_disables_surviving_worker_handles() {
        let fixture = Fixture::new();
        let mut owner = Owner::create(fixture.root.clone(), 4096).unwrap();
        let worker = Pool::open(owner.pool.directory().unwrap()).unwrap();
        fixture.file("final", b"old");
        fixture.file("part", b"new");
        assert!(fixture.publish(&worker, "part", "final").unwrap());
        let name = owner.name.clone();
        owner.close().unwrap();
        owner.close().unwrap();
        assert!(fixture.root.metadata_optional(&name).unwrap().is_none());
        assert!(fixture.take(&worker, "next", 3).unwrap().is_none());
        fixture.file("another-part", b"next");
        assert!(!fixture.publish(&worker, "another-part", "final").unwrap());
        assert_eq!(fixture.read("final"), b"new");
    }

    #[test]
    fn drop_disposes_retired_files() {
        let fixture = Fixture::new();
        let name;
        {
            let owner = Owner::create(fixture.root.clone(), 4096).unwrap();
            name = owner.name.clone();
            fixture.file("final", b"old");
            fixture.file("part", b"new");
            assert!(fixture.publish(&owner.pool, "part", "final").unwrap());
        }
        assert!(fixture.root.metadata_optional(&name).unwrap().is_none());
        assert_eq!(fixture.read("final"), b"new");
    }

    #[test]
    fn slot_count_bounds_small_retirements() {
        let fixture = Fixture::new();
        let mut owner = Owner::create(fixture.root.clone(), 4096).unwrap();
        for index in 0..=SLOTS {
            let old = format!("old-{index}");
            let part = format!("part-{index}");
            fixture.file(&old, b"a");
            fixture.file(&part, b"b");
            assert_eq!(
                fixture.publish(&owner.pool, &part, &old).unwrap(),
                index < SLOTS
            );
        }
        assert_eq!(slots(&owner.pool).unwrap().len(), SLOTS);
        owner.close().unwrap();
    }

    #[test]
    fn cleanup_does_not_follow_a_replaced_pool_directory() {
        let fixture = Fixture::new();
        let mut owner = Owner::create(fixture.root.clone(), 4096).unwrap();
        fixture.file("final", b"old");
        fixture.file("part", b"new");
        assert!(fixture.publish(&owner.pool, "part", "final").unwrap());
        let original = fixture.directory.path().join(owner.name.label());
        let moved = fixture.directory.path().join("moved-pool");
        fs::rename(&original, &moved).unwrap();
        fs::create_dir(&original).unwrap();
        fs::write(original.join("state"), b"unrelated data").unwrap();
        assert!(owner.close().is_err());
        assert_eq!(fs::read(original.join("state")).unwrap(), b"unrelated data");
        assert_eq!(fs::read_dir(moved).unwrap().count(), 0);
        assert!(owner.pool.closed().unwrap());
    }

    #[test]
    fn attributes_on_old_file_or_new_parent_prevent_reuse() {
        let fixture = Fixture::new();
        let mut owner = Owner::create(fixture.root.clone(), 4096).unwrap();
        fixture.file("attributed", b"old");
        fixture.file("part", b"new");
        let old = fixture
            .root
            .open_regular_read_write(&Fixture::path("attributed"))
            .unwrap();
        assert_eq!(
            unsafe {
                libc::fsetxattr(
                    old.as_raw_fd(),
                    c"user.syq-test".as_ptr(),
                    b"x".as_ptr().cast(),
                    1,
                    0,
                )
            },
            0
        );
        drop(old);
        assert!(!fixture.publish(&owner.pool, "part", "attributed").unwrap());
        fixture.file("ordinary", b"old");
        assert!(fixture.publish(&owner.pool, "part", "ordinary").unwrap());
        assert_eq!(
            unsafe {
                libc::fsetxattr(
                    fixture.root.directory.as_raw_fd(),
                    c"user.syq-test".as_ptr(),
                    b"x".as_ptr().cast(),
                    1,
                    0,
                )
            },
            0
        );
        assert!(fixture.take(&owner.pool, "next", 3).unwrap().is_none());
        assert_eq!(owner.pool.stats().unwrap().files, 0);
        owner.close().unwrap();
    }
}

//! Cleanup is limited to the selected domain and waits for keeper ownership.
use super::*;
use std::os::unix::fs::FileTypeExt;

fn index_name(path: &Path, extension: &str) -> bool {
    path.extension().is_some_and(|ext| ext == extension)
        && path
            .file_stem()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.len() == 64 && name.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn private_file(path: &Path, limit: u64) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0
            && metadata.len() <= limit,
        "unexpected SSH account state file {}",
        path.display()
    );
    Ok(file)
}

struct KeeperLock(File);
impl Drop for KeeperLock {
    fn drop(&mut self) {
        // Forked descriptors must not keep the lock after its owner finishes.
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

/// The caller validated and closed this recorded master. A concurrent new
/// keeper may replace its index entry: take its lock and compare before removal.
/// Keep the lock file itself so concurrent starters continue sharing one inode.
pub(super) fn retire_record(path: &Path, control: &Path) -> Result<()> {
    let lock = match private_file(&path.with_extension("lock"), 0) {
        Ok(lock) => lock,
        Err(error) if not_found(&error) && !path.exists() => return Ok(()),
        Err(error) => return Err(error),
    };
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::WouldBlock {
            return Ok(());
        }
        return Err(error.into());
    }
    let _lock = KeeperLock(lock);
    let Some(record) = read_record(path)? else {
        return Ok(());
    };
    if record.control != control {
        return Ok(());
    }
    cleanup_master(
        control
            .parent()
            .context("SSH account control has no directory")?,
    )?;
    fs::remove_file(path)?;
    Ok(())
}

fn keepers_running(domain: &Domain) -> Result<usize> {
    let Some(index) = existing_directory(domain)? else {
        return Ok(0);
    };
    let mut running = 0;
    for entry in fs::read_dir(index)? {
        let path = entry?.path();
        if !index_name(&path, "lock") {
            continue;
        }
        let lock = private_file(&path, 0)?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::WouldBlock {
                return Err(error.into());
            }
            running += 1;
        } else {
            drop(KeeperLock(lock));
        }
    }
    Ok(running)
}

pub(super) fn wait_for_keepers(domain: &Domain) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut progress = Instant::now();
    loop {
        let running = keepers_running(domain)?;
        if running == 0 {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("{running} approved SSH keepers did not release their scope within 10 seconds");
        }
        if progress.elapsed() >= Duration::from_secs(1) {
            crate::output::diagnostic!("syq: waiting for {running} approved SSH keepers to close");
            progress = Instant::now();
        }
        std::thread::sleep(POLL);
    }
}

fn master_name(name: &str) -> bool {
    name.strip_prefix("cm-")
        .is_some_and(|hash| hash.len() == 16 && hash.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Validate sidecars before asking the shared pool machinery to remove them.
/// The caller already owns the recorded control path; names alone do not grant
/// permission to unlink a symlink, ordinary file in place of a socket, or a
/// non-private lock file.
fn validate_pool_files(control: &Path) -> Result<()> {
    let socket = crate::session_pool::socket_path(control);
    match socket.symlink_metadata() {
        Ok(metadata) => anyhow::ensure!(
            metadata.file_type().is_socket() && metadata.uid() == unsafe { libc::geteuid() },
            "unexpected approved SSH pool socket {}",
            socket.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    match private_file(&crate::session_pool::lock_path(control), 0) {
        Ok(_) => {}
        Err(error) if not_found(&error) => {}
        Err(error) => return Err(error),
    }
    Ok(())
}

pub(super) fn stop_pool(control: &Path) -> Result<()> {
    validate_pool_files(control)?;
    crate::session_pool::stop(control)
}

fn not_found(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
}

fn cleanup_master(scope: &Path) -> Result<()> {
    let result = cleanup_master_present(scope);
    match result {
        Err(error)
            if not_found(&error)
                && scope
                    .symlink_metadata()
                    .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
        {
            // The keeper owns this temporary directory and may finish removing
            // it between our directory inventory and validation.
            Ok(())
        }
        result => result,
    }
}

fn cleanup_master_present(scope: &Path) -> Result<()> {
    crate::persistence::validate_scope(scope)?;
    let mut paths = Vec::new();
    let mut controls = std::collections::BTreeSet::new();
    for entry in fs::read_dir(scope)? {
        let path = entry?.path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .context("unexpected non-UTF-8 approved SSH scope file")?;
        let metadata = match path.symlink_metadata() {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if master_name(name) {
            anyhow::ensure!(
                metadata.file_type().is_socket() && metadata.uid() == unsafe { libc::geteuid() },
                "unexpected approved SSH control file {}",
                path.display()
            );
            controls.insert(path.clone());
        } else if let Some(name) = crate::session_pool::owned_name(name.as_bytes()) {
            let name = std::str::from_utf8(name)?;
            anyhow::ensure!(
                master_name(name),
                "unexpected approved SSH pool file {}",
                path.display()
            );
            let control = scope.join(name);
            // An orphaned pool remains owned after its socket disappears, but
            // only a registered endpoint can own these sidecar names.
            let record = private_file(&control.with_extension("json"), 128 * 1024)?;
            let _: crate::persistence::EndpointRecord = serde_json::from_reader(record)
                .with_context(|| format!("parse approved SSH endpoint {}", control.display()))?;
            validate_pool_files(&control)?;
            controls.insert(control);
        } else if let Some(hash) = name.strip_prefix("tool-").or_else(|| {
            (name.len() == 40 && name.bytes().all(|b| b.is_ascii_hexdigit())).then_some(name)
        }) {
            anyhow::ensure!(
                !hash.is_empty()
                    && hash.bytes().all(|b| b.is_ascii_hexdigit())
                    && metadata.file_type().is_symlink(),
                "unexpected approved SSH tool alias {}",
                path.display()
            );
            let target = fs::read_link(&path)?;
            anyhow::ensure!(
                target.components().count() == 1 && target.to_str().is_some_and(master_name),
                "invalid approved SSH tool alias {}",
                path.display()
            );
        } else {
            let recognized = name == crate::receive_service::CLOSING
                || name == ".syq-persistence"
                || [".json", ".generation", ".peer.json"]
                    .iter()
                    .any(|suffix| name.strip_suffix(suffix).is_some_and(master_name));
            anyhow::ensure!(
                recognized,
                "unexpected file in approved SSH scope {}",
                path.display()
            );
            match private_file(&path, 128 * 1024) {
                Ok(_) => {}
                Err(error) if not_found(&error) => continue,
                Err(error) => return Err(error),
            }
        }
        paths.push(path);
    }
    // Finish validation before shutdown can remove any pool files. Each pool
    // stops before its master, including pools whose master already exited.
    for control in controls {
        let endpoint = NativeEndpoint {
            user: None,
            host: "syq-control".into(),
            port: None,
        };
        close_master(&Record {
            version: 1,
            authorizer: Provider::Return("cleanup".into()),
            requested: endpoint.clone(),
            endpoint,
            control,
        })?;
    }
    for path in paths {
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    fs::remove_dir(scope)?;
    Ok(())
}

/// Called after the selected domain is marked closing. stop_all retires each
/// recorded master in either domain; explicit scopes also remove their index.
/// The default domain keeps lock files for concurrent future starters.
pub(crate) fn cleanup_domain(domain: &Domain) -> Result<()> {
    if domain.is_default() {
        return Ok(());
    }
    let scope = domain.runtime_path();
    crate::persistence::validate_scope(&scope)?;
    anyhow::ensure!(
        scope.join(crate::receive_service::CLOSING).exists(),
        "SSH account cleanup requires a closing persistence scope"
    );
    wait_for_keepers(domain)?;
    super::resolution::cleanup(domain)?;
    // Any remaining approved directory belongs to an exited keeper. Never
    // recursively remove it: validate every owned file and close native SSH.
    for entry in fs::read_dir(&scope)? {
        let path = entry?.path();
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("approved-"))
        {
            cleanup_master(&path)?;
        }
    }
    let Some(index) = existing_directory(domain)? else {
        return Ok(());
    };
    let mut paths = Vec::new();
    for entry in fs::read_dir(&index)? {
        let path = entry?.path();
        if index_name(&path, "json") {
            let record =
                read_record(&path)?.context("SSH account record disappeared during cleanup")?;
            anyhow::ensure!(
                record.control.parent().and_then(Path::parent) == Some(scope.as_path()),
                "SSH account record belongs to another persistence scope"
            );
        } else if index_name(&path, "lock") {
            private_file(&path, 0)?;
        } else if path.file_name().is_some_and(|name| name == GENERATION) {
            read_generation(&path)?;
        } else {
            bail!("unexpected file in SSH account index {}", path.display());
        }
        paths.push(path);
    }
    for path in paths {
        fs::remove_file(path)?;
    }
    fs::remove_dir(index)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::BufRead;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    fn temporary() -> tempfile::TempDir {
        // Leave room for OpenSSH's temporary control suffix under macOS's
        // longer ambient temporary directory, without switching fixture roots.
        tempfile::Builder::new()
            .prefix("")
            .tempdir_in(crate::test_support::temp_dir())
            .unwrap()
    }

    fn registered_control(scope: &Path) -> PathBuf {
        crate::persistence::initialize_scope(scope).unwrap();
        crate::persistence::prepare_endpoint(scope, None, "host.invalid", None, None).unwrap()
    }

    fn pool_lock(control: &Path) -> File {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(crate::session_pool::lock_path(control))
            .unwrap()
    }

    fn record(control: PathBuf) -> Record {
        let endpoint = NativeEndpoint {
            user: None,
            host: "host.invalid".into(),
            port: None,
        };
        Record {
            version: 1,
            authorizer: Provider::Return("test".into()),
            requested: endpoint.clone(),
            endpoint,
            control,
        }
    }

    fn stored_record(root: &Path, control: PathBuf) -> (PathBuf, File) {
        let path = root.join(format!("{}.json", "a".repeat(64)));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        serde_json::to_writer(&mut file, &record(control)).unwrap();
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path.with_extension("lock"))
            .unwrap();
        (path, lock)
    }

    #[test]
    fn retired_record_removes_dead_master_state_but_preserves_lock_inode() {
        let root = crate::test_support::short_tempdir().unwrap();
        let scope = root.path().join("approved-dead");
        let control = registered_control(&scope);
        let (path, lock) = stored_record(root.path(), control.clone());
        fs::write(scope.join(crate::receive_service::CLOSING), b"").unwrap();
        fs::set_permissions(
            scope.join(crate::receive_service::CLOSING),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        retire_record(&path, &control).unwrap();
        assert!(!scope.exists());
        assert!(!path.exists());
        assert_eq!(
            lock.metadata().unwrap().ino(),
            path.with_extension("lock").metadata().unwrap().ino()
        );
        retire_record(&path, &control).unwrap();
    }

    #[test]
    fn retiring_record_preserves_active_or_replacement_keeper() {
        let root = crate::test_support::short_tempdir().unwrap();
        let scope = root.path().join("approved-old");
        let control = registered_control(&scope);
        let (path, lock) = stored_record(root.path(), control.clone());
        assert_eq!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        let lock = KeeperLock(lock);
        retire_record(&path, &control).unwrap();
        assert!(path.exists());
        assert!(scope.exists());
        drop(lock);
        let replacement = registered_control(&root.path().join("approved-new"));
        fs::write(
            &path,
            serde_json::to_vec(&record(replacement.clone())).unwrap(),
        )
        .unwrap();
        retire_record(&path, &control).unwrap();
        assert_eq!(read_record(&path).unwrap().unwrap().control, replacement);
        assert!(scope.exists());
        assert!(replacement.parent().unwrap().exists());
    }

    #[test]
    fn retiring_record_preserves_unknown_files_and_damaged_records() {
        let root = crate::test_support::short_tempdir().unwrap();
        let scope = root.path().join("approved-dead");
        let control = registered_control(&scope);
        let (path, _lock) = stored_record(root.path(), control.clone());
        fs::write(scope.join("user-file"), b"keep").unwrap();
        assert!(retire_record(&path, &control).is_err());
        assert_eq!(fs::read(scope.join("user-file")).unwrap(), b"keep");
        assert!(path.exists());
        fs::write(&path, b"damaged record").unwrap();
        assert!(retire_record(&path, &control).is_err());
        assert_eq!(fs::read(path).unwrap(), b"damaged record");
    }

    #[test]
    fn stale_registered_pool_is_cleaned_after_its_master_disappears() {
        let temporary = temporary();
        let scope = temporary.path().join("a");
        let control = registered_control(&scope);
        drop(UnixListener::bind(crate::session_pool::socket_path(&control)).unwrap());
        drop(pool_lock(&control));
        // Both previously exported tool-* aliases and the shorter full-hash
        // spelling remain owned by their recorded master.
        for alias in ["tool-0123456789abcdef".to_owned(), "a".repeat(40)] {
            std::os::unix::fs::symlink(control.file_name().unwrap(), scope.join(alias)).unwrap();
        }
        cleanup_master(&scope).unwrap();
        assert!(!scope.exists());
    }

    #[test]
    fn unregistered_pool_and_foreign_sidecars_are_preserved() {
        let temporary = temporary();
        let scope = temporary.path().join("a");
        let control = registered_control(&scope);
        let socket = crate::session_pool::socket_path(&control);
        // An ordinary file at the pool socket path must not be unlinked.
        fs::write(&socket, b"keep").unwrap();
        assert!(cleanup_master(&scope).is_err());
        assert_eq!(fs::read(&socket).unwrap(), b"keep");
        fs::remove_file(&socket).unwrap();
        // A private-looking pool without its endpoint record is not owned.
        drop(UnixListener::bind(&socket).unwrap());
        drop(pool_lock(&control));
        fs::remove_file(control.with_extension("json")).unwrap();
        assert!(cleanup_master(&scope).is_err());
        assert!(socket.exists());
        assert!(crate::session_pool::lock_path(&control).exists());
    }

    #[test]
    fn pool_cleanup_preserves_symlinks_and_non_private_locks() {
        let temporary = temporary();
        let control = registered_control(&temporary.path().join("a"));
        let outside = temporary.path().join("keep");
        fs::write(&outside, b"keep").unwrap();
        let socket = crate::session_pool::socket_path(&control);
        std::os::unix::fs::symlink(&outside, &socket).unwrap();
        assert!(stop_pool(&control).is_err());
        assert!(socket.symlink_metadata().unwrap().file_type().is_symlink());
        fs::remove_file(&socket).unwrap();
        let lock = crate::session_pool::lock_path(&control);
        std::os::unix::fs::symlink(&outside, &lock).unwrap();
        assert!(stop_pool(&control).is_err());
        assert_eq!(fs::read(&outside).unwrap(), b"keep");
        assert!(lock.symlink_metadata().unwrap().file_type().is_symlink());
        fs::remove_file(&lock).unwrap();
        drop(pool_lock(&control));
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(stop_pool(&control).is_err());
        assert!(lock.exists());
    }

    #[test]
    fn pool_stops_before_approved_master_retirement() {
        let temporary = temporary();
        let control = registered_control(&temporary.path().join("a"));
        // A stale socket makes real OpenSSH's shutdown fail promptly, then the
        // existing master cleanup removes it. It must still exist at pool exit.
        drop(UnixListener::bind(&control).unwrap());
        let lock = pool_lock(&control);
        assert_eq!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        let listener = UnixListener::bind(crate::session_pool::socket_path(&control)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let observed_control = control.clone();
        let pool = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut progress = Instant::now();
            loop {
                match listener.accept() {
                    Ok((stream, _)) => {
                        // BSD accepts inherit the listener's nonblocking mode.
                        stream.set_nonblocking(false).unwrap();
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let mut request = String::new();
                        std::io::BufReader::new(&stream)
                            .read_line(&mut request)
                            .unwrap();
                        let request: serde_json::Value = serde_json::from_str(&request).unwrap();
                        assert_eq!(request["exit"], true);
                        assert!(observed_control.exists(), "master retired before pool stop");
                        let reply = serde_json::to_vec(&serde_json::json!({
                            "status": "exiting", "identity": crate::identity::build()
                        }))
                        .unwrap();
                        crate::descriptor_broker::send_message(stream.as_raw_fd(), &reply, &[])
                            .unwrap();
                        break;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "pool did not receive shutdown");
                        if progress.elapsed() >= Duration::from_secs(1) {
                            eprintln!("waiting for approved pool shutdown");
                            progress = Instant::now();
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("accept pool shutdown: {error}"),
                }
            }
            // flock is shared with transient forked descriptors in parallel
            // tests; release it explicitly before reporting pool completion.
            assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_UN) }, 0);
        });
        let result = close_master(&record(control.clone()));
        pool.join().unwrap();
        result.unwrap();
        assert!(!control.exists());
        assert!(!crate::session_pool::socket_path(&control).exists());
        assert!(!crate::session_pool::lock_path(&control).exists());
    }

    #[test]
    fn invalid_pool_does_not_prevent_master_retirement() {
        let temporary = temporary();
        let control = registered_control(&temporary.path().join("a"));
        drop(UnixListener::bind(&control).unwrap());
        let socket = crate::session_pool::socket_path(&control);
        fs::write(&socket, b"keep").unwrap();
        assert!(close_master(&record(control.clone())).is_err());
        assert!(!control.exists());
        assert_eq!(fs::read(socket).unwrap(), b"keep");
    }

    #[test]
    fn keeper_drop_cleans_pool_without_requiring_a_live_master() {
        let temporary = temporary();
        let control = registered_control(&temporary.path().join("a"));
        drop(UnixListener::bind(crate::session_pool::socket_path(&control)).unwrap());
        drop(pool_lock(&control));
        drop(KeeperPool::new(&control));
        assert!(!crate::session_pool::socket_path(&control).exists());
        assert!(!crate::session_pool::lock_path(&control).exists());
    }

    #[test]
    fn disappeared_scope_is_finished_but_damaged_present_scope_is_an_error() {
        let temporary = temporary();
        let scope = temporary.path().join("a");
        registered_control(&scope);
        fs::remove_file(scope.join(".syq-persistence")).unwrap();
        assert!(cleanup_master(&scope).is_err());
        fs::remove_dir_all(&scope).unwrap();
        cleanup_master(&scope).unwrap();
    }

    #[test]
    fn closing_waits_for_unpublished_keeper_ownership_before_removing_its_directory() {
        let temporary = crate::test_support::short_tempdir().unwrap();
        let scope = temporary.path().join("scope");
        crate::persistence::initialize_scope(&scope).unwrap();
        let domain = Domain::select(Some(&scope)).unwrap();
        let index = directory(&domain).unwrap();
        let lock = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(index.join(format!("{}.lock", "a".repeat(64))))
            .unwrap();
        assert_eq!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        let approved = scope.join("approved-starting");
        crate::persistence::initialize_scope(&approved).unwrap();
        assert_eq!(keepers_running(&domain).unwrap(), 1);
        // Models keeper Drop: its temporary scope is removed before its lock.
        let keeper = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            fs::remove_file(approved.join(".syq-persistence")).unwrap();
            fs::remove_dir(approved).unwrap();
            drop(lock);
        });
        wait_for_keepers(&domain).unwrap();
        keeper.join().unwrap();
        assert!(!scope.join("approved-starting").exists());
        assert_eq!(keepers_running(&domain).unwrap(), 0);
    }
}

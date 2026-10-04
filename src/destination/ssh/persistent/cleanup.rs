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

fn cleanup_master(scope: &Path) -> Result<()> {
    crate::persistence::validate_scope(scope)?;
    let mut paths = Vec::new();
    for entry in fs::read_dir(scope)? {
        let path = entry?.path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .context("unexpected non-UTF-8 approved SSH scope file")?;
        let metadata = path.symlink_metadata()?;
        if master_name(name) {
            anyhow::ensure!(
                metadata.file_type().is_socket() && metadata.uid() == unsafe { libc::geteuid() },
                "unexpected approved SSH control file {}",
                path.display()
            );
            let record = Record {
                version: 1,
                authorizer: String::new(),
                requested: NativeEndpoint {
                    user: None,
                    host: "syq-control".into(),
                    port: None,
                },
                endpoint: NativeEndpoint {
                    user: None,
                    host: "syq-control".into(),
                    port: None,
                },
                control: path.clone(),
            };
            if live(&record) {
                close_master(&record)?;
            }
        } else if let Some(hash) = name.strip_prefix("tool-") {
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
            private_file(&path, 128 * 1024)?;
        }
        paths.push(path);
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

/// Called after the selected domain is marked closing. Default legacy index
/// files are deliberately retained; explicit scopes remove their owned state.
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

    #[test]
    fn closing_waits_for_unpublished_keeper_ownership_before_removing_its_directory() {
        let temporary = tempfile::tempdir_in("/tmp").unwrap();
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

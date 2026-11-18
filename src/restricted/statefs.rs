use super::*;

pub(super) fn current_account() -> Result<(String, PathBuf)> {
    let uid = unsafe { libc::geteuid() };
    let suggested = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let capacity = if suggested > 0 {
        usize::try_from(suggested).unwrap_or(16 * 1024)
    } else {
        16 * 1024
    }
    .clamp(1024, 1024 * 1024);
    let mut buffer = vec![0u8; capacity];
    let mut record: libc::passwd = unsafe { std::mem::zeroed() };
    let mut found = std::ptr::null_mut();
    let result = unsafe {
        libc::getpwuid_r(
            uid,
            &mut record,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut found,
        )
    };
    if result != 0 {
        return Err(std::io::Error::from_raw_os_error(result)).context("resolve current account");
    }
    if found.is_null() || record.pw_name.is_null() || record.pw_dir.is_null() {
        bail!("current effective uid has no passwd entry");
    }
    let name = unsafe { CStr::from_ptr(record.pw_name) }
        .to_str()
        .context("current account name is not UTF-8")?
        .to_owned();
    let home = OsString::from_vec(unsafe { CStr::from_ptr(record.pw_dir) }.to_bytes().to_vec());
    Ok((name, PathBuf::from(home)))
}

pub(super) fn ensure_directory(path: &Path, mode: u32) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                bail!("{} is not a real directory", path.display());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::DirBuilder::new()
                .mode(mode)
                .create(path)
                .with_context(|| format!("create private directory {}", path.display()))?;
        }
        Err(error) => {
            return Err(error).with_context(|| format!("inspect directory {}", path.display()))
        }
    }
    Ok(())
}

pub(super) fn ensure_directory_chain(home: &Path, components: &[&str]) -> Result<PathBuf> {
    let mut path = home.to_path_buf();
    for component in components {
        path.push(component);
        ensure_directory(&path, 0o700)?;
    }
    Ok(path)
}

pub(super) fn ensure_private_chain(home: &Path, components: &[&str]) -> Result<PathBuf> {
    let path = ensure_directory_chain(home, components)?;
    delegation::validate_private_directory_path(&path)?;
    Ok(path)
}

pub(super) fn open_directory(path: &Path) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NOCTTY | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("open private directory {}", path.display()))
}

pub(super) fn lock_directory(directory: &File) -> Result<()> {
    loop {
        if unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX) } == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error).context("lock private directory");
        }
    }
}

pub(super) fn leaf_name(name: &str) -> Result<CString> {
    if name.is_empty() || name.contains('/') || name == "." || name == ".." {
        bail!("invalid private state filename");
    }
    CString::new(name).context("private state filename contains NUL")
}

pub(super) fn read_leaf(
    directory: &File,
    name: &str,
    maximum: usize,
    private: bool,
) -> Result<Option<Vec<u8>>> {
    leaf_name(name)?;
    let rule = if private {
        crate::state_file::FileRule::Exact0600
    } else {
        crate::state_file::FileRule::Regular
    };
    crate::state_file::read_private_at(
        directory,
        name.as_ref(),
        &format!("private state file {name:?}"),
        maximum,
        rule,
    )
}

pub(super) fn atomic_write(
    directory_path: &Path,
    name: &str,
    contents: &[u8],
    mode: u32,
) -> Result<()> {
    delegation::validate_private_directory_path(directory_path)?;
    let directory = open_directory(directory_path)?;
    lock_directory(&directory)?;
    atomic_write_locked(&directory, name, contents, mode, true)
}

pub(super) fn atomic_write_locked(
    directory: &File,
    name: &str,
    contents: &[u8],
    mode: u32,
    existing_private: bool,
) -> Result<()> {
    leaf_name(name)?;
    if let Some(existing) = read_leaf(directory, name, MAX_AUTHORIZED_KEYS, existing_private)? {
        let _ = existing;
    }
    crate::state_file::write_atomic_at(
        directory,
        name.as_ref(),
        contents,
        mode,
        crate::state_file::Publish::Replace,
        crate::state_file::Durability::Synced,
    )
    .context("publish atomic private state file")?;
    Ok(())
}

pub(super) fn atomic_replace_executable_locked(
    directory: &File,
    name: &str,
    contents: &[u8],
) -> Result<()> {
    leaf_name(name)?;
    crate::state_file::write_atomic_at(
        directory,
        name.as_ref(),
        contents,
        0o700,
        crate::state_file::Publish::Replace,
        crate::state_file::Durability::Synced,
    )
    .context("publish restricted receiver")?;
    Ok(())
}

pub(super) fn remove_leaf_locked(directory: &File, name: &str) -> Result<()> {
    let name = leaf_name(name)?;
    loop {
        let result = unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) };
        if result == 0 {
            directory.sync_all()?;
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(());
        }
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error).context("remove private state file");
        }
    }
}

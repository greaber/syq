//! Best-effort interactive installation after a release helper is bootstrapped.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};

pub fn install() {
    if !crate::identity::is_release_build() {
        return;
    }
    let result = (|| {
        let home = std::env::var_os("HOME").context("HOME is not set")?;
        let path = std::env::var_os("PATH").unwrap_or_default();
        let source = std::env::current_exe().context("locate the installed helper")?;
        install_from(&source, Path::new(&home), &path)
    })();
    match result {
        Ok(Some(on_path)) => {
            crate::output::diagnostic!("installed syq {} at ~/.local/bin/syq for use on this server", env!("CARGO_PKG_VERSION"));
            if !on_path {
                crate::output::diagnostic!("add ~/.local/bin to PATH to run it as syq; shell configuration was not changed");
            }
        }
        Ok(None) => {}
        Err(error) => crate::output::diagnostic!("could not install ~/.local/bin/syq ({error:#}); the transfer can still use its cached helper"),
    }
}

fn exists(path: &Path) -> bool {
    // Preserve dangling symlinks and non-executable entries too. Only a definite
    // missing entry permits installation; unreadable entries are not ours to replace.
    !matches!(fs::symlink_metadata(path), Err(error) if matches!(error.kind(), std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory))
}

fn install_from(source: &Path, home: &Path, path: &std::ffi::OsStr) -> Result<Option<bool>> {
    let bin = home.join(".local/bin");
    let destination = bin.join("syq");
    if exists(&destination) || std::env::split_paths(path).any(|dir| exists(&dir.join("syq"))) {
        return Ok(None);
    }
    fs::create_dir_all(&bin).context("create the user binary directory")?;
    let temporary = tempfile::Builder::new()
        .prefix(".syq-install-")
        .tempfile_in(&bin)?;
    // cp exposes filesystem cloning on both supported platforms. A failed clone
    // is harmless: the ordinary copy truncates the private temporary file.
    let clone_flag = if cfg!(target_os = "macos") {
        "-c"
    } else {
        "--reflink=always"
    };
    let cloned = Command::new("cp")
        .arg(clone_flag)
        .arg(source)
        .arg(temporary.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if !cloned {
        fs::copy(source, temporary.path()).context("copy the helper for interactive use")?;
    }
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o755))?;
    fs::File::open(temporary.path())?.sync_all()?;
    // Atomic no-clobber publication protects installations created concurrently.
    // This never links the interactive command to the cached helper inode.
    match temporary.persist_noclobber(&destination) {
        Ok(_) => {}
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => return Ok(None),
        Err(error) => return Err(error.error.into()),
    }
    Ok(Some(std::env::split_paths(path).any(|dir| dir == bin)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, MetadataExt};

    #[test]
    fn installs_independent_copy_and_preserves_it_on_later_connections() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("helper");
        let home = root.path().join("home with spaces");
        let bin = home.join(".local/bin");
        fs::write(&source, b"first release").unwrap();
        assert_eq!(
            install_from(&source, &home, bin.as_os_str()).unwrap(),
            Some(true)
        );
        let destination = bin.join("syq");
        assert_ne!(
            fs::metadata(&source).unwrap().ino(),
            fs::metadata(&destination).unwrap().ino()
        );
        assert_eq!(
            fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
            0o755
        );
        fs::write(&source, b"second release").unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"first release");
        assert_eq!(install_from(&source, &home, bin.as_os_str()).unwrap(), None);
        fs::write(&destination, b"self updated").unwrap();
        assert_eq!(fs::read(&source).unwrap(), b"second release");
    }

    #[test]
    fn preserves_existing_path_entries_and_dangling_destination_symlinks() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let other = root.path().join("other-bin");
        fs::create_dir_all(&other).unwrap();
        fs::write(other.join("syq"), b"existing install").unwrap();
        let source = root.path().join("missing helper");
        assert_eq!(
            install_from(&source, &home, other.as_os_str()).unwrap(),
            None
        );
        assert!(!home.exists());
        let bin = home.join(".local/bin");
        fs::create_dir_all(&bin).unwrap();
        symlink("missing", bin.join("syq")).unwrap();
        assert_eq!(install_from(&source, &home, "".as_ref()).unwrap(), None);
        assert_eq!(
            fs::read_link(bin.join("syq")).unwrap(),
            Path::new("missing")
        );
    }

    #[test]
    fn reports_missing_path_and_leaves_no_temporary_files() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("helper");
        fs::write(&source, b"release").unwrap();
        assert_eq!(
            install_from(&source, root.path(), "".as_ref()).unwrap(),
            Some(false)
        );
        assert_eq!(
            fs::read_dir(root.path().join(".local/bin"))
                .unwrap()
                .count(),
            1
        );
    }
}

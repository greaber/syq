//! Best-effort interactive installation after a release helper is bootstrapped.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};

pub const NOTICE_PREFIX: &str = "syq-remote-install-notice:";

fn notice(message: impl std::fmt::Display) {
    for line in message.to_string().lines() {
        crate::output::diagnostic!("{NOTICE_PREFIX}{line}");
    }
}

pub fn install() {
    if !crate::identity::is_release_build() {
        return;
    }
    let result: Result<Option<bool>> = (|| {
        let home = std::env::var_os("HOME").context("HOME is not set")?;
        let path = std::env::var_os("PATH").unwrap_or_default();
        let source = std::env::current_exe().context("locate the installed helper")?;
        // The standalone receipt can describe an installation outside SSH's PATH.
        // Leave that installation and its update authority alone too.
        if crate::update::standalone_receipt_exists()? {
            return Ok(None);
        }
        let installed = install_from(&source, Path::new(&home), &path)?;
        if installed.is_some() {
            let registration = Path::new(&home)
                .join(".local/bin/syq")
                .canonicalize()
                .context("locate the installed command for self-update")
                .and_then(crate::update::register_standalone_install_at);
            if let Err(error) = registration {
                notice(format!("installed ~/.local/bin/syq, but could not enable self-update ({error:#}); rerun the standalone installer to enable updates"));
            }
        }
        Ok(installed)
    })();
    match result {
        Ok(Some(on_path)) => {
            notice(format!("installed syq {} at ~/.local/bin/syq for use on this server", env!("CARGO_PKG_VERSION")));
            if !on_path {
                notice("~/.local/bin is absent from the non-interactive SSH PATH; if syq is unavailable after login, add it to your shell PATH");
            }
        }
        Ok(None) => {}
        Err(error) => notice(format!("could not install ~/.local/bin/syq ({error:#}); the transfer can still use its cached helper")),
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
    if exists(&destination)
        || std::env::split_paths(path).any(|dir| {
            fs::metadata(dir.join("syq")).is_ok_and(|metadata| {
                metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
            })
        })
    {
        return Ok(None);
    }
    fs::create_dir_all(&bin).context("create the user binary directory")?;
    let temporary = tempfile::Builder::new()
        .prefix(".syq-install-")
        .tempfile_in(&bin)?;
    // cp prefers cloning on both supported platforms. If the tool is missing
    // or fails, the ordinary copy truncates the private temporary file.
    let clone_flag = if cfg!(target_os = "macos") {
        "-c"
    } else {
        "--reflink=auto"
    };
    let copied = Command::new("cp")
        .arg(clone_flag)
        .arg(source)
        .arg(temporary.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if !copied {
        fs::copy(source, temporary.path()).context("copy the helper for interactive use")?;
    }
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o755))?;
    // macOS cp -c may replace the temporary inode; sync the file being published.
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
        fs::set_permissions(other.join("syq"), fs::Permissions::from_mode(0o755)).unwrap();
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
    fn inaccessible_path_directory_does_not_block_install_but_destination_does() {
        if unsafe { libc::geteuid() } == 0 {
            return; // Root bypasses the directory search permissions under test.
        }
        let root = tempfile::tempdir().unwrap();
        let blocked = root.path().join("module-bin");
        let source = root.path().join("helper");
        let home = root.path().join("home");
        fs::write(&source, b"release").unwrap();
        fs::create_dir(&blocked).unwrap();
        fs::set_permissions(&blocked, fs::Permissions::from_mode(0o000)).unwrap();
        assert_eq!(
            fs::metadata(blocked.join("syq")).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        let result = install_from(&source, &home, blocked.as_os_str());
        fs::set_permissions(&blocked, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(result.unwrap(), Some(false));
        assert_eq!(fs::read(home.join(".local/bin/syq")).unwrap(), b"release");

        let bin = home.join(".local/bin");
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o000)).unwrap();
        let result = install_from(&source, &home, "".as_ref());
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn non_commands_on_path_do_not_suppress_installation() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("helper");
        fs::write(&source, b"release").unwrap();
        for directory in [false, true] {
            let bin = root.path().join(format!("path-{directory}"));
            fs::create_dir(&bin).unwrap();
            if directory {
                fs::create_dir(bin.join("syq")).unwrap();
            } else {
                fs::write(bin.join("syq"), b"not executable").unwrap();
            }
            let home = root.path().join(format!("home-{directory}"));
            assert_eq!(
                install_from(&source, &home, bin.as_os_str()).unwrap(),
                Some(false)
            );
            assert_eq!(fs::read(home.join(".local/bin/syq")).unwrap(), b"release");
        }
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

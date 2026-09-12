//! Best-effort interactive installation after a release helper is bootstrapped.

use std::fs;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{ensure, Context, Result};

pub const NOTICE_PREFIX: &str = "syq-remote-install-notice:";

fn notice(message: impl std::fmt::Display) {
    for line in message.to_string().lines() {
        crate::output::diagnostic!("{NOTICE_PREFIX}{line}");
    }
}

// This runs only in the short-lived installer process. Let an interrupted copy
// return, then unwind normally so its private temporary directory is removed.
// SIGKILL and crashes can still leave a temporary file behind.
#[derive(Default)]
struct Cancellation {
    cancelled: Arc<AtomicBool>,
    handlers: Vec<signal_hook::SigId>,
}

impl Cancellation {
    fn register() -> Result<Self> {
        let mut cancellation = Self::default();
        for signal in [libc::SIGHUP, libc::SIGINT, libc::SIGTERM] {
            cancellation.handlers.push(signal_hook::flag::register(
                signal,
                cancellation.cancelled.clone(),
            )?);
        }
        Ok(cancellation)
    }

    fn check(&self) -> Result<()> {
        ensure!(
            !self.cancelled.load(Ordering::Relaxed),
            "remote command installation interrupted"
        );
        Ok(())
    }
}

impl Drop for Cancellation {
    fn drop(&mut self) {
        for handler in &self.handlers {
            signal_hook::low_level::unregister(*handler);
        }
    }
}

pub fn install() {
    if !crate::identity::is_release_build() {
        return;
    }
    let result: Result<bool> = (|| {
        let cancellation = Cancellation::register()?;
        let home = std::env::var_os("HOME")
            .filter(|value| !value.is_empty())
            .context("HOME is not set")?;
        let source = std::env::current_exe().context("locate the installed helper")?;
        let destination = Path::new(&home).join(".local/bin/syq");
        if exists(&destination)? || crate::update::was_standalone_install(&destination)? {
            return Ok(false);
        }
        let installed = install_from(&source, Path::new(&home), &cancellation)?;
        if installed {
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
        Ok(true) => {
            notice(format!("installed syq {} at ~/.local/bin/syq for use on this server", env!("CARGO_PKG_VERSION")));
            notice("to use it on this server, ensure ~/.local/bin is on your shell PATH");
        }
        Ok(false) => {}
        Err(error) => notice(format!("could not install ~/.local/bin/syq ({error:#}); the transfer can still use its cached helper")),
    }
}

fn exists(path: &Path) -> Result<bool> {
    // Preserve every existing entry, including dangling links. Failure to inspect
    // the destination must be reported, rather than mistaken for an installation.
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("inspect {}", path.display())),
    }
}

fn check_directory(path: &Path) -> Result<()> {
    let metadata = fs::metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    ensure!(metadata.is_dir(), "{} is not a directory", path.display());
    ensure!(
        metadata.uid() == unsafe { libc::geteuid() } || metadata.uid() == 0,
        "{} is not owned by this user or root",
        path.display()
    );
    ensure!(
        metadata.mode() & 0o002 == 0,
        "{} is other-writable; leaving its permissions unchanged",
        path.display()
    );
    Ok(())
}

fn prepare_bin(home: &Path) -> Result<PathBuf> {
    let local = home.join(".local");
    let bin = local.join("bin");
    for directory in [&local, &bin] {
        match fs::DirBuilder::new().mode(0o755).create(directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error).with_context(|| format!("create {}", directory.display()))
            }
        }
        check_directory(directory)?;
    }
    Ok(bin)
}

fn install_from(source: &Path, home: &Path, cancellation: &Cancellation) -> Result<bool> {
    let destination = home.join(".local/bin/syq");
    if exists(&destination)? {
        return Ok(false);
    }
    cancellation.check()?;
    let bin = prepare_bin(home)?;
    copy_and_publish(source, &bin, &destination, cancellation)
}

fn copy_and_publish(
    source: &Path,
    bin: &Path,
    destination: &Path,
    cancellation: &Cancellation,
) -> Result<bool> {
    let staging = tempfile::Builder::new()
        .prefix(".syq-install-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(bin)?;
    // The destination must not exist for Rust's macOS cloning path. Keep the
    // fresh name inside a private directory; fs::copy handles platform fallbacks.
    let temporary = tempfile::TempPath::try_from_path(staging.path().join("syq"))?;
    fs::copy(source, &temporary).context("copy the helper for interactive use")?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o755))?;
    fs::File::open(&temporary)?.sync_all()?;
    cancellation.check()?;
    // Atomic no-clobber publication never links to the cached helper inode.
    match temporary.persist_noclobber(destination) {
        Ok(_) => {}
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => return Ok(false),
        Err(error) => return Err(error.error.into()),
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn installs_independent_copy_preserves_it_and_reinstalls_after_removal() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("helper");
        let home = root.path().join("home with spaces");
        fs::DirBuilder::new().mode(0o700).create(&home).unwrap();
        let cancellation = Cancellation::default();
        fs::write(&source, b"first release").unwrap();
        assert!(install_from(&source, &home, &cancellation).unwrap());
        let destination = home.join(".local/bin/syq");
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
        assert!(!install_from(&source, &home, &cancellation).unwrap());
        fs::write(&destination, b"self updated").unwrap();
        assert_eq!(fs::read(&source).unwrap(), b"second release");
        fs::remove_file(&destination).unwrap();
        assert!(install_from(&source, &home, &cancellation).unwrap());
        assert_eq!(fs::read(&destination).unwrap(), b"second release");
    }

    #[test]
    fn preserves_dangling_destination_symlinks() {
        let root = tempfile::tempdir().unwrap();
        let bin = root.path().join(".local/bin");
        fs::create_dir_all(&bin).unwrap();
        symlink("missing", bin.join("syq")).unwrap();
        assert!(!install_from(
            &root.path().join("missing helper"),
            root.path(),
            &Cancellation::default()
        )
        .unwrap());
        assert_eq!(
            fs::read_link(bin.join("syq")).unwrap(),
            Path::new("missing")
        );
    }

    #[test]
    fn refuses_other_writable_install_directories_without_changing_permissions() {
        let root = tempfile::tempdir().unwrap();
        let bin = root.path().join(".local/bin");
        fs::create_dir_all(&bin).unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o777)).unwrap();
        let error = prepare_bin(root.path()).unwrap_err();
        assert!(error.to_string().contains("other-writable"));
        assert_eq!(fs::metadata(&bin).unwrap().mode() & 0o777, 0o777);
        assert!(!bin.join("syq").exists());
    }

    #[test]
    fn accepts_group_writable_and_setgid_layouts_without_chmod() {
        for mode in [0o775, 0o2775] {
            let root = tempfile::tempdir().unwrap();
            let home = root.path().join("home");
            let local = home.join(".local");
            let bin = local.join("bin");
            fs::create_dir_all(&bin).unwrap();
            for directory in [&home, &local, &bin] {
                fs::set_permissions(directory, fs::Permissions::from_mode(mode)).unwrap();
            }
            let source = root.path().join("helper");
            fs::write(&source, b"release").unwrap();
            assert!(install_from(&source, &home, &Cancellation::default()).unwrap());
            for directory in [&home, &local, &bin] {
                assert_eq!(fs::metadata(directory).unwrap().mode() & 0o7777, mode);
            }
        }
    }

    #[test]
    fn lookup_errors_are_reported_and_do_not_create_a_command() {
        let root = tempfile::tempdir().unwrap();
        let local = root.path().join(".local");
        symlink(".local", &local).unwrap();
        let error = install_from(
            &root.path().join("helper"),
            root.path(),
            &Cancellation::default(),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("inspect"));
        assert_eq!(fs::read_link(local).unwrap(), Path::new(".local"));
    }

    #[test]
    fn cancellation_before_publication_cleans_up_the_completed_copy() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("helper");
        fs::write(&source, b"release").unwrap();
        let bin = prepare_bin(root.path()).unwrap();
        let cancellation = Cancellation::default();
        cancellation.cancelled.store(true, Ordering::Relaxed);
        let error = copy_and_publish(&source, &bin, &bin.join("syq"), &cancellation).unwrap_err();
        assert!(error.to_string().contains("interrupted"));
        assert_eq!(fs::read_dir(bin).unwrap().count(), 0);
    }
}

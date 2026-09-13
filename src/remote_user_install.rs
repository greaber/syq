//! Best-effort interactive installation after a release helper is bootstrapped.

use std::fs;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context, Result};

pub const NOTICE_PREFIX: &str = "syq-remote-install-notice:";

fn notice(message: impl std::fmt::Display) {
    for line in message.to_string().lines() {
        crate::output::diagnostic!("\n{NOTICE_PREFIX}{line}");
    }
}

enum InstallOutcome {
    Unchanged,
    Installed,
    Unregistered(anyhow::Error),
}

pub fn install() {
    if !crate::identity::is_release_build() {
        return;
    }
    let result: Result<InstallOutcome> = (|| {
        let home = std::env::var_os("HOME")
            .filter(|value| !value.is_empty())
            .context("HOME is not set")?;
        let source = running_executable()?;
        let Some(destination) = install_from(&source, Path::new(&home))? else {
            return Ok(InstallOutcome::Unchanged);
        };
        let registration = destination
            .canonicalize()
            .context("locate the installed command for self-update")
            .and_then(crate::update::register_standalone_install_at);
        Ok(match registration {
            Ok(()) => InstallOutcome::Installed,
            Err(error) => InstallOutcome::Unregistered(error),
        })
    })();
    match result {
        Ok(InstallOutcome::Installed) => {
            notice(format!("installed syq {} at ~/.local/bin/syq for use on this server", env!("CARGO_PKG_VERSION")));
            notice("to use it on this server, ensure ~/.local/bin is on your shell PATH");
        }
        Ok(InstallOutcome::Unchanged) => {}
        Ok(InstallOutcome::Unregistered(error)) => notice(format!("installed ~/.local/bin/syq, but could not enable self-update ({error:#}); rerun the standalone installer to enable updates")),
        Err(error) => notice(format!("could not install ~/.local/bin/syq ({error:#}); the transfer can still use its cached helper")),
    }
}

fn running_executable() -> Result<PathBuf> {
    // Open the proc link itself: readlink/current_exe may describe an unlinked
    // inode as "path (deleted)" when another bootstrap replaces the cache entry.
    #[cfg(target_os = "linux")]
    {
        Ok(PathBuf::from("/proc/self/exe"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::env::current_exe().context("locate the installed helper")
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

fn install_from(source: &Path, home: &Path) -> Result<Option<PathBuf>> {
    let destination = home.join(".local/bin/syq");
    if exists(&destination)? || crate::update::was_standalone_install(&destination)? {
        return Ok(None);
    }
    let bin = prepare_bin(home)?;
    Ok(copy_and_publish(source, &bin, &destination)?.then_some(destination))
}

fn copy_and_publish(source: &Path, bin: &Path, destination: &Path) -> Result<bool> {
    // Use default signal handling. Termination may leave this private staging
    // directory behind; normal returns and errors remove it.
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
    fn installs_after_running_helper_is_replaced() {
        const CHILD_HOME: &str = "SYQ_TEST_REPLACED_HELPER_HOME";
        const TEST_ARGS: [&str; 3] = [
            "--exact",
            "remote_user_install::tests::installs_after_running_helper_is_replaced",
            "--nocapture",
        ];
        if let Some(home) = std::env::var_os(CHILD_HOME) {
            let home = PathBuf::from(home);
            let original = std::env::current_exe().unwrap();
            if std::env::var_os("SYQ_TEST_HELPER_COPY_READY").is_none() {
                // Prepare the executable in isolation: parallel tests can fork
                // with its writable fd, briefly preventing exec with ETXTBSY.
                use std::os::unix::process::CommandExt;
                let helper = home.join("helper");
                fs::copy(&original, &helper).unwrap();
                let error = std::process::Command::new(helper)
                    .args(TEST_ARGS)
                    .env("SYQ_TEST_HELPER_COPY_READY", "1")
                    .exec();
                panic!("execute disposable helper: {error}");
            }
            // This is a disposable copy of the test executable, never Cargo's.
            let replacement = home.join("replacement");
            fs::copy(&original, &replacement).unwrap();
            fs::rename(&replacement, &original).unwrap();
            #[cfg(target_os = "linux")]
            assert!(std::env::current_exe()
                .unwrap()
                .to_string_lossy()
                .ends_with(" (deleted)"));
            let installed = install_from(&running_executable().unwrap(), &home)
                .unwrap()
                .unwrap();
            assert_eq!(fs::read(&installed).unwrap(), fs::read(&original).unwrap());
            return;
        }
        let home = tempfile::tempdir().unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(TEST_ARGS)
            .env(CHILD_HOME, home.path())
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(home.path().join(".local/bin/syq").is_file());
    }

    #[test]
    fn concurrent_publication_preserves_the_winning_copy() {
        let home = tempfile::tempdir().unwrap();
        let bin = prepare_bin(home.path()).unwrap();
        let destination = bin.join("syq");
        let sources = [home.path().join("first"), home.path().join("second")];
        for (index, source) in sources.iter().enumerate() {
            fs::write(source, [index as u8; 4096]).unwrap();
        }
        let barrier = std::sync::Barrier::new(2);
        let outcomes = std::thread::scope(|scope| {
            let handles: Vec<_> = sources
                .iter()
                .map(|source| {
                    let (barrier, bin, destination) = (&barrier, &bin, &destination);
                    scope.spawn(move || {
                        barrier.wait();
                        copy_and_publish(source, bin, destination).unwrap()
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(outcomes.iter().filter(|won| **won).count(), 1);
        let winner = outcomes.iter().position(|won| *won).unwrap();
        assert_eq!(
            fs::read(&destination).unwrap(),
            fs::read(&sources[winner]).unwrap()
        );
        assert_eq!(fs::read_dir(&bin).unwrap().count(), 1);
    }

    #[test]
    fn installs_independent_copy_preserves_it_and_reinstalls_after_removal() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("helper");
        let home = root.path().join("home with spaces");
        fs::DirBuilder::new().mode(0o700).create(&home).unwrap();
        fs::write(&source, b"first release").unwrap();
        assert!(install_from(&source, &home).unwrap().is_some());
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
        assert!(install_from(&source, &home).unwrap().is_none());
        fs::write(&destination, b"self updated").unwrap();
        assert_eq!(fs::read(&source).unwrap(), b"second release");
        fs::remove_file(&destination).unwrap();
        assert!(install_from(&source, &home).unwrap().is_some());
        assert_eq!(fs::read(&destination).unwrap(), b"second release");
    }

    #[test]
    fn preserves_dangling_destination_symlinks() {
        let root = tempfile::tempdir().unwrap();
        let bin = root.path().join(".local/bin");
        fs::create_dir_all(&bin).unwrap();
        symlink("missing", bin.join("syq")).unwrap();
        assert!(
            install_from(&root.path().join("missing helper"), root.path())
                .unwrap()
                .is_none()
        );
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
            assert!(install_from(&source, &home).unwrap().is_some());
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
        let error = install_from(&root.path().join("helper"), root.path()).unwrap_err();
        assert!(format!("{error:#}").contains("inspect"));
        assert_eq!(fs::read_link(local).unwrap(), Path::new(".local"));
    }

    #[test]
    fn copy_failure_cleans_up_staging() {
        let root = tempfile::tempdir().unwrap();
        let bin = prepare_bin(root.path()).unwrap();
        let error =
            copy_and_publish(&root.path().join("missing"), &bin, &bin.join("syq")).unwrap_err();
        assert!(error.to_string().contains("copy the helper"));
        assert_eq!(fs::read_dir(bin).unwrap().count(), 0);
    }
}

//! Root-anchored filesystem primitives for restricted receivers.
//!
//! `Root` follows the explicitly selected root path once, opens that directory,
//! and uses only the resulting descriptor afterward. Descendant paths are raw
//! Unix bytes split into validated relative components. Every intermediate
//! component is opened relative to the preceding descriptor with
//! `O_DIRECTORY | O_NOFOLLOW`; leaf operations are performed relative to a
//! held parent descriptor. There is no pathname fallback.
//!
//! This is currently an internal foundation rather than a replacement for the
//! unrestricted rsync-shaped filesystem implementation. It supports existing
//! directory roots, opening existing regular files for reading or writing,
//! creating new regular files and single directories, renaming leaves, and
//! non-recursive unlink/rmdir. Recursive removal, symlink and special-file
//! creation, metadata mutation, missing-root creation, and protocol root IDs
//! remain intentionally unsupported until they can preserve the same
//! confinement guarantee. Roots and directory components must be openable with
//! `O_RDONLY | O_DIRECTORY`.
//!
//! Linux currently uses the same component walk as other Unix platforms. An
//! `openat2` fast path should be added only with tests proving that it has
//! exactly the same root-symlink, descendant-symlink, and mount semantics.
//!
//! The guarantee is pathname confinement. A hard link beneath the root may
//! still refer to an inode with another name outside the root. As with all
//! descriptor-based traversal, an already-open descendant remains the selected
//! object if another process subsequently renames it.

use anyhow::{bail, Context, Result};
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

/// Stable identity of an opened root. Independent helper processes can reopen
/// the configured path and require this identity before serving requests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RootIdentity {
    pub(crate) dev: u64,
    pub(crate) ino: u64,
}

/// A syntactically safe descendant path. Empty means the opened root itself;
/// operations that need a leaf reject it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RelativePath {
    components: Vec<Vec<u8>>,
}

impl RelativePath {
    pub(crate) fn new(path: &[u8]) -> Result<Self> {
        if path.starts_with(b"/") {
            bail!("confined path must be relative");
        }
        if path.contains(&0) {
            bail!("confined path contains NUL");
        }
        if path.is_empty() {
            return Ok(Self {
                components: Vec::new(),
            });
        }

        let mut components = Vec::new();
        for component in path.split(|byte| *byte == b'/') {
            if component.is_empty() {
                bail!("confined path contains an empty component");
            }
            if component == b"." || component == b".." {
                bail!("confined path contains forbidden component");
            }
            components.push(component.to_vec());
        }
        Ok(Self { components })
    }

    fn leaf(&self) -> Result<(&[Vec<u8>], &[u8])> {
        let (leaf, parents) = self
            .components
            .split_last()
            .context("operation requires a descendant path")?;
        Ok((parents, leaf))
    }

    fn label(&self) -> String {
        if self.components.is_empty() {
            return ".".into();
        }
        self.components
            .iter()
            .map(|component| String::from_utf8_lossy(component))
            .collect::<Vec<_>>()
            .join("/")
    }
}

/// An existing directory opened once as the authority boundary.
pub(crate) struct Root {
    directory: File,
    identity: RootIdentity,
}

impl Root {
    /// Open an explicit root. Symlinks in this user-selected path are followed;
    /// symlinks in every later descendant path are rejected.
    pub(crate) fn open(path: &Path) -> Result<Self> {
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(path)
            .with_context(|| format!("open confined root {}", path.display()))?;
        let metadata = directory
            .metadata()
            .with_context(|| format!("stat confined root {}", path.display()))?;
        if !metadata.is_dir() {
            bail!("confined root {} is not a directory", path.display());
        }
        Ok(Self {
            directory,
            identity: RootIdentity {
                dev: metadata.dev(),
                ino: metadata.ino(),
            },
        })
    }

    /// Reopen a root for another process and reject path replacement.
    pub(crate) fn open_verified(path: &Path, expected: RootIdentity) -> Result<Self> {
        let root = Self::open(path)?;
        if root.identity != expected {
            bail!(
                "confined root {} changed identity (expected {}:{}, found {}:{})",
                path.display(),
                expected.dev,
                expected.ino,
                root.identity.dev,
                root.identity.ino
            );
        }
        Ok(root)
    }

    pub(crate) fn identity(&self) -> RootIdentity {
        self.identity
    }

    /// Open the root or a descendant directory without following any
    /// descendant symlink.
    pub(crate) fn open_directory(&self, path: &RelativePath) -> Result<File> {
        let mut directory = self.directory.try_clone().context("duplicate root fd")?;
        for component in &path.components {
            directory = open_directory_at(&directory, component)
                .with_context(|| format!("open confined directory {}", path.label()))?;
        }
        Ok(directory)
    }

    pub(crate) fn open_regular_read(&self, path: &RelativePath) -> Result<File> {
        self.open_regular(path, libc::O_RDONLY, false)
    }

    /// Open an existing regular file for mutation. Truncation occurs only after
    /// the opened descriptor has been verified as a regular file.
    pub(crate) fn open_regular_write(&self, path: &RelativePath, truncate: bool) -> Result<File> {
        self.open_regular(path, libc::O_WRONLY, truncate)
    }

    fn open_regular(
        &self,
        path: &RelativePath,
        access: libc::c_int,
        truncate: bool,
    ) -> Result<File> {
        let parent = self.resolve_parent(path)?;
        let file = open_at(
            parent.directory.as_raw_fd(),
            &parent.leaf,
            access | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            0,
        )
        .with_context(|| format!("open confined regular file {}", path.label()))?;
        require_regular(&file, path)?;
        if truncate {
            file.set_len(0)
                .with_context(|| format!("truncate confined file {}", path.label()))?;
        }
        Ok(file)
    }

    /// Create a new regular leaf. Existing leaves of every type are refused.
    pub(crate) fn create_file(&self, path: &RelativePath, mode: u32) -> Result<File> {
        let parent = self.resolve_parent(path)?;
        let file = open_at(
            parent.directory.as_raw_fd(),
            &parent.leaf,
            libc::O_RDWR
                | libc::O_CREAT
                | libc::O_EXCL
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | libc::O_CLOEXEC,
            mode & 0o7777,
        )
        .with_context(|| format!("create confined file {}", path.label()))?;
        require_regular(&file, path)?;
        Ok(file)
    }

    /// Create exactly one directory. Parents must already exist and be real
    /// directories beneath this root.
    pub(crate) fn create_directory(&self, path: &RelativePath, mode: u32) -> Result<()> {
        let parent = self.resolve_parent(path)?;
        let result = unsafe {
            libc::mkdirat(
                parent.directory.as_raw_fd(),
                parent.leaf.as_ptr(),
                (mode & 0o7777) as libc::mode_t,
            )
        };
        cvt_zero(result).with_context(|| format!("create confined directory {}", path.label()))
    }

    /// Rename one leaf to another. Both parents are resolved and retained
    /// beneath this root before the atomic rename. Existing destinations follow
    /// ordinary `rename(2)` replacement rules.
    pub(crate) fn rename(&self, source: &RelativePath, target: &RelativePath) -> Result<()> {
        let source_parent = self.resolve_parent(source)?;
        let target_parent = self.resolve_parent(target)?;
        let result = unsafe {
            libc::renameat(
                source_parent.directory.as_raw_fd(),
                source_parent.leaf.as_ptr(),
                target_parent.directory.as_raw_fd(),
                target_parent.leaf.as_ptr(),
            )
        };
        cvt_zero(result).with_context(|| {
            format!(
                "rename confined path {} to {}",
                source.label(),
                target.label()
            )
        })
    }

    /// Remove a non-directory leaf. Symlinks are removed themselves, never
    /// followed. Directories are refused by the kernel.
    pub(crate) fn unlink(&self, path: &RelativePath) -> Result<()> {
        self.unlink_with_flags(path, 0, "unlink")
    }

    /// Remove one empty directory. Recursive deletion is intentionally not part
    /// of this foundation.
    pub(crate) fn remove_directory(&self, path: &RelativePath) -> Result<()> {
        self.unlink_with_flags(path, libc::AT_REMOVEDIR, "remove directory")
    }

    fn unlink_with_flags(
        &self,
        path: &RelativePath,
        flags: libc::c_int,
        operation: &str,
    ) -> Result<()> {
        let parent = self.resolve_parent(path)?;
        let result =
            unsafe { libc::unlinkat(parent.directory.as_raw_fd(), parent.leaf.as_ptr(), flags) };
        cvt_zero(result).with_context(|| format!("{operation} confined path {}", path.label()))
    }

    fn resolve_parent(&self, path: &RelativePath) -> Result<ResolvedParent> {
        let (parents, leaf) = path.leaf()?;
        let mut directory = self.directory.try_clone().context("duplicate root fd")?;
        for component in parents {
            directory = open_directory_at(&directory, component)
                .with_context(|| format!("resolve confined parent for {}", path.label()))?;
        }
        Ok(ResolvedParent {
            directory,
            leaf: component_cstring(leaf),
        })
    }
}

struct ResolvedParent {
    directory: File,
    leaf: CString,
}

fn component_cstring(component: &[u8]) -> CString {
    CString::new(component).expect("RelativePath already rejected NUL")
}

fn open_directory_at(parent: &File, component: &[u8]) -> io::Result<File> {
    open_at(
        parent.as_raw_fd(),
        &component_cstring(component),
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        0,
    )
}

fn open_at(parent: RawFd, name: &CString, flags: libc::c_int, mode: u32) -> io::Result<File> {
    // `mode_t` is narrower than `int` on some platforms (including macOS),
    // so C's default argument promotions require an `int` in this variadic
    // position. Our callers have already restricted modes to 0o7777.
    let fd = unsafe { libc::openat(parent, name.as_ptr(), flags, mode as libc::c_int) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn cvt_zero(result: libc::c_int) -> io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn require_regular(file: &File, path: &RelativePath) -> Result<()> {
    if !file.metadata()?.is_file() {
        bail!("confined path {} is not a regular file", path.label());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::fs;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;

    static NEXT_TEST: AtomicU64 = AtomicU64::new(0);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(name: &str) -> Self {
            let n = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("syq-rooted-{name}-{}-{n}", std::process::id()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn relative(path: &[u8]) -> RelativePath {
        RelativePath::new(path).unwrap()
    }

    #[test]
    fn validates_raw_relative_components() {
        assert_eq!(relative(b"").components, Vec::<Vec<u8>>::new());
        assert_eq!(
            relative(b"safe/name").components,
            vec![b"safe".to_vec(), b"name".to_vec()]
        );
        assert_eq!(relative(b"non-utf8-\xff").components[0], b"non-utf8-\xff");

        for unsafe_path in [
            &b"/absolute"[..],
            &b"."[..],
            &b".."[..],
            &b"a/../b"[..],
            &b"a/./b"[..],
            &b"a//b"[..],
            &b"a/"[..],
            &b"nul\0name"[..],
        ] {
            assert!(
                RelativePath::new(unsafe_path).is_err(),
                "accepted {:?}",
                String::from_utf8_lossy(unsafe_path)
            );
        }
    }

    #[test]
    fn follows_only_the_explicit_root_symlink() {
        let tree = TestDir::new("root-symlink");
        let real = tree.path().join("real");
        fs::create_dir(&real).unwrap();
        fs::write(real.join("inside"), b"data").unwrap();
        symlink(&real, tree.path().join("selected")).unwrap();

        let root = Root::open(&tree.path().join("selected")).unwrap();
        let mut file = root.open_regular_read(&relative(b"inside")).unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"data");

        let outside = tree.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("sentinel"), b"unchanged").unwrap();
        symlink(&outside, real.join("escape")).unwrap();
        assert!(root
            .open_regular_read(&relative(b"escape/sentinel"))
            .is_err());
        assert_eq!(fs::read(outside.join("sentinel")).unwrap(), b"unchanged");
    }

    #[test]
    fn root_identity_detects_path_replacement_but_open_root_stays_stable() {
        let tree = TestDir::new("identity");
        let selected = tree.path().join("selected");
        fs::create_dir(&selected).unwrap();
        fs::write(selected.join("old"), b"old").unwrap();
        let root = Root::open(&selected).unwrap();
        let identity = root.identity();

        fs::rename(&selected, tree.path().join("moved")).unwrap();
        fs::create_dir(&selected).unwrap();
        fs::write(selected.join("new"), b"new").unwrap();

        assert!(Root::open_verified(&selected, identity).is_err());
        let mut old = root.open_regular_read(&relative(b"old")).unwrap();
        let mut bytes = Vec::new();
        old.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"old");
        assert!(root.open_regular_read(&relative(b"new")).is_err());
    }

    #[test]
    fn confined_primitives_round_trip_non_utf8_names() {
        let tree = TestDir::new("primitives");
        let root = Root::open(tree.path()).unwrap();
        root.create_directory(&relative(b"dir"), 0o700).unwrap();

        let raw_name = std::ffi::OsString::from_vec(b"stage-\xff".to_vec());
        let stage_path = tree.path().join("dir").join(&raw_name);
        let mut stage = root
            .create_file(&relative(b"dir/stage-\xff"), 0o600)
            .unwrap();
        stage.write_all(b"payload").unwrap();
        stage.flush().unwrap();
        assert_eq!(fs::read(&stage_path).unwrap(), b"payload");

        root.rename(&relative(b"dir/stage-\xff"), &relative(b"dir/final"))
            .unwrap();
        assert!(!stage_path.exists());
        let mut final_file = root
            .open_regular_write(&relative(b"dir/final"), false)
            .unwrap();
        final_file.seek(SeekFrom::End(0)).unwrap();
        final_file.write_all(b"-more").unwrap();
        drop(final_file);
        assert_eq!(
            fs::read(tree.path().join("dir/final")).unwrap(),
            b"payload-more"
        );

        root.unlink(&relative(b"dir/final")).unwrap();
        root.remove_directory(&relative(b"dir")).unwrap();
        assert!(!tree.path().join("dir").exists());
    }

    #[test]
    fn owner_write_only_regular_file_can_be_written_without_escaping_root() {
        let tree = TestDir::new("write-only");
        let root_path = tree.path().join("root");
        let outside = tree.path().join("outside");
        fs::create_dir(&root_path).unwrap();
        fs::create_dir(&outside).unwrap();

        let inside = root_path.join("inside");
        let sentinel = outside.join("sentinel");
        fs::write(&inside, b"initial").unwrap();
        fs::write(&sentinel, b"outside").unwrap();
        fs::set_permissions(&inside, fs::Permissions::from_mode(0o200)).unwrap();
        fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o200)).unwrap();
        assert_eq!(fs::metadata(&inside).unwrap().uid(), unsafe {
            libc::geteuid()
        });
        symlink(&outside, root_path.join("escape")).unwrap();

        let root = Root::open(&root_path).unwrap();
        let mut file = root
            .open_regular_write(&relative(b"inside"), false)
            .unwrap();
        let descriptor_flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        assert_ne!(descriptor_flags, -1);
        assert_eq!(descriptor_flags & libc::O_ACCMODE, libc::O_WRONLY);
        file.write_all(b"updated").unwrap();
        drop(file);
        assert!(root
            .open_regular_write(&relative(b"escape/sentinel"), false)
            .is_err());

        fs::set_permissions(&inside, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(fs::read(&inside).unwrap(), b"updated");
        assert_eq!(fs::read(&sentinel).unwrap(), b"outside");
    }

    #[test]
    fn held_parent_does_not_follow_a_replacement_symlink() {
        let tree = TestDir::new("held-parent");
        let root_path = tree.path().join("root");
        let outside = tree.path().join("outside");
        fs::create_dir(&root_path).unwrap();
        fs::create_dir(root_path.join("gate")).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("sentinel"), b"unchanged").unwrap();
        let root = Root::open(&root_path).unwrap();

        let path = relative(b"gate/created");
        let parent = root.resolve_parent(&path).unwrap();
        fs::rename(root_path.join("gate"), root_path.join("parked")).unwrap();
        symlink(&outside, root_path.join("gate")).unwrap();

        let mut file = open_at(
            parent.directory.as_raw_fd(),
            &parent.leaf,
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
            0o600,
        )
        .unwrap();
        file.write_all(b"inside").unwrap();
        drop(file);

        assert_eq!(fs::read(outside.join("sentinel")).unwrap(), b"unchanged");
        assert!(!outside.join("created").exists());
        assert_eq!(
            fs::read(root_path.join("parked/created")).unwrap(),
            b"inside"
        );
        assert!(root.create_file(&path, 0o600).is_err());
    }

    #[test]
    fn concurrent_intermediate_swaps_never_touch_outside_sentinel() {
        let tree = TestDir::new("swap-race");
        let root_path = tree.path().join("root");
        let outside = tree.path().join("outside");
        fs::create_dir(&root_path).unwrap();
        fs::create_dir(root_path.join("gate")).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("sentinel"), b"unchanged").unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let attacker_stop = stop.clone();
        let attacker_root = root_path.clone();
        let attacker_outside = outside.clone();
        let attacker = std::thread::spawn(move || {
            while !attacker_stop.load(Ordering::Relaxed) {
                if fs::rename(attacker_root.join("gate"), attacker_root.join("parked")).is_ok() {
                    let _ = symlink(&attacker_outside, attacker_root.join("gate"));
                    let _ = fs::remove_file(attacker_root.join("gate"));
                    let _ = fs::rename(attacker_root.join("parked"), attacker_root.join("gate"));
                }
            }
        });

        let root = Root::open(&root_path).unwrap();
        let temp = relative(b"gate/work");
        let final_path = relative(b"gate/final");
        for _ in 0..2_000 {
            if let Ok(mut file) = root.create_file(&temp, 0o600) {
                let _ = file.write_all(b"inside");
                drop(file);
                let _ = root.rename(&temp, &final_path);
                let _ = root.unlink(&final_path);
                let _ = root.unlink(&temp);
            }
        }
        stop.store(true, Ordering::Relaxed);
        attacker.join().unwrap();

        assert_eq!(fs::read(outside.join("sentinel")).unwrap(), b"unchanged");
        assert!(!outside.join("work").exists());
        assert!(!outside.join("final").exists());
    }

    #[test]
    fn leaf_symlink_is_never_opened_but_can_be_unlinked() {
        let tree = TestDir::new("leaf-symlink");
        let root_path = tree.path().join("root");
        let outside = tree.path().join("outside");
        fs::create_dir(&root_path).unwrap();
        fs::write(&outside, b"unchanged").unwrap();
        symlink(&outside, root_path.join("leaf")).unwrap();
        let root = Root::open(&root_path).unwrap();

        assert!(root.open_regular_read(&relative(b"leaf")).is_err());
        assert!(root.open_regular_write(&relative(b"leaf"), true).is_err());
        assert_eq!(fs::read(&outside).unwrap(), b"unchanged");
        root.unlink(&relative(b"leaf")).unwrap();
        assert_eq!(fs::read(&outside).unwrap(), b"unchanged");
    }

    #[test]
    fn root_path_cannot_be_used_as_a_mutating_leaf() {
        let tree = TestDir::new("empty-leaf");
        let root = Root::open(tree.path()).unwrap();
        let empty = relative(b"");
        assert!(root.create_file(&empty, 0o600).is_err());
        assert!(root.create_directory(&empty, 0o700).is_err());
        assert!(root.unlink(&empty).is_err());
        assert!(root.remove_directory(&empty).is_err());
        assert!(root.rename(&empty, &relative(b"other")).is_err());
        assert!(root.open_directory(&empty).is_ok());
    }

    #[test]
    fn os_string_conversion_in_test_is_byte_exact() {
        let name = OsStr::from_bytes(b"byte-\xff");
        assert_eq!(name.as_bytes(), b"byte-\xff");
    }
}

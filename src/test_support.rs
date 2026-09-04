//! Shared helpers for unit tests.

use std::path::PathBuf;

/// The process temporary directory with symlinks resolved.
///
/// macOS places `TMPDIR` under `/var`, a symlink to `/private/var`. Native
/// operator paths refuse symlink components by default, so tests that hand a
/// temporary path to the product must start from its resolved form.
pub(crate) fn temp_dir() -> PathBuf {
    let path = std::env::temp_dir();
    std::fs::canonicalize(&path).unwrap_or(path)
}

/// A fresh temporary directory beneath the resolved [`temp_dir`].
pub(crate) fn tempdir() -> std::io::Result<tempfile::TempDir> {
    tempfile::tempdir_in(temp_dir())
}

/// Whether the temporary filesystem accepts file names that are not valid
/// UTF-8. APFS on macOS rejects them with `EILSEQ`, so tests that exercise raw
/// byte names have nothing to test there.
pub(crate) fn filesystem_accepts_non_utf8_names() -> bool {
    use std::os::unix::ffi::OsStringExt;
    let name =
        std::ffi::OsString::from_vec(format!("syq-probe-{}-", std::process::id()).into_bytes());
    let mut name = name;
    name.push(std::ffi::OsString::from_vec(vec![0xff]));
    let path = temp_dir().join(name);
    match std::fs::File::create(&path) {
        Ok(_) => {
            let _ = std::fs::remove_file(&path);
            true
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod experiment {
    // TEMPORARY: probe whether two concurrent unlinkat calls on one name can
    // both succeed on this kernel.
    #[test]
    fn concurrent_unlink_semantics() {
        use std::ffi::CString;
        use std::os::fd::AsRawFd;
        use std::sync::{Arc, Barrier};
        let dir = super::tempdir().unwrap();
        let directory = std::fs::File::open(dir.path()).unwrap();
        let fd = directory.as_raw_fd();
        let mut double = 0;
        let mut stat_after_unlink = 0;
        for i in 0..3000 {
            let name = format!("f{i}");
            std::fs::write(dir.path().join(&name), b"x").unwrap();
            let barrier = Arc::new(Barrier::new(2));
            let handles: Vec<_> = (0..2)
                .map(|_| {
                    let name = CString::new(name.clone()).unwrap();
                    let barrier = Arc::clone(&barrier);
                    std::thread::spawn(move || {
                        barrier.wait();
                        let mut st: libc::stat = unsafe { std::mem::zeroed() };
                        let seen = unsafe {
                            libc::fstatat(fd, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW)
                        } == 0;
                        let removed = unsafe { libc::unlinkat(fd, name.as_ptr(), 0) } == 0;
                        (seen, removed)
                    })
                })
                .collect();
            let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
            if results.iter().filter(|r| r.1).count() == 2 {
                double += 1;
            }
            if results.iter().any(|r| !r.0) {
                stat_after_unlink += 1;
            }
        }
        panic!(
            "double unlink successes: {double}/3000; stat saw absence first: {stat_after_unlink}"
        );
    }
}

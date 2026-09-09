//! Probe the test filesystem independently of syq so unsupported TMPDIRs can
//! skip clone-specific cases locally while the APFS CI job requires coverage.
use std::os::fd::AsRawFd;

pub fn available() -> bool {
    static AVAILABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *AVAILABLE.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap();
        let source = std::fs::File::create(dir.path().join("source")).unwrap();
        source.set_len(4096).unwrap();
        let source = std::fs::File::open(dir.path().join("source")).unwrap();
        let parent = std::fs::File::open(dir.path()).unwrap();
        let result = unsafe {
            libc::fclonefileat(source.as_raw_fd(), parent.as_raw_fd(), c"clone".as_ptr(), 2)
        };
        if result == 0 {
            return true;
        }
        let error = std::io::Error::last_os_error();
        assert!(
            matches!(
                error.raw_os_error(),
                Some(libc::EXDEV | libc::ENOTSUP | libc::ENOSYS)
            ),
            "test filesystem clone probe failed: {error}"
        );
        assert!(
            std::env::var_os("GITHUB_ACTIONS").is_none(),
            "macOS CI requires an APFS TMPDIR: {error}"
        );
        eprintln!("skipping clone-specific test: TMPDIR does not support cloning ({error})");
        false
    })
}

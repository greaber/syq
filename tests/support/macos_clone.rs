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

/// Check source metadata independently of attributes macOS creates itself.
pub fn assert_xattr(file: &std::fs::File, name: &std::ffi::CStr, expected: Option<&[u8]>) {
    let mut buffer = vec![0; expected.map_or(0, <[u8]>::len)];
    let size = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            name.as_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            0,
            0,
        )
    };
    if let Some(expected) = expected {
        assert_eq!(size, expected.len() as isize, "{name:?}");
        assert_eq!(buffer, expected, "{name:?}");
    } else {
        assert_eq!(size, -1, "unexpected attribute {name:?}");
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ENOATTR),
            "{name:?}"
        );
    }
}

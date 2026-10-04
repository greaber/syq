//! Populate private output before comparing it. A donor is only a hint: all
//! hashes are subsequently read from the private output, never from the donor.
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;

#[cfg(all(test, target_os = "linux"))]
thread_local! {
    /// Refuses the clones this thread asks for, as a filesystem that
    /// cannot clone would.
    pub(super) static REFUSE_CLONES: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(target_os = "linux")]
pub(super) fn try_clone(input: &File, output: &File, len: u64) -> bool {
    #[cfg(debug_assertions)]
    if std::env::var_os("SYQ_TEST_BASIS_CLONE_UNSUPPORTED").is_some() {
        return false;
    }
    #[cfg(test)]
    if REFUSE_CLONES.get() {
        return false;
    }
    crate::local_copy::try_clone(input, output, len)
}

pub(super) fn seed(
    input: &File,
    output: &File,
    len: u64,
    prepare_copy: impl FnOnce() -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let len = len.min(input.metadata()?.len());
    if len == 0 {
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    if try_clone(input, output, len) {
        return Ok(());
    }
    prepare_copy()?;
    // Whole-file copy_file_range can materialize holes on ext4. Discover data
    // extents first; filesystems without SEEK_DATA use bounded sparse writes.
    let mut off = 0;
    while off < len {
        let data = match seek_extent(input, off, libc::SEEK_DATA) {
            Ok(data) => data.min(len),
            Err(e) if e.raw_os_error() == Some(libc::ENXIO) => break,
            Err(e) if extent_unsupported(&e) => {
                return buffered(input, output, off, len).map_err(Into::into)
            }
            Err(e) => return Err(e.into()),
        };
        if data == len {
            break;
        }
        let end = match seek_extent(input, data, libc::SEEK_HOLE) {
            Ok(end) => end.min(len),
            // A donor can shrink between extent queries. Missing bytes are
            // obtained from the source after the staged file is compared.
            Err(e) if e.raw_os_error() == Some(libc::ENXIO) => break,
            Err(e) if extent_unsupported(&e) => {
                return buffered(input, output, off, len).map_err(Into::into)
            }
            Err(e) => return Err(e.into()),
        };
        if data < off || end <= data {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid donor extent").into());
        }
        copy_extent(input, output, data, end)?;
        off = end;
    }
    Ok(())
}

fn extent_unsupported(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EINVAL | libc::ENOTSUP | libc::ENOSYS)
    )
}

fn seek_extent(file: &File, off: u64, whence: i32) -> io::Result<u64> {
    let off = libc::off_t::try_from(off)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "donor offset overflow"))?;
    // SAFETY: live descriptor and representable offset. The donor is private
    // to this preparation; subsequent copying uses explicit offsets.
    let result = unsafe { libc::lseek(file.as_raw_fd(), off, whence) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result as u64)
    }
}

fn copy_extent(input: &File, output: &File, start: u64, end: u64) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let mut pos = start;
        while pos < end {
            let mut src = pos as libc::loff_t;
            let mut dst = src;
            // SAFETY: both descriptors and explicit offsets remain live; no
            // userspace buffers are passed to the kernel.
            let n = unsafe {
                libc::copy_file_range(
                    input.as_raw_fd(),
                    &mut src,
                    output.as_raw_fd(),
                    &mut dst,
                    (end - pos).min(16 << 20) as usize,
                    0,
                )
            };
            if n > 0 {
                pos += n as u64;
                continue;
            }
            if n == 0 {
                // The donor is only a hint; a concurrent truncation must not
                // fail a copy whose source still has all the required bytes.
                return Ok(());
            }
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if matches!(
                error.raw_os_error(),
                Some(libc::EXDEV | libc::EINVAL | libc::ENOSYS | libc::EOPNOTSUPP)
            ) {
                return buffered(input, output, pos, end);
            }
            return Err(error);
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    buffered(input, output, start, end)
}

fn buffered(input: &File, output: &File, mut off: u64, end: u64) -> io::Result<()> {
    let mut buf = vec![0; (end - off).min(4 << 20) as usize];
    while off < end {
        let n = (end - off).min(buf.len() as u64) as usize;
        let n = match input.read_at(&mut buf[..n], off) {
            Ok(0) => break,
            Ok(n) => n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        crate::sparse::write_at(output, &buf[..n], off, false)?;
        off += n as u64;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn donor_truncated_after_extent_discovery_keeps_available_bytes() {
        for copy in [copy_extent, buffered] {
            let tree = crate::test_support::tempdir().unwrap();
            let input = File::options()
                .read(true)
                .write(true)
                .create_new(true)
                .open(tree.path().join("input"))
                .unwrap();
            let output = File::options()
                .read(true)
                .write(true)
                .create_new(true)
                .open(tree.path().join("output"))
                .unwrap();
            input.write_all_at(&[7; 8192], 0).unwrap();
            output.set_len(8192).unwrap();
            // The copy interval was selected while all 8192 bytes existed.
            input.set_len(4096).unwrap();
            copy(&input, &output, 0, 8192).unwrap();
            let mut bytes = [0; 8192];
            output.read_exact_at(&mut bytes, 0).unwrap();
            assert_eq!(&bytes[..4096], &[7; 4096]);
            assert_eq!(&bytes[4096..], &[0; 4096]);
        }
    }

    #[test]
    fn seed_preserves_holes_and_is_independent_of_donor_writes() {
        let tree = crate::test_support::tempdir().unwrap();
        let input = File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .open(tree.path().join("input"))
            .unwrap();
        let output = File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .open(tree.path().join("output"))
            .unwrap();
        let len = 64 << 20;
        input.set_len(len).unwrap();
        input.write_all_at(b"start", 0).unwrap();
        input.write_all_at(b"end", len - 3).unwrap();
        seed(&input, &output, len, || Ok(())).unwrap();
        output.set_len(len).unwrap();
        input.write_all_at(b"other", 0).unwrap();
        let mut bytes = [0; 5];
        output.read_exact_at(&mut bytes, 0).unwrap();
        assert_eq!(&bytes, b"start");
        output.read_exact_at(&mut bytes, len - 5).unwrap();
        assert_eq!(&bytes, b"\0\0end");
        if input.metadata().unwrap().blocks() * 512 < len / 2 {
            assert!(output.metadata().unwrap().blocks() * 512 < len / 2);
        }
    }
}

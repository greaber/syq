//! Sparse writes preserve bytes, not an exact source extent layout. Callers
//! establish the final length separately: skipping trailing zeros cannot grow it.
use std::{fs::File, io, os::fd::AsRawFd, os::unix::fs::FileExt};

/// `clear_existing` is false only for a newly created or truncated output. Old
/// bytes must be punched out, never merely skipped, on resumed/in-place writes.
pub(crate) fn write_at(
    file: &File,
    data: &[u8],
    offset: u64,
    clear_existing: bool,
) -> io::Result<()> {
    offset
        .checked_add(data.len() as u64)
        .filter(|end| *end <= i64::MAX as u64)
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EFBIG))?;
    // APFS can fill the gap when a write extends past EOF. Establish and
    // punch the new zero range before writing its nonzero contents.
    #[cfg(target_os = "macos")]
    if offset + data.len() as u64 > file.metadata()?.len() {
        set_len(file, offset + data.len() as u64)?;
    }
    let block = block_size(file)?;
    let mut cursor = 0;
    let mut written = 0;
    while cursor < data.len() {
        let absolute = offset + cursor as u64;
        let len = (block - absolute % block).min((data.len() - cursor) as u64) as usize;
        let hole = (!clear_existing || (absolute.is_multiple_of(block) && len as u64 == block))
            && data[cursor..cursor + len].iter().all(|byte| *byte == 0);
        if !hole {
            cursor += len;
            continue;
        }
        file.write_all_at(&data[written..cursor], offset + written as u64)?;
        let start = cursor;
        cursor += len;
        while cursor < data.len() {
            let len = block.min((data.len() - cursor) as u64) as usize;
            if (clear_existing && len as u64 != block)
                || data[cursor..cursor + len].iter().any(|byte| *byte != 0)
            {
                break;
            }
            cursor += len;
        }
        if clear_existing {
            punch(file, offset + start as u64, (cursor - start) as u64)?;
        }
        written = cursor;
    }
    file.write_all_at(&data[written..], offset + written as u64)
}

/// APFS can allocate zero-filled ranges on growth, including writes past EOF.
/// Punch newly added whole blocks explicitly; preserve the old partial block.
/// Callers serialize resizing with writes to the same output.
pub(crate) fn set_len(file: &File, size: u64) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        let old_size = file.metadata()?.len();
        file.set_len(size)?;
        if size > old_size {
            let block = block_size(file)?;
            let start = old_size.div_ceil(block) * block;
            let end = size / block * block;
            if end > start {
                punch(file, start, end - start)?;
            }
        }
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    file.set_len(size)
}

#[cfg(not(target_os = "macos"))]
fn block_size(_: &File) -> io::Result<u64> {
    Ok(4096)
}

#[cfg(target_os = "macos")]
fn block_size(file: &File) -> io::Result<u64> {
    // F_PUNCHHOLE requires filesystem block alignment, unlike Linux fallocate.
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::fstatfs(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(u64::from(unsafe { stat.assume_init() }.f_bsize).max(1))
}

fn punch(file: &File, offset: u64, len: u64) -> io::Result<()> {
    let offset = i64::try_from(offset).map_err(|_| io::Error::from_raw_os_error(libc::EFBIG))?;
    let len = i64::try_from(len).map_err(|_| io::Error::from_raw_os_error(libc::EFBIG))?;
    #[cfg(target_os = "linux")]
    let result = unsafe {
        libc::fallocate(
            file.as_raw_fd(),
            libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
            offset,
            len,
        )
    };
    #[cfg(target_os = "macos")]
    let result = unsafe {
        let hole = libc::fpunchhole_t {
            fp_flags: 0,
            reserved: 0,
            fp_offset: offset,
            fp_length: len,
        };
        libc::fcntl(file.as_raw_fd(), libc::F_PUNCHHOLE, &hole)
    };
    if result == 0 {
        Ok(())
    } else {
        let error = io::Error::last_os_error();
        Err(io::Error::new(
            error.kind(),
            format!("sparse hole creation failed at {offset} for {len} bytes: {error}"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unaligned_sparse_updates_clear_old_bytes_without_touching_neighbors() {
        let directory = crate::test_support::tempdir().unwrap();
        let path = directory.path().join("file");
        let file = File::options()
            .create_new(true)
            .write(true)
            .open(&path)
            .unwrap();
        let mut expected = vec![0x53; 256 * 1024];
        file.write_all_at(&expected, 0).unwrap();
        let mut data = vec![0; 192 * 1024 + 71];
        data[7000..7020].fill(0x29);
        data[120_000..120_004].fill(0x72);
        write_at(&file, &data, 23, true).unwrap();
        expected[23..23 + data.len()].copy_from_slice(&data);
        assert_eq!(std::fs::read(path).unwrap(), expected);
    }

    #[test]
    fn fresh_sparse_writes_keep_trailing_zeros_and_small_zero_files() {
        let directory = crate::test_support::tempdir().unwrap();
        for size in [0, 17, 4096, 65_539, 8 * 1024 * 1024] {
            let path = directory.path().join(size.to_string());
            let file = File::create(&path).unwrap();
            let mut data = vec![0; size];
            if size > 4096 {
                data[4090..4100].fill(7);
            }
            write_at(&file, &data, 0, false).unwrap();
            set_len(&file, size as u64).unwrap();
            if size > 1024 * 1024 {
                use std::os::unix::fs::MetadataExt;
                file.sync_all().unwrap();
                assert!(file.metadata().unwrap().blocks() * 512 < size as u64 / 4);
            }
            assert_eq!(std::fs::read(path).unwrap(), data);
        }
    }

    #[test]
    fn a_failed_hole_punch_is_an_error() {
        let directory = crate::test_support::tempdir().unwrap();
        let path = directory.path().join("file");
        std::fs::write(&path, vec![1; 128 * 1024]).unwrap();
        let file = File::open(&path).unwrap();
        assert!(write_at(&file, &[0; 128 * 1024], 0, true).is_err());
        assert_eq!(std::fs::read(path).unwrap(), vec![1; 128 * 1024]);
    }
}

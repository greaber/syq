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
    plan(file, data, offset, clear_existing)?.apply(file)
}

/// One sparse write, planned: the requests that store `data` at `offset`,
/// found by scanning it for zero blocks. Planning only reads `data`, so a
/// caller that serializes writes to one file (`write_gate`) scans outside
/// its lock and holds it only while `apply` makes the requests.
pub(crate) struct Planned<'a> {
    data: &'a [u8],
    offset: u64,
    requests: Vec<Request>,
}

/// One request of a planned write, as a range of its data.
enum Request {
    Write(std::ops::Range<usize>),
    Punch(std::ops::Range<usize>),
}

/// Plan writing `data` at `offset` as `write_at` does.
pub(crate) fn plan<'a>(
    file: &File,
    data: &'a [u8],
    offset: u64,
    clear_existing: bool,
) -> io::Result<Planned<'a>> {
    offset
        .checked_add(data.len() as u64)
        .filter(|end| *end <= i64::MAX as u64)
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EFBIG))?;
    let clear_existing = clear_existing || cfg!(target_os = "macos");
    let block = block_size(file)?;
    let mut requests = Vec::new();
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
        if written < cursor {
            requests.push(Request::Write(written..cursor));
        }
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
            requests.push(Request::Punch(start..cursor));
        }
        written = cursor;
    }
    if written < data.len() {
        requests.push(Request::Write(written..data.len()));
    }
    Ok(Planned {
        data,
        offset,
        requests,
    })
}

impl Planned<'_> {
    /// Make the planned requests, in order.
    pub(crate) fn apply(&self, file: &File) -> io::Result<()> {
        // Establish EOF before writes on APFS. Explicitly punch even fresh
        // zero ranges: merely skipping writes can leave delayed zero
        // allocations.
        #[cfg(target_os = "macos")]
        {
            let end = self.offset + self.data.len() as u64;
            if end > file.metadata()?.len() {
                set_len(file, end)?;
            }
        }
        for request in &self.requests {
            match request {
                Request::Write(range) => {
                    file.write_all_at(&self.data[range.clone()], self.offset + range.start as u64)?
                }
                Request::Punch(range) => {
                    punch(file, self.offset + range.start as u64, range.len() as u64)?
                }
            }
        }
        Ok(())
    }
}

/// Callers serialize resizing with writes to the same output.
pub(crate) fn set_len(file: &File, size: u64) -> io::Result<()> {
    file.set_len(size)
}

#[cfg(not(target_os = "macos"))]
fn block_size(_: &File) -> io::Result<u64> {
    Ok(4096)
}

#[cfg(target_os = "macos")]
fn block_size(file: &File) -> io::Result<u64> {
    // F_PUNCHHOLE requires filesystem block alignment, unlike Linux fallocate.
    Ok(crate::fsops::file_system_of(file)?.block_size())
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
    fn sparse_range_order_does_not_allocate_unwritten_zero_ranges() {
        use std::os::unix::fs::MetadataExt;
        let directory = crate::test_support::tempdir().unwrap();
        let chunk = 1024 * 1024;
        for reverse in [false, true] {
            let path = directory.path().join(reverse.to_string());
            let file = File::create(&path).unwrap();
            set_len(&file, 8 * chunk as u64).unwrap();
            let mut expected = vec![0; 8 * chunk];
            for index in 0..8 {
                let index = if reverse { 7 - index } else { index };
                let offset = index * chunk;
                // Data at both ends exercises holes followed by later writes.
                expected[offset..offset + 4096].fill(7);
                expected[offset + chunk - 4096..offset + chunk].fill(9);
                write_at(
                    &file,
                    &expected[offset..offset + chunk],
                    offset as u64,
                    false,
                )
                .unwrap();
            }
            file.sync_all().unwrap();
            assert!(file.metadata().unwrap().blocks() * 512 < expected.len() as u64 / 4);
            assert_eq!(std::fs::read(path).unwrap(), expected);
        }
    }

    #[test]
    fn planning_touches_nothing_and_applying_writes_what_write_at_would() {
        let directory = crate::test_support::tempdir().unwrap();
        let block = 4096;
        let mut data = vec![0; 9 * block + 333];
        data[17..40].fill(3);
        data[2 * block..3 * block].fill(5);
        data[5 * block + 9] = 1;
        data[9 * block + 100] = 8;
        for clear_existing in [false, true] {
            for offset in [0, 23, block as u64] {
                let old = vec![0x6b; offset as usize + data.len() + block];
                let path = directory.path().join(format!("{clear_existing}-{offset}"));
                std::fs::write(&path, &old).unwrap();
                // A read-only descriptor: planning makes no request.
                let planned =
                    plan(&File::open(&path).unwrap(), &data, offset, clear_existing).unwrap();
                assert_eq!(std::fs::read(&path).unwrap(), old);
                let file = File::options().write(true).open(&path).unwrap();
                planned.apply(&file).unwrap();
                let applied = std::fs::read(&path).unwrap();
                std::fs::write(&path, &old).unwrap();
                write_at(&file, &data, offset, clear_existing).unwrap();
                assert_eq!(applied, std::fs::read(&path).unwrap());
                if clear_existing {
                    let mut expected = old.clone();
                    expected[offset as usize..offset as usize + data.len()].copy_from_slice(&data);
                    assert_eq!(applied, expected);
                }
            }
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

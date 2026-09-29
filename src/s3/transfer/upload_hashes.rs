//! Whole-object identities, and any provider part checksums, from one file read.
use super::{Algorithm, Digest, HashAlgorithm, Result};
use rayon::prelude::*;

pub(super) struct Hashes {
    pub whole: String,
    pub comparison: Option<String>,
    /// One per part; empty when uploads send no request checksum.
    pub checksums: Vec<String>,
    /// Parts were read concurrently, so no single read saw the file finish.
    pub concurrent: bool,
}

struct PartHashes {
    checksums: Vec<String>,
    blake3: Option<[u8; 32]>,
}

pub(super) fn bytes(
    bytes: &[u8],
    native: Algorithm,
    whole: HashAlgorithm,
    comparison: Option<HashAlgorithm>,
) -> Hashes {
    let whole_digest = Digest::hash_bytes(whole, bytes).value;
    let comparison = comparison.map(|algorithm| {
        if algorithm == whole {
            whole_digest.clone()
        } else {
            Digest::hash_bytes(algorithm, bytes).value
        }
    });
    Hashes {
        whole: whole_digest,
        comparison,
        checksums: native.digest(bytes).into_iter().collect(),
        concurrent: false,
    }
}

// Keep the small-file path to one read for every algorithm. Large files read
// parts in parallel for any request checksums and for BLAKE3, whose subtrees can
// reuse that read when each part starts at a BLAKE3 chunk boundary. Other whole
// hashes use one sequential read, alongside the parts when they have work.
// The factory gives each parallel part and whole-file pass its own reader. Its
// end offset lets the caller check source identity after the final read.
pub(super) fn ranges<R>(
    size: u64,
    part_size: u64,
    native: Algorithm,
    whole: HashAlgorithm,
    comparison: Option<HashAlgorithm>,
    open: impl Fn(u64) -> Result<R> + Sync,
) -> Result<Hashes>
where
    R: FnMut(&mut [u8], u64) -> Result<()>,
{
    let tree = size > part_size
        && part_size.is_multiple_of(blake3::CHUNK_LEN as u64)
        && (whole == HashAlgorithm::Blake3 || comparison == Some(HashAlgorithm::Blake3));
    let parallel =
        size >= 32 * 1024 * 1024 && size > part_size && (native != Algorithm::None || tree);
    let reusable = |algorithm| parallel && tree && algorithm == HashAlgorithm::Blake3;
    let mut whole_hashes: Vec<_> = [Some(whole), comparison]
        .into_iter()
        .flatten()
        .filter(|&algorithm| !reusable(algorithm))
        .fold(Vec::new(), |mut hashes, algorithm| {
            if !hashes.iter().any(|(a, _)| *a == algorithm) {
                hashes.push((algorithm, algorithm.hasher()));
            }
            hashes
        });
    let PartHashes { checksums, blake3 } = if parallel {
        let (whole_result, parts) = rayon::join(
            || -> Result<()> {
                if !whole_hashes.is_empty() {
                    let mut read = open(size)?;
                    let mut buffer = vec![0; 1024 * 1024];
                    let mut offset = 0;
                    while offset < size {
                        let length = (size - offset).min(buffer.len() as u64) as usize;
                        read(&mut buffer[..length], offset)?;
                        for (_, hash) in &mut whole_hashes {
                            hash.update(&buffer[..length]);
                        }
                        offset += length as u64;
                    }
                }
                Ok(())
            },
            || parallel_parts(size, part_size, native, tree, &open),
        );
        whole_result?;
        parts?
    } else {
        let mut read = open(size)?;
        let mut parts = Vec::new();
        let mut buffer = vec![0; 1024 * 1024];
        for index in 0..size.div_ceil(part_size).max(1) {
            let mut hash = native.hasher();
            let mut offset = index * part_size;
            let end = (offset + part_size).min(size);
            while offset < end {
                let length = (end - offset).min(buffer.len() as u64) as usize;
                read(&mut buffer[..length], offset)?;
                if let Some(hash) = &mut hash {
                    hash.update(&buffer[..length]);
                }
                for (_, whole) in &mut whole_hashes {
                    whole.update(&buffer[..length]);
                }
                offset += length as u64;
            }
            parts.extend(hash.map(|hash| hash.finish()));
        }
        PartHashes {
            checksums: parts,
            blake3: None,
        }
    };
    let digests: Vec<_> = whole_hashes
        .into_iter()
        .map(|(algorithm, hash)| Digest::from_hash(algorithm, &hash.finalize()))
        .collect();
    let digest = |algorithm| {
        if let Some(hash) = blake3.filter(|_| algorithm == HashAlgorithm::Blake3) {
            Digest::from_hash(algorithm, &hash).value
        } else {
            digests
                .iter()
                .find(|digest| digest.algorithm == algorithm)
                .unwrap()
                .value
                .clone()
        }
    };
    Ok(Hashes {
        whole: digest(whole),
        comparison: comparison.map(digest),
        checksums,
        concurrent: parallel,
    })
}

// Each aligned part is split into complete BLAKE3 subtrees, with a possibly
// short final chunk at EOF. No subtree crosses a provider part boundary.
fn parallel_parts<R>(
    size: u64,
    part_size: u64,
    native: Algorithm,
    tree: bool,
    open: impl Fn(u64) -> Result<R> + Sync,
) -> Result<PartHashes>
where
    R: FnMut(&mut [u8], u64) -> Result<()>,
{
    use blake3::hazmat::{
        left_subtree_len, max_subtree_len, merge_subtrees_non_root, merge_subtrees_root, HasherExt,
        Mode,
    };
    anyhow::ensure!(!tree || (size > part_size && part_size > 0 && part_size.is_multiple_of(1024)));
    struct Subtree {
        offset: u64,
        hash: [u8; 32],
    }
    let parts = (0..size.div_ceil(part_size))
        .into_par_iter()
        .map(|index| -> Result<_> {
            let start = index * part_size;
            let end = (start + part_size).min(size);
            let mut read = open(end)?;
            let mut native = native.hasher();
            let mut subtrees = Vec::new();
            let mut buffer = vec![0; part_size.min(1024 * 1024) as usize];
            let mut offset = start;
            while offset < end {
                let subtree_start = offset;
                let remaining = end - offset;
                let length = if tree && remaining >= blake3::CHUNK_LEN as u64 {
                    // The largest complete subtree that fits this part and is
                    // valid at this offset. Only the final chunk can be short.
                    let complete = 1u64 << (63 - remaining.leading_zeros());
                    complete.min(max_subtree_len(offset).unwrap_or(complete))
                } else {
                    remaining
                };
                let subtree_end = offset + length;
                let mut subtree = tree.then(|| {
                    let mut hash = blake3::Hasher::new();
                    hash.set_input_offset(offset);
                    hash
                });
                while offset < subtree_end {
                    let length = (subtree_end - offset).min(buffer.len() as u64) as usize;
                    read(&mut buffer[..length], offset)?;
                    if let Some(native) = &mut native {
                        native.update(&buffer[..length]);
                    }
                    if let Some(subtree) = &mut subtree {
                        subtree.update(&buffer[..length]);
                    }
                    offset += length as u64;
                }
                if let Some(subtree) = subtree {
                    subtrees.push(Subtree {
                        offset: subtree_start,
                        hash: subtree.finalize_non_root(),
                    });
                }
            }
            Ok((native.map(|hash| hash.finish()), subtrees))
        })
        .collect::<Result<Vec<_>>>()?;
    fn merge(subtrees: &[Subtree], end: u64, root: bool) -> [u8; 32] {
        if subtrees.len() == 1 {
            return subtrees[0].hash;
        }
        // Split by bytes, not the number of pieces: aligned parts can produce
        // different subtree sizes. Complete subtrees never cross this boundary.
        let start = subtrees[0].offset;
        let boundary = start + left_subtree_len(end - start);
        let split = subtrees.partition_point(|subtree| subtree.offset < boundary);
        debug_assert_eq!(subtrees[split].offset, boundary);
        let left = merge(&subtrees[..split], boundary, false);
        let right = merge(&subtrees[split..], end, false);
        if root {
            *merge_subtrees_root(&left, &right, Mode::Hash).as_bytes()
        } else {
            merge_subtrees_non_root(&left, &right, Mode::Hash)
        }
    }
    let mut checksums = Vec::with_capacity(parts.len());
    let mut subtrees = Vec::new();
    for (checksum, pieces) in parts {
        checksums.extend(checksum);
        subtrees.extend(pieces);
    }
    Ok(PartHashes {
        checksums,
        blake3: tree.then(|| merge(&subtrees, size, true)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn parallel_subtrees_match_standard_blake3_with_one_read() {
        let bytes: Vec<_> = (0..5 * 1024 * 1024 + 31).map(|n| (n % 251) as u8).collect();
        for part_size in [
            1024usize,
            2048,
            3 * 1024,
            5 * 1024,
            1024 * 1024,
            5 * 1024 * 1024,
        ] {
            let sizes = [
                part_size + 1,
                2 * part_size,
                3 * part_size - 1,
                3 * part_size,
                4 * part_size,
                bytes.len(),
            ];
            for size in sizes.into_iter().filter(|&size| size <= bytes.len()) {
                for native in [Algorithm::None, Algorithm::Sha256, Algorithm::Md5] {
                    let read_bytes = AtomicUsize::new(0);
                    let PartHashes {
                        checksums: parts,
                        blake3: whole,
                    } = parallel_parts(size as u64, part_size as u64, native, true, |_| {
                        Ok(|buffer: &mut [u8], offset| {
                            buffer.copy_from_slice(
                                &bytes[offset as usize..offset as usize + buffer.len()],
                            );
                            read_bytes.fetch_add(buffer.len(), Ordering::Relaxed);
                            Ok(())
                        })
                    })
                    .unwrap();
                    assert_eq!(
                        Digest::from_hash(HashAlgorithm::Blake3, &whole.unwrap()).value,
                        blake3::hash(&bytes[..size]).to_hex().to_string(),
                        "size {size} part {part_size}"
                    );
                    assert_eq!(read_bytes.load(Ordering::Relaxed), size);
                    assert_eq!(
                        parts,
                        bytes[..size]
                            .chunks(part_size)
                            .filter_map(|b| native.digest(b))
                            .collect::<Vec<_>>()
                    );
                }
            }
        }
        assert!(parallel_parts(4096, 3073, Algorithm::None, true, |_| Ok(
            |_: &mut [u8], _| Ok(())
        ))
        .is_err());
    }

    #[test]
    fn whole_and_part_hashes_share_one_read() {
        let bytes: Vec<_> = (0..5 * 1024 * 1024 + 31).map(|n| (n % 251) as u8).collect();
        // Empty and single-part objects, multipart files below the parallel
        // threshold, and final parts with uneven lengths all share one read.
        for size in [0, 101, bytes.len()] {
            for part_size in [1024 * 1024 + 3, 3 * 1024 * 1024, 8 * 1024 * 1024] {
                for native in [Algorithm::None, Algorithm::Sha256, Algorithm::Md5] {
                    for whole in [
                        HashAlgorithm::Blake3,
                        HashAlgorithm::Sha256,
                        HashAlgorithm::Md5,
                        HashAlgorithm::Xxh3,
                    ] {
                        let read_bytes = AtomicUsize::new(0);
                        let opens = AtomicUsize::new(0);
                        let result = ranges(
                            size as u64,
                            part_size,
                            native,
                            whole,
                            Some(HashAlgorithm::Sha256),
                            |_| {
                                opens.fetch_add(1, Ordering::Relaxed);
                                Ok(|buffer: &mut [u8], offset| {
                                    buffer.copy_from_slice(
                                        &bytes[offset as usize..offset as usize + buffer.len()],
                                    );
                                    read_bytes.fetch_add(buffer.len(), Ordering::Relaxed);
                                    Ok(())
                                })
                            },
                        )
                        .unwrap();
                        assert_eq!(read_bytes.load(Ordering::Relaxed), size);
                        assert_eq!(opens.load(Ordering::Relaxed), 1);
                        assert_eq!(
                            result.whole,
                            Digest::hash_bytes(whole, &bytes[..size]).value
                        );
                        assert_eq!(
                            result.comparison.unwrap(),
                            Digest::hash_bytes(HashAlgorithm::Sha256, &bytes[..size]).value
                        );
                        let expected: Vec<_> = if size == 0 {
                            native.digest(&[]).into_iter().collect()
                        } else {
                            bytes[..size]
                                .chunks(part_size as usize)
                                .filter_map(|b| native.digest(b))
                                .collect()
                        };
                        assert_eq!(result.checksums, expected);
                    }
                }
            }
        }
    }

    #[test]
    fn large_file_read_counts_distinguish_subtree_and_general_hash_paths() {
        let bytes: Vec<_> = (0..32 * 1024 * 1024 + 23)
            .map(|n| (n % 251) as u8)
            .collect();
        for native in [Algorithm::None, Algorithm::Sha256, Algorithm::Md5] {
            for (part_size, whole, comparison, reads) in [
                (16 * 1024 * 1024, HashAlgorithm::Blake3, None, 1),
                (5 * 1024 * 1024, HashAlgorithm::Blake3, None, 1),
                (5 * 1024 * 1024 + 1, HashAlgorithm::Blake3, None, 2),
                (
                    16 * 1024 * 1024,
                    HashAlgorithm::Blake3,
                    Some(HashAlgorithm::Sha256),
                    2,
                ),
                (
                    16 * 1024 * 1024,
                    HashAlgorithm::Sha256,
                    Some(HashAlgorithm::Blake3),
                    2,
                ),
            ] {
                let read_bytes = AtomicUsize::new(0);
                let opens = AtomicUsize::new(0);
                let result = ranges(
                    bytes.len() as u64,
                    part_size,
                    native,
                    whole,
                    comparison,
                    |end| {
                        opens.fetch_add(1, Ordering::Relaxed);
                        let bytes = &bytes;
                        let read_bytes = &read_bytes;
                        let mut next = None;
                        Ok(move |buffer: &mut [u8], offset| {
                            assert!(next.is_none_or(|next| next == offset));
                            next = Some(offset + buffer.len() as u64);
                            assert!(next.unwrap() <= end);
                            buffer.copy_from_slice(
                                &bytes[offset as usize..offset as usize + buffer.len()],
                            );
                            read_bytes.fetch_add(buffer.len(), Ordering::Relaxed);
                            Ok(())
                        })
                    },
                )
                .unwrap();
                // Without request checksums or BLAKE3 subtrees, parts have no
                // work: one sequential read computes the whole-file hash.
                let parts_idle = native == Algorithm::None && !part_size.is_multiple_of(1024);
                assert_eq!(result.concurrent, !parts_idle);
                let (reads, expected_opens) = if parts_idle {
                    (1, 1)
                } else {
                    (reads, bytes.len().div_ceil(part_size as usize) + reads - 1)
                };
                assert_eq!(read_bytes.load(Ordering::Relaxed), reads * bytes.len());
                assert_eq!(opens.load(Ordering::Relaxed), expected_opens);
                assert_eq!(result.whole, Digest::hash_bytes(whole, &bytes).value);
                assert_eq!(
                    result.comparison,
                    comparison.map(|a| Digest::hash_bytes(a, &bytes).value)
                );
                assert_eq!(
                    result.checksums,
                    bytes
                        .chunks(part_size as usize)
                        .filter_map(|b| native.digest(b))
                        .collect::<Vec<_>>()
                );
            }
        }
    }

    #[test]
    fn short_reads_fail_before_returning_any_hash() {
        let result = ranges(
            100,
            50,
            Algorithm::Sha256,
            HashAlgorithm::Blake3,
            None,
            |_| {
                Ok(|_: &mut [u8], _| {
                    Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into())
                })
            },
        );
        assert!(result.is_err());
    }
}

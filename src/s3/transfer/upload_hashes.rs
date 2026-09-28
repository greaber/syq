//! Whole-object identities and provider part checksums from the same file read.
use super::{encode_native_parts, Algorithm, Digest, HashAlgorithm, Result};
use rayon::prelude::*;

pub(super) struct Hashes {
    pub whole: String,
    pub comparison: Option<String>,
    pub checksums: Vec<String>,
}

pub(super) fn native_algorithm(algorithm: Algorithm) -> HashAlgorithm {
    match algorithm {
        Algorithm::Sha256 => HashAlgorithm::Sha256,
        Algorithm::Md5 => HashAlgorithm::Md5,
    }
}

pub(super) fn bytes(
    bytes: &[u8],
    native: Algorithm,
    whole: HashAlgorithm,
    comparison: Option<HashAlgorithm>,
) -> Hashes {
    let native = native_algorithm(native);
    let hash = native.hash(bytes);
    let digest = |algorithm| {
        if algorithm == native {
            Digest::from_hash(algorithm, &hash).value
        } else {
            Digest::hash_bytes(algorithm, bytes).value
        }
    };
    let whole_digest = digest(whole);
    let comparison = comparison.map(|algorithm| {
        if algorithm == whole {
            whole_digest.clone()
        } else {
            digest(algorithm)
        }
    });
    Hashes {
        whole: whole_digest,
        comparison,
        checksums: encode_native_parts(native, &[hash]),
    }
}

// Keep the small-file path to one read for every algorithm. Large files retain
// independent parallel native part hashing. BLAKE3 can reuse that read when each
// part is a power-of-two subtree; other whole hashes share one additional read.
pub(super) fn ranges(
    size: u64,
    part_size: u64,
    native: Algorithm,
    whole: HashAlgorithm,
    comparison: Option<HashAlgorithm>,
    read: impl Fn(&mut [u8], u64) -> Result<()> + Sync,
) -> Result<Hashes> {
    let native = native_algorithm(native);
    let tree = size > part_size
        && part_size.is_power_of_two()
        && part_size >= blake3::CHUNK_LEN as u64
        && (whole == HashAlgorithm::Blake3 || comparison == Some(HashAlgorithm::Blake3));
    let parallel = size >= 32 * 1024 * 1024 && size > part_size;
    let reusable = |algorithm| {
        (size <= part_size && algorithm == native)
            || (parallel && tree && algorithm == HashAlgorithm::Blake3)
    };
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
    let (parts, blake3) = if parallel {
        let (whole_result, parts) = rayon::join(
            || -> Result<()> {
                if !whole_hashes.is_empty() {
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
            || parallel_parts(size, part_size, native, tree, &read),
        );
        whole_result?;
        parts?
    } else {
        let mut parts = Vec::new();
        let mut buffer = vec![0; 1024 * 1024];
        for index in 0..size.div_ceil(part_size).max(1) {
            let mut hash = native.hasher();
            let mut offset = index * part_size;
            let end = (offset + part_size).min(size);
            while offset < end {
                let length = (end - offset).min(buffer.len() as u64) as usize;
                read(&mut buffer[..length], offset)?;
                hash.update(&buffer[..length]);
                for (_, whole) in &mut whole_hashes {
                    whole.update(&buffer[..length]);
                }
                offset += length as u64;
            }
            parts.push(hash.finalize());
        }
        (parts, None)
    };
    let digests: Vec<_> = whole_hashes
        .into_iter()
        .map(|(algorithm, hash)| Digest::from_hash(algorithm, &hash.finalize()))
        .collect();
    let digest = |algorithm| {
        if size <= part_size && algorithm == native {
            Digest::from_hash(algorithm, &parts[0]).value
        } else if let Some(hash) = blake3.filter(|_| algorithm == HashAlgorithm::Blake3) {
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
        checksums: encode_native_parts(native, &parts),
    })
}

// In tree mode each part is a complete, equally sized BLAKE3 subtree except the
// final rightmost part. These are exactly the tree shapes supported here.
fn parallel_parts(
    size: u64,
    part_size: u64,
    native: HashAlgorithm,
    tree: bool,
    read: impl Fn(&mut [u8], u64) -> Result<()> + Sync,
) -> Result<(Vec<[u8; 32]>, Option<[u8; 32]>)> {
    use blake3::hazmat::{merge_subtrees_non_root, merge_subtrees_root, HasherExt, Mode};
    anyhow::ensure!(
        !tree || (size > part_size && part_size.is_power_of_two() && part_size >= 1024)
    );
    let parts = (0..size.div_ceil(part_size))
        .into_par_iter()
        .map(|index| -> Result<_> {
            let start = index * part_size;
            let end = (start + part_size).min(size);
            let mut native = native.hasher();
            let mut subtree = tree.then(|| {
                let mut hash = blake3::Hasher::new();
                hash.set_input_offset(start);
                hash
            });
            let mut buffer = vec![0; part_size.min(1024 * 1024) as usize];
            let mut offset = start;
            while offset < end {
                let length = (end - offset).min(buffer.len() as u64) as usize;
                read(&mut buffer[..length], offset)?;
                native.update(&buffer[..length]);
                if let Some(subtree) = &mut subtree {
                    subtree.update(&buffer[..length]);
                }
                offset += length as u64;
            }
            Ok((native.finalize(), subtree.map(|h| h.finalize_non_root())))
        })
        .collect::<Result<Vec<_>>>()?;
    fn merge(parts: &[([u8; 32], Option<[u8; 32]>)], root: bool) -> [u8; 32] {
        if parts.len() == 1 {
            return parts[0].1.unwrap();
        }
        // BLAKE3's left child is the largest power-of-two subtree that leaves
        // any input for its right child. Only the rightmost part may be short.
        let split = parts.len().next_power_of_two() / 2;
        let left = merge(&parts[..split], false);
        let right = merge(&parts[split..], false);
        if root {
            *merge_subtrees_root(&left, &right, Mode::Hash).as_bytes()
        } else {
            merge_subtrees_non_root(&left, &right, Mode::Hash)
        }
    }
    let whole = tree.then(|| merge(&parts, true));
    Ok((parts.into_iter().map(|part| part.0).collect(), whole))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn parallel_subtrees_match_standard_blake3_with_one_read() {
        let bytes: Vec<_> = (0..5 * 1024 * 1024 + 31).map(|n| (n % 251) as u8).collect();
        for part_size in [1024usize, 2048, 1024 * 1024] {
            let sizes = [
                part_size + 1,
                2 * part_size,
                3 * part_size - 1,
                3 * part_size,
                4 * part_size,
                bytes.len(),
            ];
            for size in sizes {
                for native in [Algorithm::Sha256, Algorithm::Md5] {
                    let read_bytes = AtomicUsize::new(0);
                    let (parts, whole) = parallel_parts(
                        size as u64,
                        part_size as u64,
                        native_algorithm(native),
                        true,
                        |buffer, offset| {
                            buffer.copy_from_slice(
                                &bytes[offset as usize..offset as usize + buffer.len()],
                            );
                            read_bytes.fetch_add(buffer.len(), Ordering::Relaxed);
                            Ok(())
                        },
                    )
                    .unwrap();
                    assert_eq!(
                        Digest::from_hash(HashAlgorithm::Blake3, &whole.unwrap()).value,
                        blake3::hash(&bytes[..size]).to_hex().to_string(),
                        "size {size} part {part_size}"
                    );
                    assert_eq!(read_bytes.load(Ordering::Relaxed), size);
                    assert_eq!(
                        encode_native_parts(native_algorithm(native), &parts),
                        bytes[..size]
                            .chunks(part_size)
                            .map(|b| native.digest(b))
                            .collect::<Vec<_>>()
                    );
                }
            }
        }
        assert!(parallel_parts(4096, 3072, HashAlgorithm::Sha256, true, |_, _| Ok(())).is_err());
    }

    #[test]
    fn whole_and_part_hashes_share_one_read() {
        let bytes: Vec<_> = (0..5 * 1024 * 1024 + 31).map(|n| (n % 251) as u8).collect();
        // Empty and single-part objects, multipart files below the parallel
        // threshold, and final parts with uneven lengths all share one read.
        for size in [0, 101, bytes.len()] {
            for part_size in [1024 * 1024 + 3, 3 * 1024 * 1024, 8 * 1024 * 1024] {
                for native in [Algorithm::Sha256, Algorithm::Md5] {
                    for whole in [
                        HashAlgorithm::Blake3,
                        HashAlgorithm::Sha256,
                        HashAlgorithm::Md5,
                        HashAlgorithm::Xxh3,
                    ] {
                        let read_bytes = AtomicUsize::new(0);
                        let result = ranges(
                            size as u64,
                            part_size,
                            native,
                            whole,
                            Some(HashAlgorithm::Sha256),
                            |buffer, offset| {
                                buffer.copy_from_slice(
                                    &bytes[offset as usize..offset as usize + buffer.len()],
                                );
                                read_bytes.fetch_add(buffer.len(), Ordering::Relaxed);
                                Ok(())
                            },
                        )
                        .unwrap();
                        assert_eq!(read_bytes.load(Ordering::Relaxed), size);
                        assert_eq!(
                            result.whole,
                            Digest::hash_bytes(whole, &bytes[..size]).value
                        );
                        assert_eq!(
                            result.comparison.unwrap(),
                            Digest::hash_bytes(HashAlgorithm::Sha256, &bytes[..size]).value
                        );
                        let expected: Vec<_> = if size == 0 {
                            vec![native.digest(&[])]
                        } else {
                            bytes[..size]
                                .chunks(part_size as usize)
                                .map(|b| native.digest(b))
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
        for (part_size, whole, comparison, reads) in [
            (16 * 1024 * 1024, HashAlgorithm::Blake3, None, 1),
            (5 * 1024 * 1024, HashAlgorithm::Blake3, None, 2),
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
            let result = ranges(
                bytes.len() as u64,
                part_size,
                Algorithm::Sha256,
                whole,
                comparison,
                |buffer, offset| {
                    buffer.copy_from_slice(&bytes[offset as usize..offset as usize + buffer.len()]);
                    read_bytes.fetch_add(buffer.len(), Ordering::Relaxed);
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(read_bytes.load(Ordering::Relaxed), reads * bytes.len());
            assert_eq!(result.whole, Digest::hash_bytes(whole, &bytes).value);
            assert_eq!(
                result.comparison,
                comparison.map(|a| Digest::hash_bytes(a, &bytes).value)
            );
            assert_eq!(
                result.checksums,
                bytes
                    .chunks(part_size as usize)
                    .map(|b| Algorithm::Sha256.digest(b))
                    .collect::<Vec<_>>()
            );
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
            |_, _| Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into()),
        );
        assert!(result.is_err());
    }
}

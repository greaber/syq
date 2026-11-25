//! Compute the ordinary BLAKE3 digest from independent, chunk-aligned ranges.
use blake3::hazmat::{
    left_subtree_len, max_subtree_len, merge_subtrees_non_root, merge_subtrees_root, HasherExt,
    Mode,
};

pub(super) struct Subtree {
    pub offset: u64,
    pub hash: [u8; 32],
}

pub(super) fn length(offset: u64, end: u64) -> u64 {
    let remaining = end - offset;
    if remaining < blake3::CHUNK_LEN as u64 {
        // Only the final chunk at EOF may be short.
        return remaining;
    }
    let complete = 1u64 << (63 - remaining.leading_zeros());
    complete.min(max_subtree_len(offset).unwrap_or(complete))
}

pub(super) fn merge(subtrees: &[Subtree], size: u64) -> [u8; 32] {
    fn parent(subtrees: &[Subtree], end: u64, root: bool) -> [u8; 32] {
        if subtrees.len() == 1 {
            debug_assert!(!root);
            return subtrees[0].hash;
        }
        // Split by bytes because a range can produce subtrees of several sizes.
        let boundary = subtrees[0].offset + left_subtree_len(end - subtrees[0].offset);
        let split = subtrees.partition_point(|subtree| subtree.offset < boundary);
        debug_assert_eq!(subtrees[split].offset, boundary);
        let left = parent(&subtrees[..split], boundary, false);
        let right = parent(&subtrees[split..], end, false);
        if root {
            *merge_subtrees_root(&left, &right, Mode::Hash).as_bytes()
        } else {
            merge_subtrees_non_root(&left, &right, Mode::Hash)
        }
    }
    parent(subtrees, size, true)
}

pub(super) struct Part {
    end: u64,
    offset: u64,
    remaining: u64,
    hash: blake3::Hasher,
    subtrees: Vec<Subtree>,
}

impl Part {
    pub(super) fn new(offset: u64, bytes: u64) -> Self {
        let end = offset + bytes;
        let mut hash = blake3::Hasher::new();
        hash.set_input_offset(offset);
        Self {
            end,
            offset,
            remaining: length(offset, end),
            hash,
            subtrees: Vec::new(),
        }
    }

    pub(super) fn update(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let n = self.remaining.min(bytes.len() as u64) as usize;
            self.hash.update(&bytes[..n]);
            self.remaining -= n as u64;
            bytes = &bytes[n..];
            if self.remaining == 0 {
                self.subtrees.push(Subtree {
                    offset: self.offset,
                    hash: self.hash.finalize_non_root(),
                });
                self.offset += length(self.offset, self.end);
                if self.offset < self.end {
                    self.remaining = length(self.offset, self.end);
                    // reset() does not clear the initial counter set by
                    // set_input_offset() in the current BLAKE3 API.
                    self.hash = blake3::Hasher::new();
                    self.hash.set_input_offset(self.offset);
                } else {
                    debug_assert!(bytes.is_empty());
                    break;
                }
            }
        }
    }

    pub(super) fn finish(self) -> Vec<Subtree> {
        debug_assert_eq!(self.offset, self.end);
        self.subtrees
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragmented_ranges_merge_into_the_standard_digest() {
        let bytes: Vec<_> = (0..13 * 1024 + 27).map(|i| (i % 251) as u8).collect();
        for part_size in [1024, 2048, 3072, 5120] {
            for size in [3 * part_size - 1, 2 * part_size, part_size + 1] {
                let data = &bytes[..size.min(bytes.len())];
                let mut subtrees = Vec::new();
                for (index, part) in data.chunks(part_size).enumerate() {
                    let mut tree = Part::new((index * part_size) as u64, part.len() as u64);
                    for fragment in part.chunks(1523) {
                        tree.update(fragment);
                    }
                    subtrees.extend(tree.finish());
                }
                assert_eq!(
                    merge(&subtrees, data.len() as u64),
                    *blake3::hash(data).as_bytes()
                );
            }
        }
    }
}

//! An incoming write owns its encoded frame, exposing only its file bytes.
//! This keeps queued writes independent without copying the payload out of
//! the frame. Locally produced writes own their original Vec directly.
use super::{Request, WireRequest};
use crate::wire_budget::{self, Budgeted};
use serde::{Deserializer, Serializer};
use std::io;
use std::ops::{Deref, DerefMut, Range};
use std::sync::{Arc, Mutex, OnceLock, Weak};

// Keep ordinary bulk frames, without letting an exceptional frame determine
// idle memory. One returned allocation per reader; queued writes remain owned.
const MIN_RECYCLED_FRAME: usize = 64 << 10;
const MAX_RECYCLED_FRAME: usize = 8 << 20;
type ReturnedFrame = Mutex<Option<Vec<u8>>>;

#[derive(Default)]
pub(super) struct FramePool {
    returned: Option<Arc<ReturnedFrame>>,
}

impl FramePool {
    pub(super) fn buffer(&mut self, len: usize, recycle: bool) -> FrameBuffer {
        if !recycle || !(MIN_RECYCLED_FRAME..=MAX_RECYCLED_FRAME).contains(&len) {
            self.clear();
            return vec![0; len].into();
        }
        let returned = self.returned.get_or_insert_with(Default::default);
        let mut bytes = returned.lock().unwrap().take().unwrap_or_default();
        if bytes.len() < len {
            bytes.reserve_exact(len - bytes.len());
            bytes.resize(len, 0);
        }
        FrameBuffer {
            bytes,
            len,
            returned: Arc::downgrade(returned),
        }
    }

    pub(super) fn clear(&mut self) {
        // Outstanding writes hold Weak references, so neither their storage nor
        // a return slot keeps the reader alive after a phase change or failure.
        self.returned = None;
    }
}

/// Initialized storage travels with the request until its consumer releases it.
/// Only the current frame is visible, even when a reused allocation is longer.
pub struct FrameBuffer {
    bytes: Vec<u8>,
    len: usize,
    returned: Weak<ReturnedFrame>,
}

impl From<Vec<u8>> for FrameBuffer {
    fn from(bytes: Vec<u8>) -> Self {
        Self {
            len: bytes.len(),
            bytes,
            returned: Weak::new(),
        }
    }
}
impl Deref for FrameBuffer {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}
impl DerefMut for FrameBuffer {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[..self.len]
    }
}
impl Drop for FrameBuffer {
    fn drop(&mut self) {
        if let Some(returned) = self.returned.upgrade() {
            let mut slot = returned.lock().unwrap();
            if slot.is_none() && self.bytes.capacity() <= MAX_RECYCLED_FRAME {
                *slot = Some(std::mem::take(&mut self.bytes));
            }
        }
    }
}
impl FrameBuffer {
    fn into_vec(mut self) -> Vec<u8> {
        self.returned = Weak::new();
        let mut bytes = std::mem::take(&mut self.bytes);
        bytes.truncate(self.len);
        bytes
    }
}

pub struct Payload {
    storage: FrameBuffer,
    range: Range<usize>,
}

impl std::fmt::Debug for Payload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&**self, f)
    }
}

impl From<Vec<u8>> for Payload {
    fn from(storage: Vec<u8>) -> Self {
        let range = 0..storage.len();
        Self {
            storage: storage.into(),
            range,
        }
    }
}
impl Clone for Payload {
    fn clone(&self) -> Self {
        self.to_vec().into()
    }
}
impl Deref for Payload {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.storage[self.range.clone()]
    }
}
impl DerefMut for Payload {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.storage[self.range.clone()]
    }
}
impl Payload {
    /// Outgoing buffers have offset zero, so returning them to the producer
    /// preserves their allocation. A forwarded received frame is compacted.
    pub(crate) fn into_vec(mut self) -> Vec<u8> {
        if self.range.start != 0 {
            self.storage.copy_within(self.range.clone(), 0);
        }
        self.storage.len = self.range.len();
        self.storage.into_vec()
    }
}
impl serde_bytes::Serialize for Payload {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self)
    }
}
impl<'de> serde_bytes::Deserialize<'de> for Payload {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        <Vec<u8> as serde_bytes::Deserialize>::deserialize(deserializer).map(Self::from)
    }
}

fn write_range_tag() -> u32 {
    // Derive the tag from the same enum used by the writer. Other requests
    // retain their ordinary decode path; there is no second wire schema.
    static TAG: OnceLock<u32> = OnceLock::new();
    *TAG.get_or_init(|| {
        let request = WireRequest::WriteRange {
            path: Vec::new(),
            inplace: false,
            copy_id: [0; 16],
            attempt: 0,
            off: 0,
            hash: [0; 32],
            data: &[] as &[u8],
            guard: None,
        };
        let encoded = postcard::to_stdvec(&request).expect("serialize write-range tag");
        postcard::take_from_bytes::<u32>(&encoded)
            .expect("decode write-range tag")
            .0
    })
}

pub(super) fn decode_request(mut frame: FrameBuffer) -> io::Result<Budgeted<Request>> {
    if postcard::take_from_bytes::<u32>(&frame).map(|(tag, _)| tag) != Ok(write_range_tag()) {
        // Only raw write payloads return buffers; other requests keep their
        // existing allocation lifetime.
        frame.returned = Weak::new();
        return wire_budget::decode(&frame);
    }
    let decoded = wire_budget::decode::<WireRequest<&[u8]>>(&frame)?;
    let (request, mut hold) = decoded.into_parts();
    // The borrowed view can be smaller than the owned request that will be
    // queued. Keep collection accounting at least as conservative as before.
    hold.grow(
        std::mem::size_of::<Request>().saturating_sub(std::mem::size_of::<WireRequest<&[u8]>>()),
    )?;
    let WireRequest::WriteRange {
        path,
        inplace,
        copy_id,
        attempt,
        off,
        hash,
        data,
        guard,
    } = request
    else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected write range",
        ));
    };
    // Postcard borrows this slice from frame. Store a checked offset, never a
    // pointer or a reference to storage that the reader may reuse.
    let start = (data.as_ptr() as usize)
        .checked_sub(frame.as_ptr() as usize)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "payload outside frame"))?;
    let end = start
        .checked_add(data.len())
        .filter(|end| *end <= frame.len())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "payload outside frame"))?;
    Ok(Budgeted {
        value: Request::WriteRange {
            path,
            inplace,
            copy_id,
            attempt,
            off,
            hash,
            data: Payload {
                storage: frame,
                range: start..end,
            },
            guard,
        },
        hold,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{ContainerGuard, FrameReader, FrameWriter};

    fn request(data: Vec<u8>) -> Request {
        Request::WriteRange {
            path: b"dir/\xfffile".to_vec(),
            inplace: true,
            copy_id: [129; 16],
            attempt: 300,
            off: (1 << 40) + 17,
            hash: [231; 32],
            data: data.into(),
            guard: Some(ContainerGuard {
                root: b"/root".to_vec(),
                dev: 456,
                ino: 789,
            }),
        }
    }

    #[test]
    fn unchanged_writer_fixture_keeps_wire_bytes_and_frame_allocation() {
        // Captured with the unchanged writer at master 2a708853, before the
        // payload representation changed. Do not regenerate with this writer.
        let old = include_bytes!("../../tests/fixtures/protocol/write-range-2a708853.bin");
        let bytes = [0, 1, 127, 128, 255, 9];
        assert_eq!(postcard::to_stdvec(&request(bytes.to_vec())).unwrap(), old);
        let frame = old.to_vec();
        let ptr = frame.as_ptr();
        let decoded = decode_request(frame.into()).unwrap();
        assert_eq!(postcard::to_stdvec(&decoded.value).unwrap(), old);
        let Request::WriteRange { data, .. } = decoded.value else {
            panic!("not a write")
        };
        assert_eq!(data.storage.as_ptr(), ptr);
        assert!(data.range.start > 0);
        assert_eq!(&*data, bytes);
        assert_eq!(data.clone().into_vec(), bytes);
        assert_eq!(data.into_vec(), bytes);
        // Standalone serde decoding still owns its bytes when there is no
        // frame to transfer, and re-encoding has the same representation.
        let standalone: Request = postcard::from_bytes(old).unwrap();
        assert_eq!(postcard::to_stdvec(&standalone).unwrap(), old);
    }

    #[test]
    fn outgoing_buffer_recycling_preserves_the_allocation() {
        let mut bytes = Vec::with_capacity(4096);
        bytes.extend_from_slice(b"outgoing");
        let ptr = bytes.as_ptr();
        let bytes = Payload::from(bytes).into_vec();
        assert_eq!(bytes.as_ptr(), ptr);
        assert_eq!(bytes.capacity(), 4096);
        assert_eq!(bytes, b"outgoing");
    }

    #[test]
    fn writes_own_their_frames_across_queue_and_codec_boundaries() {
        for codec in [0, crate::compression::ZSTD, crate::compression::LZ4] {
            let mut wire = Vec::new();
            FrameWriter::new(&mut wire, false).write_preamble().unwrap();
            let mut expected = Vec::new();
            for (index, size) in [0, 1, 128, 256 << 10, 2 << 20, 7, 0]
                .into_iter()
                .enumerate()
            {
                let data = vec![index as u8; size];
                let encoded = postcard::to_stdvec(&request(data.clone())).unwrap();
                let body = match codec {
                    0 => encoded,
                    crate::compression::ZSTD => zstd::bulk::compress(&encoded, 1).unwrap(),
                    crate::compression::LZ4 => lz4::block::compress(&encoded, None, true).unwrap(),
                    _ => unreachable!(),
                };
                wire.extend_from_slice(&((body.len() + 1) as u32).to_le_bytes());
                wire.push(codec);
                wire.extend_from_slice(&body);
                expected.push(data);
            }
            let (tx, rx) = std::sync::mpsc::sync_channel(4);
            let count = expected.len();
            let reader = std::thread::spawn(move || {
                let mut reader = FrameReader::new(wire.as_slice());
                for _ in 0..count {
                    tx.send(reader.read_budgeted::<Request>().unwrap()).unwrap();
                }
            });
            // Keep every decoded request alive while subsequent frames decode,
            // and inspect only after the reader and its input have been dropped.
            let messages: Vec<_> = rx.into_iter().collect();
            reader.join().unwrap();
            for (message, expected) in messages.into_iter().zip(expected) {
                let Request::WriteRange { data, guard, .. } = message.value else {
                    panic!("not a write")
                };
                assert_eq!(&*data, expected);
                assert_eq!(guard.unwrap().ino, 789);
            }
        }
    }

    #[test]
    fn completed_writes_recycle_initialized_storage_across_threads_and_sizes() {
        let mut wire = Vec::new();
        let sizes = [1 << 20, 256 << 10, 1 << 20];
        for (i, size) in sizes.into_iter().enumerate() {
            // A single writer owns the preamble below.
            let encoded = postcard::to_stdvec(&request(vec![i as u8; size])).unwrap();
            if wire.is_empty() {
                FrameWriter::new(&mut wire, false).write_preamble().unwrap();
            }
            wire.extend_from_slice(&((encoded.len() + 1) as u32).to_le_bytes());
            wire.push(0);
            wire.extend_from_slice(&encoded);
        }
        let mut reader = FrameReader::new(wire.as_slice());
        let mut original = None;
        let mut initialized = 0;
        for (i, size) in sizes.into_iter().enumerate() {
            let message = reader.read_budgeted::<Request>().unwrap();
            let Request::WriteRange { data, .. } = &message.value else {
                panic!("not a write");
            };
            assert_eq!(&**data, vec![i as u8; size]);
            let ptr = data.storage.bytes.as_ptr() as usize;
            match original {
                None => {
                    original = Some(ptr);
                    initialized = data.storage.bytes.len();
                }
                Some(original) => {
                    assert_eq!(ptr, original);
                    assert_eq!(data.storage.bytes.len(), initialized);
                }
            }
            // A clone is independent and must not return a live write's buffer.
            let cloned = data.clone();
            std::thread::spawn(move || drop(message)).join().unwrap();
            assert_eq!(&*cloned, vec![i as u8; size]);
            let slot = reader.pool.returned.as_ref().unwrap().lock().unwrap();
            assert_eq!(slot.as_ref().unwrap().as_ptr() as usize, ptr);
        }
    }

    #[test]
    fn queued_writes_keep_distinct_buffers_and_only_one_completed_buffer_is_retained() {
        let mut wire = Vec::new();
        let mut writer = FrameWriter::new(&mut wire, false);
        for i in 0..6 {
            writer.write_msg(&request(vec![i; 256 << 10])).unwrap();
        }
        drop(writer);
        let mut reader = FrameReader::new(wire.as_slice());
        let mut messages: Vec<_> = (0..5)
            .map(|_| reader.read_budgeted::<Request>().unwrap())
            .collect();
        let pointers: Vec<_> = messages
            .iter()
            .map(|message| {
                let Request::WriteRange { data, .. } = &message.value else {
                    panic!("not a write")
                };
                data.storage.bytes.as_ptr() as usize
            })
            .collect();
        let distinct: std::collections::HashSet<_> = pointers.iter().collect();
        assert_eq!(distinct.len(), 5);
        let returned = Arc::downgrade(reader.pool.returned.as_ref().unwrap());
        assert!(returned.upgrade().unwrap().lock().unwrap().is_none());
        // Complete in reverse order. Later returns are freed when the slot is full.
        drop(messages.pop());
        drop(messages.pop());
        assert_eq!(
            returned
                .upgrade()
                .unwrap()
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .as_ptr() as usize,
            pointers[4]
        );
        let next = reader.read_budgeted::<Request>().unwrap();
        let Request::WriteRange { data, .. } = &next.value else {
            panic!("not a write")
        };
        assert_eq!(data.storage.bytes.as_ptr() as usize, pointers[4]);
        assert_eq!(&**data, vec![5; 256 << 10]);
        drop(reader);
        assert!(returned.upgrade().is_none());
        for (i, message) in messages.into_iter().enumerate() {
            let Request::WriteRange { data, .. } = message.value else {
                panic!("not a write")
            };
            assert_eq!(&*data, vec![i as u8; 256 << 10]);
        }
        drop(next);
    }

    #[test]
    fn failed_reads_and_codec_changes_release_returned_storage() {
        for codec in [crate::compression::ZSTD, crate::compression::LZ4] {
            let mut wire = Vec::new();
            FrameWriter::new(&mut wire, false)
                .write_msg(&request(vec![11; 256 << 10]))
                .unwrap();
            let encoded = postcard::to_stdvec(&request(vec![23; 256 << 10])).unwrap();
            let compressed = if codec == crate::compression::ZSTD {
                zstd::bulk::compress(&encoded, 1).unwrap()
            } else {
                lz4::block::compress(&encoded, None, true).unwrap()
            };
            wire.extend_from_slice(&((compressed.len() + 1) as u32).to_le_bytes());
            wire.push(codec);
            wire.extend_from_slice(&compressed);
            let mut reader = FrameReader::new(wire.as_slice());
            drop(reader.read_budgeted::<Request>().unwrap());
            let returned = Arc::downgrade(reader.pool.returned.as_ref().unwrap());
            let next = reader.read_budgeted::<Request>().unwrap();
            assert!(returned.upgrade().is_none());
            assert!(reader.pool.returned.is_none());
            let Request::WriteRange { data, .. } = next.value else {
                panic!("not a write")
            };
            assert_eq!(&*data, vec![23; 256 << 10]);
        }
        let mut wire = Vec::new();
        FrameWriter::new(&mut wire, false)
            .write_msg(&request(vec![11; 256 << 10]))
            .unwrap();
        wire.extend_from_slice(&((256u32 << 10) + 1).to_le_bytes());
        wire.push(0);
        wire.extend_from_slice(b"truncated body");
        let mut reader = FrameReader::new(wire.as_slice());
        drop(reader.read_budgeted::<Request>().unwrap());
        let returned = Arc::downgrade(reader.pool.returned.as_ref().unwrap());
        assert!(reader.read_budgeted::<Request>().is_err());
        assert!(returned.upgrade().is_none());
        assert!(reader.pool.returned.is_none());
    }

    #[test]
    fn recycling_limits_and_outgoing_extraction_do_not_retain_extra_storage() {
        let mut pool = FramePool::default();
        drop(pool.buffer(MAX_RECYCLED_FRAME, true));
        assert_eq!(
            pool.returned
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .len(),
            MAX_RECYCLED_FRAME
        );
        let returned = Arc::downgrade(pool.returned.as_ref().unwrap());
        drop(pool.buffer(MAX_RECYCLED_FRAME + 1, true));
        assert!(returned.upgrade().is_none());
        assert!(pool.returned.is_none());
        drop(pool.buffer(MIN_RECYCLED_FRAME, true));
        drop(pool.buffer(MIN_RECYCLED_FRAME - 1, true));
        assert!(pool.returned.is_none());
        let buffer = pool.buffer(MIN_RECYCLED_FRAME, true);
        let ptr = buffer.as_ptr();
        let bytes = buffer.into_vec();
        assert_eq!(bytes.as_ptr(), ptr);
        assert!(pool.returned.as_ref().unwrap().lock().unwrap().is_none());
    }

    #[test]
    fn truncated_writes_and_frame_limits_are_rejected() {
        let encoded = postcard::to_stdvec(&request(vec![37; 256])).unwrap();
        for end in 0..encoded.len() {
            assert!(
                decode_request(encoded[..end].to_vec().into()).is_err(),
                "prefix {end}"
            );
        }
        let mut wire = Vec::new();
        FrameWriter::new(&mut wire, false)
            .write_msg(&request(vec![0; 1024]))
            .unwrap();
        let mut reader = FrameReader::new(wire.as_slice());
        reader.set_limit(1024);
        assert!(reader.read_budgeted::<Request>().is_err());
        let mut reader = FrameReader::new(&wire[..wire.len() - 1]);
        assert!(reader.read_budgeted::<Request>().is_err());
    }
}

//! An incoming write owns its encoded frame, exposing only its file bytes.
//! This keeps queued writes independent without copying the payload out of
//! the frame. Locally produced writes own their original Vec directly.
use super::{Request, WireRequest};
use crate::wire_budget::{self, Budgeted};
use serde::{Deserializer, Serializer};
use std::io;
use std::ops::{Deref, DerefMut, Range};
use std::sync::OnceLock;

pub struct Payload {
    storage: Vec<u8>,
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
        Self { storage, range }
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
        self.storage.truncate(self.range.len());
        self.storage
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

pub(super) fn decode_request(frame: Vec<u8>) -> io::Result<Budgeted<Request>> {
    if postcard::take_from_bytes::<u32>(&frame).map(|(tag, _)| tag) != Ok(write_range_tag()) {
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
        let decoded = decode_request(frame).unwrap();
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
    fn truncated_writes_and_frame_limits_are_rejected() {
        let encoded = postcard::to_stdvec(&request(vec![37; 256])).unwrap();
        for end in 0..encoded.len() {
            assert!(
                decode_request(encoded[..end].to_vec()).is_err(),
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

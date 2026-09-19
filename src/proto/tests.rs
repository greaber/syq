#[test]
fn streaming_request_bounds_are_checked_before_starting() {
    let valid = super::ReadStreamRequest {
        path: Vec::new(),
        source: None,
        attempt: 0,
        off: 0,
        end: 1,
        block: 512,
    };
    valid.validate().unwrap();
    for (off, end, block) in [
        (0, 0, 512),
        (2, 1, 512),
        (0, u64::MAX, 512),
        (0, 1, 0),
        (0, 1, 511),
        (0, 1, (64 << 20) + 1),
    ] {
        assert!(super::ReadStreamRequest {
            off,
            end,
            block,
            ..valid.clone()
        }
        .validate()
        .is_err());
    }
    super::ReadStreamRequest {
        off: i64::MAX as u64 - 1,
        end: i64::MAX as u64,
        block: 64 << 20,
        ..valid
    }
    .validate()
    .unwrap();
}
use super::*;

fn local_preamble_len() -> usize {
    WIRE_PREAMBLE_FIXED_LEN + crate::identity::build().len()
}

fn block_message(data: Vec<u8>) -> Response {
    Response::Block {
        off: 7,
        hash: [11; 32],
        data,
    }
}

fn block_frame(data: Vec<u8>, compress: bool) -> Vec<u8> {
    let mut frame = Vec::new();
    FrameWriter::new(&mut frame, compress)
        .write_msg(&block_message(data))
        .unwrap();
    frame
}

fn raw_frame(body: &[u8], flag: u8) -> Vec<u8> {
    let mut bytes = Vec::new();
    FrameWriter::new(&mut bytes, false)
        .write_preamble()
        .unwrap();
    bytes.extend_from_slice(&((body.len() + 1) as u32).to_le_bytes());
    bytes.push(flag);
    bytes.extend_from_slice(body);
    bytes
}

#[test]
fn selected_seed_frames_accommodate_large_comparisons() {
    // Alternating matches need one range per two blocks. A large supported
    // comparison can exceed the ordinary metadata frame limit.
    let count = (MAX_FRAME - HASH_RESPONSE_OVERHEAD as usize - 1) / 64;
    let ranges: Vec<_> = (0..count as u64)
        .map(|i| {
            (
                2 * i * MIN_HASH_BLOCK_BYTES,
                (2 * i + 1) * MIN_HASH_BLOCK_BYTES,
            )
        })
        .collect();
    let request = Request::SeedBasis {
        path: b"file".to_vec(),
        copy_id: [0; 16],
        len: 2 * count as u64 * MIN_HASH_BLOCK_BYTES,
        final_ranges: Some(ranges),
        block: MIN_HASH_BLOCK_BYTES,
        attempt: 0,
        guard: None,
    };
    let Request::SeedBasis { len, block, .. } = &request else {
        unreachable!()
    };
    assert!(hash_response_fits(*block, *len));
    let encoded = postcard::to_stdvec(&request).unwrap();
    assert!(encoded.len() > MAX_METADATA_FRAME && encoded.len() < MAX_FRAME);
    let mut wire = Vec::new();
    FrameWriter::new(&mut wire, false)
        .write_msg(&request)
        .unwrap();
    let decoded: Request = FrameReader::new(wire.as_slice()).read_msg().unwrap();
    assert!(
        matches!(decoded, Request::SeedBasis { final_ranges: Some(ranges), .. } if ranges.len() == count)
    );
    let response = Response::SeededBasis(SeededBasis {
        hashes: vec![[1; 32]; MAX_METADATA_FRAME / 32 + 1],
        selected_final: true,
    });
    let mut wire = Vec::new();
    FrameWriter::new(&mut wire, false)
        .write_msg(&response)
        .unwrap();
    let decoded: Response = FrameReader::new(wire.as_slice()).read_msg().unwrap();
    assert!(
        matches!(decoded, Response::SeededBasis(seed) if seed.selected_final && seed.hashes.len() == MAX_METADATA_FRAME / 32 + 1)
    );
}

#[test]
fn direct_frames_preserve_buffered_encoding_and_released_payloads() {
    // The previous writer (also in v0.5.1) materializes postcard bytes
    // before adding this header. Compare entire consecutive frames.
    let mut actual = Vec::new();
    let mut expected = Vec::new();
    FrameWriter::new(&mut expected, false)
        .write_preamble()
        .unwrap();
    {
        let mut writer = FrameWriter::new(&mut actual, false);
        for size in [0, 127, 128, 16384, (1 << 20) - 40, 1 << 20, 4 << 20] {
            let response = Response::Block {
                off: 1234567,
                hash: [11; 32],
                data: vec![0xab; size],
            };
            let payload = postcard::to_stdvec(&response).unwrap();
            expected.extend_from_slice(&raw_frame(&payload, 0)[local_preamble_len()..]);
            writer.write_msg(&response).unwrap();
        }
    }
    assert_eq!(actual, expected);
    let fixture = include_bytes!("../../tests/fixtures/completion/list-dir-v0.3.2.bin");
    let request: Request = postcard::from_bytes(fixture).unwrap();
    let mut actual = Vec::new();
    FrameWriter::new(&mut actual, false)
        .write_msg(&request)
        .unwrap();
    assert_eq!(
        &actual[local_preamble_len()..],
        &raw_frame(fixture, 0)[local_preamble_len()..]
    );
}

#[test]
fn direct_frame_passes_large_payload_to_transport_without_copying() {
    struct ObservePayload {
        pointer: *const u8,
        length: usize,
        seen: bool,
    }
    impl Write for ObservePayload {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.as_ptr() == self.pointer && bytes.len() == self.length {
                self.seen = true;
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let data = vec![17; 4 << 20];
    let mut output = ObservePayload {
        pointer: data.as_ptr(),
        length: data.len(),
        seen: false,
    };
    FrameWriter::new(&mut output, false)
        .write_msg(&Response::Block {
            off: 0,
            hash: [0; 32],
            data,
        })
        .unwrap();
    assert!(
        output.seen,
        "transport did not receive the original payload slice"
    );
}

#[test]
fn metadata_keeps_single_pass_serialization() {
    struct Metadata(std::cell::Cell<usize>);
    impl Serialize for Metadata {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            self.0.set(self.0.get() + 1);
            serializer.serialize_u8(0)
        }
    }
    impl SizeHint for Metadata {
        fn size_hint(&self) -> usize {
            1
        }
        fn frame_limit(&self) -> usize {
            MAX_FRAME
        }
    }
    let message = Metadata(std::cell::Cell::new(0));
    FrameWriter::new(io::sink(), false)
        .write_msg(&message)
        .unwrap();
    assert_eq!(message.0.get(), 1);
    assert!(!Response::ScanBatch(Vec::new()).direct_payload());
    assert!(!Request::PutSmallBatch(Vec::new()).direct_payload());
}

#[test]
fn frames_check_uncompressed_size_before_writing_header() {
    #[derive(Serialize)]
    struct Limited {
        #[serde(skip)]
        direct: bool,
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
    }
    impl SizeHint for Limited {
        fn direct_payload(&self) -> bool {
            self.direct
        }
        fn size_hint(&self) -> usize {
            self.data.len() + 2
        }
        fn frame_limit(&self) -> usize {
            1024
        }
    }
    for direct in [false, true] {
        for compress in [false, true] {
            // The encoded length is exactly the exclusive limit. Even
            // though these bytes compress well, reject before the header.
            let message = Limited {
                direct,
                data: vec![0; 1022],
            };
            assert_eq!(
                postcard::experimental::serialized_size(&message).unwrap(),
                1024
            );
            let mut bytes = Vec::new();
            let error = FrameWriter::new(&mut bytes, compress)
                .write_msg(&message)
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert!(error.to_string().contains("size limit"));
            assert_eq!(bytes.len(), local_preamble_len());
        }
    }
}

#[test]
fn direct_frame_preserves_payload_io_error() {
    struct FailPayload;
    impl Write for FailPayload {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.len() >= 1 << 20 {
                Err(io::Error::from_raw_os_error(libc::EPIPE))
            } else {
                Ok(bytes.len())
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let error = FrameWriter::new(FailPayload, false)
        .write_msg(&Response::Block {
            off: 0,
            hash: [0; 32],
            data: vec![0; 2 << 20],
        })
        .unwrap_err();
    assert_eq!(error.raw_os_error(), Some(libc::EPIPE));
}

#[test]
fn direct_frame_handles_short_writes_and_flush_errors() {
    struct ShortWriter {
        bytes: Vec<u8>,
        fail_flush: bool,
    }
    impl Write for ShortWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let n = bytes.len().min(31);
            self.bytes.extend_from_slice(&bytes[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            if self.fail_flush {
                Err(io::Error::from_raw_os_error(libc::EIO))
            } else {
                Ok(())
            }
        }
    }
    let mut output = ShortWriter {
        bytes: Vec::new(),
        fail_flush: false,
    };
    FrameWriter::new(&mut output, false)
        .write_msg(&block_message(vec![4; 2 << 20]))
        .unwrap();
    assert_eq!(output.bytes, block_frame(vec![4; 2 << 20], false));
    output.fail_flush = true;
    let error = FrameWriter::with_preamble_written(&mut output, false)
        .write_msg(&block_message(vec![4; 2 << 20]))
        .unwrap_err();
    assert_eq!(error.raw_os_error(), Some(libc::EIO));
}

#[test]
fn direct_frame_bounds_a_serializer_that_changes_length() {
    struct Changing(std::cell::Cell<bool>, bool);
    impl Serialize for Changing {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let second = self.0.replace(true);
            serializer.serialize_bytes(if second == self.1 { b"long" } else { b"s" })
        }
    }
    impl SizeHint for Changing {
        fn direct_payload(&self) -> bool {
            true
        }
        fn size_hint(&self) -> usize {
            16
        }
        fn frame_limit(&self) -> usize {
            MAX_FRAME
        }
    }
    for grows in [false, true] {
        let mut bytes = Vec::new();
        let error = FrameWriter::new(&mut bytes, false)
            .write_msg(&Changing(std::cell::Cell::new(false), grows))
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("length changed"));
        let offset = local_preamble_len();
        let announced = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        assert!(bytes.len() < offset + 4 + announced);
    }
}

#[test]
fn oversized_handshake_is_rejected_before_reading_its_body() {
    let mut bytes = Vec::new();
    FrameWriter::new(&mut bytes, false)
        .write_preamble()
        .unwrap();
    bytes.extend_from_slice(&((MAX_HANDSHAKE_FRAME + 1) as u32).to_le_bytes());
    let mut reader = FrameReader::new(bytes.as_slice());
    reader.set_limit(MAX_HANDSHAKE_FRAME);
    let error = reader.read_msg::<Request>().unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(error.to_string().contains("bad frame length"));
}

#[test]
fn compressed_handshake_cannot_expand_past_its_limit() {
    let payload = postcard::to_stdvec(&Response::Err("x".repeat(4096))).unwrap();
    let compressed = zstd::bulk::compress(&payload, 1).unwrap();
    let bytes = raw_frame(&compressed, 1);
    let mut reader = FrameReader::new(bytes.as_slice());
    reader.set_limit(1024);
    assert!(reader
        .read_msg::<Response>()
        .unwrap_err()
        .to_string()
        .contains("decompressed frame exceeds"));
}

#[test]
fn compressed_metadata_still_obeys_its_message_limit() {
    let payload = postcard::to_stdvec(&Response::Err("x".repeat(MAX_METADATA_FRAME))).unwrap();
    let compressed = zstd::bulk::compress(&payload, 1).unwrap();
    let bytes = raw_frame(&compressed, 1);
    let error = FrameReader::new(bytes.as_slice())
        .read_msg::<Response>()
        .unwrap_err();
    assert!(error.to_string().contains("message exceeds its size limit"));
}

#[test]
fn bounded_decoder_preserves_released_completion_payloads() {
    let request = include_bytes!("../../tests/fixtures/completion/list-dir-v0.3.2.bin");
    let response = include_bytes!("../../tests/fixtures/completion/directory-entries-v0.3.2.bin");
    let decoded = crate::wire_budget::decode::<Request>(request)
        .unwrap()
        .into_inner();
    assert_eq!(postcard::to_stdvec(&decoded).unwrap(), request);
    let decoded = crate::wire_budget::decode::<Response>(response)
        .unwrap()
        .into_inner();
    assert_eq!(postcard::to_stdvec(&decoded).unwrap(), response);
}

#[test]
fn compression_is_per_frame_and_never_expands_the_wire_payload() {
    let data = vec![b'a'; 64 * 1024];
    let compressed = block_frame(data.clone(), true);
    assert_eq!(
        compressed[local_preamble_len() + 4],
        if crate::identity::build() == "v0.6.0" {
            1
        } else {
            2
        },
        "compressible frame was not compressed"
    );

    let decoded = FrameReader::new(compressed.as_slice())
        .read_msg::<Response>()
        .unwrap();
    match decoded {
        Response::Block {
            off,
            hash,
            data: decoded,
        } => {
            assert_eq!((off, hash), (7, [11; 32]));
            assert_eq!(decoded, data);
        }
        other => panic!("unexpected response {other:?}"),
    }

    let disabled = block_frame(data, false);
    assert_eq!(
        disabled[local_preamble_len() + 4],
        0,
        "disabled compression changed the frame"
    );

    let mut random = vec![0u8; 64 * 1024];
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    for byte in &mut random {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *byte = state as u8;
    }
    let incompressible = block_frame(random, true);
    assert_eq!(
        incompressible[local_preamble_len() + 4],
        0,
        "an expanded compressed representation was selected"
    );
}

#[test]
fn captured_old_format_handshake_is_rejected_before_postcard_decode() {
    // Captured pre-preamble frame for Request::Hello { identity: "v0.1.8",
    // compress: false, debug: false, token: [], role: Control }.
    const OLD_FORMAT_HELLO: &[u8] = &[
        0x0d, 0x00, 0x00, 0x00, // frame length
        0x00, // frame flags
        0x00, // Request::Hello
        0x06, b'v', b'0', b'.', b'1', b'.', b'8', // identity
        0x00, 0x00, // compress, debug
        0x00, // empty token
        0x00, // ConnectionRole::Control
    ];

    let error = FrameReader::new(OLD_FORMAT_HELLO)
        .read_msg::<Request>()
        .unwrap_err();
    let diagnostic = error.to_string();
    assert!(diagnostic.contains(WIRE_PREAMBLE_PROTOCOL_ERROR));
    assert!(diagnostic.contains("magic mismatch"));
    assert!(diagnostic.contains("may predate"));
}

#[test]
fn released_v040_preamble_keeps_its_build_identity_boundary() {
    // v0.4.0's fixed preamble: magic, big-endian identity length, identity.
    // Kept independent of the current encoder and current enum variants.
    const V040: &[u8] = b"SYQWIRE\0\0\x06v0.4.0";
    let result = FrameReader::new(V040).read_preamble();
    if crate::identity::build() == "v0.4.0" {
        result.unwrap();
    } else {
        let message = result.unwrap_err().to_string();
        assert!(message.contains("build identity mismatch"), "{message}");
        assert!(message.contains("remote v0.4.0"), "{message}");
    }
}

#[test]
fn released_v052_preamble_rejects_new_transfer_messages_before_decoding() {
    // Literal v0.5.2 preamble, independent of today's enum encodings.
    const V052: &[u8] = b"SYQWIRE\0\0\x06v0.5.2";
    if crate::identity::build() != "v0.5.2" {
        let error = FrameReader::new(V052).read_msg::<Response>().unwrap_err();
        assert!(
            error.to_string().contains("build identity mismatch"),
            "{error}"
        );
    }
}

#[test]
fn released_v060_preamble_preserves_explicit_compatibility() {
    // v0.6.0 preamble, kept independent of the current encoder. Selecting
    // release helpers must accept it; ordinary source builds must reject it.
    const V060: &[u8] = b"SYQWIRE\0\0\x06v0.6.0";
    let result = FrameReader::new(V060).read_preamble();
    if crate::identity::build() == "v0.6.0" {
        result.unwrap();
    } else {
        let error = result.unwrap_err().to_string();
        assert!(error.contains("build identity mismatch"), "{error}");
    }
}

#[test]
fn every_malformed_build_identity_is_a_preamble_protocol_error() {
    let preamble = |length: u16, identity: &[u8]| {
        let mut input = Vec::new();
        input.extend_from_slice(WIRE_PREAMBLE_MAGIC);
        input.extend_from_slice(&length.to_be_bytes());
        input.extend_from_slice(identity);
        input
    };
    let cases = [
        (preamble(0, b""), "length 0 is invalid"),
        (
            preamble((MAX_BUILD_IDENTITY_BYTES + 1) as u16, b""),
            "length 513 is invalid",
        ),
        (preamble(4, b"ab"), "read remote syq build identity"),
        (preamble(1, &[0xff]), "not UTF-8"),
    ];

    for (input, expected) in cases {
        let error = FrameReader::new(input.as_slice())
            .read_msg::<Response>()
            .unwrap_err();
        let diagnostic = error.to_string();
        assert!(
            diagnostic.contains(WIRE_PREAMBLE_PROTOCOL_ERROR),
            "{diagnostic}"
        );
        assert!(diagnostic.contains(expected), "{diagnostic}");
    }
}

#[test]
fn build_identity_mismatch_is_reported_before_frame_decode() {
    let remote_identity = b"v0.0.0+different-build";
    let mut input = Vec::new();
    input.extend_from_slice(WIRE_PREAMBLE_MAGIC);
    input.extend_from_slice(&(remote_identity.len() as u16).to_be_bytes());
    input.extend_from_slice(remote_identity);
    input.extend_from_slice(b"not a postcard frame");

    let error = FrameReader::new(input.as_slice())
        .read_msg::<Response>()
        .unwrap_err();
    let diagnostic = error.to_string();
    assert!(diagnostic.contains("build identity mismatch"));
    assert!(diagnostic.contains("remote v0.0.0+different-build"));
    assert!(diagnostic.contains(crate::identity::build()));
}

#[test]
fn registered_paths_reject_unsafe_wire_components() {
    let temporary = crate::test_support::tempdir().unwrap();
    let session = crate::descriptor_broker::DescriptorSessionSlot::default();
    let ticket = session
        .register(std::fs::File::open(temporary.path()).unwrap())
        .unwrap();
    let root = ticket.root_id();
    assert_eq!(
        RegisteredPath::new(root, b"safe/non-utf8-\xff".to_vec())
            .unwrap()
            .relative,
        b"safe/non-utf8-\xff"
    );
    for relative in [
        b"/absolute".as_slice(),
        b"a//b",
        b".",
        b"a/../b",
        b"nul\0byte",
    ] {
        let invalid = RegisteredPath {
            root,
            relative: relative.to_vec(),
        };
        let encoded = postcard::to_allocvec(&invalid).unwrap();
        assert!(postcard::from_bytes::<RegisteredPath>(&encoded).is_err());
    }
}

#[test]
fn copy_local_fallback_has_a_structured_wire_response() {
    // Released v0.5.2's postcard encoding: response discriminant 32,
    // no payload. Keep this fixed fixture independent of today's encoder.
    const V052_UNSUPPORTED: &[u8] = &[32];
    assert!(matches!(
        postcard::from_bytes::<Response>(V052_UNSUPPORTED).unwrap(),
        Response::CopyLocalUnsupported
    ));
    assert_eq!(
        postcard::to_stdvec(&Response::CopyLocalUnsupported).unwrap(),
        V052_UNSUPPORTED
    );
    let mut frame = Vec::new();
    FrameWriter::new(&mut frame, false)
        .write_msg(&Response::CopyLocalUnsupported)
        .unwrap();
    assert!(matches!(
        FrameReader::new(frame.as_slice())
            .read_msg::<Response>()
            .unwrap(),
        Response::CopyLocalUnsupported
    ));
}

#[test]
fn frames_mix_lz4_zstd_and_raw_without_losing_boundaries() {
    let mut bytes = Vec::new();
    let inputs = [
        vec![b'a'; 128 << 10],
        vec![b'b'; 128 << 10],
        b"short".to_vec(),
        vec![b'c'; 128 << 10],
    ];
    {
        let mut writer = FrameWriter::new(&mut bytes, true);
        writer.write_msg(&block_message(inputs[0].clone())).unwrap();
        writer
            .compression
            .observe_write(4 << 20, std::time::Duration::from_secs(1));
        writer.write_msg(&block_message(inputs[1].clone())).unwrap();
        writer.write_msg(&block_message(inputs[2].clone())).unwrap();
        writer
            .compression
            .observe_write(4 << 20, std::time::Duration::from_millis(1));
        writer.write_msg(&block_message(inputs[3].clone())).unwrap();
    }
    let mut reader = FrameReader::new(bytes.as_slice());
    for expected in inputs {
        let Response::Block { data, .. } = reader.read_msg().unwrap() else {
            panic!("expected block")
        };
        assert_eq!(data, expected);
    }
    let mut offset = local_preamble_len();
    let mut codecs = Vec::new();
    while offset < bytes.len() {
        let len = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        codecs.push(bytes[offset + 4]);
        offset += 4 + len;
    }
    assert_eq!(
        codecs,
        if crate::identity::build() == "v0.6.0" {
            vec![1, 1, 0, 1]
        } else {
            vec![2, 1, 0, 2]
        }
    );
}

#[test]
fn lz4_frames_enforce_handshake_and_message_limits_and_reject_corruption() {
    let payload = postcard::to_stdvec(&Response::Err("x".repeat(4096))).unwrap();
    let compressed = lz4::block::compress(&payload, None, true).unwrap();
    let bytes = raw_frame(&compressed, crate::compression::LZ4);
    let mut reader = FrameReader::new(bytes.as_slice());
    reader.set_limit(1024);
    assert!(reader
        .read_msg::<Response>()
        .unwrap_err()
        .to_string()
        .contains("decompressed frame exceeds"));

    let payload = postcard::to_stdvec(&Response::Err("x".repeat(MAX_METADATA_FRAME))).unwrap();
    let compressed = lz4::block::compress(&payload, None, true).unwrap();
    let bytes = raw_frame(&compressed, crate::compression::LZ4);
    assert!(FrameReader::new(bytes.as_slice())
        .read_msg::<Response>()
        .unwrap_err()
        .to_string()
        .contains("message exceeds its size limit"));

    for body in [
        vec![],
        vec![1, 2, 3],
        u32::MAX.to_le_bytes().to_vec(),
        compressed[..compressed.len() - 1].to_vec(),
    ] {
        let bytes = raw_frame(&body, crate::compression::LZ4);
        assert!(FrameReader::new(bytes.as_slice())
            .read_msg::<Response>()
            .is_err());
    }
    let bytes = raw_frame(&[0], 3);
    assert!(FrameReader::new(bytes.as_slice())
        .read_msg::<Response>()
        .unwrap_err()
        .to_string()
        .contains("unknown frame flags"));
}

#[test]
fn compressed_frames_preserve_transport_write_and_flush_failures() {
    struct Broken(bool);
    impl Write for Broken {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.0 {
                Ok(bytes.len())
            } else {
                Err(io::Error::from_raw_os_error(libc::EIO))
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::from_raw_os_error(libc::EIO))
        }
    }
    for flush in [false, true] {
        let error = FrameWriter::with_preamble_written(Broken(flush), true)
            .write_msg(&block_message(vec![b'x'; 65536]))
            .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
    }
}

#[test]
fn released_v060_zstd_frame_remains_decodable() {
    // Captured from the published v0.6.0 Linux x86-64 helper, not regenerated
    // by today's encoder. Its ListDir response contains 64 empty-file names.
    // The preamble is tested separately: frame compatibility does not bypass
    // the build identity check when connecting to a different executable.
    let fixture =
        include_bytes!("../../tests/fixtures/completion/directory-entries-zstd-v0.6.0.bin");
    let mut bytes = Vec::new();
    FrameWriter::new(&mut bytes, false)
        .write_preamble()
        .unwrap();
    bytes.extend_from_slice(fixture);
    let Response::DirectoryEntries { entries, truncated } =
        FrameReader::new(bytes.as_slice()).read_msg().unwrap()
    else {
        panic!("expected released directory listing")
    };
    assert!(!truncated);
    assert_eq!(entries.len(), 64);
    for (index, entry) in entries.iter().enumerate() {
        assert_eq!(
            entry.name,
            format!("compressible-entry-{index:03}").as_bytes()
        );
    }
}

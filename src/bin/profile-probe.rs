use aes_gcm::aead::{Aead, KeyInit};
use sha2::Digest;
use std::{hint::black_box, io::Write, time::Instant};

fn measure(name: &str, mut operation: impl FnMut()) {
    let mut times = Vec::new();
    for _ in 0..3 {
        let start = Instant::now();
        let mut iterations = 0;
        loop {
            operation();
            iterations += 1;
            if start.elapsed().as_secs_f64() >= 0.25 {
                break;
            }
        }
        times.push(start.elapsed().as_secs_f64() / f64::from(iterations));
    }
    println!("PROBE {}", serde_json::json!({"name":name,"seconds":times}));
}
fn main() {
    assert!(
        cfg!(debug_assertions),
        "experiment must preserve debug assertions"
    );
    let mut state = 42u64;
    let data: Vec<u8> = (0..8 * 1024 * 1024)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect();
    measure("blake3_32mib", || {
        for _ in 0..4 {
            black_box(blake3::hash(black_box(&data)));
        }
    });
    measure("sha256_32mib", || {
        for _ in 0..4 {
            black_box(sha2::Sha256::digest(black_box(&data)));
        }
    });
    measure("md5_32mib", || {
        for _ in 0..4 {
            black_box(md5::Md5::digest(black_box(&data)));
        }
    });
    measure("xxh3_32mib", || {
        for _ in 0..4 {
            black_box(xxhash_rust::xxh3::xxh3_128(black_box(&data)));
        }
    });
    let cipher = aes_gcm::Aes256Gcm::new_from_slice(&[7; 32]).unwrap();
    let mut counter = 0u64;
    measure("aes256gcm_roundtrip_8mib", || {
        for chunk in data.chunks(256 * 1024) {
            let mut nonce = [0u8; 12];
            nonce[4..].copy_from_slice(&counter.to_be_bytes());
            counter += 1;
            let nonce = aes_gcm::Nonce::try_from(nonce.as_slice()).unwrap();
            let sealed = cipher.encrypt(&nonce, black_box(chunk)).unwrap();
            let opened = cipher.decrypt(&nonce, sealed.as_slice()).unwrap();
            assert_eq!(opened, chunk);
        }
    });
    measure("zstd_roundtrip_8mib", || {
        let packed = zstd::bulk::compress(black_box(&data), 1).unwrap();
        assert_eq!(zstd::bulk::decompress(&packed, data.len()).unwrap(), data);
    });
    measure("gzip_encode_8mib", || {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(black_box(&data)).unwrap();
        black_box(encoder.finish().unwrap());
    });
    let rows: Vec<_> = (0..10000)
        .map(|i| (format!("directory/file-{i}"), i as u64, 0o644u32))
        .collect();
    measure("postcard_100k_rows", || {
        for _ in 0..10 {
            black_box(postcard::to_allocvec(black_box(&rows)).unwrap());
        }
    });
}

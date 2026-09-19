//! Record layer for TCP data connections: AES-256-GCM, or plain records
//! when encryption is off. Records are `u32 len | body`; for the encrypted
//! variant the body is ciphertext + 16-byte tag and the nonce is
//! `direction(1) | conn_id(3) | counter(8)`.

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use std::io::{self, Read, Write};

pub const RECORD_MAX: usize = 256 * 1024;
pub const KEY_LEN: usize = 32;
/// The wire ID is four bytes, but only three bytes enter the nonce.
pub const CONNECTION_ID_MAX: u32 = 0x00ff_ffff;

pub struct Cipher {
    aead: LessSafeKey,
    conn_id: u32,
    dir: u8,
    counter: u64,
}

impl Cipher {
    pub fn new(key: &[u8], conn_id: u32, dir: u8) -> Cipher {
        assert!(
            conn_id <= CONNECTION_ID_MAX,
            "TCP connection id exceeds nonce space"
        );
        Cipher {
            aead: LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).expect("key length")),
            conn_id,
            dir,
            counter: 0,
        }
    }
    fn nonce(&mut self) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[0] = self.dir;
        n[1..4].copy_from_slice(&self.conn_id.to_be_bytes()[1..]);
        n[4..].copy_from_slice(&self.counter.to_be_bytes());
        self.counter += 1;
        n
    }
    pub fn seal(&mut self, plain: &[u8]) -> Vec<u8> {
        let nonce = Nonce::assume_unique_for_key(self.nonce());
        let mut buffer = Vec::with_capacity(plain.len() + 16);
        buffer.extend_from_slice(plain);
        self.aead
            .seal_in_place_append_tag(nonce, Aad::empty(), &mut buffer)
            .expect("encrypt");
        buffer
    }
    pub fn open(&mut self, cipher: &[u8]) -> io::Result<Vec<u8>> {
        let nonce = Nonce::assume_unique_for_key(self.nonce());
        let mut buffer = Vec::from(cipher);
        let len = self
            .aead
            .open_in_place(nonce, Aad::empty(), &mut buffer)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "authentication failed (wrong key or corrupted data)",
                )
            })?
            .len();
        buffer.truncate(len);
        Ok(buffer)
    }
}

pub struct RecordWriter<W: Write> {
    inner: W,
    cipher: Option<Cipher>,
    buf: Vec<u8>,
}

impl<W: Write> RecordWriter<W> {
    pub fn new(inner: W, cipher: Option<Cipher>) -> Self {
        RecordWriter {
            inner,
            cipher,
            buf: Vec::with_capacity(RECORD_MAX),
        }
    }
    fn emit(&mut self) -> io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let body = match &mut self.cipher {
            Some(c) => c.seal(&self.buf),
            None => std::mem::take(&mut self.buf),
        };
        self.inner.write_all(&(body.len() as u32).to_le_bytes())?;
        self.inner.write_all(&body)?;
        self.buf.clear();
        Ok(())
    }
}

impl<W: Write> Write for RecordWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let room = RECORD_MAX - self.buf.len();
        let n = data.len().min(room);
        self.buf.extend_from_slice(&data[..n]);
        if self.buf.len() == RECORD_MAX {
            self.emit()?;
        }
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.emit()?;
        self.inner.flush()
    }
}

pub struct RecordReader<R: Read> {
    inner: R,
    cipher: Option<Cipher>,
    buf: Vec<u8>,
    pos: usize,
}

impl<R: Read> RecordReader<R> {
    pub fn new(inner: R, cipher: Option<Cipher>) -> Self {
        RecordReader {
            inner,
            cipher,
            buf: Vec::new(),
            pos: 0,
        }
    }
    fn fill(&mut self) -> io::Result<()> {
        let mut hdr = [0u8; 4];
        self.inner.read_exact(&mut hdr)?;
        let len = u32::from_le_bytes(hdr) as usize;
        if len == 0 || len > RECORD_MAX + 64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("bad record length {len}"),
            ));
        }
        let mut body = vec![0u8; len];
        self.inner.read_exact(&mut body)?;
        self.buf = match &mut self.cipher {
            Some(c) => c.open(&body)?,
            None => body,
        };
        self.pos = 0;
        Ok(())
    }
}

impl<R: Read> Read for RecordReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.buf.len() {
            self.fill()?;
        }
        let n = out.len().min(self.buf.len() - self.pos);
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    getrandom::fill(&mut v).expect("getrandom");
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn cipher_preserves_legacy_bytes_at_record_boundaries() {
        use sha2::{Digest, Sha256};

        // SHA-256 of the concatenated ciphertexts and tags for these 81 cases,
        // captured with the previous aes-gcm 0.11.1 backend, independently of
        // Cipher. Keep this fixed so both wire bytes and nonce order are tested.
        let expected = [
            0xde, 0x91, 0xeb, 0xa8, 0xa5, 0x26, 0xae, 0x3d, 0xd2, 0x73, 0x9b, 0x53, 0xb8, 0x1a,
            0x46, 0x56, 0xd9, 0x86, 0x68, 0x9f, 0xd8, 0x17, 0xb0, 0x90, 0x52, 0x8a, 0xaf, 0xd0,
            0xa0, 0xc2, 0xff, 0x3f,
        ];
        let key = [7; KEY_LEN];
        let mut digest = Sha256::new();
        for direction in [0, 1, 2] {
            for id in [0, 0x123456, CONNECTION_ID_MAX] {
                let mut sender = Cipher::new(&key, id, direction);
                let mut receiver = Cipher::new(&key, id, direction);
                for (counter, len) in [0, 1, 15, 16, 17, 255, 256, RECORD_MAX - 1, RECORD_MAX]
                    .into_iter()
                    .enumerate()
                {
                    let plain: Vec<u8> = (0..len).map(|i| (i * 31 + counter) as u8).collect();
                    let encoded = sender.seal(&plain);
                    digest.update(&encoded);
                    assert_eq!(receiver.open(&encoded).unwrap(), plain);
                }
            }
        }
        assert_eq!(digest.finalize().as_slice(), expected);
    }

    #[test]
    fn cipher_rejects_wrong_key_nonce_tag_and_truncation() {
        let key = [7; KEY_LEN];
        let mut sender = Cipher::new(&key, 42, 1);
        let encoded = sender.seal(b"authenticated payload");
        for mut receiver in [
            Cipher::new(&[8; KEY_LEN], 42, 1),
            Cipher::new(&key, 43, 1),
            Cipher::new(&key, 42, 0),
        ] {
            assert_eq!(
                receiver.open(&encoded).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
        let second = sender.seal(b"next record");
        assert!(Cipher::new(&key, 42, 1).open(&second).is_err());
        let mut bad_tag = encoded.clone();
        *bad_tag.last_mut().unwrap() ^= 1;
        assert!(Cipher::new(&key, 42, 1).open(&bad_tag).is_err());
        for len in [0, 1, 15, 16, encoded.len() - 1] {
            assert_eq!(
                Cipher::new(&key, 42, 1)
                    .open(&encoded[..len])
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn encrypted_records_preserve_v041_wire_bytes() {
        // Generated with the unchanged src/tcp_records.rs from tag v0.4.1:
        // key [7; 32], ID 0x123456, direction 1, first record.
        let fixture = [
            35, 0, 0, 0, 198, 164, 119, 78, 242, 66, 129, 200, 51, 63, 3, 50, 75, 180, 63, 56, 117,
            145, 62, 157, 157, 91, 122, 238, 3, 197, 253, 74, 74, 210, 26, 155, 127, 220, 156,
        ];
        let plain = b"released TCP record";
        let mut reader = RecordReader::new(
            Cursor::new(fixture),
            Some(Cipher::new(&[7; KEY_LEN], 0x123456, 1)),
        );
        let mut decoded = [0; 19];
        reader.read_exact(&mut decoded).unwrap();
        assert_eq!(&decoded, plain);
        let mut encoded = Vec::new();
        let mut writer =
            RecordWriter::new(&mut encoded, Some(Cipher::new(&[7; KEY_LEN], 0x123456, 1)));
        writer.write_all(plain).unwrap();
        writer.flush().unwrap();
        assert_eq!(encoded, fixture);
    }

    #[test]
    #[should_panic(expected = "TCP connection id exceeds nonce space")]
    fn cipher_rejects_connection_id_aliases() {
        Cipher::new(&[7; KEY_LEN], 0x0100_0001, 1);
    }

    #[test]
    fn encrypted_records_round_trip_across_nonce_counters() {
        let key = [7; KEY_LEN];
        let plain = vec![0x5a; RECORD_MAX + 19];
        let mut encoded = Vec::new();
        {
            let cipher = Cipher::new(&key, 42, 1);
            let mut writer = RecordWriter::new(&mut encoded, Some(cipher));
            writer.write_all(&plain).unwrap();
            writer.flush().unwrap();
        }

        let cipher = Cipher::new(&key, 42, 1);
        let mut reader = RecordReader::new(Cursor::new(encoded), Some(cipher));
        let mut decoded = vec![0; plain.len()];
        reader.read_exact(&mut decoded).unwrap();
        assert_eq!(decoded, plain);
    }

    #[test]
    fn encrypted_records_reject_tampering() {
        let key = [9; KEY_LEN];
        let mut sender = Cipher::new(&key, 17, 0);
        let mut ciphertext = sender.seal(b"authenticated payload");
        ciphertext[0] ^= 1;

        let mut receiver = Cipher::new(&key, 17, 0);
        let error = receiver.open(&ciphertext).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}

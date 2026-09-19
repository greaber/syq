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
    pub fn seal_in_place(&mut self, buffer: &mut Vec<u8>) {
        let nonce = Nonce::assume_unique_for_key(self.nonce());
        self.aead
            .seal_in_place_append_tag(nonce, Aad::empty(), buffer)
            .expect("encrypt");
    }
    pub fn open_in_place(&mut self, buffer: &mut Vec<u8>) -> io::Result<()> {
        let nonce = Nonce::assume_unique_for_key(self.nonce());
        match self.aead.open_in_place(nonce, Aad::empty(), buffer) {
            Ok(plain) => {
                let len = plain.len();
                buffer.truncate(len);
                Ok(())
            }
            Err(_) => {
                // The crypto implementation may modify the buffer on failure.
                // Only authenticated plaintext may remain readable.
                buffer.clear();
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "authentication failed (wrong key or corrupted data)",
                ))
            }
        }
    }
}

pub struct RecordWriter<W: Write> {
    inner: W,
    cipher: Option<Cipher>,
    buf: Vec<u8>,
}

impl<W: Write> RecordWriter<W> {
    pub fn new(inner: W, cipher: Option<Cipher>) -> Self {
        let capacity = RECORD_MAX
            + if cipher.is_some() {
                AES_256_GCM.tag_len()
            } else {
                0
            };
        RecordWriter {
            inner,
            cipher,
            buf: Vec::with_capacity(capacity),
        }
    }
    fn emit(&mut self) -> io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        if let Some(cipher) = &mut self.cipher {
            cipher.seal_in_place(&mut self.buf);
        }
        let result = self
            .inner
            .write_all(&(self.buf.len() as u32).to_le_bytes())
            .and_then(|()| self.inner.write_all(&self.buf));
        // A failed record write is fatal to this stream. Retain the allocation,
        // but never treat a failed record's ciphertext as fresh plaintext.
        self.buf.clear();
        result
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
        self.buf.resize(len, 0);
        // Hide the buffer until both reading and authentication succeed, even
        // if a caller attempts another read after a partial or invalid record.
        self.pos = len;
        self.inner.read_exact(&mut self.buf)?;
        if let Some(cipher) = &mut self.cipher {
            cipher.open_in_place(&mut self.buf)?;
        }
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
                    let mut encoded = plain.clone();
                    sender.seal_in_place(&mut encoded);
                    digest.update(&encoded);
                    receiver.open_in_place(&mut encoded).unwrap();
                    assert_eq!(encoded, plain);
                }
            }
        }
        assert_eq!(digest.finalize().as_slice(), expected);
    }

    #[test]
    fn cipher_rejects_wrong_key_nonce_tag_and_truncation() {
        let key = [7; KEY_LEN];
        let mut sender = Cipher::new(&key, 42, 1);
        let mut encoded = b"authenticated payload".to_vec();
        sender.seal_in_place(&mut encoded);
        for mut receiver in [
            Cipher::new(&[8; KEY_LEN], 42, 1),
            Cipher::new(&key, 43, 1),
            Cipher::new(&key, 42, 0),
        ] {
            let mut body = encoded.clone();
            assert_eq!(
                receiver.open_in_place(&mut body).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
            assert!(body.is_empty());
        }
        let mut second = b"next record".to_vec();
        sender.seal_in_place(&mut second);
        assert!(Cipher::new(&key, 42, 1).open_in_place(&mut second).is_err());
        assert!(second.is_empty());
        let mut bad_tag = encoded.clone();
        *bad_tag.last_mut().unwrap() ^= 1;
        assert!(Cipher::new(&key, 42, 1)
            .open_in_place(&mut bad_tag)
            .is_err());
        assert!(bad_tag.is_empty());
        for len in [0, 1, 15, 16, encoded.len() - 1] {
            let mut body = encoded[..len].to_vec();
            assert_eq!(
                Cipher::new(&key, 42, 1)
                    .open_in_place(&mut body)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
            assert!(body.is_empty());
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
    fn records_round_trip_changing_lengths_and_partial_reads() {
        for encrypted in [false, true] {
            let cipher = || encrypted.then(|| Cipher::new(&[7; KEY_LEN], 42, 1));
            let mut encoded = Vec::new();
            let mut expected = Vec::new();
            {
                let mut writer = RecordWriter::new(&mut encoded, cipher());
                for (i, len) in [19, RECORD_MAX, 1, RECORD_MAX - 1, RECORD_MAX + 17]
                    .into_iter()
                    .enumerate()
                {
                    let plain = vec![i as u8; len];
                    writer.write_all(&plain).unwrap();
                    writer.flush().unwrap();
                    expected.extend_from_slice(&plain);
                }
            }
            let mut reader = RecordReader::new(Cursor::new(encoded), cipher());
            let mut decoded = vec![0; expected.len()];
            for part in decoded.chunks_mut(997) {
                reader.read_exact(part).unwrap();
            }
            assert_eq!(decoded, expected);
        }
    }

    #[test]
    fn failed_record_reads_do_not_expose_buffer_contents() {
        let cipher = || Cipher::new(&[7; KEY_LEN], 42, 1);
        let mut encoded = Vec::new();
        {
            let mut writer = RecordWriter::new(&mut encoded, Some(cipher()));
            writer.write_all(b"good").unwrap();
            writer.flush().unwrap();
            writer.write_all(&vec![0x5a; RECORD_MAX]).unwrap();
            writer.flush().unwrap();
        }
        for truncated in [false, true] {
            let mut broken = encoded.clone();
            let error_kind = if truncated {
                broken.truncate(broken.len() - 32);
                io::ErrorKind::UnexpectedEof
            } else {
                *broken.last_mut().unwrap() ^= 1;
                io::ErrorKind::InvalidData
            };
            let mut reader = RecordReader::new(Cursor::new(broken), Some(cipher()));
            let mut good = [0; 4];
            reader.read_exact(&mut good).unwrap();
            assert_eq!(&good, b"good");
            let mut output = [0xa5; 17];
            assert_eq!(reader.read(&mut output).unwrap_err().kind(), error_kind);
            assert_eq!(output, [0xa5; 17]);
            assert_eq!(
                reader.read(&mut output).unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof
            );
            assert_eq!(output, [0xa5; 17]);
        }
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
        let mut ciphertext = b"authenticated payload".to_vec();
        sender.seal_in_place(&mut ciphertext);
        ciphertext[0] ^= 1;

        let mut receiver = Cipher::new(&key, 17, 0);
        let error = receiver.open_in_place(&mut ciphertext).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(ciphertext.is_empty());
    }
}

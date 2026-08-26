//! Record layer for TCP data connections: AES-256-GCM, or plain records
//! when encryption is off. Records are `u32 len | body`; for the encrypted
//! variant the body is ciphertext + 16-byte tag and the nonce is
//! `direction(1) | conn_id(3) | counter(8)`.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use std::io::{self, Read, Write};

pub const RECORD_MAX: usize = 256 * 1024;
pub const KEY_LEN: usize = 32;

pub struct Cipher {
    aead: Aes256Gcm,
    conn_id: u32,
    dir: u8,
    counter: u64,
}

impl Cipher {
    pub fn new(key: &[u8], conn_id: u32, dir: u8) -> Cipher {
        Cipher { aead: Aes256Gcm::new_from_slice(key).expect("key length"), conn_id, dir, counter: 0 }
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
        let n = self.nonce();
        self.aead
            .encrypt(Nonce::from_slice(&n), Payload { msg: plain, aad: &[] })
            .expect("encrypt")
    }
    pub fn open(&mut self, cipher: &[u8]) -> io::Result<Vec<u8>> {
        let n = self.nonce();
        self.aead
            .decrypt(Nonce::from_slice(&n), Payload { msg: cipher, aad: &[] })
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "authentication failed (wrong key or corrupted data)"))
    }
}

pub struct RecordWriter<W: Write> {
    inner: W,
    cipher: Option<Cipher>,
    buf: Vec<u8>,
}

impl<W: Write> RecordWriter<W> {
    pub fn new(inner: W, cipher: Option<Cipher>) -> Self {
        RecordWriter { inner, cipher, buf: Vec::with_capacity(RECORD_MAX) }
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
        RecordReader { inner, cipher, buf: Vec::new(), pos: 0 }
    }
    fn fill(&mut self) -> io::Result<()> {
        let mut hdr = [0u8; 4];
        self.inner.read_exact(&mut hdr)?;
        let len = u32::from_le_bytes(hdr) as usize;
        if len == 0 || len > RECORD_MAX + 64 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("bad record length {len}")));
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
    getrandom::getrandom(&mut v).expect("getrandom");
    v
}

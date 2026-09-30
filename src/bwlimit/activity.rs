//! Continuous transport activity for capped-copy tuning, separate from confirmed
//! file progress. Count completed I/O, not reserved credit or sleeping time.
use std::io::{self, Read, Write};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};

pub(crate) struct ActivityIo<T> {
    pub inner: T,
    pub bytes: Option<Arc<AtomicU64>>,
    pub handshake_pending: Arc<AtomicBool>,
}
impl<T> ActivityIo<T> {
    fn record(&self, bytes: usize) {
        if let Some(counter) = &self.bytes {
            if !self.handshake_pending.load(Ordering::Acquire) {
                counter.fetch_add(bytes as u64, Ordering::Relaxed);
            }
        }
    }
}
impl<T: Read> Read for ActivityIo<T> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(out)?;
        self.record(n);
        Ok(n)
    }
}
impl<T: Write> Write for ActivityIo<T> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(bytes)?;
        self.record(n);
        Ok(n)
    }
    fn write_vectored(&mut self, bytes: &[io::IoSlice<'_>]) -> io::Result<usize> {
        let n = self.inner.write_vectored(bytes)?;
        self.record(n);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn counts_successful_partial_io_only_after_handshake() {
        let bytes = Arc::new(AtomicU64::new(0));
        let handshake_pending = Arc::new(AtomicBool::new(true));
        let mut output = [0; 6];
        let mut writer = ActivityIo {
            inner: &mut output[..],
            bytes: Some(bytes.clone()),
            handshake_pending: handshake_pending.clone(),
        };
        assert_eq!(writer.write(b"hi").unwrap(), 2);
        assert_eq!(bytes.load(Ordering::Relaxed), 0);
        handshake_pending.store(false, Ordering::Release);
        assert_eq!(
            writer
                .write_vectored(&[io::IoSlice::new(b"abcdef")])
                .unwrap(),
            4
        );
        assert!(writer.write_all(b"full").is_err());
        assert_eq!(bytes.load(Ordering::Relaxed), 4);
        let mut reader = ActivityIo {
            inner: &b"received"[..],
            bytes: Some(bytes.clone()),
            handshake_pending,
        };
        let mut buffer = [0; 3];
        assert_eq!(reader.read(&mut buffer).unwrap(), 3);
        assert_eq!(bytes.load(Ordering::Relaxed), 7);
    }
}

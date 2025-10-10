//! Atomic reader wrapper for all-or-nothing reads in P2P message handling.

use std::io;
use std::io::Read;

/// Wraps a reader so reads become all-or-nothing.
pub struct AtomicReader<'a> {
    buf: Vec<u8>,
    reader: &'a mut dyn Read,
}

impl<'a> AtomicReader<'a> {
    /// Creates a new atomic reader wrapper.
    #[must_use]
    pub fn new(reader: &mut dyn Read) -> AtomicReader {
        AtomicReader { buf: Vec::new(), reader }
    }
}

impl<'a> Read for AtomicReader<'a> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let buf_len = self.buf.len();
        let out_len = out.len();
        if buf_len >= out_len {
            // If we have enough in the buffer already, use it
            out.copy_from_slice(&self.buf[0..out_len]);
            self.buf = self.buf[out_len..].to_vec();
            Ok(out_len)
        } else if buf_len > 0 {
            // Copy what we have and try to read the rest
            out[0..buf_len].copy_from_slice(&self.buf);
            let size = self.reader.read(&mut out[buf_len..])?;
            if size == 0 {
                Err(io::Error::new(io::ErrorKind::NotConnected, "Disconnected"))
            } else if buf_len + size < out_len {
                // Didn't read enough. Put what we read into the buffer.
                self.buf.extend_from_slice(&out[buf_len..buf_len + size]);
                Err(io::Error::new(io::ErrorKind::TimedOut, "Incomplete read"))
            } else {
                // Read enough. Clear the buffer and return.
                self.buf.clear();
                Ok(out_len)
            }
        } else {
            let size = self.reader.read(out)?;
            if size == 0 {
                Err(io::Error::new(io::ErrorKind::NotConnected, "Disconnected"))
            } else if size < out_len {
                // Didn't read enough. Put what we read into the buffer.
                self.buf.extend_from_slice(&out[0..size]);
                Err(io::Error::new(io::ErrorKind::TimedOut, "Incomplete read"))
            } else {
                // Read enough. Return.
                Ok(out_len)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::io::Cursor;
    use pretty_assertions::assert_eq;

    #[test]
    fn read() {
        let mut o = [0; 10];
        // Success: Read expected
        let v = vec![0; 10];
        let mut c = Cursor::new(&v);
        let mut r = AtomicReader::new(&mut c);
        assert_eq!(r.read(&mut o).unwrap(), 10);

        // Success: Read less than expected
        let v = vec![0; 12];
        let mut c = Cursor::new(&v);
        let mut r = AtomicReader::new(&mut c);
        assert_eq!(r.read(&mut o).unwrap(), 10);

        // Success: Read buffered
        let v = vec![0; 0];
        let mut c = Cursor::new(&v);
        let mut r = AtomicReader::new(&mut c);
        r.buf = vec![1; 10];
        assert_eq!(r.read(&mut o).unwrap(), 10);
        assert_eq!(r.buf.len(), 0);

        // Success: Read partially buffered
        let v = vec![0; 6];
        let mut c = Cursor::new(&v);
        let mut r = AtomicReader::new(&mut c);
        r.buf = vec![1; 4];
        assert_eq!(r.read(&mut o).unwrap(), 10);
        assert_eq!(o, [1, 1, 1, 1, 0, 0, 0, 0, 0, 0]);

        // Error: Read empty
        let v = vec![0; 0];
        let mut c = Cursor::new(&v);
        let mut r = AtomicReader::new(&mut c);
        assert!(r.read(&mut o).is_err());

        // Error: Read incomplete
        let v = vec![0; 9];
        let mut c = Cursor::new(&v);
        let mut r = AtomicReader::new(&mut c);
        assert!(r.read(&mut o).is_err());
        assert_eq!(r.buf.len(), 9);

        // Error: Read buffered and incomplete
        let v = vec![0; 0];
        let mut c = Cursor::new(&v);
        let mut r = AtomicReader::new(&mut c);
        r.buf = vec![1; 9];
        assert!(r.read(&mut o).is_err());
        assert_eq!(r.buf.len(), 9);

        // Error: Read partially buffered and incomplete
        let v = vec![0; 6];
        let mut c = Cursor::new(&v);
        let mut r = AtomicReader::new(&mut c);
        r.buf = vec![1; 3];
        assert!(r.read(&mut o).is_err());
        assert_eq!(r.buf.len(), 9);
    }
}

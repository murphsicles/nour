//! Variable length integer (varint) ser/des for Bitcoin SV P2P.

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io;
use std::io::{Read, Write};

#[cfg(feature = "async")]
use tokio::io::{AsyncRead, AsyncWrite};

/// Returns the number of bytes required for the varint.
#[must_use]
#[inline]
pub fn size(n: u64) -> usize {
    if n <= 252 {
        1
    } else if n <= 0xffff {
        3
    } else if n <= 0xffffffff {
        5
    } else {
        9
    }
}

/// Writes the var int to bytes.
#[inline]
pub fn write(n: u64, writer: &mut dyn Write) -> io::Result<()> {
    if n <= 252 {
        writer.write_u8(n as u8)
    } else if n <= 0xffff {
        writer.write_u8(0xfd)?;
        writer.write_u16::<LittleEndian>(n as u16)
    } else if n <= 0xffffffff {
        writer.write_u8(0xfe)?;
        writer.write_u32::<LittleEndian>(n as u32)
    } else {
        writer.write_u8(0xff)?;
        writer.write_u64::<LittleEndian>(n)
    }
}

/// Reads a var int from bytes.
#[inline]
pub fn read(reader: &mut dyn Read) -> io::Result<u64> {
    let n0 = reader.read_u8()?;
    match n0 {
        0xff => reader.read_u64::<LittleEndian>(),
        0xfe => reader.read_u32::<LittleEndian>().map(u64::from),
        0xfd => reader.read_u16::<LittleEndian>().map(u64::from),
        _ => Ok(n0 as u64),
    }
}

#[cfg(feature = "async")]
pub async fn write_async(n: u64, writer: &mut dyn AsyncWrite) -> io::Result<()> {
    if n <= 252 {
        writer.write_all(&[n as u8]).await
    } else if n <= 0xffff {
        let mut buf = [0u8; 3];
        buf[0] = 0xfd;
        buf[1..3].copy_from_slice(&(n as u16).to_le_bytes());
        writer.write_all(&buf).await
    } else if n <= 0xffffffff {
        let mut buf = [0u8; 5];
        buf[0] = 0xfe;
        buf[1..5].copy_from_slice(&(n as u32).to_le_bytes());
        writer.write_all(&buf).await
    } else {
        let mut buf = [0u8; 9];
        buf[0] = 0xff;
        buf[1..9].copy_from_slice(&n.to_le_bytes());
        writer.write_all(&buf).await
    }
}

#[cfg(feature = "async")]
pub async fn read_async(reader: &mut dyn AsyncRead) -> io::Result<u64> {
    let mut n0 = [0u8; 1];
    reader.read_exact(&mut n0).await?;
    let n0 = n0[0];
    match n0 {
        0xff => {
            let mut buf = [0u8; 8];
            reader.read_exact(&mut buf).await?;
            Ok(u64::from_le_bytes(buf))
        }
        0xfe => {
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf).await?;
            Ok(u32::from_le_bytes(buf) as u64)
        }
        0xfd => {
            let mut buf = [0u8; 2];
            reader.read_exact(&mut buf).await?;
            Ok(u16::from_le_bytes(buf) as u64)
        }
        _ => Ok(n0 as u64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use pretty_assertions::assert_eq;

    #[test]
    fn size() {
        assert_eq!(super::size(0), 1);
        assert_eq!(super::size(253), 3);
        assert_eq!(super::size(u16::MAX as u64), 3);
        assert_eq!(super::size(u32::MAX as u64), 5);
        assert_eq!(super::size(u64::MAX), 9);
    }

    #[test]
    fn write_read() {
        write_read_value(0);
        write_read_value(253);
        write_read_value(u16::MAX as u64);
        write_read_value(u32::MAX as u64);
        write_read_value(u64::MAX);
    }

    fn write_read_value(n: u64) {
        let mut v = Vec::new();
        write(n, &mut v).unwrap();
        assert_eq!(read(&mut Cursor::new(&v)).unwrap(), n);
    }
}

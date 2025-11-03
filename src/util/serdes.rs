//! Binary serialization/deserialization trait for Bitcoin SV objects.
use crate::util::{Error, Result};
use std::io;
use std::io::{Read, Write};
#[cfg(feature = "async")]
use tokio::io::{AsyncRead, AsyncWrite};

/// An object that may be serialized and deserialized.
pub trait Serializable<T> {
    /// Reads the object from serialized form.
    ///
    /// # Errors
    /// Propagates IO errors or invalid data.
    fn read(reader: &mut dyn Read) -> Result<T>
    where
        Self: Sized;
    /// Writes the object to the object to serialized form.
    ///
    /// # Errors
    /// IO errors.
    fn write(&self, writer: &mut dyn Write) -> io::Result<()>;
}

#[cfg(feature = "async")]
pub trait AsyncSerializable<T> {
    /// Reads the object from serialized form asynchronously.
    ///
    /// # Errors
    /// Propagates IO errors or invalid data.
    async fn read_async(reader: &mut dyn AsyncRead) -> Result<T>
    where
        Self: Sized;
    /// Writes the object to serialized form asynchronously.
    ///
    /// # Errors
    /// IO errors.
    async fn write_async(&self, writer: &mut dyn AsyncWrite) -> io::Result<()>;
}

impl Serializable<[u8; 16]> for [u8; 16] {
    fn read(reader: &mut dyn Read) -> Result<[u8; 16]> {
        let mut d = [0; 16];
        reader.read_exact(&mut d).map_err(|e| Error::IOError(e))?;
        Ok(d)
    }
    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        writer.write_all(self)
    }
}

impl Serializable<[u8; 32]> for [u8; 32] {
    fn read(reader: &mut dyn Read) -> Result<[u8; 32]> {
        let mut d = [0; 32];
        reader.read_exact(&mut d).map_err(|e| Error::IOError(e))?;
        Ok(d)
    }
    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        writer.write_all(self)
    }
}

#[cfg(feature = "async")]
impl AsyncSerializable<[u8; 16]> for [u8; 16] {
    async fn read_async(reader: &mut dyn AsyncRead) -> Result<[u8; 16]> {
        // Use tokio read_exact impl
        let mut d = [0; 16];
        reader
            .read_exact(&mut d)
            .await
            .map_err(|e| Error::IOError(e))?;
        Ok(d)
    }
    async fn write_async(&self, writer: &mut dyn AsyncWrite) -> io::Result<()> {
        writer.write_all(self).await
    }
}

#[cfg(feature = "async")]
impl AsyncSerializable<[u8; 32]> for [u8; 32] {
    async fn read_async(reader: &mut dyn AsyncRead) -> Result<[u8; 32]> {
        let mut d = [0; 32];
        reader
            .read_exact(&mut d)
            .await
            .map_err(|e| Error::IOError(e))?;
        Ok(d)
    }
    async fn write_async(&self, writer: &mut dyn AsyncWrite) -> io::Result<()> {
        writer.write_all(self).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use byteorder::{LittleEndian, ReadBytesExt};
    use pretty_assertions::assert_eq;
    use std::io::Cursor;

    #[test]
    fn test_serdes_array16() -> Result<()> {
        let array = [1; 16];
        let mut v = Vec::new();
        array.write(&mut v)?;
        let deserialized = <[u8; 16]>::read(&mut Cursor::new(&v))?;
        assert_eq!(array, deserialized);
        Ok(())
    }

    #[test]
    fn test_serdes_array32() -> Result<()> {
        let array = [2; 32];
        let mut v = Vec::new();
        array.write(&mut v)?;
        let deserialized = <[u8; 32]>::read(&mut Cursor::new(&v))?;
        assert_eq!(array, deserialized);
        Ok(())
    }

    #[test]
    fn test_short_read() {
        use std::io::Cursor;
        let short_bytes = vec![0u8; 3]; // For read_u32 expecting 4
        let mut ser = Cursor::new(short_bytes);
        assert_eq!(
            ser.read_u32::<LittleEndian>().unwrap_err().to_string(),
            "failed to fill whole buffer"
        );
    }
}

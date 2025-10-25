//! SendCmpct message for Bitcoin SV P2P, signaling compact block support (BIP-152).
use crate::messages::message::Payload;
use crate::util::{Error, Result, Serializable};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io;
use std::io::{Read, Write};
#[cfg(feature = "async")]
use tokio::io::{AsyncRead, AsyncWrite};
/// Specifies whether compact blocks are supported (BIP-152; optional in BSV/Teranode for large blocks).
#[derive(Debug, Default, PartialEq, Eq, Hash, Clone)]
pub struct SendCmpct {
    /// Whether compact blocks may be sent (1 = yes).
    pub enable: u8,
    /// Should always be 1.
    pub version: u64,
}
impl SendCmpct {
    /// Size of the SendCmpct payload in bytes (1 + 8 = 9).
    pub const SIZE: usize = 9;
    /// Returns whether compact blocks should be used.
    #[must_use]
    #[inline]
    pub fn use_cmpctblock(&self) -> bool {
        self.enable == 1 && self.version == 1
    }
}
impl Serializable<SendCmpct> for SendCmpct {
    fn read(reader: &mut dyn Read) -> Result<SendCmpct> {
        let enable = reader.read_u8().map_err(|e| Error::IOError(e))?;
        let mut version = [0u8; 8];
        reader.read_exact(&mut version).map_err(|e| Error::IOError(e))?;
        let version = u64::from_le_bytes(version);
        Ok(SendCmpct { enable, version })
    }
    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        writer.write_u8(self.enable)?;
        writer.write_all(&self.version.to_le_bytes())
    }
}
#[cfg(feature = "async")]
impl AsyncSerializable<SendCmpct> for SendCmpct {
    async fn read_async(reader: &mut dyn AsyncRead) -> Result<SendCmpct> {
        let enable = reader.read_u8().await.map_err(|e| Error::IOError(e))?;
        let mut version = [0u8; 8];
        reader.read_exact(&mut version).await.map_err(|e| Error::IOError(e))?;
        let version = u64::from_le_bytes(version);
        Ok(SendCmpct { enable, version })
    }
    async fn write_async(&self, writer: &mut dyn AsyncWrite) -> io::Result<()> {
        writer.write_u8(self.enable).await?;
        writer.write_all(&self.version.to_le_bytes()).await
    }
}
impl Payload<SendCmpct> for SendCmpct {
    fn size(&self) -> usize {
        Self::SIZE
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    use std::io::Cursor;
    use pretty_assertions::assert_eq;
    #[test]
    fn read_bytes() {
        let b = hex::decode("000100000000000000").unwrap();
        let f = SendCmpct::read(&mut Cursor::new(&b)).unwrap();
        assert_eq!(f.enable, 0);
        assert_eq!(f.version, 1);
    }
    #[test]
    fn write_read() {
        let mut v = Vec::new();
        let s = SendCmpct { enable: 1, version: 1 };
        s.write(&mut v).unwrap();
        assert_eq!(v.len(), s.size());
        assert_eq!(SendCmpct::read(&mut Cursor::new(&v)).unwrap(), s);
    }
}

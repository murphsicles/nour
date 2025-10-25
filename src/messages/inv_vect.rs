//! Inventory vector for Bitcoin SV P2P, identifying objects by type and hash.
use crate::util::{Error, Hash256, Result, Serializable};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io;
use std::io::{Read, Write};
#[cfg(feature = "async")]
use tokio::io::{AsyncRead, AsyncWrite};
// Inventory vector types
/// May be ignored.
pub const INV_VECT_ERROR: u32 = 0;
/// Hash of a transaction.
pub const INV_VECT_TX: u32 = 1;
/// Hash of a block header.
pub const INV_VECT_BLOCK: u32 = 2;
/// Hash of a block header. Indicates the reply should be a merkleblock message.
pub const INV_VECT_FILTERED_BLOCK: u32 = 3;
/// Hash of a block header. Indicates the reply should be a cmpctblock message (BIP-152).
pub const INV_VECT_COMPACT_BLOCK: u32 = 4;
/// Inventory vector describing an object being requested or announced.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct InvVect {
    /// Object type linked to this inventory (e.g., INV_VECT_TX).
    pub obj_type: u32,
    /// Hash of the object.
    pub hash: Hash256,
}
impl InvVect {
    /// Size of the inventory vector in bytes (4 + 32 = 36).
    pub const SIZE: usize = 36;
    /// Returns the size of the inventory vector in bytes.
    #[must_use]
    #[inline]
    pub fn size(&self) -> usize {
        Self::SIZE
    }
}
impl Serializable<InvVect> for InvVect {
    fn read(reader: &mut dyn Read) -> Result<InvVect> {
        let mut obj_type = [0u8; 4];
        reader.read_exact(&mut obj_type).map_err(|e| Error::IOError(e))?;
        let obj_type = u32::from_le_bytes(obj_type);
        let hash = Hash256::read(reader)?;
        Ok(InvVect { obj_type, hash })
    }
    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        writer.write_all(&self.obj_type.to_le_bytes())?;
        self.hash.write(writer)?;
        Ok(())
    }
}
#[cfg(feature = "async")]
impl AsyncSerializable<InvVect> for InvVect {
    async fn read_async(reader: &mut dyn AsyncRead) -> Result<InvVect> {
        let mut obj_type = [0u8; 4];
        reader.read_exact(&mut obj_type).await.map_err(|e| Error::IOError(e))?;
        let obj_type = u32::from_le_bytes(obj_type);
        let hash = Hash256::read_async(reader).await?;
        Ok(InvVect { obj_type, hash })
    }
    async fn write_async(&self, writer: &mut dyn AsyncWrite) -> io::Result<()> {
        writer.write_all(&self.obj_type.to_le_bytes()).await?;
        self.hash.write_async(writer).await?;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use pretty_assertions::assert_eq;
    #[test]
    fn write_read() {
        let mut v = Vec::new();
        let iv = InvVect {
            obj_type: INV_VECT_TX,
            hash: Hash256([8; 32]),
        };
        iv.write(&mut v).unwrap();
        assert_eq!(v.len(), iv.size());
        assert_eq!(InvVect::read(&mut Cursor::new(&v)).unwrap(), iv);
    }
}

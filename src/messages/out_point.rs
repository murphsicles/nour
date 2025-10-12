//! OutPoint for Bitcoin SV P2P, referencing transaction outputs.

use crate::util::{Hash256, Result, Serializable};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io;
use std::io::{Read, Write};

#[cfg(feature = "async")]
use tokio::io::{AsyncRead, AsyncWrite};

/// The coinbase transaction input hash (all zeros).
pub const COINBASE_OUTPOINT_HASH: Hash256 = Hash256([0; 32]);
/// The coinbase transaction input index (0xffffffff).
pub const COINBASE_OUTPOINT_INDEX: u32 = 0xffffffff;

/// Reference to a transaction output.
#[derive(Debug, Default, PartialEq, Eq, Hash, Clone)]
pub struct OutPoint {
    /// Hash of the referenced transaction.
    pub hash: Hash256,
    /// Index of the output in the transaction, zero-indexed.
    pub index: u32,
}

impl OutPoint {
    /// Size of the out point in bytes (32 + 4 = 36).
    pub const SIZE: usize = 36;

    /// Returns the size of the out point in bytes.
    #[must_use]
    #[inline]
    pub fn size(&self) -> usize {
        Self::SIZE
    }
}

impl Serializable<OutPoint> for OutPoint {
    fn read(reader: &mut dyn Read) -> Result<OutPoint> {
        let hash = Hash256::read(reader)?;
        let mut index = [0u8; 4];
        reader.read_exact(&mut index).map_err(|e| Error::IOError(e))?;
        let index = u32::from_le_bytes(index);
        Ok(OutPoint { hash, index })
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        self.hash.write(writer)?;
        writer.write_all(&self.index.to_le_bytes())
    }
}

#[cfg(feature = "async")]
impl AsyncSerializable<OutPoint> for OutPoint {
    async fn read_async(reader: &mut dyn AsyncRead) -> Result<OutPoint> {
        let hash = Hash256::read_async(reader).await?;
        let mut index = [0u8; 4];
        reader.read_exact(&mut index).await.map_err(|e| Error::IOError(e))?;
        let index = u32::from_le_bytes(index);
        Ok(OutPoint { hash, index })
    }

    async fn write_async(&self, writer: &mut dyn AsyncWrite) -> io::Result<()> {
        self.hash.write_async(writer).await?;
        writer.write_all(&self.index.to_le_bytes()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    use std::io::Cursor;
    use pretty_assertions::assert_eq;

    #[test]
    fn write_read() {
        let mut v = Vec::new();
        let t = OutPoint {
            hash: Hash256::decode(
                "123412345678567890ab90abcdefcdef123412345678567890ab90abcdefcdef",
            )
            .unwrap(),
            index: 0,
        };
        t.write(&mut v).unwrap();
        assert_eq!(v.len(), t.size());
        assert_eq!(OutPoint::read(&mut Cursor::new(&v)).unwrap(), t);
    }

    #[test]
    fn coinbase() {
        let mut v = Vec::new();
        let t = OutPoint {
            hash: COINBASE_OUTPOINT_HASH,
            index: COINBASE_OUTPOINT_INDEX,
        };
        t.write(&mut v).unwrap();
        assert_eq!(v.len(), t.size());
        assert_eq!(OutPoint::read(&mut Cursor::new(&v)).unwrap(), t);
    }
}

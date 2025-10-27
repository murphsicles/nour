//! Block header for Bitcoin SV P2P messages.

use crate::util::{sha256d, Error, Hash256, Result, Serializable};
use byteorder::{LittleEndian, WriteBytesExt};
use std::cmp::min;
use std::io;
use std::io::{Read, Write};

#[cfg(feature = "async")]
use tokio::io::{AsyncRead, AsyncWrite};

/// Block header.
#[derive(Debug, Default, PartialEq, Eq, Hash, Clone)]
pub struct BlockHeader {
    /// Block version specifying which validation rules to use.
    pub version: u32,
    /// Hash of the previous block.
    pub prev_hash: Hash256,
    /// Root of the merkle tree of this block's transaction hashes.
    pub merkle_root: Hash256,
    /// Timestamp when this block was created as recorded by the miner.
    pub timestamp: u32,
    /// Target difficulty bits.
    pub bits: u32,
    /// Nonce used to mine the block.
    pub nonce: u32,
}

impl BlockHeader {
    /// Size of the BlockHeader in bytes (80).
    pub const SIZE: usize = 80;

    /// Returns the size of the block header in bytes.
    #[must_use]
    #[inline]
    pub fn size(&self) -> usize {
        Self::SIZE
    }

    /// Calculates the hash for this block header.
    #[must_use]
    pub fn hash(&self) -> Hash256 {
        let mut v = Vec::with_capacity(Self::SIZE);
        v.write_u32::<LittleEndian>(self.version).unwrap();
        self.prev_hash.write(&mut v).unwrap();
        self.merkle_root.write(&mut v).unwrap();
        v.write_u32::<LittleEndian>(self.timestamp).unwrap();
        v.write_u32::<LittleEndian>(self.bits).unwrap();
        v.write_u32::<LittleEndian>(self.nonce).unwrap();
        sha256d(&v)
    }

    /// Checks that the block header is valid.
    ///
    /// # Errors
    /// `Error::BadData` if timestamp too old or POW invalid.
    pub fn validate(&self, hash: &Hash256, prev_headers: &[BlockHeader]) -> Result<()> {
        // Timestamp > median timestamp of last 11 blocks
        if !prev_headers.is_empty() {
            let h = &prev_headers[prev_headers.len() - min(prev_headers.len(), 11)..];
            let mut timestamps: Vec<u32> = h.iter().map(|x| x.timestamp).collect();
            timestamps.sort();
            if self.timestamp < timestamps[timestamps.len() / 2] {
                return Err(Error::BadData(format!("Timestamp too old: {}", self.timestamp)));
            }
        }

        // POW
        let target = self.difficulty_target()?;
        if hash > &target {
            return Err(Error::BadData("Invalid POW".to_string()));
        }

        Ok(())
    }

    /// Calculates the target difficulty hash.
    ///
    /// # Errors
    /// `Error::BadArgument` if difficulty exponent out of range (3-32).
    fn difficulty_target(&self) -> Result<Hash256> {
        let exp = (self.bits >> 24) as usize;
        if exp < 3 || exp > 32 {
            return Err(Error::BadArgument(format!("Difficulty exponent out of range: {}", self.bits)));
        }
        let mut difficulty = [0u8; 32];
        difficulty[exp - 1] = ((self.bits >> 16) & 0xff) as u8;
        difficulty[exp - 2] = ((self.bits >> 8) & 0xff) as u8;
        difficulty[exp - 3] = (self.bits & 0xff) as u8;
        Ok(Hash256(difficulty))
    }
}

impl Serializable<BlockHeader> for BlockHeader {
    fn read(reader: &mut dyn Read) -> Result<BlockHeader> {
        let mut version = [0u8; 4];
        reader.read_exact(&mut version).map_err(|e| Error::IOError(e))?;
        let version = u32::from_le_bytes(version);
        let prev_hash = Hash256::read(reader)?;
        let merkle_root = Hash256::read(reader)?;
        let mut timestamp = [0u8; 4];
        reader.read_exact(&mut timestamp).map_err(|e| Error::IOError(e))?;
        let timestamp = u32::from_le_bytes(timestamp);
        let mut bits = [0u8; 4];
        reader.read_exact(&mut bits).map_err(|e| Error::IOError(e))?;
        let bits = u32::from_le_bytes(bits);
        let mut nonce = [0u8; 4];
        reader.read_exact(&mut nonce).map_err(|e| Error::IOError(e))?;
        let nonce = u32::from_le_bytes(nonce);
        Ok(BlockHeader {
            version,
            prev_hash,
            merkle_root,
            timestamp,
            bits,
            nonce,
        })
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        writer.write_all(&self.version.to_le_bytes())?;
        self.prev_hash.write(writer)?;
        self.merkle_root.write(writer)?;
        writer.write_all(&self.timestamp.to_le_bytes())?;
        writer.write_all(&self.bits.to_le_bytes())?;
        writer.write_all(&self.nonce.to_le_bytes())?;
        Ok(())
    }
}

#[cfg(feature = "async")]
impl AsyncSerializable<BlockHeader> for BlockHeader {
    async fn read_async(reader: &mut dyn AsyncRead) -> Result<BlockHeader> {
        let mut version = [0u8; 4];
        reader.read_exact(&mut version).await.map_err(|e| Error::IOError(e))?;
        let version = u32::from_le_bytes(version);
        let prev_hash = Hash256::read_async(reader).await?;
        let merkle_root = Hash256::read_async(reader).await?;
        let mut timestamp = [0u8; 4];
        reader.read_exact(&mut timestamp).await.map_err(|e| Error::IOError(e))?;
        let timestamp = u32::from_le_bytes(timestamp);
        let mut bits = [0u8; 4];
        reader.read_exact(&mut bits).await.map_err(|e| Error::IOError(e))?;
        let bits = u32::from_le_bytes(bits);
        let mut nonce = [0u8; 4];
        reader.read_exact(&mut nonce).await.map_err(|e| Error::IOError(e))?;
        let nonce = u32::from_le_bytes(nonce);
        Ok(BlockHeader {
            version,
            prev_hash,
            merkle_root,
            timestamp,
            bits,
            nonce,
        })
    }

    async fn write_async(&self, writer: &mut dyn AsyncWrite) -> io::Result<()> {
        writer.write_all(&self.version.to_le_bytes()).await?;
        self.prev_hash.write_async(writer).await?;
        self.merkle_root.write_async(writer).await?;
        writer.write_all(&self.timestamp.to_le_bytes()).await?;
        writer.write_all(&self.bits.to_le_bytes()).await?;
        writer.write_all(&self.nonce.to_le_bytes()).await?;
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
        let block_header = BlockHeader {
            version: 12345,
            prev_hash: Hash256::decode(
                "7766009988776600998877660099887766009988776600998877660099887766",
            )
            .unwrap(),
            merkle_root: Hash256::decode(
                "2211554433221155443322115544332211554433221155443322115544332211",
            )
            .unwrap(),
            timestamp: 66,
            bits: 4488,
            nonce: 9999,
        };
        block_header.write(&mut v).unwrap();
        assert_eq!(v.len(), block_header.size());
        assert_eq!(BlockHeader::read(&mut Cursor::new(&v)).unwrap(), block_header);
    }

    #[test]
    fn hash() {
        let block_header = BlockHeader {
            version: 0x00000001,
            prev_hash: Hash256::decode(
                "00000000000008a3a41b85b8b29ad444def299fee21793cd8b9e567eab02cd81",
            )
            .unwrap(),
            merkle_root: Hash256::decode(
                "2b12fcf1b09288fcaff797d71e950e71ae42b91e8bdb2304758dfcffc2b620e3",
            )
            .unwrap(),
            timestamp: 0x4dd7f5c7,
            bits: 0x1a44b9f2,
            nonce: 0x9546a142,
        };
        let str_hash = block_header.hash().encode();
        let expected_hash = "00000000000000001e8d6829a8a21adc5d38d0a473b144b6765798e61f98bd1d";
        assert_eq!(str_hash, expected_hash);
    }

    #[test]
    fn validate() {
        let prev_hash =
            Hash256::decode("00000000000008a3a41b85b8b29ad444def299fee21793cd8b9e567eab02cd81")
                .unwrap();
        let mut headers = Vec::with_capacity(11);
        for i in 0..11 {
            headers.push(BlockHeader {
                timestamp: i * 10,
                ..Default::default()
            });
        }

        let valid = BlockHeader {
            version: 0x00000001,
            prev_hash,
            merkle_root: Hash256::decode(
                "2b12fcf1b09288fcaff797d71e950e71ae42b91e8bdb2304758dfcffc2b620e3",
            )
            .unwrap(),
            timestamp: 0x4dd7f5c7,
            bits: 0x1a44b9f2,
            nonce: 0x9546a142,
        };
        assert!(valid.validate(&valid.hash(), &headers).is_ok());

        let h = valid.clone();
        for header in headers.iter_mut() {
            header.timestamp = valid.timestamp + 1;
        }
        assert_eq!(
        header.validate().unwrap_err().to_string(),
        "Bad data: Timestamp too old: 1305998791"
        );

        let mut h = valid.clone();
        h.nonce = 0;
        assert_eq!(h.validate(&h.hash(), &headers).unwrap_err().to_string(), "Bad data: Invalid POW");
    }
}

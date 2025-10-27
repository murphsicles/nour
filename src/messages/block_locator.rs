//! Block locator for Bitcoin SV P2P GetBlocks/GetHeaders messages.

use crate::messages::message::Payload;
use crate::messages::version::MIN_SUPPORTED_PROTOCOL_VERSION;
use crate::util::{var_int, Error, Hash256, Result, Serializable};
use std::io;
use std::io::{Read, Write};

#[cfg(feature = "async")]
use tokio::io::{AsyncRead, AsyncWrite};

/// Hash to stop at none (all zeros).
pub const NO_HASH_STOP: Hash256 = Hash256([0; 32]);

/// Maximum number of block locator hashes (per GetHeaders/GetBlocks limits).
const MAX_BLOCK_LOCATOR_HASHES: u64 = 32000;

/// Specifies which blocks to return.
#[derive(Debug, Default, PartialEq, Eq, Hash, Clone)]
pub struct BlockLocator {
    /// Protocol version of this node.
    pub version: u32,
    /// Block hashes to start after (first found used).
    pub block_locator_hashes: Vec<Hash256>,
    /// Block hash to stop at (or NO_HASH_STOP).
    pub hash_stop: Hash256,
}

impl BlockLocator {
    /// Checks if the message is valid.
    ///
    /// # Errors
    /// `Error::BadData` if version < MIN_SUPPORTED_PROTOCOL_VERSION.
    pub fn validate(&self) -> Result<()> {
        if self.version < MIN_SUPPORTED_PROTOCOL_VERSION as u32 {
            return Err(Error::BadData(format!("Unsupported protocol version: {}", self.version)));
        }
        if self.block_locator_hashes.len() as u64 > MAX_BLOCK_LOCATOR_HASHES {
            return Err(Error::BadData(format!("Too many hashes: {}", self.block_locator_hashes.len())));
        }
        Ok(())
    }
}

impl Serializable<BlockLocator> for BlockLocator {
    fn read(reader: &mut dyn Read) -> Result<BlockLocator> {
        let mut version = [0u8; 4];
        reader.read_exact(&mut version).map_err(|e| Error::IOError(e))?;
        let version = u32::from_le_bytes(version);
        let num_hashes = var_int::read(reader)?;
        if num_hashes > MAX_BLOCK_LOCATOR_HASHES {
            return Err(Error::BadData(format!("Too many hashes: {}", num_hashes)));
        }
        let mut block_locator_hashes = Vec::with_capacity(num_hashes as usize);
        for _ in 0..num_hashes {
            block_locator_hashes.push(Hash256::read(reader)?);
        }
        let hash_stop = Hash256::read(reader)?;
        Ok(BlockLocator {
            version,
            block_locator_hashes,
            hash_stop,
        })
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        writer.write_all(&self.version.to_le_bytes())?;
        var_int::write(self.block_locator_hashes.len() as u64, writer)?;
        for hash in &self.block_locator_hashes {
            hash.write(writer)?;
        }
        self.hash_stop.write(writer)?;
        Ok(())
    }
}

#[cfg(feature = "async")]
impl AsyncSerializable<BlockLocator> for BlockLocator {
    async fn read_async(reader: &mut dyn AsyncRead) -> Result<BlockLocator> {
        let mut version = [0u8; 4];
        reader.read_exact(&mut version).await.map_err(|e| Error::IOError(e))?;
        let version = u32::from_le_bytes(version);
        let num_hashes = var_int::read_async(reader).await?;
        if num_hashes > MAX_BLOCK_LOCATOR_HASHES {
            return Err(Error::BadData(format!("Too many hashes: {}", num_hashes)));
        }
        let mut block_locator_hashes = Vec::with_capacity(num_hashes as usize);
        for _ in 0..num_hashes {
            block_locator_hashes.push(Hash256::read_async(reader).await?);
        }
        let hash_stop = Hash256::read_async(reader).await?;
        Ok(BlockLocator {
            version,
            block_locator_hashes,
            hash_stop,
        })
    }

    async fn write_async(&self, writer: &mut dyn AsyncWrite) -> io::Result<()> {
        writer.write_all(&self.version.to_le_bytes()).await?;
        var_int::write_async(self.block_locator_hashes.len() as u64, writer).await?;
        for hash in &self.block_locator_hashes {
            hash.write_async(writer).await?;
        }
        self.hash_stop.write_async(writer).await?;
        Ok(())
    }
}

impl Payload<BlockLocator> for BlockLocator {
    fn size(&self) -> usize {
        4 + var_int::size(self.block_locator_hashes.len() as u64) + self.block_locator_hashes.len() * 32 + 32
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
        let p = BlockLocator {
            version: 12345,
            block_locator_hashes: vec![
                NO_HASH_STOP,
                Hash256::decode("6677889900667788990066778899006677889900667788990066778899006677")
                    .unwrap(),
            ],
            hash_stop: Hash256::decode(
                "1122334455112233445511223344551122334455112233445511223344551122",
            )
            .unwrap(),
        };
        p.write(&mut v).unwrap();
        assert_eq!(v.len(), p.size());
        assert_eq!(BlockLocator::read(&mut Cursor::new(&v)).unwrap(), p);
    }

    #[test]
    fn validate() {
        let p = BlockLocator {
            version: MIN_SUPPORTED_PROTOCOL_VERSION as u32,
            block_locator_hashes: vec![NO_HASH_STOP; 500],
            hash_stop: NO_HASH_STOP,
        };
        assert!(p.validate().is_ok());

        let mut p = p.clone();
        p.version = MIN_SUPPORTED_PROTOCOL_VERSION as u32 - 1;
        assert_eq!(p.validate().unwrap_err().to_string(), format!("Bad data: Unsupported protocol version: {}", p.version));

        let mut p = p.clone();
        p.version = MIN_SUPPORTED_PROTOCOL_VERSION as u32;
        p.block_locator_hashes = vec![NO_HASH_STOP; MAX_BLOCK_LOCATOR_HASHES as usize + 1];
        assert_eq!(p.validate().unwrap_err().to_string(), format!("Bad data: Too many hashes: {}", p.block_locator_hashes.len()));
    }
}

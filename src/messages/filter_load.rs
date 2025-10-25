//! FilterLoad message for Bitcoin SV P2P, setting bloom filters (BIP-37).
use crate::messages::message::Payload;
use crate::util::{var_int, BloomFilter, Error, Result, Serializable};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io;
use std::io::{Read, Write};
#[cfg(feature = "async")]
use tokio::io::{AsyncRead, AsyncWrite};
/// Filter is not adjusted when a match is found.
pub const BLOOM_UPDATE_NONE: u8 = 0;
/// Filter is updated to include the serialized outpoint if any data elements matched in its script pubkey.
pub const BLOOM_UPDATE_ALL: u8 = 1;
/// Filter is updated similar to BLOOM_UPDATE_ALL but only for P2PK or multisig transactions.
pub const BLOOM_UPDATE_P2PUBKEY_ONLY: u8 = 2;
/// Loads a bloom filter using the specified parameters.
#[derive(Default, Debug, PartialEq, Eq, Hash, Clone)]
pub struct FilterLoad {
    /// Bloom filter.
    pub bloom_filter: BloomFilter,
    /// Flags controlling how matched items are added to the filter (0-2).
    pub flags: u8,
}
impl FilterLoad {
    /// Returns whether the FilterLoad message is valid.
    ///
    /// # Errors
    /// `Error::BadData` if bloom filter invalid (size > 36000, funcs > 50) or flags > 2.
    pub fn validate(&self) -> Result<()> {
        self.bloom_filter.validate()?;
        if self.flags > BLOOM_UPDATE_P2PUBKEY_ONLY {
            return Err(Error::BadData(format!("Invalid flags: {}", self.flags)));
        }
        Ok(())
    }
}
impl Serializable<FilterLoad> for FilterLoad {
    fn read(reader: &mut dyn Read) -> Result<FilterLoad> {
        let num_filters = var_int::read(reader)?;
        let mut filter = vec![0; num_filters as usize];
        reader.read_exact(&mut filter).map_err(|e| Error::IOError(e))?;
        let mut num_hash_funcs = [0u8; 4];
        reader.read_exact(&mut num_hash_funcs).map_err(|e| Error::IOError(e))?;
        let num_hash_funcs = u32::from_le_bytes(num_hash_funcs) as usize;
        let mut tweak = [0u8; 4];
        reader.read_exact(&mut tweak).map_err(|e| Error::IOError(e))?;
        let tweak = u32::from_le_bytes(tweak);
        let flags = reader.read_u8().map_err(|e| Error::IOError(e))?;
        Ok(FilterLoad {
            bloom_filter: BloomFilter {
                filter,
                num_hash_funcs,
                tweak,
            },
            flags,
        })
    }
    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        var_int::write(self.bloom_filter.filter.len() as u64, writer)?;
        writer.write_all(&self.bloom_filter.filter)?;
        writer.write_all(&(self.bloom_filter.num_hash_funcs as u32).to_le_bytes())?;
        writer.write_all(&self.bloom_filter.tweak.to_le_bytes())?;
        writer.write_u8(self.flags)?;
        Ok(())
    }
}
#[cfg(feature = "async")]
impl AsyncSerializable<FilterLoad> for FilterLoad {
    async fn read_async(reader: &mut dyn AsyncRead) -> Result<FilterLoad> {
        let num_filters = var_int::read_async(reader).await?;
        let mut filter = vec![0; num_filters as usize];
        reader.read_exact(&mut filter).await.map_err(|e| Error::IOError(e))?;
        let mut num_hash_funcs = [0u8; 4];
        reader.read_exact(&mut num_hash_funcs).await.map_err(|e| Error::IOError(e))?;
        let num_hash_funcs = u32::from_le_bytes(num_hash_funcs) as usize;
        let mut tweak = [0u8; 4];
        reader.read_exact(&mut tweak).await.map_err(|e| Error::IOError(e))?;
        let tweak = u32::from_le_bytes(tweak);
        let flags = reader.read_u8().await.map_err(|e| Error::IOError(e))?;
        Ok(FilterLoad {
            bloom_filter: BloomFilter {
                filter,
                num_hash_funcs,
                tweak,
            },
            flags,
        })
    }
    async fn write_async(&self, writer: &mut dyn AsyncWrite) -> io::Result<()> {
        var_int::write_async(self.bloom_filter.filter.len() as u64, writer).await?;
        writer.write_all(&self.bloom_filter.filter).await?;
        writer.write_all(&(self.bloom_filter.num_hash_funcs as u32).to_le_bytes()).await?;
        writer.write_all(&self.bloom_filter.tweak.to_le_bytes()).await?;
        writer.write_u8(self.flags).await?;
        Ok(())
    }
}
impl Payload<FilterLoad> for FilterLoad {
    fn size(&self) -> usize {
        var_int::size(self.bloom_filter.filter.len() as u64) + self.bloom_filter.filter.len() + 9
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
        let b = hex::decode("02b50f0b0000000000000001").unwrap();
        let f = FilterLoad::read(&mut Cursor::new(&b)).unwrap();
        assert_eq!(f.bloom_filter.filter, vec![0xb5, 0x0f]);
        assert_eq!(f.bloom_filter.num_hash_funcs, 11);
        assert_eq!(f.bloom_filter.tweak, 0);
        assert_eq!(f.flags, BLOOM_UPDATE_ALL);
    }
    #[test]
    fn write_read() {
        let mut v = Vec::new();
        let p = FilterLoad {
            bloom_filter: BloomFilter {
                filter: vec![0, 1, 2, 3, 4, 5],
                num_hash_funcs: 3,
                tweak: 100,
            },
            flags: 1,
        };
        p.write(&mut v).unwrap();
        assert_eq!(v.len(), p.size());
        assert_eq!(FilterLoad::read(&mut Cursor::new(&v)).unwrap(), p);
    }
    #[test]
    fn validate() {
        let p = FilterLoad {
            bloom_filter: BloomFilter {
                filter: vec![0; 1000],
                num_hash_funcs: 10,
                tweak: 100,
            },
            flags: BLOOM_UPDATE_ALL,
        };
        assert!(p.validate().is_ok());
        let p = FilterLoad {
            bloom_filter: BloomFilter {
                filter: vec![0; 36001], // Exceeds max
                num_hash_funcs: 10,
                tweak: 100,
            },
            flags: BLOOM_UPDATE_ALL,
        };
        assert_eq!(p.validate().unwrap_err().to_string(), "Filter too long");
        let p = FilterLoad {
            bloom_filter: BloomFilter {
                filter: vec![0; 1000],
                num_hash_funcs: 51, // Exceeds max
                tweak: 100,
            },
            flags: BLOOM_UPDATE_ALL,
        };
        assert_eq!(p.validate().unwrap_err().to_string(), "Too many hash funcs");
        let p = FilterLoad {
            bloom_filter: BloomFilter {
                filter: vec![0; 1000],
                num_hash_funcs: 10,
                tweak: 100,
            },
            flags: 3, // Invalid flags
        };
        assert_eq!(p.validate().unwrap_err().to_string(), "Invalid flags: 3");
    }
}

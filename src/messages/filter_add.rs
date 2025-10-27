//! FilterAdd message for Bitcoin SV P2P, adding data to bloom filters (BIP-37).

use crate::messages::message::Payload;
use crate::util::{var_int, Error, Result, Serializable};
use hex;
use std::fmt;
use std::io;
use std::io::{Read, Write};

#[cfg(feature = "async")]
use tokio::io::{AsyncRead, AsyncWrite};

/// Maximum size of a data element in the FilterAdd message (520 bytes, BIP-37 standard, unchanged in BSV/Teranode).
pub const MAX_FILTER_ADD_DATA_SIZE: usize = 520;

/// Adds a data element to the bloom filter.
#[derive(Default, PartialEq, Eq, Hash, Clone)]
pub struct FilterAdd {
    /// Data element to be added.
    pub data: Vec<u8>,
}

impl FilterAdd {
    /// Returns whether the FilterAdd message is valid.
    ///
    /// # Errors
    /// `Error::BadData` if data > MAX_FILTER_ADD_DATA_SIZE.
    pub fn validate(&self) -> Result<()> {
        if self.data.len() > MAX_FILTER_ADD_DATA_SIZE {
            return Err(Error::BadData("Data too long".to_string()));
        }
        Ok(())
    }
}

impl Serializable<FilterAdd> for FilterAdd {
    fn read(reader: &mut dyn Read) -> Result<FilterAdd> {
        let data_len = var_int::read(reader)?;
        let mut data = vec![0; data_len as usize];
        reader.read_exact(&mut data).map_err(|e| Error::IOError(e))?;
        Ok(FilterAdd { data })
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        var_int::write(self.data.len() as u64, writer)?;
        writer.write_all(&self.data)
    }
}

#[cfg(feature = "async")]
impl AsyncSerializable<FilterAdd> for FilterAdd {
    async fn read_async(reader: &mut dyn AsyncRead) -> Result<FilterAdd> {
        let data_len = var_int::read_async(reader).await?;
        let mut data = vec![0; data_len as usize];
        reader.read_exact(&mut data).await.map_err(|e| Error::IOError(e))?;
        Ok(FilterAdd { data })
    }

    async fn write_async(&self, writer: &mut dyn AsyncWrite) -> io::Result<()> {
        var_int::write_async(self.data.len() as u64, writer).await?;
        writer.write_all(&self.data).await
    }
}

impl Payload<FilterAdd> for FilterAdd {
    fn size(&self) -> usize {
        var_int::size(self.data.len() as u64) + self.data.len()
    }
}

impl fmt::Debug for FilterAdd {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("FilterAdd")
            .field("data", &hex::encode(&self.data))
            .finish()
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
    let b = hex::decode("deadbeef").unwrap();
    let filter_add = FilterAdd::read(&mut Cursor::new(&b)).unwrap();
        assert_eq!(f.data.len(), 32);
    }

    #[test]
    fn write_read() {
        let mut v = Vec::new();
        let p = FilterAdd { data: vec![20; 20] };
        p.write(&mut v).unwrap();
        assert_eq!(v.len(), p.size());
        assert_eq!(FilterAdd::read(&mut Cursor::new(&v)).unwrap(), p);
    }

    #[test]
    fn validate() {
        let p = FilterAdd { data: vec![21; 21] };
        assert!(p.validate().is_ok());

        let p = FilterAdd { data: vec![21; MAX_FILTER_ADD_DATA_SIZE + 1] };
        assert_eq!(p.validate().unwrap_err().to_string(), "Bad data: Data too long");
    }
}

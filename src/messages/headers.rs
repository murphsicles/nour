//! Headers message for Bitcoin SV P2P, carrying block headers for chain sync.

use crate::messages::block_header::BlockHeader;
use crate::messages::message::Payload;
use crate::util::{var_int, Error, Hash256, Result, Serializable};
use byteorder::{ReadBytesExt, WriteBytesExt};
use std::fmt;
use std::io;
use std::io::{Read, Write};

#[cfg(feature = "async")]
use tokio::io::{AsyncRead, AsyncWrite};

/// Maximum number of headers in Headers message (per GetHeaders limit).
const MAX_HEADERS: u64 = 32000;

/// Collection of block headers.
#[derive(Default, PartialEq, Eq, Hash, Clone)]
pub struct Headers {
    /// List of sequential block headers.
    pub headers: Vec<BlockHeader>,
}

impl Serializable<Headers> for Headers {
    fn read(reader: &mut dyn Read) -> Result<Headers> {
        let n = var_int::read(reader)?;
        if n > MAX_HEADERS {
            return Err(Error::BadData(format!("Too many headers: {}", n)));
        }
        let mut headers = Vec::with_capacity(n as usize);
        for _ in 0..n {
            headers.push(BlockHeader::read(reader)?);
            let txn_count = reader.read_u8().map_err(|e| Error::IOError(e))?;
            if txn_count != 0 {
                return Err(Error::BadData("Non-zero tx count in header".to_string()));
            }
        }
        Ok(Headers { headers })
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        var_int::write(self.headers.len() as u64, writer)?;
        for header in &self.headers {
            header.write(writer)?;
            writer.write_u8(0)?;
        }
        Ok(())
    }
}

#[cfg(feature = "async")]
impl AsyncSerializable<Headers> for Headers {
    async fn read_async(reader: &mut dyn AsyncRead) -> Result<Headers> {
        let n = var_int::read_async(reader).await?;
        if n > MAX_HEADERS {
            return Err(Error::BadData(format!("Too many headers: {}", n)));
        }
        let mut headers = Vec::with_capacity(n as usize);
        for _ in 0..n {
            headers.push(BlockHeader::read_async(reader).await?);
            let txn_count = reader.read_u8().await.map_err(|e| Error::IOError(e))?;
            if txn_count != 0 {
                return Err(Error::BadData("Non-zero tx count in header".to_string()));
            }
        }
        Ok(Headers { headers })
    }

    async fn write_async(&self, writer: &mut dyn AsyncWrite) -> io::Result<()> {
        var_int::write_async(self.headers.len() as u64, writer).await?;
        for header in &self.headers {
            header.write_async(writer).await?;
            writer.write_u8(0).await?;
        }
        Ok(())
    }
}

impl Payload<Headers> for Headers {
    fn size(&self) -> usize {
        var_int::size(self.headers.len() as u64) + (BlockHeader::SIZE + 1) * self.headers.len()
    }
}

impl fmt::Debug for Headers {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let h = format!("[<{} block headers>]", self.headers.len());
        f.debug_struct("Headers").field("headers", &h).finish()
    }
}

/// Returns the hash for a header at a particular index utilizing prev_hash if possible.
///
/// # Errors
/// `Error::BadArgument` if index out of range.
pub fn header_hash(i: usize, headers: &[BlockHeader]) -> Result<Hash256> {
    if i + 1 < headers.len() {
        Ok(headers[i + 1].prev_hash)
    } else if i + 1 == headers.len() {
        Ok(headers[i].hash())
    } else {
        Err(Error::BadArgument("Index out of range".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::Hash256;
    use std::io::Cursor;
    use pretty_assertions::assert_eq;

    #[test]
    fn write_read() {
        let mut v = Vec::new();
        let p = Headers {
            headers: vec![
                BlockHeader {
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
                },
                BlockHeader {
                    version: 67890,
                    prev_hash: Hash256::decode(
                        "1122334455112233445511223344551122334455112233445511223344551122",
                    )
                    .unwrap(),
                    merkle_root: Hash256::decode(
                        "6677889900667788990066778899006677889900667788990066778899006677",
                    )
                    .unwrap(),
                    timestamp: 77,
                    bits: 5599,
                    nonce: 1111,
                },
            ],
        };
        p.write(&mut v).unwrap();
        assert_eq!(v.len(), p.size());
        assert_eq!(Headers::read(&mut Cursor::new(&v)).unwrap(), p);
    }

    #[test]
    fn header_hash_test() {
        let header1 = BlockHeader {
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

        let header2 = BlockHeader {
            version: 67890,
            prev_hash: header1.hash(),
            merkle_root: Hash256::decode(
                "6677889900667788990066778899006677889900667788990066778899006677",
            )
            .unwrap(),
            timestamp: 77,
            bits: 5599,
            nonce: 1111,
        };

        assert_eq!(header_hash(0, &vec![]).unwrap_err().to_string(), "Index out of range");

        let headers = vec![header1.clone()];
        assert_eq!(header_hash(0, &headers).unwrap(), header1.hash());
        assert_eq!(header_hash(1, &headers).unwrap_err().to_string(), "Index out of range");

        let headers = vec![header1.clone(), header2.clone()];
        assert_eq!(header_hash(0, &headers).unwrap(), header1.hash());
        assert_eq!(header_hash(1, &headers).unwrap(), header2.hash());
        assert_eq!(header_hash(2, &headers).unwrap_err().to_string(), "Index out of range");
    }
}

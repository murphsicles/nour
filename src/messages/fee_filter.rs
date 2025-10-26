//! FeeFilter message for Bitcoin SV P2P, signaling minimum transaction fee.
use crate::messages::message::Payload;
use crate::util::{Error, Result, Serializable};
use byteorder::WriteBytesExt;
use std::io;
use std::io::{Read, Write};
#[cfg(feature = "async")]
use tokio::io::{AsyncRead, AsyncWrite};
/// Specifies the minimum transaction fee this node accepts.
///
/// Typically 1 sat/1000 bytes (0.001 sats/byte) on standard BSV nodes, or as low as
/// 0.0001 sats/1000 bytes (0.0000001 sats/byte) with Galaxy or Teranode for high-throughput apps.
#[derive(Debug, Default, PartialEq, Eq, Hash, Clone)]
pub struct FeeFilter {
    /// Minimum fee accepted by the node in satoshis per 1000 bytes.
    pub minfee: u64,
}
impl FeeFilter {
    /// Size of the fee filter payload in bytes (8).
    pub const SIZE: usize = 8;
}
impl Serializable<FeeFilter> for FeeFilter {
    fn read(reader: &mut dyn Read) -> Result<FeeFilter> {
        let mut minfee = [0u8; 8];
        reader.read_exact(&mut minfee).map_err(|e| Error::IOError(e))?;
        Ok(FeeFilter {
            minfee: u64::from_le_bytes(minfee),
        })
    }
    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        writer.write_all(&self.minfee.to_le_bytes())
    }
}
#[cfg(feature = "async")]
impl AsyncSerializable<FeeFilter> for FeeFilter {
    async fn read_async(reader: &mut dyn AsyncRead) -> Result<FeeFilter> {
        let mut minfee = [0u8; 8];
        reader.read_exact(&mut minfee).await.map_err(|e| Error::IOError(e))?;
        Ok(FeeFilter {
            minfee: u64::from_le_bytes(minfee),
        })
    }
    async fn write_async(&self, writer: &mut dyn AsyncWrite) -> io::Result<()> {
        writer.write_all(&self.minfee.to_le_bytes()).await
    }
}
impl Payload<FeeFilter> for FeeFilter {
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
        let b = hex::decode("e803000000000000").unwrap();
        let f = FeeFilter::read(&mut Cursor::new(&b)).unwrap();
        assert_eq!(f.minfee, 1000);
    }
    #[test]
    fn write_read() {
        let mut v = Vec::new();
        let f = FeeFilter { minfee: 1234 };
        f.write(&mut v).unwrap();
        assert_eq!(v.len(), f.size());
        assert_eq!(FeeFilter::read(&mut Cursor::new(&v)).unwrap(), f);
    }
}

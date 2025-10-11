//! Extended network address for Bitcoin SV P2P node discovery.

use crate::messages::node_addr::NodeAddr;
use crate::util::{Result, Serializable};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io;
use std::io::{Read, Write};

#[cfg(feature = "async")]
use tokio::io::{AsyncRead, AsyncWrite};

/// Node network address extended with a last connected time.
#[derive(Debug, Default, PartialEq, Eq, Hash, Clone)]
pub struct NodeAddrEx {
    /// Last connected time in seconds since the Unix epoch.
    pub last_connected_time: u32,
    /// Node address.
    pub addr: NodeAddr,
}

impl NodeAddrEx {
    /// Size of the NodeAddrEx in bytes (4 + NodeAddr::SIZE = 30).
    pub const SIZE: usize = NodeAddr::SIZE + 4;

    /// Returns the size of the address in bytes.
    #[must_use]
    #[inline]
    pub fn size(&self) -> usize {
        Self::SIZE
    }
}

impl Serializable<NodeAddrEx> for NodeAddrEx {
    fn read(reader: &mut dyn Read) -> Result<NodeAddrEx> {
        let mut time = [0u8; 4];
        reader.read_exact(&mut time).map_err(|e| Error::IOError(e))?;
        let last_connected_time = u32::from_le_bytes(time);
        let addr = NodeAddr::read(reader)?;
        Ok(NodeAddrEx { last_connected_time, addr })
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        writer.write_all(&self.last_connected_time.to_le_bytes())?;
        self.addr.write(writer)?;
        Ok(())
    }
}

#[cfg(feature = "async")]
impl AsyncSerializable<NodeAddrEx> for NodeAddrEx {
    async fn read_async(reader: &mut dyn AsyncRead) -> Result<NodeAddrEx> {
        let mut time = [0u8; 4];
        reader.read_exact(&mut time).await.map_err(|e| Error::IOError(e))?;
        let last_connected_time = u32::from_le_bytes(time);
        let addr = NodeAddr::read_async(reader).await?;
        Ok(NodeAddrEx { last_connected_time, addr })
    }

    async fn write_async(&self, writer: &mut dyn AsyncWrite) -> io::Result<()> {
        writer.write_all(&self.last_connected_time.to_le_bytes()).await?;
        self.addr.write_async(writer).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::net::Ipv6Addr;
    use pretty_assertions::assert_eq;

    #[test]
    fn write_read() {
        let mut v = Vec::new();
        let a = NodeAddrEx {
            last_connected_time: 12345,
            addr: NodeAddr {
                services: 1,
                ip: Ipv6Addr::from([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
                port: 123,
            },
        };
        a.write(&mut v).unwrap();
        assert_eq!(v.len(), a.size());
        assert_eq!(NodeAddrEx::read(&mut Cursor::new(&v)).unwrap(), a);
    }
}

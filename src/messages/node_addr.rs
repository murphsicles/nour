//! Network address for Bitcoin SV P2P node discovery.

use crate::util::{Result, Serializable};
use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv6Addr};

#[cfg(feature = "async")]
use tokio::io::{AsyncRead, AsyncWrite};

/// Network address for a node on the network.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct NodeAddr {
    /// Services flags for the node (e.g., NODE_NETWORK).
    pub services: u64,
    /// IPv6 address for the node (IPv4 mapped as ::ffff:a.b.c.d).
    pub ip: Ipv6Addr,
    /// Port for Bitcoin P2P communication.
    pub port: u16,
}

impl NodeAddr {
    /// Size of the NodeAddr in bytes (8+16+2).
    pub const SIZE: usize = 26;

    /// Creates a NodeAddr from an IP address and port.
    #[must_use]
    #[inline]
    pub fn new(ip: IpAddr, port: u16) -> Self {
        Self {
            services: 0,
            ip: match ip {
                IpAddr::V4(ipv4) => ipv4.to_ipv6_mapped(),
                IpAddr::V6(ipv6) => ipv6,
            },
            port,
        }
    }

    /// Returns the size of the address in bytes.
    #[must_use]
    #[inline]
    pub fn size(&self) -> usize {
        Self::SIZE
    }
}

impl Serializable<NodeAddr> for NodeAddr {
    fn read(reader: &mut dyn Read) -> Result<NodeAddr> {
        let services = reader.read_u64::<LittleEndian>().map_err(|e| Error::IOError(e))?;
        let mut ip = [0; 16];
        reader.read_exact(&mut ip).map_err(|e| Error::IOError(e))?;
        let ip = Ipv6Addr::from(ip);
        let port = reader.read_u16::<BigEndian>().map_err(|e| Error::IOError(e))?;
        Ok(NodeAddr { services, ip, port })
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        writer.write_u64::<LittleEndian>(self.services)?;
        writer.write_all(&self.ip.octets())?;
        writer.write_u16::<BigEndian>(self.port)?;
        Ok(())
    }
}

#[cfg(feature = "async")]
impl AsyncSerializable<NodeAddr> for NodeAddr {
    async fn read_async(reader: &mut dyn AsyncRead) -> Result<NodeAddr> {
        let services = reader.read_u64_le().await.map_err(|e| Error::IOError(e))?;
        let mut ip = [0; 16];
        reader.read_exact(&mut ip).await.map_err(|e| Error::IOError(e))?;
        let ip = Ipv6Addr::from(ip);
        let port = reader.read_u16_be().await.map_err(|e| Error::IOError(e))?;
        Ok(NodeAddr { services, ip, port })
    }

    async fn write_async(&self, writer: &mut dyn AsyncWrite) -> io::Result<()> {
        writer.write_u64_le(self.services).await?;
        writer.write_all(&self.ip.octets()).await?;
        writer.write_u16_be(self.port).await?;
        Ok(())
    }
}

impl Default for NodeAddr {
    fn default() -> Self {
        Self {
            services: 0,
            ip: Ipv6Addr::from([0; 16]),
            port: 0,
        }
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
        let b = hex::decode("250000000000000000000000000000000000ffff2d32bffbddd3").unwrap();
        let a = NodeAddr::read(&mut Cursor::new(&b)).unwrap();
        assert_eq!(a.services, 37);
        assert_eq!(a.ip.octets(), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 45, 50, 191, 251]);
        assert_eq!(a.port, 56787);
    }

    #[test]
    fn write_read() {
        let mut v = Vec::new();
        let a = NodeAddr {
            services: 1,
            ip: Ipv6Addr::from([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
            port: 123,
        };
        a.write(&mut v).unwrap();
        assert_eq!(v.len(), a.size());
        assert_eq!(NodeAddr::read(&mut Cursor::new(&v)).unwrap(), a);
    }
}

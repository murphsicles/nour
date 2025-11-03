//! Addr message for Bitcoin SV P2P, sharing known node addresses.

use crate::messages::message::Payload;
use crate::messages::node_addr_ex::NodeAddrEx;
use crate::util::{Error, Result, Serializable, var_int};
use std::fmt;
use std::io;
use std::io::{Read, Write};

#[cfg(feature = "async")]
use tokio::io::{AsyncRead, AsyncWrite};

/// Maximum number of addresses allowed in an Addr message.
const MAX_ADDR_COUNT: u64 = 1000;

/// Known node addresses.
#[derive(Default, PartialEq, Eq, Hash, Clone)]
pub struct Addr {
    /// List of addresses of known nodes.
    pub addrs: Vec<NodeAddrEx>,
}

impl Serializable<Addr> for Addr {
    fn read(reader: &mut dyn Read) -> Result<Addr> {
        let count = var_int::read(reader)?;
        if count > MAX_ADDR_COUNT {
            return Err(Error::BadData(format!("Too many addrs: {}", count)));
        }
        let mut addrs = Vec::with_capacity(count as usize);
        for _ in 0..count {
            addrs.push(NodeAddrEx::read(reader)?);
        }
        Ok(Addr { addrs })
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        var_int::write(self.addrs.len() as u64, writer)?;
        for item in &self.addrs {
            item.write(writer)?;
        }
        Ok(())
    }
}

#[cfg(feature = "async")]
impl AsyncSerializable<Addr> for Addr {
    async fn read_async(reader: &mut dyn AsyncRead) -> Result<Addr> {
        let count = var_int::read_async(reader).await?;
        if count > MAX_ADDR_COUNT {
            return Err(Error::BadData(format!("Too many addrs: {}", count)));
        }
        let mut addrs = Vec::with_capacity(count as usize);
        for _ in 0..count {
            addrs.push(NodeAddrEx::read_async(reader).await?);
        }
        Ok(Addr { addrs })
    }

    async fn write_async(&self, writer: &mut dyn AsyncWrite) -> io::Result<()> {
        var_int::write_async(self.addrs.len() as u64, writer).await?;
        for item in &self.addrs {
            item.write_async(writer).await?;
        }
        Ok(())
    }
}

impl Payload<Addr> for Addr {
    fn size(&self) -> usize {
        var_int::size(self.addrs.len() as u64) + self.addrs.len() * NodeAddrEx::SIZE
    }
}

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.addrs.len() <= 3 {
            f.debug_struct("Addr").field("addrs", &self.addrs).finish()
        } else {
            f.debug_struct("Addr")
                .field("addrs", &format!("[<{} addrs>]", self.addrs.len()))
                .finish()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::NodeAddr;
    use hex;
    use pretty_assertions::assert_eq;
    use std::io::Cursor;
    use std::net::Ipv6Addr;

    #[test]
    fn read_bytes() {
        let b =
            hex::decode("013c93dd5a250000000000000000000000000000000000ffff43cdb3a1479d").unwrap();
        let a = Addr::read(&mut Cursor::new(&b)).unwrap();
        assert_eq!(a.addrs.len(), 1);
        assert_eq!(a.addrs[0].last_connected_time, 1524470588);
        assert_eq!(a.addrs[0].addr.services, 37);
        let ip = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 67, 205, 179, 161];
        assert_eq!(a.addrs[0].addr.ip.octets(), ip);
        assert_eq!(a.addrs[0].addr.port, 18333);
    }

    #[test]
    fn write_read() {
        let mut v = Vec::new();
        let addr1 = NodeAddrEx {
            last_connected_time: 100,
            addr: NodeAddr {
                services: 900,
                ip: Ipv6Addr::from([1; 16]),
                port: 2000,
            },
        };
        let addr2 = NodeAddrEx {
            last_connected_time: 200,
            addr: NodeAddr {
                services: 800,
                ip: Ipv6Addr::from([2; 16]),
                port: 3000,
            },
        };
        let addr3 = NodeAddrEx {
            last_connected_time: 700,
            addr: NodeAddr {
                services: 900,
                ip: Ipv6Addr::from([3; 16]),
                port: 4000,
            },
        };
        let f = Addr {
            addrs: vec![addr1, addr2, addr3],
        };
        f.write(&mut v).unwrap();
        assert_eq!(v.len(), f.size());
        assert_eq!(Addr::read(&mut Cursor::new(&v)).unwrap(), f);
    }
}

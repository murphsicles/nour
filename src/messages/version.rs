//! Version message for Bitcoin SV P2P handshake, defining node capabilities.

use crate::messages::message::Payload;
use crate::messages::node_addr::NodeAddr;
use crate::util::{secs_since, var_int, Error, Result, Serializable};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io;
use std::io::{Read, Write};
use std::time::UNIX_EPOCH;

#[cfg(feature = "async")]
use tokio::io::{AsyncRead, AsyncWrite};

/// Protocol version supported by this library (BSV standard).
pub const PROTOCOL_VERSION: u32 = 70016;

/// Minimum protocol version supported by this library.
pub const MIN_SUPPORTED_PROTOCOL_VERSION: u32 = 70001;

/// Unknown IP address to use as a default (::ffff:127.0.0.1).
pub const UNKNOWN_IP: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 127, 0, 0, 1];

/// Service flag for SPV wallets (not full node).
pub const NODE_NONE: u64 = 0;

/// Service flag for full node with all protocol features.
pub const NODE_NETWORK: u64 = 1;

/// Service flag for BSV full node (post-fork).
pub const NODE_BITCOIN_CASH: u64 = 1 << 5;

/// Maximum user agent length (256 bytes, protocol limit).
const MAX_USER_AGENT_LEN: usize = 256;

/// Version payload defining a node's capabilities.
#[derive(Debug, Default, PartialEq, Eq, Hash, Clone)]
pub struct Version {
    /// The protocol version being used by the node.
    pub version: u32,
    /// Bitfield of features enabled for this connection.
    pub services: u64,
    /// Time since the Unix epoch in seconds.
    pub timestamp: i64,
    /// Network address of the node receiving this message.
    pub recv_addr: NodeAddr,
    /// Network address of the node emitting this message.
    pub tx_addr: NodeAddr,
    /// A random nonce to detect self-connection.
    pub nonce: u64,
    /// User agent string.
    pub user_agent: String,
    /// Height of the node's best block chain (or header chain for SPV).
    pub start_height: i32,
    /// Whether to receive broadcast transactions before filter set.
    pub relay: bool,
}

impl Version {
    /// Checks if the version message is valid.
    ///
    /// # Errors
    /// `Error::BadData` if version < MIN_SUPPORTED_PROTOCOL_VERSION or timestamp > ±2 hours.
    pub fn validate(&self) -> Result<()> {
        if self.version < MIN_SUPPORTED_PROTOCOL_VERSION {
            return Err(Error::BadData(format!("Unsupported protocol version: {}", self.version)));
        }
        let now = secs_since(UNIX_EPOCH) as i64;
        if (self.timestamp - now).abs() > 2 * 60 * 60 {
            return Err(Error::BadData(format!("Timestamp too old: {}", self.timestamp)));
        }
        if self.user_agent.len() > MAX_USER_AGENT_LEN {
            return Err(Error::BadData(format!("User agent too long: {}", self.user_agent.len())));
        }
        Ok(())
    }
}

impl Serializable<Version> for Version {
    fn read(reader: &mut dyn Read) -> Result<Version> {
        let mut version = [0u8; 4];
        reader.read_exact(&mut version).map_err(|e| Error::IOError(e))?;
        let version = u32::from_le_bytes(version);
        let mut services = [0u8; 8];
        reader.read_exact(&mut services).map_err(|e| Error::IOError(e))?;
        let services = u64::from_le_bytes(services);
        let mut timestamp = [0u8; 8];
        reader.read_exact(&mut timestamp).map_err(|e| Error::IOError(e))?;
        let timestamp = i64::from_le_bytes(timestamp);
        let recv_addr = NodeAddr::read(reader)?;
        let tx_addr = NodeAddr::read(reader)?;
        let mut nonce = [0u8; 8];
        reader.read_exact(&mut nonce).map_err(|e| Error::IOError(e))?;
        let nonce = u64::from_le_bytes(nonce);
        let user_agent_size = var_int::read(reader)? as usize;
        if user_agent_size > MAX_USER_AGENT_LEN {
            return Err(Error::BadData(format!("User agent too long: {}", user_agent_size)));
        }
        let mut user_agent_bytes = vec![0; user_agent_size];
        reader.read_exact(&mut user_agent_bytes).map_err(|e| Error::IOError(e))?;
        let user_agent = String::from_utf8(user_agent_bytes)
            .map_err(|_| Error::BadData("Invalid UTF8 user agent".to_string()))?;
        let mut start_height = [0u8; 4];
        reader.read_exact(&mut start_height).map_err(|e| Error::IOError(e))?;
        let start_height = i32::from_le_bytes(start_height);
        let relay = reader.read_u8().map_err(|e| Error::IOError(e))? == 0x01;
        let ret = Version {
            version,
            services,
            timestamp,
            recv_addr,
            tx_addr,
            nonce,
            user_agent,
            start_height,
            relay,
        };
        ret.validate()?;
        Ok(ret)
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        writer.write_all(&self.version.to_le_bytes())?;
        writer.write_all(&self.services.to_le_bytes())?;
        writer.write_all(&self.timestamp.to_le_bytes())?;
        self.recv_addr.write(writer)?;
        self.tx_addr.write(writer)?;
        writer.write_all(&self.nonce.to_le_bytes())?;
        var_int::write(self.user_agent.as_bytes().len() as u64, writer)?;
        writer.write_all(self.user_agent.as_bytes())?;
        writer.write_all(&self.start_height.to_le_bytes())?;
        writer.write_u8(if self.relay { 0x01 } else { 0x00 })?;
        Ok(())
    }
}

#[cfg(feature = "async")]
impl AsyncSerializable<Version> for Version {
    async fn read_async(reader: &mut dyn AsyncRead) -> Result<Version> {
        let mut version = [0u8; 4];
        reader.read_exact(&mut version).await.map_err(|e| Error::IOError(e))?;
        let version = u32::from_le_bytes(version);
        let mut services = [0u8; 8];
        reader.read_exact(&mut services).await.map_err(|e| Error::IOError(e))?;
        let services = u64::from_le_bytes(services);
        let mut timestamp = [0u8; 8];
        reader.read_exact(&mut timestamp).await.map_err(|e| Error::IOError(e))?;
        let timestamp = i64::from_le_bytes(timestamp);
        let recv_addr = NodeAddr::read_async(reader).await?;
        let tx_addr = NodeAddr::read_async(reader).await?;
        let mut nonce = [0u8; 8];
        reader.read_exact(&mut nonce).await.map_err(|e| Error::IOError(e))?;
        let nonce = u64::from_le_bytes(nonce);
        let user_agent_size = var_int::read_async(reader).await? as usize;
        if user_agent_size > MAX_USER_AGENT_LEN {
            return Err(Error::BadData(format!("User agent too long: {}", user_agent_size)));
        }
        let mut user_agent_bytes = vec![0; user_agent_size];
        reader.read_exact(&mut user_agent_bytes).await.map_err(|e| Error::IOError(e))?;
        let user_agent = String::from_utf8(user_agent_bytes)
            .map_err(|_| Error::BadData("Invalid UTF8 user agent".to_string()))?;
        let mut start_height = [0u8; 4];
        reader.read_exact(&mut start_height).await.map_err(|e| Error::IOError(e))?;
        let start_height = i32::from_le_bytes(start_height);
        let relay = reader.read_u8().await.map_err(|e| Error::IOError(e))? == 0x01;
        let ret = Version {
            version,
            services,
            timestamp,
            recv_addr,
            tx_addr,
            nonce,
            user_agent,
            start_height,
            relay,
        };
        ret.validate()?;
        Ok(ret)
    }

    async fn write_async(&self, writer: &mut dyn AsyncWrite) -> io::Result<()> {
        writer.write_all(&self.version.to_le_bytes()).await?;
        writer.write_all(&self.services.to_le_bytes()).await?;
        writer.write_all(&self.timestamp.to_le_bytes()).await?;
        self.recv_addr.write_async(writer).await?;
        self.tx_addr.write_async(writer).await?;
        writer.write_all(&self.nonce.to_le_bytes()).await?;
        var_int::write_async(self.user_agent.as_bytes().len() as u64, writer).await?;
        writer.write_all(self.user_agent.as_bytes()).await?;
        writer.write_all(&self.start_height.to_le_bytes()).await?;
        writer.write_u8(if self.relay { 0x01 } else { 0x00 }).await?;
        Ok(())
    }
}

impl Payload<Version> for Version {
    fn size(&self) -> usize {
        33 + self.recv_addr.size() + self.tx_addr.size() + var_int::size(self.user_agent.as_bytes().len() as u64) + self.user_agent.as_bytes().len()
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
        let b = hex::decode("7f1101002500000000000000f2d2d25a00000000000000000000000000000000000000000000ffff2d32bffbdd1725000000000000000000000000000000000000000000000000008d501d3bb5369deb242f426974636f696e204142433a302e31362e30284542382e303b20626974636f7265292f6606080001").unwrap();
        let v = Version::read(&mut Cursor::new(&b)).unwrap();
        assert_eq!(v.version, 70015);
        assert_eq!(v.services, 37);
        assert_eq!(v.timestamp, 1523766002);
        assert_eq!(v.recv_addr.services, 0);
        assert_eq!(v.recv_addr.ip.octets(), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 45, 50, 191, 251]);
        assert_eq!(v.recv_addr.port, 56599);
        assert_eq!(v.tx_addr.services, 37);
        assert_eq!(v.tx_addr.ip.octets(), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(v.tx_addr.port, 0);
        assert_eq!(v.nonce, 16977786322265395341);
        assert_eq!(v.user_agent, "/Bitcoin ABC:0.16.0(EB8.0; bitcore)/");
        assert_eq!(v.start_height, 525926);
        assert_eq!(v.relay, true);
    }

    #[test]
    fn write_read() {
        let mut v = Vec::new();
        let m = Version {
            version: MIN_SUPPORTED_PROTOCOL_VERSION,
            services: 77,
            timestamp: 1234,
            recv_addr: NodeAddr::default(),
            tx_addr: NodeAddr::default(),
            nonce: 99,
            user_agent: "dummy".to_string(),
            start_height: 22,
            relay: true,
        };
        m.write(&mut v).unwrap();
        assert_eq!(v.len(), m.size());
        assert_eq!(Version::read(&mut Cursor::new(&v)).unwrap(), m);
    }

    #[test]
    fn validate() {
        let m = Version {
            version: MIN_SUPPORTED_PROTOCOL_VERSION,
            services: 77,
            timestamp: secs_since(UNIX_EPOCH) as i64,
            recv_addr: NodeAddr::default(),
            tx_addr: NodeAddr::default(),
            nonce: 99,
            user_agent: "dummy".to_string(),
            start_height: 22,
            relay: true,
        };
        assert!(m.validate().is_ok());

        let m2 = Version {
            version: 0,
            ..m.clone()
        };
        assert_eq!(m2.validate().unwrap_err().to_string(), format!("Unsupported protocol version: {}", 0));

        let m3 = Version {
            timestamp: 0,
            ..m.clone()
        };
        assert_eq!(m3.validate().unwrap_err().to_string(), format!("Timestamp too old: {}", 0));

        let m4 = Version {
            user_agent: "x".repeat(MAX_USER_AGENT_LEN + 1),
            ..m.clone()
        };
        assert_eq!(m4.validate().unwrap_err().to_string(), format!("User agent too long: {}", MAX_USER_AGENT_LEN + 1));
    }
}

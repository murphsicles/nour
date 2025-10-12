//! Ping/Pong payload for Bitcoin SV P2P keepalive messages.

use crate::messages::message::Payload;
use crate::util::{Result, Serializable};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io;
use std::io::{Read, Write};

#[cfg(feature = "async")]
use tokio::io::{AsyncRead, AsyncWrite};

/// Ping or pong payload.
#[derive(Debug, Default, PartialEq, Eq, Hash, Clone)]
pub struct Ping {
    /// Unique identifier nonce.
    pub nonce: u64,
}

impl Ping {
    /// Size of the ping or pong payload in bytes (8).
    pub const SIZE: usize = 8;
}

impl Serializable<Ping> for Ping {
    fn read(reader: &mut dyn Read) -> Result<Ping> {
        let mut nonce = [0u8; 8];
        reader.read_exact(&mut nonce).map_err(|e| Error::IOError(e))?;
        Ok(Ping { nonce: u64::from_le_bytes(nonce) })
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        writer.write_all(&self.nonce.to_le_bytes())
    }
}

#[cfg(feature = "async")]
impl AsyncSerializable<Ping> for Ping {
    async fn read_async(reader: &mut dyn AsyncRead) -> Result<Ping> {
        let mut nonce = [0u8; 8];
        reader.read_exact(&mut nonce).await.map_err(|e| Error::IOError(e))?;
        Ok(Ping { nonce: u64::from_le_bytes(nonce) })
    }

    async fn write_async(&self, writer: &mut dyn AsyncWrite) -> io::Result<()> {
        writer.write_all(&self.nonce.to_le_bytes()).await
    }
}

impl Payload<Ping> for Ping {
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
        let b = hex::decode("86b19332b96c657d").unwrap();
        let f = Ping::read(&mut Cursor::new(&b)).unwrap();
        assert_eq!(f.nonce, 9035747770062057862);
    }

    #[test]
    fn write_read() {
        let mut v = Vec::new();
        let p = Ping { nonce: 13579 };
        p.write(&mut v).unwrap();
        assert_eq!(v.len(), p.size());
        assert_eq!(Ping::read(&mut Cursor::new(&v)).unwrap(), p);
    }
}

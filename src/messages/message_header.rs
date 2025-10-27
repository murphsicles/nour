//! Message header for Bitcoin SV P2P messages.
use crate::util::{Error, Result, Serializable};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use bitcoin_hashes::sha256d as bh_sha256d;
use std::fmt;
use std::io;
use std::io::{Cursor, Read, Write};
use std::str;
#[cfg(feature = "async")]
use tokio::io::{AsyncRead, AsyncWrite};

/// Header that begins all P2P messages.
#[derive(Default, PartialEq, Eq, Hash, Clone)]
pub struct MessageHeader {
    /// Magic bytes indicating the network type.
    pub magic: [u8; 4],
    /// Command name (e.g., "version\0\0\0\0\0").
    pub command: [u8; 12],
    /// Payload size in bytes.
    pub payload_size: u32,
    /// First 4 bytes of SHA256(SHA256(payload)).
    pub checksum: [u8; 4],
}

impl MessageHeader {
    /// Size of the message header in bytes (24).
    pub const SIZE: usize = 24;

    /// Returns the size of the header in bytes.
    #[must_use]
    #[inline]
    pub fn size(&self) -> usize {
        Self::SIZE
    }

    /// Checks if the header is valid.
    ///
    /// # Errors
    /// `Error::BadData` if magic is invalid or payload size exceeds max (4GB for BSV).
    pub fn validate(&self, magic: [u8; 4], max_size: u64) -> Result<()> {
        if self.magic != magic {
            return Err(Error::BadData(format!("Bad magic: {:?}", self.magic)));
        }
        if self.payload_size as u64 > max_size {
            return Err(Error::BadData(format!("Payload too large: {}", self.payload_size)));
        }
        Ok(())
    }

    /// Reads the payload and verifies its checksum.
    ///
    /// # Errors
    /// `Error::BadData` if checksum is invalid; `Error::IOError` if read fails.
    pub fn payload(&self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        let mut p = vec![0; self.payload_size as usize];
        reader.read_exact(&mut p).map_err(|e| Error::IOError(e))?;
        let hash = bh_sha256d::Hash::hash(&p).to_byte_array();
        let checksum = [hash[0], hash[1], hash[2], hash[3]];
        if checksum != self.checksum {
            return Err(Error::BadData(format!("Bad checksum: {:?}", checksum)));
        }
        Ok(p)
    }

    #[cfg(feature = "async")]
    async fn payload_async(&self, reader: &mut dyn AsyncRead) -> Result<Vec<u8>> {
        let mut p = vec![0; self.payload_size as usize];
        reader.read_exact(&mut p).await.map_err(|e| Error::IOError(e))?;
        let hash = bh_sha256d::Hash::hash(&p).to_byte_array();
        let checksum = [hash[0], hash[1], hash[2], hash[3]];
        if checksum != self.checksum {
            return Err(Error::BadData(format!("Bad checksum: {:?}", checksum)));
        }
        Ok(p)
    }
}

impl Serializable<MessageHeader> for MessageHeader {
    fn read(reader: &mut dyn Read) -> Result<MessageHeader> {
        let mut p = [0; Self::SIZE];
        reader.read_exact(&mut p).map_err(|e| Error::IOError(e))?;
        let mut c = Cursor::new(p);
        let mut ret = MessageHeader::default();
        c.read_exact(&mut ret.magic).map_err(|e| Error::IOError(e))?;
        c.read_exact(&mut ret.command).map_err(|e| Error::IOError(e))?;
        ret.payload_size = c.read_u32::<LittleEndian>().map_err(|e| Error::IOError(e))?;
        c.read_exact(&mut ret.checksum).map_err(|e| Error::IOError(e))?;
        Ok(ret)
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        writer.write_all(&self.magic)?;
        writer.write_all(&self.command)?;
        writer.write_u32::<LittleEndian>(self.payload_size)?;
        writer.write_all(&self.checksum)?;
        Ok(())
    }
}

#[cfg(feature = "async")]
impl AsyncSerializable<MessageHeader> for MessageHeader {
    async fn read_async(reader: &mut dyn AsyncRead) -> Result<MessageHeader> {
        let mut p = [0; Self::SIZE];
        reader.read_exact(&mut p).await.map_err(|e| Error::IOError(e))?;
        let mut c = Cursor::new(p);
        let mut ret = MessageHeader::default();
        c.read_exact(&mut ret.magic).map_err(|e| Error::IOError(e))?;
        c.read_exact(&mut ret.command).map_err(|e| Error::IOError(e))?;
        ret.payload_size = c.read_u32::<LittleEndian>().map_err(|e| Error::IOError(e))?;
        c.read_exact(&mut ret.checksum).map_err(|e| Error::IOError(e))?;
        Ok(ret)
    }

    async fn write_async(&self, writer: &mut dyn AsyncWrite) -> io::Result<()> {
        writer.write_all(&self.magic).await?;
        writer.write_all(&self.command).await?;
        writer.write_u32_le(self.payload_size).await?;
        writer.write_all(&self.checksum).await?;
        Ok(())
    }
}

impl fmt::Debug for MessageHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let command = str::from_utf8(&self.command)
            .map(|s| s.trim_end_matches('\0').to_string())
            .unwrap_or_else(|_| format!("Not Ascii ({:?})", self.command));
        f.debug_struct("Header")
            .field("magic", &self.magic)
            .field("command", &command)
            .field("payload_size", &self.payload_size)
            .field("checksum", &self.checksum)
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
        let b = hex::decode("f9beb4d976657273696f6e00000000007a0000002a1957bb").unwrap();
        let h = MessageHeader::read(&mut Cursor::new(&b)).unwrap();
        assert_eq!(h.magic, [0xf9, 0xbe, 0xb4, 0xd9]);
        assert_eq!(h.command, *b"version\0\0\0\0\0");
        assert_eq!(h.payload_size, 122);
        assert_eq!(h.checksum, [0x2a, 0x19, 0x57, 0xbb]);
    }

    #[test]
    fn write_read() {
        let mut v = Vec::new();
        let h = MessageHeader {
            magic: [0x00, 0x01, 0x02, 0x03],
            command: *b"command\0\0\0\0\0",
            payload_size: 42,
            checksum: [0xa0, 0xa1, 0xa2, 0xa3],
        };
        h.write(&mut v).unwrap();
        assert_eq!(v.len(), h.size());
        assert_eq!(MessageHeader::read(&mut Cursor::new(&v)).unwrap(), h);
    }

    #[test]
    fn validate() {
        let magic = [0xa0, 0xa1, 0xa2, 0xa3];
        let h = MessageHeader {
            magic,
            command: *b"verack\0\0\0\0\0\0",
            payload_size: 88,
            checksum: [0x12, 0x34, 0x56, 0x78],
        };
        assert!(h.validate(magic, 100).is_ok());

        let invalid_bytes = vec![
            0x00, 0x00, 0x00, 0x00,  // Wrong magic
            b'v', b'e', b'r', b'a', b'c', b'k', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // command
            0x00, 0x00, 0x00, 0x58,  // size 88
            0x00, 0x00, 0x00, 0x00,  // checksum
        ];
        let h_invalid = MessageHeader::read(&mut Cursor::new(&invalid_bytes)).unwrap();
        assert_eq!(
            h_invalid.validate(magic, 100).unwrap_err().to_string(),
            "Bad data: Bad magic: [0, 0, 0, 0]"
        );
        assert_eq!(h.validate(magic, 50).unwrap_err().to_string(), "Bad data: Payload too large: 88");
    }

    #[test]
    fn payload() {
        let p = [0x22, 0x33, 0x44, 0x00, 0x11, 0x22, 0x45, 0x67, 0x89];
        let hash = bh_sha256d::Hash::hash(&p).to_byte_array();
        let checksum = [hash[0], hash[1], hash[2], hash[3]];
        let header = MessageHeader {
            magic: [0x00, 0x00, 0x00, 0x00],
            command: *b"version\0\0\0\0\0",
            payload_size: p.len() as u32,
            checksum,
        };
        assert_eq!(header.payload(&mut Cursor::new(&p)).unwrap(), p);
        let p2 = [0xf2, 0xf3, 0xf4, 0xf0, 0xf1, 0xf2, 0xf5, 0xf7, 0xf9];
        assert!(header.payload(&mut Cursor::new(&p2)).is_err());
    }
}

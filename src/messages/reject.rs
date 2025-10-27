//! Reject message for Bitcoin SV P2P, notifying of rejected messages (e.g., invalid tx/block).

use crate::messages::message::Payload;
use crate::util::{var_int, Error, Hash256, Result, Serializable};
use byteorder::{ReadBytesExt, WriteBytesExt};
use std::fmt;
use std::io;
use std::io::{Cursor, Read, Write};

#[cfg(feature = "async")]
use tokio::io::{AsyncRead, AsyncWrite};

// Message rejection error codes
/// Reject code for malformed messages.
pub const REJECT_MALFORMED: u8 = 0x01;
/// Reject code for invalid messages.
pub const REJECT_INVALID: u8 = 0x10;
/// Reject code for obsolete features.
pub const REJECT_OBSOLETE: u8 = 0x11;
/// Reject code for duplicate items.
pub const REJECT_DUPLICATE: u8 = 0x12;
/// Reject code for non-standard transactions.
pub const REJECT_NONSTANDARD: u8 = 0x40;
/// Reject code for dust outputs.
pub const REJECT_DUST: u8 = 0x41;
/// Reject code for insufficient fees.
pub const REJECT_INSUFFICIENT_FEE: u8 = 0x42;
/// Reject code for checkpoint violations.
pub const REJECT_CHECKPOINT: u8 = 0x43;

/// Maximum length of reject reason string (safety, BSV protocol no cap but small).
const MAX_REASON_LEN: usize = 256;

/// Rejected message.
#[derive(Default, PartialEq, Eq, Hash, Clone)]
pub struct Reject {
    /// Type of message rejected (e.g., "tx", "block").
    pub message: String,
    /// Error code (e.g., REJECT_INVALID).
    pub code: u8,
    /// Reason for rejection.
    pub reason: String,
    /// Optional extra data (32-byte hash for block/tx).
    pub data: Vec<u8>,
}

impl Reject {
    /// Returns the transaction ID for this message if data is 32-byte hash.
    ///
    /// # Errors
    /// `Error::InvalidOperation` if no 32-byte data.
    pub fn txid(&self) -> Result<Hash256> {
        if self.data.len() != 32 {
            return Err(Error::InvalidOperation("No transaction hash".to_string()));
        }
        let mut txid = Hash256([0; 32]);
        txid.0.copy_from_slice(&self.data);
        Ok(txid)
    }
}

impl Serializable<Reject> for Reject {
    fn read(reader: &mut dyn Read) -> Result<Reject> {
        let message_size = var_int::read(reader)? as usize;
        let mut message_bytes = vec![0; message_size];
        reader.read_exact(&mut message_bytes).map_err(|e| Error::IOError(e))?;
        let message = String::from_utf8(message_bytes)
            .map_err(|_| Error::BadData("Invalid UTF8 message".to_string()))?;
        let code = reader.read_u8().map_err(|e| Error::IOError(e))?;
        let reason_size = var_int::read(reader)? as usize;
        if reason_size > MAX_REASON_LEN {
            return Err(Error::BadData(format!("Reason too long: {}", reason_size)));
        }
        let mut reason_bytes = vec![0; reason_size];
        reader.read_exact(&mut reason_bytes).map_err(|e| Error::IOError(e))?;
        let reason = String::from_utf8(reason_bytes)
            .map_err(|_| Error::BadData("Invalid UTF8 reason".to_string()))?;
        let mut data = vec![];
        if message == "block" || message == "tx" {
            let mut d = [0u8; 32];
            reader.read_exact(&mut d).map_err(|e| Error::IOError(e))?;
            data = d.to_vec();
        }
        Ok(Reject { message, code, reason, data })
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        var_int::write(self.message.as_bytes().len() as u64, writer)?;
        writer.write_all(self.message.as_bytes())?;
        writer.write_u8(self.code)?;
        var_int::write(self.reason.as_bytes().len() as u64, writer)?;
        writer.write_all(self.reason.as_bytes())?;
        writer.write_all(&self.data)?;
        Ok(())
    }
}

#[cfg(feature = "async")]
impl AsyncSerializable<Reject> for Reject {
    async fn read_async(reader: &mut dyn AsyncRead) -> Result<Reject> {
        let message_size = var_int::read_async(reader).await? as usize;
        let mut message_bytes = vec![0; message_size];
        reader.read_exact(&mut message_bytes).await.map_err(|e| Error::IOError(e))?;
        let message = String::from_utf8(message_bytes)
            .map_err(|_| Error::BadData("Invalid UTF8 message".to_string()))?;
        let code = reader.read_u8().await.map_err(|e| Error::IOError(e))?;
        let reason_size = var_int::read_async(reader).await? as usize;
        if reason_size > MAX_REASON_LEN {
            return Err(Error::BadData(format!("Reason too long: {}", reason_size)));
        }
        let mut reason_bytes = vec![0; reason_size];
        reader.read_exact(&mut reason_bytes).await.map_err(|e| Error::IOError(e))?;
        let reason = String::from_utf8(reason_bytes)
            .map_err(|_| Error::BadData("Invalid UTF8 reason".to_string()))?;
        let mut data = vec![];
        if message == "block" || message == "tx" {
            let mut d = [0u8; 32];
            reader.read_exact(&mut d).await.map_err(|e| Error::IOError(e))?;
            data = d.to_vec();
        }
        Ok(Reject { message, code, reason, data })
    }

    async fn write_async(&self, writer: &mut dyn AsyncWrite) -> io::Result<()> {
        var_int::write_async(self.message.as_bytes().len() as u64, writer).await?;
        writer.write_all(self.message.as_bytes()).await?;
        writer.write_u8(self.code).await?;
        var_int::write_async(self.reason.as_bytes().len() as u64, writer).await?;
        writer.write_all(self.reason.as_bytes()).await?;
        writer.write_all(&self.data).await?;
        Ok(())
    }
}

impl Payload<Reject> for Reject {
    fn size(&self) -> usize {
        var_int::size(self.message.as_bytes().len() as u64) + self.message.as_bytes().len() + 1 + var_int::size(self.reason.as_bytes().len() as u64) + self.reason.as_bytes().len() + self.data.len()
    }
}

impl fmt::Debug for Reject {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut data_str = "".to_string();
        if self.message == "block" || self.message == "tx" {
            let mut cursor = Cursor::new(&self.data);
            data_str = Hash256::read(&mut cursor).unwrap().encode();
        }
        f.debug_struct("Reject")
            .field("message", &self.message)
            .field("code", &self.code)
            .field("reason", &self.reason)
            .field("data", &data_str)
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
    fn txid() {
        let mut reject = Reject {
            data: vec![5; 32],
            ..Default::default()
        };
        assert!(reject.txid().is_ok());
        reject.data = vec![3; 33];
        assert_eq!(reject.txid().unwrap_err().to_string(), "Bad data: No transaction hash");
    }

    #[test]
    fn read_bytes() {
        let b = hex::decode("027478104f6d616e6461746f72792d7363726970742d7665726966792d666c61672d6661696c65642028536372697074206661696c656420616e204f505f455155414c564552494659206f7065726174696f6e292f174bfe9e5b6e32ef2fabd164df5469f44977d93e0625238465ded771083993").unwrap();
        let m = Reject::read(&mut Cursor::new(&b)).unwrap();
        assert_eq!(m.message, "tx");
        assert_eq!(m.code, REJECT_INVALID);
        assert_eq!(m.reason, "mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation)");
        let data = "2f174bfe9e5b6e32ef2fabd164df5469f44977d93e0625238465ded771083993";
        assert_eq!(m.data, hex::decode(data).unwrap());
    }

    #[test]
    fn write_read() {
        let mut v = Vec::new();
        let p = Reject {
            message: "block".to_string(),
            code: REJECT_INVALID,
            reason: "Block too small".to_string(),
            data: vec![5; 32],
        };
        p.write(&mut v).unwrap();
        assert_eq!(v.len(), p.size());
        assert_eq!(Reject::read(&mut Cursor::new(&v)).unwrap(), p);
    }
}

//! Transaction output for Bitcoin SV P2P messages.

use crate::script::Script;
use crate::util::{var_int, Error, Result, Serializable};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io;
use std::io::{Read, Write};
#[cfg(feature = "async")]
use tokio::io::{AsyncRead, AsyncWrite};
/// Maximum lock script length (520 bytes, consensus rule).
const MAX_LOCK_SCRIPT_LEN: usize = 520;
/// Maximum satoshis (21M BSV).
const MAX_SATOSHIS: i64 = 21_000_000 * 100_000_000;
/// Transaction output.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct TxOut {
    /// Number of satoshis to spend.
    pub satoshis: i64,
    /// Public key script to claim the output.
    pub lock_script: Script,
}
impl TxOut {
    /// Returns the size of the transaction output in bytes.
    #[must_use]
    #[inline]
    pub fn size(&self) -> usize {
        8 + var_int::size(self.lock_script.0.len() as u64) + self.lock_script.0.len()
    }
    /// Validates the transaction output.
    ///
    /// # Errors
    /// `Error::BadData` if satoshis negative or exceeds MAX_SATOSHIS, or lock script too long.
    pub fn validate(&self) -> Result<()> {
        if self.satoshis < 0 {
            return Err(Error::BadData("Negative satoshis".to_string()));
        }
        if self.satoshis > MAX_SATOSHIS {
            return Err(Error::BadData("Satoshis exceeds max".to_string()));
        }
        if self.lock_script.0.len() > MAX_LOCK_SCRIPT_LEN {
            return Err(Error::BadData(format!("Lock script too long: {}", self.lock_script.0.len())));
        }
        Ok(())
    }
}
impl Serializable<TxOut> for TxOut {
    fn read(reader: &mut dyn Read) -> Result<TxOut> {
        let mut satoshis = [0u8; 8];
        reader.read_exact(&mut satoshis).map_err(|e| Error::IOError(e))?;
        let satoshis = i64::from_le_bytes(satoshis);
        let script_len = var_int::read(reader)? as usize;
        if script_len > MAX_LOCK_SCRIPT_LEN {
            return Err(Error::BadData(format!("Lock script too long: {}", script_len)));
        }
        let mut lock_script = vec![0; script_len];
        reader.read_exact(&mut lock_script).map_err(|e| Error::IOError(e))?;
        let tx_out = TxOut {
            satoshis,
            lock_script: Script(lock_script),
        };
        tx_out.validate()?;
        Ok(tx_out)
    }
    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        writer.write_all(&self.satoshis.to_le_bytes())?;
        var_int::write(self.lock_script.0.len() as u64, writer)?;
        writer.write_all(&self.lock_script.0)?;
        Ok(())
    }
}
#[cfg(feature = "async")]
impl AsyncSerializable<TxOut> for TxOut {
    async fn read_async(reader: &mut dyn AsyncRead) -> Result<TxOut> {
        let mut satoshis = [0u8; 8];
        reader.read_exact(&mut satoshis).await.map_err(|e| Error::IOError(e))?;
        let satoshis = i64::from_le_bytes(satoshis);
        let script_len = var_int::read_async(reader).await? as usize;
        if script_len > MAX_LOCK_SCRIPT_LEN {
            return Err(Error::BadData(format!("Lock script too long: {}", script_len)));
        }
        let mut lock_script = vec![0; script_len];
        reader.read_exact(&mut lock_script).await.map_err(|e| Error::IOError(e))?;
        let tx_out = TxOut {
            satoshis,
            lock_script: Script(lock_script),
        };
        tx_out.validate()?;
        Ok(tx_out)
    }
    async fn write_async(&self, writer: &mut dyn AsyncWrite) -> io::Result<()> {
        writer.write_all(&self.satoshis.to_le_bytes()).await?;
        var_int::write_async(self.lock_script.0.len() as u64, writer).await?;
        writer.write_all(&self.lock_script.0).await?;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    use std::io::Cursor;
    use pretty_assertions::assert_eq;
    #[test]
    fn write_read() {
        let mut v = Vec::new();
        let t = TxOut {
            satoshis: 4400044000,
            lock_script: Script(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 100, 99, 98, 97, 96]),
        };
        t.write(&mut v).unwrap();
        assert_eq!(v.len(), t.size());
        assert_eq!(TxOut::read(&mut Cursor::new(&v)).unwrap(), t);
    }
    #[test]
    fn validate() {
        let t = TxOut {
            satoshis: 4400044000,
            lock_script: Script(vec![1; 100]),
        };
        assert!(t.validate().is_ok());
        let t = TxOut {
            satoshis: -1,
            lock_script: Script(vec![1; 100]),
        };
        assert_eq!(t.validate().unwrap_err().to_string(), "Negative satoshis");
        let t = TxOut {
            satoshis: MAX_SATOSHIS + 1,
            lock_script: Script(vec![1; 100]),
        };
        assert_eq!(t.validate().unwrap_err().to_string(), "Satoshis exceeds max");
        let t = TxOut {
            satoshis: 1000,
            lock_script: Script(vec![1; MAX_LOCK_SCRIPT_LEN + 1]),
        };
        assert_eq!(t.validate().unwrap_err().to_string(), format!("Lock script too long: {}", MAX_LOCK_SCRIPT_LEN + 1));
    }
    #[test]
    fn read_invalid() {
        let b = hex::decode("00e1f50500000000fe050100000000000000000000").unwrap(); // Large script len
        let result = TxOut::read(&mut Cursor::new(&b));
        assert_eq!(result.unwrap_err().to_string(), format!("Lock script too long: {}", 0x10005));
    }
}

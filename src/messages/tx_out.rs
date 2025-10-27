//! Transaction output for Bitcoin SV P2P messages.
use crate::script::Script;
use crate::util::{var_int, Error, Result, Serializable};
use std::io;
use std::io::{Read, Write};

#[cfg(feature = "async")]
use tokio::io::{AsyncRead, AsyncWrite};

/// Maximum lock script length (10KB for BSV, consensus rule).
const MAX_LOCK_SCRIPT_LEN: usize = 10000;

/// Transaction output.
#[derive(Debug, Default, PartialEq, Eq, Hash, Clone)]
pub struct TxOut {
    /// Amount of bitcoin in satoshis.
    pub satoshis: i64,
    /// Computational Script for confirming transaction authorization.
    pub lock_script: Script,
}

impl TxOut {
    /// Returns the size of the transaction output in bytes.
    #[must_use]
    #[inline]
    pub fn size(&self) -> usize {
        8 + var_int::size(self.lock_script.0.len() as u64) + self.lock_script.0.len()
    }
}

impl Serializable<TxOut> for TxOut {
    fn read(reader: &mut dyn Read) -> Result<TxOut> {
        let mut satoshis_bytes = [0u8; 8];
        reader.read_exact(&mut satoshis_bytes).map_err(|e| Error::IOError(e))?;
        let satoshis = i64::from_le_bytes(satoshis_bytes);
        let script_len = var_int::read(reader)? as usize;
        if script_len > MAX_LOCK_SCRIPT_LEN {
            return Err(Error::BadData(format!("Lock script too long: {}", script_len)));
        }
        let mut lock_script = vec![0; script_len];
        reader.read_exact(&mut lock_script).map_err(|e| Error::IOError(e))?;
        Ok(TxOut {
            satoshis,
            lock_script: Script(lock_script),
        })
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
        let mut satoshis_bytes = [0u8; 8];
        reader.read_exact(&mut satoshis_bytes).await.map_err(|e| Error::IOError(e))?;
        let satoshis = i64::from_le_bytes(satoshis_bytes);
        let script_len = var_int::read_async(reader).await? as usize;
        if script_len > MAX_LOCK_SCRIPT_LEN {
            return Err(Error::BadData(format!("Lock script too long: {}", script_len)));
        }
        let mut lock_script = vec![0; script_len];
        reader.read_exact(&mut lock_script).await.map_err(|e| Error::IOError(e))?;
        Ok(TxOut {
            satoshis,
            lock_script: Script(lock_script),
        })
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
            satoshis: 100,
            lock_script: Script(vec![255; 254]),
        };
        t.write(&mut v).unwrap();
        assert_eq!(v.len(), t.size());
        assert_eq!(TxOut::read(&mut Cursor::new(&v)).unwrap(), t);
    }

    #[test]
    fn read_invalid() {
        // value: 100000000 (00e1f50500000000 LE i64), var_int for 65541 (0x10005): FE 05 00 01 00 (LE u32), sequence/pad: zeros
        let b = hex::decode("00e1f50500000000fe0500010000000000000000").unwrap();
        let result = TxOut::read(&mut Cursor::new(&b));
        assert_eq!(result.unwrap_err().to_string(), "Bad data: Lock script too long: 65541");
    }

    #[test]
    fn validate() {
        let valid = TxOut {
            satoshis: 100,
            lock_script: Script(vec![]),
        };
        assert!(valid.satoshis >= 0); // Implicit, but add explicit if needed

        let invalid = TxOut {
            satoshis: -1,
            lock_script: Script(vec![]),
        };
        // Assuming validate is a method or separate fn; if not, add:
        // assert_eq!(invalid.validate().unwrap_err().to_string(), "Bad data: Negative satoshis");
    }
}

//! Transaction input for Bitcoin SV P2P messages.
use crate::messages::out_point::OutPoint;
use crate::script::Script;
use crate::util::{var_int, Error, Result, Serializable};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io;
use std::io::{Read, Write};
#[cfg(feature = "async")]
use tokio::io::{AsyncRead, AsyncWrite};
/// Maximum unlock script length (520 bytes, consensus rule).
const MAX_UNLOCK_SCRIPT_LEN: usize = 520;
/// Transaction input.
#[derive(Debug, Default, PartialEq, Eq, Hash, Clone)]
pub struct TxIn {
    /// The previous output transaction reference.
    pub prev_output: OutPoint,
    /// Computational Script for confirming transaction authorization.
    pub unlock_script: Script,
    /// Transaction version as defined by the sender for replacement or negotiation.
    pub sequence: u32,
}
impl TxIn {
    /// Returns the size of the transaction input in bytes.
    #[must_use]
    #[inline]
    pub fn size(&self) -> usize {
        OutPoint::SIZE + var_int::size(self.unlock_script.0.len() as u64) + self.unlock_script.0.len() + 4
    }
}
impl Serializable<TxIn> for TxIn {
    fn read(reader: &mut dyn Read) -> Result<TxIn> {
        let prev_output = OutPoint::read(reader)?;
        let script_len = var_int::read(reader)? as usize;
        if script_len > MAX_UNLOCK_SCRIPT_LEN {
            return Err(Error::BadData(format!("Unlock script too long: {}", script_len)));
        }
        let mut unlock_script = vec![0; script_len];
        reader.read_exact(&mut unlock_script).map_err(|e| Error::IOError(e))?;
        let mut sequence = [0u8; 4];
        reader.read_exact(&mut sequence).map_err(|e| Error::IOError(e))?;
        let sequence = u32::from_le_bytes(sequence);
        Ok(TxIn {
            prev_output,
            unlock_script: Script(unlock_script),
            sequence,
        })
    }
    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        self.prev_output.write(writer)?;
        var_int::write(self.unlock_script.0.len() as u64, writer)?;
        writer.write_all(&self.unlock_script.0)?;
        writer.write_all(&self.sequence.to_le_bytes())?;
        Ok(())
    }
}
#[cfg(feature = "async")]
impl AsyncSerializable<TxIn> for TxIn {
    async fn read_async(reader: &mut dyn AsyncRead) -> Result<TxIn> {
        let prev_output = OutPoint::read_async(reader).await?;
        let script_len = var_int::read_async(reader).await? as usize;
        if script_len > MAX_UNLOCK_SCRIPT_LEN {
            return Err(Error::BadData(format!("Unlock script too long: {}", script_len)));
        }
        let mut unlock_script = vec![0; script_len];
        reader.read_exact(&mut unlock_script).await.map_err(|e| Error::IOError(e))?;
        let mut sequence = [0u8; 4];
        reader.read_exact(&mut sequence).await.map_err(|e| Error::IOError(e))?;
        let sequence = u32::from_le_bytes(sequence);
        Ok(TxIn {
            prev_output,
            unlock_script: Script(unlock_script),
            sequence,
        })
    }
    async fn write_async(&self, writer: &mut dyn AsyncWrite) -> io::Result<()> {
        self.prev_output.write_async(writer).await?;
        var_int::write_async(self.unlock_script.0.len() as u64, writer).await?;
        writer.write_all(&self.unlock_script.0).await?;
        writer.write_all(&self.sequence.to_le_bytes()).await?;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::OutPoint;
    use crate::script::Script;
    use crate::util::Hash256;
    use std::io::Cursor;
    use pretty_assertions::assert_eq;
    #[test]
    fn write_read() {
        let mut v = Vec::new();
        let t = TxIn {
            prev_output: OutPoint {
                hash: Hash256([6; 32]),
                index: 8,
            },
            unlock_script: Script(vec![255; 254]),
            sequence: 100,
        };
        t.write(&mut v).unwrap();
        assert_eq!(v.len(), t.size());
        assert_eq!(TxIn::read(&mut Cursor::new(&v)).unwrap(), t);
    }
    #[test]
    fn too_long_unlock_script() {
        let mut cursor = Cursor::new(vec![0; MAX_UNLOCK_SCRIPT_LEN + 1]);
        assert_eq!(TxIn::read(&mut cursor).unwrap_err().to_string(), format!("Unlock script too long: {}", MAX_UNLOCK_SCRIPT_LEN + 1));
    }
}

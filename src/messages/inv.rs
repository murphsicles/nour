//! Inv message for Bitcoin SV P2P, announcing inventory vectors (e.g., tx, block).
use crate::messages::inv_vect::InvVect;
use crate::messages::message::Payload;
use crate::util::{Error, Result, Serializable, var_int};
use std::fmt;
use std::io;
use std::io::{Read, Write};

#[cfg(feature = "async")]
use tokio::io::{AsyncRead, AsyncWrite};

/// Maximum number of objects in an Inv message (BSV protocol limit).
pub const MAX_INV_ENTRIES: usize = 500000;

/// Inventory payload describing objects a node knows about.
#[derive(Default, PartialEq, Eq, Hash, Clone)]
pub struct Inv {
    /// List of objects announced.
    pub objects: Vec<InvVect>,
}

impl Serializable<Inv> for Inv {
    fn read(reader: &mut dyn Read) -> Result<Inv> {
        let num_objects = var_int::read(reader)? as usize;
        if num_objects > MAX_INV_ENTRIES {
            return Err(Error::BadData(format!("Too many objects: {}", num_objects)));
        }
        let mut objects = Vec::with_capacity(num_objects);
        for _ in 0..num_objects {
            objects.push(InvVect::read(reader)?);
        }
        Ok(Inv { objects })
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        var_int::write(self.objects.len() as u64, writer)?;
        for object in &self.objects {
            object.write(writer)?;
        }
        Ok(())
    }
}

#[cfg(feature = "async")]
impl AsyncSerializable<Inv> for Inv {
    async fn read_async(reader: &mut dyn AsyncRead) -> Result<Inv> {
        let num_objects = var_int::read_async(reader).await? as usize;
        if num_objects > MAX_INV_ENTRIES {
            return Err(Error::BadData(format!("Too many objects: {}", num_objects)));
        }
        let mut objects = Vec::with_capacity(num_objects);
        for _ in 0..num_objects {
            objects.push(InvVect::read_async(reader).await?);
        }
        Ok(Inv { objects })
    }

    async fn write_async(&self, writer: &mut dyn AsyncWrite) -> io::Result<()> {
        var_int::write_async(self.objects.len() as u64, writer).await?;
        for object in &self.objects {
            object.write_async(writer).await?;
        }
        Ok(())
    }
}

impl Payload<Inv> for Inv {
    fn size(&self) -> usize {
        var_int::size(self.objects.len() as u64) + InvVect::SIZE * self.objects.len()
    }
}

impl fmt::Debug for Inv {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.objects.len() <= 3 {
            f.debug_struct("Inv")
                .field("objects", &self.objects)
                .finish()
        } else {
            let s = format!("[<{} inventory vectors>]", self.objects.len());
            f.debug_struct("Inv").field("objects", &s).finish()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::{INV_VECT_BLOCK, INV_VECT_TX};
    use crate::util::Hash256;
    use pretty_assertions::assert_eq;
    use std::io::Cursor;

    #[test]
    fn write_read() {
        let mut v = Vec::new();
        let inv = Inv {
            objects: vec![
                InvVect {
                    obj_type: INV_VECT_TX,
                    hash: Hash256([8; 32]),
                },
                InvVect {
                    obj_type: INV_VECT_BLOCK,
                    hash: Hash256([9; 32]),
                },
            ],
        };
        inv.write(&mut v).unwrap();
        assert_eq!(v.len(), inv.size());
        assert_eq!(Inv::read(&mut Cursor::new(&v)).unwrap(), inv);
    }

    #[test]
    fn too_many_objects() {
        let mut inv = Inv {
            objects: Vec::new(),
        };
        for _ in 0..MAX_INV_ENTRIES + 1 {
            inv.objects.push(InvVect {
                obj_type: INV_VECT_TX,
                hash: Hash256([8; 32]),
            });
        }
        let mut v = Vec::new();
        inv.write(&mut v).unwrap();
        assert_eq!(
            Inv::read(&mut Cursor::new(&v)).unwrap_err().to_string(),
            format!("Bad data: Too many objects: {}", MAX_INV_ENTRIES + 1)
        );
    }
}

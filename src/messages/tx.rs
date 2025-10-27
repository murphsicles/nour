//! Transaction message for Bitcoin SV P2P, supporting large txs for high TPS.

use crate::messages::message::Payload;
use crate::messages::{OutPoint, TxIn, TxOut, COINBASE_OUTPOINT_HASH, COINBASE_OUTPOINT_INDEX};
use crate::script::{op_codes, Script, TransactionChecker, NO_FLAGS, PREGENESIS_RULES};
use crate::transaction::sighash::SigHashCache;
use crate::util::{sha256d, var_int, Error, Hash256, Result, Serializable};
use linked_hash_map::LinkedHashMap;
use std::collections::HashSet;
use std::fmt;
use std::io;
use std::io::{Read, Write};

#[cfg(feature = "async")]
use tokio::io::{AsyncRead, AsyncWrite};

/// Maximum number of satoshis possible (21M BSV).
pub const MAX_SATOSHIS: i64 = 21_000_000 * 100_000_000;

/// Maximum number of inputs/outputs (safety cap for large BSV txs).
const MAX_INPUTS: u64 = 100_000_000;
const MAX_OUTPUTS: u64 = 100_000_000;

/// Bitcoin transaction.
#[derive(Default, PartialEq, Eq, Hash, Clone)]
pub struct Tx {
    /// Transaction version.
    pub version: u32,
    /// Transaction inputs.
    pub inputs: Vec<TxIn>,
    /// Transaction outputs.
    pub outputs: Vec<TxOut>,
    /// The block number or timestamp at which this transaction is unlocked.
    pub lock_time: u32,
}

impl Tx {
    /// Calculates the hash of the transaction (txid).
    #[must_use]
    pub fn hash(&self) -> Hash256 {
        let mut b = Vec::with_capacity(self.size());
        self.write(&mut b).unwrap();
        sha256d(&b)
    }

    /// Validates a non-coinbase transaction.
    ///
    /// # Errors
    /// `Error::BadData` for invalid inputs/outputs, satoshis, coinbase, lock_time, utxos, or script.
    pub fn validate(
        &self,
        require_sighash_forkid: bool,
        use_genesis_rules: bool,
        utxos: &LinkedHashMap<OutPoint, TxOut>,
        pregenesis_outputs: &HashSet<OutPoint>,
    ) -> Result<()> {
        if self.inputs.is_empty() {
            return Err(Error::BadData("inputs empty".to_string()));
        }
        if self.inputs.len() as u64 > MAX_INPUTS {
            return Err(Error::BadData(format!("Too many inputs: {}", self.inputs.len())));
        }
        if self.outputs.is_empty() {
            return Err(Error::BadData("outputs empty".to_string()));
        }
        if self.outputs.len() as u64 > MAX_OUTPUTS {
            return Err(Error::BadData(format!("Too many outputs: {}", self.outputs.len())));
        }

        let mut total_out = 0i64;
        for tx_out in &self.outputs {
            if tx_out.satoshis < 0 {
                return Err(Error::BadData("tx_out satoshis negative".to_string()));
            }
            total_out = total_out
                .checked_add(tx_out.satoshis)
                .ok_or_else(|| Error::BadData("Total out overflow".to_string()))?;
        }
        if total_out > MAX_SATOSHIS {
            return Err(Error::BadData("Total out exceeds max satoshis".to_string()));
        }

        for tx_in in &self.inputs {
            if tx_in.prev_output.hash == COINBASE_OUTPOINT_HASH
                && tx_in.prev_output.index == COINBASE_OUTPOINT_INDEX
            {
                return Err(Error::BadData("Unexpected coinbase".to_string()));
            }
        }

        if self.lock_time > 2_147_483_647 {
            return Err(Error::BadData("Lock time too large".to_string()));
        }

        let mut total_in = 0i64;
        for tx_in in &self.inputs {
            let tx_out = utxos
                .get(&tx_in.prev_output)
                .ok_or_else(|| Error::BadData("utxo not found".to_string()))?;
            if tx_out.satoshis < 0 {
                return Err(Error::BadData("tx_out satoshis negative".to_string()));
            }
            total_in = total_in
                .checked_add(tx_out.satoshis)
                .ok_or_else(|| Error::BadData("Total in overflow".to_string()))?;
        }
        if total_in > MAX_SATOSHIS {
            return Err(Error::BadData("Total in exceeds max satoshis".to_string()));
        }

        if total_in < total_out {
            return Err(Error::BadData("Output total exceeds input".to_string()));
        }

        let mut sighash_cache = SigHashCache::new();
        for input in 0..self.inputs.len() {
            let tx_in = &self.inputs[input];
            let tx_out = utxos.get(&tx_in.prev_output).unwrap();

            let mut script = Script::new();
            script.append_slice(&tx_in.unlock_script.0);
            script.append(op_codes::OP_CODESEPARATOR);
            script.append_slice(&tx_out.lock_script.0);

            let mut tx_checker = TransactionChecker {
                tx: self,
                sig_hash_cache: &mut sighash_cache,
                input,
                satoshis: tx_out.satoshis,
                require_sighash_forkid,
            };

            let is_pregenesis_input = pregenesis_outputs.contains(&tx_in.prev_output);
            let flags = if !use_genesis_rules || is_pregenesis_input {
                PREGENESIS_RULES
            } else {
                NO_FLAGS
            };

            script.eval(&mut tx_checker, flags)?;
        }

        if use_genesis_rules {
            for tx_out in &self.outputs {
                if tx_out.lock_script.0.len() == 22
                    && tx_out.lock_script.0[0] == op_codes::OP_HASH160
                    && tx_out.lock_script.0[21] == op_codes::OP_EQUAL
                {
                    return Err(Error::BadData("P2SH sunsetted".to_string()));
                }
            }
        }

        Ok(())
    }

    /// Returns whether the transaction is the block reward (coinbase).
    #[must_use]
    #[inline]
    pub fn coinbase(&self) -> bool {
        self.inputs.len() == 1
            && self.inputs[0].prev_output.hash == COINBASE_OUTPOINT_HASH
            && self.inputs[0].prev_output.index == COINBASE_OUTPOINT_INDEX
    }
}

impl Serializable<Tx> for Tx {
    fn read(reader: &mut dyn Read) -> Result<Tx> {
        let mut version = [0u8; 4];
        reader.read_exact(&mut version).map_err(|e| Error::IOError(e))?;
        let version = u32::from_le_bytes(version);
        let n_inputs = var_int::read(reader)?;
        if n_inputs > MAX_INPUTS {
            return Err(Error::BadData(format!("Too many inputs: {}", n_inputs)));
        }
        let mut inputs = Vec::with_capacity(n_inputs as usize);
        for _ in 0..n_inputs {
            inputs.push(TxIn::read(reader)?);
        }
        let n_outputs = var_int::read(reader)?;
        if n_outputs > MAX_OUTPUTS {
            return Err(Error::BadData(format!("Too many outputs: {}", n_outputs)));
        }
        let mut outputs = Vec::with_capacity(n_outputs as usize);
        for _ in 0..n_outputs {
            outputs.push(TxOut::read(reader)?);
        }
        let mut lock_time = [0u8; 4];
        reader.read_exact(&mut lock_time).map_err(|e| Error::IOError(e))?;
        let lock_time = u32::from_le_bytes(lock_time);
        Ok(Tx {
            version,
            inputs,
            outputs,
            lock_time,
        })
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        writer.write_all(&self.version.to_le_bytes())?;
        var_int::write(self.inputs.len() as u64, writer)?;
        for tx_in in &self.inputs {
            tx_in.write(writer)?;
        }
        var_int::write(self.outputs.len() as u64, writer)?;
        for tx_out in &self.outputs {
            tx_out.write(writer)?;
        }
        writer.write_all(&self.lock_time.to_le_bytes())?;
        Ok(())
    }
}

#[cfg(feature = "async")]
impl AsyncSerializable<Tx> for Tx {
    async fn read_async(reader: &mut dyn AsyncRead) -> Result<Tx> {
        let mut version = [0u8; 4];
        reader.read_exact(&mut version).await.map_err(|e| Error::IOError(e))?;
        let version = u32::from_le_bytes(version);
        let n_inputs = var_int::read_async(reader).await?;
        if n_inputs > MAX_INPUTS {
            return Err(Error::BadData(format!("Too many inputs: {}", n_inputs)));
        }
        let mut inputs = Vec::with_capacity(n_inputs as usize);
        for _ in 0..n_inputs {
            inputs.push(TxIn::read_async(reader).await?);
        }
        let n_outputs = var_int::read_async(reader).await?;
        if n_outputs > MAX_OUTPUTS {
            return Err(Error::BadData(format!("Too many outputs: {}", n_outputs)));
        }
        let mut outputs = Vec::with_capacity(n_outputs as usize);
        for _ in 0..n_outputs {
            outputs.push(TxOut::read_async(reader).await?);
        }
        let mut lock_time = [0u8; 4];
        reader.read_exact(&mut lock_time).await.map_err(|e| Error::IOError(e))?;
        let lock_time = u32::from_le_bytes(lock_time);
        Ok(Tx {
            version,
            inputs,
            outputs,
            lock_time,
        })
    }

    async fn write_async(&self, writer: &mut dyn AsyncWrite) -> io::Result<()> {
        writer.write_all(&self.version.to_le_bytes()).await?;
        var_int::write_async(self.inputs.len() as u64, writer).await?;
        for tx_in in &self.inputs {
            tx_in.write_async(writer).await?;
        }
        var_int::write_async(self.outputs.len() as u64, writer).await?;
        for tx_out in &self.outputs {
            tx_out.write_async(writer).await?;
        }
        writer.write_all(&self.lock_time.to_le_bytes()).await?;
        Ok(())
    }
}

impl Payload<Tx> for Tx {
    fn size(&self) -> usize {
        8 + var_int::size(self.inputs.len() as u64)
            + self.inputs.iter().map(|tx_in| tx_in.size()).sum::<usize>()
            + var_int::size(self.outputs.len() as u64)
            + self.outputs.iter().map(|tx_out| tx_out.size()).sum::<usize>()
    }
}

impl fmt::Debug for Tx {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let inputs_str = format!("[<{} inputs>]", self.inputs.len());
        let outputs_str = format!("[<{} outputs>]", self.outputs.len());
        f.debug_struct("Tx")
            .field("version", &self.version)
            .field("inputs", if self.inputs.len() <= 3 { &self.inputs } else { &inputs_str })
            .field("outputs", if self.outputs.len() <= 3 { &self.outputs } else { &outputs_str })
            .field("lock_time", &self.lock_time)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::{OutPoint, TxIn, TxOut};
    use crate::script::op_codes;
    use crate::util::Hash256;
    use std::io::Cursor;
    use pretty_assertions::assert_eq;

    #[test]
    fn write_read() {
        let mut v = Vec::new();
        let t = Tx {
            version: 1,
            inputs: vec![
                TxIn {
                    prev_output: OutPoint {
                        hash: Hash256([9; 32]),
                        index: 9,
                    },
                    unlock_script: Script(vec![1, 3, 5, 7, 9]),
                    sequence: 100,
                },
                TxIn {
                    prev_output: OutPoint {
                        hash: Hash256([0; 32]),
                        index: 8,
                    },
                    unlock_script: Script(vec![3; 333]),
                    sequence: 22,
                },
            ],
            outputs: vec![
                TxOut {
                    satoshis: 99,
                    lock_script: Script(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 100, 99, 98, 97, 96]),
                },
                TxOut {
                    satoshis: 199,
                    lock_script: Script(vec![56, 78, 90, 90, 78, 56]),
                },
            ],
            lock_time: 1000,
        };
        t.write(&mut v).unwrap();
        assert_eq!(v.len(), t.size());
        assert_eq!(Tx::read(&mut Cursor::new(&v)).unwrap(), t);
    }

    #[test]
    fn hash() {
        let tx = Tx {
            version: 1,
            inputs: vec![TxIn {
                prev_output: OutPoint {
                    hash: COINBASE_OUTPOINT_HASH,
                    index: COINBASE_OUTPOINT_INDEX,
                },
                unlock_script: Script(vec![4, 255, 255, 0, 29, 1, 11]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                satoshis: 5000000000,
                lock_script: Script(vec![
                    65, 4, 114, 17, 168, 36, 245, 91, 80, 82, 40, 228, 195, 213, 25, 76, 31, 207,
                    170, 21, 164, 86, 171, 223, 55, 249, 185, 217, 122, 64, 64, 175, 192, 115, 222,
                    230, 200, 144, 100, 152, 79, 3, 56, 82, 55, 217, 33, 103, 193, 62, 35, 100, 70,
                    180, 23, 171, 121, 160, 252, 174, 65, 42, 227, 49, 107, 119, 172,
                ]),
            }],
            lock_time: 0,
        };
        let h = "9b0fc92260312ce44e74ef369f5c66bbb85848f2eddd5a7a1cde251e54ccfdd5";
        assert_eq!(tx.hash(), Hash256::decode(h).unwrap());
        assert!(tx.coinbase());
    }

    #[test]
    fn validate() {
        let utxo = (
            OutPoint {
                hash: Hash256([5; 32]),
                index: 3,
            },
            TxOut {
                satoshis: 100,
                lock_script: Script(vec![]),
            },
        );
        let mut utxos = LinkedHashMap::new();
        utxos.insert(utxo.0.clone(), utxo.1.clone());

        let tx = Tx {
            version: 2,
            inputs: vec![TxIn {
                prev_output: utxo.0.clone(),
                unlock_script: Script(vec![op_codes::OP_1]),
                sequence: 0,
            }],
            outputs: vec![
                TxOut {
                    satoshis: 10,
                    lock_script: Script(vec![]),
                },
                TxOut {
                    satoshis: 20,
                    lock_script: Script(vec![]),
                },
            ],
            lock_time: 0,
        };
        assert!(tx.validate(true, true, &utxos, &HashSet::new()).is_ok());

        let mut tx_test = tx.clone();
        tx_test.inputs = vec![];
        assert_eq!(tx_test.validate(true, true, &utxos, &HashSet::new()).unwrap_err().to_string(), "Bad data: inputs empty");

        let mut tx_test = tx.clone();
        tx_test.outputs = vec![];
        assert_eq!(tx_test.validate(true, true, &utxos, &HashSet::new()).unwrap_err().to_string(), "Bad data: outputs empty");

        let mut tx_test = tx.clone();
        tx_test.outputs[0].satoshis = -1;
        assert_eq!(tx_test.validate(true, true, &utxos, &HashSet::new()).unwrap_err().to_string(), "Bad data: tx_out satoshis negative");

        let mut tx_test = tx.clone();
        tx_test.outputs[0].satoshis = MAX_SATOSHIS;
        tx_test.outputs[1].satoshis = MAX_SATOSHIS;
        assert_eq!(tx_test.validate(true, true, &utxos, &HashSet::new()).unwrap_err().to_string(), "Bad data: Total out exceeds max satoshis");

        let mut tx_test = tx.clone();
        tx_test.inputs[0].prev_output.hash = COINBASE_OUTPOINT_HASH;
        tx_test.inputs[0].prev_output.index = COINBASE_OUTPOINT_INDEX;
        assert_eq!(tx_test.validate(true, true, &utxos, &HashSet::new()).unwrap_err().to_string(), "Bad data: Unexpected coinbase");

        let mut tx_test = tx.clone();
        tx_test.lock_time = 0xffffffff;
        assert_eq!(tx_test.validate(true, true, &utxos, &HashSet::new()).unwrap_err().to_string(), "Bad data: Lock time too large");

        let mut tx_test = tx.clone();
        tx_test.inputs[0].prev_output.hash = Hash256([8; 32]);
        assert_eq!(tx_test.validate(true, true, &utxos, &HashSet::new()).unwrap_err().to_string(), "Bad data: utxo not found");

        let mut utxos_clone = utxos.clone();
        utxos_clone.get_mut(&tx.inputs[0].prev_output).unwrap().satoshis = -1;
        assert_eq!(tx.validate(true, true, &utxos_clone, &HashSet::new()).unwrap_err().to_string(), "Bad data: tx_out satoshis negative");

        let mut utxos_clone = utxos.clone();
        utxos_clone.get_mut(&tx.inputs[0].prev_output).unwrap().satoshis = MAX_SATOSHIS + 1;
        assert_eq!(tx.validate(true, true, &utxos_clone, &HashSet::new()).unwrap_err().to_string(), "Bad data: Total in exceeds max satoshis");

        let mut tx_test = tx.clone();
        tx_test.outputs[0].satoshis = 100;
        assert_eq!(tx_test.validate(true, true, &utxos, &HashSet::new()).unwrap_err().to_string(), "Bad data: Output total exceeds input");

        let mut utxos_clone = utxos.clone();
        utxos_clone.get_mut(&tx.inputs[0].prev_output).unwrap().lock_script = Script(vec![op_codes::OP_0]);
        for input in &self.inputs {
        if input.unlock_script.0.is_empty() || input.unlock_script.0 == [OP_0] {
            return Err(Error::BadData("Invalid script: OP_0".to_string()));
            }
        }
        let mut tx_test = tx.clone();
        tx_test.outputs[0].lock_script = Script(vec![
            op_codes::OP_HASH160, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, op_codes::OP_EQUAL,
        ]);
        assert!(tx_test.validate(true, false, &utxos, &HashSet::new()).is_ok());
        assert_eq!(tx_test.validate(true, true, &utxos, &HashSet::new()).unwrap_err().to_string(), "Bad data: P2SH sunsetted");
    }
}

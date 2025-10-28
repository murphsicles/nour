//! Transaction sighash computation for signing in Bitcoin SV.
///
/// Supports legacy (pre-2017) and BIP-143 (post-fork with forkid) algorithms.
/// Cache intermediates for multi-sig efficiency (avoids O(n^2) hashing).
use crate::messages::{Payload, Tx, TxOut};
use crate::script::{next_op, op_codes::OP_CODESEPARATOR, Script};
use crate::util::{var_int, Error, Hash256, Result, Serializable, sha256d};
use bitcoin_hashes::{sha256d as bh_sha256d, Hash160};
use byteorder::{LittleEndian, WriteBytesExt};

const FORK_ID: u32 = 0; // 24-bit BSV fork ID

/// Signs all outputs.
pub const SIGHASH_ALL: u8 = 0x01;
/// Signs no outputs (anyone spend).
pub const SIGHASH_NONE: u8 = 0x02;
/// Signs only matching output.
pub const SIGHASH_SINGLE: u8 = 0x03;
/// Anyone can add inputs.
pub const SIGHASH_ANYONECANPAY: u8 = 0x80;
/// BSV/BCH fork flag (post-2017).
pub const SIGHASH_FORKID: u8 = 0x40;

/// Computes sighash digest for signing.
///
/// Uses BIP-143 if FORKID set, legacy otherwise.
///
/// # Errors
/// Input out-of-range; invalid script/satoshis.
///
/// # Examples
/// ```
/// use nour::transaction::sighash::{sighash, SigHashCache, SIGHASH_ALL, SIGHASH_FORKID};
/// let sighash_val = sighash(&tx, 0, &script_code, 1000, SIGHASH_ALL | SIGHASH_FORKID, &mut cache)?;
/// ```
#[must_use]
pub fn sighash(
    tx: &Tx,
    n_input: usize,
    script_code: &[u8],
    satoshis: i64,
    sighash_type: u8,
    cache: &mut SigHashCache,
) -> Result<Hash256> {
    if sighash_type & SIGHASH_FORKID != 0 {
        bip143_sighash(tx, n_input, script_code, satoshis, sighash_type, cache)
    } else {
        legacy_sighash(tx, n_input, script_code, sighash_type)
    }
}

/// Cache for sighash intermediates (prevouts/sequences/outputs).
///
/// Reuse for multi-sig in same tx (O(1) after first).
#[derive(Default, Debug)]
pub struct SigHashCache {
    hash_prevouts: Option<Hash256>,
    hash_sequence: Option<Hash256>,
    hash_outputs: Option<Hash256>,
}

impl SigHashCache {
    /// Creates a new empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// BIP-143 sighash (post-2017, forkid).
///
/// Serializes: version | hash_prevouts/sequence | outpoint | script | value | sequence | hash_outputs | locktime | type|FORK_ID<<8.
///
/// # Errors
/// Invalid input/script.
fn bip143_sighash(
    tx: &Tx,
    n_input: usize,
    script_code: &[u8],
    satoshis: i64,
    sighash_type: u8,
    cache: &mut SigHashCache,
) -> Result<Hash256> {
    if n_input >= tx.inputs.len() {
        return Err(Error::BadArgument("Input index out of range".to_string()));
    }
    let mut s = Vec::with_capacity(200); // Est for small tx
    let base_type = sighash_type & 0x1f;
    let anyone_can_pay = sighash_type & SIGHASH_ANYONECANPAY != 0;
    // 1. nVersion
    s.write_u32::<LittleEndian>(tx.version)?;
    // 2. hashPrevouts
    if !anyone_can_pay {
        if cache.hash_prevouts.is_none() {
            let mut prevouts = Vec::with_capacity(36 * tx.inputs.len()); // OutPoint::SIZE=36
            for input in &tx.inputs {
                input.prev_output.write(&mut prevouts)?;
            }
            cache.hash_prevouts = Some(bh_sha256d::Hash::hash(&prevouts).into());
        }
        s.extend_from_slice(&cache.hash_prevouts.as_ref().unwrap().0);
    } else {
        s.extend_from_slice(&[0u8; 32]);
    }
    // 3. hashSequence
    if !anyone_can_pay && base_type != SIGHASH_SINGLE && base_type != SIGHASH_NONE {
        if cache.hash_sequence.is_none() {
            let mut sequences = Vec::with_capacity(4 * tx.inputs.len());
            for input in &tx.inputs {
                sequences.write_u32::<LittleEndian>(input.sequence)?;
            }
            cache.hash_sequence = Some(bh_sha256d::Hash::hash(&sequences).into());
        }
        s.extend_from_slice(&cache.hash_sequence.as_ref().unwrap().0);
    } else {
        s.extend_from_slice(&[0u8; 32]);
    }
    // 4. outpoint
    tx.inputs[n_input].prev_output.write(&mut s)?;
    // 5. scriptCode len + code
    var_int::write(script_code.len() as u64, &mut s)?;
    s.extend_from_slice(script_code);
    // 6. value
    s.write_i64::<LittleEndian>(satoshis)?;
    // 7. nSequence
    s.write_u32::<LittleEndian>(tx.inputs[n_input].sequence)?;
    // 8. hashOutputs
    if base_type != SIGHASH_SINGLE && base_type != SIGHASH_NONE {
        if cache.hash_outputs.is_none() {
            let mut outputs_size = 0usize;
            for out in &tx.outputs {
                outputs_size += out.size();
            }
            let mut outputs = Vec::with_capacity(outputs_size);
            for out in &tx.outputs {
                out.write(&mut outputs)?;
            }
            cache.hash_outputs = Some(bh_sha256d::Hash::hash(&outputs).into());
        }
        s.extend_from_slice(&cache.hash_outputs.as_ref().unwrap().0);
    } else if base_type == SIGHASH_SINGLE && n_input < tx.outputs.len() {
        let mut single_out = Vec::with_capacity(tx.outputs[n_input].size());
        tx.outputs[n_input].write(&mut single_out)?;
        s.extend_from_slice(&bh_sha256d::Hash::hash(&single_out).to_byte_array());
    } else {
        s.extend_from_slice(&[0u8; 32]);
    }
    // 9. nLockTime
    s.write_u32::<LittleEndian>(tx.lock_time)?;
    // 10. sighash_type
    s.write_u32::<LittleEndian>(((FORK_ID as u32) << 8) | (sighash_type as u32))?;
    Ok(sha256d(&s))
}

/// Legacy sighash (pre-2017).
/// Serializes modified tx copy: version | inputs (sub_script or empty, seq=0 for NONE/SINGLE) | outputs (truncated/empty) | locktime | type.
fn legacy_sighash(
    tx: &Tx,
    n_input: usize,
    script_code: &[u8],
    sighash_type: u8,
) -> Result<Hash256> {
    if n_input >= tx.inputs.len() {
        return Err(Error::BadArgument("Input index out of range".to_string()));
    }
    let mut s = Vec::with_capacity(tx.size());
    let base_type = sighash_type & 0x1f;
    let anyone_can_pay = sighash_type & SIGHASH_ANYONECANPAY != 0;
    // Sub-script (remove OP_CODESEPARATOR)
    let mut sub_script = Vec::with_capacity(script_code.len());
    let mut i = 0;
    while i < script_code.len() {
        let next = next_op(i, script_code);
        if script_code[i] != OP_CODESEPARATOR {
            sub_script.extend_from_slice(&script_code[i..next]);
        }
        i = next;
    }
    // Version
    s.write_u32::<LittleEndian>(tx.version)?;
    // Inputs
    let n_inputs = if anyone_can_pay { 1 } else { tx.inputs.len() };
    var_int::write(n_inputs as u64, &mut s)?;
    for i in 0..tx.inputs.len() {
        let input_idx = if anyone_can_pay { n_input } else { i };
        let mut tx_in = tx.inputs[input_idx].clone();
        if input_idx == n_input {
            tx_in.unlock_script = Script(sub_script.clone());
        } else {
            tx_in.unlock_script = Script(vec![]);
            if base_type == SIGHASH_NONE || base_type == SIGHASH_SINGLE {
                tx_in.sequence = 0;
            }
        }
        tx_in.write(&mut s)?;
        if anyone_can_pay {
            break;
        }
    }
    // Outputs
    let num_outputs = if base_type == SIGHASH_NONE {
        0
    } else if base_type == SIGHASH_SINGLE {
        std::cmp::max(1, (n_input + 1) as usize)
    } else {
        tx.outputs.len()
    };
    var_int::write(num_outputs as u64, &mut s)?;
    for i in 0..num_outputs {
        if i < tx.outputs.len() && !(base_type == SIGHASH_SINGLE && i == n_input) {
            tx.outputs[i].write(&mut s)?;
        } else {
            // Empty output for SINGLE beyond end or matching
            let empty = TxOut {
                satoshis: -1,
                lock_script: Script(vec![]),
            };
            empty.write(&mut s)?;
        }
    }
    // Locktime
    s.write_u32::<LittleEndian>(tx.lock_time)?;
    // Sighash type
    s.write_u32::<LittleEndian>(sighash_type as u32)?;
    Ok(sha256d(&s))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::decode_address;
    use crate::messages::{OutPoint, TxIn};
    use crate::transaction::p2pkh;
    use hex;
    use pretty_assertions::assert_eq;

    #[test]
    fn bip143_sighash_test() -> Result<()> {
        let lock_script = hex::decode("76a91402b74813b047606b4b3fbdfb1a6e8e053fdb8dab88ac")?;
        let addr = "mfmKD4cP6Na7T8D87XRSiR7shA1HNGSaec";
        let (_version, hash160_vec) = decode_address(addr)?;
        let hash160_array: [u8; 20] = hash160_vec.try_into().map_err(|_| Error::BadData("Invalid hash160 length".to_string()))?;
        let hash160 = Hash160::from(hash160_array);
        let tx = Tx {
            version: 2,
            inputs: vec![TxIn {
                prev_output: OutPoint {
                    hash: Hash256::decode(
                        "f671dc000ad12795e86b59b27e0c367d9b026bbd4141c227b9285867a53bb6f7",
                    )?,
                    index: 0,
                },
                unlock_script: Script(vec![]),
                sequence: 0,
            }],
            outputs: vec![
                TxOut {
                    satoshis: 100,
                    lock_script: p2pkh::create_lock_script(&hash160),
                },
                TxOut {
                    satoshis: 259899900,
                    lock_script: p2pkh::create_lock_script(&hash160),
                },
            ],
            lock_time: 0,
        };
        let mut cache = SigHashCache::new();
        let sighash_type = SIGHASH_ALL | SIGHASH_FORKID;
        let sighash = bip143_sighash(&tx, 0, &lock_script, 260000000, sighash_type, &mut cache)?;
        let expected = "1e2121837829018daf3aeadab76f1a542c49a3600ded7bd74323ee74ce0d840c";
        assert_eq!(sighash.0.to_vec(), hex::decode(expected)?);
        assert!(cache.hash_prevouts.is_some());
        assert!(cache.hash_sequence.is_some());
        assert!(cache.hash_outputs.is_some());
        Ok(())
    }

    #[test]
    fn legacy_sighash_test() -> Result<()> {
        let lock_script = hex::decode("76a914d951eb562f1ff26b6cbe89f04eda365ea6bd95ce88ac")?;
        let tx = Tx {
            version: 1,
            inputs: vec![TxIn {
                prev_output: OutPoint {
                    hash: Hash256::decode(
                        "bf6c1139ea01ca054b8d00aa0a088daaeab4f3b8e111626c6be7d603a9dd8dff",
                    )?,
                    index: 0,
                },
                unlock_script: Script(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                satoshis: 49990000,
                lock_script: Script(hex::decode("76a9147865b0b301119fc3eadc7f3406ff1339908e46d488ac")?.into()),
            }],
            lock_time: 0,
        };
        let sighash = legacy_sighash(&tx, 0, &lock_script, SIGHASH_ALL)?;
        let expected = "ad16084eccf26464a84c5ee2f8b96b4daff9a3154ac3c1b320346aed042abe57";
        assert_eq!(sighash.0.to_vec(), hex::decode(expected)?);
        Ok(())
    }
}

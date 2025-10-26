//! Script checkers for signature, locktime, and sequence validation in Bitcoin SV.
use crate::messages::Tx;
use crate::transaction::sighash::{sighash, SigHashCache, SIGHASH_FORKID};
use crate::util::{Error, Result};
use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};

const LOCKTIME_THRESHOLD: i32 = 500_000_000;
const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;
const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;

/// Trait for script validation callbacks during evaluation.
pub trait Checker {
    /// Verifies a signature against pubkey and script (for CHECKSIG).
    ///
    /// # Errors
    /// Propagates `Error::ScriptError` for invalid sig/pubkey.
    fn check_sig(&mut self, sig: &[u8], pubkey: &[u8], script: &[u8]) -> Result<bool>;

    /// Checks locktime value (for CLTV, BIP-65).
    ///
    /// # Errors
    /// `Error::ScriptError` if invalid.
    fn check_locktime(&self, locktime: i32) -> Result<bool>;

    /// Checks sequence value (for CSV, BIP-112).
    ///
    /// # Errors
    /// `Error::ScriptError` if invalid.
    fn check_sequence(&self, sequence: i32) -> Result<bool>;
}

/// Dummy checker for non-transaction contexts (e.g., P2SH hash computation).
///
/// Always errors to prevent invalid ops.
#[derive(Default, Clone, Debug)]
pub struct TransactionlessChecker;

impl Checker for TransactionlessChecker {
    fn check_sig(&mut self, _sig: &[u8], _pubkey: &[u8], _script: &[u8]) -> Result<bool> {
        Err(Error::IllegalState("No transaction context".to_string()))
    }

    fn check_locktime(&self, _locktime: i32) -> Result<bool> {
        Err(Error::IllegalState("No transaction context".to_string()))
    }

    fn check_sequence(&self, _sequence: i32) -> Result<bool> {
        Err(Error::IllegalState("No transaction context".to_string()))
    }
}

/// Checker for full transaction signature/locktime/sequence validation.
#[derive(Debug)]
pub struct TransactionChecker<'a> {
    /// The transaction being validated.
    pub tx: &'a Tx,

    /// Cache for sighash computations.
    pub sig_hash_cache: &'a mut SigHashCache,

    /// Input index being checked.
    pub input: usize,

    /// Input value in satoshis.
    pub satoshis: i64,

    /// Require SIGHASH_FORKID (post-Genesis txs).
    pub require_sighash_forkid: bool,
}

impl<'a> TransactionChecker<'a> {
    /// Creates a new transaction checker.
    #[must_use]
    pub fn new(
        tx: &'a Tx,
        cache: &'a mut SigHashCache,
        input: usize,
        satoshis: i64,
        require_forkid: bool,
    ) -> Self {
        Self {
            tx,
            sig_hash_cache: cache,
            input,
            satoshis,
            require_sighash_forkid: require_forkid,
        }
    }
}

impl<'a> Checker for TransactionChecker<'a> {
    #[inline]
    fn check_sig(&mut self, sig: &[u8], pubkey: &[u8], script: &[u8]) -> Result<bool> {
        if sig.is_empty() {
            return Err(Error::ScriptError("Empty signature".to_string()));
        }

        let sighash_type = sig[sig.len() - 1];
        if self.require_sighash_forkid && (sighash_type & SIGHASH_FORKID) == 0 {
            return Err(Error::ScriptError("Missing SIGHASH_FORKID".to_string()));
        }

        let sig_hash = sighash(
            self.tx,
            self.input,
            script,
            self.satoshis,
            sighash_type,
            self.sig_hash_cache,
        )?;

        let der_sig = &sig[..sig.len() - 1];
        let secp = Secp256k1::verification_only();
        let signature =
            Signature::from_der(der_sig).map_err(|_| Error::ScriptError("Invalid DER".to_string()))?;
        let message = Message::from_digest(&sig_hash.0);
        let public_key =
            PublicKey::from_slice(pubkey).map_err(|_| Error::ScriptError("Invalid pubkey".to_string()))?;

        Ok(secp.verify_ecdsa(message, &signature, &public_key).is_ok())
    }

    #[inline]
    fn check_locktime(&self, locktime: i32) -> Result<bool> {
        if locktime < 0 {
            return Err(Error::ScriptError("Negative locktime".to_string()));
        }

        let tx_locktime = self.tx.lock_time as i32;
        let locktime_type = locktime >= LOCKTIME_THRESHOLD;
        let tx_type = tx_locktime >= LOCKTIME_THRESHOLD;

        if locktime_type != tx_type {
            return Err(Error::ScriptError("Locktime type mismatch".to_string()));
        }

        if locktime > tx_locktime {
            return Err(Error::ScriptError("Locktime exceeds tx".to_string()));
        }

        if self.tx.inputs[self.input].sequence == 0xffffffff {
            return Err(Error::ScriptError("Max sequence disables locktime".to_string()));
        }

        Ok(true)
    }

    #[inline]
    fn check_sequence(&self, sequence: i32) -> Result<bool> {
        if sequence < 0 {
            return Err(Error::ScriptError("Negative sequence".to_string()));
        }

        let sequence_u32 = sequence as u32;
        if sequence_u32 & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
            return Ok(true); // Disabled
        }

        if self.tx.version < 2 {
            return Err(Error::ScriptError("Version <2 disables CSV".to_string()));
        }

        let tx_seq = self.tx.inputs[self.input].sequence;
        if tx_seq & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
            return Err(Error::ScriptError("Tx sequence disabled".to_string()));
        }

        let seq_masked = sequence_u32 & 0x0000_ffff;
        let tx_masked = tx_seq & 0x0000_ffff;
        let seq_type = seq_masked >= SEQUENCE_LOCKTIME_TYPE_FLAG;
        let tx_type = tx_masked >= SEQUENCE_LOCKTIME_TYPE_FLAG;

        if seq_type != tx_type {
            return Err(Error::ScriptError("Sequence type mismatch".to_string()));
        }

        if seq_masked > tx_masked {
            return Err(Error::ScriptError("Sequence exceeds tx".to_string()));
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::{OutPoint, TxIn, TxOut};
    use crate::script::{op_codes::*, Script, NO_FLAGS, PREGENESIS_RULES};
    use crate::transaction::generate_signature;
    use crate::transaction::sighash::{
        SIGHASH_ALL, SIGHASH_ANYONECANPAY, SIGHASH_FORKID, SIGHASH_NONE, SIGHASH_SINGLE,
    };
    use crate::util::{hash160, Hash256};
    use secp256k1::{PublicKey, Secp256k1, SecretKey};
    use pretty_assertions::assert_eq;

    #[test]
    fn standard_p2pkh() {
        standard_p2pkh_test(SIGHASH_ALL);
        standard_p2pkh_test(SIGHASH_ALL | SIGHASH_FORKID);
    }

    fn standard_p2pkh_test(sighash_type: u8) {
        let secp = Secp256k1::new();
        let private_key = [1; 32];
        let secret_key = SecretKey::from_slice(&private_key).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &secret_key).serialize();
        let pkh = hash160(&pk);
        let mut lock_script = Script::new();
        lock_script.append(OP_DUP);
        lock_script.append(OP_HASH160);
        lock_script.append_data(&pkh.0).unwrap();
        lock_script.append(OP_EQUALVERIFY);
        lock_script.append(OP_CHECKSIG);
        let tx_1 = Tx {
            version: 1,
            inputs: vec![],
            outputs: vec![TxOut {
                satoshis: 10,
                lock_script,
            }],
            lock_time: 0,
        };
        let mut tx_2 = Tx {
            version: 1,
            inputs: vec![TxIn {
                prev_output: OutPoint {
                    hash: tx_1.hash(),
                    index: 0,
                },
                unlock_script: Script(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![],
            lock_time: 0,
        };
        let mut cache = SigHashCache::new();
        let lock_script_bytes = &tx_1.outputs[0].lock_script.0;
        let sig_hash = sighash(&tx_2, 0, lock_script_bytes, 10, sighash_type, &mut cache).unwrap();
        let sig = generate_signature(&private_key, &sig_hash, sighash_type).unwrap();
        let mut unlock_script = Script::new();
        unlock_script.append_data(&sig).unwrap();
        unlock_script.append_data(&pk).unwrap();
        tx_2.inputs[0].unlock_script = unlock_script;
        let mut cache = SigHashCache::new();
        let mut c = TransactionChecker::new(&tx_2, &mut cache, 0, 10, false);
        let mut script = Script::new();
        script.append_slice(&tx_2.inputs[0].unlock_script.0);
        script.append(OP_CODESEPARATOR);
        script.append_slice(lock_script_bytes);
        assert!(script.eval(&mut c, NO_FLAGS).is_ok());
    }

    #[test]
    fn multisig() {
        multisig_test(SIGHASH_ALL);
        multisig_test(SIGHASH_ALL | SIGHASH_FORKID);
    }

    fn multisig_test(sighash_type: u8) {
        let secp = Secp256k1::new();
        let private_key1 = [1; 32];
        let private_key2 = [2; 32];
        let private_key3 = [3; 32];
        let secret_key1 = SecretKey::from_slice(&private_key1).unwrap();
        let secret_key2 = SecretKey::from_slice(&private_key2).unwrap();
        let secret_key3 = SecretKey::from_slice(&private_key3).unwrap();
        let pk1 = PublicKey::from_secret_key(&secp, &secret_key1).serialize();
        let pk2 = PublicKey::from_secret_key(&secp, &secret_key2).serialize();
        let pk3 = PublicKey::from_secret_key(&secp, &secret_key3).serialize();
        let mut lock_script = Script::new();
        lock_script.append(OP_2);
        lock_script.append_data(&pk1).unwrap();
        lock_script.append_data(&pk2).unwrap();
        lock_script.append_data(&pk3).unwrap();
        lock_script.append(OP_3);
        lock_script.append(OP_CHECKMULTISIG);
        let tx_1 = Tx {
            version: 1,
            inputs: vec![],
            outputs: vec![TxOut {
                satoshis: 10,
                lock_script,
            }],
            lock_time: 0,
        };
        let mut tx_2 = Tx {
            version: 1,
            inputs: vec![TxIn {
                prev_output: OutPoint {
                    hash: tx_1.hash(),
                    index: 0,
                },
                unlock_script: Script(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![],
            lock_time: 0,
        };
        let mut cache = SigHashCache::new();
        let lock_script_bytes = &tx_1.outputs[0].lock_script.0;
        let sig_hash = sighash(&tx_2, 0, lock_script_bytes, 10, sighash_type, &mut cache).unwrap();
        let sig1 = generate_signature(&private_key1, &sig_hash, sighash_type).unwrap();
        let sig3 = generate_signature(&private_key3, &sig_hash, sighash_type).unwrap();
        let mut unlock_script = Script::new();
        unlock_script.append(OP_0);
        unlock_script.append_data(&sig1).unwrap();
        unlock_script.append_data(&sig3).unwrap();
        tx_2.inputs[0].unlock_script = unlock_script;
        let mut cache = SigHashCache::new();
        let mut c = TransactionChecker::new(&tx_2, &mut cache, 0, 10, false);
        let mut script = Script::new();
        script.append_slice(&tx_2.inputs[0].unlock_script.0);
        script.append(OP_CODESEPARATOR);
        script.append_slice(lock_script_bytes);
        assert!(script.eval(&mut c, NO_FLAGS).is_ok());
    }

    #[test]
    fn blank_check() {
        blank_check_test(SIGHASH_NONE | SIGHASH_ANYONECANPAY);
        blank_check_test(SIGHASH_NONE | SIGHASH_ANYONECANPAY | SIGHASH_FORKID);
    }

    fn blank_check_test(sighash_type: u8) {
        let secp = Secp256k1::new();
        let private_key1 = [1; 32];
        let secret_key1 = SecretKey::from_slice(&private_key1).unwrap();
        let pk1 = PublicKey::from_secret_key(&secp, &secret_key1).serialize();
        let pkh1 = hash160(&pk1);
        let private_key2 = [2; 32];
        let secret_key2 = SecretKey::from_slice(&private_key2).unwrap();
        let pk2 = PublicKey::from_secret_key(&secp, &secret_key2).serialize();
        let pkh2 = hash160(&pk2);
        let mut lock_script1 = Script::new();
        lock_script1.append(OP_DUP);
        lock_script1.append(OP_HASH160);
        lock_script1.append_data(&pkh1.0).unwrap();
        lock_script1.append(OP_EQUALVERIFY);
        lock_script1.append(OP_CHECKSIG);
        let mut lock_script2 = Script::new();
        lock_script2.append(OP_DUP);
        lock_script2.append(OP_HASH160);
        lock_script2.append_data(&pkh2.0).unwrap();
        lock_script2.append(OP_EQUALVERIFY);
        lock_script2.append(OP_CHECKSIG);
        let tx_1 = Tx {
            version: 1,
            inputs: vec![],
            outputs: vec![
                TxOut {
                    satoshis: 10,
                    lock_script: lock_script1,
                },
                TxOut {
                    satoshis: 20,
                    lock_script: lock_script2,
                },
            ],
            lock_time: 0,
        };
        let mut tx_2 = Tx {
            version: 1,
            inputs: vec![TxIn {
                prev_output: OutPoint {
                    hash: tx_1.hash(),
                    index: 0,
                },
                unlock_script: Script(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![],
            lock_time: 0,
        };
        // Sign the first input
        let mut cache = SigHashCache::new();
        let lock_script_bytes = &tx_1.outputs[0].lock_script.0;
        let sig_hash1 = sighash(&tx_2, 0, lock_script_bytes, 10, sighash_type, &mut cache).unwrap();
        let sig1 = generate_signature(&private_key1, &sig_hash1, sighash_type).unwrap();
        let mut unlock_script1 = Script::new();
        unlock_script1.append_data(&sig1).unwrap();
        unlock_script1.append_data(&pk1).unwrap();
        tx_2.inputs[0].unlock_script = unlock_script1;
        // Add another input and sign that separately
        tx_2.inputs.push(TxIn {
            prev_output: OutPoint {
                hash: tx_1.hash(),
                index: 1,
            },
            unlock_script: Script(vec![]),
            sequence: 0xffffffff,
        });
        let mut cache = SigHashCache::new();
        let lock_script_bytes2 = &tx_1.outputs[1].lock_script.0;
        let sig_hash2 =
            sighash(&tx_2, 1, lock_script_bytes2, 20, sighash_type, &mut cache).unwrap();
        let sig2 = generate_signature(&private_key2, &sig_hash2, sighash_type).unwrap();
        let mut unlock_script2 = Script::new();
        unlock_script2.append_data(&sig2).unwrap();
        unlock_script2.append_data(&pk2).unwrap();
        tx_2.inputs[1].unlock_script = unlock_script2;
        let mut cache = SigHashCache::new();
        let mut c1 = TransactionChecker::new(&tx_2, &mut cache, 0, 10, false);
        let mut script1 = Script::new();
        script1.append_slice(&tx_2.inputs[0].unlock_script.0);
        script1.append(OP_CODESEPARATOR);
        script1.append_slice(&tx_1.outputs[0].lock_script.0);
        assert!(script1.eval(&mut c1, NO_FLAGS).is_ok());
        let mut cache = SigHashCache::new();
        let mut c2 = TransactionChecker::new(&tx_2, &mut cache, 1, 20, false);
        let mut script2 = Script::new();
        script2.append_slice(&tx_2.inputs[1].unlock_script.0);
        script2.append(OP_CODESEPARATOR);
        script2.append_slice(&tx_1.outputs[1].lock_script.0);
        assert!(script2.eval(&mut c2, NO_FLAGS).is_ok());
    }

    #[test]
    fn check_locktime() {
        let mut lock_script = Script::new();
        lock_script.append_num(500).unwrap();
        lock_script.append(OP_CHECKLOCKTIMEVERIFY);
        lock_script.append(OP_1);
        let mut tx = Tx {
            version: 1,
            inputs: vec![TxIn {
                prev_output: OutPoint {
                    hash: Hash256([0; 32]),
                    index: 0,
                },
                unlock_script: Script(vec![]),
                sequence: 0,
            }],
            outputs: vec![],
            lock_time: 499,
        };
        let mut cache = SigHashCache::new();
        let mut c = TransactionChecker::new(&tx, &mut cache, 0, 0, false);
        assert_eq!(
            lock_script.eval(&mut c, PREGENESIS_RULES).unwrap_err().to_string(),
            "locktime greater than tx"
        );
        tx.lock_time = 500;
        let mut cache = SigHashCache::new();
        let mut c = TransactionChecker::new(&tx, &mut cache, 0, 0, false);
        assert!(lock_script.eval(&mut c, PREGENESIS_RULES).is_ok());
    }

    #[test]
    fn check_sequence() {
        let mut lock_script = Script::new();
        lock_script
            .append_num((500 | SEQUENCE_LOCKTIME_TYPE_FLAG as i32) as i32)
            .unwrap();
        lock_script.append(OP_CHECKSEQUENCEVERIFY);
        lock_script.append(OP_1);
        let mut tx = Tx {
            version: 2,
            inputs: vec![TxIn {
                prev_output: OutPoint {
                    hash: Hash256([0; 32]),
                    index: 0,
                },
                unlock_script: Script(vec![]),
                sequence: (499 | SEQUENCE_LOCKTIME_TYPE_FLAG) as u32,
            }],
            outputs: vec![],
            lock_time: 0,
        };
        let mut cache = SigHashCache::new();
        let mut c = TransactionChecker::new(&tx, &mut cache, 0, 0, false);
        assert_eq!(
            lock_script.eval(&mut c, PREGENESIS_RULES).unwrap_err().to_string(),
            "sequence greater than tx"
        );
        tx.inputs[0].sequence = (500 | SEQUENCE_LOCKTIME_TYPE_FLAG) as u32;
        let mut cache = SigHashCache::new();
        let mut c = TransactionChecker::new(&tx, &mut cache, 0, 0, false);
        assert!(lock_script.eval(&mut c, PREGENESIS_RULES).is_ok());
    }
}

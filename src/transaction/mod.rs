//! Transaction building and signing for Bitcoin SV.
///
/// Supports P2PKH/P2SH, sighash computation (BIP-143 + forkid), and ECDSA signing.
///
/// # Examples
///
/// Sign a P2PKH transaction:
/// ```
/// use nour::messages::{Tx, TxIn};
/// use nour::transaction::{generate_signature, p2pkh::{create_lock_script, create_unlock_script}, sighash::{sighash, SigHashCache, SIGHASH_FORKID, SIGHASH_NONE}};
/// use nour::util::hash160;
///
/// // Use real values
/// let mut tx = Tx {
/// inputs: vec![TxIn { ..Default::default() }],
/// ..Default::default()
/// };
/// let private_key = [1; 32];
/// let public_key = [1; 33];
///
/// let lock_script = create_lock_script(&hash160(&public_key));
/// let mut cache = SigHashCache::new();
/// let sighash_type = SIGHASH_NONE | SIGHASH_FORKID;
/// let sighash_val = sighash(&tx, 0, &lock_script.0, 0, sighash_type, &mut cache).unwrap();
/// let signature = generate_signature(&private_key, &sighash_val, sighash_type).unwrap();
/// tx.inputs[0].unlock_script = create_unlock_script(&signature, &public_key);
/// ```
pub mod p2pkh;
pub mod sighash;
use crate::util::{Error, Hash256, Result};
use secp256k1::{Message, Secp256k1, SecretKey};
/// Generates DER-encoded ECDSA signature for sighash + type.
///
/// Normalizes S (low); errors on invalid key.
///
/// # Errors
/// `Error::ScriptError` for invalid private key.
#[must_use]
#[inline]
pub fn generate_signature(private_key: &[u8; 32], sighash: &Hash256, sighash_type: u8) -> Result<Vec<u8>> {
    let secp = Secp256k1::signing_only();
    let secret_key = SecretKey::from_byte_array(*private_key).map_err(|_| Error::BadData("Invalid private key".to_string()))?;
    let message = Message::from_digest(sighash.0);
    let mut signature = secp.sign_ecdsa(message, &secret_key);
    signature.normalize_s();
    let mut der = signature.serialize_der().to_vec();
    der.push(sighash_type);
    Ok(der)
}

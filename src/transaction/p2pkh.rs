//! Pay-to-Public-Key-Hash (P2PKH) transaction scripts for Bitcoin SV.
///
/// Standard for "sending to an address"; creates/checks lock/unlock scripts.
/// Note: For P2SH, see BIP-16.
use crate::script::op_codes::{OP_CHECKSIG, OP_DUP, OP_EQUALVERIFY, OP_HASH160, OP_PUSH};
use crate::script::{next_op, Script};
use crate::util::{Error, Hash160, Result};
/// Creates P2PKH lock script (DUP HASH160 [hash] EQUALVERIFY CHECKSIG).
#[must_use]
#[inline]
pub fn create_lock_script(address: &Hash160) -> Script {
    let mut script = Script::new();
    script.append(OP_DUP);
    script.append(OP_HASH160);
    script.append(OP_PUSH + 20);
    script.append_slice(&address.0);
    script.append(OP_EQUALVERIFY);
    script.append(OP_CHECKSIG);
    script
}
/// Creates P2PKH unlock script (push sig + pubkey).
#[must_use]
#[inline]
pub fn create_unlock_script(sig: &[u8], public_key: &[u8]) -> Script {
    let mut script = Script::new();
    script.append_data(sig).unwrap();
    script.append_data(public_key).unwrap();
    script
}
/// Checks if script is P2PKH lock (len=25, ops match).
#[must_use]
#[inline]
pub fn check_lock_script(lock_script: &[u8]) -> bool {
    lock_script.len() == 25
        && lock_script[0] == OP_DUP
        && lock_script[1] == OP_HASH160
        && lock_script[2] == OP_PUSH + 20
        && lock_script[23] == OP_EQUALVERIFY
        && lock_script[24] == OP_CHECKSIG
}
/// Checks if script is P2PKH unlock (sig push 71-73B + pubkey 33/65B).
#[must_use]
#[inline]
pub fn check_unlock_script(unlock_script: &[u8]) -> bool {
    if unlock_script.is_empty() {
        return false;
    }
    let sig_len = unlock_script[0];
    if sig_len < OP_PUSH + 71 || sig_len > OP_PUSH + 73 {
        return false;
    }
    let i = next_op(0, unlock_script);
    if i >= unlock_script.len() {
        return false;
    }
    let pk_len = unlock_script[i];
    if pk_len != OP_PUSH + 33 && pk_len != OP_PUSH + 65 {
        return false;
    }
    next_op(i, unlock_script) == unlock_script.len()
}
/// Checks if P2PKH lock matches hash160.
#[must_use]
#[inline]
pub fn check_lock_script_addr(hash160: &Hash160, lock_script: &[u8]) -> bool {
    check_lock_script(lock_script) && lock_script[3..23] == hash160.0
}
/// Checks if P2PKH unlock matches pubkey.
#[must_use]
#[inline]
pub fn check_unlock_script_addr(pubkey: &[u8], unlock_script: &[u8]) -> bool {
    if !check_unlock_script(unlock_script) {
        return false;
    }
    let i = next_op(0, unlock_script);
    unlock_script[i + 1..] == *pubkey
}
/// Extracts pubkey from P2PKH unlock.
#[must_use]
pub fn extract_pubkey(unlock_script: &[u8]) -> Result<Vec<u8>> {
    if !check_unlock_script(unlock_script) {
        return Err(Error::BadData("Not P2PKH unlock".to_string()));
    }
    let i = next_op(0, unlock_script);
    Ok(unlock_script[i + 1..].to_vec())
}
/// Extracts hash160 from P2PKH lock.
#[must_use]
pub fn extract_pubkeyhash(lock_script: &[u8]) -> Result<Hash160> {
    if !check_lock_script(lock_script) {
        return Err(Error::BadData("Not P2PKH lock".to_string()));
    }
    let mut hash160 = Hash160([0; 20]);
    hash160.0.copy_from_slice(&lock_script[3..23]);
    Ok(hash160)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::op_codes::OP_1;
    #[test]
    fn check_lock_script_test() {
        let mut s = Script::new();
        assert!(!check_lock_script(&s.0));
        s.append(OP_DUP);
        s.append(OP_HASH160);
        s.append(OP_PUSH + 20);
        s.append_slice(&[0; 20]);
        s.append(OP_EQUALVERIFY);
        s.append(OP_CHECKSIG);
        assert!(check_lock_script(&s.0));
        s.append(OP_1);
        assert!(!check_lock_script(&s.0));
    }
    #[test]
    fn check_unlock_script_test() {
        assert!(!check_unlock_script(&Script::new().0));
        let mut sig71pkh33 = Script::new();
        sig71pkh33.append(OP_PUSH + 71);
        sig71pkh33.append_slice(&[0; 71]);
        assert!(!check_unlock_script(&sig71pkh33.0));
        sig71pkh33.append(OP_PUSH + 33);
        sig71pkh33.append_slice(&[0; 33]);
        assert!(check_unlock_script(&sig71pkh33.0));
        sig71pkh33.append(OP_1);
        assert!(!check_unlock_script(&sig71pkh33.0));
        let mut sig73pkh65 = Script::new();
        sig73pkh65.append(OP_PUSH + 73);
        sig73pkh65.append_slice(&[0; 73]);
        sig73pkh65.append(OP_PUSH + 65);
        sig73pkh65.append_slice(&[0; 65]);
        assert!(check_unlock_script(&sig73pkh65.0));
        let mut sig72pkh30 = Script::new();
        sig72pkh30.append(OP_PUSH + 72);
        sig72pkh30.append_slice(&[0; 72]);
        sig72pkh30.append(OP_PUSH + 30);
        sig72pkh30.append_slice(&[0; 30]);
        assert!(!check_unlock_script(&sig72pkh30.0));
    }
    #[test]
    fn check_lock_script_addr_test() {
        let s = create_lock_script(&Hash160([5; 20]));
        assert!(check_lock_script_addr(&Hash160([5; 20]), &s.0));
    }
    #[test]
    fn check_unlock_script_addr_test() {
        let mut s = Script::new();
        s.append(OP_PUSH + 71);
        s.append_slice(&[5; 71]);
        s.append(OP_PUSH + 65);
        s.append_slice(&[6; 65]);
        assert!(check_unlock_script_addr(&[6; 65], &s.0));
        assert!(!check_unlock_script_addr(&[7; 65], &s.0));
    }
}

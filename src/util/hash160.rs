//! Hash160 computation for Bitcoin SV (SHA256 then RIPEMD160).

use bitcoin_hashes::{hash160 as bh_hash160, Hash as BHHash}; // SIMD opt
use std::fmt;

#[derive(Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hash160(pub [u8; 20]);

/// Computes Hash160 (RIPEMD160(SHA256(data))).
#[must_use]
#[inline]
pub fn hash160(data: &[u8]) -> Hash160 {
    let h = bh_hash160::Hash::hash(data).to_byte_array();
    Hash160(h)
}

impl From<[u8; 20]> for Hash160 {
    fn from(bytes: [u8; 20]) -> Self {
        Hash160(bytes)
    }
}

impl fmt::Debug for Hash160 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex; // For cleaner hex literals in tests
    use pretty_assertions::assert_eq;

    #[test]
    fn tohash160() {
        let pubkey = hex!("126999eabe3f84a3a9f5c09e87faab27484818a0ec1d67b94c9a02e40268499d98538cf770198550adfb9d1d473e5e926bb00e4c58baec1fb42ffa6069781003e4");
        let expected = hex!("3c231b5e624a42e99a87160c6e4231718a6d77c0");
        assert_eq!(hash160(&pubkey).0, expected);
    }

    #[test]
    fn test_from_array() {
        let bytes = [0u8; 20];
        let hash160: Hash160 = bytes.into();
        assert_eq!(hash160.0, bytes);
    }
}

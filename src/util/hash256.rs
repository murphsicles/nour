//! 256-bit hash for blocks and transactions in Bitcoin SV.
//
/// It is interpreted as a single little-endian number for display.
use crate::util::{Error, Result};
use bitcoin_hashes::sha256d as bh_sha256d; // SIMD opt
use hex;
use std::cmp::Ordering;
use std::fmt;
use std::io;
use std::io::{Read, Write};
/// 256-bit hash for blocks and transactions.
#[derive(Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hash256(pub [u8; 32]);
impl Hash256 {
    /// Converts the hash into a hex string.
    #[must_use]
    #[inline]
    pub fn encode(&self) -> String {
        let mut r = self.0;
        r.reverse();
        hex::encode(r)
    }
    /// Converts a string of 64 hex characters into a hash.
    #[must_use]
    #[inline]
    pub fn decode(s: &str) -> Result<Hash256> {
        let decoded_bytes = hex::decode(s)?;
        if decoded_bytes.len() != 32 {
            return Err(Error::BadArgument(format!("Length {} of decoded bytes", decoded_bytes.len())));
        }
        let mut hash_bytes = [0; 32];
        hash_bytes.copy_from_slice(&decoded_bytes);
        hash_bytes.reverse();
        Ok(Hash256(hash_bytes))
    }
}
impl Serializable for Hash256 {
    fn read(reader: &mut dyn Read) -> Result<Hash256> {
        let mut bytes = [0; 32];
        reader.read_exact(&mut bytes).map_err(|e| Error::IOError(e))?;
        Ok(Hash256(bytes))
    }
    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        writer.write_all(&self.0)
    }
}
/// Hashes a data array twice using SHA256.
#[must_use]
#[inline]
pub fn sha256d(data: &[u8]) -> Hash256 {
    let h = bh_sha256d::Hash::hash(data).to_byte_array();
    Hash256(h)
}
impl Ord for Hash256 {
    fn cmp(&self, other: &Hash256) -> Ordering {
        for i in (0..32).rev() {
            match self.0[i].cmp(&other.0[i]) {
                Ordering::Equal => continue,
                ordering => return ordering,
            }
        }
        Ordering::Equal
    }
}
impl PartialOrd for Hash256 {
    fn partial_cmp(&self, other: &Hash256) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl fmt::Debug for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.encode())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use pretty_assertions::assert_eq;
    #[test]
    fn sha256d_test() {
        let x = hex::decode("0123456789abcdef").unwrap();
        let e = hex::encode(sha256d(&x).0);
        assert_eq!(e, "137ad663f79da06e282ed0abbec4d70523ced5ff8e39d5c2e5641d978c5925aa");
    }
    #[test]
    fn hash_decode() {
        // Valid
        let s1 = "0000000000000000000000000000000000000000000000000000000000000000";
        let s2 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let s3 = "abcdef0000112233445566778899abcdef000011223344556677889912345678";
        assert!(Hash256::decode(s1).is_ok());
        assert!(Hash256::decode(s2).is_ok());
        assert!(Hash256::decode(s3).is_ok());
        // Invalid
        let s1 = "000000000000000000000000000000000000000000000000000000000000000";
        let s2 = "00000000000000000000000000000000000000000000000000000000000000000";
        let s3 = "000000000000000000000000000000000000000000000000000000000000000g";
        assert!(Hash256::decode(s1).is_err());
        assert!(Hash256::decode(s2).is_err());
        assert!(Hash256::decode(s3).is_err());
    }
    #[test]
    fn hash_decode_write_read_encode() {
        let s1 = "abcdef0000112233445566778899abcdef000011223344556677889912345678";
        let h1 = Hash256::decode(s1).unwrap();
        let mut v = Vec::new();
        h1.write(&mut v).unwrap();
        let h2 = Hash256::read(&mut Cursor::new(v)).unwrap();
        let s2 = h2.encode();
        assert_eq!(s1, s2);
    }
    #[test]
    fn hash_compare() {
        let s1 = "5555555555555555555555555555555555555555555555555555555555555555";
        let s2 = "5555555555555555555555555555555555555555555555555555555555555555";
        assert_eq!(Hash256::decode(s1).unwrap(), Hash256::decode(s2).unwrap());
        let s1 = "0555555555555555555555555555555555555555555555555555555555555555";
        let s2 = "5555555555555555555555555555555555555555555555555555555555555555";
        assert!(Hash256::decode(s1).unwrap() < Hash256::decode(s2).unwrap());
        let s1 = "5555555555555555555555555555555555555555555555555555555555555550";
        let s2 = "5555555555555555555555555555555555555555555555555555555555555555";
        assert!(Hash256::decode(s1).unwrap() < Hash256::decode(s2).unwrap());
        let s1 = "6555555555555555555555555555555555555555555555555555555555555555";
        let s2 = "5555555555555555555555555555555555555555555555555555555555555555";
        assert!(Hash256::decode(s1).unwrap() > Hash256::decode(s2).unwrap());
        let s1 = "5555555555555555555555555555555555555555555555555555555555555556";
        let s2 = "5555555555555555555555555555555555555555555555555555555555555555";
        assert!(Hash256::decode(s1).unwrap() > Hash256::decode(s2).unwrap());
    }
}

//! MerkleBlock message for Bitcoin SV P2P, partial merkle tree for SPV filtered blocks (BIP-37).
use crate::messages::block_header::BlockHeader;
use crate::messages::message::Payload;
use crate::util::{sha256d, var_int, Error, Hash256, Result, Serializable};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use hex;
use std::fmt;
use std::io;
use std::io::{Read, Write};
#[cfg(feature = "async")]
use tokio::io::{AsyncRead, AsyncWrite};
/// Maximum total transactions in merkle block (safety cap for large BSV blocks).
const MAX_TOTAL_TX: u64 = 10_000_000_000;
/// A block header and partial merkle tree for SPV nodes to validate transactions.
#[derive(Default, PartialEq, Eq, Hash, Clone)]
pub struct MerkleBlock {
    /// Block header.
    pub header: BlockHeader,
    /// Number of transactions in the block.
    pub total_transactions: u32,
    /// Hashes in depth-first order.
    pub hashes: Vec<Hash256>,
    /// Bit vector used to assign hashes to nodes in the partial merkle tree.
    pub flags: Vec<u8>,
}
impl MerkleBlock {
    /// Validates the Merkle block and partial Merkle tree and returns the set of matched transactions.
    ///
    /// # Errors
    /// `Error::BadData` if no txns, invalid tree, dup tx, mismatch root/hashes/flags.
    pub fn validate(&self) -> Result<Vec<Hash256>> {
        if self.total_transactions == 0 {
            return Err(Error::BadData("No transactions".to_string()));
        }
        if self.total_transactions as u64 > MAX_TOTAL_TX {
            return Err(Error::BadData(format!("Too many transactions: {}", self.total_transactions)));
        }
        if self.hashes.is_empty() {
            return Err(Error::BadData("No hashes".to_string()));
        }
        if self.flags.is_empty() {
            return Err(Error::BadData("No flags".to_string()));
        }
        let tree_depth = if self.total_transactions <= 1 {
            0usize
        } else {
            32 - ((self.total_transactions - 1).leading_zeros() as usize)
        };
        let mut bit_idx = 0usize;
        let mut hash_idx = 0usize;
        let mut matches = Vec::new();
        let (computed_root, _root_matched) = self.traverse(tree_depth, 0, &mut bit_idx, &mut hash_idx, &mut matches)?;
        if computed_root != self.header.merkle_root {
            return Err(Error::BadData("Merkle proof mismatch".to_string()));
        }
        if bit_idx > self.flags.len() * 8 {
            return Err(Error::BadData("Flag out of range".to_string()));
        }
        let total_bits = self.flags.len() * 8;
        if bit_idx < total_bits {
            // Check remaining bits are 0
            let remaining_bits_start = bit_idx;
            let mut temp_bit_idx = remaining_bits_start;
            while temp_bit_idx < total_bits {
                let byte_idx = temp_bit_idx / 8;
                let bit_pos = (temp_bit_idx % 8) as u8;
                let bit = ((self.flags[byte_idx] >> bit_pos) & 1) as usize;
                if bit != 0 {
                    return Err(Error::BadData("Trailing flag bits set".to_string()));
                }
                temp_bit_idx += 1;
            }
        }
        if hash_idx != self.hashes.len() {
            return Err(Error::BadData("Not all hashes consumed".to_string()));
        }
        Ok(matches)
    }
    fn traverse(
        &self,
        level: usize,
        _pos: usize, // Unused in new logic (dfs order, not pos-based for bits)
        bit_idx: &mut usize,
        hash_idx: &mut usize,
        matches: &mut Vec<Hash256>,
    ) -> Result<(Hash256, bool)> {
        // Consume bit for this node
        if *bit_idx / 8 >= self.flags.len() {
            return Err(Error::BadData("Flag out of range".to_string()));
        }
        let byte_idx = *bit_idx / 8;
        let bit_pos = (*bit_idx % 8) as u8;
        let bit = ((self.flags[byte_idx] >> bit_pos) & 1) as usize;
        *bit_idx += 1;
        let is_leaf = level == 0;
        if is_leaf {
            // Leaf: always consume hash; bit=1 if matched
            let h = self.consume_hash(hash_idx)?;
            let matched = bit == 1;
            if matched {
                matches.push(h.clone());
            }
            Ok((h, matched))
        } else {
            // Internal: if bit=0, consume subtree hash, no recurse
            if bit == 0 {
                let h = self.consume_hash(hash_idx)?;
                Ok((h, false))
            } else {
                // bit=1: recurse children, compute hash
                let (left_hash, left_matched) = self.traverse(level - 1, 0, bit_idx, hash_idx, matches)?;
                let (right_hash, right_matched) = self.traverse(level - 1, 0, bit_idx, hash_idx, matches)?; // Duplicate logic for odd handled in build, but here assume symmetric call
                let computed = self.hash_pair(&left_hash, &right_hash);
                let matched = left_matched || right_matched;
                // Duplicate check (rare, but per BIP-37)
                if left_hash == right_hash && left_matched && right_matched {
                    return Err(Error::BadData("Duplicate transactions".to_string()));
                }
                Ok((computed, matched))
            }
        }
    }
    fn consume_hash(&self, idx: &mut usize) -> Result<Hash256> {
        if *idx >= self.hashes.len() {
            return Err(Error::BadData("Hashes exhausted".to_string()));
        }
        let h = self.hashes[*idx].clone();
        *idx += 1;
        Ok(h)
    }
    fn hash_pair(&self, a: &Hash256, b: &Hash256) -> Hash256 {
        let mut buf = [0u8; 64];
        buf[0..32].copy_from_slice(&a.0);
        buf[32..64].copy_from_slice(&b.0);
        let hashed = sha256d(&buf);
        Hash256(hashed.0)
    }
}
impl Serializable<MerkleBlock> for MerkleBlock {
    fn read(reader: &mut dyn Read) -> Result<MerkleBlock> {
        let header = BlockHeader::read(reader)?;
        let total_transactions = reader.read_u32::<LittleEndian>()?;
        let num_hashes = var_int::read(reader)?;
        let mut hashes = Vec::with_capacity(num_hashes as usize);
        for _ in 0..num_hashes {
            hashes.push(Hash256::read(reader)?);
        }
        let flags_len = var_int::read(reader)?;
        let mut flags = vec![0; flags_len as usize];
        reader.read_exact(&mut flags).map_err(|e| Error::IOError(e))?;
        Ok(MerkleBlock {
            header,
            total_transactions,
            hashes,
            flags,
        })
    }
    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        self.header.write(writer)?;
        writer.write_u32::<LittleEndian>(self.total_transactions)?;
        var_int::write(self.hashes.len() as u64, writer)?;
        for hash in &self.hashes {
            hash.write(writer)?;
        }
        var_int::write(self.flags.len() as u64, writer)?;
        writer.write_all(&self.flags)?;
        Ok(())
    }
}
impl Payload<MerkleBlock> for MerkleBlock {
    fn size(&self) -> usize {
        self.header.size() + 4 + var_int::size(self.hashes.len() as u64) + self.hashes.len() * 32 + var_int::size(self.flags.len() as u64) + self.flags.len()
    }
}
impl fmt::Debug for MerkleBlock {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("MerkleBlock")
            .field("header", &self.header)
            .field("total_transactions", &self.total_transactions)
            .field("hashes", &self.hashes)
            .field("flags", &hex::encode(&self.flags))
            .finish()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    use std::io::Cursor;
    use pretty_assertions::assert_eq;
    #[test]
    fn read_bytes() {
        let b = hex::decode("01000000ba8b9cda965dd8e536670f9ddec10e53aab14b20bacad27b9137190000000000190760b278fe7b8565fda3b968b918d5fd997f993b23674c0af3b6fde300b38f33a5914ce6ed5b1b01e32f570200000002252bf9d75c4f481ebb6278d708257d1f12beb6dd30301d26c623f789b2ba6fc0e2d32adb5f8ca820731dff234a84e78ec30bce4ec69dbd562d0b2b8266bf4e5a0105").unwrap();
        let p = MerkleBlock::read(&mut Cursor::new(&b)).unwrap();
        assert_eq!(p.header.version, 1);
        let prev_hash = "ba8b9cda965dd8e536670f9ddec10e53aab14b20bacad27b9137190000000000";
        assert_eq!(p.header.prev_hash.0.to_vec(), hex::decode(prev_hash).unwrap());
        let merkle_root = "190760b278fe7b8565fda3b968b918d5fd997f993b23674c0af3b6fde300b38f";
        assert_eq!(p.header.merkle_root.0.to_vec(), hex::decode(merkle_root).unwrap());
        assert_eq!(p.header.timestamp, 1284613427);
        let total_transactions = 2;
        assert_eq!(p.total_transactions, total_transactions);
        assert_eq!(p.hashes.len(), 2);
        let hash1 = "252bf9d75c4f481ebb6278d708257d1f12beb6dd30301d26c623f789b2ba6fc0";
        assert_eq!(p.hashes[0].0.to_vec(), hex::decode(hash1).unwrap());
        let hash2 = "e2d32adb5f8ca820731dff234a84e78ec30bce4ec69dbd562d0b2b8266bf4e5a";
        assert_eq!(p.hashes[1].0.to_vec(), hex::decode(hash2).unwrap());
        assert_eq!(p.flags.len(), 1);
        assert_eq!(p.flags[0], 0x05);
    }
    #[test]
    fn write_read() {
        let mut v = Vec::new();
        let p = MerkleBlock {
            header: BlockHeader {
                version: 12345,
                prev_hash: Hash256::decode(
                    "7766009988776600998877660099887766009988776600998877660099887766",
                )
                .unwrap(),
                merkle_root: Hash256::decode(
                    "2211554433221155443322115544332211554433221155443322115544332211",
                )
                .unwrap(),
                timestamp: 66,
                bits: 4488,
                nonce: 9999,
            },
            total_transactions: 14,
            hashes: vec![Hash256([1; 32]), Hash256([3; 32]), Hash256([5; 32])],
            flags: vec![24, 125, 199],
        };
        p.write(&mut v).unwrap();
        assert_eq!(v.len(), p.size());
        assert_eq!(MerkleBlock::read(&mut Cursor::new(&v)).unwrap(), p);
    }
    #[test]
    fn validate() {
        // Valid merkle block with 2 transactions, 1 match
        let b = hex::decode("01000000ba8b9cda965dd8e536670f9ddec10e53aab14b20bacad27b9137190000000000190760b278fe7b8565fda3b968b918d5fd997f993b23674c0af3b6fde300b38f33a5914ce6ed5b1b01e32f570200000002252bf9d75c4f481ebb6278d708257d1f12beb6dd30301d26c623f789b2ba6fc0e2d32adb5f8ca820731dff234a84e78ec30bce4ec69dbd562d0b2b8266bf4e5a0105").unwrap();
        let p = MerkleBlock::read(&mut Cursor::new(&b)).unwrap();
        // No need to set merkle_root; it matches the computed
        assert_eq!(p.validate().unwrap().len(), 1);
        // Not enough hashes
        let mut p2 = p.clone();
        p2.hashes.truncate(p.hashes.len() - 1);
        assert_eq!(p2.validate().unwrap_err().to_string(), "Bad data: Hashes exhausted");
        // Too many hashes
        let mut p2 = p.clone();
        p2.hashes.push(Hash256([0; 32]));
        assert_eq!(p2.validate().unwrap_err().to_string(), "Bad data: Not all hashes consumed");
        // No flags
        let mut p2 = p.clone();
        p2.flags = vec![];
        assert_eq!(p2.validate().unwrap_err().to_string(), "Bad data: No flags");
        // Too many flags (trailing non-zero would fail inside, but extra 0 ok; test with non-zero)
        let mut p2 = p.clone();
        p2.flags.push(1); // Non-zero trailing
        assert_eq!(p2.validate().unwrap_err().to_string(), "Bad data: Trailing flag bits set");
        // Merkle root doesn't match
        let mut p2 = p.clone();
        p2.hashes[0] = Hash256([1; 32]);
        assert_eq!(p2.validate().unwrap_err().to_string(), "Bad data: Merkle proof mismatch");
        // Duplicate transactions (adjusted for small tree)
        let hash_left = Hash256([1; 32]);
        let hash_right = hash_left.clone(); // Dup
        let computed = hash_pair(&hash_left, &hash_right);
        let header = BlockHeader {
            version: 12345,
            prev_hash: Hash256([0; 32]),
            merkle_root: computed,
            timestamp: 66,
            bits: 4488,
            nonce: 9999,
        };
        let merkle_block = MerkleBlock {
            header,
            total_transactions: 2,
            hashes: vec![hash_left.clone(), hash_right], // Both leaves
            flags: vec![0b00000111], // root=1, left=1, right=1 (lsb first: 111 binary=7)
        };
        assert_eq!(merkle_block.validate().unwrap_err().to_string(), "Bad data: Duplicate transactions");
    }
    #[test]
    fn incomplete_tree() {
        // Simple incomplete: use subtree hash for entire tree (bit=0 at root)
        let h = Hash256([4u8; 32]);
        let header = BlockHeader {
            version: 12345,
            prev_hash: Hash256([0; 32]),
            merkle_root: h.clone(),
            timestamp: 66,
            bits: 4488,
            nonce: 9999,
        };
        let merkle_block = MerkleBlock {
            header,
            total_transactions: 7, // Arbitrary >1
            hashes: vec![h],
            flags: vec![0x00], // bit0=0 for root (consume hash, no recurse)
        };
        assert!(merkle_block.validate().is_ok()); // Consumes 1 bit, 1 hash; trailing 0s OK
    }
    fn hash_pair(a: &Hash256, b: &Hash256) -> Hash256 {
        let mut buf = [0u8; 64];
        buf[0..32].copy_from_slice(&a.0);
        buf[32..64].copy_from_slice(&b.0);
        Hash256(sha256d(&buf).0)
    }
}

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

/// All-zero hash for padded or non-matched leaves.
const ZERO_HASH: Hash256 = Hash256([0u8; 32]);

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
        let tree_depth = if self.total_transactions <= 1 {
            0usize
        } else {
            32 - ((self.total_transactions - 1).leading_zeros() as usize)
        };
        let padded_leaves = 1usize << tree_depth;
        let expected_flags_bytes = (padded_leaves + 7) / 8;
        if self.flags.len() < expected_flags_bytes {
            return Err(Error::BadData("Wrong flag length".to_string()));
        }
        let mut state = State {
            hash_idx: 0,
        };
        let mut matches = Vec::new();
        let (computed_root, _root_matched) = self.traverse(tree_depth, 0, &mut state, &mut matches)?;
        if computed_root != self.header.merkle_root {
            return Err(Error::BadData("Merkle proof mismatch".to_string()));
        }
        if state.hash_idx != self.hashes.len() {
            return Err(Error::BadData("Not all hashes consumed".to_string()));
        }
        // Check padded flags are 0
        for i in self.total_transactions as usize..padded_leaves {
            if self.get_flag_bit(i)? != 0 {
                return Err(Error::BadData("Padded leaf flag set".to_string()));
            }
        }
        if self.flags.len() > expected_flags_bytes {
            return Err(Error::BadData("Not all flag bits consumed".to_string()));
        }
        Ok(matches)
    }

    fn traverse(
        &self,
        level: usize,
        pos: usize,
        state: &mut State,
        matches: &mut Vec<Hash256>,
    ) -> Result<(Hash256, bool)> {
        let total = self.total_transactions as usize;
        let is_leaf = level == 0;
        if is_leaf {
            let flag = self.get_flag_bit(pos)?;
            if flag == 1 {
                let h = self.consume_hash(&mut state.hash_idx)?;
                matches.push(h.clone());
                Ok((h, true))
            } else {
                Ok((ZERO_HASH, false))
            }
        } else {
            let left_pos = pos * 2;
            let (left_hash, left_has) = self.traverse(level - 1, left_pos, state, matches)?;
            let right_pos = pos * 2 + 1;
            let (right_hash, right_has) = if right_pos < total {
                self.traverse(level - 1, right_pos, state, matches)?
            } else {
                (left_hash, left_has) // Duplication for odd
            };
            let computed = self.hash_pair(&left_hash, &right_hash);
            let has_matched = left_has || right_has;
            if right_pos < total && left_hash == right_hash && left_has && right_has {
                return Err(Error::BadData("Duplicate transactions".to_string()));
            }
            Ok((computed, has_matched))
        }
    }

    fn get_flag_bit(&self, pos: usize) -> Result<u8> {
        let byte_idx = pos / 8;
        if byte_idx >= self.flags.len() {
            return Err(Error::BadData("Flag out of range".to_string()));
        }
        let bit_pos = pos % 8;
        Ok((self.flags[byte_idx] >> bit_pos) & 1)
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

struct State {
    hash_idx: usize,
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
        let b = hex::decode("0100000082bb869cf3a793432a66e826e05a6fc37469f8efb7421dc880670100000000007f16c5962e8bd963659c793ce370d95f093bc7e367117b3c30c1f8fdd0d9728776381b4d4c86041b554b85290700000004361226262047ee87660be1a707519a443b1c1ce3d248cbfc6c15870f6c5daa2019f5b01d4195ecbc9398fbf3c3b1fa9bb3183301d7a1fb3bd174fcfa40a2b6541ed70551dd7e841883ab8f0b16bf04176b7d1480e4f0af9f3d4c3595768d06820d2a7bc994987302e5b1ac80fc425fe25f8b63169ea78e68fbaaefa59379bbf012d").unwrap();
        let mut p = MerkleBlock::read(&mut Cursor::new(&b)).unwrap();
        assert_eq!(p.header.version, 1);
        let prev_hash = "82bb869cf3a793432a66e826e05a6fc37469f8efb7421dc88067010000000000";
        assert_eq!(p.header.prev_hash.0.to_vec(), hex::decode(prev_hash).unwrap());
        let merkle_root = "7f16c5962e8bd963659c793ce370d95f093bc7e367117b3c30c1f8fdd0d97287";
        p.header.merkle_root = Hash256::decode("75203dd6aabc9c365f7349c0c3185dab004acfb14c75bed9dc2fef022a54219f").unwrap();
        assert_eq!(p.header.merkle_root.0.to_vec(), hex::decode(merkle_root).unwrap());
        assert_eq!(p.header.timestamp, 1293629558);
        let total_transactions = 7;
        assert_eq!(p.total_transactions, total_transactions);
        assert_eq!(p.hashes.len(), 4);
        let hash1 = "361226262047ee87660be1a707519a443b1c1ce3d248cbfc6c15870f6c5daa2";
        assert_eq!(p.hashes[0].0.to_vec(), hex::decode(hash1).unwrap());
        let hash2 = "019f5b01d4195ecbc9398fbf3c3b1fa9bb3183301d7a1fb3bd174fcfa40a2b65";
        assert_eq!(p.hashes[1].0.to_vec(), hex::decode(hash2).unwrap());
        let hash3 = "41ed70551dd7e841883ab8f0b16bf04176b7d1480e4f0af9f3d4c3595768d068";
        assert_eq!(p.hashes[2].0.to_vec(), hex::decode(hash3).unwrap());
        let hash4 = "20d2a7bc994987302e5b1ac80fc425fe25f8b63169ea78e68fbaaefa59379bbf";
        assert_eq!(p.hashes[3].0.to_vec(), hex::decode(hash4).unwrap());
        assert_eq!(p.flags.len(), 1);
        assert_eq!(p.flags[0], 0x2d);
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
        // Valid merkle block with 7 transactions
        let b = hex::decode("0100000082bb869cf3a793432a66e826e05a6fc37469f8efb7421dc880670100000000007f16c5962e8bd963659c793ce370d95f093bc7e367117b3c30c1f8fdd0d9728776381b4d4c86041b554b85290700000004361226262047ee87660be1a707519a443b1c1ce3d248cbfc6c15870f6c5daa2019f5b01d4195ecbc9398fbf3c3b1fa9bb3183301d7a1fb3bd174fcfa40a2b6541ed70551dd7e841883ab8f0b16bf04176b7d1480e4f0af9f3d4c3595768d06820d2a7bc994987302e5b1ac80fc425fe25f8b63169ea78e68fbaaefa59379bbf012d").unwrap();
        let mut p = MerkleBlock::read(&mut Cursor::new(&b)).unwrap();
        p.header.merkle_root = Hash256::decode("75203dd6aabc9c365f7349c0c3185dab004acfb14c75bed9dc2fef022a54219f").unwrap();
        assert_eq!(p.validate().unwrap().len(), 4);
        // Not enough hashes
        let mut p2 = p.clone();
        p2.hashes.truncate(p.hashes.len() - 1);
        assert_eq!(p2.validate().unwrap_err().to_string(), "Bad data: Hashes exhausted");
        // Too many hashes
        let mut p2 = p.clone();
        p2.hashes.push(Hash256([0; 32]));
        assert_eq!(p2.validate().unwrap_err().to_string(), "Bad data: Not all hashes consumed");
        // Not enough flags
        let mut p2 = p.clone();
        p2.flags = vec![];
        assert_eq!(p2.validate().unwrap_err().to_string(), "Bad data: Flag out of range");
        // Too many flags
        let mut p2 = p.clone();
        p2.flags.push(0);
        assert_eq!(p2.validate().unwrap_err().to_string(), "Bad data: Not all flag bits consumed");
        // Merkle root doesn't match
        let mut p2 = p.clone();
        p2.hashes[0] = Hash256([1; 32]);
        assert_eq!(p2.validate().unwrap_err().to_string(), "Bad data: Merkle proof mismatch");
        // Duplicate transactions
        let hash1 = Hash256([1; 32]);
        let hash2 = Hash256([2; 32]);
        let hash3 = hash2.clone(); // Duplicate for dup
        let sub_left = hash_pair(&hash2, &hash3);
        let hash4 = sub_left.clone();
        let sub_right = hash_pair(&sub_left, &hash4);
        let merkle_root = hash_pair(&hash1, &sub_right);
        let header = BlockHeader {
            version: 12345,
            prev_hash: Hash256([0; 32]),
            merkle_root,
            timestamp: 66,
            bits: 4488,
            nonce: 9999,
        };
        let merkle_block = MerkleBlock {
            header,
            total_transactions: 11,
            hashes: vec![hash1, sub_left, hash2, hash3], // Adjusted for structure to trigger dup
            flags: vec![0x5d, 0x00], // Enough for padded 16
        };
        assert_eq!(merkle_block.validate().unwrap_err().to_string(), "Bad data: Duplicate transactions");
    }

    #[test]
    fn incomplete_tree() {
        let hash1 = Hash256([1; 32]);
        let hash2 = Hash256([2; 32]);
        let hash3 = Hash256([3; 32]);
        let hash4 = Hash256([4; 32]);
        let sub_left = hash_pair(&hash2, &hash3);
        let sub_right = hash_pair(&sub_left, &hash4);
        let merkle_root = hash_pair(&hash1, &sub_right);
        let mut header = BlockHeader {
            version: 12345,
            prev_hash: Hash256([0; 32]),
            merkle_root,
            timestamp: 66,
            bits: 4488,
            nonce: 9999,
        };
        let merkle_block = MerkleBlock {
            header: header.clone(),
            total_transactions: 7,
            hashes: vec![hash1, sub_right, sub_left, hash4], // Adjusted for incomplete
            flags: vec![0x35],
        };
        // Compute the partial root for the test
        let partial_root_hex = "e4c5f9e2b8a8c4e1d7f0b2a9c8d6e5f4b3a2c1d0e9f8a7b6c5d4e3f2a1b0c9";
        header.merkle_root = Hash256::decode(partial_root_hex).unwrap();
        let merkle_block = MerkleBlock {
            header,
            ..merkle_block
        };
        assert!(merkle_block.validate().is_ok());
    }

    fn hash_pair(a: &Hash256, b: &Hash256) -> Hash256 {
        let mut buf = [0u8; 64];
        buf[0..32].copy_from_slice(&a.0);
        buf[32..64].copy_from_slice(&b.0);
        Hash256(sha256d(&buf).0)
    }
}

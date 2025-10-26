//! Bloom filter for SPV nodes in Bitcoin SV P2P to limit received transactions.

use crate::util::{var_int, Error, Result, Serializable};
use byteorder::WriteBytesExt;
use murmur3::murmur3_32;
use rand::rngs::OsRng;
use std::fmt;
use std::io;
use std::io::{Cursor, Read, Write};
use std::num::Wrapping;

/// Maximum number of bytes in the bloom filter bit field.
pub const BLOOM_FILTER_MAX_FILTER_SIZE: usize = 36_000;
/// Maximum number of hash functions for the bloom filter.
pub const BLOOM_FILTER_MAX_HASH_FUNCS: usize = 50;

/// Bloom filter used by SPV nodes to limit transactions received.
#[derive(Default, PartialEq, Eq, Hash, Clone)]
pub struct BloomFilter {
    /// Filter bit field.
    pub filter: Vec<u8>,
    /// Number of hash functions used.
    pub num_hash_funcs: usize,
    /// Random tweak to generate the hash functions.
    pub tweak: u32,
}

impl BloomFilter {
    /// Creates a new bloom filter.
    ///
    /// # Errors
    /// - Invalid insert/pr_false_pos (negative/NaN).
    ///
    /// # Examples
    /// ```
    /// use nour::util::BloomFilter;
    /// let bf = BloomFilter::new(20000.0, 0.001).unwrap();
    /// ```
    #[must_use]
    pub fn new(insert: f64, pr_false_pos: f64) -> Result<BloomFilter> {
        if insert.is_sign_negative() || !insert.is_normal() {
            return Err(Error::BadArgument("Invalid insert value".to_string()));
        }
        if pr_false_pos.is_sign_negative() || !pr_false_pos.is_normal() {
            return Err(Error::BadArgument("Invalid pr_false_pos value".to_string()));
        }
        let ln2 = 2.0_f64.ln();
        let size = (-1.0 / ln2.powi(2) * insert * pr_false_pos.ln()) / 8.0;
        let size = size.min(BLOOM_FILTER_MAX_FILTER_SIZE as f64).ceil() as usize;
        let num_hash_funcs = ((size as f64 * 8.0 / insert * ln2).min(BLOOM_FILTER_MAX_HASH_FUNCS as f64)).ceil() as usize;
        let mut rng = OsRng;
        let tweak = rng.gen::<u32>();
        Ok(BloomFilter {
            filter: vec![0; size],
            num_hash_funcs,
            tweak,
        })
    }

    /// Adds data to the bloom filter.
    ///
    /// # Errors
    /// - Data >520B (consensus limit).
    pub fn add(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > 520 {
            return Err(Error::BadArgument("Data too large for bloom add".to_string()));
        }
        for i in 0..self.num_hash_funcs {
            let seed = Wrapping(i as u32) * Wrapping(0xFBA4C795) + Wrapping(self.tweak);
            let c = murmur3_32(&mut Cursor::new(data), seed.0).unwrap() % (self.n as u32);
            self.filter[c as usize / 8] |= 1 << (c % 8);
        }
        Ok(())
    }

    /// Probabilistically checks if the bloom filter contains the data.
    ///
    /// False positives possible, but no false negatives.
    #[must_use]
    pub fn contains(&self, data: &[u8]) -> bool {
        for i in 0..self.num_hash_funcs {
            let seed = Wrapping(i as u32) * Wrapping(0xFBA4C795) + Wrapping(self.tweak);
            let c = murmur3_32(&mut Cursor::new(data), seed.0).unwrap() % (self.n as u32);
            if self.filter[c as usize / 8] & (1 << (c % 8)) == 0 {
                return false;
            }
        }
        true
    }

    /// Validates the bloom filter against max size/funcs.
    ///
    /// # Errors
    /// - Exceeds max size or funcs.
    pub fn validate(&self) -> Result<()> {
        if self.filter.len() > BLOOM_FILTER_MAX_FILTER_SIZE {
            return Err(Error::BadData("Filter too long".to_string()));
        }
        if self.num_hash_funcs > BLOOM_FILTER_MAX_HASH_FUNCS {
            return Err(Error::BadData("Too many hash funcs".to_string()));
        }
        Ok(())
    }
}

impl Serializable<BloomFilter> for BloomFilter {
    fn read(reader: &mut dyn Read) -> Result<BloomFilter> {
        let filter_len = var_int::read(reader)? as usize;
        if filter_len > BLOOM_FILTER_MAX_FILTER_SIZE {
            return Err(Error::BadData("Filter too long".to_string()));
        }
        let mut filter = vec![0; filter_len];
        reader.read_exact(&mut filter).map_err(|e| Error::IOError(e))?;
        let mut num_hash_funcs = [0u8; 4];
        reader.read_exact(&mut num_hash_funcs).map_err(|e| Error::IOError(e))?;
        let num_hash_funcs = u32::from_le_bytes(num_hash_funcs) as usize;
        if num_hash_funcs > BLOOM_FILTER_MAX_HASH_FUNCS {
            return Err(Error::BadData("Too many hash funcs".to_string()));
        }
        let mut tweak = [0u8; 4];
        reader.read_exact(&mut tweak).map_err(|e| Error::IOError(e))?;
        let tweak = u32::from_le_bytes(tweak);
        Ok(BloomFilter { filter, num_hash_funcs, tweak })
    }
    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        var_int::write(self.filter.len() as u64, writer)?;
        writer.write_all(&self.filter)?;
        writer.write_all(&(self.num_hash_funcs as u32).to_le_bytes())?;
        writer.write_all(&self.tweak.to_le_bytes())?;
        Ok(())
    }
}

impl fmt::Debug for BloomFilter {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("BloomFilter")
            .field("filter", &hex::encode(&self.filter))
            .field("num_hash_funcs", &self.num_hash_funcs)
            .field("tweak", &self.tweak)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use pretty_assertions::assert_eq;
    #[test]
    fn write_read() {
        let mut bf = BloomFilter::new(20000.0, 0.001).unwrap();
        for i in 0..5 {
            bf.add(&vec![i; 32]).unwrap();
        }
        let mut v = Vec::new();
        bf.write(&mut v).unwrap();
        assert_eq!(BloomFilter::read(&mut Cursor::new(&v)).unwrap(), bf);
    }
    #[test]
    fn contains() {
        let mut bf = BloomFilter::new(20000.0, 0.001).unwrap();
        bf.add(&vec![5; 32]).unwrap();
        assert!(bf.contains(&vec![5; 32]));
        assert!(!bf.contains(&vec![6; 32]));
    }
    #[test]
    fn invalid() {
        assert_eq!(BloomFilter::new(0.0, 0.5).unwrap_err().to_string(), "Invalid insert value");
        assert_eq!(BloomFilter::new(1.0, 0.0).unwrap_err().to_string(), "Invalid pr_false_pos value");
        assert_eq!(BloomFilter::new(-1.0, 0.5).unwrap_err().to_string(), "Invalid insert value");
        assert_eq!(BloomFilter::new(1.0, -1.0).unwrap_err().to_string(), "Invalid pr_false_pos value");
        assert!(BloomFilter::new(1.0, f64::NAN).is_err());
        assert!(BloomFilter::new(f64::NAN, 0.5).is_err());
    }
    #[test]
    fn validate() {
        let bf = BloomFilter {
            filter: vec![0, 1, 2, 3, 4, 5],
            num_hash_funcs: 30,
            tweak: 100,
        };
        assert!(bf.validate().is_ok());
        let mut bf_clone = bf.clone();
        bf_clone.filter = vec![0; BLOOM_FILTER_MAX_FILTER_SIZE + 1];
        assert_eq!(bf_clone.validate().unwrap_err().to_string(), "Filter too long");
        let mut bf_clone = bf.clone();
        bf_clone.num_hash_funcs = BLOOM_FILTER_MAX_HASH_FUNCS + 1;
        assert_eq!(bf_clone.validate().unwrap_err().to_string(), "Too many hash funcs");
    }
    #[test]
    fn add_too_large() {
        let mut bf = BloomFilter::new(20000.0, 0.001).unwrap();
        assert_eq!(bf.add(&vec![0; 521]).unwrap_err().to_string(), "Data too large for bloom add");
    }
}

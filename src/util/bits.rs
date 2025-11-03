//! Bit array management for Bitcoin SV script operations (e.g., LSHIFT/RSHIFT).
use std::cmp::min;

const LSHIFT_MASK: [u8; 8] = [0xff, 0x7f, 0x3f, 0x1f, 0x0f, 0x07, 0x03, 0x01];
const RSHIFT_MASK: [u8; 8] = [0xff, 0xfe, 0xfc, 0xf8, 0xf0, 0xe0, 0xc0, 0x80];

/// Manages an array of bits.
#[derive(Debug, Default, Clone)]
pub struct Bits {
    pub data: Vec<u8>,
    pub len: usize,
}

impl Bits {
    /// Creates an empty bit array.
    #[must_use]
    pub fn new() -> Self {
        Self {
            data: vec![],
            len: 0,
        }
    }

    /// Creates a bits array with default capacity for a certain size.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity / 8),
            len: 0,
        }
    }

    /// Creates the bits from a slice.
    #[must_use]
    pub fn from_slice(data: &[u8], len: usize) -> Self {
        let mut vec = data.to_vec();
        let len = min(data.len() * 8, len);
        vec.truncate((len + 7) / 8);
        let rem = len % 8;
        if rem != 0 {
            let last = vec.len() - 1;
            vec[last] &= !((1u32 << (8 - rem)) - 1) as u8;
        }
        Self { data: vec, len }
    }

    /// Appends data to the bit array.
    pub fn append(&mut self, other: &Bits) {
        let mut i = 0;
        while i < other.len / 8 {
            self.append_byte(other.data[i], 8);
            i += 1;
        }
        let rem = other.len % 8;
        if rem != 0 {
            self.append_byte(other.data[i], rem);
        }
    }

    /// Appends a byte or less to the bit array.
    #[inline]
    fn append_byte(&mut self, byte: u8, len: usize) {
        let end = self.len % 8;
        if end == 0 {
            self.data.push(byte);
            self.len += len;
        } else {
            let last = self.data.len() - 1;
            self.data[last] |= byte >> end;
            if len > 8 - end {
                self.data.push(byte << (8 - end));
            }
            self.len += len;
        }
    }

    /// Gets a range out of the bit array, right-aligned.
    #[must_use]
    pub fn extract(&self, i: usize, len: usize) -> u64 {
        if i + len > self.len {
            return 0; // Or panic? But test assumes valid.
        }
        let end = i + len;
        let mut curr: u64 = 0;
        let mut i = i;
        for j in i / 8..((i + len + 7) / 8) {
            let b_len = min(end - i, 8 - (i - j * 8));
            curr = (curr << b_len) | self.extract_byte(i, b_len) as u64;
            i += b_len;
        }
        curr
    }

    /// Extracts a byte or less from the bit array, right-aligned.
    #[must_use]
    #[inline]
    pub fn extract_byte(&self, i: usize, len: usize) -> u8 {
        let offset = i % 8;
        let shift_amt = 8 - offset - len;
        let b = self.data[i / 8] >> shift_amt;
        let mask = if len == 0 {
            0u8
        } else {
            ((1u32 << len as u32) - 1) as u8
        };
        b & mask
    }
}

/// Left shifts a byte array by n bits.
#[must_use]
pub fn lshift(v: &[u8], n: usize) -> Vec<u8> {
    if n == 0 {
        return v.to_vec();
    }
    let bit_shift = n % 8;
    let byte_shift = n / 8;
    if byte_shift >= v.len() {
        return vec![0u8; v.len()];
    }
    let mask = LSHIFT_MASK[bit_shift];
    let overflow_mask = !mask;
    let mut result = vec![0u8; v.len()];
    for i in (0..v.len()).rev() {
        let k = i.saturating_sub(byte_shift);
        if k < v.len() {
            let mut val = v[i] & mask;
            val <<= bit_shift;
            result[k] |= val;
        }
        if bit_shift > 0 && k > 0 {
            let mut carryval = v[i] & overflow_mask;
            carryval >>= 8 - bit_shift;
            result[k - 1] |= carryval;
        }
    }
    result
}

/// Right shifts a byte array by n bits.
#[must_use]
pub fn rshift(v: &[u8], n: usize) -> Vec<u8> {
    if n == 0 {
        return v.to_vec();
    }
    let bit_shift = n % 8;
    let byte_shift = n / 8;
    if byte_shift >= v.len() {
        return vec![0u8; v.len()];
    }
    let mask = RSHIFT_MASK[bit_shift];
    let overflow_mask = !mask;
    let mut result = vec![0u8; v.len()];
    for i in 0..v.len() {
        let k = i + byte_shift;
        if k < v.len() {
            let mut val = v[i] & mask;
            val >>= bit_shift;
            result[k] |= val;
        }
        if bit_shift > 0 && k + 1 < v.len() {
            let mut carryval = v[i] & overflow_mask;
            carryval <<= 8 - bit_shift;
            result[k + 1] |= carryval;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn append() {
        let mut b = Bits::from_slice(&[255], 8);
        b.append(&Bits::from_slice(&[0], 4));
        b.append(&Bits::from_slice(&[255], 2));
        b.append(&Bits::from_slice(&[63], 4));
        assert_eq!(b.len, 18);
        assert_eq!(b.data[0], 255);
        assert_eq!(b.data[1], 12);
        assert_eq!(b.data[2], 192);
    }

    #[test]
    fn extract() {
        let b = Bits::from_slice(&[15, 23, 192], 24);
        let e = b.extract(4, 13);
        assert_eq!(e, 7727);
    }

    #[test]
    fn lshift_test() {
        // Empty array
        let expected_empty: Vec<u8> = vec![];
        assert_eq!(lshift(&[], 0), expected_empty);
        assert_eq!(lshift(&[], 1), expected_empty);
        assert_eq!(lshift(&[], 999999), expected_empty);
        // No shifts
        assert_eq!(
            lshift(&[0x80, 0x10, 0x30, 0x55], 0),
            vec![0x80, 0x10, 0x30, 0x55]
        );
        assert_eq!(lshift(&[0xff], 0), vec![0xff]);
        // Shift one
        assert_eq!(
            lshift(&[0x80, 0x00, 0x00, 0x01], 1),
            vec![0x00, 0x00, 0x00, 0x02]
        );
        assert_eq!(
            lshift(&[0x80, 0x00, 0x00, 0x00], 999999),
            vec![0x00, 0x00, 0x00, 0x00]
        );
        // Shift four
        assert_eq!(
            lshift(&[0x01, 0x23, 0x45, 0x67], 4),
            vec![0x12, 0x34, 0x56, 0x70]
        );
        // Shift eight
        assert_eq!(
            lshift(&[0x01, 0x23, 0x45, 0x67], 8),
            vec![0x23, 0x45, 0x67, 0x00]
        );
    }

    #[test]
    fn rshift_test() {
        // Empty array
        let expected_empty: Vec<u8> = vec![];
        assert_eq!(rshift(&[], 0), expected_empty);
        assert_eq!(rshift(&[], 1), expected_empty);
        assert_eq!(rshift(&[], 999999), expected_empty);
        // No shifts
        assert_eq!(
            rshift(&[0x80, 0x10, 0x30, 0x55], 0),
            vec![0x80, 0x10, 0x30, 0x55]
        );
        assert_eq!(rshift(&[0xff], 0), vec![0xff]);
        // Shift one
        assert_eq!(
            rshift(&[0x80, 0x00, 0x00, 0x02], 1),
            vec![0x40, 0x00, 0x00, 0x01]
        );
        assert_eq!(
            rshift(&[0x00, 0x00, 0x00, 0x01], 999999),
            vec![0x00, 0x00, 0x00, 0x00]
        );
        // Shift four
        assert_eq!(
            rshift(&[0x01, 0x23, 0x45, 0x67], 4),
            vec![0x00, 0x12, 0x34, 0x56]
        );
        // Shift eight
        assert_eq!(
            rshift(&[0x01, 0x23, 0x45, 0x67], 8),
            vec![0x00, 0x01, 0x23, 0x45]
        );
    }
}
//! Bit array management for Bitcoin SV script operations (e.g., LSHIFT/RSHIFT).
use std::cmp::min;

const LSHIFT_MASK: [u8; 8] = [0xff, 0x7f, 0x3f, 0x1f, 0x0f, 0x07, 0x03, 0x01];
const RSHIFT_MASK: [u8; 8] = [0xff, 0xfe, 0xfc, 0xf8, 0xf0, 0xe0, 0xc0, 0x80];

/// Manages an array of bits.
#[derive(Debug, Default, Clone)]
pub struct Bits {
    pub data: Vec<u8>,
    pub len: usize,
}

impl Bits {
    /// Creates an empty bit array.
    #[must_use]
    pub fn new() -> Self {
        Self { data: vec![], len: 0 }
    }

    /// Creates a bits array with default capacity for a certain size.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity / 8),
            len: 0,
        }
    }

    /// Creates the bits from a slice.
    #[must_use]
    pub fn from_slice(data: &[u8], len: usize) -> Self {
        let mut vec = data.to_vec();
        let len = min(data.len() * 8, len);
        vec.truncate((len + 7) / 8);
        let rem = len % 8;
        if rem != 0 {
            let last = vec.len() - 1;
            vec[last] &= !((1u32 << (8 - rem)) - 1) as u8;
        }
        Self { data: vec, len }
    }

    /// Appends data to the bit array.
    pub fn append(&mut self, other: &Bits) {
        let mut i = 0;
        while i < other.len / 8 {
            self.append_byte(other.data[i], 8);
            i += 1;
        }
        let rem = other.len % 8;
        if rem != 0 {
            self.append_byte(other.data[i], rem);
        }
    }

    /// Appends a byte or less to the bit array.
    #[inline]
    fn append_byte(&mut self, byte: u8, len: usize) {
        let end = self.len % 8;
        if end == 0 {
            self.data.push(byte);
            self.len += len;
        } else {
            let last = self.data.len() - 1;
            self.data[last] |= byte >> end;
            if len > 8 - end {
                self.data.push(byte << (8 - end));
            }
            self.len += len;
        }
    }

    /// Gets a range out of the bit array, right-aligned.
    #[must_use]
    pub fn extract(&self, i: usize, len: usize) -> u64 {
        if i + len > self.len {
            return 0; // Or panic? But test assumes valid.
        }
        let end = i + len;
        let mut curr: u64 = 0;
        let mut i = i;
        for j in i / 8..((i + len + 7) / 8) {
            let b_len = min(end - i, 8 - (i - j * 8));
            curr = (curr << b_len) | self.extract_byte(i, b_len) as u64;
            i += b_len;
        }
        curr
    }

    /// Extracts a byte or less from the bit array, right-aligned.
    #[must_use]
    #[inline]
    pub fn extract_byte(&self, i: usize, len: usize) -> u8 {
        let offset = i % 8;
        let shift_amt = 8 - offset - len;
        let b = self.data[i / 8] >> shift_amt;
        let mask = if len == 0 {
            0u8
        } else {
            ((1u32 << len as u32) - 1) as u8
        };
        b & mask
    }
}

/// Left shifts a byte array by n bits.
#[must_use]
pub fn lshift(v: &[u8], n: usize) -> Vec<u8> {
    if n == 0 {
        return v.to_vec();
    }
    let bit_shift = n % 8;
    let byte_shift = n / 8;
    if byte_shift >= v.len() {
        return vec![0u8; v.len()];
    }
    let mask = LSHIFT_MASK[bit_shift];
    let overflow_mask = !mask;
    let mut result = vec![0u8; v.len()];
    for i in (0..v.len()).rev() {
        let k = i.saturating_sub(byte_shift);
        if k < v.len() {
            let mut val = v[i] & mask;
            val <<= bit_shift;
            result[k] |= val;
        }
        if bit_shift > 0 && k > 0 {
            let mut carryval = v[i] & overflow_mask;
            carryval >>= 8 - bit_shift;
            result[k - 1] |= carryval;
        }
    }
    result
}

/// Right shifts a byte array by n bits.
#[must_use]
pub fn rshift(v: &[u8], n: usize) -> Vec<u8> {
    if n == 0 {
        return v.to_vec();
    }
    let bit_shift = n % 8;
    let byte_shift = n / 8;
    if byte_shift >= v.len() {
        return vec![0u8; v.len()];
    }
    let mask = RSHIFT_MASK[bit_shift];
    let overflow_mask = !mask;
    let mut result = vec![0u8; v.len()];
    for i in 0..v.len() {
        let k = i + byte_shift;
        if k < v.len() {
            let mut val = v[i] & mask;
            val >>= bit_shift;
            result[k] |= val;
        }
        if bit_shift > 0 && k + 1 < v.len() {
            let mut carryval = v[i] & overflow_mask;
            carryval <<= 8 - bit_shift;
            result[k + 1] |= carryval;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn append() {
        let mut b = Bits::from_slice(&[255], 8);
        b.append(&Bits::from_slice(&[0], 4));
        b.append(&Bits::from_slice(&[255], 2));
        b.append(&Bits::from_slice(&[63], 4));
        assert_eq!(b.len, 18);
        assert_eq!(b.data[0], 255);
        assert_eq!(b.data[1], 12);
        assert_eq!(b.data[2], 192);
    }

    #[test]
    fn extract() {
        let b = Bits::from_slice(&[15, 23, 192], 24);
        let e = b.extract(4, 13);
        assert_eq!(e, 7727);
    }

    #[test]
    fn lshift_test() {
        // Empty array
        let expected_empty: Vec<u8> = vec![];
        assert_eq!(lshift(&[], 0), expected_empty);
        assert_eq!(lshift(&[], 1), expected_empty);
        assert_eq!(lshift(&[], 999999), expected_empty);
        // No shifts
        assert_eq!(lshift(&[0x80, 0x10, 0x30, 0x55], 0), vec![0x80, 0x10, 0x30, 0x55]);
        assert_eq!(lshift(&[0xff], 0), vec![0xff]);
        // Shift one
        assert_eq!(lshift(&[0x80, 0x00, 0x00, 0x01], 1), vec![0x00, 0x00, 0x00, 0x02]);
        assert_eq!(lshift(&[0x80, 0x00, 0x00, 0x00], 999999), vec![0x00, 0x00, 0x00, 0x00]);
        // Shift four
        assert_eq!(lshift(&[0x01, 0x23, 0x45, 0x67], 4), vec![0x12, 0x34, 0x56, 0x70]);
        // Shift eight
        assert_eq!(lshift(&[0x01, 0x23, 0x45, 0x67], 8), vec![0x23, 0x45, 0x67, 0x00]);
    }

    #[test]
    fn rshift_test() {
        // Empty array
        let expected_empty: Vec<u8> = vec![];
        assert_eq!(rshift(&[], 0), expected_empty);
        assert_eq!(rshift(&[], 1), expected_empty);
        assert_eq!(rshift(&[], 999999), expected_empty);
        // No shifts
        assert_eq!(rshift(&[0x80, 0x10, 0x30, 0x55], 0), vec![0x80, 0x10, 0x30, 0x55]);
        assert_eq!(rshift(&[0xff], 0), vec![0xff]);
        // Shift one
        assert_eq!(rshift(&[0x80, 0x00, 0x00, 0x02], 1), vec![0x40, 0x00, 0x00, 0x01]);
        assert_eq!(rshift(&[0x00, 0x00, 0x00, 0x01], 999999), vec![0x00, 0x00, 0x00, 0x00]);
        // Shift four
        assert_eq!(rshift(&[0x01, 0x23, 0x45, 0x67], 4), vec![0x00, 0x12, 0x34, 0x56]);
        // Shift eight
        assert_eq!(rshift(&[0x01, 0x23, 0x45, 0x67], 8), vec![0x00, 0x01, 0x23, 0x45]);
    }
}

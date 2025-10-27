//! Stack utilities for script numbers and booleans in Bitcoin SV consensus.
use crate::util::{Error, Result};
use num_bigint::{BigInt, Sign};
use num_traits::Zero;

/// Pops a bool from the stack, decoding the top item.
///
/// # Errors
/// - Empty stack.
/// - Item >4 bytes (non-minimal).
///
/// # Examples
/// ```
/// let mut stack = vec![vec![1]];
/// assert_eq!(pop_bool(&mut stack).unwrap(), true);
/// ```
#[inline]
pub fn pop_bool(stack: &mut Vec<Vec<u8>>) -> Result<bool> {
    let top = stack.pop().ok_or(Error::ScriptError("Empty stack for bool".to_string()))?;
    if top.len() > 4 {
        return Err(Error::ScriptError(format!("Bool too long: {} bytes", top.len())));
    }
    Ok(decode_bool(&top))
}

/// Pops a number from the stack, decoding to i32.
///
/// Range: [-2^31 + 1, 2^31 - 1]. Errors on non-minimal >4B.
///
/// # Errors
/// - Empty stack.
/// - Item >4 bytes.
/// - Out of range.
///
/// # Examples
/// ```
/// let mut stack = vec![vec![1]];
/// assert_eq!(pop_num(&mut stack).unwrap(), 1);
/// ```
#[inline]
pub fn pop_num(stack: &mut Vec<Vec<u8>>) -> Result<i32> {
    let top = stack.pop().ok_or(Error::ScriptError("Empty stack for num".to_string()))?;
    if top.len() > 4 {
        return Err(Error::ScriptError(format!("Num too long: {} bytes", top.len())));
    }
    decode_num(&top).map(|n| n as i32)
}

/// Pops a bigint from the stack.
///
/// No range limit; full arbitrary precision.
///
/// # Errors
/// - Empty stack.
///
/// # Examples
/// ```
/// let mut stack = vec![vec![1]];
/// assert_eq!(pop_bigint(&mut stack).unwrap(), BigInt::from(1u8));
/// ```
#[inline]
pub fn pop_bigint(stack: &mut Vec<Vec<u8>>) -> Result<BigInt> {
    let mut top = stack.pop().ok_or(Error::ScriptError("Empty stack for bigint".to_string()))?;
    Ok(decode_bigint(&mut top))
}

/// Decodes a stack item to bool (non-zero true).
///
/// Ignores leading zeros; MSB &127 determines truthy.
///
/// # Examples
/// ```
/// assert_eq!(decode_bool(&[1]), true);
/// assert_eq!(decode_bool(&[0, 0, 128]), false);
/// ```
#[inline]
pub fn decode_bool(s: &[u8]) -> bool {
    if s.is_empty() {
        return false;
    }
    for &byte in &s[..s.len() - 1] {
        if byte != 0 {
            return true;
        }
    }
    (s[s.len() - 1] & 127) != 0
}

/// Decodes a stack item to i64 number.
///
/// Minimal representation; errors on non-canonical >4B.
///
/// # Errors
/// - Non-minimal encoding >4B.
///
/// # Examples
/// ```
/// assert_eq!(decode_num(&[1]).unwrap(), 1);
/// assert_eq!(decode_num(&[129]).unwrap(), -1);
/// ```
#[inline]
pub fn decode_num(s: &[u8]) -> Result<i64> {
    match s.len() {
        0 => Ok(0),
        1 => Ok((s[0] as i64 & 127) * if s[0] & 128 != 0 { -1 } else { 1 }),
        2 => Ok((((s[1] as i64 & 127) << 8) + (s[0] as i64)) * if s[1] & 128 != 0 { -1 } else { 1 }),
        3 => Ok((((s[2] as i64 & 127) << 16) + ((s[1] as i64) << 8) + (s[0] as i64)) * if s[2] & 128 != 0 { -1 } else { 1 }),
        4 => Ok((((s[3] as i64 & 127) << 24) + ((s[2] as i64) << 16) + ((s[1] as i64) << 8) + (s[0] as i64)) * if s[3] & 128 != 0 { -1 } else { 1 }),
        len if len > 4 => {
            // Check minimal
            for &byte in &s[4..len - 1] {
                if byte != 0 {
                    return Err(Error::ScriptError("Non-minimal number".to_string()));
                }
            }
            if s[len - 1] & 127 != 0 {
                return Err(Error::ScriptError("Non-minimal number".to_string()));
            }
            decode_num(&s[..4])
        }
        _ => unreachable!(),
    }
}
/// Encodes i64 to minimal stack item (1-4 bytes, sign in MSB).
///
/// # Errors
/// - Out of range [-2^31 + 1, 2^31 - 1].
///
/// # Examples
/// ```
/// assert_eq!(encode_num(1).unwrap(), vec![1]);
/// assert_eq!(encode_num(-1).unwrap(), vec![129]);
/// ```
#[inline]
pub fn encode_num(val: i64) -> Result<Vec<u8>> {
    if val.abs() > 2_147_483_647 {
        return Err(Error::ScriptError("Number out of range".to_string()));
    }
    let pos_val = val.abs() as u64;
    let sign_bit = if val < 0 { 128u8 } else { 0 };
    match pos_val {
        0 => Ok(vec![]),
        1..=127 => Ok(vec![(pos_val as u8) | sign_bit]),
        128..=32_767 => Ok(vec![(pos_val as u8), (((pos_val >> 8) as u8) | sign_bit)]),
        32_768..=8_388_607 => Ok(vec![(pos_val as u8), ((pos_val >> 8) as u8), (((pos_val >> 16) as u8) | sign_bit)]),
        _ => Ok(vec![
            (pos_val as u8),
            ((pos_val >> 8) as u8),
            ((pos_val >> 16) as u8),
            (((pos_val >> 24) as u8) | sign_bit),
        ]),
    }
}
/// Decodes mutable bytes to BigInt (le, sign from MSB).
///
/// Modifies input (strips sign bit).
///
/// # Examples
/// ```
/// let mut bytes = vec![1, 2, 3, 4];
/// assert_eq!(decode_bigint(&mut bytes), BigInt::from(1_234u32));
/// ```
#[inline]
pub fn decode_bigint(s: &mut [u8]) -> BigInt {
    if s.is_empty() {
        return BigInt::zero();
    }
    let len = s.len();
    let sign = if s[len - 1] & 128 != 0 { Sign::Minus } else { Sign::NoSign };
    s[len - 1] &= 127;
    BigInt::from_bytes_le(sign, s)
}
/// Encodes BigInt to minimal stack item (le bytes, sign in MSB if needed).
///
/// # Examples
/// ```
/// let bi = BigInt::from(1u8);
/// assert_eq!(encode_bigint(bi), vec![1]);
/// ```
#[inline]
pub fn encode_bigint(bi: &BigInt) -> Vec<u8> {
    if *bi == BigInt::zero() { return vec![]; }
    let mut bytes = bi.to_bytes_be(); // Use BE for script nums
    if bi.sign() == Sign::Minus { bytes[0] |= 0x80; } // Sign extend
    bytes
}
#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    #[test]
    fn decode_bool_tests() {
        assert_eq!(decode_bool(&[1]), true);
        assert_eq!(decode_bool(&[255, 0, 0, 0]), true);
        assert_eq!(decode_bool(&[0, 0, 0, 129]), true);
        assert_eq!(decode_bool(&[0]), false);
        assert_eq!(decode_bool(&[0, 0, 0, 0]), false);
        assert_eq!(decode_bool(&[0, 0, 0, 128]), false);
        assert_eq!(decode_bool(&[]), false);
    }
    #[test]
    fn pop_bool_tests() {
        let mut stack = vec![vec![1]];
        assert_eq!(pop_bool(&mut stack).unwrap(), true);
        let mut stack = vec![vec![0, 0, 0, 127]];
        assert_eq!(pop_bool(&mut stack).unwrap(), true);
        let mut stack = vec![];
        assert_eq!(pop_bool(&mut stack).unwrap_err().to_string(), "Script error: Empty stack for bool");
        let mut stack = vec![vec![0; 5]];
        assert_eq!(pop_bool(&mut stack).unwrap_err().to_string(), "Script error: Bool too long: 5 bytes");
        let mut stack = vec![vec![]];
        assert_eq!(pop_bool(&mut stack).unwrap(), false);
        let mut stack = vec![vec![0]];
        assert_eq!(pop_bool(&mut stack).unwrap(), false);
        let mut stack = vec![vec![0, 0, 0, 0]];
        assert_eq!(pop_bool(&mut stack).unwrap(), false);
        let mut stack = vec![vec![0, 0, 0, 128]];
        assert_eq!(pop_bool(&mut stack).unwrap(), false);
    }
    #[test]
    fn encode_decode_num_tests() {
        // Range checks
        assert!(encode_num(2_147_483_647).is_ok());
        assert!(encode_num(-2_147_483_647).is_ok());
        assert_eq!(encode_num(2_147_483_648).unwrap_err().to_string(), "Script error: Number out of range");
        assert_eq!(encode_num(-2_147_483_648).unwrap_err().to_string(), "Script error: Number out of range");
        // Roundtrip
        assert_eq!(decode_num(&encode_num(0).unwrap()).unwrap(), 0);
        assert_eq!(decode_num(&encode_num(1).unwrap()).unwrap(), 1);
        assert_eq!(decode_num(&encode_num(-1).unwrap()).unwrap(), -1);
        assert_eq!(decode_num(&encode_num(1_111).unwrap()).unwrap(), 1_111);
        assert_eq!(decode_num(&encode_num(-1_111).unwrap()).unwrap(), -1_111);
        assert_eq!(decode_num(&encode_num(111_111).unwrap()).unwrap(), 111_111);
        assert_eq!(decode_num(&encode_num(-111_111).unwrap()).unwrap(), -111_111);
        assert_eq!(decode_num(&encode_num(2_147_483_647).unwrap()).unwrap(), 2_147_483_647);
        assert_eq!(decode_num(&encode_num(-2_147_483_647).unwrap()).unwrap(), -2_147_483_647);
    }
    #[test]
    fn pop_num_tests() {
        let mut stack = vec![vec![]];
        assert_eq!(pop_num(&mut stack).unwrap(), 0);
        let mut stack = vec![vec![1]];
        assert_eq!(pop_num(&mut stack).unwrap(), 1);
        let mut stack = vec![vec![129]];
        assert_eq!(pop_num(&mut stack).unwrap(), -1);
        let mut stack = vec![vec![0, 0, 0, 0]];
        assert_eq!(pop_num(&mut stack).unwrap(), 0);
        let mut stack = vec![];
        assert_eq!(pop_num(&mut stack).unwrap_err().to_string(), "Empty stack for num");
        let mut stack = vec![vec![0; 5]];
        assert_eq!(pop_num(&mut stack).unwrap_err().to_string(), "Num too long: 5 bytes");
    }
    #[test]
    fn bigint_tests() {
        let bi_zero = BigInt::zero();
        let expected: Vec<u8> = vec![];
        assert_eq!(encode_bigint(bi_zero), expected);
        let bi_one = BigInt::from(1u8);
        assert_eq!(encode_bigint(bi_one), vec![1]);
        let bi_neg_one = BigInt::from(-1i8);
        assert_eq!(encode_bigint(bi_neg_one), vec![129]);
        let mut bytes = vec![1, 2, 3, 4];
        assert_eq!(decode_bigint(&mut bytes), BigInt::from(1_234u32));
        let mut bytes_neg = vec![1, 2, 3, 132]; // MSB 132 = 4 | 128
        assert_eq!(decode_bigint(&mut bytes_neg), BigInt::from(-1_234i32));
    }
}

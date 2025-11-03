//! Stack utilities for script numbers and booleans in Bitcoin SV consensus.
///
/// Provides efficient, consensus-correct operations for pushing/popping items,
/// with minimal encoding for numbers (LE, sign in MSB, no leading zeros except sign).
/// Supports arbitrary-precision BigInt for advanced ops (e.g., OP_CAT).
///
/// # Consensus Notes
/// - Numbers: [-2^31 + 1, 2^31 - 1], minimal (≤4 bytes), sign extend negative.
/// - Bools: Non-zero = true; minimal ≤4 bytes.
/// - BigInts: No range limit; LE with optional sign bit on MSB.
use crate::util::{Error, Result};
use num_bigint::BigInt;
use num_traits::Zero;
const MAX_BOOL_LEN: usize = 4; // Consensus: bools minimal ≤4B
const MAX_NUM_LEN: usize = 4; // Numbers ≤4B
const NUM_RANGE: i64 = 1i64 << 31; // 2^31
/// Pops a bool from the stack, decoding the top item.
///
/// # Errors
/// - `Error::ScriptError("Empty stack for bool")` if empty.
/// - `Error::ScriptError("Bool too long: N bytes")` if >4 bytes (non-minimal).
///
/// # Examples
/// ```
/// use nour::script::stack::pop_bool;
/// let mut stack = vec![vec![1]];
/// assert_eq!(pop_bool(&mut stack).unwrap(), true);
/// ```
#[inline]
pub fn pop_bool(stack: &mut Vec<Vec<u8>>) -> Result<bool> {
    let top = stack
        .pop()
        .ok_or(Error::ScriptError("Empty stack for bool".to_string()))?;
    if top.len() > MAX_BOOL_LEN {
        return Err(Error::ScriptError(format!(
            "Bool too long: {} bytes",
            top.len()
        )));
    }
    Ok(decode_bool(&top))
}
/// Pops a number from the stack, decoding to i32.
///
/// # Errors
/// - `Error::ScriptError("Empty stack for num")` if empty.
/// - `Error::ScriptError("Num too long: N bytes")` if >4 bytes.
/// - `Error::ScriptError("Number out of range")` if outside [-2^31 + 1, 2^31 - 1].
///
/// # Examples
/// ```
/// use nour::script::stack::pop_num;
/// let mut stack = vec![vec![1]];
/// assert_eq!(pop_num(&mut stack).unwrap(), 1i32);
/// ```
#[inline]
pub fn pop_num(stack: &mut Vec<Vec<u8>>) -> Result<i32> {
    let top = stack
        .pop()
        .ok_or(Error::ScriptError("Empty stack for num".to_string()))?;
    if top.len() > MAX_NUM_LEN {
        return Err(Error::ScriptError(format!(
            "Num too long: {} bytes",
            top.len()
        )));
    }
    decode_num(&top).map(|n| n as i32)
}
/// Pops a bigint from the stack.
///
/// Arbitrary precision; no range limit.
///
/// # Errors
/// - `Error::ScriptError("Empty stack for bigint")` if empty.
///
/// # Examples
/// ```
/// use num_bigint::BigInt;
/// use nour::script::stack::pop_bigint;
/// let mut stack = vec![vec![1]];
/// assert_eq!(pop_bigint(&mut stack).unwrap(), BigInt::from(1u8));
/// ```
#[inline]
pub fn pop_bigint(stack: &mut Vec<Vec<u8>>) -> Result<BigInt> {
    let top = stack
        .pop()
        .ok_or(Error::ScriptError("Empty stack for bigint".to_string()))?;
    Ok(decode_bigint(&top))
}
/// Decodes a stack item to bool (non-zero true).
///
/// Ignores leading zeros; truthy if any non-zero byte (MSB &127 for last byte).
///
/// # Examples
/// ```
/// use nour::script::stack::decode_bool;
/// assert_eq!(decode_bool(&[1]), true);
/// assert_eq!(decode_bool(&[0, 0, 0, 128]), false); // 128 &127 =0
/// ```
#[inline]
pub fn decode_bool(s: &[u8]) -> bool {
    if s.is_empty() {
        return false;
    }
    for &byte in &s[..s.len().saturating_sub(1)] {
        if byte != 0 {
            return true;
        }
    }
    (s[s.len() - 1] & 127) != 0
}
/// Decodes a stack item to i64 number (LE, sign in MSB).
///
/// Minimal check: No leading zeros except sign; errors on non-canonical.
///
/// # Errors
/// - `Error::ScriptError("Non-minimal number")` if non-canonical.
/// - `Error::ScriptError("Number out of range")` if >2^31 or <-2^31 +1.
///
/// # Examples
/// ```
/// use nour::script::stack::decode_num;
/// assert_eq!(decode_num(&[1]).unwrap(), 1i64);
/// assert_eq!(decode_num(&[255]).unwrap(), -1i64);
/// ```
#[inline]
pub fn decode_num(s: &[u8]) -> Result<i64> {
    let high = if s.is_empty() { 0u8 } else { s[s.len() - 1] };
    let sign = (high & 0x80) != 0;
    let mut extended: Vec<u8> = s.to_vec();
    while extended.len() < 8 {
        extended.push(if sign { 0xffu8 } else { 0u8 });
    }
    let n = i64::from_le_bytes(
        extended
            .try_into()
            .map_err(|_| Error::ScriptError("Invalid extension".to_string()))?,
    );
    if n.abs() >= NUM_RANGE {
        return Err(Error::ScriptError("Number out of range".to_string()));
    }
    Ok(n)
}
/// Encodes i64 to minimal stack item (1-4 bytes LE, sign in MSB).
///
/// # Errors
/// - `Error::ScriptError("Number out of range")` if outside range.
///
/// # Examples
/// ```
/// use nour::script::stack::encode_num;
/// assert_eq!(encode_num(1).unwrap(), vec![1]);
/// assert_eq!(encode_num(-1).unwrap(), vec![255]); // 255u8 = -1 signed
/// ```
#[inline]
pub fn encode_num(val: i64) -> Result<Vec<u8>> {
    if val.abs() >= NUM_RANGE {
        return Err(Error::ScriptError("Number out of range".to_string()));
    }
    if val == 0 {
        return Ok(vec![]);
    }
    let full = (val as i32).to_le_bytes();
    for l in 1..=4usize {
        let test = full[0..l].to_vec();
        let high_byte = test[l - 1];
        let is_neg = (high_byte & 0x80) != 0;
        let mut extended = test.clone();
        for _ in l..4 {
            extended.push(if is_neg { 0xffu8 } else { 0u8 });
        }
        let decoded = i32::from_le_bytes(
            extended
                .try_into()
                .map_err(|_| Error::ScriptError("Invalid slice".to_string()))?,
        ) as i64;
        if decoded == val {
            return Ok(test);
        }
    }
    unreachable!("Value out of 32-bit range")
}
/// Decodes bytes to BigInt (LE, sign from MSB if set).
///
/// # Examples
/// ```
/// use num_bigint::BigInt;
/// use nour::script::stack::decode_bigint;
/// assert_eq!(decode_bigint(&[1, 0]), BigInt::from(1u16));
/// ```
#[inline]
pub fn decode_bigint(s: &[u8]) -> BigInt {
    BigInt::from_signed_bytes_le(s)
}
/// Encodes BigInt to minimal stack item (LE bytes, sign in MSB if negative).
///
/// Trims leading zeros; sets MSB sign bit for negative.
///
/// # Examples
/// ```
/// use num_bigint::BigInt;
/// use nour::script::stack::encode_bigint;
/// let bi = BigInt::from(1234u32);
/// assert_eq!(encode_bigint(&bi), vec![210, 4]); // LE 0x04D2
/// ```
#[inline]
pub fn encode_bigint(bi: &BigInt) -> Vec<u8> {
    if *bi == BigInt::zero() {
        return vec![];
    }
    bi.to_signed_bytes_le()
}
#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigInt;
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
        assert_eq!(
            pop_bool(&mut stack).unwrap_err().to_string(),
            "Script error: Empty stack for bool"
        );
        let mut stack = vec![vec![0; 5]];
        assert_eq!(
            pop_bool(&mut stack).unwrap_err().to_string(),
            "Script error: Bool too long: 5 bytes"
        );
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
        assert_eq!(
            encode_num(2_147_483_648).unwrap_err().to_string(),
            "Script error: Number out of range"
        );
        assert_eq!(
            encode_num(-2_147_483_648).unwrap_err().to_string(),
            "Script error: Number out of range"
        );
        // Roundtrip
        assert_eq!(decode_num(&encode_num(0).unwrap()).unwrap(), 0);
        assert_eq!(decode_num(&encode_num(1).unwrap()).unwrap(), 1);
        assert_eq!(decode_num(&encode_num(-1).unwrap()).unwrap(), -1);
        assert_eq!(decode_num(&encode_num(1_111).unwrap()).unwrap(), 1_111);
        assert_eq!(decode_num(&encode_num(-1_111).unwrap()).unwrap(), -1_111);
        assert_eq!(decode_num(&encode_num(111_111).unwrap()).unwrap(), 111_111);
        assert_eq!(
            decode_num(&encode_num(-111_111).unwrap()).unwrap(),
            -111_111
        );
        assert_eq!(
            decode_num(&encode_num(2_147_483_647).unwrap()).unwrap(),
            2_147_483_647
        );
        assert_eq!(
            decode_num(&encode_num(-2_147_483_647).unwrap()).unwrap(),
            -2_147_483_647
        );
    }
    #[test]
    fn pop_num_tests() {
        let mut stack = vec![vec![]];
        assert_eq!(pop_num(&mut stack).unwrap(), 0i32);
        let mut stack = vec![vec![1]];
        assert_eq!(pop_num(&mut stack).unwrap(), 1i32);
        let mut stack = vec![vec![255]]; // -1
        assert_eq!(pop_num(&mut stack).unwrap(), -1i32);
        let mut stack = vec![vec![0, 0, 0, 0]];
        assert_eq!(pop_num(&mut stack).unwrap(), 0i32);
        let mut stack = vec![];
        let err = pop_num(&mut stack).unwrap_err();
        assert_eq!(err.to_string(), "Script error: Empty stack for num");
        let mut stack = vec![vec![0; 5]];
        let err = pop_num(&mut stack).unwrap_err();
        assert_eq!(err.to_string(), "Script error: Num too long: 5 bytes");
    }
    #[test]
    fn bigint_tests() {
        let bi_zero = BigInt::zero();
        assert_eq!(encode_bigint(&bi_zero), Vec::<u8>::new());
        let bi_1234 = BigInt::from(1234u32);
        let bytes_1234 = encode_bigint(&bi_1234);
        assert_eq!(decode_bigint(&bytes_1234), bi_1234);
        let bi_neg1234 = -bi_1234.clone();
        let bytes_neg = encode_bigint(&bi_neg1234);
        assert!(bytes_neg.last().unwrap() & 0x80 != 0); // Sign bit set on MSB
        assert_eq!(decode_bigint(&bytes_neg), bi_neg1234);
    }
}

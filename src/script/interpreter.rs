//! Script interpreter for Bitcoin SV consensus evaluation.
//!
//! Executes opcodes with stack management, branching, and checker callbacks for signatures/locktime.
//! Supports Genesis (NO_FLAGS) and pre-Genesis (PREGENESIS_RULES) rules.

use crate::script::{op_codes::*, stack::*, Checker};
use crate::transaction::sighash::SIGHASH_FORKID;
use crate::util::{hash160, lshift, rshift, sha256d, Error, Result};
use bitcoin_hashes::{hash160 as bh_hash160, sha256d as bh_sha256d, Hash as BHHash}; // SIMD opt
use num_bigint::BigInt; // Fallback for large nums
use num_traits::{One, ToPrimitive, Zero};
use std::borrow::Cow;
use std::collections::VecDeque;

/// Default stack capacity (exceed errors).
pub const STACK_CAPACITY: usize = 100;
/// Alternate stack capacity.
pub const ALT_STACK_CAPACITY: usize = 10;
/// Execute with Genesis rules (OP_RETURN allowed in scripts).
pub const NO_FLAGS: u32 = 0x00;
/// Execute with pre-Genesis rules (OP_RETURN errors in non-coinbase).
pub const PREGENESIS_RULES: u32 = 0x01;

/// Evaluates a script using the checker and flags.
///
/// # Errors
/// - `Error::ScriptError` for invalid ops, underflow, div0, etc.
/// - Propagates from checker (e.g., sig fail).
///
/// # Panics
/// Stack overflow (rare, capped).
///
/// # Examples
/// ```
/// use nour::script::{eval, op_codes::*, TransactionlessChecker, NO_FLAGS};
/// let script = [OP_10, OP_5, OP_DIV];
/// eval(&script, &mut TransactionlessChecker::default(), NO_FLAGS).unwrap();
/// ```
#[must_use]
pub fn eval<T: Checker>(script: &[u8], checker: &mut T, flags: u32) -> Result<()> {
    let mut stack: VecDeque<Cow<'_, [u8]>> = VecDeque::with_capacity(STACK_CAPACITY);
    let mut alt_stack: VecDeque<Cow<'_, [u8]>> = VecDeque::with_capacity(ALT_STACK_CAPACITY);
    let mut branch_exec: Vec<bool> = Vec::new();
    let mut check_index = 0;
    let mut i = 0;
    'outer: while i < script.len() {
        if let Some(exec) = branch_exec.last() {
            if !*exec {
                i = skip_branch(script, i);
                if i >= script.len() {
                    break;
                }
                continue;
            }
        }
        let op = script[i];
        i += 1;
        match op {
            OP_0 => stack.push_back(encode_num(0)?.into()),
            OP_1NEGATE => stack.push_back(encode_num(-1)?.into()),
            OP_1 => stack.push_back(encode_num(1)?.into()),
            OP_2 => stack.push_back(encode_num(2)?.into()),
            OP_3 => stack.push_back(encode_num(3)?.into()),
            OP_4 => stack.push_back(encode_num(4)?.into()),
            OP_5 => stack.push_back(encode_num(5)?.into()),
            OP_6 => stack.push_back(encode_num(6)?.into()),
            OP_7 => stack.push_back(encode_num(7)?.into()),
            OP_8 => stack.push_back(encode_num(8)?.into()),
            OP_9 => stack.push_back(encode_num(9)?.into()),
            OP_10 => stack.push_back(encode_num(10)?.into()),
            OP_11 => stack.push_back(encode_num(11)?.into()),
            OP_12 => stack.push_back(encode_num(12)?.into()),
            OP_13 => stack.push_back(encode_num(13)?.into()),
            OP_14 => stack.push_back(encode_num(14)?.into()),
            OP_15 => stack.push_back(encode_num(15)?.into()),
            OP_16 => stack.push_back(encode_num(16)?.into()),
            len @ 1..=75 => {
                remains(i, len as usize, script)?;
                if len as usize > 520 {
                    return Err(Error::ScriptError("Push data too large".to_string()));
                }
                let slice = &script[i..i + len as usize];
                stack.push_back(Cow::Borrowed(slice));
                i += len as usize;
                continue 'outer;
            }
            OP_PUSHDATA1 => {
                remains(i, 1, script)?;
                let len = script[i] as usize;
                i += 1;
                remains(i, len, script)?;
                if len > 520 {
                    return Err(Error::ScriptError("Push data too large".to_string()));
                }
                let slice = &script[i..i + len];
                stack.push_back(Cow::Borrowed(slice));
                i += len;
                continue 'outer;
            }
            OP_PUSHDATA2 => {
                remains(i, 2, script)?;
                let len = u16::from_le_bytes([script[i], script[i + 1]]) as usize;
                i += 2;
                remains(i, len, script)?;
                if len > 520 {
                    return Err(Error::ScriptError("Push data too large".to_string()));
                }
                let slice = &script[i..i + len];
                stack.push_back(Cow::Borrowed(slice));
                i += len;
                continue 'outer;
            }
            OP_PUSHDATA4 => {
                remains(i, 4, script)?;
                let len = u32::from_le_bytes([script[i], script[i + 1], script[i + 2], script[i + 3]]) as usize;
                i += 4;
                remains(i, len, script)?;
                if len > 520 {
                    return Err(Error::ScriptError("Push data too large".to_string()));
                }
                let slice = &script[i..i + len];
                stack.push_back(Cow::Borrowed(slice));
                i += len;
                continue 'outer;
            }
            OP_NOP => {}
            OP_IF => branch_exec.push(pop_bool(&mut stack)?),
            OP_NOTIF => branch_exec.push(!pop_bool(&mut stack)?),
            OP_ELSE => {
                let len = branch_exec.len();
                if len == 0 {
                    return Err(Error::ScriptError("ELSE without IF".to_string()));
                }
                branch_exec[len - 1] = !branch_exec[len - 1];
            }
            OP_ENDIF => {
                if branch_exec.is_empty() {
                    return Err(Error::ScriptError("ENDIF without IF".to_string()));
                }
                branch_exec.pop();
            }
            OP_VERIFY => {
                if !pop_bool(&mut stack)? {
                    return Err(Error::ScriptError("OP_VERIFY failed".to_string()));
                }
            }
            OP_RETURN => {
                if flags & PREGENESIS_RULES != 0 {
                    return Err(Error::ScriptError("OP_RETURN disallowed pre-Genesis".to_string()));
                }
                break 'outer;
            }
            OP_TOALTSTACK => {
                check_stack_size(1, &stack)?;
                alt_stack.push_back(stack.pop_back().unwrap());
            }
            OP_FROMALTSTACK => {
                check_stack_size(1, &alt_stack)?;
                stack.push_back(alt_stack.pop_back().unwrap());
            }
            OP_IFDUP => {
                check_stack_size(1, &stack)?;
                if decode_bool(stack.back().unwrap()) {
                    let copy = stack.back().cloned().unwrap_or_default();
                    stack.push_back(copy);
                }
            }
            OP_DEPTH => stack.push_back(encode_num(stack.len() as i64)?.into()),
            OP_DROP => {
                check_stack_size(1, &stack)?;
                stack.pop_back();
            }
            OP_DUP => {
                check_stack_size(1, &stack)?;
                let copy = stack.back().cloned().unwrap_or_default();
                stack.push_back(copy);
            }
            OP_NIP => {
                check_stack_size(2, &stack)?;
                stack.remove(stack.len() - 2);
            }
            OP_OVER => {
                check_stack_size(2, &stack)?;
                let copy = stack[stack.len() - 2].clone();
                stack.push_back(copy);
            }
            OP_PICK => {
                let n = pop_num(&mut stack)?;
                if n < 0 {
                    return Err(Error::ScriptError("OP_PICK negative n".to_string()));
                }
                let idx = (stack.len() as i64).saturating_sub(n as i64 + 1) as usize;
                if idx >= stack.len() {
                    return Err(Error::ScriptError("OP_PICK out of range".to_string()));
                }
                let copy = stack[idx].clone();
                stack.push_back(copy);
            }
            OP_ROLL => {
                let n = pop_num(&mut stack)?;
                if n < 0 {
                    return Err(Error::ScriptError("OP_ROLL negative n".to_string()));
                }
                let idx = (stack.len() as i64).saturating_sub(n as i64 + 1) as usize;
                if idx >= stack.len() {
                    return Err(Error::ScriptError("OP_ROLL out of range".to_string()));
                }
                let item = stack.remove(idx).into_owned();
                stack.push_back(item);
            }
            OP_ROT => {
                check_stack_size(3, &stack)?;
                let idx = stack.len() - 3;
                let third = stack.remove(idx).into_owned();
                stack.push_back(third);
            }
            OP_SWAP => {
                check_stack_size(2, &stack)?;
                let idx = stack.len() - 2;
                let second = stack.remove(idx).into_owned();
                stack.push_back(second);
            }
            OP_TUCK => {
                check_stack_size(2, &stack)?;
                let len = stack.len();
                let top = stack[len - 1].clone();
                stack.insert(len - 2, top);
            }
            OP_2DROP => {
                check_stack_size(2, &stack)?;
                stack.pop_back();
                stack.pop_back();
            }
            OP_2DUP => {
                check_stack_size(2, &stack)?;
                let len = stack.len();
                let top = stack[len - 1].clone();
                let second = stack[len - 2].clone();
                stack.push_back(second);
                stack.push_back(top);
            }
            OP_3DUP => {
                check_stack_size(3, &stack)?;
                let len = stack.len();
                let top = stack[len - 1].clone();
                let second = stack[len - 2].clone();
                let third = stack[len - 3].clone();
                stack.push_back(third);
                stack.push_back(second);
                stack.push_back(top);
            }
            OP_2OVER => {
                check_stack_size(4, &stack)?;
                let len = stack.len();
                let third = stack[len - 3].clone();
                let fourth = stack[len - 4].clone();
                stack.push_back(fourth);
                stack.push_back(third);
            }
            OP_2ROT => {
                check_stack_size(6, &stack)?;
                let idx = stack.len() - 6;
                let sixth = stack.remove(idx).into_owned();
                let fifth = stack.remove(idx).into_owned();
                stack.push_back(sixth);
                stack.push_back(fifth);
            }
            OP_2SWAP => {
                check_stack_size(4, &stack)?;
                let idx = stack.len() - 4;
                let fourth = stack.remove(idx).into_owned();
                let third = stack.remove(idx).into_owned();
                stack.push_back(fourth);
                stack.push_back(third);
            }
            OP_CAT => {
                check_stack_size(2, &stack)?;
                let top = stack.pop_back().unwrap().into_owned();
                let mut second = stack.pop_back().unwrap().into_owned();
                second.extend(top);
                stack.push_back(second.into());
            }
            OP_SPLIT => {
                check_stack_size(2, &stack)?;
                let n = pop_num(&mut stack)?;
                let x = stack.pop_back().unwrap().into_owned();
                if n < 0 {
                    return Err(Error::ScriptError("OP_SPLIT negative n".to_string()));
                }
                let n_usize = n as usize;
                if n_usize > x.len() {
                    return Err(Error::ScriptError("OP_SPLIT n out of range".to_string()));
                }
                if n_usize == 0 {
                    stack.push_back(encode_num(0)?.into());
                    stack.push_back(x.into());
                } else if n_usize == x.len() {
                    stack.push_back(x.into());
                    stack.push_back(encode_num(0)?.into());
                } else {
                    let left = x[..n_usize].to_vec().into();
                    let right = x[n_usize..].to_vec().into();
                    stack.push_back(left);
                    stack.push_back(right);
                }
            }
            OP_SIZE => {
                check_stack_size(1, &stack)?;
                let len = stack.back().map_or(0, |item| item.len());
                stack.push_back(encode_num(len as i64)?.into());
            }
            OP_AND => arith_binary(&mut stack, |a, b| {
                if a.len() != b.len() {
                    Err(Error::ScriptError("OP_AND size mismatch".to_string()))
                } else {
                    let result: Vec<u8> = a.iter().zip(b.iter()).map(|(&x, &y)| x & y).collect();
                    Ok(result.into())
                }
            })?,
            OP_OR => arith_binary(&mut stack, |a, b| {
                if a.len() != b.len() {
                    Err(Error::ScriptError("OP_OR size mismatch".to_string()))
                } else {
                    let result: Vec<u8> = a.iter().zip(b.iter()).map(|(&x, &y)| x | y).collect();
                    Ok(result.into())
                }
            })?,
            OP_XOR => arith_binary(&mut stack, |a, b| {
                if a.len() != b.len() {
                    Err(Error::ScriptError("OP_XOR size mismatch".to_string()))
                } else {
                    let result: Vec<u8> = a.iter().zip(b.iter()).map(|(&x, &y)| x ^ y).collect();
                    Ok(result.into())
                }
            })?,
            OP_INVERT => {
                check_stack_size(1, &stack)?;
                let mut v = stack.pop_back().unwrap().into_owned();
                v.iter_mut().for_each(|byte| *byte = !*byte);
                stack.push_back(v.into());
            }
            OP_LSHIFT => bit_shift(&mut stack, lshift)?,
            OP_RSHIFT => bit_shift(&mut stack, rshift)?,
            OP_EQUAL => {
                check_stack_size(2, &stack)?;
                let a = stack.pop_back().unwrap();
                let b = stack.pop_back().unwrap();
                let eq = a.len() == b.len() && a == b;
                stack.push_back(encode_num(eq as i64)?.into());
            }
            OP_EQUALVERIFY => {
                check_stack_size(2, &stack)?;
                let a = stack.pop_back().unwrap();
                let b = stack.pop_back().unwrap();
                if a.len() != b.len() || a != b {
                    return Err(Error::ScriptError("OP_EQUALVERIFY mismatch".to_string()));
                }
            }
            OP_1ADD => arith_unary(&mut stack, |x| x + 1)?,
            OP_1SUB => arith_unary(&mut stack, |x| x - 1)?,
            OP_NEGATE => arith_unary(&mut stack, |x| -x)?,
            OP_ABS => arith_unary(&mut stack, |x| if x < 0 { -x } else { x })?,
            OP_NOT => arith_unary(&mut stack, |x| if x == 0 { 1 } else { 0 })?,
            OP_0NOTEQUAL => arith_unary(&mut stack, |x| if x == 0 { 0 } else { 1 })?,
            OP_ADD => arith_binary_num(&mut stack, |a, b| a + b)?,
            OP_SUB => arith_binary_num(&mut stack, |a, b| a - b)?,
            OP_MUL => arith_binary_num(&mut stack, |a, b| a * b)?,
            OP_DIV => arith_binary_num(&mut stack, |a, b| {
                if b == 0 {
                    Err(Error::ScriptError("OP_DIV by zero".to_string()))
                } else {
                    Ok(a / b)
                }
            })?,
            OP_MOD => arith_binary_num(&mut stack, |a, b| {
                if b == 0 {
                    Err(Error::ScriptError("OP_MOD by zero".to_string()))
                } else {
                    Ok(a % b)
                }
            })?,
            OP_BOOLAND => arith_binary_num(&mut stack, |a, b| (a != 0 && b != 0).into())?,
            OP_BOOLOR => arith_binary_num(&mut stack, |a, b| (a != 0 || b != 0).into())?,
            OP_NUMEQUAL => arith_binary_num(&mut stack, |a, b| (a == b).into())?,
            OP_NUMEQUALVERIFY => {
                let b = pop_num(&mut stack)?;
                let a = pop_num(&mut stack)?;
                if a != b {
                    return Err(Error::ScriptError("OP_NUMEQUALVERIFY mismatch".to_string()));
                }
            }
            OP_NUMNOTEQUAL => arith_binary_num(&mut stack, |a, b| (a != b).into())?,
            OP_LESSTHAN => arith_binary_num(&mut stack, |a, b| (a < b).into())?,
            OP_GREATERTHAN => arith_binary_num(&mut stack, |a, b| (a > b).into())?,
            OP_LESSTHANOREQUAL => arith_binary_num(&mut stack, |a, b| (a <= b).into())?,
            OP_GREATERTHANOREQUAL => arith_binary_num(&mut stack, |a, b| (a >= b).into())?,
            OP_MIN => arith_binary_num(&mut stack, |a, b| std::cmp::min(a, b))?,
            OP_MAX => arith_binary_num(&mut stack, |a, b| std::cmp::max(a, b))?,
            OP_WITHIN => {
                let max = pop_num(&mut stack)?;
                let min = pop_num(&mut stack)?;
                let x = pop_num(&mut stack)?;
                stack.push_back(encode_num((x >= min && x < max) as i64)?.into());
            }
            OP_NUM2BIN => {
                check_stack_size(2, &stack)?;
                let m = pop_num(&mut stack)?;
                let mut n = stack.pop_back().unwrap().into_owned();
                if m < 1 {
                    return Err(Error::ScriptError(format!("OP_NUM2BIN m too small: {}", m)));
                }
                let nlen = n.len();
                if m as usize > 2_147_483_647 || m as usize < nlen {
                    return Err(Error::ScriptError("OP_NUM2BIN m invalid".to_string()));
                }
                let mut v = vec![0u8; m as usize];
                let mut neg = 0;
                if nlen > 0 {
                    neg = (n[nlen - 1] & 128) as i64;
                    n[nlen - 1] &= 127;
                }
                v[m as usize - nlen..].copy_from_slice(&n);
                if neg != 0 {
                    v[0] |= 128;
                }
                stack.push_back(v.into());
            }
            OP_BIN2NUM => {
                check_stack_size(1, &mut stack)?;
                let mut v = stack.pop_back().unwrap().into_owned();
                v.reverse();
                let n = decode_bigint(&mut v);
                stack.push_back(encode_bigint(n).into());
            }
            OP_RIPEMD160 => {
                check_stack_size(1, &stack)?;
                let v = stack.pop_back().unwrap();
                let mut ripemd = Ripemd160::new();
                ripemd.update(v.as_ref());
                stack.push_back(ripemd.finalize().to_vec().into());
            }
            OP_SHA1 => {
                check_stack_size(1, &stack)?;
                let v = stack.pop_back().unwrap();
                use ring::digest::SHA1_FOR_LEGACY_USE_ONLY;
                let result = digest(&SHA1_FOR_LEGACY_USE_ONLY, v.as_ref());
                stack.push_back(result.as_ref().to_vec().into());
            }
            OP_SHA256 => {
                check_stack_size(1, &stack)?;
                let v = stack.pop_back().unwrap();
                let result = digest(&SHA256, v.as_ref());
                stack.push_back(result.as_ref().to_vec().into());
            }
            OP_HASH160 => {
                check_stack_size(1, &stack)?;
                let v = stack.pop_back().unwrap();
                let h = bh_hash160::Hash::hash(v.as_ref()).to_byte_array().to_vec();
                stack.push_back(h.into());
            }
            OP_HASH256 => {
                check_stack_size(1, &stack)?;
                let v = stack.pop_back().unwrap();
                let h = bh_sha256d::Hash::hash(v.as_ref()).to_byte_array().to_vec();
                stack.push_back(h.into());
            }
            OP_CODESEPARATOR => check_index = i,
            OP_CHECKSIG => {
                check_stack_size(2, &stack)?;
                let pubkey = stack.pop_back().unwrap().into_owned();
                let sig = stack.pop_back().unwrap().into_owned();
                let mut cleaned_script = script[check_index..].to_vec();
                if prefork(&sig) {
                    cleaned_script = remove_sig(&sig, &cleaned_script);
                }
                let success = checker.check_sig(&sig, &pubkey, &cleaned_script)?;
                stack.push_back(encode_num(success as i64)?.into());
            }
            OP_CHECKSIGVERIFY => {
                check_stack_size(2, &stack)?;
                let pubkey = stack.pop_back().unwrap().into_owned();
                let sig = stack.pop_back().unwrap().into_owned();
                let mut cleaned_script = script[check_index..].to_vec();
                if prefork(&sig) {
                    cleaned_script = remove_sig(&sig, &cleaned_script);
                }
                if !checker.check_sig(&sig, &pubkey, &cleaned_script)? {
                    return Err(Error::ScriptError("OP_CHECKSIGVERIFY failed".to_string()));
                }
            }
            OP_CHECKMULTISIG => {
                let success = check_multisig(&mut stack, checker, &script[check_index..])?;
                stack.push_back(encode_num(success as i64)?.into());
            }
            OP_CHECKMULTISIGVERIFY => {
                if !check_multisig(&mut stack, checker, &script[check_index..])? {
                    return Err(Error::ScriptError("OP_CHECKMULTISIGVERIFY failed".to_string()));
                }
            }
            OP_CHECKLOCKTIMEVERIFY if flags & PREGENESIS_RULES != 0 => {
                let locktime = pop_num(&mut stack)?;
                if !checker.check_locktime(locktime)? {
                    return Err(Error::ScriptError("OP_CHECKLOCKTIMEVERIFY failed".to_string()));
                }
            }
            OP_CHECKSEQUENCEVERIFY if flags & PREGENESIS_RULES != 0 => {
                let sequence = pop_num(&mut stack)?;
                if !checker.check_sequence(sequence)? {
                    return Err(Error::ScriptError("OP_CHECKSEQUENCEVERIFY failed".to_string()));
                }
            }
            OP_NOP1 | OP_NOP4 | OP_NOP5 | OP_NOP6 | OP_NOP7 | OP_NOP8 | OP_NOP9 | OP_NOP10 => {}
            _ => return Err(Error::ScriptError(format!("Invalid opcode 0x{:02x} at {}", op, i - 1))),
        }
        i = next_op(i - 1, script); // Adjust for i++ 
    }
    if !branch_exec.is_empty() {
        return Err(Error::ScriptError("Unmatched ENDIF".to_string()));
    }
    check_stack_size(1, &stack)?;
    if !decode_bool(stack.back().unwrap()) {
        return Err(Error::ScriptError("False final stack".to_string()));
    }
    Ok(())
}

#[inline]
fn arith_unary<F>(stack: &mut VecDeque<Cow<'_, [u8]>>, op: F) -> Result<()>
where
    F: FnOnce(i64) -> i64,
{
    check_stack_size(1, stack)?;
    let item = stack.pop_back().unwrap();
    let n = pop_num_from_item(&item)?;
    stack.push_back(encode_num(op(n))?.into());
    Ok(())
}

#[inline]
fn arith_binary_num<F>(stack: &mut VecDeque<Cow<'_, [u8]>>, op: F) -> Result<()>
where
    F: FnOnce(i64, i64) -> Result<i64>,
{
    check_stack_size(2, stack)?;
    let b_item = stack.pop_back().unwrap();
    let a_item = stack.pop_back().unwrap();
    let b = pop_num_from_item(&b_item)?;
    let a = pop_num_from_item(&a_item)?;
    let result = op(a, b)?;
    stack.push_back(encode_num(result)?.into());
    Ok(())
}

#[inline]
fn pop_num_from_item(item: &Cow<'_, [u8]>) -> Result<i64> {
    if item.len() > 4 {
        let mut v = item.to_vec();
        let bi = decode_bigint(&mut v);
        bi.to_i64().ok_or(Error::ScriptError("Num too large".to_string()))
    } else {
        pop_num_from_slice(item)
    }
}

#[inline]
fn bit_shift<F>(stack: &mut VecDeque<Cow<'_, [u8]>>, shift_fn: F) -> Result<()>
where
    F: FnOnce(&[u8], usize) -> Vec<u8>,
{
    check_stack_size(2, stack)?;
    let n_item = stack.pop_back().unwrap();
    let v_item = stack.pop_back().unwrap();
    let n = pop_num_from_item(&n_item)?;
    if n < 0 {
        return Err(Error::ScriptError("Negative shift".to_string()));
    }
    let result = shift_fn(v_item.as_ref(), n as usize);
    stack.push_back(result.into());
    Ok(())
}

#[inline]
fn arith_binary<F>(stack: &mut VecDeque<Cow<'_, [u8]>>, op: F) -> Result<()>
where
    F: FnOnce(&[u8], &[u8]) -> Result<Cow<'static, [u8]>>,
{
    check_stack_size(2, stack)?;
    let a = stack.pop_back().unwrap();
    let b = stack.pop_back().unwrap();
    let result = op(a.as_ref(), b.as_ref())?;
    stack.push_back(result);
    Ok(())
}

#[inline]
fn check_multisig<T: Checker>(
    stack: &mut VecDeque<Cow<'_, [u8]>>,
    checker: &mut T,
    script: &[u8],
) -> Result<bool> {
    let total = pop_num(stack)?;
    if total < 0 {
        return Err(Error::ScriptError("Multisig total negative".to_string()));
    }
    check_stack_size(total as usize, stack)?;
    let mut keys: Vec<Vec<u8>> = (0..total as usize).map(|_| stack.pop_back().unwrap().into_owned()).collect();
    let required = pop_num(stack)?;
    if required < 0 || required > total {
        return Err(Error::ScriptError("Multisig required invalid".to_string()));
    }
    check_stack_size(required as usize, stack)?;
    let mut sigs: Vec<Vec<u8>> = (0..required as usize).map(|_| stack.pop_back().unwrap().into_owned()).collect();
    // Dummy pop
    check_stack_size(1, stack)?;
    stack.pop_back();
    let mut cleaned_script = script.to_vec();
    for sig in &sigs {
        if prefork(sig) {
            cleaned_script = remove_sig(sig, &cleaned_script);
        }
    }
    let mut key_idx = 0;
    let mut sig_idx = 0;
    while sig_idx < sigs.len() {
        if key_idx == keys.len() {
            return Ok(false);
        }
        if checker.check_sig(&sigs[sig_idx], &keys[key_idx], &cleaned_script)? {
            sig_idx += 1;
        }
        key_idx += 1;
    }
    Ok(sig_idx == required as usize)
}

#[inline]
fn prefork(sig: &[u8]) -> bool {
    !sig.is_empty() && (sig[sig.len() - 1] & SIGHASH_FORKID == 0)
}

/// Removes signature pushes from script for pre-fork verification.
#[must_use]
fn remove_sig(sig: &[u8], script: &[u8]) -> Vec<u8> {
    if sig.is_empty() {
        return script.to_vec();
    }
    let mut result = Vec::with_capacity(script.len());
    let mut i = 0;
    let mut start = 0;
    while i + sig.len() <= script.len() {
        if &script[i..i + sig.len()] == sig {
            result.extend_from_slice(&script[start..i]);
            start = i + sig.len();
            i = start;
        } else {
            i = next_op(i, script);
        }
    }
    result.extend_from_slice(&script[start..]);
    result
}

#[inline]
fn check_stack_size(min: usize, stack: &VecDeque<Cow<'_, [u8]>>) -> Result<()> {
    if stack.len() < min {
        Err(Error::ScriptError(format!("Stack underflow: need {}", min)))
    } else {
        Ok(())
    }
}

#[inline]
fn remains(i: usize, len: usize, script: &[u8]) -> Result<()> {
    if i + len > script.len() {
        Err(Error::ScriptError("Script truncated".to_string()))
    } else {
        Ok(())
    }
}

/// Skips to next opcode, clamping to end.
#[must_use]
#[inline]
pub fn next_op(i: usize, script: &[u8]) -> usize {
    if i >= script.len() {
        return script.len();
    }
    let op = script[i];
    match op {
        len @ 1..=75 => (i + 1 + len as usize).min(script.len()),
        OP_PUSHDATA1 if i + 2 <= script.len() => {
            let len = script[i + 1] as usize;
            (i + 2 + len).min(script.len())
        }
        OP_PUSHDATA2 if i + 3 <= script.len() => {
            let len = u16::from_le_bytes([script[i + 1], script[i + 2]]) as usize;
            (i + 3 + len).min(script.len())
        }
        OP_PUSHDATA4 if i + 5 <= script.len() => {
            let len = u32::from_le_bytes([script[i + 1], script[i + 2], script[i + 3], script[i + 4]]) as usize;
            (i + 5 + len).min(script.len())
        }
        _ => i + 1,
    }
}

/// Skips IF/ELSE branch to matching ELSE/ENDIF.
#[must_use]
fn skip_branch(script: &[u8], mut i: usize) -> usize {
    let mut count = 0;
    while i < script.len() {
        match script[i] {
            OP_IF | OP_NOTIF => count += 1,
            OP_ELSE if count == 0 => return i,
            OP_ENDIF if count == 0 => return i,
            OP_ENDIF => count -= 1,
            _ => {}
        }
        i = next_op(i, script);
    }
    script.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::Script;
    use hex;
    use std::cell::RefCell;

    #[test]
    fn op_div_example() {
        let script = [OP_10, OP_5, OP_DIV];
        let mut checker = MockChecker::default();
        assert!(eval(&script, &mut checker, NO_FLAGS).is_ok());
    }

    // MockChecker and pass/fail helpers retained as-is for brevity
    // Add:
    use pretty_assertions::assert_eq;

    fn pass(script: &[u8]) {
        let mut c = MockChecker::default();
        assert!(eval(script, &mut c, NO_FLAGS).is_ok(), "Failed: {:?}", script);
    }
}

#[test]
    fn valid() {
        pass(&[OP_TRUE]);
        pass(&[OP_16]);
        pass(&[OP_PUSH + 1, 1]);
        pass(&[OP_PUSHDATA1, 2, 0, 1]);
        pass(&[OP_PUSHDATA2, 2, 0, 0, 1]);
        pass(&[OP_PUSHDATA4, 2, 0, 0, 0, 0, 1]);
        pass(&[OP_NOP, OP_NOP, OP_NOP, OP_1]);
        pass(&[OP_1, OP_1, OP_IF, OP_ELSE, OP_ENDIF]);
        pass(&[OP_1, OP_1, OP_1, OP_IF, OP_IF, OP_ENDIF, OP_ENDIF]);
        pass(&[OP_1, OP_IF, OP_1, OP_ELSE, OP_0, OP_ENDIF]);
        pass(&[OP_0, OP_IF, OP_0, OP_ELSE, OP_1, OP_ENDIF]);
        pass(&[OP_1, OP_IF, OP_0, OP_1, OP_ENDIF]);
        pass(&[OP_1, OP_IF, OP_0, OP_IF, OP_ELSE, OP_1, OP_ENDIF, OP_ENDIF]);
        pass(&[OP_1, OP_IF, OP_PUSHDATA1, 1, 0, OP_1, OP_ENDIF]);
        pass(&[OP_1, OP_IF, OP_ELSE, OP_ELSE, OP_1, OP_ENDIF]);
        pass(&[
            OP_1, OP_IF, OP_ELSE, OP_ELSE, OP_ELSE, OP_ELSE, OP_1, OP_ENDIF,
        ]);
        pass(&[OP_1, OP_VERIFY, OP_1]);
        pass(&[OP_1, OP_RETURN]);
        pass(&[OP_FALSE, OP_TRUE, OP_RETURN]);
        pass(&[OP_1, OP_0, OP_TOALTSTACK]);
        pass(&[OP_1, OP_TOALTSTACK, OP_FROMALTSTACK]);
        pass(&[OP_1, OP_IFDUP, OP_DROP, OP_DROP, OP_1]);
        pass(&[OP_DEPTH, OP_1]);
        pass(&[OP_0, OP_DEPTH]);
        pass(&[OP_1, OP_0, OP_DROP]);
        pass(&[OP_0, OP_DUP, OP_DROP, OP_DROP, OP_1]);
        pass(&[OP_1, OP_0, OP_0, OP_NIP, OP_DROP]);
        pass(&[OP_1, OP_0, OP_OVER]);
        pass(&[OP_1, OP_0, OP_PICK]);
        pass(&[OP_1, OP_0, OP_0, OP_0, OP_0, OP_4, OP_PICK]);
        pass(&[OP_1, OP_0, OP_ROLL]);
        pass(&[OP_1, OP_0, OP_0, OP_ROLL, OP_DROP]);
        pass(&[OP_1, OP_0, OP_0, OP_0, OP_0, OP_4, OP_ROLL]);
        pass(&[OP_1, OP_0, OP_0, OP_ROT]);
        pass(&[OP_0, OP_1, OP_0, OP_ROT, OP_ROT]);
        pass(&[OP_0, OP_0, OP_1, OP_ROT, OP_ROT, OP_ROT]);
        pass(&[OP_1, OP_0, OP_SWAP]);
        pass(&[OP_0, OP_1, OP_TUCK, OP_DROP, OP_DROP]);
        pass(&[OP_1, OP_0, OP_0, OP_2DROP]);
        pass(&[OP_0, OP_1, OP_2DUP]);
        pass(&[OP_0, OP_1, OP_2DUP, OP_DROP, OP_DROP]);
        pass(&[OP_0, OP_0, OP_1, OP_3DUP]);
        pass(&[OP_0, OP_0, OP_1, OP_3DUP, OP_DROP, OP_DROP, OP_DROP]);
        pass(&[OP_0, OP_1, OP_0, OP_0, OP_2OVER]);
        pass(&[OP_0, OP_0, OP_0, OP_1, OP_2OVER, OP_DROP, OP_DROP]);
        pass(&[OP_0, OP_1, OP_0, OP_0, OP_0, OP_0, OP_2ROT]);
        pass(&[OP_0, OP_0, OP_0, OP_1, OP_0, OP_0, OP_2ROT, OP_2ROT]);
        pass(&[
            OP_0, OP_0, OP_0, OP_0, OP_0, OP_1, OP_2ROT, OP_2ROT, OP_2ROT,
        ]);
        pass(&[OP_1, OP_0, OP_0, OP_0, OP_0, OP_0, OP_2ROT, OP_DROP]);
        pass(&[OP_0, OP_1, OP_0, OP_0, OP_2SWAP]);
        pass(&[OP_1, OP_0, OP_0, OP_0, OP_2SWAP, OP_DROP]);
        pass(&[OP_0, OP_1, OP_CAT]);
        pass(&[OP_1, OP_0, OP_0, OP_2, OP_0, OP_CAT, OP_PICK]);
        pass(&[OP_0, OP_0, OP_CAT, OP_IF, OP_ELSE, OP_1, OP_ENDIF]);
        pass(&[OP_PUSH + 2, OP_0, OP_1, OP_1, OP_SPLIT]);
        pass(&[OP_PUSH + 2, OP_0, OP_1, OP_2, OP_SPLIT, OP_DROP]);
        pass(&[OP_PUSH + 2, OP_0, OP_1, OP_0, OP_SPLIT]);
        pass(&[OP_0, OP_0, OP_SPLIT, OP_1]);
        pass(&[OP_1, OP_1, OP_SPLIT, OP_DROP]);
        pass(&[OP_1, OP_SIZE]);
        pass(&[OP_1, OP_SIZE, OP_DROP]);
        pass(&[OP_1, OP_1, OP_AND]);
        pass(&[OP_1, OP_1, OP_OR]);
        pass(&[OP_1, OP_1, OP_XOR, OP_IF, OP_ELSE, OP_1, OP_ENDIF]);
        pass(&[
            OP_PUSH + 3,
            0xFF,
            0x01,
            0x00,
            OP_INVERT,
            OP_PUSH + 3,
            0x00,
            0xFE,
            0xFF,
            OP_EQUAL,
        ]);
        pass(&[OP_0, OP_0, OP_LSHIFT, OP_0, OP_EQUAL]);
        pass(&[OP_4, OP_2, OP_LSHIFT, OP_16, OP_EQUAL]);
        pass(&[
            OP_PUSH + 2,
            0x12,
            0x34,
            OP_4,
            OP_LSHIFT,
            OP_PUSH + 2,
            0x23,
            0x40,
            OP_EQUAL,
        ]);
        pass(&[OP_0, OP_0, OP_RSHIFT, OP_0, OP_EQUAL]);
        pass(&[OP_4, OP_2, OP_RSHIFT, OP_1, OP_EQUAL]);
        pass(&[
            OP_PUSH + 2,
            0x12,
            0x34,
            OP_4,
            OP_RSHIFT,
            OP_PUSH + 2,
            0x01,
            0x23,
            OP_EQUAL,
        ]);
        pass(&[OP_0, OP_0, OP_EQUAL]);
        pass(&[OP_1, OP_1, OP_EQUAL]);
        pass(&[OP_1, OP_0, OP_0, OP_EQUALVERIFY]);
        pass(&[OP_0, OP_1ADD]);
        pass(&[OP_1, OP_1ADD, OP_2, OP_EQUAL]);
        pass(&[OP_2, OP_1SUB]);
        pass(&[OP_0, OP_1SUB, OP_1NEGATE, OP_EQUAL]);
        let mut v = vec![OP_PUSH + 4, 0xFF, 0xFF, 0xFF, 0x7F];
        v.extend_from_slice(&[OP_1ADD, OP_SIZE, OP_5, OP_EQUAL]);
        pass(&v);
        let mut v = vec![OP_PUSH + 4, 0xFF, 0xFF, 0xFF, 0xFF];
        v.extend_from_slice(&[OP_1SUB, OP_SIZE, OP_5, OP_EQUAL]);
        pass(&v);
        pass(&[OP_1, OP_NEGATE, OP_1NEGATE, OP_EQUAL]);
        pass(&[OP_1NEGATE, OP_NEGATE, OP_1, OP_EQUAL]);
        pass(&[OP_1, OP_ABS, OP_1, OP_EQUAL]);
        pass(&[OP_1NEGATE, OP_ABS, OP_1, OP_EQUAL]);
        pass(&[OP_0, OP_NOT]);
        pass(&[OP_1, OP_NOT, OP_0, OP_EQUAL]);
        pass(&[OP_2, OP_NOT, OP_0, OP_EQUAL]);
        pass(&[OP_1, OP_NOT, OP_NOT]);
        pass(&[OP_1, OP_0NOTEQUAL]);
        pass(&[OP_0, OP_0NOTEQUAL, OP_0, OP_EQUAL]);
        pass(&[OP_2, OP_0NOTEQUAL]);
        pass(&[OP_PUSH + 5, 0, 0, 0, 0, 0, OP_1ADD]);
        pass(&[OP_PUSH + 5, 0, 0, 0, 0, 0, OP_1SUB]);
        pass(&[OP_PUSH + 5, 0, 0, 0, 0, 0, OP_NEGATE, OP_1]);
        pass(&[OP_PUSH + 5, 0, 0, 0, 0, 0, OP_ABS, OP_1]);
        pass(&[OP_PUSH + 5, 0, 0, 0, 0, 0, OP_NOT]);
        pass(&[OP_PUSH + 5, 0, 0, 0, 0, 0, OP_0NOTEQUAL, OP_1]);
        pass(&[OP_0, OP_1, OP_ADD]);
        pass(&[OP_1, OP_0, OP_ADD]);
        pass(&[OP_1, OP_2, OP_ADD, OP_3, OP_EQUAL]);
        let mut v = vec![OP_PUSH + 4, 0xFF, 0xFF, 0xFF, 0xFF];
        v.extend_from_slice(&[OP_PUSH + 4, 0xFF, 0xFF, 0xFF, 0xFF]);
        v.extend_from_slice(&[OP_ADD, OP_SIZE, OP_5, OP_EQUAL]);
        pass(&v);
        let mut v = vec![OP_PUSH + 5, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        v.extend_from_slice(&[OP_PUSH + 5, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        v.extend_from_slice(&[OP_ADD, OP_SIZE, OP_6, OP_EQUAL]);
        pass(&v);
        let mut v = vec![OP_PUSH + 4, 0xFF, 0xFF, 0xFF, 0x7F];
        v.extend_from_slice(&[OP_PUSH + 4, 0xFF, 0xFF, 0xFF, 0xFF]);
        v.extend_from_slice(&[OP_ADD, OP_0, OP_EQUAL]);
        pass(&v);
        pass(&[OP_2, OP_1, OP_SUB]);
        pass(&[OP_1, OP_1, OP_SUB, OP_0, OP_EQUAL]);
        let mut v = vec![OP_PUSH + 4, 0xFF, 0xFF, 0xFF, 0xFF];
        v.extend_from_slice(&[OP_PUSH + 4, 0xFF, 0xFF, 0xFF, 0x7F]);
        v.extend_from_slice(&[OP_SUB, OP_SIZE, OP_5, OP_EQUAL]);
        pass(&v);
        let mut v = vec![OP_PUSH + 4, 0xFF, 0xFF, 0xFF, 0x7F];
        v.extend_from_slice(&[OP_PUSH + 4, 0xFF, 0xFF, 0xFF, 0x7F]);
        v.extend_from_slice(&[OP_SUB, OP_0, OP_EQUAL]);
        pass(&v);
        pass(&[OP_1, OP_1, OP_MUL, OP_1, OP_EQUAL]);
        pass(&[OP_2, OP_3, OP_MUL, OP_6, OP_EQUAL]);
        pass(&[
            OP_PUSH + 4,
            0xFF,
            0xFF,
            0xFF,
            0x7F,
            OP_PUSH + 4,
            0xFF,
            0xFF,
            0xFF,
            0x7F,
            OP_MUL,
        ]);
        pass(&[OP_1, OP_1NEGATE, OP_MUL, OP_1NEGATE, OP_EQUAL]);
        pass(&[OP_1, OP_1, OP_DIV, OP_1, OP_EQUAL]);
        pass(&[OP_5, OP_2, OP_DIV, OP_2, OP_EQUAL]);
        pass(&[OP_2, OP_1NEGATE, OP_DIV, OP_PUSH + 1, 130, OP_EQUAL]);
        pass(&[OP_1, OP_1, OP_MOD, OP_0, OP_EQUAL]);
        pass(&[OP_5, OP_2, OP_MOD, OP_1, OP_EQUAL]);
        pass(&[OP_5, OP_PUSH + 1, 130, OP_MOD, OP_1, OP_EQUAL]);
        pass(&[OP_PUSH + 1, 133, OP_2, OP_MOD, OP_1NEGATE, OP_EQUAL]);
        pass(&[OP_1, OP_1, OP_BOOLAND]);
        pass(&[OP_0, OP_1, OP_BOOLAND, OP_0, OP_EQUAL]);
        pass(&[OP_1, OP_0, OP_BOOLOR]);
        pass(&[OP_0, OP_0, OP_BOOLOR, OP_0, OP_EQUAL]);
        pass(&[OP_1, OP_1, OP_NUMEQUAL]);
        pass(&[OP_0, OP_1, OP_NUMEQUAL, OP_NOT]);
        pass(&[OP_1, OP_1, OP_NUMEQUALVERIFY, OP_1]);
        pass(&[OP_1, OP_0, OP_NUMNOTEQUAL]);
        pass(&[OP_1, OP_1, OP_NUMNOTEQUAL, OP_NOT]);
        pass(&[OP_0, OP_1, OP_LESSTHAN]);
        pass(&[OP_1NEGATE, OP_0, OP_LESSTHAN]);
        pass(&[OP_0, OP_0, OP_LESSTHAN, OP_NOT]);
        pass(&[OP_1, OP_0, OP_GREATERTHAN]);
        pass(&[OP_0, OP_1NEGATE, OP_GREATERTHAN]);
        pass(&[OP_0, OP_0, OP_GREATERTHAN, OP_NOT]);
        pass(&[OP_0, OP_1, OP_LESSTHANOREQUAL]);
        pass(&[OP_1NEGATE, OP_0, OP_LESSTHANOREQUAL]);
        pass(&[OP_0, OP_0, OP_LESSTHANOREQUAL]);
        pass(&[OP_1, OP_0, OP_GREATERTHANOREQUAL]);
        pass(&[OP_0, OP_1NEGATE, OP_GREATERTHANOREQUAL]);
        pass(&[OP_0, OP_0, OP_GREATERTHANOREQUAL]);
        pass(&[OP_0, OP_1, OP_MIN, OP_0, OP_EQUAL]);
        pass(&[OP_0, OP_0, OP_MIN, OP_0, OP_EQUAL]);
        pass(&[OP_1NEGATE, OP_0, OP_MIN, OP_1NEGATE, OP_EQUAL]);
        pass(&[OP_0, OP_1, OP_MAX, OP_1, OP_EQUAL]);
        pass(&[OP_0, OP_0, OP_MAX, OP_0, OP_EQUAL]);
        pass(&[OP_1NEGATE, OP_0, OP_MAX, OP_0, OP_EQUAL]);
        pass(&[OP_0, OP_0, OP_1, OP_WITHIN]);
        pass(&[OP_0, OP_1NEGATE, OP_1, OP_WITHIN]);
        pass(&[OP_PUSH + 9, 0, 0, 0, 0, 0, 0, 0, 0, 1, OP_BIN2NUM]);
        pass(&[OP_PUSH + 4, 128, 0, 0, 1, OP_BIN2NUM, OP_1NEGATE, OP_EQUAL]);
        pass(&[OP_PUSH + 7, 0, 0, 0, 0, 0, 0, 0, OP_BIN2NUM, OP_0, OP_EQUAL]);
        pass(&[OP_PUSH + 5, 129, 0, 0, 0, 0, OP_BIN2NUM]);
        pass(&[OP_1, OP_16, OP_NUM2BIN]);
        pass(&[OP_0, OP_4, OP_NUM2BIN, OP_0, OP_NUMEQUAL]);
        pass(&[OP_1, OP_DUP, OP_16, OP_NUM2BIN, OP_BIN2NUM, OP_EQUAL]);
        pass(&[OP_1NEGATE, OP_DUP, OP_16, OP_NUM2BIN, OP_BIN2NUM, OP_EQUAL]);
        pass(&[OP_1, OP_PUSH + 5, 129, 0, 0, 0, 0, OP_NUM2BIN]);
        let mut v = Vec::new();
        v.push(OP_1);
        v.push(OP_PUSH + 2);
        v.extend_from_slice(&encode_num(520).unwrap());
        v.push(OP_NUM2BIN);
        pass(&v);
        pass(&[OP_1, OP_RIPEMD160]);
        pass(&[OP_0, OP_RIPEMD160]);
        let mut s = Script::new();
        let h = "cea1b21f1a739fba68d1d4290437d2c5609be1d3";
        s.append_data(&hex::decode(h).unwrap());
        s.append_data(&hex::decode("0123456789abcdef").unwrap());
        s.append_slice(&[OP_RIPEMD160, OP_EQUAL]);
        pass(&s.0);
        pass(&[OP_1, OP_SHA1]);
        pass(&[OP_0, OP_SHA1]);
        let mut s = Script::new();
        let h = "0ca2eadb529ac2e63abf9b4ae3df8ee121f10547";
        s.append_data(&hex::decode(h).unwrap());
        s.append_data(&hex::decode("0123456789abcdef").unwrap());
        s.append_slice(&[OP_SHA1, OP_EQUAL]);
        pass(&s.0);
        pass(&[OP_1, OP_SHA256]);
        pass(&[OP_0, OP_SHA256]);
        let mut s = Script::new();
        let h = "55c53f5d490297900cefa825d0c8e8e9532ee8a118abe7d8570762cd38be9818";
        s.append_data(&hex::decode(h).unwrap());
        s.append_data(&hex::decode("0123456789abcdef").unwrap());
        s.append_slice(&[OP_SHA256, OP_EQUAL]);
        pass(&s.0);
        pass(&[OP_1, OP_HASH160]);
        pass(&[OP_0, OP_HASH160]);
        let mut s = Script::new();
        let h = "a956ed79819901b1b2c7b3ec045081f749c588ed";
        s.append_data(&hex::decode(h).unwrap());
        s.append_data(&hex::decode("0123456789abcdef").unwrap());
        s.append_slice(&[OP_HASH160, OP_EQUAL]);
        pass(&s.0);
        pass(&[OP_1, OP_HASH256]);
        pass(&[OP_0, OP_HASH256]);
        let mut s = Script::new();
        let h = "137ad663f79da06e282ed0abbec4d70523ced5ff8e39d5c2e5641d978c5925aa";
        s.append_data(&hex::decode(h).unwrap());
        s.append_data(&hex::decode("0123456789abcdef").unwrap());
        s.append_slice(&[OP_HASH256, OP_EQUAL]);
        pass(&s.0);
        pass(&[OP_1, OP_1, OP_CHECKSIG]);
        pass(&[OP_1, OP_1, OP_CHECKSIGVERIFY, OP_1]);
        pass(&[OP_0, OP_0, OP_0, OP_CHECKMULTISIG]);
        pass(&[OP_0, OP_0, OP_9, OP_9, OP_9, OP_3, OP_CHECKMULTISIG]);
        pass(&[OP_0, OP_9, OP_1, OP_9, OP_1, OP_CHECKMULTISIG]);
        pass(&[OP_0, OP_9, OP_1, OP_9, OP_9, OP_9, OP_3, OP_CHECKMULTISIG]);
        let mut c = MockChecker::sig_checks(vec![true]);
        assert!(eval(
            &[OP_0, OP_9, OP_1, OP_9, OP_1, OP_CHECKMULTISIG],
            &mut c,
            NO_FLAGS
        )
        .is_ok());
        let mut c = MockChecker::sig_checks(vec![false, true, true]);
        let mut s = vec![OP_0, OP_9, OP_9, OP_2, OP_9, OP_9, OP_9, OP_3];
        s.push(OP_CHECKMULTISIG);
        assert!(eval(&s, &mut c, NO_FLAGS).is_ok());
        pass_pregenesis(&[OP_0, OP_CHECKLOCKTIMEVERIFY, OP_1]);
        pass(&[OP_CHECKLOCKTIMEVERIFY, OP_1]);
        pass_pregenesis(&[OP_0, OP_CHECKSEQUENCEVERIFY, OP_1]);
        pass(&[OP_CHECKSEQUENCEVERIFY, OP_1]);
        pass(&[OP_NOP1, OP_1]);
        pass(&[OP_NOP4, OP_1]);
        pass(&[OP_NOP5, OP_1]);
        pass(&[OP_NOP6, OP_1]);
        pass(&[OP_NOP7, OP_1]);
        pass(&[OP_NOP8, OP_1]);
        pass(&[OP_NOP9, OP_1]);
        pass(&[OP_NOP10, OP_1]);
        let mut v = vec![OP_DEPTH; 501];
        v.push(OP_1);
        pass(&v);
        pass(&vec![OP_1; 10001]);
    }

    #[test]
    fn invalid() {
        fail(&[]);
        fail(&[OP_FALSE]);
        fail(&[OP_PUSH + 1]);
        fail(&[OP_PUSH + 3, 0, 1]);
        fail(&[OP_PUSHDATA1, 0]);
        fail(&[OP_PUSHDATA1, 1]);
        fail(&[OP_PUSHDATA1, 10, 0]);
        fail(&[OP_PUSHDATA2, 20, 0]);
        fail(&[OP_PUSHDATA4, 30, 0]);
        fail(&[OP_IF, OP_ENDIF]);
        fail(&[OP_1, OP_1, OP_IF]);
        fail(&[OP_1, OP_1, OP_NOTIF]);
        fail(&[OP_1, OP_ELSE]);
        fail(&[OP_1, OP_ENDIF]);
        fail(&[OP_1, OP_1, OP_IF, OP_ELSE]);
        fail(&[OP_1, OP_1, OP_IF, OP_IF, OP_ENDIF]);
        fail(&[OP_0, OP_IF, OP_1, OP_ELSE, OP_0, OP_ENDIF]);
        fail(&[OP_0, OP_IF, OP_PUSHDATA1, 1, 1, OP_1, OP_ENDIF]);
        fail(&[OP_VERIFY]);
        fail(&[OP_0, OP_VERIFY]);
        fail(&[OP_RETURN]);
        fail(&[OP_FALSE, OP_RETURN]);
        fail_pregenesis(&[OP_RETURN]);
        fail_pregenesis(&[OP_1, OP_RETURN, OP_1]);
        fail(&[OP_TOALTSTACK]);
        fail(&[OP_FROMALTSTACK]);
        fail(&[OP_0, OP_TOALTSTACK, OP_1, OP_FROMALTSTACK]);
        fail(&[OP_IFDUP]);
        fail(&[OP_DROP]);
        fail(&[OP_1, OP_DROP, OP_DROP]);
        fail(&[OP_DUP]);
        fail(&[OP_NIP]);
        fail(&[OP_1, OP_NIP]);
        fail(&[OP_OVER]);
        fail(&[OP_1, OP_OVER]);
        fail(&[OP_PICK]);
        fail(&[OP_0, OP_PICK]);
        fail(&[OP_0, OP_1, OP_PICK]);
        fail(&[OP_ROLL]);
        fail(&[OP_0, OP_ROLL]);
        fail(&[OP_0, OP_1, OP_ROLL]);
        fail(&[OP_ROT]);
        fail(&[OP_1, OP_ROT]);
        fail(&[OP_1, OP_1, OP_ROT]);
        fail(&[OP_0, OP_1, OP_1, OP_ROT]);
        fail(&[OP_SWAP]);
        fail(&[OP_1, OP_SWAP]);
        fail(&[OP_0, OP_1, OP_SWAP]);
        fail(&[OP_TUCK]);
        fail(&[OP_1, OP_TUCK]);
        fail(&[OP_1, OP_0, OP_TUCK]);
        fail(&[OP_2DROP]);
        fail(&[OP_1, OP_2DROP]);
        fail(&[OP_1, OP_1, OP_2DROP]);
        fail(&[OP_2DUP]);
        fail(&[OP_1, OP_2DUP]);
        fail(&[OP_1, OP_0, OP_2DUP]);
        fail(&[OP_3DUP]);
        fail(&[OP_1, OP_3DUP]);
        fail(&[OP_1, OP_1, OP_3DUP]);
        fail(&[OP_1, OP_1, OP_0, OP_3DUP]);
        fail(&[OP_2OVER]);
        fail(&[OP_1, OP_2OVER]);
        fail(&[OP_1, OP_1, OP_2OVER]);
        fail(&[OP_1, OP_1, OP_1, OP_2OVER]);
        fail(&[OP_1, OP_0, OP_1, OP_1, OP_2OVER]);
        fail(&[OP_2ROT]);
        fail(&[OP_1, OP_2ROT]);
        fail(&[OP_1, OP_1, OP_2ROT]);
        fail(&[OP_1, OP_1, OP_1, OP_2ROT]);
        fail(&[OP_1, OP_1, OP_1, OP_1, OP_2ROT]);
        fail(&[OP_1, OP_1, OP_1, OP_1, OP_1, OP_2ROT]);
        fail(&[OP_1, OP_0, OP_1, OP_1, OP_1, OP_1, OP_2ROT]);
        fail(&[OP_2SWAP]);
        fail(&[OP_1, OP_2SWAP]);
        fail(&[OP_1, OP_1, OP_2SWAP]);
        fail(&[OP_1, OP_1, OP_1, OP_2SWAP]);
        fail(&[OP_1, OP_0, OP_1, OP_1, OP_2SWAP]);
        fail(&[OP_CAT]);
        fail(&[OP_1, OP_CAT]);
        fail(&[OP_1, OP_0, OP_0, OP_CAT]);
        fail(&[OP_SPLIT]);
        fail(&[OP_1, OP_SPLIT]);
        fail(&[OP_0, OP_1, OP_SPLIT]);
        fail(&[OP_1, OP_2, OP_SPLIT]);
        fail(&[OP_1, OP_1NEGATE, OP_SPLIT]);
        fail(&[OP_0, OP_SIZE]);
        fail(&[OP_AND]);
        fail(&[OP_0, OP_AND]);
        fail(&[OP_0, OP_1, OP_AND]);
        fail(&[OP_OR]);
        fail(&[OP_0, OP_OR]);
        fail(&[OP_0, OP_1, OP_OR]);
        fail(&[OP_XOR]);
        fail(&[OP_0, OP_XOR]);
        fail(&[OP_0, OP_1, OP_XOR]);
        fail(&[OP_LSHIFT]);
        fail(&[OP_1, OP_LSHIFT]);
        fail(&[OP_1, OP_1NEGATE, OP_LSHIFT]);
        fail(&[OP_RSHIFT]);
        fail(&[OP_1, OP_RSHIFT]);
        fail(&[OP_1, OP_1NEGATE, OP_RSHIFT]);
        fail(&[OP_INVERT]);
        fail(&[OP_EQUAL]);
        fail(&[OP_0, OP_EQUAL]);
        fail(&[OP_1, OP_0, OP_EQUAL]);
        fail(&[OP_1, OP_0, OP_EQUALVERIFY, OP_1]);
        fail(&[OP_1ADD]);
        fail(&[OP_1SUB]);
        fail(&[OP_NEGATE]);
        fail(&[OP_ABS]);
        fail(&[OP_NOT]);
        fail(&[OP_0NOTEQUAL]);
        fail(&[OP_ADD]);
        fail(&[OP_1, OP_ADD]);
        fail(&[OP_PUSH + 5, 0, 0, 0, 0, 0, OP_ADD]);
        fail(&[OP_SUB]);
        fail(&[OP_1, OP_SUB]);
        fail(&[OP_PUSH + 5, 0, 0, 0, 0, 0, OP_SUB]);
        fail(&[OP_MUL]);
        fail(&[OP_1, OP_MUL]);
        fail(&[OP_PUSH + 5, 0, 0, 0, 0, 0, OP_MUL]);
        fail(&[OP_PUSH + 2, 0, 0, OP_PUSH + 2, 0, 0, OP_MUL]);
        fail(&[OP_DIV]);
        fail(&[OP_1, OP_DIV]);
        fail(&[OP_PUSH + 5, 0, 0, 0, 0, 0, OP_DIV]);
        fail(&[OP_1, OP_0, OP_DIV]);
        fail(&[OP_MOD]);
        fail(&[OP_1, OP_MOD]);
        fail(&[OP_PUSH + 5, 0, 0, 0, 0, 0, OP_MOD]);
        fail(&[OP_1, OP_0, OP_MOD]);
        fail(&[OP_BOOLAND]);
        fail(&[OP_1, OP_BOOLAND]);
        fail(&[OP_PUSH + 5, 0, 0, 0, 0, 0, OP_BOOLAND]);
        fail(&[OP_BOOLOR]);
        fail(&[OP_1, OP_BOOLOR]);
        fail(&[OP_PUSH + 5, 0, 0, 0, 0, 0, OP_BOOLOR]);
        fail(&[OP_NUMEQUAL]);
        fail(&[OP_1, OP_NUMEQUAL]);
        fail(&[OP_PUSH + 5, 0, 0, 0, 0, 0, OP_NUMEQUAL]);
        fail(&[OP_0, OP_1, OP_NUMEQUAL]);
        fail(&[OP_NUMEQUALVERIFY]);
        fail(&[OP_1, OP_NUMEQUALVERIFY]);
        fail(&[OP_PUSH + 5, 0, 0, 0, 0, 0, OP_NUMEQUALVERIFY]);
        fail(&[OP_1, OP_2, OP_NUMEQUALVERIFY]);
        fail(&[OP_NUMNOTEQUAL]);
        fail(&[OP_1, OP_NUMNOTEQUAL]);
        fail(&[OP_PUSH + 5, 0, 0, 0, 0, 0, OP_NUMNOTEQUAL]);
        fail(&[OP_1, OP_1, OP_NUMNOTEQUAL]);
        fail(&[OP_LESSTHAN]);
        fail(&[OP_1, OP_LESSTHAN]);
        fail(&[OP_PUSH + 5, 0, 0, 0, 0, 0, OP_LESSTHAN]);
        fail(&[OP_1, OP_0, OP_LESSTHAN]);
        fail(&[OP_GREATERTHAN]);
        fail(&[OP_1, OP_GREATERTHAN]);
        fail(&[OP_PUSH + 5, 0, 0, 0, 0, 0, OP_GREATERTHAN]);
        fail(&[OP_0, OP_1, OP_GREATERTHAN]);
        fail(&[OP_LESSTHANOREQUAL]);
        fail(&[OP_1, OP_LESSTHANOREQUAL]);
        fail(&[OP_PUSH + 5, 0, 0, 0, 0, 0, OP_LESSTHANOREQUAL]);
        fail(&[OP_1, OP_0, OP_LESSTHANOREQUAL]);
        fail(&[OP_GREATERTHANOREQUAL]);
        fail(&[OP_1, OP_GREATERTHANOREQUAL]);
        fail(&[OP_PUSH + 5, 0, 0, 0, 0, 0, OP_GREATERTHANOREQUAL]);
        fail(&[OP_0, OP_1, OP_GREATERTHANOREQUAL]);
        fail(&[OP_MIN]);
        fail(&[OP_1, OP_MIN]);
        fail(&[OP_PUSH + 5, 0, 0, 0, 0, 0, OP_MIN]);
        fail(&[OP_MAX]);
        fail(&[OP_1, OP_MAX]);
        fail(&[OP_PUSH + 5, 0, 0, 0, 0, 0, OP_MAX]);
        fail(&[OP_WITHIN]);
        fail(&[OP_1, OP_WITHIN]);
        fail(&[OP_1, OP_1, OP_WITHIN]);
        fail(&[OP_PUSH + 5, 0, 0, 0, 0, 0, OP_WITHIN]);
        fail(&[OP_0, OP_1, OP_2, OP_WITHIN]);
        fail(&[OP_0, OP_1NEGATE, OP_0, OP_WITHIN]);
        fail(&[OP_BIN2NUM]);
        fail(&[OP_NUM2BIN]);
        fail(&[OP_1, OP_NUM2BIN]);
        fail(&[OP_1, OP_0, OP_NUM2BIN]);
        fail(&[OP_1, OP_1NEGATE, OP_NUM2BIN]);
        fail(&[OP_PUSH + 5, 129, 0, 0, 0, 0, OP_1, OP_NUM2BIN]);
        fail(&[OP_RIPEMD160]);
        fail(&[OP_SHA1]);
        fail(&[OP_SHA256]);
        fail(&[OP_HASH160]);
        fail(&[OP_HASH256]);
        fail(&[OP_CHECKSIG]);
        fail(&[OP_1, OP_CHECKSIG]);
        let mut c = MockChecker::sig_checks(vec![false; 1]);
        assert!(eval(&[OP_1, OP_1, OP_CHECKSIG], &mut c, NO_FLAGS).is_err());
        fail(&[OP_CHECKSIGVERIFY]);
        fail(&[OP_1, OP_CHECKSIGVERIFY]);
        let mut c = MockChecker::sig_checks(vec![false; 1]);
        assert!(eval(&[OP_1, OP_1, OP_CHECKSIGVERIFY, OP_1], &mut c, NO_FLAGS).is_err());
        fail(&[OP_CHECKMULTISIG]);
        fail(&[OP_1, OP_CHECKMULTISIG]);
        fail(&[OP_0, OP_0, OP_CHECKMULTISIG]);
        fail(&[OP_0, OP_0, OP_1NEGATE, OP_CHECKMULTISIG]);
        fail(&[OP_0, OP_1NEGATE, OP_0, OP_CHECKMULTISIG]);
        fail(&[OP_0, OP_0, OP_1, OP_CHECKMULTISIG]);
        fail(&[OP_0, OP_0, OP_PUSH + 1, 21, OP_CHECKMULTISIG]);
        fail(&[OP_0, OP_9, OP_9, OP_2, OP_9, OP_1, OP_CHECKMULTISIG]);
        let mut c = MockChecker::sig_checks(vec![false; 1]);
        assert!(eval(
            &[OP_0, OP_9, OP_1, OP_9, OP_1, OP_CHECKMULTISIG],
            &mut c,
            NO_FLAGS
        )
        .is_err());
        let mut c = MockChecker::sig_checks(vec![true, false]);
        let s = [OP_0, OP_9, OP_9, OP_2, OP_9, OP_9, OP_2, OP_CHECKMULTISIG];
        assert!(eval(&s, &mut c, NO_FLAGS).is_err());
        let mut c = MockChecker::sig_checks(vec![false, true, false]);
        let mut s = vec![OP_0, OP_9, OP_9, OP_2, OP_9, OP_9, OP_9, OP_3];
        s.push(OP_CHECKMULTISIG);
        assert!(eval(&s, &mut c, NO_FLAGS).is_err());
        fail_pregenesis(&[OP_CHECKLOCKTIMEVERIFY, OP_1]);
        fail_pregenesis(&[OP_PUSH + 5, 129, 0, 0, 0, 0, OP_CHECKLOCKTIMEVERIFY, OP_1]);
        let mut c = MockChecker::locktime_checks(vec![false]);
        assert!(eval(
            &vec![OP_0, OP_CHECKLOCKTIMEVERIFY, OP_1],
            &mut c,
            PREGENESIS_RULES
        )
        .is_err());
        fail_pregenesis(&[OP_CHECKSEQUENCEVERIFY, OP_1]);
        fail_pregenesis(&[OP_PUSH + 5, 129, 0, 0, 0, 0, OP_CHECKSEQUENCEVERIFY, OP_1]);
        let mut c = MockChecker::sequence_checks(vec![false]);
        assert!(eval(
            &vec![OP_0, OP_CHECKSEQUENCEVERIFY, OP_1],
            &mut c,
            PREGENESIS_RULES
        )
        .is_err());
        fail(&[OP_RESERVED, OP_1]);
        fail(&[OP_VER, OP_1]);
        fail(&[OP_VERIF, OP_1]);
        fail(&[OP_VERNOTIF, OP_1]);
        fail(&[OP_RESERVED1, OP_1]);
        fail(&[OP_RESERVED2, OP_1]);
        fail(&[OP_INVERT, OP_1]);
        fail(&[OP_2MUL, OP_1]);
        fail(&[OP_2DIV, OP_1]);
        fail(&[OP_MUL, OP_1]);
        fail(&[OP_LSHIFT, OP_1]);
        fail(&[OP_RSHIFT, OP_1]);
        fail(&[OP_INVALID_ABOVE, OP_1]);
        fail(&[OP_PUBKEYHASH, OP_1]);
        fail(&[OP_PUBKEY, OP_1]);
        fail(&[OP_INVALIDOPCODE, OP_1]);
    }

    #[test]
    fn next_op_tests() {
        let script = [];
        assert!(next_op(0, &script) == script.len());

        let script = [OP_0, OP_CHECKSIG, OP_ADD];
        assert!(next_op(0, &script) == 1);
        assert!(next_op(1, &script) == 2);
        assert!(next_op(2, &script) == script.len());

        let script = [OP_1, OP_PUSH + 4, 1, 2, 3, 4, OP_1];
        assert!(next_op(0, &script) == 1);
        assert!(next_op(1, &script) == 6);
        assert!(next_op(6, &script) == script.len());

        let script = [OP_1, OP_PUSHDATA1, 2, 3, 4, OP_1];
        assert!(next_op(0, &script) == 1);
        assert!(next_op(1, &script) == 5);
        assert!(next_op(5, &script) == script.len());

        let script = [OP_1, OP_PUSHDATA2, 2, 0, 3, 4, OP_1];
        assert!(next_op(0, &script) == 1);
        assert!(next_op(1, &script) == 6);
        assert!(next_op(6, &script) == script.len());

        let script = [OP_1, OP_PUSHDATA4, 2, 0, 0, 0, 3, 4, OP_1];
        assert!(next_op(0, &script) == 1);
        assert!(next_op(1, &script) == 8);
        assert!(next_op(8, &script) == script.len());

        // Parse failures

        let script = [OP_PUSH + 1];
        assert!(next_op(0, &script) == script.len());

        let script = [OP_PUSH + 3, 1, 2];
        assert!(next_op(0, &script) == script.len());

        let script = [OP_PUSHDATA1];
        assert!(next_op(0, &script) == script.len());

        let script = [OP_PUSHDATA1, 2, 1];
        assert!(next_op(0, &script) == script.len());

        let script = [OP_PUSHDATA2];
        assert!(next_op(0, &script) == script.len());

        let script = [OP_PUSHDATA2, 0];
        assert!(next_op(0, &script) == script.len());

        let script = [OP_PUSHDATA2, 2, 0, 1];
        assert!(next_op(0, &script) == script.len());

        let script = [OP_PUSHDATA4];
        assert!(next_op(0, &script) == script.len());

        let script = [OP_PUSHDATA4, 1, 2, 3];
        assert!(next_op(0, &script) == script.len());

        let script = [OP_PUSHDATA4, 2, 0, 0, 0, 1];
        assert!(next_op(0, &script) == script.len());
    }

    #[test]
    fn remove_sig_tests() {
        assert!(remove_sig(&[], &[]) == vec![]);
        assert!(remove_sig(&[], &[OP_0]) == vec![OP_0]);
        assert!(remove_sig(&[OP_0], &[OP_0]) == vec![]);
        let v = [OP_0, OP_1, OP_2, OP_3, OP_4, OP_0, OP_1, OP_2, OP_3, OP_4];
        assert!(remove_sig(&[OP_2, OP_3], &v) == vec![OP_0, OP_1, OP_4, OP_0, OP_1, OP_4]);
    }

    /// A test run that doesn't do signature checks and expects failure
    fn pass(script: &[u8]) {
        let mut c = MockChecker {
            sig_checks: RefCell::new(vec![true; 32]),
            locktime_checks: RefCell::new(vec![true; 32]),
            sequence_checks: RefCell::new(vec![true; 32]),
        };
        assert!(eval(script, &mut c, NO_FLAGS).is_ok());
    }

    /// A test run that doesn't do signature checks and expects failure
    fn fail(script: &[u8]) {
        let mut c = MockChecker {
            sig_checks: RefCell::new(vec![true; 32]),
            locktime_checks: RefCell::new(vec![true; 32]),
            sequence_checks: RefCell::new(vec![true; 32]),
        };
        assert!(eval(script, &mut c, NO_FLAGS).is_err());
    }

    /// Pre-genesis versions of the above checks
    fn pass_pregenesis(script: &[u8]) {
        let mut c = MockChecker {
            sig_checks: RefCell::new(vec![true; 32]),
            locktime_checks: RefCell::new(vec![true; 32]),
            sequence_checks: RefCell::new(vec![true; 32]),
        };
        assert!(eval(script, &mut c, PREGENESIS_RULES).is_ok());
    }

    /// A test run that doesn't do signature checks and expects failure
    fn fail_pregenesis(script: &[u8]) {
        let mut c = MockChecker {
            sig_checks: RefCell::new(vec![true; 32]),
            locktime_checks: RefCell::new(vec![true; 32]),
            sequence_checks: RefCell::new(vec![true; 32]),
        };
        assert!(eval(script, &mut c, PREGENESIS_RULES).is_err());
    }

    /// Mocks a transaction checker to always return a set of values
    struct MockChecker {
        sig_checks: RefCell<Vec<bool>>,
        locktime_checks: RefCell<Vec<bool>>,
        sequence_checks: RefCell<Vec<bool>>,
    }

    impl MockChecker {
        fn sig_checks(sig_checks: Vec<bool>) -> MockChecker {
            MockChecker {
                sig_checks: RefCell::new(sig_checks),
                locktime_checks: RefCell::new(vec![true; 32]),
                sequence_checks: RefCell::new(vec![true; 32]),
            }
        }

        fn locktime_checks(locktime_checks: Vec<bool>) -> MockChecker {
            MockChecker {
                sig_checks: RefCell::new(vec![true; 32]),
                locktime_checks: RefCell::new(locktime_checks),
                sequence_checks: RefCell::new(vec![true; 32]),
            }
        }

        fn sequence_checks(sequence_checks: Vec<bool>) -> MockChecker {
            MockChecker {
                sig_checks: RefCell::new(vec![true; 32]),
                locktime_checks: RefCell::new(vec![true; 32]),
                sequence_checks: RefCell::new(sequence_checks),
            }
        }
    }

    impl Checker for MockChecker {
        fn check_sig(&mut self, _sig: &[u8], _pubkey: &[u8], _script: &[u8]) -> Result<bool> {
            Ok(self.sig_checks.borrow_mut().pop().unwrap())
        }

        fn check_locktime(&self, _locktime: i32) -> Result<bool> {
            Ok(self.locktime_checks.borrow_mut().pop().unwrap())
        }

        fn check_sequence(&self, _sequence: i32) -> Result<bool> {
            Ok(self.sequence_checks.borrow_mut().pop().unwrap())
        }
    }
}

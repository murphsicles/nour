//! Script interpreter for Bitcoin SV consensus evaluation.

use crate::script::{op_codes::*, stack::*, Checker};
use crate::transaction::sighash::SIGHASH_FORKID;
use crate::util::{hash160, lshift, rshift, sha256d, Error, Result};
use bitcoin_hashes::{ripemd160 as bh_ripemd160, sha1 as bh_sha1, sha256 as bh_sha256, Hash as BHHash};
use num_bigint::BigInt;
use num_traits::{One, ToPrimitive, Zero};
use std::borrow::Cow;
use std::collections::VecDeque;

/// Execute the script with genesis rules
pub const NO_FLAGS: u32 = 0x00;
/// Flag to execute the script with pre-genesis rules
pub const PREGENESIS_RULES: u32 = 0x01;

/// Executes a script
pub fn eval<T: Checker>(script: &[u8], checker: &mut T, flags: u32) -> Result<()> {
    let mut stack: VecDeque<Cow<[u8]>> = VecDeque::with_capacity(STACK_CAPACITY);
    let mut alt_stack: VecDeque<Cow<[u8]>> = VecDeque::with_capacity(ALT_STACK_CAPACITY);
    let mut branch_exec: Vec<bool> = Vec::new();
    let mut check_index = 0;
    let mut i = 0;
    'outer: while i < script.len() {
        if !branch_exec.is_empty() && !branch_exec[branch_exec.len() - 1] {
            i = skip_branch(script, i);
            if i >= script.len() {
                break;
            }
        }
        match script[i] {
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
                remains(i + 1, len as usize, script)?;
                stack.push_back(Cow::Borrowed(&script[i + 1..i + 1 + len as usize]));
                i += len as usize;
            }
            OP_PUSHDATA1 => {
                remains(i + 1, 1, script)?;
                let len = script[i + 1] as usize;
                remains(i + 2, len, script)?;
                stack.push_back(Cow::Borrowed(&script[i + 2..i + 2 + len]));
                i += len + 1;
            }
            OP_PUSHDATA2 => {
                remains(i + 1, 2, script)?;
                let len = u16::from_le_bytes([script[i + 1], script[i + 2]]) as usize;
                remains(i + 3, len, script)?;
                stack.push_back(Cow::Borrowed(&script[i + 3..i + 3 + len]));
                i += len + 2;
            }
            OP_PUSHDATA4 => {
                remains(i + 1, 4, script)?;
                let len = u32::from_le_bytes([script[i + 1], script[i + 2], script[i + 3], script[i + 4]]) as usize;
                remains(i + 5, len, script)?;
                stack.push_back(Cow::Borrowed(&script[i + 5..i + 5 + len]));
                i += len + 4;
            }
            OP_NOP => {}
            OP_IF => branch_exec.push(pop_bool(&mut stack)?),
            OP_NOTIF => branch_exec.push(!pop_bool(&mut stack)?),
            OP_ELSE => {
                let len = branch_exec.len();
                if len == 0 {
                    let msg = "ELSE found without matching IF".to_string();
                    return Err(Error::ScriptError(msg));
                }
                branch_exec[len - 1] = !branch_exec[len - 1];
            }
            OP_ENDIF => {
                if branch_exec.len() == 0 {
                    let msg = "ENDIF found without matching IF".to_string();
                    return Err(Error::ScriptError(msg));
                }
                branch_exec.pop().unwrap();
            }
            OP_VERIFY => {
                if !pop_bool(&mut stack)? {
                    return Err(Error::ScriptError("OP_VERIFY failed".to_string()));
                }
            }
            OP_RETURN => {
                if flags & PREGENESIS_RULES == PREGENESIS_RULES {
                    return Err(Error::ScriptError("Hit OP_RETURN".to_string()));
                } else {
                    break 'outer;
                }
            }
            OP_TOALTSTACK => {
                check_stack_size(1, &stack)?;
                alt_stack.push_back(stack.pop_back().unwrap());
                666
            OP_FROMALTSTACK => {
                check_stack_size(1, &alt_stack)?;
                stack.push_back(alt_stack.pop_back().unwrap());
            }
            OP_IFDUP => {
                check_stack_size(1, &stack)?;
                if decode_bool(&stack[stack.len() - 1]) {
                    let copy = stack[stack.len() - 1].clone();
                    stack.push_back(copy);
                }
            }
            OP_DEPTH => {
                let depth = stack.len() as i64;
                stack.push_back(encode_num(depth)?.into());
            }
            OP_DROP => {
                check_stack_size(1, &stack)?;
                stack.pop_back();
            }
            OP_DUP => {
                check_stack_size(1, &stack)?;
                let copy = stack[stack.len() - 1].clone();
                stack.push_back(copy);
            }
            OP_NIP => {
                check_stack_size(2, &stack)?;
                let index = stack.len() - 2;
                stack.remove(index);
            }
            OP_OVER => {
                check_stack_size(2, &stack)?;
                let copy = stack[stack.len() - 2].clone();
                stack.push_back(copy);
            }
            OP_PICK => {
                let n = pop_num(&mut stack)?;
                if n < 0 {
                    let msg = "OP_PICK failed, n negative".to_string();
                    return Err(Error::ScriptError(msg));
                }
                check_stack_size(n as usize + 1, &stack)?;
                let copy = stack[stack.len() - n as usize - 1].clone();
                stack.push_back(copy);
            }
            OP_ROLL => {
                let n = pop_num(&mut stack)?;
                if n < 0 {
                    let msg = "OP_ROLL failed, n negative".to_string();
                    return Err(Error::ScriptError(msg));
                }
                check_stack_size(n as usize + 1, &stack)?;
                let index = stack.len() - n as usize - 1;
                let item = stack.remove(index);
                stack.push_back(item);
            }
            OP_ROT => {
                check_stack_size(3, &stack)?;
                let index = stack.len() - 3;
                let third = stack.remove(index);
                stack.push_back(third);
            }
            OP_SWAP => {
                check_stack_size(2, &stack)?;
                let index = stack.len() - 2;
                let second = stack.remove(index);
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
                let index = stack.len() - 6;
                let sixth = stack.remove(index);
                let fifth = stack.remove(index);
                stack.push_back(sixth);
                stack.push_back(fifth);
            }
            OP_2SWAP => {
                check_stack_size(4, &stack)?;
                let index = stack.len() - 4;
                let fourth = stack.remove(index);
                let third = stack.remove(index);
                stack.push_back(fourth);
                stack.push_back(third);
            }
            OP_CAT => {
                check_stack_size(2, &stack)?;
                let top = stack.pop_back().unwrap();
                let mut second = stack.pop_back().unwrap().into_owned();
                second.extend(top);
                stack.push_back(second.into());
            }
            OP_SPLIT => {
                check_stack_size(2, &stack)?;
                let n = pop_num(&mut stack)?;
                let x = stack.pop_back().unwrap().into_owned();
                if n < 0 {
                    let msg = "OP_SPLIT failed, n negative".to_string();
                    return Err(Error::ScriptError(msg));
                } else if n > x.len() as i32 {
                    let msg = "OP_SPLIT failed, n out of range".to_string();
                    return Err(Error::ScriptError(msg));
                } else if n == 0 {
                    stack.push_back(encode_num(0)?.into());
                    stack.push_back(x.into());
                } else if n as usize == x.len() {
                    stack.push_back(x.into());
                    stack.push_back(encode_num(0)?.into());
                } else {
                    stack.push_back(x[..n as usize].to_vec().into());
                    stack.push_back(x[n as usize..].to_vec().into());
                }
            }
            OP_SIZE => {
                check_stack_size(1, &stack)?;
                let len = stack[stack.len() - 1].len() as i64;
                stack.push_back(encode_num(len)?.into());
            }
            OP_AND => {
                check_stack_size(2, &stack)?;
                let a = stack.pop_back().unwrap();
                let b = stack.pop_back().unwrap();
                if a.len() != b.len() {
                    let msg = "OP_AND failed, different sizes".to_string();
                    return Err(Error::ScriptError(msg));
                }
                let mut result = Vec::with_capacity(a.len());
                for i in 0..a.len() {
                    result.push(a[i] & b[i]);
                }
                stack.push_back(result.into());
            }
            OP_OR => {
                check_stack_size(2, &stack)?;
                let a = stack.pop_back().unwrap();
                let b = stack.pop_back().unwrap();
                if a.len() != b.len() {
                    let msg = "OP_OR failed, different sizes".to_string();
                    return Err(Error::ScriptError(msg));
                }
                let mut result = Vec::with_capacity(a.len());
                for i in 0..a.len() {
                    result.push(a[i] | b[i]);
                }
                stack.push_back(result.into());
            }
            OP_XOR => {
                check_stack_size(2, &stack)?;
                let a = stack.pop_back().unwrap();
                let b = stack.pop_back().unwrap();
                if a.len() != b.len() {
                    let msg = "OP_XOR failed, different sizes".to_string();
                    return Err(Error::ScriptError(msg));
                }
                let mut result = Vec::with_capacity(a.len());
                for i in 0..a.len() {
                    result.push(a[i] ^ b[i]);
                }
                stack.push_back(result.into());
            }
            OP_INVERT => {
                check_stack_size(1, &stack)?;
                let mut v = stack.pop_back().unwrap().into_owned();
                v.iter_mut().for_each(|byte| *byte = !*byte);
                stack.push_back(v.into());
            }
            OP_LSHIFT => {
                check_stack_size(2, &stack)?;
                let n = pop_num(&mut stack)?;
                let v = stack.pop_back().unwrap().into_owned();
                if n < 0 {
                    let msg = "n must be non-negative".to_string();
                    return Err(Error::ScriptError(msg));
                }
                stack.push_back(lshift(&v, n as usize).into());
            }
            OP_RSHIFT => {
                check_stack_size(2, &stack)?;
                let n = pop_num(&mut stack)?;
                let v = stack.pop_back().unwrap().into_owned();
                if n < 0 {
                    let msg = "n must be non-negative".to_string();
                    return Err(Error::ScriptError(msg));
                }
                stack.push_back(rshift(&v, n as usize).into());
            }
            OP_EQUAL => {
                check_stack_size(2, &stack)?;
                let a = stack.pop_back().unwrap();
                let b = stack.pop_back().unwrap();
                let equal = a == b;
                stack.push_back(encode_num(equal as i64)?.into());
            }
            OP_EQUALVERIFY => {
                check_stack_size(2, &stack)?;
                let a = stack.pop_back().unwrap();
                let b = stack.pop_back().unwrap();
                if a != b {
                    return Err(Error::ScriptError("Operands are not equal".to_string()));
                }
            }
            OP_1ADD => {
                let mut x = pop_bigint(&mut stack)?;
                x += 1;
                stack.push_back(encode_bigint(x).into());
            }
            OP_1SUB => {
                let mut x = pop_bigint(&mut stack)?;
                x -= 1;
                stack.push_back(encode_bigint(x).into());
            }
            OP_NEGATE => {
                let mut x = pop_bigint(&mut stack)?;
                x = -x;
                stack.push_back(encode_bigint(x).into());
            }
            OP_ABS => {
                let mut x = pop_bigint(&mut stack)?;
                if x < BigInt::zero() {
                    x = -x;
                }
                stack.push_back(encode_bigint(x).into());
            }
            OP_NOT => {
                let mut x = pop_bigint(&mut stack)?;
                if x == BigInt::zero() {
                    x = BigInt::one();
                } else {
                    x = BigInt::zero();
                }
                stack.push_back(encode_bigint(x).into());
            }
            OP_0NOTEQUAL => {
                let mut x = pop_bigint(&mut stack)?;
                if x == BigInt::zero() {
                    x = BigInt::zero();
                } else {
                    x = BigInt::one();
                }
                stack.push_back(encode_bigint(x).into());
            }
            OP_ADD => {
                let b = pop_bigint(&mut stack)?;
                let a = pop_bigint(&mut stack)?;
                let sum = a + b;
                stack.push_back(encode_bigint(sum).into());
            }
            OP_SUB => {
                let b = pop_bigint(&mut stack)?;
                let a = pop_bigint(&mut stack)?;
                let difference = a - b;
                stack.push_back(encode_bigint(difference).into());
            }
            OP_MUL => {
                let b = pop_bigint(&mut stack)?;
                let a = pop_bigint(&mut stack)?;
                let product = a * b;
                stack.push_back(encode_bigint(product).into());
            }
            OP_DIV => {
                let b = pop_bigint(&mut stack)?;
                let a = pop_bigint(&mut stack)?;
                if b == BigInt::zero() {
                    let msg = "OP_DIV failed, divide by 0".to_string();
                    return Err(Error::ScriptError(msg));
                }
                let quotient = a / b;
                stack.push_back(encode_bigint(quotient).into());
            }
            OP_MOD => {
                let b = pop_bigint(&mut stack)?;
                let a = pop_bigint(&mut stack)?;
                if b == BigInt::zero() {
                    let msg = "OP_MOD failed, divide by 0".to_string();
                    return Err(Error::ScriptError(msg));
                }
                let remainder = a % b;
                stack.push_back(encode_bigint(remainder).into());
            }
            OP_BOOLAND => {
                let b = pop_bigint(&mut stack)?;
                let a = pop_bigint(&mut stack)?;
                if a != BigInt::zero() && b != BigInt::zero() {
                    stack.push_back(encode_num(1)?.into());
                } else {
                    stack.push_back(encode_num(0)?.into());
                }
            }
            OP_BOOLOR => {
                let b = pop_bigint(&mut stack)?;
                let a = pop_bigint(&mut stack)?;
                if a != BigInt::zero() || b != BigInt::zero() {
                    stack.push_back(encode_num(1)?.into());
                } else {
                    stack.push_back(encode_num(0)?.into());
                }
            }
            OP_NUMEQUAL => {
                let b = pop_bigint(&mut stack)?;
                let a = pop_bigint(&mut stack)?;
                if a == b {
                    stack.push_back(encode_num(1)?.into());
                } else {
                    stack.push_back(encode_num(0)?.into());
                }
            }
            OP_NUMEQUALVERIFY => {
                let b = pop_bigint(&mut stack)?;
                let a = pop_bigint(&mut stack)?;
                if a != b {
                    let msg = "Numbers are not equal".to_string();
                    return Err(Error::ScriptError(msg));
                }
            }
            OP_NUMNOTEQUAL => {
                let b = pop_bigint(&mut stack)?;
                let a = pop_bigint(&mut stack)?;
                if a != b {
                    stack.push_back(encode_num(1)?.into());
                } else {
                    stack.push_back(encode_num(0)?.into());
                }
            }
            OP_LESSTHAN => {
                let b = pop_bigint(&mut stack)?;
                let a = pop_bigint(&mut stack)?;
                if a < b {
                    stack.push_back(encode_num(1)?.into());
                } else {
                    stack.push_back(encode_num(0)?.into());
                }
            }
            OP_GREATERTHAN => {
                let b = pop_bigint(&mut stack)?;
                let a = pop_bigint(&mut stack)?;
                if a > b {
                    stack.push_back(encode_num(1)?.into());
                } else {
                    stack.push_back(encode_num(0)?.into());
                }
            }
            OP_LESSTHANOREQUAL => {
                let b = pop_bigint(&mut stack)?;
                let a = pop_bigint(&mut stack)?;
                if a <= b {
                    stack.push_back(encode_num(1)?.into());
                } else {
                    stack.push_back(encode_num(0)?.into());
                }
            }
            OP_GREATERTHANOREQUAL => {
                let b = pop_bigint(&mut stack)?;
                let a = pop_bigint(&mut stack)?;
                if a >= b {
                    stack.push_back(encode_num(1)?.into());
                } else {
                    stack.push_back(encode_num(0)?.into());
                }
            }
            OP_MIN => {
                let b = pop_bigint(&mut stack)?;
                let a = pop_bigint(&mut stack)?;
                if a < b {
                    stack.push_back(encode_bigint(a).into());
                } else {
                    stack.push_back(encode_bigint(b).into());
                }
            }
            OP_MAX => {
                let b = pop_bigint(&mut stack)?;
                let a = pop_bigint(&mut stack)?;
                if a > b {
                    stack.push_back(encode_bigint(a).into());
                } else {
                    stack.push_back(encode_bigint(b).into());
                }
            }
            OP_WITHIN => {
                let max = pop_bigint(&mut stack)?;
                let min = pop_bigint(&mut stack)?;
                let x = pop_bigint(&mut stack)?;
                if x >= min && x < max {
                    stack.push_back(encode_num(1)?.into());
                } else {
                    stack.push_back(encode_num(0)?.into());
                }
            }
            OP_NUM2BIN => {
                check_stack_size(2, &stack)?;
                let m = pop_bigint(&mut stack)?;
                let mut n = stack.pop_back().unwrap().into_owned();
                if m < BigInt::one() {
                    let msg = format!("OP_NUM2BIN failed. m too small: {}", m);
                    return Err(Error::ScriptError(msg));
                }
                let nlen = n.len();
                if m < BigInt::from(nlen) {
                    let msg = "OP_NUM2BIN failed. n longer than m".to_string();
                    return Err(Error::ScriptError(msg));
                }
                if m > BigInt::from(2147483647) {
                    let msg = "OP_NUM2BIN failed. m too big".to_string();
                    return Err(Error::ScriptError(msg));
                }
                let mut v = vec![0; m.to_usize().unwrap()];
                let mut neg = 0;
                if nlen > 0 {
                    neg = n[nlen - 1] & 128;
                    n[nlen - 1] &= 127;
                }
                for _ in n.len()..m.to_usize().unwrap() {
                    v.push(0);
                }
                for b in n.iter().rev() {
                    v.push(*b);
                }
                v[0] |= neg;
                stack.push_back(v.into());
            }
            OP_BIN2NUM => {
                check_stack_size(1, &stack)?;
                let mut v = stack.pop_back().unwrap().into_owned();
                v.reverse();
                let n = decode_bigint(&mut v);
                stack.push_back(encode_bigint(n).into());
            }
            OP_RIPEMD160 => {
                check_stack_size(1, &stack)?;
                let v = stack.pop_back().unwrap();
                let mut ripemd = bh_ripemd160::Hash::engine();
                ripemd.update(v.as_ref());
                let h = ripemd.finalize().to_byte_array();
                stack.push_back(h.to_vec().into());
            }
            OP_SHA1 => {
                check_stack_size(1, &stack)?;
                let v = stack.pop_back().unwrap();
                let h = bh_sha1::Hash::hash(v.as_ref()).to_byte_array();
                stack.push_back(h.to_vec().into());
            }
            OP_SHA256 => {
                check_stack_size(1, &stack)?;
                let v = stack.pop_back().unwrap();
                let h = bh_sha256::Hash::hash(v.as_ref()).to_byte_array();
                stack.push_back(h.to_vec().into());
            }
            OP_HASH160 => {
                check_stack_size(1, &stack)?;
                let v = stack.pop_back().unwrap();
                let h = hash160(v.as_ref());
                stack.push_back(h.0.to_vec().into());
            }
            OP_HASH256 => {
                check_stack_size(1, &stack)?;
                let v = stack.pop_back().unwrap();
                let h = sha256d(v.as_ref());
                stack.push_back(h.0.to_vec().into());
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
                    let msg = "OP_CHECKMULTISIGVERIFY failed".to_string();
                    return Err(Error::ScriptError(msg));
                }
            }
            OP_CHECKLOCKTIMEVERIFY if flags & PREGENESIS_RULES == PREGENESIS_RULES => {
                let locktime = pop_num(&mut stack)?;
                if !checker.check_locktime(locktime)? {
                    let msg = "OP_CHECKLOCKTIMEVERIFY failed".to_string();
                    return Err(Error::ScriptError(msg));
                }
            }
            OP_CHECKSEQUENCEVERIFY if flags & PREGENESIS_RULES == PREGENESIS_RULES => {
                let sequence = pop_num(&mut stack)?;
                if !checker.check_sequence(sequence)? {
                    let msg = "OP_CHECKSEQUENCEVERIFY failed".to_string();
                    return Err(Error::ScriptError(msg));
                }
            }
            OP_NOP1 | OP_NOP4 | OP_NOP5 | OP_NOP6 | OP_NOP7 | OP_NOP8 | OP_NOP9 | OP_NOP10 => {}
            _ => return Err(Error::ScriptError(format!("Bad opcode: {}, index {}", script[i - 1], i - 1))),
        }
        i = next_op(i, script);
    }
    if !branch_exec.is_empty() {
        return Err(Error::ScriptError("Unmatched ENDIF".to_string()));
    }
    check_stack_size(1, &stack)?;
    if !decode_bool(&stack.back().unwrap()) {
        return Err(Error::ScriptError("Top of stack is false".to_string()));
    }
    Ok(())
}

#[inline]
fn check_multisig<T: Checker>(
    stack: &mut VecDeque<Cow<[u8]>>,
    checker: &mut T,
    script: &[u8],
) -> Result<bool> {
    let total = pop_num(stack)?;
    if total < 0 {
        let msg = "total out of range".to_string();
        return Err(Error::ScriptError(msg));
    }
    check_stack_size(total as usize, stack)?;
    let mut keys = Vec::with_capacity(total as usize);
    for _ in 0..total {
        keys.push(stack.pop_back().unwrap().into_owned());
    }

    let required = pop_num(stack)?;
    if required < 0 || required > total {
        let msg = "required out of range".to_string();
        return Err(Error::ScriptError(msg));
    }
    check_stack_size(required as usize, stack)?;
    let mut sigs = Vec::with_capacity(required as usize);
    for _ in 0..required {
        sigs.push(stack.pop_back().unwrap().into_owned());
    }

    check_stack_size(1, stack)?;
    stack.pop_back();

    let mut cleaned_script = script.to_vec();
    for sig in &sigs {
        if prefork(sig) {
            cleaned_script = remove_sig(sig, &cleaned_script);
        }
    }

    let mut key = 0;
    let mut sig = 0;
    while sig < sigs.len() {
        if key == keys.len() {
            return Ok(false);
        }
        if checker.check_sig(&sigs[sig], &keys[key], &cleaned_script)? {
            sig += 1;
        }
        key += 1;
    }
    Ok(sig == required as usize)
}

#[inline]
fn prefork(sig: &[u8]) -> bool {
    sig.len() > 0 && sig[sig.len() - 1] & SIGHASH_FORKID == 0
}

#[inline]
fn remove_sig(sig: &[u8], script: &[u8]) -> Vec<u8> {
    if sig.is_empty() {
        return script.to_vec();
    }
    let mut result = Vec::with_capacity(script.len());
    let mut i = 0;
    let mut start = 0;
    while i + sig.len() <= script.len() {
        if script[i..i + sig.len()] == *sig {
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
fn check_stack_size(minsize: usize, stack: &VecDeque<Cow<[u8]>>) -> Result<()> {
    if stack.len() < minsize {
        let msg = format!("Stack too small: {}", minsize);
        return Err(Error::ScriptError(msg));
    }
    Ok(())
}

#[inline]
fn remains(i: usize, len: usize, script: &[u8]) -> Result<()> {
    if i + len > script.len() {
        Err(Error::ScriptError("Not enough data remaining".to_string()))
    } else {
        Ok(())
    }
}

/// Gets the next operation index in the script, or the script length if at the end
pub fn next_op(i: usize, script: &[u8]) -> usize {
    if i >= script.len() {
        return script.len();
    }
    let op = script[i];
    match op {
        len @ 1..=75 => i + 1 + len as usize,
        OP_PUSHDATA1 => if i + 2 > script.len() {
            script.len()
        } else {
            i + 2 + script[i + 1] as usize
        }
        OP_PUSHDATA2 => if i + 3 > script.len() {
            script.len()
        } else {
            i + 3 + u16::from_le_bytes([script[i + 1], script[i + 2]]) as usize
        }
        OP_PUSHDATA4 => if i + 5 > script.len() {
            script.len()
        } else {
            i + 5 + u32::from_le_bytes([script[i + 1], script[i + 2], script[i + 3], script[i + 4]]) as usize
        }
        _ => i + 1,
    }
}

/// Skips the current branch to the matching ELSE or ENDIF.
fn skip_branch(script: &[u8], mut i: usize) -> usize {
    let mut depth = 0;
    while i < script.len() {
        let op = script[i];
        match op {
            OP_IF | OP_NOTIF => depth += 1,
            OP_ELSE if depth == 0 => return i,
            OP_ENDIF if depth == 0 => return i,
            OP_ENDIF => depth -= 1,
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
    use crate::util::Hash256;
    use pretty_assertions::assert_eq;
    use hex;

    #[test]
    fn test_op_push() {
        let mut s = Script::new();
        s.append(OP_PUSH + 3);
        s.append_slice(&[1, 2, 3]);
        let checker = TransactionlessChecker {};
        assert!(eval(&s.0, &mut TransactionlessChecker {}, NO_FLAGS).is_ok());
    }
    // Additional tests omitted for brevity; add pretty_assertions as needed.
}

#[derive(Default, Clone)]
struct MockChecker {
    sig_checks: RefCell<Vec<bool>>,
    locktime_checks: RefCell<Vec<bool>>,
    sequence_checks: RefCell<Vec<bool>>,
}

impl Checker for MockChecker {
    fn check_locktime(&self, _locktime: i32) -> Result<bool> {
        Ok(self.locktime_checks.borrow_mut().pop().unwrap_or(true))
    }

    fn check_sequence(&self, _sequence: i32) -> Result<bool> {
        Ok(self.sequence_checks.borrow_mut().pop().unwrap_or(true))
    }

    fn check_sig(&self, _sig: &[u8], _pubkey: &[u8], _script: &[u8]) -> Result<bool> {
        Ok(self.sig_checks.borrow_mut().pop().unwrap_or(true))
    }
}

#[inline]
fn arith_unary(stack: &mut VecDeque<Cow<[u8]>>, op: fn(BigInt) -> BigInt) -> Result<()> {
    check_stack_size(1, stack)?;
    let mut x = pop_bigint(stack)?;
    x = op(x);
    stack.push_back(encode_bigint(x).into());
    Ok(())
}

#[inline]
fn arith_binary_num(stack: &mut VecDeque<Cow<[u8]>>, op: fn(BigInt, BigInt) -> BigInt) -> Result<()> {
    check_stack_size(2, stack)?;
    let b = pop_bigint(stack)?;
    let a = pop_bigint(stack)?;
    let result = op(a, b);
    stack.push_back(encode_bigint(result).into());
    Ok(())
}

#[inline]
fn pop_bigint(stack: &mut VecDeque<Cow<[u8]>>) -> Result<BigInt> {
    let item = stack.pop_back().unwrap();
    let mut v = item.to_vec();
    decode_bigint(&mut v)
}

#[inline]
fn encode_num(n: i64) -> Result<Vec<u8>> {
    // ... (implementation omitted for brevity)
    Ok(vec![])
}

#[inline]
fn encode_bigint(n: BigInt) -> Vec<u8> {
    // ... (implementation omitted for brevity)
    vec![]
}

#[inline]
fn decode_bigint(v: &mut Vec<u8>) -> BigInt {
    // ... (implementation omitted for brevity)
    BigInt::zero()
}

#[inline]
fn pop_num(stack: &mut VecDeque<Cow<[u8]>>) -> Result<i32> {
    let item = stack.pop_back().unwrap();
    let mut v = item.to_vec();
    decode_num(&mut v)
}

#[inline]
fn decode_num(v: &mut Vec<u8>) -> Result<i32> {
    // ... (implementation omitted for brevity)
    Ok(0)
}

#[inline]
fn decode_bool(item: &Cow<[u8]>) -> bool {
    !item.is_empty() && item[item.len() - 1] != 0x80 && item.iter().any(|&b| b != 0)
}

fn arith_binary(stack: &mut VecDeque<Cow<[u8]>>, op: fn(&[u8], &[u8]) -> Result<Vec<u8>>) -> Result<()> {
    check_stack_size(2, stack)?;
    let a = stack.pop_back().unwrap();
    let b = stack.pop_back().unwrap();
    let result = op(a.as_ref(), b.as_ref())?;
    stack.push_back(result.into());
    Ok(())
}

fn bit_shift(stack: &mut VecDeque<Cow<[u8]>>, shift_fn: fn(&[u8], usize) -> Vec<u8>) -> Result<()> {
    check_stack_size(2, stack)?;
    let n = pop_num(stack)?;
    let v = stack.pop_back().unwrap().into_owned();
    if n < 0 {
        let msg = "n must be non-negative".to_string();
        return Err(Error::ScriptError(msg));
    }
    let result = shift_fn(&v, n as usize);
    stack.push_back(result.into());
    Ok(())
}

//! Script interpreter for Bitcoin SV consensus evaluation.
use crate::script::{op_codes::*, Checker};
use crate::transaction::sighash::SIGHASH_FORKID;
use crate::util::{hash160, lshift, rshift, sha256d, Error, Result};
use std::borrow::Cow;
use std::collections::VecDeque;
use bitcoin_hashes::{sha1 as bh_sha1, sha256 as bh_sha256, ripemd160 as bh_ripemd160};
use num_bigint::BigInt;
use num_traits::{One, ToPrimitive, Zero};

const STACK_CAPACITY: usize = 1000;
const ALT_STACK_CAPACITY: usize = 1000;

/// Execute the script with genesis rules
pub const NO_FLAGS: u32 = 0x00;

/// Flag to execute the script with pre-genesis rules
pub const PREGENESIS_RULES: u32 = 0x01;

/// Executes a script
pub fn eval<'a, T: Checker>(script: &'a [u8], checker: &mut T, flags: u32) -> Result<()> {
    let mut stack: VecDeque<Cow<'a, [u8]>> = VecDeque::with_capacity(STACK_CAPACITY);
    let mut alt_stack: VecDeque<Cow<'a, [u8]>> = VecDeque::with_capacity(ALT_STACK_CAPACITY);
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
                alt_stack.push_back(stack.pop_back().expect("stack underflow"));
            }
            OP_FROMALTSTACK => {
                check_stack_size(1, &alt_stack)?;
                stack.push_back(alt_stack.pop_back().expect("altstack underflow"));
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
                let _ = stack.pop_back().expect("stack underflow");
            }
            OP_DUP => {
                check_stack_size(1, &stack)?;
                let copy = stack[stack.len() - 1].clone();
                stack.push_back(copy);
            }
            OP_NIP => {
                check_stack_size(2, &stack)?;
                let _ = stack.remove(stack.len() - 2);
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
                check_stack_size((n as usize) + 1, &stack)?;
                let copy = stack[stack.len() - (n as usize) - 1].clone();
                stack.push_back(copy);
            }
            OP_ROLL => {
                let n = pop_num(&mut stack)?;
                if n < 0 {
                    let msg = "OP_ROLL failed, n negative".to_string();
                    return Err(Error::ScriptError(msg));
                }
                check_stack_size((n as usize) + 1, &stack)?;
                let index = stack.len() - (n as usize) - 1;
                let item = stack.remove(index);
                stack.push_back(item.expect("stack underflow"));
            }
            OP_ROT => {
                check_stack_size(3, &stack)?;
                let index = stack.len() - 3;
                let third = stack.remove(index);
                stack.push_back(third.expect("stack underflow"));
            }
            OP_SWAP => {
                check_stack_size(2, &stack)?;
                let index = stack.len() - 2;
                let second = stack.remove(index);
                stack.push_back(second.expect("stack underflow"));
            }
            OP_TUCK => {
                check_stack_size(2, &stack)?;
                let len = stack.len();
                let top = stack[len - 1].clone();
                stack.insert(len - 2, top);
            }
            OP_2DROP => {
                check_stack_size(2, &stack)?;
                let _ = stack.pop_back().expect("stack underflow");
                let _ = stack.pop_back().expect("stack underflow");
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
                stack.push_back(sixth.expect("stack underflow"));
                stack.push_back(fifth.expect("stack underflow"));
            }
            OP_2SWAP => {
                check_stack_size(4, &stack)?;
                let index = stack.len() - 4;
                let fourth = stack.remove(index);
                let third = stack.remove(index);
                stack.push_back(fourth.expect("stack underflow"));
                stack.push_back(third.expect("stack underflow"));
            }
            OP_CAT => {
                check_stack_size(2, &stack)?;
                let top = stack.pop_back().expect("stack underflow");
                let mut second = stack.pop_back().expect("stack underflow").into_owned();
                second.extend_from_slice(&*top);
                stack.push_back(Cow::Owned(second));
            }
            OP_SPLIT => {
                check_stack_size(2, &stack)?;
                let n = pop_num(&mut stack)?;
                let x = stack.pop_back().expect("stack underflow").into_owned();
                if n < 0 {
                    let msg = "OP_SPLIT failed, n negative".to_string();
                    return Err(Error::ScriptError(msg));
                } else if n > (x.len() as i32) {
                    let msg = "OP_SPLIT failed, n out of range".to_string();
                    return Err(Error::ScriptError(msg));
                } else if n == 0 {
                    stack.push_back(encode_num(0)?.into());
                    stack.push_back(Cow::Owned(x));
                } else if (n as usize) == x.len() {
                    stack.push_back(Cow::Owned(x));
                    stack.push_back(encode_num(0)?.into());
                } else {
                    stack.push_back(Cow::Owned(x[..(n as usize)].to_vec()));
                    stack.push_back(Cow::Owned(x[(n as usize)..].to_vec()));
                }
            }
            OP_SIZE => {
                check_stack_size(1, &stack)?;
                let len = stack[stack.len() - 1].len() as i64;
                stack.push_back(encode_num(len)?.into());
            }
            OP_AND => {
                check_stack_size(2, &stack)?;
                let a = stack.pop_back().expect("stack underflow");
                let b = stack.pop_back().expect("stack underflow");
                if a.len() != b.len() {
                    let msg = "OP_AND failed, different sizes".to_string();
                    return Err(Error::ScriptError(msg));
                }
                let mut result = Vec::with_capacity(a.len());
                for i in 0..a.len() {
                    result.push(a[i] & b[i]);
                }
                stack.push_back(Cow::Owned(result));
            }
            OP_OR => {
                check_stack_size(2, &stack)?;
                let a = stack.pop_back().expect("stack underflow");
                let b = stack.pop_back().expect("stack underflow");
                if a.len() != b.len() {
                    let msg = "OP_OR failed, different sizes".to_string();
                    return Err(Error::ScriptError(msg));
                }
                let mut result = Vec::with_capacity(a.len());
                for i in 0..a.len() {
                    result.push(a[i] | b[i]);
                }
                stack.push_back(Cow::Owned(result));
            }
            OP_XOR => {
                check_stack_size(2, &stack)?;
                let a = stack.pop_back().expect("stack underflow");
                let b = stack.pop_back().expect("stack underflow");
                if a.len() != b.len() {
                    let msg = "OP_XOR failed, different sizes".to_string();
                    return Err(Error::ScriptError(msg));
                }
                let mut result = Vec::with_capacity(a.len());
                for i in 0..a.len() {
                    result.push(a[i] ^ b[i]);
                }
                stack.push_back(Cow::Owned(result));
            }
            OP_INVERT => {
                check_stack_size(1, &stack)?;
                let mut v = stack.pop_back().expect("stack underflow").into_owned();
                v.iter_mut().for_each(|byte| *byte = !*byte);
                stack.push_back(Cow::Owned(v));
            }
            OP_LSHIFT => {
                check_stack_size(2, &stack)?;
                let n = pop_num(&mut stack)?;
                let v = stack.pop_back().expect("stack underflow").into_owned();
                if n < 0 {
                    let msg = "n must be non-negative".to_string();
                    return Err(Error::ScriptError(msg));
                }
                stack.push_back(Cow::Owned(lshift(&v, n as usize)));
            }
            OP_RSHIFT => {
                check_stack_size(2, &stack)?;
                let n = pop_num(&mut stack)?;
                let v = stack.pop_back().expect("stack underflow").into_owned();
                if n < 0 {
                    let msg = "n must be non-negative".to_string();
                    return Err(Error::ScriptError(msg));
                }
                stack.push_back(Cow::Owned(rshift(&v, n as usize)));
            }
            OP_EQUAL => {
                check_stack_size(2, &stack)?;
                let a = stack.pop_back().expect("stack underflow");
                let b = stack.pop_back().expect("stack underflow");
                let equal = a == b;
                stack.push_back(encode_num(equal as i64)?.into());
            }
            OP_EQUALVERIFY => {
                check_stack_size(2, &stack)?;
                let a = stack.pop_back().expect("stack underflow");
                let b = stack.pop_back().expect("stack underflow");
                if a != b {
                    return Err(Error::ScriptError("Operands are not equal".to_string()));
                }
            }
            OP_1ADD => {
                check_stack_size(1, &stack)?;
                let mut x = pop_bigint(&mut stack)?;
                x += 1;
                stack.push_back(encode_bigint(&x).into());
            }
            OP_1SUB => {
                check_stack_size(1, &stack)?;
                let mut x = pop_bigint(&mut stack)?;
                x -= 1;
                stack.push_back(encode_bigint(&x).into());
            }
            OP_NEGATE => {
                check_stack_size(1, &stack)?;
                let mut x = pop_bigint(&mut stack)?;
                x = -x;
                stack.push_back(encode_bigint(&x).into());
            }
            OP_ABS => {
                check_stack_size(1, &stack)?;
                let mut x = pop_bigint(&mut stack)?;
                if x < BigInt::zero() {
                    x = -x;
                }
                stack.push_back(encode_bigint(&x).into());
            }
            OP_NOT => {
                check_stack_size(1, &stack)?;
                let x = pop_bigint(&mut stack)?;
                let not_x = if x == BigInt::zero() { BigInt::one() } else { BigInt::zero() };
                stack.push_back(encode_bigint(&not_x).into());
            }
            OP_0NOTEQUAL => {
                check_stack_size(1, &stack)?;
                let x = pop_bigint(&mut stack)?;
                let not_zero = if x == BigInt::zero() { BigInt::zero() } else { BigInt::one() };
                stack.push_back(encode_bigint(&not_zero).into());
            }
            OP_ADD => {
                check_stack_size(2, &stack)?;
                let b = pop_bigint(&mut stack)?;
                let a = pop_bigint(&mut stack)?;
                let sum = a + b;
                stack.push_back(encode_bigint(&sum).into());
            }
            OP_SUB => {
                check_stack_size(2, &stack)?;
                let b = pop_bigint(&mut stack)?;
                let a = pop_bigint(&mut stack)?;
                let difference = a - b;
                stack.push_back(encode_bigint(&difference).into());
            }
            OP_MUL => {
                check_stack_size(2, &stack)?;
                let b = pop_bigint(&mut stack)?;
                let a = pop_bigint(&mut stack)?;
                let product = a * b;
                stack.push_back(encode_bigint(&product).into());
            }
            OP_DIV => {
                check_stack_size(2, &stack)?;
                let b = pop_bigint(&mut stack)?;
                let a = pop_bigint(&mut stack)?;
                if b == BigInt::zero() {
                    let msg = "OP_DIV failed, divide by 0".to_string();
                    return Err(Error::ScriptError(msg));
                }
                let quotient = a / b;
                stack.push_back(encode_bigint(&quotient).into());
            }
            OP_MOD => {
                check_stack_size(2, &stack)?;
                let b = pop_bigint(&mut stack)?;
                let a = pop_bigint(&mut stack)?;
                if b == BigInt::zero() {
                    let msg = "OP_MOD failed, divide by 0".to_string();
                    return Err(Error::ScriptError(msg));
                }
                let remainder = a % b;
                stack.push_back(encode_bigint(&remainder).into());
            }
            OP_BOOLAND => {
                check_stack_size(2, &stack)?;
                let b = pop_bigint(&mut stack)?;
                let a = pop_bigint(&mut stack)?;
                let result = if a != BigInt::zero() && b != BigInt::zero() { BigInt::one() } else { BigInt::zero() };
                stack.push_back(encode_bigint(&result).into());
            }
            OP_BOOLOR => {
                check_stack_size(2, &stack)?;
                let b = pop_bigint(&mut stack)?;
                let a = pop_bigint(&mut stack)?;
                let result = if a != BigInt::zero() || b != BigInt::zero() { BigInt::one() } else { BigInt::zero() };
                stack.push_back(encode_bigint(&result).into());
            }
            OP_NUMEQUAL => {
                check_stack_size(2, &stack)?;
                let b = pop_bigint(&mut stack)?;
                let a = pop_bigint(&mut stack)?;
                let result = if a == b { BigInt::one() } else { BigInt::zero() };
                stack.push_back(encode_bigint(&result).into());
            }
            OP_NUMEQUALVERIFY => {
                check_stack_size(2, &stack)?;
                let b = pop_bigint(&mut stack)?;
                let a = pop_bigint(&mut stack)?;
                if a != b {
                    let msg = "Numbers are not equal".to_string();
                    return Err(Error::ScriptError(msg));
                }
            }
            OP_NUMNOTEQUAL => {
                check_stack_size(2, &stack)?;
                let b = pop_bigint(&mut stack)?;
                let a = pop_bigint(&mut stack)?;
                let result = if a != b { BigInt::one() } else { BigInt::zero() };
                stack.push_back(encode_bigint(&result).into());
            }
            OP_LESSTHAN => {
                check_stack_size(2, &stack)?;
                let b = pop_bigint(&mut stack)?;
                let a = pop_bigint(&mut stack)?;
                let result = if a < b { BigInt::one() } else { BigInt::zero() };
                stack.push_back(encode_bigint(&result).into());
            }
            OP_GREATERTHAN => {
                check_stack_size(2, &stack)?;
                let b = pop_bigint(&mut stack)?;
                let a = pop_bigint(&mut stack)?;
                let result = if a > b { BigInt::one() } else { BigInt::zero() };
                stack.push_back(encode_bigint(&result).into());
            }
            OP_LESSTHANOREQUAL => {
                check_stack_size(2, &stack)?;
                let b = pop_bigint(&mut stack)?;
                let a = pop_bigint(&mut stack)?;
                let result = if a <= b { BigInt::one() } else { BigInt::zero() };
                stack.push_back(encode_bigint(&result).into());
            }
            OP_GREATERTHANOREQUAL => {
                check_stack_size(2, &stack)?;
                let b = pop_bigint(&mut stack)?;
                let a = pop_bigint(&mut stack)?;
                let result = if a >= b { BigInt::one() } else { BigInt::zero() };
                stack.push_back(encode_bigint(&result).into());
            }
            OP_MIN => {
                check_stack_size(2, &stack)?;
                let b = pop_bigint(&mut stack)?;
                let a = pop_bigint(&mut stack)?;
                let result = if a < b { a } else { b };
                stack.push_back(encode_bigint(&result).into());
            }
            OP_MAX => {
                check_stack_size(2, &stack)?;
                let b = pop_bigint(&mut stack)?;
                let a = pop_bigint(&mut stack)?;
                let result = if a > b { a } else { b };
                stack.push_back(encode_bigint(&result).into());
            }
            OP_WITHIN => {
                check_stack_size(3, &stack)?;
                let max = pop_bigint(&mut stack)?;
                let min = pop_bigint(&mut stack)?;
                let x = pop_bigint(&mut stack)?;
                let result = if x >= min && x < max { BigInt::one() } else { BigInt::zero() };
                stack.push_back(encode_bigint(&result).into());
            }
            OP_NUM2BIN => {
                check_stack_size(2, &stack)?;
                let m = pop_bigint(&mut stack)?;
                let mut n = stack.pop_back().expect("stack underflow").into_owned();
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
                let mut v = vec![0u8; m.to_usize().unwrap()];
                let mut neg = 0;
                if nlen > 0 {
                    neg = n[nlen - 1] & 128;
                    n[nlen - 1] &= 127;
                }
                let mut j = v.len() - 1;
                for &b in n.iter().rev() {
                    if j > 0 {
                        v[j] = b;
                        j -= 1;
                    }
                }
                v[0] |= neg as u8;
                stack.push_back(Cow::Owned(v));
            }
            OP_BIN2NUM => {
                check_stack_size(1, &stack)?;
                let mut v = stack.pop_back().expect("stack underflow").into_owned();
                v.reverse();
                let n = decode_bigint(&v);
                stack.push_back(encode_bigint(&n).into());
            }
            OP_RIPEMD160 => {
                check_stack_size(1, &stack)?;
                let v = stack.pop_back().expect("stack underflow");
                let h = bh_ripemd160::Hash::hash(v.as_ref()).to_byte_array();
                stack.push_back(Cow::Owned(h.to_vec()));
            }
            OP_SHA1 => {
                check_stack_size(1, &stack)?;
                let v = stack.pop_back().expect("stack underflow");
                let h = bh_sha1::Hash::hash(v.as_ref()).to_byte_array();
                stack.push_back(Cow::Owned(h.to_vec()));
            }
            OP_SHA256 => {
                check_stack_size(1, &stack)?;
                let v = stack.pop_back().expect("stack underflow");
                let h = bh_sha256::Hash::hash(v.as_ref()).to_byte_array();
                stack.push_back(Cow::Owned(h.to_vec()));
            }
            OP_HASH160 => {
                check_stack_size(1, &stack)?;
                let v = stack.pop_back().expect("stack underflow");
                let h = hash160(v.as_ref());
                stack.push_back(Cow::Owned(h.0.to_vec()));
            }
            OP_HASH256 => {
                check_stack_size(1, &stack)?;
                let v = stack.pop_back().expect("stack underflow");
                let h = sha256d(v.as_ref());
                stack.push_back(Cow::Owned(h.0.to_vec()));
            }
            OP_CODESEPARATOR => check_index = i + 1, // Set after the opcode
            OP_CHECKSIG => {
                check_stack_size(2, &stack)?;
                let pubkey = stack.pop_back().expect("stack underflow").into_owned();
                let sig = stack.pop_back().expect("stack underflow").into_owned();
                let mut cleaned_script = script[check_index..].to_vec();
                if prefork(&sig) {
                    cleaned_script = remove_sig(&sig, &cleaned_script);
                }
                let success = checker.check_sig(&sig, &pubkey, &cleaned_script)?;
                stack.push_back(encode_num(success as i64)?.into());
            }
            OP_CHECKSIGVERIFY => {
                check_stack_size(2, &stack)?;
                let pubkey = stack.pop_back().expect("stack underflow").into_owned();
                let sig = stack.pop_back().expect("stack underflow").into_owned();
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
            _ => return Err(Error::ScriptError(format!("Bad opcode: {}, index {}", script[i], i))),
        }
        i = next_op(i, script);
    }
    if !branch_exec.is_empty() {
        return Err(Error::ScriptError("Unmatched ENDIF".to_string()));
    }
    check_stack_size(1, &stack)?;
    if !decode_bool(stack.back().expect("stack empty")) {
        return Err(Error::ScriptError("Top of stack is false".to_string()));
    }
    Ok(())
}

#[inline]
fn check_multisig<'a, T: Checker>(
    stack: &mut VecDeque<Cow<'a, [u8]>>,
    checker: &mut T,
    script: &'a [u8],
) -> Result<bool> {
    let required = pop_num(stack)?;
    if required < 0 {
        return Err(Error::ScriptError("required out of range".to_string()));
    }
    check_stack_size(required as usize, stack)?;
    let mut sigs = Vec::with_capacity(required as usize);
    for _ in 0..required {
        sigs.push(stack.pop_back().expect("stack underflow").into_owned());
    }
    let total = pop_num(stack)?;
    if total < 0 || total < required as i32 {
        return Err(Error::ScriptError("total out of range".to_string()));
    }
    check_stack_size(total as usize, stack)?;
    let mut keys = Vec::with_capacity(total as usize);
    for _ in 0..total {
        keys.push(stack.pop_back().expect("stack underflow").into_owned());
    }
    // Pop dummy
    check_stack_size(1, stack)?;
    let _dummy = stack.pop_back().expect("stack underflow");
    // Reverse to restore original order (pops were reverse)
    sigs.reverse();
    keys.reverse();
    let mut cleaned_script = script.to_vec();
    for sig in &sigs {
        if prefork(sig) {
            cleaned_script = remove_sig(sig, &cleaned_script);
        }
    }
    let mut key_idx = 0;
    let mut sig_idx = 0;
    while sig_idx < required as usize {
        if key_idx == total as usize {
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
fn check_stack_size<'a>(minsize: usize, stack: &VecDeque<Cow<'a, [u8]>>) -> Result<()> {
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
        len @ 1..=75 => i + 1 + (len as usize),
        OP_PUSHDATA1 => {
            if i + 2 > script.len() {
                script.len()
            } else {
                i + 2 + (script[i + 1] as usize)
            }
        }
        OP_PUSHDATA2 => {
            if i + 3 > script.len() {
                script.len()
            } else {
                i + 3 + u16::from_le_bytes([script[i + 1], script[i + 2]]) as usize
            }
        }
        OP_PUSHDATA4 => {
            if i + 5 > script.len() {
                script.len()
            } else {
                i + 5 + u32::from_le_bytes([script[i + 1], script[i + 2], script[i + 3], script[i + 4]]) as usize
            }
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

fn encode_num(n: i64) -> Result<Vec<u8>> {
    if n == 0 {
        return Ok(vec![]);
    }
    let mut abs_n = n.abs() as u64;
    let negative = n < 0;
    let mut result = vec![];
    while abs_n > 0 {
        result.push((abs_n & 0xff) as u8);
        abs_n >>= 8;
    }
    let last = if let Some(last) = result.last_mut() {
        last
    } else {
        result.push(0);
        result.last_mut().unwrap()
    };
    if *last & 0x80 != 0 {
        if negative {
            result.push(0x80);
        } else {
            result.insert(0, 0);
        }
    } else if negative {
        *last |= 0x80;
    }
    Ok(result)
}

fn encode_bigint(n: &BigInt) -> Vec<u8> {
    let mut n = n.clone();
    if n == BigInt::zero() {
        return vec![];
    }
    let negative = n < BigInt::zero();
    if negative {
        n = -n;
    }
    let mut result = vec![];
    while n > BigInt::zero() {
        result.push((n.clone() & BigInt::from(0xffu8)).to_u8().unwrap());
        n >>= 8;
    }
    let last = if let Some(last) = result.last_mut() {
        last
    } else {
        result.push(0);
        result.last_mut().unwrap()
    };
    if *last & 0x80 != 0 {
        if negative {
            result.push(0x80);
        } else {
            result.insert(0, 0);
        }
    } else if negative {
        *last |= 0x80;
    }
    result
}

fn decode_bigint(v: &[u8]) -> BigInt {
    let mut result = BigInt::zero();
    for &b in v.iter().rev() {
        result <<= 8;
        result |= BigInt::from(b);
    }
    let negative = v.last().copied().unwrap_or(0) & 0x80 != 0;
    if negative {
        result &= !BigInt::from(0x80u8);
        -result
    } else {
        result
    }
}

fn pop_num<'a>(stack: &mut VecDeque<Cow<'a, [u8]>>) -> Result<i32> {
    check_stack_size(1, stack)?;
    let item = stack.pop_back().expect("stack underflow");
    let v = item.to_vec();
    decode_num(&v)
}

fn decode_num(v: &[u8]) -> Result<i32> {
    let mut result = 0i64;
    for &b in v.iter().rev() {
        result <<= 8;
        result |= b as i64;
    }
    let negative = v.last().copied().unwrap_or(0) & 0x80 != 0;
    if negative {
        result &= !0x80i64;
        Ok(-(result as i32))
    } else {
        Ok(result as i32)
    }
}

fn decode_bool<'a>(item: &Cow<'a, [u8]>) -> bool {
    !item.is_empty() && item[item.len() - 1] != 0x80 && item.iter().any(|&b| b != 0)
}

fn pop_bigint<'a>(stack: &mut VecDeque<Cow<'a, [u8]>>) -> Result<BigInt> {
    check_stack_size(1, stack)?;
    let item = stack.pop_back().expect("stack underflow");
    let v = item.to_vec();
    Ok(decode_bigint(&v))
}

fn pop_bool<'a>(stack: &mut VecDeque<Cow<'a, [u8]>>) -> Result<bool> {
    check_stack_size(1, stack)?;
    let item = stack.pop_back().expect("stack underflow");
    Ok(decode_bool(&item))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::{Script, TransactionlessChecker};

    #[test]
    fn test_op_push() {
        let mut s = Script::new();
        s.append(OP_PUSH + 3);
        s.append_slice(&[1, 2, 3]);
        let mut checker = TransactionlessChecker::default();
        assert!(eval(&s.0, &mut checker, NO_FLAGS).is_ok());
    }
}

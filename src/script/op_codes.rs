/// Script opcodes for Bitcoin SV consensus execution.
///
/// Constants grouped by category, matching BIP-16/34/65/68/112/143 and BSV Genesis upgrades (e.g., OP_CAT re-enabled).
///
/// Use in interpreter: `match op { OP_IF => ..., _ => err }`.
///
/// # Examples
/// ```
/// use nour::script::op_codes::*;
/// assert_eq!(OP_IF, 99);
/// ```

// Pushdata and Constants
/// Pushes empty array (0/false) onto the stack.
pub const OP_0: u8 = 0;
pub const OP_FALSE: u8 = 0;
pub const OP_PUSH: u8 = 0;

/// Offset to push n bytes (n: 1-75).
pub const OP_PUSHBYTES_1_TO_75: u8 = 1; // OP_PUSH implicit

/// Next byte is push length (up to 255 bytes).
pub const OP_PUSHDATA1: u8 = 76;
/// Next two bytes are push length (up to 65535 bytes).
pub const OP_PUSHDATA2: u8 = 77;
/// Next four bytes are push length (up to 4GB).
pub const OP_PUSHDATA4: u8 = 78;

/// Pushes -1 onto the stack.
pub const OP_1NEGATE: u8 = 79;

/// Pushes 1 (true) onto the stack.
pub const OP_1: u8 = 81;
pub const OP_TRUE: u8 = 81;

// Numeric constants (2-16)
pub const OP_2: u8 = 82;
pub const OP_3: u8 = 83;
pub const OP_4: u8 = 84;
pub const OP_5: u8 = 85;
pub const OP_6: u8 = 86;
pub const OP_7: u8 = 87;
pub const OP_8: u8 = 88;
pub const OP_9: u8 = 89;
pub const OP_10: u8 = 90;
pub const OP_11: u8 = 91;
pub const OP_12: u8 = 92;
pub const OP_13: u8 = 93;
pub const OP_14: u8 = 94;
pub const OP_15: u8 = 95;
pub const OP_16: u8 = 96;

// Flow Control
/// Does nothing.
pub const OP_NOP: u8 = 97;

/// If top stack is true, execute block (pops bool).
pub const OP_IF: u8 = 99;
/// If top stack is false, execute block (pops bool).
pub const OP_NOTIF: u8 = 100;
/// Inverts preceding IF/NOTIF execution.
pub const OP_ELSE: u8 = 103;
/// Ends IF/ELSE block.
pub const OP_ENDIF: u8 = 104;
/// Fails if top stack false (pops bool).
pub const OP_VERIFY: u8 = 105;
/// Ends execution (invalid pre-Genesis unless coinbase).
pub const OP_RETURN: u8 = 106;

// Stack Operations
/// Moves top item to alt stack.
pub const OP_TOALTSTACK: u8 = 107;
/// Moves top alt stack item to main stack.
pub const OP_FROMALTSTACK: u8 = 108;

/// Duplicates top if non-zero.
pub const OP_IFDUP: u8 = 115;
/// Pushes stack depth.
pub const OP_DEPTH: u8 = 116;
/// Drops top item.
pub const OP_DROP: u8 = 117;
/// Duplicates top.
pub const OP_DUP: u8 = 118;
/// Removes second-top.
pub const OP_NIP: u8 = 119;
/// Copies second-top to top.
pub const OP_OVER: u8 = 120;
/// Copies nth item to top.
pub const OP_PICK: u8 = 121;
/// Moves nth item to top.
pub const OP_ROLL: u8 = 122;
/// Rotates top three left.
pub const OP_ROT: u8 = 123;
/// Swaps top two.
pub const OP_SWAP: u8 = 124;
/// Copies top under second-top.
pub const OP_TUCK: u8 = 125;

/// Drops top two.
pub const OP_2DROP: u8 = 109;
/// Duplicates top two.
pub const OP_2DUP: u8 = 110;
/// Duplicates top three.
pub const OP_3DUP: u8 = 111;
/// Copies third/fourth to top.
pub const OP_2OVER: u8 = 112;
/// Moves fifth/sixth to top.
pub const OP_2ROT: u8 = 113;
/// Swaps top two pairs.
pub const OP_2SWAP: u8 = 114;

// Splice
/// Concatenates top two (re-enabled Genesis).
pub const OP_CAT: u8 = 126;
/// Splits top at n (re-enabled Genesis).
pub const OP_SPLIT: u8 = 127;
/// Pushes length of top (no pop).
pub const OP_SIZE: u8 = 130;

// Bitwise Logic
/// Inverts all bits in top (disabled pre-Genesis).
pub(crate) const OP_INVERT: u8 = 131;
/// Bitwise AND top two.
pub const OP_AND: u8 = 132;
/// Bitwise OR top two.
pub const OP_OR: u8 = 133;
/// Bitwise XOR top two.
pub const OP_XOR: u8 = 134;
/// Equals top two (bytes).
pub const OP_EQUAL: u8 = 135;
/// Equals + VERIFY.
pub const OP_EQUALVERIFY: u8 = 136;

// Arithmetic
/// Adds 1 to top.
pub const OP_1ADD: u8 = 139;
/// Subtracts 1 from top.
pub const OP_1SUB: u8 = 140;
/// Negates top.
pub const OP_NEGATE: u8 = 143;
/// Absolute value of top.
pub const OP_ABS: u8 = 144;
/// Logical NOT top (0/1 -> 1/0).
pub const OP_NOT: u8 = 145;
/// 0 != top (1 if non-zero).
pub const OP_0NOTEQUAL: u8 = 146;
/// Adds top two.
pub const OP_ADD: u8 = 147;
/// Subtracts top from second.
pub const OP_SUB: u8 = 148;
/// Multiplies top two (disabled pre-Genesis).
pub(crate) const OP_MUL: u8 = 149;
/// Divides second by top.
pub const OP_DIV: u8 = 150;
/// Modulo second % top.
pub const OP_MOD: u8 = 151;
/// Left shift top by n bits (disabled pre-Genesis).
pub(crate) const OP_LSHIFT: u8 = 152;
/// Right shift top by n bits (disabled pre-Genesis).
pub(crate) const OP_RSHIFT: u8 = 153;
/// Boolean AND nums.
pub const OP_BOOLAND: u8 = 154;
/// Boolean OR nums.
pub const OP_BOOLOR: u8 = 155;
/// Numeric equal.
pub const OP_NUMEQUAL: u8 = 156;
/// Numeric equal + VERIFY.
pub const OP_NUMEQUALVERIFY: u8 = 157;
/// Numeric not equal.
pub const OP_NUMNOTEQUAL: u8 = 158;
/// a < b (nums).
pub const OP_LESSTHAN: u8 = 159;
/// a > b (nums).
pub const OP_GREATERTHAN: u8 = 160;
/// a <= b (nums).
pub const OP_LESSTHANOREQUAL: u8 = 161;
/// a >= b (nums).
pub const OP_GREATERTHANOREQUAL: u8 = 162;
/// Min(a, b) nums.
pub const OP_MIN: u8 = 163;
/// Max(a, b) nums.
pub const OP_MAX: u8 = 164;
/// min <= x < max (nums).
pub const OP_WITHIN: u8 = 165;
/// Num to bin of len m.
pub const OP_NUM2BIN: u8 = 128;
/// Bin to num.
pub const OP_BIN2NUM: u8 = 129;

// Cryptography
/// RIPEMD160(top).
pub const OP_RIPEMD160: u8 = 166;
/// SHA1(top) (legacy).
pub const OP_SHA1: u8 = 167;
/// SHA256(top).
pub const OP_SHA256: u8 = 168;
/// RIPEMD160(SHA256(top)).
pub const OP_HASH160: u8 = 169;
/// SHA256(SHA256(top)).
pub const OP_HASH256: u8 = 170;
/// Starts sig matching from here.
pub const OP_CODESEPARATOR: u8 = 171;
/// Verifies sig for pubkey/tx (1/0).
pub const OP_CHECKSIG: u8 = 172;
/// CHECKSIG + VERIFY.
pub const OP_CHECKSIGVERIFY: u8 = 173;
/// m-of-n multisig verify (1/0).
pub const OP_CHECKMULTISIG: u8 = 174;
/// CHECKMULTISIG + VERIFY.
pub const OP_CHECKMULTISIGVERIFY: u8 = 175;

// Locktime
/// Fails if locktime > tx.lock_time (BIP-65).
pub const OP_CHECKLOCKTIMEVERIFY: u8 = 177;
/// Fails if sequence < tx.sequence (BIP-112, relative).
pub const OP_CHECKSEQUENCEVERIFY: u8 = 178;

// Pseudo-words
pub(crate) const OP_PUBKEYHASH: u8 = 253;
pub(crate) const OP_PUBKEY: u8 = 254;
pub(crate) const OP_INVALIDOPCODE: u8 = 255;

// Reserved (invalid unless unexecuted IF)
pub(crate) const OP_RESERVED: u8 = 80;
pub(crate) const OP_VER: u8 = 98;
pub(crate) const OP_VERIF: u8 = 101;
pub(crate) const OP_VERNOTIF: u8 = 102;
pub(crate) const OP_RESERVED1: u8 = 137;
pub(crate) const OP_RESERVED2: u8 = 138;

// NOPs (ignored)
pub(crate) const OP_NOP1: u8 = 176;
pub(crate) const OP_NOP4: u8 = 179;
pub(crate) const OP_NOP5: u8 = 180;
pub(crate) const OP_NOP6: u8 = 181;
pub(crate) const OP_NOP7: u8 = 182;
pub(crate) const OP_NOP8: u8 = 183;
pub(crate) const OP_NOP9: u8 = 184;
pub(crate) const OP_NOP10: u8 = 185;

/// Opcodes >= this are invalid.
pub(crate) const OP_INVALID_ABOVE: u8 = 186;

// Disabled (pre-Genesis)
pub(crate) const OP_2MUL: u8 = 141;
pub(crate) const OP_2DIV: u8 = 142;

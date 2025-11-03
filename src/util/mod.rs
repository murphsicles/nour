//! Miscellaneous helpers for Bitcoin SV toolkit.

use std::time::SystemTime;

#[allow(dead_code)]
mod bits;
mod bloom_filter;
pub mod hash160;
mod hash256;
mod result;
pub mod rx;
mod serdes;
pub(crate) mod var_int;

pub(crate) use self::bits::{lshift, rshift};

#[allow(dead_code)]
pub use self::bloom_filter::{
    BLOOM_FILTER_MAX_FILTER_SIZE, BLOOM_FILTER_MAX_HASH_FUNCS, BloomFilter,
};

pub use self::hash160::{Hash160, hash160};
pub use self::hash256::{Hash256, sha256d};
pub use self::result::{Error, Result};
#[allow(unused_imports)]
pub use self::serdes::Serializable;

/// Gets the time in seconds since a time in the past.
#[must_use]
#[inline]
pub fn secs_since(time: SystemTime) -> u32 {
    SystemTime::now().duration_since(time).unwrap().as_secs() as u32
}

/// Block height that BCH and BTC forked on mainnet.
pub const BITCOIN_CASH_FORK_HEIGHT_MAINNET: i32 = 478558;
/// Block height that BCH and BTC forked on testnet.
pub const BITCOIN_CASH_FORK_HEIGHT_TESTNET: i32 = 1155875;
/// Block height that activated the genesis upgrade on mainnet.
pub const GENESIS_UPGRADE_HEIGHT_MAINNET: i32 = 620538;
/// Block height that activated the genesis upgrade on testnet.
pub const GENESIS_UPGRADE_HEIGHT_TESTNET: i32 = 1344302;

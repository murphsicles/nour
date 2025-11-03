//! Wallet module for Bitcoin SV key management (BIP-32 extended keys).

pub mod extended_key;
pub use crate::address;

pub use self::extended_key::{
    ExtendedKey, ExtendedKeyType, HARDENED_KEY, MAINNET_PRIVATE_EXTENDED_KEY,
    MAINNET_PUBLIC_EXTENDED_KEY, TESTNET_PRIVATE_EXTENDED_KEY, TESTNET_PUBLIC_EXTENDED_KEY,
    derive_extended_key, extended_key_from_seed,
};

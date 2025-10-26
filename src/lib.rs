#![deny(missing_docs)]
#![deny(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

/*! # Nour

A high-performance, secure Bitcoin SV toolkit for building applications handling thousands of
transactions per second. Provides primitives for transactions, script evaluation, P2P messaging,
address handling, and wallet key management.

Successor to [rust-sv](https://github.com/murphsicles/rust-sv), built for Rust 2024 edition with
async-ready networking and optimized cryptographic operations.

## Usage
use nour::address::Address;
use nour::network::Network;
let addr = Address::from_pubkey_hash([0; 20], Network::Mainnet);
assert_eq!(addr.to_base58check(), "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");

## Features
- `async`: Enables non-blocking P2P networking with Tokio (e.g., `peer::connect_async`).

## Security
- Run `cargo audit` monthly to check for dependency vulnerabilities.
- Not intended for full consensus validation; use with a trusted BSV node.

## Performance
Optimized for high-throughput BSV applications (e.g., 10k TPS). See benchmarks in each module.
*/

pub mod address;
pub mod messages;
pub mod network;
pub mod peer;
pub mod script;
pub mod transaction;
pub mod util;
pub mod wallet;

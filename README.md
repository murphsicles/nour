# 💡 Nour

A Zeta library for building Bitcoin SV (BSV) applications and infrastructure — P2P networking, address handling, transaction processing, script evaluation, node connections, and wallet management.

[![Zorbs.io](https://img.shields.io/badge/zorbs.io-@crypto/nour-cyan?logo=zeta)](https://zorbs.io/@crypto/nour)
[![License](https://img.shields.io/badge/license-Open%20BSV-blue)](LICENSE)
[![GitHub](https://img.shields.io/badge/GitHub-murphsicles/nour-181717?logo=github)](https://github.com/murphsicles/nour)
[![GitHub last commit](https://img.shields.io/github/last-commit/murphsicles/nour?logo=github)](https://github.com/murphsicles/nour)

## Features

| Module | What it does |
|--------|-------------|
| `address` | Encode/decode Base58 addresses (P2PKH, P2SH) |
| `messages` | Full P2P message set — version, tx, block, inv, merkle, headers, etc. |
| `network` | Network types, seed node iteration |
| `peer` | TCP peer connections with message framing |
| `script` | BSV script evaluator — opcodes, stack, BIP-62, CHECKMULTISIG |
| `transaction` | P2PKH building, BIP-143 + legacy sighash |
| `util` | Bloom filters, varint, bits, hashing, reactive observers |
| `wallet` | BIP-32 extended keys, BIP-39 mnemonics |

## Installation

Add to your `zorb.toml`:

```toml
[dependencies]
nour = "0.1"
```

Then pull it down:

```bash
zorb install
```

## Usage

### Encode a Base58 Address

```zeta
use nour::address::{addr_encode, Network, AddressType};

let pubkeyhash: [u8; 20] = [0; 20];
let addr = addr_encode(pubkeyhash, AddressType::P2PKH, Network::Mainnet);
print(addr);
```

### Decode a Base58 Address

```zeta
use nour::address::{addr_decode, Network};

let (pubkeyhash, addr_type) = addr_decode("15wpV72HRpAFPMmosR3jvGq7axU7t6ghX5", Network::Mainnet);
```

### Connect to a Bitcoin SV Node

```zeta
use nour::peer::{Peer, SVPeerFilter};
use nour::messages::{Message, Ping, Version};
use nour::network::Network;

fn main() {
    let version = Version {
        version: 70016,
        services: 1,
        timestamp: 0,
        ..Version::default()
    };
    let peer = Peer::connect("127.0.0.1", 8333, Network::Mainnet, version, SVPeerFilter::new(0));
    peer.send(Message::Ping(Ping { nonce: 0 }));
}
```

### Sign a Transaction

```zeta
use nour::transaction::{generate_signature, SIGHASH_ALL_FORKID};
use nour::script::{Script, script_debug};

fn main() {
    let private_key: [u8; 32] = [0; 32];
    let sighash: [u8; 32] = [0; 32];
    let sig = generate_signature(private_key, sighash, SIGHASH_ALL_FORKID);
    print("Signature: ");
    print(hex::encode(sig));
}
```

## Building

```bash
zetac src/lib.z
```

## Performance

Performance-critical paths leverage Zeta's native capabilities:

| Operation | Notes |
|-----------|-------|
| Base58 encode/decode | SIMD-accelerated via `@crypto/bsv58` |
| SHA256 / Hash160 | Hardware-optimized via `@crypto/bitcoin-hashes` |
| ECDSA sign/verify | `@crypto/secp256k1` |
| Script evaluation | LLVM-optimized, tight loops |
| Bloom filter | Murmur3 via `@crypto/murmur3` |

## Module Structure

```
@crypto/nour/
├── zorb.toml
├── src/
│   ├── lib.z          — Top-level module
│   ├── address/       — Base58 address encoding/decoding
│   ├── messages/      — P2P protocol messages (24 types)
│   ├── network/       — Network configuration + seed iteration
│   ├── peer/          — TCP peer connections
│   ├── script/        — BSV script opcodes + interpreter
│   ├── transaction/   — P2PKH building + sighash
│   ├── util/          — Bloom filters, hashing, varint, reactive
│   └── wallet/        — BIP-32 + BIP-39 key management
```

## Original Rust Code

The original Rust implementation is preserved on the [`rust`](https://github.com/murphsicles/nour/tree/rust) branch.

Now available on zorbs.io as [`@crypto/nour`](https://zorbs.io/@crypto/nour).

## License

Open BSV License — see [LICENSE](LICENSE).

# 💡 Nour

A Rust library for building Bitcoin SV (BSV) applications and infrastructure, providing robust tools for P2P networking, address handling, transaction processing, script evaluation, node connections, and wallet management. Nour is optimized for BSV’s massive on-chain scaling, supporting millions of transactions per second (TPS) with async networking, efficient cryptography, and compatibility with Galaxy’s high-throughput capabilities.

[![Crates.io](https://img.shields.io/crates/v/nour.svg)](https://crates.io/crates/nour)
[![Documentation](https://docs.rs/nour/badge.svg)](https://docs.rs/nour/)
[![Dependencies](https://deps.rs/repo/github/murphsicles/nour/status.svg)](https://deps.rs/repo/github/murphsicles/nour)
[![Build Status](https://github.com/murphsicles/nour/actions/workflows/rust.yml/badge.svg)](https://github.com/murphsicles/nour/actions)

## Features

- **P2P Protocol**: Construct, serialize, and deserialize messages (sync/async) for BSV’s peer-to-peer network, supporting protocol version 70016.
- **Address Handling**: Encode/decode Base58 addresses for P2PKH and P2SH.
- **Transaction Signing**: Create and sign transactions, optimized for large blocks.
- **Script Evaluation**: Validate BSV scripts with Genesis rules (e.g., P2SH sunset).
- **Node Connections**: Connect to BSV nodes with async message handling for high TPS.
- **Wallet Support**: BIP-32/BIP-39 key derivation and mnemonic phrases.
- **Network Support**: Mainnet, Testnet, STN with seed node iteration.
- **Primitives**: Fast hashing (`Hash160`, `SHA256d`), bloom filters, variable integers, reactive programming.

## Installation

Add to your `Cargo.toml`:

    [dependencies]
    nour = "1.0.0"

Or use the development version:

    [dependencies]
    nour = { git = "https://github.com/murphsicles/nour", branch = "main" }

### System Requirements

- **Rust**: Stable 1.82 or later.
- **Dependencies**: `libzmq3-dev` (networking), `secp256k1`, `bitcoin_hashes`, `tokio`, `base58` (see Cargo.toml).
- **OS**: Linux (recommended), macOS, Windows.

Install dependencies on Ubuntu:

    sudo apt-get update && sudo apt-get install -y libzmq3-dev

## Usage

### Encode a Base58 Address

```rust
use nour::address::{addr_encode, AddressType};
use nour::network::Network;
use nour::util::hash160;

let pubkeyhash = hash160(&[0; 33]);
let addr = addr_encode(&pubkeyhash, AddressType::P2PKH, Network::Mainnet);
println!("Address: {}", addr);
```

### Decode a Base58 Address

```rust
use nour::address::addr_decode;
use nour::network::Network;

let addr = "15wpV72HRpAFPMmosR3jvGq7axU7t6ghX5";
let (pubkeyhash, addr_type) = addr_decode(&addr, Network::Mainnet).unwrap();
println!("Pubkey Hash: {:?}", pubkeyhash);
println!("Address Type: {:?}", addr_type);
```

### Connect to a Bitcoin SV Node

```rust
use nour::messages::{Message, Ping, Version, NODE_BITCOIN_CASH, PROTOCOL_VERSION};
use nour::network::Network;
use nour::peer::{Peer, SVPeerFilter};
use nour::util::secs_since;
use std::sync::Arc;
use std::time::UNIX_EPOCH;
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let stream = TcpStream::connect("127.0.0.1:8333").await?;
    let version = Version {
        version: PROTOCOL_VERSION,
        services: NODE_BITCOIN_CASH,
        timestamp: secs_since(UNIX_EPOCH) as i64,
        ..Default::default()
    };
    let peer = Peer::connect("127.0.0.1", 8333, Network::Mainnet, version, Arc::new(SVPeerFilter::new(0)));
    peer.connected_event().poll();
    let ping = Message::Ping(Ping { nonce: 0 });
    peer.send_async(&ping).await.unwrap();
    Ok(())
}
```

More examples are available in the [examples directory](examples/).

## Building and Testing

Clone the repository and run tests:

    git clone https://github.com/murphsicles/nour.git
    cd nour
    cargo test -- --nocapture

Build the library:

    cargo build --release

## Known Limitations

- **ZMQ Dependency**: Some node connections may require a running BSV node with ZMQ enabled.

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/my-feature`).
3. Commit changes (`git commit -m "Add my feature"`).
4. Push to the branch (`git push origin feature/my-feature`).
5. Open a Pull Request.

Report issues at [GitHub Issues](https://github.com/murphsicles/nour/issues).

## License

Nour is licensed under the [Open BSV License](LICENSE).

## Acknowledgments

- Built for the BSV blockchain community by [murphsicles](https://github.com/murphsicles).
- Designed to support Bitcoin SV’s commitment to massive on-chain scaling and Galaxy’s high-throughput architecture.

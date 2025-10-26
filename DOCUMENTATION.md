# 💡 Nour Docs

## Overview

Nour is a Rust library providing a foundation for building applications on Bitcoin SV (BSV) using Rust. It offers robust tools for Bitcoin SV primitive execution and consensus mechanisms, including P2P networking, address handling, transaction processing, script evaluation, node connections, wallet management, and various utility functions.

The library supports both Mainnet and Testnet, including compatibility with the Genesis upgrade and protocol version 70016. Nour is designed to power BSV applications with incredibly high throughput, supporting millions of transactions per second (TPS) through optimizations like async networking, efficient cryptographic operations, and support for the high-performance scaling of Galaxy's microservices.

### Key Features

- **P2P Protocol**: Construct, serialize, and deserialize messages for the Bitcoin SV peer-to-peer network, with async support via Tokio for high-throughput connections.
- **Address Handling**: Encode and decode Base58 addresses for Pay-to-PubKey-Hash (P2PKH) and Pay-to-Script-Hash (P2SH).
- **Transaction Signing**: Create and sign transactions using BSV scripts, optimized for large transactions.
- **Script Evaluation**: Execute and validate Bitcoin SV scripts with Genesis rules (e.g., P2SH sunset, large scripts).
- **Node Connections**: Establish and manage connections to BSV nodes with message handling, supporting async I/O for scalable applications.
- **Wallet Support**: Derive keys and parse mnemonics for wallet applications using BIP-32 and BIP-39.
- **Network Support**: Configurations for Mainnet, Testnet, and STN, including seed node iteration.
- **Primitives**: Utilities for hashing (Hash160, SHA256d), bloom filters, variable integers, serialization, and reactive programming.

## Installation

Add the following to your `Cargo.toml`:

    [dependencies]
    nour = "1.0.0"

For the development version:

    [dependencies]
    nour = { git = "https://github.com/murphsicles/nour", branch = "main" }

### System Requirements

- Rust: Stable version 1.82 or later.
- Dependencies: Requires libraries like `libzmq3-dev` for networking, `secp256k1`, `bitcoin_hashes`, `tokio`, `base58`, and others (see Cargo.toml).
- Operating Systems: Linux (recommended), macOS, Windows.

## Crates

The primary crate is `nour`, a library crate with no additional workspace crates. Dependencies include `bytes` (serialization), `secp256k1` (cryptography), `bitcoin_hashes` (hashing), `tokio` (async networking), `base58`, and others for bloom filters and reactive utilities, managed via Cargo.toml.

## Internal Structure

The library is modular, with each module focusing on a specific domain. Below is a detailed description of each module, including public types, traits, functions, constants, and examples.

### Main Library Entry (`src/lib.rs`)

The crate root declares public modules:
- `address`: Address encoding/decoding.
- `messages`: P2P protocol messages.
- `network`: Network configurations.
- `peer`: Node connections and message handling.
- `script`: Script opcodes and interpreter.
- `transaction`: Transaction building and signing.
- `util`: Miscellaneous helpers.
- `wallet`: Wallet and key management.

No root-level re-exports or additional types are specified.

### Address Module (`src/address/mod.rs`)

Handles encoding and decoding of BSV addresses.

**Public Enums**:
- `AddressType`: `P2PKH` or `P2SH`.

**Public Functions**:
- `addr_decode(addr: &str, network: Network) -> Result<(Vec<u8>, AddressType), Error>`: Decodes a Base58 address to public key hash and type.
  - Example:
    ```rust
    use nour::address::addr_decode;
    use nour::network::Network;

    let addr = "15wpV72HRpAFPMmosR3jvGq7axU7t6ghX5";
    let (pubkeyhash, addr_type) = addr_decode(&addr, Network::Mainnet).unwrap();
    ```
- `addr_encode(pubkeyhash: &[u8], addr_type: AddressType, network: Network) -> String`: Encodes a public key hash to a Base58 address.
  - Example:
    ```rust
    use nour::address::{addr_encode, AddressType};
    use nour::network::Network;
    use nour::util::hash160;

    let pubkeyhash = hash160(&[0; 33]);
    let addr = addr_encode(&pubkeyhash, AddressType::P2PKH, Network::Mainnet);
    ```

### Messages Module (`src/messages/mod.rs`)

Defines P2P messages with sync/async serialization/deserialization, optimized for high-throughput BSV networks.

**Public Structs**:
- `Addr`: List of node addresses.
- `Block`: Block of transactions.
- `BlockHeader`: Block header.
- `BlockLocator`: Specifies blocks for GetBlocks/GetHeaders.
- `FeeFilter`: Minimum transaction fee (e.g., 250 sats/1000 bytes, down to 10 with Galaxy & Teranode).
- `FilterAdd`: Adds data to bloom filter.
- `FilterLoad`: Loads bloom filter parameters.
- `Headers`: Collection of block headers (up to 20,000).
- `Inv`: Inventory vectors (up to 500,000).
- `InvVect`: Single inventory vector (tx/block/etc.).
- `MerkleBlock`: Partial merkle tree for SPV (up to 10M txs).
- `MessageHeader`: Header for all messages (magic, command, size, checksum).
- `NodeAddr`: Network address (IPv6, port, services).
- `NodeAddrEx`: Extended node address with timestamp.
- `OutPoint`: Transaction output reference.
- `Ping`: Ping/pong keepalive.
- `Reject`: Rejection message with code/reason.
- `SendCmpct`: Compact block support (BIP-152, optional in BSV).
- `Tx`: Transaction (version, inputs, outputs, lock_time).
- `TxIn`: Transaction input (OutPoint, unlock script, sequence).
- `TxOut`: Transaction output (satoshis, lock script).
- `Version`: Handshake capabilities (protocol 70016).

**Public Enums**:
- `Message`: Enum for all P2P messages (e.g., `Message::Version(version)`).

**Submodules**:
- `commands`: Message command strings.

**Constants** (selected):
- `BLOOM_UPDATE_*`: Bloom filter flags (NONE=0, ALL=1, P2PUBKEY_ONLY=2).
- `COINBASE_OUTPOINT_*`: Coinbase markers.
- `INV_VECT_*`: Inventory types (ERROR=0, TX=1, BLOCK=2, etc.).
- `REJECT_*`: Rejection codes (MALFORMED=0x01, INVALID=0x10, etc.).
- `MAX_INV_ENTRIES=50000`, `MAX_PAYLOAD_SIZE=4GB`, `MAX_TOTAL_TX=10B`, `MAX_BLOCK_LOCATOR_HASHES=2000`, `MAX_HEADERS=2000`.

**Examples**:
- Decoding a message:
    ```rust
    use nour::messages::Message;
    use nour::network::Network;
    use std::io::Cursor;

    let bytes = [/* byte array */];
    let magic = Network::Mainnet.magic();
    let message = Message::read(&mut Cursor::new(&bytes), magic).unwrap();
    match message {
        Message::Headers(headers) => println!("Received {} headers", headers.headers.len()),
        _ => println!("Other message"),
    }
    ```
- Async message handling:
    ```rust
    use nour::messages::{Message, Ping};
    use nour::network::Network;
    use tokio::io;

    async fn handle_message() -> io::Result<()> {
        let magic = Network::Mainnet.magic();
        let bytes = [/* byte array */];
        let message = Message::read_async(&mut io::Cursor::new(&bytes), magic).await.unwrap();
        if let Message::Ping(ping) = message {
            println!("Ping nonce: {}", ping.nonce);
        }
        Ok(())
    }
    ```
- Constructing a transaction:
    ```rust
    use nour::messages::{OutPoint, Tx, TxIn, TxOut};
    use nour::script::op_codes;
    use nour::util::Hash256;

    let tx = Tx {
        version: 2,
        inputs: vec![TxIn {
            prev_output: OutPoint { hash: Hash256([0; 32]), index: 0 },
            unlock_script: Script(vec![op_codes::OP_1]),
            sequence: 0,
        }],
        outputs: vec![TxOut {
            satoshis: 1000,
            lock_script: Script(vec![op_codes::OP_DUP, op_codes::OP_HASH160, /* pubkeyhash */]),
        }],
        lock_time: 0,
    };
    ```

### Network Module (`src/network/mod.rs`)

Provides network configurations and seed node iteration.

**Public Enums**:
- `Network`: Mainnet, Testnet, STN.

**Public Structs**:
- `NetworkConfig`: Network configuration with seeds and port.
- `SeedIter`: Iterates through DNS seeds semi-randomly.

**Public Functions**:
- `NetworkConfig::new(network_type: u8) -> Result<NetworkConfig>`: Creates a network configuration.
- `network_config.port() -> u16`: Returns the default TCP port.
- `network_config.magic() -> [u8; 4]`: Returns the magic bytes.
- `network_config.genesis_block() -> Block`: Returns the genesis block.
- `network_config.genesis_hash() -> Hash256`: Returns the genesis block hash.
- `network_config.addr_pubkeyhash_flag() -> u8`: Version byte for P2PKH addresses.
- `network_config.addr_script_flag() -> u8`: Version byte for P2SH addresses.
- `network_config.seed_iter() -> SeedIter`: Creates a DNS seed iterator.

**Examples**:
- Iterate through seed nodes:
    ```rust
    use nour::network::NetworkConfig;

    let network = NetworkConfig::new(0).unwrap(); // Mainnet
    for (ip, port) in network.seed_iter() {
        println!("Seed node {}:{}", ip, port);
    }
    ```

### Peer Module (`src/peer/mod.rs`)

Manages node connections and message handling with async support.

**Public Structs**:
- `Peer`: Node for sending/receiving messages.
- `PeerConnected`: Connection established event.
- `PeerDisconnected`: Connection terminated event.
- `PeerMessage`: Received message event.
- `SVPeerFilter`: Filters BSV full nodes.

**Public Traits**:
- `PeerFilter`: Filters peers by version.

**Public Functions**:
- `Peer::connect(ip, port, network: NetworkConfig, version: Version, filter: Arc<dyn PeerFilter>) -> Arc<Peer>`: Connects to a peer.
- `peer.send(&message) -> Result<()>`: Sends a message.
- `peer.send_async(&message) -> impl Future<Output = Result<()>>`: Sends asynchronously.
- `peer.connected_event() -> impl Observable<PeerConnected>`: Observable for connection events.
- Similar for `disconnected_event()`, `messages()`.

**Examples**:
- Async connection:
    ```rust
    use nour::messages::{Message, Ping, Version, NODE_BITCOIN_CASH, PROTOCOL_VERSION};
    use nour::network::NetworkConfig;
    use nour::peer::{Peer, SVPeerFilter};
    use nour::util::secs_since;
    use std::time::UNIX_EPOCH;
    use tokio;

    #[tokio::main]
    async fn main() -> Result<()> {
        let version = Version {
            version: PROTOCOL_VERSION,
            services: NODE_BITCOIN_CASH,
            timestamp: secs_since(UNIX_EPOCH) as i64,
            ..Default::default()
        };
        let peer = Peer::connect("127.0.0.1", 8333, NetworkConfig::new(0).unwrap(), version, SVPeerFilter::new(0));
        let ping = Message::Ping(Ping { nonce: 0 });
        peer.send_async(&ping).await.unwrap();
        Ok(())
    }
    ```

### Script Module (`src/script/mod.rs`)

Handles script opcodes and interpretation.

**Public Structs**:
- `Script`: Transaction script.
- `TransactionChecker`: Validates transaction spends.
- `TransactionlessChecker`: Fails transaction checks.

**Public Traits**:
- `Checker`: External value checks for scripts.

**Submodules**:
- `op_codes`: Script opcodes (e.g., `OP_DUP`, `OP_HASH160`).

**Constants**:
- `NO_FLAGS`: Genesis rules.
- `PREGENESIS_RULES`: Pre-Genesis rules.

**Public Functions**:
- `script.eval(&mut checker, flags) -> Result<()>`: Evaluates a script.

**Examples**:
- Evaluate a simple script:
    ```rust
    use nour::script::{op_codes, Script, TransactionlessChecker, NO_FLAGS};

    let mut script = Script::new();
    script.append(op_codes::OP_10);
    script.append(op_codes::OP_5);
    script.append(op_codes::OP_DIV);
    script.eval(&mut TransactionlessChecker {}, NO_FLAGS).unwrap();
    ```

### Transaction Module (`src/transaction/mod.rs`)

Supports building and signing transactions.

**Public Structs**:
- `SigHashCache`: Caches sighash computations.

**Public Functions**:
- `generate_signature(private_key: &[u8;32], sighash: &Hash256, sighash_type: u32) -> Result<Vec<u8>>`: Generates a signature for a sighash.

**Submodules**:
- `p2pkh`: P2PKH scripts (`create_lock_script`, `create_unlock_script`).
- `sighash`: Sighash helpers (`sighash`, `SIGHASH_FORKID`, etc.).

**Examples**:
- Signing a transaction:
    ```rust
    use nour::messages::{Tx, TxIn, TxOut};
    use nour::transaction::p2pkh::{create_lock_script, create_unlock_script};
    use nour::transaction::sighash::{sighash, SigHashCache, SIGHASH_FORKID, SIGHASH_ALL};
    use nour::util::{hash160, Hash256};

    let private_key = [/* 32-byte key */];
    let public_key = [/* 33-byte pubkey */];
    let tx = Tx { /* initialize */ };
    let mut cache = SigHashCache::new();
    let sighash = sighash(&tx, 0, &[], SIGHASH_ALL | SIGHASH_FORKID, 0, &mut cache).unwrap();
    let signature = generate_signature(&private_key, &sighash, SIGHASH_ALL | SIGHASH_FORKID).unwrap();
    tx.inputs[0].unlock_script = create_unlock_script(&signature, &public_key);
    ```

### Util Module (`src/util/mod.rs`)

Miscellaneous helpers.

**Public Structs**:
- `BloomFilter`: Bloom filter for SPV (max 36000 bytes, 50 hash funcs).
- `Hash160`: 160-bit hash for addresses.
- `Hash256`: 256-bit hash for blocks/transactions.
- `Bits`: Bit manipulation for mnemonics.

**Public Enums**:
- `Error`: Standard error type (e.g., `IOError`, `BadData`).

**Public Traits**:
- `Serializable`: Sync serialization/deserialization.
- `AsyncSerializable`: Async serialization/deserialization.

**Public Functions**:
- `hash160(data: &[u8]) -> Hash160`: RIPEMD160(SHA256(data)).
- `sha256d(data: &[u8]) -> Hash256`: Double SHA256.
- `var_int::{read, write, size}`: Variable integer encoding.
- `secs_since(time: SystemTime) -> u64`: Seconds since time.

**Type Aliases**:
- `Result<T>`: `std::result::Result<T, Error>`.

**Constants**:
- `BITCOIN_CASH_FORK_HEIGHT_*`, `GENESIS_UPGRADE_HEIGHT_*`: Fork heights.
- `BLOOM_FILTER_MAX_*`: Bloom filter limits.

**Submodules**:
- `rx`: Reactive programming (`Observable`, `Observer`).

**Examples**:
- Hashing:
    ```rust
    use nour::util::{hash160, Hash256};

    let data = b"test";
    let h160 = hash160(data);
    let h256 = Hash256::sha256d(data);
    ```

### Wallet Module (`src/wallet/mod.rs`)

Wallet and key management with BIP-32/BIP-39.

**Public Structs**:
- `ExtendedKey`: BIP-32 xpub/xprv (78 bytes).

**Public Enums**:
- `ExtendedKeyType`: Private or Public.
- `Wordlist`: Languages (English, Spanish, etc.).

**Public Functions**:
- `derive_extended_key(input: &str, path: &str, network: Network, secp: &Secp256k1) -> Result<ExtendedKey>`: Derives key from seed or parent (m/0H/1).
- `extended_key_from_seed(seed: &[u8], network: Network) -> Result<ExtendedKey>`: Master private key from seed.
- `load_wordlist(language: Wordlist) -> &'static [String]`: Loads 2048-word list.
- `mnemonic_encode(data: &[u8], word_list: &[String]) -> Result<Vec<String>>`: Encodes to BIP-39 mnemonic.
- `mnemonic_decode(mnemonic: &[String], word_list: &[String]) -> Result<Vec<u8>>`: Decodes BIP-39 mnemonic.

**Constants**:
- `HARDENED_KEY=0x80000000`: Hardened derivation.
- `MAINNET_PRIVATE_EXTENDED_KEY`, etc.: xprv/xpub prefixes.
- `MAX_DATA_LEN=64`: Mnemonic data limit (512 bits).

**Examples**:
- Derive key from mnemonic:
    ```rust
    use nour::network::Network;
    use nour::wallet::{load_wordlist, mnemonic_decode, derive_extended_key, Wordlist};
    use secp256k1::Secp256k1;

    let secp = Secp256k1::new();
    let wordlist = load_wordlist(Wordlist::English);
    let mnemonic = ["word", /* 12-24 words */].iter().map(String::from).collect::<Vec<_>>();
    let seed = mnemonic_decode(&mnemonic, &wordlist).unwrap();
    let xprv = derive_extended_key(&hex::encode(seed), "m/44H/0H/0H", Network::Mainnet, &secp).unwrap();
    ```

## Additional Files

- **.github/workflows/**: CI pipelines for testing and publishing.
- `.gitignore`, `CHANGELOG.md`, `LICENSE` (Open BSV), `README.md`: Standard project files.

This documentation covers the full Nour crate, optimized for BSV’s high-throughput applications. For further details, refer to the source code or generated Rust docs.

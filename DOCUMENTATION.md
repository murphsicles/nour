# 💡 Nour Docs

## Overview

Nour is a Zeta library providing a foundation for building applications on Bitcoin SV (BSV). It offers P2P networking, address handling, transaction processing, script evaluation, node connections, wallet management, and various utility functions.

The library supports Mainnet, Testnet, and STN, including compatibility with the Genesis upgrade and protocol version 70016.

### Key Features

- **P2P Protocol**: Construct, serialize, and deserialize messages for the Bitcoin SV peer-to-peer network.
- **Address Handling**: Encode and decode Base58 addresses for P2PKH and P2SH.
- **Transaction Signing**: Create and sign transactions using BSV scripts.
- **Script Evaluation**: Execute and validate BSV scripts with Genesis rules.
- **Node Connections**: Establish and manage connections to BSV nodes with message handling.
- **Wallet Support**: Derive keys and parse mnemonics using BIP-32 and BIP-39.
- **Network Support**: Configurations for Mainnet, Testnet, and STN, including seed node iteration.
- **Primitives**: Hashes (Hash160, SHA256d), bloom filters, variable integers, serialization.

## Installation

Add to your `zorb.toml`:

    [dependencies]
    nour = "0.1"

Then pull it down:

    zorb install

### System Requirements

- **Zeta compiler**: Latest stable.
- **Dependencies**: Resolved automatically by zorb — see `zorb.toml` for the full list.
- **Operating Systems**: Linux (recommended), macOS, Windows.

## Internal Structure

### Main Library Entry (`src/lib.z`)

The library root declares public modules:
- `address`: Address encoding/decoding.
- `messages`: P2P protocol messages.
- `network`: Network configurations.
- `peer`: Node connections and message handling.
- `script`: Script opcodes and interpreter.
- `transaction`: Transaction building and signing.
- `util`: Miscellaneous helpers.
- `wallet`: Wallet and key management.

### Address Module (`src/address/mod.z`)

Handles encoding and decoding of BSV addresses.

**Public Types**:
- `AddressType`: enum with `P2PKH` and `P2SH` variants.

**Public Functions**:
- `addr_decode(addr: string, network: Network) -> ([u8], AddressType)`: Decodes a Base58 address to public key hash and type.
  - Example:
    ```zeta
    use nour::address::addr_decode;
    use nour::network::Network;

    let (pubkeyhash, addr_type) = addr_decode("15wpV72HRpAFPMmosR3jvGq7axU7t6ghX5", Network::Mainnet);
    ```
- `addr_encode(pubkeyhash: [u8], addr_type: AddressType, network: Network) -> string`: Encodes a public key hash to a Base58 address.
  - Example:
    ```zeta
    use nour::address::{addr_encode, AddressType};
    use nour::network::Network;

    let pubkeyhash: [u8; 20] = [0; 20];
    let addr = addr_encode(pubkeyhash, AddressType::P2PKH, Network::Mainnet);
    ```

### Messages Module (`src/messages/mod.z`)

Defines P2P message types with serialization/deserialization for BSV's peer-to-peer network.

**Public Structs**:
- `Addr`: List of node addresses.
- `Block`: Block of transactions.
- `BlockHeader`: Block header.
- `BlockLocator`: Block locator hashes for GetBlocks/GetHeaders.
- `FeeFilter`: Minimum transaction fee filter.
- `FilterAdd`: Data to add to bloom filter.
- `FilterLoad`: Bloom filter parameters to load.
- `Headers`: Collection of block headers.
- `Inv`: Inventory vectors.
- `InvVect`: Single inventory vector (tx, block, etc.).
- `MerkleBlock`: Partial merkle tree for SPV (BIP-37).
- `MessageHeader`: Header for all messages (magic, command, size, checksum).
- `NodeAddr`: Network address (IPv6, port, services).
- `NodeAddrEx`: Extended node address with timestamp.
- `OutPoint`: Transaction output reference (hash + index).
- `Ping`: Ping/pong keepalive.
- `Reject`: Rejection message with code, reason, and data.
- `SendCmpct`: Compact block support (BIP-152).
- `Tx`: Transaction (version, inputs, outputs, lock_time).
- `TxIn`: Transaction input (outpoint, unlock script, sequence).
- `TxOut`: Transaction output (satoshis, lock script).
- `Version`: Handshake message (protocol 70016).

**Public Enums**:
- `Message`: Union type for all P2P messages.

**Constants**:
- `PROTOCOL_VERSION = 70016`
- `NODE_BITCOIN_CASH = 1`
- `MAX_INV_ENTRIES = 50000`
- `MAX_PAYLOAD_SIZE`: 4 GB
- `MAX_HEADERS = 2000`
- `MAX_BLOCK_LOCATOR_HASHES = 2000`
- `MAX_TOTAL_TX = 10000000000`
- `BLOOM_UPDATE_NONE = 0`
- `BLOOM_UPDATE_ALL = 1`
- `BLOOM_UPDATE_P2PUBKEY_ONLY = 2`
- `COINBASE_OUTPOINT_HASH`: zero hash
- `COINBASE_OUTPOINT_INDEX`: 0xFFFFFFFF
- Rejection codes: `REJECT_MALFORMED = 0x01`, `REJECT_INVALID = 0x10`, `REJECT_OBSOLETE = 0x11`, `REJECT_DUPLICATE = 0x12`, `REJECT_NONSTANDARD = 0x40`, `REJECT_DUST = 0x41`, `REJECT_INSUFFICIENTFEE = 0x42`, `REJECT_CHECKPOINT = 0x43`
- Inventory types: `INV_VECT_ERROR = 0`, `INV_VECT_TX = 1`, `INV_VECT_BLOCK = 2`, `INV_VECT_FILTERED_BLOCK = 3`, `INV_VECT_CMPCT_BLOCK = 4`

### Network Module (`src/network/mod.z`)

Provides network configurations and seed node iteration.

**Public Types**:
- `Network`: enum with `Mainnet`, `Testnet`, `STN` variants.
- `NetworkConfig`: Configuration struct with port, magic bytes, genesis block, address version bytes.
- `SeedIter`: DNS seed iterator.

**Public Functions**:
- `network_config_new(network_type: i64) -> NetworkConfig`: Creates a network configuration.
- `network_config_port(config: NetworkConfig) -> i64`: Returns the default TCP port.
- `network_config_magic(config: NetworkConfig) -> [u8; 4]`: Returns the magic bytes.
- `network_config_genesis_block(config: NetworkConfig) -> Block`: Returns the genesis block.
- `network_config_genesis_hash(config: NetworkConfig) -> [u8; 32]`: Returns the genesis block hash.
- `network_config_addr_pubkeyhash_flag(config: NetworkConfig) -> u8`: Version byte for P2PKH.
- `network_config_addr_script_flag(config: NetworkConfig) -> u8`: Version byte for P2SH.
- `seed_iter_new(config: NetworkConfig) -> SeedIter`: Creates a DNS seed iterator.

**Examples**:
- Iterate through seed nodes:
    ```zeta
    use nour::network::{network_config_new, seed_iter_next};

    let network = network_config_new(0); // Mainnet
    let mut iter = seed_iter_new(network);
    while let Some((ip, port)) = seed_iter_next(iter) {
        // Connect to seed node
    }
    ```

### Peer Module (`src/peer/mod.z`)

Manages node connections and message sending/receiving.

**Public Structs**:
- `Peer`: Node for sending/receiving messages.
- `SVPeerFilter`: Filters for BSV full nodes.

**Public Functions**:
- `peer_connect(ip: string, port: i64, network: Network, version: Version, filter: SVPeerFilter) -> Peer`: Connects to a peer.
- `peer_send(peer: Peer, message: Message) -> i64`: Sends a message synchronously.
- `peer_send_async(peer: Peer, message: Message)`: Sends a message asynchronously (requires `async` feature).
- `peer_connected(peer: Peer) -> bool`: Returns true if connected.
- `peer_disconnect(peer: Peer)`: Disconnects.

**Examples**:
- Connect and send a ping:
    ```zeta
    use nour::messages::{Message, Ping, Version, NODE_BITCOIN_CASH, PROTOCOL_VERSION};
    use nour::network::Network;
    use nour::peer::{peer_connect, peer_send, SVPeerFilter};

    fn main() {
        let version = Version {
            version: PROTOCOL_VERSION,
            services: NODE_BITCOIN_CASH,
            timestamp: 0,
            user_agent: "/nour:0.1/".to_string(),
            start_height: 0,
            relay: true,
        };
        let peer = peer_connect("127.0.0.1", 8333, Network::Mainnet, version, SVPeerFilter::new(0));
        _ = peer_send(peer, Message::Ping(Ping { nonce: 0 }));
    }
    ```

### Script Module (`src/script/mod.z`)

Handles script opcodes, stack evaluation, and signature checking.

**Public Types**:
- `Script`: Transaction script with byte data and length tracking.
- `EvalChecker`: Checker interface for transaction validation.
- `TransactionChecker`: Full transaction validation.
- `TransactionlessChecker`: Checker that cannot validate spends.

**Submodules**:
- `op_codes`: All BSV script opcodes (`OP_DUP`, `OP_HASH160`, `OP_CHECKSIG`, etc.).
- `stack`: Stack data structure for script evaluation.
- `interpreter`: Main script evaluator.
- `checker`: Signature and transaction checking.

**Constants**:
- `NO_FLAGS = 0`: Genesis rules.
- `PREGENESIS_RULES`: Pre-Genesis compatibility flags.
- `MAX_SCRIPT_SIZE = 10000`
- `MAX_STACK_SIZE = 1000`
- `MAX_OP_COUNT = 201`

**Public Functions**:
- `script_new() -> Script`: Creates an empty script.
- `script_append(script: Script, byte: u8)`: Appends a byte.
- `script_append_data(script: Script, data: [u8]) -> i64`: Appends pushdata.
- `script_append_num(script: Script, n: i64) -> i64`: Appends a number.
- `script_eval(script: Script, checker: EvalChecker, flags: i64) -> i64`: Evaluates the script.
- `script_debug(script: Script) -> string`: Returns debug representation.
- `next_op(pos: i64, data: [u8]) -> i64`: Returns position of the next opcode.

**Examples**:
- Evaluate a simple script:
    ```zeta
    use nour::script::{script_new, script_append, script_append_num, script_eval, TransactionlessChecker, NO_FLAGS, op_codes};

    fn main() {
        let mut s = script_new();
        _ = script_append_num(s, 10);
        _ = script_append_num(s, 5);
        script_append(s, op_codes::OP_DIV);
        _ = script_eval(s, TransactionlessChecker {}, NO_FLAGS);
    }
    ```

### Transaction Module (`src/transaction/mod.z`)

Supports building and signing transactions.

**Submodules**:
- `p2pkh`: P2PKH script creation and extraction.
- `sighash`: BIP-143 forkid sighash and legacy sighash computation.

**Public Functions**:
- `generate_signature(private_key: [u8; 32], sighash: [u8; 32], sighash_type: u8) -> [u8]`: Generates a DER-encoded ECDSA signature.

**Sighash types** (defined in `sighash.z`):
- `SIGHASH_ALL = 1`
- `SIGHASH_NONE = 2`
- `SIGHASH_SINGLE = 3`
- `SIGHASH_FORKID = 0x40`
- `SIGHASH_ANYONECANPAY = 0x80`
- `SIGHASH_ALL_FORKID = SIGHASH_ALL | SIGHASH_FORKID`
- `SIGHASH_SINGLE_ANYONECANPAY_FORKID = SIGHASH_SINGLE | SIGHASH_FORKID | SIGHASH_ANYONECANPAY`

**Examples**:
- Sign a P2PKH transaction input:
    ```zeta
    use nour::transaction::{generate_signature, SIGHASH_ALL_FORKID};
    use nour::transaction::p2pkh::{create_lock_script, create_unlock_script};
    use nour::transaction::sighash::sighash;

    fn main() {
        let private_key: [u8; 32] = [0; 32];
        let public_key: [u8; 33] = [2; 33];
        let tx: Tx = Tx { /* create transaction */ };
        let sighash_bytes = sighash(tx, 0, [], SIGHASH_ALL_FORKID, 0);
        let signature = generate_signature(private_key, sighash_bytes, SIGHASH_ALL_FORKID);
        // Assign unlock script
    }
    ```

### Util Module (`src/util/mod.z`)

Miscellaneous helpers and utilities.

**Public Structs**:
- `BloomFilter`: Bloom filter for SPV (max 36000 bytes, 50 hash functions).
- `Bits`: Bit-level data structure for mnemonic operations.

**Public Functions**:
- `hash160(data: [u8]) -> [u8; 20]`: RIPEMD160(SHA256(data)).
- `sha256d(data: [u8]) -> [u8; 32]`: Double SHA256.
- `var_int_size(n: i64) -> i64`: Returns the size of a variable integer.
- `var_int_write(n: i64) -> [u8]`: Writes a variable integer to bytes.
- `var_int_read(data: [u8]) -> (i64, i64)`: Reads a variable integer, returns (value, new_offset).
- `bits_new() -> Bits`: Creates an empty Bits array.
- `bits_from_slice(data: [u8], len: i64) -> Bits`: Creates Bits from a slice.
- `bits_append(bits: Bits, other: Bits)`: Appends data.
- `bits_extract(bits: Bits, i: i64, len: i64) -> i64`: Extracts bits.
- `bits_lshift(v: [u8], n: i64) -> [u8]`: Left-shifts a byte array.
- `bits_rshift(v: [u8], n: i64) -> [u8]`: Right-shifts a byte array.

**Constants**:
- *Fork heights*: `BITCOIN_CASH_FORK_HEIGHT_MAINNET`, `BITCOIN_CASH_FORK_HEIGHT_TESTNET`, `GENESIS_UPGRADE_HEIGHT_MAINNET`, `GENESIS_UPGRADE_HEIGHT_TESTNET`, `GENESIS_UPGRADE_HEIGHT_STN`.
- *Bloom filter limits*: `BLOOM_FILTER_MAX_SIZE = 36000`, `BLOOM_FILTER_MAX_HASH_FUNCS = 50`.

**Examples**:
- Hashing:
    ```zeta
    use nour::util::{hash160, sha256d};

    fn main() {
        let data: [u8] = [0x74, 0x65, 0x73, 0x74]; // "test"
        let h160 = hash160(data);
        let h256 = sha256d(data);
    }
    ```

### Wallet Module (`src/wallet/mod.z`)

Wallet and key management with BIP-32 and BIP-39.

**Public Types**:
- `ExtendedKey`: BIP-32 extended public or private key.
- `ExtendedKeyType`: enum with `Private` and `Public` variants.

**Constants**:
- `HARDENED_KEY = 0x80000000`
- `MAINNET_PRIVATE_EXTENDED_KEY`: xprv prefix bytes
- `MAINNET_PUBLIC_EXTENDED_KEY`: xpub prefix bytes
- `TESTNET_PRIVATE_EXTENDED_KEY`: tprv prefix bytes
- `TESTNET_PUBLIC_EXTENDED_KEY`: tpub prefix bytes
- `MAX_DATA_LEN = 64`: Mnemonic data limit (512 bits)

**Public Functions**:
- `hmac_sha512(key: [u8], data: [u8]) -> [u8; 64]`: HMAC-SHA512.
- `derive_child(key: ExtendedKey, index: i64) -> ExtendedKey`: Derives a child key.
- `extended_key_from_seed(seed: [u8], network: Network) -> ExtendedKey`: Creates master key from seed.
- `derive_extended_key(input: [u8], path: string, network: Network) -> ExtendedKey`: Derives key from path (e.g., "m/44'/0'/0'").
- `encode_extended_key(key: ExtendedKey) -> string`: Encodes to Base58Check.
- `decode_extended_key(encoded: string) -> ExtendedKey`: Decodes from Base58Check.
- `mnemonic_encode(data: [u8], wordlist: [string]) -> [string]`: Encodes data to BIP-39 mnemonic.
- `mnemonic_decode(mnemonic: [string], wordlist: [string]) -> [u8]`: Decodes BIP-39 mnemonic to seed.

**Examples**:
- Derive a key from a seed:
    ```zeta
    use nour::network::Network;
    use nour::wallet::{extended_key_from_seed, derive_extended_key, encode_extended_key};

    fn main() {
        let seed: [u8; 64] = [0; 64]; // 512-bit seed
        let master = extended_key_from_seed(seed, Network::Mainnet);
        let child = derive_extended_key(master, "m/44'/0'/0'/0/0", Network::Mainnet);
        let encoded = encode_extended_key(child);
        print(encoded);
    }
    ```

## Additional Files

- **zorb.toml**: Package manifest.
- **FILETREE**: Directory structure listing.
- **LICENSE**: Open BSV License.
- **README.md**: Quick-start guide.

The original Rust implementation is preserved on the [`rust`](https://github.com/murphsicles/nour/tree/rust) branch.

---

This documentation covers the full Nour Zeta library. For further details, refer to the source code.

//! Bitcoin SV P2P message handling with serialization/deserialization.
use crate::messages::{
    addr::Addr, block::Block, block_locator::BlockLocator, fee_filter::FeeFilter,
    filter_add::FilterAdd, filter_load::FilterLoad, headers::Headers, inv::Inv,
    merkle_block::MerkleBlock, message_header::MessageHeader, ping::Ping, reject::Reject,
    send_cmpct::SendCmpct, tx::Tx, version::Version,
};
use crate::util::{Error, Result, Serializable};
use bitcoin_hashes::sha256d as bh_sha256d;
use std::fmt;
use std::io;
use std::io::{Cursor, Read, Write};
#[cfg(feature = "async")]
use tokio::io::{AsyncRead, AsyncWrite};
/// Checksum to use when there is an empty payload.
pub const NO_CHECKSUM: [u8; 4] = [0x5d, 0xf6, 0xe0, 0xe2];
/// Max message payload size (4GB for BSV post-Genesis).
pub const MAX_PAYLOAD_SIZE: u64 = 0x100000000; // 4GB
/// Enum representing Bitcoin P2P messages.
#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    /// Address message (node addresses).
    Addr(Addr),
    /// Block message (full block data).
    Block(Block),
    /// Fee filter message (min fee threshold).
    FeeFilter(FeeFilter),
    /// Filter add message (add data to bloom filter).
    FilterAdd(FilterAdd),
    /// Filter clear message (clear bloom filter).
    FilterClear,
    /// Filter load message (load new bloom filter).
    FilterLoad(FilterLoad),
    /// Get address message (request peer addresses).
    GetAddr,
    /// Get blocks message (request blocks by locator).
    GetBlocks(BlockLocator),
    /// Get data message (request inventory items).
    GetData(Inv),
    /// Get headers message (request block headers).
    GetHeaders(BlockLocator),
    /// Headers message (block headers).
    Headers(Headers),
    /// Inventory message (announce data).
    Inv(Inv),
    /// Mempool message (request mempool contents).
    Mempool,
    /// Merkle block message (filtered block).
    MerkleBlock(MerkleBlock),
    /// Not found message (response to getdata).
    NotFound(Inv),
    /// Other/unknown message type.
    Other(String),
    /// Partial message (header only).
    Partial(MessageHeader),
    /// Ping message (keep-alive).
    Ping(Ping),
    /// Pong message (ping response).
    Pong(Ping),
    /// Reject message (error response).
    Reject(Reject),
    /// Send headers message (prefer headers over blocks).
    SendHeaders,
    /// Send compact message (announce compact blocks).
    SendCmpct(SendCmpct),
    /// Transaction message (full tx).
    Tx(Tx),
    /// Verack message (version ack).
    Verack,
    /// Version message (protocol handshake).
    Version(Version),
}
#[derive(Default, PartialEq, Eq, Hash, Clone)]
struct FilterClear;
impl Serializable<FilterClear> for FilterClear {
    fn read(_: &mut dyn Read) -> Result<FilterClear> {
        Ok(FilterClear)
    }
    fn write(&self, _: &mut dyn Write) -> io::Result<()> {
        Ok(())
    }
}
#[derive(Default, PartialEq, Eq, Hash, Clone)]
struct GetAddr;
impl Serializable<GetAddr> for GetAddr {
    fn read(_: &mut dyn Read) -> Result<GetAddr> {
        Ok(GetAddr)
    }
    fn write(&self, _: &mut dyn Write) -> io::Result<()> {
        Ok(())
    }
}
#[derive(Default, PartialEq, Eq, Hash, Clone)]
struct Mempool;
impl Serializable<Mempool> for Mempool {
    fn read(_: &mut dyn Read) -> Result<Mempool> {
        Ok(Mempool)
    }
    fn write(&self, _: &mut dyn Write) -> io::Result<()> {
        Ok(())
    }
}
#[derive(Default, PartialEq, Eq, Hash, Clone)]
struct SendHeaders;
impl Serializable<SendHeaders> for SendHeaders {
    fn read(_: &mut dyn Read) -> Result<SendHeaders> {
        Ok(SendHeaders)
    }
    fn write(&self, _: &mut dyn Write) -> io::Result<()> {
        Ok(())
    }
}
#[derive(Default, PartialEq, Eq, Hash, Clone)]
struct Verack;
impl Serializable<Verack> for Verack {
    fn read(_: &mut dyn Read) -> Result<Verack> {
        Ok(Verack)
    }
    fn write(&self, _: &mut dyn Write) -> io::Result<()> {
        Ok(())
    }
}
/// Command strings as [u8; 12], padded with \0.
pub mod commands {
    pub const ADDR: [u8; 12] = *b"addr\0\0\0\0\0\0\0\0";
    pub const BLOCK: [u8; 12] = *b"block\0\0\0\0\0\0\0";
    pub const FEEFILTER: [u8; 12] = *b"feefilter\0\0\0";
    pub const FILTERADD: [u8; 12] = *b"filteradd\0\0\0";
    pub const FILTERCLEAR: [u8; 12] = *b"filterclear\0";
    pub const FILTERLOAD: [u8; 12] = *b"filterload\0\0";
    pub const GETADDR: [u8; 12] = *b"getaddr\0\0\0\0\0";
    pub const GETBLOCKS: [u8; 12] = *b"getblocks\0\0\0";
    pub const GETDATA: [u8; 12] = *b"getdata\0\0\0\0\0";
    pub const GETHEADERS: [u8; 12] = *b"getheaders\0\0";
    pub const HEADERS: [u8; 12] = *b"headers\0\0\0\0\0";
    pub const INV: [u8; 12] = *b"inv\0\0\0\0\0\0\0\0\0";
    pub const MEMPOOL: [u8; 12] = *b"mempool\0\0\0\0\0";
    pub const MERKLEBLOCK: [u8; 12] = *b"merkleblock\0";
    pub const NOTFOUND: [u8; 12] = *b"notfound\0\0\0\0";
    pub const PING: [u8; 12] = *b"ping\0\0\0\0\0\0\0\0";
    pub const PONG: [u8; 12] = *b"pong\0\0\0\0\0\0\0\0";
    pub const REJECT: [u8; 12] = *b"reject\0\0\0\0\0\0";
    pub const SENDCMPCT: [u8; 12] = *b"sendcmpct\0\0\0";
    pub const SENDHEADERS: [u8; 12] = *b"sendheaders\0";
    pub const TX: [u8; 12] = *b"tx\0\0\0\0\0\0\0\0\0\0";
    pub const VERACK: [u8; 12] = *b"verack\0\0\0\0\0\0";
    pub const VERSION: [u8; 12] = *b"version\0\0\0\0\0";
}
impl Message {
    /// Reads a Bitcoin P2P message with its payload from bytes.
    ///
    /// # Errors
    /// IO errors, invalid magic, payload too large, or invalid payload data.
    ///
    /// Returns `Message::Partial` if payload read times out (use `read_partial` to complete).
    pub fn read(reader: &mut dyn Read, magic: [u8; 4]) -> Result<Self> {
        let header = MessageHeader::read(reader)?;
        header.validate(magic, MAX_PAYLOAD_SIZE)?;
        match Self::read_partial(reader, &header) {
            Ok(msg) => Ok(msg),
            Err(e) => {
                if let Error::IOError(e) = &e {
                    if e.kind() == io::ErrorKind::TimedOut || e.kind() == io::ErrorKind::WouldBlock {
                        return Ok(Message::Partial(header));
                    }
                }
                Err(e)
            }
        }
    }
    /// Reads the complete message given a message header.
    ///
    /// # Errors
    /// IO errors or invalid payload data.
    pub fn read_partial(reader: &mut dyn Read, header: &MessageHeader) -> Result<Self> {
        macro_rules! read_payload {
            ($cmd:expr, $type:ty) => {
                if header.command == $cmd {
                    let payload = header.payload(reader)?;
                    return Ok(<$type>::read(&mut Cursor::new(payload))?.into());
                }
            };
            ($cmd:expr, $type:ty, validate) => {
                if header.command == $cmd {
                    let payload = header.payload(reader)?;
                    let item = <$type>::read(&mut Cursor::new(payload))?;
                    item.validate()?;
                    return Ok(item.into());
                }
            };
            ($cmd:expr, $variant:ident) => {
                if header.command == $cmd {
                    if header.payload_size != 0 {
                        return Err(Error::BadData("Bad payload".to_string()));
                    }
                    return Ok(Message::$variant);
                }
            };
        }
        read_payload!(commands::ADDR, Addr);
        read_payload!(commands::BLOCK, Block);
        read_payload!(commands::FEEFILTER, FeeFilter);
        read_payload!(commands::FILTERADD, FilterAdd, validate);
        read_payload!(commands::FILTERCLEAR, FilterClear);
        read_payload!(commands::FILTERLOAD, FilterLoad, validate);
        read_payload!(commands::GETADDR, GetAddr);
        read_payload!(commands::GETBLOCKS, BlockLocator);
        if header.command == commands::GETDATA {
            let payload = header.payload(reader)?;
            return Ok(Message::GetData(Inv::read(&mut Cursor::new(payload))?));
        }
        if header.command == commands::GETHEADERS {
            let payload = header.payload(reader)?;
            return Ok(Message::GetHeaders(BlockLocator::read(&mut Cursor::new(payload))?));
        }
        read_payload!(commands::HEADERS, Headers);
        read_payload!(commands::INV, Inv);
        read_payload!(commands::MEMPOOL, Mempool);
        read_payload!(commands::MERKLEBLOCK, MerkleBlock);
        if header.command == commands::NOTFOUND {
            let payload = header.payload(reader)?;
            return Ok(Message::NotFound(Inv::read(&mut Cursor::new(payload))?));
        }
        read_payload!(commands::PING, Ping);
        if header.command == commands::PONG {
            let payload = header.payload(reader)?;
            return Ok(Message::Pong(Ping::read(&mut Cursor::new(payload))?));
        }
        read_payload!(commands::REJECT, Reject);
        read_payload!(commands::SENDCMPCT, SendCmpct);
        read_payload!(commands::SENDHEADERS, SendHeaders);
        read_payload!(commands::TX, Tx);
        read_payload!(commands::VERACK, Verack);
        read_payload!(commands::VERSION, Version, validate);
        if header.payload_size > 0 {
            header.payload(reader)?;
        }
        let command = String::from_utf8(header.command.to_vec())
            .map_err(|_| Error::BadData("Invalid command string".to_string()))?;
        Ok(Message::Other(command))
    }
    /// Writes a Bitcoin P2P message with its payload to bytes.
    ///
    /// # Errors
    /// IO errors or if message is `Other` or `Partial`.
    pub fn write(&self, writer: &mut dyn Write, magic: [u8; 4]) -> io::Result<()> {
        macro_rules! write_payload {
            ($cmd:expr, $payload:expr) => {
                write_with_payload(writer, $cmd, $payload, magic)
            };
            ($cmd:expr) => {
                write_without_payload(writer, $cmd, magic)
            };
        }
        match self {
            Message::Addr(p) => write_payload!(commands::ADDR, p),
            Message::Block(p) => write_payload!(commands::BLOCK, p),
            Message::FeeFilter(p) => write_payload!(commands::FEEFILTER, p),
            Message::FilterAdd(p) => write_payload!(commands::FILTERADD, p),
            Message::FilterClear => write_payload!(commands::FILTERCLEAR),
            Message::FilterLoad(p) => write_payload!(commands::FILTERLOAD, p),
            Message::GetAddr => write_payload!(commands::GETADDR),
            Message::GetBlocks(p) => write_payload!(commands::GETBLOCKS, p),
            Message::GetData(p) => write_payload!(commands::GETDATA, p),
            Message::GetHeaders(p) => write_payload!(commands::GETHEADERS, p),
            Message::Headers(p) => write_payload!(commands::HEADERS, p),
            Message::Inv(p) => write_payload!(commands::INV, p),
            Message::Mempool => write_payload!(commands::MEMPOOL),
            Message::MerkleBlock(p) => write_payload!(commands::MERKLEBLOCK, p),
            Message::NotFound(p) => write_payload!(commands::NOTFOUND, p),
            Message::Other(s) => Err(io::Error::new(io::ErrorKind::InvalidData, s.as_str())),
            Message::Partial(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Cannot write partial message",
            )),
            Message::Ping(p) => write_payload!(commands::PING, p),
            Message::Pong(p) => write_payload!(commands::PONG, p),
            Message::Reject(p) => write_payload!(commands::REJECT, p),
            Message::SendHeaders => write_payload!(commands::SENDHEADERS),
            Message::SendCmpct(p) => write_payload!(commands::SENDCMPCT, p),
            Message::Tx(p) => write_payload!(commands::TX, p),
            Message::Verack => write_payload!(commands::VERACK),
            Message::Version(v) => write_payload!(commands::VERSION, v),
        }
    }
    #[cfg(feature = "async")]
    async fn write_async(&self, writer: &mut dyn AsyncWrite, magic: [u8; 4]) -> io::Result<()> {
        macro_rules! write_payload {
            ($cmd:expr, $payload:expr) => {
                write_with_payload_async(writer, $cmd, $payload, magic).await
            };
            ($cmd:expr) => {
                write_without_payload_async(writer, $cmd, magic).await
            };
        }
        match self {
            Message::Addr(p) => write_payload!(commands::ADDR, p),
            Message::Block(p) => write_payload!(commands::BLOCK, p),
            Message::FeeFilter(p) => write_payload!(commands::FEEFILTER, p),
            Message::FilterAdd(p) => write_payload!(commands::FILTERADD, p),
            Message::FilterClear => write_payload!(commands::FILTERCLEAR),
            Message::FilterLoad(p) => write_payload!(commands::FILTERLOAD, p),
            Message::GetAddr => write_payload!(commands::GETADDR),
            Message::GetBlocks(p) => write_payload!(commands::GETBLOCKS, p),
            Message::GetData(p) => write_payload!(commands::GETDATA, p),
            Message::GetHeaders(p) => write_payload!(commands::GETHEADERS, p),
            Message::Headers(p) => write_payload!(commands::HEADERS, p),
            Message::Inv(p) => write_payload!(commands::INV, p),
            Message::Mempool => write_payload!(commands::MEMPOOL),
            Message::MerkleBlock(p) => write_payload!(commands::MERKLEBLOCK, p),
            Message::NotFound(p) => write_payload!(commands::NOTFOUND, p),
            Message::Other(s) => Err(io::Error::new(io::ErrorKind::InvalidData, s.as_str())),
            Message::Partial(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Cannot write partial message",
            )),
            Message::Ping(p) => write_payload!(commands::PING, p),
            Message::Pong(p) => write_payload!(commands::PONG, p),
            Message::Reject(p) => write_payload!(commands::REJECT, p),
            Message::SendHeaders => write_payload!(commands::SENDHEADERS),
            Message::SendCmpct(p) => write_payload!(commands::SENDCMPCT, p),
            Message::Tx(p) => write_payload!(commands::TX, p),
            Message::Verack => write_payload!(commands::VERACK),
            Message::Version(v) => write_payload!(commands::VERSION, v),
        }
    }
}
fn write_without_payload(writer: &mut dyn Write, command: [u8; 12], magic: [u8; 4]) -> io::Result<()> {
    let header = MessageHeader {
        magic,
        command,
        payload_size: 0,
        checksum: NO_CHECKSUM,
    };
    header.write(writer)
}
fn write_with_payload<T: Serializable<T>>(
    writer: &mut dyn Write,
    command: [u8; 12],
    payload: &dyn Payload<T>,
    magic: [u8; 4],
) -> io::Result<()> {
    let mut bytes = Vec::with_capacity(payload.size());
    payload.write(&mut bytes)?;
    let hash = bh_sha256d::Hash::hash(&bytes).to_byte_array();
    let checksum = [hash[0], hash[1], hash[2], hash[3]];
    let header = MessageHeader {
        magic,
        command,
        payload_size: payload.size() as u32,
        checksum,
    };
    header.write(writer)?;
    writer.write_all(&bytes)
}
#[cfg(feature = "async")]
async fn write_without_payload_async(
    writer: &mut dyn AsyncWrite,
    command: [u8; 12],
    magic: [u8; 4],
) -> io::Result<()> {
    let header = MessageHeader {
        magic,
        command,
        payload_size: 0,
        checksum: NO_CHECKSUM,
    };
    header.write_async(writer).await
}
#[cfg(feature = "async")]
async fn write_with_payload_async<T: Serializable<T>>(
    writer: &mut dyn AsyncWrite,
    command: [u8; 12],
    payload: &dyn Payload<T>,
    magic: [u8; 4],
) -> io::Result<()> {
    let mut bytes = Vec::with_capacity(payload.size());
    payload.write(&mut bytes)?;
    let hash = bh_sha256d::Hash::hash(&bytes).to_byte_array();
    let checksum = [hash[0], hash[1], hash[2], hash[3]];
    let header = MessageHeader {
        magic,
        command,
        payload_size: payload.size() as u32,
        checksum,
    };
    header.write_async(writer).await?;
    writer.write_all(&bytes).await
}
/// Message payload that is writable to bytes.
pub trait Payload<T>: Serializable<T> + fmt::Debug {
/// Returns the serialized size of the message in bytes.
fn size(&self) -> usize;
}
impl From<Addr> for Message {
    fn from(p: Addr) -> Self {
        Message::Addr(p)
    }
}
impl From<Block> for Message {
    fn from(p: Block) -> Self {
        Message::Block(p)
    }
}
impl From<FeeFilter> for Message {
    fn from(p: FeeFilter) -> Self {
        Message::FeeFilter(p)
    }
}
impl From<FilterAdd> for Message {
    fn from(p: FilterAdd) -> Self {
        Message::FilterAdd(p)
    }
}
impl From<FilterClear> for Message {
    fn from(_: FilterClear) -> Self {
        Message::FilterClear
    }
}
impl From<FilterLoad> for Message {
    fn from(p: FilterLoad) -> Self {
        Message::FilterLoad(p)
    }
}
impl From<BlockLocator> for Message {
    fn from(p: BlockLocator) -> Self {
        Message::GetBlocks(p)
    }
}
impl From<Inv> for Message {
    fn from(p: Inv) -> Self {
        Message::Inv(p)
    }
}
impl From<Headers> for Message {
    fn from(p: Headers) -> Self {
        Message::Headers(p)
    }
}
impl From<MerkleBlock> for Message {
    fn from(p: MerkleBlock) -> Self {
        Message::MerkleBlock(p)
    }
}
impl From<GetAddr> for Message {
    fn from(_: GetAddr) -> Self {
        Message::GetAddr
    }
}
impl From<Mempool> for Message {
    fn from(_: Mempool) -> Self {
        Message::Mempool
    }
}
impl From<Ping> for Message {
    fn from(p: Ping) -> Self {
        Message::Ping(p)
    }
}
impl From<Reject> for Message {
    fn from(p: Reject) -> Self {
        Message::Reject(p)
    }
}
impl From<SendCmpct> for Message {
    fn from(p: SendCmpct) -> Self {
        Message::SendCmpct(p)
    }
}
impl From<SendHeaders> for Message {
    fn from(_: SendHeaders) -> Self {
        Message::SendHeaders
    }
}
impl From<Tx> for Message {
    fn from(p: Tx) -> Self {
        Message::Tx(p)
    }
}
impl From<Verack> for Message {
    fn from(_: Verack) -> Self {
        Message::Verack
    }
}
impl From<Version> for Message {
    fn from(p: Version) -> Self {
        Message::Version(p)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::{BlockHeader, InvVect, INV_VECT_TX, MIN_SUPPORTED_PROTOCOL_VERSION,
    NodeAddr, NodeAddrEx, OutPoint, TxIn, TxOut, REJECT_INVALID};
    use crate::script::Script;
    use crate::util::{secs_since, BloomFilter, Hash256};
    use std::io::Cursor;
    use std::net::Ipv6Addr;
    use std::time::UNIX_EPOCH;
    use pretty_assertions::assert_eq;
    #[test]
    fn write_read() {
        let magic = [7, 8, 9, 0];
        // Addr
        let mut v = Vec::new();
        let a = NodeAddrEx {
            last_connected_time: 700,
            addr: NodeAddr {
                services: 900,
                ip: Ipv6Addr::from([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 9, 8, 7, 6, 5]),
                port: 4000,
            },
        };
        let p = Addr { addrs: vec![a] };
        let m = Message::Addr(p);
        m.write(&mut v, magic).unwrap();
        assert_eq!(Message::read(&mut Cursor::new(&v), magic).unwrap(), m);
        // Block
        let mut v = Vec::new();
        let p = Block {
            header: BlockHeader {
                version: 0x00000001,
                prev_hash: Hash256::decode(
                    "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
                ).unwrap(),
                merkle_root: Hash256::decode(
                    "2b12fcf1b09288fcaff797d71e950e71ae42b91e8bdb2304758dfcffc2b620e3",
                ).unwrap(),
                timestamp: 0x4dd7f5c7,
                bits: 0x1a44b9f2,
                nonce: 0x9546a142,
            },
            txns: vec![
                Tx {
                    version: 0x44556677,
                    inputs: vec![TxIn {
                        prev_output: OutPoint {
                            hash: Hash256([5; 32]),
                            index: 3,
                        },
                        unlock_script: Script(vec![5; 5]),
                        sequence: 2,
                    }],
                    outputs: vec![TxOut {
                        satoshis: 42,
                        lock_script: Script(vec![9; 21]),
                    }],
                    lock_time: 0x12ff34aa,
                },
                Tx {
                    version: 0x99881122,
                    inputs: vec![TxIn {
                        prev_output: OutPoint {
                            hash: Hash256([6; 32]),
                            index: 4,
                        },
                        unlock_script: Script(vec![4; 4]),
                        sequence: 3,
                    }],
                    outputs: vec![TxOut {
                        satoshis: 43,
                        lock_script: Script(vec![10; 22]),
                    }],
                    lock_time: 0x44550011,
                },
            ],
        };
        let m = Message::Block(p);
        m.write(&mut v, magic).unwrap();
        assert_eq!(Message::read(&mut Cursor::new(&v), magic).unwrap(), m);
        // FeeFilter
        let mut v = Vec::new();
        let p = FeeFilter { minfee: 1234 };
        let m = Message::FeeFilter(p);
        m.write(&mut v, magic).unwrap();
        assert_eq!(Message::read(&mut Cursor::new(&v), magic).unwrap(), m);
        // FilterAdd
        let mut v = Vec::new();
        let p = FilterAdd { data: vec![15; 45] };
        let m = Message::FilterAdd(p);
        m.write(&mut v, magic).unwrap();
        assert_eq!(Message::read(&mut Cursor::new(&v), magic).unwrap(), m);
        // FilterClear
        let mut v = Vec::new();
        let m = Message::FilterClear;
        m.write(&mut v, magic).unwrap();
        assert_eq!(Message::read(&mut Cursor::new(&v), magic).unwrap(), m);
        // FilterLoad
        let mut v = Vec::new();
        let p = FilterLoad {
            bloom_filter: BloomFilter {
                filter: vec![1, 2, 3],
                num_hash_funcs: 2,
                tweak: 1,
            },
            flags: 0,
        };
        let m = Message::FilterLoad(p);
        m.write(&mut v, magic).unwrap();
        assert_eq!(Message::read(&mut Cursor::new(&v), magic).unwrap(), m);
        // GetAddr
        let mut v = Vec::new();
        let m = Message::GetAddr;
        m.write(&mut v, magic).unwrap();
        assert_eq!(Message::read(&mut Cursor::new(&v), magic).unwrap(), m);
        // GetBlocks
        let mut v = Vec::new();
        let p = BlockLocator {
            version: 567,
            block_locator_hashes: vec![Hash256([3; 32]), Hash256([4; 32])],
            hash_stop: Hash256([6; 32]),
        };
        let m = Message::GetBlocks(p);
        m.write(&mut v, magic).unwrap();
        assert_eq!(Message::read(&mut Cursor::new(&v), magic).unwrap(), m);
        // GetData
        let mut v = Vec::new();
        let p = Inv {
            objects: vec![InvVect {
                obj_type: INV_VECT_TX,
                hash: Hash256([0; 32]),
            }],
        };
        let m = Message::GetData(p);
        m.write(&mut v, magic).unwrap();
        assert_eq!(Message::read(&mut Cursor::new(&v), magic).unwrap(), m);
        // GetHeaders
        let mut v = Vec::new();
        let p = BlockLocator {
            version: 345,
            block_locator_hashes: vec![Hash256([1; 32]), Hash256([2; 32])],
            hash_stop: Hash256([3; 32]),
        };
        let m = Message::GetHeaders(p);
        m.write(&mut v, magic).unwrap();
        assert_eq!(Message::read(&mut Cursor::new(&v), magic).unwrap(), m);
        // Headers
        let mut v = Vec::new();
        let p = Headers {
            headers: vec![BlockHeader {
                ..Default::default()
            }],
        };
        let m = Message::Headers(p);
        m.write(&mut v, magic).unwrap();
        assert_eq!(Message::read(&mut Cursor::new(&v), magic).unwrap(), m);
        // Mempool
        let mut v = Vec::new();
        let m = Message::Mempool;
        m.write(&mut v, magic).unwrap();
        assert_eq!(Message::read(&mut Cursor::new(&v), magic).unwrap(), m);
        // MerkleBlock
        let mut v = Vec::new();
        let p = MerkleBlock {
            header: BlockHeader {
                version: 12345,
                prev_hash: Hash256::decode(
                    "7766009988776600998877660099887766009988776600998877660099887766",
                ).unwrap(),
                merkle_root: Hash256::decode(
                    "2211554433221155443322115544332211554433221155443322115544332211",
                ).unwrap(),
                timestamp: 66,
                bits: 4488,
                nonce: 9999,
            },
            total_transactions: 14,
            hashes: vec![Hash256([1; 32]), Hash256([3; 32]), Hash256([5; 32])],
            flags: vec![24, 125, 199],
        };
        let m = Message::MerkleBlock(p);
        m.write(&mut v, magic).unwrap();
        assert_eq!(Message::read(&mut Cursor::new(&v), magic).unwrap(), m);
        // NotFound
        let mut v = Vec::new();
        let p = Inv {
            objects: vec![InvVect {
                obj_type: INV_VECT_TX,
                hash: Hash256([0; 32]),
            }],
        };
        let m = Message::NotFound(p);
        m.write(&mut v, magic).unwrap();
        assert_eq!(Message::read(&mut Cursor::new(&v), magic).unwrap(), m);
        // Inv
        let mut v = Vec::new();
        let p = Inv {
            objects: vec![InvVect {
                obj_type: INV_VECT_TX,
                hash: Hash256([0; 32]),
            }],
        };
        let m = Message::Inv(p);
        m.write(&mut v, magic).unwrap();
        assert_eq!(Message::read(&mut Cursor::new(&v), magic).unwrap(), m);
        // Ping
        let mut v = Vec::new();
        let p = Ping { nonce: 7890 };
        let m = Message::Ping(p);
        m.write(&mut v, magic).unwrap();
        assert_eq!(Message::read(&mut Cursor::new(&v), magic).unwrap(), m);
        // Pong
        let mut v = Vec::new();
        let p = Ping { nonce: 7890 };
        let m = Message::Pong(p);
        m.write(&mut v, magic).unwrap();
        assert_eq!(Message::read(&mut Cursor::new(&v), magic).unwrap(), m);
        // Reject
        let mut v = Vec::new();
        let p = Reject {
            message: "getaddr".to_string(),
            code: REJECT_INVALID,
            reason: "womp womp".to_string(),
            data: vec![],
        };
        let m = Message::Reject(p);
        m.write(&mut v, magic).unwrap();
        assert_eq!(Message::read(&mut Cursor::new(&v), magic).unwrap(), m);
        // SendHeaders
        let mut v = Vec::new();
        let m = Message::SendHeaders;
        m.write(&mut v, magic).unwrap();
        assert_eq!(Message::read(&mut Cursor::new(&v), magic).unwrap(), m);
        // SendCmpct
        let mut v = Vec::new();
        let p = SendCmpct { enable: 1, version: 1 };
        let m = Message::SendCmpct(p);
        m.write(&mut v, magic).unwrap();
        assert_eq!(Message::read(&mut Cursor::new(&v), magic).unwrap(), m);
        // Tx
        let mut v = Vec::new();
        let p = Tx {
            version: 0x44556677,
            inputs: vec![TxIn {
                prev_output: OutPoint {
                    hash: Hash256([5; 32]),
                    index: 3,
                },
                unlock_script: Script(vec![7; 7]),
                sequence: 2,
            }],
            outputs: vec![TxOut {
                satoshis: 42,
                lock_script: Script(vec![8; 8]),
            }],
            lock_time: 0x12ff34aa,
        };
        let m = Message::Tx(p);
        m.write(&mut v, magic).unwrap();
        assert_eq!(Message::read(&mut Cursor::new(&v), magic).unwrap(), m);
        // Verack
        let mut v = Vec::new();
        let m = Message::Verack;
        m.write(&mut v, magic).unwrap();
        assert_eq!(Message::read(&mut Cursor::new(&v), magic).unwrap(), m);
        // Version
        let mut v = Vec::new();
        let p = Version {
            version: MIN_SUPPORTED_PROTOCOL_VERSION,
            services: 77,
            timestamp: secs_since(UNIX_EPOCH) as i64,
            recv_addr: NodeAddr::default(),
            tx_addr: NodeAddr::default(),
            nonce: 99,
            user_agent: "dummy".to_string(),
            start_height: 22,
            relay: true,
        };
        let m = Message::Version(p);
        m.write(&mut v, magic).unwrap();
        assert_eq!(Message::read(&mut Cursor::new(&v), magic).unwrap(), m);
    }
    #[test]
    fn write_other_errors() {
        let mut v = Vec::new();
        let m = Message::Other("Unknown message".to_string());
        assert!(m.write(&mut v, [7, 8, 9, 0]).is_err());
    }
    #[test]
    fn read_other() {
        let magic = [7, 8, 9, 0];
        let command = *b"unknowncmd\0\0";
        let header = MessageHeader {
            magic,
            command,
            payload_size: 0,
            checksum: NO_CHECKSUM,
        };
        let mut v = Vec::new();
        header.write(&mut v).unwrap();
        let m = Message::read(&mut Cursor::new(&v), magic).unwrap();
        assert!(matches!(m, Message::Other(_)));
    }
}

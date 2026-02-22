//! Bitcoin P2P Wire Protocol
//!
//! Pure domain-layer implementation of the Bitcoin peer-to-peer network protocol.
//! This module provides I/O-free serialization and deserialization of all Bitcoin
//! P2P messages, suitable for use with any transport (TCP, in-memory, etc.).
//!
//! ## Architecture
//!
//! - `types` — Service flags, inventory types, network addresses, protocol constants
//! - `messages` — Complete `NetworkMessage` enum with all P2P message variants
//! - `codec` — Wire-format encoding/decoding: message headers, payloads, checksums
//!
//! ## Protocol Coverage
//!
//! Handshake: version, verack
//! Feature negotiation: wtxidrelay (BIP339), sendheaders (BIP130),
//!   sendcmpct (BIP152), feefilter (BIP133), sendaddrv2 (BIP155)
//! Address relay: addr, addrv2 (BIP155), getaddr
//! Inventory: inv, getdata, notfound
//! Block relay: block, headers, getheaders, getblocks
//! Transaction relay: tx, mempool
//! Compact blocks (BIP152): cmpctblock, getblocktxn, blocktxn
//! Keepalive: ping, pong

pub mod codec;
pub mod messages;
pub mod types;

// Re-export key types
pub use codec::{
    compute_checksum, decode_compact_size, decode_message, decode_payload, encode_compact_size,
    encode_message, encode_payload, push_compact_size, verify_checksum, CodecError, MessageHeader,
    HEADER_SIZE,
};
pub use messages::{
    AddrV2Entry, BlockTxnMessage, CmpctBlockMessage, GetBlockTxnMessage, GetBlocksMessage,
    GetHeadersMessage, NetworkMessage, PrefilledTx, SendCmpctMessage, TimestampedAddress,
    VersionMessage,
};
pub use types::{
    InvType, InvVector, NetAddress, ServiceFlags, MAX_HEADERS, MAX_INV_SIZE,
    MAX_PROTOCOL_MESSAGE_LENGTH, MIN_PEER_PROTO_VERSION, PROTOCOL_VERSION, USER_AGENT,
};

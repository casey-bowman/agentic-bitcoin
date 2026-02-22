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

pub mod types;
pub mod messages;
pub mod codec;

// Re-export key types
pub use types::{
    ServiceFlags, InvType, InvVector, NetAddress,
    PROTOCOL_VERSION, MIN_PEER_PROTO_VERSION, MAX_PROTOCOL_MESSAGE_LENGTH,
    MAX_HEADERS, MAX_INV_SIZE, USER_AGENT,
};
pub use messages::{
    NetworkMessage, VersionMessage, TimestampedAddress, AddrV2Entry,
    GetHeadersMessage, GetBlocksMessage, SendCmpctMessage,
    CmpctBlockMessage, PrefilledTx, GetBlockTxnMessage, BlockTxnMessage,
};
pub use codec::{
    CodecError, MessageHeader, HEADER_SIZE,
    encode_message, decode_message, encode_payload, decode_payload,
    compute_checksum, verify_checksum,
    encode_compact_size, decode_compact_size, push_compact_size,
};

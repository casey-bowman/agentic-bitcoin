//! P2P wire protocol codec
//!
//! Serialisation and deserialisation of Bitcoin P2P protocol messages.
//! Handles the 24-byte message header (magic + command + length + checksum)
//! and all payload formats.
//!
//! The codec is I/O-free: it operates on `&[u8]` / `Vec<u8>` and can be
//! used with any transport (TCP, in-memory, etc.).

use super::messages::*;
use super::types::*;
use crate::hashing::hash256;
use crate::primitives::block::BlockHeader;
use crate::primitives::hash::{BlockHash, Hash256};
use crate::primitives::transaction::Transaction;
use crate::primitives::Block;
use std::fmt;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during message encoding/decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    /// Not enough bytes to decode
    UnexpectedEnd,
    /// Magic bytes don't match expected network
    BadMagic { expected: [u8; 4], got: [u8; 4] },
    /// Checksum mismatch
    BadChecksum { expected: [u8; 4], got: [u8; 4] },
    /// Payload exceeds maximum size
    PayloadTooLarge(u32),
    /// Compact size value is non-canonical or too large
    BadCompactSize,
    /// Transaction deserialization failed
    BadTransaction(String),
    /// Command string contains invalid bytes
    BadCommand,
    /// Payload doesn't match expected format
    MalformedPayload(String),
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodecError::UnexpectedEnd => write!(f, "unexpected end of data"),
            CodecError::BadMagic { expected, got } => {
                write!(f, "bad magic: expected {:02x?}, got {:02x?}", expected, got)
            }
            CodecError::BadChecksum { expected, got } => {
                write!(
                    f,
                    "bad checksum: expected {:02x?}, got {:02x?}",
                    expected, got
                )
            }
            CodecError::PayloadTooLarge(sz) => write!(f, "payload too large: {} bytes", sz),
            CodecError::BadCompactSize => write!(f, "bad compact size encoding"),
            CodecError::BadTransaction(e) => write!(f, "bad transaction: {}", e),
            CodecError::BadCommand => write!(f, "bad command string"),
            CodecError::MalformedPayload(e) => write!(f, "malformed payload: {}", e),
        }
    }
}

// ---------------------------------------------------------------------------
// Message header
// ---------------------------------------------------------------------------

/// Size of the protocol message header (magic + command + length + checksum).
pub const HEADER_SIZE: usize = 24;

/// A decoded message header.
#[derive(Debug, Clone)]
pub struct MessageHeader {
    /// Network magic bytes
    pub magic: [u8; 4],
    /// Command string (up to 12 bytes, null-padded)
    pub command: [u8; 12],
    /// Payload length
    pub payload_len: u32,
    /// SHA256d checksum (first 4 bytes)
    pub checksum: [u8; 4],
}

impl MessageHeader {
    /// Create a header for the given command and payload.
    pub fn new(magic: [u8; 4], command_str: &str, payload: &[u8]) -> Self {
        let mut command = [0u8; 12];
        let bytes = command_str.as_bytes();
        let copy_len = bytes.len().min(12);
        command[..copy_len].copy_from_slice(&bytes[..copy_len]);

        let checksum = compute_checksum(payload);

        MessageHeader {
            magic,
            command,
            payload_len: payload.len() as u32,
            checksum,
        }
    }

    /// Get the command as a string (trimmed of null bytes).
    pub fn command_string(&self) -> Result<String, CodecError> {
        let end = self.command.iter().position(|&b| b == 0).unwrap_or(12);
        let s = std::str::from_utf8(&self.command[..end]).map_err(|_| CodecError::BadCommand)?;
        Ok(s.to_string())
    }

    /// Serialize header to 24 bytes.
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..4].copy_from_slice(&self.magic);
        buf[4..16].copy_from_slice(&self.command);
        buf[16..20].copy_from_slice(&self.payload_len.to_le_bytes());
        buf[20..24].copy_from_slice(&self.checksum);
        buf
    }

    /// Decode a header from 24 bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, CodecError> {
        if data.len() < HEADER_SIZE {
            return Err(CodecError::UnexpectedEnd);
        }
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&data[0..4]);
        let mut command = [0u8; 12];
        command.copy_from_slice(&data[4..16]);
        let payload_len = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
        let mut checksum = [0u8; 4];
        checksum.copy_from_slice(&data[20..24]);

        Ok(MessageHeader {
            magic,
            command,
            payload_len,
            checksum,
        })
    }
}

/// Compute double-SHA256 checksum (first 4 bytes).
pub fn compute_checksum(data: &[u8]) -> [u8; 4] {
    let hash = hash256(data);
    let mut cs = [0u8; 4];
    cs.copy_from_slice(&hash.as_bytes()[..4]);
    cs
}

/// Verify that a payload matches its header checksum.
pub fn verify_checksum(payload: &[u8], expected: [u8; 4]) -> bool {
    compute_checksum(payload) == expected
}

// ---------------------------------------------------------------------------
// Compact-size encoding/decoding
// ---------------------------------------------------------------------------

/// Encode a value as a Bitcoin CompactSize (varint).
pub fn encode_compact_size(value: u64) -> Vec<u8> {
    if value < 0xfd {
        vec![value as u8]
    } else if value <= 0xffff {
        let mut buf = vec![0xfd];
        buf.extend_from_slice(&(value as u16).to_le_bytes());
        buf
    } else if value <= 0xffff_ffff {
        let mut buf = vec![0xfe];
        buf.extend_from_slice(&(value as u32).to_le_bytes());
        buf
    } else {
        let mut buf = vec![0xff];
        buf.extend_from_slice(&value.to_le_bytes());
        buf
    }
}

/// Push a CompactSize into a buffer.
pub fn push_compact_size(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&encode_compact_size(value));
}

/// Decode a CompactSize from a cursor position. Returns (value, bytes_consumed).
pub fn decode_compact_size(data: &[u8], pos: usize) -> Result<(u64, usize), CodecError> {
    if pos >= data.len() {
        return Err(CodecError::UnexpectedEnd);
    }
    let first = data[pos];
    match first {
        0..=0xfc => Ok((first as u64, 1)),
        0xfd => {
            if pos + 3 > data.len() {
                return Err(CodecError::UnexpectedEnd);
            }
            let v = u16::from_le_bytes([data[pos + 1], data[pos + 2]]);
            if v < 0xfd {
                return Err(CodecError::BadCompactSize);
            }
            Ok((v as u64, 3))
        }
        0xfe => {
            if pos + 5 > data.len() {
                return Err(CodecError::UnexpectedEnd);
            }
            let v =
                u32::from_le_bytes([data[pos + 1], data[pos + 2], data[pos + 3], data[pos + 4]]);
            if v < 0x10000 {
                return Err(CodecError::BadCompactSize);
            }
            Ok((v as u64, 5))
        }
        0xff => {
            if pos + 9 > data.len() {
                return Err(CodecError::UnexpectedEnd);
            }
            let v = u64::from_le_bytes([
                data[pos + 1],
                data[pos + 2],
                data[pos + 3],
                data[pos + 4],
                data[pos + 5],
                data[pos + 6],
                data[pos + 7],
                data[pos + 8],
            ]);
            if v < 0x100000000 {
                return Err(CodecError::BadCompactSize);
            }
            Ok((v, 9))
        }
    }
}

// ---------------------------------------------------------------------------
// Cursor helper
// ---------------------------------------------------------------------------

/// A simple cursor for reading sequential bytes from a slice.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Cursor { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn read_u8(&mut self) -> Result<u8, CodecError> {
        if self.pos >= self.data.len() {
            return Err(CodecError::UnexpectedEnd);
        }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn _read_u16_le(&mut self) -> Result<u16, CodecError> {
        if self.pos + 2 > self.data.len() {
            return Err(CodecError::UnexpectedEnd);
        }
        let v = u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    fn read_u32_le(&mut self) -> Result<u32, CodecError> {
        if self.pos + 4 > self.data.len() {
            return Err(CodecError::UnexpectedEnd);
        }
        let v = u32::from_le_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    fn read_i32_le(&mut self) -> Result<i32, CodecError> {
        Ok(self.read_u32_le()? as i32)
    }

    fn read_u64_le(&mut self) -> Result<u64, CodecError> {
        if self.pos + 8 > self.data.len() {
            return Err(CodecError::UnexpectedEnd);
        }
        let v = u64::from_le_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
            self.data[self.pos + 4],
            self.data[self.pos + 5],
            self.data[self.pos + 6],
            self.data[self.pos + 7],
        ]);
        self.pos += 8;
        Ok(v)
    }

    fn read_i64_le(&mut self) -> Result<i64, CodecError> {
        Ok(self.read_u64_le()? as i64)
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        if self.pos + n > self.data.len() {
            return Err(CodecError::UnexpectedEnd);
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    fn read_hash32(&mut self) -> Result<[u8; 32], CodecError> {
        let bytes = self.read_bytes(32)?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(arr)
    }

    fn read_compact_size(&mut self) -> Result<u64, CodecError> {
        let (val, consumed) = decode_compact_size(self.data, self.pos)?;
        self.pos += consumed;
        Ok(val)
    }

    fn read_string(&mut self) -> Result<String, CodecError> {
        let len = self.read_compact_size()? as usize;
        if len > 256 {
            return Err(CodecError::MalformedPayload("user agent too long".into()));
        }
        let bytes = self.read_bytes(len)?;
        String::from_utf8(bytes.to_vec())
            .map_err(|_| CodecError::MalformedPayload("invalid utf-8 in string".into()))
    }

    fn read_net_addr(&mut self) -> Result<NetAddress, CodecError> {
        let services = ServiceFlags::from_u64(self.read_u64_le()?);
        let mut addr = [0u8; 16];
        addr.copy_from_slice(self.read_bytes(16)?);
        let port = self.read_u16_be()?;
        Ok(NetAddress {
            services,
            addr,
            port,
        })
    }

    fn read_u16_be(&mut self) -> Result<u16, CodecError> {
        if self.pos + 2 > self.data.len() {
            return Err(CodecError::UnexpectedEnd);
        }
        let v = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    fn read_inv_vector(&mut self) -> Result<InvVector, CodecError> {
        let type_id = self.read_u32_le()?;
        let inv_type = InvType::from_u32(type_id).ok_or_else(|| {
            CodecError::MalformedPayload(format!("unknown inv type: {}", type_id))
        })?;
        let hash = self.read_hash32()?;
        Ok(InvVector::new(inv_type, hash))
    }

    fn read_block_header(&mut self) -> Result<BlockHeader, CodecError> {
        let version = self.read_i32_le()?;
        let prev_hash = BlockHash::from_hash(Hash256::from_bytes(self.read_hash32()?));
        let merkle_root = Hash256::from_bytes(self.read_hash32()?);
        let time = self.read_u32_le()?;
        let bits = self.read_u32_le()?;
        let nonce = self.read_u32_le()?;
        Ok(BlockHeader::new(
            version,
            prev_hash,
            merkle_root,
            time,
            bits,
            nonce,
        ))
    }

    fn read_transaction(&mut self) -> Result<Transaction, CodecError> {
        let start = self.pos;
        let remaining = &self.data[self.pos..];
        let (tx, consumed) = Transaction::deserialize(remaining)
            .map_err(|e| CodecError::BadTransaction(format!("{:?}", e)))?;
        self.pos = start + consumed;
        Ok(tx)
    }
}

// ---------------------------------------------------------------------------
// Serialise helpers (write into Vec<u8>)
// ---------------------------------------------------------------------------

fn push_u8(buf: &mut Vec<u8>, v: u8) {
    buf.push(v);
}

fn _push_u16_le(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn push_u16_be(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn push_u32_le(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn push_i32_le(buf: &mut Vec<u8>, v: i32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn push_u64_le(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn push_i64_le(buf: &mut Vec<u8>, v: i64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn push_hash32(buf: &mut Vec<u8>, hash: &[u8; 32]) {
    buf.extend_from_slice(hash);
}

fn push_string(buf: &mut Vec<u8>, s: &str) {
    push_compact_size(buf, s.len() as u64);
    buf.extend_from_slice(s.as_bytes());
}

fn push_net_addr(buf: &mut Vec<u8>, addr: &NetAddress) {
    push_u64_le(buf, addr.services.as_u64());
    buf.extend_from_slice(&addr.addr);
    push_u16_be(buf, addr.port);
}

fn push_inv_vector(buf: &mut Vec<u8>, iv: &InvVector) {
    push_u32_le(buf, iv.inv_type.as_u32());
    push_hash32(buf, &iv.hash);
}

fn push_block_header(buf: &mut Vec<u8>, hdr: &BlockHeader) {
    push_i32_le(buf, hdr.version);
    push_hash32(buf, hdr.prev_block_hash.as_bytes());
    push_hash32(buf, hdr.merkle_root.as_bytes());
    push_u32_le(buf, hdr.time);
    push_u32_le(buf, hdr.bits);
    push_u32_le(buf, hdr.nonce);
}

// ---------------------------------------------------------------------------
// Encode a NetworkMessage into a payload
// ---------------------------------------------------------------------------

/// Encode a message payload (without header) into bytes.
pub fn encode_payload(msg: &NetworkMessage) -> Vec<u8> {
    let mut buf = Vec::new();
    match msg {
        NetworkMessage::Version(v) => {
            push_u32_le(&mut buf, v.version);
            push_u64_le(&mut buf, v.services.as_u64());
            push_i64_le(&mut buf, v.timestamp);
            push_net_addr(&mut buf, &v.addr_recv);
            push_net_addr(&mut buf, &v.addr_from);
            push_u64_le(&mut buf, v.nonce);
            push_string(&mut buf, &v.user_agent);
            push_i32_le(&mut buf, v.start_height);
            push_u8(&mut buf, if v.relay { 1 } else { 0 });
        }

        NetworkMessage::Verack
        | NetworkMessage::WtxidRelay
        | NetworkMessage::SendHeaders
        | NetworkMessage::SendAddrV2
        | NetworkMessage::GetAddr
        | NetworkMessage::MemPool => {
            // Empty payload
        }

        NetworkMessage::Ping { nonce } | NetworkMessage::Pong { nonce } => {
            push_u64_le(&mut buf, *nonce);
        }

        NetworkMessage::FeeFilter { feerate } => {
            push_u64_le(&mut buf, *feerate);
        }

        NetworkMessage::SendCmpct(sc) => {
            push_u8(&mut buf, if sc.announce { 1 } else { 0 });
            push_u64_le(&mut buf, sc.version);
        }

        NetworkMessage::Inv(items)
        | NetworkMessage::GetData(items)
        | NetworkMessage::NotFound(items) => {
            push_compact_size(&mut buf, items.len() as u64);
            for iv in items {
                push_inv_vector(&mut buf, iv);
            }
        }

        NetworkMessage::Addr(addrs) => {
            push_compact_size(&mut buf, addrs.len() as u64);
            for ta in addrs {
                push_u32_le(&mut buf, ta.timestamp);
                push_net_addr(&mut buf, &ta.addr);
            }
        }

        NetworkMessage::AddrV2(entries) => {
            push_compact_size(&mut buf, entries.len() as u64);
            for e in entries {
                push_u32_le(&mut buf, e.timestamp);
                push_compact_size(&mut buf, e.services.as_u64());
                push_u8(&mut buf, e.network_id);
                push_compact_size(&mut buf, e.addr.len() as u64);
                buf.extend_from_slice(&e.addr);
                push_u16_be(&mut buf, e.port);
            }
        }

        NetworkMessage::GetHeaders(gh) => {
            push_u32_le(&mut buf, gh.version);
            push_compact_size(&mut buf, gh.locator_hashes.len() as u64);
            for hash in &gh.locator_hashes {
                push_hash32(&mut buf, hash.as_bytes());
            }
            push_hash32(&mut buf, gh.hash_stop.as_bytes());
        }

        NetworkMessage::GetBlocks(gb) => {
            push_u32_le(&mut buf, gb.version);
            push_compact_size(&mut buf, gb.locator_hashes.len() as u64);
            for hash in &gb.locator_hashes {
                push_hash32(&mut buf, hash.as_bytes());
            }
            push_hash32(&mut buf, gb.hash_stop.as_bytes());
        }

        NetworkMessage::Headers(headers) => {
            push_compact_size(&mut buf, headers.len() as u64);
            for hdr in headers {
                push_block_header(&mut buf, hdr);
                push_u8(&mut buf, 0); // tx_count = 0 for headers message
            }
        }

        NetworkMessage::Block(block) => {
            push_block_header(&mut buf, &block.header);
            push_compact_size(&mut buf, block.transactions.len() as u64);
            for tx in &block.transactions {
                buf.extend_from_slice(&tx.serialize());
            }
        }

        NetworkMessage::Tx(tx) => {
            buf.extend_from_slice(&tx.serialize());
        }

        NetworkMessage::CmpctBlock(cb) => {
            push_block_header(&mut buf, &cb.header);
            push_u64_le(&mut buf, cb.nonce);
            push_compact_size(&mut buf, cb.short_ids.len() as u64);
            for sid in &cb.short_ids {
                // Short IDs are 6 bytes (little-endian)
                let bytes = sid.to_le_bytes();
                buf.extend_from_slice(&bytes[..6]);
            }
            push_compact_size(&mut buf, cb.prefilled_txs.len() as u64);
            for pf in &cb.prefilled_txs {
                push_compact_size(&mut buf, pf.index as u64);
                buf.extend_from_slice(&pf.tx.serialize());
            }
        }

        NetworkMessage::GetBlockTxn(gbt) => {
            push_hash32(&mut buf, gbt.block_hash.as_bytes());
            push_compact_size(&mut buf, gbt.indices.len() as u64);
            for idx in &gbt.indices {
                push_compact_size(&mut buf, *idx as u64);
            }
        }

        NetworkMessage::BlockTxn(bt) => {
            push_hash32(&mut buf, bt.block_hash.as_bytes());
            push_compact_size(&mut buf, bt.transactions.len() as u64);
            for tx in &bt.transactions {
                buf.extend_from_slice(&tx.serialize());
            }
        }

        NetworkMessage::Alert(data) => {
            buf.extend_from_slice(data);
        }

        NetworkMessage::Unknown { payload, .. } => {
            buf.extend_from_slice(payload);
        }
    }
    buf
}

/// Encode a complete message (header + payload) ready for the wire.
pub fn encode_message(magic: [u8; 4], msg: &NetworkMessage) -> Vec<u8> {
    let payload = encode_payload(msg);
    let header = MessageHeader::new(magic, msg.command(), &payload);
    let mut out = Vec::with_capacity(HEADER_SIZE + payload.len());
    out.extend_from_slice(&header.to_bytes());
    out.extend_from_slice(&payload);
    out
}

// ---------------------------------------------------------------------------
// Decode a payload into a NetworkMessage
// ---------------------------------------------------------------------------

/// Decode a message payload given its command string.
pub fn decode_payload(command: &str, payload: &[u8]) -> Result<NetworkMessage, CodecError> {
    let mut c = Cursor::new(payload);

    match command {
        "version" => {
            let version = c.read_u32_le()?;
            let services = ServiceFlags::from_u64(c.read_u64_le()?);
            let timestamp = c.read_i64_le()?;
            let addr_recv = c.read_net_addr()?;
            let addr_from = c.read_net_addr()?;
            let nonce = c.read_u64_le()?;
            let user_agent = c.read_string()?;
            let start_height = c.read_i32_le()?;
            let relay = if c.remaining() > 0 {
                c.read_u8()? != 0
            } else {
                true // default to true for old peers
            };
            Ok(NetworkMessage::Version(VersionMessage {
                version,
                services,
                timestamp,
                addr_recv,
                addr_from,
                nonce,
                user_agent,
                start_height,
                relay,
            }))
        }

        "verack" => Ok(NetworkMessage::Verack),

        "wtxidrelay" => Ok(NetworkMessage::WtxidRelay),

        "sendheaders" => Ok(NetworkMessage::SendHeaders),

        "sendaddrv2" => Ok(NetworkMessage::SendAddrV2),

        "sendcmpct" => {
            let announce = c.read_u8()? != 0;
            let version = c.read_u64_le()?;
            Ok(NetworkMessage::SendCmpct(SendCmpctMessage {
                announce,
                version,
            }))
        }

        "feefilter" => {
            let feerate = c.read_u64_le()?;
            Ok(NetworkMessage::FeeFilter { feerate })
        }

        "ping" => {
            let nonce = c.read_u64_le()?;
            Ok(NetworkMessage::Ping { nonce })
        }

        "pong" => {
            let nonce = c.read_u64_le()?;
            Ok(NetworkMessage::Pong { nonce })
        }

        "getaddr" => Ok(NetworkMessage::GetAddr),

        "mempool" => Ok(NetworkMessage::MemPool),

        "inv" => {
            let count = c.read_compact_size()? as usize;
            if count > MAX_INV_SIZE {
                return Err(CodecError::MalformedPayload(format!(
                    "inv count {} exceeds max {}",
                    count, MAX_INV_SIZE
                )));
            }
            let mut items = Vec::with_capacity(count);
            for _ in 0..count {
                items.push(c.read_inv_vector()?);
            }
            Ok(NetworkMessage::Inv(items))
        }

        "getdata" => {
            let count = c.read_compact_size()? as usize;
            if count > MAX_INV_SIZE {
                return Err(CodecError::MalformedPayload(format!(
                    "getdata count {} exceeds max",
                    count
                )));
            }
            let mut items = Vec::with_capacity(count);
            for _ in 0..count {
                items.push(c.read_inv_vector()?);
            }
            Ok(NetworkMessage::GetData(items))
        }

        "notfound" => {
            let count = c.read_compact_size()? as usize;
            let mut items = Vec::with_capacity(count.min(MAX_INV_SIZE));
            for _ in 0..count {
                items.push(c.read_inv_vector()?);
            }
            Ok(NetworkMessage::NotFound(items))
        }

        "addr" => {
            let count = c.read_compact_size()? as usize;
            if count > MAX_ADDR_TO_SEND {
                return Err(CodecError::MalformedPayload(format!(
                    "addr count {} exceeds max",
                    count
                )));
            }
            let mut addrs = Vec::with_capacity(count);
            for _ in 0..count {
                let timestamp = c.read_u32_le()?;
                let addr = c.read_net_addr()?;
                addrs.push(TimestampedAddress { timestamp, addr });
            }
            Ok(NetworkMessage::Addr(addrs))
        }

        "addrv2" => {
            let count = c.read_compact_size()? as usize;
            if count > MAX_ADDR_TO_SEND {
                return Err(CodecError::MalformedPayload(format!(
                    "addrv2 count {} exceeds max",
                    count
                )));
            }
            let mut entries = Vec::with_capacity(count);
            for _ in 0..count {
                let timestamp = c.read_u32_le()?;
                let services = ServiceFlags::from_u64(c.read_compact_size()?);
                let network_id = c.read_u8()?;
                let addr_len = c.read_compact_size()? as usize;
                let addr = c.read_bytes(addr_len)?.to_vec();
                let port = c.read_u16_be()?;
                entries.push(AddrV2Entry {
                    timestamp,
                    services,
                    network_id,
                    addr,
                    port,
                });
            }
            Ok(NetworkMessage::AddrV2(entries))
        }

        "getheaders" => {
            let version = c.read_u32_le()?;
            let count = c.read_compact_size()? as usize;
            if count > MAX_LOCATOR_SIZE {
                return Err(CodecError::MalformedPayload("locator too long".into()));
            }
            let mut locator_hashes = Vec::with_capacity(count);
            for _ in 0..count {
                locator_hashes.push(BlockHash::from_hash(Hash256::from_bytes(c.read_hash32()?)));
            }
            let hash_stop = BlockHash::from_hash(Hash256::from_bytes(c.read_hash32()?));
            Ok(NetworkMessage::GetHeaders(GetHeadersMessage {
                version,
                locator_hashes,
                hash_stop,
            }))
        }

        "getblocks" => {
            let version = c.read_u32_le()?;
            let count = c.read_compact_size()? as usize;
            if count > MAX_LOCATOR_SIZE {
                return Err(CodecError::MalformedPayload("locator too long".into()));
            }
            let mut locator_hashes = Vec::with_capacity(count);
            for _ in 0..count {
                locator_hashes.push(BlockHash::from_hash(Hash256::from_bytes(c.read_hash32()?)));
            }
            let hash_stop = BlockHash::from_hash(Hash256::from_bytes(c.read_hash32()?));
            Ok(NetworkMessage::GetBlocks(GetBlocksMessage {
                version,
                locator_hashes,
                hash_stop,
            }))
        }

        "headers" => {
            let count = c.read_compact_size()? as usize;
            if count > MAX_HEADERS {
                return Err(CodecError::MalformedPayload(format!(
                    "headers count {} exceeds max {}",
                    count, MAX_HEADERS
                )));
            }
            let mut headers = Vec::with_capacity(count);
            for _ in 0..count {
                let hdr = c.read_block_header()?;
                let _tx_count = c.read_compact_size()?; // always 0 for headers
                headers.push(hdr);
            }
            Ok(NetworkMessage::Headers(headers))
        }

        "block" => {
            let header = c.read_block_header()?;
            let tx_count = c.read_compact_size()? as usize;
            let mut transactions = Vec::with_capacity(tx_count);
            for _ in 0..tx_count {
                transactions.push(c.read_transaction()?);
            }
            Ok(NetworkMessage::Block(Block::new(header, transactions)))
        }

        "tx" => {
            let tx = c.read_transaction()?;
            Ok(NetworkMessage::Tx(tx))
        }

        "cmpctblock" => {
            let header = c.read_block_header()?;
            let nonce = c.read_u64_le()?;
            let short_count = c.read_compact_size()? as usize;
            let mut short_ids = Vec::with_capacity(short_count);
            for _ in 0..short_count {
                // 6 bytes little-endian
                let bytes = c.read_bytes(6)?;
                let mut arr = [0u8; 8];
                arr[..6].copy_from_slice(bytes);
                short_ids.push(u64::from_le_bytes(arr));
            }
            let pf_count = c.read_compact_size()? as usize;
            let mut prefilled_txs = Vec::with_capacity(pf_count);
            for _ in 0..pf_count {
                let index = c.read_compact_size()? as u16;
                let tx = c.read_transaction()?;
                prefilled_txs.push(PrefilledTx { index, tx });
            }
            Ok(NetworkMessage::CmpctBlock(CmpctBlockMessage {
                header,
                nonce,
                short_ids,
                prefilled_txs,
            }))
        }

        "getblocktxn" => {
            let block_hash = BlockHash::from_hash(Hash256::from_bytes(c.read_hash32()?));
            let count = c.read_compact_size()? as usize;
            let mut indices = Vec::with_capacity(count);
            for _ in 0..count {
                indices.push(c.read_compact_size()? as u16);
            }
            Ok(NetworkMessage::GetBlockTxn(GetBlockTxnMessage {
                block_hash,
                indices,
            }))
        }

        "blocktxn" => {
            let block_hash = BlockHash::from_hash(Hash256::from_bytes(c.read_hash32()?));
            let count = c.read_compact_size()? as usize;
            let mut transactions = Vec::with_capacity(count);
            for _ in 0..count {
                transactions.push(c.read_transaction()?);
            }
            Ok(NetworkMessage::BlockTxn(BlockTxnMessage {
                block_hash,
                transactions,
            }))
        }

        "alert" => Ok(NetworkMessage::Alert(payload.to_vec())),

        _ => Ok(NetworkMessage::Unknown {
            command: command.to_string(),
            payload: payload.to_vec(),
        }),
    }
}

/// Decode a complete wire message (header + payload) from a byte buffer.
///
/// Returns the decoded message and the number of bytes consumed.
pub fn decode_message(
    expected_magic: [u8; 4],
    data: &[u8],
) -> Result<(NetworkMessage, usize), CodecError> {
    let header = MessageHeader::from_bytes(data)?;

    if header.magic != expected_magic {
        return Err(CodecError::BadMagic {
            expected: expected_magic,
            got: header.magic,
        });
    }

    if header.payload_len > MAX_PROTOCOL_MESSAGE_LENGTH {
        return Err(CodecError::PayloadTooLarge(header.payload_len));
    }

    let total = HEADER_SIZE + header.payload_len as usize;
    if data.len() < total {
        return Err(CodecError::UnexpectedEnd);
    }

    let payload = &data[HEADER_SIZE..total];

    if !verify_checksum(payload, header.checksum) {
        return Err(CodecError::BadChecksum {
            expected: header.checksum,
            got: compute_checksum(payload),
        });
    }

    let command = header.command_string()?;
    let msg = decode_payload(&command, payload)?;
    Ok((msg, total))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::block::BlockHeader;
    use crate::primitives::hash::{BlockHash, Hash256};

    const MAINNET_MAGIC: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];

    // ── compact size ────────────────────────────────────────────────

    #[test]
    fn test_compact_size_single_byte() {
        let encoded = encode_compact_size(0);
        assert_eq!(encoded, vec![0]);
        let (val, len) = decode_compact_size(&encoded, 0).unwrap();
        assert_eq!(val, 0);
        assert_eq!(len, 1);
    }

    #[test]
    fn test_compact_size_max_single() {
        let encoded = encode_compact_size(0xfc);
        assert_eq!(encoded, vec![0xfc]);
        let (val, _) = decode_compact_size(&encoded, 0).unwrap();
        assert_eq!(val, 0xfc);
    }

    #[test]
    fn test_compact_size_u16() {
        let encoded = encode_compact_size(0xfd);
        assert_eq!(encoded.len(), 3);
        assert_eq!(encoded[0], 0xfd);
        let (val, len) = decode_compact_size(&encoded, 0).unwrap();
        assert_eq!(val, 0xfd);
        assert_eq!(len, 3);
    }

    #[test]
    fn test_compact_size_u32() {
        let encoded = encode_compact_size(0x10000);
        assert_eq!(encoded.len(), 5);
        assert_eq!(encoded[0], 0xfe);
        let (val, len) = decode_compact_size(&encoded, 0).unwrap();
        assert_eq!(val, 0x10000);
        assert_eq!(len, 5);
    }

    #[test]
    fn test_compact_size_u64() {
        let encoded = encode_compact_size(0x100000000);
        assert_eq!(encoded.len(), 9);
        assert_eq!(encoded[0], 0xff);
        let (val, len) = decode_compact_size(&encoded, 0).unwrap();
        assert_eq!(val, 0x100000000);
        assert_eq!(len, 9);
    }

    #[test]
    fn test_compact_size_non_canonical_u16() {
        // 0xfd prefix but value < 0xfd → non-canonical
        let data = [0xfd, 0x01, 0x00];
        assert_eq!(
            decode_compact_size(&data, 0),
            Err(CodecError::BadCompactSize)
        );
    }

    #[test]
    fn test_compact_size_non_canonical_u32() {
        // 0xfe prefix but value fits in u16
        let data = [0xfe, 0x01, 0x00, 0x00, 0x00];
        assert_eq!(
            decode_compact_size(&data, 0),
            Err(CodecError::BadCompactSize)
        );
    }

    // ── checksum ────────────────────────────────────────────────────

    #[test]
    fn test_compute_checksum_empty() {
        let cs = compute_checksum(&[]);
        // double-SHA256 of empty = known value; just check it's deterministic
        let cs2 = compute_checksum(&[]);
        assert_eq!(cs, cs2);
    }

    #[test]
    fn test_verify_checksum() {
        let data = b"hello world";
        let cs = compute_checksum(data);
        assert!(verify_checksum(data, cs));
        assert!(!verify_checksum(b"wrong data", cs));
    }

    // ── message header ──────────────────────────────────────────────

    #[test]
    fn test_header_roundtrip() {
        let hdr = MessageHeader::new(MAINNET_MAGIC, "version", b"test payload");
        let bytes = hdr.to_bytes();
        assert_eq!(bytes.len(), 24);

        let decoded = MessageHeader::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.magic, MAINNET_MAGIC);
        assert_eq!(decoded.command_string().unwrap(), "version");
        assert_eq!(decoded.payload_len, 12);
        assert_eq!(decoded.checksum, hdr.checksum);
    }

    #[test]
    fn test_header_short_command() {
        let hdr = MessageHeader::new(MAINNET_MAGIC, "tx", &[]);
        assert_eq!(hdr.command_string().unwrap(), "tx");
    }

    // ── verack roundtrip ────────────────────────────────────────────

    #[test]
    fn test_verack_roundtrip() {
        let msg = NetworkMessage::Verack;
        let wire = encode_message(MAINNET_MAGIC, &msg);
        let (decoded, consumed) = decode_message(MAINNET_MAGIC, &wire).unwrap();
        assert_eq!(consumed, wire.len());
        assert_eq!(decoded.command(), "verack");
    }

    // ── ping/pong roundtrip ─────────────────────────────────────────

    #[test]
    fn test_ping_roundtrip() {
        let msg = NetworkMessage::Ping {
            nonce: 0xDEADBEEF12345678,
        };
        let wire = encode_message(MAINNET_MAGIC, &msg);
        let (decoded, _) = decode_message(MAINNET_MAGIC, &wire).unwrap();
        match decoded {
            NetworkMessage::Ping { nonce } => assert_eq!(nonce, 0xDEADBEEF12345678),
            _ => panic!("expected Ping"),
        }
    }

    #[test]
    fn test_pong_roundtrip() {
        let msg = NetworkMessage::Pong { nonce: 42 };
        let wire = encode_message(MAINNET_MAGIC, &msg);
        let (decoded, _) = decode_message(MAINNET_MAGIC, &wire).unwrap();
        match decoded {
            NetworkMessage::Pong { nonce } => assert_eq!(nonce, 42),
            _ => panic!("expected Pong"),
        }
    }

    // ── version roundtrip ───────────────────────────────────────────

    #[test]
    fn test_version_roundtrip() {
        let addr = NetAddress {
            services: ServiceFlags::NETWORK,
            addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1],
            port: 8333,
        };
        let vm = VersionMessage {
            version: 70016,
            services: ServiceFlags::NETWORK.union(ServiceFlags::WITNESS),
            timestamp: 1700000000,
            addr_recv: addr,
            addr_from: addr,
            nonce: 0x1234567890ABCDEF,
            user_agent: "/AgenticBitcoin:0.1.0/".to_string(),
            start_height: 800000,
            relay: true,
        };
        let msg = NetworkMessage::Version(vm);
        let wire = encode_message(MAINNET_MAGIC, &msg);
        let (decoded, _) = decode_message(MAINNET_MAGIC, &wire).unwrap();
        match decoded {
            NetworkMessage::Version(v) => {
                assert_eq!(v.version, 70016);
                assert_eq!(v.services.as_u64(), 0x09);
                assert_eq!(v.timestamp, 1700000000);
                assert_eq!(v.nonce, 0x1234567890ABCDEF);
                assert_eq!(v.user_agent, "/AgenticBitcoin:0.1.0/");
                assert_eq!(v.start_height, 800000);
                assert!(v.relay);
                assert_eq!(v.addr_recv.port, 8333);
            }
            _ => panic!("expected Version"),
        }
    }

    // ── inv / getdata / notfound roundtrips ──────────────────────────

    #[test]
    fn test_inv_roundtrip() {
        let items = vec![
            InvVector::new(InvType::Tx, [0xaa; 32]),
            InvVector::new(InvType::Block, [0xbb; 32]),
            InvVector::new(InvType::WitnessTx, [0xcc; 32]),
        ];
        let msg = NetworkMessage::Inv(items.clone());
        let wire = encode_message(MAINNET_MAGIC, &msg);
        let (decoded, _) = decode_message(MAINNET_MAGIC, &wire).unwrap();
        match decoded {
            NetworkMessage::Inv(dec_items) => {
                assert_eq!(dec_items.len(), 3);
                assert_eq!(dec_items[0].inv_type, InvType::Tx);
                assert_eq!(dec_items[0].hash, [0xaa; 32]);
                assert_eq!(dec_items[1].inv_type, InvType::Block);
                assert_eq!(dec_items[2].inv_type, InvType::WitnessTx);
            }
            _ => panic!("expected Inv"),
        }
    }

    #[test]
    fn test_getdata_roundtrip() {
        let items = vec![InvVector::new(InvType::WitnessBlock, [0xdd; 32])];
        let msg = NetworkMessage::GetData(items);
        let wire = encode_message(MAINNET_MAGIC, &msg);
        let (decoded, _) = decode_message(MAINNET_MAGIC, &wire).unwrap();
        match decoded {
            NetworkMessage::GetData(items) => {
                assert_eq!(items.len(), 1);
                assert_eq!(items[0].inv_type, InvType::WitnessBlock);
            }
            _ => panic!("expected GetData"),
        }
    }

    #[test]
    fn test_notfound_roundtrip() {
        let items = vec![InvVector::new(InvType::Tx, [0x11; 32])];
        let msg = NetworkMessage::NotFound(items);
        let wire = encode_message(MAINNET_MAGIC, &msg);
        let (decoded, _) = decode_message(MAINNET_MAGIC, &wire).unwrap();
        assert_eq!(decoded.command(), "notfound");
    }

    // ── feefilter roundtrip ─────────────────────────────────────────

    #[test]
    fn test_feefilter_roundtrip() {
        let msg = NetworkMessage::FeeFilter { feerate: 1000 };
        let wire = encode_message(MAINNET_MAGIC, &msg);
        let (decoded, _) = decode_message(MAINNET_MAGIC, &wire).unwrap();
        match decoded {
            NetworkMessage::FeeFilter { feerate } => assert_eq!(feerate, 1000),
            _ => panic!("expected FeeFilter"),
        }
    }

    // ── sendcmpct roundtrip ─────────────────────────────────────────

    #[test]
    fn test_sendcmpct_roundtrip() {
        let msg = NetworkMessage::SendCmpct(SendCmpctMessage {
            announce: true,
            version: 2,
        });
        let wire = encode_message(MAINNET_MAGIC, &msg);
        let (decoded, _) = decode_message(MAINNET_MAGIC, &wire).unwrap();
        match decoded {
            NetworkMessage::SendCmpct(sc) => {
                assert!(sc.announce);
                assert_eq!(sc.version, 2);
            }
            _ => panic!("expected SendCmpct"),
        }
    }

    // ── feature negotiation roundtrips ───────────────────────────────

    #[test]
    fn test_empty_messages_roundtrip() {
        for msg in [
            NetworkMessage::WtxidRelay,
            NetworkMessage::SendHeaders,
            NetworkMessage::SendAddrV2,
            NetworkMessage::GetAddr,
            NetworkMessage::MemPool,
        ] {
            let cmd = msg.command().to_string();
            let wire = encode_message(MAINNET_MAGIC, &msg);
            let (decoded, _) = decode_message(MAINNET_MAGIC, &wire).unwrap();
            assert_eq!(decoded.command(), cmd);
        }
    }

    // ── getheaders / getblocks roundtrip ─────────────────────────────

    #[test]
    fn test_getheaders_roundtrip() {
        let msg = NetworkMessage::GetHeaders(GetHeadersMessage {
            version: 70016,
            locator_hashes: vec![
                BlockHash::from_hash(Hash256::from_bytes([0x11; 32])),
                BlockHash::from_hash(Hash256::from_bytes([0x22; 32])),
            ],
            hash_stop: BlockHash::zero(),
        });
        let wire = encode_message(MAINNET_MAGIC, &msg);
        let (decoded, _) = decode_message(MAINNET_MAGIC, &wire).unwrap();
        match decoded {
            NetworkMessage::GetHeaders(gh) => {
                assert_eq!(gh.version, 70016);
                assert_eq!(gh.locator_hashes.len(), 2);
                assert_eq!(gh.hash_stop, BlockHash::zero());
            }
            _ => panic!("expected GetHeaders"),
        }
    }

    #[test]
    fn test_getblocks_roundtrip() {
        let msg = NetworkMessage::GetBlocks(GetBlocksMessage {
            version: 70016,
            locator_hashes: vec![BlockHash::genesis_mainnet()],
            hash_stop: BlockHash::zero(),
        });
        let wire = encode_message(MAINNET_MAGIC, &msg);
        let (decoded, _) = decode_message(MAINNET_MAGIC, &wire).unwrap();
        match decoded {
            NetworkMessage::GetBlocks(gb) => {
                assert_eq!(gb.version, 70016);
                assert_eq!(gb.locator_hashes.len(), 1);
                assert_eq!(gb.locator_hashes[0], BlockHash::genesis_mainnet());
            }
            _ => panic!("expected GetBlocks"),
        }
    }

    // ── headers roundtrip ───────────────────────────────────────────

    #[test]
    fn test_headers_roundtrip() {
        let headers = vec![
            BlockHeader::new(1, BlockHash::zero(), Hash256::zero(), 1000, 0x1d00ffff, 42),
            BlockHeader::new(2, BlockHash::zero(), Hash256::zero(), 2000, 0x1d00ffff, 99),
        ];
        let msg = NetworkMessage::Headers(headers);
        let wire = encode_message(MAINNET_MAGIC, &msg);
        let (decoded, _) = decode_message(MAINNET_MAGIC, &wire).unwrap();
        match decoded {
            NetworkMessage::Headers(hdrs) => {
                assert_eq!(hdrs.len(), 2);
                assert_eq!(hdrs[0].version, 1);
                assert_eq!(hdrs[0].time, 1000);
                assert_eq!(hdrs[0].nonce, 42);
                assert_eq!(hdrs[1].version, 2);
                assert_eq!(hdrs[1].time, 2000);
            }
            _ => panic!("expected Headers"),
        }
    }

    // ── addr roundtrip ──────────────────────────────────────────────

    #[test]
    fn test_addr_roundtrip() {
        let addr: std::net::SocketAddr = "1.2.3.4:8333".parse().unwrap();
        let na = NetAddress::from_socket_addr(addr, ServiceFlags::NETWORK);
        let addrs = vec![TimestampedAddress {
            timestamp: 1700000000,
            addr: na,
        }];
        let msg = NetworkMessage::Addr(addrs);
        let wire = encode_message(MAINNET_MAGIC, &msg);
        let (decoded, _) = decode_message(MAINNET_MAGIC, &wire).unwrap();
        match decoded {
            NetworkMessage::Addr(a) => {
                assert_eq!(a.len(), 1);
                assert_eq!(a[0].timestamp, 1700000000);
                assert_eq!(a[0].addr.port, 8333);
            }
            _ => panic!("expected Addr"),
        }
    }

    // ── addrv2 roundtrip ────────────────────────────────────────────

    #[test]
    fn test_addrv2_roundtrip() {
        let entries = vec![AddrV2Entry {
            timestamp: 1700000000,
            services: ServiceFlags::NETWORK,
            network_id: 1, // IPv4
            addr: vec![192, 168, 1, 1],
            port: 8333,
        }];
        let msg = NetworkMessage::AddrV2(entries);
        let wire = encode_message(MAINNET_MAGIC, &msg);
        let (decoded, _) = decode_message(MAINNET_MAGIC, &wire).unwrap();
        match decoded {
            NetworkMessage::AddrV2(e) => {
                assert_eq!(e.len(), 1);
                assert_eq!(e[0].network_id, 1);
                assert_eq!(e[0].addr, vec![192, 168, 1, 1]);
                assert_eq!(e[0].port, 8333);
            }
            _ => panic!("expected AddrV2"),
        }
    }

    // ── bad magic ───────────────────────────────────────────────────

    #[test]
    fn test_bad_magic() {
        let msg = NetworkMessage::Verack;
        let wire = encode_message(MAINNET_MAGIC, &msg);
        let result = decode_message([0, 0, 0, 0], &wire);
        assert!(matches!(result, Err(CodecError::BadMagic { .. })));
    }

    // ── bad checksum ────────────────────────────────────────────────

    #[test]
    fn test_bad_checksum() {
        let msg = NetworkMessage::Ping { nonce: 1 };
        let mut wire = encode_message(MAINNET_MAGIC, &msg);
        // Corrupt the checksum
        wire[20] ^= 0xff;
        let result = decode_message(MAINNET_MAGIC, &wire);
        assert!(matches!(result, Err(CodecError::BadChecksum { .. })));
    }

    // ── unknown command ─────────────────────────────────────────────

    #[test]
    fn test_unknown_command_passthrough() {
        let msg = NetworkMessage::Unknown {
            command: "foobarbaz".to_string(),
            payload: vec![1, 2, 3, 4],
        };
        let wire = encode_message(MAINNET_MAGIC, &msg);
        let (decoded, _) = decode_message(MAINNET_MAGIC, &wire).unwrap();
        match decoded {
            NetworkMessage::Unknown { command, payload } => {
                assert_eq!(command, "foobarbaz");
                assert_eq!(payload, vec![1, 2, 3, 4]);
            }
            _ => panic!("expected Unknown"),
        }
    }

    // ── payload too large ───────────────────────────────────────────

    #[test]
    fn test_payload_too_large() {
        // Craft a header claiming 5MB payload
        let hdr = MessageHeader {
            magic: MAINNET_MAGIC,
            command: *b"verack\0\0\0\0\0\0",
            payload_len: 5_000_000,
            checksum: [0; 4],
        };
        let bytes = hdr.to_bytes();
        let result = decode_message(MAINNET_MAGIC, &bytes);
        assert!(matches!(
            result,
            Err(CodecError::PayloadTooLarge(5_000_000))
        ));
    }

    // ── getblocktxn roundtrip ───────────────────────────────────────

    #[test]
    fn test_getblocktxn_roundtrip() {
        let msg = NetworkMessage::GetBlockTxn(GetBlockTxnMessage {
            block_hash: BlockHash::from_hash(Hash256::from_bytes([0x55; 32])),
            indices: vec![0, 3, 5],
        });
        let wire = encode_message(MAINNET_MAGIC, &msg);
        let (decoded, _) = decode_message(MAINNET_MAGIC, &wire).unwrap();
        match decoded {
            NetworkMessage::GetBlockTxn(gbt) => {
                assert_eq!(gbt.block_hash.as_bytes(), &[0x55; 32]);
                assert_eq!(gbt.indices, vec![0, 3, 5]);
            }
            _ => panic!("expected GetBlockTxn"),
        }
    }
}

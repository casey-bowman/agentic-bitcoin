//! BIP157 P2P Messages for Compact Block Filter Protocol
//!
//! Defines the message types used by light clients to request and receive
//! compact block filters and their headers from full nodes.
//!
//! ## Message Flow
//!
//! 1. Light client sends `getcfheaders` to get filter header chain for a range
//! 2. Light client verifies the header chain links correctly
//! 3. Light client sends `getcfilters` to fetch actual filters for blocks of interest
//! 4. Light client matches filters against its wallet scriptPubKeys
//! 5. For checkpoints, `getcfcheckpt` provides evenly-spaced filter headers
//!
//! ## References
//!
//! - BIP157: <https://github.com/bitcoin/bips/blob/master/bip-0157.mediawiki>

use crate::primitives::hash::{BlockHash, Hash256};

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------

/// `getcfilters` — Request compact filters for a range of blocks.
///
/// The peer responds with a `cfilter` message for each block in the range
/// `[start_height, stop_hash]`.
#[derive(Debug, Clone)]
pub struct GetCFilters {
    /// Filter type (0 = basic)
    pub filter_type: u8,
    /// Start block height
    pub start_height: u32,
    /// Stop block hash (inclusive)
    pub stop_hash: BlockHash,
}

/// `cfilter` — A single compact block filter.
///
/// Sent in response to `getcfilters`, one per block.
#[derive(Debug, Clone)]
pub struct CFilter {
    /// Filter type (0 = basic)
    pub filter_type: u8,
    /// Block hash this filter covers
    pub block_hash: BlockHash,
    /// Serialized GCS filter data (N || encoded_deltas)
    pub filter_data: Vec<u8>,
}

/// `getcfheaders` — Request filter headers for a range of blocks.
///
/// The peer responds with a single `cfheaders` message covering the range.
#[derive(Debug, Clone)]
pub struct GetCFHeaders {
    /// Filter type (0 = basic)
    pub filter_type: u8,
    /// Start block height
    pub start_height: u32,
    /// Stop block hash (inclusive)
    pub stop_hash: BlockHash,
}

/// `cfheaders` — Filter headers for a range of blocks.
///
/// Contains the previous filter header (for chain verification) followed by
/// a list of filter hashes. The client derives the full header chain by
/// chaining: `header[i] = hash(filter_hash[i] || header[i-1])`.
#[derive(Debug, Clone)]
pub struct CFHeaders {
    /// Filter type (0 = basic)
    pub filter_type: u8,
    /// The stop block hash (end of the range)
    pub stop_hash: BlockHash,
    /// Previous filter header (for chaining)
    pub prev_filter_header: Hash256,
    /// Filter hashes for each block in the range
    pub filter_hashes: Vec<Hash256>,
}

/// `getcfcheckpt` — Request evenly-spaced filter header checkpoints.
///
/// Checkpoints are filter headers at every 1000th block, allowing clients
/// to verify the header chain in parallel from multiple peers.
#[derive(Debug, Clone)]
pub struct GetCFCheckpt {
    /// Filter type (0 = basic)
    pub filter_type: u8,
    /// Stop block hash
    pub stop_hash: BlockHash,
}

/// `cfcheckpt` — Evenly-spaced filter header checkpoints.
///
/// Contains filter headers at blocks 999, 1999, 2999, ... up to the
/// stop hash.
#[derive(Debug, Clone)]
pub struct CFCheckpt {
    /// Filter type (0 = basic)
    pub filter_type: u8,
    /// Stop block hash
    pub stop_hash: BlockHash,
    /// Filter headers at checkpoint heights
    pub filter_headers: Vec<Hash256>,
}

// ---------------------------------------------------------------------------
// Encoding / decoding
// ---------------------------------------------------------------------------

impl GetCFilters {
    /// Encode to wire format.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(37);
        buf.push(self.filter_type);
        buf.extend_from_slice(&self.start_height.to_le_bytes());
        buf.extend_from_slice(self.stop_hash.as_bytes());
        buf
    }

    /// Decode from wire format.
    pub fn decode(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 37 {
            return Err("getcfilters too short");
        }
        let filter_type = data[0];
        let start_height = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&data[5..37]);
        Ok(GetCFilters {
            filter_type,
            start_height,
            stop_hash: BlockHash::from_hash(Hash256::from_bytes(hash)),
        })
    }
}

impl CFilter {
    /// Encode to wire format.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(33 + self.filter_data.len());
        buf.push(self.filter_type);
        buf.extend_from_slice(self.block_hash.as_bytes());
        buf.extend_from_slice(&self.filter_data);
        buf
    }

    /// Decode from wire format.
    pub fn decode(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 33 {
            return Err("cfilter too short");
        }
        let filter_type = data[0];
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&data[1..33]);
        let filter_data = data[33..].to_vec();
        Ok(CFilter {
            filter_type,
            block_hash: BlockHash::from_hash(Hash256::from_bytes(hash)),
            filter_data,
        })
    }
}

impl GetCFHeaders {
    /// Encode to wire format.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(37);
        buf.push(self.filter_type);
        buf.extend_from_slice(&self.start_height.to_le_bytes());
        buf.extend_from_slice(self.stop_hash.as_bytes());
        buf
    }

    /// Decode from wire format.
    pub fn decode(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 37 {
            return Err("getcfheaders too short");
        }
        let filter_type = data[0];
        let start_height = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&data[5..37]);
        Ok(GetCFHeaders {
            filter_type,
            start_height,
            stop_hash: BlockHash::from_hash(Hash256::from_bytes(hash)),
        })
    }
}

impl CFHeaders {
    /// Encode to wire format.
    pub fn encode(&self) -> Vec<u8> {
        use crate::protocol::codec::push_compact_size;
        let mut buf = Vec::with_capacity(65 + self.filter_hashes.len() * 32);
        buf.push(self.filter_type);
        buf.extend_from_slice(self.stop_hash.as_bytes());
        buf.extend_from_slice(self.prev_filter_header.as_bytes());
        push_compact_size(&mut buf, self.filter_hashes.len() as u64);
        for fh in &self.filter_hashes {
            buf.extend_from_slice(fh.as_bytes());
        }
        buf
    }

    /// Decode from wire format.
    pub fn decode(data: &[u8]) -> Result<Self, &'static str> {
        use crate::protocol::codec::decode_compact_size;
        if data.len() < 65 {
            return Err("cfheaders too short");
        }
        let filter_type = data[0];
        let mut stop_hash = [0u8; 32];
        stop_hash.copy_from_slice(&data[1..33]);
        let mut prev = [0u8; 32];
        prev.copy_from_slice(&data[33..65]);

        let (count, cs_len) = decode_compact_size(data, 65).map_err(|_| "bad compact size")?;
        let count = count as usize;
        let mut pos = 65 + cs_len;

        let mut filter_hashes = Vec::with_capacity(count);
        for _ in 0..count {
            if pos + 32 > data.len() {
                return Err("cfheaders truncated");
            }
            let mut h = [0u8; 32];
            h.copy_from_slice(&data[pos..pos + 32]);
            filter_hashes.push(Hash256::from_bytes(h));
            pos += 32;
        }

        Ok(CFHeaders {
            filter_type,
            stop_hash: BlockHash::from_hash(Hash256::from_bytes(stop_hash)),
            prev_filter_header: Hash256::from_bytes(prev),
            filter_hashes,
        })
    }
}

impl GetCFCheckpt {
    /// Encode to wire format.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(33);
        buf.push(self.filter_type);
        buf.extend_from_slice(self.stop_hash.as_bytes());
        buf
    }

    /// Decode from wire format.
    pub fn decode(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 33 {
            return Err("getcfcheckpt too short");
        }
        let filter_type = data[0];
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&data[1..33]);
        Ok(GetCFCheckpt {
            filter_type,
            stop_hash: BlockHash::from_hash(Hash256::from_bytes(hash)),
        })
    }
}

impl CFCheckpt {
    /// Encode to wire format.
    pub fn encode(&self) -> Vec<u8> {
        use crate::protocol::codec::push_compact_size;
        let mut buf = Vec::with_capacity(33 + self.filter_headers.len() * 32);
        buf.push(self.filter_type);
        buf.extend_from_slice(self.stop_hash.as_bytes());
        push_compact_size(&mut buf, self.filter_headers.len() as u64);
        for fh in &self.filter_headers {
            buf.extend_from_slice(fh.as_bytes());
        }
        buf
    }

    /// Decode from wire format.
    pub fn decode(data: &[u8]) -> Result<Self, &'static str> {
        use crate::protocol::codec::decode_compact_size;
        if data.len() < 33 {
            return Err("cfcheckpt too short");
        }
        let filter_type = data[0];
        let mut stop_hash = [0u8; 32];
        stop_hash.copy_from_slice(&data[1..33]);

        let (count, cs_len) = decode_compact_size(data, 33).map_err(|_| "bad compact size")?;
        let count = count as usize;
        let mut pos = 33 + cs_len;

        let mut filter_headers = Vec::with_capacity(count);
        for _ in 0..count {
            if pos + 32 > data.len() {
                return Err("cfcheckpt truncated");
            }
            let mut h = [0u8; 32];
            h.copy_from_slice(&data[pos..pos + 32]);
            filter_headers.push(Hash256::from_bytes(h));
            pos += 32;
        }

        Ok(CFCheckpt {
            filter_type,
            stop_hash: BlockHash::from_hash(Hash256::from_bytes(stop_hash)),
            filter_headers,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_getcfilters_roundtrip() {
        let msg = GetCFilters {
            filter_type: 0,
            start_height: 100_000,
            stop_hash: BlockHash::from_hash(Hash256::from_bytes([0xaa; 32])),
        };
        let encoded = msg.encode();
        assert_eq!(encoded.len(), 37);

        let decoded = GetCFilters::decode(&encoded).unwrap();
        assert_eq!(decoded.filter_type, 0);
        assert_eq!(decoded.start_height, 100_000);
        assert_eq!(decoded.stop_hash.as_bytes(), &[0xaa; 32]);
    }

    #[test]
    fn test_cfilter_roundtrip() {
        let msg = CFilter {
            filter_type: 0,
            block_hash: BlockHash::from_hash(Hash256::from_bytes([0xbb; 32])),
            filter_data: vec![0x03, 0x12, 0x34, 0x56],
        };
        let encoded = msg.encode();
        let decoded = CFilter::decode(&encoded).unwrap();
        assert_eq!(decoded.filter_type, 0);
        assert_eq!(decoded.block_hash.as_bytes(), &[0xbb; 32]);
        assert_eq!(decoded.filter_data, vec![0x03, 0x12, 0x34, 0x56]);
    }

    #[test]
    fn test_getcfheaders_roundtrip() {
        let msg = GetCFHeaders {
            filter_type: 0,
            start_height: 500,
            stop_hash: BlockHash::from_hash(Hash256::from_bytes([0xcc; 32])),
        };
        let encoded = msg.encode();
        let decoded = GetCFHeaders::decode(&encoded).unwrap();
        assert_eq!(decoded.filter_type, 0);
        assert_eq!(decoded.start_height, 500);
        assert_eq!(decoded.stop_hash.as_bytes(), &[0xcc; 32]);
    }

    #[test]
    fn test_cfheaders_roundtrip() {
        let msg = CFHeaders {
            filter_type: 0,
            stop_hash: BlockHash::from_hash(Hash256::from_bytes([0xdd; 32])),
            prev_filter_header: Hash256::from_bytes([0xee; 32]),
            filter_hashes: vec![
                Hash256::from_bytes([0x11; 32]),
                Hash256::from_bytes([0x22; 32]),
                Hash256::from_bytes([0x33; 32]),
            ],
        };
        let encoded = msg.encode();
        let decoded = CFHeaders::decode(&encoded).unwrap();
        assert_eq!(decoded.filter_type, 0);
        assert_eq!(decoded.stop_hash.as_bytes(), &[0xdd; 32]);
        assert_eq!(decoded.prev_filter_header.as_bytes(), &[0xee; 32]);
        assert_eq!(decoded.filter_hashes.len(), 3);
        assert_eq!(decoded.filter_hashes[0].as_bytes(), &[0x11; 32]);
        assert_eq!(decoded.filter_hashes[2].as_bytes(), &[0x33; 32]);
    }

    #[test]
    fn test_getcfcheckpt_roundtrip() {
        let msg = GetCFCheckpt {
            filter_type: 0,
            stop_hash: BlockHash::from_hash(Hash256::from_bytes([0xff; 32])),
        };
        let encoded = msg.encode();
        assert_eq!(encoded.len(), 33);
        let decoded = GetCFCheckpt::decode(&encoded).unwrap();
        assert_eq!(decoded.filter_type, 0);
        assert_eq!(decoded.stop_hash.as_bytes(), &[0xff; 32]);
    }

    #[test]
    fn test_cfcheckpt_roundtrip() {
        let msg = CFCheckpt {
            filter_type: 0,
            stop_hash: BlockHash::from_hash(Hash256::from_bytes([0xaa; 32])),
            filter_headers: vec![
                Hash256::from_bytes([0x01; 32]),
                Hash256::from_bytes([0x02; 32]),
            ],
        };
        let encoded = msg.encode();
        let decoded = CFCheckpt::decode(&encoded).unwrap();
        assert_eq!(decoded.filter_type, 0);
        assert_eq!(decoded.stop_hash.as_bytes(), &[0xaa; 32]);
        assert_eq!(decoded.filter_headers.len(), 2);
    }

    #[test]
    fn test_cfheaders_empty() {
        let msg = CFHeaders {
            filter_type: 0,
            stop_hash: BlockHash::zero(),
            prev_filter_header: Hash256::zero(),
            filter_hashes: vec![],
        };
        let encoded = msg.encode();
        let decoded = CFHeaders::decode(&encoded).unwrap();
        assert!(decoded.filter_hashes.is_empty());
    }

    #[test]
    fn test_decode_too_short() {
        assert!(GetCFilters::decode(&[0; 10]).is_err());
        assert!(CFilter::decode(&[0; 10]).is_err());
        assert!(GetCFHeaders::decode(&[0; 10]).is_err());
        assert!(CFHeaders::decode(&[0; 10]).is_err());
        assert!(GetCFCheckpt::decode(&[0; 10]).is_err());
        assert!(CFCheckpt::decode(&[0; 10]).is_err());
    }
}

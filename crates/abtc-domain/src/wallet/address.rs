//! Bitcoin address derivation and encoding
//!
//! Supports P2PKH (legacy), P2WPKH (native SegWit), and P2SH-P2WPKH (wrapped SegWit).
//! Includes Base58Check for legacy addresses and Bech32 for native SegWit.

use super::keys::{base58check_decode, base58check_encode, KeyError, PublicKey};
use crate::crypto::hashing;
use crate::script::{Opcodes, Script, ScriptBuilder};

/// Bitcoin address types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressType {
    /// Legacy Pay-to-Public-Key-Hash (1...)
    P2PKH,
    /// Native SegWit Pay-to-Witness-Public-Key-Hash (bc1q...)
    P2WPKH,
    /// Wrapped SegWit Pay-to-Script-Hash(Pay-to-Witness-PKH) (3...)
    P2shP2wpkh,
    /// Taproot Pay-to-Taproot (bc1p...)
    P2TR,
}

/// A Bitcoin address (string encoding + metadata)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    /// The encoded address string
    pub encoded: String,
    /// The address type
    pub address_type: AddressType,
    /// Whether this is a mainnet address
    pub mainnet: bool,
    /// The script pubkey this address corresponds to
    pub script_pubkey: Script,
}

/// Address encoding/decoding errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressError {
    /// Invalid address format
    InvalidFormat(String),
    /// Unknown address version
    UnknownVersion(u8),
    /// Wrong network
    WrongNetwork,
    /// Invalid bech32 encoding
    InvalidBech32(String),
    /// Key error
    Key(KeyError),
}

impl std::fmt::Display for AddressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddressError::InvalidFormat(msg) => write!(f, "invalid address format: {}", msg),
            AddressError::UnknownVersion(v) => write!(f, "unknown address version: 0x{:02x}", v),
            AddressError::WrongNetwork => write!(f, "address is for wrong network"),
            AddressError::InvalidBech32(msg) => write!(f, "invalid bech32: {}", msg),
            AddressError::Key(e) => write!(f, "key error: {}", e),
        }
    }
}

impl std::error::Error for AddressError {}

impl From<KeyError> for AddressError {
    fn from(e: KeyError) -> Self {
        AddressError::Key(e)
    }
}

impl Address {
    /// Derive a P2PKH address from a public key.
    ///
    /// Format: Base58Check( version_byte | pubkey_hash )
    /// Mainnet version = 0x00 (starts with '1')
    /// Testnet version = 0x6F (starts with 'm' or 'n')
    pub fn p2pkh(pubkey: &PublicKey, mainnet: bool) -> Self {
        let hash = pubkey.pubkey_hash();
        let version = if mainnet { 0x00 } else { 0x6F };

        let mut payload = Vec::with_capacity(21);
        payload.push(version);
        payload.extend_from_slice(&hash);

        let encoded = base58check_encode(&payload);

        // Build scriptPubKey: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        let script_pubkey = ScriptBuilder::new()
            .push_opcode(Opcodes::OP_DUP)
            .push_opcode(Opcodes::OP_HASH160)
            .push_slice(&hash)
            .push_opcode(Opcodes::OP_EQUALVERIFY)
            .push_opcode(Opcodes::OP_CHECKSIG)
            .build();

        Address {
            encoded,
            address_type: AddressType::P2PKH,
            mainnet,
            script_pubkey,
        }
    }

    /// Derive a P2WPKH (native SegWit) address from a public key.
    ///
    /// Format: Bech32( hrp, witness_version=0, pubkey_hash )
    /// Mainnet hrp = "bc", testnet hrp = "tb"
    ///
    /// Requires compressed public key.
    pub fn p2wpkh(pubkey: &PublicKey, mainnet: bool) -> Result<Self, AddressError> {
        if !pubkey.compressed() {
            return Err(AddressError::InvalidFormat(
                "P2WPKH requires compressed public key".into(),
            ));
        }

        let hash = pubkey.pubkey_hash();
        let hrp = if mainnet { "bc" } else { "tb" };

        let encoded = bech32_encode(hrp, 0, &hash);

        // Build scriptPubKey: OP_0 <20-byte pubkey hash>
        let mut spk_bytes = Vec::with_capacity(22);
        spk_bytes.push(0x00); // OP_0
        spk_bytes.push(20); // push 20 bytes
        spk_bytes.extend_from_slice(&hash);
        let script_pubkey = Script::from_bytes(spk_bytes);

        Ok(Address {
            encoded,
            address_type: AddressType::P2WPKH,
            mainnet,
            script_pubkey,
        })
    }

    /// Derive a P2SH-P2WPKH (wrapped SegWit) address from a public key.
    ///
    /// The redeem script is: OP_0 <20-byte pubkey hash>
    /// The address is: Base58Check( version | HASH160(redeem_script) )
    /// Mainnet P2SH version = 0x05 (starts with '3')
    /// Testnet P2SH version = 0xC4 (starts with '2')
    pub fn p2sh_p2wpkh(pubkey: &PublicKey, mainnet: bool) -> Result<Self, AddressError> {
        if !pubkey.compressed() {
            return Err(AddressError::InvalidFormat(
                "P2SH-P2WPKH requires compressed public key".into(),
            ));
        }

        let hash = pubkey.pubkey_hash();

        // Build redeem script: OP_0 <20-byte pubkey hash>
        let mut redeem_script = Vec::with_capacity(22);
        redeem_script.push(0x00); // OP_0
        redeem_script.push(20);
        redeem_script.extend_from_slice(&hash);

        // P2SH address uses HASH160 of the redeem script
        let script_hash = hashing::hash160(&redeem_script);

        let version = if mainnet { 0x05 } else { 0xC4 };
        let mut payload = Vec::with_capacity(21);
        payload.push(version);
        payload.extend_from_slice(&script_hash);

        let encoded = base58check_encode(&payload);

        // Build scriptPubKey: OP_HASH160 <20-byte script hash> OP_EQUAL
        let script_pubkey = ScriptBuilder::new()
            .push_opcode(Opcodes::OP_HASH160)
            .push_slice(&script_hash)
            .push_opcode(Opcodes::OP_EQUAL)
            .build();

        Ok(Address {
            encoded,
            address_type: AddressType::P2shP2wpkh,
            mainnet,
            script_pubkey,
        })
    }

    /// Derive a P2TR (Taproot) address from an x-only output public key.
    ///
    /// The output key is typically computed as:
    ///   output_key = internal_key + tagged_hash("TapTweak", internal_key [|| merkle_root]) * G
    ///
    /// For key-path-only outputs (no scripts), the merkle_root is omitted.
    ///
    /// Format: Bech32m( hrp, witness_version=1, output_key )
    /// Mainnet: starts with 'bc1p', Testnet: starts with 'tb1p'
    ///
    /// # Arguments
    /// * `output_key` - 32-byte x-only public key (the tweaked output key)
    /// * `mainnet` - Whether this is a mainnet address
    pub fn p2tr(output_key: &[u8; 32], mainnet: bool) -> Self {
        let hrp = if mainnet { "bc" } else { "tb" };

        let encoded = bech32m_encode(hrp, 1, output_key);

        // Build scriptPubKey: OP_1 <32-byte output key>
        let mut spk_bytes = Vec::with_capacity(34);
        spk_bytes.push(0x51); // OP_1
        spk_bytes.push(32); // push 32 bytes
        spk_bytes.extend_from_slice(output_key);
        let script_pubkey = Script::from_bytes(spk_bytes);

        Address {
            encoded,
            address_type: AddressType::P2TR,
            mainnet,
            script_pubkey,
        }
    }

    /// Derive a P2TR address from an internal key (convenience wrapper).
    ///
    /// Computes the output key by tweaking the internal key with no script tree
    /// (key-path-only), then creates the address.
    ///
    /// # Arguments
    /// * `internal_key` - 32-byte x-only internal public key
    /// * `mainnet` - Whether this is a mainnet address
    pub fn p2tr_from_internal_key(
        internal_key: &[u8; 32],
        mainnet: bool,
    ) -> Result<Self, AddressError> {
        use secp256k1::{Scalar, Secp256k1, XOnlyPublicKey};

        let secp = Secp256k1::verification_only();

        let pk = XOnlyPublicKey::from_slice(internal_key)
            .map_err(|e| AddressError::InvalidFormat(format!("invalid internal key: {}", e)))?;

        // Tweak: t = tagged_hash("TapTweak", internal_key)  (no merkle root)
        let tweak = crate::crypto::taproot::taptweak_hash(internal_key, None);
        let scalar = Scalar::from_be_bytes(tweak)
            .map_err(|_| AddressError::InvalidFormat("tweak overflow".into()))?;

        let (output_key, _parity) = pk
            .add_tweak(&secp, &scalar)
            .map_err(|e| AddressError::InvalidFormat(format!("tweak failed: {}", e)))?;

        Ok(Self::p2tr(&output_key.serialize(), mainnet))
    }

    /// Decode a Bitcoin address string back into its script pubkey.
    ///
    /// Supports P2PKH (1.../m.../n...), P2SH (3.../2...), P2WPKH (bc1q.../tb1q...),
    /// and P2TR (bc1p.../tb1p...).
    pub fn decode(address: &str) -> Result<Self, AddressError> {
        // Try bech32 first
        if address.starts_with("bc1") || address.starts_with("tb1") {
            return Self::decode_bech32(address);
        }

        // Try Base58Check
        Self::decode_base58(address)
    }

    fn decode_base58(address: &str) -> Result<Self, AddressError> {
        let payload = base58check_decode(address).map_err(AddressError::Key)?;

        if payload.len() != 21 {
            return Err(AddressError::InvalidFormat(format!(
                "expected 21 bytes, got {}",
                payload.len()
            )));
        }

        let version = payload[0];
        let hash = &payload[1..21];

        match version {
            // P2PKH mainnet
            0x00 => {
                let script_pubkey = ScriptBuilder::new()
                    .push_opcode(Opcodes::OP_DUP)
                    .push_opcode(Opcodes::OP_HASH160)
                    .push_slice(hash)
                    .push_opcode(Opcodes::OP_EQUALVERIFY)
                    .push_opcode(Opcodes::OP_CHECKSIG)
                    .build();

                Ok(Address {
                    encoded: address.to_string(),
                    address_type: AddressType::P2PKH,
                    mainnet: true,
                    script_pubkey,
                })
            }
            // P2PKH testnet
            0x6F => {
                let script_pubkey = ScriptBuilder::new()
                    .push_opcode(Opcodes::OP_DUP)
                    .push_opcode(Opcodes::OP_HASH160)
                    .push_slice(hash)
                    .push_opcode(Opcodes::OP_EQUALVERIFY)
                    .push_opcode(Opcodes::OP_CHECKSIG)
                    .build();

                Ok(Address {
                    encoded: address.to_string(),
                    address_type: AddressType::P2PKH,
                    mainnet: false,
                    script_pubkey,
                })
            }
            // P2SH mainnet
            0x05 => {
                let script_pubkey = ScriptBuilder::new()
                    .push_opcode(Opcodes::OP_HASH160)
                    .push_slice(hash)
                    .push_opcode(Opcodes::OP_EQUAL)
                    .build();

                Ok(Address {
                    encoded: address.to_string(),
                    address_type: AddressType::P2shP2wpkh,
                    mainnet: true,
                    script_pubkey,
                })
            }
            // P2SH testnet
            0xC4 => {
                let script_pubkey = ScriptBuilder::new()
                    .push_opcode(Opcodes::OP_HASH160)
                    .push_slice(hash)
                    .push_opcode(Opcodes::OP_EQUAL)
                    .build();

                Ok(Address {
                    encoded: address.to_string(),
                    address_type: AddressType::P2shP2wpkh,
                    mainnet: false,
                    script_pubkey,
                })
            }
            _ => Err(AddressError::UnknownVersion(version)),
        }
    }

    fn decode_bech32(address: &str) -> Result<Self, AddressError> {
        let (hrp, version, program, encoding) = bech32_decode_versioned(address)?;

        let mainnet = hrp == "bc";

        // BIP350: witness v0 uses bech32, witness v1+ uses bech32m
        match version {
            0 => {
                if encoding != Bech32Encoding::Bech32 {
                    return Err(AddressError::InvalidBech32(
                        "witness v0 must use bech32 (not bech32m)".into(),
                    ));
                }
                if program.len() == 20 {
                    // P2WPKH
                    let mut spk_bytes = Vec::with_capacity(22);
                    spk_bytes.push(0x00); // OP_0
                    spk_bytes.push(20);
                    spk_bytes.extend_from_slice(&program);

                    Ok(Address {
                        encoded: address.to_string(),
                        address_type: AddressType::P2WPKH,
                        mainnet,
                        script_pubkey: Script::from_bytes(spk_bytes),
                    })
                } else {
                    Err(AddressError::InvalidFormat(format!(
                        "unsupported v0 program length {}",
                        program.len()
                    )))
                }
            }
            1 => {
                if encoding != Bech32Encoding::Bech32m {
                    return Err(AddressError::InvalidBech32(
                        "witness v1+ must use bech32m (not bech32)".into(),
                    ));
                }
                if program.len() == 32 {
                    // P2TR
                    let mut spk_bytes = Vec::with_capacity(34);
                    spk_bytes.push(0x51); // OP_1
                    spk_bytes.push(32);
                    spk_bytes.extend_from_slice(&program);

                    Ok(Address {
                        encoded: address.to_string(),
                        address_type: AddressType::P2TR,
                        mainnet,
                        script_pubkey: Script::from_bytes(spk_bytes),
                    })
                } else {
                    Err(AddressError::InvalidFormat(format!(
                        "unsupported v1 program length {}",
                        program.len()
                    )))
                }
            }
            _ => Err(AddressError::InvalidFormat(format!(
                "unsupported witness version {} with program length {}",
                version,
                program.len()
            ))),
        }
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.encoded)
    }
}

// ---- Bech32 encoding/decoding (BIP173) ----

const BECH32_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

fn bech32_polymod(values: &[u8]) -> u32 {
    let mut chk: u32 = 1;
    for &v in values {
        let top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ (v as u32);
        for (i, gen) in BECH32_GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= gen;
            }
        }
    }
    chk
}

fn bech32_hrp_expand(hrp: &str) -> Vec<u8> {
    let mut result = Vec::with_capacity(hrp.len() * 2 + 1);
    for c in hrp.chars() {
        result.push((c as u8) >> 5);
    }
    result.push(0);
    for c in hrp.chars() {
        result.push((c as u8) & 31);
    }
    result
}

/// Bech32 vs Bech32m encoding variant (BIP350).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Bech32Encoding {
    /// Original bech32 (BIP173) — for witness v0
    Bech32,
    /// Bech32m (BIP350) — for witness v1+
    Bech32m,
}

/// Bech32m constant (BIP350): replaces the `1` used in bech32.
const BECH32M_CONST: u32 = 0x2bc830a3;

fn bech32_create_checksum(hrp: &str, data: &[u8]) -> Vec<u8> {
    bech32_create_checksum_with(hrp, data, Bech32Encoding::Bech32)
}

fn bech32_create_checksum_with(hrp: &str, data: &[u8], encoding: Bech32Encoding) -> Vec<u8> {
    let mut values = bech32_hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    let constant = match encoding {
        Bech32Encoding::Bech32 => 1,
        Bech32Encoding::Bech32m => BECH32M_CONST,
    };
    let polymod = bech32_polymod(&values) ^ constant;
    (0..6)
        .map(|i| ((polymod >> (5 * (5 - i))) & 31) as u8)
        .collect()
}

// Old bech32-only checksum removed; use bech32_verify_checksum_encoding instead.

fn bech32_verify_checksum_encoding(hrp: &str, data: &[u8]) -> Option<Bech32Encoding> {
    let mut values = bech32_hrp_expand(hrp);
    values.extend_from_slice(data);
    let residue = bech32_polymod(&values);
    if residue == 1 {
        Some(Bech32Encoding::Bech32)
    } else if residue == BECH32M_CONST {
        Some(Bech32Encoding::Bech32m)
    } else {
        None
    }
}

/// Convert 8-bit data to 5-bit groups (for bech32)
fn convert_bits_8_to_5(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;

    for &byte in data {
        acc = (acc << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            result.push(((acc >> bits) & 31) as u8);
        }
    }

    if bits > 0 {
        result.push(((acc << (5 - bits)) & 31) as u8);
    }

    result
}

/// Convert 5-bit data back to 8-bit bytes
fn convert_bits_5_to_8(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;

    for &v in data {
        acc = (acc << 5) | v as u32;
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            result.push(((acc >> bits) & 0xff) as u8);
        }
    }

    result
}

/// Encode a witness program as a bech32 address
fn bech32_encode(hrp: &str, witness_version: u8, program: &[u8]) -> String {
    let mut data = vec![witness_version];
    data.extend_from_slice(&convert_bits_8_to_5(program));

    let checksum = bech32_create_checksum(hrp, &data);
    data.extend_from_slice(&checksum);

    let mut result = String::from(hrp);
    result.push('1'); // separator
    for &d in &data {
        result.push(BECH32_CHARSET[d as usize] as char);
    }

    result
}

/// Encode a witness program as a bech32m address (BIP350, for witness v1+).
fn bech32m_encode(hrp: &str, witness_version: u8, program: &[u8]) -> String {
    let mut data = vec![witness_version];
    data.extend_from_slice(&convert_bits_8_to_5(program));

    let checksum = bech32_create_checksum_with(hrp, &data, Bech32Encoding::Bech32m);
    data.extend_from_slice(&checksum);

    let mut result = String::from(hrp);
    result.push('1'); // separator
    for &d in &data {
        result.push(BECH32_CHARSET[d as usize] as char);
    }

    result
}

/// Decode a bech32/bech32m address → (hrp, witness_version, program, encoding)
fn bech32_decode_versioned(
    address: &str,
) -> Result<(String, u8, Vec<u8>, Bech32Encoding), AddressError> {
    let lower = address.to_lowercase();

    let sep = lower
        .rfind('1')
        .ok_or_else(|| AddressError::InvalidBech32("no separator".into()))?;

    if sep < 1 {
        return Err(AddressError::InvalidBech32("empty HRP".into()));
    }

    let hrp = &lower[..sep];
    let data_str = &lower[sep + 1..];

    if data_str.len() < 6 {
        return Err(AddressError::InvalidBech32("data too short".into()));
    }

    let mut data = Vec::with_capacity(data_str.len());
    for c in data_str.chars() {
        let pos = BECH32_CHARSET
            .iter()
            .position(|&ch| ch == c as u8)
            .ok_or_else(|| AddressError::InvalidBech32(format!("invalid char: {}", c)))?;
        data.push(pos as u8);
    }

    let encoding = bech32_verify_checksum_encoding(hrp, &data)
        .ok_or_else(|| AddressError::InvalidBech32("checksum failed".into()))?;

    // Remove checksum (last 6 bytes)
    let data = &data[..data.len() - 6];

    if data.is_empty() {
        return Err(AddressError::InvalidBech32("empty data".into()));
    }

    let witness_version = data[0];
    let program = convert_bits_5_to_8(&data[1..]);

    Ok((hrp.to_string(), witness_version, program, encoding))
}

// Old bech32_decode removed; use bech32_decode_versioned instead.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::keys::PrivateKey;

    #[test]
    fn test_p2pkh_mainnet() {
        let key = PrivateKey::generate(true, true);
        let pubkey = key.public_key();
        let addr = Address::p2pkh(&pubkey, true);

        assert!(addr.encoded.starts_with('1'));
        assert_eq!(addr.address_type, AddressType::P2PKH);
        assert!(addr.mainnet);
        assert!(addr.script_pubkey.is_p2pkh());
    }

    #[test]
    fn test_p2pkh_testnet() {
        let key = PrivateKey::generate(true, false);
        let pubkey = key.public_key();
        let addr = Address::p2pkh(&pubkey, false);

        assert!(addr.encoded.starts_with('m') || addr.encoded.starts_with('n'));
        assert!(!addr.mainnet);
    }

    #[test]
    fn test_p2wpkh_mainnet() {
        let key = PrivateKey::generate(true, true);
        let pubkey = key.public_key();
        let addr = Address::p2wpkh(&pubkey, true).unwrap();

        assert!(addr.encoded.starts_with("bc1q"));
        assert_eq!(addr.address_type, AddressType::P2WPKH);
        assert!(addr.mainnet);
        assert!(addr.script_pubkey.is_p2wpkh());
    }

    #[test]
    fn test_p2wpkh_testnet() {
        let key = PrivateKey::generate(true, false);
        let pubkey = key.public_key();
        let addr = Address::p2wpkh(&pubkey, false).unwrap();

        assert!(addr.encoded.starts_with("tb1q"));
    }

    #[test]
    fn test_p2wpkh_rejects_uncompressed() {
        let key = PrivateKey::generate(false, true);
        let pubkey = key.public_key();
        let result = Address::p2wpkh(&pubkey, true);
        assert!(result.is_err());
    }

    #[test]
    fn test_p2sh_p2wpkh_mainnet() {
        let key = PrivateKey::generate(true, true);
        let pubkey = key.public_key();
        let addr = Address::p2sh_p2wpkh(&pubkey, true).unwrap();

        assert!(addr.encoded.starts_with('3'));
        assert_eq!(addr.address_type, AddressType::P2shP2wpkh);
        assert!(addr.script_pubkey.is_p2sh());
    }

    #[test]
    fn test_address_decode_p2pkh() {
        let key = PrivateKey::generate(true, true);
        let pubkey = key.public_key();
        let addr = Address::p2pkh(&pubkey, true);

        let decoded = Address::decode(&addr.encoded).unwrap();
        assert_eq!(decoded.address_type, AddressType::P2PKH);
        assert_eq!(
            decoded.script_pubkey.as_bytes(),
            addr.script_pubkey.as_bytes()
        );
    }

    #[test]
    fn test_address_decode_p2wpkh() {
        let key = PrivateKey::generate(true, true);
        let pubkey = key.public_key();
        let addr = Address::p2wpkh(&pubkey, true).unwrap();

        let decoded = Address::decode(&addr.encoded).unwrap();
        assert_eq!(decoded.address_type, AddressType::P2WPKH);
        assert_eq!(
            decoded.script_pubkey.as_bytes(),
            addr.script_pubkey.as_bytes()
        );
    }

    #[test]
    fn test_bech32_roundtrip() {
        let program = [
            0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c, 0x45, 0xd1, 0xb3,
            0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6,
        ];

        let encoded = bech32_encode("bc", 0, &program);
        assert!(encoded.starts_with("bc1q"));

        let (hrp, version, decoded_program, encoding) = bech32_decode_versioned(&encoded).unwrap();
        assert_eq!(hrp, "bc");
        assert_eq!(version, 0);
        assert_eq!(decoded_program, program);
        assert!(matches!(encoding, Bech32Encoding::Bech32));
    }

    // ── P2TR (Taproot) address tests ───────────────────────────────

    #[test]
    fn test_p2tr_mainnet() {
        // Use a known 32-byte x-only output key
        let output_key = [0x42; 32];
        let addr = Address::p2tr(&output_key, true);

        assert!(addr.encoded.starts_with("bc1p"));
        assert_eq!(addr.address_type, AddressType::P2TR);
        assert!(addr.mainnet);
        assert!(addr.script_pubkey.is_p2tr());
        assert_eq!(addr.script_pubkey.as_bytes().len(), 34);
        assert_eq!(addr.script_pubkey.as_bytes()[0], 0x51); // OP_1
        assert_eq!(addr.script_pubkey.as_bytes()[1], 32); // push 32
        assert_eq!(&addr.script_pubkey.as_bytes()[2..], &output_key);
    }

    #[test]
    fn test_p2tr_testnet() {
        let output_key = [0x42; 32];
        let addr = Address::p2tr(&output_key, false);

        assert!(addr.encoded.starts_with("tb1p"));
        assert_eq!(addr.address_type, AddressType::P2TR);
        assert!(!addr.mainnet);
    }

    #[test]
    fn test_p2tr_decode_roundtrip() {
        let output_key = [0x42; 32];
        let addr = Address::p2tr(&output_key, true);

        let decoded = Address::decode(&addr.encoded).unwrap();
        assert_eq!(decoded.address_type, AddressType::P2TR);
        assert_eq!(
            decoded.script_pubkey.as_bytes(),
            addr.script_pubkey.as_bytes()
        );
        assert!(decoded.mainnet);
    }

    #[test]
    fn test_p2tr_decode_testnet_roundtrip() {
        let output_key = [0x42; 32];
        let addr = Address::p2tr(&output_key, false);

        let decoded = Address::decode(&addr.encoded).unwrap();
        assert_eq!(decoded.address_type, AddressType::P2TR);
        assert!(!decoded.mainnet);
    }

    #[test]
    fn test_p2tr_from_internal_key() {
        use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};

        let secret = SecretKey::from_slice(&[0x42; 32]).unwrap();
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let (xonly, _) = XOnlyPublicKey::from_keypair(&keypair);

        let addr = Address::p2tr_from_internal_key(&xonly.serialize(), true).unwrap();

        assert!(addr.encoded.starts_with("bc1p"));
        assert_eq!(addr.address_type, AddressType::P2TR);
        assert!(addr.script_pubkey.is_p2tr());

        // Decode roundtrip
        let decoded = Address::decode(&addr.encoded).unwrap();
        assert_eq!(
            decoded.script_pubkey.as_bytes(),
            addr.script_pubkey.as_bytes()
        );
    }

    #[test]
    fn test_bech32m_roundtrip() {
        // Test that bech32m encode/decode is consistent
        let program = [0x42; 32];
        let encoded = bech32m_encode("bc", 1, &program);
        assert!(encoded.starts_with("bc1p"));

        let (hrp, version, decoded_program, encoding) = bech32_decode_versioned(&encoded).unwrap();
        assert_eq!(hrp, "bc");
        assert_eq!(version, 1);
        assert_eq!(decoded_program, program);
        assert_eq!(encoding, Bech32Encoding::Bech32m);
    }

    #[test]
    fn test_bech32_vs_bech32m_different_checksums() {
        // Verify that bech32 and bech32m produce different encodings
        // for the same data (different checksum constants)
        let program = [0x42; 32];
        let bech32_addr = bech32_encode("bc", 1, &program);
        let bech32m_addr = bech32m_encode("bc", 1, &program);

        // Same data part but different checksums → different last 6 chars
        assert_ne!(bech32_addr, bech32m_addr);
    }
}

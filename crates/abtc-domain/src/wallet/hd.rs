//! BIP32 Hierarchical Deterministic Key Derivation
//!
//! Implements the BIP32 standard for deterministic key trees, plus BIP44
//! derivation path helpers. A single master seed (typically 16-64 bytes from
//! a BIP39 mnemonic) can derive an effectively unlimited tree of child keys.
//!
//! ## Key path notation
//!
//! `m / purpose' / coin_type' / account' / change / address_index`
//!
//! where `'` denotes hardened derivation.
//!
//! ## References
//!
//! - BIP32: <https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki>
//! - BIP44: <https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki>

use crate::crypto::hashing;
use crate::wallet::keys::{
    base58check_decode, base58check_encode, KeyError, PrivateKey, PublicKey,
};
use hmac::{Hmac, Mac};
use secp256k1::{Secp256k1, SecretKey};
use sha2::Sha512;

type HmacSha512 = Hmac<Sha512>;

// ── Constants ───────────────────────────────────────────────────────

/// Hardened key offset (2^31).
pub const HARDENED_OFFSET: u32 = 0x8000_0000;

/// BIP44 purpose constant (44').
pub const BIP44_PURPOSE: u32 = 44;

/// Coin type for Bitcoin mainnet (0').
pub const COIN_TYPE_BITCOIN: u32 = 0;

/// Coin type for Bitcoin testnet (1').
pub const COIN_TYPE_TESTNET: u32 = 1;

/// Version bytes for xpub (mainnet).
const XPUB_VERSION: [u8; 4] = [0x04, 0x88, 0xB2, 0x1E];

/// Version bytes for xprv (mainnet).
const XPRV_VERSION: [u8; 4] = [0x04, 0x88, 0xAD, 0xE4];

/// Version bytes for tpub (testnet).
const TPUB_VERSION: [u8; 4] = [0x04, 0x35, 0x87, 0xCF];

/// Version bytes for tprv (testnet).
const TPRV_VERSION: [u8; 4] = [0x04, 0x35, 0x83, 0x94];

// ── Extended key types ──────────────────────────────────────────────

/// An extended private key (BIP32).
///
/// Carries a 256-bit private key plus a 256-bit chain code.
/// The chain code provides the entropy needed for child derivation.
#[derive(Clone)]
pub struct ExtendedPrivateKey {
    /// The 32-byte private key.
    secret_key: SecretKey,
    /// The 32-byte chain code.
    chain_code: [u8; 32],
    /// Depth in the derivation tree (0 = master).
    depth: u8,
    /// The index at which this key was derived from its parent.
    child_number: u32,
    /// First 4 bytes of Hash160 of the parent's serialised public key.
    parent_fingerprint: [u8; 4],
    /// Whether this key is for mainnet.
    mainnet: bool,
}

/// An extended public key (BIP32).
///
/// Can derive non-hardened child public keys without the private key.
#[derive(Clone, Debug)]
pub struct ExtendedPublicKey {
    /// The compressed public key (33 bytes).
    public_key: secp256k1::PublicKey,
    /// The 32-byte chain code.
    chain_code: [u8; 32],
    /// Depth in the derivation tree.
    depth: u8,
    /// The index at which this key was derived from its parent.
    child_number: u32,
    /// First 4 bytes of Hash160 of the parent's serialised public key.
    parent_fingerprint: [u8; 4],
    /// Whether this key is for mainnet.
    mainnet: bool,
}

/// Errors during HD key derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HdError {
    /// Seed is too short (must be 16-64 bytes).
    InvalidSeedLength,
    /// HMAC produced an invalid secret key (astronomically unlikely).
    InvalidChildKey,
    /// Attempted hardened derivation from a public key.
    HardenedFromPublic,
    /// Invalid serialised extended key.
    InvalidExtendedKey(String),
    /// Key-level error.
    KeyError(KeyError),
}

impl std::fmt::Display for HdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HdError::InvalidSeedLength => write!(f, "seed must be 16-64 bytes"),
            HdError::InvalidChildKey => write!(f, "derived key is invalid (try next index)"),
            HdError::HardenedFromPublic => {
                write!(f, "cannot do hardened derivation from public key")
            }
            HdError::InvalidExtendedKey(msg) => write!(f, "invalid extended key: {}", msg),
            HdError::KeyError(e) => write!(f, "key error: {}", e),
        }
    }
}

impl std::error::Error for HdError {}

impl From<KeyError> for HdError {
    fn from(e: KeyError) -> Self {
        HdError::KeyError(e)
    }
}

// ── Master key generation ───────────────────────────────────────────

impl ExtendedPrivateKey {
    /// Generate a master key from a seed (BIP32 §2.1).
    ///
    /// The seed should be 16-64 bytes (128-512 bits). A BIP39 mnemonic
    /// typically produces a 64-byte seed.
    pub fn from_seed(seed: &[u8], mainnet: bool) -> Result<Self, HdError> {
        if seed.len() < 16 || seed.len() > 64 {
            return Err(HdError::InvalidSeedLength);
        }

        let mut mac =
            HmacSha512::new_from_slice(b"Bitcoin seed").expect("HMAC can take any key size");
        mac.update(seed);
        let result = mac.finalize().into_bytes();

        let secret_key =
            SecretKey::from_slice(&result[..32]).map_err(|_| HdError::InvalidChildKey)?;
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&result[32..]);

        Ok(ExtendedPrivateKey {
            secret_key,
            chain_code,
            depth: 0,
            child_number: 0,
            parent_fingerprint: [0; 4],
            mainnet,
        })
    }

    /// Derive a child extended private key at the given index.
    ///
    /// For hardened derivation, add [`HARDENED_OFFSET`] to the index.
    pub fn derive_child(&self, index: u32) -> Result<Self, HdError> {
        let secp = Secp256k1::new();
        let public_key = secp256k1::PublicKey::from_secret_key(&secp, &self.secret_key);

        let mut mac =
            HmacSha512::new_from_slice(&self.chain_code).expect("HMAC can take any key size");

        if index >= HARDENED_OFFSET {
            // Hardened child: HMAC-SHA512(key = chain_code, data = 0x00 || secret_key || index)
            mac.update(&[0x00]);
            mac.update(&self.secret_key.secret_bytes());
        } else {
            // Normal child: HMAC-SHA512(key = chain_code, data = public_key || index)
            mac.update(&public_key.serialize());
        }
        mac.update(&index.to_be_bytes());

        let result = mac.finalize().into_bytes();

        // Parse IL as a 256-bit big-endian integer and add to parent key (mod n).
        let il = SecretKey::from_slice(&result[..32]).map_err(|_| HdError::InvalidChildKey)?;
        let child_key = self
            .secret_key
            .add_tweak(&il.into())
            .map_err(|_| HdError::InvalidChildKey)?;

        let mut child_chain_code = [0u8; 32];
        child_chain_code.copy_from_slice(&result[32..]);

        // Fingerprint = first 4 bytes of Hash160(parent compressed pubkey).
        let parent_pk_bytes = public_key.serialize();
        let hash = hashing::hash160(&parent_pk_bytes);
        let mut fingerprint = [0u8; 4];
        fingerprint.copy_from_slice(&hash[..4]);

        Ok(ExtendedPrivateKey {
            secret_key: child_key,
            chain_code: child_chain_code,
            depth: self.depth.saturating_add(1),
            child_number: index,
            parent_fingerprint: fingerprint,
            mainnet: self.mainnet,
        })
    }

    /// Derive along a path like `m/44'/0'/0'/0/0`.
    ///
    /// The path should be a slice of indices (with hardened offsets already applied).
    pub fn derive_path(&self, path: &[u32]) -> Result<Self, HdError> {
        let mut current = self.clone();
        for &index in path {
            current = current.derive_child(index)?;
        }
        Ok(current)
    }

    /// Get the BIP44 path for a Bitcoin address.
    ///
    /// `m / 44' / coin_type' / account' / change / address_index`
    pub fn derive_bip44(
        &self,
        account: u32,
        change: u32,
        address_index: u32,
    ) -> Result<Self, HdError> {
        let coin_type = if self.mainnet {
            COIN_TYPE_BITCOIN
        } else {
            COIN_TYPE_TESTNET
        };
        self.derive_path(&[
            BIP44_PURPOSE + HARDENED_OFFSET,
            coin_type + HARDENED_OFFSET,
            account + HARDENED_OFFSET,
            change,
            address_index,
        ])
    }

    /// Get the corresponding extended public key.
    pub fn to_extended_public_key(&self) -> ExtendedPublicKey {
        let secp = Secp256k1::new();
        let public_key = secp256k1::PublicKey::from_secret_key(&secp, &self.secret_key);
        ExtendedPublicKey {
            public_key,
            chain_code: self.chain_code,
            depth: self.depth,
            child_number: self.child_number,
            parent_fingerprint: self.parent_fingerprint,
            mainnet: self.mainnet,
        }
    }

    /// Get the underlying private key.
    pub fn private_key(&self) -> PrivateKey {
        let bytes = self.secret_key.secret_bytes();
        PrivateKey::from_bytes(&bytes, true, self.mainnet).expect("extended key always valid")
    }

    /// Get the corresponding public key.
    pub fn public_key(&self) -> PublicKey {
        self.private_key().public_key()
    }

    /// Serialise as xprv/tprv (Base58Check, 78 bytes payload).
    pub fn to_base58(&self) -> String {
        let version = if self.mainnet {
            XPRV_VERSION
        } else {
            TPRV_VERSION
        };
        let mut data = Vec::with_capacity(78);
        data.extend_from_slice(&version);
        data.push(self.depth);
        data.extend_from_slice(&self.parent_fingerprint);
        data.extend_from_slice(&self.child_number.to_be_bytes());
        data.extend_from_slice(&self.chain_code);
        data.push(0x00); // padding byte before private key
        data.extend_from_slice(&self.secret_key.secret_bytes());
        base58check_encode(&data)
    }

    /// Deserialise from xprv/tprv Base58Check string.
    pub fn from_base58(s: &str) -> Result<Self, HdError> {
        let data = base58check_decode(s).map_err(|e| HdError::InvalidExtendedKey(e.to_string()))?;
        if data.len() != 78 {
            return Err(HdError::InvalidExtendedKey(format!(
                "expected 78 bytes, got {}",
                data.len()
            )));
        }

        let mut version = [0u8; 4];
        version.copy_from_slice(&data[0..4]);

        let mainnet = if version == XPRV_VERSION {
            true
        } else if version == TPRV_VERSION {
            false
        } else {
            return Err(HdError::InvalidExtendedKey("unknown version".into()));
        };

        let depth = data[4];
        let mut parent_fingerprint = [0u8; 4];
        parent_fingerprint.copy_from_slice(&data[5..9]);
        let child_number = u32::from_be_bytes([data[9], data[10], data[11], data[12]]);
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&data[13..45]);

        // data[45] should be 0x00 (padding)
        if data[45] != 0x00 {
            return Err(HdError::InvalidExtendedKey(
                "missing private key padding".into(),
            ));
        }

        let secret_key = SecretKey::from_slice(&data[46..78])
            .map_err(|_| HdError::InvalidExtendedKey("invalid private key".into()))?;

        Ok(ExtendedPrivateKey {
            secret_key,
            chain_code,
            depth,
            child_number,
            parent_fingerprint,
            mainnet,
        })
    }

    /// Depth in the derivation tree.
    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// Whether this is a mainnet key.
    pub fn is_mainnet(&self) -> bool {
        self.mainnet
    }

    /// The chain code.
    pub fn chain_code(&self) -> &[u8; 32] {
        &self.chain_code
    }

    /// The fingerprint of this key (first 4 bytes of Hash160 of public key).
    pub fn fingerprint(&self) -> [u8; 4] {
        let secp = Secp256k1::new();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &self.secret_key);
        let hash = hashing::hash160(&pk.serialize());
        let mut fp = [0u8; 4];
        fp.copy_from_slice(&hash[..4]);
        fp
    }
}

impl std::fmt::Debug for ExtendedPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ExtendedPrivateKey(depth={}, child={:#x}, mainnet={})",
            self.depth, self.child_number, self.mainnet
        )
    }
}

// ── Extended Public Key ─────────────────────────────────────────────

impl ExtendedPublicKey {
    /// Derive a non-hardened child public key.
    ///
    /// Hardened derivation is impossible without the private key.
    pub fn derive_child(&self, index: u32) -> Result<Self, HdError> {
        if index >= HARDENED_OFFSET {
            return Err(HdError::HardenedFromPublic);
        }

        let secp = Secp256k1::new();

        let mut mac =
            HmacSha512::new_from_slice(&self.chain_code).expect("HMAC can take any key size");
        mac.update(&self.public_key.serialize());
        mac.update(&index.to_be_bytes());

        let result = mac.finalize().into_bytes();

        // IL is treated as a tweak to the parent public key.
        let il = SecretKey::from_slice(&result[..32]).map_err(|_| HdError::InvalidChildKey)?;

        let child_pk = self
            .public_key
            .add_exp_tweak(&secp, &il.into())
            .map_err(|_| HdError::InvalidChildKey)?;

        let mut child_chain_code = [0u8; 32];
        child_chain_code.copy_from_slice(&result[32..]);

        let parent_hash = hashing::hash160(&self.public_key.serialize());
        let mut fingerprint = [0u8; 4];
        fingerprint.copy_from_slice(&parent_hash[..4]);

        Ok(ExtendedPublicKey {
            public_key: child_pk,
            chain_code: child_chain_code,
            depth: self.depth.saturating_add(1),
            child_number: index,
            parent_fingerprint: fingerprint,
            mainnet: self.mainnet,
        })
    }

    /// Derive along a path of non-hardened indices.
    pub fn derive_path(&self, path: &[u32]) -> Result<Self, HdError> {
        let mut current = self.clone();
        for &index in path {
            current = current.derive_child(index)?;
        }
        Ok(current)
    }

    /// Get the compressed public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from_bytes(&self.public_key.serialize()).expect("valid secp256k1 key")
    }

    /// Serialise as xpub/tpub (Base58Check, 78 bytes payload).
    pub fn to_base58(&self) -> String {
        let version = if self.mainnet {
            XPUB_VERSION
        } else {
            TPUB_VERSION
        };
        let mut data = Vec::with_capacity(78);
        data.extend_from_slice(&version);
        data.push(self.depth);
        data.extend_from_slice(&self.parent_fingerprint);
        data.extend_from_slice(&self.child_number.to_be_bytes());
        data.extend_from_slice(&self.chain_code);
        data.extend_from_slice(&self.public_key.serialize());
        base58check_encode(&data)
    }

    /// Deserialise from xpub/tpub Base58Check string.
    pub fn from_base58(s: &str) -> Result<Self, HdError> {
        let data = base58check_decode(s).map_err(|e| HdError::InvalidExtendedKey(e.to_string()))?;
        if data.len() != 78 {
            return Err(HdError::InvalidExtendedKey(format!(
                "expected 78 bytes, got {}",
                data.len()
            )));
        }

        let mut version = [0u8; 4];
        version.copy_from_slice(&data[0..4]);

        let mainnet = if version == XPUB_VERSION {
            true
        } else if version == TPUB_VERSION {
            false
        } else {
            return Err(HdError::InvalidExtendedKey("unknown version".into()));
        };

        let depth = data[4];
        let mut parent_fingerprint = [0u8; 4];
        parent_fingerprint.copy_from_slice(&data[5..9]);
        let child_number = u32::from_be_bytes([data[9], data[10], data[11], data[12]]);
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&data[13..45]);

        let public_key = secp256k1::PublicKey::from_slice(&data[45..78])
            .map_err(|_| HdError::InvalidExtendedKey("invalid public key".into()))?;

        Ok(ExtendedPublicKey {
            public_key,
            chain_code,
            depth,
            child_number,
            parent_fingerprint,
            mainnet,
        })
    }

    /// Depth in the derivation tree.
    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// The fingerprint of this key.
    pub fn fingerprint(&self) -> [u8; 4] {
        let hash = hashing::hash160(&self.public_key.serialize());
        let mut fp = [0u8; 4];
        fp.copy_from_slice(&hash[..4]);
        fp
    }
}

// ── Derivation path parsing ─────────────────────────────────────────

/// Parse a BIP32 derivation path string like "m/44'/0'/0'/0/0".
///
/// Returns a vector of child indices with hardened offsets applied.
pub fn parse_derivation_path(path: &str) -> Result<Vec<u32>, HdError> {
    let path = path.trim();
    if !path.starts_with('m') && !path.starts_with('M') {
        return Err(HdError::InvalidExtendedKey(
            "path must start with 'm'".into(),
        ));
    }

    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() < 2 {
        return Ok(Vec::new()); // just "m"
    }

    let mut indices = Vec::with_capacity(parts.len() - 1);
    for part in &parts[1..] {
        let (num_str, hardened) =
            if part.ends_with('\'') || part.ends_with('h') || part.ends_with('H') {
                (&part[..part.len() - 1], true)
            } else {
                (*part, false)
            };

        let index: u32 = num_str.parse().map_err(|_| {
            HdError::InvalidExtendedKey(format!("invalid path component: {}", part))
        })?;

        if hardened {
            indices.push(index + HARDENED_OFFSET);
        } else {
            indices.push(index);
        }
    }

    Ok(indices)
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// A well-known test seed from BIP32 test vector 1.
    const TEST_SEED_HEX: &str = "000102030405060708090a0b0c0d0e0f";

    fn test_seed() -> Vec<u8> {
        hex::decode(TEST_SEED_HEX).unwrap()
    }

    #[test]
    fn test_master_from_seed() {
        let master = ExtendedPrivateKey::from_seed(&test_seed(), true).unwrap();
        assert_eq!(master.depth(), 0);
        assert!(master.is_mainnet());
    }

    #[test]
    fn test_seed_too_short() {
        let short = vec![0u8; 10];
        assert!(ExtendedPrivateKey::from_seed(&short, true).is_err());
    }

    #[test]
    fn test_seed_too_long() {
        let long = vec![0u8; 65];
        assert!(ExtendedPrivateKey::from_seed(&long, true).is_err());
    }

    #[test]
    fn test_child_derivation_normal() {
        let master = ExtendedPrivateKey::from_seed(&test_seed(), true).unwrap();
        let child = master.derive_child(0).unwrap();
        assert_eq!(child.depth(), 1);

        // Different from master.
        assert_ne!(
            master.private_key().secret_bytes(),
            child.private_key().secret_bytes()
        );
    }

    #[test]
    fn test_child_derivation_hardened() {
        let master = ExtendedPrivateKey::from_seed(&test_seed(), true).unwrap();
        let child_h = master.derive_child(HARDENED_OFFSET).unwrap();
        assert_eq!(child_h.depth(), 1);

        // Different from normal child at index 0.
        let child_n = master.derive_child(0).unwrap();
        assert_ne!(
            child_h.private_key().secret_bytes(),
            child_n.private_key().secret_bytes()
        );
    }

    #[test]
    fn test_derive_path() {
        let master = ExtendedPrivateKey::from_seed(&test_seed(), true).unwrap();
        // m/0'/1
        let key = master.derive_path(&[HARDENED_OFFSET, 1]).unwrap();
        assert_eq!(key.depth(), 2);
    }

    #[test]
    fn test_bip44_derivation() {
        let master = ExtendedPrivateKey::from_seed(&test_seed(), true).unwrap();
        // m/44'/0'/0'/0/0
        let key = master.derive_bip44(0, 0, 0).unwrap();
        assert_eq!(key.depth(), 5);

        // Different addresses should produce different keys.
        let key2 = master.derive_bip44(0, 0, 1).unwrap();
        assert_ne!(
            key.private_key().secret_bytes(),
            key2.private_key().secret_bytes()
        );
    }

    #[test]
    fn test_public_key_derivation_matches() {
        let master = ExtendedPrivateKey::from_seed(&test_seed(), true).unwrap();

        // Derive child privately and publicly — results should match for normal indices.
        let child_priv = master.derive_child(0).unwrap();
        let master_pub = master.to_extended_public_key();
        let child_pub = master_pub.derive_child(0).unwrap();

        assert_eq!(
            child_priv.public_key().serialize(),
            child_pub.public_key().serialize(),
        );
    }

    #[test]
    fn test_hardened_from_public_fails() {
        let master = ExtendedPrivateKey::from_seed(&test_seed(), true).unwrap();
        let master_pub = master.to_extended_public_key();

        let result = master_pub.derive_child(HARDENED_OFFSET);
        assert!(matches!(result, Err(HdError::HardenedFromPublic)));
    }

    #[test]
    fn test_xprv_base58_roundtrip() {
        let master = ExtendedPrivateKey::from_seed(&test_seed(), true).unwrap();
        let encoded = master.to_base58();

        assert!(encoded.starts_with("xprv"));

        let decoded = ExtendedPrivateKey::from_base58(&encoded).unwrap();
        assert_eq!(
            master.private_key().secret_bytes(),
            decoded.private_key().secret_bytes()
        );
        assert_eq!(master.chain_code(), decoded.chain_code());
        assert_eq!(master.depth(), decoded.depth());
    }

    #[test]
    fn test_xpub_base58_roundtrip() {
        let master = ExtendedPrivateKey::from_seed(&test_seed(), true).unwrap();
        let master_pub = master.to_extended_public_key();
        let encoded = master_pub.to_base58();

        assert!(encoded.starts_with("xpub"));

        let decoded = ExtendedPublicKey::from_base58(&encoded).unwrap();
        assert_eq!(
            master_pub.public_key().serialize(),
            decoded.public_key().serialize(),
        );
    }

    #[test]
    fn test_tprv_base58_roundtrip() {
        let master = ExtendedPrivateKey::from_seed(&test_seed(), false).unwrap();
        let encoded = master.to_base58();

        assert!(encoded.starts_with("tprv"));

        let decoded = ExtendedPrivateKey::from_base58(&encoded).unwrap();
        assert!(!decoded.is_mainnet());
    }

    #[test]
    fn test_parse_derivation_path() {
        let path = parse_derivation_path("m/44'/0'/0'/0/0").unwrap();
        assert_eq!(path.len(), 5);
        assert_eq!(path[0], 44 + HARDENED_OFFSET);
        assert_eq!(path[1], 0 + HARDENED_OFFSET);
        assert_eq!(path[2], 0 + HARDENED_OFFSET);
        assert_eq!(path[3], 0);
        assert_eq!(path[4], 0);
    }

    #[test]
    fn test_parse_derivation_path_h_notation() {
        let path = parse_derivation_path("m/44h/0h/0h/0/5").unwrap();
        assert_eq!(path[0], 44 + HARDENED_OFFSET);
        assert_eq!(path[4], 5);
    }

    #[test]
    fn test_parse_derivation_path_just_m() {
        let path = parse_derivation_path("m").unwrap();
        assert!(path.is_empty());
    }

    #[test]
    fn test_fingerprint() {
        let master = ExtendedPrivateKey::from_seed(&test_seed(), true).unwrap();
        let fp = master.fingerprint();
        assert_eq!(fp.len(), 4);

        // Fingerprint should be deterministic.
        assert_eq!(fp, master.fingerprint());
    }

    #[test]
    fn test_multiple_accounts() {
        let master = ExtendedPrivateKey::from_seed(&test_seed(), true).unwrap();

        let acct0 = master.derive_bip44(0, 0, 0).unwrap();
        let acct1 = master.derive_bip44(1, 0, 0).unwrap();

        // Different accounts produce different keys.
        assert_ne!(
            acct0.private_key().secret_bytes(),
            acct1.private_key().secret_bytes()
        );
    }

    #[test]
    fn test_change_addresses() {
        let master = ExtendedPrivateKey::from_seed(&test_seed(), true).unwrap();

        let receive = master.derive_bip44(0, 0, 0).unwrap();
        let change = master.derive_bip44(0, 1, 0).unwrap();

        assert_ne!(
            receive.private_key().secret_bytes(),
            change.private_key().secret_bytes()
        );
    }

    #[test]
    fn test_public_key_path_derivation() {
        let master = ExtendedPrivateKey::from_seed(&test_seed(), true).unwrap();

        // Derive account key privately (hardened).
        let account = master
            .derive_path(&[
                44 + HARDENED_OFFSET,
                0 + HARDENED_OFFSET,
                0 + HARDENED_OFFSET,
            ])
            .unwrap();

        // From the account's xpub, derive receive addresses (non-hardened).
        let account_pub = account.to_extended_public_key();
        let addr_pub = account_pub.derive_path(&[0, 0]).unwrap();

        // Same result from private derivation.
        let addr_priv = account.derive_path(&[0, 0]).unwrap();

        assert_eq!(
            addr_pub.public_key().serialize(),
            addr_priv.public_key().serialize(),
        );
    }
}

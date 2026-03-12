//! Bitcoin public key type
//!
//! The `PublicKey` type lives here in `primitives` so that both `script`
//! (miniscript) and `wallet` can depend on it without creating a cycle.

use crate::hashing;

/// A Bitcoin public key (secp256k1 point)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    /// The raw secp256k1 public key
    key: secp256k1::PublicKey,
    /// Whether this is a compressed public key
    compressed: bool,
}

/// Errors during key operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    /// Invalid private key bytes (not a valid scalar)
    InvalidPrivateKey,
    /// Invalid public key bytes
    InvalidPublicKey,
    /// WIF decoding error
    InvalidWif(String),
    /// Checksum mismatch
    ChecksumMismatch,
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyError::InvalidPrivateKey => write!(f, "invalid private key"),
            KeyError::InvalidPublicKey => write!(f, "invalid public key"),
            KeyError::InvalidWif(msg) => write!(f, "invalid WIF: {}", msg),
            KeyError::ChecksumMismatch => write!(f, "WIF checksum mismatch"),
        }
    }
}

impl std::error::Error for KeyError {}

impl PublicKey {
    /// Create a public key from a secp256k1 key and compression flag.
    pub fn from_inner(key: secp256k1::PublicKey, compressed: bool) -> Self {
        PublicKey { key, compressed }
    }

    /// Create a public key from raw bytes (33 compressed or 65 uncompressed).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeyError> {
        let key =
            secp256k1::PublicKey::from_slice(bytes).map_err(|_| KeyError::InvalidPublicKey)?;
        let compressed = bytes.len() == 33;
        Ok(PublicKey { key, compressed })
    }

    /// Serialize the public key (33 bytes compressed, 65 bytes uncompressed).
    pub fn serialize(&self) -> Vec<u8> {
        if self.compressed {
            self.key.serialize().to_vec()
        } else {
            self.key.serialize_uncompressed().to_vec()
        }
    }

    /// Compute the Hash160 (RIPEMD160(SHA256)) of the serialized public key.
    ///
    /// This is the "public key hash" used in P2PKH and P2WPKH addresses.
    pub fn pubkey_hash(&self) -> [u8; 20] {
        hashing::hash160(&self.serialize())
    }

    /// Get the inner secp256k1 PublicKey.
    pub fn inner(&self) -> &secp256k1::PublicKey {
        &self.key
    }

    /// Whether this is a compressed key.
    pub fn compressed(&self) -> bool {
        self.compressed
    }
}

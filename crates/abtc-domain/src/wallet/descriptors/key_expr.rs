// Output descriptor key expressions
//
// Key expressions represent the keys used in output descriptors.
// They can be:
//   - A raw public key (hex-encoded compressed pubkey)
//   - An extended key (xpub/xprv) with optional origin info and derivation path
//
// Reference: BIP380-386

use std::fmt;

use crate::wallet::keys::PublicKey;
use crate::wallet::hd::{ExtendedPublicKey, ExtendedPrivateKey};

// ---------------------------------------------------------------------------
// Key origin — [fingerprint/path] annotation
// ---------------------------------------------------------------------------

/// Origin information for a key: master fingerprint and derivation path
/// from master to the key.  Written as `[deadbeef/44'/0'/0']` in descriptor strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyOrigin {
    /// 4-byte fingerprint of the master key.
    pub fingerprint: [u8; 4],
    /// Derivation path from the master to this key.
    /// Hardened indices have bit 31 set.
    pub path: Vec<u32>,
}

impl fmt::Display for KeyOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}", hex_encode(&self.fingerprint))?;
        for &idx in &self.path {
            if idx & HARDENED_BIT != 0 {
                write!(f, "/{}h", idx & !HARDENED_BIT)?;
            } else {
                write!(f, "/{}", idx)?;
            }
        }
        write!(f, "]")
    }
}

/// Bit 31, used to mark hardened derivation indices.
pub const HARDENED_BIT: u32 = 0x80000000;

// ---------------------------------------------------------------------------
// Wildcard — derivation suffix for extended keys
// ---------------------------------------------------------------------------

/// Wildcard mode for extended key derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wildcard {
    /// No wildcard — the key is used as-is.
    None,
    /// `/*` — derive unhardened children.
    Unhardened,
    /// `/*h` or `/*'` — derive hardened children (requires xprv).
    Hardened,
}

// ---------------------------------------------------------------------------
// DescriptorKey — the key expression enum
// ---------------------------------------------------------------------------

/// A key expression in an output descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DescriptorKey {
    /// A single public key, optionally with origin info.
    Single(SingleKey),
    /// An extended key (xpub or xprv) with optional origin, derivation path,
    /// and wildcard.
    Extended(ExtendedKey),
}

/// A single (non-extended) public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingleKey {
    /// The public key.
    pub key: PublicKey,
    /// Optional origin information.
    pub origin: Option<KeyOrigin>,
}

/// An extended key with derivation information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedKey {
    /// The extended key (public or private).
    pub xkey: XKey,
    /// Optional origin information.
    pub origin: Option<KeyOrigin>,
    /// Additional derivation path after the xkey.
    pub derivation_path: Vec<u32>,
    /// Wildcard mode.
    pub wildcard: Wildcard,
}

/// Either an extended public or private key.
#[derive(Debug, Clone)]
pub enum XKey {
    Pub(ExtendedPublicKey),
    Priv(ExtendedPrivateKey),
}

impl PartialEq for XKey {
    fn eq(&self, other: &Self) -> bool {
        // Compare by base58 serialisation (the canonical representation)
        match (self, other) {
            (XKey::Pub(a), XKey::Pub(b)) => a.to_base58() == b.to_base58(),
            (XKey::Priv(a), XKey::Priv(b)) => a.to_base58() == b.to_base58(),
            _ => false,
        }
    }
}

impl Eq for XKey {}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/// Errors that can occur during descriptor key operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    /// HD derivation failed.
    Derivation(String),
    /// Hardened derivation requires an xprv.
    HardenedWithoutPrivateKey,
    /// Cannot derive — single key has no derivation capability.
    NotDerivable,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyError::Derivation(msg) => write!(f, "derivation error: {}", msg),
            KeyError::HardenedWithoutPrivateKey => {
                write!(f, "hardened derivation requires a private key")
            }
            KeyError::NotDerivable => write!(f, "single key is not derivable"),
        }
    }
}

impl std::error::Error for KeyError {}

impl DescriptorKey {
    /// Derive the concrete public key at the given child index.
    ///
    /// For `SingleKey`, the index is ignored (the key is returned as-is).
    /// For `ExtendedKey`, the derivation path is applied, then the wildcard
    /// index is appended if present.
    pub fn derive_public_key(&self, index: u32) -> Result<PublicKey, KeyError> {
        match self {
            DescriptorKey::Single(sk) => Ok(sk.key.clone()),
            DescriptorKey::Extended(ek) => ek.derive_public_key(index),
        }
    }

    /// Returns true if this key expression has a wildcard.
    pub fn has_wildcard(&self) -> bool {
        match self {
            DescriptorKey::Single(_) => false,
            DescriptorKey::Extended(ek) => ek.wildcard != Wildcard::None,
        }
    }
}

impl ExtendedKey {
    /// Derive the concrete public key at the given wildcard index.
    pub fn derive_public_key(&self, index: u32) -> Result<PublicKey, KeyError> {
        // First, derive along the explicit derivation path
        let xpub = match &self.xkey {
            XKey::Pub(xpub) => {
                let mut key = xpub.clone();
                for &idx in &self.derivation_path {
                    if idx & HARDENED_BIT != 0 {
                        return Err(KeyError::HardenedWithoutPrivateKey);
                    }
                    key = key.derive_child(idx)
                        .map_err(|e| KeyError::Derivation(e.to_string()))?;
                }
                key
            }
            XKey::Priv(xprv) => {
                let mut key = xprv.clone();
                for &idx in &self.derivation_path {
                    key = key.derive_child(idx)
                        .map_err(|e| KeyError::Derivation(e.to_string()))?;
                }
                key.to_extended_public_key()
            }
        };

        // Then apply the wildcard
        let final_xpub = match self.wildcard {
            Wildcard::None => xpub,
            Wildcard::Unhardened => {
                xpub.derive_child(index)
                    .map_err(|e| KeyError::Derivation(e.to_string()))?
            }
            Wildcard::Hardened => {
                // Hardened wildcard requires going back to the xprv
                match &self.xkey {
                    XKey::Priv(xprv) => {
                        let mut key = xprv.clone();
                        for &idx in &self.derivation_path {
                            key = key.derive_child(idx)
                                .map_err(|e| KeyError::Derivation(e.to_string()))?;
                        }
                        let child = key.derive_child(index | HARDENED_BIT)
                            .map_err(|e| KeyError::Derivation(e.to_string()))?;
                        child.to_extended_public_key()
                    }
                    XKey::Pub(_) => return Err(KeyError::HardenedWithoutPrivateKey),
                }
            }
        };

        // Extract the PublicKey (public_key() already returns our PublicKey type)
        Ok(final_xpub.public_key())
    }
}

// ---------------------------------------------------------------------------
// Display
// ---------------------------------------------------------------------------

impl fmt::Display for DescriptorKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DescriptorKey::Single(sk) => {
                if let Some(ref origin) = sk.origin {
                    write!(f, "{}", origin)?;
                }
                write!(f, "{}", hex_encode(&sk.key.serialize()))
            }
            DescriptorKey::Extended(ek) => {
                if let Some(ref origin) = ek.origin {
                    write!(f, "{}", origin)?;
                }
                match &ek.xkey {
                    XKey::Pub(xpub) => write!(f, "{}", xpub.to_base58())?,
                    XKey::Priv(xprv) => write!(f, "{}", xprv.to_base58())?,
                }
                for &idx in &ek.derivation_path {
                    if idx & HARDENED_BIT != 0 {
                        write!(f, "/{}h", idx & !HARDENED_BIT)?;
                    } else {
                        write!(f, "/{}", idx)?;
                    }
                }
                match ek.wildcard {
                    Wildcard::None => {}
                    Wildcard::Unhardened => write!(f, "/*")?,
                    Wildcard::Hardened => write!(f, "/*h")?,
                }
                Ok(())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_key(seed: u8) -> PublicKey {
        use crate::crypto::hashing::sha256;
        let hash = sha256(&[seed]);
        let mut secret = [0u8; 32];
        secret.copy_from_slice(hash.as_bytes());
        secret[0] = seed.wrapping_add(1).max(1);
        let secp = secp256k1::Secp256k1::new();
        let sk = secp256k1::SecretKey::from_slice(&secret).unwrap();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
        PublicKey::from_bytes(&pk.serialize()).unwrap()
    }

    #[test]
    fn test_single_key_derive() {
        let key = dummy_key(1);
        let dk = DescriptorKey::Single(SingleKey {
            key: key.clone(),
            origin: None,
        });
        // Index is ignored for single keys
        let derived = dk.derive_public_key(0).unwrap();
        assert_eq!(derived, key);
        let derived2 = dk.derive_public_key(42).unwrap();
        assert_eq!(derived2, key);
    }

    #[test]
    fn test_single_key_no_wildcard() {
        let dk = DescriptorKey::Single(SingleKey {
            key: dummy_key(2),
            origin: None,
        });
        assert!(!dk.has_wildcard());
    }

    #[test]
    fn test_key_origin_display() {
        let origin = KeyOrigin {
            fingerprint: [0xde, 0xad, 0xbe, 0xef],
            path: vec![44 | HARDENED_BIT, 0 | HARDENED_BIT, 0 | HARDENED_BIT],
        };
        assert_eq!(origin.to_string(), "[deadbeef/44h/0h/0h]");
    }

    #[test]
    fn test_key_origin_display_mixed() {
        let origin = KeyOrigin {
            fingerprint: [0x01, 0x02, 0x03, 0x04],
            path: vec![44 | HARDENED_BIT, 0, 3],
        };
        assert_eq!(origin.to_string(), "[01020304/44h/0/3]");
    }

    #[test]
    fn test_single_key_display() {
        let key = dummy_key(5);
        let dk = DescriptorKey::Single(SingleKey {
            key: key.clone(),
            origin: Some(KeyOrigin {
                fingerprint: [0xaa, 0xbb, 0xcc, 0xdd],
                path: vec![0 | HARDENED_BIT],
            }),
        });
        let s = dk.to_string();
        assert!(s.starts_with("[aabbccdd/0h]"));
        assert_eq!(s.len(), 13 + 66); // origin + 33-byte hex pubkey
    }

    #[test]
    fn test_extended_key_with_xpub() {
        // Create an xprv, derive xpub, test derivation
        let seed = [0x42u8; 64];
        let xprv = ExtendedPrivateKey::from_seed(&seed, true).unwrap();
        let xpub = xprv.to_extended_public_key();

        let ek = DescriptorKey::Extended(ExtendedKey {
            xkey: XKey::Pub(xpub),
            origin: None,
            derivation_path: vec![0],
            wildcard: Wildcard::Unhardened,
        });

        assert!(ek.has_wildcard());

        // Derive at index 0 and index 1 — should give different keys
        let k0 = ek.derive_public_key(0).unwrap();
        let k1 = ek.derive_public_key(1).unwrap();
        assert_ne!(k0, k1);
    }

    #[test]
    fn test_extended_key_hardened_requires_xprv() {
        let seed = [0x43u8; 64];
        let xprv = ExtendedPrivateKey::from_seed(&seed, true).unwrap();
        let xpub = xprv.to_extended_public_key();

        let ek = DescriptorKey::Extended(ExtendedKey {
            xkey: XKey::Pub(xpub),
            origin: None,
            derivation_path: vec![],
            wildcard: Wildcard::Hardened,
        });

        let result = ek.derive_public_key(0);
        assert!(matches!(result, Err(KeyError::HardenedWithoutPrivateKey)));
    }

    #[test]
    fn test_extended_key_with_xprv_hardened() {
        let seed = [0x44u8; 64];
        let xprv = ExtendedPrivateKey::from_seed(&seed, true).unwrap();

        let ek = DescriptorKey::Extended(ExtendedKey {
            xkey: XKey::Priv(xprv),
            origin: None,
            derivation_path: vec![],
            wildcard: Wildcard::Hardened,
        });

        // Should work with xprv
        let k0 = ek.derive_public_key(0).unwrap();
        let k1 = ek.derive_public_key(1).unwrap();
        assert_ne!(k0, k1);
    }

    #[test]
    fn test_extended_key_no_wildcard() {
        let seed = [0x45u8; 64];
        let xprv = ExtendedPrivateKey::from_seed(&seed, true).unwrap();
        let xpub = xprv.to_extended_public_key();

        let ek = DescriptorKey::Extended(ExtendedKey {
            xkey: XKey::Pub(xpub),
            origin: None,
            derivation_path: vec![0, 0],
            wildcard: Wildcard::None,
        });

        // No wildcard — same key regardless of index
        let k0 = ek.derive_public_key(0).unwrap();
        let k1 = ek.derive_public_key(1).unwrap();
        assert_eq!(k0, k1);
    }
}

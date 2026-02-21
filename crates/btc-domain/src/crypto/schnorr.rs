//! BIP340 Schnorr signature verification
//!
//! Provides Schnorr signature verification using x-only public keys,
//! as defined in BIP340. This is the signature scheme used by Taproot
//! (BIP341/342) for both key-path and script-path spending.
//!
//! Key differences from ECDSA:
//! - Uses 32-byte x-only public keys (no parity byte)
//! - Signatures are 64 bytes (r, s) instead of DER-encoded
//! - Simpler, more efficient, and enables signature aggregation
//! - An optional 1-byte sighash type may be appended (65 bytes total)

use secp256k1::{Secp256k1, XOnlyPublicKey};

/// Verify a BIP340 Schnorr signature.
///
/// # Arguments
/// * `pubkey_bytes` - 32-byte x-only public key
/// * `msg` - 32-byte message hash (the sighash)
/// * `sig_bytes` - 64-byte Schnorr signature (without sighash type byte)
///
/// # Returns
/// `true` if the signature is valid, `false` otherwise.
pub fn verify_schnorr(pubkey_bytes: &[u8], msg: &[u8; 32], sig_bytes: &[u8]) -> bool {
    if pubkey_bytes.len() != 32 || sig_bytes.len() != 64 {
        return false;
    }

    let secp = Secp256k1::verification_only();

    let pubkey = match XOnlyPublicKey::from_slice(pubkey_bytes) {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    let sig = match secp256k1::schnorr::Signature::from_slice(sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let msg = match secp256k1::Message::from_digest_slice(msg) {
        Ok(m) => m,
        Err(_) => return false,
    };

    secp.verify_schnorr(&sig, &msg, &pubkey).is_ok()
}

/// Schnorr sighash types (BIP341)
///
/// Taproot uses a different sighash scheme than legacy/SegWit v0.
/// The default sighash type is 0x00 (SIGHASH_DEFAULT), which behaves
/// like SIGHASH_ALL but produces a different tagged hash.
pub mod sighash_type {
    /// Default sighash (equivalent to ALL but with different tag)
    pub const SIGHASH_DEFAULT: u8 = 0x00;
    /// Sign all inputs and outputs
    pub const SIGHASH_ALL: u8 = 0x01;
    /// Sign all inputs, no outputs
    pub const SIGHASH_NONE: u8 = 0x02;
    /// Sign all inputs, only the output at the same index
    pub const SIGHASH_SINGLE: u8 = 0x03;
    /// ANYONECANPAY modifier (can be combined with above)
    pub const SIGHASH_ANYONECANPAY: u8 = 0x80;
}

/// Parse a Schnorr signature from witness data.
///
/// A Taproot signature is either:
/// - 64 bytes: signature only (implies SIGHASH_DEFAULT = 0x00)
/// - 65 bytes: signature + 1-byte sighash type
///
/// Returns `(signature_bytes, sighash_type)` or None if invalid length.
pub fn parse_schnorr_signature(sig_data: &[u8]) -> Option<(&[u8], u8)> {
    match sig_data.len() {
        64 => Some((sig_data, sighash_type::SIGHASH_DEFAULT)),
        65 => {
            let hash_type = sig_data[64];
            // SIGHASH_DEFAULT (0x00) must NOT appear in the explicit byte
            // (it's only implied by a 64-byte signature)
            if hash_type == sighash_type::SIGHASH_DEFAULT {
                return None;
            }
            Some((&sig_data[..64], hash_type))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_schnorr_signature_64_bytes() {
        let sig = [0xABu8; 64];
        let (parsed, hash_type) = parse_schnorr_signature(&sig).unwrap();
        assert_eq!(parsed.len(), 64);
        assert_eq!(hash_type, sighash_type::SIGHASH_DEFAULT);
    }

    #[test]
    fn test_parse_schnorr_signature_65_bytes() {
        let mut sig = [0xABu8; 65];
        sig[64] = sighash_type::SIGHASH_ALL;
        let (parsed, hash_type) = parse_schnorr_signature(&sig).unwrap();
        assert_eq!(parsed.len(), 64);
        assert_eq!(hash_type, sighash_type::SIGHASH_ALL);
    }

    #[test]
    fn test_parse_schnorr_signature_65_bytes_default_rejected() {
        // SIGHASH_DEFAULT (0x00) as explicit byte is invalid
        let mut sig = [0xABu8; 65];
        sig[64] = sighash_type::SIGHASH_DEFAULT;
        assert!(parse_schnorr_signature(&sig).is_none());
    }

    #[test]
    fn test_parse_schnorr_signature_invalid_length() {
        let sig = [0xABu8; 63];
        assert!(parse_schnorr_signature(&sig).is_none());

        let sig = [0xABu8; 66];
        assert!(parse_schnorr_signature(&sig).is_none());
    }

    #[test]
    fn test_verify_schnorr_invalid_pubkey() {
        let pubkey = [0u8; 32]; // all zeros is not a valid point
        let msg = [0u8; 32];
        let sig = [0u8; 64];
        assert!(!verify_schnorr(&pubkey, &msg, &sig));
    }

    #[test]
    fn test_verify_schnorr_wrong_length() {
        let pubkey = [1u8; 31]; // wrong length
        let msg = [0u8; 32];
        let sig = [0u8; 64];
        assert!(!verify_schnorr(&pubkey, &msg, &sig));
    }
}

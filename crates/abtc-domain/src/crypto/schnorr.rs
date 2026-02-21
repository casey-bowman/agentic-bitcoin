//! BIP340 Schnorr signature signing and verification
//!
//! Provides Schnorr signature generation and verification using x-only
//! public keys, as defined in BIP340. This is the signature scheme used
//! by Taproot (BIP341/342) for both key-path and script-path spending.
//!
//! Key differences from ECDSA:
//! - Uses 32-byte x-only public keys (no parity byte)
//! - Signatures are 64 bytes (r, s) instead of DER-encoded
//! - Simpler, more efficient, and enables signature aggregation
//! - An optional 1-byte sighash type may be appended (65 bytes total)

use secp256k1::{Secp256k1, SecretKey, XOnlyPublicKey, Keypair};

/// Sign a 32-byte message hash with a secret key using BIP340 Schnorr.
///
/// # Arguments
/// * `secret_key` - The secp256k1 secret key
/// * `msg` - 32-byte message hash (the sighash)
///
/// # Returns
/// A 64-byte Schnorr signature.
pub fn sign_schnorr(secret_key: &SecretKey, msg: &[u8; 32]) -> [u8; 64] {
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, secret_key);
    let message = secp256k1::Message::from_digest_slice(msg)
        .expect("32 bytes is always valid for Message");
    let sig = secp.sign_schnorr(&message, &keypair);
    *sig.as_ref()
}

/// Sign a 32-byte message hash with a *tweaked* key for Taproot key-path spending.
///
/// The secret key is tweaked with `t = tagged_hash("TapTweak", internal_key || merkle_root)`
/// (or just `tagged_hash("TapTweak", internal_key)` for key-path-only outputs).
///
/// # Arguments
/// * `secret_key` - The internal secret key (before tweaking)
/// * `merkle_root` - Optional merkle root of the script tree (None for key-path-only)
/// * `msg` - 32-byte message hash (the sighash)
///
/// # Returns
/// A 64-byte Schnorr signature from the tweaked key, plus the 32-byte
/// x-only output public key.
pub fn sign_schnorr_tweaked(
    secret_key: &SecretKey,
    merkle_root: Option<&[u8; 32]>,
    msg: &[u8; 32],
) -> ([u8; 64], [u8; 32]) {
    use secp256k1::Scalar;

    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, secret_key);
    let (internal_xonly, _parity) = XOnlyPublicKey::from_keypair(&keypair);

    // Compute the tweak: t = tagged_hash("TapTweak", internal_key [|| merkle_root])
    let tweak_hash = super::taproot::taptweak_hash(
        &internal_xonly.serialize(),
        merkle_root,
    );
    let tweak_scalar = Scalar::from_be_bytes(tweak_hash)
        .expect("taptweak hash is valid scalar");

    // Tweak the keypair: tweaked_key = internal_key + t
    let tweaked_keypair = keypair.add_xonly_tweak(&secp, &tweak_scalar)
        .expect("tweak must not overflow");
    let (output_xonly, _) = XOnlyPublicKey::from_keypair(&tweaked_keypair);

    let message = secp256k1::Message::from_digest_slice(msg)
        .expect("32 bytes is always valid for Message");
    let sig = secp.sign_schnorr(&message, &tweaked_keypair);

    (*sig.as_ref(), output_xonly.serialize())
}

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

    #[test]
    fn test_sign_schnorr_and_verify() {
        // Generate a keypair, sign a message, verify
        let secret = SecretKey::from_slice(&[0x42; 32]).unwrap();
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let (xonly, _) = XOnlyPublicKey::from_keypair(&keypair);

        let msg = [0xBB; 32];
        let sig = sign_schnorr(&secret, &msg);

        assert_eq!(sig.len(), 64);
        assert!(verify_schnorr(&xonly.serialize(), &msg, &sig));
    }

    #[test]
    fn test_sign_schnorr_wrong_message_fails() {
        let secret = SecretKey::from_slice(&[0x42; 32]).unwrap();
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let (xonly, _) = XOnlyPublicKey::from_keypair(&keypair);

        let msg = [0xBB; 32];
        let sig = sign_schnorr(&secret, &msg);

        // Wrong message should not verify
        let wrong_msg = [0xCC; 32];
        assert!(!verify_schnorr(&xonly.serialize(), &wrong_msg, &sig));
    }

    #[test]
    fn test_sign_schnorr_tweaked_and_verify() {
        let secret = SecretKey::from_slice(&[0x42; 32]).unwrap();
        let msg = [0xAA; 32];

        // Key-path-only (no merkle root)
        let (sig, output_key) = sign_schnorr_tweaked(&secret, None, &msg);

        assert_eq!(sig.len(), 64);
        assert_eq!(output_key.len(), 32);
        // The signature should verify against the tweaked output key
        assert!(verify_schnorr(&output_key, &msg, &sig));
    }

    #[test]
    fn test_sign_schnorr_tweaked_with_merkle_root() {
        let secret = SecretKey::from_slice(&[0x42; 32]).unwrap();
        let msg = [0xAA; 32];
        let merkle_root = [0x55; 32];

        let (sig, output_key) = sign_schnorr_tweaked(&secret, Some(&merkle_root), &msg);

        // Should verify against the tweaked output key
        assert!(verify_schnorr(&output_key, &msg, &sig));

        // Should NOT verify against untweaked internal key
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let (internal_xonly, _) = XOnlyPublicKey::from_keypair(&keypair);
        assert!(!verify_schnorr(&internal_xonly.serialize(), &msg, &sig));
    }

    #[test]
    fn test_sign_schnorr_tweaked_different_roots_different_keys() {
        let secret = SecretKey::from_slice(&[0x42; 32]).unwrap();
        let msg = [0xAA; 32];
        let root_a = [0x11; 32];
        let root_b = [0x22; 32];

        let (_, key_a) = sign_schnorr_tweaked(&secret, Some(&root_a), &msg);
        let (_, key_b) = sign_schnorr_tweaked(&secret, Some(&root_b), &msg);

        // Different merkle roots produce different output keys
        assert_ne!(key_a, key_b);
    }
}

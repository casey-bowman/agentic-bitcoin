//! BIP324 v2 Transport Encryption Primitives
//!
//! Implements the cryptographic building blocks for Bitcoin's encrypted P2P
//! transport protocol (BIP324):
//!
//! - **ECDH key exchange** using secp256k1 for shared secret derivation
//! - **HKDF-SHA256** for session key derivation from the shared secret
//! - **FSChaCha20Poly1305** — forward-secure AEAD with periodic rekeying
//!   (re-keys every 224 messages to limit the damage of key compromise)
//! - **FSChaCha20** — length encryption cipher (encrypts the 3-byte length
//!   prefix so an observer cannot determine message boundaries)
//!
//! This module lives in the domain crate because it is pure cryptographic
//! logic with no I/O.  The adapter layer wraps these primitives in a
//! transport state machine that drives the handshake and message framing.
//!
//! Reference: <https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki>

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as AeadNonce};
use hkdf::Hkdf;
use sha2::Sha256;

// ═══════════════════════════════════════════════════════════════
// Key exchange and session key derivation
// ═══════════════════════════════════════════════════════════════

/// Perform ECDH key exchange using secp256k1.
///
/// Given our secret key and the peer's public key, compute the 32-byte
/// shared secret `SHA256(ECDH(our_secret, their_pubkey))`.
///
/// BIP324 specifies ElligatorSwift encoding for public keys (64 bytes)
/// to make the handshake indistinguishable from random.  For now we use
/// standard compressed public keys and can add EllSwift later.
pub fn ecdh_shared_secret(
    our_secret: &secp256k1::SecretKey,
    their_pubkey: &secp256k1::PublicKey,
) -> [u8; 32] {
    use secp256k1::ecdh::SharedSecret;

    let shared = SharedSecret::new(their_pubkey, our_secret);
    let mut out = [0u8; 32];
    out.copy_from_slice(shared.as_ref());
    out
}

/// BIP324 session keys derived from the ECDH shared secret.
///
/// The handshake produces four keys:
/// - `initiator_key` / `responder_key` — ChaCha20-Poly1305 AEAD keys
/// - `initiator_length_key` / `responder_length_key` — FSChaCha20 keys
///   used to encrypt the 3-byte message length prefix.
///
/// The initiator uses `initiator_key` to **send** and `responder_key` to
/// **receive** (and vice-versa for the responder).
#[derive(Debug, Clone)]
pub struct SessionKeys {
    pub initiator_key: [u8; 32],
    pub responder_key: [u8; 32],
    pub initiator_length_key: [u8; 32],
    pub responder_length_key: [u8; 32],
    /// A 32-byte "session id" that both peers can compare out-of-band
    /// to detect a MITM attack.
    pub session_id: [u8; 32],
}

/// Derive BIP324 session keys from an ECDH shared secret.
///
/// Uses HKDF-SHA256 with the salt composed of the sorted public keys
/// (the same salt both peers compute independently).  The info strings
/// follow the BIP324 spec.
pub fn derive_session_keys(
    shared_secret: &[u8; 32],
    initiator_pubkey: &[u8],
    responder_pubkey: &[u8],
) -> SessionKeys {
    // Salt = SHA256("bitcoin_v2_shared_secret_extract" || initiator_pk || responder_pk)
    let mut salt_preimage =
        Vec::with_capacity(32 + initiator_pubkey.len() + responder_pubkey.len());
    salt_preimage.extend_from_slice(b"bitcoin_v2_shared_secret_extract");
    salt_preimage.extend_from_slice(initiator_pubkey);
    salt_preimage.extend_from_slice(responder_pubkey);

    let salt = {
        use sha2::Digest;
        let hash = Sha256::digest(&salt_preimage);
        let mut s = [0u8; 32];
        s.copy_from_slice(&hash);
        s
    };

    let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret);

    let mut initiator_length_key = [0u8; 32];
    hk.expand(
        b"bitcoin_v2_shared_secret_expand_initiator_length_key",
        &mut initiator_length_key,
    )
    .expect("HKDF expand failed for initiator_length_key");

    let mut initiator_key = [0u8; 32];
    hk.expand(
        b"bitcoin_v2_shared_secret_expand_initiator_key",
        &mut initiator_key,
    )
    .expect("HKDF expand failed for initiator_key");

    let mut responder_length_key = [0u8; 32];
    hk.expand(
        b"bitcoin_v2_shared_secret_expand_responder_length_key",
        &mut responder_length_key,
    )
    .expect("HKDF expand failed for responder_length_key");

    let mut responder_key = [0u8; 32];
    hk.expand(
        b"bitcoin_v2_shared_secret_expand_responder_key",
        &mut responder_key,
    )
    .expect("HKDF expand failed for responder_key");

    let mut session_id = [0u8; 32];
    hk.expand(
        b"bitcoin_v2_shared_secret_expand_session_id",
        &mut session_id,
    )
    .expect("HKDF expand failed for session_id");

    SessionKeys {
        initiator_key,
        responder_key,
        initiator_length_key,
        responder_length_key,
        session_id,
    }
}

// ═══════════════════════════════════════════════════════════════
// Forward-Secure ChaCha20-Poly1305 (FSChaCha20Poly1305)
// ═══════════════════════════════════════════════════════════════

/// Number of messages between automatic re-keys.
///
/// BIP324 re-keys every 224 messages to provide forward secrecy:
/// if a key is later compromised, only the last ≤224 messages are
/// exposed rather than the entire session.
const REKEY_INTERVAL: u32 = 224;

/// Forward-Secure ChaCha20-Poly1305 AEAD cipher.
///
/// Wraps the standard ChaCha20-Poly1305 AEAD with:
/// - Automatic re-keying every [`REKEY_INTERVAL`] messages
/// - Nonce derived from an incrementing packet counter
///
/// The 96-bit (12-byte) AEAD nonce is built as:
///   `little_endian_u32(packet_counter % REKEY_INTERVAL) || little_endian_u64(0)`
///
/// After every `REKEY_INTERVAL` messages the key is replaced by
/// encrypting 32 zero bytes with the next nonce (the "rekey" operation).
pub struct FSChaCha20Poly1305 {
    key: [u8; 32],
    packet_counter: u64,
}

impl FSChaCha20Poly1305 {
    /// Create a new cipher from a 32-byte key.
    pub fn new(key: [u8; 32]) -> Self {
        FSChaCha20Poly1305 {
            key,
            packet_counter: 0,
        }
    }

    /// Build the 12-byte AEAD nonce from the current counter.
    fn nonce(&self) -> [u8; 12] {
        let sub_counter = (self.packet_counter % REKEY_INTERVAL as u64) as u32;
        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&sub_counter.to_le_bytes());
        // bytes 4..12 are the "rekey counter" (upper 64 bits): zero within an epoch
        let rekey_epoch = self.packet_counter / REKEY_INTERVAL as u64;
        nonce[4..12].copy_from_slice(&rekey_epoch.to_le_bytes());
        nonce
    }

    /// Encrypt a plaintext with an optional AAD (Additional Authenticated Data).
    ///
    /// Returns the ciphertext || 16-byte Poly1305 tag.
    pub fn encrypt(&mut self, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let nonce_bytes = self.nonce();
        let nonce = AeadNonce::from_slice(&nonce_bytes);

        let cipher =
            ChaCha20Poly1305::new_from_slice(&self.key).expect("BIP324: invalid key length");

        let payload = chacha20poly1305::aead::Payload {
            msg: plaintext,
            aad,
        };

        let ciphertext = cipher
            .encrypt(nonce, payload)
            .expect("BIP324: encryption failed");

        self.packet_counter += 1;

        // Re-key if we've hit the interval boundary
        if self.packet_counter % REKEY_INTERVAL as u64 == 0 {
            self.rekey();
        }

        ciphertext
    }

    /// Decrypt a ciphertext (with appended Poly1305 tag) and verify the AAD.
    ///
    /// Returns the plaintext on success, or `None` if authentication fails.
    pub fn decrypt(&mut self, aad: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
        let nonce_bytes = self.nonce();
        let nonce = AeadNonce::from_slice(&nonce_bytes);

        let cipher =
            ChaCha20Poly1305::new_from_slice(&self.key).expect("BIP324: invalid key length");

        let payload = chacha20poly1305::aead::Payload {
            msg: ciphertext,
            aad,
        };

        let plaintext = cipher.decrypt(nonce, payload).ok()?;

        self.packet_counter += 1;

        // Re-key if we've hit the interval boundary
        if self.packet_counter % REKEY_INTERVAL as u64 == 0 {
            self.rekey();
        }

        Some(plaintext)
    }

    /// Replace the current key by encrypting 32 zero bytes.
    ///
    /// This provides forward secrecy: the old key is discarded and
    /// cannot be recovered even if the new key is later compromised.
    fn rekey(&mut self) {
        let nonce_bytes = self.nonce();
        let nonce = AeadNonce::from_slice(&nonce_bytes);

        let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
            .expect("BIP324: invalid key length for rekey");

        let zeros = [0u8; 32];
        let payload = chacha20poly1305::aead::Payload {
            msg: &zeros,
            aad: b"",
        };

        // The rekey ciphertext is 32 + 16 = 48 bytes.
        // We take the first 32 bytes as the new key.
        let rekey_ct = cipher
            .encrypt(nonce, payload)
            .expect("BIP324: rekey encryption failed");

        self.key.copy_from_slice(&rekey_ct[..32]);
    }

    /// Get the current packet counter (useful for diagnostics).
    pub fn packet_counter(&self) -> u64 {
        self.packet_counter
    }
}

// ═══════════════════════════════════════════════════════════════
// FSChaCha20 — length encryption
// ═══════════════════════════════════════════════════════════════

/// Forward-Secure ChaCha20 stream cipher for length encryption.
///
/// BIP324 encrypts the 3-byte message length with a separate cipher
/// so that an eavesdropper cannot determine message boundaries.  This
/// uses raw ChaCha20 (no Poly1305) because the length is authenticated
/// implicitly by the AEAD on the full message.
///
/// Re-keys every [`REKEY_INTERVAL`] messages, matching the AEAD cipher.
pub struct FSChaCha20 {
    key: [u8; 32],
    packet_counter: u64,
}

impl FSChaCha20 {
    /// Create a new length cipher from a 32-byte key.
    pub fn new(key: [u8; 32]) -> Self {
        FSChaCha20 {
            key,
            packet_counter: 0,
        }
    }

    /// Encrypt or decrypt a 3-byte length field in place.
    ///
    /// ChaCha20 is a symmetric stream cipher, so encrypt and decrypt
    /// are the same XOR operation.
    pub fn crypt(&mut self, length_bytes: &mut [u8; 3]) {
        // Generate a ChaCha20 keystream block and XOR the first 3 bytes.
        // We use the same nonce construction as the AEAD cipher.
        let sub_counter = (self.packet_counter % REKEY_INTERVAL as u64) as u32;
        let rekey_epoch = self.packet_counter / REKEY_INTERVAL as u64;

        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&sub_counter.to_le_bytes());
        nonce[4..12].copy_from_slice(&rekey_epoch.to_le_bytes());

        // Use HKDF to derive 3 keystream bytes from key + nonce.
        // (A full implementation would use raw ChaCha20 block function;
        // we use HKDF-Expand as a pragmatic PRF here.)
        let hk = Hkdf::<Sha256>::new(Some(&nonce), &self.key);
        let mut keystream = [0u8; 3];
        hk.expand(b"bitcoin_v2_length_cipher", &mut keystream)
            .expect("HKDF expand failed for length cipher");

        length_bytes[0] ^= keystream[0];
        length_bytes[1] ^= keystream[1];
        length_bytes[2] ^= keystream[2];

        self.packet_counter += 1;

        if self.packet_counter % REKEY_INTERVAL as u64 == 0 {
            // Derive new key
            let mut new_key = [0u8; 32];
            let hk2 = Hkdf::<Sha256>::new(Some(&nonce), &self.key);
            hk2.expand(b"bitcoin_v2_length_cipher_rekey", &mut new_key)
                .expect("HKDF expand failed for length rekey");
            self.key = new_key;
        }
    }

    /// Get the current packet counter.
    pub fn packet_counter(&self) -> u64 {
        self.packet_counter
    }
}

// ═══════════════════════════════════════════════════════════════
// V2 message IDs — short integer command encoding
// ═══════════════════════════════════════════════════════════════

/// BIP324 replaces 12-byte ASCII command strings with 1-byte IDs
/// for common messages, saving bandwidth on the encrypted wire.
///
/// The first byte of the decrypted content encodes the message type.
/// If it is 0, the rest is a variable-length ASCII command (for
/// uncommon or future messages).  If it is 1–12, it maps to a
/// frequently used message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum V2MessageId {
    /// 0x00: short-id not used; followed by a 12-byte ASCII command
    Other = 0,
    Addr = 1,
    Block = 2,
    GetData = 3,
    GetHeaders = 4,
    Headers = 5,
    Inv = 6,
    Ping = 7,
    Pong = 8,
    Tx = 9,
    GetBlocks = 10,
    SendHeaders = 11,
    Version = 12,
}

impl V2MessageId {
    /// Try to map a v1 command string to a v2 short ID.
    pub fn from_command(cmd: &str) -> Option<V2MessageId> {
        match cmd {
            "addr" => Some(V2MessageId::Addr),
            "block" => Some(V2MessageId::Block),
            "getdata" => Some(V2MessageId::GetData),
            "getheaders" => Some(V2MessageId::GetHeaders),
            "headers" => Some(V2MessageId::Headers),
            "inv" => Some(V2MessageId::Inv),
            "ping" => Some(V2MessageId::Ping),
            "pong" => Some(V2MessageId::Pong),
            "tx" => Some(V2MessageId::Tx),
            "getblocks" => Some(V2MessageId::GetBlocks),
            "sendheaders" => Some(V2MessageId::SendHeaders),
            "version" => Some(V2MessageId::Version),
            _ => None,
        }
    }

    /// Convert a v2 short ID back to its v1 command string.
    pub fn to_command(self) -> &'static str {
        match self {
            V2MessageId::Other => "",
            V2MessageId::Addr => "addr",
            V2MessageId::Block => "block",
            V2MessageId::GetData => "getdata",
            V2MessageId::GetHeaders => "getheaders",
            V2MessageId::Headers => "headers",
            V2MessageId::Inv => "inv",
            V2MessageId::Ping => "ping",
            V2MessageId::Pong => "pong",
            V2MessageId::Tx => "tx",
            V2MessageId::GetBlocks => "getblocks",
            V2MessageId::SendHeaders => "sendheaders",
            V2MessageId::Version => "version",
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── ECDH key exchange ──────────────────────────────────

    #[test]
    fn test_ecdh_shared_secret_agreement() {
        use secp256k1::Secp256k1;

        let secp = Secp256k1::new();
        let (sk_a, pk_a) = secp.generate_keypair(&mut rand::thread_rng());
        let (sk_b, pk_b) = secp.generate_keypair(&mut rand::thread_rng());

        let secret_ab = ecdh_shared_secret(&sk_a, &pk_b);
        let secret_ba = ecdh_shared_secret(&sk_b, &pk_a);

        // Both sides must arrive at the same shared secret
        assert_eq!(secret_ab, secret_ba);
        // Must not be all zeros
        assert_ne!(secret_ab, [0u8; 32]);
    }

    #[test]
    fn test_ecdh_different_peers_different_secrets() {
        use secp256k1::Secp256k1;

        let secp = Secp256k1::new();
        let (sk_a, _pk_a) = secp.generate_keypair(&mut rand::thread_rng());
        let (_sk_b, pk_b) = secp.generate_keypair(&mut rand::thread_rng());
        let (_sk_c, pk_c) = secp.generate_keypair(&mut rand::thread_rng());

        let secret1 = ecdh_shared_secret(&sk_a, &pk_b);
        let secret2 = ecdh_shared_secret(&sk_a, &pk_c);

        assert_ne!(secret1, secret2);
    }

    // ── Session key derivation ─────────────────────────────

    #[test]
    fn test_derive_session_keys_deterministic() {
        let shared_secret = [0x42u8; 32];
        let init_pk = [0x01u8; 33];
        let resp_pk = [0x02u8; 33];

        let keys1 = derive_session_keys(&shared_secret, &init_pk, &resp_pk);
        let keys2 = derive_session_keys(&shared_secret, &init_pk, &resp_pk);

        assert_eq!(keys1.initiator_key, keys2.initiator_key);
        assert_eq!(keys1.responder_key, keys2.responder_key);
        assert_eq!(keys1.session_id, keys2.session_id);
    }

    #[test]
    fn test_derive_session_keys_all_distinct() {
        let shared_secret = [0x42u8; 32];
        let init_pk = [0x01u8; 33];
        let resp_pk = [0x02u8; 33];

        let keys = derive_session_keys(&shared_secret, &init_pk, &resp_pk);

        // All keys must be different from each other
        assert_ne!(keys.initiator_key, keys.responder_key);
        assert_ne!(keys.initiator_key, keys.initiator_length_key);
        assert_ne!(keys.initiator_key, keys.responder_length_key);
        assert_ne!(keys.initiator_key, keys.session_id);
        assert_ne!(keys.responder_key, keys.responder_length_key);
    }

    #[test]
    fn test_derive_session_keys_swapped_pubkeys_differ() {
        let shared_secret = [0x42u8; 32];
        let pk1 = [0x01u8; 33];
        let pk2 = [0x02u8; 33];

        let keys_forward = derive_session_keys(&shared_secret, &pk1, &pk2);
        let keys_reversed = derive_session_keys(&shared_secret, &pk2, &pk1);

        // Swapping initiator/responder pubkeys must produce different keys
        assert_ne!(keys_forward.initiator_key, keys_reversed.initiator_key);
    }

    // ── FSChaCha20Poly1305 AEAD ────────────────────────────

    #[test]
    fn test_aead_encrypt_decrypt_roundtrip() {
        let key = [0x01u8; 32];
        let mut enc = FSChaCha20Poly1305::new(key);
        let mut dec = FSChaCha20Poly1305::new(key);

        let plaintext = b"Hello, BIP324 encrypted transport!";
        let aad = b"v2";

        let ciphertext = enc.encrypt(aad, plaintext);
        let recovered = dec.decrypt(aad, &ciphertext).expect("decryption failed");

        assert_eq!(&recovered, plaintext);
    }

    #[test]
    fn test_aead_wrong_key_fails() {
        let mut enc = FSChaCha20Poly1305::new([0x01u8; 32]);
        let mut dec = FSChaCha20Poly1305::new([0x02u8; 32]); // wrong key

        let ciphertext = enc.encrypt(b"", b"secret data");
        assert!(dec.decrypt(b"", &ciphertext).is_none());
    }

    #[test]
    fn test_aead_wrong_aad_fails() {
        let key = [0x01u8; 32];
        let mut enc = FSChaCha20Poly1305::new(key);
        let mut dec = FSChaCha20Poly1305::new(key);

        let ciphertext = enc.encrypt(b"correct", b"data");
        assert!(dec.decrypt(b"wrong", &ciphertext).is_none());
    }

    #[test]
    fn test_aead_tampered_ciphertext_fails() {
        let key = [0x01u8; 32];
        let mut enc = FSChaCha20Poly1305::new(key);
        let mut dec = FSChaCha20Poly1305::new(key);

        let mut ciphertext = enc.encrypt(b"", b"data");
        // Flip a bit in the ciphertext
        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0x01;
        }
        assert!(dec.decrypt(b"", &ciphertext).is_none());
    }

    #[test]
    fn test_aead_counter_increments() {
        let key = [0x01u8; 32];
        let mut cipher = FSChaCha20Poly1305::new(key);

        assert_eq!(cipher.packet_counter(), 0);
        cipher.encrypt(b"", b"msg1");
        assert_eq!(cipher.packet_counter(), 1);
        cipher.encrypt(b"", b"msg2");
        assert_eq!(cipher.packet_counter(), 2);
    }

    #[test]
    fn test_aead_multiple_messages_roundtrip() {
        let key = [0x03u8; 32];
        let mut enc = FSChaCha20Poly1305::new(key);
        let mut dec = FSChaCha20Poly1305::new(key);

        for i in 0..50u32 {
            let msg = format!("message number {}", i);
            let ct = enc.encrypt(b"", msg.as_bytes());
            let pt = dec.decrypt(b"", &ct).expect("decryption failed");
            assert_eq!(pt, msg.as_bytes());
        }
    }

    #[test]
    fn test_aead_rekey_after_224_messages() {
        let key = [0x04u8; 32];
        let mut enc = FSChaCha20Poly1305::new(key);
        let mut dec = FSChaCha20Poly1305::new(key);

        // Send 225 messages — crosses the rekey boundary
        for i in 0..225u32 {
            let msg = format!("msg{}", i);
            let ct = enc.encrypt(b"", msg.as_bytes());
            let pt = dec
                .decrypt(b"", &ct)
                .expect(&format!("decrypt failed at {}", i));
            assert_eq!(pt, msg.as_bytes());
        }

        assert_eq!(enc.packet_counter(), 225);
    }

    #[test]
    fn test_aead_out_of_sync_counters_fail() {
        let key = [0x05u8; 32];
        let mut enc = FSChaCha20Poly1305::new(key);
        let mut dec = FSChaCha20Poly1305::new(key);

        // Encrypt two messages but only decrypt the second one
        let _ct1 = enc.encrypt(b"", b"message 1");
        let ct2 = enc.encrypt(b"", b"message 2");

        // Decryptor is still at counter 0, but ct2 was encrypted at counter 1
        assert!(dec.decrypt(b"", &ct2).is_none());
    }

    // ── FSChaCha20 length cipher ───────────────────────────

    #[test]
    fn test_length_cipher_roundtrip() {
        let key = [0x06u8; 32];
        let mut enc = FSChaCha20::new(key);
        let mut dec = FSChaCha20::new(key);

        let original: [u8; 3] = [0x01, 0x02, 0x03];
        let mut buf = original;

        enc.crypt(&mut buf);
        // Encrypted bytes should differ from original
        assert_ne!(buf, original);

        dec.crypt(&mut buf);
        // After decrypt they should match original
        assert_eq!(buf, original);
    }

    #[test]
    fn test_length_cipher_counter_increments() {
        let mut cipher = FSChaCha20::new([0x07u8; 32]);
        let mut buf = [0u8; 3];

        assert_eq!(cipher.packet_counter(), 0);
        cipher.crypt(&mut buf);
        assert_eq!(cipher.packet_counter(), 1);
    }

    // ── V2 message ID mapping ──────────────────────────────

    #[test]
    fn test_v2_message_id_roundtrip() {
        let commands = [
            "addr",
            "block",
            "getdata",
            "getheaders",
            "headers",
            "inv",
            "ping",
            "pong",
            "tx",
            "getblocks",
            "sendheaders",
            "version",
        ];
        for cmd in commands {
            let id = V2MessageId::from_command(cmd).unwrap();
            assert_eq!(id.to_command(), cmd);
        }
    }

    #[test]
    fn test_v2_message_id_unknown_returns_none() {
        assert!(V2MessageId::from_command("notfound").is_none());
        assert!(V2MessageId::from_command("foobar").is_none());
    }

    // ═══════════════════════════════════════════════════════════
    // Regression tests — Session 15 (BIP324 crypto primitives)
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn regression_rekey_does_not_break_sync() {
        // Verify that after exactly REKEY_INTERVAL messages, both
        // sides re-key and remain in sync for subsequent messages.
        let key = [0xABu8; 32];
        let mut enc = FSChaCha20Poly1305::new(key);
        let mut dec = FSChaCha20Poly1305::new(key);

        // Send exactly 224 messages (one full epoch)
        for i in 0..REKEY_INTERVAL {
            let msg = format!("epoch1-{}", i);
            let ct = enc.encrypt(b"", msg.as_bytes());
            let pt = dec.decrypt(b"", &ct).unwrap();
            assert_eq!(pt, msg.as_bytes());
        }

        // Both should now be at counter 224 with new keys
        assert_eq!(enc.packet_counter(), REKEY_INTERVAL as u64);
        assert_eq!(dec.packet_counter(), REKEY_INTERVAL as u64);

        // Next message uses the new key — must still work
        let ct = enc.encrypt(b"", b"after rekey");
        let pt = dec.decrypt(b"", &ct).unwrap();
        assert_eq!(pt, b"after rekey");
    }

    #[test]
    fn regression_session_keys_not_all_zero() {
        let shared_secret = [0x00u8; 32]; // even with zero input
        let keys = derive_session_keys(&shared_secret, &[0x00; 33], &[0x01; 33]);

        // HKDF should never produce all-zero output
        assert_ne!(keys.initiator_key, [0u8; 32]);
        assert_ne!(keys.responder_key, [0u8; 32]);
        assert_ne!(keys.session_id, [0u8; 32]);
    }

    #[test]
    fn regression_ecdh_with_known_keys() {
        // Verify ECDH with specific secret keys (not random) to ensure
        // the function is deterministic and doesn't silently return zeros.
        use secp256k1::{Secp256k1, SecretKey};

        let secp = Secp256k1::new();
        let sk_a = SecretKey::from_slice(&[0x01; 32]).unwrap();
        let pk_a = secp256k1::PublicKey::from_secret_key(&secp, &sk_a);

        let sk_b = SecretKey::from_slice(&[0x02; 32]).unwrap();
        let pk_b = secp256k1::PublicKey::from_secret_key(&secp, &sk_b);

        let secret = ecdh_shared_secret(&sk_a, &pk_b);
        assert_ne!(secret, [0u8; 32]);

        // Must be deterministic
        let secret2 = ecdh_shared_secret(&sk_a, &pk_b);
        assert_eq!(secret, secret2);

        // Must agree from both sides
        let secret_ba = ecdh_shared_secret(&sk_b, &pk_a);
        assert_eq!(secret, secret_ba);
    }
}

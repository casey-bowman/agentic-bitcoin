//! BIP324 v2 Encrypted Transport
//!
//! This module implements the application-layer state machine for
//! Bitcoin's v2 P2P protocol.  It wraps the cryptographic primitives
//! from `abtc_domain::crypto::bip324` and drives:
//!
//! 1. **Handshake** — ephemeral key exchange → shared secret → session keys
//! 2. **Encrypted framing** — 3-byte encrypted length ‖ encrypted content ‖ 16-byte tag
//! 3. **Decryption** — length decryption → payload decryption → command demux
//!
//! ## Wire format after handshake
//!
//! ```text
//!  ┌──────────────┬────────────────────────────────────────┐
//!  │ 3 bytes      │ N bytes                                │
//!  │ enc(length)  │ AEAD(flag ‖ command_id ‖ payload, tag) │
//!  └──────────────┴────────────────────────────────────────┘
//! ```
//!
//! The 3-byte length is XOR-encrypted with FSChaCha20 so observers
//! cannot determine message boundaries.  The content is encrypted
//! with FSChaCha20Poly1305 (ChaCha20-Poly1305 with periodic re-keying).
//!
//! ## Handshake overview
//!
//! 1. Both peers generate an ephemeral secp256k1 keypair.
//! 2. The **initiator** sends its 33-byte compressed public key.
//! 3. The **responder** sends its 33-byte compressed public key.
//! 4. Both compute the ECDH shared secret.
//! 5. Both derive session keys via HKDF.
//! 6. All subsequent messages use encrypted framing.
//!
//! In a full BIP324 implementation the public keys would use
//! ElligatorSwift (64 bytes) to make the handshake indistinguishable
//! from random.  We start with compressed keys for simplicity.

use abtc_domain::crypto::bip324::{self, FSChaCha20, FSChaCha20Poly1305, SessionKeys, V2MessageId};

// ═══════════════════════════════════════════════════════════════
// Handshake state machine
// ═══════════════════════════════════════════════════════════════

/// The v2 handshake progresses through these states:
///
/// ```text
/// KeyExchange  →  AwaitingPeerKey  →  Established
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    /// Waiting to initiate key exchange (haven't sent our key yet).
    KeyExchange,
    /// We sent our public key; waiting for the peer's public key.
    AwaitingPeerKey,
    /// Session is established — all messages are encrypted.
    Established,
}

/// Errors that can occur during the v2 handshake or message processing.
#[derive(Debug)]
pub enum V2Error {
    /// The handshake has not completed yet.
    HandshakeIncomplete,
    /// ECDH shared secret derivation failed.
    KeyExchangeFailed(String),
    /// AEAD decryption/authentication failed.
    DecryptionFailed,
    /// The message is too short to contain valid framing.
    MessageTooShort,
    /// An invalid v2 message ID was received.
    InvalidMessageId(u8),
}

impl std::fmt::Display for V2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            V2Error::HandshakeIncomplete => write!(f, "v2 handshake incomplete"),
            V2Error::KeyExchangeFailed(e) => write!(f, "key exchange failed: {}", e),
            V2Error::DecryptionFailed => write!(f, "AEAD decryption/authentication failed"),
            V2Error::MessageTooShort => write!(f, "v2 message too short"),
            V2Error::InvalidMessageId(id) => write!(f, "invalid v2 message ID: {}", id),
        }
    }
}

impl std::error::Error for V2Error {}

// ═══════════════════════════════════════════════════════════════
// Per-connection v2 transport state
// ═══════════════════════════════════════════════════════════════

/// Manages the encrypted transport state for a single peer connection.
///
/// Each peer connection that negotiates v2 gets its own `V2Transport`.
/// The struct holds the handshake state, ephemeral keypair, session
/// keys, and the two cipher instances (send + receive).
pub struct V2Transport {
    /// Current handshake state.
    state: HandshakeState,
    /// Are we the initiator (client) or responder (server)?
    is_initiator: bool,
    /// Our ephemeral secret key (zeroed after key derivation).
    our_secret: Option<secp256k1::SecretKey>,
    /// Our ephemeral public key (sent to the peer during handshake).
    our_pubkey: Option<secp256k1::PublicKey>,
    /// Session keys (populated after handshake).
    session_keys: Option<SessionKeys>,
    /// AEAD cipher for sending messages.
    send_cipher: Option<FSChaCha20Poly1305>,
    /// AEAD cipher for receiving messages.
    recv_cipher: Option<FSChaCha20Poly1305>,
    /// Length encryption cipher for sending.
    send_length_cipher: Option<FSChaCha20>,
    /// Length decryption cipher for receiving.
    recv_length_cipher: Option<FSChaCha20>,
}

impl V2Transport {
    /// Create a new v2 transport for a connection.
    ///
    /// `is_initiator` indicates whether we initiated the connection
    /// (true = outbound, false = inbound).
    pub fn new(is_initiator: bool) -> Self {
        let secp = secp256k1::Secp256k1::new();
        let (secret, pubkey) = secp.generate_keypair(&mut rand::thread_rng());

        V2Transport {
            state: HandshakeState::KeyExchange,
            is_initiator,
            our_secret: Some(secret),
            our_pubkey: Some(pubkey),
            session_keys: None,
            send_cipher: None,
            recv_cipher: None,
            send_length_cipher: None,
            recv_length_cipher: None,
        }
    }

    /// Get our ephemeral public key as a 33-byte compressed encoding.
    ///
    /// Call this to obtain the bytes to send to the peer during
    /// the key exchange phase.
    pub fn our_pubkey_bytes(&self) -> Option<Vec<u8>> {
        self.our_pubkey.map(|pk| pk.serialize().to_vec())
    }

    /// Get the current handshake state.
    pub fn handshake_state(&self) -> HandshakeState {
        self.state
    }

    /// Get the session ID (for optional MITM detection).
    pub fn session_id(&self) -> Option<[u8; 32]> {
        self.session_keys.as_ref().map(|k| k.session_id)
    }

    /// Complete the handshake by processing the peer's public key.
    ///
    /// `peer_pubkey_bytes` is the 33-byte compressed public key
    /// received from the peer.  After this call, the transport
    /// transitions to `Established` and all subsequent messages
    /// must use `encrypt_message()` / `decrypt_message()`.
    pub fn complete_handshake(&mut self, peer_pubkey_bytes: &[u8]) -> Result<(), V2Error> {
        let our_secret = self
            .our_secret
            .take()
            .ok_or_else(|| V2Error::KeyExchangeFailed("no secret key".into()))?;

        let peer_pubkey = secp256k1::PublicKey::from_slice(peer_pubkey_bytes)
            .map_err(|e| V2Error::KeyExchangeFailed(format!("invalid peer pubkey: {}", e)))?;

        // Compute ECDH shared secret
        let shared_secret = bip324::ecdh_shared_secret(&our_secret, &peer_pubkey);

        // Derive session keys.  The "initiator" is whoever initiated the
        // TCP connection (outbound peer).
        let our_pk_bytes = self
            .our_pubkey
            .ok_or_else(|| V2Error::KeyExchangeFailed("no pubkey".into()))?
            .serialize();

        let (init_pk, resp_pk) = if self.is_initiator {
            (our_pk_bytes.as_ref(), peer_pubkey_bytes)
        } else {
            (peer_pubkey_bytes, our_pk_bytes.as_ref())
        };

        let keys = bip324::derive_session_keys(&shared_secret, init_pk, resp_pk);

        // Set up ciphers.
        // The initiator sends with initiator_key and receives with responder_key.
        let (send_key, recv_key, send_len_key, recv_len_key) = if self.is_initiator {
            (
                keys.initiator_key,
                keys.responder_key,
                keys.initiator_length_key,
                keys.responder_length_key,
            )
        } else {
            (
                keys.responder_key,
                keys.initiator_key,
                keys.responder_length_key,
                keys.initiator_length_key,
            )
        };

        self.send_cipher = Some(FSChaCha20Poly1305::new(send_key));
        self.recv_cipher = Some(FSChaCha20Poly1305::new(recv_key));
        self.send_length_cipher = Some(FSChaCha20::new(send_len_key));
        self.recv_length_cipher = Some(FSChaCha20::new(recv_len_key));
        self.session_keys = Some(keys);

        // Clear the secret key for forward secrecy
        // (already taken above via `take()`)
        self.our_pubkey = None;

        self.state = HandshakeState::Established;
        Ok(())
    }

    /// Encrypt a message for sending over the wire.
    ///
    /// Takes a v1 command string (e.g. "inv", "tx") and the payload
    /// bytes.  Returns the complete v2 wire bytes:
    ///   `encrypted_length(3) ‖ AEAD(flag ‖ command_id ‖ payload, tag)`
    ///
    /// The caller is responsible for writing the returned bytes to the
    /// TCP stream.
    pub fn encrypt_message(&mut self, command: &str, payload: &[u8]) -> Result<Vec<u8>, V2Error> {
        if self.state != HandshakeState::Established {
            return Err(V2Error::HandshakeIncomplete);
        }

        let aead = self.send_cipher.as_mut().unwrap();
        let len_cipher = self.send_length_cipher.as_mut().unwrap();

        // Build the plaintext: flag(1) ‖ command_id(1) ‖ payload
        // Flag byte: 0x00 = normal data message
        let mut plaintext = Vec::with_capacity(2 + payload.len());
        plaintext.push(0x00); // flag

        // Try to use a short command ID; fall back to full ASCII
        if let Some(id) = V2MessageId::from_command(command) {
            plaintext.push(id as u8);
        } else {
            plaintext.push(V2MessageId::Other as u8);
            // Write 12-byte null-padded command string
            let mut cmd_bytes = [0u8; 12];
            let bytes = command.as_bytes();
            let n = bytes.len().min(12);
            cmd_bytes[..n].copy_from_slice(&bytes[..n]);
            plaintext.extend_from_slice(&cmd_bytes);
        }

        plaintext.extend_from_slice(payload);

        // Encrypt with AEAD (no AAD for the content packet)
        let ciphertext = aead.encrypt(b"", &plaintext);
        // ciphertext includes the 16-byte Poly1305 tag

        // Encrypt the length
        let content_len = ciphertext.len() as u32;
        let mut length_bytes: [u8; 3] = [
            (content_len & 0xFF) as u8,
            ((content_len >> 8) & 0xFF) as u8,
            ((content_len >> 16) & 0xFF) as u8,
        ];
        len_cipher.crypt(&mut length_bytes);

        // Assemble wire bytes: encrypted_length ‖ ciphertext
        let mut wire = Vec::with_capacity(3 + ciphertext.len());
        wire.extend_from_slice(&length_bytes);
        wire.extend_from_slice(&ciphertext);

        Ok(wire)
    }

    /// Decrypt the 3-byte length prefix to determine how many more
    /// bytes to read from the stream.
    ///
    /// Returns the content length (number of bytes after the length
    /// prefix, including the 16-byte AEAD tag).
    pub fn decrypt_length(&mut self, encrypted_length: &mut [u8; 3]) -> Result<usize, V2Error> {
        if self.state != HandshakeState::Established {
            return Err(V2Error::HandshakeIncomplete);
        }

        let len_cipher = self.recv_length_cipher.as_mut().unwrap();
        len_cipher.crypt(encrypted_length);

        let length = encrypted_length[0] as usize
            | (encrypted_length[1] as usize) << 8
            | (encrypted_length[2] as usize) << 16;

        Ok(length)
    }

    /// Decrypt an encrypted content payload.
    ///
    /// `ciphertext` is the bytes after the 3-byte length prefix
    /// (including the 16-byte AEAD tag at the end).
    ///
    /// Returns `(command, payload)` on success.
    pub fn decrypt_message(&mut self, ciphertext: &[u8]) -> Result<(String, Vec<u8>), V2Error> {
        if self.state != HandshakeState::Established {
            return Err(V2Error::HandshakeIncomplete);
        }

        let aead = self.recv_cipher.as_mut().unwrap();

        let plaintext = aead
            .decrypt(b"", ciphertext)
            .ok_or(V2Error::DecryptionFailed)?;

        if plaintext.len() < 2 {
            return Err(V2Error::MessageTooShort);
        }

        let _flag = plaintext[0]; // 0x00 = data message
        let cmd_id = plaintext[1];

        if cmd_id == V2MessageId::Other as u8 {
            // Full ASCII command follows (12 bytes)
            if plaintext.len() < 14 {
                return Err(V2Error::MessageTooShort);
            }
            let cmd_bytes = &plaintext[2..14];
            let cmd = std::str::from_utf8(cmd_bytes)
                .unwrap_or("")
                .trim_end_matches('\0')
                .to_string();
            let payload = plaintext[14..].to_vec();
            Ok((cmd, payload))
        } else {
            // Map short ID to command string
            let cmd = match cmd_id {
                1 => "addr",
                2 => "block",
                3 => "getdata",
                4 => "getheaders",
                5 => "headers",
                6 => "inv",
                7 => "ping",
                8 => "pong",
                9 => "tx",
                10 => "getblocks",
                11 => "sendheaders",
                12 => "version",
                _ => return Err(V2Error::InvalidMessageId(cmd_id)),
            };
            let payload = plaintext[2..].to_vec();
            Ok((cmd.to_string(), payload))
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_and_encrypt_decrypt_roundtrip() {
        // Simulate two peers performing the v2 handshake
        let mut initiator = V2Transport::new(true);
        let mut responder = V2Transport::new(false);

        assert_eq!(initiator.handshake_state(), HandshakeState::KeyExchange);
        assert_eq!(responder.handshake_state(), HandshakeState::KeyExchange);

        // Exchange public keys
        let init_pk = initiator.our_pubkey_bytes().unwrap();
        let resp_pk = responder.our_pubkey_bytes().unwrap();

        // Complete handshake on both sides
        initiator.complete_handshake(&resp_pk).unwrap();
        responder.complete_handshake(&init_pk).unwrap();

        assert_eq!(initiator.handshake_state(), HandshakeState::Established);
        assert_eq!(responder.handshake_state(), HandshakeState::Established);

        // Session IDs must match (MITM detection)
        assert_eq!(initiator.session_id(), responder.session_id());

        // Initiator sends a message → responder decrypts it
        let wire = initiator
            .encrypt_message("ping", &42u64.to_le_bytes())
            .unwrap();

        // Split into length prefix and content
        let mut length_bytes: [u8; 3] = [wire[0], wire[1], wire[2]];
        let content_len = responder.decrypt_length(&mut length_bytes).unwrap();
        assert_eq!(content_len, wire.len() - 3);

        let (cmd, payload) = responder.decrypt_message(&wire[3..]).unwrap();
        assert_eq!(cmd, "ping");
        assert_eq!(payload, 42u64.to_le_bytes());
    }

    #[test]
    fn test_bidirectional_communication() {
        let mut initiator = V2Transport::new(true);
        let mut responder = V2Transport::new(false);

        let init_pk = initiator.our_pubkey_bytes().unwrap();
        let resp_pk = responder.our_pubkey_bytes().unwrap();

        initiator.complete_handshake(&resp_pk).unwrap();
        responder.complete_handshake(&init_pk).unwrap();

        // Initiator → Responder
        let wire1 = initiator.encrypt_message("inv", b"test_inv_data").unwrap();
        let mut len1: [u8; 3] = [wire1[0], wire1[1], wire1[2]];
        responder.decrypt_length(&mut len1).unwrap();
        let (cmd1, data1) = responder.decrypt_message(&wire1[3..]).unwrap();
        assert_eq!(cmd1, "inv");
        assert_eq!(data1, b"test_inv_data");

        // Responder → Initiator
        let wire2 = responder.encrypt_message("tx", b"tx_payload").unwrap();
        let mut len2: [u8; 3] = [wire2[0], wire2[1], wire2[2]];
        initiator.decrypt_length(&mut len2).unwrap();
        let (cmd2, data2) = initiator.decrypt_message(&wire2[3..]).unwrap();
        assert_eq!(cmd2, "tx");
        assert_eq!(data2, b"tx_payload");
    }

    #[test]
    fn test_encrypt_before_handshake_fails() {
        let mut transport = V2Transport::new(true);
        let result = transport.encrypt_message("ping", b"");
        assert!(result.is_err());
    }

    #[test]
    fn test_unknown_command_uses_ascii_fallback() {
        let mut initiator = V2Transport::new(true);
        let mut responder = V2Transport::new(false);

        let init_pk = initiator.our_pubkey_bytes().unwrap();
        let resp_pk = responder.our_pubkey_bytes().unwrap();

        initiator.complete_handshake(&resp_pk).unwrap();
        responder.complete_handshake(&init_pk).unwrap();

        // "cmpctblock" has no short ID → falls back to 12-byte ASCII
        let wire = initiator
            .encrypt_message("cmpctblock", b"compact_data")
            .unwrap();
        let mut len: [u8; 3] = [wire[0], wire[1], wire[2]];
        responder.decrypt_length(&mut len).unwrap();
        let (cmd, data) = responder.decrypt_message(&wire[3..]).unwrap();
        assert_eq!(cmd, "cmpctblock");
        assert_eq!(data, b"compact_data");
    }

    #[test]
    fn test_tampered_ciphertext_rejected() {
        let mut initiator = V2Transport::new(true);
        let mut responder = V2Transport::new(false);

        let init_pk = initiator.our_pubkey_bytes().unwrap();
        let resp_pk = responder.our_pubkey_bytes().unwrap();

        initiator.complete_handshake(&resp_pk).unwrap();
        responder.complete_handshake(&init_pk).unwrap();

        let mut wire = initiator.encrypt_message("ping", b"data").unwrap();

        // Decrypt the length first (to advance the length cipher counter)
        let mut len: [u8; 3] = [wire[0], wire[1], wire[2]];
        responder.decrypt_length(&mut len).unwrap();

        // Tamper with the AEAD ciphertext
        if wire.len() > 5 {
            wire[5] ^= 0x01;
        }

        let result = responder.decrypt_message(&wire[3..]);
        assert!(result.is_err());
    }

    #[test]
    fn test_many_messages_across_rekey_boundary() {
        let mut initiator = V2Transport::new(true);
        let mut responder = V2Transport::new(false);

        let init_pk = initiator.our_pubkey_bytes().unwrap();
        let resp_pk = responder.our_pubkey_bytes().unwrap();

        initiator.complete_handshake(&resp_pk).unwrap();
        responder.complete_handshake(&init_pk).unwrap();

        // Send 250 messages — crosses the 224-message rekey boundary
        for i in 0u32..250 {
            let payload = i.to_le_bytes();
            let wire = initiator.encrypt_message("ping", &payload).unwrap();

            let mut len: [u8; 3] = [wire[0], wire[1], wire[2]];
            let _content_len = responder.decrypt_length(&mut len).unwrap();
            let (cmd, data) = responder
                .decrypt_message(&wire[3..])
                .expect(&format!("decrypt failed at message {}", i));

            assert_eq!(cmd, "ping");
            assert_eq!(data, payload);
        }
    }

    #[test]
    fn test_invalid_peer_pubkey() {
        let mut transport = V2Transport::new(true);
        let result = transport.complete_handshake(&[0x00; 33]);
        assert!(result.is_err());
    }

    // ═══════════════════════════════════════════════════════════
    // Regression tests — Session 15 (BIP324 v2 transport)
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn regression_session_ids_match_after_handshake() {
        let mut a = V2Transport::new(true);
        let mut b = V2Transport::new(false);

        let pk_a = a.our_pubkey_bytes().unwrap();
        let pk_b = b.our_pubkey_bytes().unwrap();

        a.complete_handshake(&pk_b).unwrap();
        b.complete_handshake(&pk_a).unwrap();

        let sid_a = a.session_id().unwrap();
        let sid_b = b.session_id().unwrap();
        assert_eq!(sid_a, sid_b);
        assert_ne!(sid_a, [0u8; 32]);
    }

    #[test]
    fn regression_different_sessions_different_keys() {
        // Two independent sessions must produce different session IDs
        let mut a1 = V2Transport::new(true);
        let mut b1 = V2Transport::new(false);
        let pk_a1 = a1.our_pubkey_bytes().unwrap();
        let pk_b1 = b1.our_pubkey_bytes().unwrap();
        a1.complete_handshake(&pk_b1).unwrap();
        b1.complete_handshake(&pk_a1).unwrap();

        let mut a2 = V2Transport::new(true);
        let mut b2 = V2Transport::new(false);
        let pk_a2 = a2.our_pubkey_bytes().unwrap();
        let pk_b2 = b2.our_pubkey_bytes().unwrap();
        a2.complete_handshake(&pk_b2).unwrap();
        b2.complete_handshake(&pk_a2).unwrap();

        // Ephemeral keys are random → session IDs differ
        assert_ne!(a1.session_id(), a2.session_id());
    }

    #[test]
    fn regression_v2_all_short_commands_roundtrip() {
        let mut initiator = V2Transport::new(true);
        let mut responder = V2Transport::new(false);

        let init_pk = initiator.our_pubkey_bytes().unwrap();
        let resp_pk = responder.our_pubkey_bytes().unwrap();
        initiator.complete_handshake(&resp_pk).unwrap();
        responder.complete_handshake(&init_pk).unwrap();

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
            let wire = initiator.encrypt_message(cmd, b"").unwrap();
            let mut len: [u8; 3] = [wire[0], wire[1], wire[2]];
            responder.decrypt_length(&mut len).unwrap();
            let (got_cmd, _) = responder.decrypt_message(&wire[3..]).unwrap();
            assert_eq!(got_cmd, cmd, "roundtrip failed for command '{}'", cmd);
        }
    }

    #[test]
    fn regression_v2_error_display() {
        // Ensure all error variants have non-empty Display output
        let errors = [
            V2Error::HandshakeIncomplete,
            V2Error::KeyExchangeFailed("test".into()),
            V2Error::DecryptionFailed,
            V2Error::MessageTooShort,
            V2Error::InvalidMessageId(255),
        ];
        for e in &errors {
            assert!(!format!("{}", e).is_empty());
        }
    }
}

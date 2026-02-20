//! ECDSA signature verification using libsecp256k1
//!
//! Provides a concrete `SignatureChecker` implementation that uses the
//! `secp256k1` crate (Rust bindings to Bitcoin Core's libsecp256k1) to
//! verify ECDSA signatures against public keys.
//!
//! ## Sighash computation
//!
//! Bitcoin transaction signing follows a specific protocol:
//! 1. A "sighash" is computed by serializing a modified copy of the
//!    transaction (with inputs/outputs masked according to the sighash type)
//! 2. The sighash is double-SHA256'd to produce the message digest
//! 3. The signature is verified against this digest and the public key
//!
//! This module implements sighash types SIGHASH_ALL, SIGHASH_NONE,
//! SIGHASH_SINGLE, and the SIGHASH_ANYONECANPAY modifier.

use crate::crypto::hashing;
use crate::primitives::{Transaction, Amount};
use crate::script::interpreter::SignatureChecker;
use crate::script::script::Script;

/// Sighash type constants
pub mod sighash_type {
    pub const SIGHASH_ALL: u8 = 0x01;
    pub const SIGHASH_NONE: u8 = 0x02;
    pub const SIGHASH_SINGLE: u8 = 0x03;
    pub const SIGHASH_ANYONECANPAY: u8 = 0x80;
}

/// A signature checker that verifies ECDSA signatures for a specific
/// transaction input.
///
/// This is the "real" checker used during block/transaction validation.
/// It holds a reference to the spending transaction and the index of
/// the input being validated, allowing it to compute the correct sighash.
pub struct TransactionSignatureChecker<'a> {
    /// The transaction being validated
    tx: &'a Transaction,
    /// The input index being validated
    input_index: usize,
    /// The amount of the output being spent (needed for SegWit sighash)
    _amount: Amount,
    /// The lock time of the transaction
    lock_time: u32,
    /// The sequence number of the input
    sequence: u32,
}

impl<'a> TransactionSignatureChecker<'a> {
    /// Create a new transaction signature checker
    pub fn new(tx: &'a Transaction, input_index: usize, amount: Amount) -> Self {
        let lock_time = tx.lock_time;
        let sequence = if input_index < tx.inputs.len() {
            tx.inputs[input_index].sequence
        } else {
            0
        };

        TransactionSignatureChecker {
            tx,
            input_index,
            _amount: amount,
            lock_time,
            sequence,
        }
    }

    /// Compute the legacy sighash (pre-SegWit) for the given hash type.
    ///
    /// This follows Bitcoin Core's `SignatureHash()` function logic.
    fn compute_sighash_legacy(&self, script_code: &Script, hash_type: u8) -> [u8; 32] {
        let base_type = hash_type & 0x1f;
        let anyone_can_pay = hash_type & sighash_type::SIGHASH_ANYONECANPAY != 0;

        let mut data = Vec::new();

        // Transaction version
        data.extend_from_slice(&self.tx.version.to_le_bytes());

        // Inputs
        if anyone_can_pay {
            // Only include the current input
            data.push(1u8); // varint count = 1
            let input = &self.tx.inputs[self.input_index];
            data.extend_from_slice(input.previous_output.txid.as_bytes());
            data.extend_from_slice(&input.previous_output.vout.to_le_bytes());
            // Script code
            let sc = script_code.as_bytes();
            push_varint(&mut data, sc.len() as u64);
            data.extend_from_slice(sc);
            data.extend_from_slice(&input.sequence.to_le_bytes());
        } else {
            // Include all inputs
            push_varint(&mut data, self.tx.inputs.len() as u64);
            for (i, input) in self.tx.inputs.iter().enumerate() {
                data.extend_from_slice(input.previous_output.txid.as_bytes());
                data.extend_from_slice(&input.previous_output.vout.to_le_bytes());
                if i == self.input_index {
                    let sc = script_code.as_bytes();
                    push_varint(&mut data, sc.len() as u64);
                    data.extend_from_slice(sc);
                } else {
                    data.push(0u8); // empty script for other inputs
                }
                if (base_type == sighash_type::SIGHASH_NONE
                    || base_type == sighash_type::SIGHASH_SINGLE)
                    && i != self.input_index
                {
                    data.extend_from_slice(&0u32.to_le_bytes()); // zero sequence
                } else {
                    data.extend_from_slice(&input.sequence.to_le_bytes());
                }
            }
        }

        // Outputs
        match base_type {
            sighash_type::SIGHASH_NONE => {
                data.push(0u8); // no outputs
            }
            sighash_type::SIGHASH_SINGLE => {
                if self.input_index < self.tx.outputs.len() {
                    push_varint(&mut data, (self.input_index + 1) as u64);
                    for i in 0..=self.input_index {
                        if i == self.input_index {
                            let out = &self.tx.outputs[i];
                            data.extend_from_slice(&out.value.as_sat().to_le_bytes());
                            let spk = out.script_pubkey.as_bytes();
                            push_varint(&mut data, spk.len() as u64);
                            data.extend_from_slice(spk);
                        } else {
                            // "blank" outputs
                            data.extend_from_slice(&(-1i64 as u64).to_le_bytes());
                            data.push(0u8);
                        }
                    }
                } else {
                    data.push(0u8);
                }
            }
            _ => {
                // SIGHASH_ALL — include all outputs
                push_varint(&mut data, self.tx.outputs.len() as u64);
                for out in &self.tx.outputs {
                    data.extend_from_slice(&out.value.as_sat().to_le_bytes());
                    let spk = out.script_pubkey.as_bytes();
                    push_varint(&mut data, spk.len() as u64);
                    data.extend_from_slice(spk);
                }
            }
        }

        // Lock time
        data.extend_from_slice(&self.tx.lock_time.to_le_bytes());

        // Sighash type (4 bytes LE)
        data.extend_from_slice(&(hash_type as u32).to_le_bytes());

        // Double SHA-256
        let hash = hashing::hash256(&data);
        let mut result = [0u8; 32];
        result.copy_from_slice(hash.as_bytes());
        result
    }
}

/// Push a Bitcoin-style varint to a buffer
fn push_varint(buf: &mut Vec<u8>, value: u64) {
    if value < 0xfd {
        buf.push(value as u8);
    } else if value <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(value as u16).to_le_bytes());
    } else if value <= 0xffff_ffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(value as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&value.to_le_bytes());
    }
}

impl<'a> SignatureChecker for TransactionSignatureChecker<'a> {
    fn check_sig(
        &self,
        sig: &[u8],
        pubkey: &[u8],
        script_code: &Script,
    ) -> bool {
        if sig.is_empty() || pubkey.is_empty() {
            return false;
        }

        // Last byte of signature is the sighash type
        let hash_type = sig[sig.len() - 1];
        let der_sig = &sig[..sig.len() - 1];

        // Compute sighash
        let sighash = self.compute_sighash_legacy(script_code, hash_type);

        // Verify using secp256k1
        verify_ecdsa(&sighash, der_sig, pubkey)
    }

    fn check_lock_time(&self, lock_time: i64) -> bool {
        // BIP65: nLockTime must be <= tx locktime, and both must be same type
        let tx_lock = self.lock_time as i64;

        // Type mismatch check
        if (tx_lock < 500_000_000) != (lock_time < 500_000_000) {
            return false;
        }

        if lock_time > tx_lock {
            return false;
        }

        // Input must not have sequence 0xFFFFFFFF (final)
        if self.sequence == 0xFFFFFFFF {
            return false;
        }

        true
    }

    fn check_sequence(&self, sequence: i64) -> bool {
        // BIP112: relative lock-time
        let tx_version = self.tx.version;
        if tx_version < 2 {
            return false;
        }

        // Disable flag
        if self.sequence & (1 << 31) != 0 {
            return false;
        }

        let sequence = sequence as u32;
        let tx_sequence = self.sequence;

        // Type flag (bit 22) must match
        let mask_type = 1u32 << 22;
        if (sequence & mask_type) != (tx_sequence & mask_type) {
            return false;
        }

        // Masked value comparison
        let mask_value = 0x0000ffff;
        (sequence & mask_value) <= (tx_sequence & mask_value)
    }
}

/// Verify an ECDSA signature using the secp256k1 crate.
///
/// Returns true if the signature is valid for the given message hash and public key.
pub fn verify_ecdsa(msg_hash: &[u8; 32], der_sig: &[u8], pubkey_bytes: &[u8]) -> bool {
    use secp256k1::{Message, PublicKey, Secp256k1};
    use secp256k1::ecdsa::Signature;

    let secp = Secp256k1::verification_only();

    // Parse public key
    let pubkey = match PublicKey::from_slice(pubkey_bytes) {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    // Parse DER signature
    let sig = match Signature::from_der(der_sig) {
        Ok(s) => s,
        Err(_) => {
            // Try compact/normalized form as fallback
            match Signature::from_compact(der_sig) {
                Ok(s) => s,
                Err(_) => return false,
            }
        }
    };

    // Parse message
    let msg = match Message::from_digest_slice(msg_hash) {
        Ok(m) => m,
        Err(_) => return false,
    };

    // Verify
    secp.verify_ecdsa(&msg, &sig, &pubkey).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_push_varint() {
        let mut buf = Vec::new();
        push_varint(&mut buf, 0);
        assert_eq!(buf, vec![0]);

        buf.clear();
        push_varint(&mut buf, 252);
        assert_eq!(buf, vec![252]);

        buf.clear();
        push_varint(&mut buf, 253);
        assert_eq!(buf, vec![0xfd, 253, 0]);

        buf.clear();
        push_varint(&mut buf, 0x1234);
        assert_eq!(buf, vec![0xfd, 0x34, 0x12]);
    }

    #[test]
    fn test_sighash_type_constants() {
        assert_eq!(sighash_type::SIGHASH_ALL, 1);
        assert_eq!(sighash_type::SIGHASH_NONE, 2);
        assert_eq!(sighash_type::SIGHASH_SINGLE, 3);
        assert_eq!(sighash_type::SIGHASH_ANYONECANPAY, 0x80);
    }
}

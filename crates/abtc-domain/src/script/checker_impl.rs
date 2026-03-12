//! SignatureChecker trait implementation for TransactionSignatureChecker.
//!
//! This lives in the `script` module (rather than `crypto`) so that:
//! - `crypto` does not depend on `script` (avoiding a cycle)
//! - `crypto` does not depend on `covenants` (avoiding a cycle)
//!
//! The impl uses inherent `pub(crate)` sighash methods defined on
//! `TransactionSignatureChecker` in `crypto::signing`.

use crate::covenants::ctv::compute_ctv_hash;
use crate::covenants::vault::{verify_vault_trigger, verify_vault_recover, VaultTriggerInfo};
use crate::crypto::schnorr::verify_schnorr;
use crate::crypto::signing::{verify_ecdsa, TransactionSignatureChecker};
use crate::primitives::{Amount, Hash256, Script};
use super::interpreter::SignatureChecker;

impl<'a> SignatureChecker for TransactionSignatureChecker<'a> {
    fn check_sig(&self, sig: &[u8], pubkey: &[u8], script_code: &Script) -> bool {
        if sig.is_empty() || pubkey.is_empty() {
            return false;
        }

        // Last byte of signature is the sighash type
        let hash_type = sig[sig.len() - 1];
        let der_sig = &sig[..sig.len() - 1];

        // Compute sighash using appropriate algorithm
        let sighash = if self.witness_v0 {
            self.compute_sighash_witness_v0(script_code, hash_type)
        } else {
            self.compute_sighash_legacy(script_code, hash_type)
        };

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

    fn check_schnorr_sig(&self, sig: &[u8], pubkey: &[u8], hash_type: u8) -> bool {
        if sig.len() != 64 || pubkey.len() != 32 {
            return false;
        }

        // Use script-path sighash if tapleaf_hash is set, else key-path
        let sighash = if let Some(ref leaf_hash) = self.tapleaf_hash {
            self.compute_taproot_sighash_script_path(leaf_hash, hash_type)
        } else {
            self.compute_taproot_sighash(hash_type)
        };

        verify_schnorr(pubkey, &sighash, sig)
    }

    fn check_tapscript_sig(
        &self,
        sig: &[u8],
        pubkey: &[u8],
        leaf_hash: &[u8; 32],
        hash_type: u8,
    ) -> bool {
        if sig.len() != 64 || pubkey.len() != 32 {
            return false;
        }

        let sighash = self.compute_taproot_sighash_script_path(leaf_hash, hash_type);
        verify_schnorr(pubkey, &sighash, sig)
    }

    fn check_ctv(&self, hash: &[u8; 32]) -> bool {
        let expected = compute_ctv_hash(self.tx, self.input_index as u32);
        expected.as_bytes() == hash
    }

    fn check_vault(
        &self,
        target_output_index: u32,
        leaf_update_script_body: &[u8],
        spend_delay: u32,
        _recovery_spk_hash: &[u8; 32],
    ) -> bool {
        let trigger = VaultTriggerInfo {
            target_output_index,
            leaf_update_script_body: leaf_update_script_body.to_vec(),
        };
        // Use 10_000 sat fee tolerance (configurable in production)
        verify_vault_trigger(
            self.tx,
            &trigger,
            self.amount,
            spend_delay,
            Amount::from_sat(10_000),
        )
        .is_ok()
    }

    fn check_vault_recover(&self, target_output_index: u32, recovery_spk_hash: &[u8; 32]) -> bool {
        let recovery_hash = Hash256::from_bytes(*recovery_spk_hash);
        // Use 10_000 sat fee tolerance (configurable in production)
        verify_vault_recover(
            self.tx,
            target_output_index,
            &recovery_hash,
            self.amount,
            Amount::from_sat(10_000),
        )
        .is_ok()
    }
}

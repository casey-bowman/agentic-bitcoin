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
//!
//! ## BIP143 (SegWit v0 sighash)
//!
//! For SegWit inputs (P2WPKH, P2WSH), the sighash is computed differently
//! using the algorithm specified in BIP143. This eliminates the quadratic
//! hashing problem of legacy sighash and commits to the value of the
//! spent output.

use crate::crypto::hashing;
use crate::primitives::{Amount, Transaction};
use crate::script::interpreter::SignatureChecker;
use crate::script::script::Script;

/// Sighash type constants
pub mod sighash_type {
    pub const SIGHASH_ALL: u8 = 0x01;
    pub const SIGHASH_NONE: u8 = 0x02;
    pub const SIGHASH_SINGLE: u8 = 0x03;
    pub const SIGHASH_ANYONECANPAY: u8 = 0x80;
}

/// Information about a spent output, needed for Taproot sighash (BIP341).
///
/// BIP341 requires committing to the amounts and scriptPubKeys of ALL spent
/// outputs (not just the current input), unlike BIP143 which only needs the
/// current input's amount.
#[derive(Debug, Clone)]
pub struct SpentOutput {
    /// The value of the spent output
    pub amount: Amount,
    /// The scriptPubKey of the spent output
    pub script_pubkey: Script,
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
    amount: Amount,
    /// The lock time of the transaction
    lock_time: u32,
    /// The sequence number of the input
    sequence: u32,
    /// Whether to use BIP143 (SegWit v0) sighash computation
    witness_v0: bool,
    /// All spent outputs (needed for Taproot sighash — BIP341 §4.1)
    spent_outputs: Option<Vec<SpentOutput>>,
    /// Tapleaf hash for script-path spending (BIP341 §4.3).
    /// When set, check_schnorr_sig uses script-path sighash instead of key-path.
    tapleaf_hash: Option<[u8; 32]>,
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
            amount,
            lock_time,
            sequence,
            witness_v0: false,
            spent_outputs: None,
            tapleaf_hash: None,
        }
    }

    /// Create a new signature checker configured for BIP143 (SegWit v0) sighash.
    ///
    /// This is used when verifying witness programs (P2WPKH, P2WSH).
    /// The amount parameter is critical for BIP143 as it's included in the
    /// sighash preimage (unlike legacy sighash).
    pub fn new_witness_v0(tx: &'a Transaction, input_index: usize, amount: Amount) -> Self {
        let mut checker = Self::new(tx, input_index, amount);
        checker.witness_v0 = true;
        checker
    }

    /// Create a new signature checker configured for Taproot (BIP341) sighash.
    ///
    /// BIP341 requires all spent outputs (amounts + scriptPubKeys) to be
    /// committed in the sighash, not just the current input's.
    pub fn new_taproot(
        tx: &'a Transaction,
        input_index: usize,
        spent_outputs: Vec<SpentOutput>,
    ) -> Self {
        let amount = if input_index < spent_outputs.len() {
            spent_outputs[input_index].amount
        } else {
            Amount::from_sat(0)
        };
        let mut checker = Self::new(tx, input_index, amount);
        checker.spent_outputs = Some(spent_outputs);
        checker
    }

    /// Set the tapleaf hash for script-path signature verification.
    ///
    /// When set, `check_schnorr_sig` will compute the script-path sighash
    /// (BIP341 §4.3) instead of the key-path sighash.
    pub fn set_tapleaf_hash(&mut self, leaf_hash: [u8; 32]) {
        self.tapleaf_hash = Some(leaf_hash);
    }

    /// Compute the Taproot sighash for key-path spending (BIP341 §4.1).
    ///
    /// This implements SIGHASH_DEFAULT (0x00) which commits to all inputs
    /// and outputs. The sighash is computed as:
    ///
    ///   tagged_hash("TapSighash", epoch || hash_type || version || locktime ||
    ///     sha256(prevouts) || sha256(amounts) || sha256(scriptpubkeys) ||
    ///     sha256(sequences) || sha256(outputs) || spend_type || input_index)
    pub(crate) fn compute_taproot_sighash(&self, hash_type: u8) -> [u8; 32] {
        use sha2::{Digest, Sha256};

        // SHA256 of all prevouts (txid || vout for each input)
        let mut prevouts_hasher = Sha256::new();
        for input in &self.tx.inputs {
            prevouts_hasher.update(input.previous_output.txid.as_bytes());
            prevouts_hasher.update(input.previous_output.vout.to_le_bytes());
        }
        let sha_prevouts: [u8; 32] = prevouts_hasher.finalize().into();

        // BIP341 requires all spent outputs for the sighash. If they're missing,
        // we cannot compute a correct sighash — return a sentinel that will never
        // match a valid signature, causing verification to fail deterministically.
        let spent = match self.spent_outputs {
            Some(ref s) => s,
            None => return [0xff; 32],
        };

        // SHA256 of all amounts
        let mut amounts_hasher = Sha256::new();
        for so in spent {
            amounts_hasher.update(so.amount.as_sat().to_le_bytes());
        }
        let sha_amounts: [u8; 32] = amounts_hasher.finalize().into();

        // SHA256 of all scriptpubkeys
        let mut spks_hasher = Sha256::new();
        for so in spent {
            let spk = so.script_pubkey.as_bytes();
            encode_compact_size_into(&mut spks_hasher, spk.len());
            spks_hasher.update(spk);
        }
        let sha_scriptpubkeys: [u8; 32] = spks_hasher.finalize().into();

        // SHA256 of all sequences
        let mut sequences_hasher = Sha256::new();
        for input in &self.tx.inputs {
            sequences_hasher.update(input.sequence.to_le_bytes());
        }
        let sha_sequences: [u8; 32] = sequences_hasher.finalize().into();

        // SHA256 of all outputs
        let mut outputs_hasher = Sha256::new();
        for output in &self.tx.outputs {
            outputs_hasher.update(output.value.as_sat().to_le_bytes());
            let spk_bytes = output.script_pubkey.as_bytes();
            encode_compact_size_into(&mut outputs_hasher, spk_bytes.len());
            outputs_hasher.update(spk_bytes);
        }
        let sha_outputs: [u8; 32] = outputs_hasher.finalize().into();

        // Build the sighash preimage (everything after epoch + hash_type)
        let mut preimage = Vec::with_capacity(200);
        // nVersion
        preimage.extend_from_slice(&self.tx.version.to_le_bytes());
        // nLockTime
        preimage.extend_from_slice(&self.lock_time.to_le_bytes());
        // sha_prevouts || sha_amounts || sha_scriptpubkeys || sha_sequences
        preimage.extend_from_slice(&sha_prevouts);
        preimage.extend_from_slice(&sha_amounts);
        preimage.extend_from_slice(&sha_scriptpubkeys);
        preimage.extend_from_slice(&sha_sequences);
        // sha_outputs
        preimage.extend_from_slice(&sha_outputs);
        // spend_type: 0x00 for key-path with no annex
        preimage.push(0x00);
        // input_index
        preimage.extend_from_slice(&(self.input_index as u32).to_le_bytes());

        super::taproot::taproot_sighash(0x00, hash_type, &preimage)
    }

    /// Compute the Taproot sighash for script-path spending (BIP341 §4.3).
    ///
    /// Script-path spending extends the key-path sighash with:
    /// - `spend_type` = `ext_flag * 2` (ext_flag = 1 for script-path)
    /// - tapleaf_hash (32 bytes) appended after input_index
    /// - key_version (1 byte, always 0x00 for BIP342 tapscripts)
    /// - code_separator_pos (4 bytes, 0xFFFFFFFF if no OP_CODESEPARATOR)
    pub(crate) fn compute_taproot_sighash_script_path(
        &self,
        leaf_hash: &[u8; 32],
        hash_type: u8,
    ) -> [u8; 32] {
        use sha2::{Digest, Sha256};

        // Same common preimage as key-path...
        let mut prevouts_hasher = Sha256::new();
        for input in &self.tx.inputs {
            prevouts_hasher.update(input.previous_output.txid.as_bytes());
            prevouts_hasher.update(input.previous_output.vout.to_le_bytes());
        }
        let sha_prevouts: [u8; 32] = prevouts_hasher.finalize().into();

        // BIP341 requires all spent outputs. Fail if missing.
        let spent = match self.spent_outputs {
            Some(ref s) => s,
            None => return [0xff; 32],
        };

        let mut amounts_hasher = Sha256::new();
        for so in spent {
            amounts_hasher.update(so.amount.as_sat().to_le_bytes());
        }
        let sha_amounts: [u8; 32] = amounts_hasher.finalize().into();

        let mut spks_hasher = Sha256::new();
        for so in spent {
            let spk = so.script_pubkey.as_bytes();
            encode_compact_size_into(&mut spks_hasher, spk.len());
            spks_hasher.update(spk);
        }
        let sha_scriptpubkeys: [u8; 32] = spks_hasher.finalize().into();

        let mut sequences_hasher = Sha256::new();
        for input in &self.tx.inputs {
            sequences_hasher.update(input.sequence.to_le_bytes());
        }
        let sha_sequences: [u8; 32] = sequences_hasher.finalize().into();

        let mut outputs_hasher = Sha256::new();
        for output in &self.tx.outputs {
            outputs_hasher.update(output.value.as_sat().to_le_bytes());
            let spk_bytes = output.script_pubkey.as_bytes();
            encode_compact_size_into(&mut outputs_hasher, spk_bytes.len());
            outputs_hasher.update(spk_bytes);
        }
        let sha_outputs: [u8; 32] = outputs_hasher.finalize().into();

        // Build preimage
        let mut preimage = Vec::with_capacity(250);
        preimage.extend_from_slice(&self.tx.version.to_le_bytes());
        preimage.extend_from_slice(&self.lock_time.to_le_bytes());
        preimage.extend_from_slice(&sha_prevouts);
        preimage.extend_from_slice(&sha_amounts);
        preimage.extend_from_slice(&sha_scriptpubkeys);
        preimage.extend_from_slice(&sha_sequences);
        preimage.extend_from_slice(&sha_outputs);
        // spend_type: ext_flag=1 → spend_type = 0x02 (no annex)
        preimage.push(0x02);
        // input_index
        preimage.extend_from_slice(&(self.input_index as u32).to_le_bytes());

        // Script-path extension (BIP341 §4.3):
        // tapleaf_hash (32 bytes)
        preimage.extend_from_slice(leaf_hash);
        // key_version (1 byte, 0x00 for BIP342)
        preimage.push(0x00);
        // code_separator_pos (4 bytes LE, 0xFFFFFFFF = no OP_CODESEPARATOR executed)
        preimage.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());

        super::taproot::taproot_sighash(0x00, hash_type, &preimage)
    }

    /// Compute the legacy sighash (pre-SegWit) for the given hash type.
    ///
    /// This follows Bitcoin Core's `SignatureHash()` function logic.
    pub(crate) fn compute_sighash_legacy(&self, script_code: &Script, hash_type: u8) -> [u8; 32] {
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

    /// Compute the BIP143 SegWit v0 sighash.
    ///
    /// BIP143 defines a new transaction digest algorithm for SegWit inputs
    /// that fixes the O(n²) hashing problem and commits to the spent output
    /// value. The serialization is:
    ///
    /// 1. nVersion (4 bytes LE)
    /// 2. hashPrevouts (32 bytes)
    /// 3. hashSequence (32 bytes)
    /// 4. outpoint being spent (32+4 bytes)
    /// 5. scriptCode (varint + data)
    /// 6. value of output being spent (8 bytes LE)
    /// 7. nSequence of this input (4 bytes LE)
    /// 8. hashOutputs (32 bytes)
    /// 9. nLockTime (4 bytes LE)
    /// 10. sighash type (4 bytes LE)
    pub(crate) fn compute_sighash_witness_v0(
        &self,
        script_code: &Script,
        hash_type: u8,
    ) -> [u8; 32] {
        let base_type = hash_type & 0x1f;
        let anyone_can_pay = hash_type & sighash_type::SIGHASH_ANYONECANPAY != 0;

        // 2. hashPrevouts
        let hash_prevouts = if !anyone_can_pay {
            let mut buf = Vec::new();
            for input in &self.tx.inputs {
                buf.extend_from_slice(input.previous_output.txid.as_bytes());
                buf.extend_from_slice(&input.previous_output.vout.to_le_bytes());
            }
            let h = hashing::hash256(&buf);
            let mut arr = [0u8; 32];
            arr.copy_from_slice(h.as_bytes());
            arr
        } else {
            [0u8; 32]
        };

        // 3. hashSequence
        let hash_sequence = if !anyone_can_pay
            && base_type != sighash_type::SIGHASH_SINGLE
            && base_type != sighash_type::SIGHASH_NONE
        {
            let mut buf = Vec::new();
            for input in &self.tx.inputs {
                buf.extend_from_slice(&input.sequence.to_le_bytes());
            }
            let h = hashing::hash256(&buf);
            let mut arr = [0u8; 32];
            arr.copy_from_slice(h.as_bytes());
            arr
        } else {
            [0u8; 32]
        };

        // 8. hashOutputs
        let hash_outputs = if base_type != sighash_type::SIGHASH_SINGLE
            && base_type != sighash_type::SIGHASH_NONE
        {
            // SIGHASH_ALL: hash all outputs
            let mut buf = Vec::new();
            for out in &self.tx.outputs {
                buf.extend_from_slice(&out.value.as_sat().to_le_bytes());
                let spk = out.script_pubkey.as_bytes();
                push_varint(&mut buf, spk.len() as u64);
                buf.extend_from_slice(spk);
            }
            let h = hashing::hash256(&buf);
            let mut arr = [0u8; 32];
            arr.copy_from_slice(h.as_bytes());
            arr
        } else if base_type == sighash_type::SIGHASH_SINGLE
            && self.input_index < self.tx.outputs.len()
        {
            // SIGHASH_SINGLE: hash only the corresponding output
            let mut buf = Vec::new();
            let out = &self.tx.outputs[self.input_index];
            buf.extend_from_slice(&out.value.as_sat().to_le_bytes());
            let spk = out.script_pubkey.as_bytes();
            push_varint(&mut buf, spk.len() as u64);
            buf.extend_from_slice(spk);
            let h = hashing::hash256(&buf);
            let mut arr = [0u8; 32];
            arr.copy_from_slice(h.as_bytes());
            arr
        } else {
            [0u8; 32]
        };

        // Now build the full preimage
        let mut data = Vec::new();

        // 1. nVersion
        data.extend_from_slice(&self.tx.version.to_le_bytes());

        // 2. hashPrevouts
        data.extend_from_slice(&hash_prevouts);

        // 3. hashSequence
        data.extend_from_slice(&hash_sequence);

        // 4. outpoint (txid + vout)
        let input = &self.tx.inputs[self.input_index];
        data.extend_from_slice(input.previous_output.txid.as_bytes());
        data.extend_from_slice(&input.previous_output.vout.to_le_bytes());

        // 5. scriptCode
        let sc = script_code.as_bytes();
        push_varint(&mut data, sc.len() as u64);
        data.extend_from_slice(sc);

        // 6. value of the output being spent
        data.extend_from_slice(&self.amount.as_sat().to_le_bytes());

        // 7. nSequence of this input
        data.extend_from_slice(&input.sequence.to_le_bytes());

        // 8. hashOutputs
        data.extend_from_slice(&hash_outputs);

        // 9. nLockTime
        data.extend_from_slice(&self.tx.lock_time.to_le_bytes());

        // 10. sighash type
        data.extend_from_slice(&(hash_type as u32).to_le_bytes());

        // Double SHA-256
        let hash = hashing::hash256(&data);
        let mut result = [0u8; 32];
        result.copy_from_slice(hash.as_bytes());
        result
    }
}

/// Encode a compact size integer directly into a hasher (for Taproot sighash).
fn encode_compact_size_into<D: sha2::Digest>(hasher: &mut D, size: usize) {
    let mut buf = Vec::with_capacity(9);
    push_varint(&mut buf, size as u64);
    hasher.update(&buf);
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

        super::schnorr::verify_schnorr(pubkey, &sighash, sig)
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
        super::schnorr::verify_schnorr(pubkey, &sighash, sig)
    }

    fn check_ctv(&self, hash: &[u8; 32]) -> bool {
        use crate::covenants::ctv::compute_ctv_hash;
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
        use crate::covenants::vault::{verify_vault_trigger, VaultTriggerInfo};

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
        use crate::covenants::vault::verify_vault_recover;
        use crate::primitives::Hash256;

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

/// Verify an ECDSA signature using the secp256k1 crate.
///
/// Returns true if the signature is valid for the given message hash and public key.
pub fn verify_ecdsa(msg_hash: &[u8; 32], der_sig: &[u8], pubkey_bytes: &[u8]) -> bool {
    use secp256k1::ecdsa::Signature;
    use secp256k1::{Message, PublicKey, Secp256k1};

    let secp = Secp256k1::verification_only();

    // Parse public key
    let pubkey = match PublicKey::from_slice(pubkey_bytes) {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    // Parse DER signature (strict DER only — no compact fallback per BIP66)
    let sig = match Signature::from_der(der_sig) {
        Ok(s) => s,
        Err(_) => return false,
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

    #[test]
    fn test_witness_v0_checker_creation() {
        use crate::primitives::{OutPoint, TxIn, TxOut, Txid};

        let tx = Transaction::new(
            2,
            vec![TxIn::new(
                OutPoint::new(Txid::zero(), 0),
                Script::new(),
                0xfffffffe,
            )],
            vec![TxOut::new(Amount::from_sat(100_000), Script::new())],
            500_000,
        );

        let checker =
            TransactionSignatureChecker::new_witness_v0(&tx, 0, Amount::from_sat(600_000));
        assert!(checker.witness_v0);
    }

    #[test]
    fn test_bip143_sighash_components() {
        // Test that BIP143 sighash produces a different hash than legacy
        // for the same transaction (they use fundamentally different algorithms)
        use crate::primitives::{OutPoint, TxIn, TxOut, Txid};

        let tx = Transaction::new(
            1,
            vec![TxIn::new(
                OutPoint::new(Txid::zero(), 0),
                Script::new(),
                0xffffffff,
            )],
            vec![TxOut::new(Amount::from_sat(50_000), Script::new())],
            0,
        );

        let script_code = Script::from_bytes(vec![
            0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0xac,
        ]);

        let legacy_checker = TransactionSignatureChecker::new(&tx, 0, Amount::from_sat(100_000));
        let witness_checker =
            TransactionSignatureChecker::new_witness_v0(&tx, 0, Amount::from_sat(100_000));

        let legacy_hash =
            legacy_checker.compute_sighash_legacy(&script_code, sighash_type::SIGHASH_ALL);
        let witness_hash =
            witness_checker.compute_sighash_witness_v0(&script_code, sighash_type::SIGHASH_ALL);

        // They must be different — BIP143 includes the amount, legacy doesn't
        assert_ne!(legacy_hash, witness_hash);
    }

    // ═══════════════════════════════════════════════════════════════════
    // Regression tests — Session 14, Part 4 (code review fixes)
    //
    // These tests were written specifically for this implementation to
    // guard against bugs found during a code review. They are NOT ports
    // of Bitcoin Core test vectors. Each test name begins with
    // `regression_` so it can be distinguished from the implementation
    // unit tests above, which exercise baseline functionality.
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn regression_verify_ecdsa_rejects_compact_signatures() {
        // Regression: verify_ecdsa used to fall back to Signature::from_compact()
        // after DER parsing failed. BIP66 requires strict DER encoding.
        //
        // A compact signature is 64 bytes (r || s). DER encoding requires ~72 bytes.
        // We ensure that a valid compact signature is rejected.
        use secp256k1::{Message, Secp256k1, SecretKey};

        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0xcd; 32]).unwrap();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let msg_hash = [0xab; 32];
        let msg = Message::from_digest_slice(&msg_hash).unwrap();
        let sig = secp.sign_ecdsa(&msg, &sk);

        // DER-encoded signature should verify.
        let der_bytes = sig.serialize_der();
        assert!(
            verify_ecdsa(&msg_hash, &der_bytes, &pk.serialize()),
            "valid DER signature should verify"
        );

        // Compact-encoded (64 bytes) should NOT verify — this is the regression test.
        let compact_bytes = sig.serialize_compact();
        assert!(
            !verify_ecdsa(&msg_hash, &compact_bytes, &pk.serialize()),
            "compact signature must be rejected (strict DER per BIP66)"
        );
    }

    #[test]
    fn regression_taproot_sighash_fails_without_spent_outputs() {
        // Regression: compute_taproot_sighash used to substitute zero amounts
        // when spent_outputs was None, producing a plausible-looking (but wrong)
        // sighash that could match a crafted signature.
        // Now it returns [0xff; 32] — guaranteed to never match.
        use crate::primitives::{OutPoint, TxIn, TxOut, Txid};

        let tx = Transaction::new(
            2,
            vec![TxIn::new(
                OutPoint::new(Txid::zero(), 0),
                Script::new(),
                0xfffffffe,
            )],
            vec![TxOut::new(Amount::from_sat(50_000), Script::new())],
            0,
        );

        // Create checker WITHOUT spent_outputs (the old bug).
        let checker = TransactionSignatureChecker::new(&tx, 0, Amount::from_sat(100_000));
        // spent_outputs is None, so taproot sighash should return sentinel.
        let sighash = checker.compute_taproot_sighash(0x00);
        assert_eq!(
            sighash, [0xff; 32],
            "taproot sighash without spent_outputs must return sentinel"
        );
    }

    #[test]
    fn regression_taproot_sighash_script_path_fails_without_spent_outputs() {
        use crate::primitives::{OutPoint, TxIn, TxOut, Txid};

        let tx = Transaction::new(
            2,
            vec![TxIn::new(
                OutPoint::new(Txid::zero(), 0),
                Script::new(),
                0xfffffffe,
            )],
            vec![TxOut::new(Amount::from_sat(50_000), Script::new())],
            0,
        );

        let checker = TransactionSignatureChecker::new(&tx, 0, Amount::from_sat(100_000));
        let leaf_hash = [0xab; 32];
        let sighash = checker.compute_taproot_sighash_script_path(&leaf_hash, 0x00);
        assert_eq!(
            sighash, [0xff; 32],
            "taproot script-path sighash without spent_outputs must return sentinel"
        );
    }

    #[test]
    fn regression_taproot_sighash_works_with_spent_outputs() {
        // With valid spent outputs, the sighash should NOT be the sentinel.
        use crate::primitives::{OutPoint, TxIn, TxOut, Txid};

        let tx = Transaction::new(
            2,
            vec![TxIn::new(
                OutPoint::new(Txid::zero(), 0),
                Script::new(),
                0xfffffffe,
            )],
            vec![TxOut::new(Amount::from_sat(50_000), Script::new())],
            0,
        );

        let spent_outputs = vec![SpentOutput {
            amount: Amount::from_sat(100_000),
            script_pubkey: Script::new(),
        }];
        let checker = TransactionSignatureChecker::new_taproot(&tx, 0, spent_outputs);
        let sighash = checker.compute_taproot_sighash(0x00);
        assert_ne!(
            sighash, [0xff; 32],
            "taproot sighash with spent_outputs should produce a real hash"
        );
        assert_ne!(
            sighash, [0x00; 32],
            "taproot sighash should not be all zeros"
        );
    }

    #[test]
    fn regression_taproot_sighash_hash_type_affects_result() {
        // Different hash_type values should produce different sighashes.
        use crate::primitives::{OutPoint, TxIn, TxOut, Txid};

        let tx = Transaction::new(
            2,
            vec![TxIn::new(
                OutPoint::new(Txid::zero(), 0),
                Script::new(),
                0xfffffffe,
            )],
            vec![TxOut::new(Amount::from_sat(50_000), Script::new())],
            0,
        );

        let spent_outputs = vec![SpentOutput {
            amount: Amount::from_sat(100_000),
            script_pubkey: Script::new(),
        }];
        let checker = TransactionSignatureChecker::new_taproot(&tx, 0, spent_outputs);

        let sighash_default = checker.compute_taproot_sighash(0x00);
        let sighash_all = checker.compute_taproot_sighash(0x01);
        assert_ne!(
            sighash_default, sighash_all,
            "SIGHASH_DEFAULT and SIGHASH_ALL should produce different hashes"
        );
    }
}

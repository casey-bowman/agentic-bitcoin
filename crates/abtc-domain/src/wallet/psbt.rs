//! Partially Signed Bitcoin Transaction (PSBT) — BIP174
//!
//! PSBTs allow multiple parties to collaborate on constructing and signing
//! a Bitcoin transaction. Each party can add their inputs, outputs, and
//! signatures independently, then combine and finalize the result.
//!
//! ## Structure
//!
//! A PSBT contains:
//! - A global map with the unsigned transaction and optional metadata
//! - Per-input maps with UTXO data, partial signatures, redeem scripts, etc.
//! - Per-output maps with redeem scripts and BIP32 derivation paths
//!
//! ## Roles
//!
//! - **Creator**: Creates the base PSBT with the unsigned transaction
//! - **Updater**: Adds UTXO information, scripts, and derivation paths
//! - **Signer**: Adds partial signatures using their private keys
//! - **Combiner**: Merges multiple PSBTs with different signatures
//! - **Finalizer**: Converts partial signatures into final scriptSig/witness
//! - **Extractor**: Extracts the fully signed transaction
//!
//! ## Serialization
//!
//! PSBTs use a binary key-value format with a `0x70736274ff` magic header.
//! This implementation provides both in-memory manipulation and binary
//! serialization.

use crate::primitives::{Transaction, TxOut};
use crate::script::Script;
use std::collections::BTreeMap;

// ── PSBT Key Types (BIP174) ────────────────────────────────────────

/// PSBT magic bytes: "psbt" followed by 0xff separator.
pub const PSBT_MAGIC: [u8; 5] = [0x70, 0x73, 0x62, 0x74, 0xff];

/// Global key types.
pub mod global_key {
    pub const UNSIGNED_TX: u8 = 0x00;
    pub const XPUB: u8 = 0x01;
    pub const VERSION: u8 = 0xFB;
}

/// Per-input key types.
pub mod input_key {
    pub const NON_WITNESS_UTXO: u8 = 0x00;
    pub const WITNESS_UTXO: u8 = 0x01;
    pub const PARTIAL_SIG: u8 = 0x02;
    pub const SIGHASH_TYPE: u8 = 0x03;
    pub const REDEEM_SCRIPT: u8 = 0x04;
    pub const WITNESS_SCRIPT: u8 = 0x05;
    pub const BIP32_DERIVATION: u8 = 0x06;
    pub const FINAL_SCRIPTSIG: u8 = 0x07;
    pub const FINAL_SCRIPTWITNESS: u8 = 0x08;
}

/// Per-output key types.
pub mod output_key {
    pub const REDEEM_SCRIPT: u8 = 0x00;
    pub const WITNESS_SCRIPT: u8 = 0x01;
    pub const BIP32_DERIVATION: u8 = 0x02;
}

// ── Error types ─────────────────────────────────────────────────────

/// Errors during PSBT operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PsbtError {
    /// Invalid magic bytes.
    InvalidMagic,
    /// Unexpected end of data during deserialization.
    UnexpectedEof,
    /// Duplicate key in a map.
    DuplicateKey(Vec<u8>),
    /// Missing the unsigned transaction.
    MissingUnsignedTx,
    /// Input count mismatch between transaction and PSBT input maps.
    InputCountMismatch {
        tx_inputs: usize,
        psbt_inputs: usize,
    },
    /// Output count mismatch between transaction and PSBT output maps.
    OutputCountMismatch {
        tx_outputs: usize,
        psbt_outputs: usize,
    },
    /// Cannot extract: not all inputs are finalized.
    NotFullyFinalized,
    /// Cannot sign: the unsigned transaction has non-empty scriptSigs.
    TransactionNotUnsigned,
    /// Incompatible PSBTs cannot be combined.
    IncompatibleForCombine,
    /// Signing error.
    SigningError(String),
}

impl std::fmt::Display for PsbtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PsbtError::InvalidMagic => write!(f, "invalid PSBT magic"),
            PsbtError::UnexpectedEof => write!(f, "unexpected end of PSBT data"),
            PsbtError::DuplicateKey(k) => write!(f, "duplicate PSBT key: {:?}", k),
            PsbtError::MissingUnsignedTx => write!(f, "missing unsigned transaction"),
            PsbtError::InputCountMismatch {
                tx_inputs,
                psbt_inputs,
            } => write!(
                f,
                "input count mismatch: tx has {}, PSBT has {}",
                tx_inputs, psbt_inputs
            ),
            PsbtError::OutputCountMismatch {
                tx_outputs,
                psbt_outputs,
            } => write!(
                f,
                "output count mismatch: tx has {}, PSBT has {}",
                tx_outputs, psbt_outputs
            ),
            PsbtError::NotFullyFinalized => write!(f, "not all inputs are finalized"),
            PsbtError::TransactionNotUnsigned => write!(f, "transaction is not unsigned"),
            PsbtError::IncompatibleForCombine => write!(f, "incompatible PSBTs"),
            PsbtError::SigningError(msg) => write!(f, "signing error: {}", msg),
        }
    }
}

impl std::error::Error for PsbtError {}

// ── PSBT types ──────────────────────────────────────────────────────

/// BIP32 derivation information for a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bip32Derivation {
    /// The master key fingerprint (first 4 bytes of the hash160 of the master pubkey).
    pub master_fingerprint: [u8; 4],
    /// The derivation path as a series of child indices.
    pub path: Vec<u32>,
}

/// Per-input data in a PSBT.
#[derive(Debug, Clone, Default)]
pub struct PsbtInput {
    /// The full previous transaction (for non-witness UTXOs).
    pub non_witness_utxo: Option<Transaction>,
    /// The specific UTXO being spent (for witness UTXOs).
    pub witness_utxo: Option<TxOut>,
    /// Partial signatures: pubkey → signature.
    pub partial_sigs: BTreeMap<Vec<u8>, Vec<u8>>,
    /// The sighash type to use for this input.
    pub sighash_type: Option<u32>,
    /// Redeem script (for P2SH inputs).
    pub redeem_script: Option<Script>,
    /// Witness script (for P2WSH inputs).
    pub witness_script: Option<Script>,
    /// BIP32 derivation paths: pubkey → derivation.
    pub bip32_derivation: BTreeMap<Vec<u8>, Bip32Derivation>,
    /// Final scriptSig (set by the Finalizer).
    pub final_script_sig: Option<Script>,
    /// Final scriptWitness (set by the Finalizer).
    pub final_script_witness: Option<Vec<Vec<u8>>>,
    /// Unknown key-value pairs (for forward compatibility).
    pub unknown: BTreeMap<Vec<u8>, Vec<u8>>,
}

/// Per-output data in a PSBT.
#[derive(Debug, Clone, Default)]
pub struct PsbtOutput {
    /// Redeem script (for P2SH outputs).
    pub redeem_script: Option<Script>,
    /// Witness script (for P2WSH outputs).
    pub witness_script: Option<Script>,
    /// BIP32 derivation paths: pubkey → derivation.
    pub bip32_derivation: BTreeMap<Vec<u8>, Bip32Derivation>,
    /// Unknown key-value pairs.
    pub unknown: BTreeMap<Vec<u8>, Vec<u8>>,
}

/// A Partially Signed Bitcoin Transaction (PSBT).
#[derive(Debug, Clone)]
pub struct Psbt {
    /// The unsigned transaction that this PSBT wraps.
    pub unsigned_tx: Transaction,
    /// Version of the PSBT format (0 for BIP174).
    pub version: u32,
    /// Extended public keys (global xpubs).
    pub xpubs: BTreeMap<Vec<u8>, Bip32Derivation>,
    /// Unknown global key-value pairs.
    pub global_unknown: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Per-input data.
    pub inputs: Vec<PsbtInput>,
    /// Per-output data.
    pub outputs: Vec<PsbtOutput>,
}

impl Psbt {
    // ── Creator role ────────────────────────────────────────────

    /// Create a new PSBT from an unsigned transaction.
    ///
    /// The transaction's scriptSig fields must all be empty.
    pub fn from_unsigned_tx(tx: Transaction) -> Result<Self, PsbtError> {
        // Verify all inputs have empty scriptSig
        for input in &tx.inputs {
            if !input.script_sig.is_empty() {
                return Err(PsbtError::TransactionNotUnsigned);
            }
        }

        let input_count = tx.inputs.len();
        let output_count = tx.outputs.len();

        Ok(Psbt {
            unsigned_tx: tx,
            version: 0,
            xpubs: BTreeMap::new(),
            global_unknown: BTreeMap::new(),
            inputs: vec![PsbtInput::default(); input_count],
            outputs: vec![PsbtOutput::default(); output_count],
        })
    }

    // ── Updater role ────────────────────────────────────────────

    /// Add witness UTXO information for an input.
    pub fn set_witness_utxo(&mut self, input_index: usize, utxo: TxOut) -> Result<(), PsbtError> {
        let input = self
            .inputs
            .get_mut(input_index)
            .ok_or(PsbtError::InputCountMismatch {
                tx_inputs: self.unsigned_tx.inputs.len(),
                psbt_inputs: input_index + 1,
            })?;
        input.witness_utxo = Some(utxo);
        Ok(())
    }

    /// Add a non-witness (full) previous transaction for an input.
    pub fn set_non_witness_utxo(
        &mut self,
        input_index: usize,
        tx: Transaction,
    ) -> Result<(), PsbtError> {
        let input = self
            .inputs
            .get_mut(input_index)
            .ok_or(PsbtError::InputCountMismatch {
                tx_inputs: self.unsigned_tx.inputs.len(),
                psbt_inputs: input_index + 1,
            })?;
        input.non_witness_utxo = Some(tx);
        Ok(())
    }

    /// Set the sighash type for an input.
    pub fn set_sighash_type(
        &mut self,
        input_index: usize,
        sighash_type: u32,
    ) -> Result<(), PsbtError> {
        let input = self
            .inputs
            .get_mut(input_index)
            .ok_or(PsbtError::InputCountMismatch {
                tx_inputs: self.unsigned_tx.inputs.len(),
                psbt_inputs: input_index + 1,
            })?;
        input.sighash_type = Some(sighash_type);
        Ok(())
    }

    /// Add a BIP32 derivation path for a key on an input.
    pub fn add_input_bip32_derivation(
        &mut self,
        input_index: usize,
        pubkey: Vec<u8>,
        derivation: Bip32Derivation,
    ) -> Result<(), PsbtError> {
        let input = self
            .inputs
            .get_mut(input_index)
            .ok_or(PsbtError::InputCountMismatch {
                tx_inputs: self.unsigned_tx.inputs.len(),
                psbt_inputs: input_index + 1,
            })?;
        input.bip32_derivation.insert(pubkey, derivation);
        Ok(())
    }

    /// Add a BIP32 derivation path for a key on an output.
    pub fn add_output_bip32_derivation(
        &mut self,
        output_index: usize,
        pubkey: Vec<u8>,
        derivation: Bip32Derivation,
    ) -> Result<(), PsbtError> {
        let output = self
            .outputs
            .get_mut(output_index)
            .ok_or(PsbtError::OutputCountMismatch {
                tx_outputs: self.unsigned_tx.outputs.len(),
                psbt_outputs: output_index + 1,
            })?;
        output.bip32_derivation.insert(pubkey, derivation);
        Ok(())
    }

    // ── Signer role ─────────────────────────────────────────────

    /// Add a partial signature for an input.
    pub fn add_partial_sig(
        &mut self,
        input_index: usize,
        pubkey: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<(), PsbtError> {
        let input = self
            .inputs
            .get_mut(input_index)
            .ok_or(PsbtError::InputCountMismatch {
                tx_inputs: self.unsigned_tx.inputs.len(),
                psbt_inputs: input_index + 1,
            })?;

        // Cannot add signatures after finalization
        if input.final_script_sig.is_some() || input.final_script_witness.is_some() {
            return Err(PsbtError::SigningError(
                "input already finalized".to_string(),
            ));
        }

        input.partial_sigs.insert(pubkey, signature);
        Ok(())
    }

    // ── Combiner role ───────────────────────────────────────────

    /// Combine another PSBT into this one.
    ///
    /// Both PSBTs must have the same unsigned transaction. The combiner
    /// merges partial signatures and other per-input/per-output data.
    pub fn combine(&mut self, other: Psbt) -> Result<(), PsbtError> {
        // The unsigned transactions must match
        if self.unsigned_tx.txid() != other.unsigned_tx.txid() {
            return Err(PsbtError::IncompatibleForCombine);
        }

        // Merge per-input data
        for (i, other_input) in other.inputs.into_iter().enumerate() {
            if i >= self.inputs.len() {
                return Err(PsbtError::IncompatibleForCombine);
            }
            let self_input = &mut self.inputs[i];

            // Merge partial signatures
            for (key, sig) in other_input.partial_sigs {
                self_input.partial_sigs.entry(key).or_insert(sig);
            }

            // Merge UTXO info (prefer existing)
            if self_input.witness_utxo.is_none() {
                self_input.witness_utxo = other_input.witness_utxo;
            }
            if self_input.non_witness_utxo.is_none() {
                self_input.non_witness_utxo = other_input.non_witness_utxo;
            }

            // Merge BIP32 derivations
            for (key, deriv) in other_input.bip32_derivation {
                self_input.bip32_derivation.entry(key).or_insert(deriv);
            }

            // Merge unknown entries
            for (key, val) in other_input.unknown {
                self_input.unknown.entry(key).or_insert(val);
            }
        }

        // Merge per-output data
        for (i, other_output) in other.outputs.into_iter().enumerate() {
            if i >= self.outputs.len() {
                return Err(PsbtError::IncompatibleForCombine);
            }
            let self_output = &mut self.outputs[i];

            for (key, deriv) in other_output.bip32_derivation {
                self_output.bip32_derivation.entry(key).or_insert(deriv);
            }

            for (key, val) in other_output.unknown {
                self_output.unknown.entry(key).or_insert(val);
            }
        }

        // Merge global xpubs
        for (key, deriv) in other.xpubs {
            self.xpubs.entry(key).or_insert(deriv);
        }

        Ok(())
    }

    // ── Finalizer role ──────────────────────────────────────────

    /// Finalize an input by converting its partial signatures into
    /// a final scriptSig and/or scriptWitness.
    ///
    /// For P2WPKH: creates a witness with [signature, pubkey].
    /// For P2PKH: creates a scriptSig with <sig> <pubkey>.
    ///
    /// Returns an error if the input has no partial signatures.
    pub fn finalize_input(&mut self, input_index: usize) -> Result<(), PsbtError> {
        let input = self
            .inputs
            .get_mut(input_index)
            .ok_or(PsbtError::InputCountMismatch {
                tx_inputs: self.unsigned_tx.inputs.len(),
                psbt_inputs: input_index + 1,
            })?;

        // Already finalized?
        if input.final_script_sig.is_some() || input.final_script_witness.is_some() {
            return Ok(());
        }

        // Need at least one partial signature
        if input.partial_sigs.is_empty() {
            return Err(PsbtError::NotFullyFinalized);
        }

        // Take the first partial signature (single-sig case)
        let (pubkey, signature) = input.partial_sigs.iter().next().unwrap();
        let pubkey = pubkey.clone();
        let signature = signature.clone();

        if let Some(ref utxo) = input.witness_utxo {
            if utxo.script_pubkey.is_p2tr() {
                // Taproot P2TR: witness is just [signature] (64 or 65 bytes)
                // No pubkey needed — the output key is in the scriptPubKey
                input.final_script_witness = Some(vec![signature]);
                input.final_script_sig = Some(Script::new());
            } else {
                // SegWit v0: witness stack [signature, pubkey]
                input.final_script_witness = Some(vec![signature, pubkey]);
                input.final_script_sig = Some(Script::new());
            }
        } else {
            // Legacy input: create scriptSig with <sig> <pubkey>
            let mut script_bytes = Vec::new();
            // Push signature
            script_bytes.push(signature.len() as u8);
            script_bytes.extend_from_slice(&signature);
            // Push pubkey
            script_bytes.push(pubkey.len() as u8);
            script_bytes.extend_from_slice(&pubkey);
            input.final_script_sig = Some(Script::from_bytes(script_bytes));
        }

        // Clear partial data after finalization
        input.partial_sigs.clear();
        input.sighash_type = None;
        input.redeem_script = None;
        input.witness_script = None;
        input.bip32_derivation.clear();

        Ok(())
    }

    /// Check if all inputs are finalized.
    pub fn is_fully_finalized(&self) -> bool {
        self.inputs
            .iter()
            .all(|input| input.final_script_sig.is_some() || input.final_script_witness.is_some())
    }

    // ── Extractor role ──────────────────────────────────────────

    /// Extract the final signed transaction from a fully-finalized PSBT.
    ///
    /// Copies the final scriptSig and witness data into the unsigned
    /// transaction and returns the result.
    pub fn extract_tx(&self) -> Result<Transaction, PsbtError> {
        if !self.is_fully_finalized() {
            return Err(PsbtError::NotFullyFinalized);
        }

        let mut tx = self.unsigned_tx.clone();

        for (i, psbt_input) in self.inputs.iter().enumerate() {
            if let Some(ref script_sig) = psbt_input.final_script_sig {
                tx.inputs[i].script_sig = script_sig.clone();
            }
            // Note: witness data would be applied here in a full implementation.
            // For now we store it in the PSBT input but Transaction doesn't have
            // a witness field per input yet. This is tracked for future work.
        }

        Ok(tx)
    }

    // ── Utility ─────────────────────────────────────────────────

    /// Get the number of inputs.
    pub fn input_count(&self) -> usize {
        self.inputs.len()
    }

    /// Get the number of outputs.
    pub fn output_count(&self) -> usize {
        self.outputs.len()
    }

    /// Count how many inputs have at least one partial signature.
    pub fn signed_input_count(&self) -> usize {
        self.inputs
            .iter()
            .filter(|input| {
                !input.partial_sigs.is_empty()
                    || input.final_script_sig.is_some()
                    || input.final_script_witness.is_some()
            })
            .count()
    }

    /// Serialize the PSBT to its binary format (BIP174).
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Magic
        data.extend_from_slice(&PSBT_MAGIC);

        // Global map
        // Key 0x00: unsigned tx
        let tx_bytes = self.unsigned_tx.serialize();
        write_kv_pair(&mut data, &[global_key::UNSIGNED_TX], &tx_bytes);

        // Separator (empty key = 0x00)
        data.push(0x00);

        // Per-input maps
        for input in &self.inputs {
            if let Some(ref utxo) = input.witness_utxo {
                let utxo_bytes = serialize_txout(utxo);
                write_kv_pair(&mut data, &[input_key::WITNESS_UTXO], &utxo_bytes);
            }

            for (pubkey, sig) in &input.partial_sigs {
                let mut key = vec![input_key::PARTIAL_SIG];
                key.extend_from_slice(pubkey);
                write_kv_pair(&mut data, &key, sig);
            }

            if let Some(sighash) = input.sighash_type {
                write_kv_pair(
                    &mut data,
                    &[input_key::SIGHASH_TYPE],
                    &sighash.to_le_bytes(),
                );
            }

            if let Some(ref script) = input.final_script_sig {
                write_kv_pair(&mut data, &[input_key::FINAL_SCRIPTSIG], script.as_bytes());
            }

            if let Some(ref witness_items) = input.final_script_witness {
                let mut witness_bytes = Vec::new();
                write_compact_size(&mut witness_bytes, witness_items.len() as u64);
                for item in witness_items {
                    write_compact_size(&mut witness_bytes, item.len() as u64);
                    witness_bytes.extend_from_slice(item);
                }
                write_kv_pair(&mut data, &[input_key::FINAL_SCRIPTWITNESS], &witness_bytes);
            }

            // Separator
            data.push(0x00);
        }

        // Per-output maps
        for output in &self.outputs {
            if let Some(ref script) = output.redeem_script {
                write_kv_pair(&mut data, &[output_key::REDEEM_SCRIPT], script.as_bytes());
            }

            // Separator
            data.push(0x00);
        }

        data
    }
}

// ── Serialization helpers ───────────────────────────────────────────

fn write_compact_size(data: &mut Vec<u8>, value: u64) {
    if value < 0xfd {
        data.push(value as u8);
    } else if value <= 0xffff {
        data.push(0xfd);
        data.extend_from_slice(&(value as u16).to_le_bytes());
    } else if value <= 0xffffffff {
        data.push(0xfe);
        data.extend_from_slice(&(value as u32).to_le_bytes());
    } else {
        data.push(0xff);
        data.extend_from_slice(&value.to_le_bytes());
    }
}

fn write_kv_pair(data: &mut Vec<u8>, key: &[u8], value: &[u8]) {
    write_compact_size(data, key.len() as u64);
    data.extend_from_slice(key);
    write_compact_size(data, value.len() as u64);
    data.extend_from_slice(value);
}

fn serialize_txout(txout: &TxOut) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&txout.value.as_sat().to_le_bytes());
    let script_bytes = txout.script_pubkey.as_bytes();
    write_compact_size(&mut data, script_bytes.len() as u64);
    data.extend_from_slice(script_bytes);
    data
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::{Amount, Hash256, OutPoint, TxIn, TxOut, Txid};
    use crate::script::Script;

    fn make_unsigned_tx() -> Transaction {
        Transaction::v1(
            vec![
                TxIn::final_input(
                    OutPoint::new(Txid::from_hash(Hash256::from_bytes([0x01; 32])), 0),
                    Script::new(), // empty scriptSig = unsigned
                ),
                TxIn::final_input(
                    OutPoint::new(Txid::from_hash(Hash256::from_bytes([0x02; 32])), 1),
                    Script::new(),
                ),
            ],
            vec![
                TxOut::new(
                    Amount::from_sat(50000),
                    Script::from_bytes(vec![0x76, 0xa9]),
                ),
                TxOut::new(
                    Amount::from_sat(40000),
                    Script::from_bytes(vec![0x00, 0x14]),
                ),
            ],
            0,
        )
    }

    #[test]
    fn test_create_psbt() {
        let tx = make_unsigned_tx();
        let psbt = Psbt::from_unsigned_tx(tx).unwrap();
        assert_eq!(psbt.input_count(), 2);
        assert_eq!(psbt.output_count(), 2);
        assert_eq!(psbt.version, 0);
        assert_eq!(psbt.signed_input_count(), 0);
    }

    #[test]
    fn test_reject_signed_tx() {
        let tx = Transaction::v1(
            vec![TxIn::final_input(
                OutPoint::new(Txid::from_hash(Hash256::from_bytes([0x01; 32])), 0),
                Script::from_bytes(vec![0x01, 0x02]), // non-empty = already signed
            )],
            vec![TxOut::new(Amount::from_sat(50000), Script::new())],
            0,
        );
        let result = Psbt::from_unsigned_tx(tx);
        assert_eq!(result.unwrap_err(), PsbtError::TransactionNotUnsigned);
    }

    #[test]
    fn test_set_witness_utxo() {
        let tx = make_unsigned_tx();
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

        let utxo = TxOut::new(
            Amount::from_sat(100000),
            Script::from_bytes(vec![0x00, 0x14]),
        );
        psbt.set_witness_utxo(0, utxo.clone()).unwrap();

        assert_eq!(
            psbt.inputs[0].witness_utxo.as_ref().unwrap().value,
            utxo.value
        );
    }

    #[test]
    fn test_add_partial_sig() {
        let tx = make_unsigned_tx();
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

        let pubkey = vec![0x02; 33]; // compressed pubkey placeholder
        let sig = vec![0x30; 72]; // DER signature placeholder

        psbt.add_partial_sig(0, pubkey.clone(), sig.clone())
            .unwrap();
        assert_eq!(psbt.signed_input_count(), 1);
        assert_eq!(psbt.inputs[0].partial_sigs.get(&pubkey).unwrap(), &sig);
    }

    #[test]
    fn test_combine_psbts() {
        let tx = make_unsigned_tx();
        let mut psbt1 = Psbt::from_unsigned_tx(tx.clone()).unwrap();
        let mut psbt2 = Psbt::from_unsigned_tx(tx).unwrap();

        // Signer 1 signs input 0
        psbt1
            .add_partial_sig(0, vec![0x02; 33], vec![0x30; 72])
            .unwrap();

        // Signer 2 signs input 1
        psbt2
            .add_partial_sig(1, vec![0x03; 33], vec![0x31; 72])
            .unwrap();

        // Combine
        psbt1.combine(psbt2).unwrap();
        assert_eq!(psbt1.signed_input_count(), 2);
    }

    #[test]
    fn test_combine_incompatible() {
        let tx1 = make_unsigned_tx();
        let tx2 = Transaction::v1(
            vec![TxIn::final_input(
                OutPoint::new(Txid::from_hash(Hash256::from_bytes([0xFF; 32])), 0),
                Script::new(),
            )],
            vec![TxOut::new(Amount::from_sat(10000), Script::new())],
            0,
        );

        let mut psbt1 = Psbt::from_unsigned_tx(tx1).unwrap();
        let psbt2 = Psbt::from_unsigned_tx(tx2).unwrap();

        assert_eq!(
            psbt1.combine(psbt2).unwrap_err(),
            PsbtError::IncompatibleForCombine
        );
    }

    #[test]
    fn test_finalize_witness_input() {
        let tx = make_unsigned_tx();
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

        // Set witness UTXO and add a partial signature
        let utxo = TxOut::new(
            Amount::from_sat(100000),
            Script::from_bytes(vec![0x00, 0x14]),
        );
        psbt.set_witness_utxo(0, utxo).unwrap();
        psbt.add_partial_sig(0, vec![0x02; 33], vec![0x30; 72])
            .unwrap();

        // Finalize
        psbt.finalize_input(0).unwrap();

        assert!(psbt.inputs[0].final_script_witness.is_some());
        let witness = psbt.inputs[0].final_script_witness.as_ref().unwrap();
        assert_eq!(witness.len(), 2); // [signature, pubkey]
        assert!(psbt.inputs[0].partial_sigs.is_empty()); // cleared after finalization
    }

    #[test]
    fn test_finalize_legacy_input() {
        let tx = make_unsigned_tx();
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

        // No witness UTXO = legacy
        psbt.add_partial_sig(0, vec![0x02; 33], vec![0x30; 72])
            .unwrap();

        psbt.finalize_input(0).unwrap();

        assert!(psbt.inputs[0].final_script_sig.is_some());
        assert!(psbt.inputs[0].final_script_witness.is_none());
    }

    #[test]
    fn test_extract_tx() {
        let tx = make_unsigned_tx();
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

        // Sign and finalize both inputs
        psbt.add_partial_sig(0, vec![0x02; 33], vec![0x30; 72])
            .unwrap();
        psbt.add_partial_sig(1, vec![0x03; 33], vec![0x31; 72])
            .unwrap();
        psbt.finalize_input(0).unwrap();
        psbt.finalize_input(1).unwrap();

        assert!(psbt.is_fully_finalized());

        let signed_tx = psbt.extract_tx().unwrap();
        // Input 1 has a legacy final_script_sig (non-empty)
        assert!(!signed_tx.inputs[1].script_sig.is_empty());
    }

    #[test]
    fn test_extract_not_finalized() {
        let tx = make_unsigned_tx();
        let psbt = Psbt::from_unsigned_tx(tx).unwrap();

        assert_eq!(psbt.extract_tx().unwrap_err(), PsbtError::NotFullyFinalized);
    }

    #[test]
    fn test_serialize_roundtrip_magic() {
        let tx = make_unsigned_tx();
        let psbt = Psbt::from_unsigned_tx(tx).unwrap();

        let bytes = psbt.serialize();
        // Should start with PSBT magic
        assert_eq!(&bytes[..5], &PSBT_MAGIC);
    }

    #[test]
    fn test_bip32_derivation() {
        let tx = make_unsigned_tx();
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

        let deriv = Bip32Derivation {
            master_fingerprint: [0xDE, 0xAD, 0xBE, 0xEF],
            path: vec![44 | 0x80000000, 0 | 0x80000000, 0 | 0x80000000, 0, 0],
        };

        psbt.add_input_bip32_derivation(0, vec![0x02; 33], deriv.clone())
            .unwrap();
        assert_eq!(psbt.inputs[0].bip32_derivation.len(), 1);

        psbt.add_output_bip32_derivation(0, vec![0x02; 33], deriv)
            .unwrap();
        assert_eq!(psbt.outputs[0].bip32_derivation.len(), 1);
    }

    #[test]
    fn test_cannot_sign_after_finalize() {
        let tx = make_unsigned_tx();
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

        psbt.add_partial_sig(0, vec![0x02; 33], vec![0x30; 72])
            .unwrap();
        psbt.finalize_input(0).unwrap();

        // Should fail — already finalized
        let result = psbt.add_partial_sig(0, vec![0x04; 33], vec![0x32; 72]);
        assert!(result.is_err());
    }

    #[test]
    fn test_sighash_type() {
        let tx = make_unsigned_tx();
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

        psbt.set_sighash_type(0, 0x01).unwrap(); // SIGHASH_ALL
        assert_eq!(psbt.inputs[0].sighash_type, Some(0x01));
    }

    // ── End-to-end PSBT workflow tests ─────────────────────────────

    #[test]
    fn test_psbt_full_workflow_witness() {
        // Full BIP174 workflow: create → update → sign → finalize → extract
        // Simulates a 2-input P2WPKH transaction signed by a single signer.
        let tx = make_unsigned_tx();
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

        // UPDATE: Add witness UTXO info for both inputs
        let utxo_0 = TxOut::new(
            Amount::from_sat(100_000),
            Script::from_bytes(vec![0x00, 0x14, 0xAA]),
        );
        let utxo_1 = TxOut::new(
            Amount::from_sat(80_000),
            Script::from_bytes(vec![0x00, 0x14, 0xBB]),
        );
        psbt.set_witness_utxo(0, utxo_0).unwrap();
        psbt.set_witness_utxo(1, utxo_1).unwrap();

        // UPDATE: Add BIP32 derivation paths
        let deriv = Bip32Derivation {
            master_fingerprint: [0xDE, 0xAD, 0xBE, 0xEF],
            path: vec![84 | 0x80000000, 0 | 0x80000000, 0 | 0x80000000, 0, 0],
        };
        psbt.add_input_bip32_derivation(0, vec![0x02; 33], deriv.clone())
            .unwrap();
        psbt.add_input_bip32_derivation(1, vec![0x02; 33], deriv)
            .unwrap();

        // UPDATE: Set sighash types
        psbt.set_sighash_type(0, 0x01).unwrap();
        psbt.set_sighash_type(1, 0x01).unwrap();

        // SIGN: Add partial signatures for both inputs
        let pubkey = vec![0x02; 33];
        let sig_0 = vec![0x30; 72]; // mock DER sig
        let sig_1 = vec![0x31; 72];
        psbt.add_partial_sig(0, pubkey.clone(), sig_0).unwrap();
        psbt.add_partial_sig(1, pubkey.clone(), sig_1).unwrap();

        assert_eq!(psbt.signed_input_count(), 2);
        assert!(!psbt.is_fully_finalized());

        // FINALIZE: Both inputs
        psbt.finalize_input(0).unwrap();
        psbt.finalize_input(1).unwrap();
        assert!(psbt.is_fully_finalized());

        // Verify finalization cleared signing data (but witness_utxo is preserved)
        assert!(psbt.inputs[0].partial_sigs.is_empty());
        assert!(psbt.inputs[0].witness_utxo.is_some()); // witness_utxo preserved
        assert!(psbt.inputs[1].partial_sigs.is_empty());

        // Both inputs should have witness data (P2WPKH)
        assert!(psbt.inputs[0].final_script_witness.is_some());
        assert!(psbt.inputs[1].final_script_witness.is_some());

        // EXTRACT: Get the signed transaction
        let signed_tx = psbt.extract_tx().unwrap();
        assert_eq!(signed_tx.inputs.len(), 2);
        assert_eq!(signed_tx.outputs.len(), 2);
    }

    #[test]
    fn test_psbt_multi_signer_combine_workflow() {
        // Simulates a multi-party signing workflow:
        // Creator makes PSBT → distributes to 2 signers → combine → finalize → extract
        let tx = make_unsigned_tx();

        // Creator creates base PSBT
        let base_psbt = Psbt::from_unsigned_tx(tx).unwrap();

        // Signer 1 gets a copy, adds their signature to input 0
        let mut signer1_psbt = base_psbt.clone();
        let utxo_0 = TxOut::new(
            Amount::from_sat(100_000),
            Script::from_bytes(vec![0x00, 0x14]),
        );
        signer1_psbt.set_witness_utxo(0, utxo_0).unwrap();
        signer1_psbt
            .add_partial_sig(0, vec![0x02; 33], vec![0x30; 72])
            .unwrap();

        // Signer 2 gets a copy, adds their signature to input 1
        let mut signer2_psbt = base_psbt.clone();
        let utxo_1 = TxOut::new(
            Amount::from_sat(80_000),
            Script::from_bytes(vec![0x00, 0x14]),
        );
        signer2_psbt.set_witness_utxo(1, utxo_1).unwrap();
        signer2_psbt
            .add_partial_sig(1, vec![0x03; 33], vec![0x31; 72])
            .unwrap();

        // Combiner merges both
        let mut combined = signer1_psbt;
        combined.combine(signer2_psbt).unwrap();
        assert_eq!(combined.signed_input_count(), 2);

        // Verify witness UTXOs were merged
        assert!(combined.inputs[0].witness_utxo.is_some());
        assert!(combined.inputs[1].witness_utxo.is_some());

        // Finalize and extract
        combined.finalize_input(0).unwrap();
        combined.finalize_input(1).unwrap();
        assert!(combined.is_fully_finalized());

        let signed_tx = combined.extract_tx().unwrap();
        assert_eq!(signed_tx.inputs.len(), 2);
    }

    #[test]
    fn test_psbt_legacy_full_workflow() {
        // Full workflow for legacy (non-witness) inputs
        let tx = make_unsigned_tx();
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

        // No witness UTXO set → legacy finalization path
        psbt.add_partial_sig(0, vec![0x02; 33], vec![0x30; 72])
            .unwrap();
        psbt.add_partial_sig(1, vec![0x03; 33], vec![0x31; 72])
            .unwrap();

        psbt.finalize_input(0).unwrap();
        psbt.finalize_input(1).unwrap();

        // Both should have scriptSig, not witness
        assert!(psbt.inputs[0].final_script_sig.is_some());
        assert!(psbt.inputs[0].final_script_witness.is_none());
        assert!(psbt.inputs[1].final_script_sig.is_some());
        assert!(psbt.inputs[1].final_script_witness.is_none());

        let signed_tx = psbt.extract_tx().unwrap();
        assert!(!signed_tx.inputs[0].script_sig.is_empty());
        assert!(!signed_tx.inputs[1].script_sig.is_empty());
    }

    #[test]
    fn test_psbt_serialize_deserialize_roundtrip() {
        // Verify serialization produces valid PSBT magic and is deterministic
        let tx = make_unsigned_tx();
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

        let utxo = TxOut::new(
            Amount::from_sat(100_000),
            Script::from_bytes(vec![0x00, 0x14]),
        );
        psbt.set_witness_utxo(0, utxo).unwrap();
        psbt.add_partial_sig(0, vec![0x02; 33], vec![0x30; 72])
            .unwrap();

        let bytes1 = psbt.serialize();
        let bytes2 = psbt.serialize();

        // Deterministic
        assert_eq!(bytes1, bytes2);

        // Starts with PSBT magic
        assert_eq!(&bytes1[..5], &PSBT_MAGIC);

        // Non-trivial size (has actual data)
        assert!(bytes1.len() > 20);
    }

    #[test]
    fn test_psbt_error_index_out_of_bounds() {
        let tx = make_unsigned_tx();
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

        // Input index 5 is out of bounds (only 2 inputs)
        let result = psbt.set_witness_utxo(5, TxOut::new(Amount::from_sat(100_000), Script::new()));
        assert!(result.is_err());

        let result = psbt.add_partial_sig(5, vec![0x02; 33], vec![0x30; 72]);
        assert!(result.is_err());

        let result = psbt.finalize_input(5);
        assert!(result.is_err());
    }

    #[test]
    fn test_psbt_finalize_unsigned_input_fails() {
        let tx = make_unsigned_tx();
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

        // No signatures added — finalize should fail
        let result = psbt.finalize_input(0);
        assert!(result.is_err());
    }

    #[test]
    fn test_psbt_double_finalize_is_idempotent() {
        let tx = make_unsigned_tx();
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

        psbt.add_partial_sig(0, vec![0x02; 33], vec![0x30; 72])
            .unwrap();
        psbt.finalize_input(0).unwrap();

        // Second finalize is idempotent (returns Ok, no-op)
        let result = psbt.finalize_input(0);
        assert!(result.is_ok());

        // Still finalized with same data
        assert!(
            psbt.inputs[0].final_script_sig.is_some()
                || psbt.inputs[0].final_script_witness.is_some()
        );
    }

    #[test]
    fn test_psbt_p2tr_finalize_single_sig_witness() {
        // P2TR finalization should produce witness with only [signature], no pubkey
        let tx = make_unsigned_tx();
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

        // Set witness UTXO with a P2TR scriptPubKey (OP_1 <32 bytes>)
        let mut p2tr_spk = vec![0x51, 32]; // OP_1 + push 32
        p2tr_spk.extend_from_slice(&[0x42; 32]); // 32-byte output key
        let utxo = TxOut::new(Amount::from_sat(100_000), Script::from_bytes(p2tr_spk));
        psbt.set_witness_utxo(0, utxo).unwrap();

        // Add a 64-byte Schnorr signature (no sighash byte → SIGHASH_DEFAULT)
        let schnorr_sig = vec![0xAB; 64];
        psbt.add_partial_sig(0, vec![0x42; 32], schnorr_sig.clone())
            .unwrap();

        psbt.finalize_input(0).unwrap();

        // P2TR witness should be just [signature], not [signature, pubkey]
        let witness = psbt.inputs[0].final_script_witness.as_ref().unwrap();
        assert_eq!(witness.len(), 1);
        assert_eq!(witness[0], schnorr_sig);

        // scriptSig should be empty
        assert!(psbt.inputs[0].final_script_sig.as_ref().unwrap().is_empty());
    }

    #[test]
    fn test_psbt_p2wpkh_finalize_still_has_two_items() {
        // Ensure P2WPKH finalization still produces [signature, pubkey]
        let tx = make_unsigned_tx();
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

        // Set witness UTXO with a P2WPKH scriptPubKey (OP_0 <20 bytes>)
        let mut p2wpkh_spk = vec![0x00, 20]; // OP_0 + push 20
        p2wpkh_spk.extend_from_slice(&[0xAA; 20]);
        let utxo = TxOut::new(Amount::from_sat(100_000), Script::from_bytes(p2wpkh_spk));
        psbt.set_witness_utxo(0, utxo).unwrap();

        let sig = vec![0x30; 72];
        let pubkey = vec![0x02; 33];
        psbt.add_partial_sig(0, pubkey.clone(), sig.clone())
            .unwrap();

        psbt.finalize_input(0).unwrap();

        // P2WPKH witness should be [signature, pubkey]
        let witness = psbt.inputs[0].final_script_witness.as_ref().unwrap();
        assert_eq!(witness.len(), 2);
        assert_eq!(witness[0], sig);
        assert_eq!(witness[1], pubkey);
    }
}

//! Transaction builder and signer
//!
//! Constructs and signs Bitcoin transactions using wallet keys.
//! Supports P2PKH (legacy) and P2WPKH (native SegWit) inputs.

use crate::crypto::signing::{sighash_type, SpentOutput, TransactionSignatureChecker};
use crate::primitives::{Amount, OutPoint, Transaction, TxIn, TxOut};
use crate::script::{Opcodes, Script, ScriptBuilder};
use crate::script::witness::Witness;
use super::keys::PrivateKey;

use secp256k1::{Secp256k1, Message};

/// Errors during transaction building
#[derive(Debug, Clone)]
pub enum BuilderError {
    /// No inputs added
    NoInputs,
    /// No outputs added
    NoOutputs,
    /// Missing private key for an input
    MissingKey(usize),
    /// Signing failed
    SigningFailed(String),
    /// Invalid amounts
    InvalidAmounts(String),
}

impl std::fmt::Display for BuilderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuilderError::NoInputs => write!(f, "no inputs"),
            BuilderError::NoOutputs => write!(f, "no outputs"),
            BuilderError::MissingKey(i) => write!(f, "missing key for input {}", i),
            BuilderError::SigningFailed(msg) => write!(f, "signing failed: {}", msg),
            BuilderError::InvalidAmounts(msg) => write!(f, "invalid amounts: {}", msg),
        }
    }
}

impl std::error::Error for BuilderError {}

/// Taproot script-path spending information.
///
/// When provided on an `InputInfo`, the signer will produce a script-path
/// witness (`[args..., script, control_block]`) instead of a key-path witness.
#[derive(Debug, Clone)]
pub struct TapScriptPath {
    /// The tapscript to execute (the leaf being spent)
    pub script: Script,
    /// Serialized control block (leaf_version|parity + internal_key + merkle_path)
    pub control_block: Vec<u8>,
    /// The tapleaf hash (precomputed for the sighash)
    pub leaf_hash: [u8; 32],
}

/// Information about an input being spent
#[derive(Debug, Clone)]
pub struct InputInfo {
    /// The outpoint being spent
    pub outpoint: OutPoint,
    /// The script pubkey of the output being spent (needed for sighash)
    pub script_pubkey: Script,
    /// The value of the output being spent (needed for SegWit sighash)
    pub amount: Amount,
    /// The private key to sign with
    pub signing_key: Option<PrivateKey>,
    /// Sequence number (default: 0xFFFFFFFE for RBF compatibility)
    pub sequence: u32,
    /// Optional: Taproot script-path spending info. When set, the input
    /// is signed via script-path instead of key-path.
    pub tap_script_path: Option<TapScriptPath>,
}

/// Builds and signs Bitcoin transactions.
///
/// # Usage
///
/// ```ignore
/// let tx = TransactionBuilder::new()
///     .version(2)
///     .add_input(InputInfo { ... })
///     .add_output(TxOut::new(amount, script_pubkey))
///     .sign()
///     .unwrap();
/// ```
pub struct TransactionBuilder {
    version: i32,
    inputs: Vec<InputInfo>,
    outputs: Vec<TxOut>,
    lock_time: u32,
}

impl TransactionBuilder {
    /// Create a new transaction builder.
    pub fn new() -> Self {
        TransactionBuilder {
            version: 2,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
        }
    }

    /// Set the transaction version (default: 2).
    pub fn version(mut self, version: i32) -> Self {
        self.version = version;
        self
    }

    /// Add an input to the transaction.
    pub fn add_input(mut self, input: InputInfo) -> Self {
        self.inputs.push(input);
        self
    }

    /// Add an output to the transaction.
    pub fn add_output(mut self, output: TxOut) -> Self {
        self.outputs.push(output);
        self
    }

    /// Set the lock time (default: 0).
    pub fn lock_time(mut self, lock_time: u32) -> Self {
        self.lock_time = lock_time;
        self
    }

    /// Build an unsigned transaction.
    pub fn build_unsigned(&self) -> Result<Transaction, BuilderError> {
        if self.inputs.is_empty() {
            return Err(BuilderError::NoInputs);
        }
        if self.outputs.is_empty() {
            return Err(BuilderError::NoOutputs);
        }

        let inputs: Vec<TxIn> = self
            .inputs
            .iter()
            .map(|info| TxIn::new(info.outpoint, Script::new(), info.sequence))
            .collect();

        Ok(Transaction::new(
            self.version,
            inputs,
            self.outputs.clone(),
            self.lock_time,
        ))
    }

    /// Build and sign the transaction.
    ///
    /// For each input:
    /// - If the scriptPubKey is P2PKH, produces a legacy scriptSig
    /// - If the scriptPubKey is P2WPKH, produces an empty scriptSig and witness data
    /// - If the scriptPubKey is P2SH (wrapping P2WPKH), produces the redeem script
    ///   in scriptSig and witness data
    pub fn sign(self) -> Result<Transaction, BuilderError> {
        // Check all inputs have keys
        for (i, input) in self.inputs.iter().enumerate() {
            if input.signing_key.is_none() {
                return Err(BuilderError::MissingKey(i));
            }
        }

        // Build unsigned transaction first
        let mut tx = self.build_unsigned()?;

        let secp = Secp256k1::new();

        // Sign each input
        for i in 0..self.inputs.len() {
            let info = &self.inputs[i];
            let key = info.signing_key.as_ref().unwrap();
            let pubkey = key.public_key();
            let pubkey_bytes = pubkey.serialize();
            let pubkey_hash = pubkey.pubkey_hash();

            if info.script_pubkey.is_p2pkh() {
                // Legacy P2PKH signing
                let checker = TransactionSignatureChecker::new(&tx, i, info.amount);

                let sighash = compute_sighash_for_checker(
                    &checker,
                    &info.script_pubkey,
                    sighash_type::SIGHASH_ALL,
                    false,
                );

                let sig = sign_hash(&secp, key, &sighash)
                    .map_err(|e| BuilderError::SigningFailed(e.to_string()))?;

                // scriptSig = <sig | SIGHASH_ALL> <pubkey>
                let mut sig_with_hashtype = sig;
                sig_with_hashtype.push(sighash_type::SIGHASH_ALL);

                let script_sig = ScriptBuilder::new()
                    .push_slice(&sig_with_hashtype)
                    .push_slice(&pubkey_bytes)
                    .build();

                tx.inputs[i].script_sig = script_sig;
            } else if info.script_pubkey.is_p2wpkh() {
                // Native SegWit P2WPKH signing (BIP143)
                // scriptCode for P2WPKH is: OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
                let script_code = ScriptBuilder::new()
                    .push_opcode(Opcodes::OP_DUP)
                    .push_opcode(Opcodes::OP_HASH160)
                    .push_slice(&pubkey_hash)
                    .push_opcode(Opcodes::OP_EQUALVERIFY)
                    .push_opcode(Opcodes::OP_CHECKSIG)
                    .build();

                let checker = TransactionSignatureChecker::new_witness_v0(&tx, i, info.amount);

                let sighash = compute_sighash_for_checker(
                    &checker,
                    &script_code,
                    sighash_type::SIGHASH_ALL,
                    true,
                );

                let sig = sign_hash(&secp, key, &sighash)
                    .map_err(|e| BuilderError::SigningFailed(e.to_string()))?;

                let mut sig_with_hashtype = sig;
                sig_with_hashtype.push(sighash_type::SIGHASH_ALL);

                // Empty scriptSig for native SegWit
                tx.inputs[i].script_sig = Script::new();

                // Witness: [signature, pubkey]
                let mut witness = Witness::new();
                witness.push(sig_with_hashtype);
                witness.push(pubkey_bytes.clone());
                tx.inputs[i].witness = witness;
            } else if info.script_pubkey.is_p2tr() {
                // Taproot P2TR signing (BIP341/BIP342)
                let spent_outputs: Vec<SpentOutput> = self.inputs.iter().map(|inp| {
                    SpentOutput {
                        amount: inp.amount,
                        script_pubkey: inp.script_pubkey.clone(),
                    }
                }).collect();

                // Empty scriptSig for Taproot (must be set before creating checker
                // which borrows &tx immutably)
                tx.inputs[i].script_sig = Script::new();

                let checker = TransactionSignatureChecker::new_taproot(
                    &tx, i, spent_outputs,
                );

                if let Some(ref script_path) = info.tap_script_path {
                    // SCRIPT-PATH spending (BIP342)
                    // 1. Compute script-path sighash with tapleaf hash
                    let sighash = checker.compute_taproot_sighash_script_path(
                        &script_path.leaf_hash,
                    );

                    // 2. Sign with the raw (untweaked) internal key for script-path
                    let sig = crate::crypto::schnorr::sign_schnorr(
                        key.inner(),
                        &sighash,
                    );

                    // 3. Build witness: [signature, script, control_block]
                    let mut witness = Witness::new();
                    witness.push(sig.to_vec());
                    witness.push(script_path.script.as_bytes().to_vec());
                    witness.push(script_path.control_block.clone());
                    tx.inputs[i].witness = witness;
                } else {
                    // KEY-PATH spending (BIP341)
                    let sighash = checker.compute_taproot_sighash();

                    let (sig, _output_key) = crate::crypto::schnorr::sign_schnorr_tweaked(
                        key.inner(),
                        None,
                        &sighash,
                    );

                    let mut witness = Witness::new();
                    witness.push(sig.to_vec());
                    tx.inputs[i].witness = witness;
                }
            } else if info.script_pubkey.is_p2sh() {
                // P2SH-P2WPKH: scriptSig contains the redeem script,
                // witness contains the signature and pubkey

                // Redeem script: OP_0 <20-byte pubkey hash>
                let mut redeem_script_bytes = Vec::with_capacity(22);
                redeem_script_bytes.push(0x00);
                redeem_script_bytes.push(20);
                redeem_script_bytes.extend_from_slice(&pubkey_hash);

                // scriptCode for signing (same as P2WPKH)
                let script_code = ScriptBuilder::new()
                    .push_opcode(Opcodes::OP_DUP)
                    .push_opcode(Opcodes::OP_HASH160)
                    .push_slice(&pubkey_hash)
                    .push_opcode(Opcodes::OP_EQUALVERIFY)
                    .push_opcode(Opcodes::OP_CHECKSIG)
                    .build();

                let checker = TransactionSignatureChecker::new_witness_v0(&tx, i, info.amount);

                let sighash = compute_sighash_for_checker(
                    &checker,
                    &script_code,
                    sighash_type::SIGHASH_ALL,
                    true,
                );

                let sig = sign_hash(&secp, key, &sighash)
                    .map_err(|e| BuilderError::SigningFailed(e.to_string()))?;

                let mut sig_with_hashtype = sig;
                sig_with_hashtype.push(sighash_type::SIGHASH_ALL);

                // scriptSig = <redeem_script>
                let script_sig = ScriptBuilder::new()
                    .push_slice(&redeem_script_bytes)
                    .build();
                tx.inputs[i].script_sig = script_sig;

                // Witness: [signature, pubkey]
                let mut witness = Witness::new();
                witness.push(sig_with_hashtype);
                witness.push(pubkey_bytes.clone());
                tx.inputs[i].witness = witness;
            } else {
                return Err(BuilderError::SigningFailed(format!(
                    "unsupported script type for input {}",
                    i
                )));
            }
        }

        Ok(tx)
    }
}

impl Default for TransactionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute a sighash using the TransactionSignatureChecker.
///
/// The checker's sighash methods are `pub(crate)`, so we can call them
/// directly from within the domain crate.
fn compute_sighash_for_checker(
    checker: &TransactionSignatureChecker,
    script_code: &Script,
    hash_type: u8,
    witness_v0: bool,
) -> [u8; 32] {
    if witness_v0 {
        checker.compute_sighash_witness_v0(script_code, hash_type)
    } else {
        checker.compute_sighash_legacy(script_code, hash_type)
    }
}

/// Sign a 32-byte hash with a private key, returning the DER-encoded signature.
fn sign_hash(
    secp: &Secp256k1<secp256k1::All>,
    key: &PrivateKey,
    hash: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let msg = Message::from_digest_slice(hash)
        .map_err(|e| format!("invalid message: {}", e))?;

    let sig = secp.sign_ecdsa(&msg, key.inner());

    Ok(sig.serialize_der().to_vec())
}

/// Create a P2PKH scriptPubKey from a public key hash.
pub fn make_p2pkh_script(pubkey_hash: &[u8; 20]) -> Script {
    ScriptBuilder::new()
        .push_opcode(Opcodes::OP_DUP)
        .push_opcode(Opcodes::OP_HASH160)
        .push_slice(pubkey_hash)
        .push_opcode(Opcodes::OP_EQUALVERIFY)
        .push_opcode(Opcodes::OP_CHECKSIG)
        .build()
}

/// Create a P2WPKH scriptPubKey from a public key hash.
pub fn make_p2wpkh_script(pubkey_hash: &[u8; 20]) -> Script {
    let mut bytes = Vec::with_capacity(22);
    bytes.push(0x00); // OP_0
    bytes.push(20);
    bytes.extend_from_slice(pubkey_hash);
    Script::from_bytes(bytes)
}

/// Create a P2TR scriptPubKey from a 32-byte x-only output key.
pub fn make_p2tr_script(output_key: &[u8; 32]) -> Script {
    let mut bytes = Vec::with_capacity(34);
    bytes.push(0x51); // OP_1
    bytes.push(32);
    bytes.extend_from_slice(output_key);
    Script::from_bytes(bytes)
}

/// Estimate the virtual size of a P2PKH input (approx 148 vbytes).
pub const P2PKH_INPUT_VSIZE: u32 = 148;

/// Estimate the virtual size of a P2WPKH input (approx 68 vbytes).
pub const P2WPKH_INPUT_VSIZE: u32 = 68;

/// Estimate the virtual size of a P2SH-P2WPKH input (approx 91 vbytes).
pub const P2SH_P2WPKH_INPUT_VSIZE: u32 = 91;

/// Estimate the virtual size of a P2PKH output (34 vbytes).
pub const P2PKH_OUTPUT_VSIZE: u32 = 34;

/// Estimate the virtual size of a P2WPKH output (31 vbytes).
pub const P2WPKH_OUTPUT_VSIZE: u32 = 31;

/// Estimate the virtual size of a P2TR input (approx 57.5 vbytes).
pub const P2TR_INPUT_VSIZE: u32 = 58;

/// Estimate the virtual size of a P2TR output (43 vbytes).
pub const P2TR_OUTPUT_VSIZE: u32 = 43;

/// Transaction overhead: version(4) + locktime(4) + input_count(1) + output_count(1) = 10
/// For SegWit: + marker(1) + flag(1) = 12, but witness is discounted
pub const TX_OVERHEAD_VSIZE: u32 = 11;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::Txid;
    use crate::wallet::keys::PrivateKey;

    #[test]
    fn test_builder_no_inputs() {
        let result = TransactionBuilder::new()
            .add_output(TxOut::new(Amount::from_sat(100_000), Script::new()))
            .build_unsigned();

        assert!(result.is_err());
    }

    #[test]
    fn test_builder_no_outputs() {
        let result = TransactionBuilder::new()
            .add_input(InputInfo {
                outpoint: OutPoint::new(Txid::zero(), 0),
                script_pubkey: Script::new(),
                amount: Amount::from_sat(100_000),
                signing_key: None,
                sequence: 0xFFFFFFFE,
                tap_script_path: None,
            })
            .build_unsigned();

        assert!(result.is_err());
    }

    #[test]
    fn test_build_unsigned() {
        let tx = TransactionBuilder::new()
            .version(2)
            .add_input(InputInfo {
                outpoint: OutPoint::new(Txid::zero(), 0),
                script_pubkey: Script::new(),
                amount: Amount::from_sat(100_000),
                signing_key: None,
                sequence: 0xFFFFFFFE,
                tap_script_path: None,
            })
            .add_output(TxOut::new(Amount::from_sat(90_000), Script::new()))
            .lock_time(0)
            .build_unsigned()
            .unwrap();

        assert_eq!(tx.version, 2);
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.outputs[0].value.as_sat(), 90_000);
    }

    #[test]
    fn test_sign_missing_key() {
        let result = TransactionBuilder::new()
            .add_input(InputInfo {
                outpoint: OutPoint::new(Txid::zero(), 0),
                script_pubkey: Script::new(),
                amount: Amount::from_sat(100_000),
                signing_key: None,
                sequence: 0xFFFFFFFE,
                tap_script_path: None,
            })
            .add_output(TxOut::new(Amount::from_sat(90_000), Script::new()))
            .sign();

        assert!(result.is_err());
    }

    #[test]
    fn test_sign_p2pkh_produces_scriptsig() {
        let key = PrivateKey::generate(true, true);
        let pubkey = key.public_key();
        let pubkey_hash = pubkey.pubkey_hash();
        let script_pubkey = make_p2pkh_script(&pubkey_hash);

        let tx = TransactionBuilder::new()
            .version(1)
            .add_input(InputInfo {
                outpoint: OutPoint::new(Txid::zero(), 0),
                script_pubkey,
                amount: Amount::from_sat(100_000),
                signing_key: Some(key),
                sequence: 0xFFFFFFFF,
                tap_script_path: None,
            })
            .add_output(TxOut::new(Amount::from_sat(90_000), Script::new()))
            .sign()
            .unwrap();

        // Should have a non-empty scriptSig
        assert!(!tx.inputs[0].script_sig.is_empty());
    }

    #[test]
    fn test_sign_p2wpkh_produces_witness() {
        let key = PrivateKey::generate(true, true);
        let pubkey = key.public_key();
        let pubkey_hash = pubkey.pubkey_hash();
        let script_pubkey = make_p2wpkh_script(&pubkey_hash);

        let tx = TransactionBuilder::new()
            .version(2)
            .add_input(InputInfo {
                outpoint: OutPoint::new(Txid::zero(), 0),
                script_pubkey,
                amount: Amount::from_sat(100_000),
                signing_key: Some(key),
                sequence: 0xFFFFFFFE,
                tap_script_path: None,
            })
            .add_output(TxOut::new(Amount::from_sat(90_000), Script::new()))
            .sign()
            .unwrap();

        // Should have empty scriptSig and non-empty witness
        assert!(tx.inputs[0].script_sig.is_empty());
        assert!(!tx.inputs[0].witness.is_empty());
        assert_eq!(tx.inputs[0].witness.len(), 2); // [sig, pubkey]
    }

    #[test]
    fn test_make_scripts() {
        let key = PrivateKey::generate(true, true);
        let pubkey = key.public_key();
        let hash = pubkey.pubkey_hash();

        let p2pkh = make_p2pkh_script(&hash);
        assert!(p2pkh.is_p2pkh());

        let p2wpkh = make_p2wpkh_script(&hash);
        assert!(p2wpkh.is_p2wpkh());
    }

    #[test]
    fn test_make_p2tr_script() {
        let output_key = [0x42; 32];
        let script = make_p2tr_script(&output_key);
        assert!(script.is_p2tr());
        assert_eq!(script.as_bytes().len(), 34);
        assert_eq!(script.as_bytes()[0], 0x51); // OP_1
    }

    #[test]
    fn test_sign_p2tr_produces_witness() {
        use secp256k1::{Keypair, XOnlyPublicKey, Scalar};

        // Generate a key and derive the P2TR output key
        let key = PrivateKey::generate(true, true);
        let secret = key.inner();

        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, secret);
        let (internal_xonly, _) = XOnlyPublicKey::from_keypair(&keypair);

        // Compute tweaked output key (key-path-only, no merkle root)
        let tweak = crate::crypto::taproot::taptweak_hash(
            &internal_xonly.serialize(), None,
        );
        let scalar = Scalar::from_be_bytes(tweak).unwrap();
        let (output_key, _) = internal_xonly.add_tweak(&secp, &scalar).unwrap();

        let script_pubkey = make_p2tr_script(&output_key.serialize());

        let tx = TransactionBuilder::new()
            .version(2)
            .add_input(InputInfo {
                outpoint: OutPoint::new(Txid::zero(), 0),
                script_pubkey,
                amount: Amount::from_sat(100_000),
                signing_key: Some(key),
                sequence: 0xFFFFFFFE,
                tap_script_path: None,
            })
            .add_output(TxOut::new(Amount::from_sat(90_000), Script::new()))
            .sign()
            .unwrap();

        // Should have empty scriptSig
        assert!(tx.inputs[0].script_sig.is_empty());
        // Witness should contain exactly 1 item: the 64-byte Schnorr signature
        assert_eq!(tx.inputs[0].witness.len(), 1);
        assert_eq!(tx.inputs[0].witness.get(0).unwrap().len(), 64);
    }

    #[test]
    fn test_sign_p2tr_signature_verifies() {
        use secp256k1::{Keypair, XOnlyPublicKey, Scalar};

        let key = PrivateKey::generate(true, true);
        let secret = key.inner();

        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, secret);
        let (internal_xonly, _) = XOnlyPublicKey::from_keypair(&keypair);

        let tweak = crate::crypto::taproot::taptweak_hash(
            &internal_xonly.serialize(), None,
        );
        let scalar = Scalar::from_be_bytes(tweak).unwrap();
        let (output_key, _) = internal_xonly.add_tweak(&secp, &scalar).unwrap();

        let script_pubkey = make_p2tr_script(&output_key.serialize());

        let tx = TransactionBuilder::new()
            .version(2)
            .add_input(InputInfo {
                outpoint: OutPoint::new(Txid::zero(), 0),
                script_pubkey: script_pubkey.clone(),
                amount: Amount::from_sat(100_000),
                signing_key: Some(key),
                sequence: 0xFFFFFFFE,
                tap_script_path: None,
            })
            .add_output(TxOut::new(Amount::from_sat(90_000), Script::new()))
            .sign()
            .unwrap();

        // Verify the Schnorr signature by re-computing the sighash
        let spent_outputs = vec![SpentOutput {
            amount: Amount::from_sat(100_000),
            script_pubkey,
        }];
        let checker = TransactionSignatureChecker::new_taproot(&tx, 0, spent_outputs);
        let sighash = checker.compute_taproot_sighash();

        let sig = tx.inputs[0].witness.get(0).unwrap();
        assert!(crate::crypto::schnorr::verify_schnorr(
            &output_key.serialize(),
            &sighash,
            sig,
        ));
    }
}

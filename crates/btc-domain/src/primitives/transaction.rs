//! Bitcoin transaction types
//!
//! Complete representation of Bitcoin transactions including inputs, outputs,
//! sequence numbers, and witness data.

use crate::crypto::hashing::hash256;
use crate::script::Script;
use crate::script::witness::Witness;
use std::fmt;

pub use crate::primitives::hash::{Hash256, Txid, Wtxid};
pub use crate::primitives::amount::Amount;

/// Sequence number constants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sequence;

impl Sequence {
    /// Final sequence number (0xffffffff)
    pub const FINAL: u32 = 0xffffffff;

    /// Maximum non-final sequence
    pub const MAX_NONFINAL: u32 = 0xfffffffe;

    /// Disable locktime flag
    pub const LOCKTIME_DISABLE_FLAG: u32 = 0x80000000;

    /// Locktime type flag (1 = blocks, 0 = seconds)
    pub const LOCKTIME_TYPE_FLAG: u32 = 0x00400000;

    /// Mask for locktime value
    pub const LOCKTIME_MASK: u32 = 0x0000ffff;
}

/// An outpoint - reference to a previous transaction output
///
/// Consists of a transaction hash and an output index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OutPoint {
    /// The transaction hash
    pub txid: Txid,
    /// The output index
    pub vout: u32,
}

impl OutPoint {
    /// Create a new outpoint
    pub const fn new(txid: Txid, vout: u32) -> Self {
        OutPoint { txid, vout }
    }

    /// Create a coinbase outpoint (zero hash, any index)
    pub const fn coinbase() -> Self {
        OutPoint {
            txid: Txid::zero(),
            vout: u32::MAX,
        }
    }

    /// Check if this is a coinbase outpoint
    pub fn is_coinbase(&self) -> bool {
        self.txid == Txid::zero() && self.vout == u32::MAX
    }
}

impl fmt::Display for OutPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.txid, self.vout)
    }
}

/// Transaction input
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxIn {
    /// The previous output being spent
    pub previous_output: OutPoint,
    /// The signature script
    pub script_sig: Script,
    /// Sequence number
    pub sequence: u32,
    /// Witness data (BIP141)
    pub witness: Witness,
}

impl TxIn {
    /// Create a new transaction input
    pub fn new(previous_output: OutPoint, script_sig: Script, sequence: u32) -> Self {
        TxIn {
            previous_output,
            script_sig,
            sequence,
            witness: Witness::new(),
        }
    }

    /// Create a final input (sequence = 0xffffffff)
    pub fn final_input(previous_output: OutPoint, script_sig: Script) -> Self {
        TxIn {
            previous_output,
            script_sig,
            sequence: Sequence::FINAL,
            witness: Witness::new(),
        }
    }

    /// Create with witness data
    pub fn with_witness(mut self, witness: Witness) -> Self {
        self.witness = witness;
        self
    }

    /// Check if this input is final
    pub fn is_final(&self) -> bool {
        self.sequence == Sequence::FINAL
    }
}

/// Transaction output
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOut {
    /// The amount being sent in satoshis
    pub value: Amount,
    /// The script pubkey
    pub script_pubkey: Script,
}

impl TxOut {
    /// Create a new transaction output
    pub fn new(value: Amount, script_pubkey: Script) -> Self {
        TxOut {
            value,
            script_pubkey,
        }
    }
}

/// A Bitcoin transaction
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    /// Transaction version
    pub version: i32,
    /// Transaction inputs
    pub inputs: Vec<TxIn>,
    /// Transaction outputs
    pub outputs: Vec<TxOut>,
    /// Locktime
    pub lock_time: u32,
}

impl Transaction {
    /// Create a new transaction
    pub fn new(version: i32, inputs: Vec<TxIn>, outputs: Vec<TxOut>, lock_time: u32) -> Self {
        Transaction {
            version,
            inputs,
            outputs,
            lock_time,
        }
    }

    /// Create a new v1 transaction (most common)
    pub fn v1(inputs: Vec<TxIn>, outputs: Vec<TxOut>, lock_time: u32) -> Self {
        Transaction::new(1, inputs, outputs, lock_time)
    }

    /// Create a coinbase transaction
    pub fn coinbase(_height: u32, coinbase_script: Script, outputs: Vec<TxOut>) -> Self {
        let mut coinbase_input = TxIn::final_input(OutPoint::coinbase(), coinbase_script);
        coinbase_input.sequence = 0xffffffff;
        
        Transaction {
            version: 1,
            inputs: vec![coinbase_input],
            outputs,
            lock_time: 0,
        }
    }

    /// Compute the transaction ID (txid)
    pub fn txid(&self) -> Txid {
        let serialized = self.serialize_noinput();
        Txid::from_hash(hash256(&serialized))
    }

    /// Compute the witness transaction ID (wtxid)
    pub fn wtxid(&self) -> Wtxid {
        let serialized = self.serialize();
        Wtxid::from_hash(hash256(&serialized))
    }

    /// Check if transaction is a coinbase transaction
    pub fn is_coinbase(&self) -> bool {
        self.inputs.len() == 1 && self.inputs[0].previous_output.is_coinbase()
    }

    /// Calculate total output value
    pub fn total_output_value(&self) -> Amount {
        self.outputs.iter().fold(Amount::from_sat(0), |acc, out| {
            acc + out.value
        })
    }

    /// Check if transaction has witness data
    pub fn has_witness(&self) -> bool {
        self.inputs.iter().any(|input| !input.witness.is_empty())
    }

    /// Compute transaction weight in witness units (4x non-witness data + 1x witness data)
    /// For non-witness transactions: weight = size * 4
    pub fn compute_weight(&self) -> u32 {
        let base_size = self.serialize_noinput().len() as u32;
        let total_size = self.serialize().len() as u32;
        let witness_size = total_size - base_size;
        
        base_size * 4 + witness_size
    }

    /// Compute virtual size (weight in vbytes, rounded up)
    pub fn compute_vsize(&self) -> u32 {
        (self.compute_weight() + 3) / 4
    }

    /// Check if all inputs are final
    pub fn is_final(&self) -> bool {
        self.inputs.iter().all(|input| input.is_final())
    }

    /// Serialize transaction without witness data
    fn serialize_noinput(&self) -> Vec<u8> {
        let mut data = Vec::new();
        
        // Version
        data.extend_from_slice(&self.version.to_le_bytes());
        
        // Input count
        data.extend_from_slice(&compact_size(self.inputs.len() as u64));
        
        // Inputs (without witness)
        for input in &self.inputs {
            // Previous output
            data.extend_from_slice(input.previous_output.txid.as_bytes());
            data.extend_from_slice(&input.previous_output.vout.to_le_bytes());
            
            // Script sig
            let script_bytes = input.script_sig.as_bytes();
            data.extend_from_slice(&compact_size(script_bytes.len() as u64));
            data.extend_from_slice(script_bytes);
            
            // Sequence
            data.extend_from_slice(&input.sequence.to_le_bytes());
        }
        
        // Output count
        data.extend_from_slice(&compact_size(self.outputs.len() as u64));
        
        // Outputs
        for output in &self.outputs {
            data.extend_from_slice(&output.value.as_sat().to_le_bytes());
            
            let script_bytes = output.script_pubkey.as_bytes();
            data.extend_from_slice(&compact_size(script_bytes.len() as u64));
            data.extend_from_slice(script_bytes);
        }
        
        // Locktime
        data.extend_from_slice(&self.lock_time.to_le_bytes());
        
        data
    }

    /// Serialize full transaction (including witness if present)
    fn serialize(&self) -> Vec<u8> {
        if !self.has_witness() {
            return self.serialize_noinput();
        }
        
        let mut data = Vec::new();
        
        // Version
        data.extend_from_slice(&self.version.to_le_bytes());
        
        // Marker and flag
        data.push(0x00);
        data.push(0x01);
        
        // Input count
        data.extend_from_slice(&compact_size(self.inputs.len() as u64));
        
        // Inputs
        for input in &self.inputs {
            // Previous output
            data.extend_from_slice(input.previous_output.txid.as_bytes());
            data.extend_from_slice(&input.previous_output.vout.to_le_bytes());
            
            // Script sig
            let script_bytes = input.script_sig.as_bytes();
            data.extend_from_slice(&compact_size(script_bytes.len() as u64));
            data.extend_from_slice(script_bytes);
            
            // Sequence
            data.extend_from_slice(&input.sequence.to_le_bytes());
        }
        
        // Output count
        data.extend_from_slice(&compact_size(self.outputs.len() as u64));
        
        // Outputs
        for output in &self.outputs {
            data.extend_from_slice(&output.value.as_sat().to_le_bytes());
            
            let script_bytes = output.script_pubkey.as_bytes();
            data.extend_from_slice(&compact_size(script_bytes.len() as u64));
            data.extend_from_slice(script_bytes);
        }
        
        // Witness data
        for input in &self.inputs {
            let witness_count = input.witness.len();
            data.extend_from_slice(&compact_size(witness_count as u64));
            
            for item in input.witness.stack() {
                data.extend_from_slice(&compact_size(item.len() as u64));
                data.extend_from_slice(item);
            }
        }
        
        // Locktime
        data.extend_from_slice(&self.lock_time.to_le_bytes());
        
        data
    }
}

impl fmt::Display for Transaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Transaction {{ version: {}, inputs: {}, outputs: {}, locktime: {} }}",
            self.version,
            self.inputs.len(),
            self.outputs.len(),
            self.lock_time
        )
    }
}

/// Encode a value as a Bitcoin compact size
fn compact_size(value: u64) -> Vec<u8> {
    if value < 0xfd {
        vec![value as u8]
    } else if value <= 0xffff {
        let mut bytes = vec![0xfd];
        bytes.extend_from_slice(&(value as u16).to_le_bytes());
        bytes
    } else if value <= 0xffffffff {
        let mut bytes = vec![0xfe];
        bytes.extend_from_slice(&(value as u32).to_le_bytes());
        bytes
    } else {
        let mut bytes = vec![0xff];
        bytes.extend_from_slice(&value.to_le_bytes());
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_outpoint_creation() {
        let txid = Txid::zero();
        let outpoint = OutPoint::new(txid, 0);
        assert_eq!(outpoint.vout, 0);
        assert!(!outpoint.is_coinbase());
    }

    #[test]
    fn test_coinbase_outpoint() {
        let outpoint = OutPoint::coinbase();
        assert!(outpoint.is_coinbase());
    }

    #[test]
    fn test_transaction_creation() {
        let tx = Transaction::v1(vec![], vec![], 0);
        assert_eq!(tx.version, 1);
        assert!(tx.inputs.is_empty());
        assert!(tx.outputs.is_empty());
    }

    #[test]
    fn test_transaction_is_coinbase() {
        let coinbase_tx = Transaction::coinbase(
            1,
            Script::new(),
            vec![TxOut::new(Amount::from_sat(5000000000), Script::new())],
        );
        assert!(coinbase_tx.is_coinbase());
    }

    #[test]
    fn test_witness_creation() {
        let mut witness = Witness::new();
        assert!(witness.is_empty());
        
        witness.push(vec![1, 2, 3]);
        assert_eq!(witness.len(), 1);
        assert!(!witness.is_empty());
    }
}

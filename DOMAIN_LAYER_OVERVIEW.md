# Agentic Bitcoin - Domain Layer (abtc-domain crate)

## Project Structure

```
agentic-bitcoin/
└── crates/
    └── abtc-domain/
        ├── Cargo.toml
        ├── README.md
        ├── src/
        │   ├── lib.rs                          (main entry, re-exports all public types)
        │   ├── primitives/
        │   │   ├── mod.rs
        │   │   ├── amount.rs                   (Amount, COIN, MAX_MONEY, arithmetic)
        │   │   ├── hash.rs                     (Hash256, Txid, Wtxid, BlockHash, hash256())
        │   │   ├── transaction.rs              (Transaction, TxIn, TxOut, OutPoint, Witness, Sequence)
        │   │   └── block.rs                    (BlockHeader, Block, BlockLocator, merkle trees)
        │   ├── consensus/
        │   │   ├── mod.rs
        │   │   ├── params.rs                   (ConsensusParams, Network, mainnet/testnet/regtest/signet)
        │   │   ├── validation.rs               (ValidationError, ValidationResult, ValidationState)
        │   │   ├── rules.rs                    (check_transaction, check_block, constants)
        │   │   ├── connect.rs                  (block connection/disconnection logic)
        │   │   └── signet.rs                   (signet challenge validation)
        │   ├── script/
        │   │   ├── mod.rs
        │   │   ├── opcodes.rs                  (Opcodes enum, ~100+ Bitcoin opcodes)
        │   │   ├── script.rs                   (Script, ScriptBuilder, pattern matching)
        │   │   ├── witness.rs                  (Witness stack)
        │   │   ├── interpreter.rs              (full script interpreter with stack machine)
        │   │   └── miniscript/
        │   │       ├── mod.rs
        │   │       ├── fragment.rs             (Miniscript fragment types)
        │   │       ├── decode.rs               (script-to-miniscript decoding)
        │   │       ├── compiler.rs             (policy-to-miniscript compilation)
        │   │       ├── policy.rs               (spending policy representation)
        │   │       └── types.rs                (type system for correctness/malleability)
        │   ├── crypto/
        │   │   ├── mod.rs
        │   │   ├── hashing.rs                  (hash256, hash160, sha256, hash_sig)
        │   │   ├── signing.rs                  (ECDSA signature verification, sighash computation)
        │   │   ├── schnorr.rs                  (BIP340 Schnorr signatures)
        │   │   ├── taproot.rs                  (BIP341/342 taproot key/script paths)
        │   │   └── bip324.rs                   (v2 encrypted P2P transport)
        │   ├── chain_params/
        │   │   └── mod.rs                      (ChainParams, genesis blocks, network config)
        │   ├── wallet/
        │   │   ├── mod.rs
        │   │   ├── keys.rs                     (BIP32 HD key derivation, xpub/xprv)
        │   │   ├── hd.rs                       (HD wallet path handling)
        │   │   ├── address.rs                  (address generation for all types)
        │   │   ├── coin_selection.rs           (branch-and-bound, knapsack, SRD)
        │   │   ├── tx_builder.rs               (transaction construction and signing)
        │   │   ├── psbt.rs                     (BIP174 partially signed transactions)
        │   │   └── descriptors/
        │   │       ├── mod.rs
        │   │       ├── descriptor.rs           (output descriptor types)
        │   │       ├── parser.rs               (descriptor string parsing)
        │   │       ├── compiler.rs             (descriptor-to-script compilation)
        │   │       ├── key_expr.rs             (key expression handling)
        │   │       └── checksum.rs             (descriptor checksum validation)
        │   ├── policy/
        │   │   ├── mod.rs
        │   │   ├── limits.rs                   (standardness and relay policy limits)
        │   │   ├── rbf.rs                      (BIP125 replace-by-fee rules)
        │   │   └── packages.rs                 (package relay policy, CPFP)
        │   ├── filters/
        │   │   ├── mod.rs
        │   │   ├── block_filter.rs             (BIP157/158 compact block filters)
        │   │   ├── gcs.rs                      (Golomb-coded set implementation)
        │   │   └── messages.rs                 (filter protocol messages)
        │   ├── protocol/
        │   │   ├── mod.rs
        │   │   ├── messages.rs                 (P2P protocol message types)
        │   │   ├── codec.rs                    (message serialization/deserialization)
        │   │   └── types.rs                    (network address, service flags, inventory)
        │   ├── utxo/
        │   │   ├── mod.rs
        │   │   ├── coin.rs                     (UTXO coin type and accessors)
        │   │   ├── muhash.rs                   (MuHash3072 for UTXO set hashing)
        │   │   └── snapshot.rs                 (assumeUTXO snapshot types)
        │   └── covenants/
        │       ├── mod.rs
        │       ├── ctv.rs                      (BIP119 CheckTemplateVerify)
        │       └── vault.rs                    (OP_VAULT covenant support)
        └── tests/
            ├── tx_validation_tests.rs
            ├── block_validation_tests.rs
            ├── script_tests.rs
            └── benchmarks.rs
```

## Layer Characteristics: INNERMOST HEXAGONAL LAYER

### Pure Domain Logic
- **Zero Infrastructure Dependencies**: No database, networking, async, or I/O
- **Type-Safe Representations**: Strong typing for all Bitcoin primitives
- **Deterministic & Testable**: All operations are pure functions
- **Serializable**: All types can be serialized/deserialized

### Comprehensive Coverage

**Primitives (Bitcoin Data Structures)**
- Amounts (satoshis) with arithmetic
- Hash types (256-bit hashes with hex encoding)
- Transactions with full serialization including SegWit
- Transaction inputs/outputs with witness support
- Blocks with merkle root computation
- Complete script representation

**Consensus Rules & Parameters**
- Network-specific configurations (4 networks)
- Subsidy halving, BIP activation heights
- Difficulty/PoW parameters
- Block connection/disconnection with UTXO updates
- Signet challenge validation
- Pure validation functions (no side effects)
- Detailed error types

**Script Engine**
- All Bitcoin opcodes defined
- Full stack-based script interpreter (all arithmetic, crypto, flow-control, and stack ops)
- Script pattern recognition (P2PKH, P2SH, P2WPKH, P2WSH, P2TR, OP_RETURN)
- Builder pattern for script construction
- Instruction iteration
- Miniscript: fragment types, policy compilation, decoding, and a type system for correctness and malleability analysis

**Cryptography**
- Double-SHA256 (primary Bitcoin hash)
- SHA256 + RIPEMD160 (address generation)
- ECDSA signature verification and sighash computation
- BIP340 Schnorr signatures
- BIP341/342 taproot (key path and script path spending, tapscript)
- BIP324 v2 encrypted P2P transport (ChaCha20-Poly1305, HKDF key derivation, rekeying)

**Wallet**
- BIP32 HD key derivation (xpub/xprv, child key derivation, hardened paths)
- Address generation for all types (P2PKH, P2SH, P2WPKH, P2WSH, P2TR, bech32/bech32m)
- Coin selection algorithms (branch-and-bound, knapsack, single-random-draw)
- Transaction builder with automatic change handling and fee calculation
- BIP174 PSBT (partially signed Bitcoin transactions)
- Output descriptors with parsing, compilation, key expressions, and checksums

**Policy**
- Standardness and relay policy limits
- BIP125 replace-by-fee rules
- Package relay policy for CPFP

**Compact Block Filters**
- BIP157/158 compact block filters
- Golomb-coded set (GCS) implementation
- Filter protocol messages

**P2P Protocol**
- Protocol message types (version, verack, inv, getdata, block, tx, headers, etc.)
- Message serialization/deserialization codec
- Network types (addresses, service flags, inventory vectors)

**UTXO Set**
- Coin type with height and coinbase tracking
- MuHash3072 for UTXO set integrity verification
- AssumeUTXO snapshot types

**Covenants**
- BIP119 CheckTemplateVerify (CTV)
- OP_VAULT covenant support

## Key Design Decisions

### 1. Strong Typing Over String/Bytes
```rust
// Not: amount: i64
// But: amount: Amount

let tx = Transaction::v1(inputs, outputs, locktime);
let txid: Txid = tx.txid();  // Type-safe ID
```

### 2. Pure Functions for Validation
```rust
// No state mutation, no I/O
pub fn check_transaction(tx: &Transaction) -> ValidationResult<()>
pub fn check_block(block: &Block, params: &ConsensusParams) -> ValidationResult<()>
```

### 3. Builder Patterns for Construction
```rust
let script = ScriptBuilder::new()
    .push_opcode(Opcodes::OP_DUP)
    .push_opcode(Opcodes::OP_HASH160)
    .push_int(1)
    .build();
```

### 4. Faithful Bitcoin Representation
- Transaction serialization matches Bitcoin Core exactly
- SegWit witness weight calculation (4x base + 1x witness)
- Merkle tree computation with proper padding
- All consensus constants accurate

## Type Exports from lib.rs

The crate re-exports essential types for convenient use:

```rust
pub use chain_params::ChainParams;
pub use consensus::Network;
pub use consensus::{ConsensusParams, ValidationResult, ValidationState};
pub use crypto::signing::{verify_ecdsa, TransactionSignatureChecker};
pub use primitives::{
    Amount, Block, BlockHash, BlockHeader, BlockLocator, Hash256,
    OutPoint, Sequence, Transaction, TxIn, TxOut, Txid, Witness, Wtxid,
};
pub use script::{
    is_push_only, verify_script, verify_script_with_witness, NoSigChecker,
    ScriptError, ScriptFlags, ScriptInterpreter, SignatureChecker,
};
pub use script::{Opcodes, Script, ScriptBuilder};
pub use secp256k1;
```

## Validation Rules Provided

### Transaction Validation
- Has inputs and outputs
- Output values non-negative and within MAX_MONEY
- No duplicate inputs
- Coinbase script size constraints
- Transaction size limits

### Block Validation
- Has transactions
- First tx is coinbase, others aren't
- Merkle root validity
- Block size within limits
- Block weight within limits
- Proof of work validity

## Testing Strategy

- **Unit Tests**: In each module
- **Integration Tests**: Dedicated test files for transaction validation, block validation, and script execution
- **Benchmarks**: Performance tests for core operations

Run tests:
```bash
cd crates/abtc-domain
cargo test                           # All tests
cargo test --test tx_validation      # Transaction validation
cargo test --test block_validation   # Block validation
cargo test --test script_tests       # Script interpreter
```

## Dependencies

Core cryptography and encoding:
- `sha1`, `sha2` (0.10): SHA-1 and SHA-256 hashing
- `hmac` (0.12): HMAC for HD key derivation
- `ripemd` (0.1): RIPEMD-160 hashing
- `hex` (0.4): Hex encoding/decoding
- `serde` (1.0): Serialization framework
- `thiserror` (1.0): Error derive macros
- `secp256k1` (0.29): Elliptic curve operations (ECDSA, Schnorr)
- `chacha20poly1305` (0.10): AEAD encryption for BIP324
- `hkdf` (0.12): Key derivation for BIP324
- `rand` (0.8): Random number generation

No database, networking, or async libraries.

## Rust Idioms Used

- **Derives**: Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord
- **Builders**: ScriptBuilder, TransactionBuilder for ergonomic construction
- **Iterators**: Script instruction iteration
- **Enums**: ValidationError, ScriptError with detailed codes
- **Option/Result**: Proper error handling throughout
- **Newtypes**: Txid, Wtxid, BlockHash for type safety
- **Traits**: SignatureChecker trait for pluggable verification

## File Statistics

- **Source Files**: 60 Rust modules
- **Source Lines**: ~30,800 lines
- **Test Lines**: ~2,660 lines across 4 test files
- **Modules**: 11 top-level modules (primitives, consensus, script, crypto, chain_params, wallet, policy, filters, protocol, utxo, covenants)

## Summary

The abtc-domain crate is a Bitcoin domain layer that:
- Faithfully represents all Bitcoin primitives
- Provides pure validation functions and a full script interpreter
- Implements modern Bitcoin features (taproot, Schnorr, BIP324, miniscript, descriptors, PSBT)
- Maintains zero infrastructure dependencies
- Uses strong typing and Rust idioms
- Serves as the foundation for the hexagonal architecture layers above

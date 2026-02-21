# Agentic Bitcoin - Domain Layer (btc-domain crate)

## Project Structure

```
agentic-bitcoin/
└── crates/
    └── btc-domain/
        ├── Cargo.toml
        ├── README.md
        ├── STRUCTURE.md
        ├── FILES_CREATED.txt
        ├── src/
        │   ├── lib.rs                      (main entry, re-exports all public types)
        │   ├── primitives/
        │   │   ├── mod.rs
        │   │   ├── amount.rs               (Amount, COIN, MAX_MONEY, arithmetic)
        │   │   ├── hash.rs                 (Hash256, Txid, Wtxid, BlockHash, hash256())
        │   │   ├── transaction.rs          (Transaction, TxIn, TxOut, OutPoint, Witness, Sequence)
        │   │   └── block.rs                (BlockHeader, Block, BlockLocator, merkle trees)
        │   ├── consensus/
        │   │   ├── mod.rs
        │   │   ├── params.rs               (ConsensusParams, Network, mainnet/testnet/regtest/signet)
        │   │   ├── validation.rs           (ValidationError, ValidationResult, ValidationState)
        │   │   └── rules.rs                (check_transaction, check_block, constants)
        │   ├── script/
        │   │   ├── mod.rs
        │   │   ├── opcodes.rs              (Opcodes enum, ~100+ Bitcoin opcodes)
        │   │   ├── script.rs               (Script, ScriptBuilder, pattern matching)
        │   │   └── witness.rs              (Witness stack)
        │   ├── crypto/
        │   │   ├── mod.rs
        │   │   └── hashing.rs              (hash256, hash160, sha256, hash_sig)
        │   └── chain_params/
        │       └── mod.rs                  (ChainParams, genesis blocks, network config)
        └── tests/
            └── integration.rs              (integration tests)
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
- Pure validation functions (no side effects)
- Detailed error types

**Script Engine Foundation**
- All Bitcoin opcodes defined
- Script pattern recognition (P2PKH, P2SH, P2WPKH, P2WSH, P2TR, OP_RETURN)
- Builder pattern for script construction
- Instruction iteration

**Cryptography**
- Double-SHA256 (primary Bitcoin hash)
- SHA256 + RIPEMD160 (address generation)
- Pluggable via dependency injection to upper layers

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

The crate re-exports all essential types for convenient use:

```rust
pub use chain_params::{ChainParams, Network};
pub use consensus::{ConsensusParams, ValidationResult, ValidationState};
pub use primitives::{
    Amount, Block, BlockHash, BlockHeader, BlockLocator, Hash256, 
    OutPoint, Sequence, Transaction, TxIn, TxOut, Txid, Witness, Wtxid,
};
pub use script::{Opcodes, Script, ScriptBuilder};
```

## Validation Rules Provided

### Transaction Validation
- ✓ Has inputs and outputs
- ✓ Output values non-negative and within MAX_MONEY
- ✓ No duplicate inputs
- ✓ Coinbase script size constraints
- ✓ Transaction size limits

### Block Validation
- ✓ Has transactions
- ✓ First tx is coinbase, others aren't
- ✓ Merkle root validity
- ✓ Block size within limits
- ✓ Block weight within limits
- ✓ Proof of work validity

## Testing Strategy

- **Unit Tests**: In each module (amount, hash, transaction, etc.)
- **Integration Tests**: In tests/integration.rs
- **Test Coverage**: All public APIs tested

Run tests:
```bash
cd crates/btc-domain
cargo test                 # All tests
cargo test --test integration   # Integration only
```

## Dependencies

Only essential cryptography and encoding:
- `sha2` (0.10): SHA256 hashing
- `ripemd` (0.1): RIPEMD160 hashing
- `hex` (0.4): Hex encoding/decoding

No higher-level dependencies; upper layers can introduce their own.

## Extensibility Points

### For Upper Layers (Application Layer)
1. **Transaction Signing**: Layers above implement signature verification
2. **UTXO Management**: External layers manage the UTXO set
3. **Networking**: P2P communication layer sits above
4. **Storage**: Persistence layer remains independent
5. **Serialization**: Serde integration can be added in adapter layer

### Pluggable Components
- Different hash implementations can be swapped
- Validation logic is composable
- Network parameters are configurable

## Rust Idioms Used

- **Derives**: Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord
- **Builders**: ScriptBuilder for ergonomic construction
- **Iterators**: Script instruction iteration
- **Enums**: ValidationError with detailed codes
- **Option/Result**: Proper error handling
- **Constants**: Const-time constructors where applicable

## File Statistics

- **Total Source Files**: 17 main modules + documentation
- **Total Lines**: ~4,000+ lines of idiomatic Rust
- **Test Coverage**: Integration + unit tests throughout
- **Documentation**: Extensive inline docs and README

## Next Steps (For Upper Layers)

This domain layer provides the foundation for:
1. **Application Layer**: Business logic, UTXO management
2. **Adapter Layer**: Serialization (Serde), network formats
3. **Infrastructure Layer**: Database, networking, RPC
4. **Test Doubles**: Mock implementations using domain types

## Summary

The btc-domain crate is a complete, production-quality Bitcoin domain layer that:
- Faithfully represents all Bitcoin primitives
- Provides pure validation functions
- Maintains zero infrastructure dependencies
- Uses strong typing and Rust idioms
- Is fully tested and documented
- Serves as the foundation for hexagonal architecture layers

All code is idiomatic Rust, properly documented, and ready for integration with upper layers.

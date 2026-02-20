# BTC-Domain Crate

Bitcoin domain layer - the INNERMOST layer of hexagonal architecture with pure domain logic and ZERO infrastructure dependencies.

## Overview

This crate provides complete Bitcoin domain types and validation rules:
- Transaction and block types faithfully modeling Bitcoin's data structures
- Consensus parameters for mainnet, testnet, regtest, and signet
- Script type with Bitcoin opcode support
- Hash functions and cryptographic primitives
- Pure validation functions with no side effects

## Modules

### `primitives`
Core Bitcoin types representing the blockchain data structure:
- **Amount**: Satoshi amounts with arithmetic operations
- **Hash256/Txid/Wtxid/BlockHash**: Hash types with hex encoding
- **Transaction/TxIn/TxOut/OutPoint**: Transaction structure
- **Witness**: SegWit witness data
- **Block/BlockHeader/BlockLocator**: Block structure and merkle roots

### `consensus`
Consensus rules and parameters:
- **ConsensusParams**: Network parameters (4 networks: mainnet, testnet, regtest, signet)
- **Validation errors and states**
- **Pure validation rules** for transactions and blocks
- Constants: MAX_BLOCK_SIZE, MAX_BLOCK_WEIGHT, WITNESS_SCALE_FACTOR, etc.

### `script`
Bitcoin script handling:
- **Opcodes**: All ~100+ Bitcoin opcodes defined
- **Script**: Script type with pattern matching for P2PKH, P2SH, P2WPKH, P2WSH, P2TR, OP_RETURN
- **ScriptBuilder**: Builder pattern for script construction
- **Witness**: Witness data stack for signature verification

### `crypto`
Cryptographic functions:
- **hash256**: Double-SHA256 (primary Bitcoin hash)
- **hash160**: SHA256 → RIPEMD160 (for address generation)
- **sha256**: Single SHA256
- **hash_sig**: Signature hashing

### `chain_params`
Network configuration:
- **ChainParams**: Per-network configuration (magic bytes, ports, DNS seeds)
- **Network**: Enum for mainnet, testnet, regtest, signet
- **Genesis blocks**: Per-network genesis block generation

## Key Design Decisions

### Pure Domain Logic
- No database, networking, or async code
- All types are serializable/deserializable
- Validation functions are pure (no side effects)
- Complete independence from infrastructure layers

### Type Safety
- Strong typing for Amount, Hash, Txid, BlockHash
- Witness data properly typed
- Sequence numbers as constants
- OutPoint type instead of separate hash/index fields

### Idiomatic Rust
- Extensive use of derives (Debug, Clone, PartialEq, Eq, Hash)
- Builder patterns (ScriptBuilder)
- Proper error handling (ValidationError enum)
- Iterator support (script instructions)

### Bitcoin Accuracy
- Transaction serialization including witness data
- Merkle root computation with proper padding
- SegWit weight calculation (4x base + 1x witness)
- Virtual size (vsize) computation
- All consensus constants (COIN, MAX_MONEY, subsidy halving, etc.)

## Example Usage

```rust
use btc_domain::*;

// Create a transaction
let input = TxIn::final_input(
    OutPoint::new(Txid::zero(), 0),
    Script::new()
);
let output = TxOut::new(
    Amount::from_sat(100_000),
    Script::new()
);
let tx = Transaction::v1(vec![input], vec![output], 0);

// Get transaction ID
let txid = tx.txid();

// Build a script
let script = ScriptBuilder::new()
    .push_opcode(Opcodes::OP_DUP)
    .push_opcode(Opcodes::OP_HASH160)
    .push_int(1)
    .build();

// Check network parameters
let params = ConsensusParams::mainnet();
assert_eq!(params.subsidy_halving_interval, 210_000);

// Validate transaction
use btc_domain::consensus::rules::check_transaction;
let result = check_transaction(&tx);
```

## No External Dependencies Beyond Core Cryptography
- `sha2`: SHA-256 hashing
- `ripemd`: RIPEMD-160 hashing  
- `hex`: Hex encoding/decoding

## Testing

Run integration tests:
```bash
cargo test --test integration
```

Run all tests including module tests:
```bash
cargo test
```

## License

MIT

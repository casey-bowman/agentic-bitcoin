# Agentic Bitcoin — Session Notes

## Architecture

Hexagonal architecture with 5 crates:

- **btc-domain**: Core types, consensus rules, script interpreter, wallet (HD/PSBT/coin selection/tx builder), crypto (hashing, signing, schnorr, taproot)
- **btc-ports**: Trait interfaces (no implementations)
- **btc-adapters**: In-memory implementations of port traits (storage, mempool, wallet, mining, network, rpc)
- **btc-application**: Services and use-cases (chain_state, net_processing, block_template, miner, fee_estimator, mempool_acceptance, compact_blocks, download_scheduler, peer_scoring, orphan_pool, rebroadcast, handlers, chain_events)
- **btc-infrastructure**: Node wiring layer that composes everything together

## What Has Been Implemented (Sessions 1–6)

- Script interpreter with full opcode support
- P2PKH and P2WPKH signing and verification
- HD wallets (BIP32/BIP44) with derivation paths, xprv/xpub serialization
- Coin selection (largest-first, smallest-first, closest-match)
- Transaction builder with P2PKH and P2WPKH signing
- Block validation with real script execution
- Compact blocks (BIP152) with SipHash short txids
- Download scheduler with peer selection and timeout detection
- Peer scoring with misbehavior tracking and banning
- Transaction rebroadcast manager
- Fee estimator with block history and percentile calculations
- Median Time Past / BIP113 in BlockIndex
- Chain tip notification event bus (chain_events)
- PSBT / BIP174 (create, sign, combine, finalize, extract)
- Comprehensive test suite (548 tests, 0 failures as of Session 6)

## Test Coverage Summary (Session 6)

| Crate / Binary | Tests | Notes |
|---|---|---|
| btc-domain | 219 | Primitives, consensus, script, wallet/HD/PSBT, crypto |
| btc-application (unit) | 178 | chain_state, net_processing, block_template, miner, fee_estimator, mempool_acceptance, compact_blocks, download_scheduler, peer_scoring, orphan_pool, rebroadcast, handlers, chain_events |
| btc-application (integration) | 14 | chain_state_tests |
| btc-adapters | 76 | storage, mempool, wallet, mining, network, rpc |
| btc-infrastructure | 4 | Node wiring |
| block_validation_tests | 16 | End-to-end block connect/disconnect with real scripts |
| tx_validation_tests | 29 | Serialization, signing, policy, end-to-end |
| script_tests | 8 | Script vectors, hash known vectors |
| benchmarks | 4 | Hashing, secp256k1, script execution, taproot |

## Known Coverage Gaps

- `btc-ports` has 0 tests (trait definitions only, but could test trait object construction)
- `btc-infrastructure` has only 4 tests — Node wiring could use more
- No integration tests for PSBT workflows end-to-end
- No tests for chain event bus integration with chain_state (events tested in isolation only)
- `net_processing.rs` is ~88KB — fuzz/property-based tests would add value
- No tests for Taproot script-path spending end-to-end

## Development Environment Notes

- No Rust toolchain in the Claude sandbox — user runs `cargo check`/`cargo test` locally and shares output files
- Output files are saved as RTF in `output/` directory (e.g., output85.rtf, output86.rtf)
- All code compiles with zero warnings as of Session 6

## Session Log

### Session 6 — Tests & Hardening
- Added ~60 new tests across 6 files (~800 lines of test code)
- Fixed unused imports in psbt.rs (Session 5 leftover) and chain_state.rs
- Fixed merkle root bug in chain_state test helper — `make_genesis()` now uses `block.compute_merkle_root()` instead of zeroed bytes
- Final: 548 tests pass, 0 failures, 0 warnings

### Session 5 — New Features
- Median Time Past (BIP113) in BlockIndex
- Chain tip notification event bus (chain_events.rs)
- PSBT (BIP174) in wallet/psbt.rs

### Sessions 1–4 — Foundation
- Core primitives, consensus, script interpreter
- Wallet layer (keys, addresses, HD, coin selection, tx builder)
- P2P networking (net_processing, peer scoring, download scheduler)
- Block/transaction validation with real cryptographic verification
- Compact blocks, fee estimator, rebroadcast manager
- RPC handler framework

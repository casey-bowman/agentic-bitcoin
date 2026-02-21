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
- Taproot key-path signing (BIP340/BIP341) with Schnorr signatures, P2TR addresses (bech32m/BIP350), P2TR tx building, PSBT P2TR finalization
- Taproot script-path spending (BIP341/BIP342) with TapTree construction, OP_CHECKSIGADD, script-path sighash, full signing pipeline
- Comprehensive test suite (612 tests, 0 failures as of Session 9)

## Test Coverage Summary (Session 7)

| Crate / Binary | Tests | Notes |
|---|---|---|
| btc-domain | 266 | Primitives, consensus, script, wallet/HD/PSBT/P2TR, crypto/taproot/schnorr-signing |
| btc-application (unit) | 178 | chain_state, net_processing, block_template, miner, fee_estimator, mempool_acceptance, compact_blocks, download_scheduler, peer_scoring, orphan_pool, rebroadcast, handlers, chain_events |
| btc-application (integration) | 20 | chain_state_tests (UTXO tracking, reorg, persistence) |
| btc-adapters | 76 | storage, mempool, wallet, mining, network, rpc |
| btc-infrastructure | 10 | Node wiring, fee estimator, rebroadcast, wallet, mempool, testnet |
| block_validation_tests | 16 | End-to-end block connect/disconnect with real scripts |
| tx_validation_tests | 34 | Serialization, signing, policy, end-to-end (incl. P2TR, script-path) |
| script_tests | 8 | Script vectors, hash known vectors |
| benchmarks | 4 | Hashing, secp256k1, script execution, taproot |

## Roadmap (User-Requested, In Order)
1. **Wallet persistence** — serialize/deserialize wallet state (keys, UTXOs, addresses) to disk
2. **BIP325 Signet support** — custom signets with challenge scripts
3. **Miniscript / output descriptors** — user is most interested in this one; policy→miniscript compilation, descriptor parsing, script generation

## Known Coverage Gaps

- `btc-ports` has 0 tests (trait definitions only, but could test trait object construction)
- No tests for chain event bus integration with chain_state (events tested in isolation only)
- `net_processing.rs` is ~88KB — fuzz/property-based tests would add value

## Development Environment Notes

- No Rust toolchain in the Claude sandbox — user runs `cargo check`/`cargo test` locally and shares output files
- Output files are saved as RTF in `output/` directory (e.g., output85.rtf, output86.rtf)
- All code compiles with zero warnings as of Session 9

## Session Log

### Session 9 — Taproot Script-Path Spending (BIP341/BIP342)
- Added **TapTree** builder to crypto/taproot.rs — `TapLeaf` (leaf_version + script), `TapNode` enum (Leaf/Branch), `TapTree` struct with balanced binary tree construction, merkle root, leaf hashes, control block generation, `serialize_control_block()`, `compute_output_key()`
- Added **script-path sighash** (BIP341 §4.3) to signing.rs — `compute_taproot_sighash_script_path()` with spend_type=0x02 (ext_flag=1), tapleaf_hash, key_version=0x00, code_separator_pos=0xFFFFFFFF; added `tapleaf_hash` field and `set_tapleaf_hash()` to `TransactionSignatureChecker`
- Added **OP_CHECKSIGADD** (0xBA) to opcodes.rs + interpreter.rs — BIP342 multi-sig accumulator: pops pubkey, num, sig; empty sig→push n, valid sig→push n+1, invalid non-empty→fail
- Added **TapscriptChecker** wrapper to interpreter.rs — redirects `check_sig` to Schnorr in tapscript context, delegates `check_tapscript_sig` to inner checker with tapleaf_hash
- Updated **verify_taproot()** in interpreter.rs — script-path branch computes tapleaf_hash, creates TapscriptChecker, passes to ScriptInterpreter
- Added **script-path signing** to tx_builder.rs — `TapScriptPath` struct (script, control_block, leaf_hash), `tap_script_path` field on `InputInfo`; script-path uses `sign_schnorr` (untweaked) + script-path sighash, witness = [sig, script, control_block]
- Added `check_tapscript_sig()` to `SignatureChecker` trait (default false) for passing leaf_hash through trait boundary
- 11 new tests: 9 TapTree unit tests (single/two/three leaf trees, control blocks, serialize roundtrip, compute+verify output key), 3 E2E tests (`test_e2e_taproot_script_path_single_checksig`, `test_e2e_taproot_script_path_op1_leaf`, `test_e2e_taproot_script_path_wrong_script_fails`)
- Fixed borrow checker error E0502 in tx_builder.rs — moved `script_sig = Script::new()` before creating checker to avoid overlapping immutable/mutable borrows
- Final: 612 tests pass, 0 failures, 0 warnings

### Session 8 — Taproot Key-Path Signing (BIP340/341)
- Added **Schnorr signing** (`sign_schnorr`, `sign_schnorr_tweaked`) to crypto/schnorr.rs — BIP340-compliant 64-byte signatures with key tweaking for Taproot
- Added **SpentOutput** struct and `new_taproot()` constructor to signing.rs — fixes BIP341 sighash to use all spent output amounts/scriptPubKeys
- Added **P2TR addresses** with bech32m (BIP350) to address.rs — `Address::p2tr()`, `Address::p2tr_from_internal_key()`, bech32m encode/decode with `BECH32M_CONST = 0x2bc830a3`
- Added **P2TR key-path signing** to tx_builder.rs — detects `is_p2tr()`, collects spent outputs, computes taproot sighash, signs with tweaked key
- Added **P2TR PSBT finalization** to psbt.rs — produces witness with `[signature]` only (no pubkey), vs P2WPKH `[signature, pubkey]`
- Added **P2TR to btc-adapters** — wallet now handles `AddressType::P2TR` for address generation and key import
- Removed obsolete `bech32_decode` and `bech32_verify_checksum` (superseded by versioned variants)
- 19 new tests: 5 schnorr signing, 8 P2TR address, 3 tx_builder P2TR, 2 PSBT P2TR, 2 E2E integration (sign+serialize+verify, address-to-verification)
- Final: 601 tests pass, 0 failures, 4 warnings (unused imports — cleaned up post-output)

### Session 7 — More Tests & Hardening
- Added 34 new tests across 4 files, bringing total from 548 → 582
- **PSBT (psbt.rs):** 8 new end-to-end tests — full workflow (witness & legacy), multi-signer combine, serialize roundtrip, error cases, idempotent finalization
- **Taproot (taproot.rs):** 14 new tests — real secp256k1 script-path commitment verification (single & two-script trees), parity checks, control block parsing (multi-node paths, max depth rejection), compact size encoding edge cases
- **Chain state (chain_state_tests.rs):** 6 new integration tests — UTXO existence after connection, removal after spend, restoration after reorg, multiple spends in same block, flush-to-store persistence, flush-after-reorg persistence
- **Infrastructure (lib.rs):** 6 new Node wiring tests — fee estimator, rebroadcast manager, wallet enable/disable, mempool starts empty, testnet creation
- Added `has_utxo()` method to ChainState for UTXO-level querying
- Fixed PSBT finalization semantics: `finalize_input()` does NOT clear `witness_utxo` and IS idempotent
- Final: 582 tests pass, 0 failures, 0 warnings

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

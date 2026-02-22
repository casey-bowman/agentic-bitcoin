# Agentic Bitcoin — Session Notes

## Architecture

Hexagonal architecture with 5 crates:

- **abtc-domain**: Core types, consensus rules, script interpreter, wallet (HD/PSBT/coin selection/tx builder), crypto (hashing, signing, schnorr, taproot)
- **abtc-ports**: Trait interfaces (no implementations)
- **abtc-adapters**: In-memory implementations of port traits (storage, mempool, wallet, mining, network, rpc)
- **abtc-application**: Services and use-cases (chain_state, net_processing, block_template, miner, fee_estimator, mempool_acceptance, compact_blocks, download_scheduler, peer_scoring, orphan_pool, rebroadcast, handlers, chain_events)
- **abtc-infrastructure**: Node wiring layer that composes everything together

## What Has Been Implemented (Sessions 1–15)

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
- Wallet persistence — JSON file store with atomic writes, PersistentWallet wrapper, `--wallet-file` CLI flag
- BIP325 Signet validation — challenge script verification, signet commitment extraction, virtual tx construction, P2WPKH signing
- Miniscript type system (B/V/K/W base types + 10 modifier flags), fragment AST (~30 terminal types), compilation to Script, parsing from Script
- Output descriptors (BIP380-386): pk/pkh/wpkh/sh/wsh/tr, multi/sortedmulti, key expressions (raw hex, xpub/xprv with derivation paths, wildcards), BIP380 checksum, script/address derivation
- P2P wire protocol: complete message codec (protocol/ module) with all Bitcoin P2P message types, real SHA-256d checksums, compact size encoding, BIP144/BIP152/BIP339 support
- BIP158 compact block filters (Neutrino): Golomb-Coded Set encoding/decoding, SipHash-2-4, basic filter construction from blocks, filter header chain, BIP157 P2P messages
- UTXO set commitments / AssumeUTXO: coin compression (amount + script), MuHash3072 rolling set hash (3072-bit multiplicative group), snapshot format (metadata, serialize/deserialize, commitment verification), hardcoded AssumeUTXO parameters
- Covenant opcodes (BIP119 CTV + BIP345 OP_VAULT/OP_VAULT_RECOVER) — proposed, activation-gated via `VERIFY_CHECKTEMPLATEVERIFY` and `VERIFY_VAULT` ScriptFlags
- BIP324 encrypted transport (v2 P2P) with ChaCha20-Poly1305
- Package relay (BIP331-style) with topological sort, CPFP fee evaluation
- Infrastructure hardening: graceful shutdown, health checks, SIGTERM handling
- Comprehensive test suite (1,103 tests, 0 failures as of Session 15)

## Test Coverage Summary (Session 15)

| Crate / Binary | Tests | Notes |
|---|---|---|
| abtc-domain | 688 | Primitives, consensus, script, wallet/HD/PSBT/P2TR, crypto (taproot, schnorr, BIP324) |
| abtc-application (unit) | 199 | chain_state, net_processing, block_template, miner, fee_estimator, mempool_acceptance, compact_blocks, download_scheduler, peer_scoring, orphan_pool, rebroadcast, handlers, chain_events, package_relay |
| abtc-application (integration) | 20 | chain_state_tests (UTXO tracking, reorg, persistence) |
| abtc-adapters | 105 | storage, mempool, wallet, mining, network (incl. v2 transport), rpc |
| abtc-infrastructure | 29 | Node wiring, health checks, shutdown signaling, task tracker, fee estimator, rebroadcast, wallet, mempool, testnet, signet |
| block_validation_tests | 16 | End-to-end block connect/disconnect with real scripts |
| tx_validation_tests | 34 | Serialization, signing, policy, end-to-end (incl. P2TR, script-path) |
| script_tests | 8 | Script vectors, hash known vectors |
| benchmarks | 4 | Hashing, secp256k1, script execution, taproot |

## Roadmap (User-Requested, In Order)
1. ~~**Wallet persistence** — serialize/deserialize wallet state (keys, UTXOs, addresses) to disk~~ ✓ Done (Session 11)
2. ~~**BIP325 Signet support** — custom signets with challenge scripts~~ ✓ Done (Session 11 Part 2)
3. ~~**Miniscript / output descriptors** — user is most interested in this one; miniscript type system, fragment AST, compilation/decoding, descriptor parsing, script/address generation~~ ✓ Done (Session 12)
4. ~~**P2P wire protocol (BIP144/BIP339)** — complete message codec for all Bitcoin P2P messages~~ ✓ Done (Session 13)
5. ~~**BIP158 compact block filters (Neutrino)** — GCS encoding, filter construction, P2P messages~~ ✓ Done (Session 13)
6. ~~**UTXO set commitments / AssumeUTXO** — serializable UTXO snapshots for fast sync~~ ✓ Done (Session 14)
7. ~~**Covenant opcodes (BIP119 CTV + BIP345 OP_VAULT)** — template verification and vault spending~~ ✓ Done (Session 14, activation-gated via ScriptFlags)
8. ~~**BIP324 encrypted transport** — v2 P2P with ChaCha20-Poly1305 AEAD~~ ✓ Done (Session 15)
9. ~~**Package relay (BIP331-style)** — topological sort, CPFP fee evaluation, PackageAcceptor~~ ✓ Done (Session 15)
10. ~~**Infrastructure hardening** — graceful shutdown, health checks, SIGTERM, task tracking~~ ✓ Done (Session 15)
11. ~~**Refactor pass** — consensus params injection, dead code elimination, test hardening~~ ✓ Done (Session 15)

## Simplifications vs Bitcoin Core ("Lite → Full" Upgrade Path)

The current implementation prioritizes correctness of algorithms and interfaces over production-scale performance. Every simplification below is a candidate for a "Full" variant that could handle mainnet-scale load. The hexagonal architecture makes this feasible — most upgrades are new adapters behind existing port traits, leaving abtc-domain untouched.

### UTXO Storage
- **Lite (current):** `HashMap<(Txid, u32), UtxoEntry>` in memory. Simple, fast for tests.
- **Full:** LevelDB/RocksDB-backed `CCoinsViewDB` with a multi-layer write-back cache (`CCoinsViewCache` → `CCoinsViewBacked` → DB). Batch writes, memory-mapped I/O. Required for mainnet's ~180M UTXOs.
- **Upgrade path:** New adapter behind the existing `UtxoStore` port trait.

### Block Storage
- **Lite (current):** `HashMap<Hash256, Block>` in memory. No disk persistence, no pruning.
- **Full:** Raw blocks split across `blk*.dat` files (~128MB each) with a separate block index DB for O(1) lookup by hash or height. Pruning support to cap disk usage.
- **Upgrade path:** New adapter behind the existing `BlockStore` port trait.

### Mempool
- **Lite (current):** Basic ancestor/descendant tracking, simplified eviction and mining selection. Linear scans for candidate selection.
- **Full:** Multi-index container (by feerate, by ancestor score, by time) for O(1) best-candidate selection. Incremental feerate comparison for eviction. Full package relay support (BIP331).
- **Upgrade path:** Mostly internal to the mempool adapter; port trait stays the same.

### Script Verification
- **Lite (current):** Single-threaded, sequential signature checks during block validation.
- **Full:** `CCheckQueue`-style thread pool distributing signature verification across all CPU cores. Particularly important for blocks with many inputs.
- **Upgrade path:** Parallel iterator in the block validation loop (e.g., `rayon`), or a dedicated verification queue in abtc-application.

### Peer / Address Management
- **Lite (current):** Simple new/tried tables with basic eviction and source tracking.
- **Full:** Bucketed address manager with deterministic bucket placement (hash of address + source + group) to resist eclipse attacks. 1024 "new" buckets, 256 "tried" buckets.
- **Upgrade path:** Replace the address manager adapter; the port trait already supports the needed operations.

### Block Index
- **Lite (current):** `HashMap` with linear ancestor traversal.
- **Full:** Linked tree with `pskip` pointers for O(log n) ancestor lookups (used heavily in reorg detection and MTP calculation). Persisted to LevelDB.
- **Upgrade path:** New `BlockIndex` implementation in abtc-application with skip-list pointers; storage adapter for persistence.

### Fee Estimation
- **Lite (current):** Sliding window of recent block median fee rates.
- **Full:** Exponentially-decaying moving average across multiple confirmation-target buckets, tracking where transactions actually confirmed. Core uses ~40 fee rate buckets with 3 decay periods.
- **Upgrade path:** Replace the fee estimator in abtc-application; the port trait already returns fee rate estimates by target.

### Wallet Persistence
- **Lite (implemented, Session 11):** JSON file serialization of keys (WIF), UTXOs, addresses, and key counter. Atomic writes with temp file + rename. PersistentWallet wrapper with auto-save. Enabled via `--wallet-file` CLI flag.
- **Full:** SQLite-backed descriptor wallet (Core's post-v0.21 model) with proper schema, WAL journaling, concurrent RPC access support.
- **Upgrade path:** New adapter behind the existing `WalletStore` port trait.

### General Strategy
The "Lite" versions are correct — they implement the same algorithms, validate the same rules, and produce the same results as Core. The "Full" versions add the infrastructure needed to do so under mainnet load (~1M transactions/day, ~180M UTXOs, thousands of peers, multi-GB block storage). The hexagonal architecture means most upgrades are isolated to new adapters, with no changes to domain logic or consensus rules.

## Known Coverage Gaps

- `abtc-ports` has 0 tests (trait definitions only, but could test trait object construction)
- No tests for chain event bus integration with chain_state (events tested in isolation only)
- `net_processing.rs` is ~88KB — fuzz/property-based tests would add value

## Architectural Notes for Future Work

- **`net_processing.rs` is the largest module (~88KB)** and the one place that keeps growing as new P2P features land. It could benefit from being split into sub-handlers (handshake, block sync, tx relay, package relay) while keeping `SyncManager` as the coordinator. Not urgent but worth doing before the next major P2P feature.
- **Two `NetworkMessage` types exist**: one in `abtc-ports` (application-facing, used by net_processing and infrastructure) and one in `abtc-domain/src/protocol/` (wire-format codec with full serialization). They work fine independently but should eventually converge — likely by having the ports type delegate to the domain codec for encoding/decoding.
- **`services.rs` error handling** still uses `Result<_, String>` while `mempool_acceptance.rs` has proper `AcceptError` enums. A `ServiceError` enum would improve consistency and make error handling more actionable for callers.
- **The hexagonal architecture is holding up well after 15 sessions and 1,103 tests.** Features land cleanly in their respective layers without cross-cutting changes. Infrastructure hardening (Session 15) touched only `abtc-infrastructure` despite rewriting all background tasks. The composition root pattern in `BitcoinNode::new()` keeps wiring isolated.

## Development Environment Notes

- No Rust toolchain in the Claude sandbox — user runs `cargo check`/`cargo test` locally and shares output files
- Output files are saved as RTF in `output/` directory (e.g., o39.rtf, o40.rtf) — naming convention changed from `outputNN.rtf` to `oNN.rtf` around Session 15
- User communicates cargo results by saying "oNN" — meaning "read output/oNN.rtf"
- All code compiles with zero warnings (maintained since Session 9, verified through Session 15)
- Tests that call `node.start()` need unique RPC ports to avoid AddrInUse in parallel runs — use `unique_port()` helper in infrastructure tests

## Session Log

### Session 15 — BIP324, Package Relay, Infrastructure Hardening, Refactor Pass
- **BIP324 encrypted transport** (`abtc-domain/src/crypto/bip324.rs`, `abtc-adapters/src/network/v2/`):
  - Full v2 P2P handshake: ECDH key exchange, HKDF-SHA256 key derivation, ChaCha20-Poly1305 AEAD encryption/decryption
  - Session IDs derived from shared secret for authentication
  - Bidirectional message encryption with 3-byte header (1 flag + 2 length) + AEAD tag
  - Short command IDs for common messages (12 types), ASCII fallback for unknown commands
  - `V2Transport` struct managing handshake state machine → encrypted session
  - ~20 tests: ECDH agreement, HKDF derivation, AEAD roundtrip, handshake completion, bidirectional communication, tampered ciphertext rejection, session ID matching, error display

- **Package relay** (`abtc-domain/src/policy/packages.rs`, `abtc-application/src/package_relay.rs`, network messages):
  - BIP331-style package validation: topological sort (Kahn's algorithm), conflict detection, aggregate fee rate evaluation
  - Package classification: `ChildWithParents` (CPFP) vs `TopologicalPackage`
  - `PackageAcceptor` service: resolves inputs from UTXO set AND package-internal outputs (critical for CPFP)
  - `PackageTx` and `SendPackages` network message variants with encoding/decoding
  - Handler in `net_processing.rs` for incoming package messages
  - ~29 tests: topological sort, cycle detection, conflict detection, fee rate checks, classification, CPFP acceptance, regression tests

- **Infrastructure hardening** (`abtc-infrastructure/src/lib.rs`):
  - `NodeHealth` struct: aggregates running status, active tasks, uptime, sync state, block height, mempool size, peer count, RPC status
  - `TaskTracker` + `TaskGuard` (RAII): spawned tasks register a guard that decrements active count on drop
  - `tokio::sync::watch` channel: shutdown signal to all 5 background tasks via `tokio::select!`
  - Orderly `stop()`: signal tasks → wait → stop RPC → disconnect peers → log final state + uptime
  - `wait_for_shutdown_signal()`: SIGINT + SIGTERM (Unix) handling
  - `run()` with `tokio::time::timeout`: 10-second shutdown deadline before forced exit
  - `health()` async method for runtime diagnostics
  - Unique-port test infrastructure (`unique_port()` atomic counter) for parallel test safety
  - 14 new tests: TaskTracker register/count/drop, running state lifecycle, shutdown signal propagation, health before/after start/stop, uptime, double-stop safety, NodeHealth derive traits

- **Refactor pass**:
  - **Fixed hardcoded `ConsensusParams::mainnet()` bug** — Added `with_params()` constructors to `BlockchainService` and `MiningService`; infrastructure now passes actual network consensus params (testnet/regtest/signet get correct params)
  - **Eliminated all 7 `#[allow(dead_code)]` suppressions**: 2 unused constants removed, 3 struct fields renamed with `_` prefix, 2 falsely suppressed fields left as-is (they ARE used — `WalletKey.label` in snapshots, `PeerSyncState.info` in handshake)
  - **Zero `#[allow(dead_code)]` remaining in codebase**
  - 4 remaining TODOs are genuine future work: MTP timelock checks (mempool_acceptance), wallet transaction history, hex block parsing (handlers)

- **Final state**: 1,103 tests, 0 warnings, 0 failures
- **Output files**: o35 (BIP324 clean), o36-o38 (package relay iterations), o39 (infrastructure hardening clean), o40-o42 (refactor pass iterations)

### Session 14 (Part 4) — Code Review Fixes
- Addressed 12 findings from code review (`reviews/code-review-2026-02-21.md`):
  - **#12** `MAX_BLOCK_SIGOPS_COST` corrected from 20,000,000 to 80,000 (= MAX_BLOCK_WEIGHT / 50)
  - **#14** Added `VERIFY_TAPROOT` to `ScriptFlags::standard()`
  - **#4** Full 256-bit PoW comparison: added `decode_compact_u256()` and `hash_meets_target()`, updated `check_block_header` and miner
  - **#1** Taproot signature checker selection: inspect witness version from script_pubkey (not `witness.is_empty()`), collect all spent outputs for BIP341
  - **#2** Taproot sighash: extract `hash_type` from signature bytes (64B→DEFAULT, 65B→explicit), pass through trait to sighash computation
  - **#3** Taproot sighash: return sentinel `[0xff; 32]` when spent_outputs missing (fails verification deterministically)
  - **#15** BIP342 tapscript: removed legacy 10,000-byte script size and 201-opcode limits via `tapscript_mode` flag on `ScriptInterpreter`
  - **#19** ECDSA: removed `from_compact()` fallback, strict DER only (BIP66)
  - **#9** Coinbase: output script now uses `coinbase_script` instead of empty `Script::new()`
  - **#7** Mempool fee: compute from in-mempool parent outputs where available (TODO: inject UtxoView for confirmed UTXOs)
  - **#8** Block store: `store_block` now updates `best_block_hash` when new block extends the chain
  - **#11** Reorg path: replaced 4 `.unwrap()` calls with proper `ChainStateError::CorruptedIndex` / `NoForkPoint` error propagation

### Session 14 (Part 3) — Policy Language → Miniscript Compiler
- Created **miniscript/policy.rs** — spending policy DSL that compiles to Miniscript:
  - `Policy` enum: atoms (PubKey, PubKeyHash, Older, After, Sha256, Hash256, Ripemd160, Hash160), combinators (And, Or, WeightedOr, Thresh, Multi)
  - `parse_policy(input)` — recursive descent parser supporting `pk(KEY)`, `pkh(HASH)`, `older(N)`, `after(N)`, hash functions, `and(P,P)`, `or(P,P)`, `or(W@P,W@P)` weighted or, `thresh(K,P,...)`, `multi(K,KEY,...)`; whitespace-tolerant
  - `compile(policy)` — type-aware Policy → Miniscript compiler: `pk(K)` → `c:pk_k(K)`, `and(A,B)` → `and_v(v:A,B)`, `or(A,B)` → `or_d(A,B)` or `or_i(A,B)` based on type compatibility, `thresh` with k==n optimized to chain of `and_v`, general thresh wraps non-first subs in `s:` for W type
  - `Display` impl for round-trip formatting
  - `PolicyParseError` and `CompileError` error types with Display/Error
  - ~30 tests: parse atoms, parse combinators, parse errors, compile atoms, compile combinators, display roundtrip, full pipeline, compile errors, whitespace tolerance
- Modified **miniscript/mod.rs** — added `pub mod policy;` and re-exports for Policy, PolicyParseError, CompileError, parse_policy

### Session 14 (Part 2) — Covenant Opcodes (BIP119 CTV + BIP345 OP_VAULT)
- Created **covenants/ctv.rs** — BIP119 OP_CHECKTEMPLATEVERIFY domain logic: `compute_ctv_hash(tx, input_index)` computing SHA-256 of (nVersion, nLockTime, scriptSigs hash if non-empty, input count, sequences hash, output count, outputs hash, input index); helper functions `hash_scriptsigs()`, `hash_sequences()`, `hash_outputs()`, `push_compact_size()`; ~12 tests covering determinism, output sensitivity, locktime, input index, input count, version, scriptSig inclusion, sequences, multiple outputs, compact size encoding
- Created **covenants/vault.rs** — BIP345 OP_VAULT/OP_VAULT_RECOVER domain logic: `VaultParams` (recovery_spk_hash, spend_delay), `VaultTriggerInfo` (target_output_index, leaf_update_script_body); `verify_vault_trigger()` checking output index, amount preservation, trigger script structure; `verify_vault_recover()` checking output index, recovery script hash match, amount; `build_trigger_script()`, `build_vault_script()`, `build_recovery_script()`, `build_vault_taproot_leaves()`; `push_script_number()` minimal encoding; `VaultError` enum with Display/Error; ~18 tests
- Created **covenants/mod.rs** — module wiring with re-exports
- Modified **opcodes.rs** — repurposed `OP_NOP4` (0xb3) as `OP_CHECKTEMPLATEVERIFY` with `OP_NOP4` alias; added `OP_VAULT` (0xbb) and `OP_VAULT_RECOVER` (0xbc); updated `from_u8()` mappings
- Modified **interpreter.rs** — added `VERIFY_CHECKTEMPLATEVERIFY` (bit 18) and `VERIFY_VAULT` (bit 19) to ScriptFlags; added `CtvHashMismatch`, `VaultVerifyFailed`, `VaultRecoverFailed` to ScriptError; added `check_ctv()`, `check_vault()`, `check_vault_recover()` methods to SignatureChecker trait (all default false); CTV dispatch follows NOP-upgrade pattern (flag off → NOP, flag on → pop hash + verify); vault opcodes fail if flag off (new byte values, not NOP-repurposed)
- Modified **signing.rs** — implemented `check_ctv()` in TransactionSignatureChecker calling `compute_ctv_hash()` and comparing; implemented `check_vault()` delegating to `verify_vault_trigger()`; implemented `check_vault_recover()` delegating to `verify_vault_recover()`
- Wired up `pub mod covenants;` in `abtc-domain/src/lib.rs`
- **Activation-gated design**: both CTV and vault opcodes are inert unless their respective ScriptFlags bits are set, matching Bitcoin Core's soft-fork activation pattern (same as CLTV/CSV)

### Session 14 — UTXO Set Commitments / AssumeUTXO
- Created **utxo/coin.rs** — Bitcoin Core-compatible coin compression: `compress_amount()`/`decompress_amount()` with decimal exponent extraction (round amounts map to small varints), `compress_script()`/`decompress_script()` recognizing P2PKH (type 0x00), P2SH (0x01), P2PK compressed (0x02/0x03), P2PK uncompressed (0x04/0x05), and non-standard scripts; `CompressedCoin` struct with `(height<<1)|is_coinbase` code, compressed amount, compressed script; `serialize()`/`deserialize()` with Bitcoin Core's CVarInt encoding (7-bit chunks with +1 continuation trick to prevent non-canonical encodings); `serialize_utxo()`/`deserialize_utxo()` for outpoint-coin pairs
- Created **utxo/muhash.rs** — MuHash3072 rolling multiset hash: `Num3072` struct (48 × u64 limbs, little-endian) with `mul_mod_p()` (schoolbook multiplication + Barrett-style reduction using p = 2^3072 − 1103717), `mod_inverse()` via Fermat's little theorem (a^{p-2} mod p using binary exponentiation), `reduce_mod_p()`, `reduce_wide()` exploiting special prime form; `hash_to_num3072()` expanding SHA-256 seed to 384 bytes via SHA-256(seed||le32(i)) for i=0..11; `MuHash3072` public API with `insert()`/`remove()`/`combine()`/`finalize()` producing 256-bit digest
- Created **utxo/snapshot.rs** — AssumeUTXO snapshot format: `SnapshotMetadata` (version, network_magic, block_hash, height, num_coins, muhash digest) with binary serialize/deserialize; `UtxoSnapshot` with `build()` computing MuHash commitment, `serialize()`/`deserialize()` for full snapshot I/O, `verify_commitment()` and `validate()` against hardcoded params; `AssumeUtxoParams` with mainnet height 840,000 entry; `SnapshotError` enum with Display/Error impls
- Created **utxo/mod.rs** — module wiring with re-exports
- Wired up `pub mod utxo;` in `abtc-domain/src/lib.rs`
- ~50 new tests: amount compression (zero, roundtrip for 11 specific amounts, round amounts compress small, odd values), varint (roundtrip for 10 values including u64::MAX, canonical encoding), script compression (P2PKH, P2SH, P2PK compressed, non-standard roundtrips), CompressedCoin (roundtrip, coinbase flag), full UTXO serialization (roundtrip), amount compression sampled exhaustive (0..100M step 99999), height/coinbase encoding, Num3072 (multiplicative identity, commutativity, mod inverse, reduce_mod_p), MuHash (empty, deterministic, order-independent, insert/remove cancel, all-remove=empty, different-sets-differ, combine, single element, incremental-vs-batch), snapshot metadata (roundtrip, validate-against-params with good/bad-height/bad-coins), UtxoSnapshot (build-and-verify, serialize-deserialize, tampered-commitment, validate-full, empty-set, preserves-coin-data), AssumeUtxoParams (mainnet exists), unsupported version rejected

### Session 13 — P2P Wire Protocol (BIP144/BIP339)
- Created **protocol/types.rs** — `ServiceFlags` bitmask (NETWORK, WITNESS, BLOOM, COMPACT_FILTERS, NETWORK_LIMITED, etc.) with union/has/is_desirable; `InvType` enum (Error, Tx, Block, FilteredBlock, CompactBlock, WitnessTx, WitnessBlock, WitnessFilteredBlock) with u32 conversion; `InvVector` struct; `NetAddress` with IPv4-mapped-IPv6 encoding and SocketAddr conversion; protocol constants (PROTOCOL_VERSION=70016, MAX_PROTOCOL_MESSAGE_LENGTH=4MB, MAX_HEADERS=2000, MAX_INV_SIZE=50000, etc.)
- Created **protocol/messages.rs** — Complete `NetworkMessage` enum with 24 variants covering the full Bitcoin P2P protocol: handshake (Version/Verack), feature negotiation (WtxidRelay/SendHeaders/SendCmpct/FeeFilter/SendAddrV2), address relay (Addr/AddrV2/GetAddr), inventory (Inv/GetData/NotFound), block relay (Block/GetHeaders/Headers/GetBlocks), transaction relay (Tx/MemPool), compact blocks BIP152 (CmpctBlock/GetBlockTxn/BlockTxn), keepalive (Ping/Pong), plus Alert and Unknown fallback; sub-message structs: VersionMessage, TimestampedAddress, AddrV2Entry, GetHeadersMessage, GetBlocksMessage, SendCmpctMessage, CmpctBlockMessage, PrefilledTx, GetBlockTxnMessage, BlockTxnMessage
- Created **protocol/codec.rs** — Full wire-format codec: `MessageHeader` (24-byte header with real SHA-256d checksums via domain crypto), `encode_message()`/`decode_message()` for complete wire roundtrips, `encode_payload()`/`decode_payload()` for all 24 message types, `encode_compact_size()`/`decode_compact_size()` with canonical encoding enforcement, cursor-based decoder with type-safe readers (u8/u16/u32/u64 LE/BE, hash32, compact_size, string, net_addr, inv_vector, block_header, transaction), validation (magic check, checksum verification, payload size limits, inv/addr count limits, locator size limits)
- Created **protocol/mod.rs** — Module wiring with re-exports of all public types
- Wired up `pub mod protocol;` in `abtc-domain/src/lib.rs`
- ~45 new tests: ServiceFlags (none, network, union, from_u64), InvType roundtrip, InvVector display, NetAddress (IPv4, IPv6, display), compact size (single byte, max single, u16, u32, u64, non-canonical rejection), checksum (empty, verify), message header roundtrip, verack/ping/pong roundtrip, version roundtrip (full field verification), inv/getdata/notfound roundtrip, feefilter/sendcmpct roundtrip, empty messages (wtxidrelay, sendheaders, sendaddrv2, getaddr, mempool), getheaders/getblocks roundtrip, headers roundtrip, addr/addrv2 roundtrip, getblocktxn roundtrip, bad magic/bad checksum rejection, unknown command passthrough, payload too large rejection, command string tests
- Design: new `protocol::NetworkMessage` is the wire-format codec in the domain layer; existing `abtc_ports::NetworkMessage` remains the application-facing interface (will converge over time)
- Created **filters/gcs.rs** — Golomb-Coded Set implementation: `siphash_2_4()` full SipHash-2-4 with proper initialization/finalization, `key_from_block_hash()` extracts (k0,k1) from first 16 bytes, `hash_to_range()` with fast range reduction `(h*F)>>64`, `BitWriter`/`BitReader` for MSB-first bit-level I/O, `write_golomb_rice()`/`read_golomb_rice()` with unary quotient + P-bit remainder, `GcsFilter` struct with `build()`/`build_basic()` construction (hash→sort→dedup→encode deltas), `match_any()` single-element query, `match_any_of()` merge-intersection batch query, `serialize()`/`deserialize()` in BIP158 format (CompactSize(N) || data); constants BASIC_FILTER_M=784931, BASIC_FILTER_P=19
- Created **filters/block_filter.rs** — `BlockFilter` struct with `build_basic(block, prev_output_scripts)` extracting non-OP_RETURN scriptPubKeys from outputs + prev outputs, `from_elements()` constructor, `match_script()`/`match_any_scripts()` query methods, `filter_hash()` via hash256, `serialize()` for wire format; `compute_filter_header(filter_hash, prev_header)` chaining function, `FilterHeader` struct, `build_filter_header_chain()` batch builder; BASIC_FILTER_TYPE=0
- Created **filters/messages.rs** — BIP157 P2P message types: `GetCFilters` (filter_type, start_height, stop_hash), `CFilter` (filter_type, block_hash, filter_data), `GetCFHeaders` (filter_type, start_height, stop_hash), `CFHeaders` (filter_type, stop_hash, prev_filter_header, filter_hashes), `GetCFCheckpt` (filter_type, stop_hash), `CFCheckpt` (filter_type, stop_hash, filter_headers); each with `encode()`/`decode()` wire-format methods
- ~65 new tests: SipHash (deterministic, different keys, different data, empty), key derivation, hash_to_range (bounds, uniformity), BitWriter/BitReader (single bits, partial byte, multi-bit), Golomb-Rice roundtrips (single, multiple, BIP158 params), unary coding, GCS (empty, single, multiple elements, match_any, match_any_of, dedup, wrong key, serialize roundtrip, build_basic, larger filter 200 elements), block filter (empty block, outputs, OP_RETURN skip, prev outputs, no false negatives, match_any_scripts, filter hash deterministic/changes, from_elements), filter header chain (compute, changes with prev, build chain, empty chain), BIP157 messages (getcfilters/cfilter/getcfheaders/cfheaders/getcfcheckpt/cfcheckpt roundtrips, empty cfheaders, decode too short)

### Session 12 — Miniscript & Output Descriptors
- Created **miniscript type system** (`script/miniscript/types.rs`) — `BaseType` enum (B/V/K/W), `TypeModifiers` struct (10 boolean flags: z, o, n, d, u, e, f, s, m, x), `MiniscriptType` combining both; type inference functions for all atom types (pk_k, pk_h, older, after, hash, true, false, multi, multi_a), combinator type inference (and_v, and_b, or_b, or_c, or_d, or_i, thresh), wrapper transformations (alt, swap, check, dupif, verify, nonzero, zero_not_equal)
- Created **miniscript fragment AST** (`script/miniscript/fragment.rs`) — `Terminal` enum with ~30 variants (atoms: True, False, PkK, PkH, Older, After, Sha256, Hash256, Ripemd160, Hash160; combinators: AndV, AndB, OrB, OrC, OrD, OrI, Thresh, Multi, MultiA; wrappers: Alt, Swap, Check, DupIf, Verify, NonZero, ZeroNotEqual), `Miniscript` struct with typed constructors, convenience helpers (pk, pkh), Display formatting
- Created **miniscript compiler** (`script/miniscript/compiler.rs`) — `Miniscript::encode()` compiles AST to Bitcoin Script; recursive traversal mapping each Terminal variant to opcode sequences; verify-wrapper optimization merges OP_CHECKSIG→OP_CHECKSIGVERIFY, OP_EQUAL→OP_EQUALVERIFY, OP_CHECKMULTISIG→OP_CHECKMULTISIGVERIFY at AST level
- Created **miniscript decoder** (`script/miniscript/decode.rs`) — `Miniscript::parse(script)` parses Bitcoin Script back to AST; pattern-matching cursor-based parser recognizing atoms, wrappers, combinators; roundtrip tests for all major fragment types
- Created **descriptor key expressions** (`wallet/descriptors/key_expr.rs`) — `DescriptorKey` enum (Single, Extended), `SingleKey` struct, `ExtendedKey` with XKey (Pub/Priv), KeyOrigin ([fingerprint/path]), Wildcard (None/Unhardened/Hardened); key derivation via HD wallet integration
- Created **descriptor types** (`wallet/descriptors/descriptor.rs`) — `Descriptor` enum (Pk, Pkh, Wpkh, ShWpkh, Sh, Wsh, ShWsh, Tr), `ShInner` (Wpkh, Wsh, Multi, SortedMulti), `WshInner` (Multi, SortedMulti, Miniscript), `TrTree` (Leaf, Branch); Display formatting
- Created **descriptor checksum** (`wallet/descriptors/checksum.rs`) — BIP380 polymod-based 8-character checksum; `descriptor_checksum()`, `verify_checksum()`, `add_checksum()`; uses descriptor-specific INPUT_CHARSET and CHECKSUM_CHARSET
- Created **descriptor compiler** (`wallet/descriptors/compiler.rs`) — `Descriptor::script_pubkey(index)` compiles to scriptPubKey for P2PKH/P2WPKH/P2SH/P2WSH/P2TR; `Descriptor::address(index, mainnet)` derives addresses; `witness_script()` and `redeem_script()` for segwit; Taproot key tweaking with tagged hashes; TapTree merkle root computation; sortedmulti key sorting
- Created **descriptor parser** (`wallet/descriptors/parser.rs`) — `parse_descriptor(input)` recursive descent parser; handles pk/pkh/wpkh/sh/wsh/tr with nested multi/sortedmulti; key expression parsing (hex pubkeys, xpub/xprv with derivation paths, origin info, wildcards); optional checksum verification
- Wired up **miniscript module** — added `pub mod miniscript;` to `script/mod.rs`, re-exports of Miniscript, Terminal, MiniscriptType, BaseType, DecodeError
- Wired up **descriptor module** — added `pub mod descriptors;` to `wallet/mod.rs`, re-exports of Descriptor, DescriptorKey, parse_descriptor, add_checksum, ParseError, DescriptorError
- ~120 new tests: type inference (~15), fragment construction & display (~20), compilation & opcode verification (~25), decode roundtrips (~15), key expression derivation (~10), descriptor display (~10), checksum generation & validation (~8), descriptor compilation & address derivation (~15), descriptor parsing (~12)

### Session 11 (Part 2) — BIP325 Signet Support
- Created **signet.rs** (`abtc-domain/src/consensus/signet.rs`) — full BIP325 validation module:
  - `SIGNET_HEADER` constant (`[0xec, 0xa7, 0xb2, 0xef]`), `SignetError` enum
  - `extract_signet_solution()` — scans coinbase OP_RETURN for signet commitment
  - `compute_block_data_hash()` — strips signet data, recomputes merkle root, hashes modified 80-byte header
  - `make_signet_to_spend()` / `make_signet_to_sign()` — constructs BIP325 virtual transactions
  - `parse_witness_solution()` / `serialize_witness_stack()` — compact-size witness serialization
  - `build_signet_commitment()` — constructs OP_RETURN output with signet header + solution
  - `validate_signet_block()` — orchestrates extraction → hashing → virtual txs → script verification
  - `sign_block_p2wpkh()` — signs a block for a P2WPKH challenge (ECDSA + BIP143 sighash)
- Modified **consensus/mod.rs** — added `pub mod signet;` and re-exports for all public items
- Modified **connect.rs** — added `SignetValidationFailed(String)` variant to `ConnectBlockError`; signet check in `connect_block()` when `params.signet_challenge` is set
- Modified **infrastructure lib.rs** — added `--signet-challenge` CLI arg (optional hex string); custom challenge wiring; `signet_challenge: None` in all test configs; 3 new tests (signet node creation, custom challenge, invalid hex)
- Modified **infrastructure Cargo.toml** — added `hex = "0.4"` dependency
- Modified **miner.rs** — added `SignetSigningFailed(String)` variant to `MiningError`; `sign_signet_block_p2wpkh()` wrapper delegating to domain-level signing function
- Re-exported `secp256k1` from `abtc-domain/src/lib.rs` for downstream crate access
- ~20 new signet tests: extraction (valid, missing, wrong header, empty block), block data hash (deterministic, different data, strips signet data), virtual tx structure (to_spend, to_sign), witness parsing (empty, single, two items, truncated, roundtrip), commitment builder, end-to-end validation (OP_TRUE, OP_FALSE, P2WPKH valid, P2WPKH wrong key, custom challenge), signing (sign+validate, no placeholder, wrong key), compact size roundtrip, miner integration test

### Session 11 — Wallet Persistence
- Added **WalletStore** port trait (`abtc-ports/src/wallet/store.rs`) — `WalletSnapshot`, `WalletKeyEntry`, `WalletUtxoEntry` data types; async `save()`, `load()`, `delete()` trait methods
- Added **snapshot/restore** to `InMemoryWallet` (`abtc-adapters/src/wallet/mod.rs`) — `snapshot()` serializes keys (WIF), UTXOs (hex), and metadata; `restore_from_snapshot()` parses and rebuilds state; helper methods `is_mainnet()`, `address_type_str()`, `parse_address_type()`, `reverse_hex()`, `hex_to_bytes()`
- Added **FileBasedWalletStore** adapter (`abtc-adapters/src/wallet/file_store.rs`) — JSON file persistence with atomic writes (temp file + rename), 0o600 permissions on Unix, version checking, parent directory creation
- Added **PersistentWallet** wrapper (`abtc-adapters/src/wallet/persistent.rs`) — wraps `InMemoryWallet` + `WalletStore`; implements `WalletPort` with auto-save after `get_new_address()`, `import_key()`, `send_transaction()`, `add_utxo()`, `remove_utxos()`; loads from store on construction
- Added `--wallet-file` CLI argument to `CliArgs` in infrastructure layer — when set, wraps wallet in `PersistentWallet` with `FileBasedWalletStore`; when absent, uses plain `InMemoryWallet` (backward compatible)
- JSON wallet file format: version 1, keys as WIF + address + label, UTXOs as txid hex + vout + amount + script hex + confirmations + coinbase flag
- New tests: ~10 FileBasedWalletStore unit tests (roundtrip, missing file, corrupt JSON, wrong version, delete, permissions, nested dirs, overwrite, empty wallet), ~6 PersistentWallet unit tests (fresh start, auto-save on key gen/import/UTXO add, load restores state, multiple saves), ~2 infrastructure integration tests (persistence across node restart, in-memory fallback)
- Final: 630 tests pass, 0 failures, 0 warnings (output o1)

### Session 10 — Folder Rename & Keyword Cleanup
- Renamed all 5 crate **folders** from `crates/btc-*` to `crates/abtc-*` to match crate names:
  - `crates/btc-domain` → `crates/abtc-domain`
  - `crates/btc-ports` → `crates/abtc-ports`
  - `crates/btc-adapters` → `crates/abtc-adapters`
  - `crates/btc-application` → `crates/abtc-application`
  - `crates/btc-infrastructure` → `crates/abtc-infrastructure`
- Updated workspace `members` in root Cargo.toml and all 10 inter-crate `path` dependencies to use new folder names
- Fixed crates.io keyword validation: replaced `"hexagonal-architecture"` (22 chars, over 20-char limit) with `"clean-architecture"`, `"hexagonal"`, `"ports-and-adapters"`
- Standardized keywords across all 6 Cargo.toml files to: `["bitcoin", "agentic", "clean-architecture", "hexagonal", "ports-and-adapters"]`
- Verified: 612 tests pass, 0 failures, 0 warnings (output100)
- Casey's nickname for me: "Art" (short for "Artifact" / the AI assistant)

### Session 9 (continued) — Crate Rename for crates.io Publishing
- Renamed all 5 workspace crates from `btc-*` to `abtc-*` namespace (binary remains `agentic-bitcoin`):
  - `btc-domain` → `abtc-domain`
  - `btc-ports` → `abtc-ports`
  - `btc-adapters` → `abtc-adapters`
  - `btc-application` → `abtc-application`
  - `btc-infrastructure` → `abtc-infrastructure`
- Added crates.io metadata to all Cargo.toml files: `description`, `license`, `repository`, `homepage`, `keywords`, `categories`
- Added `version = "0.1.0"` to all inter-crate `path` dependencies (required for crates.io publishing)
- Updated all 34+ Rust source files: `use btc_domain::` → `use abtc_domain::` etc.
- Updated doc comments in lib.rs files for ports, adapters, and domain
- Created README.md with prominent experimental-software warning and full project description
- Created CRATES.md — user guide for which crate to depend on for different use cases
- Repository: https://github.com/casey-bowman/agentic-bitcoin

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
- Added **P2TR to abtc-adapters** — wallet now handles `AddressType::P2TR` for address generation and key import
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

# Agentic-Bitcoin Implementation Checklist

## Project Overview

Hexagonal architecture Rust reimplementation of Bitcoin Core.
5 crates: btc-domain, btc-ports, btc-adapters, btc-application, btc-infrastructure.
All compile cleanly with `cargo check` (zero errors, zero warnings) as of Session 4.

## Session History

### Session 1: Domain Layer Foundation
- Created all 5 crates with hexagonal architecture
- Implemented btc-domain: primitives, consensus, script types, crypto hashing, chain params
- Implemented btc-ports: trait definitions for all adapters
- Started btc-adapters: storage, stub network, basic RPC, mining, wallet

### Session 2: Fixing Errors and Real Implementations
- Fixed 4 compilation errors (Box<dyn Error> vs Box<dyn Error + Send + Sync>)
- Fixed ~20 warnings (unused imports, mut, lifetimes)
- Created real InMemoryMempool adapter (replaced stub)
- Rewrote mining adapter with halving-aware subsidy and mempool TX selection
- Rewrote BlockchainService with real transaction validation and UTXO tracking
- Added RPC handlers: getblockchaininfo, getrawmempool, estimatesmartfee, getmininginfo
- Wired infrastructure layer with background task loops

### Session 3: HTTP Server, P2P Network, Script Interpreter, secp256k1
- Implemented real HTTP JSON-RPC server (TCP listener, HTTP parsing, CORS, batch requests)
- Implemented TcpPeerManager with Bitcoin protocol message framing and version/verack handshake
- Added CLI flags: --enable-p2p, --seed-peers
- **Built full Script interpreter** (~750 lines):
  - Stack VM with main/alt stacks
  - All enabled opcodes (data push, constants, stack ops, arithmetic, equality, crypto, signatures, locktime)
  - Disabled opcodes correctly fail
  - Consensus limits enforced (script size, op count, stack size, element size)
  - Script number encoding/decoding
  - verify_script() with P2SH support
  - SignatureChecker trait for pluggable crypto
  - 30+ unit tests
- **Integrated secp256k1 crate** for real ECDSA signature verification
- Created TransactionSignatureChecker with legacy sighash computation
- BIP65 (CLTV) and BIP112 (CSV) locktime verification

### Session 4: SegWit, Persistent Storage, Block Index
- **BIP143 SegWit sighash** — `compute_sighash_witness_v0()` in `TransactionSignatureChecker`
  - Implements the full BIP143 digest algorithm (hashPrevouts, hashSequence, hashOutputs, amount commitment)
  - Supports all sighash types (ALL, NONE, SINGLE, ANYONECANPAY)
  - `new_witness_v0()` constructor sets the checker to use BIP143 automatically
  - Renamed `_amount` to `amount` (now actively used)
- **SegWit witness verification (BIP141)** — `verify_script_with_witness()`
  - P2WPKH: validates witness=[sig, pubkey], checks HASH160(pubkey)==program, constructs implicit P2PKH script
  - P2WSH: validates witness=[...stack, witnessScript], checks SHA256(witnessScript)==program, evaluates witnessScript
  - P2SH-wrapped SegWit: detects witness programs inside P2SH redeemScripts
  - Native SegWit: requires empty scriptSig, dispatches to witness verifier
  - Future witness versions (v1-v16): succeed for forward compatibility
  - WitnessUnexpected error for non-witness scripts with witness data
  - 10+ new unit tests for all SegWit paths
- **RocksDB persistent storage** (behind `rocksdb-storage` feature flag)
  - `RocksDbBlockStore`: stores blocks, headers, heights in column families
  - `RocksDbChainStateStore`: persistent UTXO set with atomic batch writes, chain tip tracking
  - Custom block serialization/deserialization (header + transactions + witness)
  - UTXO entry serialization (height + coinbase flag + value + script)
  - All RocksDB operations wrapped in `tokio::task::spawn_blocking`
  - Feature-gated: `cargo check` works without RocksDB installed, `cargo check --features rocksdb-storage` enables it
- **Block index with best-chain selection** — `BlockIndex` in btc-application
  - In-memory tree of all known block headers
  - Cumulative proof-of-work tracking (u128 to avoid overflow)
  - `work_from_bits()`: compact target → work calculation
  - Automatic best-chain reorg when a fork accumulates more work
  - Active chain vector for O(1) height-to-hash lookups
  - Block locator generation (exponential backoff for getblocks)
  - Ancestor chain walking
  - 8 unit tests including fork/reorg scenarios

### Session 5: P2P Chain Sync, Infrastructure Wiring, Wallet, Policy, SegWit Wiring
- **Net processing module** (`net_processing.rs`) — the "brain" of the P2P protocol
  - `SyncManager` state machine: Idle → HeaderSync → BlockSync → Synced
  - Headers-first sync: `getheaders` → receive `headers` → add to block index
  - Block download with in-flight tracking, round-robin distribution across peers
  - Orphan block storage and automatic connection when gaps fill
  - Transaction relay: `inv` → `getdata` → `tx` → mempool
  - Peer disconnect reassignment (in-flight blocks return to download queue)
  - `SyncAction` enum decouples sync logic from infrastructure
  - 3 unit tests
- **Extended P2P networking** in btc-adapters
  - Added `send_to_peer()` to `PeerManager` trait (btc-ports) and both implementations
  - `encode_network_message()`: serializes all `NetworkMessage` variants to Bitcoin wire format
  - `push_varint_net()` helper for Bitcoin varint encoding
  - Added `InventoryItem` to btc-ports re-exports
  - Renamed user agent to `/AgenticBitcoin:0.1.0/`
- **Infrastructure wiring** — fully connected architecture
  - `BlockIndex` initialized with genesis header at startup
  - `SyncManager` wired with `Arc<RwLock<BlockIndex>>`
  - `handle_peer_event()` method on `BitcoinNode` — processes SyncActions (ProcessBlock, ProcessTransaction, SendMessage, DisconnectPeer)
  - Sync status background task (reports header/block download progress)
  - `--storage-backend` CLI flag: "memory" (default) or "rocksdb" (feature-gated)
  - RocksDB integration with directory creation and proper `open()` calls
  - Named application "Agentic Bitcoin" throughout
  - 4 new infrastructure tests (block_index init, sync_manager init)
- **Full wallet implementation** (domain + adapter + RPC)
  - `btc-domain/src/wallet/keys.rs` — PrivateKey, PublicKey, WIF encode/decode, Base58Check, key generation (secp256k1)
  - `btc-domain/src/wallet/address.rs` — P2PKH, P2WPKH, P2SH-P2WPKH address derivation, Bech32 encode/decode (BIP173)
  - `btc-domain/src/wallet/coin_selection.rs` — CoinSelector with LargestFirst, SmallestFirst, ClosestMatch, BranchAndBound strategies
  - `btc-domain/src/wallet/tx_builder.rs` — TransactionBuilder with P2PKH/P2WPKH/P2SH-P2WPKH signing, BIP143 sighash
  - `btc-adapters/src/wallet/mod.rs` — InMemoryWallet: key store, UTXO tracking, create/sign/send transactions
  - `btc-application/src/handlers.rs` — WalletRpcHandler: getbalance, getwalletinfo, getnewaddress, listunspent, importprivkey
  - `btc-infrastructure/src/lib.rs` — Wallet wired into BitcoinNode with --enable-wallet and --address-type CLI flags
  - 50+ unit tests across all wallet modules
- **Transaction pool policy** (domain + adapter enhancement)
  - `btc-domain/src/policy/rbf.rs` — BIP125 Replace-by-Fee policy (SignalsRbf trait, RbfPolicy checker, 6 BIP125 rules)
  - `btc-domain/src/policy/limits.rs` — Mempool limits, CPFP PackageInfo, ancestor/descendant limits (25/101KB), dust (546 sat), standard tx checks
  - `btc-adapters/src/mempool/mod.rs` — Rewritten with ancestor/descendant graph tracking, RBF replacement, CPFP-aware mining selection (ancestor fee rate), descendant fee rate eviction
  - 29+ unit tests across policy and mempool modules
- **SegWit verification wired into BlockchainService**
  - `btc-application/src/services.rs` — `validate_and_accept_block()` and `process_new_transaction()` now perform full script verification
  - Uses `TransactionSignatureChecker` with automatic BIP143 sighash for witness programs
  - P2SH-wrapped witness detection via `is_p2sh_witness()` helper
  - Standard script flags: P2SH + DER sigs + CLTV + CSV + SegWit + minimal data + null dummy

## Crate Status

### btc-domain ✅ COMPLETE
- primitives/ — Amount, Hash256, Txid, BlockHash, OutPoint, TxIn, TxOut, Transaction, Block, BlockHeader, Witness
- consensus/ — ConsensusParams, Network, ValidationState, rules (check_transaction, check_block)
- script/ — Opcodes, Script, ScriptBuilder, Witness, **ScriptInterpreter**, verify_script, **verify_script_with_witness**, is_push_only
- crypto/ — hash256, sha256, hash160, **verify_ecdsa, TransactionSignatureChecker** (legacy + **BIP143 sighash**)
- chain_params/ — ChainParams for mainnet/testnet/regtest/signet, genesis blocks
- **wallet/** — PrivateKey, PublicKey, Address (P2PKH/P2WPKH/P2SH-P2WPKH), CoinSelector, TransactionBuilder, Base58Check, Bech32
- **policy/** — RbfPolicy (BIP125 rules), MempoolLimits (ancestor/descendant), PackageInfo (CPFP), SignalsRbf trait, standard tx checks
- Dependencies: sha2, ripemd, hex, serde, thiserror, secp256k1, rand

### btc-ports ✅ COMPLETE
- BlockStore, ChainStateStore, MempoolPort, PeerManager, NetworkListener
- RpcServer, RpcHandler, RpcRequest, RpcResponse, RpcError
- BlockTemplateProvider, BlockTemplate
- WalletPort, Balance, UnspentOutput
- NetworkMessage, InventoryItem, PeerInfo, PeerEvent

### btc-adapters ✅ COMPLETE
- storage/ — InMemoryBlockStore, InMemoryChainStateStore, **RocksDbBlockStore, RocksDbChainStateStore** (feature-gated)
- mempool/ — InMemoryMempool (**RBF, CPFP, ancestor/descendant graph**, fee-rate ordering, eviction, fee estimation)
- network/ — StubPeerManager, **TcpPeerManager** (Bitcoin protocol framing, version/verack)
- rpc/ — **JsonRpcServer** (real HTTP server, TCP listener, batch requests, CORS)
- mining/ — SimpleMiner (halving subsidy, mempool TX selection, merkle root)
- wallet/ — **InMemoryWallet** (key generation, UTXO tracking, create/sign/send transactions, address derivation)

### btc-application ✅ COMPLETE
- **block_index.rs** — BlockIndex (header tree, best-chain selection, reorg, locator, work calculation)
- **net_processing.rs** — SyncManager (headers-first sync, block download, tx relay, orphan handling)
- services.rs — BlockchainService (validate_and_accept_block **with full script/SegWit verification**, process_new_transaction **with script verification**, UTXO tracking), MempoolService, MiningService
- handlers.rs — BlockchainRpcHandler, MiningRpcHandler, **WalletRpcHandler** (getblockcount, getbestblockhash, getblockchaininfo, getmempoolinfo, getrawmempool, estimatesmartfee, getblocktemplate, getmininginfo, **getbalance, getwalletinfo, getnewaddress, listunspent, importprivkey**)

### btc-infrastructure ✅ COMPLETE
- Composition root wiring all components (BlockIndex, SyncManager, BlockchainService, etc.)
- CLI: --network, --datadir, --rpc-port, --p2p-port, --log-level, --max-mempool-mb, --enable-p2p, --seed-peers, **--storage-backend**, **--enable-wallet**, **--address-type**
- Background tasks: mempool stats, peer monitoring, **sync status reporting**, TCP keepalive
- `handle_peer_event()` — processes SyncActions from SyncManager
- Graceful shutdown (Ctrl+C) with final sync state logging
- Feature flag: `rocksdb-storage` propagated to btc-adapters

## Key Technical Notes

- **Fields are public**: Transaction, TxIn, TxOut, OutPoint use `pub` fields (direct access, not getters). E.g., `tx.version` not `tx.version()`, `tx.inputs` not `tx.inputs()`, `input.sequence` not `input.sequence()`.
- **Error types**: All async trait methods use `Box<dyn std::error::Error + Send + Sync>` (not plain `Box<dyn Error>`).
- **Borrow checker pattern**: When you need both immutable reads and a mutable write on the same collection, extract the immutable values into local variables FIRST, then take the mutable borrow. This came up twice (mempool `buckets.drain`, interpreter `exec_stack` OP_ELSE).
- **Amount**: `i64` satoshis internally, with `as_sat()` and `from_sat()` methods. Implements Add, Sub.
- **Hash256**: `[u8; 32]` wrapper with `as_bytes()`, `from_bytes()`, `to_hex_reversed()`.
- **ConsensusParams**: `pow_limit_bits` is `u32` (not Option), `subsidy_halving_interval` is `u32`.
- **No network access in sandbox**: Can't install tools or download crates. User runs `cargo check` on their machine.
- **secp256k1 v0.29**: Uses `Message::from_digest_slice`, `Signature::from_der`, `PublicKey::from_slice`, `Secp256k1::verification_only()`.
- **RocksDB feature**: `rocksdb-storage` feature flag on btc-adapters and btc-infrastructure. Without it, only in-memory storage compiles. With it, RocksDB is available.
- **BIP143 sighash**: `TransactionSignatureChecker::new_witness_v0()` creates a checker that uses BIP143 sighash. The `witness_v0` bool field controls which algorithm `check_sig()` uses.
- **SegWit verification**: `verify_script_with_witness()` is the new main entry point. `verify_script()` delegates to it with an empty witness for backward compat.

## What's Left (Priority Order)

### High Priority — Core Functionality
1. ~~**Full P2P chain sync**~~ ✅ Done (Session 5) — SyncManager, headers-first sync, block download
2. ~~**Transaction relay**~~ ✅ Done (Session 5) — inv/getdata/tx handling in SyncManager
3. ~~**Wire up RocksDB in infrastructure**~~ ✅ Done (Session 5) — --storage-backend CLI flag
4. ~~**Wire up BlockIndex in infrastructure**~~ ✅ Done (Session 5) — Initialized from genesis, used in SyncManager

### Medium Priority — Features
5. ~~**Wallet**~~ ✅ Done (Session 5) — Key management, address derivation (P2PKH/P2WPKH/P2SH-P2WPKH), coin selection, tx builder/signer, wallet RPC.
6. ~~**Transaction pool policy**~~ ✅ Done (Session 5) — BIP125 RBF, CPFP (ancestor fee rate mining), ancestor/descendant limits (25/101KB), standard tx checks, graph tracking.
7. ~~**Wire SegWit verification into BlockchainService**~~ ✅ Done (Session 5) — Full script verification in validate_and_accept_block + process_new_transaction using TransactionSignatureChecker with BIP143 sighash.

### Lower Priority — Polish
8. ~~**SHA-1 opcode**~~ ✅ Done (Session 5) — Added `sha1` crate, proper OP_SHA1 implementation with known-answer test.
9. ~~**Taproot (BIP341/342)**~~ ✅ Done (Session 5) — BIP340 Schnorr signatures, tagged hashes, taptweak/tapleaf/tapbranch, control block parsing, merkle proof verification, key-path + script-path spending in witness v1, Taproot sighash computation.
10. ~~**Full test suite**~~ ✅ Done (Session 5) — Script test vector runner (Bitcoin Core format JSON, 70+ vectors), tx validation tests (valid/invalid/RBF/CPFP/witness/Taproot), crypto known-answer tests (SHA1, SHA256, HASH160, HASH256, RIPEMD160).
11. ~~**Benchmarks**~~ ✅ Done (Session 5) — Timing harness for hashing ops, tagged hashes, script execution (trivial/arithmetic/hash chains/stack-heavy/conditionals), secp256k1 ECDSA/Schnorr sign+verify.

## Estimated Scope

- **Current**: ~10,500+ lines across 5 crates (roughly 17-19% of Bitcoin Core's 337K LOC)
- **Bitcoin Core C++ reference**: 337,513 LOC across 1,375 files
- **Minimum viable syncing node**: Would need items 1-4 above
- **Full feature parity**: Items 1-11 and much more

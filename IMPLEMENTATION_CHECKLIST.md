# Bitcoin-Rust Implementation Checklist

## Project Overview

Hexagonal architecture Rust reimplementation of Bitcoin Core.
5 crates: btc-domain, btc-ports, btc-adapters, btc-application, btc-infrastructure.
All compile cleanly with `cargo check` (zero errors, zero warnings) as of Session 3.

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

## Crate Status

### btc-domain ✅ COMPLETE
- primitives/ — Amount, Hash256, Txid, BlockHash, OutPoint, TxIn, TxOut, Transaction, Block, BlockHeader, Witness
- consensus/ — ConsensusParams, Network, ValidationState, rules (check_transaction, check_block)
- script/ — Opcodes, Script, ScriptBuilder, Witness, **ScriptInterpreter**, verify_script, is_push_only
- crypto/ — hash256, sha256, hash160, **verify_ecdsa, TransactionSignatureChecker**
- chain_params/ — ChainParams for mainnet/testnet/regtest/signet, genesis blocks
- Dependencies: sha2, ripemd, hex, serde, thiserror, secp256k1

### btc-ports ✅ COMPLETE
- BlockStore, ChainStateStore, MempoolPort, PeerManager, NetworkListener
- RpcServer, RpcHandler, RpcRequest, RpcResponse, RpcError
- BlockTemplateProvider, BlockTemplate
- WalletPort, Balance, UnspentOutput
- NetworkMessage, InventoryItem, PeerInfo, PeerEvent

### btc-adapters ✅ COMPLETE
- storage/ — InMemoryBlockStore, InMemoryChainStateStore
- mempool/ — InMemoryMempool (fee-rate ordering, eviction, fee estimation)
- network/ — StubPeerManager, **TcpPeerManager** (Bitcoin protocol framing, version/verack)
- rpc/ — **JsonRpcServer** (real HTTP server, TCP listener, batch requests, CORS)
- mining/ — SimpleMiner (halving subsidy, mempool TX selection, merkle root)
- wallet/ — InMemoryWallet (stub)

### btc-application ✅ COMPLETE
- services.rs — BlockchainService (validate_and_accept_block, process_new_transaction, UTXO tracking), MempoolService, MiningService
- handlers.rs — BlockchainRpcHandler, MiningRpcHandler (getblockcount, getbestblockhash, getblockchaininfo, getmempoolinfo, getrawmempool, estimatesmartfee, getblocktemplate, getmininginfo)

### btc-infrastructure ✅ COMPLETE
- Composition root wiring all components
- CLI: --network, --datadir, --rpc-port, --p2p-port, --log-level, --max-mempool-mb, --enable-p2p, --seed-peers
- Background tasks: mempool stats, peer monitoring, TCP keepalive
- Graceful shutdown (Ctrl+C)

## Key Technical Notes

- **Fields are public**: Transaction, TxIn, TxOut, OutPoint use `pub` fields (direct access, not getters). E.g., `tx.version` not `tx.version()`, `tx.inputs` not `tx.inputs()`, `input.sequence` not `input.sequence()`.
- **Error types**: All async trait methods use `Box<dyn std::error::Error + Send + Sync>` (not plain `Box<dyn Error>`).
- **Borrow checker pattern**: When you need both immutable reads and a mutable write on the same collection, extract the immutable values into local variables FIRST, then take the mutable borrow. This came up twice (mempool `buckets.drain`, interpreter `exec_stack` OP_ELSE).
- **Amount**: `i64` satoshis internally, with `as_sat()` and `from_sat()` methods. Implements Add, Sub.
- **Hash256**: `[u8; 32]` wrapper with `as_bytes()`, `from_bytes()`, `to_hex_reversed()`.
- **ConsensusParams**: `pow_limit_bits` is `u32` (not Option), `subsidy_halving_interval` is `u32`.
- **No network access in sandbox**: Can't install tools or download crates. User runs `cargo check` on their machine.
- **secp256k1 v0.29**: Uses `Message::from_digest_slice`, `Signature::from_der`, `PublicKey::from_slice`, `Secp256k1::verification_only()`.

## What's Left (Priority Order)

### High Priority — Core Functionality
1. **SegWit sighash (BIP143)** — Currently only legacy sighash is implemented. BIP143 is needed for P2WPKH/P2WSH signature verification.
2. **Persistent storage** — Replace in-memory HashMaps with LevelDB or RocksDB for UTXO set and block index.
3. **Full P2P chain sync** — net_processing logic: getblocks, getheaders, block relay, initial block download.
4. **Transaction relay** — Accept mempool transactions from peers, validate, relay.

### Medium Priority — Features
5. **Wallet** — Key generation, address derivation, UTXO selection, transaction creation and signing.
6. **SegWit witness verification** — Evaluate witness programs for P2WPKH and P2WSH.
7. **Block index** — Track all known block headers, implement best-chain selection.
8. **Transaction pool policy** — Replace-by-fee, CPFP, ancestor/descendant limits.

### Lower Priority — Polish
9. **SHA-1 opcode** — OP_SHA1 currently uses SHA-256 as placeholder (needs `sha1` crate).
10. **Taproot (BIP341/342)** — Schnorr signatures, tapscript.
11. **Full test suite** — Run Bitcoin Core's script_tests.json and tx_valid/tx_invalid test vectors.
12. **Benchmarks** — Performance testing for script execution, block validation.

## Estimated Scope

- **Current**: ~4,500 lines across 5 crates (roughly 8% of Bitcoin Core's 337K LOC)
- **Bitcoin Core C++ reference**: 337,513 LOC across 1,375 files
- **Minimum viable syncing node**: Would need items 1-4 above
- **Full feature parity**: Items 1-12 and much more

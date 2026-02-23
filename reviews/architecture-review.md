# Agentic-Bitcoin Architecture Review

**Date:** February 23, 2026
**Reviewer:** Claude (Opus 4.6)
**Scope:** Architectural assessment against Clean Architecture and Hexagonal (Ports & Adapters) patterns

---

## Classification

Agentic-bitcoin implements **Hexagonal Architecture (Ports & Adapters)** rather than Clean Architecture. The distinction is clear from the crate structure and dependency graph.

## Overall Structure

The project is a Rust workspace of five crates arranged in concentric layers:

```
abtc-infrastructure (outermost -- composition root, entry point)
  abtc-application   (use cases and service orchestration)
  abtc-adapters      (concrete implementations of port traits)
    abtc-ports       (trait definitions only -- the port layer)
      abtc-domain    (innermost -- pure business logic, zero I/O)
```

Each crate has a single, well-defined responsibility, and the layering is enforced at the Rust crate level, meaning the compiler itself prevents dependency violations.

## Dependency Flow

Dependencies flow strictly inward. No reverse dependencies were found.

- **abtc-domain** depends on nothing internal (only crypto primitives like `secp256k1`, `sha2`, `chacha20poly1305`)
- **abtc-ports** depends only on `abtc-domain` (uses domain types in trait signatures)
- **abtc-adapters** depends on `abtc-ports` and `abtc-domain` (implements the traits)
- **abtc-application** depends on `abtc-ports` and `abtc-domain` (never `abtc-adapters`)
- **abtc-infrastructure** depends on everything (the only place concrete adapters are known)

## Why Hexagonal, Not Clean Architecture

The defining feature is the **explicit `abtc-ports` crate** -- a dedicated layer whose sole purpose is to define trait contracts (`BlockStore`, `ChainStateStore`, `MempoolPort`, `PeerManager`, `BlockTemplateProvider`, `BlockSubmitter`, `WalletPort`, `RpcHandler`, `RpcServer`) with zero concrete implementations. This is the hallmark of Hexagonal thinking. Clean Architecture treats the boundary as a conceptual layer but doesn't typically materialize it as a standalone first-class module.

The ports also carry the implicit primary/secondary distinction characteristic of Hexagonal Architecture: RPC handlers and the sync manager are primary (driving) ports, while storage, mempool, and network are secondary (driven) ports.

## Layer Details

### Domain (abtc-domain)

Approximately 30,800 lines across 60+ modules. Entirely pure -- zero I/O, no async, no database, no networking. Contains:

- **Primitives:** Transaction, Block, BlockHeader, Amount, Hash types
- **Consensus:** Validation rules, block connection/disconnection, UTXO updates, signet support
- **Script:** Full stack-based interpreter with 100+ opcodes, witness verification
- **Crypto:** SHA256, ECDSA, BIP340 Schnorr, BIP341/342 Taproot, BIP324 encrypted transport
- **Wallet:** BIP32 HD keys, all address types, transaction builder, coin selection (branch-and-bound, knapsack, SRD), BIP174 PSBT, output descriptors
- **Policy:** BIP125 RBF, CPFP, relay limits, standardness rules
- **Protocol:** P2P message types, codec, network types
- **Filters:** BIP157/158 compact block filters, Golomb-coded sets
- **UTXO:** Coin types, MuHash3072, AssumeUTXO snapshots
- **Covenants:** BIP119 CTV, OP_VAULT

All validation functions are pure and deterministic -- they take data in and return valid/invalid with no side effects.

### Ports (abtc-ports)

Approximately 800 lines across 6 modules. Contains only `#[async_trait]` trait definitions. No concrete implementations. This crate defines what external systems must do, not how they do it.

### Adapters (abtc-adapters)

Approximately 2,000 lines across 6 modules. Concrete implementations of port traits:

- **Storage:** `InMemoryBlockStore` / `InMemoryChainStateStore` (HashMap-backed) and `RocksDbBlockStore` / `RocksDbChainStateStore` (feature-gated persistent storage)
- **Mempool:** `InMemoryMempool` with ancestor/descendant tracking, RBF, CPFP, fee-rate sorting, size-based eviction
- **Network:** `TcpPeerManager` (real TCP P2P) and `StubPeerManager` (no-op for testing)
- **Mining:** `SimpleMiner` with fee-maximizing transaction selection
- **Wallet:** `InMemoryWallet`, `PersistentWallet`, `FileBasedWalletStore`
- **RPC:** `JsonRpcServer` (HTTP-based JSON-RPC 2.0)

The adapter swappability is real, not theoretical -- multiple implementations already exist and are selectable via CLI flags.

### Application (abtc-application)

Approximately 3,000 lines across 19 modules. Orchestrates domain logic through port abstractions:

- **BlockchainService:** Validates and accepts blocks using domain rules, queries and updates chain state through ports, broadcasts to peers through ports
- **MempoolService / MempoolAcceptor:** Transaction validation and mempool management
- **MiningService:** Block template creation and submission
- **ChainState:** Block index, UTXO set management, chain tip selection, reorg logic
- **SyncManager:** P2P synchronization state machine (HeaderSync, BlockSync, Synced, Idle)
- **RPC Handlers:** `BlockchainRpcHandler`, `MiningRpcHandler`, `WalletRpcHandler` -- dispatch JSON-RPC calls to services
- **Supporting modules:** Fee estimation, peer scoring, orphan pool, transaction rebroadcast, compact blocks, download scheduling, package relay, chain event notifications

This layer depends on `abtc-ports` and `abtc-domain` but never on `abtc-adapters`. Services accept `Arc<dyn PortTrait>` and are completely adapter-agnostic.

### Infrastructure (abtc-infrastructure)

Approximately 1,500 lines. The composition root and entry point. This is the only layer that knows about concrete adapter types. Responsibilities:

- CLI argument parsing (network, ports, storage backend, wallet config)
- Creating concrete adapter instances based on configuration
- Injecting adapters into services as trait objects
- Background task management (mempool maintenance, peer connections, sync reporting, rebroadcast, keepalive)
- Graceful shutdown via tokio watch channels with timeout

## Divergences from Clean Architecture

Beyond the explicit port layer (which is Hexagonal rather than Clean), several specific differences from Clean Architecture were observed:

1. **RPC handlers mix orchestration with serialization.** The `BlockchainRpcHandler` in `abtc-application` imports `serde_json::Value` and does JSON parsing alongside business orchestration. Clean Architecture would separate these into an interface adapter layer (handling JSON) and a use case interactor (handling business logic).

2. **No request/response DTOs at use case boundaries.** Services expose methods that take domain types directly rather than use-case-specific request and response objects. Clean Architecture formalizes these boundaries with explicit input/output models.

3. **No formal use case input boundary traits.** Controllers call service methods directly rather than depending on `UseCase` or `InputBoundary` traits. Clean Architecture uses these to create a formal contract between the driving side and application logic.

## On the Purity of the Use Case Layer

The most consequential of the divergences above is the first: the application layer is not fully protocol-agnostic. The RPC handlers in `abtc-application` accept `serde_json::Value` parameters, parse JSON inline, and construct JSON responses -- meaning the use case layer has knowledge of the wire format. This is worth examining in detail because the project otherwise demonstrates excellent separation of concerns.

Consider what `BlockchainRpcHandler::handle_request` does today. It receives a method name and a `serde_json::Value`, pattern-matches on the method, extracts fields from JSON, calls into domain services, and then serializes the result back to JSON. That's two distinct responsibilities in one place: translating between wire format and domain concepts, and orchestrating the business operation itself.

In a Clean Architecture, these would be separated. A thin interface adapter (living outside the application layer) would handle JSON parsing and produce a plain Rust struct -- say, `GetBlockRequest { hash: BlockHash, verbosity: u32 }` -- which it would pass to a use case interactor. The interactor would do the business work and return a `GetBlockResponse` containing domain data. The interface adapter would then serialize that response back to JSON. The use case interactor would never encounter `serde_json::Value` at all.

The practical benefit is that the orchestration logic becomes reusable across protocols without modification. If the node were to expose a gRPC interface, a REST API, a CLI, or an in-process Rust library API, each would only need its own thin interface adapter that translates its wire format into the same request/response types. The use case layer would remain untouched. Today, adding a gRPC interface would require either duplicating the orchestration logic or refactoring the existing handlers to extract it.

There's also a testability advantage. Currently, testing the RPC handlers requires constructing `serde_json::Value` objects and parsing JSON responses. If the orchestration were separated, you could test business flows with plain Rust types and test the JSON mapping layer independently with simple serialization round-trip tests.

That said, the current approach is a defensible trade-off. Bitcoin's JSON-RPC interface is well-established, unlikely to be replaced, and the project has a single entry protocol. The additional indirection of a separate interface adapter layer would add types and mapping code for every RPC method -- a real maintenance cost -- in exchange for flexibility the project may never need. The point is worth keeping in mind as the project evolves, particularly if there's ever interest in embedding the node as a library or exposing alternative interfaces.

## Architectural Strengths

- **Pure domain logic.** Zero infrastructure dependencies, fully testable without mocks, clear and deterministic validation rules.
- **Proven adapter swappability.** In-memory vs RocksDB storage, stub vs TCP networking -- already implemented and switchable at runtime.
- **Compiler-enforced boundaries.** Rust's crate system means dependency violations are compilation errors, not just convention.
- **Clean composition root.** All wiring happens in one place (`BitcoinNode::new()`), making the system's assembly transparent.
- **Graceful lifecycle management.** Watch channels for shutdown signaling, RAII task guards, timeout-bounded cleanup.
- **612 passing tests.**

## Areas for Potential Improvement

- **Separating serialization from orchestration** in RPC handlers would make the application layer protocol-agnostic, enabling reuse from gRPC, CLI, or in-process APIs without encountering JSON concerns.
- **Introducing boundary DTOs** would decouple the use case contract from domain type evolution, useful if the RPC interface needs versioning.
- **Formalizing input ports** with explicit use case traits would clarify the driving-side contract and improve testability of the orchestration layer in isolation.
- **Async in ports** creates an implicit dependency on the Tokio runtime model. A stricter Hexagonal approach might define runtime-agnostic ports, though for a Rust/Tokio project this is a reasonable trade-off.

## Verdict

Agentic-bitcoin is a textbook implementation of Hexagonal Architecture for a Bitcoin node. The layering is clean, the dependency flow is correct and compiler-enforced, the domain is genuinely isolated, and the adapter swappability is demonstrated rather than theoretical. The divergences from Clean Architecture are reasonable trade-offs for a system with a stable, singular interface (JSON-RPC). If the project were to grow multiple front-ends or become an embeddable library, tightening the use case boundaries would become more valuable.

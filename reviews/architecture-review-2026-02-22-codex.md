# Architecture Review - agentic-bitcoin

Date: 2026-02-22
Reviewer: Codex

## Findings (Severity-Ordered)

### 1) [High] Persistence architecture is internally inconsistent at startup
- Evidence:
  - `crates/abtc-infrastructure/src/lib.rs:311` initializes genesis every startup.
  - `crates/abtc-infrastructure/src/lib.rs:326` unconditionally writes chain tip to genesis.
  - `crates/abtc-infrastructure/src/lib.rs:336` re-initializes in-memory block index from genesis only.
- Architectural impact:
  - Runtime projections (`block_index`) are not rebuilt from persisted state.
  - Persistent tip can be overwritten during bootstrap.
  - Creates split-brain risk between durable storage and in-memory view after restart.
- Recommendation:
  - Add an explicit bootstrap phase:
    - Read existing chain tip first.
    - Initialize genesis only when storage is empty.
    - Rehydrate block index from persisted headers/blocks (or persist block-index projection directly).

### 2) [Medium] Composition root leaks concrete adapter types into node contract
- Evidence:
  - `crates/abtc-infrastructure/src/lib.rs:172` `rpc_server: Arc<JsonRpcServer>`
  - `crates/abtc-infrastructure/src/lib.rs:174` `mempool_adapter: Arc<InMemoryMempool>`
  - `crates/abtc-infrastructure/src/lib.rs:186` `tcp_peer_manager: Option<Arc<TcpPeerManager>>`
  - `crates/abtc-infrastructure/src/lib.rs:292` concrete RPC creation
  - `crates/abtc-infrastructure/src/lib.rs:293` concrete mempool creation
- Architectural impact:
  - Limits replaceability and configurability despite having port traits.
  - Makes outer-layer policy decisions harder to test with alternate adapters.
- Recommendation:
  - Keep concrete adapter selection in composition, but store/use them through trait-object fields where possible (`Arc<dyn RpcServer>`, `Arc<dyn MempoolPort>`) and isolate adapter-specific control paths behind narrowly scoped helper traits.

### 3) [Medium] Application layer is coupled to JSON-RPC transport protocol details
- Evidence:
  - `crates/abtc-application/src/handlers.rs:45` dispatches on method strings.
  - `crates/abtc-application/src/handlers.rs:73` and similar lines produce protocol-shaped JSON responses.
  - `crates/abtc-ports/src/rpc/mod.rs:131` uses `serde_json::Value` in core handler contract.
- Architectural impact:
  - Application/use-case layer becomes protocol-aware instead of transport-agnostic.
  - Harder to expose the same use cases via non-JSON-RPC interfaces (CLI/GRPC/internal APIs) without duplicating behavior.
- Recommendation:
  - Move JSON mapping and method-name routing to adapter/infrastructure edge.
  - Keep application APIs typed around commands/queries and domain DTOs.

### 4) [Low] CQRS command/query layer exists but is not integrated
- Evidence:
  - Types are defined in `crates/abtc-application/src/commands.rs:9` and `crates/abtc-application/src/queries.rs:9`.
  - They are not referenced by production application flows.
- Architectural impact:
  - Adds conceptual overhead without enforcing boundaries.
  - Signals intended architecture but current implementation bypasses it.
- Recommendation:
  - Either wire handlers/services through these command/query types or remove them until actively used.

### 5) [Low] Port contracts use erased error types, reducing boundary precision
- Evidence:
  - `crates/abtc-ports/src/storage/mod.rs:88` and many similar methods return `Box<dyn Error + Send + Sync>`.
  - `crates/abtc-ports/src/network/mod.rs:132` similar broad error shape.
  - `crates/abtc-ports/src/rpc/mod.rs:148` similar broad error shape.
- Architectural impact:
  - Cross-layer failures lose semantics (recoverable vs fatal, retriable vs permanent).
  - Encourages stringly error mapping in application layer.
- Recommendation:
  - Introduce typed port error enums per port (storage/network/rpc/wallet), with conversion from adapter-native errors.

## Strengths

- Layered crate split is clear and mostly coherent:
  - `abtc-domain` remains infrastructure-free at crate dependency level.
  - `abtc-ports` centralizes interface contracts.
  - `abtc-infrastructure` acts as composition root.
- Dependency direction is largely correct for a hexagonal approach (outer layers depend inward, not vice versa).
- Runtime wiring is explicit and readable, which helps reasoning and debugging.

## Overall Assessment

The architecture is strong in high-level intent and crate-level boundaries. The main gap is that lifecycle/bootstrap and boundary contracts do not yet fully honor the same separation principles at runtime. If the bootstrap/persistence path and adapter abstraction leakage are tightened, the implementation will align much more cleanly with the documented hexagonal design.

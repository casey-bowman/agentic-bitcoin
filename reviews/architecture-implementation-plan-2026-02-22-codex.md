# Architecture Implementation Plan - agentic-bitcoin

Date: 2026-02-22
Author: Codex
Scope: Plan only (no implementation in this document)

## Goal

Address the architecture findings from `architecture-review-2026-02-22-codex.md` through a sequenced, low-risk refactor plan that preserves behavior while improving boundary integrity, restart correctness, and replaceability.

## Constraints

- No changes in this step (planning only).
- Keep public behavior stable unless explicitly noted.
- Prefer incremental PRs with passing tests after each PR.
- Avoid large cross-cutting rewrites in one pass.

## Workstreams

### Workstream A: Startup/Persistence Bootstrap Correctness (Highest Priority)

Objective:
- Ensure node restart behavior is consistent with persistent storage and does not regress chain state.

Planned changes:
1. Add an explicit bootstrap state machine in infrastructure startup:
   - Detect if storage is empty/uninitialized.
   - Initialize genesis only when empty.
   - Preserve existing chain tip when present.
2. Separate bootstrap responsibilities:
   - `StorageBootstrapper` (tip/genesis init policy)
   - `ProjectionBootstrapper` (in-memory block index rehydration)
3. Rehydrate `BlockIndex` from persisted headers/blocks up to best tip (or introduce a persisted block-index snapshot adapter).
4. Add startup invariants:
   - persisted tip hash/height must match loaded index tip.
   - fail-fast with explicit error if inconsistent.

Tests/validation:
- New restart integration tests for memory and RocksDB backends.
- Regression test: restart must not reset tip to genesis.
- Recovery test: process exits with clear error when persistence is corrupt/inconsistent.

Acceptance criteria:
- Restart preserves best tip.
- No unconditional genesis tip overwrite.
- Block index height/hash align with persisted tip after startup.

---

### Workstream B: Adapter Abstraction at Node Boundary

Objective:
- Reduce concrete-adapter coupling in `BitcoinNode` to improve replaceability and testability.

Planned changes:
1. Replace concrete fields with trait-oriented boundaries where possible:
   - `Arc<dyn RpcServer>` instead of `Arc<JsonRpcServer>`
   - `Arc<dyn MempoolPort>` where read-only adapter internals are not required.
2. Encapsulate adapter-specific controls behind narrow traits/extensions:
   - e.g., optional `PeerKeepalive` trait for TCP-specific maintenance.
3. Introduce a `NodeComponents` builder struct in infrastructure:
   - centralizes adapter construction and dependency injection.
   - enables alternate compositions for tests.

Tests/validation:
- Compile-time checks with alternative test doubles implementing port traits.
- Existing infra tests continue to pass with builder-based wiring.

Acceptance criteria:
- `BitcoinNode` public/internal contract references primarily ports/application services.
- Concrete adapter types confined to composition/build phase.

---

### Workstream C: Decouple Transport Protocol from Application Use Cases

Objective:
- Move JSON-RPC protocol concerns out of application handlers and keep use cases typed.

Planned changes:
1. Introduce typed application request/response DTOs for major RPC methods.
2. Keep method-name dispatch + JSON parsing/serialization in adapter/infrastructure edge.
3. Convert `abtc-application` RPC handlers to call typed use-case functions/services.
4. Add translation layer:
   - JSON-RPC `Value` <-> typed DTO mapping in `abtc-adapters::rpc` or infrastructure module.

Tests/validation:
- Unit tests for JSON mapping layer (valid/invalid params).
- Application tests on typed DTO/use-case functions (no JSON dependency).
- End-to-end RPC tests to ensure wire compatibility.

Acceptance criteria:
- Application layer no longer builds protocol-shaped JSON directly.
- JSON-RPC remains wire-compatible for existing methods.

---

### Workstream D: Resolve CQRS Drift (Integrate or Remove)

Objective:
- Eliminate unused architectural artifacts and clarify command/query path.

Decision gate:
- Choose one path before implementation:
  1. Integrate command/query types into real execution flow, or
  2. Remove dormant types and document simpler service-oriented architecture.

Recommended path:
- Integrate minimally for high-value operations (`sendrawtransaction`, `getblock`, `getmempoolinfo`, `estimatesmartfee`) to avoid dead abstractions.

Planned changes (if integrate):
1. Add application handlers/services that accept command/query structs.
2. Route RPC translation layer to command/query dispatch.
3. Keep initial scope tight; avoid full framework upfront.

Tests/validation:
- Ensure command/query structs are referenced in production code paths.
- Remove dead code warnings for unused CQRS types.

Acceptance criteria:
- No dormant CQRS types without runtime usage.
- Architecture docs match code reality.

---

### Workstream E: Typed Port Errors

Objective:
- Replace `Box<dyn Error>`-only contracts with typed, semantically meaningful port errors.

Planned changes:
1. Introduce per-port error enums in `abtc-ports`:
   - `StorageError`, `NetworkError`, `RpcServerError`, `WalletError`, `MempoolError`.
2. Update trait signatures to return typed errors.
3. Add adapter-level `From<backend_error>` conversions.
4. Preserve upper-layer ergonomics with `thiserror` and helper mapping methods.

Migration strategy:
- Do one port at a time (Storage first, then RPC, Network, Wallet, Mempool).
- Keep temporary compatibility wrappers during transition if needed.

Tests/validation:
- Unit tests asserting specific error variants for common failure modes.
- No loss of context in error propagation.

Acceptance criteria:
- Port boundaries expose typed errors.
- Application/infrastructure can branch behavior on error class (retriable/fatal/invalid input).

## Recommended PR Sequence

1. PR-1: Workstream A (bootstrap correctness) + regression tests.
2. PR-2: Workstream B foundational refactor (`NodeComponents` + trait-oriented fields).
3. PR-3: Workstream C phase 1 (typed DTO/use-case path for a small RPC subset).
4. PR-4: Workstream D (CQRS decision implementation for selected methods).
5. PR-5: Workstream C phase 2 (remaining RPC methods migrated).
6. PR-6: Workstream E phase 1 (typed storage + RPC errors).
7. PR-7: Workstream E phase 2 (network/wallet/mempool typed errors) + cleanup/docs alignment.

## Estimated Effort (Rough)

- Workstream A: M
- Workstream B: M
- Workstream C: L
- Workstream D: S-M (depends on decision)
- Workstream E: M-L

Total: L (multi-PR effort)

## Risk Register

- Risk: Bootstrap/index rehydration introduces startup latency.
  - Mitigation: instrument timing; cache snapshots if needed.
- Risk: Typed error migration causes broad signature churn.
  - Mitigation: per-port migration with compatibility shims.
- Risk: RPC decoupling breaks response compatibility.
  - Mitigation: golden tests for JSON responses before/after.
- Risk: Large refactor destabilizes test suite.
  - Mitigation: strict PR slicing and no mixed concerns per PR.

## Definition of Done

- Restart and persistence behavior are correct and regression-tested.
- Infrastructure node contract is mostly port-oriented, not adapter-concrete.
- Application use-cases are transport-agnostic.
- CQRS layer is either actively used or removed.
- Port traits use typed errors with clear semantics.
- Architecture docs accurately describe the implemented system.

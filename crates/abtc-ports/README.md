# abtc-ports

Trait interfaces (ports) for the Agentic-Bitcoin hexagonal architecture. This crate defines the contracts between the domain layer and external systems — with no concrete implementations.

## Overview

abtc-ports sits between `abtc-domain` (pure logic) and `abtc-adapters` (concrete implementations). It contains only trait definitions, ensuring that the domain layer never depends on infrastructure details.

```text
External Systems (DB, Network, RPC)
         ▲
         │  ← adapter implementations
         │
    abtc-ports (this crate)
    Trait definitions only
         ▲
         │  ← domain types
         │
    abtc-domain
```

## Port Traits

### `storage`

Persistent storage for blocks and chain state:

- **`BlockStore`** — store and retrieve blocks, block headers, and block index entries by hash or height
- **`ChainStateStore`** — UTXO set management, best chain tip tracking, and chain state queries

### `mempool`

Transaction mempool interface:

- **`MempoolPort`** — add/remove transactions, query by txid, get mempool info, select mining candidates, ancestor/descendant tracking

### `network`

Peer-to-peer networking:

- **`PeerManager`** — connect/disconnect peers, send/broadcast messages, query peer info
- **`NetworkListener`** — receive peer events (messages, connections, disconnections)

### `mining`

Block creation and submission:

- **`BlockTemplateProvider`** — generate block templates with fee-maximizing transaction selection
- **`BlockSubmitter`** — submit mined blocks to the chain

### `wallet`

Wallet storage and operations:

- **`WalletPort`** — key management, balance queries, UTXO listing, transaction history
- **`WalletStore`** — persistent wallet state (keys, labels, metadata)

### `rpc`

JSON-RPC server interface:

- **`RpcHandler`** — dispatch incoming RPC requests to the appropriate handler
- **`RpcServer`** — start/stop the JSON-RPC server

## Usage

Depend on this crate when you need to write code that is generic over storage backends, network implementations, or other infrastructure:

```rust
use abtc_ports::{BlockStore, ChainStateStore, MempoolPort};

fn process_block<S: BlockStore + ChainStateStore, M: MempoolPort>(
    store: &mut S,
    mempool: &mut M,
    // ...
) {
    // Works with any adapter implementation
}
```

## Dependencies

This crate depends only on `abtc-domain` (for domain types used in trait signatures), `async-trait`, `thiserror`, and `serde_json`.

## License

MIT — see [LICENSE-MIT](../../LICENSE-MIT) for details.

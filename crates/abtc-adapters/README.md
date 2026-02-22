# abtc-adapters

Concrete implementations of the port traits defined in `abtc-ports`. Provides in-memory adapters suitable for testing and lightweight usage, plus optional persistent backends.

## Overview

This crate sits in the adapter layer of the hexagonal architecture, implementing every trait from `abtc-ports` so that `abtc-application` and `abtc-infrastructure` can wire up a working node without any infrastructure leaking into the domain.

## Adapters

### Storage

- **`InMemoryBlockStore`** — HashMap-backed block and header storage. Fast and simple, suitable for testing and regtest usage.
- **`InMemoryChainStateStore`** — HashMap-backed UTXO set and chain tip tracking.
- **`RocksDbBlockStore`** / **`RocksDbChainStateStore`** — Persistent storage backed by RocksDB (behind the `rocksdb-storage` feature flag).

### Mempool

- **`InMemoryMempool`** — Full-featured mempool with ancestor/descendant tracking, RBF (BIP125), CPFP fee boosting, size-based eviction, and fee-rate-sorted mining candidate selection.

### Network

- **`TcpPeerManager`** — Real TCP-based P2P peer manager for connecting to Bitcoin nodes. Handles version handshake, message framing, and peer lifecycle.
- **`StubPeerManager`** — No-op peer manager for testing scenarios that don't require networking.

### Mining

- **`SimpleMiner`** — Block template creation with fee-maximizing transaction selection and coinbase construction.

### Wallet

- **`InMemoryWallet`** — Ephemeral wallet for testing. Keys and UTXOs are held in memory and lost on shutdown.
- **`PersistentWallet`** — Wallet with on-disk persistence via JSON serialization.
- **`FileBasedWalletStore`** — File-backed wallet key and metadata storage.

### RPC

- **`JsonRpcServer`** — HTTP-based JSON-RPC server that dispatches requests to registered `RpcHandler` implementations.

## Feature Flags

- **`rocksdb-storage`** — Enables `RocksDbBlockStore` and `RocksDbChainStateStore` for persistent on-disk storage. Requires the `rocksdb` system library.

## Usage

```rust
use abtc_adapters::{InMemoryBlockStore, InMemoryChainStateStore, InMemoryMempool};

let block_store = InMemoryBlockStore::new();
let chain_state = InMemoryChainStateStore::new();
let mempool = InMemoryMempool::new();
```

## License

MIT — see [LICENSE-MIT](../../LICENSE-MIT) for details.

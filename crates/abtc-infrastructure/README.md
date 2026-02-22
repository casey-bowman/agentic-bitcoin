# abtc-infrastructure

Composition root for the Agentic-Bitcoin node. This is the outermost layer of the hexagonal architecture — it wires together the domain, adapters, and application services into a running Bitcoin node.

## Overview

abtc-infrastructure is the entry point. It handles CLI argument parsing, dependency injection, background task management, and graceful shutdown. No other crate in the workspace depends on it; it depends on everything else.

## What It Does

- **Dependency injection** — Instantiates concrete adapters (storage, mempool, wallet, network, RPC) and injects them into the generic application services.
- **Background tasks** — Spawns tokio tasks for P2P message processing, RPC server, transaction rebroadcast, and periodic maintenance. All tasks are tracked for health reporting.
- **Graceful shutdown** — Listens for SIGINT (Ctrl+C) or SIGTERM, then triggers an orderly shutdown via a `tokio::sync::watch` channel. A configurable timeout ensures the process exits even if tasks hang.
- **CLI parsing** — Uses `clap` for command-line arguments: network selection (mainnet, testnet, regtest, signet), data directory, RPC port, peer addresses, and more.
- **Logging** — Configures `tracing-subscriber` with an environment filter for structured, level-based logging.

## Running

```bash
# Start a regtest node
cargo run -- --network regtest

# Start with custom RPC port and data directory
cargo run -- --network regtest --rpc-port 18443 --datadir ./data

# With verbose logging
RUST_LOG=debug cargo run -- --network regtest
```

## Feature Flags

- **`rocksdb-storage`** — Enables persistent block and chain state storage via RocksDB (forwarded to `abtc-adapters`).

## License

MIT — see [LICENSE-MIT](../../LICENSE-MIT) for details.

# abtc-application

Application services and use cases for Agentic-Bitcoin. Orchestrates domain logic through the port interfaces to implement high-level blockchain operations.

## Overview

This crate sits between the domain/port layers and the infrastructure layer. It contains all the "business logic" that coordinates multiple domain operations — chain state management, P2P message processing, mempool acceptance, mining, fee estimation, and more — without depending on any concrete adapter.

## Services

### Chain State (`chain_state`)

Block connection and disconnection with UTXO set management. Handles automatic reorganization when a competing chain tip arrives with more work.

### Mempool Acceptance (`mempool_acceptance`)

Validates transactions against consensus rules and mempool policy before admitting them. Checks script execution, fee requirements, ancestor/descendant limits, and RBF rules.

### P2P Sync (`net_processing`)

Processes incoming peer messages and drives the sync state machine: version handshake, header-first sync, block download scheduling, inventory relay, and compact block handling (BIP152).

### Mining (`miner`, `block_template`)

Assembles block templates with fee-maximizing transaction selection from the mempool. The `generate_blocks` helper mines a sequence of blocks on regtest for testing.

### Fee Estimation (`fee_estimator`)

Tracks median fee rates from recently confirmed blocks using a sliding window. Provides `estimatesmartfee`-style fee rate suggestions for target confirmation depths.

### Peer Scoring (`peer_scoring`)

Tracks misbehavior across peers with cumulative scoring. Peers that exceed the ban threshold are automatically disconnected and banned with configurable expiry.

### Download Scheduler (`download_scheduler`)

Manages in-flight block requests across multiple peers. Handles timeout detection, peer selection, and stale-tip monitoring to keep sync progressing.

### Compact Blocks (`compact_blocks`)

BIP152 compact block support — SipHash-based short transaction IDs, block reconstruction from mempool prefill, and `getblocktxn`/`blocktxn` round-trips for missing transactions.

### Package Relay (`package_relay`)

BIP331 transaction package acceptance. Validates and accepts packages of related transactions as a unit, enabling CPFP fee bumping for transactions that wouldn't pass individually.

### RPC Handlers (`handlers`)

JSON-RPC dispatch for `getblock`, `getblockheader`, `getrawtransaction`, `sendrawtransaction`, `estimatesmartfee`, `getmempoolinfo`, `generate`, wallet RPCs, and more.

### Additional Modules

- **`block_index`** — In-memory block tree with fork tracking and best-chain selection
- **`chain_events`** — Publish/subscribe notification bus for block and transaction events
- **`orphan_pool`** — Orphan transaction management with peer tracking and expiry
- **`rebroadcast`** — Automatic wallet transaction rebroadcast with attempt limits
- **`address_manager`** — Peer address book for discovery and connection management
- **`queries`** / **`commands`** — Query and command types for the service interfaces

## Usage

All services are generic over the port traits, so they work with any adapter:

```rust
use abtc_application::{ChainState, MempoolAcceptor, FeeEstimator};

// ChainState is generic over BlockStore + ChainStateStore
// MempoolAcceptor is generic over MempoolPort + ChainStateStore
// FeeEstimator works standalone with no adapter dependency
```

## License

MIT — see [LICENSE-MIT](../../LICENSE-MIT) for details.

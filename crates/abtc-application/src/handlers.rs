//! Event and command handlers for the application layer
//!
//! Handles RPC requests, network messages, and other application events.

use crate::block_index::BlockIndex;
use crate::fee_estimator::FeeEstimator;
use crate::services::{BlockchainService, MempoolService, MiningService};
use abtc_domain::script::Script;
use abtc_ports::{ChainStateStore, RpcHandler};
use async_trait::async_trait;
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::RwLock;

/// RPC handler for blockchain queries and operations
pub struct BlockchainRpcHandler {
    blockchain: Arc<BlockchainService>,
    mempool: Arc<MempoolService>,
    fee_estimator: Arc<RwLock<FeeEstimator>>,
    chain_state: Arc<dyn ChainStateStore>,
    block_index: Arc<RwLock<BlockIndex>>,
}

impl BlockchainRpcHandler {
    /// Create a new blockchain RPC handler.
    pub fn new(
        blockchain: Arc<BlockchainService>,
        mempool: Arc<MempoolService>,
        fee_estimator: Arc<RwLock<FeeEstimator>>,
        chain_state: Arc<dyn ChainStateStore>,
        block_index: Arc<RwLock<BlockIndex>>,
    ) -> Self {
        BlockchainRpcHandler {
            blockchain,
            mempool,
            fee_estimator,
            chain_state,
            block_index,
        }
    }
}

#[async_trait]
impl RpcHandler for BlockchainRpcHandler {
    async fn handle_request(
        &self,
        method: &str,
        _params: &Value,
    ) -> Result<Option<Value>, abtc_ports::RpcError> {
        match method {
            "getblockcount" => {
                let info = self
                    .blockchain
                    .get_chain_info()
                    .await
                    .map_err(abtc_ports::RpcError::internal_error)?;
                Ok(Some(Value::Number(info.height.into())))
            }
            "getbestblockhash" => {
                let info = self
                    .blockchain
                    .get_chain_info()
                    .await
                    .map_err(abtc_ports::RpcError::internal_error)?;
                Ok(Some(Value::String(info.best_block_hash.to_hex_reversed())))
            }
            "getblockchaininfo" => {
                let info = self
                    .blockchain
                    .get_chain_info()
                    .await
                    .map_err(abtc_ports::RpcError::internal_error)?;
                Ok(Some(json!({
                    "chain": "main",
                    "blocks": info.blocks,
                    "headers": info.blocks,
                    "bestblockhash": info.best_block_hash.to_hex_reversed(),
                    "difficulty": 1.0,
                    "mediantime": 0,
                    "verificationprogress": 1.0,
                    "initialblockdownload": false,
                    "chainwork": "0000000000000000000000000000000000000000000000000000000000000000",
                    "pruned": false
                })))
            }
            "getmempoolinfo" => {
                let mempool_info = self
                    .mempool
                    .get_mempool_info()
                    .await
                    .map_err(abtc_ports::RpcError::internal_error)?;
                Ok(Some(json!({
                    "loaded": true,
                    "size": mempool_info.size,
                    "bytes": mempool_info.bytes,
                    "usage": mempool_info.usage,
                    "maxmempool": mempool_info.max_mempool,
                    "mempoolminfee": mempool_info.min_relay_fee,
                    "minrelaytxfee": mempool_info.min_relay_fee
                })))
            }
            "getrawmempool" => {
                let contents = self
                    .mempool
                    .get_mempool_contents()
                    .await
                    .map_err(abtc_ports::RpcError::internal_error)?;
                Ok(Some(json!(contents)))
            }
            "getblockhash" => {
                let height = _params
                    .get(0)
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| abtc_ports::RpcError::invalid_params("missing height"))?
                    as u32;

                let idx = self.block_index.read().await;
                match idx.get_hash_at_height(height) {
                    Some(hash) => Ok(Some(Value::String(hash.to_hex_reversed()))),
                    None => Err(abtc_ports::RpcError::invalid_params(
                        "Block height out of range",
                    )),
                }
            }
            "getblock" => {
                let hash_hex = _params
                    .get(0)
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| abtc_ports::RpcError::invalid_params("missing blockhash"))?;
                let verbosity = _params.get(1).and_then(|v| v.as_u64()).unwrap_or(1);

                let hash = abtc_domain::primitives::BlockHash::from_hex(hash_hex)
                    .ok_or_else(|| abtc_ports::RpcError::invalid_params("invalid blockhash"))?;

                let block = self
                    .blockchain
                    .get_block(&hash)
                    .await
                    .map_err(abtc_ports::RpcError::internal_error)?
                    .ok_or_else(|| abtc_ports::RpcError {
                        code: -5,
                        message: "Block not found".to_string(),
                        data: None,
                    })?;

                if verbosity == 0 {
                    // Return serialised hex (simplified — just return hash)
                    Ok(Some(Value::String(hash.to_hex_reversed())))
                } else {
                    // Look up block height and confirmations from the block index
                    let idx = self.block_index.read().await;
                    let (block_height, confirmations) = match idx.get(&hash) {
                        Some(entry) => {
                            let confs = (idx.best_height() as i64) - (entry.height as i64) + 1;
                            (entry.height, confs.max(1) as u64)
                        }
                        None => (0u32, 1u64),
                    };
                    let next_block_hash = idx.get_hash_at_height(block_height + 1);
                    drop(idx);

                    // Return JSON object
                    let tx_ids: Vec<Value> = block
                        .transactions
                        .iter()
                        .map(|tx| Value::String(tx.txid().to_hex_reversed()))
                        .collect();
                    let mut result = json!({
                        "hash": hash.to_hex_reversed(),
                        "confirmations": confirmations,
                        "size": block.size(),
                        "weight": block.transactions.iter()
                            .map(|tx| tx.compute_weight() as u64).sum::<u64>(),
                        "height": block_height,
                        "version": block.header.version,
                        "merkleroot": block.header.merkle_root.to_hex_reversed(),
                        "tx": tx_ids,
                        "time": block.header.time,
                        "nonce": block.header.nonce,
                        "bits": format!("{:08x}", block.header.bits),
                        "difficulty": 1.0,
                        "nTx": block.transactions.len(),
                        "previousblockhash": block.header.prev_block_hash.to_hex_reversed()
                    });
                    if let Some(next_hash) = next_block_hash {
                        result["nextblockhash"] = Value::String(next_hash.to_hex_reversed());
                    }
                    Ok(Some(result))
                }
            }
            "getdifficulty" => {
                // Difficulty = pow_limit_target / current_target
                // For now return 1.0 (minimum difficulty)
                Ok(Some(json!(1.0)))
            }
            "getpeerinfo" => {
                // Stub — would need PeerManager access
                Ok(Some(json!([])))
            }
            "getnetworkinfo" => Ok(Some(json!({
                "version": 270000,
                "subversion": "/agentic-bitcoin:0.1.0/",
                "protocolversion": 70016,
                "localservices": "0000000000000409",
                "localservicesnames": ["NETWORK", "WITNESS", "NETWORK_LIMITED"],
                "localrelay": true,
                "timeoffset": 0,
                "networkactive": true,
                "connections": 0,
                "connections_in": 0,
                "connections_out": 0,
                "relayfee": 0.00001,
                "incrementalfee": 0.00001,
                "warnings": ""
            }))),
            "sendrawtransaction" => {
                // Parse hex-encoded raw transaction and submit to mempool.
                let hex_str = _params
                    .get(0)
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| abtc_ports::RpcError::invalid_params("missing hex string"))?;

                let tx_bytes = hex::decode(hex_str)
                    .map_err(|_| abtc_ports::RpcError::invalid_params("invalid hex encoding"))?;

                let (tx, _) = abtc_domain::primitives::Transaction::deserialize(&tx_bytes)
                    .map_err(|e| {
                        abtc_ports::RpcError::invalid_params(format!("TX decode failed: {}", e))
                    })?;

                let txid_hex = self
                    .mempool
                    .submit_transaction(&tx)
                    .await
                    .map_err(abtc_ports::RpcError::internal_error)?;

                Ok(Some(Value::String(txid_hex)))
            }
            "getrawtransaction" => {
                // Look up a transaction by txid.
                // Checks mempool first, then block store.
                let txid_hex = _params
                    .get(0)
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| abtc_ports::RpcError::invalid_params("missing txid"))?;
                let verbose = _params.get(1).and_then(|v| v.as_u64()).unwrap_or(0);

                let txid = abtc_domain::primitives::Txid::from_hex(txid_hex)
                    .ok_or_else(|| abtc_ports::RpcError::invalid_params("invalid txid"))?;

                // Try mempool first.
                let mempool_entry = self.mempool.get_mempool_entry(&txid).await;
                if let Some(entry) = mempool_entry {
                    if verbose == 0 {
                        let raw_hex = hex::encode(entry.tx.serialize());
                        return Ok(Some(Value::String(raw_hex)));
                    } else {
                        return Ok(Some(json!({
                            "txid": entry.tx.txid().to_hex_reversed(),
                            "hash": entry.tx.wtxid().to_hex_reversed(),
                            "version": entry.tx.version,
                            "size": entry.tx.serialize().len(),
                            "vsize": entry.tx.compute_vsize(),
                            "weight": entry.tx.compute_weight(),
                            "locktime": entry.tx.lock_time,
                            "vin": entry.tx.inputs.iter().map(|input| {
                                json!({
                                    "txid": input.previous_output.txid.to_hex_reversed(),
                                    "vout": input.previous_output.vout,
                                    "sequence": input.sequence
                                })
                            }).collect::<Vec<Value>>(),
                            "vout": entry.tx.outputs.iter().enumerate().map(|(i, output)| {
                                json!({
                                    "value": output.value.as_sat() as f64 / 100_000_000.0,
                                    "n": i,
                                    "scriptPubKey": {
                                        "hex": hex::encode(output.script_pubkey.as_bytes())
                                    }
                                })
                            }).collect::<Vec<Value>>(),
                            "hex": hex::encode(entry.tx.serialize()),
                            "confirmations": 0
                        })));
                    }
                }

                // Not in mempool — transaction not found (block store lookup would go here).
                Err(abtc_ports::RpcError {
                    code: -5,
                    message: "No such mempool or blockchain transaction. Use gettxoutsetinfo to query for unspent outputs.".to_string(),
                    data: None,
                })
            }
            "gettxoutsetinfo" => {
                let info = self
                    .chain_state
                    .get_utxo_set_info()
                    .await
                    .map_err(|e| abtc_ports::RpcError::internal_error(e.to_string()))?;

                let total_btc = info.total_amount.as_sat() as f64 / 100_000_000.0;

                Ok(Some(json!({
                    "height": info.height,
                    "bestblock": info.best_block.to_hex_reversed(),
                    "txouts": info.txout_count,
                    "total_amount": total_btc,
                    "hash_serialized_2": "0000000000000000000000000000000000000000000000000000000000000000",
                    "disk_size": 0,
                    "bogosize": info.txout_count * 50
                })))
            }
            "estimatesmartfee" => {
                let conf_target = _params.get(0).and_then(|v| v.as_u64()).unwrap_or(6) as u32;
                let _estimate_mode = _params
                    .get(1)
                    .and_then(|v| v.as_str())
                    .unwrap_or("conservative");

                let estimator = self.fee_estimator.read().await;
                let fee_rate_sat_vb = estimator.estimate_fee(conf_target);
                drop(estimator);

                // Bitcoin Core returns fee rate in BTC/kvB (per 1000 virtual bytes).
                // fee_rate_sat_vb is in sat/vB, so: BTC/kvB = sat/vB * 1000 / 100_000_000
                let feerate_btc_kvb = fee_rate_sat_vb * 1000.0 / 100_000_000.0;

                let mut result = json!({
                    "feerate": feerate_btc_kvb,
                    "blocks": conf_target
                });

                // If we have no data, include an errors array like Bitcoin Core does
                if fee_rate_sat_vb <= 1.0 {
                    result["errors"] = json!(["Insufficient data or no feerate found"]);
                }

                Ok(Some(result))
            }
            "estimaterawfee" => {
                let conf_target = _params.get(0).and_then(|v| v.as_u64()).unwrap_or(6) as u32;

                let estimator = self.fee_estimator.read().await;
                let fee_rate = estimator.estimate_fee(conf_target);
                let (p10, p25, p50, p75, p90) = estimator.fee_rate_percentiles();
                drop(estimator);

                Ok(Some(json!({
                    "short": {
                        "feerate": fee_rate * 1000.0 / 100_000_000.0,
                        "decay": 0.998,
                        "scale": 1,
                        "pass": {
                            "startrange": 1.0,
                            "endrange": 10000.0,
                            "totalconfirmed": 0.0,
                            "inmempool": 0.0,
                            "leftmempool": 0.0
                        },
                        "fail": {
                            "startrange": 0.0,
                            "endrange": 0.0,
                            "totalconfirmed": 0.0,
                            "inmempool": 0.0,
                            "leftmempool": 0.0
                        }
                    },
                    "medium": {
                        "feerate": fee_rate * 1000.0 / 100_000_000.0,
                        "decay": 0.998,
                        "scale": 2
                    },
                    "long": {
                        "feerate": fee_rate * 1000.0 / 100_000_000.0,
                        "decay": 0.998,
                        "scale": 4
                    },
                    "percentiles": {
                        "p10": p10,
                        "p25": p25,
                        "p50": p50,
                        "p75": p75,
                        "p90": p90
                    }
                })))
            }
            _ => Ok(None), // Let another handler try
        }
    }
}

/// RPC handler for wallet operations
pub struct WalletRpcHandler {
    wallet: Arc<dyn abtc_ports::WalletPort>,
}

impl WalletRpcHandler {
    /// Create a new wallet RPC handler.
    pub fn new(wallet: Arc<dyn abtc_ports::WalletPort>) -> Self {
        WalletRpcHandler { wallet }
    }
}

#[async_trait]
impl RpcHandler for WalletRpcHandler {
    async fn handle_request(
        &self,
        method: &str,
        params: &Value,
    ) -> Result<Option<Value>, abtc_ports::RpcError> {
        match method {
            "getbalance" => {
                let balance = self
                    .wallet
                    .get_balance()
                    .await
                    .map_err(|e| abtc_ports::RpcError::internal_error(e.to_string()))?;
                // Return confirmed balance in BTC
                let btc = balance.confirmed.as_sat() as f64 / 100_000_000.0;
                Ok(Some(json!(btc)))
            }
            "getwalletinfo" => {
                let balance = self
                    .wallet
                    .get_balance()
                    .await
                    .map_err(|e| abtc_ports::RpcError::internal_error(e.to_string()))?;
                Ok(Some(json!({
                    "walletname": "default",
                    "walletversion": 1,
                    "format": "memory",
                    "balance": balance.confirmed.as_sat() as f64 / 100_000_000.0,
                    "unconfirmed_balance": balance.unconfirmed.as_sat() as f64 / 100_000_000.0,
                    "immature_balance": balance.immature.as_sat() as f64 / 100_000_000.0,
                    "txcount": 0,
                    "keypoolsize": 0,
                    "paytxfee": 0.0,
                    "private_keys_enabled": true
                })))
            }
            "getnewaddress" => {
                let label = params.get(0).and_then(|v| v.as_str());
                let address = self
                    .wallet
                    .get_new_address(label)
                    .await
                    .map_err(|e| abtc_ports::RpcError::internal_error(e.to_string()))?;
                Ok(Some(Value::String(address)))
            }
            "listunspent" => {
                let min_conf = params.get(0).and_then(|v| v.as_u64()).unwrap_or(1) as u32;
                let utxos = self
                    .wallet
                    .list_unspent(min_conf, None)
                    .await
                    .map_err(|e| abtc_ports::RpcError::internal_error(e.to_string()))?;
                let result: Vec<Value> = utxos
                    .iter()
                    .map(|u| {
                        json!({
                            "txid": u.outpoint.txid.to_hex_reversed(),
                            "vout": u.outpoint.vout,
                            "amount": u.output.value.as_sat() as f64 / 100_000_000.0,
                            "confirmations": u.confirmations,
                            "spendable": true,
                            "solvable": true
                        })
                    })
                    .collect();
                Ok(Some(json!(result)))
            }
            "importprivkey" => {
                let wif = params
                    .get(0)
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| abtc_ports::RpcError::invalid_params("missing WIF key"))?;
                let label = params.get(1).and_then(|v| v.as_str());
                let rescan = params.get(2).and_then(|v| v.as_bool()).unwrap_or(true);
                self.wallet
                    .import_key(wif, label, rescan)
                    .await
                    .map_err(|e| abtc_ports::RpcError::internal_error(e.to_string()))?;
                Ok(Some(Value::Null))
            }
            _ => Ok(None),
        }
    }
}

/// RPC handler for mining operations
pub struct MiningRpcHandler {
    mining: Arc<MiningService>,
}

impl MiningRpcHandler {
    /// Create a new mining RPC handler.
    pub fn new(mining: Arc<MiningService>) -> Self {
        MiningRpcHandler { mining }
    }
}

#[async_trait]
impl RpcHandler for MiningRpcHandler {
    async fn handle_request(
        &self,
        method: &str,
        _params: &Value,
    ) -> Result<Option<Value>, abtc_ports::RpcError> {
        match method {
            "getblocktemplate" => {
                let template = self
                    .mining
                    .generate_block_template(&Script::new())
                    .await
                    .map_err(abtc_ports::RpcError::internal_error)?;

                let total_fees: i64 = template.fees.iter().map(|f| f.as_sat()).sum();

                Ok(Some(json!({
                    "version": template.block.header.version,
                    "previousblockhash": template.block.header.prev_block_hash.to_hex_reversed(),
                    "transactions": template.block.transactions.len() - 1, // Exclude coinbase
                    "coinbaseaux": {},
                    "coinbasevalue": template.block.transactions[0].total_output_value().as_sat(),
                    "longpollid": template.block.header.prev_block_hash.to_hex_reversed(),
                    "target": format!("{:08x}", template.target),
                    "mintime": template.block.header.time,
                    "mutable": ["time", "transactions", "prevblock"],
                    "noncerange": "00000000ffffffff",
                    "sigoplimit": 20000,
                    "sizelimit": 4000000,
                    "weightlimit": 4000000,
                    "curtime": template.block.header.time,
                    "bits": format!("{:08x}", template.target),
                    "height": template.height,
                    "fees": total_fees
                })))
            }
            "submitblock" => {
                // TODO: Parse block from hex params
                Ok(Some(Value::Null))
            }
            "getmininginfo" => Ok(Some(json!({
                "blocks": 0,
                "difficulty": 1.0,
                "networkhashps": 0,
                "pooledtx": 0,
                "chain": "main",
                "warnings": ""
            }))),
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use abtc_domain::primitives::{Amount, OutPoint, Transaction, TxIn, TxOut, Txid};
    use abtc_domain::script::Script;
    use std::sync::Arc;

    #[test]
    fn test_tx_hex_roundtrip() {
        // Build a simple transaction, serialize to hex, deserialize back.
        let tx = Transaction::v1(
            vec![TxIn::final_input(
                OutPoint::new(Txid::zero(), 0),
                Script::new(),
            )],
            vec![TxOut::new(Amount::from_sat(50_000), Script::new())],
            0,
        );

        let raw = tx.serialize();
        let hex_str = hex::encode(&raw);

        let decoded_bytes = hex::decode(&hex_str).unwrap();
        let (decoded_tx, _) = Transaction::deserialize(&decoded_bytes).unwrap();
        assert_eq!(decoded_tx.txid(), tx.txid());
    }

    #[test]
    fn test_invalid_hex_detection() {
        let bad_hex = "zzzz";
        assert!(hex::decode(bad_hex).is_err());
    }

    #[tokio::test]
    async fn test_estimatesmartfee_default_target() {
        use crate::fee_estimator::FeeEstimator;
        use tokio::sync::RwLock;

        let estimator = Arc::new(RwLock::new(FeeEstimator::new()));

        // With no data, should still return a result with the minimum fee rate
        let est = estimator.read().await;
        let fee_rate = est.estimate_fee(6);
        drop(est);

        // Minimum fee rate is 1.0 sat/vB
        assert!(fee_rate >= 1.0);

        // Verify BTC/kvB conversion: 1.0 sat/vB * 1000 / 100_000_000 = 0.00001
        let btc_kvb = fee_rate * 1000.0 / 100_000_000.0;
        assert!((btc_kvb - 0.00001).abs() < 1e-10);
    }

    #[tokio::test]
    async fn test_estimatesmartfee_with_data() {
        use crate::fee_estimator::FeeEstimator;
        use tokio::sync::RwLock;

        let estimator = Arc::new(RwLock::new(FeeEstimator::new()));

        // Feed some blocks with varying fee rates
        {
            let mut est = estimator.write().await;
            for height in 1..=20 {
                let fees: Vec<(Amount, usize, u32)> = (0..10)
                    .map(|i| {
                        let fee = Amount::from_sat(((height * 10 + i) * 200) as i64);
                        let vsize = 200usize;
                        (fee, vsize, 1u32) // all confirmed in 1 block
                    })
                    .collect();
                est.process_block(height, &fees);
            }
        }

        let est = estimator.read().await;
        let fee_rate = est.estimate_fee(6);
        drop(est);

        // After processing data, should return a fee rate above minimum
        assert!(fee_rate >= 1.0);
    }

    #[tokio::test]
    async fn test_gettxoutsetinfo_empty() {
        use abtc_ports::ChainStateStore;

        // Create a mock chain state store
        let chain_state = Arc::new(abtc_adapters::storage::InMemoryChainStateStore::new());

        // Add a UTXO
        use abtc_domain::primitives::Amount;
        let txid = Txid::zero();
        let entry = abtc_ports::UtxoEntry {
            output: TxOut::new(Amount::from_sat(50_000), Script::new()),
            height: 1,
            is_coinbase: false,
        };
        chain_state
            .write_utxo_set(vec![(txid, 0, entry)], vec![])
            .await
            .unwrap();
        chain_state
            .write_chain_tip(abtc_domain::primitives::BlockHash::zero(), 5)
            .await
            .unwrap();

        let info = chain_state.get_utxo_set_info().await.unwrap();
        assert_eq!(info.txout_count, 1);
        assert_eq!(info.total_amount.as_sat(), 50_000);
        assert_eq!(info.height, 5);
    }

    #[test]
    fn test_block_index_height_lookup() {
        use crate::block_index::BlockIndex;
        use abtc_domain::primitives::{BlockHash, BlockHeader, Hash256};

        let mut index = BlockIndex::new();
        let genesis = BlockHeader {
            version: 1,
            prev_block_hash: BlockHash::zero(),
            merkle_root: Hash256::zero(),
            time: 1231006505,
            bits: 0x1d00ffff,
            nonce: 0,
        };
        let genesis_hash = genesis.block_hash();
        index.init_genesis(genesis);

        // Height 0 → genesis
        assert_eq!(index.get_hash_at_height(0), Some(genesis_hash));

        // Add block at height 1
        let h1 = BlockHeader {
            version: 1,
            prev_block_hash: genesis_hash,
            merkle_root: Hash256::from_bytes([1u8; 32]),
            time: 1231006506,
            bits: 0x1d00ffff,
            nonce: 1,
        };
        let (h1_hash, _) = index.add_header(h1).unwrap();

        // Add block at height 2
        let h2 = BlockHeader {
            version: 1,
            prev_block_hash: h1_hash,
            merkle_root: Hash256::from_bytes([2u8; 32]),
            time: 1231006507,
            bits: 0x1d00ffff,
            nonce: 2,
        };
        let (h2_hash, _) = index.add_header(h2).unwrap();

        // All heights should be resolvable
        assert_eq!(index.get_hash_at_height(0), Some(genesis_hash));
        assert_eq!(index.get_hash_at_height(1), Some(h1_hash));
        assert_eq!(index.get_hash_at_height(2), Some(h2_hash));
        assert_eq!(index.get_hash_at_height(3), None);
    }

    #[test]
    fn test_tx_verbose_fields() {
        // Verify that we can compute all the fields needed for verbose getrawtransaction.
        let tx = Transaction::v1(
            vec![TxIn::final_input(
                OutPoint::new(Txid::zero(), 0),
                Script::new(),
            )],
            vec![
                TxOut::new(Amount::from_sat(30_000), Script::new()),
                TxOut::new(Amount::from_sat(20_000), Script::new()),
            ],
            0,
        );

        assert_eq!(tx.version, 1);
        assert_eq!(tx.outputs.len(), 2);
        assert!(tx.compute_vsize() > 0);
        assert!(tx.compute_weight() > 0);
        assert!(!tx.txid().to_hex_reversed().is_empty());
    }
}

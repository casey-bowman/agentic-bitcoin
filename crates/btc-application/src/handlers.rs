//! Event and command handlers for the application layer
//!
//! Handles RPC requests, network messages, and other application events.

use crate::services::{BlockchainService, MempoolService, MiningService};
use btc_domain::script::Script;
use btc_ports::RpcHandler;
use async_trait::async_trait;
use serde_json::{json, Value};
use std::sync::Arc;

/// RPC handler for blockchain queries and operations
pub struct BlockchainRpcHandler {
    blockchain: Arc<BlockchainService>,
    mempool: Arc<MempoolService>,
}

impl BlockchainRpcHandler {
    pub fn new(blockchain: Arc<BlockchainService>, mempool: Arc<MempoolService>) -> Self {
        BlockchainRpcHandler { blockchain, mempool }
    }
}

#[async_trait]
impl RpcHandler for BlockchainRpcHandler {
    async fn handle_request(&self, method: &str, _params: &Value) -> Result<Option<Value>, btc_ports::RpcError> {
        match method {
            "getblockcount" => {
                let info = self.blockchain
                    .get_chain_info()
                    .await
                    .map_err(|e| btc_ports::RpcError::internal_error(e))?;
                Ok(Some(Value::Number(info.height.into())))
            }
            "getbestblockhash" => {
                let info = self.blockchain
                    .get_chain_info()
                    .await
                    .map_err(|e| btc_ports::RpcError::internal_error(e))?;
                Ok(Some(Value::String(info.best_block_hash.to_hex_reversed())))
            }
            "getblockchaininfo" => {
                let info = self.blockchain
                    .get_chain_info()
                    .await
                    .map_err(|e| btc_ports::RpcError::internal_error(e))?;
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
                let mempool_info = self.mempool
                    .get_mempool_info()
                    .await
                    .map_err(|e| btc_ports::RpcError::internal_error(e))?;
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
                let contents = self.mempool
                    .get_mempool_contents()
                    .await
                    .map_err(|e| btc_ports::RpcError::internal_error(e))?;
                Ok(Some(json!(contents)))
            }
            "sendrawtransaction" => {
                // TODO: Parse hex-encoded transaction from params and submit
                Ok(Some(Value::String("not_implemented".to_string())))
            }
            "estimatesmartfee" => {
                let fee = self.mempool
                    .estimate_fee(6)
                    .await
                    .map_err(|e| btc_ports::RpcError::internal_error(e))?;
                Ok(Some(json!({
                    "feerate": fee / 100_000_000.0, // Convert sat/byte to BTC/kB
                    "blocks": 6
                })))
            }
            _ => Ok(None), // Let another handler try
        }
    }
}

/// RPC handler for mining operations
pub struct MiningRpcHandler {
    mining: Arc<MiningService>,
}

impl MiningRpcHandler {
    pub fn new(mining: Arc<MiningService>) -> Self {
        MiningRpcHandler { mining }
    }
}

#[async_trait]
impl RpcHandler for MiningRpcHandler {
    async fn handle_request(&self, method: &str, _params: &Value) -> Result<Option<Value>, btc_ports::RpcError> {
        match method {
            "getblocktemplate" => {
                let template = self.mining
                    .generate_block_template(&Script::new())
                    .await
                    .map_err(|e| btc_ports::RpcError::internal_error(e))?;

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
            "getmininginfo" => {
                Ok(Some(json!({
                    "blocks": 0,
                    "difficulty": 1.0,
                    "networkhashps": 0,
                    "pooledtx": 0,
                    "chain": "main",
                    "warnings": ""
                })))
            }
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handler_creation() {
        // Note: Real tests would use a test framework with mocks
    }
}

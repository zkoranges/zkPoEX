// SPDX-License-Identifier: MIT
//! Minimal JSON-RPC client for Ethereum node communication.
//!
//! Uses raw HTTP requests to avoid dependency conflicts between
//! alloy (RPC) and revm (EVM).

use std::sync::atomic::{AtomicU64, Ordering};

use alloy_primitives::{Address, Bytes, B256, U256};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::debug;

/// A minimal Ethereum JSON-RPC client.
#[derive(Clone)]
pub struct RpcClient {
    url: String,
    client: reqwest::Client,
    id: std::sync::Arc<AtomicU64>,
}

#[derive(Serialize)]
struct JsonRpcRequest<'a> {
    jsonrpc: &'a str,
    method: &'a str,
    params: serde_json::Value,
    id: u64,
}

#[derive(Deserialize)]
struct JsonRpcResponse {
    result: Option<serde_json::Value>,
    error: Option<JsonRpcError>,
}

#[derive(Deserialize, Debug)]
struct JsonRpcError {
    code: i64,
    message: String,
}

impl RpcClient {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            client: reqwest::Client::new(),
            id: std::sync::Arc::new(AtomicU64::new(1)),
        }
    }

    /// Maximum number of retries for transient failures.
    const MAX_RETRIES: u32 = 5;
    /// Initial backoff delay in milliseconds.
    const INITIAL_BACKOFF_MS: u64 = 1000;
    /// Maximum backoff delay in milliseconds.
    const MAX_BACKOFF_MS: u64 = 30_000;

    async fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
        let id = self.id.fetch_add(1, Ordering::Relaxed);
        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            method,
            params,
            id,
        };

        debug!(method, %id, "RPC request");

        let mut last_err = None;
        for attempt in 0..=Self::MAX_RETRIES {
            if attempt > 0 {
                let backoff = std::cmp::min(
                    Self::INITIAL_BACKOFF_MS * 2u64.pow(attempt - 1),
                    Self::MAX_BACKOFF_MS,
                );
                debug!(
                    method,
                    attempt,
                    backoff_ms = backoff,
                    "Retrying RPC request"
                );
                tokio::time::sleep(std::time::Duration::from_millis(backoff)).await;
            }

            let resp = self.client.post(&self.url).json(&request).send().await;

            let response = match resp {
                Ok(r) => r,
                Err(e) if e.is_timeout() || e.is_connect() => {
                    last_err = Some(anyhow::anyhow!(e).context(format!(
                        "RPC request to {} failed (attempt {})",
                        method,
                        attempt + 1
                    )));
                    continue;
                }
                Err(e) => {
                    return Err(
                        anyhow::anyhow!(e).context(format!("RPC request to {} failed", method))
                    );
                }
            };

            // Retry on 429 (rate limited) and 5xx server errors
            if response.status() == 429 || response.status().is_server_error() {
                last_err = Some(anyhow::anyhow!(
                    "RPC {} returned status {} (attempt {})",
                    method,
                    response.status(),
                    attempt + 1
                ));
                continue;
            }

            let body: JsonRpcResponse = response
                .json()
                .await
                .with_context(|| format!("Failed to parse RPC response for {}", method))?;

            if let Some(err) = body.error {
                // Retry on rate-limit JSON-RPC errors
                if err.code == -32005 || err.code == 429 {
                    last_err = Some(anyhow::anyhow!(
                        "RPC rate limit for {} (code {}, attempt {})",
                        method,
                        err.code,
                        attempt + 1
                    ));
                    continue;
                }
                anyhow::bail!(
                    "RPC error for {}: {} (code {})",
                    method,
                    err.message,
                    err.code
                );
            }

            return body
                .result
                .with_context(|| format!("RPC response for {} has no result", method));
        }

        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("RPC {} failed after retries", method)))
    }

    /// Get the chain ID.
    pub async fn get_chain_id(&self) -> Result<u64> {
        let result = self.call("eth_chainId", serde_json::json!([])).await?;
        let hex_str = result
            .as_str()
            .context("eth_chainId result is not a string")?;
        parse_hex_u64(hex_str).context("parse chain_id")
    }

    /// Get balance of an address at a specific block.
    pub async fn get_balance(&self, address: Address, block_number: u64) -> Result<U256> {
        let result = self
            .call(
                "eth_getBalance",
                serde_json::json!([format!("{address:?}"), format!("0x{block_number:x}")]),
            )
            .await?;
        let hex_str = result
            .as_str()
            .context("eth_getBalance result is not a string")?;
        parse_hex_u256(hex_str).context("parse balance")
    }

    /// Get transaction count (nonce) of an address at a specific block.
    pub async fn get_transaction_count(&self, address: Address, block_number: u64) -> Result<u64> {
        let result = self
            .call(
                "eth_getTransactionCount",
                serde_json::json!([format!("{address:?}"), format!("0x{block_number:x}")]),
            )
            .await?;
        let hex_str = result
            .as_str()
            .context("eth_getTransactionCount result is not a string")?;
        parse_hex_u64(hex_str).context("parse nonce")
    }

    /// Get code at an address at a specific block.
    pub async fn get_code(&self, address: Address, block_number: u64) -> Result<Vec<u8>> {
        let result = self
            .call(
                "eth_getCode",
                serde_json::json!([format!("{address:?}"), format!("0x{block_number:x}")]),
            )
            .await?;
        let hex_str = result
            .as_str()
            .context("eth_getCode result is not a string")?;
        parse_hex_bytes(hex_str).context("parse code")
    }

    /// Get storage value at a specific slot for an address at a specific block.
    pub async fn get_storage_at(
        &self,
        address: Address,
        slot: U256,
        block_number: u64,
    ) -> Result<U256> {
        let slot_hex = format!("0x{slot:064x}");
        let result = self
            .call(
                "eth_getStorageAt",
                serde_json::json!([
                    format!("{address:?}"),
                    slot_hex,
                    format!("0x{block_number:x}")
                ]),
            )
            .await?;
        let hex_str = result
            .as_str()
            .context("eth_getStorageAt result is not a string")?;
        parse_hex_u256(hex_str).context("parse storage value")
    }

    /// Call a contract and parse the return value as U256.
    pub async fn eth_call_u256(&self, to: Address, data: Bytes, block_number: u64) -> Result<U256> {
        let data_hex = format!("0x{}", hex::encode(data));
        let result = self
            .call(
                "eth_call",
                serde_json::json!([
                    {
                        "to": format!("{to:?}"),
                        "data": data_hex,
                    },
                    format!("0x{block_number:x}")
                ]),
            )
            .await?;
        let hex_str = result.as_str().context("eth_call result is not a string")?;
        parse_hex_u256(hex_str).context("parse eth_call u256")
    }

    /// Get a block by number (header only, no transactions).
    pub async fn get_block_by_number(&self, block_number: u64) -> Result<BlockHeader> {
        let result = self
            .call(
                "eth_getBlockByNumber",
                serde_json::json!([format!("0x{block_number:x}"), false]),
            )
            .await?;

        let obj = result.as_object().context("block is not an object")?;

        Ok(BlockHeader {
            hash: parse_b256(
                obj.get("hash")
                    .and_then(|v| v.as_str())
                    .context("no hash")?,
            )?,
            number: parse_hex_u64(
                obj.get("number")
                    .and_then(|v| v.as_str())
                    .context("no number")?,
            )?,
            timestamp: parse_hex_u64(
                obj.get("timestamp")
                    .and_then(|v| v.as_str())
                    .context("no timestamp")?,
            )?,
            beneficiary: parse_address(
                obj.get("miner")
                    .and_then(|v| v.as_str())
                    .context("no miner")?,
            )?,
            difficulty: parse_hex_u256(
                obj.get("difficulty")
                    .and_then(|v| v.as_str())
                    .context("no difficulty")?,
            )?,
            gas_limit: parse_hex_u64(
                obj.get("gasLimit")
                    .and_then(|v| v.as_str())
                    .context("no gasLimit")?,
            )?,
            base_fee_per_gas: obj
                .get("baseFeePerGas")
                .and_then(|v| v.as_str())
                .map(parse_hex_u64)
                .transpose()?,
            mix_hash: parse_b256(
                obj.get("mixHash")
                    .and_then(|v| v.as_str())
                    .context("no mixHash")?,
            )?,
            excess_blob_gas: obj
                .get("excessBlobGas")
                .and_then(|v| v.as_str())
                .map(parse_hex_u64)
                .transpose()?,
            state_root: parse_b256(
                obj.get("stateRoot")
                    .and_then(|v| v.as_str())
                    .context("no stateRoot")?,
            )?,
        })
    }

    /// Call `eth_getProof` for an address with a set of storage keys at a block.
    pub async fn get_proof(
        &self,
        address: Address,
        storage_keys: &[U256],
        block_number: u64,
    ) -> Result<EthGetProofResponse> {
        let keys: Vec<String> = storage_keys.iter().map(|k| format!("0x{k:064x}")).collect();

        let result = self
            .call(
                "eth_getProof",
                serde_json::json!([format!("{address:?}"), keys, format!("0x{block_number:x}")]),
            )
            .await?;

        let obj = result
            .as_object()
            .context("eth_getProof result is not an object")?;

        let address = parse_address(
            obj.get("address")
                .and_then(|v| v.as_str())
                .context("no address in proof")?,
        )?;

        let nonce = parse_hex_u64(
            obj.get("nonce")
                .and_then(|v| v.as_str())
                .context("no nonce in proof")?,
        )?;

        let balance = parse_hex_u256(
            obj.get("balance")
                .and_then(|v| v.as_str())
                .context("no balance in proof")?,
        )?;

        let storage_hash = parse_b256(
            obj.get("storageHash")
                .and_then(|v| v.as_str())
                .context("no storageHash in proof")?,
        )?;

        let code_hash = parse_b256(
            obj.get("codeHash")
                .and_then(|v| v.as_str())
                .context("no codeHash in proof")?,
        )?;

        let account_proof = obj
            .get("accountProof")
            .and_then(|v| v.as_array())
            .context("no accountProof array")?
            .iter()
            .map(|v| {
                let s = v.as_str().context("accountProof item is not a string")?;
                parse_hex_bytes(s).context("parse accountProof node")
            })
            .collect::<Result<Vec<Vec<u8>>>>()?;

        let storage_proof = obj
            .get("storageProof")
            .and_then(|v| v.as_array())
            .context("no storageProof array")?
            .iter()
            .map(|entry| {
                let entry_obj = entry
                    .as_object()
                    .context("storageProof entry is not an object")?;
                let key = parse_hex_u256(
                    entry_obj
                        .get("key")
                        .and_then(|v| v.as_str())
                        .context("no key")?,
                )?;
                let value = parse_hex_u256(
                    entry_obj
                        .get("value")
                        .and_then(|v| v.as_str())
                        .context("no value")?,
                )?;
                let proof = entry_obj
                    .get("proof")
                    .and_then(|v| v.as_array())
                    .context("no proof array in storageProof")?
                    .iter()
                    .map(|v| {
                        let s = v.as_str().context("proof item is not a string")?;
                        parse_hex_bytes(s).context("parse storage proof node")
                    })
                    .collect::<Result<Vec<Vec<u8>>>>()?;
                Ok(StorageProofItem { key, value, proof })
            })
            .collect::<Result<Vec<StorageProofItem>>>()?;

        Ok(EthGetProofResponse {
            address,
            nonce,
            balance,
            storage_hash,
            code_hash,
            account_proof,
            storage_proof,
        })
    }
}

/// Parsed block header fields needed for EVM execution.
#[derive(Debug, Clone)]
pub struct BlockHeader {
    pub hash: B256,
    pub number: u64,
    pub timestamp: u64,
    pub beneficiary: Address,
    pub difficulty: U256,
    pub gas_limit: u64,
    pub base_fee_per_gas: Option<u64>,
    pub mix_hash: B256,
    pub excess_blob_gas: Option<u64>,
    pub state_root: B256,
}

/// Response from `eth_getProof` for a single account.
#[derive(Debug, Clone)]
pub struct EthGetProofResponse {
    pub address: Address,
    pub nonce: u64,
    pub balance: U256,
    pub storage_hash: B256,
    pub code_hash: B256,
    pub account_proof: Vec<Vec<u8>>,
    pub storage_proof: Vec<StorageProofItem>,
}

/// A single storage proof item within an `eth_getProof` response.
#[derive(Debug, Clone)]
pub struct StorageProofItem {
    pub key: U256,
    pub value: U256,
    pub proof: Vec<Vec<u8>>,
}

// --- Hex parsing utilities ---

fn parse_hex_u64(s: &str) -> Result<u64> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(s, 16).with_context(|| format!("invalid hex u64: {s}"))
}

fn parse_hex_u256(s: &str) -> Result<U256> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    // Pad to 64 chars for U256
    let padded = format!("{:0>64}", s);
    let bytes = hex::decode(&padded).with_context(|| format!("invalid hex U256: {s}"))?;
    Ok(U256::from_be_slice(&bytes))
}

fn parse_hex_bytes(s: &str) -> Result<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.is_empty() {
        return Ok(Vec::new());
    }
    hex::decode(s).context("invalid hex bytes")
}

fn parse_b256(s: &str) -> Result<B256> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).with_context(|| format!("invalid hex B256: {s}"))?;
    if bytes.len() != 32 {
        anyhow::bail!("B256 must be 32 bytes, got {}", bytes.len());
    }
    Ok(B256::from_slice(&bytes))
}

fn parse_address(s: &str) -> Result<Address> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).with_context(|| format!("invalid hex address: {s}"))?;
    if bytes.len() != 20 {
        anyhow::bail!("Address must be 20 bytes, got {}", bytes.len());
    }
    Ok(Address::from_slice(&bytes))
}

// SPDX-License-Identifier: MIT
use std::collections::BTreeMap;

use alloy_primitives::{Address, U256};
use anyhow::{Context, Result};
use futures::stream::{self, StreamExt};
use revm::primitives::{AccountInfo, Bytecode, KECCAK_EMPTY};
use tracing::info;

use bridge_types::conversions::{addr_to_fixed, b256_to_fixed, u256_to_fixed};
use bridge_types::types::{
    EIP1186AccountProof, RkyvAccount, RkyvBlockEnv, RkyvMemDB, StorageProofEntry,
};

use crate::proxy_db::AccessTrace;
use crate::rpc::RpcClient;

/// Fetch all data referenced in the access trace from the RPC provider,
/// using parallel requests with bounded concurrency.
///
/// Returns a fully populated `RkyvMemDB` containing only the state needed
/// for the exploit execution.
pub async fn fetch_all_parallel(
    client: &RpcClient,
    trace: &AccessTrace,
    block_number: u64,
) -> Result<RkyvMemDB> {
    info!(
        accounts = trace.accounts.len(),
        storage_slots = trace.storage.len(),
        block_hashes = trace.block_hashes.len(),
        "Fetching state from RPC"
    );

    // Fetch accounts in parallel
    let account_addrs: Vec<Address> = trace.accounts.iter().copied().collect();
    let accounts_data: Vec<(Address, Result<AccountInfo>)> = stream::iter(account_addrs)
        .map(|addr| {
            let client = client.clone();
            async move {
                let result = fetch_account(&client, addr, block_number).await;
                (addr, result)
            }
        })
        .buffer_unordered(20)
        .collect()
        .await;

    // Fetch storage slots in parallel
    let storage_keys: Vec<(Address, U256)> = trace.storage.iter().copied().collect();
    let storage_data: Vec<((Address, U256), Result<U256>)> = stream::iter(storage_keys)
        .map(|key| {
            let client = client.clone();
            async move {
                let result = client.get_storage_at(key.0, key.1, block_number).await;
                (key, result)
            }
        })
        .buffer_unordered(20)
        .collect()
        .await;

    // Fetch block hashes in parallel
    let block_nums: Vec<u64> = trace.block_hashes.iter().copied().collect();
    let block_data: Vec<(u64, Result<[u8; 32]>)> = stream::iter(block_nums)
        .map(|num| {
            let client = client.clone();
            async move {
                let result = client
                    .get_block_by_number(num)
                    .await
                    .map(|h| b256_to_fixed(h.hash));
                (num, result)
            }
        })
        .buffer_unordered(20)
        .collect()
        .await;

    // Fetch code for accounts that have code
    let mut code_map: BTreeMap<Address, Vec<u8>> = BTreeMap::new();
    let mut account_infos: BTreeMap<Address, AccountInfo> = BTreeMap::new();

    for (addr, result) in accounts_data {
        let info = result.with_context(|| format!("failed to fetch account {addr:?}"))?;
        if info.code_hash != KECCAK_EMPTY && info.code_hash != alloy_primitives::B256::ZERO {
            let code = client
                .get_code(addr, block_number)
                .await
                .with_context(|| format!("failed to fetch code for {addr:?}"))?;
            code_map.insert(addr, code);
        }
        account_infos.insert(addr, info);
    }

    // Build storage map
    let mut storage_map: BTreeMap<Address, BTreeMap<[u8; 32], [u8; 32]>> = BTreeMap::new();
    for ((addr, key), result) in storage_data {
        let value =
            result.with_context(|| format!("failed to fetch storage {addr:?} slot {key}"))?;
        storage_map
            .entry(addr)
            .or_default()
            .insert(u256_to_fixed(key), u256_to_fixed(value));
    }

    // Build block hashes map
    let mut block_hashes: BTreeMap<u64, [u8; 32]> = BTreeMap::new();
    for (num, result) in block_data {
        let hash = result.with_context(|| format!("failed to fetch block hash {num}"))?;
        block_hashes.insert(num, hash);
    }

    // Assemble RkyvMemDB
    let mut accounts: BTreeMap<[u8; 20], RkyvAccount> = BTreeMap::new();
    for (addr, info) in &account_infos {
        let addr_fixed = addr_to_fixed(*addr);
        let code = code_map.get(addr).cloned();
        let storage = storage_map.remove(addr).unwrap_or_default();

        accounts.insert(
            addr_fixed,
            RkyvAccount {
                nonce: info.nonce,
                balance: u256_to_fixed(info.balance),
                code_hash: b256_to_fixed(info.code_hash),
                code,
                storage,
            },
        );
    }

    Ok(RkyvMemDB {
        accounts,
        block_hashes,
    })
}

/// Fetch block environment from the RPC.
pub async fn fetch_block_env(client: &RpcClient, block_number: u64) -> Result<RkyvBlockEnv> {
    let header = client
        .get_block_by_number(block_number)
        .await
        .context("failed to fetch block")?;

    let chain_id = client
        .get_chain_id()
        .await
        .context("failed to get chain id")?;

    Ok(RkyvBlockEnv {
        number: header.number,
        timestamp: header.timestamp,
        coinbase: addr_to_fixed(header.beneficiary),
        difficulty: u256_to_fixed(header.difficulty),
        gas_limit: header.gas_limit,
        basefee: u256_to_fixed(U256::from(header.base_fee_per_gas.unwrap_or(0))),
        prevrandao: Some(b256_to_fixed(header.mix_hash)),
        excess_blob_gas: header.excess_blob_gas,
        chain_id,
        state_root: b256_to_fixed(header.state_root),
    })
}

/// Fetch EIP-1186 proofs for all accounts and their storage keys in the access trace.
///
/// For each account in the trace, calls `eth_getProof` with all storage keys
/// that were accessed for that account.
pub async fn fetch_proofs_parallel(
    client: &RpcClient,
    trace: &AccessTrace,
    block_number: u64,
) -> Result<Vec<EIP1186AccountProof>> {
    // Group storage keys by address
    let mut storage_by_addr: std::collections::BTreeMap<Address, Vec<U256>> =
        std::collections::BTreeMap::new();
    for &(addr, key) in &trace.storage {
        storage_by_addr.entry(addr).or_default().push(key);
    }

    // Ensure all accounts are included (even those with no storage accesses)
    for &addr in &trace.accounts {
        storage_by_addr.entry(addr).or_default();
    }

    let entries: Vec<(Address, Vec<U256>)> = storage_by_addr.into_iter().collect();

    info!(
        accounts = entries.len(),
        "Fetching EIP-1186 proofs from RPC"
    );

    let proofs: Vec<(Address, Result<crate::rpc::EthGetProofResponse>)> = stream::iter(entries)
        .map(|(addr, keys)| {
            let client = client.clone();
            async move {
                let result = client.get_proof(addr, &keys, block_number).await;
                (addr, result)
            }
        })
        .buffer_unordered(20)
        .collect()
        .await;

    let mut result = Vec::new();
    for (addr, resp) in proofs {
        let resp = resp.with_context(|| format!("failed to fetch proof for {addr:?}"))?;
        result.push(EIP1186AccountProof {
            address: addr_to_fixed(resp.address),
            nonce: resp.nonce,
            balance: u256_to_fixed(resp.balance),
            storage_hash: b256_to_fixed(resp.storage_hash),
            code_hash: b256_to_fixed(resp.code_hash),
            account_proof: resp.account_proof,
            storage_proofs: resp
                .storage_proof
                .into_iter()
                .map(|sp| StorageProofEntry {
                    key: u256_to_fixed(sp.key),
                    value: u256_to_fixed(sp.value),
                    proof: sp.proof,
                })
                .collect(),
        });
    }

    Ok(result)
}

async fn fetch_account(
    client: &RpcClient,
    address: Address,
    block_number: u64,
) -> Result<AccountInfo> {
    let balance = client
        .get_balance(address, block_number)
        .await
        .with_context(|| format!("get_balance for {address:?}"))?;

    let nonce = client
        .get_transaction_count(address, block_number)
        .await
        .with_context(|| format!("get_transaction_count for {address:?}"))?;

    let code = client
        .get_code(address, block_number)
        .await
        .with_context(|| format!("get_code for {address:?}"))?;

    let code_hash = if code.is_empty() {
        KECCAK_EMPTY
    } else {
        use alloy_primitives::keccak256;
        keccak256(&code)
    };

    let bytecode = if code.is_empty() {
        Bytecode::default()
    } else {
        Bytecode::new_raw(alloy_primitives::Bytes::copy_from_slice(&code))
    };

    Ok(AccountInfo {
        balance,
        nonce,
        code_hash,
        code: Some(bytecode),
    })
}

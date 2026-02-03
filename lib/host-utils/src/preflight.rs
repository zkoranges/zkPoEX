// SPDX-License-Identifier: MIT
use std::cell::RefCell;

use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use anyhow::{Context, Result};
use revm::primitives::{AccountInfo, Bytecode, KECCAK_EMPTY};
use revm::DatabaseRef;
use tracing::info;

use bridge_types::conversions::{addr_to_fixed, fixed_to_u256, u256_to_fixed};
use bridge_types::types::{
    Assertion, DealRecord, ExploitInput, ExploitOptions, RkyvBlockEnv, RkyvMemDB,
};

use crate::fetcher::{fetch_all_parallel, fetch_block_env, fetch_proofs_parallel};
use crate::proxy_db::ProxyDB;
use crate::rpc::RpcClient;

use bridge_logic::db::MutableMemDB;
use bridge_logic::executor::{sim_exploit, sim_exploit_with_inspector};
use bridge_logic::hardfork::spec_id_from_chain;

/// An RPC-backed database for the preflight dry-run.
/// Uses a tokio runtime handle to make blocking RPC calls from `DatabaseRef`.
struct RpcDB {
    client: RpcClient,
    block_number: u64,
    handle: tokio::runtime::Handle,
    /// Inline cache to avoid redundant fetches during the dry-run.
    account_cache: RefCell<std::collections::HashMap<Address, Option<AccountInfo>>>,
    storage_cache: RefCell<std::collections::HashMap<(Address, U256), U256>>,
}

impl RpcDB {
    fn new(client: RpcClient, block_number: u64) -> Self {
        Self {
            client,
            block_number,
            handle: tokio::runtime::Handle::current(),
            account_cache: RefCell::new(std::collections::HashMap::new()),
            storage_cache: RefCell::new(std::collections::HashMap::new()),
        }
    }
}

impl DatabaseRef for RpcDB {
    type Error = anyhow::Error;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        if let Some(cached) = self.account_cache.borrow().get(&address) {
            return Ok(cached.clone());
        }

        let result = tokio::task::block_in_place(|| {
            self.handle.block_on(async {
                let balance = self
                    .client
                    .get_balance(address, self.block_number)
                    .await
                    .with_context(|| format!("get_balance for {address:?}"))?;

                let nonce = self
                    .client
                    .get_transaction_count(address, self.block_number)
                    .await
                    .with_context(|| format!("get_transaction_count for {address:?}"))?;

                let code = self
                    .client
                    .get_code(address, self.block_number)
                    .await
                    .with_context(|| format!("get_code for {address:?}"))?;

                let code_hash = if code.is_empty() {
                    KECCAK_EMPTY
                } else {
                    keccak256(&code)
                };

                let bytecode = if code.is_empty() {
                    Bytecode::default()
                } else {
                    Bytecode::new_raw(Bytes::copy_from_slice(&code))
                };

                Ok::<_, anyhow::Error>(Some(AccountInfo {
                    balance,
                    nonce,
                    code_hash,
                    code: Some(bytecode),
                }))
            })
        })?;

        self.account_cache
            .borrow_mut()
            .insert(address, result.clone());
        Ok(result)
    }

    fn code_by_hash_ref(&self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
        // Code is already embedded in AccountInfo from basic_ref
        Ok(Bytecode::default())
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        if let Some(cached) = self.storage_cache.borrow().get(&(address, index)) {
            return Ok(*cached);
        }

        let value = tokio::task::block_in_place(|| {
            self.handle.block_on(async {
                self.client
                    .get_storage_at(address, index, self.block_number)
                    .await
                    .with_context(|| format!("get_storage_at {address:?} slot {index}"))
            })
        })?;

        self.storage_cache
            .borrow_mut()
            .insert((address, index), value);
        Ok(value)
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        let header = tokio::task::block_in_place(|| {
            self.handle.block_on(async {
                self.client
                    .get_block_by_number(number)
                    .await
                    .with_context(|| format!("get block {number}"))
            })
        })?;

        Ok(header.hash)
    }
}

/// Build the complete `ExploitInput` for the ZK guest.
///
/// Steps:
/// 1. Fetch block environment from RPC
/// 2. Create RPC-backed DB, wrap in ProxyDB for access tracing
/// 3. Inject PoC contract + caller into the DB overlay
/// 4. Dry-run `sim_exploit` to discover touched state
/// 5. Parallel-fetch all discovered state from RPC
/// 6. Package into `ExploitInput`
pub async fn build_exploit_input(
    client: &RpcClient,
    block_number: u64,
    poc_bytecode: Vec<u8>,
    deals: Vec<DealRecord>,
    assertions: Vec<Assertion>,
    nonce: [u8; 32],
    caller: [u8; 20],
    contract_address: [u8; 20],
    gas_limit: u64,
    options: ExploitOptions,
    debug: bool,
) -> Result<(ExploitInput, RkyvBlockEnv)> {
    info!("Fetching block environment for block {block_number}");
    let block_env = fetch_block_env(client, block_number)
        .await
        .context("fetch_block_env")?;

    let chain_id = block_env.chain_id;
    let spec_id = spec_id_from_chain(chain_id, block_env.timestamp);
    info!(?spec_id, chain_id, "Determined hardfork spec");

    // Build RPC-backed DB with PoC injected for the dry-run.
    let rpc_db = RpcDB::new(client.clone(), block_number);

    // Create a mutable overlay: start from empty, inject PoC + caller + deals
    let mut overlay = MutableMemDB::from_rkyv(RkyvMemDB {
        accounts: std::collections::BTreeMap::new(),
        block_hashes: std::collections::BTreeMap::new(),
    });

    // Inject the PoC contract
    let contract_addr = Address::from(contract_address);
    let poc_code_hash = keccak256(&poc_bytecode);
    let poc_bytecode_obj = Bytecode::new_raw(Bytes::copy_from_slice(&poc_bytecode));
    overlay
        .codes
        .insert(poc_code_hash, Bytes::copy_from_slice(&poc_bytecode));
    overlay.accounts.insert(
        contract_addr,
        AccountInfo {
            balance: U256::ZERO,
            nonce: 1,
            code_hash: poc_code_hash,
            code: Some(poc_bytecode_obj),
        },
    );

    // Inject the caller with some ETH for gas
    let caller_addr = Address::from(caller);
    overlay.accounts.insert(
        caller_addr,
        AccountInfo {
            balance: U256::from(1_000_000_000_000_000_000u128), // 1 ETH
            nonce: 0,
            code_hash: KECCAK_EMPTY,
            code: Some(Bytecode::default()),
        },
    );

    // Apply deals to the overlay for the dry-run
    overlay.apply_deals(&deals);

    // Create a layered DB: overlay on top of RPC
    let layered = LayeredDB {
        overlay,
        fallback: rpc_db,
    };

    // Wrap in ProxyDB to trace all accesses
    let proxy = ProxyDB::new(layered);

    info!("Running preflight dry-run");
    let (result, debug_trace) = if debug {
        let (result, inspector) = sim_exploit_with_inspector(
            &proxy,
            &block_env,
            &poc_bytecode,
            gas_limit,
            caller_addr,
            contract_addr,
            spec_id,
            DebugInspector::default(),
        );
        (result, Some(format_debug_trace(&inspector)))
    } else {
        let result = sim_exploit(
            &proxy,
            &block_env,
            &poc_bytecode,
            gas_limit,
            caller_addr,
            contract_addr,
            spec_id,
        );
        (result, None)
    };

    let result = result.context("preflight dry-run failed")?;

    // Check that the dry-run succeeded
    match &result.result {
        revm::primitives::ExecutionResult::Success { .. } => {
            info!("Preflight dry-run succeeded");
        }
        revm::primitives::ExecutionResult::Revert { output, .. } => {
            let reason = decode_revert_reason(output.as_ref());
            if let Some(trace) = debug_trace {
                anyhow::bail!("Preflight dry-run reverted: {reason}\n\nDebug trace:\n{trace}");
            }
            anyhow::bail!("Preflight dry-run reverted: {reason}");
        }
        revm::primitives::ExecutionResult::Halt { reason, .. } => {
            if let Some(trace) = debug_trace {
                anyhow::bail!("Preflight dry-run halted: {reason:?}\n\nDebug trace:\n{trace}");
            }
            anyhow::bail!("Preflight dry-run halted: {reason:?}");
        }
    }

    let mut trace = proxy.into_trace();
    info!(
        accounts = trace.accounts.len(),
        storage = trace.storage.len(),
        block_hashes = trace.block_hashes.len(),
        "Preflight trace collected"
    );

    if !trace.block_hashes.is_empty() {
        anyhow::bail!(
            "BLOCKHASH opcode detected (blocks: {:?}). zkpoex disallows BLOCKHASH for soundness/performance.",
            trace.block_hashes
        );
    }

    // Ensure all assertion-targeted accounts/slots are fetched and proven.
    for assertion in &assertions {
        match assertion {
            Assertion::NoDeals => {}
            Assertion::Balance { address, .. } => {
                trace.accounts.insert(Address::from(*address));
            }
            Assertion::Storage { address, slot, .. } => {
                let addr = Address::from(*address);
                let slot_u256 = fixed_to_u256(*slot);
                trace.accounts.insert(addr);
                trace.storage.insert((addr, slot_u256));
            }
            Assertion::NotOwner { address, slot } => {
                let addr = Address::from(*address);
                let slot_u256 = fixed_to_u256(*slot);
                trace.accounts.insert(addr);
                trace.storage.insert((addr, slot_u256));
            }
        }
    }

    // Always fetch proofs for the PoC contract address to prove its pre-state is empty.
    trace.accounts.insert(contract_addr);

    // Important: The dry-run executes *at* `contract_addr` (because we inject the PoC there),
    // so the access trace will include storage touches for `contract_addr`. Those storage reads
    // are not part of the real chain state and must not be "proven" from RPC (they will all read
    // as zero and would incorrectly make the account appear non-empty in our partial DB).
    trace.storage.retain(|(addr, _)| *addr != contract_addr);

    // Parallel-fetch all discovered state from RPC
    info!("Fetching state from RPC");
    let mut original_db = fetch_all_parallel(client, &trace, block_number)
        .await
        .context("fetch_all_parallel")?;

    // Fetch EIP-1186 proofs for all accessed accounts
    info!("Fetching EIP-1186 proofs");
    let proofs = fetch_proofs_parallel(client, &trace, block_number)
        .await
        .context("fetch_proofs_parallel")?;

    // Ensure the chosen PoC contract address is empty on-chain (using an authenticated proof).
    ensure_contract_address_empty(
        Some(client),
        block_number,
        &block_env,
        contract_addr,
        &proofs,
    )
    .await
    .context("contract address emptiness check")?;

    // Ensure the caller is present in the DB (synthetic caller overlay).
    let caller_addr_fixed = addr_to_fixed(caller_addr);
    original_db
        .accounts
        .entry(caller_addr_fixed)
        .or_insert_with(|| bridge_types::types::RkyvAccount {
            nonce: 0,
            balance: u256_to_fixed(U256::from(1_000_000_000_000_000_000u128)),
            code_hash: KECCAK_EMPTY.0,
            code: None,
            storage: std::collections::BTreeMap::new(),
        });

    let input = ExploitInput {
        original_db,
        deals,
        assertions,
        nonce,
        caller,
        contract_address,
        env: block_env.clone(),
        poc_bytecode,
        gas_limit,
        proofs,
        options,
    };

    Ok((input, block_env))
}

async fn ensure_contract_address_empty(
    client: Option<&RpcClient>,
    block_number: u64,
    block_env: &RkyvBlockEnv,
    contract_addr: Address,
    proofs: &[bridge_types::types::EIP1186AccountProof],
) -> Result<()> {
    let contract_fixed = addr_to_fixed(contract_addr);

    let proof = proofs
        .iter()
        .find(|p| p.address == contract_fixed)
        .context("missing EIP-1186 proof for --contract-address")?;

    // Verify the proof against the block's state root, then interpret "empty" from the proven
    // account object. This avoids relying on RPC-reported nonce/balance/codeHash directly.
    let proven = bridge_types::mpt::verify_account_proof(
        block_env.state_root,
        &proof.address,
        &proof.account_proof,
    )
    .map_err(|e| anyhow::anyhow!(e))
    .context("verify_account_proof for contract address")?;

    let is_empty_by_proof = match proven {
        None => true, // absent account
        Some(p) => {
            // Consider this "empty" only if it's indistinguishable from absence.
            p.nonce == 0
                && p.balance == [0u8; 32]
                && p.code_hash == KECCAK_EMPTY.0
                && p.storage_root == bridge_types::mpt::EMPTY_TRIE_ROOT
        }
    };

    if is_empty_by_proof {
        return Ok(());
    }

    // Failure path: provide a few deterministic suggestions to reduce user friction.
    let suggestions = if let Some(client) = client {
        suggest_empty_contract_addresses(
            client,
            block_number,
            block_env.chain_id,
            contract_addr,
            3,
            64,
        )
        .await
        .unwrap_or_default()
    } else {
        Vec::new()
    };

    if suggestions.is_empty() {
        anyhow::bail!(
            "contract address 0x{} is non-empty at block {}. Choose a different --contract-address.",
            hex::encode(contract_addr.as_slice()),
            block_number
        );
    }

    let rendered = suggestions
        .iter()
        .map(|a| format!("{a:?}"))
        .collect::<Vec<_>>()
        .join(", ");

    anyhow::bail!(
        "contract address 0x{} is non-empty at block {}. Choose a different --contract-address. Suggestions (empty at this block): {}",
        hex::encode(contract_addr.as_slice()),
        block_number,
        rendered
    );
}

async fn suggest_empty_contract_addresses(
    client: &RpcClient,
    block_number: u64,
    chain_id: u64,
    occupied: Address,
    want: usize,
    max_attempts: u64,
) -> Result<Vec<Address>> {
    let mut out = Vec::new();
    for attempt in 0..max_attempts {
        let candidate = derive_candidate_address(chain_id, block_number, occupied, attempt);
        if candidate == occupied || candidate == Address::ZERO {
            continue;
        }
        if is_precompile_like(candidate) {
            continue;
        }
        if is_empty_by_rpc(client, candidate, block_number).await? {
            out.push(candidate);
            if out.len() >= want {
                break;
            }
        }
    }
    Ok(out)
}

fn derive_candidate_address(
    chain_id: u64,
    block_number: u64,
    occupied: Address,
    attempt: u64,
) -> Address {
    // Deterministic derivation: keccak256(domain || chain_id || block || occupied || attempt)[12..]
    let mut buf = [0u8; 6 + 8 + 8 + 20 + 8];
    buf[..6].copy_from_slice(b"zkpoex");
    buf[6..14].copy_from_slice(&chain_id.to_be_bytes());
    buf[14..22].copy_from_slice(&block_number.to_be_bytes());
    buf[22..42].copy_from_slice(occupied.as_slice());
    buf[42..50].copy_from_slice(&attempt.to_be_bytes());
    let h = alloy_primitives::keccak256(buf).0;
    Address::from_slice(&h[12..32])
}

fn is_precompile_like(addr: Address) -> bool {
    // Avoid the historical "low addresses" range (0x1..0x9) which can be special-cased.
    let b = addr.as_slice();
    b[..19].iter().all(|x| *x == 0) && matches!(b[19], 1..=9)
}

async fn is_empty_by_rpc(client: &RpcClient, addr: Address, block_number: u64) -> Result<bool> {
    let (bal, nonce, code) = tokio::try_join!(
        client.get_balance(addr, block_number),
        client.get_transaction_count(addr, block_number),
        client.get_code(addr, block_number),
    )?;
    Ok(bal.is_zero() && nonce == 0 && code.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bridge_types::conversions::b256_to_fixed;
    use bridge_types::types::EIP1186AccountProof;

    fn rlp_encode_bytes(data: &[u8]) -> Vec<u8> {
        if data.len() == 1 && data[0] < 0x80 {
            return data.to_vec();
        }
        if data.len() <= 55 {
            let mut out = vec![0x80 + data.len() as u8];
            out.extend_from_slice(data);
            out
        } else {
            let len_bytes = encode_length(data.len());
            let mut out = vec![0xb7 + len_bytes.len() as u8];
            out.extend_from_slice(&len_bytes);
            out.extend_from_slice(data);
            out
        }
    }

    fn rlp_encode_list(payload: &[u8]) -> Vec<u8> {
        if payload.len() <= 55 {
            let mut out = vec![0xc0 + payload.len() as u8];
            out.extend_from_slice(payload);
            out
        } else {
            let len_bytes = encode_length(payload.len());
            let mut out = vec![0xf7 + len_bytes.len() as u8];
            out.extend_from_slice(&len_bytes);
            out.extend_from_slice(payload);
            out
        }
    }

    fn encode_length(len: usize) -> Vec<u8> {
        if len <= 0xff {
            vec![len as u8]
        } else if len <= 0xffff {
            vec![(len >> 8) as u8, len as u8]
        } else {
            vec![(len >> 16) as u8, (len >> 8) as u8, len as u8]
        }
    }

    #[test]
    fn test_is_precompile_like() {
        for i in 1u8..=9 {
            let mut bytes = [0u8; 20];
            bytes[19] = i;
            assert!(is_precompile_like(Address::from(bytes)));
        }
        assert!(!is_precompile_like(Address::ZERO));
        assert!(!is_precompile_like(Address::from([0xff; 20])));
        // 0x..0a is not a precompile
        let mut bytes = [0u8; 20];
        bytes[19] = 10;
        assert!(!is_precompile_like(Address::from(bytes)));
    }

    #[test]
    fn test_derive_candidate_address_deterministic_and_varies() {
        let occupied = Address::from([0x11; 20]);
        let a1 = derive_candidate_address(1, 17007838, occupied, 0);
        let a2 = derive_candidate_address(1, 17007838, occupied, 0);
        assert_eq!(a1, a2);

        let b = derive_candidate_address(1, 17007838, occupied, 1);
        assert_ne!(a1, b);
    }

    #[test]
    fn test_filter_contract_storage_from_trace() {
        let contract = Address::from([0x22; 20]);
        let other = Address::from([0x33; 20]);
        let mut trace = crate::proxy_db::AccessTrace::default();
        trace.storage.insert((contract, U256::from(1)));
        trace.storage.insert((contract, U256::from(2)));
        trace.storage.insert((other, U256::from(3)));

        trace.storage.retain(|(addr, _)| *addr != contract);

        assert!(trace.storage.contains(&(other, U256::from(3))));
        assert!(!trace.storage.iter().any(|(a, _)| *a == contract));
    }

    #[tokio::test]
    async fn test_ensure_contract_address_empty_accepts_absent_account_via_proof() {
        // Build a tiny state trie with a single account at address A.
        // Then provide a proof for a different address B using the same nodes; this should
        // prove "absent" (None) for B in this single-leaf trie.
        let addr_a = Address::from([0xaa; 20]);
        let addr_b = Address::from([0xbb; 20]);

        let key_a = alloy_primitives::keccak256(addr_a.as_slice());

        // RLP([nonce, balance, storageRoot, codeHash]) for addr_a
        let nonce_rlp = rlp_encode_bytes(&[0x01]); // nonce=1 (non-empty, but irrelevant for B)
        let balance_rlp = rlp_encode_bytes(&[0x01]); // balance=1 wei
        let storage_root_rlp = rlp_encode_bytes(&bridge_types::mpt::EMPTY_TRIE_ROOT);
        let code_hash_rlp = rlp_encode_bytes(&revm::primitives::KECCAK_EMPTY.0);
        let account_payload = [
            nonce_rlp.as_slice(),
            balance_rlp.as_slice(),
            storage_root_rlp.as_slice(),
            code_hash_rlp.as_slice(),
        ]
        .concat();
        let account_rlp = rlp_encode_list(&account_payload);

        // Leaf node: RLP([compact_key, rlp_encode_bytes(account_rlp)])
        let compact_key = {
            let mut v = vec![0x20]; // even leaf prefix
            v.extend_from_slice(key_a.as_slice());
            v
        };
        let encoded_key = rlp_encode_bytes(&compact_key);
        let encoded_value = rlp_encode_bytes(&account_rlp);
        let leaf_payload = [encoded_key.as_slice(), encoded_value.as_slice()].concat();
        let leaf_rlp = rlp_encode_list(&leaf_payload);

        let state_root = b256_to_fixed(alloy_primitives::keccak256(&leaf_rlp));

        let block_env = RkyvBlockEnv {
            number: 17007838,
            timestamp: 0,
            coinbase: [0; 20],
            difficulty: [0; 32],
            gas_limit: 30_000_000,
            basefee: [0; 32],
            prevrandao: None,
            excess_blob_gas: None,
            chain_id: 1,
            state_root,
        };

        let proof_b = EIP1186AccountProof {
            address: addr_to_fixed(addr_b),
            nonce: 0,
            balance: [0u8; 32],
            storage_hash: bridge_types::mpt::EMPTY_TRIE_ROOT,
            code_hash: revm::primitives::KECCAK_EMPTY.0,
            account_proof: vec![leaf_rlp],
            storage_proofs: vec![],
        };

        // Should accept: addr_b is absent at this state root.
        ensure_contract_address_empty(None, block_env.number, &block_env, addr_b, &[proof_b])
            .await
            .expect("emptiness check should pass");
    }
}

#[derive(Default)]
struct DebugInspector {
    depth: usize,
    events: Vec<CallEvent>,
}

#[derive(Clone)]
struct CallEvent {
    depth: usize,
    caller: Address,
    target: Address,
    scheme: revm::interpreter::CallScheme,
    gas_limit: u64,
    value: U256,
    input_len: usize,
    result: revm::interpreter::InstructionResult,
    output: Bytes,
}

impl<DB: revm::Database> revm::Inspector<DB> for DebugInspector {
    fn call(
        &mut self,
        _context: &mut revm::EvmContext<DB>,
        _inputs: &mut revm::interpreter::CallInputs,
    ) -> Option<revm::interpreter::CallOutcome> {
        self.depth += 1;
        None
    }

    fn call_end(
        &mut self,
        _context: &mut revm::EvmContext<DB>,
        inputs: &revm::interpreter::CallInputs,
        outcome: revm::interpreter::CallOutcome,
    ) -> revm::interpreter::CallOutcome {
        let result = *outcome.instruction_result();
        self.events.push(CallEvent {
            depth: self.depth,
            caller: inputs.caller,
            target: inputs.target_address,
            scheme: inputs.scheme,
            gas_limit: inputs.gas_limit,
            value: inputs.call_value(),
            input_len: inputs.input.len(),
            result,
            output: outcome.output().clone(),
        });
        if self.depth > 0 {
            self.depth -= 1;
        }
        outcome
    }
}

fn format_debug_trace(inspector: &DebugInspector) -> String {
    const MAX_EVENTS: usize = 64;
    let mut out = String::new();
    let start = inspector.events.len().saturating_sub(MAX_EVENTS);
    for event in inspector.events.iter().skip(start) {
        let indent = "  ".repeat(event.depth);
        let output = decode_revert_reason(event.output.as_ref());
        out.push_str(&format!(
            "{}{} -> {} scheme={:?} gas={} value={} input_len={} result={:?} output={}\n",
            indent,
            format!("{:?}", event.caller),
            format!("{:?}", event.target),
            event.scheme,
            event.gas_limit,
            event.value,
            event.input_len,
            event.result,
            output
        ));
    }
    out
}

fn decode_revert_reason(output: &[u8]) -> String {
    if output.is_empty() {
        return "<empty>".to_string();
    }
    if output.len() >= 4 {
        let selector = &output[..4];
        // Error(string)
        if selector == [0x08, 0xc3, 0x79, 0xa0] && output.len() >= 4 + 32 + 32 {
            let len_bytes = &output[4 + 32 + 24..4 + 32 + 32];
            let len = u64::from_be_bytes(len_bytes.try_into().unwrap_or([0u8; 8])) as usize;
            let start = 4 + 32 + 32;
            if output.len() >= start + len {
                let msg = String::from_utf8_lossy(&output[start..start + len]);
                return format!("Error({})", msg);
            }
        }
        // Panic(uint256)
        if selector == [0x4e, 0x48, 0x7b, 0x71] && output.len() >= 4 + 32 {
            let code_bytes = &output[4 + 24..4 + 32];
            let code = u64::from_be_bytes(code_bytes.try_into().unwrap_or([0u8; 8]));
            return format!("Panic(0x{:x})", code);
        }
    }
    format!("0x{}", hex::encode(output))
}

/// A layered database: checks overlay first, falls back to inner DB.
struct LayeredDB<O, F> {
    overlay: O,
    fallback: F,
}

impl<O: DatabaseRef, F: DatabaseRef<Error = anyhow::Error>> DatabaseRef for LayeredDB<O, F>
where
    O::Error: std::fmt::Debug,
{
    type Error = anyhow::Error;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        match self.overlay.basic_ref(address) {
            Ok(Some(info)) => Ok(Some(info)),
            Ok(None) => self.fallback.basic_ref(address),
            Err(e) => Err(anyhow::anyhow!("overlay basic_ref error: {:?}", e)),
        }
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        match self.overlay.code_by_hash_ref(code_hash) {
            Ok(code) if !code.bytecode().is_empty() => Ok(code),
            _ => self.fallback.code_by_hash_ref(code_hash),
        }
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        match self.overlay.basic_ref(address) {
            Ok(Some(_)) => match self.overlay.storage_ref(address, index) {
                Ok(val) if val != U256::ZERO => Ok(val),
                _ => self.fallback.storage_ref(address, index),
            },
            _ => self.fallback.storage_ref(address, index),
        }
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        match self.overlay.block_hash_ref(number) {
            Ok(hash) if hash != B256::ZERO => Ok(hash),
            _ => self.fallback.block_hash_ref(number),
        }
    }
}

// SPDX-License-Identifier: MIT
use alloy_primitives::{Address, Bytes, U256};
use anyhow::{Context, Result};
use revm::db::WrapDatabaseRef;
use revm::primitives::{
    BlockEnv, CfgEnv, CfgEnvWithHandlerCfg, EnvWithHandlerCfg, ResultAndState, SpecId, TransactTo,
    TxEnv,
};
use revm::{inspector_handle_register, DatabaseRef, Evm, Inspector};

use bridge_types::constants::CALL_EXPLOIT_DATA;
use bridge_types::conversions::{fixed_to_b256, fixed_to_u256};
use bridge_types::types::RkyvBlockEnv;

/// Execute the exploit PoC against the given database and environment.
///
/// Returns the full `ResultAndState` from revm, including the execution
/// outcome and all state changes.
pub fn sim_exploit<DB: DatabaseRef>(
    db: DB,
    env: &RkyvBlockEnv,
    _poc_bytecode: &[u8],
    gas_limit: u64,
    caller: Address,
    contract: Address,
    spec_id: SpecId,
) -> Result<ResultAndState>
where
    DB::Error: std::fmt::Debug,
{
    // Build block env
    let block_basefee = fixed_to_u256(env.basefee);
    let block_env = BlockEnv {
        number: U256::from(env.number),
        coinbase: Address::from(env.coinbase),
        timestamp: U256::from(env.timestamp),
        gas_limit: U256::from(env.gas_limit),
        // Bind execution to the real basefee from the block env.
        basefee: block_basefee,
        difficulty: fixed_to_u256(env.difficulty),
        prevrandao: env.prevrandao.map(fixed_to_b256),
        blob_excess_gas_and_price: env
            .excess_blob_gas
            .map(|v| revm::primitives::BlobExcessGasAndPrice::new(v, false)),
    };

    // Build tx env
    // Bind gas_price to the block basefee to satisfy EIP-1559 validation.
    let tx_env = TxEnv {
        caller,
        gas_limit,
        gas_price: block_basefee,
        transact_to: TransactTo::Call(contract),
        value: U256::ZERO,
        data: Bytes::copy_from_slice(&CALL_EXPLOIT_DATA),
        ..Default::default()
    };

    // Build cfg env
    let mut cfg = CfgEnv::default();
    cfg.chain_id = env.chain_id;

    let cfg_with_handler = CfgEnvWithHandlerCfg::new_with_spec_id(cfg, spec_id);
    let env_with_handler = EnvWithHandlerCfg::new_with_cfg_env(cfg_with_handler, block_env, tx_env);

    let mut evm = Evm::builder()
        .with_ref_db(db)
        .with_env_with_handler_cfg(env_with_handler)
        .build();

    let result = evm
        .transact()
        .map_err(|e| anyhow::anyhow!("EVM execution failed: {:?}", e))
        .context("sim_exploit transact")?;

    Ok(result)
}

/// Execute the exploit PoC with an Inspector attached (for call trace commitments).
///
/// Returns the execution result and the inspector instance (to read collected data).
pub fn sim_exploit_with_inspector<DB, INSP>(
    db: DB,
    env: &RkyvBlockEnv,
    _poc_bytecode: &[u8],
    gas_limit: u64,
    caller: Address,
    contract: Address,
    spec_id: SpecId,
    inspector: INSP,
) -> (Result<ResultAndState>, INSP)
where
    DB: DatabaseRef,
    DB::Error: std::fmt::Debug,
    INSP: Inspector<WrapDatabaseRef<DB>>,
{
    let block_basefee = fixed_to_u256(env.basefee);
    let block_env = BlockEnv {
        number: U256::from(env.number),
        coinbase: Address::from(env.coinbase),
        timestamp: U256::from(env.timestamp),
        gas_limit: U256::from(env.gas_limit),
        basefee: block_basefee,
        difficulty: fixed_to_u256(env.difficulty),
        prevrandao: env.prevrandao.map(fixed_to_b256),
        blob_excess_gas_and_price: env
            .excess_blob_gas
            .map(|v| revm::primitives::BlobExcessGasAndPrice::new(v, false)),
    };

    let tx_env = TxEnv {
        caller,
        gas_limit,
        gas_price: block_basefee,
        transact_to: TransactTo::Call(contract),
        value: U256::ZERO,
        data: Bytes::copy_from_slice(&CALL_EXPLOIT_DATA),
        ..Default::default()
    };

    let mut cfg = CfgEnv::default();
    cfg.chain_id = env.chain_id;

    let cfg_with_handler = CfgEnvWithHandlerCfg::new_with_spec_id(cfg, spec_id);
    let env_with_handler = EnvWithHandlerCfg::new_with_cfg_env(cfg_with_handler, block_env, tx_env);

    let mut evm = Evm::builder()
        .with_ref_db(db)
        .with_external_context(inspector)
        .with_env_with_handler_cfg(env_with_handler)
        .append_handler_register(inspector_handle_register)
        .build();

    let result = evm
        .transact()
        .map_err(|e| anyhow::anyhow!("EVM execution failed: {:?}", e))
        .context("sim_exploit_with_inspector transact");

    let inspector = evm.into_context().external;
    (result, inspector)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::MutableMemDB;
    use bridge_types::conversions::u256_to_fixed;
    use bridge_types::types::{RkyvAccount, RkyvBlockEnv, RkyvMemDB};
    use revm::primitives::{ExecutionResult, KECCAK_EMPTY};
    use std::collections::BTreeMap;

    fn make_env() -> RkyvBlockEnv {
        RkyvBlockEnv {
            number: 100,
            timestamp: 1700000000,
            coinbase: [0; 20],
            difficulty: [0; 32],
            gas_limit: 30_000_000,
            basefee: [0; 32],
            prevrandao: Some([0xde; 32]),
            excess_blob_gas: Some(0),
            chain_id: 1,
            state_root: [0; 32],
        }
    }

    #[test]
    fn test_sim_exploit_stop_opcode() {
        // Deploy a contract with just STOP (0x00) at the contract address
        let contract_addr = bridge_types::constants::DEFAULT_CONTRACT_ADDRESS;
        let caller_addr = bridge_types::constants::DEFAULT_CALLER;

        // STOP opcode bytecode
        let bytecode = vec![0x00];
        let code_hash = alloy_primitives::keccak256(&bytecode);

        let mut accounts = BTreeMap::new();

        // Contract account with STOP bytecode
        accounts.insert(
            contract_addr,
            RkyvAccount {
                nonce: 1,
                balance: [0; 32],
                code_hash: code_hash.0,
                code: Some(bytecode),
                storage: BTreeMap::new(),
            },
        );

        // Caller account with some ETH
        let keccak_empty_bytes: [u8; 32] = KECCAK_EMPTY.0;
        accounts.insert(
            caller_addr,
            RkyvAccount {
                nonce: 0,
                balance: u256_to_fixed(U256::from(1_000_000_000_000_000_000u128)),
                code_hash: keccak_empty_bytes,
                code: None,
                storage: BTreeMap::new(),
            },
        );

        // Coinbase account (Address::ZERO) - required because revm touches it
        accounts.insert(
            [0; 20],
            RkyvAccount {
                nonce: 0,
                balance: [0; 32],
                code_hash: keccak_empty_bytes,
                code: None,
                storage: BTreeMap::new(),
            },
        );

        let rkyv_db = RkyvMemDB {
            accounts,
            block_hashes: BTreeMap::new(),
        };

        let db = MutableMemDB::from_rkyv(rkyv_db);
        let env = make_env();
        let spec_id = crate::hardfork::spec_id_from_chain(1, 0);

        let result = sim_exploit(
            db,
            &env,
            &[],
            30_000_000,
            Address::from(caller_addr),
            Address::from(contract_addr),
            spec_id,
        )
        .unwrap();

        match result.result {
            ExecutionResult::Success { .. } => {}
            other => panic!("Expected success, got {:?}", other),
        }
    }
}

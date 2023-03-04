#![cfg_attr(not(test), no_std)]

extern crate alloc;
extern crate core;

use core::str::FromStr;

use alloc::{vec::Vec, collections::BTreeMap, string::String};
use evm::{
	Config,ExitReason, ExitSucceed,
	backend::{
		MemoryVicinity, MemoryAccount, MemoryBackend, Backend
	},
	executor::stack::{
		StackSubstateMetadata, MemoryStackState, StackExecutor
	},
};
use primitive_types::{U256, H160, H256};

pub fn run_target_contract(
	target_bytecode: &str,
	target_address: &str,
	caller_address: &str,
	calldata: &str
) -> Vec<String> {
    run_evm(
		target_bytecode,
		target_address,
		caller_address,
		calldata
	)
}

fn run_evm(
	target_bytecode: &str,
	target_address: &str,
	caller_address: &str,
	calldata: &str
) -> Vec<String> {
    let config = Config::istanbul();

	let vicinity = MemoryVicinity {
		gas_price: U256::zero(),
		origin: H160::default(),
		block_hashes: Vec::new(),
		block_number: Default::default(),
		block_coinbase: Default::default(),
		block_timestamp: Default::default(),
		block_difficulty: Default::default(),
		block_gas_limit: Default::default(),
		chain_id: U256::one(),
		block_base_fee_per_gas: U256::zero(),
	};

	
	let mut state_btree_map = BTreeMap::new();

	let mut target_storage = BTreeMap::new();
	target_storage.insert(H256::zero(),H256::from_low_u64_be(1));

	state_btree_map.insert(
		H160::from_str(target_address).unwrap(),
		MemoryAccount {
			nonce: U256::one(),
			balance: U256::from(10000000),
			storage: target_storage,
			code: hex::decode(target_bytecode).unwrap(),
		}
	);
	state_btree_map.insert(
		H160::from_str(caller_address).unwrap(),
		MemoryAccount {
			nonce: U256::one(),
			balance: U256::from(10000000),
			storage: BTreeMap::new(),
			code: Vec::new(),
		},
	);

	let backend = MemoryBackend::new(&vicinity, state_btree_map);
	let metadata = StackSubstateMetadata::new(u64::MAX, &config);
	let state = MemoryStackState::new(metadata, &backend);
	let precompiles = BTreeMap::new();
	let mut executor = StackExecutor::new_with_precompiles(state, &config, &precompiles);

	let mut vec = Vec::new();

	let before = executor.state().storage(H160::from_str(target_address).unwrap(), H256::zero());
	
	let (exit_reason, result) = executor.transact_call(
		H160::from_str(caller_address).unwrap(),
		H160::from_str(target_address).unwrap(),
		U256::zero(),
		hex::decode(calldata).unwrap(),
		u64::MAX,
		Vec::new(),
	);
	
	assert!(exit_reason == ExitReason::Succeed(ExitSucceed::Returned));
	
	let after = executor.state().storage(H160::from_str(target_address).unwrap(), H256::zero());

	vec.push(hex::encode(result));
	vec.push(hex::encode(before));
	vec.push(hex::encode(after));

	vec
}

#[cfg(test)]
mod tests {
    use super::*;

    const target_bytecode: &str = include_str!("../../bytecode/Target.bin-runtime");
    const target_address: &str = "0x1000000000000000000000000000000000000000";
    const caller_address: &str = "0xf000000000000000000000000000000000000000";

    #[test]
		fn evm_balance_works() {
			let calldata = "b69ef8a8";
			let result = run_target_contract(target_bytecode, target_address, caller_address, calldata);
			assert_eq!(result[0], "0000000000000000000000000000000000000000000000000000000000000001");
		}
		
		#[test]
		fn evm_rug_works() {
			let calldata = "e9be02aa";
			let result = run_target_contract(target_bytecode, target_address, caller_address, calldata);
			assert_eq!(result[0], "0000000000000000000000000000000000000000000000000000000000000000");
			assert_eq!(result[1], "0000000000000000000000000000000000000000000000000000000000000001");
			assert_eq!(result[2], "0000000000000000000000000000000000000000000000000000000000000000");
		}
		
		#[test]
		fn evm_fund_works() {
			let calldata = "b60d4288";
			let result = run_target_contract(target_bytecode, target_address, caller_address, calldata);
	assert_eq!(result[0], "0000000000000000000000000000000000000000000000000000000000000064");
	assert_eq!(result[1], "0000000000000000000000000000000000000000000000000000000000000001");
	assert_eq!(result[2], "0000000000000000000000000000000000000000000000000000000000000064");
	}

}

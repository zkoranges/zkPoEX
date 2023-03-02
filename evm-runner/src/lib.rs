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
	Runtime, Context
};
use primitive_types::{U256, H160, H256};

pub const TARGET_CONTRACT_EVM_PROGRAM: &str = include_str!("../../bytecode/Target.bin-runtime");
pub const TARGET_ADDRESS: &str = "0x1000000000000000000000000000000000000000";
pub const CALLER_ADDRESS: &str = "0xf000000000000000000000000000000000000000";

pub fn run_target_contract(input: &str) -> Vec<String> {
    run_evm(TARGET_CONTRACT_EVM_PROGRAM, input)
}

fn run_evm(program: &str, input: &str) -> Vec<String> {
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

	
	let mut state = BTreeMap::new();

	let mut target_storage = BTreeMap::new();
	target_storage.insert(H256::zero(),H256::from_low_u64_be(1));

	state.insert(
		H160::from_str(TARGET_ADDRESS).unwrap(),
		MemoryAccount {
			nonce: U256::one(),
			balance: U256::from(10000000),
			storage: target_storage,
			code: hex::decode(program).unwrap(),
		}
	);
	state.insert(
		H160::from_str(CALLER_ADDRESS).unwrap(),
		MemoryAccount {
			nonce: U256::one(),
			balance: U256::from(10000000),
			storage: BTreeMap::new(),
			code: Vec::new(),
		},
	);

	let backend = MemoryBackend::new(&vicinity, state);
	let metadata = StackSubstateMetadata::new(u64::MAX, &config);
	let state = MemoryStackState::new(metadata, &backend);
	let precompiles = BTreeMap::new();
	let mut executor = StackExecutor::new_with_precompiles(state, &config, &precompiles);

	let before = backend.state().get(&H160::from_str(TARGET_ADDRESS).unwrap()).unwrap().storage.get(&H256::zero()).unwrap();
	// let before = state.storage(H160::from_str(TARGET_ADDRESS).unwrap(), H256::zero());

	let (exit_reason, result) = executor.transact_call(
		H160::from_str(CALLER_ADDRESS).unwrap(),
		H160::from_str(TARGET_ADDRESS).unwrap(),
		U256::zero(),
		hex::decode(input).unwrap(),
		u64::MAX,
		Vec::new(),
	);

    assert!(exit_reason == ExitReason::Succeed(ExitSucceed::Returned));
		let after = backend.state().get(&H160::from_str(TARGET_ADDRESS).unwrap()).unwrap().storage.get(&H256::zero()).unwrap();
		// let after = state.storage(H160::from_str(TARGET_ADDRESS).unwrap(), H256::zero());

		let mut vec = Vec::new();
		vec.push(hex::encode(result));
		vec.push(hex::encode(before));
		vec.push(hex::encode(after));
		vec
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
		fn evm_balance_works() {
			let data = "b69ef8a8";
			let result = run_target_contract(data);
		assert_eq!(result[0], "0000000000000000000000000000000000000000000000000000000000000001");
	}
	
	#[test]
	fn evm_rug_works() {
		let data = "e9be02aa";
		let result = run_target_contract(data);
	assert_eq!(result[0], "0000000000000000000000000000000000000000000000000000000000000000");
	println!("{:?}", result[1]);
	println!("{:?}", result[2]);
	}

	#[test]
	fn evm_fund_works() {
		let data = "b60d4288";
		let result = run_target_contract(data);
	assert_eq!(result[0], "0000000000000000000000000000000000000000000000000000000000000064");
	println!("{:?}", result[1]);
	println!("{:?}", result[2]);
	}

}

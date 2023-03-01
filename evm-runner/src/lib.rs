#![cfg_attr(not(test), no_std)]

extern crate alloc;
extern crate core;

use core::str::FromStr;

use alloc::{vec::Vec, collections::BTreeMap, string::String};
use evm::{
	Config,ExitReason, ExitSucceed,
	backend::{
		MemoryVicinity, MemoryAccount, MemoryBackend
	},
	executor::stack::{
		StackSubstateMetadata, MemoryStackState, StackExecutor
	}
};
use primitive_types::{U256, H160, H256};

pub const WRAPPER_CONTRACT_EVM_PROGRAM: &str = include_str!("../../bytecode/Wrapper.bin-runtime");

pub fn run_wrapper_contract(input: &str) -> String {
    run_evm(WRAPPER_CONTRACT_EVM_PROGRAM, input)
}

fn run_evm(program: &str, input: &str) -> String {
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

	let mut hack_me_state = BTreeMap::new();
	hack_me_state.insert(H256::zero(),H256::from_low_u64_be(1));
	
	state.insert(
		H160::from_str("0x1000000000000000000000000000000000000000").unwrap(),
		MemoryAccount {
			nonce: U256::one(),
			balance: U256::from(10000000),
			storage: hack_me_state,
			code: hex::decode(program).unwrap(),
		}
	);
	state.insert(
		H160::from_str("0xf000000000000000000000000000000000000000").unwrap(),
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

	let (exit_reason, result) = executor.transact_call(
		H160::from_str("0xf000000000000000000000000000000000000000").unwrap(),
		H160::from_str("0x1000000000000000000000000000000000000000").unwrap(),
		U256::zero(),
		hex::decode(input).unwrap(),
		u64::MAX,
		Vec::new(),
	);
    assert!(exit_reason == ExitReason::Succeed(ExitSucceed::Returned));
    hex::encode(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn evm_version_works() {
        let data = "54fd4d50";
        let result = run_wrapper_contract(data);
		assert_eq!(result, "0000000000000000000000000000000000000000000000000000000000000001");
    }

    #[test]
		fn evm_balance_works() {
			let data = "b69ef8a8";
			let result = run_wrapper_contract(data);
		assert_eq!(result, "0000000000000000000000000000000000000000000000000000000000000001");
	}
	
	#[test]
	fn evm_rug_works() {
		let data = "e9be02aa";
		let result = run_wrapper_contract(data);
	assert_eq!(result, "0000000000000000000000000000000000000000000000000000000000000000");
}

#[test]
fn evm_fund_works() {
	let data = "b60d4288";
	let result = run_wrapper_contract(data);
assert_eq!(result, "00000000000000000000000000000000000000000000d3c21bcecceda1000000");
}

#[test]
fn evm_fund2_works() {
	let data = "ca1d209d00000000000000000000000000000000000000000000d3c21bcecceda1000000";
	let result = run_wrapper_contract(data);
assert_eq!(result, "00000000000000000000000000000000000000000000d3c21bcecceda1000000");
}


#[test]
fn delta_works() {
	// delta(rug())
	let data = "2734344e00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000004e9be02aa00000000000000000000000000000000000000000000000000000000";
	let result = run_wrapper_contract(data);
assert_eq!(result, "0000000000000000000000000000000000000000000000000000000000000001");
}
}

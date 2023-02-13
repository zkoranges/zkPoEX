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
use primitive_types::{U256, H160};

pub const CALCULATOR_EVM_PROGRAM: &str = include_str!("../../bytecode/Calculator.bin-runtime");

pub fn run_calc_contract(input: &str) -> String {
    run_evm(CALCULATOR_EVM_PROGRAM, input)
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
	state.insert(
		H160::from_str("0x1000000000000000000000000000000000000000").unwrap(),
		MemoryAccount {
			nonce: U256::one(),
			balance: U256::from(10000000),
			storage: BTreeMap::new(),
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
    fn evm_fibb_works() {
        let data = "61047ff4000000000000000000000000000000000000000000000000000000000000000a";
        let result = run_calc_contract(data);
        assert_eq!(result, "0000000000000000000000000000000000000000000000000000000000000037");  
    }
    
    #[test]
    fn evm_calc_works() {
        let data = "771602f700000000000000000000000000000000000000000000000000000000000000070000000000000000000000000000000000000000000000000000000000000002";
        let result = run_calc_contract(data);
		assert_eq!(result, "0000000000000000000000000000000000000000000000000000000000000009");
    }
}

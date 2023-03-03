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
	},
};
use primitive_types::{U256, H160, H256};
use ethereum_types::{Address};
use std::dbg;


pub const TARGET_CONTRACT_EVM_PROGRAM: &str = include_str!("../../bytecode/Target.bin-runtime");
pub const EXPLOITER_CONTRACT_EVM_PROGRAM: &str = include_str!("../../bytecode/Exploiter.bin-runtime");

pub const TARGET_ADDRESS: &str = "0x1000000000000000000000000000000000000000";
pub const EXPLOITER_ADDRESS: &str = "0x2000000000000000000000000000000000000000";
pub const CALLER_ADDRESS: &str = "0xf000000000000000000000000000000000000000";

pub fn run_simulation(input: &str) -> Vec<String> {
    run_evm(TARGET_CONTRACT_EVM_PROGRAM, EXPLOITER_CONTRACT_EVM_PROGRAM, input)
}

fn run_evm(target_bytecode: &str, exploiter_bytecode: &str, tx_data: &str) -> Vec<String> {
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

	// chain state
	let mut global_state = BTreeMap::new();

	let target_storage = BTreeMap::new();

	let mut exploiter_storage = BTreeMap::new();
	
	// insert target address in exploiter contract
	let target_address = H256::from(Address::from(H160::from_str(TARGET_ADDRESS).unwrap()));
	exploiter_storage.insert(H256::zero(),target_address);

	// deploy target contract to state
	global_state.insert(
		H160::from_str(TARGET_ADDRESS).unwrap(),
		MemoryAccount {
			nonce: U256::one(),
			balance: U256::from_dec_str("10000000000000000000").unwrap(), // 10 ether
			storage: target_storage,
			code: hex::decode(target_bytecode).unwrap(),
		}
	);

	// deploy exploiter contract to state
	global_state.insert(
			H160::from_str(EXPLOITER_ADDRESS).unwrap(),
			MemoryAccount {
				nonce: U256::one(),
				balance: U256::from_dec_str("0").unwrap(), // 0 ether
				storage: exploiter_storage,
				code: hex::decode(exploiter_bytecode).unwrap(),
			}
		);

	// deploy caller address in state
	global_state.insert(
		H160::from_str(CALLER_ADDRESS).unwrap(),
		MemoryAccount {
			nonce: U256::one(),
			balance: U256::from_dec_str("10000000000000000000").unwrap(), // 10 ether for the caller
			storage: BTreeMap::new(),
			code: Vec::new(),
		},
	);

	let backend = MemoryBackend::new(&vicinity, global_state);
	let metadata = StackSubstateMetadata::new(u64::MAX, &config);
	let state = MemoryStackState::new(metadata, &backend);
	let precompiles = BTreeMap::new();
	let mut executor = StackExecutor::new_with_precompiles(state, &config, &precompiles);

	// TODO define before and after
	// let before = executor.state().storage(H160::from_str(TARGET_ADDRESS).unwrap(), H256::zero());
	
	let (exit_reason, result) = executor.transact_call(
		H160::from_str(CALLER_ADDRESS).unwrap(),
		H160::from_str(EXPLOITER_ADDRESS).unwrap(),
		U256::from_dec_str("1000000000000000000").unwrap(), // 1 ether - 1000000000000000000
		hex::decode(tx_data).unwrap(),
		u64::MAX,
		Vec::new(),
	);
	
	// dbg!(&exit_reason);
	// println!("{:?}", exit_reason);
	assert!(exit_reason == ExitReason::Succeed(ExitSucceed::Returned));
	
	// let after = executor.state().storage(H160::from_str(TARGET_ADDRESS).unwrap(), H256::zero());

	// define outputs of the simulation
	let mut outputs = Vec::new();
	
	outputs.push(hex::encode(result));
	// outputs.push(hex::encode(before));
	// outputs.push(hex::encode(after));

	outputs
}

#[cfg(test)]
mod tests {
    use super::*;

  //   #[test]
	// 	fn evm_balance_works() {
	// 		let data = "b69ef8a8";
	// 		let result = run_simulation(data);
	
	// 		println!("{:?}", result);
	// 	// assert_eq!(result[0], "0000000000000000000000000000000000000000000000000000000000000001");
	// }
	
	#[test]
	fn evm_exploit_works() {
		let func_selector = "63d9b770"; // exploit()
		let result = run_simulation(func_selector);
		println!("Result: {:?}", result);
	// assert_eq!(result[0], "0000000000000000000000000000000000000000000000000000000000000000");
	// assert_eq!(result[1], "0000000000000000000000000000000000000000000000000000000000000001");
	// assert_eq!(result[2], "0000000000000000000000000000000000000000000000000000000000000000");
	}

	// #[test]
	// fn evm_balance_works() {
	// 	let func_selector = "b69ef8a8"; // balance
	// 	let result = run_simulation(func_selector);
	// 	println!("Result: {:?}", result);
	// assert_eq!(result[0], "0000000000000000000000000000000000000000000000000000000000000000");
	// // assert_eq!(result[1], "0000000000000000000000000000000000000000000000000000000000000001");
	// // assert_eq!(result[2], "0000000000000000000000000000000000000000000000000000000000000000");
	// }

	

	// #[test]
	// fn evm_fund_works() {
	// 	let data = "b60d4288";
	// 	let result = run_simulation(data);
	// 	println!("{:?}", result);
	// // assert_eq!(result[0], "0000000000000000000000000000000000000000000000000000000000000064");
	// // assert_eq!(result[1], "0000000000000000000000000000000000000000000000000000000000000001");
	// // assert_eq!(result[2], "0000000000000000000000000000000000000000000000000000000000000064");
	// }

}

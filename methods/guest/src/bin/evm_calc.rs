#![no_main]
#![no_std]

extern crate alloc;

use alloc::{string::String};
use risc0_zkvm::guest::{env};
use evm_runner::run_target_contract;

risc0_zkvm::guest::entry!(main);

pub fn main() {
    let target_bytecode: String = env::read();
    let target_address: String = env::read();
    let caller_address: String = env::read();
    let calldata: String = env::read();
    let result = run_target_contract(&target_bytecode, &target_address, &caller_address, &calldata);
    env::commit(&result);
}
    

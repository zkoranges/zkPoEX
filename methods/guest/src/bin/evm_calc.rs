#![no_main]
#![no_std]

extern crate alloc;

use alloc::{string::String};
use risc0_zkvm::guest::{env};
use evm_runner::run_target_contract;

risc0_zkvm::guest::entry!(main);

pub fn main() {
    let input: String = env::read();
    let result = run_target_contract(&input);
    env::commit(&result);
}
    

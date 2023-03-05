#![no_main]
#![no_std]

extern crate alloc;

use alloc::{string::String};
use risc0_zkvm::guest::{env};
use evm_runner::run_simulation;

risc0_zkvm::guest::entry!(main);

pub fn main() {
    let calldata: String = env::read();
    let blockchain_settings: String = env::read();
    let result = run_simulation(&calldata, &blockchain_settings);
    env::commit(&result);
}
    

use methods::{EVM_CALC_ID, EVM_CALC_PATH};
use risc0_zkvm::Prover;
use risc0_zkvm::serde::{from_slice, to_vec};

fn main() {
    println!("Proving state change after hack tx");

    // inputs
    let target_bytecode: &str = include_str!("../../bytecode/Target.bin-runtime");
    let target_address = "0x1000000000000000000000000000000000000000";
    let caller_address = "0xf000000000000000000000000000000000000000";
    let calldata = "e9be02aa";

    let result:Vec<String> = run_prover(target_bytecode, target_address, caller_address, calldata);
    println!("Proof generated. Result = {:?}", result);
}

fn run_prover(
	target_bytecode: &str,
	target_address: &str,
	caller_address: &str,
	calldata: &str
) -> Vec<String> {
    // Make the prover.
    let method_code = std::fs::read(EVM_CALC_PATH).unwrap();
    let mut prover = Prover::new(&method_code, EVM_CALC_ID).unwrap();

    // multiple inputs provided to the user
    prover.add_input_u32_slice(to_vec(target_bytecode).unwrap().as_slice());
    prover.add_input_u32_slice(to_vec(target_address).unwrap().as_slice());
    prover.add_input_u32_slice(to_vec(caller_address).unwrap().as_slice());
    prover.add_input_u32_slice(to_vec(calldata).unwrap().as_slice());

    let receipt = prover.run().unwrap();
    assert!(receipt.verify(EVM_CALC_ID).is_ok());
    let result: Vec<String> = from_slice(receipt.journal.as_slice()).unwrap();
    result
}

use methods::{EVM_CALC_ID, EVM_CALC_PATH};
use risc0_zkvm::Prover;
use risc0_zkvm::serde::{from_slice, to_vec};

fn main() {
    println!("Proving state change after hack tx...");
    let input = "63d9b770"; // exploit()
    run_prover(input);
    // println!("Proof generated. Receipt = {:?}", receipt);
}

fn run_prover(input: &str) -> Vec<String>{
    println!("Making the prover...");
    let method_code = std::fs::read(EVM_CALC_PATH).unwrap();
    let mut prover = Prover::new(&method_code, EVM_CALC_ID).unwrap();
    prover.add_input_u32_slice(to_vec(input).unwrap().as_slice());
    println!("Running the prover...");
    let receipt = prover.run().unwrap();
    println!("Verifying the prover...");
    assert!(receipt.verify(EVM_CALC_ID).is_ok());
    println!("Proof verified!");
    let result: Vec<String> = from_slice(receipt.journal.as_slice()).unwrap();
    result
}

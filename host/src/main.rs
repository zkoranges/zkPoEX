use methods::{EVM_CALC_ID, EVM_CALC_PATH};
use risc0_zkvm::Prover;
use risc0_zkvm::serde::{from_slice, to_vec};

fn main() {
    println!("Proving state change after hack tx");
    let input = "63d9b770"; // exploit()
    let result:Vec<String> = run_prover(input);
    println!("Proof generated. Before, After = {:?}", result);
}

fn run_prover(input: &str) -> Vec<String> {
    // Make the prover.
    let method_code = std::fs::read(EVM_CALC_PATH).unwrap();
    let mut prover = Prover::new(&method_code, EVM_CALC_ID).unwrap();
    prover.add_input_u32_slice(to_vec(input).unwrap().as_slice());
    let receipt = prover.run().unwrap();
    assert!(receipt.verify(EVM_CALC_ID).is_ok());
    let result: Vec<String> = from_slice(receipt.journal.as_slice()).unwrap();
    result
}

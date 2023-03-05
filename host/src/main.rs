use methods::{EVM_CALC_ID, EVM_CALC_PATH};
use risc0_zkvm::Prover;
use risc0_zkvm::serde::{from_slice, to_vec};

fn main() {
    println!("Proving state change after hack tx...");

    let calldata = "63d9b770"; // exploit()
    let blockchain_settings = r#"
        {
			"gas_price": "0",
			"origin": "0x0000000000000000000000000000000000000000",
			"block_hashes": "[]",
			"block_number": "0",
			"block_coinbase": "0x0000000000000000000000000000000000000000",
			"block_timestamp": "0",
			"block_difficulty": "0",
			"block_gas_limit": "0",
			"chain_id": "1",
			"block_base_fee_per_gas": "0"
        }
    "#;

    let result = run_prover(
        calldata,
        blockchain_settings
    );
    println!("Results: there's a certain tx that makes target contract eth balance go [from, to, private input hash] = {:?}", result);
}

fn run_prover(
    calldata: &str,
    blockchain_settings: &str
) -> Vec<String>{
    println!("Making the prover...");
    let method_code = std::fs::read(EVM_CALC_PATH).unwrap();
    let mut prover = Prover::new(&method_code, EVM_CALC_ID).unwrap();
    prover.add_input_u32_slice(to_vec(calldata).unwrap().as_slice());
    prover.add_input_u32_slice(to_vec(blockchain_settings).unwrap().as_slice());
    println!("Running the prover...");
    let receipt = prover.run().unwrap();
    println!("Verifying the prover...");
    assert!(receipt.verify(EVM_CALC_ID).is_ok());
    println!("Proof verified!");
    let result: Vec<String> = from_slice(receipt.journal.as_slice()).unwrap();
    result
}

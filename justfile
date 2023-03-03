compile-contract:
    solc --bin-runtime \
        --optimize \
        --overwrite \
        --evm-version istanbul \
        --output-dir bytecode \
        bytecode/Target.sol  
    solc --bin-runtime \
        --optimize \
        --overwrite \
        --evm-version istanbul \
        --output-dir bytecode \
        bytecode/Exploiter.sol  

test-evm: compile-contract
    cargo test -p evm-runner -- --nocapture

prove: compile-contract
    cargo run --release -p host


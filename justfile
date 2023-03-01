compile-contract:
    solc --bin-runtime \
        --optimize \
        --overwrite \
        --evm-version istanbul \
        --output-dir bytecode \
        bytecode/Wrapper.sol  

test-evm-runtime: compile-contract
    cargo test -p evm-runner

prove: compile-contract
    cargo run --release -p host


# zkpoex - Zero-Knowledge Proof of Exploit
# Run `just` to see all available recipes.
# Run `just <recipe>` to execute one.

ZKPOEX := "./target/release/zkpoex"

# Default: list available recipes
default:
    @just --list

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

# Build the CLI (debug, skips ZK guest compilation)
build:
    RISC0_SKIP_BUILD=1 cargo build -p zkpoex-cli

# Build the CLI in release mode (compiles the RISC-V guest)
build-release:
    cargo build -p zkpoex-cli --release

# Build with Apple Silicon GPU acceleration (best performance on macOS)
build-metal:
    cargo build -p zkpoex-cli --release --features metal

# Build with NVIDIA GPU acceleration
build-cuda:
    cargo build -p zkpoex-cli --release --features cuda

# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------

# Run unit tests (skip RISC-V guest build for speed)
test:
    RISC0_SKIP_BUILD=1 cargo test -p bridge-types -p bridge-logic -p host-utils -p zkpoex-cli

# Run end-to-end tests (requires anvil + solc)
test-e2e:
    bash tests/e2e_simple.sh

# Run unit tests with output visible
test-verbose:
    RISC0_SKIP_BUILD=1 cargo test -p bridge-types -p bridge-logic -p host-utils -p zkpoex-cli -- --nocapture

# Run the full workspace tests (includes guest build)
test-full:
    cargo test

# ---------------------------------------------------------------------------
# Lint & Format
# ---------------------------------------------------------------------------

# Run clippy on all non-guest crates
lint:
    RISC0_SKIP_BUILD=1 cargo clippy -p bridge-types -p bridge-logic -p host-utils -p zkpoex-cli -- -D warnings

# Check formatting
fmt-check:
    cargo fmt --all -- --check

# Auto-fix formatting
fmt:
    cargo fmt --all

# Run all checks (what CI runs)
ci: fmt-check lint test

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

# Run an arbitrary CLI command against the release binary.
# Example: `just run -- --help`
run *args:
    {{ZKPOEX}} {{args}}

# Explain a PoC and optionally emit assertions/CLI command.
explain poc rpc_url block_number *extra:
    cargo run -p zkpoex-cli --release --features metal -- explain \
        --poc {{ poc }} \
        --rpc-url {{ rpc_url }} \
        --block-number {{ block_number }} \
        {{ if extra != "" { extra } else { "" } }}

# Dry-run an exploit PoC (no proof generation).
# Pass any additional flags via `extra`, e.g. `--assertions file.txt --caller 0x... --debug`.
dry-run poc rpc_url block_number *extra:
    cargo run -p zkpoex-cli --release --features metal -- prove \
        --poc {{ poc }} \
        --rpc-url {{ rpc_url }} \
        --block-number {{ block_number }} \
        {{ if extra != "" { extra } else { "" } }} \
        --dry-run

# Generate a proof (release + Metal)
prove poc rpc_url block_number output *extra:
    cargo run -p zkpoex-cli --release --features metal -- prove \
        --poc {{ poc }} \
        --rpc-url {{ rpc_url }} \
        --block-number {{ block_number }} \
        {{ if extra != "" { extra } else { "" } }} \
        -o {{ output }}

# Verify a proof file.
# Pass expected flags via `extra`, e.g. `--assertions file.txt --nonce 0x... --caller 0x... --rpc-url ...`
verify proof *extra:
    cargo run -p zkpoex-cli -- verify {{ proof }} {{ if extra != "" { extra } else { "" } }}

# ---------------------------------------------------------------------------
# Dev mode (fast iteration, no real proof)
# ---------------------------------------------------------------------------

# Run prove in dev mode (skips real proving, no cryptographic guarantees)
dev-prove poc rpc_url block_number *extra:
    RISC0_DEV_MODE=1 cargo run -p zkpoex-cli --release --features metal -- prove \
        --poc {{ poc }} \
        --rpc-url {{ rpc_url }} \
        --block-number {{ block_number }} \
        {{ if extra != "" { extra } else { "" } }} \
        -o dev.proof

# Profile guest execution (generates pprof output)
profile poc rpc_url block_number *extra:
    RISC0_PPROF_OUT=profile.pb RISC0_DEV_MODE=1 \
        cargo run -p zkpoex-cli --release --features metal -- prove \
        --poc {{ poc }} \
        --rpc-url {{ rpc_url }} \
        --block-number {{ block_number }} \
        {{ if extra != "" { extra } else { "" } }} \
        -o /dev/null
    @echo "Profile written to profile.pb"
    @echo "View with: go tool pprof -http=:8080 profile.pb"

# ---------------------------------------------------------------------------
# Local dev environment
# ---------------------------------------------------------------------------

# Start a local anvil node on port 18545
anvil:
    anvil --port 18545 --block-time 1

# Clean the RPC cache
clean-cache:
    cargo run -p zkpoex-cli -- clean

# Clean all build artifacts
clean:
    cargo clean

# ---------------------------------------------------------------------------
# Quick examples
# ---------------------------------------------------------------------------

# Dry-run SimpleTx against local anvil
example-simple: build
    cargo run -p zkpoex-cli -- prove \
        --poc tests/fixtures/SimpleTx.sol \
        --rpc-url http://localhost:18545 \
        --block-number 1 \
        --dry-run

# Dry-run ReentrancyExploit against local anvil
example-reentrancy: build
    cargo run -p zkpoex-cli -- prove \
        --poc tests/fixtures/ReentrancyExploit.sol \
        --rpc-url http://localhost:18545 \
        --block-number 1 \
        --deal "0x412049F92065a2597458c4cE9b969C846fE994fD:100ETH" \
        --dry-run

# Dry-run MissingOnlyOwner against local anvil
example-access-control: build
    cargo run -p zkpoex-cli -- prove \
        --poc tests/fixtures/MissingOnlyOwner.sol \
        --rpc-url http://localhost:18545 \
        --block-number 1 \
        --deal "0x412049F92065a2597458c4cE9b969C846fE994fD:10ETH" \
        --dry-run

# Dry-run a real-world PoC from pocs/
example-parity-mainnet rpc_url:
    just dry-run pocs/parity_wallet/PoC.sol {{rpc_url}} 4043799 --assertions pocs/parity_wallet/assertions.txt --debug

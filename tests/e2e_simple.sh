#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# End-to-end dry-run tests for the zkpoex pipeline.
# Requires: anvil (from foundry), solc
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PASS=0
FAIL=0

run_test() {
    local name="$1"
    shift
    echo "--- TEST: $name ---"
    if "$@"; then
        echo "PASS: $name"
        ((PASS++))
    else
        echo "FAIL: $name"
        ((FAIL++))
    fi
    echo
}

# Check dependencies
if ! command -v anvil &>/dev/null; then
    echo "ERROR: anvil not found. Install foundry: https://getfoundry.sh"
    exit 1
fi

if ! command -v solc &>/dev/null; then
    echo "ERROR: solc not found."
    exit 1
fi

# Start anvil in background with auto-mining every second
echo "Starting anvil..."
anvil --port 18546 --block-time 1 --silent &
ANVIL_PID=$!
trap "kill $ANVIL_PID 2>/dev/null || true" EXIT

# Wait for anvil to be ready and for block >= 1 to be mined
echo "Waiting for block 1..."
for i in $(seq 1 20); do
    RESULT=$(curl -s http://localhost:18546 -X POST -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' 2>/dev/null || true)
    if echo "$RESULT" | grep -q '"result"'; then
        BLOCK_HEX=$(echo "$RESULT" | python3 -c "import sys,json; print(int(json.load(sys.stdin)['result'],16))" 2>/dev/null || echo 0)
        if [ "$BLOCK_HEX" -ge 1 ] 2>/dev/null; then
            break
        fi
    fi
    sleep 1
done

echo "Anvil ready."
echo

# Build the CLI
echo "Building zkpoex..."
RISC0_SKIP_BUILD=1 cargo build -p zkpoex-cli 2>&1
ZKPOEX="$PROJECT_ROOT/target/debug/zkpoex"
echo

# --- Test 1: SimpleTx dry-run ---
run_test "SimpleTx dry-run" \
    "$ZKPOEX" prove \
    --poc "$SCRIPT_DIR/fixtures/SimpleTx.sol" \
    --rpc-url http://localhost:18546 \
    --block-number 1 \
    --dry-run

# --- Test 2: MissingOnlyOwner dry-run (with deal) ---
run_test "MissingOnlyOwner dry-run" \
    "$ZKPOEX" prove \
    --poc "$SCRIPT_DIR/fixtures/MissingOnlyOwner.sol" \
    --rpc-url http://localhost:18546 \
    --block-number 1 \
    --deal "0x412049F92065a2597458c4cE9b969C846fE994fD:10ETH" \
    --dry-run

# --- Test 3: ReentrancyExploit dry-run (with deal) ---
run_test "ReentrancyExploit dry-run" \
    "$ZKPOEX" prove \
    --poc "$SCRIPT_DIR/fixtures/ReentrancyExploit.sol" \
    --rpc-url http://localhost:18546 \
    --block-number 1 \
    --deal "0x412049F92065a2597458c4cE9b969C846fE994fD:100ETH" \
    --dry-run

# --- Test 4: CLI --help ---
run_test "CLI --help" \
    "$ZKPOEX" --help

# --- Test 5: prove --help ---
run_test "prove --help" \
    "$ZKPOEX" prove --help

# --- Test 6: verify --help ---
run_test "verify --help" \
    "$ZKPOEX" verify --help

# --- Test 7: clean command ---
run_test "clean command" \
    "$ZKPOEX" clean

# --- Summary ---
echo "=============================="
echo "Results: $PASS passed, $FAIL failed"
echo "=============================="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi

> **⚠️ Legal Notice**: See [DISCLAIMER](./DISCLAIMER) before using this software.

# zkPoEX Usage Guide

This document describes common use cases for `zkpoex`, a CLI tool for generating
Zero-Knowledge Proofs of EVM state transitions. Each use case below
has been tested against a local Anvil instance.

## Prerequisites

- **Rust** (stable, via `rustup`)
- **solc** (Solidity compiler, `>=0.8.20`)
- **anvil** (from [Foundry](https://getfoundry.sh)) for local testing

Build the CLI:

```bash
# For dry-run testing (skips guest RISC-V build):
RISC0_SKIP_BUILD=1 cargo build -p zkpoex-cli

# For full proving (requires RISC Zero toolchain):
cargo build -p zkpoex-cli --release
```

## Quick Guide (PoC-First Workflow)

This is the simplest end‑to‑end flow for researchers:

1. **Explain (interactive):** run the PoC, detect transfers, and pick assertions.
2. **Prove:** generate the ZK proof using the suggested assertions.
3. **Verify:** check the proof offline with the same assertions.

```bash
# 1) Explain and generate assertions
zkpoex explain \
    --poc path/to/Exploit.sol \
    --rpc-url https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY \
    --block-number 17007838 \
    --interactive \
    --emit-assertions assertions.txt \
    --emit-cli

# 2) Prove using the saved assertions
zkpoex prove \
    --poc path/to/Exploit.sol \
    --rpc-url https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY \
    --block-number 17007838 \
    --assertions assertions.txt \
    -o exploit.proof

# 3) Verify with the same assertions
zkpoex verify exploit.proof \
    --rpc-url https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY \
    --assertions assertions.txt
```

If you want to test without proving, add `--dry-run` to `prove`.

For real-world exploit walkthroughs and exact commands, see `pocs/README.md`.

**Caller binding:** By default, the exploit transaction is sent from the synthetic
address `0x000000000000000000000000000000000000add1`. Use `--caller` to bind the
proof to a specific sender.

**BLOCKHASH:** zkpoex currently **disallows** the `BLOCKHASH` opcode to avoid
unauthenticated randomness. If your PoC uses `blockhash(...)`, proving will fail.

## Explain (Interactive Assertion Builder)

Use `explain` to run a preflight dry-run, detect transfers, and generate a
ready-to-run `prove` command. This avoids manual ERC20 storage slot lookup.

```bash
zkpoex explain \
    --poc pocs/sushi_router/PoC.sol \
    --rpc-url https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY \
    --block-number 17007838 \
    --interactive
```

Non-interactive mode (auto-select largest transfer + emit CLI):

```bash
zkpoex explain \
    --poc pocs/sushi_router/PoC.sol \
    --rpc-url https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY \
    --block-number 17007838 \
    --auto-assert \
    --emit-assertions assertions.txt \
    --emit-cli
```

---


## Proving Modes (Fast vs Slow)

By default, proving runs in **fast mode**. Fast mode skips call-trace hashing and full state diff computation to reduce proving time.
Use `--slow` if you need those additional commitments (e.g., to verify call-trace hash or verify-only `changed:` assertions).

```bash
# Fast mode (default)
zkpoex prove --poc exploit.sol --block-number 17007838 --assertions assertions.txt

# Slow mode (extra commitments)
zkpoex prove --poc exploit.sol --block-number 17007838 --assertions assertions.txt --slow
```

---

## Proving “No Privileges” (Not Owner)

To show the exploit works **without owner/admin privileges**, bind the caller
and assert that the caller is **not** the owner in pre‑state. This is enforced
inside the ZK proof.

```bash
zkpoex prove \
    --poc path/to/Exploit.sol \
    --rpc-url https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY \
    --block-number 17007838 \
    --caller 0x000000000000000000000000000000000000add1 \
    --assert not-owner:0xVictimContract:0x0 \
    --assert no-deals \
    -o exploit.proof
```

Notes:
- `not-owner:ADDRESS:SLOT` checks that the pre‑state storage slot does **not**
  equal the caller address (Solidity’s packed `address` layout).
- If the protocol uses a role/allowlist mapping, assert that mapping slot is `0`
  pre‑state instead (use a `slot:` assertion or extend with a custom helper).
## Full Prove + Verify Workflow

Once you've validated a dry-run, generate and verify a full ZK proof:

```bash
# 1. Generate proof
zkpoex prove \
    --poc tests/fixtures/MissingOnlyOwner.sol \
    --rpc-url http://localhost:18545 \
    --block-number 1 \
    --deal "0x0000000000000000000000000000000987123aBc:10ETH" \
    -o missing_owner.proof

# 2. Verify proof (must pass the same deals)
zkpoex verify missing_owner.proof \
    --rpc-url http://localhost:18545 \
    --deal "0x0000000000000000000000000000000987123aBc:10ETH"
```

The verifier checks:
1. The RISC Zero receipt is valid against the guest program image ID
2. The `deals_hash` in the journal matches the hash of the CLI-provided deals
3. The exploit execution succeeded inside the ZK circuit
4. Optional: assertion hashes, nonce, and call-trace commitment (if supplied)

---

## JSON Output

Use `--json` for machine-readable output (useful for CI or piping to `jq`):

```bash
zkpoex --json prove \
    --poc tests/fixtures/SimpleTx.sol \
    --rpc-url http://localhost:18545 \
    --block-number 1 \
    -o simple.proof
```

```json
{
  "success": true,
  "gas_used": 21234,
  "exit_reason": "Stop",
  "deals_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "assertions_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "assertions_ok": true,
  "nonce": "0000000000000000000000000000000000000000000000000000000000000000",
  "caller": "0x000000000000000000000000000000000000add1",
  "call_trace_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "proof_path": "simple.proof",
  "proof_size": 123456,
  "chain_id": 31337,
  "block_number": 1
}
```

---

## Confidential Bounty Workflow (Verifier-Friendly)

This is the recommended flow when you want to prove exploitability without revealing the PoC or calldata.

**1) Verifier provides a challenge nonce**
- Ask the verifier to give you a fresh `nonce` (32‑byte hex).
- This binds the proof to the verifier and demonstrates you have the exact calldata/PoC.

**2) Choose public impact assertions**
- `--assert no-deals` (no balance overrides)
- `--assert balance:ADDRESS:FROM:TO` (public balance change)
- `--assert slot:ADDRESS:SLOT:FROM:TO` (public storage change)
- `--assert not-owner:ADDRESS:SLOT` (prove caller is not owner in pre‑state)

**3) Prove**
```bash
zkpoex prove \
    --poc exploit.sol \
    --rpc-url https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY \
    --block-number 17007841 \
    --nonce 0x1234 \
    --caller 0x000000000000000000000000000000000000add1 \
    --assert no-deals \
    --assert not-owner:0xVictim:0x0 \
    --assert balance:0xVictim:0x00:0x01 \
    --assert slot:0xToken:0xSlot:0x00:0x01 \
    -o exploit.proof
```

**4) Provide the verifier**
- `exploit.proof`
- `nonce`
- the exact assertions
- optional `call-trace-hash` (commitment to the call sequence)

**5) Verify**
```bash
zkpoex verify exploit.proof \
    --rpc-url https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY \
    --nonce 0x1234 \
    --caller 0x000000000000000000000000000000000000add1 \
    --assert no-deals \
    --assert not-owner:0xVictim:0x0 \
    --assert balance:0xVictim:0x00:0x01 \
    --assert slot:0xToken:0xSlot:0x00:0x01 \
    --poc-code-hash 0x... \
    --call-trace-hash 0x...
```

---

## Configuration File

Save default settings in `~/.zkpoex/config.toml` to avoid repeating flags:

```toml
rpc_url = "https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY"
```

Then just run:

```bash
zkpoex prove --poc exploit.sol --block-number 17007841 --dry-run
```

The RPC URL resolution order is: CLI flag > `ZKPOEX_RPC_URL`/`RPC_URL` env var > config file.

---

## Deal Format

Deals override account balances for the exploit simulation. Format:

```
0x<40 hex chars>:<amount>[ETH|wei]
```

Examples:

| Deal string | Effect |
|---|---|
| `0x0000000000000000000000000000000987123aBc:10ETH` | Set balance to 10 ETH |
| `0xAbC...123:5000000000000000000wei` | Set balance to 5 ETH (in wei) |
| `0xAbC...123:1000` | Set balance to 1000 wei |
| `0xAbC...123:1.5ETH` | Set balance to 1.5 ETH |

Multiple deals can be specified:

```bash
zkpoex prove --poc exploit.sol --rpc-url ... \
    --deal "0xAddr1:10ETH" \
    --deal "0xAddr2:5ETH"
```

---

## Assertions, Nonce, and Call-Trace Commitments

These flags let a verifier confirm impact without seeing your PoC or calldata.

Assertion formats:
- `no-deals`
- `balance:ADDRESS:FROM:TO`
- `slot:ADDRESS:SLOT:FROM:TO`
- `erc20:TOKEN:OWNER:FROM:TO[:SLOT_INDEX]`
- `transfer:TOKEN:FROM:TO:AMOUNT[:SLOT_INDEX]`
- `changed:ADDRESS` (verify-only)
- `slot-changed:ADDRESS:SLOT` (verify-only)

**Prove (with assertions + challenge nonce):**

```bash
zkpoex prove \
    --poc exploit.sol \
    --rpc-url http://localhost:18545 \
    --block-number 1 \
    --nonce 0x1234 \
    --assert no-deals \
    --assert balance:0xVictim:0x00:0x01 \
    --assert slot:0xToken:0xSlot:0x00:0x01 \
    -o exploit.proof
```

**Verify (same assertions + nonce + optional call-trace commitment):**

```bash
zkpoex verify exploit.proof \
    --nonce 0x1234 \
    --assert no-deals \
    --assert balance:0xVictim:0x00:0x01 \
    --assert slot:0xToken:0xSlot:0x00:0x01 \
    --call-trace-hash 0x... \
    --deal "0x0000000000000000000000000000000987123aBc:10ETH"
```

Notes:
- `--nonce` binds the proof to a verifier challenge.
- `--assert` entries are committed inside the proof; the verifier can check them by providing the same assertions.
- You can also load them from a file using `--assertions assertions.txt`.
- `--call-trace-hash` lets a verifier bind the proof to a known call-trace commitment without revealing calldata.

---

## Cache Management

zkpoex caches RPC responses in `~/.zkpoex/cache/` to speed up repeated runs.

```bash
# Clear all cache
zkpoex clean

# Clear cache for a specific chain
zkpoex clean --chain-id 1
```

---

## Writing Your Own Exploit PoC

1. Create a Solidity file with a contract named `Exploit`
2. The contract must have a function `exploit()` with selector `0x63d9b770`
3. The exploit runs as a single transaction from the default caller address
4. Use `require()` statements to assert the exploit succeeded
5. Use `--deal` flags to set up initial balances as needed

```solidity
pragma solidity ^0.8.20;

contract Exploit {
    function exploit() external {
        // Your exploit logic here
        // Use require() to assert success conditions
    }
}
```

The PoC contract is deployed at address `0x0000000000000000000000000000000987123aBc`
and called by `0x000000000000000000000000000000000000add1`.

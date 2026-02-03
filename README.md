# zkPoEX

**Prove a vulnerability exists without revealing how to exploit it.**

> **⚠️** By using this software you agree to the [DISCLAIMER](./DISCLAIMER). For authorized security research only.

[![Rust](https://img.shields.io/badge/rust-stable-orange.svg?logo=rust)](https://www.rust-lang.org/)
[![RISC0](https://img.shields.io/badge/risc0-v3.0.4-blueviolet.svg)](https://www.risczero.com/)
[![License: MIT + Disclaimer](https://img.shields.io/badge/license-MIT%20%2B%20Disclaimer-yellow.svg)](DISCLAIMER)

---

## Why It Matters

Today, a white-hat researcher who discovers a vulnerability must transmit the actual exploit code to the protocol team to prove it works. If that code leaks — through a compromised inbox, a careless forward, or an insider — the protocol can be drained before a fix ships.

zkPoEX eliminates the transmission of exploit code. By allowing **proof without payload**, the researcher proves exploitability cryptographically while the exploit mechanics stay private. The protocol learns *that* a vulnerability exists and *what* its impact is, without ever receiving code that could be replayed.

zkPoEX executes the simulation **locally** and does **not** broadcast transactions to any live blockchain network. It only performs read-only RPC queries to fetch public chain data needed to build the proving input.

---

## Quick Start

### Prerequisites

- **Rust** (stable)
- **Foundry** (for `anvil` and `solc`)

### Installation

No prebuilt binaries are distributed. You must build from source.

#### One-Line Install (macOS/Linux)

```bash
curl -fsSL https://raw.githubusercontent.com/zkoranges/zkPoEX/main/install.sh | bash
```

This clones the repository and builds from source. On Apple Silicon it automatically enables Metal GPU acceleration. Requires `git` and `cargo`.

#### Manual Build

```bash
git clone https://github.com/zkoranges/zkPoEX
cd zkPoEX
cargo build -p zkpoex-cli --release --features <gpu>
```

Replace `<gpu>` with the flag for your platform:

| Flag    | Platform                |
|---------|-------------------------|
| `metal` | Apple Silicon (macOS)   |
| `cuda`  | NVIDIA GPUs             |

Omit `--features` entirely to build without GPU acceleration.

### PoC-First Flow

**1) Explain** (interactive, generates assertions)

```bash
./target/release/zkpoex explain \
    --poc pocs/sushi_router/PoC.sol \
    --rpc-url https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY \
    --block-number 17007838 \
    --interactive \
    --emit-assertions assertions.txt \
    --emit-cli
```

**2) Prove** (uses the saved assertions)

```bash
./target/release/zkpoex prove \
    --poc pocs/sushi_router/PoC.sol \
    --rpc-url https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY \
    --block-number 17007838 \
    --assertions assertions.txt \
    -o exploit.proof
```

**3) Verify** (offline, same assertions)

```bash
./target/release/zkpoex verify exploit.proof \
    --assertions assertions.txt
```

For detailed usage, see [`USAGE.md`](USAGE.md). For real-world exploit walkthroughs, see [`pocs/README.md`](pocs/README.md).

---

## Counterfactual Execution Model

zkPoEX proofs are **not** claims that a historical on-chain transaction happened.
They are **counterfactual**: a proof attests that, starting from the authenticated pre-state of a real Ethereum block,
there exists a transaction that executes successfully and satisfies the public assertions you chose.

Concretely:
- The proof is bound to a real block via `block_number`, `chain_id`, and the block `state_root` (and other env fields).
- The PoC contract is injected into an overlay at `--contract-address` *only if that address is empty at the fork point*
  (zkPoEX refuses to overwrite real chain code).
- A single call to `Exploit.exploit()` is executed from `--caller` with the chosen `gas_limit`.
- No transaction is broadcast to mainnet: the execution happens locally inside the prover/verifier model.
- Optional "deals" can override balances inside the guest; use `--assert no-deals` to prove no balance overrides were used.

---

## Assertion Grammar

All public claims are expressed via `--assert`:

- `no-deals`
- `balance:ADDRESS:FROM:TO`
- `slot:ADDRESS:SLOT:FROM:TO`
- `erc20:TOKEN:OWNER:FROM:TO[:SLOT_INDEX]`
- `transfer:TOKEN:FROM:TO:AMOUNT[:SLOT_INDEX]`
- `not-owner:ADDRESS:SLOT`
- `changed:ADDRESS` (verify-only)
- `slot-changed:ADDRESS:SLOT` (verify-only)

Assertions are hash-committed inside the proof. Verification succeeds only if the verifier supplies **the same assertion set** (or a matching `assertions.txt` file).

---

## Architecture (High-Level)

- **Host**: fetches authenticated chain state, compiles PoC, orchestrates proof generation.
- **Guest (ZKVM)**: verifies Merkle proofs, checks bytecode hash, executes EVM, commits public journal.
- **Verifier**: validates the receipt and checks assertion commitments against their own expectations.

---

## Repository Layout

- `pocs/` — real-world exploit PoCs with minimal assertions and exact prove/verify commands.
- `tests/fixtures/` — small fixtures used by unit/integration tests.
- `bin/zkpoex-cli/` — CLI implementation.
- `guests/` — zkVM guest code.

---

## Limitations (Intentional)

This is a research prototype. It is designed to be useful and verifier-friendly, but it does **not** prove every
property a verifier might wish it proved.

### What zkPoEX Proves (When Verification Passes)

A verifying receipt means the zkVM guest program ran, and the guest committed the `ExploitJournal` included in the
receipt. Concretely, the proof attests to the following statements, as implemented by the guest:

- The guest verified EIP-1186 Merkle Patricia Trie proofs against the claimed block `state_root` for the accounts and
  storage slots the proof depends on.
- The guest bound execution to the block environment included in the journal (at minimum `chain_id`, `block_number`,
  `timestamp`, `basefee`, `block_gas_limit`, and `state_root`).
- The PoC contract was injected at the chosen `--contract-address`, and proving fails if that address is non-empty on
  chain at the target block (we never overwrite real chain state).
- The exploit call executed inside `revm` under the derived hardfork spec for that block, from the chosen `--caller`.
- The public `--assert` set is enforced inside the guest, and the committed `assertions_hash` binds the proof to the
  exact assertion list the verifier expects.
- Deals (balance overrides) are applied inside the guest, and the committed `deals_hash` binds the proof to the exact
  deal list the verifier expects.
- If provided, `--nonce` is committed in the journal to support verifier-challenge binding and replay resistance.
- If `--slow` was used, the proof can additionally commit a call-trace hash and a state-diff summary (as recorded in
  the journal).

### What zkPoEX Does Not Prove

These are important non-goals and sharp edges for verifiers:

- Canonical chain inclusion: the proof contains a `state_root`, but it does not by itself prove that this `state_root`
  is the canonical head/state for a given chain. Verifiers should independently verify the block header (and thus the
  `state_root`) from a trusted source (for example by passing `--rpc-url` to `zkpoex verify`).
- Economic meaning or intent: "execution succeeded" does not imply the behavior is malicious, unauthorized, or
  exploitable in the bounty sense. You must choose assertions that capture the intended impact.
- Multi-transaction / multi-block exploits: zkPoEX proves a single transaction execution of `Exploit.exploit()`. It
  does not natively model time-delayed, multi-tx, or off-chain coordination requirements.
- Completeness of impact: unless you commit a full state diff (slow mode), the verifier only learns what your chosen
  assertions reveal. A proof can be valid while omitting other important side effects.
- Exact client equivalence: execution uses `revm`. The proof inherits any semantic mismatches or bugs in `revm` (or in
  the fork-selection logic) relative to a real client and the target chain.
- Perfect confidentiality: zk proofs hide the PoC bytecode and calldata, but the public journal fields (gas used,
  chosen assertions, optional state diff) can leak information. A determined verifier can sometimes infer mechanics by
  search or side-channel reasoning.

### Security Notes (Read Before Relying On Proofs)

- zkPoEX is not a formal verification system. Its security depends on the correctness of the guest program, the host
  tooling, and the underlying proof system (RISC Zero) and its cryptographic assumptions.
- `RISC0_DEV_MODE` receipts (fake proofs) must never be treated as evidence. `zkpoex verify` rejects dev-mode receipts.
- No one can honestly guarantee that false proofs are impossible. The intent is that forging a proof that verifies but
  lies should be computationally infeasible under standard assumptions, but software vulnerabilities, integration
  mistakes, or future cryptographic breaks could make forgery possible.

### BLOCKHASH Restriction

To preserve soundness without adding heavy commitments, zkPoEX currently disallows the `BLOCKHASH` opcode. If a PoC
executes `BLOCKHASH`, proving will fail. This avoids relying on block hashes that are not authenticated by the state
root and are awkward to validate inside the circuit.

---

## License & Disclaimer

**License: MIT + Strict Usage Disclaimer.** See [`DISCLAIMER`](DISCLAIMER) for prohibited use cases (e.g., Extortion/Ransomware).

This tool is a **research artifact** and experimental prototype. It is intended for academic study, authorized security testing, and the exploration of ZKVM capabilities. Users are responsible for ensuring they have permission to test any systems they target. The authors assume no liability for misuse.

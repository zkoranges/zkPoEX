> **⚠️** All PoCs are for authorized security research only. See [DISCLAIMER](../DISCLAIMER).

# PoC Catalog

This directory holds **real‑world exploit PoCs** and their **minimal proof claims**.
Each PoC lives in its own folder with a consistent structure, so adding new exploits
is just copy‑paste.

## Structure (per PoC)

```
pocs/<slug>/
  PoC.sol            # The exploit contract
  assertions.txt     # Minimal public claims for verification
  README.md          # Context + exact prove/verify commands
```

## Current PoCs

| Slug | Exploit | Target Block | PoC | Assertions |
|---|---|---:|---|---|
| `parity_wallet` | Unprotected `initWallet` (2017) | 4,043,799 | `pocs/parity_wallet/PoC.sol` | `pocs/parity_wallet/assertions.txt` |
| `sushi_router` | RouteProcessor2 callback (2023) | 17,007,838 | `pocs/sushi_router/PoC.sol` | `pocs/sushi_router/assertions.txt` |
| `euler_finance` | Flashloan + liquidation drain (2023) | 16,817,995 | `pocs/euler_finance/PoC.sol` | `pocs/euler_finance/assertions.txt` |

## Adding a New PoC

1. Create a new folder under `pocs/` (use a short, stable slug).
2. Place the Solidity PoC in `PoC.sol`.
3. Generate minimal assertions (ideally with `zkpoex explain`).
4. Document the exploit and commands in `README.md`.

The goal is **minimal assertions** that prove impact, not a full state diff.

## Responsible Use

These PoCs document historical vulnerabilities that have already been publicly disclosed and patched. They are provided for educational purposes and to demonstrate zkPoEX capabilities. Do not use these techniques against live, unpatched systems.

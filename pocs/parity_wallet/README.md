# Parity Wallet (2017) — Unprotected `initWallet`

**Vulnerability:** Access control failure in `initWallet()`  
**Wallet:** `0xBEc591De75b8699A3Ba52F073428822d0Bfc0D7e`  
**Historical attacker:** `0xB3764761E297D6f121e79C32A65829Cd1dDb4D32`  
**Proof receiver (zkpoex caller):** `0x000000000000000000000000000000000000add1`  
**Target block:** `4043799` (pre‑drain)  

## PoC

`pocs/parity_wallet/PoC.sol`

The PoC reproduces the **full exploit sequence in a single transaction**:
1. Call `initWallet` to take ownership (unprotected).
2. Call `execute` to drain the wallet to the caller.

## Assertions

`pocs/parity_wallet/assertions.txt` contains the minimal public claims:
- No deals
- Wallet balance goes to zero
- Caller balance increases to the drained amount **plus** the tool’s fixed “gas funding” seed.
  Note: assertions use the *proven on-chain pre-state* for the caller (which is zero at this block), not the seeded balance.

## Prove

```bash
zkpoex prove \
  --poc pocs/parity_wallet/PoC.sol \
  --rpc-url $RPC_URL \
  --block-number 4043799 \
  --assertions pocs/parity_wallet/assertions.txt \
  -o parity_wallet.proof
```

## Verify

```bash
zkpoex verify parity_wallet.proof \
  --assertions pocs/parity_wallet/assertions.txt
```

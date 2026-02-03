# Euler Finance (2023) — Flashloan + Liquidation Drain

**Vulnerability:** Euler’s lending accounting could be exploited via a crafted
deposit/mint/repay/donate sequence + liquidation, draining protocol‑held assets.  
**Original tx:** `0xc310a0affe2169d1f6feec1c63dbc7f7c62a887fa48795d327d4d2da2d6b111d`  
**Historical attacker EOA:** `0x5F259D0b76665c337c6104145894F4D1D2758B8c`  
**Token:** DAI (`0x6B175474E89094C44Da98b954EedeAC495271d0F`)  
**Aave flashloan:** 30,000,000 DAI (premium 27,000 DAI)  

## Target Block Notes

The tx above is the **first tx in block `16817996`** (tx index `0`).  
To prove the exploit from a clean snapshot, fork from the **previous block**
(`16817995`), which matches the tx’s pre‑state.

## PoC

`pocs/euler_finance/PoC.sol`

## Assertions

`pocs/euler_finance/assertions.txt` contains the minimal public claims:
- `no-deals`
- Euler’s DAI balance goes from ~8.904M DAI to 0
- The default zkpoex caller (`0x000000000000000000000000000000000000add1`) ends with the profit

## Prove

```bash
zkpoex prove \
  --poc pocs/euler_finance/PoC.sol \
  --rpc-url $RPC_URL \
  --block-number 16817995 \
  --assertions pocs/euler_finance/assertions.txt \
  -o euler_finance.proof
```

## Verify

```bash
zkpoex verify euler_finance.proof \
  --assertions pocs/euler_finance/assertions.txt
```

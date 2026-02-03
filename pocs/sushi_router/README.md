# Sushi RouteProcessor2 (2023) — Arbitrary Pool Callback

**Vulnerability:** RouteProcessor2 allows arbitrary pool addresses (callback hijack)  
**Victim:** `0x31d3243CfB54B34Fc9C73e1CB1137124bD6B13E1`  
**Token:** WETH  
**Target block:** `17007838`  

## PoC

`pocs/sushi_router/PoC.sol`

## Assertions

`pocs/sushi_router/assertions.txt` asserts the victim‑to‑PoC WETH transfer
and enforces `no-deals`.

## Prove

```bash
zkpoex prove \
  --poc pocs/sushi_router/PoC.sol \
  --rpc-url $RPC_URL \
  --block-number 17007838 \
  --assertions pocs/sushi_router/assertions.txt \
  -o sushi_router.proof
```

## Verify

```bash
zkpoex verify sushi_router.proof \
  --assertions pocs/sushi_router/assertions.txt
```

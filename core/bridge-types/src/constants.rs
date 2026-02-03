// SPDX-License-Identifier: MIT
use hex_literal::hex;

/// Default caller address for exploit transactions (synthetic: ...add1).
pub const DEFAULT_CALLER: [u8; 20] = hex!("000000000000000000000000000000000000add1");

/// Default contract address where the PoC exploit is deployed (synthetic: ...23abc).
///
/// This address MUST be empty (nonce=0, balance=0, code=empty) at the target block,
/// or proving will fail (we never overwrite real chain state).
pub const DEFAULT_CONTRACT_ADDRESS: [u8; 20] = hex!("0000000000000000000000000000000987123abc");

/// Function selector for `exploit()` — keccak256("exploit()")[..4].
pub const CALL_EXPLOIT_DATA: [u8; 4] = hex!("63d9b770");

/// Default gas limit for exploit transactions (30M).
pub const DEFAULT_GAS_LIMIT: u64 = 30_000_000;

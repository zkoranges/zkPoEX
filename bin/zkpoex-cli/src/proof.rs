// SPDX-License-Identifier: MIT
use bridge_types::types::DealRecord;
use risc0_zkvm::Receipt;
use serde::{Deserialize, Serialize};

/// Serialized proof bundle containing all verification data.
#[derive(Serialize, Deserialize)]
pub struct Proof {
    pub version: u32,
    pub chain_id: u64,
    pub block_number: u64,
    pub poc_code_hash: [u8; 32],
    pub deals: Vec<DealRecord>,
    pub receipt: Receipt,
}

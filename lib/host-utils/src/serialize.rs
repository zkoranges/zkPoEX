// SPDX-License-Identifier: MIT
use anyhow::{Context, Result};
use rkyv::Deserialize;

use bridge_types::types::ExploitInput;

/// Serialize an `ExploitInput` to rkyv bytes (no compression).
pub fn serialize_and_compress(input: &ExploitInput) -> Result<Vec<u8>> {
    let rkyv_bytes = rkyv::to_bytes::<_, 1024>(input)
        .map_err(|e| anyhow::anyhow!("rkyv serialization failed: {}", e))
        .context("serialize ExploitInput to rkyv")?;
    Ok(rkyv_bytes.into_vec())
}

/// Validate and deserialize rkyv bytes as an `ExploitInput`.
pub fn decompress_and_validate(bytes: &[u8]) -> Result<ExploitInput> {
    let archived = rkyv::check_archived_root::<ExploitInput>(bytes)
        .map_err(|e| anyhow::anyhow!("rkyv validation failed: {}", e))
        .context("validate rkyv archive")?;

    let input: ExploitInput = archived
        .deserialize(&mut rkyv::Infallible)
        .map_err(|e| anyhow::anyhow!("rkyv deserialization failed: {:?}", e))
        .context("deserialize ExploitInput from rkyv")?;

    Ok(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bridge_types::types::{Assertion, DealRecord, ExploitOptions, RkyvBlockEnv, RkyvMemDB};
    use std::collections::BTreeMap;

    fn make_test_input() -> ExploitInput {
        ExploitInput {
            original_db: RkyvMemDB {
                accounts: BTreeMap::new(),
                block_hashes: BTreeMap::new(),
            },
            deals: vec![DealRecord {
                address: [0xaa; 20],
                balance: [0x01; 32],
            }],
            assertions: vec![Assertion::NoDeals],
            nonce: [0x11; 32],
            caller: [0xcc; 20],
            contract_address: [0xdd; 20],
            env: RkyvBlockEnv {
                number: 17007841,
                timestamp: 1681000000,
                coinbase: [0; 20],
                difficulty: [0; 32],
                gas_limit: 30_000_000,
                basefee: [0; 32],
                prevrandao: None,
                excess_blob_gas: None,
                chain_id: 1,
                state_root: [0xaa; 32],
            },
            poc_bytecode: vec![0x60, 0x00, 0x60, 0x00],
            gas_limit: 30_000_000,
            proofs: vec![],
            options: ExploitOptions::default(),
        }
    }

    #[test]
    fn test_round_trip() {
        let original = make_test_input();
        let compressed = serialize_and_compress(&original).unwrap();
        let restored = decompress_and_validate(&compressed).unwrap();

        assert_eq!(original.gas_limit, restored.gas_limit);
        assert_eq!(original.poc_bytecode, restored.poc_bytecode);
        assert_eq!(original.deals.len(), restored.deals.len());
        assert_eq!(original.deals[0].address, restored.deals[0].address);
        assert_eq!(original.env.chain_id, restored.env.chain_id);
        assert_eq!(original.env.number, restored.env.number);
        assert_eq!(original.caller, restored.caller);
    }

    #[test]
    fn test_serialization_works() {
        let original = make_test_input();
        let rkyv_bytes = rkyv::to_bytes::<_, 1024>(&original).unwrap();
        let serialized = serialize_and_compress(&original).unwrap();

        // Without compression, the serialized output should match rkyv output
        assert_eq!(rkyv_bytes.as_slice(), serialized.as_slice());
    }

    #[test]
    fn test_invalid_data_fails() {
        let result = decompress_and_validate(b"not valid rkyv data");
        assert!(result.is_err());
    }
}

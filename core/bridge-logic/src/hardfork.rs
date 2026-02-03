// SPDX-License-Identifier: MIT
use revm::primitives::SpecId;

/// Determine the appropriate EVM specification based on chain ID and timestamp.
///
/// For Ethereum Mainnet (chain 1), uses timestamp-based fork detection:
///   - timestamp < 1681338455  → MERGE  (pre-Shanghai, block < 17,034,870)
///   - timestamp < 1710338135  → SHANGHAI (pre-Cancun, block < 19,426,587)
///   - timestamp >= 1710338135 → CANCUN
///
/// L2 chains default to CANCUN. Unknown chains default to SHANGHAI.
pub fn spec_id_from_chain(chain_id: u64, timestamp: u64) -> SpecId {
    match chain_id {
        1 => {
            // Ethereum Mainnet: timestamp-based fork detection
            const SHANGHAI_TS: u64 = 1_681_338_455; // Block 17,034,870
            const CANCUN_TS: u64 = 1_710_338_135; // Block 19,426,587
            if timestamp >= CANCUN_TS {
                SpecId::CANCUN
            } else if timestamp >= SHANGHAI_TS {
                SpecId::SHANGHAI
            } else {
                SpecId::MERGE
            }
        }
        10 => SpecId::CANCUN,    // Optimism
        8453 => SpecId::CANCUN,  // Base
        42161 => SpecId::CANCUN, // Arbitrum One
        _ => SpecId::SHANGHAI,
    }
}

/// Returns true if the given chain ID is an L2 that requires
/// block gas limit validation to be disabled.
pub fn is_l2_chain(chain_id: u64) -> bool {
    matches!(chain_id, 10 | 8453 | 42161)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mainnet_merge() {
        // Pre-Shanghai timestamp (block 17,007,841 era)
        assert_eq!(spec_id_from_chain(1, 1_681_000_000), SpecId::MERGE);
    }

    #[test]
    fn test_mainnet_shanghai() {
        // Post-Shanghai, pre-Cancun
        assert_eq!(spec_id_from_chain(1, 1_681_338_455), SpecId::SHANGHAI);
        assert_eq!(spec_id_from_chain(1, 1_700_000_000), SpecId::SHANGHAI);
    }

    #[test]
    fn test_mainnet_cancun() {
        assert_eq!(spec_id_from_chain(1, 1_710_338_135), SpecId::CANCUN);
        assert_eq!(spec_id_from_chain(1, 1_800_000_000), SpecId::CANCUN);
    }

    #[test]
    fn test_optimism_is_cancun() {
        assert_eq!(spec_id_from_chain(10, 0), SpecId::CANCUN);
    }

    #[test]
    fn test_base_is_cancun() {
        assert_eq!(spec_id_from_chain(8453, 0), SpecId::CANCUN);
    }

    #[test]
    fn test_arbitrum_is_cancun() {
        assert_eq!(spec_id_from_chain(42161, 0), SpecId::CANCUN);
    }

    #[test]
    fn test_unknown_chain_is_shanghai() {
        assert_eq!(spec_id_from_chain(999, 0), SpecId::SHANGHAI);
    }

    #[test]
    fn test_l2_detection() {
        assert!(is_l2_chain(10));
        assert!(is_l2_chain(8453));
        assert!(is_l2_chain(42161));
        assert!(!is_l2_chain(1));
        assert!(!is_l2_chain(999));
    }
}

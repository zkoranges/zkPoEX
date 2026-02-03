// SPDX-License-Identifier: MIT
use alloy_primitives::{Address, B256, U256};

/// Convert an alloy `Address` to a fixed `[u8; 20]`.
pub fn addr_to_fixed(addr: Address) -> [u8; 20] {
    addr.0.into()
}

/// Convert a `[u8; 20]` to an alloy `Address`.
pub fn fixed_to_addr(bytes: [u8; 20]) -> Address {
    Address::from(bytes)
}

/// Convert an alloy `U256` to a big-endian `[u8; 32]`.
pub fn u256_to_fixed(val: U256) -> [u8; 32] {
    val.to_be_bytes()
}

/// Convert a big-endian `[u8; 32]` to an alloy `U256`.
pub fn fixed_to_u256(bytes: [u8; 32]) -> U256 {
    U256::from_be_bytes(bytes)
}

/// Convert an alloy `B256` to a `[u8; 32]`.
pub fn b256_to_fixed(val: B256) -> [u8; 32] {
    val.0
}

/// Convert a `[u8; 32]` to an alloy `B256`.
pub fn fixed_to_b256(bytes: [u8; 32]) -> B256 {
    B256::from(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_addr_round_trip() {
        let addr = Address::ZERO;
        assert_eq!(fixed_to_addr(addr_to_fixed(addr)), addr);

        let addr = Address::from([0xff; 20]);
        assert_eq!(fixed_to_addr(addr_to_fixed(addr)), addr);
    }

    #[test]
    fn test_u256_round_trip() {
        let val = U256::ZERO;
        assert_eq!(fixed_to_u256(u256_to_fixed(val)), val);

        let val = U256::MAX;
        assert_eq!(fixed_to_u256(u256_to_fixed(val)), val);

        let val = U256::from(42u64);
        assert_eq!(fixed_to_u256(u256_to_fixed(val)), val);
    }

    #[test]
    fn test_b256_round_trip() {
        let val = B256::ZERO;
        assert_eq!(fixed_to_b256(b256_to_fixed(val)), val);

        let val = B256::from([0xab; 32]);
        assert_eq!(fixed_to_b256(b256_to_fixed(val)), val);
    }

    #[test]
    fn test_addr_zero_is_zero_bytes() {
        assert_eq!(addr_to_fixed(Address::ZERO), [0u8; 20]);
    }
}

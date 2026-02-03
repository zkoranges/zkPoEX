// SPDX-License-Identifier: MIT
use std::fmt;
use std::str::FromStr;

use alloy_primitives::{Address, U256};

use crate::conversions::{addr_to_fixed, u256_to_fixed};
use crate::types::DealRecord;

/// Error type for parsing deal strings.
#[derive(Debug, Clone)]
pub struct DealParseError {
    pub message: String,
}

impl fmt::Display for DealParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid deal: {}", self.message)
    }
}

impl std::error::Error for DealParseError {}

impl FromStr for DealRecord {
    type Err = DealParseError;

    /// Parse a deal string in the format `0x<40 hex chars>:<amount>[ETH|wei]`.
    ///
    /// Examples:
    /// - `"0xAbCd...1234:100ETH"` — 100 ETH (converted to wei)
    /// - `"0xAbCd...1234:500wei"` — 500 wei
    /// - `"0xAbCd...1234:1000"` — 1000 wei (default unit)
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = |msg: &str| DealParseError {
            message: msg.to_string(),
        };

        let (addr_str, amount_str) = s
            .split_once(':')
            .ok_or_else(|| err("expected format '0x<address>:<amount>[ETH|wei]'"))?;

        // Parse address
        if !addr_str.starts_with("0x") && !addr_str.starts_with("0X") {
            return Err(err("address must start with 0x"));
        }
        if addr_str.len() != 42 {
            return Err(err("address must be exactly 42 characters (0x + 40 hex)"));
        }
        let address =
            Address::from_str(addr_str).map_err(|e| err(&format!("invalid address: {e}")))?;

        // Parse amount with optional suffix
        let (num_str, unit) = if let Some(stripped) = amount_str
            .strip_suffix("ETH")
            .or_else(|| amount_str.strip_suffix("eth"))
        {
            (stripped, "ETH")
        } else if let Some(stripped) = amount_str.strip_suffix("wei") {
            (stripped, "wei")
        } else {
            (amount_str, "wei")
        };

        if num_str.is_empty() {
            return Err(err("amount cannot be empty"));
        }

        // Check for decimal point (only valid with ETH)
        let balance_wei = if num_str.contains('.') {
            if unit != "ETH" {
                return Err(err("decimal amounts only valid with ETH suffix"));
            }
            parse_eth_decimal(num_str)?
        } else {
            let amount = U256::from_str_radix(num_str, 10)
                .map_err(|e| err(&format!("invalid amount: {e}")))?;
            if unit == "ETH" {
                amount
                    .checked_mul(U256::from(10u64).pow(U256::from(18u64)))
                    .ok_or_else(|| err("amount overflow when converting ETH to wei"))?
            } else {
                amount
            }
        };

        Ok(DealRecord {
            address: addr_to_fixed(address),
            balance: u256_to_fixed(balance_wei),
        })
    }
}

/// Parse a decimal ETH amount like "1.5" into wei.
fn parse_eth_decimal(s: &str) -> Result<U256, DealParseError> {
    let err = |msg: &str| DealParseError {
        message: msg.to_string(),
    };

    let (whole, frac) = s
        .split_once('.')
        .ok_or_else(|| err("expected decimal point"))?;

    if frac.len() > 18 {
        return Err(err("too many decimal places (max 18 for ETH)"));
    }

    let whole_wei = if whole.is_empty() {
        U256::ZERO
    } else {
        U256::from_str_radix(whole, 10)
            .map_err(|e| err(&format!("invalid whole part: {e}")))?
            .checked_mul(U256::from(10u64).pow(U256::from(18u64)))
            .ok_or_else(|| err("overflow"))?
    };

    let frac_padded = format!("{:0<18}", frac);
    let frac_wei = U256::from_str_radix(&frac_padded, 10)
        .map_err(|e| err(&format!("invalid fractional part: {e}")))?;

    whole_wei
        .checked_add(frac_wei)
        .ok_or_else(|| err("overflow"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conversions::fixed_to_u256;

    #[test]
    fn test_parse_eth_whole() {
        let deal: DealRecord = "0xe42a4fc3902506f15E7E8FC100542D6310d1c93a:100ETH"
            .parse()
            .unwrap();
        let balance = fixed_to_u256(deal.balance);
        let expected = U256::from(100u64) * U256::from(10u64).pow(U256::from(18u64));
        assert_eq!(balance, expected);
    }

    #[test]
    fn test_parse_eth_decimal() {
        let deal: DealRecord = "0xe42a4fc3902506f15E7E8FC100542D6310d1c93a:1.5ETH"
            .parse()
            .unwrap();
        let balance = fixed_to_u256(deal.balance);
        let expected = U256::from(15u64) * U256::from(10u64).pow(U256::from(17u64));
        assert_eq!(balance, expected);
    }

    #[test]
    fn test_parse_wei() {
        let deal: DealRecord = "0xe42a4fc3902506f15E7E8FC100542D6310d1c93a:500wei"
            .parse()
            .unwrap();
        let balance = fixed_to_u256(deal.balance);
        assert_eq!(balance, U256::from(500u64));
    }

    #[test]
    fn test_parse_no_unit_defaults_to_wei() {
        let deal: DealRecord = "0xe42a4fc3902506f15E7E8FC100542D6310d1c93a:1000"
            .parse()
            .unwrap();
        let balance = fixed_to_u256(deal.balance);
        assert_eq!(balance, U256::from(1000u64));
    }

    #[test]
    fn test_parse_missing_colon() {
        let result = "0xe42a4fc3902506f15E7E8FC100542D6310d1c93a500".parse::<DealRecord>();
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_bad_address() {
        let result = "0xZZZZ:100ETH".parse::<DealRecord>();
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_no_0x_prefix() {
        let result = "e42a4fc3902506f15E7E8FC100542D6310d1c93a:100ETH".parse::<DealRecord>();
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_negative_amount() {
        let result = "0xe42a4fc3902506f15E7E8FC100542D6310d1c93a:-100ETH".parse::<DealRecord>();
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_empty_amount() {
        let result = "0xe42a4fc3902506f15E7E8FC100542D6310d1c93a:".parse::<DealRecord>();
        assert!(result.is_err());
    }
}

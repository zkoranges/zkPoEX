// SPDX-License-Identifier: MIT
use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, Result};
use tracing::warn;

use alloy_primitives::{Address, Bytes, U256};

use bridge_types::conversions::{addr_to_fixed, u256_to_fixed};
use bridge_types::types::Assertion;
use host_utils::rpc::RpcClient;

const MAX_SLOT_SCAN: u64 = 10;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyAssertion {
    Changed(Address),
    StorageChanged { address: Address, slot: U256 },
}

#[derive(Debug, Default)]
pub struct ParsedAssertions {
    pub guest: Vec<Assertion>,
    pub verify_only: Vec<VerifyAssertion>,
    pub has_no_deals: bool,
}

pub fn load_assertions_file(path: &Path) -> Result<Vec<String>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read assertions from {}", path.display()))?;
    let mut out = Vec::new();
    for line in content.lines() {
        if let Some(spec) = normalize_assert_line(line) {
            out.push(spec);
        }
    }
    Ok(out)
}

pub fn normalize_assert_line(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.starts_with('#') || trimmed.starts_with("//") {
        return None;
    }
    let stripped = trimmed
        .strip_prefix("--assert")
        .map(str::trim)
        .or_else(|| trimmed.strip_prefix("assert").map(str::trim))
        .unwrap_or(trimmed);
    if stripped.is_empty() {
        None
    } else {
        Some(stripped.to_string())
    }
}

pub async fn parse_assertions(
    entries: &[String],
    rpc: Option<&RpcClient>,
    block_number: Option<u64>,
) -> Result<ParsedAssertions> {
    let mut parsed = ParsedAssertions::default();
    for entry in entries {
        let Some(spec) = normalize_assert_line(entry) else {
            continue;
        };
        let parsed_entry = parse_assertion_entry(&spec, rpc, block_number).await?;
        if parsed_entry.has_no_deals {
            parsed.has_no_deals = true;
        }
        parsed.guest.extend(parsed_entry.guest);
        parsed.verify_only.extend(parsed_entry.verify_only);
    }
    Ok(parsed)
}

async fn parse_assertion_entry(
    input: &str,
    rpc: Option<&RpcClient>,
    block_number: Option<u64>,
) -> Result<ParsedAssertions> {
    let parts: Vec<&str> = input.split(':').collect();
    if parts.is_empty() {
        anyhow::bail!("empty assertion");
    }
    let kind = parts[0].trim().to_lowercase();
    let mut parsed = ParsedAssertions::default();

    match kind.as_str() {
        "no-deals" => {
            parsed.guest.push(Assertion::NoDeals);
            parsed.has_no_deals = true;
        }
        "balance" => {
            let assertion = parse_balance(&parts)?;
            parsed.guest.push(assertion);
        }
        "slot" => {
            let assertion = parse_slot(&parts)?;
            parsed.guest.push(assertion);
        }
        "erc20" => {
            let assertion = parse_erc20(&parts, rpc, block_number).await?;
            parsed.guest.push(assertion);
        }
        "transfer" => {
            let assertions = parse_transfer(&parts, rpc, block_number).await?;
            parsed.guest.extend(assertions);
        }
        "not-owner" => {
            let assertion = parse_not_owner(&parts)?;
            parsed.guest.push(assertion);
        }
        "changed" => {
            let addr = parse_address_arg(parts.get(1))?;
            parsed.verify_only.push(VerifyAssertion::Changed(addr));
        }
        "slot-changed" => {
            if parts.len() != 3 {
                anyhow::bail!("Invalid format. Expected slot-changed:ADDRESS:SLOT");
            }
            let addr = parse_address_arg(parts.get(1))?;
            let slot = parse_u256_arg(parts.get(2))?;
            parsed.verify_only.push(VerifyAssertion::StorageChanged {
                address: addr,
                slot,
            });
        }
        _ => {
            anyhow::bail!(
                "Unknown assertion type '{}'. Expected one of: no-deals, balance, slot, erc20, transfer, not-owner, changed, slot-changed",
                kind
            );
        }
    }

    Ok(parsed)
}

fn parse_balance(parts: &[&str]) -> Result<Assertion> {
    if parts.len() != 4 {
        anyhow::bail!("Invalid format. Expected balance:ADDRESS:FROM:TO");
    }
    let address = parse_address_arg(parts.get(1))?;
    let from = parse_u256_arg(parts.get(2))?;
    let to = parse_u256_arg(parts.get(3))?;

    Ok(Assertion::Balance {
        address: addr_to_fixed(address),
        from: u256_to_fixed(from),
        to: u256_to_fixed(to),
    })
}

fn parse_slot(parts: &[&str]) -> Result<Assertion> {
    if parts.len() != 5 {
        anyhow::bail!("Invalid format. Expected slot:ADDRESS:SLOT:FROM:TO");
    }
    let address = parse_address_arg(parts.get(1))?;
    let slot = parse_u256_arg(parts.get(2))?;
    let from = parse_u256_arg(parts.get(3))?;
    let to = parse_u256_arg(parts.get(4))?;

    Ok(Assertion::Storage {
        address: addr_to_fixed(address),
        slot: u256_to_fixed(slot),
        from: u256_to_fixed(from),
        to: u256_to_fixed(to),
    })
}

fn parse_not_owner(parts: &[&str]) -> Result<Assertion> {
    if parts.len() != 3 {
        anyhow::bail!("Invalid format. Expected not-owner:ADDRESS:SLOT");
    }
    let address = parse_address_arg(parts.get(1))?;
    let slot = parse_u256_arg(parts.get(2))?;
    Ok(Assertion::NotOwner {
        address: addr_to_fixed(address),
        slot: u256_to_fixed(slot),
    })
}

async fn parse_erc20(
    parts: &[&str],
    rpc: Option<&RpcClient>,
    block_number: Option<u64>,
) -> Result<Assertion> {
    if parts.len() != 5 && parts.len() != 6 {
        anyhow::bail!("Invalid format. Expected erc20:TOKEN:OWNER:FROM:TO[:SLOT_INDEX]");
    }
    let token = parse_address_arg(parts.get(1))?;
    let owner = parse_address_arg(parts.get(2))?;
    let from = parse_u256_arg(parts.get(3))?;
    let to = parse_u256_arg(parts.get(4))?;

    let slot_index = if parts.len() == 6 {
        parse_u256_arg(parts.get(5))?
    } else {
        let client = rpc.context("erc20 assertion requires RPC to infer slot")?;
        let block = block_number.context("erc20 assertion requires block number")?;
        infer_balance_slot_for_owner(client, token, owner, block)
            .await?
            .ok_or_else(|| {
                anyhow::anyhow!("failed to infer ERC20 balance slot; provide SLOT_INDEX")
            })?
    };

    let slot_key = erc20_balance_slot(owner, slot_index);

    Ok(Assertion::Storage {
        address: addr_to_fixed(token),
        slot: slot_key,
        from: u256_to_fixed(from),
        to: u256_to_fixed(to),
    })
}

async fn parse_transfer(
    parts: &[&str],
    rpc: Option<&RpcClient>,
    block_number: Option<u64>,
) -> Result<Vec<Assertion>> {
    if parts.len() != 5 && parts.len() != 6 {
        anyhow::bail!("Invalid format. Expected transfer:TOKEN:FROM:TO:AMOUNT[:SLOT_INDEX]");
    }
    let client = rpc.context("transfer assertion requires RPC")?;
    let block = block_number.context("transfer assertion requires block number")?;
    let token = parse_address_arg(parts.get(1))?;
    let from_addr = parse_address_arg(parts.get(2))?;
    let to_addr = parse_address_arg(parts.get(3))?;
    let amount = parse_u256_arg(parts.get(4))?;

    let slot_index = if parts.len() == 6 {
        parse_u256_arg(parts.get(5))?
    } else {
        infer_balance_slot_for_token(client, token, &[from_addr, to_addr], block)
            .await?
            .ok_or_else(|| {
                anyhow::anyhow!("failed to infer ERC20 balance slot; provide SLOT_INDEX")
            })?
    };

    let from_slot = erc20_balance_slot(from_addr, slot_index);
    let to_slot = erc20_balance_slot(to_addr, slot_index);

    let from_before = client
        .get_storage_at(token, U256::from_be_bytes(from_slot), block)
        .await
        .context("failed to fetch from balance via RPC")?;
    let to_before = client
        .get_storage_at(token, U256::from_be_bytes(to_slot), block)
        .await
        .context("failed to fetch to balance via RPC")?;

    if from_before < amount {
        anyhow::bail!("transfer amount exceeds from balance at block {}", block);
    }

    let from_after = from_before - amount;
    let to_after = to_before + amount;

    Ok(vec![
        Assertion::Storage {
            address: addr_to_fixed(token),
            slot: from_slot,
            from: u256_to_fixed(from_before),
            to: u256_to_fixed(from_after),
        },
        Assertion::Storage {
            address: addr_to_fixed(token),
            slot: to_slot,
            from: u256_to_fixed(to_before),
            to: u256_to_fixed(to_after),
        },
    ])
}

fn parse_address_arg(value: Option<&&str>) -> Result<Address> {
    let raw = value.context("missing address")?;
    Address::from_str(raw).context("failed to parse address")
}

fn parse_u256_arg(value: Option<&&str>) -> Result<U256> {
    let raw = value.context("missing numeric value")?;
    U256::from_str(raw).context("failed to parse numeric value")
}

pub async fn infer_balance_slot_for_owner(
    client: &RpcClient,
    token: Address,
    owner: Address,
    block_number: u64,
) -> Result<Option<U256>> {
    let balance = erc20_balance_of(client, token, owner, block_number).await?;
    if balance.is_zero() {
        return Ok(None);
    }
    find_balance_slot_for_owner(client, token, owner, balance, block_number).await
}

pub async fn infer_balance_slot_for_token(
    client: &RpcClient,
    token: Address,
    owners: &[Address],
    block_number: u64,
) -> Result<Option<U256>> {
    for owner in owners {
        if *owner == Address::ZERO {
            continue;
        }
        if let Some(slot) =
            infer_balance_slot_for_owner(client, token, *owner, block_number).await?
        {
            return Ok(Some(slot));
        }
    }
    Ok(None)
}

async fn erc20_balance_of(
    client: &RpcClient,
    token: Address,
    owner: Address,
    block_number: u64,
) -> Result<U256> {
    const BALANCE_OF_SELECTOR: [u8; 4] = [0x70, 0xa0, 0x82, 0x31];
    let mut data = [0u8; 4 + 32];
    data[..4].copy_from_slice(&BALANCE_OF_SELECTOR);
    data[4 + 12..].copy_from_slice(owner.as_slice());
    client
        .eth_call_u256(token, Bytes::copy_from_slice(&data), block_number)
        .await
        .context("balanceOf eth_call failed")
}

async fn find_balance_slot_for_owner(
    client: &RpcClient,
    token: Address,
    owner: Address,
    expected: U256,
    block_number: u64,
) -> Result<Option<U256>> {
    if expected.is_zero() {
        return Ok(None);
    }
    for idx in 0..=MAX_SLOT_SCAN {
        let slot_key = erc20_balance_slot(owner, U256::from(idx));
        let value = client
            .get_storage_at(token, U256::from_be_bytes(slot_key), block_number)
            .await
            .context("eth_getStorageAt failed")?;
        if value == expected {
            return Ok(Some(U256::from(idx)));
        }
    }
    Ok(None)
}

fn erc20_balance_slot(owner: Address, slot_index: U256) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[12..32].copy_from_slice(owner.as_slice());
    buf[32..].copy_from_slice(&slot_index.to_be_bytes::<32>());
    alloy_primitives::keccak256(buf).0
}

pub fn warn_verify_only(assertions: &[VerifyAssertion]) {
    if assertions.is_empty() {
        return;
    }
    warn!("Verifier-only assertions are ignored during proving");
}

#[cfg(test)]
mod tests {
    use super::*;
    use bridge_types::types::Assertion;

    #[tokio::test]
    async fn test_parse_balance_assertion() {
        let inputs = vec!["balance:0x0000000000000000000000000000000000000001:0:10".to_string()];
        let parsed = parse_assertions(&inputs, None, None).await.expect("parse");
        assert_eq!(parsed.guest.len(), 1);
        matches!(parsed.guest[0], Assertion::Balance { .. });
    }

    #[tokio::test]
    async fn test_parse_no_deals() {
        let inputs = vec!["no-deals".to_string()];
        let parsed = parse_assertions(&inputs, None, None).await.expect("parse");
        assert!(parsed.has_no_deals);
    }

    #[tokio::test]
    async fn test_parse_changed_verify_only() {
        let inputs = vec!["changed:0x0000000000000000000000000000000000000002".to_string()];
        let parsed = parse_assertions(&inputs, None, None).await.expect("parse");
        assert!(parsed.guest.is_empty());
        assert_eq!(parsed.verify_only.len(), 1);
    }

    #[tokio::test]
    async fn test_parse_not_owner() {
        let inputs = vec!["not-owner:0x0000000000000000000000000000000000000002:0x0".to_string()];
        let parsed = parse_assertions(&inputs, None, None).await.expect("parse");
        assert_eq!(parsed.guest.len(), 1);
        matches!(parsed.guest[0], Assertion::NotOwner { .. });
    }

    #[test]
    fn test_normalize_line() {
        assert_eq!(
            normalize_assert_line(" --assert balance:0x1:0:1 "),
            Some("balance:0x1:0:1".to_string())
        );
        assert_eq!(normalize_assert_line("# comment"), None);
    }
}

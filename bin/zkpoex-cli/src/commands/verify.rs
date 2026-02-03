// SPDX-License-Identifier: MIT
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args;
use tracing::{info, warn};

use alloy_primitives::Address;
use bridge_types::types::{compute_assertions_hash, compute_deals_hash, DealRecord};
use host_utils::rpc::RpcClient;
use risc0_zkvm::InnerReceipt;
use std::str::FromStr;

use crate::assertions::{self, VerifyAssertion};
use crate::config;

#[derive(Args, Debug)]
pub struct VerifyArgs {
    /// Path to the proof file.
    pub path: PathBuf,

    /// Expected deals (must match what was used during proving).
    #[arg(long = "deal")]
    pub deals: Vec<String>,

    /// Expected nonce (32-byte hex) to bind the proof to a verifier challenge.
    #[arg(long)]
    pub nonce: Option<String>,

    /// Public assertions. Format: "TYPE:...".
    /// Types: no-deals, balance, slot, erc20, transfer, not-owner, changed, slot-changed.
    #[arg(long = "assert")]
    pub assertions: Vec<String>,

    /// Load assertions from a file (one per line).
    #[arg(long = "assertions")]
    pub assertions_file: Option<PathBuf>,

    /// Expected call trace hash (32-byte hex) to bind the proof to a known call trace.
    #[arg(long = "call-trace-hash")]
    pub call_trace_hash: Option<String>,

    /// RPC URL to verify `state_root` (and block env) against the real chain.
    ///
    /// If omitted, zkPoEX will try `ZKPOEX_RPC_URL`, then `RPC_URL`, then `~/.zkpoex/config.toml`.
    /// If no RPC URL is available, `state_root` is displayed but not verified.
    #[arg(long = "rpc-url")]
    pub rpc_url: Option<String>,

    /// Verify that the proof corresponds to a specific PoC code hash (hex string).
    /// Used to ensure the proof matches a specific source code.
    #[arg(long = "poc-code-hash")]
    pub poc_code_hash: Option<String>,

    /// Expected caller address for the exploit transaction. If omitted, caller is not checked.
    #[arg(long)]
    pub caller: Option<String>,

    /// Expected contract address where the PoC was injected. If omitted, contract address is not checked.
    #[arg(long = "contract-address")]
    pub contract_address: Option<String>,
}

pub async fn run(args: VerifyArgs, json_output: bool) -> Result<()> {
    // Load proof
    let proof_bytes = std::fs::read(&args.path)
        .with_context(|| format!("failed to read proof from {}", args.path.display()))?;

    let proof: crate::proof::Proof =
        bincode::deserialize(&proof_bytes).context("failed to deserialize proof")?;

    info!(
        version = proof.version,
        chain_id = proof.chain_id,
        block_number = proof.block_number,
        "Loaded proof"
    );

    if matches!(&proof.receipt.inner, InnerReceipt::Fake(_)) {
        anyhow::bail!("Receipt is a dev-mode FakeReceipt; re-run proving without RISC0_DEV_MODE");
    }

    // Verify the receipt
    info!("Verifying receipt...");
    proof
        .receipt
        .verify(guests::EXPLOIT_ID)
        .context("receipt verification failed")?;

    info!("Receipt verification passed");

    // Decode journal
    let journal: bridge_types::types::ExploitJournal = proof
        .receipt
        .journal
        .decode()
        .context("failed to decode journal")?;

    info!(
        success = journal.success,
        gas_used = journal.gas_used,
        exit_reason = %journal.exit_reason,
        block_number = journal.block_number,
        chain_id = journal.chain_id,
        state_root = %hex::encode(journal.state_root),
        poc_code_hash = %hex::encode(journal.poc_code_hash),
        "Journal decoded"
    );

    // Parse and verify deals
    let cli_deals: Vec<DealRecord> = args
        .deals
        .iter()
        .map(|s| s.parse::<DealRecord>())
        .collect::<Result<Vec<_>, _>>()
        .context("failed to parse deal arguments")?;

    let expected_hash = compute_deals_hash(&cli_deals);
    if expected_hash != journal.deals_hash {
        anyhow::bail!(
            "Deals hash mismatch!\n  Expected: {}\n  Got:      {}",
            hex::encode(expected_hash),
            hex::encode(journal.deals_hash)
        );
    }

    info!("Deals hash verified");

    let mut assertion_specs = Vec::new();
    if let Some(path) = &args.assertions_file {
        assertion_specs.extend(assertions::load_assertions_file(path)?);
    }
    assertion_specs.extend(args.assertions.clone());

    let resolved_rpc_url = config::resolve_rpc_url_optional(args.rpc_url.as_deref().unwrap_or(""));
    let rpc_client = resolved_rpc_url.as_ref().map(|url| RpcClient::new(url));
    let parsed = assertions::parse_assertions(
        &assertion_specs,
        rpc_client.as_ref(),
        Some(journal.block_number),
    )
    .await
    .context("failed to parse assertions")?;

    if parsed.has_no_deals && !cli_deals.is_empty() {
        anyhow::bail!("no-deals assertion provided but deals were specified");
    }

    let assertions = parsed.guest;
    let verify_only = parsed.verify_only;

    if !assertions.is_empty() {
        let expected_assertions_hash = compute_assertions_hash(&assertions);
        if expected_assertions_hash != journal.assertions_hash {
            anyhow::bail!(
                "Assertions hash mismatch!\n  Expected: {}\n  Got:      {}",
                hex::encode(expected_assertions_hash),
                hex::encode(journal.assertions_hash)
            );
        }
        info!("Assertions hash verified");
    } else {
        info!(
            assertions_hash = %hex::encode(journal.assertions_hash),
            "No assertions provided by verifier"
        );
    }

    if !journal.assertions_ok {
        anyhow::bail!("Assertion checks failed inside the proof");
    }

    if let Some(nonce_str) = &args.nonce {
        let expected = parse_fixed_32(nonce_str).context("failed to parse --nonce")?;
        if expected != journal.nonce {
            anyhow::bail!(
                "Nonce mismatch!\n  Expected: {}\n  Journal:  {}",
                hex::encode(expected),
                hex::encode(journal.nonce)
            );
        }
        info!("Nonce verified against --nonce");
    }

    if let Some(caller_str) = &args.caller {
        let expected = parse_address(caller_str).context("failed to parse --caller")?;
        if expected.0 != journal.caller {
            anyhow::bail!(
                "Caller mismatch!\n  Expected: {}\n  Journal:  0x{}",
                caller_str,
                hex::encode(journal.caller)
            );
        }
        info!("Caller verified against --caller");
    }

    if let Some(contract_str) = &args.contract_address {
        let expected = parse_address(contract_str).context("failed to parse --contract-address")?;
        if expected.0 != journal.contract_address {
            anyhow::bail!(
                "Contract address mismatch!\n  Expected: {}\n  Journal:  0x{}",
                contract_str,
                hex::encode(journal.contract_address)
            );
        }
        info!("Contract address verified against --contract-address");
    }

    if let Some(call_hash) = &args.call_trace_hash {
        if !journal.call_trace_enabled {
            anyhow::bail!("Call trace hash not available in this proof (run prover with --slow)");
        }
        let expected = parse_fixed_32(call_hash).context("failed to parse --call-trace-hash")?;
        if expected != journal.call_trace_hash {
            anyhow::bail!(
                "Call trace hash mismatch!\n  Expected: {}\n  Journal:  {}",
                hex::encode(expected),
                hex::encode(journal.call_trace_hash)
            );
        }
        info!("Call trace hash verified against --call-trace-hash");
    }

    // Verify PoC code hash (Critical: binds proof to specific PoC)
    if journal.poc_code_hash != proof.poc_code_hash {
        anyhow::bail!(
            "PoC code hash mismatch!\n  Journal: {}\n  Proof:   {}",
            hex::encode(journal.poc_code_hash),
            hex::encode(proof.poc_code_hash)
        );
    }

    if let Some(expected_hash_hex) = &args.poc_code_hash {
        let expected =
            parse_fixed_32(expected_hash_hex).context("failed to decode expected poc-code-hash")?;
        if expected != journal.poc_code_hash {
            anyhow::bail!(
                "PoC code hash mismatch against expected!\n  Journal:  {}\n  Expected: {}",
                hex::encode(journal.poc_code_hash),
                expected_hash_hex
            );
        }
        info!("PoC code hash verified against --poc-code-hash");
    } else {
        warn!(
            "No --poc-code-hash provided. PoC hash check is internal consistency only. \
             If you have an expected PoC commitment, pass --poc-code-hash (keccak256 of the PoC bytecode)."
        );
    }

    info!("PoC code hash checks passed");

    // Display State Diff
    if journal.state_diff_enabled && !journal.state_diff.0.is_empty() {
        info!("State Changes:");
        for (addr, diff) in &journal.state_diff.0 {
            use bridge_types::types::Delta;
            let addr_str = format!("{:?}", addr);

            // Balance
            match &diff.balance {
                Delta::Changed { from, to } => {
                    // Try to format as Signed ETH change if possible, or just raw values
                    // For CLI output, simple is better.
                    println!("  {}: Balance {} -> {}", addr_str, from, to);
                }
                Delta::Added(val) => println!("  {}: Balance (New) {}", addr_str, val),
                Delta::Removed(_) => println!("  {}: Balance (Removed)", addr_str),
                Delta::Unchanged => {}
            }

            // Nonce
            match &diff.nonce {
                Delta::Changed { from, to } => println!("  {}: Nonce {} -> {}", addr_str, from, to),
                Delta::Added(val) => println!("  {}: Nonce (New) {}", addr_str, val),
                _ => {}
            }

            // Storage
            for (slot, delta) in &diff.storage {
                match delta {
                    Delta::Changed { from, to } => {
                        println!("  {}: Slot {:#x} {:#x} -> {:#x}", addr_str, slot, from, to);
                    }
                    Delta::Added(val) => {
                        println!("  {}: Slot {:#x} (New) {:#x}", addr_str, slot, val)
                    }
                    _ => {}
                }
            }
        }

        println!();
        tracing::warn!("⚠️  INTERPRETATION REQUIRED: A valid proof confirms the state CHANGED.");
        tracing::warn!("⚠️  It does NOT automatically prove the change was MALICIOUS.");
        tracing::warn!("⚠️  Verify that the 'To' values above represent an actual loss/bypass.");
        println!();
    } else if journal.state_diff_enabled {
        info!("No state changes detected (read-only execution?)");
    } else {
        info!("State diff disabled (proof produced in fast mode)");
    }

    for assertion in verify_only {
        match assertion {
            VerifyAssertion::Changed(addr) => {
                if !journal.state_diff_enabled {
                    anyhow::bail!(
                        "State diff not available in this proof (run prover with --slow)"
                    );
                }
                if !journal.state_diff.0.contains_key(&addr) {
                    anyhow::bail!(
                        "Assertion failed: State of {} did not change in this proof.",
                        addr
                    );
                }
                info!("Assertion passed: State of {} changed.", addr);
            }
            VerifyAssertion::StorageChanged { address, slot } => {
                if !journal.state_diff_enabled {
                    anyhow::bail!(
                        "State diff not available in this proof (run prover with --slow)"
                    );
                }
                let changed = if let Some(account_diff) = journal.state_diff.0.get(&address) {
                    account_diff.storage.contains_key(&slot)
                } else {
                    false
                };
                if !changed {
                    anyhow::bail!(
                        "Assertion failed: Storage slot {:#x} on contract {} did NOT change.",
                        slot,
                        address
                    );
                }
                info!("Assertion passed: Slot {:#x} on {} changed.", slot, address);
            }
        }
    }

    // Verify state_root against RPC if an RPC URL is available
    let mut rpc_verified = false;
    if let Some(rpc_url) = &resolved_rpc_url {
        info!("Verifying state_root and block env against RPC...");
        let client = host_utils::rpc::RpcClient::new(rpc_url);
        let header = client
            .get_block_by_number(journal.block_number)
            .await
            .context("failed to fetch block header from RPC")?;

        let rpc_state_root: [u8; 32] = header.state_root.0;
        if rpc_state_root != journal.state_root {
            anyhow::bail!(
                "State root mismatch!\n  Journal:  {}\n  RPC:      {}",
                hex::encode(journal.state_root),
                hex::encode(rpc_state_root)
            );
        }

        // Verify Block Env
        if header.timestamp != journal.timestamp {
            anyhow::bail!(
                "Timestamp mismatch!\n  Journal: {}\n  RPC:     {}",
                journal.timestamp,
                header.timestamp
            );
        }

        let rpc_basefee = header.base_fee_per_gas.unwrap_or(0);
        let journal_basefee = alloy_primitives::U256::from_be_bytes(journal.basefee);
        // Compare as U256
        if alloy_primitives::U256::from(rpc_basefee) != journal_basefee {
            anyhow::bail!(
                "Basefee mismatch!\n  Journal: {}\n  RPC:     {}",
                journal_basefee,
                rpc_basefee
            );
        }

        if header.gas_limit != journal.block_gas_limit {
            anyhow::bail!(
                "Block gas limit mismatch!\n  Journal: {}\n  RPC:     {}",
                journal.block_gas_limit,
                header.gas_limit
            );
        }

        // Also verify chain_id
        let rpc_chain_id = client
            .get_chain_id()
            .await
            .context("failed to get chain_id from RPC")?;
        if rpc_chain_id != journal.chain_id {
            anyhow::bail!(
                "Chain ID mismatch!\n  Journal: {}\n  RPC:     {}",
                journal.chain_id,
                rpc_chain_id
            );
        }

        info!("State root, block env, and chain ID verified against RPC");
        rpc_verified = true;
    } else {
        warn!(
            "No RPC URL available (--rpc-url/ZKPOEX_RPC_URL/RPC_URL/config). \
             State root not verified against the chain. \
             state_root={}, block_number={}, chain_id={}",
            hex::encode(journal.state_root),
            journal.block_number,
            journal.chain_id
        );
    }

    if json_output {
        let result = serde_json::json!({
            "valid": true,
            "success": journal.success,
            "gas_used": journal.gas_used,
            "exit_reason": journal.exit_reason,
            "deals_hash": hex::encode(journal.deals_hash),
            "assertions_hash": hex::encode(journal.assertions_hash),
            "assertions_ok": journal.assertions_ok,
            "nonce": hex::encode(journal.nonce),
            "caller": format!("0x{}", hex::encode(journal.caller)),
            "call_trace_hash": hex::encode(journal.call_trace_hash),
            "call_trace_enabled": journal.call_trace_enabled,
            "state_diff_enabled": journal.state_diff_enabled,
            "chain_id": journal.chain_id,
            "block_number": journal.block_number,
            "state_root": hex::encode(journal.state_root),
            "rpc_verified": rpc_verified,
            "poc_code_hash": hex::encode(journal.poc_code_hash),
            "contract_address": format!("0x{}", hex::encode(journal.contract_address)),
            "state_diff": journal.state_diff,
        });
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else if journal.success {
        info!(
            "Exploit proof VALID: execution succeeded with {} gas used (block={}, chain_id={}, state_root={}{})",
            journal.gas_used,
            journal.block_number,
            journal.chain_id,
            hex::encode(journal.state_root),
            if rpc_verified { ", RPC-verified" } else { "" }
        );
        println!("\n\u{26a0}\u{fe0f}  Local Simulation only. Tool provided 'AS IS' with NO WARRANTY of correctness.");
        println!("Results may be invalid due to bugs or manipulation. See DISCLAIMER.");
    } else {
        info!(
            "Exploit proof VALID but execution failed: {} (block={}, chain_id={}, state_root={}{})",
            journal.exit_reason,
            journal.block_number,
            journal.chain_id,
            hex::encode(journal.state_root),
            if rpc_verified { ", RPC-verified" } else { "" }
        );
        println!("\n\u{26a0}\u{fe0f}  Local Simulation only. Tool provided 'AS IS' with NO WARRANTY of correctness.");
        println!("Results may be invalid due to bugs or manipulation. See DISCLAIMER.");
    }

    Ok(())
}

fn parse_fixed_32(input: &str) -> Result<[u8; 32]> {
    let s = input.strip_prefix("0x").unwrap_or(input);
    let bytes = hex::decode(s).context("invalid hex")?;
    if bytes.len() > 32 {
        anyhow::bail!("expected <= 32 bytes, got {}", bytes.len());
    }
    let mut out = [0u8; 32];
    let start = 32 - bytes.len();
    out[start..].copy_from_slice(&bytes);
    Ok(out)
}

fn parse_address(input: &str) -> Result<Address> {
    Address::from_str(input).context("invalid address")
}

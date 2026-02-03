// SPDX-License-Identifier: MIT
use std::collections::{BTreeMap, HashMap};
use std::io::{self, Write};
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{Context, Result};
use clap::Args;
use tracing::info;

use alloy_primitives::{Address, Bytes, Log, U256};
use revm::primitives::{AccountInfo, Bytecode, ExecutionResult, KECCAK_EMPTY};

use bridge_logic::db::MutableMemDB;
use bridge_logic::executor::sim_exploit;
use bridge_logic::hardfork::spec_id_from_chain;
use bridge_logic::state_diff::compute_state_diff;
use bridge_types::constants::{DEFAULT_CALLER, DEFAULT_CONTRACT_ADDRESS, DEFAULT_GAS_LIMIT};
use bridge_types::conversions::addr_to_fixed;
use bridge_types::types::DealRecord;

use host_utils::compiler::compile_poc;
use host_utils::preflight::build_exploit_input;
use host_utils::rpc::RpcClient;

use crate::assertions;
use crate::config;
use crate::progress;

#[derive(Args, Debug)]
pub struct ExplainArgs {
    /// Path to the Solidity PoC file.
    #[arg(long)]
    pub poc: PathBuf,

    /// Ethereum JSON-RPC endpoint URL.
    #[arg(long, default_value = "")]
    pub rpc_url: String,

    /// Block number to fork from. Uses latest if not specified.
    #[arg(long)]
    pub block_number: Option<u64>,

    /// Balance overrides. Format: 0xAddress:AmountETH or 0xAddress:Amountwei
    #[arg(long = "deal")]
    pub deals: Vec<String>,

    /// Gas limit for the exploit transaction.
    #[arg(long, default_value_t = DEFAULT_GAS_LIMIT)]
    pub gas_limit: u64,

    /// Caller address for the exploit transaction. Defaults to 0x...add1.
    #[arg(long)]
    pub caller: Option<String>,

    /// Contract address where the PoC is injected. Defaults to 0x...1337.
    #[arg(long = "contract-address")]
    pub contract_address: Option<String>,

    /// Limit number of suggested assertions.
    #[arg(long)]
    pub limit: Option<usize>,

    /// Use interactive prompts to select assertions.
    #[arg(long)]
    pub interactive: bool,

    /// Auto-select assertions (non-interactive).
    #[arg(long)]
    pub auto_assert: bool,

    /// Emit a ready-to-run `zkpoex prove` command.
    #[arg(long)]
    pub emit_cli: bool,

    /// Write assertions to a file (one per line).
    #[arg(long)]
    pub emit_assertions: Option<PathBuf>,
}

pub async fn run(args: ExplainArgs, json_output: bool) -> Result<()> {
    let rpc_url = config::resolve_rpc_url(&args.rpc_url)?;

    let deals: Vec<DealRecord> = args
        .deals
        .iter()
        .map(|s| s.parse::<DealRecord>())
        .collect::<Result<Vec<_>, _>>()
        .context("failed to parse deal arguments")?;

    info!(deals = deals.len(), "Parsed deals");

    // Compile PoC
    let sp = progress::spinner("Compiling PoC...");
    let compiled = compile_poc(&args.poc).context("failed to compile PoC")?;
    progress::finish(
        &sp,
        &format!(
            "Compiled PoC ({} bytes, hash {})",
            compiled.bytecode.len(),
            &hex::encode(compiled.code_hash)[..8]
        ),
    );

    // Build RPC client
    let client = RpcClient::new(&rpc_url);

    let block_number = match args.block_number {
        Some(n) => n,
        None => {
            let header = client.get_block_by_number(u64::MAX).await;
            match header {
                Ok(h) => h.number,
                Err(_) => {
                    anyhow::bail!("--block-number is required (could not auto-detect latest block)")
                }
            }
        }
    };

    info!(block_number, "Target block");

    // Preflight: build input (no assertions, zero nonce)
    let sp = progress::spinner("Fetching state...");
    let options = bridge_types::types::ExploitOptions {
        enable_call_trace: false,
        enable_state_diff: true,
    };

    let caller_addr = match &args.caller {
        Some(raw) => Address::from_str(raw).context("failed to parse --caller")?,
        None => Address::from(DEFAULT_CALLER),
    };

    let contract_addr = match &args.contract_address {
        Some(raw) => Address::from_str(raw).context("failed to parse --contract-address")?,
        None => Address::from(DEFAULT_CONTRACT_ADDRESS),
    };

    let (input, _) = build_exploit_input(
        &client,
        block_number,
        compiled.bytecode.clone(),
        deals.clone(),
        Vec::new(),
        [0u8; 32],
        addr_to_fixed(caller_addr),
        addr_to_fixed(contract_addr),
        args.gas_limit,
        options,
        false,
    )
    .await
    .context("preflight failed")?;
    progress::finish(
        &sp,
        &format!(
            "Fetched state ({} accounts)",
            input.original_db.accounts.len()
        ),
    );

    // Build strict DB and inject PoC + caller
    let mut db = MutableMemDB::from_rkyv_strict(input.original_db.clone());
    let poc_code_hash = alloy_primitives::keccak256(&input.poc_bytecode);
    let poc_bytecode = Bytecode::new_raw(Bytes::copy_from_slice(&input.poc_bytecode));
    db.codes
        .insert(poc_code_hash, Bytes::copy_from_slice(&input.poc_bytecode));
    db.accounts.insert(
        contract_addr,
        AccountInfo {
            balance: U256::ZERO,
            nonce: 1,
            code_hash: poc_code_hash,
            code: Some(poc_bytecode),
        },
    );

    db.accounts.insert(
        caller_addr,
        AccountInfo {
            balance: U256::from(1_000_000_000_000_000_000u128),
            nonce: 0,
            code_hash: KECCAK_EMPTY,
            code: Some(Bytecode::default()),
        },
    );

    db.apply_deals(&deals);

    let spec_id = spec_id_from_chain(input.env.chain_id, input.env.timestamp);
    let result = sim_exploit(
        &db,
        &input.env,
        &input.poc_bytecode,
        input.gas_limit,
        caller_addr,
        contract_addr,
        spec_id,
    )
    .context("sim_exploit failed")?;

    let state_diff = compute_state_diff(&result.state, &input.original_db);
    let transfer_candidates = extract_transfer_candidates(&result.result);
    let state_diff_suggestions = build_state_diff_suggestions(&state_diff, args.limit);

    if json_output {
        if args.interactive {
            anyhow::bail!("--interactive cannot be used with --json");
        }
        let out = serde_json::json!({
            "success": result.result.is_success(),
            "exit_reason": format!("{:?}", result.result),
            "state_diff": state_diff,
            "transfer_candidates": transfer_candidates,
            "suggestions": state_diff_suggestions,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    println!("Explain summary:");
    println!("  success: {}", result.result.is_success());
    println!("  exit: {:?}", result.result);

    let mut assert_specs: Vec<String> = Vec::new();
    let mut selected_transfers: Vec<TransferCandidate> = Vec::new();

    if args.interactive {
        if !transfer_candidates.is_empty() {
            println!();
            println!("Detected transfers:");
            for (idx, cand) in transfer_candidates.iter().enumerate() {
                println!(
                    "  {}) {}: {} -> {} amount {}",
                    idx + 1,
                    format!("{:?}", cand.token),
                    format!("{:?}", cand.from),
                    format!("{:?}", cand.to),
                    format_amount(cand.amount)
                );
            }

            let default_idxs = default_transfer_selection(&transfer_candidates, contract_addr);
            let chosen = prompt_transfer_selection(&transfer_candidates, &default_idxs)?;
            selected_transfers = chosen
                .into_iter()
                .filter_map(|i| transfer_candidates.get(i).cloned())
                .collect();
        }

        if deals.is_empty() {
            if prompt_yes_no("Add --assert-no-deals?", true)? {
                assert_specs.push("no-deals".to_string());
            }
        }
    } else if args.auto_assert || args.emit_cli {
        let default_idxs = default_transfer_selection(&transfer_candidates, contract_addr);
        selected_transfers = default_idxs
            .into_iter()
            .filter_map(|i| transfer_candidates.get(i).cloned())
            .collect();
        if deals.is_empty() {
            assert_specs.push("no-deals".to_string());
        }
    }

    if !selected_transfers.is_empty() {
        let slot_map =
            infer_slot_map(&client, block_number, &selected_transfers, args.interactive).await?;
        let mut token_slots: BTreeMap<Address, U256> = BTreeMap::new();
        for (token, slot) in slot_map {
            token_slots.insert(token, slot);
        }
        for transfer in &selected_transfers {
            let slot_suffix = token_slots
                .get(&transfer.token)
                .map(|slot| format!(":0x{:x}", slot));
            let mut spec = format!(
                "transfer:{}:{}:{}:{}",
                format!("{:?}", transfer.token),
                format!("{:?}", transfer.from),
                format!("{:?}", transfer.to),
                format_amount_hex(transfer.amount)
            );
            if let Some(suffix) = slot_suffix {
                spec.push_str(&suffix);
            }
            assert_specs.push(spec);
        }
    }

    println!();
    if !assert_specs.is_empty() {
        println!("Selected assertions:");
        for spec in &assert_specs {
            println!("  --assert {}", spec);
        }
    } else {
        println!("Suggested assertions:");
        for line in &state_diff_suggestions {
            println!("  {}", line);
        }
    }

    if let Some(path) = &args.emit_assertions {
        if !assert_specs.is_empty() {
            write_assertions_file(path, &assert_specs)?;
            println!();
            println!("Assertions written to {}", path.display());
        } else {
            println!();
            println!("No assertions to write.");
        }
    }

    if args.interactive || args.emit_cli {
        if !assert_specs.is_empty() {
            println!();
            println!("Suggested prove command:");
            let assertions_path = if args.emit_assertions.is_some() {
                args.emit_assertions.as_ref()
            } else {
                None
            };
            println!(
                "  {}",
                build_prove_command(
                    &args,
                    &rpc_url,
                    block_number,
                    &assert_specs,
                    assertions_path
                )
            );
        } else {
            println!();
            println!("No transfer assertions selected. Use --auto-assert or review the state-diff suggestions above.");
        }
    }

    Ok(())
}

fn build_state_diff_suggestions(
    state_diff: &bridge_types::types::StateDiff,
    limit: Option<usize>,
) -> Vec<String> {
    use bridge_types::types::Delta;
    let mut out = Vec::new();
    for (addr, diff) in &state_diff.0 {
        if let Delta::Changed { from, to } = &diff.balance {
            out.push(format!(
                "--assert balance:{}:{}:{}",
                format!("{:?}", addr),
                format!("{:#x}", from),
                format!("{:#x}", to)
            ));
        }
        for (slot, delta) in &diff.storage {
            if let Delta::Changed { from, to } = delta {
                out.push(format!(
                    "--assert slot:{}:{:#x}:{:#x}:{:#x}",
                    format!("{:?}", addr),
                    slot,
                    from,
                    to
                ));
            }
        }
    }

    if let Some(max) = limit {
        out.truncate(max);
    }
    out
}

#[derive(Debug, Clone, serde::Serialize)]
struct TransferCandidate {
    token: Address,
    from: Address,
    to: Address,
    amount: U256,
}

fn extract_transfer_candidates(result: &ExecutionResult) -> Vec<TransferCandidate> {
    let mut out = Vec::new();
    let logs: &[Log] = match result {
        ExecutionResult::Success { logs, .. } => logs,
        _ => return out,
    };

    let transfer_sig = alloy_primitives::keccak256("Transfer(address,address,uint256)");
    for log in logs {
        let topics = log.data.topics();
        if topics.len() < 3 {
            continue;
        }
        if topics[0] != transfer_sig {
            continue;
        }
        let from = Address::from_word(topics[1]);
        let to = Address::from_word(topics[2]);
        let amount = bytes_to_u256(&log.data.data);
        if amount.is_zero() {
            continue;
        }
        out.push(TransferCandidate {
            token: log.address,
            from,
            to,
            amount,
        });
    }

    out
}

fn bytes_to_u256(data: &Bytes) -> U256 {
    let bytes = data.as_ref();
    if bytes.is_empty() {
        return U256::ZERO;
    }
    let mut buf = [0u8; 32];
    if bytes.len() >= 32 {
        buf.copy_from_slice(&bytes[bytes.len() - 32..]);
    } else {
        buf[32 - bytes.len()..].copy_from_slice(bytes);
    }
    U256::from_be_slice(&buf)
}

fn format_amount(amount: U256) -> String {
    format!("{} (0x{:x})", amount, amount)
}

fn format_amount_hex(amount: U256) -> String {
    format!("0x{:x}", amount)
}

fn default_transfer_selection(
    candidates: &[TransferCandidate],
    preferred_to: Address,
) -> Vec<usize> {
    let mut best_idx = None;
    let mut best_amount = U256::ZERO;
    for (idx, cand) in candidates.iter().enumerate() {
        if cand.to != preferred_to {
            continue;
        }
        if cand.amount > best_amount {
            best_amount = cand.amount;
            best_idx = Some(idx);
        }
    }

    if best_idx.is_none() {
        for (idx, cand) in candidates.iter().enumerate() {
            if cand.amount > best_amount {
                best_amount = cand.amount;
                best_idx = Some(idx);
            }
        }
    }

    best_idx.map(|i| vec![i]).unwrap_or_default()
}

fn prompt_transfer_selection(
    candidates: &[TransferCandidate],
    default_indices: &[usize],
) -> Result<Vec<usize>> {
    if candidates.is_empty() {
        return Ok(Vec::new());
    }

    let default_label = if default_indices.is_empty() {
        "skip".to_string()
    } else {
        default_indices
            .iter()
            .map(|i| (i + 1).to_string())
            .collect::<Vec<_>>()
            .join(",")
    };

    loop {
        let input = prompt_line(&format!(
            "Select transfers to assert [default: {}]: ",
            default_label
        ))?;
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Ok(default_indices.to_vec());
        }
        let lower = trimmed.to_lowercase();
        if lower == "skip" || lower == "none" {
            return Ok(Vec::new());
        }
        if lower == "all" {
            return Ok((0..candidates.len()).collect());
        }

        let mut out = Vec::new();
        let mut ok = true;
        for part in trimmed.split(',') {
            let token = part.trim();
            if token.is_empty() {
                continue;
            }
            match token.parse::<usize>() {
                Ok(n) if n >= 1 && n <= candidates.len() => out.push(n - 1),
                _ => {
                    ok = false;
                    break;
                }
            }
        }
        if ok && !out.is_empty() {
            out.sort();
            out.dedup();
            return Ok(out);
        }
        println!("Invalid selection. Use comma-separated indices, 'all', or 'skip'.");
    }
}

fn prompt_yes_no(question: &str, default_yes: bool) -> Result<bool> {
    let suffix = if default_yes { "[Y/n]" } else { "[y/N]" };
    loop {
        let input = prompt_line(&format!("{question} {suffix} "))?;
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Ok(default_yes);
        }
        match trimmed.to_lowercase().as_str() {
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => println!("Please enter 'y' or 'n'."),
        }
    }
}

fn prompt_line(prompt: &str) -> Result<String> {
    print!("{prompt}");
    io::stdout().flush().context("flush stdout")?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf).context("read input")?;
    Ok(buf)
}

async fn infer_slot_map(
    client: &RpcClient,
    block_number: u64,
    transfers: &[TransferCandidate],
    interactive: bool,
) -> Result<HashMap<Address, U256>> {
    let mut map = HashMap::new();
    for transfer in transfers {
        if map.contains_key(&transfer.token) {
            continue;
        }
        if let Some(slot) = assertions::infer_balance_slot_for_token(
            client,
            transfer.token,
            &[transfer.from, transfer.to],
            block_number,
        )
        .await?
        {
            map.insert(transfer.token, slot);
            continue;
        }
        if interactive {
            println!(
                "Could not infer balance slot for token {}.",
                format!("{:?}", transfer.token)
            );
            if let Some(slot) = prompt_slot_index(&transfer.token)? {
                map.insert(transfer.token, slot);
            }
        }
    }
    Ok(map)
}

fn prompt_slot_index(token: &Address) -> Result<Option<U256>> {
    let input = prompt_line(&format!(
        "Enter balance slot index for token {} (blank to skip): ",
        format!("{:?}", token)
    ))?;
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let slot = U256::from_str(trimmed).context("invalid slot index")?;
    Ok(Some(slot))
}

fn build_prove_command(
    args: &ExplainArgs,
    rpc_url: &str,
    block_number: u64,
    assert_specs: &[String],
    assertions_path: Option<&PathBuf>,
) -> String {
    let mut parts: Vec<String> = Vec::new();
    parts.push("zkpoex".to_string());
    parts.push("prove".to_string());
    parts.push("--poc".to_string());
    parts.push(shell_escape(&args.poc.to_string_lossy()));
    if !args.rpc_url.is_empty() {
        parts.push("--rpc-url".to_string());
        parts.push(shell_escape(&args.rpc_url));
    } else if !rpc_url.is_empty() {
        parts.push("--rpc-url".to_string());
        parts.push(shell_escape(rpc_url));
    }
    parts.push("--block-number".to_string());
    parts.push(block_number.to_string());
    for deal in &args.deals {
        parts.push("--deal".to_string());
        parts.push(shell_escape(deal));
    }
    if let Some(caller) = &args.caller {
        parts.push("--caller".to_string());
        parts.push(shell_escape(caller));
    }
    if let Some(contract) = &args.contract_address {
        parts.push("--contract-address".to_string());
        parts.push(shell_escape(contract));
    }
    if let Some(path) = assertions_path {
        parts.push("--assertions".to_string());
        parts.push(shell_escape(&path.to_string_lossy()));
    } else {
        for spec in assert_specs {
            parts.push("--assert".to_string());
            parts.push(shell_escape(spec));
        }
    }
    parts.join(" ")
}

fn write_assertions_file(path: &PathBuf, assert_specs: &[String]) -> Result<()> {
    let mut content = String::new();
    for spec in assert_specs {
        content.push_str(spec);
        content.push('\n');
    }
    std::fs::write(path, content)
        .with_context(|| format!("failed to write assertions to {}", path.display()))?;
    Ok(())
}

fn shell_escape(value: &str) -> String {
    if value.contains(' ') || value.contains('"') {
        format!("{:?}", value)
    } else {
        value.to_string()
    }
}

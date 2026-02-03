// SPDX-License-Identifier: MIT
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args;
use tracing::info;

use alloy_primitives::Address;
use bridge_types::constants::{DEFAULT_CALLER, DEFAULT_CONTRACT_ADDRESS, DEFAULT_GAS_LIMIT};
use bridge_types::conversions::addr_to_fixed;
use bridge_types::types::{DealRecord, ExploitOptions};
use host_utils::compiler::compile_poc;
use host_utils::preflight::build_exploit_input;
use host_utils::rpc::RpcClient;
use host_utils::serialize::serialize_and_compress;
use std::str::FromStr;

use crate::assertions;
use crate::config;
use crate::progress;

#[derive(Args, Debug)]
pub struct ProveArgs {
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

    /// Verifier-provided nonce (32-byte hex) to bind the proof to a fresh challenge.
    #[arg(long)]
    pub nonce: Option<String>,

    /// Public assertions. Format: "TYPE:...".
    /// Types: no-deals, balance, slot, erc20, transfer, not-owner, changed, slot-changed.
    #[arg(long = "assert")]
    pub assertions: Vec<String>,

    /// Load assertions from a file (one per line).
    #[arg(long = "assertions")]
    pub assertions_file: Option<PathBuf>,

    /// Gas limit for the exploit transaction.
    #[arg(long, default_value_t = DEFAULT_GAS_LIMIT)]
    pub gas_limit: u64,

    /// Caller address for the exploit transaction. Defaults to 0x...add1.
    #[arg(long)]
    pub caller: Option<String>,

    /// Contract address where the PoC is injected. Defaults to 0x...1337.
    #[arg(long = "contract-address")]
    pub contract_address: Option<String>,

    /// Output file for the proof.
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Enable slow commitments (call-trace hash + full state diff).
    #[arg(long)]
    pub slow: bool,

    /// Run preflight only (no proving).
    #[arg(long)]
    pub dry_run: bool,

    /// Skip the RPC cache.
    #[arg(long)]
    pub no_cache: bool,

    /// Enable EVM debug tracing (prints EIP-3155 trace on failure).
    #[arg(long)]
    pub debug: bool,
}

pub async fn run(args: ProveArgs, json_output: bool) -> Result<()> {
    // Resolve RPC URL from flag / env / config
    let rpc_url = config::resolve_rpc_url(&args.rpc_url)?;

    // Parse deals
    let deals: Vec<DealRecord> = args
        .deals
        .iter()
        .map(|s| s.parse::<DealRecord>())
        .collect::<Result<Vec<_>, _>>()
        .context("failed to parse deal arguments")?;

    info!(deals = deals.len(), "Parsed deals");

    // Parse nonce
    let nonce = if let Some(nonce_str) = &args.nonce {
        parse_fixed_32(nonce_str).context("failed to parse --nonce")?
    } else {
        [0u8; 32]
    };

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
    info!(poc_code_hash = %hex::encode(compiled.code_hash), "PoC code hash");

    // Build RPC client
    let client = RpcClient::new(&rpc_url);

    // Determine block number
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

    let mut assertion_specs = Vec::new();
    if let Some(path) = &args.assertions_file {
        assertion_specs.extend(assertions::load_assertions_file(path)?);
    }
    assertion_specs.extend(args.assertions.clone());

    let parsed = assertions::parse_assertions(&assertion_specs, Some(&client), Some(block_number))
        .await
        .context("failed to parse assertions")?;

    if parsed.has_no_deals && !deals.is_empty() {
        anyhow::bail!("no-deals assertion provided but deals were specified");
    }
    assertions::warn_verify_only(&parsed.verify_only);
    let assertions = parsed.guest;

    // Resolve caller address
    let caller_addr = match &args.caller {
        Some(raw) => Address::from_str(raw).context("failed to parse --caller")?,
        None => Address::from(DEFAULT_CALLER),
    };

    let contract_addr = match &args.contract_address {
        Some(raw) => Address::from_str(raw).context("failed to parse --contract-address")?,
        None => Address::from(DEFAULT_CONTRACT_ADDRESS),
    };

    // Preflight: dry-run + fetch state
    let sp = progress::spinner("Fetching state...");
    let block_header = client
        .get_block_by_number(block_number)
        .await
        .context("failed to fetch block header for gas limit")?;

    let mut gas_limit = args.gas_limit;
    if gas_limit > block_header.gas_limit {
        tracing::warn!(
            requested = gas_limit,
            block_gas_limit = block_header.gas_limit,
            "Requested gas limit exceeds block gas limit; clamping"
        );
        gas_limit = block_header.gas_limit;
    }

    let options = ExploitOptions {
        enable_call_trace: args.slow,
        enable_state_diff: args.slow,
    };

    let (input, block_env) = build_exploit_input(
        &client,
        block_number,
        compiled.bytecode,
        deals,
        assertions,
        nonce,
        addr_to_fixed(caller_addr),
        addr_to_fixed(contract_addr),
        gas_limit,
        options,
        args.debug,
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

    if args.dry_run {
        let sp = progress::spinner("Serializing...");
        let compressed = serialize_and_compress(&input)?;
        progress::finish(
            &sp,
            &format!("Serialized ({} bytes compressed)", compressed.len()),
        );
        info!("Dry run complete. Skipping proving.");
        return Ok(());
    }

    // Serialize and compress input
    let sp = progress::spinner("Serializing...");
    let compressed = serialize_and_compress(&input).context("serialize_and_compress")?;
    progress::finish(
        &sp,
        &format!("Serialized ({} bytes compressed)", compressed.len()),
    );

    // Prove
    let sp = progress::spinner("Proving...");
    let env = risc0_zkvm::ExecutorEnv::builder()
        .write(&compressed)
        .context("failed to write input to executor env")?
        .build()
        .context("failed to build executor env")?;

    let prover = risc0_zkvm::default_prover();
    let start_time = std::time::Instant::now();
    let prove_info = prover
        .prove(env, guests::EXPLOIT_ELF)
        .context("proof generation failed")?;
    let duration = start_time.elapsed();

    let receipt = prove_info.receipt;
    progress::finish(
        &sp,
        &format!("Proof generated in {:.2}s", duration.as_secs_f64()),
    );

    // Decode journal
    let journal: bridge_types::types::ExploitJournal = receipt
        .journal
        .decode()
        .context("failed to decode journal")?;

    info!(
        success = journal.success,
        gas_used = journal.gas_used,
        exit_reason = %journal.exit_reason,
        deals_hash = hex::encode(journal.deals_hash),
        proving_time_secs = duration.as_secs_f64(),
        "Journal"
    );

    // Save proof
    let sp = progress::spinner("Saving proof...");
    let output_path = args.output.unwrap_or_else(|| PathBuf::from("proof.bin"));
    let proof_data = crate::proof::Proof {
        version: 1,
        chain_id: block_env.chain_id,
        block_number,
        poc_code_hash: compiled.code_hash,
        deals: input.deals,
        receipt,
    };

    let encoded = bincode::serialize(&proof_data).context("failed to serialize proof")?;
    std::fs::write(&output_path, &encoded)
        .with_context(|| format!("failed to write proof to {}", output_path.display()))?;
    progress::finish(
        &sp,
        &format!(
            "Proof saved to {} ({} bytes)",
            output_path.display(),
            encoded.len()
        ),
    );

    if json_output {
        let result = serde_json::json!({
            "success": journal.success,
            "gas_used": journal.gas_used,
            "exit_reason": journal.exit_reason,
            "deals_hash": hex::encode(journal.deals_hash),
            "poc_code_hash": hex::encode(journal.poc_code_hash),
            "caller": format!("0x{}", hex::encode(journal.caller)),
            "contract_address": format!("0x{}", hex::encode(journal.contract_address)),
            "proof_path": output_path.display().to_string(),
            "proof_size": encoded.len(),
            "chain_id": block_env.chain_id,
            "block_number": block_number,
            "proving_time_secs": duration.as_secs_f64(),
        });
        println!("{}", serde_json::to_string_pretty(&result)?);
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

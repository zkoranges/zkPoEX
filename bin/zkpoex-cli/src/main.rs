// SPDX-License-Identifier: MIT
mod assertions;
mod commands;
mod config;
mod progress;
mod proof;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "zkpoex", version, about = "Zero-knowledge proof of exploit")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Output results as JSON.
    #[arg(long, global = true)]
    json: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate a ZK proof of an EVM exploit.
    Prove(commands::prove::ProveArgs),

    /// Verify an existing proof.
    Verify(commands::verify::VerifyArgs),

    /// Explain and suggest assertions for an exploit.
    Explain(commands::explain::ExplainArgs),

    /// Clean the RPC cache.
    Clean(commands::clean::CleanArgs),
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    if cfg!(feature = "metal") {
        tracing::info!("Running with Metal acceleration enabled 🚀");
    } else if cfg!(feature = "cuda") {
        tracing::info!("Running with CUDA acceleration enabled 🚀");
    } else {
        tracing::info!(
            "Running in CPU-only mode (slow). Build with --features metal/cuda for speed."
        );
    }

    tracing::warn!(
        "zkPoEX is experimental security research software. Authorized testing only. \
         Not affiliated with any protocol. See DISCLAIMER."
    );

    // Register Ctrl+C handler to clean up partial cache files
    ctrlc::set_handler(move || {
        tracing::warn!("Interrupted. Cleaning up...");
        // Best-effort cleanup of partial cache
        if let Some(home) = dirs_next::home_dir() {
            let lock_file = home.join(".zkpoex").join("cache").join(".lock");
            let _ = std::fs::remove_file(lock_file);
        }
        std::process::exit(130);
    })
    .ok();

    let cli = Cli::parse();

    match cli.command {
        Commands::Prove(args) => commands::prove::run(args, cli.json).await,
        Commands::Verify(args) => commands::verify::run(args, cli.json).await,
        Commands::Explain(args) => commands::explain::run(args, cli.json).await,
        Commands::Clean(args) => commands::clean::run(args).await,
    }
}

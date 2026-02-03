// SPDX-License-Identifier: MIT
use anyhow::{Context, Result};
use clap::Args;
use tracing::info;

#[derive(Args, Debug)]
pub struct CleanArgs {
    /// Only clean cache for a specific chain ID.
    #[arg(long)]
    pub chain_id: Option<u64>,
}

pub async fn run(args: CleanArgs) -> Result<()> {
    let cache_dir = dirs_next::home_dir()
        .context("could not determine home directory")?
        .join(".zkpoex")
        .join("cache");

    if !cache_dir.exists() {
        info!("No cache directory found at {}", cache_dir.display());
        return Ok(());
    }

    if let Some(chain_id) = args.chain_id {
        let chain_dir = cache_dir.join(chain_id.to_string());
        if chain_dir.exists() {
            std::fs::remove_dir_all(&chain_dir)
                .with_context(|| format!("failed to remove {}", chain_dir.display()))?;
            info!("Removed cache for chain {chain_id}");
        } else {
            info!("No cache found for chain {chain_id}");
        }
    } else {
        std::fs::remove_dir_all(&cache_dir)
            .with_context(|| format!("failed to remove {}", cache_dir.display()))?;
        info!("Removed all cache at {}", cache_dir.display());
    }

    Ok(())
}

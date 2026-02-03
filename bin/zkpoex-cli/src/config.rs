// SPDX-License-Identifier: MIT
use anyhow::Result;
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Default, Deserialize)]
pub struct Config {
    pub rpc_url: Option<String>,
}

fn config_path() -> Option<PathBuf> {
    dirs_next::home_dir().map(|h| h.join(".zkpoex").join("config.toml"))
}

pub fn load_config() -> Config {
    let Some(path) = config_path() else {
        return Config::default();
    };
    if !path.exists() {
        return Config::default();
    }
    match std::fs::read_to_string(&path) {
        Ok(contents) => toml::from_str(&contents).unwrap_or_default(),
        Err(_) => Config::default(),
    }
}

/// Resolve the RPC URL from CLI flag, environment variable, or config file.
///
/// This is the "optional" variant used by commands like `verify` where RPC
/// verification is recommended but not required.
pub fn resolve_rpc_url_optional(cli_flag: &str) -> Option<String> {
    if !cli_flag.is_empty() {
        return Some(cli_flag.to_string());
    }

    // Prefer the tool-specific env var, but also support the ubiquitous `RPC_URL`.
    if let Ok(env_val) = std::env::var("ZKPOEX_RPC_URL") {
        if !env_val.is_empty() {
            return Some(env_val);
        }
    }
    if let Ok(env_val) = std::env::var("RPC_URL") {
        if !env_val.is_empty() {
            return Some(env_val);
        }
    }

    let config = load_config();
    if let Some(url) = config.rpc_url {
        if !url.is_empty() {
            return Some(url);
        }
    }

    None
}

/// Resolve the RPC URL from CLI flag, environment variable, or config file.
pub fn resolve_rpc_url(cli_flag: &str) -> Result<String> {
    if let Some(url) = resolve_rpc_url_optional(cli_flag) {
        return Ok(url);
    }
    anyhow::bail!(
        "No RPC URL provided. Use --rpc-url, ZKPOEX_RPC_URL/RPC_URL env var, or ~/.zkpoex/config.toml"
    )
}

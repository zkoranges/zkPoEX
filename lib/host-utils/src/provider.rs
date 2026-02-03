// SPDX-License-Identifier: MIT
use anyhow::{bail, Context, Result};
use url::Url;

/// Validate an RPC URL. Only http(s) and ws(s) schemes are allowed.
/// Rejects file://, ftp://, and other potentially dangerous schemes.
pub fn validate_rpc_url(raw: &str) -> Result<Url> {
    let url = Url::parse(raw).context("failed to parse RPC URL")?;

    match url.scheme() {
        "http" | "https" | "ws" | "wss" => Ok(url),
        scheme => bail!(
            "unsupported RPC URL scheme '{}'. Only http, https, ws, wss are allowed",
            scheme
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_accepts_https() {
        assert!(validate_rpc_url("https://eth.llamarpc.com").is_ok());
    }

    #[test]
    fn test_accepts_http() {
        assert!(validate_rpc_url("http://localhost:8545").is_ok());
    }

    #[test]
    fn test_accepts_wss() {
        assert!(validate_rpc_url("wss://eth-mainnet.g.alchemy.com/v2/key").is_ok());
    }

    #[test]
    fn test_accepts_ws() {
        assert!(validate_rpc_url("ws://localhost:8546").is_ok());
    }

    #[test]
    fn test_rejects_file_scheme() {
        assert!(validate_rpc_url("file:///etc/passwd").is_err());
    }

    #[test]
    fn test_rejects_ftp_scheme() {
        assert!(validate_rpc_url("ftp://example.com").is_err());
    }

    #[test]
    fn test_rejects_invalid_url() {
        assert!(validate_rpc_url("not a url").is_err());
    }
}

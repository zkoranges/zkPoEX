// SPDX-License-Identifier: MIT
use std::path::Path;
use std::process::Command;

use alloy_primitives::keccak256;
use anyhow::{bail, Context, Result};

/// Compiled PoC contract output.
#[derive(Debug)]
pub struct CompiledPoc {
    pub bytecode: Vec<u8>,
    pub code_hash: [u8; 32],
}

/// Compile a Solidity PoC file and extract the `Exploit` contract bytecode.
///
/// Uses `solc` directly via command line. Expects `solc` to be available
/// in PATH (e.g., installed via `solc-select` or `svm`).
///
/// The pragma version in the source file determines which solc version
/// should be active.
pub fn compile_poc(path: &Path) -> Result<CompiledPoc> {
    // Canonicalize path to prevent path traversal attacks
    let canonical = path
        .canonicalize()
        .with_context(|| format!("failed to canonicalize PoC path: {}", path.display()))?;

    if !canonical.exists() {
        bail!("PoC file does not exist: {}", canonical.display());
    }

    if canonical.extension().and_then(|e| e.to_str()) != Some("sol") {
        bail!("PoC file must be a .sol file: {}", canonical.display());
    }

    // Run solc with combined-json output to get deployed (runtime) bytecode.
    // We use bin-runtime (not bin) because the bytecode is placed directly as
    // the contract's code in the EVM state — there is no CREATE step, so
    // constructor/init code must not be included.
    // Target paris EVM to avoid PUSH0 (Shanghai+), ensuring PoC bytecode
    // works at any block height from Merge onwards.
    let output = Command::new("solc")
        .arg("--evm-version")
        .arg("paris")
        .arg("--combined-json")
        .arg("bin-runtime")
        .arg(&canonical)
        .output()
        .context("failed to execute solc. Is solc installed? Try: pip install solc-select && solc-select install 0.8.20 && solc-select use 0.8.20")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("solc compilation failed:\n{}", stderr);
    }

    // Parse the combined JSON output
    let stdout = String::from_utf8(output.stdout).context("solc output is not valid UTF-8")?;

    let json: serde_json::Value =
        serde_json::from_str(&stdout).context("failed to parse solc JSON output")?;

    let contracts = json
        .get("contracts")
        .context("solc output missing 'contracts' field")?
        .as_object()
        .context("solc 'contracts' is not an object")?;

    // Find the Exploit contract. solc keys are "filename:ContractName"
    let exploit_key = contracts
        .keys()
        .find(|k| k.ends_with(":Exploit"))
        .with_context(|| {
            let available: Vec<&String> = contracts.keys().collect();
            format!(
                "Contract 'Exploit' not found in solc output. Available contracts: {:?}",
                available
            )
        })?
        .clone();

    let contract = &contracts[&exploit_key];
    let bin_hex = contract
        .get("bin-runtime")
        .and_then(|v| v.as_str())
        .context("solc output missing 'bin-runtime' for Exploit contract")?;

    if bin_hex.is_empty() {
        bail!("Exploit contract has empty bytecode (is it abstract or an interface?)");
    }

    let bytecode = hex::decode(bin_hex).context("failed to decode hex bytecode from solc")?;

    let code_hash: [u8; 32] = keccak256(&bytecode).0;

    Ok(CompiledPoc {
        bytecode,
        code_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixtures_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .canonicalize()
            .unwrap()
    }

    #[test]
    fn test_compile_simple_exploit() {
        let path = fixtures_dir().join("SimpleTx.sol");
        let result = compile_poc(&path).unwrap();
        assert!(!result.bytecode.is_empty(), "bytecode should not be empty");
        assert_ne!(result.code_hash, [0u8; 32], "code_hash should not be zero");
    }

    #[test]
    fn test_compile_multi_contract_file() {
        let path = fixtures_dir().join("MissingOnlyOwner.sol");
        let result = compile_poc(&path).unwrap();
        assert!(!result.bytecode.is_empty());
    }

    #[test]
    fn test_compile_deterministic_hash() {
        let path = fixtures_dir().join("SimpleTx.sol");
        let r1 = compile_poc(&path).unwrap();
        let r2 = compile_poc(&path).unwrap();
        assert_eq!(
            r1.code_hash, r2.code_hash,
            "same file should produce same hash"
        );
        assert_eq!(
            r1.bytecode, r2.bytecode,
            "same file should produce same bytecode"
        );
    }

    #[test]
    fn test_compile_nonexistent_file() {
        let result = compile_poc(Path::new("/nonexistent/file.sol"));
        assert!(result.is_err());
    }

    #[test]
    fn test_compile_non_sol_file() {
        // Use Cargo.toml as a non-sol file
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        let result = compile_poc(&path);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains(".sol"),
            "error should mention .sol requirement"
        );
    }
}

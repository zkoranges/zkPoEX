// SPDX-License-Identifier: MIT
use std::collections::BTreeMap;

use alloy_primitives::{Address, B256, U256};
use rkyv::{Archive, Deserialize, Serialize};
use sha2::{Digest, Sha256};

// --- State Diff Types (moved from bridge-logic) ---

/// Represents a change in a single value.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Delta<T> {
    Unchanged,
    Added(T),
    Removed(T),
    Changed { from: T, to: T },
}

/// Diff of a single account.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AccountDiff {
    pub balance: Delta<U256>,
    pub nonce: Delta<u64>,
    pub code_hash: Delta<B256>,
    pub storage: BTreeMap<U256, Delta<U256>>,
}

/// State diff across all accounts.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StateDiff(pub BTreeMap<Address, AccountDiff>);

// --- Rkyv Types ---

/// Account state stored as raw bytes for rkyv compatibility.
#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[archive(check_bytes)]
pub struct RkyvAccount {
    pub nonce: u64,
    pub balance: [u8; 32],
    pub code_hash: [u8; 32],
    pub code: Option<Vec<u8>>,
    pub storage: BTreeMap<[u8; 32], [u8; 32]>,
}

/// In-memory database of account states and block hashes.
/// All keys are raw byte arrays for deterministic serialization.
#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[archive(check_bytes)]
pub struct RkyvMemDB {
    pub accounts: BTreeMap<[u8; 20], RkyvAccount>,
    pub block_hashes: BTreeMap<u64, [u8; 32]>,
}

/// Block environment configuration for EVM execution.
#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[archive(check_bytes)]
pub struct RkyvBlockEnv {
    pub number: u64,
    pub timestamp: u64,
    pub coinbase: [u8; 20],
    pub difficulty: [u8; 32],
    pub gas_limit: u64,
    pub basefee: [u8; 32],
    pub prevrandao: Option<[u8; 32]>,
    pub excess_blob_gas: Option<u64>,
    pub chain_id: u64,
    pub state_root: [u8; 32],
}

/// A single storage proof entry within an EIP-1186 account proof.
#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[archive(check_bytes)]
pub struct StorageProofEntry {
    pub key: [u8; 32],
    pub value: [u8; 32],
    pub proof: Vec<Vec<u8>>,
}

/// EIP-1186 account proof for a single address.
#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[archive(check_bytes)]
pub struct EIP1186AccountProof {
    pub address: [u8; 20],
    pub nonce: u64,
    pub balance: [u8; 32],
    pub storage_hash: [u8; 32],
    pub code_hash: [u8; 32],
    pub account_proof: Vec<Vec<u8>>,
    pub storage_proofs: Vec<StorageProofEntry>,
}

/// A balance override ("deal") to be applied inside the guest circuit.
#[derive(
    Archive,
    Serialize,
    Deserialize,
    Debug,
    Clone,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
)]
#[archive(check_bytes)]
pub struct DealRecord {
    pub address: [u8; 20],
    pub balance: [u8; 32],
}

/// Public assertions that must hold for the proof to be considered valid.
#[derive(
    Archive,
    Serialize,
    Deserialize,
    Debug,
    Clone,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
)]
#[archive(check_bytes)]
pub enum Assertion {
    /// Assert that no balance overrides (deals) were applied.
    NoDeals,
    /// Assert that an account's balance changed from `from` to `to`.
    Balance {
        address: [u8; 20],
        from: [u8; 32],
        to: [u8; 32],
    },
    /// Assert that a storage slot changed from `from` to `to`.
    Storage {
        address: [u8; 20],
        slot: [u8; 32],
        from: [u8; 32],
        to: [u8; 32],
    },
    /// Assert that the caller is NOT the current owner at a given slot.
    /// Ownership is checked against the pre-state slot value.
    NotOwner { address: [u8; 20], slot: [u8; 32] },
}

/// Complete input payload sent to the ZK guest.
#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[archive(check_bytes)]
pub struct ExploitInput {
    pub original_db: RkyvMemDB,
    pub deals: Vec<DealRecord>,
    pub assertions: Vec<Assertion>,
    pub nonce: [u8; 32],
    pub caller: [u8; 20],
    pub contract_address: [u8; 20],
    pub env: RkyvBlockEnv,
    pub poc_bytecode: Vec<u8>,
    pub gas_limit: u64,
    pub proofs: Vec<EIP1186AccountProof>,
    pub options: ExploitOptions,
}

/// Journal output committed by the guest. Uses serde for risc0 journal.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ExploitJournal {
    pub success: bool,
    pub gas_used: u64,
    pub deals_hash: [u8; 32],
    pub assertions_hash: [u8; 32],
    pub assertions_ok: bool,
    pub nonce: [u8; 32],
    pub caller: [u8; 20],
    pub contract_address: [u8; 20],
    pub call_trace_hash: [u8; 32],
    pub exit_reason: String,
    pub state_root: [u8; 32],
    pub block_number: u64,
    pub chain_id: u64,
    pub timestamp: u64,
    pub basefee: [u8; 32],
    pub block_gas_limit: u64,
    pub poc_code_hash: [u8; 32],
    pub state_diff: StateDiff,
    pub call_trace_enabled: bool,
    pub state_diff_enabled: bool,
}

/// Optional commitments that affect proving cost.
#[derive(Archive, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[archive(check_bytes)]
pub struct ExploitOptions {
    pub enable_call_trace: bool,
    pub enable_state_diff: bool,
}

/// Compute a deterministic hash of a set of deals.
/// Used to verify that the deals applied inside the guest match
/// the deals the verifier expects.
pub fn compute_deals_hash(deals: &[DealRecord]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for deal in deals {
        hasher.update(deal.address);
        hasher.update(deal.balance);
    }
    hasher.finalize().into()
}

/// Compute a deterministic hash of a set of assertions.
/// Used to verify that the assertions enforced inside the guest
/// match what the verifier expects.
pub fn compute_assertions_hash(assertions: &[Assertion]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for assertion in assertions {
        match assertion {
            Assertion::NoDeals => {
                hasher.update([0u8]);
            }
            Assertion::Balance { address, from, to } => {
                hasher.update([1u8]);
                hasher.update(address);
                hasher.update(from);
                hasher.update(to);
            }
            Assertion::Storage {
                address,
                slot,
                from,
                to,
            } => {
                hasher.update([2u8]);
                hasher.update(address);
                hasher.update(slot);
                hasher.update(from);
                hasher.update(to);
            }
            Assertion::NotOwner { address, slot } => {
                hasher.update([3u8]);
                hasher.update(address);
                hasher.update(slot);
            }
        }
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_account() -> RkyvAccount {
        let mut storage = BTreeMap::new();
        storage.insert([1u8; 32], [2u8; 32]);
        RkyvAccount {
            nonce: 42,
            balance: [0xff; 32],
            code_hash: [0xab; 32],
            code: Some(vec![0x60, 0x00, 0x60, 0x00]),
            storage,
        }
    }

    fn make_test_memdb() -> RkyvMemDB {
        let mut accounts = BTreeMap::new();
        accounts.insert([0xaa; 20], make_test_account());
        let mut block_hashes = BTreeMap::new();
        block_hashes.insert(100, [0xcc; 32]);
        RkyvMemDB {
            accounts,
            block_hashes,
        }
    }

    fn make_test_block_env() -> RkyvBlockEnv {
        RkyvBlockEnv {
            number: 17007841,
            timestamp: 1681000000,
            coinbase: [0x01; 20],
            difficulty: [0; 32],
            gas_limit: 30_000_000,
            basefee: [0; 32],
            prevrandao: Some([0xde; 32]),
            excess_blob_gas: None,
            chain_id: 1,
            state_root: [0xaa; 32],
        }
    }

    /// Round-trip an rkyv-serializable value through serialize -> validate -> deserialize.
    macro_rules! rkyv_round_trip {
        ($ty:ty, $value:expr) => {{
            let bytes = rkyv::to_bytes::<_, 256>($value).expect("serialize");
            let archived = rkyv::check_archived_root::<$ty>(&bytes).expect("validate");
            let deserialized: $ty = archived
                .deserialize(&mut rkyv::Infallible)
                .expect("deserialize");
            deserialized
        }};
    }

    #[test]
    fn test_rkyv_account_round_trip() {
        let original = make_test_account();
        let restored = rkyv_round_trip!(RkyvAccount, &original);
        assert_eq!(original.nonce, restored.nonce);
        assert_eq!(original.balance, restored.balance);
        assert_eq!(original.code_hash, restored.code_hash);
        assert_eq!(original.code, restored.code);
        assert_eq!(original.storage, restored.storage);
    }

    #[test]
    fn test_rkyv_memdb_round_trip() {
        let original = make_test_memdb();
        let restored = rkyv_round_trip!(RkyvMemDB, &original);
        assert_eq!(original.accounts.len(), restored.accounts.len());
        assert_eq!(original.block_hashes, restored.block_hashes);
    }

    #[test]
    fn test_rkyv_exploit_input_round_trip() {
        let original = ExploitInput {
            original_db: make_test_memdb(),
            deals: vec![DealRecord {
                address: [0xbb; 20],
                balance: [0x01; 32],
            }],
            assertions: vec![Assertion::NoDeals],
            nonce: [0x11; 32],
            caller: [0xcc; 20],
            contract_address: [0xdd; 20],
            env: make_test_block_env(),
            poc_bytecode: vec![0x60, 0x00],
            gas_limit: 30_000_000,
            proofs: vec![],
            options: ExploitOptions::default(),
        };
        let restored = rkyv_round_trip!(ExploitInput, &original);
        assert_eq!(original.deals.len(), restored.deals.len());
        assert_eq!(original.caller, restored.caller);
        assert_eq!(original.contract_address, restored.contract_address);
        assert_eq!(original.gas_limit, restored.gas_limit);
        assert_eq!(original.poc_bytecode, restored.poc_bytecode);
    }

    #[test]
    fn test_deals_hash_determinism() {
        let deals = vec![
            DealRecord {
                address: [0xaa; 20],
                balance: [0x01; 32],
            },
            DealRecord {
                address: [0xbb; 20],
                balance: [0x02; 32],
            },
        ];
        let h1 = compute_deals_hash(&deals);
        let h2 = compute_deals_hash(&deals);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_deals_hash_different_input() {
        let deals_a = vec![DealRecord {
            address: [0xaa; 20],
            balance: [0x01; 32],
        }];
        let deals_b = vec![DealRecord {
            address: [0xbb; 20],
            balance: [0x01; 32],
        }];
        assert_ne!(compute_deals_hash(&deals_a), compute_deals_hash(&deals_b));
    }

    #[test]
    fn test_deals_hash_empty() {
        let h = compute_deals_hash(&[]);
        // SHA256 of empty input is a known constant
        assert_eq!(
            h,
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55,
            ]
        );
    }
}

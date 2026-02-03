// SPDX-License-Identifier: MIT
use std::collections::BTreeMap;

use revm::primitives::EvmState;

use bridge_types::conversions::{fixed_to_addr, fixed_to_u256};
use bridge_types::types::{AccountDiff, Delta, RkyvMemDB, StateDiff};

/// Compute the state diff between the post-execution state and the original DB.
pub fn compute_state_diff(state: &EvmState, original_db: &RkyvMemDB) -> StateDiff {
    let mut diffs = BTreeMap::new();

    for (address, account) in state {
        let original = original_db
            .accounts
            .iter()
            .find(|(addr_bytes, _)| fixed_to_addr(**addr_bytes) == *address)
            .map(|(_, acc)| acc);

        let mut account_diff = AccountDiff {
            balance: Delta::Unchanged,
            nonce: Delta::Unchanged,
            code_hash: Delta::Unchanged,
            storage: BTreeMap::new(),
        };
        let mut has_changes = false;

        match original {
            Some(orig) => {
                let orig_balance = fixed_to_u256(orig.balance);
                if account.info.balance != orig_balance {
                    account_diff.balance = Delta::Changed {
                        from: orig_balance,
                        to: account.info.balance,
                    };
                    has_changes = true;
                }

                if account.info.nonce != orig.nonce {
                    account_diff.nonce = Delta::Changed {
                        from: orig.nonce,
                        to: account.info.nonce,
                    };
                    has_changes = true;
                }

                // Storage diffs
                for (key, slot) in &account.storage {
                    if slot.original_value != slot.present_value {
                        account_diff.storage.insert(
                            *key,
                            Delta::Changed {
                                from: slot.original_value,
                                to: slot.present_value,
                            },
                        );
                        has_changes = true;
                    }
                }
            }
            None => {
                // New account
                if !account.info.balance.is_zero() || account.info.nonce > 0 {
                    account_diff.balance = Delta::Added(account.info.balance);
                    account_diff.nonce = Delta::Added(account.info.nonce);
                    has_changes = true;
                }
            }
        }

        if has_changes {
            diffs.insert(*address, account_diff);
        }
    }

    StateDiff(diffs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, U256};
    use revm::primitives::{Account, AccountInfo, AccountStatus, EvmStorageSlot, KECCAK_EMPTY};
    use std::collections::HashMap;

    use bridge_types::conversions::{addr_to_fixed, u256_to_fixed};
    use bridge_types::types::RkyvAccount;

    #[test]
    fn test_balance_changed() {
        let addr = Address::from([0xaa; 20]);
        let original_balance = U256::from(100u64);

        // Original DB
        let mut accounts = BTreeMap::new();
        accounts.insert(
            addr_to_fixed(addr),
            RkyvAccount {
                nonce: 0,
                balance: u256_to_fixed(original_balance),
                code_hash: [0; 32],
                code: None,
                storage: BTreeMap::new(),
            },
        );
        let db = RkyvMemDB {
            accounts,
            block_hashes: BTreeMap::new(),
        };

        // Post-execution state
        let mut state = HashMap::default();
        state.insert(
            addr,
            Account {
                info: AccountInfo {
                    balance: U256::from(200u64),
                    nonce: 0,
                    code_hash: KECCAK_EMPTY,
                    code: None,
                },
                storage: HashMap::default(),
                status: AccountStatus::Touched,
            },
        );

        let diff = compute_state_diff(&state, &db);
        let account_diff = diff.0.get(&addr).expect("should have diff");
        assert_eq!(
            account_diff.balance,
            Delta::Changed {
                from: U256::from(100u64),
                to: U256::from(200u64)
            }
        );
    }

    #[test]
    fn test_unchanged_account_excluded() {
        let addr = Address::from([0xaa; 20]);
        let balance = U256::from(100u64);

        let mut accounts = BTreeMap::new();
        accounts.insert(
            addr_to_fixed(addr),
            RkyvAccount {
                nonce: 0,
                balance: u256_to_fixed(balance),
                code_hash: [0; 32],
                code: None,
                storage: BTreeMap::new(),
            },
        );
        let db = RkyvMemDB {
            accounts,
            block_hashes: BTreeMap::new(),
        };

        let mut state = HashMap::default();
        state.insert(
            addr,
            Account {
                info: AccountInfo {
                    balance,
                    nonce: 0,
                    code_hash: KECCAK_EMPTY,
                    code: None,
                },
                storage: HashMap::default(),
                status: AccountStatus::Touched,
            },
        );

        let diff = compute_state_diff(&state, &db);
        assert!(
            diff.0.is_empty(),
            "unchanged account should not appear in diff"
        );
    }

    #[test]
    fn test_storage_changed() {
        let addr = Address::from([0xaa; 20]);
        let key = U256::from(1u64);

        let mut storage = BTreeMap::new();
        storage.insert(u256_to_fixed(key), u256_to_fixed(U256::from(10u64)));
        let mut accounts = BTreeMap::new();
        accounts.insert(
            addr_to_fixed(addr),
            RkyvAccount {
                nonce: 0,
                balance: [0; 32],
                code_hash: [0; 32],
                code: None,
                storage,
            },
        );
        let db = RkyvMemDB {
            accounts,
            block_hashes: BTreeMap::new(),
        };

        let mut evm_storage = HashMap::default();
        evm_storage.insert(
            key,
            EvmStorageSlot {
                original_value: U256::from(10u64),
                present_value: U256::from(20u64),
                is_cold: false,
            },
        );

        let mut state = HashMap::default();
        state.insert(
            addr,
            Account {
                info: AccountInfo {
                    balance: U256::ZERO,
                    nonce: 0,
                    code_hash: KECCAK_EMPTY,
                    code: None,
                },
                storage: evm_storage,
                status: AccountStatus::Touched,
            },
        );

        let diff = compute_state_diff(&state, &db);
        let account_diff = diff.0.get(&addr).expect("should have diff");
        let slot_diff = account_diff
            .storage
            .get(&key)
            .expect("should have storage diff");
        assert_eq!(
            *slot_diff,
            Delta::Changed {
                from: U256::from(10u64),
                to: U256::from(20u64)
            }
        );
    }

    #[test]
    fn test_new_account_added() {
        let addr = Address::from([0xff; 20]);
        let db = RkyvMemDB {
            accounts: BTreeMap::new(),
            block_hashes: BTreeMap::new(),
        };

        let mut state = HashMap::default();
        state.insert(
            addr,
            Account {
                info: AccountInfo {
                    balance: U256::from(500u64),
                    nonce: 1,
                    code_hash: KECCAK_EMPTY,
                    code: None,
                },
                storage: HashMap::default(),
                status: AccountStatus::Created,
            },
        );

        let diff = compute_state_diff(&state, &db);
        let account_diff = diff.0.get(&addr).expect("should have diff for new account");
        assert_eq!(account_diff.balance, Delta::Added(U256::from(500u64)));
        assert_eq!(account_diff.nonce, Delta::Added(1));
    }
}

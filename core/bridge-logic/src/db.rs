// SPDX-License-Identifier: MIT
use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;

use alloy_primitives::{Address, Bytes, B256, U256};
use revm::primitives::{AccountInfo, Bytecode, KECCAK_EMPTY};
use revm::DatabaseRef;

use bridge_types::conversions::{fixed_to_addr, fixed_to_b256, fixed_to_u256};
use bridge_types::types::{DealRecord, RkyvMemDB};

/// Mutable in-memory database suitable for revm's `DatabaseRef` trait.
/// Created from deserialized rkyv data.
pub struct MutableMemDB {
    pub accounts: BTreeMap<Address, AccountInfo>,
    pub storage: BTreeMap<Address, BTreeMap<U256, U256>>,
    pub block_hashes: BTreeMap<u64, B256>,
    pub codes: BTreeMap<B256, Bytes>,
    /// Addresses for which missing storage reads should return 0 even in strict mode.
    ///
    /// This is used for "synthetic" accounts (e.g., injected PoC contract) whose
    /// storage is not part of the authenticated chain pre-state.
    allow_missing_storage: BTreeSet<Address>,
    strict_missing: bool,
}

impl MutableMemDB {
    /// Create a new MutableMemDB from deserialized rkyv data.
    pub fn from_rkyv(db: RkyvMemDB) -> Self {
        let mut accounts = BTreeMap::new();
        let mut storage_map = BTreeMap::new();
        let mut codes = BTreeMap::new();

        for (addr_bytes, account) in db.accounts {
            let address = fixed_to_addr(addr_bytes);
            let balance = fixed_to_u256(account.balance);
            let code_hash = fixed_to_b256(account.code_hash);

            let bytecode = if let Some(code_bytes) = &account.code {
                let bc = Bytecode::new_raw(Bytes::copy_from_slice(code_bytes));
                codes.insert(code_hash, Bytes::copy_from_slice(code_bytes));
                bc
            } else {
                Bytecode::default()
            };

            let info = AccountInfo {
                balance,
                nonce: account.nonce,
                code_hash,
                code: Some(bytecode),
            };
            accounts.insert(address, info);

            let mut slot_map = BTreeMap::new();
            for (key_bytes, val_bytes) in &account.storage {
                slot_map.insert(fixed_to_u256(*key_bytes), fixed_to_u256(*val_bytes));
            }
            if !slot_map.is_empty() {
                storage_map.insert(address, slot_map);
            }
        }

        let mut block_hashes = BTreeMap::new();
        for (num, hash_bytes) in db.block_hashes {
            block_hashes.insert(num, fixed_to_b256(hash_bytes));
        }

        MutableMemDB {
            accounts,
            storage: storage_map,
            block_hashes,
            codes,
            allow_missing_storage: BTreeSet::new(),
            strict_missing: false,
        }
    }

    /// Create a new MutableMemDB that panics on any access to missing state.
    pub fn from_rkyv_strict(db: RkyvMemDB) -> Self {
        let mut db = Self::from_rkyv(db);
        db.strict_missing = true;
        db
    }

    /// Allow missing storage reads for `address` (returning 0) even in strict mode.
    pub fn allow_missing_storage_for(&mut self, address: Address) {
        self.allow_missing_storage.insert(address);
    }

    /// Apply balance overrides (deals) to the database.
    /// If an account does not exist, it is created with default values.
    pub fn apply_deals(&mut self, deals: &[DealRecord]) {
        for deal in deals {
            let address = fixed_to_addr(deal.address);
            let balance = fixed_to_u256(deal.balance);

            let info = self.accounts.entry(address).or_insert_with(|| AccountInfo {
                balance: U256::ZERO,
                nonce: 0,
                code_hash: KECCAK_EMPTY,
                code: Some(Bytecode::default()),
            });
            info.balance = balance;
        }
    }
}

impl DatabaseRef for MutableMemDB {
    type Error = Infallible;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        match self.accounts.get(&address) {
            Some(info) => Ok(Some(info.clone())),
            None => {
                if self.strict_missing {
                    panic!("Accessing unproven account: {:?}", address);
                }
                Ok(None)
            }
        }
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        match self.codes.get(&code_hash) {
            Some(bytes) => Ok(Bytecode::new_raw(bytes.clone())),
            None => {
                if self.strict_missing {
                    panic!("Accessing unproven code hash: {:?}", code_hash);
                }
                Ok(Bytecode::default())
            }
        }
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        match self.storage.get(&address) {
            Some(account_storage) => match account_storage.get(&index) {
                Some(value) => Ok(*value),
                None => {
                    if self.strict_missing {
                        if self.allow_missing_storage.contains(&address) {
                            return Ok(U256::ZERO);
                        }
                        panic!("Accessing unproven storage slot: {:?} {:?}", address, index);
                    }
                    Ok(U256::ZERO)
                }
            },
            None => {
                if self.strict_missing {
                    if self.allow_missing_storage.contains(&address) {
                        return Ok(U256::ZERO);
                    }
                    panic!("Accessing unproven storage account: {:?}", address);
                }
                Ok(U256::ZERO)
            }
        }
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        match self.block_hashes.get(&number) {
            Some(hash) => Ok(*hash),
            None => {
                if self.strict_missing {
                    panic!("Accessing unproven block hash: {}", number);
                }
                Ok(B256::ZERO)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bridge_types::conversions::u256_to_fixed;
    use bridge_types::types::{RkyvAccount, RkyvMemDB};

    fn make_rkyv_memdb() -> RkyvMemDB {
        let mut storage = BTreeMap::new();
        storage.insert(
            u256_to_fixed(U256::from(1u64)),
            u256_to_fixed(U256::from(42u64)),
        );

        let account = RkyvAccount {
            nonce: 5,
            balance: u256_to_fixed(U256::from(1000u64)),
            code_hash: [0; 32],
            code: None,
            storage,
        };

        let mut accounts = BTreeMap::new();
        let addr = [0xaa; 20];
        accounts.insert(addr, account);

        let mut block_hashes = BTreeMap::new();
        block_hashes.insert(100, [0xbb; 32]);

        RkyvMemDB {
            accounts,
            block_hashes,
        }
    }

    #[test]
    fn test_from_rkyv_preserves_data() {
        let db = MutableMemDB::from_rkyv(make_rkyv_memdb());
        let addr = Address::from([0xaa; 20]);

        let info = db.basic_ref(addr).unwrap().unwrap();
        assert_eq!(info.nonce, 5);
        assert_eq!(info.balance, U256::from(1000u64));

        let val = db.storage_ref(addr, U256::from(1u64)).unwrap();
        assert_eq!(val, U256::from(42u64));

        let hash = db.block_hash_ref(100).unwrap();
        assert_eq!(hash, B256::from([0xbb; 32]));
    }

    #[test]
    #[should_panic(expected = "Accessing unproven account")]
    fn test_missing_account_panics() {
        let db = MutableMemDB::from_rkyv_strict(make_rkyv_memdb());
        let missing = Address::from([0xff; 20]);
        let _ = db.basic_ref(missing);
    }

    #[test]
    #[should_panic(expected = "Accessing unproven storage slot")]
    fn test_missing_storage_panics() {
        let db = MutableMemDB::from_rkyv_strict(make_rkyv_memdb());
        let addr = Address::from([0xaa; 20]);
        let _ = db.storage_ref(addr, U256::from(999u64));
    }

    #[test]
    fn test_apply_deals_existing_account() {
        let mut db = MutableMemDB::from_rkyv(make_rkyv_memdb());
        let addr = [0xaa; 20];
        let new_balance = U256::from(9999u64);

        db.apply_deals(&[DealRecord {
            address: addr,
            balance: u256_to_fixed(new_balance),
        }]);

        let info = db.basic_ref(Address::from(addr)).unwrap().unwrap();
        assert_eq!(info.balance, new_balance);
        assert_eq!(info.nonce, 5); // nonce preserved
    }

    #[test]
    fn test_apply_deals_new_account() {
        let mut db = MutableMemDB::from_rkyv(make_rkyv_memdb());
        let new_addr = [0xcc; 20];
        let balance = U256::from(500u64);

        db.apply_deals(&[DealRecord {
            address: new_addr,
            balance: u256_to_fixed(balance),
        }]);

        let info = db.basic_ref(Address::from(new_addr)).unwrap().unwrap();
        assert_eq!(info.balance, balance);
        assert_eq!(info.nonce, 0);
    }

    #[test]
    fn test_missing_block_hash_returns_zero() {
        let db = MutableMemDB::from_rkyv(make_rkyv_memdb());
        let hash = db.block_hash_ref(999).unwrap();
        assert_eq!(hash, B256::ZERO);
    }

    #[test]
    fn test_apply_multiple_deals() {
        let mut db = MutableMemDB::from_rkyv(make_rkyv_memdb());
        let deals = vec![
            DealRecord {
                address: [0xaa; 20],
                balance: u256_to_fixed(U256::from(111u64)),
            },
            DealRecord {
                address: [0xdd; 20],
                balance: u256_to_fixed(U256::from(222u64)),
            },
        ];
        db.apply_deals(&deals);

        let a = db.basic_ref(Address::from([0xaa; 20])).unwrap().unwrap();
        assert_eq!(a.balance, U256::from(111u64));
        let d = db.basic_ref(Address::from([0xdd; 20])).unwrap().unwrap();
        assert_eq!(d.balance, U256::from(222u64));
    }

    #[test]
    fn test_code_by_hash_ref() {
        let db = MutableMemDB::from_rkyv(make_rkyv_memdb());
        let addr = Address::from([0xaa; 20]);
        let info = db.basic_ref(addr).unwrap().unwrap();
        let code = db.code_by_hash_ref(info.code_hash).unwrap();
        assert!(!code.bytecode().is_empty());
    }
}

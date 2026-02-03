// SPDX-License-Identifier: MIT
use std::cell::RefCell;
use std::collections::BTreeSet;

use alloy_primitives::{Address, B256, U256};
use revm::primitives::{AccountInfo, Bytecode};
use revm::DatabaseRef;

/// Records of all DB accesses during a dry-run trace.
#[derive(Debug, Default, Clone)]
pub struct AccessTrace {
    pub accounts: BTreeSet<Address>,
    pub storage: BTreeSet<(Address, U256)>,
    pub block_hashes: BTreeSet<u64>,
}

/// A tracing wrapper around an inner `DatabaseRef` that records all accesses.
///
/// Used during the preflight dry-run to discover which storage slots,
/// accounts, and block hashes the exploit touches, so they can be
/// batch-fetched from the RPC.
pub struct ProxyDB<DB> {
    inner: DB,
    trace: RefCell<AccessTrace>,
}

impl<DB> ProxyDB<DB> {
    pub fn new(inner: DB) -> Self {
        ProxyDB {
            inner,
            trace: RefCell::new(AccessTrace::default()),
        }
    }

    /// Consume the ProxyDB and return the accumulated access trace.
    pub fn into_trace(self) -> AccessTrace {
        self.trace.into_inner()
    }
}

impl<DB: DatabaseRef> DatabaseRef for ProxyDB<DB> {
    type Error = DB::Error;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.trace.borrow_mut().accounts.insert(address);
        self.inner.basic_ref(address)
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.inner.code_by_hash_ref(code_hash)
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        self.trace.borrow_mut().storage.insert((address, index));
        self.inner.storage_ref(address, index)
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        self.trace.borrow_mut().block_hashes.insert(number);
        self.inner.block_hash_ref(number)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bridge_logic::db::MutableMemDB;
    use bridge_types::conversions::u256_to_fixed;
    use bridge_types::types::{RkyvAccount, RkyvMemDB};
    use std::collections::BTreeMap;

    #[test]
    fn test_proxy_records_accesses() {
        // Construct a DB that actually has the data we're going to access,
        // because MutableMemDB panics on missing data.
        let addr_bytes = [0xaa; 20];
        let addr = Address::from(addr_bytes);

        let mut storage = BTreeMap::new();
        storage.insert(u256_to_fixed(U256::from(1u64)), [0u8; 32]); // Insert slot 1

        let account = RkyvAccount {
            nonce: 0,
            balance: [0u8; 32],
            code_hash: [0u8; 32],
            code: None,
            storage,
        };

        let mut accounts = BTreeMap::new();
        accounts.insert(addr_bytes, account);

        let mut block_hashes = BTreeMap::new();
        block_hashes.insert(100, [0u8; 32]);

        let db = MutableMemDB::from_rkyv(RkyvMemDB {
            accounts,
            block_hashes,
        });

        let proxy = ProxyDB::new(&db);
        let _ = proxy.basic_ref(addr);
        let _ = proxy.storage_ref(addr, U256::from(1u64));
        let _ = proxy.block_hash_ref(100);

        let trace = proxy.into_trace();
        assert!(trace.accounts.contains(&addr));
        assert!(trace.storage.contains(&(addr, U256::from(1u64))));
        assert!(trace.block_hashes.contains(&100));
    }
}

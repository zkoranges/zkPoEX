// SPDX-License-Identifier: MIT
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use alloy_primitives::{Address, U256};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::warn;

/// Cached block data stored on disk as JSON.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct BlockCacheData {
    pub accounts: BTreeMap<String, CachedAccountInfo>,
    pub storage: BTreeMap<String, BTreeMap<String, String>>,
    pub block_hashes: BTreeMap<u64, String>,
}

/// Serializable account info for the cache.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedAccountInfo {
    pub nonce: u64,
    pub balance: String,
    pub code_hash: String,
    pub code: Option<String>,
}

/// Thread-safe block cache with JSON persistence and self-healing on corrupt files.
pub struct BlockCache {
    data: RwLock<BlockCacheData>,
    path: PathBuf,
}

impl BlockCache {
    /// Load an existing cache file or create a new empty cache.
    /// If the file exists but is corrupt, it is deleted and an empty cache is returned.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        let data = if path.exists() {
            match std::fs::File::open(path) {
                Ok(file) => {
                    let reader = std::io::BufReader::new(file);
                    match serde_json::from_reader(reader) {
                        Ok(data) => data,
                        Err(e) => {
                            warn!(
                                "Cache file {} is corrupt ({}), deleting and starting fresh",
                                path.display(),
                                e
                            );
                            let _ = std::fs::remove_file(path);
                            BlockCacheData::default()
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to open cache file {}: {}", path.display(), e);
                    BlockCacheData::default()
                }
            }
        } else {
            BlockCacheData::default()
        };

        Ok(BlockCache {
            data: RwLock::new(data),
            path: path.to_path_buf(),
        })
    }

    /// Get cached account info.
    pub fn get_account(&self, address: &Address) -> Option<CachedAccountInfo> {
        let data = self.data.read().unwrap();
        data.accounts.get(&format!("{:?}", address)).cloned()
    }

    /// Insert account info into the cache.
    pub fn insert_account(&self, address: Address, info: CachedAccountInfo) {
        let mut data = self.data.write().unwrap();
        data.accounts.insert(format!("{:?}", address), info);
    }

    /// Get cached storage value.
    pub fn get_storage(&self, address: &Address, key: &U256) -> Option<String> {
        let data = self.data.read().unwrap();
        data.storage
            .get(&format!("{:?}", address))
            .and_then(|slots| slots.get(&format!("{:?}", key)))
            .cloned()
    }

    /// Insert storage value into the cache.
    pub fn insert_storage(&self, address: Address, key: U256, value: String) {
        let mut data = self.data.write().unwrap();
        data.storage
            .entry(format!("{:?}", address))
            .or_default()
            .insert(format!("{:?}", key), value);
    }

    /// Get cached block hash.
    pub fn get_block_hash(&self, number: u64) -> Option<String> {
        let data = self.data.read().unwrap();
        data.block_hashes.get(&number).cloned()
    }

    /// Insert block hash into the cache.
    pub fn insert_block_hash(&self, number: u64, hash: String) {
        let mut data = self.data.write().unwrap();
        data.block_hashes.insert(number, hash);
    }

    /// Flush the cache to disk.
    pub fn flush(&self) -> Result<()> {
        let data = self.data.read().unwrap();
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("failed to create cache directory {}", parent.display())
            })?;
        }
        let file = std::fs::File::create(&self.path)
            .with_context(|| format!("failed to create cache file {}", self.path.display()))?;
        serde_json::to_writer_pretty(file, &*data)
            .with_context(|| format!("failed to write cache file {}", self.path.display()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.json");

        let cache = BlockCache::load_or_create(&path).unwrap();
        cache.insert_block_hash(100, "0xabc".to_string());
        cache.flush().unwrap();

        let cache2 = BlockCache::load_or_create(&path).unwrap();
        assert_eq!(cache2.get_block_hash(100), Some("0xabc".to_string()));
    }

    #[test]
    fn test_self_healing_corrupt_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.json");

        // Write garbage
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(b"not valid json {{{{").unwrap();
        }

        // Should recover gracefully
        let cache = BlockCache::load_or_create(&path).unwrap();
        assert!(cache.get_block_hash(100).is_none());

        // Corrupt file should be deleted
        assert!(!path.exists());
    }

    #[test]
    fn test_nonexistent_file_creates_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent.json");

        let cache = BlockCache::load_or_create(&path).unwrap();
        assert!(cache.get_block_hash(100).is_none());
    }

    #[test]
    fn test_account_insert_and_get() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.json");

        let cache = BlockCache::load_or_create(&path).unwrap();
        let addr = Address::from([0xaa; 20]);
        cache.insert_account(
            addr,
            CachedAccountInfo {
                nonce: 5,
                balance: "1000".to_string(),
                code_hash: "0x00".to_string(),
                code: None,
            },
        );

        let info = cache.get_account(&addr).unwrap();
        assert_eq!(info.nonce, 5);
        assert_eq!(info.balance, "1000");
    }

    #[test]
    fn test_storage_insert_and_get() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.json");

        let cache = BlockCache::load_or_create(&path).unwrap();
        let addr = Address::from([0xaa; 20]);
        let key = U256::from(1u64);

        cache.insert_storage(addr, key, "42".to_string());
        assert_eq!(cache.get_storage(&addr, &key), Some("42".to_string()));
    }
}

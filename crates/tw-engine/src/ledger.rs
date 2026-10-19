//! Canonical Dependency Ledger

use crate::hasher::hash_to_hex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Canonical entry for a single file or dependency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerEntry {
    /// Normalized path (cross-platform consistent)
    pub path: String,
    /// SHA-256 hash
    pub sha256: String,
    /// BLAKE3 hash
    pub blake3: String,
    /// File size in bytes
    pub size: u64,
    /// Last modification timestamp (normalized)
    pub modified: u64,
}

/// The complete canonical dependency ledger
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyLedger {
    /// TrustWeave engine version
    pub engine_version: String,
    /// Root hash of entire tree
    pub root_hash: String,
    /// Algorithm used for root hash
    pub root_hash_algorithm: String,
    /// Timestamp of ledger generation
    pub timestamp: u64,
    /// All entries (BTreeMap ensures deterministic ordering)
    pub entries: BTreeMap<String, LedgerEntry>,
}

impl DependencyLedger {
    /// Create a new empty ledger
    pub fn new() -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Self {
            engine_version: crate::VERSION.to_string(),
            root_hash: String::new(),
            root_hash_algorithm: crate::ROOT_HASH_ALGORITHM.to_string(),
            timestamp,
            entries: BTreeMap::new(),
        }
    }

    /// Add an entry to the ledger
    pub fn add_entry(&mut self, entry: LedgerEntry) {
        self.entries.insert(entry.path.clone(), entry);
    }

    /// Compute and set the global root hash
    ///
    /// The root commits to length-prefixed, ordered content records. Timestamps
    /// remain descriptive ledger metadata and are deliberately excluded.
    pub fn compute_root_hash(&mut self) {
        let mut hasher = Sha256::new();
        hasher.update(b"TrustWeave.DependencyLedger.v1\0");
        update_field(&mut hasher, self.engine_version.as_bytes());
        for entry in self.entries.values() {
            update_field(&mut hasher, entry.path.as_bytes());
            update_field(&mut hasher, entry.sha256.as_bytes());
            update_field(&mut hasher, entry.blake3.as_bytes());
            hasher.update(entry.size.to_be_bytes());
        }

        let result = hasher.finalize();
        self.root_hash = hash_to_hex(&result);
    }

    /// Serialize ledger to JSON
    pub fn to_json(&self) -> Result<String, crate::error::EngineError> {
        serde_json::to_string_pretty(self).map_err(Into::into)
    }

    /// Deserialize ledger from JSON
    pub fn from_json(json: &str) -> Result<Self, crate::error::EngineError> {
        serde_json::from_str(json).map_err(Into::into)
    }
}

impl Default for DependencyLedger {
    fn default() -> Self {
        Self::new()
    }
}

fn update_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ledger_with_file(timestamp: u64, modified: u64) -> DependencyLedger {
        let mut ledger = DependencyLedger::new();
        ledger.timestamp = timestamp;
        ledger.add_entry(LedgerEntry {
            path: "src/main.rs".to_string(),
            sha256: "aa".repeat(32),
            blake3: "bb".repeat(32),
            size: 42,
            modified,
        });
        ledger.compute_root_hash();
        ledger
    }

    #[test]
    fn content_root_is_independent_of_timestamps() {
        let first = ledger_with_file(10, 20);
        let second = ledger_with_file(30, 40);
        assert_eq!(first.root_hash, second.root_hash);
    }

    #[test]
    fn content_changes_change_the_root() {
        let first = ledger_with_file(10, 20);
        let mut second = first.clone();
        if let Some(entry) = second.entries.get_mut("src/main.rs") {
            entry.size += 1;
        }
        second.compute_root_hash();
        assert_ne!(first.root_hash, second.root_hash);
    }
}

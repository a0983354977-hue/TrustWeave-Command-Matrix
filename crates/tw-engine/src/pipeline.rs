//! Deterministic ingestion pipeline coordinator

use crate::hasher::{hash_file_blake3, hash_file_sha256, hash_to_hex};
use crate::ledger::{DependencyLedger, LedgerEntry};
use crate::traversal::{traverse_deterministic, TraversalConfig};
use crate::Result;
use rayon::prelude::*;

/// Configuration for the complete ingestion pipeline
#[derive(Debug, Clone, Default)]
pub struct PipelineConfig {
    /// Traversal configuration
    pub traversal: TraversalConfig,
}

/// Execute the complete deterministic ingestion pipeline
///
/// This function:
/// 1. Traverses the directory with blacklist filtering
/// 2. Normalizes all paths to cross-platform format
/// 3. Computes SHA-256 and BLAKE3 hashes for all files (stream-based)
/// 4. Builds the canonical ledger with deterministic ordering
/// 5. Computes the global root hash
pub fn execute_pipeline(config: &PipelineConfig) -> Result<DependencyLedger> {
    tracing::info!("Starting deterministic ingestion pipeline");
    tracing::info!("Root directory: {:?}", config.traversal.root);

    // Step 1: Traverse directory with blacklist filtering
    let files = traverse_deterministic(&config.traversal)?;
    tracing::info!("Found {} files after filtering", files.len());

    // Step 2: Build ledger entries in parallel
    let buffer_size = config.traversal.buffer_size;
    let root = config.traversal.root.clone();
    let entries: Vec<LedgerEntry> = files
        .par_iter()
        .map(|path_str| -> Result<LedgerEntry> {
            // Join relative path with root to get absolute path
            let path = root.join(path_str);
            let metadata = std::fs::metadata(&path)?;

            // Compute hashes with stream-based reading
            let sha256 = hash_file_sha256(&path, buffer_size)?;
            let blake3 = hash_file_blake3(&path, buffer_size)?;

            Ok(LedgerEntry {
                path: path_str.clone(),
                sha256: hash_to_hex(&sha256),
                blake3: hash_to_hex(&blake3),
                size: metadata.len(),
                modified: metadata
                    .modified()?
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    // Step 3: Build ledger
    let mut ledger = DependencyLedger::new();
    for entry in entries {
        ledger.add_entry(entry);
    }

    // Step 4: Compute global root hash
    ledger.compute_root_hash();
    tracing::info!("Global root hash: {}", ledger.root_hash);

    Ok(ledger)
}

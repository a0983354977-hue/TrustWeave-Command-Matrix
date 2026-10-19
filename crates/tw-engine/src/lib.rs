//! TrustWeave Engine - Deterministic Ingestion Layer
//!
//! This module provides the foundational I/O and hashing core for the TrustWeave
//! global software supply chain security architecture.
//!
//! # Phase 1: Deterministic Ingestion Layer
//!
//! The engine guarantees bit-level consistency across environments by:
//! - Normalizing file system traversal with strict ordering
//! - Computing deterministic cryptographic hashes (SHA-256, BLAKE3)
//! - Building Merkle trees for dependency provenance
//! - Filtering noise (VCS, build artifacts, self-generated artifacts)
//!
//! # Security Guarantees
//!
//! - Zero heap allocation for binary parsing (handled by Zig layer)
//! - Parallel hashing with deterministic ordering
//! - Cross-platform path normalization
//! - Stream-based file reading to prevent memory exhaustion

#![warn(missing_docs)]
#![warn(clippy::all)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

pub mod bundle;
pub mod error;
pub mod fault_injection_tests;
pub mod hasher;
pub mod ledger;
pub mod pipeline;
pub mod stress_tests;
pub mod traversal;

#[cfg(feature = "yara-scanner")]
pub mod scanner;

/// TrustWeave Engine version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Global root hash algorithm (SHA-256 for broad compatibility)
pub const ROOT_HASH_ALGORITHM: &str = "sha256";

/// Default buffer size for stream-based file reading (64KB, L1-cache friendly)
pub const DEFAULT_BUFFER_SIZE: usize = 64 * 1024;

/// Result type alias for TrustWeave operations
pub type Result<T> = std::result::Result<T, error::EngineError>;

pub mod deps;

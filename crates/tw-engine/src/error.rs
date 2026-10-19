//! Error types for TrustWeave Engine

use thiserror::Error;

/// Errors that can occur in the TrustWeave engine
#[derive(Error, Debug)]
pub enum EngineError {
    /// I/O operation failed
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Path normalization failed
    #[error("Path normalization error: {0}")]
    PathNormalization(String),

    /// Hash computation failed
    #[error("Hash computation error: {0}")]
    Hash(String),

    /// Serialization/deserialization failed
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Path traversal attempted to escape root directory
    #[error("Traversed path is not within root: {0}")]
    PathEscalation(String),

    /// A provenance bundle failed validation
    #[error("Invalid provenance bundle: {0}")]
    InvalidBundle(String),

    /// Malware scan failed
    #[error("Malware scan error: {0}")]
    Scan(String),
}

//! Cryptographic hashing utilities for TrustWeave

use crate::Result;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read};

/// SHA-256 hash output
pub type Sha256Hash = [u8; 32];

/// BLAKE3 hash output
pub type Blake3Hash = [u8; 32];

/// Convert hash bytes to hex string
pub fn hash_to_hex(hash: &[u8]) -> String {
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Compute SHA-256 hash of file content (stream-based with fixed buffer)
pub fn hash_file_sha256(path: &std::path::Path, buffer_size: usize) -> Result<Sha256Hash> {
    let file = File::open(path)?;
    let mut reader = BufReader::with_capacity(buffer_size, file);
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; buffer_size];

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    Ok(hash)
}

/// Compute BLAKE3 hash of file content (stream-based with fixed buffer)
pub fn hash_file_blake3(path: &std::path::Path, buffer_size: usize) -> Result<Blake3Hash> {
    let file = File::open(path)?;
    let mut reader = BufReader::with_capacity(buffer_size, file);
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0u8; buffer_size];

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let hash = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_bytes());
    Ok(result)
}

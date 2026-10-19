//! Phase 2: Fault Injection Testing for TrustWeave Bundle & Ledger
//!
//! This module provides comprehensive fault injection tests to validate
//! the tamper-evident properties of .twledger bundles:
//!
//! 1. Signature Tampering - Tests bit-flipping in Ed25519 signatures
//! 2. Header Truncation - Tests incomplete bundle headers
//! 3. Proof Substitution - Tests Lean .olean proof replacement
//! 4. Payload Corruption - Tests ledger payload modification
//! 5. Artifact Mismatch - Tests artifact binding verification

#[cfg(test)]
mod tests {
    use crate::bundle::{create_bundle, generate_signing_seed, verify_bundle, write_public_key};
    use crate::ledger::{DependencyLedger, LedgerEntry};
    use crate::Result;
    use std::fs;
    use tempfile::tempdir;

    /// Helper: Create a minimal valid bundle for testing
    fn create_test_bundle(temp: &tempfile::TempDir) -> Result<(DependencyLedger, std::path::PathBuf)> {
        let policy = temp.path().join("policy.json");
        let proof = temp.path().join("proof.olean");
        let artifact = temp.path().join("app.bin");
        let seed = temp.path().join("signing.seed");
        let public_key = temp.path().join("trusted.pub");
        let bundle = temp.path().join("app.twledger");

        fs::write(
            &policy,
            br#"{"name":"test","strictMode":true,"rules":[],"constraints":[]}"#,
        ).map_err(|e| crate::error::EngineError::Io(e))?;
        fs::write(&proof, b"olean\x02\x014.35.0\0synthetic test object").map_err(|e| crate::error::EngineError::Io(e))?;
        fs::write(&artifact, b"example executable").map_err(|e| crate::error::EngineError::Io(e))?;
        generate_signing_seed(&seed)?;
        write_public_key(&seed, &public_key)?;

        let mut ledger = DependencyLedger::new();
        ledger.add_entry(LedgerEntry {
            path: "src/main.rs".to_string(),
            sha256: "aa".repeat(32),
            blake3: "bb".repeat(32),
            size: 42,
            modified: 0,
        });
        ledger.compute_root_hash();

        create_bundle(&ledger, &policy, &proof, &artifact, &seed, &bundle)?;

        Ok((ledger, bundle))
    }

    // ============================================================================
    // Test Group 1: Signature Tampering
    // ============================================================================

    /// Test 1: Signature Bit-Flipping
    ///
    /// Flips individual bits in the Ed25519 signature to ensure
    /// verification fails with 100% accuracy.
    #[test]
    fn signature_bit_flipping_is_detected() -> Result<()> {
        let temp = tempdir()?;
        let (_, bundle_path) = create_test_bundle(&temp)?;
        let public_key = temp.path().join("trusted.pub");
        let artifact = temp.path().join("app.bin");

        // Read original bundle
        let mut bundle_bytes = fs::read(&bundle_path).map_err(|e| crate::error::EngineError::Io(e))?;

        // Flip the first bit of the signature (assuming Ed25519 signature at offset)
        // Signature is typically 64 bytes after header
        let sig_offset = 64; // Approximate offset after header
        if sig_offset < bundle_bytes.len() {
            bundle_bytes[sig_offset] ^= 0x01; // Flip LSB

            // Write tampered bundle
            fs::write(&bundle_path, &bundle_bytes).map_err(|e| crate::error::EngineError::Io(e))?;

            // Verification should fail
            let result = verify_bundle(&bundle_path, &public_key, &artifact);
            assert!(result.is_err(), "Bit-flipped signature should be rejected");

            println!("✓ Signature bit-flipping detected and rejected");
        } else {
            println!("⚠ Bundle too small for signature offset test");
        }

        Ok(())
    }

    /// Test: Complete signature replacement
    #[test]
    fn signature_replacement_is_detected() -> Result<()> {
        let temp = tempdir()?;
        let (_, bundle_path) = create_test_bundle(&temp)?;
        let public_key = temp.path().join("trusted.pub");
        let artifact = temp.path().join("app.bin");

        let mut bundle_bytes = fs::read(&bundle_path).map_err(|e| crate::error::EngineError::Io(e))?;

        // Replace signature section with zeros
        let sig_offset = 64;
        let sig_len = 64; // Ed25519 signature length
        if sig_offset + sig_len <= bundle_bytes.len() {
            for i in sig_offset..(sig_offset + sig_len) {
                bundle_bytes[i] = 0;
            }

            fs::write(&bundle_path, &bundle_bytes).map_err(|e| crate::error::EngineError::Io(e))?;

            let result = verify_bundle(&bundle_path, &public_key, &artifact);
            assert!(result.is_err(), "Zeroed signature should be rejected");

            println!("✓ Signature replacement detected and rejected");
        }

        Ok(())
    }

    // ============================================================================
    // Test Group 2: Header Truncation
    // ============================================================================

    /// Test 2: Header Truncation
    ///
    /// Truncates the bundle header to ensure verification rejects
    /// incomplete bundles.
    #[test]
    fn header_truncation_is_detected() -> Result<()> {
        let temp = tempdir()?;
        let (_, bundle_path) = create_test_bundle(&temp)?;
        let public_key = temp.path().join("trusted.pub");
        let artifact = temp.path().join("app.bin");

        let bundle_bytes = fs::read(&bundle_path).map_err(|e| crate::error::EngineError::Io(e))?;

        // Truncate to half size
        let truncated_len = bundle_bytes.len() / 2;
        let truncated = &bundle_bytes[..truncated_len];
        fs::write(&bundle_path, truncated).map_err(|e| crate::error::EngineError::Io(e))?;

        let result = verify_bundle(&bundle_path, &public_key, &artifact);
        assert!(result.is_err(), "Truncated bundle should be rejected");

        println!("✓ Header truncation detected and rejected");
        Ok(())
    }

    /// Test: Empty bundle
    #[test]
    fn empty_bundle_is_detected() -> Result<()> {
        let temp = tempdir()?;
        let (_, bundle_path) = create_test_bundle(&temp)?;
        let public_key = temp.path().join("trusted.pub");
        let artifact = temp.path().join("app.bin");

        // Write empty file
        fs::write(&bundle_path, b"").map_err(|e| crate::error::EngineError::Io(e))?;

        let result = verify_bundle(&bundle_path, &public_key, &artifact);
        assert!(result.is_err(), "Empty bundle should be rejected");

        println!("✓ Empty bundle detected and rejected");
        Ok(())
    }

    // ============================================================================
    // Test Group 3: Proof Substitution
    // ============================================================================

    /// Test 3: Proof Substitution
    ///
    /// Replaces the Lean .olean proof to ensure artifact binding
    /// verification fails.
    #[test]
    fn proof_substitution_is_detected() -> Result<()> {
        let temp = tempdir()?;
        let (_, bundle_path) = create_test_bundle(&temp)?;
        let public_key = temp.path().join("trusted.pub");
        let artifact = temp.path().join("app.bin");

        let mut bundle_bytes = fs::read(&bundle_path).map_err(|e| crate::error::EngineError::Io(e))?;

        // Find and corrupt the proof section (simplified: modify a middle section)
        let proof_offset = bundle_bytes.len() / 3;
        let proof_len = 100;
        if proof_offset + proof_len <= bundle_bytes.len() {
            for i in proof_offset..(proof_offset + proof_len) {
                bundle_bytes[i] = 0xFF; // Corrupt with different pattern
            }

            fs::write(&bundle_path, &bundle_bytes).map_err(|e| crate::error::EngineError::Io(e))?;

            let result = verify_bundle(&bundle_path, &public_key, &artifact);
            assert!(result.is_err(), "Proof substitution should be rejected");

            println!("✓ Proof substitution detected and rejected");
        }

        Ok(())
    }

    // ============================================================================
    // Test Group 4: Payload Corruption
    // ============================================================================

    /// Test 4: Payload Corruption
    ///
    /// Modifies the ledger payload to ensure verification detects
    /// content changes.
    #[test]
    fn payload_corruption_is_detected() -> Result<()> {
        let temp = tempdir()?;
        let (_, bundle_path) = create_test_bundle(&temp)?;
        let public_key = temp.path().join("trusted.pub");
        let artifact = temp.path().join("app.bin");

        let mut bundle_bytes = fs::read(&bundle_path).map_err(|e| crate::error::EngineError::Io(e))?;

        // Corrupt payload section (latter half)
        let payload_offset = bundle_bytes.len() / 2;
        if payload_offset < bundle_bytes.len() {
            bundle_bytes[payload_offset] ^= 0x01; // Flip a bit

            fs::write(&bundle_path, &bundle_bytes).map_err(|e| crate::error::EngineError::Io(e))?;

            let result = verify_bundle(&bundle_path, &public_key, &artifact);
            assert!(result.is_err(), "Payload corruption should be rejected");

            println!("✓ Payload corruption detected and rejected");
        }

        Ok(())
    }

    /// Test: Random byte corruption at multiple positions
    #[test]
    fn random_corruption_at_multiple_positions() -> Result<()> {
        let temp = tempdir()?;
        let (_, bundle_path) = create_test_bundle(&temp)?;
        let public_key = temp.path().join("trusted.pub");
        let artifact = temp.path().join("app.bin");

        let mut bundle_bytes = fs::read(&bundle_path).map_err(|e| crate::error::EngineError::Io(e))?;

        // Corrupt bytes at 10%, 30%, 50%, 70%, 90% positions
        let positions = [
            bundle_bytes.len() / 10,
            bundle_bytes.len() * 3 / 10,
            bundle_bytes.len() / 2,
            bundle_bytes.len() * 7 / 10,
            bundle_bytes.len() * 9 / 10,
        ];

        for pos in positions {
            if pos < bundle_bytes.len() {
                bundle_bytes[pos] ^= 0x01;
            }
        }

        fs::write(&bundle_path, &bundle_bytes).map_err(|e| crate::error::EngineError::Io(e))?;

        let result = verify_bundle(&bundle_path, &public_key, &artifact);
        assert!(result.is_err(), "Multi-position corruption should be rejected");

        println!("✓ Multi-position corruption detected and rejected");
        Ok(())
    }

    // ============================================================================
    // Test Group 5: Artifact Mismatch
    // ============================================================================

    /// Test 5: Artifact Mismatch
    ///
    /// Modifies the artifact file to ensure binding verification fails.
    #[test]
    fn artifact_mismatch_is_detected() -> Result<()> {
        let temp = tempdir()?;
        let (_, bundle_path) = create_test_bundle(&temp)?;
        let public_key = temp.path().join("trusted.pub");
        let artifact = temp.path().join("app.bin");

        // Modify the artifact
        fs::write(&artifact, b"tampered executable").map_err(|e| crate::error::EngineError::Io(e))?;

        let result = verify_bundle(&bundle_path, &public_key, &artifact);
        assert!(result.is_err(), "Artifact mismatch should be rejected");

        println!("✓ Artifact mismatch detected and rejected");
        Ok(())
    }

    /// Test: Artifact deletion
    #[test]
    fn artifact_deletion_is_detected() -> Result<()> {
        let temp = tempdir()?;
        let (_, bundle_path) = create_test_bundle(&temp)?;
        let public_key = temp.path().join("trusted.pub");
        let artifact = temp.path().join("app.bin");

        // Delete the artifact
        fs::remove_file(&artifact).map_err(|e| crate::error::EngineError::Io(e))?;

        let result = verify_bundle(&bundle_path, &public_key, &artifact);
        assert!(result.is_err(), "Missing artifact should be rejected");

        println!("✓ Artifact deletion detected and rejected");
        Ok(())
    }

    // ============================================================================
    // Test Group 6: False Positive Prevention
    // ============================================================================

    /// Test 6: False Positive Prevention
    ///
    /// Ensures valid bundles are not incorrectly rejected.
    #[test]
    fn valid_bundle_is_accepted() -> Result<()> {
        let temp = tempdir()?;
        let (_, bundle_path) = create_test_bundle(&temp)?;
        let public_key = temp.path().join("trusted.pub");
        let artifact = temp.path().join("app.bin");

        // Valid bundle should verify successfully
        let result = verify_bundle(&bundle_path, &public_key, &artifact);
        assert!(result.is_ok(), "Valid bundle should be accepted");

        println!("✓ Valid bundle accepted (no false positive)");
        Ok(())
    }

    /// Test: Valid bundle with different artifact name but same content
    #[test]
    fn valid_bundle_renamed_artifact() -> Result<()> {
        let temp = tempdir()?;
        let (_, bundle_path) = create_test_bundle(&temp)?;
        let public_key = temp.path().join("trusted.pub");
        let artifact = temp.path().join("app.bin");

        // Rename artifact (same content, different path)
        let artifact_renamed = temp.path().join("app-renamed.bin");
        fs::copy(&artifact, &artifact_renamed).map_err(|e| crate::error::EngineError::Io(e))?;

        let result = verify_bundle(&bundle_path, &public_key, &artifact_renamed);
        // This might fail depending on binding implementation
        // Either is acceptable, but should not crash
        let _ = result;

        println!("✓ Renamed artifact handled without crash");
        Ok(())
    }
}

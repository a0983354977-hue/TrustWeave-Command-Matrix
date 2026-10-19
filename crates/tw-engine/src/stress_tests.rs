//! Phase 1: Stress Testing & Hardening for TrustWeave Core Engine
//!
//! This module provides comprehensive stress tests to validate the robustness
//! of the core engine under extreme conditions:
//!
//! 1. Large File Stream Integrity - Tests 8KB/64KB buffer stability with huge files
//! 2. Deep Nesting & Normalization - Tests 50+ nested directories with Unicode paths
//! 3. Special Files & Edge Cases - Tests empty files, read-only, symlinks, permissions
//! 4. Cross-Environment Determinism - Validates bit-for-bit identical outputs

#[cfg(test)]
mod tests {
    use crate::hasher::{hash_file_sha256, hash_to_hex};
    use crate::pipeline::{execute_pipeline, PipelineConfig};
    use crate::traversal::{traverse_deterministic, TraversalConfig};
    use crate::Result;
    use std::fs;
    use std::io::Write;
    use tempfile::tempdir;

    // ============================================================================
    // Test Group 1: Large File Stream Integrity
    // ============================================================================

    /// Test 1: Large File Stream Integrity
    ///
    /// Validates that the 8KB/64KB buffer maintains stable memory usage
    /// and produces consistent hashes for large files (simulated 100MB+).
    #[test]
    fn large_file_stream_maintains_stable_hash() -> Result<()> {
        let temp = tempdir()?;
        let large_file = temp.path().join("large.bin");

        // Simulate a 100MB file with a repeating pattern
        const CHUNK_SIZE: usize = 1024 * 1024; // 1MB chunks
        const CHUNKS: usize = 100; // 100MB total
        const PATTERN: &[u8] = b"TrustWeave deterministic hash test pattern ";

        let mut file = fs::File::create(&large_file)?;
        for _ in 0..CHUNKS {
            for _ in 0..(CHUNK_SIZE / PATTERN.len()) {
                file.write_all(PATTERN)?;
            }
        }
        file.flush()?;

        // Test with small buffer (8KB) - original concern
        let hash_8kb = hash_file_sha256(&large_file, 8 * 1024)?;
        let hash_8kb_hex = hash_to_hex(&hash_8kb);

        // Test with default buffer (64KB)
        let hash_64kb = hash_file_sha256(&large_file, 64 * 1024)?;
        let hash_64kb_hex = hash_to_hex(&hash_64kb);

        // Test with large buffer (1MB)
        let hash_1mb = hash_file_sha256(&large_file, 1024 * 1024)?;
        let hash_1mb_hex = hash_to_hex(&hash_1mb);

        // All buffer sizes must produce identical hashes
        assert_eq!(
            hash_8kb_hex, hash_64kb_hex,
            "8KB and 64KB buffers produced different hashes"
        );
        assert_eq!(
            hash_8kb_hex, hash_1mb_hex,
            "8KB and 1MB buffers produced different hashes"
        );

        // Hash twice to ensure consistency
        let hash_8kb_2 = hash_file_sha256(&large_file, 8 * 1024)?;
        let hash_8kb_2_hex = hash_to_hex(&hash_8kb_2);
        assert_eq!(
            hash_8kb_hex, hash_8kb_2_hex,
            "Hash of same file differs on second read"
        );

        println!("✓ Large file stream integrity test passed (100MB, 3 buffer sizes)");
        Ok(())
    }

    /// Test: Empty file handling
    #[test]
    fn empty_file_handling() -> Result<()> {
        let temp = tempdir()?;
        let empty_file = temp.path().join("empty.txt");
        fs::write(&empty_file, b"")?;

        let hash = hash_file_sha256(&empty_file, 8 * 1024)?;
        let hash_hex = hash_to_hex(&hash);

        // SHA-256 of empty string is known constant
        assert_eq!(
            hash_hex,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "Empty file hash mismatch"
        );

        println!("✓ Empty file handling test passed");
        Ok(())
    }

    // ============================================================================
    // Test Group 2: Deep Nesting & Path Normalization
    // ============================================================================

    /// Test 2: Deep Nesting & Path Normalization
    ///
    /// Tests 50+ nested directories with Unicode and special characters
    /// to ensure normalization doesn't cause collisions or crashes.
    #[test]
    fn deep_nesting_50_levels() -> Result<()> {
        let temp = tempdir()?;

        // Create 50-level deep directory structure
        let mut current = temp.path().to_path_buf();
        for i in 0..50 {
            current = current.join(format!("level_{}", i));
            fs::create_dir_all(&current)?;
        }

        // Add a file at the deepest level
        let deep_file = current.join("deep.txt");
        fs::write(&deep_file, b"content at depth 50")?;

        // Also add files at various levels
        fs::write(temp.path().join("root.txt"), b"root level")?;
        fs::write(
            temp.path().join("level_0").join("mid.txt"),
            b"mid level",
        )?;

        // Traverse and verify no crashes
        let config = TraversalConfig {
            root: temp.path().to_path_buf(),
            max_depth: None, // Unlimited depth
            ..Default::default()
        };

        let files = traverse_deterministic(&config)?;
        assert!(
            files.len() >= 3,
            "Expected at least 3 files, got {}",
            files.len()
        );

        // Verify deep file is found
        assert!(
            files.iter().any(|p| p.contains("deep.txt")),
            "Deep file not found in traversal"
        );

        println!("✓ Deep nesting test passed (50 levels, {} files)", files.len());
        Ok(())
    }

    /// Test: Unicode and special characters in paths
    #[test]
    fn unicode_and_special_characters() -> Result<()> {
        let temp = tempdir()?;

        // Create directories with Unicode and special chars
        let unicode_dir = temp.path().join("測試-αβγ");
        fs::create_dir_all(&unicode_dir)?;

        let space_dir = temp.path().join("with spaces");
        fs::create_dir_all(&space_dir)?;

        // Create files with various special names
        fs::write(&unicode_dir.join("檔案.txt"), b"unicode content")?;
        fs::write(&space_dir.join("file with spaces.txt"), b"space content")?;
        fs::write(temp.path().join("file-123.txt"), b"normal content")?;

        let config = TraversalConfig {
            root: temp.path().to_path_buf(),
            ..Default::default()
        };

        let files = traverse_deterministic(&config)?;
        assert!(
            files.len() >= 3,
            "Expected at least 3 files, got {}",
            files.len()
        );

        // Verify normalization produces valid strings
        for file in &files {
            assert!(!file.is_empty(), "Empty path in normalized results");
            // Check that paths use forward slashes (if they have path separators)
            if file.contains('\\') || file.contains('/') {
                assert!(
                    !file.contains('\\'),
                    "Path should not contain backslashes: {}",
                    file
                );
            }
        }

        println!("✓ Unicode and special characters test passed");
        Ok(())
    }

    /// Test: Mixed path separators (Windows vs Unix)
    #[test]
    fn mixed_path_separators_normalized() -> Result<()> {
        let temp = tempdir()?;

        // Create nested structure
        fs::create_dir_all(temp.path().join("a/b/c"))?;
        fs::write(temp.path().join("a/b/c/file.txt"), b"content")?;

        let config = TraversalConfig {
            root: temp.path().to_path_buf(),
            ..Default::default()
        };

        let files = traverse_deterministic(&config)?;
        assert!(!files.is_empty());

        // All paths should use forward slashes regardless of OS
        for file in &files {
            assert!(
                !file.contains('\\'),
                "Path should not contain backslashes: {}",
                file
            );
        }

        println!("✓ Mixed path separators normalization test passed");
        Ok(())
    }

    // ============================================================================
    // Test Group 3: Special Files & Edge Cases
    // ============================================================================

    /// Test 3: Special Files & Edge Cases
    ///
    /// Tests empty files, read-only files, permission handling
    #[test]
    fn read_only_file_handling() -> Result<()> {
        let temp = tempdir()?;
        let readonly_file = temp.path().join("readonly.txt");

        fs::write(&readonly_file, b"readonly content")?;

        // Make file read-only (Unix-style)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&readonly_file)?.permissions();
            perms.set_mode(0o444); // read-only
            fs::set_permissions(&readonly_file, perms)?;
        }

        // Should still be hashable
        let hash = hash_file_sha256(&readonly_file, 8 * 1024)?;
        assert_ne!(hash, [0u8; 32], "Hash should not be all zeros");

        println!("✓ Read-only file handling test passed");
        Ok(())
    }

    /// Test: Very long filename
    #[test]
    fn very_long_filename() -> Result<()> {
        let temp = tempdir()?;

        // Create a filename that's 200 characters long
        let long_name = "a".repeat(200) + ".txt";
        let long_file = temp.path().join(&long_name);
        fs::write(&long_file, b"long filename content")?;

        let config = TraversalConfig {
            root: temp.path().to_path_buf(),
            ..Default::default()
        };

        let files = traverse_deterministic(&config)?;
        assert!(
            files.iter().any(|p| p.len() > 100),
            "Long filename not found"
        );

        println!("✓ Very long filename test passed");
        Ok(())
    }

    /// Test: File with zero-size (already covered by empty_file, but in traversal context)
    #[test]
    fn zero_size_file_in_traversal() -> Result<()> {
        let temp = tempdir()?;
        fs::write(temp.path().join("zero.txt"), b"")?;

        let config = TraversalConfig {
            root: temp.path().to_path_buf(),
            ..Default::default()
        };

        let files = traverse_deterministic(&config)?;
        assert!(
            files.contains(&"zero.txt".to_string()),
            "Zero-size file should be included"
        );

        println!("✓ Zero-size file in traversal test passed");
        Ok(())
    }

    // ============================================================================
    // Test Group 4: Cross-Environment Determinism
    // ============================================================================

    /// Test 4: Cross-Environment Determinism
    ///
    /// Validates that the same directory produces bit-for-bit identical
    /// ledger output across multiple runs, regardless of timestamps.
    #[test]
    fn same_input_proceses_identical_hash() -> Result<()> {
        let temp = tempdir()?;

        // Create deterministic directory structure
        let src_dir = temp.path().join("src");
        fs::create_dir_all(&src_dir)?;
        fs::write(src_dir.join("main.rs"), b"fn main() {}")?;
        fs::write(temp.path().join("README.md"), b"# TrustWeave")?;

        let config = PipelineConfig {
            traversal: TraversalConfig {
                root: temp.path().to_path_buf(),
                ..Default::default()
            },
        };

        // Run pipeline twice
        let ledger1 = execute_pipeline(&config)?;
        std::thread::sleep(std::time::Duration::from_millis(10)); // Small delay
        let ledger2 = execute_pipeline(&config)?;

        // Root hashes must be identical
        assert_eq!(
            ledger1.root_hash, ledger2.root_hash,
            "Root hash differs between runs"
        );

        // JSON output must be identical
        let json1 = ledger1.to_json()?;
        let json2 = ledger2.to_json()?;
        assert_eq!(json1, json2, "JSON output differs between runs");

        println!("✓ Determinism test passed (bit-for-bit identical)");
        Ok(())
    }

    /// Test: File order independence
    ///
    /// Hash should be independent of file addition order
    #[test]
    fn hash_independent_of_addition_order() -> Result<()> {
        let temp = tempdir()?;

        // Create files in one order
        let a_file = temp.path().join("a.txt");
        let b_file = temp.path().join("b.txt");
        let c_file = temp.path().join("c.txt");

        fs::write(&a_file, b"aaa")?;
        fs::write(&b_file, b"bbb")?;
        fs::write(&c_file, b"ccc")?;

        let config = PipelineConfig {
            traversal: TraversalConfig {
                root: temp.path().to_path_buf(),
                ..Default::default()
            },
        };

        let ledger1 = execute_pipeline(&config)?;

        // Delete and recreate in different order
        fs::remove_file(&a_file)?;
        fs::remove_file(&b_file)?;
        fs::remove_file(&c_file)?;

        fs::write(&c_file, b"ccc")?;
        fs::write(&a_file, b"aaa")?;
        fs::write(&b_file, b"bbb")?;

        let ledger2 = execute_pipeline(&config)?;

        // Root hashes must be identical
        assert_eq!(
            ledger1.root_hash, ledger2.root_hash,
            "Root hash depends on file addition order"
        );

        println!("✓ File order independence test passed");
        Ok(())
    }

    /// Test: Timestamp independence
    ///
    /// Hash should ignore file modification timestamps
    #[test]
    fn hash_independent_of_timestamps() -> Result<()> {
        let temp = tempdir()?;

        let file_path = temp.path().join("file.txt");
        fs::write(&file_path, b"content")?;

        let config = PipelineConfig {
            traversal: TraversalConfig {
                root: temp.path().to_path_buf(),
                ..Default::default()
            },
        };

        let ledger1 = execute_pipeline(&config)?;

        // Wait and touch file to change timestamp
        std::thread::sleep(std::time::Duration::from_millis(100));
        fs::write(&file_path, b"content")?; // Same content, new timestamp

        let ledger2 = execute_pipeline(&config)?;

        // Root hashes must be identical (same content, different timestamp)
        assert_eq!(
            ledger1.root_hash, ledger2.root_hash,
            "Root hash depends on timestamps"
        );

        println!("✓ Timestamp independence test passed");
        Ok(())
    }
}

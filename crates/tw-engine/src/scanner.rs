//! Malware signature scanning backed by YARA-X (pure Rust, no libclang).
//!
//! This module provides static malware detection for both local artifacts and
//! third-party packages. It is compiled only when the `yara-scanner` feature is
//! enabled, so the default engine build stays dependency-light.

use crate::error::EngineError;
use crate::Result;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};
use yara_x::{Compiler, Rules, Scanner};

/// A single rule that matched during a scan.
#[derive(Debug, Clone)]
pub struct RuleMatch {
    /// Rule identifier as written in the YARA source.
    pub rule: String,
    /// Rule `description` metadata, empty when the rule does not define one.
    pub description: String,
}

/// Scan result for a single file
#[derive(Debug, Clone)]
pub struct ScanResult {
    /// File path that was scanned
    pub path: String,
    /// Whether the file matched any YARA rules
    pub detected: bool,
    /// Rules that matched, with their descriptions
    pub matches: Vec<RuleMatch>,
    /// File size in bytes
    pub size: u64,
    /// Scan duration in milliseconds
    pub duration_ms: u64,
}

/// Summary of a batch scan operation
#[derive(Debug, Clone)]
pub struct ScanSummary {
    /// Total files scanned
    pub total_files: usize,
    /// Files with detected threats
    pub threat_count: usize,
    /// Detections only (clean files are counted but not retained)
    pub threats: Vec<ScanResult>,
    /// Total scan duration in milliseconds
    pub total_duration_ms: u64,
}

/// YARA scanner configuration
#[derive(Debug, Clone)]
pub struct ScannerConfig {
    /// Path to a YARA rules file or a directory of `.yar`/`.yara` files
    pub rules_path: String,
    /// Maximum file size to scan (in bytes, default 100MB)
    pub max_file_size: u64,
    /// Scan timeout in seconds (default 30)
    pub timeout_secs: u64,
    /// Whether to scan archives (zip, tar, etc.)
    pub scan_archives: bool,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            rules_path: "yara-rules".to_string(),
            max_file_size: 100 * 1024 * 1024, // 100MB
            timeout_secs: 30,
            scan_archives: false,
        }
    }
}

/// YARA malware scanner
pub struct YaraScanner {
    config: ScannerConfig,
    rules: Rules,
}

impl YaraScanner {
    /// Create a new YARA scanner with the given configuration
    pub fn new(config: ScannerConfig) -> Result<Self> {
        let rules = Self::load_rules(&config.rules_path)?;
        Ok(Self { config, rules })
    }

    /// Compile YARA rules from a file or a directory of rule files.
    fn load_rules(rules_path: &str) -> Result<Rules> {
        let path = Path::new(rules_path);

        if !path.exists() {
            return Err(EngineError::Scan(format!(
                "YARA rules path does not exist: {rules_path}"
            )));
        }

        let mut compiler = Compiler::new();

        if path.is_file() {
            let source = fs::read_to_string(path)
                .map_err(|e| EngineError::Scan(format!("Failed to read YARA rules file: {e}")))?;
            compiler
                .add_source(source.as_str())
                .map_err(|e| EngineError::Scan(format!("Failed to compile YARA rules: {e}")))?;
        } else if path.is_dir() {
            let mut loaded = 0usize;
            let mut entries: Vec<_> = fs::read_dir(path)
                .map_err(|e| EngineError::Scan(format!("Failed to read YARA rules directory: {e}")))?
                .filter_map(|entry| entry.ok())
                .map(|entry| entry.path())
                .collect();
            // Deterministic compilation order keeps rule priority stable.
            entries.sort();

            for file_path in entries {
                if !file_path.is_file() {
                    continue;
                }
                let extension = file_path
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .unwrap_or("");
                if extension != "yar" && extension != "yara" {
                    continue;
                }
                let source = fs::read_to_string(&file_path).map_err(|e| {
                    EngineError::Scan(format!(
                        "Failed to read YARA rules file {}: {e}",
                        file_path.display()
                    ))
                })?;
                // Compile each file in its own namespace so identical rule
                // names across files do not collide.
                let namespace = file_path
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .unwrap_or("default")
                    .to_string();
                compiler
                    .new_namespace(&namespace)
                    .add_source(source.as_str())
                    .map_err(|e| {
                        EngineError::Scan(format!(
                            "Failed to compile YARA rules from {}: {e}",
                            file_path.display()
                        ))
                    })?;
                loaded += 1;
            }

            if loaded == 0 {
                return Err(EngineError::Scan(format!(
                    "no .yar or .yara rules found in {}",
                    path.display()
                )));
            }
        }

        Ok(compiler.build())
    }

    /// Scan a single file
    pub fn scan_file(&self, file_path: &Path) -> Result<ScanResult> {
        let start = Instant::now();

        if !file_path.exists() {
            return Err(EngineError::Scan(format!(
                "File does not exist: {}",
                file_path.display()
            )));
        }

        let metadata = fs::metadata(file_path)
            .map_err(|e| EngineError::Scan(format!("Failed to read file metadata: {e}")))?;

        // Oversized inputs are reported as clean-by-policy rather than read.
        if metadata.len() > self.config.max_file_size {
            return Ok(ScanResult {
                path: file_path.display().to_string(),
                detected: false,
                matches: vec![],
                size: metadata.len(),
                duration_ms: start.elapsed().as_millis() as u64,
            });
        }

        let file_content = fs::read(file_path)
            .map_err(|e| EngineError::Scan(format!("Failed to read file: {e}")))?;

        let mut scanner = Scanner::new(&self.rules);
        scanner.set_timeout(Duration::from_secs(self.config.timeout_secs));

        let results = scanner
            .scan(&file_content)
            .map_err(|e| EngineError::Scan(format!("YARA scan failed: {e}")))?;

        let mut matches = Vec::new();
        for rule in results.matching_rules() {
            let description = rule
                .metadata()
                .find_map(|(key, value)| match (key, value) {
                    ("description", yara_x::MetaValue::String(text)) => Some(text.to_string()),
                    _ => None,
                })
                .unwrap_or_default();
            matches.push(RuleMatch {
                rule: rule.identifier().to_string(),
                description,
            });
        }

        Ok(ScanResult {
            path: file_path.display().to_string(),
            detected: !matches.is_empty(),
            matches,
            size: metadata.len(),
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }

    /// Scan a directory recursively
    pub fn scan_directory(&self, dir_path: &Path) -> Result<ScanSummary> {
        let start = Instant::now();
        let mut total_files = 0;
        let mut threats = Vec::new();

        for entry in walkdir::WalkDir::new(dir_path)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            match self.scan_file(path) {
                Ok(result) => {
                    total_files += 1;
                    if result.detected {
                        threats.push(result);
                    }
                }
                Err(e) => {
                    eprintln!("Warning: Failed to scan {}: {}", path.display(), e);
                }
            }
        }

        Ok(ScanSummary {
            total_files,
            threat_count: threats.len(),
            threats,
            total_duration_ms: start.elapsed().as_millis() as u64,
        })
    }

    /// Scan a specific binary artifact (e.g., executable, library)
    pub fn scan_artifact(&self, artifact_path: &Path) -> Result<ScanResult> {
        self.scan_file(artifact_path)
    }
}

/// Create a simple malware detection rule set for demonstration
pub fn create_default_rules(output_path: &Path) -> Result<()> {
    let default_rules = r#"
rule Suspicious_Pattern_Base64_Encoded_Shellcode
{
    meta:
        description = "Detects potential base64-encoded shellcode patterns"
        author = "TrustWeave Security Team"
        date = "2026-10-19"
    strings:
        $base64_long = /[A-Za-z0-9+\/]{100,}/
        $shellcode_markers = /\xeb[0-9a-f]{2}/
    condition:
        #base64_long and #shellcode_markers
}

rule Suspicious_Backdoor_Connection_String
{
    meta:
        description = "Detects potential backdoor connection strings"
        author = "TrustWeave Security Team"
        date = "2026-10-19"
    strings:
        $http = "http://" nocase
        $domain = /[a-z0-9\-]+\.[a-z]{2,}/ nocase
        $port = /:[0-9]{4,5}/
    condition:
        #http and #domain and #port
}

rule Suspicious_Process_Injection_Patterns
{
    meta:
        description = "Detects patterns associated with process injection"
        author = "TrustWeave Security Team"
        date = "2026-10-19"
    strings:
        $virtualalloc = "VirtualAlloc" nocase
        $writeprocessmemory = "WriteProcessMemory" nocase
        $createremotethread = "CreateRemoteThread" nocase
    condition:
        2 of them
}

rule Suspicious_Crypto_Miner_Patterns
{
    meta:
        description = "Detects potential cryptocurrency mining patterns"
        author = "TrustWeave Security Team"
        date = "2026-10-19"
    strings:
        $stratum = "stratum+" nocase
        $miner = "miner" nocase
        $pool = "pool" nocase
    condition:
        #stratum and #miner and #pool
}

rule Suspicious_Ransomware_Patterns
{
    meta:
        description = "Detects potential ransomware indicators"
        author = "TrustWeave Security Team"
        date = "2026-10-19"
    strings:
        $encrypt = "encrypt" nocase
        $decrypt = "decrypt" nocase
        $ransom = "ransom" nocase
        $bitcoin = "bitcoin" nocase
    condition:
        3 of them
}
"#;

    fs::write(output_path, default_rules)
        .map_err(|e| EngineError::Scan(format!("Failed to write default YARA rules: {e}")))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_create_default_rules() {
        let temp = tempdir().unwrap();
        let rules_path = temp.path().join("default_rules.yar");
        create_default_rules(&rules_path).unwrap();
        assert!(rules_path.exists());
    }

    #[test]
    fn test_scanner_creation() {
        let temp = tempdir().unwrap();
        let rules_path = temp.path().join("test_rules.yar");
        create_default_rules(&rules_path).unwrap();

        let config = ScannerConfig {
            rules_path: rules_path.to_str().unwrap().to_string(),
            ..Default::default()
        };

        let scanner = YaraScanner::new(config);
        assert!(scanner.is_ok());
    }

    #[test]
    fn test_scan_clean_file() {
        let temp = tempdir().unwrap();
        let rules_path = temp.path().join("test_rules.yar");
        create_default_rules(&rules_path).unwrap();

        let test_file = temp.path().join("clean.txt");
        fs::write(&test_file, "This is a clean file with no malicious content").unwrap();

        let config = ScannerConfig {
            rules_path: rules_path.to_str().unwrap().to_string(),
            ..Default::default()
        };

        let scanner = YaraScanner::new(config).unwrap();
        let result = scanner.scan_file(&test_file).unwrap();

        assert!(!result.detected);
        assert!(result.matches.is_empty());
    }

    #[test]
    fn test_scan_suspicious_file() {
        let temp = tempdir().unwrap();
        let rules_path = temp.path().join("test_rules.yar");
        create_default_rules(&rules_path).unwrap();

        let test_file = temp.path().join("suspicious.txt");
        fs::write(
            &test_file,
            "This file contains VirtualAlloc and WriteProcessMemory patterns",
        )
        .unwrap();

        let config = ScannerConfig {
            rules_path: rules_path.to_str().unwrap().to_string(),
            ..Default::default()
        };

        let scanner = YaraScanner::new(config).unwrap();
        let result = scanner.scan_file(&test_file).unwrap();

        assert!(result.detected);
        assert!(!result.matches.is_empty());
    }

    #[test]
    fn test_scan_directory() {
        let temp = tempdir().unwrap();
        let rules_path = temp.path().join("test_rules.yar");
        create_default_rules(&rules_path).unwrap();

        // Keep the rules file outside the scanned tree: the default rules name
        // the very strings they detect, so the rules file would match itself.
        let samples = temp.path().join("samples");
        fs::create_dir_all(&samples).unwrap();
        fs::write(samples.join("clean.txt"), "Clean content").unwrap();
        fs::write(samples.join("suspicious.txt"), "VirtualAlloc WriteProcessMemory").unwrap();

        let config = ScannerConfig {
            rules_path: rules_path.to_str().unwrap().to_string(),
            ..Default::default()
        };

        let scanner = YaraScanner::new(config).unwrap();
        let summary = scanner.scan_directory(&samples).unwrap();

        assert_eq!(summary.total_files, 2);
        assert_eq!(summary.threat_count, 1);
        assert_eq!(summary.threats.len(), 1);
    }
}

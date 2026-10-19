//! TrustWeave Engine CLI - Test harness for Phase 1

use std::collections::BTreeMap;
use std::path::PathBuf;
use tw_engine::bundle::{create_bundle, generate_signing_seed, verify_bundle, write_public_key};
use tw_engine::pipeline::{execute_pipeline, PipelineConfig};
use tw_engine::traversal::TraversalConfig;

#[cfg(feature = "yara-scanner")]
use tw_engine::scanner::{create_default_rules, ScannerConfig, YaraScanner};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::fmt()
        .with_env_filter("tw_engine=debug,info")
        .init();

    let mut args = std::env::args().skip(1);
    let command = args.next();
    match command.as_deref() {
        Some("keygen") => {
            let options = parse_options(args.collect())?;
            let seed = required_path(&options, "--seed")?;
            let public = required_path(&options, "--public")?;
            if seed == public {
                return Err("signing seed and public key must use different files".into());
            }
            if seed.exists() || public.exists() {
                return Err("refusing to overwrite an existing key file".into());
            }
            generate_signing_seed(&seed)?;
            write_public_key(&seed, &public)?;
            println!("Created Ed25519 key pair. Protect the seed file; it can sign bundles.");
            println!("Public key: {}", public.display());
        }
        Some("bundle") => {
            let options = parse_options(args.collect())?;
            let root = required_path(&options, "--root")?;
            let policy = required_path(&options, "--policy")?;
            let proof = required_path(&options, "--proof")?;
            let artifact = required_path(&options, "--artifact")?;
            let seed = required_path(&options, "--seed")?;
            let output = required_path(&options, "--output")?;
            let ledger = scan(&root)?;
            let summary = create_bundle(&ledger, &policy, &proof, &artifact, &seed, &output)?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
            println!("Signed provenance bundle: {}", output.display());
        }
        Some("verify") => {
            let options = parse_options(args.collect())?;
            let bundle = required_path(&options, "--bundle")?;
            let public = required_path(&options, "--trusted-key")?;
            let artifact = required_path(&options, "--artifact")?;
            let summary = verify_bundle(&bundle, &public, &artifact)?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
            println!("Bundle signature and artifact binding verified.");
        }
        #[cfg(feature = "yara-scanner")]
        Some("scan") => {
            let options = parse_options(args.collect())?;
            let target = required_path(&options, "--target")?;
            let rules_path = options
                .get("--rules")
                .and_then(|p| p.to_str())
                .unwrap_or("yara-rules")
                .to_string();

            let config = ScannerConfig {
                rules_path,
                ..Default::default()
            };

            // Create default rules if they don't exist
            let rules_file = PathBuf::from(&config.rules_path);
            if !rules_file.exists() {
                println!("Creating default YARA rules at: {}", config.rules_path);
                create_default_rules(&rules_file)?;
            }

            let scanner = YaraScanner::new(config)?;
            println!("TrustWeave Scanner v{}", tw_engine::VERSION);
            println!("Scanning: {}", target.display());

            if target.is_file() {
                let result = scanner.scan_file(&target)?;
                println!("\nScan result for: {}", result.path);
                println!("Detected: {}", result.detected);
                println!("Duration: {}ms", result.duration_ms);
                if result.detected {
                    println!("Matched rules:");
                    for rule in &result.matches {
                        println!("  - {} ({})", rule.rule, rule.description);
                    }
                }
            } else if target.is_dir() {
                let summary = scanner.scan_directory(&target)?;
                println!("\nScan summary:");
                println!("Total files scanned: {}", summary.total_files);
                println!("Threats detected: {}", summary.threat_count);
                println!("Total duration: {}ms", summary.total_duration_ms);

                if summary.threat_count > 0 {
                    println!("\nDetected threats:");
                    for result in &summary.threats {
                        let names: Vec<&str> =
                            result.matches.iter().map(|m| m.rule.as_str()).collect();
                        println!("  - {} matched: {}", result.path, names.join(", "));
                    }
                }
            }
        }
        #[cfg(not(feature = "yara-scanner"))]
        Some("scan") => {
            return Err("YARA scanner feature is not enabled. Build with: cargo build --features yara-scanner".into());
        }
        Some("--help") | Some("-h") | Some("help") => print_usage(),
        Some(command) if command.starts_with('-') => {
            return Err(format!("unknown command: {command}").into());
        }
        command => {
            let target_dir = command.unwrap_or(".");
            let target_path = PathBuf::from(&target_dir);
            println!("TrustWeave Engine v{}", tw_engine::VERSION);
            println!("Phase 1: Deterministic Ingestion Layer\n");
            println!("Scanning directory: {:?}", target_path);
            let ledger = scan(&target_path)?;
            println!("\nPipeline completed successfully");
            println!("Files processed: {}", ledger.entries.len());
            println!("Global root hash: {}", ledger.root_hash);
            println!("Hash algorithm: {}", ledger.root_hash_algorithm);
            let json_output = ledger.to_json()?;
            let output_path = PathBuf::from("tw-ledger.json");
            std::fs::write(&output_path, json_output)?;
            println!("Ledger written to: {}", output_path.display());
        }
    }

    Ok(())
}

fn scan(
    root: &std::path::Path,
) -> Result<tw_engine::ledger::DependencyLedger, Box<dyn std::error::Error>> {
    let config = PipelineConfig {
        traversal: TraversalConfig {
            root: root.to_path_buf(),
            ..Default::default()
        },
    };
    Ok(execute_pipeline(&config)?)
}

fn parse_options(
    args: Vec<String>,
) -> Result<BTreeMap<String, PathBuf>, Box<dyn std::error::Error>> {
    if args.len() % 2 != 0 {
        return Err("options must be provided as --name value pairs".into());
    }
    let mut options = BTreeMap::new();
    for pair in args.chunks_exact(2) {
        if !pair[0].starts_with("--") {
            return Err(format!("expected an option name, got {}", pair[0]).into());
        }
        if options
            .insert(pair[0].clone(), PathBuf::from(&pair[1]))
            .is_some()
        {
            return Err(format!("duplicate option: {}", pair[0]).into());
        }
    }
    Ok(options)
}

fn required_path(
    options: &BTreeMap<String, PathBuf>,
    name: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    options
        .get(name)
        .cloned()
        .ok_or_else(|| format!("missing required option {name}").into())
}

fn print_usage() {
    println!(
        "TrustWeave Engine v{}\n\
         Usage:\n\
           tw-engine [ROOT]\n\
           tw-engine keygen --seed PATH --public PATH\n\
           tw-engine bundle --root PATH --policy JSON --proof OLEAN --artifact PATH --seed PATH --output FILE.twledger\n\
           tw-engine verify --bundle FILE.twledger --trusted-key PATH --artifact PATH",
        tw_engine::VERSION
    );

    #[cfg(feature = "yara-scanner")]
    println!("\n           tw-engine scan --target PATH [--rules PATH]  (requires --features yara-scanner)");
}

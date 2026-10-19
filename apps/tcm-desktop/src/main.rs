//! TrustWeave Command Matrix desktop shell.
//!
//! Bridges drag-and-drop project drops to the real `tw-engine` pipeline:
//! deterministic ledgers, Merkle-DAG views, dual-track provenance credentials,
//! and (when built with `--features yara-scanner`) YARA-X threat scanning.

use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use tauri::{DragDropEvent, Emitter, Manager, WindowEvent};
use tw_engine::bundle::{
    create_bundle, generate_signing_seed, merkle_levels, merkle_root, write_public_key,
};
use tw_engine::hasher::hash_to_hex;
use tw_engine::ledger::DependencyLedger;
use tw_engine::pipeline::{execute_pipeline, PipelineConfig};
use tw_engine::traversal::TraversalConfig;

/// Upper bound on Merkle leaves returned to the canvas, to keep IPC payloads
/// bounded on very large trees. The reported Merkle root is always the real,
/// full-tree root regardless of this rendering cap.
const MERKLE_VIEW_LEAF_LIMIT: usize = 512;

#[derive(Serialize)]
struct EngineCapabilities {
    version: String,
    scanner_linked: bool,
}

#[derive(Serialize)]
struct InventorySummary {
    path: String,
    file_count: usize,
    total_bytes: u64,
    ledger_root_hash: String,
    merkle_root: String,
}

#[derive(Serialize)]
struct MerkleView {
    leaf_paths: Vec<String>,
    levels: Vec<Vec<String>>,
    subtree_root: String,
    merkle_root: String,
    total_leaves: usize,
    truncated: bool,
}

#[derive(Serialize)]
struct CredentialReport {
    /// `signed` for a signed `.twledger`, `unsigned` for a ledger credential.
    kind: String,
    output_path: String,
    /// Copied to the clipboard: provenance root when signed, Merkle root when not.
    hash: String,
    reason: Option<String>,
    provenance_root: Option<String>,
    signer_public_key: Option<String>,
    artifact_sha256: Option<String>,
    entry_count: usize,
    total_bytes: u64,
}

#[derive(Serialize)]
struct RuleHit {
    rule: String,
    description: String,
}

#[derive(Serialize)]
struct ScanThreat {
    path: String,
    size: u64,
    rules: Vec<RuleHit>,
}

#[derive(Serialize)]
struct ScanReport {
    target: String,
    is_directory: bool,
    rules_path: String,
    total_files: usize,
    threat_count: usize,
    duration_ms: u64,
    /// `SECURE` when clean, `THREAT` when at least one rule matched.
    verdict: String,
    threats: Vec<ScanThreat>,
}

fn load_ledger(root: &Path) -> Result<DependencyLedger, String> {
    if !root.is_dir() {
        return Err(format!("Not a directory: {}", root.display()));
    }
    execute_pipeline(&PipelineConfig {
        traversal: TraversalConfig {
            root: root.to_path_buf(),
            ..Default::default()
        },
    })
    .map_err(|error| error.to_string())
}

fn total_bytes(ledger: &DependencyLedger) -> u64 {
    ledger
        .entries
        .values()
        .fold(0_u64, |total, entry| total.saturating_add(entry.size))
}

/// Locate a built executable to bind into a signed bundle.
fn find_artifact(root: &Path) -> Option<PathBuf> {
    for relative in ["dist", "target/release"] {
        let dir = root.join(relative);
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        let mut candidates: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.is_file()
                    && path
                        .extension()
                        .and_then(|ext| ext.to_str())
                        .is_some_and(|ext| ext.eq_ignore_ascii_case("exe"))
            })
            .collect();
        candidates.sort();
        if let Some(first) = candidates.into_iter().next() {
            return Some(first);
        }
    }
    None
}

/// Ensure a persistent Ed25519 signing key exists in the app config directory.
fn ensure_signing_key(config_dir: &Path) -> Result<PathBuf, String> {
    fs::create_dir_all(config_dir).map_err(|error| error.to_string())?;
    let seed = config_dir.join("signer.seed");
    let public = config_dir.join("signer.pub");
    if !seed.exists() {
        generate_signing_seed(&seed).map_err(|error| error.to_string())?;
        write_public_key(&seed, &public).map_err(|error| error.to_string())?;
    } else if !public.exists() {
        write_public_key(&seed, &public).map_err(|error| error.to_string())?;
    }
    Ok(seed)
}

#[tauri::command]
fn engine_capabilities() -> EngineCapabilities {
    EngineCapabilities {
        version: tw_engine::VERSION.to_string(),
        scanner_linked: cfg!(feature = "yara-scanner"),
    }
}

#[tauri::command]
async fn inspect_project(path: String) -> Result<InventorySummary, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let root = PathBuf::from(&path);
        let ledger = load_ledger(&root)?;
        let resolved = root
            .canonicalize()
            .map_err(|error| format!("Could not resolve project path: {error}"))?;
        let source_root = merkle_root(&ledger).map_err(|error| error.to_string())?;
        Ok(InventorySummary {
            path: resolved.display().to_string(),
            file_count: ledger.entries.len(),
            total_bytes: total_bytes(&ledger),
            ledger_root_hash: ledger.root_hash.clone(),
            merkle_root: hash_to_hex(&source_root),
        })
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
async fn build_merkle(path: String) -> Result<MerkleView, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let root = PathBuf::from(&path);
        let ledger = load_ledger(&root)?;
        let full_root = merkle_root(&ledger).map_err(|error| error.to_string())?;
        let total_leaves = ledger.entries.len();

        // The full root is always reported; the rendered subtree is capped.
        let mut view = DependencyLedger::new();
        for entry in ledger.entries.values().take(MERKLE_VIEW_LEAF_LIMIT) {
            view.add_entry(entry.clone());
        }
        let levels = merkle_levels(&view).map_err(|error| error.to_string())?;
        let subtree_root = merkle_root(&view).map_err(|error| error.to_string())?;

        Ok(MerkleView {
            leaf_paths: view.entries.keys().cloned().collect(),
            levels,
            subtree_root: hash_to_hex(&subtree_root),
            merkle_root: hash_to_hex(&full_root),
            total_leaves,
            truncated: total_leaves > MERKLE_VIEW_LEAF_LIMIT,
        })
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
async fn generate_credential(
    app: tauri::AppHandle,
    path: String,
) -> Result<CredentialReport, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let root = PathBuf::from(&path);
        let ledger = load_ledger(&root)?;
        let source_root = merkle_root(&ledger).map_err(|error| error.to_string())?;
        let merkle_hex = hash_to_hex(&source_root);

        let config_dir = app
            .path()
            .app_config_dir()
            .map_err(|error| error.to_string())?;
        let out_dir = config_dir.join("credentials");
        fs::create_dir_all(&out_dir).map_err(|error| error.to_string())?;

        let stem = root
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("project")
            .to_string();
        let short = &merkle_hex[..12];
        let entry_count = ledger.entries.len();
        let bytes = total_bytes(&ledger);
        let ledger_root_hash = ledger.root_hash.clone();

        // Dual track: sign a full bundle when the materials are present.
        let policy = root.join("tw-policy.json");
        let proof = root.join("specs").join("TrustWeave.olean");
        let artifact = find_artifact(&root);
        if policy.is_file() && proof.is_file() {
            if let Some(artifact) = artifact {
                let seed = ensure_signing_key(&config_dir)?;
                let output = out_dir.join(format!("{stem}-{short}.twledger"));
                let summary =
                    create_bundle(&ledger, &policy, &proof, &artifact, &seed, &output)
                        .map_err(|error| error.to_string())?;
                return Ok(CredentialReport {
                    kind: "signed".to_string(),
                    output_path: output.display().to_string(),
                    hash: summary.provenance_root.clone(),
                    reason: None,
                    provenance_root: Some(summary.provenance_root),
                    signer_public_key: Some(summary.signer_public_key),
                    artifact_sha256: Some(summary.artifact_sha256),
                    entry_count,
                    total_bytes: bytes,
                });
            }
        }

        // Unsigned track: a real, self-contained ledger credential.
        let output = out_dir.join(format!("{stem}-{short}.twcred.json"));
        let credential = serde_json::json!({
            "schema": "trustweave.credential.v1",
            "engine_version": tw_engine::VERSION,
            "ledger_root_hash": ledger_root_hash,
            "merkle_root": merkle_hex,
            "entry_count": entry_count,
            "total_bytes": bytes,
            "ledger": ledger,
        });
        fs::write(
            &output,
            serde_json::to_vec_pretty(&credential).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;

        let reason = if !policy.is_file() {
            "tw-policy.json not found in the project"
        } else if !proof.is_file() {
            "specs/TrustWeave.olean not found in the project"
        } else {
            "no built executable found in dist/ or target/release/"
        };

        Ok(CredentialReport {
            kind: "unsigned".to_string(),
            output_path: output.display().to_string(),
            hash: merkle_hex,
            reason: Some(reason.to_string()),
            provenance_root: None,
            signer_public_key: None,
            artifact_sha256: None,
            entry_count,
            total_bytes: bytes,
        })
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
async fn scan_target(
    app: tauri::AppHandle,
    path: String,
    rules: Option<String>,
) -> Result<ScanReport, String> {
    #[cfg(feature = "yara-scanner")]
    {
        tauri::async_runtime::spawn_blocking(move || scan_inner(&app, &path, rules.as_deref()))
            .await
            .map_err(|error| error.to_string())?
    }
    #[cfg(not(feature = "yara-scanner"))]
    {
        let _ = (app, path, rules);
        Err(
            "YARA scanner is not linked in this build. Rebuild with --features yara-scanner."
                .to_string(),
        )
    }
}

#[cfg(feature = "yara-scanner")]
fn scan_inner(
    app: &tauri::AppHandle,
    path: &str,
    rules: Option<&str>,
) -> Result<ScanReport, String> {
    use tw_engine::scanner::{create_default_rules, ScannerConfig, YaraScanner};

    let target = PathBuf::from(path);
    if !target.exists() {
        return Err(format!("Target does not exist: {path}"));
    }

    // Rules: explicit path, project-local `yara-rules`, or a provisioned default.
    let rules_path = if let Some(explicit) = rules {
        PathBuf::from(explicit)
    } else {
        let local = target
            .is_dir()
            .then(|| target.join("yara-rules"))
            .filter(|candidate| candidate.exists());
        match local {
            Some(local) => local,
            None => {
                let config_dir = app
                    .path()
                    .app_config_dir()
                    .map_err(|error| error.to_string())?;
                let dir = config_dir.join("yara-rules");
                fs::create_dir_all(&dir).map_err(|error| error.to_string())?;
                let file = dir.join("default_rules.yar");
                if !file.exists() {
                    create_default_rules(&file).map_err(|error| error.to_string())?;
                }
                file
            }
        }
    };

    let scanner = YaraScanner::new(ScannerConfig {
        rules_path: rules_path.display().to_string(),
        ..Default::default()
    })
    .map_err(|error| error.to_string())?;

    let is_directory = target.is_dir();
    if is_directory {
        let summary = scanner
            .scan_directory(&target)
            .map_err(|error| error.to_string())?;
        Ok(ScanReport {
            target: target.display().to_string(),
            is_directory,
            rules_path: rules_path.display().to_string(),
            total_files: summary.total_files,
            threat_count: summary.threat_count,
            duration_ms: summary.total_duration_ms,
            verdict: verdict(summary.threat_count),
            threats: summary
                .threats
                .into_iter()
                .map(|result| ScanThreat {
                    path: result.path,
                    size: result.size,
                    rules: result
                        .matches
                        .into_iter()
                        .map(|hit| RuleHit {
                            rule: hit.rule,
                            description: hit.description,
                        })
                        .collect(),
                })
                .collect(),
        })
    } else {
        let result = scanner
            .scan_file(&target)
            .map_err(|error| error.to_string())?;
        let detected = result.detected;
        let threats = if detected {
            vec![ScanThreat {
                path: result.path,
                size: result.size,
                rules: result
                    .matches
                    .into_iter()
                    .map(|hit| RuleHit {
                        rule: hit.rule,
                        description: hit.description,
                    })
                    .collect(),
            }]
        } else {
            Vec::new()
        };
        Ok(ScanReport {
            target: target.display().to_string(),
            is_directory,
            rules_path: rules_path.display().to_string(),
            total_files: 1,
            threat_count: usize::from(detected),
            duration_ms: result.duration_ms,
            verdict: verdict(usize::from(detected)),
            threats,
        })
    }
}

#[cfg(feature = "yara-scanner")]
fn verdict(threat_count: usize) -> String {
    if threat_count == 0 {
        "SECURE".to_string()
    } else {
        "THREAT".to_string()
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
fn main() {
    tauri::Builder::default()
        .on_window_event(|window, event| {
            if let WindowEvent::DragDrop(DragDropEvent::Drop { paths, .. }) = event {
                let paths: Vec<String> = paths
                    .iter()
                    .map(|path| path.to_string_lossy().into_owned())
                    .collect();
                if let Err(error) = window.emit("vault-drop", paths) {
                    eprintln!("Could not deliver dropped paths to the TCM window: {error}");
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            engine_capabilities,
            inspect_project,
            build_merkle,
            generate_credential,
            scan_target
        ])
        .run(tauri::generate_context!())
        .expect("error while running TrustWeave Command Matrix");
}

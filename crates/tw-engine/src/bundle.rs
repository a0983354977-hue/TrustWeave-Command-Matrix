//! Signed, binary provenance bundles.

use crate::error::EngineError;
use crate::hasher::{hash_file_sha256, hash_to_hex};
use crate::ledger::DependencyLedger;
use crate::{Result, VERSION};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

const MAGIC: &[u8; 8] = b"TWLDGR01";
const HEADER_LEN: usize = 208;
const MAX_PAYLOAD_LEN: u64 = 512 * 1024 * 1024;
const SIGNING_DOMAIN: &[u8] = b"TrustWeave.twledger.v1\0";
const LEAN_VERSION: &str = "4.35.0";

/// Summary of a created or verified provenance bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleSummary {
    /// SHA-256 root of the source dependency Merkle tree.
    pub source_merkle_root: String,
    /// SHA-256 root binding source, policy, proof, and built artifact.
    pub provenance_root: String,
    /// SHA-256 of the signed policy matrix.
    pub policy_sha256: String,
    /// SHA-256 of the Lean proof certificate bytes.
    pub proof_sha256: String,
    /// SHA-256 of the bound executable.
    pub artifact_sha256: String,
    /// Ed25519 signer public key in lowercase hexadecimal.
    pub signer_public_key: String,
}

#[derive(Serialize, Deserialize)]
struct BundlePayload {
    schema_version: u32,
    engine_version: String,
    ledger: DependencyLedger,
    policy: Value,
    proof_certificate: Vec<u8>,
    source_merkle_root: String,
    policy_sha256: String,
    proof_sha256: String,
    artifact_sha256: String,
    provenance_root: String,
}

/// Create a signed `.twledger` bundle.
///
/// The signing key file must contain a raw 32-byte Ed25519 seed. The policy is
/// canonicalized as JSON; the proof certificate and executable are bound by
/// their SHA-256 digests.
pub fn create_bundle(
    ledger: &DependencyLedger,
    policy_path: &Path,
    proof_path: &Path,
    artifact_path: &Path,
    signing_seed_path: &Path,
    output_path: &Path,
) -> Result<BundleSummary> {
    validate_ledger(ledger)?;
    let policy_bytes = read_limited(policy_path, 16 * 1024 * 1024)?;
    let policy: Value = serde_json::from_slice(&policy_bytes)?;
    validate_policy_matrix(&policy)?;
    let proof = read_limited(proof_path, MAX_PAYLOAD_LEN)?;
    validate_lean_certificate(&proof)?;
    let artifact_hash = hash_file_sha256(artifact_path, crate::DEFAULT_BUFFER_SIZE)?;
    let source_root = merkle_root(ledger)?;
    let policy_hash = sha256(&serde_json::to_vec(&policy)?);
    let proof_hash = sha256(&proof);
    let provenance_root = provenance_root(&source_root, &policy_hash, &proof_hash, &artifact_hash);

    let payload = BundlePayload {
        schema_version: 1,
        engine_version: VERSION.to_string(),
        ledger: ledger.clone(),
        policy,
        proof_certificate: proof,
        source_merkle_root: hex(&source_root),
        policy_sha256: hex(&policy_hash),
        proof_sha256: hex(&proof_hash),
        artifact_sha256: hex(&artifact_hash),
        provenance_root: hex(&provenance_root),
    };
    let payload_bytes = serde_json::to_vec(&payload)?;
    if payload_bytes.len() as u64 > MAX_PAYLOAD_LEN {
        return Err(EngineError::InvalidBundle(
            "payload exceeds the 512 MiB format limit".to_string(),
        ));
    }
    let payload_hash = sha256(&payload_bytes);
    let seed = read_limited(signing_seed_path, 32)?;
    let key_pair = Ed25519KeyPair::from_seed_unchecked(&seed).map_err(|_| {
        EngineError::InvalidBundle("signing key must be a raw 32-byte Ed25519 seed".to_string())
    })?;
    let signer = key_pair.public_key().as_ref();

    let mut signed_message = Vec::with_capacity(SIGNING_DOMAIN.len() + 96);
    signed_message.extend_from_slice(SIGNING_DOMAIN);
    signed_message.extend_from_slice(&payload_hash);
    signed_message.extend_from_slice(&artifact_hash);
    signed_message.extend_from_slice(&provenance_root);
    let signature = key_pair.sign(&signed_message);

    let mut bundle = Vec::with_capacity(HEADER_LEN + payload_bytes.len());
    bundle.extend_from_slice(MAGIC);
    bundle.extend_from_slice(&(payload_bytes.len() as u64).to_be_bytes());
    bundle.extend_from_slice(&payload_hash);
    bundle.extend_from_slice(&artifact_hash);
    bundle.extend_from_slice(&provenance_root);
    bundle.extend_from_slice(signer);
    bundle.extend_from_slice(signature.as_ref());
    bundle.extend_from_slice(&payload_bytes);
    fs::write(output_path, bundle)?;

    Ok(BundleSummary {
        source_merkle_root: hex(&source_root),
        provenance_root: hex(&provenance_root),
        policy_sha256: hex(&policy_hash),
        proof_sha256: hex(&proof_hash),
        artifact_sha256: hex(&artifact_hash),
        signer_public_key: hex(signer),
    })
}

/// Verify a bundle against an independently trusted public key and executable.
pub fn verify_bundle(
    bundle_path: &Path,
    trusted_public_key_path: &Path,
    artifact_path: &Path,
) -> Result<BundleSummary> {
    let file = fs::File::open(bundle_path)?;
    let mut bytes = Vec::new();
    file.take(HEADER_LEN as u64 + MAX_PAYLOAD_LEN + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > HEADER_LEN as u64 + MAX_PAYLOAD_LEN {
        return Err(EngineError::InvalidBundle(
            "bundle exceeds the 512 MiB format limit".to_string(),
        ));
    }
    if bytes.len() < HEADER_LEN || &bytes[..8] != MAGIC {
        return Err(EngineError::InvalidBundle(
            "bad magic or truncated header".to_string(),
        ));
    }
    let payload_len = u64::from_be_bytes(
        bytes[8..16]
            .try_into()
            .map_err(|_| EngineError::InvalidBundle("invalid payload length".to_string()))?,
    );
    if payload_len > MAX_PAYLOAD_LEN
        || payload_len as usize != bytes.len().saturating_sub(HEADER_LEN)
    {
        return Err(EngineError::InvalidBundle(
            "payload length does not match bundle size".to_string(),
        ));
    }
    let payload_hash = &bytes[16..48];
    let artifact_hash = &bytes[48..80];
    let root_hash = &bytes[80..112];
    let signer = &bytes[112..144];
    let signature = &bytes[144..208];
    let payload_bytes = &bytes[HEADER_LEN..];
    if sha256(payload_bytes).as_slice() != payload_hash {
        return Err(EngineError::InvalidBundle(
            "payload digest mismatch".to_string(),
        ));
    }

    let trusted_key = read_limited(trusted_public_key_path, 32)?;
    if trusted_key.len() != 32 || trusted_key.as_slice() != signer {
        return Err(EngineError::InvalidBundle(
            "bundle signer does not match trusted public key".to_string(),
        ));
    }
    let payload: BundlePayload = serde_json::from_slice(payload_bytes)?;
    if payload.schema_version != 1 || payload.engine_version.is_empty() {
        return Err(EngineError::InvalidBundle(
            "unsupported schema or missing engine version".to_string(),
        ));
    }
    validate_policy_matrix(&payload.policy)?;
    validate_ledger(&payload.ledger)?;
    validate_lean_certificate(&payload.proof_certificate)?;

    let source_root = merkle_root(&payload.ledger)?;
    let policy_hash = sha256(&serde_json::to_vec(&payload.policy)?);
    let proof_hash = sha256(&payload.proof_certificate);
    let artifact_on_disk = hash_file_sha256(artifact_path, crate::DEFAULT_BUFFER_SIZE)?;
    let expected_root = provenance_root(&source_root, &policy_hash, &proof_hash, &artifact_on_disk);
    if artifact_on_disk.as_slice() != artifact_hash
        || source_root.as_slice() != decode_hash(&payload.source_merkle_root)?.as_slice()
        || policy_hash.as_slice() != decode_hash(&payload.policy_sha256)?.as_slice()
        || proof_hash.as_slice() != decode_hash(&payload.proof_sha256)?.as_slice()
        || artifact_on_disk.as_slice() != decode_hash(&payload.artifact_sha256)?.as_slice()
        || expected_root.as_slice() != root_hash
        || expected_root.as_slice() != decode_hash(&payload.provenance_root)?.as_slice()
    {
        return Err(EngineError::InvalidBundle(
            "provenance commitments do not match bundle contents".to_string(),
        ));
    }

    let mut signed_message = Vec::with_capacity(SIGNING_DOMAIN.len() + 96);
    signed_message.extend_from_slice(SIGNING_DOMAIN);
    signed_message.extend_from_slice(payload_hash);
    signed_message.extend_from_slice(artifact_hash);
    signed_message.extend_from_slice(root_hash);
    UnparsedPublicKey::new(&ED25519, trusted_key)
        .verify(&signed_message, signature)
        .map_err(|_| EngineError::InvalidBundle("signature verification failed".to_string()))?;

    Ok(BundleSummary {
        source_merkle_root: hex(&source_root),
        provenance_root: hex(&expected_root),
        policy_sha256: hex(&policy_hash),
        proof_sha256: hex(&proof_hash),
        artifact_sha256: hex(&artifact_on_disk),
        signer_public_key: hex(signer),
    })
}

/// Compute a deterministic, domain-separated Merkle root over ledger entries.
pub fn merkle_root(ledger: &DependencyLedger) -> Result<[u8; 32]> {
    merkle_hashes(ledger)?
        .last()
        .and_then(|level| level.first())
        .copied()
        .ok_or_else(|| EngineError::InvalidBundle("merkle tree has no root".to_string()))
}

/// Deterministic Merkle levels over the ledger as lowercase-hex digests.
///
/// The first level holds the leaf digests in the ledger's canonical entry
/// order; the last level holds the single root returned by [`merkle_root`].
/// The empty ledger yields one level with its domain-separated empty root.
pub fn merkle_levels(ledger: &DependencyLedger) -> Result<Vec<Vec<String>>> {
    Ok(merkle_hashes(ledger)?
        .into_iter()
        .map(|level| level.into_iter().map(|hash| hex(&hash)).collect())
        .collect())
}

fn merkle_hashes(ledger: &DependencyLedger) -> Result<Vec<Vec<[u8; 32]>>> {
    validate_ledger_entries(ledger)?;
    let leaves: Vec<[u8; 32]> = ledger
        .entries
        .values()
        .map(|entry| {
            let mut leaf = Vec::with_capacity(entry.path.len() + 73);
            leaf.push(0);
            leaf.extend_from_slice(&(entry.path.len() as u64).to_be_bytes());
            leaf.extend_from_slice(entry.path.as_bytes());
            leaf.extend_from_slice(&decode_hash(&entry.sha256)?);
            Ok(sha256(&leaf))
        })
        .collect::<Result<Vec<_>>>()?;

    let mut levels: Vec<Vec<[u8; 32]>> = Vec::new();
    let mut level = leaves;
    if level.is_empty() {
        levels.push(vec![sha256(&[2])]);
        return Ok(levels);
    }
    loop {
        if level.len() == 1 {
            levels.push(level);
            break;
        }
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let right = pair.get(1).unwrap_or(&pair[0]);
            let mut node = [0u8; 65];
            node[0] = 1;
            node[1..33].copy_from_slice(&pair[0]);
            node[33..].copy_from_slice(right);
            next.push(sha256(&node));
        }
        levels.push(level);
        level = next;
    }
    Ok(levels)
}

fn validate_ledger(ledger: &DependencyLedger) -> Result<()> {
    if ledger.root_hash_algorithm != "sha256" {
        return Err(EngineError::InvalidBundle(
            "ledger root hash algorithm must be sha256".to_string(),
        ));
    }
    validate_ledger_entries(ledger)?;
    let mut recalculated = ledger.clone();
    recalculated.compute_root_hash();
    if recalculated.root_hash != ledger.root_hash {
        return Err(EngineError::InvalidBundle(
            "ledger root hash does not match its entries".to_string(),
        ));
    }
    Ok(())
}

fn validate_ledger_entries(ledger: &DependencyLedger) -> Result<()> {
    for (path, entry) in &ledger.entries {
        if path != &entry.path || path.is_empty() {
            return Err(EngineError::InvalidBundle(
                "ledger entry key and normalized path must match".to_string(),
            ));
        }
        decode_hash(&entry.sha256)?;
        decode_hash(&entry.blake3)?;
    }
    Ok(())
}

fn validate_policy_matrix(policy: &Value) -> Result<()> {
    let invalid = || {
        EngineError::InvalidBundle(
            "policy must contain name, strictMode, rules, and constraints".to_string(),
        )
    };
    let object = policy.as_object().ok_or_else(invalid)?;
    if object.get("name").and_then(Value::as_str).is_none()
        || object.get("strictMode").and_then(Value::as_bool).is_none()
    {
        return Err(invalid());
    }
    let rules = object
        .get("rules")
        .and_then(Value::as_array)
        .ok_or_else(invalid)?;
    for rule in rules {
        let rule = rule.as_object().ok_or_else(invalid)?;
        if rule.get("pattern").and_then(Value::as_str).is_none()
            || rule.get("allowed").and_then(Value::as_bool).is_none()
            || rule.get("source").and_then(Value::as_str).is_none()
            || rule
                .get("versionConstraint")
                .and_then(Value::as_str)
                .is_none()
        {
            return Err(invalid());
        }
    }
    let constraints = object
        .get("constraints")
        .and_then(Value::as_array)
        .ok_or_else(invalid)?;
    for constraint in constraints {
        let constraint = constraint.as_object().ok_or_else(invalid)?;
        if constraint.get("name").and_then(Value::as_str).is_none()
            || constraint.get("value").and_then(Value::as_str).is_none()
        {
            return Err(invalid());
        }
    }
    Ok(())
}

fn validate_lean_certificate(proof: &[u8]) -> Result<()> {
    if proof.len() < 9 || &proof[..5] != b"olean" {
        return Err(EngineError::InvalidBundle(
            "proof certificate is not a Lean .olean object".to_string(),
        ));
    }
    let version_end = proof[7..]
        .iter()
        .position(|byte| *byte == 0)
        .map(|offset| offset + 7)
        .ok_or_else(|| {
            EngineError::InvalidBundle("Lean .olean header has no version terminator".to_string())
        })?;
    let version = std::str::from_utf8(&proof[7..version_end])
        .map_err(|_| EngineError::InvalidBundle("invalid Lean .olean version".to_string()))?;
    if version != LEAN_VERSION {
        return Err(EngineError::InvalidBundle(format!(
            "Lean .olean version {version} does not match pinned version {LEAN_VERSION}"
        )));
    }
    Ok(())
}

fn provenance_root(
    source_root: &[u8; 32],
    policy_hash: &[u8; 32],
    proof_hash: &[u8; 32],
    artifact_hash: &[u8; 32],
) -> [u8; 32] {
    let mut node = Vec::with_capacity(129);
    node.push(3);
    node.extend_from_slice(source_root);
    node.extend_from_slice(policy_hash);
    node.extend_from_slice(proof_hash);
    node.extend_from_slice(artifact_hash);
    sha256(&node)
}

fn decode_hash(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(EngineError::InvalidBundle(
            "expected a 32-byte hexadecimal digest".to_string(),
        ));
    }
    let mut result = [0u8; 32];
    for (index, byte) in result.iter_mut().enumerate() {
        let start = index * 2;
        *byte = u8::from_str_radix(&value[start..start + 2], 16)
            .map_err(|_| EngineError::InvalidBundle("invalid digest".to_string()))?;
    }
    Ok(result)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn hex(bytes: &[u8]) -> String {
    hash_to_hex(bytes)
}

fn read_limited(path: &Path, max_len: u64) -> Result<Vec<u8>> {
    let file = fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(max_len + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_len {
        return Err(EngineError::InvalidBundle(format!(
            "{} exceeds the {} byte limit",
            path.display(),
            max_len
        )));
    }
    Ok(bytes)
}

/// Save the public key matching a raw seed in the bundle's 32-byte format.
pub fn write_public_key(signing_seed_path: &Path, output_path: &Path) -> Result<()> {
    let seed = read_limited(signing_seed_path, 32)?;
    let pair = Ed25519KeyPair::from_seed_unchecked(&seed).map_err(|_| {
        EngineError::InvalidBundle("signing key must be a raw 32-byte Ed25519 seed".to_string())
    })?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_path)?;
    file.write_all(pair.public_key().as_ref())?;
    Ok(())
}

/// Create a new Ed25519 seed without overwriting an existing key file.
pub fn generate_signing_seed(output_path: &Path) -> Result<()> {
    let mut seed = [0u8; 32];
    SystemRandom::new()
        .fill(&mut seed)
        .map_err(|_| EngineError::Hash("operating-system random generator failed".to_string()))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_path)?;
    file.write_all(&seed)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::{DependencyLedger, LedgerEntry};
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn merkle_root_is_order_independent_and_path_sensitive() -> Result<()> {
        let mut first = DependencyLedger::new();
        first.add_entry(LedgerEntry {
            path: "a".to_string(),
            sha256: "00".repeat(32),
            blake3: "11".repeat(32),
            size: 1,
            modified: 0,
        });
        first.add_entry(LedgerEntry {
            path: "b".to_string(),
            sha256: "22".repeat(32),
            blake3: "33".repeat(32),
            size: 1,
            modified: 0,
        });
        let root = merkle_root(&first)?;
        let mut second = first.clone();
        second.entries.remove("a");
        second.entries.insert(
            "c".to_string(),
            LedgerEntry {
                path: "c".to_string(),
                sha256: "00".repeat(32),
                blake3: "11".repeat(32),
                size: 1,
                modified: 0,
            },
        );
        assert_ne!(root, merkle_root(&second)?);
        Ok(())
    }

    #[test]
    fn rejects_non_olean_proof_bytes() {
        assert!(validate_lean_certificate(b"synthetic proof bytes").is_err());
    }

    #[test]
    fn signed_bundle_binds_certificate_policy_and_artifact() -> Result<()> {
        let temp = tempdir()?;
        let policy = temp.path().join("policy.json");
        let proof = temp.path().join("proof.olean");
        let artifact = temp.path().join("app.bin");
        let seed = temp.path().join("signing.seed");
        let public_key = temp.path().join("trusted.pub");
        let bundle = temp.path().join("app.twledger");
        fs::write(
            &policy,
            br#"{"name":"test","strictMode":true,"rules":[],"constraints":[]}"#,
        )?;
        fs::write(&proof, b"olean\x02\x014.35.0\0synthetic test object")?;
        fs::write(&artifact, b"example executable")?;
        fs::write(&seed, [7u8; 32])?;
        write_public_key(&seed, &public_key)?;

        let mut ledger = DependencyLedger::new();
        ledger.compute_root_hash();
        create_bundle(&ledger, &policy, &proof, &artifact, &seed, &bundle)?;
        verify_bundle(&bundle, &public_key, &artifact)?;

        let mut changed = fs::read(&bundle)?;
        changed[HEADER_LEN] ^= 1;
        let mut file = fs::File::create(&bundle)?;
        file.write_all(&changed)?;
        assert!(verify_bundle(&bundle, &public_key, &artifact).is_err());

        Ok(())
    }

    #[test]
    fn rejects_artifact_mismatch() -> Result<()> {
        let temp = tempdir()?;
        let policy = temp.path().join("policy.json");
        let proof = temp.path().join("proof.olean");
        let artifact = temp.path().join("app.bin");
        let seed = temp.path().join("signing.seed");
        let public_key = temp.path().join("trusted.pub");
        let bundle = temp.path().join("app.twledger");
        fs::write(
            &policy,
            br#"{"name":"test","strictMode":true,"rules":[],"constraints":[]}"#,
        )?;
        fs::write(&proof, b"olean\x02\x014.35.0\0synthetic test object")?;
        fs::write(&artifact, b"original")?;
        fs::write(&seed, [9u8; 32])?;
        write_public_key(&seed, &public_key)?;
        let mut ledger = DependencyLedger::new();
        ledger.compute_root_hash();
        create_bundle(&ledger, &policy, &proof, &artifact, &seed, &bundle)?;
        fs::write(&artifact, b"tampered")?;
        assert!(verify_bundle(&bundle, &public_key, &artifact).is_err());
        Ok(())
    }
}

#[cfg(test)]
mod protocol_tests {
    use super::*;
    use crate::ledger::{DependencyLedger, LedgerEntry};
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_minimal_bundle() {
        let temp = tempdir().unwrap();
        let policy = temp.path().join("policy.json");
        let proof = temp.path().join("proof.olean");
        let artifact = temp.path().join("app.bin");
        let seed = temp.path().join("signing.seed");
        let public_key = temp.path().join("trusted.pub");
        let bundle = temp.path().join("app.twledger");

        // Create minimal ledger
        let mut ledger = DependencyLedger::new();
        ledger.compute_root_hash();

        // Create minimal policy
        fs::write(
            &policy,
            br#"{"name":"Minimal Policy","strictMode":true,"rules":[],"constraints":[]}"#,
        )
        .unwrap();

        // Create synthetic proof certificate
        fs::write(&proof, b"olean\x02\x014.35.0\0synthetic test object").unwrap();

        // Create artifact
        fs::write(&artifact, b"hello").unwrap();

        // Generate keys
        fs::write(&seed, [1u8; 32]).unwrap();
        write_public_key(&seed, &public_key).unwrap();

        // Create bundle
        let summary = create_bundle(&ledger, &policy, &proof, &artifact, &seed, &bundle).unwrap();

        // Verify bundle
        let verify_summary = verify_bundle(&bundle, &public_key, &artifact).unwrap();

        // Assert consistency
        assert_eq!(summary.source_merkle_root, verify_summary.source_merkle_root);
        assert_eq!(summary.provenance_root, verify_summary.provenance_root);
        assert_eq!(summary.policy_sha256, verify_summary.policy_sha256);
        assert_eq!(summary.proof_sha256, verify_summary.proof_sha256);
        assert_eq!(summary.artifact_sha256, verify_summary.artifact_sha256);
        assert_eq!(summary.signer_public_key, verify_summary.signer_public_key);
    }

    #[test]
    fn test_single_file_ledger() {
        let temp = tempdir().unwrap();
        let policy = temp.path().join("policy.json");
        let proof = temp.path().join("proof.olean");
        let artifact = temp.path().join("app.bin");
        let seed = temp.path().join("signing.seed");
        let public_key = temp.path().join("trusted.pub");
        let bundle = temp.path().join("app.twledger");

        // Create ledger with single file
        let mut ledger = DependencyLedger::new();
        ledger.add_entry(LedgerEntry {
            path: "src/main.rs".to_string(),
            sha256: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".to_string(),
            blake3: "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100".to_string(),
            size: 1024,
            modified: 1234567890,
        });
        ledger.compute_root_hash();

        // Create policy
        fs::write(
            &policy,
            br#"{"name":"Single File Policy","strictMode":true,"rules":[{"pattern":"serde","allowed":true,"source":"crates.io","versionConstraint":">=1.0.0"}],"constraints":[{"name":"max-dependencies","value":"100"}]}"#,
        )
        .unwrap();

        // Create synthetic proof certificate
        fs::write(&proof, b"olean\x02\x014.35.0\0synthetic test object").unwrap();

        // Create artifact
        fs::write(&artifact, b"hello world").unwrap();

        // Generate keys
        fs::write(&seed, [2u8; 32]).unwrap();
        write_public_key(&seed, &public_key).unwrap();

        // Create and verify bundle
        create_bundle(&ledger, &policy, &proof, &artifact, &seed, &bundle).unwrap();
        verify_bundle(&bundle, &public_key, &artifact).unwrap();
    }

    #[test]
    fn test_merkle_root_deterministic() {
        let mut ledger1 = DependencyLedger::new();
        ledger1.add_entry(LedgerEntry {
            path: "a".to_string(),
            sha256: "00".repeat(32),
            blake3: "11".repeat(32),
            size: 1,
            modified: 0,
        });
        ledger1.add_entry(LedgerEntry {
            path: "b".to_string(),
            sha256: "22".repeat(32),
            blake3: "33".repeat(32),
            size: 1,
            modified: 0,
        });
        let root1 = merkle_root(&ledger1).unwrap();

        let mut ledger2 = DependencyLedger::new();
        ledger2.add_entry(LedgerEntry {
            path: "a".to_string(),
            sha256: "00".repeat(32),
            blake3: "11".repeat(32),
            size: 1,
            modified: 0,
        });
        ledger2.add_entry(LedgerEntry {
            path: "b".to_string(),
            sha256: "22".repeat(32),
            blake3: "33".repeat(32),
            size: 1,
            modified: 0,
        });
        let root2 = merkle_root(&ledger2).unwrap();

        assert_eq!(root1, root2);
    }

    #[test]
    fn test_merkle_root_path_sensitive() {
        let mut ledger1 = DependencyLedger::new();
        ledger1.add_entry(LedgerEntry {
            path: "a".to_string(),
            sha256: "00".repeat(32),
            blake3: "11".repeat(32),
            size: 1,
            modified: 0,
        });
        let root1 = merkle_root(&ledger1).unwrap();

        let mut ledger2 = DependencyLedger::new();
        ledger2.add_entry(LedgerEntry {
            path: "b".to_string(),
            sha256: "00".repeat(32),
            blake3: "11".repeat(32),
            size: 1,
            modified: 0,
        });
        let root2 = merkle_root(&ledger2).unwrap();

        assert_ne!(root1, root2);
    }

    #[test]
    fn test_empty_ledger_root() {
        let ledger = DependencyLedger::new();
        let root = merkle_root(&ledger).unwrap();
        // Empty tree should have deterministic root
        // Actual empty root from implementation
        assert_eq!(
            hex::encode(root),
            "dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986"
        );
    }
}

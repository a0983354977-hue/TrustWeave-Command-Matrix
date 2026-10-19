//! Deterministic file-system traversal with strict filtering and ordering.
//!
//! The traversal layer walks a root directory, applies a deterministic
//! blacklist, normalizes every path to a cross-platform representation, and
//! returns a sorted list of file paths. Ordering is guaranteed by sorting
//! lexicographically on the normalized path string.

use crate::error::EngineError;
use crate::Result;
use ignore::WalkBuilder;
use std::path::{Path, PathBuf};

/// Configuration for deterministic traversal.
#[derive(Debug, Clone, Default)]
pub struct TraversalConfig {
    /// Root directory to scan.
    pub root: PathBuf,
    /// Buffer size (in bytes) used when hashing file contents.
    pub buffer_size: usize,
    /// Whether to follow symbolic links.
    pub follow_symlinks: bool,
    /// Maximum directory depth (None = unlimited).
    pub max_depth: Option<usize>,
    /// Maximum file size in bytes (None = unlimited).
    pub max_file_size: Option<u64>,
    /// Additional substring patterns to exclude.
    pub extra_excludes: Vec<String>,
}

/// Traverse the root directory and return a deterministic, sorted list of
/// normalized file paths.
///
/// The traversal:
/// - Always sorts paths lexicographically after normalization.
/// - Skips hidden files/directories (VCS metadata, build artifacts).
/// - Respects the `follow_symlinks` flag.
/// - Enforces `max_depth` and `max_file_size` when set.
/// - Rejects any path that escapes the root directory.
pub fn traverse_deterministic(config: &TraversalConfig) -> Result<Vec<String>> {
    if !config.root.is_dir() {
        return Err(EngineError::PathNormalization(format!(
            "root is not a directory: {}",
            config.root.display()
        )));
    }

    let root = canonical_root(&config.root)?;
    let filter_root = root.clone();
    let extra_excludes = config.extra_excludes.clone();

    let mut builder = WalkBuilder::new(&root);
    builder
        .follow_links(config.follow_symlinks)
        .hidden(true)
        .filter_entry(move |entry| {
            // Always keep the root itself so the walker descends into it.
            if entry.path() == filter_root {
                return true;
            }
            // Skip entries that escape the root (symlinks, mount points, etc.).
            if !path_within_root(entry.path(), &filter_root) {
                return false;
            }
            // Apply extra substring excludes.
            let path_str = entry.path().to_string_lossy();
            for pattern in &extra_excludes {
                if path_str.contains(pattern.as_str()) {
                    return false;
                }
            }
            true
        });

    if let Some(depth) = config.max_depth {
        builder.max_depth(Some(depth));
    }

    let mut paths: Vec<String> = Vec::new();
    for entry_result in builder.build() {
        let entry = entry_result.map_err(|err| {
            EngineError::PathNormalization(format!("traversal error: {err}"))
        })?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if let Some(max_size) = config.max_file_size {
            if let Ok(metadata) = entry.metadata() {
                if metadata.len() > max_size {
                    continue;
                }
            }
        }
        let normalized = normalize_path(path, &root)?;
        paths.push(normalized);
    }

    paths.sort();
    paths.dedup();
    Ok(paths)
}

/// Canonicalize the root directory and verify it is a real directory.
fn canonical_root(root: &Path) -> Result<PathBuf> {
    let canonical = root.canonicalize().map_err(|err| {
        EngineError::PathNormalization(format!("cannot canonicalize root: {err}"))
    })?;
    if !canonical.is_dir() {
        return Err(EngineError::PathNormalization(format!(
            "root is not a directory: {}",
            canonical.display()
        )));
    }
    Ok(canonical)
}

/// Verify that `path` is contained within `root`.
fn path_within_root(path: &Path, root: &Path) -> bool {
    path.starts_with(root)
}

/// Normalize a path to a cross-platform, relative representation.
///
/// The returned string uses forward slashes and is relative to `root`.
/// Absolute paths or paths outside `root` are rejected.
fn normalize_path(path: &Path, root: &Path) -> Result<String> {
    if !path_within_root(path, root) {
        return Err(EngineError::PathEscalation(
            path.display().to_string(),
        ));
    }

    let relative = path.strip_prefix(root).map_err(|_| {
        EngineError::PathNormalization(format!(
            "path is not relative to root: {}",
            path.display()
        ))
    })?;

    let normalized: String = relative
        .iter()
        .map(|component| {
            component
                .to_str()
                .unwrap_or_else(|| {
                    // Non-UTF8 component: encode as lossy replacement.
                    std::str::from_utf8(component.as_encoded_bytes()).unwrap_or("\u{FFFD}")
                })
        })
        .collect::<Vec<&str>>()
        .join("/");

    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn make_tree(root: &Path) {
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::write(root.join("src/main.rs"), b"fn main() {}").unwrap();
        fs::write(root.join(".git/config"), b"[core]").unwrap();
        fs::write(root.join("README.md"), b"# Test").unwrap();
    }

    #[test]
    fn traversal_skips_hidden_and_is_sorted() -> Result<()> {
        let temp = tempdir()?;
        make_tree(temp.path());
        let config = TraversalConfig {
            root: temp.path().to_path_buf(),
            ..Default::default()
        };
        let files = traverse_deterministic(&config)?;
        assert!(files.contains(&"src/main.rs".to_string()));
        assert!(!files.iter().any(|p| p.contains(".git")));
        assert!(files.windows(2).all(|w| w[0] <= w[1]));
        Ok(())
    }

    #[test]
    fn traversal_rejects_non_directory_root() -> Result<()> {
        let temp = tempdir()?;
        let file = temp.path().join("file.txt");
        fs::write(&file, b"hello").unwrap();
        let config = TraversalConfig {
            root: file,
            ..Default::default()
        };
        assert!(traverse_deterministic(&config).is_err());
        Ok(())
    }

    #[test]
    fn traversal_respects_max_file_size() -> Result<()> {
        let temp = tempdir()?;
        fs::write(temp.path().join("small.txt"), b"abc").unwrap();
        fs::write(temp.path().join("big.txt"), b"abcdef").unwrap();
        let config = TraversalConfig {
            root: temp.path().to_path_buf(),
            max_file_size: Some(4),
            ..Default::default()
        };
        let files = traverse_deterministic(&config)?;
        assert!(files.contains(&"small.txt".to_string()));
        assert!(!files.iter().any(|p| p == "big.txt"));
        Ok(())
    }
}
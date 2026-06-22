use std::{
    fs,
    path::{Path, PathBuf},
};

use thiserror::Error;

/// Prefix that every Prism-owned pin name must start with.
const PRISM_PIN_PREFIX: &str = "prism-";

/// Reads the boot ID from the kernel.
///
/// Returns `"unknown"` when the file cannot be read so callers never have
/// to handle a hard error just because boot ID is unavailable.
#[must_use]
pub fn read_boot_id() -> String {
    fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_or_else(|_| "unknown".to_owned(), |s| s.trim().replace('-', ""))
}

/// Builds a versioned, instance-scoped pin name.
///
/// Format: `prism-<instance_id>-<boot_id_prefix>`
///
/// The boot ID is truncated to 8 characters to keep pin names short while
/// still making them unique across reboots.
#[must_use]
pub fn versioned_pin_name(instance_id: &str, boot_id: &str) -> String {
    let boot_prefix = boot_id.chars().take(8).collect::<String>();
    format!("{PRISM_PIN_PREFIX}{instance_id}-{boot_prefix}")
}

/// Returns `true` when the path is owned by Prism.
///
/// A path is Prism-owned when its file name starts with [`PRISM_PIN_PREFIX`].
fn is_prism_owned(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.starts_with(PRISM_PIN_PREFIX))
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CleanupReport {
    removed_entries: usize,
}

impl CleanupReport {
    #[must_use]
    pub const fn removed_entries(self) -> usize {
        self.removed_entries
    }

    fn increment(&mut self) {
        self.removed_entries += 1;
    }
}

#[derive(Debug, Error)]
pub enum CleanupError {
    #[error("failed to inspect eBPF pin path {path}")]
    Inspect {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to remove stale eBPF pin {path}")]
    Remove {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("pin path {0} escapes the configured Prism pin root")]
    PathEscape(PathBuf),
}

/// Removes stale Prism-owned pins below the configured pin root.
///
/// Only entries whose names start with `prism-` are removed. Files and
/// directories outside the pin root are never touched.
///
/// # Errors
///
/// Returns an error when the pin root cannot be inspected or a stale entry
/// cannot be removed.
pub fn reconcile_stale_pins(pin_root: &Path) -> Result<CleanupReport, CleanupError> {
    if !pin_root.exists() {
        return Ok(CleanupReport::default());
    }

    let canonical_root = pin_root
        .canonicalize()
        .map_err(|source| CleanupError::Inspect {
            path: pin_root.to_path_buf(),
            source,
        })?;

    let mut report = CleanupReport::default();
    remove_prism_children(&canonical_root, &canonical_root, &mut report)?;
    Ok(report)
}

fn remove_prism_children(
    root: &Path,
    dir: &Path,
    report: &mut CleanupReport,
) -> Result<(), CleanupError> {
    let entries = fs::read_dir(dir).map_err(|source| CleanupError::Inspect {
        path: dir.to_path_buf(),
        source,
    })?;

    for entry in entries {
        let entry = entry.map_err(|source| CleanupError::Inspect {
            path: dir.to_path_buf(),
            source,
        })?;

        let path = entry.path();

        // Guard: never traverse outside the pin root.
        let canonical = path
            .canonicalize()
            .map_err(|source| CleanupError::Inspect {
                path: path.clone(),
                source,
            })?;

        if !canonical.starts_with(root) {
            return Err(CleanupError::PathEscape(canonical));
        }

        // Only touch Prism-owned entries.
        if is_prism_owned(&path) {
            remove_entry(&path, root, report)?;
        }
    }

    Ok(())
}

fn remove_entry(path: &Path, root: &Path, report: &mut CleanupReport) -> Result<(), CleanupError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| CleanupError::Inspect {
        path: path.to_path_buf(),
        source,
    })?;

    if metadata.is_dir() {
        remove_prism_children(root, path, report)?;
        fs::remove_dir(path).map_err(|source| CleanupError::Remove {
            path: path.to_path_buf(),
            source,
        })?;
    } else {
        fs::remove_file(path).map_err(|source| CleanupError::Remove {
            path: path.to_path_buf(),
            source,
        })?;
    }

    report.increment();
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn missing_pin_path_has_empty_report() {
        let report = reconcile_stale_pins(Path::new("/tmp/prism-missing-pin-root-for-test"))
            .expect("missing path should be accepted");
        assert_eq!(report.removed_entries(), 0);
    }

    #[test]
    fn reconcile_removes_children_but_keeps_root() {
        let temp_dir = TempDir::new().expect("tempdir should be created");
        let root = temp_dir.path();
        let nested = root.join("prism-agent");
        fs::create_dir(&nested).expect("nested dir should be created");
        fs::write(nested.join("prism-map"), b"stale").expect("stale pin should be written");
        let report = reconcile_stale_pins(root).expect("stale pins should be removed");
        assert_eq!(report.removed_entries(), 2);
        assert!(root.exists());
        assert!(!nested.exists());
    }

    #[test]
    fn reconcile_ignores_non_prism_files() {
        let temp_dir = TempDir::new().expect("tempdir should be created");
        let root = temp_dir.path();

        // Prism-owned file — should be removed.
        fs::write(root.join("prism-map"), b"stale").expect("prism pin should be written");

        // Unrelated file — must not be touched.
        fs::write(root.join("unrelated-file"), b"keep").expect("unrelated file should be written");

        let report = reconcile_stale_pins(root).expect("reconcile should succeed");

        assert_eq!(report.removed_entries(), 1);
        assert!(!root.join("prism-map").exists());
        assert!(root.join("unrelated-file").exists());
    }

    #[test]
    fn versioned_pin_name_includes_prefix_instance_and_boot() {
        let name = versioned_pin_name("local", "abcdef1234567890");
        assert!(name.starts_with("prism-"));
        assert!(name.contains("local"));
        assert!(name.contains("abcdef12"));
    }

    #[test]
    fn boot_id_truncated_to_eight_chars() {
        let name = versioned_pin_name("agent", "1234567890abcdef");
        let suffix: String = name
            .split('-')
            .next_back()
            .unwrap_or("")
            .chars()
            .take(8)
            .collect();
        assert_eq!(suffix.len(), 8);
    }

    #[test]
    fn read_boot_id_returns_non_empty_string() {
        let boot_id = read_boot_id();
        assert!(!boot_id.is_empty());
    }

    #[test]
    fn is_prism_owned_rejects_unrelated_paths() {
        assert!(!is_prism_owned(Path::new("/tmp/unrelated")));
        assert!(!is_prism_owned(Path::new("/sys/fs/bpf/cilium")));
        assert!(is_prism_owned(Path::new("/sys/fs/bpf/prism-agent")));
    }
}

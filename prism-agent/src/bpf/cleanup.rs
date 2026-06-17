use std::{
    fs,
    path::{Path, PathBuf},
};

use thiserror::Error;

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
}

/// Removes stale Prism-owned pins below the configured pin root.
///
/// # Errors
///
/// Returns an error when the pin root cannot be inspected or a stale entry
/// cannot be removed.
pub fn reconcile_stale_pins(pin_root: &Path) -> Result<CleanupReport, CleanupError> {
    if !pin_root.exists() {
        return Ok(CleanupReport::default());
    }

    let mut report = CleanupReport::default();
    remove_children(pin_root, &mut report)?;
    Ok(report)
}

fn remove_children(dir: &Path, report: &mut CleanupReport) -> Result<(), CleanupError> {
    let entries = fs::read_dir(dir).map_err(|source| CleanupError::Inspect {
        path: dir.to_path_buf(),
        source,
    })?;

    for entry in entries {
        let entry = entry.map_err(|source| CleanupError::Inspect {
            path: dir.to_path_buf(),
            source,
        })?;
        remove_entry(&entry.path(), report)?;
    }

    Ok(())
}

fn remove_entry(path: &Path, report: &mut CleanupReport) -> Result<(), CleanupError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| CleanupError::Inspect {
        path: path.to_path_buf(),
        source,
    })?;

    if metadata.is_dir() {
        remove_children(path, report)?;
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
        let nested = root.join("agent");
        fs::create_dir(&nested).expect("nested dir should be created");
        fs::write(nested.join("map"), b"stale").expect("stale pin should be written");

        let report = reconcile_stale_pins(root).expect("stale pins should be removed");

        assert_eq!(report.removed_entries(), 2);
        assert!(root.exists());
        assert!(!nested.exists());
    }
}

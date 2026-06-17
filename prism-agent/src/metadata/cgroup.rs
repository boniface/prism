use std::path::{Path, PathBuf};

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CgroupVersion {
    V1,
    V2,
}

#[derive(Debug, Error)]
pub enum MetadataError {
    #[error("failed to inspect cgroup root {path}")]
    InspectCgroup {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cgroup v2 is required, detected {detected:?}")]
    UnsupportedCgroupVersion { detected: CgroupVersion },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupDetector {
    root: PathBuf,
}

impl CgroupDetector {
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    #[must_use]
    pub fn system() -> Self {
        Self::new(PathBuf::from("/sys/fs/cgroup"))
    }

    /// Detects whether the configured cgroup root is cgroup v1 or v2.
    ///
    /// # Errors
    ///
    /// Returns an error when the cgroup root cannot be inspected.
    pub fn detect(&self) -> Result<CgroupVersion, MetadataError> {
        if self.root.join("cgroup.controllers").exists() {
            return Ok(CgroupVersion::V2);
        }

        ensure_root_readable(&self.root)?;
        Ok(CgroupVersion::V1)
    }

    /// Verifies that the configured cgroup root uses cgroup v2.
    ///
    /// # Errors
    ///
    /// Returns an error when the cgroup root cannot be inspected or cgroup v1
    /// is detected.
    pub fn ensure_v2(&self) -> Result<(), MetadataError> {
        let detected = self.detect()?;
        if detected == CgroupVersion::V2 {
            return Ok(());
        }

        Err(MetadataError::UnsupportedCgroupVersion { detected })
    }
}

fn ensure_root_readable(root: &Path) -> Result<(), MetadataError> {
    root.metadata()
        .map(|_| ())
        .map_err(|source| MetadataError::InspectCgroup {
            path: root.to_path_buf(),
            source,
        })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn detects_cgroup_v2_from_controllers_file() {
        let temp_dir = TempDir::new().expect("tempdir should be created");
        fs::write(temp_dir.path().join("cgroup.controllers"), b"cpu io")
            .expect("controllers file should be written");
        let detector = CgroupDetector::new(temp_dir.path().to_path_buf());

        let version = detector
            .detect()
            .expect("cgroup version should be detected");

        assert_eq!(version, CgroupVersion::V2);
    }

    #[test]
    fn ensure_v2_rejects_v1_like_root() {
        let temp_dir = TempDir::new().expect("tempdir should be created");
        let detector = CgroupDetector::new(temp_dir.path().to_path_buf());

        let error = detector.ensure_v2().expect_err("v1 root should fail");

        assert!(matches!(
            error,
            MetadataError::UnsupportedCgroupVersion {
                detected: CgroupVersion::V1
            }
        ));
    }
}

use std::{
    collections::HashMap,
    fs, io,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

use crate::metadata::CgroupV2Path;

/// Resolves numeric cgroup v2 IDs (kernfs inode numbers) to their
/// filesystem path by walking the cgroup v2 hierarchy.
///
/// Cgroup v2 IDs surfaced by eBPF helpers such as
/// `bpf_get_current_cgroup_id()` are the inode number of the cgroup's
/// kernfs directory, so resolution is done via `stat()` rather than any
/// dedicated lookup API.
#[derive(Debug, Clone)]
pub struct CgroupPathLookup {
    cgroup_root: PathBuf,
}

impl CgroupPathLookup {
    #[must_use]
    pub fn new(cgroup_root: PathBuf) -> Self {
        Self { cgroup_root }
    }

    #[must_use]
    pub fn system() -> Self {
        Self::new(PathBuf::from("/sys/fs/cgroup"))
    }

    /// Walks the cgroup v2 hierarchy once, returning a map from cgroup ID
    /// (kernfs inode number) to its path.
    ///
    /// # Errors
    ///
    /// Returns an error when the cgroup root cannot be read. Individual
    /// unreadable subdirectories are skipped rather than failing the whole
    /// walk, since cgroups can be removed concurrently while walking.
    pub fn build_map(&self) -> io::Result<HashMap<u64, CgroupV2Path>> {
        let mut map = HashMap::new();
        self.walk(&self.cgroup_root, &mut map)?;
        Ok(map)
    }

    fn walk(&self, dir: &Path, map: &mut HashMap<u64, CgroupV2Path>) -> io::Result<()> {
        let metadata = match fs::metadata(dir) {
            Ok(metadata) => metadata,
            Err(_) => return Ok(()), // race: removed between listing and stat
        };
        if let Some(relative) = self.relative_path(dir) {
            map.insert(metadata.ino(), relative);
        }

        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(_) => return Ok(()),
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let is_dir = entry
                .file_type()
                .map(|file_type| file_type.is_dir())
                .unwrap_or(false);
            if is_dir {
                self.walk(&path, map)?;
            }
        }

        Ok(())
    }

    fn relative_path(&self, dir: &Path) -> Option<CgroupV2Path> {
        let relative = dir.strip_prefix(&self.cgroup_root).ok()?;
        let normalized = if relative.as_os_str().is_empty() {
            "/".to_string()
        } else {
            format!("/{}", relative.display())
        };
        CgroupV2Path::new(&normalized).ok()
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn resolves_nested_cgroup_directories_by_inode() {
        let temp_dir = TempDir::new().expect("tempdir should be created");
        let nested = temp_dir.path().join("system.slice/prism.service");
        fs::create_dir_all(&nested).expect("nested dir should be created");
        let expected_ino = fs::metadata(&nested).expect("metadata should read").ino();

        let lookup = CgroupPathLookup::new(temp_dir.path().to_path_buf());
        let map = lookup.build_map().expect("map should build");

        let resolved = map
            .get(&expected_ino)
            .expect("nested cgroup should resolve");
        assert_eq!(
            resolved.as_path(),
            Path::new("/system.slice/prism.service")
        );
    }

    #[test]
    fn missing_root_returns_empty_map() {
        let lookup = CgroupPathLookup::new(PathBuf::from("/nonexistent-path-for-test"));

        let map = lookup.build_map().expect("missing root should not error");

        assert!(map.is_empty());
    }
}

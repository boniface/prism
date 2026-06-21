use std::{
    collections::HashMap,
    fs,
    path::{Component, Path, PathBuf},
};

use prism_core::ids::CgroupId;
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
    #[error("failed to read process cgroup file {path}")]
    ReadProcessCgroup {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse process cgroup data: {reason}")]
    InvalidProcessCgroup { reason: &'static str },
    #[error("cgroup v2 entry is missing from process cgroup data")]
    MissingCgroupV2Entry,
    #[error("cgroup path escapes configured root: {path}")]
    CgroupPathEscapesRoot { path: PathBuf },
    #[error("failed to inspect cgroup path {path}")]
    InspectCgroupPath {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cgroup identity resolution requires Unix metadata support")]
    UnsupportedPlatform,
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProcessId(u32);

impl ProcessId {
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupV2Path {
    path: PathBuf,
}

impl CgroupV2Path {
    /// Parses a cgroup v2 path from a single `/proc/<pid>/cgroup` line.
    ///
    /// # Errors
    ///
    /// Returns an error when the line is malformed or describes cgroup v1.
    pub fn parse_proc_line(line: &str) -> Result<Self, MetadataError> {
        let mut parts = line.splitn(3, ':');
        let hierarchy = parts.next().ok_or(MetadataError::InvalidProcessCgroup {
            reason: "missing hierarchy",
        })?;
        let controllers = parts.next().ok_or(MetadataError::InvalidProcessCgroup {
            reason: "missing controllers",
        })?;
        let path = parts.next().ok_or(MetadataError::InvalidProcessCgroup {
            reason: "missing cgroup path",
        })?;

        if hierarchy != "0" || !controllers.is_empty() {
            return Err(MetadataError::UnsupportedCgroupVersion {
                detected: CgroupVersion::V1,
            });
        }

        Self::new(path)
    }

    /// Parses the cgroup v2 path from complete `/proc/<pid>/cgroup` contents.
    ///
    /// # Errors
    ///
    /// Returns an error when the data has no cgroup v2 entry or only contains
    /// cgroup v1 entries.
    pub fn parse_proc_contents(contents: &str) -> Result<Self, MetadataError> {
        let mut found_v1 = false;

        for line in contents.lines().filter(|line| !line.is_empty()) {
            match Self::parse_proc_line(line) {
                Ok(path) => return Ok(path),
                Err(MetadataError::UnsupportedCgroupVersion {
                    detected: CgroupVersion::V1,
                }) => found_v1 = true,
                Err(error) => return Err(error),
            }
        }

        if found_v1 {
            return Err(MetadataError::UnsupportedCgroupVersion {
                detected: CgroupVersion::V1,
            });
        }

        Err(MetadataError::MissingCgroupV2Entry)
    }

    /// Creates a normalized cgroup v2 path.
    ///
    /// # Errors
    ///
    /// Returns an error when the path is empty, relative, or attempts to
    /// traverse parent directories.
    pub fn new(path: &str) -> Result<Self, MetadataError> {
        let path = Path::new(path);
        if !path.is_absolute() {
            return Err(MetadataError::InvalidProcessCgroup {
                reason: "cgroup path must be absolute",
            });
        }

        if path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::CurDir | Component::Prefix(_)
            )
        }) {
            return Err(MetadataError::InvalidProcessCgroup {
                reason: "cgroup path must be normalized",
            });
        }

        Ok(Self {
            path: path.to_path_buf(),
        })
    }

    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.path
    }

    fn relative_to_root(&self) -> &Path {
        match self.path.strip_prefix(Path::new("/")) {
            Ok(path) => path,
            Err(_) => self.path.as_path(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessCgroup {
    pid: ProcessId,
    cgroup_id: CgroupId,
    path: CgroupV2Path,
}

impl ProcessCgroup {
    #[must_use]
    pub const fn pid(&self) -> ProcessId {
        self.pid
    }

    #[must_use]
    pub const fn cgroup_id(&self) -> CgroupId {
        self.cgroup_id
    }

    #[must_use]
    pub fn path(&self) -> &CgroupV2Path {
        &self.path
    }
}

#[cfg(unix)]
fn cgroup_id_from_metadata(path: &Path) -> Result<CgroupId, MetadataError> {
    use std::os::unix::fs::MetadataExt;

    path.metadata()
        .map(|metadata| CgroupId::new(metadata.ino()))
        .map_err(|source| MetadataError::InspectCgroupPath {
            path: path.to_path_buf(),
            source,
        })
}

#[cfg(not(unix))]
fn cgroup_id_from_metadata(_path: &Path) -> Result<CgroupId, MetadataError> {
    Err(MetadataError::UnsupportedPlatform)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PidCgroupCache {
    capacity: usize,
    clock: u64,
    entries: HashMap<ProcessId, CacheEntry>,
}

impl PidCgroupCache {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            clock: 0,
            entries: HashMap::with_capacity(capacity),
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    fn get(&mut self, pid: ProcessId) -> Option<ProcessCgroup> {
        let next_clock = self.next_clock();
        let entry = self.entries.get_mut(&pid)?;
        entry.last_used = next_clock;
        Some(entry.value.clone())
    }

    fn insert(&mut self, value: ProcessCgroup) {
        if self.capacity == 0 {
            return;
        }

        let last_used = self.next_clock();
        self.entries
            .insert(value.pid, CacheEntry { value, last_used });
        self.evict_if_needed();
    }

    fn evict_if_needed(&mut self) {
        while self.entries.len() > self.capacity {
            if let Some(pid) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(pid, _)| *pid)
            {
                self.entries.remove(&pid);
            }
        }
    }

    fn next_clock(&mut self) -> u64 {
        self.clock = self.clock.saturating_add(1);
        self.clock
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CacheEntry {
    value: ProcessCgroup,
    last_used: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupIdentityResolver {
    proc_root: PathBuf,
    cgroup_root: PathBuf,
    cache: PidCgroupCache,
}

impl CgroupIdentityResolver {
    #[must_use]
    pub fn new(proc_root: PathBuf, cgroup_root: PathBuf, cache_capacity: usize) -> Self {
        Self {
            proc_root,
            cgroup_root,
            cache: PidCgroupCache::new(cache_capacity),
        }
    }

    #[must_use]
    pub fn system(cache_capacity: usize) -> Self {
        Self::new(
            PathBuf::from("/proc"),
            PathBuf::from("/sys/fs/cgroup"),
            cache_capacity,
        )
    }

    /// Resolves a process ID to a cgroup v2 path and ID.
    ///
    /// # Errors
    ///
    /// Returns an error when `/proc/<pid>/cgroup` cannot be read, is not
    /// cgroup v2, or the matching cgroup directory cannot be inspected.
    pub fn resolve(&mut self, pid: ProcessId) -> Result<ProcessCgroup, MetadataError> {
        if let Some(cgroup) = self.cache.get(pid) {
            return Ok(cgroup);
        }

        let path = self.read_process_cgroup(pid)?;
        let cgroup_id = self.resolve_cgroup_id(&path)?;
        let cgroup = ProcessCgroup {
            pid,
            cgroup_id,
            path,
        };
        self.cache.insert(cgroup.clone());
        Ok(cgroup)
    }

    #[must_use]
    pub fn cached_entries(&self) -> usize {
        self.cache.len()
    }

    fn read_process_cgroup(&self, pid: ProcessId) -> Result<CgroupV2Path, MetadataError> {
        let path = self.proc_root.join(pid.value().to_string()).join("cgroup");
        let contents = fs::read_to_string(&path)
            .map_err(|source| MetadataError::ReadProcessCgroup { path, source })?;

        CgroupV2Path::parse_proc_contents(&contents)
    }

    fn resolve_cgroup_id(&self, path: &CgroupV2Path) -> Result<CgroupId, MetadataError> {
        let full_path = self.cgroup_root.join(path.relative_to_root());
        if !full_path.starts_with(&self.cgroup_root) {
            return Err(MetadataError::CgroupPathEscapesRoot {
                path: path.as_path().to_path_buf(),
            });
        }

        cgroup_id_from_metadata(&full_path)
    }
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
    use std::{
        fs,
        path::{Path, PathBuf},
    };

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

    #[test]
    fn process_id_preserves_value() {
        let pid = ProcessId::new(1234);

        assert_eq!(pid.value(), 1234);
    }

    #[test]
    fn cgroup_v1_process_data_is_rejected() {
        let error = CgroupV2Path::parse_proc_contents("5:cpu,cpuacct:/docker/abc\n")
            .expect_err("cgroup v1 should fail");

        assert!(matches!(
            error,
            MetadataError::UnsupportedCgroupVersion {
                detected: CgroupVersion::V1
            }
        ));
    }

    #[test]
    fn parses_systemd_cgroup_v2_path() {
        let path = parse_path("0::/system.slice/ssh.service\n");

        assert_eq!(path.as_path(), Path::new("/system.slice/ssh.service"));
    }

    #[test]
    fn parses_docker_cgroup_v2_path() {
        let path = parse_path(
            "0::/system.slice/docker-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.scope\n",
        );

        assert_eq!(
            path.as_path(),
            Path::new(
                "/system.slice/docker-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.scope"
            )
        );
    }

    #[test]
    fn parses_containerd_cgroup_v2_path() {
        let path = parse_path(
            "0::/system.slice/containerd.service/kubepods-besteffort-podabc.slice/cri-containerd-deadbeef.scope\n",
        );

        assert_eq!(
            path.as_path(),
            Path::new(
                "/system.slice/containerd.service/kubepods-besteffort-podabc.slice/cri-containerd-deadbeef.scope"
            )
        );
    }

    #[test]
    fn parses_kubernetes_cgroup_v2_path() {
        let path = parse_path(
            "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podabc.slice/cri-containerd-deadbeef.scope\n",
        );

        assert_eq!(
            path.as_path(),
            Path::new(
                "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podabc.slice/cri-containerd-deadbeef.scope"
            )
        );
    }

    #[test]
    fn rejects_relative_cgroup_v2_path() {
        let error = CgroupV2Path::parse_proc_line("0::relative/path")
            .expect_err("relative path should fail");

        assert!(matches!(
            error,
            MetadataError::InvalidProcessCgroup {
                reason: "cgroup path must be absolute"
            }
        ));
    }

    #[test]
    fn resolves_pid_to_cgroup_path_and_id() {
        let fixture = ResolverFixture::new();
        let cgroup_path = Path::new("/system.slice/prism.service");
        fixture.write_pid_cgroup(ProcessId::new(42), cgroup_path);
        fixture.create_cgroup_dir(cgroup_path);
        let mut resolver = fixture.resolver(16);

        let cgroup = resolver
            .resolve(ProcessId::new(42))
            .expect("process cgroup should resolve");

        assert_eq!(cgroup.pid(), ProcessId::new(42));
        assert_ne!(cgroup.cgroup_id(), CgroupId::new(0));
        assert_eq!(cgroup.path().as_path(), cgroup_path);
        assert_eq!(resolver.cached_entries(), 1);
    }

    #[test]
    fn resolver_uses_cached_value_when_proc_file_changes() {
        let fixture = ResolverFixture::new();
        let pid = ProcessId::new(42);
        let first_path = Path::new("/system.slice/first.service");
        let second_path = Path::new("/system.slice/second.service");
        fixture.write_pid_cgroup(pid, first_path);
        fixture.create_cgroup_dir(first_path);
        fixture.create_cgroup_dir(second_path);
        let mut resolver = fixture.resolver(16);

        let first = resolver.resolve(pid).expect("first lookup should resolve");
        fixture.write_pid_cgroup(pid, second_path);
        let second = resolver.resolve(pid).expect("cached lookup should resolve");

        assert_eq!(first, second);
        assert_eq!(second.path().as_path(), first_path);
    }

    #[test]
    fn pid_cache_is_bounded() {
        let fixture = ResolverFixture::new();
        let first = ProcessId::new(1);
        let second = ProcessId::new(2);
        let third = ProcessId::new(3);
        fixture.write_pid_cgroup(first, Path::new("/first"));
        fixture.write_pid_cgroup(second, Path::new("/second"));
        fixture.write_pid_cgroup(third, Path::new("/third"));
        fixture.create_cgroup_dir(Path::new("/first"));
        fixture.create_cgroup_dir(Path::new("/second"));
        fixture.create_cgroup_dir(Path::new("/third"));
        let mut resolver = fixture.resolver(2);

        resolver.resolve(first).expect("first should resolve");
        resolver.resolve(second).expect("second should resolve");
        resolver.resolve(third).expect("third should resolve");

        assert_eq!(resolver.cached_entries(), 2);
    }

    fn parse_path(contents: &str) -> CgroupV2Path {
        CgroupV2Path::parse_proc_contents(contents).expect("cgroup v2 path should parse")
    }

    struct ResolverFixture {
        _temp_dir: TempDir,
        proc_root: PathBuf,
        cgroup_root: PathBuf,
    }

    impl ResolverFixture {
        fn new() -> Self {
            let temp_dir = TempDir::new().expect("tempdir should be created");
            let proc_root = temp_dir.path().join("proc");
            let cgroup_root = temp_dir.path().join("sys/fs/cgroup");
            fs::create_dir_all(&proc_root).expect("proc root should be created");
            fs::create_dir_all(&cgroup_root).expect("cgroup root should be created");

            Self {
                _temp_dir: temp_dir,
                proc_root,
                cgroup_root,
            }
        }

        fn resolver(&self, cache_capacity: usize) -> CgroupIdentityResolver {
            CgroupIdentityResolver::new(
                self.proc_root.clone(),
                self.cgroup_root.clone(),
                cache_capacity,
            )
        }

        fn write_pid_cgroup(&self, pid: ProcessId, path: &Path) {
            let proc_dir = self.proc_root.join(pid.value().to_string());
            fs::create_dir_all(&proc_dir).expect("process proc dir should be created");
            fs::write(proc_dir.join("cgroup"), format!("0::{}\n", path.display()))
                .expect("process cgroup should be written");
        }

        fn create_cgroup_dir(&self, path: &Path) {
            let relative_path = path
                .strip_prefix(Path::new("/"))
                .expect("test cgroup path should be absolute");
            fs::create_dir_all(self.cgroup_root.join(relative_path))
                .expect("cgroup dir should be created");
        }
    }
}

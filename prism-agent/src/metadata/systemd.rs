use std::{
    fmt, fs,
    path::{Path, PathBuf},
};

use async_trait::async_trait;
use prism_core::ids::CgroupId;
use tokio::sync::mpsc;

use crate::metadata::{ContainerMeta, MetadataError, RuntimeEvent, RuntimeProvider};

const DEFAULT_CGROUP_ROOT: &str = "/sys/fs/cgroup";

#[derive(Debug, Clone)]
pub struct SystemdProvider<C = NoopUncloudClient> {
    cgroup_root: PathBuf,
    uncloud_client: C,
}

impl SystemdProvider<NoopUncloudClient> {
    #[must_use]
    pub fn new(cgroup_root: PathBuf) -> Self {
        Self::with_uncloud_client(cgroup_root, NoopUncloudClient)
    }

    #[must_use]
    pub fn system() -> Self {
        Self::new(PathBuf::from(DEFAULT_CGROUP_ROOT))
    }
}

impl<C> SystemdProvider<C>
where
    C: UncloudApi,
{
    #[must_use]
    pub fn with_uncloud_client(cgroup_root: PathBuf, uncloud_client: C) -> Self {
        Self {
            cgroup_root,
            uncloud_client,
        }
    }

    #[must_use]
    pub fn cgroup_root(&self) -> &Path {
        &self.cgroup_root
    }

    /// Resolves metadata from an already-known cgroup v2 path.
    ///
    /// # Errors
    ///
    /// Returns an error when the cgroup path cannot be parsed as a supported
    /// systemd cgroup path or Uncloud enrichment fails unexpectedly.
    pub async fn resolve_path(
        &self,
        cgroup_id: CgroupId,
        cgroup_path: &Path,
    ) -> Result<Option<ContainerMeta>, MetadataError> {
        let unit = SystemdUnitMeta::parse(cgroup_path)?;
        let uncloud = match self.uncloud_client.enrich(&unit).await {
            Ok(meta) => meta,
            Err(MetadataError::UncloudUnavailable { .. }) => None,
            Err(error) => return Err(error),
        };

        Ok(Some(unit.into_container_meta(cgroup_id, uncloud.as_ref())))
    }

    fn find_cgroup_path(&self, cgroup_id: CgroupId) -> Result<Option<PathBuf>, MetadataError> {
        find_cgroup_path_by_id(&self.cgroup_root, &self.cgroup_root, cgroup_id)
    }
}

#[async_trait]
impl<C> RuntimeProvider for SystemdProvider<C>
where
    C: UncloudApi,
{
    async fn resolve(&self, cgroup_id: CgroupId) -> Result<Option<ContainerMeta>, MetadataError> {
        let Some(path) = self.find_cgroup_path(cgroup_id)? else {
            return Ok(None);
        };
        let relative_path = path
            .strip_prefix(&self.cgroup_root)
            .map(|path| Path::new("/").join(path))
            .unwrap_or(path);

        self.resolve_path(cgroup_id, &relative_path).await
    }

    async fn watch_events(&self) -> Result<mpsc::Receiver<RuntimeEvent>, MetadataError> {
        let (_sender, receiver) = mpsc::channel(1);
        Ok(receiver)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemdUnitMeta {
    cgroup_path: PathBuf,
    unit_name: String,
    slice: Option<String>,
    kind: SystemdUnitKind,
}

impl SystemdUnitMeta {
    /// Parses a cgroup v2 path into systemd unit metadata.
    ///
    /// # Errors
    ///
    /// Returns an error when no unit, scope, or slice component can be found.
    pub fn parse(cgroup_path: &Path) -> Result<Self, MetadataError> {
        let components = cgroup_path
            .components()
            .filter_map(|component| component.as_os_str().to_str())
            .filter(|component| !component.is_empty())
            .collect::<Vec<_>>();
        let unit = components
            .iter()
            .rev()
            .find_map(|component| {
                SystemdUnitKind::from_component(component).map(|kind| (*component, kind))
            })
            .ok_or(MetadataError::InvalidSystemdCgroupPath {
                path: cgroup_path.to_path_buf(),
                reason: "missing systemd unit component",
            })?;
        let slice = components
            .iter()
            .find(|component| has_unit_extension(component, "slice"))
            .map(|component| (*component).to_owned());

        Ok(Self {
            cgroup_path: cgroup_path.to_path_buf(),
            unit_name: unit.0.to_owned(),
            slice,
            kind: unit.1,
        })
    }

    #[must_use]
    pub fn cgroup_path(&self) -> &Path {
        &self.cgroup_path
    }

    #[must_use]
    pub fn unit_name(&self) -> &str {
        &self.unit_name
    }

    #[must_use]
    pub fn slice(&self) -> Option<&str> {
        self.slice.as_deref()
    }

    #[must_use]
    pub const fn kind(&self) -> SystemdUnitKind {
        self.kind
    }

    fn into_container_meta(
        self,
        cgroup_id: CgroupId,
        uncloud: Option<&UncloudMeta>,
    ) -> ContainerMeta {
        let namespace = uncloud
            .map(|meta| format!("uncloud:{}", meta.project()))
            .or_else(|| Some("systemd".to_owned()));
        let container_name = uncloud.map_or_else(
            || self.unit_name.clone(),
            |meta| format!("{}:{}", meta.service(), self.unit_name),
        );

        ContainerMeta {
            cgroup_id,
            container_id: self.unit_name,
            container_name,
            namespace,
            pod_name: self.slice,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemdUnitKind {
    Service,
    Scope,
    Slice,
}

impl SystemdUnitKind {
    fn from_component(component: &str) -> Option<Self> {
        if has_unit_extension(component, "service") {
            return Some(Self::Service);
        }
        if has_unit_extension(component, "scope") {
            return Some(Self::Scope);
        }
        if has_unit_extension(component, "slice") {
            return Some(Self::Slice);
        }
        None
    }
}

fn has_unit_extension(component: &str, expected: &str) -> bool {
    Path::new(component)
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case(expected))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UncloudMeta {
    project: String,
    service: String,
}

impl UncloudMeta {
    #[must_use]
    pub fn new(project: impl Into<String>, service: impl Into<String>) -> Self {
        Self {
            project: project.into(),
            service: service.into(),
        }
    }

    #[must_use]
    pub fn project(&self) -> &str {
        &self.project
    }

    #[must_use]
    pub fn service(&self) -> &str {
        &self.service
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct UncloudCredentials {
    endpoint: String,
    token: String,
}

impl UncloudCredentials {
    #[must_use]
    pub fn new(endpoint: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            token: token.into(),
        }
    }

    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }
}

impl fmt::Debug for UncloudCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UncloudCredentials")
            .field("endpoint", &self.endpoint)
            .field("token", &"<redacted>")
            .finish()
    }
}

#[async_trait]
pub trait UncloudApi: Clone + Send + Sync + 'static {
    async fn enrich(&self, unit: &SystemdUnitMeta) -> Result<Option<UncloudMeta>, MetadataError>;
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct NoopUncloudClient;

#[async_trait]
impl UncloudApi for NoopUncloudClient {
    async fn enrich(&self, _unit: &SystemdUnitMeta) -> Result<Option<UncloudMeta>, MetadataError> {
        Ok(None)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfiguredUncloudClient {
    credentials: Option<UncloudCredentials>,
}

impl ConfiguredUncloudClient {
    #[must_use]
    pub const fn new(credentials: Option<UncloudCredentials>) -> Self {
        Self { credentials }
    }
}

#[async_trait]
impl UncloudApi for ConfiguredUncloudClient {
    async fn enrich(&self, _unit: &SystemdUnitMeta) -> Result<Option<UncloudMeta>, MetadataError> {
        if self.credentials.is_some() {
            return Ok(None);
        }

        Err(MetadataError::UncloudUnavailable {
            reason: "Uncloud credentials are not configured",
        })
    }
}

fn find_cgroup_path_by_id(
    root: &Path,
    path: &Path,
    cgroup_id: CgroupId,
) -> Result<Option<PathBuf>, MetadataError> {
    if path_cgroup_id(path)? == Some(cgroup_id) {
        return Ok(Some(path.to_path_buf()));
    }

    let entries = fs::read_dir(path).map_err(|source| MetadataError::InspectCgroupPath {
        path: path.to_path_buf(),
        source,
    })?;

    for entry in entries {
        let entry = entry.map_err(|source| MetadataError::InspectCgroupPath {
            path: path.to_path_buf(),
            source,
        })?;
        let entry_path = entry.path();
        if !entry_path.starts_with(root) {
            continue;
        }
        if entry_path.is_dir()
            && let Some(path) = find_cgroup_path_by_id(root, &entry_path, cgroup_id)?
        {
            return Ok(Some(path));
        }
    }

    Ok(None)
}

fn path_cgroup_id(path: &Path) -> Result<Option<CgroupId>, MetadataError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        path.metadata()
            .map(|metadata| Some(CgroupId::new(metadata.ino())))
            .map_err(|source| MetadataError::InspectCgroupPath {
                path: path.to_path_buf(),
                source,
            })
    }

    #[cfg(not(unix))]
    {
        let _unused = path;
        Err(MetadataError::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        fs,
        sync::{Arc, RwLock as StdRwLock},
    };

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn parses_system_service_path() {
        let meta = SystemdUnitMeta::parse(Path::new("/system.slice/ssh.service"))
            .expect("service path should parse");

        assert_eq!(meta.unit_name(), "ssh.service");
        assert_eq!(meta.slice(), Some("system.slice"));
        assert_eq!(meta.kind(), SystemdUnitKind::Service);
    }

    #[test]
    fn parses_user_session_scope_path() {
        let meta = SystemdUnitMeta::parse(Path::new("/user.slice/user-1000.slice/session-2.scope"))
            .expect("scope path should parse");

        assert_eq!(meta.unit_name(), "session-2.scope");
        assert_eq!(meta.slice(), Some("user.slice"));
        assert_eq!(meta.kind(), SystemdUnitKind::Scope);
    }

    #[test]
    fn parses_machine_slice_scope_path() {
        let meta = SystemdUnitMeta::parse(Path::new("/machine.slice/machine-qemu\\x2dvm.scope"))
            .expect("machine scope should parse");

        assert_eq!(meta.unit_name(), "machine-qemu\\x2dvm.scope");
        assert_eq!(meta.slice(), Some("machine.slice"));
        assert_eq!(meta.kind(), SystemdUnitKind::Scope);
    }

    #[test]
    fn rejects_path_without_systemd_unit() {
        let error = SystemdUnitMeta::parse(Path::new("/kubepods/podabc"))
            .expect_err("non-systemd path should fail");

        assert!(matches!(
            error,
            MetadataError::InvalidSystemdCgroupPath { .. }
        ));
    }

    #[test]
    fn uncloud_credentials_debug_redacts_token() {
        let credentials = UncloudCredentials::new("https://api.uncloud.local", "secret-token");
        let debug = format!("{credentials:?}");

        assert!(debug.contains("https://api.uncloud.local"));
        assert!(!debug.contains("secret-token"));
        assert!(debug.contains("<redacted>"));
    }

    #[tokio::test]
    async fn resolves_systemd_metadata_from_cgroup_id() {
        let fixture = SystemdFixture::new();
        let cgroup_id = fixture.create_cgroup("/system.slice/ssh.service");
        let provider = SystemdProvider::new(fixture.cgroup_root().to_path_buf());

        let meta = provider
            .resolve(cgroup_id)
            .await
            .expect("systemd resolve should succeed")
            .expect("metadata should exist");

        assert_eq!(meta.container_id, "ssh.service");
        assert_eq!(meta.container_name, "ssh.service");
        assert_eq!(meta.namespace.as_deref(), Some("systemd"));
        assert_eq!(meta.pod_name.as_deref(), Some("system.slice"));
    }

    #[tokio::test]
    async fn uncloud_enrichment_is_optional() {
        let fixture = SystemdFixture::new();
        let cgroup_id = fixture.create_cgroup("/system.slice/app.service");
        let client = MockUncloudApi::new()
            .with_meta("app.service", UncloudMeta::new("project-a", "payments-api"));
        let provider =
            SystemdProvider::with_uncloud_client(fixture.cgroup_root().to_path_buf(), client);

        let meta = provider
            .resolve(cgroup_id)
            .await
            .expect("systemd resolve should succeed")
            .expect("metadata should exist");

        assert_eq!(meta.namespace.as_deref(), Some("uncloud:project-a"));
        assert_eq!(meta.container_name, "payments-api:app.service");
    }

    #[derive(Debug)]
    struct SystemdFixture {
        _temp_dir: TempDir,
        cgroup_root: PathBuf,
    }

    impl SystemdFixture {
        fn new() -> Self {
            let temp_dir = TempDir::new().expect("tempdir should be created");
            let cgroup_root = temp_dir.path().join("sys/fs/cgroup");
            fs::create_dir_all(&cgroup_root).expect("cgroup root should be created");

            Self {
                _temp_dir: temp_dir,
                cgroup_root,
            }
        }

        fn cgroup_root(&self) -> &Path {
            &self.cgroup_root
        }

        fn create_cgroup(&self, cgroup_path: &str) -> CgroupId {
            let relative_path = Path::new(cgroup_path)
                .strip_prefix(Path::new("/"))
                .expect("test path should be absolute");
            let path = self.cgroup_root.join(relative_path);
            fs::create_dir_all(&path).expect("cgroup path should be created");
            path_cgroup_id(&path)
                .expect("cgroup ID should resolve")
                .expect("cgroup ID should exist")
        }
    }

    #[derive(Debug, Clone)]
    struct MockUncloudApi {
        by_unit: Arc<StdRwLock<HashMap<String, UncloudMeta>>>,
    }

    impl MockUncloudApi {
        fn new() -> Self {
            Self {
                by_unit: Arc::new(StdRwLock::new(HashMap::new())),
            }
        }

        fn with_meta(self, unit: &str, meta: UncloudMeta) -> Self {
            self.by_unit
                .write()
                .expect("mock Uncloud lock should not be poisoned")
                .insert(unit.to_owned(), meta);
            self
        }
    }

    #[async_trait]
    impl UncloudApi for MockUncloudApi {
        async fn enrich(
            &self,
            unit: &SystemdUnitMeta,
        ) -> Result<Option<UncloudMeta>, MetadataError> {
            Ok(self
                .by_unit
                .read()
                .expect("mock Uncloud lock should not be poisoned")
                .get(unit.unit_name())
                .cloned())
        }
    }
}

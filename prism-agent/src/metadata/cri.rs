use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use async_trait::async_trait;
use prism_core::ids::CgroupId;
use tokio::sync::{RwLock, mpsc};

use crate::metadata::{ContainerMeta, MetadataError, RuntimeEvent, RuntimeProvider};

const DEFAULT_CRI_SOCKET: &str = "/run/containerd/containerd.sock";
const DEFAULT_CGROUP_ROOT: &str = "/sys/fs/cgroup";
const EVENTS_CAPACITY: usize = 64;

#[derive(Debug, Clone)]
pub struct CriProvider<C = CriSocketClient> {
    client: C,
    socket_path: PathBuf,
    cgroup_root: PathBuf,
    index: Arc<RwLock<CriIndex>>,
}

impl CriProvider<CriSocketClient> {
    #[must_use]
    pub fn new(socket_path: PathBuf) -> Self {
        let client = CriSocketClient::new(socket_path.clone());

        Self::with_client(client, socket_path, PathBuf::from(DEFAULT_CGROUP_ROOT))
    }

    #[must_use]
    pub fn default_containerd() -> Self {
        Self::new(PathBuf::from(DEFAULT_CRI_SOCKET))
    }
}

impl<C> CriProvider<C>
where
    C: CriApi,
{
    #[must_use]
    pub fn with_client(client: C, socket_path: PathBuf, cgroup_root: PathBuf) -> Self {
        Self {
            client,
            socket_path,
            cgroup_root,
            index: Arc::new(RwLock::new(CriIndex::default())),
        }
    }

    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Lists CRI pods and containers and rebuilds the metadata index.
    ///
    /// # Errors
    ///
    /// Returns CRI protocol and cgroup metadata errors except socket
    /// unavailability, which is treated as an empty index.
    pub async fn refresh_index(&self) -> Result<(), MetadataError> {
        let pods = match self.client.list_pods().await {
            Ok(pods) => pods,
            Err(MetadataError::CriUnavailable { .. }) => {
                self.index.write().await.clear();
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let containers = self.client.list_containers().await?;
        let pods = pods
            .into_iter()
            .map(|pod| (pod.id.clone(), pod))
            .collect::<HashMap<_, _>>();
        let mut index = CriIndex::with_capacity(containers.len());

        for container in containers
            .iter()
            .filter(|container| container.state == CriContainerState::Running)
        {
            if let Some(meta) = self.container_meta(container, &pods) {
                index.insert(meta);
            }
        }

        *self.index.write().await = index;
        Ok(())
    }

    fn container_meta(
        &self,
        container: &CriContainer,
        pods: &HashMap<String, CriPodSandbox>,
    ) -> Option<ContainerMeta> {
        let cgroup_id = cgroup_id_for_path(&self.cgroup_root, container.cgroup_path())?;
        let pod = pods.get(container.pod_id());

        Some(ContainerMeta {
            cgroup_id,
            container_id: container.id().to_owned(),
            container_name: container.name().to_owned(),
            namespace: pod.map(|pod| pod.namespace().to_owned()),
            pod_name: pod.map(|pod| pod.name().to_owned()),
        })
    }

    async fn handle_event(
        &self,
        event: CriContainerEvent,
        sender: &mpsc::Sender<RuntimeEvent>,
    ) -> Result<(), MetadataError> {
        match event {
            CriContainerEvent::Started(container) => {
                let pods = self
                    .client
                    .list_pods()
                    .await?
                    .into_iter()
                    .map(|pod| (pod.id.clone(), pod))
                    .collect::<HashMap<_, _>>();
                if let Some(meta) = self.container_meta(&container, &pods) {
                    self.index.write().await.insert(meta.clone());
                    let _ignored = sender.send(RuntimeEvent::Started(meta)).await;
                }
            }
            CriContainerEvent::Stopped { container_id } => {
                if let Some(cgroup_id) = self.index.write().await.remove_container(&container_id) {
                    let _ignored = sender.send(RuntimeEvent::Stopped(cgroup_id)).await;
                }
            }
        }

        Ok(())
    }
}

#[async_trait]
impl<C> RuntimeProvider for CriProvider<C>
where
    C: CriApi,
{
    async fn resolve(&self, cgroup_id: CgroupId) -> Result<Option<ContainerMeta>, MetadataError> {
        if let Some(meta) = self.index.read().await.by_cgroup.get(&cgroup_id).cloned() {
            return Ok(Some(meta));
        }

        self.refresh_index().await?;
        Ok(self.index.read().await.by_cgroup.get(&cgroup_id).cloned())
    }

    async fn watch_events(&self) -> Result<mpsc::Receiver<RuntimeEvent>, MetadataError> {
        let (sender, receiver) = mpsc::channel(EVENTS_CAPACITY);
        let mut cri_events = match self.client.watch_events().await {
            Ok(events) => events,
            Err(MetadataError::CriUnavailable { .. }) => return Ok(receiver),
            Err(error) => return Err(error),
        };
        let provider = self.clone();

        tokio::spawn(async move {
            while let Some(event) = cri_events.recv().await {
                if provider.handle_event(event, &sender).await.is_err() {
                    break;
                }
            }
        });

        Ok(receiver)
    }
}

#[async_trait]
pub trait CriApi: Clone + Send + Sync + 'static {
    async fn list_pods(&self) -> Result<Vec<CriPodSandbox>, MetadataError>;

    async fn list_containers(&self) -> Result<Vec<CriContainer>, MetadataError>;

    async fn watch_events(&self) -> Result<mpsc::Receiver<CriContainerEvent>, MetadataError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CriPodSandbox {
    id: String,
    name: String,
    namespace: String,
}

impl CriPodSandbox {
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        namespace: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            namespace: namespace.into(),
        }
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CriContainer {
    id: String,
    name: String,
    pod_id: String,
    cgroup_path: PathBuf,
    state: CriContainerState,
}

impl CriContainer {
    #[must_use]
    pub fn running(
        id: impl Into<String>,
        name: impl Into<String>,
        pod_id: impl Into<String>,
        cgroup_path: PathBuf,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            pod_id: pod_id.into(),
            cgroup_path,
            state: CriContainerState::Running,
        }
    }

    #[must_use]
    pub fn exited(
        id: impl Into<String>,
        name: impl Into<String>,
        pod_id: impl Into<String>,
        cgroup_path: PathBuf,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            pod_id: pod_id.into(),
            cgroup_path,
            state: CriContainerState::Exited,
        }
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn pod_id(&self) -> &str {
        &self.pod_id
    }

    #[must_use]
    pub fn cgroup_path(&self) -> &Path {
        &self.cgroup_path
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CriContainerState {
    Running,
    Exited,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CriContainerEvent {
    Started(CriContainer),
    Stopped { container_id: String },
}

#[derive(Debug, Clone)]
pub struct CriSocketClient {
    socket_path: PathBuf,
}

impl CriSocketClient {
    #[must_use]
    pub fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    fn ensure_available(&self) -> Result<(), MetadataError> {
        if self.socket_path.exists() {
            return Ok(());
        }

        Err(MetadataError::CriUnavailable {
            path: self.socket_path.clone(),
        })
    }
}

#[async_trait]
impl CriApi for CriSocketClient {
    async fn list_pods(&self) -> Result<Vec<CriPodSandbox>, MetadataError> {
        self.ensure_available()?;
        Err(MetadataError::CriProtocol {
            operation: "list pods",
            reason: "CRI gRPC transport is not configured in this build",
        })
    }

    async fn list_containers(&self) -> Result<Vec<CriContainer>, MetadataError> {
        self.ensure_available()?;
        Err(MetadataError::CriProtocol {
            operation: "list containers",
            reason: "CRI gRPC transport is not configured in this build",
        })
    }

    async fn watch_events(&self) -> Result<mpsc::Receiver<CriContainerEvent>, MetadataError> {
        self.ensure_available()?;
        Err(MetadataError::CriProtocol {
            operation: "watch events",
            reason: "CRI gRPC transport is not configured in this build",
        })
    }
}

#[derive(Debug, Default, Clone)]
struct CriIndex {
    by_cgroup: HashMap<CgroupId, ContainerMeta>,
    by_container: HashMap<String, CgroupId>,
}

impl CriIndex {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            by_cgroup: HashMap::with_capacity(capacity),
            by_container: HashMap::with_capacity(capacity),
        }
    }

    fn insert(&mut self, meta: ContainerMeta) {
        self.by_container
            .insert(meta.container_id.clone(), meta.cgroup_id);
        self.by_cgroup.insert(meta.cgroup_id, meta);
    }

    fn remove_container(&mut self, container_id: &str) -> Option<CgroupId> {
        let cgroup_id = self.by_container.remove(container_id)?;
        self.by_cgroup.remove(&cgroup_id);
        Some(cgroup_id)
    }

    fn clear(&mut self) {
        self.by_cgroup.clear();
        self.by_container.clear();
    }
}

fn cgroup_id_for_path(root: &Path, relative_or_absolute: &Path) -> Option<CgroupId> {
    let relative = relative_or_absolute
        .strip_prefix(Path::new("/"))
        .unwrap_or(relative_or_absolute);
    let path = root.join(relative);

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        path.metadata()
            .ok()
            .map(|metadata| CgroupId::new(metadata.ino()))
    }

    #[cfg(not(unix))]
    {
        let _unused = path;
        None
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, fs, sync::RwLock as StdRwLock};

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn cri_provider_preserves_socket_path() {
        let provider = CriProvider::new(PathBuf::from("/run/containerd/containerd.sock"));

        assert_eq!(
            provider.socket_path(),
            Path::new("/run/containerd/containerd.sock")
        );
    }

    #[tokio::test]
    async fn resolve_returns_kubernetes_container_metadata() {
        let fixture = CriFixture::new();
        let path = "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podabc.slice/cri-containerd-deadbeef.scope";
        fixture.create_cgroup(path);
        let cgroup_id = fixture.cgroup_id(path);
        let client = MockCriApi::new()
            .with_pod(CriPodSandbox::new("pod-a", "checkout", "payments"))
            .with_container(CriContainer::running(
                "deadbeef",
                "api",
                "pod-a",
                PathBuf::from(path),
            ));
        let provider = CriProvider::with_client(
            client,
            PathBuf::from("/run/containerd/containerd.sock"),
            fixture.cgroup_root().to_path_buf(),
        );

        let meta = provider
            .resolve(cgroup_id)
            .await
            .expect("CRI resolve should succeed")
            .expect("metadata should exist");

        assert_eq!(meta.container_id, "deadbeef");
        assert_eq!(meta.container_name, "api");
        assert_eq!(meta.namespace.as_deref(), Some("payments"));
        assert_eq!(meta.pod_name.as_deref(), Some("checkout"));
    }

    #[tokio::test]
    async fn unavailable_socket_returns_no_metadata() {
        let client = MockCriApi::unavailable(PathBuf::from("/missing/containerd.sock"));
        let provider = CriProvider::with_client(
            client,
            PathBuf::from("/missing/containerd.sock"),
            PathBuf::from("/sys/fs/cgroup"),
        );

        let meta = provider
            .resolve(CgroupId::new(42))
            .await
            .expect("unavailable CRI should fail soft");

        assert_eq!(meta, None);
    }

    #[tokio::test]
    async fn exited_containers_are_not_indexed() {
        let fixture = CriFixture::new();
        let path = "/system.slice/containerd.service/deadbeef";
        fixture.create_cgroup(path);
        let cgroup_id = fixture.cgroup_id(path);
        let client = MockCriApi::new()
            .with_pod(CriPodSandbox::new("pod-a", "checkout", "payments"))
            .with_container(CriContainer::exited(
                "deadbeef",
                "api",
                "pod-a",
                PathBuf::from(path),
            ));
        let provider = CriProvider::with_client(
            client,
            PathBuf::from("/run/containerd/containerd.sock"),
            fixture.cgroup_root().to_path_buf(),
        );

        let meta = provider
            .resolve(cgroup_id)
            .await
            .expect("CRI resolve should succeed");

        assert_eq!(meta, None);
    }

    #[tokio::test]
    async fn watch_events_updates_index() {
        let fixture = CriFixture::new();
        let path = "/system.slice/containerd.service/cri-containerd-deadbeef.scope";
        fixture.create_cgroup(path);
        let cgroup_id = fixture.cgroup_id(path);
        let client =
            MockCriApi::new().with_pod(CriPodSandbox::new("pod-a", "checkout", "payments"));
        let event_sender = client.event_sender();
        let provider = CriProvider::with_client(
            client,
            PathBuf::from("/run/containerd/containerd.sock"),
            fixture.cgroup_root().to_path_buf(),
        );
        let mut events = provider.watch_events().await.expect("watch should start");

        event_sender
            .send(CriContainerEvent::Started(CriContainer::running(
                "deadbeef",
                "api",
                "pod-a",
                PathBuf::from(path),
            )))
            .await
            .expect("event should send");
        let event = events.recv().await.expect("runtime event should arrive");
        let meta = provider
            .resolve(cgroup_id)
            .await
            .expect("CRI resolve should succeed")
            .expect("metadata should exist");

        assert!(matches!(event, RuntimeEvent::Started(_)));
        assert_eq!(meta.container_id, "deadbeef");
        assert_eq!(meta.pod_name.as_deref(), Some("checkout"));
    }

    #[derive(Debug)]
    struct CriFixture {
        _temp_dir: TempDir,
        cgroup_root: PathBuf,
    }

    impl CriFixture {
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

        fn create_cgroup(&self, cgroup_path: &str) {
            let relative_path = Path::new(cgroup_path)
                .strip_prefix(Path::new("/"))
                .expect("test path should be absolute");
            fs::create_dir_all(self.cgroup_root.join(relative_path))
                .expect("cgroup path should be created");
        }

        fn cgroup_id(&self, cgroup_path: &str) -> CgroupId {
            cgroup_id_for_path(&self.cgroup_root, Path::new(cgroup_path))
                .expect("test cgroup id should resolve")
        }
    }

    #[derive(Debug, Clone)]
    struct MockCriApi {
        pods: Arc<StdRwLock<HashMap<String, CriPodSandbox>>>,
        containers: Arc<StdRwLock<Vec<CriContainer>>>,
        events: Arc<RwLock<Option<mpsc::Receiver<CriContainerEvent>>>>,
        event_sender: mpsc::Sender<CriContainerEvent>,
        unavailable: Option<PathBuf>,
    }

    impl MockCriApi {
        fn new() -> Self {
            let (event_sender, events) = mpsc::channel(16);
            Self {
                pods: Arc::new(StdRwLock::new(HashMap::new())),
                containers: Arc::new(StdRwLock::new(Vec::new())),
                events: Arc::new(RwLock::new(Some(events))),
                event_sender,
                unavailable: None,
            }
        }

        fn unavailable(path: PathBuf) -> Self {
            Self {
                unavailable: Some(path),
                ..Self::new()
            }
        }

        fn with_pod(self, pod: CriPodSandbox) -> Self {
            self.pods
                .write()
                .expect("mock pod lock should not be poisoned")
                .insert(pod.id().to_owned(), pod);
            self
        }

        fn with_container(self, container: CriContainer) -> Self {
            self.containers
                .write()
                .expect("mock container lock should not be poisoned")
                .push(container);
            self
        }

        fn event_sender(&self) -> mpsc::Sender<CriContainerEvent> {
            self.event_sender.clone()
        }
    }

    #[async_trait]
    impl CriApi for MockCriApi {
        async fn list_pods(&self) -> Result<Vec<CriPodSandbox>, MetadataError> {
            if let Some(path) = &self.unavailable {
                return Err(MetadataError::CriUnavailable { path: path.clone() });
            }

            Ok(self
                .pods
                .read()
                .expect("mock pod lock should not be poisoned")
                .values()
                .cloned()
                .collect())
        }

        async fn list_containers(&self) -> Result<Vec<CriContainer>, MetadataError> {
            if let Some(path) = &self.unavailable {
                return Err(MetadataError::CriUnavailable { path: path.clone() });
            }

            Ok(self
                .containers
                .read()
                .expect("mock container lock should not be poisoned")
                .clone())
        }

        async fn watch_events(&self) -> Result<mpsc::Receiver<CriContainerEvent>, MetadataError> {
            if let Some(path) = &self.unavailable {
                return Err(MetadataError::CriUnavailable { path: path.clone() });
            }

            self.events
                .write()
                .await
                .take()
                .ok_or(MetadataError::CriProtocol {
                    operation: "watch events",
                    reason: "mock event stream already consumed",
                })
        }
    }
}

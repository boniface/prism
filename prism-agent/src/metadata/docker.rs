use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use async_trait::async_trait;
use prism_core::ids::CgroupId;
use serde::Deserialize;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
    sync::{RwLock, mpsc},
};

use crate::metadata::{ContainerMeta, MetadataError, RuntimeEvent, RuntimeProvider};

const DEFAULT_DOCKER_SOCKET: &str = "/var/run/docker.sock";
const DEFAULT_CGROUP_ROOT: &str = "/sys/fs/cgroup";
const EVENTS_CAPACITY: usize = 64;

#[derive(Debug, Clone)]
pub struct DockerProvider<C = DockerSocketClient> {
    client: C,
    socket_path: PathBuf,
    cgroup_root: PathBuf,
    index: Arc<RwLock<DockerIndex>>,
}

impl DockerProvider<DockerSocketClient> {
    #[must_use]
    pub fn new(socket_path: PathBuf) -> Self {
        let client = DockerSocketClient::new(socket_path.clone());

        Self::with_client(client, socket_path, PathBuf::from(DEFAULT_CGROUP_ROOT))
    }

    #[must_use]
    pub fn default_socket() -> Self {
        Self::new(PathBuf::from(DEFAULT_DOCKER_SOCKET))
    }
}

impl<C> DockerProvider<C>
where
    C: DockerApi,
{
    #[must_use]
    pub fn with_client(client: C, socket_path: PathBuf, cgroup_root: PathBuf) -> Self {
        Self {
            client,
            socket_path,
            cgroup_root,
            index: Arc::new(RwLock::new(DockerIndex::default())),
        }
    }

    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Lists running Docker containers and rebuilds the cgroup metadata index.
    ///
    /// # Errors
    ///
    /// Returns Docker API and cgroup metadata errors except socket
    /// unavailability, which is treated as an empty index.
    pub async fn refresh_index(&self) -> Result<(), MetadataError> {
        let containers = match self.client.list_containers().await {
            Ok(containers) => containers,
            Err(MetadataError::DockerUnavailable { .. }) => {
                self.index.write().await.clear();
                return Ok(());
            }
            Err(error) => return Err(error),
        };

        let mut index = DockerIndex::with_capacity(containers.len());
        for container in containers.iter().filter(|container| container.is_running()) {
            if let Some(meta) = self.container_meta(container).await? {
                index.insert(meta);
            }
        }

        *self.index.write().await = index;
        Ok(())
    }

    async fn container_meta(
        &self,
        summary: &DockerContainerSummary,
    ) -> Result<Option<ContainerMeta>, MetadataError> {
        let inspect = self.client.inspect_container(summary.id()).await?;
        let Some(cgroup_id) = self.resolve_container_cgroup(&inspect) else {
            return Ok(None);
        };

        Ok(Some(ContainerMeta {
            cgroup_id,
            container_id: summary.id().to_owned(),
            container_name: summary.primary_name().to_owned(),
            namespace: None,
            pod_name: None,
        }))
    }

    fn resolve_container_cgroup(&self, inspect: &DockerContainerInspect) -> Option<CgroupId> {
        let mut candidates = docker_cgroup_candidates(inspect.id(), inspect.cgroup_parent());
        if let Some(path) = inspect.cgroup_path() {
            candidates.insert(0, path.to_path_buf());
        }

        candidates
            .iter()
            .find_map(|path| cgroup_id_for_path(&self.cgroup_root, path))
    }

    async fn handle_event(
        &self,
        event: DockerContainerEvent,
        sender: &mpsc::Sender<RuntimeEvent>,
    ) -> Result<(), MetadataError> {
        match event.action() {
            DockerEventAction::Start => {
                let summary = DockerContainerSummary::running(event.container_id(), Vec::new());
                if let Some(meta) = self.container_meta(&summary).await? {
                    self.index.write().await.insert(meta.clone());
                    let _ignored = sender.send(RuntimeEvent::Started(meta)).await;
                }
            }
            DockerEventAction::Stop => {
                if let Some(cgroup_id) = self
                    .index
                    .write()
                    .await
                    .remove_container(event.container_id())
                {
                    let _ignored = sender.send(RuntimeEvent::Stopped(cgroup_id)).await;
                }
            }
            DockerEventAction::Other => {}
        }

        Ok(())
    }
}

#[async_trait]
impl<C> RuntimeProvider for DockerProvider<C>
where
    C: DockerApi,
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
        let mut docker_events = match self.client.watch_events().await {
            Ok(events) => events,
            Err(MetadataError::DockerUnavailable { .. }) => return Ok(receiver),
            Err(error) => return Err(error),
        };
        let provider = self.clone();

        tokio::spawn(async move {
            while let Some(event) = docker_events.recv().await {
                if provider.handle_event(event, &sender).await.is_err() {
                    break;
                }
            }
        });

        Ok(receiver)
    }
}

#[async_trait]
pub trait DockerApi: Clone + Send + Sync + 'static {
    async fn list_containers(&self) -> Result<Vec<DockerContainerSummary>, MetadataError>;

    async fn inspect_container(
        &self,
        container_id: &str,
    ) -> Result<DockerContainerInspect, MetadataError>;

    async fn watch_events(&self) -> Result<mpsc::Receiver<DockerContainerEvent>, MetadataError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DockerContainerSummary {
    id: String,
    names: Vec<String>,
    state: DockerContainerState,
}

impl DockerContainerSummary {
    #[must_use]
    pub fn running(id: impl Into<String>, names: Vec<String>) -> Self {
        Self {
            id: id.into(),
            names,
            state: DockerContainerState::Running,
        }
    }

    #[must_use]
    pub fn stopped(id: impl Into<String>, names: Vec<String>) -> Self {
        Self {
            id: id.into(),
            names,
            state: DockerContainerState::Stopped,
        }
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn is_running(&self) -> bool {
        self.state == DockerContainerState::Running
    }

    fn primary_name(&self) -> &str {
        self.names
            .first()
            .map(|name| name.trim_start_matches('/'))
            .filter(|name| !name.is_empty())
            .unwrap_or(&self.id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DockerContainerState {
    Running,
    Stopped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DockerContainerInspect {
    id: String,
    cgroup_path: Option<PathBuf>,
    cgroup_parent: Option<PathBuf>,
}

impl DockerContainerInspect {
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        cgroup_path: Option<PathBuf>,
        cgroup_parent: Option<PathBuf>,
    ) -> Self {
        Self {
            id: id.into(),
            cgroup_path,
            cgroup_parent,
        }
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    fn cgroup_path(&self) -> Option<&Path> {
        self.cgroup_path.as_deref()
    }

    fn cgroup_parent(&self) -> Option<&Path> {
        self.cgroup_parent.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DockerContainerEvent {
    action: DockerEventAction,
    container_id: String,
}

impl DockerContainerEvent {
    #[must_use]
    pub fn started(container_id: impl Into<String>) -> Self {
        Self {
            action: DockerEventAction::Start,
            container_id: container_id.into(),
        }
    }

    #[must_use]
    pub fn stopped(container_id: impl Into<String>) -> Self {
        Self {
            action: DockerEventAction::Stop,
            container_id: container_id.into(),
        }
    }

    fn action(&self) -> DockerEventAction {
        self.action
    }

    fn container_id(&self) -> &str {
        &self.container_id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DockerEventAction {
    Start,
    Stop,
    Other,
}

#[derive(Debug, Clone)]
pub struct DockerSocketClient {
    socket_path: PathBuf,
}

impl DockerSocketClient {
    #[must_use]
    pub fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    async fn request(&self, path: &str) -> Result<String, MetadataError> {
        let mut stream = UnixStream::connect(&self.socket_path).await.map_err(|_| {
            MetadataError::DockerUnavailable {
                path: self.socket_path.clone(),
            }
        })?;
        let request = format!("GET {path} HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n");
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|source| MetadataError::DockerIo {
                operation: "request",
                source,
            })?;

        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .map_err(|source| MetadataError::DockerIo {
                operation: "response",
                source,
            })?;

        parse_http_body(&response, "request").map(str::to_owned)
    }
}

#[async_trait]
impl DockerApi for DockerSocketClient {
    async fn list_containers(&self) -> Result<Vec<DockerContainerSummary>, MetadataError> {
        let body = self.request("/containers/json?all=true").await?;
        let containers: Vec<DockerSummaryJson> =
            serde_json::from_str(&body).map_err(|source| MetadataError::DockerDecode {
                operation: "list containers",
                source,
            })?;

        Ok(containers
            .into_iter()
            .map(DockerContainerSummary::from)
            .collect())
    }

    async fn inspect_container(
        &self,
        container_id: &str,
    ) -> Result<DockerContainerInspect, MetadataError> {
        let body = self
            .request(&format!("/containers/{container_id}/json"))
            .await?;
        let inspect: DockerInspectJson =
            serde_json::from_str(&body).map_err(|source| MetadataError::DockerDecode {
                operation: "inspect container",
                source,
            })?;

        Ok(DockerContainerInspect::from(inspect))
    }

    async fn watch_events(&self) -> Result<mpsc::Receiver<DockerContainerEvent>, MetadataError> {
        let stream = UnixStream::connect(&self.socket_path).await.map_err(|_| {
            MetadataError::DockerUnavailable {
                path: self.socket_path.clone(),
            }
        })?;
        let (sender, receiver) = mpsc::channel(EVENTS_CAPACITY);
        tokio::spawn(read_docker_events(stream, sender));
        Ok(receiver)
    }
}

async fn read_docker_events(mut stream: UnixStream, sender: mpsc::Sender<DockerContainerEvent>) {
    let request = "GET /events?filters=%7B%22type%22%3A%5B%22container%22%5D%2C%22event%22%3A%5B%22start%22%2C%22die%22%2C%22stop%22%2C%22destroy%22%5D%7D HTTP/1.1\r\nHost: docker\r\n\r\n";
    if stream.write_all(request.as_bytes()).await.is_err() {
        return;
    }

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let mut in_body = false;
    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) | Err(_) => return,
            Ok(_) if !in_body && line == "\r\n" => in_body = true,
            Ok(_) if !in_body => {}
            Ok(_) => {
                if let Ok(event) = serde_json::from_str::<DockerEventJson>(&line) {
                    let _ignored = sender.send(DockerContainerEvent::from(event)).await;
                }
            }
        }
    }
}

#[derive(Debug, Default, Clone)]
struct DockerIndex {
    by_cgroup: HashMap<CgroupId, ContainerMeta>,
    by_container: HashMap<String, CgroupId>,
}

impl DockerIndex {
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DockerSummaryJson {
    id: String,
    names: Option<Vec<String>>,
    state: Option<String>,
}

impl From<DockerSummaryJson> for DockerContainerSummary {
    fn from(value: DockerSummaryJson) -> Self {
        let state = match value.state.as_deref() {
            Some("running") => DockerContainerState::Running,
            Some(_) | None => DockerContainerState::Stopped,
        };

        Self {
            id: value.id,
            names: value.names.unwrap_or_default(),
            state,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DockerInspectJson {
    id: String,
    host_config: Option<DockerHostConfigJson>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DockerHostConfigJson {
    cgroup_parent: Option<String>,
}

impl From<DockerInspectJson> for DockerContainerInspect {
    fn from(value: DockerInspectJson) -> Self {
        let cgroup_parent = value
            .host_config
            .and_then(|host| host.cgroup_parent)
            .filter(|parent| !parent.is_empty())
            .map(PathBuf::from);

        Self::new(value.id, None, cgroup_parent)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DockerEventJson {
    action: Option<String>,
    id: Option<String>,
}

impl From<DockerEventJson> for DockerContainerEvent {
    fn from(value: DockerEventJson) -> Self {
        let action = match value.action.as_deref() {
            Some("start") => DockerEventAction::Start,
            Some("die" | "stop" | "destroy") => DockerEventAction::Stop,
            Some(_) | None => DockerEventAction::Other,
        };

        Self {
            action,
            container_id: value.id.unwrap_or_default(),
        }
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

fn docker_cgroup_candidates(container_id: &str, cgroup_parent: Option<&Path>) -> Vec<PathBuf> {
    let mut candidates = Vec::with_capacity(4);
    if let Some(parent) = cgroup_parent {
        candidates.push(parent.join(format!("docker-{container_id}.scope")));
        candidates.push(parent.join(container_id));
    }
    candidates.push(PathBuf::from(format!(
        "/system.slice/docker-{container_id}.scope"
    )));
    candidates.push(PathBuf::from(format!("/docker/{container_id}")));
    candidates
}

fn parse_http_body<'a>(
    response: &'a [u8],
    operation: &'static str,
) -> Result<&'a str, MetadataError> {
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or(MetadataError::DockerProtocol {
            operation,
            reason: "missing http headers",
        })?;
    std::str::from_utf8(&response[split + 4..]).map_err(|_| MetadataError::DockerProtocol {
        operation,
        reason: "response body is not utf-8",
    })
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, fs, sync::RwLock as StdRwLock};

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn docker_provider_preserves_socket_path() {
        let provider = DockerProvider::new(PathBuf::from("/var/run/docker.sock"));

        assert_eq!(provider.socket_path(), Path::new("/var/run/docker.sock"));
    }

    #[tokio::test]
    async fn resolve_indexes_running_container_metadata() {
        let fixture = DockerFixture::new();
        let inspect = fixture.inspect("abc123", "/system.slice/docker-abc123.scope");
        let cgroup_id = fixture.cgroup_id("/system.slice/docker-abc123.scope");
        let client = MockDockerApi::new()
            .with_container(DockerContainerSummary::running(
                "abc123",
                vec!["/compose-web-1".to_owned()],
            ))
            .with_inspect(inspect);
        let provider = DockerProvider::with_client(
            client,
            PathBuf::from("/tmp/docker.sock"),
            fixture.cgroup_root().to_path_buf(),
        );

        let meta = provider
            .resolve(cgroup_id)
            .await
            .expect("docker resolve should succeed")
            .expect("metadata should exist");

        assert_eq!(meta.container_id, "abc123");
        assert_eq!(meta.container_name, "compose-web-1");
        assert_eq!(meta.cgroup_id, cgroup_id);
    }

    #[tokio::test]
    async fn unavailable_socket_returns_no_metadata() {
        let client = MockDockerApi::unavailable(PathBuf::from("/missing/docker.sock"));
        let provider = DockerProvider::with_client(
            client,
            PathBuf::from("/missing/docker.sock"),
            PathBuf::from("/sys/fs/cgroup"),
        );

        let meta = provider
            .resolve(CgroupId::new(42))
            .await
            .expect("unavailable docker should fail soft");

        assert_eq!(meta, None);
    }

    #[tokio::test]
    async fn stopped_containers_are_not_indexed() {
        let fixture = DockerFixture::new();
        let inspect = fixture.inspect("abc123", "/docker/abc123");
        let cgroup_id = fixture.cgroup_id("/docker/abc123");
        let client = MockDockerApi::new()
            .with_container(DockerContainerSummary::stopped(
                "abc123",
                vec!["/web".to_owned()],
            ))
            .with_inspect(inspect);
        let provider = DockerProvider::with_client(
            client,
            PathBuf::from("/tmp/docker.sock"),
            fixture.cgroup_root().to_path_buf(),
        );

        let meta = provider
            .resolve(cgroup_id)
            .await
            .expect("docker resolve should succeed");

        assert_eq!(meta, None);
    }

    #[tokio::test]
    async fn watch_events_updates_index_and_emits_runtime_events() {
        let fixture = DockerFixture::new();
        let inspect = fixture.inspect("abc123", "/docker/abc123");
        let cgroup_id = fixture.cgroup_id("/docker/abc123");
        let client = MockDockerApi::new().with_inspect(inspect);
        let event_sender = client.event_sender();
        let provider = DockerProvider::with_client(
            client,
            PathBuf::from("/tmp/docker.sock"),
            fixture.cgroup_root().to_path_buf(),
        );
        let mut events = provider.watch_events().await.expect("watch should start");

        event_sender
            .send(DockerContainerEvent::started("abc123"))
            .await
            .expect("event should send");
        let event = events.recv().await.expect("runtime event should arrive");
        let meta = provider
            .resolve(cgroup_id)
            .await
            .expect("docker resolve should succeed")
            .expect("metadata should exist");

        assert!(matches!(event, RuntimeEvent::Started(_)));
        assert_eq!(meta.container_id, "abc123");
    }

    #[test]
    fn parses_docker_http_body() {
        let body = parse_http_body(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n[]",
            "test",
        )
        .expect("body should parse");

        assert_eq!(body, "[]");
    }

    #[derive(Debug)]
    struct DockerFixture {
        _temp_dir: TempDir,
        cgroup_root: PathBuf,
    }

    impl DockerFixture {
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

        fn inspect(&self, id: &str, cgroup_path: &str) -> DockerContainerInspect {
            self.create_cgroup(cgroup_path);
            DockerContainerInspect::new(id, Some(PathBuf::from(cgroup_path)), None)
        }

        fn cgroup_id(&self, cgroup_path: &str) -> CgroupId {
            cgroup_id_for_path(&self.cgroup_root, Path::new(cgroup_path))
                .expect("test cgroup id should resolve")
        }

        fn create_cgroup(&self, cgroup_path: &str) {
            let relative_path = Path::new(cgroup_path)
                .strip_prefix(Path::new("/"))
                .expect("test path should be absolute");
            fs::create_dir_all(self.cgroup_root.join(relative_path))
                .expect("cgroup path should be created");
        }
    }

    #[derive(Debug, Clone)]
    struct MockDockerApi {
        containers: Arc<StdRwLock<Vec<DockerContainerSummary>>>,
        inspections: Arc<StdRwLock<HashMap<String, DockerContainerInspect>>>,
        events: Arc<RwLock<Option<mpsc::Receiver<DockerContainerEvent>>>>,
        event_sender: mpsc::Sender<DockerContainerEvent>,
        unavailable: Option<PathBuf>,
    }

    impl MockDockerApi {
        fn new() -> Self {
            let (event_sender, events) = mpsc::channel(16);
            Self {
                containers: Arc::new(StdRwLock::new(Vec::new())),
                inspections: Arc::new(StdRwLock::new(HashMap::new())),
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

        fn with_container(self, container: DockerContainerSummary) -> Self {
            self.containers
                .write()
                .expect("mock container lock should not be poisoned")
                .push(container);
            self
        }

        fn with_inspect(self, inspect: DockerContainerInspect) -> Self {
            self.inspections
                .write()
                .expect("mock inspect lock should not be poisoned")
                .insert(inspect.id().to_owned(), inspect);
            self
        }

        fn event_sender(&self) -> mpsc::Sender<DockerContainerEvent> {
            self.event_sender.clone()
        }
    }

    #[async_trait]
    impl DockerApi for MockDockerApi {
        async fn list_containers(&self) -> Result<Vec<DockerContainerSummary>, MetadataError> {
            if let Some(path) = &self.unavailable {
                return Err(MetadataError::DockerUnavailable { path: path.clone() });
            }

            Ok(self
                .containers
                .read()
                .expect("mock container lock should not be poisoned")
                .clone())
        }

        async fn inspect_container(
            &self,
            container_id: &str,
        ) -> Result<DockerContainerInspect, MetadataError> {
            if let Some(path) = &self.unavailable {
                return Err(MetadataError::DockerUnavailable { path: path.clone() });
            }

            self.inspections
                .read()
                .expect("mock inspect lock should not be poisoned")
                .get(container_id)
                .cloned()
                .ok_or(MetadataError::DockerProtocol {
                    operation: "inspect container",
                    reason: "missing mocked inspection",
                })
        }

        async fn watch_events(
            &self,
        ) -> Result<mpsc::Receiver<DockerContainerEvent>, MetadataError> {
            if let Some(path) = &self.unavailable {
                return Err(MetadataError::DockerUnavailable { path: path.clone() });
            }

            self.events
                .write()
                .await
                .take()
                .ok_or(MetadataError::DockerProtocol {
                    operation: "watch events",
                    reason: "mock event stream already consumed",
                })
        }
    }
}

use std::{
    collections::{BTreeMap, BTreeSet},
    env,
};

use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::metadata::{ContainerMeta, MetadataError};

const EVENTS_CAPACITY: usize = 64;
const KUBERNETES_SERVICE_HOST: &str = "KUBERNETES_SERVICE_HOST";
const KUBERNETES_SERVICE_PORT: &str = "KUBERNETES_SERVICE_PORT";
const DEFAULT_TOKEN_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";

#[derive(Debug, Clone)]
pub struct KubernetesProvider<C = KubernetesServiceAccountClient> {
    client: C,
    allowlist: KubernetesAllowlist,
}

impl KubernetesProvider<KubernetesServiceAccountClient> {
    #[must_use]
    pub fn in_cluster(allowlist: KubernetesAllowlist) -> Self {
        Self {
            client: KubernetesServiceAccountClient::default(),
            allowlist,
        }
    }
}

impl<C> KubernetesProvider<C>
where
    C: KubernetesApi,
{
    #[must_use]
    pub fn with_client(client: C, allowlist: KubernetesAllowlist) -> Self {
        Self { client, allowlist }
    }

    /// Enriches runtime metadata with Kubernetes API pod metadata.
    ///
    /// # Errors
    ///
    /// Returns Kubernetes protocol errors. API unavailability is treated as a
    /// soft miss so the agent continues with base runtime metadata.
    pub async fn enrich(
        &self,
        container: &ContainerMeta,
    ) -> Result<EnrichedContainerMeta, MetadataError> {
        let mut enriched = EnrichedContainerMeta::new(container.clone());
        let Some(namespace) = container.namespace.as_deref() else {
            return Ok(enriched);
        };
        let Some(pod_name) = container.pod_name.as_deref() else {
            return Ok(enriched);
        };

        match self.client.pod(namespace, pod_name).await {
            Ok(Some(pod)) => {
                enriched.pod = Some(self.allowlist.filter_object(&pod));
                Ok(enriched)
            }
            Ok(None) | Err(MetadataError::KubernetesUnavailable { .. }) => Ok(enriched),
            Err(error) => Err(error),
        }
    }

    /// Starts Kubernetes watch streams for pod, namespace, and node changes.
    ///
    /// # Errors
    ///
    /// Returns Kubernetes protocol errors. API unavailability is treated as an
    /// empty event stream.
    pub async fn watch_events(&self) -> Result<mpsc::Receiver<KubernetesEvent>, MetadataError> {
        let (sender, receiver) = mpsc::channel(EVENTS_CAPACITY);
        let streams = match self.client.watch_all().await {
            Ok(streams) => streams,
            Err(MetadataError::KubernetesUnavailable { .. }) => return Ok(receiver),
            Err(error) => return Err(error),
        };

        spawn_forwarder(streams.pods, sender.clone());
        spawn_forwarder(streams.namespaces, sender.clone());
        spawn_forwarder(streams.nodes, sender);

        Ok(receiver)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrichedContainerMeta {
    container: ContainerMeta,
    pod: Option<KubernetesObjectMeta>,
}

impl EnrichedContainerMeta {
    #[must_use]
    pub const fn new(container: ContainerMeta) -> Self {
        Self {
            container,
            pod: None,
        }
    }

    #[must_use]
    pub const fn container(&self) -> &ContainerMeta {
        &self.container
    }

    #[must_use]
    pub const fn pod(&self) -> Option<&KubernetesObjectMeta> {
        self.pod.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KubernetesObjectMeta {
    name: String,
    namespace: Option<String>,
    labels: BTreeMap<String, String>,
    annotations: BTreeMap<String, String>,
}

impl KubernetesObjectMeta {
    #[must_use]
    pub fn new(name: impl Into<String>, namespace: Option<String>) -> Self {
        Self {
            name: name.into(),
            namespace,
            labels: BTreeMap::new(),
            annotations: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.insert(key.into(), value.into());
        self
    }

    #[must_use]
    pub fn with_annotation(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.annotations.insert(key.into(), value.into());
        self
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }

    #[must_use]
    pub fn labels(&self) -> &BTreeMap<String, String> {
        &self.labels
    }

    #[must_use]
    pub fn annotations(&self) -> &BTreeMap<String, String> {
        &self.annotations
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KubernetesAllowlist {
    labels: BTreeSet<String>,
    annotations: BTreeSet<String>,
}

impl KubernetesAllowlist {
    #[must_use]
    pub fn new(
        labels: impl IntoIterator<Item = String>,
        annotations: impl IntoIterator<Item = String>,
    ) -> Self {
        Self {
            labels: labels.into_iter().collect(),
            annotations: annotations.into_iter().collect(),
        }
    }

    #[must_use]
    pub fn labels(&self) -> &BTreeSet<String> {
        &self.labels
    }

    #[must_use]
    pub fn annotations(&self) -> &BTreeSet<String> {
        &self.annotations
    }

    fn filter_object(&self, object: &KubernetesObjectMeta) -> KubernetesObjectMeta {
        let labels = object
            .labels
            .iter()
            .filter(|(key, _)| self.labels.contains(*key))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        let annotations = object
            .annotations
            .iter()
            .filter(|(key, _)| self.annotations.contains(*key))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();

        KubernetesObjectMeta {
            name: object.name.clone(),
            namespace: object.namespace.clone(),
            labels,
            annotations,
        }
    }
}

impl Default for KubernetesAllowlist {
    fn default() -> Self {
        Self::new(
            [
                "app.kubernetes.io/name".to_owned(),
                "app.kubernetes.io/instance".to_owned(),
                "app.kubernetes.io/component".to_owned(),
            ],
            ["prism.io/workload".to_owned()],
        )
    }
}

#[derive(Debug)]
pub struct KubernetesWatchStreams {
    pods: mpsc::Receiver<KubernetesEvent>,
    namespaces: mpsc::Receiver<KubernetesEvent>,
    nodes: mpsc::Receiver<KubernetesEvent>,
}

impl KubernetesWatchStreams {
    #[must_use]
    pub const fn new(
        pods: mpsc::Receiver<KubernetesEvent>,
        namespaces: mpsc::Receiver<KubernetesEvent>,
        nodes: mpsc::Receiver<KubernetesEvent>,
    ) -> Self {
        Self {
            pods,
            namespaces,
            nodes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KubernetesEvent {
    PodChanged(KubernetesObjectMeta),
    NamespaceChanged(KubernetesObjectMeta),
    NodeChanged(KubernetesObjectMeta),
}

#[async_trait]
pub trait KubernetesApi: Clone + Send + Sync + 'static {
    async fn pod(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Option<KubernetesObjectMeta>, MetadataError>;

    async fn watch_all(&self) -> Result<KubernetesWatchStreams, MetadataError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KubernetesServiceAccountClient {
    token_path: String,
    host: Option<String>,
    port: Option<String>,
}

impl Default for KubernetesServiceAccountClient {
    fn default() -> Self {
        Self {
            token_path: DEFAULT_TOKEN_PATH.to_owned(),
            host: env::var(KUBERNETES_SERVICE_HOST).ok(),
            port: env::var(KUBERNETES_SERVICE_PORT).ok(),
        }
    }
}

impl KubernetesServiceAccountClient {
    fn ensure_available(&self) -> Result<(), MetadataError> {
        if self.host.is_some()
            && self.port.is_some()
            && std::path::Path::new(&self.token_path).exists()
        {
            return Ok(());
        }

        Err(MetadataError::KubernetesUnavailable {
            reason: "in-cluster service account is unavailable",
        })
    }
}

#[async_trait]
impl KubernetesApi for KubernetesServiceAccountClient {
    async fn pod(
        &self,
        _namespace: &str,
        _name: &str,
    ) -> Result<Option<KubernetesObjectMeta>, MetadataError> {
        self.ensure_available()?;
        Err(MetadataError::KubernetesProtocol {
            operation: "get pod",
            reason: "kubernetes HTTP transport is not configured in this build",
        })
    }

    async fn watch_all(&self) -> Result<KubernetesWatchStreams, MetadataError> {
        self.ensure_available()?;
        Err(MetadataError::KubernetesProtocol {
            operation: "watch resources",
            reason: "kubernetes HTTP transport is not configured in this build",
        })
    }
}

fn spawn_forwarder(
    mut input: mpsc::Receiver<KubernetesEvent>,
    output: mpsc::Sender<KubernetesEvent>,
) {
    tokio::spawn(async move {
        while let Some(event) = input.recv().await {
            if output.send(event).await.is_err() {
                return;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{Arc, RwLock as StdRwLock},
    };

    use super::*;

    #[tokio::test]
    async fn enrich_filters_labels_and_annotations_by_allowlist() {
        let client = MockKubernetesApi::new().with_pod(
            "payments",
            KubernetesObjectMeta::new("checkout", Some("payments".to_owned()))
                .with_label("app.kubernetes.io/name", "checkout")
                .with_label("team", "payments")
                .with_annotation("prism.io/workload", "checkout-api")
                .with_annotation("kubectl.kubernetes.io/last-applied-configuration", "{}"),
        );
        let provider = KubernetesProvider::with_client(client, KubernetesAllowlist::default());
        let container = container_meta("payments", "checkout");

        let enriched = provider
            .enrich(&container)
            .await
            .expect("enrichment should succeed");
        let pod = enriched.pod().expect("pod metadata should be present");

        assert_eq!(pod.labels().len(), 1);
        assert_eq!(
            pod.labels()
                .get("app.kubernetes.io/name")
                .map(String::as_str),
            Some("checkout")
        );
        assert!(!pod.labels().contains_key("team"));
        assert_eq!(pod.annotations().len(), 1);
        assert_eq!(
            pod.annotations()
                .get("prism.io/workload")
                .map(String::as_str),
            Some("checkout-api")
        );
    }

    #[tokio::test]
    async fn unavailable_api_returns_base_metadata() {
        let provider = KubernetesProvider::with_client(
            MockKubernetesApi::unavailable(),
            KubernetesAllowlist::default(),
        );
        let container = container_meta("payments", "checkout");

        let enriched = provider
            .enrich(&container)
            .await
            .expect("unavailable Kubernetes should fail soft");

        assert_eq!(enriched.container(), &container);
        assert!(enriched.pod().is_none());
    }

    #[tokio::test]
    async fn missing_pod_returns_base_metadata() {
        let provider = KubernetesProvider::with_client(
            MockKubernetesApi::new(),
            KubernetesAllowlist::default(),
        );
        let container = container_meta("payments", "missing");

        let enriched = provider
            .enrich(&container)
            .await
            .expect("missing pod should not fail");

        assert!(enriched.pod().is_none());
    }

    #[tokio::test]
    async fn watch_events_forwards_pods_namespaces_and_nodes() {
        let client = MockKubernetesApi::new();
        let senders = client.senders();
        let provider = KubernetesProvider::with_client(client, KubernetesAllowlist::default());
        let mut events = provider.watch_events().await.expect("watch should start");

        senders
            .pods
            .send(KubernetesEvent::PodChanged(KubernetesObjectMeta::new(
                "checkout",
                Some("payments".to_owned()),
            )))
            .await
            .expect("pod event should send");
        senders
            .namespaces
            .send(KubernetesEvent::NamespaceChanged(
                KubernetesObjectMeta::new("payments", None),
            ))
            .await
            .expect("namespace event should send");
        senders
            .nodes
            .send(KubernetesEvent::NodeChanged(KubernetesObjectMeta::new(
                "node-a", None,
            )))
            .await
            .expect("node event should send");

        let first = events.recv().await.expect("first event should arrive");
        let second = events.recv().await.expect("second event should arrive");
        let third = events.recv().await.expect("third event should arrive");

        assert!(matches!(first, KubernetesEvent::PodChanged(_)));
        assert!(matches!(second, KubernetesEvent::NamespaceChanged(_)));
        assert!(matches!(third, KubernetesEvent::NodeChanged(_)));
    }

    fn container_meta(namespace: &str, pod_name: &str) -> ContainerMeta {
        ContainerMeta {
            cgroup_id: prism_core::ids::CgroupId::new(7),
            container_id: "container-a".to_owned(),
            container_name: "api".to_owned(),
            namespace: Some(namespace.to_owned()),
            pod_name: Some(pod_name.to_owned()),
        }
    }

    #[derive(Debug, Clone)]
    struct MockKubernetesApi {
        pods: Arc<StdRwLock<HashMap<(String, String), KubernetesObjectMeta>>>,
        streams: Arc<StdRwLock<Option<MockWatchSenders>>>,
        unavailable: bool,
    }

    impl MockKubernetesApi {
        fn new() -> Self {
            Self {
                pods: Arc::new(StdRwLock::new(HashMap::new())),
                streams: Arc::new(StdRwLock::new(Some(MockWatchSenders::new()))),
                unavailable: false,
            }
        }

        fn unavailable() -> Self {
            Self {
                unavailable: true,
                ..Self::new()
            }
        }

        fn with_pod(self, namespace: &str, pod: KubernetesObjectMeta) -> Self {
            self.pods
                .write()
                .expect("mock pod lock should not be poisoned")
                .insert((namespace.to_owned(), pod.name().to_owned()), pod);
            self
        }

        fn senders(&self) -> MockWatchSenders {
            self.streams
                .read()
                .expect("mock stream lock should not be poisoned")
                .as_ref()
                .expect("mock streams should exist")
                .clone()
        }
    }

    #[async_trait]
    impl KubernetesApi for MockKubernetesApi {
        async fn pod(
            &self,
            namespace: &str,
            name: &str,
        ) -> Result<Option<KubernetesObjectMeta>, MetadataError> {
            if self.unavailable {
                return Err(MetadataError::KubernetesUnavailable {
                    reason: "mock unavailable",
                });
            }

            Ok(self
                .pods
                .read()
                .expect("mock pod lock should not be poisoned")
                .get(&(namespace.to_owned(), name.to_owned()))
                .cloned())
        }

        async fn watch_all(&self) -> Result<KubernetesWatchStreams, MetadataError> {
            if self.unavailable {
                return Err(MetadataError::KubernetesUnavailable {
                    reason: "mock unavailable",
                });
            }

            self.streams
                .write()
                .expect("mock stream lock should not be poisoned")
                .take()
                .map(MockWatchSenders::into_streams)
                .ok_or(MetadataError::KubernetesProtocol {
                    operation: "watch resources",
                    reason: "mock streams already consumed",
                })
        }
    }

    #[derive(Debug, Clone)]
    struct MockWatchSenders {
        pods: mpsc::Sender<KubernetesEvent>,
        namespaces: mpsc::Sender<KubernetesEvent>,
        nodes: mpsc::Sender<KubernetesEvent>,
        receivers: Arc<StdRwLock<Option<MockWatchReceivers>>>,
    }

    impl MockWatchSenders {
        fn new() -> Self {
            let (pods, pod_receiver) = mpsc::channel(16);
            let (namespaces, namespace_receiver) = mpsc::channel(16);
            let (nodes, node_receiver) = mpsc::channel(16);

            Self {
                pods,
                namespaces,
                nodes,
                receivers: Arc::new(StdRwLock::new(Some(MockWatchReceivers {
                    pods: pod_receiver,
                    namespaces: namespace_receiver,
                    nodes: node_receiver,
                }))),
            }
        }

        fn into_streams(self) -> KubernetesWatchStreams {
            self.receivers
                .write()
                .expect("mock receiver lock should not be poisoned")
                .take()
                .expect("mock receivers should exist")
                .into_streams()
        }
    }

    #[derive(Debug)]
    struct MockWatchReceivers {
        pods: mpsc::Receiver<KubernetesEvent>,
        namespaces: mpsc::Receiver<KubernetesEvent>,
        nodes: mpsc::Receiver<KubernetesEvent>,
    }

    impl MockWatchReceivers {
        fn into_streams(self) -> KubernetesWatchStreams {
            KubernetesWatchStreams::new(self.pods, self.namespaces, self.nodes)
        }
    }
}

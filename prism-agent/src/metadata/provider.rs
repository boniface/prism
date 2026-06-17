use async_trait::async_trait;
use prism_core::ids::CgroupId;
use tokio::sync::mpsc;

use crate::metadata::MetadataError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerMeta {
    pub cgroup_id: CgroupId,
    pub container_id: String,
    pub container_name: String,
    pub namespace: Option<String>,
    pub pod_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeEvent {
    Started(ContainerMeta),
    Stopped(CgroupId),
}

#[async_trait]
pub trait RuntimeProvider: Send + Sync {
    async fn resolve(&self, cgroup_id: CgroupId) -> Result<Option<ContainerMeta>, MetadataError>;

    async fn watch_events(&self) -> Result<mpsc::Receiver<RuntimeEvent>, MetadataError>;
}

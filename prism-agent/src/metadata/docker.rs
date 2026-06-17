use std::path::PathBuf;

use async_trait::async_trait;
use prism_core::ids::CgroupId;
use tokio::sync::mpsc;

use crate::metadata::{ContainerMeta, MetadataError, RuntimeEvent, RuntimeProvider};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DockerProvider {
    socket_path: PathBuf,
}

impl DockerProvider {
    #[must_use]
    pub fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    #[must_use]
    pub fn socket_path(&self) -> &PathBuf {
        &self.socket_path
    }
}

#[async_trait]
impl RuntimeProvider for DockerProvider {
    async fn resolve(&self, _cgroup_id: CgroupId) -> Result<Option<ContainerMeta>, MetadataError> {
        Ok(None)
    }

    async fn watch_events(&self) -> Result<mpsc::Receiver<RuntimeEvent>, MetadataError> {
        let (_sender, receiver) = mpsc::channel(1);
        Ok(receiver)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_provider_preserves_socket_path() {
        let provider = DockerProvider::new(PathBuf::from("/var/run/docker.sock"));

        assert_eq!(
            provider.socket_path(),
            &PathBuf::from("/var/run/docker.sock")
        );
    }
}

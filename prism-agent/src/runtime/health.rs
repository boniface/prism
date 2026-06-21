use std::{collections::BTreeMap, sync::Arc};

use tokio::sync::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    Starting,
    Running,
    Stopping,
    Stopped,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskHealth {
    name: String,
    state: TaskState,
    error: Option<String>,
}

impl TaskHealth {
    #[must_use]
    pub fn new(name: String, state: TaskState, error: Option<String>) -> Self {
        Self { name, state, error }
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn state(&self) -> TaskState {
        self.state
    }

    #[must_use]
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TaskHealthSnapshot {
    tasks: Vec<TaskHealth>,
}

impl TaskHealthSnapshot {
    #[must_use]
    pub fn tasks(&self) -> &[TaskHealth] {
        &self.tasks
    }

    #[must_use]
    pub fn failed_tasks(&self) -> usize {
        self.tasks
            .iter()
            .filter(|task| task.state == TaskState::Failed)
            .count()
    }

    #[must_use]
    pub fn state_for(&self, name: &str) -> Option<TaskState> {
        self.tasks
            .iter()
            .find(|task| task.name == name)
            .map(TaskHealth::state)
    }
}

#[derive(Debug, Default, Clone)]
pub struct HealthRegistry {
    inner: Arc<RwLock<BTreeMap<String, TaskHealth>>>,
}

impl HealthRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn set_state(&self, name: &str, state: TaskState) {
        self.set(name, state, None).await;
    }

    pub async fn set_failed(&self, name: &str, error: String) {
        self.set(name, TaskState::Failed, Some(error)).await;
    }

    pub async fn snapshot(&self) -> TaskHealthSnapshot {
        let tasks = self.inner.read().await.values().cloned().collect();

        TaskHealthSnapshot { tasks }
    }

    async fn set(&self, name: &str, state: TaskState, error: Option<String>) {
        self.inner.write().await.insert(
            name.to_owned(),
            TaskHealth::new(name.to_owned(), state, error),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn health_snapshot_counts_failures() {
        let registry = HealthRegistry::new();

        registry.set_state("processor", TaskState::Running).await;
        registry
            .set_failed("exporter", "export failed".to_owned())
            .await;
        let snapshot = registry.snapshot().await;

        assert_eq!(snapshot.failed_tasks(), 1);
        assert_eq!(snapshot.state_for("processor"), Some(TaskState::Running));
        assert_eq!(snapshot.state_for("exporter"), Some(TaskState::Failed));
    }
}

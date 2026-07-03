use std::{collections::BTreeMap, sync::Arc};

use axum::serve;
use axum::{
    Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::get,
};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

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

// Health check response format
#[derive(Debug, serde::Serialize)]
struct HealthResponse {
    status: &'static str,
    tasks: Vec<TaskHealthResponse>,
    failed_tasks: usize,
}

#[derive(Debug, serde::Serialize)]
struct TaskHealthResponse {
    name: String,
    state: String,
    error: Option<String>,
}

impl From<&TaskHealth> for TaskHealthResponse {
    fn from(task: &TaskHealth) -> Self {
        Self {
            name: task.name().to_owned(),
            state: match task.state() {
                TaskState::Starting => "starting",
                TaskState::Running => "running",
                TaskState::Stopping => "stopping",
                TaskState::Stopped => "stopped",
                TaskState::Failed => "failed",
            }
            .to_owned(),
            error: task.error().map(ToOwned::to_owned),
        }
    }
}

async fn healthz_handler(State(registry): State<HealthRegistry>) -> impl IntoResponse {
    let snapshot = registry.snapshot().await;

    if snapshot.failed_tasks() > 0 {
        let response = HealthResponse {
            status: "unhealthy",
            tasks: snapshot
                .tasks()
                .iter()
                .map(TaskHealthResponse::from)
                .collect(),
            failed_tasks: snapshot.failed_tasks(),
        };
        (StatusCode::SERVICE_UNAVAILABLE, Json(response))
    } else {
        let response = HealthResponse {
            status: "ok",
            tasks: snapshot
                .tasks()
                .iter()
                .map(TaskHealthResponse::from)
                .collect(),
            failed_tasks: 0,
        };
        (StatusCode::OK, Json(response))
    }
}

async fn readyz_handler(State(registry): State<HealthRegistry>) -> impl IntoResponse {
    let snapshot = registry.snapshot().await;

    let all_running = snapshot
        .tasks()
        .iter()
        .all(|task| matches!(task.state(), TaskState::Running | TaskState::Starting));

    if all_running && snapshot.failed_tasks() == 0 {
        (StatusCode::OK, "ready")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not ready")
    }
}

/// Starts the health HTTP server on the configured address.
///
/// # Errors
///
/// Returns an error when the server cannot bind or accept connections.
pub async fn run_health_server(
    registry: HealthRegistry,
    listen_addr: &str,
    shutdown: CancellationToken,
) -> Result<(), anyhow::Error> {
    let app = Router::new()
        .route("/healthz", get(healthz_handler))
        .route("/readyz", get(readyz_handler))
        .with_state(registry);

    let listener = tokio::net::TcpListener::bind(listen_addr)
        .await
        .map_err(|e| anyhow::anyhow!("failed to bind health endpoint {listen_addr}: {e}"))?;

    tracing::info!(addr = %listen_addr, "health endpoint listening");

    serve(listener, app)
        .with_graceful_shutdown(async move {
            shutdown.cancelled().await;
        })
        .await
        .map_err(|e| anyhow::anyhow!("health server error: {e}"))
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

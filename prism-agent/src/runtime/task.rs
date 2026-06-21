use std::{future::Future, time::Duration};

use thiserror::Error;
use tokio::{task::JoinHandle, time::timeout};
use tokio_util::sync::CancellationToken;

use crate::runtime::{HealthRegistry, TaskHealthSnapshot, TaskState};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskRuntimeConfig {
    task_shutdown_timeout: Duration,
    queue_drain_timeout: Duration,
}

impl TaskRuntimeConfig {
    #[must_use]
    pub const fn new(task_shutdown_timeout: Duration, queue_drain_timeout: Duration) -> Self {
        Self {
            task_shutdown_timeout,
            queue_drain_timeout,
        }
    }

    #[must_use]
    pub const fn task_shutdown_timeout(self) -> Duration {
        self.task_shutdown_timeout
    }

    #[must_use]
    pub const fn queue_drain_timeout(self) -> Duration {
        self.queue_drain_timeout
    }
}

impl Default for TaskRuntimeConfig {
    fn default() -> Self {
        Self {
            task_shutdown_timeout: Duration::from_secs(5),
            queue_drain_timeout: Duration::from_secs(2),
        }
    }
}

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("task {task} failed: {reason}")]
    TaskFailed { task: String, reason: String },
    #[error("task {task} panicked or was cancelled: {reason}")]
    TaskJoin { task: String, reason: String },
    #[error("task {task} did not stop within {timeout:?}")]
    TaskShutdownTimeout { task: String, timeout: Duration },
    #[error("kernel event queue did not drain within {timeout:?}")]
    QueueDrainTimeout { timeout: Duration },
}

impl RuntimeError {
    #[must_use]
    pub fn task_failed(task: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::TaskFailed {
            task: task.into(),
            reason: reason.into(),
        }
    }
}

#[derive(Debug)]
pub struct ManagedTaskRuntime {
    config: TaskRuntimeConfig,
    cancellation: CancellationToken,
    health: HealthRegistry,
    tasks: Vec<ManagedTask>,
}

impl ManagedTaskRuntime {
    #[must_use]
    pub fn new(config: TaskRuntimeConfig) -> Self {
        Self {
            config,
            cancellation: CancellationToken::new(),
            health: HealthRegistry::new(),
            tasks: Vec::new(),
        }
    }

    #[must_use]
    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    #[must_use]
    pub fn health_registry(&self) -> HealthRegistry {
        self.health.clone()
    }

    pub async fn health_snapshot(&self) -> TaskHealthSnapshot {
        self.health.snapshot().await
    }

    pub async fn spawn<F, Fut>(&mut self, name: impl Into<String>, task: F)
    where
        F: FnOnce(CancellationToken) -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), RuntimeError>> + Send + 'static,
    {
        let name = name.into();
        self.health.set_state(&name, TaskState::Starting).await;
        let health = self.health.clone();
        let task_token = self.cancellation.child_token();
        let task_name = name.clone();
        let handle = tokio::spawn(async move {
            health.set_state(&task_name, TaskState::Running).await;
            task(task_token).await
        });

        self.tasks.push(ManagedTask { name, handle });
    }

    pub fn cancel(&self) {
        self.cancellation.cancel();
    }

    /// Cancels all tasks and waits for them to stop in spawn order.
    ///
    /// # Errors
    ///
    /// Returns the first task failure, join error, or shutdown timeout.
    pub async fn shutdown(mut self) -> Result<(), RuntimeError> {
        self.cancel();
        let mut first_error = None;
        let tasks = std::mem::take(&mut self.tasks);

        for task in tasks {
            if let Err(error) = self.shutdown_task(task).await
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }

        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    async fn shutdown_task(&self, mut task: ManagedTask) -> Result<(), RuntimeError> {
        self.health.set_state(&task.name, TaskState::Stopping).await;

        match timeout(self.config.task_shutdown_timeout(), &mut task.handle).await {
            Ok(Ok(Ok(()))) => {
                self.health.set_state(&task.name, TaskState::Stopped).await;
                Ok(())
            }
            Ok(Ok(Err(error))) => {
                let reason = error.to_string();
                self.health.set_failed(&task.name, reason).await;
                Err(error)
            }
            Ok(Err(error)) => {
                let reason = error.to_string();
                self.health.set_failed(&task.name, reason.clone()).await;
                Err(RuntimeError::TaskJoin {
                    task: task.name,
                    reason,
                })
            }
            Err(_) => {
                task.handle.abort();
                let error = RuntimeError::TaskShutdownTimeout {
                    task: task.name.clone(),
                    timeout: self.config.task_shutdown_timeout(),
                };
                self.health.set_failed(&task.name, error.to_string()).await;
                Err(error)
            }
        }
    }
}

#[derive(Debug)]
struct ManagedTask {
    name: String,
    handle: JoinHandle<Result<(), RuntimeError>>,
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::sync::oneshot;

    use super::*;

    #[tokio::test]
    async fn long_running_task_stops_on_cancellation() {
        let mut runtime = ManagedTaskRuntime::new(TaskRuntimeConfig::new(
            Duration::from_millis(100),
            Duration::from_millis(100),
        ));

        runtime
            .spawn("processor", |token| async move {
                token.cancelled().await;
                Ok(())
            })
            .await;

        runtime.shutdown().await.expect("task should stop");
    }

    #[tokio::test]
    async fn task_failure_is_visible_in_health() {
        let mut runtime = ManagedTaskRuntime::new(TaskRuntimeConfig::default());
        let health = runtime.health_registry();

        runtime
            .spawn("exporter", |_token| async {
                Err(RuntimeError::task_failed("exporter", "send failed"))
            })
            .await;
        let error = runtime
            .shutdown()
            .await
            .expect_err("task failure should propagate");
        let snapshot = health.snapshot().await;

        assert!(matches!(error, RuntimeError::TaskFailed { .. }));
        assert_eq!(snapshot.failed_tasks(), 1);
        assert_eq!(snapshot.state_for("exporter"), Some(TaskState::Failed));
    }

    #[tokio::test]
    async fn shutdown_times_out_unresponsive_task() {
        let mut runtime = ManagedTaskRuntime::new(TaskRuntimeConfig::new(
            Duration::from_millis(5),
            Duration::from_millis(100),
        ));
        let health = runtime.health_registry();
        let (_sender, receiver) = oneshot::channel::<()>();

        runtime
            .spawn("stuck", |_token| async move {
                let _ = receiver.await;
                Ok(())
            })
            .await;
        let error = runtime
            .shutdown()
            .await
            .expect_err("stuck task should time out");
        let snapshot = health.snapshot().await;

        assert!(matches!(error, RuntimeError::TaskShutdownTimeout { .. }));
        assert_eq!(snapshot.state_for("stuck"), Some(TaskState::Failed));
    }

    #[tokio::test]
    async fn cancellation_token_is_shared_with_tasks() {
        let mut runtime = ManagedTaskRuntime::new(TaskRuntimeConfig::default());
        let token = runtime.cancellation_token();
        let (sender, receiver) = oneshot::channel();

        runtime
            .spawn("processor", move |task_token| async move {
                task_token.cancelled().await;
                sender
                    .send(())
                    .map_err(|()| RuntimeError::task_failed("processor", "notify failed"))?;
                Ok(())
            })
            .await;

        token.cancel();
        receiver.await.expect("task should observe cancellation");
        runtime.shutdown().await.expect("shutdown should succeed");
    }
}

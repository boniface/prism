use anyhow::{Context, Result};
#[cfg(target_os = "linux")]
use prism_agent::processors::run_security_processor;
use prism_agent::{
    bpf::{LoadedBpf, reconcile_stale_pins},
    config::AgentConfig,
    metrics::{BpfMetricSource, MetricSnapshotSource, PrometheusServer},
    runtime::{
        ManagedTaskRuntime, TaskRuntimeConfig,
        health::{TaskState, run_health_server},
    },
};
use std::sync::Arc;
use std::time::Duration;
#[cfg(target_os = "linux")]
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

#[tokio::main]
#[allow(clippy::too_many_lines)]
async fn main() -> Result<()> {
    init_tracing()?;

    let config = AgentConfig::load().context("failed to load agent config")?;

    let cleanup = reconcile_stale_pins(config.bpf.pin_path.as_path())
        .context("failed to reconcile stale eBPF pins")?;
    info!(
        removed = cleanup.removed_entries(),
        "reconciled stale eBPF pins"
    );

    let loaded_bpf = if config.network.tc_hooks_enabled {
        LoadedBpf::load_with_tc_hooks(&config.bpf, &config.network.tc_interfaces)
            .context("failed to load eBPF programs with TC hooks")?
    } else {
        LoadedBpf::load(&config.bpf).context("failed to load eBPF programs")?
    };

    let metrics_source: Arc<dyn MetricSnapshotSource> = Arc::new(BpfMetricSource::new(loaded_bpf));
    let prometheus = PrometheusServer::bind(&config.prometheus, metrics_source)
        .await
        .context("failed to bind prometheus exporter")?;
    let shutdown = CancellationToken::new();
    let prometheus_task = tokio::spawn(prometheus.run(shutdown.clone()));

    // Health registry and server
    let health_registry = prism_agent::runtime::health::HealthRegistry::new();
    let health_shutdown = CancellationToken::new();
    let health_shutdown_clone = health_shutdown.clone();
    let health_listen_addr = "127.0.0.1:19091".to_owned();
    let health_registry_clone = health_registry.clone();
    let health_task = tokio::spawn(async move {
        if let Err(e) = run_health_server(
            health_registry_clone,
            &health_listen_addr,
            health_shutdown_clone,
        )
        .await
        {
            error!(error = %e, "health server failed");
        }
    });

    let mut runtime = ManagedTaskRuntime::new(TaskRuntimeConfig::default());
    let token = runtime.cancellation_token();

    #[cfg(target_os = "linux")]
    {
        health_registry
            .set_state("security-processor", TaskState::Starting)
            .await;
        let ebpf_arc = Arc::new(Mutex::new(
            LoadedBpf::load(&config.bpf).context("failed to load eBPF for security processor")?,
        ));
        let ebpf_for_processor = Arc::clone(&ebpf_arc);
        let security_settings = config.security;
        let registry = health_registry.clone();
        runtime
            .spawn("security-processor", move |task_token| async move {
                registry
                    .set_state("security-processor", TaskState::Running)
                    .await;
                let mut guard = ebpf_for_processor.lock().await;
                let result =
                    run_security_processor(guard.ebpf_mut(), task_token, security_settings).await;
                if let Err(e) = &result {
                    registry
                        .set_failed("security-processor", e.to_string())
                        .await;
                } else {
                    registry
                        .set_state("security-processor", TaskState::Stopped)
                        .await;
                }
                result
            })
            .await;
    }

    info!("prism-agent started");
    wait_for_shutdown().await;

    // Begin graceful shutdown with timeout
    info!("shutdown signal received, beginning graceful shutdown");
    let shutdown_start = std::time::Instant::now();
    let graceful_timeout = Duration::from_secs(30);

    // First phase: cancel runtime tasks
    token.cancel();
    info!("runtime tasks cancelled, waiting for shutdown...");

    // Use timeout for runtime shutdown
    let runtime_result = tokio::time::timeout(graceful_timeout, runtime.shutdown()).await;

    match runtime_result {
        Ok(result) => {
            if let Err(e) = result {
                error!(error = %e, "runtime shutdown error");
            } else {
                info!("runtime shutdown completed successfully");
            }
        }
        Err(_) => {
            error!(
                timeout_secs = graceful_timeout.as_secs(),
                "runtime shutdown timed out"
            );
        }
    }

    // Second phase: health server shutdown
    health_shutdown.cancel();
    info!("health server shutdown requested");

    let health_result = tokio::time::timeout(Duration::from_secs(5), health_task).await;

    match health_result {
        Ok(Ok(())) => info!("health server shutdown completed"),
        Ok(Err(_)) => error!("health server shutdown error"),
        Err(_) => warn!("health server shutdown timed out"),
    }

    // Third phase: prometheus exporter shutdown
    shutdown.cancel();
    info!("prometheus exporter shutdown requested");

    let prometheus_result = tokio::time::timeout(Duration::from_secs(5), prometheus_task).await;

    match prometheus_result {
        Ok(Ok(result)) => {
            if let Err(e) = result {
                error!(error = %e, "prometheus exporter error");
            } else {
                info!("prometheus exporter shutdown completed");
            }
        }
        Ok(Err(_)) => error!("prometheus exporter task join error"),
        Err(_) => warn!("prometheus exporter shutdown timed out"),
    }

    let shutdown_duration = shutdown_start.elapsed();
    info!(
        duration_secs = shutdown_duration.as_secs_f64(),
        "graceful shutdown completed"
    );

    info!("prism-agent stopped cleanly");
    Ok(())
}

fn init_tracing() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init()
        .map_err(|e| anyhow::anyhow!("failed to initialize tracing subscriber: {e}"))
}

async fn wait_for_shutdown() {
    let sigterm = async {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let mut sigterm =
                signal(SignalKind::terminate()).expect("failed to register SIGTERM handler");
            sigterm.recv().await;
        }
        #[cfg(not(unix))]
        {
            tokio::signal::ctrl_c().await.ok();
        }
    };

    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            if let Err(source) = result {
                error!(%source, "failed to listen for SIGINT");
            } else {
                info!("received SIGINT shutdown signal");
            }
        }
        () = sigterm => {
            info!("received SIGTERM shutdown signal");
        }
    }

    tokio::time::sleep(Duration::from_millis(100)).await;
}

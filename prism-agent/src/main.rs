use anyhow::{Context, Result};
use prism_agent::{
    bpf::{LoadedBpf, reconcile_stale_pins},
    config::AgentConfig,
    metrics::{BpfMetricSource, MetricSnapshotSource, PrometheusServer},
};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

#[tokio::main]
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
    info!("prism-agent started");

    wait_for_shutdown().await;

    shutdown.cancel();
    prometheus_task
        .await
        .context("failed to join prometheus exporter task")?
        .context("prometheus exporter failed")?;
    info!("prism-agent stopped cleanly");

    Ok(())
}

fn init_tracing() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init()
        .map_err(|source| anyhow::anyhow!("failed to initialize tracing subscriber: {source}"))
}

async fn wait_for_shutdown() {
    let token = CancellationToken::new();
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            if let Err(source) = result {
                error!(%source, "failed to listen for shutdown signal");
            }
        }
        () = token.cancelled() => {}
    }
}

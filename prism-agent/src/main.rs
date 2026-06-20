use anyhow::{Context, Result};
use prism_agent::{
    bpf::{LoadedBpf, reconcile_stale_pins},
    config::AgentConfig,
};
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

    let loaded_bpf = LoadedBpf::load(&config.bpf).context("failed to load eBPF lifecycle proof")?;
    info!("prism-agent started");

    wait_for_shutdown().await;

    loaded_bpf.shutdown();
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

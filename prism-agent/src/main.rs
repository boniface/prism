use anyhow::{Context, Result};
use prism_agent::{
    bpf::{LoadedBpf, reconcile_stale_pins},
    config::AgentConfig,
    processors::run_security_processor,
    runtime::{ManagedTaskRuntime, TaskRuntimeConfig},
};
use std::sync::Arc;
use tokio::sync::Mutex;
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

    let mut runtime = ManagedTaskRuntime::new(TaskRuntimeConfig::default());
    let token = runtime.cancellation_token();

    #[cfg(target_os = "linux")]
    {
        let ebpf = Arc::new(Mutex::new(loaded_bpf));
        let ebpf_for_processor = Arc::clone(&ebpf);

        runtime
            .spawn("security-processor", move |task_token| async move {
                let mut guard = ebpf_for_processor.lock().await;
                run_security_processor(guard.ebpf_mut(), task_token).await
            })
            .await;

        info!("prism-agent started");
        wait_for_shutdown().await;

        token.cancel();
        if let Err(e) = runtime.shutdown().await {
            error!(error = %e, "runtime shutdown error");
        }

        let bpf = Arc::try_unwrap(ebpf)
            .map_err(|_| anyhow::anyhow!("eBPF handle still referenced at shutdown"))?
            .into_inner();
        bpf.shutdown();
    }

    #[cfg(not(target_os = "linux"))]
    {
        info!("prism-agent started");
        wait_for_shutdown().await;
        token.cancel();
        let _ = runtime.shutdown().await;
        loaded_bpf.shutdown();
    }

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
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            if let Err(source) = result {
                error!(%source, "failed to listen for shutdown signal");
            }
        }
    }
}

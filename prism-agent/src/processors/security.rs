use aya::Ebpf;
use aya::maps::RingBuf;
use prism_core::events::security::ProcessExecEvent;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::runtime::RuntimeError;

const SECURITY_RING_BUF_NAME: &str = "SECURITY_EVENTS";

/// Reads `ProcessExecEvent` records from the eBPF ring buffer and logs them.
///
/// # Errors
///
/// Returns an error when the ring buffer map cannot be found in the loaded
/// eBPF object.
pub async fn run_security_processor(
    ebpf: &mut Ebpf,
    token: CancellationToken,
) -> Result<(), RuntimeError> {
    let map = ebpf.map_mut(SECURITY_RING_BUF_NAME).ok_or_else(|| {
        RuntimeError::task_failed(
            "security-processor",
            format!("ring buffer map not found: {SECURITY_RING_BUF_NAME}"),
        )
    })?;

    let mut ring_buf = RingBuf::try_from(map).map_err(|e| {
        RuntimeError::task_failed(
            "security-processor",
            format!("failed to open ring buffer: {e}"),
        )
    })?;

    info!("security processor started");

    loop {
        tokio::select! {
            () = token.cancelled() => {
                info!("security processor stopping");
                break;
            }
            () = tokio::time::sleep(tokio::time::Duration::from_millis(10)) => {
                while let Some(item) = ring_buf.next() {
                    let bytes = item.as_ref();
                    if bytes.len() < core::mem::size_of::<ProcessExecEvent>() {
                        warn!(
                            len = bytes.len(),
                            expected = core::mem::size_of::<ProcessExecEvent>(),
                            "security event too short — skipping"
                        );
                        continue;
                    }
                    let mut raw = [0u8; core::mem::size_of::<ProcessExecEvent>()];
                    raw.copy_from_slice(&bytes[..core::mem::size_of::<ProcessExecEvent>()]);
                    let event: ProcessExecEvent = bytemuck::pod_read_unaligned(&raw);
                    let comm = String::from_utf8_lossy(
                        &event.comm[..event.comm_len.min(16) as usize],
                    );
                    info!(
                        pid = event.pid,
                        ppid = event.ppid,
                        uid = event.uid,
                        gid = event.gid,
                        comm = %comm,
                        timestamp_ns = event.timestamp_ns,
                        "process exec event"
                    );
                }
            }
        }
    }

    Ok(())
}

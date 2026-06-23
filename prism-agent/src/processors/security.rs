use aya::Ebpf;
use aya::maps::{MapData, RingBuf};
use prism_core::events::security::{FileAccessEvent, ProcessExecEvent};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::runtime::RuntimeError;

const SECURITY_RING_BUF_NAME: &str = "SECURITY_EVENTS";
const FILE_ACCESS_RING_BUF_NAME: &str = "FILE_ACCESS_EVENTS";

/// Reads `ProcessExecEvent` and `FileAccessEvent` records from eBPF ring
/// buffers and logs them.
///
/// # Errors
///
/// Returns an error when a ring buffer map cannot be found in the loaded
/// eBPF object.
pub async fn run_security_processor(
    ebpf: &mut Ebpf,
    token: CancellationToken,
) -> Result<(), RuntimeError> {
    let exec_map = ebpf.take_map(SECURITY_RING_BUF_NAME).ok_or_else(|| {
        RuntimeError::task_failed(
            "security-processor",
            format!("ring buffer map not found: {SECURITY_RING_BUF_NAME}"),
        )
    })?;

    let mut exec_ring = RingBuf::<MapData>::try_from(exec_map).map_err(|e| {
        RuntimeError::task_failed(
            "security-processor",
            format!("failed to open exec ring buffer: {e}"),
        )
    })?;

    let file_map = ebpf.take_map(FILE_ACCESS_RING_BUF_NAME).ok_or_else(|| {
        RuntimeError::task_failed(
            "security-processor",
            format!("ring buffer map not found: {FILE_ACCESS_RING_BUF_NAME}"),
        )
    })?;

    let mut file_ring = RingBuf::<MapData>::try_from(file_map).map_err(|e| {
        RuntimeError::task_failed(
            "security-processor",
            format!("failed to open file access ring buffer: {e}"),
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
                process_exec_events(&mut exec_ring);
                process_file_access_events(&mut file_ring);
            }
        }
    }

    Ok(())
}

fn process_exec_events(ring: &mut RingBuf<MapData>) {
    while let Some(item) = ring.next() {
        let bytes = item.as_ref();
        if bytes.len() < core::mem::size_of::<ProcessExecEvent>() {
            warn!(
                len = bytes.len(),
                expected = core::mem::size_of::<ProcessExecEvent>(),
                "exec event too short — skipping"
            );
            continue;
        }
        let mut raw = [0u8; core::mem::size_of::<ProcessExecEvent>()];
        raw.copy_from_slice(&bytes[..core::mem::size_of::<ProcessExecEvent>()]);
        let event: ProcessExecEvent = bytemuck::pod_read_unaligned(&raw);
        let comm = String::from_utf8_lossy(&event.comm[..event.comm_len.min(16) as usize]);
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

fn process_file_access_events(ring: &mut RingBuf<MapData>) {
    while let Some(item) = ring.next() {
        let bytes = item.as_ref();
        if bytes.len() < core::mem::size_of::<FileAccessEvent>() {
            warn!(
                len = bytes.len(),
                expected = core::mem::size_of::<FileAccessEvent>(),
                "file access event too short — skipping"
            );
            continue;
        }
        let mut raw = [0u8; core::mem::size_of::<FileAccessEvent>()];
        raw.copy_from_slice(&bytes[..core::mem::size_of::<FileAccessEvent>()]);
        let event: FileAccessEvent = bytemuck::pod_read_unaligned(&raw);
        let path = String::from_utf8_lossy(&event.path[..event.path_len.min(128) as usize]);
        info!(
            pid = event.pid,
            uid = event.uid,
            cgroup_id = event.cgroup_id,
            path = %path,
            timestamp_ns = event.timestamp_ns,
            "file access event"
        );
    }
}

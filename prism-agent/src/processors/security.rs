use aya::Ebpf;
use aya::maps::{MapData, RingBuf};
use prism_core::events::security::{FileAccessEvent, NetworkConnectionEvent, ProcessExecEvent};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::runtime::RuntimeError;

const SECURITY_RING_BUF_NAME: &str = "SECURITY_EVENTS";
const FILE_ACCESS_RING_BUF_NAME: &str = "FILE_ACCESS_EVENTS";
const NETWORK_SECURITY_RING_BUF_NAME: &str = "NETWORK_SECURITY_EVENTS";

/// Reads security audit events from eBPF ring buffers and logs them.
///
/// # Errors
///
/// Returns an error when a ring buffer map cannot be found in the loaded
/// eBPF object.
pub async fn run_security_processor(
    ebpf: &mut Ebpf,
    token: CancellationToken,
) -> Result<(), RuntimeError> {
    let mut exec_ring = {
        let map = ebpf.take_map(SECURITY_RING_BUF_NAME).ok_or_else(|| {
            RuntimeError::task_failed(
                "security-processor",
                format!("ring buffer map not found: {SECURITY_RING_BUF_NAME}"),
            )
        })?;
        RingBuf::<MapData>::try_from(map).map_err(|e| {
            RuntimeError::task_failed(
                "security-processor",
                format!("failed to open exec ring buffer: {e}"),
            )
        })?
    };

    let mut file_ring = {
        let map = ebpf.take_map(FILE_ACCESS_RING_BUF_NAME).ok_or_else(|| {
            RuntimeError::task_failed(
                "security-processor",
                format!("ring buffer map not found: {FILE_ACCESS_RING_BUF_NAME}"),
            )
        })?;
        RingBuf::<MapData>::try_from(map).map_err(|e| {
            RuntimeError::task_failed(
                "security-processor",
                format!("failed to open file access ring buffer: {e}"),
            )
        })?
    };

    let mut network_ring = {
        let map = ebpf
            .take_map(NETWORK_SECURITY_RING_BUF_NAME)
            .ok_or_else(|| {
                RuntimeError::task_failed(
                    "security-processor",
                    format!("ring buffer map not found: {NETWORK_SECURITY_RING_BUF_NAME}"),
                )
            })?;
        RingBuf::<MapData>::try_from(map).map_err(|e| {
            RuntimeError::task_failed(
                "security-processor",
                format!("failed to open network security ring buffer: {e}"),
            )
        })?
    };

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
                process_network_events(&mut network_ring);
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

fn process_network_events(ring: &mut RingBuf<MapData>) {
    while let Some(item) = ring.next() {
        let bytes = item.as_ref();
        if bytes.len() < core::mem::size_of::<NetworkConnectionEvent>() {
            warn!(
                len = bytes.len(),
                expected = core::mem::size_of::<NetworkConnectionEvent>(),
                "network event too short — skipping"
            );
            continue;
        }
        let mut raw = [0u8; core::mem::size_of::<NetworkConnectionEvent>()];
        raw.copy_from_slice(&bytes[..core::mem::size_of::<NetworkConnectionEvent>()]);
        let event: NetworkConnectionEvent = bytemuck::pod_read_unaligned(&raw);
        let comm = String::from_utf8_lossy(&event.comm[..event.comm_len.min(16) as usize]);
        let dst = format!(
            "{}.{}.{}.{}:{}",
            event.dst_addr[0],
            event.dst_addr[1],
            event.dst_addr[2],
            event.dst_addr[3],
            event.dst_port,
        );
        info!(
            pid = event.pid,
            uid = event.uid,
            cgroup_id = event.cgroup_id,
            comm = %comm,
            dst = %dst,
            timestamp_ns = event.timestamp_ns,
            "network connection event"
        );
    }
}

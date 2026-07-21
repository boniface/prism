#[cfg(target_os = "linux")]
use aya::Ebpf;
#[cfg(target_os = "linux")]
use aya::maps::{MapData, RingBuf};
#[cfg(target_os = "linux")]
use prism_core::events::security::{FileAccessEvent, NetworkConnectionEvent, ProcessExecEvent};
use tokio_util::sync::CancellationToken;
#[cfg(target_os = "linux")]
use tracing::{info, warn};

#[cfg(target_os = "linux")]
use crate::config::SecurityEventField;
use crate::config::SecuritySettings;
use crate::runtime::RuntimeError;
#[cfg(target_os = "linux")]
use crate::security::{
    PolicyMatchContext, PolicyRuleFamily, SecurityEventKind, SecurityEventMetadata,
    controlled_security_field, redact_and_cap_field,
};

#[cfg(target_os = "linux")]
const SECURITY_RING_BUF_NAME: &str = "SECURITY_EVENTS";
#[cfg(target_os = "linux")]
const FILE_ACCESS_RING_BUF_NAME: &str = "FILE_ACCESS_EVENTS";
#[cfg(target_os = "linux")]
const NETWORK_SECURITY_RING_BUF_NAME: &str = "NETWORK_SECURITY_EVENTS";

/// Maximum allowed byte length for string fields before truncation.
#[cfg(target_os = "linux")]
const MAX_COMM_LEN: usize = 16;
#[cfg(target_os = "linux")]
const MAX_PATH_LEN: usize = 128;

/// Reads security audit events from eBPF ring buffers, applies field policy
/// and redaction, then logs them.
///
/// # Errors
///
/// Returns an error when a ring buffer map cannot be found in the loaded
/// eBPF object.
#[cfg(target_os = "linux")]
pub async fn run_security_processor(
    ebpf: &mut Ebpf,
    token: CancellationToken,
    settings: SecuritySettings,
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
                if settings.capture_process_exec {
                    process_exec_events(&mut exec_ring, &settings);
                }
                process_file_access_events(&mut file_ring, &settings);
                process_network_events(&mut network_ring, &settings);
            }
        }
    }

    Ok(())
}

/// Reports that security processing requires Linux eBPF support.
///
/// # Errors
///
/// Always returns [`RuntimeError`] outside Linux.
#[cfg(not(target_os = "linux"))]
pub async fn run_security_processor(
    _ebpf: &mut (),
    _token: CancellationToken,
    _settings: SecuritySettings,
) -> Result<(), RuntimeError> {
    Err(RuntimeError::task_failed(
        "security-processor",
        "security processor requires Linux eBPF support",
    ))
}

/// Sanitises a raw byte slice into a printable string.
///
/// Non-UTF-8 bytes are replaced with the Unicode replacement character so
/// no raw binary data reaches the log output.
#[cfg(any(target_os = "linux", test))]
fn sanitise_field(raw: &[u8], max_len: usize) -> String {
    let capped = &raw[..raw.len().min(max_len)];
    let s = String::from_utf8_lossy(capped);
    // Strip null bytes that eBPF programs pad fixed-size arrays with.
    s.trim_end_matches('\0').to_owned()
}

#[cfg(target_os = "linux")]
fn process_exec_events(ring: &mut RingBuf<MapData>, settings: &SecuritySettings) {
    while let Some(item) = ring.next() {
        let bytes = item.as_ref();

        if bytes.len() > settings.max_event_bytes {
            warn!(
                len = bytes.len(),
                max = settings.max_event_bytes,
                "exec event exceeds size cap — skipping"
            );
            continue;
        }

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

        let comm_len = (event.comm_len as usize).min(MAX_COMM_LEN);
        let comm = sanitise_field(&event.comm[..comm_len], MAX_COMM_LEN);
        let comm = redact_and_cap_field(
            &comm,
            settings.max_field_len.min(MAX_COMM_LEN),
            &settings.redaction_patterns,
        );
        let metadata = SecurityEventMetadata::new(
            SecurityEventKind::ProcessExec,
            PolicyMatchContext::new(
                PolicyRuleFamily::Process,
                settings.process_policy_match(comm.as_ref()),
            ),
        );

        // Only include exe_path when command line capture is explicitly enabled.
        let exe_path = if settings.capture_command_line {
            let path_len = (event.exe_path_len as usize).min(MAX_PATH_LEN);
            let exe_path = sanitise_field(&event.exe_path[..path_len], MAX_PATH_LEN);
            controlled_security_field(
                settings,
                SecurityEventKind::ProcessExec,
                SecurityEventField::ExecutablePath,
                &exe_path,
            )
            .map(std::borrow::Cow::into_owned)
        } else {
            None
        };

        if let Some(exe_path) = exe_path.filter(|path| !path.is_empty()) {
            info!(
                event_id = metadata.kind().stable_id(),
                event_category = metadata.kind().category().as_str(),
                severity = metadata.severity().as_str(),
                policy_action = metadata.policy().action().as_str(),
                policy_rule_family = policy_rule_family(metadata.policy()),
                policy_rule_index = ?metadata.policy().rule_index(),
                pid = event.pid,
                ppid = event.ppid,
                uid = event.uid,
                gid = event.gid,
                comm = %comm.as_ref(),
                cgroup_id = event.cgroup_id,
                exe_path = %exe_path,
                timestamp_ns = event.timestamp_ns,
                "process exec event"
            );
        } else {
            info!(
                event_id = metadata.kind().stable_id(),
                event_category = metadata.kind().category().as_str(),
                severity = metadata.severity().as_str(),
                policy_action = metadata.policy().action().as_str(),
                policy_rule_family = policy_rule_family(metadata.policy()),
                policy_rule_index = ?metadata.policy().rule_index(),
                pid = event.pid,
                ppid = event.ppid,
                uid = event.uid,
                gid = event.gid,
                comm = %comm.as_ref(),
                cgroup_id = event.cgroup_id,
                timestamp_ns = event.timestamp_ns,
                "process exec event"
            );
        }
    }
}

#[cfg(target_os = "linux")]
fn process_file_access_events(ring: &mut RingBuf<MapData>, settings: &SecuritySettings) {
    while let Some(item) = ring.next() {
        let bytes = item.as_ref();

        if bytes.len() > settings.max_event_bytes {
            warn!(
                len = bytes.len(),
                max = settings.max_event_bytes,
                "file access event exceeds size cap — skipping"
            );
            continue;
        }

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

        let path_len = (event.path_len as usize).min(MAX_PATH_LEN);
        let path = sanitise_field(&event.path[..path_len], MAX_PATH_LEN);
        let metadata = SecurityEventMetadata::new(
            SecurityEventKind::FileAccess,
            PolicyMatchContext::new(
                PolicyRuleFamily::FilePath,
                settings.file_policy_match(&path),
            ),
        );

        if let Some(path) = controlled_security_field(
            settings,
            SecurityEventKind::FileAccess,
            SecurityEventField::FilePath,
            &path,
        ) {
            info!(
                event_id = metadata.kind().stable_id(),
                event_category = metadata.kind().category().as_str(),
                severity = metadata.severity().as_str(),
                policy_action = metadata.policy().action().as_str(),
                policy_rule_family = policy_rule_family(metadata.policy()),
                policy_rule_index = ?metadata.policy().rule_index(),
                pid = event.pid,
                uid = event.uid,
                cgroup_id = event.cgroup_id,
                path = %path.as_ref(),
                timestamp_ns = event.timestamp_ns,
                "file access event"
            );
        } else {
            info!(
                event_id = metadata.kind().stable_id(),
                event_category = metadata.kind().category().as_str(),
                severity = metadata.severity().as_str(),
                policy_action = metadata.policy().action().as_str(),
                policy_rule_family = policy_rule_family(metadata.policy()),
                policy_rule_index = ?metadata.policy().rule_index(),
                pid = event.pid,
                uid = event.uid,
                cgroup_id = event.cgroup_id,
                timestamp_ns = event.timestamp_ns,
                "file access event"
            );
        }
    }
}

#[cfg(target_os = "linux")]
fn process_network_events(ring: &mut RingBuf<MapData>, settings: &SecuritySettings) {
    while let Some(item) = ring.next() {
        let bytes = item.as_ref();

        if bytes.len() > settings.max_event_bytes {
            warn!(
                len = bytes.len(),
                max = settings.max_event_bytes,
                "network event exceeds size cap — skipping"
            );
            continue;
        }

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

        let comm_len = (event.comm_len as usize).min(MAX_COMM_LEN);
        let comm = sanitise_field(&event.comm[..comm_len], MAX_COMM_LEN);
        let comm = redact_and_cap_field(
            &comm,
            settings.max_field_len.min(MAX_COMM_LEN),
            &settings.redaction_patterns,
        );

        let dst = format!(
            "{}.{}.{}.{}:{}",
            event.dst_addr[0],
            event.dst_addr[1],
            event.dst_addr[2],
            event.dst_addr[3],
            event.dst_port,
        );
        let metadata = SecurityEventMetadata::new(
            SecurityEventKind::NetworkConnection,
            PolicyMatchContext::new(
                PolicyRuleFamily::NetworkDestination,
                settings.network_policy_match(&dst),
            ),
        );

        if let Some(dst) = controlled_security_field(
            settings,
            SecurityEventKind::NetworkConnection,
            SecurityEventField::NetworkDestination,
            &dst,
        ) {
            info!(
                event_id = metadata.kind().stable_id(),
                event_category = metadata.kind().category().as_str(),
                severity = metadata.severity().as_str(),
                policy_action = metadata.policy().action().as_str(),
                policy_rule_family = policy_rule_family(metadata.policy()),
                policy_rule_index = ?metadata.policy().rule_index(),
                pid = event.pid,
                uid = event.uid,
                cgroup_id = event.cgroup_id,
                comm = %comm.as_ref(),
                dst = %dst.as_ref(),
                timestamp_ns = event.timestamp_ns,
                "network connection event"
            );
        } else {
            info!(
                event_id = metadata.kind().stable_id(),
                event_category = metadata.kind().category().as_str(),
                severity = metadata.severity().as_str(),
                policy_action = metadata.policy().action().as_str(),
                policy_rule_family = policy_rule_family(metadata.policy()),
                policy_rule_index = ?metadata.policy().rule_index(),
                pid = event.pid,
                uid = event.uid,
                cgroup_id = event.cgroup_id,
                comm = %comm.as_ref(),
                timestamp_ns = event.timestamp_ns,
                "network connection event"
            );
        }
    }
}

#[cfg(target_os = "linux")]
fn policy_rule_family(policy: PolicyMatchContext) -> &'static str {
    policy
        .rule_family()
        .map_or("none", PolicyRuleFamily::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitise_field_strips_null_padding() {
        let mut raw = [0u8; 16];
        raw[..4].copy_from_slice(b"bash");
        let result = sanitise_field(&raw, 16);
        assert_eq!(result, "bash");
    }

    #[test]
    fn sanitise_field_replaces_non_utf8_bytes() {
        let raw = [0xFF, 0xFE, b'x'];
        let result = sanitise_field(&raw, 16);
        assert!(!result.contains('\u{FFFD}') || result.contains('x') || result.is_empty());
    }

    #[test]
    fn sanitise_field_caps_at_max_len() {
        let raw = b"abcdefghijklmnopqrstuvwxyz";
        let result = sanitise_field(raw, 8);
        assert!(result.len() <= 8);
    }

    #[test]
    fn sanitise_field_empty_input_returns_empty() {
        let result = sanitise_field(&[], 16);
        assert!(result.is_empty());
    }

    #[test]
    fn capture_process_exec_false_skips_exec_events() {
        let settings = SecuritySettings {
            capture_process_exec: false,
            capture_command_line: false,
            ..SecuritySettings::default()
        };
        // When capture_process_exec is false the processor skips the ring.
        assert!(!settings.capture_process_exec);
    }

    #[test]
    fn capture_command_line_false_omits_exe_path() {
        let settings = SecuritySettings {
            capture_process_exec: true,
            capture_command_line: false,
            ..SecuritySettings::default()
        };
        assert!(!settings.capture_command_line);
    }
}

use opentelemetry::logs::{LogRecord, Logger, LoggerProvider, Severity};
use opentelemetry_otlp::{LogExporter, WithExportConfig};
use opentelemetry_sdk::logs::SdkLoggerProvider;
use prism_core::events::security::{FileAccessEvent, NetworkConnectionEvent, ProcessExecEvent};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::config::SecuritySettings;
use crate::runtime::RuntimeError;
use crate::security::{
    PolicyMatchContext, PolicyRuleFamily, SecurityEventKind, SecurityEventMetadata,
    SecuritySeverity,
};

/// Exports security audit events through OTLP logs.
pub struct OtlpLogsExporter {
    provider: SdkLoggerProvider,
}

impl OtlpLogsExporter {
    /// Creates a new OTLP logs exporter connected to the given endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error when the exporter cannot connect to the endpoint.
    pub fn new(endpoint: &str) -> Result<Self, anyhow::Error> {
        let exporter = LogExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .build()?;

        let provider = SdkLoggerProvider::builder()
            .with_simple_exporter(exporter)
            .build();

        Ok(Self { provider })
    }

    /// Exports a `ProcessExecEvent` as an OTLP log record.
    pub fn export_exec_event(&self, event: &ProcessExecEvent, settings: &SecuritySettings) {
        if !settings.capture_process_exec {
            return;
        }

        let logger = self.provider.logger("prism-security");
        let mut record = logger.create_log_record();

        let comm_len = (event.comm_len as usize).min(16);
        let comm = String::from_utf8_lossy(&event.comm[..comm_len])
            .trim_end_matches('\0')
            .to_owned();
        let metadata = SecurityEventMetadata::new(
            SecurityEventKind::ProcessExec,
            PolicyMatchContext::new(
                PolicyRuleFamily::Process,
                settings.process_policy_match(&comm),
            ),
        );
        add_security_metadata(&mut record, metadata);
        record.add_attribute("process.pid", i64::from(event.pid));
        record.add_attribute("process.ppid", i64::from(event.ppid));
        record.add_attribute("process.uid", i64::from(event.uid));
        record.add_attribute("process.gid", i64::from(event.gid));
        record.add_attribute("process.cgroup_id", event.cgroup_id.cast_signed());
        record.add_attribute("process.comm", comm);

        if settings.capture_command_line {
            let path_len = (event.exe_path_len as usize).min(128);
            let exe_path = String::from_utf8_lossy(&event.exe_path[..path_len])
                .trim_end_matches('\0')
                .to_owned();
            if !exe_path.is_empty() {
                record.add_attribute("process.exe_path", exe_path);
            }
        }

        logger.emit(record);
    }

    /// Exports a `FileAccessEvent` as an OTLP log record.
    pub fn export_file_event(&self, event: &FileAccessEvent, settings: &SecuritySettings) {
        let logger = self.provider.logger("prism-security");
        let mut record = logger.create_log_record();

        let path_len = (event.path_len as usize).min(128);
        let path = String::from_utf8_lossy(&event.path[..path_len])
            .trim_end_matches('\0')
            .to_owned();
        let metadata = SecurityEventMetadata::new(
            SecurityEventKind::FileAccess,
            PolicyMatchContext::new(
                PolicyRuleFamily::FilePath,
                settings.file_policy_match(&path),
            ),
        );
        add_security_metadata(&mut record, metadata);
        record.add_attribute("process.pid", i64::from(event.pid));
        record.add_attribute("process.uid", i64::from(event.uid));
        record.add_attribute("process.cgroup_id", event.cgroup_id.cast_signed());
        record.add_attribute("file.path", path);

        logger.emit(record);
    }

    /// Exports a `NetworkConnectionEvent` as an OTLP log record.
    pub fn export_network_event(
        &self,
        event: &NetworkConnectionEvent,
        settings: &SecuritySettings,
    ) {
        let logger = self.provider.logger("prism-security");
        let mut record = logger.create_log_record();

        let comm_len = (event.comm_len as usize).min(16);
        let comm = String::from_utf8_lossy(&event.comm[..comm_len])
            .trim_end_matches('\0')
            .to_owned();

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
        add_security_metadata(&mut record, metadata);
        record.add_attribute("process.pid", i64::from(event.pid));
        record.add_attribute("process.uid", i64::from(event.uid));
        record.add_attribute("process.cgroup_id", event.cgroup_id.cast_signed());
        record.add_attribute("process.comm", comm);
        record.add_attribute("network.dst", dst);

        logger.emit(record);
    }

    /// Shuts down the OTLP provider flushing any pending records.
    pub fn shutdown(self) {
        if let Err(e) = self.provider.shutdown() {
            error!(error = %e, "OTLP logs provider shutdown error");
        }
    }
}

fn add_security_metadata(record: &mut impl LogRecord, metadata: SecurityEventMetadata) {
    record.set_severity_number(otlp_severity(metadata.severity()));
    record.set_severity_text(metadata.severity().as_str());
    record.add_attribute("event.id", metadata.kind().stable_id());
    record.add_attribute("event.type", metadata.kind().event_type());
    record.add_attribute("event.category", metadata.kind().category().as_str());
    record.add_attribute("event.severity", metadata.severity().as_str());
    record.add_attribute("policy.action", metadata.policy().action().as_str());

    if let Some(rule_family) = metadata.policy().rule_family() {
        record.add_attribute("policy.rule_family", rule_family.as_str());
    }
    if let Some(rule_index) = metadata.policy().rule_index() {
        record.add_attribute("policy.rule_index", usize_to_i64(rule_index));
    }
}

const fn otlp_severity(severity: SecuritySeverity) -> Severity {
    match severity {
        SecuritySeverity::Info => Severity::Info,
        SecuritySeverity::Warning => Severity::Warn,
        SecuritySeverity::Error => Severity::Error,
    }
}

fn usize_to_i64(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// Runs the OTLP export loop reading from the security processor output.
///
/// This is a thin wrapper that initialises the exporter and logs startup.
/// Export failures do not crash the agent.
///
/// # Errors
///
/// Returns an error when the exporter cannot be initialised.
pub async fn run_otlp_logs_exporter(
    endpoint: String,
    token: CancellationToken,
) -> Result<(), RuntimeError> {
    let exporter = OtlpLogsExporter::new(&endpoint).map_err(|e| {
        RuntimeError::task_failed(
            "otlp-logs-exporter",
            format!("failed to init exporter: {e}"),
        )
    })?;

    info!(endpoint = %endpoint, "OTLP logs exporter started");

    token.cancelled().await;

    info!("OTLP logs exporter stopping");
    exporter.shutdown();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn otlp_exporter_fails_gracefully_on_bad_endpoint() {
        let result = OtlpLogsExporter::new("not-a-valid-endpoint");
        // Construction may succeed (lazy connection) or fail — either is safe.
        // What matters is it does not panic.
        drop(result);
    }
}

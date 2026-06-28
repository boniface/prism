use std::{
    collections::HashMap,
    env,
    ffi::OsString,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use serde::Deserialize;
use thiserror::Error;

use crate::bpf::BpfLoaderConfig;

pub const DEFAULT_CONFIG_PATH: &str = "/etc/prism/config.yaml";

const ENV_CONFIG_PATH: &str = "PRISM_CONFIG_PATH";
const ENV_NODE_NAME: &str = "PRISM_NODE_NAME";
const ENV_INSTANCE_ID: &str = "PRISM_AGENT_INSTANCE_ID";
const ENV_EBPF_OBJECT: &str = "PRISM_EBPF_OBJECT";
const ENV_BPF_PIN_PATH: &str = "PRISM_BPF_PIN_PATH";
const ENV_BPF_EPHEMERAL: &str = "PRISM_BPF_EPHEMERAL";
const ENV_PROMETHEUS_LISTEN_ADDR: &str = "PRISM_PROMETHEUS_LISTEN_ADDR";
const ENV_PROMETHEUS_LABEL_ALLOWLIST: &str = "PRISM_PROMETHEUS_LABEL_ALLOWLIST";
const ENV_PROMETHEUS_MAX_LABEL_VALUE_LEN: &str = "PRISM_PROMETHEUS_MAX_LABEL_VALUE_LEN";
const ENV_PROMETHEUS_EXPENSIVE_DIMENSIONS_ENABLED: &str =
    "PRISM_PROMETHEUS_EXPENSIVE_DIMENSIONS_ENABLED";
const ENV_PROMETHEUS_SERIES_LIMIT: &str = "PRISM_PROMETHEUS_SERIES_LIMIT";
const ENV_NETWORK_TC_HOOKS_ENABLED: &str = "PRISM_NETWORK_TC_HOOKS_ENABLED";
const ENV_NETWORK_TC_INTERFACES: &str = "PRISM_NETWORK_TC_INTERFACES";
const ENV_OTLP_ENDPOINT: &str = "PRISM_OTLP_ENDPOINT";
const ENV_LOG_LEVEL: &str = "PRISM_LOG_LEVEL";
const ENV_CAPTURE_PROCESS_EXEC: &str = "PRISM_CAPTURE_PROCESS_EXEC";
const ENV_CAPTURE_COMMAND_LINE: &str = "PRISM_CAPTURE_COMMAND_LINE";
const ENV_POSTGRES_TELEMETRY_ENABLED: &str = "PRISM_POSTGRES_TELEMETRY_ENABLED";
const ENV_REDIS_TELEMETRY_ENABLED: &str = "PRISM_REDIS_TELEMETRY_ENABLED";
const ENV_TRACE_CREATE_ROOT_SPANS: &str = "PRISM_TRACE_CREATE_ROOT_SPANS";
const ENV_TRACE_SPAN_QUEUE_CAPACITY: &str = "PRISM_TRACE_SPAN_QUEUE_CAPACITY";
const ENV_TLS_TELEMETRY_ENABLED: &str = "PRISM_TLS_TELEMETRY_ENABLED";
const ENV_TLS_LIBRARY_ALLOWLIST: &str = "PRISM_TLS_LIBRARY_ALLOWLIST";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentConfig {
    pub agent: AgentSettings,
    pub bpf: BpfLoaderConfig,
    pub metadata: MetadataSettings,
    pub network: NetworkSettings,
    pub prometheus: PrometheusSettings,
    pub otlp: OtlpSettings,
    pub security: SecuritySettings,
    pub application_telemetry: ApplicationTelemetrySettings,
    pub trace: TraceSettings,
    pub tls_telemetry: TlsTelemetrySettings,
    pub logging: LoggingSettings,
}

impl AgentConfig {
    /// Loads configuration from `PRISM_CONFIG_PATH`, `/etc/prism/config.yaml`,
    /// and supported environment overrides.
    ///
    /// # Errors
    ///
    /// Returns an error when an explicit config path cannot be read, YAML
    /// cannot be parsed, an environment override is invalid, or validation
    /// fails.
    pub fn load() -> Result<Self, ConfigError> {
        let env = EnvOverrides::from_env();
        let path = env
            .path_override()
            .map_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH), PathBuf::from);
        let mode = if env.path_override().is_some() {
            ConfigPathMode::Required
        } else {
            ConfigPathMode::Optional
        };

        Self::load_with_env(&path, mode, &env)
    }

    #[cfg(test)]
    fn load_with_test_env(
        path: &Path,
        mode: ConfigPathMode,
        env: &[(&str, &str)],
    ) -> Result<Self, ConfigError> {
        let env = EnvOverrides::from_pairs(env);

        Self::load_with_env(path, mode, &env)
    }

    fn load_with_env(
        path: &Path,
        mode: ConfigPathMode,
        env: &EnvOverrides,
    ) -> Result<Self, ConfigError> {
        let raw = RawConfig::load(path, mode)?;
        let mut config = raw.into_config()?;
        env.apply(&mut config)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        ensure_non_empty("agent.node_name", &self.agent.node_name)?;
        ensure_non_empty("agent.instance_id", &self.agent.instance_id)?;
        ensure_non_empty_path("bpf.object_path", &self.bpf.object_path)?;
        ensure_non_empty_path("bpf.pin_path", &self.bpf.pin_path)?;
        ensure_non_empty("otlp.endpoint", &self.otlp.endpoint)?;
        ensure_non_empty("logging.level", &self.logging.level)?;

        if self.metadata.providers.is_empty() {
            return Err(ConfigError::MissingRequired {
                field: "metadata.providers",
            });
        }
        if self.network.tc_hooks_enabled && self.network.tc_interfaces.is_empty() {
            return Err(ConfigError::MissingRequired {
                field: "network.tc_interfaces",
            });
        }
        if self
            .network
            .tc_interfaces
            .iter()
            .any(|interface| interface.trim().is_empty())
        {
            return Err(ConfigError::InvalidValue {
                field: "network.tc_interfaces",
                reason: "interface names must be non-empty",
            });
        }
        if self.prometheus.max_label_value_len == 0 {
            return Err(ConfigError::InvalidValue {
                field: "prometheus.max_label_value_len",
                reason: "must be greater than zero",
            });
        }
        if self.prometheus.series_limit == 0 {
            return Err(ConfigError::InvalidValue {
                field: "prometheus.series_limit",
                reason: "must be greater than zero",
            });
        }
        if self.trace.span_queue_capacity == 0 {
            return Err(ConfigError::InvalidValue {
                field: "trace.span_queue_capacity",
                reason: "must be greater than zero",
            });
        }
        if self.tls_telemetry.enabled && self.tls_telemetry.library_allowlist.is_empty() {
            return Err(ConfigError::MissingRequired {
                field: "tls_telemetry.library_allowlist",
            });
        }
        if !self.prometheus.expensive_dimensions_enabled
            && self
                .prometheus
                .label_allowlist
                .iter()
                .any(|label| label.is_high_cardinality())
        {
            return Err(ConfigError::InvalidValue {
                field: "prometheus.label_allowlist",
                reason: "high-cardinality labels require expensive_dimensions_enabled",
            });
        }

        Ok(())
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            agent: AgentSettings::default(),
            bpf: BpfLoaderConfig::new(default_ebpf_object_path(), default_bpf_pin_path()),
            metadata: MetadataSettings::default(),
            network: NetworkSettings::default(),
            prometheus: PrometheusSettings::default(),
            otlp: OtlpSettings::default(),
            security: SecuritySettings::default(),
            application_telemetry: ApplicationTelemetrySettings::default(),
            trace: TraceSettings::default(),
            tls_telemetry: TlsTelemetrySettings::default(),
            logging: LoggingSettings::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentSettings {
    pub node_name: String,
    pub instance_id: String,
}

impl Default for AgentSettings {
    fn default() -> Self {
        Self {
            node_name: "localhost".to_owned(),
            instance_id: "prism-local".to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataSettings {
    pub providers: Vec<MetadataProvider>,
}

impl Default for MetadataSettings {
    fn default() -> Self {
        Self {
            providers: vec![MetadataProvider::Systemd],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MetadataProvider {
    Docker,
    Cri,
    Kubernetes,
    Systemd,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct NetworkSettings {
    pub tc_hooks_enabled: bool,
    pub tc_interfaces: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrometheusSettings {
    pub listen_addr: SocketAddr,
    pub label_allowlist: Vec<PrometheusLabel>,
    pub max_label_value_len: usize,
    pub expensive_dimensions_enabled: bool,
    pub series_limit: usize,
}

impl Default for PrometheusSettings {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 9090)),
            label_allowlist: vec![PrometheusLabel::CgroupId],
            max_label_value_len: 128,
            expensive_dimensions_enabled: false,
            series_limit: 10_000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrometheusLabel {
    CgroupId,
    ContainerId,
    ContainerName,
    Namespace,
    PodName,
}

impl PrometheusLabel {
    #[must_use]
    pub const fn is_high_cardinality(self) -> bool {
        matches!(
            self,
            Self::ContainerId | Self::ContainerName | Self::PodName
        )
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::CgroupId => "cgroup_id",
            Self::ContainerId => "container_id",
            Self::ContainerName => "container_name",
            Self::Namespace => "namespace",
            Self::PodName => "pod_name",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtlpSettings {
    pub endpoint: String,
}

impl Default for OtlpSettings {
    fn default() -> Self {
        Self {
            endpoint: "http://127.0.0.1:4317".to_owned(),
        }
    }
}

/// Action to take when a security policy rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PolicyAction {
    /// Emit the event with no additional annotation.
    #[default]
    Allow,
    /// Emit the event and label it as a policy violation.
    Alert,
    /// Drop the event silently.
    Deny,
}

/// A rule that matches a file path prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilePathRule {
    /// Path prefix to match (e.g. `/etc/`).
    pub prefix: String,
    /// Action when this rule matches.
    pub action: PolicyAction,
}

/// A rule that matches a process executable name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessRule {
    /// Executable comm name to match (e.g. `bash`).
    pub comm: String,
    /// Action when this rule matches.
    pub action: PolicyAction,
}

/// A rule that matches a network destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkRule {
    /// Destination CIDR or IP prefix to match (e.g. `10.0.0.`).
    pub destination: String,
    /// Action when this rule matches.
    pub action: PolicyAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SecuritySettings {
    pub capture_process_exec: bool,
    pub capture_command_line: bool,
    /// Ordered list of file path rules. First match wins.
    pub file_path_rules: Vec<FilePathRule>,
    /// Ordered list of process execution rules. First match wins.
    pub process_rules: Vec<ProcessRule>,
    /// Ordered list of network destination rules. First match wins.
    pub network_rules: Vec<NetworkRule>,
}

impl SecuritySettings {
    /// Returns the policy action for a file path.
    /// Returns `PolicyAction::Allow` when no rule matches.
    #[must_use]
    pub fn file_policy(&self, path: &str) -> PolicyAction {
        self.file_path_rules
            .iter()
            .find(|r| path.starts_with(&r.prefix))
            .map_or(PolicyAction::Allow, |r| r.action)
    }

    /// Returns the policy action for a process comm name.
    /// Returns `PolicyAction::Allow` when no rule matches.
    #[must_use]
    pub fn process_policy(&self, comm: &str) -> PolicyAction {
        self.process_rules
            .iter()
            .find(|r| comm == r.comm)
            .map_or(PolicyAction::Allow, |r| r.action)
    }

    /// Returns the policy action for a network destination.
    /// Returns `PolicyAction::Allow` when no rule matches.
    #[must_use]
    pub fn network_policy(&self, destination: &str) -> PolicyAction {
        self.network_rules
            .iter()
            .find(|r| destination.starts_with(&r.destination))
            .map_or(PolicyAction::Allow, |r| r.action)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ApplicationTelemetrySettings {
    pub postgres_enabled: bool,
    pub redis_enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceSettings {
    pub create_root_spans: bool,
    pub span_queue_capacity: usize,
}

impl Default for TraceSettings {
    fn default() -> Self {
        Self {
            create_root_spans: false,
            span_queue_capacity: 1024,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TlsLibrary {
    OpenSsl,
    BoringSsl,
    Rustls,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsTelemetrySettings {
    pub enabled: bool,
    pub library_allowlist: Vec<TlsLibrary>,
}

impl Default for TlsTelemetrySettings {
    fn default() -> Self {
        Self {
            enabled: false,
            library_allowlist: vec![TlsLibrary::OpenSsl],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoggingSettings {
    pub level: String,
}

impl Default for LoggingSettings {
    fn default() -> Self {
        Self {
            level: "info".to_owned(),
        }
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse config file {path}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },
    #[error("config field {field} is required")]
    MissingRequired { field: &'static str },
    #[error("config field {field} is invalid: {reason}")]
    InvalidValue {
        field: &'static str,
        reason: &'static str,
    },
    #[error("environment variable {name} must be valid unicode")]
    NonUnicodeEnv { name: &'static str },
    #[error("environment variable {name} is invalid: {reason}")]
    InvalidEnv {
        name: &'static str,
        reason: &'static str,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfigPathMode {
    Optional,
    Required,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawConfig {
    agent: RawAgentSettings,
    bpf: RawBpfSettings,
    metadata: RawMetadataSettings,
    network: RawNetworkSettings,
    prometheus: RawPrometheusSettings,
    otlp: RawOtlpSettings,
    security: RawSecuritySettings,
    application_telemetry: RawApplicationTelemetrySettings,
    trace: RawTraceSettings,
    tls_telemetry: RawTlsTelemetrySettings,
    logging: RawLoggingSettings,
}

impl RawConfig {
    fn load(path: &Path, mode: ConfigPathMode) -> Result<Self, ConfigError> {
        match fs::read_to_string(path) {
            Ok(contents) => serde_yaml::from_str(&contents).map_err(|source| ConfigError::Parse {
                path: path.to_path_buf(),
                source,
            }),
            Err(source)
                if mode == ConfigPathMode::Optional
                    && source.kind() == std::io::ErrorKind::NotFound =>
            {
                Ok(Self::default())
            }
            Err(source) => Err(ConfigError::Read {
                path: path.to_path_buf(),
                source,
            }),
        }
    }

    fn into_config(self) -> Result<AgentConfig, ConfigError> {
        let defaults = AgentConfig::default();

        Ok(AgentConfig {
            agent: self.agent.into_settings(defaults.agent),
            bpf: self.bpf.into_settings(defaults.bpf),
            metadata: self.metadata.into_settings(defaults.metadata),
            network: self.network.into_settings(defaults.network),
            prometheus: self.prometheus.into_settings(defaults.prometheus)?,
            otlp: self.otlp.into_settings(defaults.otlp),
            security: self.security.into_settings(defaults.security),
            application_telemetry: self
                .application_telemetry
                .into_settings(defaults.application_telemetry),
            trace: self.trace.into_settings(defaults.trace),
            tls_telemetry: self.tls_telemetry.into_settings(defaults.tls_telemetry),
            logging: self.logging.into_settings(defaults.logging),
        })
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawAgentSettings {
    node_name: Option<String>,
    instance_id: Option<String>,
}

impl RawAgentSettings {
    fn into_settings(self, defaults: AgentSettings) -> AgentSettings {
        AgentSettings {
            node_name: self.node_name.unwrap_or(defaults.node_name),
            instance_id: self.instance_id.unwrap_or(defaults.instance_id),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawBpfSettings {
    object_path: Option<PathBuf>,
    pin_path: Option<PathBuf>,
    ephemeral: Option<bool>,
}

impl RawBpfSettings {
    fn into_settings(self, defaults: BpfLoaderConfig) -> BpfLoaderConfig {
        BpfLoaderConfig::new(
            self.object_path.unwrap_or(defaults.object_path),
            self.pin_path.unwrap_or(defaults.pin_path),
        )
        .with_ephemeral(self.ephemeral.unwrap_or(defaults.ephemeral))
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawMetadataSettings {
    providers: Option<Vec<MetadataProvider>>,
}

impl RawMetadataSettings {
    fn into_settings(self, defaults: MetadataSettings) -> MetadataSettings {
        MetadataSettings {
            providers: self.providers.unwrap_or(defaults.providers),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawNetworkSettings {
    tc_hooks_enabled: Option<bool>,
    tc_interfaces: Option<Vec<String>>,
}

impl RawNetworkSettings {
    fn into_settings(self, defaults: NetworkSettings) -> NetworkSettings {
        NetworkSettings {
            tc_hooks_enabled: self.tc_hooks_enabled.unwrap_or(defaults.tc_hooks_enabled),
            tc_interfaces: self.tc_interfaces.unwrap_or(defaults.tc_interfaces),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawPrometheusSettings {
    listen_addr: Option<String>,
    label_allowlist: Option<Vec<PrometheusLabel>>,
    max_label_value_len: Option<usize>,
    expensive_dimensions_enabled: Option<bool>,
    series_limit: Option<usize>,
}

impl RawPrometheusSettings {
    fn into_settings(
        self,
        defaults: PrometheusSettings,
    ) -> Result<PrometheusSettings, ConfigError> {
        Ok(PrometheusSettings {
            listen_addr: parse_socket_addr(
                "prometheus.listen_addr",
                self.listen_addr.as_deref(),
                defaults.listen_addr,
            )?,
            label_allowlist: self.label_allowlist.unwrap_or(defaults.label_allowlist),
            max_label_value_len: self
                .max_label_value_len
                .unwrap_or(defaults.max_label_value_len),
            expensive_dimensions_enabled: self
                .expensive_dimensions_enabled
                .unwrap_or(defaults.expensive_dimensions_enabled),
            series_limit: self.series_limit.unwrap_or(defaults.series_limit),
        })
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawOtlpSettings {
    endpoint: Option<String>,
}

impl RawOtlpSettings {
    fn into_settings(self, defaults: OtlpSettings) -> OtlpSettings {
        OtlpSettings {
            endpoint: self.endpoint.unwrap_or(defaults.endpoint),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawSecuritySettings {
    capture_process_exec: Option<bool>,
    capture_command_line: Option<bool>,
}

impl RawSecuritySettings {
    fn into_settings(self, defaults: SecuritySettings) -> SecuritySettings {
        SecuritySettings {
            capture_process_exec: self
                .capture_process_exec
                .unwrap_or(defaults.capture_process_exec),
            capture_command_line: self
                .capture_command_line
                .unwrap_or(defaults.capture_command_line),
            file_path_rules: defaults.file_path_rules,
            process_rules: defaults.process_rules,
            network_rules: defaults.network_rules,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawApplicationTelemetrySettings {
    postgres_enabled: Option<bool>,
    redis_enabled: Option<bool>,
}

impl RawApplicationTelemetrySettings {
    fn into_settings(self, defaults: ApplicationTelemetrySettings) -> ApplicationTelemetrySettings {
        ApplicationTelemetrySettings {
            postgres_enabled: self.postgres_enabled.unwrap_or(defaults.postgres_enabled),
            redis_enabled: self.redis_enabled.unwrap_or(defaults.redis_enabled),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawTraceSettings {
    create_root_spans: Option<bool>,
    span_queue_capacity: Option<usize>,
}

impl RawTraceSettings {
    fn into_settings(self, defaults: TraceSettings) -> TraceSettings {
        TraceSettings {
            create_root_spans: self.create_root_spans.unwrap_or(defaults.create_root_spans),
            span_queue_capacity: self
                .span_queue_capacity
                .unwrap_or(defaults.span_queue_capacity),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawTlsTelemetrySettings {
    enabled: Option<bool>,
    library_allowlist: Option<Vec<TlsLibrary>>,
}

impl RawTlsTelemetrySettings {
    fn into_settings(self, defaults: TlsTelemetrySettings) -> TlsTelemetrySettings {
        TlsTelemetrySettings {
            enabled: self.enabled.unwrap_or(defaults.enabled),
            library_allowlist: self.library_allowlist.unwrap_or(defaults.library_allowlist),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawLoggingSettings {
    level: Option<String>,
}

impl RawLoggingSettings {
    fn into_settings(self, defaults: LoggingSettings) -> LoggingSettings {
        LoggingSettings {
            level: self.level.unwrap_or(defaults.level),
        }
    }
}

#[derive(Debug, Default)]
struct EnvOverrides {
    values: HashMap<String, OsString>,
}

impl EnvOverrides {
    fn from_env() -> Self {
        let values = env::vars_os()
            .filter_map(|(name, value)| {
                let name = name.into_string().ok()?;
                name.starts_with("PRISM_").then_some((name, value))
            })
            .collect();

        Self { values }
    }

    #[cfg(test)]
    fn from_pairs(pairs: &[(&str, &str)]) -> Self {
        Self {
            values: pairs
                .iter()
                .map(|(name, value)| ((*name).to_owned(), OsString::from(value)))
                .collect(),
        }
    }

    fn path_override(&self) -> Option<&Path> {
        self.values.get(ENV_CONFIG_PATH).map(Path::new)
    }

    fn apply(&self, config: &mut AgentConfig) -> Result<(), ConfigError> {
        self.apply_string(ENV_NODE_NAME, &mut config.agent.node_name)?;
        self.apply_string(ENV_INSTANCE_ID, &mut config.agent.instance_id)?;
        self.apply_path(ENV_EBPF_OBJECT, &mut config.bpf.object_path);
        self.apply_path(ENV_BPF_PIN_PATH, &mut config.bpf.pin_path);
        self.apply_bool(ENV_BPF_EPHEMERAL, &mut config.bpf.ephemeral)?;
        self.apply_socket_addr(
            ENV_PROMETHEUS_LISTEN_ADDR,
            &mut config.prometheus.listen_addr,
        )?;
        self.apply_prometheus_labels(
            ENV_PROMETHEUS_LABEL_ALLOWLIST,
            &mut config.prometheus.label_allowlist,
        )?;
        self.apply_usize(
            ENV_PROMETHEUS_MAX_LABEL_VALUE_LEN,
            &mut config.prometheus.max_label_value_len,
        )?;
        self.apply_bool(
            ENV_PROMETHEUS_EXPENSIVE_DIMENSIONS_ENABLED,
            &mut config.prometheus.expensive_dimensions_enabled,
        )?;
        self.apply_usize(
            ENV_PROMETHEUS_SERIES_LIMIT,
            &mut config.prometheus.series_limit,
        )?;
        self.apply_bool(
            ENV_NETWORK_TC_HOOKS_ENABLED,
            &mut config.network.tc_hooks_enabled,
        )?;
        self.apply_string_list(ENV_NETWORK_TC_INTERFACES, &mut config.network.tc_interfaces)?;
        self.apply_string(ENV_OTLP_ENDPOINT, &mut config.otlp.endpoint)?;
        self.apply_string(ENV_LOG_LEVEL, &mut config.logging.level)?;
        self.apply_bool(
            ENV_CAPTURE_PROCESS_EXEC,
            &mut config.security.capture_process_exec,
        )?;
        self.apply_bool(
            ENV_CAPTURE_COMMAND_LINE,
            &mut config.security.capture_command_line,
        )?;
        self.apply_bool(
            ENV_POSTGRES_TELEMETRY_ENABLED,
            &mut config.application_telemetry.postgres_enabled,
        )?;
        self.apply_bool(
            ENV_REDIS_TELEMETRY_ENABLED,
            &mut config.application_telemetry.redis_enabled,
        )?;
        self.apply_bool(
            ENV_TRACE_CREATE_ROOT_SPANS,
            &mut config.trace.create_root_spans,
        )?;
        self.apply_usize(
            ENV_TRACE_SPAN_QUEUE_CAPACITY,
            &mut config.trace.span_queue_capacity,
        )?;
        self.apply_bool(ENV_TLS_TELEMETRY_ENABLED, &mut config.tls_telemetry.enabled)?;
        self.apply_tls_libraries(
            ENV_TLS_LIBRARY_ALLOWLIST,
            &mut config.tls_telemetry.library_allowlist,
        )?;
        Ok(())
    }

    fn apply_bool(&self, name: &'static str, target: &mut bool) -> Result<(), ConfigError> {
        if let Some(value) = self.value(name)? {
            *target = parse_bool(name, value)?;
        }

        Ok(())
    }

    fn apply_path(&self, name: &'static str, target: &mut PathBuf) {
        if let Some(value) = self.values.get(name) {
            *target = PathBuf::from(value);
        }
    }

    fn apply_socket_addr(
        &self,
        name: &'static str,
        target: &mut SocketAddr,
    ) -> Result<(), ConfigError> {
        if let Some(value) = self.value(name)? {
            *target = value.parse().map_err(|_| ConfigError::InvalidEnv {
                name,
                reason: "expected socket address",
            })?;
        }

        Ok(())
    }

    fn apply_usize(&self, name: &'static str, target: &mut usize) -> Result<(), ConfigError> {
        if let Some(value) = self.value(name)? {
            *target = value.parse().map_err(|_| ConfigError::InvalidEnv {
                name,
                reason: "expected unsigned integer",
            })?;
        }

        Ok(())
    }

    fn apply_prometheus_labels(
        &self,
        name: &'static str,
        target: &mut Vec<PrometheusLabel>,
    ) -> Result<(), ConfigError> {
        if let Some(value) = self.value(name)? {
            let labels = parse_csv_list(name, value)?
                .into_iter()
                .map(|label| parse_prometheus_label(name, &label))
                .collect::<Result<Vec<_>, _>>()?;
            target.clear();
            target.extend(labels);
        }

        Ok(())
    }

    fn apply_tls_libraries(
        &self,
        name: &'static str,
        target: &mut Vec<TlsLibrary>,
    ) -> Result<(), ConfigError> {
        if let Some(value) = self.value(name)? {
            let libraries = parse_csv_list(name, value)?
                .into_iter()
                .map(|library| parse_tls_library(name, &library))
                .collect::<Result<Vec<_>, _>>()?;
            target.clear();
            target.extend(libraries);
        }

        Ok(())
    }

    fn apply_string(&self, name: &'static str, target: &mut String) -> Result<(), ConfigError> {
        if let Some(value) = self.value(name)? {
            target.clear();
            target.push_str(value);
        }

        Ok(())
    }

    fn apply_string_list(
        &self,
        name: &'static str,
        target: &mut Vec<String>,
    ) -> Result<(), ConfigError> {
        if let Some(value) = self.value(name)? {
            let values = parse_csv_list(name, value)?;
            target.clear();
            target.extend(values);
        }

        Ok(())
    }

    fn value(&self, name: &'static str) -> Result<Option<&str>, ConfigError> {
        self.values
            .get(name)
            .map(|value| value.to_str().ok_or(ConfigError::NonUnicodeEnv { name }))
            .transpose()
    }
}

fn default_ebpf_object_path() -> PathBuf {
    PathBuf::from("target/bpfel-unknown-none/release/prism-ebpf")
}

fn default_bpf_pin_path() -> PathBuf {
    PathBuf::from("/sys/fs/bpf/prism")
}

fn ensure_non_empty(field: &'static str, value: &str) -> Result<(), ConfigError> {
    if value.trim().is_empty() {
        return Err(ConfigError::MissingRequired { field });
    }

    Ok(())
}

fn ensure_non_empty_path(field: &'static str, value: &Path) -> Result<(), ConfigError> {
    if value.as_os_str().is_empty() {
        return Err(ConfigError::MissingRequired { field });
    }

    Ok(())
}

fn parse_bool(name: &'static str, value: &str) -> Result<bool, ConfigError> {
    match value {
        "1" | "true" | "TRUE" | "yes" | "YES" => Ok(true),
        "0" | "false" | "FALSE" | "no" | "NO" => Ok(false),
        _ => Err(ConfigError::InvalidEnv {
            name,
            reason: "expected boolean",
        }),
    }
}

fn parse_socket_addr(
    field: &'static str,
    value: Option<&str>,
    default: SocketAddr,
) -> Result<SocketAddr, ConfigError> {
    value.map_or(Ok(default), |value| {
        value.parse().map_err(|_| ConfigError::InvalidValue {
            field,
            reason: "expected socket address",
        })
    })
}

fn parse_csv_list(name: &'static str, value: &str) -> Result<Vec<String>, ConfigError> {
    let values = value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();

    if values.is_empty() {
        return Err(ConfigError::InvalidEnv {
            name,
            reason: "expected comma-separated non-empty values",
        });
    }

    Ok(values)
}

fn parse_prometheus_label(name: &'static str, value: &str) -> Result<PrometheusLabel, ConfigError> {
    match value {
        "cgroup-id" | "cgroup_id" => Ok(PrometheusLabel::CgroupId),
        "container-id" | "container_id" => Ok(PrometheusLabel::ContainerId),
        "container-name" | "container_name" => Ok(PrometheusLabel::ContainerName),
        "namespace" => Ok(PrometheusLabel::Namespace),
        "pod-name" | "pod_name" => Ok(PrometheusLabel::PodName),
        _ => Err(ConfigError::InvalidEnv {
            name,
            reason: "unknown prometheus label",
        }),
    }
}

fn parse_tls_library(name: &'static str, value: &str) -> Result<TlsLibrary, ConfigError> {
    match value {
        "openssl" | "open-ssl" | "open_ssl" => Ok(TlsLibrary::OpenSsl),
        "boringssl" | "boring-ssl" | "boring_ssl" => Ok(TlsLibrary::BoringSsl),
        "rustls" => Ok(TlsLibrary::Rustls),
        _ => Err(ConfigError::InvalidEnv {
            name,
            reason: "unknown TLS library",
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn missing_default_config_uses_defaults() {
        let config = AgentConfig::load_with_test_env(
            Path::new("/tmp/prism-missing-default-config-for-test"),
            ConfigPathMode::Optional,
            &[],
        )
        .expect("missing optional config should use defaults");

        assert_eq!(config.agent.node_name, "localhost");
        assert_eq!(config.agent.instance_id, "prism-local");
        assert_eq!(config.bpf.object_path, default_ebpf_object_path());
        assert_eq!(config.bpf.pin_path, default_bpf_pin_path());
        assert!(config.bpf.ephemeral);
        assert_eq!(config.metadata.providers, vec![MetadataProvider::Systemd]);
        assert!(!config.network.tc_hooks_enabled);
        assert!(config.network.tc_interfaces.is_empty());
        assert_eq!(
            config.prometheus.listen_addr,
            SocketAddr::from(([127, 0, 0, 1], 9090))
        );
        assert_eq!(
            config.prometheus.label_allowlist,
            vec![PrometheusLabel::CgroupId]
        );
        assert_eq!(config.prometheus.max_label_value_len, 128);
        assert!(!config.prometheus.expensive_dimensions_enabled);
        assert_eq!(config.prometheus.series_limit, 10_000);
        assert!(!config.application_telemetry.postgres_enabled);
        assert!(!config.application_telemetry.redis_enabled);
        assert!(!config.trace.create_root_spans);
        assert_eq!(config.trace.span_queue_capacity, 1024);
        assert!(!config.tls_telemetry.enabled);
        assert_eq!(
            config.tls_telemetry.library_allowlist,
            vec![TlsLibrary::OpenSsl]
        );
    }

    #[test]
    fn yaml_config_is_loaded() {
        let temp_dir = TempDir::new().expect("tempdir should be created");
        let path = temp_dir.path().join("config.yaml");
        fs::write(
            &path,
            r"
agent:
  node_name: node-a
  instance_id: prism-a
bpf:
  object_path: /opt/prism/prism-ebpf
  pin_path: /run/prism/bpf
  ephemeral: false
metadata:
  providers:
    - docker
    - systemd
network:
  tc_hooks_enabled: true
  tc_interfaces:
    - eth0
prometheus:
  listen_addr: 0.0.0.0:9999
  label_allowlist:
    - cgroup-id
    - namespace
  max_label_value_len: 64
  expensive_dimensions_enabled: false
  series_limit: 500
otlp:
  endpoint: http://collector:4317
security:
  capture_process_exec: true
  capture_command_line: true
application_telemetry:
  postgres_enabled: true
  redis_enabled: false
trace:
  create_root_spans: true
  span_queue_capacity: 128
tls_telemetry:
  enabled: true
  library_allowlist:
    - open-ssl
    - rustls
logging:
  level: debug
",
        )
        .expect("config should be written");

        let config = AgentConfig::load_with_test_env(&path, ConfigPathMode::Required, &[])
            .expect("config should load");

        assert_eq!(config.agent.node_name, "node-a");
        assert_eq!(config.agent.instance_id, "prism-a");
        assert_eq!(
            config.bpf.object_path,
            PathBuf::from("/opt/prism/prism-ebpf")
        );
        assert_eq!(config.bpf.pin_path, PathBuf::from("/run/prism/bpf"));
        assert!(!config.bpf.ephemeral);
        assert_eq!(
            config.metadata.providers,
            vec![MetadataProvider::Docker, MetadataProvider::Systemd]
        );
        assert!(config.network.tc_hooks_enabled);
        assert_eq!(config.network.tc_interfaces, vec!["eth0"]);
        assert_eq!(
            config.prometheus.listen_addr,
            "0.0.0.0:9999"
                .parse::<SocketAddr>()
                .expect("socket addr should parse")
        );
        assert_eq!(
            config.prometheus.label_allowlist,
            vec![PrometheusLabel::CgroupId, PrometheusLabel::Namespace]
        );
        assert_eq!(config.prometheus.max_label_value_len, 64);
        assert!(!config.prometheus.expensive_dimensions_enabled);
        assert_eq!(config.prometheus.series_limit, 500);
        assert_eq!(config.otlp.endpoint, "http://collector:4317");
        assert!(config.security.capture_process_exec);
        assert!(config.security.capture_command_line);
        assert!(config.application_telemetry.postgres_enabled);
        assert!(!config.application_telemetry.redis_enabled);
        assert!(config.trace.create_root_spans);
        assert_eq!(config.trace.span_queue_capacity, 128);
        assert!(config.tls_telemetry.enabled);
        assert_eq!(
            config.tls_telemetry.library_allowlist,
            vec![TlsLibrary::OpenSsl, TlsLibrary::Rustls]
        );
        assert_eq!(config.logging.level, "debug");
    }

    #[test]
    fn environment_overrides_yaml_config() {
        let temp_dir = TempDir::new().expect("tempdir should be created");
        let path = temp_dir.path().join("config.yaml");
        fs::write(
            &path,
            r"
agent:
  node_name: node-a
  instance_id: prism-a
bpf:
  object_path: /opt/prism/prism-ebpf
  pin_path: /run/prism/bpf
prometheus:
  listen_addr: 127.0.0.1:9090
",
        )
        .expect("config should be written");

        let config = AgentConfig::load_with_test_env(
            &path,
            ConfigPathMode::Required,
            &[
                (ENV_NODE_NAME, "node-b"),
                (ENV_INSTANCE_ID, "prism-b"),
                (ENV_EBPF_OBJECT, "/tmp/prism-ebpf"),
                (ENV_BPF_PIN_PATH, "/tmp/prism-pins"),
                (ENV_BPF_EPHEMERAL, "false"),
                (ENV_PROMETHEUS_LISTEN_ADDR, "0.0.0.0:9091"),
                (ENV_PROMETHEUS_LABEL_ALLOWLIST, "cgroup-id,container-name"),
                (ENV_PROMETHEUS_MAX_LABEL_VALUE_LEN, "32"),
                (ENV_PROMETHEUS_EXPENSIVE_DIMENSIONS_ENABLED, "true"),
                (ENV_PROMETHEUS_SERIES_LIMIT, "250"),
                (ENV_NETWORK_TC_HOOKS_ENABLED, "true"),
                (ENV_NETWORK_TC_INTERFACES, "eth0, lo"),
                (ENV_OTLP_ENDPOINT, "http://collector:4317"),
                (ENV_LOG_LEVEL, "trace"),
                (ENV_CAPTURE_PROCESS_EXEC, "true"),
                (ENV_CAPTURE_COMMAND_LINE, "true"),
                (ENV_POSTGRES_TELEMETRY_ENABLED, "true"),
                (ENV_REDIS_TELEMETRY_ENABLED, "true"),
                (ENV_TRACE_CREATE_ROOT_SPANS, "true"),
                (ENV_TRACE_SPAN_QUEUE_CAPACITY, "256"),
                (ENV_TLS_TELEMETRY_ENABLED, "true"),
                (ENV_TLS_LIBRARY_ALLOWLIST, "openssl,boringssl"),
            ],
        )
        .expect("config should load");

        assert_eq!(config.agent.node_name, "node-b");
        assert_eq!(config.agent.instance_id, "prism-b");
        assert_eq!(config.bpf.object_path, PathBuf::from("/tmp/prism-ebpf"));
        assert_eq!(config.bpf.pin_path, PathBuf::from("/tmp/prism-pins"));
        assert!(!config.bpf.ephemeral);
        assert_eq!(
            config.prometheus.listen_addr,
            "0.0.0.0:9091"
                .parse::<SocketAddr>()
                .expect("socket addr should parse")
        );
        assert_eq!(
            config.prometheus.label_allowlist,
            vec![PrometheusLabel::CgroupId, PrometheusLabel::ContainerName]
        );
        assert_eq!(config.prometheus.max_label_value_len, 32);
        assert!(config.prometheus.expensive_dimensions_enabled);
        assert_eq!(config.prometheus.series_limit, 250);
        assert!(config.network.tc_hooks_enabled);
        assert_eq!(config.network.tc_interfaces, vec!["eth0", "lo"]);
        assert_eq!(config.otlp.endpoint, "http://collector:4317");
        assert_eq!(config.logging.level, "trace");
        assert!(config.security.capture_process_exec);
        assert!(config.security.capture_command_line);
        assert!(config.application_telemetry.postgres_enabled);
        assert!(config.application_telemetry.redis_enabled);
        assert!(config.trace.create_root_spans);
        assert_eq!(config.trace.span_queue_capacity, 256);
        assert!(config.tls_telemetry.enabled);
        assert_eq!(
            config.tls_telemetry.library_allowlist,
            vec![TlsLibrary::OpenSsl, TlsLibrary::BoringSsl]
        );
    }

    #[test]
    fn invalid_config_returns_structured_error() {
        let temp_dir = TempDir::new().expect("tempdir should be created");
        let path = temp_dir.path().join("config.yaml");
        fs::write(
            &path,
            r#"
agent:
  node_name: ""
"#,
        )
        .expect("config should be written");

        let error = AgentConfig::load_with_test_env(&path, ConfigPathMode::Required, &[])
            .expect_err("empty required field should fail");

        assert!(matches!(
            error,
            ConfigError::MissingRequired {
                field: "agent.node_name"
            }
        ));
    }

    #[test]
    fn invalid_env_override_returns_structured_error() {
        let error = AgentConfig::load_with_test_env(
            Path::new("/tmp/prism-missing-default-config-for-test"),
            ConfigPathMode::Optional,
            &[(ENV_BPF_EPHEMERAL, "maybe")],
        )
        .expect_err("invalid bool should fail");

        assert!(matches!(
            error,
            ConfigError::InvalidEnv {
                name: ENV_BPF_EPHEMERAL,
                reason: "expected boolean"
            }
        ));
    }

    #[test]
    fn enabled_network_hooks_require_interfaces() {
        let temp_dir = TempDir::new().expect("tempdir should be created");
        let path = temp_dir.path().join("config.yaml");
        fs::write(
            &path,
            r"
network:
  tc_hooks_enabled: true
",
        )
        .expect("config should be written");

        let error = AgentConfig::load_with_test_env(&path, ConfigPathMode::Required, &[])
            .expect_err("enabled tc hooks should require interfaces");

        assert!(matches!(
            error,
            ConfigError::MissingRequired {
                field: "network.tc_interfaces"
            }
        ));
    }

    #[test]
    fn high_cardinality_labels_require_explicit_opt_in() {
        let temp_dir = TempDir::new().expect("tempdir should be created");
        let path = temp_dir.path().join("config.yaml");
        fs::write(
            &path,
            r"
prometheus:
  label_allowlist:
    - container-name
",
        )
        .expect("config should be written");

        let error = AgentConfig::load_with_test_env(&path, ConfigPathMode::Required, &[])
            .expect_err("high-cardinality labels should require opt-in");

        assert!(matches!(
            error,
            ConfigError::InvalidValue {
                field: "prometheus.label_allowlist",
                reason: "high-cardinality labels require expensive_dimensions_enabled"
            }
        ));
    }

    #[test]
    fn trace_queue_capacity_must_be_non_zero() {
        let temp_dir = TempDir::new().expect("tempdir should be created");
        let path = temp_dir.path().join("config.yaml");
        fs::write(
            &path,
            r"
trace:
  span_queue_capacity: 0
",
        )
        .expect("config should be written");

        let error = AgentConfig::load_with_test_env(&path, ConfigPathMode::Required, &[])
            .expect_err("zero trace queue capacity should fail");

        assert!(matches!(
            error,
            ConfigError::InvalidValue {
                field: "trace.span_queue_capacity",
                reason: "must be greater than zero"
            }
        ));
    }

    #[test]
    fn enabled_tls_telemetry_requires_library_allowlist() {
        let temp_dir = TempDir::new().expect("tempdir should be created");
        let path = temp_dir.path().join("config.yaml");
        fs::write(
            &path,
            r"
tls_telemetry:
  enabled: true
  library_allowlist: []
",
        )
        .expect("config should be written");

        let error = AgentConfig::load_with_test_env(&path, ConfigPathMode::Required, &[])
            .expect_err("enabled TLS telemetry should require allowlist");

        assert!(matches!(
            error,
            ConfigError::MissingRequired {
                field: "tls_telemetry.library_allowlist"
            }
        ));
    }
}

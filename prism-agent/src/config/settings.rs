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
const ENV_NETWORK_TC_HOOKS_ENABLED: &str = "PRISM_NETWORK_TC_HOOKS_ENABLED";
const ENV_NETWORK_TC_INTERFACES: &str = "PRISM_NETWORK_TC_INTERFACES";
const ENV_OTLP_ENDPOINT: &str = "PRISM_OTLP_ENDPOINT";
const ENV_LOG_LEVEL: &str = "PRISM_LOG_LEVEL";
const ENV_CAPTURE_PROCESS_EXEC: &str = "PRISM_CAPTURE_PROCESS_EXEC";
const ENV_CAPTURE_COMMAND_LINE: &str = "PRISM_CAPTURE_COMMAND_LINE";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentConfig {
    pub agent: AgentSettings,
    pub bpf: BpfLoaderConfig,
    pub metadata: MetadataSettings,
    pub network: NetworkSettings,
    pub prometheus: PrometheusSettings,
    pub otlp: OtlpSettings,
    pub security: SecuritySettings,
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
}

impl Default for PrometheusSettings {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 9090)),
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

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SecuritySettings {
    pub capture_process_exec: bool,
    pub capture_command_line: bool,
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
        let bpf = BpfLoaderConfig::new(
            self.bpf.object_path.unwrap_or(defaults.bpf.object_path),
            self.bpf.pin_path.unwrap_or(defaults.bpf.pin_path),
        )
        .with_ephemeral(self.bpf.ephemeral.unwrap_or(defaults.bpf.ephemeral));

        Ok(AgentConfig {
            agent: AgentSettings {
                node_name: self.agent.node_name.unwrap_or(defaults.agent.node_name),
                instance_id: self.agent.instance_id.unwrap_or(defaults.agent.instance_id),
            },
            bpf,
            metadata: MetadataSettings {
                providers: self
                    .metadata
                    .providers
                    .unwrap_or(defaults.metadata.providers),
            },
            network: NetworkSettings {
                tc_hooks_enabled: self
                    .network
                    .tc_hooks_enabled
                    .unwrap_or(defaults.network.tc_hooks_enabled),
                tc_interfaces: self
                    .network
                    .tc_interfaces
                    .unwrap_or(defaults.network.tc_interfaces),
            },
            prometheus: PrometheusSettings {
                listen_addr: parse_socket_addr(
                    "prometheus.listen_addr",
                    self.prometheus.listen_addr.as_deref(),
                    defaults.prometheus.listen_addr,
                )?,
            },
            otlp: OtlpSettings {
                endpoint: self.otlp.endpoint.unwrap_or(defaults.otlp.endpoint),
            },
            security: SecuritySettings {
                capture_process_exec: self
                    .security
                    .capture_process_exec
                    .unwrap_or(defaults.security.capture_process_exec),
                capture_command_line: self
                    .security
                    .capture_command_line
                    .unwrap_or(defaults.security.capture_command_line),
            },
            logging: LoggingSettings {
                level: self.logging.level.unwrap_or(defaults.logging.level),
            },
        })
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawAgentSettings {
    node_name: Option<String>,
    instance_id: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawBpfSettings {
    object_path: Option<PathBuf>,
    pin_path: Option<PathBuf>,
    ephemeral: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawMetadataSettings {
    providers: Option<Vec<MetadataProvider>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawNetworkSettings {
    tc_hooks_enabled: Option<bool>,
    tc_interfaces: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawPrometheusSettings {
    listen_addr: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawOtlpSettings {
    endpoint: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawSecuritySettings {
    capture_process_exec: Option<bool>,
    capture_command_line: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawLoggingSettings {
    level: Option<String>,
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
otlp:
  endpoint: http://collector:4317
security:
  capture_process_exec: true
  capture_command_line: true
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
        assert_eq!(config.otlp.endpoint, "http://collector:4317");
        assert!(config.security.capture_process_exec);
        assert!(config.security.capture_command_line);
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
                (ENV_NETWORK_TC_HOOKS_ENABLED, "true"),
                (ENV_NETWORK_TC_INTERFACES, "eth0, lo"),
                (ENV_OTLP_ENDPOINT, "http://collector:4317"),
                (ENV_LOG_LEVEL, "trace"),
                (ENV_CAPTURE_PROCESS_EXEC, "true"),
                (ENV_CAPTURE_COMMAND_LINE, "true"),
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
        assert!(config.network.tc_hooks_enabled);
        assert_eq!(config.network.tc_interfaces, vec!["eth0", "lo"]);
        assert_eq!(config.otlp.endpoint, "http://collector:4317");
        assert_eq!(config.logging.level, "trace");
        assert!(config.security.capture_process_exec);
        assert!(config.security.capture_command_line);
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
}

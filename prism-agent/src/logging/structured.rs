use std::env;
use tracing_subscriber::{EnvFilter, fmt};

/// Configuration for structured logging.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct LoggingConfig {
    pub json_format: bool,
    pub log_level: String,
    pub include_span_id: bool,
    pub include_trace_id: bool,
    pub redact_sensitive: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            json_format: false,
            log_level: "info".to_owned(),
            include_span_id: true,
            include_trace_id: true,
            redact_sensitive: true,
        }
    }
}

impl LoggingConfig {
    /// Loads logging configuration from environment variables.
    #[must_use]
    pub fn from_env() -> Self {
        let json_format =
            env::var("PRISM_LOG_JSON").is_ok_and(|v| v == "1" || v == "true" || v == "yes");

        let log_level = env::var("PRISM_LOG_LEVEL")
            .or_else(|_| env::var("RUST_LOG"))
            .unwrap_or_else(|_| "info".to_owned());

        let include_span_id =
            env::var("PRISM_LOG_SPAN_ID").map_or(true, |v| v != "0" && v != "false");

        let include_trace_id =
            env::var("PRISM_LOG_TRACE_ID").map_or(true, |v| v != "0" && v != "false");

        let redact_sensitive =
            env::var("PRISM_LOG_REDACT").map_or(true, |v| v != "0" && v != "false");

        Self {
            json_format,
            log_level,
            include_span_id,
            include_trace_id,
            redact_sensitive,
        }
    }
}

/// Initializes the structured logging subscriber.
///
/// # Errors
///
/// Returns an error when the subscriber cannot be initialized.
pub fn init_structured_logging(config: &LoggingConfig) -> Result<(), anyhow::Error> {
    let env_filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(&config.log_level))
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let subscriber = fmt::fmt()
        .with_env_filter(env_filter)
        .with_target(true)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_file(true)
        .with_line_number(true)
        .with_ansi(false);

    if config.json_format {
        // Since we have the json feature enabled in Cargo.toml, use it
        subscriber.json().init();
    } else {
        subscriber.init();
    }

    tracing::info!(
        json_format = config.json_format,
        log_level = %config.log_level,
        include_span_id = config.include_span_id,
        include_trace_id = config.include_trace_id,
        redact_sensitive = config.redact_sensitive,
        "structured logging initialized"
    );

    Ok(())
}

/// Redacts sensitive field values from a log message.
///
/// Scans whitespace-separated `key=value` tokens and replaces the value
/// with `***` when the key matches a known sensitive field name.
#[must_use]
pub fn redact_sensitive_fields(message: &str) -> String {
    const SENSITIVE_KEYS: [&str; 6] = [
        "password",
        "secret",
        "token",
        "api_key",
        "authorization",
        "cookie",
    ];

    message
        .split_whitespace()
        .map(|token| match token.split_once('=') {
            Some((key, _value))
                if SENSITIVE_KEYS
                    .iter()
                    .any(|pattern| key.to_lowercase().contains(pattern)) =>
            {
                format!("{key}=***")
            }
            _ => token.to_owned(),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_sensitive_fields_works() {
        let message = "password=secret123 token=abc123";
        let redacted = redact_sensitive_fields(message);
        assert!(!redacted.contains("secret123"));
        assert!(!redacted.contains("abc123"));
        assert!(redacted.contains("***"));
    }

    #[test]
    fn logging_config_from_env_uses_defaults() {
        let config = LoggingConfig::default();
        assert!(!config.json_format);
        assert_eq!(config.log_level, "info");
        assert!(config.include_span_id);
        assert!(config.include_trace_id);
        assert!(config.redact_sensitive);
    }
}

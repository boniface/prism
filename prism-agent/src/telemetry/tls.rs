use crate::config::{TlsLibrary, TlsTelemetrySettings};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsFallbackReason {
    Disabled,
    LibraryNotAllowlisted,
    LibraryUnsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsTelemetryDecision {
    OpenSslUprobes,
    ConnectionTelemetryFallback(TlsFallbackReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsUprobePlanner {
    settings: TlsTelemetrySettings,
}

impl TlsUprobePlanner {
    #[must_use]
    pub const fn new(settings: TlsTelemetrySettings) -> Self {
        Self { settings }
    }

    #[must_use]
    pub fn decision_for(&self, library: TlsLibrary) -> TlsTelemetryDecision {
        if !self.settings.enabled {
            return TlsTelemetryDecision::ConnectionTelemetryFallback(TlsFallbackReason::Disabled);
        }

        if !self.settings.library_allowlist.contains(&library) {
            return TlsTelemetryDecision::ConnectionTelemetryFallback(
                TlsFallbackReason::LibraryNotAllowlisted,
            );
        }

        match library {
            TlsLibrary::OpenSsl => TlsTelemetryDecision::OpenSslUprobes,
            TlsLibrary::BoringSsl | TlsLibrary::Rustls => {
                TlsTelemetryDecision::ConnectionTelemetryFallback(
                    TlsFallbackReason::LibraryUnsupported,
                )
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMetadataClass {
    Method,
    Status,
    Protocol,
    TraceContext,
    HeaderName,
    HeaderValue,
    Body,
    TlsKey,
    Secret,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TlsMetadataPolicy;

impl TlsMetadataPolicy {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    #[must_use]
    pub fn permits(self, class: TlsMetadataClass, name: Option<&str>) -> bool {
        match class {
            TlsMetadataClass::Method
            | TlsMetadataClass::Status
            | TlsMetadataClass::Protocol
            | TlsMetadataClass::TraceContext => true,
            TlsMetadataClass::HeaderName => name.is_none_or(Self::permits_header_name),
            TlsMetadataClass::HeaderValue => name.is_some_and(Self::permits_header_value),
            TlsMetadataClass::Body | TlsMetadataClass::TlsKey | TlsMetadataClass::Secret => false,
        }
    }

    fn permits_header_name(name: &str) -> bool {
        !is_blocked_header(name)
    }

    fn permits_header_value(name: &str) -> bool {
        matches!(
            normalise_header(name).as_deref(),
            Some("traceparent" | "tracestate")
        )
    }
}

fn is_blocked_header(name: &str) -> bool {
    matches!(
        normalise_header(name).as_deref(),
        Some("authorization" | "cookie" | "set-cookie" | "proxy-authorization")
    )
}

fn normalise_header(name: &str) -> Option<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.len() > 64 {
        return None;
    }
    Some(trimmed.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_telemetry_is_disabled_by_default() {
        let planner = TlsUprobePlanner::new(TlsTelemetrySettings::default());

        assert_eq!(
            planner.decision_for(TlsLibrary::OpenSsl),
            TlsTelemetryDecision::ConnectionTelemetryFallback(TlsFallbackReason::Disabled)
        );
    }

    #[test]
    fn openssl_is_selected_only_when_enabled_and_allowlisted() {
        let planner = TlsUprobePlanner::new(TlsTelemetrySettings {
            enabled: true,
            library_allowlist: vec![TlsLibrary::OpenSsl],
        });

        assert_eq!(
            planner.decision_for(TlsLibrary::OpenSsl),
            TlsTelemetryDecision::OpenSslUprobes
        );
    }

    #[test]
    fn unsupported_allowlisted_libraries_fall_back_to_connection_telemetry() {
        let planner = TlsUprobePlanner::new(TlsTelemetrySettings {
            enabled: true,
            library_allowlist: vec![TlsLibrary::BoringSsl, TlsLibrary::Rustls],
        });

        assert_eq!(
            planner.decision_for(TlsLibrary::BoringSsl),
            TlsTelemetryDecision::ConnectionTelemetryFallback(
                TlsFallbackReason::LibraryUnsupported
            )
        );
        assert_eq!(
            planner.decision_for(TlsLibrary::Rustls),
            TlsTelemetryDecision::ConnectionTelemetryFallback(
                TlsFallbackReason::LibraryUnsupported
            )
        );
    }

    #[test]
    fn non_allowlisted_library_falls_back_to_connection_telemetry() {
        let planner = TlsUprobePlanner::new(TlsTelemetrySettings {
            enabled: true,
            library_allowlist: vec![TlsLibrary::OpenSsl],
        });

        assert_eq!(
            planner.decision_for(TlsLibrary::Rustls),
            TlsTelemetryDecision::ConnectionTelemetryFallback(
                TlsFallbackReason::LibraryNotAllowlisted
            )
        );
    }

    #[test]
    fn metadata_policy_blocks_secrets_cookies_keys_and_bodies() {
        let policy = TlsMetadataPolicy::new();

        assert!(policy.permits(TlsMetadataClass::Method, None));
        assert!(policy.permits(TlsMetadataClass::TraceContext, None));
        assert!(policy.permits(TlsMetadataClass::HeaderValue, Some("traceparent")));
        assert!(!policy.permits(TlsMetadataClass::HeaderName, Some("authorization")));
        assert!(!policy.permits(TlsMetadataClass::HeaderName, Some("cookie")));
        assert!(!policy.permits(TlsMetadataClass::HeaderValue, Some("set-cookie")));
        assert!(!policy.permits(TlsMetadataClass::TlsKey, None));
        assert!(!policy.permits(TlsMetadataClass::Secret, None));
        assert!(!policy.permits(TlsMetadataClass::Body, None));
    }
}

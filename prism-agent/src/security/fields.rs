use std::borrow::Cow;

use crate::config::{SecurityEventField, SecuritySettings};
use crate::security::SecurityEventKind;

pub const REDACTED_FIELD: &str = "[REDACTED]";

#[must_use]
pub fn controlled_security_field<'a>(
    settings: &SecuritySettings,
    kind: SecurityEventKind,
    field: SecurityEventField,
    value: &'a str,
) -> Option<Cow<'a, str>> {
    field_allowed(settings, kind, field)
        .then(|| redact_and_cap_field(value, settings.max_field_len, &settings.redaction_patterns))
}

#[must_use]
pub fn redact_and_cap_field<'a>(
    value: &'a str,
    max_len: usize,
    redaction_patterns: &[String],
) -> Cow<'a, str> {
    if should_redact(value, redaction_patterns) {
        return Cow::Borrowed(REDACTED_FIELD);
    }

    if value.len() <= max_len {
        return Cow::Borrowed(value);
    }

    Cow::Owned(truncate_utf8(value, max_len))
}

fn field_allowed(
    settings: &SecuritySettings,
    kind: SecurityEventKind,
    field: SecurityEventField,
) -> bool {
    match kind {
        SecurityEventKind::ProcessExec => settings.process_exec_fields.contains(&field),
        SecurityEventKind::FileAccess => settings.file_access_fields.contains(&field),
        SecurityEventKind::NetworkConnection => settings.network_connection_fields.contains(&field),
    }
}

fn should_redact(value: &str, redaction_patterns: &[String]) -> bool {
    let lower = value.to_ascii_lowercase();
    redaction_patterns
        .iter()
        .map(|pattern| pattern.trim())
        .filter(|pattern| !pattern.is_empty())
        .any(|pattern| lower.contains(&pattern.to_ascii_lowercase()))
}

fn truncate_utf8(value: &str, max_len: usize) -> String {
    let mut end = 0;
    for (index, ch) in value.char_indices() {
        let next = index + ch.len_utf8();
        if next > max_len {
            break;
        }
        end = next;
    }
    value[..end].to_owned()
}

#[cfg(test)]
mod tests {
    use crate::config::SecurityEventField;

    use super::*;

    #[test]
    fn command_line_is_omitted_by_default() {
        let settings = SecuritySettings::default();
        let value = controlled_security_field(
            &settings,
            SecurityEventKind::ProcessExec,
            SecurityEventField::CommandLine,
            "psql password=secret",
        );

        assert!(value.is_none());
    }

    #[test]
    fn file_path_requires_event_allowlist() {
        let mut settings = SecuritySettings::default();
        settings
            .file_access_fields
            .push(SecurityEventField::FilePath);

        let value = controlled_security_field(
            &settings,
            SecurityEventKind::FileAccess,
            SecurityEventField::FilePath,
            "/var/log/auth.log",
        );

        assert_eq!(value.as_deref(), Some("/var/log/auth.log"));
    }

    #[test]
    fn labels_annotations_and_sql_text_are_redacted_before_export() {
        let settings = SecuritySettings::default();

        assert_eq!(
            redact_and_cap_field(
                "app=checkout;token=abc",
                settings.max_field_len,
                &settings.redaction_patterns
            ),
            REDACTED_FIELD
        );
        assert_eq!(
            redact_and_cap_field(
                "kubectl.kubernetes.io/last-applied-configuration={\"password\":\"x\"}",
                settings.max_field_len,
                &settings.redaction_patterns
            ),
            REDACTED_FIELD
        );
        assert_eq!(
            redact_and_cap_field(
                "select * from users where secret = 'x'",
                settings.max_field_len,
                &settings.redaction_patterns
            ),
            REDACTED_FIELD
        );
    }

    #[test]
    fn field_values_are_capped_on_utf8_boundaries() {
        let settings = SecuritySettings {
            max_field_len: 5,
            ..SecuritySettings::default()
        };

        let value = redact_and_cap_field("abcde-remaining", 5, &settings.redaction_patterns);
        let unicode = redact_and_cap_field("abcéfg", 5, &settings.redaction_patterns);

        assert_eq!(value, "abcde");
        assert_eq!(unicode, "abcé");
    }
}

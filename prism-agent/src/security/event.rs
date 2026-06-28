use crate::config::{PolicyAction, PolicyRuleMatch};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityEventKind {
    ProcessExec,
    FileAccess,
    NetworkConnection,
}

impl SecurityEventKind {
    #[must_use]
    pub const fn event_type(self) -> &'static str {
        match self {
            Self::ProcessExec => "process_exec",
            Self::FileAccess => "file_access",
            Self::NetworkConnection => "network_connection",
        }
    }

    #[must_use]
    pub const fn stable_id(self) -> &'static str {
        match self {
            Self::ProcessExec => "prism.security.process_exec.v1",
            Self::FileAccess => "prism.security.file_access.v1",
            Self::NetworkConnection => "prism.security.network_connection.v1",
        }
    }

    #[must_use]
    pub const fn category(self) -> EventCategory {
        match self {
            Self::ProcessExec => EventCategory::Process,
            Self::FileAccess => EventCategory::File,
            Self::NetworkConnection => EventCategory::Network,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventCategory {
    Process,
    File,
    Network,
}

impl EventCategory {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Process => "process",
            Self::File => "file",
            Self::Network => "network",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecuritySeverity {
    Info,
    Warning,
    Error,
}

impl SecuritySeverity {
    #[must_use]
    pub const fn from_policy_action(action: PolicyAction) -> Self {
        match action {
            PolicyAction::Allow => Self::Info,
            PolicyAction::Alert => Self::Warning,
            PolicyAction::Deny => Self::Error,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Warning => "WARN",
            Self::Error => "ERROR",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyRuleFamily {
    FilePath,
    Process,
    NetworkDestination,
}

impl PolicyRuleFamily {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FilePath => "file_path",
            Self::Process => "process",
            Self::NetworkDestination => "network_destination",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyMatchContext {
    action: PolicyAction,
    rule_family: Option<PolicyRuleFamily>,
    rule_index: Option<usize>,
}

impl PolicyMatchContext {
    #[must_use]
    pub const fn new(rule_family: PolicyRuleFamily, rule_match: PolicyRuleMatch) -> Self {
        Self {
            action: rule_match.action(),
            rule_family: Some(rule_family),
            rule_index: rule_match.rule_index(),
        }
    }

    #[must_use]
    pub const fn unmatched() -> Self {
        Self {
            action: PolicyAction::Allow,
            rule_family: None,
            rule_index: None,
        }
    }

    #[must_use]
    pub const fn action(self) -> PolicyAction {
        self.action
    }

    #[must_use]
    pub const fn rule_family(self) -> Option<PolicyRuleFamily> {
        self.rule_family
    }

    #[must_use]
    pub const fn rule_index(self) -> Option<usize> {
        self.rule_index
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityEventMetadata {
    kind: SecurityEventKind,
    severity: SecuritySeverity,
    policy: PolicyMatchContext,
}

impl SecurityEventMetadata {
    #[must_use]
    pub fn new(kind: SecurityEventKind, policy: PolicyMatchContext) -> Self {
        Self {
            kind,
            severity: SecuritySeverity::from_policy_action(policy.action()),
            policy,
        }
    }

    #[must_use]
    pub const fn kind(&self) -> SecurityEventKind {
        self.kind
    }

    #[must_use]
    pub const fn severity(&self) -> SecuritySeverity {
        self.severity
    }

    #[must_use]
    pub const fn policy(&self) -> PolicyMatchContext {
        self.policy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_event_ids_are_versioned() {
        assert_eq!(
            SecurityEventKind::ProcessExec.stable_id(),
            "prism.security.process_exec.v1"
        );
        assert_eq!(
            SecurityEventKind::FileAccess.stable_id(),
            "prism.security.file_access.v1"
        );
        assert_eq!(
            SecurityEventKind::NetworkConnection.stable_id(),
            "prism.security.network_connection.v1"
        );
    }

    #[test]
    fn event_kinds_have_categories() {
        assert_eq!(
            SecurityEventKind::ProcessExec.category(),
            EventCategory::Process
        );
        assert_eq!(
            SecurityEventKind::FileAccess.category(),
            EventCategory::File
        );
        assert_eq!(
            SecurityEventKind::NetworkConnection.category(),
            EventCategory::Network
        );
    }

    #[test]
    fn severity_follows_policy_action() {
        assert_eq!(
            SecuritySeverity::from_policy_action(PolicyAction::Allow),
            SecuritySeverity::Info
        );
        assert_eq!(
            SecuritySeverity::from_policy_action(PolicyAction::Alert),
            SecuritySeverity::Warning
        );
        assert_eq!(
            SecuritySeverity::from_policy_action(PolicyAction::Deny),
            SecuritySeverity::Error
        );
    }

    #[test]
    fn policy_context_contains_rule_identity_without_payload() {
        let policy = PolicyMatchContext::new(
            PolicyRuleFamily::FilePath,
            PolicyRuleMatch::matched(PolicyAction::Alert, 7),
        );

        assert_eq!(policy.action(), PolicyAction::Alert);
        assert_eq!(policy.rule_family(), Some(PolicyRuleFamily::FilePath));
        assert_eq!(policy.rule_index(), Some(7));
    }
}
